import type { DurableJob } from "../types.js";

export interface DurableDb {
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

export const DURABLE_JOBS_DDL = `
CREATE TABLE IF NOT EXISTS durable_jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('write', 'live-query', 'source-sync', 'movement', 'company-file-upload', 'relationship-enrichment')),
  namespace TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
  payload JSONB NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at TIMESTAMPTZ NOT NULL,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
`;

export const DURABLE_JOBS_INDEX_DDL = `CREATE INDEX IF NOT EXISTS durable_jobs_claim_idx
  ON durable_jobs (state, available_at, lease_expires_at)`;

export interface EnqueueJob<T> {
  id: string;
  kind: DurableJob<T>["kind"];
  namespace: string;
  payload: T;
  availableAt?: string;
}

export interface ClaimOptions {
  now?: Date;
  leaseMs?: number;
  kinds?: DurableJob["kind"][];
  /** Optional worker affinity for radioactive, non-persistable credentials. */
  affinity?: string;
}

interface JobRow {
  id: string;
  kind: DurableJob["kind"];
  namespace: string;
  state: DurableJob["state"];
  payload: unknown;
  attempts: number | string;
  available_at: Date | string;
  lease_owner: string | null;
  lease_expires_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
}

function iso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function rowToJob<T>(row: JobRow): DurableJob<T> {
  return {
    id: row.id,
    kind: row.kind,
    namespace: row.namespace,
    state: row.state,
    payload: row.payload as T,
    attempts: Number(row.attempts),
    availableAt: iso(row.available_at),
    leaseOwner: row.lease_owner,
    leaseExpiresAt: row.lease_expires_at === null ? null : iso(row.lease_expires_at),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

export class DurableJobStore {
  constructor(private readonly db: DurableDb) {}

  async enqueue<T>(input: EnqueueJob<T>): Promise<DurableJob<T>> {
    if (input.id.length === 0 || input.namespace.length > 512) {
      throw new RangeError("job id or namespace is invalid");
    }
    const now = new Date().toISOString();
    const availableAt = input.availableAt ?? now;
    const result = await this.db.query(
      `INSERT INTO durable_jobs
         (id, kind, namespace, state, payload, attempts, available_at,
          lease_owner, lease_expires_at, created_at, updated_at)
       VALUES ($1, $2, $3, 'queued', $4::jsonb, 0, $5, NULL, NULL, $6, $6)
       ON CONFLICT (id) DO NOTHING
       RETURNING *`,
      [input.id, input.kind, input.namespace, JSON.stringify(input.payload), availableAt, now],
    );
    const row = result.rows[0] as JobRow | undefined;
    if (row) return rowToJob<T>(row);
    const existing = await this.get<T>(input.id);
    if (!existing) throw new Error("durable job insert lost without an existing row");
    return existing;
  }

  async get<T = unknown>(id: string): Promise<DurableJob<T> | null> {
    const result = await this.db.query(`SELECT * FROM durable_jobs WHERE id = $1`, [id]);
    const row = result.rows[0] as JobRow | undefined;
    return row ? rowToJob<T>(row) : null;
  }

  /** Remove stale non-running schedule jobs before pause/reschedule/manual mode. */
  async cancelSourceSync(sourceId: string): Promise<number> {
    const result = await this.db.query(
      `DELETE FROM durable_jobs
        WHERE kind = 'source-sync'
          AND state <> 'running'
          AND payload->>'sourceId' = $1
        RETURNING id`,
      [sourceId],
    );
    return result.rows.length;
  }

  async claim<T = unknown>(workerId: string, options: ClaimOptions = {}): Promise<DurableJob<T> | null> {
    if (workerId.length === 0) throw new RangeError("worker id is required");
    const now = options.now ?? new Date();
    const leaseMs = options.leaseMs ?? 30_000;
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) {
      throw new RangeError("leaseMs must be a positive safe integer");
    }
    const expiresAt = new Date(now.getTime() + leaseMs).toISOString();
    const kinds = options.kinds;
    if (kinds?.length === 0) return null;
    let nextParam = 4;
    const kindClause = kinds ? `AND kind = ANY($${nextParam++}::text[])` : "";
    const affinityClause = options.affinity
      ? `AND (payload->>'affinity' IS NULL OR payload->>'affinity' = $${nextParam++})`
      : "";
    const params: unknown[] = [now.toISOString(), workerId, expiresAt];
    if (kinds) params.push(kinds);
    if (options.affinity) params.push(options.affinity);
    const result = await this.db.query(
      `WITH candidate AS (
         SELECT id FROM durable_jobs
         WHERE (
           (state = 'queued' AND available_at <= $1)
           OR (state = 'running' AND lease_expires_at <= $1)
         )
         ${kindClause}
         ${affinityClause}
         ORDER BY available_at, created_at, id
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       UPDATE durable_jobs AS job
       SET state = 'running', attempts = job.attempts + 1,
           lease_owner = $2, lease_expires_at = $3, updated_at = $1
       FROM candidate
       WHERE job.id = candidate.id
       RETURNING job.*`,
      params,
    );
    const row = result.rows[0] as JobRow | undefined;
    return row ? rowToJob<T>(row) : null;
  }

  async complete(id: string, workerId: string): Promise<boolean> {
    const result = await this.db.query(
      `UPDATE durable_jobs
       SET state = 'done', lease_owner = NULL, lease_expires_at = NULL, updated_at = $3
       WHERE id = $1 AND state = 'running' AND lease_owner = $2
       RETURNING id`,
      [id, workerId, new Date().toISOString()],
    );
    return result.rows.length === 1;
  }

  async renew(id: string, workerId: string, leaseMs: number, now = new Date()): Promise<boolean> {
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) {
      throw new RangeError("leaseMs must be a positive safe integer");
    }
    const result = await this.db.query(
      `UPDATE durable_jobs SET lease_expires_at = $3, updated_at = $4
       WHERE id = $1 AND state = 'running' AND lease_owner = $2
       RETURNING id`,
      [id, workerId, new Date(now.getTime() + leaseMs).toISOString(), now.toISOString()],
    );
    return result.rows.length === 1;
  }

  async fail(
    id: string,
    workerId: string,
    error: string,
    options: { retryAt?: string } = {},
  ): Promise<boolean> {
    const retry = options.retryAt !== undefined;
    const now = new Date().toISOString();
    const result = await this.db.query(
      `UPDATE durable_jobs
       SET state = $3, available_at = $4, lease_owner = NULL,
           lease_expires_at = NULL, last_error = $5, updated_at = $6
       WHERE id = $1 AND state = 'running' AND lease_owner = $2
       RETURNING id`,
      [id, workerId, retry ? "queued" : "failed", options.retryAt ?? now, error.slice(0, 2048), now],
    );
    return result.rows.length === 1;
  }
}
