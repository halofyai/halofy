import type { Identity } from "../types.js";
import type { DurableDb } from "./jobs.js";

export const DURABLE_TICKETS_DDL = `
CREATE TABLE IF NOT EXISTS durable_tickets (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('write', 'live-query')),
  namespace TEXT NOT NULL,
  subject_key TEXT,
  state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed')),
  result JSONB,
  error TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
`;

export const DURABLE_TICKETS_INDEX_DDL =
  `CREATE INDEX IF NOT EXISTS durable_tickets_expiry_idx ON durable_tickets (expires_at)`;

export interface DurableTicket<T = unknown> {
  id: string;
  kind: "write" | "live-query";
  namespace: string;
  state: "running" | "done" | "failed";
  result: T | null;
  error: string | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

interface TicketRow {
  id: string;
  kind: DurableTicket["kind"];
  namespace: string;
  state: DurableTicket["state"];
  result: unknown | null;
  error: string | null;
  expires_at: Date | string;
  created_at: Date | string;
  updated_at: Date | string;
}

const toIso = (value: Date | string): string =>
  value instanceof Date ? value.toISOString() : new Date(value).toISOString();

function toTicket<T>(row: TicketRow): DurableTicket<T> {
  return {
    id: row.id,
    kind: row.kind,
    namespace: row.namespace,
    state: row.state,
    result: row.result as T | null,
    error: row.error,
    expiresAt: toIso(row.expires_at),
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

export class DurableTicketStore {
  constructor(private readonly db: DurableDb) {}

  async issue(input: {
    id: string;
    kind: DurableTicket["kind"];
    namespace: string;
    subjectKey: string;
    expiresAt: string;
  }): Promise<DurableTicket> {
    if (input.id.length === 0 || input.namespace.length > 512 || input.subjectKey.length === 0) {
      throw new RangeError("ticket id or namespace is invalid");
    }
    const now = new Date().toISOString();
    const result = await this.db.query(
      `INSERT INTO durable_tickets
         (id, kind, namespace, subject_key, state, result, error, expires_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, 'running', NULL, NULL, $5, $6, $6)
       ON CONFLICT (id) DO NOTHING
       RETURNING *`,
      [input.id, input.kind, input.namespace, input.subjectKey, input.expiresAt, now],
    );
    const row = result.rows[0] as TicketRow | undefined;
    if (row) return toTicket(row);
    const existing = await this.raw(input.id);
    if (!existing) throw new Error("durable ticket insert lost without an existing row");
    return existing;
  }

  async complete(id: string, result: unknown): Promise<boolean> {
    const now = new Date().toISOString();
    const updated = await this.db.query(
      `UPDATE durable_tickets
       SET state = 'done', result = $2::jsonb, error = NULL, updated_at = $3
       WHERE id = $1 AND state = 'running' RETURNING id`,
      [id, JSON.stringify(result), now],
    );
    return updated.rows.length === 1;
  }

  async fail(id: string, error: string): Promise<boolean> {
    const updated = await this.db.query(
      `UPDATE durable_tickets
       SET state = 'failed', result = NULL, error = $2, updated_at = $3
       WHERE id = $1 AND state = 'running' RETURNING id`,
      [id, error.slice(0, 2048), new Date().toISOString()],
    );
    return updated.rows.length === 1;
  }

  async resolve<T = unknown>(
    id: string,
    identity: Identity,
    options: { now?: Date } = {},
  ): Promise<DurableTicket<T> | null> {
    const result = await this.db.query(
      `SELECT * FROM durable_tickets
       WHERE id = $1 AND namespace = $2 AND expires_at > $3
         AND subject_key = $4`,
      [id, identity.namespace, (options.now ?? new Date()).toISOString(), identity.keyId],
    );
    const row = result.rows[0] as TicketRow | undefined;
    return row ? toTicket<T>(row) : null;
  }

  private async raw(id: string): Promise<DurableTicket | null> {
    const result = await this.db.query(`SELECT * FROM durable_tickets WHERE id = $1`, [id]);
    const row = result.rows[0] as TicketRow | undefined;
    return row ? toTicket(row) : null;
  }
}
