import type { DurableDb } from "./jobs.js";

export const DURABLE_RATE_LIMITS_DDL = `
CREATE TABLE IF NOT EXISTS durable_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  window_started_at TIMESTAMPTZ NOT NULL,
  window_ends_at TIMESTAMPTZ NOT NULL,
  request_count INTEGER NOT NULL CHECK (request_count >= 0),
  updated_at TIMESTAMPTZ NOT NULL
);
`;

export const DURABLE_RATE_LIMITS_INDEX_DDL = `CREATE INDEX IF NOT EXISTS durable_rate_limits_expiry_idx
  ON durable_rate_limits (window_ends_at)`;

export interface RateLimitOutcome {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
  resetAt: string;
}

interface BucketRow {
  request_count: number | string;
  window_ends_at: Date | string;
}

export class DurableRateLimitStore {
  constructor(private readonly db: DurableDb) {}

  async consume(
    bucketKey: string,
    limit: number,
    windowMs: number,
    now = new Date(),
  ): Promise<RateLimitOutcome> {
    if (bucketKey.length === 0 || bucketKey.length > 512) {
      throw new RangeError("rate-limit bucket key must be 1..512 characters");
    }
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new RangeError("rate-limit limit must be a positive safe integer");
    }
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
      throw new RangeError("rate-limit windowMs must be a positive safe integer");
    }
    const nowIso = now.toISOString();
    const newEnd = new Date(now.getTime() + windowMs).toISOString();
    const changed = await this.db.query(
      `INSERT INTO durable_rate_limits
         (bucket_key, window_started_at, window_ends_at, request_count, updated_at)
       VALUES ($1, $2, $3, 1, $2)
       ON CONFLICT (bucket_key) DO UPDATE SET
         window_started_at = CASE
           WHEN durable_rate_limits.window_ends_at <= $2 THEN $2
           ELSE durable_rate_limits.window_started_at END,
         window_ends_at = CASE
           WHEN durable_rate_limits.window_ends_at <= $2 THEN $3
           ELSE durable_rate_limits.window_ends_at END,
         request_count = CASE
           WHEN durable_rate_limits.window_ends_at <= $2 THEN 1
           ELSE durable_rate_limits.request_count + 1 END,
         updated_at = $2
       WHERE durable_rate_limits.window_ends_at <= $2
          OR durable_rate_limits.request_count < $4
       RETURNING request_count, window_ends_at`,
      [bucketKey, nowIso, newEnd, limit],
    );
    const row = (changed.rows[0] ?? (
      await this.db.query(
        `SELECT request_count, window_ends_at FROM durable_rate_limits WHERE bucket_key = $1`,
        [bucketKey],
      )
    ).rows[0]) as BucketRow;
    const count = Number(row.request_count);
    const reset = row.window_ends_at instanceof Date
      ? row.window_ends_at
      : new Date(row.window_ends_at);
    const allowed = changed.rows.length === 1;
    return {
      allowed,
      remaining: allowed ? Math.max(0, limit - count) : 0,
      retryAfterSec: allowed ? 0 : Math.max(1, Math.ceil((reset.getTime() - now.getTime()) / 1000)),
      resetAt: reset.toISOString(),
    };
  }

  /** Syscall-gate compatibility: one durable fixed window per credential. */
  async allow(key: string, limit: number): Promise<boolean> {
    return (await this.consume(`syscall:${key}`, limit, 60_000)).allowed;
  }

  async prune(now = new Date()): Promise<number> {
    const result = await this.db.query(
      `DELETE FROM durable_rate_limits WHERE window_ends_at <= $1 RETURNING bucket_key`,
      [now.toISOString()],
    );
    return result.rows.length;
  }

  /** A successful authentication clears the preceding failure window. */
  async reset(bucketKey: string): Promise<void> {
    if (bucketKey.length === 0 || bucketKey.length > 512) {
      throw new RangeError("rate-limit bucket key must be 1..512 characters");
    }
    await this.db.query(`DELETE FROM durable_rate_limits WHERE bucket_key = $1`, [bucketKey]);
  }
}
