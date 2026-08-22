/**
 * Module A/C — database client (D5: one database).
 *
 * Normalizes `pg` (when DATABASE_URL is set) and embedded PGlite (dev/test,
 * with the pgvector extension) behind one minimal `Db` handle. All other
 * modules receive this handle; none open their own connections.
 *
 * M1 hardening: `transaction<T>(fn)` runs `fn` against a transactional view
 * of the same interface — commit on resolve, rollback on throw. Nested
 * transactions are NOT supported: the `tx` handle passed to `fn` throws if
 * `transaction()` or `close()` is called on it.
 */

import type { KernelConfig } from "../config.js";
import {
  createEntraTokenSource,
  parsePostgresDsn,
  type EntraTokenSource,
} from "./entra-auth.js";

export interface Db {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[] }>;
  /**
   * Run `fn` inside a single database transaction. Commits when `fn`
   * resolves; rolls back (and rethrows) when `fn` throws. The `tx` argument
   * is a `Db` scoped to the transaction — do not retain it after `fn`
   * returns, and do not call `tx.transaction()` (nesting unsupported) or
   * `tx.close()`.
   */
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * Escape SQL LIKE metacharacters (`\`, `%`, `_`) in a literal string so it
 * can be embedded in a LIKE pattern; pair with an explicit `ESCAPE '\'`
 * clause. Namespaces are arbitrary strings — without this, `_`/`%` inside a
 * namespace act as wildcards and match SIBLING namespaces (cross-tenant key
 * listing / budget attribution leaks). Same hazard the syscall ACL path
 * avoids with exact IN-lists (see syscalls visibleNamespaces).
 */
export function escapeLikePattern(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** Transaction-scoped Db: only query() is legal on the tx handle. */
function txDb(query: Db["query"]): Db {
  return {
    query,
    transaction() {
      return Promise.reject(
        new Error("Db.transaction: nested transactions are not supported"),
      );
    },
    close() {
      return Promise.reject(
        new Error("Db.close: cannot close the database from inside a transaction"),
      );
    },
  };
}

/**
 * Pool configuration for a networked Postgres.
 *
 * `password` mode (the default) hands `pg` the DSN untouched — byte-identical
 * to the pre-Entra behaviour, so nothing about the existing deployment moves.
 *
 * `entra` mode swaps the static password for a per-connection managed-identity
 * token. `pg` calls the `password` callback on every NEW connection, which is
 * exactly the refresh hook a rotating credential needs. Note the DSN must be
 * decomposed rather than passed through: see parsePostgresDsn for why a
 * callback alongside `connectionString` is silently dropped.
 *
 * Brownout (CONTRACTS rule 5): if the token endpoint is unreachable we fall
 * back to the DSN password when the server still accepts one, and log it. A
 * degraded credential beats a kernel that cannot open a connection.
 */
export function poolConfigFor(
  config: KernelConfig,
  seams: { tokens?: EntraTokenSource } = {},
): Record<string, unknown> {
  if (config.dbAuthMode !== "entra") {
    return { connectionString: config.databaseUrl };
  }
  const parts = parsePostgresDsn(config.databaseUrl);
  const fallbackPassword = new URL(config.databaseUrl).password;
  const tokens = seams.tokens ??
    createEntraTokenSource({ clientId: config.dbEntraClientId || undefined });
  return {
    host: parts.host,
    port: parts.port,
    database: parts.database,
    // The Entra principal name, NOT the SQL role in the DSN: Postgres matches
    // the token's identity against the username it was given.
    user: config.dbEntraUser || parts.user,
    ssl: parts.ssl,
    password: async () => {
      try {
        return await tokens.token();
      } catch (error) {
        if (!fallbackPassword) throw error;
        console.warn(
          `[db] entra token unavailable, falling back to password auth: ${(error as Error).message}`,
        );
        return fallbackPassword;
      }
    },
  };
}

export async function createDb(config: KernelConfig): Promise<Db> {
  if (config.databaseUrl) {
    const { default: pg } = await import("pg");
    const pool = new pg.Pool(poolConfigFor(config));
    return {
      async query(sql: string, params?: unknown[]) {
        const res = await pool.query(sql, params as any[] | undefined);
        return { rows: res.rows };
      },
      async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
        // Dedicated client: a pool's query() may hop connections, which
        // would scatter BEGIN/COMMIT across sessions.
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const tx = txDb(async (sql: string, params?: unknown[]) => {
            const res = await client.query(sql, params as any[] | undefined);
            return { rows: res.rows };
          });
          const result = await fn(tx);
          await client.query("COMMIT");
          return result;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            // Connection may already be broken; the original error wins.
          }
          throw err;
        } finally {
          client.release();
        }
      },
      async close() {
        await pool.end();
      },
    };
  }

  const { PGlite } = await import("@electric-sql/pglite");
  const { vector } = await import("@electric-sql/pglite/vector");
  // Empty pgliteDataDir → in-memory database. NOTE: pglite 0.2.x silently
  // ignores the options argument when the first argument is undefined, so we
  // must use the single-options-object form for the in-memory case.
  const pglite = config.pgliteDataDir
    ? new PGlite(config.pgliteDataDir, { extensions: { vector } })
    : new PGlite({ extensions: { vector } });
  await pglite.waitReady;
  return {
    async query(sql: string, params?: unknown[]) {
      const res = await pglite.query(sql, params as any[] | undefined);
      return { rows: res.rows as any[] };
    },
    async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      // PGlite's native transaction(): commits when the callback resolves,
      // rolls back when it throws.
      return pglite.transaction(async (ptx) => {
        const tx = txDb(async (sql: string, params?: unknown[]) => {
          const res = await ptx.query(sql, params as any[] | undefined);
          return { rows: res.rows as any[] };
        });
        return fn(tx);
      }) as Promise<T>;
    },
    async close() {
      await pglite.close();
    },
  };
}
