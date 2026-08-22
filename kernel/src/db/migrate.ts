/**
 * Module C (M1) — versioned schema migration runner.
 *
 * Signature unchanged from v0.1 (`migrate(db, embedDim)`) so callers don't
 * break. Behavior hardened:
 *   - creates `schema_migrations(version int pk, name text, applied_at
 *     timestamptz)` if missing,
 *   - applies pending migrations from ./migrations.js in version order,
 *   - the whole read-then-apply runs in ONE transaction that first takes a
 *     session advisory lock (`pg_advisory_xact_lock`, auto-released at
 *     commit/rollback): two processes booting against the same Postgres —
 *     `npm run serve` + the CLI, or two horizontally-scaled servers —
 *     serialize instead of racing CREATE TABLE / the version INSERT and
 *     crashing the loser with a duplicate-key error. The loser simply sees
 *     the winner's rows as already applied. A failed migration leaves no
 *     trace (full rollback),
 *   - re-running is a no-op for already-recorded versions.
 *
 * Databases migrated before versioning existed are safe: migration 001 is a
 * verbatim IF-NOT-EXISTS capture of the v0.1 schema, so replaying it over an
 * existing schema changes nothing.
 */

import type { Db } from "./client.js";
import { MIGRATIONS, embeddingRealignSql, splitStatements } from "./migrations.js";

/** Arbitrary but stable app-wide advisory-lock key for schema migration. */
const MIGRATE_LOCK_KEY = 727_274_001;

export async function migrate(db: Db, embedDim: number): Promise<void> {
  if (!Number.isInteger(embedDim) || embedDim <= 0) {
    throw new Error(`migrate: embedDim must be a positive integer, got ${embedDim}`);
  }

  await db.transaction(async (tx) => {
    // Cross-process serialization. Transaction-scoped, so the lock can never
    // leak: it is released when this transaction commits or rolls back — and
    // Db.transaction runs on a single dedicated connection, so the lock and
    // the queries below share one session. On single-process PGlite this is
    // effectively a no-op.
    await tx.query(`SELECT pg_advisory_xact_lock(${MIGRATE_LOCK_KEY})`);

    await tx.query(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         version    INTEGER PRIMARY KEY,
         name       TEXT NOT NULL,
         applied_at TIMESTAMPTZ NOT NULL
       )`,
    );

    const res = await tx.query(`SELECT version FROM schema_migrations`);
    const applied = new Set<number>(res.rows.map((r) => Number(r.version)));

    const ordered = [...MIGRATIONS].sort((a, b) => a.version - b.version);
    for (const migration of ordered) {
      if (applied.has(migration.version)) continue;
      for (const statement of splitStatements(migration.sql(embedDim))) {
        await tx.query(statement);
      }
      await tx.query(
        `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
        [migration.version, migration.name, new Date().toISOString()],
      );
    }

    // Embedding width is configuration, not schema version: the vector columns
    // are cut at whatever embedder was configured the first time a database was
    // migrated, and switching one on later moves the dimension. So this runs on
    // EVERY migrate, not once — a versioned migration would fire as a no-op
    // before the embedding key exists, record itself as applied, and never run
    // again once it does. It is a catalog lookup per table when nothing moved.
    //
    // Inside the same transaction and advisory lock as the migrations above, so
    // two booting processes cannot realign concurrently. A realign discards the
    // old vectors (see embeddingRealignSql) and the rows need `cli.ts reembed`.
    await tx.query(embeddingRealignSql(embedDim));
  });
}
