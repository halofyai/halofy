/**
 * Embedding-dimension reconciliation (migrate.ts).
 *
 * The vector columns are cut at whatever embedder was configured the FIRST time
 * a database was migrated. Production was migrated with no embedding key set,
 * so all three columns are vector(256) — the HashEmbedder's width. Switching on
 * a real embeddings deployment moves the effective dimension to 3072, and every
 * insert and search then fails against a 256-wide column with nothing failing
 * fast at boot to say why.
 *
 * This is reconciled on EVERY migrate rather than by a numbered migration,
 * because a once-only migration would fire as a no-op while no embedding key
 * exists, record itself applied, and never run again once the key is set. The
 * second test below is the one that would catch that regression.
 */

import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { EMBEDDING_TABLES } from "../src/db/migrations.js";

let db: Db | null = null;

afterEach(async () => {
  await db?.close();
  db = null;
});

async function freshDb(dim: number): Promise<Db> {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: dim });
  const created = await createDb(config);
  await migrate(created, dim);
  return created;
}

async function columnTypes(target: Db): Promise<Record<string, string>> {
  const res = await target.query(
    `SELECT a.attrelid::regclass::text AS tbl, format_type(a.atttypid, a.atttypmod) AS ty
       FROM pg_attribute a
      WHERE a.attname = 'embedding' AND a.attnum > 0 AND NOT a.attisdropped`,
  );
  const out: Record<string, string> = {};
  for (const row of res.rows as { tbl: string; ty: string }[]) out[row.tbl] = row.ty;
  return out;
}

describe("embedding dimension reconciliation", () => {
  it("cuts every embedding column at the configured dimension on a fresh database", async () => {
    db = await freshDb(8);
    const types = await columnTypes(db);
    for (const table of EMBEDDING_TABLES) {
      expect(types[table], `${table}.embedding`).toBe("vector(8)");
    }
  });

  it("realigns the columns when the configured dimension changes", async () => {
    db = await freshDb(8);
    // Re-migrating an ALREADY-migrated database at a new width is exactly what a
    // deployment does when an embeddings key is switched on: every numbered
    // migration is already recorded, so only the reconciliation can act.
    await migrate(db, 16);
    const types = await columnTypes(db);
    for (const table of EMBEDDING_TABLES) {
      expect(types[table], `${table}.embedding`).toBe("vector(16)");
    }
  });

  it("drops vectors that cannot survive the width change, leaving the rows intact", async () => {
    db = await freshDb(8);
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          assertion_time, t_valid_from, provenance, embedding)
       VALUES ('m1','acme','org','L2','ref','a fact','fact',1,$1,$1,'[]',$2::vector)`,
      [now, "[1,0,0,0,0,0,0,0]"],
    );

    await migrate(db, 16);

    const res = await db.query(
      `SELECT content, embedding IS NULL AS cleared FROM memory_objects WHERE id = 'm1'`,
    );
    // The row survives; only the meaningless vector is discarded. Retrieval
    // browns out to BM25 until `cli.ts reembed` rebuilds it.
    expect(res.rows).toEqual([{ content: "a fact", cleared: true }]);
  });

  it("is a no-op when the dimension has not moved", async () => {
    db = await freshDb(8);
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          assertion_time, t_valid_from, provenance, embedding)
       VALUES ('m1','acme','org','L2','ref','a fact','fact',1,$1,$1,'[]',$2::vector)`,
      [now, "[1,0,0,0,0,0,0,0]"],
    );

    await migrate(db, 8);

    // An unconditional ALTER ... USING NULL would silently wipe every vector in
    // the hermetic lane on each boot; the guard is what keeps this a no-op.
    const res = await db.query(
      `SELECT embedding IS NULL AS cleared FROM memory_objects WHERE id = 'm1'`,
    );
    expect(res.rows).toEqual([{ cleared: false }]);
  });
});
