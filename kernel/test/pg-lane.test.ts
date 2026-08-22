/**
 * Module C (M1) — real-Postgres lane.
 *
 * Runs ONLY when TEST_DATABASE_URL is set (e.g.
 *   TEST_DATABASE_URL=postgres://user:pass@localhost:5432/halomem_test)
 * against a Postgres with the pgvector extension available. Skipped
 * everywhere else, so the default suite stays hermetic.
 *
 * Flow: drop any leftover kernel tables (migrate from zero), run the
 * versioned migrations, exercise MemoryIndex insert / getById / vectorSearch
 * / closeValidity plus Db.transaction rollback, then drop everything again.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations.js";
import { MemoryIndex } from "../src/index/index.js";
import { loadConfig } from "../src/config.js";
import type { MemoryObject } from "../src/types.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const DIM = 8;

/** Order matters only for readability; CASCADE handles the self-FK. */
const KERNEL_TABLES = [
  "conflict_repair_proposals",
  "conflict_pair_recheck_queue",
  "conflict_detection_queue",
  "memory_forks",
  "segment_mounts",
  "segment_members",
  "memory_segments",
  "movement_actions",
  "proposal_decisions",
  "knowledge_proposals",
  "consolidation_runs",
  "memory_pins",
  "knowledge_versions",
  "knowledge_concepts",
  "setup_operations",
  "teams",
  "auth_invitations",
  "auth_bootstrap",
  "sessions",
  "users",
  "source_document_claims",
  "fragmentation_reports",
  "source_documents",
  "sources",
  "deletion_certificates",
  "tombstones",
  "tenants",
  "scorecards",
  "cold_kek_state",
  "erasure_fences",
  "cold_concept_keys",
  "schema_migrations",
  "memory_objects",
  "concepts",
  "entity_registry",
  "audit_log",
  "policies",
  "api_keys",
  "cost_ledger",
];

function makeObj(overrides: Partial<MemoryObject> & { id: string }): MemoryObject {
  const now = new Date().toISOString();
  return {
    namespace: "pglane/team",
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: "pg-lane content",
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "manual", actor: "pg-lane", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
    ...overrides,
  };
}

function unit(hot: number): number[] {
  const v = new Array<number>(DIM).fill(0);
  v[hot] = 1;
  return v;
}

async function dropAll(db: Db): Promise<void> {
  for (const table of KERNEL_TABLES) {
    await db.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
  }
}

describe.skipIf(!TEST_DATABASE_URL)("real Postgres lane", () => {
  let db: Db;
  let index: MemoryIndex;

  beforeAll(async () => {
    const config = loadConfig({
      databaseUrl: TEST_DATABASE_URL,
      pgliteDataDir: "",
      embedDim: DIM,
    });
    db = await createDb(config);
    await dropAll(db); // migrate from zero
    await migrate(db, DIM);
    index = new MemoryIndex(db);
  });

  afterAll(async () => {
    if (!db) return;
    await dropAll(db);
    await db.close();
  });

  it("applies every declared migration from zero and records the current head", async () => {
    const res = await db.query(`SELECT version FROM schema_migrations ORDER BY version`);
    expect(res.rows.map((r) => Number(r.version))).toEqual(MIGRATIONS.map((m) => m.version));
    // Re-migrate is a no-op on real pg too.
    await migrate(db, DIM);
    const again = await db.query(`SELECT COUNT(*) AS n FROM schema_migrations`);
    expect(Number(again.rows[0].n)).toBe(MIGRATIONS.length);
  });

  it("round-trips insert / getById / vectorSearch / closeValidity", async () => {
    const a = makeObj({ id: "pg-a", content: "alpha row" });
    const b = makeObj({ id: "pg-b", content: "beta row" });
    await index.insert(a, unit(0));
    await index.insert(b, unit(3));

    // getById in-namespace
    const got = await index.getById("pg-a", "pglane/team");
    expect(got.denied).toBe(false);
    expect(got.obj).not.toBeNull();
    expect(got.obj!.content).toBe("alpha row");
    expect(got.obj!.tValidTo).toBeNull();

    // ACL: sibling namespace is denied, not a miss
    const denied = await index.getById("pg-a", "pglane/other");
    expect(denied.obj).toBeNull();
    expect(denied.denied).toBe(true);

    // vectorSearch: query near unit(0) ranks pg-a first with similarity ~1
    const hits = await index.vectorSearch("pglane/team", unit(0), 2);
    expect(hits.length).toBe(2);
    expect(hits[0].obj.id).toBe("pg-a");
    expect(hits[0].similarity).toBeGreaterThan(0.99);
    expect(hits[1].obj.id).toBe("pg-b");

    // closeValidity: t_valid_to set, row leaves the valid-only search set
    const closedAt = new Date().toISOString();
    expect(await index.closeValidity("pg-a", closedAt)).toBe(1);
    const after = await index.getById("pg-a", "pglane/team");
    expect(after).toEqual({ obj: null, denied: false });
    const historical = await db.query(
      `SELECT t_valid_to FROM memory_objects WHERE id = $1`,
      ["pg-a"],
    );
    expect(historical.rows).toHaveLength(1);
    const persistedValidTo = (historical.rows[0] as { t_valid_to: unknown }).t_valid_to;
    expect(
      persistedValidTo instanceof Date
        ? persistedValidTo.toISOString()
        : new Date(String(persistedValidTo)).toISOString(),
    ).toBe(closedAt);
    expect(await index.closeValidity("pg-a", new Date().toISOString())).toBe(0);
    const validHits = await index.vectorSearch("pglane/team", unit(0), 2, true);
    expect(validHits.map((h) => h.obj.id)).toEqual(["pg-b"]);
  });

  it("transaction commits and rollback leaves no row (pg backend)", async () => {
    const value = await db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO policies (namespace, yaml, updated_at) VALUES ($1, $2, $3)`,
        ["pglane/commit", "budget: 1", new Date().toISOString()],
      );
      return "ok";
    });
    expect(value).toBe("ok");
    const committed = await db.query(
      `SELECT 1 FROM policies WHERE namespace = 'pglane/commit'`,
    );
    expect(committed.rows.length).toBe(1);

    await expect(
      db.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO policies (namespace, yaml, updated_at) VALUES ($1, $2, $3)`,
          ["pglane/rollback", "budget: 2", new Date().toISOString()],
        );
        throw new Error("boom: rollback on real pg");
      }),
    ).rejects.toThrow(/boom/);
    const rolledBack = await db.query(
      `SELECT 1 FROM policies WHERE namespace = 'pglane/rollback'`,
    );
    expect(rolledBack.rows.length).toBe(0);
  });
});
