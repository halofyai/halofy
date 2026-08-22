/**
 * Module B tests — ColdStore (L3).
 * Hermetic: in-memory PGlite with the vector extension, deterministic
 * hash-based embedder, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { vector } from "@electric-sql/pglite/vector";
import * as path from "node:path";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { ColdStore } from "../src/cold/index.js";
import type { Embedder } from "../src/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_KNOWLEDGE_DIR = path.resolve(__dirname, "..", "knowledge");
const TEST_DIM = 32;

/** Deterministic bag-of-words hash embedder (HashEmbedder-style). */
class TestHashEmbedder implements Embedder {
  readonly name = "test-hash";
  readonly dim = TEST_DIM;

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((t) => {
      const vec = new Array<number>(this.dim).fill(0);
      const tokens = t.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
      for (const tok of tokens) {
        let h = 2166136261;
        for (let i = 0; i < tok.length; i++) {
          h ^= tok.charCodeAt(i);
          h = Math.imul(h, 16777619);
        }
        vec[Math.abs(h) % this.dim] += 1;
      }
      const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
      return vec.map((v) => v / norm);
    });
  }
}

/** Concepts-table DDL from CONTRACTS.md with the test embed dim. */
const CONCEPTS_DDL = `
CREATE TABLE IF NOT EXISTS concepts (
  path          TEXT PRIMARY KEY,
  type          TEXT NOT NULL,
  title         TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  tags          JSONB NOT NULL DEFAULT '[]',
  namespace     TEXT,
  visibility    TEXT,
  pii_subjects  JSONB NOT NULL DEFAULT '[]',
  owner         TEXT,
  verified_against TEXT,
  verified_at   TIMESTAMPTZ,
  body          TEXT NOT NULL,
  embedding     vector(${TEST_DIM}),
  synced_at     TIMESTAMPTZ NOT NULL,
  CONSTRAINT concepts_ownership_check CHECK (
    (namespace IS NOT NULL AND namespace <> '' AND visibility IS NULL)
    OR (namespace IS NULL AND visibility IS NOT NULL AND visibility = 'public')
  )
);
`;

const COLD_KEYS_DDL = `
CREATE TABLE IF NOT EXISTS cold_concept_keys (
  path TEXT PRIMARY KEY,
  wrapped_dek TEXT NOT NULL,
  wrap_iv TEXT NOT NULL,
  wrap_tag TEXT NOT NULL,
  namespace TEXT,
  pii_subjects JSONB,
  kek_id TEXT,
  envelope_version INTEGER,
  write_state TEXT NOT NULL DEFAULT 'committed',
  kek_generation BIGINT,
  created_at TIMESTAMPTZ NOT NULL
);
`;

const COLD_STATE_DDL = `
CREATE TABLE IF NOT EXISTS cold_kek_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
  active_kek_id TEXT NOT NULL,
  generation BIGINT NOT NULL,
  maintenance BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL
);
`;

const KNOWLEDGE_CONCEPTS_DDL = `
CREATE TABLE IF NOT EXISTS knowledge_concepts (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  current_version_id TEXT,
  status TEXT NOT NULL
);
`;

const KNOWLEDGE_VERSIONS_DDL = `
CREATE TABLE IF NOT EXISTS knowledge_versions (
  id TEXT PRIMARY KEY,
  concept_id TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL
);
`;

const TOMBSTONES_DDL = `
CREATE TABLE IF NOT EXISTS tombstones (
  id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  reason TEXT NOT NULL,
  erased_at TIMESTAMPTZ NOT NULL,
  certificate_id TEXT NOT NULL
);
`;

const ERASURE_FENCES_DDL = `
CREATE TABLE IF NOT EXISTS erasure_fences (
  namespace TEXT PRIMARY KEY,
  generation BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL
);
`;

describe("ColdStore (L3 cold tier)", () => {
  let pg: PGlite;
  const db = {
    query: (sql: string, params?: unknown[]) => pg.query(sql, params as any[]),
  };
  const embedder = new TestHashEmbedder();
  let knowledgeDir: string;
  let store: ColdStore;

  beforeAll(async () => {
    pg = new PGlite({ extensions: { vector } });
    await pg.query("CREATE EXTENSION IF NOT EXISTS vector;");
    await pg.query(CONCEPTS_DDL);
    await pg.query(COLD_KEYS_DDL);
    await pg.query(COLD_STATE_DDL);
    await pg.query(KNOWLEDGE_CONCEPTS_DDL);
    await pg.query(KNOWLEDGE_VERSIONS_DDL);
    await pg.query(TOMBSTONES_DDL);
    await pg.query(ERASURE_FENCES_DDL);
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-samples-"));
    store = new ColdStore(knowledgeDir, randomBytes(32).toString("base64"));
    await store.writePrivateConcept(db, {
      path: "concepts/refund-policy.okf.enc", namespace: "org", type: "policy",
      title: "Refund policy", description: "When and how Halo issues customer refunds.",
      tags: ["support", "payments", "policy"], owner: "ops",
      verifiedAgainst: "handbook/finance.md", verifiedAt: "2026-06-20",
      body: "Refunds are issued in full before preparation.",
    });
    await store.writePrivateConcept(db, {
      path: "concepts/escalation-matrix.okf.enc", namespace: "org", type: "runbook",
      title: "Support escalation matrix", description: "Escalation rules.",
      tags: ["support", "runbook"], body: "Allergy incidents page Tier 2 immediately.",
    });
    await store.writePrivateConcept(db, {
      path: "concepts/ordering-platforms.okf.enc", namespace: "org", type: "reference",
      title: "Ordering platform integrations", description: "Delivery platforms.",
      tags: ["integrations", "reference"], body: "DoorDash, UberEats, and Grubhub.",
    });
  });

  afterAll(async () => {
    await fs.rm(knowledgeDir, { recursive: true, force: true });
    await pg.close();
  });

  it("listConcepts finds the 3 sample concepts with correct frontmatter", async () => {
    const concepts = await store.listConcepts("org");
    expect(concepts).toHaveLength(3);
    expect(concepts.map((c) => c.path).sort()).toEqual([
      "concepts/escalation-matrix.okf.enc",
      "concepts/ordering-platforms.okf.enc",
      "concepts/refund-policy.okf.enc",
    ]);

    const refund = concepts.find((c) => c.path === "concepts/refund-policy.okf.enc")!;
    expect(refund.type).toBe("policy");
    expect(refund.title).toBe("Refund policy");
    expect(refund.description).toContain("customer refunds");
    expect(refund.tags).toEqual(["support", "payments", "policy"]);
    expect(refund.namespace).toBe("org");
    expect(refund.owner).toBe("ops");
    expect(refund.verifiedAgainst).toBe("handbook/finance.md");
    expect(refund.verifiedAt).toBeTruthy();
    // Body has frontmatter stripped.
    expect(refund.body).not.toContain("---");
    expect(refund.body).toContain("Refunds are issued in full");

    const escalation = concepts.find((c) => c.path === "concepts/escalation-matrix.okf.enc")!;
    expect(escalation.type).toBe("runbook");
    expect(escalation.title).toBe("Support escalation matrix");

    const platforms = concepts.find((c) => c.path === "concepts/ordering-platforms.okf.enc")!;
    expect(platforms.type).toBe("reference");
    expect(platforms.tags).toEqual(["integrations", "reference"]);
  });

  it("readConcept returns a concept by path and null for missing paths", async () => {
    await store.syncToDb(db, embedder);
    const c = await store.readConcept("org/support", "concepts/refund-policy.okf.enc");
    expect(c).not.toBeNull();
    expect(c!.title).toBe("Refund policy");
    expect(
      await store.readConcept("acme/support", "concepts/does-not-exist.md"),
    ).toBeNull();
  });

  it("skips files without a type field and collects a warning", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-"));
    try {
      await fs.mkdir(path.join(tmp, "sub"), { recursive: true });
      await fs.writeFile(
        path.join(tmp, "sub", "good.md"),
        "---\ntype: policy\ntitle: Good\nvisibility: public\n---\nbody here\n",
        "utf8",
      );
      await fs.writeFile(
        path.join(tmp, "no-type.md"),
        "---\ntitle: Missing type\n---\nbody\n",
        "utf8",
      );
      const s = new ColdStore(tmp);
      const list = await s.listConcepts("org");
      expect(list).toHaveLength(1);
      expect(list[0].path).toBe("sub/good.md");
      expect(s.warnings).toHaveLength(1);
      expect(s.warnings[0]).toContain("no-type.md");
      expect(s.warnings[0]).toContain("type");
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it("quarantines concepts whose YAML frontmatter exceeds the safe parsing limit", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-oversized-"));
    try {
      await fs.writeFile(
        path.join(tmp, "oversized.md"),
        `---\ntype: policy\ntitle: ${"x".repeat(70_000)}\nvisibility: public\n---\nbody\n`,
        "utf8",
      );
      const scoped = new ColdStore(tmp);

      expect(await scoped.listConcepts("org")).toEqual([]);
      expect(scoped.warnings.join("\n")).toMatch(/oversized\.md.*frontmatter.*65,?536/i);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it("syncToDb upserts all concepts with embeddings and synced_at", async () => {
    const n = await store.syncToDb(db, embedder);
    expect(n).toBe(3);
    const { rows } = await db.query(
      "SELECT path, type, title, tags, namespace, visibility, owner, body, embedding, synced_at FROM concepts ORDER BY path",
    );
    expect(rows).toHaveLength(3);
    for (const r of rows) {
      expect(r.embedding).not.toBeNull();
      expect(r.synced_at).toBeTruthy();
      expect(String(r.body).length).toBeGreaterThan(0);
      expect(r.namespace).toBe("org");
      expect(r.visibility).toBeNull();
    }
    const refund = rows.find((r: any) => r.path === "concepts/refund-policy.okf.enc");
    expect(refund.type).toBe("policy");
    expect(refund.owner).toBe("ops");

    // Idempotent: second sync updates in place, no duplicate rows.
    const n2 = await store.syncToDb(db, embedder);
    expect(n2).toBe(3);
    const { rows: rows2 } = await db.query("SELECT count(*)::int AS c FROM concepts");
    expect(rows2[0].c).toBe(3);
  });

  it("searchConcepts('refund') ranks refund-policy first with normalized scores", async () => {
    const results = await store.searchConcepts(
      db,
      embedder,
      "org/support",
      "refund",
      3,
    );
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].ref).toBe("concepts/refund-policy.okf.enc");
    expect(results[0].tier).toBe("L3");
    expect(results[0].id).toBeNull();
    expect(results[0].content.startsWith("Refund policy: ")).toBe(true);
    expect(results[0].tokenEstimate).toBeGreaterThan(0);
    for (const r of results) {
      expect(r.score).toBeGreaterThanOrEqual(0);
      expect(r.score).toBeLessThanOrEqual(1);
    }
    // Descending order.
    for (let i = 1; i < results.length; i++) {
      expect(results[i].score).toBeLessThanOrEqual(results[i - 1].score);
    }
    // Respects k.
    const one = await store.searchConcepts(db, embedder, "org", "refund", 1);
    expect(one).toHaveLength(1);
  });

  it("syncToDb removes rows for deleted/renamed concept files", async () => {
    const pg2 = new PGlite({ extensions: { vector } });
    const db2 = {
      query: (sql: string, params?: unknown[]) => pg2.query(sql, params as any[]),
    };
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-sync-"));
    try {
      await pg2.query("CREATE EXTENSION IF NOT EXISTS vector;");
      await pg2.query(CONCEPTS_DDL);
      const write = (name: string, title: string) =>
        fs.writeFile(
          path.join(tmp, name),
          `---\ntype: policy\ntitle: ${title}\nvisibility: public\n---\nbody of ${title}\n`,
          "utf8",
        );
      await write("keep.md", "Keep");
      await write("retired.md", "Retired");

      const s = new ColdStore(tmp);
      expect(await s.syncToDb(db2, embedder)).toBe(2);

      // Retire one concept (delete) and rename the other.
      await fs.rm(path.join(tmp, "retired.md"));
      await fs.rename(path.join(tmp, "keep.md"), path.join(tmp, "kept.md"));
      expect(await s.syncToDb(db2, embedder)).toBe(1);

      const { rows } = await db2.query("SELECT path FROM concepts ORDER BY path");
      // Stale rows are gone: no retired.md, no duplicate under the old name.
      expect(rows.map((r: any) => r.path)).toEqual(["kept.md"]);

      // Empty (but readable) dir → all rows removed.
      await fs.rm(path.join(tmp, "kept.md"));
      expect(await s.syncToDb(db2, embedder)).toBe(0);
      const { rows: empty } = await db2.query("SELECT count(*)::int AS c FROM concepts");
      expect(empty[0].c).toBe(0);

      // Unreadable dir (scan failed) → keep the last good sync, never wipe.
      await write("late.md", "Late");
      await s.syncToDb(db2, embedder);
      const missing = new ColdStore(path.join(tmp, "does-not-exist"));
      expect(await missing.syncToDb(db2, embedder)).toBe(0);
      const { rows: kept } = await db2.query("SELECT count(*)::int AS c FROM concepts");
      expect(kept[0].c).toBe(1);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
      await pg2.close();
    }
  });

  it("scopes private concepts to namespace ancestors while public concepts cross tenants", async () => {
    const pg2 = new PGlite({ extensions: { vector } });
    const db2 = {
      query: (sql: string, params?: unknown[]) => pg2.query(sql, params as any[]),
    };
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-acl-"));
    try {
      await pg2.query("CREATE EXTENSION IF NOT EXISTS vector;");
      await pg2.query(CONCEPTS_DDL);
      await pg2.query(COLD_KEYS_DDL);
      await pg2.query(COLD_STATE_DDL);
      await pg2.query(KNOWLEDGE_CONCEPTS_DDL);
      await pg2.query(KNOWLEDGE_VERSIONS_DDL);
      await pg2.query(TOMBSTONES_DDL);
      await pg2.query(ERASURE_FENCES_DDL);
      await fs.writeFile(
        path.join(tmp, "public.md"),
        "---\ntype: reference\ntitle: Public guide\nvisibility: public\n---\nshared launch glossary\n",
      );
      const scoped = new ColdStore(tmp, randomBytes(32).toString("base64"));
      await scoped.writePrivateConcept(db2, {
        path: "acme.okf.enc",
        type: "policy",
        title: "Acme secret",
        description: "",
        tags: [],
        namespace: "acme",
        body: "acme-only launch codeword",
      });
      await scoped.writePrivateConcept(db2, {
        path: "globex.okf.enc",
        type: "policy",
        title: "Globex secret",
        description: "",
        tags: [],
        namespace: "globex",
        body: "globex-only launch codeword",
      });
      expect(await scoped.syncToDb(db2, embedder)).toBe(3);

      expect((await scoped.readConcept("acme/team", "acme.okf.enc"))?.title).toBe(
        "Acme secret",
      );
      expect(await scoped.readConcept("globex/team", "acme.okf.enc")).toBeNull();
      expect((await scoped.readConcept("globex/team", "public.md"))?.title).toBe(
        "Public guide",
      );

      const acmeHits = await scoped.searchConcepts(
        db2,
        embedder,
        "acme/team",
        "launch codeword glossary",
        10,
      );
      expect(acmeHits.map((h) => h.ref)).toContain("acme.okf.enc");
      expect(acmeHits.map((h) => h.ref)).toContain("public.md");
      expect(acmeHits.map((h) => h.ref)).not.toContain("globex.okf.enc");

      const globexHits = await scoped.searchConcepts(
        db2,
        embedder,
        "globex/team",
        "launch codeword glossary",
        10,
      );
      expect(globexHits.map((h) => h.ref)).toContain("globex.okf.enc");
      expect(globexHits.map((h) => h.ref)).toContain("public.md");
      expect(globexHits.map((h) => h.ref)).not.toContain("acme.okf.enc");
      expect(await scoped.countConcepts(db2, "acme/team")).toBe(2);
      expect(await scoped.countConcepts(db2, "globex/team")).toBe(2);

      const rootNamespaceHits = await scoped.searchConcepts(
        db2,
        embedder,
        "",
        "launch codeword glossary",
        10,
      );
      expect(rootNamespaceHits.map((h) => h.ref)).toEqual(["public.md"]);
      expect(await scoped.countConcepts(db2, "")).toBe(1);

      await scoped.writePrivateConcept(db2, {
        path: "acme-source.okf.enc",
        type: "policy",
        title: "Source-team secret",
        description: "",
        tags: [],
        namespace: "acme/source",
        body: "mounted source-team knowledge",
      });
      expect(await scoped.syncToDb(db2, embedder)).toBe(4);
      expect(await scoped.countConcepts(db2, "acme/consumer")).toBe(2);
      scoped.setMountedConceptResolver(async (namespace) =>
        namespace === "acme/consumer" ? ["acme-source.okf.enc"] : []
      );
      expect(await scoped.countConcepts(db2, "acme/consumer")).toBe(3);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
      await pg2.close();
    }
  });

  it("serves only the current published version of governed logical knowledge", async () => {
    const v1 = "logical-v1";
    const v2 = "logical-v2";
    const conceptId = "logical-policy";
    const v1Path = `concepts/${v1}.okf.enc`;
    const v2Path = `concepts/${v2}.okf.enc`;
    await store.writePrivateConcept(db, {
      path: v1Path,
      namespace: "org",
      type: "policy",
      title: "Retired governed policy",
      description: "",
      tags: ["governed"],
      body: "OBSOLETE-CANARY-991 must never be returned after revision.",
    });
    await store.writePrivateConcept(db, {
      path: v2Path,
      namespace: "org",
      type: "policy",
      title: "Current governed policy",
      description: "",
      tags: ["governed"],
      body: "CURRENT-CANARY-992 is the only official revision.",
    });
    await store.syncToDb(db, new TestHashEmbedder());
    await db.query(
      `INSERT INTO knowledge_concepts (id, namespace, current_version_id, status)
       VALUES ($1, 'org', $2, 'active')`,
      [conceptId, v2],
    );
    await db.query(
      `INSERT INTO knowledge_versions (id, concept_id, path, state)
       VALUES ($1, $2, $3, 'archived'), ($4, $2, $5, 'published')`,
      [v1, conceptId, v1Path, v2, v2Path],
    );

    expect(await store.readConcept("org", v1Path)).toBeNull();
    expect((await store.readConcept("org", v2Path))?.body).toContain("CURRENT-CANARY-992");
    expect((await store.listConcepts("org")).some((concept) => concept.path === v1Path)).toBe(false);
    const results = await store.searchConcepts(db, new TestHashEmbedder(), "org", "OBSOLETE-CANARY-991", 8);
    expect(results.some((result) => result.ref === v1Path)).toBe(false);
  });

  it("rejects unowned concepts instead of making them implicitly global", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-owner-"));
    try {
      await fs.writeFile(
        path.join(tmp, "unowned.md"),
        "---\ntype: policy\ntitle: Unowned\n---\nsecret body\n",
      );
      const scoped = new ColdStore(tmp);
      expect(await scoped.listConcepts("acme")).toEqual([]);
      expect(scoped.warnings.join("\n")).toMatch(/unowned\.md.*namespace.*visibility/i);
      expect(await scoped.readConcept("acme", "unowned.md")).toBeNull();
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it("rejects paths that escape the configured knowledge directory", async () => {
    await expect(
      store.readConcept("acme", "../package.json"),
    ).rejects.toThrow(/outside|escape|relative/i);
    await expect(
      store.readConcept("acme", path.resolve(DEFAULT_KNOWLEDGE_DIR, "concepts/refund-policy.md")),
    ).rejects.toThrow(/outside|relative/i);
  });
});
