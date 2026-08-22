/**
 * Module A (M2) tests — driver core: buildScopedView, BaselineDriver,
 * DriverRegistry. Hermetic: in-memory PGlite + vector extension,
 * HashEmbedder, zero network.
 *
 * Covers the M2 contract's canary attack: rows in a sibling namespace must
 * be unreachable through the view (candidates, vectorSearch, AND
 * entityFacts), baseline ranking parity with the legacy searchL2 lane on a
 * 12-fact corpus, and the registry's unknown-name → baseline fallback.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ulid } from "ulid";

import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { MemoryIndex, namespaceAncestors } from "../src/index/index.js";
import { ColdStore } from "../src/cold/index.js";
import { HashEmbedder, HASH_EMBED_DIM } from "../src/embed/index.js";
import { searchL2, type L2IndexLike } from "../src/retrieval/index.js";
import {
  BaselineDriver,
  DriverRegistry,
  DriverUnavailableError,
  buildScopedView,
  type ViewEntitiesLike,
} from "../src/driver/index.js";
import type {
  MemoryObject,
  Namespace,
  RetrieverDriver,
  RetrieverQuery,
  ScopedView,
  ScoredRef,
} from "../src/types.js";

const NS_A = "acme/alpha";
const NS_B = "acme/beta";
const NS_PARITY = "parity/corp";

const embedder = new HashEmbedder();

let db: Db;
let index: MemoryIndex;
let cold: ColdStore;
let entities: ViewEntitiesLike;
let viewA: ScopedView;
let viewB: ScopedView;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

async function insertFact(
  ns: Namespace,
  content: string,
  provenance?: MemoryObject["provenance"],
): Promise<string> {
  const id = ulid();
  const now = new Date().toISOString();
  const obj: MemoryObject = {
    id,
    namespace: ns,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content,
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: provenance ?? [{ source: "manual", actor: "test", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  const [emb] = await embedder.embed([content]);
  await index.insert(obj, emb);
  return id;
}

async function insertEntity(
  ns: Namespace,
  canonicalName: string,
  aliases: string[],
): Promise<void> {
  const [emb] = await embedder.embed([canonicalName]);
  await db.query(
    `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, embedding, created_at)
     VALUES ($1, $2, $3, $4, $5::vector, $6)`,
    [
      ulid(),
      ns,
      canonicalName,
      JSON.stringify(aliases),
      `[${emb.join(",")}]`,
      new Date().toISOString(),
    ],
  );
}

/** Test-side ACL-scoped read-only entity reader (kernel wires the real one). */
function makeEntityReader(handle: Db): ViewEntitiesLike {
  return {
    async listEntities(namespace) {
      const allowed = namespaceAncestors(namespace);
      const ph = allowed.map((_, i) => `$${i + 1}`).join(", ");
      const res = await handle.query(
        `SELECT canonical_name, aliases FROM entity_registry WHERE namespace IN (${ph})`,
        allowed,
      );
      return res.rows.map((r: Record<string, unknown>) => ({
        canonicalName: r.canonical_name as string,
        aliases: Array.isArray(r.aliases)
          ? (r.aliases as string[])
          : (JSON.parse(String(r.aliases ?? "[]")) as string[]),
      }));
    },
  };
}

/** Same adapter shape the syscall layer uses for the legacy searchL2 lane. */
function toL2IndexLike(idx: MemoryIndex): L2IndexLike {
  return {
    async vectorSearch(namespace, queryEmbedding, k, validOnly) {
      const hits = await idx.vectorSearch(namespace, queryEmbedding, k, validOnly);
      return hits.map((h) => ({
        ref: h.obj.id,
        score: h.similarity,
        content: h.obj.content,
      }));
    },
    async listCandidates(namespace, validOnly) {
      const rows = await idx.listCandidates(namespace, { validOnly });
      return rows.map((r) => ({ ref: r.id, content: r.content }));
    },
    async lexicalCandidates(namespace, query, k, validOnly) {
      const rows = await idx.listLexicalCandidates(namespace, query, {
        validOnly,
        limit: k,
      });
      return rows.map((r) => ({ ref: r.id, content: r.content }));
    },
  };
}

// Fact ids captured during seeding.
const aIds: Record<string, string> = {};
const bIds: string[] = [];

beforeAll(async () => {
  db = await createDb(
    loadConfig({
      databaseUrl: "",
      pgliteDataDir: "",
      openaiApiKey: "",
      embedDim: HASH_EMBED_DIM,
    }),
  );
  await migrate(db, HASH_EMBED_DIM);
  index = new MemoryIndex(db);
  cold = new ColdStore("./nonexistent-knowledge-dir");
  entities = makeEntityReader(db);

  const deps = { db, index, cold, entities, embedder };
  viewA = buildScopedView(deps, NS_A);
  viewB = buildScopedView(deps, NS_B);

  // --- namespace A corpus -------------------------------------------------
  aIds.launch = await insertFact(NS_A, "Nimbus launch is scheduled for March");
  aIds.lead = await insertFact(NS_A, "Sarah Chen leads the Nimbus rollout");
  aIds.standup = await insertFact(NS_A, "Sarah Chen prefers async standups");
  aIds.weekly = await insertFact(NS_A, "The alpha team ships every Friday");
  aIds.sales = await insertFact(
    NS_A,
    '[company-file] {"purpose":"sales","businessFunction":"Sales team","dataSensitive":true}\n\naccount,stage\nNorthwind,Closed Won',
    [{
      source: "document",
      actor: "ingest",
      sourceId: "company-file-source",
      documentKey: "sales.csv",
      ts: new Date().toISOString(),
    }],
  );
  await insertEntity(NS_A, "Project Nimbus", ["Nimbus"]);
  await insertEntity(NS_A, "Sarah Chen", []);

  // --- namespace B canaries (must NEVER surface through view A) ------------
  bIds.push(await insertFact(NS_B, "CANARY the beta payroll runs on Nimbus"));
  bIds.push(await insertFact(NS_B, "CANARY Sarah Chen salary is confidential"));
  // B-side entity sharing the alias "Nimbus": invisible to view A's reader.
  await insertEntity(NS_B, "Nimbus Payroll", ["Nimbus"]);

  // L3 canaries exercise the same namespace fence through ScopedView.
  const now = new Date().toISOString();
  await db.query(
    `INSERT INTO cold_kek_state
       (singleton, active_kek_id, generation, maintenance, updated_at)
     VALUES (TRUE, 'fixture-kek', 1, FALSE, $1)
     ON CONFLICT (singleton) DO UPDATE SET active_kek_id = EXCLUDED.active_kek_id,
       generation = EXCLUDED.generation, maintenance = FALSE, updated_at = EXCLUDED.updated_at`,
    [now],
  );
  for (const [conceptPath, namespace, visibility, title, body] of [
    ["concepts/a-private.md", NS_A, null, "Alpha private", "alpha L3 canary"],
    ["concepts/b-private.md", NS_B, null, "Beta private", "beta L3 canary"],
    ["concepts/public.md", null, "public", "Public reference", "shared L3 guide"],
  ] as const) {
    await db.query(
      `INSERT INTO concepts
         (path, type, title, description, tags, namespace, visibility, body, synced_at)
       VALUES ($1, 'reference', $2, '', '[]', $3, $4, $5, $6)`,
      [conceptPath, title, namespace, visibility, body, now],
    );
    if (namespace !== null) {
      await db.query(
        `INSERT INTO cold_concept_keys
           (path, wrapped_dek, wrap_iv, wrap_tag, created_at, namespace,
            pii_subjects, kek_id, envelope_version, write_state, kek_generation)
         VALUES ($1, 'fixture-dek', 'fixture-iv', 'fixture-tag', $2, $3,
                 '[]', 'fixture-kek', 2, 'committed', 1)`,
        [conceptPath, now, namespace],
      );
    }
  }
}, 60_000);

afterAll(async () => {
  await db.close();
});

// ---------------------------------------------------------------------------
// ScopedView — namespace fence
// ---------------------------------------------------------------------------

describe("buildScopedView - ACL fence (two namespaces, one PGlite)", () => {
  it("candidates(): ns-A view never returns ns-B rows", async () => {
    const rows = await viewA.candidates();
    const refs = rows.map((r) => r.ref);
    expect(refs).toEqual(expect.arrayContaining(Object.values(aIds)));
    for (const b of bIds) expect(refs).not.toContain(b);
    for (const r of rows) expect(r.content).not.toContain("CANARY");
  });

  it("projects an existing company-file documentKey into retrieval without rewriting memory", async () => {
    const candidates = await viewA.candidates();
    const sales = candidates.find((row) => row.ref === aIds.sales);
    expect(sales?.content).toContain(
      '[company-file-source] {"fileName":"sales.csv"}',
    );

    const driver = new BaselineDriver();
    const hits = await driver.plan({
      query: "sales.csv",
      view: viewA,
      k: 3,
      tokenBudget: 2_000,
    });
    expect(hits[0]?.ref).toBe(aIds.sales);
    expect(hits[0]?.content).toContain('"fileName":"sales.csv"');

    const canonical = await index.getById(aIds.sales, NS_A);
    expect(canonical.obj?.content).not.toContain("[company-file-source]");
  });

  it("lexicalCandidates searches the full governed projection without crossing the ACL fence", async () => {
    const rows = await viewA.lexicalCandidates!("Project Nimbus rollout", 20);
    const refs = rows.map((row) => row.ref);
    expect(refs).toEqual(expect.arrayContaining([aIds.launch, aIds.lead]));
    for (const b of bIds) expect(refs).not.toContain(b);
    for (const row of rows) expect(row.content).not.toContain("CANARY");
  });

  it("vectorSearch(): canary rows unreachable even with a targeted query", async () => {
    const [emb] = await viewA.embed(["CANARY beta payroll salary confidential"]);
    const hits = await viewA.vectorSearch(emb, 10);
    const refs = hits.map((h) => h.ref);
    for (const b of bIds) expect(refs).not.toContain(b);
    for (const h of hits) expect(h.content).not.toContain("CANARY");
  });

  it("entityFacts hop 1: alias match (ci) returns only ns-A facts, tagged with the canonical name", async () => {
    const facts = await viewA.entityFacts("nimbus", 1);
    const refs = facts.map((f) => f.ref);
    expect(refs).toEqual(expect.arrayContaining([aIds.launch, aIds.lead]));
    // Hop-2-only fact excluded at hop 1.
    expect(refs).not.toContain(aIds.standup);
    // Canary fence: B facts mention "Nimbus" too — must not appear.
    for (const b of bIds) expect(refs).not.toContain(b);
    for (const f of facts) {
      expect(f.entity).toBe("Project Nimbus");
      expect(f.content).not.toContain("CANARY");
    }
  });

  it("entityFacts hop 2: co-mentioned entity pulls its own facts, still no ns-B rows", async () => {
    const facts = await viewA.entityFacts("Nimbus", 2);
    const refs = facts.map((f) => f.ref);
    // hop 1 facts first, then Sarah Chen's other fact via co-mention in
    // "Sarah Chen leads the Nimbus rollout".
    expect(refs).toEqual(
      expect.arrayContaining([aIds.launch, aIds.lead, aIds.standup]),
    );
    const standup = facts.find((f) => f.ref === aIds.standup);
    expect(standup?.entity).toBe("Sarah Chen");
    // Dedup: each ref once.
    expect(new Set(refs).size).toBe(refs.length);
    for (const b of bIds) expect(refs).not.toContain(b);
  });

  it("entityFacts: unknown mention and empty mention → []", async () => {
    expect(await viewA.entityFacts("Zorblax", 2)).toEqual([]);
    expect(await viewA.entityFacts("   ", 1)).toEqual([]);
  });

  it("entityFacts: short names/aliases match whole words only - no phantom substring edges", async () => {
    // Entity 'Ann' (alias 'Bo'): substrings of "planning", "channel",
    // "scanner", "keyboard" — none of these facts mention the entity.
    await insertEntity(NS_A, "Ann", ["Bo"]);
    const phantoms = [
      await insertFact(NS_A, "the team is planning the channel scanner rollout"),
      await insertFact(NS_A, "the keyboard shortcuts doc moved to the wiki"),
    ];
    const genuine = [
      await insertFact(NS_A, "Ann approved the migration window on Friday"),
      await insertFact(NS_A, "Bo owns the incident postmortem template"),
      await insertFact(NS_A, "ping ann, about the audit (punctuation still counts)"),
    ];

    const refs = (await viewA.entityFacts("ann", 1)).map((f) => f.ref);
    for (const p of phantoms) expect(refs).not.toContain(p);
    for (const g of genuine) expect(refs).toContain(g);

    // Hop 2 must not resurrect the phantom edges either.
    const refs2 = (await viewA.entityFacts("ann", 2)).map((f) => f.ref);
    for (const p of phantoms) expect(refs2).not.toContain(p);
  });

  it("ns-B view sees its own rows but none of ns-A's (no sideways flow either way)", async () => {
    const rows = await viewB.candidates();
    const refs = rows.map((r) => r.ref);
    for (const b of bIds) expect(refs).toContain(b);
    for (const a of Object.values(aIds)) expect(refs).not.toContain(a);
    // B's entityFacts resolves via B's own "Nimbus Payroll" alias.
    const facts = await viewB.entityFacts("Nimbus", 1);
    expect(facts.length).toBeGreaterThan(0);
    for (const f of facts) expect(bIds).toContain(f.ref);
  });

  it("concepts(): private rows stay tenant-scoped and explicit public rows cross tenants", async () => {
    const aRefs = (await viewA.concepts("L3", 10)).map((row) => row.ref);
    expect(aRefs).toContain("concepts/a-private.md");
    expect(aRefs).toContain("concepts/public.md");
    expect(aRefs).not.toContain("concepts/b-private.md");

    const bRefs = (await viewB.concepts("L3", 10)).map((row) => row.ref);
    expect(bRefs).toContain("concepts/b-private.md");
    expect(bRefs).toContain("concepts/public.md");
    expect(bRefs).not.toContain("concepts/a-private.md");
  });
});

// ---------------------------------------------------------------------------
// BaselineDriver — parity with legacy searchL2
// ---------------------------------------------------------------------------

describe("BaselineDriver - ranking parity with searchL2 on a 12-fact corpus", () => {
  const corpus = [
    "the refund policy allows returns within thirty days",
    "quarterly revenue grew twelve percent this year",
    "shipping times vary by region and carrier",
    "the gpu cluster is down for maintenance on sunday",
    "support hours are nine to five on weekdays",
    "enterprise customers get a dedicated account manager",
    "the refund window for enterprise plans is sixty days",
    "invoices are issued on the first business day of the month",
    "the mobile app release train ships every two weeks",
    "database backups run nightly at two am utc",
    "customer churn dropped after the onboarding redesign",
    "the api rate limit is one thousand requests per minute",
  ];
  const queries = [
    "refund policy returns window",
    "gpu cluster maintenance",
    "quarterly revenue growth",
    "api rate limit requests",
  ];

  const driver = new BaselineDriver();
  let parityView: ScopedView;

  beforeAll(async () => {
    for (const content of corpus) await insertFact(NS_PARITY, content);
    parityView = buildScopedView({ db, index, cold, entities, embedder }, NS_PARITY);
  }, 60_000);

  it("has the contract name and capabilities", () => {
    expect(driver.name).toBe("baseline");
    expect(driver.capabilities()).toEqual({ graph: false, streaming: false });
  });

  it("plan() top-3 matches legacy searchL2 top-3 (refs AND scores) for every query", async () => {
    for (const query of queries) {
      const legacy = await searchL2(toL2IndexLike(index), embedder, {
        namespace: NS_PARITY,
        query,
        k: 8,
        tokenBudget: 2000,
      });
      const planned = await driver.plan({
        query,
        view: parityView,
        k: 8,
        tokenBudget: 2000,
      });
      expect(planned.map((r) => r.ref).slice(0, 3)).toEqual(
        legacy.map((r) => r.ref).slice(0, 3),
      );
      expect(planned.map((r) => r.score.toFixed(10))).toEqual(
        legacy.map((r) => r.score.toFixed(10)),
      );
      // ScoredRef shape: L2, id === ref.
      for (const r of planned) {
        expect(r.tier).toBe("L2");
        expect(r.id).toBe(r.ref);
      }
    }
  });

  it("respects k and the token budget; k <= 0 → []", async () => {
    const q: RetrieverQuery = {
      query: "refund policy returns",
      view: parityView,
      k: 2,
      tokenBudget: 2000,
    };
    expect((await driver.plan(q)).length).toBeLessThanOrEqual(2);

    const tight = await driver.plan({ ...q, k: 5, tokenBudget: 1 });
    expect(tight).toHaveLength(1); // top hit always survives the trim

    expect(await driver.plan({ ...q, k: 0 })).toEqual([]);
  });

  it("skips an oversized middle hit instead of hiding later evidence that fits", async () => {
    const view: ScopedView = {
      ...parityView,
      lexicalCandidates: async () => [],
      vectorSearch: async () => [
        { ref: "short-first", content: "alpha evidence", score: 1 },
        { ref: "oversized-middle", content: "alpha ".repeat(2_000), score: 0.9 },
        { ref: "short-later", content: "alpha compact proof", score: 0.8 },
      ],
    };
    const hits = await driver.plan({
      query: "alpha",
      view,
      k: 3,
      tokenBudget: 20,
    });
    expect(hits.map((hit) => hit.ref)).toEqual(["short-first", "short-later"]);
  });

  it("is deterministic: same query twice → same refs", async () => {
    const q: RetrieverQuery = {
      query: "enterprise refund window",
      view: parityView,
      k: 5,
      tokenBudget: 2000,
    };
    const a = await driver.plan(q);
    const b = await driver.plan(q);
    expect(a.map((r) => r.ref)).toEqual(b.map((r) => r.ref));
  });
});

// ---------------------------------------------------------------------------
// DriverRegistry
// ---------------------------------------------------------------------------

describe("DriverRegistry", () => {
  function fakeDriver(name: string): RetrieverDriver {
    return {
      name,
      capabilities: () => ({ graph: true, streaming: false }),
      plan: async (_q: RetrieverQuery): Promise<ScoredRef[]> => [],
    };
  }

  it("mount/get/list round-trip", () => {
    const registry = new DriverRegistry({ warn: () => {} });
    const baseline = new BaselineDriver();
    const graph = fakeDriver("graph");
    registry.mount(baseline);
    registry.mount(graph);
    expect(registry.list()).toEqual(["baseline", "graph"]);
    expect(registry.get("baseline")).toBe(baseline);
    expect(registry.get("graph")).toBe(graph);
  });

  it("unknown name → baseline fallback + warn log", () => {
    const warns: string[] = [];
    const registry = new DriverRegistry({ warn: (m) => warns.push(m) });
    const baseline = new BaselineDriver();
    registry.mount(baseline);
    const got = registry.get("mem0-typo");
    expect(got).toBe(baseline);
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('"mem0-typo"');
    expect(warns[0]).toContain('"baseline"');
  });

  it("unknown name with no baseline mounted → DriverUnavailableError", () => {
    const registry = new DriverRegistry({ warn: () => {} });
    registry.mount(fakeDriver("graph"));
    let err: unknown;
    try {
      registry.get("nope");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DriverUnavailableError);
    expect((err as DriverUnavailableError).driver).toBe("nope");
    expect((err as DriverUnavailableError).name).toBe("DriverUnavailableError");
  });

  it("remount replaces under the same name; unnamed driver rejected", () => {
    const registry = new DriverRegistry({ warn: () => {} });
    const first = fakeDriver("baseline");
    const second = fakeDriver("baseline");
    registry.mount(first);
    registry.mount(second);
    expect(registry.get("baseline")).toBe(second);
    expect(registry.list()).toEqual(["baseline"]);
    expect(() => registry.mount(fakeDriver(""))).toThrow(/no name/);
  });

  it("fallback driver actually serves a plan over the view", async () => {
    const registry = new DriverRegistry({ warn: () => {} });
    registry.mount(new BaselineDriver());
    const driver = registry.get("not-a-driver");
    const refs = await driver.plan({
      query: "Nimbus launch March",
      view: viewA,
      k: 3,
      tokenBudget: 2000,
    });
    expect(refs.length).toBeGreaterThan(0);
    expect(refs[0].ref).toBe(aIds.launch);
    for (const b of bIds) expect(refs.map((r) => r.ref)).not.toContain(b);
  });
});
