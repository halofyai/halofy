/**
 * Module E tests — write path + StubLlm + EntityRegistry.
 * Hermetic: in-memory PGlite (vector extension), deterministic HashEmbedder,
 * StubLlm. Zero network.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { vector } from "@electric-sql/pglite/vector";
import type {
  AuditEvent,
  Embedder,
  LlmClient,
  MemoryId,
  MemoryObject,
  Namespace,
  PolicyConfig,
} from "../src/types.js";
import { loadConfig } from "../src/config.js";
import {
  ENTITY_MARKER,
  EXTRACT_MARKER,
  StubLlm,
  VERIFY_BATCH_MARKER,
  VERIFY_MARKER,
  createLlm,
  parseLooseJson,
} from "../src/llm/index.js";
import { EntityRegistry, toVectorLiteral, type DbLike } from "../src/write/entities.js";
import { namespaceAncestors } from "../src/index/index.js";
import {
  WritePath,
  type AuditSink,
  type MemoryIndexLike,
  type VectorHit,
  type WritePathDeps,
} from "../src/write/index.js";
import { LlmUnavailableError } from "../src/resilience/index.js";

const EMBED_DIM = 256;

const DDL = `
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS memory_objects (
  id            TEXT PRIMARY KEY,
  namespace     TEXT NOT NULL,
  scope         TEXT NOT NULL CHECK (scope IN ('user','assistant','team','org')),
  tier          TEXT NOT NULL CHECK (tier IN ('L2','L3')),
  backend_ref   TEXT NOT NULL,
  content       TEXT NOT NULL,
  type          TEXT NOT NULL,
  confidence    REAL NOT NULL,
  event_time    TIMESTAMPTZ,
  assertion_time TIMESTAMPTZ NOT NULL,
  t_valid_from  TIMESTAMPTZ NOT NULL,
  t_valid_to    TIMESTAMPTZ,
  supersedes    TEXT REFERENCES memory_objects(id),
  provenance    JSONB NOT NULL DEFAULT '[]',
  ttl_seconds   INTEGER,
  last_accessed TIMESTAMPTZ,
  access_count  INTEGER NOT NULL DEFAULT 0,
  fault_count   INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','tombstoned','disputed')),
  embedding     vector(${EMBED_DIM})
);
CREATE INDEX IF NOT EXISTS idx_mem_ns ON memory_objects(namespace, status);
CREATE INDEX IF NOT EXISTS idx_mem_valid ON memory_objects(namespace, t_valid_to);

CREATE TABLE IF NOT EXISTS fact_disputes (
  id                   TEXT PRIMARY KEY,
  namespace            TEXT NOT NULL,
  memory_id            TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
  disputed_against     TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
  category             TEXT NOT NULL CHECK (category IN ('policies-legal','order-management','product-info','other')),
  reason               TEXT NOT NULL,
  status               TEXT NOT NULL CHECK (status IN ('open','resolved')),
  resolution           TEXT CHECK (resolution IN ('uphold-new','keep-old','edit','retracted')),
  resolution_memory_id TEXT,
  resolved_by          TEXT,
  resolved_at          TIMESTAMPTZ,
  row_version          INTEGER NOT NULL DEFAULT 1,
  created_at           TIMESTAMPTZ NOT NULL,
  updated_at           TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_registry (
  id             TEXT PRIMARY KEY,
  namespace      TEXT NOT NULL,
  canonical_name TEXT NOT NULL,
  aliases        JSONB NOT NULL DEFAULT '[]',
  embedding      vector(${EMBED_DIM}),
  created_at     TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_ns_name ON entity_registry(namespace, canonical_name);

CREATE TABLE IF NOT EXISTS erasure_fences (
  namespace  TEXT PRIMARY KEY,
  generation BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL
);

-- CA1: the write path enqueues every committed fact for its conflict check in
-- the SAME transaction, so this fixture carries the outbox exactly as it
-- carries fact_disputes. Its presence is what makes the audit-failure cases
-- below prove a full rollback of the write AND its queued check.
CREATE TABLE IF NOT EXISTS entity_tag_queue (
  memory_id     TEXT PRIMARY KEY,
  namespace     TEXT NOT NULL,
  enqueued_at   TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending',
  attempts      INTEGER NOT NULL DEFAULT 0,
  retry_at      TIMESTAMPTZ,
  lease_owner   TEXT,
  lease_until   TIMESTAMPTZ,
  last_error    TEXT,
  completed_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS conflict_detection_queue (
  memory_id     TEXT PRIMARY KEY,
  namespace     TEXT NOT NULL,
  enqueued_at   TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending',
  attempts      INTEGER NOT NULL DEFAULT 0,
  retry_at      TIMESTAMPTZ,
  lease_owner   TEXT,
  lease_until   TIMESTAMPTZ,
  last_error    TEXT,
  completed_at  TIMESTAMPTZ,
  detector_version TEXT NOT NULL DEFAULT 'luna-context-v1',
  candidate_cursor INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq        BIGSERIAL PRIMARY KEY,
  ts         TIMESTAMPTZ NOT NULL,
  actor      TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  op         TEXT NOT NULL,
  memory_id  TEXT,
  namespace  TEXT NOT NULL,
  purpose    TEXT,
  result     TEXT NOT NULL,
  detail     TEXT
);
`;

// ---------------------------------------------------------------------------
// Deterministic HashEmbedder (module-C style; local to keep the test hermetic)
// ---------------------------------------------------------------------------

function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

class HashEmbedder implements Embedder {
  readonly name = "hash";
  readonly dim = EMBED_DIM;

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((t) => {
      const v = new Array<number>(this.dim).fill(0);
      const words = t
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, " ")
        .split(" ")
        .filter(Boolean);
      for (const w of words) v[fnv1a(w) % this.dim]! += 1;
      const norm = Math.hypot(...v) || 1;
      return v.map((x) => x / norm);
    });
  }
}

// ---------------------------------------------------------------------------
// Test-local implementations of the module-A structural interfaces
// ---------------------------------------------------------------------------

class TestIndex implements MemoryIndexLike {
  private readonly objects = new Map<MemoryId, MemoryObject>();

  constructor(private readonly db: DbLike) {}

  async insert(obj: MemoryObject, embedding: number[] | null): Promise<void> {
    this.objects.set(obj.id, obj);
    await this.db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
          provenance, ttl_seconds, last_accessed, access_count, fault_count,
          status, embedding)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::vector)`,
      [
        obj.id,
        obj.namespace,
        obj.scope,
        obj.tier,
        obj.backendRef,
        obj.content,
        obj.type,
        obj.confidence,
        obj.eventTime,
        obj.assertionTime,
        obj.tValidFrom,
        obj.tValidTo,
        obj.supersedes,
        JSON.stringify(obj.provenance),
        obj.ttlSeconds,
        obj.telemetry.lastAccessed,
        obj.telemetry.accessCount,
        obj.telemetry.faultCount,
        obj.status,
        embedding ? toVectorLiteral(embedding) : null,
      ],
    );
  }

  async vectorSearch(
    namespace: Namespace,
    embedding: number[],
    k: number,
  ): Promise<VectorHit[]> {
    // ACL-scoped exactly like the real MemoryIndex.vectorSearch: prefix
    // ancestors are visible, so the write path's own-namespace guard for
    // dedupe/supersedence is actually exercised here.
    const allowed = namespaceAncestors(namespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 2}`).join(", ");
    const res = await this.db.query<{
      id: string;
      cosine: number | string;
    }>(
      `SELECT id, 1 - (embedding <=> $1::vector) AS cosine
       FROM memory_objects
       WHERE namespace IN (${nsPlaceholders}) AND status = 'active' AND t_valid_to IS NULL
         AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector
       LIMIT $${allowed.length + 2}`,
      [toVectorLiteral(embedding), ...allowed, k],
    );
    return res.rows.flatMap((r) => {
      const obj = this.objects.get(r.id);
      return obj ? [{ obj, similarity: Number(r.cosine) }] : [];
    });
  }

  async bumpAccess(ids: MemoryId[]): Promise<void> {
    if (ids.length === 0) return;
    const placeholders = ids.map((_, i) => `$${i + 2}`).join(", ");
    await this.db.query(
      `UPDATE memory_objects
       SET access_count = access_count + 1, last_accessed = $1
       WHERE id IN (${placeholders})`,
      [new Date().toISOString(), ...ids],
    );
  }

  async closeValidity(id: MemoryId, atIso: string): Promise<void> {
    await this.db.query(
      `UPDATE memory_objects SET t_valid_to = $2 WHERE id = $1`,
      [id, atIso],
    );
  }
}

class TestAudit implements AuditSink {
  readonly events: AuditEvent[] = [];

  constructor(private readonly db: DbLike) {}

  async append(event: AuditEvent): Promise<void> {
    this.events.push(event);
    await this.db.query(
      `INSERT INTO audit_log (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        event.ts,
        event.actor,
        event.agentId,
        event.op,
        event.memoryId,
        event.namespace,
        event.purpose,
        event.result,
        event.detail ?? null,
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const NS = "org/team/agent/user1";

const policy: PolicyConfig = {
  namespace: NS,
  tokenBudget: 3000,
  ttlDefaultsSeconds: { user: 3600, assistant: 1800, team: null, org: null },
  pinnedConcepts: [],
  dedupeSimilarityThreshold: 0.92,
  verifierEnabled: true,
};

let db: PGlite;
let index: TestIndex;
let audit: TestAudit;
let embedder: HashEmbedder;
let stub: StubLlm;
let deps: WritePathDeps;
let writePath: WritePath;

beforeEach(async () => {
  db = new PGlite({ extensions: { vector } });
  await db.exec(DDL);
  index = new TestIndex(db);
  audit = new TestAudit(db);
  embedder = new HashEmbedder();
  stub = new StubLlm();
  deps = {
    db,
    index,
    audit,
    embedder,
    llm: stub,
    config: loadConfig({
      databaseUrl: "",
      pgliteDataDir: "",
      embedDim: EMBED_DIM,
      anthropicApiKey: "",
      openaiApiKey: "",
    }),
  };
  writePath = new WritePath(deps);
});

afterEach(async () => {
  await db.close();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createLlm", () => {
  it("returns StubLlm without an api key and AnthropicLlm with one", () => {
    expect(createLlm(deps.config).name).toBe("stub");
    expect(
      createLlm(loadConfig({ ...deps.config, anthropicApiKey: "sk-test" })).name,
    ).toBe("anthropic");
  });
});

describe("WritePath", () => {
  it("rejects upload metadata artifacts while keeping the meaningful extracted claim", async () => {
    const llm: LlmClient = {
      name: "fact-quality-test",
      complete: async (system) => system.includes(EXTRACT_MARKER)
        ? JSON.stringify([
            { content: "This statement contains marker X", speaker: "user", eventTime: null, entities: [], confidence: 0.9 },
            { content: "Acme refunds are available for 14 days", speaker: "user", eventTime: null, entities: ["Acme"], confidence: 0.9 },
          ])
        : JSON.stringify({ verified: true, reason: "grounded" }),
    };
    const result = await new WritePath({ ...deps, llm }).write({ namespace: NS, scope: "org", content: "This statement contains marker X. Acme refunds are available for 14 days.", actor: "connector:test", provenance: { source: "document", sourceId: "file:test" } }, policy);
    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]?.content).toContain("Acme refunds are available for 14 days");
    expect(result.rejected).toEqual([{ candidate: "This statement contains marker X", reason: "low-information-fact" }]);
    expect(audit.events.some((event) => event.op === "reject" && event.detail === "low-information-fact")).toBe(true);
  });

  it("preserves governance metadata on every stored fact", async () => {
    const sourceAccess = {
      principals: ["user:42"],
      groups: ["legal"],
      inheritedFrom: "space:legal",
    };
    const classification = {
      sensitivity: "restricted" as const,
      piiSubjects: ["email"],
      secretKinds: [],
      residency: "eu",
      allowedDestinations: ["canonical-l2", "embedding-provider"],
    };

    const result = await writePath.write(
      {
        namespace: NS,
        scope: "org",
        content: "Contact legal@example.com",
        actor: "ingest",
        hints: { verbatim: true },
        provenance: {
          source: "document",
          sourceId: "notion:legal",
          sourceAccess,
          classification,
        },
      },
      {
        ...policy,
        dataRegion: "eu",
        restrictedDestinations: ["canonical-l2", "embedding-provider"],
      },
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]?.provenance[0]).toMatchObject({
      sourceAccess,
      classification,
    });
  });

  function extractingLlm(entity: string): LlmClient {
    return {
      name: "entity-extractor",
      complete: async (system) =>
        system.includes(EXTRACT_MARKER)
          ? JSON.stringify([
              {
                content: `${entity} signed the agreement`,
                speaker: "user",
                eventTime: null,
                entities: [entity],
                confidence: 0.9,
              },
            ])
          : JSON.stringify({ verified: true, reason: "grounded" }),
    };
  }

  function writePathWithFailingTransactionalAudit(llm: LlmClient): WritePath {
    return new WritePath({
      ...deps,
      llm,
      transact: (fn) =>
        db.transaction(async (rawTx) => {
          const tx = rawTx as unknown as DbLike;
          return fn(
            new TestIndex(tx),
            { append: async () => { throw new Error("injected audit failure"); } },
            tx,
          );
        }),
    });
  }

  it("rolls back a newly extracted entity and its fences when the write audit fails", async () => {
    const wp = writePathWithFailingTransactionalAudit(extractingLlm("Alice"));

    await expect(
      wp.write(
        {
          namespace: NS,
          scope: "user",
          content: "Alice signed the agreement",
          actor: "tester",
        },
        policy,
      ),
    ).rejects.toThrow("injected audit failure");

    const entities = await db.query(`SELECT id FROM entity_registry WHERE namespace = $1`, [NS]);
    const memories = await db.query(`SELECT id FROM memory_objects WHERE namespace = $1`, [NS]);
    const fences = await db.query(`SELECT namespace FROM erasure_fences`);
    expect(entities.rows).toHaveLength(0);
    expect(memories.rows).toHaveLength(0);
    expect(fences.rows).toHaveLength(0);
  });

  it("rolls back an extracted alias update and fence generations when the write audit fails", async () => {
    const registry = new EntityRegistry(db, embedder, stub);
    const original = await registry.resolve(NS, "Acme Corp Holdings International");
    const fencesBefore = await db.query<{ namespace: string; generation: number | string }>(
      `SELECT namespace, generation FROM erasure_fences ORDER BY namespace`,
    );
    const wp = writePathWithFailingTransactionalAudit(
      extractingLlm("Acme Corp Holdings International Ltd"),
    );

    await expect(
      wp.write(
        {
          namespace: NS,
          scope: "user",
          content: "Acme Corp Holdings International Ltd signed the agreement",
          actor: "tester",
        },
        policy,
      ),
    ).rejects.toThrow("injected audit failure");

    const entity = await db.query<{ aliases: string[] | string }>(
      `SELECT aliases FROM entity_registry WHERE id = $1`,
      [original.id],
    );
    const aliases = typeof entity.rows[0]!.aliases === "string"
      ? JSON.parse(entity.rows[0]!.aliases) as string[]
      : entity.rows[0]!.aliases;
    const fencesAfter = await db.query<{ namespace: string; generation: number | string }>(
      `SELECT namespace, generation FROM erasure_fences ORDER BY namespace`,
    );
    expect(aliases).toEqual([]);
    expect(fencesAfter.rows.map((row) => ({ ...row, generation: Number(row.generation) })))
      .toEqual(fencesBefore.rows.map((row) => ({ ...row, generation: Number(row.generation) })));
  });

  it("retries a candidate from fresh preparation when the entity registry drifts mid-write", async () => {
    // Regression (production 2026-08-20): concurrent upload lanes registering
    // similar entities made resolvePrepared throw EntityResolutionConflictError,
    // which failed the whole record — no caller retried extracted (non-verbatim)
    // writes. Stage the exact drift deterministically: prepare() sees an exact
    // registry row (so it skips embedding), then the row vanishes before the
    // commit transaction runs — resolvePrepared must fail closed. The write
    // path now re-runs the candidate from a fresh preparation, which embeds
    // the mention and lands it as a new entity record.
    const registry = new EntityRegistry(db, embedder, stub);
    const seeded = await registry.resolve(NS, "Acme Corp");
    let transactCalls = 0;
    const wp = new WritePath({
      ...deps,
      llm: extractingLlm("Acme Corp"),
      transact: async (fn) => {
        transactCalls += 1;
        if (transactCalls === 1) {
          // Simulate the concurrent lane winning the window between
          // prepare() and the transaction: the exact row prepare() saw is
          // gone by the time the commit runs. Outside the transaction on
          // purpose — a rollback must not resurrect it.
          await db.query(`DELETE FROM entity_registry WHERE id = $1`, [seeded.id]);
        }
        return db.transaction(async (rawTx) => {
          const tx = rawTx as unknown as DbLike;
          return fn(new TestIndex(tx), new TestAudit(tx), tx);
        });
      },
    });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "Acme Corp signed the agreement",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]?.content).toContain("[entities: Acme Corp]");
    expect(transactCalls).toBeGreaterThanOrEqual(2);
    const rows = await db.query<{ canonical_name: string }>(
      `SELECT canonical_name FROM entity_registry WHERE namespace = $1`,
      [NS],
    );
    expect(rows.rows.map((row) => row.canonical_name)).toEqual(["Acme Corp"]);
  });

  it("verbatim write stores one fact with provenance and an audit row", async () => {
    const result = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content: "Customer prefers email contact",
        actor: "tester",
        session: "s1",
        hints: { verbatim: true },
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.rejected).toHaveLength(0);
    expect(result.deduplicated).toBe(0);

    const fact = result.stored[0]!;
    expect(fact.tier).toBe("L2");
    expect(fact.backendRef).toBe("inline");
    expect(fact.content).toBe("Customer prefers email contact");
    expect(fact.tValidTo).toBeNull();
    expect(fact.ttlSeconds).toBe(3600);
    expect(fact.provenance).toEqual([
      {
        extraction: "verbatim",
        source: "conversation",
        actor: "tester",
        session: "s1",
        sourceAccess: { principals: [], groups: [] },
        classification: {
          sensitivity: "internal",
          piiSubjects: [],
          secretKinds: [],
          allowedDestinations: [],
        },
        ts: fact.assertionTime,
      },
    ]);

    const rows = await db.query<{ id: string; content: string }>(
      `SELECT id, content FROM memory_objects`,
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]!.id).toBe(fact.id);

    const auditRows = await db.query<{ op: string; result: string; memory_id: string }>(
      `SELECT op, result, memory_id FROM audit_log`,
    );
    expect(auditRows.rows).toEqual([
      { op: "write", result: "ok", memory_id: fact.id },
    ]);
  });

  it("localOnly ingestion write lands with derived entity annotation and zero egress", async () => {
    // DLP brownout lane (sink retries a classification-denied document write
    // with verbatim+localOnly): registry resolution would egress the classified
    // content, but the fact must still carry [entities: …] or conflict scans
    // skip it as entity_metadata_unavailable.
    let llmCalls = 0;
    const countingLlm: LlmClient = {
      name: "counting-stub",
      complete: async (system, user) => {
        llmCalls += 1;
        return stub.complete(system, user);
      },
    };
    const wp = new WritePath({ ...deps, llm: countingLlm });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "org",
        content: "Northwind Enterprise renewed the East region contract",
        actor: "ingest",
        hints: { verbatim: true, localOnly: true },
        provenance: { source: "document", sourceId: "fs:handbook" },
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]!.content).toBe(
      "Northwind Enterprise renewed the East region contract [entities: Northwind, Enterprise, East]",
    );
    // Zero egress: no LLM call, and no entity_registry rows created or mutated.
    expect(llmCalls).toBe(0);
    const entities = await db.query(`SELECT id FROM entity_registry`);
    expect(entities.rows).toHaveLength(0);

    // A NON-ingestion localOnly write (no provenance) stays exactly as-is.
    const conversation = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "Paris holds the Q3 forecast",
        actor: "tester",
        hints: { verbatim: true, localOnly: true },
      },
      policy,
    );
    expect(conversation.stored).toHaveLength(1);
    expect(conversation.stored[0]!.content).toBe("Paris holds the Q3 forecast");
    expect(llmCalls).toBe(0);
  });

  it("deterministic entity brownout preserves an ingestion body without registry mutation", async () => {
    const result = await writePath.write(
      {
        namespace: NS,
        scope: "org",
        content: "While Northwind Enterprise reviewed the East region contract",
        actor: "ingest",
        hints: { verbatim: true, deterministicEntities: true },
        provenance: { source: "document", sourceId: "notion:workspace" },
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]!.content).toBe(
      "While Northwind Enterprise reviewed the East region contract [entities: While, Northwind, Enterprise, East]",
    );
    const entities = await db.query(`SELECT id FROM entity_registry`);
    expect(entities.rows).toHaveLength(0);
  });

  it("extracts user vs assistant facts from a dialogue transcript with correct scopes", async () => {
    const result = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "User: Alice moved to Paris\nAssistant: I booked the Paris hotel for Alice",
        actor: "tester",
        session: "s2",
      },
      policy,
    );

    expect(result.rejected).toHaveLength(0);
    expect(result.stored).toHaveLength(2);

    const userFact = result.stored[0]!;
    const assistantFact = result.stored[1]!;
    expect(userFact.scope).toBe("user");
    expect(userFact.content).toContain("Alice moved to Paris");
    expect(userFact.content).toContain("[entities: Alice, Paris]");
    expect(userFact.ttlSeconds).toBe(3600);
    expect(assistantFact.scope).toBe("assistant");
    expect(assistantFact.content).toContain("I booked the Paris hotel for Alice");
    expect(assistantFact.ttlSeconds).toBe(1800);

    // Repeated mentions resolved against the same registry records.
    const entities = await db.query<{ canonical_name: string }>(
      `SELECT canonical_name FROM entity_registry ORDER BY canonical_name`,
    );
    expect(entities.rows.map((r) => r.canonical_name)).toEqual(["Alice", "Paris"]);
  });

  it("rejects a hallucinated fact via the verifier", async () => {
    // LLM that fabricates an extraction but delegates VERIFY to the stub.
    const hallucinating: LlmClient = {
      name: "hallucinating",
      complete: async (system, user) =>
        system.includes(EXTRACT_MARKER)
          ? JSON.stringify([
              {
                content: "Bob was promoted to CEO of Initech",
                speaker: "user",
                eventTime: null,
                entities: [],
                confidence: 0.9,
              },
            ])
          : stub.complete(system, user),
    };
    const wp = new WritePath({ ...deps, llm: hallucinating });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "User: the weather in Lisbon is sunny",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(0);
    expect(result.rejected).toEqual([
      {
        candidate: "Bob was promoted to CEO of Initech",
        reason: "failed-verification",
      },
    ]);
    const rejects = audit.events.filter((e) => e.op === "reject");
    expect(rejects).toHaveLength(1);
    expect(rejects[0]!.result).toBe("denied");
  });

  it("verifies a multi-fact document in one batched call, not one per fact", async () => {
    // Per-fact verification re-sent the whole transcript per candidate — the
    // write path's dominant model spend on ingested documents (Aug 2026).
    let batchCalls = 0;
    let singleCalls = 0;
    const counting: LlmClient = {
      name: "counting",
      complete: async (system, user) => {
        if (system.includes(VERIFY_BATCH_MARKER)) batchCalls++;
        else if (system.includes(VERIFY_MARKER)) singleCalls++;
        return stub.complete(system, user);
      },
    };
    const wp = new WritePath({ ...deps, llm: counting });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "User: the Lisbon office opens in March\n" +
          "User: Carla leads the Lisbon launch team\n" +
          "User: the launch budget is 40000 euros",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(3);
    expect(result.rejected).toHaveLength(0);
    expect(batchCalls).toBe(1); // all three verdicts ride one call
    expect(singleCalls).toBe(0);
  });

  it("rejects only the hallucinated fact from a batched verification", async () => {
    // Extraction fabricates one fact alongside a real one; the batched
    // verifier must keep per-fact verdicts — reject the fabrication, store
    // the grounded fact.
    const hallucinating: LlmClient = {
      name: "hallucinating-batch",
      complete: async (system, user) =>
        system.includes(EXTRACT_MARKER)
          ? JSON.stringify([
              {
                content: "the weather in Lisbon is sunny",
                speaker: "user",
                eventTime: null,
                entities: [],
                confidence: 0.9,
              },
              {
                content: "Bob was promoted to CEO of Initech",
                speaker: "user",
                eventTime: null,
                entities: [],
                confidence: 0.9,
              },
            ])
          : stub.complete(system, user),
    };
    const wp = new WritePath({ ...deps, llm: hallucinating });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "User: the weather in Lisbon is sunny",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]!.content).toContain("the weather in Lisbon is sunny");
    expect(result.rejected).toEqual([
      {
        candidate: "Bob was promoted to CEO of Initech",
        reason: "failed-verification",
      },
    ]);
  });

  it("falls back to single-fact verification for candidates a malformed batch response missed", async () => {
    // A bad packet must cost extra calls, never a verdict the model did not
    // give — the blast radius of one malformed response stays one fact.
    let singleCalls = 0;
    const malformedBatch: LlmClient = {
      name: "malformed-batch",
      complete: async (system, user) => {
        if (system.includes(VERIFY_BATCH_MARKER)) {
          // Covers id 1 only; id 2 is missing and must fall back.
          return '[{"id":1,"verified":true}] trailing garbage';
        }
        if (system.includes(VERIFY_MARKER)) {
          singleCalls++;
        }
        return stub.complete(system, user);
      },
    };
    const wp = new WritePath({ ...deps, llm: malformedBatch });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "User: the Lisbon office opens in March\n" +
          "User: Carla leads the Lisbon launch team",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(2); // both verdicts still land
    expect(result.rejected).toHaveLength(0);
    expect(singleCalls).toBe(1); // exactly the uncovered candidate fell back
  });

  it("dedupes an exact re-write and bumps access on the original", async () => {
    const req = {
      namespace: NS,
      scope: "user" as const,
      content: "Customer prefers email contact",
      actor: "tester",
      hints: { verbatim: true },
    };
    const first = await writePath.write(req, policy);
    const second = await writePath.write(req, policy);

    expect(first.stored).toHaveLength(1);
    expect(second.stored).toHaveLength(0);
    expect(second.deduplicated).toBe(1);
    expect(second.superseded).toHaveLength(0);

    const rows = await db.query<{ access_count: number }>(
      `SELECT access_count FROM memory_objects WHERE id = $1`,
      [first.stored[0]!.id],
    );
    expect(rows.rows[0]!.access_count).toBe(1);
  });

  it("keeps two similar but non-identical facts active for asynchronous judgement", async () => {
    const first = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "The customer preferred shipping address for the Anvil order is 12 Oak St",
        actor: "tester",
        hints: { verbatim: true },
      },
      policy,
    );
    const second = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "The customer preferred shipping address for the Anvil order is 99 Pine Ave",
        actor: "tester",
        hints: { verbatim: true },
      },
      policy,
    );

    const prior = first.stored[0]!;
    expect(second.deduplicated).toBe(0);
    expect(second.stored).toHaveLength(1);
    expect(second.superseded).toEqual([]);
    expect(second.stored[0]!.supersedes).toBeNull();

    // Similarity is candidate retrieval only; neither fact is changed.
    const rows = await db.query<{ t_valid_to: Date | string | null; content: string }>(
      `SELECT t_valid_to, content FROM memory_objects WHERE id = $1`,
      [prior.id],
    );
    expect(rows.rows[0]!.t_valid_to).toBeNull();
    expect(rows.rows[0]!.content).toContain("12 Oak St");

    expect(audit.events.some((e) => e.op === "supersede" && e.memoryId === prior.id)).toBe(false);
  });

  it("never supersedes or dedupes across namespaces: ancestor facts stay valid", async () => {
    // Org-level fact written at the org root.
    const orgWrite = await writePath.write(
      {
        namespace: "org",
        scope: "org",
        content: "The weekly team standup meeting time is 9am on Mondays",
        actor: "org-admin",
        hints: { verbatim: true },
      },
      { ...policy, namespace: "org" },
    );
    const orgId = orgWrite.stored[0]!.id;

    // Child-namespace write in the supersede band (~0.9 cosine, same scope):
    // must NOT close the ancestor row; it lands in the child's own namespace.
    const conflicting = await writePath.write(
      {
        namespace: "org/team2",
        scope: "org",
        content: "The weekly team standup meeting time is 10am on Mondays",
        actor: "team2-agent",
        hints: { verbatim: true },
      },
      { ...policy, namespace: "org/team2" },
    );
    expect(conflicting.stored).toHaveLength(1);
    expect(conflicting.stored[0]!.namespace).toBe("org/team2");
    expect(conflicting.stored[0]!.supersedes).toBeNull();
    expect(conflicting.superseded).toEqual([]);
    expect(conflicting.deduplicated).toBe(0);

    // Child-namespace write with IDENTICAL content (dedupe band): must not be
    // silently swallowed by the ancestor row — it lands in the caller's
    // namespace.
    const duplicate = await writePath.write(
      {
        namespace: "org/team3",
        scope: "org",
        content: "The weekly team standup meeting time is 9am on Mondays",
        actor: "team3-agent",
        hints: { verbatim: true },
      },
      { ...policy, namespace: "org/team3" },
    );
    expect(duplicate.deduplicated).toBe(0);
    expect(duplicate.stored).toHaveLength(1);
    expect(duplicate.stored[0]!.namespace).toBe("org/team3");

    // The org fact is still currently valid for everyone.
    const rows = await db.query<{ t_valid_to: unknown }>(
      `SELECT t_valid_to FROM memory_objects WHERE id = $1`,
      [orgId],
    );
    expect(rows.rows[0]!.t_valid_to).toBeNull();
  });

  it("keeps the prior fact valid when the successor insert fails (D7 crash safety)", async () => {
    const first = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content:
          "The customer preferred shipping address for the Anvil order is 12 Oak St",
        actor: "tester",
        hints: { verbatim: true },
      },
      policy,
    );
    const priorId = first.stored[0]!.id;

    // Index whose insert fails (connection drop / constraint error).
    const failingIndex: MemoryIndexLike = {
      insert: async () => {
        throw new Error("boom: connection lost");
      },
      vectorSearch: (ns, e, k) => index.vectorSearch(ns, e, k),
      bumpAccess: (ids) => index.bumpAccess(ids),
      closeValidity: (id, ts) => index.closeValidity(id, ts),
    };
    const wp = new WritePath({ ...deps, index: failingIndex });

    await expect(
      wp.write(
        {
          namespace: NS,
          scope: "user",
          content:
            "The customer preferred shipping address for the Anvil order is 99 Pine Ave",
          actor: "tester",
          hints: { verbatim: true },
        },
        policy,
      ),
    ).rejects.toThrow("boom");

    // The prior fact must still be currently valid — its validity is only
    // closed after the successor row is durably inserted.
    const rows = await db.query<{ t_valid_to: unknown }>(
      `SELECT t_valid_to FROM memory_objects WHERE id = $1`,
      [priorId],
    );
    expect(rows.rows[0]!.t_valid_to).toBeNull();
    expect(audit.events.some((e) => e.op === "supersede")).toBe(false);
  });

  it("LLM outage mid-write keeps committed candidates and reports the rest (no whole-write rethrow)", async () => {
    // Verification is batched BEFORE any candidate commits now, so a verifier
    // outage always strikes at zero progress (covered below). The surviving
    // mid-write LLM call is the ENTITY TIEBREAK — the circuit opening there
    // after candidate 1 committed must surface a partial result, never a
    // whole-write rethrow (whose verbatim fallback would duplicate the
    // committed row).
    const axis = (i: number): number[] => {
      const v = new Array<number>(EMBED_DIM).fill(0);
      v[i] = 1;
      return v;
    };
    // Mention vector at cosine 0.7 to the seeded canonical — inside the
    // [0.6, 0.85) band that forces the LLM tiebreak (entities.ts header).
    const band = (): number[] => {
      const v = new Array<number>(EMBED_DIM).fill(0);
      v[0] = 0.7;
      v[1] = Math.sqrt(1 - 0.49);
      return v;
    };
    const bandEmbedder: Embedder = {
      name: "band-embed",
      dim: EMBED_DIM,
      embed: async (texts) =>
        texts.map((t) =>
          t === "Dana Ruiz" ? axis(0)
          : t === "Dana Ruiz Co" ? band()
          : t.startsWith("Team met") ? axis(10)
          : t.startsWith("Dana moved") ? axis(11)
          : axis(12)),
    };

    // Seed the registry with the canonical the tiebreak will collide with.
    const seeding: LlmClient = {
      name: "seeding",
      complete: async (system, user) =>
        system.includes(EXTRACT_MARKER)
          ? JSON.stringify([
              { content: "Team met Dana Ruiz", speaker: "user", eventTime: null, entities: ["Dana Ruiz"], confidence: 0.9 },
            ])
          : stub.complete(system, user),
    };
    await new WritePath({ ...deps, embedder: bandEmbedder, llm: seeding }).write(
      { namespace: NS, scope: "user", content: "User: Team met Dana Ruiz", actor: "tester" },
      policy,
    );

    const flaky: LlmClient = {
      name: "flaky",
      complete: async (system, user) => {
        if (system.includes(EXTRACT_MARKER)) {
          return JSON.stringify([
            { content: "Dana moved to Lisbon", speaker: "user", eventTime: null, entities: [], confidence: 0.9 },
            { content: "Dana adopted a tortoise", speaker: "user", eventTime: null, entities: ["Dana Ruiz Co"], confidence: 0.9 },
          ]);
        }
        if (system.includes(ENTITY_MARKER)) throw new LlmUnavailableError();
        return stub.complete(system, user);
      },
    };
    const wp = new WritePath({ ...deps, embedder: bandEmbedder, llm: flaky });

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "User: Dana moved to Lisbon\nUser: Dana adopted a tortoise",
        actor: "tester",
      },
      policy,
    );

    expect(result.stored).toHaveLength(1);
    expect(result.stored[0]!.content).toContain("Dana moved to Lisbon");
    expect(result.rejected).toEqual([
      { candidate: "Dana adopted a tortoise", reason: "llm-unavailable" },
    ]);

    // The committed candidate is reported, never re-stored, and no verbatim
    // duplicate of the whole transcript exists (seed row + candidate 1 only).
    const rows = await db.query<{ content: string }>(
      `SELECT content FROM memory_objects ORDER BY content`,
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.map((r) => r.content.split(" [entities:")[0])).toEqual([
      "Dana moved to Lisbon",
      "Team met Dana Ruiz",
    ]);
    expect(audit.events.filter((e) => e.op === "reject" && e.result === "error")).toHaveLength(1);
  });

  it("a verifier outage on a multi-fact write rethrows at zero progress (nothing committed to duplicate)", async () => {
    // With verification hoisted before the commit loop, the verifier can no
    // longer fail mid-write: either every verdict lands, or the write fails
    // whole with zero rows and the caller's verbatim fallback is safe.
    const deadVerifier: LlmClient = {
      name: "dead-verifier",
      complete: async (system, user) => {
        if (system.includes(EXTRACT_MARKER)) {
          return JSON.stringify([
            { content: "Dana moved to Lisbon", speaker: "user", eventTime: null, entities: [], confidence: 0.9 },
            { content: "Dana adopted a tortoise", speaker: "user", eventTime: null, entities: [], confidence: 0.9 },
          ]);
        }
        throw new LlmUnavailableError();
      },
    };
    const wp = new WritePath({ ...deps, llm: deadVerifier });
    await expect(
      wp.write(
        {
          namespace: NS,
          scope: "user",
          content: "User: Dana moved to Lisbon\nUser: Dana adopted a tortoise",
          actor: "tester",
        },
        policy,
      ),
    ).rejects.toBeInstanceOf(LlmUnavailableError);
    const rows = await db.query(`SELECT id FROM memory_objects`);
    expect(rows.rows).toHaveLength(0);
  });

  it("LLM outage with ZERO progress still rethrows (caller's verbatim fallback stays safe)", async () => {
    const dead: LlmClient = {
      name: "dead",
      complete: async () => {
        throw new LlmUnavailableError();
      },
    };
    const wp = new WritePath({ ...deps, llm: dead });
    await expect(
      wp.write(
        { namespace: NS, scope: "user", content: "User: anything at all", actor: "tester" },
        policy,
      ),
    ).rejects.toBeInstanceOf(LlmUnavailableError);
    const rows = await db.query(`SELECT id FROM memory_objects`);
    expect(rows.rows).toHaveLength(0);
  });

  it("verbatim writes never call the LLM, even with verifierEnabled (brownout is truly no-LLM)", async () => {
    let llmCalls = 0;
    const counting: LlmClient = {
      name: "counting-dead",
      complete: async () => {
        llmCalls++;
        throw new LlmUnavailableError();
      },
    };
    const wp = new WritePath({ ...deps, llm: counting });
    expect(policy.verifierEnabled).toBe(true);

    const result = await wp.write(
      {
        namespace: NS,
        scope: "user",
        content: "Stored verbatim while the LLM circuit is open",
        actor: "tester",
        hints: { verbatim: true },
      },
      policy,
    );
    expect(result.stored).toHaveLength(1);
    expect(llmCalls).toBe(0); // no extraction, no verifier - the no-LLM lane
  });

  it("attributes write-path audit rows to the syscall agentId, not the actor (D4)", async () => {
    await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content: "Customer prefers SMS notifications",
        actor: "user:dana",
        hints: { verbatim: true },
      },
      policy,
      "mcp",
    );
    const ev = audit.events.find((e) => e.op === "write")!;
    expect(ev.agentId).toBe("mcp");
    expect(ev.actor).toBe("user:dana");
  });
});

describe("EntityRegistry", () => {
  it("resolves repeated mentions (case-insensitive, alias, near-duplicate) to the same record", async () => {
    const registry = new EntityRegistry(db, embedder, stub);

    const first = await registry.resolve("ns1", "Acme Corp");
    const sameLower = await registry.resolve("ns1", "acme corp");
    expect(sameLower.id).toBe(first.id);
    expect(sameLower.canonicalName).toBe("Acme Corp");

    // Distant name → new record.
    const other = await registry.resolve("ns1", "Globex Industries");
    expect(other.id).not.toBe(first.id);

    // High-cosine near-duplicate (>= 0.85) → alias added to the same record.
    const base = await registry.resolve("ns1", "Acme Corp Holdings International");
    const near = await registry.resolve("ns1", "Acme Corp Holdings International Ltd");
    expect(near.id).toBe(base.id);
    expect(near.aliases).toContain("Acme Corp Holdings International Ltd");

    // The alias now matches exactly (case-insensitive).
    const viaAlias = await registry.resolve("ns1", "acme corp holdings international ltd");
    expect(viaAlias.id).toBe(base.id);

    // Mid-band cosine [0.6, 0.85) → stub tiebreak answers {"same": false} → new record.
    const inc = await registry.resolve("ns1", "Acme Corp Inc");
    expect(inc.id).not.toBe(first.id);
    expect(inc.canonicalName).toBe("Acme Corp Inc");
  });

  it("lands a mention as its own record when a band neighbor drifts in mid-write", async () => {
    // Regression (production 2026-08-20): a concurrent writer committing an
    // entity during another lane's prepare() window made resolvePrepared
    // throw for every tiebreak-band mismatch, so concurrent multi-file
    // ingestion failed even through bounded re-preparation. Commit-time
    // state now decides: an unjudged band neighbor yields a NEW record (the
    // same outcome as an LLM "different" verdict), never a failed write.
    const registry = new EntityRegistry(db, embedder, stub);
    const prepared = await registry.prepare("ns-drift", "Acme Corp Inc");
    expect(prepared.tiebreakCandidateId).toBeNull();
    // The concurrent lane lands a mid-band neighbor before our transaction.
    const neighbor = await registry.resolve("ns-drift", "Acme Corp");
    const record = await registry.resolvePrepared(prepared);
    expect(record.canonicalName).toBe("Acme Corp Inc");
    expect(record.id).not.toBe(neighbor.id);
  });

  it("merges into a drifted-in neighbor at or above the alias threshold", async () => {
    const registry = new EntityRegistry(db, embedder, stub);
    const prepared = await registry.prepare("ns-drift2", "Acme Corp Holdings International Ltd");
    // A near-duplicate (cosine >= 0.85) commits between prepare and resolve.
    const base = await registry.resolve("ns-drift2", "Acme Corp Holdings International");
    const record = await registry.resolvePrepared(prepared);
    expect(record.id).toBe(base.id);
    expect(record.aliases).toContain("Acme Corp Holdings International Ltd");
  });

  it("still fails closed when the exact row prepare() saw has vanished", async () => {
    const registry = new EntityRegistry(db, embedder, stub);
    const seeded = await registry.resolve("ns-drift3", "Acme Corp");
    const prepared = await registry.prepare("ns-drift3", "Acme Corp");
    expect(prepared.embedding).toBeNull();
    await db.query(`DELETE FROM entity_registry WHERE id = $1`, [seeded.id]);
    await expect(registry.resolvePrepared(prepared)).rejects.toThrow(
      "entity resolution changed while writing: Acme Corp",
    );
  });
});

describe("StubLlm", () => {
  it("answers entity tiebreaks with same=false and parses fenced JSON", async () => {
    const raw = await stub.complete("x " + "[HALOMEM-ENTITY-TIEBREAK]", "ENTITY A: a\nENTITY B: b");
    expect(parseLooseJson(raw)).toEqual({ same: false });
    expect(parseLooseJson('```json\n{"verified": true, "reason": "r"}\n```')).toEqual({
      verified: true,
      reason: "r",
    });
    expect(parseLooseJson("not json at all")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Trust-ranked supersedence + dispute quarantine (non-transactional lane)
// ---------------------------------------------------------------------------

describe("trust-ranked supersedence", () => {
  const DOC = "The refund window is 30 days for all Acme orders";
  const CLAIM = "The refund window is 14 days for Acme orders";

  async function seedDocumentFact(content = DOC): Promise<string> {
    const result = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content,
        actor: "connector:fs",
        provenance: { source: "document", sourceId: "fs:handbook" },
        hints: { verbatim: true },
      },
      policy,
    );
    expect(result.stored).toHaveLength(1);
    return result.stored[0]!.id;
  }

  it("does not let source trust bypass Luna or human review", async () => {
    const conv = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      policy,
    );
    const doc = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content: DOC,
        actor: "connector:fs",
        provenance: { source: "document", sourceId: "fs:handbook" },
        hints: { verbatim: true },
      },
      policy,
    );
    expect(doc.stored).toHaveLength(1);
    expect(doc.superseded).toEqual([]);
    expect(doc.disputed ?? []).toHaveLength(0);
  });

  it("keeps an underranking conversation fact active and queues it", async () => {
    const incumbentId = await seedDocumentFact();
    const result = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      policy,
    );
    expect(result.stored).toHaveLength(1);
    expect(result.superseded).toEqual([]);
    expect(result.disputed ?? []).toHaveLength(0);
    const disputedId = result.stored[0]!.id;
    const mem = await db.query<{ status: string; supersedes: string | null }>(
      `SELECT status, supersedes FROM memory_objects WHERE id = $1`,
      [disputedId],
    );
    expect(mem.rows[0]!.status).toBe("active");
    expect(mem.rows[0]!.supersedes).toBeNull();

    const incumbent = await db.query<{ t_valid_to: unknown }>(
      `SELECT t_valid_to FROM memory_objects WHERE id = $1`,
      [incumbentId],
    );
    expect(incumbent.rows[0]!.t_valid_to).toBeNull();

    // This fixture uses the structural non-transactional seam; production
    // enqueues in its shared write transaction (covered by autopilot tests).
    expect(audit.events.some((e) => e.op === "dispute")).toBe(false);
    expect(audit.events.some((e) => e.op === "supersede")).toBe(false);

    // Exact re-write dedupes against the active fact.
    const repeat = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      policy,
    );
    expect(repeat.deduplicated).toBe(1);
    expect(repeat.disputed ?? []).toHaveLength(0);
  });

  it("the legacy mode dial cannot re-enable cosine retirement", async () => {
    const incumbentId = await seedDocumentFact();
    const result = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      { ...policy, conflictReview: "off" },
    );
    expect(result.disputed ?? []).toHaveLength(0);
    expect(result.stored).toHaveLength(1);
    expect(result.superseded).toEqual([]);
  });

  it("the legacy all mode also keeps both facts active", async () => {
    const conv = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      policy,
    );
    const doc = await writePath.write(
      {
        namespace: NS,
        scope: "user",
        content: DOC,
        actor: "connector:fs",
        provenance: { source: "document", sourceId: "fs:handbook" },
        hints: { verbatim: true },
      },
      { ...policy, conflictReview: "all" },
    );
    expect(doc.superseded).toEqual([]);
    expect(doc.stored).toHaveLength(1);
    expect(doc.disputed ?? []).toHaveLength(0);
  });

  it("classification brownout never blocks storing and queueing the fact", async () => {
    await seedDocumentFact();
    // Delegates extraction/verification to the stub; classify calls explode.
    deps.llm = {
      name: "classify-bomb",
      complete: async (system: string, user: string) => {
        if (system.includes("[HALOMEM-DISPUTE-CATEGORY]")) {
          throw new Error("classifier down");
        }
        return stub.complete(system, user);
      },
    };
    writePath = new WritePath(deps);
    const result = await writePath.write(
      { namespace: NS, scope: "user", content: `User: ${CLAIM}`, actor: "agent-7" },
      policy,
    );
    expect(result.stored).toHaveLength(1);
    expect(result.disputed ?? []).toHaveLength(0);
  });

  it("verbatim write makes zero synchronous conflict LLM calls", async () => {
    await seedDocumentFact();
    let llmCalls = 0;
    deps.llm = {
      name: "counting",
      complete: async (system: string, user: string) => {
        llmCalls += 1;
        return stub.complete(system, user);
      },
    };
    writePath = new WritePath(deps);
    const result = await writePath.write(
      { namespace: NS, scope: "user", content: CLAIM, actor: "agent-7", hints: { verbatim: true } },
      policy,
    );
    expect(result.stored).toHaveLength(1);
    expect(result.disputed ?? []).toHaveLength(0);
    expect(llmCalls).toBe(0);
  });
});

describe("subject-aware write conflicts", () => {
  const alice14 = "Alice refund window for premium annual customer orders is exactly 14 days";
  const bob30 = "Bob refund window for premium annual customer orders is exactly 30 days";
  const alice30 = "Alice refund window for premium annual customer orders is exactly 30 days";
  async function documentFact(content: string) {
    return writePath.write({ namespace: NS, scope: "org", content, actor: "connector:test", provenance: { source: "document", sourceId: "file:test" }, hints: { verbatim: true } }, policy);
  }
  it("does not dispute two similar claims about different named subjects", async () => {
    await documentFact(alice14);
    const result = await documentFact(bob30);
    expect(result.stored).toHaveLength(1);
    expect(result.disputed ?? []).toHaveLength(0);
    expect(result.superseded).toHaveLength(0);
  });
  it("does not synchronously supersede even for the same named subject", async () => {
    const first = await documentFact(alice14);
    const result = await documentFact(alice30);
    expect(first.stored).toHaveLength(1);
    expect(result.stored).toHaveLength(1);
    expect(result.superseded).toEqual([]);
  });
});
