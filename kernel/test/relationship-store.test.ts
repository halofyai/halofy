import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import type { RelationshipClassificationResult } from "../src/relationships/classifier.js";
import {
  RelationshipStore,
  RelationshipStoreError,
} from "../src/relationships/store.js";

const DIM = 8;
const NOW = "2026-07-21T10:00:00.000Z";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

type Accepted = Extract<RelationshipClassificationResult, { status: "accepted" }>;

let db: Db;
let store: RelationshipStore;

function accepted(overrides: Partial<Accepted> = {}): Accepted {
  return {
    status: "accepted",
    subjectEntityId: "entity-a",
    objectEntityId: "entity-b",
    relationship: "uses",
    confidence: 0.86,
    evidenceMemoryIds: ["memory-a"],
    ...overrides,
  };
}

async function seedEntities(
  namespace = "acme/support",
  subject = "entity-a",
  object = "entity-b",
): Promise<void> {
  await db.query(
    `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, created_at)
     VALUES ($1, $3, $4, '[]', $5), ($2, $3, $6, '[]', $5)`,
    [subject, object, namespace, `${subject}-name`, NOW, `${object}-name`],
  );
}

async function seedEvidence(options: {
  id?: string;
  namespace?: string;
  sourceId?: string;
  sourceNamespace?: string;
  documentKey?: string;
  memoryHash?: string;
  documentHash?: string;
  status?: "active" | "archived" | "tombstoned" | "disputed";
  tValidTo?: string | null;
  ttlSeconds?: number | null;
} = {}): Promise<void> {
  const id = options.id ?? "memory-a";
  const namespace = options.namespace ?? "acme/support";
  const sourceId = options.sourceId ?? `source-${id}`;
  const documentKey = options.documentKey ?? `${id}.json`;
  const memoryHash = options.memoryHash ?? HASH_A;
  const documentHash = options.documentHash ?? memoryHash;

  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at, lifecycle_state)
     VALUES ($1, $2, 'filesystem', '{}', $3, 'active')`,
    [sourceId, options.sourceNamespace ?? "acme", NOW],
  );
  await db.query(
    `INSERT INTO source_documents
       (source_id, landing_namespace, document_key, content_hash, synced_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [sourceId, namespace, documentKey, documentHash, NOW],
  );
  await db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        assertion_time, t_valid_from, t_valid_to, provenance, ttl_seconds, status)
     VALUES ($1, $2, 'team', 'L2', $3, $4, 'fact', 0.9,
             $5, $5, $6, $7, $8, $9)`,
    [
      id,
      namespace,
      `backend:${id}`,
      `Evidence ${id}`,
      "2026-07-20T10:00:00.000Z",
      options.tValidTo ?? null,
      JSON.stringify([{
        source: "filesystem",
        actor: "ingest:source",
        sourceId,
        documentKey,
        contentHash: memoryHash,
        ts: "2026-07-20T10:00:00.000Z",
      }]),
      options.ttlSeconds ?? null,
      options.status ?? "active",
    ],
  );
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
});

beforeEach(async () => {
  await db.query(`DELETE FROM entity_relationship_evidence`);
  await db.query(`DELETE FROM entity_relationships`);
  await db.query(`DELETE FROM entity_mentions`);
  await db.query(`DELETE FROM memory_objects`);
  await db.query(`DELETE FROM source_documents`);
  await db.query(`DELETE FROM company_files`);
  await db.query(`DELETE FROM knowledge_sources`);
  await db.query(`DELETE FROM knowledge_bases`);
  await db.query(`DELETE FROM sources`);
  await db.query(`DELETE FROM entity_registry`);
  store = new RelationshipStore(db, {
    now: () => new Date(NOW),
    makeId: (() => {
      let next = 0;
      return () => `relationship-test-${++next}`;
    })(),
  });
});

afterAll(async () => {
  await db.close();
});

describe("RelationshipStore.commit", () => {
  it("persists an evidence-backed L2 edge with source coordinates derived from provenance", async () => {
    await seedEntities();
    await seedEvidence();

    const result = await store.commit(
      { namespace: "acme/support", actor: "relationship-worker" },
      accepted(),
      "2026-07-20T09:00:00.000Z",
    );

    expect(result).toMatchObject({ deduplicated: false, relationship: {
      namespace: "acme/support",
      subjectEntityId: "entity-a",
      relationship: "uses",
      objectEntityId: "entity-b",
      evidence: [{
        memoryId: "memory-a",
        sourceId: "source-memory-a",
        documentKey: "memory-a.json",
        contentHash: HASH_A,
      }],
      assertionTime: NOW,
      eventTime: "2026-07-20T09:00:00.000Z",
      status: "active",
      createdBy: "relationship-worker",
    } });
    const evidence = await db.query(
      `SELECT namespace, memory_id, source_id, document_key, content_hash
         FROM entity_relationship_evidence`,
    );
    expect(evidence.rows).toEqual([{
      namespace: "acme/support",
      memory_id: "memory-a",
      source_id: "source-memory-a",
      document_key: "memory-a.json",
      content_hash: HASH_A,
    }]);
  });

  it("deduplicates a current triple with the same normalized evidence", async () => {
    await seedEntities();
    await seedEvidence();

    const first = await store.commit(
      { namespace: "acme/support", actor: "worker-a" },
      accepted(),
    );
    const duplicate = await store.commit(
      { namespace: "acme/support", actor: "worker-b" },
      accepted({ confidence: 0.91, evidenceMemoryIds: ["memory-a", "memory-a"] }),
    );

    expect(duplicate).toEqual({ relationship: first.relationship, deduplicated: true });
    expect((await db.query(`SELECT id FROM entity_relationships`)).rows).toHaveLength(1);
    expect((await db.query(`SELECT id FROM entity_relationship_evidence`)).rows).toHaveLength(1);
  });

  it("closes the prior edge and appends a correction without deleting its evidence", async () => {
    await seedEntities();
    await seedEvidence();
    await seedEvidence({ id: "memory-b", memoryHash: HASH_B });
    const context = { namespace: "acme/support", actor: "relationship-worker" };
    const first = await store.commit(context, accepted());

    const correction = await store.commit(context, accepted({
      confidence: 0.94,
      evidenceMemoryIds: ["memory-b"],
    }));

    expect(correction).toMatchObject({
      deduplicated: false,
      supersededId: first.relationship.id,
      relationship: { supersedes: first.relationship.id, confidence: 0.94 },
    });
    const rows = await db.query(
      `SELECT id, status, t_valid_to, supersedes
         FROM entity_relationships ORDER BY created_at, id`,
    );
    expect(rows.rows).toEqual([
      expect.objectContaining({
        id: first.relationship.id,
        status: "archived",
        t_valid_to: new Date(NOW),
        supersedes: null,
      }),
      expect.objectContaining({
        id: correction.relationship.id,
        status: "active",
        t_valid_to: null,
        supersedes: first.relationship.id,
      }),
    ]);
    expect((await db.query(
      `SELECT memory_id FROM entity_relationship_evidence ORDER BY memory_id`,
    )).rows).toEqual([{ memory_id: "memory-a" }, { memory_id: "memory-b" }]);
  });

  it("rejects ancestor, descendant, and sibling entity or evidence authority", async () => {
    await seedEntities("acme");
    await seedEvidence({ namespace: "acme/support" });

    await expect(store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted(),
    )).rejects.toMatchObject({ code: "entity_unavailable", retryable: false });

    await db.query(`UPDATE entity_registry SET namespace = 'acme/support'`);
    await db.query(`UPDATE memory_objects SET namespace = 'acme/sales' WHERE id = 'memory-a'`);
    await expect(store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted(),
    )).rejects.toMatchObject({ code: "evidence_unavailable", retryable: false });
  });

  it("rejects stale source provenance and inactive memory versions", async () => {
    await seedEntities();
    await seedEvidence({ memoryHash: HASH_A, documentHash: HASH_B });

    await expect(store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted(),
    )).rejects.toMatchObject({ code: "evidence_provenance_invalid", retryable: false });

    await db.query(
      `UPDATE source_documents SET content_hash = $1 WHERE document_key = 'memory-a.json'`,
      [HASH_A],
    );
    await db.query(
      `UPDATE memory_objects SET status = 'archived', t_valid_to = $1 WHERE id = 'memory-a'`,
      [NOW],
    );
    await expect(store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted(),
    )).rejects.toMatchObject({ code: "evidence_unavailable", retryable: false });
  });

  it.each([
    ["unknown ontology", { relationship: "executes_sql" }, "invalid_classification"],
    ["non-finite confidence", { confidence: Number.NaN }, "invalid_classification"],
    ["empty evidence", { evidenceMemoryIds: [] }, "invalid_classification"],
    ["unbounded evidence", { evidenceMemoryIds: Array.from({ length: 33 }, (_, i) => `memory-${i}`) }, "invalid_classification"],
    ["future event time", {}, "invalid_event_time"],
  ])("returns a typed non-retryable error for %s", async (_label, overrides, code) => {
    await seedEntities();
    await seedEvidence();
    const eventTime = _label === "future event time" ? "2026-07-22T00:00:00.000Z" : undefined;

    await expect(store.commit(
      { namespace: "acme/support", actor: "worker" },
      { ...accepted(), ...overrides } as Accepted,
      eventTime,
    )).rejects.toMatchObject({ code, retryable: false });
  });

  it("rolls back the edge when normalized evidence persistence fails", async () => {
    await seedEntities();
    await seedEvidence();
    await seedEvidence({ id: "memory-b", memoryHash: HASH_B });
    const colliding = new RelationshipStore(db, {
      now: () => new Date(NOW),
      makeId: () => "same-id",
    });

    await expect(colliding.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted({ evidenceMemoryIds: ["memory-a", "memory-b"] }),
    )).rejects.toBeInstanceOf(RelationshipStoreError);
    expect((await db.query(`SELECT id FROM entity_relationships`)).rows).toEqual([]);
    expect((await db.query(`SELECT id FROM entity_relationship_evidence`)).rows).toEqual([]);
  });
});

describe("RelationshipStore.list", () => {
  it("uses only the supplied exact namespace list and presents symmetric edges in either direction", async () => {
    await seedEntities();
    await seedEvidence();
    await store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted({ relationship: "same_as", confidence: 0.96 }),
    );
    await db.query(
      `INSERT INTO entity_relationships
         (id, namespace, subject_entity_id, relationship, object_entity_id,
          confidence, evidence, assertion_time, event_time, t_valid_from,
          t_valid_to, supersedes, status, created_by, created_at)
       VALUES ('sibling-edge', 'acme/sales', 'entity-a', 'same_as', 'entity-b',
               0.99, '[]', $1, NULL, $1, NULL, NULL, 'active', 'forged', $1)`,
      [NOW],
    );

    const listed = await store.list(["acme", "acme/support"], {
      entityId: "entity-b",
      direction: "outgoing",
    });

    expect(listed.data).toHaveLength(1);
    expect(listed.data[0]).toMatchObject({
      namespace: "acme/support",
      subjectEntityId: "entity-b",
      relationship: "same_as",
      objectEntityId: "entity-a",
    });
  });

  it("does not synthesize inverse presentation for directed relationships", async () => {
    await seedEntities();
    await seedEvidence();
    await store.commit(
      { namespace: "acme/support", actor: "worker" },
      accepted({ relationship: "depends_on" }),
    );

    await expect(store.list(["acme/support"], {
      entityId: "entity-b",
      direction: "outgoing",
    })).resolves.toEqual({ data: [] });
    const incoming = await store.list(["acme/support"], {
      entityId: "entity-b",
      direction: "incoming",
    });
    expect(incoming.data[0]).toMatchObject({
      subjectEntityId: "entity-a",
      relationship: "depends_on",
      objectEntityId: "entity-b",
    });
  });
});
