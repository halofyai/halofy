import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb } from "../src/db/client.js";
import { MIGRATIONS, splitStatements } from "../src/db/migrations.js";
import { sha256hex, syncWithDrift } from "../src/ingest/connectors/framework.js";
import { DbSourceState } from "../src/ingest/kernel-store.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

let kernel: Kernel;
let orgOwner: Identity;
let owner: Identity;
let corpus: string;

/**
 * Source DOCUMENT rows for a namespace. M6 (CONTRACTS-M6 row A) mints one
 * `type='pointer'` catalog fact per source surface after every sync; those are
 * a different artifact with their own lifecycle (dedupe/supersede on refresh),
 * so this suite — which is about the drift/retraction lifecycle of the
 * documents themselves — scopes its row counts to non-pointer facts.
 */
async function rows(namespace: string) {
  const result = await kernel.db.query(
    `SELECT id, content, status, t_valid_to, provenance
       FROM memory_objects
      WHERE namespace = $1 AND type <> 'pointer'
      ORDER BY assertion_time, id`,
    [namespace],
  );
  return result.rows as Array<Record<string, unknown>>;
}

function provenance(row: Record<string, unknown>): Array<Record<string, unknown>> {
  return typeof row.provenance === "string"
    ? (JSON.parse(row.provenance) as Array<Record<string, unknown>>)
    : (row.provenance as Array<Record<string, unknown>>);
}

beforeAll(async () => {
  corpus = await mkdtemp(join(tmpdir(), "halomem-source-life-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: await mkdtemp(join(tmpdir(), "halomem-source-life-knowledge-")),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root identity failed");
  const orgOwnerKey = await kernel.auth.issueKey("life", "owner:life", "owner", root);
  const resolvedOrgOwner = await kernel.auth.resolve(orgOwnerKey.plaintext);
  if (!resolvedOrgOwner) throw new Error("organization identity failed");
  orgOwner = resolvedOrgOwner;
  await seedActiveSourceTeam(kernel, "life/source-tests");
  const ownerKey = await kernel.auth.issueKey("life/source-tests", "owner:life-sources", "owner", orgOwner);
  const resolved = await kernel.auth.resolve(ownerKey.plaintext);
  if (!resolved) throw new Error("tenant identity failed");
  owner = resolved;
  await kernel.setPolicy("life/source-tests", "rateLimitPerMin: 100000\n");
}, 120_000);

afterAll(async () => {
  const knowledge = kernel.config.knowledgeDir;
  await kernel.close();
  await rm(corpus, { recursive: true, force: true });
  await rm(knowledge, { recursive: true, force: true });
});

describe("source document lifecycle", () => {
  it("lands a changed version before atomically archiving only the exact retired version", async () => {
    const file = join(corpus, "policy.txt");
    await writeFile(file, "Returns are accepted for thirty days.\n", "utf8");
    const source = await kernel.registerSource("filesystem", { path: corpus }, owner);

    const first = await kernel.syncSource(source.id, owner);
    expect(first.stored).toBe(1);
    const firstRows = await rows("life/source-tests");
    expect(firstRows).toHaveLength(1);
    const oldId = firstRows[0]!.id as string;
    const oldProv = provenance(firstRows[0]!)[0]!;
    expect(oldProv).toMatchObject({ sourceId: source.id, documentKey: "policy.txt" });
    expect(oldProv.contentHash).toMatch(/^[a-f0-9]{64}$/);

    await writeFile(file, "Returns are accepted for sixty days.\n", "utf8");
    const second = await kernel.syncSource(source.id, owner);
    expect(second.changed).toBe(1);

    const after = await rows("life/source-tests");
    expect(after).toHaveLength(2);
    const retired = after.find((r) => r.id === oldId)!;
    const active = after.find((r) => r.id !== oldId)!;
    expect(retired.status).toBe("archived");
    expect(retired.t_valid_to).not.toBeNull();
    expect(active.status).toBe("active");
    expect(active.t_valid_to).toBeNull();
    expect(provenance(active)[0]).toMatchObject({
      sourceId: source.id,
      documentKey: "policy.txt",
    });
    expect(provenance(active)[0]!.contentHash).not.toBe(oldProv.contentHash);

    const search = await kernel.memSearch({ query: "thirty days" }, owner);
    expect(search.some((hit) => hit.id === oldId)).toBe(false);
    await expect(kernel.memRead({ id: oldId }, owner)).resolves.toMatchObject({
      found: false,
    });
    // M6: the sync also minted one pointer-catalog fact (CONTRACTS-M6 row A),
    // which is a real, visible L2 fact — stats and fragmentation see the one
    // active document fact PLUS the source's pointer.
    const stats = await kernel.memStats("life/source-tests", owner);
    expect(stats.l2Count).toBe(2);
    const fragmented = await kernel.runFragmentation("life/source-tests", owner);
    expect(fragmented.factCount).toBe(2);

    const audits = await kernel.db.query(
      `SELECT memory_id, detail FROM audit_log
        WHERE namespace = $1 AND op = 'retract' ORDER BY seq`,
      ["life/source-tests"],
    );
    expect(audits.rows).toHaveLength(1);
    expect(audits.rows[0]!.memory_id).toBe(oldId);
    expect(String(audits.rows[0]!.detail)).toContain("policy.txt");
  });

  it("removal preserves history while hiding the retired fact", async () => {
    const source = (await kernel.sources.list("life/source-tests"))[0]!;
    const otherCorpus = await mkdtemp(join(tmpdir(), "halomem-source-other-"));
    await writeFile(
      join(otherCorpus, "policy.txt"),
      "Returns are accepted for sixty days.\n",
      "utf8",
    );
    const otherSource = await kernel.registerSource(
      "filesystem",
      { path: otherCorpus },
      owner,
    );
    expect((await kernel.syncSource(otherSource.id, owner)).stored).toBe(1);

    const siblingKey = await kernel.auth.issueKey(
      "life/source-tests/sibling",
      "agent:sibling",
      "agent",
      orgOwner,
    );
    const sibling = await kernel.auth.resolve(siblingKey.plaintext);
    if (!sibling) throw new Error("sibling identity failed");
    const siblingSync = await kernel.syncSource(source.id, sibling);
    expect(siblingSync.stored).toBe(1);

    const relationshipFact = (await rows("life/source-tests")).find((row) =>
      row.status === "active" &&
      provenance(row).some((entry) => entry.sourceId === source.id)
    );
    if (!relationshipFact) throw new Error("source fact missing before relationship seed");
    const now = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, created_at)
       VALUES ('life-policy', 'life/source-tests', 'Synthetic policy node', '[]', $1),
              ('life-returns', 'life/source-tests', 'Synthetic returns node', '[]', $1)`,
      [now],
    );
    await kernel.db.query(
      `INSERT INTO entity_relationships
         (id, namespace, subject_entity_id, relationship, object_entity_id,
          confidence, evidence, assertion_time, t_valid_from, status,
          created_by, created_at)
       VALUES ('life-policy-returns', 'life/source-tests', 'life-policy', 'uses',
               'life-returns', 1, $1::jsonb, $2, $2, 'active', 'ingest', $2)`,
      [JSON.stringify([{ memoryId: relationshipFact.id }]), now],
    );
    await kernel.db.query(
      `INSERT INTO entity_relationship_evidence
         (id, namespace, relationship_id, memory_id, source_id, evidence_role,
          confidence, created_by, created_at)
       VALUES ('life-policy-returns-evidence', 'life/source-tests',
               'life-policy-returns', $1, $2, 'supporting', 1, 'ingest', $3)`,
      [relationshipFact.id, source.id, now],
    );

    await rm(join(corpus, "policy.txt"));
    const result = await kernel.syncSource(source.id, owner);
    expect(result.removed).toEqual(["policy.txt"]);

    const all = await rows("life/source-tests");
    const sourceRows = all.filter((row) =>
      provenance(row).some((entry) => entry.sourceId === source.id),
    );
    const otherRows = all.filter((row) =>
      provenance(row).some((entry) => entry.sourceId === otherSource.id),
    );
    expect(sourceRows.filter((r) => r.status === "active")).toHaveLength(0);
    expect(sourceRows.filter((r) => r.status === "archived")).toHaveLength(2);
    expect(otherRows.filter((r) => r.status === "active")).toHaveLength(1);
    // M6: pointer-catalog facts are visible candidates too — the document-
    // lifecycle claim is about the DOCUMENT facts, so scope to non-pointers.
    const candidates = (await kernel.index.listCandidates("life/source-tests")).filter(
      (candidate) => candidate.type !== "pointer",
    );
    expect(candidates.map((candidate) => candidate.id)).toEqual([otherRows[0]!.id]);
    const activeDocs = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM memory_objects
        WHERE namespace = 'life/source-tests' AND status = 'active' AND type <> 'pointer'
          AND (ttl_seconds IS NULL OR
               assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)`,
    );
    expect(Number((activeDocs.rows[0] as { n: unknown }).n)).toBe(1);
    const retiredRelationship = await kernel.db.query(
      `SELECT status, t_valid_to FROM entity_relationships
        WHERE id = 'life-policy-returns'`,
    );
    expect(retiredRelationship.rows[0]).toMatchObject({ status: "archived" });
    expect(retiredRelationship.rows[0]!.t_valid_to).not.toBeNull();
    expect(await kernel.listEntityRelationships({ entityId: "life-policy" }, owner))
      .toEqual({ data: [] });
    const siblingRows = await rows("life/source-tests/sibling");
    expect(siblingRows.filter((r) => r.status === "active")).toHaveLength(1);
    await rm(otherCorpus, { recursive: true, force: true });
  });

  it("disconnecting a backend retires all of its derived memory and routing pointers", async () => {
    const disconnectCorpus = await mkdtemp(join(tmpdir(), "halomem-source-disconnect-"));
    try {
      await writeFile(
        join(disconnectCorpus, "disconnect.txt"),
        "Disconnected backend facts must leave active memory.\n",
        "utf8",
      );
      const source = await kernel.registerSource("filesystem", { path: disconnectCorpus }, owner);
      expect((await kernel.syncSource(source.id, owner)).stored).toBe(1);

      const before = await kernel.db.query(
        `SELECT id, type FROM memory_objects
          WHERE namespace = 'life/source-tests' AND status = 'active' AND t_valid_to IS NULL
            AND provenance @> $1::jsonb`,
        [JSON.stringify([{ sourceId: source.id }])],
      );
      expect(before.rows.some((row) => row.type === "fact")).toBe(true);
      expect(before.rows.some((row) => row.type === "pointer")).toBe(true);

      const disconnected = await kernel.pauseSource(source.id, owner);
      expect(disconnected.lifecycleState).toBe("paused");

      const after = await kernel.db.query(
        `SELECT id FROM memory_objects
          WHERE status IN ('active','disputed') AND t_valid_to IS NULL
            AND provenance @> $1::jsonb`,
        [JSON.stringify([{ sourceId: source.id }])],
      );
      expect(after.rows).toHaveLength(0);
      const disconnectedIds = new Set(before.rows.map((row) => String(row.id)));
      const search = await kernel.memSearch({ query: "Disconnected backend facts" }, owner);
      expect(search.some((hit) => disconnectedIds.has(hit.id))).toBe(false);
    } finally {
      await rm(disconnectCorpus, { recursive: true, force: true });
    }
  });

  it("deleting a knowledge base retires memory from its attached backend", async () => {
    const attachedCorpus = await mkdtemp(join(tmpdir(), "halomem-kb-delete-source-"));
    try {
      await writeFile(
        join(attachedCorpus, "attached.txt"),
        "Knowledge attached to a deleted collection must be retired.\n",
        "utf8",
      );
      const source = await kernel.registerSource("filesystem", { path: attachedCorpus }, owner);
      const base = await kernel.createKnowledgeBase({
        name: "Attached backend collection",
        kind: "file",
        targetTeamId: null,
        primaryBusinessFunction: "Operations",
        description: "Collection deletion lifecycle",
        dataSensitive: false,
      }, owner);
      await kernel.attachKnowledgeBaseSource(base.id, {
        kind: "folder",
        sourceId: source.id,
        name: "Attached folder",
        description: "",
        purpose: "Deletion lifecycle proof",
      }, owner);
      expect((await kernel.syncSource(source.id, owner)).stored).toBe(1);

      await kernel.archiveKnowledgeBase(base.id, owner);

      expect((await kernel.sources.get(source.id))?.lifecycleState).toBe("paused");
      const active = await kernel.db.query(
        `SELECT id FROM memory_objects
          WHERE status IN ('active','disputed') AND t_valid_to IS NULL
            AND provenance @> $1::jsonb`,
        [JSON.stringify([{ sourceId: source.id }])],
      );
      expect(active.rows).toHaveLength(0);
      expect((await kernel.listKnowledgeBaseSources(base.id, {}, owner)).data).toEqual([]);
    } finally {
      await rm(attachedCorpus, { recursive: true, force: true });
    }
  });

  it("rolls retraction and drift acknowledgement back together, then retries idempotently", async () => {
    const retryCorpus = await mkdtemp(join(tmpdir(), "halomem-source-retry-"));
    try {
      const file = join(retryCorpus, "retry.txt");
      await writeFile(file, "Escalations page the bronze team.\n", "utf8");
      const source = await kernel.registerSource("filesystem", { path: retryCorpus }, owner);
      expect((await kernel.syncSource(source.id, owner)).stored).toBe(1);

      const beforeState = await kernel.db.query(
        `SELECT content_hash FROM source_documents WHERE source_id = $1`,
        [source.id],
      );
      const oldHash = String(beforeState.rows[0]!.content_hash);
      await writeFile(file, "Escalations page the silver team.\n", "utf8");

      const originalTransaction = kernel.db.transaction.bind(kernel.db);
      kernel.db.transaction = async <T>(fn: Parameters<typeof kernel.db.transaction<T>>[0]) =>
        originalTransaction(async (tx) =>
          fn({
            ...tx,
            async query(sql: string, params?: unknown[]) {
              if (sql.includes("INSERT INTO audit_log") && params?.includes("retract")) {
                throw new Error("injected retraction audit failure");
              }
              return tx.query(sql, params);
            },
          }),
        );

      let failed;
      try {
        failed = await kernel.syncSource(source.id, owner);
      } finally {
        kernel.db.transaction = originalTransaction;
      }
      expect(failed.errors).toEqual([
        { docId: "retry.txt", reason: "injected retraction audit failure" },
      ]);

      const afterFailureState = await kernel.db.query(
        `SELECT content_hash FROM source_documents WHERE source_id = $1`,
        [source.id],
      );
      expect(afterFailureState.rows[0]!.content_hash).toBe(oldHash);
      const afterFailure = (await rows("life/source-tests")).filter((row) =>
        provenance(row).some((entry) => entry.sourceId === source.id),
      );
      expect(afterFailure.filter((row) => row.status === "active")).toHaveLength(2);

      const retry = await kernel.syncSource(source.id, owner);
      expect(retry.errors).toEqual([]);
      expect(retry.deduplicated).toBe(1);
      const afterRetry = (await rows("life/source-tests")).filter((row) =>
        provenance(row).some((entry) => entry.sourceId === source.id),
      );
      expect(afterRetry).toHaveLength(2);
      expect(afterRetry.filter((row) => row.status === "active")).toHaveLength(1);
      expect(afterRetry.filter((row) => row.status === "archived")).toHaveLength(1);
    } finally {
      await rm(retryCorpus, { recursive: true, force: true });
    }
  });

  it("serializes concurrent first syncs so one committed document version wins", async () => {
    const concurrentCorpus = await mkdtemp(join(tmpdir(), "halomem-source-concurrent-"));
    try {
      await writeFile(
        join(concurrentCorpus, "first.txt"),
        "The launch owner is the blue team.\n",
        "utf8",
      );
      const source = await kernel.registerSource(
        "filesystem",
        { path: concurrentCorpus },
        owner,
      );

      const [left, right] = await Promise.all([
        kernel.syncSource(source.id, owner),
        kernel.syncSource(source.id, owner),
      ]);

      expect([...left.errors, ...right.errors]).toEqual([]);
      expect(left.stored + right.stored).toBe(1);
      expect(left.unchanged + right.unchanged).toBe(1);

      const facts = (await rows("life/source-tests")).filter((row) =>
        provenance(row).some((entry) => entry.sourceId === source.id),
      );
      expect(facts.filter((row) => row.status === "active" && row.t_valid_to === null))
        .toHaveLength(1);

      const drift = await kernel.db.query(
        `SELECT landing_namespace, document_key, content_hash
           FROM source_documents
          WHERE source_id = $1`,
        [source.id],
      );
      expect(drift.rows).toEqual([
        expect.objectContaining({
          landing_namespace: "life/source-tests",
          document_key: "first.txt",
          content_hash: expect.stringMatching(/^[a-f0-9]{64}$/),
        }),
      ]);
    } finally {
      await rm(concurrentCorpus, { recursive: true, force: true });
    }
  });

  it("releases unchanged document claims when removal detection is disabled", async () => {
    const source = await kernel.registerSource("filesystem", { path: corpus }, owner);
    const docId = "platform-record.json";
    const content = "A platform record that has already landed.";
    const contentHash = sha256hex(content);
    const appendAudit = async () => undefined;
    const seededState = new DbSourceState(
      kernel.db,
      source.id,
      owner.namespace,
      appendAudit,
    );
    expect(await seededState.priorHash(docId)).toBeNull();
    await seededState.record(docId, contentHash, new Date().toISOString(), null);

    const replayState = new DbSourceState(
      kernel.db,
      source.id,
      owner.namespace,
      appendAudit,
    );
    const result = await syncWithDrift(
      {
        sink: {
          sourceId: source.id,
          write: async () => {
            throw new Error("unchanged records must not enter the write path");
          },
        },
        state: replayState,
        config: {},
      },
      async () => [{ docId, content, scope: "org", verbatim: true }],
      { detectRemovals: false },
    );

    expect(result.unchanged).toBe(1);
    expect((await kernel.db.query(
      `SELECT claim_token FROM source_document_claims
        WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3`,
      [source.id, owner.namespace, docId],
    )).rows).toHaveLength(0);
  });

  it("migrates legacy packed drift keys into an explicit three-column identity", async () => {
    const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "" }));
    try {
      await db.query(`CREATE TABLE sources (id TEXT PRIMARY KEY, namespace TEXT NOT NULL)`);
      await db.query(
        `CREATE TABLE source_documents (
           source_id TEXT NOT NULL,
           doc_id TEXT NOT NULL,
           content_hash TEXT NOT NULL,
           synced_at TIMESTAMPTZ NOT NULL,
           PRIMARY KEY (source_id, doc_id)
         )`,
      );
      await db.query(`INSERT INTO sources (id, namespace) VALUES ('s1', 'registered')`);
      await db.query(
        `INSERT INTO source_documents (source_id, doc_id, content_hash, synced_at)
         VALUES ('s1', $1, 'packed-hash', CURRENT_TIMESTAMP),
                ('s1', 'plain.txt', 'plain-hash', CURRENT_TIMESTAMP)`,
        [`landing\x1epacked.txt`],
      );

      const migration = MIGRATIONS.find((candidate) => candidate.version === 14);
      expect(migration?.name).toBe("explicit-source-document-identity");
      for (const statement of splitStatements(migration!.sql(8))) {
        await db.query(statement);
      }

      const migrated = await db.query(
        `SELECT source_id, landing_namespace, document_key, content_hash
           FROM source_documents
          ORDER BY document_key`,
      );
      expect(migrated.rows).toEqual([
        {
          source_id: "s1",
          landing_namespace: "landing",
          document_key: "packed.txt",
          content_hash: "packed-hash",
        },
        {
          source_id: "s1",
          landing_namespace: "registered",
          document_key: "plain.txt",
          content_hash: "plain-hash",
        },
      ]);
      const primaryKey = await db.query(
        `SELECT kcu.column_name
           FROM information_schema.table_constraints tc
           JOIN information_schema.key_column_usage kcu
             ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
          WHERE tc.table_name = 'source_documents'
            AND tc.constraint_type = 'PRIMARY KEY'
          ORDER BY kcu.ordinal_position`,
      );
      expect(primaryKey.rows.map((row) => row.column_name)).toEqual([
        "source_id",
        "landing_namespace",
        "document_key",
      ]);
    } finally {
      await db.close();
    }
  });
});
