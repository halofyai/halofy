import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let rootAdmin: Identity;
let rootAuditor: Identity;
let acmeOwner: Identity;
let legalAgent: Identity;
let siblingAgent: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const resolved = await kernel.auth.resolve(issued.plaintext);
  if (!resolved) throw new Error(`identity resolution failed for ${actor}`);
  return resolved;
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-policy-docs-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
  });

  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root identity resolution failed");
  root = resolvedRoot;
  rootAdmin = await issue("", "admin:platform", "admin", root);
  rootAuditor = await issue("", "auditor:platform", "auditor", root);
  acmeOwner = await issue("acme", "owner:acme", "owner", root);
  legalAgent = await issue("acme/legal/agent-1", "agent:legal", "agent", acmeOwner);
  siblingAgent = await issue("acme/finance/agent-1", "agent:finance", "agent", acmeOwner);
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\n");
}, 120_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("governed policy-document ingestion", () => {
  it("lands an uploaded policy through D10 with provenance and descendant-only retrieval", async () => {
    const document = await kernel.uploadPolicyDocument({
      namespace: "acme/legal",
      title: "Travel approval policy",
      kind: "policy",
      fileName: "travel-approval.md",
      content: "Travel expenses require director approval before booking.",
    }, acmeOwner);

    expect(document).toMatchObject({
      namespace: "acme/legal",
      title: "Travel approval policy",
      kind: "policy",
      status: "active",
      fileName: "travel-approval.md",
      mediaType: "text/markdown",
      factCount: 1,
      failureCode: null,
    });
    expect(document.contentSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(document.loadedAt).not.toBeNull();

    const source = await kernel.sources.get(document.sourceId);
    expect(source).not.toBeNull();
    expect(JSON.stringify(source?.config)).not.toContain(
      "Travel expenses require director approval",
    );

    const rows = await kernel.db.query(
      `SELECT namespace, content, provenance
         FROM memory_objects
        WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL`,
      ["acme/legal"],
    );
    expect(rows.rows).toHaveLength(1);
    const provenance = typeof rows.rows[0]!.provenance === "string"
      ? JSON.parse(rows.rows[0]!.provenance as string)
      : rows.rows[0]!.provenance;
    expect(provenance[0]).toMatchObject({
      source: "document",
      sourceId: document.sourceId,
      documentKey: "travel-approval.md",
    });

    const legalHits = await kernel.memSearch(
      { query: "director approval before booking", k: 10 },
      legalAgent,
    );
    expect(legalHits.some((hit) => hit.content.includes("director approval"))).toBe(true);

    const siblingHits = await kernel.memSearch(
      { query: "director approval before booking", k: 10 },
      siblingAgent,
    );
    expect(siblingHits.some((hit) => hit.content.includes("director approval"))).toBe(false);

    const listed = await kernel.listPolicyDocuments({
      namespace: "acme/legal",
      page: 1,
      pageSize: 20,
    }, acmeOwner);
    expect(listed.data.map((item) => item.id)).toContain(document.id);
    expect(listed.summary).toMatchObject({ total: 1, active: 1, failed: 0 });
  });

  it("blocks duplicate active content and out-of-subtree administration", async () => {
    await expect(kernel.uploadPolicyDocument({
      namespace: "acme/legal",
      title: "Duplicate title does not matter",
      kind: "guideline",
      fileName: "duplicate.txt",
      content: "Travel expenses require director approval before booking.",
    }, acmeOwner)).rejects.toMatchObject({ name: "PolicyDocumentConflictError" });

    await expect(kernel.uploadPolicyDocument({
      namespace: "globex/legal",
      kind: "policy",
      fileName: "escape.md",
      content: "This must never cross the administrative boundary.",
    }, acmeOwner)).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("reserves the global empty scope for the platform root owner", async () => {
    await expect(
      kernel.listPolicyDocuments({ namespace: "" }, rootAdmin),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      kernel.listPolicyDocuments({ namespace: "" }, rootAuditor),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(kernel.uploadPolicyDocument({
      namespace: "",
      kind: "policy",
      fileName: "root-admin.md",
      content: "Only the platform root owner may land this policy.",
    }, rootAdmin)).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      kernel.listPolicyDocuments({ namespace: "" }, root),
    ).resolves.toMatchObject({ data: expect.any(Array) });
  });

  it("keeps policy-upload sources out of the connector lifecycle", async () => {
    const listed = await kernel.listPolicyDocuments({
      namespace: "acme/legal",
      pageSize: 20,
    }, acmeOwner);
    const document = listed.data.find((item) => item.fileName === "travel-approval.md");
    expect(document).toBeDefined();
    expect((await kernel.sourcesView(acmeOwner)).sources).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: document!.sourceId })]),
    );
    await expect(
      kernel.testSource(document!.sourceId, acmeOwner),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      kernel.scheduleSource(document!.sourceId, 60, acmeOwner),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      kernel.syncSource(document!.sourceId, acmeOwner),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("retracts exact-provenance facts when a multi-fact upload fails partway", async () => {
    await kernel.setPolicy(
      "acme/partial-compensation",
      "verifierEnabled: false\nrateLimitPerMin: 100000\n",
    );
    const llm = kernel.llm as {
      complete(system: string, user: string): Promise<string>;
    };
    const embedder = kernel.embedder as {
      embed(texts: string[]): Promise<number[][]>;
    };
    const originalComplete = llm.complete.bind(llm);
    const originalEmbed = embedder.embed.bind(embedder);
    let embedCalls = 0;
    llm.complete = async (system, user) => {
      if (system.includes("[HALOMEM-EXTRACT]")) {
        return JSON.stringify([
          {
            content: "Partial policy fact one",
            speaker: "user",
            eventTime: null,
            entities: [],
            confidence: 0.99,
          },
          {
            content: "Partial policy fact two",
            speaker: "user",
            eventTime: null,
            entities: [],
            confidence: 0.99,
          },
        ]);
      }
      return originalComplete(system, user);
    };
    embedder.embed = async (texts) => {
      embedCalls++;
      if (embedCalls > 1) throw new Error("forced second-candidate embedding failure");
      return originalEmbed(texts);
    };

    let failed;
    try {
      failed = await kernel.uploadPolicyDocument({
        namespace: "acme/partial-compensation",
        kind: "policy",
        fileName: "partial.md",
        content: "Two facts are extracted and the second provider call fails.",
      }, acmeOwner);
    } finally {
      llm.complete = originalComplete;
      embedder.embed = originalEmbed;
    }

    expect(failed).toMatchObject({
      status: "failed",
      failureCode: "ingest-failed",
      factCount: 0,
    });
    const visible = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status IN ('active','disputed') AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      [
        "acme/partial-compensation",
        JSON.stringify([{
          sourceId: failed!.sourceId,
          documentKey: "partial.md",
          contentHash: failed!.contentSha256,
        }]),
      ],
    );
    expect(visible.rows).toHaveLength(0);
    const retractions = await kernel.db.query(
      `SELECT result FROM audit_log
        WHERE namespace = $1 AND op = 'retract' AND detail LIKE '%"reason":"failed"%'`,
      ["acme/partial-compensation"],
    );
    expect(retractions.rows.length).toBeGreaterThan(0);
  });

  it("never lets a failed policy attempt close a pre-existing governing fact", async () => {
    const namespace = "acme/policy-conflict-compensation";
    const namespaceOwner = await issue(
      namespace,
      "owner:policy-conflict-compensation",
      "owner",
      acmeOwner,
    );
    await kernel.setPolicy(
      namespace,
      'verifierEnabled: false\nconflictReview: "off"\nrateLimitPerMin: 100000\n',
    );
    const llm = kernel.llm as {
      complete(system: string, user: string): Promise<string>;
    };
    const embedder = kernel.embedder as {
      embed(texts: string[]): Promise<number[][]>;
    };
    const originalComplete = llm.complete.bind(llm);
    const originalEmbed = embedder.embed.bind(embedder);
    const incumbentContent = "Policy access requires manager approval.";
    const conflictingContent = "Policy access does not require manager approval.";
    const failingContent = "A second extracted fact fails after the conflict.";
    const vector = (first: number, second: number) => [
      first,
      second,
      ...Array(Math.max(0, kernel.config.embedDim - 2)).fill(0),
    ];
    embedder.embed = async (texts) => {
      if (texts.some((text) => text === failingContent)) {
        throw new Error("forced post-conflict embedding failure");
      }
      return texts.map((text) =>
        text === incumbentContent ? vector(1, 0) : vector(0.8, 0.6),
      );
    };
    llm.complete = async (system, user) => {
      if (system.includes("[HALOMEM-EXTRACT]")) {
        return JSON.stringify([
          {
            content: conflictingContent,
            speaker: "user",
            eventTime: null,
            entities: [],
            confidence: 0.99,
          },
          {
            content: failingContent,
            speaker: "user",
            eventTime: null,
            entities: [],
            confidence: 0.99,
          },
        ]);
      }
      return originalComplete(system, user);
    };

    let failed;
    try {
      await kernel.memWrite(
        {
          scope: "org",
          content: incumbentContent,
          hints: { verbatim: true },
        },
        namespaceOwner,
      );
      failed = await kernel.uploadPolicyDocument({
        namespace,
        kind: "policy",
        fileName: "conflicting-policy.md",
        content: "The upload contains a conflict followed by a provider failure.",
      }, namespaceOwner);
    } finally {
      llm.complete = originalComplete;
      embedder.embed = originalEmbed;
    }

    expect(failed).toMatchObject({
      status: "failed",
      failureCode: "ingest-failed",
    });
    const incumbent = await kernel.db.query(
      `SELECT status, t_valid_to FROM memory_objects
        WHERE namespace = $1 AND content = $2`,
      [namespace, incumbentContent],
    );
    expect(incumbent.rows).toEqual([
      expect.objectContaining({ status: "active", t_valid_to: null }),
    ]);
    const attemptFacts = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status IN ('active','disputed')
          AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      [
        namespace,
        JSON.stringify([{ sourceId: failed!.sourceId }]),
      ],
    );
    expect(attemptFacts.rows).toHaveLength(0);
  });

  it("fences a timed-out attempt so its late failure cannot archive a successful retry", async () => {
    const namespace = "acme/lease-overlap";
    await kernel.setPolicy(
      namespace,
      "verifierEnabled: false\nrateLimitPerMin: 100000\n",
    );
    const llm = kernel.llm as {
      complete(system: string, user: string): Promise<string>;
    };
    const originalComplete = llm.complete.bind(llm);
    let extractionCalls = 0;
    let signalStarted!: () => void;
    let releaseOriginal!: () => void;
    const originalStarted = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const originalGate = new Promise<void>((resolve) => {
      releaseOriginal = resolve;
    });
    llm.complete = async (system, user) => {
      if (!system.includes("[HALOMEM-EXTRACT]")) {
        return originalComplete(system, user);
      }
      extractionCalls++;
      if (extractionCalls === 1) {
        signalStarted();
        await originalGate;
      }
      return JSON.stringify([{
        content: "Lease-fenced policy fact",
        speaker: "user",
        eventTime: null,
        entities: [],
        confidence: 0.99,
      }]);
    };

    const input = {
      namespace,
      kind: "policy" as const,
      fileName: "lease-overlap.md",
      content: "A timed-out attempt must never retract the successful retry.",
    };
    let originalUpload: Promise<Awaited<ReturnType<Kernel["uploadPolicyDocument"]>>> | undefined;
    let retry;
    try {
      originalUpload = kernel.uploadPolicyDocument(input, acmeOwner);
      await originalStarted;
      const pending = await kernel.db.query(
        `SELECT id, attempt_token FROM policy_documents
          WHERE namespace = $1 AND status = 'processing'`,
        [namespace],
      );
      expect(pending.rows).toHaveLength(1);
      await kernel.db.query(
        `UPDATE policy_documents
            SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
          WHERE id = $1`,
        [pending.rows[0]!.id],
      );

      retry = await kernel.uploadPolicyDocument(input, acmeOwner);
      expect(retry).toMatchObject({ status: "active", factCount: 1 });
      const sourceBeforeLateOriginal = await kernel.sources.get(retry.sourceId);
      releaseOriginal();
      const original = await originalUpload;
      expect(original).toMatchObject({
        status: "failed",
        failureCode: "processing-timeout",
        factCount: 0,
      });

      const facts = await kernel.db.query(
        `SELECT status, t_valid_to, provenance
           FROM memory_objects
          WHERE namespace = $1 AND provenance @> $2::jsonb`,
        [
          namespace,
          JSON.stringify([{
            sourceId: retry.sourceId,
            documentKey: input.fileName,
            contentHash: retry.contentSha256,
          }]),
        ],
      );
      expect(facts.rows).toHaveLength(1);
      expect(facts.rows[0]).toEqual(
        expect.objectContaining({ status: "active", t_valid_to: null }),
      );
      const provenance = typeof facts.rows[0]!.provenance === "string"
        ? JSON.parse(facts.rows[0]!.provenance as string)
        : facts.rows[0]!.provenance;
      expect(provenance[0].attemptToken).toBeTruthy();
      expect(provenance[0].attemptToken).not.toBe(pending.rows[0]!.attempt_token);
      const sourceAfterLateOriginal = await kernel.sources.get(retry.sourceId);
      expect(sourceAfterLateOriginal).toEqual(sourceBeforeLateOriginal);
    } finally {
      releaseOriginal();
      if (originalUpload) await originalUpload.catch(() => undefined);
      llm.complete = originalComplete;
    }
  });

  it("audits upload-rate denials before creating source or document state", async () => {
    const limiter = kernel.rateLimiter as {
      consume(
        bucket: string,
        limit: number,
        windowMs: number,
      ): Promise<{ allowed: boolean; remaining: number; retryAfterSec: number; resetAt: string }>;
    };
    const originalConsume = limiter.consume.bind(limiter);
    limiter.consume = async () => ({
      allowed: false,
      remaining: 0,
      retryAfterSec: 42,
      resetAt: new Date(Date.now() + 42_000).toISOString(),
    });
    try {
      await expect(kernel.uploadPolicyDocument({
        namespace: "acme/rate-denied",
        kind: "policy",
        fileName: "rate.md",
        content: "This upload is denied before durable policy state.",
      }, acmeOwner)).rejects.toMatchObject({ name: "RateLimitError" });
    } finally {
      limiter.consume = originalConsume;
    }

    const documents = await kernel.db.query(
      "SELECT id FROM policy_documents WHERE namespace = $1",
      ["acme/rate-denied"],
    );
    expect(documents.rows).toHaveLength(0);
    const audit = await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE namespace = $1 AND op = 'write' AND purpose = 'policy-upload'`,
      ["acme/rate-denied"],
    );
    expect(audit.rows).toEqual([
      expect.objectContaining({
        result: "denied",
        detail: "policy_upload_rate_limit",
      }),
    ]);
  });

  it("treats policy sources as immutable provenance rather than connector sync state", async () => {
    const registry = kernel.sources as {
      touchLastSync(sourceId: string, syncedAt: string): Promise<void>;
    };
    const originalTouch = registry.touchLastSync.bind(registry);
    let touchCalls = 0;
    registry.touchLastSync = async () => {
      touchCalls++;
      throw new Error("forced source metadata brownout");
    };
    let document;
    try {
      document = await kernel.uploadPolicyDocument({
        namespace: "acme/source-metadata-brownout",
        kind: "guideline",
        fileName: "brownout.md",
        content: "Agents continue using finalized policy state during bookkeeping brownout.",
      }, acmeOwner);
    } finally {
      registry.touchLastSync = originalTouch;
    }

    expect(document).toMatchObject({ status: "active", factCount: 1 });
    expect(touchCalls).toBe(0);
    const persisted = await kernel.db.query(
      "SELECT status FROM policy_documents WHERE id = $1",
      [document!.id],
    );
    expect(persisted.rows).toEqual([{ status: "active" }]);
  });

  it("returns a content-free failed row when DLP rejects the file before write", async () => {
    const secret = "private key: -----BEGIN PRIVATE KEY-----";
    const failed = await kernel.uploadPolicyDocument({
      namespace: "acme/legal",
      title: "Unsafe upload",
      kind: "policy",
      fileName: "unsafe.txt",
      content: secret,
    }, acmeOwner);

    expect(failed).toMatchObject({
      namespace: "acme/legal",
      status: "failed",
      factCount: 0,
    });
    expect(failed.failureCode).toMatch(/classification|ingest/i);
    expect(JSON.stringify(failed)).not.toContain(secret);

    const persisted = await kernel.db.query(
      `SELECT failure_code FROM policy_documents WHERE id = $1`,
      [failed.id],
    );
    expect(JSON.stringify(persisted.rows)).not.toContain(secret);
    const leaked = await kernel.db.query(
      `SELECT id FROM memory_objects WHERE content LIKE $1`,
      ["%BEGIN PRIVATE KEY%"],
    );
    expect(leaked.rows).toHaveLength(0);
    const source = await kernel.sources.get(failed.sourceId);
    expect(source?.lastSyncError).toBeNull();
    expect(JSON.stringify(source)).not.toContain(secret);
  });

  it("permanently deletes a policy document and removes its facts from memory", async () => {
    const namespace = "acme/delete-policy";
    const namespaceOwner = await issue(
      namespace,
      "owner:delete-policy",
      "owner",
      acmeOwner,
    );
    await kernel.setPolicy(namespace, "verifierEnabled: false\nrateLimitPerMin: 100000\n");

    const document = await kernel.uploadPolicyDocument({
      namespace,
      kind: "policy",
      fileName: "deletable.md",
      content: "This policy will be permanently deleted.",
    }, namespaceOwner);
    expect(document).toMatchObject({ status: "active", factCount: 1 });

    const beforeFacts = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      [
        namespace,
        JSON.stringify([{
          sourceId: document.sourceId,
          documentKey: "deletable.md",
          contentHash: document.contentSha256,
        }]),
      ],
    );
    expect(beforeFacts.rows).toHaveLength(1);

    const deleted = await kernel.deletePolicyDocument(document.id, namespaceOwner);
    expect(deleted.id).toBe(document.id);

    const row = await kernel.db.query(
      "SELECT id FROM policy_documents WHERE id = $1",
      [document.id],
    );
    expect(row.rows).toHaveLength(0);

    const afterFacts = await kernel.db.query(
      `SELECT id, status, t_valid_to FROM memory_objects
        WHERE namespace = $1
          AND provenance @> $2::jsonb`,
      [
        namespace,
        JSON.stringify([{
          sourceId: document.sourceId,
          documentKey: "deletable.md",
          contentHash: document.contentSha256,
        }]),
      ],
    );
    expect(afterFacts.rows).toHaveLength(1);
    expect(afterFacts.rows[0]).toEqual(
      expect.objectContaining({ status: "archived" }),
    );
    expect(afterFacts.rows[0].t_valid_to).not.toBeNull();

    const audit = await kernel.db.query(
      `SELECT op, result FROM audit_log
        WHERE namespace = $1 AND op = 'policy_delete'`,
      [namespace],
    );
    expect(audit.rows).toEqual([
      expect.objectContaining({ op: "policy_delete", result: "ok" }),
    ]);
  });

  it("blocks policy deletion outside the caller's subtree", async () => {
    const document = await kernel.uploadPolicyDocument({
      namespace: "acme/legal",
      kind: "policy",
      fileName: "protected.md",
      content: "Only the owner of acme/legal can delete this policy.",
    }, acmeOwner);

    await expect(
      kernel.deletePolicyDocument(document.id, rootAdmin),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      kernel.deletePolicyDocument(document.id, rootAuditor),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });
});
