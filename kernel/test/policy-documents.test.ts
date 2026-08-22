import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  normalizePolicyDocumentUpload,
  PolicyDocumentConflictError,
  PolicyDocumentQuotaError,
  PolicyDocumentStore,
  PolicyDocumentValidationError,
  type NormalizedPolicyDocumentUpload,
} from "../src/policy/documents.js";
import type {
  PolicyDocumentKind,
  PolicyDocumentStatus,
} from "../src/types.js";

const DIM = 8;
const CONTENT_LIMIT_BYTES = 512 * 1024;

let db: Db;
let store: PolicyDocumentStore;
let sourceOrdinal = 0;

beforeAll(async () => {
  db = await createDb(
    loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }),
  );
  await migrate(db, DIM);
  store = new PolicyDocumentStore(db);
});

beforeEach(async () => {
  await db.query("DELETE FROM policy_documents");
  await db.query("DELETE FROM policy_document_quota_usage");
  await db.query("DELETE FROM sources");
  sourceOrdinal = 0;
});

afterAll(async () => {
  await db.close();
});

function upload(
  overrides: Partial<{
    namespace: string;
    title: string;
    kind: PolicyDocumentKind;
    fileName: string;
    content: string;
  }> = {},
): NormalizedPolicyDocumentUpload {
  return normalizePolicyDocumentUpload({
    namespace: "acme",
    kind: "policy",
    fileName: "employee-handbook.md",
    content: "# Employee handbook\nKeep customer data private.",
    ...overrides,
  });
}

async function source(namespace: string): Promise<string> {
  const id = `source-${++sourceOrdinal}`;
  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at)
     VALUES ($1, $2, 'policy-upload', '{}', $3)`,
    [id, namespace, new Date().toISOString()],
  );
  return id;
}

async function createDocument(
  options: {
    namespace?: string;
    title?: string;
    kind?: PolicyDocumentKind;
    fileName?: string;
    content?: string;
    status?: Exclude<PolicyDocumentStatus, "processing">;
    factCount?: number;
  } = {},
) {
  const normalized = upload(options);
  const created = await store.createProcessing({
    sourceId: await source(normalized.namespace),
    upload: normalized,
    createdBy: "owner@acme.test",
  });
  if (options.status === "active") {
    return store.markActive(created.id, options.factCount ?? 1);
  }
  if (options.status === "needs_review") {
    return store.markNeedsReview(created.id, options.factCount ?? 1);
  }
  if (options.status === "failed") {
    return store.markFailed(created.id, "ingest_rejected");
  }
  return created;
}

describe("normalizePolicyDocumentUpload", () => {
  it("derives trusted metadata and a readable default title from the file", () => {
    const content = "Policy café";
    const normalized = upload({
      namespace: " acme/team ",
      fileName: "Incident_Response.MARKDOWN",
      content,
    });

    expect(normalized).toEqual({
      namespace: "acme/team",
      title: "Incident Response",
      kind: "policy",
      // A loaded policy is a guardrail by default — an upload that never says
      // otherwise is `required` and its misses are recorded.
      enforcement: "required",
      fileName: "Incident_Response.MARKDOWN",
      content,
      mediaType: "text/markdown",
      byteSize: Buffer.byteLength(content, "utf8"),
      contentSha256: createHash("sha256").update(content, "utf8").digest("hex"),
    });
  });

  it("accepts the exact empty namespace used by the authenticated platform root", () => {
    expect(upload({ namespace: "" })).toEqual(
      expect.objectContaining({
        namespace: "",
        title: "employee handbook",
      }),
    );
    expect(() => upload({ namespace: "   " })).toThrow(
      PolicyDocumentValidationError,
    );
  });

  it.each([
    ["parent traversal", "../policy.md", "ok"],
    ["Windows traversal", String.raw`folder\policy.md`, "ok"],
    ["control character", "policy\u0007.md", "ok"],
    ["NUL filename", "policy\u0000.md", "ok"],
    ["missing stem", ".md", "ok"],
    ["unsupported extension", "policy.pdf", "ok"],
    ["empty content", "policy.md", ""],
    ["whitespace-only content", "policy.md", " \r\n\t"],
    ["NUL content", "policy.md", "before\u0000after"],
  ])("rejects %s", (_case, fileName, content) => {
    expect(() => upload({ fileName, content })).toThrow(
      PolicyDocumentValidationError,
    );
  });

  it("enforces the 512 KiB cap using decoded UTF-8 bytes", () => {
    expect(
      upload({ content: "a".repeat(CONTENT_LIMIT_BYTES) }).byteSize,
    ).toBe(CONTENT_LIMIT_BYTES);
    expect(() =>
      upload({ content: "é".repeat(CONTENT_LIMIT_BYTES / 2 + 1) }),
    ).toThrow(PolicyDocumentValidationError);
  });

  it("rejects unbounded or invalid metadata", () => {
    expect(() => upload({ namespace: " " })).toThrow(
      PolicyDocumentValidationError,
    );
    expect(() => upload({ title: " " })).toThrow(
      PolicyDocumentValidationError,
    );
    expect(() =>
      upload({ title: "x".repeat(201) }),
    ).toThrow(PolicyDocumentValidationError);
    expect(() => upload({ title: "unsafe\u0000title" })).toThrow(
      PolicyDocumentValidationError,
    );
    expect(() => upload({ namespace: "unsafe\u0000scope" })).toThrow(
      PolicyDocumentValidationError,
    );
    expect(() =>
      upload({ kind: "contract" as PolicyDocumentKind }),
    ).toThrow(PolicyDocumentValidationError);
  });
});

describe("PolicyDocumentStore", () => {
  it("persists metadata only and records successful loading", async () => {
    const normalized = upload({ content: "Never persist this raw policy body." });
    const created = await store.createProcessing({
      sourceId: await source(normalized.namespace),
      upload: normalized,
      createdBy: "owner@acme.test",
    });

    expect(created).toEqual(
      expect.objectContaining({
        namespace: "acme",
        status: "processing",
        factCount: 0,
        failureCode: null,
        loadedAt: null,
      }),
    );
    const stored = await db.query(
      `SELECT to_jsonb(policy_documents)::text AS row
         FROM policy_documents WHERE id = $1`,
      [created.id],
    );
    expect(String(stored.rows[0]?.row)).not.toContain(normalized.content);

    const active = await store.markActive(created.id, 3);
    expect(active.status).toBe("active");
    expect(active.factCount).toBe(3);
    expect(active.loadedAt).toBeTruthy();
  });

  it("records needs-review and bounded failure outcomes", async () => {
    const review = await createDocument({ fileName: "review.md", content: "review" });
    const needsReview = await store.markNeedsReview(review.id, 2);
    expect(needsReview).toEqual(
      expect.objectContaining({
        status: "needs_review",
        factCount: 2,
        failureCode: null,
      }),
    );

    const failed = await createDocument({ fileName: "failed.md", content: "failed" });
    expect(await store.markFailed(failed.id, "dlp_rejected")).toEqual(
      expect.objectContaining({
        status: "failed",
        factCount: 0,
        failureCode: "dlp_rejected",
        loadedAt: null,
      }),
    );
    await expect(
      store.markFailed(failed.id, "provider said: raw secret follows"),
    ).rejects.toThrow(PolicyDocumentValidationError);
  });

  it("blocks active duplicate content but permits retry after failure", async () => {
    const firstUpload = upload({ content: "Same policy" });
    const first = await store.createProcessing({
      sourceId: await source("acme"),
      upload: firstUpload,
      createdBy: "owner@acme.test",
    });
    await store.markFailed(first.id, "ingest_rejected");

    const retry = await store.createProcessing({
      sourceId: await source("acme"),
      upload: firstUpload,
      createdBy: "owner@acme.test",
    });
    await store.markActive(retry.id, 1);

    await expect(
      store.createProcessing({
        sourceId: await source("acme"),
        upload: firstUpload,
        createdBy: "owner@acme.test",
      }),
    ).rejects.toBeInstanceOf(PolicyDocumentConflictError);

    await expect(
      store.createProcessing({
        sourceId: await source("acme/team"),
        upload: upload({ namespace: "acme/team", content: "Same policy" }),
        createdBy: "admin@acme.test",
      }),
    ).resolves.toEqual(expect.objectContaining({ namespace: "acme/team" }));
  });

  it("treats wildcard characters in namespaces and search as literals", async () => {
    await createDocument({
      namespace: "acme_1",
      title: String.raw`100% secure_ \ guide`,
      fileName: "root.md",
      content: "root",
      status: "active",
    });
    await createDocument({
      namespace: "acme_1/team%ops",
      title: "Child guide",
      fileName: "child.md",
      content: "child",
      status: "active",
    });
    await createDocument({
      namespace: "acmeX1",
      title: "Wildcard sibling",
      fileName: "sibling.md",
      content: "sibling",
      status: "active",
    });
    await createDocument({
      namespace: "percent%root",
      title: "Percent root",
      fileName: "percent-root.md",
      content: "percent root",
      status: "active",
    });
    await createDocument({
      namespace: "percent%root/team",
      title: "Percent child",
      fileName: "percent-child.md",
      content: "percent child",
      status: "active",
    });
    await createDocument({
      namespace: "percentXroot",
      title: "Percent sibling",
      fileName: "percent-sibling.md",
      content: "percent sibling",
      status: "active",
    });
    await createDocument({
      namespace: String.raw`slash\root`,
      title: "Backslash root",
      fileName: "backslash-root.md",
      content: "backslash root",
      status: "active",
    });
    await createDocument({
      namespace: String.raw`slash\root/team`,
      title: "Backslash child",
      fileName: "backslash-child.md",
      content: "backslash child",
      status: "active",
    });
    await createDocument({
      namespace: "slashXroot",
      title: "Backslash sibling",
      fileName: "backslash-sibling.md",
      content: "backslash sibling",
      status: "active",
    });

    const scoped = await store.list({ namespace: "acme_1", pageSize: 50 });
    expect(scoped.data.map((row) => row.namespace).sort()).toEqual([
      "acme_1",
      "acme_1/team%ops",
    ]);
    expect(
      (await store.list({ namespace: "percent%root" })).data.map(
        (row) => row.namespace,
      ).sort(),
    ).toEqual(["percent%root", "percent%root/team"]);
    expect(
      (await store.list({ namespace: String.raw`slash\root` })).data.map(
        (row) => row.namespace,
      ).sort(),
    ).toEqual([String.raw`slash\root`, String.raw`slash\root/team`]);

    for (const query of ["%", "_", "\\"]) {
      const result = await store.list({ namespace: "acme_1", query });
      expect(result.data.map((row) => row.title)).toEqual([
        String.raw`100% secure_ \ guide`,
      ]);
    }
  });

  it("lists every tenant from the platform root without weakening tenant scoping", async () => {
    await createDocument({
      namespace: "",
      title: "Platform policy",
      fileName: "platform.md",
      content: "platform",
      status: "active",
    });
    await createDocument({
      namespace: "acme_%root",
      title: "Acme root",
      fileName: "acme.md",
      content: "acme",
      status: "active",
    });
    await createDocument({
      namespace: "acme_%root/team",
      title: "Acme child",
      fileName: "acme-child.md",
      content: "acme child",
      status: "active",
    });
    await createDocument({
      namespace: String.raw`acmeXanythingroot\other`,
      title: "Wildcard sibling",
      fileName: "sibling.md",
      content: "wildcard sibling",
      status: "active",
    });
    await createDocument({
      namespace: "globex",
      title: "Globex policy",
      fileName: "globex.md",
      content: "globex",
      status: "active",
    });

    const global = await store.list({ namespace: "", pageSize: 50 });
    expect(global.data.map((row) => row.title).sort()).toEqual([
      "Acme child",
      "Acme root",
      "Globex policy",
      "Platform policy",
      "Wildcard sibling",
    ]);
    expect(global.summary).toEqual({
      total: 5,
      active: 5,
      needsReview: 0,
      failed: 0,
    });

    const tenant = await store.list({
      namespace: "acme_%root",
      pageSize: 50,
    });
    expect(tenant.data.map((row) => row.title).sort()).toEqual([
      "Acme child",
      "Acme root",
    ]);
  });

  it("filters and paginates deterministic rows while summaries cover the scope", async () => {
    const rows = [
      await createDocument({
        fileName: "a.md",
        title: "Alpha policy",
        kind: "policy",
        content: "a",
        status: "active",
      }),
      await createDocument({
        fileName: "b.md",
        title: "Bravo guide",
        kind: "guideline",
        content: "b",
        status: "needs_review",
      }),
      await createDocument({
        fileName: "c.yaml",
        title: "Charlie standard",
        kind: "standard",
        content: "c",
        status: "failed",
      }),
      await createDocument({
        namespace: "acme/team",
        fileName: "d.md",
        title: "Delta policy",
        kind: "policy",
        content: "d",
        status: "active",
      }),
      await createDocument({
        namespace: "other",
        fileName: "e.md",
        title: "External policy",
        kind: "policy",
        content: "e",
        status: "active",
      }),
    ];
    for (let index = 0; index < rows.length; index++) {
      await db.query(
        "UPDATE policy_documents SET created_at = $2 WHERE id = $1",
        [rows[index]!.id, new Date(Date.UTC(2026, 0, index + 1)).toISOString()],
      );
    }

    const page = await store.list({ namespace: "acme", page: 2, pageSize: 2 });
    expect(page.data.map((row) => row.title)).toEqual([
      "Bravo guide",
      "Alpha policy",
    ]);
    expect(page.pagination).toEqual({
      page: 2,
      pageSize: 2,
      total: 4,
      totalPages: 2,
    });
    expect(page.summary).toEqual({
      total: 4,
      active: 2,
      needsReview: 1,
      failed: 1,
    });

    const filtered = await store.list({
      namespace: "acme",
      query: "policy",
      kind: "policy",
      status: "active",
      pageSize: 50,
    });
    expect(filtered.data.map((row) => row.title).sort()).toEqual([
      "Alpha policy",
      "Delta policy",
    ]);
    expect(filtered.summary.total).toBe(4);
  });

  it("expires abandoned processing leases so an identical file can be retried", async () => {
    const normalized = upload({
      namespace: "acme/legal",
      fileName: "lease.md",
      content: "A durable policy lease",
    });
    const pending = await store.createProcessingAttempt({
      sourceId: await source("acme/legal"),
      upload: normalized,
      createdBy: "owner@acme.test",
    });
    await db.query(
      "UPDATE policy_documents SET lease_expires_at = $2 WHERE id = $1",
      [pending.document.id, "2026-01-01T00:00:00.000Z"],
    );

    const compensated: string[] = [];
    const expired = await store.claimExpiredProcessing(
      "acme/legal",
      pending.document.contentSha256,
      async (_tx, attempt) => {
        compensated.push(attempt.attemptToken);
      },
    );
    expect(expired).toHaveLength(1);
    expect(compensated).toEqual([pending.attemptToken]);
    await expect(
      store.renewLease(pending.document.id, pending.attemptToken),
    ).resolves.toBe(false);
    await expect(
      store.markActive(pending.document.id, 1, pending.attemptToken),
    ).rejects.toBeInstanceOf(PolicyDocumentConflictError);
    await expect(
      store.createProcessing({
        sourceId: await source("acme/legal"),
        upload: normalized,
        createdBy: "owner@acme.test",
      }),
    ).resolves.toMatchObject({ status: "processing" });
  });

  it("enforces aggregate document and byte quotas within one tenant subtree", async () => {
    await createDocument({
      namespace: "acme/legal",
      fileName: "quota.md",
      content: "Quota policy",
      status: "active",
    });

    await expect(
      store.assertWithinQuota("acme", 1, { maxDocuments: 1, maxBytes: 1_000 }),
    ).rejects.toBeInstanceOf(PolicyDocumentQuotaError);
    await expect(
      store.assertWithinQuota("globex", 1, { maxDocuments: 1, maxBytes: 1_000 }),
    ).resolves.toBeUndefined();
    await expect(
      store.assertWithinQuota("acme", 1_000, { maxDocuments: 10, maxBytes: 1_000 }),
    ).rejects.toBeInstanceOf(PolicyDocumentQuotaError);
  });

  it("reserves tenant quota atomically under concurrent uploads", async () => {
    const first = upload({
      namespace: "acme/legal",
      fileName: "one.md",
      content: "one",
    });
    const second = upload({
      namespace: "acme/security",
      fileName: "two.md",
      content: "two",
    });
    const outcomes = await Promise.allSettled([
      store.createProcessingAttempt(
        {
          sourceId: await source(first.namespace),
          upload: first,
          createdBy: "owner@acme.test",
        },
        { maxDocuments: 1, maxBytes: 100, maxRows: 10 },
      ),
      store.createProcessingAttempt(
        {
          sourceId: await source(second.namespace),
          upload: second,
          createdBy: "owner@acme.test",
        },
        { maxDocuments: 1, maxBytes: 100, maxRows: 10 },
      ),
    ]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const rejected = outcomes.find((outcome) => outcome.status === "rejected");
    expect(rejected).toMatchObject({ reason: expect.any(PolicyDocumentQuotaError) });
    const usage = await db.query(
      `SELECT current_documents, current_bytes, total_rows
         FROM policy_document_quota_usage WHERE tenant_root = 'acme'`,
    );
    expect(usage.rows[0]).toEqual(
      expect.objectContaining({
        current_documents: 1,
        total_rows: 1,
      }),
    );
  });

  it("bounds failed upload history so failures cannot bypass tenant quotas", async () => {
    for (const [index, content] of ["failed one", "failed two"].entries()) {
      const normalized = upload({
        fileName: `failed-${index}.md`,
        content,
      });
      const attempt = await store.createProcessingAttempt(
        {
          sourceId: await source("acme"),
          upload: normalized,
          createdBy: "owner@acme.test",
        },
        { maxDocuments: 1, maxBytes: 100, maxRows: 2 },
      );
      await store.markFailed(
        attempt.document.id,
        "ingest_failed",
        attempt.attemptToken,
      );
    }

    const third = upload({ fileName: "failed-3.md", content: "failed three" });
    await expect(
      store.createProcessingAttempt(
        {
          sourceId: await source("acme"),
          upload: third,
          createdBy: "owner@acme.test",
        },
        { maxDocuments: 1, maxBytes: 100, maxRows: 2 },
      ),
    ).rejects.toBeInstanceOf(PolicyDocumentQuotaError);
    const usage = await db.query(
      `SELECT current_documents, current_bytes, total_rows
         FROM policy_document_quota_usage WHERE tenant_root = 'acme'`,
    );
    expect(usage.rows[0]).toEqual(
      expect.objectContaining({
        current_documents: 0,
        current_bytes: 0,
        total_rows: 2,
      }),
    );
  });

  it("returns a bounded searchable scope directory without sibling leakage", async () => {
    await createDocument({
      namespace: "acme/legal",
      fileName: "legal.md",
      content: "Legal policy",
      status: "active",
    });
    await createDocument({
      namespace: "acme/support",
      fileName: "support.md",
      content: "Support policy",
      status: "active",
    });
    await createDocument({
      namespace: "globex/legal",
      fileName: "globex.md",
      content: "Globex policy",
      status: "active",
    });

    const tenant = await store.listScopes("acme");
    expect(tenant.data).toEqual(expect.arrayContaining([
      { namespace: "acme", documentCount: 0 },
      { namespace: "acme/legal", documentCount: 1 },
      { namespace: "acme/support", documentCount: 1 },
    ]));
    expect(tenant.data.some((item) => item.namespace.startsWith("globex"))).toBe(false);
    expect((await store.listScopes("acme", { query: "legal" })).data).toEqual([
      { namespace: "acme/legal", documentCount: 1 },
    ]);
    expect((await store.listScopes("", { global: true })).data).toEqual(
      expect.arrayContaining([
        { namespace: "", documentCount: 0 },
        { namespace: "globex/legal", documentCount: 1 },
      ]),
    );
  });

  it("validates list bounds before querying", async () => {
    await expect(store.list({ namespace: " ", page: 1 })).rejects.toThrow(
      PolicyDocumentValidationError,
    );
    await expect(store.list({ namespace: "acme", page: 0 })).rejects.toThrow(
      PolicyDocumentValidationError,
    );
    await expect(
      store.list({ namespace: "acme", pageSize: 51 }),
    ).rejects.toThrow(PolicyDocumentValidationError);
    await expect(
      store.list({ namespace: "acme", query: "x".repeat(201) }),
    ).rejects.toThrow(PolicyDocumentValidationError);
  });
});

describe("PolicyDocumentStore.delete", () => {
  it("removes an active document and releases its quota", async () => {
    const doc = await createDocument({
      namespace: "acme/legal",
      fileName: "retention.md",
      content: "Retention policy",
      status: "active",
      factCount: 3,
    });

    const deleted = await store.delete(doc.id);

    expect(deleted).toEqual({
      id: doc.id,
      sourceId: doc.sourceId,
      namespace: "acme/legal",
      fileName: "retention.md",
      contentSha256: doc.contentSha256,
      attemptToken: expect.any(String),
      byteSize: doc.byteSize,
      status: "active",
      // Deletion has to know which lane the row came from: it decides whether
      // facts are retracted by attempt token or by the file's provenance.
      origin: "upload",
    });
    expect(await store.get(doc.id)).toBeNull();
    const usage = await db.query(
      `SELECT current_documents, current_bytes, total_rows
         FROM policy_document_quota_usage WHERE tenant_root = 'acme'`,
    );
    expect(usage.rows[0]).toEqual(
      expect.objectContaining({
        current_documents: 0,
        current_bytes: 0,
        total_rows: 1,
      }),
    );
  });

  it("removes a failed document without double-releasing quota", async () => {
    const doc = await createDocument({
      namespace: "acme",
      fileName: "failed.md",
      content: "Failed policy",
      status: "failed",
    });

    const deleted = await store.delete(doc.id);

    expect(deleted.status).toBe("failed");
    expect(await store.get(doc.id)).toBeNull();
    const usage = await db.query(
      `SELECT current_documents, current_bytes, total_rows
         FROM policy_document_quota_usage WHERE tenant_root = 'acme'`,
    );
    expect(usage.rows[0]).toEqual(
      expect.objectContaining({
        current_documents: 0,
        current_bytes: 0,
        total_rows: 1,
      }),
    );
  });

  it("rejects deletion of an unknown document", async () => {
    await expect(store.delete("doc-does-not-exist")).rejects.toThrow(
      PolicyDocumentValidationError,
    );
  });

  it("runs inside a caller-owned transaction so retraction can share the same commit", async () => {
    const doc = await createDocument({
      namespace: "acme",
      fileName: "shared.md",
      content: "Shared policy",
      status: "needs_review",
    });

    const deleted = await db.transaction(async (tx) => {
      return store.deleteInTransaction(tx, doc.id);
    });

    expect(deleted.id).toBe(doc.id);
    expect(await store.get(doc.id)).toBeNull();
  });
});
