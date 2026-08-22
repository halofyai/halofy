import { beforeEach, afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  CompanyFileConcurrencyError,
  CompanyFileConflictError,
  CompanyFileLeaseExpiredError,
  CompanyFileQuotaError,
  CompanyFileRateLimitError,
  CompanyFileStore,
  MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS,
  type CompanyFileCompensation,
  type CompanyFileQuotaLimits,
} from "../src/knowledge-bases/company-files.js";

const DIM = 256;
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const REQUEST_A = "c".repeat(64);
const REQUEST_B = "d".repeat(64);

let db: Db;
let store: CompanyFileStore;

beforeEach(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  store = new CompanyFileStore(db);
});

afterEach(async () => {
  await db.close();
});

async function createBase(namespace = "acme", suffix = "root") {
  const now = new Date().toISOString();
  const sourceId = `source-${suffix}`;
  const knowledgeBaseId = `kb-${suffix}`;
  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at)
     VALUES ($1, $2, 'file-upload', '{}', $3)`,
    [sourceId, namespace, now],
  );
  await db.query(
    `INSERT INTO knowledge_bases
       (id, namespace, name, kind, status, lifecycle_state,
        primary_business_function, description, data_sensitive, t_valid_from,
        created_by, created_at, updated_at)
     VALUES ($1, $2, $3, 'file', 'empty', 'active', 'Operations', '', FALSE,
             $4, 'owner@acme.test', $4, $4)`,
    [knowledgeBaseId, namespace, `Files ${suffix}`, now],
  );
  return { sourceId, knowledgeBaseId, namespace };
}

async function reserve(
  base: Awaited<ReturnType<typeof createBase>>,
  options: {
    key?: string;
    requestHash?: string;
    contentHash?: string;
    fileName?: string;
    requestedFileCount?: number;
    limits?: CompanyFileQuotaLimits;
  } = {},
) {
  const attempt = await store.reserveAttempt({
    namespace: base.namespace,
    knowledgeBaseId: base.knowledgeBaseId,
    targetTeamId: null,
    idempotencyKey: options.key ?? `upload-${base.knowledgeBaseId}`,
    requestSha256: options.requestHash ?? REQUEST_A,
    requestedFileCount: options.requestedFileCount ?? 1,
    createdBy: "owner@acme.test",
  });
  const file = await store.reserveFile({
    namespace: base.namespace,
    knowledgeBaseId: base.knowledgeBaseId,
    sourceId: base.sourceId,
    uploadAttemptId: attempt.attempt.id,
    attemptToken: attempt.attemptToken,
    title: options.fileName ?? "Runbook",
    description: "Operational reference",
    purpose: "Incident response",
    fileName: options.fileName ?? "runbook.md",
    mediaType: "text/markdown",
    byteSize: 128,
    contentSha256: options.contentHash ?? HASH_A,
    createdBy: "owner@acme.test",
    uploadedBy: "owner@acme.test",
  }, options.limits);
  return { attempt, file };
}

describe("CompanyFileStore", () => {
  it("reserves metadata-only attempts and files without a raw-content surface", async () => {
    const base = await createBase();
    const { attempt, file } = await reserve(base);

    expect(attempt.attempt).toMatchObject({
      namespace: "acme",
      knowledgeBaseId: base.knowledgeBaseId,
      status: "processing",
      requestedFileCount: 1,
      acceptedFileCount: 0,
      failedFileCount: 0,
    });
    expect(file.file).toMatchObject({
      namespace: "acme",
      knowledgeBaseId: base.knowledgeBaseId,
      sourceId: base.sourceId,
      status: "processing",
      lifecycleState: "active",
      factCount: 0,
    });
    const stored = await db.query(
      `SELECT to_jsonb(company_files)::text AS file,
              (SELECT to_jsonb(company_file_upload_attempts)::text
                 FROM company_file_upload_attempts WHERE id = $2) AS attempt
         FROM company_files WHERE id = $1`,
      [file.file.id, attempt.attempt.id],
    );
    expect(String(stored.rows[0]?.file)).not.toMatch(/"(content|raw_content|payload|file_bytes|blob)"\s*:/i);
    expect(String(stored.rows[0]?.attempt)).not.toMatch(/"(content|raw_content|payload|file_bytes|blob)"\s*:/i);
  });

  it("replays the same idempotency digest and rejects key reuse with another digest", async () => {
    const base = await createBase();
    const first = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_A,
      requestedFileCount: 2,
      createdBy: "owner@acme.test",
    });
    const replay = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_A,
      requestedFileCount: 2,
      createdBy: "owner@acme.test",
    });
    expect(first.replayed).toBe(false);
    expect(replay).toEqual({ ...first, replayed: true });
    await expect(store.findAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_A,
      requestedFileCount: 2,
      createdBy: "owner@acme.test",
    })).resolves.toEqual(replay);

    await expect(store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_B,
      requestedFileCount: 2,
      createdBy: "owner@acme.test",
    })).rejects.toBeInstanceOf(CompanyFileConflictError);
    await expect(store.findAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_A,
      requestedFileCount: 2,
      createdBy: "another-admin@acme.test",
    })).rejects.toBeInstanceOf(CompanyFileConflictError);

    const sibling = await createBase("globex", "idempotency-sibling");
    await expect(store.reserveAttempt({
      namespace: sibling.namespace,
      knowledgeBaseId: sibling.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "stable-request",
      requestSha256: REQUEST_A,
      requestedFileCount: 2,
      createdBy: "owner@globex.test",
    })).resolves.toMatchObject({ replayed: false });
  });

  it("blocks active duplicate content but permits new immutable rows after failure or archive", async () => {
    const base = await createBase();
    const first = await reserve(base, { key: "first" });

    const secondAttempt = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "duplicate",
      requestSha256: REQUEST_B,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
    });
    await expect(store.reserveFile({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      sourceId: base.sourceId,
      uploadAttemptId: secondAttempt.attempt.id,
      attemptToken: secondAttempt.attemptToken,
      title: "Duplicate",
      description: "",
      purpose: "Reference",
      fileName: "duplicate.md",
      mediaType: "text/markdown",
      byteSize: 64,
      contentSha256: HASH_A,
      createdBy: "owner@acme.test",
      uploadedBy: "owner@acme.test",
    })).rejects.toBeInstanceOf(CompanyFileConflictError);

    await store.finalize(first.file.file.id, first.file.attemptToken, {
      status: "failed",
      factCount: 0,
      failureCode: "ingest_failed",
    });
    const retry = await reserve(base, { key: "retry", requestHash: HASH_B });
    await store.finalize(retry.file.file.id, retry.file.attemptToken, {
      status: "ready",
      factCount: 2,
    });
    await store.archive(retry.file.file.id, "acme");
    await expect(reserve(base, {
      key: "after-archive",
      requestHash: "e".repeat(64),
    })).resolves.toBeDefined();

    expect(Number((await db.query(
      "SELECT count(*) AS n FROM company_files WHERE knowledge_base_id = $1",
      [base.knowledgeBaseId],
    )).rows[0]?.n)).toBe(3);
  });

  it("admits attempts and consumes upload rate atomically while replays consume neither", async () => {
    const base = await createBase("acme", "atomic-rate");
    const rateLimit = { bucketKey: "company-file:test-atomic", limit: 1, windowMs: 60_000 };
    const first = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "atomic-first",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
      rateLimit,
    });
    await expect(store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "atomic-first",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
      rateLimit,
    })).resolves.toEqual({ ...first, replayed: true });
    await expect(store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "atomic-denied",
      requestSha256: REQUEST_B,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
      rateLimit,
    })).rejects.toBeInstanceOf(CompanyFileRateLimitError);

    expect((await db.query(
      "SELECT count(*) AS count FROM company_file_upload_attempts WHERE knowledge_base_id = $1",
      [base.knowledgeBaseId],
    )).rows[0]).toMatchObject({ count: 1 });
    expect((await db.query(
      "SELECT request_count FROM durable_rate_limits WHERE bucket_key = $1",
      [rateLimit.bucketKey],
    )).rows[0]).toMatchObject({ request_count: 1 });
  });

  it("reads only exact namespace ancestors and treats wildcard characters literally", async () => {
    const root = await createBase("acme_%", "literal-root");
    const child = await createBase("acme_%/legal", "literal-child");
    const sibling = await createBase("acmeXanything", "wildcard-sibling");
    const rootFile = await reserve(root, { key: "root" });
    const childFile = await reserve(child, { key: "child", contentHash: HASH_B });
    await reserve(sibling, { key: "sibling", contentHash: "f".repeat(64) });

    expect(await store.get(rootFile.file.file.id, "acme_%/legal/agent")).toMatchObject({
      namespace: "acme_%",
    });
    expect(await store.get(childFile.file.file.id, "acme_%")).toBeNull();
    expect((await store.list({ viewerNamespace: "acme_%/legal/agent", pageSize: 50 })).data
      .map((row) => row.namespace).sort()).toEqual(["acme_%", "acme_%/legal"]);
  });

  it("finalizes each file once and derives partial attempt counters atomically", async () => {
    const base = await createBase();
    const first = await reserve(base, { key: "batch", requestedFileCount: 2 });
    const second = await store.reserveFile({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      sourceId: base.sourceId,
      uploadAttemptId: first.attempt.attempt.id,
      attemptToken: first.attempt.attemptToken,
      title: "Second",
      description: "",
      purpose: "Operations",
      fileName: "second.md",
      mediaType: "text/markdown",
      byteSize: 32,
      contentSha256: HASH_B,
      createdBy: "owner@acme.test",
      uploadedBy: "owner@acme.test",
    });

    expect(await store.finalize(first.file.file.id, first.file.attemptToken, {
      status: "ready",
      factCount: 4,
    })).toMatchObject({ status: "ready", factCount: 4 });
    expect(await store.finalize(second.file.id, second.attemptToken, {
      status: "failed",
      factCount: 0,
      failureCode: "parser_failed",
    })).toMatchObject({ status: "failed", failureCode: "parser_failed" });

    const attempt = await store.getAttempt(first.attempt.attempt.id, "acme");
    expect(attempt).toMatchObject({
      status: "partially_failed",
      acceptedFileCount: 1,
      failedFileCount: 1,
    });
    await expect(store.finalize(first.file.file.id, first.file.attemptToken, {
      status: "needs_review",
      factCount: 1,
    })).rejects.toBeInstanceOf(CompanyFileConflictError);
  });

  it("renews active leases and expires abandoned work with exact provenance compensation", async () => {
    const base = await createBase();
    const pending = await reserve(base);
    expect(await store.renewLease(
      pending.attempt.attempt.id,
      pending.attempt.attemptToken,
      60_000,
    )).toBe(true);
    await db.query(
      `UPDATE company_file_upload_attempts SET lease_expires_at = $2 WHERE id = $1`,
      [pending.attempt.attempt.id, "2026-01-01T00:00:00.000Z"],
    );
    await db.query(
      `UPDATE company_files SET lease_expires_at = $2 WHERE id = $1`,
      [pending.file.file.id, "2026-01-01T00:00:00.000Z"],
    );

    const compensated: CompanyFileCompensation[] = [];
    const expired = await store.expireAttempt(
      pending.attempt.attempt.id,
      pending.attempt.attemptToken,
      async (_tx, exact) => { compensated.push(exact); },
    );
    expect(expired).toBe(true);
    expect(compensated).toEqual([expect.objectContaining({
      id: pending.file.file.id,
      sourceId: base.sourceId,
      namespace: "acme",
      documentKey: "runbook.md",
      contentHash: HASH_A,
      attemptToken: pending.attempt.attemptToken,
    })]);
    expect(await store.renewLease(
      pending.attempt.attempt.id,
      pending.attempt.attemptToken,
    )).toBe(false);
    await expect(store.finalize(pending.file.file.id, pending.file.attemptToken, {
      status: "ready",
      factCount: 1,
    })).rejects.toBeInstanceOf(CompanyFileLeaseExpiredError);
  });

  it("prevents expired writers from mutating a successful retry", async () => {
    const base = await createBase();
    const stale = await reserve(base, { key: "stale" });
    await db.query(
      `UPDATE company_file_upload_attempts SET lease_expires_at = $2 WHERE id = $1`,
      [stale.attempt.attempt.id, "2026-01-01T00:00:00.000Z"],
    );
    await db.query(
      `UPDATE company_files SET lease_expires_at = $2 WHERE id = $1`,
      [stale.file.file.id, "2026-01-01T00:00:00.000Z"],
    );
    await store.expireAttempt(stale.attempt.attempt.id, stale.attempt.attemptToken);

    const retry = await reserve(base, { key: "fresh", requestHash: HASH_B });
    await store.finalize(retry.file.file.id, retry.file.attemptToken, {
      status: "ready",
      factCount: 7,
    });
    await expect(store.finalize(stale.file.file.id, stale.file.attemptToken, {
      status: "ready",
      factCount: 99,
    })).rejects.toBeInstanceOf(CompanyFileLeaseExpiredError);
    expect(await store.get(retry.file.file.id, "acme")).toMatchObject({
      status: "ready",
      factCount: 7,
    });
  });

  it("archives without delete and invokes compensation exactly once", async () => {
    const base = await createBase();
    const pending = await reserve(base);
    await store.finalize(pending.file.file.id, pending.file.attemptToken, {
      status: "ready",
      factCount: 3,
    });
    const compensated: CompanyFileCompensation[] = [];
    const first = await store.archive(
      pending.file.file.id,
      "acme/team/admin",
      async (_tx, exact) => { compensated.push(exact); },
    );
    const replay = await store.archive(
      pending.file.file.id,
      "acme/team/admin",
      async (_tx, exact) => { compensated.push(exact); },
    );
    expect(first).toMatchObject({ lifecycleState: "archived", archivedAt: expect.any(String) });
    expect(replay).toEqual(first);
    expect(compensated).toHaveLength(1);
    expect((await db.query("SELECT lifecycle_state, t_valid_to FROM company_files WHERE id = $1", [
      pending.file.file.id,
    ])).rows[0]).toMatchObject({ lifecycle_state: "archived", t_valid_to: expect.anything() });
  });

  it("enforces tenant-wide current file/byte limits and a monotonic lifetime row cap", async () => {
    const limits = { maxFiles: 1, maxBytes: 128, maxRows: 2 };
    const firstBase = await createBase("acme/team-a", "quota-a");
    const secondBase = await createBase("acme/team-b", "quota-b");
    const thirdBase = await createBase("acme/team-c", "quota-c");

    const first = await reserve(firstBase, { key: "quota-a", limits });
    await expect(reserve(secondBase, {
      key: "quota-b",
      requestHash: REQUEST_B,
      contentHash: HASH_B,
      fileName: "second.md",
      limits,
    })).rejects.toBeInstanceOf(CompanyFileQuotaError);

    await store.finalize(first.file.file.id, first.file.attemptToken, {
      status: "failed",
      factCount: 0,
      failureCode: "test_failure",
    });
    const second = await reserve(secondBase, {
      key: "quota-b",
      requestHash: REQUEST_B,
      contentHash: HASH_B,
      fileName: "second.md",
      limits,
    });
    await store.finalize(second.file.file.id, second.file.attemptToken, {
      status: "ready",
      factCount: 1,
    });
    await store.archive(second.file.file.id, "acme/team-b/admin");

    await expect(reserve(thirdBase, {
      key: "quota-c",
      requestHash: "e".repeat(64),
      contentHash: "f".repeat(64),
      fileName: "third.md",
      limits,
    })).rejects.toBeInstanceOf(CompanyFileQuotaError);
    expect((await db.query(
      "SELECT current_files, current_bytes, total_rows FROM company_file_quota_usage WHERE tenant_root = 'acme'",
    )).rows[0]).toMatchObject({ current_files: 0, current_bytes: 0, total_rows: 2 });
  });

  // The concurrent-attempt cap bounds how much simultaneously-processing upload
  // work (and therefore LLM-extraction fan-out) one namespace can hold open,
  // independently of the per-minute request rate limit.
  it("caps concurrent processing attempts per namespace and leaves siblings unaffected", async () => {
    const base = await createBase("acme", "cap");
    for (let i = 0; i < MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS; i += 1) {
      await store.reserveAttempt({
        namespace: base.namespace,
        knowledgeBaseId: base.knowledgeBaseId,
        targetTeamId: null,
        idempotencyKey: `concurrent-${i}`,
        requestSha256: REQUEST_A,
        requestedFileCount: 1,
        createdBy: "owner@acme.test",
      });
    }

    // Reconciliation is not new work and remains available while fresh
    // attempts are blocked by the namespace concurrency cap.
    const replay = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "concurrent-0",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
    });
    expect(replay.replayed).toBe(true);

    await expect(store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "concurrent-overflow",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
    })).rejects.toBeInstanceOf(CompanyFileConcurrencyError);

    // The cap is per-namespace: a sibling namespace still has its full budget.
    const sibling = await createBase("globex", "cap-sibling");
    const ok = await store.reserveAttempt({
      namespace: sibling.namespace,
      knowledgeBaseId: sibling.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "sibling-1",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@globex.test",
    });
    expect(ok.attempt.status).toBe("processing");
  });

  // The cap counts in-flight attempts, so finalized ones must stop counting —
  // otherwise a namespace would wedge shut after MAX successful uploads.
  it("frees concurrency budget as attempts finalize", async () => {
    const base = await createBase("acme", "drain");
    for (let i = 0; i < MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS + 5; i += 1) {
      const { attempt, file } = await reserve(base, {
        key: `drain-${i}`,
        contentHash: i.toString(16).padStart(64, "0"),
        fileName: `drain-${i}.md`,
      });
      await store.finalize(file.file.id, file.attemptToken, {
        status: "ready",
        factCount: 1,
      });
      const row = await db.query(
        "SELECT status FROM company_file_upload_attempts WHERE id = $1",
        [attempt.attempt.id],
      );
      expect(row.rows[0]).toMatchObject({ status: "completed" });
    }
    const inFlight = await db.query(
      `SELECT count(*) AS count FROM company_file_upload_attempts
        WHERE namespace = $1 AND status = 'processing'`,
      [base.namespace],
    );
    expect(Number(inFlight.rows[0]?.count)).toBe(0);
  });

  it("does not count expired leases against the concurrency cap", async () => {
    const base = await createBase("acme", "expired");
    for (let i = 0; i < MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS; i += 1) {
      await store.reserveAttempt({
        namespace: base.namespace,
        knowledgeBaseId: base.knowledgeBaseId,
        targetTeamId: null,
        idempotencyKey: `expired-${i}`,
        requestSha256: REQUEST_A,
        requestedFileCount: 1,
        createdBy: "owner@acme.test",
      });
    }
    // Age every lease out; abandoned attempts must not wedge the namespace shut.
    await db.query(
      `UPDATE company_file_upload_attempts
          SET lease_expires_at = $1 WHERE namespace = $2`,
      [new Date(Date.now() - 60_000).toISOString(), base.namespace],
    );

    const revived = await store.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.knowledgeBaseId,
      targetTeamId: null,
      idempotencyKey: "expired-overflow",
      requestSha256: REQUEST_A,
      requestedFileCount: 1,
      createdBy: "owner@acme.test",
    });
    expect(revived.attempt.status).toBe("processing");
  });
});
