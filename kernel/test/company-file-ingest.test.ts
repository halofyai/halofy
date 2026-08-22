import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  Kernel,
  WRITE_PATH_EMBED_ATTEMPT_TIMEOUT_MS,
  WRITE_PATH_LLM_ATTEMPT_TIMEOUT_MS,
} from "../src/kernel.js";
import {
  MAX_COMPANY_FILE_CHUNK_BYTES,
  parseCompanyFileInput,
} from "../src/ingest/company-file.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let acmeOwner: Identity;
let acmeAuditor: Identity;
let acmeAgent: Identity;
let globexAdmin: Identity;

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
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-company-files-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
  });
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root identity resolution failed");
  root = resolvedRoot;
  acmeOwner = await issue("acme", "owner:acme", "owner", root);
  acmeAuditor = await issue("acme", "auditor:acme", "auditor", acmeOwner);
  acmeAgent = await issue("acme/agent-1", "agent:acme", "agent", acmeOwner);
  globexAdmin = await issue("globex", "admin:globex", "admin", root);
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\nverifierEnabled: false\n");
}, 120_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("kernel knowledge-base orchestration", () => {
  it("resolves target teams server-side and enforces the management role matrix", async () => {
    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, name, created_by, created_at)
       VALUES ('support-team', 'acme/support', 'Support', 'owner:acme', $1),
              ('globex-team', 'globex/support', 'Globex', 'owner:platform', $1)`,
      [new Date().toISOString()],
    );

    const base = await kernel.createKnowledgeBase({
      name: "Support library",
      kind: "file",
      targetTeamId: "support-team",
      primaryBusinessFunction: "Customer support",
      description: "Approved support knowledge",
      dataSensitive: true,
    }, acmeOwner);
    expect(base).toMatchObject({
      namespace: "acme/support",
      targetTeamId: "support-team",
      lifecycleState: "active",
      status: "empty",
    });

    await expect(kernel.listKnowledgeBases({}, acmeAuditor)).resolves.toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([expect.objectContaining({ id: base.id })]),
      }),
    );
    await expect(kernel.createKnowledgeBase({
      name: "Denied",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "General",
      description: "",
      dataSensitive: false,
    }, acmeAuditor)).rejects.toMatchObject({ name: "AuthzError" });
    await expect(kernel.listKnowledgeBases({}, acmeAgent)).rejects.toMatchObject({
      name: "AuthzError",
    });
    await expect(kernel.createKnowledgeBase({
      name: "Cross tenant",
      kind: "file",
      targetTeamId: "globex-team",
      primaryBusinessFunction: "General",
      description: "",
      dataSensitive: false,
    }, acmeOwner)).rejects.toMatchObject({ name: "AuthzError" });

    expect(await kernel.pauseKnowledgeBase(base.id, acmeOwner)).toMatchObject({
      lifecycleState: "paused",
    });
    expect(await kernel.resumeKnowledgeBase(base.id, acmeOwner)).toMatchObject({
      lifecycleState: "active",
    });
  });

  it("reuses an existing folder connector and mirrors pause/resume lifecycle", async () => {
    const source = await kernel.sources.register(
      "acme",
      "filesystem",
      { path: "C:/mounted/knowledge" },
      "kb_folder_source",
    );
    const base = await kernel.createKnowledgeBase({
      name: "Mounted docs",
      kind: "folder",
      sourceId: source.id,
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Mounted operating documents",
      dataSensitive: false,
    }, acmeOwner);
    expect(base.sourceId).toBe(source.id);

    await kernel.pauseKnowledgeBase(base.id, acmeOwner);
    expect((await kernel.sources.get(source.id))?.lifecycleState).toBe("paused");
    await kernel.resumeKnowledgeBase(base.id, acmeOwner);
    expect((await kernel.sources.get(source.id))?.lifecycleState).toBe("active");
  });
});

describe("kernel company-file ingestion", () => {
  it("allows three minutes for each extraction and embedding provider attempt", () => {
    expect(WRITE_PATH_LLM_ATTEMPT_TIMEOUT_MS).toBe(180_000);
    expect(WRITE_PATH_EMBED_ATTEMPT_TIMEOUT_MS).toBe(180_000);
  });

  it("splits large extracted documents into stable provider-sized records", async () => {
    const content = Array.from(
      { length: 240 },
      (_, index) => `Section ${index + 1}\n${"Design evidence and benchmark context. ".repeat(5)}`,
    ).join("\n\n");
    const input = {
      fileName: "benchmark.md",
      content: new TextEncoder().encode(content),
      purpose: "Compare ingestion quality",
      description: "Large document regression",
      businessFunction: "Design",
      dataSensitive: false,
    };

    const first = await parseCompanyFileInput(input);
    const replay = await parseCompanyFileInput(input);

    expect(first.length).toBeGreaterThan(1);
    expect(first.map((record) => record.docId)).toEqual(replay.map((record) => record.docId));
    expect(first[0]?.docId).toMatch(/^benchmark\.md#chunk-0001-of-/);
    expect(first.at(-1)?.docId).toMatch(new RegExp(`of-${String(first.length).padStart(4, "0")}$`));
    expect(first.every((record) =>
      Buffer.byteLength(record.content, "utf8") <= MAX_COMPANY_FILE_CHUNK_BYTES + 2_048,
    )).toBe(true);
    expect(first.every((record) => record.content.includes('"chunk":'))).toBe(true);
  });

  it("keeps the original filename and media type when a document is chunked", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Chunked file metadata",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Design",
      description: "Chunked file metadata regression",
      dataSensitive: false,
    }, acmeOwner);
    const content = Array.from(
      { length: 240 },
      (_, index) => `Design benchmark section ${index + 1}: ${"governed component guidance. ".repeat(5)}`,
    ).join("\n\n");

    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "large-design-guide.md",
      content,
      title: "Large design guide",
      description: "",
      purpose: "Verify chunked uploads",
    }, acmeOwner);

    expect(file).toMatchObject({
      status: "ready",
      fileName: "large-design-guide.md",
      mediaType: "text/markdown",
      failureCode: null,
    });
    expect(file.factCount).toBeGreaterThan(1);
  });

  it("reports the real embedding stage when indexing fails", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Embedding failure detail",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Engineering",
      description: "Stage-specific error regression",
      dataSensitive: false,
    }, globexAdmin);
    const embedSpy = vi.spyOn(kernel.embedder, "embed")
      .mockRejectedValue(new Error("test embedding provider unavailable"));
    try {
      const file = await kernel.uploadCompanyFile({
        knowledgeBaseId: base.id,
        fileName: "embedding-failure.md",
        content: "This unique document must reach its embedding boundary.",
        title: "Embedding failure",
        description: "",
        purpose: "Verify stage reporting",
      }, globexAdmin);

      expect(file).toMatchObject({
        status: "failed",
        factCount: 0,
        failureCode: "embedding_failed",
      });
    } finally {
      embedSpy.mockRestore();
    }
  });

  it("durably acknowledges an encrypted upload, processes it in the background, and scrubs staging", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Async design library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Design",
      description: "Durable upload regression",
      dataSensitive: false,
    }, acmeOwner);
    const content = "Sextant buttons use the approved focus-ring token.";
    const input = {
      knowledgeBaseId: base.id,
      fileName: "sextant-async.md",
      idempotencyKey: "async_sextant_001",
      content,
      title: "Sextant async",
      description: "Design system reference",
      purpose: "Guide product design",
    };

    const persistedStages: string[] = [];
    const advanceStage = kernel.companyFileJobs.advanceStage.bind(kernel.companyFileJobs);
    const stageSpy = vi.spyOn(kernel.companyFileJobs, "advanceStage")
      .mockImplementation(async (uploadId, stage) => {
        await advanceStage(uploadId, stage);
        const persisted = await kernel.companyFileJobs.get(uploadId);
        if (persisted) persistedStages.push(persisted.stage);
      });
    const accepted = await kernel.submitCompanyFileUpload(input, acmeOwner);
    const visibleWhileProcessing = await kernel.listCompanyFiles({
      knowledgeBaseId: base.id,
      lifecycleState: "active",
      includeUploads: true,
    }, acmeAuditor);
    expect(visibleWhileProcessing.uploads).toEqual([
      expect.objectContaining({
        uploadId: accepted.uploadId,
        knowledgeBaseId: base.id,
        fileName: "sextant-async.md",
        title: "Sextant async",
        status: expect.stringMatching(/^(queued|processing)$/),
      }),
    ]);
    expect(JSON.stringify(visibleWhileProcessing.uploads)).not.toContain(content);
    await expect(kernel.listCompanyFiles({
      knowledgeBaseId: base.id,
      includeUploads: true,
    }, globexAdmin)).rejects.toMatchObject({ name: "KnowledgeBaseNotFoundError" });
    const replay = await kernel.submitCompanyFileUpload(input, acmeOwner);
    expect(accepted).toMatchObject({ status: "queued" });
    expect(replay.uploadId).toBe(accepted.uploadId);
    await expect(kernel.submitCompanyFileUpload({
      ...input,
      content: "Different content must not reuse this accepted request.",
    }, acmeOwner)).rejects.toMatchObject({
      name: "CompanyFileIdempotencyError",
      code: "company_file_idempotency_conflict",
    });

    const staged = await kernel.db.query(
      `SELECT payload_ciphertext, payload_iv, payload_tag, payload_kek_id
         FROM company_file_ingest_jobs WHERE id = $1`,
      [accepted.uploadId],
    );
    expect(staged.rows).toHaveLength(1);
    expect(JSON.stringify(staged.rows[0])).not.toContain(content);
    const durable = await kernel.db.query(
      `SELECT payload::text AS payload FROM durable_jobs
        WHERE id = $1`,
      [`company-file-upload:${accepted.uploadId}`],
    );
    expect(String(durable.rows[0]?.payload)).not.toContain(content);

    let status = await kernel.companyFileUploadStatus(accepted.uploadId, acmeAuditor);
    for (let attempt = 0; attempt < 50 && ["queued", "processing"].includes(status.status); attempt++) {
      await kernel.runCompanyFileUploadJobsOnce(1);
      await new Promise((resolve) => setTimeout(resolve, 20));
      status = await kernel.companyFileUploadStatus(accepted.uploadId, acmeAuditor);
    }
    expect(status).toMatchObject({ status: "ready", stage: "complete", failureCode: null });
    expect(status.file).toMatchObject({ fileName: "sextant-async.md", factCount: 1 });
    expect(stageSpy.mock.calls.map((call) => call[1])).toEqual(expect.arrayContaining([
      "parsing", "extracting", "embedding", "finalizing",
    ]));
    expect(persistedStages).toEqual([
      "parsing", "extracting", "embedding", "finalizing",
    ]);
    stageSpy.mockRestore();

    const scrubbed = await kernel.db.query(
      `SELECT stage, payload_ciphertext, payload_iv, payload_tag, payload_kek_id
         FROM company_file_ingest_jobs WHERE id = $1`,
      [accepted.uploadId],
    );
    expect(scrubbed.rows[0]).toEqual({
      stage: "complete",
      payload_ciphertext: null,
      payload_iv: null,
      payload_tag: null,
      payload_kek_id: null,
    });

    const duplicate = await kernel.submitCompanyFileUpload({
      ...input,
      fileName: "sextant-async-copy.md",
      idempotencyKey: "async_sextant_duplicate_001",
    }, acmeOwner);
    let duplicateStatus = await kernel.companyFileUploadStatus(duplicate.uploadId, acmeAuditor);
    for (
      let attempt = 0;
      attempt < 50 && ["queued", "processing"].includes(duplicateStatus.status);
      attempt++
    ) {
      await kernel.runCompanyFileUploadJobsOnce(1);
      await new Promise((resolve) => setTimeout(resolve, 20));
      duplicateStatus = await kernel.companyFileUploadStatus(duplicate.uploadId, acmeAuditor);
    }
    expect(duplicateStatus).toMatchObject({
      status: "failed",
      failureCode: "duplicate_content",
      file: null,
    });

    await expect(kernel.companyFileUploadStatus(accepted.uploadId, acmeAgent))
      .rejects.toMatchObject({ name: "AuthzError" });
    await expect(kernel.companyFileUploadStatus(accepted.uploadId, globexAdmin))
      .rejects.toMatchObject({ name: "KnowledgeBaseNotFoundError" });
  });

  it("checkpoints successful chunks and resumes only the failed chunk", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Resumable complex documents",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Engineering",
      description: "Durable chunk recovery regression",
      dataSensitive: false,
    }, acmeOwner);
    const firstMarker = "FIRST_CHECKPOINT_SECTION";
    const secondMarker = "SECOND_CHECKPOINT_SECTION";
    const content = `${firstMarker}\n${"First section context. ".repeat(530)}\n\n` +
      `${secondMarker}\n${"Second section context. ".repeat(160)}`;
    const input = {
      knowledgeBaseId: base.id,
      fileName: "resumable-complex.md",
      idempotencyKey: `resumable_complex_${Date.now()}`,
      content,
      title: "Resumable complex document",
      description: "Two deterministic chunks",
      purpose: "Verify durable chunk recovery",
    };
    expect((await parseCompanyFileInput({
      fileName: input.fileName,
      content: new TextEncoder().encode(content),
      purpose: input.purpose,
      description: input.description,
      businessFunction: "Engineering",
      dataSensitive: false,
    }))).toHaveLength(2);

    const accepted = await kernel.companyFileJobs.enqueue({
      namespace: base.namespace,
      knowledgeBaseId: base.id,
      idempotencyKey: `job_${input.idempotencyKey}`,
      requestSha256: createHash("sha256").update(JSON.stringify(input)).digest("hex"),
      payload: input,
      createdBy: acmeOwner.actor,
      rateLimit: {
        bucketKey: `chunk-resume-${Date.now()}`,
        limit: 10,
        windowMs: 60_000,
      },
    });

    const llm = kernel.llm as { complete(system: string, user: string): Promise<string> };
    const originalComplete = llm.complete.bind(llm);
    const originalEmbed = kernel.embedder.embed.bind(kernel.embedder);
    let extractionCalls = 0;
    let secondEmbeddingFailures = 3;
    llm.complete = async (system, user) => {
      if (!system.includes("[HALOMEM-EXTRACT]")) return originalComplete(system, user);
      extractionCalls++;
      return JSON.stringify([{
        content: extractionCalls === 1
          ? "First checkpoint fact remains durable."
          : "Second checkpoint fact is recoverable.",
        speaker: "user",
        eventTime: null,
        entities: [],
        confidence: 0.99,
      }]);
    };
    kernel.embedder.embed = async (texts) => {
      if (
        secondEmbeddingFailures > 0 &&
        texts.some((text) => text.includes("Second checkpoint fact"))
      ) {
        secondEmbeddingFailures--;
        throw new Error("temporary embedding outage");
      }
      return originalEmbed(texts);
    };

    try {
      const firstRun = await kernel.runCompanyFileUploadJobsOnce(1);
      expect(firstRun).toMatchObject({ claimed: 1, completed: 0 });
      const firstCheckpoints = await kernel.db.query(
        `SELECT chunk_index, status, attempts, fact_count
           FROM company_file_ingest_chunks WHERE upload_id = $1 ORDER BY chunk_index`,
        [accepted.uploadId],
      );
      expect(firstCheckpoints.rows).toEqual([
        expect.objectContaining({ chunk_index: 0, status: "complete", attempts: 1 }),
        expect.objectContaining({ chunk_index: 1, status: "failed", attempts: 1 }),
      ]);
      expect(extractionCalls).toBe(2);
      expect((await kernel.db.query(
        `SELECT count(*)::int AS n FROM memory_objects
          WHERE namespace = $1 AND content LIKE '%First checkpoint fact%'
            AND t_valid_to IS NULL`,
        [base.namespace],
      )).rows[0]?.n).toBe(1);

      await kernel.db.query(
        `UPDATE durable_jobs SET available_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
          WHERE id = $1`,
        [`company-file-upload:${accepted.uploadId}`],
      );
      const secondRun = await kernel.runCompanyFileUploadJobsOnce(1);
      expect(secondRun).toMatchObject({ claimed: 1, completed: 1 });
      expect(extractionCalls).toBe(3);

      const final = await kernel.companyFileUploadStatus(accepted.uploadId, acmeAuditor);
      expect(final).toMatchObject({ status: "ready", stage: "complete", failureCode: null });
      expect(final.file?.factCount).toBe(2);
      const completed = await kernel.db.query(
        `SELECT chunk_index, status, attempts, fact_count
           FROM company_file_ingest_chunks WHERE upload_id = $1 ORDER BY chunk_index`,
        [accepted.uploadId],
      );
      expect(completed.rows).toEqual([
        expect.objectContaining({ chunk_index: 0, status: "complete", attempts: 1 }),
        expect.objectContaining({ chunk_index: 1, status: "complete", attempts: 2 }),
      ]);
      const scrubbed = await kernel.db.query(
        `SELECT payload_ciphertext FROM company_file_ingest_jobs WHERE id = $1`,
        [accepted.uploadId],
      );
      expect(scrubbed.rows[0]?.payload_ciphertext).toBeNull();
    } finally {
      llm.complete = originalComplete;
      kernel.embedder.embed = originalEmbed;
    }
  });

  it("keeps worker lanes full when one queued company file is slow", async () => {
    await kernel.runCompanyFileUploadJobsOnce(2);
    const base = await kernel.createKnowledgeBase({
      name: "Parallel upload regression",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Design",
      description: "Worker concurrency regression",
      dataSensitive: false,
    }, acmeOwner);
    const inputs = [1, 2, 3].map((index) => ({
      knowledgeBaseId: base.id,
      fileName: `parallel-${index}.md`,
      content: `Parallel upload ${index} carries unique governed content.`,
      title: `Parallel upload ${index}`,
      description: "",
      purpose: "Verify bounded concurrency",
    }));
    for (const [index, input] of inputs.entries()) {
      await kernel.companyFileJobs.enqueue({
        namespace: base.namespace,
        knowledgeBaseId: base.id,
        idempotencyKey: `parallel_worker_${index + 1}_${Date.now()}`,
        requestSha256: createHash("sha256").update(JSON.stringify(input)).digest("hex"),
        payload: input,
        createdBy: acmeOwner.actor,
        rateLimit: {
          bucketKey: `parallel-worker-test-${index}-${Date.now()}`,
          limit: 10,
          windowMs: 60_000,
        },
      });
    }

    const originalUpload = kernel.uploadCompanyFile.bind(kernel);
    let active = 0;
    let maximumActive = 0;
    const started: string[] = [];
    let markThirdStarted!: () => void;
    let release!: () => void;
    const thirdStarted = new Promise<void>((resolve) => { markThirdStarted = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const uploadSpy = vi.spyOn(kernel, "uploadCompanyFile")
      .mockImplementation(async (input, identity, options) => {
        active++;
        started.push(input.fileName);
        maximumActive = Math.max(maximumActive, active);
        if (input.fileName === "parallel-3.md") markThirdStarted();
        if (input.fileName === "parallel-1.md") await gate;
        try {
          return await originalUpload(input, identity, options);
        } finally {
          active--;
        }
      });
    try {
      const run = kernel.runCompanyFileUploadJobsOnce(2);
      const observedThird = await Promise.race([
        thirdStarted.then(() => true),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 2_000)),
      ]);
      release();
      const result = await run;

      expect(observedThird).toBe(true);
      expect(started).toEqual(expect.arrayContaining([
        "parallel-1.md", "parallel-2.md", "parallel-3.md",
      ]));
      expect(maximumActive).toBe(2);
      expect(result).toMatchObject({ claimed: 3, completed: 3 });
    } finally {
      release();
      uploadSpy.mockRestore();
    }
  });

  it("completes an upload before optional relationship enrichment", async () => {
    await kernel.runCompanyFileUploadJobsOnce(1);
    const base = await kernel.createKnowledgeBase({
      name: "Non-blocking relationship enrichment",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Upload finalization regression",
      dataSensitive: false,
    }, acmeOwner);
    const input = {
      knowledgeBaseId: base.id,
      fileName: "non-blocking-enrichment.md",
      content: "The synthetic Beacon team owns the Atlas service at https://example.com/atlas.",
      title: "Non-blocking enrichment",
      description: "",
      purpose: "Verify upload finalization",
    };
    const accepted = await kernel.companyFileJobs.enqueue({
      namespace: base.namespace,
      knowledgeBaseId: base.id,
      idempotencyKey: `non_blocking_enrichment_${Date.now()}`,
      requestSha256: createHash("sha256").update(JSON.stringify(input)).digest("hex"),
      payload: input,
      createdBy: acmeOwner.actor,
      rateLimit: {
        bucketKey: `non-blocking-enrichment-${Date.now()}`,
        limit: 10,
        windowMs: 60_000,
      },
    });

    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const originalEnrich = kernel.relationships.enrich.bind(kernel.relationships);
    const enrichSpy = vi.spyOn(kernel.relationships, "enrich")
      .mockImplementation(async (payload) => {
        await gate;
        return originalEnrich(payload);
      });
    try {
      const result = await Promise.race([
        kernel.runCompanyFileUploadJobsOnce(1),
        new Promise<never>((_, reject) => setTimeout(
          () => reject(new Error("company-file worker waited for relationship enrichment")),
          2_000,
        )),
      ]);
      expect(result).toMatchObject({ claimed: 1, completed: 1 });
      await expect(kernel.companyFileUploadStatus(accepted.uploadId, acmeAuditor))
        .resolves.toMatchObject({ status: "ready", stage: "complete" });

      const relationshipJob = await kernel.db.query(
        `SELECT state, payload::text AS payload FROM durable_jobs WHERE id = $1`,
        [`relationship-enrichment:${accepted.uploadId}`],
      );
      expect(relationshipJob.rows).toHaveLength(1);
      expect(["queued", "running"]).toContain(relationshipJob.rows[0]?.state);
      expect(String(relationshipJob.rows[0]?.payload)).not.toContain(input.content);

      const sourceDocument = await kernel.db.query(
        `SELECT document_key FROM source_documents
          WHERE landing_namespace = $1 AND document_key = $2`,
        [base.namespace, "non-blocking-enrichment.md"],
      );
      expect(sourceDocument.rows).toHaveLength(1);
    } finally {
      release();
      for (let attempt = 0; attempt < 20; attempt++) {
        await kernel.runRelationshipEnrichmentJobsOnce(1);
        const state = await kernel.db.query(
          `SELECT state FROM durable_jobs WHERE id = $1`,
          [`relationship-enrichment:${accepted.uploadId}`],
        );
        if (state.rows[0]?.state === "done") break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      enrichSpy.mockRestore();
    }

    const completedJob = await kernel.db.query(
      `SELECT state FROM durable_jobs WHERE id = $1`,
      [`relationship-enrichment:${accepted.uploadId}`],
    );
    expect(completedJob.rows[0]?.state).toBe("done");
  });

  it("stores the document through verbatim brownout when provider retries exhaust", async () => {
    let providerCalls = 0;
    const provider = createServer((req, res) => {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        if (body.includes("Sextant spacing tokens")) providerCalls += 1;
        res.writeHead(429, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "rate_limit", message: "busy" } }));
      });
    });
    await new Promise<void>((resolve) => provider.listen(0, "127.0.0.1", resolve));
    const port = (provider.address() as AddressInfo).port;
    const degradedDir = await mkdtemp(join(tmpdir(), "halomem-company-file-brownout-"));
    let degraded: Kernel | undefined;
    try {
      degraded = await Kernel.boot({
        databaseUrl: "",
        pgliteDataDir: "",
        knowledgeDir: degradedDir,
        azureOpenaiLlmApiKey: "test-key",
        azureOpenaiLlmEndpoint: `http://127.0.0.1:${port}`,
        azureOpenaiLlmDeployment: "test-deployment",
      });
      const rootKey = await degraded.auth.issueKey("", "owner:brownout-root", "owner");
      const rootIdentity = await degraded.auth.resolve(rootKey.plaintext);
      if (!rootIdentity) throw new Error("brownout root identity resolution failed");
      const ownerKey = await degraded.auth.issueKey(
        "acme/design",
        "owner:design",
        "owner",
        rootIdentity,
      );
      const owner = await degraded.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("brownout owner identity resolution failed");
      await degraded.setPolicy(
        "acme/design",
        "rateLimitPerMin: 100000\nverifierEnabled: false\n",
      );
      const base = await degraded.createKnowledgeBase({
        name: "Design system",
        kind: "file",
        targetTeamId: null,
        primaryBusinessFunction: "Design",
        description: "Provider brownout regression",
        dataSensitive: false,
      }, owner);

      const file = await degraded.uploadCompanyFile({
        knowledgeBaseId: base.id,
        fileName: "design-system-sextant-v2.3.md",
        content: "Sextant spacing tokens use an eight point layout grid.",
        title: "Sextant design system v2.3",
        description: "Design system reference",
        purpose: "Guide the design team",
      }, owner);

      expect(providerCalls).toBe(3);
      expect(file).toMatchObject({ status: "ready", factCount: 1 });
      const memory = await degraded.db.query(
        `SELECT provenance FROM memory_objects
          WHERE namespace = 'acme/design' AND t_valid_to IS NULL`,
      );
      expect(memory.rows).toHaveLength(1);
      expect(memory.rows[0]?.provenance).toEqual(
        expect.arrayContaining([expect.objectContaining({ extraction: "verbatim" })]),
      );
    } finally {
      if (degraded) await degraded.close();
      await new Promise<void>((resolve, reject) =>
        provider.close((error) => error ? reject(error) : resolve()),
      );
      await rm(degradedDir, { recursive: true, force: true });
    }
  }, 120_000);

  it("lands through D10 with exact raw-file provenance and stores metadata only", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Operations files",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Company operating references",
      dataSensitive: false,
    }, acmeOwner);
    const content = "Warehouse returns require an inspection before restocking.";
    const digest = createHash("sha256").update(content, "utf8").digest("hex");
    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "warehouse-returns.md",
      content,
      title: "Warehouse returns",
      description: "Returns procedure",
      purpose: "Guide warehouse support agents",
    }, acmeOwner);

    expect(file).toMatchObject({
      knowledgeBaseId: base.id,
      namespace: "acme",
      status: "ready",
      lifecycleState: "active",
      mediaType: "text/markdown",
      contentSha256: digest,
      uploadedBy: "owner:acme",
      factCount: 1,
    });
    const source = await kernel.sources.get(file.sourceId);
    expect(source?.kind).toBe("file-upload");
    expect(JSON.stringify(source?.config)).not.toContain(content);

    const durable = await kernel.db.query(
      `SELECT to_jsonb(f)::text AS row FROM company_files f WHERE id = $1`,
      [file.id],
    );
    expect(String(durable.rows[0]?.row)).not.toContain(content);
    const memories = await kernel.db.query(
      `SELECT provenance FROM memory_objects
        WHERE namespace = $1 AND status IN ('active','disputed') AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      [
        "acme",
        JSON.stringify([{
          sourceId: file.sourceId,
          documentKey: "warehouse-returns.md",
          contentHash: digest,
        }]),
      ],
    );
    expect(memories.rows).toHaveLength(1);

    expect(await kernel.listCompanyFiles({ knowledgeBaseId: base.id }, acmeAuditor)).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([expect.objectContaining({ id: file.id })]),
      }),
    );
    expect(await kernel.listCompanyFiles({
      query: "warehouse-returns.md",
      status: "ready",
      lifecycleState: "active",
    }, root)).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([expect.objectContaining({
          id: file.id,
          namespace: "acme",
          fileName: "warehouse-returns.md",
        })]),
      }),
    );
    expect(await kernel.getKnowledgeBase(base.id, acmeAuditor)).toMatchObject({
      status: "ready",
      fileCount: 1,
      factCount: 1,
    });
    const audit = await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE namespace = 'acme' AND purpose = 'company-file'
        ORDER BY ts DESC`,
    );
    expect(audit.rows).toEqual(
      expect.arrayContaining([expect.objectContaining({ result: "ok", detail: "upload_ready" })]),
    );
  });

  it("deleting an uploaded file retires every memory derived from that file", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Disposable file library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "File deletion lifecycle",
      dataSensitive: false,
    }, acmeOwner);
    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "temporary-process.md",
      content: "Temporary process facts must disappear when this file is deleted.",
      title: "Temporary process",
      description: "Deletion lifecycle proof",
      purpose: "Verify source-derived memory retirement",
    }, acmeOwner);
    const before = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status IN ('active','disputed') AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      ["acme", JSON.stringify([{ sourceId: file.sourceId }])],
    );
    expect(before.rows).toHaveLength(1);

    await kernel.archiveCompanyFile(file.id, acmeOwner);

    const after = await kernel.db.query(
      `SELECT id, status, t_valid_to FROM memory_objects
        WHERE namespace = $1 AND provenance @> $2::jsonb`,
      ["acme", JSON.stringify([{ sourceId: file.sourceId }])],
    );
    expect(after.rows).toHaveLength(1);
    expect(after.rows[0]).toMatchObject({ status: "archived" });
    expect(after.rows[0]!.t_valid_to).not.toBeNull();
    await expect(kernel.memRead({ id: String(before.rows[0]!.id) }, acmeOwner))
      .resolves.toMatchObject({ found: false });
  });

  it("reconciles transport retries before admission and binds keys to the full request", async () => {
    const replayAdmin = await issue(
      "acme",
      "admin:reliable-upload-replay",
      "admin",
      acmeOwner,
    );
    const base = await kernel.createKnowledgeBase({
      name: "Reliable upload replay",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Transport retry regression",
      dataSensitive: false,
    }, acmeOwner);
    const bytes = Buffer.from(
      "Reliable uploads retain one durable result across proxy retries.",
      "utf8",
    );
    const input = {
      knowledgeBaseId: base.id,
      fileName: "reliable-upload.md",
      contentBase64: bytes.toString("base64"),
      idempotencyKey: "file_transport_retry_001",
      title: "Reliable upload",
      description: "Retry behavior",
      purpose: "Verify file upload reliability",
    };

    await kernel.setPolicy("acme", "rateLimitPerMin: 1\nverifierEnabled: false\n");
    try {
      const first = await kernel.uploadCompanyFile(input, replayAdmin);
      const replay = await kernel.uploadCompanyFile(input, replayAdmin);
      expect(replay).toEqual(first);
      expect(replay.contentSha256).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
      expect((await kernel.db.query(
        "SELECT count(*) AS count FROM company_files WHERE knowledge_base_id = $1",
        [base.id],
      )).rows[0]).toMatchObject({ count: 1 });

      // The same bytes are not enough: request metadata is part of the stable
      // identity and cannot be changed behind an existing key.
      await expect(kernel.uploadCompanyFile({
        ...input,
        purpose: "A different request purpose",
      }, replayAdmin)).rejects.toThrow(/different upload request/i);

      await kernel.archiveKnowledgeBase(base.id, replayAdmin);
      await expect(kernel.uploadCompanyFile(input, replayAdmin)).resolves.toMatchObject({
        id: first.id,
        lifecycleState: "archived",
      });

      const replayAudit = await kernel.db.query(
        `SELECT result, detail FROM audit_log
          WHERE actor = $1 AND purpose = 'company-file'
            AND detail = 'upload_replayed_ready'
          ORDER BY seq DESC LIMIT 1`,
        [replayAdmin.actor],
      );
      expect(replayAudit.rows[0]).toMatchObject({
        result: "ok",
        detail: "upload_replayed_ready",
      });
    } finally {
      await kernel.setPolicy("acme", "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    }
  });

  it("serializes concurrent first deliveries of one key before rate admission", async () => {
    const concurrentAdmin = await issue(
      "acme",
      "admin:concurrent-upload-replay",
      "admin",
      acmeOwner,
    );
    const base = await kernel.createKnowledgeBase({
      name: "Concurrent upload replay",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Concurrent retry regression",
      dataSensitive: false,
    }, acmeOwner);
    const input = {
      knowledgeBaseId: base.id,
      fileName: "concurrent-retry.md",
      content: "Concurrent deliveries share one durable company-file result.",
      idempotencyKey: "file_concurrent_retry_001",
      description: "Concurrent retry",
      purpose: "Verify same-key serialization",
    };

    await kernel.setPolicy("acme", "rateLimitPerMin: 1\nverifierEnabled: false\n");
    try {
      const deliveries = await Promise.allSettled([
        kernel.uploadCompanyFile(input, concurrentAdmin),
        kernel.uploadCompanyFile(input, concurrentAdmin),
      ]);
      for (const delivery of deliveries) {
        if (delivery.status === "rejected") {
          expect(delivery.reason).not.toMatchObject({ name: "RateLimitError" });
          expect(delivery.reason).toMatchObject({
            name: "CompanyFileIdempotencyError",
            code: "company_file_upload_processing",
          });
        }
      }
      const fulfilled = deliveries.find((delivery) => delivery.status === "fulfilled");
      expect(fulfilled?.status).toBe("fulfilled");
      const stable = await kernel.uploadCompanyFile(input, concurrentAdmin);
      if (fulfilled?.status === "fulfilled") expect(stable).toEqual(fulfilled.value);
      expect((await kernel.db.query(
        "SELECT count(*) AS count FROM company_files WHERE knowledge_base_id = $1",
        [base.id],
      )).rows[0]).toMatchObject({ count: 1 });
      expect((await kernel.db.query(
        "SELECT count(*) AS count FROM company_file_upload_attempts WHERE knowledge_base_id = $1",
        [base.id],
      )).rows[0]).toMatchObject({ count: 1 });
      expect((await kernel.db.query(
        "SELECT request_count FROM durable_rate_limits WHERE bucket_key = $1",
        [`company-file-upload:${concurrentAdmin.keyId}`],
      )).rows[0]).toMatchObject({ request_count: 1 });
    } finally {
      await kernel.setPolicy("acme", "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    }
  });

  it("returns a stable recovery message when an attempt failed before file reservation", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Pre-reservation retry",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Pre-reservation retry regression",
      dataSensitive: false,
    }, acmeOwner);
    const content = "Duplicate reservation failures retain their attempt identity.";
    await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "original.md",
      content,
      description: "Original",
      purpose: "Create the active content row",
    }, acmeOwner);
    const retryInput = {
      knowledgeBaseId: base.id,
      fileName: "duplicate.md",
      content,
      idempotencyKey: "file_pre_reservation_001",
      description: "Duplicate",
      purpose: "Exercise pre-reservation recovery",
    };
    await expect(kernel.uploadCompanyFile(retryInput, acmeOwner))
      .rejects.toThrow(/already active/i);
    await expect(kernel.uploadCompanyFile(retryInput, acmeOwner))
      .rejects.toThrow("Previous upload request ended before file reservation");
  });

  it("expires a stale no-file attempt on its first replay", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Stale no-file retry",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Stale no-file regression",
      dataSensitive: false,
    }, acmeOwner);
    const input = {
      knowledgeBaseId: base.id,
      fileName: "stale-no-file.md",
      content: "A stale claimed request must become a stable failed attempt.",
      idempotencyKey: "file_stale_no_file_001",
      description: "Stale attempt",
      purpose: "Exercise expired pre-reservation recovery",
    };
    const contentSha256 = createHash("sha256").update(input.content, "utf8").digest("hex");
    const requestSha256 = createHash("sha256").update(JSON.stringify({
      version: 1,
      knowledgeBaseId: base.id,
      fileName: input.fileName,
      contentSha256,
      title: "stale no file",
      description: input.description,
      purpose: input.purpose,
    })).digest("hex");
    const claimed = await kernel.companyFiles.reserveAttempt({
      namespace: base.namespace,
      knowledgeBaseId: base.id,
      targetTeamId: null,
      idempotencyKey: `company_attempt_client_${input.idempotencyKey}`,
      requestSha256,
      requestedFileCount: 1,
      createdBy: acmeOwner.actor,
    });
    await kernel.db.query(
      `UPDATE company_file_upload_attempts
          SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
        WHERE id = $1`,
      [claimed.attempt.id],
    );

    await expect(kernel.uploadCompanyFile(input, acmeOwner))
      .rejects.toThrow("Previous upload request ended before file reservation");
    expect((await kernel.db.query(
      "SELECT status, failure_code FROM company_file_upload_attempts WHERE id = $1",
      [claimed.attempt.id],
    )).rows[0]).toMatchObject({ status: "failed", failure_code: "processing_timeout" });
  });

  it("browns sensitive files out to local-only verbatim ingestion", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Confidential policies",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Legal",
      description: "Policies that must remain inside HaloMem",
      dataSensitive: true,
    }, acmeOwner);
    const llm = kernel.llm as {
      complete(system: string, user: string): Promise<string>;
    };
    const embedder = kernel.embedder;
    const originalComplete = llm.complete.bind(llm);
    const originalEmbed = embedder.embed.bind(embedder);
    let llmCalls = 0;
    let externalEmbedCalls = 0;
    llm.complete = async (system, user) => {
      llmCalls += 1;
      return originalComplete(system, user);
    };
    embedder.embed = async (texts) => {
      externalEmbedCalls += 1;
      return originalEmbed(texts);
    };

    try {
      const file = await kernel.uploadCompanyFile({
        knowledgeBaseId: base.id,
        fileName: "incident-response.md",
        content: "Security incidents must be reported to the response lead within 15 minutes.",
        title: "Incident response",
        description: "Internal response policy",
        purpose: "Guide security incident handling",
      }, acmeOwner);

      expect(file).toMatchObject({
        knowledgeBaseId: base.id,
        status: "ready",
        failureCode: null,
        factCount: 1,
      });
      expect(llmCalls).toBe(0);
      expect(externalEmbedCalls).toBe(0);

      const memories = await kernel.db.query<{
        content: string;
        classification: { sensitivity?: string } | null;
      }>(
        `SELECT content, classification
           FROM memory_objects
          WHERE namespace = $1 AND status IN ('active','disputed') AND t_valid_to IS NULL
            AND provenance @> $2::jsonb`,
        [
          "acme",
          JSON.stringify([{
            sourceId: file.sourceId,
            documentKey: "incident-response.md",
          }]),
        ],
      );
      expect(memories.rows).toHaveLength(1);
      expect(memories.rows[0]?.content).toContain("reported to the response lead");
      expect(memories.rows[0]?.classification).toMatchObject({
        sensitivity: "confidential",
      });

      const audit = await kernel.db.query<{ result: string; detail: string | null }>(
        `SELECT result, detail FROM audit_log
          WHERE namespace = 'acme'
            AND detail LIKE 'classification_denied sensitivity=confidential%'
          ORDER BY ts DESC`,
      );
      expect(audit.rows).toEqual(expect.arrayContaining([
        expect.objectContaining({
          result: "denied",
          detail: expect.stringContaining("destination=llm-extraction"),
        }),
      ]));
    } finally {
      llm.complete = originalComplete;
      embedder.embed = originalEmbed;
    }
  });

  it("rejects caller authority and unsupported files before durable upload state", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Bounded inputs",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Security",
      description: "",
      dataSensitive: true,
    }, acmeOwner);
    const malicious = {
      knowledgeBaseId: base.id,
      fileName: "escape.pdf",
      content: "not really a PDF",
      description: "",
      purpose: "escape",
      namespace: "globex",
    };
    await expect(
      kernel.uploadCompanyFile(malicious as never, acmeOwner),
    ).rejects.toMatchObject({ name: "CompanyFileValidationError" });
    const rows = await kernel.db.query(
      "SELECT id FROM company_files WHERE knowledge_base_id = $1",
      [base.id],
    );
    expect(rows.rows).toHaveLength(0);
  });

  it("checks the company-document lease inside the write transaction", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Lease fence",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Risk",
      description: "",
      dataSensitive: false,
    }, acmeOwner);
    const llm = kernel.llm as {
      complete(system: string, user: string): Promise<string>;
    };
    const originalComplete = llm.complete.bind(llm);
    let signalStarted!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => { signalStarted = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    llm.complete = async (system, user) => {
      if (!system.includes("[HALOMEM-EXTRACT]")) return originalComplete(system, user);
      signalStarted();
      await gate;
      return JSON.stringify([{
        content: "This late fact must not land",
        speaker: "user",
        eventTime: null,
        entities: [],
        confidence: 0.99,
      }]);
    };

    const input = {
      knowledgeBaseId: base.id,
      fileName: "late.txt",
      content: "The processing lease expires while extraction is running.",
      idempotencyKey: "file_terminal_failure_replay_001",
      description: "",
      purpose: "Exercise the write fence",
    };
    let upload: Promise<Awaited<ReturnType<Kernel["uploadCompanyFile"]>>> | undefined;
    try {
      upload = kernel.uploadCompanyFile(input, acmeOwner);
      await started;
      await kernel.db.query(
        `UPDATE company_file_upload_attempts
            SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
          WHERE knowledge_base_id = $1 AND status = 'processing'`,
        [base.id],
      );
      await kernel.db.query(
        `UPDATE company_files
            SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
          WHERE knowledge_base_id = $1 AND status = 'processing'`,
        [base.id],
      );
      release();
      const failed = await upload;
      expect(failed).toMatchObject({
        status: "failed",
        failureCode: "processing_timeout",
        factCount: 0,
      });
      await expect(kernel.uploadCompanyFile(input, acmeOwner)).resolves.toEqual(failed);
      const landed = await kernel.db.query(
        `SELECT id FROM memory_objects
          WHERE namespace = 'acme' AND content LIKE '%late fact must not land%'
            AND t_valid_to IS NULL`,
      );
      expect(landed.rows).toHaveLength(0);
    } finally {
      release();
      if (upload) await upload.catch(() => undefined);
      llm.complete = originalComplete;
    }
  });

  // Uploads previously ignored tenant governance entirely (a hardcoded 10/min).
  // The tenant cap must now lower the upload limit exactly like it lowers the
  // syscall limit — it may only ever tighten, never loosen.
  it("lets a tenant cap lower the effective upload rate limit", async () => {
    await kernel.tenants.register(
      { id: "capco", name: "Capco", rateLimitPerMin: 2 },
      root,
    );
    await kernel.setPolicy("capco", "verifierEnabled: false\n");
    const capcoOwner = await issue("capco", "owner:capco", "owner", root);
    const base = await kernel.createKnowledgeBase({
      name: "Capped library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Tenant-capped uploads",
      dataSensitive: false,
    }, capcoOwner);

    const upload = (n: number) => kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: `capped-${n}.md`,
      content: `Capped upload number ${n} carries a distinct operational fact.`,
      title: `Capped ${n}`,
      description: "Rate cap probe",
      purpose: "Prove the tenant cap governs uploads",
    }, capcoOwner);

    // The tenant's 2/min cap wins over the 120/min default: two land, the
    // third is denied even though the default would have allowed it.
    await upload(1);
    await upload(2);
    await expect(upload(3)).rejects.toMatchObject({ name: "RateLimitError" });

    const denied = await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE namespace = 'capco' AND result = 'denied'
          AND detail = 'upload_rate_limit'`,
    );
    expect(denied.rows).toHaveLength(1);
  });
});

// One-page PDF whose text layer reads the warehouse-returns sentence.
const PDF_WITH_FACT = Buffer.from(
  "JVBERi0xLjQKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoKMiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2UvUGFyZW50IDIgMCBSL01lZGlhQm94WzAgMCA2MTIgNzkyXS9SZXNvdXJjZXM8PC9Gb250PDwvRjEgNCAwIFI+Pj4+L0NvbnRlbnRzIDUgMCBSPj4KZW5kb2JqCjQgMCBvYmoKPDwvVHlwZS9Gb250L1N1YnR5cGUvVHlwZTEvQmFzZUZvbnQvSGVsdmV0aWNhPj4KZW5kb2JqCjUgMCBvYmoKPDwvTGVuZ3RoIDg5Pj5zdHJlYW0KQlQgL0YxIDI0IFRmIDcyIDcyMCBUZCAoV2FyZWhvdXNlIHJldHVybnMgcmVxdWlyZSBhbiBpbnNwZWN0aW9uIGJlZm9yZSByZXN0b2NraW5nLikgVGogRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMDkgMDAwMDAgbiAKMDAwMDAwMDA1NCAwMDAwMCBuIAowMDAwMDAwMTA1IDAwMDAwIG4gCjAwMDAwMDAyMTcgMDAwMDAgbiAKMDAwMDAwMDI4MCAwMDAwMCBuIAp0cmFpbGVyCjw8L1NpemUgNi9Sb290IDEgMCBSPj4Kc3RhcnR4cmVmCjQxNgolJUVPRgo=",
  "base64",
);

// Minimal valid DOCX whose paragraph reads "Hello HaloMem Word".
const DOCX_WITH_FACT = Buffer.from(
  "UEsDBBQAAAAIABwPEl15bjPX6AAAAK0BAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH1QyU7DMBD9FWuuKHHggBCK0wPLETiUDxjZk8SqN3nc0v49Tlt6QIXjzFv1+tXeO7GjzDYGBbdtB4KCjsaGScHn+rV5AMEFg0EXAyk4EMNq6NeHRCyqNrCCuZT0KCXrmTxyGxOFiowxeyz1zJNMqDc4kbzrunupYygUSlMWDxj6Zxpx64p42df3qUcmxyCeTsQlSwGm5KzGUnG5C+ZXSnNOaKvyyOHZJr6pBJBXExbk74Cz7r0Ok60h8YG5vKGvLPkVs5Em6q2vyvZ/mys94zhaTRf94pZy1MRcF/euvSAebfjpL49zD99QSwMEFAAAAAgAHA8SXZv9N+qtAAAAKQEAAAsAAABfcmVscy8ucmVsc43POw7CMAwG4KtE3mlaBoRQ0y4IqSsqB7ASN61oHkrCo7cnAwNFDIy2f3+W6/ZpZnanECdnBVRFCYysdGqyWsClP232wGJCq3B2lgQsFKFt6jPNmPJKHCcfWTZsFDCm5A+cRzmSwVg4TzZPBhcMplwGzT3KK2ri27Lc8fBpwNpknRIQOlUB6xdP/9huGCZJRydvhmz6ceIrkWUMmpKAhwuKq3e7yCzwpuarF5sXUEsDBBQAAAAIABwPEl0r0veZowAAANsAAAARAAAAd29yZC9kb2N1bWVudC54bWxFjsEOwiAMhl+FcHdMD8YsY7uZXbxpPCPUbQm0BNC5txfmwcvX9G/6tW3/cZa9IcSZUPJ9VXMGqMnMOEp+u553J85iUmiUJQTJV4i879qlMaRfDjCxLMDYLJJPKflGiKgncCpW5AHz7EnBqZTbMIqFgvGBNMSY/c6KQ10fhVMz8qJ8kFlL9QWhIHUDWEtsyNcv4Ng9C1pR8sKw0W/87Yr/X90XUEsBAhQDFAAAAAgAHA8SXXluM9foAAAArQEAABMAAAAAAAAAAAAAAIABAAAAAFtDb250ZW50X1R5cGVzXS54bWxQSwECFAMUAAAACAAcDxJdm/036q0AAAApAQAACwAAAAAAAAAAAAAAgAEZAQAAX3JlbHMvLnJlbHNQSwECFAMUAAAACAAcDxJdK9L3maMAAADbAAAAEQAAAAAAAAAAAAAAgAHvAQAAd29yZC9kb2N1bWVudC54bWxQSwUGAAAAAAMAAwC5AAAAwQIAAAAA",
  "base64",
);

describe("kernel company-file byte-true transport and binary formats", () => {
  it("hashes the caller's original base64 bytes, not a re-encoded derivative", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Byte-true library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Byte fidelity probes",
      dataSensitive: false,
    }, acmeOwner);
    // Multibyte content: the legacy text path would decode then re-encode;
    // the hash must cover the exact submitted bytes either way.
    const bytes = Buffer.from("Café opening hours change on Mondays — check the rota.", "utf8");
    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "cafe-rota.md",
      contentBase64: bytes.toString("base64"),
      title: "Café rota",
      description: "Byte fidelity probe",
      purpose: "Prove original-byte provenance",
    }, acmeOwner);

    expect(file.contentSha256).toBe(createHash("sha256").update(bytes).digest("hex"));
    expect(file.status).toBe("ready");
  });

  it("rejects UTF-16 text instead of storing browser-transcoded mojibake", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Encoding probe library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Encoding probes",
      dataSensitive: false,
    }, acmeOwner);
    const utf16 = Buffer.from("Warehouse returns require an inspection.", "utf16le");

    await expect(kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "utf16-note.txt",
      contentBase64: utf16.toString("base64"),
      title: "UTF-16 note",
      description: "Encoding probe",
      purpose: "Prove fatal decoding reaches the server",
    }, acmeOwner)).rejects.toThrow(/valid UTF-8|control characters/i);
  });

  it("rejects re-uploaded identical content as duplicate_content", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Duplicate probe library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Duplicate probes",
      dataSensitive: false,
    }, acmeOwner);
    const upload = () => kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "returns-policy.md",
      contentBase64: Buffer.from("Returns need a manager sign-off within two days.", "utf8").toString("base64"),
      title: "Returns policy",
      description: "Duplicate probe",
      purpose: "Prove duplicate content is named honestly",
    }, acmeOwner);

    const first = await upload();
    expect(first.status).toBe("ready");
    // Same content under a different file name is still the same content.
    await expect(kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "renamed-copy.md",
      contentBase64: Buffer.from("Returns need a manager sign-off within two days.", "utf8").toString("base64"),
      title: "Renamed copy",
      description: "Duplicate probe",
      purpose: "Prove duplicate content is named honestly",
    }, acmeOwner)).rejects.toThrow(/already active/i);

    const attempt = await kernel.db.query(
      `SELECT failure_code FROM company_file_upload_attempts
        WHERE knowledge_base_id = $1 AND status = 'failed'
        ORDER BY created_at DESC LIMIT 1`,
      [base.id],
    );
    expect(attempt.rows[0]?.failure_code).toBe("duplicate_content");
  });

  it("requires exactly one of content and contentBase64", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "Field probe library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Field probes",
      dataSensitive: false,
    }, acmeOwner);
    const baseFields = {
      knowledgeBaseId: base.id,
      fileName: "probe.md",
      title: "Probe",
      description: "Field probe",
      purpose: "Prove the content contract",
    };
    await expect(kernel.uploadCompanyFile({
      ...baseFields,
      content: "text",
      contentBase64: Buffer.from("text").toString("base64"),
    }, acmeOwner)).rejects.toThrow(/exactly one of content or contentBase64/i);
    await expect(kernel.uploadCompanyFile({ ...baseFields }, acmeOwner))
      .rejects.toThrow(/exactly one of content or contentBase64/i);
    await expect(kernel.uploadCompanyFile({
      ...baseFields,
      contentBase64: "not valid base64!!!",
    }, acmeOwner)).rejects.toThrow(/valid base64/i);
  });

  it("ingests a PDF above the legacy 512 KiB metadata limit without detaching its bytes", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "PDF library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "PDF probes",
      dataSensitive: false,
    }, acmeOwner);
    const pdfBytes = Buffer.concat([
      PDF_WITH_FACT,
      Buffer.alloc(600 * 1_024 - PDF_WITH_FACT.byteLength, 0x20),
    ]);
    const byteLengthBeforeUpload = pdfBytes.byteLength;
    const input = {
      knowledgeBaseId: base.id,
      fileName: "warehouse-returns.pdf",
      contentBase64: pdfBytes.toString("base64"),
      idempotencyKey: "file_pdf_retry_001",
      title: "Warehouse returns PDF",
      description: "PDF probe",
      purpose: "Prove PDF text lands as governed memory",
    };
    const file = await kernel.uploadCompanyFile(input, acmeOwner);
    const replay = await kernel.uploadCompanyFile(input, acmeOwner);

    expect(file).toMatchObject({
      status: "ready",
      mediaType: "application/pdf",
      contentSha256: createHash("sha256").update(pdfBytes).digest("hex"),
    });
    expect(pdfBytes.byteLength).toBe(byteLengthBeforeUpload);
    expect(file.byteSize).toBe(600 * 1_024);
    expect(replay).toEqual(file);
    expect(file.factCount).toBeGreaterThanOrEqual(1);
    expect((await kernel.db.query(
      "SELECT count(*) AS count FROM company_files WHERE knowledge_base_id = $1",
      [base.id],
    )).rows[0]).toMatchObject({ count: 1 });
    const memories = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status IN ('active','disputed') AND t_valid_to IS NULL
          AND provenance @> $2::jsonb`,
      ["acme", JSON.stringify([{ sourceId: file.sourceId }])],
    );
    expect(memories.rows.length).toBeGreaterThanOrEqual(1);
  });

  it("replays a byte-true DOCX upload without creating another row", async () => {
    const base = await kernel.createKnowledgeBase({
      name: "DOCX replay library",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "DOCX replay probe",
      dataSensitive: false,
    }, acmeOwner);
    const input = {
      knowledgeBaseId: base.id,
      fileName: "word-runbook.docx",
      contentBase64: DOCX_WITH_FACT.toString("base64"),
      idempotencyKey: "file_docx_retry_001",
      title: "Word runbook",
      description: "DOCX retry probe",
      purpose: "Prove DOCX retry byte fidelity",
    };
    const file = await kernel.uploadCompanyFile(input, acmeOwner);
    const replay = await kernel.uploadCompanyFile(input, acmeOwner);
    expect(replay).toEqual(file);
    expect(file).toMatchObject({
      mediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      contentSha256: createHash("sha256").update(DOCX_WITH_FACT).digest("hex"),
    });
    expect((await kernel.db.query(
      "SELECT count(*) AS count FROM company_files WHERE knowledge_base_id = $1",
      [base.id],
    )).rows[0]).toMatchObject({ count: 1 });
  });
});
