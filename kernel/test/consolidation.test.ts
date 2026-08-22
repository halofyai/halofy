import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { MemoryIndex } from "../src/index/index.js";
import { AuditLog } from "../src/audit/index.js";
import {
  AesGcmDraftCipher,
  ConsolidationService,
  ProposalConflictError,
  type ConsolidationEngine,
  type PrivateKnowledgePublisher,
} from "../src/consolidation/index.js";
import type { Identity, MemoryObject } from "../src/types.js";

const DIM = 8;
const now = "2026-07-10T10:00:00.000Z";

function identity(overrides: Partial<Identity> = {}): Identity {
  return {
    keyId: "key-admin",
    namespace: "acme/support",
    actor: "steward@acme.test",
    role: "admin",
    ...overrides,
  };
}

function memory(id: string, namespace = "acme/support", session = "session-1"): MemoryObject {
  return {
    id,
    namespace,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: `Evidence ${id}: refund escalation requires finance review`,
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "conversation", actor: "agent", session, ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
}

class FakeEngine implements ConsolidationEngine {
  constructor(private readonly conceptId?: string) {}

  async createDrafts(evidence: readonly { id: string; content: string }[]) {
    return [{
      evidenceIds: evidence.map((item) => item.id),
      slug: "refund-escalation",
      title: "Refund escalation",
      body: "SECRET-DRAFT: refunds above 100 require finance approval",
      confidence: 0.94,
      ...(this.conceptId === undefined ? {} : { conceptId: this.conceptId }),
    }];
  }

  async verifyDraft(): Promise<boolean> {
    return true;
  }
}

class RecordingPublisher implements PrivateKnowledgePublisher {
  readonly writes: { path: string; body: string }[] = [];
  failAfterWriteOnce = false;

  async publish(input: { path: string; body: string }): Promise<void> {
    if (!this.writes.some((write) => write.path === input.path)) {
      this.writes.push({ path: input.path, body: input.body });
    }
    if (this.failAfterWriteOnce) {
      this.failAfterWriteOnce = false;
      throw new Error("simulated crash after durable private write");
    }
  }
}

describe("ConsolidationService", () => {
  let db: Db;
  let publisher: RecordingPublisher;
  let service: ConsolidationService;

  beforeEach(async () => {
    db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    await migrate(db, DIM);
    const index = new MemoryIndex(db);
    await index.insert(memory("mem-1", "acme/support", "session-1"), new Array(DIM).fill(0.1));
    await index.insert(memory("mem-2", "acme/support", "session-2"), new Array(DIM).fill(0.2));
    await index.insert(memory("mem-sibling", "acme/sales"), new Array(DIM).fill(0.3));
    publisher = new RecordingPublisher();
    service = new ConsolidationService({
      db,
      audit: new AuditLog(db),
      engine: new FakeEngine(),
      cipher: new AesGcmDraftCipher(Buffer.alloc(32, 7), "test-draft-key"),
      publisher,
      now: () => new Date(now),
    });
  });

  afterEach(async () => {
    await db.close();
  });

  it("creates only encrypted pending proposals from active exact-scope evidence", async () => {
    const result = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });

    expect(result.status).toBe("complete");
    expect(result.proposals).toHaveLength(1);
    expect(result.proposals[0]).toMatchObject({
      namespace: "acme/support",
      status: "pending_review",
      evidenceIds: ["mem-1", "mem-2"],
      sourceSessionCount: 2,
      draft: { body: expect.stringContaining("SECRET-DRAFT") },
    });

    const stored = await db.query(
      `SELECT draft_ciphertext, draft_iv, draft_tag, draft_kek_id FROM knowledge_proposals`,
    );
    expect(JSON.stringify(stored.rows)).not.toContain("SECRET-DRAFT");
    expect(stored.rows[0].draft_kek_id).toBe("test-draft-key");

    const audit = await db.query(`SELECT detail FROM audit_log ORDER BY seq`);
    expect(JSON.stringify(audit.rows)).not.toContain("SECRET-DRAFT");
  });

  it("prepares without writes and commits the same pending review proposal transactionally", async () => {
    const prepared = await service.prepare(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });

    expect(Number((await db.query(`SELECT count(*) AS n FROM consolidation_runs`)).rows[0].n)).toBe(0);
    expect(Number((await db.query(`SELECT count(*) AS n FROM knowledge_proposals`)).rows[0].n)).toBe(0);
    expect(Number((await db.query(`SELECT count(*) AS n FROM audit_log`)).rows[0].n)).toBe(0);

    await db.transaction((tx) => prepared.commitPrepared(tx));
    expect((await db.query(`SELECT status FROM knowledge_proposals WHERE id = $1`, [prepared.proposalIds[0]])).rows[0])
      .toMatchObject({ status: "pending_review" });
  });

  it("rejects sibling evidence without creating a run or leaking whether it exists", async () => {
    await expect(service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-sibling"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    })).rejects.toThrow(/evidence selection/i);

    expect(Number((await db.query(`SELECT count(*) AS n FROM consolidation_runs`)).rows[0].n)).toBe(0);
    expect((await db.query(`SELECT result, detail FROM audit_log ORDER BY seq DESC LIMIT 1`)).rows[0]).toMatchObject({
      result: "miss",
      detail: "evidence unavailable",
    });
  });

  it("audits role denial and verification dependency errors without sensitive bodies", async () => {
    await expect(service.runManual(identity({ role: "auditor" }), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    })).rejects.toBeInstanceOf(Error);

    const failingService = new ConsolidationService({
      db,
      audit: new AuditLog(db),
      engine: {
        createDrafts: (evidence) => new FakeEngine().createDrafts(evidence),
        async verifyDraft() {
          throw new Error("provider-secret-verification-payload");
        },
      },
      cipher: new AesGcmDraftCipher(Buffer.alloc(32, 7), "test-draft-key"),
      publisher,
      now: () => new Date(now),
    });
    await expect(failingService.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    })).rejects.toThrow("provider-secret-verification-payload");

    const rows = await db.query(`SELECT result, detail FROM audit_log ORDER BY seq`);
    expect(rows.rows).toEqual([
      expect.objectContaining({ result: "denied", detail: "manual denied" }),
      expect.objectContaining({ result: "error", detail: "prepare failed" }),
    ]);
    expect(JSON.stringify(rows.rows)).not.toContain("provider-secret");
    expect(JSON.stringify(rows.rows)).not.toContain("SECRET-DRAFT");
  });

  it("scopes list and get while rejecting stale or duplicate decisions", async () => {
    const run = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    const proposal = run.proposals[0];

    expect(await service.list(identity())).toHaveLength(1);
    expect(await service.list(identity({ namespace: "acme", role: "auditor" }))).toHaveLength(1);
    expect(await service.get(identity({ namespace: "acme", role: "auditor" }), proposal.id)).not.toBeNull();
    expect(await service.get(identity({ namespace: "acme/sales", role: "member" }), proposal.id)).toBeNull();

    await expect(service.reject(identity({ namespace: "acme/sales", role: "admin" }), proposal.id, {
      expectedRowVersion: proposal.rowVersion,
      reason: "sibling must not decide",
    })).rejects.toBeInstanceOf(Error);
    expect((await db.query(
      `SELECT namespace, result, detail FROM audit_log WHERE op = 'reject' ORDER BY seq DESC LIMIT 1`,
    )).rows[0]).toMatchObject({
      namespace: "acme/support",
      result: "denied",
      detail: `proposal=${proposal.id} denied`,
    });

    await service.reject(identity(), proposal.id, { expectedRowVersion: proposal.rowVersion, reason: "not policy" });
    await expect(service.reject(identity(), proposal.id, {
      expectedRowVersion: proposal.rowVersion,
      reason: "second decision",
    })).rejects.toBeInstanceOf(ProposalConflictError);

    expect((await db.query(
      `SELECT result, detail FROM audit_log WHERE op = 'reject' ORDER BY seq DESC LIMIT 1`,
    )).rows[0]).toMatchObject({ result: "error", detail: `proposal=${proposal.id} conflict` });

    expect(publisher.writes).toHaveLength(0);
    const stored = await service.get(identity(), proposal.id);
    expect(stored?.status).toBe("rejected");
    expect((await db.query(`SELECT action FROM proposal_decisions`)).rows).toEqual([
      expect.objectContaining({ action: "reject" }),
    ]);
  });

  it("resumes an interrupted approval at one immutable version path", async () => {
    const run = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    const proposal = run.proposals[0];
    publisher.failAfterWriteOnce = true;

    await expect(service.approve(identity(), proposal.id, {
      expectedRowVersion: proposal.rowVersion,
    })).rejects.toThrow(/simulated crash/);
    const interrupted = await service.get(identity(), proposal.id);
    expect(interrupted?.status).toBe("publishing");

    const published = await service.approve(identity(), proposal.id, {
      expectedRowVersion: interrupted!.rowVersion,
    });
    expect(published.status).toBe("published");
    expect(publisher.writes).toHaveLength(1);
    expect(publisher.writes[0].path).toMatch(/\/v1-[0-9A-HJKMNP-TV-Z]{26}\.okf\.enc$/);

    const versions = await db.query(
      `SELECT id, path, state, proposal_id FROM knowledge_versions WHERE proposal_id = $1`,
      [proposal.id],
    );
    expect(versions.rows).toHaveLength(1);
    expect(versions.rows[0]).toMatchObject({ state: "published", proposal_id: proposal.id });
    expect(Number((await db.query(`SELECT count(*) AS n FROM proposal_decisions`)).rows[0].n)).toBe(1);

    const metrics = await service.metrics(identity(), "acme/support");
    expect(metrics).toEqual({ approvals: 1, mergeWithoutEdit: 1, mergeWithoutEditRatio: 1 });
    await expect(service.approve(identity(), proposal.id, {
      expectedRowVersion: interrupted!.rowVersion,
    })).rejects.toBeInstanceOf(ProposalConflictError);
  });

  it("edits the encrypted pending draft, then publishes and measures it as edited", async () => {
    const run = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    const proposal = run.proposals[0];
    const editedBody = "SECRET-EDIT: finance and support lead approval required";

    const edited = await service.edit(identity(), proposal.id, {
      expectedRowVersion: proposal.rowVersion,
      draft: {
        slug: "refund-escalation",
        title: "Refund escalation policy",
        body: editedBody,
      },
    });
    expect(edited).toMatchObject({ status: "pending_review", rowVersion: proposal.rowVersion + 1 });
    expect(edited.draft.body).toBe(editedBody);

    await service.approve(identity(), proposal.id, {
      expectedRowVersion: edited.rowVersion,
    });

    expect(publisher.writes[0].body).toBe(editedBody);
    expect(JSON.stringify((await db.query(`SELECT * FROM knowledge_proposals`)).rows)).not.toContain(editedBody);
    expect((await db.query(`SELECT edited, action FROM proposal_decisions`)).rows[0]).toMatchObject({
      edited: true,
      action: "edit_approve",
    });
    expect(await service.decisions(identity(), proposal.id)).toEqual([
      expect.objectContaining({ proposalId: proposal.id, action: "edit_approve", edited: true }),
    ]);
    expect(await service.decisions(identity({ namespace: "acme/sales", role: "member" }), proposal.id)).toEqual([]);
    expect(await service.metrics(identity(), "acme/support")).toEqual({
      approvals: 1,
      mergeWithoutEdit: 0,
      mergeWithoutEditRatio: 0,
    });
  });

  it("allows only one concurrent decision for the expected row version", async () => {
    const run = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    const proposal = run.proposals[0];

    const decisions = await Promise.allSettled([
      service.reject(identity(), proposal.id, {
        expectedRowVersion: proposal.rowVersion,
        reason: "first reviewer",
      }),
      service.reject(identity(), proposal.id, {
        expectedRowVersion: proposal.rowVersion,
        reason: "second reviewer",
      }),
    ]);

    expect(decisions.filter((decision) => decision.status === "fulfilled")).toHaveLength(1);
    expect(decisions.filter((decision) => decision.status === "rejected")).toHaveLength(1);
    expect(Number((await db.query(`SELECT count(*) AS n FROM proposal_decisions`)).rows[0].n)).toBe(1);
  });

  it("rolls back a decision when its success audit cannot commit", async () => {
    const run = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    const proposal = run.proposals[0];
    const failAuditService = new ConsolidationService({
      db,
      audit: {
        async appendTo(_db, event) {
          if (event.op === "reject") throw new Error("audit unavailable");
        },
      },
      engine: new FakeEngine(),
      cipher: new AesGcmDraftCipher(Buffer.alloc(32, 7), "test-draft-key"),
      publisher,
      now: () => new Date(now),
    });

    const failed = await failAuditService.reject(identity(), proposal.id, {
      expectedRowVersion: proposal.rowVersion,
      reason: "must roll back",
    }).then(() => null, (error: unknown) => error);
    expect(failed).toBeInstanceOf(AggregateError);
    expect((failed as AggregateError).errors.map((error) => String(error))).toEqual([
      expect.stringContaining("audit unavailable"),
      expect.stringContaining("audit unavailable"),
    ]);

    expect((await service.get(identity(), proposal.id))?.status).toBe("pending_review");
    expect(Number((await db.query(`SELECT count(*) AS n FROM proposal_decisions`)).rows[0].n)).toBe(0);
  });

  it("revises knowledge by adding an immutable superseding version", async () => {
    const firstRun = await service.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    await service.approve(identity(), firstRun.proposals[0].id, {
      expectedRowVersion: firstRun.proposals[0].rowVersion,
    });
    const conceptId = String((await db.query(`SELECT id FROM knowledge_concepts`)).rows[0].id);
    const revisionService = new ConsolidationService({
      db,
      audit: new AuditLog(db),
      engine: new FakeEngine(conceptId),
      cipher: new AesGcmDraftCipher(Buffer.alloc(32, 7), "test-draft-key"),
      publisher,
      now: () => new Date(now),
    });
    const secondRun = await revisionService.runManual(identity(), {
      namespace: "acme/support",
      evidenceIds: ["mem-1", "mem-2"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: now,
    });
    await revisionService.approve(identity(), secondRun.proposals[0].id, {
      expectedRowVersion: secondRun.proposals[0].rowVersion,
    });

    const versions = await db.query(
      `SELECT id, version, supersedes_version_id, state, path
         FROM knowledge_versions WHERE concept_id = $1 ORDER BY version`,
      [conceptId],
    );
    expect(versions.rows).toHaveLength(2);
    expect(versions.rows[0]).toMatchObject({ version: 1, supersedes_version_id: null, state: "archived" });
    expect(versions.rows[1]).toMatchObject({
      version: 2,
      supersedes_version_id: versions.rows[0].id,
      state: "published",
    });
    expect(versions.rows[1].path).not.toBe(versions.rows[0].path);
  });
});
