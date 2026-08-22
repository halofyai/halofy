import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ulid } from "ulid";
import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MemoryIndex } from "../src/index/index.js";
import { MovementEngine } from "../src/movement/index.js";
import { AesGcmDraftCipher, ConsolidationService } from "../src/consolidation/index.js";
import type { AuditEvent, Identity } from "../src/types.js";

const DIM = 8;
const owner: Identity = { keyId: "session-owner", namespace: "acme/team", actor: "owner@acme.test", role: "owner" };

let db: Db;
let audit: AuditLog;

async function seedMemory(options: {
  id?: string;
  namespace?: string;
  accessCount?: number;
  sessions?: string[];
  status?: "active" | "archived";
} = {}): Promise<string> {
  const id = options.id ?? ulid();
  const now = new Date().toISOString();
  const provenance = (options.sessions ?? []).map((session) => ({
    source: "conversation",
    actor: "agent",
    session,
    ts: now,
  }));
  await db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
        provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
     VALUES ($1, $2, 'team', 'L2', 'inline', 'durable fact', 'fact', 0.9,
             NULL, $3, $3, NULL, NULL, $4, NULL, NULL, $5, 0, $6, NULL)`,
    [
      id,
      options.namespace ?? owner.namespace,
      now,
      JSON.stringify(provenance),
      options.accessCount ?? 0,
      options.status ?? "active",
    ],
  );
  return id;
}

beforeEach(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  audit = new AuditLog(db);
});

afterEach(async () => {
  await db.close();
});

describe("R5C movement engine", () => {
  it("promotes only configured threshold-qualified rows and is idempotent", async () => {
    const memoryId = await seedMemory({ accessCount: 3, sessions: ["s1", "s2"] });
    const engine = new MovementEngine(db, audit, {}, {
      promotePin: { enabled: true, minAccessCount: 3, minSessionCount: 2 },
    });

    const first = await engine.runManual(owner, {
      action: "promote_pin",
      targetRef: memoryId,
      idempotencyKey: "promote-1",
    });
    const retry = await engine.runManual(owner, {
      action: "promote_pin",
      targetRef: memoryId,
      idempotencyKey: "promote-1",
    });

    expect(first.status).toBe("complete");
    expect(first.result).toMatchObject({ promoted: true, existing: false });
    expect(retry).toEqual(first);
    expect(
      Number(
        (
          await db.query(
            `SELECT count(*) AS n FROM memory_pins
             WHERE target_ref = $1 AND source = 'movement' AND released_at IS NULL`,
            [memoryId],
          )
        ).rows[0].n,
      ),
    ).toBe(1);
    expect((await audit.list(owner.namespace)).filter((event) => event.op === "move")).toHaveLength(2);
  });

  it("persists threshold skips without creating a pin", async () => {
    const memoryId = await seedMemory({ accessCount: 1, sessions: ["s1"] });
    const engine = new MovementEngine(db, audit, {}, {
      promotePin: { enabled: true, minAccessCount: 2, minSessionCount: 2 },
    });
    const action = await engine.runManual(owner, {
      action: "promote_pin",
      targetRef: memoryId,
      idempotencyKey: "promote-skip",
    });
    expect(action.status).toBe("complete");
    expect(action.result).toEqual({ promoted: false, reason: "threshold_not_met" });
    expect(Number((await db.query(`SELECT count(*) AS n FROM memory_pins`)).rows[0].n)).toBe(0);
  });

  it("honors an active lease and reclaims an expired lease", async () => {
    const memoryId = await seedMemory({ accessCount: 5, sessions: ["a", "b"] });
    const engine = new MovementEngine(db, audit, {}, {
      leaseMs: 60_000,
      promotePin: { enabled: true, minAccessCount: 1, minSessionCount: 1 },
    });
    const now = new Date();
    await db.query(
      `INSERT INTO movement_actions
         (id, namespace, action, target_ref, idempotency_key, status, lease_until,
          result, error, created_at, updated_at)
       VALUES ($1, $2, 'promote_pin', $3, 'leased', 'running', $4, NULL, NULL, $5, $5)`,
      [ulid(), owner.namespace, memoryId, new Date(now.getTime() + 60_000).toISOString(), now.toISOString()],
    );
    const leased = await engine.runManual(owner, {
      action: "promote_pin",
      targetRef: memoryId,
      idempotencyKey: "leased",
    });
    expect(leased.status).toBe("running");
    expect(Number((await db.query(`SELECT count(*) AS n FROM memory_pins`)).rows[0].n)).toBe(0);

    await db.query(`UPDATE movement_actions SET lease_until = $1 WHERE idempotency_key = 'leased'`, [
      new Date(now.getTime() - 1_000).toISOString(),
    ]);
    const reclaimed = await engine.runManual(owner, {
      action: "promote_pin",
      targetRef: memoryId,
      idempotencyKey: "leased",
    });
    expect(reclaimed.status).toBe("complete");
    expect(reclaimed.result).toMatchObject({ promoted: true });
  });

  it("materializes a published version once with explicit immutable lineage", async () => {
    const conceptId = ulid();
    const versionId = ulid();
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO knowledge_concepts
         (id, namespace, slug, title, current_version_id, status, created_at, updated_at)
       VALUES ($1, $2, 'refunds', 'Refunds', NULL, 'active', $3, $3)`,
      [conceptId, owner.namespace, now],
    );
    await db.query(
      `INSERT INTO knowledge_versions
         (id, concept_id, path, version, supersedes_version_id, content_hash,
          proposal_id, state, published_at, created_at)
       VALUES ($1, $2, $3, 1, NULL, 'hash', NULL, 'published', $4, $4)`,
      [versionId, conceptId, `concepts/${conceptId}/1.okf.enc`, now],
    );
    await db.query(`UPDATE knowledge_concepts SET current_version_id = $1 WHERE id = $2`, [versionId, conceptId]);
    const load = vi.fn(async () => ({ content: "Official refund policy", embedding: null }));
    const engine = new MovementEngine(db, audit, { loadPublishedVersion: load });

    const action = await engine.runManual(owner, {
      action: "materialize_warm",
      targetRef: versionId,
      idempotencyKey: "materialize-1",
    });
    expect(action.status).toBe("complete");
    expect(action.result).toMatchObject({ materialized: true, versionId, existing: false });
    const rows = await db.query(
      `SELECT id, namespace, backend_ref, content, status FROM memory_objects WHERE backend_ref = $1`,
      [`knowledge-version:${versionId}`],
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      namespace: owner.namespace,
      backend_ref: `knowledge-version:${versionId}`,
      content: "Official refund policy",
      status: "active",
    });
  });

  it("creates only a pending review proposal for propose_cold", async () => {
    const targetRef = ulid();
    const secondEvidenceId = ulid();
    const runId = ulid();
    const proposalId = ulid();
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO consolidation_runs
         (id, namespace, window_start, window_end, status, metrics, created_at, updated_at)
       VALUES ($1, $2, $3, $3, 'running', '{}', $3, $3)`,
      [runId, owner.namespace, now],
    );
    const engine = new MovementEngine(db, audit, {
      prepareColdProposal: async () => ({
        commitPrepared: async (tx) => {
          await tx.query(
            `INSERT INTO knowledge_proposals
               (id, run_id, namespace, draft_ciphertext, draft_iv, draft_tag, draft_kek_id,
                content_hash, confidence, evidence_ids, source_session_count, status,
                row_version, created_at, updated_at)
             VALUES ($1, $2, $3, 'cipher', 'iv', 'tag', 'kek', 'hash', 0.9, '[]', 2,
                     'pending_review', 1, $4, $4)`,
            [proposalId, runId, owner.namespace, now],
          );
          return { proposalId };
        },
      }),
    });
    const action = await engine.runManual(owner, {
      action: "propose_cold",
      targetRef,
      evidenceIds: [targetRef, secondEvidenceId],
      idempotencyKey: "propose-1",
    });
    expect(action.status).toBe("complete");
    expect(action.result).toMatchObject({ proposed: true, proposalId });
    expect((await db.query(`SELECT status FROM knowledge_proposals WHERE id = $1`, [proposalId])).rows[0].status).toBe(
      "pending_review",
    );
    expect(Number((await db.query(`SELECT count(*) AS n FROM knowledge_versions`)).rows[0].n)).toBe(0);
  });

  it("uses the real consolidation prepare/commit boundary for propose_cold", async () => {
    const first = await seedMemory({ sessions: ["session-1"] });
    const second = await seedMemory({ sessions: ["session-2"] });
    const consolidation = new ConsolidationService({
      db,
      audit,
      engine: {
        async createDrafts(evidence) {
          return [{
            evidenceIds: evidence.map((item) => item.id),
            slug: "movement-draft",
            title: "Movement draft",
            body: "Governed proposal body",
            confidence: 0.9,
          }];
        },
        async verifyDraft() { return true; },
      },
      cipher: new AesGcmDraftCipher(Buffer.alloc(32, 9), "movement-test-key"),
      publisher: { async publish() {} },
    });
    const engine = new MovementEngine(db, audit, {
      prepareColdProposal: async (_targetRef, evidenceIds, caller) => {
        const prepared = await consolidation.prepare(caller, {
          namespace: caller.namespace,
          evidenceIds: [...evidenceIds],
          windowStart: new Date(0).toISOString(),
          windowEnd: new Date().toISOString(),
        });
        return {
          commitPrepared: async (tx) => {
            await prepared.commitPrepared(tx);
            return { proposalId: prepared.proposalIds[0]! };
          },
        };
      },
    });

    const action = await engine.runManual(owner, {
      action: "propose_cold",
      targetRef: first,
      evidenceIds: [first, second],
      idempotencyKey: "real-consolidation-boundary",
    });

    expect(action).toMatchObject({ status: "complete", result: { proposed: true, evidenceRef: first } });
    expect((await db.query(`SELECT status, evidence_ids FROM knowledge_proposals`)).rows[0]).toMatchObject({
      status: "pending_review",
    });
    expect(Number((await db.query(`SELECT count(*) AS n FROM knowledge_versions`)).rows[0].n)).toBe(0);
  });

  it("isolates idempotency keys by tenant and audits same-tenant conflicts", async () => {
    const acmeMemory = await seedMemory({ namespace: "acme/team" });
    const globexMemory = await seedMemory({ namespace: "globex/team" });
    const acmeOther = await seedMemory({ namespace: "acme/team" });
    const globexOwner: Identity = {
      keyId: "globex-owner",
      namespace: "globex/team",
      actor: "owner@globex.test",
      role: "owner",
    };
    const engine = new MovementEngine(db, audit);

    await engine.runManual(owner, { action: "archive_warm", targetRef: acmeMemory, idempotencyKey: "shared-key" });
    await engine.runManual(globexOwner, {
      action: "archive_warm",
      targetRef: globexMemory,
      idempotencyKey: "shared-key",
    });
    expect(Number((await db.query(
      `SELECT count(*) AS n FROM movement_actions WHERE idempotency_key = 'shared-key'`,
    )).rows[0].n)).toBe(2);
    expect((await engine.get(owner, "shared-key"))?.namespace).toBe("acme/team");
    expect((await engine.get(globexOwner, "shared-key"))?.namespace).toBe("globex/team");

    await expect(engine.runManual(owner, {
      action: "archive_warm",
      targetRef: acmeOther,
      idempotencyKey: "shared-key",
    })).rejects.toThrow(/already bound/);
    expect((await db.query(
      `SELECT result, detail FROM audit_log WHERE namespace = 'acme/team' AND op = 'move' ORDER BY seq DESC LIMIT 1`,
    )).rows[0]).toMatchObject({ result: "error", detail: "idempotency_conflict" });
  });

  it("audits invalid propose evidence and role denial without creating actions", async () => {
    const targetRef = ulid();
    await expect(new MovementEngine(db, audit).runManual(owner, {
      action: "propose_cold",
      targetRef,
      evidenceIds: [targetRef],
      idempotencyKey: "invalid-evidence",
    })).rejects.toThrow(/at least two/);
    await expect(new MovementEngine(db, audit).runManual({ ...owner, role: "member" }, {
      action: "archive_warm",
      targetRef,
      idempotencyKey: "denied-role",
    })).rejects.toThrow(/owner or admin/);

    expect((await db.query(`SELECT result, detail FROM audit_log ORDER BY seq`)).rows).toEqual([
      expect.objectContaining({ result: "error", detail: "invalid_input" }),
      expect.objectContaining({ result: "denied", detail: "role_denied" }),
    ]);
    expect(Number((await db.query(`SELECT count(*) AS n FROM movement_actions`)).rows[0].n)).toBe(0);
  });

  it("archives instead of deleting and disappears from normal reads", async () => {
    const memoryId = await seedMemory();
    const engine = new MovementEngine(db, audit);
    const action = await engine.runManual(owner, {
      action: "archive_warm",
      targetRef: memoryId,
      idempotencyKey: "archive-1",
    });
    expect(action.result).toMatchObject({ archived: true, existing: false });
    expect((await db.query(`SELECT status FROM memory_objects WHERE id = $1`, [memoryId])).rows[0].status).toBe(
      "archived",
    );
    expect(await new MemoryIndex(db).getById(memoryId, owner.namespace)).toEqual({ obj: null, denied: false });
  });

  it("persists dependency brownout and leaves current memory untouched", async () => {
    const memoryId = await seedMemory();
    const secondEvidenceId = await seedMemory();
    const engine = new MovementEngine(db, audit, {
      prepareColdProposal: async () => {
        throw new Error("provider leaked secret should not persist");
      },
    });
    const action = await engine.runManual(owner, {
      action: "propose_cold",
      targetRef: memoryId,
      evidenceIds: [memoryId, secondEvidenceId],
      idempotencyKey: "brownout-1",
    });
    expect(action.status).toBe("degraded");
    expect(action.error).toBe("dependency_failed");
    expect(JSON.stringify(action)).not.toContain("provider leaked secret");
    expect((await db.query(`SELECT status FROM memory_objects WHERE id = $1`, [memoryId])).rows[0].status).toBe(
      "active",
    );
    expect((await audit.list(owner.namespace))[0]).toMatchObject({
      op: "move",
      result: "error",
      purpose: "movement:propose_cold",
    });
  });

  it("rolls back placement when the success audit cannot commit", async () => {
    class FailingAudit extends AuditLog {
      override async appendTo(_tx: Db, _event: AuditEvent): Promise<void> {
        throw new Error("audit unavailable");
      }
    }
    const memoryId = await seedMemory({ accessCount: 4, sessions: ["s1", "s2"] });
    const engine = new MovementEngine(db, new FailingAudit(db), {}, {
      promotePin: { enabled: true, minAccessCount: 1, minSessionCount: 1 },
    });
    await expect(
      engine.runManual(owner, {
        action: "promote_pin",
        targetRef: memoryId,
        idempotencyKey: "audit-rollback",
      }),
    ).rejects.toThrow("audit unavailable");
    expect(Number((await db.query(`SELECT count(*) AS n FROM memory_pins`)).rows[0].n)).toBe(0);
    expect((await engine.get(owner, "audit-rollback"))?.status).toBe("running");
  });
});
