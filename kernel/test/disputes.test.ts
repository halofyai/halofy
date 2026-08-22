/**
 * Trust-ranked supersedence quarantine + DisputeService review queue.
 *
 * Full-kernel e2e: a conversational claim that contradicts a higher-trust
 * document fact must land status:'disputed' (invisible to every read path,
 * incumbent untouched) with an open fact_disputes row, and resolve only
 * through the governed review actions (uphold-new | keep-old | edit) under
 * subtree owner/admin authorization with optimistic locking.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import { MemoryIndex } from "../src/index/index.js";
import type { Identity, MemoryObject, WriteResult } from "../src/types.js";

let kernel: Kernel;
let root: Identity;
let supportAdmin: Identity;
let salesAdmin: Identity;
let orgAuditor: Identity;
let supportAgent: Identity;

const SUPPORT = "org/support";

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

/** A currently-valid rank-40 document fact with a real (kernel) embedding. */
async function seedDocumentFact(namespace: string, content: string): Promise<string> {
  const [embedding] = await kernel.embedder.embed([content]);
  const now = new Date().toISOString();
  const obj: MemoryObject = {
    id: ulid(),
    namespace,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content,
    type: "fact",
    confidence: 1,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "document", actor: "connector:fs", sourceId: "fs:handbook", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  await new MemoryIndex(kernel.db).insert(obj, embedding ?? null);
  return obj.id;
}

/**
 * Create a legacy quarantine record explicitly. Luna v1 no longer creates
 * these on write, but the historical review service must remain operable while
 * migration 89 revalidates old rows.
 */
async function claim(content: string, identity: Identity = supportAgent): Promise<WriteResult> {
  const duplicate = await kernel.db.query(
    `SELECT d.id FROM fact_disputes d JOIN memory_objects m ON m.id=d.memory_id
      WHERE d.namespace=$1 AND d.status='open' AND m.content=$2 LIMIT 1`,
    [identity.namespace, content],
  );
  if (duplicate.rows[0]) {
    return { stored: [], superseded: [], deduplicated: 1, rejected: [] };
  }
  const result = sync(await kernel.memWrite(
    { scope: "team", content, hints: { verbatim: true } }, identity, "agent-7",
  ));
  const memoryId = result.stored[0]!.id;
  const incumbent = await kernel.db.query(
    `SELECT id FROM memory_objects
      WHERE namespace=$1 AND id<>$2 AND status='active' AND t_valid_to IS NULL
        AND provenance->0->>'source' = 'document'
      ORDER BY assertion_time DESC,id DESC LIMIT 1`,
    [identity.namespace, memoryId],
  );
  const incumbentId = String(incumbent.rows[0]!.id);
  const category = /refund|exchange|gift|bonus/i.test(content)
    ? "policies-legal"
    : /shipping|carrier|order/i.test(content) ? "order-management" : "other";
  const now = new Date().toISOString();
  await kernel.db.transaction(async (tx) => {
    await tx.query(`UPDATE memory_objects SET status='disputed' WHERE id=$1`, [memoryId]);
    await tx.query(`DELETE FROM conflict_detection_queue WHERE memory_id=$1`, [memoryId]);
    await tx.query(
      `INSERT INTO fact_disputes
         (id,namespace,memory_id,disputed_against,category,reason,status,row_version,created_at,updated_at)
       VALUES ($1,$2,$3,$4,$5,'document(40) outranks conversation(10)','open',1,$6,$6)`,
      [ulid(), identity.namespace, memoryId, incumbentId, category, now],
    );
    await kernel.audit.appendTo(tx, {
      ts: now, actor: identity.actor, agentId: "agent-7", op: "dispute",
      memoryId, namespace: identity.namespace, purpose: "legacy-dispute-fixture",
      result: "ok", detail: `against=${incumbentId}`,
    });
  });
  return {
    stored: [], superseded: [], deduplicated: 0, rejected: [],
    disputed: [{ id: memoryId, against: incumbentId, category }],
  };
}

async function disputeRow(disputedAgainst: string): Promise<Record<string, unknown> | undefined> {
  const res = await kernel.db.query(
    `SELECT * FROM fact_disputes WHERE disputed_against = $1 ORDER BY created_at DESC, id DESC`,
    [disputedAgainst],
  );
  return res.rows[0] as Record<string, unknown> | undefined;
}

async function memoryStatus(id: string): Promise<{ status: string; tValidTo: unknown; supersedes: unknown }> {
  const res = await kernel.db.query(
    `SELECT status, t_valid_to, supersedes FROM memory_objects WHERE id = $1`,
    [id],
  );
  const row = res.rows[0] as Record<string, unknown>;
  return { status: String(row.status), tValidTo: row.t_valid_to, supersedes: row.supersedes };
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;
  supportAdmin = await issue(SUPPORT, "admin:support", "admin");
  salesAdmin = await issue("org/sales", "admin:sales", "admin");
  orgAuditor = await issue("org", "auditor:org", "auditor");
  supportAgent = await issue(SUPPORT, "agent:support", "agent");
});

afterAll(async () => {
  await kernel.close();
});

describe("historical quarantine review", () => {
  let incumbentId: string;
  let disputedId: string;

  it("quarantines a conversational claim against a document fact", async () => {
    incumbentId = await seedDocumentFact(
      SUPPORT,
      "The refund window is 30 days for all Acme orders.",
    );
    const result = await claim("The refund window is 14 days for Acme orders.");
    expect(result.superseded).toEqual([]);
    expect(result.stored).toEqual([]);
    expect(result.disputed).toHaveLength(1);
    expect(result.disputed![0]!.against).toBe(incumbentId);
    expect(result.disputed![0]!.category).toBe("policies-legal");
    disputedId = result.disputed![0]!.id;

    const incumbent = await memoryStatus(incumbentId);
    expect(incumbent.status).toBe("active");
    expect(incumbent.tValidTo).toBeNull();
    const disputed = await memoryStatus(disputedId);
    expect(disputed.status).toBe("disputed");
    expect(disputed.supersedes).toBeNull();

    const dispute = await disputeRow(incumbentId);
    expect(dispute?.status).toBe("open");
    expect(String(dispute?.reason)).toBe("document(40) outranks conversation(10)");
  });

  it("keeps the disputed claim invisible to search", async () => {
    const refs = await kernel.memSearch({ query: "refund window Acme" }, supportAgent);
    expect(refs.some((r) => r.content.includes("30 days"))).toBe(true);
    expect(refs.some((r) => r.content.includes("14 days"))).toBe(false);
  });

  it("audits the quarantine as op:'dispute' (D4)", async () => {
    const rows = await kernel.audit.search({ op: "dispute" }, [SUPPORT]);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[0]!.memoryId).toBe(disputedId);
    expect(rows[0]!.result).toBe("ok");
    expect(String(rows[0]!.detail)).toContain(`against=${incumbentId}`);
  });

  it("suppresses a duplicate of an already-open dispute as a dedupe", async () => {
    const repeat = await claim("The refund window is 14 days for Acme orders.");
    expect(repeat.disputed ?? []).toHaveLength(0);
    expect(repeat.deduplicated).toBe(1);
    const open = await kernel.db.query(
      `SELECT count(*) AS n FROM fact_disputes WHERE disputed_against = $1 AND status = 'open'`,
      [incumbentId],
    );
    expect(Number((open.rows[0] as { n: unknown }).n)).toBe(1);
  });

  it("lists the dispute for subtree reviewers but never a sibling admin", async () => {
    const dispute = (await disputeRow(incumbentId))!;
    const forSupport = await kernel.listDisputes(supportAdmin);
    expect(forSupport.some((d) => d.id === String(dispute.id))).toBe(true);
    const view = forSupport.find((d) => d.incumbent.id === incumbentId)!;
    expect(view.team).toBe(SUPPORT);
    expect(view.category).toBe("policies-legal");
    expect(view.incumbentCurrent).toBe(true);
    expect(view.disputed.content).toContain("14 days");
    expect(view.incumbent.content).toContain("30 days");
    expect(view.incumbent.source).toBe("document");
    expect(view.disputed.source).toBe("conversation");

    const forSales = await kernel.listDisputes(salesAdmin);
    expect(forSales.some((d) => d.incumbent.id === incumbentId)).toBe(false);

    const forAuditor = await kernel.listDisputes(orgAuditor);
    expect(forAuditor.some((d) => d.incumbent.id === incumbentId)).toBe(true);

    const forRoot = await kernel.listDisputes(root);
    expect(forRoot.some((d) => d.incumbent.id === incumbentId)).toBe(true);
  });

  it("denies resolution to a sibling admin and to an auditor", async () => {
    const dispute = (await disputeRow(incumbentId))!;
    const input = { action: "keep-old" as const, expectedRowVersion: Number(dispute.row_version) };
    await expect(kernel.resolveDispute(salesAdmin, String(dispute.id), input)).rejects.toThrow(
      "dispute operation denied",
    );
    await expect(kernel.resolveDispute(orgAuditor, String(dispute.id), input)).rejects.toThrow(
      "dispute operation denied",
    );
  });

  it("rejects a stale expectedRowVersion (optimistic locking)", async () => {
    const dispute = (await disputeRow(incumbentId))!;
    await expect(
      kernel.resolveDispute(supportAdmin, String(dispute.id), {
        action: "keep-old",
        expectedRowVersion: Number(dispute.row_version) + 5,
      }),
    ).rejects.toThrow("dispute changed or was already decided");
  });

  it("keep-old archives the claim, leaves the incumbent current, audits resolve", async () => {
    const dispute = (await disputeRow(incumbentId))!;
    const outcome = await kernel.resolveDispute(supportAdmin, String(dispute.id), {
      action: "keep-old",
      expectedRowVersion: Number(dispute.row_version),
    });
    expect(outcome.resolutionMemoryId).toBeNull();

    expect((await memoryStatus(disputedId)).status).toBe("archived");
    const incumbent = await memoryStatus(incumbentId);
    expect(incumbent.status).toBe("active");
    expect(incumbent.tValidTo).toBeNull();

    const resolved = (await disputeRow(incumbentId))!;
    expect(resolved.status).toBe("resolved");
    expect(resolved.resolution).toBe("keep-old");
    expect(resolved.resolved_by).toBe(supportAdmin.actor);

    const rows = await kernel.audit.search({ op: "resolve" }, [SUPPORT]);
    expect(rows.some((r) => r.memoryId === disputedId && r.result === "ok")).toBe(true);

    // Terminal: the same dispute can never be decided twice.
    await expect(
      kernel.resolveDispute(supportAdmin, String(resolved.id), {
        action: "uphold-new",
        expectedRowVersion: Number(resolved.row_version),
      }),
    ).rejects.toThrow("dispute changed or was already decided");
  });

  it("uphold-new activates the claim, closes the incumbent, links supersedes", async () => {
    const result = await claim("The refund window is 21 days for Acme orders.");
    expect(result.disputed).toHaveLength(1);
    const newDisputedId = result.disputed![0]!.id;
    const dispute = (await disputeRow(incumbentId))!;
    expect(dispute.status).toBe("open");

    const outcome = await kernel.resolveDispute(supportAdmin, String(dispute.id), {
      action: "uphold-new",
      expectedRowVersion: Number(dispute.row_version),
    });
    expect(outcome.resolutionMemoryId).toBe(newDisputedId);

    const upheld = await memoryStatus(newDisputedId);
    expect(upheld.status).toBe("active");
    expect(upheld.supersedes).toBe(incumbentId);
    const incumbent = await memoryStatus(incumbentId);
    expect(incumbent.tValidTo).not.toBeNull();

    const refs = await kernel.memSearch({ query: "refund window Acme" }, supportAgent);
    expect(refs.some((r) => r.content.includes("21 days"))).toBe(true);
    expect(refs.some((r) => r.content.includes("30 days"))).toBe(false);

    const supersedeRows = await kernel.audit.search({ op: "supersede" }, [SUPPORT]);
    expect(supersedeRows.some((r) => r.memoryId === incumbentId)).toBe(true);
  });

  it("edit lands the reviewer's fact as manual provenance superseding the incumbent", async () => {
    const shippingId = await seedDocumentFact(
      SUPPORT,
      "Standard shipping takes 5 days for Acme orders.",
    );
    const result = await claim("Standard shipping takes 2 days for Acme orders.");
    expect(result.disputed).toHaveLength(1);
    expect(result.disputed![0]!.category).toBe("order-management");
    const claimId = result.disputed![0]!.id;
    const dispute = (await disputeRow(shippingId))!;

    const outcome = await kernel.resolveDispute(supportAdmin, String(dispute.id), {
      action: "edit",
      expectedRowVersion: Number(dispute.row_version),
      editedContent: "Standard shipping takes 5 business days for Acme orders.",
    });
    expect(outcome.resolutionMemoryId).not.toBeNull();
    expect(outcome.resolutionMemoryId).not.toBe(claimId);

    const replacement = await kernel.db.query(
      `SELECT status, supersedes, provenance, confidence FROM memory_objects WHERE id = $1`,
      [outcome.resolutionMemoryId],
    );
    const row = replacement.rows[0] as Record<string, unknown>;
    expect(row.status).toBe("active");
    expect(row.supersedes).toBe(shippingId);
    const provenance = typeof row.provenance === "string"
      ? (JSON.parse(row.provenance) as Array<{ source: string; actor: string }>)
      : (row.provenance as Array<{ source: string; actor: string }>);
    expect(provenance[0]!.source).toBe("manual");
    expect(provenance[0]!.actor).toBe(supportAdmin.actor);

    expect((await memoryStatus(claimId)).status).toBe("archived");
    expect((await memoryStatus(shippingId)).tValidTo).not.toBeNull();
    const resolved = (await disputeRow(shippingId))!;
    expect(resolved.resolution).toBe("edit");
    expect(resolved.resolution_memory_id).toBe(outcome.resolutionMemoryId);
  });

  it("rolls the whole resolution back when the incumbent is no longer current", async () => {
    const staleId = await seedDocumentFact(
      SUPPORT,
      "Premium support responds within 4 hours for Acme tickets.",
    );
    const result = await claim("Premium support responds within 9 hours for Acme tickets.");
    expect(result.disputed).toHaveLength(1);
    const dispute = (await disputeRow(staleId))!;

    // Simulate a concurrent higher-trust supersede closing the incumbent.
    await kernel.db.query(
      `UPDATE memory_objects SET t_valid_to = $2 WHERE id = $1`,
      [staleId, new Date().toISOString()],
    );

    await expect(
      kernel.resolveDispute(supportAdmin, String(dispute.id), {
        action: "uphold-new",
        expectedRowVersion: Number(dispute.row_version),
      }),
    ).rejects.toThrow("dispute changed or was already decided");

    // Rollback: dispute still open, claim still quarantined, staleness visible.
    const after = (await disputeRow(staleId))!;
    expect(after.status).toBe("open");
    expect(Number(after.row_version)).toBe(Number(dispute.row_version));
    expect((await memoryStatus(result.disputed![0]!.id)).status).toBe("disputed");
    const views = await kernel.listDisputes(supportAdmin);
    expect(views.find((d) => d.incumbent.id === staleId)?.incumbentCurrent).toBe(false);
  });

  it("restores both entries only when Luna created a repair proposal", async () => {
    const incumbent = await seedDocumentFact(
      SUPPORT,
      "Widget sales were 30 units on 2026-07-01.",
    );
    const result = await claim("Widget sales were 14 units on 2026-07-02.");
    const held = result.disputed![0]!.id;
    const dispute = (await disputeRow(incumbent))!;
    await kernel.db.query(
      `INSERT INTO conflict_repair_proposals
         (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
          detector_version,classification,status,created_at)
       VALUES ($1,$2,'dispute',$3,$4,$5,'luna-context-v1',
               'compatible_distinct','open',$6)`,
      [ulid(), SUPPORT, dispute.id, held, incumbent, new Date().toISOString()],
    );
    const view = (await kernel.listDisputes(supportAdmin))
      .find((entry) => entry.id === String(dispute.id));
    expect(view).toMatchObject({ repairProposed: true, repairClassification: "compatible_distinct" });

    await kernel.resolveDispute(supportAdmin, String(dispute.id), {
      action: "both-valid",
      expectedRowVersion: Number(dispute.row_version),
    });
    expect(await memoryStatus(held)).toMatchObject({ status: "active", supersedes: null });
    expect((await memoryStatus(incumbent)).tValidTo).toBeNull();
    const proposal = await kernel.db.query(
      `SELECT status FROM conflict_repair_proposals WHERE source_id=$1`, [dispute.id],
    );
    expect(proposal.rows[0]).toMatchObject({ status: "applied" });
  });
});

describe("retired conflictReview policy dial", () => {
  it("'all' no longer lets cosine quarantine an equal-rank conflict", async () => {
    await kernel.policyStore.set("org/dialed", "conflictReview: all\n");
    const agent = await issue("org/dialed", "agent:dialed", "agent");
    const first = sync(
      await kernel.memWrite(
        { scope: "team", content: "The Acme welcome bonus is 100 points.", hints: { verbatim: true } },
        agent,
      ),
    );
    expect(first.stored).toHaveLength(1);
    const second = sync(
      await kernel.memWrite(
        { scope: "team", content: "The Acme welcome bonus is 250 points.", hints: { verbatim: true } },
        agent,
      ),
    );
    expect(second.stored).toHaveLength(1);
    expect(second.disputed ?? []).toHaveLength(0);
    expect(second.superseded).toEqual([]);
  });

  it("'off' cannot re-enable cosine retirement", async () => {
    await kernel.policyStore.set("org/legacy", "conflictReview: \"off\"\n");
    const agent = await issue("org/legacy", "agent:legacy", "agent");
    const incumbentId = await seedDocumentFact(
      "org/legacy",
      "The exchange window is 30 days for all Acme orders.",
    );
    const result = sync(
      await kernel.memWrite(
        { scope: "team", content: "The exchange window is 14 days for Acme orders.", hints: { verbatim: true } },
        agent,
      ),
    );
    expect(result.disputed ?? []).toHaveLength(0);
    expect(result.stored).toHaveLength(1);
    expect(result.superseded).toEqual([]);
    expect((await memoryStatus(incumbentId)).tValidTo).toBeNull();
  });
});

describe("erasure interaction", () => {
  it("cascades the dispute away and archives the surviving disputed claim", async () => {
    const incumbentId = await seedDocumentFact(
      SUPPORT,
      "Gift cards expire after 24 months at Acme.",
    );
    const result = await claim("Gift cards expire after 6 months at Acme.");
    expect(result.disputed).toHaveLength(1);
    const claimId = result.disputed![0]!.id;

    const forget = await kernel.memForget(
      { target: { kind: "memory", value: incumbentId } },
      supportAdmin,
    );
    expect(forget.erasedCount).toBeGreaterThanOrEqual(1);

    const gone = await kernel.db.query(
      `SELECT count(*) AS n FROM fact_disputes WHERE disputed_against = $1`,
      [incumbentId],
    );
    expect(Number((gone.rows[0] as { n: unknown }).n)).toBe(0);
    expect((await memoryStatus(claimId)).status).toBe("archived");
  });
});
