/**
 * Answer-outcome capture + accuracy rollup (#18, D31/E31–E33).
 *
 * The service is instantiated directly against the kernel's Db + AuditLog
 * (the exact wiring the integrator adds to kernel.ts), so this file stays
 * green independent of shared-file integration.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import {
  AnswerOutcomeService,
  AnswerOutcomeAuthorizationError,
  AnswerOutcomeValidationError,
  parseAnswerOutcomeBody,
} from "../src/feedback/index.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let service: AnswerOutcomeService;
let root: Identity;
let supportAdmin: Identity;
let supportAgent: Identity;
let salesAdmin: Identity;
let orgAuditor: Identity;

const SUPPORT = "org/support";

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

async function outcomeRows(turnId: string): Promise<Record<string, unknown>[]> {
  const res = await kernel.db.query(
    `SELECT * FROM answer_outcomes WHERE turn_id = $1 ORDER BY created_at, id`,
    [turnId],
  );
  return res.rows as Record<string, unknown>[];
}

async function auditRows(op: string, result?: string): Promise<Record<string, unknown>[]> {
  const res = await kernel.db.query(
    `SELECT * FROM audit_log WHERE op = $1 ${result ? "AND result = $2" : ""} ORDER BY seq`,
    result ? [op, result] : [op],
  );
  return res.rows as Record<string, unknown>[];
}

/** Seed an open fact_disputes row (the write path normally creates these). */
async function seedOpenDispute(namespace: string): Promise<string> {
  const now = new Date().toISOString();
  const mkFact = async (): Promise<string> => {
    const id = ulid();
    await kernel.db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
          provenance, ttl_seconds, last_accessed, access_count, fault_count, status)
       VALUES ($1, $2, 'team', 'L2', 'inline', $3, 'fact', 1,
               NULL, $4, $4, NULL, NULL, $5, NULL, NULL, 0, 0, 'active')`,
      [id, namespace, `fact ${id}`, now,
       JSON.stringify([{ source: "document", actor: "connector:fs", ts: now }])],
    );
    return id;
  };
  const disputedId = await mkFact();
  const incumbentId = await mkFact();
  const disputeId = ulid();
  await kernel.db.query(
    `INSERT INTO fact_disputes
       (id, namespace, memory_id, disputed_against, category, reason, status,
        row_version, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 'other', 'test seed', 'open', 1, $5, $5)`,
    [disputeId, namespace, disputedId, incumbentId, now],
  );
  return disputeId;
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  service = new AnswerOutcomeService({ db: kernel.db, audit: kernel.audit });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;
  supportAdmin = await issue(SUPPORT, "admin:support", "admin");
  supportAgent = await issue(SUPPORT, "agent:support", "agent");
  salesAdmin = await issue("org/sales", "admin:sales", "admin");
  orgAuditor = await issue("org", "auditor:org", "auditor");
});

afterAll(async () => {
  await kernel.close();
});

describe("record - identity is server-resolved (D9/E31)", () => {
  it("stores namespace/actor from the Identity, never the body", async () => {
    const result = await service.record(supportAgent, {
      turnId: "t-identity",
      outcome: "answered-without-human",
      queryText: "what is the refund window?",
    });
    expect(result.deduplicated).toBe(false);
    const rows = await outcomeRows("t-identity");
    expect(rows).toHaveLength(1);
    expect(rows[0].namespace).toBe(SUPPORT);
    expect(rows[0].actor).toBe("agent:support");
    expect(rows[0].resolved_by).toBeNull();
    // query text hashed server-side, never stored raw
    expect(String(rows[0].query_sha256)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a body asserting identity fields", () => {
    expect(() =>
      parseAnswerOutcomeBody({ turnId: "x", outcome: "answered", namespace: "org/sales" }),
    ).toThrow(AnswerOutcomeValidationError);
    expect(() =>
      parseAnswerOutcomeBody({ turnId: "x", outcome: "answered", resolvedBy: "eve" }),
    ).toThrow(AnswerOutcomeValidationError);
  });

  it("sets resolved_by to the resolver for human-resolved outcomes", async () => {
    await service.record(supportAdmin, { turnId: "t-human", outcome: "answered" });
    const rows = await outcomeRows("t-human");
    expect(rows[0].resolved_by).toBe("admin:support");
  });
});

describe("record - authorization + audit evidence (D4)", () => {
  it("denies an agent badge asserting a human-resolved outcome, with an audit row", async () => {
    await expect(
      service.record(supportAgent, { turnId: "t-agent-deny", outcome: "answered" }),
    ).rejects.toBeInstanceOf(AnswerOutcomeAuthorizationError);
    expect(await outcomeRows("t-agent-deny")).toHaveLength(0);
    const denied = await auditRows("answer_outcome", "denied");
    expect(denied.some((r) => String(r.detail).includes("t-agent-deny"))).toBe(true);
  });

  it("denies an agent badge superseding a human-resolved outcome (D31)", async () => {
    // Isolated subtree so the fixed-count accuracy expectations below stay put.
    const lockAdmin = await issue("iso/lock", "admin:lock", "admin");
    const lockAgent = await issue("iso/lock", "agent:lock", "agent");
    const human = await service.record(lockAdmin, {
      turnId: "t-human-lock",
      outcome: "answered",
    });
    // 'weak' is an agent-recordable outcome — but not over a human judgement.
    await expect(
      service.record(lockAgent, { turnId: "t-human-lock", outcome: "weak" }),
    ).rejects.toBeInstanceOf(AnswerOutcomeAuthorizationError);
    const rows = await outcomeRows("t-human-lock");
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(human.id);
    expect(rows[0].t_valid_to).toBeNull(); // the human row is still current
    const denied = await auditRows("answer_outcome", "denied");
    expect(denied.some((r) => String(r.detail).includes("t-human-lock"))).toBe(true);
    // A human-resolved 'weak' is equally immutable to an agent...
    await service.record(lockAdmin, { turnId: "t-weak-lock", outcome: "weak" });
    await expect(
      service.record(lockAgent, {
        turnId: "t-weak-lock",
        outcome: "answered-without-human",
      }),
    ).rejects.toBeInstanceOf(AnswerOutcomeAuthorizationError);
    // ...while an agent self-report (resolved_by NULL) stays supersedable and
    // a human may always overrule the agent (the existing D7 chain).
    await service.record(lockAgent, {
      turnId: "t-agent-lock",
      outcome: "answered-without-human",
    });
    const upgraded = await service.record(lockAgent, {
      turnId: "t-agent-lock",
      outcome: "weak",
    });
    expect(upgraded.superseded).not.toBeNull();
  });

  it("denies an auditor, with an audit row", async () => {
    await expect(
      service.record(orgAuditor, { turnId: "t-auditor-deny", outcome: "weak" }),
    ).rejects.toBeInstanceOf(AnswerOutcomeAuthorizationError);
    const denied = await auditRows("answer_outcome", "denied");
    expect(denied.some((r) => String(r.detail).includes("t-auditor-deny"))).toBe(true);
  });

  it("audits ok in the same store as the row (D4/E32 - one Postgres)", async () => {
    const ok = await auditRows("answer_outcome", "ok");
    expect(ok.some((r) => String(r.detail).includes("turn=t-identity"))).toBe(true);
  });
});

describe("record - supersedence (D7) and dedup", () => {
  it("re-recording a turn closes the prior row and links supersedes", async () => {
    const first = await service.record(supportAgent, {
      turnId: "t-chain",
      outcome: "answered-without-human",
    });
    const second = await service.record(supportAdmin, {
      turnId: "t-chain",
      outcome: "weak",
      detail: "missed the enterprise tier",
    });
    expect(second.superseded).toBe(first.id);
    const rows = await outcomeRows("t-chain");
    expect(rows).toHaveLength(2);
    const closed = rows.find((r) => r.id === first.id)!;
    const current = rows.find((r) => r.id === second.id)!;
    expect(closed.t_valid_to).not.toBeNull();
    expect(current.t_valid_to).toBeNull();
    expect(current.supersedes).toBe(first.id);
  });

  it("an identical re-record dedupes instead of growing the chain", async () => {
    const again = await service.record(supportAdmin, { turnId: "t-chain", outcome: "weak" });
    expect(again.deduplicated).toBe(true);
    expect(await outcomeRows("t-chain")).toHaveLength(2);
  });
});

describe("record - dispute integration (src/disputes/, no parallel system)", () => {
  it("links a visible open dispute on a 'disputed' outcome", async () => {
    const disputeId = await seedOpenDispute(SUPPORT);
    await service.record(supportAdmin, {
      turnId: "t-disputed",
      outcome: "disputed",
      disputeId,
    });
    const rows = await outcomeRows("t-disputed");
    expect(rows[0].dispute_id).toBe(disputeId);
  });

  it("denies a dispute link outside the caller's scope (no existence oracle)", async () => {
    const foreign = await seedOpenDispute("org/sales");
    await expect(
      service.record(supportAdmin, {
        turnId: "t-foreign-dispute",
        outcome: "disputed",
        disputeId: foreign,
      }),
    ).rejects.toBeInstanceOf(AnswerOutcomeAuthorizationError);
    await expect(
      service.record(supportAdmin, {
        turnId: "t-missing-dispute",
        outcome: "disputed",
        disputeId: "does-not-exist",
      }),
    ).rejects.toThrow("dispute not found or not visible");
  });

  it("rejects disputeId with a non-disputed outcome", () => {
    expect(() =>
      parseAnswerOutcomeBody({ turnId: "x", outcome: "answered", disputeId: "d1" }),
    ).toThrow(AnswerOutcomeValidationError);
  });
});

describe("accuracy - derived only, subtree-scoped (E33)", () => {
  it("computes accuracy from current rows + unlinked open disputes", async () => {
    const rollup = await service.accuracy(supportAdmin);
    // Current SUPPORT rows at this point:
    //   t-identity  answered-without-human
    //   t-human     answered
    //   t-chain     weak
    //   t-disputed  disputed (linked dispute — must NOT double count)
    // Plus 0 unlinked open disputes in org/support scope? The linked one is
    // excluded; no other SUPPORT dispute was seeded.
    expect(rollup.answered).toBe(1);
    expect(rollup.weak).toBe(1);
    expect(rollup.disputed).toBe(1);
    expect(rollup.answeredWithoutHuman).toBe(1);
    expect(rollup.openDisputes).toBe(0);
    expect(rollup.answeredTotal).toBe(4);
    expect(rollup.accurate).toBe(2); // answered + answered-without-human
    expect(rollup.accuracy).toBeCloseTo(2 / 4);
    expect(rollup.verifiedAccuracy).toBeCloseTo(1 / 3);
  });

  it("folds unlinked open disputes into the denominator", async () => {
    const salesRollup1 = await service.accuracy(salesAdmin);
    // org/sales has one open dispute (seeded above) with no outcome link.
    expect(salesRollup1.openDisputes).toBe(1);
    expect(salesRollup1.answeredTotal).toBe(1);
    expect(salesRollup1.accuracy).toBe(0);
  });

  it("never leaks a sibling subtree", async () => {
    const sales = await service.accuracy(salesAdmin);
    expect(sales.answered).toBe(0);
    expect(sales.weak).toBe(0);
    // and support's rollup did not see sales' dispute (openDisputes was 0)
  });

  it("root owner sees the whole org", async () => {
    const org = await service.accuracy(root);
    expect(org.answeredTotal).toBeGreaterThanOrEqual(5);
  });

  it("audits the rollup read (D4)", async () => {
    const stats = await auditRows("stats");
    expect(stats.some((r) => r.purpose === "accuracy-rollup")).toBe(true);
  });

  // D40: the accuracy hero heads the member's Usage analytics screen, where
  // every other number is actor-pinned. A member reads its own outcomes.
  it("pins a member to its own outcomes and drops the unattributable dispute term", async () => {
    const member = await issue(SUPPORT, "mira", "member");
    const before = await service.accuracy(member);
    expect(before.answeredTotal).toBe(0);
    expect(before.accuracy).toBeNull();

    await service.record(member, { turnId: "t-member-own", outcome: "answered" });
    const mine = await service.accuracy(member);
    expect(mine.answered).toBe(1);
    expect(mine.answeredTotal).toBe(1);
    expect(mine.accuracy).toBe(1);
    // The admin over the SAME namespace still reads every actor's outcomes.
    const team = await service.accuracy(supportAdmin);
    expect(team.answeredTotal).toBe(5);

    // fact_disputes carries no actor, so a pinned caller never inherits the
    // subtree's open-dispute count (the sales member proves it explicitly).
    const salesMember = await issue("org/sales", "sofia", "member");
    const salesMemberRollup = await service.accuracy(salesMember);
    expect(salesMemberRollup.openDisputes).toBe(0);
    expect((await service.accuracy(salesAdmin)).openDisputes).toBe(1);
  });

  it("keeps an auditor on the oversight side of the accuracy pin", async () => {
    const asAuditor = await service.accuracy(orgAuditor);
    expect(asAuditor.answeredTotal).toBeGreaterThanOrEqual(5);
  });

  it("validates window bounds", async () => {
    await expect(
      service.accuracy(supportAdmin, { since: "not-a-date" }),
    ).rejects.toBeInstanceOf(AnswerOutcomeValidationError);
    const windowed = await service.accuracy(supportAdmin, {
      since: new Date(Date.now() + 3_600_000).toISOString(),
    });
    expect(windowed.answeredTotal).toBe(0);
    expect(windowed.accuracy).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// D37: answer_outcomes trace linkage
// ---------------------------------------------------------------------------

describe("record - D37 trace linkage", () => {
  async function seedTrace(traceId: string, namespace: string, actor: string): Promise<void> {
    await kernel.db.query(
      `INSERT INTO query_traces (trace_id, ts, namespace, actor, events)
       VALUES ($1, $2, $3, $4, 1)`,
      [traceId, new Date().toISOString(), namespace, actor],
    );
  }

  async function traceOutcome(traceId: string): Promise<string | null> {
    const res = await kernel.db.query(
      `SELECT outcome FROM query_traces WHERE trace_id = $1`,
      [traceId],
    );
    return res.rows.length > 0 ? ((res.rows[0].outcome as string | null) ?? null) : null;
  }

  it("stores traceId on the row and back-links query_traces.outcome", async () => {
    await seedTrace("trace-d37-accept", SUPPORT, "agent:support");
    const result = await service.record(supportAgent, {
      turnId: "t-d37-accept",
      outcome: "weak",
      traceId: "trace-d37-accept",
    });
    expect(result.deduplicated).toBe(false);
    const rows = await outcomeRows("t-d37-accept");
    expect(rows).toHaveLength(1);
    expect(rows[0].trace_id).toBe("trace-d37-accept");
    expect(await traceOutcome("trace-d37-accept")).toBe("weak");
  });

  it("scopes the back-link to the caller's namespace (no cross-tenant relabel)", async () => {
    // The trace exists only in org/sales; a support outcome must not link it.
    await seedTrace("trace-d37-scoped", "org/sales", "admin:sales");
    await service.record(supportAgent, {
      turnId: "t-d37-scoped",
      outcome: "weak",
      traceId: "trace-d37-scoped",
    });
    const rows = await outcomeRows("t-d37-scoped");
    expect(rows[0].trace_id).toBe("trace-d37-scoped");
    expect(await traceOutcome("trace-d37-scoped")).toBeNull();
  });

  it("supersede links the NEW current row's outcome", async () => {
    await seedTrace("trace-d37-supersede", SUPPORT, "admin:support");
    await service.record(supportAdmin, {
      turnId: "t-d37-supersede",
      outcome: "answered",
      traceId: "trace-d37-supersede",
    });
    expect(await traceOutcome("trace-d37-supersede")).toBe("answered");
    const result = await service.record(supportAdmin, {
      turnId: "t-d37-supersede",
      outcome: "disputed",
      traceId: "trace-d37-supersede",
    });
    expect(result.superseded).not.toBeNull();
    expect(await traceOutcome("trace-d37-supersede")).toBe("disputed");
    const rows = await outcomeRows("t-d37-supersede");
    const current = rows.filter((r) => r.t_valid_to === null);
    expect(current).toHaveLength(1);
    expect(current[0].trace_id).toBe("trace-d37-supersede");
  });

  it("a missing traceId stores NULL and touches no trace", async () => {
    await seedTrace("trace-d37-unlinked", SUPPORT, "agent:support");
    await service.record(supportAgent, {
      turnId: "t-d37-unlinked",
      outcome: "answered-without-human",
    });
    const rows = await outcomeRows("t-d37-unlinked");
    expect(rows[0].trace_id).toBeNull();
    expect(await traceOutcome("trace-d37-unlinked")).toBeNull();
  });

  it("rejects a malformed traceId (parse → 400; service re-validates in depth)", async () => {
    expect(() =>
      parseAnswerOutcomeBody({ turnId: "t-x", outcome: "weak", traceId: "bad trace!!" }),
    ).toThrow(AnswerOutcomeValidationError);
    expect(() =>
      parseAnswerOutcomeBody({ turnId: "t-x", outcome: "weak", traceId: "" }),
    ).toThrow(AnswerOutcomeValidationError);
    await expect(
      service.record(supportAgent, {
        turnId: "t-d37-bad",
        outcome: "weak",
        traceId: "bad trace!!",
      }),
    ).rejects.toBeInstanceOf(AnswerOutcomeValidationError);
  });

  it("still hard-rejects identity-shaped fields alongside traceId (D9)", async () => {
    expect(() =>
      parseAnswerOutcomeBody({
        turnId: "t-x",
        outcome: "weak",
        traceId: "ok-trace",
        actor: "mallory",
      }),
    ).toThrow(AnswerOutcomeValidationError);
  });
});
