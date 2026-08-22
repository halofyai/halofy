/**
 * Write-time conflict detection with trust-ranked auto-resolution
 * (CONTRACTS-CONFLICT-AUTOPILOT CA1-CA6, CA10).
 *
 * The decision matrix is exercised as a pure function; everything else runs
 * against a real in-memory PGlite kernel, because the properties that matter
 * here — the outbox committing with the write, D7 supersedence, fail-closed
 * behaviour without a judge, and namespace isolation of the neighbour query —
 * only exist at the database boundary. No network access.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import {
  ConflictAutopilot,
  JUDGE_CALLS_PER_PASS,
  autoDecision,
  type ConflictAutonomy,
} from "../src/conflict-autopilot/index.js";
import { enqueueConflictCheck } from "../src/conflict-autopilot/queue.js";
import type {
  ConflictClassificationCandidate,
  ConflictClassifier,
} from "../src/conflict-scans/classifier.js";
import { MemoryIndex } from "../src/index/index.js";
import { TRUST_RANK } from "../src/write/index.js";
import type { Identity, MemoryObject, ProvenanceEntry } from "../src/types.js";

const ACME = "acme";
const GLOBEX = "globex";

describe("CA4 decision matrix", () => {
  const doc = TRUST_RANK.document;
  const chat = TRUST_RANK.conversation;

  it("lets a higher-trust newer fact settle the conflict itself", () => {
    expect(autoDecision(doc, chat, 0.95, "auto"))
      .toEqual({ keep: "newer", rule: "higher-trust-wins" });
  });

  it("rejects a lower-trust newer claim without retiring the trusted fact", () => {
    expect(autoDecision(chat, doc, 0.95, "auto"))
      .toEqual({ keep: "older", rule: "lower-trust-rejected" });
  });

  it("gives a confident equal-trust tie to the newer fact", () => {
    expect(autoDecision(doc, doc, 0.95, "auto"))
      .toEqual({ keep: "newer", rule: "equal-trust-newest-wins" });
  });

  it("parks an equal-trust tie the judge is unsure about", () => {
    expect(autoDecision(doc, doc, 0.85, "auto")).toBeNull();
  });

  it("under 'lower-trust' only an outranking write may act unattended", () => {
    expect(autoDecision(doc, chat, 0.99, "lower-trust"))
      .toEqual({ keep: "newer", rule: "higher-trust-wins" });
    expect(autoDecision(chat, doc, 0.99, "lower-trust")).toBeNull();
    expect(autoDecision(doc, doc, 0.99, "lower-trust")).toBeNull();
  });

  it("under 'all' nothing is ever settled automatically", () => {
    for (const [a, b] of [[doc, chat], [chat, doc], [doc, doc]] as const) {
      expect(autoDecision(a, b, 0.99, "all")).toBeNull();
    }
  });
});

let kernel: Kernel;
let knowledgeDir: string;
let owner: Identity;
let judgeCalls = 0;
let judgeBatchSizes: number[] = [];
let judgeBatchNamespaces: string[][] = [];
let judgeFails = false;

/**
 * Stands in for the Azure judge. Contradiction is keyed off the planted
 * "N days" pairing so a test can plant an agreeing fact and prove it is left
 * alone; "Maybe" plants a decision confident enough to publish (>= 0.8) but
 * under the equal-trust auto bar (0.9).
 */
const classifier: ConflictClassifier = {
  model: "test-semantic-judge",
  async classify(candidates: readonly ConflictClassificationCandidate[]) {
    judgeCalls += 1;
    judgeBatchSizes.push(candidates.length);
    judgeBatchNamespaces.push([...new Set(candidates.flatMap((candidate) =>
      [candidate.left.namespace, candidate.right.namespace]))]);
    if (judgeFails) throw new Error("judge unavailable");
    return candidates.map((candidate) => {
      const pair = `${candidate.left.content}\n${candidate.right.content}`;
      const sameEvent = candidate.left.eventTime === candidate.right.eventTime;
      const contradiction = pair.includes("30 days") && pair.includes("14 days") && sameEvent;
      return {
        candidateId: candidate.id,
        classification: contradiction ? "contradiction" as const : "compatible_distinct" as const,
        sameSubject: true,
        sameAttribute: true,
        sameContext: sameEvent,
        valuesCompatible: !contradiction,
        contextDifferences: sameEvent ? [] : ["event_time"],
        contradiction,
        confidence: !contradiction ? 0.9 : pair.includes("Maybe") ? 0.85 : 0.97,
        reason: contradiction ? "conflicting_quantity" : "other_semantic_conflict",
      };
    });
  },
};

/** A unit vector whose cosine against `base()` is exactly `similarity`. */
function similarVector(similarity: number, dim = 256): number[] {
  const out = new Array<number>(dim).fill(0);
  out[0] = similarity;
  out[1] = Math.sqrt(Math.max(0, 1 - similarity * similarity));
  return out;
}

function base(dim = 256): number[] {
  const out = new Array<number>(dim).fill(0);
  out[0] = 1;
  return out;
}

async function seedFact(input: {
  namespace: string;
  content: string;
  source: ProvenanceEntry["source"];
  embedding: number[];
  scope?: MemoryObject["scope"];
  eventTime?: string | null;
}): Promise<string> {
  const id = ulid();
  const now = new Date().toISOString();
  const fact: MemoryObject = {
    id,
    namespace: input.namespace,
    scope: input.scope ?? "team",
    tier: "L2",
    backendRef: "inline",
    content: input.content,
    type: "fact",
    confidence: 1,
    eventTime: input.eventTime ?? null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{
      source: input.source,
      actor: input.source === "conversation" ? "agent:support" : "connector:handbook",
      ts: now,
    }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  await new MemoryIndex(kernel.db).insert(fact, input.embedding);
  return id;
}

function autopilot(autonomy: ConflictAutonomy = "auto", judge = classifier) {
  // Zero backoff: these cases assert what the NEXT pass does, not how long a
  // deferred row waits.
  return new ConflictAutopilot(kernel.db, kernel.audit, judge, async () => autonomy, 0);
}

async function factRow(id: string): Promise<Record<string, unknown> | undefined> {
  const result = await kernel.db.query(
    `SELECT status, t_valid_to, supersedes FROM memory_objects WHERE id = $1`,
    [id],
  );
  return result.rows[0] as Record<string, unknown> | undefined;
}

async function findings(): Promise<Record<string, unknown>[]> {
  const result = await kernel.db.query(
    `SELECT status, origin, detector_version, resolution, resolution_memory_id, resolved_by, reason,
            auto_rule, left_memory_id, right_memory_id
       FROM conflict_scan_findings ORDER BY first_seen_at, id`,
  );
  return result.rows as Record<string, unknown>[];
}

async function queueRow(id: string): Promise<Record<string, unknown> | undefined> {
  const result = await kernel.db.query(
    `SELECT status, attempts, last_error FROM conflict_detection_queue WHERE memory_id = $1`,
    [id],
  );
  return result.rows[0] as Record<string, unknown> | undefined;
}

/** Reset every table this suite asserts on, so cases stay independent. */
async function reset(): Promise<void> {
  await kernel.db.query(`DELETE FROM conflict_scan_findings`);
  await kernel.db.query(`DELETE FROM conflict_detection_queue`);
  await kernel.db.query(`DELETE FROM memory_objects`);
  judgeCalls = 0;
  judgeBatchSizes = [];
  judgeBatchNamespaces = [];
  judgeFails = false;
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-conflict-autopilot-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
    conflictClassifier: classifier,
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root owner did not resolve");
  const acmeKey = await kernel.auth.issueKey(ACME, "owner:acme", "owner", root);
  const resolved = await kernel.auth.resolve(acmeKey.plaintext);
  if (!resolved) throw new Error("acme owner did not resolve");
  owner = resolved;
});

beforeEach(reset);

afterAll(async () => {
  await kernel.close();
  await rm(knowledgeDir, { recursive: true, force: true });
});

describe("write-time detection", () => {
  it("publishes a review finding and leaves both trust levels in use", async () => {
    const document = await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());

    const run = await autopilot().runOnce();
    expect(run).toMatchObject({ claimed: 1, checked: 1, autoResolved: 0, needsReview: 1 });

    const retired = await factRow(chat);
    expect(retired?.t_valid_to).toBeNull();
    expect(retired?.status).toBe("active");
    const kept = await factRow(document);
    expect(kept?.t_valid_to).toBeNull();
    expect(kept?.supersedes).toBeNull();

    const rows = await findings();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      status: "open",
      origin: "write",
      detector_version: "luna-context-v1",
    });
    expect(await queueRow(chat)).toMatchObject({ status: "done" });
  });

  it("does not let a higher-trust fact retire another without a person", async () => {
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: base(),
    });
    const document = await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, document, ACME, new Date().toISOString());

    expect(await autopilot().runOnce()).toMatchObject({ autoResolved: 0, needsReview: 1 });
    expect((await factRow(chat))?.t_valid_to).toBeNull();
    expect((await factRow(document))?.t_valid_to).toBeNull();
    expect((await findings())[0]).toMatchObject({ status: "open" });
  });

  it("parks an equal-trust conflict the judge is unsure about", async () => {
    const first = await seedFact({
      namespace: ACME,
      content: "Maybe the refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const second = await seedFact({
      namespace: ACME,
      content: "Maybe the refund window is 14 days.",
      source: "document",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, second, ACME, new Date().toISOString());

    expect(await autopilot().runOnce()).toMatchObject({ autoResolved: 0, needsReview: 1 });
    // Nothing was retired: an ambiguous tie is a review item, not a decision.
    expect((await factRow(first))?.t_valid_to).toBeNull();
    expect((await factRow(second))?.t_valid_to).toBeNull();
    expect((await findings())[0]).toMatchObject({ status: "open", origin: "write" });
  });

  it("leaves compatible neighbours alone", async () => {
    await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const compatible = await seedFact({
      namespace: ACME,
      content: "Refund requests are handled by the Support team.",
      source: "document",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, compatible, ACME, new Date().toISOString());

    expect(await autopilot().runOnce()).toMatchObject({ checked: 1, autoResolved: 0, needsReview: 0 });
    expect(await findings()).toHaveLength(0);
    expect((await factRow(compatible))?.t_valid_to).toBeNull();
  });

  it("never judges a neighbour in another namespace", async () => {
    await seedFact({
      namespace: GLOBEX,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const acmeFact = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.99),
    });
    await enqueueConflictCheck(kernel.db, acmeFact, ACME, new Date().toISOString());

    expect(await autopilot().runOnce()).toMatchObject({ checked: 1, autoResolved: 0 });
    expect(judgeCalls).toBe(0);
    expect(await findings()).toHaveLength(0);
    expect((await factRow(acmeFact))?.t_valid_to).toBeNull();
  });

  it("never mixes organizations when filling a cross-fact model batch", async () => {
    await seedFact({
      namespace: ACME,
      content: "Acme support is available on weekdays.",
      source: "document",
      embedding: base(),
    });
    const acmeQueued = await seedFact({
      namespace: ACME,
      content: "Acme support handles refund questions.",
      source: "document",
      embedding: similarVector(0.95),
    });
    await seedFact({
      namespace: GLOBEX,
      content: "Globex support is available on weekdays.",
      source: "document",
      embedding: base(),
    });
    const globexQueued = await seedFact({
      namespace: GLOBEX,
      content: "Globex support handles refund questions.",
      source: "document",
      embedding: similarVector(0.95),
    });
    await enqueueConflictCheck(kernel.db, acmeQueued, ACME, "2026-08-13T00:00:00.000Z");
    await enqueueConflictCheck(kernel.db, globexQueued, GLOBEX, "2026-08-13T00:00:01.000Z");

    expect(await autopilot().runOnce({ limit: 10 })).toMatchObject({ claimed: 1, checked: 1 });
    expect(judgeBatchNamespaces).toEqual([[ACME]]);
    expect(await autopilot().runOnce({ limit: 10 })).toMatchObject({ claimed: 1, checked: 1 });
    expect(judgeBatchNamespaces).toEqual([[ACME], [GLOBEX]]);
  });

  it("skips a neighbour that is merely nearby, without paying the judge", async () => {
    await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const distant = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      // Under the 0.6 floor: not the same subject, not worth a model call.
      embedding: similarVector(0.2),
    });
    await enqueueConflictCheck(kernel.db, distant, ACME, new Date().toISOString());

    expect(await autopilot().runOnce()).toMatchObject({ checked: 1 });
    expect(judgeCalls).toBe(0);
    expect(await findings()).toHaveLength(0);
  });
});

describe("autonomy dial (CA5)", () => {
  async function plantLowerTrustConflict(): Promise<{ document: string; chat: string }> {
    const document = await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());
    return { document, chat };
  }

  it("'all' detects everything and settles nothing", async () => {
    const { document, chat } = await plantLowerTrustConflict();
    expect(await autopilot("all").runOnce())
      .toMatchObject({ checked: 1, autoResolved: 0, needsReview: 1 });
    expect((await factRow(document))?.t_valid_to).toBeNull();
    expect((await factRow(chat))?.t_valid_to).toBeNull();
    expect((await findings())[0]).toMatchObject({ status: "open" });
  });

  it("'lower-trust' parks a claim it may not settle", async () => {
    const { chat } = await plantLowerTrustConflict();
    expect(await autopilot("lower-trust").runOnce())
      .toMatchObject({ autoResolved: 0, needsReview: 1 });
    expect((await factRow(chat))?.t_valid_to).toBeNull();
  });
});

describe("fail-closed and durability (CA1/CA3)", () => {
  async function plantAndEnqueue(): Promise<string> {
    await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());
    return chat;
  }

  it("publishes nothing and retires nothing when the judge is unreachable", async () => {
    const chat = await plantAndEnqueue();
    judgeFails = true;

    expect(await autopilot().runOnce()).toMatchObject({ checked: 0, deferred: 1 });
    expect(await findings()).toHaveLength(0);
    expect((await factRow(chat))?.t_valid_to).toBeNull();
    // Retained as pending work — never recorded as a completed clean check.
    expect(await queueRow(chat)).toMatchObject({ status: "pending", last_error: "judge_unavailable" });
  });

  it("publishes nothing when no judge is configured at all", async () => {
    const chat = await plantAndEnqueue();
    expect(await autopilot("auto", null as never).runOnce())
      .toMatchObject({ checked: 0, deferred: 1 });
    expect(await findings()).toHaveLength(0);
    expect((await factRow(chat))?.t_valid_to).toBeNull();
  });

  it("drains the backlog on recovery without duplicating the finding", async () => {
    const chat = await plantAndEnqueue();
    judgeFails = true;
    await autopilot().runOnce();
    judgeFails = false;

    expect(await autopilot().runOnce()).toMatchObject({ autoResolved: 0, needsReview: 1 });
    // A third pass has nothing left to claim, and CS6 keeps the ledger at one
    // row for the pair even if the same fact is re-enqueued.
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());
    await autopilot().runOnce();
    expect(await findings()).toHaveLength(1);
  });

  it("reports pending work and judge health for the S11 ledger", async () => {
    await plantAndEnqueue();
    const health = await autopilot().ledgerHealth({ namespace: ACME, pattern: `${ACME}/%` });
    expect(health).toEqual({ pendingChecks: 1, detectionDegraded: false });
    const degraded = await autopilot("auto", null as never)
      .ledgerHealth({ namespace: ACME, pattern: `${ACME}/%` });
    expect(degraded.detectionDegraded).toBe(true);
  });
});

describe("cost ceiling (CA3)", () => {
  it("spends a bounded number of judge calls per pass and defers the rest", async () => {
    // One bulk import: many facts committed at once, each worth up to K judge
    // calls. The pass must stop at its ceiling and leave the rest queued —
    // never drop them, never spend without bound.
    await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const ids: string[] = [];
    for (let index = 0; index < 12; index += 1) {
      const id = await seedFact({
        namespace: ACME,
        content: `Import row ${index}: the refund window is 14 days.`,
        source: "document",
        embedding: similarVector(0.9 - index * 0.001),
      });
      ids.push(id);
      await enqueueConflictCheck(kernel.db, id, ACME, new Date().toISOString());
    }

    const run = await autopilot().runOnce();
    expect(run.claimed).toBe(10);
    // Ten queued facts contribute to one organization-scoped Luna packet.
    // The ceiling is candidate pairs, not provider requests.
    expect(judgeCalls).toBe(1);
    expect(judgeBatchSizes).toEqual([JUDGE_CALLS_PER_PASS]);
    // Nothing was lost — the unspent work is still queued.
    const pending = await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM conflict_detection_queue WHERE status <> 'done'`,
    );
    expect(Number((pending.rows[0] as Record<string, unknown>).count)).toBeGreaterThan(0);
  });
});

describe("human-only resolution", () => {
  it("creates no automatic decision to overturn", async () => {
    const document = await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());
    expect(await autopilot().runOnce()).toMatchObject({ autoResolved: 0, needsReview: 1 });

    const decisions = await kernel.conflictScans.listAutoDecisions(owner);
    expect(decisions).toHaveLength(0);
    expect((await factRow(chat))?.t_valid_to).toBeNull();
    expect((await factRow(document))?.t_valid_to).toBeNull();
    expect((await findings())[0]).toMatchObject({ status: "open" });
  });

  it("leaves facts untouched until the open finding is resolved", async () => {
    await seedFact({
      namespace: ACME,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const chat = await seedFact({
      namespace: ACME,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, chat, ACME, new Date().toISOString());
    await autopilot().runOnce();
    expect(await kernel.conflictScans.listAutoDecisions(owner)).toHaveLength(0);
    expect((await factRow(chat))?.t_valid_to).toBeNull();
    expect((await findings())[0]).toMatchObject({ status: "open" });
  });

  it("denies an overturn from outside the caller's subtree", async () => {
    await seedFact({
      namespace: GLOBEX,
      content: "The refund window is 30 days.",
      source: "document",
      embedding: base(),
    });
    const globexChat = await seedFact({
      namespace: GLOBEX,
      content: "The refund window is 14 days.",
      source: "conversation",
      embedding: similarVector(0.9),
    });
    await enqueueConflictCheck(kernel.db, globexChat, GLOBEX, new Date().toISOString());
    await autopilot().runOnce();
    const rows = await findings();
    expect(rows).toHaveLength(1);
    const id = (await kernel.db.query(
      `SELECT id, row_version FROM conflict_scan_findings LIMIT 1`,
    )).rows[0] as Record<string, unknown>;

    // The ACME owner can neither see nor overturn a GLOBEX decision.
    expect(await kernel.conflictScans.listAutoDecisions(owner)).toHaveLength(0);
    await expect(kernel.overturnConflictFinding(
      owner, String(id.id), Number(id.row_version),
    )).rejects.toThrow(/outside the caller's subtree/i);
  });
});

describe("write path integration (CA1)", () => {
  it("enqueues every committed fact with the write that produced it", async () => {
    const written = await kernel.memWrite(
      { scope: "team", content: "The refund window is 14 days." },
      owner,
      "agent-test",
    );
    expect(written.stored).toHaveLength(1);
    const id = written.stored[0]!.id;
    expect(await queueRow(id)).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("catches a differently-worded contradiction the door's band walks past", async () => {
    // Both facts are planted through the real write path with its real
    // embedder. The wording is deliberately far enough apart (cosine ~0.68)
    // that the synchronous supersedence band (>= 0.75) does NOT fire — which
    // is precisely the case the batch scan was left to catch, and missed.
    const first = await kernel.memWrite(
      { scope: "team", content: "The refund window is 30 days." },
      owner,
      "agent-test",
    );
    const second = await kernel.memWrite(
      { scope: "team", content: "The stated refund window is 14 days for everyone." },
      owner,
      "agent-test",
    );
    expect(second.superseded).toHaveLength(0);
    const firstId = first.stored[0]?.id;
    const secondId = second.stored[0]?.id;
    expect(firstId).toBeDefined();
    expect(secondId).toBeDefined();

    const run = await autopilot().runOnce();
    expect(run.claimed).toBe(2);
    expect(run.autoResolved).toBe(0);
    expect(run.needsReview).toBe(1);
    const rows = await findings();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      origin: "write",
      status: "open",
      reason: "conflicting_quantity",
      detector_version: "luna-context-v1",
    });
    expect((await factRow(firstId!))?.t_valid_to).toBeNull();
    expect((await factRow(secondId!))?.t_valid_to).toBeNull();
  });

  it("treats the same product on different event dates as compatible observations", async () => {
    const first = await seedFact({
      namespace: ACME,
      content: "Widget sales were 30 units.",
      source: "document",
      embedding: base(),
      eventTime: "2026-08-01T00:00:00.000Z",
    });
    const second = await seedFact({
      namespace: ACME,
      content: "Widget sales were 14 units.",
      source: "document",
      embedding: similarVector(0.99),
      eventTime: "2026-08-02T00:00:00.000Z",
    });
    await enqueueConflictCheck(kernel.db, second, ACME, new Date().toISOString());
    expect(await autopilot().runOnce()).toMatchObject({ autoResolved: 0, needsReview: 0 });
    expect(await findings()).toHaveLength(0);
    expect((await factRow(first))?.t_valid_to).toBeNull();
    expect((await factRow(second))?.t_valid_to).toBeNull();
  });
});

describe("historical Luna revalidation", () => {
  it("rechecks an exact legacy pair and dismisses a different-date false finding", async () => {
    const left = await seedFact({
      namespace: ACME,
      content: "Widget sales were 30 units.",
      source: "document",
      embedding: base(),
      eventTime: "2026-07-01T00:00:00.000Z",
    });
    const right = await seedFact({
      namespace: ACME,
      content: "Widget sales were 14 units.",
      source: "document",
      embedding: similarVector(0.99),
      eventTime: "2026-07-02T00:00:00.000Z",
    });
    const findingId = ulid();
    const now = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO conflict_scan_findings
         (id,target_namespace,left_memory_id,right_memory_id,fingerprint,detector_version,
          entity,category,reason,confidence,flags,status,row_version,origin,first_seen_at,last_seen_at)
       VALUES ($1,$2,$3,$4,$5,'legacy-cosine-v1','Widget','product-info',
               'conflicting_quantity',0.99,'[]','open',1,'write',$6,$6)`,
      [findingId, ACME, left, right, `legacy-${findingId}`, now],
    );
    await kernel.db.query(
      `INSERT INTO conflict_pair_recheck_queue
         (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
          detector_version,status,attempts,created_at)
       VALUES ($1,$2,'finding',$3,$4,$5,'luna-context-v1','pending',0,$6)`,
      [`finding:${findingId}`, ACME, findingId, left, right, now],
    );

    expect(await autopilot().runOnce()).toMatchObject({ claimed: 1, checked: 1 });
    const finding = await kernel.db.query(`SELECT status FROM conflict_scan_findings WHERE id=$1`, [findingId]);
    expect(finding.rows[0]).toMatchObject({ status: "dismissed" });
    const work = await kernel.db.query(`SELECT status FROM conflict_pair_recheck_queue WHERE source_id=$1`, [findingId]);
    expect(work.rows[0]).toMatchObject({ status: "done" });
  });

  it("creates a repair proposal for a false auto-resolution and restores both only after review", async () => {
    const kept = await seedFact({
      namespace: ACME, content: "Widget sales were 30 units.", source: "document",
      embedding: base(), eventTime: "2026-06-01T00:00:00.000Z",
    });
    const retired = await seedFact({
      namespace: ACME, content: "Widget sales were 14 units.", source: "document",
      embedding: similarVector(0.99), eventTime: "2026-06-02T00:00:00.000Z",
    });
    const findingId = ulid();
    const now = new Date().toISOString();
    await kernel.db.query(`UPDATE memory_objects SET supersedes=$2 WHERE id=$1`, [kept, retired]);
    await kernel.db.query(`UPDATE memory_objects SET t_valid_to=$2 WHERE id=$1`, [retired, now]);
    await kernel.db.query(
      `INSERT INTO conflict_scan_findings
         (id,target_namespace,left_memory_id,right_memory_id,fingerprint,detector_version,
          entity,category,reason,confidence,flags,status,row_version,origin,resolution,
          resolution_memory_id,resolved_by,resolved_at,auto_rule,first_seen_at,last_seen_at)
       VALUES ($1,$2,$3,$4,$5,'write-neighbor-llm-v1','Widget','product-info',
               'conflicting_quantity',0.99,'[]','auto_resolved',1,'write','keep-left',
               $3,'system',$6,'equal-trust-newest-wins',$6,$6)`,
      [findingId, ACME, kept, retired, `legacy-auto-${findingId}`, now],
    );
    await kernel.db.query(
      `INSERT INTO conflict_pair_recheck_queue
         (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
          detector_version,status,attempts,created_at)
       VALUES ($1,$2,'auto_resolution',$3,$4,$5,'luna-context-v1','pending',0,$6)`,
      [`auto:${findingId}`, ACME, findingId, kept, retired, now],
    );

    await autopilot().runOnce();
    const decision = (await kernel.conflictScans.listAutoDecisions(owner))
      .find((entry) => entry.id === findingId);
    expect(decision).toMatchObject({ repairProposed: true, repairClassification: "compatible_distinct" });
    expect((await factRow(retired))?.t_valid_to).not.toBeNull();

    await kernel.overturnConflictFinding(owner, findingId, decision!.rowVersion);
    expect((await factRow(kept))?.t_valid_to).toBeNull();
    expect((await factRow(kept))?.supersedes).toBeNull();
    expect((await factRow(retired))?.t_valid_to).toBeNull();
    const proposal = await kernel.db.query(
      `SELECT status FROM conflict_repair_proposals WHERE source_id=$1`, [findingId],
    );
    expect(proposal.rows[0]).toMatchObject({ status: "applied" });
  });
});
