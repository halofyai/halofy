/**
 * D37 trace isolation (composite PK (namespace, trace_id), migration v50).
 *
 * Caller trace hints are arbitrary strings, so two namespaces can use the
 * SAME hint. Every consumer — the query_traces upsert, the cost-lane usd
 * bump, the answer-outcome back-link, and the usage read model — must stay
 * per-namespace: no merge, no squat, no cross-tenant leak.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm (no LLM keys).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { Kernel } from "../src/kernel.js";
import { AnswerOutcomeService } from "../src/feedback/index.js";
import type { Identity, Role } from "../src/types.js";

const NSA = "iso/alpha";
const NSB = "iso/beta";
const AGENT = "iso-test";

let kernel: Kernel;
let outcomes: AnswerOutcomeService;
let knowledgeDir: string;
let root: Identity;
let memberA: Identity;
let memberB: Identity;

async function issue(namespace: string, actor: string, role: Role): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued identity did not resolve");
  return identity;
}

interface TraceRow {
  namespace: string;
  events: number;
  usd: number;
  outcome: string | null;
}

async function traceRows(traceId: string): Promise<TraceRow[]> {
  const res = await kernel.db.query(
    `SELECT namespace, events, usd, outcome FROM query_traces WHERE trace_id = $1 ORDER BY namespace`,
    [traceId],
  );
  return (res.rows as { namespace: string; events: unknown; usd: unknown; outcome: string | null }[])
    .map((row) => ({
      namespace: row.namespace,
      events: Number(row.events),
      usd: Number(row.usd),
      outcome: row.outcome,
    }));
}

async function eventCount(namespace: string, traceId: string): Promise<number> {
  const res = await kernel.db.query(
    `SELECT count(*) AS n FROM usage_events WHERE namespace = $1 AND trace_id = $2`,
    [namespace, traceId],
  );
  return Number((res.rows[0] as { n: unknown }).n);
}

describe("trace-id isolation across namespaces (D37 composite PK)", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-usage-iso-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    outcomes = new AnswerOutcomeService({ db: kernel.db, audit: kernel.audit });
    const first = await kernel.auth.issueKey("", "root", "owner");
    const resolved = await kernel.auth.resolve(first.plaintext);
    if (!resolved) throw new Error("root identity did not resolve");
    root = resolved;
    memberA = await issue(NSA, "member-a", "member");
    memberB = await issue(NSB, "member-b", "member");
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("the same caller traceId in two namespaces stays two rows; events and usd never merge", async () => {
    const traceId = "session-1";
    await kernel.memWrite(
      { scope: "user", content: "alpha zirconium coupling datasheet", hints: { verbatim: true } },
      memberA,
      AGENT,
    );
    await kernel.memWrite(
      { scope: "user", content: "beta vanadium coupling datasheet", hints: { verbatim: true } },
      memberB,
      AGENT,
    );

    // Two searches per namespace: the FIRST search's embed cost lands before
    // the trace row exists (no bump); the SECOND bumps its own row only.
    await kernel.memSearch({ query: "zirconium coupling" }, memberA, AGENT, { traceId });
    await kernel.memSearch({ query: "zirconium coupling" }, memberA, AGENT, { traceId });
    await kernel.memSearch({ query: "vanadium coupling" }, memberB, AGENT, { traceId });
    await kernel.memSearch({ query: "vanadium coupling" }, memberB, AGENT, { traceId });

    const rows = await traceRows(traceId);
    expect(rows.map((row) => row.namespace)).toEqual([NSA, NSB]);
    expect(rows[0]?.events).toBe(2);
    expect(rows[1]?.events).toBe(2);
    expect(await eventCount(NSA, traceId)).toBe(2);
    expect(await eventCount(NSB, traceId)).toBe(2);
    expect(rows[0]?.usd).toBeGreaterThan(0);
    expect(rows[1]?.usd).toBeGreaterThan(0);

    // Every cost row with the shared trace id belongs to its own namespace.
    const costs = await kernel.db.query(
      `SELECT DISTINCT namespace FROM cost_ledger WHERE trace_id = $1`,
      [traceId],
    );
    expect(costs.rows.map((row) => (row as { namespace: string }).namespace).sort())
      .toEqual([NSA, NSB]);

    // A stamped append in one namespace bumps only that namespace's row.
    const beforeA = rows[0]!.usd;
    const beforeB = rows[1]!.usd;
    await kernel.costLedger.append(NSA, "embed", 100, 0.5, {
      actor: memberA.actor,
      traceId,
    });
    const after = await traceRows(traceId);
    expect(after[0]!.usd).toBeCloseTo(beforeA + 0.5, 9);
    expect(after[1]!.usd).toBeCloseTo(beforeB, 9);
  });

  it("squatting: a pre-existing foreign trace row never absorbs another tenant's events/usd/outcome", async () => {
    const traceId = "squat-1";
    // NSB pre-creates the trace; NSA then uses the same hint.
    await kernel.memSearch({ query: "squatter seed query" }, memberB, AGENT, { traceId });
    const squatBefore = (await traceRows(traceId))[0]!;
    expect(squatBefore.namespace).toBe(NSB);
    expect(squatBefore.events).toBe(1);

    await kernel.memSearch({ query: "honest alpha query" }, memberA, AGENT, { traceId });
    await kernel.costLedger.append(NSA, "llm", 200, 0.25, {
      actor: memberA.actor,
      traceId,
    });
    await outcomes.record(memberA, {
      turnId: "t-squat-1",
      outcome: "answered",
      traceId,
    });

    const rows = await traceRows(traceId);
    expect(rows.map((row) => row.namespace)).toEqual([NSA, NSB]);
    // NSA's row carries its own event, usd bump, and outcome back-link.
    expect(rows[0]?.events).toBe(1);
    expect(rows[0]?.usd).toBeCloseTo(0.25, 9);
    expect(rows[0]?.outcome).toBe("answered");
    // NSB's squatted row is untouched by NSA's activity.
    expect(rows[1]?.events).toBe(1);
    expect(rows[1]?.usd).toBe(0);
    expect(rows[1]?.outcome).toBeNull();
  });

  it("usageQueryTrace disambiguates: own-namespace row first, events scoped to it", async () => {
    const traceId = "session-1"; // exists in BOTH namespaces from the first test
    const detailA = await kernel.usageQueryTrace(memberA, traceId);
    expect(detailA).not.toBeNull();
    expect(detailA?.trace.actor).toBe(memberA.actor);
    expect(detailA?.events).toHaveLength(2);
    expect(detailA?.events.every((event) => event.op === "search")).toBe(true);

    const detailB = await kernel.usageQueryTrace(memberB, traceId);
    expect(detailB?.trace.actor).toBe(memberB.actor);

    // The two views share the trace id but never the events.
    const idsA = new Set(detailA?.events.map((event) => event.id));
    for (const event of detailB?.events ?? []) expect(idsA.has(event.id)).toBe(false);

    // Root owner sees a collided id resolved to ONE row (most recent ts),
    // with events drawn from that row's namespace only.
    const detailRoot = await kernel.usageQueryTrace(root, traceId);
    expect(detailRoot).not.toBeNull();
    expect(detailRoot?.events.length).toBeGreaterThan(0);
  });

  it("the answer-outcome back-link lands on the caller's own trace row (composite PK)", async () => {
    const traceId = "session-1";
    await outcomes.record(memberB, {
      turnId: "t-iso-backlink",
      outcome: "weak",
      traceId,
    });
    const rows = await traceRows(traceId);
    expect(rows[0]?.outcome).toBeNull(); // NSA untouched
    expect(rows[1]?.outcome).toBe("weak"); // NSB linked

    // And the detail view surfaces the outcome for the right namespace.
    const detailB = await kernel.usageQueryTrace(memberB, traceId);
    expect(detailB?.outcome?.outcome).toBe("weak");
    const detailA = await kernel.usageQueryTrace(memberA, traceId);
    expect(detailA?.outcome).toBeNull();
  });
});
