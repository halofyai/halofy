/**
 * Usage analytics / query traction (D36–D39) — write-side core.
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm (no LLM keys → the D39
 * summarizer dep is never wired, so verbatim summaries stand).
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { promises as fs } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";

import { Kernel } from "../src/kernel.js";
import { AuthzError } from "../src/auth/index.js";
import { AgentConnectionGrantStore } from "../src/gateway/store.js";
import type { Identity, Role, WriteResult } from "../src/types.js";
import type { MemWriteResult } from "../src/syscalls/index.js";
import { BASELINE_DRIVER_NAME } from "../src/driver/index.js";
import { MIGRATIONS, splitStatements } from "../src/db/migrations.js";

const NS = "usage-events";
const AGENT = "usage-events-test";
const ULID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let member: Identity;

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(namespace: string, actor: string, role: Role): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued identity did not resolve");
  return identity;
}

interface UsageRow {
  audit_seq: number | string;
  trace_id: string;
  namespace: string;
  actor: string;
  principal: string;
  caller_class: string;
  op: string;
  tool: string | null;
  result: string;
  latency_ms: number;
  tokens: number;
  returned: number;
  driver: string | null;
  source_tier: string | null;
  top_score: number | null;
}

async function usageRows(where: string, params: unknown[]): Promise<UsageRow[]> {
  const res = await kernel.db.query(
    `SELECT audit_seq, trace_id, namespace, actor, principal, caller_class, op, tool,
            result, latency_ms, tokens, returned, driver, source_tier, top_score
       FROM usage_events WHERE ${where} ORDER BY ts, id`,
    params,
  );
  return res.rows as unknown as UsageRow[];
}

async function latestAuditSeq(op: string, result: string): Promise<number> {
  const res = await kernel.db.query(
    `SELECT seq FROM audit_log WHERE namespace = $1 AND op = $2 AND result = $3
       ORDER BY seq DESC LIMIT 1`,
    [NS, op, result],
  );
  expect(res.rows).toHaveLength(1);
  return Number((res.rows[0] as { seq: unknown }).seq);
}

async function writeCanary(content: string): Promise<string> {
  const written = sync(await kernel.memWrite(
    { scope: "user", content, hints: { verbatim: true } },
    member,
    AGENT,
  ));
  expect(written.stored).toHaveLength(1);
  return written.stored[0]!.id;
}

describe("usage events (D36–D39)", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-usage-events-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    const first = await kernel.auth.issueKey("", "root", "owner");
    const resolved = await kernel.auth.resolve(first.plaintext);
    if (!resolved) throw new Error("root identity did not resolve");
    root = resolved;
    member = await issue(NS, "member", "member");
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("migration v48 creates the tables with RLS and the cost columns", async () => {
    const migration = MIGRATIONS.find((m) => m.version === 48);
    expect(migration?.name).toBe("usage-events-traces");

    const rls = await kernel.db.query(
      `SELECT relname, relrowsecurity FROM pg_class
        WHERE relname IN ('usage_events', 'query_traces') ORDER BY relname`,
    );
    expect(rls.rows).toEqual([
      { relname: "query_traces", relrowsecurity: true },
      { relname: "usage_events", relrowsecurity: true },
    ]);

    const costCols = await kernel.db.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'cost_ledger' AND column_name IN ('actor', 'trace_id')
        ORDER BY column_name`,
    );
    expect(costCols.rows.map((r) => (r as { column_name: string }).column_name))
      .toEqual(["actor", "trace_id"]);

    const outcomeCols = await kernel.db.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'answer_outcomes' AND column_name = 'trace_id'`,
    );
    expect(outcomeCols.rows).toHaveLength(1);
  });

  it("read/search/fault/assemble each write exactly one usage row FK'd to their audit row", async () => {
    const canary = "quartz harmonic resonator calibration procedure";
    const id = await writeCanary(canary);

    // -- read (hit) -----------------------------------------------------------
    const read = await kernel.memRead({ id }, member, AGENT);
    expect(read.found).toBe(true);
    let rows = await usageRows("op = $1 AND namespace = $2", ["read", NS]);
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.audit_seq)).toBe(await latestAuditSeq("read", "ok"));
    expect(rows[0]).toMatchObject({
      namespace: NS,
      actor: member.actor,
      principal: "human",
      caller_class: "unclassified",
      tool: "kernel",
      result: "ok",
      tokens: 0,
      returned: 1,
      source_tier: "index",
    });
    expect(rows[0]!.trace_id).toMatch(ULID_PATTERN);

    // -- search ---------------------------------------------------------------
    const refs = await kernel.memSearch({ query: canary }, member, AGENT);
    expect(refs.length).toBeGreaterThan(0);
    const expectedTokens = refs.reduce((sum, r) => sum + r.tokenEstimate, 0);
    rows = await usageRows("op = $1 AND namespace = $2", ["search", NS]);
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.audit_seq)).toBe(await latestAuditSeq("search", "ok"));
    expect(rows[0]).toMatchObject({
      result: "ok",
      tokens: expectedTokens,
      returned: refs.length,
      driver: BASELINE_DRIVER_NAME,
      source_tier: "index",
    });
    expect(rows[0]!.top_score).toBeCloseTo(refs[0]!.score, 6);

    // -- fault ----------------------------------------------------------------
    const fault = await kernel.memFault({ query: canary, live: "off" }, member, AGENT);
    expect(fault.hit).toBe(true);
    const injectedTokens = fault.injected.reduce((sum, r) => sum + r.tokenEstimate, 0);
    rows = await usageRows("op = $1 AND namespace = $2 AND tool = $3", ["fault", NS, "kernel"]);
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.audit_seq)).toBe(await latestAuditSeq("fault", "ok"));
    expect(rows[0]).toMatchObject({
      result: "ok",
      tokens: injectedTokens,
      returned: fault.injected.length,
      driver: BASELINE_DRIVER_NAME,
      source_tier: "warm",
    });

    // -- assemble ---------------------------------------------------------------
    const ws = await kernel.memAssemble({}, member, AGENT);
    rows = await usageRows("op = $1 AND namespace = $2", ["assemble", NS]);
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.audit_seq)).toBe(await latestAuditSeq("assemble", "ok"));
    expect(rows[0]).toMatchObject({
      result: "ok",
      tokens: ws.totalTokens,
      returned: ws.blocks.length,
    });
  });

  it("groups a caller-supplied traceId into one query_traces row; no ctx mints per call", async () => {
    const traceId = "agent-turn-0001.search";
    const q1 = "resonator calibration first pass";
    const q2 = "resonator calibration second pass";
    await kernel.memSearch({ query: q1 }, member, AGENT, { traceId, tool: "test" });
    await kernel.memSearch({ query: q2 }, member, AGENT, { traceId, tool: "test" });

    const events = await usageRows("trace_id = $1", [traceId]);
    expect(events).toHaveLength(2);
    expect(events.every((row) => row.tool === "test")).toBe(true);

    const traces = await kernel.db.query(
      `SELECT events, latency_ms, tokens, query_sha256, query_summary
         FROM query_traces WHERE trace_id = $1`,
      [traceId],
    );
    expect(traces.rows).toHaveLength(1);
    const trace = traces.rows[0] as {
      events: number;
      latency_ms: number;
      tokens: number;
      query_sha256: string | null;
      query_summary: string | null;
    };
    expect(trace.events).toBe(2);
    expect(trace.latency_ms).toBe(events.reduce((sum, row) => sum + Number(row.latency_ms), 0));
    expect(trace.tokens).toBe(events.reduce((sum, row) => sum + row.tokens, 0));
    // D39: the FIRST search's verbatim query sticks (COALESCE), hashed + truncated.
    expect(trace.query_sha256).toBe(createHash("sha256").update(q1).digest("hex"));
    expect(trace.query_summary).toBe(q1.slice(0, 200));

    // Without ctx each call mints its own trace.
    await kernel.memSearch({ query: q1 }, member, AGENT);
    await kernel.memSearch({ query: q2 }, member, AGENT);
    const minted = await usageRows("op = $1 AND namespace = $2 AND trace_id <> $3", ["search", NS, traceId]);
    expect(minted.length).toBeGreaterThanOrEqual(2);
    const traceIds = new Set(minted.map((row) => row.trace_id));
    expect(traceIds.size).toBe(minted.length);
    for (const id of traceIds) expect(id).toMatch(ULID_PATTERN);
  });

  it("does not persist Assistant prompt text in audit or query analytics", async () => {
    const traceId = "assistant-sensitive-trace";
    const turnId = "01JASSISTANTSENSITIVETURN01";
    const query = "confidential acquisition target and employee medical note";
    const summarizer = vi.fn(async () => "sensitive summary");
    const deps = (kernel as unknown as {
      deps: { traceSummarizer?: (text: string, namespace: string) => Promise<string> };
    }).deps;
    const previousSummarizer = deps.traceSummarizer;
    deps.traceSummarizer = summarizer;

    try {
      await kernel.memSearch(
        { query },
        member,
        AGENT,
        { traceId, tool: "halo-assistant", sensitiveTurnId: turnId },
      );
      await new Promise((resolve) => setTimeout(resolve, 0));
    } finally {
      deps.traceSummarizer = previousSummarizer;
    }

    expect(summarizer).not.toHaveBeenCalled();

    const traces = await kernel.db.query(
      `SELECT query_sha256, query_summary FROM query_traces
        WHERE namespace = $1 AND trace_id = $2`,
      [NS, traceId],
    );
    expect(traces.rows).toHaveLength(1);
    expect(traces.rows[0]).toMatchObject({ query_sha256: null, query_summary: null });

    const audit = await kernel.db.query(
      `SELECT purpose FROM audit_log
        WHERE namespace = $1 AND actor = $2 AND op = 'search'
        ORDER BY seq DESC LIMIT 1`,
      [NS, member.actor],
    );
    expect(audit.rows).toHaveLength(1);
    expect((audit.rows[0] as { purpose: string }).purpose).toBe(`assistant-turn:${turnId}`);
    expect(JSON.stringify({ traces: traces.rows, audit: audit.rows })).not.toContain(query);
  });

  it("replaces a malformed caller traceId with a minted ULID", async () => {
    await kernel.memSearch(
      { query: "resonator calibration malformed trace" },
      member,
      AGENT,
      { traceId: "bad trace!!", tool: "test" },
    );
    const res = await kernel.db.query(
      `SELECT trace_id FROM usage_events WHERE op = 'search' AND namespace = $1
         ORDER BY ts DESC, id DESC LIMIT 1`,
      [NS],
    );
    const traceId = (res.rows[0] as { trace_id: string }).trace_id;
    expect(traceId).not.toBe("bad trace!!");
    expect(traceId).toMatch(ULID_PATTERN);
  });

  it("keeps the verbatim summary without LLM keys (no D39 upgrade fires)", async () => {
    const query = `resonator calibration ${"verbatim ".repeat(40)}tail`;
    const traceId = "agent-turn-verbatim";
    await kernel.memSearch({ query }, member, AGENT, { traceId });
    // Give a hypothetical fire-and-forget upgrader a beat to (not) run.
    await new Promise((resolve) => setTimeout(resolve, 50));
    const res = await kernel.db.query(
      `SELECT query_sha256, query_summary FROM query_traces WHERE trace_id = $1`,
      [traceId],
    );
    expect(res.rows).toHaveLength(1);
    const row = res.rows[0] as { query_sha256: string; query_summary: string };
    expect(row.query_sha256).toBe(createHash("sha256").update(query).digest("hex"));
    expect(row.query_summary).toBe(query.slice(0, 200));
    expect(row.query_summary).toHaveLength(200);
  });

  it("keeps the audit hash chain intact after instrumented syscalls", async () => {
    const result = await kernel.audit.verifyChain();
    expect(result.ok).toBe(true);
    expect(result.checked).toBeGreaterThan(0);
  });

  it("an agent key without the operation grant → denied audit row + usage row", async () => {
    const agent = await issue(NS, "grant-denied-agent", "agent");
    await kernel.db.query(
      `INSERT INTO sources (id, namespace, kind, config, created_at)
       VALUES ('conn-facade-denial', $1, 'postgres', '{}', now())
       ON CONFLICT (id) DO NOTHING`,
      [NS],
    );
    // Opt the badge into grants WITHOUT the search operation (fail-closed).
    await new AgentConnectionGrantStore(kernel.db).create(
      {
        id: "grant-facade-denial",
        keyId: agent.keyId,
        namespace: NS,
        connectorId: "conn-facade-denial",
        allowedOperations: ["read"],
        allowedSourceRefs: ["customers"],
        allowedFields: { customers: ["id"] },
        allowedPurposes: ["support"],
        maxSensitivity: "internal",
        maxRows: 10,
        maxBytes: 1024,
        policyVersion: 1,
        status: "active",
        expiresAt: null,
        oversight: {
          maxRequestsPerMinute: 60,
          usageAlertThreshold: 100,
          deniedAlertThreshold: 1,
          recipientRoles: ["owner", "admin"],
          accessRequests: "allowed",
          approvalTtlSeconds: 3600,
        },
      },
      { namespace: "", role: "owner" },
    );

    await expect(
      kernel.memSearch({ query: "facade denial canary" }, agent, AGENT, {
        traceId: "facade-denied-trace",
        tool: "test",
      }),
    ).rejects.toBeInstanceOf(AuthzError);

    const audit = await kernel.db.query(
      `SELECT seq FROM audit_log
        WHERE namespace = $1 AND op = 'search' AND result = 'denied'
        ORDER BY seq DESC LIMIT 1`,
      [NS],
    );
    expect(audit.rows).toHaveLength(1);
    const seq = Number((audit.rows[0] as { seq: unknown }).seq);

    const rows = await usageRows("audit_seq = $1", [seq]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      namespace: NS,
      actor: agent.actor,
      principal: "agent",
      op: "search",
      tool: "test",
      result: "denied",
      tokens: 0,
      returned: 0,
      trace_id: "facade-denied-trace",
    });
  });

  it("brownout: a failed usage insert never fails the syscall or its audit row", async () => {
    await kernel.db.query(`DROP TABLE usage_events`);
    try {
      const canary = "obsidian lattice thermal brownout canary";
      const id = await writeCanary(canary);
      const read = await kernel.memRead({ id }, member, AGENT);
      expect(read.found).toBe(true);

      // The D4 audit row exists even though every usage insert failed.
      const audit = await kernel.db.query(
        `SELECT seq FROM audit_log WHERE namespace = $1 AND op = 'read' AND result = 'ok'
           ORDER BY seq DESC LIMIT 1`,
        [NS],
      );
      expect(audit.rows).toHaveLength(1);
      // query_traces writes ride the same savepoint, so they brown out too —
      // no crash, no partial state, and the chain still verifies.
      expect((await kernel.audit.verifyChain()).ok).toBe(true);
    } finally {
      // Restore the table for any later suites sharing this database shape.
      const v48 = MIGRATIONS.find((m) => m.version === 48);
      if (!v48) throw new Error("migration v48 missing");
      for (const statement of splitStatements(v48.sql(256))) {
        await kernel.db.query(statement);
      }
    }
  });
});
