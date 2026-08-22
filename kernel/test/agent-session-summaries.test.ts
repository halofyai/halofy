/**
 * Agent-session completion contract (CONTRACTS-CONFLICT-SCAN.md CS8-CS11).
 *
 * Tests the service boundary directly with the real kernel database and the
 * canonical kernel memWrite syscall injected as its only memory-write seam.
 * Raw turns are untrusted, ephemeral input; only verified summaries/claims may
 * reach that seam or durable storage.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { AgentSessionSummaryService } from "../src/agent-sessions/index.js";
import { Kernel } from "../src/kernel.js";
import type {
  Identity,
  MemWriteResult,
  WriteRequest,
  WriteResult,
} from "../src/index.js";

const NAMESPACE = "org/support";
const RAW_SENTINEL = "RAW-TRANSCRIPT-MUST-NEVER-PERSIST-7f96";
const SESSION_ID = "client-session-private-42";

let kernel: Kernel;
let agent: Identity;

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("session-summary writes must be synchronous");
  return result;
}

interface CapturedWrite {
  request: WriteRequest;
  identity: Identity;
}

function successfulService(): {
  service: AgentSessionSummaryService;
  writes: CapturedWrite[];
} {
  const writes: CapturedWrite[] = [];
  return {
    writes,
    service: new AgentSessionSummaryService({
      db: kernel.db,
      audit: kernel.audit,
      summarize: async () => ({
        summary: "A support session established the current refund window.",
        claims: [{
          content: "Refund requests are accepted for 30 days.",
          role: "user" as const,
        }],
      }),
      write: async (request, identity) => {
        writes.push({ request, identity });
        return sync(await kernel.memWrite(
          {
            scope: request.scope,
            content: request.content,
            session: request.session,
            hints: request.hints,
          },
          identity,
          "agent-session-summary-test",
        ));
      },
    }),
  };
}

function completionInput(): Record<string, unknown> {
  return {
    sessionId: SESSION_ID,
    startedAt: "2026-07-22T08:00:00.000Z",
    endedAt: "2026-07-22T08:30:00.000Z",
    turns: [
      { role: "user", content: `${RAW_SENTINEL}: what is our refund policy?` },
      { role: "assistant", content: `${RAW_SENTINEL}: I found a 30-day window.` },
    ],
  };
}

async function summaryRows(): Promise<Record<string, unknown>[]> {
  return (await kernel.db.query(
    `SELECT id, namespace, key_id, actor, session_hash, status,
            summary_memory_id, fact_count, failure_code, started_at, ended_at
       FROM agent_session_summaries
      WHERE namespace = $1
      ORDER BY created_at, id`,
    [NAMESPACE],
  )).rows as Record<string, unknown>[];
}

async function durableText(): Promise<string> {
  const [summaries, memories, audits] = await Promise.all([
    kernel.db.query(`SELECT * FROM agent_session_summaries WHERE namespace = $1`, [NAMESPACE]),
    kernel.db.query(
      `SELECT content, provenance FROM memory_objects WHERE namespace = $1 ORDER BY id`,
      [NAMESPACE],
    ),
    kernel.db.query(
      `SELECT purpose, detail FROM audit_log WHERE namespace = $1 ORDER BY seq`,
      [NAMESPACE],
    ),
  ]);
  return JSON.stringify({
    summaries: summaries.rows,
    memories: memories.rows,
    audits: audits.rows,
  });
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root identity failed to resolve");
  const badge = await kernel.auth.issueKey(NAMESPACE, "agent:support", "agent", root);
  const resolved = await kernel.auth.resolve(badge.plaintext);
  if (!resolved) throw new Error("agent identity failed to resolve");
  agent = resolved;
}, 120_000);

beforeEach(async () => {
  await kernel.db.query(`DELETE FROM agent_session_summaries WHERE namespace = $1`, [NAMESPACE]);
  await kernel.db.query(`DELETE FROM memory_objects WHERE namespace = $1`, [NAMESPACE]);
});

afterAll(async () => {
  await kernel.close();
});

describe("AgentSessionSummaryService.complete", () => {
  it("binds namespace, actor, and provenance to the authenticated agent badge", async () => {
    const { service, writes } = successfulService();
    const result = await service.complete(agent, completionInput());

    expect(result).toMatchObject({ status: "completed" });
    expect(writes.length).toBeGreaterThan(0);
    for (const write of writes) {
      expect(write.identity).toEqual(agent);
      expect(write.request).toMatchObject({
        namespace: NAMESPACE,
        actor: "agent:support",
        provenance: {
          source: "conversation",
        },
      });
      expect(write.request.provenance?.sourceId).toContain(agent.keyId);
      expect(write.request.session).toMatch(/^[0-9a-f]{64}$/);
      expect(write.request.session).not.toBe(SESSION_ID);
    }

    const rows = await summaryRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      namespace: NAMESPACE,
      key_id: agent.keyId,
      actor: "agent:support",
      status: "completed",
    });
    expect(String(rows[0].session_hash)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects caller-supplied identity fields instead of widening agent scope", async () => {
    const { service, writes } = successfulService();
    const forged = {
      ...completionInput(),
      namespace: "other-tenant",
      actor: "owner:other-tenant",
      keyId: "forged-key",
    };

    await expect(service.complete(agent, forged)).rejects.toThrow(/identity|namespace|actor|key/i);
    expect(writes).toHaveLength(0);
    expect(await summaryRows()).toHaveLength(0);
  });

  it("deduplicates retries by authenticated key and session hash", async () => {
    const { service, writes } = successfulService();
    const first = await service.complete(agent, completionInput());
    const memoryCountAfterFirst = Number((await kernel.db.query(
      `SELECT count(*) AS n FROM memory_objects WHERE namespace = $1`,
      [NAMESPACE],
    )).rows[0].n);

    const second = await service.complete(agent, completionInput());
    const memoryCountAfterSecond = Number((await kernel.db.query(
      `SELECT count(*) AS n FROM memory_objects WHERE namespace = $1`,
      [NAMESPACE],
    )).rows[0].n);

    expect(second.id).toBe(first.id);
    expect(await summaryRows()).toHaveLength(1);
    expect(memoryCountAfterSecond).toBe(memoryCountAfterFirst);
    expect(writes.length).toBe(memoryCountAfterFirst);
  });

  it("persists summaries and claims without retaining raw turns or client session ids", async () => {
    const { service } = successfulService();
    await service.complete(agent, completionInput());

    const stored = await durableText();
    expect(stored).toContain("current refund window");
    expect(stored).toContain("30 days");
    expect(stored).not.toContain(RAW_SENTINEL);
    expect(stored).not.toContain(SESSION_ID);
  });

  it("records a content-free failure and stores zero facts when summary generation fails", async () => {
    const writes: CapturedWrite[] = [];
    const service = new AgentSessionSummaryService({
      db: kernel.db,
      audit: kernel.audit,
      summarize: async () => {
        throw new Error(`${RAW_SENTINEL}: provider unavailable`);
      },
      write: async (request, identity) => {
        writes.push({ request, identity });
        throw new Error("write must not run after summary failure");
      },
    });

    const result = await service.complete(agent, completionInput());

    expect(result).toMatchObject({ status: "failed" });
    expect(writes).toHaveLength(0);
    expect(Number((await kernel.db.query(
      `SELECT count(*) AS n FROM memory_objects WHERE namespace = $1`,
      [NAMESPACE],
    )).rows[0].n)).toBe(0);
    const rows = await summaryRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "failed" });
    expect(rows[0].failure_code).toBeTruthy();
    expect(await durableText()).not.toContain(RAW_SENTINEL);
  });

  it("redacts secrets and personal data before the summarizer sees raw turns", async () => {
    let outbound = "";
    const service = new AgentSessionSummaryService({
      db: kernel.db,
      audit: kernel.audit,
      summarize: async (turns) => {
        outbound = JSON.stringify(turns);
        return {
          summary: "The refund discussion confirmed a 30 day window.",
          claims: [],
        };
      },
      write: async (request, identity) => sync(await kernel.memWrite(
        { scope: request.scope, content: request.content, session: request.session, hints: request.hints },
        identity,
        "agent-session-redaction-test",
      )),
    });
    const input = completionInput();
    input.turns = [
      { role: "user", content: "Refund window is 30 days; key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 and SSN 123-45-6789." },
    ];
    const result = await service.complete(agent, input);

    expect(result.status).toBe("completed");
    expect(outbound).not.toContain("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    expect(outbound).not.toContain("123-45-6789");
    expect(outbound).toMatch(/REDACTED/);
  });

  it("rejects unsupported model claims before any canonical memory write", async () => {
    const writes: CapturedWrite[] = [];
    const input = completionInput();
    input.sessionId = "unsupported-claim-session";
    const service = new AgentSessionSummaryService({
      db: kernel.db,
      audit: kernel.audit,
      summarize: async () => ({
        summary: "Invoices must be paid within 90 business days.",
        claims: [{ content: "All invoices use a 90 day term.", role: "assistant" }],
      }),
      write: async (request, identity) => {
        writes.push({ request, identity });
        throw new Error("unsupported claims must not reach write");
      },
    });

    const result = await service.complete(agent, input);
    expect(result.status).toBe("failed");
    expect(writes).toHaveLength(0);
  });
});
