/**
 * Module F executable spec — full end-to-end loop through the Kernel facade.
 *
 * Hermetic: in-memory PGlite (pgliteDataDir: ""), HashEmbedder (openaiApiKey:
 * ""), StubLlm (anthropicApiKey: ""), local knowledge dir. Zero network.
 *
 * M1 (D9): syscalls take a resolved Identity — namespace/actor come from API
 * keys issued in setup (bootstrap owner key first, then per-namespace keys).
 * The cross-namespace deny cases now use SEPARATE KEYS, which is a stronger
 * assertion than the old caller-asserted-namespace version.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomBytes } from "node:crypto";
import { Kernel } from "../src/kernel.js";
import type { Identity, Role, WriteResult } from "../src/types.js";
import type { MemWriteResult } from "../src/syscalls/index.js";

// Portable: derive from this file's location (works on CI and any machine).
let knowledgeDir: string;

const NS_ORG = "org";
const NS_AGENT = "org/support/agent1";
const NS_FOREIGN = "org/sales";
const ACTOR = "tester";
const AGENT = "vitest";

let kernel: Kernel;
let storedId: string;
let orgFactId: string;

/** Platform root owner used for cross-tenant administration. */
let idRoot: Identity;
/** Owner identity at the tenant root. */
let idOrg: Identity;
/** Member identity bound to the agent namespace. */
let idAgent: Identity;
/** Member identity bound to a sibling namespace (foreign to idAgent). */
let idForeign: Identity;
let idOrg1: Identity;
let idOrgX1Team: Identity;
let idOrg1Team: Identity;

/** All writes in this file are synchronous — narrow the union. */
function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issueIdentity(
  ns: string,
  actor: string,
  role: Role,
  caller?: Identity,
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(ns, actor, role, caller ?? null);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued key failed to resolve");
  return identity;
}

describe("kernel syscalls end-to-end", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-syscalls-knowledge-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "", // in-memory PGlite
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "", // StubLlm - deterministic, no network
      openaiApiKey: "", // HashEmbedder - deterministic, dim 256
      embedDim: 256,
    });

    // Bootstrap: api_keys is empty → create the platform root owner first.
    idRoot = await issueIdentity("", "platform-owner", "owner");
    for (const concept of [
      { path: "concepts/refund.okf.enc", title: "Refund policy", body: "Refund escalation requires support lead approval." },
      { path: "concepts/escalation.okf.enc", title: "Severity escalation matrix", body: "Severity-1 incidents and allergy incidents page Tier 2 immediately." },
      { path: "concepts/platforms.okf.enc", title: "Ordering platforms", body: "DoorDash, UberEats, and Grubhub integration guidance." },
    ]) {
      await kernel.createPrivateConcept({
        ...concept,
        namespace: NS_ORG,
        type: "policy",
        description: "Hermetic syscall fixture",
        tags: ["support"],
      }, idRoot);
    }
    idOrg = await issueIdentity(NS_ORG, ACTOR, "owner", idRoot);
    // Tenant-local keys may be issued by the tenant owner.
    idAgent = await issueIdentity(NS_AGENT, ACTOR, "agent", idOrg);
    idForeign = await issueIdentity(NS_FOREIGN, ACTOR, "member", idOrg);
    // Sibling-tenant wildcard fixtures require platform-root authority.
    idOrg1 = await issueIdentity("org_1", ACTOR, "member", idRoot);
    idOrgX1Team = await issueIdentity("orgX1/team", ACTOR, "member", idRoot);
    idOrg1Team = await issueIdentity("org_1/team", ACTOR, "member", idRoot);
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("boots with default per-namespace policies", async () => {
    const policy = await kernel.getPolicy(NS_AGENT);
    expect(policy.namespace).toBe(NS_AGENT);
    expect(policy.tokenBudget).toBe(3000);
    expect(policy.ttlDefaultsSeconds.org).toBeNull();
    expect(policy.ttlDefaultsSeconds.team).toBeNull();
    expect(policy.ttlDefaultsSeconds.user).toBe(90 * 24 * 60 * 60);
    expect(policy.ttlDefaultsSeconds.assistant).toBe(90 * 24 * 60 * 60);
    expect(policy.pinnedConcepts).toEqual([]);
    expect(policy.verifierEnabled).toBe(true);
    // Cached: repeat lookup returns the same effective policy. (M1: the
    // DB-backed PolicyStore returns defensive clones, so identity (`toBe`)
    // is no longer the caching contract — value equality is.)
    expect(await kernel.getPolicy(NS_AGENT)).toEqual(policy);
  });

  it("memWrite stores a verbatim fact", async () => {
    const result = sync(
      await kernel.memWrite(
        {
          scope: "user",
          content:
            "Customer Priya Sharma prefers email over phone for refund status updates.",
          hints: { verbatim: true, type: "preference" },
        },
        idAgent,
        AGENT,
      ),
    );
    expect(result.stored.length).toBeGreaterThanOrEqual(1);
    storedId = result.stored[0]!.id;
    expect(storedId).toBeTruthy();
    expect(result.stored[0]!.namespace).toBe(NS_AGENT);
    expect(result.stored[0]!.tier).toBe("L2");
  });

  it("memSearch finds the stored fact within token budget", async () => {
    const refs = await kernel.memSearch(
      { query: "Priya email refund updates", k: 8 },
      idAgent,
      AGENT,
    );
    expect(refs.length).toBeGreaterThan(0);
    expect(
      refs.some((r) => r.id === storedId || r.content.includes("Priya")),
    ).toBe(true);
    const totalTokens = refs.reduce((sum, r) => sum + r.tokenEstimate, 0);
    expect(totalTokens).toBeLessThanOrEqual(2000);
  });

  it("memRead returns the fact in its own namespace", async () => {
    const res = await kernel.memRead({ id: storedId }, idAgent, AGENT);
    expect(res.found).toBe(true);
    expect(res.denied).toBe(false);
    expect(res.memory?.id).toBe(storedId);
    expect(res.memory?.content).toContain("Priya");
  });

  it("memRead denies foreign-namespace access and audits result='denied'", async () => {
    // Stronger than v0.1: the foreign caller holds a DIFFERENT KEY bound to
    // halo/sales — it cannot assert any other namespace at all.
    const res = await kernel.memRead({ id: storedId }, idForeign, AGENT);
    // Caller-facing result is indistinguishable from a miss — no existence
    // oracle for rows in namespaces the caller cannot see. The audit trail
    // (checked below) still records 'denied' distinctly.
    expect(res.found).toBe(false);
    expect(res.denied).toBe(false);
    expect(res.memory).toBeNull();

    const missRes = await kernel.memRead(
      { id: "01JUNKNONEXISTENTULID0000X" },
      idForeign,
      AGENT,
    );
    // Exists-but-forbidden and does-not-exist look identical to the caller.
    expect(missRes).toEqual(res);

    const { rows } = await kernel.db.query(
      "SELECT result FROM audit_log WHERE op = 'read' AND namespace = $1",
      [NS_FOREIGN],
    );
    expect(
      (rows as Array<{ result: string }>).some((r) => r.result === "denied"),
    ).toBe(true);
  });

  it("ancestor-namespace memories flow down to descendants", async () => {
    const write = sync(
      await kernel.memWrite(
        {
          scope: "org",
          content: "HaloMem org rule: memory is a managed resource, not a bag of strings.",
          hints: { verbatim: true, type: "fact" },
        },
        idOrg, // key bound to "halo" - writes land in the caller's own namespace
        AGENT,
      ),
    );
    orgFactId = write.stored[0]!.id;
    expect(write.stored[0]!.namespace).toBe(NS_ORG);

    const res = await kernel.memRead({ id: orgFactId }, idAgent, AGENT); // descendant of "halo"
    expect(res.found).toBe(true);
    expect(res.denied).toBe(false);
  });

  it("a child-namespace write never supersedes or dedupes an ancestor fact", async () => {
    // Similar-but-conflicting variant of the org fact, written from the
    // agent's namespace (cosine lands in the supersede band, same scope).
    const w = sync(
      await kernel.memWrite(
        {
          scope: "org",
          content:
            "HaloMem org rule: memory is a managed resource, not a pile of chairs.",
          hints: { verbatim: true, type: "fact" },
        },
        idAgent,
        AGENT,
      ),
    );
    expect(w.superseded).toEqual([]);
    expect(w.stored).toHaveLength(1);
    expect(w.stored[0]!.namespace).toBe(NS_AGENT);
    expect(w.stored[0]!.supersedes).toBeNull();

    // The org-level fact remains currently valid and visible to siblings.
    const sibling = await kernel.memRead({ id: orgFactId }, idForeign, AGENT); // another descendant of "halo"
    expect(sibling.found).toBe(true);
    expect(sibling.memory?.tValidTo).toBeNull();
  });

  it("agent audit attribution is badge-bound and ignores a transport label", async () => {
    await kernel.memStats({}, idAgent, "caller-supplied-transport-label");
    const latest = await kernel.db.query(
      `SELECT agent_id FROM audit_log
       WHERE op = 'stats' AND namespace = $1
       ORDER BY seq DESC LIMIT 1`,
      [NS_AGENT],
    );
    expect(latest.rows[0]?.agent_id).toBe(idAgent.keyId);
  });

  it("preserves supplied execution attribution for non-agent identities", async () => {
    await kernel.memStats({}, idOrg, "internal-control-room");
    const latest = await kernel.db.query(
      `SELECT agent_id FROM audit_log
       WHERE op = 'stats' AND namespace = $1
       ORDER BY seq DESC LIMIT 1`,
      [NS_ORG],
    );
    expect(latest.rows[0]?.agent_id).toBe("internal-control-room");
  });

  it("write-path audit rows carry the badge-bound agent id (D4 attribution)", async () => {
    const { rows } = await kernel.db.query(
      "SELECT agent_id FROM audit_log WHERE op = 'write' AND namespace = $1",
      [NS_AGENT],
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows as Array<{ agent_id: string }>) {
      expect(r.agent_id).toBe(idAgent.keyId);
    }
  });

  it("memFault on a knowledge question hits L3", async () => {
    const res = await kernel.memFault(
      { query: "What is the escalation matrix for severity-1 incidents?" },
      idAgent,
      AGENT,
    );
    expect(res.hit).toBe(true);
    expect(res.source).toBe("L3");
    expect(res.injected.length).toBeGreaterThan(0);
    expect(res.injected[0]!.tier).toBe("L3");
  });

  it("memFault reports a miss for an unrelated query (L3 floor is meaningful)", async () => {
    const res = await kernel.memFault({ query: "zzzz qqqq wwww vvvv" }, idAgent, AGENT);
    expect(res.hit).toBe(false);
    expect(res.source).toBeNull();
    expect(res.injected).toEqual([]);

    const { rows } = await kernel.db.query(
      "SELECT result FROM audit_log WHERE op = 'fault' AND namespace = $1",
      [NS_AGENT],
    );
    expect(
      (rows as Array<{ result: string }>).some((r) => r.result === "miss"),
    ).toBe(true);
  });

  it("memAssemble returns a working set within the policy budget", async () => {
    const ws = await kernel.memAssemble(
      { taskHint: "handle a refund escalation" },
      idAgent,
      AGENT,
    );
    expect(ws.namespace).toBe(NS_AGENT);
    expect(ws.budget).toBe((await kernel.getPolicy(NS_AGENT)).tokenBudget);
    expect(ws.totalTokens).toBeLessThanOrEqual(ws.budget);
  });

  it("memStats reflects counts, fault hit rate, and top-accessed", async () => {
    const stats = await kernel.memStats({}, idAgent, AGENT);
    expect(stats.namespace).toBe(NS_AGENT);
    // Priya fact (own ns) + org fact (ancestor) are both visible.
    expect(stats.l2Count).toBeGreaterThanOrEqual(2);
    // The encrypted temp knowledge repository has exactly 3 private concepts.
    expect(stats.l3ConceptCount).toBe(3);
    expect(stats.faultCount).toBeGreaterThanOrEqual(1);
    expect(stats.faultHitRate).toBeGreaterThan(0);
    expect(stats.auditEventCount).toBeGreaterThanOrEqual(5);
    expect(stats.topAccessed.length).toBeGreaterThan(0);
    expect(stats.topAccessed.some((t) => t.id === storedId)).toBe(true);
  });

  it("memStats excludes TTL-expired facts from counts and hottest facts", async () => {
    const before = await kernel.memStats({}, idAgent, AGENT);
    const written = sync(
      await kernel.memWrite(
        {
          scope: "user",
          content: "temporary stats fact that must expire",
          hints: { verbatim: true },
        },
        idAgent,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    await kernel.db.query(
      `UPDATE memory_objects
       SET ttl_seconds = 1,
           assertion_time = CURRENT_TIMESTAMP - INTERVAL '2 seconds'
       WHERE id = $1`,
      [id],
    );

    const after = await kernel.memStats({}, idAgent, AGENT);
    expect(after.l2Count).toBe(before.l2Count);
    expect(after.topAccessed.some((fact) => fact.id === id)).toBe(false);
  });

  it("memStats never treats '_'/'%' in stored namespaces as LIKE wildcards", async () => {
    sync(
      await kernel.memWrite(
        {
          scope: "team",
          content: "SECRET fact belonging to org_1 only",
          hints: { verbatim: true, type: "fact" },
        },
        idOrg1,
        AGENT,
      ),
    );

    // 'orgX1/team' LIKE 'org_1/%' is true in SQL ('_' matches 'X') but this
    // caller is NOT a descendant of 'org_1' — nothing may leak. The caller
    // holds its own key bound to orgX1/team.
    const lookalike = await kernel.memStats({}, idOrgX1Team, AGENT);
    expect(lookalike.l2Count).toBe(0);
    expect(lookalike.topAccessed).toEqual([]);

    // The genuine descendant still sees the fact.
    const descendant = await kernel.memStats({}, idOrg1Team, AGENT);
    expect(descendant.l2Count).toBe(1);
    expect(
      descendant.topAccessed.some((t) => t.content.includes("SECRET")),
    ).toBe(true);
  });

  it("wrote an audit row for every syscall op (D4)", async () => {
    const { rows } = await kernel.db.query(
      "SELECT DISTINCT op FROM audit_log WHERE namespace = $1",
      [NS_AGENT],
    );
    const ops = (rows as Array<{ op: string }>).map((r) => r.op);
    for (const op of ["write", "search", "read", "fault", "assemble", "stats"]) {
      expect(ops, `missing audit row for op=${op}`).toContain(op);
    }
  });
});
