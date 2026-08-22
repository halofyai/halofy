/**
 * M1 exit-criteria adversarial suite (CONTRACTS-M1.md).
 *
 * Attacks the exit criteria end-to-end on a real Kernel (in-memory PGlite,
 * HashEmbedder, StubLlm) through BOTH the Identity syscall layer and a live
 * HTTP server (module B transport + integrator adapter) on an ephemeral port:
 *
 *   1. No request path reaches MemoryIndex without a resolved Identity
 *      (missing/garbage/revoked bearer → 401 before any syscall runs).
 *   2. Key bound to org/team-a cannot read/search/stats/write into
 *      org/team-b — by id, via search, via stats, via write.
 *   3. Supersede is atomic under injected mid-transaction failure
 *      (monkey-patched MemoryIndex.prototype inside Db.transaction).
 *   4. Auditor cannot write (denied + audited); member cannot touch admin
 *      routes; revoked key → 401 instantly.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { MemoryIndex } from "../src/index/index.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { AuthzError } from "../src/auth/index.js";
import type { Identity, Role, WriteResult } from "../src/types.js";
import type { MemWriteResult } from "../src/syscalls/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KNOWLEDGE_DIR = path.resolve(__dirname, "..", "knowledge");

const NS_A = "org/team-a";
const NS_B = "org/team-b";

let kernel: Kernel;
let server: HaloHttpServer;
let baseUrl: string;

let ownerKey: string;
let keyA: string;
let keyB: string;
let auditorKey: string;

let idOwner: Identity;
let idA: Identity;
let idB: Identity;
let idAuditor: Identity;

/** B's private fact — the target of every cross-namespace attack. */
let bFactId: string;
const B_SECRET = "TEAMB-ZEBRA payroll cadence is biweekly on Fridays";

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(
  ns: string,
  actor: string,
  role: Role,
  caller?: Identity,
): Promise<{ key: string; identity: Identity }> {
  const { plaintext } = await kernel.auth.issueKey(ns, actor, role, caller ?? null);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued key did not resolve");
  return { key: plaintext, identity };
}

async function post(
  route: string,
  body: unknown,
  key?: string,
): Promise<{ status: number; json: any }> {
  const res = await fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(key ? { authorization: `Bearer ${key}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

async function get(route: string, key?: string): Promise<{ status: number; json: any }> {
  const res = await fetch(`${baseUrl}${route}`, {
    headers: key ? { authorization: `Bearer ${key}` } : {},
  });
  return { status: res.status, json: await res.json() };
}

describe("M1 exit criteria - adversarial", () => {
  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: KNOWLEDGE_DIR,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });

    // Bootstrap owner, then per-namespace keys through the owner.
    ({ key: ownerKey, identity: idOwner } = await issue("org", "boss", "owner"));
    ({ key: keyA, identity: idA } = await issue(NS_A, "alice", "member", idOwner));
    ({ key: keyB, identity: idB } = await issue(NS_B, "bob", "member", idOwner));
    ({ key: auditorKey, identity: idAuditor } = await issue(NS_A, "aud", "auditor", idOwner));

    // Seed B's private memory.
    const w = sync(
      await kernel.memWrite(
        { scope: "team", content: B_SECRET, hints: { verbatim: true, type: "fact" } },
        idB,
        "exit-test",
      ),
    );
    bFactId = w.stored[0]!.id;
    expect(w.stored[0]!.namespace).toBe(NS_B);

    server = createHttpServer(buildHttpDeps(kernel));
    const port = await server.start(0);
    baseUrl = `http://127.0.0.1:${port}`;
  }, 120_000);

  afterAll(async () => {
    await server?.stop();
    await kernel?.close();
  });

  // -------------------------------------------------------------------------
  // Exit 2 — cross-namespace isolation, syscall layer
  // -------------------------------------------------------------------------

  it("syscall: A cannot read B's memory by id (indistinguishable from a miss)", async () => {
    const res = await kernel.memRead({ id: bFactId }, idA, "exit-test");
    expect(res.found).toBe(false);
    expect(res.memory).toBeNull();

    // ...and the denial is audited under A's namespace (D4).
    const { rows } = await kernel.db.query(
      "SELECT result FROM audit_log WHERE op = 'read' AND namespace = $1 AND memory_id = $2",
      [NS_A, bFactId],
    );
    expect((rows as Array<{ result: string }>).some((r) => r.result === "denied")).toBe(true);
  });

  it("syscall: search from A never returns B's rows", async () => {
    const refs = await kernel.memSearch(
      { query: "TEAMB-ZEBRA payroll cadence biweekly Fridays", k: 20 },
      idA,
      "exit-test",
    );
    expect(refs.every((r) => !r.content.includes("TEAMB-ZEBRA"))).toBe(true);
    expect(refs.every((r) => r.id !== bFactId)).toBe(true);
  });

  it("syscall: stats are scoped - A never counts or surfaces B's rows", async () => {
    const statsA = await kernel.memStats({}, idA, "exit-test");
    expect(statsA.namespace).toBe(NS_A);
    expect(statsA.topAccessed.every((t) => t.id !== bFactId)).toBe(true);

    const statsB = await kernel.memStats({}, idB, "exit-test");
    // B sees its own fact; A's count excludes it entirely.
    expect(statsB.topAccessed.some((t) => t.id === bFactId)).toBe(true);
    expect(statsB.l2Count).toBe(1); // exactly the seeded B secret
    expect(statsA.l2Count).toBe(0); // A sees none of it
  });

  it("syscall: A's write lands ONLY in A's namespace (no caller-asserted ns exists)", async () => {
    const w = sync(
      await kernel.memWrite(
        { scope: "team", content: "Team A stand-up is 09:30", hints: { verbatim: true } },
        idA,
        "exit-test",
      ),
    );
    expect(w.stored).toHaveLength(1);
    expect(w.stored[0]!.namespace).toBe(NS_A);
    const { rows } = await kernel.db.query(
      "SELECT namespace FROM memory_objects WHERE id = $1",
      [w.stored[0]!.id],
    );
    expect(rows[0].namespace).toBe(NS_A);
  });

  // -------------------------------------------------------------------------
  // Exit 2 — cross-namespace isolation, live HTTP transport
  // -------------------------------------------------------------------------

  it("http: A cannot read B's memory by id", async () => {
    const own = await post("/v1/mem/read", { id: bFactId }, keyB);
    expect(own.status).toBe(200);
    expect(own.json.found).toBe(true); // sanity: the row is really there for B

    const theft = await post("/v1/mem/read", { id: bFactId }, keyA);
    expect(theft.status).toBe(200);
    expect(theft.json.found).toBe(false);
    expect(theft.json.memory).toBeNull();
  });

  it("http: bodies asserting namespace/actor are rejected with 400 identity_from_key", async () => {
    const res = await post("/v1/mem/read", { id: bFactId, namespace: NS_B }, keyA);
    expect(res.status).toBe(400);
    expect(res.json.code).toBe("identity_from_key");

    const res2 = await post(
      "/v1/mem/write",
      { scope: "team", content: "x", actor: "bob" },
      keyA,
    );
    expect(res2.status).toBe(400);
    expect(res2.json.code).toBe("identity_from_key");
  });

  it("http: search from A never returns B's rows", async () => {
    const res = await post(
      "/v1/mem/search",
      { query: "TEAMB-ZEBRA payroll cadence biweekly Fridays", k: 20 },
      keyA,
    );
    expect(res.status).toBe(200);
    const refs = res.json as Array<{ id: string; content: string }>;
    expect(refs.every((r) => !r.content.includes("TEAMB-ZEBRA"))).toBe(true);
    expect(refs.every((r) => r.id !== bFactId)).toBe(true);
  });

  it("http: stats scoped to the key's namespace", async () => {
    const res = await post("/v1/mem/stats", {}, keyA);
    expect(res.status).toBe(200);
    expect(res.json.namespace).toBe(NS_A);
    expect(
      (res.json.topAccessed as Array<{ id: string }>).every((t) => t.id !== bFactId),
    ).toBe(true);
  });

  it("http: A's write lands only in A's namespace", async () => {
    const res = await post(
      "/v1/mem/write",
      { scope: "team", content: "Team A retro is Thursday", hints: { verbatim: true } },
      keyA,
    );
    expect(res.status).toBe(200);
    expect(res.json.stored).toHaveLength(1);
    expect(res.json.stored[0].namespace).toBe(NS_A);
  });

  it("http: fault from A cannot page in B's L2 rows", async () => {
    const res = await post(
      "/v1/mem/fault",
      { query: "TEAMB-ZEBRA payroll cadence biweekly Fridays" },
      keyA,
    );
    expect(res.status).toBe(200);
    const injected = res.json.injected as Array<{ ref: string; content: string }>;
    expect(injected.every((r) => r.ref !== bFactId)).toBe(true);
    expect(injected.every((r) => !r.content.includes("TEAMB-ZEBRA"))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Exit 1 + 4 — identity gate: 401s, revocation, auditor, admin roles
  // -------------------------------------------------------------------------

  it("http: missing or garbage bearer → 401 before any syscall", async () => {
    const missing = await post("/v1/mem/stats", {});
    expect(missing.status).toBe(401);
    expect(missing.json.code).toBe("unauthorized");

    const garbage = await post("/v1/mem/stats", {}, "not-an-hm-key");
    expect(garbage.status).toBe(401);

    const wellFormedUnknown = await post("/v1/mem/stats", {}, "hm_" + "0".repeat(40));
    expect(wellFormedUnknown.status).toBe(401);
  });

  it("http: revoked key → 401 instantly", async () => {
    const { key: tempKey, identity: tempId } = await issue(NS_A, "temp", "member", idOwner);
    const before = await post("/v1/mem/stats", {}, tempKey);
    expect(before.status).toBe(200);

    const revoked = await kernel.auth.revoke(tempId.keyId);
    expect(revoked).toBe(true);

    const after = await post("/v1/mem/stats", {}, tempKey);
    expect(after.status).toBe(401);
    expect(after.json.code).toBe("unauthorized");

    // ...and the syscall layer sees no identity at all.
    expect(await kernel.auth.resolve(tempKey)).toBeNull();
  });

  it("a long-lived identity snapshot is denied on its next syscall after revocation", async () => {
    const { identity: tempId } = await issue(NS_A, "long-lived", "member", idOwner);
    await expect(kernel.memStats({}, tempId, "stdio-test")).resolves.toMatchObject({
      namespace: NS_A,
    });

    expect(await kernel.auth.revoke(tempId.keyId)).toBe(true);

    await expect(kernel.memStats({}, tempId, "stdio-test")).rejects.toThrow(/revoked/i);
    const { rows } = await kernel.db.query(
      `SELECT result, detail FROM audit_log
       WHERE actor = $1 AND op = 'stats'
       ORDER BY ts DESC LIMIT 1`,
      [tempId.actor],
    );
    expect(rows[0]).toMatchObject({ result: "denied" });
    expect(String(rows[0].detail)).toMatch(/revoked/i);
  });

  it("search brownouts to BM25 on the first embedding-provider failure", async () => {
    const ns = `${NS_A}/embed-brownout`;
    const { identity } = await issue(ns, "embed-brownout", "member", idOwner);
    await kernel.memWrite(
      {
        scope: "team",
        content: "The zanzibar refund escalation procedure uses form omega",
        hints: { verbatim: true },
      },
      identity,
      "brownout-test",
    );

    const originalEmbed = kernel.embedder.embed;
    kernel.embedder.embed = async () => {
      throw new Error("embedding provider unavailable");
    };
    try {
      const refs = await kernel.memSearch(
        { query: "zanzibar refund escalation procedure", k: 5 },
        identity,
        "brownout-test",
      );
      expect(refs[0]?.content).toContain("zanzibar refund escalation");
      const { rows } = await kernel.db.query(
        `SELECT detail FROM audit_log
         WHERE actor = $1 AND op = 'search'
         ORDER BY ts DESC LIMIT 1`,
        [identity.actor],
      );
      expect(String(rows[0].detail)).toContain("driver=bm25-degraded");
    } finally {
      kernel.embedder.embed = originalEmbed;
    }
  });

  it("auditor write → denied + audited (syscall AND http)", async () => {
    await expect(
      kernel.memWrite(
        { scope: "team", content: "auditor should not write this" },
        idAuditor,
        "exit-test",
      ),
    ).rejects.toThrow(AuthzError);

    const res = await post(
      "/v1/mem/write",
      { scope: "team", content: "auditor should not write this either" },
      auditorKey,
    );
    expect(res.status).toBe(403);
    expect(res.json.code).toBe("forbidden");

    // Both denials are audited (D4): op 'write', result 'denied', auditor ns.
    const { rows } = await kernel.db.query(
      "SELECT detail FROM audit_log WHERE op = 'write' AND result = 'denied' AND namespace = $1 AND actor = $2",
      [NS_A, "aud"],
    );
    expect(rows.length).toBeGreaterThanOrEqual(2);

    // Nothing landed.
    const { rows: stored } = await kernel.db.query(
      "SELECT count(*) AS n FROM memory_objects WHERE content LIKE '%auditor should not write%'",
    );
    expect(Number(stored[0].n)).toBe(0);
  });

  it("auditor can still read/search/stats", async () => {
    const stats = await kernel.memStats({}, idAuditor, "exit-test");
    expect(stats.namespace).toBe(NS_A);
    const refs = await kernel.memSearch({ query: "stand-up" }, idAuditor, "exit-test");
    expect(Array.isArray(refs)).toBe(true);
  });

  it("http: member/auditor cannot touch admin routes; owner can", async () => {
    // An auditor never reaches the key listing.
    const auditorList = await get("/v1/admin/keys", auditorKey);
    expect(auditorList.status).toBe(403);
    expect(auditorList.json.code).toBe("forbidden");

    // D50: a member DOES reach the key routes — it may deploy agents in its own
    // scope — but the listing is limited to agent keys at its own namespace,
    // and every other admin route stays closed to it.
    const memberList = await get("/v1/admin/keys", keyA);
    expect(memberList.status).toBe(200);
    for (const rec of memberList.json) {
      expect(rec.role).toBe("agent");
      expect(rec.namespace).toBe(NS_A);
    }
    for (const path of ["/v1/admin/policy", "/v1/admin/pins", "/v1/admin/scorecard"]) {
      const denied = await get(path, keyA);
      expect(denied.status).toBe(403);
      expect(denied.json.code).toBe("forbidden");
    }

    const ownerList = await get("/v1/admin/keys", ownerKey);
    expect(ownerList.status).toBe(200);
    expect(Array.isArray(ownerList.json)).toBe(true);
    expect(ownerList.json.length).toBeGreaterThanOrEqual(4);
    // Key hashes/plaintext never appear in listings.
    for (const rec of ownerList.json) {
      expect(rec.keyHash).toBeUndefined();
      expect(rec.key_hash).toBeUndefined();
    }
  });

  it("http: issuing a key requires owner; issued key works immediately", async () => {
    const denied = await post(
      "/v1/admin/keys",
      { namespace: NS_B, actor: "eve", role: "owner" },
      keyA,
    );
    expect(denied.status).toBe(403);

    const issued = await post(
      "/v1/admin/keys",
      { namespace: NS_B, actor: "carol", role: "member" },
      ownerKey,
    );
    expect(issued.status).toBe(201);
    expect(issued.json.plaintext).toMatch(/^hm_[0-9a-f]{40}$/);

    const stats = await post("/v1/mem/stats", {}, issued.json.plaintext);
    expect(stats.status).toBe(200);
    expect(stats.json.namespace).toBe(NS_B);
  });

  // -------------------------------------------------------------------------
  // Exit 2 — MCP over HTTP (Streamable, stateless): tools carry no namespace
  // -------------------------------------------------------------------------

  it("mcp-http: tool schemas have no namespace/actor params and reads are key-scoped", async () => {
    const rpc = async (key: string, body: unknown) => {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
      });
      const raw = await res.text();
      const dataLine = raw.split("\n").find((line) => line.startsWith("data:"));
      return {
        status: res.status,
        json: JSON.parse(dataLine ? dataLine.slice(5).trim() : raw),
      };
    };

    const init = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "exit-test", version: "0.0.0" },
      },
    };
    const initRes = await rpc(keyA, init);
    expect(initRes.status).toBe(200);

    const list = await rpc(keyA, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    expect(list.status).toBe(200);
    const tools = list.json.result.tools as Array<{
      name: string;
      inputSchema: { properties?: Record<string, unknown> };
    }>;
    expect(tools.map((t) => t.name).sort()).toEqual([
      "company_file_list",
      "company_file_read",
      "describe_access", // M8A addendum: badge-visible standing access + escalation policy
      "mem_assemble",
      "mem_fault",
      "mem_forget", // M4: compliance erasure tool (owner/admin) added to the set
      "mem_live_result", // M6 (D15): redeem a two-phase live-confirmation ticket
      "mem_manifest",
      "mem_pin",
      "mem_policy", // guardrail lane: the governed directive set + its digest
      "mem_policy_ack", // the caller echoes that digest back (acknowledged/applied)
      "mem_read",
      "mem_search",
      "mem_share",
      "mem_stats",
      "mem_unpin",
      "mem_write",
      "mem_write_status",
      "request_access",
      "skill_invoke",
      "skill_list",
      "source_list",
      "source_read",
      "source_search",
    ]);
    for (const tool of tools) {
      const props = Object.keys(tool.inputSchema.properties ?? {});
      expect(props, `${tool.name} must not expose namespace`).not.toContain("namespace");
      expect(props, `${tool.name} must not expose actor`).not.toContain("actor");
    }

    // A's key + B's memory id through the MCP tool → invisible.
    const manifestCall = await rpc(keyA, {
      jsonrpc: "2.0",
      id: 21,
      method: "tools/call",
      params: { name: "mem_manifest", arguments: { variant: "index" } },
    });
    expect(manifestCall.status).toBe(200);
    const manifest = JSON.parse(manifestCall.json.result.content[0].text);
    expect(manifest.namespace).toBe(NS_A);
    expect(manifest.markdown).toContain(`# Memory manifest - ${NS_A}`);

    const fileListCall = await rpc(ownerKey, {
      jsonrpc: "2.0",
      id: 22,
      method: "tools/call",
      params: { name: "company_file_list", arguments: { query: "sales" } },
    });
    expect(fileListCall.status).toBe(200);
    expect(fileListCall.json.result.isError, JSON.stringify(fileListCall.json.result)).not.toBe(true);
    const fileList = JSON.parse(fileListCall.json.result.content[0].text);
    expect(fileList.data).toEqual([]);

    const skillListCall = await rpc(ownerKey, {
      jsonrpc: "2.0",
      id: 23,
      method: "tools/call",
      params: { name: "skill_list", arguments: {} },
    });
    expect(skillListCall.status).toBe(200);
    const skillList = JSON.parse(skillListCall.json.result.content[0].text);
    expect(Array.isArray(skillList)).toBe(true);
    for (const skill of skillList) expect(skill.definition).toBeUndefined();

    const call = await rpc(keyA, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "mem_read", arguments: { id: bFactId } },
    });
    expect(call.status).toBe(200);
    const payload = JSON.parse(call.json.result.content[0].text);
    expect(payload.found).toBe(false);

    const spoof = await rpc(keyA, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "source_read",
        arguments: {
          grantId: "grant-x",
          connectorId: "source-x",
          sourceRef: "customers",
          purpose: "support",
          query: "Ada",
          resourceSensitivity: "public",
        },
      },
    });
    expect(spoof.status).toBe(200);
    expect(spoof.json.result.isError).toBe(true);
    const ingressAudit = (await kernel.audit.list(NS_A, { limit: 20 })).find((event) =>
      event.detail?.includes("gateway_phase=ingress"),
    );
    expect(ingressAudit).toMatchObject({ result: "denied", agentId: idA.keyId });

    // Unauthenticated /mcp → 401 before the SDK transport is reached.
    const anon = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify(init),
    });
    expect(anon.status).toBe(401);
  });

  // -------------------------------------------------------------------------
  // Async write lane — tickets are redeemable, scoped, and failures audited
  // -------------------------------------------------------------------------

  it("http: async write tickets are redeemable and scoped to the caller's namespace", async () => {
    const res = await post(
      "/v1/mem/write",
      { scope: "team", content: "async ticket redemption fact", hints: { verbatim: true }, async: true },
      keyA,
    );
    expect(res.status).toBe(200);
    const ticket = res.json.ticket as string;
    expect(ticket).toBeTruthy();

    await kernel.writeQueue.drain();

    const status = await get(`/v1/mem/write/${ticket}`, keyA);
    expect(status.status).toBe(200);
    expect(status.json.state).toBe("done");
    expect(status.json.result.stored[0].namespace).toBe(NS_A);

    // A foreign namespace's key cannot probe the ticket (WriteResults carry
    // stored memory objects) — indistinguishable from a miss.
    const foreign = await get(`/v1/mem/write/${ticket}`, keyB);
    expect(foreign.status).toBe(404);

    // Unknown ticket → 404.
    const unknown = await get("/v1/mem/write/01UNKNOWNTICKET0000000000X", keyA);
    expect(unknown.status).toBe(404);
  });

  it("a failed async write flips the ticket to 'failed' AND leaves an audit row (D4)", async () => {
    const realInsert = MemoryIndex.prototype.insert;
    MemoryIndex.prototype.insert = async () => {
      throw new Error("injected async insert failure");
    };
    let ticket = "";
    try {
      const res = await post(
        "/v1/mem/write",
        { scope: "team", content: "this async write will fail", hints: { verbatim: true }, async: true },
        keyA,
      );
      expect(res.status).toBe(200);
      ticket = res.json.ticket as string;
      await kernel.writeQueue.drain();
    } finally {
      MemoryIndex.prototype.insert = realInsert;
    }

    const status = await get(`/v1/mem/write/${ticket}`, keyA);
    expect(status.status).toBe(200);
    expect(status.json.state).toBe("failed");
    expect(status.json.error).toContain("injected async insert failure");

    const { rows } = await kernel.db.query(
      "SELECT detail FROM audit_log WHERE op = 'write' AND result = 'error' AND namespace = $1",
      [NS_A],
    );
    expect(
      (rows as Array<{ detail: string | null }>).some((r) =>
        (r.detail ?? "").includes("injected async insert failure"),
      ),
    ).toBe(true);
  });

  it("a stale revoked identity cannot enqueue an async write", async () => {
    const { identity: qid } = await issue(NS_A, "queued-actor", "member", idOwner);
    expect(await kernel.auth.revoke(qid.keyId)).toBe(true);

    // Direct kernel call with the stale Identity snapshot (the HTTP layer
    // already 401s). The syscall gate must reject before queue acceptance.
    await expect(
      kernel.memWrite(
        { scope: "team", content: "ghost write after revocation", hints: { verbatim: true }, async: true },
        qid,
        "exit-test",
      ),
    ).rejects.toThrow(/revoked|inactive/i);
    await kernel.writeQueue.drain();

    const { rows } = await kernel.db.query(
      "SELECT count(*) AS n FROM memory_objects WHERE content LIKE '%ghost write after revocation%'",
    );
    expect(Number(rows[0].n)).toBe(0);

    // The denial is audited (D4).
    const { rows: denied } = await kernel.db.query(
      "SELECT count(*) AS n FROM audit_log WHERE op = 'write' AND result = 'denied' AND actor = 'queued-actor'",
    );
    expect(Number(denied[0].n)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Exit 3 — supersede atomicity under injected mid-transaction failure
  // -------------------------------------------------------------------------

  it("supersede is atomic: injected failure rolls back BOTH statements", async () => {
    const first = sync(
      await kernel.memWrite(
        {
          scope: "user",
          content:
            "Customer Dana Whitfield's current shipping address for order 4127 is 12 Elm Street, Springfield",
          hints: { verbatim: true, type: "fact" },
        },
        idA,
        "exit-test",
      ),
    );
    const priorId = first.stored[0]!.id;

    const countRows = async (): Promise<number> => {
      const { rows } = await kernel.db.query(
        "SELECT count(*) AS n FROM memory_objects WHERE namespace = $1",
        [NS_A],
      );
      return Number(rows[0].n);
    };
    const rowsBefore = await countRows();

    // (a) insert fails mid-supersede → prior fact untouched, nothing new.
    const realInsert = MemoryIndex.prototype.insert;
    MemoryIndex.prototype.insert = async () => {
      throw new Error("injected insert failure");
    };
    try {
      await expect(
        kernel.memWrite(
          {
            scope: "user",
            content:
              "Customer Dana Whitfield's current shipping address for order 4127 is 99 Oak Street, Springfield",
            hints: { verbatim: true, type: "fact" },
          },
          idA,
          "exit-test",
        ),
      ).rejects.toThrow(/injected insert failure/);
    } finally {
      MemoryIndex.prototype.insert = realInsert;
    }

    let prior = await kernel.memRead({ id: priorId }, idA, "exit-test");
    expect(prior.found).toBe(true);
    expect(prior.memory!.tValidTo).toBeNull(); // still currently valid
    expect(await countRows()).toBe(rowsBefore); // no orphan row

    // (b) Ordinary semantic similarity never calls closeValidity in Luna v1.
    const realClose = MemoryIndex.prototype.closeValidity;
    MemoryIndex.prototype.closeValidity = async () => {
      throw new Error("injected closeValidity failure");
    };
    try {
      const independent = sync(await kernel.memWrite(
          {
            scope: "user",
            content:
              "Customer Dana Whitfield's current shipping address for order 4127 is 99 Oak Street, Springfield",
            hints: { verbatim: true, type: "fact" },
          },
          idA,
          "exit-test",
        ));
      expect(independent.stored).toHaveLength(1);
      expect(independent.superseded).toEqual([]);
    } finally {
      MemoryIndex.prototype.closeValidity = realClose;
    }

    prior = await kernel.memRead({ id: priorId }, idA, "exit-test");
    expect(prior.found).toBe(true);
    expect(prior.memory!.tValidTo).toBeNull(); // prior fact still valid
    expect(await countRows()).toBe(rowsBefore + 1);
    const { rows: oak } = await kernel.db.query(
      "SELECT count(*) AS n FROM memory_objects WHERE content LIKE '%99 Oak Street%'",
    );
    expect(Number(oak[0].n)).toBe(1);

    // (c) the exact repeat dedupes; neither fact is retired.
    const w = sync(
      await kernel.memWrite(
        {
          scope: "user",
          content:
            "Customer Dana Whitfield's current shipping address for order 4127 is 99 Oak Street, Springfield",
          hints: { verbatim: true, type: "fact" },
        },
        idA,
        "exit-test",
      ),
    );
    expect(w.superseded).toEqual([]);
    expect(w.deduplicated).toBe(1);
    const closed = await kernel.memRead({ id: priorId }, idA, "exit-test");
    expect(closed.found).toBe(true);
    const historical = await kernel.db.query(
      `SELECT t_valid_to FROM memory_objects WHERE id = $1`,
      [priorId],
    );
    expect(historical.rows[0]!.t_valid_to).toBeNull();
  });

  it("concurrent conflicting writes never fork the supersede chain (D7)", async () => {
    const seed = sync(
      await kernel.memWrite(
        {
          scope: "user",
          content: "Conference room Aurora booking code for visitors is 1111",
          hints: { verbatim: true, type: "fact" },
        },
        idA,
        "exit-test",
      ),
    );
    const seedId = seed.stored[0]!.id;

    // Two conflicting updates race: whatever the interleaving, the guarded
    // closeValidity + bounded re-decision must leave exactly ONE currently-
    // valid row and a linear (never forked) chain.
    await Promise.all([
      kernel.memWrite(
        {
          scope: "user",
          content: "Conference room Aurora booking code for visitors is 2222",
          hints: { verbatim: true, type: "fact" },
        },
        idA,
        "exit-test",
      ),
      kernel.memWrite(
        {
          scope: "user",
          content: "Conference room Aurora booking code for visitors is 3333",
          hints: { verbatim: true, type: "fact" },
        },
        idA,
        "exit-test",
      ),
    ]);

    const { rows } = await kernel.db.query(
      "SELECT id, t_valid_to, supersedes FROM memory_objects WHERE content LIKE '%Aurora booking code%'",
    );
    const typed = rows as Array<{ id: string; t_valid_to: unknown; supersedes: string | null }>;
    // Cosine candidates do not mutate any of the three facts.
    expect(typed.filter((r) => r.t_valid_to === null)).toHaveLength(3);
    expect(typed.find((r) => r.id === seedId)!.t_valid_to).toBeNull();
    const victims = typed.map((r) => r.supersedes).filter((s): s is string => s !== null);
    expect(new Set(victims).size).toBe(victims.length);
  });
});
