/**
 * M1 module B — HTTP transport tests.
 *
 * Boots the node:http server on an ephemeral port with hand-rolled stub deps
 * (zero network beyond loopback, no DB, no kernel). Asserts:
 *   - no auth → 401; unknown/bad key → 401 (both audited, actor 'unknown');
 *   - good key routes to the syscall with the RESOLVED identity, never a
 *     body-supplied one;
 *   - body containing 'namespace' (or 'actor') → 400;
 *   - member on admin routes → 403 (audited with the resolved actor);
 *   - /healthz open; /metrics auth'd but any role;
 *   - MCP at /mcp: auth before transport, per-request buildMcpServer(identity).
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { createServer } from "node:http";

import {
  handleHttpRequest,
  createHttpServer,
  type HaloHttpServer,
  type HttpChannels,
  type HttpServerDeps,
} from "../src/http/server.js";
import type { AuditEvent, Identity, SyscallContext } from "../src/types.js";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Stub deps
// ---------------------------------------------------------------------------

const MEMBER: Identity = {
  keyId: "01MEMBERKEY",
  namespace: "org/team-a",
  actor: "alice",
  role: "member",
};
const AGENT: Identity = {
  keyId: "01AGENTKEY",
  namespace: "org/team-a",
  actor: "support-agent",
  role: "agent",
  // D50: the default badge is member-level (the least-privileged agent).
  agentAccessLevel: "member",
};
const MANAGER_AGENT: Identity = {
  keyId: "01MANAGERAGENTKEY",
  namespace: "org/team-a",
  actor: "team-manager-agent",
  role: "agent",
  agentAccessLevel: "manager",
};
const ADMIN: Identity = {
  keyId: "01ADMINKEY",
  namespace: "org",
  actor: "root",
  role: "admin",
};

const AUDITOR: Identity = {
  keyId: "01AUDITORKEY",
  namespace: "org/team-a",
  actor: "auditor:a",
  role: "auditor",
};

const TENANT_OWNER: Identity = {
  keyId: "01TENANTOWNERKEY",
  namespace: "org",
  actor: "owner@org.test",
  role: "owner",
};

const ROOT_OWNER: Identity = {
  keyId: "01ROOTOWNERKEY",
  namespace: "",
  actor: "platform-owner",
  role: "owner",
};

const MEMBER_KEY = "hm_" + "a".repeat(40);
const AGENT_KEY = "hm_" + "c".repeat(40);
const ADMIN_KEY = "hm_" + "b".repeat(40);
const AUDITOR_KEY = "hm_" + "d".repeat(40);
const MANAGER_AGENT_KEY = "hm_" + "m".repeat(40);
const TENANT_OWNER_KEY = "hm_" + "e".repeat(40);
const ROOT_OWNER_KEY = "hm_" + "g".repeat(40);
const COPILOT_CAPABILITY = "hmc_test-capability";

interface SyscallCall {
  op: string;
  payload: Record<string, unknown>;
  identity: Identity;
}

interface AdminCall {
  op: string;
  args: unknown[];
  identity: Identity;
}

function makeStubs() {
  const auditEvents: AuditEvent[] = [];
  const syscallCalls: SyscallCall[] = [];
  const adminCalls: AdminCall[] = [];
  const mcpIdentities: Identity[] = [];
  const mcpContexts: Array<SyscallContext | undefined> = [];
  const resolveCalls: string[] = [];
  const webhookCalls: Array<{ sourceId: string; rawBody: string; timestamp: string; signature: string }> = [];
  const obsidianCalls: Array<{ sourceId: string; rawBody: string; timestamp: string; signature: string }> = [];
  const channelCalls: Array<{ op: string; id: string; body: Record<string, unknown>; identity: Identity }> = [];

  const syscall =
    (op: string) =>
    async (
      payload: Record<string, unknown>,
      identity: Identity,
    ): Promise<unknown> => {
      syscallCalls.push({ op, payload, identity });
      return { op, echo: payload, ns: identity.namespace };
    };

  const deps: HttpServerDeps = {
    auth: {
      async resolve(key: string): Promise<Identity | null> {
        resolveCalls.push(key);
        if (key === MEMBER_KEY) return MEMBER;
        if (key === AGENT_KEY) return AGENT;
        if (key === MANAGER_AGENT_KEY) return MANAGER_AGENT;
        if (key === ADMIN_KEY) return ADMIN;
        if (key === AUDITOR_KEY) return AUDITOR;
        if (key === TENANT_OWNER_KEY) return TENANT_OWNER;
        if (key === ROOT_OWNER_KEY) return ROOT_OWNER;
        return null;
      },
      async resolveCopilotCapability(token: string): Promise<Identity | null> {
        return token === COPILOT_CAPABILITY
          ? {
              ...MEMBER,
              assistantObservability: {
                traceId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                turnId: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
                invocationId: "01ARZ3NDEKTSV4RRFFQ69G5FAX",
              },
            }
          : null;
      },
    },
    syscalls: {
      memRead: syscall("read"),
      memSearch: syscall("search"),
      memWrite: syscall("write"),
      memFault: syscall("fault"),
      memStats: syscall("stats"),
      memAssemble: syscall("assemble"),
      memPin: syscall("pin"),
      memUnpin: syscall("unpin"),
      memShare: syscall("share"),
      completeAgentSession: syscall("session_capture"),
      invokeSkill: syscall("skill_invoke"),
      listSkills: async (identity) => {
        syscallCalls.push({ op: "skills-list", payload: {}, identity });
        return [];
      },
      registerSkill: syscall("skill-register"),
      downloadSkill: async (id, identity) => {
        syscallCalls.push({ op: "skill-download", payload: { id }, identity });
        return {
          filename: "demo.md",
          content: '---\nname: "Demo"\n---\n\ndemo body\n',
        };
      },
    },
    admin: {
      async getPolicy(ns, identity) {
        adminCalls.push({ op: "getPolicy", args: [ns], identity });
        return { namespace: ns, tokenBudget: 3000 };
      },
      async setPolicy(ns, yamlText, identity) {
        adminCalls.push({ op: "setPolicy", args: [ns, yamlText], identity });
        return { namespace: ns, updated: true };
      },
      async listKeys(identity) {
        adminCalls.push({ op: "listKeys", args: [], identity });
        return [];
      },
      async issueKey(params, identity) {
        adminCalls.push({ op: "issueKey", args: [params], identity });
        return { id: "01NEWKEY", plaintext: "hm_" + "c".repeat(40) };
      },
      async revokeKey(keyId, identity) {
        adminCalls.push({ op: "revokeKey", args: [keyId], identity });
        return { revoked: keyId };
      },
      async listPins(namespace, identity) {
        adminCalls.push({ op: "listPins", args: [namespace], identity });
        return [{ id: "01PIN", namespace }];
      },
      async createPin(body, identity) {
        adminCalls.push({ op: "createPin", args: [body], identity });
        return { pin: { id: "01PIN" }, created: true };
      },
      async deletePin(pinId, identity) {
        adminCalls.push({ op: "deletePin", args: [pinId], identity });
        return { pin: { id: pinId }, released: true };
      },
      async forkMount(body, identity) {
        adminCalls.push({ op: "forkMount", args: [body], identity });
        return {
          id: "01FORK",
          origin: body.origin,
          targetMemoryId: "01TARGET",
        };
      },
      async runMovement(body, identity) {
        adminCalls.push({ op: "runMovement", args: [body], identity });
        return { status: "degraded" };
      },
      async getCertificate(id, identity) {
        adminCalls.push({ op: "getCertificate", args: [id], identity });
        // The kernel is what enforces the subtree ACL; this stub returns a
        // sentinel so the test can assert the RESOLVED identity was forwarded.
        return {
          id,
          forwardedNamespace: identity.namespace,
          forwardedRole: identity.role,
        };
      },
      async overview(query, identity) {
        adminCalls.push({ op: "overview", args: [query], identity });
        return { namespace: identity.namespace };
      },
      async people(identity) {
        adminCalls.push({ op: "people", args: [], identity });
        return [];
      },
      async memoryMap(namespace, identity) {
        adminCalls.push({ op: "memoryMap", args: [namespace], identity });
        return { namespace };
      },
      async setup(body, identity) {
        adminCalls.push({ op: "setup", args: [body], identity });
        return { created: true };
      },
      async setupCapabilities(identity) {
        adminCalls.push({ op: "setupCapabilities", args: [], identity });
        return { retrievers: [{ name: "baseline" }] };
      },
      async setupStatus(operationId, identity) {
        adminCalls.push({ op: "setupStatus", args: [operationId], identity });
        return { operationId, status: "source_failed" };
      },
      async setupRetry(operationId, identity) {
        adminCalls.push({ op: "setupRetry", args: [operationId], identity });
        return { operationId, status: "waiting_for_agent" };
      },
      async warmStores(identity) {
        adminCalls.push({ op: "warmStores", args: [], identity });
        return [];
      },
      async warmFlush(identity) {
        adminCalls.push({ op: "warmFlush", args: [], identity });
        return {};
      },
      async warmRebuild(name, body, identity) {
        adminCalls.push({ op: "warmRebuild", args: [name, body], identity });
        return { store: name, namespace: body.namespace, records: 0 };
      },
      async importCsvSource(id, body, identity) {
        adminCalls.push({ op: "importCsvSource", args: [id, body], identity });
        return { records: 1, stored: 1, errors: [] };
      },
      async syncSource(id, identity) {
        adminCalls.push({ op: "syncSource", args: [id], identity });
        return {
          accepted: true,
          jobId: "source-sync:manual:01SOURCE",
          status: "queued",
        };
      },
      async pairObsidian(body, identity) {
        adminCalls.push({ op: "pairObsidian", args: [body], identity });
        return {
          pairing: {
            sourceId: "01OBSIDIAN",
            path: "/v1/ingest/obsidian/01OBSIDIAN",
            secret: "once",
          },
        };
      },
      async approveSkill(id, identity) {
        adminCalls.push({ op: "approveSkill", args: [id], identity });
        return { id, approvalStatus: "approved" };
      },
      async rejectSkill(id, body, identity) {
        adminCalls.push({ op: "rejectSkill", args: [id, body], identity });
        return { id, approvalStatus: "rejected" };
      },
      async updateSkill(id, body, identity) {
        adminCalls.push({ op: "updateSkill", args: [id, body], identity });
        return { skill: { id: "01SKILLV2", supersedes: id, ...body } };
      },
      async listConflicts(identity) {
        adminCalls.push({ op: "listConflicts", args: [], identity });
        return { disputes: [], findings: [], latestScan: null };
      },
      async requestConflictScan(body, identity) {
        adminCalls.push({ op: "requestConflictScan", args: [body], identity });
        return { id: "01SCAN", status: "queued" };
      },
      async latestConflictScan(identity) {
        adminCalls.push({ op: "latestConflictScan", args: [], identity });
        return null;
      },
      async getConflictScan(id, identity) {
        adminCalls.push({ op: "getConflictScan", args: [id], identity });
        return { id, status: "completed" };
      },
    },
    metrics: {
      snapshot: () => ({ uptimeMs: 42, ops: {} }),
    },
    audit: {
      async append(event: AuditEvent) {
        auditEvents.push(event);
      },
    },
    webhooks: {
      async ingest(sourceId, rawBody, timestamp, signature) {
        webhookCalls.push({ sourceId, rawBody, timestamp, signature });
        return { records: 1, stored: 1, errors: [] };
      },
      async obsidian(sourceId, rawBody, timestamp, signature) {
        obsidianCalls.push({ sourceId, rawBody, timestamp, signature });
        return { records: 1, stored: 1, errors: [] };
      },
    },
    channels: {
      async managedGoogleChatStart(identity) {
        channelCalls.push({ op: "managedGoogleChatStart", identity });
        return { state: "waiting_installation", setupId: "01JYZ0000000000000000000GC" };
      },
      async managedGoogleChatStatus(identity, id) {
        channelCalls.push({ op: "managedGoogleChatStatus", id, identity });
        return { state: "verifying", setupId: id };
      },
      async setupTelegram(identity, id, body) {
        channelCalls.push({ op: "setupTelegram", id, body, identity });
        return { id, lifecycleState: "active", outboundAuthority: true };
      },
    } as unknown as HttpChannels,
    buildMcpServer(identity: Identity, serverContext?: SyscallContext) {
      mcpIdentities.push(identity);
      mcpContexts.push(serverContext);
      const server = new McpServer({ name: "halomem-test", version: "0.0.0" });
      server.registerTool(
        "ping",
        { description: "test tool", inputSchema: z.object({}) },
        async () => ({
          content: [{ type: "text" as const, text: identity.namespace }],
        }),
      );
      return server;
    },
  };

  return {
    deps,
    auditEvents,
    syscallCalls,
    adminCalls,
    mcpIdentities,
    mcpContexts,
    resolveCalls,
    webhookCalls,
    obsidianCalls,
    channelCalls,
  };
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("http transport (module B)", () => {
  let stubs: ReturnType<typeof makeStubs>;
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    stubs = makeStubs();
    server = createHttpServer(stubs.deps);
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    stubs.auditEvents.length = 0;
    stubs.syscallCalls.length = 0;
    stubs.adminCalls.length = 0;
    stubs.mcpIdentities.length = 0;
    stubs.mcpContexts.length = 0;
    stubs.resolveCalls.length = 0;
    stubs.webhookCalls.length = 0;
    stubs.obsidianCalls.length = 0;
    stubs.channelCalls.length = 0;
  });

  const post = (path: string, body: unknown, key?: string) =>
    fetch(base + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(key ? { authorization: `Bearer ${key}` } : {}),
      },
      body: JSON.stringify(body),
    });

  const patch = (path: string, body: unknown, key?: string) =>
    fetch(base + path, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        ...(key ? { authorization: `Bearer ${key}` } : {}),
      },
      body: JSON.stringify(body),
    });

  // --- healthz -------------------------------------------------------------

  it("GET /healthz is open (no auth) and returns { ok: true }", async () => {
    const res = await fetch(base + "/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(stubs.auditEvents).toHaveLength(0);
  });

  it("GET /healthz/mastra verifies the running HaloMem-to-sidecar bearer", async () => {
    stubs.deps.copilot = {
      listProfiles: async () => [],
      complete: async () => ({}),
      probe: async () => {},
    };

    const ok = await fetch(base + "/healthz/mastra");
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ok: true });

    stubs.deps.copilot.probe = async () => {
      throw new Error("raw sidecar failure");
    };
    const failed = await fetch(base + "/healthz/mastra");
    expect(failed.status).toBe(503);
    const body = await failed.json();
    expect(body).toEqual({ ok: false });
    expect(JSON.stringify(body)).not.toContain("raw sidecar failure");
    expect(stubs.auditEvents).toHaveLength(0);
  });

  it("routes Telegram token setup only for a resolved channel manager", async () => {
    const id = "01JYZ0000000000000000000EE";
    const body = {
      botToken: "654321:abcdefghijklmnopqrstuvwxyz_1234567890",
      expectedRowVersion: 7,
      expectedAuthorityEpoch: 4,
    };
    const accepted = await post(
      `/v1/channels/connections/${id}/telegram-setup`,
      body,
      ADMIN_KEY,
    );
    expect(accepted.status).toBe(200);
    expect(stubs.channelCalls).toEqual([{
      op: "setupTelegram",
      id,
      body,
      identity: ADMIN,
    }]);

    const denied = await post(
      `/v1/channels/connections/${id}/telegram-setup`,
      body,
      MEMBER_KEY,
    );
    expect(denied.status).toBe(403);
    expect(stubs.channelCalls).toHaveLength(1);
  });

  it("routes managed Google Chat setup only for a resolved channel manager", async () => {
    const id = "01JYZ0000000000000000000GC";
    const started = await post("/v1/channels/google-chat/managed", {}, ADMIN_KEY);
    expect(started.status).toBe(201);
    expect(await started.json()).toMatchObject({ state: "waiting_installation", setupId: id });
    const status = await fetch(base + `/v1/channels/google-chat/managed/${id}`, {
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ state: "verifying", setupId: id });
    const denied = await post("/v1/channels/google-chat/managed", {}, MEMBER_KEY);
    expect(denied.status).toBe(403);
    expect(stubs.channelCalls.map((call) => call.op)).toEqual([
      "managedGoogleChatStart",
      "managedGoogleChatStatus",
    ]);
  });

  it("captures completed agent sessions through the resolved badge and rejects identity spoofing", async () => {
    const body = {
      sessionId: "local-session-1",
      turns: [{ role: "user", content: "What is the refund window?" }],
    };
    const accepted = await post("/v1/agent-sessions/complete", body, AGENT_KEY);
    expect(accepted.status).toBe(201);
    expect(stubs.syscallCalls).toContainEqual({
      op: "session_capture",
      payload: body,
      identity: AGENT,
    });

    stubs.syscallCalls.length = 0;
    const denied = await post(
      "/v1/agent-sessions/complete",
      { ...body, namespace: "other" },
      AGENT_KEY,
    );
    expect(denied.status).toBe(400);
    expect(stubs.syscallCalls).toHaveLength(0);
  });

  it("routes conflict scans by console role without accepting member mutation", async () => {
    const read = await fetch(base + "/v1/admin/conflicts", {
      headers: { authorization: `Bearer ${AUDITOR_KEY}` },
    });
    expect(read.status).toBe(200);
    expect(stubs.adminCalls.at(-1)).toMatchObject({
      op: "listConflicts",
      identity: AUDITOR,
    });

    const requested = await post(
      "/v1/admin/conflict-scans",
      { focus: "refunds", include: ["agent-summary"] },
      ADMIN_KEY,
    );
    expect(requested.status).toBe(202);
    expect(stubs.adminCalls.at(-1)).toMatchObject({
      op: "requestConflictScan",
      identity: ADMIN,
    });

    const denied = await post("/v1/admin/conflict-scans", {}, AUDITOR_KEY);
    expect(denied.status).toBe(403);
  });

  it("accepts source webhooks without a HaloMem API key and forwards the raw signed body", async () => {
    const rawBody = JSON.stringify({
      records: [{ id: "evt_1", text: "signed" }],
    });
    const res = await fetch(base + "/v1/webhooks/sources/01SOURCE", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-halomem-timestamp": "1784100000",
        "x-halomem-signature": "sha256=" + "a".repeat(64),
      },
      body: rawBody,
    });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({
      accepted: true,
      result: { records: 1, stored: 1, errors: [] },
    });
    expect(stubs.webhookCalls).toEqual([
      {
        sourceId: "01SOURCE",
        rawBody,
        timestamp: "1784100000",
        signature: "sha256=" + "a".repeat(64),
      },
    ]);
    expect(stubs.resolveCalls).toHaveLength(0);
  });

  it("routes signed Obsidian batches without API-key auth and pairs only through admin auth", async () => {
    const rawBody = JSON.stringify({
      version: 1,
      sequence: 1,
      kind: "changes",
      records: [],
      deleted: [],
    });
    const ingested = await fetch(base + "/v1/ingest/obsidian/01OBSIDIAN", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-halomem-timestamp": "1784100000000",
        "x-halomem-signature": "sha256=" + "b".repeat(64),
      },
      body: rawBody,
    });
    expect(ingested.status).toBe(202);
    expect(stubs.obsidianCalls).toEqual([{
      sourceId: "01OBSIDIAN",
      rawBody,
      timestamp: "1784100000000",
      signature: "sha256=" + "b".repeat(64),
    }]);
    expect(stubs.resolveCalls).toHaveLength(0);

    const pairingBody = {
      vaultName: "Company vault",
      includedFolders: ["Handbook"],
      excludedFolders: ["Private"],
      targetTeamId: null,
      sourceAccessMode: "namespace-open",
    };
    const paired = await post(
      "/v1/admin/connectors/obsidian/pair",
      pairingBody,
      TENANT_OWNER_KEY,
    );
    expect(paired.status).toBe(201);
    expect(paired.headers.get("cache-control")).toBe("no-store");
    expect(stubs.adminCalls.at(-1)).toEqual({
      op: "pairObsidian",
      args: [pairingBody],
      identity: TENANT_OWNER,
    });

  });

  it("uses only the address bucket before Obsidian authentication", async () => {
    const original = stubs.deps.webhookThrottle;
    const buckets: string[] = [];
    stubs.deps.webhookThrottle = {
      consume: async (bucket) => {
        buckets.push(bucket);
        return { allowed: true, retryAfterSec: 0 };
      },
    };
    try {
      const rawBody = JSON.stringify({
        version: 1,
        sequence: 1,
        kind: "changes",
        records: [],
        deleted: [],
      });
      const res = await fetch(base + "/v1/ingest/obsidian/attacker-controlled-source", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-halomem-timestamp": "1784100000000",
          "x-halomem-signature": "sha256=" + "b".repeat(64),
        },
        body: rawBody,
      });
      expect(res.status).toBe(202);
      expect(buckets).toHaveLength(1);
      expect(buckets[0]).toMatch(/^obsidian:ip:[a-f0-9]{64}$/);
      expect(buckets).not.toContain("obsidian:source:attacker-controlled-source");
      expect(stubs.obsidianCalls).toHaveLength(1);
    } finally {
      stubs.deps.webhookThrottle = original;
    }
  });

  it("rejects webhook requests with missing signature metadata before dispatch", async () => {
    const res = await fetch(base + "/v1/webhooks/sources/01SOURCE", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ records: [] }),
    });
    expect(res.status).toBe(401);
    expect(stubs.webhookCalls).toHaveLength(0);
    expect(stubs.auditEvents).toEqual([
      expect.objectContaining({
        op: "write",
        result: "denied",
        actor: "webhook:unknown",
      }),
    ]);
  });

  it("rate-limits webhook ingress before body dispatch without audit amplification", async () => {
    const original = stubs.deps.webhookThrottle;
    stubs.deps.webhookThrottle = {
      consume: async () => ({ allowed: false, retryAfterSec: 30 }),
    };
    try {
      const res = await fetch(base + "/v1/webhooks/sources/01SOURCE", {
        method: "POST",
        headers: {
          "x-halomem-timestamp": "1784100000",
          "x-halomem-signature": "sha256=" + "a".repeat(64),
        },
        body: JSON.stringify({ records: [{ id: "evt", text: "blocked" }] }),
      });
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe("30");
      expect(stubs.webhookCalls).toHaveLength(0);
      expect(stubs.auditEvents).toHaveLength(0);
    } finally {
      stubs.deps.webhookThrottle = original;
    }
  });

  it("routes an authenticated CSV snapshot import with the resolved owner identity", async () => {
    const payload = {
      csv: "id,note\nr1,remember",
      mapping: { idColumn: "id", textColumns: ["note"] },
    };
    const res = await post(
      "/v1/admin/sources/01SOURCE/import-csv",
      payload,
      TENANT_OWNER_KEY,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ records: 1, stored: 1, errors: [] });
    expect(stubs.adminCalls).toEqual([
      {
        op: "importCsvSource",
        args: ["01SOURCE", payload],
        identity: TENANT_OWNER,
      },
    ]);
  });

  it("accepts a manual source sync for durable background execution", async () => {
    const res = await post(
      "/v1/admin/sources/01SOURCE/sync",
      {},
      TENANT_OWNER_KEY,
    );

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({
      accepted: true,
      jobId: "source-sync:manual:01SOURCE",
      status: "queued",
    });
    expect(stubs.adminCalls).toEqual([
      {
        op: "syncSource",
        args: ["01SOURCE"],
        identity: TENANT_OWNER,
      },
    ]);
  });

  it("serves requests through the exported serverless request handler", async () => {
    const direct = createServer((req, res) => {
      void handleHttpRequest(stubs.deps, req, res);
    });
    const port = await new Promise<number>((resolve, reject) => {
      direct.once("error", reject);
      direct.listen(0, "127.0.0.1", () => {
        const address = direct.address();
        resolve(
          typeof address === "object" && address !== null ? address.port : 0,
        );
      });
    });

    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
    } finally {
      await new Promise<void>((resolve, reject) => {
        direct.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });

  // --- 401 paths -----------------------------------------------------------

  it("no Authorization header → 401 JSON error, audited denied as actor 'unknown'", async () => {
    const res = await post("/v1/mem/search", { query: "x" });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.code).toBe("unauthorized");
    expect(body.error).toBeTruthy();

    expect(stubs.syscallCalls).toHaveLength(0);
    expect(stubs.auditEvents).toHaveLength(1);
    const evt = stubs.auditEvents[0];
    expect(evt.result).toBe("denied");
    expect(evt.actor).toBe("unknown");
    expect(evt.op).toBe("search"); // attempted route's op
  });

  it("unknown key → 401 audited; non-hm_ token never reaches auth.resolve", async () => {
    const res = await post(
      "/v1/mem/read",
      { id: "01X" },
      "hm_" + "f".repeat(40),
    );
    expect(res.status).toBe(401);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].result).toBe("denied");
    expect(stubs.auditEvents[0].op).toBe("read");
    expect(stubs.resolveCalls).toHaveLength(1);

    const res2 = await post("/v1/mem/read", { id: "01X" }, "not-a-halomem-key");
    expect(res2.status).toBe(401);
    expect(stubs.resolveCalls).toHaveLength(1); // resolve NOT called again
    expect(stubs.auditEvents).toHaveLength(2);
  });

  it("GET /metrics without auth → 401 audited with op 'stats'", async () => {
    const res = await fetch(base + "/metrics");
    expect(res.status).toBe(401);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].op).toBe("stats");
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  // --- identity comes from the key, never the body --------------------------

  it("good key routes to the syscall with the RESOLVED identity", async () => {
    const res = await post(
      "/v1/mem/search",
      { query: "roadmap", k: 3 },
      MEMBER_KEY,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ns: string };
    expect(body.ns).toBe("org/team-a");

    expect(stubs.syscallCalls).toHaveLength(1);
    const call = stubs.syscallCalls[0];
    expect(call.op).toBe("search");
    expect(call.identity).toEqual(MEMBER); // resolved, not body-supplied
    expect(call.payload).toEqual({ query: "roadmap", k: 3 });
  });

  it("every mem route dispatches to its own syscall", async () => {
    for (const op of [
      "read",
      "search",
      "write",
      "fault",
      "stats",
      "assemble",
      "pin",
      "unpin",
      "share",
    ]) {
      const res = await post(`/v1/mem/${op}`, {}, MEMBER_KEY);
      expect(res.status).toBe(200);
    }
    expect(stubs.syscallCalls.map((c) => c.op)).toEqual([
      "read",
      "search",
      "write",
      "fault",
      "stats",
      "assemble",
      "pin",
      "unpin",
      "share",
    ]);
  });

  it("body containing 'namespace' → 400 'namespace comes from your key'", async () => {
    const res = await post(
      "/v1/mem/write",
      { namespace: "org/team-b", scope: "team", content: "steal" },
      MEMBER_KEY,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("namespace comes from your key");
    expect(stubs.syscallCalls).toHaveLength(0);
    expect(stubs.auditEvents).toEqual([
      expect.objectContaining({
        op: "write",
        result: "denied",
        actor: MEMBER.actor,
      }),
    ]);
  });

  it("body containing 'actor' → 400 as well", async () => {
    const res = await post(
      "/v1/mem/search",
      { query: "x", actor: "mallory" },
      MEMBER_KEY,
    );
    expect(res.status).toBe(400);
    expect(stubs.syscallCalls).toHaveLength(0);
    expect(stubs.auditEvents).toEqual([
      expect.objectContaining({
        op: "search",
        result: "denied",
        actor: MEMBER.actor,
      }),
    ]);
  });

  it("invalid JSON body → 400 JSON error", async () => {
    const res = await fetch(base + "/v1/mem/search", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${MEMBER_KEY}`,
      },
      body: "{nope",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: string };
    expect(body.code).toBe("invalid_json");
  });

  it("unknown mem route → 404", async () => {
    const res = await post("/v1/mem/drop_tables", {}, MEMBER_KEY);
    expect(res.status).toBe(404);
  });

  // --- metrics -------------------------------------------------------------

  it("GET /metrics with any authenticated role → snapshot", async () => {
    const res = await fetch(base + "/metrics", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ uptimeMs: 42, ops: {} });
  });

  // --- admin role gate -----------------------------------------------------

  it("member reads its scoped console routes (Home, Memory Map, usage, accuracy); other admin routes 403", async () => {
    const overview = await fetch(base + "/v1/admin/overview", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    const memoryMap = await fetch(
      base + "/v1/admin/memory-map?namespace=org%2Fteam-a",
      { headers: { authorization: `Bearer ${MEMBER_KEY}` } },
    );
    const people = await fetch(base + "/v1/admin/people", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });

    expect(overview.status).toBe(200);
    expect(memoryMap.status).toBe(200);
    expect(people.status).toBe(403);
    expect(stubs.adminCalls.map((call) => call.op)).toEqual([
      "overview",
      "memoryMap",
    ]);
    expect(stubs.adminCalls.every((call) => call.identity === MEMBER)).toBe(
      true,
    );
  });

  it("setup is platform-root-owner only", async () => {
    for (const key of [ADMIN_KEY, TENANT_OWNER_KEY, AUDITOR_KEY, MEMBER_KEY]) {
      const denied = await fetch(base + "/v1/admin/setup", {
        method: "POST",
        headers: {
          authorization: `Bearer ${key}`,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(denied.status).toBe(403);
    }

    const allowed = await fetch(base + "/v1/admin/setup", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ROOT_OWNER_KEY}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(allowed.status).toBe(201);
    expect(stubs.adminCalls.map((call) => call.op)).toEqual(["setup"]);
    expect(stubs.adminCalls[0].identity).toEqual(ROOT_OWNER);
  });

  it("setup capability, status, and explicit retry routes are root-owner only", async () => {
    for (const path of [
      "/v1/admin/setup/capabilities",
      "/v1/admin/setup/op-1",
    ]) {
      const denied = await fetch(base + path, {
        headers: { authorization: `Bearer ${TENANT_OWNER_KEY}` },
      });
      expect(denied.status).toBe(403);
    }
    const deniedRetry = await fetch(base + "/v1/admin/setup/op-1/retry", {
      method: "POST",
      headers: { authorization: `Bearer ${TENANT_OWNER_KEY}` },
    });
    expect(deniedRetry.status).toBe(403);

    const headers = { authorization: `Bearer ${ROOT_OWNER_KEY}` };
    const capabilities = await fetch(base + "/v1/admin/setup/capabilities", {
      headers,
    });
    const status = await fetch(base + "/v1/admin/setup/op-1", { headers });
    const retry = await fetch(base + "/v1/admin/setup/op-1/retry", {
      method: "POST",
      headers,
    });
    expect([capabilities.status, status.status, retry.status]).toEqual([
      200, 200, 200,
    ]);
    expect(stubs.adminCalls.map((call) => call.op)).toEqual([
      "setupCapabilities",
      "setupStatus",
      "setupRetry",
    ]);
    expect(stubs.adminCalls.every((call) => call.identity === ROOT_OWNER)).toBe(
      true,
    );
  });

  it("warm-store routes forward the resolved identity; member is route-gated 403", async () => {
    const denied = await fetch(base + "/v1/admin/warmstores", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    expect(denied.status).toBe(403);
    expect(stubs.adminCalls).toHaveLength(0);

    const headers = {
      authorization: `Bearer ${ROOT_OWNER_KEY}`,
      "content-type": "application/json",
    };
    const list = await fetch(base + "/v1/admin/warmstores", { headers });
    const flush = await fetch(base + "/v1/admin/warmstores/flush", {
      method: "POST",
      headers,
    });
    const rebuild = await fetch(base + "/v1/admin/warmstores/mem0/rebuild", {
      method: "POST",
      headers,
      body: JSON.stringify({ namespace: "acme" }),
    });
    expect([list.status, flush.status, rebuild.status]).toEqual([
      200, 200, 200,
    ]);
    expect(stubs.adminCalls.map((call) => call.op)).toEqual([
      "warmStores",
      "warmFlush",
      "warmRebuild",
    ]);
    expect(stubs.adminCalls[2].args).toEqual(["mem0", { namespace: "acme" }]);
    expect(stubs.adminCalls.every((call) => call.identity === ROOT_OWNER)).toBe(
      true,
    );

    // Method discipline: rebuild is POST-only.
    const wrongMethod = await fetch(
      base + "/v1/admin/warmstores/mem0/rebuild",
      {
        headers,
      },
    );
    expect(wrongMethod.status).toBe(405);
  });

  it("member on admin route → 403, audited denied with the resolved actor", async () => {
    // D50 carve-out: the KEY routes are open to a member (it may deploy agents
    // in its own scope, and AuthService.list scopes what it sees). Every other
    // admin route is still closed, which is what this case asserts.
    const res = await fetch(base + "/v1/admin/policy", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { code: string };
    expect(body.code).toBe("forbidden");

    expect(stubs.adminCalls).toHaveLength(0);
    expect(stubs.auditEvents).toHaveLength(1);
    const evt = stubs.auditEvents[0];
    expect(evt.result).toBe("denied");
    expect(evt.actor).toBe("alice");
    expect(evt.namespace).toBe("org/team-a");
  });

  it("D50: a member reaches the agent-key routes and nothing else", async () => {
    const list = await fetch(base + "/v1/admin/keys", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    expect(list.status).toBe(200);
    expect(stubs.adminCalls.map((call) => call.op)).toContain("listKeys");

    // …but not a mutation on some other admin surface.
    const denied = await fetch(base + "/v1/admin/pins", {
      method: "POST",
      headers: {
        authorization: `Bearer ${MEMBER_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ target: { kind: "memory", ref: "x" } }),
    });
    expect(denied.status).toBe(403);
  });

  it("agent admin denial is audited against the resolved badge id", async () => {
    const res = await fetch(base + "/v1/admin/keys", {
      headers: { authorization: `Bearer ${AGENT_KEY}` },
    });
    expect(res.status).toBe(403);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0]?.agentId).toBe(AGENT.keyId);
  });

  it("D50: only a MANAGER-level agent reaches the governance read allowlist", async () => {
    // The member-level agent badge is the default AGENT fixture.
    const memberLevel = await fetch(base + "/v1/admin/audit", {
      headers: { authorization: `Bearer ${AGENT_KEY}` },
    });
    expect(memberLevel.status).toBe(403);

    const managerLevel = await fetch(base + "/v1/admin/audit", {
      headers: { authorization: `Bearer ${MANAGER_AGENT_KEY}` },
    });
    // The manager-level badge clears the ROLE gate; this stub deps object has
    // no audit backend, so the request then 404s ("audit search unavailable")
    // instead of 200. Not-403 is exactly the assertion that matters here.
    expect(managerLevel.status).not.toBe(403);

    // …and the allowlist is READ-only, and does not include key issuance.
    const issue = await fetch(base + "/v1/admin/keys", {
      method: "POST",
      headers: {
        authorization: `Bearer ${MANAGER_AGENT_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        type: "assistant",
        actor: "x",
        namespace: "org/team-a",
      }),
    });
    expect(issue.status).toBe(403);
  });

  it("member PUT /v1/admin/policy → 403 audited (op 'write' for mutations)", async () => {
    const res = await fetch(base + "/v1/admin/policy", {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${MEMBER_KEY}`,
      },
      body: JSON.stringify({ yaml: "tokenBudget: 1" }),
    });
    expect(res.status).toBe(403);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].op).toBe("write");
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  it("S16: member reaches the public /v1/skills list, submit, and download routes", async () => {
    const headers = { authorization: `Bearer ${MEMBER_KEY}` };

    const list = await fetch(base + "/v1/skills", { headers });
    expect(list.status).toBe(200);
    expect(await list.json()).toEqual([]);

    const reg = await post(
      "/v1/skills",
      { skillKey: "demo", name: "Demo", definition: "do a demo" },
      MEMBER_KEY,
    );
    expect(reg.status).toBe(201);

    const dl = await fetch(base + "/v1/skills/01SKILL/download", { headers });
    expect(dl.status).toBe(200);
    expect(dl.headers.get("content-type")).toContain("text/markdown");
    expect(dl.headers.get("content-disposition")).toBe(
      'attachment; filename="demo.md"',
    );
    expect(await dl.text()).toContain('name: "Demo"');

    expect(stubs.syscallCalls.map((c) => c.op)).toEqual([
      "skills-list",
      "skill-register",
      "skill-download",
    ]);
    expect(stubs.syscallCalls.every((c) => c.identity === MEMBER)).toBe(true);
    expect(stubs.syscallCalls[2].payload).toEqual({ id: "01SKILL" });
  });

  it("S16: POST /v1/skills/invoke still exact-matches (not swallowed by /v1/skills routes)", async () => {
    const res = await post(
      "/v1/skills/invoke",
      { skillKey: "demo" },
      MEMBER_KEY,
    );
    expect(res.status).toBe(200);
    expect(stubs.syscallCalls).toHaveLength(1);
    expect(stubs.syscallCalls[0].op).toBe("skill_invoke");
  });

  it("S16: member on /v1/admin/skills/:id/approve → 403 audited, syscall never runs", async () => {
    const res = await post("/v1/admin/skills/01SKILL/approve", {}, MEMBER_KEY);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { code: string };
    expect(body.code).toBe("forbidden");
    expect(stubs.adminCalls).toHaveLength(0);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  it("S16: member cannot PATCH a skill through the admin editor", async () => {
    const res = await patch(
      "/v1/admin/skills/01SKILL",
      {
        name: "Forbidden edit",
        description: "",
        definition: "Member edit through an admin route.",
      },
      MEMBER_KEY,
    );
    expect(res.status).toBe(403);
    expect(stubs.adminCalls).toHaveLength(0);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  it("S16: admin approve/reject routes forward the resolved identity and body", async () => {
    const ap = await post("/v1/admin/skills/01SKILL/approve", {}, ADMIN_KEY);
    expect(ap.status).toBe(200);
    expect(await ap.json()).toEqual({
      id: "01SKILL",
      approvalStatus: "approved",
    });

    const rej = await post(
      "/v1/admin/skills/01SKILL/reject",
      { reason: "not safe for the fleet" },
      ADMIN_KEY,
    );
    expect(rej.status).toBe(200);
    expect(await rej.json()).toEqual({
      id: "01SKILL",
      approvalStatus: "rejected",
    });

    expect(stubs.adminCalls.map((c) => c.op)).toEqual([
      "approveSkill",
      "rejectSkill",
    ]);
    expect(stubs.adminCalls[0].args).toEqual(["01SKILL"]);
    expect(stubs.adminCalls[1].args).toEqual([
      "01SKILL",
      { reason: "not safe for the fleet" },
    ]);
    expect(stubs.adminCalls.every((c) => c.identity === ADMIN)).toBe(true);
  });

  it("S16: PATCH /v1/admin/skills/:id updates the selected skill with resolved identity", async () => {
    const body = {
      name: "Updated skill",
      description: "New description",
      definition: "New governed instructions.",
    };
    const res = await patch("/v1/admin/skills/01SKILL", body, ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      skill: { id: "01SKILLV2", supersedes: "01SKILL", ...body },
    });
    expect(stubs.adminCalls).toHaveLength(1);
    expect(stubs.adminCalls[0]).toEqual({
      op: "updateSkill",
      args: ["01SKILL", body],
      identity: ADMIN,
    });
  });

  it("admin key: full admin surface routes with the resolved identity", async () => {
    // GET policy (namespace via query param)
    let res = await fetch(base + "/v1/admin/policy?namespace=org%2Fteam-a", {
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.status).toBe(200);

    // PUT policy
    res = await fetch(base + "/v1/admin/policy", {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ADMIN_KEY}`,
      },
      body: JSON.stringify({
        namespace: "org/team-a",
        yaml: "tokenBudget: 500",
      }),
    });
    expect(res.status).toBe(200);

    // list / issue / revoke keys
    res = await fetch(base + "/v1/admin/keys", {
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.status).toBe(200);

    res = await post(
      "/v1/admin/keys",
      { namespace: "org/team-a", actor: "bot", role: "agent" },
      ADMIN_KEY,
    );
    expect(res.status).toBe(201);

    res = await fetch(base + "/v1/admin/keys/01SOMEKEY", {
      method: "DELETE",
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.status).toBe(200);

    expect(stubs.adminCalls.map((c) => c.op)).toEqual([
      "getPolicy",
      "setPolicy",
      "listKeys",
      "issueKey",
      "revokeKey",
    ]);
    expect(stubs.adminCalls[0].args).toEqual(["org/team-a"]);
    expect(stubs.adminCalls[1].args).toEqual([
      "org/team-a",
      "tokenBudget: 500",
    ]);
    expect(stubs.adminCalls[4].args).toEqual(["01SOMEKEY"]);
    for (const call of stubs.adminCalls) expect(call.identity).toEqual(ADMIN);
  });

  it("exposes scoped admin pin lifecycle and copy-on-write fork routes", async () => {
    const headers = { authorization: `Bearer ${ADMIN_KEY}` };
    const pinTarget = { kind: "memory", ref: "01ARZ3NDEKTSV4RRFFQ69G5FAV" };

    const listed = await fetch(base + "/v1/admin/pins?namespace=org%2Fteam-a", {
      headers,
    });
    const created = await fetch(base + "/v1/admin/pins", {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ target: pinTarget, namespace: "org/team-a" }),
    });
    const deleted = await fetch(base + "/v1/admin/pins/01PIN", {
      method: "DELETE",
      headers,
    });
    const forked = await fetch(base + "/v1/admin/mounts/fork", {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({
        origin: pinTarget,
        targetNamespace: "org/team-a",
        content: "Team-owned fork",
      }),
    });

    expect([
      listed.status,
      created.status,
      deleted.status,
      forked.status,
    ]).toEqual([200, 201, 200, 201]);
    expect(stubs.adminCalls.map((call) => call.op)).toEqual([
      "listPins",
      "createPin",
      "deletePin",
      "forkMount",
    ]);
    expect(stubs.adminCalls[0].args).toEqual(["org/team-a"]);
    expect(stubs.adminCalls[2].args).toEqual(["01PIN"]);
    expect(stubs.adminCalls.every((call) => call.identity === ADMIN)).toBe(
      true,
    );
  });

  it("forwards propose-cold evidence through the admin movement route", async () => {
    const targetRef = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const body = {
      action: "propose_cold",
      targetRef,
      idempotencyKey: "proposal-1",
      evidenceIds: [targetRef, "01BX5ZZKBKACTAV9WEVGEMMVRZ"],
    };
    const res = await post("/v1/admin/movement/run", body, ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(stubs.adminCalls).toEqual([
      { op: "runMovement", args: [body], identity: ADMIN },
    ]);
  });

  it("GET /v1/admin/certificate/:id forwards the RESOLVED identity (never drops it)", async () => {
    // The adapter previously called kernel.getCertificate(id) WITHOUT identity —
    // the P0 cross-tenant leak. The route must forward the server-resolved
    // Identity so the kernel can subtree-scope the read. Here an auditor reads;
    // the stub echoes the identity it received, proving it was forwarded.
    const res = await fetch(base + "/v1/admin/certificate/01CERTABC", {
      headers: { authorization: `Bearer ${AUDITOR_KEY}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      id: string;
      forwardedNamespace: string;
      forwardedRole: string;
    };
    expect(body.id).toBe("01CERTABC");
    // The identity forwarded to getCertificate is the RESOLVED auditor identity,
    // not a body/route value — this is what lets the kernel enforce the ACL.
    expect(body.forwardedNamespace).toBe(AUDITOR.namespace);
    expect(body.forwardedRole).toBe("auditor");
    expect(stubs.adminCalls).toHaveLength(1);
    expect(stubs.adminCalls[0].op).toBe("getCertificate");
    expect(stubs.adminCalls[0].args).toEqual(["01CERTABC"]);
    expect(stubs.adminCalls[0].identity).toEqual(AUDITOR);
  });

  it("member on GET /v1/admin/certificate/:id → 403 (owner/admin/auditor only)", async () => {
    const res = await fetch(base + "/v1/admin/certificate/01CERTABC", {
      headers: { authorization: `Bearer ${MEMBER_KEY}` },
    });
    expect(res.status).toBe(403);
    expect(stubs.adminCalls).toHaveLength(0);
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  it("PUT /v1/admin/policy without 'yaml' string → 400", async () => {
    const res = await fetch(base + "/v1/admin/policy", {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ADMIN_KEY}`,
      },
      body: JSON.stringify({ namespace: "org" }),
    });
    expect(res.status).toBe(400);
  });

  // --- error shape ---------------------------------------------------------

  it("syscall failure → redacted 500 JSON { error, code: 'internal' }", async () => {
    const failing = makeStubs();
    failing.deps.syscalls.memStats = async () => {
      throw new Error("db exploded");
    };
    const srv = createHttpServer(failing.deps);
    const port = await srv.start(0);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/v1/mem/stats`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${MEMBER_KEY}`,
        },
        body: "{}",
      });
      expect(res.status).toBe(500);
      const body = (await res.json()) as { error: string; code: string };
      expect(body.code).toBe("internal");
      expect(body.error).toBe("internal server error");
      expect(JSON.stringify(body)).not.toContain("db exploded");
    } finally {
      await srv.stop();
    }
  });

  it("maps pin validation, share denial, and movement idempotency conflicts to client statuses", async () => {
    const failing = makeStubs();
    failing.deps.syscalls.memPin = async () => {
      throw Object.assign(
        new Error("pin target must be a stable ULID reference"),
        {
          name: "PinValidationError",
        },
      );
    };
    failing.deps.syscalls.memShare = async () => {
      throw Object.assign(new Error("cross-tenant mounts are denied"), {
        name: "SharingAuthorizationError",
      });
    };
    failing.deps.admin.forkMount = async () => {
      throw Object.assign(
        new Error("fork origin must be a stable ULID reference"),
        {
          name: "SharingValidationError",
        },
      );
    };
    failing.deps.admin.runMovement = async () => {
      throw Object.assign(
        new Error("idempotencyKey is already bound to another movement action"),
        {
          name: "MovementConflictError",
        },
      );
    };
    const srv = createHttpServer(failing.deps);
    const port = await srv.start(0);
    const local = `http://127.0.0.1:${port}`;
    try {
      const headers = {
        authorization: `Bearer ${ADMIN_KEY}`,
        "content-type": "application/json",
      };
      const pin = await fetch(local + "/v1/mem/pin", {
        method: "POST",
        headers,
        body: "{}",
      });
      const share = await fetch(local + "/v1/mem/share", {
        method: "POST",
        headers,
        body: "{}",
      });
      const fork = await fetch(local + "/v1/admin/mounts/fork", {
        method: "POST",
        headers,
        body: "{}",
      });
      const movement = await fetch(local + "/v1/admin/movement/run", {
        method: "POST",
        headers,
        body: "{}",
      });
      expect([pin.status, share.status, fork.status, movement.status]).toEqual([
        400, 403, 400, 409,
      ]);
      await expect(pin.json()).resolves.toMatchObject({ code: "bad_request" });
      await expect(share.json()).resolves.toMatchObject({ code: "forbidden" });
      await expect(fork.json()).resolves.toMatchObject({ code: "bad_request" });
      await expect(movement.json()).resolves.toMatchObject({
        code: "conflict",
      });
    } finally {
      await srv.stop();
    }
  });

  // --- MCP Streamable HTTP -------------------------------------------------

  it("POST /mcp without auth → 401 audited; transport never sees the request", async () => {
    const res = await fetch(base + "/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      }),
    });
    expect(res.status).toBe(401);
    expect(stubs.mcpIdentities).toHaveLength(0);
    expect(stubs.auditEvents).toHaveLength(1);
    expect(stubs.auditEvents[0].result).toBe("denied");
  });

  it("authenticated /mcp initialize → per-request server built with resolved identity", async () => {
    const res = await fetch(base + "/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${MEMBER_KEY}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "vitest", version: "0.0.0" },
        },
      }),
    });
    expect(res.status).toBe(200);
    const responseText = await res.text();
    const jsonText = res.headers
      .get("content-type")
      ?.includes("text/event-stream")
      ? responseText
          .split("\n")
          .find((line) => line.startsWith("data: "))
          ?.slice(6)
      : responseText;
    expect(jsonText).toBeTruthy();
    const body = JSON.parse(jsonText!) as {
      result?: { serverInfo?: { name?: string } };
    };
    expect(body.result?.serverInfo?.name).toBe("halomem-test");

    expect(stubs.mcpIdentities).toHaveLength(1);
    expect(stubs.mcpIdentities[0]).toEqual(MEMBER);
  });

  it("negotiates MCP 2026-07-28 and serves stateless tool calls", async () => {
    const client = new Client(
      { name: "halomem-v2-test", version: "1.0.0" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    const transport = new StreamableHTTPClientTransport(
      new URL(base + "/mcp"),
      {
        requestInit: {
          headers: { authorization: `Bearer ${MEMBER_KEY}` },
        },
      },
    );

    try {
      await client.connect(transport);
      expect(client.getProtocolEra()).toBe("modern");
      await expect(client.listTools()).resolves.toMatchObject({
        tools: [{ name: "ping" }],
      });
      await expect(
        client.callTool({ name: "ping", arguments: {} }),
      ).resolves.toMatchObject({
        content: [{ type: "text", text: MEMBER.namespace }],
      });
      expect(stubs.mcpIdentities).toHaveLength(3);
      expect(stubs.mcpIdentities).toEqual([MEMBER, MEMBER, MEMBER]);
    } finally {
      await client.close();
    }
  });

  it("accepts a Copilot capability only on /mcp", async () => {
    const initialize = await fetch(base + "/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${COPILOT_CAPABILITY}`,
        "x-halomem-trace": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "x-halomem-turn": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "mastra-sidecar", version: "2" },
        },
      }),
    });
    expect(initialize.status).toBe(200);
    expect(stubs.mcpIdentities).toEqual([
      {
        ...MEMBER,
        assistantObservability: {
          traceId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
          turnId: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
          invocationId: "01ARZ3NDEKTSV4RRFFQ69G5FAX",
        },
      },
    ]);

    const replay = await post("/v1/mem/stats", {}, COPILOT_CAPABILITY);
    expect(replay.status).toBe(401);
    expect(stubs.syscallCalls).toHaveLength(0);
  });

  it("binds sensitive turn headers only for a Copilot capability", async () => {
    const headers = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-halomem-trace": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "x-halomem-turn": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
    };
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "vitest", version: "0.0.0" },
      },
    });

    const ordinary = await fetch(base + "/mcp", {
      method: "POST",
      headers: { ...headers, authorization: `Bearer ${MEMBER_KEY}` },
      body,
    });
    expect(ordinary.status).toBe(200);
    expect(stubs.mcpContexts.at(-1)).toBeUndefined();

    const delegated = await fetch(base + "/mcp", {
      method: "POST",
      headers: { ...headers, authorization: `Bearer ${COPILOT_CAPABILITY}` },
      body,
    });
    expect(delegated.status).toBe(200);
    expect(stubs.mcpContexts.at(-1)).toEqual({
      traceId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      tool: "halo-assistant-sidecar",
      sensitiveTurnId: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
    });

    const forged = await fetch(base + "/mcp", {
      method: "POST",
      headers: {
        ...headers,
        authorization: `Bearer ${COPILOT_CAPABILITY}`,
        "x-halomem-turn": "01ARZ3NDEKTSV4RRFFQ69G5FZZ",
      },
      body,
    });
    expect(forged.status).toBe(401);
  });
});
