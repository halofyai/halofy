import { afterEach, describe, expect, it } from "vitest";

import { createHttpServer, type HaloHttpServer, type HttpServerDeps } from "../src/http/server.js";
import type { Identity } from "../src/types.js";

const OWNER: Identity = {
  keyId: "owner-key",
  namespace: "acme",
  actor: "owner@acme.test",
  role: "owner",
};
const AGENT: Identity = {
  keyId: "agent-key",
  namespace: "acme/support",
  actor: "refund-agent",
  role: "agent",
};
const AUDITOR: Identity = {
  keyId: "auditor-key",
  namespace: "acme",
  actor: "auditor@acme.test",
  role: "auditor",
};
const OWNER_TOKEN = `hm_${"a".repeat(40)}`;
const AGENT_TOKEN = `hm_${"b".repeat(40)}`;
const AUDITOR_TOKEN = `hm_${"c".repeat(40)}`;

let server: HaloHttpServer | null = null;

afterEach(async () => {
  await server?.stop();
  server = null;
});

function fixtures() {
  const calls: Array<{ op: string; value: unknown; identity: Identity }> = [];
  const record = (op: string) => async (value: unknown, identity: Identity) => {
    calls.push({ op, value, identity });
    return { op, value };
  };
  const authzError = (message: string): Error => {
    const error = new Error(message);
    error.name = "AuthzError";
    return error;
  };
  const description = [{
    grantId: "grant-1",
    connectorId: "crm",
    allowedOperations: ["source-read"],
    allowedSourceRefs: ["refunds"],
    allowedFields: { refunds: ["id", "status"] },
    allowedPurposes: ["support"],
    maxRows: 10,
    maxBytes: 4_096,
    maxSensitivity: "confidential",
    expiresAt: null,
    policyVersion: 3,
    accessRequests: {
      enabled: true,
      maxDurationSeconds: 86_400,
      approvalTtlSeconds: 900,
      maxUsesCap: 100,
    },
    hint: "This badge may ask a human owner/admin for temporary extra access.",
  }];
  const deps = {
    auth: {
      resolve: async (key: string) => key === OWNER_TOKEN
        ? OWNER
        : key === AGENT_TOKEN
          ? AGENT
          : key === AUDITOR_TOKEN
            ? AUDITOR
            : null,
    },
    syscalls: {
      requestAgentAccess: record("agent-request"),
      listAgentAccessRequests: async (identity: Identity) => {
        calls.push({ op: "agent-list", value: null, identity });
        return [];
      },
      describeAgentAccess: async (identity: Identity) => {
        calls.push({ op: "describe-access", value: null, identity });
        if (identity.role !== "agent") throw authzError("agent role required");
        return description;
      },
      sourceRead: async (value: unknown, identity: Identity) => {
        calls.push({ op: "source-read", value, identity });
        throw authzError(
          "governed source read denied: 'orders' is outside this badge's scope. " +
          "This badge may request temporary access - call request_access (MCP) or " +
          "POST /v1/agent/access-requests with the same grantId, connectorId, sourceRef, plus " +
          "requestedFields, requestedRows, requestedBytes, justification, and " +
          "requestedDurationSeconds (at most 3600 seconds). " +
          "A human owner/admin must approve before any read succeeds.",
        );
      },
    },
    admin: {
      issueAgentBadge: record("issue-badge"),
      listAgentAccessEvents: record("events"),
      listAgentAccessAlerts: record("alerts"),
      acknowledgeAgentAccessAlert: record("acknowledge"),
      listAgentAccessRequests: record("requests"),
      approveAgentAccessRequest: async (id: string, body: unknown, identity: Identity) => {
        calls.push({ op: "approve", value: { id, body }, identity });
        return { id, body };
      },
      denyAgentAccessRequest: async (id: string, body: unknown, identity: Identity) => {
        calls.push({ op: "deny", value: { id, body }, identity });
        return { id, body };
      },
    },
    metrics: { snapshot: () => ({}) },
    audit: { append: async () => {} },
    buildMcpServer: () => { throw new Error("unused"); },
    webhooks: { ingest: async () => ({}) },
  } as unknown as HttpServerDeps;
  return { deps, calls, description };
}

async function start(deps: HttpServerDeps): Promise<string> {
  server = createHttpServer(deps);
  const port = await server.start(0);
  return `http://127.0.0.1:${port}`;
}

function auth(token: string, json = false): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    ...(json ? { "content-type": "application/json" } : {}),
  };
}

describe("M8A oversight HTTP surface", () => {
  it("dispatches the atomic badge bundle with server-owned role and key binding", async () => {
    const { deps, calls } = fixtures();
    const base = await start(deps);
    const body = {
      badge: { actor: "refund-agent", namespace: "acme/support" },
      grant: {
        connectorId: "crm",
        allowedOperations: ["source-read"],
        allowedSourceRefs: ["customers"],
        allowedFields: { customers: ["id", "status"] },
        allowedPurposes: ["refunds"],
        maxSensitivity: "confidential",
        maxRows: 10,
        maxBytes: 4096,
        expiresAt: null,
        oversight: {
          maxRequestsPerMinute: 30,
          usageAlertThreshold: 50,
          deniedAlertThreshold: 1,
          recipientRoles: ["owner", "admin"],
          accessRequests: "allowed",
          approvalTtlSeconds: 900,
        },
      },
    };
    const response = await fetch(`${base}/v1/admin/agent-badges`, {
      method: "POST",
      headers: auth(OWNER_TOKEN, true),
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(201);
    expect(calls).toContainEqual({ op: "issue-badge", value: body, identity: OWNER });
  });

  it("exposes exact agent requests and scoped admin decisions", async () => {
    const { deps, calls } = fixtures();
    const base = await start(deps);
    const request = {
      grantId: "grant-1",
      connectorId: "crm",
      sourceRef: "refunds",
      purpose: "support",
      requestedFields: ["id", "status"],
      requestedRows: 5,
      requestedBytes: 2048,
      justification: "Resolve ticket 42",
      requestedDurationSeconds: 600,
    };
    const created = await fetch(`${base}/v1/agent/access-requests`, {
      method: "POST",
      headers: auth(AGENT_TOKEN, true),
      body: JSON.stringify(request),
    });
    expect(created.status).toBe(201);
    const listed = await fetch(`${base}/v1/agent/access-requests`, {
      headers: auth(AGENT_TOKEN),
    });
    expect(listed.status).toBe(200);

    const adminCases: Array<[string, string, unknown, string]> = [
      ["GET", "/v1/admin/agent-access/events?keyId=agent-key&limit=25", null, "events"],
      ["GET", "/v1/admin/agent-access/alerts?status=open&limit=25", null, "alerts"],
      ["GET", "/v1/admin/agent-access/requests?status=pending&limit=25", null, "requests"],
      ["POST", "/v1/admin/agent-access/alerts/alert-1/acknowledge", {}, "acknowledge"],
      ["POST", "/v1/admin/agent-access/requests/request-1/approve", { durationSeconds: 300, maxUses: 1 }, "approve"],
      ["POST", "/v1/admin/agent-access/requests/request-1/deny", { note: "Owner data excluded" }, "deny"],
    ];
    for (const [method, path, value, op] of adminCases) {
      const response = await fetch(`${base}${path}`, {
        method,
        headers: auth(OWNER_TOKEN, value !== null),
        ...(value !== null ? { body: JSON.stringify(value) } : {}),
      });
      expect(response.status, `${method} ${path}`).toBe(200);
      expect(calls.some((call) => call.op === op && call.identity === OWNER)).toBe(true);
    }
  });

  it("lets auditors read oversight but never mutate it", async () => {
    const { deps } = fixtures();
    const base = await start(deps);
    for (const path of [
      "/v1/admin/agent-access/events",
      "/v1/admin/agent-access/alerts",
      "/v1/admin/agent-access/requests",
    ]) {
      const response = await fetch(`${base}${path}`, { headers: auth(AUDITOR_TOKEN) });
      expect(response.status, path).toBe(200);
    }
    const mutate = await fetch(
      `${base}/v1/admin/agent-access/requests/request-1/approve`,
      { method: "POST", headers: auth(AUDITOR_TOKEN, true), body: "{}" },
    );
    expect(mutate.status).toBe(403);
  });
});

describe("M8A describe-access HTTP surface", () => {
  it("serves the badge's own access description to the agent role", async () => {
    const { deps, calls, description } = fixtures();
    const base = await start(deps);
    const response = await fetch(`${base}/v1/agent/describe-access`, {
      headers: auth(AGENT_TOKEN),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(description);
    expect(calls).toContainEqual({ op: "describe-access", value: null, identity: AGENT });

    const rejected = await fetch(`${base}/v1/agent/describe-access`, {
      method: "POST",
      headers: auth(AGENT_TOKEN, true),
      body: "{}",
    });
    expect(rejected.status).toBe(405);
  });

  it("returns 403 for non-agent roles", async () => {
    const { deps } = fixtures();
    const base = await start(deps);
    for (const token of [OWNER_TOKEN, AUDITOR_TOKEN]) {
      const response = await fetch(`${base}/v1/agent/describe-access`, {
        headers: auth(token),
      });
      expect(response.status).toBe(403);
      const body = await response.json() as { error: string; code: string };
      expect(body.code).toBe("forbidden");
      expect(body.error).toContain("agent role required");
    }
  });

  it("carries the escalation hint in the 403 denial body", async () => {
    const { deps } = fixtures();
    const base = await start(deps);
    const response = await fetch(`${base}/v1/agent/source-read`, {
      method: "POST",
      headers: auth(AGENT_TOKEN, true),
      body: JSON.stringify({
        grantId: "grant-1",
        connectorId: "crm",
        sourceRef: "orders",
        purpose: "support",
        query: "Ada",
      }),
    });
    expect(response.status).toBe(403);
    const body = await response.json() as { error: string; code: string };
    expect(body.code).toBe("forbidden");
    expect(body.error).toContain("'orders' is outside this badge's scope");
    expect(body.error).toContain("request_access");
    expect(body.error).toContain("POST /v1/agent/access-requests");
  });
});
