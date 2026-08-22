/**
 * M5 module C — console transport tests (static serving + cookie sessions).
 *
 * Boots the node:http server on an ephemeral port with hand-rolled deps (zero
 * network beyond loopback, no DB, no kernel) plus a real tmp `console/` dir.
 * Asserts:
 *   - GET /console/ serves index.html (clean URLs: /console → 308 /console/,
 *     *.html → 308 extensionless); no auth for static;
 *   - GET /console/../server.ts (traversal) → 403; a missing file → 404;
 *   - POST /auth/login sets an HttpOnly halomem_session cookie + returns { user };
 *   - a GET-equivalent /v1/mem/stats carrying ONLY that cookie resolves via
 *     resolveSession and succeeds with the session Identity;
 *   - GET /auth/me returns the resolved identity;
 *   - POST /auth/logout clears the cookie (Max-Age=0) and invalidates the token;
 *   - a wrong password → 401, no cookie set (no enumeration oracle).
 */

import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import type { AuditEvent, Identity } from "../src/types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OWNER: Identity = {
  keyId: "sess_01OWNER",
  namespace: "acme",
  actor: "owner@acme.test",
  role: "owner",
};

const GOOD_EMAIL = "owner@acme.test";
const GOOD_PASSWORD = "correct horse battery staple";
const LIVE_TOKEN = "opaque-random-token-abc123";

interface SyscallCall {
  op: string;
  payload: Record<string, unknown>;
  identity: Identity;
}

/** Hand-rolled deps + a set of live session tokens the stub honours. */
function makeStubs(consoleDir: string) {
  const auditEvents: AuditEvent[] = [];
  const syscallCalls: SyscallCall[] = [];
  const resolveSessionCalls: string[] = [];
  const loginCalls: { email: string; password: string }[] = [];
  const logoutCalls: string[] = [];
  const handoffCalls: Identity[] = [];
  const knowledgeSyncCalls: Array<{ body: Record<string, unknown>; identity: Identity }> = [];
  const knowledgeSyncStatusCalls: Identity[] = [];
  // Tokens currently valid — logout removes from here (server-side invalidation).
  const liveTokens = new Set<string>([]);

  const syscall =
    (op: string) =>
    async (payload: Record<string, unknown>, identity: Identity): Promise<unknown> => {
      syscallCalls.push({ op, payload, identity });
      return { op, echo: payload, ns: identity.namespace, actor: identity.actor };
    };

  const deps: HttpServerDeps = {
    consoleDir,
    secureCookies: false,
    auth: {
      async resolve(key): Promise<Identity | null> {
        return key === `hm_${"a".repeat(40)}` ? OWNER : null;
      },
      async resolveSession(token: string): Promise<Identity | null> {
        resolveSessionCalls.push(token);
        return liveTokens.has(token) ? OWNER : null;
      },
      async login(email, password) {
        loginCalls.push({ email, password });
        if (email === GOOD_EMAIL && password === GOOD_PASSWORD) {
          liveTokens.add(LIVE_TOKEN);
          return {
            token: LIVE_TOKEN,
            user: { id: "u1", email, namespace: OWNER.namespace, role: OWNER.role, status: "active" },
          };
        }
        return null;
      },
      async logout(token) {
        logoutCalls.push(token);
        liveTokens.delete(token);
      },
      async profile() {
        return {
          homeNamespace: OWNER.namespace,
          displayName: "Owner One",
          teams: [],
        };
      },
    },
    syscalls: {
      memRead: syscall("read"),
      memSearch: syscall("search"),
      memWrite: syscall("write"),
      memFault: syscall("fault"),
      memStats: syscall("stats"),
      memAssemble: syscall("assemble"),
    },
    admin: {
      async getPolicy() {
        return {};
      },
      async setPolicy() {
        return {};
      },
      async listKeys() {
        return [];
      },
      async issueKey() {
        return {};
      },
      async revokeKey() {
        return {};
      },
      async queueKnowledgeSync(body, identity) {
        knowledgeSyncCalls.push({ body, identity });
        return { status: "queued", scope: body.scope, queuedSpaces: [] };
      },
      async knowledgeSyncStatus(identity) {
        knowledgeSyncStatusCalls.push(identity);
        return {
          runs: [{
            id: "team-support",
            name: "Support",
            status: "queued",
            queuedAt: "2026-07-22T04:20:00.000Z",
            startedAt: null,
            completedAt: null,
            nextRunAt: null,
            lastRunStatus: null,
            lastError: null,
            processed: null,
            proposals: null,
            hasMore: null,
          }],
          totals: { queued: 1, running: 0, completed: 0, failed: 0, scheduled: 0 },
          retentionDays: 30,
        };
      },
    },
    metrics: { snapshot: () => ({ ok: true }) },
    audit: {
      async append(event: AuditEvent) {
        auditEvents.push(event);
      },
    },
    buildMcpServer() {
      throw new Error("not used in this suite");
    },
  };

  return {
    deps,
    auditEvents,
    syscallCalls,
    resolveSessionCalls,
    loginCalls,
    logoutCalls,
    handoffCalls,
    knowledgeSyncCalls,
    knowledgeSyncStatusCalls,
    liveTokens,
  };
}

/** Pull the Set-Cookie header lines from a fetch Response, robust to combining. */
function setCookies(res: Response): string[] {
  const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(res.headers);
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

/** The value of the halomem_session cookie in a Set-Cookie line, or null. */
function sessionCookieLine(lines: string[]): string | null {
  return lines.find((l) => l.startsWith(`${SESSION_COOKIE}=`)) ?? null;
}

/**
 * Send a raw HTTP/1.1 GET with an EXACT request-target — no client-side path
 * normalization (fetch/undici collapses `..` before the request leaves). This
 * is the only way to prove serveStatic itself rejects a traversal target that
 * literally contains `/console/../server.ts`. Returns { status, body }.
 */
function rawGet(port: number, target: string): Promise<{ status: number; body: string }> {
  return new Promise((resolveP, reject) => {
    const sock = connect(port, "127.0.0.1", () => {
      sock.write(
        `GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
      );
    });
    const chunks: Buffer[] = [];
    sock.on("data", (c) => chunks.push(c));
    sock.on("error", reject);
    sock.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const sep = raw.indexOf("\r\n\r\n");
      const head = sep >= 0 ? raw.slice(0, sep) : raw;
      const body = sep >= 0 ? raw.slice(sep + 4) : "";
      const statusLine = head.split("\r\n")[0] ?? "";
      const status = Number(statusLine.split(" ")[1] ?? "0");
      resolveP({ status, body });
    });
  });
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("console transport (module C)", () => {
  let root: string;
  let consoleDir: string;
  let stubs: ReturnType<typeof makeStubs>;
  let server: HaloHttpServer;
  let base: string;
  let port: number;

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "halomem-console-"));
    consoleDir = join(root, "console");
    mkdirSync(consoleDir, { recursive: true });
    writeFileSync(
      join(consoleDir, "index.html"),
      "<!doctype html><title>control room</title><h1>screens land in M5 part 2</h1>",
    );
    writeFileSync(join(consoleDir, "app.css"), "body{color:#111}");
    // A file OUTSIDE the console dir that traversal would try to reach.
    writeFileSync(join(root, "server.ts"), "SECRET SOURCE - must never be served");

    stubs = makeStubs(consoleDir);
    server = createHttpServer(stubs.deps);
    port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
    rmSync(root, { recursive: true, force: true });
  });

  beforeEach(() => {
    stubs.auditEvents.length = 0;
    stubs.syscallCalls.length = 0;
    stubs.resolveSessionCalls.length = 0;
    stubs.loginCalls.length = 0;
    stubs.logoutCalls.length = 0;
    stubs.handoffCalls.length = 0;
    stubs.knowledgeSyncCalls.length = 0;
    stubs.knowledgeSyncStatusCalls.length = 0;
    stubs.liveTokens.clear();
  });

  // --- static serving ------------------------------------------------------

  it("GET /console 308-redirects to the canonical /console/ with no auth", async () => {
    const res = await fetch(base + "/console", { redirect: "manual" });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe("/console/");
    expect(stubs.auditEvents).toHaveLength(0);
  });

  it("GET /console/ (canonical) serves index.html", async () => {
    const res = await fetch(base + "/console/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("control room");
  });

  it("GET /console/index.html 308-redirects to /console/ (clean URLs)", async () => {
    const res = await fetch(base + "/console/index.html", { redirect: "manual" });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe("/console/");
    // Following the redirect lands on the served index.html.
    const followed = await fetch(base + "/console/index.html");
    expect(followed.status).toBe(200);
    expect(await followed.text()).toContain("screens land in M5 part 2");
  });

  it("GET /console/app.css served with the css content-type", async () => {
    const res = await fetch(base + "/console/app.css");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/css");
    expect(res.headers.get("cache-control")).toBe("public, max-age=0, must-revalidate");
    const etag = res.headers.get("etag");
    expect(etag).toMatch(/^W\/"[a-f0-9]+-[a-f0-9]+"$/);

    const revalidated = await fetch(base + "/console/app.css", {
      headers: { "if-none-match": etag! },
    });
    expect(revalidated.status).toBe(304);
    expect(await revalidated.text()).toBe("");
  });

  it("traversal via /console/../server.ts never serves the source (defense in depth)", async () => {
    // A raw socket sends the EXACT target (fetch/undici collapses `..` client
    // side). Plain `..` — and even `%2e%2e` — is normalized away by the WHATWG
    // URL parser in the router BEFORE serveStatic: `/server.ts` is not a route
    // → a rejection, and the source is never served.
    for (const t of ["/console/../server.ts", "/console/%2e%2e/server.ts"]) {
      const r = await rawGet(port, t);
      expect(r.status).not.toBe(200);
      expect(r.body).not.toContain("SECRET SOURCE");
    }

    // An ENCODED slash (`%2f`) survives URL parsing — pathname keeps the whole
    // `%2e%2e%2fserver.ts` — so this form actually reaches serveStatic, which
    // decodeURIComponent's to `../server.ts` and rejects the escape with 403.
    // This is the serveStatic traversal guard proper.
    const encoded = await rawGet(port, "/console/%2e%2e%2fserver.ts");
    expect(encoded.status).toBe(403);
    expect(encoded.body).not.toContain("SECRET SOURCE");
  });

  it("GET a missing console file → 404", async () => {
    const res = await fetch(base + "/console/nope.html");
    expect(res.status).toBe(404);
  });

  // --- login / cookie ------------------------------------------------------

  it("POST /auth/login sets an HttpOnly halomem_session cookie + returns { user }", async () => {
    const res = await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string; role: string } };
    expect(body.user.email).toBe(GOOD_EMAIL);
    expect(body.user.role).toBe("owner");

    const line = sessionCookieLine(setCookies(res));
    expect(line).not.toBeNull();
    expect(line!).toContain(`${SESSION_COOKIE}=`);
    expect(line!).toContain("HttpOnly");
    expect(line!.toLowerCase()).toContain("samesite=lax");
    expect(line!).toContain("Path=/");
    expect(line!).toContain("Max-Age=");
    // secureCookies:false → no Secure attribute.
    expect(line!).not.toContain("Secure");
    expect(stubs.loginCalls).toEqual([{ email: GOOD_EMAIL, password: GOOD_PASSWORD }]);
  });

  it("wrong password → 401 and sets NO session cookie (no enumeration oracle)", async () => {
    const res = await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: "wrong" }),
    });
    expect(res.status).toBe(401);
    expect(sessionCookieLine(setCookies(res))).toBeNull();
  });

  it("unknown email → 401, indistinguishable from wrong password", async () => {
    const res = await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "ghost@acme.test", password: GOOD_PASSWORD }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { code: string };
    expect(body.code).toBe("unauthorized");
  });

  // --- cookie-authenticated syscall ----------------------------------------

  it("POST /v1/mem/stats with ONLY the session cookie resolves via resolveSession and succeeds", async () => {
    // 1. login to obtain the cookie
    const login = await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    expect(login.status).toBe(200);
    const cookie = `${SESSION_COOKIE}=${LIVE_TOKEN}`;

    // 2. call a syscall carrying ONLY that cookie — no Authorization header
    const res = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: "{}",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ns: string; actor: string };
    expect(body.ns).toBe(OWNER.namespace);
    expect(body.actor).toBe(OWNER.actor);

    expect(stubs.resolveSessionCalls).toContain(LIVE_TOKEN);
    expect(stubs.syscallCalls).toHaveLength(1);
    expect(stubs.syscallCalls[0].identity).toEqual(OWNER);
  });

  // The server slides `sessions.expires_at` on every resolve. If the cookie
  // were not re-sent, the browser would drop it on a fixed schedule from
  // sign-in and stop presenting a session the server still considers live —
  // which is exactly the "signed out after closing the browser" bug.
  it("a cookie-authenticated request re-sends the session cookie so its window slides", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });

    const res = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
      },
      body: "{}",
    });
    expect(res.status).toBe(200);

    const line = sessionCookieLine(setCookies(res));
    expect(line).not.toBeNull();
    // Same opaque token, same attributes — only the window moves.
    expect(line!).toContain(`${SESSION_COOKIE}=${LIVE_TOKEN}`);
    expect(line!).toContain("HttpOnly");
    expect(line!).toContain("Max-Age=");
    expect(line!).not.toContain("Max-Age=0");
  });

  it("a bearer-key request never re-sends a session cookie", async () => {
    const res = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer hm_${"a".repeat(40)}`,
      },
      body: "{}",
    });
    expect(res.status).toBe(200);
    expect(sessionCookieLine(setCookies(res))).toBeNull();
  });

  it("cookie caller is held to the D9 no-namespace-in-body rule too → 400", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    const res = await fetch(base + "/v1/mem/write", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
      },
      body: JSON.stringify({ namespace: "globex", scope: "org", content: "x" }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("namespace comes from your key");
    expect(stubs.syscallCalls).toHaveLength(0);
  });

  it("POST /v1/admin/knowledge-sync accepts a server-resolved target and rejects raw namespaces", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    const headers = {
      "content-type": "application/json",
      cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
      origin: base,
    };

    const accepted = await fetch(base + "/v1/admin/knowledge-sync", {
      method: "POST",
      headers,
      body: JSON.stringify({ scope: "team", teamId: "team-support" }),
    });
    expect(accepted.status).toBe(202);
    expect(stubs.knowledgeSyncCalls).toEqual([{
      body: { scope: "team", teamId: "team-support" },
      identity: OWNER,
    }]);

    const rejected = await fetch(base + "/v1/admin/knowledge-sync", {
      method: "POST",
      headers,
      body: JSON.stringify({ scope: "team", teamId: "team-support", namespace: "acme/support" }),
    });
    expect(rejected.status).toBe(400);
    expect(stubs.knowledgeSyncCalls).toHaveLength(1);
  });

  it("GET /v1/admin/knowledge-sync returns server-resolved sync activity", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });

    const res = await fetch(base + "/v1/admin/knowledge-sync", {
      headers: { cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}` },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      runs: [{
        id: "team-support",
        name: "Support",
        status: "queued",
        queuedAt: "2026-07-22T04:20:00.000Z",
        startedAt: null,
        completedAt: null,
        nextRunAt: null,
        lastRunStatus: null,
        lastError: null,
        processed: null,
        proposals: null,
        hasMore: null,
      }],
      totals: { queued: 1, running: 0, completed: 0, failed: 0, scheduled: 0 },
      retentionDays: 30,
    });
    expect(stubs.knowledgeSyncStatusCalls).toEqual([OWNER]);
  });

  it("a stale/unknown session cookie → 401 (expiry enforced server-side by resolveSession)", async () => {
    const res = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=never-issued`,
      },
      body: "{}",
    });
    expect(res.status).toBe(401);
    expect(stubs.syscallCalls).toHaveLength(0);
    expect(stubs.auditEvents.at(-1)?.result).toBe("denied");
  });

  // --- /auth/me ------------------------------------------------------------

  it("GET /auth/me returns the resolved session identity", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    const res = await fetch(base + "/auth/me", {
      headers: { cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}` },
    });
    expect(res.status).toBe(200);
    // M10 (D41/E1, CONTRACTS-M10-ACCESS): the session payload carries the
    // PRODUCT role — internal `owner` crosses the boundary as `root`. The
    // previous exact assertion pinned the pre-M10 internal role; the
    // contract supersedes it (fixed per the "test contradicts a contract"
    // rule — the identity itself is unchanged internally).
    expect(await res.json()).toEqual({
      keyId: OWNER.keyId,
      namespace: OWNER.namespace,
      actor: OWNER.actor,
      displayName: "Owner One",
      role: "root",
    });
  });

  it("GET /auth/me with no credential → 401", async () => {
    const res = await fetch(base + "/auth/me");
    expect(res.status).toBe(401);
  });

  it("exposes and performs the Halo Agents handoff only for a human session", async () => {
    stubs.deps.haloAgents = {
      issuer: base,
      destination: "https://updatedev.halofy.ai/auth/halomem",
      createAssertion(identity) {
        stubs.handoffCalls.push(identity);
        return "opaque";
      },
    };
    try {
      await fetch(base + "/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
      });

      const me = await fetch(base + "/auth/me", {
        headers: { cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}` },
      });
      expect(await me.json()).toMatchObject({ capabilities: { haloAgents: true } });

      const handoff = await fetch(base + "/auth/halo-agents", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
          origin: base,
        },
        body: "{}",
      });
      expect(handoff.status).toBe(200);
      expect(await handoff.json()).toEqual({
        destination: "https://updatedev.halofy.ai/auth/halomem",
        assertion: "opaque",
      });
      expect(handoff.headers.get("cache-control")).toBe("no-store");
      expect(handoff.headers.get("referrer-policy")).toBe("no-referrer");
      expect(stubs.handoffCalls).toEqual([OWNER]);
      expect(stubs.auditEvents.at(-1)).toMatchObject({
        actor: OWNER.actor,
        namespace: OWNER.namespace,
        op: "read",
        purpose: "halo-agents-sso-handoff",
        result: "ok",
      });

      const bearer = await fetch(base + "/auth/halo-agents", {
        method: "POST",
        headers: {
          authorization: `Bearer hm_${"a".repeat(40)}`,
          origin: base,
        },
      });
      expect(bearer.status).toBe(403);
      expect(stubs.handoffCalls).toHaveLength(1);
      expect(stubs.auditEvents.at(-1)).toMatchObject({
        result: "denied",
        purpose: "halo-agents-sso-handoff",
      });

      const crossSite = await fetch(base + "/auth/halo-agents", {
        method: "POST",
        headers: {
          cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
          origin: "https://attacker.example",
        },
      });
      expect(crossSite.status).toBe(403);
      expect(stubs.handoffCalls).toHaveLength(1);

      const malformed = await fetch(base + "/auth/halo-agents", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
          origin: base,
        },
        body: "{",
      });
      expect(malformed.status).toBe(400);
      expect(stubs.handoffCalls).toHaveLength(1);
      expect(stubs.auditEvents.at(-1)).toMatchObject({
        actor: OWNER.actor,
        namespace: OWNER.namespace,
        purpose: "halo-agents-sso-handoff",
        result: "denied",
      });
    } finally {
      delete stubs.deps.haloAgents;
    }
  });

  it("fails closed when the mandatory Halo Agents issuance audit cannot persist", async () => {
    stubs.deps.haloAgents = {
      issuer: base,
      destination: "https://updatedev.halofy.ai/auth/halomem",
      createAssertion(identity) {
        stubs.handoffCalls.push(identity);
        return "must-not-leave-the-server";
      },
    };
    const append = stubs.deps.audit.append;
    stubs.deps.audit.append = async () => {
      throw new Error("audit unavailable");
    };
    try {
      await fetch(base + "/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
      });
      const response = await fetch(base + "/auth/halo-agents", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
          origin: base,
        },
        body: "{}",
      });
      expect(response.status).toBe(503);
      expect(await response.text()).not.toContain("must-not-leave-the-server");
    } finally {
      stubs.deps.audit.append = append;
      delete stubs.deps.haloAgents;
    }
  });

  // --- logout --------------------------------------------------------------

  it("POST /auth/logout clears the cookie and invalidates the token server-side", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    expect(stubs.liveTokens.has(LIVE_TOKEN)).toBe(true);

    const res = await fetch(base + "/auth/logout", {
      method: "POST",
      headers: { cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}` },
    });
    expect(res.status).toBe(200);

    // Clearing cookie: same name, Max-Age=0.
    const line = sessionCookieLine(setCookies(res));
    expect(line).not.toBeNull();
    expect(line!).toContain("Max-Age=0");

    // Server-side invalidation happened + the token no longer resolves.
    expect(stubs.logoutCalls).toEqual([LIVE_TOKEN]);
    expect(stubs.liveTokens.has(LIVE_TOKEN)).toBe(false);

    const after = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
      },
      body: "{}",
    });
    expect(after.status).toBe(401);
  });

  // --- precedence ----------------------------------------------------------

  it("a present-but-bad bearer key 401s even with a live cookie (no silent downgrade)", async () => {
    await fetch(base + "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: GOOD_EMAIL, password: GOOD_PASSWORD }),
    });
    const res = await fetch(base + "/v1/mem/stats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer hm_" + "0".repeat(40),
        cookie: `${SESSION_COOKIE}=${LIVE_TOKEN}`,
      },
      body: "{}",
    });
    expect(res.status).toBe(401);
    // The cookie path was NOT consulted — the bearer key was authoritative.
    expect(stubs.resolveSessionCalls).not.toContain(LIVE_TOKEN);
  });
});
