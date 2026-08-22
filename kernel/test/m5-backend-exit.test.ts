/**
 * M5 backend exit criteria (CONTRACTS-M5-backend.md §4 + §Exit) — the human
 * sign-in + control-room management API through the REAL kernel over REAL HTTP
 * (node:http on an ephemeral port, fetch as the client, cookie sessions for the
 * human flows). Hermetic: in-memory PGlite, HashEmbedder, StubLlm; zero network
 * beyond loopback.
 *
 * Journeys (PRD, at the API level):
 *   J1  owner setup — bootstrap-owner USER logs in by cookie → POST
 *       /v1/admin/setup → a tenant + first source + retriever are created and a
 *       paste-ready MCP snippet is returned (no engineer in the loop).
 *   J2  a team ADMIN issues an agent badge scoped to its team via
 *       POST /v1/admin/keys, and is 403 issuing OUTSIDE its subtree.
 *   J3  a team admin reads GET /v1/admin/memory-map and flips the retriever via
 *       PUT /v1/admin/policy (the map reflects its own subtree only).
 *   J5  an AUDITOR searches GET /v1/admin/audit + reads a certificate, but is
 *       403 on POST /v1/admin/forget and on every other mutation (read-only).
 *   Cross-tenant — a globex admin SESSION sees ZERO acme rows through overview /
 *   people / audit / memory-map (the M4 isolation guarantee holds for the human
 *   read routes too).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Kernel } from "../src/kernel.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import type { Identity, Role, WriteResult } from "../src/types.js";
import { hashPassword } from "../src/console/auth.js";

let knowledgeDir: string;
const AGENT = "m5-exit";

let kernel: Kernel;
let server: HaloHttpServer;
let baseUrl: string;

/** Bootstrap-owner USER credentials (the human who owns the org, namespace ""). */
const OWNER_EMAIL = "owner@halo.test";
const OWNER_PASSWORD = "correct horse battery staple";
const BOOTSTRAP_TOKEN = "m5-backend-test-bootstrap-token-32-bytes-minimum";

/** acme team-admin USER credentials. */
const ACME_OWNER_EMAIL = "owner@acme.test";
const ACME_OWNER_PASSWORD = "acme-owner-pw-01";
const ACME_ADMIN_EMAIL = "admin@acme.test";
const ACME_ADMIN_PASSWORD = "acme-admin-pw-01";

/** globex team-admin USER credentials (the cross-tenant probe). */
const GLOBEX_ADMIN_EMAIL = "admin@globex.test";
const GLOBEX_ADMIN_PASSWORD = "globex-admin-pw-01";

/** acme auditor USER credentials. */
const ACME_AUDITOR_EMAIL = "auditor@acme.test";
const ACME_AUDITOR_PASSWORD = "acme-auditor-pw-01";

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issueBadge(
  namespace: string,
  actor: string,
  role: Role,
  caller: Identity,
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, caller);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

// ---------------------------------------------------------------------------
// HTTP helpers: bearer (agent) + a tiny cookie jar (human session).
// ---------------------------------------------------------------------------

interface Res {
  status: number;
  json: any;
  setCookie: string[];
}

function getSetCookie(res: Response): string[] {
  const fn = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof fn === "function") return fn.call(res.headers);
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

async function parseJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** A request carrying EITHER a bearer key OR a session cookie (or neither). */
async function req(
  method: string,
  route: string,
  opts: { key?: string; cookie?: string; body?: unknown } = {},
): Promise<Res> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.key) headers.authorization = `Bearer ${opts.key}`;
  if (opts.cookie) headers.cookie = opts.cookie;
  const res = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    redirect: "manual",
  });
  return { status: res.status, json: await parseJson(res), setCookie: getSetCookie(res) };
}

/** Sign a user in and return the `halomem_session=...` cookie header string. */
async function loginCookie(email: string, password: string): Promise<string> {
  const res = await req("POST", "/auth/login", { body: { email, password } });
  expect(res.status).toBe(200);
  const line = res.setCookie.find((l) => l.startsWith(`${SESSION_COOKIE}=`));
  if (!line) throw new Error(`login for ${email} set no session cookie`);
  // Reduce to just "name=value" for the request Cookie header.
  const nameValue = line.split(";")[0]!;
  expect(line).toContain("HttpOnly");
  return nameValue;
}

// ---------------------------------------------------------------------------
// Boot: one kernel, a bootstrap owner user, per-team admins/auditor users, and
// seed memory in acme + globex so the read routes have subtree-scoped data.
// ---------------------------------------------------------------------------

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-m5-knowledge-"));
  await writeFile(join(knowledgeDir, "handbook.md"), "# Handbook\n\nSetup fixture knowledge.");
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
    bootstrapToken: BOOTSTRAP_TOKEN,
  });

  // --- platform-root owner USER, provisioned directly -----------------------
  // This lane models a PLATFORM ROOT minting tenant roots below. Bootstrap no
  // longer produces one: it creates an organization and puts its owner inside
  // it (CONTRACTS-SELF-SERVICE-ONBOARDING.md decision 9), so root is now an
  // operator-provisioned row — exactly what this insert is.
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
    ["root-m5-exit", OWNER_EMAIL, hashPassword(OWNER_PASSWORD), new Date().toISOString()],
  );
  const ownerIdentity = await kernel.resolveSessionIdentity(
    (await kernel.login(OWNER_EMAIL, OWNER_PASSWORD))!.token,
  );
  if (!ownerIdentity) throw new Error("owner session did not resolve");

  // A bootstrap owner API key too (the empty api_keys path), used to mint the
  // per-team agent badges that seed subtree memory.
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const rootBadge = await kernel.auth.resolve(rootKey.plaintext);
  if (!rootBadge) throw new Error("root badge did not resolve");

  // --- per-team human users (created by the owner) -------------------------
  await kernel.createUser(
    { email: ACME_OWNER_EMAIL, namespace: "acme", role: "owner", password: ACME_OWNER_PASSWORD },
    ownerIdentity,
  );
  await kernel.createUser(
    { email: ACME_ADMIN_EMAIL, namespace: "acme", role: "admin", password: ACME_ADMIN_PASSWORD },
    ownerIdentity,
  );
  await kernel.createUser(
    { email: ACME_AUDITOR_EMAIL, namespace: "acme", role: "auditor", password: ACME_AUDITOR_PASSWORD },
    ownerIdentity,
  );
  await kernel.createUser(
    { email: GLOBEX_ADMIN_EMAIL, namespace: "globex", role: "admin", password: GLOBEX_ADMIN_PASSWORD },
    ownerIdentity,
  );

  // --- seed acme subtree memory (facts land in a child namespace) ----------
  const acmeAgent = await issueBadge("acme/team", "agent:acme", "agent", rootBadge);
  await kernel.setPolicy("acme/team", "rateLimitPerMin: 100000\n");
  const w = sync(
    await kernel.memWrite(
      { scope: "team", content: "Acme refund window is 30 days ACMEMARKER", hints: { verbatim: true } },
      acmeAgent,
      AGENT,
    ),
  );
  const acmeFactId = w.stored[0]!.id;
  await kernel.memRead({ id: acmeFactId }, acmeAgent, AGENT);
  await kernel.memRead({ id: acmeFactId }, acmeAgent, AGENT);
  await kernel.memSearch({ query: "refund window", k: 3 }, acmeAgent, AGENT);

  // --- seed globex subtree memory (the sibling — must never leak) ----------
  const globexAgent = await issueBadge("globex/team", "agent:globex", "agent", rootBadge);
  await kernel.setPolicy("globex/team", "rateLimitPerMin: 100000\n");
  sync(
    await kernel.memWrite(
      { scope: "team", content: "Globex discount ceiling is 15 percent GLOBEXMARKER", hints: { verbatim: true } },
      globexAgent,
      AGENT,
    ),
  );
  await kernel.memSearch({ query: "discount ceiling GLOBEXMARKER", k: 3 }, globexAgent, AGENT);

  server = createHttpServer(
    buildHttpDeps(kernel, {
      consoleDir: fileURLToPath(new URL("../console", import.meta.url)),
      secureCookies: false,
    }),
  );
  const port = await server.start(0);
  baseUrl = `http://127.0.0.1:${port}`;
}, 120_000);

afterAll(async () => {
  await server?.stop();
  await kernel?.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Cookie auth basics — a /v1/* request authenticates by cookie like a bearer.
// ---------------------------------------------------------------------------

describe("human sign-in (cookie session)", () => {
  it("wrong password → 401, no cookie set (no enumeration oracle)", async () => {
    const res = await req("POST", "/auth/login", {
      body: { email: OWNER_EMAIL, password: "wrong" },
    });
    expect(res.status).toBe(401);
    expect(res.setCookie.find((l) => l.startsWith(SESSION_COOKIE))).toBeUndefined();
  });

  it("unknown email → 401, indistinguishable from a bad password", async () => {
    const res = await req("POST", "/auth/login", {
      body: { email: "nobody@halo.test", password: "whatever" },
    });
    expect(res.status).toBe(401);
  });

  it("login sets an HttpOnly cookie; GET /auth/me resolves the identity", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const me = await req("GET", "/auth/me", { cookie });
    expect(me.status).toBe(200);
    expect(me.json.namespace).toBe("acme");
    expect(me.json.actor).toBe(ACME_ADMIN_EMAIL);
    expect(me.json.role).toBe("admin");
  });

  it("logout invalidates the session server-side", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const out = await req("POST", "/auth/logout", { cookie });
    expect(out.status).toBe(200);
    // The now-destroyed token no longer resolves.
    const me = await req("GET", "/auth/me", { cookie });
    expect(me.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// J1 — owner setup orchestration
// ---------------------------------------------------------------------------

describe("J1 - owner setup (zero engineer in the loop)", () => {
  it("owner logs in and POST /v1/admin/setup creates tenant + source + retriever + MCP snippet", async () => {
    const cookie = await loginCookie(OWNER_EMAIL, OWNER_PASSWORD);
    const res = await req("POST", "/v1/admin/setup", {
      cookie,
      body: {
        idempotencyKey: "m5-initech-first-setup",
        tenant: { id: "initech", name: "Initech", monthlyBudgetUsd: 500 },
        team: { id: "platform", name: "Platform" },
        source: { kind: "filesystem", config: { path: knowledgeDir } },
        retriever: "graph",
        agentActor: "initech-bot",
      },
    });
    expect(res.status, JSON.stringify(res.json)).toBe(201);

    // A tenant was created.
    expect(res.json.tenant.id).toBe("initech");
    expect(res.json.tenant.status).toBe("active");
    // A first source was connected in the tenant root.
    expect(res.json.source).not.toBeNull();
    expect(res.json.source.kind).toBe("filesystem");
    expect(res.json.source.namespace).toBe("initech/platform");
    expect(res.json.source.status).toBe("synced");
    expect(res.json.status).toBe("waiting_for_agent");
    // A paste-ready MCP snippet came back with a working bearer badge.
    expect(typeof res.json.mcpSnippet).toBe("string");
    expect(res.json.mcpSnippet).toContain("/mcp");
    const snippet = JSON.parse(res.json.mcpSnippet);
    const badgeKey: string = snippet.mcpServers.halomem.headers.Authorization.replace(
      /^Bearer /,
      "",
    );
    expect(badgeKey).toMatch(/^hm_[0-9a-f]{40}$/);

    // The retriever was picked (policy override persisted on the tenant root).
    const policy = await kernel.getPolicy("initech/platform");
    expect(policy.retriever).toBe("graph");

    // The minted badge actually works as an agent credential.
    const badgeIdentity = await kernel.auth.resolve(badgeKey);
    expect(badgeIdentity?.namespace).toBe("initech/platform");
    expect(badgeIdentity?.role).toBe("agent");
  });
});

// ---------------------------------------------------------------------------
// J2 — team admin issues an agent badge in its team, denied outside it
// ---------------------------------------------------------------------------

describe("J2 - team-admin badge issuance is subtree-scoped", () => {
  it("admin issues an agent badge INSIDE its team", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("POST", "/v1/admin/keys", {
      cookie,
      body: { namespace: "acme/support", actor: "acme-support-bot", role: "agent" },
    });
    expect(res.status).toBe(201);
    expect(res.json.plaintext).toMatch(/^hm_[0-9a-f]{40}$/);
    const issued = await kernel.auth.resolve(res.json.plaintext);
    expect(issued?.namespace).toBe("acme/support");
    expect(issued?.role).toBe("agent");
  });

  it("admin CANNOT issue a badge OUTSIDE its team (sibling tenant) → 403", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("POST", "/v1/admin/keys", {
      cookie,
      body: { namespace: "globex/team", actor: "intruder", role: "agent" },
    });
    expect(res.status).toBe(403);
    expect(res.json.code).toBe("forbidden");
  });
});

// ---------------------------------------------------------------------------
// POST /v1/admin/people — invite is owner/admin (contract), but an admin may
// invite ONLY non-owner roles: minting an owner requires an owner caller, and
// the empty-users bootstrap is NEVER reachable over the wire (a caller is
// always present). Regression for the invite-authorization defects.
// ---------------------------------------------------------------------------

describe("POST /v1/admin/people - admin invite authorization", () => {
  it("admin CAN invite a member in its own subtree → 201", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("POST", "/v1/admin/people", {
      cookie,
      body: {
        displayName: "Member One",
        email: "member1@acme.test",
        namespace: "acme/support",
        role: "member",
      },
    });
    expect(res.status).toBe(201);
    expect(res.json.invite.role).toBe("member");
    expect(res.json.invite.namespace).toBe("acme/support");
    expect(res.json.invite.status).toBe("pending");
    expect(res.json.activationToken).toMatch(/^[0-9a-f]{64}$/);

    const accepted = await req("POST", "/auth/invite/accept", {
      body: {
        token: res.json.activationToken,
        password: "member1 activation password",
      },
    });
    expect(accepted.status).toBe(200);
    const login = await req("POST", "/auth/login", {
      body: { email: "member1@acme.test", password: "member1 activation password" },
    });
    expect(login.status).toBe(200);
  });

  it("admin CANNOT mint an OWNER (no escalation to org owner) → 403", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    // M10/D41: the escalation input is now the PRODUCT role 'root' (the
    // retired internal 'owner' spelling is rejected as 400 below, before
    // authorization is even consulted). The escalation itself must stay 403.
    const res = await req("POST", "/v1/admin/people", {
      cookie,
      body: {
        displayName: "Evil Owner",
        email: "evil@acme.test",
        namespace: "acme",
        role: "root",
      },
    });
    expect(res.status).toBe(403);
    expect(res.json.code).toBe("forbidden");
    // Retired spelling: rejected as bad input (D41), never reaches authz.
    const retired = await req("POST", "/v1/admin/people", {
      cookie,
      body: {
        displayName: "Evil Owner",
        email: "evil@acme.test",
        namespace: "acme",
        role: "owner",
      },
    });
    expect(retired.status).toBe(400);
    // The escalation user was NOT created — login is impossible.
    const login = await req("POST", "/auth/login", {
      body: { email: "evil@acme.test", password: "evil-pw-01" },
    });
    expect(login.status).toBe(401);
  });

  it("admin CANNOT invite OUTSIDE its subtree (sibling tenant) → 403", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("POST", "/v1/admin/people", {
      cookie,
      body: {
        displayName: "Member Two",
        email: "member2@globex.test",
        namespace: "globex",
        role: "member",
      },
    });
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// J3 — admin reads memory-map + flips the retriever via PUT /v1/admin/policy
// ---------------------------------------------------------------------------

describe("J3 - admin reads the memory map and flips the retriever", () => {
  it("GET /v1/admin/memory-map reflects the admin's subtree", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("GET", "/v1/admin/memory-map?namespace=acme", { cookie });
    expect(res.status).toBe(200);
    expect(res.json.namespace).toBe("acme");
    // The twice-read acme fact is the hottest in the acme subtree.
    expect(res.json.hottest.some((h: any) => h.content.includes("ACMEMARKER"))).toBe(true);
    // No globex data leaks in.
    expect(JSON.stringify(res.json)).not.toContain("GLOBEXMARKER");
  });

  it("memory-map for a sibling tenant is refused (outside the subtree) → 403", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("GET", "/v1/admin/memory-map?namespace=globex", { cookie });
    expect(res.status).toBe(403);
  });

  it("PUT /v1/admin/policy flips the retriever inside the subtree", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("PUT", "/v1/admin/policy", {
      cookie,
      body: { namespace: "acme", yaml: "retriever: graph\n" },
    });
    expect(res.status).toBe(200);
    const policy = await kernel.getPolicy("acme");
    expect(policy.retriever).toBe("graph");
  });

  it("admin CANNOT flip a sibling tenant's policy → 403", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("PUT", "/v1/admin/policy", {
      cookie,
      body: { namespace: "globex", yaml: "retriever: graph\n" },
    });
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// J5 — auditor reads audit + a certificate, but mutates nothing
// ---------------------------------------------------------------------------

describe("J5 - auditor is read-only", () => {
  it("auditor GETs /v1/admin/audit (subtree-scoped)", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const res = await req("GET", "/v1/admin/audit", { cookie });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.json)).toBe(true);
    expect(res.json.every((r: any) => r.namespace.startsWith("acme"))).toBe(true);
    // No globex audit rows.
    expect(JSON.stringify(res.json)).not.toContain("globex");
  });

  it("auditor can read a deletion certificate (a regulator reads, never mints)", async () => {
    // Mint as the tenant owner; team admins are intentionally not erasure
    // authorities. The tenant auditor can read the trusted certificate.
    const adminCookie = await loginCookie(ACME_OWNER_EMAIL, ACME_OWNER_PASSWORD);
    const forget = await req("POST", "/v1/admin/forget", {
      cookie: adminCookie,
      body: { target: { kind: "namespace", value: "acme/team" } },
    });
    expect(forget.status, JSON.stringify(forget.json)).toBe(200);
    const certId: string = forget.json.certificate.id;
    expect(forget.json.certificate.namespace).toBe("acme");

    const auditorCookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const cert = await req("GET", `/v1/admin/certificate/${certId}`, { cookie: auditorCookie });
    expect(cert.status).toBe(200);
    expect(cert.json.id).toBe(certId);
    expect(cert.json.verified).toBe(true);

    const stored = await kernel.db.query(
      `SELECT json FROM deletion_certificates WHERE id = $1`,
      [certId],
    );
    const raw = stored.rows[0]!.json;
    const tampered = typeof raw === "string" ? JSON.parse(raw) : raw;
    tampered.erasedCount = Number(tampered.erasedCount) + 1;
    await kernel.db.query(
      `UPDATE deletion_certificates SET json = $2::jsonb WHERE id = $1`,
      [certId, JSON.stringify(tampered)],
    );

    const untrusted = await req("GET", `/v1/admin/certificate/${certId}`, {
      cookie: auditorCookie,
    });
    expect(untrusted.status).toBe(200);
    expect(untrusted.json.verified).toBe(false);
  });

  it("auditor CANNOT POST /v1/admin/forget → 403", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const res = await req("POST", "/v1/admin/forget", {
      cookie,
      body: { target: { kind: "namespace", value: "acme" } },
    });
    expect(res.status).toBe(403);
  });

  it("auditor CANNOT run any control-room mutation (invite / connect / run) → 403", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const invite = await req("POST", "/v1/admin/people", {
      cookie,
      body: { email: "new@acme.test", namespace: "acme", role: "member" },
    });
    expect(invite.status).toBe(403);

    const connect = await req("POST", "/v1/admin/sources", {
      cookie,
      body: { kind: "filesystem", config: { path: "/tmp/x" } },
    });
    expect(connect.status).toBe(403);

    const runFrag = await req("POST", "/v1/admin/fragmentation", {
      cookie,
      body: { namespace: "acme" },
    });
    expect(runFrag.status).toBe(403);
  });

  it("auditor CAN read the control-room screens (overview / people / sources)", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    for (const route of ["/v1/admin/overview", "/v1/admin/people", "/v1/admin/sources"]) {
      const res = await req("GET", route, { cookie });
      expect(res.status).toBe(200);
    }
  });

  it("auditor CAN read GET /v1/admin/fragmentation for its OWN subtree → 200", async () => {
    // The admin RUNS the report (a write); the auditor then READS it back — the
    // read-only-everywhere-in-scope invariant covers fragmentation GET.
    const adminCookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const run = await req("POST", "/v1/admin/fragmentation", {
      cookie: adminCookie,
      body: { namespace: "acme" },
    });
    expect(run.status).toBe(200);

    const auditorCookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const read = await req("GET", "/v1/admin/fragmentation?namespace=acme", {
      cookie: auditorCookie,
    });
    expect(read.status).toBe(200);
  });

  it("auditor CANNOT read fragmentation OUTSIDE its subtree (sibling tenant) → 403", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    const res = await req("GET", "/v1/admin/fragmentation?namespace=globex", { cookie });
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant — a globex admin SESSION sees zero acme data on every screen
// ---------------------------------------------------------------------------

describe("cross-tenant isolation (human read routes)", () => {
  it("globex admin sees ZERO acme rows via overview / people / audit / memory-map", async () => {
    const cookie = await loginCookie(GLOBEX_ADMIN_EMAIL, GLOBEX_ADMIN_PASSWORD);

    const overview = await req("GET", "/v1/admin/overview", { cookie });
    expect(overview.status).toBe(200);
    expect(overview.json.namespace).toBe("globex");
    expect(JSON.stringify(overview.json)).not.toContain("ACMEMARKER");
    expect(JSON.stringify(overview.json)).not.toContain("acme");

    const people = await req("GET", "/v1/admin/people", { cookie });
    expect(people.status).toBe(200);
    expect(people.json.users.every((u: any) => !u.email.includes("acme"))).toBe(true);
    expect(people.json.badges.every((b: any) => b.namespace.startsWith("globex"))).toBe(true);

    const audit = await req("GET", "/v1/admin/audit", { cookie });
    expect(audit.status).toBe(200);
    expect(audit.json.every((r: any) => r.namespace.startsWith("globex"))).toBe(true);

    // A globex admin cannot even point the map at acme (outside its subtree).
    const map = await req("GET", "/v1/admin/memory-map?namespace=acme", { cookie });
    expect(map.status).toBe(403);

    // Its own subtree map works and carries only globex data.
    const ownMap = await req("GET", "/v1/admin/memory-map?namespace=globex", { cookie });
    expect(ownMap.status).toBe(200);
    expect(JSON.stringify(ownMap.json)).not.toContain("ACMEMARKER");
  });
});
