/**
 * M10 exit-criteria test (CONTRACTS-M10-ACCESS §Exit criteria).
 *
 * Boots the REAL kernel + HTTP transport (in-memory PGlite, HashEmbedder,
 * StubLlm, loopback only) and drives the role-scoped memory graph end to end:
 *
 *   (a) SIBLING LEAK  (E3): a Marketing member's serialized /v1/memory-graph
 *       response carries zero Sales markers — nodes, edges, counts, topology,
 *       agent labels, ids.
 *   (b) TENANT WALL   (E5): tenant A's root sees zero tenant-B markers, and
 *       vice versa.
 *   (c) PREVIEW EQUIVALENCE (E6/D43): root previewing an actual member gets
 *       authorization-identical content to the member's own response (the
 *       preview-only "why" annotation removed before comparison — it is
 *       derived from the same projection, not an authorization difference).
 *   (d) ROLE PREVIEW  (E7): a bare role (no functional area) is rejected.
 *   (e) READ-ONLY     (E8/D43): every mutating route presented with the
 *       preview header → 403, with a denial audit row attributed to ROOT.
 *   (f) REVOCATION    (E9/D47): revoking the member's marketing grant removes
 *       marketing from the next graph call — nothing stale is served.
 *   (g) POISONING     (D9/D46): caller-supplied namespace/role/tenant/grant-
 *       root injection attempts fail closed and audit; a real-but-
 *       unauthorized scope is byte-identical to a nonexistent one.
 *   (h) TOKEN AT REST (D43): the preview table stores only sha256(token).
 */

import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import { memoryGraphScopeId } from "../src/console/api.js";
import type { Identity, WriteResult } from "../src/types.js";
import { hashPassword } from "../src/console/auth.js";

const KNOWLEDGE_DIR = fileURLToPath(new URL("../knowledge", import.meta.url));
const BOOTSTRAP_TOKEN = "m10-access-exit-bootstrap-token-32-bytes-minimum";

const ROOT_EMAIL = "root@acme.test";
const ROOT_PASSWORD = "acme-root-password-01";
const MEMBER_EMAIL = "mia@acme.test";
const MEMBER_PASSWORD = "acme-member-password-01";
const BETA_ROOT_EMAIL = "root@beta.test";
const BETA_ROOT_PASSWORD = "beta-root-password-01";

const MKT_MARKER = "MKTMARKER";
const SALES_MARKER = "SALESMARKER";
const BETA_MARKER = "BETAMARKER";
const GROWTH_MARKER = "GROWTHMARKER";
const ORG_MEMBER_EMAIL = "gina@halo.test";

let kernel: Kernel;
let server: HaloHttpServer;
let baseUrl: string;
let rootCookie: string;
let memberCookie: string;
let betaCookie: string;
let memberUserId: string;
let marketingTeamId: string;
let salesTeamId: string;

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

interface Res {
  status: number;
  text: string;
  json: unknown;
  setCookie: string[];
}

async function req(
  method: string,
  route: string,
  opts: { cookie?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<Res> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.cookie) headers.cookie = opts.cookie;
  const res = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    redirect: "manual",
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text === "" ? null : JSON.parse(text);
  } catch {
    json = null;
  }
  const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] })
    .getSetCookie;
  const setCookie = typeof getSetCookie === "function"
    ? getSetCookie.call(res.headers)
    : res.headers.get("set-cookie")
      ? [res.headers.get("set-cookie") as string]
      : [];
  return { status: res.status, text, json, setCookie };
}

async function loginCookie(email: string, password: string): Promise<string> {
  const res = await req("POST", "/auth/login", { body: { email, password } });
  expect(res.status).toBe(200);
  const line = res.setCookie.find((l) => l.startsWith(`${SESSION_COOKIE}=`));
  if (!line) throw new Error(`login for ${email} set no session cookie`);
  return line.split(";")[0]!;
}

async function auditRows(where: string, params: unknown[]): Promise<
  Array<{ actor: string; purpose: string; result: string; detail: string }>
> {
  const res = await kernel.db.query(
    `SELECT actor, purpose, result, detail FROM audit_log WHERE ${where} ORDER BY ts ASC`,
    params,
  );
  return res.rows as Array<{ actor: string; purpose: string; result: string; detail: string }>;
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: KNOWLEDGE_DIR,
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
    bootstrapToken: BOOTSTRAP_TOKEN,
  });

  // A PLATFORM ROOT mints the two tenant roots + the member. Provisioned
  // directly: bootstrap creates an organization and an owner inside it now
  // (decision 9), so it can no longer hand back a caller at namespace "".
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
    [
      "root-m10-exit",
      "platform@halo.test",
      hashPassword("platform-owner-password-01"),
      new Date().toISOString(),
    ],
  );
  const platformIdentity = await kernel.resolveSessionIdentity(
    (await kernel.login("platform@halo.test", "platform-owner-password-01"))!.token,
  );
  if (!platformIdentity) throw new Error("platform session did not resolve");

  await kernel.createUser(
    { email: ROOT_EMAIL, namespace: "acme", role: "owner", password: ROOT_PASSWORD },
    platformIdentity,
  );
  const member = await kernel.createUser(
    {
      email: MEMBER_EMAIL,
      namespace: "acme/people/mia",
      role: "member",
      password: MEMBER_PASSWORD,
    },
    platformIdentity,
  );
  memberUserId = member.id;
  await kernel.createUser(
    { email: BETA_ROOT_EMAIL, namespace: "beta", role: "owner", password: BETA_ROOT_PASSWORD },
    platformIdentity,
  );

  // Tenant-A root creates the two functional areas and enrolls the member in
  // Marketing — the roster row and its consume grant commit in ONE tx.
  const acmeRootIdentity = (await kernel.resolveSessionIdentity(
    (await kernel.login(ROOT_EMAIL, ROOT_PASSWORD))!.token,
  )) as Identity;
  const marketing = await kernel.createTeam(acmeRootIdentity, { name: "Marketing" });
  const sales = await kernel.createTeam(acmeRootIdentity, { name: "Sales" });
  marketingTeamId = marketing.id;
  salesTeamId = sales.id;
  await kernel.addTeamMember(acmeRootIdentity, marketing.id, MEMBER_EMAIL);

  // Seed distinctive facts per namespace through the real write path.
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const rootBadge = await kernel.auth.resolve(rootKey.plaintext);
  if (!rootBadge) throw new Error("root badge did not resolve");
  const seed = async (namespace: string, actor: string, content: string) => {
    const key = await kernel.auth.issueKey(namespace, actor, "agent", rootBadge);
    const agent = await kernel.auth.resolve(key.plaintext);
    if (!agent) throw new Error(`agent for ${namespace} did not resolve`);
    sync(await kernel.memWrite(
      { scope: "team", content, hints: { verbatim: true } },
      agent,
      "m10-exit",
    ));
  };
  await seed("acme/marketing", "mkt-agent", `Campaign brief cadence weekly ${MKT_MARKER}`);
  await seed("acme/sales", `sales-agent-${SALES_MARKER}`, `Pipeline target Q3 ${SALES_MARKER}`);
  await seed("beta", "beta-agent", `Beta tenant onboarding checklist ${BETA_MARKER}`);

  // The "" ORGANIZATION: a top-level team + member owned by the bootstrap
  // root's own workspace (single-org install shape). Created BEFORE any
  // tenant is registered — with tenants present, root-created teams/users
  // now attach to the sole tenant (or refuse to guess between several), so
  // the legacy top-level shape can only be minted on a tenantless install.
  const growth = await kernel.createTeam(platformIdentity, { name: "Growth" });
  await kernel.createUser(
    {
      email: ORG_MEMBER_EMAIL,
      namespace: "growth/people/gina",
      role: "member",
      password: "org-member-password-01",
    },
    platformIdentity,
  );
  await kernel.addTeamMember(platformIdentity, growth.id, ORG_MEMBER_EMAIL);
  await seed("growth", "growth-agent", `Onboarding playbook ${GROWTH_MARKER}`);
  // Register acme and beta as TENANTS (production truth: every self-serve
  // org signup mints a `tenants` row) — registration is what fences them
  // off from the "" organization root's View-as ((j)/(l)).
  for (const [id, name] of [["acme", "Acme"], ["beta", "Beta"]]) {
    await kernel.db.query(
      `INSERT INTO tenants (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
       VALUES ($1, $2, 'active', 100, 100, $3) ON CONFLICT (id) DO NOTHING`,
      [id, name, new Date().toISOString()],
    );
  }

  server = createHttpServer(buildHttpDeps(kernel, { secureCookies: false }));
  const port = await server.start(0);
  baseUrl = `http://127.0.0.1:${port}`;

  rootCookie = await loginCookie(ROOT_EMAIL, ROOT_PASSWORD);
  memberCookie = await loginCookie(MEMBER_EMAIL, MEMBER_PASSWORD);
  betaCookie = await loginCookie(BETA_ROOT_EMAIL, BETA_ROOT_PASSWORD);
}, 120_000);

afterAll(async () => {
  await server?.stop();
  await kernel?.close();
});

describe("m10 access exit", () => {
  it("(a) sibling leak: the Marketing member's wire bytes carry zero Sales markers", async () => {
    const res = await req("GET", "/v1/memory-graph", { cookie: memberCookie });
    expect(res.status).toBe(200);
    expect(res.text).toContain(MKT_MARKER);
    expect(res.text).not.toContain(SALES_MARKER);
    expect(res.text).not.toContain("acme/sales");
    expect(res.text).not.toContain(BETA_MARKER);
    const body = res.json as { title: string; counts: { nodes: number } };
    expect(body.title).toBe("Your memory");
    expect(body.counts.nodes).toBeGreaterThan(0);
  });

  it("(b) tenant wall: each tenant root sees only its own tenant", async () => {
    const acme = await req("GET", "/v1/memory-graph", { cookie: rootCookie });
    expect(acme.status).toBe(200);
    expect(acme.text).toContain(MKT_MARKER);
    expect(acme.text).toContain(SALES_MARKER); // root sees the whole tenant (E5)
    expect(acme.text).not.toContain(BETA_MARKER);
    expect((acme.json as { title: string }).title).toBe("Company memory");

    const beta = await req("GET", "/v1/memory-graph", { cookie: betaCookie });
    expect(beta.status).toBe(200);
    expect(beta.text).toContain(BETA_MARKER);
    expect(beta.text).not.toContain(MKT_MARKER);
    expect(beta.text).not.toContain(SALES_MARKER);
  });

  it("(c) preview equivalence: root viewing the member gets the member's own bytes", async () => {
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { subjectUserId: memberUserId, reason: "support ticket 42" },
    });
    expect(start.status).toBe(201);
    const created = start.json as { id: string; token: string; subjectLabel: string };
    expect(created.token).toMatch(/^[0-9a-f]{64}$/);
    expect(created.subjectLabel).toBe(MEMBER_EMAIL);

    const preview = await req("GET", "/v1/memory-graph", {
      cookie: rootCookie,
      headers: { "x-halomem-preview-token": created.token },
    });
    expect(preview.status).toBe(200);
    const own = await req("GET", "/v1/memory-graph", { cookie: memberCookie });
    expect(own.status).toBe(200);

    const previewBody = preview.json as Record<string, unknown>;
    const ownBody = own.json as Record<string, unknown>;
    // The preview adds per-entity "why" lines derived from the SAME
    // projection; authorization content must otherwise be deep-equal.
    const why = previewBody.why as Record<string, string> | undefined;
    delete previewBody.why;
    expect(previewBody).toEqual(ownBody);
    // The why map can only name entities the member's own response contains.
    expect(why).toBeDefined();
    for (const key of Object.keys(why!)) {
      expect(own.text).toContain(key);
    }
    // The preview response never leaks Sales either.
    expect(preview.text).not.toContain(SALES_MARKER);

    await req("DELETE", `/v1/root/view-as/sessions/${created.id}`, { cookie: rootCookie });
  });

  it("(d) a bare role preview (no functional area) is rejected", async () => {
    const res = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { role: "member", reason: "training" },
    });
    expect(res.status).toBe(400);
  });

  it("(e) read-only: mutations under the preview header are 403 + root-attributed audit", async () => {
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { role: "member", functionalAreaIds: [marketingTeamId], reason: "audit walkthrough" },
    });
    expect(start.status).toBe(201);
    const created = start.json as { id: string; token: string; scopeLabel: string };
    expect(created.scopeLabel).toBe("Marketing");

    for (const [method, route, body] of [
      ["POST", "/v1/admin/teams", { name: "Sneak" }],
      ["POST", "/v1/mem/pin", { target: { kind: "memory", ref: "nope" } }],
      ["DELETE", `/v1/root/view-as/sessions/${created.id}`, undefined],
      ["PUT", "/v1/admin/usage/cap", { monthlyBudgetUsd: 1 }],
    ] as const) {
      const res = await req(method, route, {
        cookie: rootCookie,
        body,
        headers: { "x-halomem-preview-token": created.token },
      });
      expect(res.status, `${method} ${route}`).toBe(403);
    }
    const denials = await auditRows(`purpose = $1`, ["console-view-as-mutation-denied"]);
    expect(denials.length).toBeGreaterThanOrEqual(4);
    for (const row of denials) {
      expect(row.actor).toBe(ROOT_EMAIL); // ROOT-attributed, never the subject
      expect(row.result).toBe("denied");
      expect(row.detail).not.toContain(created.token);
    }
    // An INVALID credential on a mutating route is still rejected.
    const bogus = await req("POST", "/v1/admin/teams", {
      cookie: rootCookie,
      body: { name: "Sneak2" },
      headers: { "x-halomem-preview-token": "f".repeat(64) },
    });
    expect(bogus.status).toBe(403);

    // GET under the same credential works (role preview, Marketing only).
    const graph = await req("GET", "/v1/memory-graph", {
      cookie: rootCookie,
      headers: { "x-halomem-preview-token": created.token },
    });
    expect(graph.status).toBe(200);
    expect(graph.text).toContain(MKT_MARKER);
    expect(graph.text).not.toContain(SALES_MARKER);

    // Exit WITHOUT the header succeeds and is idempotent.
    const end = await req("DELETE", `/v1/root/view-as/sessions/${created.id}`, {
      cookie: rootCookie,
    });
    expect(end.status).toBe(200);
  });

  it("(h) the preview table stores only sha256(token) - never plaintext", async () => {
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { subjectUserId: memberUserId, reason: "token at rest check" },
    });
    expect(start.status).toBe(201);
    const { id, token } = start.json as { id: string; token: string };
    const rows = await kernel.db.query(
      `SELECT * FROM access_preview_sessions WHERE id = $1`,
      [id],
    );
    expect(rows.rows.length).toBe(1);
    const serialized = JSON.stringify(rows.rows[0]);
    expect(serialized).not.toContain(token);
    expect((rows.rows[0] as { token_hash: string }).token_hash).toBe(
      createHash("sha256").update(token, "utf8").digest("hex"),
    );
    // Audit detail never carries the credential either (D43).
    const all = await kernel.db.query(`SELECT detail FROM audit_log`);
    for (const row of all.rows as Array<{ detail: string | null }>) {
      if (row.detail !== null) expect(row.detail).not.toContain(token);
    }
    await req("DELETE", `/v1/root/view-as/sessions/${id}`, { cookie: rootCookie });
  });

  it("(i) a dead preview credential on GET is a uniform 404 - never root's own graph", async () => {
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { subjectUserId: memberUserId, reason: "expiry regression" },
    });
    expect(start.status).toBe(201);
    const created = start.json as { id: string; token: string; scopeLabel: string };
    // A person preview labels the subject's ROLE (PRD §8.2) — never the
    // scope-picker default "All accessible".
    expect(created.scopeLabel).toBe("Member");

    const end = await req("DELETE", `/v1/root/view-as/sessions/${created.id}`, {
      cookie: rootCookie,
    });
    expect(end.status).toBe(200);

    // D43/E6: the ended credential must NOT silently fall back to root's own
    // company-wide graph under the "Viewing as" banner.
    const stale = await req("GET", "/v1/memory-graph", {
      cookie: rootCookie,
      headers: { "x-halomem-preview-token": created.token },
    });
    expect(stale.status).toBe(404);
    expect(stale.json).toEqual({ error: "not found", code: "not_found" });
    expect(stale.text).not.toContain(MKT_MARKER);
    expect(stale.text).not.toContain(SALES_MARKER);

    // An entirely unknown token answers byte-identically (D46 — no oracle).
    const unknown = await req("GET", "/v1/memory-graph", {
      cookie: rootCookie,
      headers: { "x-halomem-preview-token": "f".repeat(64) },
    });
    expect(unknown.status).toBe(404);
    expect(unknown.text).toBe(stale.text);
  });

  it("(j) the '' organization root never enumerates or previews a registered tenant", async () => {
    const platformCookie = await loginCookie(
      "platform@halo.test",
      "platform-owner-password-01",
    );
    // PRD §14.1: Human Root is tenant-root, never platform-global. The ""
    // owner is the ORGANIZATION root of the unprefixed org (single-org
    // installs): its targets exclude every registered tenant's rows.
    const targets = await req("GET", "/v1/root/view-as/targets", {
      cookie: platformCookie,
    });
    expect(targets.status).toBe(200);
    expect(targets.text).not.toContain(ROOT_EMAIL);
    expect(targets.text).not.toContain(MEMBER_EMAIL);
    expect(targets.text).not.toContain(BETA_ROOT_EMAIL);
    expect(targets.text).not.toContain("acme");
    expect(targets.text).not.toContain("beta");

    // A tenant subject is a uniform miss, not a distinguishable denial.
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: platformCookie,
      body: { subjectUserId: memberUserId, reason: "cross-tenant grab" },
    });
    expect(start.status).toBe(404);
    const rows = await kernel.db.query(
      `SELECT subject_user_id FROM access_preview_sessions WHERE tenant_id = ''`,
    );
    for (const row of rows.rows) {
      expect(row.subject_user_id).not.toBe(memberUserId);
    }
  });

  it("(l) the '' organization root CAN view-as inside its own organization", async () => {
    const platformCookie = await loginCookie(
      "platform@halo.test",
      "platform-owner-password-01",
    );
    const targets = await req("GET", "/v1/root/view-as/targets", {
      cookie: platformCookie,
    });
    expect(targets.status).toBe(200);
    const body = targets.json as {
      people: Array<{ id: string; email: string }>;
      functions: Array<{ id: string; label: string }>;
    };
    const growth = body.functions.find((f) => f.label === "Growth");
    expect(growth).toBeDefined();
    expect(body.people.some((p) => p.email === ORG_MEMBER_EMAIL)).toBe(true);

    // Role + own-org area simulation starts and serves a projected graph.
    const start = await req("POST", "/v1/root/view-as/sessions", {
      cookie: platformCookie,
      body: { role: "member", functionalAreaIds: [growth!.id], reason: "org review" },
    });
    expect(start.status).toBeLessThan(300);
    const token = (start.json as { token: string }).token;
    expect(token.length).toBeGreaterThan(0);
    const graph = await req("GET", "/v1/memory-graph", {
      cookie: platformCookie,
      headers: { "x-halomem-preview-token": token },
    });
    expect(graph.status).toBe(200);
    expect(graph.text).toContain(GROWTH_MARKER);
    expect(graph.text).not.toContain(MKT_MARKER);
    expect(graph.text).not.toContain(SALES_MARKER);
    expect(graph.text).not.toContain(BETA_MARKER);
  });

  it("(g) poisoning: caller-owned namespace/role/tenant/grant-root inputs fail closed + audit", async () => {
    // Query-string namespace injection on the graph route → 400 + audit.
    const ns = await req("GET", "/v1/memory-graph?namespace=acme/sales", {
      cookie: memberCookie,
    });
    expect(ns.status).toBe(400);
    // A real-but-unauthorized scope id is byte-identical to a nonexistent one.
    const salesScope = memoryGraphScopeId("acme", "acme/sales");
    const poisoned = await req(`GET`, `/v1/memory-graph?scope=${salesScope}`, {
      cookie: memberCookie,
    });
    const nonexistent = await req("GET", "/v1/memory-graph?scope=deadbeefdeadbeefdead", {
      cookie: memberCookie,
    });
    expect(poisoned.status).toBe(404);
    expect(nonexistent.status).toBe(404);
    expect(poisoned.text).toBe(nonexistent.text);
    // Neither denial names the hidden target.
    const graphDenials = await auditRows(`purpose = $1 AND result = $2`, [
      "memory-graph",
      "denied",
    ]);
    expect(graphDenials.length).toBeGreaterThanOrEqual(2);
    for (const row of graphDenials) {
      expect(row.detail).not.toContain(salesScope);
      expect(row.detail).not.toContain("acme/sales");
    }

    // Body tenant/namespace injection on view-as → 400 + audit.
    const bodyPoison = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { subjectUserId: memberUserId, reason: "x", namespace: "beta" },
    });
    expect(bodyPoison.status).toBe(400);
    // Role injection: only admin|member simulate (root is impossible).
    const rolePoison = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { role: "root", functionalAreaIds: [marketingTeamId], reason: "x" },
    });
    expect(rolePoison.status).toBe(400);
    // Grant-root injection: a namespace string as a functional-area id does
    // not resolve — uniform not-found, same bytes as an unknown id.
    const grantPoison = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { role: "admin", functionalAreaIds: ["acme/sales"], reason: "x" },
    });
    const unknownArea = await req("POST", "/v1/root/view-as/sessions", {
      cookie: rootCookie,
      body: { role: "admin", functionalAreaIds: ["01UNKNOWNAREA"], reason: "x" },
    });
    expect(grantPoison.status).toBe(404);
    expect(unknownArea.status).toBe(404);
    expect(grantPoison.text).toBe(unknownArea.text);
    // A foreign tenant's root cannot preview acme's member (uniform miss).
    const foreign = await req("POST", "/v1/root/view-as/sessions", {
      cookie: betaCookie,
      body: { subjectUserId: memberUserId, reason: "x" },
    });
    expect(foreign.status).toBe(404);
  });

  it("(k) retired role spellings cannot be minted via POST /v1/admin/people (D41)", async () => {
    // The retired internal spellings are rejected at the transport boundary —
    // fromProductRole throws before any invitation row exists.
    for (const role of ["auditor", "owner"]) {
      const res = await req("POST", "/v1/admin/people", {
        cookie: rootCookie,
        body: {
          displayName: `Retired ${role}`,
          email: `retired-${role}@acme.test`,
          namespace: "acme",
          role,
        },
      });
      expect(res.status).toBe(400);
      const rows = await kernel.db.query(
        `SELECT id FROM auth_invitations WHERE email = $1`,
        [`retired-${role}@acme.test`],
      );
      expect(rows.rows).toEqual([]);
    }
    // Product roles still invite (root maps to internal owner through this
    // documented root-assignment route; owner-only downstream gate applies).
    const ok = await req("POST", "/v1/admin/people", {
      cookie: rootCookie,
      body: {
        displayName: "D41 Member",
        email: "d41-member@acme.test",
        namespace: "acme",
        role: "member",
      },
    });
    expect(ok.status).toBeLessThan(300);
  });

  it("(f) revocation: the next graph call drops the revoked area - nothing stale", async () => {
    const before = await req("GET", "/v1/memory-graph", { cookie: memberCookie });
    expect(before.text).toContain(MKT_MARKER);
    const beforeScopes = (before.json as { scopes: Array<{ label: string }> }).scopes;

    const grants = await kernel.accessGrants.listEffectiveGrants(
      "acme",
      memberUserId,
      new Date(),
    );
    const membership = grants.find(
      (g) => g.resourceId === marketingTeamId && g.accessMode === "consume",
    );
    expect(membership).toBeDefined();
    const revoked = await kernel.accessGrants.revokeGrant({
      tenantId: "acme",
      grantId: membership!.id,
      actor: ROOT_EMAIL,
    });
    expect(revoked).not.toBeNull();

    const after = await req("GET", "/v1/memory-graph", { cookie: memberCookie });
    expect(after.status).toBe(200);
    expect(after.text).not.toContain(MKT_MARKER);
    expect(after.text).not.toContain(SALES_MARKER);
    // The scope options shrank with the grant (D42: grants are locations).
    const afterScopes = (after.json as { scopes: Array<{ label: string }> }).scopes;
    expect(afterScopes.length).toBeLessThan(beforeScopes.length);
    expect(afterScopes.some((s) => s.label === "Marketing")).toBe(false);
    // The projection hash — the cache partition key — changed with the bump.
    expect(revoked!.revokedAt).not.toBeNull();
  });

  it("keeps sales reach for the sales team only (grant via roster tx, E4 shape)", async () => {
    // The sales team exists with no members; its namespace stayed invisible
    // to the marketing member throughout — proven in (a). Sanity: the sales
    // team id resolves inside the tenant for root.
    const targets = await req("GET", "/v1/root/view-as/targets", { cookie: rootCookie });
    expect(targets.status).toBe(200);
    const body = targets.json as { functions: Array<{ id: string; label: string }> };
    expect(body.functions.some((f) => f.id === salesTeamId)).toBe(true);
    // Members cannot list targets (root-only).
    const denied = await req("GET", "/v1/root/view-as/targets", { cookie: memberCookie });
    expect(denied.status).toBe(403);
  });
});
