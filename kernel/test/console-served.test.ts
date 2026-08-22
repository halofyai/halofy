/**
 * M5 frontend — console served-over-HTTP integration test.
 *
 * Boots the REAL kernel + createHttpServer on an ephemeral port with a real
 * `console/` dir and a tiny cookie jar. Asserts, per CONTRACTS-M5-frontend §3:
 *
 *   (a) STATIC (unauthenticated — the screens are public):
 *       - GET /console/ → 200 text/html (index.html); /console → 308 /console/
 *       - GET /console/app.js + /console/app.css → 200 with JS/CSS content-types
 *       - GET /console/screens/s{1..12}.js → 200 text/javascript
 *       - GET /console/login → 200 text/html; /console/login.html → 308 clean URL
 *       - a path-traversal URL (/console/../src/http/console.ts) → 403
 *
 *   (b) each screen's DATA endpoint returns the seeded data, logged in as OWNER
 *       by cookie: GET /v1/admin/{overview,people,memory-map,sources,audit},
 *       POST /v1/admin/scorecard.
 *
 *   (c) as an AUDITOR, the mutation endpoints (forget / invite / connect-source)
 *       403 while the read endpoints 200 — the same role contract the screens
 *       encode in the UI.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm; zero network beyond
 * loopback. This mirrors test/m5-backend-exit.test.ts's boot but focuses on the
 * static import graph + the screen data contract the FRONTEND consumes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import type { Identity, WriteResult } from "../src/types.js";
import { hashPassword } from "../src/console/auth.js";

const KNOWLEDGE_DIR = fileURLToPath(new URL("../knowledge", import.meta.url));
const CONSOLE_DIR = fileURLToPath(new URL("../console", import.meta.url));
const AGENT = "console-served";

let kernel: Kernel;
let server: HaloHttpServer;
let baseUrl: string;

const OWNER_EMAIL = "owner@halo.test";
const OWNER_PASSWORD = "correct horse battery staple";
const BOOTSTRAP_TOKEN = "console-served-test-bootstrap-token-32-bytes-minimum";
const ACME_ADMIN_EMAIL = "admin@acme.test";
const ACME_ADMIN_PASSWORD = "acme-admin-pw-01";
const ACME_AUDITOR_EMAIL = "auditor@acme.test";
const ACME_AUDITOR_PASSWORD = "acme-auditor-pw-01";

/** A distinctive marker present in the seeded acme fact — proves seeded data. */
const ACME_MARKER = "ACMEMARKER";

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

// ---------------------------------------------------------------------------
// HTTP helpers — raw fetch (static, no cookie) + a cookie jar (session).
// ---------------------------------------------------------------------------

interface Res {
  status: number;
  contentType: string | null;
  location: string | null;
  text: string;
  json: unknown;
  setCookie: string[];
}

function getSetCookie(res: Response): string[] {
  const fn = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof fn === "function") return fn.call(res.headers);
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

async function req(
  method: string,
  route: string,
  opts: { cookie?: string; body?: unknown } = {},
): Promise<Res> {
  const headers: Record<string, string> = {};
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
  if (text !== "") {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return {
    status: res.status,
    contentType: res.headers.get("content-type"),
    location: res.headers.get("location"),
    text,
    json,
    setCookie: getSetCookie(res),
  };
}

/** A raw GET that does NOT follow the /console prefix normalization — used for
 *  the traversal probe, so the `..` reaches the server literally. */
async function rawGet(rawPath: string): Promise<Res> {
  // fetch() normalizes `..` in the URL, so hit the socket with a hand-built
  // request line to keep the traversal segment intact.
  const { connect } = await import("node:net");
  const u = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const sock = connect({ host: u.hostname, port: Number(u.port) }, () => {
      sock.write(`GET ${rawPath} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\n\r\n`);
    });
    let buf = "";
    sock.on("data", (d) => (buf += d.toString("utf8")));
    sock.on("end", () => {
      const [head, ...rest] = buf.split("\r\n\r\n");
      const statusLine = head.split("\r\n")[0] ?? "";
      const status = Number(statusLine.split(" ")[1] ?? 0);
      const ctLine = head.split("\r\n").find((l) => /^content-type:/i.test(l));
      const contentType = ctLine ? ctLine.split(":").slice(1).join(":").trim() : null;
      resolve({ status, contentType, location: null, text: rest.join("\r\n\r\n"), json: null, setCookie: [] });
    });
    sock.on("error", reject);
  });
}

async function loginCookie(email: string, password: string): Promise<string> {
  const res = await req("POST", "/auth/login", { body: { email, password } });
  expect(res.status).toBe(200);
  const line = res.setCookie.find((l) => l.startsWith(`${SESSION_COOKIE}=`));
  if (!line) throw new Error(`login for ${email} set no session cookie`);
  expect(line).toContain("HttpOnly");
  return line.split(";")[0]!;
}

// ---------------------------------------------------------------------------
// Boot: one kernel, a bootstrap owner + acme admin/auditor users, and seeded
// acme memory + audit so the read routes return real, subtree-scoped data.
// ---------------------------------------------------------------------------

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

  // A PLATFORM ROOT owner, provisioned directly: bootstrap now creates an
  // organization and an owner inside it (decision 9), never a root account.
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
    ["root-console-served", OWNER_EMAIL, hashPassword(OWNER_PASSWORD), new Date().toISOString()],
  );
  const ownerIdentity = await kernel.resolveSessionIdentity(
    (await kernel.login(OWNER_EMAIL, OWNER_PASSWORD))!.token,
  );
  if (!ownerIdentity) throw new Error("owner session did not resolve");

  await kernel.createUser(
    { email: ACME_ADMIN_EMAIL, namespace: "acme", role: "admin", password: ACME_ADMIN_PASSWORD },
    ownerIdentity,
  );
  await kernel.createUser(
    { email: ACME_AUDITOR_EMAIL, namespace: "acme", role: "auditor", password: ACME_AUDITOR_PASSWORD },
    ownerIdentity,
  );

  // A bootstrap owner API key → mint an agent badge to seed subtree memory.
  // Facts land AT `acme` (the tenant root) — not `acme/team` — so the scorecard
  // ScopedView for `acme` (read-down: self + ancestors, NOT descendants) sees
  // them and can build referee questions. The memory-map/overview read models
  // are self+descendants scoped, so they see `acme` facts too.
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const rootBadge = await kernel.auth.resolve(rootKey.plaintext);
  if (!rootBadge) throw new Error("root badge did not resolve");
  const acmeKey = await kernel.auth.issueKey("acme", "agent:acme", "agent", rootBadge);
  const acmeAgent = await kernel.auth.resolve(acmeKey.plaintext);
  if (!acmeAgent) throw new Error("acme agent did not resolve");

  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\n");

  // Seed several distinctive verbatim facts so the fact/audit/scorecard read
  // models all have real, subtree-scoped data.
  const facts = [
    `Acme refund window is thirty calendar days ${ACME_MARKER}`,
    `Acme premium tier ships free returns worldwide ${ACME_MARKER}`,
    `Acme warranty covers manufacturing defects two years ${ACME_MARKER}`,
  ];
  let firstFactId = "";
  for (const content of facts) {
    const w = sync(
      await kernel.memWrite({ scope: "team", content, hints: { verbatim: true } }, acmeAgent, AGENT),
    );
    if (!firstFactId) firstFactId = w.stored[0]!.id;
  }
  // Read + search to produce audit rows (fault/search/read/assemble ops).
  await kernel.memRead({ id: firstFactId }, acmeAgent, AGENT);
  await kernel.memRead({ id: firstFactId }, acmeAgent, AGENT);
  await kernel.memSearch({ query: "refund window", k: 3 }, acmeAgent, AGENT);

  server = createHttpServer(buildHttpDeps(kernel, { consoleDir: CONSOLE_DIR, secureCookies: false }));
  const port = await server.start(0);
  baseUrl = `http://127.0.0.1:${port}`;
}, 120_000);

afterAll(async () => {
  await server?.stop();
  await kernel?.close();
});

// ---------------------------------------------------------------------------
// (a) Static serving — public (no auth), correct content-types, traversal 403.
// ---------------------------------------------------------------------------

describe("static console - served publicly with correct content-types", () => {
  it("GET /console/ serves index.html as text/html WITHOUT auth", async () => {
    const res = await req("GET", "/console/");
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/text\/html/);
    // The real shell, not a placeholder.
    expect(res.text).toContain('id="stage"');
    expect(res.text).toContain('src="app.js"');
    expect(res.text).not.toMatch(/placeholder/i);
  });

  it("GET /console (no trailing slash) 308-redirects to the canonical /console/", async () => {
    const res = await req("GET", "/console");
    expect(res.status).toBe(308);
    expect(res.location).toBe("/console/");
  });

  it("GET /console/login (clean URL) serves the standalone login card", async () => {
    const res = await req("GET", "/console/login");
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/text\/html/);
    expect(res.text).toContain("/auth/login");
    expect(res.text).toContain("/auth/invite/accept");
    expect(res.text).toContain("<div><b>Halofy</b></div>");
    expect(res.text).toContain('id="submit">Sign in via email</button>');
    expect(res.text).toContain('id="tab-signup" role="tab" aria-selected="false">Create account</button>');
    expect(res.text).toContain('id="organization-name"');
    expect(res.text).not.toContain("/auth/bootstrap");
    expect(res.text).not.toContain("First installation?");
    expect(res.text).not.toContain("Create first owner");
  });

  it("GET /console/login.html 308-redirects to the clean URL, query preserved", async () => {
    const res = await req("GET", "/console/login.html?invite=abc123");
    expect(res.status).toBe(308);
    expect(res.location).toBe("/console/login?invite=abc123");
  });

  it("GET /console/signup redirects to the inline organization state", async () => {
    const res = await req("GET", "/console/signup");
    expect(res.status).toBe(308);
    expect(res.location).toBe("/console/login?signup=organization");
  });

  it("GET /console/signup.html redirects directly to the inline organization state", async () => {
    const res = await req("GET", "/console/signup.html");
    expect(res.status).toBe(308);
    expect(res.location).toBe("/console/login?signup=organization");
  });

  it("GET /console/onboarding is gone (the wizard was removed by the setup gate)", async () => {
    const res = await req("GET", "/console/onboarding");
    expect(res.status).toBe(404);
  });

  it("GET /console/index.html 308-redirects to /console/", async () => {
    const res = await req("GET", "/console/index.html");
    expect(res.status).toBe(308);
    expect(res.location).toBe("/console/");
  });

  it("GET /console/app.js is served as JavaScript", async () => {
    const res = await req("GET", "/console/app.js");
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/(text|application)\/javascript/);
    // app.js is the boot-on-import shell (no top-level exports); it defines the
    // esc() primitive and calls the API with credentials:'include'.
    expect(res.text).toContain("function esc");
    expect(res.text).toContain('credentials: "include"');
  });

  it("GET /console/app.css is served as CSS", async () => {
    const res = await req("GET", "/console/app.css");
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/text\/css/);
  });

  it("serves the self-hosted Inter variable font used by every console text role", async () => {
    const res = await req("GET", "/console/assets/fonts/InterVariable.woff2");
    expect(res.status).toBe(200);
    expect(res.contentType).toBe("font/woff2");
    expect(res.text.slice(0, 4)).toBe("wOF2");
  });

  it("GET /console/assets/footer-planet.webp is served as WebP", async () => {
    const res = await req("GET", "/console/assets/footer-planet.webp");
    expect(res.status).toBe(200);
    expect(res.contentType).toBe("image/webp");
  });

  it("every screen module GET /console/screens/s<N>.js is 200 JavaScript with a render export", async () => {
    for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) {
      const res = await req("GET", `/console/screens/s${n}.js`);
      expect(res.status, `s${n}.js status`).toBe(200);
      expect(res.contentType, `s${n}.js content-type`).toMatch(/(text|application)\/javascript/);
      // Each screen exports an async render(ctx).
      expect(res.text, `s${n}.js render export`).toMatch(/export\s+async\s+function\s+render/);
    }
  });

  it("GET /console/screens/policy-library.js serves the S4 library module", async () => {
    const res = await req("GET", "/console/screens/policy-library.js");
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/(text|application)\/javascript/);
    expect(res.text).toContain("renderPolicyLibrary");
    expect(res.text).toContain("policyLibraryActions");
  });

  it("path traversal is refused (403), never leaking a source file", async () => {
    // A plain `..` is collapsed by the WHATWG URL parser BEFORE serveStatic, so
    // it lands on a non-console route (never 200, source never served). An
    // ENCODED slash (%2f) survives URL parsing — the pathname keeps the whole
    // `%2e%2e%2f...` — so it reaches serveStatic proper, which decodes it to
    // `../...` and rejects the escape with a hard 403 (the traversal guard).
    const collapsed = await rawGet("/console/../src/http/console.ts");
    expect(collapsed.status).not.toBe(200);
    expect(collapsed.text).not.toContain("SESSION_COOKIE");

    const encoded = await rawGet("/console/%2e%2e%2fsrc%2fhttp%2fconsole.ts");
    expect(encoded.status).toBe(403);
    expect(encoded.text).not.toContain("SESSION_COOKIE");
  });

  it("a missing static file 404s", async () => {
    const res = await req("GET", "/console/screens/s99.js");
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// (b) Screen data endpoints — logged in as OWNER by cookie, seeded data back.
// ---------------------------------------------------------------------------

describe("screen data endpoints return the seeded data (owner session)", () => {
  it("GET /v1/admin/overview → l2Active + spend + fault figures", async () => {
    const cookie = await loginCookie(OWNER_EMAIL, OWNER_PASSWORD);
    const res = await req("GET", "/v1/admin/overview", { cookie });
    expect(res.status).toBe(200);
    const ov = res.json as { l2Active: number; spend: unknown; faultHitRate: number };
    // The three seeded verbatim facts landed in the acme subtree (L2).
    expect(ov.l2Active).toBeGreaterThanOrEqual(3);
    expect(ov.spend).toBeDefined();
    expect(typeof ov.faultHitRate).toBe("number");
  });

  it("GET /v1/admin/people → the acme admin + auditor users and the agent badge", async () => {
    const cookie = await loginCookie(OWNER_EMAIL, OWNER_PASSWORD);
    const res = await req("GET", "/v1/admin/people", { cookie });
    expect(res.status).toBe(200);
    const people = res.json as { users: { email: string }[]; badges: { actor: string }[] };
    const emails = people.users.map((u) => u.email);
    expect(emails).toContain(ACME_ADMIN_EMAIL);
    expect(emails).toContain(ACME_AUDITOR_EMAIL);
    expect(people.badges.some((b) => b.actor === "agent:acme")).toBe(true);
  });

  it("PUT team memory access is strict and server-authoritative", async () => {
    const cookie = await loginCookie(OWNER_EMAIL, OWNER_PASSWORD);
    const created = await req("POST", "/v1/admin/teams", {
      cookie,
      body: { name: "Marketing access integration" },
    });
    expect(created.status).toBe(201);
    const team = created.json as {
      id: string;
      memoryAccess: { mode: string; version: number };
    };
    expect(team.memoryAccess).toMatchObject({ mode: "related", version: 1 });

    const enabled = await req(
      "PUT",
      `/v1/admin/teams/${encodeURIComponent(team.id)}/memory-access`,
      { cookie, body: { mode: "company-published" } },
    );
    expect(enabled.status).toBe(200);
    expect(enabled.json).toMatchObject({
      id: team.id,
      memoryAccess: { mode: "company-published", version: 2 },
    });

    const forged = await req(
      "PUT",
      `/v1/admin/teams/${encodeURIComponent(team.id)}/memory-access`,
      { cookie, body: { mode: "related", namespace: "globex/finance" } },
    );
    expect(forged.status).toBe(400);

    const listed = await req("GET", "/v1/admin/teams", { cookie });
    const teams = listed.json as Array<{
      id: string;
      memoryAccess: { mode: string; version: number };
    }>;
    expect(teams.find((candidate) => candidate.id === team.id)?.memoryAccess)
      .toMatchObject({ mode: "company-published", version: 2 });
  });

  it("GET /v1/admin/memory-map?namespace=acme → the seeded acme facts, no leak", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("GET", "/v1/admin/memory-map?namespace=acme", { cookie });
    expect(res.status).toBe(200);
    const map = res.json as { namespace: string; hottest: { content: string }[] };
    expect(map.namespace).toBe("acme");
    expect(map.hottest.some((h) => h.content.includes(ACME_MARKER))).toBe(true);
  });

  it("GET /v1/admin/sources → the sources view shape (fresh: empty list, null frag)", async () => {
    const cookie = await loginCookie(OWNER_EMAIL, OWNER_PASSWORD);
    const res = await req("GET", "/v1/admin/sources", { cookie });
    expect(res.status).toBe(200);
    const view = res.json as { sources: unknown[]; latestFragmentation: unknown };
    expect(Array.isArray(view.sources)).toBe(true);
    expect("latestFragmentation" in (res.json as object)).toBe(true);
  });

  it("GET /v1/admin/audit → seeded, subtree-scoped audit rows", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("GET", "/v1/admin/audit", { cookie });
    expect(res.status).toBe(200);
    const rows = res.json as { namespace: string; op: string }[];
    expect(Array.isArray(rows)).toBe(true);
    expect(rows.length).toBeGreaterThan(0);
    // Every visible row is inside the acme subtree.
    expect(rows.every((r) => r.namespace.startsWith("acme"))).toBe(true);
  });

  it("POST /v1/admin/scorecard {namespace:acme} → a referee scorecard over the seeded facts", async () => {
    const cookie = await loginCookie(ACME_ADMIN_EMAIL, ACME_ADMIN_PASSWORD);
    const res = await req("POST", "/v1/admin/scorecard", { cookie, body: { namespace: "acme" } });
    expect(res.status).toBe(200);
    const card = res.json as { namespace: string; drivers: { driver: string }[]; winner: string };
    expect(card.namespace).toBe("acme");
    expect(Array.isArray(card.drivers)).toBe(true);
    expect(card.drivers.length).toBeGreaterThan(0);
    // The referee row shape the screen reads: `driver` (not `name`).
    expect(typeof card.drivers[0]!.driver).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// (c) Role contract — auditor: reads 200, mutations 403 (the UI-encoded gate).
// ---------------------------------------------------------------------------

describe("auditor session - read endpoints 200, mutation endpoints 403", () => {
  it("the read screens (overview / people / sources / audit) are 200 for an auditor", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);
    for (const route of ["/v1/admin/overview", "/v1/admin/people", "/v1/admin/sources", "/v1/admin/audit"]) {
      const res = await req("GET", route, { cookie });
      expect(res.status, `GET ${route}`).toBe(200);
    }
  });

  it("forget / invite / connect-source are 403 for an auditor", async () => {
    const cookie = await loginCookie(ACME_AUDITOR_EMAIL, ACME_AUDITOR_PASSWORD);

    const forget = await req("POST", "/v1/admin/forget", {
      cookie,
      body: { target: { kind: "namespace", value: "acme" } },
    });
    expect(forget.status).toBe(403);

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
  });
});
