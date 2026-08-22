/**
 * Supabase SSO for the control room — service + transport tests.
 *
 * Service lane (real PGlite stores, stubbed IdP fetch):
 *  - a verified token whose email matches an ACTIVE kernel user mints a
 *    session that resolves to that user's identity;
 *  - a verified token whose email holds a live PENDING INVITATION consumes it
 *    into a passwordless (SSO-only) user — password login stays impossible;
 *  - unknown email / disabled user / expired invitation → no_account
 *    (authenticated at the IdP, not authorized here);
 *  - invalid or malformed tokens → unauthenticated, and header-injection-shaped
 *    tokens never reach fetch;
 *  - env factory: unset → null, plain and NEXT_PUBLIC_ names both accepted.
 *
 * Transport lane (hand-rolled deps, real node:http server):
 *  - GET /auth/sso/config is open and reflects enabled/disabled;
 *  - POST /auth/sso: ok → 200 + HttpOnly session cookie; no_account → 403
 *    `no_console_access` with NO cookie; unauthenticated → 401; missing
 *    access_token → 400; absent handler → 404.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  InvitationStore,
  hashPassword,
  SessionStore,
  UserStore,
  login as sessionLogin,
  resolveSessionIdentity,
} from "../src/console/auth.js";
import { SupabaseSsoService, supabaseSsoFromEnv } from "../src/console/sso.js";
import { OrganizationSignupService } from "../src/console/signup.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
const BOOTSTRAP_TOKEN = "b".repeat(64);
const SUPABASE_URL = "https://project.supabase.test";
const ANON_KEY = "anon-key-public";

const ROOT: Identity = {
  keyId: "sess_root",
  namespace: "",
  actor: "root@example.test",
  role: "owner",
};

let db: Db;
let users: UserStore;
let sessions: SessionStore;
let invitations: InvitationStore;
let signup: OrganizationSignupService;

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  users = new UserStore(db);
  sessions = new SessionStore(db);
  invitations = new InvitationStore(db);
  signup = new OrganizationSignupService(db);
});

afterAll(async () => {
  await db.close();
});

beforeEach(async () => {
  await db.query(`DELETE FROM sessions`);
  await db.query(`DELETE FROM users`);
  await db.query(`DELETE FROM auth_invitations`);
  await db.query(`DELETE FROM auth_signup_sessions`);
  await db.query(`DELETE FROM auth_bootstrap`);
});

/**
 * Create the platform-root human so UserStore.create accepts callers.
 *
 * Provisioned directly: no product path mints a human at namespace `""` any
 * more (CONTRACTS-SELF-SERVICE-ONBOARDING.md decision 9 — bootstrap creates an
 * organization and puts its owner inside it), so root is an operator-only
 * capability and the fixture models it that way.
 */
async function bootstrapRoot(): Promise<void> {
  await db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
    [
      `root-${ROOT.actor}`,
      ROOT.actor,
      hashPassword("correct horse battery staple"),
      new Date().toISOString(),
    ],
  );
}

/**
 * A GoTrue stub: any token present in `known` yields 200 { email }, everything
 * else 401. Records every request so tests can assert what (never) left.
 */
type StubIdentity = {
  email: string;
  confirmedAt?: string | null;
};

function stubIdp(
  known: Record<string, string | StubIdentity>,
  settings: { externalEmail?: boolean; mailerAutoconfirm?: boolean; status?: number } = {},
) {
  const calls: { url: string; auth: string | undefined }[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const auth = headers.authorization;
    calls.push({ url, auth });
    if (url.endsWith("/auth/v1/settings")) {
      return new Response(JSON.stringify({
        external: { email: settings.externalEmail ?? true },
        mailer_autoconfirm: settings.mailerAutoconfirm ?? false,
      }), { status: settings.status ?? 200 });
    }
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
    const identity = known[token];
    if (identity === undefined) {
      return new Response(JSON.stringify({ msg: "invalid JWT" }), { status: 401 });
    }
    const record = typeof identity === "string" ? { email: identity } : identity;
    return new Response(JSON.stringify({
      id: "sb-user",
      email: record.email,
      email_confirmed_at: record.confirmedAt === null
        ? null
        : (record.confirmedAt ?? "2026-07-19T00:00:00.000Z"),
    }), { status: 200 });
  }) as typeof fetch;
  return { fetchFn, calls };
}

function service(
  known: Record<string, string | StubIdentity>,
  options: {
    emailDeliveryReady?: boolean;
    allowOrganizationSignup?: boolean;
    settings?: { externalEmail?: boolean; mailerAutoconfirm?: boolean; status?: number };
  } = {},
) {
  const idp = stubIdp(known, options.settings);
  const sso = new SupabaseSsoService({
    url: SUPABASE_URL,
    anonKey: ANON_KEY,
    emailDeliveryReady: options.emailDeliveryReady,
    stores: { users, sessions },
    invitations,
    signup,
    allowOrganizationSignup: options.allowOrganizationSignup,
    fetchFn: idp.fetchFn,
  });
  return { sso, idp };
}

describe("SupabaseSsoService.exchange", () => {
  it("mints a session for an existing active user (email normalized)", async () => {
    await bootstrapRoot();
    await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const { sso, idp } = service({ "tok-1": "  Member@Acme.TEST " });

    const result = await sso.exchange("tok-1");
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user).toMatchObject({
      email: "member@acme.test",
      namespace: "acme",
      role: "member",
    });

    const identity = await resolveSessionIdentity({ users, sessions }, result.token);
    expect(identity).toMatchObject({
      namespace: "acme",
      actor: "member@acme.test",
      role: "member",
    });
    // The token was verified against the project's user endpoint.
    expect(idp.calls[0].url).toBe(`${SUPABASE_URL}/auth/v1/user`);
  });

  it("consumes a live pending invitation into a passwordless SSO-only user", async () => {
    await bootstrapRoot();
    await invitations.create(
      { email: "invited@acme.test", namespace: "acme/eng", role: "admin" },
      ROOT,
    );
    const { sso } = service({ "tok-2": "invited@acme.test" });

    const result = await sso.exchange("tok-2");
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user).toMatchObject({
      email: "invited@acme.test",
      namespace: "acme/eng",
      role: "admin",
      status: "active",
    });

    // The invitation is consumed and the row is passwordless.
    const rows = await db.query(
      `SELECT password_hash FROM users WHERE email = 'invited@acme.test'`,
    );
    expect(rows.rows[0].password_hash).toBeNull();
    const invite = await db.query(
      `SELECT accepted_at FROM auth_invitations WHERE email = 'invited@acme.test'`,
    );
    expect(invite.rows[0].accepted_at).not.toBeNull();
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM auth_signup_sessions`)).rows[0].n)).toBe(0);

    // Password login can never work for an SSO-only account (no oracle).
    expect(
      await sessionLogin({ users, sessions }, "invited@acme.test", "any password at all"),
    ).toBeNull();

    // A second exchange now hits the existing-user path, not the invitation.
    const again = await sso.exchange("tok-2");
    expect(again.status).toBe("ok");
  });

  it("starts self-service onboarding for an authenticated email with no account", async () => {
    await bootstrapRoot();
    const { sso } = service({ "tok-3": "stranger@else.test" });
    expect(await sso.exchange("tok-3")).toMatchObject({
      status: "onboarding_required",
      email: "stranger@else.test",
    });
    expect((await db.query(`SELECT COUNT(*) AS n FROM auth_signup_sessions`)).rows[0].n).toBe(1);
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM users`)).rows[0].n)).toBe(1);
  });

  it("requires an invitation for unknown identities during early access", async () => {
    await bootstrapRoot();
    const { sso } = service(
      { "tok-early": "stranger@else.test" },
      { allowOrganizationSignup: false },
    );
    expect(await sso.exchange("tok-early")).toEqual({
      status: "no_account",
      email: "stranger@else.test",
    });
    expect((await db.query(`SELECT COUNT(*) AS n FROM auth_signup_sessions`)).rows[0].n).toBe(0);
  });

  it("refuses a disabled user - SSO cannot resurrect a disabled account", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "gone@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await users.disable(user.id);
    const { sso } = service({ "tok-4": "gone@acme.test" });
    expect((await sso.exchange("tok-4")).status).toBe("no_account");
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM auth_signup_sessions`)).rows[0].n)).toBe(0);
  });

  it("refuses an expired invitation", async () => {
    await bootstrapRoot();
    const past = new InvitationStore(db, () => new Date("2026-01-01T00:00:00.000Z"));
    await past.create(
      { email: "late@acme.test", namespace: "acme", role: "member", ttlSeconds: 60 },
      ROOT,
    );
    const { sso } = service({ "tok-5": "late@acme.test" });
    expect((await sso.exchange("tok-5")).status).toBe("onboarding_required");
  });

  it("maps an invalid token to unauthenticated", async () => {
    await bootstrapRoot();
    const { sso } = service({});
    expect(await sso.exchange("garbage")).toEqual({ status: "unauthenticated" });
  });

  it("requires a confirmed email from the configured identity provider", async () => {
    await bootstrapRoot();
    const { sso } = service({
      token: { email: ROOT.actor, confirmedAt: null },
    });
    expect(await sso.exchange("token")).toEqual({ status: "unauthenticated" });
  });

  it("allows confirmed identities without enabling outbound email", async () => {
    await bootstrapRoot();
    const { sso, idp } = service({
      token: { email: ROOT.actor },
    });
    expect((await sso.exchange("token")).status).toBe("ok");
    expect(idp.calls.map((call) => call.url)).toEqual([
      `${SUPABASE_URL}/auth/v1/user`,
      `${SUPABASE_URL}/auth/v1/settings`,
    ]);
  });

  it("accepts a confirmed identity only when auto-confirm is disabled", async () => {
    await bootstrapRoot();
    const { sso } = service({
      token: { email: ROOT.actor },
    });
    expect((await sso.exchange("token")).status).toBe("ok");
  });

  it("refuses every identity if provider auto-confirm is enabled", async () => {
    await bootstrapRoot();
    const { sso } = service(
      { token: { email: ROOT.actor } },
      { settings: { mailerAutoconfirm: true } },
    );
    expect(await sso.exchange("token")).toEqual({ status: "unauthenticated" });
  });

  it("fails closed when the provider settings cannot be verified", async () => {
    await bootstrapRoot();
    const { sso } = service(
      { token: { email: ROOT.actor } },
      { settings: { status: 503 } },
    );
    expect(await sso.exchange("token")).toEqual({ status: "unauthenticated" });
  });

  it("rejects malformed tokens before any network call (header injection)", async () => {
    const { sso, idp } = service({ "tok-6": "member@acme.test" });
    expect((await sso.exchange("evil\r\nx-injected: 1")).status).toBe("unauthenticated");
    expect((await sso.exchange("")).status).toBe("unauthenticated");
    expect((await sso.exchange("a".repeat(9000))).status).toBe("unauthenticated");
    expect(idp.calls).toHaveLength(0);
  });
});

describe("supabaseSsoFromEnv", () => {
  const deps = () => ({ stores: { users, sessions }, invitations, signup });

  it("returns null when unconfigured and a service when configured", () => {
    expect(supabaseSsoFromEnv(deps(), {})).toBeNull();
    expect(supabaseSsoFromEnv(deps(), { SUPABASE_URL })).toBeNull();
    expect(
      supabaseSsoFromEnv(deps(), { SUPABASE_URL, SUPABASE_ANON_KEY: ANON_KEY }),
    ).toBeInstanceOf(SupabaseSsoService);
  });

  it("accepts the NEXT_PUBLIC_-prefixed variable names", () => {
    const sso = supabaseSsoFromEnv(deps(), {
      NEXT_PUBLIC_SUPABASE_URL: SUPABASE_URL,
      NEXT_PUBLIC_SUPABASE_ANON_KEY: ANON_KEY,
    });
    expect(sso).toBeInstanceOf(SupabaseSsoService);
    expect(sso?.publicConfig()).toEqual({
      enabled: true,
      url: SUPABASE_URL,
      anonKey: ANON_KEY,
      emailDeliveryReady: false,
    });
  });

  it("enables outbound email flows only through the explicit readiness gate", () => {
    const ready = supabaseSsoFromEnv(deps(), {
      SUPABASE_URL,
      SUPABASE_ANON_KEY: ANON_KEY,
      HALOMEM_SSO_EMAIL_DELIVERY_READY: "true",
    });
    expect(ready?.publicConfig().emailDeliveryReady).toBe(true);

    const notReady = supabaseSsoFromEnv(deps(), {
      SUPABASE_URL,
      SUPABASE_ANON_KEY: ANON_KEY,
      HALOMEM_SSO_EMAIL_DELIVERY_READY: "TRUE",
    });
    expect(notReady?.publicConfig().emailDeliveryReady).toBe(false);
  });

  it("closes unknown-organization signup under early access", async () => {
    await bootstrapRoot();
    const idp = stubIdp({ "tok-gate": "stranger@else.test" });
    const sso = supabaseSsoFromEnv(
      { ...deps(), fetchFn: idp.fetchFn },
      { SUPABASE_URL, SUPABASE_ANON_KEY: ANON_KEY, HALOMEM_EARLY_ACCESS: "true" },
    );
    expect((await sso!.exchange("tok-gate")).status).toBe("no_account");
  });

  it("reopens unknown-organization signup through the override, early access still on", async () => {
    await bootstrapRoot();
    const idp = stubIdp({ "tok-open": "stranger@else.test" });
    const sso = supabaseSsoFromEnv(
      { ...deps(), fetchFn: idp.fetchFn },
      {
        SUPABASE_URL,
        SUPABASE_ANON_KEY: ANON_KEY,
        HALOMEM_EARLY_ACCESS: "true",
        HALOMEM_ALLOW_ORG_SIGNUP: "true",
      },
    );
    expect((await sso!.exchange("tok-open")).status).toBe("onboarding_required");
  });

  it("rejects a non-http(s) project url", () => {
    expect(
      supabaseSsoFromEnv(deps(), {
        SUPABASE_URL: "file:///etc/passwd",
        SUPABASE_ANON_KEY: ANON_KEY,
      }),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Transport lane
// ---------------------------------------------------------------------------

const OWNER: Identity = {
  keyId: "sess_owner",
  namespace: "acme",
  actor: "owner@acme.test",
  role: "owner",
};

function makeDeps(withSso: boolean): HttpServerDeps {
  const syscall = async (): Promise<unknown> => ({ ok: true });
  return {
    secureCookies: false,
    auth: {
      async resolve() {
        return null;
      },
      async resolveSession(token: string) {
        return token === "live-sso-token" ? OWNER : null;
      },
      ssoConfig: withSso
        ? () => ({
            enabled: true,
            url: SUPABASE_URL,
            anonKey: ANON_KEY,
            emailDeliveryReady: true,
          })
        : undefined,
      ssoExchange: withSso
        ? async (accessToken: string) => {
            if (accessToken === "idp-good") {
              return {
                status: "ok" as const,
                token: "live-sso-token",
                user: { id: "u1", email: OWNER.actor, namespace: "acme", role: "owner" },
              };
            }
            if (accessToken === "idp-uninvited") {
              return { status: "no_account" as const, email: "x@y.test" };
            }
            return { status: "unauthenticated" as const };
          }
        : undefined,
    },
    syscalls: {
      memRead: syscall,
      memSearch: syscall,
      memWrite: syscall,
      memFault: syscall,
      memStats: syscall,
      memAssemble: syscall,
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
    },
    metrics: { snapshot: () => ({ ok: true }) },
    audit: {
      async append() {
        /* not under test */
      },
    },
    buildMcpServer() {
      throw new Error("not used in this suite");
    },
  };
}

function setCookies(res: Response): string[] {
  const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(res.headers);
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

describe("SSO transport", () => {
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    server = createHttpServer(makeDeps(true));
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
  });

  it("GET /auth/sso/config is open and returns the public IdP config", async () => {
    const res = await fetch(base + "/auth/sso/config");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      enabled: true,
      url: SUPABASE_URL,
      anonKey: ANON_KEY,
      emailDeliveryReady: true,
      github: false,
    });
  });

  it("POST /auth/sso with a good IdP token sets the session cookie", async () => {
    const res = await fetch(base + "/auth/sso", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_token: "idp-good" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string } };
    expect(body.user.email).toBe(OWNER.actor);
    const cookie = setCookies(res).find((l) => l.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("live-sso-token");

    // The minted cookie authenticates a console API call.
    const me = await fetch(base + "/auth/me", {
      headers: { cookie: `${SESSION_COOKIE}=live-sso-token` },
    });
    expect(me.status).toBe(200);
  });

  it("POST /auth/sso for an authenticated-but-uninvited email → 403, no cookie", async () => {
    const res = await fetch(base + "/auth/sso", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_token: "idp-uninvited" }),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("no_console_access");
    expect(setCookies(res).find((l) => l.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
  });

  it("POST /auth/sso with an invalid token → 401", async () => {
    const res = await fetch(base + "/auth/sso", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_token: "nope" }),
    });
    expect(res.status).toBe(401);
  });

  it("POST /auth/sso without access_token → 400", async () => {
    const res = await fetch(base + "/auth/sso", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("CSP connect-src includes the IdP origin so the login page can reach GoTrue", async () => {
    const res = await fetch(base + "/auth/sso/config");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain(`connect-src 'self' ${SUPABASE_URL}`);
  });

  it("an SSO-less deployment reports disabled and 404s the exchange", async () => {
    const bare = createHttpServer(makeDeps(false));
    const port = await bare.start(0);
    try {
      const cfg = await fetch(`http://127.0.0.1:${port}/auth/sso/config`);
      expect(await cfg.json()).toEqual({ enabled: false, github: false });
      expect(cfg.headers.get("content-security-policy")).toContain("connect-src 'self';");
      const res = await fetch(`http://127.0.0.1:${port}/auth/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ access_token: "idp-good" }),
      });
      expect(res.status).toBe(404);
    } finally {
      await bare.stop();
    }
  });
});
