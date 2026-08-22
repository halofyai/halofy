/**
 * GitHub OAuth for the control room — service + transport tests.
 *
 * Service lane (real PGlite stores, stubbed GitHub fetch):
 *  - a LINKED GitHub identity resolves to the same users row as email login;
 *  - an UNLINKED GitHub login auto-provisions a separate passwordless account
 *    in its own gh/<id> namespace — even when the verified email matches an
 *    existing user (email match alone NEVER merges);
 *  - a live pending invitation for the verified email is consumed + linked;
 *  - a disabled linked user is no_account; missing verified email falls back
 *    to the GitHub noreply alias;
 *  - link conflicts (GitHub tied to a different user, or a second GitHub for
 *    the same user) raise IdentityConflictError; unlink is idempotent;
 *  - exchange/profile failures collapse to null (brownout);
 *  - env factory: unset → null, both vars → service.
 *
 * Transport lane (hand-rolled deps, real node:http server):
 *  - GET /auth/github 302s to the authorize URL with an HttpOnly state cookie;
 *  - the callback rejects a missing/mismatched state with 400;
 *  - login mode: ok → 302 /console/ + session cookie; failure → 302 back to
 *    /console/login?error=github_*;
 *  - link mode: no session → 302 /console/login; linked → 302
 *    /console/#settings?linked=github; conflict → #settings?error=github_conflict;
 *  - GET /auth/identities + DELETE /auth/identities/github round-trip;
 *  - unconfigured deployment: routes 404, config reports github:false.
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
import {
  ExternalIdentityStore,
  GitHubOAuthService,
  IdentityConflictError,
  githubOAuthFromEnv,
  type GitHubProfile,
} from "../src/console/github-sso.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { OAUTH_STATE_COOKIE, SESSION_COOKIE } from "../src/http/console.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
const BOOTSTRAP_TOKEN = "b".repeat(64);
const REDIRECT_URI = "https://halomem.test/auth/github/callback";

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
let identities: ExternalIdentityStore;

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  users = new UserStore(db);
  sessions = new SessionStore(db);
  invitations = new InvitationStore(db);
  identities = new ExternalIdentityStore(db);
});

afterAll(async () => {
  await db.close();
});

beforeEach(async () => {
  await db.query(`DELETE FROM user_external_identities`);
  await db.query(`DELETE FROM sessions`);
  await db.query(`DELETE FROM users`);
  await db.query(`DELETE FROM auth_invitations`);
  await db.query(`DELETE FROM auth_bootstrap`);
});

/**
 * Create the platform-root human so UserStore.create accepts callers.
 * Provisioned directly — bootstrap now creates an organization and an owner
 * inside it, never a root account (decision 9).
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
 * A GitHub stub: the code exchange mints `gh-<code>` tokens, and a token maps
 * to a fixed profile. Everything else is a 401/400-shaped failure.
 */
type StubProfile = { id: number; login: string; email?: string | null };

function stubGitHub(
  profiles: Record<string, StubProfile>,
  options: { tokenStatus?: number; userStatus?: number; emailsStatus?: number } = {},
) {
  const calls: { url: string; method: string }[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: init?.method ?? "GET" });
    if (url === "https://github.com/login/oauth/access_token") {
      if (options.tokenStatus !== undefined) {
        return new Response("gateway error", { status: options.tokenStatus });
      }
      const body = JSON.parse(String(init?.body ?? "{}")) as { code?: string };
      if (body.code === "bad-code") {
        return new Response(JSON.stringify({ error: "bad_verification_code" }), { status: 200 });
      }
      return new Response(
        JSON.stringify({ access_token: `gh-${body.code}`, token_type: "bearer" }),
        { status: 200 },
      );
    }
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const auth = headers.authorization;
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
    const profile = profiles[token];
    if (url === "https://api.github.com/user") {
      if (options.userStatus !== undefined) {
        return new Response("error", { status: options.userStatus });
      }
      if (profile === undefined) {
        return new Response(JSON.stringify({ message: "Bad credentials" }), { status: 401 });
      }
      return new Response(JSON.stringify({ id: profile.id, login: profile.login }), { status: 200 });
    }
    if (url === "https://api.github.com/user/emails") {
      if (options.emailsStatus !== undefined) {
        return new Response("error", { status: options.emailsStatus });
      }
      if (profile === undefined) {
        return new Response(JSON.stringify({ message: "Bad credentials" }), { status: 401 });
      }
      const entries =
        typeof profile.email === "string"
          ? [{ email: profile.email, primary: true, verified: true }]
          : [];
      return new Response(JSON.stringify(entries), { status: 200 });
    }
    throw new Error(`unexpected GitHub url: ${url}`);
  }) as typeof fetch;
  return { fetchFn, calls };
}

function service(
  profiles: Record<string, StubProfile>,
  options: {
    tokenStatus?: number;
    userStatus?: number;
    emailsStatus?: number;
    allowOrganizationSignup?: boolean;
  } = {},
) {
  const gh = stubGitHub(profiles, options);
  const oauth = new GitHubOAuthService({
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    db,
    stores: { users, sessions },
    invitations,
    identities,
    fetchFn: gh.fetchFn,
    allowOrganizationSignup: options.allowOrganizationSignup,
  });
  return { oauth, gh };
}

/** Run the exchange + profile read for a code, asserting both succeed. */
async function profileOf(oauth: GitHubOAuthService, code: string): Promise<GitHubProfile> {
  const token = await oauth.exchangeCode(code, REDIRECT_URI);
  expect(token).not.toBeNull();
  const profile = await oauth.fetchProfile(token as string);
  expect(profile).not.toBeNull();
  return profile as GitHubProfile;
}

describe("GitHubOAuthService.loginWithGitHub", () => {
  it("a linked GitHub identity resolves to the SAME account as email login", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member", password: "twelve chars pw" },
      ROOT,
    );
    const profile: GitHubProfile = { id: "123", login: "octocat", email: "member@acme.test" };
    await identities.link(user.id, "github", profile);
    const { oauth } = service({ "gh-good": { id: 123, login: "octocat", email: "member@acme.test" } });

    const result = await oauth.loginWithGitHub(profile);
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user.id).toBe(user.id);

    const ghIdentity = await resolveSessionIdentity({ users, sessions }, result.token);
    expect(ghIdentity).toMatchObject({ namespace: "acme", actor: "member@acme.test", role: "member" });

    // Email+password login lands on the same user row.
    const pw = await sessionLogin({ users, sessions }, "member@acme.test", "twelve chars pw");
    expect(pw).not.toBeNull();
    expect(pw?.identity.actor).toBe("member@acme.test");
  });

  it("an unlinked GitHub login auto-provisions a SEPARATE account, never merging by email", async () => {
    await bootstrapRoot();
    const existing = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const { oauth } = service({});
    const profile: GitHubProfile = { id: "999", login: "newcat", email: "member@acme.test" };

    const result = await oauth.loginWithGitHub(profile);
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    // Different account: the email is taken, so the noreply alias keys the row.
    expect(result.user.id).not.toBe(existing.id);
    expect(result.user.email).toBe("999+newcat@users.noreply.github.com");
    expect(result.user.namespace).toBe("gh/999");
    expect(result.user.role).toBe("owner");

    // The email account is untouched.
    const untouched = await users.byEmail("member@acme.test");
    expect(untouched?.id).toBe(existing.id);

    // The provisioned account is passwordless — no password login possible.
    expect(
      await sessionLogin({ users, sessions }, result.user.email, "any password at all"),
    ).toBeNull();

    // A second GitHub login hits the linked path → same provisioned account.
    const again = await oauth.loginWithGitHub(profile);
    expect(again.status).toBe("ok");
    if (again.status === "ok") expect(again.user.id).toBe(result.user.id);
  });

  it("auto-provisions under the verified email when it is not taken", async () => {
    await bootstrapRoot();
    const { oauth } = service({});
    const result = await oauth.loginWithGitHub({ id: "555", login: "fresh", email: "fresh@new.test" });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user).toMatchObject({
      email: "fresh@new.test",
      namespace: "gh/555",
      role: "owner",
    });
    const link = await identities.findByProviderId("github", "555");
    expect(link?.userId).toBe(result.user.id);
  });

  it("requires an invitation for an unknown GitHub identity during early access", async () => {
    await bootstrapRoot();
    const { oauth } = service({}, { allowOrganizationSignup: false });

    await expect(oauth.loginWithGitHub({
      id: "556",
      login: "uninvited",
      email: "uninvited@new.test",
    })).resolves.toEqual({ status: "no_account" });
    expect(await users.byEmail("uninvited@new.test")).toBeNull();
    expect(await identities.findByProviderId("github", "556")).toBeNull();
  });

  it("consumes a live pending invitation for the verified email and links it", async () => {
    await bootstrapRoot();
    await invitations.create(
      { email: "invited@acme.test", namespace: "acme/eng", role: "admin" },
      ROOT,
    );
    const { oauth } = service({});
    const result = await oauth.loginWithGitHub({ id: "777", login: "invitedgh", email: "invited@acme.test" });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user).toMatchObject({
      email: "invited@acme.test",
      namespace: "acme/eng",
      role: "admin",
    });
    const invite = await db.query(
      `SELECT accepted_at FROM auth_invitations WHERE email = 'invited@acme.test'`,
    );
    expect(invite.rows[0].accepted_at).not.toBeNull();
    const link = await identities.findByProviderId("github", "777");
    expect(link?.userId).toBe(result.user.id);
  });

  it("refuses a disabled linked user - GitHub login cannot resurrect it", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "gone@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const profile: GitHubProfile = { id: "321", login: "gonegh", email: "gone@acme.test" };
    await identities.link(user.id, "github", profile);
    await users.disable(user.id);
    const { oauth } = service({});
    expect((await oauth.loginWithGitHub(profile)).status).toBe("no_account");
  });

  it("falls back to the noreply alias when GitHub reports no verified email", async () => {
    await bootstrapRoot();
    const { oauth } = service({});
    const result = await oauth.loginWithGitHub({ id: "321", login: "NoMail", email: null });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user.email).toBe("321+nomail@users.noreply.github.com");
  });
});

describe("ExternalIdentityStore", () => {
  it("rejects a GitHub account already linked to a different user", async () => {
    await bootstrapRoot();
    const a = await users.create({ email: "a@acme.test", namespace: "acme", role: "member" }, ROOT);
    const b = await users.create({ email: "b@acme.test", namespace: "acme", role: "member" }, ROOT);
    await identities.link(a.id, "github", { id: "123", login: "octocat", email: null });

    // Same pair → idempotent.
    await identities.link(a.id, "github", { id: "123", login: "octocat", email: null });
    // Same GitHub, different user → conflict.
    await expect(
      identities.link(b.id, "github", { id: "123", login: "octocat", email: null }),
    ).rejects.toBeInstanceOf(IdentityConflictError);
    // A second GitHub account for the same user → conflict.
    await expect(
      identities.link(a.id, "github", { id: "456", login: "hubot", email: null }),
    ).rejects.toBeInstanceOf(IdentityConflictError);
  });

  it("unlink removes the connection and is idempotent", async () => {
    await bootstrapRoot();
    const user = await users.create({ email: "a@acme.test", namespace: "acme", role: "member" }, ROOT);
    await identities.link(user.id, "github", { id: "123", login: "octocat", email: null });
    expect(await identities.unlink(user.id, "github")).toBe(true);
    expect(await identities.findForUser(user.id, "github")).toBeNull();
    expect(await identities.unlink(user.id, "github")).toBe(false);
  });
});

describe("GitHub exchange/profile brownout", () => {
  it("maps a rejected code exchange to null", async () => {
    const { oauth } = service({});
    expect(await oauth.exchangeCode("bad-code", REDIRECT_URI)).toBeNull();
  });

  it("maps a GitHub outage to null on both legs", async () => {
    const { oauth } = service(
      { "gh-good": { id: 1, login: "x" } },
      { tokenStatus: 502 },
    );
    expect(await oauth.exchangeCode("good", REDIRECT_URI)).toBeNull();

    const userDown = service({ "gh-good": { id: 1, login: "x" } }, { userStatus: 503 });
    expect(await userDown.oauth.fetchProfile("gh-good")).toBeNull();
  });

  it("maps a throwing fetch to null (network unreachable)", async () => {
    const throwing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    const oauth = new GitHubOAuthService({
      clientId: "id",
      clientSecret: "secret",
      db,
      stores: { users, sessions },
      invitations,
      identities,
      fetchFn: throwing,
    });
    expect(await oauth.exchangeCode("good", REDIRECT_URI)).toBeNull();
    expect(await oauth.fetchProfile("gh-good")).toBeNull();
  });

  it("reads the profile server-side and keeps only the primary verified email", async () => {
    const { oauth, gh } = service({
      "gh-good": { id: 42, login: "octocat", email: "Octo@Acme.TEST" },
    });
    const profile = await profileOf(oauth, "good");
    expect(profile).toEqual({
      id: "42",
      login: "octocat",
      displayName: "octocat",
      email: "octo@acme.test",
    });
    expect(gh.calls.map((call) => call.url)).toEqual([
      "https://github.com/login/oauth/access_token",
      "https://api.github.com/user",
      "https://api.github.com/user/emails",
    ]);
  });
});

describe("githubOAuthFromEnv", () => {
  const deps = () => ({ db, stores: { users, sessions }, invitations, identities });

  it("returns null when unconfigured and a service when configured", () => {
    expect(githubOAuthFromEnv(deps(), {})).toBeNull();
    expect(githubOAuthFromEnv(deps(), { HALOMEM_GITHUB_CLIENT_ID: "id" })).toBeNull();
    expect(
      githubOAuthFromEnv(deps(), {
        HALOMEM_GITHUB_CLIENT_ID: "id",
        HALOMEM_GITHUB_CLIENT_SECRET: "secret",
      }),
    ).toBeInstanceOf(GitHubOAuthService);
  });

  it("keeps unknown-organization signup open when the override says so", async () => {
    const oauth = githubOAuthFromEnv(deps(), {
      HALOMEM_GITHUB_CLIENT_ID: "id",
      HALOMEM_GITHUB_CLIENT_SECRET: "secret",
      HALOMEM_EARLY_ACCESS: "true",
      HALOMEM_ALLOW_ORG_SIGNUP: "true",
    });
    const result = await oauth!.loginWithGitHub({
      id: "open-558",
      login: "open",
      email: "open@new.test",
    });
    expect(result.status).toBe("ok");
  });

  it("disables unknown-organization signup when early access is enabled", async () => {
    const oauth = githubOAuthFromEnv(deps(), {
      HALOMEM_GITHUB_CLIENT_ID: "id",
      HALOMEM_GITHUB_CLIENT_SECRET: "secret",
      HALOMEM_EARLY_ACCESS: "true",
    });
    expect(oauth).toBeInstanceOf(GitHubOAuthService);
    await expect(oauth!.loginWithGitHub({
      id: "early-557",
      login: "early",
      email: "early@new.test",
    })).resolves.toEqual({ status: "no_account" });
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

const STRANGER: Identity = {
  keyId: "sess_stranger",
  namespace: "else",
  actor: "stranger@else.test",
  role: "member",
};

function makeDeps(withGitHub: boolean, publicUrl?: string): HttpServerDeps {
  const syscall = async (): Promise<unknown> => ({ ok: true });
  return {
    secureCookies: false,
    publicUrl,
    auth: {
      async resolve() {
        return null;
      },
      async resolveSession(token: string) {
        if (token === "live-session-token") return OWNER;
        if (token === "stranger-token") return STRANGER;
        return null;
      },
      githubConfig: withGitHub ? () => true : undefined,
      githubAuthorize: withGitHub
        ? (state: string, redirectUri: string) =>
            `https://github.test/authorize?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`
        : undefined,
      githubLogin: withGitHub
        ? async (code: string) => {
            if (code === "good") {
              return {
                status: "ok" as const,
                token: "live-session-token",
                user: { id: "u1", email: OWNER.actor, namespace: "acme", role: "owner" },
              };
            }
            if (code === "disabled") return { status: "no_account" as const };
            return { status: "unauthenticated" as const };
          }
        : undefined,
      githubLink: withGitHub
        ? async (code: string, _redirectUri: string, identity: Identity) => {
            if (identity.actor !== OWNER.actor) return { status: "unauthenticated" as const };
            if (code === "good") return { status: "linked" as const, login: "octocat" };
            if (code === "taken") return { status: "conflict" as const };
            return { status: "unauthenticated" as const };
          }
        : undefined,
      listIdentities: async (identity: Identity) => ({
        identities:
          identity.actor === OWNER.actor
            ? [{
                id: "e1",
                userId: "u1",
                provider: "github",
                providerAccountId: "123",
                login: "octocat",
                email: OWNER.actor,
                createdAt: "2026-07-20T00:00:00.000Z",
              }]
            : [],
      }),
      unlinkIdentity: async (identity: Identity, provider: string) =>
        provider === "github" && identity.actor === OWNER.actor,
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

describe("GitHub OAuth transport", () => {
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

  /** Start the flow and return the state nonce + the cookie header to replay. */
  async function startFlow(mode?: string): Promise<{ state: string; cookie: string }> {
    const res = await fetch(base + "/auth/github" + (mode ? `?mode=${mode}` : ""), {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("location") ?? "";
    expect(location.startsWith("https://github.test/authorize?state=")).toBe(true);
    const state = new URL(location).searchParams.get("state") ?? "";
    expect(state).not.toBe("");
    const cookieLine = setCookies(res).find((l) => l.startsWith(`${OAUTH_STATE_COOKIE}=`)) ?? "";
    expect(cookieLine).toContain("HttpOnly");
    expect(cookieLine).toContain(`${state}.`);
    return { state, cookie: cookieLine.split(";")[0] };
  }

  it("GET /auth/sso/config reports GitHub availability", async () => {
    const res = await fetch(base + "/auth/sso/config");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ enabled: false, github: true });
  });

  it("GET /auth/github redirects to GitHub with an HttpOnly state cookie", async () => {
    const { state, cookie } = await startFlow();
    expect(cookie).toBe(`${OAUTH_STATE_COOKIE}=${state}.login`);
  });

  it("uses the canonical public origin when a reverse proxy replaces Host", async () => {
    const canonical = "https://app.halofy.ai";
    const proxied = createHttpServer(makeDeps(true, canonical));
    const port = await proxied.start(0);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/auth/github`, {
        redirect: "manual",
      });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location") ?? "");
      expect(location.searchParams.get("redirect_uri")).toBe(
        `${canonical}/auth/github/callback`,
      );
    } finally {
      await proxied.stop();
    }
  });

  it("mode=link is bound into the state cookie", async () => {
    const { state, cookie } = await startFlow("link");
    expect(cookie).toBe(`${OAUTH_STATE_COOKIE}=${state}.link`);
  });

  it("callback with a missing or mismatched state → 400, no session cookie", async () => {
    const missing = await fetch(base + "/auth/github/callback?code=good&state=abc", {
      redirect: "manual",
    });
    expect(missing.status).toBe(400);
    const { state } = await startFlow();
    const wrong = await fetch(
      `${base}/auth/github/callback?code=good&state=${state}ff`,
      { headers: { cookie: `${OAUTH_STATE_COOKIE}=${state}.login` }, redirect: "manual" },
    );
    expect(wrong.status).toBe(400);
    expect(
      setCookies(wrong).find((l) => l.startsWith(`${SESSION_COOKIE}=`)),
    ).toBeUndefined();
  });

  it("login callback mints the session and lands on the console", async () => {
    const { state, cookie } = await startFlow();
    const res = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, {
      headers: { cookie },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/console/");
    const session = setCookies(res).find((l) => l.startsWith(`${SESSION_COOKIE}=`));
    expect(session).toBeDefined();
    expect(session).toContain("HttpOnly");
    expect(session).toContain("live-session-token");
  });

  /**
   * OA8 — the consent bounce must survive the GitHub round trip.
   *
   * Regression: `/oauth/authorize` bounces a signed-out visitor through the
   * console login with `?next=/oauth/authorize?…`, but the GitHub callback
   * hardcoded `/console/`. The user signed in, landed in the console, and the
   * connector that sent them (ChatGPT / Claude) never received its code — it
   * just sat there unconnected.
   */
  it("carries a consent bounce through GitHub and lands back on /oauth/authorize", async () => {
    const next = "/oauth/authorize?response_type=code&client_id=hmc_x&state=st-1";
    const start = await fetch(`${base}/auth/github?next=${encodeURIComponent(next)}`, {
      redirect: "manual",
    });
    expect(start.status).toBe(302);
    const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const cookie = (setCookies(start).find((l) => l.startsWith(`${OAUTH_STATE_COOKIE}=`)) ?? "")
      .split(";")[0];
    // Third dot-separated field, base64url — the mode parse must still work.
    expect(cookie.split(".").length).toBe(3);

    const res = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, {
      headers: { cookie },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(next);
    expect(setCookies(res).find((l) => l.startsWith(`${SESSION_COOKIE}=`))).toBeDefined();
  });

  it("refuses to be steered anywhere but /oauth/authorize (open-redirect fence)", async () => {
    for (const hostile of [
      "https://evil.example/steal",
      "//evil.example/steal",
      "/console/#s18",
      "/oauth/token?x=1",
    ]) {
      const start = await fetch(`${base}/auth/github?next=${encodeURIComponent(hostile)}`, {
        redirect: "manual",
      });
      const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
      const cookie = (setCookies(start).find((l) => l.startsWith(`${OAUTH_STATE_COOKIE}=`)) ?? "")
        .split(";")[0];
      expect(cookie, hostile).toBe(`${OAUTH_STATE_COOKIE}=${state}.login`);

      const res = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, {
        headers: { cookie },
        redirect: "manual",
      });
      expect(res.headers.get("location"), hostile).toBe("/console/");
    }
  });

  it("failed login callbacks redirect to the login page with an error marker", async () => {
    const disabled = await startFlow();
    const res = await fetch(
      `${base}/auth/github/callback?code=disabled&state=${disabled.state}`,
      { headers: { cookie: disabled.cookie }, redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/console/login?error=github_no_account");

    const bad = await startFlow();
    const res2 = await fetch(
      `${base}/auth/github/callback?code=garbage&state=${bad.state}`,
      { headers: { cookie: bad.cookie }, redirect: "manual" },
    );
    expect(res2.headers.get("location")).toBe("/console/login?error=github_unauthenticated");
  });

  it("link callback without a session redirects to the login page", async () => {
    const { state, cookie } = await startFlow("link");
    const res = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, {
      headers: { cookie },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/console/login");
  });

  it("link callback links and lands on the Profile screen", async () => {
    const ok = await startFlow("link");
    const res = await fetch(`${base}/auth/github/callback?code=good&state=${ok.state}`, {
      headers: { cookie: `${ok.cookie}; ${SESSION_COOKIE}=live-session-token` },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/console/#settings?linked=github");

    const taken = await startFlow("link");
    const res2 = await fetch(
      `${base}/auth/github/callback?code=taken&state=${taken.state}`,
      {
        headers: { cookie: `${taken.cookie}; ${SESSION_COOKIE}=live-session-token` },
        redirect: "manual",
      },
    );
    expect(res2.headers.get("location")).toBe("/console/#settings?error=github_conflict");
  });

  it("GET /auth/identities lists the session user's connections", async () => {
    const res = await fetch(base + "/auth/identities", {
      headers: { cookie: `${SESSION_COOKIE}=live-session-token` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { identities: Array<{ provider: string; login: string }> };
    expect(body.identities).toHaveLength(1);
    expect(body.identities[0]).toMatchObject({ provider: "github", login: "octocat" });

    const anon = await fetch(base + "/auth/identities");
    expect(anon.status).toBe(401);
  });

  it("DELETE /auth/identities/github removes the connection (404 when none)", async () => {
    const res = await fetch(base + "/auth/identities/github", {
      method: "DELETE",
      headers: { cookie: `${SESSION_COOKIE}=live-session-token` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const none = await fetch(base + "/auth/identities/github", {
      method: "DELETE",
      headers: { cookie: `${SESSION_COOKIE}=stranger-token` },
    });
    expect(none.status).toBe(404);
  });

  it("an unconfigured deployment 404s the GitHub routes and reports github:false", async () => {
    const bare = createHttpServer(makeDeps(false));
    const port = await bare.start(0);
    try {
      const cfg = await fetch(`http://127.0.0.1:${port}/auth/sso/config`);
      expect(await cfg.json()).toEqual({ enabled: false, github: false });
      const start = await fetch(`http://127.0.0.1:${port}/auth/github`, { redirect: "manual" });
      expect(start.status).toBe(404);
      const callback = await fetch(`http://127.0.0.1:${port}/auth/github/callback?code=x&state=y`, {
        redirect: "manual",
      });
      expect(callback.status).toBe(404);
    } finally {
      await bare.stop();
    }
  });
});
