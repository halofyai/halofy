/**
 * Unified sign-in identity — one account reachable through email+password,
 * Google, and GitHub.
 *
 * What is pinned here:
 *
 *  1. A Google (Supabase) sign-in RECORDS the connection in
 *     `user_external_identities`, so the Profile screen can show it. The
 *     recorded link is a fact the email match already granted — it never
 *     widens access.
 *  2. A recorded link then WINS over the email match, so a later Google email
 *     change still lands on the same kernel account.
 *  3. The hosted email/password channel of the same IdP records nothing (no
 *     external account exists to connect).
 *  4. `linkGoogle` connects an explicitly signed-in user, refuses a
 *     non-Google token, and reports a conflict rather than stealing a link.
 *  5. The transport surface: GET /auth/identities reports every method
 *     (identities + hasPassword), and DELETE refuses (409) to remove the LAST
 *     remaining way to sign in.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  InvitationStore,
  hashPassword,
  SessionStore,
  UserStore,
} from "../src/console/auth.js";
import { ExternalIdentityStore } from "../src/console/identities.js";
import { OrganizationSignupService } from "../src/console/signup.js";
import { SupabaseSsoService } from "../src/console/sso.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { SESSION_COOKIE } from "../src/http/console.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";

const DIM = 16;
const SUPABASE_URL = "https://proj.supabase.co";
const ANON_KEY = "anon-key";
const BOOTSTRAP_TOKEN = "bootstrap-token-for-identity-linking-tests";
const ROOT: Identity = { namespace: "", actor: "root@acme.test", role: "owner" };

let db: Db;
let users: UserStore;
let sessions: SessionStore;
let invitations: InvitationStore;
let signup: OrganizationSignupService;
let identities: ExternalIdentityStore;

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  users = new UserStore(db);
  sessions = new SessionStore(db);
  invitations = new InvitationStore(db);
  signup = new OrganizationSignupService(db);
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
  await db.query(`DELETE FROM auth_signup_sessions`);
  await db.query(`DELETE FROM auth_bootstrap`);
});

/**
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

/** A GoTrue stub whose `identities` array names the IdP behind each token. */
type StubToken = {
  email: string;
  /** null → the hosted email/password channel (no external account). */
  googleSub: string | null;
  googleEmail?: string;
};

function stubIdp(known: Record<string, StubToken>) {
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/auth/v1/settings")) {
      return new Response(JSON.stringify({ mailer_autoconfirm: false }), { status: 200 });
    }
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const auth = headers.authorization;
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
    const record = known[token];
    if (record === undefined) {
      return new Response(JSON.stringify({ msg: "invalid JWT" }), { status: 401 });
    }
    return new Response(
      JSON.stringify({
        id: "sb-user",
        email: record.email,
        email_confirmed_at: "2026-07-19T00:00:00.000Z",
        identities:
          record.googleSub === null
            ? [{ provider: "email", id: "sb-user", identity_data: { email: record.email } }]
            : [
                {
                  provider: "google",
                  id: record.googleSub,
                  identity_data: {
                    sub: record.googleSub,
                    email: record.googleEmail ?? record.email,
                  },
                },
              ],
      }),
      { status: 200 },
    );
  }) as typeof fetch;
  return fetchFn;
}

function service(known: Record<string, StubToken>): SupabaseSsoService {
  return new SupabaseSsoService({
    url: SUPABASE_URL,
    anonKey: ANON_KEY,
    stores: { users, sessions },
    invitations,
    signup,
    identities,
    fetchFn: stubIdp(known),
  });
}

describe("Google sign-in records the connection", () => {
  it("links the Google account to the user the email resolved to", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const sso = service({ "tok-g": { email: "member@acme.test", googleSub: "g-1001" } });

    const result = await sso.exchange("tok-g");
    expect(result.status).toBe("ok");

    const linked = await identities.listForUser(user.id);
    expect(linked).toHaveLength(1);
    expect(linked[0]).toMatchObject({
      provider: "google",
      providerAccountId: "g-1001",
      login: "member@acme.test",
    });
  });

  it("is idempotent across repeat sign-ins", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const sso = service({ "tok-g": { email: "member@acme.test", googleSub: "g-1001" } });
    await sso.exchange("tok-g");
    await sso.exchange("tok-g");
    expect(await identities.listForUser(user.id)).toHaveLength(1);
  });

  it("records nothing for the hosted email/password channel", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const sso = service({ "tok-e": { email: "member@acme.test", googleSub: null } });

    expect((await sso.exchange("tok-e")).status).toBe("ok");
    expect(await identities.listForUser(user.id)).toHaveLength(0);
  });

  it("a connected Google account survives a change of Google email", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await identities.link(user.id, "google", {
      id: "g-1001",
      login: "member@acme.test",
      email: "member@acme.test",
    });
    // Same Google account (same `sub`), a DIFFERENT verified email that has no
    // kernel user at all — the link is what resolves the account.
    const sso = service({
      "tok-g": {
        email: "moved@personal.test",
        googleSub: "g-1001",
        googleEmail: "moved@personal.test",
      },
    });

    const result = await sso.exchange("tok-g");
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user.email).toBe("member@acme.test");
  });

  it("refuses a connected account whose user is disabled", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await identities.link(user.id, "google", {
      id: "g-1001",
      login: "member@acme.test",
      email: "member@acme.test",
    });
    await users.disable(user.id);
    const sso = service({ "tok-g": { email: "member@acme.test", googleSub: "g-1001" } });

    expect((await sso.exchange("tok-g")).status).toBe("no_account");
  });

  it("leaves a foreign link untouched instead of failing the sign-in", async () => {
    await bootstrapRoot();
    const other = await users.create(
      { email: "other@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await users.create({ email: "member@acme.test", namespace: "acme", role: "member" }, ROOT);
    // The Google account is connected to `other`, so the linked-identity branch
    // resolves there — the email match never overwrites an existing link.
    await identities.link(other.id, "google", {
      id: "g-1001",
      login: "other@acme.test",
      email: "other@acme.test",
    });
    const sso = service({ "tok-g": { email: "member@acme.test", googleSub: "g-1001" } });

    const result = await sso.exchange("tok-g");
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.user.email).toBe("other@acme.test");
    expect(await identities.findByProviderId("google", "g-1001")).toMatchObject({
      userId: other.id,
    });
  });
});

describe("SupabaseSsoService.linkGoogle", () => {
  it("connects the Google account to the signed-in user", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const sso = service({
      "tok-g": {
        email: "personal@gmail.test",
        googleSub: "g-2002",
        googleEmail: "personal@gmail.test",
      },
    });

    const result = await sso.linkGoogle("tok-g", user.id);
    expect(result.status).toBe("linked");
    // The Google address need not match the kernel email — the session proves
    // one side, the IdP token the other.
    expect(await identities.findForUser(user.id, "google")).toMatchObject({
      providerAccountId: "g-2002",
      login: "personal@gmail.test",
    });
  });

  it("refuses a token that carries no Google account", async () => {
    await bootstrapRoot();
    const user = await users.create(
      { email: "member@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const sso = service({ "tok-e": { email: "member@acme.test", googleSub: null } });

    expect((await sso.linkGoogle("tok-e", user.id)).status).toBe("unauthenticated");
    expect((await sso.linkGoogle("nope", user.id)).status).toBe("unauthenticated");
    expect(await identities.listForUser(user.id)).toHaveLength(0);
  });

  it("reports a conflict rather than stealing another user's Google account", async () => {
    await bootstrapRoot();
    const owner = await users.create(
      { email: "owner@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    const thief = await users.create(
      { email: "thief@acme.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await identities.link(owner.id, "google", {
      id: "g-3003",
      login: "owner@acme.test",
      email: "owner@acme.test",
    });
    const sso = service({ "tok-g": { email: "owner@acme.test", googleSub: "g-3003" } });

    expect((await sso.linkGoogle("tok-g", thief.id)).status).toBe("conflict");
    expect(await identities.findByProviderId("google", "g-3003")).toMatchObject({
      userId: owner.id,
    });
  });
});

// ---------------------------------------------------------------------------
// Adapter surface: what the Profile screen actually reads and calls.
// ---------------------------------------------------------------------------

describe("Profile sign-in methods (adapter)", () => {
  let kernel: Kernel;
  let auth: ReturnType<typeof buildHttpDeps>["auth"];
  let memberIdentity: Identity;
  let memberId: string;
  let orgId: string;

  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: DIM,
      bootstrapToken: BOOTSTRAP_TOKEN,
    });
    // The install creates the organization and its owner together (decision 9),
    // so everyone in this fixture lives inside the derived tenant.
    const bootstrap = await kernel.bootstrapService.activate({
      token: BOOTSTRAP_TOKEN,
      email: "owner@profile.test",
      password: "correct horse battery staple",
      organization: "Acme",
    });
    if (!bootstrap) throw new Error("bootstrap failed");
    orgId = bootstrap.organization.id;
    const ownerIdentity = await kernel.resolveSessionIdentity(
      (await kernel.login("owner@profile.test", "correct horse battery staple"))!.token,
    );
    if (!ownerIdentity) throw new Error("owner session did not resolve");
    // A password-less member — the shape an SSO/OAuth sign-in provisions.
    const member = await kernel.createUser(
      { email: "member@profile.test", namespace: orgId, role: "member" },
      ownerIdentity,
    );
    memberId = member.id;
    memberIdentity = { namespace: orgId, actor: "member@profile.test", role: "member" };
    auth = buildHttpDeps(kernel, { secureCookies: false }).auth;
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
  });

  it("reports the password channel alongside the linked providers", async () => {
    const store = new ExternalIdentityStore(kernel.db);
    await store.link(memberId, "google", {
      id: "g-4004",
      login: "member@profile.test",
      email: "member@profile.test",
    });

    const listed = (await auth.listIdentities!(memberIdentity)) as {
      identities: Array<{ provider: string }>;
      hasPassword: boolean;
      email: string;
    };
    expect(listed.hasPassword).toBe(false);
    expect(listed.email).toBe("member@profile.test");
    expect(listed.identities.map((entry) => entry.provider)).toEqual(["google"]);

    const ownerListed = (await auth.listIdentities!({
      namespace: orgId,
      actor: "owner@profile.test",
      role: "owner",
    })) as { hasPassword: boolean; identities: unknown[] };
    expect(ownerListed.hasPassword).toBe(true);
    expect(ownerListed.identities).toHaveLength(0);
  });

  it("refuses to disconnect the only remaining sign-in method", async () => {
    const store = new ExternalIdentityStore(kernel.db);
    expect(await store.findForUser(memberId, "google")).not.toBeNull();

    // Password-less user with exactly one connection → the last door.
    expect(await auth.unlinkIdentity!(memberIdentity, "google")).toBe("last_method");
    expect(await store.findForUser(memberId, "google")).not.toBeNull();

    // With a second connection the first may be removed.
    await store.link(memberId, "github", { id: "gh-77", login: "octocat", email: null });
    expect(await auth.unlinkIdentity!(memberIdentity, "google")).toBe(true);
    expect(await store.findForUser(memberId, "google")).toBeNull();
    // …and the survivor is now itself the last door.
    expect(await auth.unlinkIdentity!(memberIdentity, "github")).toBe("last_method");
  });

  it("returns false for an unknown provider or an absent connection", async () => {
    expect(await auth.unlinkIdentity!(memberIdentity, "gitlab")).toBe(false);
    expect(
      await auth.unlinkIdentity!(
        { namespace: "", actor: "owner@profile.test", role: "owner" },
        "google",
      ),
    ).toBe(false);
  });

  it("lets a password-backed user replace both Google and GitHub accounts", async () => {
    const store = new ExternalIdentityStore(kernel.db);
    const owner = await kernel.users!.byEmail("owner@profile.test");
    if (!owner) throw new Error("owner fixture missing");
    const ownerIdentity: Identity = {
      namespace: orgId,
      actor: owner.email,
      role: "owner",
    };

    await store.link(owner.id, "google", {
      id: "g-old",
      login: "old-google@profile.test",
      email: "old-google@profile.test",
    });
    expect(await auth.unlinkIdentity!(ownerIdentity, "google")).toBe(true);
    await store.link(owner.id, "google", {
      id: "g-new",
      login: "new-google@profile.test",
      email: "new-google@profile.test",
    });
    expect(await store.findForUser(owner.id, "google")).toMatchObject({
      providerAccountId: "g-new",
      login: "new-google@profile.test",
    });

    await store.link(owner.id, "github", {
      id: "gh-old",
      login: "old-handle",
      email: null,
    });
    expect(await auth.unlinkIdentity!(ownerIdentity, "github")).toBe(true);
    await store.link(owner.id, "github", {
      id: "gh-new",
      login: "new-handle",
      email: null,
    });
    expect(await store.findForUser(owner.id, "github")).toMatchObject({
      providerAccountId: "gh-new",
      login: "new-handle",
    });
  });
});

// ---------------------------------------------------------------------------
// Transport lane: the two routes the Profile screen calls for Google.
// ---------------------------------------------------------------------------

describe("Google identity transport", () => {
  const SESSION: Identity = {
    keyId: "sess_owner",
    namespace: "acme",
    actor: "owner@acme.test",
    role: "owner",
  };
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    const syscall = async (): Promise<unknown> => ({ ok: true });
    const deps: HttpServerDeps = {
      secureCookies: false,
      auth: {
        async resolve() {
          return null;
        },
        async resolveSession(token: string) {
          return token === "live-session-token" ? SESSION : null;
        },
        ssoLinkGoogle: async (accessToken: string) => {
          if (accessToken === "good") return { status: "linked" as const, login: "owner@gmail.test" };
          if (accessToken === "taken") return { status: "conflict" as const };
          return { status: "unauthenticated" as const };
        },
        listIdentities: async () => ({ identities: [], email: SESSION.actor, hasPassword: true }),
        unlinkIdentity: async (_identity: Identity, provider: string) =>
          provider === "google" ? ("last_method" as const) : false,
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
        async getPolicy() { return {}; },
        async setPolicy() { return {}; },
        async listKeys() { return []; },
        async issueKey() { return {}; },
        async revokeKey() { return {}; },
      },
      metrics: { snapshot: () => ({ ok: true }) },
      audit: { async append() { /* not under test */ } },
      buildMcpServer() { throw new Error("not used in this suite"); },
    } as unknown as HttpServerDeps;
    server = createHttpServer(deps);
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
  });

  async function link(token: string, cookie = "live-session-token"): Promise<Response> {
    return fetch(base + "/auth/identities/google", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: `${SESSION_COOKIE}=${cookie}` },
      body: JSON.stringify({ access_token: token }),
    });
  }

  it("POST connects, 409s a conflict, 401s a bad token, 401s anonymous", async () => {
    const ok = await link("good");
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ok: true, provider: "google", login: "owner@gmail.test" });

    expect((await link("taken")).status).toBe(409);
    expect((await link("garbage")).status).toBe(401);

    const anon = await fetch(base + "/auth/identities/google", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_token: "good" }),
    });
    expect(anon.status).toBe(401);
  });

  it("DELETE refuses to remove the last sign-in method", async () => {
    const res = await fetch(base + "/auth/identities/google", {
      method: "DELETE",
      headers: { cookie: `${SESSION_COOKIE}=live-session-token` },
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ code: "last_sign_in_method" });
  });
});
