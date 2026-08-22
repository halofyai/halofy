import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  OrganizationSignupService,
  SignupConflictError,
  SignupValidationError,
  organizationSignupAllowed,
} from "../src/console/signup.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { SESSION_COOKIE, SIGNUP_COOKIE } from "../src/http/console.js";

const DIM = 8;
const ISSUED_AT = new Date("2026-07-21T10:00:00.000Z");
const USER_ID = "01K0OWNER00000000000000000";
const TENANT_ULID = "01K0TENANT0000000000000000";
const SESSION_RAW = "session-raw-token";

let db: Db;

function signupService(now: () => Date = () => ISSUED_AT): OrganizationSignupService {
  return new OrganizationSignupService(db, {
    now,
    signupToken: () => "signup-raw-token",
    sessionToken: () => SESSION_RAW,
    userId: () => USER_ID,
    tenantUlid: () => TENANT_ULID,
  });
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
});

afterAll(async () => {
  await db.close();
});

beforeEach(async () => {
  await db.query(`DELETE FROM sessions`);
  await db.query(`DELETE FROM users`);
  await db.query(`DELETE FROM tenants`);
  await db.query(`DELETE FROM auth_signup_sessions`);
  await db.query(`DELETE FROM audit_log`);
});

describe("OrganizationSignupService", () => {
  it("stores only a token digest and exposes the verified email through the raw token", async () => {
    const service = signupService();
    const issued = await service.issue("  Founder@Example.TEST ");

    expect(issued).toMatchObject({ token: "signup-raw-token", email: "founder@example.test" });
    expect(await service.inspect(issued.token)).toEqual({ email: "founder@example.test" });

    const rows = await db.query(`SELECT id, email, consumed_at FROM auth_signup_sessions`);
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0].email).toBe("founder@example.test");
    expect(rows.rows[0].id).not.toContain("signup-raw-token");
    expect(rows.rows[0].consumed_at).toBeNull();
  });

  it("rotates the pending authority for the same verified email", async () => {
    const tokens = ["signup-token-one", "signup-token-two"];
    const service = new OrganizationSignupService(db, {
      now: () => ISSUED_AT,
      signupToken: () => tokens.shift()!,
    });

    const first = await service.issue("founder@example.test");
    const second = await service.issue("founder@example.test");
    expect(await service.inspect(first.token)).toBeNull();
    expect(await service.inspect(second.token)).toEqual({ email: "founder@example.test" });
  });

  it("never issues signup authority for an existing active or disabled account", async () => {
    const service = signupService();
    for (const status of ["active", "disabled"] as const) {
      await db.query(
        `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
         VALUES ($1, $2, 'existing-org', 'member', NULL, $3, $4)`,
        [`existing-${status}`, `${status}@example.test`, status, ISSUED_AT.toISOString()],
      );
      await expect(service.issue(`${status}@example.test`)).rejects.toBeInstanceOf(
        SignupConflictError,
      );
    }
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM auth_signup_sessions`)).rows[0].n)).toBe(0);
  });

  it("enables row-level security on the signup authority table", async () => {
    const result = await db.query(
      `SELECT relrowsecurity FROM pg_class WHERE relname = 'auth_signup_sessions'`,
    );
    expect(result.rows[0].relrowsecurity).toBe(true);
  });

  it("expires signup authority server-side", async () => {
    const service = signupService();
    const issued = await service.issue("founder@example.test");
    const afterExpiry = signupService(() => new Date("2026-07-21T10:11:00.000Z"));
    expect(await afterExpiry.inspect(issued.token)).toBeNull();
    expect(await afterExpiry.complete(issued.token, "Acme Labs")).toBeNull();
  });

  it("atomically creates one tenant, its first passwordless owner, session, and audit", async () => {
    const service = signupService();
    const issued = await service.issue("founder@example.test");
    const result = await service.complete(issued.token, "  acme Labs  ", "  Ada   Founder  ");

    expect(result).not.toBeNull();
    expect(result).toMatchObject({
      token: SESSION_RAW,
      organization: {
        id: "acme-labs-00000000",
        name: "Acme Labs",
        status: "active",
      },
      user: {
        id: USER_ID,
        email: "founder@example.test",
        displayName: "Ada Founder",
        namespace: "acme-labs-00000000",
        role: "owner",
        status: "active",
      },
    });

    const users = await db.query(`SELECT password_hash, display_name, role, namespace FROM users`);
    expect(users.rows).toEqual([
      {
        password_hash: null,
        display_name: "Ada Founder",
        role: "owner",
        namespace: "acme-labs-00000000",
      },
    ]);
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM tenants`)).rows[0].n)).toBe(1);
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM sessions`)).rows[0].n)).toBe(1);
    expect(
      (await db.query(
        `SELECT purpose, namespace, actor FROM audit_log
         WHERE purpose = 'console-self-service-signup'`,
      )).rows,
    ).toEqual([
      {
        purpose: "console-self-service-signup",
        namespace: "acme-labs-00000000",
        actor: "founder@example.test",
      },
    ]);
  });

  it("is single-use and a replay creates no second organization", async () => {
    const service = signupService();
    const issued = await service.issue("founder@example.test");
    expect(await service.complete(issued.token, "Acme Labs")).not.toBeNull();
    expect(await service.complete(issued.token, "Second Org")).toBeNull();
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM tenants`)).rows[0].n)).toBe(1);
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM users`)).rows[0].n)).toBe(1);
  });

  it("rolls back the tenant when the verified email becomes an existing user", async () => {
    const service = signupService();
    const issued = await service.issue("founder@example.test");
    await db.query(
      `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
       VALUES ('existing', 'founder@example.test', 'existing-org', 'member', NULL, 'active', $1)`,
      [ISSUED_AT.toISOString()],
    );

    await expect(service.complete(issued.token, "Orphan Org")).rejects.toBeInstanceOf(
      SignupConflictError,
    );
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM tenants`)).rows[0].n)).toBe(0);
    expect(
      (await db.query(`SELECT consumed_at FROM auth_signup_sessions`)).rows[0].consumed_at,
    ).toBeNull();
  });

  it("rejects invalid organization display names before consuming authority", async () => {
    const service = signupService();
    const issued = await service.issue("founder@example.test");
    await expect(service.complete(issued.token, " ")).rejects.toBeInstanceOf(
      SignupValidationError,
    );
    expect(await service.inspect(issued.token)).toEqual({ email: "founder@example.test" });
  });
});

function transportDeps(): HttpServerDeps {
  const syscall = async (): Promise<unknown> => ({ ok: true });
  return {
    secureCookies: true,
    auth: {
      async resolve() {
        return null;
      },
      async ssoExchange(accessToken: string) {
        return accessToken === "new-user"
          ? {
              status: "onboarding_required" as const,
              signupToken: "signup-cookie-token",
              email: "founder@example.test",
            }
          : { status: "unauthenticated" as const };
      },
      async signupPending(token: string) {
        return token === "signup-cookie-token" ? { email: "founder@example.test" } : null;
      },
      async signupComplete(token: string, organizationName: string, displayName: string) {
        if (token !== "signup-cookie-token") return null;
        return {
          token: "normal-session-token",
          organization: {
            id: "acme-12345678",
            name: organizationName.trim(),
            status: "active" as const,
            monthlyBudgetUsd: null,
            rateLimitPerMin: null,
            createdAt: ISSUED_AT.toISOString(),
          },
          user: {
            id: USER_ID,
            email: "founder@example.test",
            displayName,
            namespace: "acme-12345678",
            role: "owner" as const,
            status: "active" as const,
            createdAt: ISSUED_AT.toISOString(),
          },
        };
      },
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
    audit: { async append() {} },
    buildMcpServer() { throw new Error("not used"); },
  };
}

function setCookies(res: Response): string[] {
  const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(res.headers);
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

describe("self-service signup transport", () => {
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    server = createHttpServer(transportDeps());
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
  });

  it("exchanges an unknown verified SSO identity for a secure signup cookie", async () => {
    const res = await fetch(base + "/auth/sso", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_token: "new-user" }),
    });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({
      code: "onboarding_required",
      next: "/console/login?signup=organization",
    });
    const cookie = setCookies(res).find((value) => value.startsWith(`${SIGNUP_COOKIE}=`));
    expect(cookie).toContain("signup-cookie-token");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Max-Age=600");
    expect(cookie).toContain("Secure");
    expect(setCookies(res).some((value) => value.startsWith(`${SESSION_COOKIE}=`))).toBe(false);
  });

  it("returns only the pending verified email and prevents caching", async () => {
    const res = await fetch(base + "/auth/signup", {
      headers: { cookie: `${SIGNUP_COOKIE}=signup-cookie-token` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ email: "founder@example.test" });
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("rejects authority-bearing fields in the completion body", async () => {
    const res = await fetch(base + "/auth/signup", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SIGNUP_COOKIE}=signup-cookie-token`,
      },
      body: JSON.stringify({ organizationName: "Acme", role: "owner" }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code: string }).code).toBe("invalid_body");
  });

  it("completes signup, starts a normal session, and clears signup authority", async () => {
    const res = await fetch(base + "/auth/signup", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `${SIGNUP_COOKIE}=signup-cookie-token`,
      },
      body: JSON.stringify({ displayName: "Ada Lovelace", organizationName: " Acme " }),
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({
      organization: { id: "acme-12345678", name: "Acme" },
      user: { email: "founder@example.test", displayName: "Ada Lovelace", role: "owner" },
    });
    const cookies = setCookies(res);
    expect(cookies.find((value) => value.startsWith(`${SESSION_COOKIE}=`))).toContain(
      "normal-session-token",
    );
    expect(cookies.find((value) => value.startsWith(`${SIGNUP_COOKIE}=`))).toContain("Max-Age=0");
  });

  it("fails closed without a valid signup cookie", async () => {
    const pending = await fetch(base + "/auth/signup");
    expect(pending.status).toBe(401);
    const complete = await fetch(base + "/auth/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ organizationName: "Acme" }),
    });
    expect(complete.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// The open-signup switch is independent of the early-access meters.
// ---------------------------------------------------------------------------

describe("organizationSignupAllowed", () => {
  it("defaults to open, and to invite-only while early access is on", () => {
    expect(organizationSignupAllowed({})).toBe(true);
    expect(organizationSignupAllowed({ HALOMEM_EARLY_ACCESS: "true" })).toBe(false);
  });

  it("lets the override open signup without touching the early-access flag", () => {
    expect(
      organizationSignupAllowed({
        HALOMEM_EARLY_ACCESS: "true",
        HALOMEM_ALLOW_ORG_SIGNUP: "true",
      }),
    ).toBe(true);
  });

  it("lets the override close signup while early access is off", () => {
    expect(organizationSignupAllowed({ HALOMEM_ALLOW_ORG_SIGNUP: "false" })).toBe(false);
  });

  it("ignores a garbage override and keeps the early-access default", () => {
    expect(
      organizationSignupAllowed({
        HALOMEM_EARLY_ACCESS: "true",
        HALOMEM_ALLOW_ORG_SIGNUP: "yes",
      }),
    ).toBe(false);
    expect(organizationSignupAllowed({ HALOMEM_ALLOW_ORG_SIGNUP: "" })).toBe(true);
  });

  it("takes the caller's early-access state over the env when both are given", () => {
    expect(organizationSignupAllowed({}, true)).toBe(false);
    expect(organizationSignupAllowed({ HALOMEM_EARLY_ACCESS: "true" }, false)).toBe(true);
  });
});
