/**
 * Module A (M5 part 1) tests — human sign-in.
 *
 * Covers the exit criteria in CONTRACTS-M5-backend.md's module-A row:
 *   - bootstrap the FIRST owner (empty users table, no caller);
 *   - a second create requires an owner caller (audited via 403-mapped error);
 *   - login with the correct password → an Identity whose role + namespace come
 *     from the user ROW (not the request);
 *   - wrong password AND unknown email BOTH return null (no oracle);
 *   - an expired session resolves to null;
 *   - a disabled user cannot log in and their live session stops resolving;
 *   - destroy() invalidates a token.
 *
 * Hermetic: in-memory PGlite (migration 007 supplies users/sessions), zero
 * network. No password or raw token is ever logged.
 */

import { randomBytes } from "node:crypto";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import type { Identity, Session, User } from "../src/types.js";
import {
  BootstrapService,
  DEFAULT_SESSION_TTL_SECONDS,
  SESSION_ABSOLUTE_TTL_SECONDS,
  SessionStore,
  UserStore,
  hashPassword,
  hashToken,
  isHumanRole,
  login,
  logout,
  resolveSessionIdentity,
  verifyPassword,
  type AuthStores,
} from "../src/console/auth.js";

const DIM = 8;
const TEST_BOOTSTRAP_TOKEN = "console-auth-test-bootstrap-token-32-bytes-minimum";

let db: Db;
let users: UserStore;
let sessions: SessionStore;
let stores: AuthStores;

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  users = new UserStore(db);
  sessions = new SessionStore(db);
  stores = { users, sessions };
});

afterAll(async () => {
  await db.close();
});

// Fresh users/sessions between describe blocks so bootstrap-empty semantics are
// deterministic regardless of ordering.
beforeEach(async () => {
  await db.query(`DELETE FROM sessions`);
  await db.query(`DELETE FROM auth_invitations`);
  await db.query(`DELETE FROM users`);
  await db.query(`DELETE FROM auth_bootstrap`);
});

/**
 * Provision a platform root the way an OPERATOR does: a direct row insert.
 *
 * No product path mints a human at namespace `""` any more
 * (CONTRACTS-SELF-SERVICE-ONBOARDING.md decision 9) — `BootstrapService` now
 * creates an organization and puts its first owner inside it. Root survives
 * only as a break-glass capability reached through the CLI or the database,
 * which is exactly the shape `UserStore.create`'s no-caller branch documents.
 */
async function provisionPlatformRoot(email: string, password: string): Promise<User> {
  const id = `root-${randomBytes(8).toString("hex")}`;
  const createdAt = new Date().toISOString();
  const normalized = email.trim().toLowerCase();
  await db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
    [id, normalized, hashPassword(password), createdAt],
  );
  return {
    id,
    email: normalized,
    namespace: "",
    role: "owner",
    status: "active",
    createdAt,
  };
}

async function securelyCreateInitial(input: {
  email: string;
  namespace: string;
  role: "owner";
  password: string;
}): Promise<User> {
  if (input.namespace === "") return provisionPlatformRoot(input.email, input.password);
  const root = await provisionPlatformRoot(
    "platform-root@halo.test",
    "platform-root-password",
  );
  const rootIdentity: Identity = {
    keyId: `test-root-${root.id}`,
    namespace: "",
    actor: root.email,
    role: "owner",
  };
  return users.create(input, rootIdentity);
}

describe("hashPassword / verifyPassword", () => {
  it("round-trips a correct password and rejects a wrong one", () => {
    const stored = hashPassword("s3cret-pw");
    expect(stored).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/); // 16-byte salt, 64-byte hash
    expect(verifyPassword(stored, "s3cret-pw")).toBe(true);
    expect(verifyPassword(stored, "wrong")).toBe(false);
  });

  it("never returns true for a null or malformed stored value", () => {
    expect(verifyPassword(null, "anything")).toBe(false);
    expect(verifyPassword("no-colon", "anything")).toBe(false);
    expect(verifyPassword(":onlyhash", "anything")).toBe(false);
    expect(verifyPassword("onlysalt:", "anything")).toBe(false);
  });

  it("produces a different salt (and hash) each call for the same password", () => {
    const a = hashPassword("same");
    const b = hashPassword("same");
    expect(a).not.toBe(b);
    expect(verifyPassword(a, "same")).toBe(true);
    expect(verifyPassword(b, "same")).toBe(true);
  });
});

describe("isHumanRole", () => {
  it("accepts human roles and rejects 'agent'", () => {
    for (const r of ["owner", "admin", "auditor", "member"]) {
      expect(isHumanRole(r)).toBe(true);
    }
    expect(isHumanRole("agent")).toBe(false);
    expect(isHumanRole("nonsense")).toBe(false);
  });
});

describe("UserStore.create - secure bootstrap + owner-only", () => {
  it("rejects direct first-user creation without the bootstrap credential", async () => {
    const countRes = await db.query(`SELECT COUNT(*) AS n FROM users`);
    expect(Number(countRes.rows[0].n)).toBe(0);

    await expect(
      users.create({
        email: "root@acme.test",
        namespace: "acme",
        role: "owner",
        password: "owner-pw",
      }),
    ).rejects.toThrow(/bootstrap credential/i);
    const after = await db.query(`SELECT COUNT(*) AS n FROM users`);
    expect(Number(after.rows[0].n)).toBe(0);
  });

  it("requires an owner caller for a SECOND user (non-empty table)", async () => {
    await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw" });

    // No caller once the table is non-empty → denied (403-mapped): the
    // bootstrap exception keys off "no caller", not "table empty".
    await expect(
      users.create({ email: "a@acme.test", namespace: "acme/team", role: "admin", password: "pw" }),
    ).rejects.toThrow(/owner identity/i);

    // An ADMIN caller may invite a non-owner role in its subtree (contract:
    // "invite user — owner/admin") — but may NOT mint an OWNER (that would
    // escalate a subtree-scoped admin to org owner).
    const adminCaller: Identity = {
      keyId: "sess-x",
      namespace: "acme/team",
      actor: "admin@acme.test",
      role: "admin",
    };
    const adminInvited = await users.create(
      { email: "b@acme.test", namespace: "acme/team", role: "member", password: "pw" },
      adminCaller,
    );
    expect(adminInvited.email).toBe("b@acme.test");
    expect(adminInvited.role).toBe("member");
    // Admin minting an OWNER is denied (no escalation to org owner).
    await expect(
      users.create(
        { email: "evil@acme.test", namespace: "acme/team", role: "owner", password: "pw" },
        adminCaller,
      ),
    ).rejects.toThrow(/owner identity/i);

    // An owner caller → allowed.
    const ownerCaller: Identity = {
      keyId: "sess-o",
      namespace: "acme",
      actor: "root@acme.test",
      role: "owner",
    };
    const created = await users.create(
      {
        email: "c@acme.test",
        displayName: "Cora Admin",
        namespace: "acme/team",
        role: "admin",
        password: "pw",
      },
      ownerCaller,
    );
    expect(created.email).toBe("c@acme.test");
    expect(created.displayName).toBe("Cora Admin");
    expect(created.role).toBe("admin");
    await expect(users.create(
      {
        email: "nameless@acme.test",
        displayName: "   ",
        namespace: "acme/team",
        role: "member",
      },
      ownerCaller,
    )).rejects.toThrow(/display name is required/i);
  });

  it("rejects a non-human role (e.g. 'agent') even during bootstrap", async () => {
    await expect(
      // Force through the type system — a request could carry any string.
      users.create({ email: "x@acme.test", namespace: "acme", role: "agent" as never }),
    ).rejects.toThrow(/invalid human role/i);
    // Table still empty (nothing was created).
    const countRes = await db.query(`SELECT COUNT(*) AS n FROM users`);
    expect(Number(countRes.rows[0].n)).toBe(0);
  });

  it("rejects a duplicate email (case-insensitive)", async () => {
    await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw" });
    const ownerCaller: Identity = {
      keyId: "s", namespace: "acme", actor: "root@acme.test", role: "owner",
    };
    await expect(
      users.create(
        { email: "ROOT@acme.test", namespace: "acme", role: "member", password: "pw" },
        ownerCaller,
      ),
    ).rejects.toThrow(/already exists/i);
  });

  it("stores the password as salt:scryptHash - never the plaintext", async () => {
    await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "hunter2" });
    const res = await db.query(`SELECT email, password_hash FROM users`);
    for (const row of res.rows) {
      expect(String(row.password_hash)).not.toContain("hunter2");
      expect(row.password_hash).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/);
    }
  });
});

describe("UserStore.byEmail / byId / list / disable", () => {
  it("returns the saved display name without replacing the immutable email key", async () => {
    const user = await securelyCreateInitial({
      email: "owner.one@acme.test",
      namespace: "halofy",
      role: "owner",
      password: "pw",
    });
    await db.query(`UPDATE users SET display_name = $1 WHERE id = $2`, [
      "Owner One",
      user.id,
    ]);

    expect(await users.byId(user.id)).toMatchObject({
      email: "owner.one@acme.test",
      displayName: "Owner One",
    });
    expect(await users.list({
      keyId: "owner-session",
      namespace: "halofy",
      actor: "owner.one@acme.test",
      role: "owner",
    })).toEqual([
      expect.objectContaining({
        email: "owner.one@acme.test",
        displayName: "Owner One",
      }),
    ]);
  });

  it("byEmail is case-insensitive; byId round-trips", async () => {
    const u = await securelyCreateInitial({ email: "Root@Acme.test", namespace: "acme", role: "owner", password: "pw" });
    const byEmail = await users.byEmail("root@acme.test");
    expect(byEmail?.id).toBe(u.id);
    expect(byEmail?.email).toBe("root@acme.test"); // normalized on store
    const byId = await users.byId(u.id);
    expect(byId?.email).toBe("root@acme.test");
    expect(await users.byEmail("nobody@acme.test")).toBeNull();
  });

  it("list is ancestor-subtree scoped and never leaks siblings/wildcards", async () => {
    const owner = await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw" });
    const ownerCaller: Identity = { keyId: "s", namespace: "acme", actor: owner.email, role: "owner" };

    await users.create({ email: "eng-admin@acme.test", namespace: "acme/eng_svc", role: "admin", password: "pw" }, ownerCaller);
    await users.create({ email: "eng-dev@acme.test", namespace: "acme/eng_svc/dev", role: "member", password: "pw" }, ownerCaller);
    // Sibling whose namespace matches 'acme/eng_svc/%' under a raw LIKE ('_' → 'X').
    await users.create({ email: "x@acme.test", namespace: "acme/engXsvc/dev", role: "member", password: "pw" }, ownerCaller);
    // A wholly separate subtree.
    await users.create({ email: "sales@acme.test", namespace: "acme/sales", role: "admin", password: "pw" }, ownerCaller);

    // Owner sees everyone.
    const all = await users.list(ownerCaller);
    expect(all.map((u) => u.email)).toEqual(
      expect.arrayContaining([
        "root@acme.test", "eng-admin@acme.test", "eng-dev@acme.test", "x@acme.test", "sales@acme.test",
      ]),
    );

    // eng_svc admin sees only its own subtree — never the '_'-wildcard sibling
    // or the sales subtree or the org root.
    const engAdmin: Identity = {
      keyId: "s2", namespace: "acme/eng_svc", actor: "eng-admin@acme.test", role: "admin",
    };
    const visible = await users.list(engAdmin);
    const emails = visible.map((u) => u.email);
    expect(emails).toContain("eng-admin@acme.test");
    expect(emails).toContain("eng-dev@acme.test");
    expect(emails).not.toContain("x@acme.test");        // engXsvc - sibling
    expect(emails).not.toContain("sales@acme.test");    // other subtree
    expect(emails).not.toContain("root@acme.test");     // ancestor
    for (const u of visible) {
      expect(u.namespace === "acme/eng_svc" || u.namespace.startsWith("acme/eng_svc/")).toBe(true);
    }
  });

  it("tenant owner can list and create users only inside its own subtree", async () => {
    const root = await securelyCreateInitial({
      email: "root@halo.test",
      namespace: "",
      role: "owner",
      password: "pw",
    });
    const rootCaller: Identity = {
      keyId: "root-session",
      namespace: "",
      actor: root.email,
      role: "owner",
    };
    const acmeOwner = await users.create(
      { email: "owner@acme.test", namespace: "acme", role: "owner", password: "pw" },
      rootCaller,
    );
    await users.create(
      { email: "member@globex.test", namespace: "globex", role: "member", password: "pw" },
      rootCaller,
    );
    const acmeCaller: Identity = {
      keyId: "acme-session",
      namespace: "acme",
      actor: acmeOwner.email,
      role: "owner",
    };

    const visible = await users.list(acmeCaller);
    expect(visible.map((user) => user.email)).toContain("owner@acme.test");
    expect(visible.map((user) => user.email)).not.toContain("member@globex.test");

    await expect(
      users.create(
        { email: "intruder@globex.test", namespace: "globex", role: "admin", password: "pw" },
        acmeCaller,
      ),
    ).rejects.toThrow(/outside.*subtree/i);

    const teammate = await users.create(
      { email: "teammate@acme.test", namespace: "acme/eng", role: "admin", password: "pw" },
      acmeCaller,
    );
    expect(teammate.namespace).toBe("acme/eng");
  });

  it("disable is idempotent", async () => {
    const u = await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw" });
    expect(await users.disable(u.id)).toBe(true);
    expect(await users.disable(u.id)).toBe(false);
    const back = await users.byId(u.id);
    expect(back?.status).toBe("disabled");
  });
});

describe("login - role/ns from the row, no oracle", () => {
  async function seedOwner(): Promise<User> {
    return securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "correct-horse" });
  }

  it("returns an Identity with role + namespace from the USER ROW", async () => {
    const owner = await seedOwner();
    const result = await login(stores, "root@acme.test", "correct-horse");
    expect(result).not.toBeNull();
    const { token, identity } = result!;
    expect(identity.role).toBe("owner");
    expect(identity.namespace).toBe("acme");
    expect(identity.actor).toBe("root@acme.test");
    // keyId is the session id = sha256(token), NOT the raw token or user id.
    expect(identity.keyId).toBe(hashToken(token));
    expect(identity.keyId).not.toBe(token);
    expect(identity.keyId).not.toBe(owner.id);
    // Raw token is opaque hex, 64 chars (32 bytes).
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("login is case-insensitive on email", async () => {
    await seedOwner();
    const result = await login(stores, "ROOT@ACME.test", "correct-horse");
    expect(result).not.toBeNull();
    expect(result!.identity.role).toBe("owner");
  });

  it("wrong password AND unknown email BOTH return null (no oracle)", async () => {
    await seedOwner();
    expect(await login(stores, "root@acme.test", "WRONG")).toBeNull();
    expect(await login(stores, "ghost@acme.test", "correct-horse")).toBeNull();
    expect(await login(stores, "ghost@acme.test", "anything")).toBeNull();
  });

  it("a disabled user cannot log in", async () => {
    const owner = await seedOwner();
    expect(await users.disable(owner.id)).toBe(true);
    expect(await login(stores, "root@acme.test", "correct-horse")).toBeNull();
  });

  it("a user with no password set cannot log in", async () => {
    // Bootstrap owner first (empty table), then owner creates a passwordless user.
    const owner = await seedOwner();
    const ownerCaller: Identity = { keyId: "s", namespace: "acme", actor: owner.email, role: "owner" };
    await users.create({ email: "sso@acme.test", namespace: "acme", role: "member" }, ownerCaller);
    expect(await login(stores, "sso@acme.test", "")).toBeNull();
    expect(await login(stores, "sso@acme.test", "guess")).toBeNull();
  });
});

describe("SessionStore - resolve, expiry, disabled, destroy", () => {
  async function seedOwnerUser(): Promise<User> {
    return securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw" });
  }

  it("stores sha256(token) as the id, never the raw token", async () => {
    const user = await seedOwnerUser();
    const { token, session } = await sessions.create(user);
    expect(session.id).toBe(hashToken(token));
    expect(await sessions.isActiveId(session.id)).toBe(true);
    const res = await db.query(`SELECT id FROM sessions`);
    for (const row of res.rows) {
      expect(row.id).not.toBe(token);
      expect(row.id).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("resolves a live token to a Session with role/ns/actor from the user", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    const session = await sessions.resolve(token);
    expect(session).not.toBeNull();
    const s = session as Session;
    expect(s.role).toBe("owner");
    expect(s.namespace).toBe("acme");
    expect(s.actor).toBe("root@acme.test");
    expect(s.userId).toBe(user.id);

    // resolveSessionIdentity yields the D9 Identity shape. M10 Amendment A2:
    // the session also carries its server-minted projection subject
    // (users.id) so the retrieval read scope can resolve without a request-
    // supplied value.
    const identity = await resolveSessionIdentity(stores, token);
    expect(identity).toEqual<Identity>({
      keyId: s.id,
      namespace: "acme",
      actor: "root@acme.test",
      role: "owner",
      sessionUserId: user.id,
    });
  });

  it("resolves an unknown token to null", async () => {
    expect(await sessions.resolve("deadbeef".repeat(8))).toBeNull();
    expect(await resolveSessionIdentity(stores, "nope")).toBeNull();
  });

  it("resolves an EXPIRED session to null (server-side expiry)", async () => {
    const user = await seedOwnerUser();
    // TTL of -1s → already expired the moment it's created.
    const { token } = await sessions.create(user, -1);
    expect(await sessions.resolve(token)).toBeNull();
    expect(await resolveSessionIdentity(stores, token)).toBeNull();
  });

  it("a session for a user disabled AFTER login stops resolving", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    expect(await sessions.resolve(token)).not.toBeNull();
    await users.disable(user.id);
    expect(await sessions.resolve(token)).toBeNull();
    expect(await resolveSessionIdentity(stores, token)).toBeNull();
  });

  it("destroy() invalidates a token; logout() is the free-function form", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    expect(await sessions.resolve(token)).not.toBeNull();
    expect(await sessions.destroy(token)).toBe(true);
    expect(await sessions.isActiveId(hashToken(token))).toBe(false);
    expect(await sessions.resolve(token)).toBeNull();
    // Second destroy is a no-op.
    expect(await sessions.destroy(token)).toBe(false);

    const { token: t2 } = await sessions.create(user);
    expect(await logout(stores, t2)).toBe(true);
    expect(await resolveSessionIdentity(stores, t2)).toBeNull();
  });

  // --- sliding idle expiry -------------------------------------------------
  //
  // A session is an IDLE window, not a fixed one: using it re-bases expiry at
  // now + DEFAULT_SESSION_TTL_SECONDS. Before this the window was absolute, so
  // a human was signed out on a fixed schedule from sign-in no matter how
  // actively they were using the console.

  /** Force a session's stored expiry, bypassing the store's own clock. */
  async function setExpiry(token: string, atMs: number): Promise<void> {
    await db.query(`UPDATE sessions SET expires_at = $2 WHERE id = $1`, [
      hashToken(token),
      new Date(atMs).toISOString(),
    ]);
  }

  async function storedExpiryMs(token: string): Promise<number> {
    const res = await db.query(`SELECT expires_at FROM sessions WHERE id = $1`, [
      hashToken(token),
    ]);
    const raw = (res.rows[0] as { expires_at: Date | string }).expires_at;
    return new Date(raw instanceof Date ? raw.toISOString() : raw).getTime();
  }

  it("resolve() slides expires_at forward once the window has drifted", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);

    // Drift the window well past the renew threshold: pretend the session was
    // last touched two days ago.
    const drifted = Date.now() + (DEFAULT_SESSION_TTL_SECONDS - 2 * 24 * 3600) * 1000;
    await setExpiry(token, drifted);

    const resolved = await sessions.resolveWithRenewal(token);
    expect(resolved).not.toBeNull();
    expect(resolved!.renewed).toBe(true);

    const after = await storedExpiryMs(token);
    expect(after).toBeGreaterThan(drifted);
    // Re-based at now + the full idle window (one minute of slack for runtime).
    const expected = Date.now() + DEFAULT_SESSION_TTL_SECONDS * 1000;
    expect(Math.abs(after - expected)).toBeLessThan(60_000);
  });

  it("resolve() does NOT write inside the throttle window", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    const before = await storedExpiryMs(token);

    // Freshly minted: the target is within SESSION_RENEW_AFTER_SECONDS of the
    // stored value, so this must be a pure read — one UPDATE per request would
    // put a write on every authenticated call.
    const resolved = await sessions.resolveWithRenewal(token);
    expect(resolved).not.toBeNull();
    expect(resolved!.renewed).toBe(false);
    expect(await storedExpiryMs(token)).toBe(before);
  });

  it("sliding never pushes a session past the absolute ceiling", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);

    // Backdate creation to one day short of the ceiling, and drift the window
    // so a renewal is due. The slide must clamp to created_at + absolute.
    const createdAtMs = Date.now() - (SESSION_ABSOLUTE_TTL_SECONDS - 24 * 3600) * 1000;
    await db.query(`UPDATE sessions SET created_at = $2 WHERE id = $1`, [
      hashToken(token),
      new Date(createdAtMs).toISOString(),
    ]);
    await setExpiry(token, Date.now() + 3600 * 1000);

    const resolved = await sessions.resolveWithRenewal(token);
    expect(resolved).not.toBeNull();
    expect(resolved!.renewed).toBe(true);

    const ceiling = createdAtMs + SESSION_ABSOLUTE_TTL_SECONDS * 1000;
    const after = await storedExpiryMs(token);
    expect(after).toBeLessThanOrEqual(ceiling);
    // It reached the ceiling rather than the full idle window, which would be
    // far beyond it.
    expect(after).toBe(ceiling);
  });

  it("an expired session is rejected, never revived by the slide", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    await setExpiry(token, Date.now() - 1000);

    expect(await sessions.resolveWithRenewal(token)).toBeNull();
    expect(await sessions.resolve(token)).toBeNull();
    // And the row was not quietly pushed forward.
    expect(await storedExpiryMs(token)).toBeLessThan(Date.now());
  });

  it("a disabled user is rejected even when the session is renewable", async () => {
    const user = await seedOwnerUser();
    const { token } = await sessions.create(user);
    await setExpiry(token, Date.now() + (DEFAULT_SESSION_TTL_SECONDS - 2 * 24 * 3600) * 1000);
    const before = await storedExpiryMs(token);

    await users.disable(user.id);

    expect(await sessions.resolveWithRenewal(token)).toBeNull();
    expect(await storedExpiryMs(token)).toBe(before);
  });

  it("sweepExpired removes only expired rows", async () => {
    const user = await seedOwnerUser();
    const live = await sessions.create(user, DEFAULT_SESSION_TTL_SECONDS);
    const dead = await sessions.create(user, -1);
    const removed = await sessions.sweepExpired();
    expect(removed).toBeGreaterThanOrEqual(1);
    expect(await sessions.resolve(live.token)).not.toBeNull();
    expect(await sessions.resolve(dead.token)).toBeNull();
    // Confirm the dead row is physically gone.
    const gone = await db.query(`SELECT id FROM sessions WHERE id = $1`, [hashToken(dead.token)]);
    expect(gone.rows.length).toBe(0);
  });
});

describe("end-to-end login → resolve → logout", () => {
  it("full human sign-in cycle", async () => {
    await securelyCreateInitial({ email: "root@acme.test", namespace: "acme", role: "owner", password: "pw-123" });
    const result = await login(stores, "root@acme.test", "pw-123");
    expect(result).not.toBeNull();
    const { token, identity } = result!;
    expect(identity.role).toBe("owner");

    const resolved = await resolveSessionIdentity(stores, token);
    expect(resolved).toEqual(identity);

    expect(await logout(stores, token)).toBe(true);
    expect(await resolveSessionIdentity(stores, token)).toBeNull();
  });
});
