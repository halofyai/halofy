import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  BootstrapService,
  InvitationStore,
  SessionStore,
  UserAuthzError,
  hashPassword,
  hashToken,
  verifyPassword,
} from "../src/console/auth.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
const BOOTSTRAP_TOKEN = "b".repeat(64);
const ROOT: Identity = {
  keyId: "bootstrap-session",
  namespace: "",
  actor: "root@example.test",
  role: "owner",
};

let db: Db;

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
  await db.query(`DELETE FROM auth_invitations`);
  await db.query(`DELETE FROM auth_bootstrap`);
  // Bootstrap now creates an organization too, so the tenant table is part of
  // the per-test fixture.
  await db.query(`DELETE FROM tenants`);
});

describe("BootstrapService", () => {
  /**
   * CONTRACTS-SELF-SERVICE-ONBOARDING.md decision 9: the install creates an
   * ORGANIZATION and its first owner together. It no longer produces a human
   * at the platform root — that account belonged to no organization, which is
   * what let one deployment's operator be gated by an unrelated customer's
   * onboarding (SG8).
   */
  it("atomically creates the first organization, its owner inside it, and a hashed-at-rest session", async () => {
    const service = new BootstrapService(db, BOOTSTRAP_TOKEN);

    const result = await service.activate({
      token: BOOTSTRAP_TOKEN,
      email: "Root@Example.test",
      password: "correct horse battery staple",
      organization: "example Org",
    });

    expect(result).not.toBeNull();
    // The owner lives INSIDE the derived tenant, never at "".
    expect(result?.organization.name).toBe("Example Org");
    expect(result?.organization.id).toMatch(/^example-org-[0-9a-z]{8}$/);
    expect(result?.user.namespace).toBe(result?.organization.id);
    expect(result?.user).toMatchObject({
      email: "root@example.test",
      role: "owner",
      status: "active",
    });

    const tenants = await db.query(`SELECT id, name FROM tenants`);
    expect(tenants.rows).toHaveLength(1);
    expect(tenants.rows[0].id).toBe(result!.organization.id);

    // D4: the install left evidence, in the organization it created.
    const audit = await db.query(
      `SELECT namespace, purpose, result FROM audit_log
        WHERE purpose = 'console-bootstrap' AND namespace = $1`,
      [result!.organization.id],
    );
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0].result).toBe("ok");
    expect(await new SessionStore(db).resolve(result!.token)).not.toBeNull();

    const users = await db.query(`SELECT password_hash FROM users`);
    expect(users.rows).toHaveLength(1);
    expect(users.rows[0].password_hash).not.toContain("correct horse battery staple");
    expect(verifyPassword(users.rows[0].password_hash, "correct horse battery staple")).toBe(true);

    const sessions = await db.query(`SELECT id FROM sessions`);
    expect(sessions.rows[0].id).toBe(hashToken(result!.token));
    expect(sessions.rows[0].id).not.toBe(result!.token);

    const state = await db.query(`SELECT token_hash, consumed_at FROM auth_bootstrap`);
    expect(state.rows[0].token_hash).toBe(hashToken(BOOTSTRAP_TOKEN));
    expect(state.rows[0].token_hash).not.toBe(BOOTSTRAP_TOKEN);
    expect(state.rows[0].consumed_at).not.toBeNull();
  });

  it("returns the same generic failure for a wrong token, replay, and non-empty users", async () => {
    const service = new BootstrapService(db, BOOTSTRAP_TOKEN);
    const input = {
      token: BOOTSTRAP_TOKEN,
      email: "root@example.test",
      password: "correct horse battery staple",
      organization: "Example Org",
    };

    expect(await service.activate({ ...input, token: "x".repeat(64) })).toBeNull();
    expect(await service.activate(input)).not.toBeNull();
    expect(await service.activate(input)).toBeNull();

    await db.query(`DELETE FROM auth_bootstrap`);
    expect(await service.activate({ ...input, email: "other@example.test" })).toBeNull();
    // The replayed attempts created no second organization.
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM tenants`)).rows[0].n)).toBe(1);
  });

  it("does not reveal token correctness through malformed-field behavior", async () => {
    const service = new BootstrapService(db, BOOTSTRAP_TOKEN);
    const malformed = { email: "root@example.test", password: "short" };
    await expect(
      service.activate({ ...malformed, token: BOOTSTRAP_TOKEN }),
    ).rejects.toThrow("password must be between");
    await expect(
      service.activate({ ...malformed, token: "x".repeat(64) }),
    ).rejects.toThrow("password must be between");
  });

  it("disables bootstrap when the configured out-of-band token is weak or absent", async () => {
    expect(
      await new BootstrapService(db, "short").activate({
        token: "short",
        email: "root@example.test",
        password: "correct horse battery staple",
        organization: "Example Org",
      }),
    ).toBeNull();
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM users`)).rows[0].n)).toBe(0);
    // A disabled bootstrap creates no organization either.
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM tenants`)).rows[0].n)).toBe(0);
  });
});

describe("InvitationStore", () => {
  /**
   * These cases need a PLATFORM ROOT caller, which no product path mints any
   * more (decision 9) — an operator provisions it directly, so the fixture
   * does the same rather than routing through BootstrapService.
   */
  async function bootstrap(): Promise<void> {
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

  it("stores only a hash and activates the bound role and namespace exactly once", async () => {
    await bootstrap();
    const invites = new InvitationStore(db);
    const issued = await invites.create(
      { email: "Admin@Example.test", namespace: "acme/eng", role: "admin" },
      ROOT,
    );

    expect(issued.activationToken).toMatch(/^[0-9a-f]{64}$/);
    expect(issued.invite).toMatchObject({
      email: "admin@example.test",
      namespace: "acme/eng",
      role: "admin",
      status: "pending",
    });
    expect(await db.query(`SELECT * FROM users WHERE email = $1`, ["admin@example.test"])).toMatchObject({ rows: [] });
    const stored = (await db.query(`SELECT token_hash FROM auth_invitations`)).rows[0].token_hash;
    expect(stored).toBe(hashToken(issued.activationToken));
    expect(stored).not.toBe(issued.activationToken);

    const accepted = await invites.accept({
      token: issued.activationToken,
      password: "another correct horse password",
    });
    expect(accepted).toMatchObject({
      email: "admin@example.test",
      namespace: "acme/eng",
      role: "admin",
      status: "active",
    });
    expect(await invites.accept({
      token: issued.activationToken,
      password: "another correct horse password",
    })).toBeNull();
    expect((await db.query(`SELECT accepted_at FROM auth_invitations`)).rows[0].accepted_at).not.toBeNull();
  });

  it("rejects expired tokens without activating a user", async () => {
    await bootstrap();
    const issued = await new InvitationStore(db, () => new Date("2026-01-01T00:00:00.000Z")).create(
      { email: "expired@example.test", namespace: "acme", role: "member", ttlSeconds: 60 },
      ROOT,
    );
    const accepted = await new InvitationStore(db, () => new Date("2026-01-01T00:01:00.000Z")).accept({
      token: issued.activationToken,
      password: "another correct horse password",
    });
    expect(accepted).toBeNull();
    expect(Number((await db.query(`SELECT COUNT(*) AS n FROM users WHERE email = $1`, ["expired@example.test"])).rows[0].n)).toBe(0);
  });

  it("requires an explicit rotation so duplicate invites cannot silently invalidate authority", async () => {
    await bootstrap();
    let clock = new Date("2026-01-01T00:00:00.000Z");
    const invites = new InvitationStore(db, () => clock);
    const first = await invites.create(
      { email: "rotate@example.test", namespace: "acme", role: "member" },
      ROOT,
    );
    await expect(invites.create(
      { email: "ROTATE@example.test", namespace: "globex", role: "admin" },
      ROOT,
    )).rejects.toThrow(/waiting|expired/i);

    clock = new Date("2026-01-01T01:00:00.000Z");
    const second = await invites.rotate({
      invitationId: first.invite.id,
      namespace: "acme",
      kind: "reminder",
    }, ROOT);

    const rows = await db.query(
      `SELECT namespace, role, token_hash FROM auth_invitations WHERE email = $1`,
      ["rotate@example.test"],
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({ namespace: "acme", role: "member" });
    expect(rows.rows[0].token_hash).toBe(hashToken(second.activationToken));
    expect(await invites.accept({
      token: first.activationToken,
      password: "first obsolete invitation password",
    })).toBeNull();
    const accepted = await invites.accept({
      token: second.activationToken,
      password: "second current invitation password",
    });
    expect(accepted).toMatchObject({ namespace: "acme", role: "member" });
  });

  it("throttles reminders and preserves revoked invitations as non-accepting history", async () => {
    await bootstrap();
    let clock = new Date("2026-01-01T00:00:00.000Z");
    const invites = new InvitationStore(db, () => clock);
    const issued = await invites.create(
      { email: "history@example.test", namespace: "acme", role: "member" },
      ROOT,
    );
    clock = new Date("2026-01-01T00:10:00.000Z");
    const rotated = await invites.rotate({
      invitationId: issued.invite.id,
      namespace: "acme",
      kind: "reminder",
    }, ROOT);
    clock = new Date("2026-01-01T00:20:00.000Z");
    await expect(invites.rotate({
      invitationId: issued.invite.id,
      namespace: "acme",
      kind: "reminder",
    }, ROOT)).rejects.toThrow(/once per hour/i);

    await invites.revoke({ invitationId: issued.invite.id, namespace: "acme" }, ROOT);
    expect(await invites.accept({
      token: rotated.activationToken,
      password: "another correct horse password",
    })).toBeNull();
    const history = await db.query(
      `SELECT revoked_at, accepted_at FROM auth_invitations WHERE id = $1`,
      [issued.invite.id],
    );
    expect(history.rows[0].revoked_at).not.toBeNull();
    expect(history.rows[0].accepted_at).toBeNull();
  });

  it("prevents tenant admins from inviting a sibling or escalating to owner", async () => {
    await bootstrap();
    const invites = new InvitationStore(db);
    const tenantAdmin: Identity = {
      keyId: "admin-key",
      namespace: "acme",
      actor: "admin@example.test",
      role: "admin",
    };

    await expect(
      invites.create({ email: "sibling@example.test", namespace: "globex", role: "member" }, tenantAdmin),
    ).rejects.toBeInstanceOf(UserAuthzError);
    await expect(
      invites.create({ email: "owner@example.test", namespace: "acme", role: "owner" }, tenantAdmin),
    ).rejects.toBeInstanceOf(UserAuthzError);
  });
});
