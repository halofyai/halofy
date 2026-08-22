/**
 * M10 grants module — access_grants / access_preview_sessions schema (v54)
 * and the AccessGrantStore repository (CONTRACTS-M10-ACCESS.md, module
 * "grants"). Hermetic: in-memory PGlite, injected clock, zero network.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { AccessGrantStore } from "../src/iam/access-grants.js";

const DIM = 8;
const TENANT_A = "acme";
const TENANT_B = "globex";

let db: Db;
let audit: AuditLog;
let clock: Date;
let store: AccessGrantStore;
let seq = 0;

function makeStore(): AccessGrantStore {
  return new AccessGrantStore({
    db,
    audit,
    now: () => clock,
    newId: () => `01GRANT${String(seq++).padStart(6, "0")}`,
  });
}

async function seedTeam(id: string, namespace: string): Promise<void> {
  await db.query(
    `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
     VALUES ($1, $2, $3, '', 'root@acme.test', $4)`,
    [id, namespace, `team-${id}`, clock.toISOString()],
  );
}

async function seedUser(id: string, email: string, namespace: string): Promise<void> {
  await db.query(
    `INSERT INTO users (id, email, namespace, role, status, created_at)
     VALUES ($1, $2, $3, 'member', 'active', $4)`,
    [id, email, namespace, clock.toISOString()],
  );
}

function baseGrant(overrides: Record<string, unknown> = {}) {
  return {
    tenantId: TENANT_A,
    principalType: "human" as const,
    principalId: "user-1",
    resourceType: "function" as const,
    resourceId: "team-sales",
    namespaceRoot: "acme/sales",
    accessMode: "consume" as const,
    source: "direct" as const,
    createdBy: "root@acme.test",
    ...overrides,
  };
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  audit = new AuditLog(db);
});

afterAll(async () => {
  await db.close();
});

beforeEach(async () => {
  clock = new Date("2026-07-24T12:00:00.000Z");
  seq = 0;
  store = makeStore();
  await db.query(`DELETE FROM access_grants`);
  await db.query(`DELETE FROM access_preview_sessions`);
  await db.query(`DELETE FROM org_team_members`);
  await db.query(`DELETE FROM org_teams`);
  await db.query(`DELETE FROM users`);
});

describe("migration v54 schema", () => {
  it("creates both tables with ROW LEVEL SECURITY enabled (post-M9 convention)", async () => {
    const res = await db.query(
      `SELECT relname, relrowsecurity FROM pg_class
        WHERE relname IN ('access_grants', 'access_preview_sessions')
        ORDER BY relname`,
    );
    expect(res.rows).toEqual([
      { relname: "access_grants", relrowsecurity: true },
      { relname: "access_preview_sessions", relrowsecurity: true },
    ]);
  });

  it("does NOT create agent_memory_grants (Phase 4 deferred)", async () => {
    const res = await db.query(
      `SELECT relname FROM pg_class WHERE relname = 'agent_memory_grants'`,
    );
    expect(res.rows).toHaveLength(0);
  });

  it("rejects out-of-enum values via CHECK constraints", async () => {
    await expect(
      db.query(
        `INSERT INTO access_grants
           (id, tenant_id, principal_type, principal_id, resource_type,
            resource_id, namespace_root, access_mode, source, created_by, created_at)
         VALUES ('x', 'acme', 'alien', 'p', 'function', 'r', 'acme', 'consume',
                 'direct', 'a', '2026-07-24T12:00:00Z')`,
      ),
    ).rejects.toThrow(/check/i);
    await expect(
      db.query(
        `INSERT INTO access_grants
           (id, tenant_id, principal_type, principal_id, resource_type,
            resource_id, namespace_root, access_mode, source, created_by, created_at)
         VALUES ('x', 'acme', 'human', 'p', 'function', 'r', 'acme', 'delete-all',
                 'direct', 'a', '2026-07-24T12:00:00Z')`,
      ),
    ).rejects.toThrow(/check/i);
    await expect(
      db.query(
        `INSERT INTO access_preview_sessions
           (id, token_hash, tenant_id, root_user_id, simulated_role, reason,
            created_at, expires_at)
         VALUES ('p', 'h', 'acme', 'root-1', 'root', 'why',
                 '2026-07-24T12:00:00Z', '2026-07-24T12:15:00Z')`,
      ),
    ).rejects.toThrow(/check/i);
  });
});

describe("createGrant / revokeGrant", () => {
  it("creates a grant and appends a D4 audit row in the same operation", async () => {
    const grant = await store.createGrant(baseGrant());
    expect(grant.revokedAt).toBeNull();
    expect(grant.createdAt).toBe("2026-07-24T12:00:00.000Z");

    const rows = await db.query(`SELECT * FROM access_grants WHERE id = $1`, [grant.id]);
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0].namespace_root).toBe("acme/sales");

    const events = await audit.list("acme/sales");
    expect(events).toHaveLength(1);
    expect(events[0].purpose).toBe("grant.create");
    expect(events[0].result).toBe("ok");
    expect(events[0].actor).toBe("root@acme.test");
    expect(events[0].detail).toContain("human:user-1");
    expect(events[0].detail).toContain("function:team-sales");
    expect(events[0].detail).toContain("consume");
  });

  it("revoke sets revoked_at and KEEPS the row (D7/D47 - never DELETE)", async () => {
    const grant = await store.createGrant(baseGrant());
    clock = new Date("2026-07-24T13:00:00.000Z");

    const revoked = await store.revokeGrant({
      tenantId: TENANT_A,
      grantId: grant.id,
      actor: "root@acme.test",
    });
    expect(revoked?.revokedAt).toBe("2026-07-24T13:00:00.000Z");

    const rows = await db.query(`SELECT revoked_at FROM access_grants WHERE id = $1`, [grant.id]);
    expect(rows.rows).toHaveLength(1); // row survives revocation
    expect(rows.rows[0].revoked_at).not.toBeNull();

    const events = await audit.list("acme/sales");
    expect(events[0].purpose).toBe("grant.revoke");
    expect(events[0].result).toBe("ok");
  });

  it("revoking an unknown, foreign-tenant, or already-revoked grant is one uniform audited miss", async () => {
    const grant = await store.createGrant(baseGrant());

    const unknown = await store.revokeGrant({
      tenantId: TENANT_A, grantId: "no-such-grant", actor: "root@acme.test",
    });
    const foreign = await store.revokeGrant({
      tenantId: TENANT_B, grantId: grant.id, actor: "root@globex.test",
    });
    expect(unknown).toBeNull();
    expect(foreign).toBeNull();

    // The foreign attempt did NOT revoke tenant A's grant.
    const rows = await db.query(`SELECT revoked_at FROM access_grants WHERE id = $1`, [grant.id]);
    expect(rows.rows[0].revoked_at).toBeNull();

    await store.revokeGrant({ tenantId: TENANT_A, grantId: grant.id, actor: "root@acme.test" });
    const again = await store.revokeGrant({
      tenantId: TENANT_A, grantId: grant.id, actor: "root@acme.test",
    });
    expect(again).toBeNull();

    const misses = await db.query(
      `SELECT namespace, detail FROM audit_log WHERE purpose = 'grant.revoke' AND result = 'miss'`,
    );
    expect(misses.rows).toHaveLength(3);
    // The miss detail never names the hidden target's namespace (D46).
    for (const row of misses.rows) {
      expect(String(row.detail)).not.toContain("acme/sales");
    }
  });
});

describe("listEffectiveGrants", () => {
  it("filters revoked and expired grants via the injected now", async () => {
    const live = await store.createGrant(baseGrant({ resourceId: "team-live" }));
    const expiring = await store.createGrant(baseGrant({
      resourceId: "team-expiring",
      expiresAt: "2026-07-24T12:30:00.000Z",
    }));
    const revoked = await store.createGrant(baseGrant({ resourceId: "team-revoked" }));
    await store.revokeGrant({ tenantId: TENANT_A, grantId: revoked.id, actor: "root@acme.test" });
    await store.createGrant(baseGrant({ tenantId: TENANT_B, resourceId: "team-foreign" }));
    await store.createGrant(baseGrant({ principalId: "user-2", resourceId: "team-other" }));

    const before = await store.listEffectiveGrants(
      TENANT_A, "user-1", new Date("2026-07-24T12:10:00.000Z"),
    );
    expect(before.map((g) => g.id).sort()).toEqual([live.id, expiring.id].sort());

    const after = await store.listEffectiveGrants(
      TENANT_A, "user-1", new Date("2026-07-24T12:31:00.000Z"),
    );
    expect(after.map((g) => g.id)).toEqual([live.id]);
  });
});

describe("resolveResourceRoots", () => {
  it("resolves inside the tenant only; foreign-tenant and unknown IDs are silently dropped", async () => {
    await seedTeam("team-mkt", "acme/marketing");
    await seedTeam("team-globex", "globex/ops"); // foreign-tenant team
    await store.createGrant(baseGrant({ resourceId: "res-sales", namespaceRoot: "acme/sales" }));
    await store.createGrant(baseGrant({
      tenantId: TENANT_B, resourceId: "res-globex", namespaceRoot: "globex/ops",
    }));

    const roots = await store.resolveResourceRoots(TENANT_A, [
      "team-mkt", "team-globex", "res-sales", "res-globex", "no-such-id", "",
    ]);
    expect(roots.get("team-mkt")).toBe("acme/marketing");
    expect(roots.get("res-sales")).toBe("acme/sales");
    expect(roots.has("team-globex")).toBe(false);
    expect(roots.has("res-globex")).toBe(false);
    expect(roots.has("no-such-id")).toBe(false);
    expect(roots.size).toBe(2);
  });

  it("treats _ and % in tenant roots as literal characters, never wildcards", async () => {
    // If the tenant boundary used an unescaped pattern, 'acme_x' would match
    // a team under sibling 'acmeXx'.
    await seedTeam("team-under", "acme_x/team");
    await seedTeam("team-sibling", "acmeXx/team");
    const roots = await store.resolveResourceRoots("acme_x", ["team-under", "team-sibling"]);
    expect(roots.get("team-under")).toBe("acme_x/team");
    expect(roots.has("team-sibling")).toBe(false);
  });

  it("returns an empty map for an empty ID list", async () => {
    expect((await store.resolveResourceRoots(TENANT_A, [])).size).toBe(0);
  });
});

describe("syncMembershipGrant (teams.ts seam)", () => {
  beforeEach(async () => {
    await seedTeam("team-sales", "acme/sales");
    await seedUser("user-1", "one@acme.test", "acme/sales");
  });

  it("add creates a membership consume grant with the server-resolved namespace root", async () => {
    await db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
         VALUES ('team-sales', 'user-1', 'root@acme.test', $1)`,
        [clock.toISOString()],
      );
      await store.syncMembershipGrant(tx, {
        tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
        action: "add", actor: "root@acme.test",
      });
    });

    const grants = await store.listEffectiveGrants(TENANT_A, "user-1", clock);
    expect(grants).toHaveLength(1);
    expect(grants[0].source).toBe("membership");
    expect(grants[0].accessMode).toBe("consume");
    expect(grants[0].resourceType).toBe("function");
    expect(grants[0].resourceId).toBe("team-sales");
    expect(grants[0].namespaceRoot).toBe("acme/sales");

    // Idempotent re-add: no duplicate active grant.
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "add", actor: "root@acme.test",
    }));
    expect(await store.listEffectiveGrants(TENANT_A, "user-1", clock)).toHaveLength(1);
  });

  it("add with accessMode govern mints a govern grant (admin/owner roster rows)", async () => {
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "add", actor: "root@acme.test", accessMode: "govern",
    }));
    const grants = await store.listEffectiveGrants(TENANT_A, "user-1", clock);
    expect(grants).toHaveLength(1);
    expect(grants[0].accessMode).toBe("govern");
  });

  it("update re-syncs the grant mode on a roster role change (consume -> govern -> consume)", async () => {
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "add", actor: "root@acme.test", accessMode: "consume",
    }));

    // Promote: consume grant revoked, govern grant minted, one active row.
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "update", actor: "root@acme.test", accessMode: "govern",
    }));
    let grants = await store.listEffectiveGrants(TENANT_A, "user-1", clock);
    expect(grants).toHaveLength(1);
    expect(grants[0].accessMode).toBe("govern");

    // Idempotent update with the same mode: nothing new.
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "update", actor: "root@acme.test", accessMode: "govern",
    }));
    grants = await store.listEffectiveGrants(TENANT_A, "user-1", clock);
    expect(grants).toHaveLength(1);

    // Demote back: govern revoked, consume minted. History survives (D7).
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "update", actor: "root@acme.test", accessMode: "consume",
    }));
    grants = await store.listEffectiveGrants(TENANT_A, "user-1", clock);
    expect(grants).toHaveLength(1);
    expect(grants[0].accessMode).toBe("consume");
    const all = await db.query(
      `SELECT access_mode, revoked_at FROM access_grants
        WHERE principal_id = 'user-1' ORDER BY created_at, id`,
    );
    expect(all.rows).toHaveLength(3); // consume(revoked), govern(revoked), consume(active)
    expect(all.rows.filter((r) => r.revoked_at === null)).toHaveLength(1);
  });

  it("remove revokes the membership grant (row survives) in the same transaction", async () => {
    await db.transaction((tx) => store.syncMembershipGrant(tx, {
      tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
      action: "add", actor: "root@acme.test",
    }));
    await db.transaction(async (tx) => {
      await tx.query(
        `DELETE FROM org_team_members WHERE team_id = 'team-sales' AND user_id = 'user-1'`,
      );
      await store.syncMembershipGrant(tx, {
        tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
        action: "remove", actor: "root@acme.test",
      });
    });

    expect(await store.listEffectiveGrants(TENANT_A, "user-1", clock)).toHaveLength(0);
    const rows = await db.query(
      `SELECT revoked_at FROM access_grants WHERE principal_id = 'user-1'`,
    );
    expect(rows.rows).toHaveLength(1); // D7: revoked, not deleted
    expect(rows.rows[0].revoked_at).not.toBeNull();
  });

  it("a mid-transaction failure rolls back BOTH the roster row and the grant", async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
           VALUES ('team-sales', 'user-1', 'root@acme.test', $1)`,
          [clock.toISOString()],
        );
        await store.syncMembershipGrant(tx, {
          tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-sales",
          action: "add", actor: "root@acme.test",
        });
        throw new Error("injected mid-transaction failure");
      }),
    ).rejects.toThrow("injected mid-transaction failure");

    const members = await db.query(`SELECT * FROM org_team_members`);
    const grants = await db.query(`SELECT * FROM access_grants`);
    expect(members.rows).toHaveLength(0);
    expect(grants.rows).toHaveLength(0);
  });

  it("rejects unknown and foreign-tenant functional areas, rolling the tx back", async () => {
    await seedTeam("team-globex", "globex/ops");
    await expect(
      db.transaction((tx) => store.syncMembershipGrant(tx, {
        tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "no-such-team",
        action: "add", actor: "root@acme.test",
      })),
    ).rejects.toThrow(/no functional area/);
    await expect(
      db.transaction((tx) => store.syncMembershipGrant(tx, {
        tenantId: TENANT_A, userId: "user-1", teamOrFunctionId: "team-globex",
        action: "add", actor: "root@acme.test",
      })),
    ).rejects.toThrow(/no functional area/);
    expect((await db.query(`SELECT * FROM access_grants`)).rows).toHaveLength(0);
  });
});

describe("ensureAuditReadGrant (D41 auditor translation)", () => {
  it("creates one system audit_read grant and is idempotent while active", async () => {
    const first = await db.transaction((tx) =>
      store.ensureAuditReadGrant(tx, {
        tenantId: TENANT_A, userId: "user-9", actor: "system",
      }),
    );
    expect(first?.accessMode).toBe("audit_read");
    expect(first?.resourceType).toBe("audit");
    expect(first?.source).toBe("system");
    expect(first?.namespaceRoot).toBe(TENANT_A);

    const second = await db.transaction((tx) =>
      store.ensureAuditReadGrant(tx, {
        tenantId: TENANT_A, userId: "user-9", actor: "system",
      }),
    );
    expect(second).toBeNull();
    expect((await db.query(`SELECT * FROM access_grants`)).rows).toHaveLength(1);
  });
});
