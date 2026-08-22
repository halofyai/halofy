/**
 * M9 parity #23 (E52) — product key types over the existing ROLES.
 *
 * Verifies: the three-type mapping (admin/assistant/read-only ← the five
 * roles), self-describing plaintext prefixes that still resolve through the
 * unchanged AuthService path, D4 audit rows on create/rotate/revoke AND on
 * every denial, and D9 scope (rotation reads type/namespace/actor from the
 * stored row; subtree gates reuse the AuthService helpers).
 * Hermetic: in-memory PGlite, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MIGRATIONS, splitStatements } from "../src/db/migrations.js";
import { loadConfig } from "../src/config.js";
import { AuditLog } from "../src/audit/index.js";
import { AuthService, AuthzError } from "../src/auth/index.js";
import {
  PRODUCT_KEY_TYPES,
  BearerUnavailableError,
  ProductKeyService,
  productKeyTypeForPlaintext,
  productKeyTypeForRole,
} from "../src/auth/key-types.js";
import { AgentBearerCipher } from "../src/auth/bearer-cipher.js";
import { generateSigningKey } from "../src/erasure/keys.js";
import type { Identity } from "../src/types.js";

const DIM = 8;

let db: Db;
let auth: AuthService;
let audit: AuditLog;
let svc: ProductKeyService;
let owner: Identity;

async function auditCount(op: string, result: string, detailLike: string): Promise<number> {
  const res = await db.query(
    `SELECT COUNT(*) AS n FROM audit_log
      WHERE op = $1 AND result = $2 AND detail LIKE $3 ESCAPE '\\'`,
    [op, result, detailLike],
  );
  return Number(res.rows[0].n);
}

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  audit = new AuditLog(db);
  auth = new AuthService(db, audit);
  svc = new ProductKeyService(db, auth, audit, new AgentBearerCipher(generateSigningKey()));
  // Bootstrap: first key through the empty-table rule.
  const { plaintext } = await auth.issueKey("org", "root", "owner");
  const resolved = await auth.resolve(plaintext);
  if (!resolved) throw new Error("bootstrap owner did not resolve");
  owner = resolved;
});

afterAll(async () => {
  await db.close();
});

describe("type ↔ role mapping (E52 labels, no new core auth)", () => {
  it("maps the three product types onto the existing five roles", () => {
    expect(productKeyTypeForRole("owner")).toBe("admin");
    expect(productKeyTypeForRole("admin")).toBe("admin");
    expect(productKeyTypeForRole("agent")).toBe("assistant");
    expect(productKeyTypeForRole("auditor")).toBe("read-only");
    // 'member' is a human console role with no product key type.
    expect(productKeyTypeForRole("member")).toBeNull();
  });

  it("every spec carries a distinct hm_ prefix", () => {
    const prefixes = PRODUCT_KEY_TYPES.map((spec) => spec.prefix);
    expect(new Set(prefixes).size).toBe(prefixes.length);
    for (const prefix of prefixes) expect(prefix.startsWith("hm_")).toBe(true);
  });
});

describe("issue - audited, prefixed, resolves through the unchanged path", () => {
  it("issues an assistant key that resolves to role 'agent' and audits 'share'", async () => {
    const before = await auditCount("share", "ok", "key issued:%");
    const { record, plaintext } = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "helper-bot" },
      owner,
    );
    expect(plaintext.startsWith("hm_agt_")).toBe(true);
    expect(productKeyTypeForPlaintext(plaintext)).toBe("assistant");
    expect(record.role).toBe("agent");
    expect(record.keyType).toBe("assistant");
    expect(record.keyTypeLabel).toBe("Assistant");

    const identity = await auth.resolve(plaintext);
    expect(identity).toEqual<Identity>({
      keyId: record.id,
      namespace: "org/team-a",
      actor: "helper-bot",
      role: "agent",
      // D50: an assistant key issued without a named level is member-scope.
      agentAccessLevel: "member",
      // D54: an agent identity also carries whether it may CHANGE memory.
      // NULL on the row means "may write" — every pre-D54 agent could.
      agentCanWrite: true,
      callerClass: "external",
    });
    expect(await auditCount("share", "ok", "key issued:%")).toBe(before + 1);
  });

  it("records the server-derived caller_class on the row (D9, migration 038)", async () => {
    const { record } = await svc.issue(
      { type: "read-only", namespace: "org", actor: "audit-bot" },
      owner,
    );
    const res = await db.query(`SELECT caller_class, role FROM api_keys WHERE id = $1`, [
      record.id,
    ]);
    expect(res.rows[0].role).toBe("auditor");
    expect(res.rows[0].caller_class).toBe("internal");
  });

  it("denies an admin-type key from a non-owner caller and audits the denial (D4)", async () => {
    const issued = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "team-admin" },
      owner,
    );
    const admin = await auth.resolve(issued.plaintext);
    if (!admin) throw new Error("admin key did not resolve");
    const before = await auditCount("reject", "denied", "key issue denied:%");
    await expect(
      svc.issue({ type: "admin", namespace: "org/team-a", actor: "eve" }, admin),
    ).rejects.toThrow(AuthzError);
    expect(await auditCount("reject", "denied", "key issue denied:%")).toBe(before + 1);
  });

  it("records the ISSUING caller as created_by, not the actor the key acts as (migration 76)", async () => {
    const { record } = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "attributed-bot" },
      owner,
    );
    const res = await db.query(`SELECT created_by FROM api_keys WHERE id = $1`, [record.id]);
    expect(res.rows[0].created_by).toBe(owner.actor);
    expect(record.createdBy).toBe(owner.actor);
    expect(record.actor).toBe("attributed-bot");

    // The listing carries it, which is what lets S14 show a caller its own
    // connections instead of everyone's.
    const listed = (await svc.list(owner)).find((key) => key.id === record.id);
    expect(listed?.createdBy).toBe(owner.actor);
  });

  it("attributes a badge to the admin that issued it, not to the owner above them", async () => {
    const issued = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "issuing-admin" },
      owner,
    );
    const admin = await auth.resolve(issued.plaintext);
    if (!admin) throw new Error("admin key did not resolve");

    const badge = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "admins-own-bot" },
      admin,
    );
    expect(badge.record.createdBy).toBe("issuing-admin");

    // The owner still SEES it (subtree visibility is unchanged) - attribution
    // is a display fact, not an authorization one.
    const seenByOwner = (await svc.list(owner)).find((key) => key.id === badge.record.id);
    expect(seenByOwner?.createdBy).toBe("issuing-admin");
  });

  it("rejects reserved system- actors for typed keys", async () => {
    await expect(
      svc.issue({ type: "assistant", namespace: "org/team-a", actor: "system-default-skills" }, owner),
    ).rejects.toThrow(/reserved/);
  });

  it("denies issuance outside the caller's subtree and audits it", async () => {
    const issued = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "scoped-admin" },
      owner,
    );
    const admin = await auth.resolve(issued.plaintext);
    if (!admin) throw new Error("admin key did not resolve");
    const before = await auditCount("reject", "denied", "key issue denied:%");
    await expect(
      svc.issue({ type: "assistant", namespace: "org/team-b", actor: "eve" }, admin),
    ).rejects.toThrow(AuthzError);
    expect(await auditCount("reject", "denied", "key issue denied:%")).toBe(before + 1);
  });
});

describe("created_by backfill (migration 76)", () => {
  it("recovers the issuer of a pre-migration key from its audit row", async () => {
    const { record } = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "legacy-bot" },
      owner,
    );
    // Simulate a row that predates the column: the credential exists and its
    // issuance is in the audit trail, but nothing was ever written to the row.
    await db.query(`UPDATE api_keys SET created_by = NULL WHERE id = $1`, [record.id]);

    const migration = MIGRATIONS.find((m) => m.version === 76);
    if (!migration) throw new Error("migration 76 is missing");
    // Re-running the migration is safe (IF NOT EXISTS + a NULL-only UPDATE) and
    // exercises the SHIPPED statement, not a paraphrase of it.
    for (const statement of splitStatements(migration.sql(DIM))) {
      await db.query(statement);
    }

    const res = await db.query(`SELECT created_by FROM api_keys WHERE id = $1`, [record.id]);
    expect(res.rows[0].created_by).toBe(owner.actor);
  });

  it("leaves a key with no audited issuance unattributed rather than guessing", async () => {
    // The bootstrap key: minted by the empty-table rule with no caller at all.
    const res = await db.query(
      `SELECT created_by FROM api_keys WHERE namespace = 'org' AND actor = 'root'`,
    );
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0].created_by).toBeNull();
  });
});

describe("rotate - scope-preserving supersedence (D9)", () => {
  it("mints a replacement, revokes the old key, keeps scope, audits 'supersede'", async () => {
    const first = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "rotating-bot" },
      owner,
    );
    const before = await auditCount("supersede", "ok", "key rotated:%");
    const rotated = await svc.rotate(first.record.id, owner);

    expect(rotated.rotatedFromKeyId).toBe(first.record.id);
    expect(rotated.plaintext.startsWith("hm_agt_")).toBe(true);
    expect(rotated.record.namespace).toBe("org/team-a");
    expect(rotated.record.actor).toBe("rotating-bot");
    expect(rotated.record.role).toBe("agent");

    // Old credential is dead; new one resolves.
    expect(await auth.resolve(first.plaintext)).toBeNull();
    const identity = await auth.resolve(rotated.plaintext);
    expect(identity?.keyId).toBe(rotated.record.id);
    expect(await auditCount("supersede", "ok", "key rotated:%")).toBe(before + 1);
  });

  it("rotating an owner key preserves the stored 'owner' role (no downgrade, no escalation)", async () => {
    const rootKey = await auth.issueKey("org", "second-root", "owner", owner);
    const rotated = await svc.rotate(rootKey.record.id, owner);
    expect(rotated.record.role).toBe("owner");
    expect(rotated.record.keyType).toBe("admin");
    expect(rotated.plaintext.startsWith("hm_adm_")).toBe(true);
  });

  it("keeps the ORIGINAL issuer across a rotation performed by someone else", async () => {
    const issued = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "badge-issuing-admin" },
      owner,
    );
    const admin = await auth.resolve(issued.plaintext);
    if (!admin) throw new Error("admin key did not resolve");
    const badge = await svc.issue(
      { type: "assistant", namespace: "org/team-a", actor: "long-lived-bot" },
      admin,
    );

    // The owner rotates the admin's badge. Rotation re-issues the SAME
    // authority, so the connection stays the admin's - it must not migrate into
    // the owner's connections list.
    const rotated = await svc.rotate(badge.record.id, owner);
    expect(rotated.record.createdBy).toBe("badge-issuing-admin");
    const res = await db.query(`SELECT created_by FROM api_keys WHERE id = $1`, [
      rotated.record.id,
    ]);
    expect(res.rows[0].created_by).toBe("badge-issuing-admin");
  });

  it("refuses to rotate a 'member' key (no product type) and audits the denial", async () => {
    const memberKey = await auth.issueKey("org", "human", "member", owner);
    const before = await auditCount("reject", "denied", "rotate denied:%");
    await expect(svc.rotate(memberKey.record.id, owner)).rejects.toThrow(AuthzError);
    expect(await auditCount("reject", "denied", "rotate denied:%")).toBe(before + 1);
  });

  it("denies rotate of a key outside the caller's subtree and audits it", async () => {
    const outside = await svc.issue(
      { type: "assistant", namespace: "org/team-b", actor: "other-bot" },
      owner,
    );
    const scoped = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "a-admin" },
      owner,
    );
    const admin = await auth.resolve(scoped.plaintext);
    if (!admin) throw new Error("admin key did not resolve");
    const before = await auditCount("reject", "denied", "rotate denied:%");
    await expect(svc.rotate(outside.record.id, admin)).rejects.toThrow(AuthzError);
    expect(await auditCount("reject", "denied", "rotate denied:%")).toBe(before + 1);
  });
});

describe("revoke - audited, idempotent", () => {
  it("revokes an in-subtree key and audits 'retract'", async () => {
    const issued = await svc.issue(
      { type: "read-only", namespace: "org/team-a", actor: "doomed" },
      owner,
    );
    const before = await auditCount("retract", "ok", "key revoke:%");
    const { revoked } = await svc.revoke(issued.record.id, owner);
    expect(revoked).toBe(true);
    expect(await auth.resolve(issued.plaintext)).toBeNull();
    expect(await auditCount("retract", "ok", "key revoke:%")).toBe(before + 1);

    // Idempotent second revoke still audits (D4: every outcome writes a row).
    const again = await svc.revoke(issued.record.id, owner);
    expect(again.revoked).toBe(false);
    expect(await auditCount("retract", "ok", "key revoke:%")).toBe(before + 2);
  });

  it("denies revoking a key outside the subtree and audits the denial", async () => {
    const outside = await svc.issue(
      { type: "assistant", namespace: "org/team-b", actor: "b-bot" },
      owner,
    );
    const scoped = await svc.issue(
      { type: "admin", namespace: "org/team-a", actor: "a-admin-2" },
      owner,
    );
    const admin = await auth.resolve(scoped.plaintext);
    if (!admin) throw new Error("admin key did not resolve");
    const before = await auditCount("reject", "denied", "revoke denied:%");
    await expect(svc.revoke(outside.record.id, admin)).rejects.toThrow(AuthzError);
    expect(await auditCount("reject", "denied", "revoke denied:%")).toBe(before + 1);
  });

  it("list() decorates every visible key with its product type label", async () => {
    const keys = await svc.list(owner);
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      if (key.role === "member") expect(key.keyTypeLabel).toBe("Member");
      else expect(["Admin", "Assistant", "Read-only"]).toContain(key.keyTypeLabel);
    }
  });
});

describe("recipient-bound assistant key handoff", () => {
  const assigningOwner: Identity = {
    keyId: "session-owner",
    namespace: "org",
    actor: "owner@org.test",
    role: "owner",
    sessionUserId: "user-owner",
  };
  const recipient: Identity = {
    keyId: "session-recipient",
    namespace: "org/team-a",
    actor: "member@org.test",
    role: "member",
    sessionUserId: "user-member",
  };
  const peer: Identity = {
    keyId: "session-peer",
    namespace: "org/team-a",
    actor: "peer@org.test",
    role: "member",
    sessionUserId: "user-peer",
  };

  it("creates no bearer until claim, then lets only the custodian reveal it repeatedly", async () => {
    await db.query(
      `INSERT INTO users (id, email, namespace, role, status, created_at)
       VALUES ('user-owner', 'owner@org.test', 'org', 'owner', 'active', CURRENT_TIMESTAMP),
              ('user-member', 'member@org.test', 'org/team-a', 'member', 'active', CURRENT_TIMESTAMP),
              ('user-peer', 'peer@org.test', 'org/team-a', 'member', 'active', CURRENT_TIMESTAMP),
              ('user-admin', 'admin@org.test', 'org/team-a', 'admin', 'active', CURRENT_TIMESTAMP)
       ON CONFLICT (id) DO NOTHING`,
    );
    await db.query(
      `INSERT INTO org_teams (id, namespace, name, created_by, created_at)
       VALUES ('handoff-team-a', 'org/team-a', 'Team A', 'test', CURRENT_TIMESTAMP)
       ON CONFLICT (id) DO NOTHING`,
    );
    await db.query(
      `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
       VALUES ('handoff-team-a', 'user-member', 'user-owner', CURRENT_TIMESTAMP),
              ('handoff-team-a', 'user-peer', 'user-owner', CURRENT_TIMESTAMP)
       ON CONFLICT (team_id, user_id) DO NOTHING`,
    );

    const before = await db.query(
      `SELECT COUNT(*) AS n FROM api_keys WHERE actor = 'delegated-agent'`,
    );
    const assignment = await svc.assignToMember({
      namespace: "org/team-a",
      actor: "delegated-agent",
      recipientUserId: "user-member",
      agentCanWrite: false,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      idempotencyKey: "handoff-create-1",
    }, assigningOwner);

    expect(assignment.status).toBe("pending");
    expect(assignment).not.toHaveProperty("plaintext");
    expect(Number((await db.query(
      `SELECT COUNT(*) AS n FROM api_keys WHERE actor = 'delegated-agent'`,
    )).rows[0].n)).toBe(Number(before.rows[0].n));
    expect(await svc.listAssigned(recipient)).toEqual([
      expect.objectContaining({ id: assignment.id, actor: "delegated-agent", status: "pending" }),
    ]);
    expect(await svc.listAssigned(peer)).toEqual([]);

    const claimed = await svc.claimAssigned(assignment.id, recipient);
    expect(claimed.plaintext).toMatch(/^hm_agt_[0-9a-f]{40}$/);
    expect(claimed.record.custodianUserId).toBe("user-member");
    expect(claimed.record.agentAccessLevel).toBe("member");
    expect(claimed.record.agentCanWrite).toBe(false);
    const storedBearer = (await db.query(
      `SELECT key_hash, bearer_ciphertext, bearer_iv, bearer_tag
         FROM api_keys WHERE id = $1`,
      [claimed.record.id],
    )).rows[0] as Record<string, unknown>;
    expect(storedBearer.bearer_ciphertext).toEqual(expect.any(String));
    expect(storedBearer.bearer_iv).toEqual(expect.any(String));
    expect(storedBearer.bearer_tag).toEqual(expect.any(String));
    expect(JSON.stringify(storedBearer)).not.toContain(claimed.plaintext);
    await expect(auth.resolveActiveIdentity(claimed.record.id)).resolves.toMatchObject({
      agentAccessLevel: "member",
      agentCanWrite: false,
    });
    await expect(auth.resolveChannelIdentity(claimed.record.id)).resolves.toMatchObject({
      agentAccessLevel: "member",
      agentCanWrite: false,
    });
    await expect(svc.claimAssigned(assignment.id, recipient)).rejects.toThrow(/not available/i);
    await expect(svc.claimAssigned(assignment.id, peer)).rejects.toThrow(/not available/i);

    const firstReveal = await svc.reveal(claimed.record.id, recipient);
    const secondReveal = await svc.reveal(claimed.record.id, recipient);
    expect(firstReveal.plaintext).toBe(claimed.plaintext);
    expect(secondReveal.plaintext).toBe(claimed.plaintext);
    await expect(svc.reveal(claimed.record.id, peer)).rejects.toThrow(AuthzError);
    expect(await auditCount("read", "ok", "key bearer revealed:%")).toBeGreaterThanOrEqual(2);
  });

  it("accepts an active member's additional team membership as assignment authority", async () => {
    await db.query(
      `INSERT INTO users (id, email, namespace, role, status, created_at)
       VALUES ('user-additional', 'additional@org.test', 'org/team-b', 'member', 'active', CURRENT_TIMESTAMP)
       ON CONFLICT (id) DO NOTHING`,
    );
    await db.query(
      `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
       VALUES ('handoff-team-a', 'user-additional', 'user-owner', CURRENT_TIMESTAMP)
       ON CONFLICT (team_id, user_id) DO NOTHING`,
    );
    const additional: Identity = {
      keyId: "session-additional",
      namespace: "org/team-b",
      actor: "additional@org.test",
      role: "member",
      sessionUserId: "user-additional",
    };
    const assignment = await svc.assignToMember({
      namespace: "org/team-a",
      actor: "additional-membership-agent",
      recipientUserId: "user-additional",
      idempotencyKey: "handoff-additional-membership",
    }, assigningOwner);
    const claimed = await svc.claimAssigned(assignment.id, additional);
    expect(claimed.record.namespace).toBe("org/team-a");
    await expect(svc.reveal(claimed.record.id, additional)).resolves.toMatchObject({
      plaintext: claimed.plaintext,
    });
  });

  it("reports pre-envelope credentials as unavailable until rotation", async () => {
    const humanOwner: Identity = {
      ...owner,
      actor: "owner@org.test",
      sessionUserId: "user-owner",
    };
    const legacy = await auth.issueKey("org/team-a", "legacy-agent", "agent", owner);
    const listed = await svc.list(humanOwner);
    expect(listed.find((key) => key.id === legacy.record.id)?.bearerRevealable).toBe(false);
    await expect(svc.reveal(legacy.record.id, humanOwner)).rejects.toThrow(BearerUnavailableError);
  });

  it("prevents a same-team member from rotating or revoking another member's key", async () => {
    const assigned = await svc.assignToMember({
      namespace: "org/team-a",
      actor: "recipient-owned-agent",
      recipientUserId: "user-member",
      idempotencyKey: "handoff-create-2",
    }, assigningOwner);
    const claimed = await svc.claimAssigned(assigned.id, recipient);

    await expect(svc.rotate(claimed.record.id, peer)).rejects.toThrow(AuthzError);
    await expect(svc.revoke(claimed.record.id, peer)).rejects.toThrow(AuthzError);
    await expect(svc.revoke(claimed.record.id, recipient)).resolves.toEqual({ revoked: true });
    const revokedEnvelope = (await db.query(
      `SELECT bearer_ciphertext, bearer_iv, bearer_tag FROM api_keys WHERE id = $1`,
      [claimed.record.id],
    )).rows[0] as Record<string, unknown>;
    expect(revokedEnvelope).toMatchObject({
      bearer_ciphertext: null,
      bearer_iv: null,
      bearer_tag: null,
    });
  });

  it("binds idempotency to the request and lets the assigner revoke pending delivery", async () => {
    const deniedBefore = await auditCount("reject", "denied", "key handoff denied:%");
    const first = await svc.assignToMember({
      namespace: "org/team-a", actor: "pending-agent", recipientUserId: "user-member",
      idempotencyKey: "handoff-create-3",
    }, assigningOwner);
    await expect(svc.assignToMember({
      namespace: "org/team-a", actor: "different-agent", recipientUserId: "user-member",
      idempotencyKey: "handoff-create-3",
    }, assigningOwner)).rejects.toThrow(/already bound/i);
    await expect(svc.assignToMember({
      namespace: "org/team-a", actor: "system-reserved", recipientUserId: "user-member",
      idempotencyKey: "handoff-create-invalid",
    }, assigningOwner)).rejects.toThrow(/valid agent name/i);
    expect(await auditCount("reject", "denied", "key handoff denied:%"))
      .toBe(deniedBefore + 2);
    const deniedBeforeExpiry = await auditCount("reject", "denied", "key handoff denied:%");
    await expect(svc.assignToMember({
      namespace: "org/team-a", actor: "expired-agent", recipientUserId: "user-member",
      expiresAt: "not-a-timestamp", idempotencyKey: "handoff-create-bad-expiry",
    }, assigningOwner)).rejects.toThrow(/expiresAt/i);
    expect(await auditCount("reject", "denied", "key handoff denied:%"))
      .toBe(deniedBeforeExpiry + 1);
    await expect(svc.revokeAssigned(first.id, assigningOwner)).resolves.toEqual({ revoked: true });
    await expect(svc.claimAssigned(first.id, recipient)).rejects.toThrow(/not available/i);
  });

  it("audits role, visibility, and session denials across handoff operations", async () => {
    const deniedBefore = await auditCount("reject", "denied", "key handoff %denied:%");
    await expect(svc.listAssigned({ ...recipient, role: "agent" })).rejects.toThrow(/human session/i);
    await expect(svc.claimAssigned("missing-handoff", assigningOwner)).rejects.toThrow(/member human session/i);
    await expect(svc.revokeAssigned("missing-handoff", recipient)).rejects.toThrow(/owner or admin/i);
    await expect(svc.revokeAssigned("missing-handoff", assigningOwner)).rejects.toThrow(/not found/i);
    expect(await auditCount("reject", "denied", "key handoff %denied:%"))
      .toBe(deniedBefore + 4);
  });

  it("lets a scope-authorized owner govern another admin's pending assignment", async () => {
    const teamAdmin: Identity = {
      keyId: "session-admin", namespace: "org/team-a", actor: "admin@org.test",
      role: "admin", sessionUserId: "user-admin",
    };
    const pending = await svc.assignToMember({
      namespace: "org/team-a", actor: "admin-pending", recipientUserId: "user-member",
      idempotencyKey: "handoff-create-4",
    }, teamAdmin);
    await expect(svc.listAssigned(assigningOwner)).resolves.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: pending.id })]),
    );
    await expect(svc.revokeAssigned(pending.id, assigningOwner)).resolves.toEqual({ revoked: true });
  });
});
