/**
 * Team-bound human role assignment and invitation acceptance.
 *
 * Hermetic: every test boots an in-memory PGlite kernel with HashEmbedder and
 * StubLlm defaults. The tests assert durable state and audit outcomes rather
 * than implementation call order.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import { InvitationStore } from "../src/console/auth.js";
import type { HumanRole, Identity } from "../src/types.js";

let kernel: Kernel;
let root: Identity;
let tenantOwner: Identity;
let tenantAdmin: Identity;
let siblingOwner: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const identity = await kernel.auth.resolve(issued.plaintext);
  if (!identity) throw new Error(`identity '${actor}' did not resolve`);
  return identity;
}

async function seedUser(
  email: string,
  namespace: string,
  role: HumanRole,
  status = "active",
): Promise<string> {
  const id = ulid();
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, $3, $4, NULL, $5, $6)`,
    [id, email, namespace, role, status, new Date().toISOString()],
  );
  return id;
}

async function teamWithMember(
  email: string,
  role: HumanRole,
): Promise<{ teamId: string; namespace: string; userId: string }> {
  const team = await kernel.createTeam(tenantOwner, { name: "Platform" });
  const userId = await seedUser(email, team.namespace, role);
  await kernel.addTeamMember(tenantOwner, team.id, email);
  return { teamId: team.id, namespace: team.namespace, userId };
}

beforeEach(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "root@halomem.test", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner did not resolve");
  root = resolvedRoot;
  tenantOwner = await issue("acme", "owner@acme.test", "owner", root);
  tenantAdmin = await issue("acme", "admin@acme.test", "admin", root);
  siblingOwner = await issue("globex", "owner@globex.test", "owner", root);
});

afterEach(async () => {
  await kernel.close();
});

describe("existing human role assignment", () => {
  it("allows an owner to change a role and writes durable audit evidence", async () => {
    const member = await teamWithMember("member@acme.test", "member");

    await kernel.changeTeamMemberRole(
      tenantOwner,
      member.teamId,
      member.userId,
      "admin",
    );

    const user = await kernel.db.query(
      `SELECT role FROM users WHERE id = $1`,
      [member.userId],
    );
    expect(user.rows).toEqual([{ role: "admin" }]);

    const audit = await kernel.db.query(
      `SELECT actor, namespace, purpose, result
         FROM audit_log
        WHERE purpose = 'console-team-member-role-change'
          AND actor = $1 AND namespace = $2`,
      [tenantOwner.actor, member.namespace],
    );
    expect(audit.rows).toEqual([{
      actor: tenantOwner.actor,
      namespace: member.namespace,
      purpose: "console-team-member-role-change",
      result: "ok",
    }]);
  });

  it("denies an admin changing an existing role and leaves the user unchanged", async () => {
    const member = await teamWithMember("admin-target@acme.test", "member");

    await expect(kernel.changeTeamMemberRole(
      tenantAdmin,
      member.teamId,
      member.userId,
      "admin",
    )).rejects.toMatchObject({ name: "AuthzError" });

    const user = await kernel.db.query(`SELECT role FROM users WHERE id = $1`, [member.userId]);
    expect(user.rows).toEqual([{ role: "member" }]);
  });

  it("requires selected-team membership and a home namespace in that team subtree", async () => {
    const team = await kernel.createTeam(tenantOwner, { name: "Platform" });
    const unassigned = await seedUser("unassigned@acme.test", team.namespace, "member");
    await expect(kernel.changeTeamMemberRole(
      tenantOwner,
      team.id,
      unassigned,
      "admin",
    )).rejects.toThrow(/member/i);

    const wrongHome = await seedUser("wrong-home@acme.test", "acme/sales", "member");
    await kernel.db.query(
      `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
       VALUES ($1, $2, $3, $4)`,
      [team.id, wrongHome, tenantOwner.actor, new Date().toISOString()],
    );
    await expect(kernel.changeTeamMemberRole(
      tenantOwner,
      team.id,
      wrongHome,
      "admin",
    )).rejects.toThrow(/namespace|scope|subtree/i);
  });

  it("keeps sibling teams invisible to an owner outside their subtree", async () => {
    const member = await teamWithMember("scoped@acme.test", "member");

    await expect(kernel.changeTeamMemberRole(
      siblingOwner,
      member.teamId,
      member.userId,
      "admin",
    )).rejects.toMatchObject({
      name: "BadRequestError",
      message: expect.stringContaining("no team"),
    });
  });

  it("D41 inverse guard: retired 'auditor'/'owner' inputs are rejected; 'root' mints internal owner", async () => {
    const member = await teamWithMember("guarded@acme.test", "member");

    // No NEW internal auditor or owner row can be minted from public input.
    for (const retired of ["auditor", "owner"]) {
      await expect(kernel.changeTeamMemberRole(
        tenantOwner,
        member.teamId,
        member.userId,
        retired,
      )).rejects.toMatchObject({ name: "BadRequestError" });
    }
    expect((await kernel.db.query(
      `SELECT role FROM users WHERE id = $1`,
      [member.userId],
    )).rows).toEqual([{ role: "member" }]);

    // The product role 'root' maps to the internal 'owner' through this
    // documented owner-gated root-assignment route.
    await kernel.changeTeamMemberRole(tenantOwner, member.teamId, member.userId, "root");
    expect((await kernel.db.query(
      `SELECT role FROM users WHERE id = $1`,
      [member.userId],
    )).rows).toEqual([{ role: "owner" }]);

    // The invitation path enforces the same guard.
    for (const retired of ["auditor", "owner"]) {
      await expect(kernel.inviteTeamMember(tenantOwner, member.teamId, {
        email: `${retired}-mint@acme.test`,
        role: retired,
      })).rejects.toMatchObject({ name: "BadRequestError" });
    }
    expect((await kernel.db.query(
      `SELECT id FROM auth_invitations WHERE email LIKE '%-mint@acme.test'`,
    )).rows).toEqual([]);
  });

  it("refuses to demote the final active owner in the selected team subtree", async () => {
    const first = await teamWithMember("owner-one@acme.test", "owner");
    const secondId = await seedUser("owner-two@acme.test", first.namespace, "owner");
    await kernel.addTeamMember(tenantOwner, first.teamId, "owner-two@acme.test");

    await kernel.changeTeamMemberRole(
      tenantOwner,
      first.teamId,
      first.userId,
      "admin",
    );
    await expect(kernel.changeTeamMemberRole(
      tenantOwner,
      first.teamId,
      secondId,
      "admin",
    )).rejects.toThrow(/last|final.*owner/i);

    const remaining = await kernel.db.query(
      `SELECT email, role FROM users WHERE id = $1`,
      [secondId],
    );
    expect(remaining.rows).toEqual([{ email: "owner-two@acme.test", role: "owner" }]);
  });
});

describe("team mutation audit atomicity", () => {
  it("rolls back team and membership mutations when their audit write fails", async () => {
    const createAudit = vi.spyOn(kernel.audit, "appendTo")
      .mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(kernel.createTeam(tenantOwner, { name: "Must Roll Back" }))
      .rejects.toThrow("audit unavailable");
    createAudit.mockRestore();
    const rolledBackTeam = await kernel.db.query(
      `SELECT id FROM org_teams WHERE namespace = $1`,
      ["acme/must-roll-back"],
    );
    expect(rolledBackTeam.rows).toEqual([]);

    const team = await kernel.createTeam(tenantOwner, { name: "Atomic Members" });
    const userId = await seedUser("atomic-member@acme.test", team.namespace, "member");
    const addAudit = vi.spyOn(kernel.audit, "appendTo")
      .mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(kernel.addTeamMember(tenantOwner, team.id, "atomic-member@acme.test"))
      .rejects.toThrow("audit unavailable");
    addAudit.mockRestore();
    expect((await kernel.db.query(
      `SELECT user_id FROM org_team_members WHERE team_id = $1 AND user_id = $2`,
      [team.id, userId],
    )).rows).toEqual([]);

    await kernel.addTeamMember(tenantOwner, team.id, "atomic-member@acme.test");
    const removeAudit = vi.spyOn(kernel.audit, "appendTo")
      .mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(kernel.removeTeamMember(tenantOwner, team.id, userId))
      .rejects.toThrow("audit unavailable");
    removeAudit.mockRestore();
    expect((await kernel.db.query(
      `SELECT user_id FROM org_team_members WHERE team_id = $1 AND user_id = $2`,
      [team.id, userId],
    )).rows).toEqual([{ user_id: userId }]);
  });
});

describe("Teams v2 lifecycle", () => {
  it("renames display text without changing the address and makes archived teams read-only", async () => {
    const team = await kernel.createTeam(tenantOwner, { name: "Support" });
    const renamed = await kernel.renameTeam(tenantAdmin, team.id, "Customer Support");
    expect(renamed).toMatchObject({
      name: "Customer Support",
      namespace: "acme/support",
      status: "active",
    });

    await expect(kernel.setTeamArchived(tenantAdmin, team.id, true))
      .rejects.toMatchObject({ name: "AuthzError" });
    const archived = await kernel.setTeamArchived(tenantOwner, team.id, true);
    expect(archived.status).toBe("archived");
    await expect(kernel.renameTeam(tenantOwner, team.id, "Nope"))
      .rejects.toThrow(/read-only/i);
    await expect(kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "archived@acme.test",
      role: "member",
    })).rejects.toThrow(/read-only/i);

    const restored = await kernel.setTeamArchived(tenantOwner, team.id, false);
    expect(restored.status).toBe("active");
    expect(restored.namespace).toBe("acme/support");
  });

  it("returns waiting, expired, joined, and revoked invitation history without credentials", async () => {
    const team = await kernel.createTeam(tenantOwner, { name: "Invite History" });
    const waiting = await kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "waiting@acme.test",
      role: "member",
    });
    await kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "still-waiting@acme.test",
      role: "member",
    });
    const revoked = await kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "revoked@acme.test",
      role: "member",
    });
    await kernel.revokeTeamInvitation(tenantOwner, team.id, revoked.invite.id);
    const joined = await kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "joined@acme.test",
      role: "member",
    });
    expect(await kernel.invitations.accept({
      token: joined.activationToken,
      password: "correct horse battery staple",
    })).not.toBeNull();
    await kernel.db.query(
      `UPDATE auth_invitations SET expires_at = $1 WHERE id = $2`,
      ["2020-01-01T00:00:00.000Z", waiting.invite.id],
    );

    const listed = (await kernel.listTeams(tenantOwner)).find((item) => item.id === team.id)!;
    expect(listed.invitations.map((invite) => invite.status).sort()).toEqual([
      "expired",
      "joined",
      "revoked",
      "waiting",
    ]);
    expect(JSON.stringify(listed.invitations)).not.toContain("activationToken");
    expect(JSON.stringify(listed.invitations)).not.toContain("token_hash");
  });

  it("names the visible team that already owns a live invitation", async () => {
    const support = await kernel.createTeam(tenantOwner, { name: "Support" });
    const sales = await kernel.createTeam(tenantOwner, { name: "Sales" });
    await kernel.inviteTeamMember(tenantOwner, support.id, {
      email: "pending@acme.test",
      role: "member",
    });

    await expect(kernel.inviteTeamMember(tenantOwner, sales.id, {
      email: "PENDING@acme.test",
      role: "member",
    })).rejects.toMatchObject({
      name: "BadRequestError",
      message: "This email already has a live invitation pending for Support. Revoke it there or send a reminder instead of inviting again.",
    });
  });
});

describe("Teams v2 person access", () => {
  it("previews the blast radius, kills sessions, and optionally revokes created agent keys", async () => {
    const member = await teamWithMember("suspend@acme.test", "member");
    await kernel.db.query(
      `INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
      ["session-suspend", member.userId, new Date().toISOString(), "2099-01-01T00:00:00.000Z"],
    );
    await kernel.db.query(
      `INSERT INTO api_keys
         (id, key_hash, namespace, actor, role, status, created_at, created_by)
       VALUES ($1, $2, $3, $4, 'agent', 'active', $5, $6)`,
      [
        "agent-created-by-member",
        "agent-created-by-member-hash",
        member.namespace,
        "support-agent",
        new Date().toISOString(),
        "suspend@acme.test",
      ],
    );
    await kernel.db.query(
      `INSERT INTO api_keys
         (id, key_hash, namespace, actor, role, status, created_at, created_by, custodian_user_id)
       VALUES ('agent-assigned-to-member', 'agent-assigned-hash', $1, 'assigned-agent',
               'agent', 'active', $2, 'admin@acme.test', $3)`,
      [member.namespace, new Date().toISOString(), member.userId],
    );
    await kernel.db.query(
      `INSERT INTO agent_key_handoffs
         (id, recipient_user_id, assigned_by_user_id, namespace, actor, agent_access_level,
          agent_can_write, claim_expires_at, idempotency_key, request_fingerprint, status, created_at)
       VALUES ('pending-for-member', $1, $1, $2, 'pending-agent', 'member', TRUE,
               '2099-01-01T00:00:00.000Z', 'pending-suspend', 'fingerprint', 'pending', $3)`,
      [member.userId, member.namespace, new Date().toISOString()],
    );

    const impact = await kernel.personAccessImpact(tenantOwner, member.userId);
    expect(impact).toMatchObject({
      activeSessions: 1,
      createdAgentKeys: 1,
      protected: false,
      teams: [{ id: member.teamId, name: "Platform" }],
    });

    const suspended = await kernel.changePersonAccessState(tenantOwner, member.userId, {
      status: "disabled",
      revokeCreatedKeys: true,
      reason: "Leave of absence",
    });
    expect(suspended.status).toBe("disabled");
    expect(suspended.activeSessions).toBe(0);
    expect(suspended.createdAgentKeys).toBe(0);
    expect((await kernel.db.query(`SELECT status FROM api_keys WHERE id = $1`, [
      "agent-created-by-member",
    ])).rows).toEqual([{ status: "revoked" }]);
    expect((await kernel.db.query(
      `SELECT status FROM api_keys WHERE id = 'agent-assigned-to-member'`,
    )).rows).toEqual([{ status: "revoked" }]);
    expect((await kernel.db.query(
      `SELECT status FROM agent_key_handoffs WHERE id = 'pending-for-member'`,
    )).rows).toEqual([{ status: "revoked" }]);

    const reinstated = await kernel.changePersonAccessState(tenantOwner, member.userId, {
      status: "active",
    });
    expect(reinstated.status).toBe("active");
  });

  it("protects owners, self, and sibling users from suspension", async () => {
    const ownerId = await seedUser("protected-owner@acme.test", "acme", "owner");
    await expect(kernel.changePersonAccessState(tenantOwner, ownerId, {
      status: "disabled",
    })).rejects.toThrow(/protected/i);

    const selfId = await seedUser("self-member@acme.test", "acme", "member");
    const selfIdentity = await issue("acme", "self-member@acme.test", "admin", root);
    await expect(kernel.changePersonAccessState(selfIdentity, selfId, {
      status: "disabled",
    })).rejects.toThrow(/own access/i);

    const siblingId = await seedUser("hidden@globex.test", "globex", "member");
    await expect(kernel.personAccessImpact(tenantOwner, siblingId))
      .rejects.toThrow(/no visible person/i);
  });
});

describe("human-only team directory", () => {
  it("does not query agent badges", async () => {
    await seedUser("directory-human@acme.test", "acme/platform", "member");
    const agentList = vi.spyOn(kernel.auth, "list")
      .mockRejectedValue(new Error("agent directory unavailable"));

    const directory = await kernel.teamDirectory(tenantOwner);

    expect(directory.users.map((user) => user.email)).toContain("directory-human@acme.test");
    expect(directory).not.toHaveProperty("badges");
    expect(directory.accessModel.owner).toContain("roles:write");
    expect(agentList).not.toHaveBeenCalled();
    agentList.mockRestore();
  });

  it("denies member and agent identities at the kernel boundary", async () => {
    const member = await issue("acme", "member@acme.test", "member", root);
    const agent = await issue("acme", "machine@acme.test", "agent", root);

    await expect(kernel.teamDirectory(member)).rejects.toMatchObject({ name: "AuthzError" });
    await expect(kernel.teamDirectory(agent)).rejects.toMatchObject({ name: "AuthzError" });
  });
});

describe("team invitation acceptance", () => {
  it("prevents an admin from creating a root invitation", async () => {
    const team = await kernel.createTeam(tenantOwner, { name: "Admin Invites" });

    await expect(kernel.inviteTeamMember(tenantAdmin, team.id, {
      email: "forged-owner@acme.test",
      role: "root",
    })).rejects.toMatchObject({ name: "AuthzError" });

    const invitation = await kernel.db.query(
      `SELECT id FROM auth_invitations WHERE email = $1`,
      ["forged-owner@acme.test"],
    );
    expect(invitation.rows).toEqual([]);
  });

  it("atomically creates the human and selected-team membership", async () => {
    const team = await kernel.createTeam(tenantOwner, { name: "Invited Team" });
    const invitations = new InvitationStore(kernel.db);
    const issued = await kernel.inviteTeamMember(tenantOwner, team.id, {
      email: "invitee@acme.test",
      role: "member",
      // Runtime callers may send extra JSON fields. D9 requires the kernel to
      // ignore/reject this forged sibling namespace and resolve by team id.
      namespace: "globex/forged",
    } as { email: string; role: HumanRole });
    expect(issued.invite.namespace).toBe(team.namespace);

    const accepted = await invitations.accept({
      token: issued.activationToken,
      password: "correct horse battery staple",
    });
    expect(accepted).not.toBeNull();

    const durable = await kernel.db.query(
      `SELECT u.email, u.namespace, u.role, tm.team_id
         FROM users u
         JOIN org_team_members tm ON tm.user_id = u.id
        WHERE u.email = $1`,
      ["invitee@acme.test"],
    );
    expect(durable.rows).toEqual([{
      email: "invitee@acme.test",
      namespace: team.namespace,
      role: "member",
      team_id: team.id,
    }]);

    expect(await invitations.accept({
      token: issued.activationToken,
      password: "correct horse battery staple",
    })).toBeNull();
    const count = await kernel.db.query(
      `SELECT COUNT(*)::int AS count
         FROM org_team_members tm
         JOIN users u ON u.id = tm.user_id
        WHERE u.email = $1`,
      ["invitee@acme.test"],
    );
    expect(count.rows).toEqual([{ count: 1 }]);
  });

  it("keeps backward-compatible non-team invitations out of team membership", async () => {
    const invitations = new InvitationStore(kernel.db);
    const issued = await invitations.create({
      email: "legacy@acme.test",
      namespace: "acme/legacy",
      role: "member",
    }, tenantOwner);

    const accepted = await invitations.accept({
      token: issued.activationToken,
      password: "correct horse battery staple",
    });
    expect(accepted).not.toBeNull();
    const membership = await kernel.db.query(
      `SELECT team_id FROM org_team_members WHERE user_id = $1`,
      [accepted!.id],
    );
    expect(membership.rows).toEqual([]);
  });
});
