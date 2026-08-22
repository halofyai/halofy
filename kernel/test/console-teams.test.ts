/**
 * S13 teams — namespace-backed teams + explicit membership (migration 037).
 *
 * Two sibling subtrees share ONE kernel: an admin at `org/support` creates
 * teams under its own namespace only (derived server-side — D9), sees only its
 * subtree's teams, and can only add people its roster ACL lets it see. A
 * sibling admin must neither see nor mutate the team (invisible, not merely
 * forbidden). Every mutation writes an audit row (D4).
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import { teamSlug } from "../src/console/teams.js";

let kernel: Kernel;
let root: Identity;
let supportAdmin: Identity;
let salesAdmin: Identity;
let supportAuditor: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

/** Insert a human user row directly (the invite flow is exercised elsewhere). */
async function seedUser(
  email: string,
  namespace: string,
  role: string,
  displayName = "Member",
  avatar: string | null = null,
): Promise<string> {
  const id = ulid();
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at, display_name, avatar)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5, $6, $7)`,
    [id, email, namespace, role, new Date().toISOString(), displayName, avatar],
  );
  return id;
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;

  supportAdmin = await issue("org/support", "admin:support", "admin");
  salesAdmin = await issue("org/sales", "admin:sales", "admin");
  supportAuditor = await issue("org/support", "auditor:support", "auditor");

  await seedUser(
    "ana@org.co",
    "org/support",
    "member",
    "Ana Ortiz",
    "data:image/png;base64,iVBORw0KGgo=",
  );
  await seedUser("ben@org.co", "org/support/triage", "member");
  await seedUser("sal@org.co", "org/sales", "member");
});

afterAll(async () => {
  await kernel.close();
});

describe("createTeam", () => {
  it("derives the namespace from the caller + slug(name), never the body", async () => {
    const team = await kernel.createTeam(supportAdmin, {
      name: "Support EU",
      description: "EU tickets",
    });
    expect(team.namespace).toBe("org/support/support-eu");
    expect(team.name).toBe("Support EU");
    expect(team.description).toBe("EU tickets");
    expect(team.createdBy).toBe(supportAdmin.actor);
    expect(team.members).toEqual([]);
  });

  it("rejects a duplicate namespace as a 400-class error", async () => {
    await expect(
      kernel.createTeam(supportAdmin, { name: "support   EU" }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("rejects a name with no usable characters", async () => {
    await expect(
      kernel.createTeam(supportAdmin, { name: "!!!" }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("denies an auditor (read-only everywhere)", async () => {
    await expect(
      kernel.createTeam(supportAuditor, { name: "Sneaky" }),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("slug derivation is deterministic", () => {
    expect(teamSlug("Support EU")).toBe("support-eu");
    expect(teamSlug("  Growth -- & Ops  ")).toBe("growth-ops");
    expect(teamSlug("!!!")).toBe("");
  });
});

describe("listTeams scoping", () => {
  it("a sibling admin sees nothing; the creator and root see the team", async () => {
    const mine = await kernel.listTeams(supportAdmin);
    expect(mine.map((t) => t.namespace)).toContain("org/support/support-eu");

    const sibling = await kernel.listTeams(salesAdmin);
    expect(sibling).toEqual([]);

    const all = await kernel.listTeams(root);
    expect(all.map((t) => t.namespace)).toContain("org/support/support-eu");
  });
});

describe("membership", () => {
  it("adds a visible person by email and returns the refreshed roster", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    const teams = await kernel.addTeamMember(supportAdmin, team.id, "Ana@org.co");
    const updated = teams.find((t) => t.id === team.id);
    expect(updated?.members.map((m) => m.email)).toEqual(["ana@org.co"]);

    // Descendant-namespace users are visible too. Seed it before the new name
    // assertion so a RED failure cannot poison later stateful roster cases.
    await kernel.addTeamMember(supportAdmin, team.id, "ben@org.co");
    expect(updated?.members[0]).toMatchObject({
      email: "ana@org.co",
      displayName: "Ana Ortiz",
      avatar: "data:image/png;base64,iVBORw0KGgo=",
      status: "active",
    });
    const after = (await kernel.listTeams(supportAdmin)).find((t) => t.id === team.id);
    expect(after?.members).toHaveLength(2);
  });

  it("rejects a person outside the caller's roster ACL", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    await expect(
      kernel.addTeamMember(supportAdmin, team.id, "sal@org.co"),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("rejects a duplicate membership", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    await expect(
      kernel.addTeamMember(supportAdmin, team.id, "ana@org.co"),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("a sibling admin cannot see or mutate the team (no existence oracle)", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    await expect(
      kernel.addTeamMember(salesAdmin, team.id, "sal@org.co"),
    ).rejects.toMatchObject({
      name: "BadRequestError",
      message: expect.stringContaining("no team"),
    });
    await expect(
      kernel.removeTeamMember(salesAdmin, team.id, "whatever"),
    ).rejects.toMatchObject({
      name: "BadRequestError",
      message: expect.stringContaining("no team"),
    });
  });

  it("denies an auditor mutation", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    await expect(
      kernel.addTeamMember(supportAuditor, team.id, "ana@org.co"),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("removes a member (idempotent on a second call)", async () => {
    const [team] = await kernel.listTeams(supportAdmin);
    const ana = team.members.find((m) => m.email === "ana@org.co");
    expect(ana).toBeDefined();
    const teams = await kernel.removeTeamMember(supportAdmin, team.id, ana!.userId);
    const updated = teams.find((t) => t.id === team.id);
    expect(updated?.members.map((m) => m.email)).toEqual(["ben@org.co"]);
    // Second removal of the same user is a no-op, not an error.
    await kernel.removeTeamMember(supportAdmin, team.id, ana!.userId);
  });

  it("auditor may still read the roster", async () => {
    const teams = await kernel.listTeams(supportAuditor);
    expect(teams.map((t) => t.namespace)).toContain("org/support/support-eu");
  });
});

describe("audit (D4)", () => {
  it("every team mutation wrote an audit row", async () => {
    const res = await kernel.db.query(
      `SELECT purpose, result, namespace FROM audit_log
        WHERE purpose IN ('console-team-create','console-team-member-add','console-team-member-remove')`,
    );
    const purposes = res.rows.map((r) => String(r.purpose));
    expect(purposes).toContain("console-team-create");
    expect(purposes).toContain("console-team-member-add");
    expect(purposes).toContain("console-team-member-remove");
    for (const row of res.rows) {
      expect(String(row.namespace)).toMatch(/^org\/support\//);
      expect(String(row.result)).toBe("ok");
    }
  });
});

describe("setup checklist integration", () => {
  it("counts console-created teams for the team-space step (the S13/S1 split regression)", async () => {
    // Teams were created above through the console path (org_teams only).
    // The standing checklist must see THOSE teams — before v69 it counted
    // the legacy verified-setup table and reported "no teams exist yet"
    // next to a Teams page listing five.
    const view = await kernel.setupChecklist(supportAdmin);
    expect(view.organization).toBe("org");
    const teamSpace = view.steps.find((s) => s.id === "team-space");
    expect(teamSpace?.state).toBe("complete");
    expect(teamSpace?.evidence).toMatch(/^\d+ teams?$/);
  });
});
