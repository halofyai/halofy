/**
 * M10 Module C (D41, FR1) — the product role boundary.
 *
 * The ONE translation seam (`src/iam/product-roles.ts`): internal storage
 * keeps `owner`/`admin`/`auditor`/`member`, the public boundary exposes only
 * `root`/`admin`/`member`. Auditors surface as `member` plus an explicit
 * `audit:read` entitlement. The inverse direction never mints `auditor`, and
 * maps `root` -> `owner` only through the documented root-assignment route.
 *
 * The serialization checks boot the real console read models the way the
 * sibling console-api test does (real Kernel over in-memory PGlite, the
 * integrator-wired `listUsers` replicated off the `users` table) and assert
 * that no response carries `auditor` (or raw `owner`) as a role VALUE.
 *
 * Hermetic: in-memory PGlite, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import {
  PRODUCT_HUMAN_ROLES,
  AUDIT_READ_ENTITLEMENT,
  isProductHumanRole,
  toProductRole,
  productRoleLabel,
  fromProductRole,
  toPublicUser,
  ProductRoleError,
} from "../src/iam/product-roles.js";
import {
  people,
  teamDirectory,
  type KernelSlice,
  type ConsoleUser,
} from "../src/console/api.js";
import { listTeams } from "../src/console/teams.js";

// ---------------------------------------------------------------------------
// Pure mapping matrix (no kernel)
// ---------------------------------------------------------------------------

describe("toProductRole - internal -> product boundary", () => {
  it("maps the four internal human roles", () => {
    expect(toProductRole("owner")).toEqual({ role: "root", entitlements: [] });
    expect(toProductRole("admin")).toEqual({ role: "admin", entitlements: [] });
    expect(toProductRole("member")).toEqual({ role: "member", entitlements: [] });
    expect(toProductRole("auditor")).toEqual({
      role: "member",
      entitlements: [AUDIT_READ_ENTITLEMENT],
    });
  });

  it("known roles carry no note; unknown values fail CLOSED to member + note", () => {
    for (const known of ["owner", "admin", "auditor", "member"]) {
      expect(toProductRole(known).note).toBeUndefined();
    }
    for (const unknown of ["agent", "superuser", "", "OWNER"]) {
      const view = toProductRole(unknown);
      expect(view.role).toBe("member"); // least privilege, never wider
      expect(view.entitlements).toEqual([]);
      expect(view.note).toContain("fail-closed");
    }
  });

  it("exposes exactly three product human roles", () => {
    expect(PRODUCT_HUMAN_ROLES).toEqual(["root", "admin", "member"]);
    expect(isProductHumanRole("root")).toBe(true);
    expect(isProductHumanRole("admin")).toBe(true);
    expect(isProductHumanRole("member")).toBe(true);
    expect(isProductHumanRole("owner")).toBe(false);
    expect(isProductHumanRole("auditor")).toBe(false);
    expect(isProductHumanRole("agent")).toBe(false);
  });

  it("labels are single plain words", () => {
    expect(productRoleLabel("root")).toBe("Root");
    expect(productRoleLabel("admin")).toBe("Admin");
    expect(productRoleLabel("member")).toBe("Member");
  });
});

describe("fromProductRole - product input -> internal storage value", () => {
  it("admin and member pass through", () => {
    expect(fromProductRole("admin")).toBe("admin");
    expect(fromProductRole("member")).toBe("member");
  });

  it("NEVER mints 'auditor'", () => {
    expect(() => fromProductRole("auditor")).toThrow(/audit:read/);
    // Even the root-assignment route cannot resurrect the auditor role.
    expect(() => fromProductRole("auditor", { rootAssignment: true })).toThrow(
      ProductRoleError,
    );
  });

  it("rejects raw 'owner' as a public input", () => {
    expect(() => fromProductRole("owner")).toThrow(ProductRoleError);
    expect(() => fromProductRole("owner", { rootAssignment: true })).toThrow(
      ProductRoleError,
    );
  });

  it("maps root -> owner ONLY on the documented root-assignment route", () => {
    expect(() => fromProductRole("root")).toThrow(/root-assignment/);
    expect(fromProductRole("root", { rootAssignment: true })).toBe("owner");
  });

  it("rejects garbage and maps to a 400-shaped error", () => {
    for (const junk of ["agent", "sudo", "", "Root"]) {
      try {
        fromProductRole(junk);
        expect.unreachable(`'${junk}' must not map to an internal role`);
      } catch (err) {
        expect((err as Error).name).toBe("BadRequestError");
      }
    }
  });
});

describe("toPublicUser", () => {
  const base = {
    id: "u1",
    email: "a@acme.test",
    namespace: "acme",
    role: "auditor",
    status: "active",
    createdAt: "2026-07-24T00:00:00.000Z",
  };

  it("translates the role, attaches entitlements, preserves everything else", () => {
    const pub = toPublicUser(base);
    expect(pub.role).toBe("member");
    expect(pub.entitlements).toEqual([AUDIT_READ_ENTITLEMENT]);
    expect(pub.id).toBe("u1");
    expect(pub.email).toBe("a@acme.test");
    expect(pub.namespace).toBe("acme");
    expect(pub.status).toBe("active");
    expect(pub.createdAt).toBe(base.createdAt);
  });

  it("omits the entitlements field when there are none, and never mutates input", () => {
    const owner = { ...base, role: "owner" };
    const pub = toPublicUser(owner);
    expect(pub.role).toBe("root");
    expect("entitlements" in pub).toBe(false);
    expect(owner.role).toBe("owner"); // input untouched (internal record)
    expect(base.role).toBe("auditor");
  });
});

// ---------------------------------------------------------------------------
// Serialization points — real console read models over a real kernel
// ---------------------------------------------------------------------------

let kernel: Kernel;
let slice: KernelSlice;
let root: Identity; // internal owner @ "" (bootstrap key)
let orgOwner: Identity; // internal owner @ org

/** Insert a human user row directly (same idiom as console-api.test.ts). */
async function seedUser(
  email: string,
  namespace: string,
  role: string,
): Promise<string> {
  const id = ulid();
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5)`,
    [id, email, namespace, role, new Date().toISOString()],
  );
  return id;
}

/** The integrator-wired roster, replicated off `users` (sibling-test idiom). */
async function listUsers(identity: Identity): Promise<ConsoleUser[]> {
  let where = "TRUE";
  const params: string[] = [];
  if (identity.namespace !== "") {
    const parts = identity.namespace.split("/").filter((p) => p.length > 0);
    const ancestors: string[] = [];
    for (let i = 1; i <= parts.length; i++) ancestors.push(parts.slice(0, i).join("/"));
    const inList = ancestors.map((_, i) => `$${i + 1}`).join(", ");
    params.push(...ancestors);
    const likeParam = `$${params.length + 1}`;
    const escaped = identity.namespace.replace(/[\\%_]/g, (c) => `\\${c}`);
    params.push(escaped + "/%");
    where = `(namespace IN (${inList}) OR namespace LIKE ${likeParam} ESCAPE '\\')`;
  }
  const res = await kernel.db.query(
    `SELECT id, email, namespace, role, status, created_at FROM users WHERE ${where} ORDER BY email`,
    params,
  );
  return (res.rows as Record<string, unknown>[]).map((r) => ({
    id: r.id as string,
    email: r.email as string,
    namespace: r.namespace as string,
    role: r.role as string,
    status: r.status as string,
    createdAt:
      r.created_at instanceof Date
        ? r.created_at.toISOString()
        : new Date(r.created_at as string).toISOString(),
  }));
}

const ROLE_VALUE_AUDITOR = /"role"\s*:\s*"auditor"/;
const ROLE_VALUE_OWNER = /"role"\s*:\s*"owner"/;

describe("console serialization points return root/admin/member only", () => {
  let auditorUserId: string;
  let ownerUserId: string;

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
    const orgKey = await kernel.auth.issueKey("org", "owner:org", "owner", root);
    const resolvedOrg = await kernel.auth.resolve(orgKey.plaintext);
    if (!resolvedOrg) throw new Error("org owner failed to resolve");
    orgOwner = resolvedOrg;

    slice = {
      db: kernel.db,
      audit: kernel.audit,
      auth: { list: (id) => kernel.auth.list(id) },
      sources: { list: (ns, global) => kernel.sources.list(ns, global) },
      budget: { monthToDateUsd: (ns) => kernel.budget.monthToDateUsd(ns) },
      tenants: { resolveTenant: (ns) => kernel.tenants.resolveTenant(ns) },
      listUsers,
      getPolicy: (ns) => kernel.getPolicy(ns),
    };

    // One user per internal role, all inside the org subtree.
    ownerUserId = await seedUser("owner@org.example", "org", "owner");
    await seedUser("admin@org.example", "org/support", "admin");
    auditorUserId = await seedUser("compliance@org.example", "org", "auditor");
    await seedUser("rep@org.example", "org/support", "member");

    // A team with the owner + auditor as members (member-detail surface).
    const teamId = ulid();
    const now = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
       VALUES ($1, 'org', 'Org Core', '', 'test', $2)`,
      [teamId, now],
    );
    for (const userId of [ownerUserId, auditorUserId]) {
      await kernel.db.query(
        `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
         VALUES ($1, $2, 'test', $3)`,
        [teamId, userId, now],
      );
    }
  }, 120_000);

  afterAll(async () => {
    await kernel.close();
  });

  it("GET people: every human role is root/admin/member; auditor surfaces as member + audit:read", async () => {
    const p = await people(slice, orgOwner);
    expect(p.users.length).toBeGreaterThanOrEqual(4);
    for (const u of p.users) {
      expect(["root", "admin", "member"]).toContain(u.role);
    }
    const owner = p.users.find((u) => u.email === "owner@org.example")!;
    expect(owner.role).toBe("root");
    const auditor = p.users.find((u) => u.email === "compliance@org.example")!;
    expect(auditor.role).toBe("member");
    expect(
      (auditor as { entitlements?: readonly string[] }).entitlements,
    ).toEqual([AUDIT_READ_ENTITLEMENT]);
  });

  it("people users contain no 'auditor' or raw 'owner' role value anywhere in the payload", async () => {
    const p = await people(slice, orgOwner);
    const wire = JSON.stringify(p.users);
    expect(wire).not.toMatch(ROLE_VALUE_AUDITOR);
    expect(wire).not.toMatch(ROLE_VALUE_OWNER);
    expect(wire).not.toContain('"auditor"');
  });

  it("team directory users carry product roles only", async () => {
    const d = await teamDirectory(slice, orgOwner);
    for (const u of d.users) {
      expect(["root", "admin", "member"]).toContain(u.role);
    }
    const wire = JSON.stringify(d.users);
    expect(wire).not.toMatch(ROLE_VALUE_AUDITOR);
    expect(wire).not.toMatch(ROLE_VALUE_OWNER);
  });

  it("team member detail carries product roles; auditor member gains audit:read", async () => {
    const teams = await listTeams(
      { db: kernel.db, audit: kernel.audit, listUsers },
      orgOwner,
    );
    const team = teams.find((t) => t.name === "Org Core")!;
    expect(team.members).toHaveLength(2);
    const ownerMember = team.members.find((m) => m.userId === ownerUserId)!;
    expect(ownerMember.role).toBe("root");
    expect(ownerMember.entitlements).toBeUndefined();
    const auditorMember = team.members.find((m) => m.userId === auditorUserId)!;
    expect(auditorMember.role).toBe("member");
    expect(auditorMember.entitlements).toEqual([AUDIT_READ_ENTITLEMENT]);

    const wire = JSON.stringify(teams);
    expect(wire).not.toMatch(ROLE_VALUE_AUDITOR);
    expect(wire).not.toMatch(ROLE_VALUE_OWNER);
    expect(wire).not.toContain('"auditor"');
  });
});
