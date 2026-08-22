/**
 * Organization attachment + adoption — the orphan-namespace repair.
 *
 * The halofy production deployment was built by a PLATFORM-root operator
 * (namespace ""): every team, key, and user it created landed at a TOP-LEVEL
 * namespace next to the org instead of inside it, so the per-org setup
 * checklist reported a fully-wired org as empty. Three fixes under test:
 *
 *  1. createTeam / user create / invitations from root now attach to the sole
 *     tenant (and refuse to guess between several).
 *  2. `org adopt` re-roots pre-fix orphan subtrees under the tenant.
 *  3. The checklist's team probe honors the `organization_namespace` label.
 *
 * Test ORDER matters: the zero-tenant legacy behavior is asserted before the
 * first tenant is registered on the shared kernel.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import { adoptNamespaces } from "../src/tenancy/adopt.js";

let kernel: Kernel;
let root: Identity;

async function seedUser(email: string, namespace: string, role: string): Promise<string> {
  const id = ulid();
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5)`,
    [id, email, namespace, role, new Date().toISOString()],
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
  // The checklist teammate probe counts users; the root operator exists.
  await seedUser("root@halofy.ai", "", "owner");
});

afterAll(async () => {
  await kernel.close();
});

describe("createTeam attachment", () => {
  it("zero tenants (fresh install): root still mints the legacy top-level slug", async () => {
    const team = await kernel.createTeam(root, { name: "Pre Org" });
    expect(team.namespace).toBe("pre-org");
  });

  it("one tenant: a root-created team lands INSIDE it, labeled", async () => {
    await kernel.registerTenant({ id: "halofy", name: "Halofy" }, root);
    const team = await kernel.createTeam(root, { name: "Growth" });
    expect(team.namespace).toBe("halofy/growth");
    const row = await kernel.db.query(
      `SELECT organization_namespace FROM org_teams WHERE namespace = 'halofy/growth'`,
    );
    expect(row.rows[0]?.organization_namespace).toBe("halofy");
  });

  it("several tenants: root must not guess - 400-class refusal", async () => {
    await kernel.registerTenant({ id: "acme", name: "Acme" }, root);
    await expect(
      kernel.createTeam(root, { name: "Ambiguous" }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
    await kernel.db.query(`DELETE FROM tenants WHERE id = 'acme'`);
  });
});

describe("root-minted humans attach to the sole tenant", () => {
  it("users.create from root prefixes a bare namespace", async () => {
    const user = await kernel.users.create(
      { email: "eve@halofy.ai", namespace: "growth", role: "member" },
      root,
    );
    expect(user.namespace).toBe("halofy/growth");
  });

  it("an explicit tenant-rooted namespace is kept as-is", async () => {
    const user = await kernel.users.create(
      { email: "dana@halofy.ai", namespace: "halofy/ops", role: "member" },
      root,
    );
    expect(user.namespace).toBe("halofy/ops");
  });

  it("invitations from root prefix a bare namespace", async () => {
    const issued = await kernel.invitations.create(
      { email: "newbie@halofy.ai", namespace: "design", role: "member" },
      root,
    );
    expect(issued.invite.namespace).toBe("halofy/design");
  });
});

describe("org adopt", () => {
  beforeAll(async () => {
    // Fabricate the stranded production shape: an orphan subtree that a
    // pre-fix console minted next to the tenant instead of inside it.
    const now = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, organization_namespace, name, description, created_by, created_at)
       VALUES ($1, 'sales-team', '', 'Sales team', '', 'root@halofy.ai', $2)`,
      [ulid(), now],
    );
    await seedUser("pratz@halofy.ai", "sales-team", "admin");
    await kernel.auth.issueKey("sales-team", "hermes-agent", "agent", root);
    // A historical audit row under the orphan namespace — adoption must
    // leave it exactly where history happened (D4).
    await kernel.audit.append({
      ts: now,
      actor: "pratz@halofy.ai",
      agentId: "test",
      op: "write",
      memoryId: null,
      namespace: "sales-team",
      purpose: "orphan-era-write",
      result: "ok",
      detail: "pre-adoption history",
    });
    await kernel.db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          assertion_time, t_valid_from, status)
       VALUES ($1, 'sales-team/deals', 'team', 'L2', 'test', 'orphan fact', 'fact', 0.9,
          $2, $2, 'active')`,
      [ulid(), now],
    );
  });

  it("dry run counts without writing", async () => {
    const report = await kernel.adoptOrganizationNamespaces(
      { tenant: "halofy", namespaces: ["sales-team"], dryRun: true },
      root,
    );
    expect(report.dryRun).toBe(true);
    expect(report.total).toBeGreaterThanOrEqual(4);
    const still = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM org_teams WHERE namespace = 'sales-team'`,
    );
    expect(Number(still.rows[0].n)).toBe(1);
  });

  it("moves the whole subtree in one transaction and labels the teams", async () => {
    const report = await kernel.adoptOrganizationNamespaces(
      { tenant: "halofy", namespaces: ["sales-team"] },
      root,
    );
    expect(report.dryRun).toBe(false);
    expect(report.total).toBeGreaterThanOrEqual(4);

    const team = await kernel.db.query(
      `SELECT namespace, organization_namespace FROM org_teams WHERE name = 'Sales team'`,
    );
    expect(team.rows[0]).toMatchObject({
      namespace: "halofy/sales-team",
      organization_namespace: "halofy",
    });

    const user = await kernel.db.query(
      `SELECT namespace FROM users WHERE email = 'pratz@halofy.ai'`,
    );
    expect(user.rows[0]?.namespace).toBe("halofy/sales-team");

    const key = await kernel.db.query(
      `SELECT namespace FROM api_keys WHERE actor = 'hermes-agent'`,
    );
    expect(key.rows[0]?.namespace).toBe("halofy/sales-team");

    const memory = await kernel.db.query(
      `SELECT namespace FROM memory_objects WHERE content = 'orphan fact'`,
    );
    expect(memory.rows[0]?.namespace).toBe("halofy/sales-team/deals");

    // Nothing else was dragged along.
    const strays = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM org_teams WHERE namespace = 'sales-team'`,
    );
    expect(Number(strays.rows[0].n)).toBe(0);
  });

  it("audit rows are never rewritten (D4) - and the adoption itself is audited", async () => {
    const moved = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM audit_log WHERE namespace LIKE 'halofy/sales-team%'`,
    );
    const original = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM audit_log WHERE namespace = 'sales-team'`,
    );
    // The pre-adoption key issuance audit row keeps its historical namespace.
    expect(Number(original.rows[0].n)).toBeGreaterThanOrEqual(1);
    expect(Number(moved.rows[0].n)).toBe(0);
    const adoptRow = await kernel.db.query(
      `SELECT result FROM audit_log WHERE purpose = 'org-adopt'`,
    );
    expect(adoptRow.rows.length).toBeGreaterThanOrEqual(1);
  });

  it("the checklist now counts the adopted org (the production regression)", async () => {
    const view = await kernel.setupChecklist(root);
    expect(view.organization).toBe("halofy");
    const byId = Object.fromEntries(view.steps.map((s) => [s.id, s]));
    expect(byId["team-space"]?.state).toBe("complete");
    expect(byId["badge"]?.state).toBe("complete");
    expect(byId["memory"]?.state).toBe("complete");
    expect(byId["team"]?.state).toBe("complete");
  });

  it("refuses a non-root caller, unknown tenants, and org-into-org merges", async () => {
    const scoped = await kernel.auth.issueKey("halofy", "scoped-owner", "owner", root);
    const scopedId = await kernel.auth.resolve(scoped.plaintext);
    await expect(
      kernel.adoptOrganizationNamespaces(
        { tenant: "halofy", namespaces: ["x"] },
        scopedId!,
      ),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      adoptNamespaces(kernel.db, { tenant: "nope", namespaces: ["x"] }),
    ).rejects.toMatchObject({ name: "AdoptError" });
    await kernel.registerTenant({ id: "acme2", name: "Acme 2" }, root);
    await expect(
      adoptNamespaces(kernel.db, { tenant: "halofy", namespaces: ["acme2"] }),
    ).rejects.toMatchObject({ name: "AdoptError" });
    await kernel.db.query(`DELETE FROM tenants WHERE id = 'acme2'`);
  });

  it("--root-sources moves platform-root source registrations and their documents", async () => {
    const sid = ulid();
    const now = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO sources (id, namespace, kind, config, created_at)
       VALUES ($1, '', 'filesystem', '{}', $2)`,
      [sid, now],
    );
    await kernel.db.query(
      `INSERT INTO source_documents (source_id, landing_namespace, document_key, content_hash, synced_at)
       VALUES ($1, '', 'doc-1', 'hash', $2)`,
      [sid, now],
    );
    const report = await kernel.adoptOrganizationNamespaces(
      { tenant: "halofy", namespaces: [], rootSources: true },
      root,
    );
    expect(report.rootSources).toBe(true);
    const src = await kernel.db.query(`SELECT namespace FROM sources WHERE id = $1`, [sid]);
    expect(src.rows[0]?.namespace).toBe("halofy");
    const doc = await kernel.db.query(
      `SELECT landing_namespace FROM source_documents WHERE source_id = $1`,
      [sid],
    );
    expect(doc.rows[0]?.landing_namespace).toBe("halofy");
  });

  it("the checklist team probe honors the organization_namespace label alone", async () => {
    // A team labeled for the org but NOT (yet) re-rooted under it — the
    // adopted-but-unmoved shape — must still satisfy the team-space step.
    await kernel.db.query(`UPDATE org_teams SET namespace = 'floating', organization_namespace = 'halofy' WHERE name = 'Sales team'`);
    await kernel.db.query(`DELETE FROM org_teams WHERE namespace LIKE 'halofy/%'`);
    const view = await kernel.setupChecklist(root);
    const teamSpace = view.steps.find((s) => s.id === "team-space");
    expect(teamSpace?.state).toBe("complete");
  });
});
