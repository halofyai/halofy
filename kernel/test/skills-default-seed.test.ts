/**
 * Default skill library seeding (src/skills/defaults.ts).
 *
 * The curated halomem-skills pack ships as product defaults: every newly
 * provisioned tenant root gets all 29 entries registered at its root
 * namespace — approved, vetted (one synthetic passing run per skill for
 * audit continuity), and marked created_by='system-default-skills'. The
 * ancestor-prefix ACL makes them visible/invocable org-wide; a team can
 * shadow any default by redefining the same skill_key, and a re-seed never
 * clobbers anything. Hermetic: in-memory PGlite, zero network.
 */

import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { DEFAULT_SKILLS } from "../src/skills/default-content.js";
import {
  DEFAULT_SKILL_ACTOR,
  seedDefaultSkills,
} from "../src/skills/defaults.js";
import { SkillStore } from "../src/skills/store.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let store: SkillStore;

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  // The seeding store deliberately has no writeMemory seam — provisioning
  // must not push 29 extraction writes through the write path.
  store = new SkillStore({ db: kernel.db, audit: kernel.audit });
});

afterAll(async () => {
  await kernel.close();
});

async function currentSkillsAt(namespace: string) {
  const res = await kernel.db.query(
    `SELECT * FROM skills WHERE namespace = $1 AND t_valid_to IS NULL`,
    [namespace],
  );
  return res.rows as Array<Record<string, unknown>>;
}

describe("default skill library seeding", () => {
  it("bundles exactly the 29 curated pack entries", () => {
    expect(DEFAULT_SKILLS).toHaveLength(29);
    expect(new Set(DEFAULT_SKILLS.map((s) => s.skillKey)).size).toBe(29);
    for (const entry of DEFAULT_SKILLS) {
      expect(entry.name.length).toBeGreaterThan(0);
      expect(entry.description.length).toBeGreaterThan(0);
      expect(entry.definition.length).toBeGreaterThan(0);
    }
  });

  it("seeds a fresh tenant root: 29 skills, approved + vetted, marker actor", async () => {
    const result = await seedDefaultSkills(store, kernel.db, "seedorg");
    expect(result).toEqual({ seeded: 29, skipped: 0 });

    const rows = await currentSkillsAt("seedorg");
    expect(rows).toHaveLength(29);
    for (const row of rows) {
      expect(row.approval_status).toBe("approved");
      expect(row.approved_by).toBe(DEFAULT_SKILL_ACTOR);
      expect(row.vetting_status).toBe("vetted");
      expect(row.safety_score).toBe(100);
      expect(row.created_by).toBe(DEFAULT_SKILL_ACTOR);
      expect(row.status).toBe("active");
    }
    // One synthetic passing vetting run per seeded skill (audit continuity).
    const runs = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM skill_vetting_runs
        WHERE namespace = 'seedorg' AND ran_by = $1 AND status = 'passed'`,
      [DEFAULT_SKILL_ACTOR],
    );
    expect(Number(runs.rows[0].n)).toBe(29);
  });

  it("a descendant team namespace sees, invokes, and downloads the defaults", async () => {
    const teamAgent: Identity = {
      keyId: "k-agent",
      namespace: "seedorg/team-eng",
      actor: "bot",
      role: "agent",
    };
    const visible = await kernel.listSkills(teamAgent);
    expect(visible.filter((s) => s.namespace === "seedorg")).toHaveLength(29);

    const invoke = await kernel.invokeSkill(teamAgent, "halomem-recall");
    expect(invoke.allowed).toBe(true);
    expect(invoke.reason).toBe("vetted");
    expect(invoke.skill?.namespace).toBe("seedorg");

    const recall = visible.find((s) => s.skillKey === "halomem-recall")!;
    const exported = await kernel.exportSkill(teamAgent, recall.id);
    expect(exported.filename).toBe("halomem-recall.md");
    expect(exported.content).toContain("name: ");
    expect(exported.content).toContain("# Recall");
  });

  it("is idempotent: a second seed skips all 29 and supersedes nothing", async () => {
    const before = await currentSkillsAt("seedorg");
    const result = await seedDefaultSkills(store, kernel.db, "seedorg");
    expect(result).toEqual({ seeded: 0, skipped: 29 });
    const after = await currentSkillsAt("seedorg");
    expect(after.map((r) => r.id).sort()).toEqual(before.map((r) => r.id).sort());
    // No chain rows were closed: still exactly 29 rows total at the root.
    const total = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM skills WHERE namespace = 'seedorg'`,
    );
    expect(Number(total.rows[0].n)).toBe(29);
  });

  it("a team's own redefinition of a default survives a re-seed (nearest wins)", async () => {
    const teamAdmin: Identity = {
      keyId: "k-admin",
      namespace: "seedorg/team-eng",
      actor: "ada",
      role: "admin",
    };
    const own = await kernel.registerSkill(teamAdmin, {
      skillKey: "halomem-recall",
      name: "halomem-recall",
      description: "Team-specific recall guidance.",
      definition: "team-eng recall: always search the team-eng namespace first",
    });

    const reseed = await seedDefaultSkills(store, kernel.db, "seedorg");
    expect(reseed).toEqual({ seeded: 0, skipped: 29 });

    // The team row is untouched and shadows the root default on invoke.
    const teamAgent: Identity = {
      keyId: "k-agent",
      namespace: "seedorg/team-eng",
      actor: "bot",
      role: "agent",
    };
    const invoke = await kernel.invokeSkill(teamAgent, "halomem-recall");
    expect(invoke.skill?.id).toBe(own.skill.id);
    expect(invoke.skill?.namespace).toBe("seedorg/team-eng");
    expect(invoke.skill?.definition).toContain("team-eng recall");
    expect(invoke.allowed).toBe(false); // the team's own version is unvetted
    expect(invoke.reason).toBe("unvetted");
    // The root default itself is still current.
    const rootRows = await currentSkillsAt("seedorg");
    expect(rootRows).toHaveLength(29);
  });

  it("signup integration: complete() leaves the new tenant with 29 defaults", async () => {
    const issued = await kernel.organizationSignup.issue("founder@seeded.test");
    const completion = await kernel.organizationSignup.complete(
      issued.token,
      "Seeded Org",
    );
    expect(completion).not.toBeNull();
    const rows = await currentSkillsAt(completion!.organization.id);
    expect(rows).toHaveLength(29);
    for (const row of rows) {
      expect(row.approval_status).toBe("approved");
      expect(row.vetting_status).toBe("vetted");
      expect(row.created_by).toBe(DEFAULT_SKILL_ACTOR);
    }
  });
});
