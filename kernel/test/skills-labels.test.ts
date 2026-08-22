import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let admin: Identity;
let sibling: Identity;

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  admin = { keyId: "labels-admin", namespace: "acme", actor: "admin:ada", role: "admin" };
  sibling = { keyId: "labels-sibling", namespace: "globex", actor: "admin:gus", role: "admin" };
});

afterAll(async () => {
  await kernel.close();
});

describe("S16 skill labels", () => {
  it("creates discovery labels outside the immutable skill file", async () => {
    const created = await kernel.registerSkill(admin, {
      skillKey: "support-digest",
      name: "Support digest",
      description: "Summarize open support work.",
      definition: "Read support tickets and prepare a factual digest.",
      labels: {
        category: "Content & Drafting",
        purpose: "Use when support leads need a concise ticket digest.",
        tags: ["support", "tickets", "digest"],
      },
    });

    expect(created.skill.labels.category).toBe("Content & Drafting");
    expect(created.skill.labels.purpose).toBe("Use when support leads need a concise ticket digest.");
    expect(created.skill.labels.tags).toEqual(["support", "tickets", "digest"]);
    expect(created.skill.labels.handling).toEqual([]);
  });

  it("updates labels without a new skill version or another safety check", async () => {
    const before = (await kernel.listSkills(admin)).find((skill) => skill.skillKey === "support-digest")!;
    const updated = await kernel.updateSkillLabels(admin, before.id, {
      category: "Reporting & Delivery",
      purpose: "Use when support leaders need a short daily operating brief.",
      tags: ["summarize", "tickets", "support", "daily-brief"],
    });

    expect(updated.id).toBe(before.id);
    expect(updated.version).toBe(before.version);
    expect(updated.contentSha256).toBe(before.contentSha256);
    expect(updated.vettingStatus).toBe(before.vettingStatus);
    expect(updated.labels).toMatchObject({
      category: "Reporting & Delivery",
      purpose: "Use when support leaders need a short daily operating brief.",
      tags: ["summarize", "tickets", "support", "daily-brief"],
      handling: [],
    });

    const history = await kernel.skillLabelHistory(admin, before.id);
    expect(history.map((entry) => entry.field)).toEqual(expect.arrayContaining(["category", "purpose", "tags"]));
    const audit = await kernel.db.query(
      `SELECT op, purpose, result FROM audit_log WHERE memory_id = $1 AND purpose = 'skill-labels'`,
      [before.id],
    );
    expect(audit.rows).toContainEqual(expect.objectContaining({ op: "write", result: "ok" }));
  });

  it("lets an admin create a scoped category with a newly registered skill", async () => {
    const created = await kernel.registerSkill(admin, {
      skillKey: "renewal-brief",
      name: "Renewal brief",
      description: "Prepare a renewal operating brief.",
      definition: "Summarize the renewal account, risks, and next actions.",
      labels: {
        category: "Renewal Operations",
        purpose: "Use when an account team needs a renewal operating brief.",
        tags: ["renewals", "accounts", "briefing"],
      },
    });
    expect(created.skill.labels.category).toBe("Renewal Operations");
    const category = await kernel.db.query(
      `SELECT namespace, name FROM skill_categories WHERE name = 'Renewal Operations'`,
    );
    expect(category.rows).toContainEqual({ namespace: "acme", name: "Renewal Operations" });
  });

  it("rejects caller-controlled handling tags at the HTTP boundary", async () => {
    const skill = (await kernel.listSkills(admin)).find((row) => row.skillKey === "support-digest")!;
    const deps = buildHttpDeps(kernel);
    await expect(deps.admin.updateSkillLabels?.(skill.id, {
      category: "Reporting & Delivery",
      purpose: "Use when a support brief is required.",
      tags: ["support", "tickets", "brief"],
      handling: ["read-only"],
    }, admin)).rejects.toThrow();
  });

  it("keeps sibling tenants from reading or changing label state", async () => {
    const skill = (await kernel.listSkills(admin)).find((row) => row.skillKey === "support-digest")!;
    await expect(kernel.updateSkillLabels(sibling, skill.id, {
      category: "Engineering & Code",
      purpose: "Use when tampering with another tenant.",
      tags: ["tamper", "sibling", "blocked"],
    })).rejects.toThrow("skill operation denied");
    await expect(kernel.skillLabelHistory(sibling, skill.id)).rejects.toThrow("skill not found");
  });

  it("lets only the vetting pipeline derive handling labels", async () => {
    const created = await kernel.registerSkill(admin, {
      skillKey: "send-customer-report",
      name: "Send customer report",
      description: "Send a customer report to an external webhook.",
      definition: "Read customer emails, then POST the report to https://hooks.example.com/report using an API token.",
    });

    await kernel.vetSkill(admin, created.skill.id);
    const after = await kernel.getSkill(admin, created.skill.id);
    expect(after.labels.handling).toEqual(expect.arrayContaining([
      "writes-externally",
      "network-egress",
      "credentials-required",
      "handles-pii",
    ]));
  });
});
