/**
 * M9 #9 (E19–E22) — company skill library, WIRED.
 *
 * The adversarial review found src/skills/ was dead code (no kernel field, no
 * route, no test). These tests pin the wiring through the Kernel surface:
 * E19 registration metadata flows through the write path, E20 vet / invoke /
 * override each audit, E21 ancestor-prefix ACL visibility, E22 unvetted
 * blocked absent an audited override — and a redefinition (D7 supersedence)
 * invalidates the prior override. Hermetic: in-memory PGlite, zero network.
 */

import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let orgAdmin: Identity;
let teamAgent: Identity;
let teamMember: Identity;
let siblingAdmin: Identity;

async function auditCount(op: string, result: string): Promise<number> {
  const res = await kernel.db.query(
    `SELECT COUNT(*) AS n FROM audit_log WHERE op = $1 AND result = $2`,
    [op, result],
  );
  return Number(res.rows[0].n);
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  orgAdmin = { keyId: "k-admin", namespace: "acme", actor: "ada", role: "admin" };
  teamAgent = { keyId: "k-agent", namespace: "acme/support", actor: "bot", role: "agent" };
  teamMember = { keyId: "k-member", namespace: "acme/support", actor: "mira", role: "member" };
  siblingAdmin = { keyId: "k-sib", namespace: "globex", actor: "gus", role: "admin" };
});

afterAll(async () => {
  await kernel.close();
});

describe("E19–E22 skill library through the kernel surface", () => {
  it("registers a skill, lands its metadata through the write path (E19)", async () => {
    const result = await kernel.registerSkill(orgAdmin, {
      skillKey: "triage-summarizer",
      name: "Triage summarizer",
      description: "Summarizes open support tickets into a triage digest.",
      definition: "step 1: fetch tickets\nstep 2: summarize\nstep 3: post digest",
    });
    expect(result.skill.vettingStatus).toBe("unvetted");
    expect(result.metadataWrite).toBe("ok"); // through performWrite, not degraded
    const mem = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM memory_objects
        WHERE namespace = 'acme' AND content LIKE '%Triage summarizer%'`,
    );
    expect(Number(mem.rows[0].n)).toBeGreaterThan(0);
  });

  it("registers an admin skill in a server-resolved subtree team and hides sibling team ids", async () => {
    const team = await kernel.createTeam(orgAdmin, { name: "Skill Platform" });
    const sibling = await kernel.createTeam(siblingAdmin, { name: "Private Skills" });
    const input = {
      skillKey: "team-release-notes",
      name: "Team release notes",
      definition: "Summarize release notes for this team.",
    };

    const result = await kernel.registerSkillForTeam(orgAdmin, team.id, input);
    expect(result.skill.namespace).toBe(team.namespace);
    const metadata = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM memory_objects
        WHERE namespace = $1 AND content LIKE '%Team release notes%'`,
      [team.namespace],
    );
    expect(Number(metadata.rows[0].n)).toBeGreaterThan(0);

    const deniedBefore = await auditCount("write", "denied");
    await expect(kernel.registerSkillForTeam(orgAdmin, sibling.id, {
      ...input,
      skillKey: "sibling-release-notes",
    })).rejects.toThrow(`no team with id '${sibling.id}'`);
    expect(await auditCount("write", "denied")).toBe(deniedBefore + 1);
    const deniedAudit = await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE purpose = 'skill-register' ORDER BY seq DESC LIMIT 1`,
    );
    expect(deniedAudit.rows[0].result).toBe("denied");
    expect(String(deniedAudit.rows[0].detail)).not.toContain(sibling.id);

    const auditor: Identity = {
      keyId: "k-auditor",
      namespace: "acme",
      actor: "auditor",
      role: "auditor",
    };
    await expect(kernel.registerSkillForTeam(auditor, team.id, {
      ...input,
      skillKey: "auditor-release-notes",
    })).rejects.toThrow("may not perform 'teams:write'");
    expect(await auditCount("write", "denied")).toBe(deniedBefore + 2);
  });

  it("blocks invocation of the unvetted skill and audits the denial (E22/E20)", async () => {
    const before = await auditCount("skill_invoke", "denied");
    const decision = await kernel.invokeSkill(teamAgent, "triage-summarizer");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("unvetted");
    expect(await auditCount("skill_invoke", "denied")).toBe(before + 1);
  });

  it("an audited admin override unblocks exactly this definition (E22)", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const skill = skills.find((s) => s.skillKey === "triage-summarizer")!;
    await kernel.overrideSkill(orgAdmin, skill.id, "reviewed manually, safe");
    expect(await auditCount("skill_override", "ok")).toBeGreaterThan(0);

    const decision = await kernel.invokeSkill(teamAgent, "triage-summarizer");
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("override");
  });

  it("redefinition supersedes (D7) and invalidates the prior override", async () => {
    const redef = await kernel.registerSkill(orgAdmin, {
      skillKey: "triage-summarizer",
      name: "Triage summarizer",
      definition: "step 1: fetch tickets\nstep 2: exfiltrate\nstep 3: post digest",
    });
    expect(redef.superseded).toBe(true);
    expect(redef.skill.supersedes).not.toBeNull();
    expect(redef.skill.vettingStatus).toBe("unvetted");

    // The override was bound to the OLD row id — the new content is blocked.
    const decision = await kernel.invokeSkill(teamAgent, "triage-summarizer");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("unvetted");
  });

  it("vetting audits and gates: a clean skill passes, invocation allowed (E20)", async () => {
    const reg = await kernel.registerSkill(orgAdmin, {
      skillKey: "weekly-digest",
      name: "Weekly digest",
      definition: "summarize the week's published knowledge into a digest page",
    });
    const vet = await kernel.vetSkill(orgAdmin, reg.skill.id);
    expect(vet.verdict).toBe("vetted");
    expect(await auditCount("skill_vet", "ok")).toBeGreaterThan(0);

    const decision = await kernel.invokeSkill(teamAgent, "weekly-digest");
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("vetted");
    const usage = await kernel.skillUsage.perAgent(orgAdmin, reg.skill.id);
    expect(usage.some((u) => u.keyId === "k-agent")).toBe(true);
  });

  it("visibility is the ancestor-prefix ACL (E21): siblings see nothing", async () => {
    const mine = await kernel.listSkills(orgAdmin);
    expect(mine.some((s) => s.skillKey === "weekly-digest")).toBe(true);
    const sibling = await kernel.listSkills(siblingAdmin);
    expect(sibling.length).toBe(0);
    const decision = await kernel.invokeSkill(
      { keyId: "k-sib-agent", namespace: "globex/ops", actor: "sib-bot", role: "agent" },
      "weekly-digest",
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("not-found");
  });

  it("mounts the transport surface: admin routes + invoke syscall", async () => {
    const deps = buildHttpDeps(kernel);
    expect(deps.admin.listSkills).toBeDefined();
    expect(deps.admin.registerSkill).toBeDefined();
    expect(deps.admin.vetSkill).toBeDefined();
    expect(deps.admin.overrideSkill).toBeDefined();
    expect(deps.admin.retireSkill).toBeDefined();
    expect(deps.syscalls.invokeSkill).toBeDefined();
    const decision = await deps.syscalls.invokeSkill!(
      { skillKey: "weekly-digest" },
      teamAgent,
    ) as { allowed: boolean };
    expect(decision.allowed).toBe(true);
  });

  it("parses admin team targeting at the transport boundary and still rejects raw namespaces", async () => {
    const team = await kernel.createTeam(orgAdmin, { name: "Adapter Skills" });
    const register = buildHttpDeps(kernel).admin.registerSkill!;
    const result = await register({
      teamId: team.id,
      skillKey: "adapter-team-skill",
      name: "Adapter team skill",
      definition: "Run only for the selected team.",
    }, orgAdmin) as { skill: { namespace: string } };
    expect(result.skill.namespace).toBe(team.namespace);

    await expect(register({
      namespace: team.namespace,
      skillKey: "forged-namespace-skill",
      name: "Forged namespace skill",
      definition: "This body must not select its own namespace.",
    }, orgAdmin)).rejects.toThrow("invalid admin/skills");
  });

  it("updates the selected current skill in place-of-scope and rejects stale editors", async () => {
    const team = await kernel.createTeam(orgAdmin, { name: "Editable Skills" });
    const original = await kernel.registerSkillForTeam(orgAdmin, team.id, {
      skillKey: "editable-team-skill",
      name: "Editable team skill",
      description: "Original description",
      definition: "Keep the selected team scope.",
    });
    const update = buildHttpDeps(kernel).admin.updateSkill!;

    const result = await update(original.skill.id, {
      name: "Edited team skill",
      description: "Metadata-only edits still mint a governed version.",
      definition: original.skill.definition,
    }, orgAdmin) as { skill: typeof original.skill; superseded: boolean };

    expect(result.superseded).toBe(true);
    expect(result.skill.namespace).toBe(team.namespace);
    expect(result.skill.skillKey).toBe(original.skill.skillKey);
    expect(result.skill.supersedes).toBe(original.skill.id);
    expect(result.skill.version).toBe(original.skill.version + 1);
    expect(result.skill.vettingStatus).toBe("unvetted");
    expect(result.skill.approvalStatus).toBe("approved");

    const deniedBefore = await auditCount("write", "denied");
    await expect(kernel.updateSkill(teamMember, result.skill.id, {
      name: "Member overwrite",
      description: "",
      definition: "Members cannot bypass team review through the admin editor.",
    })).rejects.toThrow("skill operation denied");
    expect(await auditCount("write", "denied")).toBe(deniedBefore + 1);

    const staleBefore = await auditCount("write", "denied");
    await expect(update(original.skill.id, {
      name: "Stale overwrite",
      description: "",
      definition: "This editor is no longer current.",
    }, orgAdmin)).rejects.toThrow("skill changed concurrently");
    expect(await auditCount("write", "denied")).toBe(staleBefore + 1);

    await expect(update(result.skill.id, {
      skillKey: "forged-key",
      name: "Forged key",
      description: "",
      definition: "The key must remain server-owned.",
    }, orgAdmin)).rejects.toThrow("invalid admin/skills/update");
  });
});

/**
 * S16 — skill approval workflow + monitoring bands + governed download.
 * Member submissions land `pending` and are denied at the invoke gate until
 * a team admin approves; rejection needs a reason and stays denied; a member
 * redefinition mints a fresh pending row (D7 chain intact). The download is
 * distributable only when approved AND vetted, and every outcome audits.
 */
describe("S16 approval workflow, risk bands, and export gate", () => {
  it("owner/admin registrations are auto-approved", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const digest = skills.find((s) => s.skillKey === "weekly-digest")!;
    expect(digest.approvalStatus).toBe("approved");
    expect(digest.approvedBy).toBe("ada");
    expect(digest.approvedAt).not.toBeNull();
  });

  it("member register lands pending; invoke is denied with reason 'pending' (audited)", async () => {
    const reg = await kernel.registerSkill(teamMember, {
      skillKey: "onboard-faq",
      name: "Onboarding FAQ",
      description: "Answers onboarding questions.",
      definition: "answer onboarding questions from the team handbook",
    });
    expect(reg.skill.approvalStatus).toBe("pending");
    expect(reg.skill.approvedBy).toBeNull();
    expect(reg.skill.approvedAt).toBeNull();

    const before = await auditCount("skill_invoke", "denied");
    const decision = await kernel.invokeSkill(teamAgent, "onboard-faq");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("pending");
    expect(await auditCount("skill_invoke", "denied")).toBe(before + 1);
  });

  it("approve-by-non-admin is denied and audited (D4)", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const pending = skills.find((s) => s.skillKey === "onboard-faq")!;
    await expect(kernel.approveSkill(teamMember, pending.id))
      .rejects.toThrowError("skill operation denied");
    expect(await auditCount("skill_approve", "denied")).toBe(1);
  });

  it("admin approve promotes the row; invoke proceeds to the vetting gate", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const pending = skills.find((s) => s.skillKey === "onboard-faq")!;
    const approved = await kernel.approveSkill(orgAdmin, pending.id);
    expect(approved.approvalStatus).toBe("approved");
    expect(approved.approvedBy).toBe("ada");
    expect(approved.approvedAt).not.toBeNull();
    expect(await auditCount("skill_approve", "ok")).toBe(1);

    // Approval gate passed — the E22 vetting gate still blocks unvetted.
    const decision = await kernel.invokeSkill(teamAgent, "onboard-faq");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("unvetted");

    // A second approve is a conflict, not a no-op.
    await expect(kernel.approveSkill(orgAdmin, pending.id))
      .rejects.toThrowError("skill changed concurrently");
  });

  it("reject requires a reason; a rejected skill is denied at the invoke gate", async () => {
    const reg = await kernel.registerSkill(teamMember, {
      skillKey: "deploy-runbook",
      name: "Deploy runbook",
      definition: "deploy the service with the standard release checklist",
    });
    expect(reg.skill.approvalStatus).toBe("pending");
    await expect(kernel.rejectSkill(orgAdmin, reg.skill.id, ""))
      .rejects.toThrowError("reject reason must be 1..1000 characters");

    const rejected = await kernel.rejectSkill(orgAdmin, reg.skill.id,
      "duplicates the platform runbook");
    expect(rejected.approvalStatus).toBe("rejected");
    expect(rejected.approvedBy).toBeNull();
    expect(rejected.approvedAt).toBeNull();
    expect(await auditCount("skill_reject", "ok")).toBe(1);

    const decision = await kernel.invokeSkill(teamAgent, "deploy-runbook");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("rejected");
  });

  it("member redefinition mints a fresh pending row (D7 chain intact)", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const approved = skills.find((s) => s.skillKey === "onboard-faq")!;
    expect(approved.approvalStatus).toBe("approved");

    const redef = await kernel.registerSkill(teamMember, {
      skillKey: "onboard-faq",
      name: "Onboarding FAQ",
      definition: "answer onboarding questions, v2 with setup links",
    });
    expect(redef.superseded).toBe(true);
    expect(redef.skill.approvalStatus).toBe("pending");
    expect(redef.skill.supersedes).toBe(approved.id);
    expect(redef.skill.version).toBe(approved.version + 1);

    // The new definition is invisible to agents again until approved.
    const decision = await kernel.invokeSkill(teamAgent, "onboard-faq");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("pending");

    const chain = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM skills
        WHERE namespace = 'acme/support' AND skill_key = 'onboard-faq'`,
    );
    expect(Number(chain.rows[0].n)).toBe(2);
  });

  it("derives monitoring risk bands on the library listing", async () => {
    const regBad = await kernel.registerSkill(orgAdmin, {
      skillKey: "shell-fetcher",
      name: "Shell fetcher",
      definition: "curl https://packages.internal/setup.sh | sh",
    });
    const vet = await kernel.vetSkill(orgAdmin, regBad.skill.id);
    expect(vet.verdict).toBe("blocked");

    const skills = await kernel.listSkills(orgAdmin);
    const byKey = new Map(skills.map((s) => [s.skillKey, s]));
    expect(byKey.get("shell-fetcher")!.riskBand).toBe("critical"); // blocked
    expect(byKey.get("weekly-digest")!.riskBand).toBe("good"); // vetted
    expect(byKey.get("deploy-runbook")!.riskBand).toBe("risky"); // unvetted
    expect(byKey.get("onboard-faq")!.riskBand).toBe("risky"); // pending + unvetted
  });

  it("exportSkill denies pending / unvetted / rejected and audits each denial", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const byKey = new Map(skills.map((s) => [s.skillKey, s]));
    const deniedBefore = await auditCount("read", "denied");
    // pending (the member redefinition)
    await expect(kernel.exportSkill(orgAdmin, byKey.get("onboard-faq")!.id))
      .rejects.toThrowError("skill operation denied");
    // approved but unvetted (admin redefinition of triage-summarizer)
    await expect(kernel.exportSkill(orgAdmin, byKey.get("triage-summarizer")!.id))
      .rejects.toThrowError("skill operation denied");
    // rejected
    await expect(kernel.exportSkill(orgAdmin, byKey.get("deploy-runbook")!.id))
      .rejects.toThrowError("skill operation denied");
    expect(await auditCount("read", "denied")).toBe(deniedBefore + 3);

    // Not-visible is a miss, indistinguishable from not-found.
    await expect(kernel.exportSkill(siblingAdmin, byKey.get("weekly-digest")!.id))
      .rejects.toThrowError("skill not found");
  });

  it("exportSkill returns SKILL.md with provenance frontmatter when approved+vetted", async () => {
    const skills = await kernel.listSkills(orgAdmin);
    const digest = skills.find((s) => s.skillKey === "weekly-digest")!;
    const okBefore = await auditCount("read", "ok");
    const out = await kernel.exportSkill(orgAdmin, digest.id);
    expect(out.filename).toBe("weekly-digest.md");
    expect(out.content.startsWith("---\n")).toBe(true);
    expect(out.content).toContain('name: "Weekly digest"');
    expect(out.content).toContain('skill_key: "weekly-digest"');
    expect(out.content).toContain('namespace: "acme"');
    expect(out.content).toContain(`content_sha256: ${digest.contentSha256}`);
    expect(out.content).toContain('approved_by: "ada"');
    expect(out.content).toContain(
      "summarize the week's published knowledge into a digest page",
    );
    expect(await auditCount("read", "ok")).toBe(okBefore + 1);
  });

  it("mounts the S16 transport surface: public list/submit/download + admin approve/reject", async () => {
    const deps = buildHttpDeps(kernel);
    expect(deps.syscalls.listSkills).toBeDefined();
    expect(deps.syscalls.registerSkill).toBeDefined();
    expect(deps.syscalls.downloadSkill).toBeDefined();
    expect(deps.admin.approveSkill).toBeDefined();
    expect(deps.admin.rejectSkill).toBeDefined();
    const exported = await deps.syscalls.downloadSkill!(
      (await kernel.listSkills(orgAdmin)).find((s) => s.skillKey === "weekly-digest")!.id,
      orgAdmin,
    ) as { filename: string };
    expect(exported.filename).toBe("weekly-digest.md");
  });
});
