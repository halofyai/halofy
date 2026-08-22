import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

async function screenSource(name: string): Promise<string> {
  return readFile(
    fileURLToPath(new URL(`../console/screens/${name}.js`, import.meta.url)),
    "utf8",
  );
}

describe("governance console minimalism source contracts", () => {
  it("renders the setup checklist as an always-expanded guided stepper", async () => {
    const [setup, checklist] = await Promise.all([
      screenSource("s1"),
      screenSource("setup-checklist"),
    ]);

    // S1 is checklist-only: the one-shot wizard (and its setup-definition
    // disclosure) was removed with the legacy teams table (migration v69).
    expect(setup).toContain("checklistCard(ctx, view)");
    expect(setup).not.toContain("setup-definition");
    expect(setup).not.toContain("Backend-verified steps.");
    // The guided stepper (CONTRACTS-SETUP-GATE E8/E9): one narrow column of
    // step cards under a header that owns the progress meter, an "up next"
    // spotlight, and a degraded-probe notice — not a card-in-a-card, and not
    // the old unstyled <details> list.
    expect(checklist).toContain('<section class="setup-stepper">');
    expect(checklist).toContain('role="progressbar"');
    expect(checklist).toContain('"setup-step is-next"');
    expect(checklist).toContain("setup-stepper__degraded");
    expect(checklist).not.toContain("<details");
    expect(checklist).not.toContain("Steps re-open on their own");
    expect(checklist).not.toContain('(view.complete ? "" : " open")');
  });

  it("discloses policy intake and runtime controls without hiding policy state", async () => {
    const [policy, library] = await Promise.all([
      screenSource("s4"),
      screenSource("policy-library"),
    ]);

    expect(policy).toContain('<details class="policy-runtime">');
    // Intake is the platform right-side drawer rather than an inline
    // disclosure: it is one task with its own flow, and pinned into the page
    // it pushed the register (what an operator came to read) below the fold.
    expect(library).toContain('id: "policy-add-panel"');
    expect(library).toContain('data-action="policy-add-open"');
    expect(library).toContain('closeAction: "policy-add-close"');
    expect(library).not.toContain("policy-intake-disclosure");
    expect(library).toContain('data-policy-summary role="list" aria-label="Policy file summary"');
    expect(library).not.toContain("Governed files agents can use.");
  });

  it("keeps approval state primary and exposes owner-triggered delta sync", async () => {
    const source = await screenSource("s7");

    expect(source).toContain('data-action="knowledge-sync"');
    expect(source).toContain('data-knowledge-sync-target');
    expect(source).not.toContain("Evidence memory ULIDs");
    expect(source).toContain('data-action="proposal-approve"');
    expect(source).not.toContain("Real approval decisions only.");
  });

  it("keeps prototype deletion and certificate cards visible with their warnings", async () => {
    const source = await screenSource("s8");

    expect(source).toContain('class="card audit-compliance-card audit-erasure"');
    expect(source).toContain('class="card audit-compliance-card certificate-viewer"');
    // The destructive-action warning survived the plain-language rewrite —
    // only its wording changed ("Irreversible" → "Cannot be undone"), and the
    // critical pill it rides on is what makes it impossible to miss.
    expect(source).toContain('class="pill pill--crit"');
    expect(source).toContain("Cannot be undone");
    expect(source).toContain('data-action="audit-erase"');
    expect(source).toContain('data-action="cert-verify"');
  });

  it("keeps conflict facts visible and discloses the replacement editor", async () => {
    const source = await screenSource("s11");

    expect(source).toContain('<details class="compact-disclosure conflict-edit">');
    expect(source).toContain('data-action="dispute-uphold"');
    expect(source).toContain('data-action="dispute-keep"');
    const editor = source.match(/<details class="compact-disclosure conflict-edit">[\s\S]*?<\/details>/)?.[0] ?? "";
    expect(editor).toContain('data-action="dispute-edit"');
    expect(source.replace(editor, "")).not.toContain('data-action="dispute-edit"');
  });

  it("puts one model deployment flow after authoritative runtime tables", async () => {
    const source = await screenSource("s12");

    expect(source.indexOf("renderConnections(ctx, connections)")).toBeLessThan(
      source.indexOf("renderModelSetup(ctx, connections, profiles)"),
    );
    expect(source).toContain('data-action="model-connection-create"');
    expect(source).toContain('data-change-action="model-deployment-connection-select"');
    expect(source).not.toContain('data-action="model-profile-create"');
  });

  it("retires the accuracy hero and observations strip and trims readiness copy", async () => {
    const [analytics, readiness] = await Promise.all([
      screenSource("s15"),
      screenSource("readiness-card"),
    ]);

    // The methodology disclosure went out with the hero it explained.
    expect(analytics).not.toContain('class="compact-disclosure analytics-method"');
    expect(analytics).not.toContain("How often was the agent right?");
    expect(analytics).not.toContain('title: "Observations"');
    expect(analytics).not.toContain('data-action="obs-filter"');
    expect(readiness).not.toContain("Freshness, coverage and trust at a glance.");
  });

  it("keeps skill safety guidance static and discloses registration policy", async () => {
    const source = await screenSource("s16");

    expect(source).toContain('<p class="skill-security-guide"><strong>How checks work.</strong>');
    expect(source).not.toContain('<details class="compact-disclosure skill-security-guide">');
    expect(source).not.toContain('<summary><span><b>How checks work</b></span></summary>');
    expect(source).toContain('rightPanelHtml({ id: "skill-register-panel"');
    expect(source).toContain('className: "skill-register-drawer"');
    expect(source).not.toContain('<details class="compact-disclosure skill-register-disclosure" open>');
    expect(source).toContain('<section class="card skill-register" id="skill-form"');
    expect(source).toContain('class="compact-disclosure skill-register-policy-disclosure"');
    expect(source).toContain('class="skill-sec"');
  });
});
