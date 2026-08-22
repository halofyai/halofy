/**
 * Console setup gate (CONTRACTS-SETUP-GATE.md, E1/E2/E5/E7/E8).
 *
 * String-level contracts over the shell sources, matching the console test
 * idiom: the gate decision comes from /auth/me's server flag, the rail locks
 * non-setup screens, members get a waiting view, and the S1 checklist is a
 * padded guided stepper — never the old unstyled list.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

function consoleFile(name: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../console/${name}`, import.meta.url)),
    "utf8",
  );
}

const APP_JS = consoleFile("app.js");
const INDEX_HTML = consoleFile("index.html");
const APP_CSS = consoleFile("app.css");
const CHECKLIST_JS = consoleFile("screens/setup-checklist.js");
const S1_JS = consoleFile("screens/s1.js");

describe("console setup gate (shell)", () => {
  it("takes the gate decision from the server flag on /auth/me - no localStorage", () => {
    expect(APP_JS).toContain("onboarding.setupRequired === true");
    expect(APP_JS).not.toContain("halomem.onboarding.skipped");
    expect(APP_JS).not.toContain("halomem.onboarding.step");
    expect(APP_JS).not.toContain("/console/onboarding");
  });

  it("locks the rail to the setup screens while gated (E1)", () => {
    expect(APP_JS).toContain(
      'const SETUP_SCREENS = new Set(["s1", "s3", "s5", "s6", "s13"])',
    );
    expect(APP_JS).toContain('? "setup"');
    expect(APP_JS).toContain(': "waiting"');
    expect(APP_JS).toContain('class="locked" data-tip="${item.label}"');
    expect(APP_JS).toContain(
      'aria-label="${item.label} - locked until setup is complete"',
    );
    expect(APP_JS).not.toContain('data-tip="Finish setup to unlock"');
    expect(APP_CSS).toContain("#rail-nav button.locked{");
  });

  it("falls back to S1 for any disallowed hash while gated (E2)", () => {
    expect(APP_JS).toContain('gateMode === "setup"');
    expect(APP_JS).toContain("SETUP_SCREEN");
    expect(APP_JS).toContain('const SETUP_SCREEN = "s1"');
  });

  it("shows members a waiting view, not screens (E5)", () => {
    expect(APP_JS).toContain('gateMode === "waiting"');
    expect(APP_JS).toContain("Your organization is being set up");
    expect(APP_JS).toContain("data-gate-reload");
  });

  it("keeps a persistent banner above the stage and unlocks live on completion (E3)", () => {
    expect(INDEX_HTML).toContain('id="setup-gate-banner"');
    expect(APP_JS).toContain("unlockConsole");
    expect(APP_JS).toContain("view.complete === true");
    expect(APP_CSS).toContain(".setup-gate-banner{");
    expect(APP_CSS).toMatch(/\.setup-gate-banner\{[^}]*border:1px solid #f4a261[^}]*background:#fff0e8/);
    expect(APP_CSS).toMatch(/\.setup-gate-banner__text\{[^}]*color:#8a3400/);
  });
});

describe("S1 guided stepper (E8/E9)", () => {
  it("renders a padded stepper with a progress meter - not bare text", () => {
    expect(CHECKLIST_JS).toContain('<section class="setup-stepper">');
    expect(CHECKLIST_JS).toContain('role="progressbar"');
    expect(APP_CSS).toContain(".setup-step{");
    expect(APP_CSS).toContain(".setup-step__marker{");
    expect(APP_CSS).toContain(".setup-stepper__bar{");
    expect(APP_CSS).toContain(".setup-step.is-next{");
  });

  it("wears the shared page title bar and never stacks two titles (E9)", () => {
    // S1 is a tab like any other: the title sits in the shared `.head`, at the
    // same offset under the breadcrumb as Home's or the Assistant's.
    expect(S1_JS).toContain('ui.head({ eyebrow: "Onboard", title: "Set up Halofy" })');
    // The stepper header survives for the org line and progress meter only —
    // a second heading there is exactly the duplication E9 forbids.
    expect(CHECKLIST_JS).toContain('class="setup-stepper__head"');
    expect(CHECKLIST_JS).not.toContain("<h1>");
    expect(APP_CSS).toContain(".setup-stepper__head{");
  });

  it("spotlights exactly one up-next step with the primary CTA (E9)", () => {
    expect(CHECKLIST_JS).toContain("nextStepId");
    expect(CHECKLIST_JS).toContain(">Start</a>");
    expect(CHECKLIST_JS).toContain(">Open</a>");
    expect(CHECKLIST_JS).toContain('aria-current="step"');
    // State reads off the marker and the title weight — no per-row status
    // pill, and a completed row keeps no action at all.
    expect(CHECKLIST_JS).not.toContain("Up next");
    expect(CHECKLIST_JS).not.toContain("ui.pill(");
  });

  it("suppresses the gate banner on the setup surface itself (E9)", () => {
    expect(APP_JS).toContain('currentScreenId === SETUP_SCREEN');
    expect(APP_JS).toContain("lastChecklistView");
    // Still persistent everywhere else while gated.
    expect(APP_JS).toContain("data-gate-continue");
  });

  it("has a completion celebration and NO skip affordance anywhere", () => {
    expect(CHECKLIST_JS).toContain("setup-celebration");
    expect(CHECKLIST_JS).toContain("Enter your console");
    expect(CHECKLIST_JS).not.toContain("Skip");
    expect(APP_CSS).toContain(".setup-celebration__burst{");
  });

  it("keeps every step value escaped (no inline JS, pure string renderer)", () => {
    expect(CHECKLIST_JS).not.toContain("innerHTML =");
    expect(CHECKLIST_JS).not.toContain("<script");
    expect(CHECKLIST_JS).not.toContain("onClick");
  });
});
