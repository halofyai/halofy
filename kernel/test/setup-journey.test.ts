/**
 * The NEW-CUSTOMER setup journey, end to end — the "butter-smooth" contract.
 *
 * A fresh user signs up (SSO → org-name screen), lands on the S1 gate, and
 * then every action the guided checklist asks for must flip its step to
 * complete ON THE VERY NEXT DERIVATION — no orphan namespaces, no manual
 * repair, no cross-org leakage:
 *
 *   sign up → org exists, all steps open
 *   create a team on S13     → "team space" complete
 *   sync a backend OR upload one knowledge-base file
 *                            → "source" AND "first memory" complete
 *   invite a teammate        → "teammate" complete
 *   mint an agent badge      → "agent" complete → gate latches, console unlocks
 *
 * A second org signing up afterwards starts from zero — org A's signals must
 * never satisfy org B's steps.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Kernel } from "../src/kernel.js";
import type { Identity, SetupStepId } from "../src/types.js";

let kernel: Kernel;

/** The identity a console session carries after signup: org owner. */
function ownerIdentity(tenantId: string, email: string): Identity {
  return {
    keyId: `session:${email}`,
    namespace: tenantId,
    actor: email,
    role: "owner",
  };
}

async function signUp(email: string, orgName: string): Promise<{
  tenantId: string;
  owner: Identity;
}> {
  const issued = await kernel.organizationSignup.issue(email);
  const completed = await kernel.organizationSignup.complete(issued.token, orgName);
  if (completed === null) throw new Error(`signup for ${email} did not complete`);
  const tenantId = (completed.organization as { id: string }).id;
  return { tenantId, owner: ownerIdentity(tenantId, email) };
}

async function stepStates(
  identity: Identity,
): Promise<Record<string, { state: string; evidence: string }>> {
  const view = await kernel.setupChecklist(identity);
  return Object.fromEntries(
    view.steps.map((s) => [s.id, { state: s.state, evidence: s.evidence }]),
  );
}

function expectStates(
  states: Record<string, { state: string; evidence: string }>,
  expected: Partial<Record<SetupStepId | string, string>>,
): void {
  for (const [id, state] of Object.entries(expected)) {
    expect(states[id]?.state, `${id} (${states[id]?.evidence})`).toBe(state);
  }
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
});

afterAll(async () => {
  await kernel.close();
});

describe("a fresh org's guided setup, action by action", () => {
  let tenantId: string;
  let owner: Identity;
  let growthTeamId: string;

  it("sign-up creates the org with the owner INSIDE it; every step is open", async () => {
    ({ tenantId, owner } = await signUp("founder@acme.test", "Acme Rockets"));
    expect(tenantId).toMatch(/^acme-rockets-/);

    const view = await kernel.setupChecklist(owner);
    expect(view.organization).toBe(tenantId);
    expect(view.complete).toBe(false);
    expectStates(await stepStates(owner), {
      "team-space": "outstanding",
      source: "outstanding",
      memory: "outstanding",
      team: "outstanding",
      badge: "outstanding",
    });
    // The gate is on.
    const onboarding = await kernel.onboardingState(owner);
    expect(onboarding.setupRequired).toBe(true);
  });

  it("creating a team on S13 flips 'team space' on the next derivation", async () => {
    const team = await kernel.createTeam(owner, { name: "Growth" });
    growthTeamId = team.id;
    expect(team.namespace).toBe(`${tenantId}/growth`);
    expectStates(await stepStates(owner), { "team-space": "complete" });
  });

  it("connecting and syncing a source flips 'source' AND 'first memory'", async () => {
    const dir = mkdtempSync(join(tmpdir(), "halomem-journey-"));
    writeFileSync(
      join(dir, "notes.md"),
      "Our refund policy allows returns within 30 days of purchase.",
    );
    const source = await kernel.registerSource(
      "filesystem",
      { path: dir },
      owner,
      undefined,
      growthTeamId,
    );
    expectStates(await stepStates(owner), { source: "outstanding" });

    const result = await kernel.syncSource(source.id, owner);
    expect(result.stored).toBeGreaterThan(0);
    expectStates(await stepStates(owner), {
      source: "complete",
      memory: "complete",
    });
  });

  it("sending an invitation completes the optional teammate step before acceptance", async () => {
    const issued = await kernel.invitations.create(
      { email: "teammate@acme.test", namespace: `${tenantId}/growth`, role: "member" },
      owner,
    );
    const invited = await stepStates(owner);
    expectStates(invited, { team: "complete" });
    expect(invited.team?.evidence).toBe("1 active invitation sent");

    const accepted = await kernel.invitations.accept({
      token: issued.activationToken,
      password: "teammate-password-01",
    });
    expect(accepted?.namespace).toBe(`${tenantId}/growth`);
    // Acceptance keeps the row complete, but was never required from the
    // recipient for the onboarding owner to finish their action.
    expectStates(await stepStates(owner), { team: "complete" });
  });

  it("minting an agent badge flips 'agent' and completes the gate", async () => {
    await kernel.auth.issueKey(`${tenantId}/growth`, "support-bot", "agent", owner);
    const view = await kernel.setupChecklist(owner);
    expectStates(await stepStates(owner), { badge: "complete" });
    expect(view.complete).toBe(true);
    expect(view.remaining).toBe(0);

    // The latch stamped — the console unlocks and stays unlocked.
    const onboarding = await kernel.onboardingState(owner);
    expect(onboarding.setupRequired).toBe(false);
    expect(onboarding.completedAt).not.toBeNull();
  });
});

describe("a second org starts from zero - no cross-org leakage", () => {
  it("org B's checklist ignores everything org A did", async () => {
    const { tenantId, owner } = await signUp("ceo@beta.test", "Beta Industries");
    const view = await kernel.setupChecklist(owner);
    expect(view.organization).toBe(tenantId);
    expect(view.complete).toBe(false);
    expectStates(await stepStates(owner), {
      "team-space": "outstanding",
      source: "outstanding",
      memory: "outstanding",
      team: "outstanding",
      badge: "outstanding",
    });
    // And org B stays gated even though org A finished.
    const onboarding = await kernel.onboardingState(owner);
    expect(onboarding.setupRequired).toBe(true);
  });

  it("org B completes solo with one knowledge-base file and no teammate invitation", async () => {
    const { tenantId, owner } = await signUp("ops@gamma.test", "Gamma Ops");
    await kernel.createTeam(owner, { name: "Ops" });
    const base = await kernel.createKnowledgeBase({
      name: "Operations runbooks",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Operations",
      description: "Incident response knowledge",
      dataSensitive: false,
    }, owner);
    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "runbook.md",
      content: "Escalate sev1 incidents to the on-call lead.",
      title: "Incident runbook",
      description: "Sev1 escalation procedure",
      purpose: "Guide the incident response team",
    }, owner);
    expect(file.status).toBe("ready");
    expectStates(await stepStates(owner), {
      source: "complete",
      memory: "complete",
    });
    await kernel.auth.issueKey(`${tenantId}/ops`, "ops-bot", "agent", owner);

    const view = await kernel.setupChecklist(owner);
    expect(view.steps.find((step) => step.id === "team")).toMatchObject({
      optional: true,
      state: "outstanding",
    });
    expect(view.complete, JSON.stringify(view.steps)).toBe(true);
  });
});
