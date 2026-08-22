/**
 * Mandatory setup gate (CONTRACTS-SETUP-GATE.md, SG3/SG4/SG6).
 *
 * Covers the server-side half of the gate with stubbed structural deps — no
 * PGlite needed: the onboarding latch is stamped exactly once when the live
 * checklist first derives complete, `onboardingState` is a plain flag read,
 * and the latch is one-way (a regressed step never un-stamps it).
 */

import { describe, expect, it } from "vitest";

import {
  onboardingState,
  setupChecklist,
  type ChecklistDeps,
} from "../src/setup/checklist.js";
import type { Identity, Tenant } from "../src/types.js";

function tenant(overrides: Partial<Tenant> = {}): Tenant {
  return {
    id: "acme",
    name: "Acme",
    status: "active",
    monthlyBudgetUsd: 10,
    rateLimitPerMin: null,
    onboardingCompletedAt: null,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

function ownerIdentity(namespace: string): Identity {
  return { keyId: "k1", namespace, actor: "owner@acme.test", role: "owner" };
}

interface Harness {
  deps: ChecklistDeps;
  record: Tenant;
  latchCalls: number;
}

/**
 * A deps harness whose probes all report complete. The fake Db applies the
 * latch UPDATE to the in-memory tenant row so the flag read sees it.
 */
function completeHarness(record: Tenant): Harness {
  const state = { latchCalls: 0 };
  const deps: ChecklistDeps = {
    db: {
      async query(sql: string, params: readonly unknown[] = []) {
        if (/UPDATE tenants SET onboarding_completed_at/i.test(sql)) {
          state.latchCalls += 1;
          if (record.onboardingCompletedAt === null) {
            record.onboardingCompletedAt = String(params[0]);
          }
          return { rows: [] };
        }
        if (/FROM org_teams/i.test(sql)) return { rows: [{ n: "1" }] };
        if (/FROM company_files/i.test(sql)) return { rows: [{ n: "0" }] };
        return { rows: [{ n: "3" }] };
      },
    } as unknown as ChecklistDeps["db"],
    sources: {
      async list() {
        return [{ syncStatus: "synced" }];
      },
    },
    tenants: {
      async resolveTenant(ns: string) {
        return ns.split("/")[0] === record.id ? record : null;
      },
      async list() {
        return [record];
      },
    },
  };
  return { deps, record, get latchCalls() { return state.latchCalls; } };
}

describe("setup gate - onboarding latch", () => {
  it("orders the steps as the guided journey, team space first", async () => {
    const { deps } = completeHarness(tenant());
    const view = await setupChecklist(deps, ownerIdentity("acme"));
    expect(view.steps.map((s) => s.id)).toEqual([
      "team-space",
      "source",
      "memory",
      "team",
      "badge",
    ]);
  });

  it("latches onboarding_completed_at exactly once when the checklist completes", async () => {
    const harness = completeHarness(tenant());
    const identity = ownerIdentity("acme");

    const first = await setupChecklist(harness.deps, identity);
    expect(first.complete).toBe(true);
    expect(harness.latchCalls).toBe(1);
    expect(harness.record.onboardingCompletedAt).not.toBeNull();

    // A second derivation must NOT re-stamp: the latch is first-wins (SG4).
    const second = await setupChecklist(harness.deps, identity);
    expect(second.complete).toBe(true);
    expect(harness.latchCalls).toBe(1);
  });

  it("does not latch while a required step is outstanding", async () => {
    const harness = completeHarness(tenant());
    harness.deps = {
      ...harness.deps,
      sources: { async list() { return []; } },
    };
    const view = await setupChecklist(harness.deps, ownerIdentity("acme"));
    expect(view.complete).toBe(false);
    expect(harness.latchCalls).toBe(0);
    expect(harness.record.onboardingCompletedAt).toBeNull();
  });

  it("accepts one uploaded knowledge-base file instead of a synced backend", async () => {
    const harness = completeHarness(tenant());
    const inner = harness.deps.db;
    harness.deps = {
      ...harness.deps,
      db: {
        async query(sql: string, params: readonly unknown[] = []) {
          if (/FROM company_files/i.test(sql)) return { rows: [{ n: "1" }] };
          return inner.query(sql, [...params]);
        },
      } as ChecklistDeps["db"],
      sources: { async list() { return []; } },
    };

    const view = await setupChecklist(harness.deps, ownerIdentity("acme"));
    expect(view.steps.find((step) => step.id === "source")).toMatchObject({
      state: "complete",
      evidence: "1 uploaded knowledge file",
    });
    expect(view.complete).toBe(true);
    expect(harness.latchCalls).toBe(1);
  });

  it("does not accept an empty knowledge base as the data-entry step", async () => {
    const harness = completeHarness(tenant());
    harness.deps = {
      ...harness.deps,
      sources: { async list() { return []; } },
    };

    const view = await setupChecklist(harness.deps, ownerIdentity("acme"));
    expect(view.steps.find((step) => step.id === "source")).toMatchObject({
      state: "outstanding",
      evidence: "no synced backends or uploaded knowledge files",
    });
    expect(view.complete).toBe(false);
  });

  it("keeps teammate invitation optional for a solo workspace", async () => {
    const harness = completeHarness(tenant());
    const inner = harness.deps.db;
    harness.deps = {
      ...harness.deps,
      db: {
        async query(sql: string, params: readonly unknown[] = []) {
          if (/FROM users/i.test(sql)) return { rows: [{ n: "1" }] };
          if (/FROM auth_invitations/i.test(sql)) return { rows: [{ n: "0" }] };
          return inner.query(sql, [...params]);
        },
      } as ChecklistDeps["db"],
    };

    const view = await setupChecklist(harness.deps, ownerIdentity("acme"));
    expect(view.steps.find((step) => step.id === "team")).toMatchObject({
      optional: true,
      state: "outstanding",
      evidence: "solo workspace; no invitations sent",
    });
    expect(view).toMatchObject({ complete: true, completed: 4, total: 4, remaining: 0 });
    expect(harness.latchCalls).toBe(1);
  });

  it("lets either positive OR lane survive a brownout in the other lane", async () => {
    const fileHarness = completeHarness(tenant());
    const inner = fileHarness.deps.db;
    fileHarness.deps = {
      ...fileHarness.deps,
      db: {
        async query(sql: string, params: readonly unknown[] = []) {
          if (/FROM company_files/i.test(sql)) return { rows: [{ n: "1" }] };
          return inner.query(sql, [...params]);
        },
      } as ChecklistDeps["db"],
      sources: { async list() { throw new Error("backend unavailable"); } },
    };
    expect(
      (await setupChecklist(fileHarness.deps, ownerIdentity("acme"))).steps
        .find((step) => step.id === "source")?.state,
    ).toBe("complete");

    const backendHarness = completeHarness(tenant());
    const backendInner = backendHarness.deps.db;
    backendHarness.deps = {
      ...backendHarness.deps,
      db: {
        async query(sql: string, params: readonly unknown[] = []) {
          if (/FROM company_files/i.test(sql)) throw new Error("knowledge unavailable");
          return backendInner.query(sql, [...params]);
        },
      } as ChecklistDeps["db"],
    };
    expect(
      (await setupChecklist(backendHarness.deps, ownerIdentity("acme"))).steps
        .find((step) => step.id === "source")?.state,
    ).toBe("complete");
  });

  it("evaluates each organization on its own signals and latches per-tenant (root)", async () => {
    const mk = (id: string) => tenant({ id, name: id });
    const alpha = mk("alpha");
    const beta = mk("beta");
    const latched: string[] = [];
    const deps: ChecklistDeps = {
      db: {
        async query(sql: string, params: readonly unknown[] = []) {
          if (/UPDATE tenants SET onboarding_completed_at/i.test(sql)) {
            latched.push(String(params[1]));
            return { rows: [] };
          }
          // Per-org probes carry the org id as $1: beta has no teams.
          if (/FROM org_teams/i.test(sql)) {
            return { rows: [{ n: params[0] === "alpha" ? "1" : "0" }] };
          }
          return { rows: [{ n: "3" }] };
        },
      } as unknown as ChecklistDeps["db"],
      sources: { async list() { return [{ syncStatus: "synced" }]; } },
      tenants: {
        async resolveTenant() { return null; },
        async list() { return [alpha, beta]; },
      },
    };
    const view = await setupChecklist(deps, ownerIdentity(""));
    // Only alpha completed on ITS OWN signals; beta's gaps are shown.
    expect(latched).toEqual(["alpha"]);
    expect(view.organization).toBe("beta");
    expect(view.complete).toBe(false);
    expect(view.steps.find((s) => s.id === "team-space")?.state).toBe("outstanding");
  });

  it("exposes the evaluated organization for a scoped caller", async () => {
    const { deps } = completeHarness(tenant());
    const view = await setupChecklist(deps, ownerIdentity("acme"));
    expect(view.organization).toBe("acme");
  });
});

describe("setup gate - onboardingState flag read", () => {
  it("reports setupRequired while the org's flag is NULL", async () => {
    const { deps } = completeHarness(tenant());
    const state = await onboardingState(deps, ownerIdentity("acme"));
    expect(state).toEqual({ setupRequired: true, completedAt: null });
  });

  it("reports not-gated with the stamp once latched", async () => {
    const { deps, record } = completeHarness(tenant());
    await setupChecklist(deps, ownerIdentity("acme"));
    const state = await onboardingState(deps, ownerIdentity("acme"));
    expect(state.setupRequired).toBe(false);
    expect(state.completedAt).toBe(record.onboardingCompletedAt);
  });

  it("never un-stamps when a step regresses after completion (SG4)", async () => {
    const harness = completeHarness(tenant());
    const identity = ownerIdentity("acme");
    await setupChecklist(harness.deps, identity);
    // The org later loses its sources: the checklist re-opens the step…
    harness.deps = {
      ...harness.deps,
      sources: { async list() { return []; } },
    };
    const view = await setupChecklist(harness.deps, identity);
    expect(view.complete).toBe(false);
    // …but the gate stays lifted — the latch is one-way.
    const state = await onboardingState(harness.deps, identity);
    expect(state.setupRequired).toBe(false);
  });

  it("gates a root owner with no tenants (fresh install)", async () => {
    const { deps } = completeHarness(tenant());
    deps.tenants = {
      async resolveTenant() { return null; },
      async list() { return []; },
    };
    const root = ownerIdentity("");
    const state = await onboardingState(deps, root);
    expect(state).toEqual({ setupRequired: true, completedAt: null });
  });

  it("gates a root owner on its sole tenant's latch (single-org install)", async () => {
    const { deps } = completeHarness(tenant({ id: "halofy" }));
    const state = await onboardingState(deps, ownerIdentity(""));
    expect(state).toEqual({ setupRequired: true, completedAt: null });
  });

  /**
   * SG8. Reproduces the 2026-08-01 production lockout: a customer completed
   * the inline `/console/login` signup state, creating a second, unlatched tenant — and the platform
   * root's console fell back into the setup gate even though its own org had
   * latched hours earlier.
   */
  it("does not gate the platform root when another org signs up unlatched (SG8)", async () => {
    const home = tenant({ id: "halofy", onboardingCompletedAt: "2026-08-01T06:07:17.330Z" });
    const newcomer = tenant({ id: "breakfast-club-fg73wp30", name: "Breakfast club" });
    const { deps } = completeHarness(home);
    deps.tenants = {
      async resolveTenant(ns: string) {
        const id = ns.split("/")[0];
        return [home, newcomer].find((t) => t.id === id) ?? null;
      },
      async list() {
        return [home, newcomer];
      },
    };

    const root = await onboardingState(deps, ownerIdentity(""));
    expect(root.setupRequired).toBe(false);
    expect(root.completedAt).toBe(home.onboardingCompletedAt);

    // The newcomer's own owner is still gated by their own org's latch — SG8
    // lifts the root's gate only, never anyone else's.
    const scoped = await onboardingState(deps, ownerIdentity(newcomer.id));
    expect(scoped).toEqual({ setupRequired: true, completedAt: null });
  });

  it("does not gate a scoped caller whose namespace resolves to no tenant", async () => {
    const { deps } = completeHarness(tenant());
    deps.tenants = {
      async resolveTenant() { return null; },
      async list() { return []; },
    };
    const state = await onboardingState(deps, ownerIdentity("ghost"));
    expect(state.setupRequired).toBe(false);
  });

  it("reads only the flag - the live probes never run (SG3 boundary)", async () => {
    const { deps } = completeHarness(tenant());
    let probed = false;
    const inner = deps.db;
    (deps as { db: unknown }).db = {
      async query(sql: string, params: readonly unknown[] = []) {
        if (/FROM org_teams|FROM memory_objects|FROM api_keys|FROM users/i.test(sql)) {
          probed = true;
        }
        return inner.query(sql, [...params]);
      },
    };
    await onboardingState(deps, ownerIdentity("acme"));
    expect(probed).toBe(false);
  });
});
