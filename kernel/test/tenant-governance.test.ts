/**
 * Module D (M4) tests — per-tenant governance: effective budget/rate-limit math
 * (MIN under "null = unlimited" semantics) + the suspended-tenant gate.
 *
 * Pure module: imports ONLY shared types + the module under test. No DB, no
 * network, no registry — the syscall layer resolves the Tenant and passes it in.
 */

import { describe, expect, it } from "vitest";
import type { Tenant } from "../src/types.js";
import {
  effectiveBudgetUsd,
  effectiveRateLimit,
  tenantGate,
  TenantSuspendedError,
} from "../src/policy/tenant.js";

function tenant(overrides: Partial<Tenant> = {}): Tenant {
  return {
    id: "acme",
    name: "Acme",
    status: "active",
    monthlyBudgetUsd: null,
    rateLimitPerMin: null,
    createdAt: "2026-07-08T00:00:00.000Z",
    ...overrides,
  };
}

describe("effectiveBudgetUsd", () => {
  it("takes the tenant cap when it is below the namespace policy cap", () => {
    expect(effectiveBudgetUsd(100, tenant({ monthlyBudgetUsd: 20 }))).toBe(20);
  });

  it("takes the namespace policy cap when it is below the tenant cap", () => {
    expect(effectiveBudgetUsd(20, tenant({ monthlyBudgetUsd: 100 }))).toBe(20);
  });

  it("null namespace cap → tenant cap governs (null = unlimited on that side)", () => {
    expect(effectiveBudgetUsd(null, tenant({ monthlyBudgetUsd: 20 }))).toBe(20);
  });

  it("null tenant cap → namespace policy cap governs", () => {
    expect(effectiveBudgetUsd(50, tenant({ monthlyBudgetUsd: null }))).toBe(50);
  });

  it("both null → unlimited (null)", () => {
    expect(effectiveBudgetUsd(null, tenant({ monthlyBudgetUsd: null }))).toBeNull();
  });

  it("no tenant registered → namespace policy cap governs; both absent → null", () => {
    expect(effectiveBudgetUsd(50, null)).toBe(50);
    expect(effectiveBudgetUsd(null, null)).toBeNull();
  });

  it("a zero cap is a real cap, not treated as unlimited", () => {
    expect(effectiveBudgetUsd(100, tenant({ monthlyBudgetUsd: 0 }))).toBe(0);
    expect(effectiveBudgetUsd(0, tenant({ monthlyBudgetUsd: 100 }))).toBe(0);
  });
});

describe("effectiveRateLimit", () => {
  it("takes the minimum of the namespace policy limit and the tenant limit", () => {
    expect(effectiveRateLimit(120, tenant({ rateLimitPerMin: 30 }))).toBe(30);
    expect(effectiveRateLimit(30, tenant({ rateLimitPerMin: 120 }))).toBe(30);
  });

  it("null on either side means unlimited on that side", () => {
    expect(effectiveRateLimit(null, tenant({ rateLimitPerMin: 60 }))).toBe(60);
    expect(effectiveRateLimit(60, tenant({ rateLimitPerMin: null }))).toBe(60);
    expect(effectiveRateLimit(null, tenant({ rateLimitPerMin: null }))).toBeNull();
  });

  it("no tenant registered → namespace policy limit governs", () => {
    expect(effectiveRateLimit(60, null)).toBe(60);
    expect(effectiveRateLimit(null, null)).toBeNull();
  });
});

describe("tenantGate", () => {
  it("throws TenantSuspendedError for a suspended tenant", () => {
    expect(() => tenantGate(tenant({ status: "suspended" }))).toThrow(
      TenantSuspendedError,
    );
  });

  it("the thrown error carries name 'TenantSuspendedError'", () => {
    try {
      tenantGate(tenant({ status: "suspended" }));
      expect.unreachable("tenantGate should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(TenantSuspendedError);
      expect((e as Error).name).toBe("TenantSuspendedError");
    }
  });

  it("does not throw for an active tenant", () => {
    expect(() => tenantGate(tenant({ status: "active" }))).not.toThrow();
  });

  it("does not throw when no tenant is registered (null)", () => {
    expect(() => tenantGate(null)).not.toThrow();
  });
});
