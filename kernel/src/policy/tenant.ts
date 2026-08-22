/**
 * Module D (M4) — per-tenant governance.
 *
 * A tenant is just a root namespace (Module A's TenantRegistry names them and
 * carries the per-tenant caps). This module holds the PURE math + gate that the
 * syscall layer applies once it has resolved the owning Tenant. Nothing here
 * touches the DB, the registry, or another builder's class — it imports ONLY
 * shared types, so the tenant cap can never drift from the ancestor ACL: the
 * cap is inherited by the whole subtree exactly like a namespace policy, and it
 * only ever LOWERS an effective limit, never raises it.
 *
 * A tenant cap composes with the namespace policy cap by taking the MIN of the
 * two (null = unlimited on that side). A suspended tenant is a bulk revoke:
 * every key under it is denied on every syscall.
 *
 * ── Integrator wiring (where each function is called) ──────────────────────
 *
 * The syscall layer resolves the owning Tenant ONCE per request and passes it
 * to these pure functions; nothing here re-queries.
 *
 *   // syscall gate() — resolve the tenant, deny suspended, then rate-limit:
 *   const tenant = await registry.resolveTenant(identity.namespace);
 *   tenantGate(tenant);                       // throws TenantSuspendedError → 403 + audit denied
 *   const limit = effectiveRateLimit(policy.rateLimitPerMin ?? null, tenant);
 *   if (limit !== null && !bucket.allow(identity.keyId, limit)) { ...429 + audit... }
 *
 *   // performWrite brownout — the tenant cap can pull brownout in early:
 *   const cap = effectiveBudgetUsd(policy.monthlyBudgetUsd ?? null, tenant);
 *   const brownedOut =
 *     cap !== null && (await budget.monthToDateUsd(identity.namespace)) >= cap;
 *
 * Ingestion (importDump/syncSource) and runFragmentation gate the same way:
 * resolve the tenant, call tenantGate(tenant) before doing any work.
 */

import type { Tenant } from "../types.js";

/**
 * The effective monthly USD spend cap = the MIN of the namespace policy cap and
 * the resolving tenant's `monthlyBudgetUsd`. `null` on either side means
 * "unlimited on that side" and so does not constrain; if BOTH are null the
 * result is null (truly unlimited). The tenant cap can only lower the effective
 * cap, never raise it above what the namespace policy allows.
 */
export function effectiveBudgetUsd(
  namespacePolicyCapUsd: number | null,
  tenant: Tenant | null,
): number | null {
  return minCap(namespacePolicyCapUsd, tenant?.monthlyBudgetUsd ?? null);
}

/**
 * The effective per-key rate limit (requests/min) = the MIN of the namespace
 * policy limit and the resolving tenant's `rateLimitPerMin`. Same null
 * semantics as {@link effectiveBudgetUsd}: null = unlimited on that side, both
 * null = null.
 */
export function effectiveRateLimit(
  namespacePolicyLimit: number | null,
  tenant: Tenant | null,
): number | null {
  return minCap(namespacePolicyLimit, tenant?.rateLimitPerMin ?? null);
}

/**
 * Thrown by {@link tenantGate} when the resolving tenant is suspended. The
 * syscall layer maps this to a denied outcome (403 + an audit row), exactly
 * like a revoked key — a suspended tenant is a bulk revoke of all its keys.
 */
export class TenantSuspendedError extends Error {
  constructor(message = "tenant is suspended") {
    super(message);
    this.name = "TenantSuspendedError";
  }
}

/**
 * Deny every syscall for a suspended tenant. PURE: it takes the ALREADY-resolved
 * Tenant (the syscall layer resolves once via TenantRegistry.resolveTenant and
 * passes it in) and throws {@link TenantSuspendedError} iff its status is
 * 'suspended'. A null tenant means no tenant is registered for this namespace,
 * which is allowed (the ancestor ACL still governs visibility).
 */
export function tenantGate(tenant: Tenant | null): void {
  if (tenant?.status === "suspended") {
    throw new TenantSuspendedError(`tenant '${tenant.id}' is suspended`);
  }
}

/**
 * MIN of two caps under "null = unlimited" semantics: null does not constrain,
 * so `min(null, x) === x` and `min(null, null) === null`.
 */
function minCap(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return Math.min(a, b);
}
