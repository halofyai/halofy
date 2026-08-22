/**
 * M10 integrator binding — `AccessProjectionDeps` over the real stores.
 *
 * `src/access-projection/index.ts` is deliberately structural (it imports
 * nothing but types + node:crypto); this module is the ONE place its deps are
 * bound to the live database and `AccessGrantStore` (D9: every value is
 * server-resolved from an opaque subject id; nothing here reads a request).
 *
 * Version counters (contract rule 7 / D47) are DERIVED from append-only
 * state, so they are monotonic across processes with no extra table:
 *  - grants counter  = COUNT(rows) + COUNT(revoked rows) for the principal —
 *    a create bumps the first term, a revoke bumps the second, rows are
 *    never deleted (D7).
 *  - membership counter = COUNT of membership/role/invitation audit rows in
 *    the subject's tenant subtree — `audit_log` is append-only (D4), so the
 *    count only grows. Tenant-wide by design: any roster/role change in the
 *    tenant advances every member's version (over-invalidation is fail-safe).
 *
 * The projection itself is resolved FRESH on every request (there is no
 * cross-request projection cache), so a revoked grant is effective on the
 * next request even without the counters; the counters exist so the
 * projection `hash` — the cache-partition key for anything derived — changes
 * whenever authorization state changes.
 */

import type {
  AccessProjectionDeps,
  MembershipRoots,
} from "../access-projection/index.js";
import { resolveProjection } from "../access-projection/index.js";
import type { AccessGrantRecord, AccessProjection, Namespace, ProductHumanRole } from "../types.js";
import { escapeLikePattern, type Db } from "../db/client.js";
import type { AccessGrantStore } from "./access-grants.js";
import { toProductRole } from "./product-roles.js";

/** Tenant ROOT namespace = the first `/`-segment ("acme/x" → "acme"). */
export function tenantRootOfNamespace(namespace: Namespace): Namespace {
  const idx = namespace.indexOf("/");
  return idx === -1 ? namespace : namespace.slice(0, idx);
}

export interface ProjectionBinding {
  db: Db;
  grants: AccessGrantStore;
  now?: () => Date;
}

interface SubjectRow {
  id: string;
  namespace: string;
  role: string;
  status: string;
}

async function subjectRow(db: Db, subjectId: string): Promise<SubjectRow | null> {
  const res = await db.query(
    `SELECT id, namespace, role, status FROM users WHERE id = $1`,
    [subjectId],
  );
  return (res.rows[0] as SubjectRow | undefined) ?? null;
}

/**
 * Audit purposes whose append advances the membership counter: team roster
 * changes, member role changes, and invitation acceptances. Appended rows are
 * immutable, so the count is monotonic.
 */
const MEMBERSHIP_AUDIT_PURPOSES = [
  "console-team-member-add",
  "console-team-member-remove",
  "console-team-member-role-change",
  "console-team-create",
  "console-invitation-accept",
  "console-invitation-accept-sso",
] as const;

/**
 * The real-user deps bundle. Every function re-reads the user row so role,
 * status, and namespace changes take effect on the next request with no
 * cache to invalidate (fail-closed: missing/disabled user → null role).
 */
export function userProjectionDeps(bind: ProjectionBinding): AccessProjectionDeps {
  const now = bind.now ?? (() => new Date());
  return {
    async tenantOf(subjectId: string): Promise<string | null> {
      const row = await subjectRow(bind.db, subjectId);
      if (row === null) return null;
      return tenantRootOfNamespace(row.namespace);
    },

    async roleOf(subjectId: string): Promise<ProductHumanRole | null> {
      const row = await subjectRow(bind.db, subjectId);
      if (row === null || row.status !== "active") return null;
      // The ONE D41 seam: owner → root, auditor → member (+ audit_read below).
      return toProductRole(row.role).role;
    },

    async grantsFor(subjectId: string): Promise<readonly AccessGrantRecord[]> {
      const row = await subjectRow(bind.db, subjectId);
      if (row === null || row.status !== "active") return [];
      const tenantId = tenantRootOfNamespace(row.namespace);
      const rows: AccessGrantRecord[] = await bind.grants.listEffectiveGrants(
        tenantId,
        subjectId,
        now(),
      );
      if (row.role === "auditor") {
        // D41: a legacy internal auditor surfaces as member + a scoped
        // audit:read entitlement. Synthesized read-only here (no write on a
        // read path); `ensureAuditReadGrant` persists it when roles change
        // through the console.
        rows.push({
          id: `auditor-role:${subjectId}`,
          tenantId,
          principalType: "human",
          principalId: subjectId,
          resourceType: "audit",
          resourceId: "audit",
          accessMode: "audit_read",
          source: "system",
          createdBy: "system",
          createdAt: now().toISOString(),
          expiresAt: null,
          revokedAt: null,
        });
      }
      return rows;
    },

    async membershipRootsFor(subjectId: string): Promise<MembershipRoots> {
      const row = await subjectRow(bind.db, subjectId);
      if (row === null || row.status !== "active") {
        return { consumeRoots: [], personalRoots: [] };
      }
      const tenantId = tenantRootOfNamespace(row.namespace);
      const consume = new Set<string>();
      // The subject's home namespace reads via the existing ancestor ACL rule.
      if (row.namespace.length > 0) consume.add(row.namespace);
      // D48: <tenant>/common is the explicit broadcast space every tenant
      // member reads. Team/function reach comes ONLY through access_grants
      // (one permission system — the roster is synced to grants in the same
      // transaction, and a revoked grant must not survive via the roster).
      if (tenantId.length > 0) consume.add(`${tenantId}/common`);
      return { consumeRoots: [...consume], personalRoots: [] };
    },

    async resourceRootOf(
      tenantId: string,
      _resourceType: AccessGrantRecord["resourceType"],
      resourceId: string,
    ): Promise<Namespace | null> {
      const roots = await bind.grants.resolveResourceRoots(tenantId, [resourceId]);
      return roots.get(resourceId) ?? null;
    },

    async grantsVersionFor(subjectId: string): Promise<number> {
      const res = await bind.db.query(
        `SELECT COUNT(*)::int AS created, COUNT(revoked_at)::int AS revoked
           FROM access_grants WHERE principal_id = $1`,
        [subjectId],
      );
      const row = res.rows[0] as { created?: unknown; revoked?: unknown } | undefined;
      return (Number(row?.created) || 0) + (Number(row?.revoked) || 0);
    },

    async membershipVersionFor(subjectId: string): Promise<number> {
      const row = await subjectRow(bind.db, subjectId);
      if (row === null) return 0;
      const tenantId = tenantRootOfNamespace(row.namespace);
      const placeholders = MEMBERSHIP_AUDIT_PURPOSES.map((_, i) => `$${i + 1}`).join(", ");
      // Fail closed: an empty tenant never widens to a cross-tenant count.
      // (resolveProjection rejects empty-tenant subjects anyway — D9.)
      const scope = tenantId === ""
        ? "FALSE"
        : `(namespace = $${MEMBERSHIP_AUDIT_PURPOSES.length + 1}
            OR namespace LIKE $${MEMBERSHIP_AUDIT_PURPOSES.length + 2} ESCAPE '\\')`;
      const params: string[] = [...MEMBERSHIP_AUDIT_PURPOSES];
      if (tenantId !== "") params.push(tenantId, escapeLikePattern(tenantId) + "/%");
      const res = await bind.db.query(
        `SELECT COUNT(*)::int AS n FROM audit_log
          WHERE purpose IN (${placeholders}) AND ${scope}`,
        params,
      );
      return Number((res.rows[0] as { n?: unknown } | undefined)?.n) || 0;
    },

    now,
  };
}

/**
 * Root View-as role simulation (D43): the caller (kernel) has already
 * resolved the selected functional areas to namespace roots INSIDE the
 * root's tenant via `AccessGrantStore.resolveResourceRoots` — unknown and
 * foreign areas are simply absent from `areaRoots` and contribute nothing.
 * The synthetic grants carry `govern` for a simulated admin (D42 gives it
 * consume too) and `consume` for a simulated member.
 */
export function simulatedRoleProjection(
  bind: ProjectionBinding,
  tenantId: Namespace,
  role: Exclude<ProductHumanRole, "root">,
  areaRoots: ReadonlyMap<string, Namespace>,
): Promise<AccessProjection> {
  const now = bind.now ?? (() => new Date());
  const subjectId = `view-as:role:${role}:${[...areaRoots.keys()].sort().join(",")}`;
  const ts = now().toISOString();
  const grants: AccessGrantRecord[] = [...areaRoots.keys()].sort().map((areaId) => ({
    id: `view-as:${areaId}`,
    tenantId,
    principalType: "human",
    principalId: subjectId,
    resourceType: "function",
    resourceId: areaId,
    accessMode: role === "admin" ? "govern" : "consume",
    source: "system",
    createdBy: "view-as",
    createdAt: ts,
    expiresAt: null,
    revokedAt: null,
  }));
  const deps: AccessProjectionDeps = {
    tenantOf: async () => tenantId,
    roleOf: async () => role,
    grantsFor: async () => grants,
    membershipRootsFor: async () => ({
      consumeRoots: tenantId.length > 0 ? [`${tenantId}/common`] : [],
      personalRoots: [],
    }),
    resourceRootOf: async (_tenant, _type, resourceId) =>
      areaRoots.get(resourceId) ?? null,
    grantsVersionFor: async () => 0,
    membershipVersionFor: async () => 0,
    now,
  };
  // Organization-root ("") simulations are legal: the kernel pre-filters
  // areaRoots against registered tenants, and the simulated role is never
  // "root" (see resolveProjection's opt-in guard).
  return resolveProjection(deps, { subjectId }, { allowOrganizationRootTenant: true });
}
