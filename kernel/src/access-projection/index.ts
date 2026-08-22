/**
 * M10 ACCESS — AccessProjectionService (CONTRACTS-M10-ACCESS.md, module
 * "projection"; PRD FR2/FR3).
 *
 * Resolves a server-owned `AccessProjection` for one subject from structural
 * dependencies only. This module imports NOTHING from db/auth/kernel — the
 * integrator binds `AccessProjectionDeps` to the real repositories. Locked
 * decisions in force here:
 *
 * - D9  — everything (tenant, role, grants, roots) is supplied by
 *         server-resolved deps keyed on an opaque subject ID. No namespace,
 *         role, actor, or tenant ever arrives from a request body.
 * - D40 — the projection is the ONLY authorization input for graph
 *         serialization; filtering happens in the query layer via
 *         `buildVisibilityPredicate` BEFORE anything is serialized.
 * - D42 — roles are ceilings, grants are locations. A member's poisoned
 *         `govern` grant is capped down to consume reach and never yields
 *         govern operations; an admin with zero govern grants has no
 *         functional admin reach.
 * - D44 — consume expands UPWARD (granted root + `/`-split prefix ancestors,
 *         exact IN lists — the EXISTING ancestor ACL rule; retrieval already
 *         implements it, this module documents and mirrors it in the
 *         predicate, it does not re-implement retrieval). Govern expands
 *         DOWNWARD (exact match + escaped-prefix LIKE with `ESCAPE '\'`).
 *         `_`, `%`, `\` in namespaces are ALWAYS literal.
 * - D47 — revoked/expired grants are ignored even if a dep leaks them;
 *         `version` (max over grant/membership counters) + `hash` strand
 *         stale caches on any change.
 * - D48 — the bare tenant namespace enters a member/admin predicate only
 *         when a common or tenant-root grant exists; `root-private` is never
 *         inherited by members or admins, even via a poisoned grant row.
 *
 * Fail-closed: any dependency failure throws `ProjectionUnavailableError`
 * (callers render "Access view unavailable") — never a broader projection,
 * never a silent fallback.
 *
 * Invalidation seam (where the integrator bumps versions): the grants
 * counter (`grantsVersionFor`) advances in `src/iam/access-grants.ts` on
 * every grant create and revoke; the membership counter
 * (`membershipVersionFor`) advances on team membership add/remove, member
 * role change, user role change, and user/tenant status change (the
 * `console/teams.ts` transaction seam and people/status mutations). A bump
 * changes `version`, which changes `hash`, which strands every cache entry
 * keyed on the old projection hash (D47).
 */

import { createHash } from "node:crypto";
import type { AccessGrantRecord, AccessProjection, Namespace, ProductHumanRole } from "../types.js";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown when a projection cannot be resolved (dependency failure, unknown
 * subject, empty tenant). Callers MUST treat this as "no access" and render
 * `Access view unavailable` — never fall back to a broader projection.
 */
export class ProjectionUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ProjectionUnavailableError";
  }
}

// ---------------------------------------------------------------------------
// Structural dependencies (D9: everything server-resolved, integrator-bound)
// ---------------------------------------------------------------------------

/** Namespace roots derived from team membership (server-resolved). */
export interface MembershipRoots {
  /** Function shared roots the memberships grant for reading (consume). */
  consumeRoots: readonly Namespace[];
  /** Exact member-personal spaces (never widened to siblings). */
  personalRoots: readonly Namespace[];
}

/**
 * Structural deps for `resolveProjection`. Every function is keyed on the
 * opaque server-owned subject ID; none accepts a caller-supplied namespace,
 * role, or tenant. `grantsFor` is expected to return only active grants
 * (unexpired, unrevoked) — this module re-filters defensively against
 * `now()` and the resolved tenant anyway, so a leaked revoked/expired/
 * cross-tenant row is still ignored (D47).
 */
export interface AccessProjectionDeps {
  /** Tenant ROOT namespace for the subject; null when unknown. */
  tenantOf(subjectId: string): Promise<string | null>;
  /**
   * PRODUCT role for the subject (already translated by
   * `src/iam/product-roles.ts`: owner->root, auditor->member+audit_read
   * grant); null when unknown.
   */
  roleOf(subjectId: string): Promise<ProductHumanRole | null>;
  /** Active grants for the subject (defensively re-filtered here). */
  grantsFor(subjectId: string): Promise<readonly AccessGrantRecord[]>;
  /** Membership-derived roots (the teams.ts transaction seam keeps these in lockstep with membership grants). */
  membershipRootsFor(subjectId: string): Promise<MembershipRoots>;
  /**
   * Resolve an opaque grant resource ID to its namespace root inside the
   * tenant; null when the resource is unknown or foreign (the grant is then
   * ignored — fail closed). Callers never supply namespace strings (D9).
   */
  resourceRootOf(
    tenantId: string,
    resourceType: AccessGrantRecord["resourceType"],
    resourceId: string,
  ): Promise<Namespace | null>;
  /** Monotonic counter bumped on grant create/revoke (access-grants.ts). */
  grantsVersionFor(subjectId: string): Promise<number>;
  /** Monotonic counter bumped on membership/role/user-status/tenant-status change. */
  membershipVersionFor(subjectId: string): Promise<number>;
  /** Injected clock (tests use a fake). */
  now(): Date;
}

/** The subject a projection is resolved for — an opaque server-owned ID. */
export interface ProjectionSubject {
  subjectId: string;
}

// ---------------------------------------------------------------------------
// Operations (role ceiling × grant mode — D42)
// ---------------------------------------------------------------------------

/** Operation vocabulary the projection emits. */
export const PROJECTION_OPERATIONS = {
  graphRead: "graph:read",
  memoryRead: "memory:read",
  memorySearch: "memory:search",
  contextAssemble: "context:assemble",
  delegateCreate: "delegate:create",
  memoryGovern: "memory:govern",
  grantsManage: "grants:manage",
  auditRead: "audit:read",
} as const;

const ALL_OPERATIONS: readonly string[] = Object.values(PROJECTION_OPERATIONS);

const CONSUME_OPERATIONS: readonly string[] = [
  PROJECTION_OPERATIONS.memoryRead,
  PROJECTION_OPERATIONS.memorySearch,
  PROJECTION_OPERATIONS.contextAssemble,
  PROJECTION_OPERATIONS.delegateCreate,
];

const GOVERN_OPERATIONS: readonly string[] = [
  PROJECTION_OPERATIONS.memoryGovern,
  PROJECTION_OPERATIONS.grantsManage,
];

// ---------------------------------------------------------------------------
// Namespace helpers (local mirrors — this module may not import db/index)
// ---------------------------------------------------------------------------

/**
 * `/`-split prefix ancestors, self included — mirrors
 * `namespaceAncestors` in `src/index/index.ts` exactly (the EXISTING
 * ancestor ACL rule; do not diverge).
 */
function ancestorsOf(namespace: Namespace): string[] {
  const parts = namespace.split("/").filter((p) => p.length > 0);
  const out: string[] = [];
  for (let i = 1; i <= parts.length; i++) {
    out.push(parts.slice(0, i).join("/"));
  }
  return out.length > 0 ? out : [namespace];
}

/**
 * Escape SQL LIKE metacharacters (`\`, `%`, `_`) — byte-for-byte the same
 * as `escapeLikePattern` in `src/db/client.ts`; pair with `ESCAPE '\'`.
 * Without this, `_`/`%` inside a namespace act as wildcards and match
 * SIBLING namespaces.
 */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * True when `ns` is the tenant root or strictly inside its subtree.
 *
 * Tenant "" is the UNPREFIXED ORGANIZATION (single-org installs). Its roots
 * are any non-empty namespace; exclusion of registered customer tenants
 * happens where the roots are resolved (view-as scoping + the kernel's
 * simulation-root filter), because it needs a `tenants` lookup. This branch
 * is only reachable via the explicit organization-root opt-in below —
 * ordinary empty-tenant subjects still fail closed.
 */
function tenantBound(tenantId: string, ns: string): boolean {
  if (tenantId === "") return ns !== "";
  return ns === tenantId || ns.startsWith(tenantId + "/");
}

/** True when `ns` is the tenant's root-private branch or inside it. */
function inRootPrivate(tenantId: string, ns: string): boolean {
  const rp = tenantId === "" ? "root-private" : tenantId + "/root-private";
  return ns === rp || ns.startsWith(rp + "/");
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

// ---------------------------------------------------------------------------
// resolveProjection
// ---------------------------------------------------------------------------

function asVersion(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new ProjectionUnavailableError(`projection unavailable: bad ${label} version`);
  }
  return Math.floor(value);
}

/**
 * Resolve the effective `AccessProjection` for one subject. Fail-closed:
 * any dep failure or unknown subject/tenant/role throws
 * `ProjectionUnavailableError` — never a broader projection.
 */
export async function resolveProjection(
  deps: AccessProjectionDeps,
  subject: ProjectionSubject,
  opts?: {
    /**
     * Explicit opt-in for the "" ORGANIZATION-ROOT tenant (single-org
     * installs). Only the View-as simulation path sets this, with roots
     * pre-filtered against registered tenants, and never for role "root"
     * (a tenant-wide "" predicate would be global — D9). Everything else
     * keeps failing closed on an empty tenant.
     */
    allowOrganizationRootTenant?: boolean;
  },
): Promise<AccessProjection> {
  const { subjectId } = subject;
  let tenantId: string | null;
  let role: ProductHumanRole | null;
  let grants: readonly AccessGrantRecord[];
  let membership: MembershipRoots;
  let grantsVersionRaw: number;
  let membershipVersionRaw: number;
  try {
    tenantId = await deps.tenantOf(subjectId);
    role = await deps.roleOf(subjectId);
    grants = await deps.grantsFor(subjectId);
    membership = await deps.membershipRootsFor(subjectId);
    grantsVersionRaw = await deps.grantsVersionFor(subjectId);
    membershipVersionRaw = await deps.membershipVersionFor(subjectId);
  } catch (err) {
    if (err instanceof ProjectionUnavailableError) throw err;
    // Brownout to "no access", never a broader projection (contract rule 12).
    throw new ProjectionUnavailableError("projection unavailable: dependency failure", {
      cause: err,
    });
  }

  if (role === null) {
    throw new ProjectionUnavailableError("projection unavailable: subject has no role");
  }
  if (!tenantId || tenantId.length === 0) {
    // An empty tenant would make every "tenant-wide" predicate global (D9).
    // Sole exception: the organization-root simulation opt-in (never for
    // role "root", whose predicate is tenant-wide by construction).
    if (!(opts?.allowOrganizationRootTenant === true && role !== "root")) {
      throw new ProjectionUnavailableError("projection unavailable: subject has no tenant");
    }
    tenantId = "";
  }

  const version = Math.max(
    asVersion(grantsVersionRaw, "grants"),
    asVersion(membershipVersionRaw, "membership"),
  );
  const nowMs = deps.now().getTime();

  // Defensive re-filter (D47/D9): tenant-bound, this principal, unrevoked,
  // unexpired. A leaked foreign/revoked/expired row contributes nothing.
  const effective = grants.filter((g) => {
    if (g.tenantId !== tenantId) return false;
    if (g.principalId !== subjectId) return false;
    if (g.revokedAt !== null) return false;
    if (g.expiresAt !== null) {
      const exp = Date.parse(g.expiresAt);
      if (!Number.isFinite(exp) || exp <= nowMs) return false; // unparsable = expired (fail closed)
    }
    return true;
  });

  const consume = new Set<string>();
  const govern = new Set<string>();
  const personal = new Set<string>();
  let hasAuditRead = false;

  const admitRoot = (root: string | null): root is string => {
    if (root === null || root.length === 0) return false;
    if (!tenantBound(tenantId, root)) return false; // cross-tenant poison ignored
    // D48: root-private is never inherited by members or admins — a poisoned
    // grant row pointing at it is dropped for every non-root role.
    if (role !== "root" && inRootPrivate(tenantId, root)) return false;
    return true;
  };

  for (const grant of effective) {
    if (grant.accessMode === "audit_read") {
      // Scoped audit entitlement (D41: auditor = member + audit_read). It
      // adds the audit:read operation, not graph visibility roots.
      hasAuditRead = true;
      continue;
    }
    const root = await deps.resourceRootOf(tenantId, grant.resourceType, grant.resourceId);
    if (!admitRoot(root)) continue;
    if (grant.accessMode === "govern" && role !== "member") {
      // Govern implies consume (PRD §6), so the root is readable too.
      govern.add(root);
      consume.add(root);
    } else if (grant.resourceType === "personal") {
      // Exact member space — never widened (a member's poisoned govern
      // grant lands here at its consume ceiling, D42).
      personal.add(root);
    } else {
      consume.add(root);
    }
  }

  for (const root of membership.consumeRoots) {
    if (admitRoot(root)) consume.add(root);
  }
  for (const root of membership.personalRoots) {
    if (admitRoot(root)) personal.add(root);
  }

  // Root role: tenant-wide reach, still tenant-bound — never empty/global.
  if (role === "root") {
    consume.add(tenantId);
    govern.add(tenantId);
    hasAuditRead = true;
  }

  const consumeRoots = sortedUnique(consume);
  const governRoots = sortedUnique(govern);
  const personalRoots = sortedUnique(personal);

  const ops = new Set<string>([PROJECTION_OPERATIONS.graphRead]);
  if (role === "root") {
    for (const op of ALL_OPERATIONS) ops.add(op);
  } else {
    if (consumeRoots.length > 0 || personalRoots.length > 0) {
      for (const op of CONSUME_OPERATIONS) ops.add(op);
    }
    // D42: govern operations need BOTH the role ceiling (admin+) and at
    // least one govern grant. An admin with zero govern grants has none.
    if (role === "admin" && governRoots.length > 0) {
      for (const op of GOVERN_OPERATIONS) ops.add(op);
    }
    if (hasAuditRead) ops.add(PROJECTION_OPERATIONS.auditRead);
  }

  const projection: AccessProjection = {
    tenantId,
    subjectId,
    role,
    consumeRoots,
    governRoots,
    personalRoots,
    allowedOperations: [...ops].sort(),
    version,
    hash: "",
  };
  return { ...projection, hash: hashProjection(projection) };
}

// ---------------------------------------------------------------------------
// hashProjection
// ---------------------------------------------------------------------------

/** Everything the hash covers; the `hash` field itself is excluded. */
export type ProjectionHashInput = Omit<AccessProjection, "hash"> & { hash?: string };

/**
 * Stable sha256 hex over the projection's authorization-relevant fields.
 * Arrays are sorted and fields serialized in a fixed order, so the hash is
 * independent of array ordering and object key order, and changes when any
 * root, role, operation, version, subject, sensitivity ceiling, or tenant
 * changes. This is the cache-partitioning key (D47, contract rule 7).
 */
export function hashProjection(p: ProjectionHashInput): string {
  const canonical = JSON.stringify([
    "halomem.access-projection.v1",
    p.tenantId,
    p.subjectId,
    p.role,
    sortedUnique(p.consumeRoots),
    sortedUnique(p.governRoots),
    sortedUnique(p.personalRoots),
    sortedUnique(p.allowedOperations),
    p.sensitivityCeiling ?? null,
    p.version,
  ]);
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// buildVisibilityPredicate
// ---------------------------------------------------------------------------

/** A parameterized SQL boolean expression over a namespace column. */
export interface VisibilityPredicate {
  /** Parenthesized boolean expression; matches nothing when `(FALSE)`. */
  sql: string;
  params: string[];
}

export interface VisibilityPredicateOptions {
  /** Column the predicate tests (default `namespace`). */
  column?: string;
  /** How many `$n` placeholders precede this fragment (default 0 → `$1`). */
  paramOffset?: number;
}

/**
 * The shared query-layer predicate (D40/D44):
 *
 * - consume roots expand UPWARD into an exact `IN (...)` list of each root
 *   plus its `/`-split prefix ancestors (the existing ancestor ACL rule);
 *   personal roots enter the exact list as-is (exact member spaces).
 * - govern roots expand DOWNWARD:
 *   `col = $n OR col LIKE $n+1 ESCAPE '\'` with the escaped prefix, so
 *   `_`, `%`, `\` in namespaces stay literal and sibling
 *   `acme/functions/marketing2` is never matched by root
 *   `acme/functions/marketing`.
 * - D48: the bare tenant namespace enters the exact list only when a
 *   common (`<tenant>/common`) or tenant-root grant exists, or the subject
 *   is root; the root-private branch never appears for non-root roles.
 * - Root role (governRoots contain the tenant) yields a tenant-wide,
 *   still tenant-BOUND clause — never an empty or global predicate.
 * - An empty projection yields `(FALSE)` — matches nothing, fail closed.
 */
export function buildVisibilityPredicate(
  projection: AccessProjection,
  options?: VisibilityPredicateOptions,
): VisibilityPredicate {
  const column = options?.column ?? "namespace";
  const offset = options?.paramOffset ?? 0;
  const { tenantId, role } = projection;
  if (!tenantId || tenantId.length === 0) {
    // A blank tenant would turn "tenant-wide" into "global" — refuse (D9).
    throw new ProjectionUnavailableError("visibility predicate unavailable: empty tenant");
  }

  const admit = (ns: string): boolean =>
    ns.length > 0 &&
    tenantBound(tenantId, ns) &&
    (role === "root" || !inRootPrivate(tenantId, ns));

  // D48: bare tenant only with an explicit common/tenant grant (or root).
  const allowBareTenant =
    role === "root" ||
    projection.governRoots.includes(tenantId) ||
    projection.consumeRoots.includes(tenantId) ||
    projection.consumeRoots.includes(tenantId + "/common");

  const exact = new Set<string>();
  for (const root of projection.consumeRoots) {
    if (!admit(root)) continue;
    for (const ancestor of ancestorsOf(root)) {
      if (admit(ancestor)) exact.add(ancestor);
    }
  }
  for (const root of projection.personalRoots) {
    if (admit(root)) exact.add(root);
  }
  if (!allowBareTenant) exact.delete(tenantId);

  const governRoots = sortedUnique(projection.governRoots).filter(admit);
  // Roots already covered by a govern subtree are redundant in the exact set.
  const exactList = sortedUnique(exact).filter(
    (ns) => !governRoots.some((g) => ns === g || ns.startsWith(g + "/")),
  );

  const params: string[] = [];
  const clauses: string[] = [];
  const bind = (value: string): string => {
    params.push(value);
    return `$${offset + params.length}`;
  };

  if (exactList.length > 0) {
    const placeholders = exactList.map(bind).join(", ");
    clauses.push(`${column} IN (${placeholders})`);
  }
  for (const root of governRoots) {
    // Exact match + escaped-prefix subtree — same shape as the repo's ACL
    // SQL (`namespace = $1 OR namespace LIKE $2 ESCAPE '\'`).
    clauses.push(`(${column} = ${bind(root)} OR ${column} LIKE ${bind(escapeLike(root) + "/%")} ESCAPE '\\')`);
  }

  if (clauses.length === 0) return { sql: "(FALSE)", params: [] };
  return { sql: `(${clauses.join(" OR ")})`, params };
}

/**
 * The projection's read reach as ROOTS (the structural twin of
 * `buildVisibilityPredicate`, for callers that need namespace lists instead
 * of SQL — e.g. the retrieval read-scope seam): consume roots ancestor-
 * expanded and tenant-clamped into `exact`, personal roots exact, govern
 * roots as downward `prefixes`. Same admit rules (tenant-bound, root-private
 * only for root, D48 bare-tenant gate); an empty projection yields empty
 * lists — fail closed.
 */
export function projectionReadRoots(projection: AccessProjection): {
  exact: string[];
  prefixes: string[];
} {
  const { tenantId, role } = projection;
  if (!tenantId || tenantId.length === 0) {
    throw new ProjectionUnavailableError("read roots unavailable: empty tenant");
  }
  const admit = (ns: string): boolean =>
    ns.length > 0 &&
    tenantBound(tenantId, ns) &&
    (role === "root" || !inRootPrivate(tenantId, ns));
  const allowBareTenant =
    role === "root" ||
    projection.governRoots.includes(tenantId) ||
    projection.consumeRoots.includes(tenantId) ||
    projection.consumeRoots.includes(tenantId + "/common");
  const exact = new Set<string>();
  for (const root of projection.consumeRoots) {
    if (!admit(root)) continue;
    for (const ancestor of ancestorsOf(root)) {
      if (admit(ancestor)) exact.add(ancestor);
    }
  }
  for (const root of projection.personalRoots) {
    if (admit(root)) exact.add(root);
  }
  if (!allowBareTenant) exact.delete(tenantId);
  const prefixes = sortedUnique(projection.governRoots).filter(admit);
  const exactList = sortedUnique(exact).filter(
    (ns) => !prefixes.some((g) => ns === g || ns.startsWith(g + "/")),
  );
  return { exact: exactList, prefixes };
}

// ---------------------------------------------------------------------------
// Invalidation seam
// ---------------------------------------------------------------------------

/**
 * Cheap current-version check for a subject — the invalidation seam. A
 * cached projection (or anything keyed on its hash) is stale as soon as
 * this exceeds the cached `version`; re-resolve then.
 *
 * The integrator bumps the underlying counters at:
 * - grant create / revoke        -> grants counter (`src/iam/access-grants.ts`)
 * - team membership add / remove -> membership counter (`console/teams.ts` tx seam)
 * - member/user role change      -> membership counter
 * - user or tenant status change -> membership counter
 */
export async function projectionVersionFor(
  deps: Pick<AccessProjectionDeps, "grantsVersionFor" | "membershipVersionFor">,
  subjectId: string,
): Promise<number> {
  try {
    const [grantsVersion, membershipVersion] = await Promise.all([
      deps.grantsVersionFor(subjectId),
      deps.membershipVersionFor(subjectId),
    ]);
    return Math.max(asVersion(grantsVersion, "grants"), asVersion(membershipVersion, "membership"));
  } catch (err) {
    if (err instanceof ProjectionUnavailableError) throw err;
    throw new ProjectionUnavailableError("projection version unavailable: dependency failure", {
      cause: err,
    });
  }
}
