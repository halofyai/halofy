/**
 * Module B (M5 part 1) — management-API completeness: the read models the nine
 * control-room screens need. Each handler is `(kernel, identity, params?) →
 * data`, subtree/ACL-scoped, and REUSES existing kernel machinery (retrieval,
 * stats, sources, policy, audit) rather than reimplementing any of it. No
 * handler mutates: the console reads through these; the write dials stay on the
 * existing admin routes.
 *
 * Scoping is the SAME exact-IN-list ACL every other read path uses
 * (`namespaceAncestors` → `namespace IN (...)`, NEVER a LIKE wildcard):
 *   - an `owner` (root/empty namespace) sees org-wide;
 *   - an `admin`/`auditor`/`member` sees ONLY its own subtree;
 *   - a sibling namespace's rows never appear.
 * A caller-supplied namespace (memoryMap) is first asserted to be inside the
 * caller's subtree, so a team admin can never point a screen at a sibling.
 *
 * To avoid a hard import cycle with kernel.ts, the handlers depend on a
 * structural {@link KernelSlice} — the subset of the concrete Kernel they use.
 * The real Kernel satisfies it.
 */

import { createHash } from "node:crypto";
import type { Db } from "../db/client.js";
import { buildVisibilityPredicate } from "../access-projection/index.js";
import {
  companyPublishedSql,
  namespaceAncestors,
  TTL_ACTIVE_CLAUSE,
} from "../index/index.js";
import { sourceAccessSubject } from "../syscalls/index.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import type { AuditLog, AuditSearchFilters, AuditSummary } from "../audit/index.js";
import { trimRepeatedCharacter } from "../strings.js";
import { buildSyncOverview } from "./rollups/sync-overview.js";
import type { SourceOverviewRow } from "./rollups/sync-overview.js";
import { buildSourceLineage } from "./rollups/source-lineage.js";
import type { SourceLineage } from "./rollups/source-lineage.js";
import { HUMAN_ROLE_PERMISSIONS, canHuman } from "./rbac.js";
import { toPublicUser } from "../iam/product-roles.js";
import type {
  AccessProjection,
  AuditEvent,
  AuditOp,
  Identity,
  MemoryGraphEdge,
  MemoryGraphNode,
  MemoryGraphResponse,
  MemoryGraphScopeOption,
  MemoryId,
  MemoryPin,
  Namespace,
  PolicyDocumentEnforcement,
  PolicyDocumentKind,
  PolicyDocumentStatus,
  Tenant,
} from "../types.js";

// ---------------------------------------------------------------------------
// Structural kernel slice (the real Kernel satisfies this — no hard cycle)
// ---------------------------------------------------------------------------

/** A source row as the SourceRegistry hands it back (mirror of SourceRow). */
export interface ConsoleSourceRow {
  id: string;
  namespace: Namespace;
  kind: string;
  config: Record<string, unknown>;
  createdAt: string;
  lastSync: string | null;
  credentialId?: string | null;
  syncStatus?: "never_synced" | "pending" | "synced" | "failed";
  lastSyncError?: string | null;
  lastSyncStartedAt?: string | null;
  lifecycleState?: "active" | "paused" | "disabled";
  syncIntervalSeconds?: number | null;
  nextSyncAt?: string | null;
  consecutiveFailures?: number;
}

/** A human user row (mirror of types.User) as listUsers returns it. */
export interface ConsoleUser {
  id: string;
  email: string;
  displayName: string;
  avatar?: string | null;
  namespace: Namespace;
  role: string;
  status: string;
  createdAt: string;
}

/** An agent badge (API key) record as auth.list returns it. */
export interface ConsoleBadge {
  id: string;
  namespace: Namespace;
  actor: string;
  role: string;
  status: string;
  createdAt: string;
  lastUsed: string | null;
}

/** Effective, merged policy for a namespace (subset used by the screens). */
export interface ConsolePolicy {
  pinnedConcepts: string[];
  tokenBudget: number;
  monthlyBudgetUsd?: number;
  retriever?: string;
  abTest?: { a: string; b: string; pctB: number };
}

/**
 * The subset of the concrete Kernel the console read models consume. The real
 * `Kernel` satisfies this structurally; a hand-rolled slice satisfies it in
 * tests. `listUsers` is the integrator-wired human-user lister (Module A) —
 * declared here so Module B does not depend on Module A's class.
 */
export interface KernelSlice {
  readonly db: Db;
  readonly audit: AuditLog;
  readonly auth: { list(identity: Identity): Promise<ConsoleBadge[]> };
  readonly sources: {
    list(namespace: Namespace, global?: boolean): Promise<ConsoleSourceRow[]>;
  };
  readonly budget: { monthToDateUsd(namespace: Namespace): Promise<number> };
  readonly tenants: {
    resolveTenant(namespace: Namespace): Promise<Tenant | null>;
  };
  /** Human roster visible to the caller (ancestor-subtree scoped, Module A). */
  listUsers(identity: Identity): Promise<ConsoleUser[]>;
  /** Effective (merged) policy for a namespace — reused for pins/cap/retriever. */
  getPolicy(namespace: Namespace): Promise<ConsolePolicy>;
  /**
   * M10 (integrator-wired): membership ↔ access_grants sync. Optional so
   * hand-rolled test slices stay valid; when present, team roster mutations
   * call it INSIDE their own transaction (one permission system — the review
   * attacks roster/grant drift).
   */
  readonly membershipGrants?: MembershipGrantSyncLike;
  /**
   * The open-conflict count S11 lists. S6 quotes it instead of deriving its own
   * conflict number. Optional so hand-rolled test slices stay valid; absent
   * means the tile reports the count as unavailable rather than inventing one.
   */
  countOpenConflicts?(identity: Identity): Promise<number>;
}

/** Structural subset of `AccessGrantStore` the teams seam consumes (M10). */
export interface MembershipGrantSyncLike {
  syncMembershipGrant(
    tx: Db,
    input: {
      tenantId: string;
      userId: string;
      teamOrFunctionId: string;
      action: "add" | "remove" | "update";
      actor: string;
      /** Derived from the member's INTERNAL role at the seam; default consume. */
      accessMode?: "consume" | "govern";
    },
  ): Promise<void>;
}

/** One hot (top-accessed) fact for the memory map (mirror of MemStats.topAccessed[n]). */
export interface HotFact {
  id: MemoryId;
  content: string;
  accessCount: number;
  pinnable: boolean;
}

// ---------------------------------------------------------------------------
// Shared scoping helpers (identical discipline to the syscall ACL path)
// ---------------------------------------------------------------------------

/**
 * Assert `ns` is inside the caller's subtree (root owner → anywhere; everyone
 * else, including tenant owners → own subtree). Mirrors the transport's `assertAdminScope` so a screen can
 * never be pointed at a sibling namespace. Throws AuthzError (→ 403) otherwise.
 */
function assertInSubtree(identity: Identity, ns: Namespace): void {
  if (isRootOwner(identity)) return;
  if (isSelfOrDescendant(ns, identity.namespace)) return;
  throw new AuthzError(
    `role '${identity.role}' may not view namespace '${ns}' (outside your subtree)`,
  );
}

/**
 * A `namespace`-column predicate scoped to the caller's subtree, as a
 * fragment + params starting at `$startAt`. For a non-root caller this is an
 * exact IN-list over the ancestor set PLUS every descendant (a subtree read —
 * a team admin's overview must count its children's facts). Descendants are
 * matched with an escaped `LIKE ... ESCAPE` (so `_`/`%` in the namespace are
 * literal, never wildcards). For an owner at the root the predicate is
 * `TRUE` (org-wide). Returns { sql, params }.
 */
function subtreePredicate(
  identity: Identity,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  if (isRootOwner(identity)) return { sql: "TRUE", params: [] };
  const ancestors = namespaceAncestors(identity.namespace);
  if (ancestors.length === 0) return { sql: "FALSE", params: [] };
  const params: string[] = [];
  let n = startAt;
  const inList = ancestors.map(() => `$${n++}`).join(", ");
  params.push(...ancestors);
  // Descendants of the caller's namespace: caller/%  (escaped so `_`/`%` in the
  // namespace are literal — the ACL wildcard hazard the repo has hit twice).
  const likeParam = `$${n++}`;
  params.push(escapeLike(identity.namespace) + "/%");
  return {
    sql: `(${column} IN (${inList}) OR ${column} LIKE ${likeParam} ESCAPE '\\')`,
    params,
  };
}

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * A `namespace`-column predicate for `ns` itself PLUS all its descendants,
 * starting at `$startAt`. Exact-match on `ns`, escaped `LIKE ns/%` for the
 * descendants (so `_`/`%` in the namespace are literal). Used by the memoryMap
 * screen, which is about ONE namespace's own subtree (not the read-down
 * ancestor set — a namespace's map is its own facts + its children's).
 */
function namespaceSubtreePredicate(
  ns: Namespace,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  // The organization root owns every namespace. An empty root cannot use the
  // normal `root/%` descendant shape because real namespaces omit that slash.
  if (ns === "") return { sql: "TRUE", params: [] };

  const selfParam = `$${startAt}`;
  const likeParam = `$${startAt + 1}`;
  return {
    sql: `(${column} = ${selfParam} OR ${column} LIKE ${likeParam} ESCAPE '\\')`,
    params: [ns, escapeLike(ns) + "/%"],
  };
}

/**
 * M10: the legacy memory-map subtree predicate routed through the SHARED
 * `AccessProjectionService` predicate builder — one authorization engine,
 * two serializations. A selected namespace behaves exactly like a govern
 * root (exact match + escaped-prefix subtree, D44), which is byte-identical
 * SQL to the previous `namespaceSubtreePredicate` output; the platform root
 * ("" — every namespace) keeps its existing TRUE shape because a projection
 * is always tenant-bound and never global (D9).
 */
function sharedSubtreePredicate(
  ns: Namespace,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  if (ns === "") return namespaceSubtreePredicate(ns, startAt, column);
  const tenantId = ns.includes("/") ? ns.slice(0, ns.indexOf("/")) : ns;
  const synthetic: AccessProjection = {
    tenantId,
    subjectId: "console-memory-map",
    role: "root",
    consumeRoots: [],
    governRoots: [ns],
    personalRoots: [],
    allowedOperations: [],
    version: 0,
    hash: "",
  };
  return buildVisibilityPredicate(synthetic, { column, paramOffset: startAt - 1 });
}

/**
 * Exact active memory mounts inherited by `ns`. This mirrors the central
 * MountedVisibilityResolver query: exact namespace ancestors, active segment
 * and member, non-revoked mount, and a currently readable L2 target.
 */
async function mountedMemoryRefs(db: Db, ns: Namespace): Promise<string[]> {
  const targets = namespaceAncestors(ns);
  if (targets.length === 0) return [];
  const placeholders = targets.map((_, index) => `$${index + 1}`).join(", ");
  const result = await db.query(
    `SELECT DISTINCT member.target_ref
       FROM segment_mounts mount
       JOIN memory_segments segment ON segment.id = mount.segment_id
       JOIN segment_members member
         ON member.segment_id = segment.id AND member.removed_at IS NULL
       JOIN memory_objects memory
         ON member.target_kind = 'memory' AND memory.id = member.target_ref
      WHERE mount.target_namespace IN (${placeholders})
        AND mount.revoked_at IS NULL
        AND segment.status = 'active'
        AND memory.status = 'active'
        AND memory.t_valid_to IS NULL
        AND ${TTL_ACTIVE_CLAUSE.replaceAll("ttl_seconds", "memory.ttl_seconds").replaceAll("assertion_time", "memory.assertion_time")}`,
    targets,
  );
  return result.rows.map((row) => String(row.target_ref));
}

/**
 * The distinct namespaces present in `audit_log` that fall inside the caller's
 * subtree (ancestors, own namespace, and descendants). Used to hand
 * {@link AuditLog.search} an EXACT enumerated IN-list — the search itself never
 * needs a LIKE. An admin at `org/support` must see its DESCENDANTS' rows
 * (`org/support/triage`), which the ancestor-only read-down set omits, so the
 * console's subtree model is own-namespace-plus-descendants (mirroring
 * `assertAdminScope`/`isSelfOrDescendant`), not the read-down ancestor set.
 */
async function subtreeAuditNamespaces(
  db: Db,
  identity: Identity,
): Promise<Namespace[]> {
  const pred = subtreePredicate(identity, 1);
  const res = await db.query(
    `SELECT DISTINCT namespace FROM audit_log WHERE ${pred.sql}`,
    pred.params,
  );
  return (res.rows as { namespace: string }[]).map((r) => r.namespace);
}

// ---------------------------------------------------------------------------
// S2 — overview
// ---------------------------------------------------------------------------

export interface OverviewChild {
  namespace: Namespace;
  l2Active: number;
}

/** One configured model profile, ranked by governed Copilot completions. */
export interface OverviewModel {
  profileId: string;
  name: string;
  provider: string;
  model: string;
  isDefault: boolean;
  completions: number;
}

/** One provenance bucket: facts contributed by a source (or conversation). */
export interface OverviewSourceUsage {
  id: string;
  kind: string;
  namespace: Namespace | null;
  facts: number;
}

/** One connected source (subtree-scoped, policy-uploads excluded). */
export interface OverviewConnectedSource {
  id: string;
  kind: string;
  namespace: Namespace;
  syncStatus: string;
  lastSync: string | null;
}

/** A ranked leaderboard row (team namespace or actor). */
export interface OverviewLeader {
  /** Immutable actor/team key used by filters and authorization. */
  name: string;
  /** Human-facing label when `name` identifies a person. */
  displayName?: string;
  count: number;
}

export interface OverviewQuerySummary {
  total: number;
  hits: number;
  misses: number;
  hitRate: number;
  topQueries: RepeatLookup[];
}

export interface OverviewAgentAccess {
  /** Agent badges (API keys with the agent role) visible in the subtree. */
  totalAgents: number;
  /** Agents with zero denied syscalls AND zero denied gateway reads. */
  withinPolicy: number;
  /** Agents that asked for more than their permissions, worst first. */
  overreaching: { actor: string; denied: number }[];
  /** Gateway source-read decisions (agent_access_events). */
  accessEvents: { allowed: number; denied: number; error: number };
  /** Escalation requests for extra access (agent_access_requests). */
  accessRequests: {
    pending: number;
    approved: number;
    denied: number;
    expired: number;
    consumed: number;
  };
}

export interface OverviewHomeCounts {
  skills: number;
  channels: number;
  agents: number;
  policies: number;
  conflicts: number;
}

export interface Overview {
  namespace: Namespace;
  /**
   * The reporting window every activity figure below was counted over, or null
   * for the all-time view. Home renders this so a windowed number is never
   * mistaken for an all-time one.
   */
  windowDays: number | null;
  /** Inclusive lower bound of the window as ISO-8601, or null when all-time. */
  since: string | null;
  children: OverviewChild[];
  l2Active: number;
  faultCount: number;
  faultHitRate: number;
  spend: {
    monthToDateUsd: number;
    effectiveCapUsd: number | null;
  };
  tokensSavedEstimate: number;
  /** Metered LLM + embedding usage from the cost ledger, over the window. */
  usage: {
    totalTokens: number;
    totalUsd: number;
    /**
     * Spend split by the ingestion source that triggered it (v94), largest
     * first. `sourceId: null` groups untagged rows: assistant/chat, platform
     * lanes, and pre-v94 history.
     */
    bySource: {
      sourceId: string | null;
      sourceKind: string | null;
      tokens: number;
      usd: number;
    }[];
  };
  /** Configured model profiles ranked by completions, most-used first. */
  models: OverviewModel[];
  /** Connected sources + the top provenance contributors. */
  sourcesSummary: {
    connectedCount: number;
    connected: OverviewConnectedSource[];
    top: OverviewSourceUsage[];
  };
  /** Teams (immediate children) ranked by memory calls, busiest first. */
  topTeams: OverviewLeader[];
  /** Actors (individuals/agents) ranked by memory calls, busiest first. */
  topActors: OverviewLeader[];
  /** Heuristic categorization of query purposes, biggest bucket first. */
  queryCategories: { category: string; count: number }[];
  querySummary: OverviewQuerySummary;
  /** Successful governed memory writes, rolled up by the owning team. */
  memoryWrites: { total: number; teams: OverviewLeader[] };
  /** Compact totals for the redesigned Home Overview card. */
  homeCounts: OverviewHomeCounts;
  agentAccess: OverviewAgentAccess;
}

/** Longest Home reporting window a caller may ask for. */
export const MAX_OVERVIEW_WINDOW_DAYS = 365;

export interface OverviewParams {
  /**
   * Home's reporting window in days (S2's 7/30/90 control). Absent, zero, or
   * unparseable means the all-time view — the historical behaviour.
   */
  days?: number;
}

/**
 * Home's window, clamped to 1..365 days. Anything that is not a usable day
 * count collapses to null (all-time) rather than to an empty dashboard.
 */
function overviewWindowDays(days: unknown): number | null {
  const n = Number(days);
  if (!Number.isFinite(n)) return null;
  const whole = Math.floor(n);
  if (whole < 1) return null;
  return Math.min(whole, MAX_OVERVIEW_WINDOW_DAYS);
}

/**
 * A `<column> >= $startAt` guard for the active window, or `TRUE` when the
 * view is all-time. Returned with its params so callers can prepend it to a
 * subtree predicate that starts one slot later.
 */
function sincePredicate(
  since: string | null,
  startAt: number,
  column: string,
): { sql: string; params: string[] } {
  return since === null
    ? { sql: "TRUE", params: [] }
    : { sql: `${column} >= $${startAt}`, params: [since] };
}

/**
 * S2 aggregate for the caller's subtree: per-immediate-child L2 active counts,
 * fault-rate + hit-rate off the audit log, month-to-date spend vs the effective
 * cap (cost_ledger + the tenant cap), and a tokens-saved estimate summed from
 * `assemble` audit rows. All figures are subtree-scoped to what the caller may
 * see; a sibling namespace never contributes.
 *
 * `params.days` is Home's reporting window. With it set, every ACTIVITY figure
 * — audit-derived leaderboards, writes, queries, faults, metered usage, agent
 * access events — counts only rows inside the window, and the memory counts
 * become "saved in the window" (`t_valid_from`). INVENTORY and configuration
 * figures (connected sources, model profiles, skills/channels/policies/
 * conflicts, agent badges, open access requests) and the month-to-date billing
 * numbers are deliberately NOT windowed: they describe the org as it stands
 * now, and a 7-day cut of "how many policies exist" is not a real number. The
 * response carries `windowDays`/`since` so the screen can label which is which.
 */
export async function overview(
  kernel: KernelSlice,
  identity: Identity,
  params: OverviewParams = {},
): Promise<Overview> {
  const windowDays = overviewWindowDays(params.days);
  const since =
    windowDays === null
      ? null
      : new Date(Date.now() - windowDays * 86_400_000).toISOString();
  const pred = subtreePredicate(identity, 1);
  /**
   * Subtree scope AND the reporting window on `column`. The window binds $1
   * when active, so the subtree predicate starts one slot later; the all-time
   * view degrades to `TRUE AND <subtree>` and keeps the original $1 shape.
   */
  const windowed = (column: string): { sql: string; params: string[] } => {
    const w = sincePredicate(since, 1, column);
    const p = subtreePredicate(identity, w.params.length + 1);
    return { sql: `${w.sql} AND ${p.sql}`, params: [...w.params, ...p.params] };
  };

  // Immediate children: active memory_objects' namespaces one level below the
  // caller's namespace, derived from the store (NOT a hard-coded org chart).
  // Windowed, this is "children that saved memory in the window".
  const memPred = windowed("t_valid_from");
  const nsRes = await kernel.db.query(
    `SELECT DISTINCT namespace FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL
       AND ${TTL_ACTIVE_CLAUSE} AND ${memPred.sql}`,
    memPred.params,
  );
  const base = identity.namespace;
  const childCounts = new Map<Namespace, number>();
  for (const r of nsRes.rows as { namespace: string }[]) {
    const child = immediateChild(base, r.namespace);
    if (child !== null && !childCounts.has(child)) childCounts.set(child, 0);
  }

  // L2 active count per child (exact-match — a child's OWN facts, plus its
  // descendants roll up under it) and the subtree total.
  const l2Pred = windowed("t_valid_from");
  const l2Res = await kernel.db.query(
    `SELECT namespace, count(*) AS n FROM memory_objects
     WHERE tier = 'L2' AND status = 'active' AND t_valid_to IS NULL
       AND ${TTL_ACTIVE_CLAUSE} AND ${l2Pred.sql}
     GROUP BY namespace`,
    l2Pred.params,
  );
  let l2Active = 0;
  for (const r of l2Res.rows as { namespace: string; n: unknown }[]) {
    const n = Number(r.n);
    l2Active += n;
    const child = immediateChild(base, r.namespace);
    if (child !== null) childCounts.set(child, (childCounts.get(child) ?? 0) + n);
  }

  // Fault + assemble + leaderboard + query rows off the audit log,
  // subtree-scoped. One pass feeds every audit-derived aggregate below.
  const auditPred = windowed("ts");
  const auditRes = await kernel.db.query(
    `SELECT op, result, detail, actor, namespace, purpose
     FROM audit_log WHERE ${auditPred.sql}`,
    auditPred.params,
  );
  const auditRows = auditRes.rows as {
    op: string;
    result: string;
    detail: string | null;
    actor: string;
    namespace: string;
    purpose: string | null;
  }[];
  const faultRows = auditRows.filter((r) => r.op === "fault");
  const faultCount = faultRows.length;
  const faultHits = faultRows.filter((r) => r.result === "ok").length;
  const faultMisses = faultRows.filter((r) => r.result === "miss").length;
  const faultHitRate =
    faultHits + faultMisses > 0 ? faultHits / (faultHits + faultMisses) : 0;

  // Tokens-saved estimate: sum the working-set token totals the allocator
  // recorded on its `assemble` rows (each assembled block is context the agent
  // did NOT have to re-derive from raw history).
  let tokensSavedEstimate = 0;
  for (const r of auditRows) {
    if (r.op !== "assemble" || r.result !== "ok" || !r.detail) continue;
    const t = extractAssembleTokens(r.detail);
    if (t !== null) tokensSavedEstimate += t;
  }

  // Spend vs the effective cap. month-to-date spend is exact for the caller's
  // namespace subtree (BudgetGuard already sums descendants). The effective cap
  // is the MIN of the namespace policy cap and the owning tenant's cap.
  const monthToDateUsd = await kernel.budget.monthToDateUsd(base);
  const policy = await kernel.getPolicy(base);
  const tenant = await kernel.tenants.resolveTenant(base);
  const effectiveCapUsd = minCap(
    policy.monthlyBudgetUsd ?? null,
    tenant?.monthlyBudgetUsd ?? null,
  );

  const children: OverviewChild[] = [...childCounts.entries()]
    .map(([namespace, l2ActiveChild]) => ({ namespace, l2Active: l2ActiveChild }))
    .sort((a, b) => (a.namespace < b.namespace ? -1 : a.namespace > b.namespace ? 1 : 0));

  // --- metered usage off the cost ledger (LLM + embeddings), in-window ------
  const costPred = windowed("ts");
  const costRes = await kernel.db.query(
    `SELECT COALESCE(SUM(tokens), 0) AS tokens, COALESCE(SUM(usd), 0) AS usd
     FROM cost_ledger WHERE ${costPred.sql}`,
    costPred.params,
  );
  const costRow = costRes.rows[0] as { tokens?: unknown; usd?: unknown } | undefined;
  // Per-source split (v94): ingestion rows carry the sources.id that
  // triggered the spend — "Linear cost this team X this week". Untagged
  // rows (assistant/chat, platform lanes, pre-v94 history) group under the
  // null source. LEFT JOIN: a deleted source keeps its historical spend.
  const sourceWindow = sincePredicate(since, 1, "cl.ts");
  const sourceScope = subtreePredicate(identity, sourceWindow.params.length + 1, "cl.namespace");
  const costBySourceRes = await kernel.db.query(
    `SELECT cl.source AS source_id, MAX(s.kind) AS source_kind,
            COALESCE(SUM(cl.tokens), 0) AS tokens, COALESCE(SUM(cl.usd), 0) AS usd
       FROM cost_ledger cl LEFT JOIN sources s ON s.id = cl.source
      WHERE ${sourceWindow.sql} AND ${sourceScope.sql}
      GROUP BY cl.source ORDER BY SUM(cl.usd) DESC`,
    [...sourceWindow.params, ...sourceScope.params],
  );
  const usage = {
    totalTokens: Number(costRow?.tokens ?? 0),
    totalUsd: Number(costRow?.usd ?? 0),
    bySource: (costBySourceRes.rows as {
      source_id?: unknown; source_kind?: unknown; tokens?: unknown; usd?: unknown;
    }[]).map((row) => ({
      sourceId: row.source_id === null || row.source_id === undefined ? null : String(row.source_id),
      sourceKind: row.source_kind === null || row.source_kind === undefined ? null : String(row.source_kind),
      tokens: Number(row.tokens ?? 0),
      usd: Number(row.usd ?? 0),
    })),
  };

  // --- model profiles ranked by governed Copilot completions ----------------
  // The copilot audits every completion with detail `profile=<id>; ...`, so
  // usage per profile is counted off the already-fetched audit rows.
  const completionsByProfile = new Map<string, number>();
  for (const r of auditRows) {
    if (r.op !== "complete" || !r.detail) continue;
    const m = /(?:^|;\s*)profile=([^;\s]+)/.exec(r.detail);
    if (!m || m[1] === "unavailable" || m[1] === "unresolved") continue;
    completionsByProfile.set(m[1], (completionsByProfile.get(m[1]) ?? 0) + 1);
  }
  const profilePred = subtreePredicate(identity, 1, "p.namespace");
  const profileRes = await kernel.db.query(
    `SELECT p.id, p.name, p.model, p.is_default, c.provider
     FROM model_profiles p
     JOIN model_connections c ON c.id = p.connection_id
     WHERE p.status = 'active' AND ${profilePred.sql}`,
    profilePred.params,
  );
  const models: OverviewModel[] = (profileRes.rows as {
    id: string;
    name: string;
    model: string;
    is_default: unknown;
    provider: string;
  }[])
    .map((r) => ({
      profileId: r.id,
      name: r.name,
      provider: r.provider,
      model: r.model,
      isDefault: r.is_default === true || r.is_default === "t",
      completions: completionsByProfile.get(r.id) ?? 0,
    }))
    .sort(
      (a, b) =>
        b.completions - a.completions ||
        (a.model < b.model ? -1 : a.model > b.model ? 1 : 0),
    );

  // --- sources: connected list + top provenance contributors ----------------
  const sourceRows = await kernel.sources.list(base, isRootOwner(identity));
  const connected: OverviewConnectedSource[] = sourceRows
    .filter((s) => s.kind !== "policy-upload")
    .map((s) => ({
      id: s.id,
      kind: s.kind,
      namespace: s.namespace,
      syncStatus: s.syncStatus ?? (s.lastSync ? "synced" : "never_synced"),
      lastSync: s.lastSync,
    }));
  const kindById = new Map(connected.map((s) => [s.id, s.kind]));
  const nsById = new Map(connected.map((s) => [s.id, s.namespace]));
  // Facts per provenance bucket: the stamped sourceId when an importer wrote
  // the fact, else the provenance `source` label (agent conversation).
  const provPred = windowed("t_valid_from");
  const provRes = await kernel.db.query(
    `SELECT COALESCE(prov.entry->>'sourceId', prov.entry->>'source', 'unknown') AS bucket,
            count(DISTINCT memory_objects.id) AS n
     FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
     WHERE status = 'active' AND t_valid_to IS NULL
       AND ${TTL_ACTIVE_CLAUSE} AND ${provPred.sql}
     GROUP BY 1 ORDER BY n DESC`,
    provPred.params,
  );
  const top: OverviewSourceUsage[] = (provRes.rows as {
    bucket: string;
    n: unknown;
  }[]).map((r) => ({
    id: r.bucket,
    kind: kindById.get(r.bucket) ?? r.bucket,
    namespace: nsById.get(r.bucket) ?? null,
    facts: Number(r.n),
  }));

  // --- leaderboards: memory calls by team and by actor ----------------------
  // "unknown" actors are the transport's unauthenticated-request denials —
  // real audit rows, but noise on a usage leaderboard.
  const READ_OPS = new Set(["read", "search", "fault", "assemble", "complete"]);
  const readRows = auditRows.filter(
    (r) => READ_OPS.has(r.op) && r.actor !== "unknown",
  );
  const actorCounts = new Map<string, number>();
  for (const r of readRows) {
    actorCounts.set(r.actor, (actorCounts.get(r.actor) ?? 0) + 1);
  }
  // Teams roll up to the immediate child of the caller's namespace. When that
  // collapses to a single bucket (e.g. the org root sees only "halofy"), step
  // one level deeper until the rollup actually differentiates teams.
  let teamBase = base;
  let teamCounts = rollupTeams(readRows, teamBase);
  for (let depth = 0; depth < 5 && teamCounts.size === 1; depth++) {
    const only = [...teamCounts.keys()][0]!;
    if (only === teamBase) break;
    const deeper = rollupTeams(readRows, only);
    if (deeper.size <= 1 && deeper.has(only)) break;
    teamBase = only;
    teamCounts = deeper;
  }
  const topTeams = rankLeaders(teamCounts);

  // --- successful memory writes by team ------------------------------------
  // A denied/error audit outcome still matters in Audit, but the Home donut is
  // deliberately "memory written", so only successful governed writes count.
  const writeRows = auditRows.filter((r) => r.op === "write" && r.result === "ok");
  let writeBase = base;
  let writeTeamCounts = rollupTeams(writeRows, writeBase);
  for (let depth = 0; depth < 5 && writeTeamCounts.size === 1; depth++) {
    const only = [...writeTeamCounts.keys()][0]!;
    if (only === writeBase) break;
    const deeper = rollupTeams(writeRows, only);
    if (deeper.size <= 1 && deeper.has(only)) break;
    writeBase = only;
    writeTeamCounts = deeper;
  }
  const memoryWrites = { total: writeRows.length, teams: rankLeaders(writeTeamCounts) };
  // Classify machine actors with the exact same namespace predicate as the
  // audit rows above. The public key-list API is deliberately narrower for
  // members and non-root admins, so it cannot safely classify this aggregate.
  const agentActorResult = await kernel.db.query(
    `SELECT DISTINCT actor FROM api_keys WHERE role = 'agent' AND ${pred.sql}`,
    pred.params,
  );
  const agentActorKeys = new Set(
    (agentActorResult.rows as Array<{ actor: string }>).map((row) => row.actor.toLowerCase()),
  );
  const badges = await kernel.auth.list(identity);
  const agentBadges = badges.filter((b) => b.role === "agent");
  const badgeActors = new Set(agentBadges.map((b) => b.actor));
  // Resolve labels only for actor strings already present in this scoped
  // aggregate. This covers visible ancestor activity without broadening the
  // people roster and excludes every actor proven to be a machine above.
  const humanActorKeys = [...actorCounts.keys()]
    .map((actor) => actor.toLowerCase())
    .filter((actor) => !agentActorKeys.has(actor));
  const peopleByEmail = new Map<string, string>();
  if (humanActorKeys.length > 0) {
    const actorParams = [...new Set(humanActorKeys)];
    const placeholders = actorParams.map((_, index) => `$${index + 1}`).join(", ");
    const peopleResult = await kernel.db.query(
      `SELECT lower(email) AS actor_key, display_name
         FROM users
        WHERE lower(email) IN (${placeholders})
          AND display_name IS NOT NULL`,
      actorParams,
    );
    for (const row of peopleResult.rows as Array<{ actor_key: string; display_name: string }>) {
      peopleByEmail.set(row.actor_key, row.display_name.trim());
    }
  }
  const topActors = rankLeaders(actorCounts, peopleByEmail);

  // --- query summary + heuristic categorization -----------------------------
  const queryRows = auditRows.filter(
    (r) => (r.op === "search" || r.op === "fault") && r.purpose !== null,
  );
  const queryCounts = new Map<string, number>();
  const categoryCounts = new Map<string, number>();
  let queryHits = 0;
  let queryMisses = 0;
  for (const r of queryRows) {
    if (r.result === "ok") queryHits += 1;
    else if (r.result === "miss") queryMisses += 1;
    const q = r.purpose as string;
    queryCounts.set(q, (queryCounts.get(q) ?? 0) + 1);
    const cat = categorizeQuery(q);
    categoryCounts.set(cat, (categoryCounts.get(cat) ?? 0) + 1);
  }
  const querySummary: OverviewQuerySummary = {
    total: queryRows.length,
    hits: queryHits,
    misses: queryMisses,
    hitRate:
      queryHits + queryMisses > 0 ? queryHits / (queryHits + queryMisses) : 0,
    topQueries: [...queryCounts.entries()]
      .map(([query, count]) => ({ query, count }))
      .sort(byCountDesc)
      .slice(0, 5),
  };
  const queryCategories = [...categoryCounts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || (a.category < b.category ? -1 : 1));

  // --- agent data-access compliance -----------------------------------------
  // Badges are the agent population; denied audit rows (D4 writes every denial)
  // plus denied gateway reads (agent_access_events) mark the overreachers.
  const actorByKeyId = new Map(badges.map((b) => [b.id, b.actor]));

  const deniedByActor = new Map<string, number>();
  for (const r of auditRows) {
    if (r.result !== "denied" || !badgeActors.has(r.actor)) continue;
    deniedByActor.set(r.actor, (deniedByActor.get(r.actor) ?? 0) + 1);
  }

  const eventPred = windowed("created_at");
  const eventRes = await kernel.db.query(
    `SELECT key_id, decision, count(*) AS n
     FROM agent_access_events WHERE ${eventPred.sql}
     GROUP BY key_id, decision`,
    eventPred.params,
  );
  const accessEvents = { allowed: 0, denied: 0, error: 0 };
  for (const r of eventRes.rows as {
    key_id: string;
    decision: string;
    n: unknown;
  }[]) {
    const n = Number(r.n);
    if (r.decision === "allowed") accessEvents.allowed += n;
    else if (r.decision === "denied") accessEvents.denied += n;
    else accessEvents.error += n;
    if (r.decision === "denied") {
      const actor = actorByKeyId.get(r.key_id) ?? r.key_id;
      deniedByActor.set(actor, (deniedByActor.get(actor) ?? 0) + n);
    }
  }

  const requestPred = subtreePredicate(identity, 1);
  const requestRes = await kernel.db.query(
    `SELECT status, count(*) AS n
     FROM agent_access_requests WHERE ${requestPred.sql}
     GROUP BY status`,
    requestPred.params,
  );
  const accessRequests = {
    pending: 0,
    approved: 0,
    denied: 0,
    expired: 0,
    consumed: 0,
  };
  for (const r of requestRes.rows as { status: string; n: unknown }[]) {
    if (r.status in accessRequests) {
      accessRequests[r.status as keyof typeof accessRequests] = Number(r.n);
    }
  }

  const overreaching = [...deniedByActor.entries()]
    .map(([actor, denied]) => ({ actor, denied }))
    .sort((a, b) => b.denied - a.denied || (a.actor < b.actor ? -1 : 1));
  const overreachingActors = new Set(overreaching.map((o) => o.actor));
  const agentAccess: OverviewAgentAccess = {
    totalAgents: agentBadges.length,
    withinPolicy: agentBadges.filter((b) => !overreachingActors.has(b.actor))
      .length,
    overreaching,
    accessEvents,
    accessRequests,
  };

  // --- compact Home overview totals ----------------------------------------
  const skillPred = subtreePredicate(identity, 1);
  const channelPred = subtreePredicate(identity, 1);
  const policyPred = subtreePredicate(identity, 1);
  const conflictPred = subtreePredicate(identity, 1, "target_namespace");
  const [skillCount, channelCount, policyCount, conflictCount] = await Promise.all([
    kernel.db.query(
      `SELECT count(*) AS n FROM skills
        WHERE status = 'active' AND t_valid_to IS NULL AND ${skillPred.sql}`,
      skillPred.params,
    ),
    kernel.db.query(
      `SELECT count(*) AS n FROM channel_connections
        WHERE lifecycle_state <> 'disconnected' AND ${channelPred.sql}`,
      channelPred.params,
    ),
    kernel.db.query(
      `SELECT count(*) AS n FROM policies WHERE ${policyPred.sql}`,
      policyPred.params,
    ),
    kernel.db.query(
      `SELECT count(*) AS n FROM conflict_scan_findings
        WHERE status = 'open' AND ${conflictPred.sql}`,
      conflictPred.params,
    ),
  ]);
  const countOf = (result: { rows: unknown[] }): number =>
    Number((result.rows[0] as { n?: unknown } | undefined)?.n ?? 0);
  const homeCounts: OverviewHomeCounts = {
    skills: countOf(skillCount),
    channels: countOf(channelCount),
    agents: agentAccess.totalAgents,
    policies: countOf(policyCount),
    conflicts: countOf(conflictCount),
  };

  return {
    namespace: base,
    windowDays,
    since,
    children,
    l2Active,
    faultCount,
    faultHitRate,
    spend: { monthToDateUsd, effectiveCapUsd },
    tokensSavedEstimate,
    usage,
    models,
    sourcesSummary: { connectedCount: connected.length, connected, top },
    topTeams,
    topActors,
    queryCategories,
    querySummary,
    memoryWrites,
    homeCounts,
    agentAccess,
  };
}

/** Ranked leaderboard rows from a name→count map, busiest first. */
function rankLeaders(
  counts: Map<string, number>,
  displayNames: ReadonlyMap<string, string> = new Map(),
): OverviewLeader[] {
  return [...counts.entries()]
    .map(([name, count]) => {
      const displayName = displayNames.get(name.toLowerCase());
      return { name, ...(displayName ? { displayName } : {}), count };
    })
    .sort((a, b) => b.count - a.count || (a.name < b.name ? -1 : 1));
}

/** Group read rows by the immediate child of `base` (rows at `base` keep it). */
function rollupTeams(
  rows: { namespace: string }[],
  base: Namespace,
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const team = immediateChild(base, r.namespace) ?? r.namespace;
    counts.set(team, (counts.get(team) ?? 0) + 1);
  }
  return counts;
}

/**
 * Heuristic query categorization for the overview's "where do queries come
 * from" buckets. Keyword-based on purpose (query) text — first matching
 * category wins; no match → "Other". Deterministic, no LLM involved.
 */
const QUERY_CATEGORY_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  [
    "Sales",
    /\b(sales?|deals?|discounts?|pricing|quotes?|pipeline|prospects?|crm|revenue|upsell|renewals?)\b/,
  ],
  [
    "Marketing",
    /\b(marketing|campaigns?|brand|seo|newsletters?|social|launch|audience|ads?|webinars?)\b/,
  ],
  [
    "Coding",
    /\b(code|coding|bugs?|deploys?|deployment|apis?|builds?|tests?|errors?|servers?|database|schema|migrations?|releases?|incidents?|repo|typescript|python)\b/,
  ],
  [
    "Research",
    /\b(research|study|studies|analysis|analy[sz]e|benchmarks?|compare|comparison|evaluat\w*|papers?|surveys?|insights?|trends?)\b/,
  ],
  [
    "Support",
    /\b(support|tickets?|refunds?|customers?|complaints?|sla|escalat\w*|faq|troubleshoot\w*|returns?)\b/,
  ],
  [
    "Finance",
    /\b(finance|budgets?|costs?|spend|expenses?|invoices?|forecasts?|payroll|billing)\b/,
  ],
  [
    "Operations",
    /\b(operations?|ops|schedules?|procurement|logistics|inventory|onboard\w*|hiring|recruit\w*|hr)\b/,
  ],
];

/** @internal exported for tests */
export function categorizeQuery(purpose: string): string {
  const q = purpose.toLowerCase();
  // Score every category by how many keyword hits it lands ("build test error
  // in the release pipeline" is Coding×4 over Sales×1 for "pipeline"); the
  // highest score wins, ties break by rule order.
  let best = "Other";
  let bestHits = 0;
  for (const [category, rule] of QUERY_CATEGORY_RULES) {
    const hits = q.match(new RegExp(rule.source, "g"))?.length ?? 0;
    if (hits > bestHits) {
      best = category;
      bestHits = hits;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// S3 — people
// ---------------------------------------------------------------------------

export interface People {
  users: ConsoleUser[];
  badges: ConsoleBadge[];
  accessModel: typeof HUMAN_ROLE_PERMISSIONS;
}

export interface TeamDirectory {
  users: ConsoleUser[];
  accessModel: typeof HUMAN_ROLE_PERMISSIONS;
}

/** Human-only directory for Teams; never queries or returns agent badges. */
export async function teamDirectory(
  kernel: KernelSlice,
  identity: Identity,
): Promise<TeamDirectory> {
  if (!canHuman(identity.role, "teams:read")) {
    throw new AuthzError(`role '${identity.role}' may not read the team directory`);
  }
  return {
    // D41: internal roles never cross the console boundary — owner surfaces
    // as `root`, auditor as `member` + the `audit:read` entitlement.
    users: (await kernel.listUsers(identity)).map((u) => toPublicUser(u)),
    accessModel: HUMAN_ROLE_PERMISSIONS,
  };
}

/**
 * Shared directory payload used by Teams and Agents: human users are
 * ancestor-subtree scoped, while agent badges come from the caller's scoped
 * lists are already scoped by their own ACL — a sibling team's people and
 * badges never appear.
 */
export async function people(
  kernel: KernelSlice,
  identity: Identity,
): Promise<People> {
  const [users, badges] = await Promise.all([
    kernel.listUsers(identity),
    kernel.auth.list(identity),
  ]);
  // D41: human users carry product roles at the boundary (owner -> root,
  // auditor -> member + audit:read). Badges are CREDENTIALS, not humans —
  // their key-type surface is owned by M9 ProductKeyType, left untouched.
  return {
    users: users.map((u) => toPublicUser(u)),
    badges,
    accessModel: HUMAN_ROLE_PERMISSIONS,
  };
}

// ---------------------------------------------------------------------------
// S5 — memory map
// ---------------------------------------------------------------------------

export interface RepeatLookup {
  query: string;
  count: number;
}

export type MemoryTopologyRouting =
  | { mode: "fixed"; name: string }
  | { mode: "ab-test"; a: string; b: string; pctB: number };

export interface MemoryTopologySource {
  id: string;
  namespace: Namespace;
  kind: string;
  /**
   * A bounded, newest-first sample of documents synced by this connector.
   * Knowledge-base ingestion sources never enter this projection: their
   * uploads live exclusively under `knowledgeBases` below.
   */
  documents: MemoryTopologySourceDocument[];
  /** Exact post-authorization total, even when `documents` is sampled. */
  documentCount: number;
  syncStatus: "never_synced" | "pending" | "synced" | "failed";
  lastSync: string | null;
  lastSyncError: string | null;
  lifecycleState: "active" | "paused" | "disabled";
}

export interface MemoryTopologySourceDocument {
  /** Stable source-local document key; paired with the parent source id. */
  id: string;
  /** Best available content-safe label, falling back to the document key. */
  name: string;
  syncedAt: string;
}

export interface MemoryTopologyMemory {
  id: MemoryId;
  namespace: Namespace;
  label: string;
  type: string;
  tier: "L2" | "L3";
  accessCount: number;
  state: "current" | "older";
  supersedes: MemoryId | null;
  sourceIds: string[];
}

/**
 * Maximum individual memories placed in one graph topology. This is separate
 * from the paginated graph-node cap: ordinary organizations such as Halofy
 * (730 current L2 memories) must not be truncated to a tiny visual sample.
 */
export const MEMORY_TOPOLOGY_NODE_CAP = 1000;

export interface MemoryTopologyAgent {
  id: string;
  namespace: Namespace;
  actor: string;
}

export interface MemoryTopologyFile {
  id: string;
  sourceId: string;
  name: string;
  status: "processing" | "ready" | "needs_review" | "failed";
  factCount: number;
}

export interface MemoryTopologyKnowledgeBase {
  id: string;
  namespace: Namespace;
  name: string;
  kind: "file" | "folder" | "url";
  status: "empty" | "processing" | "ready" | "needs_review" | "failed";
  sourceId: string | null;
  files: MemoryTopologyFile[];
}

export interface MemoryTopologySkill {
  id: string;
  namespace: Namespace;
  key: string;
  name: string;
  vettingStatus: "unvetted" | "vetting" | "vetted" | "blocked";
  safetyScore: number | null;
}

/**
 * One governed policy document whose directives reach agents in this scope.
 * `inherited` marks a document that lives at an ancestor namespace — the same
 * inheritance the guardrail lane and the query-layer ACL use.
 */
export interface MemoryTopologyPolicy {
  id: string;
  namespace: Namespace;
  title: string;
  kind: PolicyDocumentKind;
  enforcement: PolicyDocumentEnforcement;
  status: PolicyDocumentStatus;
  factCount: number;
  inherited: boolean;
}

export interface MemoryTopology {
  scope: "selected-subtree";
  sources: MemoryTopologySource[];
  activeFacts: number;
  activityFacts: number;
  /** Additive, content-safe count from the team's effective company view. */
  companyPublishedFacts: number;
  memories: MemoryTopologyMemory[];
  knowledgeBases: MemoryTopologyKnowledgeBase[];
  skills: MemoryTopologySkill[];
  agents: MemoryTopologyAgent[];
  /** Guardrails governing this scope — the policy lane of the memory graph. */
  policies: MemoryTopologyPolicy[];
  routing: MemoryTopologyRouting;
}

/**
 * These source rows are immutable provenance anchors for governed document
 * lanes, not connector backends. Knowledge-base anchors render under their
 * own hierarchy; policy-upload anchors render from `policy_documents` under
 * Policies. Neither may appear in the Backends register or topology branch.
 */
const NON_BACKEND_SOURCE_KINDS = new Set([
  "filesystem",
  "file-upload",
  "doc_site",
  "policy-upload",
]);

const TOPOLOGY_SOURCE_DOCUMENT_SAMPLE = 5;

function isBackendSourceKind(kind: unknown): boolean {
  return !NON_BACKEND_SOURCE_KINDS.has(String(kind ?? ""));
}

interface TopologySourceDocumentRow {
  source_id: string;
  document_key: string;
  document_label: string | null;
  synced_at: Date | string;
  document_count: unknown;
}

/**
 * Read a bounded per-backend sample while retaining each backend's exact
 * authorized document total. Both the source namespace and the document's
 * landing namespace must be visible; this prevents a broadly mounted
 * connector from revealing a document routed into a hidden sibling.
 */
async function topologySourceDocuments(
  db: Db,
  sourcePredicate: { sql: string; params: string[] },
  landingPredicate: { sql: string; params: string[] },
): Promise<TopologySourceDocumentRow[]> {
  const params = [...sourcePredicate.params, ...landingPredicate.params];
  const result = await db.query(
    `WITH ranked_backend_documents AS (
       SELECT sd.source_id, sd.document_key, sd.synced_at,
              document.document_label,
              ROW_NUMBER() OVER (
                PARTITION BY sd.source_id
                ORDER BY sd.synced_at DESC, sd.document_key ASC
              ) AS document_rank,
              COUNT(*) OVER (PARTITION BY sd.source_id) AS document_count
         FROM source_documents sd
         JOIN sources s ON s.id = sd.source_id
         LEFT JOIN LATERAL (
           SELECT COALESCE(
                    NULLIF(BTRIM(m.display_title), ''),
                    NULLIF(BTRIM(SPLIT_PART(m.content, E'\n', 1)), '')
                  ) AS document_label
             FROM memory_objects m
            WHERE m.namespace = sd.landing_namespace
              AND m.status = 'active'
              AND m.t_valid_to IS NULL
              AND ${TTL_ACTIVE_CLAUSE}
              AND ${GRAPH_SOURCE_ACL_OPEN}
              AND ${GRAPH_CONTEXT_ELIGIBLE}
              AND EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(COALESCE(m.provenance, '[]'::jsonb)) p
                 WHERE p->>'sourceId' = sd.source_id
                   AND p->>'documentKey' = sd.document_key
              )
            ORDER BY m.assertion_time DESC, m.id ASC
            LIMIT 1
         ) document ON TRUE
        WHERE ${sourcePredicate.sql}
          AND ${landingPredicate.sql}
          AND s.kind NOT IN ('filesystem', 'file-upload', 'doc_site', 'policy-upload')
     )
     SELECT source_id, document_key, document_label, synced_at, document_count
       FROM ranked_backend_documents
      WHERE document_rank <= ${TOPOLOGY_SOURCE_DOCUMENT_SAMPLE}
      ORDER BY source_id ASC, document_rank ASC`,
    params,
  );
  return result.rows as unknown as TopologySourceDocumentRow[];
}

function sourceDocumentName(documentKey: string, preferredLabel: unknown): string {
  const preferred = String(preferredLabel ?? "").trim();
  if (preferred !== "") return compactGraphLabel(preferred);
  const value = documentKey.trim();
  if (value === "") return "Unavailable";
  const colon = value.indexOf(":");
  if (colon > 0 && colon < value.length - 1) {
    const kind = shortHumanLabel(value.slice(0, colon));
    return `${kind} ${value.slice(colon + 1)}`;
  }
  return value;
}

function attachSourceDocuments(
  sources: MemoryTopologySource[],
  rows: readonly TopologySourceDocumentRow[],
): void {
  const byId = new Map(sources.map((source) => [source.id, source]));
  for (const row of rows) {
    const source = byId.get(String(row.source_id));
    if (!source) continue;
    source.documentCount = Math.max(source.documentCount, Number(row.document_count) || 0);
    const syncedAt = row.synced_at instanceof Date
      ? row.synced_at.toISOString()
      : new Date(row.synced_at).toISOString();
    const id = String(row.document_key);
    source.documents.push({
      id,
      name: sourceDocumentName(id, row.document_label),
      syncedAt,
    });
  }
}

/**
 * The governed policy documents whose directives reach agents in `namespace`:
 * the namespace itself plus its `/`-split prefix ancestors, exactly the chain
 * `loadPolicyDirectives` reads. Never descendants, never siblings.
 */
export async function topologyPolicies(
  db: KernelSlice["db"],
  namespace: Namespace,
): Promise<MemoryTopologyPolicy[]> {
  const scopes = [...new Set(namespaceAncestors(namespace))];
  const placeholders = scopes.map((_, index) => `$${index + 1}`).join(", ");
  return topologyPoliciesByPredicate(
    db,
    { sql: `pd.namespace IN (${placeholders})`, params: scopes },
    namespace,
  );
}

/**
 * Read policy documents through a caller-provided, server-resolved namespace
 * predicate. The role-scoped graph passes the exact same visible-set boundary
 * as every other topology register (D40/D45); the legacy map passes its
 * effective ancestor chain above.
 */
async function topologyPoliciesByPredicate(
  db: KernelSlice["db"],
  predicate: { sql: string; params: string[] },
  contextNamespace: Namespace,
): Promise<MemoryTopologyPolicy[]> {
  const rows = await db.query(
    `SELECT pd.id, pd.namespace, pd.title, pd.kind, pd.enforcement,
            pd.status, pd.fact_count
       FROM policy_documents pd
      WHERE ${predicate.sql}
        AND pd.status IN ('active','needs_review')
      ORDER BY length(pd.namespace) - length(replace(pd.namespace, '/', '')) ASC,
               pd.namespace ASC, pd.created_at ASC, pd.id ASC`,
    predicate.params,
  );
  return (rows.rows as Array<{
    id: string;
    namespace: string;
    title: string;
    kind: PolicyDocumentKind;
    enforcement: string;
    status: PolicyDocumentStatus;
    fact_count: number | string;
  }>).map((row) => ({
    id: row.id,
    namespace: row.namespace,
    title: row.title,
    kind: row.kind,
    enforcement: row.enforcement === "advisory" ? "advisory" : "required",
    status: row.status,
    factCount: Number(row.fact_count) || 0,
    inherited:
      row.namespace !== contextNamespace &&
      isSelfOrDescendant(contextNamespace, row.namespace),
  }));
}

export interface MemoryMap {
  namespace: Namespace;
  pinned: string[];
  governedPins?: MemoryPin[];
  hottest: HotFact[];
  repeatLookups: RepeatLookup[];
  gaps: RepeatLookup[];
  topology: MemoryTopology;
}

/**
 * S5 memory map for ONE namespace (asserted inside the caller's subtree first —
 * a team admin can never map a sibling): the policy's pinned concepts, the
 * hottest (top-accessed) facts via mem_stats, the repeat-lookups (successful
 * search/fault queries asked more than once — candidates for pinning), and the
 * gaps (faults that MISSED — questions with no answer in memory).
 */
export async function memoryMap(
  kernel: KernelSlice,
  identity: Identity,
  namespace: Namespace,
): Promise<MemoryMap> {
  assertInSubtree(identity, namespace);
  if (namespace === "" && !isRootOwner(identity)) {
    throw new AuthzError("only the platform root owner may view the organization root memory map");
  }

  const policy = await kernel.getPolicy(namespace);

  // The management map keeps its selected subtree roll-up, and also includes
  // the normal query-layer read fence (ancestors) plus exact active mounts.
  // This prevents the console from omitting inherited policy while preserving
  // the steward's explicit subtree overview.
  const factPred = sharedSubtreePredicate(namespace, 1);
  const ancestors = namespaceAncestors(namespace);
  const ancestorPlaceholders = ancestors
    .map((_, index) => `$${factPred.params.length + index + 1}`)
    .join(", ");
  const mountedRefs = await mountedMemoryRefs(kernel.db, namespace);
  const mountedPlaceholders = mountedRefs
    .map((_, index) => `$${factPred.params.length + ancestors.length + index + 1}`)
    .join(", ");
  const relatedFacts = mountedRefs.length > 0
    ? `(${factPred.sql} OR namespace IN (${ancestorPlaceholders}) OR id IN (${mountedPlaceholders}))`
    : `(${factPred.sql} OR namespace IN (${ancestorPlaceholders}))`;
  const baseParams = [...factPred.params, ...ancestors, ...mountedRefs];
  const companyFacts = companyPublishedSql(
    sourceAccessSubject(identity),
    baseParams.length + 1,
  );
  const visibleFacts = companyFacts.params.length > 0
    ? `(${relatedFacts} OR ${companyFacts.sql})`
    : relatedFacts;
  const visibilityParams = [...baseParams, ...companyFacts.params];
  const accessClaims: Array<{ principals?: string[]; groups?: string[] }> = [
    ...[
      identity.actor,
      identity.keyId,
      ...(identity.sourcePrincipals ?? []),
    ].map((principal) => ({ principals: [principal] })),
    ...(identity.sourceGroups ?? []).map((group) => ({ groups: [group] })),
  ];
  const accessParams = accessClaims.map((claim) => JSON.stringify(claim));
  const sourceAclAt = (parameterOffset: number): string => [
      `(jsonb_array_length(COALESCE(source_access->'principals', '[]'::jsonb)) = 0 AND
        jsonb_array_length(COALESCE(source_access->'groups', '[]'::jsonb)) = 0)`,
      ...accessParams.map((_, index) =>
        `source_access @> $${parameterOffset + index + 1}::jsonb`),
    ].join(" OR ");
  const contextEligible = `(COALESCE(classification->>'sensitivity', 'restricted') IN ('public', 'internal')
    OR COALESCE(classification->'allowedDestinations', '[]'::jsonb)
      @> '["agent-context"]'::jsonb)`;
  const sourceAcl = sourceAclAt(visibilityParams.length);
  const topRes = await kernel.db.query(
    `SELECT id, namespace, content, access_count
     FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL AND ${TTL_ACTIVE_CLAUSE}
       AND ${visibleFacts}
       AND (${sourceAcl})
       AND ${contextEligible}
     ORDER BY access_count DESC, id ASC
     LIMIT 5`,
    [...visibilityParams, ...accessParams],
  );
  const hottest = (topRes.rows as {
    id: string;
    namespace: string;
    content: string;
    access_count: unknown;
  }[]).map((r) => ({
    id: r.id,
    content: r.content,
    accessCount: Number(r.access_count),
    pinnable:
      namespaceAncestors(namespace).includes(r.namespace) || mountedRefs.includes(r.id),
  }));
  // Funnel counts describe only the selected subtree. The hot-fact list above
  // may also include inherited ancestors and explicit mounts, but those must
  // not inflate a topology payload whose declared scope is selected-subtree.
  const countRes = await kernel.db.query(
    `SELECT
       COUNT(*) FILTER (WHERE tier = 'L2') AS active_facts,
       COUNT(*) FILTER (WHERE tier = 'L2' AND access_count > 0) AS activity_facts
     FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL AND ${TTL_ACTIVE_CLAUSE}
       AND ${factPred.sql}
       AND (${sourceAclAt(factPred.params.length)})
       AND ${contextEligible}`,
    [...factPred.params, ...accessParams],
  );
  const countRow = countRes.rows[0] as
    | { active_facts?: unknown; activity_facts?: unknown }
    | undefined;
  const activeFacts = Number(countRow?.active_facts ?? 0);
  const activityFacts = Number(countRow?.activity_facts ?? 0);

  // Only the permitted row count crosses into topology. Sibling source names,
  // files, skills, agents, questions, and audit data remain selected-subtree.
  const companyCountFacts = companyPublishedSql(sourceAccessSubject(identity), 1);
  const companyCountAcl = sourceAclAt(companyCountFacts.params.length);
  const companyCountRes = companyCountFacts.params.length > 0
    ? await kernel.db.query(
        `SELECT COUNT(*) AS company_published_facts
           FROM memory_objects
          WHERE status = 'active' AND t_valid_to IS NULL AND ${TTL_ACTIVE_CLAUSE}
            AND ${companyCountFacts.sql}
            AND (${companyCountAcl})
            AND ${contextEligible}`,
        [...companyCountFacts.params, ...accessParams],
      )
    : { rows: [{ company_published_facts: 0 }] };
  const companyPublishedFacts = Number(
    (companyCountRes.rows[0] as { company_published_facts?: unknown } | undefined)
      ?.company_published_facts ?? 0,
  );

  // The graph is a bounded, selected-subtree inventory. Unlike `hottest`, it
  // does not include inherited ancestors or mounted siblings. Older versions
  // remain visible because supersedence is an immutable relationship (D7),
  // not a destructive overwrite.
  const graphSourceAcl = sourceAclAt(factPred.params.length);
  const graphRes = await kernel.db.query(
    `SELECT id, namespace, content, type, tier, access_count, t_valid_to,
            supersedes, provenance
       FROM memory_objects
      WHERE status = 'active' AND ${TTL_ACTIVE_CLAUSE}
        AND ${factPred.sql}
        AND (${graphSourceAcl})
        AND ${contextEligible}
      ORDER BY (t_valid_to IS NULL) DESC, access_count DESC,
               assertion_time DESC, id ASC
      LIMIT ${MEMORY_TOPOLOGY_NODE_CAP}`,
    [...factPred.params, ...accessParams],
  );
  const memories = (graphRes.rows as Array<{
    id: string;
    namespace: string;
    content: string;
    type: string;
    tier: "L2" | "L3";
    access_count: unknown;
    t_valid_to: unknown;
    supersedes: string | null;
    provenance: unknown;
  }>).map((row): MemoryTopologyMemory => ({
    id: row.id,
    namespace: row.namespace,
    label: compactGraphLabel(row.content),
    type: row.type,
    tier: row.tier,
    accessCount: Number(row.access_count) || 0,
    state: row.t_valid_to == null ? "current" : "older",
    supersedes: row.supersedes,
    sourceIds: graphSourceIds(row.provenance),
  }));

  // Members may read S5 but cannot enumerate API keys. Keep their agent branch
  // empty instead of turning an otherwise-authorized Memory Lane into a 403.
  const visibleAgents = identity.role === "member" ? [] : await kernel.auth.list(identity);
  const agents = visibleAgents
    .filter((badge) =>
      badge.role === "agent" &&
      badge.status === "active" &&
      isSelfOrDescendant(badge.namespace, namespace))
    .map((badge): MemoryTopologyAgent => ({
      id: badge.id,
      namespace: badge.namespace,
      actor: badge.actor,
    }));

  // Repeat lookups: successful search/fault rows whose `purpose` (the query)
  // recurs more than once — the store answered them repeatedly, so pinning
  // would cut the fault traffic. Gaps: faults that MISSED — no answer in memory.
  const auditPred = sharedSubtreePredicate(namespace, 1);
  const auditRes = await kernel.db.query(
    `SELECT op, result, purpose FROM audit_log
     WHERE ${auditPred.sql}
       AND op IN ('search', 'fault')
       AND purpose IS NOT NULL`,
    auditPred.params,
  );
  const rows = auditRes.rows as { op: string; result: string; purpose: string }[];

  const okCounts = new Map<string, number>();
  const missCounts = new Map<string, number>();
  for (const r of rows) {
    const q = r.purpose;
    if (r.result === "ok") okCounts.set(q, (okCounts.get(q) ?? 0) + 1);
    else if (r.result === "miss") missCounts.set(q, (missCounts.get(q) ?? 0) + 1);
  }

  const repeatLookups: RepeatLookup[] = [...okCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([query, count]) => ({ query, count }))
    .sort(byCountDesc);

  const gaps: RepeatLookup[] = [...missCounts.entries()]
    .map(([query, count]) => ({ query, count }))
    .sort(byCountDesc);

  const sourceRows = await kernel.sources.list(
    namespace,
    isRootOwner(identity) && namespace === "",
  );
  const sources: MemoryTopologySource[] = sourceRows
    .filter((source) => isBackendSourceKind(source.kind))
    .map((source) => ({
      id: source.id,
      namespace: source.namespace,
      kind: source.kind,
      documents: [],
      documentCount: 0,
      syncStatus:
        source.syncStatus ?? (source.lastSync ? "synced" : "never_synced"),
      lastSync: source.lastSync,
      lastSyncError: source.lastSyncError ?? null,
      lifecycleState: source.lifecycleState ?? "active",
    }));
  const sourceDocumentSourcePred = sharedSubtreePredicate(namespace, 1, "s.namespace");
  const sourceDocumentLandingPred = sharedSubtreePredicate(
    namespace,
    sourceDocumentSourcePred.params.length + 1,
    "sd.landing_namespace",
  );
  attachSourceDocuments(
    sources,
    await topologySourceDocuments(
      kernel.db,
      sourceDocumentSourcePred,
      sourceDocumentLandingPred,
    ),
  );

  // Knowledge-base and skill branches are read from their authoritative
  // registers. The graph never infers either from fact text, which previously
  // caused skill metadata memories to appear as generic knowledge nodes.
  const knowledgePred = sharedSubtreePredicate(namespace, 1, "kb.namespace");
  const skillPred = sharedSubtreePredicate(namespace, 1, "s.namespace");
  const [knowledgeRes, skillRes] = await Promise.all([
    kernel.db.query(
      `SELECT kb.id AS knowledge_base_id, kb.namespace, kb.name,
              kb.kind, kb.status, kb.source_id AS knowledge_source_id,
              file.id AS file_id, file.source_id AS file_source_id,
              file.file_name, file.status AS file_status, file.fact_count
         FROM knowledge_bases kb
         LEFT JOIN company_files file
           ON file.knowledge_base_id = kb.id
          AND file.lifecycle_state = 'active'
          AND file.t_valid_to IS NULL
        WHERE kb.lifecycle_state = 'active'
          AND kb.t_valid_to IS NULL
          AND ${knowledgePred.sql}
        ORDER BY kb.created_at ASC, kb.id ASC, file.created_at ASC, file.id ASC`,
      knowledgePred.params,
    ),
    kernel.db.query(
      `SELECT s.id, s.namespace, s.skill_key, s.name,
              s.vetting_status, s.safety_score
         FROM skills s
        WHERE s.status = 'active'
          AND s.t_valid_to IS NULL
          AND ${skillPred.sql}
        ORDER BY s.namespace ASC, s.skill_key ASC`,
      skillPred.params,
    ),
  ]);

  const knowledgeById = new Map<string, MemoryTopologyKnowledgeBase>();
  for (const raw of knowledgeRes.rows) {
    const row = raw as {
      knowledge_base_id: string;
      namespace: string;
      name: string;
      kind: MemoryTopologyKnowledgeBase["kind"];
      status: MemoryTopologyKnowledgeBase["status"];
      knowledge_source_id: string | null;
      file_id: string | null;
      file_source_id: string | null;
      file_name: string | null;
      file_status: MemoryTopologyFile["status"] | null;
      fact_count: unknown;
    };
    let base = knowledgeById.get(row.knowledge_base_id);
    if (!base) {
      base = {
        id: row.knowledge_base_id,
        namespace: row.namespace,
        name: row.name,
        kind: row.kind,
        status: row.status,
        sourceId: row.knowledge_source_id,
        files: [],
      };
      knowledgeById.set(base.id, base);
    }
    if (row.file_id && row.file_source_id && row.file_name && row.file_status) {
      base.files.push({
        id: row.file_id,
        sourceId: row.file_source_id,
        name: row.file_name,
        status: row.file_status,
        factCount: Number(row.fact_count) || 0,
      });
    }
  }
  const knowledgeBases = [...knowledgeById.values()];
  const skills = (skillRes.rows as Array<{
    id: string;
    namespace: string;
    skill_key: string;
    name: string;
    vetting_status: MemoryTopologySkill["vettingStatus"];
    safety_score: unknown;
  }>).map((row): MemoryTopologySkill => ({
    id: row.id,
    namespace: row.namespace,
    key: row.skill_key,
    name: row.name,
    vettingStatus: row.vetting_status,
    safetyScore: row.safety_score == null ? null : Number(row.safety_score),
  }));

  const routing: MemoryTopologyRouting = policy.abTest
    ? {
        mode: "ab-test",
        a: policy.abTest.a,
        b: policy.abTest.b,
        pctB: policy.abTest.pctB,
      }
    : { mode: "fixed", name: policy.retriever ?? "baseline" };

  return {
    namespace,
    pinned: policy.pinnedConcepts,
    hottest,
    repeatLookups,
    gaps,
    topology: {
      scope: "selected-subtree",
      sources,
      activeFacts: Number.isFinite(activeFacts) ? activeFacts : 0,
      activityFacts: Number.isFinite(activityFacts) ? activityFacts : 0,
      companyPublishedFacts: Number.isFinite(companyPublishedFacts)
        ? companyPublishedFacts
        : 0,
      memories,
      knowledgeBases,
      skills,
      agents,
      policies: await topologyPolicies(kernel.db, namespace),
      routing,
    },
  };
}

function compactGraphLabel(content: string): string {
  const oneLine = content.replace(/\s+/g, " ").trim();
  return oneLine.length <= 116 ? oneLine : `${oneLine.slice(0, 113)}...`;
}

function graphSourceIds(value: unknown): string[] {
  let parsed = value;
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed) as unknown;
    } catch {
      return [];
    }
  }
  if (!Array.isArray(parsed)) return [];
  return [...new Set(parsed.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const sourceId = (entry as { sourceId?: unknown }).sourceId;
    return typeof sourceId === "string" && sourceId.length > 0 ? [sourceId] : [];
  }))];
}

// ---------------------------------------------------------------------------
// S5 — role-scoped memory graph (M10, CONTRACTS-M10-ACCESS)
//
// One canonical graph, one server-authorized projection per subject (D40).
// EVERY node, edge, count, source name, knowledge base, skill, and agent
// reference passes the projection predicate BEFORE serialization; an edge is
// included only when BOTH endpoints are visible (D45); aggregates are computed
// after filtering; caps + pagination apply after authorization. The function
// is deliberately projection-pure: one AccessProjection in, one graph out —
// there is no role- or preview-conditional branch inside the filtering, which
// makes root View-as authorization-equivalence trivially true (D43): the
// transport hands the preview subject's projection to the SAME function.
// ---------------------------------------------------------------------------

/**
 * The dependencies {@link getMemoryGraph} consumes. `auditActor` is the D4
 * attribution seam: during a root View-as preview the integrator passes the
 * ROOT actor here (audit never names the preview subject — D43) while the
 * projection stays the subject's. The response never depends on it.
 */
export interface MemoryGraphDeps {
  readonly db: Db;
  readonly audit: { append(event: AuditEvent): Promise<void> };
  /** D4 attribution: the authenticated actor (root during preview — D43). */
  readonly auditActor: string;
  /** Audit agent-id column; defaults to "console". */
  readonly auditAgentId?: string;
  /** Injectable clock (tests); defaults to the real clock. */
  readonly now?: () => Date;
}

export interface MemoryGraphOptions {
  /** Opaque authorized-scope ID — narrows the union, never widens (D42). */
  scopeId?: string;
  /** Continuation cursor from a previous page. */
  cursor?: string;
  /** Page size; clamped to 1..500 (the node cap). */
  limit?: number;
}

export interface SavedMemoryLink {
  id: string;
  label: string;
  kind: string;
  role: string;
}

/** Current, projection-safe memory rows rendered below the S5 topology. */
export interface SavedMemorySummary {
  id: string;
  tier: "L2" | "L3";
  status: "Current" | "Governed";
  summary: string;
  title: string;
  body: string;
  team: string;
  source: string;
  author: string;
  authorRole: string;
  origin: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  confidence: number;
  accessCount: number;
  facts: readonly string[];
  links: readonly SavedMemoryLink[];
}

/** {@link MemoryGraphResponse} plus the continuation cursor when capped. */
export interface MemoryGraphPage extends MemoryGraphResponse {
  savedMemories: readonly SavedMemorySummary[];
  cursor?: string;
}

/**
 * Uniform not-found (D46): an unauthorized scope and a nonexistent one throw
 * the byte-identical error — no existence oracle. The transport maps this to
 * the shared 404 `not_found` shape.
 */
export class MemoryGraphNotFoundError extends Error {
  readonly code = "not_found" as const;
  constructor() {
    super("not found");
    this.name = "MemoryGraphNotFoundError";
  }
}

/** Caps applied AFTER authorization, with deterministic ordering (D45). */
export const MEMORY_GRAPH_NODE_CAP = 500;
export const MEMORY_GRAPH_EDGE_CAP = 1500;

/**
 * Deterministic opaque scope ID for one authorized root. A hash — never the
 * namespace itself — so the wire carries no namespace strings (D9); selection
 * is re-resolved server-side against the caller's OWN authorized roots only.
 */
export function memoryGraphScopeId(tenantId: string, root: Namespace): string {
  return createHash("sha256")
    .update(`m10-scope:${tenantId}:${root}`)
    .digest("hex")
    .slice(0, 20);
}

/**
 * `ns` is the tenant root itself or a `/`-descendant of it (literal compare).
 * Tenant "" is the UNPREFIXED ORGANIZATION (single-org installs): any
 * non-empty namespace counts — such projections only ever arrive from the
 * View-as simulation path, whose roots the kernel pre-filters against
 * registered tenants (resolveProjection fails closed for everything else).
 */
function withinTenant(ns: string, tenantId: string): boolean {
  if (tenantId === "") return ns !== "";
  return ns === tenantId || ns.startsWith(tenantId + "/");
}

/**
 * The projection's visible namespace set, as exact names + govern subtree
 * roots (D44): consume roots read UPWARD (self + `/`-split prefix ancestors,
 * exact IN list), personal roots are exact, govern roots read DOWNWARD (exact
 * match + escaped-prefix predicate). Everything is clamped inside the tenant
 * boundary; an empty tenant ID fails closed to "no access" (brownout — never
 * a wider projection).
 */
interface VisibleSet {
  exact: string[];
  prefixes: string[];
}

function visibleSetFor(projection: AccessProjection): VisibleSet {
  const tenant = projection.tenantId;
  const exact = new Set<string>();
  for (const root of projection.consumeRoots) {
    if (!withinTenant(root, tenant)) continue;
    for (const ns of namespaceAncestors(root)) {
      if (withinTenant(ns, tenant)) exact.add(ns);
    }
  }
  for (const root of projection.personalRoots) {
    if (withinTenant(root, tenant)) exact.add(root);
  }
  const governList = [...new Set(projection.governRoots)]
    .filter((root) => withinTenant(root, tenant))
    .sort();
  // Drop govern roots already covered by another govern root's subtree.
  const prefixes = governList.filter(
    (p) => !governList.some((q) => q !== p && isSelfOrDescendant(p, q)),
  );
  // Exact names inside a governed subtree are redundant with its predicate.
  const exactList = [...exact]
    .filter((ns) => !prefixes.some((p) => isSelfOrDescendant(ns, p)))
    .sort();
  return { exact: exactList, prefixes };
}

/** True when `ns` is inside the visible set (literal JS compare, no LIKE). */
function nsVisible(v: VisibleSet, ns: string): boolean {
  return (
    v.exact.includes(ns) || v.prefixes.some((p) => isSelfOrDescendant(ns, p))
  );
}

/**
 * SQL predicate for the visible set starting at `$startAt`: exact IN list for
 * consume/personal names, exact-match + escaped `LIKE ... ESCAPE '\'` per
 * govern root — `_`, `%`, `\` in namespaces are ALWAYS literal (D44).
 */
function visiblePredicate(
  v: VisibleSet,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  const parts: string[] = [];
  const params: string[] = [];
  let n = startAt;
  if (v.exact.length > 0) {
    parts.push(`${column} IN (${v.exact.map(() => `$${n++}`).join(", ")})`);
    params.push(...v.exact);
  }
  for (const p of v.prefixes) {
    parts.push(`${column} = $${n++}`);
    params.push(p);
    parts.push(`${column} LIKE $${n++} ESCAPE '\\'`);
    params.push(escapeLike(p) + "/%");
  }
  if (parts.length === 0) return { sql: "FALSE", params: [] };
  return { sql: `(${parts.join(" OR ")})`, params };
}

/**
 * Intersect the visible set with one selected root's subtree. A pure set
 * intersection: narrows the union, never widens it (D42).
 */
function narrowVisibleSet(v: VisibleSet, root: string): VisibleSet {
  const exact = v.exact.filter((ns) => isSelfOrDescendant(ns, root));
  const prefixes = new Set<string>();
  for (const p of v.prefixes) {
    if (isSelfOrDescendant(p, root)) prefixes.add(p);
    else if (isSelfOrDescendant(root, p)) prefixes.add(root);
  }
  return { exact, prefixes: [...prefixes].sort() };
}

/**
 * Policies inside a selected graph scope remain an inventory of that visible
 * subtree, plus the visible ancestor documents whose directives govern the
 * selected root. This is still a pure intersection with the original
 * projection: an ancestor absent from `allVisible` is never added.
 */
function policyVisibleSetForScope(
  allVisible: VisibleSet,
  scopedVisible: VisibleSet,
  root: string,
): VisibleSet {
  const exact = new Set(scopedVisible.exact);
  for (const namespace of namespaceAncestors(root)) {
    if (nsVisible(allVisible, namespace)) exact.add(namespace);
  }
  const prefixes = [...scopedVisible.prefixes];
  return {
    exact: [...exact]
      .filter((namespace) =>
        !prefixes.some((prefix) => isSelfOrDescendant(namespace, prefix)))
      .sort(),
    prefixes,
  };
}

/** The distinct authorized roots a subject may select as a scope. */
function memoryGraphScopeRoots(projection: AccessProjection): string[] {
  const tenant = projection.tenantId;
  if (tenant === "") return [];
  const roots = new Set<string>();
  for (const r of [
    ...projection.governRoots,
    ...projection.consumeRoots,
    ...projection.personalRoots,
  ]) {
    if (withinTenant(r, tenant)) roots.add(r);
  }
  return [...roots].sort();
}

/** Bound on scope options offered to one subject. */
const GRAPH_SCOPE_OPTION_CAP = 200;

/**
 * The scopes a subject may select: every authorized root, PLUS each named team
 * (`org_teams`) that sits inside one of those roots.
 *
 * A team option is a pure NARROWING (D42): the team namespace is already
 * self-or-descendant of a root this subject was granted, so selecting it can
 * only intersect the union — never widen it. A root who governs the tenant
 * therefore sees one option per team instead of a single "Halofy" that names
 * the whole company, which is what a human means by "scoped as teams".
 *
 * Ancestors of a consume root are deliberately NOT offered. They are inside
 * the visible set (inherited facts flow down), but naming one as a selectable
 * scope would read as "I can see all of that space" when the subject cannot.
 */
async function memoryGraphScopeOptions(
  db: Db,
  projection: AccessProjection,
): Promise<{ root: string; label: string }[]> {
  const tenant = projection.tenantId;
  if (tenant === "") return [];
  const granted = memoryGraphScopeRoots(projection);
  const byRoot = new Map<string, string>();
  for (const root of granted) {
    byRoot.set(root, memoryGraphScopeLabel(projection, root));
  }

  const teamRes = await db.query(
    `SELECT namespace, name FROM org_teams
      WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
      ORDER BY name ASC LIMIT ${GRAPH_SCOPE_OPTION_CAP}`,
    [tenant, escapeLike(tenant) + "/%"],
  );
  for (const row of teamRes.rows as unknown as { namespace: unknown; name: unknown }[]) {
    const ns = String(row.namespace ?? "");
    if (ns === "" || !withinTenant(ns, tenant)) continue;
    if (!granted.some((root) => isSelfOrDescendant(ns, root))) continue;
    // A personal root keeps its "Personal" label even if a team shares the
    // namespace; otherwise the team's own name is the better label.
    if (projection.personalRoots.includes(ns)) continue;
    const name = String(row.name ?? "").trim();
    byRoot.set(ns, name === "" ? memoryGraphScopeLabel(projection, ns) : name);
  }

  return [...byRoot.entries()]
    .map(([root, label]) => ({ root, label }))
    .sort((a, b) => (a.label !== b.label ? (a.label < b.label ? -1 : 1) : a.root < b.root ? -1 : 1))
    .slice(0, GRAPH_SCOPE_OPTION_CAP);
}

/** Short everyday scope label (UI-text rule): "Marketing", "Common", ... */
function memoryGraphScopeLabel(
  projection: AccessProjection,
  root: string,
): string {
  if (projection.personalRoots.includes(root)) return "Personal";
  const segs = root.split("/").filter((s) => s.length > 0);
  let last = segs[segs.length - 1] ?? root;
  if (last === "shared" && segs.length >= 2) last = segs[segs.length - 2]!;
  if (last === "common") return "Common";
  return last.charAt(0).toUpperCase() + last.slice(1);
}

/** Role-adaptive title: "Your memory" | "<Function> memory" | "Company memory". */
function memoryGraphTitle(
  projection: AccessProjection,
  scopeLabel: string | undefined,
): string {
  if (scopeLabel !== undefined) return `${scopeLabel} memory`;
  if (projection.role === "root") return "Company memory";
  if (projection.role === "admin" && projection.governRoots.length === 1) {
    return `${memoryGraphScopeLabel(projection, projection.governRoots[0]!)} memory`;
  }
  return "Your memory";
}

const CURSOR_RE = /^o=(\d{1,9})$/;

function encodeGraphCursor(offset: number): string {
  return Buffer.from(`o=${offset}`, "utf8").toString("base64url");
}

function decodeGraphCursor(cursor: string | undefined): number {
  if (cursor === undefined || cursor === "") return 0;
  let decoded: string;
  try {
    decoded = Buffer.from(cursor, "base64url").toString("utf8");
  } catch {
    return 0;
  }
  const m = CURSOR_RE.exec(decoded);
  return m ? Number(m[1]) : 0;
}

/** Deterministic node ordering: kind, then id (stable across calls/pages). */
function byKindThenId(a: MemoryGraphNode, b: MemoryGraphNode): number {
  if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function byEdgeOrder(a: MemoryGraphEdge, b: MemoryGraphEdge): number {
  if (a.from !== b.from) return a.from < b.from ? -1 : 1;
  if (a.to !== b.to) return a.to < b.to ? -1 : 1;
  return a.relation < b.relation ? -1 : a.relation > b.relation ? 1 : 0;
}

function graphProvenance(value: unknown): Array<Record<string, unknown>> {
  let parsed = value;
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      return [];
    }
  }
  return Array.isArray(parsed)
    ? parsed.filter((entry): entry is Record<string, unknown> =>
        entry !== null && typeof entry === "object" && !Array.isArray(entry))
    : [];
}

function shortHumanLabel(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (raw === "") return "Unavailable";
  return raw
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function savedMemoryTeam(
  namespace: string,
  teams: readonly { namespace: string; name: string }[],
): string {
  const matching = teams
    .filter((team) => isSelfOrDescendant(namespace, team.namespace))
    .sort((a, b) => b.namespace.length - a.namespace.length)[0];
  if (matching && matching.name.trim() !== "") return matching.name.trim();
  const parts = namespace.split("/").filter(Boolean);
  let last = parts.at(-1) ?? "";
  if (last === "shared" && parts.length > 1) last = parts.at(-2) ?? last;
  if (last === "common") return "Common";
  if (parts.includes("people")) return "Personal";
  return shortHumanLabel(last);
}

function captureRole(source: unknown): string {
  const label = String(source ?? "").trim();
  return label === "" ? "Memory capture" : `${shortHumanLabel(label)} capture`;
}

/**
 * Context-eligibility fence shared with {@link memoryMap}: public/internal
 * sensitivity, or an explicit agent-context destination. The projection route
 * additionally excludes source-ACL-restricted rows entirely (fail-closed: the
 * shared read model has no per-principal claims to evaluate — never widen).
 */
const GRAPH_CONTEXT_ELIGIBLE = `(COALESCE(classification->>'sensitivity', 'restricted') IN ('public', 'internal')
  OR COALESCE(classification->'allowedDestinations', '[]'::jsonb)
    @> '["agent-context"]'::jsonb)`;
const GRAPH_SOURCE_ACL_OPEN = `(jsonb_array_length(COALESCE(source_access->'principals', '[]'::jsonb)) = 0 AND
  jsonb_array_length(COALESCE(source_access->'groups', '[]'::jsonb)) = 0)`;

/** Bound on rows pulled per register before the post-filter node cap pages. */
const GRAPH_ROW_BOUND = 10000;

/**
 * The `/v1/memory-graph` read model (FR4, FR5, FR7). Builds the S5 topology
 * from the SAME registers the legacy {@link memoryMap} reads (memory_objects,
 * sources, knowledge_bases, skills, agent api_keys) but scoped by ONE
 * server-resolved {@link AccessProjection}. `scopeId` narrows the union of
 * grants and never widens it; an unknown OR unauthorized scope throws the
 * uniform {@link MemoryGraphNotFoundError} after writing a D4 denial row.
 * Every call — allowed or denied — audits under `deps.auditActor` (D4/D43).
 */
export async function getMemoryGraph(
  deps: MemoryGraphDeps,
  projection: AccessProjection,
  opts: MemoryGraphOptions = {},
): Promise<MemoryGraphPage> {
  const ts = (deps.now?.() ?? new Date()).toISOString();
  const agentId = deps.auditAgentId ?? "console";
  const options = await memoryGraphScopeOptions(deps.db, projection);
  const scopes: MemoryGraphScopeOption[] = options.map((option) => ({
    id: memoryGraphScopeId(projection.tenantId, option.root),
    label: option.label,
  }));

  let visible = visibleSetFor(projection);
  let scopeLabel: string | undefined;
  if (opts.scopeId !== undefined) {
    const selected = options.find(
      (option) => memoryGraphScopeId(projection.tenantId, option.root) === opts.scopeId,
    );
    if (selected === undefined) {
      // D46: unauthorized and nonexistent scopes are indistinguishable; the
      // denial detail never names the hidden target.
      await deps.audit.append({
        ts,
        actor: deps.auditActor,
        agentId,
        op: "read",
        memoryId: null,
        namespace: projection.tenantId,
        purpose: "memory-graph",
        result: "denied",
        detail: "memory-graph: scope not found",
      });
      throw new MemoryGraphNotFoundError();
    }
    visible = narrowVisibleSet(visible, selected.root);
    scopeLabel = selected.label;
  }

  const nodes: MemoryGraphNode[] = [];
  const edges: MemoryGraphEdge[] = [];
  let savedMemories: SavedMemorySummary[] = [];

  if (visible.exact.length > 0 || visible.prefixes.length > 0) {
    const pred = visiblePredicate(visible, 1);
    const kbPred = visiblePredicate(visible, 1, "kb.namespace");
    const skillPredG = visiblePredicate(visible, 1, "s.namespace");

    // The registers are independent reads under ONE already-resolved
    // predicate - nothing here feeds the next query, only the post-filtering
    // below. Run them concurrently: serially this was five Postgres round
    // trips per S5 paint, and S5 repaints on every space pick.
    const [sourceRes, memRes, kbRes, skillResG, agentRes, teamRes] = await Promise.all([
      // --- sources (their names/kinds are projection-gated too — D40) -------
      deps.db.query(
        `SELECT id, kind FROM sources
          WHERE ${pred.sql}
            AND kind NOT IN ('filesystem', 'file-upload', 'doc_site', 'policy-upload')
          ORDER BY id ASC LIMIT ${GRAPH_ROW_BOUND}`,
        pred.params,
      ),
      // --- memories ----------------------------------------------------------
      deps.db.query(
        `SELECT id, namespace, tier, content, display_title, type, confidence,
                assertion_time, t_valid_from, t_valid_to, supersedes,
                provenance, last_accessed, access_count
           FROM memory_objects
          WHERE status = 'active' AND ${TTL_ACTIVE_CLAUSE}
            AND ${pred.sql}
            AND ${GRAPH_SOURCE_ACL_OPEN}
            AND ${GRAPH_CONTEXT_ELIGIBLE}
          ORDER BY id ASC LIMIT ${GRAPH_ROW_BOUND}`,
        pred.params,
      ),
      // --- knowledge bases (post-filter file counts — D45) --------------------
      deps.db.query(
        `SELECT kb.id, kb.name, kb.source_id,
                count(f.id) FILTER (WHERE f.id IS NOT NULL) AS file_count
           FROM knowledge_bases kb
           LEFT JOIN company_files f
             ON f.knowledge_base_id = kb.id
            AND f.lifecycle_state = 'active'
            AND f.t_valid_to IS NULL
          WHERE kb.lifecycle_state = 'active'
            AND kb.t_valid_to IS NULL
            AND ${kbPred.sql}
          GROUP BY kb.id, kb.name, kb.source_id
          ORDER BY kb.id ASC LIMIT ${GRAPH_ROW_BOUND}`,
        kbPred.params,
      ),
      // --- skills --------------------------------------------------------------
      deps.db.query(
        `SELECT s.id, s.name FROM skills s
          WHERE s.status = 'active' AND s.t_valid_to IS NULL
            AND ${skillPredG.sql}
          ORDER BY s.id ASC LIMIT ${GRAPH_ROW_BOUND}`,
        skillPredG.params,
      ),
      // --- agent badges ----------------------------------------------------------
      deps.db.query(
        `SELECT id, actor FROM api_keys
          WHERE role = 'agent' AND status = 'active' AND ${pred.sql}
          ORDER BY id ASC LIMIT ${GRAPH_ROW_BOUND}`,
        pred.params,
      ),
      // Team namespaces remain server-side; only the nearest human label is
      // serialized on a saved-memory row.
      deps.db.query(
        `SELECT namespace, name FROM org_teams
          WHERE ${pred.sql}
          ORDER BY length(namespace) DESC, name ASC LIMIT ${GRAPH_SCOPE_OPTION_CAP}`,
        pred.params,
      ),
    ]);

    const sourceRows = sourceRes.rows as { id: string; kind: string }[];
    const visibleSourceIds = new Set(sourceRows.map((r) => r.id));
    const sourceFactCounts = new Map<string, number>();
    const memRows = memRes.rows as {
      id: string;
      namespace: string;
      tier: "L2" | "L3";
      content: string;
      display_title: string | null;
      type: string;
      confidence: unknown;
      assertion_time: unknown;
      t_valid_from: unknown;
      t_valid_to: unknown;
      supersedes: string | null;
      provenance: unknown;
      last_accessed: unknown;
      access_count: unknown;
    }[];
    const visibleMemoryIds = new Set(memRows.map((r) => r.id));
    const kbRows = kbRes.rows as {
      id: string;
      name: string;
      source_id: string | null;
      file_count: unknown;
    }[];
    const skillRowsG = skillResG.rows as { id: string; name: string }[];
    const agentRows = agentRes.rows as { id: string; actor: string }[];
    const teamRows = teamRes.rows as { namespace: string; name: string }[];

    // --- edges: both endpoints visible, or the edge does not exist (D45) ------
    for (const m of memRows) {
      if (m.supersedes !== null && visibleMemoryIds.has(m.supersedes)) {
        edges.push({ from: m.id, to: m.supersedes, relation: "supersedes" });
      }
      for (const sid of graphSourceIds(m.provenance)) {
        if (!visibleSourceIds.has(sid)) continue;
        edges.push({ from: m.id, to: sid, relation: "from_source" });
        sourceFactCounts.set(sid, (sourceFactCounts.get(sid) ?? 0) + 1);
      }
    }
    for (const kb of kbRows) {
      if (kb.source_id !== null && visibleSourceIds.has(kb.source_id)) {
        edges.push({ from: kb.id, to: kb.source_id, relation: "syncs_from" });
      }
    }

    for (const m of memRows) {
      nodes.push({ id: m.id, kind: "memory", label: compactGraphLabel(m.content) });
    }
    for (const s of sourceRows) {
      nodes.push({
        id: s.id,
        kind: "source",
        label: s.kind,
        count: sourceFactCounts.get(s.id) ?? 0,
      });
    }
    for (const kb of kbRows) {
      nodes.push({
        id: kb.id,
        kind: "knowledge",
        label: kb.name,
        count: Number(kb.file_count) || 0,
      });
    }
    for (const s of skillRowsG) {
      nodes.push({ id: s.id, kind: "skill", label: s.name });
    }
    for (const a of agentRows) {
      nodes.push({ id: a.id, kind: "agent", label: a.actor });
    }

    const memoryById = new Map(memRows.map((row) => [row.id, row]));
    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    const sourceById = new Map(sourceRows.map((source) => [source.id, source]));
    savedMemories = memRows
      .filter((row) => row.t_valid_to === null)
      .map((row): SavedMemorySummary => {
        const provenance = graphProvenance(row.provenance);
        const latest = provenance.at(-1);
        const visibleSourceId = graphSourceIds(row.provenance)
          .find((id) => visibleSourceIds.has(id));
        const visibleSource = visibleSourceId ? sourceById.get(visibleSourceId) : undefined;
        const documentKey = String(latest?.documentKey ?? "").trim();
        const sourceRef = String(latest?.sourceRef ?? "").trim();
        const source = documentKey || sourceRef || visibleSource?.kind ||
          shortHumanLabel(latest?.source);
        const author = String(latest?.actor ?? "").trim() || "Unavailable";

        let version = 1;
        let oldest = row;
        let previous = row.supersedes;
        const visited = new Set([row.id]);
        while (previous && !visited.has(previous)) {
          const candidate = memoryById.get(previous);
          if (!candidate) break;
          visited.add(previous);
          version += 1;
          oldest = candidate;
          previous = candidate.supersedes;
        }

        const links: SavedMemoryLink[] = [];
        const linked = new Set<string>();
        for (const edge of edges) {
          if (edge.from !== row.id && edge.to !== row.id) continue;
          const otherId = edge.from === row.id ? edge.to : edge.from;
          if (linked.has(otherId)) continue;
          const node = nodeById.get(otherId);
          if (!node) continue;
          linked.add(otherId);
          const role = edge.relation === "from_source"
            ? "Source"
            : edge.relation === "supersedes"
              ? edge.from === row.id ? "Previous version" : "Newer version"
              : shortHumanLabel(edge.relation);
          links.push({ id: node.id, label: node.label, kind: node.kind, role });
        }

        const confidence = Number(row.confidence);
        const summary = compactGraphLabel(row.content);
        return {
          id: row.id,
          tier: row.tier,
          status: row.tier === "L3" ? "Governed" : "Current",
          summary,
          title: String(row.display_title ?? "").trim() || summary,
          body: row.content,
          team: savedMemoryTeam(row.namespace, teamRows),
          source,
          author,
          authorRole: captureRole(latest?.source),
          origin: source,
          createdAt: toIso(oldest.t_valid_from),
          updatedAt: toIso(row.assertion_time),
          version,
          confidence: Number.isFinite(confidence)
            ? Math.max(0, Math.min(1, confidence))
            : 0,
          accessCount: Math.max(0, Number(row.access_count) || 0),
          facts: [row.content],
          links: links.slice(0, 6),
        };
      })
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id));
  }

  nodes.sort(byKindThenId);
  edges.sort(byEdgeOrder);

  // Counts are post-filter authorized totals; caps page AFTER authorization.
  const counts = { nodes: nodes.length, edges: edges.length };
  const limit = Math.min(
    Math.max(Math.trunc(opts.limit ?? MEMORY_GRAPH_NODE_CAP) || 1, 1),
    MEMORY_GRAPH_NODE_CAP,
  );
  const offset = decodeGraphCursor(opts.cursor);
  const pageNodes = nodes.slice(offset, offset + limit);
  const nextOffset = offset + limit;
  // An edge ships on the FIRST page where both endpoints have been delivered
  // (a client accumulates nodes across pages), so both-endpoints-included
  // (D45) holds and no edge is duplicated or lost across the cursor.
  const deliveredBefore = new Set(nodes.slice(0, offset).map((n) => n.id));
  const deliveredNow = new Set(nodes.slice(0, nextOffset).map((n) => n.id));
  const pageEdges = edges
    .filter(
      (e) =>
        deliveredNow.has(e.from) &&
        deliveredNow.has(e.to) &&
        !(deliveredBefore.has(e.from) && deliveredBefore.has(e.to)),
    )
    .slice(0, MEMORY_GRAPH_EDGE_CAP);

  await deps.audit.append({
    ts,
    actor: deps.auditActor,
    agentId,
    op: "read",
    memoryId: null,
    namespace: projection.tenantId,
    purpose: "memory-graph",
    result: "ok",
    detail: `memory-graph nodes=${counts.nodes} edges=${counts.edges}${scopeLabel !== undefined ? ` scope=${scopeLabel}` : ""}`,
  });

  const page: MemoryGraphPage = {
    title: memoryGraphTitle(projection, scopeLabel),
    nodes: pageNodes,
    edges: pageEdges,
    counts,
    scopes,
    savedMemories,
  };
  if (nextOffset < nodes.length) page.cursor = encodeGraphCursor(nextOffset);
  return page;
}

// ---------------------------------------------------------------------------
// M10 integrator wiring: the S5 dot-node renderer consumes memory-map's
// topology shape, so /v1/memory-graph ships the SAME shape — built under the
// SAME projection predicate as getMemoryGraph (one filter, two
// serializations). Only visible endpoints appear in relationship fields
// (supersedes / sourceIds / kb.sourceId are nulled or dropped when the other
// end is outside the projection — D45).
// ---------------------------------------------------------------------------

/** The structural deps {@link memoryGraphTopology} consumes. */
export interface MemoryGraphTopologyDeps {
  readonly db: Db;
  getPolicy(namespace: Namespace): Promise<ConsolePolicy>;
}

/**
 * Projection-scoped {@link MemoryTopology} for the `/v1/memory-graph`
 * response. Same visible-set derivation, scope narrowing (intersection —
 * never widens, D42), caps, and sensitivity fences as {@link getMemoryGraph};
 * an unknown/unauthorized scope throws the same uniform not-found (the graph
 * call has already written the D4 denial row — do not double-audit).
 */
export async function memoryGraphTopology(
  deps: MemoryGraphTopologyDeps,
  projection: AccessProjection,
  scopeId?: string,
): Promise<MemoryTopology> {
  const allVisible = visibleSetFor(projection);
  let visible = allVisible;
  let policyVisible = allVisible;
  let policyNamespace = projection.tenantId;
  if (scopeId !== undefined) {
    const options = await memoryGraphScopeOptions(deps.db, projection);
    const selected = options.find(
      (option) => memoryGraphScopeId(projection.tenantId, option.root) === scopeId,
    );
    if (selected === undefined) throw new MemoryGraphNotFoundError();
    visible = narrowVisibleSet(visible, selected.root);
    policyVisible = policyVisibleSetForScope(allVisible, visible, selected.root);
    policyNamespace = selected.root;
  }

  const policy = await deps.getPolicy(policyNamespace);
  const routing: MemoryTopologyRouting = policy.abTest
    ? {
        mode: "ab-test",
        a: policy.abTest.a,
        b: policy.abTest.b,
        pctB: policy.abTest.pctB,
      }
    : { mode: "fixed", name: policy.retriever ?? "baseline" };

  if (visible.exact.length === 0 && visible.prefixes.length === 0) {
    return {
      scope: "selected-subtree",
      sources: [],
      activeFacts: 0,
      activityFacts: 0,
      companyPublishedFacts: 0,
      policies: [],
      memories: [],
      knowledgeBases: [],
      skills: [],
      agents: [],
      routing,
    };
  }

  const pred = visiblePredicate(visible, 1);
  const sourcePred = visiblePredicate(visible, 1, "s.namespace");
  const kbPred = visiblePredicate(visible, 1, "kb.namespace");
  const skillPred = visiblePredicate(visible, 1, "s.namespace");
  const policyPred = visiblePredicate(policyVisible, 1, "pd.namespace");
  const sourceDocumentLandingPred = visiblePredicate(
    visible,
    sourcePred.params.length + 1,
    "sd.landing_namespace",
  );

  // Every read below is independent under the SAME resolved predicate; only
  // the row-to-shape mapping afterwards is ordered (visible endpoints are
  // nulled against sets built here). Issue them together so the topology
  // costs one round trip instead of eight - the S5 space picker repaints the
  // whole projection on every pick, and serially that wait is what the user
  // sees as a frozen screen.
  const sourcesPending = deps.db.query(
    `SELECT id, namespace, kind, last_sync, sync_status, last_sync_error,
            lifecycle_state
       FROM sources s WHERE ${sourcePred.sql}
        AND s.kind NOT IN ('filesystem', 'file-upload', 'doc_site', 'policy-upload')
      ORDER BY s.created_at ASC, s.id ASC LIMIT ${GRAPH_ROW_BOUND}`,
    sourcePred.params,
  );
  const sourceDocumentsPending = topologySourceDocuments(
    deps.db,
    sourcePred,
    sourceDocumentLandingPred,
  );
  const countsPending = deps.db.query(
    `SELECT
       COUNT(*) FILTER (WHERE tier = 'L2') AS active_facts,
       COUNT(*) FILTER (WHERE tier = 'L2' AND access_count > 0) AS activity_facts
     FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL AND ${TTL_ACTIVE_CLAUSE}
       AND ${pred.sql}
       AND ${GRAPH_SOURCE_ACL_OPEN}
       AND ${GRAPH_CONTEXT_ELIGIBLE}`,
    pred.params,
  );
  const memPending = deps.db.query(
    `SELECT id, namespace, content, type, tier, access_count, t_valid_to,
            supersedes, provenance
       FROM memory_objects
      WHERE status = 'active' AND ${TTL_ACTIVE_CLAUSE}
        AND ${pred.sql}
        AND ${GRAPH_SOURCE_ACL_OPEN}
        AND ${GRAPH_CONTEXT_ELIGIBLE}
      ORDER BY (t_valid_to IS NULL) DESC, access_count DESC,
               assertion_time DESC, id ASC
      LIMIT ${MEMORY_TOPOLOGY_NODE_CAP}`,
    pred.params,
  );
  const kbPending = deps.db.query(
    `SELECT kb.id AS knowledge_base_id, kb.namespace, kb.name,
            kb.kind, kb.status, kb.source_id AS knowledge_source_id,
            file.id AS file_id, file.source_id AS file_source_id,
            file.file_name, file.status AS file_status, file.fact_count
       FROM knowledge_bases kb
       LEFT JOIN company_files file
         ON file.knowledge_base_id = kb.id
        AND file.lifecycle_state = 'active'
        AND file.t_valid_to IS NULL
      WHERE kb.lifecycle_state = 'active'
        AND kb.t_valid_to IS NULL
        AND ${kbPred.sql}
      ORDER BY kb.created_at ASC, kb.id ASC, file.created_at ASC, file.id ASC`,
    kbPred.params,
  );
  const skillsPending = deps.db.query(
    `SELECT s.id, s.namespace, s.skill_key, s.name,
            s.vetting_status, s.safety_score
       FROM skills s
      WHERE s.status = 'active' AND s.t_valid_to IS NULL
        AND ${skillPred.sql}
      ORDER BY s.namespace ASC, s.skill_key ASC LIMIT ${GRAPH_ROW_BOUND}`,
    skillPred.params,
  );
  const agentsPending = deps.db.query(
    `SELECT id, namespace, actor FROM api_keys
      WHERE role = 'agent' AND status = 'active' AND ${pred.sql}
      ORDER BY id ASC LIMIT ${GRAPH_ROW_BOUND}`,
    pred.params,
  );
  // Company-published aggregate INSIDE the projection predicate — the same
  // scope='org' AND type<>'pointer' shape migration 054 indexes. Counted
  // after authorization, so a hidden sibling's published rows never leak.
  const companyPublishedPending = deps.db.query(
    `SELECT COUNT(*) AS company_published_facts
       FROM memory_objects
      WHERE status = 'active' AND t_valid_to IS NULL AND ${TTL_ACTIVE_CLAUSE}
        AND scope = 'org' AND type <> 'pointer' AND ${pred.sql}`,
    pred.params,
  );
  const policiesPending = topologyPoliciesByPredicate(
    deps.db,
    policyPred,
    policyNamespace,
  );

  // One await over all of them: Promise.all attaches a handler to every entry,
  // so a single failing read rejects this call instead of leaving the siblings
  // as unhandled rejections.
  const [
    sourceRes,
    sourceDocumentRows,
    countRes,
    memRes,
    kbRes,
    skillRes,
    agentRes,
    companyPublishedRes,
    policies,
  ] = await Promise.all([
    sourcesPending,
    sourceDocumentsPending,
    countsPending,
    memPending,
    kbPending,
    skillsPending,
    agentsPending,
    companyPublishedPending,
    policiesPending,
  ]);

  const sources: MemoryTopologySource[] = (sourceRes.rows as Array<{
    id: string;
    namespace: string;
    kind: string;
    last_sync: Date | string | null;
    sync_status: string | null;
    last_sync_error: string | null;
    lifecycle_state: string | null;
  }>).map((row) => ({
    id: row.id,
    namespace: row.namespace,
    kind: row.kind,
    documents: [],
    documentCount: 0,
    syncStatus: (row.sync_status ??
      (row.last_sync ? "synced" : "never_synced")) as MemoryTopologySource["syncStatus"],
    lastSync:
      row.last_sync == null
        ? null
        : row.last_sync instanceof Date
          ? row.last_sync.toISOString()
          : new Date(row.last_sync).toISOString(),
    lastSyncError: row.last_sync_error ?? null,
    lifecycleState: (row.lifecycle_state ?? "active") as MemoryTopologySource["lifecycleState"],
  }));
  attachSourceDocuments(sources, sourceDocumentRows);
  const visibleSourceIds = new Set(sources.map((s) => s.id));

  const countRow = countRes.rows[0] as
    | { active_facts?: unknown; activity_facts?: unknown }
    | undefined;

  const memRows = memRes.rows as Array<{
    id: string;
    namespace: string;
    content: string;
    type: string;
    tier: "L2" | "L3";
    access_count: unknown;
    t_valid_to: unknown;
    supersedes: string | null;
    provenance: unknown;
  }>;
  const visibleMemoryIds = new Set(memRows.map((r) => r.id));
  const memories: MemoryTopologyMemory[] = memRows.map((row) => ({
    id: row.id,
    namespace: row.namespace,
    label: compactGraphLabel(row.content),
    type: row.type,
    tier: row.tier,
    accessCount: Number(row.access_count) || 0,
    state: row.t_valid_to == null ? "current" : "older",
    // D45: a visible node never exposes a hidden neighbor.
    supersedes:
      row.supersedes !== null && visibleMemoryIds.has(row.supersedes)
        ? row.supersedes
        : null,
    sourceIds: graphSourceIds(row.provenance).filter((sid) => visibleSourceIds.has(sid)),
  }));

  const knowledgeById = new Map<string, MemoryTopologyKnowledgeBase>();
  for (const raw of kbRes.rows) {
    const row = raw as {
      knowledge_base_id: string;
      namespace: string;
      name: string;
      kind: MemoryTopologyKnowledgeBase["kind"];
      status: MemoryTopologyKnowledgeBase["status"];
      knowledge_source_id: string | null;
      file_id: string | null;
      file_source_id: string | null;
      file_name: string | null;
      file_status: MemoryTopologyFile["status"] | null;
      fact_count: unknown;
    };
    let base = knowledgeById.get(row.knowledge_base_id);
    if (!base) {
      base = {
        id: row.knowledge_base_id,
        namespace: row.namespace,
        name: row.name,
        kind: row.kind,
        status: row.status,
        sourceId:
          row.knowledge_source_id !== null && visibleSourceIds.has(row.knowledge_source_id)
            ? row.knowledge_source_id
            : null,
        files: [],
      };
      knowledgeById.set(base.id, base);
    }
    if (row.file_id && row.file_source_id && row.file_name && row.file_status) {
      base.files.push({
        id: row.file_id,
        sourceId: row.file_source_id,
        name: row.file_name,
        status: row.file_status,
        factCount: Number(row.fact_count) || 0,
      });
    }
  }

  const skills = (skillRes.rows as Array<{
    id: string;
    namespace: string;
    skill_key: string;
    name: string;
    vetting_status: MemoryTopologySkill["vettingStatus"];
    safety_score: unknown;
  }>).map((row): MemoryTopologySkill => ({
    id: row.id,
    namespace: row.namespace,
    key: row.skill_key,
    name: row.name,
    vettingStatus: row.vetting_status,
    safetyScore: row.safety_score == null ? null : Number(row.safety_score),
  }));

  const agents = (agentRes.rows as Array<{
    id: string;
    namespace: string;
    actor: string;
  }>).map((row): MemoryTopologyAgent => ({
    id: row.id,
    namespace: row.namespace,
    actor: row.actor,
  }));

  const companyPublishedFacts = Number(
    (companyPublishedRes.rows[0] as { company_published_facts?: unknown } | undefined)
      ?.company_published_facts ?? 0,
  );

  return {
    scope: "selected-subtree",
    sources,
    activeFacts: Number(countRow?.active_facts) || 0,
    activityFacts: Number(countRow?.activity_facts) || 0,
    companyPublishedFacts,
    memories,
    knowledgeBases: [...knowledgeById.values()],
    skills,
    agents,
    policies,
    routing,
  };
}

/**
 * One short plain-language line per visible entity, rendered ONLY during a
 * root View-as preview ("Why visible?"). Keys are raw entity ids; values are
 * derived from the SAME projection that admitted the entity — never from any
 * hidden state, so the map can never name an invisible node.
 */
export function memoryGraphWhy(
  projection: AccessProjection,
  topology: MemoryTopology,
): Record<string, string> {
  const lineFor = (ns: Namespace): string => {
    if (projection.personalRoots.includes(ns)) return "Personal space";
    if (ns === projection.tenantId || ns === `${projection.tenantId}/common`) {
      return "Shared with everyone";
    }
    const govern = projection.governRoots.find((g) => isSelfOrDescendant(ns, g));
    if (govern !== undefined) {
      return `In ${memoryGraphScopeLabel(projection, govern)}`;
    }
    const consume = projection.consumeRoots.find((c) => isSelfOrDescendant(ns, c));
    if (consume !== undefined) {
      return `In ${memoryGraphScopeLabel(projection, consume)}`;
    }
    // Ancestor of a granted root: knowledge that flows down to this view.
    return "Shared with everyone";
  };
  const why: Record<string, string> = {};
  for (const s of topology.sources) why[s.id] = lineFor(s.namespace);
  for (const m of topology.memories) why[m.id] = lineFor(m.namespace);
  for (const kb of topology.knowledgeBases) why[kb.id] = lineFor(kb.namespace);
  for (const sk of topology.skills) why[sk.id] = lineFor(sk.namespace);
  for (const a of topology.agents) why[a.id] = lineFor(a.namespace);
  return why;
}

// ---------------------------------------------------------------------------
// S8 — audit search
// ---------------------------------------------------------------------------

/**
 * S8 audit search: run the new {@link AuditLog.search} scoped to the caller's
 * subtree — its own namespace, ancestors (shared org knowledge flows down), and
 * DESCENDANTS (an `org/support` admin must see `org/support/triage` activity).
 * The visible set is the EXACT enumerated list of namespaces in that subtree
 * (derived here so search() stays a pure `IN (...)` with no LIKE-wildcard). An
 * owner at the root searches org-wide. The filters (actor/agentId/op/result/
 * since/until/limit) are applied inside search() as parameterized, exact-
 * equality predicates with a hard LIMIT cap.
 */
export async function auditSearch(
  kernel: KernelSlice,
  identity: Identity,
  filters: AuditSearchFilters = {},
): Promise<AuditEvent[]> {
  return kernel.audit.search(filters, await auditVisibleNamespaces(kernel, identity));
}

/** Exact S8 card totals over the same filtered, subtree-scoped trail. */
export async function auditSummary(
  kernel: KernelSlice,
  identity: Identity,
  filters: AuditSearchFilters = {},
): Promise<AuditSummary> {
  return kernel.audit.summary(filters, await auditVisibleNamespaces(kernel, identity));
}

/**
 * The exact namespace list an audit read runs against — the ONE place the S8
 * fence is derived, so the CSV export can never see a row the table would not.
 */
async function auditVisibleNamespaces(
  kernel: KernelSlice,
  identity: Identity,
): Promise<Namespace[]> {
  if (isRootOwner(identity)) {
    // Owner at the root: no fence. An empty visibleNamespaces would return zero
    // rows, so pass every distinct namespace present in the log.
    const nsRes = await kernel.db.query(
      `SELECT DISTINCT namespace FROM audit_log`,
    );
    return (nsRes.rows as { namespace: string }[]).map((r) => r.namespace);
  }
  return subtreeAuditNamespaces(kernel.db, identity);
}

// ---------------------------------------------------------------------------
// S8 — audit CSV export
// ---------------------------------------------------------------------------

/** Rows per keyset page while walking the trail (never a user-facing number). */
const AUDIT_CSV_PAGE = 1000;

/**
 * Ceiling on one CSV. Reached, it is REPORTED (`truncated`), never silently
 * applied: a compliance export that quietly stopped is worse than a refused
 * one. The console turns the flag into "narrow the date range" guidance.
 */
export const AUDIT_CSV_MAX_ROWS = 100_000;

/** Column order of the exported CSV — the header row, in plain language. */
const AUDIT_CSV_COLUMNS = [
  "When (UTC)",
  "What happened",
  "Operation",
  "Who",
  "Which app or agent",
  "Where (team)",
  "Memory id",
  "Why",
  "Outcome",
  "Details",
] as const;

/**
 * Plain-English label for every audited operation. The trail is read by
 * finance, legal and HR admins, not only by engineers — `conversation_read`
 * tells them nothing. The console keeps a MIRROR of this map for the on-screen
 * table; `test/console-s8-audit.test.ts` asserts both cover every entry of
 * `AUDIT_OPS`, so a new op cannot ship without a label on either surface.
 */
export const AUDIT_OP_LABELS: Record<AuditOp, string> = {
  read: "Read a memory",
  search: "Searched memory",
  complete: "Asked the assistant",
  write: "Saved to memory",
  propose: "Proposed a change",
  edit: "Edited a memory",
  approve: "Approved a change",
  publish: "Published knowledge",
  fault: "Recalled memory mid-task",
  stats: "Viewed memory stats",
  assemble: "Assembled context",
  policy: "Received guardrails",
  policy_ack: "Acknowledged guardrails",
  policy_enforcement: "Changed a guardrail level",
  policy_delete: "Deleted a policy document",
  policy_adopt: "Added a policy file to the register",
  pin: "Pinned a memory",
  unpin: "Unpinned a memory",
  supersede: "Replaced an outdated fact",
  reject: "Rejected a proposal",
  retract: "Retracted a memory",
  move: "Moved memory between teams",
  share: "Shared memory",
  forget: "Deleted memory permanently",
  dispute: "Flagged a conflicting fact",
  resolve: "Resolved a conflict",
  export: "Exported data",
  skill_vet: "Vetted a skill",
  skill_invoke: "Used a skill",
  skill_override: "Allowed an unvetted skill",
  skill_approve: "Approved a skill",
  skill_reject: "Rejected a skill",
  automation_run: "Ran an automation",
  credit_debit: "Used paid credit",
  answer_outcome: "Recorded an answer outcome",
  conflict_scan: "Scanned for conflicts",
  conversation_read: "Read assistant history",
  conversation_write: "Saved an assistant message",
  conversation_clear: "Cleared assistant history",
  assistant_recycle: "Moved an employee's data to the recycle bin",
  assistant_restore: "Restored an employee's data",
  assistant_purge: "Purged an employee's data permanently",
  session_capture: "Recorded an agent session",
  "channel.lifecycle": "Changed a channel",
};

export interface AuditCsvExport {
  csv: string;
  filename: string;
  rowCount: number;
  /** True when {@link AUDIT_CSV_MAX_ROWS} stopped the walk before the trail did. */
  truncated: boolean;
  /** sha256 of the exact CSV bytes — the egress evidence on the audit row. */
  sha256: string;
}

/**
 * RFC-4180 quoting PLUS spreadsheet formula neutralisation.
 *
 * `detail` is attacker-influenced (a fact's content reaches it), so a value
 * starting `=`, `+`, `-`, `@`, or a lone tab/CR is prefixed with a quote:
 * Excel and Sheets execute those as formulas on open, which would turn an
 * audit download into code execution on the auditor's machine. Escaping for
 * HTML (what the screen does) does nothing about this.
 */
function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? "" : String(value);
  const neutral = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${neutral.replaceAll('"', '""')}"`;
}

/**
 * S8 CSV export — the COMPLETE filtered trail, not the screen's first page.
 *
 * Same filters and same ACL fence as {@link auditSearch}; the difference is
 * that it walks keyset pages until the trail is exhausted rather than stopping
 * at the screen cap. Rows come back newest-first by APPEND order (`seq`) — the
 * only column that can page without duplicating or skipping, and identical to
 * the screen's `ts DESC` for a real trail, whose rows are stamped as they are
 * appended. Egress is governed like every other one
 * (D4/D28): exactly one append-only `export` audit row carries the row count,
 * the filters as identifiers, and the sha256 of the bytes — never content.
 */
export async function auditExportCsv(
  kernel: KernelSlice,
  identity: Identity,
  filters: AuditSearchFilters = {},
): Promise<AuditCsvExport> {
  const visible = await auditVisibleNamespaces(kernel, identity);
  const lines: string[] = [AUDIT_CSV_COLUMNS.map(csvCell).join(",")];
  let rowCount = 0;
  let truncated = false;
  let beforeSeq: number | undefined;

  for (;;) {
    const remaining = AUDIT_CSV_MAX_ROWS - rowCount;
    if (remaining <= 0) break;
    const page = await kernel.audit.searchPage(filters, visible, {
      beforeSeq,
      limit: Math.min(AUDIT_CSV_PAGE, remaining),
    });
    for (const event of page) {
      lines.push(
        [
          csvCell(event.ts),
          csvCell(AUDIT_OP_LABELS[event.op] ?? event.op),
          csvCell(event.op),
          csvCell(event.actor),
          csvCell(event.agentId),
          csvCell(event.namespace),
          csvCell(event.memoryId ?? ""),
          csvCell(event.purpose ?? ""),
          csvCell(event.result),
          csvCell(event.detail ?? ""),
        ].join(","),
      );
      rowCount += 1;
      beforeSeq = event.seq;
    }
    if (page.length < Math.min(AUDIT_CSV_PAGE, remaining)) break;
    if (rowCount >= AUDIT_CSV_MAX_ROWS) {
      // One more probe: only claim truncation when a further row actually
      // exists, so an export of exactly the ceiling is not mislabelled.
      const more = await kernel.audit.searchPage(filters, visible, {
        beforeSeq,
        limit: 1,
      });
      truncated = more.length > 0;
      break;
    }
  }

  // Excel/Sheets only honour UTF-8 in a downloaded CSV when it is BOM-marked;
  // without it an actor name with an accent arrives mojibake.
  const csv = `﻿${lines.join("\r\n")}\r\n`;
  const sha256 = createHash("sha256").update(csv, "utf8").digest("hex");
  const stamp = new Date().toISOString();
  const namespaceSlug = (
    identity.namespace === "" ? "organization" : identity.namespace
  ).replace(/[^A-Za-z0-9._-]+/g, "-");
  const nsPart = trimRepeatedCharacter(namespaceSlug, "-") || "organization";

  await kernel.audit.append({
    ts: stamp,
    actor: identity.actor,
    agentId: "console",
    op: "export",
    memoryId: null,
    namespace: identity.namespace,
    purpose: "audit-trail-csv",
    result: rowCount > 0 ? "ok" : "miss",
    detail: JSON.stringify({
      rowCount,
      truncated,
      sha256,
      // Filter IDENTIFIERS only — the same discipline as mem_export's row.
      filters: {
        actor: filters.actor ?? null,
        agentId: filters.agentId ?? null,
        op: filters.op ?? null,
        result: filters.result ?? null,
        since: filters.since ?? null,
        until: filters.until ?? null,
      },
    }),
  });

  return {
    csv,
    filename: `halomem-audit-${nsPart}-${stamp.slice(0, 10)}.csv`,
    rowCount,
    truncated,
    sha256,
  };
}

// ---------------------------------------------------------------------------
// S6 — sources view
// ---------------------------------------------------------------------------

export interface FragmentationSummary {
  namespace: Namespace;
  ranAt: string;
  factCount: number;
  duplicateClusters: number;
  contradictions: number;
}

/**
 * Consolidated cross-source overview types (E41) — canonical home is the
 * #4 rollup module; re-exported here so existing api.ts consumers keep their
 * import path (integrator dedupe: the inline copy this file used to carry was
 * replaced by the delegation to `buildSyncOverview`).
 */
export type {
  SourceDriver,
  SourceFailureClass,
  SourceOverviewRow,
} from "./rollups/sync-overview.js";

export interface SourcesView {
  sources: {
    id: string;
    namespace: Namespace;
    kind: string;
    registrationState: "registered";
    syncMode: "manual" | "scheduled";
    syncState: "never_synced" | "last_manual_sync";
    lastManualSyncAt: string | null;
    lastSync: string | null;
    credentialId: string | null;
    syncStatus: "never_synced" | "pending" | "synced" | "failed";
    lastSyncError: string | null;
    lastSyncStartedAt: string | null;
    lifecycleState: "active" | "paused" | "disabled";
    syncIntervalSeconds: number | null;
    nextSyncAt: string | null;
    consecutiveFailures: number;
    createdAt: string;
  }[];
  /** Consolidated cross-source overview, one row per source (E41). */
  overview: SourceOverviewRow[];
  /**
   * True when the durable/provenance rollups could not be read: the overview
   * still renders with `nextRunAt`/`recordCount` unknown rather than the whole
   * screen failing (brownout, never hard-fail).
   */
  overviewDegraded: boolean;
  latestFragmentation: FragmentationSummary | null;
  /**
   * Open conflicts awaiting review, read from the S11 queue itself. Null when
   * the count could not be read — S6 says so rather than showing a zero it
   * cannot stand behind.
   */
  openConflicts: number | null;
}

/**
 * S6 sources view for the caller's subtree: the registered sources (already
 * subtree-scoped by SourceRegistry.list — a sibling's sources never appear)
 * with their last_sync, plus the summary counts of the LATEST fragmentation
 * report in the subtree (fact count + duplicate-cluster counts, read from the
 * persisted report JSON — the analysis is NOT re-run here) and the open
 * conflict count from S11.
 *
 * The fragmentation report's own `contradictions` number is NOT a conflict
 * count and is never presented as one: it counts entities that hold more than
 * one non-near-duplicate fact, which is the ordinary state of any entity anyone
 * has written about twice. It produces no reviewable row, so nothing downstream
 * can act on it. The reviewable truth is the semantic scan (S11), and that is
 * the number both screens show.
 */
export async function sourcesView(
  kernel: KernelSlice,
  identity: Identity,
  options: { skipSubtreeAggregates?: boolean } = {},
): Promise<SourcesView> {
  const rows = await kernel.sources.list(identity.namespace, isRootOwner(identity));
  // Policy uploads are immutable library records, not runnable connectors.
  // Exposing them in S6 would offer test/sync/schedule controls that cannot
  // exist for a one-shot governed file ingestion.
  const sources = rows.filter((s) => s.kind !== "policy-upload").map((s) => ({
    id: s.id,
    namespace: s.namespace,
    kind: s.kind,
    registrationState: "registered" as const,
    syncMode: s.syncIntervalSeconds ? ("scheduled" as const) : ("manual" as const),
    syncState: s.lastSync === null ? ("never_synced" as const) : ("last_manual_sync" as const),
    lastManualSyncAt: s.lastSync,
    lastSync: s.lastSync,
    credentialId: s.credentialId ?? null,
    syncStatus: s.syncStatus ?? (s.lastSync ? "synced" : "never_synced"),
    lastSyncError: s.lastSyncError ?? null,
    lastSyncStartedAt: s.lastSyncStartedAt ?? null,
    lifecycleState: s.lifecycleState ?? "active",
    syncIntervalSeconds: s.syncIntervalSeconds ?? null,
    nextSyncAt: s.nextSyncAt ?? null,
    consecutiveFailures: s.consecutiveFailures ?? 0,
    createdAt: s.createdAt,
  }));

  // D56: exact projections must not execute legacy subtree rollups merely to
  // discard them later. Source-owned status remains available above;
  // aggregate-only fields fail closed in the member UI.
  if (options.skipSubtreeAggregates === true) {
    return {
      sources,
      overview: [],
      overviewDegraded: true,
      latestFragmentation: null,
      openConflicts: null,
    };
  }

  // --- consolidated cross-source overview (E41) ------------------------------
  // Delegated to the #4 rollup module (`rollups/sync-overview.ts`) — the
  // canonical, independently ACL-scoped implementation of the durable next-run
  // and provenance record-count rollups. Brownout inside: a rollup failure
  // degrades the unknown columns, it never fails S6.
  const { overview, degraded: overviewDegraded } = await buildSyncOverview(
    kernel.db,
    identity,
    sources,
  );

  const pred = subtreePredicate(identity, 1);
  const fragRes = await kernel.db.query(
    `SELECT namespace, ran_at, json FROM fragmentation_reports
     WHERE ${pred.sql}
     ORDER BY ran_at DESC
     LIMIT 1`,
    pred.params,
  );
  let latestFragmentation: FragmentationSummary | null = null;
  if (fragRes.rows.length > 0) {
    const row = fragRes.rows[0] as {
      namespace: string;
      ran_at: unknown;
      json: unknown;
    };
    const report = parseJson(row.json) as {
      factCount?: number;
      duplicateClusters?: unknown[];
      contradictions?: unknown[];
    };
    latestFragmentation = {
      namespace: row.namespace,
      ranAt: toIso(row.ran_at),
      factCount: Number(report.factCount ?? 0),
      duplicateClusters: Array.isArray(report.duplicateClusters)
        ? report.duplicateClusters.length
        : 0,
      contradictions: Array.isArray(report.contradictions)
        ? report.contradictions.length
        : 0,
    };
  }

  // Brownout, never hard-fail: a conflict-queue read that errors (or a role
  // without conflict authority) degrades the tile to "unavailable" and leaves
  // the rest of S6 intact.
  let openConflicts: number | null = null;
  if (typeof kernel.countOpenConflicts === "function") {
    try {
      openConflicts = await kernel.countOpenConflicts(identity);
    } catch {
      openConflicts = null;
    }
  }

  return { sources, overview, overviewDegraded, latestFragmentation, openConflicts };
}

export type { SourceLineage, SourceLineageBucket } from "./rollups/source-lineage.js";

/**
 * S6 connection drawer: what ONE source has written into memory — documents,
 * record kinds, the L2/L3 split, and the newest fact it produced.
 *
 * The source id is caller-supplied, so it is resolved against the caller's OWN
 * registry listing first (D9): an id outside the caller's subtree is "not
 * found", never a lookup. The fact rollup is independently ACL-scoped on top of
 * that, so even a resolution bug cannot widen what is counted.
 */
export async function sourceLineageView(
  kernel: KernelSlice,
  identity: Identity,
  sourceId: string,
): Promise<SourceLineage> {
  const id = String(sourceId ?? "").trim();
  const rows = await kernel.sources.list(identity.namespace, isRootOwner(identity));
  // Policy uploads are hidden from S6 entirely (see sourcesView), so they have
  // no drawer to open and must not resolve here either.
  const source = rows.find((row) => row.id === id && row.kind !== "policy-upload");
  if (source === undefined) throw new Error(`no source with id ${id}`);
  return buildSourceLineage(kernel.db, identity, {
    id: source.id,
    namespace: source.namespace,
  });
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

/**
 * The immediate child of `base` on the path to `ns`, or null if `ns` is not a
 * strict descendant of `base`. `base=""` (root) → the first path segment;
 * `base="org"`, `ns="org/support/agentX"` → `"org/support"`. `ns === base`
 * returns null (not a child).
 */
function immediateChild(base: Namespace, ns: Namespace): Namespace | null {
  if (base === "") {
    if (ns === "") return null;
    const first = ns.split("/")[0];
    return first.length > 0 ? first : null;
  }
  if (ns === base) return null;
  if (!ns.startsWith(base + "/")) return null;
  const rest = ns.slice(base.length + 1);
  const seg = rest.split("/")[0];
  return seg.length > 0 ? `${base}/${seg}` : null;
}

function byCountDesc(a: RepeatLookup, b: RepeatLookup): number {
  if (b.count !== a.count) return b.count - a.count;
  return a.query < b.query ? -1 : a.query > b.query ? 1 : 0;
}

/** MIN of two caps where null = "unlimited on that side" (both null → null). */
function minCap(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return Math.min(a, b);
}

/**
 * Pull a working-set token total out of an `assemble` audit detail. Supports
 * the allocator's "blocks=N tokens=T budget=B" format and JSON payloads with a
 * `totalTokens` field (parity with the syscall layer's extractor).
 */
function extractAssembleTokens(detail: string): number | null {
  try {
    const parsed = JSON.parse(detail) as { totalTokens?: unknown };
    if (typeof parsed.totalTokens === "number") return parsed.totalTokens;
  } catch {
    // Not JSON — fall through to key=value parsing.
  }
  const match = /(?:^|\s)tokens=(\d+)/.exec(detail);
  return match ? Number(match[1]) : null;
}

function parseJson(value: unknown): unknown {
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return value ?? {};
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  return new Date(0).toISOString();
}
