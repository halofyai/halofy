/**
 * Consolidated cross-source SYNC OVERVIEW rollup (M9-parity #4, E41).
 *
 * One row per registered source: connector, ingest driver, last sync, the
 * durable scheduler's NEXT run, record volume, and a coarse failure class.
 * Pure read path — no schema of its own, no writes, no prompt assembly.
 *
 * Scoping: every query is ACL-scoped from the SERVER-RESOLVED identity (D9).
 * The caller never passes a namespace. Ancestors bind as an exact IN(...) list;
 * the descendant leg is a LIKE with an explicit ESCAPE so `_`/`%` inside a
 * namespace are matched literally.
 *
 * Brownout, never hard-fail: if either rollup query throws, the overview still
 * renders with `nextRunAt`/`recordCount` unknown and `degraded: true`.
 */
import type { Db } from "../../db/client.js";
import { namespaceAncestors, TTL_ACTIVE_CLAUSE } from "../../index/index.js";
import { isRootOwner } from "../../auth/index.js";
import {
  connectorCatalogEntry,
  isPlatformConnectorId,
} from "../../ingest/connectors/catalog/index.js";
import type { Identity, Namespace } from "../../types.js";

/**
 * How a source's records reach the write path. Server-derived from the
 * connector catalog (never caller-asserted), so the overview and the per-source
 * connection card can never disagree about what a connector actually does.
 *
 * LOCAL TYPE — candidate for promotion to src/types.ts.
 */
export type SourceDriver = "rest" | "webhook" | "file" | "builtin";

/**
 * Coarse, operator-actionable bucket for the LAST recorded sync failure.
 * Derived from the already-redacted `lastSyncError` (connectors/lifecycle.ts
 * persists `error.name`, never a provider message), so no credential or content
 * can leak through this field.
 *
 * LOCAL TYPE — candidate for promotion to src/types.ts.
 */
export type SourceFailureClass =
  | "none"
  | "auth"
  | "config"
  | "rate-limit"
  | "network"
  | "not-found"
  | "unknown";

/** The per-source registry facts the rollup joins against. */
export interface SourceOverviewInput {
  id: string;
  namespace: Namespace;
  kind: string;
  lifecycleState: "active" | "paused" | "disabled";
  syncStatus: "never_synced" | "pending" | "synced" | "failed";
  lastSync: string | null;
  syncIntervalSeconds: number | null;
  lastSyncError: string | null;
  consecutiveFailures: number;
}

/** One row of the consolidated cross-source overview (E41). */
export interface SourceOverviewRow {
  id: string;
  namespace: Namespace;
  /** Connector id (`kind`) — the catalog entry this source instantiates. */
  connector: string;
  driver: SourceDriver;
  lifecycleState: "active" | "paused" | "disabled";
  syncStatus: "never_synced" | "pending" | "synced" | "failed";
  lastSync: string | null;
  /**
   * Next durable run: the earliest `available_at` (the `notBefore` the
   * connector lifecycle enqueues with — see ingest/connectors/lifecycle.ts
   * `schedule`/`retry`) of a queued `source-sync` job for this source.
   * `null` = nothing queued (manual, push-delivery, or paused).
   */
  nextRunAt: string | null;
  nextRunState: "queued" | "running" | "none";
  syncIntervalSeconds: number | null;
  /** Active current-version facts whose provenance stamps this source id. */
  recordCount: number | null;
  failureClass: SourceFailureClass;
  lastSyncError: string | null;
  consecutiveFailures: number;
}

export interface SourceOverviewResult {
  overview: SourceOverviewRow[];
  /** True when a rollup query browned out; unknown columns render as `—`. */
  degraded: boolean;
}

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * Caller's subtree predicate: exact-IN ancestor list OR escaped descendant
 * LIKE. Mirrors the console API's `subtreePredicate` (which is module-private);
 * kept byte-compatible so the two can never diverge in ACL semantics.
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
  const likeParam = `$${n++}`;
  params.push(escapeLike(identity.namespace) + "/%");
  return {
    sql: `(${column} IN (${inList}) OR ${column} LIKE ${likeParam} ESCAPE '\\')`,
    params,
  };
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  return new Date(0).toISOString();
}

/** Ingest driver for a connector kind — catalog first, then the built-ins. */
export function sourceDriver(kind: string): SourceDriver {
  if (isPlatformConnectorId(kind)) return connectorCatalogEntry(kind).runtime.adapter;
  return "builtin";
}

/**
 * Bucket a redacted `lastSyncError`. Substring matching over an `error.name` is
 * deliberately coarse: the point is "who fixes this", not a diagnosis. Anything
 * unrecognised stays `unknown` rather than being guessed.
 */
export function failureClass(
  lastSyncError: string | null,
  failed: boolean,
): SourceFailureClass {
  const error = (lastSyncError ?? "").toLowerCase();
  if (error === "") return failed ? "unknown" : "none";
  if (/auth|credential|token|unauthor|forbidden|permission|401|403/.test(error)) return "auth";
  if (/config|validation|invalid|schema|conformance|400|422/.test(error)) return "config";
  if (/rate|throttl|quota|429/.test(error)) return "rate-limit";
  if (/timeout|econn|enotfound|network|socket|dns|fetch|502|503|504/.test(error)) return "network";
  if (/not.?found|missing|404/.test(error)) return "not-found";
  return "unknown";
}

/**
 * Build the consolidated overview for `identity`'s subtree.
 *
 * `sources` must already be subtree-scoped by the caller (SourceRegistry.list);
 * the two rollup queries are independently ACL-scoped so a sibling org's job or
 * fact can never contribute a next-run time or a record count.
 */
export async function buildSyncOverview(
  db: Db,
  identity: Identity,
  sources: SourceOverviewInput[],
): Promise<SourceOverviewResult> {
  const nextRuns = new Map<string, { at: string | null; running: boolean }>();
  const recordCounts = new Map<string, number>();
  let degraded = false;

  try {
    const jobPred = subtreePredicate(identity, 1);
    const jobRes = await db.query(
      `SELECT payload->>'sourceId' AS source_id,
              min(available_at) FILTER (WHERE state = 'queued') AS next_at,
              bool_or(state = 'running') AS running
         FROM durable_jobs
        WHERE kind = 'source-sync'
          AND state IN ('queued', 'running')
          AND payload->>'sourceId' IS NOT NULL
          AND ${jobPred.sql}
        GROUP BY 1`,
      jobPred.params,
    );
    for (const row of jobRes.rows as {
      source_id: string;
      next_at: unknown;
      running: unknown;
    }[]) {
      nextRuns.set(row.source_id, {
        at: row.next_at === null || row.next_at === undefined ? null : toIso(row.next_at),
        running: row.running === true,
      });
    }

    const provPred = subtreePredicate(identity, 1);
    const countRes = await db.query(
      `SELECT prov.entry->>'sourceId' AS source_id,
              count(DISTINCT memory_objects.id) AS n
         FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
        WHERE status = 'active' AND t_valid_to IS NULL
          AND ${TTL_ACTIVE_CLAUSE} AND ${provPred.sql}
          AND prov.entry->>'sourceId' IS NOT NULL
        GROUP BY 1`,
      provPred.params,
    );
    for (const row of countRes.rows as { source_id: string; n: unknown }[]) {
      recordCounts.set(row.source_id, Number(row.n));
    }
  } catch {
    // Rollup brownout: render with unknown next-run/record counts.
    degraded = true;
  }

  const overview: SourceOverviewRow[] = sources.map((s) => {
    const job = nextRuns.get(s.id);
    return {
      id: s.id,
      namespace: s.namespace,
      connector: s.kind,
      driver: sourceDriver(s.kind),
      lifecycleState: s.lifecycleState,
      syncStatus: s.syncStatus,
      lastSync: s.lastSync,
      nextRunAt: job?.at ?? null,
      nextRunState:
        job === undefined ? "none" : job.running ? "running" : job.at ? "queued" : "none",
      syncIntervalSeconds: s.syncIntervalSeconds,
      recordCount: degraded ? null : recordCounts.get(s.id) ?? 0,
      failureClass: failureClass(s.lastSyncError, s.syncStatus === "failed"),
      lastSyncError: s.lastSyncError,
      consecutiveFailures: s.consecutiveFailures,
    };
  });

  return { overview, degraded };
}
