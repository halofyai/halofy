/**
 * Memory readiness score (M9-parity decision #8, E43).
 *
 * A single banded 0..100 "is this org's memory actually in shape?" number,
 * decomposed into six weighted pillars, plus a window-over-window trend.
 *
 * This module is a PURE READ MODEL, in the same shape and with the same
 * discipline as `src/console/api.ts`:
 *   - it introduces NO schema (E43) — every number comes from aggregates over
 *     tables that already exist: `memory_objects`, `audit_log`,
 *     `fact_disputes`, `sources`;
 *   - every query is ACL-scoped by the caller's server-resolved identity (D9).
 *     A root owner sees org-wide; everyone else sees an exact IN-list of their
 *     namespace ancestors PLUS their own descendants, matched with an ESCAPEd
 *     LIKE so `_`/`%` in a namespace are literal, never wildcards. Siblings are
 *     never visible. This mirrors `subtreePredicate` in `src/console/api.ts`
 *     exactly — a rollup for a team admin must include that team's children;
 *   - it never writes, never assembles a prompt (D2), and never touches the
 *     retriever (D1);
 *   - it BROWNS OUT rather than failing: any pillar whose query errors is
 *     reported `available: false`, its weight is redistributed across the
 *     pillars that did resolve, and the reason is logged on the result. A
 *     degraded score is still a score.
 *
 * The six pillars:
 *
 * | pillar     | question                                        | weight |
 * |------------|-------------------------------------------------|--------|
 * | freshness  | is what we hold recent, and are sources syncing? | 0.20   |
 * | coverage   | is the org's knowledge actually in the kernel?   | 0.20   |
 * | retrieval  | when an agent asks, does it find something?      | 0.25   |
 * | gaps       | how much read traffic misses or errors?          | 0.10   |
 * | trust      | how contested is what we hold?                   | 0.15   |
 * | structure  | how fragmented (cross-source duplication) is it? | 0.10   |
 *
 * `retrieval` and `gaps` are deliberately different measurements over different
 * denominators, not complements: `retrieval` is hit-vs-miss on the two lookup
 * ops (`search`, `fault`), while `gaps` is miss+error over ALL read traffic
 * (`read`/`search`/`fault`/`assemble`/`complete`) — an org can have a healthy
 * hit rate on searches while a lot of direct reads still come back empty.
 *
 * Fragmentation here is the CHEAP proxy for `src/ingest/fragmentation.ts`: exact
 * normalized-content duplication attributed to more than one provenance bucket.
 * It intentionally does NOT run the embedding cosine/union-find analysis — that
 * report is an on-demand job, far too expensive for a dashboard card. The full
 * report remains the drill-down; this is the indicator light.
 */

import type { Db } from "../db/client.js";
import { namespaceAncestors, TTL_ACTIVE_CLAUSE } from "../index/index.js";
import { isRootOwner } from "../auth/index.js";
import type { Identity, Namespace } from "../types.js";

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

/**
 * Banded readiness vocabulary. The repo has no pre-existing health-band union
 * to reuse (`Tier` is L2/L3 storage tiers; `degraded` is a per-run brownout
 * flag), so this is the canonical one — four bands, ordered best-first.
 */
export type ReadinessBand = "excellent" | "healthy" | "fair" | "at-risk";

/** The pillar identifiers, in display order. */
export type ReadinessPillarId =
  | "freshness"
  | "coverage"
  | "retrieval"
  | "gaps"
  | "trust"
  | "structure";

/** One pillar sub-score. `score`/`band` are null when the pillar browned out. */
export interface ReadinessPillar {
  id: ReadinessPillarId;
  /** Human label for the console card. */
  label: string;
  /** 0..100, rounded to one decimal; null when unavailable. */
  score: number | null;
  band: ReadinessBand | null;
  /** Nominal weight in the composite (before renormalization). */
  weight: number;
  /** False when the underlying aggregate could not be read (brownout). */
  available: boolean;
  /** One-line plain-English explanation of what drove the score. */
  detail: string;
  /** The raw counts behind the score — the console renders these as sub-stats. */
  metrics: Record<string, number>;
}

/**
 * Window-over-window movement. Only the audit/dispute-derived pillars are
 * genuinely windowable; `freshness`, `coverage` and `structure` are
 * point-in-time state and are held constant across both windows, so the entire
 * delta is attributable to the pillars named in `basis`. Stating that is the
 * honest alternative to back-dating state we did not snapshot.
 */
export interface ReadinessTrend {
  direction: "up" | "down" | "flat";
  /** currentScore - previousScore, in points, one decimal. */
  deltaPoints: number;
  /** The composite recomputed over the immediately preceding window. */
  previousScore: number;
  /** Length of each of the two compared windows, in days. */
  windowDays: number;
  /** The pillars that actually differ between the two windows. */
  basis: ReadinessPillarId[];
}

/** The full readiness read model. */
export interface MemoryReadiness {
  /** The caller's own namespace — server-resolved, never caller-asserted (D9). */
  namespace: Namespace;
  /** Composite 0..100, one decimal. */
  score: number;
  band: ReadinessBand;
  pillars: ReadinessPillar[];
  trend: ReadinessTrend;
  /** Observation window for the audit/dispute pillars, in days. */
  windowDays: number;
  /** True when at least one pillar browned out and weights were redistributed. */
  degraded: boolean;
  /** Why, one entry per browned-out pillar. */
  degradedReasons: string[];
  /** ISO timestamp this was computed at. */
  computedAt: string;
}

export interface ReadinessOptions {
  /** Observation window for the windowed pillars. Default 30, clamped 1..365. */
  windowDays?: number;
  /**
   * Days within which a fact (or a source sync) still counts as "fresh".
   * Default 90, clamped 1..3650.
   */
  freshnessHorizonDays?: number;
}

/**
 * The subset of the concrete Kernel this module needs. Structural, so there is
 * no import cycle with `kernel.ts` — the real Kernel satisfies it.
 */
export interface ReadinessKernelSlice {
  readonly db: Db;
}

// ---------------------------------------------------------------------------
// Tuning constants — every threshold that turns a rate into a score
// ---------------------------------------------------------------------------

const PILLAR_WEIGHTS: Record<ReadinessPillarId, number> = {
  freshness: 0.2,
  coverage: 0.2,
  retrieval: 0.25,
  gaps: 0.1,
  trust: 0.15,
  structure: 0.1,
};

const PILLAR_LABELS: Record<ReadinessPillarId, string> = {
  freshness: "Freshness",
  coverage: "Coverage",
  retrieval: "Retrieval",
  gaps: "Gaps",
  trust: "Trust",
  structure: "Structure",
};

/** Band floors, best-first. A score at or above the floor takes that band. */
const BAND_FLOORS: ReadonlyArray<readonly [ReadinessBand, number]> = [
  ["excellent", 85],
  ["healthy", 70],
  ["fair", 50],
  ["at-risk", 0],
];

/** Distinct provenance buckets at which coverage breadth saturates. */
const BREADTH_SATURATION = 5;
/** Open-dispute rate (per active fact) that scores trust at zero. */
const DISPUTE_RATE_FLOOR = 0.02;
/** Cross-source duplication rate that scores structure at zero. */
const FRAGMENTATION_RATE_FLOOR = 0.1;
/** Read ops that count toward the gaps pillar's denominator. */
const READ_OPS = ["read", "search", "fault", "assemble", "complete"];
/** Lookup ops that count toward the retrieval hit rate. */
const LOOKUP_OPS = ["search", "fault"];
/** Pillars whose value genuinely differs between the two trend windows. */
const WINDOWED_PILLARS: ReadinessPillarId[] = ["retrieval", "gaps", "trust"];

// ---------------------------------------------------------------------------
// ACL scoping — identical discipline to src/console/api.ts
// ---------------------------------------------------------------------------

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * A `namespace`-column predicate scoped to the caller's subtree, as a fragment
 * + params starting at `$startAt`. Root owner → `TRUE` (org-wide). Everyone
 * else → exact IN-list of ancestors OR an ESCAPEd `caller/%` for descendants.
 * A sibling namespace can never match either arm.
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

// ---------------------------------------------------------------------------
// Small numeric helpers
// ---------------------------------------------------------------------------

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

function round1(v: number): number {
  return Math.round(v * 10) / 10;
}

/** A rate measured against a floor, expressed as a 0..100 "less is better" score. */
function inverseRateScore(rate: number, floorRate: number): number {
  if (floorRate <= 0) return rate > 0 ? 0 : 100;
  return 100 * (1 - clamp(rate / floorRate, 0, 1));
}

export function bandFor(score: number): ReadinessBand {
  for (const [band, floor] of BAND_FLOORS) {
    if (score >= floor) return band;
  }
  return "at-risk";
}

/** A pillar that could not be computed. Weight is redistributed by the caller. */
function unavailablePillar(
  id: ReadinessPillarId,
  reason: string,
): ReadinessPillar {
  return {
    id,
    label: PILLAR_LABELS[id],
    score: null,
    band: null,
    weight: PILLAR_WEIGHTS[id],
    available: false,
    detail: `Unavailable - ${reason}`,
    metrics: {},
  };
}

function pillar(
  id: ReadinessPillarId,
  score: number,
  detail: string,
  metrics: Record<string, number>,
): ReadinessPillar {
  const s = round1(clamp(score, 0, 100));
  return {
    id,
    label: PILLAR_LABELS[id],
    score: s,
    band: bandFor(s),
    weight: PILLAR_WEIGHTS[id],
    available: true,
    detail,
    metrics,
  };
}

/**
 * Weighted mean over the AVAILABLE pillars only, with weights renormalized so a
 * brownout shifts influence rather than dragging the composite toward zero.
 * With nothing available at all the score is 0 / "at-risk" — an org we cannot
 * measure is not an org we can vouch for.
 */
function composite(pillars: ReadinessPillar[]): number {
  let weighted = 0;
  let totalWeight = 0;
  for (const p of pillars) {
    if (!p.available || p.score === null) continue;
    weighted += p.score * p.weight;
    totalWeight += p.weight;
  }
  if (totalWeight === 0) return 0;
  return round1(clamp(weighted / totalWeight, 0, 100));
}

// ---------------------------------------------------------------------------
// Pillar queries
// ---------------------------------------------------------------------------

interface FactCounts {
  active: number;
  fresh: number;
}

/** Active current-version facts, and how many were asserted inside the horizon. */
async function readFactCounts(
  db: Db,
  identity: Identity,
  horizonDays: number,
): Promise<FactCounts> {
  const pred = subtreePredicate(identity, 2);
  const res = await db.query(
    `SELECT count(*) AS active,
            count(*) FILTER (
              WHERE assertion_time > CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day')
            ) AS fresh
       FROM memory_objects
      WHERE status = 'active' AND t_valid_to IS NULL
        AND ${TTL_ACTIVE_CLAUSE} AND ${pred.sql}`,
    [String(horizonDays), ...pred.params],
  );
  const row = res.rows[0] ?? {};
  return { active: num(row.active), fresh: num(row.fresh) };
}

interface SourceCounts {
  registered: number;
  synced: number;
  recentlySynced: number;
  failing: number;
}

/** Registered (non-disabled) sources and their sync health. */
async function readSourceCounts(
  db: Db,
  identity: Identity,
  horizonDays: number,
): Promise<SourceCounts> {
  const pred = subtreePredicate(identity, 2);
  const res = await db.query(
    `SELECT count(*) AS registered,
            count(*) FILTER (WHERE sync_status = 'synced') AS synced,
            count(*) FILTER (
              WHERE last_sync IS NOT NULL
                AND last_sync > CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day')
            ) AS recently_synced,
            count(*) FILTER (WHERE sync_status = 'failed') AS failing
       FROM sources
      WHERE lifecycle_state <> 'disabled' AND ${pred.sql}`,
    [String(horizonDays), ...pred.params],
  );
  const row = res.rows[0] ?? {};
  return {
    registered: num(row.registered),
    synced: num(row.synced),
    recentlySynced: num(row.recently_synced),
    failing: num(row.failing),
  };
}

/** Distinct provenance buckets contributing active facts (coverage breadth). */
async function readProvenanceBreadth(
  db: Db,
  identity: Identity,
): Promise<number> {
  const pred = subtreePredicate(identity, 1);
  const res = await db.query(
    `SELECT count(DISTINCT COALESCE(prov.entry->>'sourceId',
                                    prov.entry->>'source', 'unknown')) AS buckets
       FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
      WHERE status = 'active' AND t_valid_to IS NULL
        AND ${TTL_ACTIVE_CLAUSE} AND ${pred.sql}`,
    pred.params,
  );
  return num(res.rows[0]?.buckets);
}

interface OpCounts {
  ok: number;
  miss: number;
  other: number;
  total: number;
}

/**
 * Audit outcome counts for `ops` over the half-open window
 * `[now - (offsetDays + windowDays), now - offsetDays)`. `offsetDays = 0` is the
 * current window; `offsetDays = windowDays` is the one before it.
 */
async function readOpCounts(
  db: Db,
  identity: Identity,
  ops: string[],
  windowDays: number,
  offsetDays: number,
): Promise<OpCounts> {
  const opList = ops.map((_, i) => `$${i + 1}`).join(", ");
  const startParam = `$${ops.length + 1}`;
  const endParam = `$${ops.length + 2}`;
  const pred = subtreePredicate(identity, ops.length + 3);
  const res = await db.query(
    `SELECT count(*) FILTER (WHERE result = 'ok') AS ok,
            count(*) FILTER (WHERE result = 'miss') AS miss,
            count(*) AS total
       FROM audit_log
      WHERE op IN (${opList})
        AND ts >= CURRENT_TIMESTAMP - (${startParam}::int * INTERVAL '1 day')
        AND ts <  CURRENT_TIMESTAMP - (${endParam}::int * INTERVAL '1 day')
        AND ${pred.sql}`,
    [
      ...ops,
      String(offsetDays + windowDays),
      String(offsetDays),
      ...pred.params,
    ],
  );
  const row = res.rows[0] ?? {};
  const ok = num(row.ok);
  const miss = num(row.miss);
  const total = num(row.total);
  return { ok, miss, total, other: Math.max(0, total - ok - miss) };
}

/** Disputes opened in a window, and how many of those are still open. */
async function readDisputeCounts(
  db: Db,
  identity: Identity,
  windowDays: number,
  offsetDays: number,
): Promise<{ raised: number; open: number }> {
  const pred = subtreePredicate(identity, 3);
  const res = await db.query(
    `SELECT count(*) AS raised,
            count(*) FILTER (WHERE status = 'open') AS open
       FROM fact_disputes
      WHERE created_at >= CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day')
        AND created_at <  CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 day')
        AND ${pred.sql}`,
    [String(offsetDays + windowDays), String(offsetDays), ...pred.params],
  );
  const row = res.rows[0] ?? {};
  return { raised: num(row.raised), open: num(row.open) };
}

/**
 * Cheap fragmentation proxy: active facts whose normalized content is attributed
 * to MORE THAN ONE provenance bucket — the same thing held twice from different
 * places. Same-source repetition is the write path's dedupe job, not
 * fragmentation, so it is excluded (mirroring `src/ingest/fragmentation.ts`).
 */
async function readDuplicationCounts(
  db: Db,
  identity: Identity,
): Promise<{ clusters: number; facts: number }> {
  const pred = subtreePredicate(identity, 1);
  const res = await db.query(
    `WITH scoped AS (
       SELECT memory_objects.id AS id,
              lower(btrim(content)) AS norm,
              COALESCE(prov.entry->>'sourceId',
                       prov.entry->>'source', 'unknown') AS bucket
         FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
        WHERE status = 'active' AND t_valid_to IS NULL
          AND ${TTL_ACTIVE_CLAUSE} AND ${pred.sql}
     ),
     dupes AS (
       SELECT norm,
              count(DISTINCT id) AS facts
         FROM scoped
        GROUP BY norm
       HAVING count(DISTINCT bucket) > 1 AND count(DISTINCT id) > 1
     )
     SELECT count(*) AS clusters, COALESCE(sum(facts), 0) AS facts FROM dupes`,
    pred.params,
  );
  const row = res.rows[0] ?? {};
  return { clusters: num(row.clusters), facts: num(row.facts) };
}

// ---------------------------------------------------------------------------
// Pillar builders
// ---------------------------------------------------------------------------

function buildFreshness(
  facts: FactCounts,
  sources: SourceCounts,
  horizonDays: number,
): ReadinessPillar {
  const factFresh = facts.active > 0 ? facts.fresh / facts.active : 0;
  const sourceFresh =
    sources.registered > 0 ? sources.recentlySynced / sources.registered : 0;
  // With nothing connected, freshness is purely about what we hold.
  const score =
    sources.registered > 0
      ? 100 * (0.7 * factFresh + 0.3 * sourceFresh)
      : 100 * factFresh;
  const detail =
    facts.active === 0
      ? "No active facts yet - nothing to keep fresh."
      : `${facts.fresh} of ${facts.active} active facts asserted in the last ` +
        `${horizonDays} days` +
        (sources.registered > 0
          ? `; ${sources.recentlySynced} of ${sources.registered} sources synced in that time.`
          : ".");
  return pillar("freshness", score, detail, {
    activeFacts: facts.active,
    freshFacts: facts.fresh,
    horizonDays,
    sourcesRegistered: sources.registered,
    sourcesRecentlySynced: sources.recentlySynced,
  });
}

function buildCoverage(
  facts: FactCounts,
  sources: SourceCounts,
  breadth: number,
): ReadinessPillar {
  const breadthRatio = clamp(breadth / BREADTH_SATURATION, 0, 1);
  const syncRatio =
    sources.registered > 0 ? sources.synced / sources.registered : 0;
  // A conversation-only org has no connectors to grade; judge it on breadth
  // alone rather than zeroing it for a lane it never opted into.
  const score =
    sources.registered > 0
      ? 100 * (0.5 * syncRatio + 0.5 * breadthRatio)
      : 100 * breadthRatio;
  const detail =
    facts.active === 0
      ? "Nothing imported or written yet - connect a source to start covering the org."
      : `${breadth} distinct provenance ${breadth === 1 ? "source" : "sources"} ` +
        `behind ${facts.active} active facts` +
        (sources.registered > 0
          ? `; ${sources.synced} of ${sources.registered} connected sources have synced.`
          : ".");
  return pillar("coverage", score, detail, {
    provenanceBuckets: breadth,
    activeFacts: facts.active,
    sourcesRegistered: sources.registered,
    sourcesSynced: sources.synced,
    sourcesFailing: sources.failing,
  });
}

function buildRetrieval(counts: OpCounts, windowDays: number): ReadinessPillar {
  const decided = counts.ok + counts.miss;
  // No lookups in the window is not a failure — it is no evidence. Score it at
  // the "fair" floor so an idle org reads as unproven, not broken.
  const score = decided > 0 ? 100 * (counts.ok / decided) : 50;
  const detail =
    decided === 0
      ? `No searches or faults in the last ${windowDays} days - hit rate unproven.`
      : `${counts.ok} of ${decided} lookups returned memory (${counts.miss} missed) ` +
        `over ${windowDays} days.`;
  return pillar("retrieval", score, detail, {
    lookups: decided,
    hits: counts.ok,
    misses: counts.miss,
    windowDays,
  });
}

function buildGaps(counts: OpCounts, windowDays: number): ReadinessPillar {
  const failed = counts.miss + counts.other;
  const score = counts.total > 0 ? 100 * (1 - failed / counts.total) : 50;
  const detail =
    counts.total === 0
      ? `No read traffic in the last ${windowDays} days - gap rate unproven.`
      : `${failed} of ${counts.total} reads came back empty, denied or errored ` +
        `over ${windowDays} days.`;
  return pillar("gaps", score, detail, {
    reads: counts.total,
    misses: counts.miss,
    deniedOrError: counts.other,
    windowDays,
  });
}

function buildTrust(
  disputes: { raised: number; open: number },
  facts: FactCounts,
  windowDays: number,
): ReadinessPillar {
  // An empty org has nothing to trust — that is 0, not a perfect record.
  if (facts.active === 0) {
    return pillar(
      "trust",
      0,
      "No active facts yet - nothing to have earned trust.",
      { disputesRaised: disputes.raised, disputesOpen: disputes.open, activeFacts: 0, windowDays },
    );
  }
  const rate = disputes.open / facts.active;
  const score = inverseRateScore(rate, DISPUTE_RATE_FLOOR);
  const detail =
    disputes.raised === 0
      ? `No facts contested in the last ${windowDays} days.`
      : `${disputes.open} of ${disputes.raised} disputes raised in ${windowDays} days ` +
        `are still open, against ${facts.active} active facts.`;
  return pillar("trust", score, detail, {
    disputesRaised: disputes.raised,
    disputesOpen: disputes.open,
    activeFacts: facts.active,
    windowDays,
  });
}

function buildStructure(
  dupes: { clusters: number; facts: number },
  facts: FactCounts,
): ReadinessPillar {
  // Same honesty as trust: an empty store is unstructured, not well-structured.
  if (facts.active === 0) {
    return pillar(
      "structure",
      0,
      "No active facts yet - no structure to grade.",
      { duplicateClusters: 0, duplicatedFacts: 0, activeFacts: 0 },
    );
  }
  const rate = dupes.facts / facts.active;
  const score = inverseRateScore(rate, FRAGMENTATION_RATE_FLOOR);
  const detail =
    dupes.clusters === 0
      ? "No cross-source duplication detected."
      : `${dupes.facts} facts across ${dupes.clusters} duplicate ` +
        `${dupes.clusters === 1 ? "cluster" : "clusters"} are held by more than one source.`;
  return pillar("structure", score, detail, {
    duplicateClusters: dupes.clusters,
    duplicatedFacts: dupes.facts,
    activeFacts: facts.active,
  });
}

// ---------------------------------------------------------------------------
// Null-tolerant pillar wrappers — a failed aggregate browns the pillar out
// ---------------------------------------------------------------------------

function retrievalPillar(
  counts: OpCounts | null,
  windowDays: number,
): ReadinessPillar {
  return counts !== null
    ? buildRetrieval(counts, windowDays)
    : unavailablePillar("retrieval", "audit aggregate unavailable");
}

function gapsPillar(counts: OpCounts | null, windowDays: number): ReadinessPillar {
  return counts !== null
    ? buildGaps(counts, windowDays)
    : unavailablePillar("gaps", "audit aggregate unavailable");
}

function trustPillar(
  disputes: { raised: number; open: number } | null,
  facts: FactCounts | null,
  windowDays: number,
): ReadinessPillar {
  return disputes !== null && facts !== null
    ? buildTrust(disputes, facts, windowDays)
    : unavailablePillar("trust", "dispute or fact aggregate unavailable");
}

function structurePillar(
  dupes: { clusters: number; facts: number } | null,
  facts: FactCounts | null,
): ReadinessPillar {
  return dupes !== null && facts !== null
    ? buildStructure(dupes, facts)
    : unavailablePillar("structure", "duplication or fact aggregate unavailable");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Compute the composite memory readiness score for the caller's ACL scope.
 *
 * `identity` is the server-resolved identity (D9) — nothing here reads a
 * namespace from a request body. Every aggregate is subtree-scoped to that
 * identity. Never throws for data reasons: a failed pillar browns out.
 */
export async function computeReadiness(
  kernel: ReadinessKernelSlice,
  identity: Identity,
  opts: ReadinessOptions = {},
): Promise<MemoryReadiness> {
  const db = kernel.db;
  const windowDays = Math.round(clamp(opts.windowDays ?? 30, 1, 365));
  const horizonDays = Math.round(
    clamp(opts.freshnessHorizonDays ?? 90, 1, 3650),
  );

  const degradedReasons: string[] = [];
  /** Run a pillar's queries; on failure record the reason and brown out. */
  const attempt = async <T>(
    id: ReadinessPillarId,
    fn: () => Promise<T>,
  ): Promise<T | null> => {
    try {
      return await fn();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      degradedReasons.push(`${id}: ${message}`);
      return null;
    }
  };

  // Facts are the denominator for three pillars, so they are read once and
  // shared. If that read fails, those pillars all brown out together.
  const facts = await attempt("freshness", () =>
    readFactCounts(db, identity, horizonDays),
  );
  const sources = await attempt("coverage", () =>
    readSourceCounts(db, identity, horizonDays),
  );
  const breadth = await attempt("coverage", () =>
    readProvenanceBreadth(db, identity),
  );
  const lookupsNow = await attempt("retrieval", () =>
    readOpCounts(db, identity, LOOKUP_OPS, windowDays, 0),
  );
  const lookupsPrev = await attempt("retrieval", () =>
    readOpCounts(db, identity, LOOKUP_OPS, windowDays, windowDays),
  );
  const readsNow = await attempt("gaps", () =>
    readOpCounts(db, identity, READ_OPS, windowDays, 0),
  );
  const readsPrev = await attempt("gaps", () =>
    readOpCounts(db, identity, READ_OPS, windowDays, windowDays),
  );
  const disputesNow = await attempt("trust", () =>
    readDisputeCounts(db, identity, windowDays, 0),
  );
  const disputesPrev = await attempt("trust", () =>
    readDisputeCounts(db, identity, windowDays, windowDays),
  );
  const dupes = await attempt("structure", () =>
    readDuplicationCounts(db, identity),
  );

  const freshness =
    facts !== null && sources !== null
      ? buildFreshness(facts, sources, horizonDays)
      : unavailablePillar("freshness", "fact or source aggregate unavailable");
  const coverage =
    facts !== null && sources !== null && breadth !== null
      ? buildCoverage(facts, sources, breadth)
      : unavailablePillar("coverage", "source or provenance aggregate unavailable");
  const retrieval = retrievalPillar(lookupsNow, windowDays);
  const gaps = gapsPillar(readsNow, windowDays);
  const trust = trustPillar(disputesNow, facts, windowDays);
  const structure = structurePillar(dupes, facts);

  const pillars = [freshness, coverage, retrieval, gaps, trust, structure];
  const score = composite(pillars);

  // Previous window: state pillars are held constant (see ReadinessTrend), so
  // the delta is entirely the windowed pillars' movement.
  const prevPillars = [
    freshness,
    coverage,
    structure,
    retrievalPillar(lookupsPrev, windowDays),
    gapsPillar(readsPrev, windowDays),
    trustPillar(disputesPrev, facts, windowDays),
  ];
  const previousScore = composite(prevPillars);
  const deltaPoints = round1(score - previousScore);

  return {
    namespace: identity.namespace,
    score,
    band: bandFor(score),
    pillars,
    trend: {
      direction: deltaPoints >= 1 ? "up" : deltaPoints <= -1 ? "down" : "flat",
      deltaPoints,
      previousScore,
      windowDays,
      basis: WINDOWED_PILLARS,
    },
    windowDays,
    degraded: degradedReasons.length > 0,
    degradedReasons,
    computedAt: new Date().toISOString(),
  };
}
