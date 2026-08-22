/**
 * UNIFIED GAP FEED rollup (M9-parity #16, E51).
 *
 * Two knowledge-quality signals already exist in the single Postgres (D5) but
 * were surfaced separately: miss-bucketed audit rows (questions memory could
 * NOT answer — the S5 "gaps" table) and `fact_disputes` rows (answers memory
 * gave that a higher-trust write or a human flagged as WRONG — the S11
 * conflict queue). This module UNIONs them into ONE ranked feed carrying a
 * `missing | wrong` discriminator, so absent knowledge and wrong/conflicting
 * knowledge sit side by side for the steward.
 *
 * NO new schema: both legs read tables that already exist (audit_log,
 * fact_disputes, memory_objects). Pure read path — this module never writes,
 * never resolves, never auto-corrects. Fixing stays HUMAN-ONLY: a `wrong` item
 * carries the dispute id so the console can route the human to the existing
 * S11 dispute flow; a `missing` item is observational (the fix is feeding the
 * knowledge in, a human/source decision — never something this feed performs).
 *
 * Scoping (both signals, independently): the caller's SERVER-RESOLVED identity
 * (D9) bounds every query to its subtree — exact IN(...) ancestor list for the
 * upward leg, escaped LIKE for the descendant leg (`_`/`%` in namespaces match
 * literally). A sibling org's misses or disputes can never appear.
 *
 * Ranking (deterministic, explainable):
 *   band 2  wrong+open      — actively-poisoning answers outrank everything
 *   band 1  missing         — by miss count, then most-recent miss
 *   band 0  wrong+resolved  — recent history, trails the live work
 * Within a band: volume desc, then recency desc, then id for stability.
 *
 * Brownout, never hard-fail: each leg runs in its own try — if one query
 * throws, the feed still serves the other leg and flags `degraded: true`.
 */
import type { Db } from "../../db/client.js";
import { namespaceAncestors } from "../../index/index.js";
import { isRootOwner } from "../../auth/index.js";
import type { Identity, Namespace } from "../../types.js";

// ---------------------------------------------------------------------------
// Feed types (LOCAL — candidates for promotion to src/types.ts)
// ---------------------------------------------------------------------------

/** The discriminator: knowledge that is absent vs knowledge that is wrong. */
export type GapKind = "missing" | "wrong";

/**
 * A question agents asked that memory could not answer, aggregated from
 * audited `search`/`fault` rows whose result was `miss` (D4 guarantees every
 * miss wrote a row). Observational: lookup text is not a stable reference, so
 * no mutation is ever offered on it.
 */
export interface MissingGapItem {
  kind: "missing";
  /** Stable-enough feed key: the miss bucket is the query text itself. */
  id: string;
  query: string;
  /** Audited miss count for this exact query text. */
  count: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

/**
 * A wrong/conflicting-information signal: one `fact_disputes` row. The fix
 * path is the EXISTING S11 dispute flow (uphold-new / keep-old / edit) — this
 * feed only points the human there, it never resolves anything itself.
 */
export interface WrongGapItem {
  kind: "wrong";
  /** The fact_disputes ULID — the S11 queue key. */
  id: string;
  namespace: Namespace;
  status: "open" | "resolved";
  category: string;
  reason: string;
  /** Challenger content (truncated for the feed; S11 shows it in full). */
  disputedContent: string;
  /** Incumbent content (truncated for the feed; S11 shows it in full). */
  incumbentContent: string;
  createdAt: string;
  resolvedAt: string | null;
  resolution: string | null;
}

export type GapFeedItem = MissingGapItem | WrongGapItem;

export interface GapFeed {
  items: GapFeedItem[];
  counts: { missing: number; wrongOpen: number; wrongResolved: number };
  /** True when one leg browned out; the feed still serves the other. */
  degraded: boolean;
}

// ---------------------------------------------------------------------------
// ACL predicate — byte-compatible with rollups/sync-overview.ts and the
// console API's module-private subtreePredicate, so the three can never
// diverge in ACL semantics. Exact IN ancestors, escaped LIKE descendants.
// ---------------------------------------------------------------------------

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

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
// Helpers
// ---------------------------------------------------------------------------

const FEED_LIMIT = 100;
const CONTENT_SNIPPET_MAX = 280;
/** Resolved disputes older than this are archive, not feed. */
const RESOLVED_WINDOW_DAYS = 30;

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  return new Date(0).toISOString();
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

function snippet(content: unknown): string {
  const text = typeof content === "string" ? content : "";
  return text.length > CONTENT_SNIPPET_MAX
    ? text.slice(0, CONTENT_SNIPPET_MAX - 1) + "…"
    : text;
}

/** Severity band for the deterministic cross-kind ranking. */
function band(item: GapFeedItem): number {
  if (item.kind === "wrong") return item.status === "open" ? 2 : 0;
  return 1;
}

function volume(item: GapFeedItem): number {
  return item.kind === "missing" ? item.count : 1;
}

function recency(item: GapFeedItem): string {
  return item.kind === "missing"
    ? item.lastSeenAt
    : item.resolvedAt ?? item.createdAt;
}

// ---------------------------------------------------------------------------
// The rollup
// ---------------------------------------------------------------------------

/**
 * Build the unified gap feed for `identity`'s subtree. Read-only; each leg is
 * independently ACL-scoped and independently browns out.
 */
export async function buildGapFeed(
  db: Db,
  identity: Identity,
  now: () => Date = () => new Date(),
): Promise<GapFeed> {
  const missing: MissingGapItem[] = [];
  const wrong: WrongGapItem[] = [];
  let degraded = false;

  // --- leg 1: MISSING — miss-bucketed audit rows ---------------------------
  // Same signal the S5 memory map already reads (op search|fault, result
  // miss, purpose = the query text), aggregated in SQL instead of JS so the
  // feed carries first/last-seen recency for ranking. D4 wrote every miss.
  try {
    const missPred = subtreePredicate(identity, 1);
    const missRes = await db.query(
      `SELECT purpose, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts
         FROM audit_log
        WHERE op IN ('search', 'fault')
          AND result = 'miss'
          AND purpose IS NOT NULL
          AND ${missPred.sql}
        GROUP BY purpose
        ORDER BY n DESC, max(ts) DESC
        LIMIT ${FEED_LIMIT}`,
      missPred.params,
    );
    for (const row of missRes.rows as {
      purpose: string;
      n: unknown;
      first_ts: unknown;
      last_ts: unknown;
    }[]) {
      missing.push({
        kind: "missing",
        id: row.purpose,
        query: row.purpose,
        count: Number(row.n),
        firstSeenAt: toIso(row.first_ts),
        lastSeenAt: toIso(row.last_ts),
      });
    }
  } catch {
    degraded = true; // brownout: serve the disputes leg alone
  }

  // --- leg 2: WRONG — fact_disputes (open + recently resolved) -------------
  // Open disputes are live wrong-information work; resolved ones inside the
  // window show the correction history alongside. No mutation here, ever —
  // resolution is the S11 human flow (DisputeService.resolve).
  try {
    const disputePred = subtreePredicate(identity, 1, "d.namespace");
    const cutoffParam = `$${disputePred.params.length + 1}`;
    const cutoff = new Date(
      now().getTime() - RESOLVED_WINDOW_DAYS * 24 * 60 * 60 * 1000,
    ).toISOString();
    const disputeRes = await db.query(
      `SELECT d.id, d.namespace, d.status, d.category, d.reason,
              d.created_at, d.resolved_at, d.resolution,
              dm.content AS disputed_content, im.content AS incumbent_content
         FROM fact_disputes d
         JOIN memory_objects dm ON dm.id = d.memory_id
         JOIN memory_objects im ON im.id = d.disputed_against
        WHERE ${disputePred.sql}
          AND (d.status = 'open' OR d.resolved_at >= ${cutoffParam})
        ORDER BY (d.status = 'open') DESC, d.created_at DESC, d.id DESC
        LIMIT ${FEED_LIMIT}`,
      [...disputePred.params, cutoff],
    );
    for (const row of disputeRes.rows as {
      id: string;
      namespace: string;
      status: string;
      category: string;
      reason: string;
      created_at: unknown;
      resolved_at: unknown;
      resolution: string | null;
      disputed_content: unknown;
      incumbent_content: unknown;
    }[]) {
      wrong.push({
        kind: "wrong",
        id: row.id,
        namespace: row.namespace,
        status: row.status === "open" ? "open" : "resolved",
        category: row.category,
        reason: row.reason,
        disputedContent: snippet(row.disputed_content),
        incumbentContent: snippet(row.incumbent_content),
        createdAt: toIso(row.created_at),
        resolvedAt: toIsoOrNull(row.resolved_at),
        resolution: row.resolution ?? null,
      });
    }
  } catch {
    degraded = true; // brownout: serve the misses leg alone
  }

  // --- union + deterministic rank ------------------------------------------
  const items: GapFeedItem[] = [...wrong, ...missing]
    .sort((a, b) => {
      const bandDelta = band(b) - band(a);
      if (bandDelta !== 0) return bandDelta;
      const volumeDelta = volume(b) - volume(a);
      if (volumeDelta !== 0) return volumeDelta;
      const recencyDelta = recency(b).localeCompare(recency(a));
      if (recencyDelta !== 0) return recencyDelta;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    })
    .slice(0, FEED_LIMIT);

  return {
    items,
    counts: {
      missing: missing.length,
      wrongOpen: wrong.filter((w) => w.status === "open").length,
      wrongResolved: wrong.filter((w) => w.status === "resolved").length,
    },
    degraded,
  };
}
