/**
 * Per-source SYNC LINEAGE rollup — what one connected source actually put into
 * memory. The S6 connection drawer draws this as the same lineage graph the
 * memory drawer uses for a single saved memory: documents and record kinds on
 * one side, the storage tiers they landed in on the other.
 *
 * Pure read path — no schema of its own, no writes, no prompt assembly.
 *
 * Scoping: the caller never passes a namespace (D9). The source must already be
 * visible to the caller (the route resolves it from the caller's own registry
 * listing); the fact query is INDEPENDENTLY ACL-scoped on top of that, so a
 * sibling org's facts can never contribute a count even if a source id leaked.
 *
 * Brownout, never hard-fail: a rollup query that throws returns `degraded:
 * true` with null counts, and the drawer says the breakdown is unavailable
 * rather than painting a zero it cannot stand behind.
 */
import type { Db } from "../../db/client.js";
import { namespaceAncestors, TTL_ACTIVE_CLAUSE } from "../../index/index.js";
import { isRootOwner } from "../../auth/index.js";
import type { Identity, Namespace } from "../../types.js";

/** One bucket of the record breakdown: a memory `type` and how many rows. */
export interface SourceLineageBucket {
  key: string;
  count: number;
}

/** What a single connected source has contributed to memory. */
export interface SourceLineage {
  sourceId: string;
  namespace: Namespace;
  /** Distinct active current-version facts whose provenance stamps the source. */
  records: number | null;
  /** Distinct source-local documents those facts were extracted from. */
  documents: number | null;
  /** Record kinds, largest first. Capped by the caller's `typeLimit`. */
  types: SourceLineageBucket[];
  /** L2 warm / L3 cold split of the same records. */
  tiers: SourceLineageBucket[];
  /** Newest fact this source produced, ISO-8601, or null when it produced none. */
  lastRecordAt: string | null;
  /** True when the rollup browned out: counts are null, not zero. */
  degraded: boolean;
}

/** How many record-kind nodes the lineage graph can legibly carry. */
const TYPE_NODE_CAP = 4;

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * Caller's subtree predicate: exact-IN ancestor list OR escaped descendant
 * LIKE. Byte-compatible with `rollups/sync-overview.ts` — the two rollups back
 * the same screen and must never disagree about what the caller can see.
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

function toIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function count(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Build the lineage for one already-authorized source.
 *
 * `namespace` is the source registry row's own namespace — it labels the
 * result, it does NOT widen the query: the fact scan is scoped to the caller's
 * subtree independently.
 */
export async function buildSourceLineage(
  db: Db,
  identity: Identity,
  source: { id: string; namespace: Namespace },
): Promise<SourceLineage> {
  const base: SourceLineage = {
    sourceId: source.id,
    namespace: source.namespace,
    records: null,
    documents: null,
    types: [],
    tiers: [],
    lastRecordAt: null,
    degraded: true,
  };

  try {
    const pred = subtreePredicate(identity, 2);
    // One pass: the breakdown rows carry everything the drawer draws, so the
    // record total is summed here rather than paid for with a second scan.
    // `count(DISTINCT id)` is per (type, tier) — a memory holds exactly one of
    // each, so the buckets partition the set and the sum is the true total.
    const res = await db.query(
      `SELECT type,
              tier,
              count(DISTINCT memory_objects.id) AS records,
              max(assertion_time) AS last_at
         FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
        WHERE status = 'active' AND t_valid_to IS NULL
          AND ${TTL_ACTIVE_CLAUSE} AND ${pred.sql}
          AND prov.entry->>'sourceId' = $1
        GROUP BY 1, 2`,
      [source.id, ...pred.params],
    );

    const rows = res.rows as {
      type: unknown;
      tier: unknown;
      records: unknown;
      last_at: unknown;
    }[];

    const byType = new Map<string, number>();
    const byTier = new Map<string, number>();
    let records = 0;
    let lastRecordAt: string | null = null;
    for (const row of rows) {
      const n = count(row.records);
      records += n;
      const type = String(row.type ?? "").trim() || "unknown";
      const tier = String(row.tier ?? "").trim() || "L2";
      byType.set(type, (byType.get(type) ?? 0) + n);
      byTier.set(tier, (byTier.get(tier) ?? 0) + n);
      const at = toIso(row.last_at);
      if (at !== null && (lastRecordAt === null || at > lastRecordAt)) lastRecordAt = at;
    }

    // One document produces facts of several kinds, so the per-bucket document
    // counts above could not be summed without double-counting. The distinct
    // total is its own small query, asked only when this source wrote anything.
    let documents = 0;
    if (records > 0) {
      const docPred = subtreePredicate(identity, 2);
      const docRes = await db.query(
        `SELECT count(DISTINCT prov.entry->>'documentKey') AS documents
           FROM memory_objects, jsonb_array_elements(provenance) AS prov(entry)
          WHERE status = 'active' AND t_valid_to IS NULL
            AND ${TTL_ACTIVE_CLAUSE} AND ${docPred.sql}
            AND prov.entry->>'sourceId' = $1
            AND prov.entry->>'documentKey' IS NOT NULL`,
        [source.id, ...docPred.params],
      );
      documents = count((docRes.rows[0] as { documents?: unknown } | undefined)?.documents);
    }

    const rank = (entries: Map<string, number>): SourceLineageBucket[] =>
      [...entries.entries()]
        .map(([key, n]) => ({ key, count: n }))
        .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));

    return {
      ...base,
      records,
      documents,
      types: rank(byType).slice(0, TYPE_NODE_CAP),
      tiers: rank(byTier),
      lastRecordAt,
      degraded: false,
    };
  } catch {
    return base;
  }
}
