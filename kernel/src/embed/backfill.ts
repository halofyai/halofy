/**
 * Self-healing vector backfill.
 *
 * `migrate()` realigns the embedding columns whenever the configured embedder's
 * width changes, and a width change cannot carry the old vectors across — a
 * 256-wide hash vector has no meaning in a 3072-wide semantic space. The rows
 * survive with a NULL embedding and retrieval browns out to BM25 until they are
 * re-embedded.
 *
 * That repair must not depend on an operator remembering to run a CLI, or on
 * having shell access to the container at all: until it completes, every
 * tenant's semantic search is degraded. So it runs as a bounded background pass
 * on the kernel's own poller, exactly like ColdStore.syncToDb already self-heals
 * `concepts` on every boot.
 *
 * Bounded on purpose. An embeddings deployment has finite capacity and live
 * syscall traffic must win, so each pass repairs at most BACKFILL_BATCH rows and
 * then yields; the poller comes back for the next batch. A few thousand rows
 * converge over a handful of minutes instead of saturating the provider in one
 * burst.
 */

import type { Db } from "../db/client.js";
import type { Embedder } from "../types.js";

/** Rows repaired per pass. Small enough that a pass never blocks live traffic. */
export const BACKFILL_BATCH = 32;
/**
 * Legacy rows can contain a whole fallback document rather than one extracted
 * fact. Keep repair inputs comfortably below provider token ceilings so one
 * oversized historical row cannot poison the entire batch forever.
 */
export const MAX_BACKFILL_EMBED_CHARS = 12 * 1024;

/**
 * Tables carrying a vector, and the column whose text produces it.
 *
 * `concepts` is absent by design: ColdStore.syncToDb re-embeds every concept
 * from cold storage at boot, so it repairs itself through a different path and
 * listing it here would race that one.
 */
const BACKFILL_TARGETS = [
  { table: "memory_objects", textColumn: "content", stripAnnotation: true },
  { table: "entity_registry", textColumn: "canonical_name", stripAnnotation: false },
] as const;

/**
 * The write path appends this marker AFTER embedding, and embeds only the base
 * text. Re-embedding the annotated form would place repaired rows in a
 * different region of the vector space than everything written normally.
 */
const ENTITIES_ANNOTATION = /\s*\[entities:\s*[^\]]*\]\s*$/;

function boundedBackfillText(value: string): string {
  if (value.length <= MAX_BACKFILL_EMBED_CHARS) return value;
  const separator = "\n\n[embedding excerpt]\n\n";
  const available = MAX_BACKFILL_EMBED_CHARS - separator.length;
  const head = Math.ceil(available / 2);
  const tail = Math.floor(available / 2);
  return value.slice(0, head) + separator + value.slice(value.length - tail);
}

export interface BackfillResult {
  repaired: number;
  remaining: number;
}

/**
 * Repair one batch of missing vectors. Returns what it fixed and how much is
 * still outstanding, so a caller can log convergence rather than guess at it.
 *
 * Never throws: an embedder outage leaves the rows NULL and the next pass
 * retries. Brownout, never hard-fail — a failing repair must not take down the
 * poller that also drives connectors and conflict scans.
 */
export async function runEmbeddingBackfillOnce(
  db: Db,
  embedder: Embedder,
): Promise<BackfillResult> {
  let repaired = 0;
  let remaining = 0;
  for (const target of BACKFILL_TARGETS) {
    let pending;
    try {
      pending = await db.query(
        `SELECT id, ${target.textColumn} AS text FROM ${target.table}
          WHERE embedding IS NULL ORDER BY id LIMIT $1`,
        [BACKFILL_BATCH],
      );
    } catch {
      // The table may not exist yet on a partially-migrated database.
      continue;
    }
    const rows = pending.rows as { id: string; text: string | null }[];
    const usable = rows.filter((row) => typeof row.text === "string" && row.text.trim().length > 0);
    if (usable.length > 0) {
      const inputs = usable.map((row) =>
        boundedBackfillText(target.stripAnnotation
          ? String(row.text).replace(ENTITIES_ANNOTATION, "")
          : String(row.text)));
      let vectors: number[][] | null = null;
      try {
        vectors = await embedder.embed(inputs);
      } catch {
        // Provider down or circuit open: leave the batch for the next pass. The
        // outstanding count below still runs — reporting "0 remaining" here
        // would let the CLI exit success having repaired nothing.
        vectors = null;
      }
      for (let i = 0; vectors !== null && i < usable.length; i += 1) {
        const vector = vectors[i];
        if (!vector || vector.length === 0) continue;
        try {
          await db.query(
            `UPDATE ${target.table} SET embedding = $2::vector
              WHERE id = $1 AND embedding IS NULL`,
            [usable[i]!.id, `[${vector.join(",")}]`],
          );
          repaired += 1;
        } catch {
          // A concurrent write may have supplied the vector already, or the row
          // may have gone. Either way the next pass re-reads the truth.
        }
      }
    }
    // Always counted, including after a failed batch and for an already-clean
    // table: `remaining` is what tells a caller whether convergence is done.
    try {
      const left = await db.query(
        `SELECT COUNT(*)::int AS n FROM ${target.table} WHERE embedding IS NULL`,
      );
      remaining += Number((left.rows[0] as { n?: number } | undefined)?.n ?? 0);
    } catch {
      // Counting is advisory only.
    }
  }
  return { repaired, remaining };
}
