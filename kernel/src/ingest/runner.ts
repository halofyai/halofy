/**
 * Module A — ingest core: the import runner.
 *
 * Drives a batch of already-parsed `IngestRecord`s through an `IngestSink`
 * (the write path's only ingestion door — D10), aggregating the per-record
 * `WriteResult` counts into a single `IngestResult`. A throw from one record's
 * write is captured into `errors[]` and the run continues — one poisoned doc
 * never aborts a bulk import.
 *
 * `aggregate` is exported for connectors, which run their own drift loop but
 * reuse the same count-folding.
 *
 * Imports ONLY ../types.js (D10 boundary).
 */

import type {
  IngestRecord,
  IngestResult,
  IngestSink,
  WriteResult,
} from "../types.js";

/** The counts every `WriteResult` contributes to an aggregate tally. */
export interface AggregateCounts {
  stored: number;
  deduplicated: number;
  superseded: number;
  rejected: number;
  /** Facts quarantined as disputed (trust-ranked conflict). */
  disputed: number;
}

/**
 * Fold a list of `WriteResult`s into aggregate counts. Reused by the runner and
 * by connectors (which drive the sink through their own drift loop but report
 * the same tallies in `SyncResult`).
 */
export function aggregate(results: WriteResult[]): AggregateCounts {
  const counts: AggregateCounts = {
    stored: 0,
    deduplicated: 0,
    superseded: 0,
    rejected: 0,
    disputed: 0,
  };
  for (const r of results) {
    counts.stored += r.stored.length;
    counts.deduplicated += r.deduplicated;
    counts.superseded += r.superseded.length;
    counts.rejected += r.rejected.length;
    counts.disputed += r.disputed?.length ?? 0;
  }
  return counts;
}

/**
 * Run a parsed record batch through the sink. Every record is written; a
 * per-record throw is recorded in `errors[]` (keyed by `docId`) and the run
 * continues. Returns the aggregate `IngestResult`.
 */
export async function runImport(
  records: IngestRecord[],
  sink: IngestSink,
): Promise<IngestResult> {
  const written: WriteResult[] = [];
  const errors: IngestResult["errors"] = [];

  for (const record of records) {
    try {
      written.push(await sink.write(record));
    } catch (err) {
      errors.push({ docId: record.docId, reason: errorReason(err) });
    }
  }

  const counts = aggregate(written);
  return {
    sourceId: sink.sourceId,
    records: records.length,
    stored: counts.stored,
    deduplicated: counts.deduplicated,
    superseded: counts.superseded,
    rejected: counts.rejected,
    disputed: counts.disputed,
    errors,
  };
}

function errorReason(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
