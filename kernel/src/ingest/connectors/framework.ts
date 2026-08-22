/**
 * Module C — connector framework: the reusable drift engine.
 *
 * D10: connectors feed the WRITE PATH, never the store. This engine's entire
 * write surface is the `IngestSink`; its entire drift surface is the
 * `SourceState`. It imports NONE of src/index, src/db, src/audit, src/write —
 * only the shared ingestion contract in ../../types.js and node:crypto.
 *
 * Drift is content-hash, not timestamp (CONTRACTS-M3): a doc is written only
 * when its sha256 content hash differs from `SourceState.priorHash(docId)`. An
 * unchanged doc is skipped (no duplicate fact, no LLM spend). A doc that
 * vanished from the source lands in `SyncResult.removed`.
 */

import { createHash } from "node:crypto";
import type {
  Connector,
  ConnectorContext,
  IngestRecord,
  LiveQueryable,
  SyncResult,
  WriteResult,
} from "../../types.js";

// ---------------------------------------------------------------------------
// M6 live-query extension (D12) — a connector MAY implement `liveQuery()` in
// addition to `enumerate()`. Additive only: nothing below touches the drift
// engine.
// ---------------------------------------------------------------------------

/**
 * Duck-typed guard for the optional second ability (D12): a connector is
 * live-queryable iff it exposes a `liveQuery` function. The L4 lane uses this
 * to decide whether a matched pointer can be confirmed against its source.
 */
export function isLiveQueryable(c: Connector): c is Connector & LiveQueryable {
  return typeof (c as Partial<LiveQueryable>).liveQuery === "function";
}

/**
 * Thrown when a live source cannot be reached after the retry budget is spent
 * (brownout, never hard-fail: the L4 lane audits this and the phase-1 answer
 * stands). `cause` MUST already be scrubbed of credential material by the
 * thrower — this message travels into audit detail and logs.
 */
export class SourceUnavailableError extends Error {
  readonly connectorId: string;

  constructor(connectorId: string, cause: string) {
    super(`live source '${connectorId}' unavailable: ${cause}`);
    this.name = "SourceUnavailableError";
    this.connectorId = connectorId;
  }
}

/** sha256 hex of a UTF-8 string (drift key). */
export function sha256hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * One enumerated source document, before the drift engine hashes it. The
 * connector supplies the full record shape (incl. `verbatim`, which the engine
 * passes straight through to the sink); `docId` is the stable drift/dedupe key.
 */
export type EnumeratedDoc = IngestRecord;

class ConnectorDeadlineError extends Error {
  constructor() {
    super("connector sync exceeded its execution deadline");
    this.name = "ConnectorDeadlineError";
  }
}

function assertDeadline(deadlineMs: number | undefined): void {
  if (deadlineMs !== undefined && Date.now() > deadlineMs) {
    throw new ConnectorDeadlineError();
  }
}

/**
 * The reusable drift engine every connector calls. For each enumerated doc:
 *   - hash = sha256hex(content); if it equals `state.priorHash(docId)` →
 *     `unchanged`, skip (no sink write, no LLM spend).
 *   - otherwise `sink.write(record)` (passing the record's own `verbatim`),
 *     then `state.record(docId, hash, now)` → `changed`, and fold the
 *     WriteResult into the aggregate counters.
 * After the loop, docs tracked by the state but no longer enumerated are
 * reported in `removed[]` and dropped via `state.forget(removed)`.
 */
export async function syncWithDrift(
  ctx: ConnectorContext,
  enumerate: () => Promise<EnumeratedDoc[]>,
  options: { detectRemovals?: boolean; deadlineMs?: number } = {},
): Promise<SyncResult> {
  const nowIso = new Date().toISOString();
  const docs = await enumerate();

  let scanned = 0;
  let changed = 0;
  let unchanged = 0;
  let stored = 0;
  let deduplicated = 0;
  let superseded = 0;
  let rejected = 0;
  let disputed = 0;
  const errors: { docId: string; reason: string }[] = [];

  const enumeratedIds = new Set<string>();
  let claimsReleased = false;

  try {
  for (const doc of docs) {
    assertDeadline(options.deadlineMs);
    scanned += 1;
    enumeratedIds.add(doc.docId);

    const hash = sha256hex(doc.content);
    const prior = await ctx.state.priorHash(doc.docId);
    assertDeadline(options.deadlineMs);
    if (hash === prior) {
      unchanged += 1;
      continue;
    }

    try {
      const res: WriteResult = await ctx.sink.write({
        docId: doc.docId,
        content: doc.content,
        contentHash: hash,
        scope: doc.scope,
        eventTime: doc.eventTime,
        verbatim: doc.verbatim,
        sourceAccess: doc.sourceAccess,
        classification: doc.classification,
        pointer: doc.pointer,
      });
      assertDeadline(options.deadlineMs);
      // Record the drift hash UNLESS the write rejected everything and landed
      // nothing. A write that rejected all candidates (e.g. failed
      // verification) persisted NOTHING and did NOT throw; recording its hash
      // would mark a never-landed doc 'synced' forever, so every future re-sync
      // skips it → silent, unrecoverable data loss. Leaving the hash unrecorded
      // lets the next sync re-attempt the doc (mirroring the throw path, which
      // skips record()). A stored / deduped / superseded result — or any result
      // with no rejections — means the fact is genuinely present, so record it.
      // A disputed landing counts as present: the fact row exists (quarantined,
      // pending human review), so the doc must not be re-attempted every sync —
      // after a keep-old resolution that would re-quarantine a claim a human
      // already rejected.
      const droppedEverything =
        res.rejected.length > 0 &&
        res.stored.length === 0 &&
        res.deduplicated === 0 &&
        res.superseded.length === 0 &&
        (res.disputed?.length ?? 0) === 0;
      if (!droppedEverything) {
        await ctx.state.record(doc.docId, hash, nowIso, prior);
        assertDeadline(options.deadlineMs);
      }
      changed += 1;
      stored += res.stored.length;
      deduplicated += res.deduplicated;
      superseded += res.superseded.length;
      rejected += res.rejected.length;
      disputed += res.disputed?.length ?? 0;
    } catch (err) {
      if (err instanceof ConnectorDeadlineError) throw err;
      rejected += 1;
      errors.push({
        docId: doc.docId,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // `knownDocIds()` is also the SourceState cleanup boundary for unchanged
  // documents and failed writes. Run it even when a partial provider response
  // cannot safely prove removals; otherwise those claims block every retry
  // until the stale-claim window expires.
  let known: string[];
  if (options.detectRemovals === false && ctx.state.releaseClaims) {
    await ctx.state.releaseClaims();
    known = [];
  } else {
    known = await ctx.state.knownDocIds();
  }
  assertDeadline(options.deadlineMs);
  claimsReleased = true;

  // Deletion detection: doc ids tracked by the source state but not enumerated
  // this pass vanished at the source.
  let removed: string[] = [];
  if (options.detectRemovals !== false) {
    removed = known.filter((id) => !enumeratedIds.has(id));
    if (removed.length > 0) {
      await ctx.state.forget(removed);
      assertDeadline(options.deadlineMs);
    }
  }

  return {
    sourceId: ctx.sink.sourceId,
    records: changed,
    stored,
    deduplicated,
    superseded,
    rejected,
    disputed,
    errors,
    scanned,
    changed,
    unchanged,
    removed,
  };
  } finally {
    if (!claimsReleased) {
      // Preserve the primary sync error. DbSourceState has a bounded stale
      // recovery path if this best-effort release itself browns out.
      if (ctx.state.releaseClaims) await ctx.state.releaseClaims().catch(() => undefined);
      else await ctx.state.knownDocIds().catch(() => undefined);
    }
  }
}
