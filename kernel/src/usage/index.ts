/**
 * Usage analytics / query traction (D36–D39) — write-side core.
 *
 * D36: every audited memory syscall persists a companion `usage_events` row
 * in the SAME database transaction as its audit row (FK audit_log(seq)). The
 * usage insert rides a SAVEPOINT inside the caller's transaction: if it fails,
 * the syscall still commits with its audit row (brownout) — the failure is
 * swallowed and reported through the injected `onFailure` hook.
 *
 * D37: `trace_id` groups the syscalls of one agent turn into one
 * `query_traces` rollup row (the unit of usage = one agent query/turn). It is
 * minted server-side unless the caller supplies an opaque hint (HTTP
 * `X-Halomem-Trace` / MCP `_meta.traceId`); caller hints are validated and
 * replaced with a fresh ULID when malformed. A trace id is a grouping hint,
 * never identity (D9) — and never a global key: `query_traces` is keyed
 * (namespace, trace_id), so colliding hints across tenants stay separate
 * rows.
 *
 * D39: `query_traces.query_summary` is the truncated verbatim query (first
 * 200 chars, same as the audit purpose) by default; an optional LLM
 * summarizer may upgrade it asynchronously (brownout-safe, see
 * {@link upgradeTraceSummary}).
 */

import { createHash } from "node:crypto";
import { ulid } from "ulid";
import type { Db } from "../db/client.js";

export interface UsageEventInput {
  auditSeq: number;
  traceId: string;
  ts: string;
  namespace: string;
  actor: string;
  principal: "human" | "agent";
  callerClass: string;
  op: string;
  tool: string | null;
  result: string;
  latencyMs: number;
  tokens: number;
  returned: number;
  driver: string | null;
  sourceTier: string | null;
  sourceIds: unknown[] | null;
  topScore: number | null;
  /** Verbatim query text for search ops — feeds query_sha256/query_summary. */
  queryText?: string | null;
}

/**
 * Minimal failure sink. MetricsRegistry has no counter primitive (histograms
 * only), so modules inject a hook — the kernel wires it to its logger.
 */
export interface UsageRecorderDeps {
  onFailure?: (err: unknown) => void;
}

/** D37 caller-hint shape: 1..128 chars of [A-Za-z0-9._:-]. */
const TRACE_ID_PATTERN = /^[A-Za-z0-9._:-]+$/;
const TRACE_ID_MAX_LENGTH = 128;

/** HALOMEM_USAGE_EVENTS: default ON; "0"/"false"/"no" disables. */
export function usageEventsEnabled(
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const raw = env.HALOMEM_USAGE_EVENTS?.trim().toLowerCase();
  return !(raw === "0" || raw === "false" || raw === "no");
}

/**
 * D37: keep a well-formed caller hint verbatim; anything else collapses to a
 * freshly minted ULID. Never throws, never rejects a syscall over a hint.
 */
export function resolveTraceId(supplied?: string | null): string {
  if (
    typeof supplied === "string" &&
    supplied.length >= 1 &&
    supplied.length <= TRACE_ID_MAX_LENGTH &&
    TRACE_ID_PATTERN.test(supplied)
  ) {
    return supplied;
  }
  return ulid();
}

export function querySha256(queryText: string): string {
  return createHash("sha256").update(queryText).digest("hex");
}

/**
 * Insert the usage_events row and roll the query_traces aggregate up INSIDE
 * the caller's transaction. A SAVEPOINT fences the usage writes: any failure
 * rolls back to the savepoint, is swallowed, and is reported via onFailure —
 * the surrounding syscall (and its D4 audit row) still commits.
 */
export async function recordUsageTx(
  tx: Db,
  input: UsageEventInput,
  deps?: UsageRecorderDeps,
): Promise<void> {
  if (!usageEventsEnabled()) return;
  try {
    await tx.query(`SAVEPOINT halomem_usage`);
    await tx.query(
      `INSERT INTO usage_events
         (id, audit_seq, trace_id, ts, namespace, actor, principal, caller_class,
          op, tool, result, latency_ms, tokens, returned, driver, source_tier,
          source_ids, top_score)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb, $18)`,
      [
        ulid(),
        input.auditSeq,
        input.traceId,
        input.ts,
        input.namespace,
        input.actor,
        input.principal,
        input.callerClass,
        input.op,
        input.tool,
        input.result,
        Math.max(0, Math.round(input.latencyMs)),
        input.tokens,
        input.returned,
        input.driver,
        input.sourceTier,
        input.sourceIds === null ? null : JSON.stringify(input.sourceIds),
        input.topScore,
      ],
    );
    if (input.queryText != null) {
      // Search ops: first writer wins on query_sha256/query_summary (D39 —
      // the verbatim default; an LLM summarizer may upgrade it later).
      await tx.query(
        `INSERT INTO query_traces
           (trace_id, ts, namespace, actor, query_sha256, query_summary, events, latency_ms, tokens)
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8)
         ON CONFLICT (namespace, trace_id) DO UPDATE SET
           events = query_traces.events + 1,
           latency_ms = query_traces.latency_ms + EXCLUDED.latency_ms,
           tokens = query_traces.tokens + EXCLUDED.tokens,
           query_sha256 = COALESCE(query_traces.query_sha256, EXCLUDED.query_sha256),
           query_summary = COALESCE(query_traces.query_summary, EXCLUDED.query_summary)`,
        [
          input.traceId,
          input.ts,
          input.namespace,
          input.actor,
          querySha256(input.queryText),
          input.queryText.slice(0, 200),
          Math.max(0, Math.round(input.latencyMs)),
          input.tokens,
        ],
      );
    } else {
      await tx.query(
        `INSERT INTO query_traces
           (trace_id, ts, namespace, actor, events, latency_ms, tokens)
         VALUES ($1, $2, $3, $4, 1, $5, $6)
         ON CONFLICT (namespace, trace_id) DO UPDATE SET
           events = query_traces.events + 1,
           latency_ms = query_traces.latency_ms + EXCLUDED.latency_ms,
           tokens = query_traces.tokens + EXCLUDED.tokens`,
        [
          input.traceId,
          input.ts,
          input.namespace,
          input.actor,
          Math.max(0, Math.round(input.latencyMs)),
          input.tokens,
        ],
      );
    }
    await tx.query(`RELEASE SAVEPOINT halomem_usage`);
  } catch (err) {
    try {
      await tx.query(`ROLLBACK TO SAVEPOINT halomem_usage`);
    } catch {
      // The surrounding transaction is already broken; the caller's own
      // error handling owns that outcome — nothing more to salvage here.
    }
    deps?.onFailure?.(err);
  }
}

/**
 * Brownout standalone lane for audit appends that have no surrounding
 * transaction (denied/error paths): the usage write gets its own transaction
 * and every failure is swallowed. Prefer recordUsageTx inside the audit
 * transaction whenever one exists (D36).
 */
export async function recordUsageStandalone(
  db: Db,
  input: UsageEventInput,
  deps?: UsageRecorderDeps,
): Promise<void> {
  if (!usageEventsEnabled()) return;
  try {
    await db.transaction((tx) => recordUsageTx(tx, input, deps));
  } catch (err) {
    deps?.onFailure?.(err);
  }
}

/**
 * D39: asynchronous LLM summary upgrade. The WHERE clause pins the namespace
 * AND the verbatim query hash so an upgrade can never relabel a trace whose
 * first query was different — or another tenant's row that happens to share
 * the caller's trace hint (a trace id is only a grouping hint; the primary
 * key is (namespace, trace_id)). Callers wrap this in try/catch and swallow —
 * an upgrade failure leaves the verbatim summary.
 */
export async function upgradeTraceSummary(
  db: Db,
  traceId: string,
  namespace: string,
  queryHash: string,
  summary: string,
): Promise<void> {
  await db.query(
    `UPDATE query_traces SET query_summary = $1
      WHERE trace_id = $2 AND namespace = $3 AND query_sha256 = $4`,
    [summary.slice(0, 200), traceId, namespace, queryHash],
  );
}
