/**
 * Module A — append-only audit log (D4).
 *
 * Every syscall writes a row here, including denied/miss/error outcomes.
 * This class deliberately exposes NO update or delete methods — the audit
 * trail is append-only by construction.
 */

import { createHash } from "node:crypto";
import type { Db } from "../db/client.js";
import type { AuditEvent, AuditOp, MemoryId, Namespace } from "../types.js";

/**
 * Filters for {@link AuditLog.search} (M5 control-room S8 audit screen). Every
 * field is optional; each present field is an EXACT-equality predicate except
 * `since`/`until` (a `ts BETWEEN` bound) and `limit` (capped). NONE of them is
 * a namespace override — visibility is set separately by the caller's subtree.
 */
export interface AuditSearchFilters {
  actor?: string;
  agentId?: string;
  op?: AuditOp;
  result?: AuditEvent["result"];
  /** Inclusive lower ts bound (ISO-8601). */
  since?: string;
  /** Inclusive upper ts bound (ISO-8601). */
  until?: string;
  /** Requested page size; hard-capped at 500, defaults to 100. */
  limit?: number;
}

/** Exact counts for the complete filtered audit trail, before the screen cap. */
export interface AuditSummary {
  events: number;
  blocked: number;
  deletions: number;
  exports: number;
}

/** Hard cap on rows any single audit search may return (screen safety). */
export const AUDIT_SEARCH_MAX_LIMIT = 500;
/** Default page size when the caller does not specify one. */
const AUDIT_SEARCH_DEFAULT_LIMIT = 100;
/** Hard cap on one keyset page of {@link AuditLog.searchPage}. */
const AUDIT_EXPORT_PAGE_MAX = 2000;

/**
 * The WHERE clauses shared by {@link AuditLog.search} and
 * {@link AuditLog.searchPage} — one builder so a filter can never be enforced
 * on the screen but skipped on the export (or the reverse).
 *
 * `namespace IN (...)` is the ACL fence: an exact enumerated list, NEVER a
 * LIKE-wildcard, so a stored namespace containing `_`/`%` cannot act as a
 * wildcard and leak a sibling tenant. Every other predicate is exact equality
 * on a bound parameter; `since`/`until` are inclusive `ts` bounds.
 */
function auditSearchClauses(
  filters: AuditSearchFilters,
  visibleNamespaces: Namespace[],
  bind: (value: unknown) => string,
): string[] {
  const clauses: string[] = [];
  const nsPlaceholders = visibleNamespaces.map((ns) => bind(ns)).join(", ");
  clauses.push(`namespace IN (${nsPlaceholders})`);
  if (filters.actor !== undefined) clauses.push(`actor = ${bind(filters.actor)}`);
  if (filters.agentId !== undefined) clauses.push(`agent_id = ${bind(filters.agentId)}`);
  if (filters.op !== undefined) clauses.push(`op = ${bind(filters.op)}`);
  if (filters.result !== undefined) clauses.push(`result = ${bind(filters.result)}`);
  if (filters.since !== undefined) clauses.push(`ts >= ${bind(filters.since)}`);
  if (filters.until !== undefined) clauses.push(`ts <= ${bind(filters.until)}`);
  return clauses;
}

function rowToAuditEvent(r: unknown): AuditEvent {
  const row = r as Record<string, unknown>;
  const event: AuditEvent = {
    ts: row.ts instanceof Date ? row.ts.toISOString() : new Date(row.ts as string).toISOString(),
    actor: row.actor as string,
    agentId: row.agent_id as string,
    op: row.op as AuditOp,
    memoryId: (row.memory_id as MemoryId | null) ?? null,
    namespace: row.namespace as Namespace,
    purpose: (row.purpose as string | null) ?? null,
    result: row.result as AuditEvent["result"],
  };
  if (row.detail !== null && row.detail !== undefined) {
    event.detail = row.detail as string;
  }
  return event;
}

/** Low-level append primitive used by transactional and recovery paths. */
function auditDigest(event: AuditEvent, prevHash: string | null): string {
  const canonical = JSON.stringify({
    prevHash,
    ts: event.ts,
    actor: event.actor,
    agentId: event.agentId,
    op: event.op,
    memoryId: event.memoryId,
    namespace: event.namespace,
    purpose: event.purpose,
    result: event.result,
    detail: event.detail ?? null,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

async function appendAuditEventTx(db: Db, event: AuditEvent): Promise<number> {
  const head = await db.query(
    `SELECT head_hash FROM audit_chain_state WHERE singleton = TRUE FOR UPDATE`,
  );
  const prevHash = head.rows[0]?.head_hash == null ? null : String(head.rows[0].head_hash);
  const eventHash = auditDigest(event, prevHash);
  const inserted = await db.query(
    `INSERT INTO audit_log
       (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail, prev_hash, event_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     RETURNING seq`,
    [
      event.ts,
      event.actor,
      event.agentId,
      event.op,
      event.memoryId,
      event.namespace,
      event.purpose,
      event.result,
      event.detail ?? null,
      prevHash,
      eventHash,
    ],
  );
  await db.query(
    `UPDATE audit_chain_state SET head_hash = $1, updated_at = $2 WHERE singleton = TRUE`,
    [eventHash, event.ts],
  );
  // seq is BIGINT: pg binds it as text, PGlite as number — coerce either way.
  return Number((inserted.rows[0] as { seq: unknown }).seq);
}

/** Standalone append: the chain-head lock and event commit atomically. */
export async function appendAuditEvent(db: Db, event: AuditEvent): Promise<void> {
  await db.transaction((tx) => appendAuditEventTx(tx, event));
}

/** Standalone append for callers that atomically link a companion row. */
export async function appendAuditEventWithSeq(db: Db, event: AuditEvent): Promise<number> {
  return await db.transaction((tx) => appendAuditEventTx(tx, event));
}

export class AuditLog {
  constructor(private readonly db: Db) {}

  async append(event: AuditEvent): Promise<void> {
    await this.db.transaction((tx) => this.appendTo(tx, event));
  }

  /** Append and return the inserted sequence for an atomic companion row. */
  async appendWithSeq(event: AuditEvent): Promise<number> {
    return await this.db.transaction((tx) => this.appendToWithSeq(tx, event));
  }

  /**
   * Append through a caller-supplied transaction handle. Mutation paths use
   * this so their state change and D4 evidence commit or roll back together.
   * Keeping the method on the long-lived AuditLog also gives tests one narrow
   * failure-injection seam for both ordinary and transactional appends.
   */
  async appendTo(db: Db, event: AuditEvent): Promise<void> {
    await appendAuditEventTx(db, event);
  }

  /** Transaction-scoped append returning the sequence for a companion row. */
  async appendToWithSeq(db: Db, event: AuditEvent): Promise<number> {
    return await appendAuditEventTx(db, event);
  }

  /** Recompute the cryptographic chain. Legacy unhashed rows are excluded. */
  async verifyChain(): Promise<{ ok: boolean; checked: number; brokenSeq?: number }> {
    const res = await this.db.query(
      `SELECT seq, ts, actor, agent_id, op, memory_id, namespace, purpose, result,
              detail, prev_hash, event_hash
         FROM audit_log WHERE event_hash IS NOT NULL ORDER BY seq`,
    );
    let expectedPrev: string | null = null;
    let checked = 0;
    for (const raw of res.rows) {
      const row = raw as Record<string, unknown>;
      checked += 1;
      const event = rowToAuditEvent(row);
      const storedPrev = row.prev_hash == null ? null : String(row.prev_hash);
      const storedHash = String(row.event_hash);
      const expectedHash = auditDigest(event, expectedPrev);
      if (storedPrev !== expectedPrev || storedHash !== expectedHash) {
        return { ok: false, checked, brokenSeq: Number(row.seq) };
      }
      expectedPrev = storedHash;
    }
    const state = await this.db.query(
      `SELECT head_hash FROM audit_chain_state WHERE singleton = TRUE`,
    );
    const storedHead = state.rows[0]?.head_hash == null
      ? null
      : String(state.rows[0].head_hash);
    if (storedHead !== expectedPrev) {
      return { ok: false, checked };
    }
    return { ok: true, checked };
  }

  /** Most recent events first for a namespace. */
  async list(namespace: Namespace, { limit = 100 }: { limit?: number } = {}): Promise<AuditEvent[]> {
    const res = await this.db.query(
      `SELECT ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail
       FROM audit_log
       WHERE namespace = $1
       ORDER BY seq DESC
       LIMIT $2`,
      [namespace, limit],
    );
    return res.rows.map(rowToAuditEvent);
  }

  /**
   * Filtered audit search for the control-room S8 screen (M5). ADDITIVE — it
   * never changes {@link list}. Visibility is set by `visibleNamespaces`, the
   * caller's ancestor/subtree set (the SAME exact-IN-list ACL every other read
   * path uses): `namespace IN (...)`, NEVER a LIKE-wildcard, so a stored
   * namespace can never act as a `_`/`%` wildcard and leak a sibling tenant.
   * An EMPTY visible set matches nothing (returns `[]`) — an empty IN-list is
   * both invalid SQL and the correct "sees nothing" answer.
   *
   * Optional filters are EXACT equality (actor / agentId / op / result); `since`
   * and `until` are inclusive `ts` bounds; every value is bound as a parameter
   * (no interpolation). Rows come back most-recent-first, capped at 500.
   */
  async search(
    filters: AuditSearchFilters,
    visibleNamespaces: Namespace[],
  ): Promise<AuditEvent[]> {
    if (visibleNamespaces.length === 0) return [];

    const params: unknown[] = [];
    const bind = (value: unknown): string => {
      params.push(value);
      return `$${params.length}`;
    };
    const clauses = auditSearchClauses(filters, visibleNamespaces, bind);

    const limit = Math.min(
      filters.limit ?? AUDIT_SEARCH_DEFAULT_LIMIT,
      AUDIT_SEARCH_MAX_LIMIT,
    );

    const res = await this.db.query(
      `SELECT ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail
       FROM audit_log
       WHERE ${clauses.join(" AND ")}
       ORDER BY ts DESC
       LIMIT ${bind(limit)}`,
      params,
    );
    return res.rows.map(rowToAuditEvent);
  }

  /**
   * Exact aggregates for the SAME filters and exact namespace fence as
   * {@link search}. The row limit is intentionally irrelevant here: this is a
   * four-number aggregate, not another path for returning an unbounded trail.
   */
  async summary(
    filters: AuditSearchFilters,
    visibleNamespaces: Namespace[],
  ): Promise<AuditSummary> {
    if (visibleNamespaces.length === 0) {
      return { events: 0, blocked: 0, deletions: 0, exports: 0 };
    }

    const params: unknown[] = [];
    const bind = (value: unknown): string => {
      params.push(value);
      return `$${params.length}`;
    };
    const clauses = auditSearchClauses(filters, visibleNamespaces, bind);
    const res = await this.db.query(
      `SELECT
         COUNT(*) AS events,
         COALESCE(SUM(CASE WHEN result = 'denied' THEN 1 ELSE 0 END), 0) AS blocked,
         COALESCE(SUM(CASE WHEN op IN ('forget', 'assistant_purge') THEN 1 ELSE 0 END), 0) AS deletions,
         COALESCE(SUM(CASE WHEN op = 'export' THEN 1 ELSE 0 END), 0) AS exports
       FROM audit_log
       WHERE ${clauses.join(" AND ")}`,
      params,
    );
    const row = res.rows[0] as Record<string, unknown>;
    return {
      events: Number(row.events),
      blocked: Number(row.blocked),
      deletions: Number(row.deletions),
      exports: Number(row.exports),
    };
  }

  /**
   * One keyset page of the SAME filtered, subtree-scoped search, for a
   * COMPLETE governed export (the CSV download on S8). ADDITIVE — `search`
   * keeps its screen-safety cap; an export that silently stopped at 500 rows
   * while claiming to be the trail is the defect this exists to avoid.
   *
   * Pagination is keyset on `seq` (the BIGSERIAL append order), not OFFSET:
   * `seq` is unique and monotonic, so a page boundary can never duplicate or
   * skip a row even while new rows are being appended mid-export. Callers walk
   * backwards by passing the last returned `seq` as `beforeSeq`.
   *
   * The ACL predicate is unchanged: the same exact `namespace IN (...)` list,
   * never a LIKE-wildcard (M5 contract, CLAUDE.md rule 3).
   */
  async searchPage(
    filters: AuditSearchFilters,
    visibleNamespaces: Namespace[],
    page: { beforeSeq?: number; limit: number },
  ): Promise<Array<AuditEvent & { seq: number }>> {
    if (visibleNamespaces.length === 0) return [];

    const params: unknown[] = [];
    const bind = (value: unknown): string => {
      params.push(value);
      return `$${params.length}`;
    };
    const clauses = auditSearchClauses(filters, visibleNamespaces, bind);
    if (page.beforeSeq !== undefined) clauses.push(`seq < ${bind(page.beforeSeq)}`);

    const limit = Math.min(
      Math.max(1, Math.floor(page.limit)),
      AUDIT_EXPORT_PAGE_MAX,
    );
    const res = await this.db.query(
      `SELECT seq, ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail
       FROM audit_log
       WHERE ${clauses.join(" AND ")}
       ORDER BY seq DESC
       LIMIT ${bind(limit)}`,
      params,
    );
    return res.rows.map((row) => ({
      ...rowToAuditEvent(row),
      seq: Number((row as Record<string, unknown>).seq),
    }));
  }

  async count(namespace: Namespace): Promise<number> {
    const res = await this.db.query(
      `SELECT COUNT(*) AS n FROM audit_log WHERE namespace = $1`,
      [namespace],
    );
    return Number(res.rows[0].n);
  }
}

/**
 * An AuditLog that is ALREADY inside a transaction.
 *
 * `AuditLog.append` opens its own transaction so a standalone caller gets the
 * chain-head lock and the row commit atomically. Handed a transaction handle
 * instead, that same call nests — and `Db.transaction` refuses to nest. Any
 * service that writes its own audit rows (`ProductKeyService`, `AuthService`)
 * therefore cannot be reused inside a larger transaction unless its audit sink
 * knows it is already in one. This subclass is that sink: same evidence, same
 * chain, no second BEGIN.
 */
export class TransactionAuditLog extends AuditLog {
  constructor(private readonly tx: Db) {
    super(tx);
  }

  override async append(event: AuditEvent): Promise<void> {
    await this.appendTo(this.tx, event);
  }

  override async appendWithSeq(event: AuditEvent): Promise<number> {
    return await this.appendToWithSeq(this.tx, event);
  }
}
