/**
 * Answer-outcome capture + accuracy rollup (#18, D31).
 *
 * First-class per-turn correctness signal for the copilot / agent answer
 * surface. Every turn that produced an answer may carry exactly ONE current
 * outcome row in `answer_outcomes` (unique on (namespace, turn_id) where
 * t_valid_to IS NULL):
 *
 *   - "answered"                a human confirmed the answer was right
 *   - "weak"                    the answer was judged thin / partially wrong
 *   - "disputed"                the answer was wrong; optionally linked to the
 *                               existing `fact_disputes` machinery (src/disputes/)
 *                               via `dispute_id` — this module deliberately does
 *                               NOT build a second dispute system
 *   - "answered-without-human"  the agent answered and no human has weighed in
 *
 * Write-path discipline (D10): outcomes are governance rows — like
 * `fact_disputes`, not memory facts — so they never pass through LLM
 * extraction, but they land through THIS single governed ingress with the same
 * invariants the write path enforces: identity is server-resolved (D9 — the
 * namespace and actor come ONLY from the resolved Identity, never the body),
 * the state change and its D4 audit row (`answer_outcome` op) commit in the
 * same transaction, and a re-recorded turn SUPERSEDES the prior row (D7 —
 * close `t_valid_to`, link `supersedes`; never overwrite, never delete).
 * Nothing else in the kernel writes `answer_outcomes`.
 *
 * Accuracy (D31/E33) is DERIVED here and only here, from those audited rows
 * (every row exists because a transaction also committed its audit evidence)
 * plus the open `fact_disputes` wrong-answer signal — a caller can never
 * assert an accuracy number:
 *
 *   accuracy = (answered turns that are not disputed and not weak) / answered turns
 *
 * where "answered turns" = every current outcome row (all four outcomes are
 * turns that received an answer) PLUS open disputes not already linked from an
 * outcome row (the pre-existing wrong-answer signal folds into the
 * denominator instead of being lost).
 */

import { createHash } from "node:crypto";
import { ulid } from "ulid";
import type { AuditEvent, Identity, Namespace } from "../types.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import { isOversightRole } from "../auth/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The four capturable per-turn outcomes (mirrors the answer_outcomes CHECK). */
export type AnswerOutcome = "answered" | "weak" | "disputed" | "answered-without-human";

const OUTCOMES: readonly AnswerOutcome[] = [
  "answered",
  "weak",
  "disputed",
  "answered-without-human",
];

/**
 * Outcomes an `agent`-role badge may self-report. An agent can state THAT it
 * answered (unverified) or that its own answer was weak — it can never assert
 * a human judgement ("answered" / "disputed" are human-resolved states, D9).
 */
const AGENT_OUTCOMES: readonly AnswerOutcome[] = ["answered-without-human", "weak"];

export class AnswerOutcomeValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnswerOutcomeValidationError";
  }
}

export class AnswerOutcomeAuthorizationError extends Error {
  constructor(message = "answer-outcome operation denied") {
    super(message);
    this.name = "AnswerOutcomeAuthorizationError";
  }
}

export interface RecordAnswerOutcomeInput {
  /** The caller's stable turn identifier (1..200 chars). */
  turnId: string;
  outcome: AnswerOutcome;
  /** Optional session/conversation identifier for grouping. */
  session?: string;
  /**
   * The question text; hashed server-side to `query_sha256` — the raw query is
   * NEVER stored by this module. Mutually exclusive with `querySha256`.
   */
  queryText?: string;
  /** Pre-hashed alternative to `queryText` (sha256 hex). */
  querySha256?: string;
  /** Memory/evidence ids the answer cited (capped, stored as JSONB). */
  evidenceIds?: string[];
  /** Free-text note from the resolver (capped). */
  detail?: string;
  /**
   * Link to an existing `fact_disputes` row (src/disputes/). Only valid with
   * outcome "disputed"; the dispute must exist and be visible to the caller.
   */
  disputeId?: string;
  /**
   * D37: optional link to the query_traces rollup row for the turn that
   * produced the answer. Validated against the same shape rule as
   * resolveTraceId (1..128 chars of [A-Za-z0-9._:-]); unlike the syscall
   * trace hint, a malformed value here is rejected (400), never regrouped.
   */
  traceId?: string;
}

export interface RecordAnswerOutcomeResult {
  id: string;
  turnId: string;
  outcome: AnswerOutcome;
  /** Prior current row this record closed and superseded (D7), if any. */
  superseded: string | null;
  /** True when the current row already carried this exact outcome (no-op). */
  deduplicated: boolean;
}

export interface AccuracyWindow {
  /** Inclusive lower `created_at` bound (ISO-8601). */
  since?: string;
  /** Inclusive upper `created_at` bound (ISO-8601). */
  until?: string;
}

/** The derived accuracy rollup (E33). Counts are current rows only. */
export interface AccuracyRollup {
  namespace: Namespace;
  since: string | null;
  until: string | null;
  /** Current-outcome bucket counts. */
  answered: number;
  weak: number;
  disputed: number;
  answeredWithoutHuman: number;
  /**
   * Open `fact_disputes` in scope NOT already linked from a current outcome
   * row — the pre-existing wrong-answer signal, folded into the denominator.
   */
  openDisputes: number;
  /** Denominator: every answered turn (all buckets) + unlinked open disputes. */
  answeredTotal: number;
  /** Numerator: answered turns that are not disputed and not weak. */
  accurate: number;
  /** accurate / answeredTotal; null when nothing has been answered. */
  accuracy: number | null;
  /**
   * Stricter secondary lane: human-verified correct over human-assessed
   * turns — answered / (answered + weak + disputed + openDisputes). Excludes
   * "answered-without-human" entirely. Null when the denominator is 0.
   */
  verifiedAccuracy: number | null;
}

interface FeedbackAuditWriter {
  /** Standalone append (own transaction) — denied/error evidence (D4). */
  append(event: AuditEvent): Promise<void>;
  /** Transactional append — the ok row commits WITH the state change (D4). */
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface AnswerOutcomeDependencies {
  db: Db;
  audit: FeedbackAuditWriter;
  now?(): Date;
}

// ---------------------------------------------------------------------------
// Input parsing (transport-agnostic; the HTTP adapter can call this directly)
// ---------------------------------------------------------------------------

const MAX_TURN_ID = 200;
const MAX_SESSION = 200;
const MAX_DETAIL = 2_000;
const MAX_QUERY_TEXT = 100_000;
const MAX_EVIDENCE_IDS = 64;
const MAX_EVIDENCE_ID_LEN = 100;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_TRACE_ID = 128;
/**
 * D37: same shape rule as resolveTraceId — but a traceId here is a direct
 * API field, so a malformed value is a 400, never a silent regroup.
 */
const TRACE_ID_PATTERN = /^[A-Za-z0-9._:-]+$/;

function requireString(value: unknown, field: string, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new AnswerOutcomeValidationError(`${field} must be a 1..${max} character string`);
  }
  return value;
}

/**
 * Validate an untrusted request body into a {@link RecordAnswerOutcomeInput}.
 * Deliberately REJECTS identity-shaped fields (`namespace`, `actor`,
 * `resolvedBy`) — identity is server-resolved (D9); a body asserting one is a
 * caller bug surfaced loudly, not silently ignored.
 */
export function parseAnswerOutcomeBody(body: unknown): RecordAnswerOutcomeInput {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new AnswerOutcomeValidationError("body must be a JSON object");
  }
  const b = body as Record<string, unknown>;
  for (const forbidden of ["namespace", "actor", "resolvedBy", "resolved_by"]) {
    if (forbidden in b) {
      throw new AnswerOutcomeValidationError(
        `'${forbidden}' is server-resolved and may not appear in the request body (D9)`,
      );
    }
  }
  const turnId = requireString(b.turnId, "turnId", MAX_TURN_ID);
  if (typeof b.outcome !== "string" || !OUTCOMES.includes(b.outcome as AnswerOutcome)) {
    throw new AnswerOutcomeValidationError(`outcome must be one of ${OUTCOMES.join(", ")}`);
  }
  const input: RecordAnswerOutcomeInput = {
    turnId,
    outcome: b.outcome as AnswerOutcome,
  };
  if (b.session !== undefined) input.session = requireString(b.session, "session", MAX_SESSION);
  if (b.queryText !== undefined && b.querySha256 !== undefined) {
    throw new AnswerOutcomeValidationError("provide queryText or querySha256, not both");
  }
  if (b.queryText !== undefined) {
    input.queryText = requireString(b.queryText, "queryText", MAX_QUERY_TEXT);
  }
  if (b.querySha256 !== undefined) {
    const hash = requireString(b.querySha256, "querySha256", 64);
    if (!SHA256_HEX.test(hash)) {
      throw new AnswerOutcomeValidationError("querySha256 must be 64 lowercase hex characters");
    }
    input.querySha256 = hash;
  }
  if (b.evidenceIds !== undefined) {
    if (!Array.isArray(b.evidenceIds) || b.evidenceIds.length > MAX_EVIDENCE_IDS) {
      throw new AnswerOutcomeValidationError(
        `evidenceIds must be an array of at most ${MAX_EVIDENCE_IDS} ids`,
      );
    }
    input.evidenceIds = b.evidenceIds.map((id, i) =>
      requireString(id, `evidenceIds[${i}]`, MAX_EVIDENCE_ID_LEN),
    );
  }
  if (b.detail !== undefined) input.detail = requireString(b.detail, "detail", MAX_DETAIL);
  if (b.disputeId !== undefined) {
    input.disputeId = requireString(b.disputeId, "disputeId", MAX_EVIDENCE_ID_LEN);
  }
  if (b.traceId !== undefined) {
    const traceId = requireString(b.traceId, "traceId", MAX_TRACE_ID);
    if (!TRACE_ID_PATTERN.test(traceId)) {
      throw new AnswerOutcomeValidationError(
        "traceId must be 1..128 characters of [A-Za-z0-9._:-]",
      );
    }
    input.traceId = traceId;
  }
  if (input.disputeId !== undefined && input.outcome !== "disputed") {
    throw new AnswerOutcomeValidationError("disputeId is only valid with outcome 'disputed'");
  }
  return input;
}

// ---------------------------------------------------------------------------
// ACL helpers (same discipline as every other read path: exact IN(...) over
// the '/'-split ancestor set; descendants matched with an ESCAPEd LIKE so
// `_`/`%` in a namespace are literal — never SQL wildcards)
// ---------------------------------------------------------------------------

function isRootOwner(identity: Identity): boolean {
  return identity.role === "owner" && identity.namespace === "";
}

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

/** Mirror of DisputeService.canRead: ancestors read-up + admin subtree down. */
function canReadDisputeNamespace(identity: Identity, namespace: Namespace): boolean {
  if (isRootOwner(identity)) return true;
  if (namespaceAncestors(identity.namespace).includes(namespace)) return true;
  return (
    (identity.role === "owner" || identity.role === "admin" || identity.role === "auditor") &&
    namespaceAncestors(namespace).includes(identity.namespace)
  );
}

function assertIsoOrUndefined(value: string | undefined, field: string): void {
  if (value === undefined) return;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new AnswerOutcomeValidationError(`${field} must be an ISO-8601 timestamp`);
  }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

interface CurrentOutcomeRow {
  id: string;
  outcome: string;
  dispute_id: string | null;
  /** Non-null iff a HUMAN resolved this row (D31 supersede authorization). */
  resolved_by: string | null;
}

export class AnswerOutcomeService {
  private readonly now: () => Date;

  constructor(private readonly deps: AnswerOutcomeDependencies) {
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Record (or supersede) the outcome of one answered turn. The single
   * governed ingress for `answer_outcomes` (D10-style discipline):
   *
   *   - namespace/actor/resolved_by come ONLY from `identity` (D9, E31);
   *   - the row and its `answer_outcome` audit evidence commit in ONE
   *     transaction (D4, D5 — the one Postgres, E32);
   *   - a re-record closes the prior row and links `supersedes` (D7);
   *   - D37: an optional traceId is stored on the row and back-linked onto
   *     the query_traces rollup (its outcome column) in the same transaction;
   *   - denied and error outcomes still audit (D4).
   */
  async record(
    identity: Identity,
    input: RecordAnswerOutcomeInput,
  ): Promise<RecordAnswerOutcomeResult> {
    const ts = this.now().toISOString();

    // --- authorization (server-resolved role; auditors are read-only) ------
    if (identity.role === "auditor") {
      await this.auditOutcome(identity, ts, "denied", input.turnId,
        `role 'auditor' may not record answer outcomes`);
      throw new AnswerOutcomeAuthorizationError("auditors may not record answer outcomes");
    }
    if (identity.role === "agent" && !AGENT_OUTCOMES.includes(input.outcome)) {
      await this.auditOutcome(identity, ts, "denied", input.turnId,
        `agent badge may not assert human-resolved outcome '${input.outcome}'`);
      throw new AnswerOutcomeAuthorizationError(
        `an agent badge may only record ${AGENT_OUTCOMES.join(" or ")}`,
      );
    }

    // --- validation (defense in depth even when the transport parsed) ------
    try {
      this.validate(input);
    } catch (err) {
      await this.auditOutcome(identity, ts, "error", input.turnId,
        err instanceof Error ? err.message : String(err));
      throw err;
    }

    // --- dispute link: integrate with src/disputes/, never a parallel lane -
    if (input.disputeId !== undefined) {
      const found = await this.deps.db.query(
        `SELECT namespace FROM fact_disputes WHERE id = $1`,
        [input.disputeId],
      );
      const disputeNs = found.rows[0]?.namespace as string | undefined;
      if (disputeNs === undefined || !canReadDisputeNamespace(identity, disputeNs)) {
        // One indistinguishable denial for missing vs. invisible (no oracle).
        await this.auditOutcome(identity, ts, "denied", input.turnId,
          `dispute '${input.disputeId}' not found or not visible`);
        throw new AnswerOutcomeAuthorizationError("dispute not found or not visible");
      }
    }

    const querySha256 =
      input.querySha256 ??
      (input.queryText !== undefined
        ? createHash("sha256").update(input.queryText).digest("hex")
        : null);
    // Human-resolved states carry the resolver; agent self-reports do not.
    const resolvedBy =
      identity.role !== "agent" && input.outcome !== "answered-without-human"
        ? identity.actor
        : null;
    const id = ulid();

    try {
      return await this.deps.db.transaction(async (tx) => {
        const current = await tx.query(
          `SELECT id, outcome, dispute_id, resolved_by FROM answer_outcomes
            WHERE namespace = $1 AND turn_id = $2 AND t_valid_to IS NULL
            FOR UPDATE`,
          [identity.namespace, input.turnId],
        );
        const prior = current.rows[0] as CurrentOutcomeRow | undefined;

        // D37: back-link the trace rollup to the recorded outcome in the SAME
        // transaction. Zero rows updated = no such trace in this namespace —
        // not an error (the link is additive, never an existence oracle).
        const linkTrace = async (outcome: AnswerOutcome): Promise<void> => {
          if (input.traceId === undefined) return;
          await tx.query(
            `UPDATE query_traces SET outcome = $1
              WHERE trace_id = $2 AND namespace = $3`,
            [outcome, input.traceId, identity.namespace],
          );
        };

        // D31/E33: an agent badge can never assert a human judgement — and
        // that includes ERASING one. If the current row was human-resolved
        // (resolved_by non-null), an agent-role caller may neither supersede
        // nor re-record it; otherwise a 'weak' self-report would close a
        // human 'answered' and silently poison the derived accuracy figure.
        if (
          prior !== undefined &&
          identity.role === "agent" &&
          prior.resolved_by !== null
        ) {
          throw new AnswerOutcomeAuthorizationError(
            "an agent badge may not supersede a human-resolved outcome",
          );
        }

        if (
          prior !== undefined &&
          prior.outcome === input.outcome &&
          (prior.dispute_id ?? null) === (input.disputeId ?? null)
        ) {
          // Idempotent re-record: no new chain link, but the syscall audits.
          // The trace back-link still applies — the outcome stands.
          await linkTrace(input.outcome);
          await this.deps.audit.appendTo(tx, this.event(identity, ts, "ok",
            `turn=${input.turnId} outcome=${input.outcome} dedup row=${prior.id}`));
          return {
            id: prior.id,
            turnId: input.turnId,
            outcome: input.outcome,
            superseded: null,
            deduplicated: true,
          };
        }

        if (prior !== undefined) {
          // Guarded close (D7): zero rows = concurrent supersede; roll back.
          const closed = await tx.query(
            `UPDATE answer_outcomes SET t_valid_to = $2
              WHERE id = $1 AND t_valid_to IS NULL RETURNING id`,
            [prior.id, ts],
          );
          if (closed.rows.length !== 1) {
            throw new AnswerOutcomeValidationError(
              `turn '${input.turnId}' was re-recorded concurrently; retry`,
            );
          }
        }

        await tx.query(
          `INSERT INTO answer_outcomes
             (id, namespace, turn_id, session, actor, query_sha256, outcome,
              resolved_by, dispute_id, evidence_ids, detail, supersedes,
              t_valid_from, t_valid_to, created_at, trace_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, $14, $15)`,
          [
            id,
            identity.namespace,
            input.turnId,
            input.session ?? null,
            identity.actor,
            querySha256,
            input.outcome,
            resolvedBy,
            input.disputeId ?? null,
            JSON.stringify(input.evidenceIds ?? []),
            input.detail ?? null,
            prior?.id ?? null,
            ts,
            ts,
            input.traceId ?? null,
          ],
        );
        // D37: on the supersede path the NEW current row's outcome is what
        // the trace rollup links to.
        await linkTrace(input.outcome);
        await this.deps.audit.appendTo(tx, this.event(identity, ts, "ok",
          `turn=${input.turnId} outcome=${input.outcome} row=${id}` +
            (prior ? ` supersedes=${prior.id}` : "") +
            (input.disputeId ? ` dispute=${input.disputeId}` : "")));
        return {
          id,
          turnId: input.turnId,
          outcome: input.outcome,
          superseded: prior?.id ?? null,
          deduplicated: false,
        };
      });
    } catch (err) {
      if (err instanceof AnswerOutcomeAuthorizationError) {
        // Denied inside the transaction (state change rolled back): the
        // denial still leaves standalone audit evidence (D4).
        try {
          await this.auditOutcome(identity, ts, "denied", input.turnId, err.message);
        } catch { /* audit brownout: the denial still surfaces */ }
        throw err;
      }
      if (!(err instanceof AnswerOutcomeValidationError)) {
        // Unexpected failure: the transaction (including its ok-row) rolled
        // back, so append standalone error evidence (D4). Best-effort — the
        // original failure is what propagates.
        try {
          await this.auditOutcome(identity, ts, "error", input.turnId,
            err instanceof Error ? err.message : String(err));
        } catch { /* audit brownout: the original error still surfaces */ }
      } else {
        await this.auditOutcome(identity, ts, "error", input.turnId, err.message);
      }
      throw err;
    }
  }

  /**
   * The derived accuracy rollup (E33) over the caller's subtree. Reads ONLY
   * the audited `answer_outcomes` rows plus the open `fact_disputes`
   * wrong-answer signal — there is no code path by which a caller-supplied
   * number enters this figure. The read itself audits (D4, op "stats").
   *
   * D40: a non-oversight caller (an operating member) reads its OWN accuracy,
   * not its team's — this figure heads the member's Usage analytics screen,
   * where every other number is already actor-pinned. `answer_outcomes.actor`
   * carries the pin. `fact_disputes` has no actor column, so the unlinked
   * open-dispute term is NOT attributable and drops to zero for a pinned
   * caller rather than importing a team-wide count into a personal figure:
   * a member's accuracy is over its own recorded outcomes only.
   */
  async accuracy(identity: Identity, window: AccuracyWindow = {}): Promise<AccuracyRollup> {
    assertIsoOrUndefined(window.since, "since");
    assertIsoOrUndefined(window.until, "until");

    const oversight = isOversightRole(identity);
    const pred = subtreePredicate(identity, 1, "ao.namespace");
    const params: unknown[] = [...pred.params];
    const bind = (value: unknown): string => {
      params.push(value);
      return `$${params.length}`;
    };
    const bounds: string[] = [];
    if (!oversight) bounds.push(`ao.actor = ${bind(identity.actor)}`);
    if (window.since !== undefined) bounds.push(`ao.created_at >= ${bind(window.since)}`);
    if (window.until !== undefined) bounds.push(`ao.created_at <= ${bind(window.until)}`);
    const boundSql = bounds.length > 0 ? ` AND ${bounds.join(" AND ")}` : "";

    const buckets = await this.deps.db.query(
      `SELECT ao.outcome, COUNT(*) AS n
         FROM answer_outcomes ao
        WHERE ao.t_valid_to IS NULL AND ${pred.sql}${boundSql}
        GROUP BY ao.outcome`,
      params,
    );
    const count: Record<string, number> = {};
    for (const raw of buckets.rows) {
      const row = raw as { outcome: string; n: number | string };
      count[row.outcome] = Number(row.n);
    }

    // Open disputes not already represented by a current "disputed" outcome
    // row: the existing wrong-answer signal joins the denominator (never
    // double-counted when the outcome row links the dispute).
    const dPred = subtreePredicate(identity, 1, "d.namespace");
    const dParams: unknown[] = [...dPred.params];
    const dBind = (value: unknown): string => {
      dParams.push(value);
      return `$${dParams.length}`;
    };
    const dBounds: string[] = [];
    if (window.since !== undefined) dBounds.push(`d.created_at >= ${dBind(window.since)}`);
    if (window.until !== undefined) dBounds.push(`d.created_at <= ${dBind(window.until)}`);
    const dBoundSql = dBounds.length > 0 ? ` AND ${dBounds.join(" AND ")}` : "";
    const unlinked = oversight
      ? await this.deps.db.query(
          `SELECT COUNT(*) AS n
             FROM fact_disputes d
            WHERE d.status = 'open' AND ${dPred.sql}${dBoundSql}
              AND NOT EXISTS (
                SELECT 1 FROM answer_outcomes ao
                 WHERE ao.dispute_id = d.id AND ao.t_valid_to IS NULL
              )`,
          dParams,
        )
      : null;
    // Unattributable to one caller (no actor on fact_disputes), so a pinned
    // caller's figure omits it entirely instead of borrowing the team's.
    const openDisputes = unlinked
      ? Number((unlinked.rows[0] as { n: number | string }).n)
      : 0;

    const answered = count["answered"] ?? 0;
    const weak = count["weak"] ?? 0;
    const disputed = count["disputed"] ?? 0;
    const answeredWithoutHuman = count["answered-without-human"] ?? 0;

    const answeredTotal = answered + weak + disputed + answeredWithoutHuman + openDisputes;
    const accurate = answered + answeredWithoutHuman; // not disputed, not weak
    const verifiedDenominator = answered + weak + disputed + openDisputes;

    const ts = this.now().toISOString();
    await this.deps.audit.append({
      ts,
      actor: identity.actor,
      agentId: identity.keyId,
      op: "stats",
      memoryId: null,
      namespace: identity.namespace,
      purpose: "accuracy-rollup",
      result: "ok",
      detail: `answered_total=${answeredTotal} accurate=${accurate} open_disputes=${openDisputes}`,
    });

    return {
      namespace: identity.namespace,
      since: window.since ?? null,
      until: window.until ?? null,
      answered,
      weak,
      disputed,
      answeredWithoutHuman,
      openDisputes,
      answeredTotal,
      accurate,
      accuracy: answeredTotal === 0 ? null : accurate / answeredTotal,
      verifiedAccuracy: verifiedDenominator === 0 ? null : answered / verifiedDenominator,
    };
  }

  // -------------------------------------------------------------------------

  private validate(input: RecordAnswerOutcomeInput): void {
    requireString(input.turnId, "turnId", MAX_TURN_ID);
    if (!OUTCOMES.includes(input.outcome)) {
      throw new AnswerOutcomeValidationError(`outcome must be one of ${OUTCOMES.join(", ")}`);
    }
    if (input.session !== undefined) requireString(input.session, "session", MAX_SESSION);
    if (input.detail !== undefined) requireString(input.detail, "detail", MAX_DETAIL);
    if (input.queryText !== undefined && input.querySha256 !== undefined) {
      throw new AnswerOutcomeValidationError("provide queryText or querySha256, not both");
    }
    if (input.queryText !== undefined) {
      requireString(input.queryText, "queryText", MAX_QUERY_TEXT);
    }
    if (input.querySha256 !== undefined && !SHA256_HEX.test(input.querySha256)) {
      throw new AnswerOutcomeValidationError("querySha256 must be 64 lowercase hex characters");
    }
    if (input.evidenceIds !== undefined) {
      if (input.evidenceIds.length > MAX_EVIDENCE_IDS) {
        throw new AnswerOutcomeValidationError(
          `evidenceIds must contain at most ${MAX_EVIDENCE_IDS} ids`,
        );
      }
      input.evidenceIds.forEach((id, i) =>
        requireString(id, `evidenceIds[${i}]`, MAX_EVIDENCE_ID_LEN),
      );
    }
    if (input.traceId !== undefined) {
      const traceId = requireString(input.traceId, "traceId", MAX_TRACE_ID);
      if (!TRACE_ID_PATTERN.test(traceId)) {
        throw new AnswerOutcomeValidationError(
          "traceId must be 1..128 characters of [A-Za-z0-9._:-]",
        );
      }
    }
    if (input.disputeId !== undefined && input.outcome !== "disputed") {
      throw new AnswerOutcomeValidationError("disputeId is only valid with outcome 'disputed'");
    }
  }

  private event(
    identity: Identity,
    ts: string,
    result: AuditEvent["result"],
    detail: string,
  ): AuditEvent {
    return {
      ts,
      actor: identity.actor,
      agentId: identity.keyId,
      op: "answer_outcome",
      memoryId: null,
      namespace: identity.namespace,
      purpose: "answer-outcome",
      result,
      detail,
    };
  }

  /** Standalone denied/error evidence (D4) — its own committed transaction. */
  private auditOutcome(
    identity: Identity,
    ts: string,
    result: AuditEvent["result"],
    turnId: string,
    detail: string,
  ): Promise<void> {
    return this.deps.audit.append(
      this.event(identity, ts, result, `turn=${turnId} ${detail}`),
    );
  }
}
