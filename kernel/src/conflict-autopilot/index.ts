/**
 * Write-time conflict detection with trust-ranked auto-resolution
 * (CONTRACTS-CONFLICT-AUTOPILOT CA1-CA6, CA10).
 *
 * The batch scan (src/conflict-scans) walks memory in bounded slices, groups by
 * canonical entity, and needs a human to drain its queue. Two consequences made
 * it a poor primary defence: a fact with no entity annotation joins no group and
 * is never examined, and two facts more than one slice apart in storage order
 * are never compared by any number of scans.
 *
 * This lane fixes both by inverting the trigger. Every committed fact is checked
 * ONCE, against its nearest neighbours by embedding — a corpus-wide lookup that
 * needs no entity annotation and does not care how far apart in time the two
 * facts were written. Confirmed contradictions are then settled by the SAME
 * trust lattice the write path's synchronous band already uses, so the common
 * cases need no person at all.
 *
 * What this lane never does: run inside the write transaction (CA1), read
 * outside the fact's own namespace (CA2), act without a validated model
 * decision (CA3/CS13-CS16), or delete anything (CA4 — every outcome is a
 * validity close plus supersedence link, and is overturnable).
 */

import { createHash } from "node:crypto";
import { ulid } from "ulid";

import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { parseEntitiesAnnotation, parseVectorText } from "../ingest/kernel-store.js";
import { cosine } from "../ingest/fragmentation.js";
import { categoryFor } from "../conflict-scans/index.js";
import {
  classifyConflictCandidatesInBatches,
  type ConflictClassificationCandidate,
  type ConflictClassificationDecision,
  type ConflictClassifier,
} from "../conflict-scans/classifier.js";
import { TRUST_RANK } from "../write/index.js";
import type {
  ConflictAutoRule,
  ConflictFindingFlag,
  MemoryId,
  ProvenanceEntry,
  Scope,
} from "../types.js";

/** Own detector lineage: the scan's version sweep must not retire these rows. */
export const AUTOPILOT_DETECTOR_VERSION = "luna-context-v1";
const FINDING_KIND = "semantic-contradiction";

/** CA2: how many nearest neighbours one committed fact is judged against. */
export const NEIGHBOR_K = 8;
/**
 * Similarity floor for a neighbour to be worth a model call. Below this the two
 * facts are not about the same thing, and paying the judge to say so is waste.
 * Deliberately far under the write path's supersedence band (0.75): the whole
 * point of this lane is catching contradictions the band's wording-similarity
 * test walks past.
 */
export const NEIGHBOR_MIN_COSINE = 0.6;
/**
 * Above this the pair is the SAME statement, not a disagreement; the write
 * path's dedupe/supersede band already decided it synchronously.
 */
/** CA4: an equal-trust pair is only auto-decided on a confident judgement. */
export const EQUAL_TRUST_MIN_CONFIDENCE = 0.9;
/** CS13 parity: nothing below this is published from either lane. */
const MIN_PUBLISH_CONFIDENCE = 0.8;

/**
 * Hard ceiling on candidate-pair judgements per worker pass. The historical
 * exported name is retained for compatibility, but batching means these are no
 * longer one provider call each. Facts beyond the budget are not dropped —
 * they stay queued and are checked by the next pass.
 */
export const JUDGE_CALLS_PER_PASS = 50;

const LEASE_MS = 5 * 60_000;
const RETRY_BACKOFF_MS = 60_000;

export interface ConflictAutopilotRunResult {
  claimed: number;
  /** Facts whose check completed (with or without a conflict found). */
  checked: number;
  /** Conflicts the trust lattice settled without a person. */
  autoResolved: number;
  /** Conflicts parked for review (ambiguous, or the tenant asked for gates). */
  needsReview: number;
  /** Facts deferred: judge unavailable, budget exhausted, or no embedding. */
  deferred: number;
}

/** The dial value that governs autonomy, resolved per namespace (CA5). */
export type ConflictAutonomy = "auto" | "lower-trust" | "all";

interface QueuedRow extends Record<string, unknown> {
  memory_id: string;
  namespace: string;
  attempts: number;
  detector_version: string;
  candidate_cursor: number;
}

interface PairQueuedRow extends Record<string, unknown> {
  id: string;
  namespace: string;
  source_type: "finding" | "auto_resolution" | "dispute";
  source_id: string;
  left_memory_id: string;
  right_memory_id: string;
  attempts: number;
}

interface AutopilotFact {
  id: MemoryId;
  namespace: string;
  scope: Scope;
  content: string;
  confidence: number;
  assertionTime: string;
  eventTime: string | null;
  provenance: ProvenanceEntry[];
  embedding: number[] | null;
}

interface PreparedCandidate {
  neighbor: AutopilotFact;
  candidate: ConflictClassificationCandidate;
}

type PreparedCheck =
  | { state: "complete"; row: QueuedRow }
  | { state: "deferred"; row: QueuedRow; reason: string }
  | {
      state: "ready";
      row: QueuedRow;
      incoming: AutopilotFact;
      cursor: number;
      totalCandidates: number;
      candidates: PreparedCandidate[];
    };

function json<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  return typeof value === "string" ? JSON.parse(value) as T : value as T;
}

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(String(value)).toISOString();
}

function factText(content: string): string {
  return content.replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "").trim();
}

function sourceOf(fact: AutopilotFact): ProvenanceEntry["source"] {
  return fact.provenance[0]?.source ?? "conversation";
}

function sourceLabel(fact: AutopilotFact): string {
  const entry = fact.provenance[0];
  if (!entry) return `memory:${fact.id}`;
  return entry.sourceId ?? `${entry.source}:${entry.actor}`;
}

function classifierEvidence(fact: AutopilotFact) {
  const provenance = fact.provenance[0];
  return {
    content: factText(fact.content),
    namespace: fact.namespace,
    memoryId: fact.id,
    eventTime: fact.eventTime,
    assertionTime: fact.assertionTime,
    source: provenance?.source,
    sourceId: provenance?.sourceId,
    sourceKind: provenance?.sourceKind,
    documentKey: provenance?.documentKey,
  };
}

function trustRank(fact: AutopilotFact): number {
  return TRUST_RANK[sourceOf(fact)] ?? TRUST_RANK.conversation;
}

function flagsFor(left: AutopilotFact, right: AutopilotFact): ConflictFindingFlag[] {
  const flags: ConflictFindingFlag[] = [];
  if (sourceLabel(left) !== sourceLabel(right)) flags.push("cross-source");
  if (sourceOf(left) === "conversation" || sourceOf(right) === "conversation") {
    flags.push("agent-derived");
  }
  if (left.namespace !== right.namespace) flags.push("cross-team");
  if (Math.min(left.confidence, right.confidence) < 0.7) flags.push("low-confidence");
  return flags;
}

/**
 * A subject label for the judge prompt and the S11 card. Prefer a subject both
 * facts actually mention; entity annotation is a nicety here, not a
 * prerequisite (that is the whole point of this lane), so an unannotated pair
 * still gets judged.
 */
function sharedSubject(left: AutopilotFact, right: AutopilotFact): string {
  const rightEntities = new Set(parseEntitiesAnnotation(right.content).map((e) => e.toLowerCase()));
  const shared = parseEntitiesAnnotation(left.content)
    .filter((entity) => rightEntities.has(entity.toLowerCase()))
    .sort((a, b) => b.length - a.length)[0];
  return shared ?? parseEntitiesAnnotation(left.content)[0] ?? "unspecified subject";
}

function fingerprint(target: string, left: MemoryId, right: MemoryId): string {
  const pair = [left, right].sort();
  return createHash("sha256")
    .update(`${AUTOPILOT_DETECTOR_VERSION}\0${target}\0${FINDING_KIND}\0${pair[0]}\0${pair[1]}`)
    .digest("hex");
}

/**
 * CA4 decision matrix, stated over the pair's TIME order rather than over which
 * fact happened to trigger the check. A backlog drain claims facts in enqueue
 * order, so the queued fact is frequently the OLDER side of the pair; deciding
 * "newest wins" from the trigger's point of view would then retire the newer
 * fact and quietly invert the rule.
 *
 * `null` means "no automatic action" — the pair is parked for a person. Every
 * other outcome names the side that stays in use; the other one's validity is
 * closed and linked, exactly as a human decision would.
 */
export function autoDecision(
  newerRank: number,
  olderRank: number,
  confidence: number,
  autonomy: ConflictAutonomy,
): { keep: "newer" | "older"; rule: ConflictAutoRule } | null {
  // Every judged conflict is a review item when the tenant asked for gates.
  if (autonomy === "all") return null;
  if (newerRank > olderRank) {
    return { keep: "newer", rule: "higher-trust-wins" };
  }
  // "lower-trust" keeps its documented meaning: only a write that OUTRANKS the
  // incumbent may land unattended. Everything else waits for a person.
  if (autonomy === "lower-trust") return null;
  if (newerRank < olderRank) {
    return { keep: "older", rule: "lower-trust-rejected" };
  }
  return confidence >= EQUAL_TRUST_MIN_CONFIDENCE
    ? { keep: "newer", rule: "equal-trust-newest-wins" }
    : null;
}

export class ConflictAutopilot {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly classifier: ConflictClassifier | null,
    /**
     * Per-namespace autonomy dial. Injected rather than read from PolicyStore
     * directly so the worker keeps one dependency and tests can pin it.
     */
    private readonly autonomyFor: (namespace: string) => Promise<ConflictAutonomy>,
    /** Backoff before a deferred check is eligible again (0 in tests). */
    private readonly retryBackoffMs = RETRY_BACKOFF_MS,
    private readonly workerId = ulid(),
  ) {}

  /** How much work is waiting, and whether it can drain at all (CA11). */
  async ledgerHealth(namespaceLike: { namespace: string; pattern: string }): Promise<{
    pendingChecks: number;
    detectionDegraded: boolean;
  }> {
    const pending = await this.db.query(
      `SELECT COUNT(*)::int AS count FROM conflict_detection_queue
        WHERE status IN ('pending','running')
          AND ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')`,
      [namespaceLike.namespace, namespaceLike.pattern],
    );
    return {
      pendingChecks: Number(pending.rows[0]?.count ?? 0),
      detectionDegraded: this.classifier === null,
    };
  }

  /** One bounded worker pass. Safe to call concurrently: claims are lease-fenced. */
  async runOnce(options: { limit?: number } = {}): Promise<ConflictAutopilotRunResult> {
    const limit = Math.max(1, Math.min(25, Math.floor(options.limit ?? 10)));
    const pairClaimed = await this.claimPairRechecks(Math.min(5, limit));
    const claimed = await this.claim(limit);
    let judgeBudget = JUDGE_CALLS_PER_PASS;
    const result: ConflictAutopilotRunResult = {
      claimed: claimed.length + pairClaimed.length,
      checked: 0,
      autoResolved: 0,
      needsReview: 0,
      deferred: 0,
    };
    for (const row of pairClaimed) {
      try {
        if (judgeBudget <= 0) {
          result.deferred += 1;
          await this.deferPair(row, "judge_budget_exhausted");
          continue;
        }
        const outcome = await this.recheckPair(row);
        judgeBudget -= outcome.judgeCalls;
        if (outcome.deferred) {
          result.deferred += 1;
          await this.deferPair(row, outcome.reason ?? "deferred");
          continue;
        }
        result.checked += 1;
        result.needsReview += outcome.needsReview;
        await this.completePair(row);
      } catch (error) {
        result.deferred += 1;
        await this.deferPair(row, error instanceof Error ? error.message : "pair_recheck_failed");
      }
    }
    if (claimed.length > 0) {
      const outcome = await this.checkClaimedBatch(claimed, judgeBudget);
      result.checked += outcome.checked;
      result.autoResolved += outcome.autoResolved;
      result.needsReview += outcome.needsReview;
      result.deferred += outcome.deferred;
    }
    return result;
  }

  private async claimPairRechecks(limit: number): Promise<PairQueuedRow[]> {
    const now = new Date();
    const leaseUntil = new Date(now.getTime() + LEASE_MS).toISOString();
    return this.db.transaction(async (tx) => {
      const claimed = await tx.query(
        `WITH candidates AS (
           SELECT id FROM conflict_pair_recheck_queue
            WHERE (status = 'pending' AND (retry_at IS NULL OR retry_at <= $1))
               OR (status = 'running' AND lease_until < $1)
            ORDER BY created_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
         )
         UPDATE conflict_pair_recheck_queue AS q
            SET status = 'running', attempts = q.attempts + 1,
                lease_owner = $3, lease_until = $4, last_error = NULL
           FROM candidates WHERE q.id = candidates.id
         RETURNING q.id,q.namespace,q.source_type,q.source_id,
                   q.left_memory_id,q.right_memory_id,q.attempts`,
        [now.toISOString(), limit, this.workerId, leaseUntil],
      );
      return claimed.rows as PairQueuedRow[];
    });
  }

  private async completePair(row: PairQueuedRow): Promise<void> {
    await this.db.query(
      `UPDATE conflict_pair_recheck_queue
          SET status = 'done', completed_at = $2, lease_owner = NULL, lease_until = NULL
        WHERE id = $1 AND lease_owner = $3`,
      [row.id, new Date().toISOString(), this.workerId],
    );
  }

  private async deferPair(row: PairQueuedRow, reason: string): Promise<void> {
    await this.db.query(
      `UPDATE conflict_pair_recheck_queue
          SET status = 'pending', retry_at = $2, last_error = $3,
              lease_owner = NULL, lease_until = NULL
        WHERE id = $1 AND lease_owner = $4`,
      [row.id, new Date(Date.now() + this.retryBackoffMs).toISOString(), reason.slice(0, 500), this.workerId],
    );
  }

  private async loadEvidenceFact(id: string): Promise<AutopilotFact | null> {
    const result = await this.db.query(
      `SELECT id,namespace,scope,content,confidence,event_time,assertion_time,provenance,
              embedding::text AS embedding_text
         FROM memory_objects WHERE id = $1 AND tier = 'L2'`,
      [id],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? this.toFact(row) : null;
  }

  private async recheckPair(row: PairQueuedRow): Promise<{
    deferred: boolean;
    reason?: string;
    judgeCalls: number;
    needsReview: number;
  }> {
    if (!this.classifier) {
      return { deferred: true, reason: "judge_unavailable", judgeCalls: 0, needsReview: 0 };
    }
    const [left, right] = await Promise.all([
      this.loadEvidenceFact(row.left_memory_id),
      this.loadEvidenceFact(row.right_memory_id),
    ]);
    // Erasure/cascade may remove the queue row concurrently. If evidence is no
    // longer available, complete honestly without reconstructing deleted data.
    if (!left || !right) return { deferred: false, judgeCalls: 0, needsReview: 0 };
    const decision = (await this.classifier.classify([{
      id: `legacy-${row.source_id}`,
      entity: sharedSubject(left, right),
      scope: left.scope,
      left: classifierEvidence(left),
      right: classifierEvidence(right),
    }]))[0];
    if (!decision || decision.classification === "uncertain") {
      return { deferred: true, reason: "judge_uncertain", judgeCalls: 1, needsReview: 0 };
    }
    const now = new Date().toISOString();
    await this.db.transaction(async (tx) => {
      if (decision.contradiction) {
        if (row.source_type !== "dispute") {
          const currentFingerprint = fingerprint(
            row.namespace,
            row.left_memory_id as MemoryId,
            row.right_memory_id as MemoryId,
          );
          const duplicate = await tx.query(
            `SELECT id FROM conflict_scan_findings
              WHERE target_namespace = $1 AND fingerprint = $2 AND id <> $3 LIMIT 1`,
            [row.namespace, currentFingerprint, row.source_id],
          );
          if (duplicate.rows[0]) {
            await tx.query(
              `UPDATE conflict_scan_findings
                  SET detector_version = $2, confidence = 1, last_seen_at = $3,
                      row_version = row_version + 1
                WHERE id = $1`,
              [String(duplicate.rows[0].id), AUTOPILOT_DETECTOR_VERSION, now],
            );
            await tx.query(
              `UPDATE conflict_scan_findings
                  SET status = 'dismissed', last_seen_at = $2, row_version = row_version + 1
                WHERE id = $1 AND status IN ('open','acknowledged')`,
              [row.source_id, now],
            );
          } else {
            await tx.query(
              `UPDATE conflict_scan_findings
                  SET detector_version = $2, fingerprint = $3, confidence = 1,
                      last_seen_at = $4, row_version = row_version + 1
                WHERE id = $1`,
              [row.source_id, AUTOPILOT_DETECTOR_VERSION, currentFingerprint, now],
            );
          }
        }
      } else if (row.source_type === "finding") {
        await tx.query(
          `UPDATE conflict_scan_findings
              SET status = 'dismissed', last_seen_at = $2, row_version = row_version + 1
            WHERE id = $1 AND status IN ('open','acknowledged')`,
          [row.source_id, now],
        );
      } else {
        await tx.query(
          `INSERT INTO conflict_repair_proposals
             (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
              detector_version,classification,status,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9)
           ON CONFLICT (source_type,source_id,detector_version) DO NOTHING`,
          [ulid(), row.namespace, row.source_type, row.source_id,
            row.left_memory_id, row.right_memory_id, AUTOPILOT_DETECTOR_VERSION,
            decision.classification, now],
        );
      }
      await this.audit.appendTo(tx, {
        ts: now, actor: "system", agentId: "conflict-autopilot",
        op: "conflict_scan", memoryId: null, namespace: row.namespace,
        purpose: "historical-conflict-recheck", result: "ok",
        detail: `source=${row.source_type}:${row.source_id} detector=${AUTOPILOT_DETECTOR_VERSION} classification=${decision.classification}`,
      });
    });
    return {
      deferred: false,
      judgeCalls: 1,
      needsReview: decision.contradiction || row.source_type !== "finding" ? 1 : 0,
    };
  }

  private async claim(limit: number): Promise<QueuedRow[]> {
    const now = new Date();
    const leaseUntil = new Date(now.getTime() + LEASE_MS).toISOString();
    return this.db.transaction(async (tx) => {
      const claimed = await tx.query(
        `WITH next_namespace AS (
           SELECT namespace FROM conflict_detection_queue
            WHERE detector_version = $5 AND (
                 (status = 'pending' AND (retry_at IS NULL OR retry_at <= $1))
               OR (status = 'running' AND lease_until < $1))
            ORDER BY enqueued_at, memory_id
            LIMIT 1
         ), candidates AS (
           SELECT memory_id FROM conflict_detection_queue
            WHERE detector_version = $5 AND (
                 (status = 'pending' AND (retry_at IS NULL OR retry_at <= $1))
               OR (status = 'running' AND lease_until < $1))
              AND namespace = (SELECT namespace FROM next_namespace)
            ORDER BY enqueued_at, memory_id
            LIMIT $2
            FOR UPDATE SKIP LOCKED
         )
         UPDATE conflict_detection_queue AS q
            SET status = 'running', attempts = q.attempts + 1,
                lease_owner = $3, lease_until = $4, last_error = NULL
           FROM candidates
          WHERE q.memory_id = candidates.memory_id
         RETURNING q.memory_id, q.namespace, q.attempts, q.detector_version, q.candidate_cursor`,
        [now.toISOString(), limit, this.workerId, leaseUntil, AUTOPILOT_DETECTOR_VERSION],
      );
      return claimed.rows as QueuedRow[];
    });
  }

  private async complete(row: QueuedRow): Promise<void> {
    await this.db.query(
      `UPDATE conflict_detection_queue
          SET status = 'done', completed_at = $2, lease_owner = NULL, lease_until = NULL
        WHERE memory_id = $1 AND lease_owner = $3 AND detector_version = $4`,
      [row.memory_id, new Date().toISOString(), this.workerId, row.detector_version],
    );
  }

  /** Park incomplete work durably; uncertainty/outage never becomes clean. */
  private async defer(row: QueuedRow, reason: string): Promise<void> {
    await this.db.query(
      `UPDATE conflict_detection_queue
          SET status = $2, retry_at = $3, last_error = $4,
              lease_owner = NULL, lease_until = NULL
        WHERE memory_id = $1 AND lease_owner = $5 AND detector_version = $6`,
      [
        row.memory_id,
        "pending",
        new Date(Date.now() + this.retryBackoffMs).toISOString(),
        reason.slice(0, 500),
        this.workerId,
        row.detector_version,
      ],
    );
  }

  private async loadFact(id: string): Promise<AutopilotFact | null> {
    const result = await this.db.query(
      `SELECT id,namespace,scope,content,confidence,event_time,assertion_time,provenance,
              embedding::text AS embedding_text
         FROM memory_objects
        WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)`,
      [id],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? this.toFact(row) : null;
  }

  private toFact(row: Record<string, unknown>): AutopilotFact {
    return {
      id: String(row.id) as MemoryId,
      namespace: String(row.namespace),
      scope: row.scope as Scope,
      content: String(row.content),
      confidence: Number(row.confidence),
      assertionTime: iso(row.assertion_time),
      eventTime: row.event_time == null ? null : iso(row.event_time),
      provenance: json<ProvenanceEntry[]>(row.provenance, []),
      embedding: parseVectorText(row.embedding_text),
    };
  }

  /**
   * CA2: nearest neighbours by meaning, inside the fact's OWN namespace and
   * scope only. Same-namespace is the deliberately tight choice — a write-time
   * check must not be able to read a sibling team's memory, and cross-team
   * contradiction remains the admin-authorised batch scan's job (CS4).
   */
  private async neighbors(fact: AutopilotFact): Promise<AutopilotFact[]> {
    if (!fact.embedding) return [];
    const result = await this.db.query(
      `SELECT id,namespace,scope,content,confidence,event_time,assertion_time,provenance,
              embedding::text AS embedding_text
         FROM memory_objects
        WHERE namespace = $1 AND scope = $2 AND id <> $3
          AND status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
          AND type <> 'pointer' AND embedding IS NOT NULL
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
        ORDER BY embedding <=> $4::vector
        LIMIT $5`,
      [fact.namespace, fact.scope, fact.id, `[${fact.embedding.join(",")}]`, NEIGHBOR_K],
    );
    return result.rows.map((row) => this.toFact(row as Record<string, unknown>));
  }

  private async prepareCheck(
    row: QueuedRow,
    judgeBudget: number,
    rowIndex: number,
  ): Promise<PreparedCheck> {
    const incoming = await this.loadFact(row.memory_id);
    // The fact stopped being currently valid before its check ran (superseded,
    // erased, expired). There is nothing left to contradict.
    if (!incoming) return { state: "complete", row };
    // CA2: an embedding brownout leaves the fact uncomparable. Defer rather
    // than record a clean check over memory that was never actually compared.
    if (!incoming.embedding) return { state: "deferred", row, reason: "embedding_unavailable" };
    // CA3 fail-closed: no judge, no decision, no false "checked and clean".
    if (!this.classifier) return { state: "deferred", row, reason: "judge_unavailable" };

    const candidates = (await this.neighbors(incoming))
      .map((neighbor) => ({ neighbor, similarity: cosine(incoming.embedding, neighbor.embedding) }))
      .filter(({ similarity }) =>
        similarity !== null &&
        similarity >= NEIGHBOR_MIN_COSINE)
      .sort((a, b) => (b.similarity ?? 0) - (a.similarity ?? 0));
    if (candidates.length === 0) return { state: "complete", row };
    const cursor = Math.max(0, Number(row.candidate_cursor ?? 0));
    if (cursor >= candidates.length) return { state: "complete", row };
    if (judgeBudget <= 0) {
      return { state: "deferred", row, reason: "judge_budget_exhausted" };
    }

    const affordable = candidates.slice(cursor, cursor + Math.max(0, judgeBudget));
    return {
      state: "ready",
      row,
      incoming,
      cursor,
      totalCandidates: candidates.length,
      candidates: affordable.map(({ neighbor }, index) => ({
        neighbor,
        candidate: {
          id: `candidate-${rowIndex + 1}-${cursor + index + 1}`,
          entity: sharedSubject(incoming, neighbor),
          scope: incoming.scope,
          left: classifierEvidence(incoming),
          right: classifierEvidence(neighbor),
        },
      })),
    };
  }

  /**
   * Fill one provider packet from many queued facts in the same namespace.
   * This amortizes prompt/reasoning overhead without ever co-mingling tenant
   * memory. Cursor updates remain per fact so a partial budget is resumable.
   */
  private async checkClaimedBatch(
    rows: readonly QueuedRow[],
    judgeBudget: number,
  ): Promise<Omit<ConflictAutopilotRunResult, "claimed"> & { judgeCalls: number }> {
    const result = { checked: 0, autoResolved: 0, needsReview: 0, deferred: 0, judgeCalls: 0 };
    const ready: Extract<PreparedCheck, { state: "ready" }>[] = [];
    let remaining = Math.max(0, judgeBudget);

    for (const [rowIndex, row] of rows.entries()) {
      try {
        const prepared = await this.prepareCheck(row, remaining, rowIndex);
        if (prepared.state === "complete") {
          await this.complete(row);
          result.checked += 1;
        } else if (prepared.state === "deferred") {
          await this.defer(row, prepared.reason);
          result.deferred += 1;
        } else {
          ready.push(prepared);
          remaining -= prepared.candidates.length;
        }
      } catch (error) {
        await this.defer(row, error instanceof Error ? error.message : "check_failed");
        result.deferred += 1;
      }
    }

    const batchCandidates = ready.flatMap((prepared) =>
      prepared.candidates.map(({ candidate }) => candidate));
    if (batchCandidates.length === 0) return result;
    result.judgeCalls = batchCandidates.length;

    let decisions: ConflictClassificationDecision[];
    try {
      decisions = await classifyConflictCandidatesInBatches(this.classifier!, batchCandidates);
    } catch {
      // CS14: one malformed/failed packet publishes nothing from that packet.
      // Every represented fact keeps its cursor and is retried in full.
      for (const prepared of ready) {
        await this.defer(prepared.row, "judge_unavailable");
        result.deferred += 1;
      }
      return result;
    }
    const decisionsById = new Map(decisions.map((decision) => [decision.candidateId, decision]));

    for (const prepared of ready) {
      try {
        for (const { neighbor, candidate } of prepared.candidates) {
          const decision = decisionsById.get(candidate.id);
          if (!decision?.contradiction) continue;
          // Re-read both sides at decision time: validity may have changed
          // while the shared model packet was in flight.
          const [freshIncoming, freshNeighbor] = await Promise.all([
            this.loadFact(prepared.incoming.id),
            this.loadFact(neighbor.id),
          ]);
          if (!freshIncoming || !freshNeighbor) continue;
          const applied = await this.apply(
            freshIncoming,
            freshNeighbor,
            decision.confidence,
            decision.reason,
          );
          if (applied === "auto") result.autoResolved += 1;
          else if (applied === "review") result.needsReview += 1;
        }
        const nextCursor = prepared.cursor + prepared.candidates.length;
        if (nextCursor < prepared.totalCandidates) {
          await this.db.query(
            `UPDATE conflict_detection_queue SET candidate_cursor = $2
              WHERE memory_id = $1 AND lease_owner = $3 AND detector_version = $4`,
            [prepared.row.memory_id, nextCursor, this.workerId, prepared.row.detector_version],
          );
          await this.defer(prepared.row, "candidate_budget_exhausted");
          result.deferred += 1;
        } else {
          await this.complete(prepared.row);
          result.checked += 1;
        }
      } catch (error) {
        await this.defer(prepared.row, error instanceof Error ? error.message : "check_failed");
        result.deferred += 1;
      }
    }
    return result;
  }

  /**
   * Publish one judged contradiction: either the trust lattice settles it now
   * (validity close + supersedence link + D4 audit, identical in shape to the
   * human resolve path) or it lands as a review item. Both are one transaction.
   */
  private async apply(
    incoming: AutopilotFact,
    existing: AutopilotFact,
    confidence: number,
    reason: string,
  ): Promise<"auto" | "review" | "skipped"> {
    const target = incoming.namespace;
    const hash = fingerprint(target, incoming.id, existing.id);
    const flags = flagsFor(incoming, existing);
    const entity = sharedSubject(incoming, existing);
    const category = categoryFor(entity, incoming.content, existing.content);
    const now = new Date().toISOString();

    return this.db.transaction(async (tx) => {
      // CS6: one open finding per evidence pair per detector. A re-check of the
      // same neighbourhood refreshes it instead of flooding the ledger.
      const existingRow = await tx.query(
        `SELECT id,status FROM conflict_scan_findings
          WHERE target_namespace = $1 AND fingerprint = $2`,
        [target, hash],
      );
      const priorStatus = existingRow.rows[0]?.status as string | undefined;
      if (priorStatus !== undefined && priorStatus !== "open") {
        return "skipped";
      }

      if (priorStatus === "open") {
        await tx.query(
          `UPDATE conflict_scan_findings
              SET last_seen_at = $2, reason = $3, confidence = $4, flags = $5::jsonb,
                  detector_version = $6, row_version = row_version + 1
            WHERE target_namespace = $1 AND fingerprint = $7`,
          [target, now, reason, confidence, JSON.stringify(flags), AUTOPILOT_DETECTOR_VERSION, hash],
        );
        return "skipped";
      }
      await tx.query(
        `INSERT INTO conflict_scan_findings
           (id,target_namespace,left_memory_id,right_memory_id,fingerprint,detector_version,
            entity,category,reason,confidence,flags,status,row_version,origin,
            first_seen_at,last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,'open',1,'write',$12,$12)
         ON CONFLICT (target_namespace,fingerprint) DO NOTHING`,
        [ulid(), target, incoming.id, existing.id, hash, AUTOPILOT_DETECTOR_VERSION,
          entity, category, reason, confidence, JSON.stringify(flags), now],
      );
      await this.audit.appendTo(tx, {
        ts: now, actor: "system", agentId: "conflict-autopilot",
        op: "conflict_scan", memoryId: null, namespace: target,
        purpose: "conflict-autopilot-review", result: "ok",
        detail: `origin=write pair=${incoming.id},${existing.id} detector=${AUTOPILOT_DETECTOR_VERSION}`,
      });
      return "review";
    });
  }
}
