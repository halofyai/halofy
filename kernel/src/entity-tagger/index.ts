/**
 * Subject derivation for facts that landed without one (CA8).
 *
 * Two thirds of live memory is agent conversation stored with no `[entities: …]`
 * annotation, because only the ingestion lane ever derived mentions. Those facts
 * join no candidate group, so the batch scan has never examined them — the
 * single largest coverage hole in conflict detection.
 *
 * The worker fills `memory_objects.derived_entities`. Stored content is NEVER
 * touched (D7): subjects are derived read-side metadata, so they live in their
 * own column and the fact's bytes stay exactly as written.
 *
 * Two tiers, cheapest first:
 *  1. Deterministic proper nouns — free, no egress, handles most facts.
 *  2. A model call, ONLY for text with no usable proper noun ("the customer
 *     wants their money back"), where nothing but a reader can name the subject.
 *
 * Tier 2 is optional: without a model the fact is still recorded as tagged with
 * whatever tier 1 found (possibly nothing), because leaving it queued forever
 * would make the backlog gauge lie.
 */

import { ulid } from "ulid";

import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { capitalizedWords } from "../llm/index.js";
import { parseEntitiesAnnotation } from "../ingest/kernel-store.js";
import { usableSubjects } from "./subjects.js";

/** Names a subject for prose the deterministic pass could not read. */
export type SubjectExtractor = (input: {
  content: string;
  namespace: string;
}) => Promise<string[]>;

export interface EntityTagRunResult {
  claimed: number;
  /** Facts that now carry at least one subject. */
  tagged: number;
  /** Facts with genuinely no nameable subject — recorded, not retried forever. */
  empty: number;
  deferred: number;
}

interface QueuedRow extends Record<string, unknown> {
  memory_id: string;
  namespace: string;
  attempts: number;
}

const LEASE_MS = 5 * 60_000;
const MAX_ATTEMPTS = 3;
const RETRY_BACKOFF_MS = 60_000;
/** Model calls per pass — the same spend discipline as the conflict judge. */
export const SUBJECT_CALLS_PER_PASS = 20;

export class EntityTagger {
  private extractor: SubjectExtractor | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly retryBackoffMs = RETRY_BACKOFF_MS,
    private readonly workerId = ulid(),
  ) {}

  /** Wire the optional model tier. Absent → deterministic-only, still correct. */
  attach(extractor: SubjectExtractor | null): void {
    this.extractor = extractor;
  }

  /** How many facts are still waiting for a subject, for the S11 gauge. */
  async pending(namespace: string, pattern: string): Promise<number> {
    const result = await this.db.query(
      `SELECT COUNT(*)::int AS count FROM entity_tag_queue
        WHERE status IN ('pending','running')
          AND ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')`,
      [namespace, pattern],
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async runOnce(options: { limit?: number } = {}): Promise<EntityTagRunResult> {
    const limit = Math.max(1, Math.min(200, Math.floor(options.limit ?? 50)));
    const claimed = await this.claim(limit);
    let modelBudget = SUBJECT_CALLS_PER_PASS;
    const result: EntityTagRunResult = {
      claimed: claimed.length,
      tagged: 0,
      empty: 0,
      deferred: 0,
    };
    for (const row of claimed) {
      try {
        const outcome = await this.tag(row, modelBudget > 0);
        if (outcome.usedModel) modelBudget -= 1;
        if (outcome.subjects.length > 0) result.tagged += 1;
        else result.empty += 1;
        await this.complete(row, outcome.subjects);
      } catch (error) {
        result.deferred += 1;
        await this.defer(row, error instanceof Error ? error.message : "tag_failed");
      }
    }
    if (result.tagged > 0) {
      await this.audit.append({
        ts: new Date().toISOString(), actor: "system", agentId: "entity-tagger",
        op: "write", memoryId: null, namespace: "",
        purpose: "entity-subject-derivation", result: "ok",
        detail: `tagged=${result.tagged} empty=${result.empty} deferred=${result.deferred}`,
      });
    }
    return result;
  }

  private async claim(limit: number): Promise<QueuedRow[]> {
    const now = new Date();
    const leaseUntil = new Date(now.getTime() + LEASE_MS).toISOString();
    return this.db.transaction(async (tx) => {
      const claimed = await tx.query(
        `WITH candidates AS (
           SELECT memory_id FROM entity_tag_queue
            WHERE (status = 'pending' AND (retry_at IS NULL OR retry_at <= $1))
               OR (status = 'running' AND lease_until < $1)
            ORDER BY enqueued_at, memory_id
            LIMIT $2
            FOR UPDATE SKIP LOCKED
         )
         UPDATE entity_tag_queue AS q
            SET status = 'running', attempts = q.attempts + 1,
                lease_owner = $3, lease_until = $4, last_error = NULL
           FROM candidates
          WHERE q.memory_id = candidates.memory_id
         RETURNING q.memory_id, q.namespace, q.attempts`,
        [now.toISOString(), limit, this.workerId, leaseUntil],
      );
      return claimed.rows as QueuedRow[];
    });
  }

  private async tag(
    row: QueuedRow,
    modelAffordable: boolean,
  ): Promise<{ subjects: string[]; usedModel: boolean }> {
    const result = await this.db.query(
      `SELECT content FROM memory_objects WHERE id = $1`,
      [row.memory_id],
    );
    const content = result.rows[0] === undefined
      ? null
      : String((result.rows[0] as Record<string, unknown>).content);
    // Erased or vacuumed between enrolment and this pass: nothing to tag.
    if (content === null) return { subjects: [], usedModel: false };
    const base = content.replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "");
    // Union of both subject sources: the write path's registry-resolved
    // annotation (higher quality, when present) plus deterministic proper
    // nouns. Mirroring the annotation here is what makes `derived_entities`
    // the single column the scan can group by.
    const deterministic = usableSubjects([
      ...parseEntitiesAnnotation(content),
      ...capitalizedWords(base),
    ]);
    if (deterministic.length > 0) return { subjects: deterministic, usedModel: false };
    if (!this.extractor || !modelAffordable) return { subjects: [], usedModel: false };
    // Prose with no proper noun. Model output is untrusted data: it is filtered
    // through the same subject vocabulary as everything else, never stored raw.
    const named = await this.extractor({ content: base, namespace: row.namespace });
    return { subjects: usableSubjects(named), usedModel: true };
  }

  private async complete(row: QueuedRow, subjects: string[]): Promise<void> {
    await this.db.transaction(async (tx) => {
      // Content is untouched — only the derived column moves (D7).
      await tx.query(
        `UPDATE memory_objects SET derived_entities = $2::jsonb WHERE id = $1`,
        [row.memory_id, JSON.stringify(subjects)],
      );
      await tx.query(
        `UPDATE entity_tag_queue
            SET status = 'done', completed_at = $2, lease_owner = NULL, lease_until = NULL
          WHERE memory_id = $1 AND lease_owner = $3`,
        [row.memory_id, new Date().toISOString(), this.workerId],
      );
    });
  }

  private async defer(row: QueuedRow, reason: string): Promise<void> {
    const exhausted = Number(row.attempts) >= MAX_ATTEMPTS;
    await this.db.query(
      `UPDATE entity_tag_queue
          SET status = $2, retry_at = $3, last_error = $4,
              lease_owner = NULL, lease_until = NULL
        WHERE memory_id = $1 AND lease_owner = $5`,
      [
        row.memory_id,
        exhausted ? "failed" : "pending",
        exhausted ? null : new Date(Date.now() + this.retryBackoffMs).toISOString(),
        reason.slice(0, 500),
        this.workerId,
      ],
    );
  }
}
