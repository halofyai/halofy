/**
 * Write-time conflict detection outbox (CA1).
 *
 * The write path enqueues a committed fact id inside its OWN transaction, so
 * the queue row and the fact commit or roll back together. Detection then runs
 * after the commit, in the durable worker: a judge outage, a budget cap, or a
 * process crash leaves the row pending and delays the check. It can never fail,
 * block, or slow the write itself (non-negotiable 5 — brownout, never
 * hard-fail).
 *
 * This module deliberately imports nothing but a database handle type: the
 * write path imports it, and the worker imports the write path's trust
 * lattice, so keeping the enqueue helper separate keeps that a straight line.
 */

/** The transaction-scoped subset of `Db` the write path already passes around. */
export interface QueueDbLike {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export const CURRENT_CONFLICT_DETECTOR_VERSION = "luna-context-v1";

/**
 * Queue a freshly committed fact for its conflict check.
 *
 * Idempotent by memory id: re-enqueuing a fact that is already awaiting its
 * check is a no-op, and a fact whose check already completed is re-armed (the
 * resync and overturn lanes both re-check a fact whose neighbourhood changed).
 */
export async function enqueueConflictCheck(
  db: QueueDbLike,
  memoryId: string,
  namespace: string,
  now: string,
): Promise<void> {
  await db.query(
    `INSERT INTO conflict_detection_queue
       (memory_id, namespace, enqueued_at, status, attempts, detector_version, candidate_cursor)
     VALUES ($1, $2, $3, 'pending', 0, $4, 0)
     ON CONFLICT (memory_id) DO UPDATE
        SET status = CASE WHEN conflict_detection_queue.status IN ('done','failed')
                           OR conflict_detection_queue.detector_version <> EXCLUDED.detector_version
                          THEN 'pending' ELSE conflict_detection_queue.status END,
            enqueued_at = EXCLUDED.enqueued_at,
            attempts = 0, retry_at = NULL, last_error = NULL,
            completed_at = NULL, detector_version = EXCLUDED.detector_version,
            candidate_cursor = 0`,
    [memoryId, namespace, now, CURRENT_CONFLICT_DETECTOR_VERSION],
  );
}

/**
 * Queue a freshly committed fact for subject derivation (CA8). Same shape and
 * same commit boundary as the conflict check: a fact that lands without a
 * usable subject is invisible to grouped detection, so losing the enrolment
 * would silently shrink coverage.
 */
export async function enqueueEntityTag(
  db: QueueDbLike,
  memoryId: string,
  namespace: string,
  now: string,
): Promise<void> {
  await enqueue(db, "entity_tag_queue", memoryId, namespace, now);
}

/** Shared upsert for the durable work queues. Table name is a literal, never caller data. */
async function enqueue(
  db: QueueDbLike,
  table: "conflict_detection_queue" | "entity_tag_queue",
  memoryId: string,
  namespace: string,
  now: string,
): Promise<void> {
  await db.query(
    `INSERT INTO ${table}
       (memory_id, namespace, enqueued_at, status, attempts)
     VALUES ($1, $2, $3, 'pending', 0)
     ON CONFLICT (memory_id) DO UPDATE
        SET status = CASE WHEN ${table}.status IN ('done','failed')
                          THEN 'pending' ELSE ${table}.status END,
            enqueued_at = CASE WHEN ${table}.status IN ('done','failed')
                               THEN EXCLUDED.enqueued_at ELSE ${table}.enqueued_at END,
            attempts = CASE WHEN ${table}.status IN ('done','failed')
                            THEN 0 ELSE ${table}.attempts END,
            retry_at = NULL,
            last_error = NULL`,
    [memoryId, namespace, now],
  );
}
