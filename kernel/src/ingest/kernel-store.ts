/**
 * Kernel-side ingestion backing (integrator-owned — NOT a connector/importer).
 *
 * This file is the deliberate exception to D10: it MAY touch db/index/types,
 * because it is the kernel wiring the connectors/importers never see. It
 * provides the three DB-backed collaborators the kernel hands into the
 * ingestion write path and the fragmentation analysis:
 *
 *   - `DbSourceState`      → `SourceState` over `source_documents` (drift-hash
 *                            bookkeeping plus atomic exact-version retirement;
 *                            the connector's whole drift surface).
 *   - `DbFragmentationReader` → `FragmentationReader`: SELECTs active L2 facts
 *                            for the caller's namespace ancestor set using the
 *                            SAME IN-list ACL as mem_stats / MemoryIndex, parses
 *                            the pgvector `embedding` column back to number[],
 *                            reads `provenance[0].source`/`sourceId` from the
 *                            JSONB, and derives canonical `entities` from the
 *                            `[entities: …]` annotation the write path appends.
 *   - `SourceRegistry`     → register/get/list rows over the `sources` table.
 *
 * D10 note: connectors/importers still reach the store ONLY through the
 * IngestSink and SourceState; this module is what the KERNEL builds behind
 * those seams. It is under src/ingest/ but is NOT under importers/ or
 * connectors/, so the D10 static guard (which scans only those two dirs) does
 * not — and must not — apply to it.
 */

import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import { namespaceAncestors, TTL_ACTIVE_CLAUSE } from "../index/index.js";
import {
  REDACTED_SOURCE_CONFIG,
  redactSourceError,
  SourceConfigCipher,
  type SealedSourceConfig,
} from "./source-config.js";
import type {
  AuditEvent,
  CreateSourceCredentialInput,
  FragmentFact,
  FragmentationReader,
  KnowledgeBaseSourceMetadata,
  Namespace,
  ProvenanceEntry,
  Scope,
  SourceCredentialRecord,
  SourceCredentialSummary,
  SourceKind,
  SourceState,
} from "../types.js";

// ---------------------------------------------------------------------------
// DbSourceState — drift-hash bookkeeping over source_documents.
// ---------------------------------------------------------------------------

const CLAIM_WAIT_MS = 10;
const CLAIM_TIMEOUT_MS = 30_000;

/**
 * `SourceState` over the `source_documents` table, scoped to one source id AND
 * the landing namespace of this sync. Connectors receive this as their whole
 * drift surface (via ConnectorContext); they never touch the DB directly.
 *
 * The landing namespace is an explicit part of the drift key: syncSource lands
 * facts in the CALLER's namespace (kernel.ts), and the ACL lets a descendant of
 * a source's registration namespace sync it. The database identity is exactly
 * `(source_id, landing_namespace, document_key)` — document ids are never
 * delimiter-packed.
 *
 * `priorHash()` also takes a durable per-document claim before the connector
 * writes. That claim spans the write-path call through `record()`, serializing
 * concurrent first syncs across processes. The loser observes the committed
 * hash after the winner releases the claim, so it skips or supersedes from a
 * coherent prior version rather than landing an orphan active fact.
 */
export class DbSourceState implements SourceState {
  private readonly claimToken = ulid();

  constructor(
    private readonly db: Db,
    private readonly sourceId: string,
    private readonly namespace: Namespace,
    private readonly appendAudit: (db: Db, event: AuditEvent) => Promise<void>,
    private readonly actor = "ingest",
    private readonly agentId = "ingest",
    private readonly enqueueInvalidations?: (
      tx: Db,
      retiredIds: string[],
      namespace: Namespace,
    ) => Promise<void>,
  ) {}

  async priorHash(docId: string): Promise<string | null> {
    return this.acquire(docId);
  }

  async record(
    docId: string,
    contentHash: string,
    syncedAt: string,
    expectedPriorHash?: string | null,
  ): Promise<void> {
    await this.acquire(docId);
    try {
      await this.db.transaction(async (tx) => {
        await this.assertClaim(tx, docId);
        const current = await tx.query(
          `SELECT content_hash FROM source_documents
            WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
            FOR UPDATE`,
          [this.sourceId, this.namespace, docId],
        );
        const priorHash =
          current.rows.length === 0
            ? null
            : (current.rows[0] as { content_hash: string }).content_hash;
        if (expectedPriorHash !== undefined && priorHash !== expectedPriorHash) {
          throw new Error(
            `source document changed concurrently: ${this.sourceId}/${this.namespace}/${docId}`,
          );
        }

        if (priorHash !== null && priorHash !== contentHash) {
          await this.retractVersion(tx, docId, priorHash, syncedAt, "changed");
        }

        await tx.query(
          `INSERT INTO source_documents
             (source_id, landing_namespace, document_key, content_hash, synced_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (source_id, landing_namespace, document_key)
           DO UPDATE SET content_hash = EXCLUDED.content_hash, synced_at = EXCLUDED.synced_at`,
          [this.sourceId, this.namespace, docId, contentHash, syncedAt],
        );
        await this.releaseClaim(tx, docId);
      });
    } catch (err) {
      await this.releaseClaimBestEffort(docId);
      throw err;
    }
  }

  async knownDocIds(): Promise<string[]> {
    return this.db.transaction(async (tx) => {
      const res = await tx.query(
        `SELECT document_key FROM source_documents
          WHERE source_id = $1 AND landing_namespace = $2
          ORDER BY document_key`,
        [this.sourceId, this.namespace],
      );
      // Releases claims for unchanged documents and failed writes. Removed
      // documents were not enumerated, so they have no claim yet.
      await tx.query(
        `DELETE FROM source_document_claims WHERE claim_token = $1`,
        [this.claimToken],
      );
      return (res.rows as { document_key: string }[]).map((row) => row.document_key);
    });
  }

  async knownDocIdsPage(
    after: string | null,
    limit: number,
  ): Promise<{ ids: string[]; nextAfter: string | null }> {
    const bounded = Math.max(1, Math.min(500, Math.floor(limit)));
    const res = await this.db.query(
      `SELECT document_key FROM source_documents
        WHERE source_id = $1 AND landing_namespace = $2
          AND ($3::text IS NULL OR document_key > $3)
        ORDER BY document_key
        LIMIT $4`,
      [this.sourceId, this.namespace, after, bounded + 1],
    );
    const rows = (res.rows as { document_key: string }[]).map((row) => row.document_key);
    const ids = rows.slice(0, bounded);
    return {
      ids,
      nextAfter: rows.length > bounded ? ids[ids.length - 1] ?? null : null,
    };
  }

  async releaseClaims(): Promise<void> {
    await this.db.query(
      `DELETE FROM source_document_claims WHERE claim_token = $1`,
      [this.claimToken],
    );
  }

  async forget(docIds: string[]): Promise<void> {
    if (docIds.length === 0) return;
    for (const docId of docIds) await this.acquire(docId);
    const retiredAt = new Date().toISOString();
    try {
      await this.db.transaction(async (tx) => {
        for (const docId of docIds) {
          await this.assertClaim(tx, docId);
          const current = await tx.query(
            `SELECT content_hash FROM source_documents
              WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
              FOR UPDATE`,
            [this.sourceId, this.namespace, docId],
          );
          if (current.rows.length === 0) continue;
          const hash = (current.rows[0] as { content_hash: string }).content_hash;
          await this.retractVersion(tx, docId, hash, retiredAt, "removed");
        }
        const placeholders = docIds.map((_, i) => `$${i + 3}`).join(", ");
        await tx.query(
          `DELETE FROM source_documents
            WHERE source_id = $1 AND landing_namespace = $2
              AND document_key IN (${placeholders})`,
          [this.sourceId, this.namespace, ...docIds],
        );
        await tx.query(
          `DELETE FROM source_document_claims WHERE claim_token = $1`,
          [this.claimToken],
        );
      });
    } catch (err) {
      await this.releaseClaimsBestEffort();
      throw err;
    }
  }

  /**
   * Compensate an import that failed after facts landed but before its source
   * version committed. Exact provenance keeps unrelated facts untouched, and
   * retractVersion supplies the mandatory D4 audit row.
   */
  async retractUncommittedVersion(
    docId: string,
    contentHash: string,
    retiredAt = new Date().toISOString(),
    attemptToken?: string,
  ): Promise<void> {
    await this.acquire(docId);
    try {
      await this.db.transaction(async (tx) => {
        await this.assertClaim(tx, docId);
        await this.retractVersion(
          tx,
          docId,
          contentHash,
          retiredAt,
          "failed",
          attemptToken,
        );
        await tx.query(
          `DELETE FROM source_documents
            WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
              AND content_hash = $4`,
          [this.sourceId, this.namespace, docId, contentHash],
        );
        await this.releaseClaim(tx, docId);
      });
    } catch (error) {
      await this.releaseClaimBestEffort(docId);
      throw error;
    }
  }

  /**
   * Transaction-scoped variant for a caller that already owns an external
   * attempt fence (the policy-document row lock). The attempt-token provenance
   * makes compensation exact, so no source-document claim is required and the
   * retraction can commit atomically with lease retirement.
   */
  async retractUncommittedVersionFrom(
    tx: Db,
    docId: string,
    contentHash: string,
    retiredAt = new Date().toISOString(),
    attemptToken?: string,
  ): Promise<void> {
    await this.retractVersion(
      tx,
      docId,
      contentHash,
      retiredAt,
      "failed",
      attemptToken,
    );
    await tx.query(
      `DELETE FROM source_documents
        WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
          AND content_hash = $4`,
      [this.sourceId, this.namespace, docId, contentHash],
    );
  }

  /**
   * Retract a committed source version and its landed facts from inside an
   * existing transaction. Used when a policy document is permanently deleted:
   * the facts it contributed must leave active memory even though the source
   * row itself may remain for provenance/audit.
   */
  async retractCommittedVersionInTransaction(
    tx: Db,
    docId: string,
    contentHash: string,
    retiredAt = new Date().toISOString(),
    attemptToken?: string,
  ): Promise<void> {
    await this.retractVersion(
      tx,
      docId,
      contentHash,
      retiredAt,
      "removed",
      attemptToken,
    );
  }

  /**
   * Retract every landed document of ONE FILE from inside an existing
   * transaction. Used when an adopted policy document is deleted: the file may
   * have landed as many fragment documents (`policies.csv#refund-cap`, …), and
   * the register row carries no attempt token because the facts predate it.
   *
   * The (documentKey, contentHash) pairs come from the provenance of the facts
   * that are actually live, not from `source_documents` — a file whose source
   * rows were already pruned must still retract cleanly, and a fact can only be
   * matched by the exact hash it carries.
   *
   * Returns the document keys it retracted, for audit detail.
   */
  async retractCommittedFileInTransaction(
    tx: Db,
    fileName: string,
    retiredAt = new Date().toISOString(),
  ): Promise<string[]> {
    const versions = await tx.query(
      `SELECT DISTINCT p->>'documentKey' AS document_key,
              p->>'contentHash' AS content_hash
         FROM memory_objects m
         CROSS JOIN LATERAL jsonb_array_elements(m.provenance) AS p
        WHERE m.namespace = $1
          AND m.status IN ('active', 'disputed')
          AND p->>'sourceId' = $2
          AND p ? 'contentHash'
          AND (p->>'documentKey' = $3
               OR p->>'documentKey' LIKE $4 ESCAPE '\\')
        ORDER BY 1`,
      [
        this.namespace,
        this.sourceId,
        fileName,
        `${escapeLikePattern(fileName)}#%`,
      ],
    );
    const retracted: string[] = [];
    for (const row of versions.rows as Array<{
      document_key: string;
      content_hash: string;
    }>) {
      await this.retractVersion(
        tx,
        row.document_key,
        row.content_hash,
        retiredAt,
        "removed",
      );
      retracted.push(row.document_key);
    }
    return retracted;
  }

  private async acquire(docId: string): Promise<string | null> {
    const deadline = Date.now() + CLAIM_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const result = await this.db.transaction(async (tx) => {
        await tx.query(
          `DELETE FROM source_document_claims
            WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
              AND claimed_at < CURRENT_TIMESTAMP - INTERVAL '15 minutes'`,
          [this.sourceId, this.namespace, docId],
        );
        const claim = await tx.query(
          `INSERT INTO source_document_claims
             (source_id, landing_namespace, document_key, claim_token, claimed_at)
           VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
           ON CONFLICT (source_id, landing_namespace, document_key) DO NOTHING
           RETURNING claim_token`,
          [this.sourceId, this.namespace, docId, this.claimToken],
        );
        const acquired = claim.rows.length > 0;
        if (!acquired) {
          const owned = await tx.query(
            `SELECT claim_token FROM source_document_claims
              WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
                AND claim_token = $4`,
            [this.sourceId, this.namespace, docId, this.claimToken],
          );
          if (owned.rows.length === 0) return { acquired: false, prior: null };
        }
        const current = await tx.query(
          `SELECT content_hash FROM source_documents
            WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3`,
          [this.sourceId, this.namespace, docId],
        );
        return {
          acquired: true,
          prior:
            current.rows.length === 0
              ? null
              : (current.rows[0] as { content_hash: string }).content_hash,
        };
      });
      if (result.acquired) return result.prior;
      await new Promise<void>((resolve) => setTimeout(resolve, CLAIM_WAIT_MS));
    }
    throw new Error(
      `timed out waiting for source document claim: ${this.sourceId}/${this.namespace}/${docId}`,
    );
  }

  private async assertClaim(tx: Db, docId: string): Promise<void> {
    const claim = await tx.query(
      `SELECT claim_token FROM source_document_claims
        WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
          AND claim_token = $4
        FOR UPDATE`,
      [this.sourceId, this.namespace, docId, this.claimToken],
    );
    if (claim.rows.length === 0) {
      throw new Error(
        `source document claim lost: ${this.sourceId}/${this.namespace}/${docId}`,
      );
    }
  }

  private releaseClaim(tx: Db, docId: string): Promise<{ rows: unknown[] }> {
    return tx.query(
      `DELETE FROM source_document_claims
        WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
          AND claim_token = $4`,
      [this.sourceId, this.namespace, docId, this.claimToken],
    );
  }

  private async releaseClaimBestEffort(docId: string): Promise<void> {
    try {
      await this.db.query(
        `DELETE FROM source_document_claims
          WHERE source_id = $1 AND landing_namespace = $2 AND document_key = $3
            AND claim_token = $4`,
        [this.sourceId, this.namespace, docId, this.claimToken],
      );
    } catch {
      // The bounded stale-claim cleanup in acquire() remains the recovery path.
    }
  }

  private async releaseClaimsBestEffort(): Promise<void> {
    try {
      await this.db.query(
        `DELETE FROM source_document_claims WHERE claim_token = $1`,
        [this.claimToken],
      );
    } catch {
      // The bounded stale-claim cleanup in acquire() remains the recovery path.
    }
  }

  private async retractVersion(
    tx: Db,
    docId: string,
    contentHash: string,
    retiredAt: string,
    reason: "changed" | "removed" | "failed",
    attemptToken?: string,
  ): Promise<void> {
    const attributable = JSON.stringify([
      {
        sourceId: this.sourceId,
        documentKey: docId,
        contentHash,
        ...(attemptToken ? { attemptToken } : {}),
      },
    ]);
    const affected = await tx.query(
      `UPDATE memory_objects
          SET t_valid_to = $1, status = 'archived'
        WHERE namespace = $2
          AND status = 'active'
          AND t_valid_to IS NULL
          AND provenance @> $3::jsonb
        RETURNING id`,
      [retiredAt, this.namespace, attributable],
    );
    // A QUARANTINED fact of the retracted version retires too, and its open
    // dispute resolves as 'retracted' — the source version is gone, so asking
    // a human to adjudicate the ghost would only wedge the review queue.
    const retiredDisputed = await tx.query(
      `UPDATE memory_objects
          SET t_valid_to = $1, status = 'archived'
        WHERE namespace = $2
          AND status = 'disputed'
          AND provenance @> $3::jsonb
        RETURNING id`,
      [retiredAt, this.namespace, attributable],
    );
    const retiredDisputedIds = (retiredDisputed.rows as Array<{ id: string }>).map(
      (row) => row.id,
    );
    const affectedIds = [
      ...(affected.rows as Array<{ id: string }>).map((row) => row.id),
      ...retiredDisputedIds,
    ];
    await this.retireDerivedGraph(tx, affectedIds, retiredAt);
    await this.resolveRetractedDisputes(tx, retiredDisputedIds, retiredAt);
    await this.enqueueInvalidations?.(tx, affectedIds, this.namespace);
    const detail = JSON.stringify({
      sourceId: this.sourceId,
      landingNamespace: this.namespace,
      documentKey: docId,
      retiredHash: contentHash,
      ...(attemptToken ? { attemptToken } : {}),
      reason,
      affectedIds,
    });
    const auditIds: Array<string | null> = affectedIds.length > 0 ? affectedIds : [null];
    for (const memoryId of auditIds) {
      await this.appendAudit(tx, {
        ts: retiredAt,
        actor: this.actor,
        agentId: this.agentId,
        op: "retract",
        memoryId,
        namespace: this.namespace,
        purpose: null,
        result: "ok",
        detail,
      });
    }
  }

  /** Retire every current fact/pointer attributed to this source and namespace. */
  async retireSource(retiredAt = new Date().toISOString()): Promise<string[]> {
    return this.db.transaction(async (tx) => {
      const attributable = JSON.stringify([{ sourceId: this.sourceId }]);
      const active = await tx.query(
        `UPDATE memory_objects
            SET t_valid_to = $1, status = 'archived'
          WHERE namespace = $2 AND status = 'active' AND t_valid_to IS NULL
            AND provenance @> $3::jsonb
          RETURNING id`,
        [retiredAt, this.namespace, attributable],
      );
      const disputed = await tx.query(
        `UPDATE memory_objects
            SET t_valid_to = $1, status = 'archived'
          WHERE namespace = $2 AND status = 'disputed' AND t_valid_to IS NULL
            AND provenance @> $3::jsonb
          RETURNING id`,
        [retiredAt, this.namespace, attributable],
      );
      const affectedIds = [
        ...(active.rows as Array<{ id: string }>).map((row) => row.id),
        ...(disputed.rows as Array<{ id: string }>).map((row) => row.id),
      ];
      await this.retireDerivedGraph(tx, affectedIds, retiredAt);
      await this.resolveRetractedDisputes(tx, affectedIds, retiredAt);
      await this.enqueueInvalidations?.(tx, affectedIds, this.namespace);
      await tx.query(
        `DELETE FROM source_documents
          WHERE source_id = $1 AND landing_namespace = $2`,
        [this.sourceId, this.namespace],
      );
      await tx.query(
        `DELETE FROM source_document_claims
          WHERE source_id = $1 AND landing_namespace = $2`,
        [this.sourceId, this.namespace],
      );

      const detail = JSON.stringify({
        sourceId: this.sourceId,
        landingNamespace: this.namespace,
        reason: "disconnected",
        affectedIds,
      });
      const auditIds: Array<string | null> = affectedIds.length > 0 ? affectedIds : [null];
      for (const memoryId of auditIds) {
        await this.appendAudit(tx, {
          ts: retiredAt,
          actor: this.actor,
          agentId: this.agentId,
          op: "retract",
          memoryId,
          namespace: this.namespace,
          purpose: null,
          result: "ok",
          detail,
        });
      }
      return affectedIds;
    });
  }

  /** Close graph projections whose supporting memories are no longer current. */
  private async retireDerivedGraph(
    tx: Db,
    memoryIds: string[],
    retiredAt: string,
  ): Promise<void> {
    if (memoryIds.length === 0) return;
    const placeholders = memoryIds.map((_, index) => `$${index + 3}`).join(", ");
    await tx.query(
      `UPDATE entity_mentions
          SET t_valid_to = $2
        WHERE namespace = $1 AND t_valid_to IS NULL
          AND memory_id IN (${placeholders})`,
      [this.namespace, retiredAt, ...memoryIds],
    );
    await tx.query(
      `UPDATE entity_relationships relationship
          SET status = 'archived', t_valid_to = $2
        WHERE relationship.namespace = $1
          AND relationship.status = 'active'
          AND relationship.t_valid_to IS NULL
          AND EXISTS (
            SELECT 1 FROM entity_relationship_evidence evidence
             WHERE evidence.relationship_id = relationship.id
               AND evidence.memory_id IN (${placeholders})
          )`,
      [this.namespace, retiredAt, ...memoryIds],
    );
  }

  private async resolveRetractedDisputes(
    tx: Db,
    memoryIds: string[],
    retiredAt: string,
  ): Promise<void> {
    if (memoryIds.length === 0) return;
    const placeholders = memoryIds.map((_, index) => `$${index + 2}`).join(", ");
    await tx.query(
      `UPDATE fact_disputes
          SET status = 'resolved', resolution = 'retracted',
              resolved_by = 'system:retract', resolved_at = $1,
              row_version = row_version + 1, updated_at = $1
        WHERE status = 'open' AND memory_id IN (${placeholders})`,
      [retiredAt, ...memoryIds],
    );
  }

}

// ---------------------------------------------------------------------------
// DbFragmentationReader — active facts for a namespace subtree, ACL-scoped.
// ---------------------------------------------------------------------------

/** Pull `[entities: a, b, c]` off a fact's content into canonical names. */
export function parseEntitiesAnnotation(content: string): string[] {
  // The write path appends " [entities: Name1, Name2]" once, at the end.
  const m = /\[entities:\s*([^\]]*)\]\s*$/.exec(content);
  if (!m) return [];
  return m[1]!
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Parse a pgvector `embedding::text` literal ('[v1,v2,...]') into number[]. */
export function parseVectorText(text: unknown): number[] | null {
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  if (trimmed.length === 0) return null;
  const inner = trimmed.replace(/^\[/, "").replace(/\]$/, "");
  if (inner.length === 0) return null;
  const out: number[] = [];
  for (const part of inner.split(",")) {
    const n = Number(part);
    if (!Number.isFinite(n)) return null;
    out.push(n);
  }
  return out.length > 0 ? out : null;
}

/** Read provenance JSONB (object OR string) into a typed array. */
function parseProvenance(value: unknown): ProvenanceEntry[] {
  if (value === null || value === undefined) return [];
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as ProvenanceEntry[];
    } catch {
      return [];
    }
  }
  return value as ProvenanceEntry[];
}

/**
 * `FragmentationReader` over `memory_objects`. `facts(namespace)` returns the
 * currently-VALID ACTIVE L2 facts for the namespace ancestor set (the same
 * exact-IN-list ACL as mem_stats — no LIKE wildcard leak), with embeddings
 * parsed to number[], provenance[0].source/sourceId read off the JSONB, and
 * canonical entities derived from the write path's `[entities: …]` annotation.
 *
 * Only currently-valid rows (t_valid_to IS NULL) are returned. Supersedence
 * closes a fact's validity (t_valid_to set) but leaves status='active' (the
 * status enum has no 'superseded' state), so filtering on status alone would
 * feed already-resolved facts into duplicate clustering + factCount/sourceCounts
 * — inflating totals and reporting a closed fact as live fragmentation.
 * Contradiction detection already self-filters to t_valid_to === null, so this
 * is the single source of truth for "what is fragmented right now".
 */
export class DbFragmentationReader implements FragmentationReader {
  constructor(private readonly db: Db) {}

  async facts(namespace: Namespace): Promise<FragmentFact[]> {
    const allowed = namespaceAncestors(namespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT id, namespace, content, scope, provenance,
              t_valid_from, t_valid_to, embedding::text AS embedding_text
       FROM memory_objects
       WHERE tier = 'L2'
         AND status = 'active'
         AND ${TTL_ACTIVE_CLAUSE}
         AND t_valid_to IS NULL
         AND namespace IN (${nsPlaceholders})
       ORDER BY id ASC`,
      allowed,
    );

    return (res.rows as Record<string, unknown>[]).map((row) => {
      const provenance = parseProvenance(row.provenance);
      const first = provenance[0];
      const content = row.content as string;
      return {
        ref: row.id as string,
        namespace: row.namespace as Namespace,
        content,
        scope: row.scope as Scope,
        embedding: parseVectorText(row.embedding_text),
        entities: parseEntitiesAnnotation(content),
        sourceId: first?.sourceId ?? null,
        source: first?.source ?? "conversation",
        tValidFrom: toIso(row.t_valid_from),
        tValidTo: toIsoOrNull(row.t_valid_to),
      };
    });
  }
}

// ---------------------------------------------------------------------------
// SourceRegistry — register/get/list over the sources table.
// ---------------------------------------------------------------------------

export interface SourceMetadataUpdate extends KnowledgeBaseSourceMetadata {}

/** Safe source projection. Connector config and credential references are excluded. */
export interface SourceMetadataProjection extends KnowledgeBaseSourceMetadata {
  id: string;
  namespace: Namespace;
}

export interface SourceRow extends KnowledgeBaseSourceMetadata {
  id: string;
  namespace: Namespace;
  kind: SourceKind;
  config: Record<string, unknown>;
  configState: "encrypted" | "quarantined";
  credentialId: string | null;
  createdAt: string;
  lastSync: string | null;
  syncStatus: "never_synced" | "pending" | "synced" | "failed";
  lastSyncError: string | null;
  lastSyncStartedAt: string | null;
  lifecycleState: "active" | "paused" | "disabled";
  syncIntervalSeconds: number | null;
  nextSyncAt: string | null;
  consecutiveFailures: number;
}

/**
 * E57: `doc_site` sources re-crawl automatically by DEFAULT — "keeps it fresh
 * automatically" is default-on, not opt-in via automations. Daily unless
 * overridden by `HALOMEM_DOC_SITE_SYNC_INTERVAL_SECONDS` (min 60, matching the
 * `sources_sync_interval_min` CHECK; `0`/`off` disables the default globally).
 * An invalid override browns out to the daily default — never a hard-fail.
 * Operators can still disable per source via the existing schedule API
 * (`setSchedule(id, null)`).
 */
export const DOC_SITE_DEFAULT_SYNC_INTERVAL_SECONDS = 86_400;
/**
 * Direct-OAuth workspace connectors re-sync on their own. Five hours keeps a
 * workspace current without cost: the connector fetches only entities whose
 * `updatedAt` moved, and the drift engine skips anything whose content hash is
 * unchanged, so a quiet workspace costs a couple of API calls and no LLM work.
 */
export const LINEAR_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS = 18_000;
/** Direct Notion uses a conservative four-hour page-level refresh cadence. */
export const NOTION_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS = 14_400;
/** Direct Airtable uses a conservative four-hour account reconciliation cadence. */
export const AIRTABLE_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS = 14_400;

/** Env override shared by the scheduled kinds; `0`/`off` disables the default. */
function envSyncInterval(name: string, fallback: number): number | null {
  const raw = process.env[name]?.trim();
  if (raw !== undefined && raw !== "") {
    if (raw === "0" || raw.toLowerCase() === "off") return null;
    const parsed = Number(raw);
    if (Number.isSafeInteger(parsed) && parsed >= 60) return parsed;
    // Brownout: an unparseable/undersized override falls back to the default.
  }
  return fallback;
}

export function defaultSyncIntervalSeconds(kind: SourceKind): number | null {
  if (kind === "doc_site") {
    return envSyncInterval(
      "HALOMEM_DOC_SITE_SYNC_INTERVAL_SECONDS",
      DOC_SITE_DEFAULT_SYNC_INTERVAL_SECONDS,
    );
  }
  if (kind === "linear_direct") {
    return envSyncInterval(
      "HALOMEM_LINEAR_SYNC_INTERVAL_SECONDS",
      LINEAR_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS,
    );
  }
  if (kind === "notion_direct") {
    return envSyncInterval(
      "HALOMEM_NOTION_SYNC_INTERVAL_SECONDS",
      NOTION_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS,
    );
  }
  if (kind === "airtable_direct") {
    return envSyncInterval(
      "HALOMEM_AIRTABLE_SYNC_INTERVAL_SECONDS",
      AIRTABLE_DIRECT_DEFAULT_SYNC_INTERVAL_SECONDS,
    );
  }
  if (kind === "google_drive_direct" || kind === "google_docs_direct" ||
      kind === "google_sheets_direct") return 14_400;
  return null;
}

const SOURCE_METADATA_KEYS = [
  "dataSensitive",
  "description",
  "primaryBusinessFunction",
] as const;
const SOURCE_METADATA_CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

function normalizeSourceMetadata(input: SourceMetadataUpdate): SourceMetadataUpdate {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("source metadata must be an object");
  }
  const keys = Object.keys(input).sort();
  if (keys.length !== SOURCE_METADATA_KEYS.length ||
      keys.some((key, index) => key !== SOURCE_METADATA_KEYS[index])) {
    throw new Error("source metadata must contain exactly primaryBusinessFunction, description, and dataSensitive");
  }
  if (typeof input.primaryBusinessFunction !== "string") {
    throw new Error("source primary business function must be a string");
  }
  if (typeof input.description !== "string") {
    throw new Error("source description must be a string");
  }
  if (typeof input.dataSensitive !== "boolean") {
    throw new Error("source dataSensitive must be explicitly true or false");
  }
  const primaryBusinessFunction = input.primaryBusinessFunction.trim();
  const description = input.description.trim();
  if (primaryBusinessFunction.length < 1 || primaryBusinessFunction.length > 120) {
    throw new Error("source primary business function must contain 1 to 120 characters");
  }
  if (description.length > 2_000) {
    throw new Error("source description must contain at most 2000 characters");
  }
  if (SOURCE_METADATA_CONTROL.test(primaryBusinessFunction) || SOURCE_METADATA_CONTROL.test(description)) {
    throw new Error("source metadata must not contain control characters");
  }
  return { primaryBusinessFunction, description, dataSensitive: input.dataSensitive };
}

function toSourceMetadataProjection(row: Record<string, unknown>): SourceMetadataProjection {
  return {
    id: String(row.id),
    namespace: row.namespace as Namespace,
    primaryBusinessFunction: typeof row.primary_business_function === "string"
      ? row.primary_business_function
      : "General",
    description: typeof row.description === "string" ? row.description : "",
    dataSensitive: row.data_sensitive === true,
  };
}

/** register/get/list/last-sync over the `sources` table. */
export class SourceRegistry {
  constructor(
    private readonly db: Db,
    private readonly configCipher: SourceConfigCipher,
    private readonly appendAudit?: (db: Db, event: AuditEvent) => Promise<void>,
  ) {}
  /** Encrypt legacy JSONB rows or remove them when a durable boot has no KEK. */
  async protectLegacyConfigs(): Promise<void> {
    const res = await this.db.query(
      `SELECT id, namespace, kind, config, last_sync_error
         FROM sources WHERE config_state = 'legacy_plaintext'`,
    );
    for (const raw of res.rows as Record<string, unknown>[]) {
      const id = raw.id as string;
      const namespace = raw.namespace as Namespace;
      const kind = raw.kind as SourceKind;
      const config = parseConfig(raw.config);
      const priorError = typeof raw.last_sync_error === "string" ? raw.last_sync_error : null;
      const safeError = priorError ? redactSourceError(priorError, config) : null;
      if (this.configCipher.available) {
        const sealed = this.configCipher.seal(id, namespace, kind, config);
        await this.db.query(
          `UPDATE sources
              SET config = '{}'::jsonb, config_ciphertext = $2, config_iv = $3,
                  config_tag = $4, config_kek_id = $5, config_sha256 = $6,
                  config_state = 'encrypted', last_sync_error = $7
            WHERE id = $1 AND config_state = 'legacy_plaintext'`,
          [id, sealed.ciphertext, sealed.iv, sealed.tag, sealed.kekId, sealed.sha256, safeError],
        );
      } else {
        await this.db.query(
          `UPDATE sources
              SET config = '{}'::jsonb, config_ciphertext = NULL, config_iv = NULL,
                  config_tag = NULL, config_kek_id = NULL,
                  config_sha256 = 'destroyed-v1',
                  config_state = 'quarantined', last_sync_error = $2
            WHERE id = $1 AND config_state = 'legacy_plaintext'`,
          [id, safeError],
        );
      }
      if (safeError !== priorError) {
        await this.db.query(
          `UPDATE setup_operations SET source_error = $2 WHERE source_id = $1`,
          [id, safeError],
        );
      }
    }
  }

  sealForStorage(
    id: string,
    namespace: Namespace,
    kind: SourceKind,
    config: Record<string, unknown>,
  ): SealedSourceConfig {
    return this.configCipher.seal(id, namespace, kind, config);
  }

  /** Insert a new source row (id = fresh ULID) and return it. */
  async register(
    namespace: Namespace,
    kind: SourceKind,
    config: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<SourceRow> {
    if (idempotencyKey !== undefined && !/^[A-Za-z0-9_-]{1,256}$/.test(idempotencyKey)) {
      throw new Error("source idempotency key is invalid");
    }
    const id = ulid();
    const createdAt = new Date().toISOString();
    const credentialId = typeof config.credentialId === "string" && config.credentialId.length > 0
      ? config.credentialId
      : null;
    const storedConfig = { ...config };
    delete storedConfig.credentialId;
    const sealed = this.sealForStorage(id, namespace, kind, storedConfig);
    // E57: doc_site sources get a default sync interval AT CREATION so the
    // existing durable notBefore re-arm chain (initial source-sync job →
    // touchLastSync computes next_sync_at → worker re-enqueues at next_sync_at)
    // keeps re-crawling automatically. next_sync_at stays NULL until the first
    // sync lands — the registration path already enqueues that first job.
    const syncIntervalSeconds = defaultSyncIntervalSeconds(kind);
    const inserted = await this.db.query(
      `INSERT INTO sources
       (id, namespace, kind, config, created_at, last_sync, sync_status,
          last_sync_error, last_sync_started_at, config_ciphertext, config_iv,
          config_tag, config_kek_id, config_sha256, config_state, credential_id,
          idempotency_key, sync_interval_seconds)
       VALUES ($1, $2, $3, '{}'::jsonb, $4, NULL, 'never_synced', NULL, NULL,
               $5, $6, $7, $8, $9, 'encrypted', $10, $11, $12)
       ON CONFLICT (namespace, idempotency_key) WHERE idempotency_key IS NOT NULL
       DO NOTHING
       RETURNING id`,
      [id, namespace, kind, createdAt, sealed.ciphertext, sealed.iv, sealed.tag,
        sealed.kekId, sealed.sha256, credentialId, idempotencyKey ?? null,
        syncIntervalSeconds],
    );
    if (inserted.rows.length === 0 && idempotencyKey) {
      const existing = await this.getByIdempotencyKey(namespace, idempotencyKey);
      if (existing) return existing;
      throw new Error("idempotent source registration failed");
    }
    return {
      id, namespace, kind, config: { ...REDACTED_SOURCE_CONFIG }, configState: "encrypted",
      credentialId,
      primaryBusinessFunction: "General", description: "", dataSensitive: false,
      createdAt, lastSync: null,
      syncStatus: "never_synced", lastSyncError: null, lastSyncStartedAt: null,
      lifecycleState: "active", syncIntervalSeconds, nextSyncAt: null,
      consecutiveFailures: 0,
    };
  }

  /** Fetch one source row by id, or null if absent. */
  async get(id: string): Promise<SourceRow | null> {
    const res = await this.db.query(
      `SELECT id, namespace, kind, config, created_at, last_sync, sync_status,
              last_sync_error, last_sync_started_at, lifecycle_state,
              sync_interval_seconds, next_sync_at, consecutive_failures, config_ciphertext,
              config_iv, config_tag, config_kek_id, config_sha256, config_state,
              credential_id, primary_business_function, description, data_sensitive
       FROM sources WHERE id = $1`,
      [id],
    );
    if (res.rows.length === 0) return null;
    return this.toRow(res.rows[0] as Record<string, unknown>, true);
  }

  async getByIdempotencyKey(
    namespace: Namespace,
    idempotencyKey: string,
  ): Promise<SourceRow | null> {
    const result = await this.db.query(
      `SELECT id FROM sources WHERE namespace = $1 AND idempotency_key = $2`,
      [namespace, idempotencyKey],
    );
    if (result.rows.length !== 1) return null;
    return this.getRedacted(String(result.rows[0].id));
  }

  /** HTTP-safe source projection: lifecycle/status with configuration redacted. */
  async getRedacted(id: string): Promise<SourceRow | null> {
    const res = await this.db.query(
      `SELECT id, namespace, kind, created_at, last_sync, sync_status,
              last_sync_error, last_sync_started_at, lifecycle_state,
              sync_interval_seconds, next_sync_at, consecutive_failures,
              config_state, credential_id, primary_business_function, description,
              data_sensitive
         FROM sources WHERE id = $1`,
      [id],
    );
    if (res.rows.length === 0) return null;
    return this.toRow(res.rows[0] as Record<string, unknown>, false);
  }

  /** Exact-namespace, metadata-only read used after server-side scope resolution. */
  async getMetadata(
    id: string,
    namespace: Namespace,
  ): Promise<SourceMetadataProjection | null> {
    const result = await this.db.query(
      `SELECT id, namespace, primary_business_function, description, data_sensitive
         FROM sources
        WHERE id = $1 AND namespace = $2`,
      [id, namespace],
    );
    if (result.rows.length !== 1) return null;
    return toSourceMetadataProjection(result.rows[0] as Record<string, unknown>);
  }

  /**
   * Update descriptive source metadata in the caller's server-resolved exact
   * namespace. Sensitivity is monotonic here: a descriptive `false` cannot
   * lower a prior conservative `true` classification floor (KR8).
   */
  async updateMetadata(
    id: string,
    namespace: Namespace,
    input: SourceMetadataUpdate,
  ): Promise<SourceMetadataProjection | null> {
    const metadata = normalizeSourceMetadata(input);
    const result = await this.db.query(
      `UPDATE sources
          SET primary_business_function = $3,
              description = $4,
              data_sensitive = data_sensitive OR $5
        WHERE id = $1 AND namespace = $2
        RETURNING id, namespace, primary_business_function, description, data_sensitive`,
      [
        id,
        namespace,
        metadata.primaryBusinessFunction,
        metadata.description,
        metadata.dataSensitive,
      ],
    );
    if (result.rows.length !== 1) return null;
    return toSourceMetadataProjection(result.rows[0] as Record<string, unknown>);
  }

  /** All sources manageable in a namespace subtree. */
  async list(namespace: Namespace, global = false): Promise<SourceRow[]> {
    if (global) {
      const res = await this.db.query(
        `SELECT id, namespace, kind, created_at, last_sync, sync_status,
                last_sync_error, last_sync_started_at, lifecycle_state,
                sync_interval_seconds, next_sync_at, consecutive_failures, config_state,
                credential_id, primary_business_function, description, data_sensitive
         FROM sources ORDER BY created_at ASC, id ASC`,
      );
      return (res.rows as Record<string, unknown>[]).map((r) => this.toRow(r, false));
    }
    if (namespace.length === 0) return [];
    const res = await this.db.query(
      `SELECT id, namespace, kind, created_at, last_sync, sync_status,
              last_sync_error, last_sync_started_at, lifecycle_state,
              sync_interval_seconds, next_sync_at, consecutive_failures, config_state,
              credential_id, primary_business_function, description, data_sensitive
       FROM sources
       WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
       ORDER BY created_at ASC, id ASC`,
      [namespace, escapeLikePattern(namespace) + "/%"],
    );
    return (res.rows as Record<string, unknown>[]).map((r) => this.toRow(r, false));
  }

  /** Exact namespace allowlist for read projections that must not scan subtrees. */
  async listExact(namespaces: readonly Namespace[]): Promise<SourceRow[]> {
    const unique = [...new Set(namespaces)];
    if (unique.length === 0) return [];
    const placeholders = unique.map((_, index) => `$${index + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT id, namespace, kind, created_at, last_sync, sync_status,
              last_sync_error, last_sync_started_at, lifecycle_state,
              sync_interval_seconds, next_sync_at, consecutive_failures, config_state,
              credential_id, primary_business_function, description, data_sensitive
         FROM sources
        WHERE namespace IN (${placeholders})
        ORDER BY created_at ASC, id ASC`,
      unique,
    );
    return (res.rows as Record<string, unknown>[]).map((row) => this.toRow(row, false));
  }

  /** Stamp last_sync = now for a source after an import/sync pass. */
  async touchLastSync(id: string, syncedAt: string): Promise<void> {
    await this.db.query(
      `UPDATE sources SET last_sync = $2, sync_status = 'synced',
              last_sync_error = NULL, consecutive_failures = 0,
              next_sync_at = CASE WHEN sync_interval_seconds IS NULL THEN NULL
                ELSE $2::timestamptz + sync_interval_seconds * INTERVAL '1 second' END
        WHERE id = $1`,
      [id, syncedAt],
    );
  }

  async markSyncPending(id: string, startedAt: string): Promise<void> {
    await this.db.query(
      `UPDATE sources SET sync_status = 'pending', last_sync_error = NULL,
              last_sync_started_at = $2 WHERE id = $1`,
      [id, startedAt],
    );
  }

  async markSyncFailed(id: string, error: string): Promise<void> {
    await this.db.query(
      `UPDATE sources SET sync_status = 'failed', last_sync_error = $2,
              consecutive_failures = consecutive_failures + 1,
              next_sync_at = CURRENT_TIMESTAMP +
                LEAST(POWER(2, LEAST(consecutive_failures, 6)) * 60, 3600) * INTERVAL '1 second'
        WHERE id = $1`,
      [id, redactSourceError(error)],
    );
  }

  async pause(id: string): Promise<void> {
    await this.db.query(
      `UPDATE sources SET lifecycle_state = 'paused', next_sync_at = NULL WHERE id = $1`,
      [id],
    );
  }

  async resume(id: string): Promise<void> {
    await this.db.query(
      `UPDATE sources SET lifecycle_state = 'active', next_sync_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND lifecycle_state <> 'disabled'`,
      [id],
    );
  }

  async setSchedule(id: string, intervalSeconds: number | null): Promise<void> {
    if (intervalSeconds !== null && (!Number.isSafeInteger(intervalSeconds) || intervalSeconds < 60)) {
      throw new RangeError("connector sync interval must be null or at least 60 seconds");
    }
    await this.db.query(
      `UPDATE sources SET sync_interval_seconds = $2,
        next_sync_at = CASE WHEN $2::integer IS NULL THEN NULL ELSE CURRENT_TIMESTAMP END
       WHERE id = $1`,
      [id, intervalSeconds],
    );
  }

  /**
   * Merge a patch into a source's sealed config and re-encrypt it in place.
   * Used by the OAuth token broker to persist rotated provider tokens; never
   * exposed to callers (config values still never leave the kernel).
   */
  async patchConfig(id: string, patch: Record<string, unknown>): Promise<void> {
    const source = await this.get(id);
    if (!source) throw new Error(`no source with id '${id}'`);
    if (source.configState !== "encrypted") {
      throw new Error("source configuration is unavailable");
    }
    const merged = { ...source.config, ...patch };
    const sealed = this.sealForStorage(id, source.namespace, source.kind, merged);
    await this.db.query(
      `UPDATE sources
          SET config_ciphertext = $2, config_iv = $3, config_tag = $4,
              config_kek_id = $5, config_sha256 = $6, config_state = 'encrypted'
        WHERE id = $1`,
      [id, sealed.ciphertext, sealed.iv, sealed.tag, sealed.kekId, sealed.sha256],
    );
  }

  /**
   * Serialize a read/refresh/write cycle for sealed source configuration.
   * Holding the source row lock across the bounded provider refresh prevents
   * two replicas from spending the same rotating refresh token concurrently.
   */
  async mutateConfigLocked<T>(
    id: string,
    mutate: (source: {
      namespace: Namespace;
      config: Record<string, unknown>;
    }) => Promise<{
      value: T;
      patch?: Record<string, unknown>;
      auditEvent?: AuditEvent;
    }>,
  ): Promise<T> {
    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `SELECT id, namespace, kind, config_ciphertext, config_iv, config_tag,
                config_kek_id, config_sha256, config_state
           FROM sources WHERE id = $1 FOR UPDATE`,
        [id],
      );
      if (result.rows.length !== 1) throw new Error(`no source with id '${id}'`);
      const row = result.rows[0] as Record<string, unknown>;
      if (row.config_state !== "encrypted") {
        throw new Error("source configuration is unavailable");
      }
      const namespace = row.namespace as Namespace;
      const kind = row.kind as SourceKind;
      const config = this.configCipher.open({
        id,
        namespace,
        kind,
        config_ciphertext: row.config_ciphertext,
        config_iv: row.config_iv,
        config_tag: row.config_tag,
        config_kek_id: row.config_kek_id,
        config_sha256: row.config_sha256,
      });
      const outcome = await mutate({ namespace, config });
      if (outcome.patch) {
        const sealed = this.sealForStorage(id, namespace, kind, {
          ...config,
          ...outcome.patch,
        });
        await tx.query(
          `UPDATE sources
              SET config_ciphertext = $2, config_iv = $3, config_tag = $4,
                  config_kek_id = $5, config_sha256 = $6, config_state = 'encrypted'
            WHERE id = $1`,
          [id, sealed.ciphertext, sealed.iv, sealed.tag, sealed.kekId, sealed.sha256],
        );
      }
      if (outcome.auditEvent) {
        if (!this.appendAudit) throw new Error("source configuration audit is unavailable");
        await this.appendAudit(tx, outcome.auditEvent);
      }
      return outcome.value;
    });
  }

  async loadCursor(id: string): Promise<string | null> {
    const result = await this.db.query(
      `SELECT cursor_value FROM connector_cursors WHERE source_id = $1`, [id],
    );
    return result.rows.length === 0 ? null : String(result.rows[0].cursor_value);
  }

  async saveCursor(
    id: string,
    cursor: string,
    expectedCursor: string | null,
  ): Promise<boolean> {
    const result = await this.db.query(
      `INSERT INTO connector_cursors (source_id, cursor_value, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (source_id) DO UPDATE SET cursor_value = EXCLUDED.cursor_value,
         updated_at = EXCLUDED.updated_at
       WHERE connector_cursors.cursor_value = $4
       RETURNING source_id`,
      [id, cursor, new Date().toISOString(), expectedCursor],
    );
    return result.rows.length === 1;
  }

  private toRow(row: Record<string, unknown>, includeConfig: boolean): SourceRow {
    const state = row.config_state === "encrypted" ? "encrypted" : "quarantined";
    const credentialId = typeof row.credential_id === "string" ? row.credential_id : null;
    const config = includeConfig && state === "encrypted"
      ? {
          ...this.configCipher.open({
          id: row.id as string,
          namespace: row.namespace as Namespace,
          kind: row.kind as SourceKind,
          config_ciphertext: row.config_ciphertext,
          config_iv: row.config_iv,
          config_tag: row.config_tag,
          config_kek_id: row.config_kek_id,
            config_sha256: row.config_sha256,
          }),
          ...(credentialId ? { credentialId } : {}),
        }
      : { ...REDACTED_SOURCE_CONFIG };
    return {
      id: row.id as string,
      namespace: row.namespace as Namespace,
      kind: row.kind as SourceKind,
      config,
      configState: state,
      credentialId,
      primaryBusinessFunction: typeof row.primary_business_function === "string"
        ? row.primary_business_function
        : "General",
      description: typeof row.description === "string" ? row.description : "",
      dataSensitive: row.data_sensitive === true,
      createdAt: toIso(row.created_at),
      lastSync: toIsoOrNull(row.last_sync),
      syncStatus: (row.sync_status ?? "never_synced") as SourceRow["syncStatus"],
      lastSyncError: typeof row.last_sync_error === "string" ? row.last_sync_error : null,
      lastSyncStartedAt: toIsoOrNull(row.last_sync_started_at),
      lifecycleState: (row.lifecycle_state ?? "active") as SourceRow["lifecycleState"],
      syncIntervalSeconds: row.sync_interval_seconds === null || row.sync_interval_seconds === undefined
        ? null : Number(row.sync_interval_seconds),
      nextSyncAt: toIsoOrNull(row.next_sync_at),
      consecutiveFailures: Number(row.consecutive_failures ?? 0),
    };
  }
}

// ---------------------------------------------------------------------------
// SourceCredentialRegistry — namespace-owned, reusable, write-only secrets.
// ---------------------------------------------------------------------------

export class SourceCredentialRegistry {
  constructor(
    private readonly db: Db,
    private readonly configCipher: SourceConfigCipher,
  ) {}

  async create(
    namespace: Namespace,
    input: CreateSourceCredentialInput,
  ): Promise<SourceCredentialSummary> {
    const name = input.name.trim();
    if (!name || name.length > 120) {
      throw new Error("source credential name must contain 1 to 120 characters");
    }
    if (!/^[a-z0-9_]+$/.test(input.connectionKey)) {
      throw new Error("source credential connectionKey is invalid");
    }
    const id = ulid();
    const now = new Date().toISOString();
    const sealed = this.configCipher.seal(id, namespace, input.connectorId, input.config);
    await this.db.query(
      `INSERT INTO source_credentials
       (id, namespace, connector_id, connection_key, name, config,
        config_ciphertext, config_iv, config_tag, config_kek_id, config_sha256,
        config_state, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6, $7, $8, $9, $10,
               'encrypted', $11, $11)`,
      [
        id,
        namespace,
        input.connectorId,
        input.connectionKey,
        name,
        sealed.ciphertext,
        sealed.iv,
        sealed.tag,
        sealed.kekId,
        sealed.sha256,
        now,
      ],
    );
    return {
      id,
      namespace,
      connectorId: input.connectorId,
      connectionKey: input.connectionKey,
      name,
      createdAt: now,
      updatedAt: now,
    };
  }

  /** Create or reuse one credential for an opaque, server-derived provider reference. */
  async createManaged(
    namespace: Namespace,
    input: CreateSourceCredentialInput,
    externalRefSha256: string,
  ): Promise<SourceCredentialSummary> {
    if (!/^[0-9a-f]{64}$/.test(externalRefSha256)) {
      throw new Error("managed source credential reference is invalid");
    }
    const name = input.name.trim();
    if (!name || name.length > 120) {
      throw new Error("source credential name must contain 1 to 120 characters");
    }
    if (!/^[a-z0-9_]+$/.test(input.connectionKey)) {
      throw new Error("source credential connectionKey is invalid");
    }
    const id = ulid();
    const now = new Date().toISOString();
    const sealed = this.configCipher.seal(id, namespace, input.connectorId, input.config);
    return this.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO source_credentials
         (id, namespace, connector_id, connection_key, name, config,
          config_ciphertext, config_iv, config_tag, config_kek_id, config_sha256,
          config_state, external_ref_sha256, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6, $7, $8, $9, $10,
                 'encrypted', $11, $12, $12)
         ON CONFLICT (external_ref_sha256) WHERE external_ref_sha256 IS NOT NULL DO NOTHING`,
        [
          id,
          namespace,
          input.connectorId,
          input.connectionKey,
          name,
          sealed.ciphertext,
          sealed.iv,
          sealed.tag,
          sealed.kekId,
          sealed.sha256,
          externalRefSha256,
          now,
        ],
      );
      const result = await tx.query(
        `SELECT id, namespace, connector_id, connection_key, name, created_at, updated_at
           FROM source_credentials WHERE external_ref_sha256 = $1`,
        [externalRefSha256],
      );
      if (result.rows.length !== 1) throw new Error("managed source credential was not persisted");
      const summary = this.toSummary(result.rows[0] as Record<string, unknown>);
      if (summary.namespace !== namespace) {
        throw new Error("managed provider connection is already assigned to another namespace");
      }
      return summary;
    });
  }

  async get(id: string): Promise<SourceCredentialRecord | null> {
    const result = await this.db.query(
      `SELECT id, namespace, connector_id, connection_key, name,
              config_ciphertext, config_iv, config_tag, config_kek_id,
              config_sha256, config_state, created_at, updated_at
         FROM source_credentials WHERE id = $1`,
      [id],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0] as Record<string, unknown>;
    if (row.config_state !== "encrypted") {
      throw new Error("source credential configuration is unavailable");
    }
    const summary = this.toSummary(row);
    const config = this.configCipher.open({
      id: summary.id,
      namespace: summary.namespace,
      kind: summary.connectorId,
      config_ciphertext: row.config_ciphertext,
      config_iv: row.config_iv,
      config_tag: row.config_tag,
      config_kek_id: row.config_kek_id,
      config_sha256: row.config_sha256,
    });
    return { ...summary, config };
  }

  async list(namespace: Namespace): Promise<SourceCredentialSummary[]> {
    const result = await this.db.query(
      `SELECT id, namespace, connector_id, connection_key, name,
              created_at, updated_at
         FROM source_credentials
        WHERE namespace = $1
        ORDER BY created_at ASC, id ASC`,
      [namespace],
    );
    return (result.rows as Record<string, unknown>[]).map((row) => this.toSummary(row));
  }

  private toSummary(row: Record<string, unknown>): SourceCredentialSummary {
    return {
      id: String(row.id),
      namespace: String(row.namespace),
      connectorId: String(row.connector_id) as SourceCredentialSummary["connectorId"],
      connectionKey: String(row.connection_key),
      name: String(row.name),
      createdAt: toIso(row.created_at),
      updatedAt: toIso(row.updated_at),
    };
  }
}

function parseConfig(value: unknown): Record<string, unknown> {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  return value as Record<string, unknown>;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  throw new Error(`expected timestamp, got ${typeof value}`);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}
