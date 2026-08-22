/**
 * Append-only persistence for evidence-backed L2 entity relationships.
 *
 * This store does not resolve identity or run an LLM. Its caller supplies a
 * server-resolved landing namespace/actor and an already accepted classifier
 * result. Authority is re-established from the database inside the mutation
 * transaction: entities and memories must be current in the exact landing
 * namespace, and source coordinates are copied only from current provenance.
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import type {
  EntityRelationshipEvidence,
  EntityRelationshipListQuery,
  EntityRelationshipListResult,
  EntityRelationshipType,
  L2EntityRelationship,
} from "../types.js";
import type { RelationshipClassificationResult } from "./classifier.js";

const RELATIONSHIP_TYPES = new Set<string>([
  "same_as",
  "part_of",
  "contains",
  "uses",
  "depends_on",
  "owned_by",
  "served_by",
  "related_to",
]);
const SYMMETRIC_TYPES = new Set<EntityRelationshipType>(["same_as", "related_to"]);
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const MAX_LIST_LIMIT = 100;
const MAX_EVIDENCE_MEMORIES = 32;
const MAX_VISIBLE_NAMESPACES = 513;

export type AcceptedRelationshipClassification = Extract<
  RelationshipClassificationResult,
  { status: "accepted" }
>;

export interface RelationshipCommitContext {
  namespace: string;
  actor: string;
}

export interface RelationshipCommitResult {
  relationship: L2EntityRelationship;
  deduplicated: boolean;
  supersededId?: string;
}

export type RelationshipStoreErrorCode =
  | "invalid_context"
  | "invalid_classification"
  | "invalid_event_time"
  | "entity_unavailable"
  | "evidence_unavailable"
  | "evidence_provenance_invalid"
  | "storage_unavailable";

/** Stable error surface lets an enrichment worker brown out without guessing. */
export class RelationshipStoreError extends Error {
  readonly name = "RelationshipStoreError";
  readonly cause?: unknown;

  constructor(
    readonly code: RelationshipStoreErrorCode,
    message: string,
    readonly retryable: boolean,
    cause?: unknown,
  ) {
    super(message);
    this.cause = cause;
  }
}

export interface RelationshipStoreOptions {
  now?: () => Date;
  makeId?: () => string;
}

interface EvidenceRow extends EntityRelationshipEvidence {
  companyFileId: string | null;
  entityMentionId: string | null;
}

function fail(
  code: RelationshipStoreErrorCode,
  message: string,
  retryable = false,
): never {
  throw new RelationshipStoreError(code, message, retryable);
}

function isBounded(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function evidenceFromJson(value: unknown): EntityRelationshipEvidence[] {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed)) return [];
  const evidence: EntityRelationshipEvidence[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    if (!isBounded(row.memoryId, 128)) continue;
    evidence.push({
      memoryId: row.memoryId,
      ...(isBounded(row.sourceId, 128) ? { sourceId: row.sourceId } : {}),
      ...(isBounded(row.documentKey, 512) ? { documentKey: row.documentKey } : {}),
      ...(typeof row.contentHash === "string" && HASH_PATTERN.test(row.contentHash)
        ? { contentHash: row.contentHash }
        : {}),
    });
  }
  return evidence;
}

function asIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
}

function rowToRelationship(row: Record<string, unknown>): L2EntityRelationship {
  return {
    id: String(row.id),
    namespace: String(row.namespace),
    subjectEntityId: String(row.subject_entity_id),
    relationship: String(row.relationship) as EntityRelationshipType,
    objectEntityId: String(row.object_entity_id),
    confidence: Number(row.confidence),
    evidence: evidenceFromJson(row.evidence),
    assertionTime: asIso(row.assertion_time),
    eventTime: row.event_time === null || row.event_time === undefined
      ? null
      : asIso(row.event_time),
    tValidFrom: asIso(row.t_valid_from),
    tValidTo: row.t_valid_to === null || row.t_valid_to === undefined
      ? null
      : asIso(row.t_valid_to),
    supersedes: row.supersedes === null || row.supersedes === undefined
      ? null
      : String(row.supersedes),
    status: String(row.status) as L2EntityRelationship["status"],
    createdBy: String(row.created_by),
  };
}

function equalIds(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function canonicalize(
  classification: AcceptedRelationshipClassification,
): AcceptedRelationshipClassification {
  if (
    SYMMETRIC_TYPES.has(classification.relationship) &&
    classification.objectEntityId < classification.subjectEntityId
  ) {
    return {
      ...classification,
      subjectEntityId: classification.objectEntityId,
      objectEntityId: classification.subjectEntityId,
    };
  }
  return classification;
}

export class RelationshipStore {
  private readonly now: () => Date;
  private readonly makeId: () => string;

  constructor(
    private readonly db: Db,
    options: RelationshipStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.makeId = options.makeId ?? (() => ulid());
  }

  async commit(
    context: RelationshipCommitContext,
    accepted: AcceptedRelationshipClassification,
    eventTime?: string,
  ): Promise<RelationshipCommitResult> {
    this.validateContext(context);
    this.validateClassification(accepted);
    const classification = canonicalize(accepted);
    const assertionTime = this.now().toISOString();
    const normalizedEventTime = this.validateEventTime(eventTime, assertionTime);
    const evidenceIds = [...new Set(classification.evidenceMemoryIds)].sort();

    try {
      return await this.db.transaction(async (tx) => {
        await this.lockEntities(tx, context.namespace, classification);
        const evidence = await this.lockAndResolveEvidence(
          tx,
          context.namespace,
          evidenceIds,
          assertionTime,
        );
        const current = await this.currentEdge(tx, context.namespace, classification);

        if (current) {
          const currentEvidence = await tx.query(
            `SELECT memory_id
               FROM entity_relationship_evidence
              WHERE relationship_id = $1
              ORDER BY memory_id`,
            [current.id],
          );
          const currentIds = currentEvidence.rows.map((row) => String(row.memory_id));
          if (equalIds(currentIds, evidenceIds)) {
            return { relationship: rowToRelationship(current), deduplicated: true };
          }
          await tx.query(
            `UPDATE entity_relationships
                SET status = 'archived', t_valid_to = $1
              WHERE id = $2 AND status = 'active' AND t_valid_to IS NULL`,
            [assertionTime, current.id],
          );
        }

        const relationshipId = this.makeId();
        const relationship: L2EntityRelationship = {
          id: relationshipId,
          namespace: context.namespace,
          subjectEntityId: classification.subjectEntityId,
          relationship: classification.relationship,
          objectEntityId: classification.objectEntityId,
          confidence: classification.confidence,
          evidence: evidence.map(({ memoryId, sourceId, documentKey, contentHash }) => ({
            memoryId,
            ...(sourceId ? { sourceId } : {}),
            ...(documentKey ? { documentKey } : {}),
            ...(contentHash ? { contentHash } : {}),
          })),
          assertionTime,
          eventTime: normalizedEventTime,
          tValidFrom: assertionTime,
          tValidTo: null,
          supersedes: current ? String(current.id) : null,
          status: "active",
          createdBy: context.actor,
        };

        await tx.query(
          `INSERT INTO entity_relationships
             (id, namespace, subject_entity_id, relationship, object_entity_id,
              confidence, evidence, assertion_time, event_time, t_valid_from,
              t_valid_to, supersedes, status, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $8,
                   NULL, $10, 'active', $11, $8)`,
          [
            relationship.id,
            relationship.namespace,
            relationship.subjectEntityId,
            relationship.relationship,
            relationship.objectEntityId,
            relationship.confidence,
            JSON.stringify(relationship.evidence),
            assertionTime,
            normalizedEventTime,
            relationship.supersedes,
            relationship.createdBy,
          ],
        );

        for (const item of evidence) {
          await tx.query(
            `INSERT INTO entity_relationship_evidence
               (id, namespace, relationship_id, memory_id, source_id,
                company_file_id, entity_mention_id, document_key, content_hash,
                evidence_role, confidence, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                     'supporting', $10, $11, $12)`,
            [
              this.makeId(),
              context.namespace,
              relationship.id,
              item.memoryId,
              item.sourceId ?? null,
              item.companyFileId,
              item.entityMentionId,
              item.documentKey ?? null,
              item.contentHash ?? null,
              relationship.confidence,
              context.actor,
              assertionTime,
            ],
          );
        }

        return {
          relationship,
          deduplicated: false,
          ...(current ? { supersededId: String(current.id) } : {}),
        };
      });
    } catch (error) {
      if (error instanceof RelationshipStoreError) throw error;
      throw new RelationshipStoreError(
        "storage_unavailable",
        "relationship enrichment storage is unavailable",
        true,
        error,
      );
    }
  }

  /** Query only the exact namespace list already resolved by the kernel. */
  async list(
    visibleNamespaces: readonly string[],
    query: EntityRelationshipListQuery,
  ): Promise<EntityRelationshipListResult> {
    const namespaces = [...new Set(visibleNamespaces)];
    if (
      namespaces.length > MAX_VISIBLE_NAMESPACES ||
      namespaces.some((namespace) => !isBounded(namespace, 512))
    ) {
      fail("invalid_context", "visible namespaces are invalid");
    }
    if (namespaces.length === 0) return { data: [] };
    if (!isBounded(query.entityId, 128)) {
      fail("invalid_classification", "relationship entity id is invalid");
    }
    if (query.relationship !== undefined && !RELATIONSHIP_TYPES.has(query.relationship)) {
      fail("invalid_classification", "relationship ontology value is invalid");
    }
    const direction = query.direction ?? "both";
    if (direction !== "outgoing" && direction !== "incoming" && direction !== "both") {
      fail("invalid_classification", "relationship direction is invalid");
    }
    const limit = query.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIST_LIMIT) {
      fail("invalid_classification", "relationship list limit is invalid");
    }

    const params: unknown[] = [...namespaces, query.entityId];
    const namespaceSql = namespaces.map((_, index) => `$${index + 1}`).join(", ");
    const entityParam = namespaces.length + 1;
    const entityClause = direction === "outgoing"
      ? `(subject_entity_id = $${entityParam} OR
          (relationship IN ('same_as','related_to') AND object_entity_id = $${entityParam}))`
      : direction === "incoming"
        ? `(object_entity_id = $${entityParam} OR
            (relationship IN ('same_as','related_to') AND subject_entity_id = $${entityParam}))`
        : `(subject_entity_id = $${entityParam} OR object_entity_id = $${entityParam})`;
    const clauses = [
      `namespace IN (${namespaceSql})`,
      entityClause,
    ];
    if (!query.includeArchived) clauses.push(`status = 'active'`, `t_valid_to IS NULL`);
    if (query.relationship !== undefined) {
      params.push(query.relationship);
      clauses.push(`relationship = $${params.length}`);
    }
    params.push(limit);
    const result = await this.db.query(
      `SELECT * FROM entity_relationships
        WHERE ${clauses.join(" AND ")}
        ORDER BY assertion_time DESC, id DESC
        LIMIT $${params.length}`,
      params,
    );

    const data: L2EntityRelationship[] = [];
    for (const raw of result.rows as Record<string, unknown>[]) {
      let relationship = rowToRelationship(raw);
      const symmetric = SYMMETRIC_TYPES.has(relationship.relationship);
      if (!symmetric) {
        if (direction === "outgoing" && relationship.subjectEntityId !== query.entityId) continue;
        if (direction === "incoming" && relationship.objectEntityId !== query.entityId) continue;
      } else {
        const shouldBeSubject = direction !== "incoming";
        const queryIsSubject = relationship.subjectEntityId === query.entityId;
        if (shouldBeSubject !== queryIsSubject) {
          relationship = {
            ...relationship,
            subjectEntityId: relationship.objectEntityId,
            objectEntityId: relationship.subjectEntityId,
          };
        }
      }
      data.push(relationship);
    }
    return { data };
  }

  private validateContext(context: RelationshipCommitContext): void {
    if (!isBounded(context.namespace, 512) || !isBounded(context.actor, 512)) {
      fail("invalid_context", "relationship write context is invalid");
    }
  }

  private validateClassification(accepted: AcceptedRelationshipClassification): void {
    if (
      !accepted ||
      accepted.status !== "accepted" ||
      !isBounded(accepted.subjectEntityId, 128) ||
      !isBounded(accepted.objectEntityId, 128) ||
      !RELATIONSHIP_TYPES.has(accepted.relationship) ||
      !Number.isFinite(accepted.confidence) ||
      accepted.confidence < 0 ||
      accepted.confidence > 1 ||
      !Array.isArray(accepted.evidenceMemoryIds) ||
      accepted.evidenceMemoryIds.length === 0 ||
      accepted.evidenceMemoryIds.length > MAX_EVIDENCE_MEMORIES ||
      accepted.evidenceMemoryIds.some((id) => !isBounded(id, 128)) ||
      (accepted.subjectEntityId === accepted.objectEntityId && accepted.relationship !== "same_as")
    ) {
      fail("invalid_classification", "accepted relationship classification is invalid");
    }
  }

  private validateEventTime(eventTime: string | undefined, assertionTime: string): string | null {
    if (eventTime === undefined) return null;
    const parsed = new Date(eventTime);
    if (
      !Number.isFinite(parsed.getTime()) ||
      parsed.toISOString() !== eventTime ||
      parsed.getTime() > new Date(assertionTime).getTime()
    ) {
      fail("invalid_event_time", "relationship event time is invalid");
    }
    return eventTime;
  }

  private async lockEntities(
    tx: Db,
    namespace: string,
    classification: AcceptedRelationshipClassification,
  ): Promise<void> {
    const ids = [...new Set([
      classification.subjectEntityId,
      classification.objectEntityId,
    ])].sort();
    const placeholders = ids.map((_, index) => `$${index + 2}`).join(", ");
    const result = await tx.query(
      `SELECT id FROM entity_registry
        WHERE namespace = $1 AND id IN (${placeholders})
        ORDER BY id
        FOR UPDATE`,
      [namespace, ...ids],
    );
    if (result.rows.length !== ids.length) {
      fail("entity_unavailable", "relationship entity is unavailable in the landing namespace");
    }
  }

  private async lockAndResolveEvidence(
    tx: Db,
    namespace: string,
    evidenceIds: string[],
    assertionTime: string,
  ): Promise<EvidenceRow[]> {
    const placeholders = evidenceIds.map((_, index) => `$${index + 3}`).join(", ");
    const result = await tx.query(
      `SELECT id, provenance
         FROM memory_objects
        WHERE namespace = $1
          AND tier = 'L2'
          AND status = 'active'
          AND t_valid_to IS NULL
          AND (ttl_seconds IS NULL OR
               assertion_time + ttl_seconds * INTERVAL '1 second' > $2)
          AND id IN (${placeholders})
        ORDER BY id
        FOR UPDATE`,
      [namespace, assertionTime, ...evidenceIds],
    );
    if (result.rows.length !== evidenceIds.length) {
      fail("evidence_unavailable", "relationship evidence is not a current exact-namespace L2 memory");
    }

    const resolved: EvidenceRow[] = [];
    for (const row of result.rows as Record<string, unknown>[]) {
      resolved.push(await this.resolveProvenance(tx, namespace, String(row.id), row.provenance));
    }
    resolved.sort((left, right) => left.memoryId.localeCompare(right.memoryId));
    return resolved;
  }

  private async resolveProvenance(
    tx: Db,
    namespace: string,
    memoryId: string,
    raw: unknown,
  ): Promise<EvidenceRow> {
    const parsed = parseJson(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      fail("evidence_provenance_invalid", "relationship evidence has no governed provenance");
    }

    const sourceCoordinates: Array<{
      sourceId: string;
      documentKey: string;
      contentHash: string;
    }> = [];
    let hasGovernedEntry = false;
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue;
      const entry = item as Record<string, unknown>;
      if (isBounded(entry.source, 120) && isBounded(entry.actor, 512) && isBounded(entry.ts, 64)) {
        hasGovernedEntry = true;
      }
      const supplied = [entry.sourceId, entry.documentKey, entry.contentHash]
        .filter((value) => value !== undefined).length;
      if (supplied === 0) continue;
      if (
        supplied !== 3 ||
        !isBounded(entry.sourceId, 128) ||
        !isBounded(entry.documentKey, 512) ||
        typeof entry.contentHash !== "string" ||
        !HASH_PATTERN.test(entry.contentHash)
      ) {
        fail("evidence_provenance_invalid", "relationship evidence source provenance is incomplete");
      }
      sourceCoordinates.push({
        sourceId: entry.sourceId,
        documentKey: entry.documentKey,
        contentHash: entry.contentHash,
      });
    }
    if (!hasGovernedEntry) {
      fail("evidence_provenance_invalid", "relationship evidence provenance is malformed");
    }
    if (sourceCoordinates.length === 0) {
      return { memoryId, ...await this.resolveMention(tx, namespace, memoryId) };
    }

    sourceCoordinates.sort((left, right) =>
      `${left.sourceId}\u0000${left.documentKey}\u0000${left.contentHash}`.localeCompare(
        `${right.sourceId}\u0000${right.documentKey}\u0000${right.contentHash}`,
      )
    );
    for (const coordinates of sourceCoordinates) {
      const current = await tx.query(
        `SELECT source.id
           FROM sources AS source
           JOIN source_documents AS document ON document.source_id = source.id
          WHERE source.id = $1
            AND source.lifecycle_state = 'active'
            AND document.landing_namespace = $2
            AND document.document_key = $3
            AND document.content_hash = $4`,
        [
          coordinates.sourceId,
          namespace,
          coordinates.documentKey,
          coordinates.contentHash,
        ],
      );
      if (current.rows.length > 0) {
        return {
          memoryId,
          ...coordinates,
          ...await this.resolveMention(tx, namespace, memoryId),
        };
      }
    }
    fail("evidence_provenance_invalid", "relationship evidence source version is not current");
  }

  private async resolveMention(
    tx: Db,
    namespace: string,
    memoryId: string,
  ): Promise<Pick<EvidenceRow, "companyFileId" | "entityMentionId">> {
    const result = await tx.query(
      `SELECT mention.id AS mention_id, mention.company_file_id
         FROM entity_mentions mention
        WHERE mention.namespace = $1
          AND mention.memory_id = $2
          AND mention.t_valid_to IS NULL
        ORDER BY mention.id
        LIMIT 1`,
      [namespace, memoryId],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return {
      companyFileId: row && typeof row.company_file_id === "string"
        ? row.company_file_id
        : null,
      entityMentionId: row && typeof row.mention_id === "string"
        ? row.mention_id
        : null,
    };
  }

  private async currentEdge(
    tx: Db,
    namespace: string,
    classification: AcceptedRelationshipClassification,
  ): Promise<Record<string, unknown> | null> {
    const result = await tx.query(
      `SELECT * FROM entity_relationships
        WHERE namespace = $1
          AND subject_entity_id = $2
          AND relationship = $3
          AND object_entity_id = $4
          AND status = 'active'
          AND t_valid_to IS NULL
        FOR UPDATE`,
      [
        namespace,
        classification.subjectEntityId,
        classification.relationship,
        classification.objectEntityId,
      ],
    );
    return result.rows.length > 0 ? result.rows[0] as Record<string, unknown> : null;
  }
}
