/**
 * Optional, bounded relationship enrichment after governed fact persistence.
 *
 * The fact write is already committed before this orchestrator runs. Every
 * enrichment failure is therefore returned as content-free metadata rather
 * than thrown: candidates may remain pending while the canonical memory stays
 * available. This module never reads or writes memory tables directly.
 */

import type { LlmClient } from "../types.js";
import {
  generateRelationshipCandidates,
  type RelationshipCandidate,
  type RelationshipCandidateEntity,
  type RelationshipCandidateOptions,
} from "./candidates.js";
import {
  classifyRelationship,
  RELATIONSHIP_TYPES,
  type RelationshipClassificationResult,
} from "./classifier.js";
import {
  RelationshipStoreError,
  type AcceptedRelationshipClassification,
  type RelationshipCommitContext,
  type RelationshipCommitResult,
  type RelationshipStoreErrorCode,
} from "./store.js";

export const RELATIONSHIP_PIPELINE_LIMITS = Object.freeze({
  maxEntities: 256,
  maxImpactedMemoryIds: 512,
  maxCandidates: 128,
});

const MAX_EVIDENCE_PER_ENTITY = 64;
const MAX_EVIDENCE_PER_CANDIDATE = 16;
const MAX_ENTITY_VALUES = 64;
const MAX_EMBEDDING_DIMENSIONS = 4_096;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REJECTION_CODES = new Set<RelationshipPipelineOutcomeCode>([
  "model_rejected",
  "low_confidence",
  "insufficient_identity_evidence",
  "invalid_candidate",
]);
const PENDING_CODES = new Set<RelationshipPipelineOutcomeCode>([
  "llm_unavailable",
  "invalid_model_output",
]);
const ONTOLOGY = new Set<string>(RELATIONSHIP_TYPES);

export interface RelationshipPipelineInput extends RelationshipCommitContext {
  /** Server-resolved ids of facts committed by or impacted by this write. */
  impactedMemoryIds: readonly string[];
  /** Server-resolved entity projections; never model output. */
  entities: readonly RelationshipCandidateEntity[];
  eventTime?: string;
}

export interface RelationshipPipelineOptions {
  maxEntities?: number;
  maxImpactedMemoryIds?: number;
  maxCandidates?: number;
}

export interface RelationshipPipelineStore {
  commit(
    context: RelationshipCommitContext,
    classification: AcceptedRelationshipClassification,
    eventTime?: string,
  ): Promise<RelationshipCommitResult>;
}

export interface RelationshipPipelineDependencies {
  llm: LlmClient;
  store: RelationshipPipelineStore;
  generateCandidates?: (
    entities: readonly RelationshipCandidateEntity[],
    options?: RelationshipCandidateOptions,
  ) => RelationshipCandidate[];
  classify?: (
    candidate: RelationshipCandidate,
    llm: LlmClient,
  ) => Promise<RelationshipClassificationResult>;
}

export type RelationshipPipelineErrorCode =
  | "invalid_input"
  | "candidate_generation_failed";

export type RelationshipPipelineOutcomeCode =
  | "model_rejected"
  | "low_confidence"
  | "insufficient_identity_evidence"
  | "invalid_candidate"
  | "llm_unavailable"
  | "invalid_model_output"
  | "classifier_unavailable"
  | "invalid_classifier_result"
  | "candidate_authority_invalid"
  | "store_unavailable"
  | "store_invalid_result"
  | `store_${RelationshipStoreErrorCode}`;

export type RelationshipPipelineOutcome =
  | {
      candidateId: string;
      status: "committed";
      relationshipId: string;
      deduplicated: boolean;
    }
  | {
      candidateId: string;
      status: "rejected" | "pending";
      code: RelationshipPipelineOutcomeCode;
    };

export interface RelationshipPipelineResult {
  namespace: string;
  status: "complete" | "brownout" | "invalid";
  candidateCount: number;
  attempted: number;
  committed: number;
  deduplicated: number;
  rejected: number;
  pending: number;
  truncated: boolean;
  pipelineError: RelationshipPipelineErrorCode | null;
  outcomes: RelationshipPipelineOutcome[];
}

function boundedLimit(value: number | undefined, fallback: number, hardMax: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value)) return fallback;
  return Math.max(0, Math.min(hardMax, Math.floor(value)));
}

function boundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function boundedStrings(value: readonly string[] | undefined, maxItems: number, maxChars: number): boolean {
  return value === undefined || (
    Array.isArray(value) &&
    value.length <= maxItems &&
    value.every((item) => boundedString(item, maxChars))
  );
}

function safeCandidateId(candidate: RelationshipCandidate, index: number): string {
  return boundedString(candidate.candidateId, 128) && SAFE_ID.test(candidate.candidateId)
    ? candidate.candidateId
    : `candidate_${index + 1}`;
}

function emptyResult(
  namespace: string,
  status: RelationshipPipelineResult["status"],
  pipelineError: RelationshipPipelineErrorCode | null,
): RelationshipPipelineResult {
  return {
    namespace,
    status,
    candidateCount: 0,
    attempted: 0,
    committed: 0,
    deduplicated: 0,
    rejected: 0,
    pending: 0,
    truncated: false,
    pipelineError,
    outcomes: [],
  };
}

function validEntityInput(
  entity: RelationshipCandidateEntity,
  namespace: string,
  impacted: ReadonlySet<string>,
): boolean {
  if (
    !boundedString(entity.entityId, 128) ||
    !SAFE_ID.test(entity.entityId) ||
    entity.namespace !== namespace ||
    !boundedString(entity.canonicalName, 512) ||
    !Array.isArray(entity.evidence) ||
    entity.evidence.length > MAX_EVIDENCE_PER_ENTITY ||
    !boundedStrings(entity.aliases, MAX_ENTITY_VALUES, 512) ||
    !boundedStrings(entity.stableIds, MAX_ENTITY_VALUES, 512) ||
    !boundedStrings(entity.skus, MAX_ENTITY_VALUES, 512) ||
    !boundedStrings(entity.urls, MAX_ENTITY_VALUES, 2_048) ||
    (entity.embedding !== undefined && (
      !Array.isArray(entity.embedding) ||
      entity.embedding.length > MAX_EMBEDDING_DIMENSIONS ||
      !entity.embedding.every(Number.isFinite)
    ))
  ) {
    return false;
  }
  return entity.evidence.every((evidence) =>
    boundedString(evidence.memoryId, 128) &&
    impacted.has(evidence.memoryId) &&
    (evidence.sourceId === undefined || boundedString(evidence.sourceId, 128)) &&
    (evidence.documentKey === undefined || boundedString(evidence.documentKey, 512)) &&
    (evidence.contentHash === undefined || SHA256.test(evidence.contentHash)) &&
    boundedStrings(evidence.recordKeys, MAX_ENTITY_VALUES, 512)
  );
}

function validCandidateAuthority(
  candidate: RelationshipCandidate,
  namespace: string,
  entityIds: ReadonlySet<string>,
  impacted: ReadonlySet<string>,
): boolean {
  return candidate.namespace === namespace &&
    boundedString(candidate.subjectEntityId, 128) &&
    boundedString(candidate.objectEntityId, 128) &&
    entityIds.has(candidate.subjectEntityId) &&
    entityIds.has(candidate.objectEntityId) &&
    candidate.subjectEntityId !== candidate.objectEntityId &&
    Array.isArray(candidate.evidence) &&
    candidate.evidence.length > 0 &&
    candidate.evidence.length <= MAX_EVIDENCE_PER_CANDIDATE &&
    candidate.evidence.every((evidence) =>
      boundedString(evidence.memoryId, 128) && impacted.has(evidence.memoryId)
    );
}

function exactAcceptedResult(
  result: unknown,
  candidate: RelationshipCandidate,
): result is AcceptedRelationshipClassification {
  if (!result || typeof result !== "object") return false;
  const decision = result as Record<string, unknown>;
  if (
    decision.status !== "accepted" ||
    !boundedString(decision.subjectEntityId, 128) ||
    !boundedString(decision.objectEntityId, 128) ||
    typeof decision.relationship !== "string" ||
    !ONTOLOGY.has(decision.relationship) ||
    typeof decision.confidence !== "number" ||
    !Number.isFinite(decision.confidence) ||
    decision.confidence < 0 ||
    decision.confidence > 1 ||
    !Array.isArray(decision.evidenceMemoryIds) ||
    !decision.evidenceMemoryIds.every((memoryId) => boundedString(memoryId, 128))
  ) {
    return false;
  }
  const expectedEvidence = candidate.evidence.map((evidence) => evidence.memoryId);
  return decision.subjectEntityId === candidate.subjectEntityId &&
    decision.objectEntityId === candidate.objectEntityId &&
    decision.evidenceMemoryIds.length === expectedEvidence.length &&
    decision.evidenceMemoryIds.every((memoryId, index) => memoryId === expectedEvidence[index]);
}

function safeStoreCode(error: unknown): RelationshipPipelineOutcomeCode {
  return error instanceof RelationshipStoreError
    ? `store_${error.code}`
    : "store_unavailable";
}

/**
 * Run optional graph enrichment over one already-committed namespace-local
 * impact set. This function intentionally resolves every failure to metadata.
 */
export async function runRelationshipPipeline(
  input: RelationshipPipelineInput,
  dependencies: RelationshipPipelineDependencies,
  options: RelationshipPipelineOptions = {},
): Promise<RelationshipPipelineResult> {
  const namespace = typeof input?.namespace === "string" ? input.namespace : "";
  if (
    !input ||
    !boundedString(input.namespace, 256) ||
    !boundedString(input.actor, 512) ||
    !Array.isArray(input.impactedMemoryIds) ||
    input.impactedMemoryIds.length > RELATIONSHIP_PIPELINE_LIMITS.maxImpactedMemoryIds ||
    !input.impactedMemoryIds.every((id) => boundedString(id, 128) && SAFE_ID.test(id)) ||
    !Array.isArray(input.entities) ||
    input.entities.length > RELATIONSHIP_PIPELINE_LIMITS.maxEntities
  ) {
    return emptyResult(namespace, "invalid", "invalid_input");
  }

  const fullImpacted = new Set(input.impactedMemoryIds);
  if (!input.entities.every((entity) => validEntityInput(entity, input.namespace, fullImpacted))) {
    return emptyResult(input.namespace, "invalid", "invalid_input");
  }

  const maxEntities = boundedLimit(
    options.maxEntities,
    RELATIONSHIP_PIPELINE_LIMITS.maxEntities,
    RELATIONSHIP_PIPELINE_LIMITS.maxEntities,
  );
  const maxImpactedMemoryIds = boundedLimit(
    options.maxImpactedMemoryIds,
    RELATIONSHIP_PIPELINE_LIMITS.maxImpactedMemoryIds,
    RELATIONSHIP_PIPELINE_LIMITS.maxImpactedMemoryIds,
  );
  const maxCandidates = boundedLimit(
    options.maxCandidates,
    RELATIONSHIP_PIPELINE_LIMITS.maxCandidates,
    RELATIONSHIP_PIPELINE_LIMITS.maxCandidates,
  );
  const impactedIds = [...fullImpacted].sort().slice(0, maxImpactedMemoryIds);
  const impacted = new Set(impactedIds);
  const selectedEntities = [...input.entities]
    .sort((left, right) => left.entityId.localeCompare(right.entityId))
    .slice(0, maxEntities)
    .map((entity) => ({
      ...entity,
      evidence: entity.evidence.filter(
        (evidence: RelationshipCandidateEntity["evidence"][number]) =>
          impacted.has(evidence.memoryId),
      ),
    }));
  const entityIds = new Set(selectedEntities.map((entity) => entity.entityId));
  let truncated = input.entities.length > maxEntities ||
    fullImpacted.size > maxImpactedMemoryIds;

  let generated: RelationshipCandidate[];
  try {
    generated = (dependencies.generateCandidates ?? generateRelationshipCandidates)(selectedEntities, {
      maxEntities,
      maxPairs: maxCandidates,
      maxEvidencePerEntity: MAX_EVIDENCE_PER_ENTITY,
      maxEvidencePerCandidate: MAX_EVIDENCE_PER_CANDIDATE,
    });
  } catch {
    return {
      ...emptyResult(input.namespace, "brownout", "candidate_generation_failed"),
      truncated,
    };
  }
  if (!Array.isArray(generated)) {
    return {
      ...emptyResult(input.namespace, "brownout", "candidate_generation_failed"),
      truncated,
    };
  }
  if (generated.length > maxCandidates) truncated = true;
  const candidates = generated.slice(0, maxCandidates);
  const classify = dependencies.classify ?? classifyRelationship;
  const outcomes: RelationshipPipelineOutcome[] = [];
  let committed = 0;
  let deduplicated = 0;
  let rejected = 0;
  let pending = 0;

  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    if (!candidate || typeof candidate !== "object") {
      outcomes.push({
        candidateId: `candidate_${index + 1}`,
        status: "pending",
        code: "candidate_authority_invalid",
      });
      pending += 1;
      continue;
    }
    const candidateId = safeCandidateId(candidate, index);
    if (!validCandidateAuthority(candidate, input.namespace, entityIds, impacted)) {
      outcomes.push({ candidateId, status: "pending", code: "candidate_authority_invalid" });
      pending += 1;
      continue;
    }

    let classification: RelationshipClassificationResult;
    try {
      classification = await classify(candidate, dependencies.llm);
    } catch {
      outcomes.push({ candidateId, status: "pending", code: "classifier_unavailable" });
      pending += 1;
      continue;
    }
    if (!classification || typeof classification !== "object") {
      outcomes.push({ candidateId, status: "pending", code: "invalid_classifier_result" });
      pending += 1;
      continue;
    }
    if (classification.status === "rejected" && REJECTION_CODES.has(classification.reason)) {
      outcomes.push({ candidateId, status: "rejected", code: classification.reason });
      rejected += 1;
      continue;
    }
    if (classification.status === "pending" && PENDING_CODES.has(classification.reason)) {
      outcomes.push({ candidateId, status: "pending", code: classification.reason });
      pending += 1;
      continue;
    }
    if (!exactAcceptedResult(classification, candidate)) {
      outcomes.push({ candidateId, status: "pending", code: "invalid_classifier_result" });
      pending += 1;
      continue;
    }

    try {
      const stored = await dependencies.store.commit(
        { namespace: input.namespace, actor: input.actor },
        classification,
        input.eventTime,
      );
      if (!stored || !boundedString(stored.relationship?.id, 128)) {
        outcomes.push({ candidateId, status: "pending", code: "store_invalid_result" });
        pending += 1;
        continue;
      }
      outcomes.push({
        candidateId,
        status: "committed",
        relationshipId: stored.relationship.id,
        deduplicated: stored.deduplicated,
      });
      committed += 1;
      if (stored.deduplicated) deduplicated += 1;
    } catch (error) {
      outcomes.push({ candidateId, status: "pending", code: safeStoreCode(error) });
      pending += 1;
    }
  }

  return {
    namespace: input.namespace,
    status: pending > 0 ? "brownout" : "complete",
    candidateCount: candidates.length,
    attempted: candidates.length,
    committed,
    deduplicated,
    rejected,
    pending,
    truncated,
    pipelineError: null,
    outcomes,
  };
}
