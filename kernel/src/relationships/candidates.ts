/**
 * Pure, bounded relationship-candidate generation.
 *
 * This module only identifies evidence-backed entity pairs. It deliberately
 * assigns neither an ontology predicate nor authority: subject/object are a
 * stable lexical orientation used to deduplicate an otherwise unordered pair.
 */

import { createHash } from "node:crypto";
import type {
  DataClassification,
  EntityRelationshipEvidence,
  Namespace,
} from "../types.js";

export type RelationshipCandidateSignal =
  | "shared_stable_id"
  | "shared_sku"
  | "shared_public_https_url"
  | "shared_canonical_name"
  | "cross_source_record_overlap"
  | "shared_alias"
  | "embedding_similarity"
  | "entity_cooccurrence";

export interface RelationshipCandidateEvidence extends EntityRelationshipEvidence {
  /** Source-independent stable record coordinates used only for candidate generation. */
  recordKeys?: readonly string[];
}

export interface RelationshipCandidateEntity {
  entityId: string;
  namespace: Namespace;
  canonicalName: string;
  aliases?: readonly string[];
  stableIds?: readonly string[];
  skus?: readonly string[];
  urls?: readonly string[];
  embedding?: readonly number[];
  classification?: DataClassification;
  evidence: readonly RelationshipCandidateEvidence[];
}

export interface RelationshipCandidateClassificationInput {
  entityId: string;
  classification: DataClassification | null;
}

export interface RelationshipCandidate {
  candidateId: string;
  namespace: Namespace;
  /** Lexically first id; this does not imply a directed relationship. */
  subjectEntityId: string;
  subjectEntityName: string;
  /** Lexically second id; this does not imply a directed relationship. */
  objectEntityId: string;
  objectEntityName: string;
  signals: RelationshipCandidateSignal[];
  evidence: EntityRelationshipEvidence[];
  score: number;
  /** Conservative classification projection; never an ACL or write authority. */
  classification: DataClassification | null;
  classificationInputs: RelationshipCandidateClassificationInput[];
}

export interface RelationshipCandidateOptions {
  maxEntities?: number;
  maxPairs?: number;
  maxEvidencePerEntity?: number;
  maxEvidencePerCandidate?: number;
  minEmbeddingSimilarity?: number;
}

export const RELATIONSHIP_CANDIDATE_LIMITS = Object.freeze({
  maxEntities: 256,
  maxPairs: 1_024,
  maxEvidencePerEntity: 64,
  maxEvidencePerCandidate: 16,
});

const SIGNAL_ORDER: readonly RelationshipCandidateSignal[] = [
  "shared_stable_id",
  "shared_sku",
  "shared_public_https_url",
  "shared_canonical_name",
  "cross_source_record_overlap",
  "shared_alias",
  "embedding_similarity",
  "entity_cooccurrence",
];

const SIGNAL_WEIGHT: Readonly<Record<Exclude<RelationshipCandidateSignal, "embedding_similarity">, number>> = {
  shared_stable_id: 0.99,
  shared_sku: 0.97,
  shared_public_https_url: 0.95,
  shared_canonical_name: 0.92,
  cross_source_record_overlap: 0.78,
  shared_alias: 0.7,
  entity_cooccurrence: 0.25,
};

interface NormalizedEvidence extends EntityRelationshipEvidence {
  recordKeys: string[];
}

interface NormalizedEntity {
  entityId: string;
  namespace: Namespace;
  canonicalName: string;
  canonicalKey: string;
  aliases: string[];
  stableIds: string[];
  skus: string[];
  urls: string[];
  embedding: number[] | null;
  classification: DataClassification | null;
  evidence: NormalizedEvidence[];
}

function boundedInteger(value: number | undefined, fallback: number, hardMax: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(0, Math.min(hardMax, Math.floor(value)));
}

function normalizedText(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}

function sortedUnique(values: readonly string[] | undefined): string[] {
  return [...new Set((values ?? []).map(normalizedText).filter(Boolean))].sort();
}

function isPublicIpv4(hostname: string): boolean {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return false;
  const bytes = parts.map(Number);
  if (bytes.some((part) => part < 0 || part > 255)) return false;
  const [a = 0, b = 0] = bytes;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || b === 168)) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
  if (a === 203 && b === 0) return false;
  return true;
}

function isPublicHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal")) return false;

  if (/^\d+(?:\.\d+){3}$/.test(host)) return isPublicIpv4(host);
  if (host.includes(":")) {
    const compact = host.replace(/^0+/, "");
    return compact !== "::" && compact !== "::1" &&
      !/^f[cd]/i.test(compact) && !/^fe[89ab]/i.test(compact) &&
      !/^::ffff:(?:0|10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)/i.test(compact);
  }
  return host.includes(".");
}

function normalizePublicHttpsUrl(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:" || url.username || url.password || !isPublicHostname(url.hostname)) {
      return null;
    }
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

function normalizeClassification(value: DataClassification | undefined): DataClassification | null {
  if (!value) return null;
  return {
    sensitivity: value.sensitivity,
    piiSubjects: sortedUnique(value.piiSubjects),
    secretKinds: sortedUnique(value.secretKinds),
    ...(value.residency ? { residency: value.residency.trim() } : {}),
    allowedDestinations: sortedUnique(value.allowedDestinations),
  };
}

function evidenceKey(evidence: EntityRelationshipEvidence): string {
  return [evidence.memoryId, evidence.sourceId ?? "", evidence.documentKey ?? "", evidence.contentHash ?? ""].join("\u0000");
}

function normalizeEvidence(
  values: readonly RelationshipCandidateEvidence[],
  limit: number,
): NormalizedEvidence[] {
  const deduped = new Map<string, NormalizedEvidence>();
  for (const value of values) {
    const memoryId = value.memoryId.trim();
    if (!memoryId) continue;
    const normalized: NormalizedEvidence = {
      memoryId,
      ...(value.sourceId?.trim() ? { sourceId: value.sourceId.trim() } : {}),
      ...(value.documentKey?.trim() ? { documentKey: value.documentKey.trim() } : {}),
      ...(value.contentHash?.trim() ? { contentHash: value.contentHash.trim().toLowerCase() } : {}),
      recordKeys: sortedUnique(value.recordKeys),
    };
    const key = evidenceKey(normalized);
    const incumbent = deduped.get(key);
    if (incumbent) {
      incumbent.recordKeys = sortedUnique([...incumbent.recordKeys, ...normalized.recordKeys]);
    } else {
      deduped.set(key, normalized);
    }
  }
  return [...deduped.values()]
    .sort((left, right) => evidenceKey(left).localeCompare(evidenceKey(right)))
    .slice(0, limit);
}

function normalizeEntity(value: RelationshipCandidateEntity, evidenceLimit: number): NormalizedEntity | null {
  const entityId = value.entityId.trim();
  const namespace = value.namespace.trim();
  const canonicalName = value.canonicalName.trim();
  if (!entityId || !namespace || !canonicalName) return null;
  const urls = [...new Set((value.urls ?? [])
    .map(normalizePublicHttpsUrl)
    .filter((url): url is string => url !== null))].sort();
  const embedding = value.embedding && value.embedding.length > 0 &&
    value.embedding.every(Number.isFinite)
    ? [...value.embedding]
    : null;
  return {
    entityId,
    namespace,
    canonicalName,
    canonicalKey: normalizedText(canonicalName),
    aliases: sortedUnique(value.aliases),
    stableIds: sortedUnique(value.stableIds),
    skus: sortedUnique(value.skus),
    urls,
    embedding,
    classification: normalizeClassification(value.classification),
    evidence: normalizeEvidence(value.evidence, evidenceLimit),
  };
}

function intersect(left: readonly string[], right: readonly string[]): boolean {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
}

function hasCrossSourceRecordOverlap(left: NormalizedEntity, right: NormalizedEntity): boolean {
  for (const leftEvidence of left.evidence) {
    if (!leftEvidence.sourceId) continue;
    const leftKeys = new Set([
      ...leftEvidence.recordKeys,
      ...(leftEvidence.contentHash ? [`hash:${leftEvidence.contentHash}`] : []),
    ]);
    if (leftKeys.size === 0) continue;
    for (const rightEvidence of right.evidence) {
      if (!rightEvidence.sourceId || rightEvidence.sourceId === leftEvidence.sourceId) continue;
      const rightKeys = [
        ...rightEvidence.recordKeys,
        ...(rightEvidence.contentHash ? [`hash:${rightEvidence.contentHash}`] : []),
      ];
      if (rightKeys.some((key) => leftKeys.has(key))) return true;
    }
  }
  return false;
}

function cosineSimilarity(left: readonly number[], right: readonly number[]): number | null {
  if (left.length === 0 || left.length !== right.length) return null;
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (let index = 0; index < left.length; index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    dot += a * b;
    leftNorm += a * a;
    rightNorm += b * b;
  }
  if (leftNorm === 0 || rightNorm === 0) return null;
  return Math.max(-1, Math.min(1, dot / Math.sqrt(leftNorm * rightNorm)));
}

function combineClassifications(
  values: readonly (DataClassification | null)[],
): DataClassification | null {
  const present = values.filter((value): value is DataClassification => value !== null);
  if (present.length === 0) return null;
  const sensitivityRank = { public: 0, internal: 1, confidential: 2, restricted: 3 } as const;
  const sensitivity = [...present]
    .sort((left, right) => sensitivityRank[right.sensitivity] - sensitivityRank[left.sensitivity])[0]?.sensitivity ?? "restricted";
  const allowed = present.slice(1).reduce(
    (current, classification) => current.filter((destination) => classification.allowedDestinations.includes(destination)),
    [...present[0]!.allowedDestinations],
  );
  const residencies = sortedUnique(present.map((value) => value.residency ?? "").filter(Boolean));
  return {
    sensitivity,
    piiSubjects: sortedUnique(present.flatMap((value) => value.piiSubjects)),
    secretKinds: sortedUnique(present.flatMap((value) => value.secretKinds)),
    ...(residencies.length === 1 ? { residency: residencies[0] } : {}),
    allowedDestinations: sortedUnique(allowed),
  };
}

function publicEvidence(entity: NormalizedEntity): EntityRelationshipEvidence[] {
  return entity.evidence.map(({ recordKeys: _recordKeys, ...evidence }) => evidence);
}

function candidateId(namespace: string, subjectEntityId: string, objectEntityId: string): string {
  const digest = createHash("sha256")
    .update(`${namespace}\u0000${subjectEntityId}\u0000${objectEntityId}`)
    .digest("hex")
    .slice(0, 24);
  return `relcand_${digest}`;
}

function candidateScore(signals: readonly RelationshipCandidateSignal[], embeddingCosine: number | null): number {
  let complement = 1;
  for (const signal of signals) {
    const weight = signal === "embedding_similarity"
      ? Math.min(0.7, 0.55 + Math.max(0, embeddingCosine ?? 0) * 0.15)
      : SIGNAL_WEIGHT[signal];
    complement *= 1 - weight;
  }
  return Math.round((1 - complement) * 1_000_000) / 1_000_000;
}

/**
 * Produce a bounded set of deterministic, evidence-backed unordered pairs.
 * The caller may pass lower limits, but cannot raise the hard safety caps.
 */
export function generateRelationshipCandidates(
  inputs: readonly RelationshipCandidateEntity[],
  options: RelationshipCandidateOptions = {},
): RelationshipCandidate[] {
  const maxEntities = boundedInteger(
    options.maxEntities,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEntities,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEntities,
  );
  const maxPairs = boundedInteger(
    options.maxPairs,
    RELATIONSHIP_CANDIDATE_LIMITS.maxPairs,
    RELATIONSHIP_CANDIDATE_LIMITS.maxPairs,
  );
  const maxEvidencePerEntity = boundedInteger(
    options.maxEvidencePerEntity,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEvidencePerEntity,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEvidencePerEntity,
  );
  const maxEvidencePerCandidate = boundedInteger(
    options.maxEvidencePerCandidate,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEvidencePerCandidate,
    RELATIONSHIP_CANDIDATE_LIMITS.maxEvidencePerCandidate,
  );
  if (maxEntities < 2 || maxPairs === 0 || maxEvidencePerEntity === 0 || maxEvidencePerCandidate === 0) return [];
  const embeddingThreshold = Number.isFinite(options.minEmbeddingSimilarity)
    ? Math.max(-1, Math.min(1, options.minEmbeddingSimilarity!))
    : 0.85;

  // Refuse to scan an unbounded caller collection. The lower caller-selected
  // max is applied after deterministic normalization so small, shuffled inputs
  // produce the same result while the absolute work remains hard-capped.
  const normalized = inputs
    .slice(0, RELATIONSHIP_CANDIDATE_LIMITS.maxEntities)
    .map((input) => normalizeEntity(input, maxEvidencePerEntity))
    .filter((input): input is NormalizedEntity => input !== null)
    .sort((left, right) =>
      left.namespace.localeCompare(right.namespace) ||
      left.entityId.localeCompare(right.entityId) ||
      JSON.stringify(left).localeCompare(JSON.stringify(right)),
    );

  const unique = new Map<string, NormalizedEntity>();
  for (const entity of normalized) {
    const key = `${entity.namespace}\u0000${entity.entityId}`;
    const incumbent = unique.get(key);
    if (incumbent && JSON.stringify(incumbent) !== JSON.stringify(entity)) {
      throw new Error(`conflicting relationship candidate input for entity ${entity.entityId}`);
    }
    unique.set(key, entity);
  }
  const entities = [...unique.values()].slice(0, maxEntities);
  const candidates: RelationshipCandidate[] = [];

  for (let leftIndex = 0; leftIndex < entities.length; leftIndex += 1) {
    const left = entities[leftIndex]!;
    if (left.evidence.length === 0) continue;
    for (let rightIndex = leftIndex + 1; rightIndex < entities.length; rightIndex += 1) {
      const right = entities[rightIndex]!;
      if (left.namespace !== right.namespace || right.evidence.length === 0) continue;

      const embeddingCosine = left.embedding && right.embedding
        ? cosineSimilarity(left.embedding, right.embedding)
        : null;
      const matched = new Set<RelationshipCandidateSignal>();
      if (intersect(left.stableIds, right.stableIds)) matched.add("shared_stable_id");
      if (intersect(left.skus, right.skus)) matched.add("shared_sku");
      if (intersect(left.urls, right.urls)) matched.add("shared_public_https_url");
      if (left.canonicalKey === right.canonicalKey) matched.add("shared_canonical_name");
      if (hasCrossSourceRecordOverlap(left, right)) matched.add("cross_source_record_overlap");
      if (intersect(left.aliases, right.aliases) || left.aliases.includes(right.canonicalKey) ||
          right.aliases.includes(left.canonicalKey)) matched.add("shared_alias");
      if (embeddingCosine !== null && embeddingCosine >= embeddingThreshold) matched.add("embedding_similarity");
      if (intersect(left.evidence.map((value) => value.memoryId), right.evidence.map((value) => value.memoryId))) {
        matched.add("entity_cooccurrence");
      }
      const signals = SIGNAL_ORDER.filter((signal) => matched.has(signal));
      if (signals.length === 0) continue;

      const evidenceMap = new Map<string, EntityRelationshipEvidence>();
      for (const evidence of [...publicEvidence(left), ...publicEvidence(right)]) {
        evidenceMap.set(evidenceKey(evidence), evidence);
      }
      const evidence = [...evidenceMap.values()]
        .sort((a, b) => evidenceKey(a).localeCompare(evidenceKey(b)))
        .slice(0, maxEvidencePerCandidate);
      if (evidence.length === 0) continue;
      const classificationInputs: RelationshipCandidateClassificationInput[] = [
        { entityId: left.entityId, classification: left.classification },
        { entityId: right.entityId, classification: right.classification },
      ];
      candidates.push({
        candidateId: candidateId(left.namespace, left.entityId, right.entityId),
        namespace: left.namespace,
        subjectEntityId: left.entityId,
        subjectEntityName: left.canonicalName,
        objectEntityId: right.entityId,
        objectEntityName: right.canonicalName,
        signals,
        evidence,
        score: candidateScore(signals, embeddingCosine),
        classification: combineClassifications(classificationInputs.map((input) => input.classification)),
        classificationInputs,
      });
    }
  }

  return candidates
    .sort((left, right) => right.score - left.score || left.candidateId.localeCompare(right.candidateId))
    .slice(0, maxPairs);
}
