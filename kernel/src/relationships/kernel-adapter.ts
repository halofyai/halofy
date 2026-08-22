import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import type {
  DataClassification,
  EntityRelationshipListQuery,
  EntityRelationshipListResult,
  LlmClient,
  Namespace,
} from "../types.js";
import type {
  RelationshipCandidateEntity,
  RelationshipCandidateEvidence,
} from "./candidates.js";
import { runRelationshipPipeline, type RelationshipPipelineResult } from "./pipeline.js";
import { RelationshipStore } from "./store.js";

const MAX_FACTS = 512;
const MAX_ENTITIES = 256;
const MAX_MENTIONS = 1_024;
const ENTITY_ANNOTATION = /\s\[entities:\s*([^\]]+)\]\s*$/u;
const PUBLIC_HTTPS_URL = /https:\/\/[^\s<>'"\])}]+/giu;
const SKU = /\bsku\s*(?:id\s*)?[:=#-]?\s*([A-Za-z0-9][A-Za-z0-9._:-]{1,127})/giu;
const STABLE_ID = /\b(?:record\s+id|stable\s+id|identifier|id)\s*[:=#-]?\s*([A-Za-z0-9][A-Za-z0-9._:-]{1,127})/giu;

interface FactRow {
  id: string;
  content: string;
  provenance: unknown;
  classification: unknown;
}

interface EntityRow {
  id: string;
  canonical_name: string;
  aliases: unknown;
  embedding_text: unknown;
}

interface MentionTarget {
  knowledgeBaseId: string;
  companyFileId: string | null;
}

interface PendingMention {
  fact: FactRow;
  entity: EntityRow;
  target: MentionTarget;
  span: { start: number; end: number };
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function strings(value: unknown): string[] {
  const parsed = parseJson(value);
  return Array.isArray(parsed)
    ? parsed.filter((item): item is string => typeof item === "string")
    : [];
}

function vector(value: unknown): number[] | undefined {
  if (Array.isArray(value) && value.every((item) => typeof item === "number" && Number.isFinite(item))) {
    return value;
  }
  if (typeof value !== "string") return undefined;
  const values = value.replace(/^\[|\]$/g, "").split(",").map(Number);
  return values.length > 0 && values.every(Number.isFinite) ? values : undefined;
}

function classification(value: unknown): DataClassification | undefined {
  const parsed = parseJson(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const row = parsed as Record<string, unknown>;
  if (!(["public", "internal", "confidential", "restricted"] as unknown[]).includes(row.sensitivity)) {
    return undefined;
  }
  if (!Array.isArray(row.piiSubjects) || !Array.isArray(row.secretKinds) || !Array.isArray(row.allowedDestinations)) {
    return undefined;
  }
  if (![...row.piiSubjects, ...row.secretKinds, ...row.allowedDestinations].every((item) => typeof item === "string")) {
    return undefined;
  }
  return {
    sensitivity: row.sensitivity as DataClassification["sensitivity"],
    piiSubjects: row.piiSubjects as string[],
    secretKinds: row.secretKinds as string[],
    allowedDestinations: row.allowedDestinations as string[],
    ...(typeof row.residency === "string" ? { residency: row.residency } : {}),
  };
}

function evidence(value: unknown, memoryId: string): RelationshipCandidateEvidence {
  const parsed = parseJson(value);
  const entries = Array.isArray(parsed) ? parsed : [];
  for (const item of entries) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    if (
      typeof row.sourceId === "string" &&
      typeof row.documentKey === "string" &&
      typeof row.contentHash === "string"
    ) {
      return {
        memoryId,
        sourceId: row.sourceId,
        documentKey: row.documentKey,
        contentHash: row.contentHash,
        recordKeys: [row.documentKey],
      };
    }
  }
  return { memoryId };
}

function normalized(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}

function uniqueMatches(pattern: RegExp, content: string): string[] {
  pattern.lastIndex = 0;
  return [...new Set([...content.matchAll(pattern)].flatMap((match) => match[1] ? [match[1]] : []))].sort();
}

function urls(content: string): string[] {
  PUBLIC_HTTPS_URL.lastIndex = 0;
  return [...new Set([...content.matchAll(PUBLIC_HTTPS_URL)].map((match) => match[0]))].sort();
}

function annotationNames(content: string): string[] {
  const match = ENTITY_ANNOTATION.exec(content);
  return match?.[1]?.split(",").map((name) => name.trim()).filter(Boolean) ?? [];
}

function contentBeforeAnnotation(content: string): string {
  return content.replace(ENTITY_ANNOTATION, "").trim();
}

function mentionSpan(content: string, names: readonly string[]): { start: number; end: number } | null {
  const lowered = content.toLocaleLowerCase("en-US");
  for (const name of names) {
    const start = lowered.indexOf(normalized(name));
    if (start >= 0) return { start, end: start + name.length };
  }
  return null;
}

/** Kernel-owned projection from governed L2 facts into bounded graph inputs. */
export class RelationshipKernelAdapter {
  readonly store: RelationshipStore;

  constructor(
    private readonly db: Db,
    private readonly llm: LlmClient,
  ) {
    this.store = new RelationshipStore(db);
  }

  list(
    visibleNamespaces: readonly string[],
    query: EntityRelationshipListQuery,
  ): Promise<EntityRelationshipListResult> {
    return this.store.list(visibleNamespaces, query);
  }

  async enrich(input: {
    namespace: Namespace;
    actor: string;
    newMemoryIds: readonly string[];
    supersededMemoryIds: readonly string[];
  }): Promise<RelationshipPipelineResult> {
    const facts = await this.currentFacts(input.namespace, input.newMemoryIds);
    await this.closeSupersededMentions(input.namespace, input.supersededMemoryIds);
    const entities = await this.projectEntities(input.namespace, input.actor, facts);
    return runRelationshipPipeline({
      namespace: input.namespace,
      actor: input.actor,
      impactedMemoryIds: facts.map((fact) => fact.id),
      entities,
    }, {
      llm: this.llm,
      store: this.store,
    });
  }

  private async currentFacts(namespace: Namespace, newMemoryIds: readonly string[]): Promise<FactRow[]> {
    const ids = [...new Set(newMemoryIds)].slice(0, MAX_FACTS);
    const params: unknown[] = [namespace, new Date().toISOString()];
    const priority = ids.length > 0
      ? `CASE WHEN id IN (${ids.map((id) => {
          params.push(id);
          return `$${params.length}`;
        }).join(", ")}) THEN 0 ELSE 1 END,`
      : "";
    const result = await this.db.query(
      `SELECT id, content, provenance, classification
         FROM memory_objects
        WHERE namespace = $1
          AND tier = 'L2'
          AND type = 'fact'
          AND status = 'active'
          AND t_valid_to IS NULL
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > $2)
        ORDER BY ${priority} assertion_time DESC, id DESC
        LIMIT ${MAX_FACTS}`,
      params,
    );
    return result.rows as FactRow[];
  }

  private async projectEntities(
    namespace: Namespace,
    actor: string,
    facts: readonly FactRow[],
  ): Promise<RelationshipCandidateEntity[]> {
    if (facts.length === 0) return [];
    const result = await this.db.query(
      `SELECT id, canonical_name, aliases, embedding::text AS embedding_text
         FROM entity_registry
        WHERE namespace = $1
        ORDER BY canonical_name, id
        LIMIT 1024`,
      [namespace],
    );
    const rows = result.rows as EntityRow[];
    const byName = new Map<string, EntityRow>();
    for (const row of rows) {
      byName.set(normalized(row.canonical_name), row);
      for (const alias of strings(row.aliases)) byName.set(normalized(alias), row);
    }

    const projected = new Map<string, RelationshipCandidateEntity & {
      aliases: string[];
      stableIds: string[];
      skus: string[];
      urls: string[];
      evidence: RelationshipCandidateEvidence[];
    }>();
    const factEvidence = new Map(
      facts.map((fact) => [fact.id, evidence(fact.provenance, fact.id)]),
    );
    const targets = await this.mentionTargets(
      namespace,
      [...new Set(
        [...factEvidence.values()]
          .map((item) => item.sourceId)
          .filter((sourceId): sourceId is string => sourceId !== undefined),
      )],
    );
    const pendingMentions: PendingMention[] = [];
    for (const fact of facts) {
      const names = annotationNames(fact.content);
      const governedEvidence = factEvidence.get(fact.id) ?? { memoryId: fact.id };
      const body = contentBeforeAnnotation(fact.content);
      const stableIds = uniqueMatches(STABLE_ID, body);
      const skus = uniqueMatches(SKU, body);
      const publicUrls = urls(body);
      const target = governedEvidence.sourceId
        ? targets.get(governedEvidence.sourceId) ?? null
        : null;

      for (const name of names) {
        const row = byName.get(normalized(name));
        if (!row) continue;
        let entity = projected.get(row.id);
        if (!entity) {
          entity = {
            entityId: row.id,
            namespace,
            canonicalName: row.canonical_name,
            aliases: strings(row.aliases),
            stableIds: [],
            skus: [],
            urls: [],
            ...(vector(row.embedding_text) ? { embedding: vector(row.embedding_text) } : {}),
            ...(classification(fact.classification) ? { classification: classification(fact.classification) } : {}),
            evidence: [],
          };
          projected.set(row.id, entity);
        }
        entity.stableIds = [...new Set([...entity.stableIds, ...stableIds])].sort();
        entity.skus = [...new Set([...entity.skus, ...skus])].sort();
        entity.urls = [...new Set([...entity.urls, ...publicUrls])].sort();
        if (!entity.evidence.some((item) => item.memoryId === fact.id)) {
          entity.evidence.push(governedEvidence);
        }
        if (target && pendingMentions.length < MAX_MENTIONS) {
          const span = mentionSpan(fact.content, [row.canonical_name, ...strings(row.aliases)]);
          if (span) pendingMentions.push({ fact, entity: row, target, span });
        }
      }
    }
    await this.persistMentions(namespace, actor, pendingMentions);
    return [...projected.values()]
      .sort((left, right) => left.entityId.localeCompare(right.entityId))
      .slice(0, MAX_ENTITIES);
  }

  private async mentionTargets(
    namespace: Namespace,
    sourceIds: readonly string[],
  ): Promise<Map<string, MentionTarget>> {
    if (sourceIds.length === 0) return new Map();
    const bounded = sourceIds.slice(0, MAX_FACTS);
    const placeholders = bounded.map((_, index) => `$${index + 2}`).join(", ");
    const result = await this.db.query(
      `SELECT source.id AS source_id,
              COALESCE(file.knowledge_base_id, base.id) AS knowledge_base_id,
              file.id AS company_file_id
         FROM sources source
         LEFT JOIN company_files file
           ON file.source_id = source.id AND file.namespace = $1
         LEFT JOIN knowledge_bases base
           ON base.source_id = source.id AND base.namespace = $1
        WHERE source.id IN (${placeholders}) AND source.namespace = $1
          AND COALESCE(file.knowledge_base_id, base.id) IS NOT NULL
        ORDER BY source.id, file.created_at DESC NULLS LAST`,
      [namespace, ...bounded],
    );
    const targets = new Map<string, MentionTarget>();
    for (const value of result.rows) {
      const row = value as Record<string, unknown>;
      if (
        typeof row.source_id === "string" &&
        typeof row.knowledge_base_id === "string" &&
        !targets.has(row.source_id)
      ) {
        targets.set(row.source_id, {
          knowledgeBaseId: row.knowledge_base_id,
          companyFileId: typeof row.company_file_id === "string" ? row.company_file_id : null,
        });
      }
    }
    return targets;
  }

  private async persistMentions(
    namespace: Namespace,
    actor: string,
    mentions: readonly PendingMention[],
  ): Promise<void> {
    if (mentions.length === 0) return;
    const now = new Date().toISOString();
    const params: unknown[] = [];
    const values = mentions.slice(0, MAX_MENTIONS).map((mention) => {
      const offset = params.length;
      params.push(
        ulid(),
        namespace,
        mention.target.knowledgeBaseId,
        mention.entity.id,
        mention.fact.id,
        mention.target.companyFileId,
        mention.span.start,
        mention.span.end,
        now,
        actor,
      );
      const bind = (index: number): string => `$${offset + index}`;
      return `(${bind(1)}, ${bind(2)}, ${bind(3)}, ${bind(4)}, ${bind(5)},
               ${bind(6)}, ${bind(7)}, ${bind(8)}, 1, 'governed-fact-annotation',
               NULL, ${bind(9)}, NULL, ${bind(10)}, ${bind(9)})`;
    });
    await this.db.query(
      `INSERT INTO entity_mentions
         (id, namespace, knowledge_base_id, entity_id, memory_id, company_file_id,
          span_start, span_end, confidence, extractor, supersedes, t_valid_from,
          t_valid_to, created_by, created_at)
       VALUES ${values.join(", ")}
       ON CONFLICT DO NOTHING`,
      params,
    );
  }

  private async closeSupersededMentions(namespace: Namespace, memoryIds: readonly string[]): Promise<void> {
    const ids = [...new Set(memoryIds)].slice(0, MAX_FACTS);
    if (ids.length === 0) return;
    const placeholders = ids.map((_, index) => `$${index + 3}`).join(", ");
    await this.db.query(
      `UPDATE entity_mentions
          SET t_valid_to = $2
        WHERE namespace = $1 AND t_valid_to IS NULL
          AND memory_id IN (${placeholders})`,
      [namespace, new Date().toISOString(), ...ids],
    );
  }
}
