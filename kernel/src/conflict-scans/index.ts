/** Durable, bounded organization-memory conflict scans (CS1-CS7, CS11). */

import { createHash } from "node:crypto";
import { ulid } from "ulid";

import type { AuditLog } from "../audit/index.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import { escapeLikePattern, type Db } from "../db/client.js";
import { DurableRateLimitStore } from "../durable/rate-limit.js";
import { cosine } from "../ingest/fragmentation.js";
import { heuristicDisputeCategory } from "../llm/index.js";
import { parseVectorText } from "../ingest/kernel-store.js";
import { factSubjects } from "../entity-tagger/subjects.js";
import { RateLimitError } from "../syscalls/index.js";
import {
  CONFLICT_CLASSIFIER_BATCH_SIZE,
  CONFLICT_CLASSIFIER_CANDIDATE_CAP,
  classifyConflictCandidatesInBatches,
  type ConflictClassificationCandidate,
  type ConflictClassifier,
} from "./classifier.js";
import type {
  ConflictAutoDecisionView,
  ConflictAutoRule,
  ConflictFindingFactView,
  ConflictFindingFlag,
  ConflictScanFindingView,
  ConflictScanInclude,
  ConflictScanRequest,
  ConflictScanRunView,
  DisputeCategory,
  Identity,
  MemoryId,
  ProvenanceEntry,
  Scope,
} from "../types.js";

const DETECTOR_VERSION = "luna-context-v1";
const FINDING_KIND = "semantic-contradiction";
const FACT_CAP = 10_000;
const PAIR_CAP = 20_000;
const MIN_PUBLISH_CONFIDENCE = 0.8;
/** Manual scans use the same retrieval-first neighborhood as new-write checks. */
export const SCAN_NEIGHBOR_K = 8;
/**
 * No single canonical entity may spend more than this share of the per-scan
 * model budget. One imported table shares an entity across every one of its
 * rows; without a quota that table's near-duplicate pairs sort to the top of
 * the similarity ranking and consume the whole budget, so a genuine
 * cross-source disagreement elsewhere in the corpus is never judged at all.
 */
const GROUP_CANDIDATE_QUOTA = 8;
const SCAN_REQUEST_COOLDOWN_MS = 5 * 60 * 1_000;
const MAX_QUEUED_SCANS = 20;
const DEFAULT_INCLUDE: ConflictScanInclude[] = [
  "knowledge-base",
  "agent-summary",
  "policy-manual",
];

export class ConflictFindingNotFoundError extends Error {
  constructor() {
    super("conflict finding not found");
    this.name = "ConflictFindingNotFoundError";
  }
}

export class ConflictFindingConflictError extends Error {
  constructor() {
    super("conflict finding changed; refresh and try again");
    this.name = "ConflictFindingConflictError";
  }
}

class ConflictScanLeaseLostError extends Error {
  constructor() {
    super("conflict scan lease lost");
    this.name = "ConflictScanLeaseLostError";
  }
}

interface ScanFact {
  id: MemoryId;
  /** Subjects mirrored by the tagger (CA8); the grouping key for this scan. */
  derivedEntities: unknown;
  namespace: string;
  scope: Scope;
  content: string;
  confidence: number;
  assertionTime: string;
  eventTime: string | null;
  provenance: ProvenanceEntry[];
  entities: string[];
  embedding: number[] | null;
  kind: ConflictScanInclude;
}

function json<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  return typeof value === "string" ? JSON.parse(value) as T : value as T;
}

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(String(value)).toISOString();
}

function sourceLabel(fact: ScanFact): string {
  const entry = fact.provenance[0];
  if (!entry) return `memory:${fact.id}`;
  return entry.sourceId ?? `${entry.source}:${entry.actor}`;
}

function classifySource(provenance: ProvenanceEntry[]): ConflictScanInclude {
  const source = provenance[0]?.source;
  if (source === "conversation") return "agent-summary";
  if (source === "manual" || source === "consolidation") return "policy-manual";
  return "knowledge-base";
}

/**
 * Categorise on the evidence, not just the entity name. A canonical entity is
 * usually a bare proper noun ("Halofy"), so entity-only classification sent
 * nearly every finding to "Other" and left the S11 filter chips useless.
 */
export function categoryFor(entity: string, ...evidence: string[]): DisputeCategory {
  const value = entity.toLowerCase();
  if (/policy|legal|refund|privacy|security|compliance/.test(value)) return "policies-legal";
  if (/order|shipping|delivery|return|fulfil/.test(value)) return "order-management";
  if (/product|sku|feature|price|plan/.test(value)) return "product-info";
  return heuristicDisputeCategory(evidence.map(normalizedFactText).join(" "));
}

function normalizedFactText(content: string): string {
  return content
    .replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

/**
 * A field whose value identifies WHICH record a structured row describes.
 * Two rows that disagree here are different observations, not disagreements.
 */
const RECORD_IDENTITY_KEY =
  /(^|_)(id|ids|uuid|no|number|key|date|day|week|month|quarter|year|period|timestamp|time|at|seq|row|index|version)$/;

/**
 * Parse the `key: value, key: value` shape that table/CSV ingestion produces
 * into a field map. Returns null for prose, or for any row whose segments are
 * not all well-formed pairs — the conservative reading, since a value
 * containing a comma would otherwise be mis-split.
 */
export function structuredFields(content: string): Map<string, string> | null {
  const base = content.replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "").trim();
  if (base.length === 0) return null;
  const fields = new Map<string, string>();
  for (const part of base.split(/\s*,\s*/)) {
    const match = /^([A-Za-z][A-Za-z0-9_ .-]{0,60}?)\s*:\s*(.+)$/.exec(part.trim());
    if (!match) return null;
    fields.set(
      match[1]!.trim().toLowerCase().replace(/\s+/g, "_"),
      match[2]!.trim().toLowerCase(),
    );
  }
  return fields.size >= 3 ? fields : null;
}

/**
 * True when two facts are rows of the same table describing DIFFERENT records
 * — same schema, disagreeing record-identity field. Monday's impressions and
 * Wednesday's impressions are both true; publishing that as a contradiction is
 * the single largest source of unusable S11 findings.
 *
 * This is a schema judgement made before any model call, not a similarity
 * veto: prose facts always fall through to the semantic judge (CS18).
 */
export function distinctStructuredRecords(left: string, right: string): boolean {
  const a = structuredFields(left);
  const b = structuredFields(right);
  if (!a || !b) return false;
  let shared = 0;
  let identityDiffers = false;
  for (const [key, value] of a) {
    const other = b.get(key);
    if (other === undefined) continue;
    shared += 1;
    if (other !== value && RECORD_IDENTITY_KEY.test(key)) identityDiffers = true;
  }
  // Require a genuinely shared schema, so an incidental key overlap between two
  // unrelated prose-ish facts cannot suppress a real contradiction.
  return identityDiffers && shared >= Math.min(a.size, b.size) * 0.8;
}

/**
 * `capitalizedWords` derives entity mentions from any capitalised token, so an
 * identifier like `MET-012-01` contributes the mention "MET". Those artifacts
 * are not subjects: they collapse an entire imported table into one candidate
 * group. Grouping on them produces noise, never a reviewable conflict.
 */
export function isDegenerateEntity(entity: string): boolean {
  const value = entity.trim();
  if (value.length < 4) return true;
  // A short all-caps token with no lowercase is an identifier prefix or code,
  // not an organizational subject a reviewer would recognise.
  return /^[A-Z0-9]{2,5}$/.test(value);
}

/**
 * Rank by how likely a pair is to be a conflict a human must resolve, not by
 * raw textual similarity. The conflicts that matter — an agent's claim against
 * an imported document — read as LESS similar than two adjacent table rows, so
 * a similarity-first ordering systematically buries them.
 */
function candidatePriority(flags: readonly ConflictFindingFlag[]): number {
  let score = 0;
  if (flags.includes("cross-source")) score += 4;
  if (flags.includes("agent-derived")) score += 3;
  if (flags.includes("cross-team")) score += 1;
  return score;
}

/** Stable full-cycle pair order; advancing rotation by one eventually leads with every fact. */
export function* conflictPairIndexes(size: number, rotation: number): Generator<readonly [number, number]> {
  if (size < 2) return;
  const start = ((rotation % size) + size) % size;
  const order = Array.from({ length: size }, (_, index) => (start + index) % size);
  for (let i = 0; i < order.length; i += 1) {
    for (let j = i + 1; j < order.length; j += 1) {
      yield [order[i]!, order[j]!] as const;
    }
  }
}

export function conflictGroupOrder(
  groupCount: number,
  pairRotation: number,
): Array<{ groupIndex: number; factRotation: number }> {
  if (groupCount <= 0) return [];
  const start = ((pairRotation % groupCount) + groupCount) % groupCount;
  const factRotation = Math.floor(Math.max(0, pairRotation) / groupCount);
  return Array.from({ length: groupCount }, (_, offset) => ({
    groupIndex: (start + offset) % groupCount,
    factRotation,
  }));
}

function fingerprint(target: string, left: MemoryId, right: MemoryId): string {
  const pair = [left, right].sort();
  return createHash("sha256")
    .update(`${DETECTOR_VERSION}\0${target}\0${FINDING_KIND}\0${pair[0]}\0${pair[1]}`)
    .digest("hex");
}

function encodeFocus(value: string | null): string | null {
  if (!value) return null;
  const terms = [...new Set(value.toLowerCase().match(/[a-z0-9_-]{3,}/g) ?? [])]
    .slice(0, 32)
    .map((term) => createHash("sha256").update(term).digest("hex"));
  return JSON.stringify({
    digest: createHash("sha256").update(value).digest("hex"),
    terms,
  });
}

function focusTermHashes(value: unknown): Set<string> {
  const parsed = json<{ terms?: unknown }>(value, {});
  return new Set(Array.isArray(parsed.terms)
    ? parsed.terms.filter((term): term is string => typeof term === "string")
    : []);
}

function normalizeInclude(value: ConflictScanRequest["include"]): ConflictScanInclude[] {
  if (!value || value.length === 0) return [...DEFAULT_INCLUDE];
  return [...new Set(value.filter((entry): entry is ConflictScanInclude =>
    DEFAULT_INCLUDE.includes(entry as ConflictScanInclude)))];
}

function rowToRun(row: Record<string, unknown>): ConflictScanRunView {
  const complete = row.status === "completed" || row.status === "completed_with_gaps" || row.status === "failed";
  const coverageGaps = json<string[]>(row.coverage_gaps, []);
  return {
    id: String(row.id),
    targetNamespace: String(row.target_namespace),
    status: row.status as ConflictScanRunView["status"],
    phase: row.phase as ConflictScanRunView["phase"],
    focus: row.focus == null ? null : "Focused scan",
    include: json<ConflictScanInclude[]>(row.include_kinds, []),
    progress: {
      itemsScanned: Number(row.items_scanned ?? 0),
      itemsTotal: Number(row.items_total ?? 0),
      sourcesReached: Number(row.sources_reached ?? 0),
      agentSummaries: coverageGaps.includes("agent_capture_unavailable")
        ? null
        : Number(row.agent_summaries ?? 0),
      candidatePairs: Number(row.candidate_pairs ?? 0),
      modelPairsReviewed: Number(row.model_pairs_reviewed ?? 0),
    },
    summary: complete ? {
      newFindings: Number(row.new_findings ?? 0),
      existingFindings: Number(row.existing_findings ?? 0),
      coverageGaps,
    } : null,
    requestedAt: iso(row.requested_at),
    startedAt: row.started_at == null ? null : iso(row.started_at),
    completedAt: row.completed_at == null ? null : iso(row.completed_at),
  };
}

function assertReader(identity: Identity, target: string): void {
  if (identity.namespace === "" && !isRootOwner(identity)) {
    throw new AuthzError("global conflict scans require the root owner");
  }
  if (!isRootOwner(identity) && !isSelfOrDescendant(target, identity.namespace)) {
    throw new AuthzError("conflict scan is outside the caller's subtree");
  }
  if (identity.role === "agent" || identity.role === "member") {
    throw new AuthzError("conflict scans require an administrative role");
  }
}

function assertRequester(identity: Identity, target: string): void {
  assertReader(identity, target);
  if (identity.role !== "owner" && identity.role !== "admin") {
    throw new AuthzError("conflict scans require owner or admin");
  }
}

export class ConflictScanService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly classifier: ConflictClassifier | null = null,
    private readonly requestCooldownMs = SCAN_REQUEST_COOLDOWN_MS,
  ) {}

  private async auditDenied(identity: Identity, purpose: string): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
      op: "conflict_scan", memoryId: null, namespace: identity.namespace,
      purpose, result: "denied", detail: "conflict scan authority denied",
    });
  }

  async request(
    identity: Identity,
    input: ConflictScanRequest,
    targetNamespace = identity.namespace,
  ): Promise<ConflictScanRunView> {
    try {
      assertRequester(identity, targetNamespace);
    } catch (error) {
      await this.auditDenied(identity, "organization-conflict-scan-request");
      throw error;
    }
    const include = normalizeInclude(input.include);
    const focusText = typeof input.focus === "string" && input.focus.trim().length > 0
      ? input.focus.trim().slice(0, 500)
      : null;
    const focus = encodeFocus(focusText);
    const requestedId = ulid();
    const now = new Date().toISOString();
    type Admission = { kind: "admitted" | "reused"; id: string } |
      { kind: "queue_full" } | { kind: "cooldown" };
    const admission = await this.db.transaction(async (tx): Promise<Admission> => {
      await tx.query(`SELECT id FROM conflict_scan_queue_guard WHERE id = 1 FOR UPDATE`);
      const active = await tx.query(
        `SELECT id FROM conflict_scan_runs
          WHERE target_namespace = $1 AND status IN ('queued','running')
          ORDER BY requested_at,id LIMIT 1`,
        [targetNamespace],
      );
      if (active.rows[0]) {
        const id = String(active.rows[0].id);
        await this.audit.appendTo(tx, {
          ts: now, actor: identity.actor, agentId: identity.keyId,
          op: "conflict_scan", memoryId: null, namespace: targetNamespace,
          purpose: "organization-conflict-scan-request", result: "ok",
          detail: `scan_id=${id} include=${include.join(",")} reused=true`,
        });
        return { kind: "reused", id };
      }
      const queuedCount = await tx.query(
        `SELECT COUNT(*)::int AS count FROM conflict_scan_runs WHERE status = 'queued'`,
      );
      if (Number(queuedCount.rows[0]?.count ?? 0) >= MAX_QUEUED_SCANS) {
        await this.audit.appendTo(tx, {
          ts: now, actor: identity.actor, agentId: identity.keyId,
          op: "conflict_scan", memoryId: null, namespace: targetNamespace,
          purpose: "organization-conflict-scan-request", result: "denied",
          detail: "code=queue_full",
        });
        return { kind: "queue_full" };
      }
      if (this.requestCooldownMs > 0) {
        const rate = await new DurableRateLimitStore(tx).consume(
          `conflict-scan:${identity.keyId}`,
          1,
          this.requestCooldownMs,
        );
        if (!rate.allowed) {
          await this.audit.appendTo(tx, {
            ts: now, actor: identity.actor, agentId: identity.keyId,
            op: "conflict_scan", memoryId: null, namespace: targetNamespace,
            purpose: "organization-conflict-scan-request", result: "denied",
            detail: "code=cooldown",
          });
          return { kind: "cooldown" };
        }
      }
      await tx.query(
        `INSERT INTO conflict_scan_runs
           (id,target_namespace,requested_by,requested_key_id,focus,include_kinds,
            status,phase,requested_at,fact_offset,candidate_offset,pair_rotation)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb,'queued','queued',$7,
           COALESCE((SELECT fact_offset + $8 FROM conflict_scan_runs
                      WHERE target_namespace = $2 ORDER BY requested_at DESC,id DESC LIMIT 1),0),
           COALESCE((SELECT candidate_offset + $9 FROM conflict_scan_runs
                      WHERE target_namespace = $2 ORDER BY requested_at DESC,id DESC LIMIT 1),0),
           COALESCE((SELECT pair_rotation + 1 FROM conflict_scan_runs
                      WHERE target_namespace = $2 ORDER BY requested_at DESC,id DESC LIMIT 1),0))`,
        [requestedId, targetNamespace, identity.actor, identity.keyId, focus,
          JSON.stringify(include), now, FACT_CAP, CONFLICT_CLASSIFIER_CANDIDATE_CAP],
      );
      await this.audit.appendTo(tx, {
        ts: now, actor: identity.actor, agentId: identity.keyId,
        op: "conflict_scan", memoryId: null, namespace: targetNamespace,
        purpose: "organization-conflict-scan-request", result: "ok",
        detail: `scan_id=${requestedId} include=${include.join(",")} reused=false`,
      });
      return { kind: "admitted", id: requestedId };
    });
    if (admission.kind === "queue_full" || admission.kind === "cooldown") {
      throw new RateLimitError(admission.kind === "queue_full"
        ? "conflict scan queue is full; try again later"
        : "conflict scans are limited to one request every five minutes per administrator");
    }
    const id = admission.id;
    return (await this.get(id, identity))!;
  }

  async get(id: string, identity: Identity): Promise<ConflictScanRunView | null> {
    const result = await this.db.query(`SELECT * FROM conflict_scan_runs WHERE id = $1`, [id]);
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) return null;
    try {
      assertReader(identity, String(row.target_namespace));
    } catch (error) {
      await this.auditDenied(identity, "organization-conflict-scan-read");
      throw error;
    }
    return rowToRun(row);
  }

  async latest(identity: Identity): Promise<ConflictScanRunView | null> {
    if (identity.role === "agent" || identity.role === "member" ||
      (identity.namespace === "" && !isRootOwner(identity))) {
      await this.auditDenied(identity, "organization-conflict-scan-read");
      throw new AuthzError("conflict scans require an administrative role");
    }
    const pattern = `${escapeLikePattern(identity.namespace)}/%`;
    const result = await this.db.query(
      `SELECT * FROM conflict_scan_runs
        WHERE ($1 = '' OR target_namespace = $1 OR target_namespace LIKE $2 ESCAPE '\\')
        ORDER BY requested_at DESC, id DESC LIMIT 1`,
      [identity.namespace, pattern],
    );
    return result.rows[0] ? rowToRun(result.rows[0] as Record<string, unknown>) : null;
  }

  async recent(identity: Identity, limit = MAX_QUEUED_SCANS + 1): Promise<ConflictScanRunView[]> {
    if (identity.role === "agent" || identity.role === "member" ||
      (identity.namespace === "" && !isRootOwner(identity))) {
      await this.auditDenied(identity, "organization-conflict-scan-read");
      throw new AuthzError("conflict scans require an administrative role");
    }
    const pattern = `${escapeLikePattern(identity.namespace)}/%`;
    const normalizedLimit = Number.isFinite(limit) ? Math.trunc(limit) : MAX_QUEUED_SCANS + 1;
    const cappedLimit = Math.max(1, Math.min(MAX_QUEUED_SCANS + 1, normalizedLimit));
    const result = await this.db.query(
      `SELECT * FROM conflict_scan_runs
        WHERE ($1 = '' OR target_namespace = $1 OR target_namespace LIKE $2 ESCAPE '\\')
        ORDER BY requested_at DESC, id DESC LIMIT $3`,
      [identity.namespace, pattern, cappedLimit],
    );
    return result.rows.map((row) => rowToRun(row as Record<string, unknown>));
  }

  private async collect(row: Record<string, unknown>): Promise<{
    facts: ScanFact[];
    gaps: string[];
    total: number;
  }> {
    const target = String(row.target_namespace);
    const countResult = await this.db.query(
      `SELECT COUNT(*)::int AS count FROM memory_objects
        WHERE status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
          AND type <> 'pointer'
          AND ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)`,
      [target, `${escapeLikePattern(target)}/%`],
    );
    const total = Number(countResult.rows[0]?.count ?? 0);
    // Retrieval-first scans need every eligible fact in the bounded corpus,
    // including facts whose entity tagger is still catching up. Entityless
    // facts use a scope-local vector fallback below; they are not silently
    // called clean or forced into one broad subject-derived Cartesian product.
    const rawRows = (await this.db.query(
      `SELECT id,namespace,scope,content,confidence,event_time,assertion_time,provenance,
              derived_entities,embedding::text AS embedding_text
         FROM memory_objects
        WHERE status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
          AND type <> 'pointer'
          AND ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
        ORDER BY id
        LIMIT $3`,
      [target, `${escapeLikePattern(target)}/%`, FACT_CAP],
    )).rows;
    const include = new Set(json<ConflictScanInclude[]>(row.include_kinds, DEFAULT_INCLUDE));
    const termHashes = focusTermHashes(row.focus);
    const selected = rawRows.flatMap((entry): ScanFact[] => {
      const value = entry as Record<string, unknown>;
      const content = String(value.content);
      if (termHashes.size > 0) {
        const contentHashes = new Set((content.toLowerCase().match(/[a-z0-9_-]{3,}/g) ?? [])
          .map((term) => createHash("sha256").update(term).digest("hex")));
        if (![...termHashes].some((term) => contentHashes.has(term))) return [];
      }
      const provenance = json<ProvenanceEntry[]>(value.provenance, []);
      const kind = classifySource(provenance);
      if (!include.has(kind)) return [];
      const entities = factSubjects(content, value.derived_entities ?? null);
      return [{
        id: String(value.id) as MemoryId,
        derivedEntities: value.derived_entities ?? null,
        namespace: String(value.namespace),
        scope: value.scope as Scope,
        content,
        confidence: Number(value.confidence),
        assertionTime: iso(value.assertion_time),
        eventTime: value.event_time == null ? null : iso(value.event_time),
        provenance,
        entities,
        embedding: parseVectorText(value.embedding_text),
        kind,
      }];
    });
    const gaps: string[] = [];
    if (total > rawRows.length) gaps.push("fact_cap_reached");
    return { facts: selected, gaps, total };
  }

  private async execute(row: Record<string, unknown>, leaseToken: string): Promise<void> {
    const id = String(row.id);
    const target = String(row.target_namespace);
    const { facts, gaps, total } = await this.collect(row);
    const groups = new Map<string, { entity: string; facts: ScanFact[] }>();
    for (const fact of facts) {
      const usable = fact.entities.filter((entity) => !isDegenerateEntity(entity));
      if (usable.length === 0) {
        const key = `embedding-fallback\0${fact.scope}`;
        const group = groups.get(key) ?? { entity: "unspecified subject", facts: [] };
        group.facts.push(fact);
        groups.set(key, group);
        continue;
      }
      for (const entity of usable) {
        const key = `${entity.length}:${entity}\0${fact.scope}`;
        const group = groups.get(key) ?? { entity, facts: [] };
        group.facts.push(fact);
        groups.set(key, group);
      }
    }
    let candidatePairs = 0;
    type PendingCandidate = ConflictClassificationCandidate & {
      left: ScanFact;
      right: ScanFact;
      flags: ConflictFindingFlag[];
      similarity: number | null;
    };
    const candidatesByPair = new Map<string, PendingCandidate>();
    const now = new Date().toISOString();
    const orderedGroups = [...groups.values()];
    const groupOrder = conflictGroupOrder(orderedGroups.length, Number(row.pair_rotation ?? 0));
    type NearestNeighbor = { fact: ScanFact; similarity: number | null; entity: string };
    // A fact may belong to several entity groups. Keep one global neighborhood
    // per fact so "nearest eight" cannot silently become eight per entity.
    const nearestByFact = new Map<string, NearestNeighbor[]>();
    for (const { groupIndex, factRotation } of groupOrder) {
      const group = orderedGroups[groupIndex]!;
      for (const [i, j] of conflictPairIndexes(group.facts.length, factRotation)) {
          const left = group.facts[i]!;
          const right = group.facts[j]!;
          if (left.id === right.id) continue;
          const similarity = cosine(left.embedding, right.embedding);
          if (normalizedFactText(left.content) === normalizedFactText(right.content)) continue;
          if (distinctStructuredRecords(left.content, right.content)) continue;
          const remember = (anchor: ScanFact, neighbor: ScanFact) => {
            const values = nearestByFact.get(anchor.id) ?? [];
            const existing = values.find((value) => value.fact.id === neighbor.id);
            if (existing) {
              if (group.entity.length > existing.entity.length) existing.entity = group.entity;
              return;
            }
            values.push({ fact: neighbor, similarity, entity: group.entity });
            values.sort((a, b) => (b.similarity ?? -1) - (a.similarity ?? -1) ||
              String(a.fact.id).localeCompare(String(b.fact.id)));
            if (values.length > SCAN_NEIGHBOR_K) values.length = SCAN_NEIGHBOR_K;
            nearestByFact.set(anchor.id, values);
          };
          remember(left, right);
          remember(right, left);
      }
    }
    outer: for (const left of facts) {
        for (const { fact: right, similarity, entity } of nearestByFact.get(left.id) ?? []) {
          const evidencePair = [left.id, right.id].sort().join("\0");
          const existing = candidatesByPair.get(evidencePair);
          if (existing) {
            if (entity.length > existing.entity.length) existing.entity = entity;
            continue;
          }
          if (candidatePairs >= PAIR_CAP) {
            gaps.push("pair_cap_reached");
            break outer;
          }
          candidatePairs += 1;
          const flags: ConflictFindingFlag[] = [];
          if (sourceLabel(left) !== sourceLabel(right)) flags.push("cross-source");
          if (left.kind === "agent-summary" || right.kind === "agent-summary") flags.push("agent-derived");
          if (left.namespace !== right.namespace) flags.push("cross-team");
          if (Math.min(left.confidence, right.confidence) < 0.7) flags.push("low-confidence");
          candidatesByPair.set(evidencePair, {
            id: "pending",
            left,
            right,
            entity,
            scope: left.scope,
            flags,
            similarity,
          });
        }
    }
    const sources = new Set(facts.map(sourceLabel));
    const agentSummaries = facts.filter((fact) => fact.kind === "agent-summary").length;
    const ranked = [...candidatesByPair.values()].sort((a, b) =>
      candidatePriority(b.flags) - candidatePriority(a.flags) ||
      (b.similarity ?? -1) - (a.similarity ?? -1) ||
      `${a.left.id}\0${a.right.id}`.localeCompare(`${b.left.id}\0${b.right.id}`));
    // Spread the budget across entities so one large imported table cannot own
    // every slot: each entity gets its quota first, then whatever budget is
    // still unspent is backfilled in rank order. Diversity comes first without
    // any of the budget going to waste on a single-entity corpus.
    const perEntity = new Map<string, number>();
    const deferred: typeof ranked = [];
    const quotaed = ranked.filter((candidate) => {
      const used = perEntity.get(candidate.entity) ?? 0;
      if (used >= GROUP_CANDIDATE_QUOTA) {
        deferred.push(candidate);
        return false;
      }
      perEntity.set(candidate.entity, used + 1);
      return true;
    });
    const budgeted = [...quotaed, ...deferred];
    const candidates = budgeted
      .map((candidate, index) => {
        const evidence = (fact: ScanFact) => {
          const provenance = fact.provenance[0];
          return {
            content: fact.content,
            namespace: fact.namespace,
            memoryId: fact.id,
            eventTime: fact.eventTime,
            assertionTime: fact.assertionTime,
            source: provenance?.source,
            sourceId: provenance?.sourceId,
            sourceKind: provenance?.sourceKind,
            documentKey: provenance?.documentKey,
          };
        };
        return {
          ...candidate,
          id: `candidate-${index + 1}`,
          left: Object.assign(candidate.left, evidence(candidate.left)),
          right: Object.assign(candidate.right, evidence(candidate.right)),
        };
      });
    const progress = await this.db.query(
      `UPDATE conflict_scan_runs SET phase = 'comparing', items_scanned = $2,
          items_total = $3, sources_reached = $4, agent_summaries = $5,
          candidate_pairs = $6, coverage_gaps = $7::jsonb, heartbeat_at = $8
        WHERE id = $1 AND status = 'running' AND lease_token = $9 RETURNING id`,
      [id, facts.length, total, sources.size, agentSummaries, candidatePairs,
        JSON.stringify([...new Set(gaps)]), new Date().toISOString(), leaseToken],
    );
    if (!progress.rows[0]) throw new ConflictScanLeaseLostError();

    let publishable: Array<PendingCandidate & { confidence: number; reason: string }> = [];
    let modelDecisions = 0;
    if (candidates.length > 0) {
      if (!this.classifier) {
        gaps.push("contradiction_model_unavailable");
      } else {
        try {
          const decisions = [];
          for (let offset = 0; offset < candidates.length; offset += CONFLICT_CLASSIFIER_BATCH_SIZE) {
            const batch = await classifyConflictCandidatesInBatches(
              this.classifier!,
              candidates.slice(offset, offset + CONFLICT_CLASSIFIER_BATCH_SIZE),
            );
            decisions.push(...batch);
            const heartbeat = await this.db.query(
              `UPDATE conflict_scan_runs SET heartbeat_at = $2, model_pairs_reviewed = $3
                WHERE id = $1 AND status = 'running' AND lease_token = $4 RETURNING id`,
              [id, new Date().toISOString(), decisions.length, leaseToken],
            );
            if (!heartbeat.rows[0]) throw new ConflictScanLeaseLostError();
          }
          const byId = new Map(decisions.map((decision) => [decision.candidateId, decision]));
          modelDecisions = decisions.length;
          publishable = candidates.flatMap((candidate) => {
            const decision = byId.get(candidate.id);
            return decision?.contradiction
              ? [{ ...candidate, confidence: decision.confidence, reason: decision.reason }]
              : [];
          });
        } catch {
          // Fail closed: an incomplete classifier pass publishes nothing and
          // cannot be misrepresented as a clean corpus.
          gaps.push("contradiction_model_unavailable");
          modelDecisions = 0;
          publishable = [];
        }
      }
    }
    const publishing = await this.db.query(
      `UPDATE conflict_scan_runs SET phase = 'publishing', coverage_gaps = $2::jsonb,
          heartbeat_at = $3 WHERE id = $1 AND status = 'running' AND lease_token = $4 RETURNING id`,
      [id, JSON.stringify([...new Set(gaps)]), new Date().toISOString(), leaseToken],
    );
    if (!publishing.rows[0]) throw new ConflictScanLeaseLostError();
    const completedAt = new Date().toISOString();
    await this.db.transaction(async (tx) => {
      const evidenceIds = [...new Set(publishable.flatMap((candidate) =>
        [candidate.left.id, candidate.right.id]))];
      if (evidenceIds.length > 0) {
        const current = await tx.query(
          `SELECT id FROM memory_objects
            WHERE id = ANY($1::text[]) AND status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
              AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
            FOR UPDATE`,
          [evidenceIds],
        );
        const currentIds = new Set(current.rows.map((value) => String(value.id)));
        const before = publishable.length;
        publishable = publishable.filter((candidate) =>
          currentIds.has(candidate.left.id) && currentIds.has(candidate.right.id));
        if (publishable.length !== before) gaps.push("evidence_changed_during_scan");
      }
      const status = gaps.length > 0 ? "completed_with_gaps" : "completed";
      // Legacy findings are hidden from the confirmed view and rejudged by
      // their exact evidence pair. A broad detector-version sweep would erase
      // unresolved history without actually asking Luna about that pair.
      let newFindings = 0;
      let existingFindings = 0;
      for (const candidate of publishable) {
        const hash = fingerprint(target, candidate.left.id, candidate.right.id);
        const matched = await tx.query(
          `SELECT id,status FROM conflict_scan_findings
            WHERE target_namespace = $1 AND detector_version = $2
              AND ((left_memory_id = $3 AND right_memory_id = $4)
                OR (left_memory_id = $4 AND right_memory_id = $3))
            ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
                     first_seen_at,id`,
          [target, DETECTOR_VERSION, candidate.left.id, candidate.right.id],
        );
        if (matched.rows.length > 0) {
          const primary = matched.rows[0] as Record<string, unknown>;
          await tx.query(
            `UPDATE conflict_scan_findings
                SET last_scan_id = $2,last_seen_at = $3,reason = $4,confidence = $5,
                    flags = $6::jsonb,row_version = row_version + 1
              WHERE id = $1`,
            [String(primary.id), id, now, candidate.reason, candidate.confidence,
              JSON.stringify(candidate.flags)],
          );
          const duplicateIds = matched.rows.slice(1).map((entry) => String(entry.id));
          if (duplicateIds.length > 0) {
            await tx.query(
              `UPDATE conflict_scan_findings
                  SET status = 'dismissed',row_version = row_version + 1
                WHERE id = ANY($1::text[]) AND status <> 'dismissed'`,
              [duplicateIds],
            );
          }
          if (primary.status === "open") existingFindings += 1;
          continue;
        }
        const inserted = await tx.query(
          `INSERT INTO conflict_scan_findings
             (id,target_namespace,left_memory_id,right_memory_id,fingerprint,detector_version,
              entity,category,reason,confidence,flags,status,row_version,first_scan_id,last_scan_id,
              first_seen_at,last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,'open',1,$12,$12,$13,$13)
           ON CONFLICT (target_namespace,fingerprint) DO NOTHING RETURNING id`,
          [ulid(), target, candidate.left.id, candidate.right.id, hash, DETECTOR_VERSION,
            candidate.entity,
            categoryFor(candidate.entity, candidate.left.content, candidate.right.content),
            candidate.reason, candidate.confidence,
            JSON.stringify(candidate.flags), id, now],
        );
        if (inserted.rows[0]) {
          newFindings += 1;
        } else {
          await tx.query(
            `UPDATE conflict_scan_findings
                SET last_scan_id = $3,last_seen_at = $4,reason = $5,confidence = $6,
                    flags = $7::jsonb,row_version = row_version + 1
              WHERE target_namespace = $1 AND fingerprint = $2`,
            [target, hash, id, now, candidate.reason, candidate.confidence,
              JSON.stringify(candidate.flags)],
          );
          existingFindings += 1;
        }
      }
      await tx.query(
        `UPDATE conflict_scan_runs SET status = $2, phase = 'complete', items_scanned = $3,
            items_total = $4, sources_reached = $5, agent_summaries = $6, candidate_pairs = $7,
            new_findings = $8, existing_findings = $9, coverage_gaps = $10::jsonb, completed_at = $11
          WHERE id = $1 AND status = 'running' AND lease_token = $12 RETURNING id`,
        [id, status, facts.length, total, sources.size, agentSummaries,
          candidatePairs, newFindings, existingFindings,
          JSON.stringify([...new Set(gaps)]), completedAt, leaseToken],
      );
      const completed = await tx.query(
        `SELECT id FROM conflict_scan_runs
          WHERE id = $1 AND status IN ('completed','completed_with_gaps') AND lease_token = $2`,
        [id, leaseToken],
      );
      if (!completed.rows[0]) throw new ConflictScanLeaseLostError();
      await this.audit.appendTo(tx, {
        ts: completedAt,
        actor: String(row.requested_by),
        agentId: String(row.requested_key_id),
        op: "conflict_scan",
        memoryId: null,
        namespace: target,
        purpose: "organization-conflict-scan-complete",
        result: "ok",
        detail: `scan_id=${id} items=${facts.length}/${total} candidates=${candidates.length} ` +
          `model_decisions=${modelDecisions} contradictions=${publishable.length} ` +
          `new=${newFindings} existing=${existingFindings} ` +
          `gaps=${gaps.length} model=${this.classifier?.model ?? "unavailable"}`,
      });
    });
  }

  async runOnce(): Promise<{ claimed: number; completed: number; failed: number }> {
    const queued = await this.db.query(
      `SELECT * FROM conflict_scan_runs
        WHERE (status = 'queued' AND NOT EXISTS (
                 SELECT 1 FROM conflict_scan_runs active
                  WHERE active.status = 'running'
                    AND COALESCE(active.heartbeat_at,active.started_at) >=
                        CURRENT_TIMESTAMP - INTERVAL '5 minutes'
               ))
           OR (status = 'running' AND COALESCE(heartbeat_at,started_at) <
               CURRENT_TIMESTAMP - INTERVAL '5 minutes')
        ORDER BY requested_at,id LIMIT 1`,
    );
    const row = queued.rows[0] as Record<string, unknown> | undefined;
    if (!row) return { claimed: 0, completed: 0, failed: 0 };
    const claimedAt = new Date().toISOString();
    const leaseToken = ulid();
    const claim = await this.db.query(
      `UPDATE conflict_scan_runs SET status = 'running', phase = 'collecting',
          started_at = CASE WHEN status = 'queued' THEN $2 ELSE started_at END,
          heartbeat_at = $2, lease_token = $3
        WHERE id = $1 AND ((status = 'queued' AND NOT EXISTS (
            SELECT 1 FROM conflict_scan_runs active
             WHERE active.status = 'running' AND active.id <> $1
               AND COALESCE(active.heartbeat_at,active.started_at) >=
                   CURRENT_TIMESTAMP - INTERVAL '5 minutes'))
          OR (status = 'running' AND COALESCE(heartbeat_at,started_at) <
              CURRENT_TIMESTAMP - INTERVAL '5 minutes'))
        RETURNING id`,
      [row.id, claimedAt, leaseToken],
    );
    if (!claim.rows[0]) return { claimed: 0, completed: 0, failed: 0 };
    try {
      await this.execute({ ...row, status: "running", phase: "collecting", started_at: claimedAt }, leaseToken);
      return { claimed: 1, completed: 1, failed: 0 };
    } catch (error) {
      const completedAt = new Date().toISOString();
      const transitioned = await this.db.transaction(async (tx) => {
        const failed = await tx.query(
          `UPDATE conflict_scan_runs SET status = 'failed', phase = 'complete',
              failure_code = 'scan_failed', completed_at = $2
            WHERE id = $1 AND status = 'running' AND lease_token = $3 RETURNING id`,
          [row.id, completedAt, leaseToken],
        );
        if (!failed.rows[0]) return false;
        await this.audit.appendTo(tx, {
          ts: completedAt,
          actor: String(row.requested_by),
          agentId: String(row.requested_key_id),
          op: "conflict_scan",
          memoryId: null,
          namespace: String(row.target_namespace),
          purpose: "organization-conflict-scan-complete",
          result: "error",
          detail: `scan_id=${String(row.id)} code=scan_failed`,
        });
        return true;
      });
      if (!transitioned || error instanceof ConflictScanLeaseLostError) {
        return { claimed: 1, completed: 0, failed: 0 };
      }
      return { claimed: 1, completed: 0, failed: 1 };
    }
  }

  /**
   * Conflicts the autopilot settled by itself (CA11). Read with the same
   * authority and the same evidence-currency rules as the review queue, so the
   * ledger can never show a decision over evidence the caller may not see.
   *
   * A retired fact is no longer currently valid, so this deliberately does NOT
   * require both sides to be live — that is exactly what an auto-decision did.
   */
  async listAutoDecisions(identity: Identity, limit = 50): Promise<ConflictAutoDecisionView[]> {
    if (identity.role === "agent" || identity.role === "member" ||
      (identity.namespace === "" && !isRootOwner(identity))) {
      await this.auditDenied(identity, "organization-conflict-finding-read");
      throw new AuthzError("conflict findings require an administrative role");
    }
    const capped = Math.max(1, Math.min(200, Math.trunc(limit)));
    const result = await this.db.query(
      `SELECT f.*,
              rp.id AS repair_proposal_id,rp.classification AS repair_classification,
              l.namespace AS l_namespace,l.scope AS l_scope,l.content AS l_content,
              l.confidence AS l_confidence,l.provenance AS l_provenance,l.assertion_time AS l_assertion_time,
              r.namespace AS r_namespace,r.scope AS r_scope,r.content AS r_content,
              r.confidence AS r_confidence,r.provenance AS r_provenance,r.assertion_time AS r_assertion_time
         FROM conflict_scan_findings f
         JOIN memory_objects l ON l.id = f.left_memory_id
         JOIN memory_objects r ON r.id = f.right_memory_id
         LEFT JOIN conflict_repair_proposals rp
           ON rp.source_type = 'auto_resolution' AND rp.source_id = f.id
          AND rp.detector_version = $4 AND rp.status = 'open'
        WHERE f.status = 'auto_resolved'
          AND ($1 = '' OR f.target_namespace = $1 OR f.target_namespace LIKE $2 ESCAPE '\\')
          AND l.tier = 'L2' AND r.tier = 'L2'
        ORDER BY f.resolved_at DESC NULLS LAST, f.id
        LIMIT $3`,
      [identity.namespace, `${escapeLikePattern(identity.namespace)}/%`, capped,
        DETECTOR_VERSION],
    );
    const sourceNames = await this.resolveSourceNames(result.rows);
    return result.rows.map((entry) => {
      const row = entry as Record<string, unknown>;
      const leftId = String(row.left_memory_id) as MemoryId;
      const rightId = String(row.right_memory_id) as MemoryId;
      const resolution = row.resolution === "keep-right" ? "keep-right" : "keep-left";
      // The rule is READ, never inferred from which side was kept: "kept the
      // left side" is reachable by more than one rule, so a re-derivation shows
      // the reviewer a confident explanation that can simply be false.
      const rule = (row.auto_rule ?? "equal-trust-newest-wins") as ConflictAutoRule;
      return {
        id: String(row.id),
        targetNamespace: String(row.target_namespace),
        entity: String(row.entity),
        category: row.category as DisputeCategory,
        reason: String(row.reason),
        confidence: Number(row.confidence),
        flags: json<ConflictFindingFlag[]>(row.flags, []),
        rowVersion: Number(row.row_version),
        resolution,
        rule,
        decidedAt: row.resolved_at == null ? iso(row.last_seen_at) : iso(row.resolved_at),
        repairProposed: row.repair_proposal_id != null,
        repairClassification: row.repair_classification == null
          ? null
          : String(row.repair_classification),
        left: this.factView(row, "l", leftId, sourceNames),
        right: this.factView(row, "r", rightId, sourceNames),
      };
    });
  }

  /** Registered knowledge-base display names for every provenance sourceId. */
  private async resolveSourceNames(
    rows: readonly unknown[],
  ): Promise<Map<string, string>> {
    const sourceIds = [...new Set(rows.flatMap((entry) => {
      const row = entry as Record<string, unknown>;
      return (["l", "r"] as const).flatMap((side) => {
        const id = json<ProvenanceEntry[]>(row[`${side}_provenance`], [])[0]?.sourceId;
        return id ? [id] : [];
      });
    }))];
    const names = new Map<string, string>();
    if (sourceIds.length === 0) return names;
    const named = await this.db.query(
      `SELECT source_id, name FROM knowledge_bases
        WHERE source_id = ANY($1::text[]) AND source_id IS NOT NULL`,
      [sourceIds],
    );
    for (const entry of named.rows) {
      const value = entry as Record<string, unknown>;
      names.set(String(value.source_id), String(value.name));
    }
    return names;
  }

  private factView(
    row: Record<string, unknown>,
    side: "l" | "r",
    id: MemoryId,
    sourceNames: Map<string, string>,
  ): ConflictFindingFactView {
    const provenance = json<ProvenanceEntry[]>(row[`${side}_provenance`], []);
    const first = provenance[0];
    const sourceId = first?.sourceId ?? null;
    return {
      id,
      namespace: String(row[`${side}_namespace`]),
      content: String(row[`${side}_content`]),
      scope: row[`${side}_scope`] as Scope,
      confidence: Number(row[`${side}_confidence`]),
      source: first?.source ?? "unknown",
      sourceId,
      sourceName: sourceId === null ? null : sourceNames.get(sourceId) ?? null,
      actor: first?.actor ?? "unknown",
      session: first?.session ?? null,
      assertionTime: iso(row[`${side}_assertion_time`]),
    };
  }

  async listFindings(identity: Identity): Promise<ConflictScanFindingView[]> {
    if (identity.role === "agent" || identity.role === "member" ||
      (identity.namespace === "" && !isRootOwner(identity))) {
      await this.auditDenied(identity, "organization-conflict-finding-read");
      throw new AuthzError("conflict findings require an administrative role");
    }
    const result = await this.db.query(
      `SELECT f.*,
              l.namespace AS l_namespace,l.scope AS l_scope,l.content AS l_content,
              l.confidence AS l_confidence,l.provenance AS l_provenance,l.assertion_time AS l_assertion_time,
              r.namespace AS r_namespace,r.scope AS r_scope,r.content AS r_content,
              r.confidence AS r_confidence,r.provenance AS r_provenance,r.assertion_time AS r_assertion_time
         FROM conflict_scan_findings f
         JOIN memory_objects l ON l.id = f.left_memory_id
         JOIN memory_objects r ON r.id = f.right_memory_id
        WHERE f.status = 'open'
          AND f.detector_version = $3
          AND ($1 = '' OR f.target_namespace = $1 OR f.target_namespace LIKE $2 ESCAPE '\\')
          AND l.status = 'active' AND l.t_valid_to IS NULL AND l.tier = 'L2'
          AND r.status = 'active' AND r.t_valid_to IS NULL AND r.tier = 'L2'
          AND (l.ttl_seconds IS NULL OR l.assertion_time + l.ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
          AND (r.ttl_seconds IS NULL OR r.assertion_time + r.ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
        ORDER BY f.last_seen_at DESC, f.id`,
      [identity.namespace, `${escapeLikePattern(identity.namespace)}/%`, DETECTOR_VERSION],
    );
    // S11 must name the thing a reviewer recognises, not the ULID the write
    // path stamped. Resolve registered knowledge-base names in one read.
    const sourceIds = [...new Set(result.rows.flatMap((entry) => {
      const row = entry as Record<string, unknown>;
      return (["l", "r"] as const).flatMap((side) => {
        const id = json<ProvenanceEntry[]>(row[`${side}_provenance`], [])[0]?.sourceId;
        return id ? [id] : [];
      });
    }))];
    const sourceNames = new Map<string, string>();
    if (sourceIds.length > 0) {
      const named = await this.db.query(
        `SELECT source_id, name FROM knowledge_bases
          WHERE source_id = ANY($1::text[]) AND source_id IS NOT NULL`,
        [sourceIds],
      );
      for (const entry of named.rows) {
        const value = entry as Record<string, unknown>;
        sourceNames.set(String(value.source_id), String(value.name));
      }
    }
    const fact = (row: Record<string, unknown>, side: "l" | "r", id: MemoryId): ConflictFindingFactView => {
      const provenance = json<ProvenanceEntry[]>(row[`${side}_provenance`], []);
      const first = provenance[0];
      const sourceId = first?.sourceId ?? null;
      return {
        id,
        namespace: String(row[`${side}_namespace`]),
        content: String(row[`${side}_content`]),
        scope: row[`${side}_scope`] as Scope,
        confidence: Number(row[`${side}_confidence`]),
        source: first?.source ?? "unknown",
        sourceId,
        sourceName: sourceId === null ? null : sourceNames.get(sourceId) ?? null,
        actor: first?.actor ?? "unknown",
        session: first?.session ?? null,
        assertionTime: iso(row[`${side}_assertion_time`]),
      };
    };
    return result.rows.map((entry) => {
      const row = entry as Record<string, unknown>;
      const leftId = String(row.left_memory_id) as MemoryId;
      const rightId = String(row.right_memory_id) as MemoryId;
      return {
        origin: (row.origin === "write" ? "write" : "scan") as "scan" | "write",
        id: String(row.id),
        scanId: row.last_scan_id == null ? null : String(row.last_scan_id),
        targetNamespace: String(row.target_namespace),
        entity: String(row.entity),
        category: row.category as DisputeCategory,
        reason: String(row.reason),
        confidence: Number(row.confidence),
        flags: json<ConflictFindingFlag[]>(row.flags, []),
        status: row.status as "open" | "acknowledged",
        rowVersion: Number(row.row_version),
        firstSeenAt: iso(row.first_seen_at),
        lastSeenAt: iso(row.last_seen_at),
        left: fact(row, "l", leftId),
        right: fact(row, "r", rightId),
      };
    });
  }

  /**
   * How many conflicts are open for this caller RIGHT NOW — the number S11
   * lists. It is deliberately `listFindings().length` rather than a parallel
   * COUNT(*): a second query with its own predicate is how the S6 tile and the
   * S11 queue drifted apart in the first place. Open findings are a reviewable
   * queue, so the set is small by construction.
   */
  async countOpenFindings(identity: Identity): Promise<number> {
    return (await this.listFindings(identity)).length;
  }

  /**
   * A reviewer picks the side that is right. The other fact's validity is
   * closed (D7 — never deleted, never overwritten) and the kept fact links to
   * it, so the contradiction leaves live memory instead of being re-published
   * by the next scan.
   */
  async resolve(
    identity: Identity,
    id: string,
    keep: "left" | "right",
    expectedRowVersion: number,
  ): Promise<{ id: string; status: "resolved"; rowVersion: number; keptMemoryId: MemoryId; retiredMemoryId: MemoryId }> {
    const current = await this.db.query(
      `SELECT target_namespace,status,row_version,left_memory_id,right_memory_id
         FROM conflict_scan_findings WHERE id = $1`,
      [id],
    );
    const row = current.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new ConflictFindingNotFoundError();
    try {
      assertRequester(identity, String(row.target_namespace));
    } catch (error) {
      await this.auditDenied(identity, "conflict-scan-finding-resolve");
      throw error;
    }
    if (row.status !== "open" || Number(row.row_version) !== expectedRowVersion) {
      throw new ConflictFindingConflictError();
    }
    const target = String(row.target_namespace);
    const kept = String(keep === "left" ? row.left_memory_id : row.right_memory_id) as MemoryId;
    const retired = String(keep === "left" ? row.right_memory_id : row.left_memory_id) as MemoryId;
    const ts = new Date().toISOString();
    const rowVersion = await this.db.transaction(async (tx) => {
      const claimed = await tx.query(
        `UPDATE conflict_scan_findings
            SET status = 'resolved', resolution = $2, resolution_memory_id = $3,
                resolved_by = $4, resolved_at = $5, last_seen_at = $5,
                row_version = row_version + 1
          WHERE id = $1 AND status = 'open' AND row_version = $6
          RETURNING row_version`,
        [id, keep === "left" ? "keep-left" : "keep-right", kept, identity.actor, ts,
          expectedRowVersion],
      );
      if (!claimed.rows[0]) throw new ConflictFindingConflictError();
      // Guarded close, same discipline as the dispute lane: zero rows means the
      // retired fact stopped being currently valid since the scan published the
      // finding, so the whole resolution rolls back rather than half-applying.
      const closed = await tx.query(
        `UPDATE memory_objects SET t_valid_to = $2
          WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL
          RETURNING id`,
        [retired, ts],
      );
      if (!closed.rows[0]) throw new ConflictFindingConflictError();
      // Only when the kept fact heads no chain of its own: overwriting an
      // existing supersedence link would erase the history it points at.
      await tx.query(
        `UPDATE memory_objects SET supersedes = $2 WHERE id = $1 AND supersedes IS NULL`,
        [kept, retired],
      );
      // Every other open finding that cited the retired fact has lost its
      // evidence. Closing them keeps the queue and its count honest instead of
      // leaving rows that only the read-time join hides.
      await tx.query(
        `UPDATE conflict_scan_findings
            SET status = 'dismissed', row_version = row_version + 1, last_seen_at = $2
          WHERE status = 'open' AND id <> $3
            AND (left_memory_id = $1 OR right_memory_id = $1)`,
        [retired, ts, id],
      );
      await this.audit.appendTo(tx, {
        ts, actor: identity.actor, agentId: identity.keyId,
        op: "supersede", memoryId: retired, namespace: target,
        purpose: "conflict-scan-finding-resolve", result: "ok",
        detail: `validity closed; finding ${id} kept ${kept}`,
      });
      await this.audit.appendTo(tx, {
        ts, actor: identity.actor, agentId: identity.keyId,
        op: "resolve", memoryId: kept, namespace: target,
        purpose: "conflict-scan-finding-resolve", result: "ok",
        detail: `finding_id=${id} action=keep-${keep} retired=${retired}`,
      });
      return Number(claimed.rows[0].row_version);
    });
    return { id, status: "resolved", rowVersion, keptMemoryId: kept, retiredMemoryId: retired };
  }

  /**
   * Reverse an automatic decision (CA4). The retired fact is re-opened and the
   * previously kept fact is closed instead — still a validity swap plus link,
   * never a delete, and still fully audited. This is what makes autonomy safe:
   * the autopilot may act unattended precisely because a person can undo it.
   */
  async overturn(
    identity: Identity,
    id: string,
    expectedRowVersion: number,
  ): Promise<{ id: string; status: "overturned"; rowVersion: number; keptMemoryId: MemoryId; retiredMemoryId: MemoryId }> {
    const current = await this.db.query(
      `SELECT f.target_namespace,f.status,f.row_version,f.left_memory_id,f.right_memory_id,f.resolution,
              rp.id AS repair_proposal_id
         FROM conflict_scan_findings f
         LEFT JOIN conflict_repair_proposals rp
           ON rp.source_type='auto_resolution' AND rp.source_id=f.id
          AND rp.detector_version=$2 AND rp.status='open'
        WHERE f.id = $1`,
      [id, DETECTOR_VERSION],
    );
    const row = current.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new ConflictFindingNotFoundError();
    try {
      assertRequester(identity, String(row.target_namespace));
    } catch (error) {
      await this.auditDenied(identity, "conflict-scan-finding-overturn");
      throw error;
    }
    if (row.status !== "auto_resolved" || Number(row.row_version) !== expectedRowVersion) {
      throw new ConflictFindingConflictError();
    }
    // Swap the sides the autopilot chose.
    const previouslyKept = String(row.resolution === "keep-right" ? row.right_memory_id : row.left_memory_id) as MemoryId;
    const previouslyRetired = String(row.resolution === "keep-right" ? row.left_memory_id : row.right_memory_id) as MemoryId;
    const target = String(row.target_namespace);
    const ts = new Date().toISOString();
    const repairProposalId = row.repair_proposal_id == null
      ? null
      : String(row.repair_proposal_id);
    const rowVersion = await this.db.transaction(async (tx) => {
      if (repairProposalId !== null) {
        const claimed = await tx.query(
          `UPDATE conflict_scan_findings
              SET status='resolved',resolved_by=$2,resolved_at=$3,last_seen_at=$3,
                  row_version=row_version+1
            WHERE id=$1 AND status='auto_resolved' AND row_version=$4
            RETURNING row_version`,
          [id, identity.actor, ts, expectedRowVersion],
        );
        if (!claimed.rows[0]) throw new ConflictFindingConflictError();
        // Repair only the exact historical chain that the automatic decision
        // created. If either side changed later, roll back and mark nothing.
        const edge = await tx.query(
          `UPDATE memory_objects SET supersedes=NULL
            WHERE id=$1 AND status='active' AND t_valid_to IS NULL AND supersedes=$2
            RETURNING id`,
          [previouslyKept, previouslyRetired],
        );
        if (!edge.rows[0]) throw new ConflictFindingConflictError();
        const reopened = await tx.query(
          `UPDATE memory_objects SET t_valid_to=NULL
            WHERE id=$1 AND status='active' AND t_valid_to IS NOT NULL
            RETURNING id`,
          [previouslyRetired],
        );
        if (!reopened.rows[0]) throw new ConflictFindingConflictError();
        const proposal = await tx.query(
          `UPDATE conflict_repair_proposals
              SET status='applied',resolved_at=$2,resolved_by=$3
            WHERE id=$1 AND status='open' RETURNING id`,
          [repairProposalId, ts, identity.actor],
        );
        if (!proposal.rows[0]) throw new ConflictFindingConflictError();
        await this.audit.appendTo(tx, {
          ts, actor: identity.actor, agentId: identity.keyId,
          op: "resolve", memoryId: previouslyRetired, namespace: target,
          purpose: "historical-conflict-repair", result: "ok",
          detail: `finding_id=${id} repair=restore-both detector=${DETECTOR_VERSION}`,
        });
        return Number(claimed.rows[0].row_version);
      }
      const claimed = await tx.query(
        `UPDATE conflict_scan_findings
            SET status = 'resolved',
                resolution = $2, resolution_memory_id = $3,
                resolved_by = $4, resolved_at = $5, last_seen_at = $5,
                row_version = row_version + 1
          WHERE id = $1 AND status = 'auto_resolved' AND row_version = $6
          RETURNING row_version`,
        [id, row.resolution === "keep-right" ? "keep-left" : "keep-right",
          previouslyRetired, identity.actor, ts, expectedRowVersion],
      );
      if (!claimed.rows[0]) throw new ConflictFindingConflictError();
      // Re-open the fact the autopilot retired. Guarded on the exact validity
      // stamp being present, so a fact retired by something ELSE since then is
      // never silently resurrected by an overturn.
      const reopened = await tx.query(
        `UPDATE memory_objects SET t_valid_to = NULL
          WHERE id = $1 AND status = 'active' AND t_valid_to IS NOT NULL
          RETURNING id`,
        [previouslyRetired],
      );
      if (!reopened.rows[0]) throw new ConflictFindingConflictError();
      const closed = await tx.query(
        `UPDATE memory_objects SET t_valid_to = $2
          WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL
          RETURNING id`,
        [previouslyKept, ts],
      );
      if (!closed.rows[0]) throw new ConflictFindingConflictError();
      // The old chain link pointed kept -> retired; it now points the other way.
      await tx.query(
        `UPDATE memory_objects SET supersedes = NULL WHERE id = $1 AND supersedes = $2`,
        [previouslyKept, previouslyRetired],
      );
      await tx.query(
        `UPDATE memory_objects SET supersedes = $2 WHERE id = $1 AND supersedes IS NULL`,
        [previouslyRetired, previouslyKept],
      );
      await this.audit.appendTo(tx, {
        ts, actor: identity.actor, agentId: identity.keyId,
        op: "supersede", memoryId: previouslyKept, namespace: target,
        purpose: "conflict-autopilot-overturn", result: "ok",
        detail: `validity closed; overturned finding ${id}`,
      });
      await this.audit.appendTo(tx, {
        ts, actor: identity.actor, agentId: identity.keyId,
        op: "resolve", memoryId: previouslyRetired, namespace: target,
        purpose: "conflict-autopilot-overturn", result: "ok",
        detail: `finding_id=${id} overturned automatic decision; retired=${previouslyKept}`,
      });
      return Number(claimed.rows[0].row_version);
    });
    return {
      id,
      status: "overturned",
      rowVersion,
      keptMemoryId: previouslyRetired,
      retiredMemoryId: previouslyKept,
    };
  }

  async review(
    identity: Identity,
    id: string,
    action: "acknowledge" | "dismiss",
    expectedRowVersion: number,
  ): Promise<{ id: string; status: "acknowledged" | "dismissed"; rowVersion: number }> {
    const current = await this.db.query(
      `SELECT target_namespace,status,row_version FROM conflict_scan_findings WHERE id = $1`,
      [id],
    );
    const row = current.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new ConflictFindingNotFoundError();
    try {
      assertRequester(identity, String(row.target_namespace));
    } catch (error) {
      await this.auditDenied(identity, "conflict-scan-finding-review");
      throw error;
    }
    if (row.status !== "open" || Number(row.row_version) !== expectedRowVersion) {
      throw new ConflictFindingConflictError();
    }
    const status = action === "acknowledge" ? "acknowledged" : "dismissed";
    const updated = await this.db.query(
      `UPDATE conflict_scan_findings SET status = $2,row_version = row_version + 1,last_seen_at = $3
        WHERE id = $1 AND status = 'open' AND row_version = $4 RETURNING row_version`,
      [id, status, new Date().toISOString(), expectedRowVersion],
    );
    if (!updated.rows[0]) throw new ConflictFindingConflictError();
    await this.audit.append({
      ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
      op: "conflict_scan", memoryId: null, namespace: String(row.target_namespace),
      purpose: "conflict-scan-finding-review", result: "ok",
      detail: `finding_id=${id} action=${action}`,
    });
    return { id, status, rowVersion: Number(updated.rows[0].row_version) };
  }
}
