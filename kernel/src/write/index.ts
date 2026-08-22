/**
 * Module E — write path.
 *
 * Pipeline: extraction → verifier → entity resolution → exact dedupe → insert.
 * Semantic similarity never changes fact validity. Every committed fact is
 * queued for the Halo-owned Luna context judge, and any confirmed conflict is
 * presented for human resolution.
 */

import { ulid } from "ulid";
import type {
  AuditEvent,
  AuditOp,
  DisputeCategory,
  Embedder,
  ExtractionMode,
  LlmClient,
  MemoryId,
  MemoryObject,
  Namespace,
  PolicyConfig,
  ProvenanceEntry,
  Scope,
  SourceAccess,
  WriteRequest,
  WriteResult,
} from "../types.js";
import type { KernelConfig } from "../config.js";
import type { ConflictReviewMode } from "../policy/store.js";
import {
  CLASSIFY_SYSTEM,
  EXTRACT_SYSTEM,
  VERIFY_BATCH_SYSTEM,
  VERIFY_SYSTEM,
  buildClassifyPrompt,
  buildVerifyBatchPrompt,
  buildVerifyPrompt,
  capitalizedWords,
  heuristicDisputeCategory,
  parseLooseJson,
} from "../llm/index.js";
import {
  EntityRegistry,
  EntityResolutionConflictError,
  type DbLike,
  type PreparedEntityResolution,
} from "./entities.js";
import { HashEmbedder } from "../embed/index.js";
import { LlmUnavailableError } from "../resilience/index.js";
import { assertDestinationAllowed, classifyData } from "../dlp/index.js";
import { enqueueConflictCheck, enqueueEntityTag } from "../conflict-autopilot/queue.js";

export { EntityRegistry, toVectorLiteral } from "./entities.js";
export type { DbLike } from "./entities.js";

// ---------------------------------------------------------------------------
// Structural interfaces for module-A collaborators (module A owns the real
// implementations — MemoryIndex and AuditLog satisfy these shapes).
// ---------------------------------------------------------------------------

export interface VectorHit {
  obj: MemoryObject;
  /** Cosine similarity = 1 - cosine distance; higher = more similar. */
  similarity: number;
}

export interface MemoryIndexLike {
  /** Insert a memory object with its embedding (pgvector literal binding). */
  insert(obj: MemoryObject, embedding: number[] | null): Promise<void>;
  /**
   * Top-k cosine search among currently-valid (t_valid_to IS NULL), active
   * facts visible from this namespace. Implementations that support the
   * optional flags (the real MemoryIndex does) restrict to currently-valid
   * rows (`validOnly`) and to EXACTLY this namespace (`ownNamespaceOnly`) —
   * the write path passes both so dedupe/supersedence candidates are never
   * crowded out of the k-window by closer ancestor-namespace rows.
   */
  vectorSearch(
    namespace: Namespace,
    embedding: number[],
    k: number,
    validOnly?: boolean,
    ownNamespaceOnly?: boolean,
    includePointers?: boolean,
    access?: SourceAccess,
  ): Promise<VectorHit[]>;
  /** Telemetry: access_count += 1, last_accessed = now. */
  bumpAccess(ids: MemoryId[]): Promise<void>;
  /**
   * Close the validity interval: t_valid_to = ts. Guarded implementations
   * (the real MemoryIndex) only close a currently-valid row and return the
   * number of rows closed — 0 signals a concurrent writer already closed the
   * victim. Hermetic test implementations may return void (treated as ok).
   */
  closeValidity(id: MemoryId, ts: string): Promise<number | void>;
}

export interface AuditSink {
  append(event: AuditEvent): Promise<void>;
}

export interface WritePathDeps {
  db: DbLike;
  index: MemoryIndexLike;
  audit: AuditSink;
  embedder: Embedder;
  llm: LlmClient;
  config: KernelConfig;
  /**
   * M1 (exit criterion 3): run `fn` against a transaction-scoped view of the
   * memory index — insert + closeValidity of a supersedence become atomic.
   * The kernel wires this to Db.transaction + a tx-scoped MemoryIndex.
   * Optional: hermetic unit tests that hand-roll `index` fall back to the
   * insert-first sequential order (old behavior, still never loses the prior
   * fact — worst case both rows are briefly valid).
   */
  transact?<T>(
    fn: (
      txIndex: MemoryIndexLike,
      txAudit: AuditSink,
      /** Same transaction handle used by txIndex/txAudit for entity mutations. */
      txDb?: DbLike,
    ) => Promise<T>,
  ): Promise<T>;
  /**
   * Optional kernel-owned fence evaluated inside every transaction before its
   * first mutation. Policy uploads use this to prove that their attempt still
   * owns an unexpired processing lease.
   */
  beforeCommit?(txDb: DbLike, req: WriteRequest): Promise<void>;
}

/** Lower bound of the conflicting-update band; upper bound is the policy's dedupe threshold. */
export const SUPERSEDE_MIN_COSINE = 0.75;

function normalizedExactFact(content: string): string {
  return content
    .replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "")
    .trim()
    .replace(/\s+/g, " ");
}

/** Kernel-internal observations; never become part of the public WriteResult. */
export interface WritePathHooks {
  onDeduplicated?(obj: MemoryObject): void;
  /** Kernel-owned progress only; never receives document or fact content. */
  onStage?(stage: "extraction" | "embedding"): void | Promise<void>;
}

/**
 * Trust lattice over provenance sources. The supersedence decision compares
 * ranks: equal rank → recency wins (pre-dispute behavior, unchanged); the
 * incoming write outranking the incumbent → supersede as before; underranking
 * → quarantine as "disputed" (subject to the conflictReview policy dial).
 * Human-entered facts sit above connector-imported documents, which sit above
 * consolidation output, bulk swap-imports, and finally agent conversation.
 */
export const TRUST_RANK: Record<ProvenanceEntry["source"], number> = {
  manual: 50,
  document: 40,
  // M6 (D14): a live-fetched fact is read straight from the source of truth —
  // it ranks with connector documents, so a fresh live result supersedes a
  // stale cached copy (equal rank → recency) and agent conversation.
  "live-fetch": 40,
  consolidation: 30,
  "swap-import": 20,
  conversation: 10,
};

/** Effective policy shape the write path consumes (base + the conflict-review dial). */
export type WritePolicy = PolicyConfig & {
  conflictReview?: ConflictReviewMode;
  restrictedDestinations?: string[];
  dataRegion?: string;
};

function governedClassification(content: string, req: WriteRequest, policy: WritePolicy) {
  const supplied = req.provenance?.classification;
  const policyDestinations = policy.restrictedDestinations ?? [];
  const allowedDestinations = supplied?.allowedDestinations
    ? supplied.allowedDestinations.filter((destination) => policyDestinations.includes(destination))
    : policyDestinations;
  return classifyData(content, {
    sensitivity: supplied?.sensitivity,
    piiSubjects: supplied?.piiSubjects,
    secretKinds: supplied?.secretKinds,
    residency: supplied?.residency,
    allowedDestinations,
  });
}

/**
 * Thrown INSIDE the supersede transaction when the guarded closeValidity
 * matched zero rows: a concurrent writer closed the same victim between our
 * decision (vectorSearch, outside the transaction) and the commit. The
 * transaction rolls back (insert included) and the decision is re-run
 * against fresh state.
 */
export class SupersedeConflictError extends Error {
  constructor(readonly victimId: MemoryId) {
    super(`supersede conflict: ${victimId} was closed by a concurrent writer`);
    this.name = "SupersedeConflictError";
  }
}

/** Bounded re-decisions after a supersede conflict before giving up. */
const MAX_SUPERSEDE_ATTEMPTS = 3;

/**
 * Bounded candidate re-runs after the entity registry drifted between
 * prepare() and the commit transaction (a concurrent writer registered a
 * similar entity mid-window). The rolled-back attempt committed nothing, so
 * re-running the candidate from a FRESH preparation is safe - and converges,
 * because the colliding entity now exists and resolves as an exact match,
 * which cannot conflict. Without this retry, concurrent multi-file ingestion
 * of entity-dense documents fails deterministically on shared mentions
 * (production 2026-08-20: "entity resolution changed while writing: UPS").
 */
export const MAX_ENTITY_RESOLUTION_ATTEMPTS = 3;

/**
 * Candidates verified per batched model call. Each verdict is ~10 completion
 * tokens, so 25 sits far inside the 4096-token Azure completion budget even
 * with a reasoning deployment's thinking overhead; the conflict lane batches
 * 50 under the same budget with a fatter per-item payload.
 */
export const VERIFY_BATCH_SIZE = 25;

interface Candidate {
  content: string;
  scope: Scope;
  eventTime: string | null;
  entities: string[];
  confidence: number;
  /** CA9: how this candidate was produced, stamped onto the stored fact. */
  extraction: ExtractionMode;
}

/**
 * The reserved trailing entity-annotation marker (`[entities: …]`) — the SAME
 * shape the read side (DbFragmentationReader.parseEntitiesAnnotation) matches.
 * The write path owns this marker; source content must never smuggle one in.
 */
const ENTITIES_ANNOTATION = /\s*\[entities:\s*[^\]]*\]\s*$/;

const GENERIC_ENTITY_WORDS = new Set([
  "a", "an", "and", "current", "document", "file", "memory", "new", "policy",
  "statement", "the", "this", "today", "user",
]);

function annotationEntities(content: string): string[] {
  const match = content.match(/\[entities:\s*([^\]]*)\]\s*$/i);
  if (!match?.[1]) return [];
  return match[1].split(",").map((value) => value.trim()).filter(Boolean);
}

function meaningfulEntityNames(values: string[]): string[] {
  return values
    .map((value) => value.trim().toLocaleLowerCase())
    .filter((value) => value.length > 1 && !GENERIC_ENTITY_WORDS.has(value));
}

/** Reject extraction artifacts that describe the upload instead of its claims. */
function isLowInformationFact(content: string): boolean {
  const text = stripEntitiesAnnotation(content).trim().toLocaleLowerCase();
  return (
    /\b(?:has|contains|includes|uses)\s+(?:the\s+)?(?:test\s+)?marker\b/.test(text) ||
    /\b(?:file|document|statement|text)\s+(?:name|title|heading|marker)\b/.test(text) ||
    /\bsynthetic\s+conflict\s+detection\s+verification\b/.test(text)
  );
}

/** Remove a trailing source-supplied `[entities: …]` so it can't be forged. */
function stripEntitiesAnnotation(content: string): string {
  return content.replace(ENTITIES_ANNOTATION, "");
}

/**
 * Connector facts are version-owned. A retry may dedupe against the same
 * document version, but a new hash/document/source must land independently so
 * lifecycle acknowledgement can retire only the exact previous version.
 */
function isSameDocumentVersion(req: WriteRequest, obj: MemoryObject): boolean {
  const requested = req.provenance;
  if (!requested?.sourceId || !requested.documentKey) {
    return true;
  }
  // M6 (D11/D14): pointer refreshes and live-cache confirmations target the
  // same logical source object, not only the same content version. Matching on
  // (sourceId, documentKey) lets a changed live row close the stale cached
  // version through D7 while retaining both versions' exact content hashes.
  // Ordinary sync/import facts keep the exact-version fence below unchanged;
  // their SourceState owns changed-version retirement.
  if (requested.pointer || requested.source === "live-fetch") {
    return obj.provenance.some(
      (entry) =>
        entry.sourceId === requested.sourceId &&
        entry.documentKey === requested.documentKey,
    );
  }
  if (!requested.contentHash) {
    return true;
  }
  return obj.provenance.some(
    (entry) =>
      entry.sourceId === requested.sourceId &&
      entry.documentKey === requested.documentKey &&
      entry.contentHash === requested.contentHash,
  );
}

export class WritePath {
  private readonly entities: EntityRegistry;
  private readonly localEmbedder: HashEmbedder;

  constructor(private readonly deps: WritePathDeps) {
    this.entities = new EntityRegistry(deps.db, deps.embedder, deps.llm);
    this.localEmbedder = new HashEmbedder(deps.embedder.dim);
  }

  async write(
    req: WriteRequest,
    policy: WritePolicy,
    /** Agent identity for audit attribution (D4); defaults to the actor. */
    agentId: string = req.actor,
    hooks?: WritePathHooks,
  ): Promise<WriteResult> {
    const now = new Date().toISOString();
    const inputClassification = governedClassification(req.content, req, policy);
    if (!req.hints?.verbatim) {
      assertDestinationAllowed(inputClassification, "llm-extraction", {
        region: policy.dataRegion,
      });
    }
    const result: WriteResult = {
      stored: [],
      rejected: [],
      superseded: [],
      deduplicated: 0,
    };

    // a. Extraction.
    await hooks?.onStage?.("extraction");
    const candidates = await this.extract(req);

    // b (hoisted). One verifier call covers every extracted candidate —
    // per-fact calls re-sent the whole transcript per candidate, which made
    // verification the write path's dominant model spend on multi-fact
    // documents. Runs BEFORE any candidate commits, so an LLM outage here
    // propagates with zero progress and the caller's verbatim fallback stays
    // safe to re-run (nothing committed to duplicate).
    const verdicts = await this.verifyCandidates(req, policy, candidates, now);

    for (const [index, cand] of candidates.entries()) {
      // M6 (D14): the caller's hard cap on STORED facts (the L4 write-back
      // passes its remaining per-fault cache budget). Checked before each
      // candidate — extraction fan-out can never land more rows than the cap,
      // and the overflow is reported, not silently dropped.
      if (req.maxFacts !== undefined && result.stored.length >= req.maxFacts) {
        result.rejected.push({ candidate: cand.content, reason: "max-facts-cap" });
        continue;
      }
      try {
        // Entity-registry drift between prepare() and the commit transaction
        // retries the whole candidate: the transaction rolled back, so a
        // fresh preparation inside processCandidate re-reads current state
        // and (normally) resolves the colliding mention as an exact match.
        // Any other failure - and a conflict that persists past the bound -
        // propagates to the handler below unchanged.
        for (let entityAttempt = 1; ; entityAttempt++) {
          try {
            await this.processCandidate(req, policy, agentId, now, cand, verdicts[index] ?? false, result, hooks);
            break;
          } catch (err) {
            if (
              err instanceof EntityResolutionConflictError &&
              entityAttempt < MAX_ENTITY_RESOLUTION_ATTEMPTS
            ) {
              continue;
            }
            throw err;
          }
        }
      } catch (err) {
        // An LLM circuit that opens MID-write — after earlier candidates
        // were already committed — must never surface as a whole-write
        // failure: the caller's verbatim fallback would re-run the ENTIRE
        // write, duplicating the committed facts (plus their supersede/
        // audit/cost rows) and dropping their ids from the returned result.
        // Record the outage per remaining candidate and keep the partial
        // WriteResult accurate instead. With ZERO progress the error still
        // propagates: the verbatim fallback is safe then (nothing committed
        // to duplicate).
        const progress =
          result.stored.length +
            result.superseded.length +
            result.rejected.length +
            (result.disputed?.length ?? 0) +
            result.deduplicated >
          0;
        if (err instanceof LlmUnavailableError && progress) {
          result.rejected.push({ candidate: cand.content, reason: "llm-unavailable" });
          await this.audit(
            req,
            agentId,
            now,
            "reject",
            null,
            "error",
            "llm-unavailable: circuit opened mid-write; earlier candidates already committed",
          );
          continue;
        }
        throw err;
      }
    }

    return result;
  }

  /** Steps b–f for one extracted candidate (mutates `result` in place). */
  private async processCandidate(
    req: WriteRequest,
    policy: WritePolicy,
    agentId: string,
    now: string,
    cand: Candidate,
    /** This candidate's verdict from the hoisted batch verification. */
    verdictOk: boolean,
    result: WriteResult,
    hooks?: WritePathHooks,
  ): Promise<void> {
    if (req.provenance !== undefined && !req.hints?.verbatim && isLowInformationFact(cand.content)) {
      result.rejected.push({ candidate: cand.content, reason: "low-information-fact" });
      await this.audit(req, agentId, now, "reject", null, "denied", "low-information-fact");
      return;
    }

    // b. Verifier verdict (computed once for the whole write in
    // verifyCandidates) — SKIPPED for verbatim requests: verbatim is the
    // no-LLM lane (budget brownout / LLM-outage fallback), so it must not
    // call the LLM again. The candidate is the caller's own content stored
    // as-is; there is nothing extracted to verify against the transcript.
    if (policy.verifierEnabled && !req.hints?.verbatim && !verdictOk) {
      result.rejected.push({
        candidate: cand.content,
        reason: "failed-verification",
      });
      await this.audit(req, agentId, now, "reject", null, "denied", "failed-verification");
      return;
    }

    // c. Entity resolution — canonical names appended as an annotation;
    // the fact text itself stays verbatim.
    //
    // `[entities: …]` is a RESERVED write-path marker: the read side
    // (DbFragmentationReader) parses canonical entities out of a trailing
    // annotation. Source-controlled content (a raw doc or verbatim import) that
    // legitimately ends in that bracket would otherwise inject FORGED canonical
    // entities the write path never resolved. Strip any trailing occurrence off
    // the base text first, so the only `[entities: …]` the read side can ever
    // see is the one the write path itself appends below after real resolution.
    const base = stripEntitiesAnnotation(cand.content);
    // A governed localOnly ingestion write (DLP brownout: the document's
    // classification denied llm-extraction / embedding-provider) must NOT
    // resolve mentions through the entity registry — EntityRegistry.prepare()
    // embeds with the external embedder and can call the external LLM
    // tiebreak, exactly the egress localOnly exists to prevent. But landing
    // with NO entity metadata makes the fact invisible to entity-grouped
    // contradiction detection (organization conflict scans report
    // entity_metadata_unavailable and skip it), so annotate the deterministic
    // proper-noun mentions directly: zero egress, no registry mutation, same
    // marker shape the read side parses. Non-ingestion localOnly writes stay
    // exactly as-is, mirroring the extract() lane's provenance gate.
    const deterministicMentions =
      (req.hints?.localOnly || req.hints?.deterministicEntities) &&
        req.provenance !== undefined
        ? capitalizedWords(base)
        : [];
    // Entity resolution itself can call the embedding provider. Report the
    // boundary before that work begins, not only before the final fact vector,
    // so a provider failure is attributed to the real stage.
    await hooks?.onStage?.("embedding");
    const preparedEntities: PreparedEntityResolution[] = [];
    if (this.deps.transact && deterministicMentions.length === 0) {
      for (const mention of cand.entities) {
        preparedEntities.push(await this.entities.prepare(req.namespace, mention));
      }
    }
    // Production writes resolve entities only after entering deps.transact so
    // entity rows, alias changes, erasure fences, the memory row, and its D4
    // audit evidence share one commit boundary. The non-transactional lane is
    // retained for small structural unit-test implementations.
    let content = deterministicMentions.length > 0
      ? `${base} [entities: ${deterministicMentions.join(", ")}]`
      : this.deps.transact
      ? base
      : await this.annotateEntities(base, req.namespace, cand.entities, this.entities);

    // Embed the fact TEXT (un-annotated base), not the `[entities: …]` marker:
    // the annotation is derived read-side metadata, so dedupe / supersedence /
    // search similarity must depend only on the fact itself. This also keeps
    // the verbatim lane's newly-added entity annotation from perturbing
    // supersede matching between two near-identical facts.
    const classification = governedClassification(content, req, policy);
    if (!req.hints?.localOnly) {
      assertDestinationAllowed(classification, "embedding-provider", {
        region: policy.dataRegion,
      });
    }
    assertDestinationAllowed(classification, "canonical-l2", {
      region: policy.dataRegion,
    });
    await hooks?.onStage?.("embedding");
    const [embedding] = await (
      req.hints?.localOnly ? this.localEmbedder : this.deps.embedder
    ).embed([base]);
    if (!embedding) return; // defensive; embedders return 1:1
    const sourceAccess = req.provenance?.sourceAccess ?? {
      principals: [],
      groups: [],
    };
    // d–f run as decision + transaction, re-decided on a supersede conflict:
    // the DECISION (vectorSearch → dedupe/conflicting) is necessarily outside
    // the transaction, so a concurrent writer may close the same victim
    // first. The guarded closeValidity detects that (0 rows), the transaction
    // rolls back (insert included), and we re-run the decision against fresh
    // state — bounded, so a pathological interleaving still terminates.
    for (let attempt = 1; ; attempt++) {
      // Dedupe/supersedence must only ever target rows in the caller's OWN
      // namespace: a child-namespace write may never swallow, close, or
      // mutate a parent/org fact (CONTRACTS.md: writes land in the caller's
      // own namespace). The query itself is own-namespace-scoped so closer
      // ancestor rows cannot crowd the k-window and hide a genuine own-
      // namespace conflict; the find() below stays as a belt-and-braces
      // filter for hermetic index implementations that ignore the flag.
      // includePointers:true — pointer facts are excluded from RETRIEVAL
      // surfaces (a pointer is a route, not an answer) but the write path must
      // still see them so a pointer re-mint dedupes/supersedes its stale
      // predecessor through the normal D7 chain.
      const hits = await this.deps.index.vectorSearch(
        req.namespace,
        embedding,
        8,
        true,
        true,
        true,
        sourceAccess,
      );
      const top = hits.find(
        (h) => h.obj.namespace === req.namespace && isSameDocumentVersion(req, h.obj),
      );
      const exact = hits.find((hit) =>
        hit.obj.namespace === req.namespace &&
        isSameDocumentVersion(req, hit.obj) &&
        normalizedExactFact(hit.obj.content) === normalizedExactFact(base));

      // d. Exact dedupe. Cosine is intentionally not a correctness signal:
      // two different dated rows can be nearly identical text.
      if (exact) {
        if (this.deps.transact) {
          await this.deps.transact(async (txIndex, txAudit, txDb) => {
            await this.assertCommitFence(txDb, req);
            if (cand.entities.length > 0) {
              await this.annotatePreparedEntities(
                base,
                preparedEntities,
                this.transactionalEntityRegistry(txDb),
              );
            }
            await txIndex.bumpAccess([exact.obj.id]);
            await this.audit(
              req,
              agentId,
              now,
              "write",
              exact.obj.id,
              "ok",
              "deduplicated=1; access telemetry bumped",
              txAudit,
            );
          });
        } else {
          await this.deps.index.bumpAccess([exact.obj.id]);
          await this.audit(
            req,
            agentId,
            now,
            "write",
            exact.obj.id,
            "ok",
            "deduplicated=1; access telemetry bumped",
          );
        }
        result.deduplicated += 1;
        hooks?.onDeduplicated?.(exact.obj);
        return;
      }

      // Pointer refresh is a deterministic connector lifecycle operation, not
      // a semantic conflict. Ordinary facts are never superseded here.
      const deterministicCacheRefresh = req.provenance?.cache === true && top !== undefined &&
        top.obj.provenance.some((entry) =>
          entry.cache === true &&
          entry.sourceId === req.provenance?.sourceId &&
          entry.documentKey === req.provenance?.documentKey &&
          entry.contentHash !== req.provenance?.contentHash);
      const conflicting = req.hints?.type === "pointer" && top?.obj.type === "pointer"
        ? top
        : deterministicCacheRefresh ? top : null;
      const supersedes: MemoryId | null = conflicting ? conflicting.obj.id : null;

      // D16: classify the final fact, not only the connector document that
      // entered the pipeline. LLM extraction and verbatim brownout both land
      // through this point, so no persisted fact can lose its protection label.
      // f. Insert the new fact and (for a supersedence) close the prior one.
      // With deps.transact wired (kernel runtime) both statements run in ONE
      // database transaction — a failure anywhere rolls both back, so the
      // prior fact stays currently valid (exit criterion 3, D7: supersedence
      // chains, never delete). Without transact (hermetic unit tests) we keep
      // the insert-first order: a failure between the statements never
      // removes information from the currently-valid set.
      const obj: MemoryObject = {
        id: ulid(),
        namespace: req.namespace,
        scope: cand.scope,
        tier: "L2",
        backendRef: "inline",
        content,
        type: req.hints?.type ?? "fact",
        confidence: cand.confidence,
        eventTime: cand.eventTime,
        assertionTime: now,
        tValidFrom: now,
        tValidTo: null,
        supersedes,
        provenance: [
          {
            // D10: ingestion (connectors/importers) stamps its own source +
            // sourceId here; agent conversation leaves req.provenance unset and
            // lands as "conversation" exactly as before.
            extraction: cand.extraction,
            source: req.provenance?.source ?? "conversation",
            actor: req.actor,
            session: req.session,
            ...(req.provenance?.sourceId ? { sourceId: req.provenance.sourceId } : {}),
            ...(req.provenance?.sourceKind ? { sourceKind: req.provenance.sourceKind } : {}),
            ...(req.provenance?.documentKey
              ? { documentKey: req.provenance.documentKey }
              : {}),
            ...(req.provenance?.contentHash
              ? { contentHash: req.provenance.contentHash }
              : {}),
            ...(req.provenance?.attemptToken
              ? { attemptToken: req.provenance.attemptToken }
              : {}),
            // M6 (D11/D14): pointer/cache stamps. credentialMode is the MODE
            // string only — never a token (D13); tokens never reach WriteRequest.
            ...(req.provenance?.connectorId
              ? { connectorId: req.provenance.connectorId }
              : {}),
            ...(req.provenance?.sourceRef
              ? { sourceRef: req.provenance.sourceRef }
              : {}),
            ...(req.provenance?.credentialMode
              ? { credentialMode: req.provenance.credentialMode }
              : {}),
            ...(req.provenance?.pointer ? { pointer: true } : {}),
            ...(req.provenance?.cache ? { cache: true } : {}),
            sourceAccess,
            classification,
            ts: now,
          },
        ],
        classification,
        sourceAccess,
        // M6 (D14): an explicit request TTL (write-back cache, default 3600s)
        // wins; otherwise the policy per-scope default applies exactly as before.
        ttlSeconds:
          req.ttlSeconds !== undefined
            ? req.ttlSeconds
            : policy.ttlDefaultsSeconds[cand.scope] ?? null,
        telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
        status: "active",
      };

      if (this.deps.transact) {
        try {
          await this.deps.transact(async (txIndex, txAudit, txDb) => {
            await this.assertCommitFence(txDb, req);
            if (cand.entities.length > 0) {
              content = await this.annotatePreparedEntities(
                base,
                preparedEntities,
                this.transactionalEntityRegistry(txDb),
              );
              obj.content = content;
            }
            await txIndex.insert(obj, embedding);
            // CA1 outbox: the detection request commits WITH the fact, so a
            // crash between commit and worker loses no check. It is deliberately
            // inside the transaction — the alternative (fire-and-forget after
            // commit) silently drops checks, which is exactly the false-clean
            // failure this lane exists to remove. Detection itself still runs
            // outside the write, so no judge or model can slow or fail a write.
            if (txDb) {
              await enqueueConflictCheck(txDb, obj.id, req.namespace, now);
              // CA8: enrol for subject derivation. EVERY fact, annotated or
              // not — `derived_entities` is the one column the scan groups by,
              // so an annotated fact still needs its subjects mirrored there.
              await enqueueEntityTag(txDb, obj.id, req.namespace, now);
            }
            if (conflicting) {
              const closed = await txIndex.closeValidity(conflicting.obj.id, now);
              // Guarded update matched nothing → the victim was already
              // closed concurrently. Abort so the insert rolls back too —
              // otherwise the chain forks (two rows superseding one fact).
              if (closed === 0) {
                throw new SupersedeConflictError(conflicting.obj.id);
              }
              await this.audit(
                req,
                agentId,
                now,
                "supersede",
                conflicting.obj.id,
                "ok",
                "validity closed; superseded by new fact",
                txAudit,
              );
            }
            await this.audit(req, agentId, now, "write", obj.id, "ok", undefined, txAudit);
          });
        } catch (err) {
          if (err instanceof SupersedeConflictError && attempt < MAX_SUPERSEDE_ATTEMPTS) {
            continue; // re-decide against fresh state
          }
          throw err;
        }
      } else {
        await this.deps.index.insert(obj, embedding);
        if (conflicting) {
          await this.deps.index.closeValidity(conflicting.obj.id, now);
        }
      }

      if (conflicting) {
        result.superseded.push(conflicting.obj.id);
        if (!this.deps.transact) {
          await this.audit(req, agentId, now, "supersede", conflicting.obj.id, "ok", "validity closed; superseded by new fact");
        }
      }

      if (!this.deps.transact) {
        await this.audit(req, agentId, now, "write", obj.id, "ok");
      }
      result.stored.push(obj);
      return;
    }
  }

  // -------------------------------------------------------------------------

  private async assertCommitFence(
    txDb: DbLike | undefined,
    req: WriteRequest,
  ): Promise<void> {
    if (!this.deps.beforeCommit) return;
    if (!txDb) {
      throw new Error("WritePath commit fence requires a transaction database");
    }
    await this.deps.beforeCommit(txDb, req);
  }

  private transactionalEntityRegistry(txDb: DbLike | undefined): EntityRegistry {
    if (!txDb) {
      throw new Error(
        "WritePath transaction must provide txDb for atomic entity resolution",
      );
    }
    return new EntityRegistry(txDb, this.deps.embedder, this.deps.llm);
  }

  private async annotateEntities(
    base: string,
    namespace: Namespace,
    mentions: string[],
    registry: EntityRegistry,
  ): Promise<string> {
    if (mentions.length === 0) return base;
    const canonical: string[] = [];
    for (const mention of mentions) {
      const record = await registry.resolve(namespace, mention);
      if (!canonical.includes(record.canonicalName)) {
        canonical.push(record.canonicalName);
      }
    }
    return `${base} [entities: ${canonical.join(", ")}]`;
  }

  /** A high vector score can conflict only when both named subjects overlap. */
  private async subjectsOverlap(
    namespace: Namespace,
    incomingMentions: string[],
    incumbentContent: string,
  ): Promise<boolean> {
    const incoming = meaningfulEntityNames(incomingMentions);
    const incumbent = meaningfulEntityNames(annotationEntities(incumbentContent));
    if (incoming.length === 0 || incumbent.length === 0) return true;
    if (incoming.some((name) => incumbent.includes(name))) return true;

    try {
      const rows = await this.deps.db.query<{ canonical_name: string; aliases: unknown }>(
        `SELECT canonical_name, aliases FROM entity_registry WHERE namespace = $1`,
        [namespace],
      );
      const canonicalFor = (names: string[]): Set<string> => {
        const resolved = new Set(names);
        for (const row of rows.rows) {
          const canonical = String(row.canonical_name ?? "").trim().toLocaleLowerCase();
          let aliases: string[] = [];
          if (Array.isArray(row.aliases)) aliases = row.aliases.filter((value): value is string => typeof value === "string");
          else if (typeof row.aliases === "string") {
            try {
              const parsed: unknown = JSON.parse(row.aliases);
              if (Array.isArray(parsed)) aliases = parsed.filter((value): value is string => typeof value === "string");
            } catch { /* malformed aliases cannot widen a match */ }
          }
          const all = [canonical, ...aliases.map((value) => value.trim().toLocaleLowerCase())];
          if (names.some((name) => all.includes(name))) resolved.add(canonical);
        }
        return resolved;
      };
      const left = canonicalFor(incoming);
      const right = canonicalFor(incumbent);
      return [...left].some((name) => right.has(name));
    } catch {
      return false;
    }
  }

  private async annotatePreparedEntities(
    base: string,
    prepared: PreparedEntityResolution[],
    registry: EntityRegistry,
  ): Promise<string> {
    if (prepared.length === 0) return base;
    const canonical: string[] = [];
    for (const resolution of prepared) {
      const record = await registry.resolvePrepared(resolution);
      if (!canonical.includes(record.canonicalName)) {
        canonical.push(record.canonicalName);
      }
    }
    return `${base} [entities: ${canonical.join(", ")}]`;
  }

  private async extract(req: WriteRequest): Promise<Candidate[]> {
    const hintTime = req.hints?.eventTime ?? null;
    // An INGESTION verbatim write (importer / connector — provenance stamped by
    // the sink) still needs its entity mentions resolved + annotated
    // ([entities: …]); otherwise an imported fact lands with no entities and is
    // invisible to entity-grouped contradiction detection, so it could never be
    // flagged as contradicting existing knowledge — the exact "contradictions
    // after an import" feature. Derived deterministically (proper-noun
    // mentions), no LLM call, so the verbatim lane stays no-LLM. A NON-ingestion
    // verbatim write (budget brownout / LLM-outage fallback of a conversation
    // write) is stored exactly as-is, unchanged from prior behavior.
    // The localOnly (DLP brownout) lane is excluded HERE because cand.entities
    // feeds EntityRegistry.prepare(), whose embedding + LLM tiebreak would
    // egress the classified content; processCandidate() instead annotates the
    // same deterministic mentions directly, without touching the registry.
    const deriveEntities =
      req.provenance !== undefined &&
      !req.hints?.localOnly &&
      !req.hints?.deterministicEntities;
    const verbatim = (confidence: number, extraction: ExtractionMode): Candidate => ({
      content: req.content,
      scope: req.scope,
      eventTime: hintTime,
      entities: deriveEntities ? capitalizedWords(req.content) : [],
      confidence,
      extraction,
    });

    // A caller that ASKED for verbatim got what it asked for; everything below
    // that returns verbatim did so because extraction failed, and is marked
    // "fallback" so the resync worker can find it later.
    if (req.hints?.verbatim) return [verbatim(1, "verbatim")];

    // Exact provider reads must remain complete (issue description/comments,
    // or all chunks of a Notion page) while still traversing the verifier and
    // the rest of the governed write path. This internal lane deliberately
    // skips fact extraction only; unlike verbatim brownout it is not a no-LLM
    // shortcut and therefore remains subject to verifier + egress policy.
    if (req.hints?.preserveSourceDocument) {
      return [{
        content: req.content,
        scope: req.scope,
        eventTime: hintTime,
        entities: [],
        confidence: 1,
        extraction: "llm",
      }];
    }

    const raw = await this.deps.llm.complete(EXTRACT_SYSTEM, req.content);
    const parsed = parseLooseJson(raw);
    if (!Array.isArray(parsed)) return [verbatim(0.5, "fallback")];

    const out: Candidate[] = [];
    for (const item of parsed) {
      if (item === null || typeof item !== "object") continue;
      const fact = item as Record<string, unknown>;
      if (typeof fact.content !== "string" || fact.content.trim() === "") continue;
      const speaker = fact.speaker === "assistant" ? "assistant" : "user";
      out.push({
        content: fact.content.trim(),
        scope: speaker === "assistant" ? "assistant" : req.scope,
        eventTime: typeof fact.eventTime === "string" ? fact.eventTime : hintTime,
        entities: Array.isArray(fact.entities)
          ? fact.entities.filter((e): e is string => typeof e === "string")
          : [],
        extraction: "llm",
        confidence:
          typeof fact.confidence === "number" &&
          Number.isFinite(fact.confidence) &&
          fact.confidence >= 0 &&
          fact.confidence <= 1
            ? fact.confidence
            : 0.9,
      });
    }
    return out.length > 0 ? out : [verbatim(0.5, "fallback")];
  }

  /**
   * Team-bucket label for a quarantined conflict. Brownout, never hard-fail
   * (non-negotiable 5): the verbatim lane stays no-LLM, and any LLM failure —
   * including an open circuit — degrades to the deterministic keyword
   * heuristic instead of blocking the write.
   */
  private async classifyDispute(
    req: WriteRequest,
    newFact: string,
    incumbentFact: string,
  ): Promise<DisputeCategory> {
    const fallback = (): DisputeCategory =>
      heuristicDisputeCategory(`${newFact} ${incumbentFact}`);
    if (req.hints?.verbatim) return fallback();
    try {
      const raw = await this.deps.llm.complete(
        CLASSIFY_SYSTEM,
        buildClassifyPrompt(newFact, incumbentFact),
      );
      const parsed = parseLooseJson(raw);
      const category =
        parsed !== null && typeof parsed === "object"
          ? (parsed as { category?: unknown }).category
          : undefined;
      if (
        category === "policies-legal" ||
        category === "order-management" ||
        category === "product-info" ||
        category === "other"
      ) {
        return category;
      }
      return fallback();
    } catch {
      return fallback();
    }
  }

  /**
   * Verdict for every extracted candidate, batched: one model call per
   * VERIFY_BATCH_SIZE candidates instead of one per candidate (each of which
   * re-sent the entire transcript). Semantics are unchanged — a candidate is
   * stored only on an explicit `verified: true` for its id. Any candidate the
   * batched response fails to cover (malformed packet, missing/duplicate id)
   * falls back to the single-fact verifier, so a bad packet costs extra calls,
   * never a verdict the model did not actually give — the blast radius of a
   * malformed response stays one fact, exactly as it was per-call.
   */
  private async verifyCandidates(
    req: WriteRequest,
    policy: WritePolicy,
    candidates: readonly Candidate[],
    nowIso: string,
  ): Promise<boolean[]> {
    if (!policy.verifierEnabled || req.hints?.verbatim || candidates.length === 0) {
      // Verification does not apply; every verdict passes so step b skips.
      return candidates.map(() => true);
    }
    // A single candidate (the common chat-turn shape) keeps the existing
    // single-fact prompt: same tokens, no format churn.
    if (candidates.length === 1) {
      return [await this.verify(req.content, candidates[0]!.content, nowIso)];
    }
    const out: boolean[] = new Array<boolean>(candidates.length).fill(false);
    for (let offset = 0; offset < candidates.length; offset += VERIFY_BATCH_SIZE) {
      const chunk = candidates.slice(offset, offset + VERIFY_BATCH_SIZE);
      const raw = await this.deps.llm.complete(
        VERIFY_BATCH_SYSTEM,
        buildVerifyBatchPrompt(req.content, chunk.map((c) => c.content), nowIso),
      );
      const parsed = parseLooseJson(raw);
      const seen = new Set<number>();
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (entry === null || typeof entry !== "object") continue;
          const { id, verified } = entry as { id?: unknown; verified?: unknown };
          if (typeof id !== "number" || !Number.isInteger(id)) continue;
          const local = id - 1; // prompt ids are 1-based within the chunk
          if (local < 0 || local >= chunk.length || seen.has(local)) continue;
          seen.add(local);
          out[offset + local] = verified === true;
        }
      }
      for (let local = 0; local < chunk.length; local++) {
        if (!seen.has(local)) {
          out[offset + local] = await this.verify(req.content, chunk[local]!.content, nowIso);
        }
      }
    }
    return out;
  }

  private async verify(
    transcript: string,
    candidate: string,
    nowIso: string,
  ): Promise<boolean> {
    const raw = await this.deps.llm.complete(
      VERIFY_SYSTEM,
      buildVerifyPrompt(transcript, candidate, nowIso),
    );
    const parsed = parseLooseJson(raw);
    return (
      parsed !== null &&
      typeof parsed === "object" &&
      (parsed as { verified?: unknown }).verified === true
    );
  }

  private async audit(
    req: WriteRequest,
    agentId: string,
    ts: string,
    op: AuditOp,
    memoryId: MemoryId | null,
    result: AuditEvent["result"],
    detail?: string,
    sink: AuditSink = this.deps.audit,
  ): Promise<void> {
    await sink.append({
      ts,
      actor: req.actor,
      agentId,
      op,
      memoryId,
      namespace: req.namespace,
      purpose: null,
      result,
      detail,
    });
  }
}
