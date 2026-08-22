/**
 * HaloMem kernel — shared types and module contracts.
 *
 * This file is the single source of truth for cross-module interfaces.
 * Modules import from here; they never import each other's internals.
 * PRD: HaloMem v1.0 (supersedes Mnemos v0.1). Locked decisions D1–D8 apply.
 */

// ---------------------------------------------------------------------------
// Core identifiers & enums
// ---------------------------------------------------------------------------

/** ULID string — stable forever (D7). */
export type MemoryId = string;

/**
 * Hierarchical namespace path: "org" | "org/team" | "org/team/agent" |
 * "org/team/agent/user" | "org/team/agent/user/session".
 * Deny-by-default across namespaces: a caller may read memories whose
 * namespace is equal to, or an ancestor of, the caller's namespace
 * (org- and team-level knowledge flows down; sibling/session data never
 * flows sideways). Writes land in the caller's own namespace.
 */
export type Namespace = string;

export type Scope = "user" | "assistant" | "team" | "org";
export type Tier = "L2" | "L3";
export type MemoryStatus = "active" | "archived" | "tombstoned" | "disputed";
export type DataSensitivity = "public" | "internal" | "confidential" | "restricted";

/** Human-facing Knowledge Review sync target; namespaces stay server-owned. */
export type KnowledgeSyncTarget =
  | { scope: "team"; teamId: string }
  | { scope: "organization" };

export interface KnowledgeSyncQueueResult {
  status: "queued";
  scope: KnowledgeSyncTarget["scope"];
  queuedSpaces: Array<{ id: string; name: string }>;
  runs?: KnowledgeSyncRunRecord[];
}

export type KnowledgeSyncRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "scheduled";

export interface KnowledgeSyncRunRecord {
  id: string;
  name: string;
  status: KnowledgeSyncRunStatus;
  queuedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  nextRunAt: string | null;
  lastRunStatus: "ok" | "degraded" | "failed" | null;
  lastError: string | null;
  processed: number | null;
  proposals: number | null;
  hasMore: boolean | null;
}

export interface KnowledgeSyncStatusResult {
  runs: KnowledgeSyncRunRecord[];
  /** Completed/failed executions included in `runs` are bounded to this window. */
  retentionDays: number;
  totals: {
    queued: number;
    running: number;
    completed: number;
    failed: number;
    scheduled: number;
  };
}

/** M7/D16: classification travels with data before persistence or egress. */
export interface DataClassification {
  sensitivity: DataSensitivity;
  piiSubjects: string[];
  secretKinds: string[];
  residency?: string;
  /** External warm/cold destinations explicitly approved for restricted data. */
  allowedDestinations: string[];
}

/** M7/D17: source-native grants captured by connectors and enforced on reads. */
export interface SourceAccess {
  /** Stable IdP/source principal ids. Empty means namespace policy only. */
  principals: string[];
  groups: string[];
  /** Source object from which the grants were inherited. */
  inheritedFrom?: string;
}

/** Resolved caller attributes used only by query-layer source ACL checks. */
export interface AccessSubject {
  principals: string[];
  groups: string[];
  /** Server-resolved, versioned additive access to company-published L2 rows. */
  teamMemoryGrant?: TeamMemoryReadGrant;
  /** M10 (D42/D44): server-resolved projection read roots for HUMAN callers. */
  memoryReadScope?: MemoryReadScope;
}

/**
 * M10 (D42/D44) query-layer read widening for HUMAN identities, resolved
 * server-side from the access projection — never from a request. Additive to
 * the base ancestor ACL rule:
 * - `exact` namespaces read as-is (consume/personal roots, already
 *   ancestor-expanded and tenant-clamped by the resolver);
 * - `prefixes` read DOWNWARD as govern subtrees (exact match + escaped-prefix
 *   LIKE). `""` means the whole unprefixed organization (Amendment A1) and is
 *   only ever paired with `excludePrefixes` = the registered tenant roots, so
 *   hosted customer tenants stay invisible to the "" organization root.
 * Machine `agent` callers never carry this (Phase 4 deferred).
 */
export interface MemoryReadScope {
  exact: Namespace[];
  prefixes: Namespace[];
  excludePrefixes?: Namespace[];
}

export type TeamMemoryAccessMode = "related" | "company-published";

/** Query-layer authority; callers can never assert this object. */
export interface TeamMemoryReadGrant {
  teamId: string;
  version: number;
}

export interface TeamMemoryAccessView {
  mode: TeamMemoryAccessMode;
  version: number;
  canBroaden: boolean;
  canTighten: boolean;
}
export type MemoryType =
  | "fact"
  | "preference"
  | "episode"
  | "entity"
  | "concept"
  /**
   * M6 (D11): a pointer fact — a memory_objects row whose content describes
   * what lives at an external source surface (table/channel/object type).
   * Embedded and searched exactly like facts; search IS the L4 router.
   */
  | "pointer";

// ---------------------------------------------------------------------------
// Memory objects (L2 warm tier rows + L3 index entries)
// ---------------------------------------------------------------------------

/**
 * How a stored fact was produced (CA9). `fallback` means extraction was wanted
 * but the model was unavailable or unparseable, so the raw input was stored
 * verbatim — those facts are the ones worth re-extracting once the model is
 * healthy again. Distinguishing them from a deliberate `verbatim` write is the
 * whole point: only one of the two is a degraded result.
 */
export type ExtractionMode = "llm" | "verbatim" | "fallback";

export interface ProvenanceEntry {
  /** Absent on rows written before CA9; treat as unknown, never as "llm". */
  extraction?: ExtractionMode;
  source:
    | "conversation"
    | "document"
    | "swap-import"
    | "consolidation"
    | "manual"
    /** M6 (D14): a fact live-fetched from an external source through the L4 lane. */
    | "live-fetch";
  actor: string;
  session?: string;
  /**
   * Ingestion source identity (M3 / D10): the connector or importer id that
   * fed this fact, e.g. "fs:handbook" or "slack:export-2024". Absent for
   * agent-conversation writes. This is what keeps the audit answer to "what do
   * we know and where from" complete once bulk data enters through the write path.
   */
  sourceId?: string;
  /**
   * Connector kind captured at ingestion time. `sourceId` remains the stable
   * identity; this additive label lets retrieval explain which backend a fact
   * came from without mutating canonical content or joining the source registry.
   * Rows written before this field was introduced are resolved by sourceId at
   * the read boundary and must be treated as unknown when no source is visible.
   */
  sourceKind?: SourceKind;
  /** Stable source-local document identity for connector/import lifecycle. */
  documentKey?: string;
  /** SHA-256 of the exact source document version that produced this fact. */
  contentHash?: string;
  /** Internal attempt owner for exact compensation of retried policy uploads. */
  attemptToken?: string;
  /**
   * M6 (D11): pointer-fact stamp. `connectorId` is the connection (source
   * registry row) behind the pointer; `sourceRef` names the surface within it
   * (table/dir/object type); `credentialMode` is the MODE string only —
   * NEVER a token or secret (D13: passthrough tokens are radioactive).
   */
  connectorId?: string;
  sourceRef?: string;
  credentialMode?: CredentialMode;
  pointer?: boolean;
  /** M6 (D14): true for write-back-cached live results (usage-governed). */
  cache?: boolean;
  /** M7/D17: source-native ACL attached to this version. */
  sourceAccess?: SourceAccess;
  /** M7/D16: classifier result attached before persistence. */
  classification?: DataClassification;
  ts: string; // ISO-8601
}

export interface MemoryObject {
  id: MemoryId;
  namespace: Namespace;
  scope: Scope;
  tier: Tier;
  /** For L2: "inline" (content stored in-row). For L3: "cold:<conceptPath>". */
  backendRef: string;
  content: string;
  type: MemoryType;
  confidence: number; // 0..1
  /** Bi-temporal schema (inherited from benchmark run — battle-tested). */
  eventTime: string | null;      // when the fact became true in the world
  assertionTime: string;         // when the system learned it
  tValidFrom: string;            // validity interval start
  tValidTo: string | null;       // null = currently valid
  /** Supersedence chain link — never overwrite (D7). */
  supersedes: MemoryId | null;
  provenance: ProvenanceEntry[];
  /** Explicit projections used for fail-closed query and egress policy. */
  classification?: DataClassification;
  sourceAccess?: SourceAccess;
  ttlSeconds: number | null;
  telemetry: {
    lastAccessed: string | null;
    accessCount: number;
    faultCount: number;
  };
  status: MemoryStatus;
}

/** Input to the write path (before extraction/verification). */
export interface WriteRequest {
  namespace: Namespace;
  scope: Scope;
  content: string;
  actor: string;
  session?: string;
  hints?: {
    type?: MemoryType;
    eventTime?: string;
    /** Skip LLM extraction; store content as a single fact verbatim. */
    verbatim?: boolean;
    /**
     * Internal exact-source-read mode. Preserve the authenticated provider
     * document as one candidate while still running classification, verifier,
     * embedding, policy, provenance, dedupe, and audit. Public write
     * transports deliberately do not expose this flag.
     */
    preserveSourceDocument?: boolean;
    /**
     * Internal DLP brownout fence. The write must not call an external LLM or
     * embedding provider; it uses a dimension-compatible local hash vector.
     * Public write transports deliberately do not expose this flag.
     */
    localOnly?: boolean;
    /**
     * Internal ingestion brownout for a stale entity-resolution decision.
     * The full fact still uses the configured embedding lane, but deterministic
     * proper-noun annotations replace registry mutation for this attempt.
     * Public write transports deliberately do not expose this flag.
     */
    deterministicEntities?: boolean;
    /**
     * Internal observation-mode fence. The raw input is ephemeral and MUST
     * never enter the verbatim brownout/fallback lane. Transport schemas for
     * ordinary mem_write deliberately do not expose this flag.
     */
    summaryOnly?: boolean;
  };
  /**
   * Provenance override for ingestion (M3 / D10): connectors and importers feed
   * the SAME write path as conversation, but must stamp their own source so the
   * governance/audit trail records where bulk data entered. Absent → the fact is
   * attributed to `source: "conversation"` exactly as before (agent write path
   * unchanged). The write path copies these onto every landed fact's provenance.
   */
  provenance?: {
    source: ProvenanceEntry["source"];
    sourceId?: string;
    sourceKind?: SourceKind;
    documentKey?: string;
    contentHash?: string;
    /** Internal attempt owner; never accepted from public request payloads. */
    attemptToken?: string;
    /** M6 (D11/D14): pointer/cache stamps copied onto the landed fact. */
    connectorId?: string;
    sourceRef?: string;
    credentialMode?: CredentialMode;
    pointer?: boolean;
    cache?: boolean;
    sourceAccess?: SourceAccess;
    classification?: DataClassification;
  };
  /**
   * M6 (D14): explicit TTL override for write-back-cached live results
   * (default 3600s at the L4 call site). Absent → the namespace policy's
   * per-scope TTL default applies exactly as before.
   */
  ttlSeconds?: number | null;
  /**
   * M6 (D14): hard cap on facts this request may STORE. LLM extraction fans
   * one request out to N candidate facts; the L4 write-back passes its
   * remaining per-fault cache budget here so "at most 10 facts per fault are
   * cached" is enforced on ROWS LANDED, not on docs or returned blocks.
   * Candidates beyond the cap are reported rejected (reason "max-facts-cap"),
   * never silently stored. Absent → unlimited (pre-M6 behavior).
   */
  maxFacts?: number;
  /**
   * Kernel-internal commit fence for a leased document-ingest attempt. This is
   * never accepted from an HTTP/MCP caller. Every mutation transaction must
   * prove the same attempt still owns an unexpired processing lease.
   */
  writeFence?:
    | {
        kind: "policy-document" | "company-document";
        documentId: string;
        attemptToken: string;
      }
    | {
        /** Connector writes stop committing as soon as their source disconnects. */
        kind: "source-active";
        sourceId: string;
      };
}

export interface WriteResult {
  stored: MemoryObject[];
  rejected: { candidate: string; reason: string }[];
  superseded: MemoryId[];
  deduplicated: number;
  /**
   * Trust-ranked quarantine outcomes (additive; absent = none). Each entry is a
   * fact that landed with status "disputed" instead of superseding: it conflicts
   * with `against` (a currently-valid higher-trust fact) and awaits human
   * resolution on the conflict-review queue. Invisible to every read path until
   * resolved.
   */
  disputed?: DisputedWrite[];
}

/** Team-facing bucket label for a quarantined conflict (LLM/heuristic). */
export type DisputeCategory =
  | "policies-legal"
  | "order-management"
  | "product-info"
  | "other";

export interface DisputedWrite {
  /** The quarantined fact (status "disputed"). */
  id: MemoryId;
  /** The currently-valid incumbent it conflicts with. */
  against: MemoryId;
  category: DisputeCategory;
}

// ---------------------------------------------------------------------------
// L3 cold tier — OKF concepts (markdown + YAML frontmatter in git)
// ---------------------------------------------------------------------------

interface ConceptBase {
  /** Identity = repo-relative path, e.g. "concepts/refund-policy.okf.enc". */
  path: string;
  type: string; // required frontmatter field per OKF
  title: string;
  description: string;
  tags: string[];
  owner?: string;
  verifiedAgainst?: string;
  verifiedAt?: string;
  /** Markdown body (frontmatter stripped). */
  body: string;
}

/**
 * L3 ownership is explicit and exclusive. A private concept belongs to one
 * non-root namespace; the only cross-tenant concept is deliberately public.
 */
export type Concept = ConceptBase &
  (
    | { namespace: Namespace; visibility?: never; piiSubjects?: string[] }
    | { namespace?: never; visibility: "public"; piiSubjects?: never }
  );

// ---------------------------------------------------------------------------
// Retrieval (D1: delegated permanently; baseline driver is the referee
// control lane. D6: no RetrieverDriver interface until a second
// implementation exists — the baseline below is a concrete module, not a
// plugin API.)
// ---------------------------------------------------------------------------

export interface ScoredRef {
  id: MemoryId | null;     // null for L3 concepts not yet materialized
  tier: Tier;
  /** For L3 hits: concept path. For L2: memory id echo. */
  ref: string;
  score: number;           // higher = better, normalized 0..1
  content: string;
  tokenEstimate: number;
}

export interface SearchQuery {
  namespace: Namespace;    // caller namespace - ACL applied before ranking
  query: string;
  k?: number;              // default 8
  tokenBudget?: number;    // cap on sum of tokenEstimate; default 2000
  /** Restrict to currently-valid facts (default true). */
  validOnly?: boolean;
}

// ---------------------------------------------------------------------------
// halomem-driver/v1 — RetrieverDriver (M2). D6 satisfied: extracted with two
// working implementations (baseline, graph). Drivers are READ-ONLY cartridges:
// they see only the ScopedView the kernel hands them, never the store.
// ---------------------------------------------------------------------------

/** ACL-scoped read surface constructed by the kernel per request. */
export interface ScopedView {
  readonly namespace: Namespace;
  /** Valid, active, ACL-visible L2 rows for lexical ranking. */
  candidates(limit?: number): Promise<{ ref: string; content: string }[]>;
  /**
   * Query-selected lexical candidates from the full ACL-visible L2 corpus.
   * Optional for third-party cartridges built against halomem-driver/v1;
   * drivers must retain their bounded `candidates()` fallback.
   */
  lexicalCandidates?(
    query: string,
    limit: number,
  ): Promise<{ ref: string; content: string }[]>;
  /** ACL-scoped vector search over L2. score = cosine similarity. */
  vectorSearch(embedding: number[], k: number): Promise<{ ref: string; content: string; score: number }[]>;
  /** Embed helper (kernel's active embedder). */
  embed(texts: string[]): Promise<number[][]>;
  /** L3 concept search (org-global in this phase). */
  concepts(query: string, k: number): Promise<ScoredRef[]>;
  /** Entity registry lookup: aliases → related fact refs (for graph drivers). */
  entityFacts(mention: string, hops: 1 | 2): Promise<{ ref: string; content: string; entity: string }[]>;
}

export interface RetrieverQuery {
  query: string;
  view: ScopedView;
  tokenBudget: number;
  k: number;
}

export interface RetrieverDriver {
  readonly name: string;
  capabilities(): { graph: boolean; streaming: boolean };
  /** Refs only — the kernel fetches + injects content. Never writes. */
  plan(q: RetrieverQuery): Promise<ScoredRef[]>;
}

// ---------------------------------------------------------------------------
// halomem-warmstore/v1 — WarmStoreDriver (R6). D6 satisfied: extracted with two
// working implementations (PostgresWarmStore canonical lane, HttpWarmStore
// external mirror). Postgres remains the sole authority (D5); external warm
// stores are REBUILDABLE CACHES: every mutation originates in the kernel
// (write-through after canonical commit, purge propagation on mem.forget,
// full rebuild from canonical rows), and a mirror failure is brownout — the
// op lands in the durable warm_mirror_ops outbox, never a syscall failure.
// This is STORAGE LIFECYCLE only: retrieval ranking stays RetrieverDriver (D1).
// ---------------------------------------------------------------------------

/** The mirrored shape of one CURRENT fact version. Never a superseded row. */
export interface WarmMirrorRecord {
  id: MemoryId;
  namespace: Namespace;
  scope: Scope;
  type: MemoryType;
  content: string;
  tValidFrom: string;
}

export interface WarmStoreHealth {
  ok: boolean;
  detail?: string;
}

export interface WarmStoreDriver {
  readonly name: string;
  /** True for externally hosted mirrors (mem0/supermemory); false = canonical. */
  readonly external: boolean;
  capabilities(): { rebuildable: boolean };
  /** Write-through of the CURRENT version of each fact after canonical commit. */
  upsert(records: WarmMirrorRecord[]): Promise<void>;
  /** Hard-remove cached copies (supersedence invalidation AND mem.forget purge). */
  remove(ids: MemoryId[]): Promise<void>;
  /** Drop every cached copy in a namespace subtree (offboard / rebuild prep). */
  removeNamespace(namespace: Namespace): Promise<void>;
  health(): Promise<WarmStoreHealth>;
  /** Optional governed read-through. Kernel MUST revalidate returned records. */
  get?(ids: MemoryId[]): Promise<WarmMirrorRecord[]>;
}

/** halomem-coldstore/v1 — immutable/versioned cold knowledge backend. */
export interface ColdStoreDriver {
  readonly name: string;
  capabilities(): { versioned: boolean; encrypted: boolean; remote: boolean };
  list(prefix: string): Promise<string[]>;
  read(ref: string): Promise<Uint8Array | null>;
  writeDraft(ref: string, content: Uint8Array): Promise<void>;
  commit(ref: string, expectedDigest?: string): Promise<{ ref: string; digest: string }>;
  remove(ref: string): Promise<void>;
  health(): Promise<{ ok: boolean; detail?: string }>;
}

export interface L1CacheEntry<T = unknown> {
  key: string;
  namespace: Namespace;
  value: T;
  version: string;
  expiresAt: string;
  policyVersion: string;
}

/** Admin status row for one mounted warm store. */
export interface WarmStoreStatus {
  name: string;
  external: boolean;
  healthy: boolean;
  detail?: string;
  /** Outbox rows still awaiting delivery to this store. */
  pendingOps: number;
  /** Highest retry count among pending ops (a growing value = wedged queue). */
  maxAttempts: number;
  /** Delivery error of the most-retried pending op, when any. */
  lastError?: string;
}

/** Per-external-store erasure propagation outcome attached to ForgetResult. */
export interface WarmPurgeOutcome {
  store: string;
  status: "purged" | "pending";
  error?: string;
}

// ---------------------------------------------------------------------------
// Context allocator (D2: returns ranked blocks; the agent framework places
// them — we never own prompt assembly).
// ---------------------------------------------------------------------------

export interface ContextBlock {
  kind:
    /**
     * A governed policy directive. Highest priority, packed from a reserved
     * slice of the budget so ordinary recall can never evict a guardrail.
     */
    | "policy-directive"
    | "pinned-memory"
    | "pinned-concept"
    | "scope-memory"
    | "predicted-relevant";
  ref: string;             // stable memory/concept id, or legacy concept path
  content: string;
  tokenEstimate: number;
  /** Stable ordering key for prompt-cache-friendly packing. */
  orderKey: string;
}

export interface WorkingSet {
  namespace: Namespace;
  blocks: ContextBlock[];
  totalTokens: number;
  budget: number;
  assembledAt: string;
  /**
   * The guardrail set shipped in this working set (blocks of kind
   * 'policy-directive'). Absent when the namespace governs no agent-ready
   * policy documents. The caller places the blocks (D2) — the digest is what
   * it echoes back on `mem_policy_ack`.
   */
  policy?: {
    digest: string;
    documents: PolicyDirectiveDocument[];
    tokens: number;
    required: boolean;
    truncated: number;
  };
}

// ---------------------------------------------------------------------------
// Audit (D4: written from the first syscall; append-only)
// ---------------------------------------------------------------------------

/**
 * The COMPLETE audited-operation vocabulary — one runtime list, and
 * {@link AuditOp} is derived from it.
 *
 * It is a list and not a bare union because every consumer that has to
 * enumerate the ops (the S8 filter allowlist in `src/http/adapter.ts`, the
 * console's operation picker) previously kept its own hand-maintained copy and
 * drifted: ops added after M5 (`conversation_read`, `automation_run`,
 * `conflict_scan`, the `skill_*`/`assistant_*` families …) appeared in the
 * trail but could not be filtered for, and the transport DROPS an unknown op
 * rather than rejecting it — so the filter silently returned everything.
 * Anything that enumerates ops must derive from this array.
 */
export const AUDIT_OPS = [
  "read",
  "search",
  "complete", // Halo model runtime - governed Copilot inference
  "write",
  "propose",
  "edit",
  "approve",
  "publish",
  "fault",
  "stats",
  "assemble",
  /** Guardrail lane: a governed policy directive set was handed to a caller. */
  "policy",
  /** The caller echoed a policy digest back (acknowledged / applied). */
  "policy_ack",
  /** A human changed a document's guardrail level (advisory ↔ required). */
  "policy_enforcement",
  /** A human permanently deleted a governed policy document and its facts. */
  "policy_delete",
  /** A human promoted an already-landed policy file into the register. */
  "policy_adopt",
  "pin",
  "unpin",
  "supersede",
  "reject",
  "retract",
  "move",
  "share",
  "forget", // M4 - compliance erasure (mem.forget); the row survives the deleted content (D4)
  "dispute", // trust-ranked quarantine: a lower-trust write conflicting with a higher-trust fact
  "resolve", // human resolution of a dispute (uphold-new | keep-old | edit)
  // M9 parity (D28–D31). Every one of these writes a row on ok/denied/miss/error (D4).
  "export", // governed egress: canExport ran, then a render (denied exports audit too)
  "skill_vet", // a vetting run over a skill definition (static scan + sandboxed dry-run)
  "skill_invoke", // an agent invoked a skill from the library
  "skill_override", // a human deliberately allowed an unvetted skill
  "skill_approve", // a team admin approved a member-submitted skill (S16)
  "skill_reject", // a team admin rejected a member-submitted skill (S16)
  "automation_run", // one switch-on automation template execution (output = proposal, D30)
  "credit_debit", // a metered feature debited the namespace credit balance
  "answer_outcome", // per-turn answered/weak/disputed capture (D31)
  "conflict_scan", // bounded organization/subtree memory conflict scan
  "conversation_read", // actor-scoped Copilot history read
  "conversation_write", // encrypted Copilot conversation/turn append
  "conversation_clear", // caller cleared their encrypted Copilot history
  "assistant_recycle", // reversible employee Assistant-data recycle
  "assistant_restore", // restore an employee from the Assistant recycle bin
  "assistant_purge", // explicit irreversible Assistant content/detail purge
  "session_capture", // summary-only agent-session observation outcome
  "channel.lifecycle", // communication-channel control plane: create/assign/pause/rotate/verify (C0)
] as const;

export type AuditOp = (typeof AUDIT_OPS)[number];

export interface AuditEvent {
  ts: string;
  actor: string;
  agentId: string;
  op: AuditOp;
  memoryId: MemoryId | null;
  namespace: Namespace;
  purpose: string | null;
  result: "ok" | "denied" | "miss" | "error";
  detail?: string;
}

// ---------------------------------------------------------------------------
// Fault handling
// ---------------------------------------------------------------------------

export interface FaultResult {
  hit: boolean;
  source: "L2" | "L3" | null;
  injected: ScoredRef[];
  latencyMs: number;
  /** Additive brownout signal: absent during normal operation. */
  degradedReason?: "embedding_unavailable" | "cold_unavailable";
}

// ---------------------------------------------------------------------------
// Policy (YAML v0 — per namespace)
// ---------------------------------------------------------------------------

export interface PolicyConfig {
  namespace: Namespace;
  tokenBudget: number;               // default 3000
  ttlDefaultsSeconds: Record<Scope, number | null>;
  pinnedConcepts: string[];          // concept paths preloaded at session start
  dedupeSimilarityThreshold: number; // default 0.92
  verifierEnabled: boolean;          // default true
}

// ---------------------------------------------------------------------------
// Embedding & LLM abstractions (concrete modules, not driver plugins — D6)
// ---------------------------------------------------------------------------

export interface Embedder {
  readonly name: string;
  readonly dim: number;
  embed(texts: string[]): Promise<number[][]>;
}

/** Provider-reported token usage for one completion (what billing counts). */
export interface LlmUsage {
  inputTokens: number;
  /** Includes hidden reasoning tokens on reasoning deployments. */
  outputTokens: number;
}

export interface LlmClient {
  readonly name: string;
  /**
   * Single-turn completion; returns raw text. When `opts.signal` aborts, the
   * client must cancel the underlying request (a provider keeps generating —
   * and billing — an abandoned completion unless the connection is closed).
   * Implementations without a live connection may ignore it. Clients that
   * receive provider usage in the response call `opts.onUsage` with the real
   * token counts — accounting estimated 1/17th of the Aug 2026 Azure bill
   * because it guessed from text length and never saw reasoning tokens.
   */
  complete(
    system: string,
    user: string,
    opts?: { signal?: AbortSignal; onUsage?: (usage: LlmUsage) => void },
  ): Promise<string>;
}

// ---------------------------------------------------------------------------
// Entity registry (Phase 1 item 1 — benchmark proved skipping this tanks
// multi-session recall)
// ---------------------------------------------------------------------------

export interface EntityRecord {
  id: string;              // ulid
  namespace: Namespace;
  canonicalName: string;
  aliases: string[];
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Identity & auth (M1 / D9: resolved server-side from a credential; callers
// never assert their own namespace or actor)
// ---------------------------------------------------------------------------

export type Role = "owner" | "admin" | "auditor" | "member" | "agent";

/**
 * D50 (CONTRACTS-AGENT-SCOPE.md) — the scope level of a MACHINE principal.
 * `manager` is the agent form of the human admin scope, `member` the agent form
 * of the human member scope. There is deliberately no agent equivalent of
 * `owner`: an agent is always bound to a team or an individual, never to the
 * organization. Stored on `api_keys.agent_access_level` and resolved
 * server-side — never asserted by a caller (D9).
 */
export type AgentAccessLevel = "manager" | "member";

export interface Identity {
  keyId: string;         // ulid of the api key row
  namespace: Namespace;  // bound at issuance - the ONLY namespace this caller acts in
  actor: string;
  role: Role;
  /**
   * D50: present only for role 'agent'. Absent/NULL on an agent row (a key
   * minted before migration 59) reads as the least-privileged 'member'.
   */
  agentAccessLevel?: AgentAccessLevel;
  /**
   * D54: present only for role 'agent'. `false` means this credential may read
   * memory but never change it. Read from the stored row (D9) — a caller can no
   * more assert this than it can assert its own namespace.
   */
  agentCanWrite?: boolean;
  /** Server-resolved source/IdP attributes; callers never assert these. */
  sourcePrincipals?: string[];
  sourceGroups?: string[];
  /** Internal channel Assistant principal; resolved only from principal_purpose. */
  channelAssistant?: true;
  /** Verified bearer expiry for non-durable identities such as OIDC JWTs. */
  credentialExpiresAt?: string;
  /** Server-only discriminator for a verified, non-durable delegated bearer. */
  credentialKind?: "copilot-capability" | "copilot-routine";
  /** Server-resolved standalone Assistant query carried by delegated calls. */
  assistantContextQuery?: string;
  /**
   * Server-derived caller classification (api_keys.caller_class, v38) copied
   * at resolve time for usage attribution (D36). Absent on non-key identities
   * (sessions, internal workers) — consumers default to "unclassified".
   */
  callerClass?: string;
  /** Server-only effective read grant resolved afresh for one syscall. */
  teamMemoryGrant?: TeamMemoryReadGrant;
  /**
   * Console-session subject (users.id) for M10 projection resolution.
   * Server-minted in sessionToIdentity only; absent on API-key identities.
   */
  sessionUserId?: string;
  /** Server-only M10 read widening resolved afresh for one syscall (D9). */
  memoryReadScope?: MemoryReadScope;
}

/**
 * Server-owned fence for work admitted by one immutable channel grant. It is
 * carried beside (never inside) model input and revalidated by deferred work
 * before provider I/O, cache write-back, and result publication.
 */
export interface ChannelAuthorityContext {
  connectionId: string;
  grantId: string;
  grantRevision: number;
  authorityEpoch: number;
  credentialVersion: number;
}

/**
 * D37: per-call trace threading. `traceId` groups the syscalls of one agent
 * turn into one query_traces row; it is a grouping hint, NEVER identity (D9).
 * Caller-supplied values are validated at the syscall boundary; invalid ones
 * are replaced with a fresh ULID. `tool` names the invoking surface
 * ("kernel", "http:<op>", or the MCP tool name).
 */
export interface SyscallContext {
  traceId?: string;
  tool?: string;
  /**
   * D56: server-owned Halo Assistant turn reference. When present, syscall
   * analytics must not persist the user's search text as audit purpose or a
   * query summary. This is never accepted from an HTTP/MCP caller.
   */
  sensitiveTurnId?: string;
  /** Internal only: exact channel authority that admitted this Assistant turn. */
  channelAuthority?: ChannelAuthorityContext;
}

export interface ApiKeyRecord {
  id: string;
  namespace: Namespace;
  actor: string;
  role: Role;
  status: "active" | "revoked";
  createdAt: string;
  lastUsed: string | null;
  sourcePrincipals?: string[];
  sourceGroups?: string[];
  /** D50: scope level of an agent credential. Absent for human key types. */
  agentAccessLevel?: AgentAccessLevel;
  /**
   * D50 grandfathering: true when this row would be refused by today's
   * issuance rules (an agent credential bound to the organization root). It
   * still resolves; the console renders it as out-of-policy with a Revoke.
   */
  outOfPolicy?: boolean;
  /**
   * D51: ISO timestamp after which the credential stops resolving. Absent means
   * standing access — still revocable at any time, just not self-terminating.
   */
  expiresAt?: string;
  /** D51: true when `expiresAt` is already in the past. Derived, never stored. */
  expired?: boolean;
  /** D51: the human sentence explaining why this agent exists. */
  description?: string;
  /**
   * D54: false when this agent may only READ memory. Absent on human key types;
   * true on an agent credential issued without the restriction.
   */
  agentCanWrite?: boolean;
  /**
   * The actor that MINTED this credential (migration 76), as opposed to the
   * `actor` the credential acts as. Absent on a bootstrap key, a key issued
   * before the column existed whose issuance is not in the audit trail, or any
   * caller-less server path. Display only — no authorization decision reads it.
   */
  createdBy?: string;
  /** Stable human custodian allowed to manage this delegated agent key. */
  custodianUserId?: string;
}

// ---------------------------------------------------------------------------
// Human identity (M5 control room) — agents authenticate with badges (API
// keys, D9); humans sign in with email/SSO and act through a role. A resolved
// session yields the SAME Identity shape the syscalls already require, so the
// control room is a face on existing controls — not a second auth system.
// The role is never "agent": humans are owner | admin | auditor | member.
// ---------------------------------------------------------------------------

export type HumanRole = Exclude<Role, "agent">;

export interface User {
  id: string;
  email: string;
  /** Required human-facing account label. Email remains the immutable auth/audit key. */
  displayName: string;
  /** Presentation-only self-uploaded raster data URL. */
  avatar?: string | null;
  namespace: Namespace;   // the scope this human acts in (their team/org root)
  role: HumanRole;
  status: "active" | "disabled";
  createdAt: string;
}

export interface Session {
  id: string;             // opaque; stored hashed at rest, matched against the cookie
  userId: string;
  namespace: Namespace;
  actor: string;          // the user's email - the audit actor for their actions
  role: HumanRole;
  createdAt: string;
  expiresAt: string;
}

// ---------------------------------------------------------------------------
// Stats surface
// ---------------------------------------------------------------------------

export interface MemStats {
  namespace: Namespace;
  l2Count: number;
  l3ConceptCount: number;
  faultCount: number;
  faultHitRate: number;
  avgWorkingSetTokens: number;
  auditEventCount: number;
  topAccessed: { id: MemoryId; content: string; accessCount: number }[];
}

// ---------------------------------------------------------------------------
// Ingestion — connectors & importers (M3). D10: connectors and importers feed
// the WRITE PATH, never the store. The kernel hands each unit an IngestSink
// (a namespace-bound wrapper over performWrite) and, for connectors, a
// SourceState (drift-hash bookkeeping). An ingestion module imports NONE of
// src/index, src/db, or src/audit and constructs no SQL — the sink is its whole
// write surface, so imported data gets the same extraction / verification /
// entity-resolution / supersedence / provenance as agent conversation.
// ---------------------------------------------------------------------------

/** Stable platform catalog identifiers mirrored from updatedev. */
export type PlatformConnectorId =
  | "shopify"
  | "woocommerce"
  | "bigcommerce"
  | "squarespace_commerce"
  | "magento"
  | "rista"
  | "urbanpiper"
  | "petpooja"
  | "toast"
  | "square_pos"
  | "gorgias"
  | "zendesk"
  | "freshdesk"
  | "intercom"
  | "front"
  | "kustomer"
  | "zoho_desk"
  | "hubspot"
  | "salesforce"
  | "pipedrive"
  | "zoho_crm"
  | "attio"
  | "close"
  | "whatsapp_business"
  | "twilio"
  | "gmail"
  | "outlook"
  | "slack_messaging"
  | "telegram"
  | "klaviyo"
  | "mailchimp"
  | "google_ads"
  | "meta_marketing"
  | "tiktok_ads"
  | "microsoft_ads"
  | "linkedin_ads"
  | "triple_whale"
  | "shopify_catalogue"
  | "woocommerce_catalogue"
  | "google_sheets"
  | "airtable"
  | "notion_catalogue"
  | "google_drive_catalogue"
  | "google_docs_catalogue"
  | "webflow"
  | "wordpress"
  | "algolia"
  | "stripe"
  | "razorpay"
  | "square_payments"
  | "recharge"
  | "skio"
  | "shipstation"
  | "loop_returns"
  | "aftership"
  | "shiprocket"
  | "delhivery"
  | "easypost"
  | "notion_knowledge"
  | "google_drive_knowledge"
  | "google_docs_knowledge"
  | "slack_knowledge"
  | "confluence"
  | "jira"
  | "custom_api"
  | "webhook_source"
  | "private_api_nango"
  | "csv_sheet_import";

export type SourceKind =
  | "filesystem"
  | "postgres"
  | "notion"
  | "slack"
  | "mem0-import"
  | "pgvector-import"
  | "policy-upload"
  /** Immutable provenance anchor for a company file uploaded through D10. */
  | "file-upload"
  /** M9 parity: GitHub App brokered repo/issue/PR ingestion (D10 write path). */
  | "github"
  /** M9 parity: bounded public doc-site crawl, HTML->markdown (D10 write path). */
  | "doc_site"
  /** Direct Linear workspace OAuth sync (no Nango; D10 write path). */
  | "linear_direct"
  /** Direct Notion workspace OAuth sync (no Nango; D10 write path). */
  | "notion_direct"
  /** Direct Airtable account OAuth sync (no Nango; D10 write path). */
  | "airtable_direct"
  /** Direct Google Drive OAuth sync, restricted to selected files/folders. */
  | "google_drive_direct"
  /** Direct Google Docs OAuth sync, restricted to selected documents/folders. */
  | "google_docs_direct"
  /** Direct Google Sheets OAuth sync, restricted to selected spreadsheets/folders. */
  | "google_sheets_direct"
  /** User-authorized local Obsidian vault plugin sync (signed push; D10 write path). */
  | "obsidian_vault"
  | PlatformConnectorId;

export type PolicyDocumentKind =
  | "policy"
  | "guideline"
  | "procedure"
  | "standard"
  | "handbook"
  | "other";

export type PolicyDocumentStatus =
  | "processing"
  | "active"
  | "needs_review"
  | "failed";

/**
 * How hard a governed policy document lands on an agent.
 *
 * `required` (default) — the directive is delivered on every working-set
 * assembly and an agent that acts in the namespace without having been served
 * the current directive digest is recorded as a bypass.
 * `advisory` — delivered the same way, but its absence is never a bypass.
 *
 * Neither level denies a syscall: policy is a guardrail lane and an evidence
 * ledger, not an authorization decision (ACL stays in the query layer).
 */
export type PolicyDocumentEnforcement = "advisory" | "required";

/**
 * How a register row came to exist.
 *
 * `upload` — the file entered through the policy library's own governed write
 * path, so the row owns an attempt token and its facts carry that token in
 * provenance.
 * `adopted` — the file's facts were already in memory from another D10 lane (a
 * connector or import), and an admin promoted that file into the register. The
 * row owns no attempt: it points at the existing source, and retraction matches
 * the facts by `(sourceId, documentKey, contentHash)` provenance instead.
 */
export type PolicyDocumentOrigin = "upload" | "adopted";

export interface PolicyDocumentUploadInput {
  namespace: string;
  title?: string;
  kind: PolicyDocumentKind;
  fileName: string;
  content: string;
  enforcement?: PolicyDocumentEnforcement;
}

export interface PolicyDocumentSummary {
  id: string;
  sourceId: string;
  namespace: string;
  title: string;
  kind: PolicyDocumentKind;
  status: PolicyDocumentStatus;
  enforcement: PolicyDocumentEnforcement;
  origin: PolicyDocumentOrigin;
  fileName: string;
  mediaType: string;
  byteSize: number;
  contentSha256: string;
  factCount: number;
  failureCode: string | null;
  createdBy: string;
  createdAt: string;
  loadedAt: string | null;
}

/**
 * A policy file whose facts are already in memory but which has no register
 * row — the gap that made the Policies screen look empty while `mem_search`
 * happily returned the same policies. One candidate is one FILE, so a CSV that
 * landed as many fragment documents (`policies.csv#refund-cap`, …) is a single
 * adoptable row, not one per clause.
 */
export interface PolicyAdoptionCandidate {
  sourceId: string;
  namespace: Namespace;
  fileName: string;
  title: string;
  mediaType: string;
  /** Distinct source documents (fragments) the file landed as. */
  documentCount: number;
  /** Currently-active facts attributable to those documents. */
  factCount: number;
  byteSize: number;
  /** Why this file reads as policy material — shown so adoption is not a guess. */
  signal: "file-name" | "content" | "both";
  firstSeenAt: string | null;
  lastSeenAt: string | null;
}

export interface PolicyAdoptionCandidateListResult {
  data: PolicyAdoptionCandidate[];
  hasMore: boolean;
}

export interface PolicyDocumentAdoptInput {
  namespace: string;
  /** The file to adopt, exactly as reported by the candidate list. */
  fileName: string;
  sourceId: string;
  title?: string;
  kind?: PolicyDocumentKind;
  enforcement?: PolicyDocumentEnforcement;
}

/** One agent-ready policy document contributing directives to a working set. */
export interface PolicyDirectiveDocument {
  documentId: string;
  namespace: Namespace;
  title: string;
  kind: PolicyDocumentKind;
  enforcement: PolicyDocumentEnforcement;
  /** Directive facts drawn from this document that fit the reserved slice. */
  directiveCount: number;
  tokenEstimate: number;
  loadedAt: string | null;
}

/**
 * The governing guardrail set for one namespace: the ordered directive blocks
 * plus the digest that identifies exactly this version of the guardrails. The
 * digest is what an agent acknowledges and what bypass detection compares.
 */
export interface PolicyDirectiveSet {
  namespace: Namespace;
  digest: string;
  documents: PolicyDirectiveDocument[];
  blocks: ContextBlock[];
  totalTokens: number;
  /** True when at least one contributing document is `required`. */
  required: boolean;
  /** Directives dropped because the reserved slice was full. */
  truncated: number;
}

/** Per-(document, agent) compliance rollup behind the S4 compliance panel. */
export interface PolicyComplianceAgent {
  agentId: string;
  actor: string;
  lastDigest: string;
  /** False when the agent's last delivery predates the current digest. */
  current: boolean;
  servedCount: number;
  acknowledgedCount: number;
  appliedCount: number;
  bypassCount: number;
  firstServedAt: string | null;
  lastServedAt: string | null;
  lastAcknowledgedAt: string | null;
  lastAppliedAt: string | null;
  lastBypassAt: string | null;
  state: "acknowledged" | "served" | "stale" | "bypassed" | "never-served";
}

export interface PolicyComplianceDocument {
  documentId: string;
  namespace: Namespace;
  title: string;
  kind: PolicyDocumentKind;
  enforcement: PolicyDocumentEnforcement;
  status: PolicyDocumentStatus;
  factCount: number;
  agents: PolicyComplianceAgent[];
}

export interface PolicyComplianceReport {
  namespace: Namespace;
  digest: string;
  documents: PolicyComplianceDocument[];
  summary: {
    documents: number;
    agents: number;
    acknowledged: number;
    served: number;
    stale: number;
    bypassed: number;
    neverServed: number;
  };
  recent: PolicyComplianceEvent[];
}

export interface PolicyComplianceEvent {
  id: string;
  namespace: Namespace;
  documentId: string;
  documentTitle: string;
  agentId: string;
  actor: string;
  kind: "served" | "acknowledged" | "applied" | "bypassed";
  channel: "assemble" | "policy-call" | "ack" | "monitor";
  policyDigest: string;
  traceId: string | null;
  ts: string;
  detail: string | null;
}

export interface PolicyDocumentListQuery {
  namespace: string;
  page?: number;
  pageSize?: number;
  query?: string;
  kind?: PolicyDocumentKind;
  status?: PolicyDocumentStatus;
}

export interface PolicyDocumentListResult {
  data: PolicyDocumentSummary[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
  summary: {
    total: number;
    active: number;
    needsReview: number;
    failed: number;
  };
}

export interface PolicyDocumentScope {
  namespace: string;
  documentCount: number;
}

export interface PolicyDocumentScopeListResult {
  data: PolicyDocumentScope[];
  hasMore: boolean;
}

// ---------------------------------------------------------------------------
// Knowledge bases + governed company files
// ---------------------------------------------------------------------------

/** Legacy persistence marker. New knowledge bases are collections, not source types. */
export type KnowledgeBaseKind = "file" | "folder" | "url";

/** Aggregate ingest health for one knowledge base. */
export type KnowledgeBaseStatus =
  | "empty"
  | "processing"
  | "ready"
  | "needs_review"
  | "failed";

/** User-controlled lifecycle never deletes knowledge or provenance (D7). */
export type KnowledgeBaseLifecycleState = "active" | "paused" | "archived";

/** Safe, non-secret business metadata shared by every first-class source. */
export interface KnowledgeBaseSourceMetadata {
  primaryBusinessFunction: string;
  description: string;
  dataSensitive: boolean;
}

/**
 * Create a knowledge base in a server-resolved organization/team scope (D9).
 * `sourceId` is required for folder/url and absent for file libraries.
 */
export interface KnowledgeBaseCreateInput extends KnowledgeBaseSourceMetadata {
  name: string;
  kind: KnowledgeBaseKind;
  targetTeamId: string | null;
  sourceId?: string;
}

export interface KnowledgeBaseSummary extends KnowledgeBaseSourceMetadata {
  id: string;
  namespace: Namespace;
  targetTeamId: string | null;
  name: string;
  kind: KnowledgeBaseKind;
  status: KnowledgeBaseStatus;
  lifecycleState: KnowledgeBaseLifecycleState;
  sourceId: string | null;
  fileCount: number;
  sourceCount: number;
  itemCount: number;
  factCount: number;
  createdBy: string;
  /** Presentation-only label for the already-visible human creator actor. */
  createdByDisplayName?: string;
  createdAt: string;
  updatedAt: string;
}

export interface KnowledgeBaseListQuery {
  query?: string;
  targetTeamId?: string;
  kind?: KnowledgeBaseKind;
  status?: KnowledgeBaseStatus;
  lifecycleState?: KnowledgeBaseLifecycleState;
  page?: number;
  pageSize?: number;
}

export interface KnowledgeBaseListResult {
  data: KnowledgeBaseSummary[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

/** A connector-backed piece attached to a knowledge base collection. */
export type KnowledgeBaseSourceKind = "folder" | "website";
export type KnowledgeBaseSourceStatus =
  | "processing"
  | "ready"
  | "needs_review"
  | "failed"
  | "archived";

export interface KnowledgeBaseSourceCreateInput {
  knowledgeBaseId: string;
  kind: KnowledgeBaseSourceKind;
  sourceId: string;
  name: string;
  description: string;
  purpose: string;
}

export interface KnowledgeBaseSourceSummary {
  id: string;
  knowledgeBaseId: string;
  sourceId: string;
  namespace: Namespace;
  targetTeamId: string | null;
  kind: KnowledgeBaseSourceKind;
  name: string;
  description: string;
  purpose: string;
  status: KnowledgeBaseSourceStatus;
  createdBy: string;
  createdAt: string;
}

export interface KnowledgeBaseSourceListResult {
  data: KnowledgeBaseSourceSummary[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

export type CompanyFileStatus = "processing" | "ready" | "needs_review" | "failed";
export type CompanyFileLifecycleState = "active" | "archived";

/**
 * Caller-controlled company-file fields. Namespace, uploader, hashes, media
 * type, byte size, status, and provenance are derived by the kernel.
 */
export interface CompanyFileUploadInput {
  knowledgeBaseId: string;
  fileName: string;
  /** Stable per-file request identity used to reconcile transport retries. */
  idempotencyKey?: string;
  /** Text content (legacy path; re-encoded by the server before hashing). */
  content?: string;
  /**
   * Original file bytes as base64. Preferred path: the server hashes and
   * validates exactly these bytes, so provenance pins the caller's file.
   * Exactly one of content / contentBase64 is required.
   */
  contentBase64?: string;
  title?: string;
  description: string;
  purpose: string;
}

export interface CompanyFileSummary {
  id: string;
  knowledgeBaseId: string;
  sourceId: string;
  namespace: Namespace;
  targetTeamId: string | null;
  title: string;
  description: string;
  purpose: string;
  fileName: string;
  mediaType: string;
  byteSize: number;
  contentSha256: string;
  status: CompanyFileStatus;
  lifecycleState: CompanyFileLifecycleState;
  factCount: number;
  failureCode: string | null;
  uploadedBy: string;
  createdAt: string;
  loadedAt: string | null;
  archivedAt: string | null;
}

export interface CompanyFileListQuery {
  knowledgeBaseId?: string;
  targetTeamId?: string;
  query?: string;
  status?: CompanyFileStatus;
  lifecycleState?: CompanyFileLifecycleState;
  /** Include content-free durable uploads for one exact knowledge base. */
  includeUploads?: boolean;
  page?: number;
  pageSize?: number;
}

/** Reload-safe, content-free progress for a file not yet finalized. */
export interface CompanyFileUploadListItem {
  uploadId: string;
  knowledgeBaseId: string;
  fileName: string;
  title: string;
  status: "queued" | "processing";
  stage: CompanyFileUploadStage;
  submittedAt: string;
}

export interface CompanyFileListResult {
  data: CompanyFileSummary[];
  /** Present when `includeUploads` was requested for an exact base. */
  uploads?: CompanyFileUploadListItem[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
  summary: {
    total: number;
    ready: number;
    processing: number;
    needsReview: number;
    failed: number;
  };
}

export type CompanyFileUploadJobStatus =
  | "queued"
  | "processing"
  | "ready"
  | "needs_review"
  | "failed";

/** Durable, monotonic progress through the company-file write path. */
export type CompanyFileUploadStage =
  | "queued"
  | "parsing"
  | "extracting"
  | "embedding"
  | "finalizing"
  | "complete";

/** Content-free acknowledgement returned once an upload is durably accepted. */
export interface CompanyFileUploadAccepted {
  uploadId: string;
  status: "queued" | "processing";
  stage: CompanyFileUploadStage;
  submittedAt: string;
}

/** Pollable upload state. Raw or extracted document content is never returned. */
export interface CompanyFileUploadStatusResult {
  uploadId: string;
  status: CompanyFileUploadJobStatus;
  stage: CompanyFileUploadStage;
  submittedAt: string;
  completedAt: string | null;
  failureCode: string | null;
  file: CompanyFileSummary | null;
}

// ---------------------------------------------------------------------------
// Typed L2 entity relationships
// ---------------------------------------------------------------------------

export type EntityRelationshipType =
  | "same_as"
  | "part_of"
  | "contains"
  | "uses"
  | "depends_on"
  | "owned_by"
  | "served_by"
  | "related_to";

export type EntityRelationshipStatus = "active" | "archived" | "disputed";

/** Evidence must resolve back to governed L2 content and its D10 provenance. */
export interface EntityRelationshipEvidence {
  memoryId: MemoryId;
  sourceId?: string;
  documentKey?: string;
  contentHash?: string;
}

/** Caller/internal creation shape; namespace and actor come from Identity (D9). */
export interface CreateEntityRelationshipInput {
  subjectEntityId: string;
  relationship: EntityRelationshipType;
  objectEntityId: string;
  confidence: number;
  evidence: EntityRelationshipEvidence[];
  eventTime?: string;
}

/** Append-only, bi-temporal L2 edge. Corrections create a supersedence chain. */
export interface L2EntityRelationship {
  id: string;
  namespace: Namespace;
  subjectEntityId: string;
  relationship: EntityRelationshipType;
  objectEntityId: string;
  confidence: number;
  evidence: EntityRelationshipEvidence[];
  assertionTime: string;
  eventTime: string | null;
  tValidFrom: string;
  tValidTo: string | null;
  supersedes: string | null;
  status: EntityRelationshipStatus;
  createdBy: string;
}

export interface EntityRelationshipListQuery {
  entityId: string;
  relationship?: EntityRelationshipType;
  direction?: "outgoing" | "incoming" | "both";
  includeArchived?: boolean;
  limit?: number;
}

export interface EntityRelationshipListResult {
  data: L2EntityRelationship[];
}

export type ConnectorCategory =
  | "commerce"
  | "pos"
  | "support"
  | "crm"
  | "messaging"
  | "marketing"
  | "catalogue"
  | "payments"
  | "fulfilment"
  | "knowledge"
  | "custom";

export type ConnectorAuthType =
  | "oauth"
  | "api_key"
  | "basic_auth"
  | "private_api"
  | "webhook"
  | "manual";

export type ConnectorMemoryMode = "snapshot" | "timeline" | "pointer";
export type ConnectorSensitivity = "public" | "internal" | "confidential" | "restricted";

export interface ConnectorAuthField {
  key: string;
  label: string;
  input: "text" | "password" | "url" | "email" | "number";
  required: boolean;
  secret: boolean;
  /** Secret values are accepted on writes but never returned by APIs. */
  writeOnly?: true;
  /** Optional lower bound enforced before credentials are persisted or used. */
  minLength?: number;
  /** Connection secrets/IDs are reusable; source selectors stay per source. */
  role?: "credential" | "source";
  placeholder?: string;
  help?: string;
}

export interface ConnectorAuthSpec {
  type: ConnectorAuthType;
  fields: readonly ConnectorAuthField[];
  scopes?: readonly string[];
  /** Authentication is completed by Halo's server-owned Nango environment. */
  managedBy?: "nango";
}

export interface ConnectorDataPoint {
  key: string;
  label: string;
  description: string;
  defaultEnabled: boolean;
  memoryMode: ConnectorMemoryMode;
  sensitivity: ConnectorSensitivity;
  /** Explicit source fields admitted into memory; never a wildcard. */
  selectedFields: readonly string[];
}

export interface ConnectorJsonObject {
  readonly [key: string]: ConnectorJsonTemplate;
}

export type ConnectorJsonTemplate =
  | string
  | number
  | boolean
  | null
  | readonly ConnectorJsonTemplate[]
  | ConnectorJsonObject;

export interface ConnectorResourceEndpoint {
  dataPoint: string;
  /** Top-level key in the committed conformance fixture, when it stores per-route responses. */
  fixtureKey?: string;
  method?: "GET" | "POST";
  path: string;
  recordsPath?: string;
  idPath: string;
  contentPaths: readonly string[];
  eventTimePath?: string;
  nextCursorPath?: string;
  cursorParameter?: string;
  pageParameter?: string;
  pageSizeParameter?: string;
  pageSize?: number;
  staticQuery?: Readonly<Record<string, string>>;
  /** Recursive JSON template with non-secret `{configField}` substitutions. */
  body?: Readonly<Record<string, ConnectorJsonTemplate>>;
  sourceAccess?: {
    principalsPath?: string;
    groupsPath?: string;
    inheritedFromPath?: string;
  };
}

export interface ConnectorRuntimeSpec {
  adapter: "rest" | "webhook" | "file";
  /** Official fixed API origin. Custom origins must be supplied and SSRF-validated. */
  baseUrl?: string;
  baseUrlField?: string;
  /** Optional suffix allowlist for customer-specific SaaS tenant hosts. */
  allowedHostSuffixes?: readonly string[];
  testPath?: string;
  auth:
    | { strategy: "bearer"; tokenField: string }
    | { strategy: "basic"; usernameField: string; passwordField: string }
    | { strategy: "header"; fields: Readonly<Record<string, string>> }
    | { strategy: "query"; fields: Readonly<Record<string, string>> }
    | { strategy: "rista_jwt"; apiKeyField: string; secretKeyField: string }
    | {
        strategy: "toast_client_credentials";
        clientIdField: string;
        clientSecretField: string;
        tokenPath: string;
      }
    | { strategy: "none" };
  headers?: Readonly<Record<string, string>>;
  /** Provider-specific HTTP-200 success envelope assertion. */
  responseSuccess?: {
    path: string;
    equals: string | number | boolean;
  };
  resources: readonly ConnectorResourceEndpoint[];
  maxPages: number;
  maxRecords: number;
}

export interface ConnectorCatalogEntry {
  id: PlatformConnectorId;
  /** Credential family. Category aliases intentionally share this key. */
  connectionKey: string;
  name: string;
  category: ConnectorCategory;
  description: string;
  logo?: string;
  auth: ConnectorAuthSpec;
  dataPoints: readonly ConnectorDataPoint[];
  runtime: ConnectorRuntimeSpec;
  capabilities: ConnectorCapabilities;
  readiness: "executable";
  docsUrl: string;
}

export interface SourceCredentialSummary {
  id: string;
  namespace: Namespace;
  connectorId: PlatformConnectorId;
  connectionKey: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface SourceCredentialRecord extends SourceCredentialSummary {
  /** Kernel-internal decrypted configuration; never serialize this record. */
  config: Record<string, unknown>;
}

export interface CreateSourceCredentialInput {
  connectorId: PlatformConnectorId;
  connectionKey: string;
  name: string;
  config: Record<string, unknown>;
}

/** One unit of source content, before it enters the write path. */
export interface IngestRecord {
  /** Stable id within the source — the drift-detection + dedupe key. */
  docId: string;
  content: string;
  /** Drift engine supplied hash. The sink computes it when absent (imports). */
  contentHash?: string;
  /** Landing scope (default "org" for org-wide corpora; importers may set per-record). */
  scope?: Scope;
  /** When the fact became true in the world, if the source knows it. */
  eventTime?: string;
  /**
   * Skip LLM extraction and store `content` as one verbatim fact. Importers of
   * ALREADY-EXTRACTED facts (a Mem0 dump is a list of facts, not transcripts)
   * set this; raw-document connectors leave it false so the extractor runs.
   */
  verbatim?: boolean;
  /** Source-native object grants, preserved through the write path (D17). */
  sourceAccess?: SourceAccess;
  /** Connector supplied hints; the kernel classifier is still authoritative. */
  classification?: Partial<DataClassification>;
  /**
   * M6 (D11): present iff this record is a pointer mint/refresh (module A's
   * catalog). The kernel-side sink detects it and (a) forces the landed fact's
   * `type` to 'pointer', (b) stamps provenance `{connectorId, sourceRef,
   * credentialMode, pointer:true}`. `credentialMode` is the MODE string only —
   * never a token (D13).
   */
  pointer?: {
    connectorId: string;
    sourceRef: string;
    credentialMode: CredentialMode;
  };
}

/**
 * The ONLY way ingestion reaches memory (D10). A namespace-bound wrapper the
 * kernel builds over performWrite: it stamps `provenance.source` + `sourceId`
 * and routes every record through extraction → verification → dedupe →
 * supersedence exactly like a conversation write.
 */
export interface IngestSink {
  readonly namespace: Namespace;
  readonly sourceId: string;
  readonly sourceKind: SourceKind;
  write(record: IngestRecord): Promise<WriteResult>;
}

export interface IngestResult {
  sourceId: string;
  records: number;      // records handed to the sink
  stored: number;
  deduplicated: number;
  superseded: number;
  rejected: number;
  /** Facts quarantined as disputed (trust-ranked conflict). Absent = 0. */
  disputed?: number;
  errors: { docId: string; reason: string }[];
}

/**
 * Drift-hash bookkeeping for connectors, kernel-implemented over the
 * `source_documents` table. Connectors use it to skip unchanged docs and to
 * detect removals — they never touch the DB themselves.
 */
export interface SourceState {
  /** Prior content hash for a doc, or null if never synced. */
  priorHash(docId: string): Promise<string | null>;
  /** Persist the new hash after a successful write. */
  record(
    docId: string,
    contentHash: string,
    syncedAt: string,
    expectedPriorHash?: string | null,
  ): Promise<void>;
  /** Doc ids currently tracked for this source — for deletion detection. */
  knownDocIds(): Promise<string[]>;
  /** Optional bounded ordered scan used by durable large-source verification. */
  knownDocIdsPage?(
    after: string | null,
    limit: number,
  ): Promise<{ ids: string[]; nextAfter: string | null }>;
  /** Release per-document sync claims without materializing the full ID set. */
  releaseClaims?(): Promise<void>;
  /** Drop tracking for docs that vanished at the source. */
  forget(docIds: string[]): Promise<void>;
}

/** Everything a connector receives from the kernel to run one sync. */
export interface ConnectorContext {
  sink: IngestSink;
  state: SourceState;
  /** Source-specific config: { path } | { dsn } | { token, ... } etc. */
  config: Record<string, unknown>;
}

export interface SyncResult extends IngestResult {
  scanned: number;      // docs enumerated at the source
  changed: number;      // new or hash-differing docs written
  unchanged: number;    // skipped by drift detection
  removed: string[];    // doc ids no longer present at the source
  /** More bounded work is durably checkpointed and should run immediately. */
  continuation?: boolean;
}

/**
 * A scheduled source connector. `available` gates the live path (e.g. a token
 * is present); offline connectors return true. Live-network connectors
 * (Notion/Slack) must also run against recorded fixtures with zero network.
 */
export interface Connector {
  readonly kind: SourceKind;
  available(config: Record<string, unknown>): boolean;
  sync(ctx: ConnectorContext): Promise<SyncResult>;
}

export interface ConnectorCapabilities {
  incremental: boolean;
  liveQuery: boolean;
  sourceAcl: boolean;
  webhook: boolean;
  oauth: boolean;
}

export interface ConnectorCursor {
  value: string;
  updatedAt: string;
}

/** M7/D19 additive enterprise cartridge contract. */
export interface EnterpriseConnector extends Connector {
  readonly version: "halomem-connector/v1";
  capabilities(): ConnectorCapabilities;
  validateConfig(config: Record<string, unknown>): Promise<void>;
  testConnection(config: Record<string, unknown>): Promise<{ ok: boolean; detail?: string }>;
  syncIncremental?(ctx: ConnectorContext, cursor: ConnectorCursor | null): Promise<{
    result: SyncResult;
    cursor: ConnectorCursor | null;
  }>;
}

export interface DurableJob<T = unknown> {
  id: string;
  /**
   * M9/D30: `automation` recurrence is a durable notBefore re-arm, never a timer.
   * M9 Wave 3: `usage-close` is the daily usage-alert close pass (E53) and
   * `usage-emit` delivers committed credit_ledger events to the external
   * billing program (E54) — both the same notBefore discipline (E36).
   */
  kind:
    | "write"
    | "live-query"
    | "source-sync"
    | "movement"
    | "automation"
    | "usage-close"
    | "usage-emit"
    | "copilot-routine"
    | "channel-ingress"
    | "channel-dispatch"
    | "channel-outbound"
    | "channel-maintenance"
    | "channel-verification"
    | "company-file-upload"
    | "relationship-enrichment";
  namespace: Namespace;
  state: "queued" | "running" | "done" | "failed";
  payload: T;
  attempts: number;
  availableAt: string;
  leaseOwner: string | null;
  leaseExpiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * A one-shot bulk importer of a vendor dump. `parse` is pure (offline,
 * deterministic) so the whole importer is testable from a committed fixture;
 * the caller runs the records through an IngestSink.
 */
export interface Importer {
  readonly kind: SourceKind;
  parse(raw: string): IngestRecord[];
}

// ---------------------------------------------------------------------------
// Fragmentation report (M3) — the dashboard that sells the product: after an
// import, show the org its own duplicated + contradictory knowledge across
// sources. Read-only analysis (NOT a driver, NOT an importer) — it may read the
// store through the structural FragmentationReader the kernel provides.
// ---------------------------------------------------------------------------

/** A fact row as the fragmentation analysis sees it (kernel-provided). */
export interface FragmentFact {
  ref: MemoryId;
  namespace: Namespace;
  content: string;
  scope: Scope;
  embedding: number[] | null;
  entities: string[];        // canonical entity names on the fact
  sourceId: string | null;   // provenance source id (null = conversation)
  source: string;            // provenance source kind
  tValidFrom: string;
  tValidTo: string | null;
}

export interface FragmentationReader {
  /** All currently-visible active facts for a namespace subtree. */
  facts(namespace: Namespace): Promise<FragmentFact[]>;
}

export interface DuplicateCluster {
  /** ≥2 facts from DIFFERENT sources whose cosine ≥ the dedupe threshold. */
  members: { ref: MemoryId; sourceId: string | null; content: string }[];
  cosine: number;
}

export interface Contradiction {
  entity: string;
  /** ≥2 currently-valid facts about one entity with overlapping validity. */
  facts: {
    ref: MemoryId;
    sourceId: string | null;
    content: string;
    tValidFrom: string;
    tValidTo: string | null;
  }[];
}

export interface FragmentationReport {
  namespace: Namespace;
  ranAt: string;
  factCount: number;
  sourceCounts: Record<string, number>;   // sourceId → fact count
  duplicateClusters: DuplicateCluster[];
  contradictions: Contradiction[];
}

// ---------------------------------------------------------------------------
// Organization conflict scans + summary-only agent-session observation.
// Scan findings deliberately remain separate from fact_disputes: both evidence
// facts are active, so the quarantined-fact resolution state machine is invalid.
// ---------------------------------------------------------------------------

export type ConflictScanInclude =
  | "knowledge-base"
  | "agent-summary"
  | "policy-manual";

export type ConflictScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "completed_with_gaps"
  | "failed";

export type ConflictScanPhase =
  | "queued"
  | "collecting"
  | "comparing"
  | "publishing"
  | "complete";

export interface ConflictScanRequest {
  targetTeamId?: string | null;
  focus?: string;
  include?: ConflictScanInclude[];
}

export interface ConflictScanProgress {
  itemsScanned: number;
  itemsTotal: number;
  sourcesReached: number;
  agentSummaries: number | null;
  candidatePairs: number;
  /** Candidate pairs durably reviewed by the semantic judge so far. */
  modelPairsReviewed: number;
}

export interface ConflictScanSummary {
  newFindings: number;
  existingFindings: number;
  coverageGaps: string[];
}

export interface ConflictScanRunView {
  id: string;
  targetNamespace: Namespace;
  status: ConflictScanStatus;
  phase: ConflictScanPhase;
  focus: string | null;
  include: ConflictScanInclude[];
  progress: ConflictScanProgress;
  summary: ConflictScanSummary | null;
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
}

export type ConflictFindingFlag =
  | "agent-derived"
  | "cross-team"
  | "cross-source"
  | "low-confidence";

export interface ConflictFindingFactView {
  id: MemoryId;
  namespace: Namespace;
  content: string;
  scope: Scope;
  confidence: number;
  source: string;
  sourceId: string | null;
  /**
   * Human display name for `sourceId` (knowledge-base name), resolved
   * server-side. Null when the fact has no registered source — S11 then falls
   * back to a plain-English label for `source` rather than printing a ULID.
   */
  sourceName: string | null;
  actor: string;
  session: string | null;
  assertionTime: string;
}

export interface ConflictScanFindingView {
  /** Which detector produced it: the batch scan, or the write-time autopilot. */
  origin: "scan" | "write";
  id: string;
  /** Null for write-lane findings — they belong to no scan run (CA6). */
  scanId: string | null;
  targetNamespace: Namespace;
  entity: string;
  category: DisputeCategory;
  reason: string;
  confidence: number;
  flags: ConflictFindingFlag[];
  status: "open" | "acknowledged";
  rowVersion: number;
  firstSeenAt: string;
  lastSeenAt: string;
  left: ConflictFindingFactView;
  right: ConflictFindingFactView;
}

/**
 * A conflict the autopilot settled by itself (CA4). The losing fact's validity
 * is closed and linked, never deleted, so every row here is overturnable.
 */
export interface ConflictAutoDecisionView {
  id: string;
  targetNamespace: Namespace;
  entity: string;
  category: DisputeCategory;
  reason: string;
  confidence: number;
  flags: ConflictFindingFlag[];
  rowVersion: number;
  /** Which side the trust lattice kept. */
  resolution: "keep-left" | "keep-right";
  /** Why it was decided without a person, in machine terms. */
  rule: ConflictAutoRule;
  decidedAt: string;
  /** Luna found that the historical automatic decision may have been wrong. */
  repairProposed?: boolean;
  repairClassification?: string | null;
  left: ConflictFindingFactView;
  right: ConflictFindingFactView;
}

export type ConflictAutoRule =
  | "higher-trust-wins"
  | "equal-trust-newest-wins"
  | "lower-trust-rejected";

/** S11 ledger header: what the autopilot did, and what it has not reached yet. */
export interface ConflictLedgerView {
  autoResolved: number;
  needsReview: number;
  /** Writes still awaiting their conflict check — never rendered as "clean". */
  pendingChecks: number;
  /** True when the judge is unreachable, so pending work cannot drain. */
  detectionDegraded: boolean;
}

export type AgentSessionTurnRole = "user" | "assistant";

export interface AgentSessionTurn {
  role: AgentSessionTurnRole;
  content: string;
}

export interface AgentSessionCompleteInput {
  sessionId: string;
  startedAt?: string;
  endedAt?: string;
  turns: AgentSessionTurn[];
}

export interface AgentSessionSummaryView {
  id: string;
  namespace: Namespace;
  status: "completed" | "failed";
  memoryIds: MemoryId[];
  factCount: number;
  startedAt: string | null;
  endedAt: string | null;
  createdAt: string;
  completedAt: string | null;
  failureCode: string | null;
}

// ---------------------------------------------------------------------------
// Tenancy (M4) — a tenant is a namespace ROOT with an isolated keyspace. The
// ancestor-prefix ACL already makes sibling roots mutually invisible; the
// tenant registry names them and sets per-tenant caps, and the adversarial
// suite proves NO query path leaks across sibling tenants.
// ---------------------------------------------------------------------------

export interface Tenant {
  /** The tenant's root namespace, e.g. "acme". Its keys/memory live under it. */
  id: Namespace;
  name: string;
  status: "active" | "suspended";
  /** Per-tenant monthly LLM/embed spend cap (inherited by the whole subtree). */
  monthlyBudgetUsd: number | null;
  /** Per-tenant default rate limit (requests/min per key). */
  rateLimitPerMin: number | null;
  /**
   * One-way latch recording when the org's setup checklist FIRST reported
   * complete (migration 068). NULL = onboarding gate still locked. Never
   * cleared: a later regressed step re-opens the checklist but does not
   * re-lock a working console.
   */
  onboardingCompletedAt: string | null;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Governed pins (R5A) — stable references only. Legacy policy.pinnedConcepts
// remains a read-only compatibility lane and is not represented here.
// ---------------------------------------------------------------------------

export type PinTarget =
  | { kind: "memory"; ref: MemoryId }
  | { kind: "concept"; ref: string };

export interface MemoryPin {
  id: string;
  namespace: Namespace;
  target: PinTarget;
  source: "manual" | "movement" | "migration";
  createdBy: string;
  createdAt: string;
  releasedBy: string | null;
  releasedAt: string | null;
}

export type ResolvedPin =
  | {
      pinId: string;
      kind: "memory";
      ref: MemoryId;
      content: string;
      createdAt: string;
    }
  | {
      pinId: string;
      kind: "concept";
      ref: string;
      versionPath: string;
      content: string;
      createdAt: string;
    };

// ---------------------------------------------------------------------------
// Verified setup (R4C) — durable first tenant/team activation.
// ---------------------------------------------------------------------------

export interface Team {
  id: string;
  tenantId: Namespace;
  namespace: Namespace;
  name: string;
  createdAt: string;
}

export interface MountedRetrieverCapability {
  name: string;
  capabilities: { graph: boolean; streaming: boolean };
}

export type SetupSourceStatus = "skipped" | "pending" | "synced" | "failed";
export type SetupStatus = "source_pending" | "source_failed" | "waiting_for_agent" | "complete";

export interface SetupInput {
  idempotencyKey: string;
  tenant: {
    id: Namespace;
    name: string;
    monthlyBudgetUsd?: number | null;
    rateLimitPerMin?: number | null;
  };
  /** A single-segment team id. The namespace is always derived server-side. */
  team: { id: string; name: string };
  source?: { kind: SourceKind; config?: Record<string, unknown> };
  retriever?: string;
  agentActor?: string;
}

export interface SetupResult {
  operationId: string;
  idempotencyKey: string;
  status: SetupStatus;
  tenant: Tenant;
  team: Team;
  retriever: MountedRetrieverCapability;
  badge: {
    keyId: string;
    namespace: Namespace;
    actor: string;
    lastUsed: string | null;
  };
  source: null | {
    id: string;
    kind: SourceKind;
    namespace: Namespace;
    status: Exclude<SetupSourceStatus, "skipped">;
    syncResult: SyncResult | null;
    error: string | null;
  };
  /** Present while the idempotent setup credential can be recovered. */
  mcpSnippet: string | null;
}

// ---------------------------------------------------------------------------
// Erasure (M4 / D3) — mem.forget hard-deletes matching memory across the store,
// writes tombstones, and emits a signed deletion certificate. This is the ONE
// governed exception to D7's "never delete": a compliance erasure. Cold-tier
// erasure is crypto-shredding of encrypted blobs, NEVER a git-history rewrite.
// ---------------------------------------------------------------------------

/** What to erase. Resolved to a concrete id set inside the caller's subtree. */
export type ForgetTarget =
  | { kind: "actor"; value: string }         // everything a person authored / is about
  | { kind: "entity"; value: string }        // facts mentioning a canonical entity
  | { kind: "namespace"; value: Namespace }  // an entire subtree
  | { kind: "memory"; value: MemoryId };     // a single fact

export interface TombstoneRecord {
  id: string;
  memoryId: MemoryId;
  namespace: Namespace;
  reason: string;
  erasedAt: string;
  certificateId: string;
}

/**
 * A self-contained, verifiable proof of erasure: the payload (target, erased
 * ids, count, tenant, actor, time) signed with the kernel's ed25519 key. The
 * public key travels inline so a regulator can verify without kernel access.
 */
export interface DeletionCertificate {
  id: string;
  target: ForgetTarget;
  namespace: Namespace;         // the tenant/subtree the erasure ran in
  erasedIds: MemoryId[];
  erasedCount: number;
  /**
   * E6: derived usage rows (usage_events ids / query_traces trace ids)
   * scrubbed with the erasure — deterministically sorted. Optional so
   * pre-E6 stored certificates (fields absent) still verify.
   */
  usageEventIds?: string[];
  queryTraceIds?: string[];
  /** D57: Assistant hard-purge categories; absent on legacy memory erasures. */
  assistantCategories?: {
    conversations: number;
    messages: number;
    turns: number;
    invocations: number;
    costRows: number;
  };
  actor: string;                // who requested it (D9 identity)
  issuedAt: string;
  algorithm: "ed25519";
  publicKey: string;            // base64 (SPKI DER)
  /** base64 signature over the canonical JSON of every field above except this. */
  signature: string;
}

export interface AssistantRecycleRecord {
  namespace: Namespace;
  actor: string;
  recycledAt: string;
  recycledBy: string;
  conversations: number;
  turns: number;
  invocations: number;
  costRows: number;
}

export interface AssistantRecycleResult extends AssistantRecycleRecord {}

export interface AssistantPurgeResult {
  certificate: DeletionCertificate;
}

export interface ForgetResult {
  certificate: DeletionCertificate;
  erasedCount: number;
  tombstones: number;
  /**
   * R6: erasure propagation to mounted EXTERNAL warm stores (additive; absent
   * when no external store is mounted or nothing was erased). "pending" means
   * the purge op is durably queued in warm_mirror_ops and will be retried
   * before any other op for that store. The certificate attests the canonical
   * store; this field is the mirror evidence.
   */
  warmPurges?: WarmPurgeOutcome[];
}

// ---------------------------------------------------------------------------
// Token estimation — one shared heuristic everywhere (chars/4, ceil).
// ---------------------------------------------------------------------------

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// ---------------------------------------------------------------------------
// Federation (M6, CONTRACTS-M6.md) — external backends stay the source of
// truth; HaloMem holds pointer facts (D11), queries sources live through the
// L4 fault lane, and write-back-caches results under usage governance (D14).
// Scaffold-owned: modules import these, never redefine them.
// ---------------------------------------------------------------------------

/** How a connection authenticates live queries (D13). Immutable after create. */
export type CredentialMode = "service" | "passthrough";

/**
 * A usable-but-unserializable credential. `reveal()` returns the secret for
 * the duration of one live call; every serialization surface (toJSON,
 * util.inspect, String()) MUST redact. Passthrough tokens exist only in the
 * request lifetime — never persisted to db, audit, provenance, or logs.
 */
export interface ResolvedCredential {
  readonly mode: CredentialMode;
  readonly connectorId: string;
  reveal(): string;
  toJSON(): { mode: CredentialMode; connectorId: string; token: "[redacted]" };
}

/** One document fetched live from an external source (untrusted input). */
export interface LiveDoc {
  docId: string;
  content: string;
  /** Which surface within the source it came from (table, path, object type). */
  sourceRef: string;
  fetchedAt: string;
  /** Preserve this exact provider object as one verified write candidate. */
  preserveDocument?: boolean;
  sourceAccess?: SourceAccess;
  classification?: DataClassification;
}

/** Everything a connector receives to answer one live query. */
export interface LiveQueryContext {
  query: string;
  pointer: { sourceRef: string };
  /**
   * Server-derived source-local document keys from ACL-visible L2 provenance.
   * Connectors may use these as exact read targets. Callers and models never
   * provide them, and the worker re-fences their source before dispatch.
   */
  documentKeys?: string[];
  credential: ResolvedCredential;
  limit: number;
  timeoutMs: number;
}

/**
 * Optional second ability of a Connector (D12): answer a query against the
 * live source, read-only, bounded by limit + timeoutMs. Import and live-query
 * share the connector's config and source identity.
 */
export interface LiveQueryable {
  liveQuery(ctx: LiveQueryContext): Promise<LiveDoc[]>;
}

/**
 * M8/D27: server-authorized projection for a direct governed source read.
 * Every authority field is produced by the gateway after grant evaluation;
 * agents never construct this context themselves.
 */
export interface GovernedSourceReadContext {
  query: string;
  sourceRef: string;
  fields: string[];
  credential: ResolvedCredential;
  limit: number;
  maxBytes: number;
  timeoutMs: number;
}

export interface GovernedSourceReadResult {
  rows: Record<string, unknown>[];
  bytes: number;
  truncated: boolean;
}

/** Optional connector ability used only after M8 gateway authorization. */
export interface GovernedSourceReadable {
  governedRead(ctx: GovernedSourceReadContext): Promise<GovernedSourceReadResult>;
}

/** A ranked pointer-fact match — the L4 router's output. */
export interface PointerMatch {
  ref: MemoryId;
  connectorId: string;
  sourceRef: string;
  score: number;
  content: string;
  /** ACL-visible document coordinates bound to this exact source route. */
  documentKeys?: string[];
  /** ACL-visible facts that established the document-to-source binding. */
  evidenceRefs?: MemoryId[];
  /** True when execution must re-prove document ownership before provider I/O. */
  documentOwnershipRequired?: boolean;
  sourceAccess?: SourceAccess;
  classification?: DataClassification;
}

/** Phase-1 marker returned inline with local results (D15). */
export interface LiveStatus {
  state: "running" | "none";
  sources: string[];
  /** Redeem via mem_live_result. Durable, subject-fenced, 120s expiry. */
  ticket?: string;
}

/** Phase-2 payload redeemed from a ticket (D15). */
export interface LiveResult {
  state: "running" | "done" | "failed";
  blocks: ContextBlock[];
  /** Cached facts closed by a contradicting live result (D7 chain). */
  superseded: MemoryId[];
  /** Per-source outcome, mirrored into audit detail. */
  sources: { connectorId: string; outcome: "hit" | "miss" | "denied" | "error" }[];
}

// ---------------------------------------------------------------------------
// M9-parity — builder-local shared types promoted as type-only re-exports.
// Type-only (`export type ... from`) so nothing here adds a runtime import
// edge: drivers and connectors importing types.js still load zero modules.
// The defining module stays the single source of truth; consumers outside
// that module's subsystem import from here per the shared-types convention.
// ---------------------------------------------------------------------------

/** #4 (E41): how a source's records reach the write path / failure buckets. */
export type { SourceDriver, SourceFailureClass } from "./console/rollups/sync-overview.js";
/** #15 (E49): server-derived internal/external caller classification. */
export type { CallerClass } from "./console/rollups/user-analytics.js";
/** #23 (E52): product key-type labels over the existing ROLES. */
export type { ProductKeyType, TypedKeyRecord } from "./auth/key-types.js";
/** #1 (E2): GitHub App installation summaries (no token/config fields exist). */
export type { GitHubInstallationStatus, GitHubInstallationSummary } from "./ingest/github-app.js";

// ---------------------------------------------------------------------------
// M10 ACCESS (CONTRACTS-M10-ACCESS.md) — role-scoped memory graph. One
// canonical graph; a server-authorized projection per subject (D40). Product
// human roles are a PUBLIC-boundary translation of the internal HumanRole
// (owner→root, auditor→member + audit_read grant — D41); internal Role /
// HumanRole storage is unchanged. Scaffold-owned: modules import these,
// never redefine them.
// ---------------------------------------------------------------------------

/** The only human roles the product boundary exposes (D41). */
export type ProductHumanRole = "root" | "admin" | "member";

/**
 * What a grant permits. `consume` reads UPWARD via the existing ancestor ACL
 * rule; `govern` administers DOWNWARD over the granted subtree via the
 * exact-match + escaped-prefix predicate (D44). `audit_read` is the scoped
 * entitlement that replaces the auditor role at the public boundary.
 */
export type AccessMode = "consume" | "govern" | "audit_read";

/**
 * The server-resolved authorization projection for one subject (FR3). Every
 * graph, memory, allocator, source, knowledge, skill, and delegation path
 * consumes this — UI code is never an authorization boundary. `hash` is the
 * stable cache-partitioning key; `version` advances on any role/grant/mount/
 * status change and strands stale caches (D47).
 */
export interface AccessProjection {
  tenantId: string;
  subjectId: string;
  role: ProductHumanRole;
  /** Roots readable via the ancestor ACL rule (self + prefix ancestors). */
  consumeRoots: readonly Namespace[];
  /** Roots administered over their whole subtree (escaped-prefix predicate). */
  governRoots: readonly Namespace[];
  /** Exact member-personal spaces (never widened to siblings). */
  personalRoots: readonly Namespace[];
  /** Operations the role ceiling + grants permit (e.g. "graph:read"). */
  allowedOperations: readonly string[];
  /** Highest sensitivity class visible; absent = tenant default. */
  sensitivityCeiling?: string;
  version: number;
  hash: string;
}

/**
 * One row of `access_grants`. Resource IDs are opaque and server-owned —
 * callers never supply namespace strings (D9). Revocation sets `revokedAt`;
 * rows are never deleted (D47).
 */
export interface AccessGrantRecord {
  id: string; // ULID
  tenantId: string;
  principalType: "human" | "agent" | "service";
  principalId: string;
  resourceType: "function" | "personal" | "common" | "audit";
  /** Opaque server-owned resource ID — never an authoritative namespace. */
  resourceId: string;
  accessMode: AccessMode;
  source: "membership" | "direct" | "system";
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

/**
 * Who a root View-as preview projects (D43). An actual person is exact and
 * preferred; a role simulation requires at least one functional area — a
 * bare role is not a valid preview.
 */
export type PreviewSubject =
  | { kind: "user"; subjectUserId: string }
  | {
      kind: "role";
      role: Exclude<ProductHumanRole, "root">;
      /** Opaque functional-area IDs, re-resolved inside the root's tenant. */
      functionalAreaIds: readonly string[];
    };

/**
 * One row of `access_preview_sessions`. The credential itself is stored only
 * as sha256 (`token_hash`) and NEVER appears on this record or any
 * serialization; it travels solely in the `x-halomem-preview-token` header.
 * Exit/expiry sets `endedAt` — never a delete (D47). Audit attributes every
 * preview event to `rootUserId`, never to the subject.
 */
export interface PreviewSessionRecord {
  id: string; // ULID
  tenantId: string;
  rootUserId: string;
  subject: PreviewSubject;
  reason: string;
  createdAt: string;
  /** Server-set; 15 minutes from creation by default. */
  expiresAt: string;
  endedAt: string | null;
}

/** One visible node of the projected graph. Hidden nodes are simply absent. */
export interface MemoryGraphNode {
  id: string;
  kind: string; // e.g. "source" | "knowledge" | "skill" | "agent" | "tier"
  label: string;
  /** Post-filter aggregate for this node's connected objects (D45). */
  count?: number;
}

/** Returned only when BOTH endpoints are visible to the subject (D45). */
export interface MemoryGraphEdge {
  from: string;
  to: string;
  relation: string;
}

/** A scope option the subject is ALREADY authorized to select (never wider). */
export interface MemoryGraphScopeOption {
  /** Opaque scope ID — re-resolved server-side on selection (D9). */
  id: string;
  label: string;
}

/**
 * The `/v1/memory-graph` response skeleton (FR4). Contains only
 * subject-safe projection metadata: no raw grant rows, policy expressions,
 * hidden counts, or foreign IDs. Counts are computed after filtering (D45).
 */
export interface MemoryGraphResponse {
  /** Role-adaptive: "Your" | "<Function>" | "Company" memory network. */
  title: string;
  nodes: readonly MemoryGraphNode[];
  edges: readonly MemoryGraphEdge[];
  counts: { nodes: number; edges: number };
  /** Authorized scope-switch options; default is the union of all grants. */
  scopes: readonly MemoryGraphScopeOption[];
}

// ---------------------------------------------------------------------------
// Communication channels — shared contracts
// ChannelKind is catalog metadata only. Executable boundaries use
// ExecutableChannelKind — cohorts 1–3 (the C2/C3 widening is the additive
// contract change the C0 contract reserved). Voice Web, Voice Phone, and
// WhatsApp T16 stay catalog-only until their dedicated long-lived workers
// exist: an executable kind without a runtime would be a false capability.
// ---------------------------------------------------------------------------
export type ChannelKind =
  | "telegram" | "slack" | "gmail" | "google_chat"
  | "whatsapp_cloud" | "instagram" | "messenger" | "x" | "sms"
  | "sendgrid_email" | "outlook" | "line" | "microsoft_teams"
  | "website_widget" | "custom_api" | "discord"
  | "voice_web" | "voice_phone" | "whatsapp_t16";
export type ExecutableChannelKind = Exclude<
  ChannelKind,
  "voice_web" | "voice_phone" | "whatsapp_t16"
>;
/** The original C0/C1 executable set; kept for the foundation contract. */
export type FirstCohortChannelKind = Extract<
  ChannelKind,
  "telegram" | "slack" | "gmail" | "google_chat"
>;

export type ChannelLifecycleState = "draft" | "active" | "paused" | "disconnected";
export type ChannelAuthorityState =
  | "storefront_authoritative" | "shadow" | "halomem_inbound"
  | "halomem_active" | "rollback";
export type ChannelVerificationState =
  | "unverified" | "pending" | "verified" | "degraded" | "revoked";
export type ChannelHealthState = "unknown" | "healthy" | "degraded" | "failed";
export type ChannelReceiptState = "processing" | "accepted" | "denied" | "retryable";
export type ChannelConsentState = "unknown" | "granted" | "denied" | "revoked";
export type ChannelHandoffState = "agent" | "human_requested" | "human_active" | "closed";

export interface ChannelPolicyState {
  consent: {
    state: ChannelConsentState;
    basis: "provider" | "connection_policy" | "operator" | "unknown";
    recordedAt: string | null;
  };
  handoff: {
    state: ChannelHandoffState;
    reasonCode: string | null;
    changedAt: string | null;
  };
}

export interface ChannelAttachmentMetadata {
  providerFileId: string;
  providerUniqueFileId?: string;
  fileName: string | null;
  mediaType: string | null;
  sizeBytes: number | null;
  direction: "inbound" | "outbound";
  disposition?: "inline" | "attachment" | "unknown";
  sha256?: string | null;
}

export interface ChannelReplyTarget {
  provider: ExecutableChannelKind;
  connectionId: string;
  recipientKey: string;
  conversationKey: string;
  threadKey: string | null;
  replyToProviderMessageId: string | null;
  attachmentRefs: readonly string[];
}

export interface ChannelIngressRouteBinding {
  connectionId: string;
  kind: ExecutableChannelKind;
  routeKeyHash: string;
  providerInstallationKey: string;
  authorityEpoch: number;
  credentialVersion: number;
  authenticationSecretTypes: readonly string[];
}

export interface ChannelProviderBinding {
  provider: ExecutableChannelKind;
  connectionId: string;
  routeKeyHash: string;
  providerInstallationKey: string;
  providerClaims: Readonly<Record<string, string | null>>;
  allowedResourceKeys: readonly string[];
  authorityEpoch: number;
  credentialVersion: number;
}

export interface ResolvedChannelCredential {
  secretType: string;
  credentialVersion: number;
  reveal(): string;
  destroy(): void;
  toJSON(): never;
}

export interface ResolvedChannelSecretSet {
  readonly credentialVersion: number;
  get(secretType: string): ResolvedChannelCredential | null;
  require(secretType: string): Uint8Array;
  destroy(): void;
}

export interface RawChannelRequest {
  method: "POST";
  path: string;
  headers: Readonly<Record<string, string | undefined>>;
  rawBody: Uint8Array;
  receivedAt: string;
  remoteAddressHash: string;
}

export interface VerifiedProviderPayload {
  provider: ExecutableChannelKind;
  kind: "event" | "challenge" | "verification" | "notification";
  providerEventKey: string;
  receivedAt: string;
  providerClaims: Readonly<Record<string, string>>;
  payload: unknown;
}

export interface VerifiedChannelRequest {
  kind: "event" | "challenge" | "ignored";
  binding: ChannelProviderBinding;
  payload: VerifiedProviderPayload | null;
  responseStatus: number;
  responseBody?: unknown;
}

export interface ProviderRequest {
  operation: string;
  method: "GET" | "POST" | "DELETE";
  path: string;
  headers: Readonly<Record<string, string>>;
  body?: Uint8Array;
  idempotencyKey?: string;
}

export interface ProviderNormalizedCandidate {
  providerEventKey: string;
  conversationKey: string;
  threadKey: string | null;
  occurredAt: string;
  participantPrincipalIds: string[];
  resourceGroupIds: string[];
  text: string;
  attachments: ChannelAttachmentMetadata[];
  provenance: {
    provider: ExecutableChannelKind;
    providerMessageId?: string;
    providerDeliveryId?: string;
  };
  trustedReplyTarget: ChannelReplyTarget;
  piiSubjects: string[];
  policyState: ChannelPolicyState;
}

export interface ChannelConnection {
  id: string;
  tenantRoot: Namespace;
  namespace: Namespace;
  kind: ExecutableChannelKind;
  displayName: string;
  displayMetadata: Readonly<Record<string, string>>;
  lifecycleState: ChannelLifecycleState;
  authorityState: ChannelAuthorityState;
  outboundAuthority: boolean;
  authorityEpoch: number;
  credentialVersion: number;
  providerInstallationKey: string;
  routeKeyHash: string;
  verificationState: ChannelVerificationState;
  healthState: ChannelHealthState;
  healthDetail: string | null;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  createdBy: string;
  createdAt: string;
  updatedBy: string;
  updatedAt: string;
  pausedBy: string | null;
  pausedAt: string | null;
  pauseReason: string | null;
  disconnectedBy: string | null;
  disconnectedAt: string | null;
  disconnectReason: string | null;
  rowVersion: number;
}

export interface CreateChannelConnectionRecord {
  id: string;
  tenantRoot: Namespace;
  namespace: Namespace;
  kind: ExecutableChannelKind;
  displayName: string;
  displayMetadata: Readonly<Record<string, string>>;
  providerInstallationKey: string;
  routeKeyHash: string;
  createdBy: string;
  createdAt: string;
}

export interface ChannelTransitionRecord {
  tenantRoot: Namespace;
  namespace: Namespace;
  connectionId: string;
  operation:
    | "pause" | "resume" | "assign" | "rotate" | "activate"
    | "disconnect" | "cutover" | "rollback" | "ownership-change";
  expectedRowVersion: number;
  expectedAuthorityEpoch: number;
  actor: string;
  reason: string | null;
  occurredAt: string;
}

export interface AgentChannelGrant {
  id: string;
  tenantRoot: Namespace;
  namespace: Namespace;
  connectionId: string;
  keyId: string;
  revision: number;
  inboundAllowed: boolean;
  outboundAllowed: boolean;
  memoryAllowed: boolean;
  systemTest: boolean;
  verificationOnly: boolean;
  status: "active" | "revoked" | "expired";
  authorityEpoch: number;
  credentialVersion: number;
  createdBy: string;
  createdAt: string;
  revokedBy: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
}

export interface NormalizedChannelEvent extends ProviderNormalizedCandidate {
  id: string;
  namespace: Namespace;
  connectionId: string;
  receivedAt: string;
  direction: "inbound" | "outbound";
  classification: DataClassification;
  sourceAccess: SourceAccess;
  authorityEpoch: number;
  credentialVersion: number;
  grantId: string;
  grantRevision: number;
}

export interface ChannelSecretContext {
  environment: string;
  tenantRoot: Namespace;
  namespace: Namespace;
  connectionId: string;
  provider: ExecutableChannelKind;
  secretType: string;
  credentialVersion: number;
}
export interface SealedChannelSecret {
  format: "channel-secret/v1";
  ciphertext: string;
  nonce: string;
  tag: string;
  kekId: string;
  keyVersion: number;
}

export type ChannelJobKind =
  | "channel-ingress" | "channel-dispatch" | "channel-outbound"
  | "channel-maintenance" | "channel-verification";
export type ChannelMaintenanceOperation =
  | "gmail-watch-renew" | "gmail-history-sync" | "oauth-refresh"
  | "provider-health" | "token-revoke" | "verification-grant-revoke"
  | "rollback-cleanup" | "ownership-reconcile";
export interface ChannelJobPayload {
  connectionId: string;
  eventId?: string;
  sendIntentId?: string;
  maintenanceOperation?: ChannelMaintenanceOperation;
  authorityEpoch: number;
  credentialVersion: number;
  grantId?: string;
  grantRevision?: number;
}

export interface ChannelSendIntent {
  id: string;
  namespace: Namespace;
  connectionId: string;
  sourceEventId: string;
  replyOrdinal: number;
  approvedText: string;
  classification: DataClassification;
  target: ChannelReplyTarget;
  state:
    | "pending" | "attempted" | "confirmed" | "retryable" | "terminal"
    | "outcome_unknown" | "operator_required";
  authorityEpoch: number;
  credentialVersion: number;
  grantId: string;
  grantRevision: number;
  providerMessageId: string | null;
  createdAt: string;
  updatedAt: string;
}
