/**
 * HaloMem syscall layer (M1 — D9 identity model).
 *
 * BREAKING (CONTRACTS-M1.md): syscalls no longer accept `namespace`/`actor`
 * from the caller. Every syscall takes a resolved `Identity` — namespace and
 * actor come ONLY from the credential the kernel resolved. No request path
 * reaches MemoryIndex without one.
 *
 * Per-syscall pipeline:
 *   metrics.time(op) → role check → policy fetch (PolicyStore, async) →
 *   rate limit (TokenBucket per keyId, denial → 429-style RateLimitError +
 *   audit row) → op body → audit.
 *
 * Role rules (CONTRACTS-M1.md):
 *   agent/member → syscalls only (admin ops enforced in transport/admin layer)
 *   auditor      → read/search/stats/assemble/fault allowed, memWrite DENIED
 *   admin/owner  → everything
 *
 * Budget brownout (D module): when the namespace subtree is over its monthly
 * USD cap, mem_write degrades to verbatim (no LLM) and the degradation is
 * logged + audited — the agent is never hard-failed. An LLM circuit-open
 * (LlmUnavailableError) likewise falls back to verbatim storage; an embedder
 * circuit-open during search falls back to the BM25-only lane.
 *
 * D4: EVERY syscall produces at least one audit row per logical outcome,
 * including denied / miss / error (write/fault/assemble audit inside their
 * modules; denial and error paths audit here).
 */

import type { KernelConfig } from "../config.js";
import type {
  AuditOp,
  AccessSubject,
  Embedder,
  FaultResult,
  ForgetResult,
  WarmPurgeOutcome,
  ForgetTarget,
  Identity,
  ChannelAuthorityContext,
  LiveResult,
  LiveStatus,
  LlmClient,
  MemoryObject,
  MemStats,
  Namespace,
  RetrieverDriver,
  ScopedView,
  ScoredRef,
  SyscallContext,
  Tenant,
  WorkingSet,
  WriteRequest,
  WriteResult,
} from "../types.js";
import { estimateTokens } from "../types.js";

import type { Db } from "../db/client.js";
import { MemoryIndex } from "../index/index.js";
import { appendAuditEventWithSeq, type AuditLog } from "../audit/index.js";
import type { ColdStore } from "../cold/index.js";
import type { ContextAllocator } from "../allocator/index.js";
import type { FaultHandler } from "../fault/index.js";
import type { WritePath, WritePathHooks } from "../write/index.js";
import {
  bm25Rank,
  hybridMerge,
  retrievalContent,
  searchL2,
  type L2IndexLike,
} from "../retrieval/index.js";
import type { RetrievalSourceProjection } from "../retrieval/source-context.js";
import { BASELINE_DRIVER_NAME, isDriverUnavailableError } from "../driver/index.js";
import { pickDriverName, type RoutingPolicy } from "../routing/index.js";
import { AuthzError } from "../auth/index.js";
import { DEFAULT_RATE_LIMIT_PER_MIN, type BudgetGuard, type PolicyConfigX } from "../policy/index.js";
import {
  effectiveBudgetUsd,
  effectiveRateLimit,
  tenantGate,
  TenantSuspendedError,
} from "../policy/tenant.js";
import { forget as erasureForget, type SigningKey } from "../erasure/index.js";
import { LlmUnavailableError } from "../resilience/index.js";
import type { MetricsRegistry } from "../metrics/index.js";
import type { Logger } from "../metrics/index.js";
import { ClassificationDeniedError } from "../dlp/index.js";
import {
  querySha256,
  recordUsageStandalone,
  recordUsageTx,
  resolveTraceId,
  upgradeTraceSummary,
  usageEventsEnabled,
  type UsageEventInput,
} from "../usage/index.js";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Thrown when a key exceeds its per-minute rate limit (transport → 429). */
export class RateLimitError extends Error {
  constructor(message: string, readonly retryAfterSec?: number) {
    super(message);
    this.name = "RateLimitError";
  }
}

// ---------------------------------------------------------------------------
// Deps
// ---------------------------------------------------------------------------

/** Per-namespace module bundle (resilient LLM/embedder wired per namespace). */
export interface NamespaceRuntime {
  embedder: Embedder;
  llm: LlmClient;
  allocator: ContextAllocator;
  faultHandler: FaultHandler<Db>;
  writePath: WritePath;
}

/** Kernel internals handed to every syscall. */
export interface SyscallDeps {
  config: KernelConfig;
  db: Db;
  index: MemoryIndex;
  audit: AuditLog;
  cold: ColdStore;
  metrics: MetricsRegistry;
  rateLimiter: {
    allow(key: string, limit: number): boolean | Promise<boolean>;
    /**
     * Durable stores expose the full outcome so a denial can carry its
     * retry-after seconds out to the transport (429 + `retry-after` header).
     * Optional: in-process buckets and test fakes implement `allow` only and
     * fall back to a denial without timing.
     */
    consume?(
      bucketKey: string,
      limit: number,
      windowMs: number,
    ): Promise<{ allowed: boolean; retryAfterSec: number }>;
  };
  budget: BudgetGuard;
  logger: Logger;
  /** Optional commercial quota clamp. Standalone builds leave this absent. */
  quotaRateLimit?(current: number, actor?: string): number;
  /**
   * Durable credential-state check. Identity objects may outlive the request
   * that resolved them (notably stdio MCP), so no syscall may trust the
   * snapshot without re-checking the backing key row.
   */
  isCredentialActive(identity: Identity): Promise<boolean>;
  /** Effective (merged, cached) policy for a namespace — PolicyStore.get. */
  getPolicy(namespace: Namespace): Promise<PolicyConfigX>;
  /**
   * M4: resolve the owning Tenant of a namespace (its root), or null when the
   * root is unregistered. The gate uses this to deny suspended tenants and to
   * lower the effective rate-limit/budget caps; a null tenant leaves M1/M2/M3
   * behavior unchanged.
   */
  resolveTenant(namespace: Namespace): Promise<Tenant | null>;
  /**
   * M4: the process-wide ed25519 signing key (loaded once at boot). Handed to
   * the erasure engine so every DeletionCertificate shares one public key.
   */
  signingKey: SigningKey;
  /** Namespace-scoped resilient runtime (cost attribution + per-ns breakers). */
  runtimeFor(namespace: Namespace): NamespaceRuntime;
  /** Async write lane (WriteQueue) — returns a ticket immediately. */
  enqueueWrite(
    req: WriteRequest,
    identity: Identity,
    agentId: string,
  ): Promise<{ ticket: string }>;
  /** M2: mounted retriever drivers (unknown names → baseline + warn). */
  registry: DriverRegistrySlice;
  /** M2: ACL-scoped read fence for a namespace (module A's buildScopedView). */
  buildView(
    namespace: Namespace,
    access?: AccessSubject,
    sourceProjection?: RetrievalSourceProjection,
  ): ScopedView;
  /**
   * R6 (halomem-warmstore/v1): post-commit write-through to mounted external
   * warm stores. Fires AFTER the canonical write transaction committed and
   * MUST never throw (mirror failure is brownout — the op stays in the
   * durable outbox). Optional so hand-rolled test deps stay valid.
   */
  afterWriteCommit?(result: WriteResult): Promise<void>;
  /** M7: access telemetry can schedule governed tier movement after commit. */
  afterAccessCommit?(ids: string[], namespace: Namespace): Promise<void>;
  l1?: {
    get(id: string, identity: Identity, policyVersion: string): MemoryObject | null;
    set(obj: MemoryObject, identity: Identity, policyVersion: string): void;
  };
  /**
   * R6: enqueue external warm-store purge ops INSIDE the erasure transaction
   * (handed through to the erasure engine as ForgetDeps.enqueueWarmPurges) —
   * a DeletionCertificate can never exist without its mirror purges durably
   * queued.
   */
  enqueueWarmPurges?(
    tx: Db,
    erasedIds: string[],
    namespace: Namespace,
  ): Promise<void>;
  /**
   * R6: erasure propagation — drain the already-queued purge ops to mounted
   * external warm stores after the canonical erasure committed. Returns the
   * per-store outcome attached to ForgetResult.warmPurges. MUST never throw.
   * Called even for a 0-row forget so a re-run drains still-pending purges.
   */
  afterForgetCommit?(
    erasedIds: string[],
    namespace: Namespace,
  ): Promise<WarmPurgeOutcome[]>;
  /**
   * D39: optional LLM trace-summary upgrader, wired only when the extraction
   * LLM lane is live. Fired-and-forgotten from mem_search; any failure leaves
   * the verbatim query summary standing. Optional so hand-rolled test deps
   * stay valid.
   */
  traceSummarizer?(query: string, namespace: Namespace): Promise<string>;
  /**
   * M6 (D15): federated live lane. Absent → mem_fault behaves exactly as
   * before and mem_live_result reports an audited miss for every ticket.
   */
  l4?: L4LaneSeam;
}

/** Minimal slice of module A's DriverRegistry the syscall layer needs. */
export interface DriverRegistrySlice {
  get(name: string): RetrieverDriver;
}

// ---------------------------------------------------------------------------
// M6 — L4 federated lane seam (D15 two-phase surface, module F).
//
// The syscall layer never runs federation itself. When the kernel wires an
// `l4` dep, mem_fault hands the query (plus the phase-1 outcome and any
// passthrough source tokens) to `dispatch` AFTER the local fault resolved;
// a non-null return means a live confirmation is running and the phase-1
// response carries `liveStatus` + a model-facing statement. `result` redeems
// a ticket for mem_live_result (undefined = unknown / expired / foreign —
// the lane fences tickets by namespace, exactly like writeStatus).
// ---------------------------------------------------------------------------

/** Everything the syscall layer hands through the seam on one dispatch. */
export interface L4DispatchOptions {
  identity: Identity;
  /** Server-owned fence when this dispatch originated from a channel grant. */
  channelAuthority?: ChannelAuthorityContext;
  agentId: string;
  k?: number;
  tokenBudget?: number;
  /**
   * Passthrough source tokens (connectorId → token) from the syscall context
   * (MCP tool arg / X-Halo-Source-Tokens header). RADIOACTIVE (D13): handed
   * to the credential broker verbatim and forgotten — this layer NEVER logs,
   * audits, persists, or echoes them, and neither may the lane.
   */
  sourceTokens?: Record<string, string>;
  /**
   * The phase-1 outcome, so the lane can decide whether a dispatch is
   * warranted (L3 miss / best score below the floor) and which pointers match.
   */
  phase1: FaultResult;
}

/** What a started dispatch hands back for the phase-1 marker. */
export interface L4DispatchOutcome {
  ticket: string;
  /** Human-readable source names for the phase-1 statement (never tokens). */
  sources: string[];
}

/** Kernel-wired seam to module D's federation lane. Optional everywhere. */
export interface L4LaneSeam {
  /**
   * Start a live confirmation for `query`, or null when no pointer matched /
   * federation declined. MUST audit each dispatch itself (D4) and MUST NOT
   * serialize `opts.sourceTokens` anywhere.
   */
  dispatch(
    query: string,
    opts: L4DispatchOptions,
  ): Promise<L4DispatchOutcome | null> | L4DispatchOutcome | null;
  /**
   * Redeem a phase-2 ticket. `undefined` = unknown, expired (120s), or a
   * ticket minted for another namespace (fenced like writeStatus — foreign
   * collapses to miss, no cross-tenant oracle).
   */
  result(
    ticket: string,
    identity: Identity,
    sourceTokens?: Record<string, string>,
  ): Promise<LiveResult | undefined> | LiveResult | undefined;
}

/** The D15 phase-1 statement — one format everywhere (MCP echoes it as text). */
export function liveConfirmStatement(sources: string[], ticket: string): string {
  return (
    `Answering from memory; confirming against ${sources.join(", ")}. ` +
    `Call mem_live_result with ticket ${ticket} for confirmed data.`
  );
}

// ---------------------------------------------------------------------------
// M2 — driver-routed L2 planning (shared by mem_search and the fault handler)
// ---------------------------------------------------------------------------

/** What planViaDriver hands back alongside the refs, for audit attribution. */
export interface DriverPlanOutcome {
  refs: ScoredRef[];
  /** Name of the driver that actually produced `refs`. */
  driver: string;
  /** Set when an unavailable driver degraded, e.g. "mem0->baseline". */
  fallback?: string;
}

/** The slice of SyscallDeps planViaDriver consumes (kernel satisfies it). */
export interface DriverPlanDeps {
  registry: DriverRegistrySlice;
  buildView(
    namespace: Namespace,
    access?: AccessSubject,
    sourceProjection?: RetrievalSourceProjection,
  ): ScopedView;
  logger: Logger;
}

/**
 * Route one L2 retrieval through the policy-selected driver (M2 wiring):
 * pickDriverName(policy, query) → registry.get (unknown → baseline + warn)
 * → driver.plan over the caller's ScopedView. A DriverUnavailableError from
 * a non-baseline driver (e.g. the mem0 sidecar is down) degrades to the
 * baseline driver over the SAME view and reports `fallback` so the caller
 * can audit `driver_fallback=<name>->baseline`. Every other error (circuit
 * open, bugs) propagates untouched.
 */
export async function planViaDriver(
  deps: DriverPlanDeps,
  policy: RoutingPolicy,
  namespace: Namespace,
  query: string,
  k: number,
  tokenBudget: number,
  access?: AccessSubject,
  sourceProjection?: RetrievalSourceProjection,
): Promise<DriverPlanOutcome> {
  const driver = deps.registry.get(pickDriverName(policy, query));
  const view = deps.buildView(namespace, access, sourceProjection);
  const q = { query, view, k, tokenBudget };
  try {
    return { refs: await driver.plan(q), driver: driver.name };
  } catch (err) {
    if (!isDriverUnavailableError(err) || driver.name === BASELINE_DRIVER_NAME) {
      throw err;
    }
    deps.logger.warn("retriever driver unavailable - falling back to baseline", {
      namespace,
      driver: driver.name,
      error: err.message,
    });
    const baseline = deps.registry.get(BASELINE_DRIVER_NAME);
    return {
      refs: await baseline.plan(q),
      driver: baseline.name,
      fallback: `${driver.name}->${BASELINE_DRIVER_NAME}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Syscall argument / result types (D9: no namespace, no actor)
// ---------------------------------------------------------------------------

export interface MemReadArgs {
  id: string;
}

export interface MemReadResult {
  found: boolean;
  /**
   * Always false in caller-facing results: an exists-but-forbidden row is
   * indistinguishable from a miss so callers cannot probe for the existence
   * of rows in namespaces they are denied. The audit trail still records
   * 'denied' distinctly from 'miss' (D4).
   */
  denied: boolean;
  memory: MemoryObject | null;
}

export interface MemSearchArgs {
  query: string;
  k?: number;
  tokenBudget?: number;
  validOnly?: boolean;
  /**
   * M6 (D15, contract module F): 'auto' (default) lets a search that finds
   * NOTHING locally start a live confirmation through the L4 lane — the
   * verified results land in the write-back cache (D14) for subsequent
   * search/fault calls, and the dispatch is audited (D4). 'off' guarantees no
   * live source is ever queried by this search. The result stays the flat
   * ScoredRef[] (pre-M6 shape); mem_fault remains the two-phase ticket
   * surface for callers that need the phase-2 handle.
   */
  live?: "off" | "auto";
}

export interface MemWriteArgs {
  scope: WriteRequest["scope"];
  content: string;
  session?: string;
  hints?: WriteRequest["hints"];
  /** true → enqueue via WriteQueue and return { ticket } immediately. */
  async?: boolean;
}

export type MemWriteResult = WriteResult | { ticket: string };

export interface MemFaultArgs {
  query: string;
  k?: number;
  tokenBudget?: number;
  /**
   * M6 (D15): 'auto' (default) lets the kernel start a live confirmation when
   * the L4 lane is wired and a pointer matches; 'off' never dispatches.
   */
  live?: "off" | "auto";
  /**
   * M6 (D13): per-connector passthrough tokens (connectorId → token) for
   * this request only. NEVER logged, audited, persisted, or echoed.
   */
  sourceTokens?: Record<string, string>;
}

/**
 * M6 (D15): mem_fault's phase-1 response — the plain FaultResult plus, when a
 * live confirmation dispatched, `liveStatus` and the model-facing statement.
 */
export type MemFaultResult = FaultResult & {
  liveStatus?: LiveStatus;
  /** Present iff liveStatus.state === 'running' — append to the answer text. */
  liveStatement?: string;
};

/** mem_live_result (M6 / D15): redeem a phase-2 ticket. */
export interface MemLiveResultArgs {
  ticket: string;
  /** Re-submit passthrough tokens after a replica hop; never persisted. */
  sourceTokens?: Record<string, string>;
}

/**
 * Miss idiom matches mem_read: unknown / expired / foreign tickets collapse
 * to `{ found: false, live: null }` (audited 'miss'), never a throw.
 */
export interface MemLiveResultResult {
  found: boolean;
  live: LiveResult | null;
}

export interface MemAssembleArgs {
  taskHint?: string;
}

export type MemStatsArgs = Record<string, never>;

/** mem.forget (M4 / D3): what to erase — resolved to ids in the caller's subtree. */
export interface MemForgetArgs {
  target: ForgetTarget;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Usage analytics (D36–D39)
// ---------------------------------------------------------------------------

/** Audited ops that get a companion usage_events row (E1). */
const USAGE_TRACKED_OPS = new Set<string>(["read", "search", "fault", "assemble"]);

/** Per-call trace grouping (D37), resolved once at the syscall boundary. */
interface ResolvedTrace {
  traceId: string;
  tool: string;
  sensitiveTurnId?: string;
}

function resolveTrace(ctx?: SyscallContext): ResolvedTrace {
  return {
    traceId: resolveTraceId(ctx?.traceId),
    tool: ctx?.tool ?? "kernel",
    ...(ctx?.sensitiveTurnId ? { sensitiveTurnId: ctx.sensitiveTurnId } : {}),
  };
}

/** Brownout sink: usage-write failures are logged, never thrown (D36). */
function usageFailureHook(deps: SyscallDeps): { onFailure: (err: unknown) => void } {
  return {
    onFailure: (err) =>
      deps.logger.warn("usage event write failed - syscall outcome stands (brownout)", {
        error: err instanceof Error ? err.message : String(err),
      }),
  };
}

function usageInput(
  identity: Identity,
  trace: ResolvedTrace,
  fields: {
    auditSeq: number;
    ts: string;
    op: string;
    result: string;
    latencyMs: number;
    tokens?: number;
    returned?: number;
    driver?: string | null;
    sourceTier?: string | null;
    sourceIds?: unknown[] | null;
    topScore?: number | null;
    queryText?: string | null;
  },
): UsageEventInput {
  return {
    auditSeq: fields.auditSeq,
    traceId: trace.traceId,
    ts: fields.ts,
    namespace: identity.namespace,
    actor: identity.actor,
    principal: identity.role === "agent" ? "agent" : "human",
    callerClass: identity.callerClass ?? "unclassified",
    op: fields.op,
    tool: trace.tool,
    result: fields.result,
    latencyMs: fields.latencyMs,
    tokens: fields.tokens ?? 0,
    returned: fields.returned ?? 0,
    driver: fields.driver ?? null,
    sourceTier: fields.sourceTier ?? null,
    sourceIds: fields.sourceIds ?? null,
    topScore: fields.topScore ?? null,
    ...(fields.queryText !== undefined ? { queryText: fields.queryText } : {}),
  };
}

/**
 * ACL rule (CONTRACTS.md): caller in namespace N sees rows whose namespace is
 * N itself or a '/'-split prefix ancestor of N.
 */
export function aclAllows(callerNamespace: Namespace, rowNamespace: Namespace): boolean {
  return (
    rowNamespace === callerNamespace ||
    callerNamespace.startsWith(rowNamespace + "/")
  );
}

/** Source ACL subject derived only from the server-resolved identity. */
export function sourceAccessSubject(identity: Identity): AccessSubject {
  const principals = new Set<string>([
    identity.actor,
    identity.keyId,
    ...(identity.sourcePrincipals ?? []),
  ]);
  return {
    principals: [...principals].filter((value) => value.length > 0).slice(0, 256),
    groups: [...new Set(identity.sourceGroups ?? [])].filter((value) => value.length > 0).slice(0, 256),
    ...(identity.teamMemoryGrant ? { teamMemoryGrant: identity.teamMemoryGrant } : {}),
    ...(identity.memoryReadScope ? { memoryReadScope: identity.memoryReadScope } : {}),
  };
}

/**
 * Adapter: module A's MemoryIndex → the structural L2IndexLike the baseline
 * retriever (module C) consumes. Bridges the return-shape difference
 * ({ obj, similarity } → { ref, score, content }) and the positional
 * `validOnly` flag.
 */
export function toRetrievalIndex(
  index: MemoryIndex,
  access?: AccessSubject,
  sourceProjection?: RetrievalSourceProjection,
): L2IndexLike {
  return {
    async vectorSearch(namespace, queryEmbedding, k, validOnly) {
      const hits = await index.vectorSearch(
        namespace,
        queryEmbedding,
        k,
        validOnly,
        false,
        false,
        access,
        sourceProjection?.sourceIds,
      );
      return hits.map((h) => ({
        ref: h.obj.id,
        score: h.similarity,
        content: retrievalContent(h.obj, sourceProjection),
      }));
    },
    async listCandidates(namespace, validOnly) {
      const rows = await index.listCandidates(namespace, {
        validOnly,
        access,
        sourceIds: sourceProjection?.sourceIds,
      });
      return rows.map((r) => ({
        ref: r.id,
        content: retrievalContent(r, sourceProjection),
      }));
    },
    async lexicalCandidates(namespace, query, k, validOnly) {
      const rows = await index.listLexicalCandidates(namespace, query, {
        validOnly,
        limit: k,
        access,
        sourceIds: sourceProjection?.sourceIds,
      });
      return rows.map((r) => ({
        ref: r.id,
        content: retrievalContent(r, sourceProjection),
      }));
    },
  };
}

/**
 * Durable error audit. A failed high-level sink gets one direct append retry
 * through the same Postgres handle; if both paths fail, surface an aggregate
 * error whose message retains the primary syscall failure.
 */
async function auditError(
  deps: SyscallDeps,
  identity: Identity,
  agentId: string,
  op: AuditOp,
  err: unknown,
  memoryId?: string | null,
  trace?: ResolvedTrace,
): Promise<void> {
  const message = err instanceof Error ? err.message : String(err);
  const event = {
    ts: nowIso(),
    actor: identity.actor,
    agentId,
    op,
    memoryId: memoryId ?? null,
    namespace: identity.namespace,
    purpose: null,
    result: "error",
    detail: message.slice(0, 500),
  } as const;
  // D36/E1: error outcomes of tracked ops persist their companion usage row
  // in the SAME transaction as the audit row (D36 literal). recordUsageTx
  // swallows its own failures via savepoint, so this transaction fails only
  // when the AUDIT append fails — then fall through to the standalone path.
  if (trace && USAGE_TRACKED_OPS.has(op)) {
    try {
      await deps.db.transaction(async (tx) => {
        const seq = await deps.audit.appendToWithSeq(tx, event);
        await recordUsageTx(
          tx,
          usageInput(identity, trace, { auditSeq: seq, ts: event.ts, op, result: "error", latencyMs: 0 }),
          usageFailureHook(deps),
        );
      });
      return;
    } catch {
      // The standalone path below owns audit-failure reporting.
    }
  }
  let auditSeq: number;
  try {
    auditSeq = await deps.audit.appendWithSeq(event);
  } catch (firstAuditError) {
    try {
      auditSeq = await appendAuditEventWithSeq(deps.db, event);
    } catch (fallbackAuditError) {
      throw new AggregateError(
        [err, firstAuditError, fallbackAuditError],
        `${message}; audit persistence failed`,
      );
    }
  }
  // Standalone fallback for db-less deps (or a failed combined transaction):
  // the usage write gets its own transaction and every failure is swallowed.
  if (trace && USAGE_TRACKED_OPS.has(op)) {
    await recordUsageStandalone(
      deps.db,
      usageInput(identity, trace, { auditSeq, ts: event.ts, op, result: "error", latencyMs: 0 }),
      usageFailureHook(deps),
    );
  }
}

/**
 * Fail-closed denial audit (rate limit / role). A caller must never receive a
 * normal denied response when its durable D4 evidence could not be written.
 */
async function auditDenied(
  deps: SyscallDeps,
  identity: Identity,
  agentId: string,
  op: AuditOp,
  detail: string,
  trace?: ResolvedTrace,
): Promise<void> {
  const event = {
    ts: nowIso(),
    actor: identity.actor,
    agentId,
    op,
    memoryId: null,
    namespace: identity.namespace,
    purpose: null,
    result: "denied",
    detail,
  } as const;
  // D36/E1: denied outcomes of tracked ops persist their companion usage
  // row in the SAME transaction as the audit row (D36 literal). The denial
  // stays fail-closed: recordUsageTx never throws, so a failure here is an
  // AUDIT failure and falls through to the standalone path, which re-throws.
  if (trace && USAGE_TRACKED_OPS.has(op)) {
    try {
      await deps.db.transaction(async (tx) => {
        const seq = await deps.audit.appendToWithSeq(tx, event);
        await recordUsageTx(
          tx,
          usageInput(identity, trace, { auditSeq: seq, ts: event.ts, op, result: "denied", latencyMs: 0 }),
          usageFailureHook(deps),
        );
      });
      return;
    } catch {
      // The standalone path below is fail-closed on audit failure.
    }
  }
  const auditSeq = await deps.audit.appendWithSeq(event);
  // Standalone fallback for db-less deps (or a failed combined transaction).
  if (trace && USAGE_TRACKED_OPS.has(op)) {
    await recordUsageStandalone(
      deps.db,
      usageInput(identity, trace, { auditSeq, ts: event.ts, op, result: "denied", latencyMs: 0 }),
      usageFailureHook(deps),
    );
  }
}

/** Denial errors are already audited as 'denied' — never re-audit as 'error'. */
function isDenialError(err: unknown): boolean {
  return (
    err instanceof AuthzError ||
    err instanceof RateLimitError ||
    err instanceof TenantSuspendedError ||
    err instanceof ClassificationDeniedError
  );
}

/**
 * What the gate hands back: the effective policy plus the resolved owning
 * Tenant (M4). performWrite consumes `tenant` to lower the brownout cap; a
 * null tenant leaves M1/M2/M3 budget behavior unchanged.
 */
export interface GateResult {
  policy: PolicyConfigX;
  tenant: Tenant | null;
}

/**
 * Shared per-syscall gate: resolve the owning tenant (deny if suspended),
 * fetch the effective policy, then charge the caller's token bucket at the
 * MIN of the namespace limit and the tenant's per-key cap (M4). A suspended
 * tenant → audit 'denied' + TenantSuspendedError (403). Over-rate → audit
 * 'denied' + RateLimitError (429).
 *
 * Tenant-null invariant: with no registered tenant, `tenantGate(null)` passes
 * and `effectiveRateLimit(limit, null) === limit`, so the rate-limit math is
 * bit-identical to M1/M2/M3.
 */
export async function gate(
  deps: SyscallDeps,
  identity: Identity,
  agentId: string,
  op: AuditOp,
  trace?: ResolvedTrace,
): Promise<GateResult> {
  if (!(await deps.isCredentialActive(identity))) {
    const detail = "credential revoked or inactive";
    await auditDenied(deps, identity, agentId, op, detail, trace);
    throw new AuthzError(detail);
  }

  const tenant = await deps.resolveTenant(identity.namespace);
  try {
    tenantGate(tenant);
  } catch (err) {
    if (err instanceof TenantSuspendedError) {
      await auditDenied(deps, identity, agentId, op, err.message, trace);
    }
    throw err;
  }

  const policy = await deps.getPolicy(identity.namespace);
  // Start from the existing per-namespace effective limit (policy override or
  // the default), then let a tenant cap only LOWER it (never raise it).
  const namespaceLimit = policy.rateLimitPerMin ?? DEFAULT_RATE_LIMIT_PER_MIN;
  const policyLimit = effectiveRateLimit(namespaceLimit, tenant) ?? namespaceLimit;
  const limit = deps.quotaRateLimit?.(policyLimit, identity.actor) ?? policyLimit;
  const denial = `rate limit exceeded (${limit} requests/min for this key)`;
  // Prefer the durable outcome so the 429 can carry a retry-after; the bucket
  // key MUST match DurableRateLimitStore.allow()'s so the syscall lane does
  // not fork into a second bucket.
  const consume = deps.rateLimiter.consume?.bind(deps.rateLimiter);
  if (consume) {
    const outcome = await consume(`syscall:${identity.keyId}`, limit, 60_000);
    if (!outcome.allowed) {
      await auditDenied(deps, identity, agentId, op, `rate limit exceeded (${limit}/min)`, trace);
      throw new RateLimitError(denial, outcome.retryAfterSec);
    }
  } else if (!(await deps.rateLimiter.allow(identity.keyId, limit))) {
    await auditDenied(deps, identity, agentId, op, `rate limit exceeded (${limit}/min)`, trace);
    throw new RateLimitError(denial);
  }
  return { policy, tenant };
}

/**
 * Pull a working-set token total out of an 'assemble' audit detail. Supports
 * the allocator's "blocks=N tokens=T budget=B" format and JSON payloads with
 * a totalTokens field.
 */
function extractAssembleTokens(detail: string): number | null {
  try {
    const parsed = JSON.parse(detail) as { totalTokens?: unknown };
    if (typeof parsed.totalTokens === "number") return parsed.totalTokens;
  } catch {
    // Not JSON — fall through to key=value parsing.
  }
  const match = /(?:^|\s)tokens=(\d+)/.exec(detail);
  return match ? Number(match[1]) : null;
}

// ---------------------------------------------------------------------------
// Syscalls
// ---------------------------------------------------------------------------

/** mem_read: resolve one memory by id under ACL; audit ok/denied/miss. */
export async function memRead(
  deps: SyscallDeps,
  args: MemReadArgs,
  identity: Identity,
  agentId: string,
  ctx?: SyscallContext,
): Promise<MemReadResult> {
  return deps.metrics.time("read", async () => {
    const t0 = performance.now();
    const trace = resolveTrace(ctx);
    const { id } = args;
    const namespace = identity.namespace;
    try {
      const { policy } = await gate(deps, identity, agentId, "read", trace);
      const policyVersion = JSON.stringify(policy);
      // The 10ms PRD gate is handle resolution inside the index, not the full
      // authenticated syscall (credential/policy checks + atomic audit).
      const cached = deps.l1?.get(id, identity, policyVersion) ?? null;
      const canonical = await deps.metrics.time(
        "index-read",
        () => deps.index.getById(id, namespace, sourceAccessSubject(identity)),
      );
      const { obj, denied } = cached && canonical.obj?.assertionTime === cached.assertionTime
        ? { obj: cached, denied: false }
        : canonical;
      const fromCache =
        obj !== null && cached !== null &&
        canonical.obj?.assertionTime === cached.assertionTime;
      if (obj && !cached) deps.l1?.set(obj, identity, policyVersion);

      const event = {
        ts: nowIso(),
        actor: identity.actor,
        agentId,
        op: "read",
        memoryId: id,
        namespace,
        purpose: null,
        result: obj ? "ok" : denied ? "denied" : "miss",
      } as const;

      if (obj) {
        // Access telemetry is a DB mutation: commit it with its success audit
        // or roll both back. A failed audit can never leave an access bump.
        await deps.db.transaction(async (tx) => {
          await new MemoryIndex(tx).bumpAccess([obj.id]);
          // D36: the companion usage row rides the same transaction (SAVEPOINT
          // brownout — a usage failure never rolls back the audit row).
          const auditSeq = await deps.audit.appendToWithSeq(tx, event);
          await recordUsageTx(
            tx,
            usageInput(identity, trace, {
              auditSeq,
              ts: event.ts,
              op: "read",
              result: "ok",
              latencyMs: performance.now() - t0,
              returned: 1,
              sourceTier: fromCache ? "cache" : "index",
            }),
            usageFailureHook(deps),
          );
        });
        try {
          await deps.afterAccessCommit?.([obj.id], namespace);
        } catch (error) {
          deps.logger.warn("automatic pager scheduling failed; read result stands", {
            namespace,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      } else {
        // D36: miss/denied reads — usage row in the same transaction as the
        // audit row (previously a standalone append).
        await deps.db.transaction(async (tx) => {
          const auditSeq = await deps.audit.appendToWithSeq(tx, event);
          await recordUsageTx(
            tx,
            usageInput(identity, trace, {
              auditSeq,
              ts: event.ts,
              op: "read",
              result: event.result,
              latencyMs: performance.now() - t0,
              sourceTier: "index",
            }),
            usageFailureHook(deps),
          );
        });
      }

      // Denied collapses to miss in the caller-facing result (no cross-
      // namespace existence oracle); the audit row above keeps the distinction.
      return { found: obj !== null, denied: false, memory: obj };
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "read", err, id, trace);
      throw err;
    }
  });
}

/**
 * mem_search: L2 retrieval routed through the policy-selected driver (M2).
 * pickDriver(policy, query).plan(view) over the caller's ScopedView; the
 * audit row records `driver=<name>` (and `driver_fallback=<a>-><b>` when an
 * unavailable driver degraded to baseline).
 * Embedder circuit-open → degrade to the BM25-only lane (never hard-fail).
 * `validOnly:false` stays on the legacy kernel-side searchL2 lane — drivers
 * only ever see currently-valid views (the fence would silently drop the
 * flag otherwise).
 */
export async function memSearch(
  deps: SyscallDeps,
  args: MemSearchArgs,
  identity: Identity,
  agentId: string,
  ctx?: SyscallContext,
  sourceProjection?: RetrievalSourceProjection,
): Promise<ScoredRef[]> {
  return deps.metrics.time("search", async () => {
    const t0 = performance.now();
    const trace = resolveTrace(ctx);
    const namespace = identity.namespace;
    const k = args.k ?? 8;
    const tokenBudget = args.tokenBudget ?? 2000;
    try {
      const { policy } = await gate(deps, identity, agentId, "search", trace);
      const runtime = deps.runtimeFor(namespace);
      let refs: ScoredRef[];
      let driverDetail: string;
      let driverName: string;
      try {
        if (args.validOnly === false) {
          // Legacy lane: bit-identical to the baseline driver's ranking, but
          // over the include-superseded candidate set drivers cannot request.
          refs = await searchL2(toRetrievalIndex(
            deps.index,
            sourceAccessSubject(identity),
            sourceProjection,
          ), runtime.embedder, {
            namespace,
            query: args.query,
            k,
            tokenBudget,
            validOnly: false,
          });
          driverDetail = " driver=legacy-validonly";
          driverName = "legacy-validonly";
        } else {
          const outcome = await planViaDriver(
            deps,
            policy,
            namespace,
            args.query,
            k,
            tokenBudget,
            sourceAccessSubject(identity),
            sourceProjection,
          );
          refs = outcome.refs;
          driverName = outcome.driver;
          driverDetail =
            ` driver=${outcome.driver}` +
            (outcome.fallback ? ` driver_fallback=${outcome.fallback}` : "");
        }
      } catch (err) {
        // The first provider failure must brown out too; waiting for the
        // circuit to open would hard-fail several agent turns. If the DB/index
        // itself is down, the BM25 fallback below also fails and the outer
        // error path records that outcome.
        deps.logger.warn("vector retrieval unavailable - degrading search to BM25 only", {
          namespace,
          error: err instanceof Error ? err.message : String(err),
        });
        refs = await bm25OnlySearch(deps, {
          namespace,
          query: args.query,
          k,
          tokenBudget,
          validOnly: args.validOnly,
          access: sourceAccessSubject(identity),
          sourceProjection,
        });
        driverDetail = " driver=bm25-degraded";
        driverName = "bm25-degraded";
      }
      const totalTokens = refs.reduce((sum, r) => sum + r.tokenEstimate, 0);

      // D36: audit row + companion usage row commit in one transaction
      // (previously a standalone append).
      const event = {
        ts: nowIso(),
        actor: identity.actor,
        agentId,
        op: "search",
        memoryId: refs[0]?.id ?? null,
        namespace,
        purpose: trace.sensitiveTurnId
          ? `assistant-turn:${trace.sensitiveTurnId}`.slice(0, 200)
          : args.query.slice(0, 200),
        result: refs.length > 0 ? "ok" : "miss",
        detail: `returned=${refs.length} tokens=${totalTokens}${driverDetail}`,
      } as const;
      await deps.db.transaction(async (tx) => {
        const auditSeq = await deps.audit.appendToWithSeq(tx, event);
        await recordUsageTx(
          tx,
          usageInput(identity, trace, {
            auditSeq,
            ts: event.ts,
            op: "search",
            result: event.result,
            latencyMs: performance.now() - t0,
            tokens: totalTokens,
            returned: refs.length,
            driver: driverName,
            sourceTier: "index",
            topScore: refs[0]?.score ?? null,
            // D56: Assistant prompt text belongs only in encrypted history.
            // The stable server-owned turn reference above is sufficient for
            // audit correlation; query analytics keeps no prompt hash/summary.
            ...(trace.sensitiveTurnId ? {} : { queryText: args.query }),
          }),
          usageFailureHook(deps),
        );
      });

      // D39: optional LLM upgrade of the trace's verbatim query summary —
      // fire-and-forget; any failure leaves the verbatim summary standing.
      const summarizer = deps.traceSummarizer;
      if (summarizer && usageEventsEnabled() && !trace.sensitiveTurnId) {
        const traceId = trace.traceId;
        const queryHash = querySha256(args.query);
        void (async () => {
          try {
            const summary = await summarizer(args.query, identity.namespace);
            await upgradeTraceSummary(deps.db, traceId, identity.namespace, queryHash, summary);
          } catch {
            // Brownout: the truncated verbatim summary (D39 default) stands.
          }
        })();
      }

      // M6 (D15, contract module F): mem_search's live seam. A search that
      // found NOTHING locally may start a live confirmation when a pointer
      // matches (the lane's zero-pointer pre-check keeps this free for
      // pointer-less deployments); its verified results land in the write-back
      // cache (D14) and are audited per dispatch (D4). Brownout: a dispatch
      // failure never fails the search. Note pointer facts themselves are
      // NEVER served as search answers (a pointer is a ROUTE — excluded in the
      // query layer), so `live` is the only path from search to a source.
      if ((args.live ?? "auto") !== "off" && deps.l4 && refs.length === 0) {
        try {
          await deps.l4.dispatch(args.query, {
            identity,
            agentId,
            k,
            tokenBudget,
            phase1: { hit: false, source: null, injected: [], latencyMs: 0 },
          });
        } catch (err) {
          deps.logger.warn("l4 live dispatch from mem_search failed - local result stands", {
            namespace,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      return refs;
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "search", err, undefined, trace);
      throw err;
    }
  });
}

/** BM25-only fallback lane (embedder unavailable). Same k/budget semantics as searchL2. */
async function bm25OnlySearch(
  deps: SyscallDeps,
  q: {
    namespace: Namespace;
    query: string;
    k?: number;
    tokenBudget?: number;
    validOnly?: boolean;
    access?: AccessSubject;
    sourceProjection?: RetrievalSourceProjection;
  },
): Promise<ScoredRef[]> {
  const k = q.k ?? 8;
  const tokenBudget = q.tokenBudget ?? 2000;
  if (k <= 0) return [];
  const rows = await deps.index.listLexicalCandidates(q.namespace, q.query, {
    validOnly: q.validOnly ?? true,
    limit: Math.max(k * 16, 128),
    access: q.access,
    sourceIds: q.sourceProjection?.sourceIds,
  });
  const candidates = rows.map((r) => ({
    ref: r.id,
    content: retrievalContent(r, q.sourceProjection),
  }));
  const bm25Hits = bm25Rank(q.query, candidates, Math.max(k * 2, 10));
  const contentByRef = new Map(candidates.map((c) => [c.ref, c.content]));
  const merged = hybridMerge([], bm25Hits, contentByRef, k, "L2");
  const out: ScoredRef[] = [];
  let total = 0;
  for (const hit of merged) {
    if (out.length > 0 && total + hit.tokenEstimate > tokenBudget) continue;
    out.push(hit);
    total += hit.tokenEstimate;
  }
  return out;
}

/**
 * mem_write: extraction / verification / dedupe / supersedence via WritePath.
 * Role: auditor is DENIED (audited). Budget-over namespaces degrade to
 * verbatim (no LLM); LLM circuit-open falls back to verbatim. {async:true}
 * enqueues into the WriteQueue and returns a ticket.
 */
export async function memWrite(
  deps: SyscallDeps,
  args: MemWriteArgs,
  identity: Identity,
  agentId: string,
): Promise<MemWriteResult> {
  return deps.metrics.time("write", async () => {
    const namespace = identity.namespace;
    try {
      if (identity.role === "auditor") {
        await auditDenied(deps, identity, agentId, "write", "role 'auditor' may not write memory");
        throw new AuthzError("role 'auditor' may not write memory");
      }
      const { policy, tenant } = await gate(deps, identity, agentId, "write");

      const req: WriteRequest = {
        namespace,
        scope: args.scope,
        content: args.content,
        actor: identity.actor,
        session: args.session,
        hints: args.hints,
      };

      if (args.async) {
        // The queue is process-local and has no durable transaction boundary;
        // write the durable acceptance evidence before exposing the ticket.
        // The worker emits the actual write outcome independently.
        await deps.audit.append({
          ts: nowIso(),
          actor: identity.actor,
          agentId,
          op: "write",
          memoryId: null,
          namespace,
          purpose: null,
          result: "ok",
          detail: "async write accepted for enqueue",
        });
        return await deps.enqueueWrite(req, identity, agentId);
      }
      return await performWrite(deps, req, policy, identity, agentId, tenant);
    } catch (err) {
      if (err instanceof ClassificationDeniedError) {
        await auditDenied(
          deps,
          identity,
          agentId,
          "write",
          `classification denied sensitivity=${err.sensitivity} destination=${err.destination}`,
        );
      }
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "write", err);
      throw err;
    }
  });
}

/**
 * The actual write body — shared by the sync path and the WriteQueue worker.
 * Applies budget brownout (verbatim-only) and LLM-unavailable fallback.
 */
export async function performWrite(
  deps: SyscallDeps,
  req: WriteRequest,
  policy: PolicyConfigX,
  identity: Identity,
  agentId: string,
  tenant: Tenant | null = null,
  hooks?: WritePathHooks,
): Promise<WriteResult> {
  const runtime = deps.runtimeFor(identity.namespace);

  let effective = req;
  // M4: the brownout cap is the MIN of the namespace policy cap and the owning
  // tenant's monthlyBudgetUsd — a lower tenant cap trips brownout earlier. With
  // no tenant, effectiveCap === policy.monthlyBudgetUsd, so budgetState is
  // bit-identical to BudgetGuard.state (M1/M2/M3 behavior unchanged).
  const effectiveCap = effectiveBudgetUsd(policy.monthlyBudgetUsd ?? null, tenant);
  const budgetOver =
    effectiveCap !== null &&
    (await deps.budget.monthToDateUsd(identity.namespace)) >= effectiveCap;
  if (budgetOver && !req.hints?.verbatim) {
    effective = { ...req, hints: { ...req.hints, verbatim: true } };
    deps.logger.warn("monthly LLM budget exceeded - write degraded to verbatim (brownout)", {
      namespace: identity.namespace,
      keyId: identity.keyId,
      capUsd: effectiveCap,
    });
    // D4: the layer acting on state()==='over' writes the degrade audit row.
    await deps.audit.append({
      ts: nowIso(),
      actor: identity.actor,
      agentId,
      op: "reject",
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: "denied",
      detail: "budget_over: LLM disabled for this write; stored verbatim instead",
    });
  }

  let result: WriteResult;
  try {
    result = await runtime.writePath.write(effective, policy, agentId, hooks);
  } catch (err) {
    if (err instanceof LlmUnavailableError && !effective.hints?.verbatim) {
      deps.logger.warn("LLM circuit open - falling back to verbatim storage", {
        namespace: identity.namespace,
      });
      result = await runtime.writePath.write(
        { ...effective, hints: { ...effective.hints, verbatim: true } },
        policy,
        agentId,
        hooks,
      );
    } else {
      throw err;
    }
  }

  const alreadyAudited =
    result.stored.length +
      result.rejected.length +
      result.superseded.length +
      (result.disputed?.length ?? 0) +
      result.deduplicated >
    0;
  if (!alreadyAudited) {
    await deps.audit.append({
      ts: nowIso(),
      actor: identity.actor,
      agentId,
      op: "write",
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: result.deduplicated > 0 ? "ok" : "miss",
      detail: `stored=0 deduplicated=${result.deduplicated}`,
    });
  }

  // R6: post-commit write-through to external warm stores. The hook contract
  // is never-throws (brownout), but a bug in it must still not fail a write
  // whose canonical commit already succeeded — belt and braces.
  if (deps.afterWriteCommit) {
    try {
      await deps.afterWriteCommit(result);
    } catch (err) {
      deps.logger.warn("afterWriteCommit hook failed (write already committed)", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return result;
}

/**
 * mem_fault: page-fault path — L2 hybrid search, L3 concept fallback, inject.
 * FaultHandler writes the 'fault' audit row (ok/miss + latency) itself.
 *
 * M6 (D15): with the L4 seam wired and `live` ≠ 'off', the phase-1 result is
 * handed to `l4.dispatch` — a started live confirmation adds `liveStatus:
 * {state:'running', sources, ticket}` plus the model-facing statement; no
 * dispatch → `{state:'none', sources: []}`. A dispatch FAILURE is brownout:
 * the phase-1 answer stands untouched (the lane audits its own error, D4).
 * `args.sourceTokens` pass through the seam verbatim and are never logged.
 */
export async function memFault(
  deps: SyscallDeps,
  args: MemFaultArgs,
  identity: Identity,
  agentId: string,
  ctx?: SyscallContext,
): Promise<MemFaultResult> {
  return deps.metrics.time("fault", async () => {
    const trace = resolveTrace(ctx);
    const namespace = identity.namespace;
    try {
      await gate(deps, identity, agentId, "fault", trace);
      const runtime = deps.runtimeFor(namespace);
      const phase1 = await runtime.faultHandler.fault({
        namespace,
        actor: identity.actor,
        agentId,
        query: args.query,
        ...(trace.sensitiveTurnId
          ? { auditPurpose: `assistant-turn:${trace.sensitiveTurnId}`.slice(0, 200) }
          : {}),
        k: args.k,
        tokenBudget: args.tokenBudget,
        access: sourceAccessSubject(identity),
        usage: {
          traceId: trace.traceId,
          tool: trace.tool,
          principal: identity.role === "agent" ? "agent" : "human",
          callerClass: identity.callerClass ?? "unclassified",
        },
      });

      // Phase 2 seam: 'off' or no lane → the pre-M6 response, bit-identical.
      if ((args.live ?? "auto") === "off" || !deps.l4) return phase1;

      let dispatched: L4DispatchOutcome | null = null;
      try {
        dispatched = await deps.l4.dispatch(args.query, {
          identity,
          ...(ctx?.channelAuthority ? { channelAuthority: ctx.channelAuthority } : {}),
          agentId,
          k: args.k,
          tokenBudget: args.tokenBudget,
          sourceTokens: args.sourceTokens,
          phase1,
        });
      } catch (err) {
        // Brownout, never hard-fail: the local answer stands. The lane owns
        // the D4 error audit for the dispatch; log the failure WITHOUT any
        // request material (no query, no tokens — messages only).
        deps.logger.warn("l4 live dispatch failed - phase-1 answer stands", {
          namespace,
          error: err instanceof Error ? err.message : String(err),
        });
      }

      if (!dispatched) {
        return { ...phase1, liveStatus: { state: "none", sources: [] } };
      }
      return {
        ...phase1,
        liveStatus: {
          state: "running",
          sources: dispatched.sources,
          ticket: dispatched.ticket,
        },
        liveStatement: liveConfirmStatement(dispatched.sources, dispatched.ticket),
      };
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "fault", err, undefined, trace);
      throw err;
    }
  });
}

/**
 * mem_live_result (M6 / D15): redeem a phase-2 ticket minted by mem_fault.
 *
 * Unknown, expired (120s), or foreign-namespace tickets collapse to
 * `{found:false, live:null}` with an audited 'miss' (D4) — never a throw, and
 * never an oracle for another tenant's tickets. A found LiveResult audits 'ok'
 * with per-source outcomes in the detail (connector ids only — no source
 * payloads, no tokens).
 */
export async function memLiveResult(
  deps: SyscallDeps,
  args: MemLiveResultArgs,
  identity: Identity,
  agentId: string,
  ctx?: SyscallContext,
): Promise<MemLiveResultResult> {
  return deps.metrics.time("live_result", async () => {
    const t0 = performance.now();
    const trace = resolveTrace(ctx);
    const namespace = identity.namespace;
    try {
      await gate(deps, identity, agentId, "fault", trace);
      const live = deps.l4
        ? args.sourceTokens
          ? await deps.l4.result(args.ticket, identity, args.sourceTokens)
          : await deps.l4.result(args.ticket, identity)
        : undefined;

      if (live === undefined) {
        const event = {
          ts: nowIso(),
          actor: identity.actor,
          agentId,
          op: "fault",
          memoryId: null,
          namespace,
          purpose: null,
          result: "miss",
          detail: `live_result ticket=${args.ticket.slice(0, 64)} unknown or expired`,
        } as const;
        // D36: audit row + companion usage row commit in one transaction.
        await deps.db.transaction(async (tx) => {
          const auditSeq = await deps.audit.appendToWithSeq(tx, event);
          await recordUsageTx(
            tx,
            usageInput(identity, trace, {
              auditSeq,
              ts: event.ts,
              op: "fault",
              result: "miss",
              latencyMs: performance.now() - t0,
            }),
            usageFailureHook(deps),
          );
        });
        return { found: false, live: null };
      }

      const sourceDetail =
        live.sources.length > 0
          ? ` sources=${live.sources.map((s) => `${s.connectorId}:${s.outcome}`).join(",")}`
          : "";
      const event = {
        ts: nowIso(),
        actor: identity.actor,
        agentId,
        op: "fault",
        memoryId: live.blocks[0]?.ref ?? null,
        namespace,
        purpose: null,
        result: "ok",
        detail:
          `live_result state=${live.state} blocks=${live.blocks.length}` +
          ` superseded=${live.superseded.length}${sourceDetail}`,
      } as const;
      // D36: audit row + companion usage row commit in one transaction.
      await deps.db.transaction(async (tx) => {
        const auditSeq = await deps.audit.appendToWithSeq(tx, event);
        await recordUsageTx(
          tx,
          usageInput(identity, trace, {
            auditSeq,
            ts: event.ts,
            op: "fault",
            result: "ok",
            latencyMs: performance.now() - t0,
            tokens: live.blocks.reduce((sum, block) => sum + block.tokenEstimate, 0),
            returned: live.blocks.length,
            sourceTier: "live",
            sourceIds: live.sources,
          }),
          usageFailureHook(deps),
        );
      });
      return { found: true, live };
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "fault", err, undefined, trace);
      throw err;
    }
  });
}

/**
 * mem_assemble: working-set assembly under the namespace policy (D2 — blocks,
 * never prompts). ContextAllocator writes the 'assemble' audit row itself.
 */
export async function memAssemble(
  deps: SyscallDeps,
  args: MemAssembleArgs,
  identity: Identity,
  agentId: string,
  ctx?: SyscallContext,
): Promise<WorkingSet> {
  return deps.metrics.time("assemble", async () => {
    const trace = resolveTrace(ctx);
    const namespace = identity.namespace;
    try {
      const { policy } = await gate(deps, identity, agentId, "assemble", trace);
      const runtime = deps.runtimeFor(namespace);
      return await runtime.allocator.assemble({
        namespace,
        actor: identity.actor,
        agentId,
        policy,
        taskHint: args.taskHint,
        access: sourceAccessSubject(identity),
        usage: {
          traceId: trace.traceId,
          tool: trace.tool,
          principal: identity.role === "agent" ? "agent" : "human",
          callerClass: identity.callerClass ?? "unclassified",
        },
      });
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "assemble", err, undefined, trace);
      throw err;
    }
  });
}

/** mem_stats: counters straight off the locked schema + audit-derived rates. */
export async function memStats(
  deps: SyscallDeps,
  _args: MemStatsArgs,
  identity: Identity,
  agentId: string,
): Promise<MemStats> {
  return deps.metrics.time("stats", async () => {
    const namespace = identity.namespace;
    try {
      await gate(deps, identity, agentId, "stats");
      // Use the same central visibility boundary as every delegated read. This
      // includes exact active mounts and excludes superseded/expired rows; a
      // parallel hand-written namespace query would make stats disagree with
      // read/search immediately after a mount or revoke.
      // includePointers: pointer-catalog facts are real, governed L2 rows —
      // stats/lifecycle accounting must count them even though retrieval
      // surfaces never serve them as answers (M6/D11: a pointer is a route).
      const visibleL2 = (await deps.index.listCandidates(namespace, {
        validOnly: true,
        limit: 2_147_483_647,
        includePointers: true,
        access: sourceAccessSubject(identity),
      })).filter((row) => row.tier === "L2");
      const l2Count = visibleL2.length;

      const l3ConceptCount = await deps.cold.countConcepts(deps.db, namespace);

      const auditRes = await deps.db.query(
        "SELECT op, result, detail FROM audit_log WHERE namespace = $1",
        [namespace],
      );
      const auditRows = auditRes.rows as Array<{
        op: string;
        result: string;
        detail: string | null;
      }>;
      const auditEventCount = auditRows.length;

      const faultRows = auditRows.filter((r) => r.op === "fault");
      const faultCount = faultRows.length;
      const faultHits = faultRows.filter((r) => r.result === "ok").length;
      const faultMisses = faultRows.filter((r) => r.result === "miss").length;
      const faultHitRate =
        faultHits + faultMisses > 0 ? faultHits / (faultHits + faultMisses) : 0;

      const wsTokens: number[] = [];
      for (const row of auditRows) {
        if (row.op !== "assemble" || row.result !== "ok" || !row.detail) continue;
        const tokens = extractAssembleTokens(row.detail);
        if (tokens !== null) wsTokens.push(tokens);
      }
      const avgWorkingSetTokens =
        wsTokens.length > 0
          ? wsTokens.reduce((a, b) => a + b, 0) / wsTokens.length
          : 0;

      const topAccessed = visibleL2
        .sort((a, b) =>
          b.telemetry.accessCount - a.telemetry.accessCount || a.id.localeCompare(b.id)
        )
        .slice(0, 5)
        .map((row) => ({
          id: row.id,
          content: row.content,
          accessCount: row.telemetry.accessCount,
        }));

      await deps.audit.append({
        ts: nowIso(),
        actor: identity.actor,
        agentId,
        op: "stats",
        memoryId: null,
        namespace,
        purpose: null,
        result: "ok",
        detail: `l2=${l2Count} l3=${l3ConceptCount} audit=${auditEventCount}`,
      });

      return {
        namespace,
        l2Count,
        l3ConceptCount,
        faultCount,
        faultHitRate,
        avgWorkingSetTokens,
        auditEventCount,
        topAccessed,
      };
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "stats", err);
      throw err;
    }
  });
}

/**
 * mem.forget (M4 / D3): compliance erasure — the ONE governed exception to D7.
 *
 * Role gate: OWNER/ADMIN only. auditor/member/agent are DENIED and audited as
 * 'denied' BEFORE any resolution runs — an auditor sees everything and mints
 * nothing (§12B). The denial audit is the syscall's ONLY audit responsibility:
 * the erasure engine owns the `op:"forget"` success row (target + erasedCount +
 * certificateId), so a successful forget produces exactly one 'forget' row.
 *
 * After the role gate, gate() runs (tenant-suspend + rate limit) and then
 * `erasureForget` resolves the target to ids INSIDE the caller's subtree,
 * hard-deletes them, writes tombstones, and mints the signed certificate. The
 * audit trail for the erased content SURVIVES (D4 append-only) — only the
 * memory rows are deleted.
 */
export async function memForget(
  deps: SyscallDeps,
  args: MemForgetArgs,
  identity: Identity,
  agentId: string,
): Promise<ForgetResult> {
  return deps.metrics.time("forget", async () => {
    try {
      if (identity.role !== "owner" && identity.role !== "admin") {
        await auditDenied(
          deps,
          identity,
          agentId,
          "forget",
          `role '${identity.role}' may not erase memory (owner/admin only)`,
        );
        throw new AuthzError(`role '${identity.role}' may not erase memory`);
      }

      // Tenant-suspend + rate limit (same gate every other syscall passes).
      await gate(deps, identity, agentId, "forget");

      // The erasure engine appends its own 'forget' success audit row; we do
      // NOT append a second one here (single audit site — see the docstring).
      // R6: enqueueWarmPurges rides INSIDE the erasure transaction, so the
      // certificate and the queued external purges commit as one fact.
      const result = await erasureForget(
        {
          db: deps.db,
          audit: deps.audit,
          signingKey: deps.signingKey,
          ...(deps.enqueueWarmPurges
            ? { enqueueWarmPurges: deps.enqueueWarmPurges }
            : {}),
        },
        args.target,
        identity,
      );

      // R6: drain the queued purges to mounted external warm stores AFTER the
      // canonical transaction committed. Runs even for a 0-row forget (the
      // re-run-forget repair lane drains still-pending purges). Never-throws
      // hook + belt-and-braces: a mirror failure leaves durable purge ops
      // queued, and must not mask an erasure that already succeeded.
      if (deps.afterForgetCommit) {
        try {
          const warmPurges = await deps.afterForgetCommit(
            result.certificate.erasedIds,
            identity.namespace,
          );
          if (warmPurges.length > 0) return { ...result, warmPurges };
        } catch (err) {
          deps.logger.warn("afterForgetCommit hook failed (erasure already committed)", {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return result;
    } catch (err) {
      if (!isDenialError(err)) await auditError(deps, identity, agentId, "forget", err);
      throw err;
    }
  });
}
