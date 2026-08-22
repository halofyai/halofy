/**
 * Module D — FaultHandler.
 *
 * A context fault fires when the agent needs knowledge that is not in its
 * working set. Resolution order:
 *   1. L2 warm tier — hybrid (vector + BM25) search over ACL-scoped
 *      candidates; accepted when the best score clears L2_SCORE_FLOOR.
 *   2. L3 cold tier — concept search via the cold store.
 *   3. Miss — nothing above the floor in either tier.
 *
 * Telemetry (fault-pressure signal):
 *   - bumpAccess on injected L2 ids when L2 serves the fault;
 *   - bumpFault on the single best L2 candidate when the answer had to come
 *     from L3 or missed entirely (that memory is "closest but insufficient").
 *
 * D4: every fault writes an audit row ('ok' | 'miss') with measured latency.
 */

import { performance } from "node:perf_hooks";
import { estimateTokens } from "../types.js";
import type {
  Embedder,
  AccessSubject,
  FaultResult,
  Namespace,
  ScoredRef,
} from "../types.js";
import { bm25Scores, cosineSim, hybridSearchL2, saturate } from "./scoring.js";
import type { AuditPort, HybridHit, L2IndexPort } from "./scoring.js";
import type { UsageEventInput } from "../usage/index.js";

export type {
  AuditPort,
  HybridHit,
  L2IndexPort,
  L2ListOpts,
  L2MemoryLike,
  VectorHitLike,
} from "./scoring.js";
export {
  bm25Scores,
  cosineSim,
  hybridSearchL2,
  saturate,
  toVectorLiteral,
  tokenize,
} from "./scoring.js";

/** Minimum hybrid score for an L2 hit to satisfy a fault. */
export const L2_SCORE_FLOOR = 0.35;
/**
 * L3 concept hits must score strictly above this floor. ColdStore scores are
 * absolute (vector lane is raw cosine, not batch-max-normalized), so this
 * floor is meaningful: unrelated/gibberish queries land well below it
 * (~0.09 with the HashEmbedder) while genuine concept hits score 0.45+.
 * Keeping it above zero is what makes the documented miss path reachable.
 */
export const L3_SCORE_FLOOR = 0.15;

const DEFAULT_K = 4;
const DEFAULT_TOKEN_BUDGET = 1500;

// ---------------------------------------------------------------------------
// Structural ports
// ---------------------------------------------------------------------------

/**
 * Structural slice of module B's cold store. Generic over the DB handle type
 * so we never import module A's Db class — the kernel wires the concrete
 * type at construction.
 */
export interface FaultColdPort<TDb> {
  searchConcepts(
    db: TDb,
    embedder: Embedder,
    namespace: Namespace,
    query: string,
    k: number,
  ): Promise<ScoredRef[]>;
}

/**
 * M2 — optional driver-routed L2 lane. When wired by the kernel, the fault
 * handler's L2 candidates come from `pickDriver(policy, query).plan(view)`
 * instead of the built-in hybridSearchL2; the returned `driver` (and
 * `fallback`, e.g. "mem0->baseline") land in the fault audit detail.
 */
export interface FaultL2PlanOutcome {
  refs: ScoredRef[];
  driver: string;
  fallback?: string;
}

export type FaultL2Planner = (
  query: string,
  k: number,
  tokenBudget: number,
  access?: AccessSubject,
) => Promise<FaultL2PlanOutcome>;

export interface FaultHandlerDeps<TDb> {
  db: TDb;
  index: L2IndexPort;
  cold: FaultColdPort<TDb>;
  audit: AuditPort;
  embedder: Embedder;
  /**
   * M2 integrator wiring — route the L2 lane through the policy-selected
   * retriever driver. Absent (module-level tests, pre-M2 callers) → the
   * legacy hybridSearchL2 lane. The L2-vs-L3 ACCEPTANCE decision always
   * uses the absolute 0.6·cosine + 0.4·saturated-BM25 score against
   * L2_SCORE_FLOOR regardless of lane: driver plan() scores are min-max
   * normalized per query (top hit ≈ 1 whenever any candidate exists), so
   * comparing THEM against the floor would make L2 swallow every fault and
   * the documented L3 path unreachable.
   */
  l2Planner?: FaultL2Planner;
  /**
   * Production transaction boundary for access/fault telemetry plus the D4
   * outcome row. Hermetic port-only tests may omit it. The third callback
   * argument is the raw transaction handle, for the D36 usage hook.
   */
  transact?<T>(
    fn: (txIndex: L2IndexPort, txAudit: AuditPort, tx?: TDb) => Promise<T>,
  ): Promise<T>;
  /**
   * D36: usage-analytics hook invoked INSIDE the audit transaction with the
   * raw tx handle and the fully populated usage event. Absent in
   * module-level tests — faults then write no usage row.
   */
  usage?(tx: TDb, input: UsageEventInput): Promise<void>;
}

export interface FaultArgs {
  namespace: Namespace;
  actor: string;
  agentId: string;
  query: string;
  /** Server-owned audit label when the retrieval query itself is sensitive. */
  auditPurpose?: string;
  k?: number;
  tokenBudget?: number;
  access?: AccessSubject;
  /** D36/D37: trace grouping threaded by the syscall layer (usage analytics). */
  usage?: {
    traceId: string;
    tool: string;
    principal: "human" | "agent";
    callerClass: string;
  };
}

// ---------------------------------------------------------------------------
// FaultHandler
// ---------------------------------------------------------------------------

export class FaultHandler<TDb = unknown> {
  constructor(private readonly deps: FaultHandlerDeps<TDb>) {}

  async fault(args: FaultArgs): Promise<FaultResult> {
    const t0 = performance.now();
    const { namespace, query } = args;
    // Defensive: some callers (syscall layer) route audit attribution
    // themselves and may omit actor/agentId at runtime.
    const actor = args.actor ?? "unknown";
    const agentId = args.agentId ?? "unknown";
    const k = args.k ?? DEFAULT_K;
    const tokenBudget = args.tokenBudget ?? DEFAULT_TOKEN_BUDGET;

    // -- tier L2 --------------------------------------------------------------
    // M2: when the kernel wired a driver-routed planner, the L2 candidates
    // come from the policy-selected retriever cartridge; otherwise the
    // legacy hybrid search runs. Either way the ACCEPTANCE decision uses the
    // absolute hybrid score against L2_SCORE_FLOOR (see FaultHandlerDeps).
    let l2Refs: ScoredRef[];
    let acceptL2: boolean;
    let bumpTargetId: string | null;
    let driverDetail = "";
    let driverName: string | null = null;
    let degradedReason: FaultResult["degradedReason"];

    try {
      if (this.deps.l2Planner) {
        const outcome = await this.deps.l2Planner(query, k, tokenBudget, args.access);
        driverDetail =
          ` driver=${outcome.driver}` +
          (outcome.fallback ? ` driver_fallback=${outcome.fallback}` : "");
        driverName = outcome.driver;
        l2Refs = outcome.refs;
        const abs = await this.absoluteScores(namespace, query, outcome.refs, args.access);
        acceptL2 = abs.some((s) => s >= L2_SCORE_FLOOR);
        bumpTargetId = outcome.refs[0]?.ref ?? null;
      } else {
        const l2Hits: HybridHit[] = await hybridSearchL2({
          index: this.deps.index,
          embedder: this.deps.embedder,
          namespace,
          query,
          k: Math.max(k * 3, 12),
          access: args.access,
        });
        const bestL2 = l2Hits.length > 0 ? l2Hits[0] : null;
        acceptL2 = bestL2 !== null && bestL2.score >= L2_SCORE_FLOOR;
        bumpTargetId = bestL2?.row.id ?? null;
        l2Refs = l2Hits
          .filter((h) => h.score > 0)
          .slice(0, k)
          .map((h) => ({
            id: h.row.id,
            tier: "L2" as const,
            ref: h.row.id,
            score: h.score,
            content: h.row.content,
            tokenEstimate: estimateTokens(h.row.content),
          }));
      }
    } catch {
      // Immediate brownout, including failures before the circuit breaker has
      // opened: retain the governed lexical lane and expose the degradation.
      const rows = await this.deps.index.listCandidates(namespace, {
        validOnly: true,
        limit: 200,
        access: args.access,
      });
      const scores = bm25Scores(
        query,
        rows.map((row) => ({ ref: row.id, content: row.content })),
      );
      l2Refs = rows
        .map((row) => ({
          id: row.id,
          tier: "L2" as const,
          ref: row.id,
          // In a lexical-only brownout the BM25 lane owns the full confidence
          // scale; retaining the hybrid 0.4 weight would make its maximum too
          // small to clear the calibrated acceptance floor reliably.
          score: saturate(scores.get(row.id) ?? 0),
          content: row.content,
          tokenEstimate: estimateTokens(row.content),
        }))
        .filter((ref) => ref.score > 0)
        .sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref))
        .slice(0, k);
      acceptL2 = (l2Refs[0]?.score ?? 0) >= L2_SCORE_FLOOR;
      bumpTargetId = l2Refs[0]?.ref ?? null;
      driverDetail = " driver=bm25-degraded brownout=embedding_unavailable";
      driverName = "bm25-degraded";
      degradedReason = "embedding_unavailable";
    }

    let source: FaultResult["source"] = null;
    let injected: ScoredRef[] = [];
    let result: "ok" | "miss";
    let accessIds: string[] = [];
    let faultId: string | null = null;

    if (acceptL2) {
      source = "L2";
      injected = packToBudget(l2Refs, tokenBudget);
      result = "ok";
      if (injected.length > 0) {
        accessIds = injected.map((r) => r.ref);
      }
    } else {
      // -- tier L3: cold concept search --------------------------------------
      let l3Refs: ScoredRef[];
      try {
        l3Refs = (
          await this.deps.cold.searchConcepts(
            this.deps.db,
            this.deps.embedder,
            namespace,
            query,
            k,
          )
        ).filter((s) => s.score > L3_SCORE_FLOOR);
      } catch {
        // Brownout: an unavailable/corrupt cold tier must not crash the agent
        // after the governed L2 lane has already been exhausted. The additive
        // result field and audit detail distinguish this from a genuine miss.
        l3Refs = [];
        degradedReason = "cold_unavailable";
      }

      if (l3Refs.length > 0) {
        source = "L3";
        injected = packToBudget(l3Refs.slice(0, k), tokenBudget);
        result = "ok";
      } else {
        source = null;
        injected = [];
        result = "miss";
      }
      // Fault pressure: the closest L2 memory was not good enough.
      if (bumpTargetId !== null) {
        faultId = bumpTargetId;
      }
    }

    const latencyMs = Math.max(0, Math.round(performance.now() - t0));
    const injectedTokens = injected.reduce((s, r) => s + r.tokenEstimate, 0);

    const event = {
      ts: new Date().toISOString(),
      actor,
      agentId,
      op: "fault",
      memoryId: injected.length > 0 ? injected[0].id : null,
      namespace,
      purpose: args.auditPurpose ?? query,
      result,
      detail:
        `source=${source ?? "none"} injected=${injected.length} tokens=${injectedTokens} latencyMs=${latencyMs}${driverDetail}` +
        (degradedReason ? ` brownout=${degradedReason}` : ""),
    } as const;

    const mutateAndAudit = async (index: L2IndexPort, audit: AuditPort, tx?: TDb): Promise<void> => {
      if (accessIds.length > 0) await index.bumpAccess(accessIds);
      if (faultId !== null) await index.bumpFault(faultId);
      const auditSeq = await audit.append(event);
      // D36: the companion usage row rides the audit transaction (the hook
      // wraps its writes in a SAVEPOINT brownout). The audit detail string
      // above stays byte-identical.
      if (this.deps.usage && tx !== undefined && typeof auditSeq === "number" && args.usage) {
        await this.deps.usage(tx, {
          auditSeq,
          traceId: args.usage.traceId,
          ts: event.ts,
          namespace,
          actor,
          principal: args.usage.principal,
          callerClass: args.usage.callerClass,
          op: "fault",
          tool: args.usage.tool,
          result,
          latencyMs,
          tokens: injectedTokens,
          returned: injected.length,
          driver: driverName,
          sourceTier: source === "L2" ? "warm" : source === "L3" ? "cold" : null,
          sourceIds: null,
          topScore: injected[0]?.score ?? null,
        });
      }
    };
    if (this.deps.transact) {
      await this.deps.transact(mutateAndAudit);
    } else {
      await mutateAndAudit(this.deps.index, this.deps.audit);
    }

    return {
      hit: result === "ok",
      source,
      injected,
      latencyMs,
      ...(degradedReason ? { degradedReason } : {}),
    };
  }

  /**
   * Absolute 0.6·cosine + 0.4·saturated-BM25 score per driver-planned ref —
   * the same scale L2_SCORE_FLOOR was calibrated against (driver plan()
   * scores are per-query normalized and NOT comparable to a fixed floor).
   *
   * BM25 IDF is computed over the SAME ~200-row ACL-scoped candidate pool
   * the legacy hybridSearchL2 lane used, NOT over just the <=k returned refs.
   * With an n<=k pool the IDF of a rare query term collapses (≈log(1.2)
   * instead of ≈log(pool/df)), systematically deflating lexical-dominant
   * matches below a floor they cleared in M1 — a silent fault hit-rate
   * regression. Refs beyond the pool cap are unioned in so every ref still
   * gets a score.
   */
  private async absoluteScores(
    namespace: Namespace,
    query: string,
    refs: ScoredRef[],
    access?: AccessSubject,
  ): Promise<number[]> {
    if (refs.length === 0) return [];
    const [queryVec] = await this.deps.embedder.embed([query]);
    const contentVecs = await this.deps.embedder.embed(refs.map((r) => r.content));

    // IDF context: full ACL-scoped candidate pool (M1 parity: hybridSearchL2
    // ran bm25Scores over listCandidates(limit 200) ∪ vectorSearch).
    const pool = await this.deps.index.listCandidates(namespace, {
      validOnly: true,
      limit: 200,
      access,
    });
    const docsByRef = new Map<string, { ref: string; content: string }>();
    for (const row of pool) docsByRef.set(row.id, { ref: row.id, content: row.content });
    for (const r of refs) {
      if (!docsByRef.has(r.ref)) docsByRef.set(r.ref, { ref: r.ref, content: r.content });
    }
    const bm = bm25Scores(query, [...docsByRef.values()]);

    return refs.map((r, i) => {
      const vecScore = Math.max(0, cosineSim(queryVec, contentVecs[i]));
      const bmScore = saturate(bm.get(r.ref) ?? 0);
      return 0.6 * vecScore + 0.4 * bmScore;
    });
  }
}

/** Greedy pack: skip refs that would overflow the budget; never split. */
function packToBudget(refs: ScoredRef[], budget: number): ScoredRef[] {
  const out: ScoredRef[] = [];
  let total = 0;
  for (const r of refs) {
    if (total + r.tokenEstimate > budget) continue;
    out.push(r);
    total += r.tokenEstimate;
  }
  return out;
}
