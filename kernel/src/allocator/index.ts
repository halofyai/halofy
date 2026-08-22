/**
 * Module D — ContextAllocator.
 *
 * Assembles a working set of ranked context blocks under a token budget.
 * D2: we return blocks; we never concatenate them into a prompt.
 *
 * Priority order (selection):
 *   0. policy-directive — governed guardrails for the namespace and its
 *                         ancestors, packed from a RESERVED slice of the
 *                         budget so recall can never evict a policy
 *   1. pinned-concept   — policy.pinnedConcepts, read from the L3 cold store
 *   2. scope-memory     — most-recently-accessed valid L2 memories in the
 *                         caller's namespace (rows that have actually been
 *                         accessed; never-touched rows only enter via lane 3)
 *   3. predicted-relevant — hybrid (vector + BM25) search seeded by taskHint
 *
 * Packing is greedy in priority order (a block that does not fit is skipped,
 * never split). The returned blocks are sorted by stable orderKey
 * ('0-policy-' < '0-pin-' < '1-scope-' < '2-rel-') for prompt-cache stability.
 */

import { estimateTokens } from "../types.js";
import type {
  Concept,
  AccessSubject,
  ContextBlock,
  Embedder,
  Namespace,
  PolicyConfig,
  PolicyDirectiveDocument,
  PolicyDirectiveSet,
  ResolvedPin,
  WorkingSet,
} from "../types.js";
import { policyTokenReserve } from "../policy/directives.js";
import { bm25Scores, hybridSearchL2, saturate } from "../fault/scoring.js";
import type { AuditPort, HybridHit, L2IndexPort, L2MemoryLike } from "../fault/scoring.js";
import type { UsageEventInput } from "../usage/index.js";

// ---------------------------------------------------------------------------
// Structural ports
// ---------------------------------------------------------------------------

/** Structural slice of module B's cold store that the allocator consumes. */
export interface AllocatorColdPort {
  readConcept(namespace: Namespace, path: string): Promise<Concept | null>;
}

/** Optional R5A stable-pin resolver. Older embedders can omit this port. */
export interface AllocatorPinPort {
  resolve(
    namespace: Namespace,
    access?: AccessSubject,
  ): Promise<{ pins: ResolvedPin[]; rejected: number }>;
}

/**
 * Guardrail lane. `load` returns the governing directive set under its own
 * reserved token ceiling; `onDelivered` records that the set reached this
 * agent (the compliance ledger). Both are optional — a module-level allocator
 * without them behaves exactly as before.
 */
export interface AllocatorPolicyPort {
  load(
    namespace: Namespace,
    tokenBudget: number,
  ): Promise<PolicyDirectiveSet>;
  onDelivered?(set: PolicyDirectiveSet, args: AssembleArgs): Promise<void>;
}

export interface ContextAllocatorDeps {
  index: L2IndexPort;
  cold: AllocatorColdPort;
  audit: AuditPort;
  embedder: Embedder;
  pins?: AllocatorPinPort;
  policyDirectives?: AllocatorPolicyPort;
  /**
   * D36: production transaction boundary so the assemble audit row and its
   * companion usage row commit together. Hermetic tests may omit both.
   */
  transact?<T>(fn: (audit: AuditPort, tx?: unknown) => Promise<T>): Promise<T>;
  /** D36: usage-analytics hook, invoked inside `transact` when both wired. */
  usage?(tx: unknown, input: UsageEventInput): Promise<void>;
}

export interface AssembleArgs {
  namespace: Namespace;
  actor: string;
  agentId: string;
  policy: PolicyConfig;
  taskHint?: string;
  access?: AccessSubject;
  /** D36/D37: trace grouping threaded by the syscall layer (usage analytics). */
  usage?: {
    traceId: string;
    tool: string;
    principal: "human" | "agent";
    callerClass: string;
  };
}

const CANDIDATE_LIMIT = 200;
const SCOPE_LANE_LIMIT = 50;
const PREDICTED_K = 12;

export class ContextAllocator {
  constructor(private readonly deps: ContextAllocatorDeps) {}

  async assemble(args: AssembleArgs): Promise<WorkingSet> {
    const t0 = performance.now();
    const { namespace, policy, taskHint } = args;
    // Defensive: some callers (syscall layer) route audit attribution
    // themselves and may omit actor/agentId at runtime.
    const actor = args.actor ?? "unknown";
    const agentId = args.agentId ?? "unknown";
    const budget = policy.tokenBudget;

    let totalTokens = 0;
    let rejectedPins = 0;
    let brownoutDetail = "";
    const selected: ContextBlock[] = [];
    const usedRefs = new Set<string>();

    const tryAdd = (block: ContextBlock): void => {
      if (usedRefs.has(block.ref)) return;
      if (totalTokens + block.tokenEstimate > budget) return; // never split
      selected.push(block);
      usedRefs.add(block.ref);
      totalTokens += block.tokenEstimate;
    };

    // -- lane 0: governed policy directives ---------------------------------
    // Guardrails are packed first out of a reserved slice of the budget, so
    // no amount of recall can push a policy out of the working set. The
    // reserve is a CEILING, not an allotment: unused policy tokens stay
    // available to the ordinary lanes below.
    let policySet: PolicyDirectiveSet | null = null;
    if (this.deps.policyDirectives) {
      try {
        const loaded = await this.deps.policyDirectives.load(
          namespace,
          policyTokenReserve(budget),
        );
        if (loaded.documents.length > 0) {
          policySet = loaded;
          for (const block of loaded.blocks) tryAdd(block);
        }
      } catch {
        // Brownout (kernel rule 5): an unreadable guardrail lane degrades the
        // working set, it never fails the agent's call. The audit detail below
        // records that policy was unavailable for this assembly.
        brownoutDetail += " brownout=policy_unavailable";
      }
    }

    // -- lane 1a: governed stable pins (durable creation order) --------------
    if (this.deps.pins) {
      try {
        const governed = await this.deps.pins.resolve(namespace, args.access);
        rejectedPins += governed.rejected;
        for (let i = 0; i < governed.pins.length; i++) {
          const pin = governed.pins[i];
          tryAdd({
            kind: pin.kind === "memory" ? "pinned-memory" : "pinned-concept",
            ref: pin.ref,
            content: pin.content,
            tokenEstimate: estimateTokens(pin.content),
            orderKey: `0-pin-0-governed-${String(i).padStart(6, "0")}-${pin.pinId}`,
          });
        }
      } catch {
        // Brownout: pin metadata or its backing store may be unavailable. The
        // compatibility and ordinary lanes still provide a working set.
        rejectedPins++;
      }
    }

    // -- lane 1b: legacy path pins (read-only compatibility; never persisted
    // as a new governed pin). Policy order remains their rank. ---------------
    for (const path of policy.pinnedConcepts) {
      let concept: Concept | null;
      try {
        concept = await this.deps.cold.readConcept(namespace, path);
      } catch {
        // Brownout: a malformed/stale pin cannot prevent the agent from
        // receiving the remaining working set. The audit detail records it.
        rejectedPins++;
        continue;
      }
      if (!concept) {
        rejectedPins++;
        continue;
      }
      const content = concept.title
        ? `${concept.title}\n\n${concept.body}`
        : concept.body;
      tryAdd({
        kind: "pinned-concept",
        ref: path,
        content,
        tokenEstimate: estimateTokens(content),
        orderKey: `0-pin-1-legacy-${path}`,
      });
    }

    // -- lane 2: most-recently-accessed valid scope memories -----------------
    const rows = await this.deps.index.listCandidates(namespace, {
      validOnly: true,
      limit: CANDIDATE_LIMIT,
      access: args.access,
    });
    const now = Date.now();
    const accessed = rows
      .filter((r) => r.tValidTo === null || Date.parse(r.tValidTo) > now)
      .filter(
        (r) =>
          r.telemetry.lastAccessed !== null || r.telemetry.accessCount > 0,
      )
      .sort(byRecencyDesc)
      .slice(0, SCOPE_LANE_LIMIT);
    for (const row of accessed) {
      tryAdd({
        kind: "scope-memory",
        ref: row.id,
        content: row.content,
        tokenEstimate: estimateTokens(row.content),
        orderKey: `1-scope-${row.id}`,
      });
    }

    // -- lane 3: predicted-relevant (only with a task hint) ------------------
    if (taskHint && taskHint.trim().length > 0) {
      let hits: HybridHit[];
      try {
        hits = await hybridSearchL2({
          index: this.deps.index,
          embedder: this.deps.embedder,
          namespace,
          query: taskHint,
          k: PREDICTED_K,
          candidateLimit: CANDIDATE_LIMIT,
          access: args.access,
        });
      } catch {
        const scores = bm25Scores(
          taskHint,
          rows.map((row) => ({ ref: row.id, content: row.content })),
        );
        hits = rows
          .map((row) => ({ row, score: saturate(scores.get(row.id) ?? 0) }))
          .filter((hit) => hit.score > 0)
          .sort((a, b) => b.score - a.score || a.row.id.localeCompare(b.row.id))
          .slice(0, PREDICTED_K);
        brownoutDetail += " brownout=embedding_unavailable";
      }
      for (const hit of hits) {
        if (hit.score <= 0) continue;
        tryAdd({
          kind: "predicted-relevant",
          ref: hit.row.id,
          content: hit.row.content,
          tokenEstimate: estimateTokens(hit.row.content),
          orderKey: `2-rel-${hit.row.id}`,
        });
      }
    }

    // Stable output ordering for prompt-cache friendliness: orderKey prefixes
    // ('0-pin-', '1-scope-', '2-rel-') keep kinds grouped in priority order.
    selected.sort((a, b) =>
      a.orderKey < b.orderKey ? -1 : a.orderKey > b.orderKey ? 1 : 0,
    );

    // Only the directives that actually survived packing count as delivered —
    // a truncated guardrail must not read as served in the compliance ledger.
    const deliveredPolicy = policySet
      ? deliveredDirectives(policySet, usedRefs)
      : null;
    const policyDetail = deliveredPolicy
      ? ` policy=${deliveredPolicy.documents.length}` +
        `/${deliveredPolicy.totalTokens}t digest=${deliveredPolicy.digest.slice(0, 12)}`
      : "";

    const assembledAt = new Date().toISOString();
    const event = {
      ts: assembledAt,
      actor,
      agentId,
      op: "assemble",
      memoryId: null,
      namespace,
      purpose: taskHint ?? null,
      result: "ok",
      detail: `blocks=${selected.length} tokens=${totalTokens} budget=${budget} rejectedPins=${rejectedPins}${policyDetail}${brownoutDetail}`,
    } as const;
    // D36: with the kernel's transact/usage wiring the audit row and its
    // companion usage row commit in one transaction; module-level tests keep
    // the standalone append.
    const writeAudit = async (audit: AuditPort, tx?: unknown): Promise<void> => {
      const auditSeq = await audit.append(event);
      if (this.deps.usage && tx !== undefined && typeof auditSeq === "number" && args.usage) {
        await this.deps.usage(tx, {
          auditSeq,
          traceId: args.usage.traceId,
          ts: assembledAt,
          namespace,
          actor,
          principal: args.usage.principal,
          callerClass: args.usage.callerClass,
          op: "assemble",
          tool: args.usage.tool,
          result: "ok",
          latencyMs: performance.now() - t0,
          tokens: totalTokens,
          returned: selected.length,
          driver: null,
          sourceTier: null,
          sourceIds: null,
          topScore: null,
        });
      }
    };
    if (this.deps.transact) {
      await this.deps.transact(writeAudit);
    } else {
      await writeAudit(this.deps.audit);
    }

    if (deliveredPolicy && this.deps.policyDirectives?.onDelivered) {
      try {
        await this.deps.policyDirectives.onDelivered(deliveredPolicy, args);
      } catch {
        // The ledger is evidence, not a gate: a failed compliance write never
        // costs the agent its working set.
      }
    }

    return {
      namespace,
      blocks: selected,
      totalTokens,
      budget,
      assembledAt,
      ...(deliveredPolicy
        ? {
            policy: {
              digest: deliveredPolicy.digest,
              documents: deliveredPolicy.documents,
              tokens: deliveredPolicy.totalTokens,
              required: deliveredPolicy.required,
              truncated: deliveredPolicy.truncated,
            },
          }
        : {}),
    };
  }
}

/**
 * Narrow a loaded directive set to the blocks that actually fit. A document
 * whose every directive was dropped leaves the delivered set entirely.
 */
function deliveredDirectives(
  set: PolicyDirectiveSet,
  packed: Set<string>,
): PolicyDirectiveSet | null {
  // `set.blocks` is the concatenation of each document's directives in
  // document order, so a cursor walk attributes every block exactly.
  const documents: PolicyDirectiveDocument[] = [];
  const blocks: ContextBlock[] = [];
  let cursor = 0;
  for (const document of set.documents) {
    let count = 0;
    let tokens = 0;
    for (let offset = 0; offset < document.directiveCount; offset++) {
      const block = set.blocks[cursor + offset];
      if (!block || !packed.has(block.ref)) continue;
      blocks.push(block);
      count++;
      tokens += block.tokenEstimate;
    }
    cursor += document.directiveCount;
    if (count > 0) {
      documents.push({ ...document, directiveCount: count, tokenEstimate: tokens });
    }
  }
  if (documents.length === 0) return null;
  return {
    ...set,
    documents,
    blocks,
    totalTokens: blocks.reduce((sum, block) => sum + block.tokenEstimate, 0),
    required: documents.some((document) => document.enforcement === "required"),
    truncated: set.truncated + (set.blocks.length - blocks.length),
  };
}

function byRecencyDesc(a: L2MemoryLike, b: L2MemoryLike): number {
  const ta = a.telemetry.lastAccessed ? Date.parse(a.telemetry.lastAccessed) : 0;
  const tb = b.telemetry.lastAccessed ? Date.parse(b.telemetry.lastAccessed) : 0;
  return (
    tb - ta ||
    b.telemetry.accessCount - a.telemetry.accessCount ||
    a.id.localeCompare(b.id)
  );
}
