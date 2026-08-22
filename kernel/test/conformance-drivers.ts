/**
 * Driver fixtures for the conformance-kit tests (NOT a test file — vitest
 * only collects test/**\/*.test.ts).
 *
 * Both drivers here deliberately import ONLY src/types.js + src/retrieval
 * (the sacred driver boundary), so the read-only static scan of THIS file
 * passes — which lets the broken driver's failures land exactly on
 * respects-scoped-view and budget-discipline.
 */

import type {
  RetrieverDriver,
  RetrieverQuery,
  ScoredRef,
} from "../src/types.js";
import { estimateTokens } from "../src/types.js";
import { bm25Rank, hybridMerge } from "../src/retrieval/index.js";

/**
 * Compliant reference driver: hybrid vector + BM25 over the ScopedView,
 * strict token-budget trim. Mirrors the baseline lane using only the view.
 */
export class ReferenceHybridDriver implements RetrieverDriver {
  readonly name = "ref-hybrid";

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }

  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    const [embedding] = await q.view.embed([q.query]);
    const laneK = Math.max(q.k * 2, 10);
    const [vectorHits, candidates] = await Promise.all([
      q.view.vectorSearch(embedding, laneK),
      q.view.candidates(500),
    ]);
    const bm25Hits = bm25Rank(q.query, candidates, laneK);
    const contentByRef = new Map(candidates.map((c) => [c.ref, c.content]));
    const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, q.k, "L2");

    // Strict budget discipline: never exceed the cap, not even for item #1.
    const out: ScoredRef[] = [];
    let total = 0;
    for (const hit of merged) {
      if (total + hit.tokenEstimate > q.tokenBudget) break;
      out.push(hit);
      total += hit.tokenEstimate;
    }
    return out;
  }
}

/**
 * Deliberately broken driver: leaks refs that are NOT reachable through its
 * ScopedView (fabricated sibling-namespace canary ids handed to it out of
 * band) and ignores the token budget entirely. Must FAIL
 * respects-scoped-view and budget-discipline — proving the kit can fail.
 * It is fast and deterministic, so latency-envelope and deterministic-k
 * still pass; its imports are clean, so read-only passes.
 */
export class LeakyBudgetBusterDriver implements RetrieverDriver {
  readonly name = "leaky-budget-buster";

  constructor(private readonly leakedRefs: readonly string[]) {}

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }

  async plan(_q: RetrieverQuery): Promise<ScoredRef[]> {
    const padding = "leak ".repeat(800); // ~1000 tokens each - blows any sane budget
    return this.leakedRefs.map((ref, i) => ({
      id: ref,
      tier: "L2" as const,
      ref,
      score: 1 - i * 0.01,
      content: `fabricated content for ${ref} ${padding}`,
      tokenEstimate: estimateTokens(`fabricated content for ${ref} ${padding}`),
    }));
  }
}
