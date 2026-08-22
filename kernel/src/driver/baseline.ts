/**
 * Module A (M2) — BaselineDriver (halomem-driver/v1, name "baseline").
 *
 * The existing hybrid L2 lane (src/retrieval searchL2: pgvector cosine +
 * in-memory BM25, min-max normalized, 50/50 merged, budget-trimmed)
 * refactored INTO plan(q). Ranking behavior is bit-identical to searchL2 on
 * the same corpus: same lane over-fetch (max(2k, 10)), same bm25Rank /
 * hybridMerge helpers (reused, not forked), same greedy budget trim that
 * always keeps the top hit.
 *
 * DRIVER BOUNDARY: this module imports ONLY src/types.js and src/retrieval.
 * The ScopedView is its whole world — no index, no db, no SQL, no writes.
 */

import type { RetrieverDriver, RetrieverQuery, ScoredRef } from "../types.js";
import { bm25Rank, hybridMerge } from "../retrieval/index.js";

export class BaselineDriver implements RetrieverDriver {
  readonly name = "baseline";

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }

  /** Refs only — the kernel fetches + injects content. Read-only. */
  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    const { view, k, tokenBudget } = q;
    if (k <= 0) return [];

    const [queryEmbedding] = await view.embed([q.query]);
    // Over-fetch each lane so the merge has enough candidates to reorder
    // (identical to searchL2).
    const laneK = Math.max(k * 2, 10);

    const lexicalPoolSize = Math.max(laneK * 8, 128);
    const [vectorHits, candidates] = await Promise.all([
      view.vectorSearch(queryEmbedding, laneK),
      view.lexicalCandidates
        ? view.lexicalCandidates(q.query, lexicalPoolSize)
        : view.candidates(),
    ]);
    const bm25Hits = bm25Rank(q.query, candidates, laneK);
    const contentByRef = new Map(candidates.map((c) => [c.ref, c.content]));

    const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, k, "L2");

    // Enforce the token budget: keep results in rank order until the
    // cumulative estimate would exceed the cap (top hit always survives).
    const out: ScoredRef[] = [];
    let total = 0;
    for (const hit of merged) {
      if (out.length > 0 && total + hit.tokenEstimate > tokenBudget) continue;
      out.push(hit);
      total += hit.tokenEstimate;
    }
    return out;
  }
}
