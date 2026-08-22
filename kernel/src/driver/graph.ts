/**
 * Module B (M2) — GraphDriver, the second retriever cartridge.
 *
 * Genuinely different ranking from baseline: entity-mention fan-out through
 * the ScopedView's entityFacts (2 hops), merged with a direct vector lane,
 * scored 0.5·cosine + 0.3·hop-proximity + 0.2·BM25.
 *
 * DRIVER BOUNDARY: this module imports ONLY from src/types.js,
 * src/retrieval, and src/embed. The ScopedView is its whole world — it never
 * touches the index, db, write path, or audit log, and it never writes.
 */

import type { RetrieverDriver, RetrieverQuery, ScoredRef } from "../types.js";
import { estimateTokens } from "../types.js";
import { bm25Rank } from "../retrieval/index.js";
import { cosineSimilarity } from "../embed/index.js";

// ---------------------------------------------------------------------------
// Mention extraction
// ---------------------------------------------------------------------------

/** Max candidate mentions fanned out per query. */
const MAX_MENTIONS = 5;

/** Weights per CONTRACTS-M2 module row B. */
const COSINE_WEIGHT = 0.5;
const HOP_WEIGHT = 0.3;
const BM25_WEIGHT = 0.2;

/** Hop proximity: hop 1 = 1.0, hop 2 = 0.5, not on the graph = 0. */
const HOP_PROXIMITY: Record<1 | 2, number> = { 1: 1.0, 2: 0.5 };

/**
 * Extract candidate entity mentions from a query: quoted spans (double or
 * single quotes) first — they are the most intentional — then capitalized
 * tokens. Everything must be 2+ chars; deduped case-insensitively; capped
 * at MAX_MENTIONS.
 */
export function extractMentions(query: string): string[] {
  const ordered: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string): void => {
    const m = raw.trim();
    if (m.length < 2) return;
    const key = m.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    ordered.push(m);
  };

  // Quoted spans: "multi word entity" or 'multi word entity'.
  const quotedRe = /"([^"]+)"|'([^']+)'/g;
  for (const match of query.matchAll(quotedRe)) {
    push(match[1] ?? match[2] ?? "");
    if (ordered.length >= MAX_MENTIONS) return ordered;
  }

  // Capitalized tokens (2+ chars, letters/digits/hyphens after the capital),
  // scanned over the query with quoted spans removed so a span's inner words
  // are not double-counted.
  const unquoted = query.replace(quotedRe, " ");
  for (const match of unquoted.matchAll(/\b[A-Z][A-Za-z0-9-]+\b/g)) {
    push(match[0]);
    if (ordered.length >= MAX_MENTIONS) return ordered;
  }

  return ordered;
}

// ---------------------------------------------------------------------------
// GraphDriver
// ---------------------------------------------------------------------------

const clamp01 = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);

interface PoolEntry {
  ref: string;
  content: string;
  /** Best (lowest) hop distance across all mentions; undefined = vector-only. */
  hop?: 1 | 2;
  /** Cosine similarity to the query embedding, when known from the vector lane. */
  cosine?: number;
}

/** Cap on the per-driver content-embedding memo (LRU, insertion-refreshed). */
const EMBED_CACHE_MAX = 4096;

export class GraphDriver implements RetrieverDriver {
  readonly name = "graph";

  /**
   * content → embedding memo for hop-linked facts. The ScopedView exposes no
   * stored-embedding read, so hop-only facts must be embedded driver-side;
   * without a cache EVERY plan() call re-embedded up to hundreds of
   * unchanged fact contents (a real-provider embed batch + cost per query,
   * where the M1 search path embedded only the query). A driver instance
   * lives inside one kernel/registry with one underlying embedder, so
   * content text is a stable cache key.
   */
  private readonly embedCache = new Map<string, number[]>();

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: true, streaming: false };
  }

  /** Cached embed: only cache-miss contents hit view.embed. */
  private async embedContents(
    view: RetrieverQuery["view"],
    texts: string[],
  ): Promise<number[][]> {
    const misses = texts.filter((t) => !this.embedCache.has(t));
    if (misses.length > 0) {
      const fresh = await view.embed(misses);
      misses.forEach((t, i) => {
        this.embedCache.set(t, fresh[i]);
        if (this.embedCache.size > EMBED_CACHE_MAX) {
          // Map preserves insertion order — evict the oldest entry.
          const oldest = this.embedCache.keys().next().value;
          if (oldest !== undefined) this.embedCache.delete(oldest);
        }
      });
    }
    return texts.map((t) => {
      const vec = this.embedCache.get(t)!;
      // LRU refresh: re-insert so hot contents survive eviction.
      this.embedCache.delete(t);
      this.embedCache.set(t, vec);
      return vec;
    });
  }

  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    const { view, tokenBudget, k } = q;
    if (k <= 0) return [];

    const [queryEmbedding] = await view.embed([q.query]);
    const laneK = Math.max(k * 2, 10);

    // (1)–(2) mention extraction + entityFacts fan-out (hop 1 and hop 2
    // separately so proximity is known), in parallel with the vector lane.
    const mentions = extractMentions(q.query);
    const [hopResults, vectorHits] = await Promise.all([
      Promise.all(
        mentions.map(async (mention) => {
          const [hop1, hop2] = await Promise.all([
            view.entityFacts(mention, 1),
            view.entityFacts(mention, 2),
          ]);
          return { hop1, hop2 };
        }),
      ),
      view.vectorSearch(queryEmbedding, laneK),
    ]);

    // (3) merged pool. Merge hop facts in mention order for determinism;
    // keep the best (lowest) hop distance per ref.
    const pool = new Map<string, PoolEntry>();
    for (const { hop1, hop2 } of hopResults) {
      for (const f of hop1) {
        const prior = pool.get(f.ref);
        if (!prior) pool.set(f.ref, { ref: f.ref, content: f.content, hop: 1 });
        else prior.hop = 1;
      }
      for (const f of hop2) {
        const prior = pool.get(f.ref);
        if (!prior) pool.set(f.ref, { ref: f.ref, content: f.content, hop: 2 });
        // hop-2 fan-out includes hop-1 facts; never demote an existing hop 1.
      }
    }

    // Fallback: no mentions resolved to graph facts → pure vector lane.
    if (pool.size === 0) {
      return trimToBudget(
        vectorHits
          .map((h) => toScoredRef(h.ref, h.content, clamp01(h.score)))
          .sort(byScoreThenRef),
        k,
        tokenBudget,
      );
    }

    // Direct vector lane joins the pool (carries its cosine along).
    for (const h of vectorHits) {
      const prior = pool.get(h.ref);
      if (prior) prior.cosine = h.score;
      else pool.set(h.ref, { ref: h.ref, content: h.content, cosine: h.score });
    }

    // Hop-only facts have no cosine yet — embed their contents (memoized:
    // only contents not seen by this driver instance hit the embedder).
    const missing = [...pool.values()].filter((e) => e.cosine === undefined);
    if (missing.length > 0) {
      const embeddings = await this.embedContents(
        view,
        missing.map((e) => e.content),
      );
      missing.forEach((e, i) => {
        e.cosine = cosineSimilarity(queryEmbedding, embeddings[i]);
      });
    }

    // (4) score = 0.5·cosine + 0.3·hop-proximity + 0.2·BM25 over the pool.
    const entries = [...pool.values()];
    const bm25Hits = bm25Rank(q.query, entries, entries.length);
    const bm25Max = bm25Hits.length > 0 ? bm25Hits[0].score : 0;
    const bm25ByRef = new Map(bm25Hits.map((h) => [h.ref, h.score]));

    const scored = entries
      .map((e) => {
        const cos = clamp01(e.cosine ?? 0);
        const hopProx = e.hop !== undefined ? HOP_PROXIMITY[e.hop] : 0;
        const bm25 = bm25Max > 0 ? (bm25ByRef.get(e.ref) ?? 0) / bm25Max : 0;
        const score =
          COSINE_WEIGHT * cos + HOP_WEIGHT * hopProx + BM25_WEIGHT * bm25;
        return toScoredRef(e.ref, e.content, score);
      })
      .sort(byScoreThenRef);

    // (5) top-k under the token budget.
    return trimToBudget(scored, k, tokenBudget);
  }
}

function toScoredRef(ref: string, content: string, score: number): ScoredRef {
  return {
    id: ref,
    tier: "L2",
    ref,
    score,
    content,
    tokenEstimate: estimateTokens(content),
  };
}

function byScoreThenRef(a: ScoredRef, b: ScoredRef): number {
  return b.score - a.score || a.ref.localeCompare(b.ref);
}

/** Top-k, then keep rank order until the cumulative token estimate would
 * exceed the budget (the first hit always survives — same discipline as the
 * baseline lane). */
function trimToBudget(scored: ScoredRef[], k: number, tokenBudget: number): ScoredRef[] {
  const out: ScoredRef[] = [];
  let total = 0;
  for (const hit of scored.slice(0, k)) {
    if (out.length > 0 && total + hit.tokenEstimate > tokenBudget) continue;
    out.push(hit);
    total += hit.tokenEstimate;
  }
  return out;
}
