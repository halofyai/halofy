/**
 * Module C (part 2) — baseline retrieval lane (D1: referee control lane,
 * concrete module, not a plugin API).
 *
 * Pipeline: embed query → pgvector cosine hits + in-memory BM25 over the
 * ACL-scoped candidate set → min-max normalize each lane → 50/50 hybrid
 * merge → top-k ScoredRef[] under the query token budget.
 */

import type {
  Embedder,
  Namespace,
  ScoredRef,
  SearchQuery,
  Tier,
} from "../types.js";
import { estimateTokens } from "../types.js";
import { tokenize } from "../embed/index.js";

export { retrievalContent } from "./source-context.js";

// ---------------------------------------------------------------------------
// Structural interface for the memory index (module A's MemoryIndex satisfies
// this shape; we deliberately do not import its class — D6, no driver plugs).
// ---------------------------------------------------------------------------

export interface VectorHit {
  /** Memory id (L2) or concept path (L3). */
  ref: string;
  /** Cosine similarity — higher is better. */
  score: number;
  content: string;
}

export interface CandidateDoc {
  ref: string;
  content: string;
}

/**
 * Minimal shape searchL2 needs from the index. `vectorSearch` returns the
 * k nearest rows by cosine similarity (ACL + validity already applied);
 * `listCandidates` returns the same ACL-scoped candidate set for BM25.
 */
export interface L2IndexLike {
  vectorSearch(
    namespace: Namespace,
    queryEmbedding: number[],
    k: number,
    validOnly: boolean,
  ): Promise<VectorHit[]>;
  listCandidates(namespace: Namespace, validOnly: boolean): Promise<CandidateDoc[]>;
  /** Full-corpus lexical preselection; optional for legacy/test adapters. */
  lexicalCandidates?(
    namespace: Namespace,
    query: string,
    k: number,
    validOnly: boolean,
  ): Promise<CandidateDoc[]>;
}

const LEXICAL_STOP_WORDS = new Set([
  "a", "about", "an", "and", "are", "as", "at", "be", "been", "being",
  "but", "by", "did", "do", "does", "explain", "for", "from", "give",
  "had", "has", "have", "how", "i", "in", "include", "including", "into",
  "is", "it", "its", "me", "my", "of", "on", "or", "our", "please",
  "show", "summarize", "summary", "tell", "that", "the", "their", "them",
  "these", "this", "those", "to", "us", "was", "were", "what", "when",
  "where", "which", "who", "why", "with", "you", "your",
]);

/**
 * Safe `simple`-dictionary OR query for Postgres full-text preselection.
 * `tokenize` emits alphanumeric lexemes only, so no tsquery operator from
 * user input survives. A bounded, de-duplicated term set keeps SQL work
 * predictable for long Assistant prompts while preserving proper nouns,
 * numbers, and non-English tokens.
 */
export function lexicalOrQuery(query: string, maxTerms = 32): string | null {
  const terms = [...new Set(tokenize(query))]
    .filter((term) => term.length > 1 && !LEXICAL_STOP_WORDS.has(term))
    .slice(0, maxTerms);
  return terms.length > 0 ? terms.join(" | ") : null;
}

// ---------------------------------------------------------------------------
// BM25 (classic Okapi, in-memory over the candidate set)
// ---------------------------------------------------------------------------

const BM25_K1 = 1.5;
const BM25_B = 0.75;

export interface Bm25Hit {
  ref: string;
  score: number;
}

export function bm25Rank(
  query: string,
  docs: { ref: string; content: string }[],
  k: number,
): Bm25Hit[] {
  if (docs.length === 0 || k <= 0) return [];
  const queryTerms = [...new Set(tokenize(query))];
  if (queryTerms.length === 0) return [];

  const docTokens = docs.map((d) => tokenize(d.content));
  const n = docs.length;
  const totalLen = docTokens.reduce((sum, toks) => sum + toks.length, 0);
  const avgdl = totalLen / n || 1;

  // Term frequency per doc + document frequency per query term.
  const tfPerDoc: Map<string, number>[] = docTokens.map((toks) => {
    const tf = new Map<string, number>();
    for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
    return tf;
  });
  const df = new Map<string, number>();
  for (const term of queryTerms) {
    let count = 0;
    for (const tf of tfPerDoc) if (tf.has(term)) count++;
    df.set(term, count);
  }

  const hits: Bm25Hit[] = [];
  for (let i = 0; i < n; i++) {
    const dl = docTokens[i].length;
    let score = 0;
    for (const term of queryTerms) {
      const tf = tfPerDoc[i].get(term) ?? 0;
      if (tf === 0) continue;
      const termDf = df.get(term) ?? 0;
      const idf = Math.log(1 + (n - termDf + 0.5) / (termDf + 0.5));
      score +=
        (idf * tf * (BM25_K1 + 1)) /
        (tf + BM25_K1 * (1 - BM25_B + (BM25_B * dl) / avgdl));
    }
    if (score > 0) hits.push({ ref: docs[i].ref, score });
  }

  hits.sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref));
  return hits.slice(0, k);
}

// ---------------------------------------------------------------------------
// Score normalization + hybrid merge
// ---------------------------------------------------------------------------

/** Min-max normalize scores to 0..1. Single entry (or all-equal) → 1. */
export function normalizeScores<T extends { score: number }>(entries: T[]): T[] {
  if (entries.length === 0) return [];
  let min = Infinity;
  let max = -Infinity;
  for (const e of entries) {
    if (e.score < min) min = e.score;
    if (e.score > max) max = e.score;
  }
  if (max === min) return entries.map((e) => ({ ...e, score: 1 }));
  return entries.map((e) => ({ ...e, score: (e.score - min) / (max - min) }));
}

/** Collapse duplicate refs within one lane, keeping the best score. */
function bestByRef<T extends { ref: string; score: number }>(entries: T[]): Map<string, T> {
  const map = new Map<string, T>();
  for (const e of entries) {
    const prior = map.get(e.ref);
    if (!prior || e.score > prior.score) map.set(e.ref, e);
  }
  return map;
}

const VECTOR_WEIGHT = 0.5;
const BM25_WEIGHT = 0.5;

/**
 * Merge the vector and BM25 lanes into ScoredRef[]: normalize each lane,
 * combined = 0.5*vec + 0.5*bm25 (a missing lane contributes 0), dedupe by
 * ref, sort descending, take top k.
 */
export function hybridMerge(
  vectorHits: VectorHit[],
  bm25Hits: Bm25Hit[],
  contentByRef: Map<string, string>,
  k: number,
  tier: Tier = "L2",
): ScoredRef[] {
  if (k <= 0) return [];
  const vecByRef = bestByRef(normalizeScores(vectorHits));
  const bmByRef = bestByRef(normalizeScores(bm25Hits));

  const refs = new Set<string>([...vecByRef.keys(), ...bmByRef.keys()]);
  const merged: ScoredRef[] = [];
  for (const ref of refs) {
    const vec = vecByRef.get(ref);
    const bm = bmByRef.get(ref);
    const score = VECTOR_WEIGHT * (vec?.score ?? 0) + BM25_WEIGHT * (bm?.score ?? 0);
    const content = vec?.content ?? contentByRef.get(ref) ?? "";
    merged.push({
      id: tier === "L2" ? ref : null,
      tier,
      ref,
      score,
      content,
      tokenEstimate: estimateTokens(content),
    });
  }

  merged.sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref));
  return merged.slice(0, k);
}

// ---------------------------------------------------------------------------
// Baseline L2 search lane
// ---------------------------------------------------------------------------

const DEFAULT_K = 8;
const DEFAULT_TOKEN_BUDGET = 2000;

/**
 * Full baseline lane over the warm tier: embed the query, run pgvector
 * cosine search and BM25 over the ACL-scoped candidates, hybrid-merge, and
 * trim to the token budget. Results carry tier 'L2' with id === ref
 * (memory id).
 */
export async function searchL2(
  index: L2IndexLike,
  embedder: Embedder,
  q: SearchQuery,
): Promise<ScoredRef[]> {
  const k = q.k ?? DEFAULT_K;
  const tokenBudget = q.tokenBudget ?? DEFAULT_TOKEN_BUDGET;
  const validOnly = q.validOnly ?? true;
  if (k <= 0) return [];

  const [queryEmbedding] = await embedder.embed([q.query]);
  // Over-fetch each lane so the merge has enough candidates to reorder.
  const laneK = Math.max(k * 2, 10);

  const lexicalPoolSize = Math.max(laneK * 8, 128);
  const [vectorHits, candidates] = await Promise.all([
    index.vectorSearch(q.namespace, queryEmbedding, laneK, validOnly),
    index.lexicalCandidates
      ? index.lexicalCandidates(q.namespace, q.query, lexicalPoolSize, validOnly)
      : index.listCandidates(q.namespace, validOnly),
  ]);
  const bm25Hits = bm25Rank(q.query, candidates, laneK);
  const contentByRef = new Map(candidates.map((c) => [c.ref, c.content]));

  const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, k, "L2");

  // Enforce the query token budget: keep results in rank order until the
  // cumulative estimate would exceed the cap.
  const out: ScoredRef[] = [];
  let total = 0;
  for (const hit of merged) {
    if (out.length > 0 && total + hit.tokenEstimate > tokenBudget) continue;
    out.push(hit);
    total += hit.tokenEstimate;
  }
  return out;
}
