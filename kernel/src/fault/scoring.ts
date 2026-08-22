/**
 * Module D shared scoring helpers + structural ports.
 *
 * Both the ContextAllocator (src/allocator) and the FaultHandler (src/fault)
 * belong to module D; this file holds the minimal structural interfaces they
 * use to talk to collaborators (module A's MemoryIndex/AuditLog, the shared
 * Embedder) without importing sibling module classes, plus a small
 * deterministic hybrid (vector-cosine + BM25) ranking used for
 * "predicted-relevant" blocks and L2 fault search.
 *
 * The ports are structural slices of module A's real surface:
 * `listCandidates` returns MemoryObject-shaped rows (camelCase, telemetry
 * nested) and `vectorSearch` takes a raw number[] embedding and returns
 * { obj, similarity } hits.
 */

import type { AccessSubject, AuditEvent, Embedder, Namespace, Scope } from "../types.js";

// ---------------------------------------------------------------------------
// Structural ports (shapes only — never import sibling module classes)
// ---------------------------------------------------------------------------

/** Minimal memory-row shape module D needs (MemoryObject satisfies this). */
export interface L2MemoryLike {
  id: string;
  content: string;
  scope: Scope;
  tValidTo: string | null;
  telemetry: {
    lastAccessed: string | null;
    accessCount: number;
  };
}

/** Vector-search hit shape (module A's VectorHit satisfies this). */
export interface VectorHitLike {
  obj: L2MemoryLike;
  /** Cosine similarity, higher = closer. */
  similarity: number;
}

export interface L2ListOpts {
  validOnly?: boolean;
  limit?: number;
  access?: AccessSubject;
}

/** Structural slice of module A's MemoryIndex that module D consumes. */
export interface L2IndexPort {
  listCandidates(
    namespace: Namespace,
    opts?: L2ListOpts,
  ): Promise<L2MemoryLike[]>;
  vectorSearch(
    namespace: Namespace,
    embedding: number[],
    k: number,
    validOnly?: boolean,
    ownNamespaceOnly?: boolean,
    includePointers?: boolean,
    access?: AccessSubject,
  ): Promise<VectorHitLike[]>;
  bumpAccess(ids: string[]): Promise<void>;
  bumpFault(id: string): Promise<void>;
}

/** Structural slice of module A's AuditLog. */
export interface AuditPort {
  /**
   * Append one event; kernel-wired ports resolve to the inserted audit_log
   * seq (D36 — usage_events rows FK to it); minimal module ports return void.
   */
  append(e: AuditEvent): Promise<number | void>;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** pgvector literal binding: '[v1,v2,...]'. */
export function toVectorLiteral(vec: number[]): string {
  return `[${vec.join(",")}]`;
}

export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 0);
}

export function cosineSim(a: number[], b: number[]): number {
  const n = Math.min(a.length, b.length);
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < n; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * Raw Okapi BM25 scores over an in-memory candidate set.
 * Returns ref -> raw score (>= 0, unbounded).
 */
export function bm25Scores(
  query: string,
  docs: { ref: string; content: string }[],
  k1 = 1.2,
  b = 0.75,
): Map<string, number> {
  const scores = new Map<string, number>();
  if (docs.length === 0) return scores;

  const docTokens = docs.map((d) => tokenize(d.content));
  const avgLen =
    docTokens.reduce((s, t) => s + t.length, 0) / docTokens.length || 1;
  const queryTerms = [...new Set(tokenize(query))];

  // document frequency per query term
  const df = new Map<string, number>();
  for (const term of queryTerms) {
    let count = 0;
    for (const toks of docTokens) {
      if (toks.includes(term)) count++;
    }
    df.set(term, count);
  }

  const nDocs = docs.length;
  for (let i = 0; i < docs.length; i++) {
    const toks = docTokens[i];
    const tf = new Map<string, number>();
    for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
    let score = 0;
    for (const term of queryTerms) {
      const f = tf.get(term) ?? 0;
      if (f === 0) continue;
      const dfi = df.get(term) ?? 0;
      const idf = Math.log(1 + (nDocs - dfi + 0.5) / (dfi + 0.5));
      score +=
        (idf * f * (k1 + 1)) /
        (f + k1 * (1 - b + (b * toks.length) / avgLen));
    }
    scores.set(docs[i].ref, score);
  }
  return scores;
}

/** Saturating normalization of a raw BM25 score into [0, 1). */
export function saturate(raw: number, k = 1.5): number {
  return raw <= 0 ? 0 : raw / (raw + k);
}

// ---------------------------------------------------------------------------
// Hybrid L2 search (vector cosine + BM25 over ACL-scoped candidates)
// ---------------------------------------------------------------------------

export interface HybridHit {
  row: L2MemoryLike;
  /** 0..1; 0.6 * cosine (clamped >= 0) + 0.4 * saturated BM25. */
  score: number;
}

const VEC_WEIGHT = 0.6;
const BM25_WEIGHT = 0.4;

/**
 * Hybrid search over the caller-visible (ACL-scoped) L2 candidate set.
 * Candidate recall = union of index.listCandidates and index.vectorSearch.
 * Vector scores use the index's cosine similarity when available and fall
 * back to embedder cosine for rows only surfaced by the BM25 lane; both are
 * absolute (same embedding space), so scores are comparable against a fixed
 * floor. Deterministic with HashEmbedder.
 */
export async function hybridSearchL2(args: {
  index: L2IndexPort;
  embedder: Embedder;
  namespace: Namespace;
  query: string;
  k: number;
  candidateLimit?: number;
  access?: AccessSubject;
}): Promise<HybridHit[]> {
  const { index, embedder, namespace, query, k } = args;
  const [queryVec] = await embedder.embed([query]);

  const [listed, vecHits] = await Promise.all([
    index.listCandidates(namespace, {
      validOnly: true,
      limit: args.candidateLimit ?? 200,
      access: args.access,
    }),
    index.vectorSearch(namespace, queryVec, Math.max(k * 4, 16), true, false, false, args.access),
  ]);

  const byId = new Map<string, L2MemoryLike>();
  const simById = new Map<string, number>();
  for (const r of listed) byId.set(r.id, r);
  for (const h of vecHits) {
    byId.set(h.obj.id, h.obj);
    simById.set(h.obj.id, h.similarity);
  }
  const rows = [...byId.values()];
  if (rows.length === 0) return [];

  // rows only surfaced by listCandidates need a locally computed cosine
  const missing = rows.filter((r) => !simById.has(r.id));
  if (missing.length > 0) {
    const vecs = await embedder.embed(missing.map((r) => r.content));
    missing.forEach((r, i) => simById.set(r.id, cosineSim(queryVec, vecs[i])));
  }

  const bm = bm25Scores(
    query,
    rows.map((r) => ({ ref: r.id, content: r.content })),
  );

  const hits: HybridHit[] = rows.map((row) => {
    const vecScore = Math.max(0, simById.get(row.id) ?? 0);
    const bmScore = saturate(bm.get(row.id) ?? 0);
    return { row, score: VEC_WEIGHT * vecScore + BM25_WEIGHT * bmScore };
  });

  hits.sort(
    (a, b) => b.score - a.score || a.row.id.localeCompare(b.row.id),
  );
  return hits.slice(0, k);
}
