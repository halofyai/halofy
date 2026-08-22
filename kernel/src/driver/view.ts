/**
 * Module A (M2) — ScopedView builder.
 *
 * `buildScopedView(deps, namespace)` is the ONLY constructor of `ScopedView`
 * (src/types.ts). The view is the fence: everything a retriever driver can
 * see flows through it. Drivers receive the view — never the index, the db,
 * the cold store, or the entity registry.
 *
 * ACL ASSUMPTION (documented per CONTRACTS-M2): this module does NOT
 * implement ACL scoping itself. It delegates entirely to the underlying
 * index methods, which already enforce the namespace rule (rows visible iff
 * their namespace equals the caller's namespace or is a '/'-split prefix
 * ancestor of it; active + currently-valid only):
 *   - `candidates()`   → index.listCandidates(namespace, {validOnly:true})
 *   - `vectorSearch()` → index.vectorSearch(namespace, emb, k, validOnly:true)
 *   - `entityFacts()`  → fact pool comes from index.listCandidates (scoped as
 *     above); the entity list comes from the injected `entities` reader,
 *     which the kernel must construct ACL-scoped for the same namespace.
 *   - `concepts()`     → cold-store query enforces private ancestor ACL and
 *     admits cross-tenant rows only when explicitly public.
 *
 * Deps are STRUCTURAL interfaces (index-like / cold-like / entities-like /
 * embedder) so this file imports no concrete storage classes. The concrete
 * MemoryIndex (src/index) and ColdStore (src/cold) satisfy these shapes
 * as-is; the entities reader is a thin adapter the kernel wires (see
 * `ViewEntitiesLike` below — EntityRegistry has no read-only listing today).
 */

import type {
  AccessSubject,
  Embedder,
  Namespace,
  ProvenanceEntry,
  ScoredRef,
  ScopedView,
} from "../types.js";
import { retrievalContent } from "../retrieval/source-context.js";
import type { RetrievalSourceProjection } from "../retrieval/source-context.js";

// ---------------------------------------------------------------------------
// Structural dependency shapes
// ---------------------------------------------------------------------------

/** Minimal row shape the view needs from the memory index. */
export interface ViewRowLike {
  id: string;
  content: string;
  provenance?: readonly ProvenanceEntry[];
}

/**
 * Structural slice of the module-A MemoryIndex. Both methods already apply
 * ACL (namespace + ancestors), status='active', and — with validOnly — the
 * currently-valid filter. The view relies on that and adds nothing.
 */
export interface ViewIndexLike {
  vectorSearch(
    namespace: Namespace,
    embedding: number[],
    k: number,
    validOnly?: boolean,
    ownNamespaceOnly?: boolean,
    includePointers?: boolean,
    access?: AccessSubject,
    sourceIds?: readonly string[],
  ): Promise<{ obj: ViewRowLike; similarity: number }[]>;
  listCandidates(
    namespace: Namespace,
    opts?: {
      validOnly?: boolean;
      limit?: number;
      access?: AccessSubject;
      sourceIds?: readonly string[];
    },
  ): Promise<ViewRowLike[]>;
  listLexicalCandidates?(
    namespace: Namespace,
    query: string,
    opts?: {
      validOnly?: boolean;
      limit?: number;
      access?: AccessSubject;
      sourceIds?: readonly string[];
    },
  ): Promise<ViewRowLike[]>;
}

/** Structural slice of the module-B ColdStore (generic over the DB handle). */
export interface ViewColdLike<TDb> {
  searchConcepts(
    db: TDb,
    embedder: Embedder,
    namespace: Namespace,
    query: string,
    k: number,
  ): Promise<ScoredRef[]>;
}

/** Entity record slice needed for alias matching. */
export interface ViewEntityLike {
  canonicalName: string;
  aliases: string[];
}

/**
 * Read-only, ACL-scoped entity listing. The kernel constructs this reader
 * (e.g. `SELECT canonical_name, aliases FROM entity_registry WHERE namespace
 * IN (<caller ns + ancestors>)`) — src/driver deliberately contains no SQL.
 * `listEntities(namespace)` must return only entities the given namespace is
 * allowed to see; the view trusts it the same way it trusts the index.
 */
export interface ViewEntitiesLike {
  listEntities(namespace: Namespace): Promise<ViewEntityLike[]>;
}

export interface ScopedViewDeps<TDb = unknown> {
  db: TDb;
  index: ViewIndexLike;
  cold: ViewColdLike<TDb>;
  entities: ViewEntitiesLike;
  embedder: Embedder;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/** Default candidate-list cap — matches MemoryIndex.listCandidates. */
const DEFAULT_CANDIDATE_LIMIT = 500;

/** Non-empty lowercase names (canonical + aliases) of an entity. */
function lowerNames(e: ViewEntityLike): string[] {
  return [e.canonicalName, ...e.aliases]
    .map((n) => n.trim().toLowerCase())
    .filter((n) => n.length > 0);
}

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g;

/**
 * WORD-BOUNDARY matchers for an entity's names. Raw substring containment
 * created phantom edges for short names (entity "Ann" matched every fact
 * containing "planning", "channel" or "scanner"; alias "Bo" matched
 * "keyboard") which then earned unrelated facts the full hop-1 proximity
 * boost in the graph driver. A name only counts as mentioned when it is not
 * embedded inside a longer alphanumeric run on either side.
 */
function nameMatchers(names: string[]): RegExp[] {
  return names.map(
    (n) =>
      new RegExp(
        `(?<![a-z0-9])${n.replace(REGEX_SPECIALS, "\\$&")}(?![a-z0-9])`,
      ),
  );
}

/** Case-insensitive whole-word "content mentions one of these names". */
function mentions(contentLower: string, matchers: RegExp[]): boolean {
  return matchers.some((re) => re.test(contentLower));
}

// ---------------------------------------------------------------------------
// buildScopedView
// ---------------------------------------------------------------------------

/**
 * Build the ACL-scoped read surface for one caller namespace. Pure fan-out
 * to the injected deps; see the module header for the ACL delegation
 * contract.
 *
 * entityFacts(mention, hops):
 *   1. alias-match: entities (visible to this namespace) whose canonical
 *      name or any alias equals the mention, case-insensitive;
 *   2. hop 1: ACL-scoped, currently-valid facts whose content mentions the
 *      matched entity's canonical name or aliases (whole word, ci — a name
 *      embedded in a longer word, e.g. "ann" in "planning", is NOT a mention);
 *   3. hop 2: entities co-mentioned in the hop-1 facts, then THEIR facts,
 *      appended after hop 1 (deduped by ref — hop-1 attribution wins).
 * Each returned row carries the canonical name of the entity that linked it.
 */
export function buildScopedView<TDb>(
  deps: ScopedViewDeps<TDb>,
  namespace: Namespace,
  access?: AccessSubject,
  sourceProjection?: RetrievalSourceProjection,
): ScopedView {
  return {
    namespace,

    async candidates(limit = DEFAULT_CANDIDATE_LIMIT) {
      const rows = await deps.index.listCandidates(namespace, {
        validOnly: true,
        limit,
        access,
        sourceIds: sourceProjection?.sourceIds,
      });
      return rows.map((r) => ({
        ref: r.id,
        content: retrievalContent(r, sourceProjection),
      }));
    },

    ...(deps.index.listLexicalCandidates
      ? {
          async lexicalCandidates(query: string, limit: number) {
            const rows = await deps.index.listLexicalCandidates!(namespace, query, {
              validOnly: true,
              limit,
              access,
              sourceIds: sourceProjection?.sourceIds,
            });
            return rows.map((r) => ({
              ref: r.id,
              content: retrievalContent(r, sourceProjection),
            }));
          },
        }
      : {}),

    async vectorSearch(embedding, k) {
      const hits = await deps.index.vectorSearch(
        namespace,
        embedding,
        k,
        true,
        false,
        false,
        access,
        sourceProjection?.sourceIds,
      );
      return hits.map((h) => ({
        ref: h.obj.id,
        content: retrievalContent(h.obj, sourceProjection),
        score: h.similarity,
      }));
    },

    async embed(texts) {
      return deps.embedder.embed(texts);
    },

    async concepts(query, k) {
      // L3 concepts do not retain per-source provenance. A source-scoped view
      // therefore fails closed instead of allowing a future driver to widen
      // the result set through the cold tier.
      if (sourceProjection?.sourceIds !== undefined) return [];
      return deps.cold.searchConcepts(deps.db, deps.embedder, namespace, query, k);
    },

    async entityFacts(mention, hops) {
      const needle = mention.trim().toLowerCase();
      if (needle.length === 0) return [];

      const entities = await deps.entities.listEntities(namespace);
      const seeds = entities.filter((e) =>
        lowerNames(e).some((n) => n === needle),
      );
      if (seeds.length === 0) return [];

      // ACL-scoped fact pool (delegated to the index — see module header).
      const pool = await deps.index.listCandidates(namespace, {
        validOnly: true,
        limit: DEFAULT_CANDIDATE_LIMIT,
        access,
        sourceIds: sourceProjection?.sourceIds,
      });
      const docs = pool.map((row) => {
        const content = retrievalContent(row, sourceProjection);
        return { ref: row.id, content, lower: content.toLowerCase() };
      });

      const out: { ref: string; content: string; entity: string }[] = [];
      const seen = new Set<string>();

      // Hop 1: facts mentioning a seed entity (whole-word, ci).
      const hop1Lower: string[] = [];
      for (const seed of seeds) {
        const matchers = nameMatchers(lowerNames(seed));
        for (const d of docs) {
          if (!mentions(d.lower, matchers)) continue;
          if (!seen.has(d.ref)) {
            seen.add(d.ref);
            out.push({ ref: d.ref, content: d.content, entity: seed.canonicalName });
            hop1Lower.push(d.lower);
          }
        }
      }

      if (hops === 2 && hop1Lower.length > 0) {
        // Hop 2: entities co-mentioned in hop-1 facts → their facts.
        const seedNames = new Set(seeds.map((s) => s.canonicalName));
        for (const other of entities) {
          if (seedNames.has(other.canonicalName)) continue;
          const matchers = nameMatchers(lowerNames(other));
          if (!hop1Lower.some((c) => mentions(c, matchers))) continue;
          for (const d of docs) {
            if (seen.has(d.ref) || !mentions(d.lower, matchers)) continue;
            seen.add(d.ref);
            out.push({ ref: d.ref, content: d.content, entity: other.canonicalName });
          }
        }
      }

      return out;
    },
  };
}
