# Driver kit

HaloMem does not build retrievers. Ranking is delegated to engines mounted as
read-only cartridges, permanently, and the shipped `baseline` driver exists as
a referee control lane rather than as a product.

If you build a retrieval engine, this is how you mount it inside a governed
memory kernel without reimplementing custody, ACL, provenance, or audit — and
without the kernel needing to trust your code.

## Why the boundary is shaped this way

Retrieval is where the field moves fastest, and it is the part of a memory
system that a specialist will always do better than a generalist. Custody is
the opposite: the write path, tier placement, supersedence chains, the ACL, and
the audit trail are slow-moving, high-consequence, and only correct if there is
exactly one of them.

So the split is: the kernel decides *what a caller may see* and *what is
recorded*; the driver decides *what ranks highest* within that. A driver
receives a `ScopedView` constructed for one caller's namespace, and that view
is its entire world. It never sees the database, the write path, or the audit
log, and there is no code path by which it could.

That is enforced three ways:

1. **Structurally** — the view is the only interface handed to `plan()`.
2. **Mechanically** — `npx tsx src/cli.ts conformance <driver>` statically
   scans the driver's source for forbidden imports and fails the run.
3. **Behaviourally** — the conformance kit plants canary facts in a sibling
   namespace and fails any driver that returns one.

## The interfaces

All three types live in `kernel/src/types.ts`. This is the complete contract:

```ts
export interface RetrieverDriver {
  readonly name: string;
  capabilities(): { graph: boolean; streaming: boolean };
  /** Refs only — the kernel fetches + injects content. Never writes. */
  plan(q: RetrieverQuery): Promise<ScoredRef[]>;
}

export interface RetrieverQuery {
  query: string;
  view: ScopedView;
  tokenBudget: number;
  k: number;
}

export interface ScoredRef {
  id: MemoryId | null;     // null for L3 concepts not yet materialized
  tier: Tier;              // "L2" | "L3"
  ref: string;             // L2: the memory id. L3: the concept path.
  score: number;           // higher = better, normalized 0..1
  content: string;
  tokenEstimate: number;
}
```

Three methods, one of which does the work. That is the whole surface a
cartridge implements.

## The ScopedView contract

```ts
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

  /** L3 concept search. */
  concepts(query: string, k: number): Promise<ScoredRef[]>;

  /** Entity registry lookup: aliases → related fact refs (for graph drivers). */
  entityFacts(mention: string, hops: 1 | 2): Promise<{ ref: string; content: string; entity: string }[]>;
}
```

What the view guarantees, so you do not have to implement it:

- **ACL.** Every method returns only rows whose namespace is the caller's
  namespace or a `/`-split prefix ancestor of it. Siblings and descendants are
  already gone. The view does not implement this itself — it delegates to the
  index methods that enforce it in SQL, which is why there is exactly one
  implementation of the rule in the codebase.
- **Validity.** `candidates`, `lexicalCandidates`, `vectorSearch`, and
  `entityFacts` return only currently-valid, active rows (`t_valid_to IS NULL`).
  Superseded history is not visible to drivers at all.
- **Source scoping.** When a request is scoped to specific sources, the view is
  narrowed accordingly, and `concepts()` fails closed and returns `[]` rather
  than letting a driver widen the result set through the cold tier.
- **Embedding.** `embed()` uses whatever embedder the kernel has active, so your
  query vector is in the same space as the stored vectors. Do not bring your
  own embedder for the vector lane unless you also bring your own index.

`buildScopedView` in `kernel/src/driver/view.ts` is the only constructor of a
`ScopedView`. If you find yourself wanting to construct one, you are on the
wrong side of the boundary.

Notes on the individual methods:

- `candidates(limit)` defaults to 500. It is a bounded window, not the corpus.
- `lexicalCandidates(query, limit)` is optional and query-selective — it
  preselects from the *full* ACL-visible corpus instead of the bounded window,
  which matters on large namespaces. Feature-detect it and keep a
  `candidates()` fallback, because a host may not provide it.
- `entityFacts(mention, hops)` matches on canonical name or alias,
  case-insensitively, at a **word boundary**. A name embedded in a longer word
  is not a mention — "Ann" does not match "planning". Hop 2 appends facts of
  entities co-mentioned in the hop-1 facts, deduped by ref with hop-1
  attribution winning.

## Rules a driver must follow

1. **Read-only.** Never write, never delete, never supersede. If your engine
   maintains derived state (an index file, a sidecar's store), that state is a
   cache and must be rebuildable from the candidates the view hands you.
2. **Refs must come from the view.** Every `ref` you return must be one the
   view admitted during *this* call. The kernel returns your `ScoredRef[]`
   without re-filtering it. Build a ref→content map from what you were given
   and drop anything else. This matters most for engines with persistent
   state, whose stored refs may since have been superseded or erased.
3. **Respect `tokenBudget`.** `sum(tokenEstimate) <= tokenBudget`. Keep the top
   hit even if it alone exceeds the budget — returning nothing is worse than
   returning one oversized block, and the conformance kit's budget check is
   written to allow exactly that. Use `estimateTokens` (`ceil(len / 4)`) so your
   arithmetic matches the kernel's.
4. **Be deterministic.** The same query over the same corpus must produce the
   same top-`k`. Sort with an explicit tiebreak (`b.score - a.score ||
   a.ref.localeCompare(b.ref)`); never rely on `Map` insertion order surviving
   a refactor. Non-determinism breaks A/B routing, replays, and caching.
5. **Fail with `DriverUnavailableError`.** If your engine or sidecar cannot
   serve, throw it. The kernel falls back to `baseline` over the same view and
   audits `driver_fallback=<name>->baseline`. Any other exception propagates
   and fails the caller's request.
6. **Return `tier`.** `"L2"` for memory rows (`id === ref`), `"L3"` for
   concepts (`id === null`, `ref` is the concept path).

## The import boundary

A driver module may import **only**:

- `../types.js`
- `../retrieval/` — BM25, hybrid merge, normalization helpers
- `../embed/` — cosine similarity, tokenization
- `./index.js` — the driver directory's own module, for `DriverUnavailableError`
  (this is what `mem0.ts` does)

and never storage, the write path, the audit log, the kernel facade, or the
`src` barrel. The barrel and the facade re-export the full storage surface, so
importing them is equivalent to importing the database.

The static scan is deliberately paranoid, because a driver is third-party code
running in-process. It rejects:

- Any quoted or backtick literal reaching `../{index,kernel,db,write,audit,cold}`
  in either directory form (`../db/client.js`) or file form (`../index.js`,
  `../kernel.js`) — **every** string literal in the file is scanned, not only
  lines that look like imports, so `const { createDb } = req("../db/client.js")`
  is caught.
- `createRequire`, the CommonJS escape hatch.
- Dynamic `import(…)` or `require(…)` whose specifier is not a single plain
  string literal. Computed, concatenated, and template specifiers cannot be
  verified statically, so they are rejected rather than guessed at.

Here is the check catching a real violation:

```
$ npx tsx src/cli.ts conformance keyword
read-only             FAIL    …/src/driver/keyword.ts: forbidden import(s): import { MemoryIndex } from "../index/index.js";
result: FAIL (5/6 checks)
```

The scan is a smoke detector, not a sandbox. It stops the accidental import
and the lazy shortcut; it does not stop a determined attacker who already has
commit access. Review cartridges you did not write.

## Running conformance

```bash
cd kernel
npx tsx src/cli.ts conformance baseline
```

```
conformance report - driver 'baseline' (view: driver/view.js)
check                 result  detail
--------------------  ------  ----------------------------------------
finds-planted-fact    PASS    10/10 planted refs in top-3 (need >= 8)
respects-scoped-view  PASS    0 violations across 15 queries (5 canaries in sibling ns unreachable)
latency-envelope      PASS    p95 5.1ms over 20 plan() calls (bound 150ms)
budget-discipline     PASS    max sum(tokenEstimate) 120/120 across 10 queries
read-only             PASS    …/src/driver/baseline.ts: no forbidden imports (../{index,kernel,db,write,audit,cold}[/.]*, createRequire, computed dynamic import)
deterministic-k       PASS    same top-3 across repeated runs of 3 queries
result: PASS (6/6 checks)
```

The kit builds its own hermetic fixture — in-memory PGlite with pgvector, a
deterministic hash embedder, 10 planted facts in namespace `conf/a` and 5
canary facts in the sibling namespace `conf/b`. No credentials, no network, no
external service. The CLI exits non-zero on failure, so it drops straight into
CI.

The command loads `src/driver/<name>.ts`, scans its exports for the first
class with a `plan()` method (or a ready-made instance), constructs it, and
runs the six checks. A driver whose constructor requires arguments is skipped
by that scan — export a zero-argument-constructible class or a pre-built
instance if you want the CLI to find it.

### What each check means

**`finds-planted-fact`** — For each of 10 planted facts, ask its paired
question and require the right ref in the top 3. At least 8 must hit. The
planted vocabulary is deliberately rare and disjoint ("the zephyr booster burns
cryogenic methalox propellant", "Marisol keeps her vintage accordion in the
cedar attic closet"), so this is a floor for basic competence, not a
benchmark. A driver that fails this is broken, not merely worse than baseline.

**`respects-scoped-view`** — Runs all 15 queries (planted *and* canary) and
fails on two conditions: returning a canary ref from the sibling namespace, or
returning any ref outside the ScopedView. Canary contents are the kind of thing
that must never cross a tenant boundary ("the staging server root password
is peppercorn"). This is the check that makes the ACL claim testable rather
than asserted.

**`latency-envelope`** — p95 over 20 `plan()` calls must be under 150 ms by
default. In-process, against a tiny fixture. It catches accidental O(corpus²)
scoring and per-call model calls; it is not a performance benchmark. Override
with `latencyBudgetMs` if your cartridge is legitimately heavier, but justify
it.

**`budget-discipline`** — With `tokenBudget: 120` and `k: 10`, the sum of
`tokenEstimate` across every response must be ≤ 120. Budget overruns are how a
retriever silently blows an agent's context window.

**`read-only`** — The static import scan described above. Skipped with a
"skipped" note if no `sourcePath` is supplied; the CLI always supplies one when
`src/driver/<name>.ts` exists, and CI callers should always pass one.

**`deterministic-k`** — Runs the first three queries twice and compares the
top-3 by ref. Any difference fails.

Six for six is the bar for mounting a driver. There is no partial credit.

## Worked example: writing a cartridge

Here is a complete, working driver. It ranks by
`0.6 · cosine + 0.4 · query-term coverage`, with the coverage term computed
in-driver rather than reusing the kernel's BM25 helper — so it demonstrates an
independent scorer rather than a baseline variant.

Save as `kernel/src/driver/keyword.ts`:

```ts
/**
 * Example cartridge: "keyword".
 *
 * DRIVER BOUNDARY: imports only src/types.js. The ScopedView is the whole
 * world — no index, no db, no SQL, no writes.
 */

import type { RetrieverDriver, RetrieverQuery, ScoredRef } from "../types.js";
import { estimateTokens } from "../types.js";

const VECTOR_WEIGHT = 0.6;
const COVERAGE_WEIGHT = 0.4;
const CANDIDATE_LIMIT = 500;

function terms(text: string): string[] {
  return text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
}

/** Fraction of distinct query terms that appear in the document. */
function coverage(queryTerms: Set<string>, content: string): number {
  if (queryTerms.size === 0) return 0;
  const docTerms = new Set(terms(content));
  let hits = 0;
  for (const t of queryTerms) if (docTerms.has(t)) hits++;
  return hits / queryTerms.size;
}

export class KeywordDriver implements RetrieverDriver {
  readonly name = "keyword";

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }

  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    const { view, k, tokenBudget } = q;
    if (k <= 0) return [];

    // 1. Everything this driver may see comes from the view.
    const pool = view.lexicalCandidates
      ? await view.lexicalCandidates(q.query, CANDIDATE_LIMIT)
      : await view.candidates(CANDIDATE_LIMIT);
    const allowed = new Map(pool.map((c) => [c.ref, c.content]));

    // 2. Vector lane, over the same ACL-scoped corpus.
    const [embedding] = await view.embed([q.query]);
    const vectorHits = await view.vectorSearch(embedding, Math.max(k * 3, 15));

    const cosineByRef = new Map<string, number>();
    for (const hit of vectorHits) {
      // A driver may only return refs the view admitted this call.
      if (!allowed.has(hit.ref)) allowed.set(hit.ref, hit.content);
      const prior = cosineByRef.get(hit.ref) ?? 0;
      if (hit.score > prior) cosineByRef.set(hit.ref, hit.score);
    }

    // 3. Score every admitted ref.
    const queryTerms = new Set(terms(q.query));
    const scored: ScoredRef[] = [];
    for (const [ref, content] of allowed) {
      const cosine = Math.max(0, cosineByRef.get(ref) ?? 0);
      const cov = coverage(queryTerms, content);
      const score = VECTOR_WEIGHT * cosine + COVERAGE_WEIGHT * cov;
      if (score <= 0) continue;
      scored.push({
        id: ref,
        tier: "L2",
        ref,
        score,
        content,
        tokenEstimate: estimateTokens(content),
      });
    }

    // 4. Deterministic order: score desc, ref asc as the tiebreak.
    scored.sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref));

    // 5. Budget discipline: never exceed tokenBudget; the top hit always survives.
    const out: ScoredRef[] = [];
    let total = 0;
    for (const hit of scored.slice(0, k)) {
      if (out.length > 0 && total + hit.tokenEstimate > tokenBudget) continue;
      out.push(hit);
      total += hit.tokenEstimate;
    }
    return out;
  }
}
```

Verify it:

```bash
npx tsx src/cli.ts conformance keyword
```

```
conformance report - driver 'keyword' (view: driver/view.js)
check                 result  detail
--------------------  ------  ----------------------------------------
finds-planted-fact    PASS    10/10 planted refs in top-3 (need >= 8)
respects-scoped-view  PASS    0 violations across 15 queries (5 canaries in sibling ns unreachable)
latency-envelope      PASS    p95 5.4ms over 20 plan() calls (bound 150ms)
budget-discipline     PASS    max sum(tokenEstimate) 120/120 across 10 queries
read-only             PASS    …/src/driver/keyword.ts: no forbidden imports (../{index,kernel,db,write,audit,cold}[/.]*, createRequire, computed dynamic import)
deterministic-k       PASS    same top-3 across repeated runs of 3 queries
result: PASS (6/6 checks)
```

Every numbered step in that file maps to a rule above: step 1 is "refs come
from the view", step 4 is determinism, step 5 is budget discipline, and the
import block is the boundary.

### Mounting it

Conformance works the moment the file exists, because the CLI loads it
dynamically. Serving real traffic takes two more steps, and **skipping either
one is silent**.

**1. Mount at boot.** In `kernel/src/kernel.ts`, next to the existing mounts:

```ts
this.registry = new DriverRegistry({ warn: (m) => this.logger.warn(m) });
this.registry.mount(new BaselineDriver());
this.registry.mount(new GraphDriver());
this.registry.mount(new KeywordDriver());   // ← yours
```

If your driver needs configuration, follow the `Mem0Driver` pattern: mount it
only when its configuration is present, construct inside a `try`, and
warn-log a construction failure rather than failing boot.

**2. Select it via policy.** Routing is configuration, not code. Set the
namespace's policy:

```yaml
retriever: "keyword"
```

or run a deterministic split:

```yaml
abTest:
  a: "baseline"
  b: "keyword"
  pctB: 25
```

The A/B split hashes the query text with FNV-1a and compares against `pctB`, so
the *same query string always routes to the same arm*. Retries, replays, and
cache lookups never flip drivers mid-flight.

The silent failure to watch for: an unmounted driver name does not error. The
registry falls back to `baseline` with a warn log, so searches keep working
while ranking on baseline. Confirm the mount before you trust any recall
comparison — check the audit trail, where the driver that actually served each
query is recorded:

```
search ok  returned=2 tokens=60 driver=keyword
```

## Out-of-process engines

If your engine is a Python service, a separate binary, or a hosted API, run it
as a sidecar and keep the in-process cartridge thin. `kernel/src/driver/mem0.ts`
is the reference implementation. Its contract is deliberately small:

```
POST /plan  {query, candidates:[{ref,content}], budget, k} -> {refs:[{ref,score}]}
GET  /healthz                                              -> {ok:true, mode:"…"}
```

The design decisions in it are worth copying:

- **The sidecar can only reorder what it was sent.** Candidates go out with the
  request; any ref in the response that was not in the sent set is dropped and
  warn-logged. The sidecar is never a second source of truth.
- **Candidates are capped** (200) so one request cannot ship an entire
  namespace over the wire.
- **Tight timeout, one retry** (1.5 s per attempt, two attempts). Any transport
  error, timeout, non-2xx, or malformed body on the final attempt throws
  `DriverUnavailableError` and the kernel degrades to baseline.
- **Retries are idempotent by construction.** Each `plan()` call carries one
  `x-halomem-request-id` across both attempts, so the sidecar can coalesce a
  retry onto the in-flight computation instead of re-running an expensive
  ingestion.
- **Fail at construction, not at request time.** The constructor throws when no
  sidecar URL is configured, so a driver that can never serve is never mounted,
  and every `plan()` failure genuinely means "the sidecar is down".

## Reference cartridges

| Driver | File | What it demonstrates |
| --- | --- | --- |
| `baseline` | `src/driver/baseline.ts` | The referee control lane: pgvector cosine + BM25, 50/50 merge. 58 lines. |
| `graph` | `src/driver/graph.ts` | Genuinely different ranking: entity-mention fan-out through `entityFacts` at two hops, scored `0.5 · cosine + 0.3 · hop-proximity + 0.2 · BM25`. |
| `mem0` | `src/driver/mem0.ts` | The out-of-process sidecar pattern, with its full failure and idempotency model. |

Read `baseline.ts` first — it is short enough to read in one sitting and it
shows the minimum shape. Read `graph.ts` when you want to see how much a
cartridge can change without touching anything it shouldn't.

## Checklist before you ship a cartridge

- [ ] `npx tsx src/cli.ts conformance <name>` reports 6/6.
- [ ] `npm run typecheck` is clean.
- [ ] The module imports only `../types.js`, `../retrieval/`, `../embed/`, and
      `./index.js`.
- [ ] Every returned `ref` came from this call's `ScopedView`.
- [ ] Sorting has an explicit tiebreak.
- [ ] Engine failures throw `DriverUnavailableError`, not a bare `Error`.
- [ ] `capabilities()` is honest — `graph: true` only if you actually use the
      entity graph.
- [ ] Derived state, if any, is rebuildable and never treated as authority.
- [ ] Mounted in `Kernel.boot` **and** selected in policy, with a search's
      audit row confirming `driver=<name>`.

## Licensing note

`kernel/src/driver/` is licensed under Apache-2.0 rather than the AGPL-3.0 that
covers the rest of the kernel, specifically so cartridges can be written,
distributed, and embedded without the network copyleft reaching them. The
directory carries its own `LICENSE`; the exact scope of the permissive
subtrees is listed in `NOTICE` and `LICENSE-APACHE-2.0` at the repository
root.
