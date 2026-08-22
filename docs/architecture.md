# Architecture

This document describes the mechanism, for people who intend to modify it. It
assumes you have run the demo in [getting-started.md](getting-started.md).

The shortest possible summary: Halofy is the **access and governance layer**
for AI agents across an organization. It resolves who an agent is, decides what
context it may use, governs how that context changes, and records the outcome.
Ranking is delegated to retrieval engines mounted as read-only drivers.
Everything else follows from that split.

## Contents

- [Authority model](#authority-model)
- [Data flow](#data-flow)
- [The syscall surface](#the-syscall-surface)
- [The per-syscall pipeline](#the-per-syscall-pipeline)
- [Storage tiers and the read path](#storage-tiers-and-the-read-path)
- [The write path](#the-write-path)
- [Supersedence and bi-temporal validity](#supersedence-and-bi-temporal-validity)
- [The ACL ancestor rule](#the-acl-ancestor-rule)
- [The context allocator](#the-context-allocator)
- [Context faults](#context-faults)
- [Where audit rows come from](#where-audit-rows-come-from)
- [Erasure](#erasure)
- [Brownout](#brownout)
- [Source map](#source-map)

## Authority model

One database is the authority. Postgres holds the memory index, the pgvector
embedding columns, the policy store, and the append-only audit log — in the
same database, so a single backup covers all of them and a single transaction
can span a fact and its audit row.

For development and the test suite, `DATABASE_URL` is unset and the kernel
embeds PGlite (Postgres compiled to WebAssembly) with pgvector. It is the same
schema and the same SQL; only the driver differs. Set `DATABASE_URL` and you
are on a real server.

Anything outside that database is a cache. Warm-store mirrors and retrieval
sidecars are rebuildable and never authoritative. If one is unreachable, the
kernel degrades and keeps serving.

Two rules protect the authority:

- **Never overwrite, never delete.** A conflicting fact closes the previous
  fact's validity interval and links back to it. The only exception is the
  governed erasure path, which is itself audited and certified.
- **Every syscall writes an audit row** — including denied, miss, brownout,
  and error outcomes. Audit data cannot be reconstructed after the fact, so it
  is never optional.

## Data flow

```
                    ┌──────────────────────────────────────────────┐
   agent / console  │  HTTP  /v1/mem/*      MCP stdio + /mcp       │
   ────────────────►│  CLI   src/cli.ts                            │
                    └───────────────────┬──────────────────────────┘
                                        │  Authorization: Bearer hm_…
                                        ▼
                            ┌───────────────────────┐
                            │  auth.resolve(key)    │  namespace, actor, role
                            │  → Identity           │  come ONLY from here
                            └───────────┬───────────┘
                                        ▼
                            ┌───────────────────────┐
                            │  syscall gate         │  role check → policy
                            │  (src/syscalls)       │  → rate limit → tenant
                            └───────┬───────┬───────┘
                     write path     │       │      read paths
              ┌─────────────────────┘       └───────────────────┐
              ▼                                                 ▼
   ┌──────────────────────┐                      ┌──────────────────────────┐
   │ extract → verify →   │                      │ ContextAllocator         │
   │ entity resolve →     │                      │  (mem_assemble)          │
   │ classify → dedupe →  │                      ├──────────────────────────┤
   │ insert (+ supersede) │                      │ planViaDriver            │
   └──────────┬───────────┘                      │  (mem_search)            │
              │                                  ├──────────────────────────┤
              │                                  │ FaultHandler L2→L3       │
              │                                  │  (mem_fault)             │
              │                                  └────────────┬─────────────┘
              │                                               │
              │                                  ┌────────────▼─────────────┐
              │                                  │  ScopedView (per call)   │
              │                                  │  candidates / vector /   │
              │                                  │  embed / concepts /      │
              │                                  │  entityFacts             │
              │                                  └────────────┬─────────────┘
              │                                               │  read-only
              │                                  ┌────────────▼─────────────┐
              │                                  │  RetrieverDriver         │
              │                                  │  baseline | graph | …    │
              │                                  └────────────┬─────────────┘
              ▼                                               ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │  Postgres (or embedded PGlite) + pgvector                              │
   │  memory_objects · concepts · entity_registry · policies · audit_log    │
   └───────────────────────────────────────────────────────────────────────┘
              ▲                                               ▲
              └──────────── every path above appends ─────────┘
                            one audit_log row per outcome
```

The driver never touches the database. It receives a `ScopedView` built for
one caller's namespace, and that view is its entire world.

## The syscall surface

Syscalls take a resolved `Identity`, never a caller-supplied namespace or
actor. The HTTP transport maps `POST /v1/mem/<name>` onto them:

| Route | Syscall | What it does |
| --- | --- | --- |
| `/v1/mem/read` | `memRead` | Fetch one memory by id. Denied and missing are indistinguishable to the caller. |
| `/v1/mem/search` | `memSearch` | Ranked retrieval over the warm tier, through the policy-selected driver. |
| `/v1/mem/write` | `memWrite` | Run the write path. `{"async":true}` returns a ticket instead. |
| `/v1/mem/fault` | `memFault` | Resolve a question the working set could not answer: L2, then L3. |
| `/v1/mem/assemble` | `memAssemble` | Build a working set of ranked blocks under a token budget. |
| `/v1/mem/stats` | `memStats` | Counts, fault-hit rate, average working-set size, audit volume. |
| `/v1/mem/pin`, `/unpin` | `memPin`, `memUnpin` | Governed pins, packed ahead of recall in the working set. |
| `/v1/mem/policy`, `/policy-ack` | `memPolicy`, `memPolicyAck` | Fetch and acknowledge governed directives. |
| `/v1/mem/share` | `memShare` | Grant scoped access to memory. |

Roles gate the surface: `agent` and `member` get syscalls only; `auditor` may
read, search, assemble, fault, and see stats but may not write; `admin` and
`owner` get everything, with management operations gated further by subtree.

## The per-syscall pipeline

Every syscall runs the same prologue before its body:

```
metrics.time(op)
  → role check
  → policy fetch (effective policy for the namespace and its ancestors)
  → tenant gate (suspended tenants fail closed)
  → rate limit (token bucket per key id)
  → op body
  → audit append
```

A denial anywhere in the prologue is itself an audited outcome. Rate-limit
rejection produces a `RateLimitError` and an audit row; it does not silently
drop.

## Storage tiers and the read path

Two tiers hold memory.

**L2 — warm.** Rows in `memory_objects`: extracted facts, preferences,
episodes, entities, pointers. Each row carries its embedding inline in a
`vector(dim)` column, a bi-temporal validity interval, provenance, a data
classification, and access telemetry.

**L3 — cold.** Concepts: OKF markdown documents with YAML frontmatter, read
from a knowledge directory, summarized and embedded into the `concepts` table.
Private concepts are encrypted at rest with AES-256-GCM under a per-concept
data key wrapped by `HALOMEM_COLD_KEK`.

`mem_search` routes to a driver, and every driver shipped here ranks over L2
only. `mem_fault` is the tier-crossing path:

1. Run the L2 lane through the policy-selected retriever driver.
2. Score the results with an absolute hybrid score — `0.6 · cosine + 0.4 ·
   saturated BM25` — and accept L2 if any result clears `L2_SCORE_FLOOR`
   (0.35).
3. Otherwise search L3 concepts and accept a hit above `L3_SCORE_FLOOR`
   (0.15).
4. Otherwise record a miss.

The absolute score matters. Driver `plan()` output is min-max normalized per
query, so the top hit is always ≈1.0 whenever any candidate exists. Comparing
normalized scores against the floor would make L2 swallow every fault and make
the L3 path unreachable. The fault handler therefore recomputes absolute
scores for the acceptance decision, independent of what the driver returned.

Faults also emit pressure telemetry: when L2 serves the fault, the injected
rows get their access counters bumped; when the answer had to come from L3 or
missed entirely, the single best L2 candidate gets a fault counter bumped —
"closest but insufficient" is the signal that drives consolidation and
promotion.

### The baseline ranking lane

The baseline driver is a referee control lane, not a competitive retriever:

1. Embed the query.
2. Over-fetch each lane at `max(2k, 10)`; the lexical pool is
   `max(laneK · 8, 128)`.
3. pgvector cosine search plus in-memory BM25 over the ACL-scoped candidates.
4. Min-max normalize each lane, merge `0.5 · vector + 0.5 · BM25`, dedupe by
   ref, sort descending with ref as a stable tiebreak, take top `k`.
5. Trim greedily to `tokenBudget`, always keeping the top hit.

Token estimates are `ceil(text.length / 4)` — deliberately cheap and
tokenizer-independent, because the budget is a guardrail, not an accounting
system.

## The write path

`WritePath.write()` runs five stages:

**1. Extraction.** The transcript or document becomes candidate facts. With an
LLM configured this is a model call; without one the content is stored
verbatim. Verbatim storage is also the brownout path when the model is
unavailable or a budget cap is hit — the caller is never hard-failed.

**2. Verification.** Candidate facts are checked before they are allowed to
become memory. Rejected candidates appear in `result.rejected` with a reason,
not silently dropped.

**3. Entity resolution.** Mentions are resolved against `entity_registry`,
producing the `[entities: …]` annotation. This annotation is derived
read-side metadata and is stripped before dedupe comparison, so it can never
change whether two facts are considered identical.

**4. Classification.** Every persisted fact is classified for sensitivity, PII
subjects, secret kinds, and allowed destinations — including facts that
arrived through the verbatim brownout path, so no fact can lose its protection
label by taking a degraded route.

**5. Dedupe, supersede, insert.** Described below.

A `WriteResult` reports four outcomes: `stored`, `rejected`, `superseded`,
`deduplicated`.

Connectors and importers feed this same path. There is no bulk loader that
writes directly to the store — imported data gets the same extraction,
verification, provenance, classification, and audit as agent conversation.

## Supersedence and bi-temporal validity

Every row in `memory_objects` carries four time columns:

| Column | Meaning |
| --- | --- |
| `event_time` | When the thing described happened (nullable). |
| `assertion_time` | When the system was told. |
| `t_valid_from` | Start of the interval over which this row is believed. |
| `t_valid_to` | End of that interval; `NULL` means currently valid. |

"Currently valid" is `t_valid_to IS NULL`. Retrieval queries add that clause
by default; `mem_search` with `{"validOnly": false}` opens a separate lane that
includes superseded rows, which drivers cannot request.

Supersedence never mutates a row:

```
closeValidity(victimId, now)      -- UPDATE … SET t_valid_to = now
                                  --   WHERE id = $1 AND t_valid_to IS NULL
insert(newRow with supersedes = victimId)
```

Both statements run in one transaction. `closeValidity` is guarded: it only
matches a currently-valid row and returns the number of rows closed. If a
concurrent writer already closed the same victim it returns 0, the transaction
rolls back — insert included — and the decision is re-run against fresh state,
bounded so a pathological interleaving still terminates. Without the guard, two
writers could each believe they superseded the same fact and one would silently
overwrite the other's `t_valid_to`.

`supersedes` is a real foreign key back into `memory_objects(id)`, so the chain
is walkable: the current fact points at the one it replaced, which points at
the one before it.

### What actually triggers a supersedence

Two things happen at insert time, both deterministic:

- **Exact dedupe.** If a currently-valid row in the caller's *own* namespace
  normalizes to the same text, no new row is written. The existing row's
  access telemetry is bumped and the write is audited with
  `deduplicated=1`. Cosine similarity is deliberately not used as the dedupe
  signal — two differently-dated facts can be textually near-identical.
- **Deterministic refresh.** Pointer facts and cache-refresh writes supersede
  their stale predecessor through the normal chain.

Semantic conflicts between ordinary facts are **not** resolved inside the write
transaction. Doing so would put a model call on the write path's critical
section and would only ever compare a new fact against whatever happened to be
in one vector window. Instead, every committed fact is queued for an
out-of-band conflict check against its nearest neighbours by embedding. A
confirmed contradiction is settled by a trust lattice over provenance:

```
manual 50 > document 40 = live-fetch 40 > consolidation 30 > swap-import 20 > conversation 10
```

Equal rank means recency wins. An incoming write that outranks the incumbent
supersedes it. An incoming write that *underranks* the incumbent is quarantined
as `disputed` rather than being applied, subject to the namespace's
conflict-review policy. Every outcome is a validity close plus a supersedence
link — never a delete — so any automatic decision is overturnable.

The practical consequence for evaluation: on the stub LLM lane there is no
model to confirm a contradiction, so conflicting facts coexist as
currently-valid rows. That is why the demo's conflicting-address step reports
`supersedes=null`.

Dedupe and supersedence only ever target rows in the caller's own namespace. A
child-namespace write may never close or swallow a parent or organization
fact, even though it can read one.

## The ACL ancestor rule

**A caller in namespace `N` sees rows whose namespace is `N` itself or a
`/`-split prefix ancestor of `N`.** Siblings and descendants are invisible.

Namespaces are hierarchical paths: `acme`, `acme/eng`, `acme/eng/platform`.

```ts
export function namespaceAncestors(namespace: Namespace): string[] {
  const parts = namespace.split("/").filter((p) => p.length > 0);
  const out: string[] = [];
  for (let i = 1; i <= parts.length; i++) out.push(parts.slice(0, i).join("/"));
  return out.length > 0 ? out : [namespace];
}
```

Worked examples for a caller in `acme/eng/platform`:

| Row namespace | Visible? | Why |
| --- | --- | --- |
| `acme/eng/platform` | yes | Exact match. |
| `acme/eng` | yes | Prefix ancestor. |
| `acme` | yes | Prefix ancestor. |
| `acme/eng/platform/db` | **no** | Descendant. A parent does not read its children. |
| `acme/sales` | **no** | Sibling subtree. |
| `acme/engineering` | **no** | Shares a string prefix but not a `/`-split path segment. |
| `acmecorp` | **no** | Different root. |

That third "no" is the one that bites. `acme/eng` is not an ancestor of
`acme/engineering`, even though `"acme/engineering".startsWith("acme/eng")` is
true. The predicate is written to require a segment boundary:

```ts
export function aclAllows(callerNamespace: Namespace, rowNamespace: Namespace): boolean {
  return (
    rowNamespace === callerNamespace ||
    callerNamespace.startsWith(rowNamespace + "/")
  );
}
```

Enforcement lives in the query/repository layer, not in callers. Nothing
reaches `memory_objects` without going through a method that has already
computed the ancestor list. Reads compile to an **exact enumerated IN list**:

```sql
SELECT … FROM memory_objects
 WHERE namespace IN ($1, $2, $3)   -- ['acme', 'acme/eng', 'acme/eng/platform']
   AND status = 'active'
   AND t_valid_to IS NULL
```

The same discipline applies to the audit log: `namespace IN (…)` is the fence,
never a wildcard.

### The LIKE / ESCAPE hazard

The base ancestor rule needs no pattern matching at all — that is a deliberate
design choice, and it is why the base rule cannot be attacked through pattern
metacharacters.

Pattern matching appears only where a **subtree** must be matched: an admin
listing its own descendants, an explicit subtree grant, an erasure resolving
downward. Those cases genuinely need "this namespace and everything under it",
which an IN list cannot express.

The hazard is that namespace strings are user-influenced and SQL `LIKE` treats
`_` as "any single character", `%` as "any sequence", and `\` as an escape
introducer. A namespace containing any of those becomes a wildcard:

```sql
-- WRONG
WHERE namespace LIKE 'acme/eng_%'
-- 'acme/eng_' is a prefix, but '_' matches ANY character:
-- acme/engX/… , acme/engineering/… all match. Cross-subtree leak.
```

Every subtree predicate in this codebase therefore escapes the literal and
declares the escape character explicitly:

```ts
export function escapeLikePattern(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}
```

```sql
WHERE namespace = $1
   OR namespace LIKE $2 ESCAPE '\'   -- $2 = escapeLikePattern(prefix) + '/%'
```

Three rules follow, and they are not negotiable:

1. Never build a namespace `LIKE` predicate without `escapeLikePattern` **and**
   `ESCAPE '\'`. Postgres's default escape character is already `\`, but
   stating it is what makes the intent reviewable and survives a dialect
   change.
2. Always anchor a subtree pattern with the separator: `prefix + '/%'`, never
   `prefix + '%'`. Without the slash, `acme/eng` matches `acme/engineering`.
3. The exact-match arm (`namespace = $1`) is separate on purpose — the pattern
   arm deliberately does not match the prefix itself.

This class of bug has been found twice in this codebase by adversarial review.
When you touch a namespace predicate, add a regression test with `_`, `%`, and
`\` in the namespace.

## The context allocator

`mem_assemble` returns ranked blocks. It never concatenates them into a
prompt — placement is the agent framework's job, and an access layer that
formats prompts becomes an agent framework.

Selection runs in priority order into a greedy packer:

| Lane | Kind | Source |
| --- | --- | --- |
| 0 | `policy-directive` | Governed guardrails for the namespace and its ancestors. |
| 1a | `pinned-memory`, `pinned-concept` | Governed stable pins, in durable creation order. |
| 1b | `pinned-concept` | Legacy path pins from policy, in policy order. |
| 2 | `scope-memory` | Most-recently-accessed currently-valid rows that have actually been accessed (limit 50). |
| 3 | `predicted-relevant` | Hybrid search seeded by `taskHint` (top 12). |

The packer is deliberately simple:

```ts
const tryAdd = (block: ContextBlock): void => {
  if (usedRefs.has(block.ref)) return;
  if (totalTokens + block.tokenEstimate > budget) return;  // never split
  selected.push(block);
  usedRefs.add(block.ref);
  totalTokens += block.tokenEstimate;
};
```

A block that does not fit is skipped, never truncated — half a fact is worse
than no fact. Deduplication is by ref, so a memory pinned in lane 1 cannot be
re-added by lane 3.

Two properties are worth understanding before you change this:

**The policy reserve is a ceiling, not an allotment.** Guardrails are packed
first, capped at 35% of the budget (`policyTokenReserve`). Because they are
packed first, no amount of recall can evict a policy. Because the reserve is a
ceiling rather than a reservation, unused policy tokens stay available to
lanes 2 and 3 — guardrails cannot starve recall either. Only directives that
actually survived packing are recorded as delivered; a truncated guardrail must
not read as served in the compliance ledger.

**Output order is stable.** Blocks are sorted by `orderKey`, whose prefixes
(`0-policy-` < `0-pin-` < `1-scope-` < `2-rel-`) keep kinds grouped in priority
order and whose suffixes are stable ids. The same working set therefore
serializes identically across calls, which is what makes upstream prompt
caching effective.

Lane 2 deliberately requires a row to have been accessed at least once.
Never-touched rows enter only through lane 3's relevance search, so a large
cold corpus cannot crowd out the working set by age alone.

## Context faults

A context fault is the "I need something that is not in my working set" call.
It is a first-class syscall rather than an extra search because the answer's
*tier* is information the caller needs: an answer that came from L3 means the
warm tier had a gap, and that gap is what the system learns from.

`FaultResult` reports `hit`, `source` (`"L2"`, `"L3"`, or `null`), the injected
refs, and measured `latencyMs`. Both hit and miss are audited, with the tier
and the driver in the detail line:

```
fault  ok  actor=user:dana source=L3 injected=2 tokens=60 latencyMs=35 driver=baseline
```

The fault handler brownouts independently of the search path: if the vector
lane throws — including before a circuit breaker has opened — it falls back to
a lexical-only ranking over the ACL-scoped candidate window and marks the
result degraded, rather than failing the agent's turn.

## Where audit rows come from

`audit_log` is append-only by construction. The `AuditLog` class exposes
`append`, `search`, and paging methods, and no update or delete method exists
to be called.

```sql
CREATE TABLE IF NOT EXISTS audit_log (
  seq        BIGSERIAL PRIMARY KEY,
  ts         TIMESTAMPTZ NOT NULL,
  actor      TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  op         TEXT NOT NULL,
  memory_id  TEXT,
  namespace  TEXT NOT NULL,
  purpose    TEXT,
  result     TEXT NOT NULL,
  detail     TEXT
);
```

`result` is one of `ok`, `denied`, `miss`, `error`. Rows are produced in three
places:

- **Inside the module that did the work.** The write path, the fault handler,
  and the allocator each append their own row, because only they know the
  outcome detail (`blocks=1 tokens=28 budget=3000 rejectedPins=0`).
- **In the syscall layer.** Denials, rate-limit rejections, and errors audit
  here, before or instead of the op body.
- **In the transport layer.** A request rejected before dispatch — for example
  a body that tries to assert a namespace — is audited with the op attributed
  to the route it targeted.

Where the kernel has a transaction handle, the audit row commits in the *same*
transaction as the work it describes. A committed fact with no audit row is not
a state this system can reach.

`agentId` distinguishes the transport: `http`, `mcp`, `cli`. `purpose` carries
the query text for retrieval ops, truncated to 200 characters, and is
suppressed for turns marked sensitive.

Retrieval rows name the driver that produced the answer, and record a
degradation when one happened:

```
search ok  returned=2 tokens=60 driver=baseline
search ok  returned=2 tokens=60 driver=mem0 driver_fallback=mem0->baseline
search ok  returned=2 tokens=60 driver=bm25-degraded
```

## Erasure

`mem.forget` is the one governed exception to "never delete", and it is
deliberately expensive to invoke. In a single transaction it:

1. Nulls dangling `supersedes` links from surviving rows into the doomed set —
   the foreign key would otherwise reject the delete.
2. Hard-deletes the matching rows, taking their inline embeddings with them.
3. Inserts one tombstone per erased id.
4. Builds a `DeletionCertificate`, signs it with ed25519, and stores it with
   its public key inline.

It never touches `audit_log`. The record that the erasure happened, and the
history of the erased content's operations, survive the content itself.

Scoping runs **downward**: a caller may only erase inside its own subtree, and
a namespace target matches that namespace and its descendants. A target
naming an ancestor or a sibling resolves to zero rows.

Set `HALOMEM_SIGNING_KEY` (base64 PKCS8 DER ed25519) in any deployment where
certificates must remain verifiable. Without it the kernel generates an
ephemeral keypair at boot and warns; certificates signed by it cannot be
verified after a restart.

## Brownout

The rule is: degrade, log the degradation, and keep serving. Never convert
missing evidence into apparent success.

| Failure | Degradation |
| --- | --- |
| LLM unavailable or over budget cap | Write path stores verbatim; classification still runs. |
| Embedder unavailable | Search falls back to BM25-only (`driver=bm25-degraded`). |
| Retrieval driver or its sidecar down | Fall back to the baseline driver; audit `driver_fallback=<name>->baseline`. |
| Policy lane unreadable | Working set is assembled without guardrails; audit records `brownout=policy_unavailable`. |
| Pin target missing or malformed | Pin counted in `rejectedPins`; the rest of the working set still ships. |
| Warm mirror unreachable | Operation lands in a durable outbox; the syscall still succeeds. |

The one thing that never browns out is a security decision. A failure to
evaluate an ACL, a policy denial, or a classification is an error, not a
permit.

## Source map

| Path | Contents |
| --- | --- |
| `kernel/src/types.ts` | Shared types. Import from here, never from another module's internals. |
| `kernel/src/db/` | Db handle, migrations, PGlite/Postgres selection. |
| `kernel/src/index/` | `MemoryIndex` — every read and write of `memory_objects`; ACL lives here. |
| `kernel/src/audit/` | Append-only audit log. |
| `kernel/src/write/` | Write path: extraction, verification, entities, dedupe, insert. |
| `kernel/src/syscalls/` | The syscall layer: gate, pipeline, audit attribution. |
| `kernel/src/allocator/` | `ContextAllocator` — working-set packing. |
| `kernel/src/fault/` | `FaultHandler` and the absolute hybrid scoring used for tier acceptance. |
| `kernel/src/retrieval/` | BM25, hybrid merge, the baseline L2 lane. |
| `kernel/src/embed/` | Embedders: hash (default), OpenAI, Azure OpenAI. |
| `kernel/src/driver/` | Driver registry, `ScopedView` builder, and the shipped cartridges. |
| `kernel/src/conformance/` | The six-check conformance kit and its hermetic fixture. |
| `kernel/src/cold/` | L3 concept store, OKF parsing, envelope encryption. |
| `kernel/src/erasure/` | `mem.forget`, tombstones, signed deletion certificates. |
| `kernel/src/policy/` | Policy store, effective policy, guardrail directives. |
| `kernel/src/auth/`, `iam/`, `tenancy/` | Key resolution, roles, tenant isolation. |
| `kernel/src/http/` | HTTP transport and the admin surface. |
| `kernel/src/mcp/` | MCP tool definitions, stdio server, `/mcp` transport. |
| `kernel/console/` | The frameworkless control room UI. |
| `kernel/test/` | The hermetic test suite: in-memory PGlite, stub LLM, hash embedder, no network. |

Conventions: Node 22, ESM (relative imports end in `.js`), strict TypeScript.
Database access goes through the shared `Db` handle. pgvector parameters bind
as `'[0.1,0.2]'` strings. Boundary timestamps are ISO-8601.

## Further reading

- [driver-kit.md](driver-kit.md) — the retrieval boundary in full, and how to
  write a cartridge.
- [self-hosting.md](self-hosting.md) — running this against real Postgres.
