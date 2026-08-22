# Getting started

Halofy is the access and governance layer between an organization's shared
context and the AI agents that use it. It resolves identity server-side,
enforces namespace and role policy, governs every change, and records every
outcome. Retrieval remains replaceable through read-only drivers.

This page takes you from a fresh clone to a running governance layer that has
issued an organization-scoped identity, stored a fact, enforced its access
boundary, answered a search, and produced an audit trail you can read.

The transcripts below are captured from real runs against this repository.
Identifiers (ULIDs, keys, timestamps, ports) will differ in your run; shapes
will not.

## Requirements

- Node.js 22 (`"engines": { "node": "22.x" }` in `kernel/package.json`)
- npm

That is the whole list for the first section. No database, no API key, no
model download, no network.

## 1. The zero-credential demo

```bash
cd kernel
npm install
npm run demo
```

`npm run demo` boots a complete kernel in-process: embedded PGlite with
pgvector for storage, a deterministic hash embedder, and a stub LLM. It then
walks one support conversation through the syscall surface and exits 0.

The first thing it prints tells you exactly which components are live:

```
== T0 ·· boot in-memory, pin the refund policy, assemble the working set
booted: embedder=hash(dim=256) llm=stub knowledge=/tmp/halomem-demo-knowledge-16zZ4L
working set for org/support/agent-1: 1 block(s), 28/3000 tokens
  [pinned-concept] concepts/refund-policy.okf.enc (28 tok): Refund policy Refunds are issued in full before preparation. Refunds over $50 r…
```

`embedder=hash(dim=256) llm=stub` is the point: with no `OPENAI_API_KEY` the
kernel uses a deterministic 256-dimension hash embedder, and with no
`ANTHROPIC_API_KEY` it uses a stub extractor. Both are intended defaults, not
a degraded mode you need to fix before evaluating the system.

Selected steps from a real run:

```
== T1 ·· mem_write - extract facts from a support-chat transcript
write result: stored=2 rejected=0 superseded=0 deduplicated=0
  + 01M0JX7GN03JEEXGPFRXFMEB07 [user/fact, conf=0.9] my name is Dana Whitfield and my loyalty tier is Gold [entities: Dana, Whitfield, Gold]

== T2 ·· mem_search - where does order 4127 ship?
  score=1.000 [L2] customer Dana Whitfield's current shipping address for order 4127 is 12 Elm Street, Springfield
  score=0.000 [L2] my name is Dana Whitfield and my loyalty tier is Gold [entities: Dana, Whitfield, Gold]

== T3 ·· mem_fault - allergy escalation is NOT in L2; page it in from L3
fault: hit=true source=L3 injected=2 latencyMs=35
  score=0.704 [L3] concepts/escalation-matrix.okf.enc: Support escalation matrix: Allergy incidents page Tier 2 immediately.

== T5 ·· mem_stats + audit trail
stats: l2=3 l3Concepts=3 faults=1 faultHitRate=1.00 avgWorkingSetTokens=28 auditEvents=6
last 7 audit rows (most recent first):
  2026-08-21T19:37:10.287Z  stats     ok     actor=user:dana l2=3 l3=3 audit=6
  2026-08-21T19:37:10.234Z  write     ok     actor=user:dana
  2026-08-21T19:37:10.197Z  fault     ok     actor=user:dana source=L3 injected=2 tokens=60 latencyMs=35 driver=baseline
  2026-08-21T19:37:10.147Z  search    ok     actor=user:dana returned=2 tokens=60 driver=baseline
  2026-08-21T19:37:10.016Z  write     ok     actor=user:dana
  2026-08-21T19:37:10.016Z  write     ok     actor=user:dana
  2026-08-21T19:37:09.997Z  assemble  ok     actor=user:dana blocks=1 tokens=28 budget=3000 rejectedPins=0

== T7 ·· mem.forget - erase the customer and mint a signed deletion certificate
before forget: mem_search surfaces 4 Dana Whitfield fact(s) (conversation + imported CRM)
forget (as org/support): erased 4 row(s), wrote 4 tombstone(s)
certificate 01M0JX7H4BZTZK81JJF6D22HE1 verifyCertificate === true
  algorithm=ed25519 publicKey=MCowBQYDK2VwAyEA… signature=3B80vUzn3WG1G9bW…
after forget: mem_search surfaces 0 Dana Whitfield fact(s) (expect 0)
  getById(01M0JX7GN03JEEXGPFRXFMEB07) found=false (expect false - the row is hard-deleted)
audit trail intact: 1 'forget' row(s) recorded (the erased content's history is never deleted)
```

Three things in that transcript are worth pausing on:

1. Every operation left an audit row, including the ones that succeeded
   quietly. Audit is not optional instrumentation; it is part of each syscall.
2. The fault at T3 was answered from the L3 cold tier because the L2 warm tier
   had nothing above its score floor. Tier selection is a kernel decision, not
   a caller flag.
3. `mem.forget` hard-deletes the memory rows, writes tombstones, and signs a
   deletion certificate with ed25519 — and the audit trail of the erased
   content survives, because the audit log is append-only.

## 2. Run the kernel

The demo runs everything in one process and throws it away. To keep state,
give the kernel a data directory and the encryption keys it needs.

```bash
cd kernel
export HALOMEM_DATA_DIR="$PWD/.halomem-data"
export HALOMEM_COLD_KEK="$(openssl rand -base64 32)"
export HALOMEM_SOURCE_CONFIG_KEK="$(openssl rand -base64 32)"
```

`HALOMEM_DATA_DIR` makes PGlite persist to disk instead of memory. The two
KEKs are 32-byte base64 keys that wrap the data keys for encrypted cold-tier
concepts and connector configuration. Keep them stable across restarts — lose
them and the data they wrap is unreadable.

For a real deployment you set `DATABASE_URL` instead and run against Postgres
with pgvector. See [self-hosting.md](self-hosting.md).

### Issue the first API key

Identity in Halofy is resolved server-side from an API key. Namespace, actor,
and role live on the key, and no request body may assert them. On an empty
database, `keygen` runs through a one-time bootstrap path that needs no
existing credential:

```bash
npx tsx src/cli.ts keygen acme "user:alice" owner
```

```
key id:    01M0JXBB680S08SE70Q6BDHEVK
namespace: acme
actor:     user:alice
role:      owner

API key (shown once, store it now):
hm_b0fd1b246210305f13dd4297d5020e0a8129a481
```

The plaintext is printed exactly once; only its hash is stored. Roles are
`owner`, `admin`, `auditor`, `member`, `agent`.

The bootstrap path is open only while `api_keys` is empty. Once any key
exists, `keygen` requires `HALOMEM_API_KEY` to name an **owner** whose
namespace is the target namespace or an ancestor of it. A refused attempt is
audited as a denial.

### Start the HTTP server

```bash
export HALOMEM_PORT=8787
npm run serve
```

```
{"ts":"...","level":"info","msg":"halomem http server listening","mod":"http-main",
 "port":8787,"embedder":"hash","embedDim":256,"llm":"stub","database":"pglite",
 "knowledgeDir":"/…/kernel/knowledge"}
```

`GET /healthz` is unauthenticated and answers `{"ok":true}`.

## 3. Write, search, read

Export your key once:

```bash
export K=hm_b0fd1b246210305f13dd4297d5020e0a8129a481
```

### Write

```bash
curl -s -X POST http://127.0.0.1:8787/v1/mem/write \
  -H "Authorization: Bearer $K" -H 'Content-Type: application/json' \
  -d '{"scope":"team","content":"The billing service owner is Priya. Deploys are frozen on Fridays."}'
```

Abridged response (the real body also carries `backendRef`, `eventTime`, a
top-level `classification`, `sourceAccess`, `ttlSeconds`, and access
telemetry):

```json
{
  "stored": [
    {
      "id": "01M0JXC3QPE6KP9S4VBTJNDF5Z",
      "namespace": "acme",
      "scope": "team",
      "tier": "L2",
      "content": "The billing service owner is Priya. Deploys are frozen on Fridays. [entities: The, Priya, Deploys, Fridays]",
      "type": "fact",
      "confidence": 0.9,
      "assertionTime": "2026-08-21T19:39:40.585Z",
      "tValidFrom": "2026-08-21T19:39:40.585Z",
      "tValidTo": null,
      "supersedes": null,
      "provenance": [
        {
          "extraction": "llm",
          "source": "conversation",
          "actor": "user:alice",
          "classification": { "sensitivity": "internal", "piiSubjects": [], "secretKinds": [] },
          "ts": "2026-08-21T19:39:40.585Z"
        }
      ],
      "status": "active"
    }
  ],
  "rejected": [],
  "superseded": [],
  "deduplicated": 0
}
```

Note what the kernel did without being asked: it assigned a namespace from the
key, stamped `tValidFrom` and left `tValidTo` open (the fact is currently
valid), recorded provenance including which extraction path produced it, and
classified the content's sensitivity.

The `[entities: …]` suffix is the entity annotation written by the stub
extractor. With a real LLM configured, extraction produces cleaner facts and
better entity sets.

### Search

```bash
curl -s -X POST http://127.0.0.1:8787/v1/mem/search \
  -H "Authorization: Bearer $K" -H 'Content-Type: application/json' \
  -d '{"query":"who owns the billing service","k":3}'
```

```json
[
  {
    "id": "01M0JXC3QPE6KP9S4VBTJNDF5Z",
    "tier": "L2",
    "ref": "01M0JXC3QPE6KP9S4VBTJNDF5Z",
    "score": 1,
    "content": "The billing service owner is Priya. Deploys are frozen on Fridays. [entities: The, Priya, Deploys, Fridays]",
    "tokenEstimate": 27
  }
]
```

The baseline lane min-max normalizes the vector and BM25 lanes separately per
query, then merges them `0.5 · vector + 0.5 · BM25`. A hit that tops both lanes
scores 1.0; a hit the lexical lane never returned tops out at 0.5. Treat scores
as an ordering within one response, not as an absolute confidence comparable
across responses.

### Read one memory by id

```bash
curl -s -X POST http://127.0.0.1:8787/v1/mem/read \
  -H "Authorization: Bearer $K" -H 'Content-Type: application/json' \
  -d '{"id":"01M0JXC3QPE6KP9S4VBTJNDF5Z"}'
```

```json
{ "found": true, "denied": false, "memory": { "id": "01M0JXC3QPE6KP9S4VBTJNDF5Z", "…": "…" } }
```

`denied` is always `false` in caller-facing results. A row that exists but is
outside your ACL is reported identically to a miss, so you cannot probe for
the existence of other namespaces' data. The audit trail still records
`denied` and `miss` as distinct outcomes.

### Assemble a working set

`mem_assemble` is what an agent framework calls at the start of a turn. It
returns ranked context blocks under a token budget. It does not build a
prompt — placement is the framework's job.

```bash
curl -s -X POST http://127.0.0.1:8787/v1/mem/assemble \
  -H "Authorization: Bearer $K" -H 'Content-Type: application/json' \
  -d '{"taskHint":"billing ownership"}'
```

Abridged — each block also carries its `content`:

```json
{
  "namespace": "acme",
  "blocks": [
    { "kind": "scope-memory", "ref": "01M0JXC3QPE6KP9S4VBTJNDF5Z", "tokenEstimate": 27, "orderKey": "1-scope-01M0JXC3QPE6KP9S4VBTJNDF5Z" },
    { "kind": "predicted-relevant", "ref": "01M0JXCJX2KWQ37V7SDW1SM4H3", "tokenEstimate": 15, "orderKey": "2-rel-01M0JXCJX2KWQ37V7SDW1SM4H3" }
  ],
  "totalTokens": 42,
  "budget": 3000,
  "assembledAt": "2026-08-21T19:42:00.823Z"
}
```

`orderKey` is stable across calls so the same working set serializes
identically — which is what makes upstream prompt caching viable.

## 4. Read the audit trail

```bash
curl -s "http://127.0.0.1:8787/v1/admin/audit?limit=10" -H "Authorization: Bearer $K"
```

Abridged — every row also carries a `purpose` field (`null` where the op has
no query text):

```json
[
  { "ts": "2026-08-21T19:39:40.865Z", "actor": "user:alice", "agentId": "http", "op": "stats",  "memoryId": null,                         "namespace": "acme", "result": "ok", "detail": "l2=1 l3=0 audit=2" },
  { "ts": "2026-08-21T19:39:40.799Z", "actor": "user:alice", "agentId": "http", "op": "search", "memoryId": "01M0JXC3QPE6KP9S4VBTJNDF5Z", "namespace": "acme", "purpose": "who owns the billing service", "result": "ok", "detail": "returned=1 tokens=27 driver=baseline" },
  { "ts": "2026-08-21T19:39:40.585Z", "actor": "user:alice", "agentId": "http", "op": "write",  "memoryId": "01M0JXC3QPE6KP9S4VBTJNDF5Z", "namespace": "acme", "result": "ok" }
]
```

Every request left a row, with the retrieval row naming the driver that
produced the answer. Your own trail will be longer than the three rows shown
here — the reads in section 3 are audited too. The `AuditLog` class exposes no
update or delete method; append-only is a property of the code, not a
convention.

## 5. Identity comes from the key

Try to assert a namespace in the request body:

```bash
curl -s -X POST http://127.0.0.1:8787/v1/mem/write \
  -H "Authorization: Bearer $K" -H 'Content-Type: application/json' \
  -d '{"scope":"team","namespace":"other","content":"x"}' -w '\nHTTP %{http_code}\n'
```

```
{"error":"namespace comes from your key","code":"identity_from_key"}
HTTP 400
```

The rejection happens in the transport layer before the syscall runs, and the
denial itself is audited. Any code path that reads a namespace, actor, or role
from a request body is a bug — this is the check that keeps that true.

## 6. Verify a retrieval driver

Retrieval is delegated to driver cartridges, and the boundary is mechanically
enforced rather than documented and hoped for:

```bash
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

The kit builds its own hermetic fixture, so this runs anywhere. To write your
own engine, see [driver-kit.md](driver-kit.md).

## 7. Connect an agent over MCP

```bash
npm run mcp
```

This starts the stdio MCP server. It resolves `HALOMEM_API_KEY` once at boot
into a server-side identity; the tool schemas carry no namespace or actor
parameters. Tools include `mem_read`, `mem_search`, `mem_write`,
`mem_write_status`, `mem_fault`, `mem_stats`, and `mem_assemble`.

The same tool definitions are served over HTTP at `/mcp`.

## 8. Turn on real models (optional)

| Variable | Effect |
| --- | --- |
| `ANTHROPIC_API_KEY` | Real LLM extraction and verification on the write path |
| `HALOMEM_LLM_BASE_URL` + `HALOMEM_LLM_API_KEY` + `HALOMEM_LLM_MODEL` | Any OpenAI-compatible endpoint for the same role |
| `OPENAI_API_KEY` | Real embeddings, dimension 1536 |

The embedding dimension is baked into the `vector(dim)` columns by the first
migration. Decide before you create the database: a database migrated at 256
dimensions cannot silently accept 1536-dimension vectors later. Changing it
requires a schema realign and a re-embed (`npx tsx src/cli.ts reembed`), during
which retrieval browns out to lexical-only ranking.

Without an LLM key, the write path stores facts verbatim and the stub
extractor does not detect semantic conflicts. Supersedence of conflicting
ordinary facts depends on model-verified conflict detection, so on the stub
lane you will see new facts stored alongside old ones rather than superseding
them. That is expected, and it is why the demo's T4 step shows
`supersedes=null`.

## Next

- [architecture.md](architecture.md) — the mechanism: syscalls, tiers, write
  path, ACL, allocator, audit.
- [driver-kit.md](driver-kit.md) — write and ship a retrieval cartridge.
- [self-hosting.md](self-hosting.md) — Docker Compose, Postgres, backups,
  upgrades, and what the open build does not include.
