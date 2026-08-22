# Halofy

**An organizational memory kernel for AI agent fleets.**

Halofy owns *custody* of memory — the write path, placement across tiers,
movement, and governance — and delegates *retrieval* to swappable open-source
engines mounted as read-only cartridges.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-22.x-brightgreen.svg)](kernel/package.json)

An agent fleet that shares memory needs answers to questions a vector store
does not have opinions about: who is allowed to read this fact, what happened
when it contradicted an older fact, which document it came from, who deleted
it and can that deletion be proven. Halofy is the layer that answers those.
It is a database schema, a write pipeline, an access-control rule, an
append-only audit log, and a syscall surface — not a retriever.

Retrieval is delegated on purpose and permanently (decision D1). The kernel
ships a baseline retriever as a referee control lane, not as a moat.

---

## What it does

Each bullet is implemented in this repository at the path given.

- **Memory syscalls over MCP and HTTP** — `mem_write`, `mem_write_status`,
  `mem_read`, `mem_search`, `mem_assemble`, `mem_fault`, `mem_pin`,
  `mem_unpin`, `mem_stats`, `mem_forget`, `mem_policy`, `mem_policy_ack`,
  `mem_share`, `mem_manifest`.
  (`kernel/src/syscalls/`, `kernel/src/mcp/tools.ts`)
- **A custody write path**, not an upsert: extract → verify → resolve entities
  → dedupe → supersede → record provenance → audit. A contradicting fact
  *closes* the prior fact's validity interval and links to it. Nothing is ever
  overwritten (D7). (`kernel/src/write/`)
- **A tiered read path.** L2 is authoritative operational memory in
  Postgres/pgvector; L3 is governed knowledge — encrypted, Git-versioned
  markdown concepts. A context fault that L2 cannot answer above the relevance
  floor pages in from L3 and records the fault.
  (`kernel/src/fault/`, `kernel/src/cold/`)
- **A hierarchical ACL enforced in the query layer**, never in callers, and
  never with an unescaped `LIKE`. (`kernel/src/index/index.ts`)
- **Append-only audit on every syscall** — including denied, miss, brownout,
  and error outcomes (D4). Audit data is retrofit-impossible, so it is written
  from the first call. (`kernel/src/audit/`)
- **Signed erasure.** `mem_forget` hard-deletes matching rows, writes
  tombstones, leaves the audit history intact, and mints an ed25519
  `DeletionCertificate` that verifies offline. (`kernel/src/erasure/`)
- **Retrieval driver cartridges** with a mechanically enforced import
  boundary. A driver sees a `ScopedView` and nothing else; a static scan
  rejects any reach into storage, the write path, or audit — including
  `createRequire` and computed dynamic imports.
  (`kernel/src/driver/`, `kernel/src/conformance/`)
- **A frameworkless control room** — string-rendered, XSS-escaped, no build
  step — for memory, sources, teams, policies, conflicts, audit, and export.
  (`kernel/console/`)
- **No telemetry and no phone-home.**
  `grep -rE "posthog|segment\.io|amplitude|mixpanel" kernel/src` returns
  nothing, and no Halofy endpoint appears anywhere under `kernel/src`. Across
  the storage, write, retrieval and governance modules the only two source
  files containing `fetch(` are `src/embed/index.ts` (the optional OpenAI
  embedder) and `src/driver/mem0.ts` (the optional sidecar driver). Both are
  off unless you configure them.

---

## Quickstart

### 1. The whole story, with no credentials

This is the part worth checking first. Halofy runs a complete end-to-end
memory story with **no API key, no database server, no network, and no model
download.** Not a mock — the real kernel, on embedded PGlite with pgvector, a
deterministic hash embedder, and a deterministic stub LLM.

```bash
git clone https://github.com/halofyai/halofy.git
cd halomem/kernel
npm install
npm run demo
```

Output from a real run on the source tree, excerpted — `...` marks an elision.
(Honesty note for this pre-release branch: the commands above are verified
against the full source tree. The reduced public tree produced by the release
tooling does not yet compile; see `open-source/STATUS.md`. This note is removed
when the public tree passes `typecheck`, `demo` and `test` in a clean checkout.)

```text
== T0 ·· boot in-memory, pin the refund policy, assemble the working set
booted: embedder=hash(dim=256) llm=stub knowledge=/tmp/halomem-demo-knowledge-6RUybo
working set for org/support/agent-1: 1 block(s), 28/3000 tokens
  [pinned-concept] concepts/refund-policy.okf.enc (28 tok): Refund policy Refunds are issued in full ...

== T1 ·· mem_write - extract facts from a support-chat transcript
write result: stored=2 rejected=0 superseded=0 deduplicated=0
  + 01M0JWREMV8M9EN2MZ573XBYR9 [user/fact, conf=0.9] my name is Dana Whitfield and my loyalty tier is Gold [entities: Dana, Whitfield, Gold]

...

== T3 ·· mem_fault - allergy escalation is NOT in L2; page it in from L3
fault: hit=true source=L3 injected=2 latencyMs=36
  score=0.704 [L3] concepts/escalation-matrix.okf.enc: Support escalation matrix: Allergy incidents page Tier 2 ...

== T5 ·· mem_stats + audit trail
stats: l2=3 l3Concepts=3 faults=1 faultHitRate=1.00 avgWorkingSetTokens=28 auditEvents=6
last 7 audit rows (most recent first):
  2026-08-21T19:28:56.731Z  stats     ok     actor=user:dana l2=3 l3=3 audit=6
  2026-08-21T19:28:56.642Z  fault     ok     actor=user:dana source=L3 injected=2 tokens=60 latencyMs=36 driver=baseline
  2026-08-21T19:28:56.589Z  search    ok     actor=user:dana returned=2 tokens=60 driver=baseline
  ...

...

== T7 ·· mem.forget - erase the customer and mint a signed deletion certificate
before forget: mem_search surfaces 4 Dana Whitfield fact(s) (conversation + imported CRM)
forget (as org/support): erased 4 row(s), wrote 4 tombstone(s)
certificate 01M0JWRF3ZMGA0RCGA9DARWERZ verifyCertificate === true
  algorithm=ed25519 publicKey=MCowBQYDK2VwAyEA… signature=CQ039g8Ml2aNtvgQ…
after forget: mem_search surfaces 0 Dana Whitfield fact(s) (expect 0)
  getById(01M0JWREMV8M9EN2MZ573XBYR9) found=false (expect false - the row is hard-deleted)
audit trail intact: 1 'forget' row(s) recorded (the erased content's history is never deleted - D4)

...

demo complete - kernel closed.
```

Exit code 0. Then run the hermetic test suite and the driver conformance kit,
still with no credentials:

```bash
npm test                                  # hermetic: PGlite + StubLlm + HashEmbedder, zero network
npx tsx src/cli.ts conformance baseline   # driver boundary + quality kit
```

Real output. The latency number is whatever your machine does, and the
`read-only` row's absolute source path is elided:

```text
conformance report - driver 'baseline' (view: driver/view.js)
check                 result  detail
--------------------  ------  ----------------------------------------
finds-planted-fact    PASS    10/10 planted refs in top-3 (need >= 8)
respects-scoped-view  PASS    0 violations across 15 queries (5 canaries in sibling ns unreachable)
latency-envelope      PASS    p95 5.5ms over 20 plan() calls (bound 150ms)
budget-discipline     PASS    max sum(tokenEstimate) 120/120 across 10 queries
read-only             PASS    no forbidden imports (../{index,kernel,db,write,audit,cold}[/.]*, createRequire, computed dynamic import)
deterministic-k       PASS    same top-3 across repeated runs of 3 queries
result: PASS (6/6 checks)
```

### 2. Self-host with real Postgres

```bash
cd kernel
npm run env:init          # generates kernel/.env: ed25519 signing key, KEKs, bootstrap token
docker compose up --build # pgvector/pg16 + the non-root kernel image
```

Open `http://localhost:8787/console/login`, expand **First installation**, and
paste `HALOMEM_BOOTSTRAP_TOKEN` from `kernel/.env`. The HTTP API and
`/healthz` live at the same origin. Numbered migrations run before the server
accepts traffic. Full walkthrough: [docs/self-hosting.md](docs/self-hosting.md).

### 3. Run it as an MCP server

```bash
cd kernel
npx tsx src/cli.ts keygen org/support/agent-1 user:dana owner   # plaintext printed once
HALOMEM_API_KEY=hm_... npm run mcp
```

Real extraction turns on with `ANTHROPIC_API_KEY`; real embeddings with
`OPENAI_API_KEY`. Without them the kernel runs deterministic stubs. That is
the intended default, not a degraded mode.

---

## How it works

```text
                    agents · applications · CLI · browser
                                    │
              MCP stdio      │      HTTP /v1      │      console
                                    │
                    ┌───────────────▼───────────────┐
                    │  identity resolution (D9)     │  API key ─▶ tenant,
                    │  resolved server-side, from   │  namespace, actor, role.
                    │  the API key alone            │  Never from the body.
                    └───────────────┬───────────────┘
                                    │
      mem_write ◀───────────────────┴───────────────────▶ mem_search · mem_fault
          │                                                      · mem_assemble
          ▼                                                      │
┌────────────────────────────┐                                   ▼
│  WRITE PATH — custody      │              ┌──────────────────────────────────┐
│                            │              │  READ PATH — delegated (D1, D2)  │
│  extract   LLM or stub     │              │                                  │
│  verify    drop hallucin.  │              │  allocator packs a working set   │
│  resolve   entity registry │              │  under a token budget and        │
│  dedupe    exact + cosine  │              │  returns RANKED BLOCKS — it      │
│  supersede close the prior │              │  never assembles a prompt        │
│            fact's validity │              │              │                   │
│            and link to it; │              │      ScopedView — read-only,     │
│            never overwrite │              │      ACL-narrowed, valid rows    │
│            (D7)            │              │              │                   │
│  provenance + audit        │              │   ┌──────────▼───────────┐       │
└─────────────┬──────────────┘              │   │  driver cartridge    │       │
              │                             │   │  import-fenced       │       │
              │                             │   │  baseline·graph·mem0 │       │
              │                             │   └──────────┬───────────┘       │
              │                             └──────────────┼───────────────────┘
              ▼                                            ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  POSTGRES — one authority (D5). PGlite embeds it for dev and test.           │
│                                                                              │
│  L2  memory_objects + pgvector    bi-temporal rows, supersedence chains      │
│  L3  concepts                     encrypted, Git-versioned markdown          │
│      policy · api_keys · entity_registry · tombstones                        │
│      audit_log — append-only ─────────────────────────────────────────────┐  │
└───────────────────────────────────────────────────────────────────────────┼──┘
                                                                            │
                                                                            ▼
        every syscall, every outcome — ok · denied · miss · brownout · error (D4)
```

**Identity (D9).** A namespace, actor, role, or source scope is resolved
server-side from the API key. Any code path that reads a namespace from a
request body is a bug, and there are regression tests that say so.

**The ACL rule.** A caller in namespace `N` sees rows whose namespace is `N`
or a `/`-split prefix *ancestor* of `N`. Org and team knowledge flows down;
sibling and session data never flows sideways. Descendants are invisible too —
admin subtree reads are an explicit, audited exception.

```text
caller namespace: org/support/agent-1

  org                          visible     (prefix ancestor)
  org/support                  visible     (prefix ancestor)
  org/support/agent-1          visible     (self)
  org/support/agent-2          not visible (sibling)
  org/support/agent-1/scratch  not visible (descendant)
  org/sales                    not visible (sibling)
```

Enforcement lives in the repository layer (`kernel/src/index/index.ts`), not
in callers. The ancestor set is matched as an exact `IN (...)` list, so no
pattern metacharacter can widen it. The one place a subtree match is
legitimate — the audited admin scope — is built as `LIKE ... ESCAPE '\'`,
because `_`, `%`, and backslashes are all legal inside a namespace.

**Delegated retrieval.** Drivers under `kernel/src/driver/` may import only
the types, retrieval, and embedding surfaces. They receive a `ScopedView`
already narrowed by the ACL and return ranked references. The conformance kit
runs six checks — planted-fact recall, scoped-view isolation with canaries in
sibling namespaces, a latency envelope, token-budget discipline, a static
read-only source scan, and determinism — and a driver that fails any of them
is not mountable.

**Brownout, never hard-fail.** If a backend, LLM, or budget cap fails, the
kernel degrades — verbatim writes, BM25-only search, pinned working set — and
logs the degradation. It never converts missing security evidence into
success.

More: [docs/architecture.md](docs/architecture.md) walks the same path with
worked examples, the SQL, and a per-directory source map.

---

## What makes this different

Three things, all checkable in the previous section:

1. **It runs end to end with nothing installed but Node.** `npm run demo`
   needs no API key, no database server, no network, and no model
   download. You can watch the whole custody story — pin, write, search,
   page in from the cold tier, erase with a signed certificate — before
   deciding whether to trust it. (Supersedence needs a real extractor to
   fire on free text; the deterministic stub does not produce the
   contradiction. `npx vitest run test/write-path.test.ts` exercises it
   directly, also with no credentials.)
2. **The governance code is the part that is open.** ACL prefix matching,
   append-only audit, supersedence chains, provenance, and erasure
   certificates are all readable source. You cannot credibly sell auditable
   memory while the audit implementation is a binary.
3. **Retrieval is a cartridge slot, not a lock-in.** The boundary is enforced
   by a static scan, not a code-review convention, so swapping the retriever
   cannot quietly grant it write or audit access.

---

## Comparison

The other projects in this space are good, and two of them are considerably
more established than this one. Values below were checked on 2026-08-21;
`—` means **we did not verify that cell**, not that the answer is no. Check
anything you plan to rely on.

| | Halofy | Cognee | Mem0 | Supermemory |
|---|---|---|---|---|
| License | AGPL-3.0-or-later, with Apache-2.0 subtrees | Apache-2.0 | Apache-2.0 | MIT (shell) |
| GitHub stars | new project | 30,170 | 63,755 | 28,983 |
| Contribution agreement | CLA | DCO | CLA | — |
| Memory engine source in the repo | yes | yes | yes | **no** — "Local" is a prebuilt binary |
| Full run with no API key | **yes** | not by default (raises `LLMAPIKeyNotSetError`; Ollama path documented) | not by default (`Memory()` raises without `OPENAI_API_KEY`; local providers via config) | partial (local embeddings, LLM still required for extraction) |
| Telemetry on by default | no | — | **yes** (PostHog), plus in-SDK upsell flags | — |
| Documented self-host limits | 60 req/min default rate limit, operator-set; flag-gated trial quotas, off by default — both in `docs/self-hosting.md` | — | — | **undocumented 10,000-document cap** |
| Graph memory in the OSS repo | yes (`kernel/src/driver/graph.ts`) | — | **removed in v2.0.0** | — |

**What the others do better.** Cognee ships its whole pipeline under
Apache-2.0 and takes contributions under a DCO rather than a CLA — materially
less friction than we ask for, and no relicensing question. Mem0 has by far
the largest community and the most mature multi-language SDK surface; if you
want something with miles on it and a busy issue tracker, that is Mem0.
Supermemory is MIT-licensed at the shell and has the most polished hosted
developer experience of the four.

**Where we are worse.** Halofy is new and has no community. AGPL-3.0 is more
restrictive than Apache-2.0 or MIT, and we require a CLA. Several subsystems
are deliberately not in this repository (next section). If any of that is
disqualifying, one of the projects above is the better choice, and we would
rather you pick it now than be surprised later.

---

## Open source and commercial

The kernel in this repository is the real thing, not a demo shell: the write
path, tiering, ACL, audit, supersedence, erasure, the console, the driver
cartridges, and the self-host stack are all here and all run offline.

**Deliberately not in this repository**, because it is what funds the work:

- **Model routing and spend attribution** — the commercial AI gateway.
- **Billing, credit ledger, and usage caps.**
- **Managed communication channels** (Slack, Discord, WhatsApp operations).
- **The managed connector catalog** — the large hosted-integration catalog.
  The connector *framework* is here, with filesystem, Postgres, CSV, and
  Obsidian connectors, so you can write your own.
- **Federated live query** across external systems.
- **Usage analytics surfaces.**
- **The tuned extraction prompt pack.** The LLM plumbing ships — the provider
  clients for Anthropic, Azure OpenAI and any OpenAI-compatible endpoint, the
  deterministic stub that the demo and the test suite run on, and the
  loose-JSON parser. The tuned prompt set behind hosted extraction quality is
  commercial.

There is no license key, no edition flag, no seat or document cap, and no
phone-home to disable. If you self-host, the kernel never contacts us.

That boundary is written down and versioned as a promise, with a stated
procedure for what happens if we ever move it:
[OPEN-SOURCE-SCOPE.md](OPEN-SOURCE-SCOPE.md). Licensing mechanics are in
[LICENSING.md](LICENSING.md); the feature-by-feature comparison is in
[docs/commercial/open-vs-managed.md](docs/commercial/open-vs-managed.md).
Commercial licenses, for organizations that cannot accept AGPL network
copyleft: <licensing@halofy.ai>.

---

## Documentation

| Path | What |
|---|---|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/getting-started.md](docs/getting-started.md) | Zero to a working kernel, with real commands and real output |
| [docs/architecture.md](docs/architecture.md) | Trace a request; locate the owning module |
| [docs/driver-kit.md](docs/driver-kit.md) | Write a retrieval cartridge and pass conformance 6/6 |
| [docs/self-hosting.md](docs/self-hosting.md) | Docker Compose, environment, backup/restore, upgrades |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Assets, adversaries, controls — including the partial ones |
| [kernel/README.md](kernel/README.md) | Kernel package: scripts, layout, development commands |
| [OPEN-SOURCE-SCOPE.md](OPEN-SOURCE-SCOPE.md) | What stays open, permanently, and what is commercial |

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. The short version: open an
issue before building anything large; changes to auth, ACL, tenancy,
migrations, encryption, audit, or the write/retrieval boundary get adversarial
review; every bug fix ships with the regression test that would have caught
it; and paste real command output in the pull request rather than describing
it.

Contributions require a CLA ([CLA.md](CLA.md)), which is what makes the
commercial license offerable alongside the AGPL one. Community expectations
are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Security issues do **not** go in the issue tracker — see
[SECURITY.md](SECURITY.md). The highest-value targets are ACL prefix
matching, `LIKE`/`ESCAPE` namespace escapes, audit omission, erasure
certificate forgery, and token handling.

---

## License and trademarks

Halofy is distributed under **AGPL-3.0-or-later** ([LICENSE](LICENSE)).

Named subtrees are **Apache-2.0** ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0))
so they can be embedded in closed applications the way a client library
should be — `kernel/src/driver/`, `kernel/src/mcp/`, and
`kernel/integrations/`. Writing a retrieval cartridge or an MCP
client should not relicense your application. The authoritative scope is in
[LICENSING.md](LICENSING.md) and [NOTICE](NOTICE); each such directory also
carries its own `LICENSE` file.

"Halofy" and "Halofy", and the Halofy logo, are trademarks. **Neither license
grants trademark rights** — see [TRADEMARK.md](TRADEMARK.md). Forks must
rename.
