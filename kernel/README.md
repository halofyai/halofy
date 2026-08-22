# Halofy kernel

The kernel package: the memory syscalls, the storage tiers, the write path, the
governance surfaces, the HTTP and MCP transports, the CLI, and the control room.

This file is the package-level map — scripts, layout, environment, development
commands. For the conceptual model, the schema, and the per-directory source
map, read [`../docs/architecture.md`](../docs/architecture.md).

## Quickstart

```bash
npm ci
npm run demo    # the full story: pin → assemble → write → search → L3 fault →
                # update → stats/audit → erase with a signed certificate.
                # No API key, no database server, no network, no model download.
npm test        # hermetic suite: in-memory PGlite + pgvector, StubLlm,
                # HashEmbedder, zero network
npm run serve   # HTTP API + console on :8787
npm run mcp     # MCP stdio server
```

`npm run demo` exits 0 with no credentials configured. That is the intended
default, not a degraded mode — see
[`../docs/getting-started.md`](../docs/getting-started.md).

## Scripts

| Script | What it does |
|---|---|
| `npm test` | Hermetic vitest suite via `scripts/run-hermetic-tests.mjs`: clears `DATABASE_URL`, `TEST_DATABASE_URL`, `HALOMEM_DATA_DIR` and `HALOMEM_KNOWLEDGE_DIR`, marks the lane hermetic so the Postgres and perf files are excluded, then runs every remaining file in its own forked process. |
| `npm run test:serial` | The same suite pinned to `--maxWorkers=1`. |
| `npm run test:pg` | The Postgres lane. Needs a real `DATABASE_URL`. |
| `npm run test:perf` | p95 latency against the NFR gates. Needs an uncontended machine. |
| `npm run typecheck` | `tsc --noEmit`. Must be clean. |
| `npm run build` | Emit `dist/`. |
| `npm run demo` | The end-to-end story, no credentials. |
| `npm run serve` / `serve:dev` | HTTP API on `:8787`; console at `/console/login`. |
| `npm run mcp` | MCP stdio server. |
| `npm run migrate` | Apply the numbered migrations. |
| `npm run env:init` | Generate local-only secrets into `kernel/.env`. |

Run one file or one test name — keep `--maxWorkers=1`, PGlite is
single-process:

```bash
npx vitest run test/write-path.test.ts --maxWorkers=1
npx vitest run -t "supersede" --maxWorkers=1
```

## Layout

| Path | What |
|---|---|
| `src/db/` | The shared `Db` handle and `migrations.ts`, the append-only numbered schema history. |
| `src/index/` | The memory index and the ACL. Every read scope is built here, never in a caller. |
| `src/audit/` | The append-only audit log and its chain verification. |
| `src/write/` | The custody write path: extract, verify, resolve entities, dedupe, supersede, provenance. |
| `src/retrieval/`, `src/embed/` | Hybrid vector + BM25 ranking; hash and OpenAI/Azure embedders. |
| `src/driver/` | **Apache-2.0.** `RetrieverDriver`, `ScopedView`, and the baseline / graph / mem0 cartridges. |
| `src/conformance/` | The six-check kit that decides whether a driver is mountable. |
| `src/allocator/`, `src/fault/` | Working-set packing under a token budget; the L2 → L3 → miss fault path. |
| `src/cold/` | L3: encrypted, Git-versioned markdown concepts. |
| `src/syscalls/` | The syscall bodies. Every one writes an audit row, including denials. |
| `src/policy/` | Policy documents, directives, the acknowledgement ledger. |
| `src/erasure/` | `mem_forget`, tombstones, and ed25519 deletion certificates. |
| `src/auth/`, `src/iam/`, `src/tenancy/` | API keys, sessions, roles, tenant isolation. |
| `src/http/` | Transport, auth, and the management API behind the console. |
| `src/mcp/` | **Apache-2.0.** MCP stdio server and tool definitions. |
| `src/console/` | Scoped read models and management actions behind the console. |
| `console/` | The frameworkless control room: string-rendered, XSS-escaped, no build step. |
| `test/` | The hermetic suite. |
| `scripts/` | Migration runner, env init, backup/restore, dev server. |
| `deploy/` | Kubernetes manifests. |
| `sidecar/mem0/` | The mem0 retrieval sidecar — the second driver implementation (D6). |

`Dockerfile` and `docker-compose.yml` are the self-host stack; see
[`../docs/self-hosting.md`](../docs/self-hosting.md).

## The ACL, in one paragraph

A caller in namespace `N` sees rows whose namespace is `N` or a `/`-split prefix
**ancestor** of `N`. Org and team knowledge flows down; sibling and session data
never flows sideways, and descendants are invisible — admin subtree reads are an
explicit, audited exception. Enforcement lives in the query/repository layer
(`src/index/index.ts`), never in callers. Denied reads still audit.

Identity — namespace, actor, role, team, source scope — is resolved server-side
from the API key (D9). No caller-asserted identity is ever trusted.

## CLI

`npx tsx src/cli.ts` with no arguments prints the full command list. The ones
you are most likely to need:

```bash
npx tsx src/cli.ts keygen <namespace> <actor> <role>   # owner|admin|auditor|member|agent
npx tsx src/cli.ts list
npx tsx src/cli.ts revoke <id>
npx tsx src/cli.ts conformance <driverName>            # the driver kit, 6 checks
npx tsx src/cli.ts scorecard <namespace>               # referee run
npx tsx src/cli.ts forget <actor|entity|namespace|memory> <value> [namespace]
npx tsx src/cli.ts fragmentation <namespace>
npx tsx src/cli.ts warmstore rebuild <name> <namespace>
```

The first key on an empty `api_keys` table uses the bootstrap path. A generated
key's plaintext is printed exactly once.

## Environment

Nothing below is required to run `npm run demo` or `npm test`.

| Variable | What it does | Default |
|---|---|---|
| `DATABASE_URL` | Real Postgres. Unset means embedded PGlite. | unset → PGlite |
| `HALOMEM_DATA_DIR` | On-disk location for the embedded database. | temp dir |
| `HALOMEM_KNOWLEDGE_DIR` | The L3 concept repository. | temp dir |
| `HALOMEM_API_KEY` | Caller credential for the CLI and the MCP server. | — |
| `ANTHROPIC_API_KEY` | Real extraction and verification. | unset → `StubLlm` |
| `OPENAI_API_KEY` | Real embeddings. | unset → `HashEmbedder` (dim 256) |
| `HALOMEM_LLM_BASE_URL` / `HALOMEM_LLM_MODEL` / `HALOMEM_LLM_API_KEY` | Any OpenAI-compatible endpoint, including a local server. Takes precedence over Anthropic. | unset |
| `AZURE_OPENAI_*` | Azure OpenAI for chat and/or embeddings. | unset |
| `HALOMEM_PUBLIC_URL` | External origin, used to build absolute callback and console URLs. Must be origin-only HTTPS when set. | unset |
| `NODE_ENV=production` | Enables fail-closed boot: required secrets must be present. | unset |

`npm run env:init` generates the local-only secrets — the ed25519 signing key
for deletion certificates, the key-encryption keys, and the first-installation
bootstrap token — into `kernel/.env`. `src/config.ts` is the authoritative list;
[`../docs/self-hosting.md`](../docs/self-hosting.md) explains which ones a
production deployment must set.

## Conventions

Node 22, ESM (relative imports end in `.js`), strict TypeScript, no `any` unless
unavoidable. Shared types live in `src/types.ts` — import from there, never from
another module's internals. Database access goes through the shared `Db` handle.
pgvector parameters bind as `'[0.1,0.2]'` strings. Boundary timestamps are
ISO-8601.

New migrations are appended, never rewritten, and any migration that
`CREATE TABLE`s must also `ENABLE ROW LEVEL SECURITY` — see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) for why, and
[`../docs/security/threat-model.md`](../docs/security/threat-model.md) for the
part of the schema that predates the convention.

## Licence

AGPL-3.0-or-later, except `src/driver/`, `src/mcp/` and `integrations/`, which
are Apache-2.0 and carry their own `LICENSE` files. See
[`../LICENSING.md`](../LICENSING.md) and [`../NOTICE`](../NOTICE).
