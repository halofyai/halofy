# Self-hosting

Halofy is designed to be run by the organization whose memory it holds. This
page covers the Compose stack, configuration, Postgres requirements, backups,
upgrades, and — importantly — what the open build deliberately does not
include.

If you only want to try the kernel, you do not need any of this. `npm run demo`
runs the full story with no database and no credentials; see
[getting-started.md](getting-started.md).

## What you are running

- One Node.js process: the kernel, its HTTP API, and the console UI.
- One Postgres database with the `pgvector` extension. It holds the memory
  index, the embedding vectors, the policy store, and the audit log. There is
  no second datastore to operate.
- A knowledge directory on a persistent volume for L3 cold-tier concepts.

That is the whole topology. Any warm-store mirror or retrieval sidecar you add
later is a rebuildable cache, not another authority.

## Quick start with Docker Compose

```bash
cd kernel
npm run env:init
docker compose up --build
```

The console is at `http://localhost:8787/console/login`. On a fresh database,
the first-installation flow asks for the bootstrap token that `env:init` wrote
into `kernel/.env`, along with an email, password, and organization name.

### What `env:init` generates

`npm run env:init` writes `kernel/.env` with mode `0600` and refuses to
overwrite an existing file — losing these values means losing access to
everything they encrypt.

| Variable | What it is |
| --- | --- |
| `POSTGRES_PASSWORD` | Random password for the Compose `db` service; flows into the kernel's `DATABASE_URL`. |
| `HALOMEM_BOOTSTRAP_TOKEN` | Single-use out-of-band credential for creating the first owner account. |
| `HALOMEM_SIGNING_KEY` | ed25519 private key (base64 PKCS8 DER) that signs erasure certificates. |
| `HALOMEM_COLD_KEK` | 32-byte base64 key encryption key wrapping L3 concept data keys. |
| `HALOMEM_SOURCE_CONFIG_KEK` | 32-byte base64 KEK for connector configuration at rest. |

It also writes additional key material and empty placeholders for optional
integrations. Leave the placeholders empty unless you are wiring the
corresponding feature, and keep every generated key stable across restarts.

Back up `kernel/.env` the way you would back up any key material. In a real
deployment, put these in a secret manager and inject them as environment
variables instead of shipping a file.

### The two services

| Service | Image | Role |
| --- | --- | --- |
| `db` | `pgvector/pgvector:pg16` | Postgres 16 with the `vector` extension; data on the named volume `halomem-pgdata`. |
| `kernel` | built from `kernel/Dockerfile` | The compiled kernel, running as the non-root `node` user, serving on `:8787`. Knowledge directory on `halomem-knowledge`. |

The kernel waits for the database's `pg_isready` healthcheck, then runs the
numbered migrations itself before serving. There is no separate migration step
in the Compose path.

The Compose file sets `NODE_ENV=development` on purpose: the private `db`
service speaks plaintext, and the production configuration correctly refuses a
non-loopback Postgres DSN without TLS. Treat the shipped Compose stack as a
local development and evaluation lane, not a production deployment.

## Running against your own Postgres

Setting `DATABASE_URL` is the entire switch away from the embedded database.

```bash
export DATABASE_URL="postgres://halomem:secret@db.internal:5432/halomem?sslmode=verify-full"
cd kernel
npm ci
npm run build
npm run migrate
npm run serve
```

`npm run migrate` applies the numbered migrations and prints how many are
recorded and which version is current:

```json
{"migrations":<count>,"latest":<version>}
```

Requirements:

- **PostgreSQL with pgvector.** The first migration runs
  `CREATE EXTENSION IF NOT EXISTS vector`, so a self-managed server needs the
  extension installed. Managed providers must have it enabled or allowlisted
  first.
- **TLS for anything non-loopback.** Use `sslmode=verify-full`. The production
  configuration check rejects an insecure DSN rather than downgrading.
- **A dedicated role.** The kernel owns its schema. Do not share the database
  with unrelated applications.

Migrations are append-only and numbered; the kernel applies pending ones on
boot as well as through `npm run migrate`. Never edit a migration that has
already been applied somewhere.

### Indexing at scale

The embedding columns are plain `vector(n)`. The retrieval lane queries with
**cosine distance**, so any approximate index you add must use the cosine
operator class or it will not be used:

```sql
CREATE INDEX CONCURRENTLY idx_mem_embedding_hnsw
  ON memory_objects USING hnsw (embedding vector_cosine_ops);
```

Tune `shared_buffers` and `work_mem` at the database layer. The kernel exposes
no flags for index type or distance metric.

## Environment variables

### Core

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | *(empty)* | Postgres connection string. Empty selects embedded PGlite. |
| `HALOMEM_DATA_DIR` | *(empty)* | On-disk path for PGlite. Empty means in-memory. Ignored when `DATABASE_URL` is set. |
| `HALOMEM_KNOWLEDGE_DIR` | `kernel/knowledge` | L3 cold-tier concept directory. |
| `HALOMEM_PORT` | `8787` | HTTP listen port. |
| `NODE_ENV` | `development` | `production` turns on the deployment assertions below. |

### Secrets

| Variable | Meaning |
| --- | --- |
| `HALOMEM_BOOTSTRAP_TOKEN` | First-installation credential. Must be long; a short value disables the bootstrap path entirely. |
| `HALOMEM_SIGNING_KEY` | ed25519 PKCS8 DER, base64. Signs erasure certificates. Without it the kernel generates an ephemeral key at boot and warns — certificates then stop verifying after a restart. |
| `HALOMEM_COLD_KEK` | 32-byte base64. Wraps L3 concept data keys. |
| `HALOMEM_SOURCE_CONFIG_KEK` | 32-byte base64. Wraps connector configuration. |

Rotate or replace these only as a planned operation. A normal restart must
keep them stable.

### Limits

The standalone composition is unmetered: its optional packaging-quota port is
`UNMETERED`, and no hosted billing or trial-quota module ships in this
repository.

Two operator-owned controls still protect a deployment. They govern capacity
and model use; they do not unlock an edition or contact Halofy.

| Control | Default | Meaning |
| --- | --- | --- |
| *(per-namespace policy)* `rateLimitPerMin` | `60` | Requests per minute per API key, enforced by the policy store (`kernel/src/policy/store.ts`, `DEFAULT_RATE_LIMIT_PER_MIN`). Set it per namespace through the policy API; there is no global override variable. |
| *(per-namespace policy)* `monthlyBudgetUsd` | unset | Optional model-spend brownout threshold. When reached, writes store verbatim rather than calling the configured LLM. It is an operator policy, not Halofy metering. |

There is no seat limit, namespace limit, document limit, memory-count limit,
retention ceiling, licence key, or remote entitlement check in the open build.

### Models and embeddings

| Variable | Effect |
| --- | --- |
| *(none set)* | Deterministic hash embedder at dimension 256 and a stub extractor. Fully offline. |
| `ANTHROPIC_API_KEY` | Real LLM extraction and verification on the write path. |
| `HALOMEM_LLM_BASE_URL`, `HALOMEM_LLM_API_KEY`, `HALOMEM_LLM_MODEL` | Any OpenAI-compatible endpoint — a hosted vendor or a local vLLM — for the same role. |
| `OPENAI_API_KEY` | Real embeddings at dimension 1536. |
| `AZURE_OPENAI_EMBED_API_KEY`, `_ENDPOINT`, `_DEPLOYMENT` | Azure OpenAI embeddings at dimension 3072; takes precedence over `OPENAI_API_KEY`. |

**The embedding dimension is fixed by the first migration.** The `vector(dim)`
columns are created at whatever dimension the active embedder reports, and a
256-wide hash vector carries no meaning in a 3072-wide semantic space. Decide
before you create the database.

If you must change it later, the kernel realigns the columns and drops the old
vectors, then you rebuild them:

```bash
npx tsx src/cli.ts reembed
```

Until that completes, retrieval browns out to lexical-only ranking. That is the
designed degradation, not an outage — but plan the window.

### Serving behind TLS

| Variable | Meaning |
| --- | --- |
| `HALOMEM_PUBLIC_URL` | Origin-only HTTPS URL of the deployment. |
| `HALOMEM_SECURE_COOKIES` | `true` behind TLS. On plain-HTTP localhost, Secure cookies would never be sent, so it defaults to `false`. |

### What `NODE_ENV=production` enforces

The kernel fails closed at boot on deployment shapes that cannot preserve its
invariants:

- Serverless environments are rejected outright — the kernel is stateful and
  needs shared Postgres plus persistent cold storage.
- `DATABASE_URL` is required; embedded PGlite is development-only.
- The DSN must be secure (`sslmode=verify-full` for non-loopback hosts).
- The key-encryption keys and `HALOMEM_SIGNING_KEY` must all be set.
- `HALOMEM_COLD_STORAGE=shared-persistent` must be set, with a genuinely
  shared durable volume behind it.

These are assertions, not warnings — a misconfigured production deployment does
not start. `assertSupportedDeployment` in `kernel/src/config.ts` is the
authoritative list; read it before you plan a rollout, because a failed boot
with a one-line error is much cheaper to diagnose from the source than from a
container log.

## Backups

Everything that matters lives in one database, which is the point of the
single-authority design: one `pg_dump` covers the memory index, the embedding
vectors, the policy store, the tombstones, the deletion certificates, and the
audit log — consistently, at one point in time.

```bash
cd kernel
DATABASE_URL=postgres://user:pass@host:5432/halomem ./scripts/backup.sh
# writes ./halomem-backup-YYYYmmddTHHMMSSZ.sql
```

Restore into a **fresh or empty** database. A plain dump replayed over
populated tables collides on primary keys and aborts:

```bash
DATABASE_URL=postgres://user:pass@host:5432/halomem ./scripts/restore.sh halomem-backup-….sql
```

Both scripts need `pg_dump` / `psql` on your `PATH`.

Two things live outside the database and need backing up separately:

1. **The key material** (`HALOMEM_COLD_KEK`, `HALOMEM_SOURCE_CONFIG_KEK`,
   `HALOMEM_SIGNING_KEY`). A database backup without the cold KEK cannot
   decrypt private concepts. A restore without the signing key cannot verify
   previously issued erasure certificates.
2. **The knowledge directory** — the L3 concept source. Its summaries and
   embeddings are re-derived into the database on boot, so the directory is the
   source and the table is the index.

Restore drill: restore into an empty database with the original keys, boot,
check `GET /healthz`, log into the console, and confirm an erasure certificate
still verifies. A backup you have never restored is a hypothesis.

## Upgrading

1. Read the changelog for schema and behaviour changes.
2. Back up the database.
3. Pull the new version and rebuild (`docker compose up --build`, or
   `npm ci && npm run build`).
4. Start it. Migrations run automatically on boot; `npm run migrate` does the
   same thing explicitly if you prefer to gate on it.

Migrations are numbered and append-only, so upgrades move forward through the
sequence. There is no automated downgrade — roll back by restoring the backup
you took in step 2. Test the upgrade against a copy of production data before
running it against production.

## Operating notes

**PGlite is single-process.** Never point two kernel processes at the same
`HALOMEM_DATA_DIR`. If you need more than one process, you need `DATABASE_URL`.

**Health checks.** `GET /healthz` is unauthenticated and returns `{"ok":true}`.
`GET /metrics` requires authentication.

**The audit log grows.** It is append-only by design and there is no compaction
path, because a compactable audit trail is not an audit trail. Size your
storage for retention, and export before you archive.

**Brownout is expected behaviour.** If the LLM, embedder, or a retrieval
sidecar is unavailable, the kernel degrades and logs the degradation rather
than failing agent requests. See the brownout table in
[architecture.md](architecture.md#brownout). Alert on degradation rates rather
than treating any single degraded response as an incident.

**Verifying the real-Postgres lane.** The default test suite is hermetic and
never touches a server. To exercise the Postgres lane, point it at a scratch
database:

```bash
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/halomem_test npm run test:pg
```

That test drops and recreates the kernel's tables. Never aim it at a database
you care about.

## What is not in the open build

The kernel, the console, the write path, the governance code, the retrieval
driver boundary, and the conformance kit are all here. Some things are
deliberately not, and you should know before you plan around them:

| Not included | What that means for you |
| --- | --- |
| **Model routing and spend attribution** | The kernel calls the model you configure, directly. There is no gateway that routes across providers, attributes spend, or enforces per-team model budgets. |
| **Billing, credits, and usage caps** | No metering, no credit ledger, no plan enforcement. The open build is unmetered; capacity is whatever your hardware and your model provider give you. |
| **Managed communication channels** | No hosted Slack, Discord, WhatsApp, or Google Chat operation. You can build against the write path yourself, but the managed channel control plane is not here. |
| **The managed connector catalog** | The connector *framework* is here, along with filesystem, Postgres, CSV, and Obsidian connectors and the importer path. The large catalog of hosted SaaS connectors — with their OAuth applications and sync operations — is not. |
| **The tuned LLM prompt pack** | The write path's extraction, verification, entity, and classification prompts are not the tuned ones, so extraction quality with a real model will differ. Everything the prompts feed — the verifier, entity resolution, dedupe, supersedence, classification, audit — is unchanged. |

The schema is the full schema either way. Migrations create the tables for
subsystems that are not part of this build; they simply stay empty. This is
deliberate — pruning them would fork the schema history and make every future
upgrade a merge conflict.

Nothing in the list above is required to run the system. A self-hosted Halofy
with no external credentials at all is a working memory kernel: it stores,
supersedes, retrieves, governs, audits, and erases.

## Where next

- [getting-started.md](getting-started.md) — first key, first write, first
  search.
- [architecture.md](architecture.md) — how the pieces fit.
- [driver-kit.md](driver-kit.md) — mounting a different retrieval engine.
