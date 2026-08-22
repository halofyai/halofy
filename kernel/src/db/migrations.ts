/**
 * Module C (M1) — numbered migrations.
 *
 * Each migration is a versioned bundle of DDL statements. `migrate()` in
 * ./migrate.ts applies pending migrations in version order, each inside its
 * own transaction, and records the version in `schema_migrations`.
 *
 * 001 = the entire v0.1 schema (verbatim capture of the original migrate.ts —
 *       every statement is IF NOT EXISTS, so it remains idempotent even on
 *       databases that were migrated before versioning existed).
 * 002 = api_keys (M1 identity, D9).
 * 003 = cost_ledger (M1 budget caps).
 * 004 = scorecards (M2 referee runs, module E).
 * 005 = sources + source_documents + fragmentation_reports (M3 ingestion).
 * 006 = tenants + tombstones + deletion_certificates (M4 tenancy + erasure).
 * 007 = users + sessions (M5 human sign-in for the control room).
 * 008 = explicit ownership + ACL metadata for L3 concepts (R2A).
 * 009 = wrapped per-concept data keys for encrypted private L3 blobs (R2B).
 * 010 = explicit normalized PII-subject projection for private L3 erasure (R2C).
 * 011 = explicit cold-write state + target-scoped erasure fence (R2 hardening).
 * 012 = redact any legacy quarantine payloads, retaining only SHA-256 metadata.
 * 013 = persistent active-KEK generation for safe rotation and promotion.
 * 014 = explicit source-document identity + cross-process sync claims.
 * 015 = durable first-boot consumption + pending human invitations.
 * 016 = durable verified-setup operations + explicit first teams/source status.
 * 017 = one pending invitation authority per normalized email.
 * 018 = encrypted-at-rest connector configuration metadata.
 * 019 = logical knowledge identity + stable governed pins.
 * 020 = consolidation proposals, decisions, and durable movement actions.
 * 021 = explicit shared segments, mounts, and copy-on-write lineage.
 * 022 = tenant-scoped movement idempotency keys.
 * 026 = encrypted model connections + named Copilot model profiles.
 * 027 = active-only name uniqueness for credential/profile rotation.
 * 023–025 = warm mirrors, trust disputes, and the M6 pointer probe.
 * 028 = M7 enterprise state: classification/ACL, durable work, connector
 *       lifecycle, distributed throttles, OIDC/SCIM mappings, audit hashes.
 * 029 = M8 immutable, badge-bound agent connection grants.
 * 030-034 = source catalog, ingress, and Nango lifecycle hardening.
 * 035 = policy library document metadata.
 * 036 = M8A immutable grant oversight, access events, alerts, and requests.
 * 037 = named org teams (namespace-backed) + explicit team membership (S13).
 * 038 = M9 Mintlify parity: skill library + vetting/usage, hosted OAuth AS
 *       (hashed tokens only), per-turn answer outcomes, org automations,
 *       credit balance/ledger, usage alerts, api_keys caller classification.
 * 039 = M9 Wave 3: durable job kinds `usage-close` (daily alert close pass)
 *       and `usage-emit` (external billing delivery, E54).
 * 040 = skill approval workflow: member submissions land `pending`, team
 *       admins approve/reject (S16). Default 'approved' keeps every existing
 *       row's admin-registered semantics — no backfill surprise.
 * 048 = usage analytics: usage_events (one row per audited syscall, FK to
 *       audit_log(seq)) + query_traces rollups (D36-D39); cost attribution
 *       columns on cost_ledger / answer_outcomes.
 * 049 = usage rollup watermark indexes (usage_events(audit_seq),
 *       query_traces(ts)) — index-served high-water marks for the rollup
 *       result cache's invalidation check.
 * 050 = query_traces composite primary key (namespace, trace_id) — trace
 *       hints are caller-supplied strings, so rollup rows are per-namespace
 *       and cross-namespace collisions/squatting cannot leak or merge.
 * 051 = 30-day Knowledge Review sync history query index over append-only
 *       automation audit rows.
 * 052 = namespace-exact usage trace signal lookup for bounded-row rollups.
 * 053 = disable legacy fresh-summary chains targeting the platform root,
 *       which is authority scope rather than a canonical private namespace.
 * 054 = explicit governed company-memory access mode and organization scope
 *       for namespace-backed teams.
 * 055 = M10 role-scoped memory graph: server-owned access_grants (opaque
 *       resource IDs, revocation = revoked_at, D47) + root View-as
 *       access_preview_sessions (sha256 token_hash only, D43). RLS on both.
 *       agent_memory_grants is Phase 4 — deliberately NOT created.
 *       (Renumbered from 054 on merge — origin's team-company-memory-access
 *       landed first and is published.)
 * 062 = encrypted, actor-scoped Copilot conversations and idempotent turns.
 * 065 = channel control plane: connections, write-only credential envelopes,
 *       immutable agent-channel grants, ingress receipts, normalized events,
 *       send intents, delivery attempts, runtime state, OAuth sessions,
 *       verifications, shadow comparisons, ownership leases (C0 Tasks 1–5;
 *       renumbered from the halomemchannels branch's 035 on port).
 * 066 = separate production and verification-only active grant slots.
 * 067 = widen executable channel kind/provider CHECKs to cohorts 2–3
 *       (sixteen runnable channels; voice + WhatsApp T16 stay catalog-only).
 * 068 = onboarding completion flag: tenants.onboarding_completed_at one-way
 *       latch backing the mandatory setup gate (CONTRACTS-SETUP-GATE.md).
 *
 * Statement splitting: splitStatements() cuts on `;` at the top level only.
 * Semicolons inside a single-quoted literal or a dollar-quoted body (a
 * PL/pgSQL block) belong to that statement and are not split points.
 */

export interface Migration {
  version: number;
  name: string;
  sql(embedDim: number): string;
}

/**
 * Split a migration's SQL bundle into individual statements. Both backends'
 * `query()` execute a single statement at a time (PGlite uses the extended
 * protocol), so multi-statement bundles must be split before execution.
 */
export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let index = 0;
  while (index < sql.length) {
    const char = sql[index]!;
    if (char === "'") {
      // Single-quoted literal: consume to the closing quote, treating '' as an
      // escaped quote rather than a close.
      const start = index;
      index += 1;
      while (index < sql.length) {
        if (sql[index] === "'") {
          if (sql[index + 1] === "'") {
            index += 2;
            continue;
          }
          index += 1;
          break;
        }
        index += 1;
      }
      current += sql.slice(start, index);
      continue;
    }
    if (char === "$") {
      // Dollar-quoted body ($$ … $$ or $tag$ … $tag$) — how a migration carries
      // a PL/pgSQL block. Postgres does not nest the SAME tag, so an exact
      // match on the opening tag finds the close.
      const tag = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(sql.slice(index))?.[0];
      if (tag) {
        const close = sql.indexOf(tag, index + tag.length);
        // An unclosed tag is malformed SQL; keep the remainder intact so the
        // backend reports it, rather than silently splitting inside the body.
        const end = close === -1 ? sql.length : close + tag.length;
        current += sql.slice(index, end);
        index = end;
        continue;
      }
    }
    if (char === ";") {
      statements.push(current);
      current = "";
      index += 1;
      continue;
    }
    current += char;
    index += 1;
  }
  statements.push(current);
  return statements.map((statement) => statement.trim()).filter((statement) => statement.length > 0);
}

/**
 * Tables whose `embedding` column must track the CONFIGURED embedder's width.
 *
 * Reconciled on every migrate() rather than by a numbered migration: the right
 * dimension is a function of current configuration, not of schema version. A
 * once-only migration would apply as a no-op while no embedding key is set,
 * record itself as done, and never run again once the key IS set — leaving the
 * columns cut for the hash embedder and every insert failing.
 */
export const EMBEDDING_TABLES = ["memory_objects", "concepts", "entity_registry"] as const;

/**
 * DDL realigning every embedding column to `embedDim`; a no-op when they
 * already match (the hermetic 256-wide test lane, and any deployment whose
 * dimension has not moved).
 *
 * Old vectors CANNOT be carried across a dimension change — a 256-wide hash
 * vector has no meaning in a 3072-wide semantic space — so a realign drops them
 * (USING NULL) and the rows must be rebuilt with `npx tsx src/cli.ts reembed`.
 * Until that completes retrieval browns out to BM25, which is the designed
 * degradation rather than an outage.
 */
export function embeddingRealignSql(embedDim: number): string {
  const tables = EMBEDDING_TABLES.map((table) => `'${table}'`).join(",");
  return `
    DO $realign$
    DECLARE
      wanted CONSTANT text := format('vector(%s)', ${embedDim});
      tbl text;
      current_type text;
    BEGIN
      FOREACH tbl IN ARRAY ARRAY[${tables}] LOOP
        SELECT format_type(a.atttypid, a.atttypmod) INTO current_type
          FROM pg_attribute a
         WHERE a.attrelid = tbl::regclass
           AND a.attname = 'embedding'
           AND a.attnum > 0
           AND NOT a.attisdropped;
        -- Compare the rendered type, not atttypmod: correct regardless of how
        -- pgvector encodes a dimension internally.
        IF current_type IS NOT NULL AND current_type <> wanted THEN
          EXECUTE format(
            'ALTER TABLE %I ALTER COLUMN embedding TYPE %s USING NULL', tbl, wanted);
        END IF;
      END LOOP;
    END
    $realign$`;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: "initial-schema",
    sql(embedDim: number): string {
      return `
    CREATE EXTENSION IF NOT EXISTS vector;

    CREATE TABLE IF NOT EXISTS memory_objects (
      id            TEXT PRIMARY KEY,
      namespace     TEXT NOT NULL,
      scope         TEXT NOT NULL CHECK (scope IN ('user','assistant','team','org')),
      tier          TEXT NOT NULL CHECK (tier IN ('L2','L3')),
      backend_ref   TEXT NOT NULL,
      content       TEXT NOT NULL,
      type          TEXT NOT NULL,
      confidence    REAL NOT NULL,
      event_time    TIMESTAMPTZ,
      assertion_time TIMESTAMPTZ NOT NULL,
      t_valid_from  TIMESTAMPTZ NOT NULL,
      t_valid_to    TIMESTAMPTZ,
      supersedes    TEXT REFERENCES memory_objects(id),
      provenance    JSONB NOT NULL DEFAULT '[]',
      ttl_seconds   INTEGER,
      last_accessed TIMESTAMPTZ,
      access_count  INTEGER NOT NULL DEFAULT 0,
      fault_count   INTEGER NOT NULL DEFAULT 0,
      status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','tombstoned')),
      embedding     vector(${embedDim})
    );
    CREATE INDEX IF NOT EXISTS idx_mem_ns ON memory_objects(namespace, status);
    CREATE INDEX IF NOT EXISTS idx_mem_valid ON memory_objects(namespace, t_valid_to);

    CREATE TABLE IF NOT EXISTS concepts (
      path          TEXT PRIMARY KEY,
      type          TEXT NOT NULL,
      title         TEXT NOT NULL,
      description   TEXT NOT NULL DEFAULT '',
      tags          JSONB NOT NULL DEFAULT '[]',
      owner         TEXT,
      verified_against TEXT,
      verified_at   TIMESTAMPTZ,
      body          TEXT NOT NULL,
      embedding     vector(${embedDim}),
      synced_at     TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entity_registry (
      id             TEXT PRIMARY KEY,
      namespace      TEXT NOT NULL,
      canonical_name TEXT NOT NULL,
      aliases        JSONB NOT NULL DEFAULT '[]',
      embedding      vector(${embedDim}),
      created_at     TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_ns_name ON entity_registry(namespace, canonical_name);

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

    CREATE TABLE IF NOT EXISTS policies (
      namespace TEXT PRIMARY KEY,
      yaml      TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 2,
    name: "api-keys",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,
      namespace TEXT NOT NULL, actor TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner','admin','auditor','member','agent')),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      created_at TIMESTAMPTZ NOT NULL, last_used TIMESTAMPTZ
    )`;
    },
  },
  {
    version: 3,
    name: "cost-ledger",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS cost_ledger (
      id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('llm','embed')),
      tokens INTEGER NOT NULL, usd REAL NOT NULL, ts TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cost_ns_ts ON cost_ledger(namespace, ts)`;
    },
  },
  {
    version: 4,
    name: "scorecards",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS scorecards (
      id        TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      ran_at    TIMESTAMPTZ NOT NULL,
      json      JSONB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scorecards_ns_ran ON scorecards(namespace, ran_at)`;
    },
  },
  {
    version: 5,
    name: "ingestion-sources",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS sources (
      id         TEXT PRIMARY KEY,
      namespace  TEXT NOT NULL,
      kind       TEXT NOT NULL CHECK (kind IN ('filesystem','postgres','notion','slack','mem0-import','pgvector-import')),
      config     JSONB NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL,
      last_sync  TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_sources_ns ON sources(namespace);

    CREATE TABLE IF NOT EXISTS source_documents (
      source_id    TEXT NOT NULL,
      doc_id       TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      synced_at    TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (source_id, doc_id)
    );

    CREATE TABLE IF NOT EXISTS fragmentation_reports (
      id        TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      ran_at    TIMESTAMPTZ NOT NULL,
      json      JSONB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_frag_ns_ran ON fragmentation_reports(namespace, ran_at)`;
    },
  },
  {
    version: 6,
    name: "tenancy-erasure",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS tenants (
      id                 TEXT PRIMARY KEY,
      name               TEXT NOT NULL,
      status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
      monthly_budget_usd REAL,
      rate_limit_per_min INTEGER,
      created_at         TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tombstones (
      id             TEXT PRIMARY KEY,
      memory_id      TEXT NOT NULL,
      namespace      TEXT NOT NULL,
      reason         TEXT NOT NULL,
      erased_at      TIMESTAMPTZ NOT NULL,
      certificate_id TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tombstones_ns ON tombstones(namespace);
    CREATE INDEX IF NOT EXISTS idx_tombstones_mem ON tombstones(memory_id);

    CREATE TABLE IF NOT EXISTS deletion_certificates (
      id        TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      actor     TEXT NOT NULL,
      issued_at TIMESTAMPTZ NOT NULL,
      json      JSONB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_delcert_ns_at ON deletion_certificates(namespace, issued_at)`;
    },
  },
  {
    version: 7,
    name: "human-auth",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      email         TEXT NOT NULL UNIQUE,
      namespace     TEXT NOT NULL,
      role          TEXT NOT NULL CHECK (role IN ('owner','admin','auditor','member')),
      password_hash TEXT,
      status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
      created_at    TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)`;
    },
  },
  {
    version: 8,
    name: "concept-ownership-acl",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE concepts ADD COLUMN IF NOT EXISTS namespace TEXT;
    ALTER TABLE concepts ADD COLUMN IF NOT EXISTS visibility TEXT;
    CREATE TABLE IF NOT EXISTS concept_quarantine (
      path                  TEXT PRIMARY KEY,
      content_sha256        TEXT NOT NULL,
      classification_reason TEXT NOT NULL,
      quarantined_at        TIMESTAMPTZ NOT NULL
    );
    INSERT INTO concept_quarantine
      (path, content_sha256, classification_reason, quarantined_at)
      SELECT path,
             encode(sha256(convert_to(COALESCE(body, ''), 'UTF8')), 'hex'),
             'legacy-unowned',
             CURRENT_TIMESTAMP
        FROM concepts
       WHERE namespace IS NULL AND visibility IS NULL
      ON CONFLICT (path) DO NOTHING;
    DELETE FROM concepts WHERE namespace IS NULL AND visibility IS NULL;
    ALTER TABLE concepts ADD CONSTRAINT concepts_ownership_check CHECK (
      (namespace IS NOT NULL AND namespace <> '' AND visibility IS NULL)
      OR (namespace IS NULL AND visibility IS NOT NULL AND visibility = 'public')
    );
    CREATE INDEX IF NOT EXISTS idx_concepts_namespace ON concepts(namespace);
    CREATE INDEX IF NOT EXISTS idx_concepts_visibility ON concepts(visibility)`;
    },
  },
  {
    version: 9,
    name: "cold-concept-keys",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS cold_concept_keys (
      path        TEXT PRIMARY KEY,
      wrapped_dek TEXT NOT NULL,
      wrap_iv     TEXT NOT NULL,
      wrap_tag    TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 10,
    name: "concept-pii-subjects",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE concepts ADD COLUMN IF NOT EXISTS pii_subjects JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS namespace TEXT;
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS pii_subjects JSONB;
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS kek_id TEXT;
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS envelope_version INTEGER;
    ALTER TABLE concepts ADD CONSTRAINT concepts_private_pii_check CHECK (
      jsonb_typeof(pii_subjects) = 'array'
      AND (namespace IS NOT NULL OR jsonb_array_length(pii_subjects) = 0)
    );
    ALTER TABLE cold_concept_keys ADD CONSTRAINT cold_key_metadata_check CHECK (
      (namespace IS NULL AND pii_subjects IS NULL AND kek_id IS NULL AND envelope_version IS NULL)
      OR (namespace IS NOT NULL AND namespace <> '' AND jsonb_typeof(pii_subjects) = 'array'
          AND kek_id IS NOT NULL AND kek_id <> '' AND envelope_version = 2)
    )`;
    },
  },
  {
    version: 11,
    name: "cold-write-state-erasure-fence",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS write_state TEXT NOT NULL DEFAULT 'committed';
    ALTER TABLE cold_concept_keys ADD CONSTRAINT cold_key_write_state_check CHECK (
      write_state IN ('pending','committed')
    );
    CREATE TABLE IF NOT EXISTS erasure_fences (
      namespace  TEXT PRIMARY KEY,
      generation BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 12,
    name: "redact-concept-quarantine",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE concept_quarantine ADD COLUMN IF NOT EXISTS content_sha256 TEXT;
    ALTER TABLE concept_quarantine ADD COLUMN IF NOT EXISTS classification_reason TEXT;
    UPDATE concept_quarantine
       SET content_sha256 = COALESCE(
             content_sha256,
             encode(sha256(convert_to(COALESCE(
               to_jsonb(concept_quarantine)->'legacy_row'->>'body', ''
             ), 'UTF8')), 'hex')
           ),
           classification_reason = COALESCE(
             classification_reason,
             to_jsonb(concept_quarantine)->>'reason',
             'legacy-unowned'
           );
    ALTER TABLE concept_quarantine ALTER COLUMN content_sha256 SET NOT NULL;
    ALTER TABLE concept_quarantine ALTER COLUMN classification_reason SET NOT NULL;
    ALTER TABLE concept_quarantine DROP COLUMN IF EXISTS legacy_row;
    ALTER TABLE concept_quarantine DROP COLUMN IF EXISTS reason`;
    },
  },
  {
    version: 13,
    name: "active-cold-kek-state",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE cold_concept_keys ADD COLUMN IF NOT EXISTS kek_generation BIGINT;
    CREATE TABLE IF NOT EXISTS cold_kek_state (
      singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
      active_kek_id TEXT NOT NULL,
      generation    BIGINT NOT NULL CHECK (generation > 0),
      maintenance   BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at    TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 14,
    name: "explicit-source-document-identity",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE source_documents ADD COLUMN IF NOT EXISTS landing_namespace TEXT;
    ALTER TABLE source_documents ADD COLUMN IF NOT EXISTS document_key TEXT;
    UPDATE source_documents AS document
       SET landing_namespace = CASE
             WHEN strpos(document.doc_id, chr(30)) > 0
               THEN split_part(document.doc_id, chr(30), 1)
             ELSE source.namespace
           END,
           document_key = CASE
             WHEN strpos(document.doc_id, chr(30)) > 0
               THEN substr(document.doc_id, strpos(document.doc_id, chr(30)) + 1)
             ELSE document.doc_id
           END
      FROM sources AS source
     WHERE source.id = document.source_id
       AND (document.landing_namespace IS NULL OR document.document_key IS NULL);
    ALTER TABLE source_documents ALTER COLUMN landing_namespace SET NOT NULL;
    ALTER TABLE source_documents ALTER COLUMN document_key SET NOT NULL;
    ALTER TABLE source_documents DROP CONSTRAINT IF EXISTS source_documents_pkey;
    ALTER TABLE source_documents ADD PRIMARY KEY (source_id, landing_namespace, document_key);
    ALTER TABLE source_documents DROP COLUMN IF EXISTS doc_id;
    CREATE TABLE IF NOT EXISTS source_document_claims (
      source_id         TEXT NOT NULL,
      landing_namespace TEXT NOT NULL,
      document_key      TEXT NOT NULL,
      claim_token       TEXT NOT NULL,
      claimed_at        TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (source_id, landing_namespace, document_key)
    )`;
    },
  },
  {
    version: 15,
    name: "human-bootstrap-invitations",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS auth_bootstrap (
      singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
      token_hash  TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS auth_invitations (
      id          TEXT PRIMARY KEY,
      email       TEXT NOT NULL UNIQUE,
      namespace   TEXT NOT NULL,
      role        TEXT NOT NULL CHECK (role IN ('owner','admin','auditor','member')),
      token_hash  TEXT NOT NULL UNIQUE,
      created_by  TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL,
      expires_at  TIMESTAMPTZ NOT NULL,
      accepted_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_auth_invites_email ON auth_invitations(email);
    CREATE INDEX IF NOT EXISTS idx_auth_invites_expiry ON auth_invitations(expires_at)`;
    },
  },
  {
    version: 16,
    name: "verified-setup-operations",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS teams (
      namespace  TEXT PRIMARY KEY,
      tenant_id  TEXT NOT NULL REFERENCES tenants(id),
      team_id    TEXT NOT NULL,
      name       TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      UNIQUE (tenant_id, team_id)
    );
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS sync_status TEXT NOT NULL DEFAULT 'never_synced';
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS last_sync_error TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS last_sync_started_at TIMESTAMPTZ;
    ALTER TABLE sources ADD CONSTRAINT sources_sync_status_check CHECK (
      sync_status IN ('never_synced','pending','synced','failed')
    );
    CREATE TABLE IF NOT EXISTS setup_operations (
      id                 TEXT PRIMARY KEY,
      idempotency_key    TEXT NOT NULL UNIQUE,
      request_hash       TEXT NOT NULL,
      tenant_id          TEXT NOT NULL REFERENCES tenants(id),
      team_namespace     TEXT NOT NULL REFERENCES teams(namespace),
      source_id          TEXT REFERENCES sources(id),
      badge_key_id       TEXT NOT NULL REFERENCES api_keys(id),
      retriever          TEXT NOT NULL,
      public_url         TEXT NOT NULL,
      status             TEXT NOT NULL CHECK (
        status IN ('source_pending','source_failed','waiting_for_agent','complete')
      ),
      source_status      TEXT NOT NULL CHECK (
        source_status IN ('skipped','pending','synced','failed')
      ),
      source_result      JSONB,
      source_error       TEXT,
      badge_ciphertext   TEXT NOT NULL,
      badge_iv           TEXT NOT NULL,
      badge_tag          TEXT NOT NULL,
      created_at         TIMESTAMPTZ NOT NULL,
      updated_at         TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_setup_operations_tenant ON setup_operations(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_setup_operations_status ON setup_operations(status)`;
    },
  },
  {
    version: 17,
    name: "single-pending-invitation-per-email",
    sql(_embedDim: number): string {
      return `
    DELETE FROM auth_invitations
     WHERE id IN (
       SELECT id FROM (
         SELECT id,
                ROW_NUMBER() OVER (PARTITION BY email ORDER BY created_at DESC, id DESC) AS ordinal
           FROM auth_invitations
       ) AS ranked
       WHERE ordinal > 1
     );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_invites_unique_email
      ON auth_invitations(email)`;
    },
  },
  {
    version: 18,
    name: "encrypted-source-configuration",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_ciphertext TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_iv TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_tag TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_kek_id TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_sha256 TEXT;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS config_state TEXT NOT NULL DEFAULT 'legacy_plaintext';
    ALTER TABLE sources ADD CONSTRAINT sources_config_state_check CHECK (
      config_state IN ('legacy_plaintext','encrypted','quarantined')
    );
    CREATE INDEX IF NOT EXISTS idx_sources_config_state ON sources(config_state)`;
    },
  },
  {
    version: 19,
    name: "logical-knowledge-and-pins",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS knowledge_concepts (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      slug TEXT NOT NULL,
      title TEXT NOT NULL,
      current_version_id TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, slug)
    );
    CREATE TABLE IF NOT EXISTS knowledge_versions (
      id TEXT PRIMARY KEY,
      concept_id TEXT NOT NULL REFERENCES knowledge_concepts(id),
      path TEXT NOT NULL UNIQUE,
      version INTEGER NOT NULL CHECK (version > 0),
      supersedes_version_id TEXT REFERENCES knowledge_versions(id),
      content_hash TEXT NOT NULL,
      proposal_id TEXT,
      state TEXT NOT NULL CHECK (state IN ('publishing','published','archived')),
      published_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL,
      UNIQUE (concept_id, version)
    );
    CREATE TABLE IF NOT EXISTS memory_pins (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      target_kind TEXT NOT NULL CHECK (target_kind IN ('memory','concept')),
      target_ref TEXT NOT NULL,
      source TEXT NOT NULL CHECK (source IN ('manual','movement','migration')),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      released_by TEXT,
      released_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_pins_active_target
      ON memory_pins(namespace, target_kind, target_ref) WHERE released_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_memory_pins_active_namespace
      ON memory_pins(namespace, created_at) WHERE released_at IS NULL`;
    },
  },
  {
    version: 20,
    name: "consolidation-and-movement",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS consolidation_runs (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      window_start TIMESTAMPTZ NOT NULL,
      window_end TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending','running','complete','failed','degraded')),
      lease_until TIMESTAMPTZ,
      metrics JSONB NOT NULL DEFAULT '{}',
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS knowledge_proposals (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL REFERENCES consolidation_runs(id),
      namespace TEXT NOT NULL,
      concept_id TEXT REFERENCES knowledge_concepts(id),
      base_version_id TEXT REFERENCES knowledge_versions(id),
      draft_ciphertext TEXT NOT NULL,
      draft_iv TEXT NOT NULL,
      draft_tag TEXT NOT NULL,
      draft_kek_id TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      confidence REAL NOT NULL,
      evidence_ids JSONB NOT NULL DEFAULT '[]',
      source_session_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL CHECK (status IN ('pending_review','publishing','published','rejected')),
      row_version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_knowledge_proposals_queue
      ON knowledge_proposals(namespace, status, created_at);
    CREATE TABLE IF NOT EXISTS proposal_decisions (
      id TEXT PRIMARY KEY,
      proposal_id TEXT NOT NULL REFERENCES knowledge_proposals(id),
      actor TEXT NOT NULL,
      action TEXT NOT NULL CHECK (action IN ('approve','edit_approve','reject')),
      edited BOOLEAN NOT NULL,
      reason TEXT,
      content_hash TEXT NOT NULL,
      ts TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS movement_actions (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      action TEXT NOT NULL CHECK (action IN ('promote_pin','propose_cold','materialize_warm','archive_warm')),
      target_ref TEXT NOT NULL,
      idempotency_key TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL CHECK (status IN ('pending','running','complete','failed','degraded')),
      lease_until TIMESTAMPTZ,
      result JSONB,
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 21,
    name: "shared-segments-and-cow",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS memory_segments (
      id TEXT PRIMARY KEY,
      owner_namespace TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS segment_members (
      id TEXT PRIMARY KEY,
      segment_id TEXT NOT NULL REFERENCES memory_segments(id),
      target_kind TEXT NOT NULL CHECK (target_kind IN ('memory','concept')),
      target_ref TEXT NOT NULL,
      added_at TIMESTAMPTZ NOT NULL,
      removed_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_segment_members_active
      ON segment_members(segment_id, target_kind, target_ref) WHERE removed_at IS NULL;
    CREATE TABLE IF NOT EXISTS segment_mounts (
      id TEXT PRIMARY KEY,
      segment_id TEXT NOT NULL REFERENCES memory_segments(id),
      target_namespace TEXT NOT NULL,
      access TEXT NOT NULL DEFAULT 'read' CHECK (access = 'read'),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      revoked_by TEXT,
      revoked_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_segment_mounts_active
      ON segment_mounts(segment_id, target_namespace) WHERE revoked_at IS NULL;
    CREATE TABLE IF NOT EXISTS memory_forks (
      id TEXT PRIMARY KEY,
      origin_kind TEXT NOT NULL CHECK (origin_kind IN ('memory','concept')),
      origin_ref TEXT NOT NULL,
      target_memory_id TEXT NOT NULL REFERENCES memory_objects(id),
      target_namespace TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 22,
    name: "tenant-scoped-movement-idempotency",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE movement_actions
      DROP CONSTRAINT IF EXISTS movement_actions_idempotency_key_key;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_movement_actions_namespace_idempotency
      ON movement_actions(namespace, idempotency_key)`;
    },
  },
  {
    version: 23,
    name: "warm-mirror-ops",
    // R6 (halomem-warmstore/v1): durable outbox for external warm-store
    // mirrors. Rows carry ONLY ids/namespaces — never content — so a failed
    // mirror op can not become a second PII copy; flush re-reads the canonical
    // row at send time. Op order per store is enforced by the manager
    // (purge_namespace → purge → invalidate → upsert, then created_at).
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS warm_mirror_ops (
      id         TEXT PRIMARY KEY,
      store      TEXT NOT NULL,
      op         TEXT NOT NULL CHECK (op IN ('upsert','invalidate','purge','purge_namespace')),
      ref        TEXT NOT NULL,
      namespace  TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      attempts   INTEGER NOT NULL DEFAULT 0,
      last_error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_warm_ops_store ON warm_mirror_ops(store, created_at)`;
    },
  },
  {
    version: 24,
    name: "trust-disputes",
    // Trust-ranked supersedence: a write whose provenance source underranks the
    // incumbent's lands with status 'disputed' (invisible to every read path)
    // and an open fact_disputes row for the human conflict-review queue.
    // ON DELETE CASCADE on both memory columns: mem.forget hard-deletes
    // memory_objects rows, and the dispute record must never block erasure.
    sql(_embedDim: number): string {
      return `
    ALTER TABLE memory_objects DROP CONSTRAINT IF EXISTS memory_objects_status_check;
    ALTER TABLE memory_objects ADD CONSTRAINT memory_objects_status_check
      CHECK (status IN ('active','archived','tombstoned','disputed'));
    CREATE TABLE IF NOT EXISTS fact_disputes (
      id                   TEXT PRIMARY KEY,
      namespace            TEXT NOT NULL,
      memory_id            TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      disputed_against     TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      category             TEXT NOT NULL CHECK (category IN ('policies-legal','order-management','product-info','other')),
      reason               TEXT NOT NULL,
      status               TEXT NOT NULL CHECK (status IN ('open','resolved')),
      resolution           TEXT CHECK (resolution IN ('uphold-new','keep-old','edit','retracted')),
      resolution_memory_id TEXT,
      resolved_by          TEXT,
      resolved_at          TIMESTAMPTZ,
      row_version          INTEGER NOT NULL DEFAULT 1,
      created_at           TIMESTAMPTZ NOT NULL,
      updated_at           TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_fact_disputes_queue
      ON fact_disputes(namespace, status, created_at);
    CREATE INDEX IF NOT EXISTS idx_fact_disputes_incumbent
      ON fact_disputes(disputed_against) WHERE status = 'open'`;
    },
  },
  {
    version: 25,
    name: "pointer-probe-index",
    // M6 (D11): mem_fault's L4 dispatch runs a cheap "does this subtree have
    // any pointer fact?" existence probe before paying for a metered query
    // embed + pointer vector scan. Pointer rows are a tiny minority of
    // memory_objects, so a partial index keeps the probe (and the type-filtered
    // pointer search) off the main table scan.
    sql(_embedDim: number): string {
      return `
    CREATE INDEX IF NOT EXISTS idx_mem_pointer_ns
      ON memory_objects(namespace, status) WHERE type = 'pointer'`;
    },
  },
  {
    version: 26,
    name: "model-runtime",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS model_connections (
      id                    TEXT PRIMARY KEY,
      namespace             TEXT NOT NULL,
      name                  TEXT NOT NULL,
      provider              TEXT NOT NULL CHECK (provider IN ('anthropic','openai-compatible')),
      base_url              TEXT NOT NULL,
      credential_ciphertext TEXT,
      credential_iv         TEXT,
      credential_tag        TEXT,
      credential_kek_id     TEXT,
      credential_sha256     TEXT,
      credential_state      TEXT NOT NULL CHECK (credential_state IN ('encrypted','none','revoked')),
      status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      created_by            TEXT NOT NULL,
      created_at            TIMESTAMPTZ NOT NULL,
      updated_at            TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, name),
      CHECK (
        (credential_state = 'encrypted'
          AND credential_ciphertext IS NOT NULL
          AND credential_iv IS NOT NULL
          AND credential_tag IS NOT NULL
          AND credential_kek_id IS NOT NULL
          AND credential_sha256 IS NOT NULL)
        OR
        (credential_state IN ('none','revoked')
          AND credential_ciphertext IS NULL
          AND credential_iv IS NULL
          AND credential_tag IS NULL
          AND credential_kek_id IS NULL
          AND credential_sha256 IS NULL)
      )
    );
    CREATE INDEX IF NOT EXISTS idx_model_connections_namespace
      ON model_connections(namespace, status, created_at);

    CREATE TABLE IF NOT EXISTS model_profiles (
      id                TEXT PRIMARY KEY,
      namespace         TEXT NOT NULL,
      name              TEXT NOT NULL,
      connection_id     TEXT NOT NULL REFERENCES model_connections(id),
      model             TEXT NOT NULL,
      temperature       REAL NOT NULL DEFAULT 0.2 CHECK (temperature >= 0 AND temperature <= 2),
      max_output_tokens INTEGER NOT NULL DEFAULT 1024 CHECK (max_output_tokens > 0 AND max_output_tokens <= 4096),
      is_default        BOOLEAN NOT NULL DEFAULT FALSE,
      status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','deleted')),
      created_at        TIMESTAMPTZ NOT NULL,
      updated_at        TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, name)
    );
    CREATE INDEX IF NOT EXISTS idx_model_profiles_visible
      ON model_profiles(namespace, status, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_model_profiles_one_default
      ON model_profiles(namespace) WHERE is_default = TRUE AND status = 'active'`;
    },
  },
  {
    version: 27,
    name: "active-model-name-uniqueness",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE model_connections
      DROP CONSTRAINT IF EXISTS model_connections_namespace_name_key;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_model_connections_active_name
      ON model_connections(namespace, name) WHERE status = 'active';
    ALTER TABLE model_profiles
      DROP CONSTRAINT IF EXISTS model_profiles_namespace_name_key;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_model_profiles_active_name
      ON model_profiles(namespace, name) WHERE status = 'active'`;
    },
  },
  {
    version: 28,
    name: "enterprise-production-hardening",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS classification JSONB NOT NULL
      DEFAULT '{"sensitivity":"internal","piiSubjects":[],"secretKinds":[],"allowedDestinations":[]}';
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS source_access JSONB NOT NULL
      DEFAULT '{"principals":[],"groups":[]}';
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS source_principals JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS source_groups JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE warm_mirror_ops ADD COLUMN IF NOT EXISTS lease_owner TEXT;
    ALTER TABLE warm_mirror_ops ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS warm_store_leases (
      store TEXT PRIMARY KEY,
      lease_owner TEXT NOT NULL,
      lease_expires_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT 'active';
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS sync_interval_seconds INTEGER;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS next_sync_at TIMESTAMPTZ;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sources ADD CONSTRAINT sources_lifecycle_state_check
      CHECK (lifecycle_state IN ('active','paused','disabled'));
    ALTER TABLE sources ADD CONSTRAINT sources_sync_interval_check
      CHECK (sync_interval_seconds IS NULL OR sync_interval_seconds >= 60);
    CREATE TABLE IF NOT EXISTS connector_cursors (
      source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
      cursor_value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS durable_jobs (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('write','live-query','source-sync','movement')),
      namespace TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued','running','done','failed')),
      payload JSONB NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      available_at TIMESTAMPTZ NOT NULL,
      lease_owner TEXT,
      lease_expires_at TIMESTAMPTZ,
      last_error TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_durable_jobs_claim
      ON durable_jobs(state, available_at, lease_expires_at, created_at);
    CREATE INDEX IF NOT EXISTS idx_durable_jobs_namespace
      ON durable_jobs(namespace, kind, created_at);
    CREATE TABLE IF NOT EXISTS durable_rate_limits (
      bucket_key TEXT PRIMARY KEY,
      window_started_at TIMESTAMPTZ NOT NULL,
      window_ends_at TIMESTAMPTZ NOT NULL,
      request_count INTEGER NOT NULL CHECK (request_count >= 0),
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_durable_rate_limits_expiry
      ON durable_rate_limits(window_ends_at);
    CREATE TABLE IF NOT EXISTS durable_tickets (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('write','live-query')),
      namespace TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('running','done','failed')),
      result JSONB,
      error TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_durable_tickets_expiry
      ON durable_tickets(expires_at);
    CREATE TABLE IF NOT EXISTS oidc_identities (
      issuer TEXT NOT NULL,
      subject TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      namespace TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner','admin','auditor','member')),
      email TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (issuer, subject)
    );
    CREATE TABLE IF NOT EXISTS scim_groups (
      id TEXT PRIMARY KEY,
      tenant_namespace TEXT NOT NULL,
      external_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      UNIQUE (tenant_namespace, external_id)
    );
    CREATE TABLE IF NOT EXISTS scim_users (
      external_id TEXT NOT NULL,
      tenant_namespace TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      updated_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (external_id, tenant_namespace)
    );
    CREATE TABLE IF NOT EXISTS scim_group_members (
      group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (group_id, user_id)
    );
    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT;
    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS event_hash TEXT;
    CREATE TABLE IF NOT EXISTS audit_chain_state (
      singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
      head_hash TEXT,
      updated_at TIMESTAMPTZ NOT NULL
    );
    INSERT INTO audit_chain_state (singleton, head_hash, updated_at)
      VALUES (TRUE, NULL, CURRENT_TIMESTAMP) ON CONFLICT (singleton) DO NOTHING;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_event_hash
      ON audit_log(event_hash) WHERE event_hash IS NOT NULL`;
    },
  },
  {
    version: 29,
    name: "agent-connection-grants",
    // M8/D24: immutable, badge-bound authority snapshots. The store may only
    // create a new row or revoke an active row; changing authority mints a new
    // id/policy version instead of updating this snapshot in place.
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS agent_connection_grants (
      id                 TEXT PRIMARY KEY,
      key_id             TEXT NOT NULL REFERENCES api_keys(id),
      namespace          TEXT NOT NULL,
      connector_id       TEXT NOT NULL,
      allowed_operations JSONB NOT NULL CHECK (jsonb_typeof(allowed_operations) = 'array'),
      allowed_source_refs JSONB NOT NULL CHECK (jsonb_typeof(allowed_source_refs) = 'array'),
      allowed_fields     JSONB NOT NULL CHECK (jsonb_typeof(allowed_fields) = 'object'),
      allowed_purposes   JSONB NOT NULL CHECK (jsonb_typeof(allowed_purposes) = 'array'),
      max_sensitivity    TEXT NOT NULL
        CHECK (max_sensitivity IN ('public','internal','confidential','restricted')),
      max_rows           INTEGER NOT NULL CHECK (max_rows > 0 AND max_rows <= 1000),
      max_bytes          INTEGER NOT NULL CHECK (max_bytes > 0 AND max_bytes <= 10485760),
      policy_version     INTEGER NOT NULL CHECK (policy_version > 0),
      status             TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','revoked')),
      expires_at         TIMESTAMPTZ,
      created_at         TIMESTAMPTZ NOT NULL,
      revoked_at         TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_agent_grants_key
      ON agent_connection_grants(key_id, status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_agent_grants_namespace
      ON agent_connection_grants(namespace, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_grants_one_active
      ON agent_connection_grants(key_id, connector_id) WHERE status = 'active'`;
    },
  },
  {
    version: 30,
    name: "model-hosting-source-classification",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE model_connections
      ADD COLUMN IF NOT EXISTS hosting_type TEXT NOT NULL DEFAULT 'unclassified';
    ALTER TABLE model_connections
      ADD COLUMN IF NOT EXISTS model_source TEXT NOT NULL DEFAULT 'unclassified';
    ALTER TABLE model_connections
      DROP CONSTRAINT IF EXISTS model_connections_hosting_type_check;
    ALTER TABLE model_connections
      ADD CONSTRAINT model_connections_hosting_type_check
      CHECK (hosting_type IN ('provider-hosted','enterprise-hosted','unclassified'));
    ALTER TABLE model_connections
      DROP CONSTRAINT IF EXISTS model_connections_model_source_check;
    ALTER TABLE model_connections
      ADD CONSTRAINT model_connections_model_source_check
      CHECK (model_source IN ('proprietary','open-source','mixed','unclassified'))`;
    },
  },
  {
    version: 31,
    name: "platform-source-catalog-and-credentials",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE sources DROP CONSTRAINT IF EXISTS sources_kind_check;
    ALTER TABLE sources ADD CONSTRAINT sources_kind_check
      CHECK (kind ~ '^[a-z0-9_-]+$');
    CREATE TABLE IF NOT EXISTS source_credentials (
      id                TEXT PRIMARY KEY,
      namespace         TEXT NOT NULL,
      connector_id      TEXT NOT NULL CHECK (connector_id ~ '^[a-z0-9_]+$'),
      connection_key    TEXT NOT NULL CHECK (connection_key ~ '^[a-z0-9_]+$'),
      name              TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
      config            JSONB NOT NULL DEFAULT '{}',
      config_ciphertext TEXT NOT NULL,
      config_iv         TEXT NOT NULL,
      config_tag        TEXT NOT NULL,
      config_kek_id     TEXT NOT NULL,
      config_sha256     TEXT NOT NULL,
      config_state      TEXT NOT NULL DEFAULT 'encrypted'
        CHECK (config_state IN ('encrypted','quarantined')),
      created_at        TIMESTAMPTZ NOT NULL,
      updated_at        TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, connection_key, name)
    );
    CREATE INDEX IF NOT EXISTS idx_source_credentials_namespace
      ON source_credentials(namespace, connection_key, created_at);
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS credential_id TEXT
      REFERENCES source_credentials(id)`;
    },
  },
  {
    version: 32,
    name: "source-ingress-hardening",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS source_webhook_receipts (
      source_id      TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
      request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
      received_at    TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (source_id, request_digest)
    );
    CREATE INDEX IF NOT EXISTS idx_source_webhook_receipts_expiry
      ON source_webhook_receipts(received_at);
    UPDATE sources SET config_sha256 = CASE
      WHEN config_state = 'encrypted' THEN 'gcm-v1' ELSE 'destroyed-v1' END
      WHERE config_sha256 IS NOT NULL;
    UPDATE source_credentials SET config_sha256 = CASE
      WHEN config_state = 'encrypted' THEN 'gcm-v1' ELSE 'destroyed-v1' END`;
    },
  },
  {
    version: 33,
    name: "nango-proxy-connections",
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS nango_environment_capacity (
      singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
      updated_at TIMESTAMPTZ NOT NULL
    );
    INSERT INTO nango_environment_capacity (singleton, updated_at)
      VALUES (TRUE, CURRENT_TIMESTAMP) ON CONFLICT (singleton) DO NOTHING;
    ALTER TABLE source_credentials
      ADD COLUMN IF NOT EXISTS external_ref_sha256 TEXT CHECK (
        external_ref_sha256 IS NULL OR external_ref_sha256 ~ '^[0-9a-f]{64}$'
      );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_source_credentials_external_ref
      ON source_credentials(external_ref_sha256)
      WHERE external_ref_sha256 IS NOT NULL;
    ALTER TABLE sources ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_sources_idempotency
      ON sources(namespace, idempotency_key)
      WHERE idempotency_key IS NOT NULL;
    CREATE TABLE IF NOT EXISTS nango_connect_attempts (
      attempt_id               TEXT PRIMARY KEY,
      namespace                TEXT NOT NULL,
      connector_id             TEXT NOT NULL CHECK (connector_id ~ '^[a-z0-9_]+$'),
      connection_key           TEXT NOT NULL CHECK (connection_key ~ '^[a-z0-9_]+$'),
      integration_id           TEXT NOT NULL CHECK (integration_id ~ '^[a-z0-9_-]+$'),
      name                     TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
      status                   TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','completed','expired','failed')),
      credential_id            TEXT,
      external_connection_hash TEXT CHECK (
        external_connection_hash IS NULL OR external_connection_hash ~ '^[0-9a-f]{64}$'
      ),
      expires_at               TIMESTAMPTZ NOT NULL,
      created_at               TIMESTAMPTZ NOT NULL,
      updated_at               TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nango_attempts_pending
      ON nango_connect_attempts(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_nango_attempts_namespace
      ON nango_connect_attempts(namespace, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_nango_external_connection
      ON nango_connect_attempts(external_connection_hash)
      WHERE external_connection_hash IS NOT NULL`;
    },
  },
  {
    version: 34,
    name: "nango-capacity-reconciliation",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE nango_environment_capacity
      ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE nango_connect_attempts
      ADD COLUMN IF NOT EXISTS organization_tag TEXT CHECK (
        organization_tag IS NULL OR length(organization_tag) BETWEEN 1 AND 256
      )`;
    },
  },
  {
    version: 35,
    name: "policy-documents",
    // S4 policy library: immutable file-level operational metadata. Raw file
    // content and extracted facts continue through the governed write path and
    // are deliberately absent from this table.
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS policy_documents (
      id             TEXT PRIMARY KEY,
      source_id      TEXT NOT NULL REFERENCES sources(id),
      namespace      TEXT NOT NULL,
      title          TEXT NOT NULL,
      kind           TEXT NOT NULL CHECK (
        kind IN ('policy','guideline','procedure','standard','handbook','other')
      ),
      status         TEXT NOT NULL CHECK (
        status IN ('processing','active','needs_review','failed')
      ),
      file_name      TEXT NOT NULL,
      media_type     TEXT NOT NULL,
      byte_size      INTEGER NOT NULL CHECK (
        byte_size > 0 AND byte_size <= 524288
      ),
      content_sha256 TEXT NOT NULL CHECK (
        content_sha256 ~ '^[0-9a-f]{64}$'
      ),
      attempt_token  TEXT NOT NULL,
      lease_expires_at TIMESTAMPTZ NOT NULL,
      fact_count     INTEGER NOT NULL DEFAULT 0 CHECK (fact_count >= 0),
      failure_code   TEXT,
      created_by     TEXT NOT NULL,
      created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      loaded_at      TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_policy_documents_namespace_created
      ON policy_documents(namespace, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_policy_documents_title
      ON policy_documents(namespace, lower(title));
    CREATE INDEX IF NOT EXISTS idx_policy_documents_file_name
      ON policy_documents(namespace, lower(file_name));
    CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_documents_active_content
      ON policy_documents(namespace, content_sha256)
      WHERE status IN ('processing','active','needs_review');
    CREATE INDEX IF NOT EXISTS idx_policy_documents_processing_lease
      ON policy_documents(lease_expires_at)
      WHERE status = 'processing';
    CREATE TABLE IF NOT EXISTS policy_document_quota_usage (
      tenant_root       TEXT PRIMARY KEY,
      current_documents INTEGER NOT NULL DEFAULT 0 CHECK (current_documents >= 0),
      current_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (current_bytes >= 0),
      total_rows        BIGINT NOT NULL DEFAULT 0 CHECK (total_rows >= 0),
      updated_at        TIMESTAMPTZ NOT NULL
    )`;
    },
  },
  {
    version: 36,
    name: "agent-access-oversight",
    sql(_embedDim: number): string {
      return `
    ALTER TABLE agent_connection_grants
      ADD COLUMN IF NOT EXISTS oversight JSONB NOT NULL DEFAULT
      '{"maxRequestsPerMinute":60,"usageAlertThreshold":100,"deniedAlertThreshold":1,"recipientRoles":["owner","admin"],"accessRequests":"allowed","approvalTtlSeconds":3600}';
    CREATE TABLE IF NOT EXISTS agent_access_events (
      id TEXT PRIMARY KEY,
      grant_id TEXT,
      key_id TEXT NOT NULL,
      namespace TEXT NOT NULL,
      connector_id TEXT NOT NULL,
      source_ref TEXT NOT NULL,
      operation TEXT NOT NULL,
      purpose TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('allowed','denied','error')),
      reason_code TEXT NOT NULL,
      rows_count INTEGER NOT NULL DEFAULT 0 CHECK (rows_count >= 0),
      bytes_count INTEGER NOT NULL DEFAULT 0 CHECK (bytes_count >= 0),
      policy_version INTEGER,
      access_request_id TEXT,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_agent_access_events_namespace_time
      ON agent_access_events(namespace, created_at);
    CREATE INDEX IF NOT EXISTS idx_agent_access_events_key_time
      ON agent_access_events(key_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_agent_access_events_grant_time
      ON agent_access_events(grant_id, created_at);
    CREATE TABLE IF NOT EXISTS agent_access_alerts (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL REFERENCES agent_access_events(id),
      grant_id TEXT,
      key_id TEXT NOT NULL,
      namespace TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (
        kind IN (
          'outside-scope','rate-limit','usage-threshold','authority-change',
          'repeated-denial'
        )
      ),
      severity TEXT NOT NULL CHECK (severity IN ('warning','critical')),
      recipient_roles JSONB NOT NULL CHECK (jsonb_typeof(recipient_roles) = 'array'),
      status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','acknowledged','resolved')),
      dedupe_key TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      acknowledged_at TIMESTAMPTZ,
      acknowledged_by TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_alerts_open_dedupe
      ON agent_access_alerts(dedupe_key) WHERE status = 'open';
    CREATE INDEX IF NOT EXISTS idx_agent_access_alerts_namespace_time
      ON agent_access_alerts(namespace, status, created_at);
    CREATE INDEX IF NOT EXISTS idx_agent_access_alerts_key_time
      ON agent_access_alerts(key_id, created_at);
    CREATE TABLE IF NOT EXISTS agent_access_requests (
      id TEXT PRIMARY KEY,
      key_id TEXT NOT NULL REFERENCES api_keys(id),
      namespace TEXT NOT NULL,
      grant_id TEXT NOT NULL REFERENCES agent_connection_grants(id),
      connector_id TEXT NOT NULL,
      source_ref TEXT NOT NULL,
      operation TEXT NOT NULL CHECK (operation = 'source-read'),
      purpose TEXT NOT NULL,
      requested_fields JSONB NOT NULL CHECK (jsonb_typeof(requested_fields) = 'array'),
      requested_rows INTEGER NOT NULL
        CHECK (requested_rows > 0 AND requested_rows <= 1000),
      requested_bytes INTEGER NOT NULL
        CHECK (requested_bytes > 0 AND requested_bytes <= 10485760),
      justification TEXT NOT NULL,
      requested_duration_seconds INTEGER NOT NULL
        CHECK (requested_duration_seconds BETWEEN 60 AND 86400),
      status TEXT NOT NULL
        CHECK (status IN ('pending','approved','denied','expired','consumed')),
      approved_until TIMESTAMPTZ,
      max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 100),
      used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      decided_at TIMESTAMPTZ,
      decided_by TEXT,
      decision_note TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_agent_access_requests_namespace_time
      ON agent_access_requests(namespace, status, created_at);
    CREATE INDEX IF NOT EXISTS idx_agent_access_requests_key_time
      ON agent_access_requests(key_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_agent_access_requests_grant_time
      ON agent_access_requests(grant_id, created_at)`;
    },
  },
  {
    version: 37,
    name: "org-teams-and-membership",
    sql(): string {
      // `teams` (migration 016) is the setup wizard's tenant-bootstrap record;
      // the console's governed team directory is a separate table.
      return `
    CREATE TABLE IF NOT EXISTS org_teams (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS org_team_members (
      team_id TEXT NOT NULL REFERENCES org_teams(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      added_by TEXT NOT NULL,
      added_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (team_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_org_team_members_user ON org_team_members(user_id)`;
    },
  },
  {
    version: 38,
    name: "mintlify-parity-m9",
    // M9 (CONTRACTS-M9-PARITY.md). One migration for the whole milestone, in the
    // single Postgres (D5). Every table carries `namespace` so the ancestor-prefix
    // ACL is applied in the query layer with exact IN(...) lists — never LIKE.
    // Redefinition is supersedence, never an in-place overwrite (D7): rows close
    // their validity (`t_valid_to`) and link to the prior id (`supersedes`).
    //
    // Per table (SQL `--` comments are deliberately absent: splitStatements()
    // splits the bundle on `;`, so prose punctuation inside the SQL would tear a
    // statement in half):
    //  - skills / skill_agent_usage / skill_vetting_runs: the company-wide skill
    //    library. A redefinition closes the incumbent's `t_valid_to` and links
    //    back through `supersedes`; usage is a per-agent per-day rollup; a
    //    vetting run is bound to one exact `content_sha256` and is never
    //    rewritten after it terminates.
    //  - oauth_clients / oauth_tokens (D29): admin-approved clients hold a
    //    sha256 hex digest of their secret and NOTHING else. `oauth_tokens` has
    //    no plaintext column by construction — `token_hash` is sha256(token) hex.
    //    The `client_ref` FK is what makes client revocation transitive.
    //  - answer_outcomes (D31): per-turn correctness. Accuracy is DERIVED from
    //    these rows, never asserted by a caller. A correction supersedes (D7).
    //  - org_automations (D30): recurrence is the durable `not_before` re-arm
    //    read by the new `automation` job kind — never an in-kernel timer.
    //  - credit_balances / credit_ledger: the ledger is the append-only
    //    authority and mirrors the audit discipline (insert only, never update
    //    or delete); the balance row is its single mutable projection.
    //  - usage_alerts: thresholds evaluated on the daily-close durable pass.
    //  - api_keys.caller_class (#15): SERVER-DERIVED at issuance (D9). No
    //    request body may assert it.
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS skills (
      id             TEXT PRIMARY KEY,
      namespace      TEXT NOT NULL,
      skill_key      TEXT NOT NULL CHECK (length(skill_key) BETWEEN 1 AND 200),
      name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
      description    TEXT NOT NULL DEFAULT '',
      definition     TEXT NOT NULL,
      content_sha256 TEXT NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
      source_id      TEXT,
      source_kind    TEXT,
      vetting_status TEXT NOT NULL DEFAULT 'unvetted'
        CHECK (vetting_status IN ('unvetted','vetting','vetted','blocked')),
      safety_score   INTEGER CHECK (safety_score IS NULL OR (safety_score >= 0 AND safety_score <= 100)),
      last_vetted_at TIMESTAMPTZ,
      supersedes     TEXT REFERENCES skills(id),
      t_valid_from   TIMESTAMPTZ NOT NULL,
      t_valid_to     TIMESTAMPTZ,
      status         TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','archived')),
      created_by     TEXT NOT NULL,
      created_at     TIMESTAMPTZ NOT NULL,
      updated_at     TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_skills_current
      ON skills(namespace, skill_key) WHERE t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_skills_namespace
      ON skills(namespace, status, created_at);
    CREATE INDEX IF NOT EXISTS idx_skills_vetting
      ON skills(namespace, vetting_status) WHERE t_valid_to IS NULL;

    CREATE TABLE IF NOT EXISTS skill_agent_usage (
      id              TEXT PRIMARY KEY,
      namespace       TEXT NOT NULL,
      skill_id        TEXT NOT NULL REFERENCES skills(id),
      key_id          TEXT NOT NULL,
      actor           TEXT NOT NULL,
      usage_date      DATE NOT NULL,
      invocations     INTEGER NOT NULL DEFAULT 0 CHECK (invocations >= 0),
      denials         INTEGER NOT NULL DEFAULT 0 CHECK (denials >= 0),
      overrides       INTEGER NOT NULL DEFAULT 0 CHECK (overrides >= 0),
      last_invoked_at TIMESTAMPTZ,
      created_at      TIMESTAMPTZ NOT NULL,
      updated_at      TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_skill_usage_bucket
      ON skill_agent_usage(skill_id, key_id, usage_date);
    CREATE INDEX IF NOT EXISTS idx_skill_usage_namespace
      ON skill_agent_usage(namespace, usage_date);

    CREATE TABLE IF NOT EXISTS skill_vetting_runs (
      id             TEXT PRIMARY KEY,
      namespace      TEXT NOT NULL,
      skill_id       TEXT NOT NULL REFERENCES skills(id),
      content_sha256 TEXT NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
      mode           TEXT NOT NULL CHECK (mode IN ('static','sandbox')),
      status         TEXT NOT NULL
        CHECK (status IN ('running','passed','failed','error')),
      safety_score   INTEGER CHECK (safety_score IS NULL OR (safety_score >= 0 AND safety_score <= 100)),
      findings       JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(findings) = 'array'),
      detail         TEXT,
      ran_by         TEXT NOT NULL,
      started_at     TIMESTAMPTZ NOT NULL,
      finished_at    TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_skill_vetting_skill
      ON skill_vetting_runs(skill_id, started_at);
    CREATE INDEX IF NOT EXISTS idx_skill_vetting_namespace
      ON skill_vetting_runs(namespace, status, started_at);

    CREATE TABLE IF NOT EXISTS oauth_clients (
      id                 TEXT PRIMARY KEY,
      namespace          TEXT NOT NULL,
      client_id          TEXT NOT NULL UNIQUE CHECK (client_id ~ '^[A-Za-z0-9_-]+$'),
      client_secret_hash TEXT NOT NULL CHECK (client_secret_hash ~ '^[0-9a-f]{64}$'),
      name               TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
      description        TEXT NOT NULL DEFAULT '',
      redirect_uris      JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(redirect_uris) = 'array'),
      allowed_tools      JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(allowed_tools) = 'array'),
      token_role         TEXT NOT NULL CHECK (token_role IN ('assistant','read-only')),
      token_ttl_seconds  INTEGER NOT NULL DEFAULT 3600
        CHECK (token_ttl_seconds BETWEEN 60 AND 86400),
      status             TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','revoked')),
      requested_by       TEXT NOT NULL,
      approved_by        TEXT,
      approved_at        TIMESTAMPTZ,
      revoked_by         TEXT,
      revoked_at         TIMESTAMPTZ,
      created_at         TIMESTAMPTZ NOT NULL,
      updated_at         TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_clients_namespace
      ON oauth_clients(namespace, status, created_at);

    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id            TEXT PRIMARY KEY,
      namespace     TEXT NOT NULL,
      client_ref    TEXT NOT NULL REFERENCES oauth_clients(id),
      token_hash    TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
      actor         TEXT NOT NULL,
      token_role    TEXT NOT NULL CHECK (token_role IN ('assistant','read-only')),
      allowed_tools JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(allowed_tools) = 'array'),
      status        TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','revoked')),
      revoked_reason TEXT
        CHECK (revoked_reason IS NULL OR revoked_reason IN ('manual','client-revoked','superseded')),
      issued_at     TIMESTAMPTZ NOT NULL,
      expires_at    TIMESTAMPTZ NOT NULL,
      last_used     TIMESTAMPTZ,
      revoked_at    TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client
      ON oauth_tokens(client_ref, status);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_namespace
      ON oauth_tokens(namespace, issued_at);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expiry
      ON oauth_tokens(expires_at) WHERE status = 'active';

    CREATE TABLE IF NOT EXISTS answer_outcomes (
      id          TEXT PRIMARY KEY,
      namespace   TEXT NOT NULL,
      turn_id     TEXT NOT NULL CHECK (length(turn_id) BETWEEN 1 AND 200),
      session     TEXT,
      actor       TEXT NOT NULL,
      query_sha256 TEXT CHECK (query_sha256 IS NULL OR query_sha256 ~ '^[0-9a-f]{64}$'),
      outcome     TEXT NOT NULL CHECK (
        outcome IN ('answered','weak','disputed','answered-without-human')
      ),
      resolved_by TEXT,
      dispute_id  TEXT REFERENCES fact_disputes(id) ON DELETE SET NULL,
      evidence_ids JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence_ids) = 'array'),
      detail      TEXT,
      supersedes  TEXT REFERENCES answer_outcomes(id),
      t_valid_from TIMESTAMPTZ NOT NULL,
      t_valid_to  TIMESTAMPTZ,
      created_at  TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_answer_outcomes_current
      ON answer_outcomes(namespace, turn_id) WHERE t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_answer_outcomes_rollup
      ON answer_outcomes(namespace, outcome, created_at) WHERE t_valid_to IS NULL;

    CREATE TABLE IF NOT EXISTS org_automations (
      id                   TEXT PRIMARY KEY,
      namespace            TEXT NOT NULL,
      template_id          TEXT NOT NULL CHECK (
        template_id IN (
          'fresh-summaries','weekly-contradictions','fill-gaps',
          're-sync','weekly-digest'
        )
      ),
      enabled              BOOLEAN NOT NULL DEFAULT FALSE,
      auto_approve         BOOLEAN NOT NULL DEFAULT FALSE,
      config               JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object'),
      interval_seconds     INTEGER NOT NULL DEFAULT 604800
        CHECK (interval_seconds >= 3600),
      cursor_value         TEXT,
      not_before           TIMESTAMPTZ,
      last_run_at          TIMESTAMPTZ,
      last_run_status      TEXT CHECK (
        last_run_status IS NULL OR last_run_status IN ('ok','degraded','failed')
      ),
      last_error           TEXT,
      consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
      row_version          INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
      created_by           TEXT NOT NULL,
      created_at           TIMESTAMPTZ NOT NULL,
      updated_at           TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, template_id)
    );
    CREATE INDEX IF NOT EXISTS idx_org_automations_due
      ON org_automations(not_before) WHERE enabled = TRUE;
    CREATE INDEX IF NOT EXISTS idx_org_automations_namespace
      ON org_automations(namespace, enabled, created_at);
    ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
    ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check
      CHECK (kind IN ('write','live-query','source-sync','movement','automation'));

    CREATE TABLE IF NOT EXISTS credit_balances (
      namespace         TEXT PRIMARY KEY,
      balance_credits   BIGINT NOT NULL DEFAULT 0 CHECK (balance_credits >= 0),
      lifetime_granted  BIGINT NOT NULL DEFAULT 0 CHECK (lifetime_granted >= 0),
      lifetime_debited  BIGINT NOT NULL DEFAULT 0 CHECK (lifetime_debited >= 0),
      trial_granted_at  TIMESTAMPTZ,
      row_version       INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
      created_at        TIMESTAMPTZ NOT NULL,
      updated_at        TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credit_ledger (
      id              TEXT PRIMARY KEY,
      namespace       TEXT NOT NULL,
      direction       TEXT NOT NULL CHECK (direction IN ('debit','credit')),
      feature         TEXT NOT NULL CHECK (
        feature IN (
          'message_out','automation_run','distill_run','export_run',
          'trial_grant','manual_grant'
        )
      ),
      amount          BIGINT NOT NULL CHECK (amount > 0),
      balance_after   BIGINT NOT NULL CHECK (balance_after >= 0),
      actor           TEXT NOT NULL,
      reason          TEXT,
      idempotency_key TEXT,
      ts              TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_credit_ledger_namespace_ts
      ON credit_ledger(namespace, ts);
    CREATE INDEX IF NOT EXISTS idx_credit_ledger_feature
      ON credit_ledger(namespace, feature, ts);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_ledger_idempotency
      ON credit_ledger(namespace, idempotency_key) WHERE idempotency_key IS NOT NULL;

    CREATE TABLE IF NOT EXISTS usage_alerts (
      id               TEXT PRIMARY KEY,
      namespace        TEXT NOT NULL,
      kind             TEXT NOT NULL CHECK (kind IN ('usage-threshold','low-balance')),
      threshold_unit   TEXT NOT NULL CHECK (threshold_unit IN ('percent','credits')),
      threshold_value  BIGINT NOT NULL CHECK (threshold_value > 0),
      enabled          BOOLEAN NOT NULL DEFAULT TRUE,
      recipient_roles  JSONB NOT NULL DEFAULT '["owner","admin"]'
        CHECK (jsonb_typeof(recipient_roles) = 'array'),
      last_fired_at    TIMESTAMPTZ,
      last_fired_value BIGINT,
      fire_count       INTEGER NOT NULL DEFAULT 0 CHECK (fire_count >= 0),
      created_by       TEXT NOT NULL,
      created_at       TIMESTAMPTZ NOT NULL,
      updated_at       TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, kind, threshold_unit, threshold_value)
    );
    CREATE INDEX IF NOT EXISTS idx_usage_alerts_namespace
      ON usage_alerts(namespace, enabled, kind);

    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS caller_class TEXT NOT NULL
      DEFAULT 'unclassified';
    ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_caller_class_check;
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_caller_class_check
      CHECK (caller_class IN ('internal','external','unclassified'));
    CREATE INDEX IF NOT EXISTS idx_api_keys_caller_class
      ON api_keys(namespace, caller_class, status)`;
    },
  },
  {
    version: 39,
    name: "m9-wave3-usage-job-kinds",
    // M9 Wave 3 (CONTRACTS-M9-PARITY.md addenda). Two new durable job kinds,
    // both the same notBefore re-arm discipline as `automation` (E36 — never
    // an in-kernel timer):
    //  - usage-close: the daily usage-alert close pass (E53). Deterministic id
    //    per UTC close day; re-arms for the next close atomically with the
    //    pass-summary audit row.
    //  - usage-emit: delivery of committed credit_ledger events to the
    //    EXTERNAL billing program (E54). The kernel ledger is an enforcement
    //    cache, never the billing source of truth; jobs are deduped on the
    //    ledger entry ULID and brown out when no endpoint is configured.
    sql(_embedDim: number): string {
      return `
    ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
    ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check
      CHECK (kind IN ('write','live-query','source-sync','movement','automation','usage-close','usage-emit'))`;
    },
  },
  {
    version: 40,
    name: "skill-approval-workflow",
    // S16 skill approval workflow (CONTRACTS-M9-PARITY.md addendum). Member
    // submissions land `pending` and stay invisible to agent invocation until
    // an owner/admin over the namespace subtree approves; owner/admin
    // registrations self-approve. `pending|approved|rejected` is lifecycle
    // state on the CURRENT row — definition content still never updates in
    // place (D7). Default 'approved' preserves the semantics of every row
    // registered before this migration (all were owner/admin). ALTER only,
    // no new table — the post-M9 RLS-on-CREATE convention does not apply.
    sql(_embedDim: number): string {
      return `
    ALTER TABLE skills
      ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved'
        CHECK (approval_status IN ('pending','approved','rejected')),
      ADD COLUMN IF NOT EXISTS approved_by TEXT,
      ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS idx_skills_approval
      ON skills(namespace, approval_status) WHERE t_valid_to IS NULL`;
    },
  },
  {
    version: 41,
    name: "skill-vetting-v2",
    // S16 vetting v2 (CONTRACTS-S16-VETTING-V2.md, D32–D35). The vetting
    // pipeline gains three lanes — `llm` (Azure OpenAI scan), `cisco` and
    // `skillspector` (pinned external scanners) — alongside the v1
    // `static`/`sandbox` fallback. `mode` widens accordingly (text column,
    // constraint swap only) and every v2 run stamps `engine_versions` at
    // finalize so a rules/model upgrade is a deliberate image rebuild and
    // stale runs stay queryable (`skills sweep --stale-engines`). ALTER only,
    // no new table — the post-M9 RLS-on-CREATE convention does not apply.
    sql(_embedDim: number): string {
      return `
    ALTER TABLE skill_vetting_runs DROP CONSTRAINT IF EXISTS skill_vetting_runs_mode_check;
    ALTER TABLE skill_vetting_runs ADD CONSTRAINT skill_vetting_runs_mode_check
      CHECK (mode IN ('static','sandbox','llm','cisco','skillspector'));
    ALTER TABLE skill_vetting_runs ADD COLUMN IF NOT EXISTS engine_versions TEXT`;
    },
  },
  {
    version: 42,
    name: "user-external-identities",
    // GitHub OAuth console login + Profile account linking. The link table is
    // the ONLY thing that joins an external provider identity to a kernel
    // `users` row — email match alone never merges accounts. UNIQUE(provider,
    // provider_account_id) makes a GitHub account resolve to at most one user;
    // UNIQUE(user_id, provider) caps one GitHub connection per user. RLS is
    // enabled per the post-M9 CREATE TABLE convention (Supabase-hosted
    // deployments must not re-expose the table to the PostgREST anon key).
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS user_external_identities (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      provider TEXT NOT NULL CHECK (provider IN ('github')),
      provider_account_id TEXT NOT NULL,
      login TEXT NOT NULL,
      email TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      UNIQUE (provider, provider_account_id),
      UNIQUE (user_id, provider)
    );
    CREATE INDEX IF NOT EXISTS idx_user_external_identities_user
      ON user_external_identities(user_id);
    ALTER TABLE user_external_identities ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 43,
    name: "auth-signup-sessions",
    // Short-lived, verified-email capability for self-service organization
    // creation. Only SHA-256 token digests are stored; the raw authority stays
    // in an HttpOnly cookie. UNIQUE(email) makes re-issuance rotate prior
    // authority. RLS follows the post-M9 CREATE TABLE convention.
    sql(_embedDim: number): string {
      return `
    CREATE TABLE IF NOT EXISTS auth_signup_sessions (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_auth_signup_sessions_expiry
      ON auth_signup_sessions(expires_at);
    ALTER TABLE auth_signup_sessions ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 44,
    name: "company-knowledge-graph",
    // Governed company-file register and derived L2 graph metadata. Upload
    // attempts and file rows deliberately retain hashes and operational
    // metadata only: raw file content continues through the D10 write path.
    // Versioned semantic rows follow D7 (`supersedes` + validity interval),
    // while relationship evidence is an insert-only evidence ledger with no
    // mutable projection columns. Every table enables RLS per the post-M9
    // Supabase hardening convention.
    sql(_embedDim: number): string {
      return `
    ALTER TABLE sources
      ADD COLUMN IF NOT EXISTS primary_business_function TEXT NOT NULL DEFAULT 'General';
    ALTER TABLE sources
      ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
    ALTER TABLE sources
      ADD COLUMN IF NOT EXISTS data_sensitive BOOLEAN NOT NULL DEFAULT FALSE;

    CREATE TABLE IF NOT EXISTS knowledge_bases (
      id                        TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace                 TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      target_team_id            TEXT REFERENCES org_teams(id) ON DELETE SET NULL,
      name                      TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
      kind                      TEXT NOT NULL CHECK (kind IN ('file','folder','url')),
      status                    TEXT NOT NULL CHECK (
        status IN ('empty','processing','ready','needs_review','failed')
      ),
      lifecycle_state           TEXT NOT NULL CHECK (
        lifecycle_state IN ('active','paused','archived')
      ),
      source_id                 TEXT REFERENCES sources(id),
      primary_business_function TEXT NOT NULL CHECK (
        length(primary_business_function) BETWEEN 1 AND 120
      ),
      description               TEXT NOT NULL CHECK (length(description) <= 2000),
      data_sensitive            BOOLEAN NOT NULL DEFAULT FALSE,
      supersedes                TEXT REFERENCES knowledge_bases(id),
      t_valid_from              TIMESTAMPTZ NOT NULL,
      t_valid_to                TIMESTAMPTZ,
      created_by                TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at                TIMESTAMPTZ NOT NULL,
      updated_at                TIMESTAMPTZ NOT NULL,
      archived_at               TIMESTAMPTZ,
      CHECK (
        (kind = 'file' AND source_id IS NULL) OR
        (kind IN ('folder','url') AND source_id IS NOT NULL)
      ),
      CHECK (supersedes IS NULL OR supersedes <> id),
      CHECK (t_valid_to IS NULL OR t_valid_to >= t_valid_from),
      CHECK (updated_at >= created_at),
      CHECK (archived_at IS NULL OR archived_at >= created_at),
      CHECK ((lifecycle_state = 'archived') = (archived_at IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS idx_knowledge_bases_namespace_lifecycle
      ON knowledge_bases(namespace, lifecycle_state, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_knowledge_bases_lower_name
      ON knowledge_bases(namespace, lower(name) text_pattern_ops);
    CREATE INDEX IF NOT EXISTS idx_knowledge_bases_source
      ON knowledge_bases(source_id) WHERE source_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS knowledge_sources (
      id                TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace         TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      knowledge_base_id TEXT NOT NULL REFERENCES knowledge_bases(id),
      source_id         TEXT REFERENCES sources(id) ON DELETE SET NULL,
      source_key        TEXT NOT NULL CHECK (length(source_key) BETWEEN 1 AND 256),
      source_kind       TEXT NOT NULL CHECK (length(source_kind) BETWEEN 1 AND 120),
      display_name      TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
      description       TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
      purpose           TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 500),
      team_id           TEXT REFERENCES org_teams(id) ON DELETE SET NULL,
      status            TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('processing','active','needs_review','failed','archived')),
      supersedes        TEXT REFERENCES knowledge_sources(id),
      t_valid_from      TIMESTAMPTZ NOT NULL,
      t_valid_to        TIMESTAMPTZ,
      created_by        TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at        TIMESTAMPTZ NOT NULL,
      CHECK (supersedes IS NULL OR supersedes <> id),
      CHECK (t_valid_to IS NULL OR t_valid_to >= t_valid_from)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_knowledge_sources_current
      ON knowledge_sources(knowledge_base_id, source_key) WHERE t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_knowledge_sources_namespace
      ON knowledge_sources(namespace, status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_knowledge_sources_source
      ON knowledge_sources(source_id) WHERE source_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS company_file_upload_attempts (
      id                  TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace           TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      knowledge_base_id   TEXT NOT NULL REFERENCES knowledge_bases(id),
      target_team_id      TEXT REFERENCES org_teams(id) ON DELETE SET NULL,
      idempotency_key     TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 256),
      request_sha256      TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
      status              TEXT NOT NULL CHECK (
        status IN ('pending','processing','completed','partially_failed','failed')
      ),
      requested_file_count INTEGER NOT NULL CHECK (requested_file_count BETWEEN 1 AND 100),
      accepted_file_count  INTEGER NOT NULL DEFAULT 0 CHECK (accepted_file_count >= 0),
      failed_file_count    INTEGER NOT NULL DEFAULT 0 CHECK (failed_file_count >= 0),
      attempt_token       TEXT NOT NULL CHECK (length(attempt_token) BETWEEN 1 AND 256),
      lease_expires_at    TIMESTAMPTZ NOT NULL,
      failure_code        TEXT CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
      ),
      created_by          TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at          TIMESTAMPTZ NOT NULL,
      completed_at        TIMESTAMPTZ,
      CHECK (accepted_file_count + failed_file_count <= requested_file_count),
      CHECK (completed_at IS NULL OR completed_at >= created_at),
      UNIQUE (namespace, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS idx_company_upload_attempts_namespace
      ON company_file_upload_attempts(namespace, status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_company_upload_attempts_lease
      ON company_file_upload_attempts(lease_expires_at)
      WHERE status IN ('pending','processing');

    CREATE TABLE IF NOT EXISTS company_file_quota_usage (
      tenant_root       TEXT PRIMARY KEY CHECK (length(tenant_root) BETWEEN 1 AND 512),
      current_files     INTEGER NOT NULL DEFAULT 0 CHECK (current_files >= 0),
      current_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (current_bytes >= 0),
      total_rows        BIGINT NOT NULL DEFAULT 0 CHECK (total_rows >= 0),
      updated_at        TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS company_files (
      id                  TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      knowledge_base_id   TEXT NOT NULL REFERENCES knowledge_bases(id),
      source_id           TEXT NOT NULL REFERENCES sources(id),
      namespace           TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      knowledge_source_id TEXT REFERENCES knowledge_sources(id),
      upload_attempt_id   TEXT REFERENCES company_file_upload_attempts(id),
      title               TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
      description         TEXT NOT NULL CHECK (length(description) <= 2000),
      purpose             TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 500),
      status              TEXT NOT NULL CHECK (
        status IN ('processing','ready','needs_review','failed')
      ),
      lifecycle_state     TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle_state IN ('active','archived')),
      file_name           TEXT NOT NULL CHECK (
        length(file_name) BETWEEN 1 AND 255 AND
        file_name !~ '[\\\\/[:cntrl:]]'
      ),
      media_type          TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 200),
      byte_size           INTEGER NOT NULL CHECK (byte_size BETWEEN 1 AND 524288),
      content_sha256      TEXT NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
      attempt_token       TEXT NOT NULL CHECK (length(attempt_token) BETWEEN 1 AND 256),
      lease_expires_at    TIMESTAMPTZ NOT NULL,
      fact_count          INTEGER NOT NULL DEFAULT 0 CHECK (fact_count >= 0),
      failure_code        TEXT CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
      ),
      supersedes          TEXT REFERENCES company_files(id),
      t_valid_from        TIMESTAMPTZ NOT NULL,
      t_valid_to          TIMESTAMPTZ,
      created_by          TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      uploaded_by         TEXT NOT NULL CHECK (length(uploaded_by) BETWEEN 1 AND 512),
      created_at          TIMESTAMPTZ NOT NULL,
      loaded_at           TIMESTAMPTZ,
      archived_at         TIMESTAMPTZ,
      CHECK (supersedes IS NULL OR supersedes <> id),
      CHECK (t_valid_to IS NULL OR t_valid_to >= t_valid_from),
      CHECK (loaded_at IS NULL OR loaded_at >= created_at),
      CHECK (archived_at IS NULL OR archived_at >= created_at),
      CHECK ((lifecycle_state = 'archived') = (archived_at IS NOT NULL))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_company_files_active_content
      ON company_files(knowledge_base_id, content_sha256)
      WHERE lifecycle_state = 'active'
        AND status IN ('processing','ready','needs_review')
        AND t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_company_files_knowledge_base
      ON company_files(knowledge_base_id, lifecycle_state, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_company_files_namespace_lifecycle
      ON company_files(namespace, lifecycle_state, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_company_files_lower_title
      ON company_files(namespace, lower(title) text_pattern_ops);
    CREATE INDEX IF NOT EXISTS idx_company_files_lower_filename
      ON company_files(namespace, lower(file_name) text_pattern_ops);
    CREATE INDEX IF NOT EXISTS idx_company_files_processing_lease
      ON company_files(lease_expires_at)
      WHERE status = 'processing' AND lifecycle_state = 'active';
    CREATE INDEX IF NOT EXISTS idx_company_files_attempt
      ON company_files(upload_attempt_id, created_at)
      WHERE upload_attempt_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_company_files_content
      ON company_files(namespace, content_sha256);

    CREATE TABLE IF NOT EXISTS entity_mentions (
      id                TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace         TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      knowledge_base_id TEXT NOT NULL REFERENCES knowledge_bases(id),
      entity_id         TEXT NOT NULL REFERENCES entity_registry(id),
      memory_id         TEXT REFERENCES memory_objects(id) ON DELETE CASCADE,
      company_file_id   TEXT REFERENCES company_files(id) ON DELETE CASCADE,
      span_start        INTEGER NOT NULL CHECK (span_start >= 0),
      span_end          INTEGER NOT NULL CHECK (span_end > span_start),
      confidence        REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
      extractor         TEXT NOT NULL CHECK (length(extractor) BETWEEN 1 AND 120),
      supersedes        TEXT REFERENCES entity_mentions(id),
      t_valid_from      TIMESTAMPTZ NOT NULL,
      t_valid_to        TIMESTAMPTZ,
      created_by        TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at        TIMESTAMPTZ NOT NULL,
      CHECK (memory_id IS NOT NULL OR company_file_id IS NOT NULL),
      CHECK (supersedes IS NULL OR supersedes <> id),
      CHECK (t_valid_to IS NULL OR t_valid_to >= t_valid_from)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_mentions_memory_current
      ON entity_mentions(memory_id, entity_id, span_start, span_end)
      WHERE memory_id IS NOT NULL AND t_valid_to IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_mentions_file_current
      ON entity_mentions(company_file_id, entity_id, span_start, span_end)
      WHERE company_file_id IS NOT NULL AND t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_entity_mentions_namespace_entity
      ON entity_mentions(namespace, entity_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS entity_relationships (
      id                TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace         TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      subject_entity_id TEXT NOT NULL REFERENCES entity_registry(id),
      relationship      TEXT NOT NULL CHECK (relationship IN (
        'same_as','part_of','contains','uses','depends_on','owned_by','served_by','related_to'
      )),
      object_entity_id  TEXT NOT NULL REFERENCES entity_registry(id),
      confidence        REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
      evidence          JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'array'),
      assertion_time    TIMESTAMPTZ NOT NULL,
      event_time        TIMESTAMPTZ,
      t_valid_from      TIMESTAMPTZ NOT NULL,
      t_valid_to        TIMESTAMPTZ,
      supersedes        TEXT REFERENCES entity_relationships(id),
      status            TEXT NOT NULL CHECK (status IN ('active','archived','disputed')),
      created_by        TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at        TIMESTAMPTZ NOT NULL,
      CHECK (subject_entity_id <> object_entity_id OR relationship = 'same_as'),
      CHECK (supersedes IS NULL OR supersedes <> id),
      CHECK (t_valid_to IS NULL OR t_valid_to >= t_valid_from),
      CHECK (event_time IS NULL OR event_time <= assertion_time)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_relationships_active_edge
      ON entity_relationships(namespace, subject_entity_id, relationship, object_entity_id)
      WHERE status = 'active' AND t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_entity_relationships_subject
      ON entity_relationships(namespace, subject_entity_id, relationship)
      WHERE t_valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_entity_relationships_object
      ON entity_relationships(namespace, object_entity_id, relationship)
      WHERE t_valid_to IS NULL;

    CREATE TABLE IF NOT EXISTS entity_relationship_evidence (
      id                TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
      namespace         TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 512),
      relationship_id   TEXT NOT NULL REFERENCES entity_relationships(id),
      memory_id         TEXT NOT NULL REFERENCES memory_objects(id),
      source_id         TEXT REFERENCES sources(id),
      company_file_id   TEXT REFERENCES company_files(id),
      entity_mention_id TEXT REFERENCES entity_mentions(id),
      document_key      TEXT CHECK (
        document_key IS NULL OR length(document_key) BETWEEN 1 AND 512
      ),
      content_hash      TEXT CHECK (
        content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'
      ),
      evidence_role     TEXT NOT NULL DEFAULT 'supporting'
        CHECK (evidence_role IN ('supporting','contradicting')),
      confidence        REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
      created_by        TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
      created_at        TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_relationship_evidence_unique
      ON entity_relationship_evidence(relationship_id, memory_id);
    CREATE INDEX IF NOT EXISTS idx_entity_relationship_evidence_relationship
      ON entity_relationship_evidence(relationship_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_entity_relationship_evidence_memory
      ON entity_relationship_evidence(namespace, memory_id);
    CREATE INDEX IF NOT EXISTS idx_entity_relationship_evidence_source
      ON entity_relationship_evidence(source_id) WHERE source_id IS NOT NULL;

    ALTER TABLE knowledge_bases ENABLE ROW LEVEL SECURITY;
    ALTER TABLE knowledge_sources ENABLE ROW LEVEL SECURITY;
    ALTER TABLE company_file_upload_attempts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE company_file_quota_usage ENABLE ROW LEVEL SECURITY;
    ALTER TABLE company_files ENABLE ROW LEVEL SECURITY;
    ALTER TABLE entity_mentions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE entity_relationships ENABLE ROW LEVEL SECURITY;
    ALTER TABLE entity_relationship_evidence ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 45,
    name: "setup-team-directory-backfill",
    sql(): string {
      return `
      INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
      SELECT 'setup:' || namespace, namespace, name, '', 'verified-setup-backfill', created_at
      FROM teams
      ON CONFLICT (namespace) DO NOTHING`;
    },
  },
  {
    version: 46,
    name: "organization-conflict-scans-and-agent-summaries",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS conflict_scan_runs (
      id                  TEXT PRIMARY KEY,
      target_namespace    TEXT NOT NULL,
      requested_by        TEXT NOT NULL,
      requested_key_id    TEXT NOT NULL,
      focus               TEXT,
      include_kinds       JSONB NOT NULL DEFAULT '[]',
      status              TEXT NOT NULL CHECK (status IN (
        'queued','running','completed','completed_with_gaps','failed'
      )),
      phase               TEXT NOT NULL CHECK (phase IN (
        'queued','collecting','comparing','publishing','complete'
      )),
      items_scanned       INTEGER NOT NULL DEFAULT 0 CHECK (items_scanned >= 0),
      items_total         INTEGER NOT NULL DEFAULT 0 CHECK (items_total >= 0),
      sources_reached     INTEGER NOT NULL DEFAULT 0 CHECK (sources_reached >= 0),
      agent_summaries     INTEGER NOT NULL DEFAULT 0 CHECK (agent_summaries >= 0),
      candidate_pairs     INTEGER NOT NULL DEFAULT 0 CHECK (candidate_pairs >= 0),
      new_findings        INTEGER NOT NULL DEFAULT 0 CHECK (new_findings >= 0),
      existing_findings   INTEGER NOT NULL DEFAULT 0 CHECK (existing_findings >= 0),
      coverage_gaps       JSONB NOT NULL DEFAULT '[]',
      failure_code        TEXT,
      requested_at        TIMESTAMPTZ NOT NULL,
      started_at          TIMESTAMPTZ,
      completed_at        TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_conflict_scan_runs_target_time
      ON conflict_scan_runs(target_namespace, requested_at DESC);

    CREATE TABLE IF NOT EXISTS conflict_scan_findings (
      id                  TEXT PRIMARY KEY,
      target_namespace    TEXT NOT NULL,
      left_memory_id      TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      right_memory_id     TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      fingerprint         TEXT NOT NULL,
      detector_version    TEXT NOT NULL,
      entity              TEXT NOT NULL,
      category            TEXT NOT NULL CHECK (category IN (
        'policies-legal','order-management','product-info','other'
      )),
      reason              TEXT NOT NULL,
      confidence          REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
      flags               JSONB NOT NULL DEFAULT '[]',
      status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','dismissed')),
      row_version         INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
      first_scan_id       TEXT NOT NULL REFERENCES conflict_scan_runs(id),
      last_scan_id        TEXT NOT NULL REFERENCES conflict_scan_runs(id),
      first_seen_at       TIMESTAMPTZ NOT NULL,
      last_seen_at        TIMESTAMPTZ NOT NULL,
      CHECK (left_memory_id <> right_memory_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_conflict_scan_findings_fingerprint
      ON conflict_scan_findings(target_namespace, fingerprint);
    CREATE INDEX IF NOT EXISTS idx_conflict_scan_findings_open
      ON conflict_scan_findings(target_namespace, last_seen_at DESC)
      WHERE status = 'open';

    CREATE TABLE IF NOT EXISTS agent_session_summaries (
      id                  TEXT PRIMARY KEY,
      namespace           TEXT NOT NULL,
      key_id              TEXT NOT NULL,
      actor               TEXT NOT NULL,
      session_hash        TEXT NOT NULL,
      input_digest        TEXT NOT NULL,
      status              TEXT NOT NULL CHECK (status IN ('processing','completed','failed')),
      summary_memory_id   TEXT REFERENCES memory_objects(id) ON DELETE SET NULL,
      fact_count          INTEGER NOT NULL DEFAULT 0 CHECK (fact_count >= 0),
      started_at          TIMESTAMPTZ,
      ended_at            TIMESTAMPTZ,
      created_at          TIMESTAMPTZ NOT NULL,
      completed_at        TIMESTAMPTZ,
      failure_code        TEXT,
      UNIQUE (key_id, session_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_agent_session_summaries_namespace_time
      ON agent_session_summaries(namespace, created_at DESC);

    CREATE TABLE IF NOT EXISTS agent_session_summary_memories (
      summary_id          TEXT NOT NULL REFERENCES agent_session_summaries(id) ON DELETE CASCADE,
      memory_id           TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      PRIMARY KEY (summary_id, memory_id)
    );
    CREATE INDEX IF NOT EXISTS idx_agent_session_summary_memories_memory
      ON agent_session_summary_memories(memory_id);

    ALTER TABLE conflict_scan_runs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE conflict_scan_findings ENABLE ROW LEVEL SECURITY;
    ALTER TABLE agent_session_summaries ENABLE ROW LEVEL SECURITY;
    ALTER TABLE agent_session_summary_memories ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 47,
    name: "conflict-scan-semantic-judge-lease",
    sql(): string {
      return `
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS lease_token TEXT;
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS fact_offset INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS candidate_offset INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS pair_rotation INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS conflict_scan_queue_guard (
      id INTEGER PRIMARY KEY CHECK (id = 1)
    );
    INSERT INTO conflict_scan_queue_guard(id) VALUES (1) ON CONFLICT (id) DO NOTHING;
    ALTER TABLE conflict_scan_queue_guard ENABLE ROW LEVEL SECURITY;
    UPDATE conflict_scan_runs
       SET heartbeat_at = COALESCE(heartbeat_at, started_at, requested_at)
     WHERE heartbeat_at IS NULL;
    WITH ranked AS (
      SELECT id, ROW_NUMBER() OVER (
        PARTITION BY target_namespace ORDER BY requested_at DESC,id DESC
      ) AS ordinal
      FROM conflict_scan_runs WHERE status IN ('queued','running')
    )
    UPDATE conflict_scan_runs SET status='failed',phase='complete',
      failure_code='superseded_active_scan',completed_at=CURRENT_TIMESTAMP
    WHERE id IN (SELECT id FROM ranked WHERE ordinal > 1);
    WITH running AS (
      SELECT id, ROW_NUMBER() OVER (ORDER BY requested_at,id) AS ordinal
      FROM conflict_scan_runs WHERE status = 'running'
    )
    UPDATE conflict_scan_runs SET status='queued',phase='queued',lease_token=NULL
    WHERE id IN (SELECT id FROM running WHERE ordinal > 1);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_conflict_scan_runs_one_active_target
      ON conflict_scan_runs(target_namespace)
      WHERE status IN ('queued','running');
    CREATE UNIQUE INDEX IF NOT EXISTS idx_conflict_scan_runs_one_global_worker
      ON conflict_scan_runs ((1)) WHERE status = 'running'`;
    },
  },
  {
    version: 48,
    name: "usage-events-traces",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS usage_events (
      id            TEXT PRIMARY KEY,
      audit_seq     BIGINT NOT NULL REFERENCES audit_log(seq),
      trace_id      TEXT NOT NULL,
      ts            TIMESTAMPTZ NOT NULL,
      namespace     TEXT NOT NULL,
      actor         TEXT NOT NULL,
      principal     TEXT NOT NULL CHECK (principal IN ('human','agent')),
      caller_class  TEXT NOT NULL,
      op            TEXT NOT NULL,
      tool          TEXT,
      result        TEXT NOT NULL,
      latency_ms    INTEGER NOT NULL,
      tokens        INTEGER NOT NULL DEFAULT 0,
      returned      INTEGER NOT NULL DEFAULT 0,
      driver        TEXT,
      source_tier   TEXT,
      source_ids    JSONB,
      top_score     REAL
    );
    CREATE INDEX IF NOT EXISTS idx_usage_events_ns_ts ON usage_events(namespace, ts);
    CREATE INDEX IF NOT EXISTS idx_usage_events_trace ON usage_events(trace_id);
    CREATE INDEX IF NOT EXISTS idx_usage_events_actor_ts ON usage_events(actor, ts);
    ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
    CREATE TABLE IF NOT EXISTS query_traces (
      trace_id      TEXT PRIMARY KEY,
      ts            TIMESTAMPTZ NOT NULL,
      namespace     TEXT NOT NULL,
      actor         TEXT NOT NULL,
      query_sha256  TEXT,
      query_summary TEXT,
      events        INTEGER NOT NULL DEFAULT 0,
      latency_ms    INTEGER NOT NULL DEFAULT 0,
      tokens        INTEGER NOT NULL DEFAULT 0,
      usd           REAL    NOT NULL DEFAULT 0,
      outcome       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_query_traces_ns_ts ON query_traces(namespace, ts);
    ALTER TABLE query_traces ENABLE ROW LEVEL SECURITY;
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS actor TEXT;
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS trace_id TEXT;
    CREATE INDEX IF NOT EXISTS idx_cost_ledger_trace ON cost_ledger(trace_id) WHERE trace_id IS NOT NULL;
    ALTER TABLE answer_outcomes ADD COLUMN IF NOT EXISTS trace_id TEXT;
    CREATE INDEX IF NOT EXISTS idx_answer_outcomes_trace ON answer_outcomes(namespace, trace_id) WHERE trace_id IS NOT NULL`;
    },
  },
  {
    version: 49,
    name: "usage-rollup-watermark-indexes",
    sql(): string {
      // E10: the usage rollup's result cache invalidates on a cheap high-water
      // mark — max(usage_events.audit_seq) / max(query_traces.ts) must be
      // index-served, never a seq scan over the big tables. Indexes only, so
      // no RLS (post-M9 convention applies to CREATE TABLE).
      return `
    CREATE INDEX IF NOT EXISTS idx_usage_events_audit_seq ON usage_events(audit_seq);
    CREATE INDEX IF NOT EXISTS idx_query_traces_ts ON query_traces(ts)`;
    },
  },
  {
    version: 50,
    name: "query-traces-namespace-key",
    sql(): string {
      // D37: caller trace hints are arbitrary strings, so a global trace_id
      // primary key let one tenant's hint merge into (or squat) another
      // tenant's rollup row. The trace row is per-namespace: the composite
      // key makes upserts, usd bumps, and detail reads namespace-exact.
      // Idempotent on re-run (the default constraint name is the same); no
      // CREATE TABLE, so no RLS action (post-M9 convention is for new tables).
      return `
    ALTER TABLE query_traces DROP CONSTRAINT IF EXISTS query_traces_pkey;
    ALTER TABLE query_traces ADD PRIMARY KEY (namespace, trace_id)`;
    },
  },
  {
    version: 51,
    name: "knowledge-sync-history-index",
    sql(): string {
      // S7 reads every fresh-summary execution in a bounded 30-day window.
      // Keep the append-only audit log authoritative while making the exact
      // namespace + time query index-served. No new table, so no RLS action.
      return `
    CREATE INDEX IF NOT EXISTS idx_audit_knowledge_sync_history
      ON audit_log(namespace, ts DESC, seq DESC)
      WHERE op = 'automation_run' AND purpose = 'automation'`;
    },
  },
  {
    version: 52,
    name: "usage-events-namespace-trace-indexes",
    sql(): string {
      // The default team rollup resolves unanswered traces with an exact
      // (namespace, trace_id) anti-join. The partial signal index keeps that
      // lookup bounded while the general composite index also serves trace
      // detail/enrichment reads after trace ids became namespace-local in v50.
      // The ordered trace watermark index makes new trace rows incrementally
      // discoverable without a query_traces scan.
      return `
    CREATE INDEX IF NOT EXISTS idx_usage_events_ns_trace
      ON usage_events(namespace, trace_id);
    CREATE INDEX IF NOT EXISTS idx_usage_events_ns_trace_signal
      ON usage_events(namespace, trace_id)
      WHERE returned > 0 OR result = 'denied';
    CREATE INDEX IF NOT EXISTS idx_query_traces_watermark
      ON query_traces(ts, trace_id, namespace)`;
    },
  },
  {
    version: 53,
    name: "disable-platform-root-knowledge-sync",
    sql(): string {
      // Root syncs created before company sync became a private-team fan-out
      // can never consolidate successfully. Preserve their audit/history row,
      // but stop the recurring chain and remove any queued arm.
      return `
    DELETE FROM durable_jobs
      WHERE kind = 'automation'
        AND namespace = ''
        AND state = 'queued'
        AND payload->>'automationId' IN (
          SELECT id
            FROM org_automations
           WHERE namespace = ''
             AND template_id = 'fresh-summaries'
        );
    UPDATE org_automations
       SET enabled = FALSE,
           not_before = NULL,
           row_version = row_version + 1,
           updated_at = CURRENT_TIMESTAMP
     WHERE namespace = ''
       AND template_id = 'fresh-summaries'`;
    },
  },
  {
    version: 54,
    name: "team-company-memory-access",
    sql(): string {
      return `
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS organization_namespace TEXT NOT NULL DEFAULT '';
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS memory_access_mode TEXT NOT NULL DEFAULT 'related';
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS memory_access_version INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS memory_access_updated_by TEXT;
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS memory_access_updated_at TIMESTAMPTZ;
    UPDATE org_teams
       SET organization_namespace = CASE
         WHEN EXISTS (
           SELECT 1 FROM tenants
            WHERE id = split_part(org_teams.namespace, '/', 1)
         ) THEN split_part(org_teams.namespace, '/', 1)
         WHEN position('/' in org_teams.namespace) > 0
           THEN split_part(org_teams.namespace, '/', 1)
         ELSE ''
       END;
    ALTER TABLE org_teams
      ADD CONSTRAINT org_teams_memory_access_mode_check
      CHECK (memory_access_mode IN ('related', 'company-published'));
    ALTER TABLE org_teams
      ADD CONSTRAINT org_teams_memory_access_version_check
      CHECK (memory_access_version > 0);
    CREATE INDEX IF NOT EXISTS idx_org_teams_organization_namespace
      ON org_teams(organization_namespace, namespace);
    CREATE INDEX IF NOT EXISTS idx_memory_company_published
      ON memory_objects(namespace, assertion_time DESC)
      WHERE scope = 'org' AND type <> 'pointer'`;
    },
  },
  {
    version: 55,
    name: "access-grants-and-preview-sessions",
    sql(): string {
      // M10 (CONTRACTS-M10-ACCESS.md). `resource_id` is an opaque
      // server-owned ID; `namespace_root` is the server-populated mapping to
      // the granted namespace root — callers never supply either (D9).
      // Revocation/exit are row states (`revoked_at` / `ended_at`), never a
      // DELETE (D47). Preview credentials exist at rest ONLY as sha256 hex
      // (`token_hash`, D43). RLS on both new tables per the post-M9
      // convention (owner/service_role bypass; a Supabase-hosted deployment
      // stays closed to the PostgREST anon key). `agent_memory_grants` is
      // Phase 4 and deliberately NOT created here.
      return `
    CREATE TABLE IF NOT EXISTS access_grants (
      id             TEXT PRIMARY KEY,
      tenant_id      TEXT NOT NULL,
      principal_type TEXT NOT NULL CHECK (principal_type IN ('human','agent','service')),
      principal_id   TEXT NOT NULL,
      resource_type  TEXT NOT NULL CHECK (resource_type IN ('function','personal','common','audit')),
      resource_id    TEXT NOT NULL,
      namespace_root TEXT NOT NULL,
      access_mode    TEXT NOT NULL CHECK (access_mode IN ('consume','govern','audit_read')),
      source         TEXT NOT NULL CHECK (source IN ('membership','direct','system')),
      created_by     TEXT NOT NULL,
      created_at     TIMESTAMPTZ NOT NULL,
      expires_at     TIMESTAMPTZ,
      revoked_at     TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_access_grants_principal
      ON access_grants(tenant_id, principal_type, principal_id)
      WHERE revoked_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_access_grants_resource
      ON access_grants(tenant_id, resource_id)
      WHERE revoked_at IS NULL;
    ALTER TABLE access_grants ENABLE ROW LEVEL SECURITY;
    CREATE TABLE IF NOT EXISTS access_preview_sessions (
      id                    TEXT PRIMARY KEY,
      token_hash            TEXT NOT NULL UNIQUE,
      tenant_id             TEXT NOT NULL,
      root_user_id          TEXT NOT NULL,
      subject_user_id       TEXT,
      simulated_role        TEXT CHECK (simulated_role IN ('admin','member')),
      selected_resource_ids JSONB NOT NULL DEFAULT '[]',
      reason                TEXT NOT NULL,
      created_at            TIMESTAMPTZ NOT NULL,
      expires_at            TIMESTAMPTZ NOT NULL,
      ended_at              TIMESTAMPTZ
    );
    ALTER TABLE access_preview_sessions ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 56,
    name: "policy-guardrails",
    sql(): string {
      // Policy documents become agent-facing guardrails: `enforcement` says how
      // hard the directive lands (advisory = delivered, required = delivered and
      // its absence is recorded as a bypass). Delivery and compliance are an
      // append-only event ledger (`policy_agent_events`, D4/D7 — never an
      // UPDATE of history) plus a derived per-(document, agent) rollup
      // (`policy_agent_state`) so the console reads one indexed row per agent
      // instead of scanning the ledger. RLS per the post-M9 convention.
      return `
    ALTER TABLE policy_documents
      ADD COLUMN IF NOT EXISTS enforcement TEXT NOT NULL DEFAULT 'required';
    ALTER TABLE policy_documents
      ADD CONSTRAINT policy_documents_enforcement_check
      CHECK (enforcement IN ('advisory','required'));
    CREATE TABLE IF NOT EXISTS policy_agent_events (
      id            TEXT PRIMARY KEY,
      namespace     TEXT NOT NULL,
      document_id   TEXT NOT NULL REFERENCES policy_documents(id),
      policy_digest TEXT NOT NULL,
      agent_id      TEXT NOT NULL,
      actor         TEXT NOT NULL,
      principal     TEXT NOT NULL CHECK (principal IN ('human','agent')),
      kind          TEXT NOT NULL CHECK (
        kind IN ('served','acknowledged','applied','bypassed')
      ),
      channel       TEXT NOT NULL CHECK (
        channel IN ('assemble','policy-call','ack','monitor')
      ),
      trace_id      TEXT,
      ts            TIMESTAMPTZ NOT NULL,
      detail        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_policy_agent_events_scope
      ON policy_agent_events(namespace, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_policy_agent_events_document
      ON policy_agent_events(document_id, agent_id, kind, ts DESC);
    ALTER TABLE policy_agent_events ENABLE ROW LEVEL SECURITY;
    CREATE TABLE IF NOT EXISTS policy_agent_state (
      namespace            TEXT NOT NULL,
      document_id          TEXT NOT NULL REFERENCES policy_documents(id),
      agent_id             TEXT NOT NULL,
      actor                TEXT NOT NULL,
      last_digest          TEXT NOT NULL,
      -- The digest the agent was last SERVED, which is what "is this agent
      -- current?" means. last_digest tracks the newest event of any kind, so
      -- a bypass row would otherwise make a never-served agent look current.
      last_served_digest   TEXT,
      served_count         BIGINT NOT NULL DEFAULT 0 CHECK (served_count >= 0),
      acknowledged_count   BIGINT NOT NULL DEFAULT 0 CHECK (acknowledged_count >= 0),
      applied_count        BIGINT NOT NULL DEFAULT 0 CHECK (applied_count >= 0),
      bypass_count         BIGINT NOT NULL DEFAULT 0 CHECK (bypass_count >= 0),
      first_served_at      TIMESTAMPTZ,
      last_served_at       TIMESTAMPTZ,
      last_acknowledged_at TIMESTAMPTZ,
      last_applied_at      TIMESTAMPTZ,
      last_bypass_at       TIMESTAMPTZ,
      updated_at           TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (namespace, document_id, agent_id)
    );
    CREATE INDEX IF NOT EXISTS idx_policy_agent_state_document
      ON policy_agent_state(document_id, last_served_at DESC);
    ALTER TABLE policy_agent_state ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 57,
    name: "external-identity-google",
    // Unified sign-in identity: the v42 link table accepted GitHub only, so a
    // Google (Supabase SSO) sign-in left no visible connection on the Profile
    // screen. Widening the CHECK lets the SAME table carry both providers —
    // UNIQUE(provider, provider_account_id) and UNIQUE(user_id, provider)
    // continue to hold per provider, so one Google account still resolves to at
    // most one kernel user and a user connects at most one account each.
    sql(): string {
      return `
    ALTER TABLE user_external_identities
      DROP CONSTRAINT IF EXISTS user_external_identities_provider_check;
    ALTER TABLE user_external_identities
      ADD CONSTRAINT user_external_identities_provider_check
      CHECK (provider IN ('github','google'))`;
    },
  },
  {
    version: 58,
    name: "byok-provider-catalog",
    // BYOK across the whole model market. `provider` was always the WIRE
    // PROTOCOL, not the vendor — widening the CHECK adds the three protocols
    // that are not OpenAI-shaped (Gemini generateContent, Cohere v2 chat, Azure
    // deployment routing). `provider_id` records which catalog vendor the
    // operator picked (src/model-runtime/catalog.ts); it is descriptive only,
    // stays NULL for raw protocol connections created before this migration,
    // and is deliberately NOT a foreign key — the catalog is code, not data, so
    // retiring a vendor must never orphan a stored connection.
    sql(): string {
      return `
    ALTER TABLE model_connections
      DROP CONSTRAINT IF EXISTS model_connections_provider_check;
    ALTER TABLE model_connections
      ADD CONSTRAINT model_connections_provider_check
      CHECK (provider IN ('anthropic','openai-compatible','google-gemini','cohere','azure-openai'));
    ALTER TABLE model_connections
      ADD COLUMN IF NOT EXISTS provider_id TEXT`;
    },
  },
  {
    version: 59,
    name: "agent-access-level",
    // D50 (CONTRACTS-AGENT-SCOPE.md): an agent credential's authority is
    // (namespace, accessLevel). The column is nullable rather than defaulted so
    // NULL keeps one meaning per row shape: on a human key type it means "not a
    // machine principal"; on an agent row minted by an older kernel mid-deploy
    // it resolves as the least-privileged 'member'. The backfill makes that
    // explicit for every agent key that exists today. There is deliberately no
    // 'owner'/'admin' value — an agent can never hold organization authority.
    sql(): string {
      return `
    ALTER TABLE api_keys
      ADD COLUMN IF NOT EXISTS agent_access_level TEXT;
    ALTER TABLE api_keys
      DROP CONSTRAINT IF EXISTS api_keys_agent_access_level_check;
    ALTER TABLE api_keys
      ADD CONSTRAINT api_keys_agent_access_level_check
      CHECK (agent_access_level IS NULL OR agent_access_level IN ('manager','member'));
    UPDATE api_keys SET agent_access_level = 'member'
      WHERE role = 'agent' AND agent_access_level IS NULL`;
    },
  },
  {
    version: 60,
    name: "agent-key-expiry-and-description",
    // D51 (CONTRACTS-AGENT-DEPLOY.md): the deploy flow asks for two things the
    // credential row could not hold. `expires_at` is the ONE limit that means
    // something for a memory agent — the connector-grant caps (rows, bytes,
    // requests/minute) govern `source_read` and are irrelevant to an agent that
    // only touches memory. `description` is the human sentence explaining why
    // the agent exists, shown on its card.
    //
    // Both nullable, and NULL keeps the pre-existing meaning: no expiry is
    // standing access (revocable at any time), no description is a blank line.
    // No backfill — every existing key is standing access, which is what it was.
    sql(): string {
      return `
    ALTER TABLE api_keys
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    ALTER TABLE api_keys
      ADD COLUMN IF NOT EXISTS description TEXT`;
    },
  },
  {
    version: 61,
    name: "agent-write-capability",
    // D54 (CONTRACTS-AGENT-DEPLOY.md): whether an agent may CHANGE memory or
    // only read it. Deliberately its own column rather than a reuse of the
    // `read-only` key type: that type maps to role 'auditor', which also grants
    // the organization's audit trail — a widening, not a narrowing, for an
    // external agent.
    //
    // NULL means "may write". Every credential minted before this migration was
    // issued under a rule where agents could write, and a nullable column with
    // that meaning keeps the backfill honest: no existing agent silently loses
    // an ability it was granted. Only `FALSE` restricts.
    sql(): string {
      return `
    ALTER TABLE api_keys
      ADD COLUMN IF NOT EXISTS agent_can_write BOOLEAN`;
    },
  },
  {
    version: 62,
    name: "copilot-conversation-history",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS copilot_conversations (
      id         TEXT PRIMARY KEY,
      namespace  TEXT NOT NULL,
      actor      TEXT NOT NULL,
      title_ciphertext TEXT NOT NULL,
      title_iv         TEXT NOT NULL,
      title_tag        TEXT NOT NULL,
      title_kek_id     TEXT NOT NULL,
      title_sha256     TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_copilot_conversations_owner
      ON copilot_conversations(namespace, actor, updated_at DESC, id DESC);
    ALTER TABLE copilot_conversations ENABLE ROW LEVEL SECURITY;
    CREATE TABLE IF NOT EXISTS copilot_conversation_messages (
      id                 TEXT PRIMARY KEY,
      conversation_id    TEXT NOT NULL REFERENCES copilot_conversations(id) ON DELETE CASCADE,
      namespace           TEXT NOT NULL,
      actor               TEXT NOT NULL,
      turn_id             TEXT NOT NULL,
      role                TEXT NOT NULL CHECK (role IN ('user','assistant')),
      sequence            INTEGER NOT NULL CHECK (sequence > 0),
      payload_ciphertext  TEXT NOT NULL,
      payload_iv          TEXT NOT NULL,
      payload_tag         TEXT NOT NULL,
      payload_kek_id      TEXT NOT NULL,
      payload_sha256      TEXT NOT NULL,
      created_at          TIMESTAMPTZ NOT NULL,
      UNIQUE (conversation_id, turn_id, role),
      UNIQUE (conversation_id, sequence)
    );
    CREATE INDEX IF NOT EXISTS idx_copilot_messages_owner
      ON copilot_conversation_messages(namespace, actor, conversation_id, sequence);
    ALTER TABLE copilot_conversation_messages ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 63,
    name: "copilot-routines",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS copilot_routines (
      id                     TEXT PRIMARY KEY,
      namespace              TEXT NOT NULL,
      actor                  TEXT NOT NULL,
      prompt_ciphertext      TEXT NOT NULL,
      prompt_iv              TEXT NOT NULL,
      prompt_tag             TEXT NOT NULL,
      prompt_kek_id          TEXT NOT NULL,
      prompt_hmac            TEXT NOT NULL,
      enabled_slot           INTEGER CHECK (enabled_slot BETWEEN 1 AND 25),
      frequency              TEXT NOT NULL CHECK (frequency IN ('daily','weekly')),
      local_time             TEXT NOT NULL,
      weekday                INTEGER CHECK (weekday BETWEEN 0 AND 6),
      time_zone              TEXT NOT NULL,
      profile_id             TEXT,
      is_enabled             BOOLEAN NOT NULL DEFAULT TRUE,
      next_run_at            TIMESTAMPTZ,
      last_run_at            TIMESTAMPTZ,
      last_run_status        TEXT CHECK (last_run_status IN ('completed','failed')),
      last_error             TEXT,
      result_conversation_id TEXT REFERENCES copilot_conversations(id) ON DELETE SET NULL,
      row_version            INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
      created_at             TIMESTAMPTZ NOT NULL,
      updated_at             TIMESTAMPTZ NOT NULL,
      CHECK (
        (frequency = 'daily' AND weekday IS NULL)
        OR (frequency = 'weekly' AND weekday IS NOT NULL)
      ),
      CHECK (
        (is_enabled = TRUE AND enabled_slot IS NOT NULL)
        OR (is_enabled = FALSE AND enabled_slot IS NULL)
      )
    );
    CREATE INDEX IF NOT EXISTS idx_copilot_routines_owner
      ON copilot_routines(namespace, actor, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_copilot_routines_due
      ON copilot_routines(next_run_at) WHERE is_enabled = TRUE;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_copilot_routines_enabled_slot
      ON copilot_routines(namespace, actor, enabled_slot)
      WHERE is_enabled = TRUE;
    ALTER TABLE copilot_routines ENABLE ROW LEVEL SECURITY;

    CREATE TABLE IF NOT EXISTS copilot_routine_runs (
      id                     TEXT PRIMARY KEY,
      routine_id             TEXT NOT NULL REFERENCES copilot_routines(id) ON DELETE CASCADE,
      scheduled_for          TIMESTAMPTZ NOT NULL,
      status                 TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
      result_conversation_id TEXT REFERENCES copilot_conversations(id) ON DELETE SET NULL,
      error                  TEXT,
      created_at             TIMESTAMPTZ NOT NULL,
      started_at             TIMESTAMPTZ,
      completed_at           TIMESTAMPTZ,
      UNIQUE (routine_id, scheduled_for)
    );
    CREATE INDEX IF NOT EXISTS idx_copilot_routine_runs_routine
      ON copilot_routine_runs(routine_id, created_at DESC);
    ALTER TABLE copilot_routine_runs ENABLE ROW LEVEL SECURITY;

    ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
    ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check
      CHECK (kind IN (
        'write','live-query','source-sync','movement','automation',
        'usage-close','usage-emit','copilot-routine'
      ))`;
    },
  },
  {
    version: 64,
    name: "widen-model-profile-output-ceiling",
    // The 4096 ceiling predates reasoning models. Their thinking tokens are
    // billed against the same output budget, so a modest cap can be consumed
    // entirely before the model emits a single visible word — which the harness
    // could only report as an empty response. Widen the ceiling and let the
    // control plane pick a default that does not need operator tuning.
    sql(): string {
      return `
    ALTER TABLE model_profiles
      DROP CONSTRAINT IF EXISTS model_profiles_max_output_tokens_check;
    ALTER TABLE model_profiles
      ALTER COLUMN max_output_tokens SET DEFAULT 8192;
    ALTER TABLE model_profiles
      ADD CONSTRAINT model_profiles_max_output_tokens_check
      CHECK (max_output_tokens > 0 AND max_output_tokens <= 32768)`;
    },
  },
  {
    version: 65,
    name: "channel-control-plane",
    sql(_embedDim: number): string {
      return `ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS tenant_root TEXT GENERATED ALWAYS AS (split_part(namespace, '/', 1)) STORED;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_tenant_root_id_key UNIQUE (tenant_root, id);
ALTER TABLE audit_log ADD CONSTRAINT audit_log_namespace_seq_key UNIQUE (namespace, seq);

CREATE TABLE IF NOT EXISTS channel_immutable_update_guard (
  violation TEXT NOT NULL,
  CONSTRAINT channel_immutable_update_rejected CHECK (FALSE)
);
ALTER TABLE channel_immutable_update_guard ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS channel_connections (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL REFERENCES tenants(id),
  namespace TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('telegram','slack','gmail','google_chat')),
  display_name TEXT NOT NULL DEFAULT 'Channel' CHECK (char_length(display_name) BETWEEN 1 AND 160),
  display_metadata JSONB NOT NULL DEFAULT '{}',
  lifecycle_state TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_state IN ('draft','active','paused','disconnected')),
  authority_state TEXT NOT NULL DEFAULT 'storefront_authoritative' CHECK (authority_state IN ('storefront_authoritative','shadow','halomem_inbound','halomem_active','rollback')),
  outbound_authority BOOLEAN NOT NULL DEFAULT FALSE,
  authority_epoch BIGINT NOT NULL DEFAULT 0 CHECK (authority_epoch >= 0),
  credential_version INTEGER NOT NULL DEFAULT 0 CHECK (credential_version >= 0),
  provider_installation_key TEXT NOT NULL,
  route_key_hash TEXT NOT NULL CHECK (route_key_hash ~ '^[0-9a-f]{64}$'),
  verification_state TEXT NOT NULL DEFAULT 'unverified' CHECK (verification_state IN ('unverified','pending','verified','degraded','revoked')),
  health_state TEXT NOT NULL DEFAULT 'unknown' CHECK (health_state IN ('unknown','healthy','degraded','failed')),
  health_detail TEXT,
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  created_by TEXT NOT NULL DEFAULT 'migration',
  created_at TIMESTAMPTZ NOT NULL,
  updated_by TEXT NOT NULL DEFAULT 'migration',
  updated_at TIMESTAMPTZ NOT NULL,
  paused_by TEXT,
  paused_at TIMESTAMPTZ,
  pause_reason TEXT,
  disconnected_by TEXT,
  disconnected_at TIMESTAMPTZ,
  disconnect_reason TEXT,
  row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version > 0),
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  CHECK ((lifecycle_state = 'paused') = (paused_at IS NOT NULL)),
  CHECK ((lifecycle_state = 'disconnected') = (disconnected_at IS NOT NULL)),
  UNIQUE (namespace, id),
  UNIQUE (kind, provider_installation_key),
  UNIQUE (route_key_hash)
);
ALTER TABLE channel_connections ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_connections_tenant_namespace ON channel_connections(tenant_root, namespace, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_channel_connections_health ON channel_connections(namespace, health_state, last_success_at DESC);

CREATE TABLE IF NOT EXISTS channel_credentials (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('telegram','slack','gmail','google_chat')),
  secret_type TEXT NOT NULL,
  credential_version INTEGER NOT NULL CHECK (credential_version > 0),
  status TEXT NOT NULL CHECK (status IN ('active','rollback','revoked')),
  envelope_format TEXT NOT NULL CHECK (envelope_format = 'channel-secret/v1'),
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  kek_id TEXT NOT NULL,
  key_version INTEGER NOT NULL CHECK (key_version > 0),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  rotated_at TIMESTAMPTZ,
  rollback_expires_at TIMESTAMPTZ,
  revoked_by TEXT,
  revoked_at TIMESTAMPTZ,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  UNIQUE (namespace, id),
  UNIQUE (namespace, connection_id, secret_type, credential_version)
);
ALTER TABLE channel_credentials ENABLE ROW LEVEL SECURITY;
CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_credentials_one_active ON channel_credentials(namespace, connection_id, secret_type) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_channel_credentials_runtime ON channel_credentials(namespace, connection_id, status, credential_version DESC);
CREATE RULE channel_credentials_protected_fields_immutable AS ON UPDATE TO channel_credentials
  WHERE (
    OLD.id IS DISTINCT FROM NEW.id OR
    OLD.tenant_root IS DISTINCT FROM NEW.tenant_root OR
    OLD.namespace IS DISTINCT FROM NEW.namespace OR
    OLD.connection_id IS DISTINCT FROM NEW.connection_id OR
    OLD.provider IS DISTINCT FROM NEW.provider OR
    OLD.secret_type IS DISTINCT FROM NEW.secret_type OR
    OLD.credential_version IS DISTINCT FROM NEW.credential_version OR
    OLD.envelope_format IS DISTINCT FROM NEW.envelope_format OR
    OLD.ciphertext IS DISTINCT FROM NEW.ciphertext OR
    OLD.nonce IS DISTINCT FROM NEW.nonce OR
    OLD.auth_tag IS DISTINCT FROM NEW.auth_tag OR
    OLD.kek_id IS DISTINCT FROM NEW.kek_id OR
    OLD.key_version IS DISTINCT FROM NEW.key_version OR
    OLD.created_by IS DISTINCT FROM NEW.created_by OR
    OLD.created_at IS DISTINCT FROM NEW.created_at OR
    OLD.rotated_at IS DISTINCT FROM NEW.rotated_at
  )
  DO ALSO INSERT INTO channel_immutable_update_guard (violation) VALUES ('channel_credentials_protected_fields');
CREATE RULE channel_credentials_lifecycle_forward_only AS ON UPDATE TO channel_credentials
  WHERE NOT (
    OLD.status = NEW.status OR
    (OLD.status = 'active' AND NEW.status IN ('rollback','revoked')) OR
    (OLD.status = 'rollback' AND NEW.status IN ('active','revoked'))
  )
  DO ALSO INSERT INTO channel_immutable_update_guard (violation) VALUES ('channel_credentials_lifecycle');

CREATE TABLE IF NOT EXISTS agent_channel_grants (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  inbound_allowed BOOLEAN NOT NULL,
  outbound_allowed BOOLEAN NOT NULL,
  memory_allowed BOOLEAN NOT NULL DEFAULT FALSE,
  system_test BOOLEAN NOT NULL DEFAULT FALSE,
  verification_only BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  authority_epoch BIGINT NOT NULL CHECK (authority_epoch >= 0),
  credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  revoked_by TEXT,
  revoked_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  CHECK (NOT verification_only OR system_test),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CONSTRAINT agent_channel_grants_key_tenant_fkey FOREIGN KEY (tenant_root, key_id) REFERENCES api_keys(tenant_root, id),
  UNIQUE (namespace, id),
  UNIQUE (namespace, connection_id, id, revision),
  UNIQUE (namespace, connection_id, revision)
);
ALTER TABLE agent_channel_grants ENABLE ROW LEVEL SECURITY;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_channel_grants_one_active ON agent_channel_grants(namespace, connection_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_agent_channel_grants_key ON agent_channel_grants(key_id, status, expires_at);
CREATE RULE agent_channel_grants_protected_fields_immutable AS ON UPDATE TO agent_channel_grants
  WHERE (
    OLD.id IS DISTINCT FROM NEW.id OR
    OLD.tenant_root IS DISTINCT FROM NEW.tenant_root OR
    OLD.namespace IS DISTINCT FROM NEW.namespace OR
    OLD.connection_id IS DISTINCT FROM NEW.connection_id OR
    OLD.key_id IS DISTINCT FROM NEW.key_id OR
    OLD.revision IS DISTINCT FROM NEW.revision OR
    OLD.inbound_allowed IS DISTINCT FROM NEW.inbound_allowed OR
    OLD.outbound_allowed IS DISTINCT FROM NEW.outbound_allowed OR
    OLD.memory_allowed IS DISTINCT FROM NEW.memory_allowed OR
    OLD.system_test IS DISTINCT FROM NEW.system_test OR
    OLD.verification_only IS DISTINCT FROM NEW.verification_only OR
    OLD.authority_epoch IS DISTINCT FROM NEW.authority_epoch OR
    OLD.credential_version IS DISTINCT FROM NEW.credential_version OR
    OLD.created_by IS DISTINCT FROM NEW.created_by OR
    OLD.created_at IS DISTINCT FROM NEW.created_at OR
    OLD.expires_at IS DISTINCT FROM NEW.expires_at
  )
  DO ALSO INSERT INTO channel_immutable_update_guard (violation) VALUES ('agent_channel_grants_protected_fields');
CREATE RULE agent_channel_grants_lifecycle_forward_only AS ON UPDATE TO agent_channel_grants
  WHERE NOT (
    OLD.status = NEW.status OR
    (OLD.status = 'active' AND NEW.status IN ('revoked','expired'))
  )
  DO ALSO INSERT INTO channel_immutable_update_guard (violation) VALUES ('agent_channel_grants_lifecycle');

CREATE TABLE IF NOT EXISTS channel_ingress_receipts (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('telegram','slack','gmail','google_chat')),
  provider_event_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  state TEXT NOT NULL CHECK (state IN ('processing','accepted','denied','retryable')),
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts > 0),
  failure_code TEXT,
  accepted_event_id TEXT,
  accepted_response_kind TEXT CHECK (accepted_response_kind IN ('event','challenge','verification','notification')),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  CHECK ((state = 'processing') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (state <> 'accepted' OR accepted_response_kind IS NOT NULL),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  UNIQUE (namespace, connection_id, id),
  UNIQUE (namespace, connection_id, provider_event_key)
);
ALTER TABLE channel_ingress_receipts ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_receipts_reclaim ON channel_ingress_receipts(state, lease_expires_at, updated_at);

CREATE TABLE IF NOT EXISTS channel_events (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  receipt_id TEXT,
  provider TEXT NOT NULL CHECK (provider IN ('telegram','slack','gmail','google_chat')),
  provider_event_key TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
  conversation_key TEXT NOT NULL,
  thread_key TEXT,
  occurred_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  normalized_text TEXT NOT NULL,
  participant_principals JSONB NOT NULL DEFAULT '[]',
  resource_groups JSONB NOT NULL DEFAULT '[]',
  attachment_metadata JSONB NOT NULL DEFAULT '[]',
  provenance JSONB NOT NULL,
  reply_target JSONB NOT NULL,
  pii_subjects JSONB NOT NULL DEFAULT '[]',
  consent_state JSONB NOT NULL,
  handoff_state JSONB NOT NULL,
  classification JSONB NOT NULL,
  source_access JSONB NOT NULL,
  processing_state TEXT NOT NULL CHECK (processing_state IN ('accepted','dispatching','dispatched','completed','denied','failed')),
  authority_epoch BIGINT NOT NULL CHECK (authority_epoch >= 0),
  credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
  grant_id TEXT NOT NULL,
  grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CONSTRAINT channel_events_receipt_tenant_fkey FOREIGN KEY (namespace, connection_id, receipt_id) REFERENCES channel_ingress_receipts(namespace, connection_id, id) ON DELETE SET NULL (receipt_id),
  CONSTRAINT channel_events_grant_tenant_revision_fkey FOREIGN KEY (namespace, connection_id, grant_id, grant_revision) REFERENCES agent_channel_grants(namespace, connection_id, id, revision),
  UNIQUE (namespace, connection_id, id),
  UNIQUE (namespace, connection_id, provider_event_key)
);
ALTER TABLE channel_events ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_events_conversation ON channel_events(namespace, connection_id, conversation_key, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_channel_events_processing ON channel_events(namespace, processing_state, updated_at);

ALTER TABLE channel_ingress_receipts DROP CONSTRAINT IF EXISTS channel_ingress_receipts_accepted_event_id_fkey;
ALTER TABLE channel_ingress_receipts ADD CONSTRAINT channel_ingress_receipts_accepted_event_tenant_fkey FOREIGN KEY (namespace, connection_id, accepted_event_id) REFERENCES channel_events(namespace, connection_id, id) ON DELETE SET NULL (accepted_event_id);

CREATE TABLE IF NOT EXISTS channel_send_intents (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  reply_ordinal INTEGER NOT NULL CHECK (reply_ordinal >= 0),
  approved_text TEXT NOT NULL,
  classification JSONB NOT NULL,
  target JSONB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','attempted','confirmed','retryable','terminal','outcome_unknown','operator_required')),
  authority_epoch BIGINT NOT NULL CHECK (authority_epoch >= 0),
  credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
  grant_id TEXT NOT NULL,
  grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
  documented_idempotency_key TEXT,
  provider_message_id TEXT,
  next_attempt_at TIMESTAMPTZ,
  operator_resolution TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CONSTRAINT channel_send_intents_source_event_tenant_fkey FOREIGN KEY (namespace, connection_id, source_event_id) REFERENCES channel_events(namespace, connection_id, id) ON DELETE CASCADE,
  CONSTRAINT channel_send_intents_grant_tenant_revision_fkey FOREIGN KEY (namespace, connection_id, grant_id, grant_revision) REFERENCES agent_channel_grants(namespace, connection_id, id, revision),
  UNIQUE (namespace, connection_id, id),
  UNIQUE (namespace, connection_id, source_event_id, reply_ordinal)
);
ALTER TABLE channel_send_intents ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_send_claim ON channel_send_intents(state, next_attempt_at, updated_at);

CREATE TABLE IF NOT EXISTS channel_delivery_attempts (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  send_intent_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
  worker_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('attempted','confirmed','retryable','terminal','outcome_unknown')),
  provider_status TEXT,
  provider_message_id TEXT,
  retry_at TIMESTAMPTZ,
  sanitized_error_code TEXT,
  audit_seq BIGINT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CONSTRAINT channel_delivery_attempts_send_intent_tenant_fkey FOREIGN KEY (namespace, connection_id, send_intent_id) REFERENCES channel_send_intents(namespace, connection_id, id) ON DELETE CASCADE,
  CONSTRAINT channel_delivery_attempts_audit_tenant_fkey FOREIGN KEY (namespace, audit_seq) REFERENCES audit_log(namespace, seq),
  UNIQUE (namespace, connection_id, send_intent_id, attempt_number)
);
ALTER TABLE channel_delivery_attempts ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_delivery_recent ON channel_delivery_attempts(namespace, connection_id, created_at DESC);

CREATE TABLE IF NOT EXISTS channel_runtime_state (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  state_kind TEXT NOT NULL CHECK (state_kind IN ('subscription','gmail_history','gmail_watch','poll_lease','worker_heartbeat','cutover','health','credential_migration')),
  state_key TEXT NOT NULL,
  state_value JSONB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  UNIQUE (namespace, connection_id, state_kind, state_key)
);
ALTER TABLE channel_runtime_state ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_runtime_expiry ON channel_runtime_state(state_kind, expires_at);

CREATE TABLE IF NOT EXISTS channel_oauth_sessions (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('slack','gmail')),
  state_hash TEXT NOT NULL UNIQUE CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  initiating_user_id TEXT NOT NULL,
  initiating_session_hash TEXT NOT NULL CHECK (initiating_session_hash ~ '^[0-9a-f]{64}$'),
  redirect_uri TEXT NOT NULL,
  nonce_hash TEXT NOT NULL CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  expected_provider_account TEXT NOT NULL,
  pkce_challenge TEXT,
  verifier_envelope JSONB,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CHECK ((provider = 'gmail') = (pkce_challenge IS NOT NULL AND verifier_envelope IS NOT NULL))
);
ALTER TABLE channel_oauth_sessions ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_oauth_expiry ON channel_oauth_sessions(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS channel_verifications (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('telegram','slack','gmail','google_chat')),
  binding_hash TEXT NOT NULL CHECK (binding_hash ~ '^[0-9a-f]{64}$'),
  probe_results JSONB NOT NULL,
  evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
  provider_event_hash TEXT,
  provider_message_hash TEXT,
  ingress_to_acceptance_ms INTEGER NOT NULL CHECK (ingress_to_acceptance_ms >= 0),
  dispatch_ms INTEGER NOT NULL CHECK (dispatch_ms >= 0),
  provider_send_ms INTEGER NOT NULL CHECK (provider_send_ms >= 0),
  end_to_end_ms INTEGER NOT NULL CHECK (end_to_end_ms >= 0),
  credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
  grant_id TEXT NOT NULL,
  grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
  authority_epoch BIGINT NOT NULL CHECK (authority_epoch >= 0),
  ownership_generation BIGINT NOT NULL CHECK (ownership_generation > 0),
  deployment_config_version TEXT NOT NULL,
  infrastructure_version TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  CONSTRAINT channel_verifications_grant_tenant_revision_fkey FOREIGN KEY (namespace, connection_id, grant_id, grant_revision) REFERENCES agent_channel_grants(namespace, connection_id, id, revision)
);
ALTER TABLE channel_verifications ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_verification_binding ON channel_verifications(namespace, connection_id, binding_hash, expires_at DESC);

CREATE TABLE IF NOT EXISTS channel_shadow_comparisons (
  id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  source_runtime TEXT NOT NULL,
  event_hash TEXT NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  normalization_hash_expected TEXT NOT NULL,
  normalization_hash_actual TEXT NOT NULL,
  classification_hash_expected TEXT NOT NULL,
  classification_hash_actual TEXT NOT NULL,
  tenant_mapping_hash_expected TEXT NOT NULL,
  tenant_mapping_hash_actual TEXT NOT NULL,
  event_identity_hash_expected TEXT NOT NULL,
  event_identity_hash_actual TEXT NOT NULL,
  routing_hash_expected TEXT NOT NULL,
  routing_hash_actual TEXT NOT NULL,
  outbound_serialization_hash_expected TEXT NOT NULL,
  outbound_serialization_hash_actual TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('matched','mismatched')),
  differences JSONB NOT NULL DEFAULT '[]',
  received_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
  UNIQUE (namespace, connection_id, source_runtime, event_hash)
);
ALTER TABLE channel_shadow_comparisons ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_shadow_status ON channel_shadow_comparisons(namespace, connection_id, status, received_at DESC);

CREATE TABLE IF NOT EXISTS channel_ownership_leases (
  connection_id TEXT PRIMARY KEY,
  tenant_root TEXT NOT NULL,
  namespace TEXT NOT NULL,
  desired_owner TEXT NOT NULL CHECK (desired_owner IN ('storefront','halomem')),
  observed_owner TEXT,
  desired_endpoint_id TEXT,
  observed_endpoint_id TEXT,
  generation BIGINT NOT NULL CHECK (generation > 0),
  authority_epoch BIGINT NOT NULL CHECK (authority_epoch >= 0),
  lease_holder TEXT NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  observed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (tenant_root = split_part(namespace, '/', 1)),
  FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE
);
ALTER TABLE channel_ownership_leases ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_channel_ownership_expiry ON channel_ownership_leases(lease_expires_at, desired_owner, observed_owner);

ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check CHECK (kind IN ('write','live-query','source-sync','movement','automation','usage-close','usage-emit','copilot-routine','channel-ingress','channel-dispatch','channel-outbound','channel-maintenance','channel-verification'));
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS priority_class TEXT NOT NULL DEFAULT 'standard' CHECK (priority_class IN ('standard','pinned'));
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS connection_id TEXT;
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS authority_epoch BIGINT;
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS credential_version INTEGER;
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS grant_id TEXT;
ALTER TABLE durable_jobs ADD COLUMN IF NOT EXISTS grant_revision INTEGER;
ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_connection_tenant_fkey FOREIGN KEY (namespace, connection_id) REFERENCES channel_connections(namespace, id) ON DELETE CASCADE;
ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_grant_tenant_revision_fkey FOREIGN KEY (namespace, connection_id, grant_id, grant_revision) REFERENCES agent_channel_grants(namespace, connection_id, id, revision);
ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_channel_fence_check CHECK (kind NOT LIKE 'channel-%' OR (connection_id IS NOT NULL AND authority_epoch IS NOT NULL AND credential_version IS NOT NULL));
CREATE INDEX IF NOT EXISTS idx_durable_jobs_channel_claim ON durable_jobs(priority_class DESC, state, available_at, lease_expires_at, created_at) WHERE kind LIKE 'channel-%';`;
    },
  },
  {
    version: 66,
    name: "channel-verification-grant-slot",
    sql(): string {
      return `
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS principal_purpose TEXT NOT NULL DEFAULT 'general' CHECK (principal_purpose IN ('general','channel_verification'));
ALTER TABLE channel_verifications ADD COLUMN IF NOT EXISTS ownership_state TEXT NOT NULL DEFAULT 'lease' CHECK (ownership_state IN ('none','lease'));
ALTER TABLE channel_verifications DROP CONSTRAINT IF EXISTS channel_verifications_ownership_generation_check;
ALTER TABLE channel_verifications ADD CONSTRAINT channel_verifications_ownership_state_generation_check CHECK ((ownership_state = 'none' AND ownership_generation = 0) OR (ownership_state = 'lease' AND ownership_generation > 0));
DROP INDEX IF EXISTS idx_agent_channel_grants_one_active;
CREATE UNIQUE INDEX idx_agent_channel_grants_one_active
  ON agent_channel_grants(namespace, connection_id)
  WHERE status = 'active' AND verification_only = FALSE;
CREATE UNIQUE INDEX idx_agent_channel_grants_one_active_verification
  ON agent_channel_grants(namespace, connection_id)
  WHERE status = 'active' AND verification_only = TRUE;`;
    },
  },
  {
    version: 67,
    name: "channel-executable-cohorts-2-3",
    // The C2/C3 additive contract change the C0 contract reserved: widen the
    // executable kind/provider CHECKs from the four first-cohort providers to
    // the sixteen runnable channels. Voice Web, Voice Phone, and WhatsApp T16
    // stay excluded until their dedicated workers exist.
    sql(): string {
      const kinds =
        "'telegram','slack','gmail','google_chat','whatsapp_cloud','instagram'," +
        "'messenger','x','sms','sendgrid_email','outlook','line'," +
        "'microsoft_teams','website_widget','custom_api','discord'";
      return `
ALTER TABLE channel_connections DROP CONSTRAINT IF EXISTS channel_connections_kind_check;
ALTER TABLE channel_connections ADD CONSTRAINT channel_connections_kind_check CHECK (kind IN (${kinds}));
ALTER TABLE channel_credentials DROP CONSTRAINT IF EXISTS channel_credentials_provider_check;
ALTER TABLE channel_credentials ADD CONSTRAINT channel_credentials_provider_check CHECK (provider IN (${kinds}));
ALTER TABLE channel_ingress_receipts DROP CONSTRAINT IF EXISTS channel_ingress_receipts_provider_check;
ALTER TABLE channel_ingress_receipts ADD CONSTRAINT channel_ingress_receipts_provider_check CHECK (provider IN (${kinds}));
ALTER TABLE channel_events DROP CONSTRAINT IF EXISTS channel_events_provider_check;
ALTER TABLE channel_events ADD CONSTRAINT channel_events_provider_check CHECK (provider IN (${kinds}));
ALTER TABLE channel_verifications DROP CONSTRAINT IF EXISTS channel_verifications_provider_check;
ALTER TABLE channel_verifications ADD CONSTRAINT channel_verifications_provider_check CHECK (provider IN (${kinds}));
ALTER TABLE channel_oauth_sessions DROP CONSTRAINT IF EXISTS channel_oauth_sessions_provider_check;
ALTER TABLE channel_oauth_sessions ADD CONSTRAINT channel_oauth_sessions_provider_check CHECK (provider IN ('slack','gmail','outlook','instagram','messenger','whatsapp_cloud','x'));
ALTER TABLE channel_oauth_sessions DROP CONSTRAINT IF EXISTS channel_oauth_sessions_check1;
ALTER TABLE channel_oauth_sessions ADD CONSTRAINT channel_oauth_sessions_pkce_check CHECK (provider NOT IN ('gmail','outlook') OR (pkce_challenge IS NOT NULL AND verifier_envelope IS NOT NULL))`;
    },
  },
  {
    version: 68,
    name: "onboarding-completion-flag",
    // The mandatory-setup gate's server-side record: a one-way latch stamped
    // when the org's setup checklist FIRST derives complete. NULL = the
    // console stays locked on the setup surface. ALTER only — no new table,
    // so no RLS statement is needed.
    sql(): string {
      return `
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMPTZ;`;
    },
  },
  {
    version: 69,
    name: "drop-legacy-teams-table",
    // The verified-setup bootstrap table (v16) was superseded by org_teams
    // (v37) and one-way backfilled in v45. As of this version nothing reads
    // or writes it — the checklist and the one-shot setup service both use
    // org_teams — so the duplicate team directory is removed.
    // setup_operations.team_namespace keeps its value as a plain historical
    // column: re-pointing the FK at org_teams would block console team
    // deletion for setup-created teams. DROP only, no new table, so no RLS
    // statement is needed.
    sql(): string {
      return `
ALTER TABLE setup_operations DROP CONSTRAINT IF EXISTS setup_operations_team_namespace_fkey;
DROP TABLE IF EXISTS teams;`;
    },
  },
  {
    version: 70,
    name: "oauth-connect",
    // CONTRACTS-OAUTH-CONNECT.md: the user-delegated half of the D29 AS —
    // authorization_code + PKCE, dynamic client registration, refresh-token
    // rotation. Everything credential-shaped stays sha256-at-rest (E23):
    //  - oauth_clients grows auth_method/grant_types/origin, and the secret
    //    hash becomes NULLABLE — NULL ⇔ public (PKCE-only) client. The old
    //    inline CHECK is dropped by its auto-generated name and re-added
    //    NULL-tolerant.
    //  - oauth_tokens grows user_id + grant_kind (defaulted so every existing
    //    row backfills as the client_credentials grant it was).
    //  - oauth_refresh_tokens: rotation chain (family_id / rotated_to) is the
    //    theft-detection unit — reuse of a rotated token revokes the family.
    //  - oauth_authorization_codes: single-use rows binding client, PKCE
    //    challenge, redirect_uri, and the consenting user's subject snapshot;
    //    consumed transactionally, minted-token backrefs enable replay revoke.
    // New tables get RLS per the post-M9 schema convention.
    sql(): string {
      return `
    ALTER TABLE oauth_clients
      ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'client_secret_basic'
        CHECK (auth_method IN ('client_secret_basic','none')),
      ADD COLUMN IF NOT EXISTS grant_types JSONB NOT NULL DEFAULT '["client_credentials"]'
        CHECK (jsonb_typeof(grant_types) = 'array'),
      ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'admin'
        CHECK (origin IN ('admin','dcr'));
    ALTER TABLE oauth_clients
      DROP CONSTRAINT IF EXISTS oauth_clients_client_secret_hash_check;
    ALTER TABLE oauth_clients ALTER COLUMN client_secret_hash DROP NOT NULL;
    ALTER TABLE oauth_clients
      ADD CONSTRAINT oauth_clients_client_secret_hash_check
        CHECK (client_secret_hash IS NULL OR client_secret_hash ~ '^[0-9a-f]{64}$');

    ALTER TABLE oauth_tokens
      ADD COLUMN IF NOT EXISTS user_id TEXT,
      ADD COLUMN IF NOT EXISTS grant_kind TEXT NOT NULL DEFAULT 'client_credentials'
        CHECK (grant_kind IN ('client_credentials','authorization_code','refresh_token'));

    CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
      id               TEXT PRIMARY KEY,
      namespace        TEXT NOT NULL,
      client_ref       TEXT NOT NULL REFERENCES oauth_clients(id),
      user_id          TEXT,
      actor            TEXT NOT NULL,
      token_role       TEXT NOT NULL CHECK (token_role IN ('assistant','read-only')),
      allowed_tools    JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(allowed_tools) = 'array'),
      token_hash       TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
      family_id        TEXT NOT NULL,
      access_token_ref TEXT REFERENCES oauth_tokens(id),
      status           TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','rotated','revoked')),
      rotated_to       TEXT REFERENCES oauth_refresh_tokens(id),
      revoked_reason   TEXT,
      issued_at        TIMESTAMPTZ NOT NULL,
      expires_at       TIMESTAMPTZ NOT NULL,
      last_used        TIMESTAMPTZ,
      revoked_at       TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family
      ON oauth_refresh_tokens(family_id, status);
    CREATE INDEX IF NOT EXISTS idx_oauth_refresh_client
      ON oauth_refresh_tokens(client_ref, status);

    CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
      id                TEXT PRIMARY KEY,
      code_hash         TEXT NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
      client_ref        TEXT NOT NULL REFERENCES oauth_clients(id),
      user_id           TEXT NOT NULL,
      namespace         TEXT NOT NULL,
      actor             TEXT NOT NULL,
      token_role        TEXT NOT NULL CHECK (token_role IN ('assistant','read-only')),
      allowed_tools     JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(allowed_tools) = 'array'),
      redirect_uri      TEXT NOT NULL,
      code_challenge    TEXT NOT NULL,
      scope             TEXT NOT NULL DEFAULT '',
      status            TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','consumed','void')),
      access_token_ref  TEXT REFERENCES oauth_tokens(id),
      refresh_token_ref TEXT REFERENCES oauth_refresh_tokens(id),
      issued_at         TIMESTAMPTZ NOT NULL,
      expires_at        TIMESTAMPTZ NOT NULL,
      consumed_at       TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_codes_client
      ON oauth_authorization_codes(client_ref, status, issued_at);

    ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
    ALTER TABLE oauth_authorization_codes ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 71,
    name: "channel-socket-state",
    // Socket-delivered channels (a paired WhatsApp account today) keep a
    // provider session that survives restarts: pairing state, signal keys,
    // registration. It is credential material, so it is stored ONLY as a
    // sealed envelope under the channel KEK, keyed by connection — never in
    // plaintext, never outside the tenant's namespace. RLS per the post-M9
    // convention (owner/service_role bypasses it, so the kernel is unaffected).
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS channel_socket_state (
      tenant_root    TEXT NOT NULL,
      namespace      TEXT NOT NULL,
      connection_id  TEXT NOT NULL,
      state_key      TEXT NOT NULL CHECK (char_length(state_key) BETWEEN 1 AND 200),
      sealed_state   JSONB NOT NULL,
      updated_at     TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (namespace, connection_id, state_key)
    );
    CREATE INDEX IF NOT EXISTS idx_channel_socket_state_connection
      ON channel_socket_state(namespace, connection_id);
    ALTER TABLE channel_socket_state ENABLE ROW LEVEL SECURITY`;
    },
  },
  {
    version: 72,
    name: "assistant-observability",
    // CONTRACTS-ASSISTANT-OBSERVABILITY.md. Analytics tables intentionally
    // contain references and allowlisted metadata only; transcripts remain in
    // the encrypted Copilot conversation authority.
    sql(): string {
      return `
CREATE TABLE IF NOT EXISTS model_price_daily (
  id TEXT PRIMARY KEY,
  price_date DATE NOT NULL,
  provider_key TEXT NOT NULL,
  model TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  input_usd_per_million REAL,
  output_usd_per_million REAL,
  basis TEXT NOT NULL CHECK (basis IN ('provider_catalog','admin_catalog','unavailable')),
  source_version TEXT,
  captured_at TIMESTAMPTZ NOT NULL,
  CHECK (input_usd_per_million IS NULL OR input_usd_per_million >= 0),
  CHECK (output_usd_per_million IS NULL OR output_usd_per_million >= 0),
  CHECK ((basis = 'unavailable' AND input_usd_per_million IS NULL AND output_usd_per_million IS NULL) OR (basis <> 'unavailable' AND input_usd_per_million IS NOT NULL AND output_usd_per_million IS NOT NULL)),
  UNIQUE (price_date, provider_key, model, currency)
);
ALTER TABLE model_price_daily ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_model_price_daily_lookup
  ON model_price_daily(provider_key, model, price_date DESC);

CREATE TABLE IF NOT EXISTS assistant_actor_lifecycle (
  namespace TEXT NOT NULL,
  actor_hash TEXT NOT NULL CHECK (actor_hash ~ '^[0-9a-f]{64}$'),
  recycled_at TIMESTAMPTZ,
  recycled_by TEXT,
  purged_at TIMESTAMPTZ,
  generation BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (namespace, actor_hash),
  CHECK (recycled_at IS NOT NULL OR recycled_by IS NULL),
  CHECK (purged_at IS NULL OR recycled_at IS NOT NULL)
);
ALTER TABLE assistant_actor_lifecycle ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_assistant_actor_lifecycle_fenced
  ON assistant_actor_lifecycle(namespace, recycled_at, purged_at)
  WHERE recycled_at IS NOT NULL OR purged_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ai_turns (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  actor TEXT NOT NULL,
  principal TEXT NOT NULL CHECK (principal IN ('human','agent')),
  source_app TEXT NOT NULL CHECK (source_app IN ('halo_assistant')),
  origin TEXT NOT NULL CHECK (origin IN ('interactive','routine')),
  conversation_id TEXT NOT NULL,
  client_turn_id TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  trace_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('accepted','running','completed','degraded','failed','denied','uncertain')),
  coverage TEXT NOT NULL CHECK (coverage IN ('full','partial','unavailable')),
  degraded_reason TEXT,
  user_message_id TEXT,
  assistant_message_id TEXT,
  evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
  operation_count INTEGER NOT NULL DEFAULT 0 CHECK (operation_count >= 0),
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  final_audit_seq BIGINT,
  recycled_at TIMESTAMPTZ,
  recycled_by TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE (namespace, id),
  UNIQUE (namespace, id, trace_id),
  UNIQUE (namespace, actor, conversation_id, client_turn_id),
  UNIQUE (namespace, trace_id)
);
ALTER TABLE ai_turns ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_ai_turns_namespace_started
  ON ai_turns(namespace, started_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_ai_turns_actor_started
  ON ai_turns(namespace, actor, started_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_ai_turns_active
  ON ai_turns(namespace, status, started_at)
  WHERE completed_at IS NULL AND recycled_at IS NULL;

CREATE TABLE IF NOT EXISTS model_invocations (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  turn_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  attempt INTEGER NOT NULL CHECK (attempt > 0),
  profile_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider_id TEXT,
  provider_protocol TEXT NOT NULL,
  model TEXT NOT NULL,
  hosting TEXT NOT NULL,
  model_source TEXT NOT NULL,
  runtime TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running','completed','failed','uncertain')),
  failure_class TEXT,
  provider_request_id TEXT,
  input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
  output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
  token_basis TEXT NOT NULL CHECK (token_basis IN ('provider_reported','estimated','unavailable')),
  input_usd REAL CHECK (input_usd IS NULL OR input_usd >= 0),
  output_usd REAL CHECK (output_usd IS NULL OR output_usd >= 0),
  total_usd REAL CHECK (total_usd IS NULL OR total_usd >= 0),
  cost_basis TEXT NOT NULL CHECK (cost_basis IN ('provider_reported','catalog_estimate','unavailable')),
  price_snapshot_id TEXT NOT NULL REFERENCES model_price_daily(id),
  pricing_version TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  recycled_at TIMESTAMPTZ,
  UNIQUE (namespace, id),
  UNIQUE (namespace, turn_id, attempt),
  FOREIGN KEY (namespace, turn_id, trace_id)
    REFERENCES ai_turns(namespace, id, trace_id) ON DELETE RESTRICT
);
ALTER TABLE model_invocations ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_model_invocations_namespace_started
  ON model_invocations(namespace, started_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_trace
  ON model_invocations(namespace, trace_id, attempt);
CREATE INDEX IF NOT EXISTS idx_model_invocations_price
  ON model_invocations(price_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_active
  ON model_invocations(namespace, status, started_at)
  WHERE completed_at IS NULL AND recycled_at IS NULL;

ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS invocation_id TEXT;
ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS recycled_at TIMESTAMPTZ;
ALTER TABLE cost_ledger ADD CONSTRAINT cost_ledger_invocation_fkey
  FOREIGN KEY (namespace, invocation_id)
  REFERENCES model_invocations(namespace, id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cost_ledger_invocation_unique
  ON cost_ledger(invocation_id) WHERE invocation_id IS NOT NULL;

ALTER TABLE copilot_conversations ADD COLUMN IF NOT EXISTS recycled_at TIMESTAMPTZ;
ALTER TABLE copilot_conversations ADD COLUMN IF NOT EXISTS recycled_by TEXT;`;
    },
  },
  {
    version: 73,
    name: "console-settings-identity",
    // CONTRACTS-CONSOLE-SETTINGS.md. Two display-only identity fields the
    // Settings screen owns: a person's own name, and the organization's mark.
    // Neither participates in authorization — the email is still the account
    // key and the tenant id is still the root namespace — so both are nullable
    // and a null simply means "derive it" (initials, tenant id).
    //
    // The icon is a small self-contained data URL (raster only, size-capped at
    // the write path) rather than a blob store: there is no object storage in
    // the one-database contract (D5), and a workspace mark is a few KB.
    sql(): string {
      return `
    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS icon TEXT`;
    },
  },
  {
    version: 74,
    name: "conflict-finding-resolution",
    // A scan finding could only ever be acknowledged or dismissed: both leave
    // BOTH contradicting facts live, so the conflict a reviewer just read stays
    // in memory and the next scan re-publishes it. A reviewer needs the same
    // authority the write-time dispute lane already gives them — pick the side
    // that is right and retire the other.
    //
    // Retiring is a validity close plus supersedence link (D7), never a delete,
    // so `resolution_memory_id` records the KEPT fact and the retired row stays
    // readable at its historical validity.
    sql(): string {
      return `
    ALTER TABLE conflict_scan_findings
      DROP CONSTRAINT IF EXISTS conflict_scan_findings_status_check;
    ALTER TABLE conflict_scan_findings
      ADD CONSTRAINT conflict_scan_findings_status_check
      CHECK (status IN ('open','acknowledged','dismissed','resolved'));
    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS resolution TEXT
      CHECK (resolution IN ('keep-left','keep-right'));
    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS resolution_memory_id TEXT
      REFERENCES memory_objects(id) ON DELETE SET NULL;
    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS resolved_by TEXT;
    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ`;
    },
  },
  {
    version: 75,
    name: "policy-document-adoption",
    // The register only ever knew about files uploaded through its own lane, so
    // policy files that arrived through a connector or import (D10 — same write
    // path, same provenance) were invisible on S4 while `mem_search` and
    // `mem_policy` could still see their facts. `origin` marks a row that was
    // promoted out of existing memory rather than uploaded.
    //
    // An adopted row owns no attempt lease: its facts predate it and are matched
    // by `(sourceId, documentKey, contentHash)` provenance, so deletion retracts
    // exactly the file's clauses. `attempt_token` stays NOT NULL (an adopted row
    // gets a fresh id used only as its own fence), and the partial unique index
    // on (namespace, content_sha256) keeps a file from being adopted twice.
    sql(): string {
      return `
    ALTER TABLE policy_documents
      ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'upload';
    ALTER TABLE policy_documents
      DROP CONSTRAINT IF EXISTS policy_documents_origin_check;
    ALTER TABLE policy_documents
      ADD CONSTRAINT policy_documents_origin_check
      CHECK (origin IN ('upload','adopted'))`;
    },
  },
  {
    version: 76,
    name: "api-key-issuer",
    // Who minted a credential was never stored — only narrated in the D4 audit
    // detail ("key issued: … keyId=<id>"). The console's Agent connections
    // screen needs it: that screen is the caller's OWN connections, while the
    // scope-wide ledger stays on Scoped memory. Derived data, never authority:
    // no authorization decision reads this column.
    //
    // Nullable on purpose — a first-boot bootstrap key has no caller, and rows
    // that predate this column may have no recoverable issuer. The backfill
    // recovers the issuer from the audit trail where the issuance was audited
    // (ProductKeyService writes `keyId=<id>` into the share detail), taking the
    // EARLIEST such row per key: that is the issuance, later rows about the same
    // id are rotations or revocations by someone else.
    sql(): string {
      return `
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS created_by TEXT;
    UPDATE api_keys AS k
       SET created_by = issued.actor
      FROM (
        SELECT DISTINCT ON (matched.key_id) matched.key_id, matched.actor
          FROM (
            SELECT actor,
                   substring(detail from 'keyId=([0-9A-Za-z_-]+)') AS key_id,
                   seq
              FROM audit_log
             WHERE op = 'share' AND result = 'ok' AND detail LIKE '%keyId=%'
          ) AS matched
         WHERE matched.key_id IS NOT NULL
         ORDER BY matched.key_id, matched.seq ASC
      ) AS issued
     WHERE k.id = issued.key_id AND k.created_by IS NULL;
    CREATE INDEX IF NOT EXISTS idx_api_keys_created_by
      ON api_keys(created_by, role, status)`;
    },
  },
  {
    version: 77,
    name: "user-profile-avatar",
    // A person's optional self-uploaded portrait. Like the organization mark,
    // it is presentation-only, raster-only and size-capped at the write path;
    // email remains the immutable authentication and audit key.
    sql(): string {
      return `
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT`;
    },
  },
  {
    version: 78,
    name: "organization-name-capitalization",
    // Organization ids remain stable lowercase authority handles. Only the
    // display name is repaired. The CHECK prevents any path, including direct
    // operator SQL, from reintroducing a lowercase initial character.
    sql(): string {
      return `
    UPDATE tenants
       SET name = upper(left(name, 1)) || substring(name FROM 2)
     WHERE name <> upper(left(name, 1)) || substring(name FROM 2);
    ALTER TABLE tenants
      DROP CONSTRAINT IF EXISTS tenants_name_initial_capital_check;
    ALTER TABLE tenants
      ADD CONSTRAINT tenants_name_initial_capital_check
      CHECK (name <> '' AND name = upper(left(name, 1)) || substring(name FROM 2))`;
    },
  },
  {
    version: 79,
    name: "managed-assistant-price-repair",
    // The managed GPT-5.4 mini deployment began recording explicit
    // `unavailable` snapshots because its provider rate was not wired into the
    // runtime. Azure's effective-dated Global Standard meters predate every
    // affected invocation, so this is a correction of missing evidence, not a
    // repricing at today's rate. Keep the profile/provider/model predicates
    // exact: organization BYOK and every other managed model remain untouched.
    sql(): string {
      return `
    UPDATE model_price_daily
       SET input_usd_per_million = 0.75,
           output_usd_per_million = 4.5,
           basis = 'provider_catalog',
           source_version = 'azure-retail:swedencentral:global-standard:2026-03-01:0L59+0L4P'
     WHERE provider_key = 'openai'
       AND model = 'gpt-5.4-mini-1'
       AND currency = 'USD'
       AND price_date >= DATE '2026-03-01'
       AND basis = 'unavailable'
       AND input_usd_per_million IS NULL
       AND output_usd_per_million IS NULL
       AND EXISTS (
         SELECT 1
           FROM model_invocations AS managed
          WHERE managed.price_snapshot_id = model_price_daily.id
            AND managed.profile_id = 'mastra-v2-managed'
            AND managed.provider_id = 'openai'
            AND managed.model = 'gpt-5.4-mini-1'
       )
       AND NOT EXISTS (
         SELECT 1
           FROM model_invocations AS foreign_profile
          WHERE foreign_profile.price_snapshot_id = model_price_daily.id
            AND (foreign_profile.profile_id <> 'mastra-v2-managed'
              OR foreign_profile.provider_id IS DISTINCT FROM 'openai'
              OR foreign_profile.model <> 'gpt-5.4-mini-1')
       );

    WITH repaired AS (
      UPDATE model_invocations AS invocation
         SET input_usd = invocation.input_tokens * 0.75 / 1000000.0,
             output_usd = invocation.output_tokens * 4.5 / 1000000.0,
             total_usd = (invocation.input_tokens * 0.75 +
                          invocation.output_tokens * 4.5) / 1000000.0,
             cost_basis = 'catalog_estimate',
             pricing_version = 'azure-retail:swedencentral:global-standard:2026-03-01:0L59+0L4P'
        FROM model_price_daily AS price
       WHERE invocation.price_snapshot_id = price.id
         AND price.provider_key = 'openai'
         AND price.model = 'gpt-5.4-mini-1'
         AND price.currency = 'USD'
         AND price.source_version = 'azure-retail:swedencentral:global-standard:2026-03-01:0L59+0L4P'
         AND invocation.profile_id = 'mastra-v2-managed'
         AND invocation.provider_id = 'openai'
         AND invocation.model = 'gpt-5.4-mini-1'
         AND invocation.status = 'completed'
         AND invocation.cost_basis = 'unavailable'
         AND invocation.input_tokens IS NOT NULL
         AND invocation.output_tokens IS NOT NULL
      RETURNING invocation.id, invocation.namespace, invocation.turn_id,
                invocation.trace_id, invocation.input_tokens,
                invocation.output_tokens, invocation.total_usd,
                invocation.started_at, invocation.completed_at
    ), inserted AS (
      INSERT INTO cost_ledger
        (id, namespace, kind, tokens, usd, ts, actor, trace_id, invocation_id)
      SELECT 'assistant-price-repair:' || repaired.id,
             repaired.namespace,
             'llm',
             repaired.input_tokens + repaired.output_tokens,
             repaired.total_usd,
             COALESCE(repaired.completed_at, repaired.started_at),
             turn.actor,
             repaired.trace_id,
             repaired.id
        FROM repaired
        JOIN ai_turns AS turn
          ON turn.namespace = repaired.namespace
         AND turn.id = repaired.turn_id
         AND turn.trace_id = repaired.trace_id
      ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING
      RETURNING namespace, trace_id, usd
    )
    UPDATE query_traces AS trace
       SET usd = COALESCE(trace.usd, 0) + inserted.usd
      FROM inserted
     WHERE trace.namespace = inserted.namespace
       AND trace.trace_id = inserted.trace_id`;
    },
  },
  {
    version: 80,
    name: "model-profile-assistant-enablement",
    // A configured model may remain available to operators without appearing
    // in Assistant routing. Defaults must always be both active and enabled;
    // lifecycle operations repair that invariant transactionally.
    sql(): string {
      return `
    ALTER TABLE model_profiles
      ADD COLUMN IF NOT EXISTS assistant_enabled BOOLEAN NOT NULL DEFAULT TRUE;
    UPDATE model_profiles
       SET assistant_enabled = FALSE,
           is_default = FALSE
     WHERE status <> 'active';
    ALTER TABLE model_profiles
      DROP CONSTRAINT IF EXISTS model_profiles_default_enabled_check;
    ALTER TABLE model_profiles
      ADD CONSTRAINT model_profiles_default_enabled_check
      CHECK (is_default = FALSE OR (status = 'active' AND assistant_enabled = TRUE));
    CREATE INDEX IF NOT EXISTS idx_model_profiles_assistant_visible
      ON model_profiles(namespace, is_default, created_at)
      WHERE status = 'active' AND assistant_enabled = TRUE`;
    },
  },
  {
    version: 81,
    name: "skill-labels-and-vocabulary",
    // S16 discovery labels are deliberately outside the immutable skill file.
    // They follow the stable (namespace, skill_key) identity across D7
    // supersedence, while the append-only history records every human change.
    // Handling tags are stored separately from user tags and are written only
    // by the vetting pipeline.
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS skill_labels (
      namespace TEXT NOT NULL,
      skill_key TEXT NOT NULL,
      category TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 80),
      purpose TEXT NOT NULL DEFAULT '' CHECK (length(purpose) <= 140),
      tags JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(tags) = 'array'),
      handling JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(handling) = 'array'),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_by TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (namespace, skill_key)
    );
    ALTER TABLE skill_labels ENABLE ROW LEVEL SECURITY;

    CREATE TABLE IF NOT EXISTS skill_label_history (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      skill_key TEXT NOT NULL,
      skill_id TEXT NOT NULL REFERENCES skills(id),
      field TEXT NOT NULL CHECK (field IN ('category','purpose','tags')),
      before_value JSONB NOT NULL,
      after_value JSONB NOT NULL,
      changed_by TEXT NOT NULL,
      changed_at TIMESTAMPTZ NOT NULL
    );
    ALTER TABLE skill_label_history ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_skill_label_history_key
      ON skill_label_history(namespace, skill_key, changed_at DESC);

    CREATE TABLE IF NOT EXISTS skill_categories (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, name)
    );
    ALTER TABLE skill_categories ENABLE ROW LEVEL SECURITY;

    CREATE TABLE IF NOT EXISTS skill_tags (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
      facet TEXT NOT NULL CHECK (facet IN ('Systems','Action','Data','Function','Lifecycle')),
      aliases JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(aliases) = 'array'),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      UNIQUE (namespace, name)
    );
    ALTER TABLE skill_tags ENABLE ROW LEVEL SECURITY;

    INSERT INTO skill_labels
      (namespace, skill_key, category, purpose, tags, handling,
       created_by, created_at, updated_by, updated_at)
    SELECT current_skill.namespace,
           current_skill.skill_key,
           CASE
             WHEN current_skill.skill_key LIKE '%driver-%' THEN 'Retrieval Engines'
             WHEN current_skill.skill_key LIKE '%from-%' THEN 'Data Import & Connectors'
             WHEN current_skill.skill_key LIKE '%with-%' THEN 'Deployment & Storage'
             WHEN current_skill.skill_key ~ '(claude|codex|rest-agent|onboard)' THEN 'Agent Setup & Clients'
             WHEN current_skill.skill_key ~ '(remember|recall|forget|memory|namespace|improve)' THEN 'Memory Operations'
             WHEN current_skill.skill_key ~ '(summary|summarize|draft|digest)' THEN 'Content & Drafting'
             WHEN current_skill.skill_key ~ '(report|linear|deliver)' THEN 'Reporting & Delivery'
             ELSE 'Research & Analysis'
           END,
           CASE WHEN current_skill.description = '' THEN ''
             ELSE left('Use this when ' || lower(left(current_skill.description, 1)) || substring(current_skill.description FROM 2), 140)
           END,
           CASE
             WHEN current_skill.skill_key LIKE '%driver-%' THEN '["retrieval","memory","data"]'::jsonb
             WHEN current_skill.skill_key LIKE '%from-%' THEN '["import","connectors","memory"]'::jsonb
             WHEN current_skill.skill_key LIKE '%with-%' THEN '["deployment","storage","memory"]'::jsonb
             WHEN current_skill.skill_key ~ '(claude|codex|rest-agent|onboard)' THEN '["agents","setup","clients"]'::jsonb
             WHEN current_skill.skill_key ~ '(remember|recall|forget|memory|namespace|improve)' THEN '["memory","operations","governance"]'::jsonb
             WHEN current_skill.skill_key ~ '(summary|summarize|draft|digest)' THEN '["summarize","content","delivery"]'::jsonb
             ELSE '["research","analysis","knowledge"]'::jsonb
           END,
           '[]'::jsonb,
           current_skill.created_by,
           current_skill.created_at,
           current_skill.created_by,
           current_skill.updated_at
      FROM skills AS current_skill
     WHERE current_skill.t_valid_to IS NULL
    ON CONFLICT (namespace, skill_key) DO NOTHING`;
    },
  },
  {
    version: 82,
    name: "teams-v2-lifecycle",
    // Teams v2 keeps immutable addresses while adding reversible lifecycle
    // state and durable invitation history. A live (waiting OR expired)
    // invitation still occupies the email slot until it is accepted/revoked;
    // accepted and revoked rows remain as history and no longer block a new
    // invitation. Raw invitation credentials remain hash-only.
    sql(): string {
      return `
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS archived_by TEXT;
    ALTER TABLE org_teams
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
    UPDATE org_teams SET updated_at = created_at WHERE updated_at IS NULL;
    ALTER TABLE org_teams ALTER COLUMN updated_at SET NOT NULL;
    ALTER TABLE org_teams ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE auth_invitations
      ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
    ALTER TABLE auth_invitations
      ADD COLUMN IF NOT EXISTS last_reminded_at TIMESTAMPTZ;
    ALTER TABLE auth_invitations
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
    UPDATE auth_invitations SET updated_at = created_at WHERE updated_at IS NULL;
    ALTER TABLE auth_invitations ALTER COLUMN updated_at SET NOT NULL;
    ALTER TABLE auth_invitations ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE auth_invitations
      DROP CONSTRAINT IF EXISTS auth_invitations_email_key;
    DROP INDEX IF EXISTS idx_auth_invites_unique_email;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_invites_live_email
      ON auth_invitations(email)
      WHERE accepted_at IS NULL AND revoked_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_auth_invites_namespace_updated
      ON auth_invitations(namespace, updated_at DESC)`;
    },
  },
  {
    version: 83,
    name: "memory-display-titles",
    // Display titles are derived metadata, never replacements for immutable
    // memory content. Durable leases let every replica converge pending rows
    // without duplicate provider calls or cross-tenant batches.
    sql(): string {
      return `
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS display_title TEXT;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS display_title_model TEXT;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS display_title_generated_at TIMESTAMPTZ;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_status TEXT NOT NULL DEFAULT 'pending';
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_retry_at TIMESTAMPTZ;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_lease_owner TEXT;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_lease_until TIMESTAMPTZ;
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS title_last_error TEXT;
    ALTER TABLE memory_objects DROP CONSTRAINT IF EXISTS memory_objects_title_status_check;
    ALTER TABLE memory_objects ADD CONSTRAINT memory_objects_title_status_check
      CHECK (title_status IN ('pending','running','complete','failed'));
    ALTER TABLE memory_objects DROP CONSTRAINT IF EXISTS memory_objects_title_attempts_check;
    ALTER TABLE memory_objects ADD CONSTRAINT memory_objects_title_attempts_check
      CHECK (title_attempts >= 0);
    CREATE INDEX IF NOT EXISTS idx_memory_objects_title_pending
      ON memory_objects(title_status, title_retry_at, assertion_time, id)
      WHERE display_title IS NULL;

    CREATE TABLE IF NOT EXISTS memory_title_invocations (
      id TEXT PRIMARY KEY,
      memory_id TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      namespace TEXT NOT NULL,
      profile_id TEXT NOT NULL,
      provider_id TEXT,
      model TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('completed','failed')),
      failure_class TEXT,
      input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
      output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
      started_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL,
      latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0)
    );
    ALTER TABLE memory_title_invocations ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_memory_title_invocations_namespace_started
      ON memory_title_invocations(namespace, started_at DESC, id);
    CREATE INDEX IF NOT EXISTS idx_memory_title_invocations_memory
      ON memory_title_invocations(memory_id, started_at DESC)`;
    },
  },
  {
    version: 84,
    name: "conflict-autopilot",
    // CA1/CA6: write-time conflict detection runs AFTER the write commits, so
    // the committed fact id is handed to a durable outbox inside the same
    // transaction. A crash between commit and detection therefore loses no
    // check — the row is still pending — and detection can never fail a write.
    //
    // Findings from this lane share `conflict_scan_findings` with the batch
    // scan (one ledger, one fingerprint rule, one resolve path), so the table
    // gains an `origin` discriminator, an `auto_resolved` terminal status for
    // trust-rank decisions the system made itself, and NULLable scan-run ids:
    // a write-lane finding belongs to no scan run.
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS conflict_detection_queue (
      memory_id     TEXT PRIMARY KEY REFERENCES memory_objects(id) ON DELETE CASCADE,
      namespace     TEXT NOT NULL,
      enqueued_at   TIMESTAMPTZ NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','done','failed')),
      attempts      INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      retry_at      TIMESTAMPTZ,
      lease_owner   TEXT,
      lease_until   TIMESTAMPTZ,
      last_error    TEXT,
      completed_at  TIMESTAMPTZ
    );
    ALTER TABLE conflict_detection_queue ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_conflict_detection_queue_pending
      ON conflict_detection_queue(retry_at, enqueued_at, memory_id)
      WHERE status IN ('pending','running');

    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS origin TEXT
      NOT NULL DEFAULT 'scan' CHECK (origin IN ('scan','write'));
    -- Which lattice rule settled it. Stored, never re-derived: "kept the left
    -- side" is compatible with more than one rule, so inferring it back would
    -- show a reviewer a confident explanation that is simply wrong.
    ALTER TABLE conflict_scan_findings ADD COLUMN IF NOT EXISTS auto_rule TEXT
      CHECK (auto_rule IS NULL OR auto_rule IN
        ('higher-trust-wins','equal-trust-newest-wins','lower-trust-rejected'));
    ALTER TABLE conflict_scan_findings ALTER COLUMN first_scan_id DROP NOT NULL;
    ALTER TABLE conflict_scan_findings ALTER COLUMN last_scan_id DROP NOT NULL;
    ALTER TABLE conflict_scan_findings
      DROP CONSTRAINT IF EXISTS conflict_scan_findings_status_check;
    ALTER TABLE conflict_scan_findings
      ADD CONSTRAINT conflict_scan_findings_status_check
      CHECK (status IN ('open','acknowledged','dismissed','resolved','auto_resolved'));
    ALTER TABLE conflict_scan_findings
      DROP CONSTRAINT IF EXISTS conflict_scan_findings_resolution_check;
    ALTER TABLE conflict_scan_findings
      ADD CONSTRAINT conflict_scan_findings_resolution_check
      CHECK (resolution IS NULL OR resolution IN ('keep-left','keep-right'));
    CREATE INDEX IF NOT EXISTS idx_conflict_scan_findings_ledger
      ON conflict_scan_findings(target_namespace, last_seen_at DESC)
      WHERE status IN ('open','auto_resolved')`;
    },
  },
  {
    version: 85,
    name: "derived-entity-subjects",
    // CA8: a fact with no subject joins no candidate group, so the batch scan
    // walks past it. Two thirds of live memory (agent conversation) is in that
    // state, because only the ingestion lane ever derived mentions.
    //
    // Subjects are DERIVED metadata, so they land in their own column: stored
    // content stays byte-identical forever (D7), and the write path's reserved
    // `[entities: …]` annotation keeps its existing meaning. Consumers read the
    // union of both.
    sql(): string {
      return `
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS derived_entities JSONB;

    CREATE TABLE IF NOT EXISTS entity_tag_queue (
      memory_id     TEXT PRIMARY KEY REFERENCES memory_objects(id) ON DELETE CASCADE,
      namespace     TEXT NOT NULL,
      enqueued_at   TIMESTAMPTZ NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','done','failed')),
      attempts      INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      retry_at      TIMESTAMPTZ,
      lease_owner   TEXT,
      lease_until   TIMESTAMPTZ,
      last_error    TEXT,
      completed_at  TIMESTAMPTZ
    );
    ALTER TABLE entity_tag_queue ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_entity_tag_queue_pending
      ON entity_tag_queue(retry_at, enqueued_at, memory_id)
      WHERE status IN ('pending','running');

    CREATE INDEX IF NOT EXISTS idx_memory_objects_derived_entities
      ON memory_objects USING GIN (derived_entities);

    -- One-time backfill enrolment: EVERY currently-valid fact, annotated or
    -- not. derived_entities then holds the union of both subject sources for
    -- every fact, which is what lets the scan slice by subject in SQL instead
    -- of by storage order. New writes enrol themselves at commit.
    INSERT INTO entity_tag_queue (memory_id, namespace, enqueued_at, status, attempts)
    SELECT id, namespace, CURRENT_TIMESTAMP, 'pending', 0
      FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
       AND derived_entities IS NULL
    ON CONFLICT (memory_id) DO NOTHING`;
    },
  },
  {
    version: 86,
    name: "source-oauth-sessions",
    // Direct provider OAuth for source connectors (first provider: Linear).
    // Single-use hashed-state custody rows mirroring channel_oauth_sessions:
    // the state is stored sha256-only, bound to the initiating admin identity
    // snapshot, TTL-bounded, consumed transactionally by the public callback.
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS source_oauth_sessions (
      id                    TEXT PRIMARY KEY,
      namespace             TEXT NOT NULL,
      provider              TEXT NOT NULL,
      state_hash            TEXT NOT NULL UNIQUE CHECK (state_hash ~ '^[0-9a-f]{64}$'),
      initiating_identity   TEXT NOT NULL,
      target_team_id        TEXT,
      redirect_uri          TEXT NOT NULL,
      expires_at            TIMESTAMPTZ NOT NULL,
      consumed_at           TIMESTAMPTZ,
      created_at            TIMESTAMPTZ NOT NULL
    );
    ALTER TABLE source_oauth_sessions ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_source_oauth_expiry
      ON source_oauth_sessions(expires_at)`;
    },
  },
  {
    version: 87,
    name: "channel-assistant-principal",
    // Channel messages run through the built-in Halo Assistant, but the
    // immutable grant/fence model still requires an api_keys principal row.
    // This purpose is server-owned and cannot authenticate over HTTP.
    sql(): string {
      return `
    ALTER TABLE api_keys
      DROP CONSTRAINT IF EXISTS api_keys_principal_purpose_check;
    ALTER TABLE api_keys
      ADD CONSTRAINT api_keys_principal_purpose_check
      CHECK (principal_purpose IN ('general','channel_verification','channel_assistant'))`;
    },
  },
  {
    version: 88,
    name: "memory-full-corpus-lexical-search",
    // Retrieval used to run BM25 over the 500 newest visible rows. Older
    // connector documents were therefore invisible to the lexical lane even
    // when their source title exactly matched the query. Keep Postgres as the
    // authority and add a derived, indexed search projection used only for
    // ACL-scoped candidate preselection. Source/human titles receive the
    // strongest weight; provenance remains searchable for document keys.
    sql(): string {
      return `
    ALTER TABLE memory_objects ADD COLUMN IF NOT EXISTS search_document TSVECTOR
      GENERATED ALWAYS AS (
        setweight(to_tsvector('simple'::regconfig, COALESCE(display_title, '')), 'A') ||
        setweight(to_tsvector('simple'::regconfig, split_part(content, chr(10), 1)), 'A') ||
        setweight(to_tsvector('simple'::regconfig, content), 'D') ||
        setweight(to_tsvector('simple'::regconfig, provenance::text), 'D')
      ) STORED;
    CREATE INDEX IF NOT EXISTS idx_memory_objects_search_document
      ON memory_objects USING GIN (search_document)`;
    },
  },
  {
    version: 89,
    name: "luna-context-conflict-revalidation",
    // Frozen conflict flow: every current fact is enrolled under the Halo-owned
    // Luna detector and every legacy finding/dispute is queued by its exact
    // evidence pair. Similarity is candidate retrieval only.
    sql(): string {
      return `
    ALTER TABLE conflict_detection_queue
      ADD COLUMN IF NOT EXISTS detector_version TEXT NOT NULL DEFAULT 'legacy';
    ALTER TABLE conflict_detection_queue
      ADD COLUMN IF NOT EXISTS candidate_cursor INTEGER NOT NULL DEFAULT 0
      CHECK (candidate_cursor >= 0);

    INSERT INTO conflict_detection_queue
      (memory_id, namespace, enqueued_at, status, attempts, detector_version, candidate_cursor)
    SELECT id, namespace, CURRENT_TIMESTAMP, 'pending', 0, 'luna-context-v1', 0
      FROM memory_objects
     WHERE status = 'active' AND t_valid_to IS NULL AND tier = 'L2' AND type <> 'pointer'
       AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
    ON CONFLICT (memory_id) DO UPDATE
       SET namespace = EXCLUDED.namespace,
           enqueued_at = EXCLUDED.enqueued_at,
           status = 'pending', attempts = 0, retry_at = NULL,
           lease_owner = NULL, lease_until = NULL, last_error = NULL,
           completed_at = NULL, detector_version = 'luna-context-v1', candidate_cursor = 0;

    CREATE TABLE IF NOT EXISTS conflict_pair_recheck_queue (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      source_type TEXT NOT NULL CHECK (source_type IN ('finding','auto_resolution','dispute')),
      source_id TEXT NOT NULL,
      left_memory_id TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      right_memory_id TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      detector_version TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','running','done')),
      attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      retry_at TIMESTAMPTZ,
      lease_owner TEXT,
      lease_until TIMESTAMPTZ,
      last_error TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ,
      UNIQUE(source_type, source_id, detector_version)
    );
    ALTER TABLE conflict_pair_recheck_queue ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_conflict_pair_recheck_pending
      ON conflict_pair_recheck_queue(retry_at, created_at, id)
      WHERE status IN ('pending','running');

    CREATE TABLE IF NOT EXISTS conflict_repair_proposals (
      id TEXT PRIMARY KEY,
      namespace TEXT NOT NULL,
      source_type TEXT NOT NULL CHECK (source_type IN ('auto_resolution','dispute')),
      source_id TEXT NOT NULL,
      left_memory_id TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      right_memory_id TEXT NOT NULL REFERENCES memory_objects(id) ON DELETE CASCADE,
      detector_version TEXT NOT NULL,
      classification TEXT NOT NULL CHECK (classification IN
        ('compatible_distinct','duplicate','unrelated')),
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','applied','dismissed','stale')),
      created_at TIMESTAMPTZ NOT NULL,
      resolved_at TIMESTAMPTZ,
      resolved_by TEXT,
      UNIQUE(source_type, source_id, detector_version)
    );
    ALTER TABLE conflict_repair_proposals ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_conflict_repair_proposals_open
      ON conflict_repair_proposals(namespace, created_at DESC) WHERE status = 'open';

    ALTER TABLE fact_disputes DROP CONSTRAINT IF EXISTS fact_disputes_resolution_check;
    ALTER TABLE fact_disputes ADD CONSTRAINT fact_disputes_resolution_check
      CHECK (resolution IS NULL OR resolution IN
        ('uphold-new','keep-old','edit','retracted','both-valid'));

    INSERT INTO conflict_pair_recheck_queue
      (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
       detector_version,status,attempts,created_at)
    SELECT 'finding:' || id, target_namespace,
           CASE WHEN status = 'auto_resolved' THEN 'auto_resolution' ELSE 'finding' END,
           id,left_memory_id,right_memory_id,'luna-context-v1','pending',0,CURRENT_TIMESTAMP
      FROM conflict_scan_findings
     WHERE status IN ('open','acknowledged','auto_resolved')
    ON CONFLICT (source_type,source_id,detector_version) DO NOTHING;

    INSERT INTO conflict_pair_recheck_queue
      (id,namespace,source_type,source_id,left_memory_id,right_memory_id,
       detector_version,status,attempts,created_at)
    SELECT 'dispute:' || id, namespace, 'dispute', id, memory_id, disputed_against,
           'luna-context-v1','pending',0,CURRENT_TIMESTAMP
      FROM fact_disputes WHERE status = 'open'
    ON CONFLICT (source_type,source_id,detector_version) DO NOTHING`;
    },
  },
  {
    version: 90,
    name: "obsidian-ingress-receipt-body-binding",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS obsidian_ingress_receipts (
      source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
      sequence BIGINT NOT NULL CHECK (sequence > 0),
      body_digest TEXT NOT NULL CHECK (body_digest ~ '^[a-f0-9]{64}$'),
      received_at TIMESTAMPTZ NOT NULL,
      committed_at TIMESTAMPTZ,
      PRIMARY KEY (source_id, sequence)
    );
    ALTER TABLE obsidian_ingress_receipts ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_obsidian_ingress_receipts_received
      ON obsidian_ingress_receipts(received_at)`;
    },
  },
  {
    version: 91,
    name: "conflict-scan-model-review-progress",
    sql(): string {
      return `
    ALTER TABLE conflict_scan_runs
      ADD COLUMN IF NOT EXISTS model_pairs_reviewed INTEGER NOT NULL DEFAULT 0
      CHECK (model_pairs_reviewed >= 0)`;
    },
  },
  {
    version: 92,
    name: "durable-ticket-subject-fence",
    sql(): string {
      return `ALTER TABLE durable_tickets
        ADD COLUMN IF NOT EXISTS subject_key TEXT`;
    },
  },
  {
    version: 93,
    name: "managed-google-chat-setup",
    // Halo-first Google Chat setup binds a short-lived, server-owned setup
    // session to the initiating console user and that user's verified Google
    // subject. Provider events may complete the binding only after Google's
    // signature and audience have been verified by the cartridge.
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS channel_google_chat_setup_sessions (
      id                       TEXT PRIMARY KEY,
      tenant_root              TEXT NOT NULL,
      namespace                TEXT NOT NULL,
      connection_id            TEXT NOT NULL,
      initiating_user_id       TEXT NOT NULL,
      initiating_actor         TEXT NOT NULL,
      expected_google_user_key TEXT NOT NULL,
      state                    TEXT NOT NULL DEFAULT 'waiting_installation'
                               CHECK (state IN ('waiting_installation','paired')),
      paired_space_key         TEXT,
      expires_at               TIMESTAMPTZ NOT NULL,
      paired_at                TIMESTAMPTZ,
      created_at               TIMESTAMPTZ NOT NULL,
      CHECK (tenant_root = split_part(namespace, '/', 1)),
      FOREIGN KEY (namespace, connection_id)
        REFERENCES channel_connections(namespace, id) ON DELETE CASCADE,
      UNIQUE (namespace, connection_id)
    );
    ALTER TABLE channel_google_chat_setup_sessions ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_google_chat_setup_pending_user
      ON channel_google_chat_setup_sessions(expected_google_user_key, created_at DESC)
      WHERE state = 'waiting_installation';
    CREATE INDEX IF NOT EXISTS idx_google_chat_setup_user
      ON channel_google_chat_setup_sessions(namespace, initiating_user_id, created_at DESC)`;
    },
  },
  {
    version: 94,
    name: "cost-ledger-honesty",
    // The ledger estimated tokens from text length and never saw reasoning
    // tokens, recording 1/17th of the Aug 2026 Azure bill. Rows now carry the
    // provider-reported input/output split (`basis` says which), and ingestion
    // rows carry the sources.id that triggered the spend, so the console can
    // answer "what did Linear cost this team this week". Existing rows keep
    // NULLs: they were estimates and stay labeled as such by absence.
    sql(): string {
      return `
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS input_tokens INTEGER;
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS output_tokens INTEGER;
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS basis TEXT;
    ALTER TABLE cost_ledger ADD COLUMN IF NOT EXISTS source TEXT`;
    },
  },
  {
    version: 95,
    name: "recipient-bound-agent-key-handoffs",
    // A delegated badge is minted only when its intended human claims it.
    // The pending row contains approved metadata, never bearer plaintext or a
    // recoverable ciphertext. api_keys.custodian_user_id is the durable
    // authorization relation used for member list/rotate/revoke after claim.
    sql(): string {
      return `
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS custodian_user_id TEXT REFERENCES users(id);
    CREATE INDEX IF NOT EXISTS idx_api_keys_custodian
      ON api_keys(custodian_user_id, status, created_at DESC);
    CREATE TABLE IF NOT EXISTS agent_key_handoffs (
      id                    TEXT PRIMARY KEY,
      recipient_user_id     TEXT NOT NULL REFERENCES users(id),
      assigned_by_user_id   TEXT NOT NULL REFERENCES users(id),
      namespace             TEXT NOT NULL,
      actor                 TEXT NOT NULL,
      agent_access_level    TEXT NOT NULL DEFAULT 'member'
                              CHECK (agent_access_level = 'member'),
      agent_can_write       BOOLEAN NOT NULL DEFAULT TRUE,
      credential_expires_at TIMESTAMPTZ,
      claim_expires_at      TIMESTAMPTZ NOT NULL,
      idempotency_key       TEXT NOT NULL,
      request_fingerprint   TEXT NOT NULL,
      status                TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','claimed','revoked')),
      claimed_key_id        TEXT UNIQUE REFERENCES api_keys(id),
      created_at            TIMESTAMPTZ NOT NULL,
      claimed_at            TIMESTAMPTZ,
      revoked_at            TIMESTAMPTZ,
      UNIQUE (assigned_by_user_id, idempotency_key),
      CHECK ((status = 'claimed') = (claimed_key_id IS NOT NULL)),
      CHECK ((status = 'claimed') = (claimed_at IS NOT NULL))
    );
    ALTER TABLE agent_key_handoffs ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_agent_key_handoffs_recipient
      ON agent_key_handoffs(recipient_user_id, status, created_at DESC)`;
    },
  },
  {
    version: 96,
    name: "encrypted-durable-company-file-uploads",
    // Upload bodies may outlive the admitting HTTP request only as an
    // authenticated ciphertext. The durable queue carries the opaque row id;
    // terminal processing scrubs the envelope while retaining status evidence.
    sql(): string {
      return `
    ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
    ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check CHECK (kind IN ('write','live-query','source-sync','movement','automation','usage-close','usage-emit','copilot-routine','channel-ingress','channel-dispatch','channel-outbound','channel-maintenance','channel-verification','company-file-upload'));
    CREATE TABLE IF NOT EXISTS company_file_ingest_jobs (
      id                 TEXT PRIMARY KEY,
      namespace          TEXT NOT NULL,
      knowledge_base_id  TEXT NOT NULL REFERENCES knowledge_bases(id),
      idempotency_key    TEXT NOT NULL,
      request_sha256     TEXT NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
      status             TEXT NOT NULL CHECK (status IN ('queued','processing','ready','needs_review','failed')),
      stage              TEXT NOT NULL DEFAULT 'queued' CHECK (stage IN ('queued','parsing','extracting','embedding','finalizing','complete')),
      payload_ciphertext TEXT,
      payload_iv         TEXT,
      payload_tag        TEXT,
      payload_kek_id     TEXT,
      file_id            TEXT REFERENCES company_files(id),
      failure_code       TEXT,
      created_by         TEXT NOT NULL,
      created_at         TIMESTAMPTZ NOT NULL,
      completed_at       TIMESTAMPTZ,
      UNIQUE (namespace, idempotency_key),
      CHECK (
        (payload_ciphertext IS NULL AND payload_iv IS NULL AND payload_tag IS NULL AND payload_kek_id IS NULL)
        OR
        (payload_ciphertext IS NOT NULL AND payload_iv IS NOT NULL AND payload_tag IS NOT NULL AND payload_kek_id IS NOT NULL)
      ),
      CHECK (
        (status IN ('ready','needs_review') AND file_id IS NOT NULL)
        OR (status IN ('queued','processing') AND file_id IS NULL)
        OR status = 'failed'
      )
    );
    ALTER TABLE company_file_ingest_jobs ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_company_file_ingest_jobs_active
      ON company_file_ingest_jobs(status, created_at)
      WHERE status IN ('queued','processing')`;
    },
  },
  {
    version: 97,
    name: "company-file-binary-size-limit",
    // PDF and DOCX admission has a 5 MiB ceiling. Keep the authoritative file
    // metadata constraint aligned with that parser boundary; text files remain
    // capped at 512 KiB before this table is reached.
    sql(): string {
      return `
    ALTER TABLE company_files
      DROP CONSTRAINT IF EXISTS company_files_byte_size_check;
    ALTER TABLE company_files
      ADD CONSTRAINT company_files_byte_size_check
      CHECK (byte_size BETWEEN 1 AND 5242880)`;
    },
  },
  {
    version: 98,
    name: "encrypted-revealable-agent-bearers",
    // Agent badges remain hash-resolved, but a human who is authorized for the
    // badge may now reveal its bearer again. The recoverable copy is an
    // authenticated ciphertext bound to the immutable key row. Legacy rows
    // remain NULL and require one rotation before repeated reveal is possible.
    sql(): string {
      return `
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS bearer_ciphertext TEXT;
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS bearer_iv TEXT;
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS bearer_tag TEXT;
    ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_bearer_envelope_check;
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_bearer_envelope_check CHECK (
      (bearer_ciphertext IS NULL AND bearer_iv IS NULL AND bearer_tag IS NULL)
      OR
      (bearer_ciphertext IS NOT NULL AND bearer_iv IS NOT NULL AND bearer_tag IS NOT NULL)
    )`;
    },
  },
  {
    version: 99,
    name: "resumable-company-file-chunks",
    // Content-free checkpoints let a reclaimed upload resume only unfinished
    // deterministic chunks. Source text remains solely in the encrypted parent
    // staging envelope and is scrubbed with it at the terminal outcome.
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS company_file_ingest_chunks (
      upload_id      TEXT NOT NULL REFERENCES company_file_ingest_jobs(id),
      chunk_index    INTEGER NOT NULL CHECK (chunk_index >= 0),
      chunk_count    INTEGER NOT NULL CHECK (chunk_count > 0),
      status         TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','processing','complete','failed')),
      attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      fact_count     INTEGER NOT NULL DEFAULT 0 CHECK (fact_count >= 0),
      failure_code   TEXT,
      updated_at     TIMESTAMPTZ NOT NULL,
      completed_at   TIMESTAMPTZ,
      PRIMARY KEY (upload_id, chunk_index),
      CHECK (chunk_index < chunk_count),
      CHECK ((status = 'complete') = (completed_at IS NOT NULL))
    );
    ALTER TABLE company_file_ingest_chunks ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_company_file_ingest_chunks_pending
      ON company_file_ingest_chunks(upload_id, status, chunk_index)`;
    },
  },
  {
    version: 100,
    name: "durable-relationship-enrichment",
    // Optional graph enrichment runs after authoritative file completion. It
    // must never occupy a company-file worker or keep a ready file reported as
    // processing, so it has an independent content-free durable queue lane.
    sql(): string {
      return `
    ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS durable_jobs_kind_check;
    ALTER TABLE durable_jobs ADD CONSTRAINT durable_jobs_kind_check CHECK (kind IN ('write','live-query','source-sync','movement','automation','usage-close','usage-emit','copilot-routine','channel-ingress','channel-dispatch','channel-outbound','channel-maintenance','channel-verification','company-file-upload','relationship-enrichment'))`;
    },
  },
  {
    version: 101,
    name: "required-human-display-names",
    // A human account is never anonymous in product surfaces. Repair legacy
    // rows with a readable label derived from the immutable account key, carry
    // the same name on pending invitations, then fence both tables so no direct
    // SQL/provisioning lane can create or clear a nameless person.
    sql(): string {
      return `
    ALTER TABLE auth_invitations ADD COLUMN IF NOT EXISTS display_name TEXT;

    UPDATE users
       SET display_name = INITCAP(REGEXP_REPLACE(
         SPLIT_PART(SPLIT_PART(email, '@', 1), '+', 1), '[._-]+', ' ', 'g'
       ))
     WHERE display_name IS NULL OR BTRIM(display_name) = '';
    UPDATE users SET display_name = 'Member'
     WHERE display_name IS NULL OR BTRIM(display_name) = '';

    UPDATE auth_invitations
       SET display_name = INITCAP(REGEXP_REPLACE(
         SPLIT_PART(SPLIT_PART(email, '@', 1), '+', 1), '[._-]+', ' ', 'g'
       ))
     WHERE display_name IS NULL OR BTRIM(display_name) = '';
    UPDATE auth_invitations SET display_name = 'Member'
     WHERE display_name IS NULL OR BTRIM(display_name) = '';

    ALTER TABLE users ALTER COLUMN display_name SET DEFAULT 'Member';
    ALTER TABLE users ALTER COLUMN display_name SET NOT NULL;
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_display_name_required;
    ALTER TABLE users ADD CONSTRAINT users_display_name_required
      CHECK (BTRIM(display_name) <> '');
    ALTER TABLE auth_invitations ALTER COLUMN display_name SET DEFAULT 'Member';
    ALTER TABLE auth_invitations ALTER COLUMN display_name SET NOT NULL;
    ALTER TABLE auth_invitations DROP CONSTRAINT IF EXISTS auth_invitations_display_name_required;
    ALTER TABLE auth_invitations ADD CONSTRAINT auth_invitations_display_name_required
      CHECK (BTRIM(display_name) <> '')`;
    },
  },
  {
    version: 102,
    name: "early-access-hard-quotas",
    sql(): string {
      return `
    CREATE TABLE IF NOT EXISTS early_access_trials (
      namespace   TEXT PRIMARY KEY,
      started_at  TIMESTAMPTZ NOT NULL,
      expires_at  TIMESTAMPTZ NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL,
      CHECK (expires_at > started_at)
    );
    ALTER TABLE early_access_trials ENABLE ROW LEVEL SECURITY;

    CREATE TABLE IF NOT EXISTS early_access_members (
      namespace   TEXT NOT NULL,
      actor       TEXT NOT NULL,
      joined_at   TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (namespace, actor),
      FOREIGN KEY (namespace) REFERENCES early_access_trials(namespace)
    );
    ALTER TABLE early_access_members ENABLE ROW LEVEL SECURITY;

    CREATE TABLE IF NOT EXISTS early_access_usage (
      id               TEXT PRIMARY KEY,
      namespace        TEXT NOT NULL,
      actor            TEXT NOT NULL,
      quota_actor      TEXT NOT NULL,
      feature          TEXT NOT NULL CHECK (feature IN (
        'assistant_luna','assistant_grok','retrieval','memory_write',
        'ingest_bytes','file','file_bytes','source','source_sync','automation',
        'consolidation','conflict_scan','export'
      )),
      units             INTEGER NOT NULL CHECK (units > 0),
      reserved_micro_usd INTEGER NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
      period_key        TEXT NOT NULL,
      idempotency_key   TEXT NOT NULL,
      ts                TIMESTAMPTZ NOT NULL,
      FOREIGN KEY (namespace) REFERENCES early_access_trials(namespace),
      UNIQUE (namespace, quota_actor, feature, period_key, idempotency_key)
    );
    ALTER TABLE early_access_usage ENABLE ROW LEVEL SECURITY;
    CREATE INDEX IF NOT EXISTS idx_early_access_usage_counter
      ON early_access_usage(namespace, quota_actor, feature, period_key, ts);
    CREATE INDEX IF NOT EXISTS idx_early_access_usage_actor
      ON early_access_usage(namespace, actor, period_key, ts);`;
    },
  },
];
