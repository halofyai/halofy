/**
 * Module C (M1) tests — db hardening: numbered migrations + Db.transaction.
 * Hermetic: fresh in-memory PGlite with the vector extension, zero network.
 *
 * Nested transactions are UNSUPPORTED by design: the tx handle passed to the
 * transaction callback throws on tx.transaction() (and tx.close()). This is
 * documented in src/db/client.ts and asserted below.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MIGRATIONS, splitStatements } from "../src/db/migrations.js";
import { loadConfig } from "../src/config.js";
import { createHash } from "node:crypto";

const DIM = 8;

let db: Db;

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
});

afterAll(async () => {
  await db.close();
});

describe("numbered migrations", () => {
  it("declares the numbered migrations in order with the expected names", () => {
    expect(MIGRATIONS.map((m) => m.version)).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
    ]);
    expect(MIGRATIONS.map((m) => m.name)).toEqual([
      "initial-schema",
      "api-keys",
      "cost-ledger",
      "scorecards", // M2 module E (referee) - additive
      "ingestion-sources", // M3 - sources/source_documents/fragmentation_reports, additive
      "tenancy-erasure", // M4 - tenants/tombstones/deletion_certificates, additive
      "human-auth", // M5 - users/sessions, additive
      "concept-ownership-acl", // R2A - explicit private/public L3 ownership
      "cold-concept-keys", // R2B - wrapped per-concept encryption keys
      "concept-pii-subjects", // R2C - normalized private PII-subject projection
      "cold-write-state-erasure-fence",
      "redact-concept-quarantine",
      "active-cold-kek-state",
      "explicit-source-document-identity",
      "human-bootstrap-invitations",
      "verified-setup-operations",
      "single-pending-invitation-per-email",
      "encrypted-source-configuration",
      "logical-knowledge-and-pins",
      "consolidation-and-movement",
      "shared-segments-and-cow",
      "tenant-scoped-movement-idempotency",
      "warm-mirror-ops", // R6 - durable external warm-store outbox, additive
      "trust-disputes", // trust-ranked supersedence quarantine + review queue, additive
      "pointer-probe-index", // M6 - partial index for the l4 zero-pointer probe, additive
      "model-runtime", // encrypted organization model connections + named Copilot profiles
      "active-model-name-uniqueness", // revoked/deleted names may be reused
      "enterprise-production-hardening",
      "agent-connection-grants",
      "model-hosting-source-classification", // hosting location and model ownership are independent
      "platform-source-catalog-and-credentials",
      "source-ingress-hardening",
      "nango-proxy-connections",
      "nango-capacity-reconciliation",
      "policy-documents",
      "agent-access-oversight",
      "org-teams-and-membership",
      "mintlify-parity-m9", // M9 - skills/oauth/outcomes/automations/credits/alerts, additive
      "m9-wave3-usage-job-kinds", // M9 Wave 3 - usage-close/usage-emit durable job kinds (E53/E54)
      "skill-approval-workflow", // S16 - pending/approved/rejected on skills, additive
      "skill-vetting-v2", // S16 vetting v2 - llm/cisco/skillspector modes + engine_versions
      "user-external-identities", // GitHub OAuth login + explicit profile linking
      "auth-signup-sessions", // verified-email self-service organization authority
      "company-knowledge-graph", // governed company files + derived L2 relationships
      "setup-team-directory-backfill", // expose verified setup teams in the management directory
      "organization-conflict-scans-and-agent-summaries",
      "conflict-scan-semantic-judge-lease",
      "usage-events-traces",
      "usage-rollup-watermark-indexes",
      "query-traces-namespace-key",
      "knowledge-sync-history-index",
      "usage-events-namespace-trace-indexes",
      "disable-platform-root-knowledge-sync",
      "team-company-memory-access",
      "access-grants-and-preview-sessions", // M10 role-scoped memory graph
      "policy-guardrails",
      "external-identity-google", // v57 - Google joins GitHub in the link table
      "byok-provider-catalog", // BYOK vendor id + non-OpenAI wire protocols
      "agent-access-level",
      "agent-key-expiry-and-description",
      "agent-write-capability",
      "copilot-conversation-history",
      "copilot-routines",
      "widen-model-profile-output-ceiling",
      "channel-control-plane",
      "channel-verification-grant-slot",
      "channel-executable-cohorts-2-3",
      "onboarding-completion-flag", // v68 - one-way setup-gate latch on tenants
      "drop-legacy-teams-table", // v69 - org_teams is the single team directory
      "oauth-connect", // v70 - authorization codes, refresh tokens, public clients
      "channel-socket-state", // v71 - sealed session state for socket-delivered channels
      "assistant-observability", // v72 - metadata-only Assistant turn and invocation ledgers
      "console-settings-identity", // v73 - display name + workspace mark, display-only
      "conflict-finding-resolution", // v74 - a reviewer keeps one side; the other closes
      "policy-document-adoption", // v75 - upload lane vs adopted-from-memory register rows
      "api-key-issuer", // v76 - who MINTED a credential, display-only, backfilled from the audit trail
      "user-profile-avatar", // v77 - optional raster portrait, display-only
      "organization-name-capitalization", // v78 - display-name backfill + lowercase-initial fence
      "managed-assistant-price-repair", // v79 - targeted price/cost-ledger repair
      "model-profile-assistant-enablement", // v80 - per-profile Assistant availability gate
      "skill-labels-and-vocabulary", // v81 - mutable discovery metadata
      "teams-v2-lifecycle", // v82 - archive and durable invitation history
      "memory-display-titles", // v83 - derived titles and durable Luna worker leases
      "conflict-autopilot", // v84 - write-time detection outbox + auto-resolved ledger
      "derived-entity-subjects", // v85 - subject column, tag queue, backfill enrolment
      "source-oauth-sessions", // v86 - direct connector OAuth single-use state custody
      "channel-assistant-principal", // v87 - internal Assistant identity for channel grants
      "memory-full-corpus-lexical-search", // v88 - indexed retrieval projection
      "luna-context-conflict-revalidation", // v89 - historical + future Luna judgement
      "obsidian-ingress-receipt-body-binding", // v90 - exact payload binding per source sequence
      "conflict-scan-model-review-progress", // v91 - truthful batched LLM progress
      "durable-ticket-subject-fence", // v92 - namespace + initiating-subject redemption
      "managed-google-chat-setup", // v93 - verified Halo-first installation binding
      "cost-ledger-honesty", // v94 - provider token splits + source attribution
      "recipient-bound-agent-key-handoffs", // v95 - one-time member bearer delivery
      "encrypted-durable-company-file-uploads", // v96 - ciphertext staging + opaque durable jobs
      "company-file-binary-size-limit", // v97 - PDF/DOCX metadata matches the 5 MiB parser limit
      "encrypted-revealable-agent-bearers", // v98 - audited on-demand bearer reveal
      "resumable-company-file-chunks", // v99 - content-free per-chunk recovery checkpoints
      "durable-relationship-enrichment", // v100 - optional graph work cannot block uploads
      "required-human-display-names", // v101 - every human/invitation has a non-blank name
      "early-access-hard-quotas", // v102 - trial, seat, and period-keyed allowance ledger (RLS on)
    ]);
  });

  it("records every declared version in schema_migrations", async () => {
    const res = await db.query(
      `SELECT version, name, applied_at FROM schema_migrations ORDER BY version`,
    );
    expect(res.rows.map((r) => Number(r.version))).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
    ]);
    expect(res.rows.map((r) => r.name as string)).toEqual([
      "initial-schema",
      "api-keys",
      "cost-ledger",
      "scorecards",
      "ingestion-sources",
      "tenancy-erasure",
      "human-auth",
      "concept-ownership-acl",
      "cold-concept-keys",
      "concept-pii-subjects",
      "cold-write-state-erasure-fence",
      "redact-concept-quarantine",
      "active-cold-kek-state",
      "explicit-source-document-identity",
      "human-bootstrap-invitations",
      "verified-setup-operations",
      "single-pending-invitation-per-email",
      "encrypted-source-configuration",
      "logical-knowledge-and-pins",
      "consolidation-and-movement",
      "shared-segments-and-cow",
      "tenant-scoped-movement-idempotency",
      "warm-mirror-ops",
      "trust-disputes",
      "pointer-probe-index",
      "model-runtime",
      "active-model-name-uniqueness",
      "enterprise-production-hardening",
      "agent-connection-grants",
      "model-hosting-source-classification",
      "platform-source-catalog-and-credentials",
      "source-ingress-hardening",
      "nango-proxy-connections",
      "nango-capacity-reconciliation",
      "policy-documents",
      "agent-access-oversight",
      "org-teams-and-membership",
      "mintlify-parity-m9",
      "m9-wave3-usage-job-kinds",
      "skill-approval-workflow",
      "skill-vetting-v2",
      "user-external-identities",
      "auth-signup-sessions",
      "company-knowledge-graph",
      "setup-team-directory-backfill",
      "organization-conflict-scans-and-agent-summaries",
      "conflict-scan-semantic-judge-lease",
      "usage-events-traces",
      "usage-rollup-watermark-indexes",
      "query-traces-namespace-key",
      "knowledge-sync-history-index",
      "usage-events-namespace-trace-indexes",
      "disable-platform-root-knowledge-sync",
      "team-company-memory-access",
      "access-grants-and-preview-sessions", // M10 role-scoped memory graph
      "policy-guardrails",
      "external-identity-google", // v57 - Google joins GitHub in the link table
      "byok-provider-catalog", // BYOK vendor id + non-OpenAI wire protocols
      "agent-access-level",
      "agent-key-expiry-and-description",
      "agent-write-capability",
      "copilot-conversation-history",
      "copilot-routines",
      "widen-model-profile-output-ceiling",
      "channel-control-plane",
      "channel-verification-grant-slot",
      "channel-executable-cohorts-2-3",
      "onboarding-completion-flag", // v68 - one-way setup-gate latch on tenants
      "drop-legacy-teams-table", // v69 - org_teams is the single team directory
      "oauth-connect", // v70 - authorization codes, refresh tokens, public clients
      "channel-socket-state", // v71 - sealed session state for socket-delivered channels
      "assistant-observability", // v72 - metadata-only Assistant turn and invocation ledgers
      "console-settings-identity", // v73 - display name + workspace mark, display-only
      "conflict-finding-resolution", // v74 - a reviewer keeps one side; the other closes
      "policy-document-adoption", // v75 - upload lane vs adopted-from-memory register rows
      "api-key-issuer", // v76 - who MINTED a credential, display-only, backfilled from the audit trail
      "user-profile-avatar", // v77 - optional raster portrait, display-only
      "organization-name-capitalization", // v78 - display-name backfill + lowercase-initial fence
      "managed-assistant-price-repair", // v79
      "model-profile-assistant-enablement", // v80
      "skill-labels-and-vocabulary", // v81
      "teams-v2-lifecycle", // v82
      "memory-display-titles", // v83
      "conflict-autopilot", // v84
      "derived-entity-subjects", // v85
      "source-oauth-sessions", // v86
      "channel-assistant-principal", // v87
      "memory-full-corpus-lexical-search", // v88
      "luna-context-conflict-revalidation", // v89
      "obsidian-ingress-receipt-body-binding", // v90
      "conflict-scan-model-review-progress", // v91
      "durable-ticket-subject-fence", // v92
      "managed-google-chat-setup", // v93
      "cost-ledger-honesty", // v94
      "recipient-bound-agent-key-handoffs", // v95
      "encrypted-durable-company-file-uploads", // v96
      "company-file-binary-size-limit", // v97
      "encrypted-revealable-agent-bearers", // v98
      "resumable-company-file-chunks", // v99
      "durable-relationship-enrichment", // v100
      "required-human-display-names", // v101
      "early-access-hard-quotas", // v102
    ]);
    for (const row of res.rows) {
      expect(row.applied_at).toBeTruthy();
    }
  });

  it("versions Luna conflict work and protects historical recheck state with RLS", async () => {
    const columns = await db.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'conflict_detection_queue'
          AND column_name IN ('detector_version','candidate_cursor')
        ORDER BY column_name`,
    );
    expect(columns.rows.map((row) => row.column_name)).toEqual([
      "candidate_cursor",
      "detector_version",
    ]);
    const rls = await db.query(
      `SELECT relname, relrowsecurity FROM pg_class
        WHERE relname IN ('conflict_pair_recheck_queue','conflict_repair_proposals')
        ORDER BY relname`,
    );
    expect(rls.rows).toEqual([
      expect.objectContaining({ relname: "conflict_pair_recheck_queue", relrowsecurity: true }),
      expect.objectContaining({ relname: "conflict_repair_proposals", relrowsecurity: true }),
    ]);
  });

  it("upgrades v27 model connections without guessing hosting or model ownership", async () => {
    const upgradeDb = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    try {
      await upgradeDb.query(
        `CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_at TIMESTAMPTZ NOT NULL
         )`,
      );
      for (const migration of MIGRATIONS.filter((candidate) => candidate.version <= 27)) {
        for (const statement of splitStatements(migration.sql(DIM))) {
          await upgradeDb.query(statement);
        }
        await upgradeDb.query(
          `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
          [migration.version, migration.name, new Date().toISOString()],
        );
      }
      for (const [id, name, baseUrl] of [
        ["legacy-http", "Legacy HTTP", "http://localhost:11434/v1"],
        ["legacy-https", "Legacy HTTPS", "https://models.internal.example/v1"],
      ]) {
        await upgradeDb.query(
          `INSERT INTO model_connections
             (id, namespace, name, provider, base_url, credential_state,
              status, created_by, created_at, updated_at)
           VALUES ($1, 'acme', $2, 'openai-compatible', $3, 'none',
                   'active', 'admin@acme.test', NOW(), NOW())`,
          [id, name, baseUrl],
        );
      }

      await migrate(upgradeDb, DIM);
      const rows = await upgradeDb.query(
        `SELECT id, hosting_type, model_source FROM model_connections ORDER BY id`,
      );
      expect(rows.rows).toEqual([
        expect.objectContaining({ id: "legacy-http", hosting_type: "unclassified", model_source: "unclassified" }),
        expect.objectContaining({ id: "legacy-https", hosting_type: "unclassified", model_source: "unclassified" }),
      ]);
      await expect(upgradeDb.query(
        `UPDATE model_connections SET hosting_type = 'guessed-from-url' WHERE id = 'legacy-http'`,
      )).rejects.toThrow();
    } finally {
      await upgradeDb.close();
    }
  }, 60_000);

  it("backfills verified setup teams into the management directory", async () => {
    const upgradeDb = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    try {
      await upgradeDb.query(
        `CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_at TIMESTAMPTZ NOT NULL
         )`,
      );
      for (const migration of MIGRATIONS.filter((candidate) => candidate.version <= 44)) {
        for (const statement of splitStatements(migration.sql(DIM))) await upgradeDb.query(statement);
        await upgradeDb.query(
          `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
          [migration.version, migration.name, new Date().toISOString()],
        );
      }
      await upgradeDb.query(
        `INSERT INTO tenants (id, name, status, created_at)
         VALUES ('acme', 'Acme', 'active', NOW())`,
      );
      await upgradeDb.query(
        `INSERT INTO teams (namespace, tenant_id, team_id, name, created_at)
         VALUES ('acme/support', 'acme', 'support', 'Customer Support', NOW())`,
      );

      await migrate(upgradeDb, DIM);
      const rows = await upgradeDb.query(
        `SELECT namespace, name, created_by FROM org_teams WHERE namespace = 'acme/support'`,
      );
      expect(rows.rows).toEqual([
        expect.objectContaining({
          namespace: "acme/support",
          name: "Customer Support",
          created_by: "verified-setup-backfill",
        }),
      ]);

      // v69: after the full run, the legacy bootstrap table itself is gone —
      // the backfilled org_teams row is the only durable record.
      const legacy = await upgradeDb.query(
        `SELECT table_name FROM information_schema.tables
          WHERE table_schema = 'public' AND table_name = 'teams'`,
      );
      expect(legacy.rows).toEqual([]);
    } finally {
      await upgradeDb.close();
    }
  }, 60_000);

  it("creates the v0.1 tables plus api_keys and cost_ledger", async () => {
    const res = await db.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const names = res.rows.map((r) => r.table_name as string);
    for (const t of [
      "schema_migrations",
      "memory_objects",
      "concepts",
      "entity_registry",
      "audit_log",
      "policies",
      "api_keys",
      "cost_ledger",
      "policy_documents",
      "policy_document_quota_usage",
      "agent_access_events",
      "agent_access_alerts",
      "agent_access_requests",
      "knowledge_bases",
      "knowledge_sources",
      "company_file_upload_attempts",
      "company_file_quota_usage",
      "company_files",
      "company_file_ingest_jobs",
      "company_file_ingest_chunks",
      "entity_mentions",
      "entity_relationships",
      "entity_relationship_evidence",
    ]) {
      expect(names).toContain(t);
    }
  });

  it("creates governed company-file and L2 graph tables without storing raw files", async () => {
    const tables = [
      "knowledge_bases",
      "knowledge_sources",
      "company_file_upload_attempts",
      "company_file_quota_usage",
      "company_files",
      "company_file_ingest_jobs",
      "company_file_ingest_chunks",
      "entity_mentions",
      "entity_relationships",
      "entity_relationship_evidence",
    ];
    const columns = await db.query(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = ANY($1)
        ORDER BY table_name, ordinal_position`,
      [tables],
    );
    const byTable = new Map<string, string[]>();
    for (const row of columns.rows) {
      const table = String(row.table_name);
      const list = byTable.get(table) ?? [];
      list.push(String(row.column_name));
      byTable.set(table, list);
    }

    for (const table of tables) {
      expect(byTable.has(table), table).toBe(true);
      if (!new Set(["company_file_quota_usage", "company_file_ingest_chunks"]).has(table)) {
        expect(byTable.get(table), table).toContain("namespace");
      }
    }
    for (const table of ["knowledge_bases", "knowledge_sources", "company_files", "entity_mentions", "entity_relationships"]) {
      expect(byTable.get(table), table).toEqual(expect.arrayContaining([
        "supersedes", "t_valid_from", "t_valid_to", "created_by", "created_at",
      ]));
    }
    expect(byTable.get("entity_relationship_evidence")).toEqual(expect.arrayContaining([
      "relationship_id", "memory_id", "source_id", "document_key", "content_hash",
      "created_by", "created_at",
    ]));
    expect(byTable.get("knowledge_bases")).toEqual(expect.arrayContaining([
      "target_team_id", "kind", "status", "lifecycle_state", "source_id",
      "primary_business_function", "data_sensitive", "updated_at", "archived_at",
    ]));
    expect(byTable.get("company_files")).toEqual(expect.arrayContaining([
      "source_id", "title", "description", "purpose", "file_name", "media_type",
      "byte_size", "content_sha256", "status", "lifecycle_state", "attempt_token",
      "lease_expires_at", "failure_code", "uploaded_by", "archived_at",
    ]));
    expect(byTable.get("company_file_upload_attempts")).toEqual(expect.arrayContaining([
      "idempotency_key", "request_sha256", "requested_file_count", "accepted_file_count",
      "failed_file_count", "attempt_token", "lease_expires_at", "created_by",
    ]));
    expect(byTable.get("company_file_quota_usage")).toEqual(expect.arrayContaining([
      "tenant_root", "current_files", "current_bytes", "total_rows", "updated_at",
    ]));
    expect(byTable.get("company_file_ingest_chunks")).toEqual(expect.arrayContaining([
      "upload_id", "chunk_index", "chunk_count", "status", "attempts",
      "fact_count", "failure_code", "updated_at", "completed_at",
    ]));
    expect(byTable.get("company_file_ingest_chunks")).not.toEqual(expect.arrayContaining([
      "content", "raw_content", "payload", "file_bytes", "blob",
    ]));
    for (const table of ["company_file_upload_attempts", "company_files"]) {
      expect(byTable.get(table), table).not.toEqual(expect.arrayContaining([
        "content", "raw_content", "payload", "file_bytes", "blob",
      ]));
    }

    const sourceMetadata = await db.query(
      `SELECT column_name
         FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sources'
          AND column_name IN ('primary_business_function','description','data_sensitive')`,
    );
    expect(sourceMetadata.rows.map((row) => row.column_name).sort()).toEqual([
      "data_sensitive", "description", "primary_business_function",
    ]);

    const rls = await db.query(
      `SELECT relname, relrowsecurity
         FROM pg_class
        WHERE relname = ANY($1)`,
      [tables],
    );
    expect(rls.rows).toHaveLength(tables.length);
    expect(rls.rows.every((row) => row.relrowsecurity === true)).toBe(true);
  });

  it("enforces knowledge-base source binding and bounded upload attempt counters", async () => {
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO knowledge_bases
         (id, namespace, name, kind, status, lifecycle_state,
          primary_business_function, description, data_sensitive, created_by,
          t_valid_from, created_at, updated_at)
       VALUES ('kb-schema-a', 'schema-test', 'Company knowledge', 'file', 'empty',
               'active', 'General', '', FALSE, 'owner@schema.test', $1, $1, $1)`,
      [now],
    );
    await expect(db.query(
      `INSERT INTO knowledge_bases
         (id, namespace, name, kind, status, lifecycle_state,
          primary_business_function, description, data_sensitive, created_by,
          t_valid_from, created_at, updated_at)
       VALUES ('kb-schema-invalid', 'schema-test', 'Folder without source', 'folder',
               'empty', 'active', 'General', '', FALSE, 'owner@schema.test', $1, $1, $1)`,
      [now],
    )).rejects.toThrow();

    await expect(db.query(
      `INSERT INTO company_file_upload_attempts
         (id, namespace, knowledge_base_id, idempotency_key, request_sha256,
          status, requested_file_count, accepted_file_count, failed_file_count,
          attempt_token, lease_expires_at, created_by, created_at)
       VALUES ('attempt-invalid', 'schema-test', 'kb-schema-a', 'attempt-invalid',
               $1, 'processing', 1, 1, 1, 'fence-1', $2, 'owner@schema.test', $3)`,
      ["a".repeat(64), new Date(Date.now() + 60_000).toISOString(), now],
    )).rejects.toThrow();
  });

  it("enforces exactly one L3 ownership mode in the database", async () => {
    const insert = (path: string, namespace: string | null, visibility: string | null) =>
      db.query(
        `INSERT INTO concepts
           (path, type, title, namespace, visibility, body, synced_at)
         VALUES ($1, 'reference', 'Ownership test', $2, $3, 'body', $4)`,
        [path, namespace, visibility, new Date().toISOString()],
      );

    await expect(insert("test/unowned.md", null, null)).rejects.toThrow();
    await expect(insert("test/ambiguous.md", "acme", "public")).rejects.toThrow();
    await expect(insert("test/private.md", "acme", null)).resolves.toBeDefined();
    await expect(insert("test/public.md", null, "public")).resolves.toBeDefined();
    await db.query("DELETE FROM concepts WHERE path LIKE 'test/%'");
  });

  it("quarantines a populated v7 legacy concept before removing it from the active table", async () => {
    const legacy = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    try {
      for (const migration of MIGRATIONS.filter((entry) => entry.version <= 7)) {
        for (const statement of splitStatements(migration.sql(DIM))) {
          await legacy.query(statement);
        }
      }
      await legacy.query(
        `INSERT INTO concepts (path, type, title, body, synced_at)
         VALUES ('legacy/unowned.md', 'reference', 'Legacy', 'recoverable body', $1)`,
        [new Date().toISOString()],
      );
      await migrate(legacy, DIM);
      expect((await legacy.query(
        "SELECT count(*) AS n FROM concepts WHERE path = 'legacy/unowned.md'",
      )).rows[0]!.n).toBe(0);
      const quarantined = (await legacy.query(
        `SELECT classification_reason, content_sha256, to_jsonb(concept_quarantine)::text AS stored
           FROM concept_quarantine WHERE path = 'legacy/unowned.md'`,
      )).rows[0];
      expect(quarantined?.classification_reason).toBe("legacy-unowned");
      expect(quarantined?.content_sha256).toBe(
        createHash("sha256").update("recoverable body").digest("hex"),
      );
      expect(String(quarantined?.stored)).not.toContain("recoverable body");
      const columns = await legacy.query(
        `SELECT column_name FROM information_schema.columns
          WHERE table_name = 'concept_quarantine' ORDER BY column_name`,
      );
      expect(columns.rows.map((row) => row.column_name)).not.toEqual(
        expect.arrayContaining(["legacy_row", "body", "title", "embedding", "reason"]),
      );
    } finally {
      await legacy.close();
    }
  });

  it("enforces api_keys role/status CHECK constraints", async () => {
    await expect(
      db.query(
        `INSERT INTO api_keys (id, key_hash, namespace, actor, role, created_at)
         VALUES ('k-bad', 'h-bad', 'acme', 'tester', 'superuser', $1)`,
        [new Date().toISOString()],
      ),
    ).rejects.toThrow();
    await db.query(
      `INSERT INTO api_keys (id, key_hash, namespace, actor, role, created_at)
       VALUES ('k-ok', 'h-ok', 'acme', 'tester', 'owner', $1)`,
      [new Date().toISOString()],
    );
    const res = await db.query(`SELECT status FROM api_keys WHERE id = 'k-ok'`);
    expect(res.rows[0].status).toBe("active");
  });

  it("accepts cost_ledger rows and rejects unknown kinds", async () => {
    await db.query(
      `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
       VALUES ('c-1', 'acme', 'llm', 120, 0.004, $1)`,
      [new Date().toISOString()],
    );
    await expect(
      db.query(
        `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
         VALUES ('c-2', 'acme', 'gpu', 1, 0.1, $1)`,
        [new Date().toISOString()],
      ),
    ).rejects.toThrow();
  });

  it("re-migrate is a no-op (same rows, applied_at unchanged)", async () => {
    const before = await db.query(
      `SELECT version, applied_at FROM schema_migrations ORDER BY version`,
    );
    await migrate(db, DIM);
    const after = await db.query(
      `SELECT version, applied_at FROM schema_migrations ORDER BY version`,
    );
    expect(after.rows.length).toBe(before.rows.length);
    expect(after.rows.map((r) => String(r.applied_at))).toEqual(
      before.rows.map((r) => String(r.applied_at)),
    );
    // Data written between runs survives re-migration.
    const keys = await db.query(`SELECT id FROM api_keys WHERE id = 'k-ok'`);
    expect(keys.rows.length).toBe(1);
  });

  it("still rejects a non-positive embedDim", async () => {
    await expect(migrate(db, 0)).rejects.toThrow(/embedDim/);
    await expect(migrate(db, 2.5)).rejects.toThrow(/embedDim/);
  });

  it("splitStatements drops empty fragments and trims", () => {
    expect(splitStatements("CREATE TABLE a (x INT);\n\nCREATE INDEX b ON a(x);\n")).toEqual([
      "CREATE TABLE a (x INT)",
      "CREATE INDEX b ON a(x)",
    ]);
  });
});

describe("Db.transaction", () => {
  it("commits on resolve and returns the callback value", async () => {
    const value = await db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO policies (namespace, yaml, updated_at) VALUES ($1, $2, $3)`,
        ["tx/commit", "budget: 1", new Date().toISOString()],
      );
      return 42;
    });
    expect(value).toBe(42);
    const res = await db.query(`SELECT yaml FROM policies WHERE namespace = 'tx/commit'`);
    expect(res.rows.length).toBe(1);
    expect(res.rows[0].yaml).toBe("budget: 1");
  });

  it("rolls back when the callback throws - row absent, error rethrown", async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO policies (namespace, yaml, updated_at) VALUES ($1, $2, $3)`,
          ["tx/rollback", "budget: 2", new Date().toISOString()],
        );
        // Row is visible inside the transaction...
        const inside = await tx.query(
          `SELECT 1 FROM policies WHERE namespace = 'tx/rollback'`,
        );
        expect(inside.rows.length).toBe(1);
        throw new Error("boom: abort this transaction");
      }),
    ).rejects.toThrow(/boom/);
    // ...but absent after rollback.
    const res = await db.query(`SELECT 1 FROM policies WHERE namespace = 'tx/rollback'`);
    expect(res.rows.length).toBe(0);
  });

  it("rolls back multi-statement work atomically", async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
           VALUES ('c-tx-1', 'tx', 'llm', 10, 0.001, $1)`,
          [new Date().toISOString()],
        );
        await tx.query(
          `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
           VALUES ('c-tx-2', 'tx', 'embed', 20, 0.002, $1)`,
          [new Date().toISOString()],
        );
        // Duplicate PK forces a mid-transaction failure.
        await tx.query(
          `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
           VALUES ('c-tx-1', 'tx', 'llm', 30, 0.003, $1)`,
          [new Date().toISOString()],
        );
      }),
    ).rejects.toThrow();
    const res = await db.query(`SELECT id FROM cost_ledger WHERE namespace = 'tx'`);
    expect(res.rows.length).toBe(0);
  });

  it("nested transactions are unsupported (documented) and throw", async () => {
    await expect(
      db.transaction(async (tx) => tx.transaction(async () => 1)),
    ).rejects.toThrow(/nested/);
    // The outer transaction rolled back cleanly and the handle still works.
    const res = await db.query(`SELECT 1 AS ok`);
    expect(Number(res.rows[0].ok)).toBe(1);
  });

  it("tx handle refuses close()", async () => {
    await expect(db.transaction(async (tx) => tx.close())).rejects.toThrow(/close/);
  });
});
