/**
 * Module C (M4) — migrations-auto-run-on-boot, the TESTABLE CORE of self-host.
 *
 * The self-host story is `docker compose up` on a clean machine: the `db`
 * service comes up, the `kernel` service waits for it, then boots. `Kernel.boot`
 * runs `migrate(db, embedDim)` before it serves a single request, so a fresh
 * database is schema-complete without any manual migration step. Docker itself
 * is NOT available in this build environment, so the container is never run
 * here — but the exact code path the container's entrypoint triggers (a fresh
 * DB + migrate to head) is proven below against an in-memory PGlite.
 *
 * Hermetic: fresh in-memory PGlite with the pgvector extension, zero network,
 * zero Docker. Imports only shared test utils (createDb/loadConfig/migrate).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations.js";
import { loadConfig } from "../src/config.js";

const DIM = 8;

let db: Db;

beforeAll(async () => {
  // A FRESH in-memory PGlite — exactly the blank-slate a container's first boot
  // sees against a brand-new `db` volume. `migrate` is what `Kernel.boot` calls.
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
});

afterAll(async () => {
  await db.close();
});

describe("migrations auto-run on boot (self-host testable core)", () => {
  it("records every declared schema migration after a fresh migrate", async () => {
    const res = await db.query(
      `SELECT version FROM schema_migrations ORDER BY version`,
    );
    expect(res.rows.map((r) => Number(r.version))).toEqual(MIGRATIONS.map((m) => m.version));
  });

  it("head version matches the highest declared migration (no drift)", async () => {
    const head = Math.max(...MIGRATIONS.map((m) => m.version));
    const res = await db.query(`SELECT MAX(version) AS head FROM schema_migrations`);
    expect(Number(res.rows[0].head)).toBe(head);
    // M10 (CONTRACTS-M10-ACCESS): migration v55 adds access_grants +
    // access_preview_sessions (renumbered after origin's v54
    // team-company-memory-access). v56-v57 policy guardrails + Google identity,
    // v58 the BYOK provider catalog, v59 agent access levels, v60 (D51) the
    // bounded credential lifetime and stated purpose an agent may carry,
    // v61 (D54) whether that agent may change memory at all, v62 adds
    // actor-scoped encrypted Copilot conversation history, v63 adds
    // manager-owned scheduled Copilot routines and their run ledger, and v64
    // widens the model-profile output ceiling to 32768 (reasoning models bill
    // their thinking against that budget, so the old 4096 could be spent before
    // any visible text was produced). v68 (setup gate) adds the one-way
    // tenants.onboarding_completed_at latch, and v69 drops the legacy
    // verified-setup teams table (org_teams is the single team directory).
    // v70 (CONTRACTS-OAUTH-CONNECT) adds authorization codes + refresh tokens
    // and widens oauth_clients for public (PKCE-only) self-registered clients.
    // v71 adds channel_socket_state: sealed provider session material for
    // socket-delivered channels (a paired WhatsApp account), which has no
    // webhook and no bearer token — the session itself is the credential.
    // v72 adds metadata-only Assistant turn, invocation, pricing, and actor
    // lifecycle projections while encrypted messages remain authoritative.
    // v73 adds the two display-only Settings identity fields. v74 lets a
    // reviewer resolve a conflict finding by keeping one side: the finding
    // gains a `resolved` status and records which fact was kept. v75 marks
    // whether a policy_documents row was uploaded through the register's own
    // lane or adopted out of memory that another lane had already landed.
    // v76 records WHO issued a credential (api_keys.created_by), backfilled
    // from the audit trail, so the console can show a caller its own agent
    // connections rather than every badge in its subtree. v77 adds optional
    // profile portraits, v78 repairs and fences organization-name casing,
    // v79 repairs unavailable managed-model pricing, v80 adds the persisted
    // Assistant enablement gate for model profiles, v81 keeps skill discovery labels outside immutable skill versions, and
    // v82 adds reversible team state plus durable invitation history; v83
    // adds derived memory titles with durable, lease-fenced backfill state.
    // v84 adds the write-time conflict-detection outbox and the auto-resolved
    // ledger; v85 adds the derived subject column, its tag queue, and the
    // one-time enrolment of every existing fact; v86 adds the single-use
    // source-connector OAuth state custody table; v87 admits the private,
    // server-owned Halo Assistant principal used by channel grants; v88 adds
    // the indexed, derived full-corpus lexical search projection; v89 freezes
    // Luna context revalidation for historical and future conflicts; v90 binds
    // every Obsidian source sequence to its exact signed raw-body digest; v91
    // tracks model review progress; v92 fences durable tickets to the subject;
    // v93 binds managed Google Chat setup to verified human/provider identity;
    // v94 adds provider-reported token splits + source attribution to the
    // cost ledger (the estimate recorded 1/17th of the real Azure bill); v95
    // adds recipient-bound, one-time agent-key handoffs; v96 adds encrypted,
    // durable staging for asynchronous company-file ingestion; v97 aligns
    // PDF/DOCX metadata storage with the 5 MiB binary parser boundary; v98 adds
    // the authenticated envelope used by audited on-demand bearer reveal; v99
    // adds content-free resumable company-file chunk checkpoints; v100 moves
    // optional relationship enrichment onto its own durable queue lane; v101
    // repairs and requires the human name carried by every user/invitation;
    // v102 adds the early-access trial, member-seat, and period-keyed
    // allowance ledger tables (RLS on).
    expect(head).toBe(102);
  });

  it("requires a non-blank human display name at the database boundary", async () => {
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO users (id, email, namespace, role, status, created_at)
       VALUES ('named-by-default', 'default-name@example.test', 'acme', 'member', 'active', $1)`,
      [now],
    );
    expect((await db.query(
      `SELECT display_name FROM users WHERE id = 'named-by-default'`,
    )).rows[0]?.display_name).toBe("Member");
    await expect(db.query(
      `INSERT INTO users (id, email, display_name, namespace, role, status, created_at)
       VALUES ('blank-name', 'blank-name@example.test', '   ', 'acme', 'member', 'active', $1)`,
      [now],
    )).rejects.toThrow(/users_display_name_required|check constraint/i);
    await expect(db.query(
      `INSERT INTO users (id, email, display_name, namespace, role, status, created_at)
       VALUES ('null-name', 'null-name@example.test', NULL, 'acme', 'member', 'active', $1)`,
      [now],
    )).rejects.toThrow(/not-null|null value/i);
  });

  it("adds honest-accounting columns to the cost ledger", async () => {
    const columns = await db.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'cost_ledger'
          AND column_name IN ('input_tokens','output_tokens','basis','source')
        ORDER BY column_name`,
    );
    expect(columns.rows.map((r) => (r as { column_name: string }).column_name)).toEqual([
      "basis", "input_tokens", "output_tokens", "source",
    ]);
  });

  it("adds an all-or-nothing encrypted bearer envelope to API keys", async () => {
    const columns = await db.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'api_keys'
          AND column_name IN ('bearer_ciphertext','bearer_iv','bearer_tag')
        ORDER BY column_name`,
    );
    expect(columns.rows.map((row) => String(row.column_name))).toEqual([
      "bearer_ciphertext", "bearer_iv", "bearer_tag",
    ]);
    const constraint = await db.query(
      `SELECT conname FROM pg_constraint WHERE conname = 'api_keys_bearer_envelope_check'`,
    );
    expect(constraint.rows).toHaveLength(1);
  });

  it("adds an enabled-by-default Assistant gate to model profiles", async () => {
    const columns = await db.query(
      `SELECT column_name, column_default, is_nullable
         FROM information_schema.columns
        WHERE table_name = 'model_profiles' AND column_name = 'assistant_enabled'`,
    );
    expect(columns.rows).toEqual([
      expect.objectContaining({
        column_name: "assistant_enabled",
        column_default: "true",
        is_nullable: "NO",
      }),
    ]);
  });

  it("migration 53 disables legacy platform-root knowledge sync chains", async () => {
    const now = "2026-07-23T07:00:00.000Z";
    await db.query(
      `INSERT INTO org_automations
         (id, namespace, template_id, enabled, auto_approve, config,
          interval_seconds, cursor_value, not_before, last_run_at,
          last_run_status, last_error, consecutive_failures, row_version,
          created_by, created_at, updated_at)
       VALUES
         ('legacy-root-sync', '', 'fresh-summaries', TRUE, FALSE, '{}'::jsonb,
          86400, NULL, $1, $1, 'failed',
          'consolidation namespace must be a canonical private namespace',
          1, 1, 'legacy', $1, $1)`,
      [now],
    );
    await db.query(
      `INSERT INTO durable_jobs
         (id, kind, namespace, state, payload, attempts, available_at,
          lease_owner, lease_expires_at, last_error, created_at, updated_at)
       VALUES
         ('legacy-root-sync-job', 'automation', '', 'queued',
          '{"automationId":"legacy-root-sync"}'::jsonb, 0, $1,
          NULL, NULL, NULL, $1, $1)`,
      [now],
    );
    await db.query(`DELETE FROM schema_migrations WHERE version = 53`);

    await migrate(db, DIM);

    const automation = await db.query(
      `SELECT enabled, not_before
         FROM org_automations
        WHERE id = 'legacy-root-sync'`,
    );
    expect(automation.rows).toEqual([{ enabled: false, not_before: null }]);
    const jobs = await db.query(
      `SELECT id FROM durable_jobs WHERE id = 'legacy-root-sync-job'`,
    );
    expect(jobs.rows).toEqual([]);
  });

  it("creates every M1–M4 table a booted kernel needs", async () => {
    const res = await db.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const names = new Set(res.rows.map((r) => r.table_name as string));
    for (const t of [
      // M1 core
      "schema_migrations",
      "memory_objects",
      "concepts",
      "entity_registry",
      "audit_log",
      "policies",
      "api_keys",
      "cost_ledger",
      // M2
      "scorecards",
      // M3 ingestion
      "sources",
      "source_documents",
      "source_document_claims",
      "source_webhook_receipts",
      "obsidian_ingress_receipts",
      "fragmentation_reports",
      // M4 tenancy + erasure
      "tenants",
      "tombstones",
      "deletion_certificates",
      // R4 human onboarding + verified setup
      "auth_bootstrap",
      "auth_invitations",
      "setup_operations",
      // R5 governed movement and sharing
      "knowledge_concepts",
      "knowledge_versions",
      "memory_pins",
      "consolidation_runs",
      "knowledge_proposals",
      "proposal_decisions",
      "movement_actions",
      "memory_segments",
      "segment_members",
      "segment_mounts",
      "memory_forks",
      "model_connections",
      "model_profiles",
      "policy_documents",
      "policy_document_quota_usage",
      "agent_access_events",
      "agent_access_alerts",
      "agent_access_requests",
    ]) {
      expect(names, `missing table after boot: ${t}`).toContain(t);
    }
  });

  it("every table a booted kernel needs is SELECT-able (schema is live, not just declared)", async () => {
    for (const t of [
      "memory_objects",
      "concepts",
      "entity_registry",
      "audit_log",
      "policies",
      "api_keys",
      "cost_ledger",
      "scorecards",
      "sources",
      "source_documents",
      "source_document_claims",
      "source_webhook_receipts",
      "obsidian_ingress_receipts",
      "fragmentation_reports",
      "tenants",
      "tombstones",
      "deletion_certificates",
      "auth_bootstrap",
      "auth_invitations",
      "setup_operations",
      "knowledge_concepts",
      "knowledge_versions",
      "memory_pins",
      "consolidation_runs",
      "knowledge_proposals",
      "proposal_decisions",
      "movement_actions",
      "memory_segments",
      "segment_members",
      "segment_mounts",
      "memory_forks",
      "model_connections",
      "model_profiles",
      "policy_documents",
      "policy_document_quota_usage",
      "agent_access_events",
      "agent_access_alerts",
      "agent_access_requests",
    ]) {
      const res = await db.query(`SELECT count(*) AS n FROM ${t}`);
      expect(Number(res.rows[0].n)).toBe(0);
    }
  });

  it("is idempotent on a second boot against the same database (no re-apply, no error)", async () => {
    const before = await db.query(
      `SELECT version, applied_at FROM schema_migrations ORDER BY version`,
    );
    // A container restart re-runs Kernel.boot → migrate against the persisted
    // volume; it must be a clean no-op, not a duplicate-key crash.
    await migrate(db, DIM);
    const after = await db.query(
      `SELECT version, applied_at FROM schema_migrations ORDER BY version`,
    );
    expect(after.rows.length).toBe(before.rows.length);
    expect(after.rows.map((r) => String(r.applied_at))).toEqual(
      before.rows.map((r) => String(r.applied_at)),
    );
  });

  it("migration 82 preserves invitation history while enforcing one live email slot", async () => {
    await db.query(
      `INSERT INTO auth_invitations
         (id,email,namespace,role,token_hash,created_by,created_at,expires_at,
          accepted_at,revoked_at,updated_at)
       VALUES ('history-live','history@example.test','acme','member','history-hash-a',
               'owner','2026-01-01','2027-01-01',NULL,NULL,'2026-01-01')`,
    );
    await expect(db.query(
      `INSERT INTO auth_invitations
         (id,email,namespace,role,token_hash,created_by,created_at,expires_at,
          accepted_at,revoked_at,updated_at)
       VALUES ('history-duplicate','history@example.test','acme','member','history-hash-b',
               'owner','2026-02-01','2027-02-01',NULL,NULL,'2026-02-01')`,
    )).rejects.toThrow();

    await db.query(
      `UPDATE auth_invitations
          SET accepted_at = '2026-02-01', updated_at = '2026-02-01'
        WHERE id = 'history-live'`,
    );
    await db.query(
      `INSERT INTO auth_invitations
         (id,email,namespace,role,token_hash,created_by,created_at,expires_at,
          accepted_at,revoked_at,updated_at)
       VALUES ('history-next','history@example.test','acme','member','history-hash-c',
               'owner','2026-03-01','2027-03-01',NULL,NULL,'2026-03-01')`,
    );
    expect((await db.query(
      `SELECT id FROM auth_invitations WHERE email = 'history@example.test' ORDER BY id`,
    )).rows).toEqual([{ id: "history-live" }, { id: "history-next" }]);
  });

  it("a genuinely fresh database migrates to head from scratch (independent instance)", async () => {
    // A second, independent in-memory PGlite — proves boot does not depend on
    // any residual state from the shared instance above.
    const cfg = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
    const fresh = await createDb(cfg);
    try {
      await migrate(fresh, DIM);
      const res = await fresh.query(
        `SELECT version FROM schema_migrations ORDER BY version`,
      );
      expect(res.rows.map((r) => Number(r.version))).toEqual(MIGRATIONS.map((m) => m.version));
      // The M4 erasure/tenancy tables exist on the fresh instance too.
      const t = await fresh.query(
        `SELECT count(*) AS n FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_name IN ('tenants','tombstones','deletion_certificates')`,
      );
      expect(Number(t.rows[0].n)).toBe(3);
    } finally {
      await fresh.close();
    }
  });
});
