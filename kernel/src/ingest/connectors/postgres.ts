/**
 * Module C — PostgresConnector: introspects a Postgres schema into facts (one
 * doc per table describing its columns). `verbatim:true` — the content is a
 * structured, machine-built sentence, not prose to be re-extracted.
 *
 * Source-query surface (D10): `ctx.config.query`, a kernel-injected
 * `(sql, params) => Promise<{ rows }>`. For the credential-free case the kernel
 * wires its OWN Db.query into `config.query`. For an external DSN (`cfg.dsn`)
 * the connector opens an npm `pg` Client itself — the live path, gated on a
 * real DSN and NOT exercised in tests. The connector NEVER receives a kernel Db
 * handle; the injected query fn (or its own pg client) is its whole world.
 *
 * Imports ONLY ../../types.js + node:crypto (via framework.ts) + npm `pg`
 * (dynamically, live path only). No src/index, src/db, src/audit, src/write.
 */

import type {
  ConnectorContext,
  EnterpriseConnector,
  GovernedSourceReadContext,
  GovernedSourceReadResult,
  LiveDoc,
  LiveQueryContext,
  SyncResult,
} from "../../types.js";
import { assertSecurePostgresDsn } from "../../security/postgres.js";
import {
  SourceUnavailableError,
  syncWithDrift,
  type EnumeratedDoc,
} from "./framework.js";

/** Kernel-injected source-query surface (or an npm pg client's query). */
export type QueryFn = (
  sql: string,
  params?: unknown[],
) => Promise<{ rows: unknown[] }>;

interface ColumnRow {
  table_name: string;
  column_name: string;
  data_type: string;
}

const INTROSPECT_SQL = `
  SELECT table_name, column_name, data_type
  FROM information_schema.columns
  WHERE table_schema = 'public'
  ORDER BY table_name, ordinal_position
`;

/**
 * HaloMem's OWN control-plane tables. For the credential-free case the kernel
 * injects its own Db.query, pointing this connector at the SAME database that
 * holds the auth/audit/store — introspecting it would ingest the kernel's
 * internal schema (api_keys, audit_log, cost_ledger, …) as org-scoped, ACL-
 * visible "facts". These names are excluded so the connector never surfaces the
 * control plane as organizational memory. (An external customer DSN is unlikely
 * to reuse these exact names; if it does, the collision is excluded too — a
 * deliberate, safe conservatism.)
 *
 * MUST cover EVERY table src/db/migrations.ts creates — the set previously
 * listed only 13 of ~38 tables, leaking the auth/session/tenant/key-state
 * schemas (users, sessions, cold_kek_state, …) into tenant-visible memory via
 * both PostgresConnector.sync and derivePointerSummaries. A regression test
 * (test/m6-review-fixes.test.ts) parses migrations.ts and fails if a new
 * table is added without an entry here.
 */
export const INTERNAL_TABLES: ReadonlySet<string> = new Set([
  // Store + retrieval
  "memory_objects",
  "concepts",
  "entity_registry",
  "scorecards",
  // Auth / identity / control room
  "api_keys",
  "users",
  "sessions",
  "auth_bootstrap",
  "auth_invitations",
  "auth_signup_sessions",
  "user_external_identities",
  "agent_connection_grants",
  "agent_key_handoffs",
  "agent_access_events",
  "agent_access_alerts",
  "agent_access_requests",
  "oidc_identities",
  "scim_users",
  "scim_groups",
  "scim_group_members",
  "teams",
  "org_teams",
  "org_team_members",
  "setup_operations",
  // Governance / audit / policy / spend
  "audit_log",
  "audit_chain_state",
  "policies",
  "policy_documents",
  "policy_document_quota_usage",
  "policy_agent_events",
  "policy_agent_state",
  "cost_ledger",
  "usage_events",
  "query_traces",
  // Assistant observability is control-plane metadata, never organizational
  // knowledge. Keep every v72 table out of credential-free introspection.
  "model_price_daily",
  "assistant_actor_lifecycle",
  "ai_turns",
  "model_invocations",
  "memory_title_invocations",
  "conflict_detection_queue",
  "conflict_pair_recheck_queue",
  "conflict_repair_proposals",
  "entity_tag_queue",
  "durable_jobs",
  "durable_tickets",
  "durable_rate_limits",
  "tenants",
  "fact_disputes",
  "conflict_scan_runs",
  "conflict_scan_findings",
  "conflict_scan_queue_guard",
  "agent_session_summaries",
  "agent_session_summary_memories",
  "model_connections",
  "model_profiles",
  "copilot_conversations",
  "copilot_conversation_messages",
  "copilot_routines",
  "copilot_routine_runs",
  // Communication channels
  "channel_immutable_update_guard",
  "channel_connections",
  "channel_credentials",
  "agent_channel_grants",
  "channel_ingress_receipts",
  "channel_events",
  "channel_send_intents",
  "channel_delivery_attempts",
  "channel_runtime_state",
  "channel_oauth_sessions",
  "channel_google_chat_setup_sessions",
  "channel_verifications",
  "channel_shadow_comparisons",
  "channel_ownership_leases",
  // Sealed provider session material for socket-delivered channels (v71).
  "channel_socket_state",
  // Ingestion
  "sources",
  "source_credentials",
  // Single-use direct-connector OAuth state custody (v86): holds the
  // initiating admin identity snapshot, so it is control plane, never data.
  "source_oauth_sessions",
  "source_webhook_receipts",
  "obsidian_ingress_receipts",
  "nango_environment_capacity",
  "nango_connect_attempts",
  "connector_cursors",
  "source_documents",
  "source_document_claims",
  "fragmentation_reports",
  "knowledge_bases",
  "knowledge_sources",
  "company_file_upload_attempts",
  "company_file_ingest_jobs",
  "company_file_ingest_chunks",
  "company_file_quota_usage",
  "company_files",
  "entity_mentions",
  "entity_relationships",
  "entity_relationship_evidence",
  // Erasure / cold-store key state
  "tombstones",
  "deletion_certificates",
  "erasure_fences",
  "concept_quarantine",
  "cold_concept_keys",
  "cold_kek_state",
  // Knowledge / movement / segments / forks / warm mirrors
  "knowledge_concepts",
  "knowledge_versions",
  "knowledge_proposals",
  "proposal_decisions",
  "consolidation_runs",
  "memory_pins",
  "movement_actions",
  "memory_segments",
  "segment_members",
  "segment_mounts",
  "memory_forks",
  "warm_mirror_ops",
  "warm_store_leases",
  // M9 parity — skills library, hosted OAuth AS, answer outcomes, automations,
  // credits, usage alerts. oauth_* in particular hold credential material
  // (hashed secrets/tokens) and must never surface as organizational memory.
  "skills",
  "skill_labels",
  "skill_label_history",
  "skill_categories",
  "skill_tags",
  "skill_agent_usage",
  "skill_vetting_runs",
  "oauth_clients",
  "oauth_tokens",
  "oauth_refresh_tokens",
  "oauth_authorization_codes",
  "answer_outcomes",
  "org_automations",
  "credit_balances",
  "credit_ledger",
  "usage_alerts",
  // M10 access — grants and preview-session credential hashes (D43) must
  // never surface as organizational memory.
  "access_grants",
  "access_preview_sessions",
  // Early-access allowance ledger (v102): trial clocks, seats, and usage are
  // commercial control-plane rows, never organizational memory.
  "early_access_trials",
  "early_access_members",
  "early_access_usage",
  // Migration bookkeeping
  "schema_migrations",
]);

/** Coerce a driver row (pg or injected stub) into a typed ColumnRow. */
function toColumnRow(row: unknown): ColumnRow | null {
  if (row === null || typeof row !== "object") return null;
  const r = row as Record<string, unknown>;
  if (typeof r.table_name !== "string" || typeof r.column_name !== "string") {
    return null;
  }
  const dataType = typeof r.data_type === "string" ? r.data_type : "unknown";
  return {
    table_name: r.table_name,
    column_name: r.column_name,
    data_type: dataType,
  };
}

/**
 * Resolve the query surface: the injected `config.query` if present, else open
 * an npm `pg` Client on `config.dsn` (live path). Returns the query fn plus an
 * optional cleanup to close a self-opened client.
 */
async function resolveQuery(
  config: Record<string, unknown>,
): Promise<{ query: QueryFn; close?: () => Promise<void> }> {
  const injected = config.query;
  if (typeof injected === "function") {
    return { query: injected as QueryFn };
  }

  const dsn = config.dsn;
  if (typeof dsn !== "string" || dsn.length === 0) {
    throw new Error(
      "PostgresConnector: config.query or config.dsn is required",
    );
  }
  assertSecurePostgresDsn(dsn, "PostgresConnector");

  // Live path: open our own pg client on the external DSN. Dynamic import keeps
  // pg off the hermetic test path (tests always inject config.query).
  const pg = await import("pg");
  const client = new pg.Client({ connectionString: dsn });
  await client.connect();
  const query: QueryFn = async (sql, params) =>
    client.query(sql, params as unknown[]);
  return { query, close: () => client.end() };
}

// ---------------------------------------------------------------------------
// M6 live-query support (D12) — helpers shared by PostgresConnector.liveQuery.
// ---------------------------------------------------------------------------

/**
 * Strict SQL identifier: a pointer's sourceRef is attacker-adjacent input (it
 * rides in a fact row), so it is validated against this before EVER appearing
 * in SQL text. Anything else is rejected outright — no quoting rescue.
 */
const IDENTIFIER_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/** Default live-call budget when the context does not carry one. */
const DEFAULT_LIVE_TIMEOUT_MS = 5000;

/** Postgres data types whose columns we ILIKE-match query terms against. */
function isTextType(dataType: string): boolean {
  const t = dataType.toLowerCase();
  return t === "text" || t.includes("char");
}

/**
 * Escape ILIKE wildcards in a user term so `_` and `%` match literally
 * (queries always run with `ESCAPE '\'`). CONTRACTS.md rule 3: never LIKE
 * without ESCAPE.
 */
function escapeLikeTerm(term: string): string {
  return term.replace(/[\\%_]/g, (m) => `\\${m}`);
}

/** Split a natural-language query into non-empty match terms. */
function queryTerms(query: string): string[] {
  return query.split(/\s+/).filter((t) => t.length > 0);
}

/**
 * Remove every occurrence of the revealed credential from an error message
 * before it can reach a SourceUnavailableError (whose message travels to audit
 * and logs). Passthrough tokens are radioactive — they must not survive even
 * inside a driver error string.
 */
function scrubCredential(message: string, secret: string): string {
  if (secret.length === 0) return message;
  return message.split(secret).join("[redacted]");
}

/** Race a promise against the live-call budget without leaking the timer. */
async function withTimeout<T>(work: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** One-line fact rendering of a row, mirroring csv.ts `rowToFact`. */
function rowToLine(row: Record<string, unknown>): string {
  return Object.entries(row)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join(", ");
}

export class PostgresConnector implements EnterpriseConnector {
  readonly kind = "postgres" as const;
  readonly version = "halomem-connector/v1" as const;

  capabilities() {
    return {
      incremental: false,
      liveQuery: true,
      sourceAcl: false,
      webhook: false,
      oauth: false,
    };
  }
  async validateConfig(config: Record<string, unknown>): Promise<void> {
    if (typeof config.query !== "function" && (typeof config.dsn !== "string" || !config.dsn)) {
      throw new Error("PostgresConnector: config.query or config.dsn is required");
    }
    if (typeof config.dsn === "string") {
      assertSecurePostgresDsn(config.dsn, "PostgresConnector");
    }
  }

  async testConnection(config: Record<string, unknown>): Promise<{ ok: boolean; detail?: string }> {
    try {
      await this.validateConfig(config);
      const { query, close } = await resolveQuery(config);
      try {
        await query("SELECT 1");
      } finally {
        if (close) await close();
      }
      return { ok: true };
    } catch {
      return { ok: false, detail: "postgres-unreachable" };
    }
  }

  /**
   * Optional connection config for the live-query path (D12: import and
   * live-query share the connector's config). Tests inject `{ query }`;
   * production leaves it empty and the live path connects with the resolved
   * credential's DSN. The default keeps `new PostgresConnector()` (registry,
   * sync path) working unchanged.
   */
  constructor(private readonly config: Record<string, unknown> = {}) {}

  /** Available when there is a query surface: an injected query fn or a DSN. */
  available(config: Record<string, unknown>): boolean {
    return !!(config.query || config.dsn);
  }

  /**
   * D12 live query: answer `ctx.query` against the live table named by the
   * pointer's sourceRef. HARD read-only — the session opens `BEGIN READ ONLY`
   * and sets a local statement_timeout before any data SQL. Query terms are
   * bound as parameters, never interpolated. One retry, then
   * SourceUnavailableError (credential-scrubbed).
   */
  async liveQuery(ctx: LiveQueryContext): Promise<LiveDoc[]> {
    const table = ctx.pointer.sourceRef;
    if (!IDENTIFIER_RE.test(table)) {
      // Attacker-adjacent input: reject before it can appear in SQL text.
      // Not a SourceUnavailableError — this is invalid input, not brownout,
      // and must not be retried.
      throw new Error(
        `PostgresConnector.liveQuery: invalid table identifier in pointer sourceRef`,
      );
    }

    const timeoutMs =
      ctx.timeoutMs > 0 ? Math.floor(ctx.timeoutMs) : DEFAULT_LIVE_TIMEOUT_MS;
    const limit = Math.max(1, Math.floor(ctx.limit));

    let lastCause = "unknown failure";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await withTimeout(this.liveAttempt(ctx, table, limit, timeoutMs), timeoutMs);
      } catch (err) {
        const raw = err instanceof Error ? err.message : String(err);
        lastCause = scrubCredential(raw, ctx.credential.reveal());
      }
    }
    throw new SourceUnavailableError(ctx.credential.connectorId, lastCause);
  }

  /**
   * M8/D27 governed source read. Unlike the legacy pointer-confirmation lane,
   * this path accepts only a gateway-derived explicit projection and never
   * emits `SELECT *`. The returned objects are reconstructed from that
   * projection as a second defence if a test double or driver misbehaves.
   */
  async governedRead(
    ctx: GovernedSourceReadContext,
  ): Promise<GovernedSourceReadResult> {
    const table = ctx.sourceRef;
    if (!IDENTIFIER_RE.test(table)) {
      throw new Error("PostgresConnector.governedRead: invalid sourceRef");
    }
    if (
      ctx.fields.length === 0 || ctx.fields.length > 64 ||
      new Set(ctx.fields).size !== ctx.fields.length ||
      ctx.fields.some((field) => !IDENTIFIER_RE.test(field))
    ) {
      throw new Error("PostgresConnector.governedRead: invalid field projection");
    }
    if (!Number.isSafeInteger(ctx.limit) || ctx.limit < 1 ||
        !Number.isSafeInteger(ctx.maxBytes) || ctx.maxBytes < 1) {
      throw new Error("PostgresConnector.governedRead: invalid bounds");
    }
    const terms = queryTerms(ctx.query);
    if (terms.length === 0 || terms.length > 32 || terms.some((term) => term.length > 128) ||
        terms.length * ctx.fields.length > 2_048) {
      throw new Error("PostgresConnector.governedRead: query complexity exceeded");
    }

    const timeoutMs = ctx.timeoutMs > 0
      ? Math.floor(ctx.timeoutMs)
      : DEFAULT_LIVE_TIMEOUT_MS;
    return withTimeout(this.governedReadAttempt(ctx, table, timeoutMs), timeoutMs);
  }

  private async governedReadAttempt(
    ctx: GovernedSourceReadContext,
    table: string,
    timeoutMs: number,
  ): Promise<GovernedSourceReadResult> {
    const { query, close } = await this.resolveLiveQuery({
      query: ctx.query,
      pointer: { sourceRef: table },
      credential: ctx.credential,
      limit: ctx.limit,
      timeoutMs,
    });
    try {
      await query("BEGIN READ ONLY");
      try {
        await query(`SET LOCAL statement_timeout = ${timeoutMs}`);
        const introspection = await query(
          `SELECT column_name, data_type FROM information_schema.columns
           WHERE table_schema = 'public' AND table_name = $1
           ORDER BY ordinal_position`,
          [table],
        );
        const columnTypes = new Map<string, string>();
        for (const raw of Array.isArray(introspection.rows) ? introspection.rows : []) {
          if (raw === null || typeof raw !== "object") continue;
          const row = raw as Record<string, unknown>;
          if (typeof row.column_name === "string" && IDENTIFIER_RE.test(row.column_name)) {
            columnTypes.set(
              row.column_name,
              typeof row.data_type === "string" ? row.data_type : "unknown",
            );
          }
        }
        if (!ctx.fields.every((field) => columnTypes.has(field))) {
          throw new Error("PostgresConnector.governedRead: projected field unavailable");
        }

        const terms = queryTerms(ctx.query);
        const searchable = ctx.fields.filter((field) => isTextType(columnTypes.get(field)!));
        if (terms.length === 0 || searchable.length === 0) {
          await query("COMMIT");
          return { rows: [], bytes: 2, truncated: false };
        }

        const params = terms.map((term) => `%${escapeLikeTerm(term)}%`);
        const predicate = searchable
          .map((field) => terms
            .map((_, index) => `"${field}"::text ILIKE $${index + 1} ESCAPE '\\'`)
            .join(" OR "))
          .join(" OR ");
        const projection = ctx.fields.map((field) => `"${field}"`).join(", ");
        const data = await query(
          `SELECT ${projection} FROM "${table}" WHERE ${predicate} LIMIT ${ctx.limit}`,
          params,
        );

        const rows: Record<string, unknown>[] = [];
        let bytes = 2; // []
        let truncated = false;
        for (const raw of Array.isArray(data.rows) ? data.rows : []) {
          if (raw === null || typeof raw !== "object" || Array.isArray(raw)) continue;
          const source = raw as Record<string, unknown>;
          const projected = Object.fromEntries(ctx.fields.map((field) => [field, source[field]]));
          const encoded = JSON.stringify(projected);
          const nextBytes = bytes + (rows.length > 0 ? 1 : 0) + Buffer.byteLength(encoded, "utf8");
          if (nextBytes > ctx.maxBytes) {
            truncated = true;
            break;
          }
          rows.push(projected);
          bytes = nextBytes;
        }
        await query("COMMIT");
        return { rows, bytes, truncated };
      } catch (error) {
        try {
          await query("ROLLBACK");
        } catch {
          // Preserve the original fixed-boundary failure.
        }
        throw error;
      }
    } finally {
      if (close) await close();
    }
  }

  /** One live attempt: open session, fence read-only, introspect, match. */
  private async liveAttempt(
    ctx: LiveQueryContext,
    table: string,
    limit: number,
    timeoutMs: number,
  ): Promise<LiveDoc[]> {
    const { query, close } = await this.resolveLiveQuery(ctx);
    try {
      // Hard read-only fence + server-side budget, BEFORE any data SQL.
      await query("BEGIN READ ONLY");
      try {
        await query(`SET LOCAL statement_timeout = ${timeoutMs}`);

        // Introspect the table's columns ($1-parameterized — the table name is
        // data here, not SQL text).
        const introspection = await query(
          `SELECT column_name, data_type FROM information_schema.columns
           WHERE table_schema = 'public' AND table_name = $1
           ORDER BY ordinal_position`,
          [table],
        );
        const rows = Array.isArray(introspection.rows) ? introspection.rows : [];
        const textColumns: string[] = [];
        for (const raw of rows) {
          if (raw === null || typeof raw !== "object") continue;
          const r = raw as Record<string, unknown>;
          if (typeof r.column_name !== "string") continue;
          if (!IDENTIFIER_RE.test(r.column_name)) continue;
          if (typeof r.data_type === "string" && isTextType(r.data_type)) {
            textColumns.push(r.column_name);
          }
        }
        if (rows.length === 0) {
          throw new Error(`table not found: ${table}`);
        }

        const terms = queryTerms(ctx.query);
        if (terms.length === 0 || textColumns.length === 0) {
          // Nothing to match terms against — an empty live answer, not an
          // unbounded table dump.
          await query("COMMIT");
          return [];
        }

        // Terms bind as $n parameters; only the regex-validated table and
        // column identifiers appear in SQL text. LIMIT is a validated integer.
        const params = terms.map((t) => `%${escapeLikeTerm(t)}%`);
        const predicate = textColumns
          .map((col) =>
            terms
              .map((_, i) => `"${col}"::text ILIKE $${i + 1} ESCAPE '\\'`)
              .join(" OR "),
          )
          .join(" OR ");
        const data = await query(
          `SELECT * FROM "${table}" WHERE ${predicate} LIMIT ${limit}`,
          params,
        );
        await query("COMMIT");

        const fetchedAt = new Date().toISOString();
        const dataRows = Array.isArray(data.rows) ? data.rows : [];
        return dataRows.flatMap((raw, index): LiveDoc[] => {
          if (raw === null || typeof raw !== "object") return [];
          const row = raw as Record<string, unknown>;
          const pk = row.id ?? row[`${table}_id`];
          const key =
            typeof pk === "string" || typeof pk === "number" ? String(pk) : String(index);
          return [
            {
              docId: `${table}:${key}`,
              content: rowToLine(row),
              sourceRef: ctx.pointer.sourceRef,
              fetchedAt,
            },
          ];
        });
      } catch (err) {
        // Best-effort rollback so a pooled/injected session is left clean.
        try {
          await query("ROLLBACK");
        } catch {
          /* session already broken — the original error is what matters */
        }
        throw err;
      }
    } finally {
      if (close) await close();
    }
  }

  /**
   * Live-query surface: the injected `config.query` if present (tests /
   * kernel-wired), else a fresh pg Client on the resolved credential's DSN
   * (service or passthrough — both are just a DSN here). The credential is
   * revealed only into the pg constructor, never stored on the connector.
   */
  private async resolveLiveQuery(
    ctx: LiveQueryContext,
  ): Promise<{ query: QueryFn; close?: () => Promise<void> }> {
    const injected = this.config.query;
    if (typeof injected === "function") {
      return { query: injected as QueryFn };
    }
    const dsn = ctx.credential.reveal();
    assertSecurePostgresDsn(dsn, "PostgresConnector");
    const pg = await import("pg");
    const client = new pg.Client({ connectionString: dsn });
    await client.connect();
    const query: QueryFn = async (sql, params) =>
      client.query(sql, params as unknown[]);
    return { query, close: () => client.end() };
  }

  async sync(ctx: ConnectorContext): Promise<SyncResult> {
    const { query, close } = await resolveQuery(ctx.config);

    const enumerate = async (): Promise<EnumeratedDoc[]> => {
      const res = await query(INTROSPECT_SQL);
      const rows = Array.isArray(res.rows) ? res.rows : [];

      // Group columns into one doc per table, preserving column order. Skip
      // HaloMem's own control-plane tables so a credential-free sync (which
      // introspects the kernel's OWN database) never ingests internal auth /
      // audit / store schema as organizational memory.
      const byTable = new Map<string, ColumnRow[]>();
      for (const raw of rows) {
        const col = toColumnRow(raw);
        if (!col) continue;
        if (INTERNAL_TABLES.has(col.table_name)) continue;
        const list = byTable.get(col.table_name);
        if (list) list.push(col);
        else byTable.set(col.table_name, [col]);
      }

      const docs: EnumeratedDoc[] = [];
      for (const [table, columns] of byTable) {
        const cols = columns
          .map((c) => `${c.column_name} (${c.data_type})`)
          .join(", ");
        const content = `Table ${table} has columns: ${cols}.`;
        docs.push({
          docId: `table:${table}`,
          content,
          verbatim: true,
          scope: "org",
        });
      }
      return docs;
    };

    try {
      return await syncWithDrift(ctx, enumerate);
    } finally {
      if (close) await close();
    }
  }
}
