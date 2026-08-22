import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { ulid } from "ulid";

import { hashKey, isRootOwner } from "../auth/index.js";
import { normalizedOrganizationName } from "../console/org-name.js";
import type { Db } from "../db/client.js";
import type { DriverRegistry } from "../driver/index.js";
import type { SigningKey } from "../erasure/keys.js";
import type { SealedSourceConfig } from "../ingest/source-config.js";
import { isValidTenantId } from "../tenancy/index.js";
import type {
  Identity,
  MountedRetrieverCapability,
  SetupInput,
  SetupResult,
  SourceKind,
  SyncResult,
  Team,
  Tenant,
} from "../types.js";

export class SetupConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SetupConflictError";
  }
}

export class SetupValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SetupValidationError";
  }
}

interface SetupOperationRow {
  id: string;
  idempotency_key: string;
  request_hash: string;
  tenant_id: string;
  team_namespace: string;
  source_id: string | null;
  badge_key_id: string;
  retriever: string;
  public_url: string;
  status: SetupResult["status"];
  source_status: "skipped" | "pending" | "synced" | "failed";
  source_result: unknown;
  source_error: string | null;
  badge_ciphertext: string;
  badge_iv: string;
  badge_tag: string;
}

export interface SetupServiceDeps {
  db: Db;
  registry: DriverRegistry;
  signingKey: SigningKey;
  preflightSource(source: NonNullable<SetupInput["source"]>): Promise<void>;
  syncSource(sourceId: string, identity: Identity): Promise<SyncResult>;
  sealSourceConfig(
    id: string,
    namespace: string,
    kind: SourceKind,
    config: Record<string, unknown>,
  ): SealedSourceConfig;
  /**
   * Default skill library hook (src/skills/defaults.ts): invoked with the new
   * tenant root after the core transaction commits. The kernel wiring
   * brownouts on failure — provisioning never fails on a seed error.
   */
  seedDefaultSkills?(namespace: string): Promise<void>;
}

const SOURCE_KINDS: ReadonlySet<SourceKind> = new Set([
  "filesystem",
  "postgres",
  "notion",
  "slack",
]);

function requireText(value: string, field: string, max = 200): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max) {
    throw new SetupValidationError(`${field} must be 1-${max} characters`);
  }
  return normalized;
}

function validateInput(input: SetupInput): SetupInput {
  const idempotencyKey = requireText(input.idempotencyKey, "idempotencyKey", 200);
  const tenantId = requireText(input.tenant.id, "tenant.id", 100);
  if (!isValidTenantId(tenantId)) {
    throw new SetupValidationError("tenant.id must be a single namespace segment");
  }
  const teamId = requireText(input.team.id, "team.id", 100);
  if (teamId.includes("/")) {
    throw new SetupValidationError("team.id must be a single namespace segment");
  }
  const monthlyBudgetUsd = input.tenant.monthlyBudgetUsd;
  if (monthlyBudgetUsd !== undefined && monthlyBudgetUsd !== null &&
      (!Number.isFinite(monthlyBudgetUsd) || monthlyBudgetUsd < 0)) {
    throw new SetupValidationError("tenant.monthlyBudgetUsd must be non-negative");
  }
  const rateLimitPerMin = input.tenant.rateLimitPerMin;
  if (rateLimitPerMin !== undefined && rateLimitPerMin !== null &&
      (!Number.isInteger(rateLimitPerMin) || rateLimitPerMin <= 0)) {
    throw new SetupValidationError("tenant.rateLimitPerMin must be a positive integer");
  }
  if (input.source && !SOURCE_KINDS.has(input.source.kind)) {
    throw new SetupValidationError(`source kind '${input.source.kind}' is not a connector`);
  }
  return {
    idempotencyKey,
    tenant: {
      id: tenantId,
      name: requireText(input.tenant.name, "tenant.name"),
      monthlyBudgetUsd: monthlyBudgetUsd ?? null,
      rateLimitPerMin: rateLimitPerMin ?? null,
    },
    team: { id: teamId, name: requireText(input.team.name, "team.name") },
    source: input.source
      ? { kind: input.source.kind, config: input.source.config ?? {} }
      : undefined,
    retriever: requireText(input.retriever ?? "baseline", "retriever", 100),
    agentActor: requireText(
      input.agentActor ?? `${tenantId}-${teamId}-agent`,
      "agentActor",
    ),
  };
}

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new SetupValidationError("setup contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  throw new SetupValidationError("setup contains an unsupported value");
}

function requestHash(input: SetupInput, publicUrl: string): string {
  return createHash("sha256").update(canonical({ input, publicUrl }), "utf8").digest("hex");
}

function setupEncryptionKey(signingKey: SigningKey): Buffer {
  const proof = signingKey.sign(Buffer.from("halomem/setup/badge/v1", "utf8"));
  return createHash("sha256").update(proof).digest();
}

function encryptBadge(
  plaintext: string,
  signingKey: SigningKey,
  operationId: string,
  keyId: string,
): { ciphertext: string; iv: string; tag: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", setupEncryptionKey(signingKey), iv);
  cipher.setAAD(Buffer.from(`${operationId}:${keyId}`, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function decryptBadge(row: SetupOperationRow, signingKey: SigningKey): string {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    setupEncryptionKey(signingKey),
    Buffer.from(row.badge_iv, "base64"),
  );
  decipher.setAAD(Buffer.from(`${row.id}:${row.badge_key_id}`, "utf8"));
  decipher.setAuthTag(Buffer.from(row.badge_tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(row.badge_ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function toIso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(String(value)).toISOString();
}

function parseJson<T>(value: unknown): T | null {
  if (value === null || value === undefined) return null;
  return (typeof value === "string" ? JSON.parse(value) : value) as T;
}

function redactError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/:\/\/([^/@\s:]+):([^/@\s]+)@/g, "://[redacted]@").slice(0, 500);
}

export function validatePublicUrl(raw: string, secureDeployment: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SetupValidationError("HALOMEM_PUBLIC_URL must be an absolute http(s) URL");
  }
  if (!new Set(["http:", "https:"]).has(url.protocol) || url.username || url.password ||
      url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new SetupValidationError(
      "HALOMEM_PUBLIC_URL must be a credential-free http(s) origin without path, query, or fragment",
    );
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (secureDeployment && (url.protocol !== "https:" || local)) {
    throw new SetupValidationError(
      "HALOMEM_PUBLIC_URL must be a non-local https origin for a secure deployment",
    );
  }
  return url.origin;
}

export class SetupService {
  constructor(private readonly deps: SetupServiceDeps) {}

  capabilities(): MountedRetrieverCapability[] {
    return this.deps.registry.capabilities();
  }

  async run(rawInput: SetupInput, publicUrl: string, identity: Identity): Promise<SetupResult> {
    if (!isRootOwner(identity)) {
      throw new SetupValidationError("verified setup requires a root owner identity");
    }
    const input = validateInput(rawInput);
    const retriever = input.retriever ?? "baseline";
    if (!this.deps.registry.has(retriever)) {
      throw new SetupValidationError(`retriever '${retriever}' is not mounted`);
    }
    const hash = requestHash(input, publicUrl);
    let operation = await this.byIdempotencyKey(input.idempotencyKey);
    if (operation && operation.request_hash !== hash) {
      throw new SetupConflictError("idempotency key was already used for a different setup request");
    }

    if (!operation) {
      if (input.source) await this.deps.preflightSource(input.source);
      try {
        operation = await this.createCore(input, publicUrl, hash);
      } catch (err) {
        // A concurrent retry may win the unique idempotency-key insert. Re-read
        // and resume its operation rather than duplicating tenant/team/key rows.
        operation = await this.byIdempotencyKey(input.idempotencyKey);
        if (!operation) {
          throw new SetupConflictError(`setup core could not be created: ${redactError(err)}`);
        }
        if (operation.request_hash !== hash) {
          throw new SetupConflictError("idempotency key was already used for a different setup request");
        }
      }
    }

    if (operation.source_id && operation.source_status !== "synced") {
      if (input.source) await this.deps.preflightSource(input.source);
      operation = await this.syncFirstSource(operation, identity);
    }
    return this.result(operation);
  }

  async status(operationId: string, identity: Identity): Promise<SetupResult | null> {
    if (!isRootOwner(identity)) {
      throw new SetupValidationError("verified setup status requires a root owner identity");
    }
    const res = await this.deps.db.query(
      `SELECT * FROM setup_operations WHERE id = $1`,
      [operationId],
    );
    if (res.rows.length === 0) return null;
    return this.result(res.rows[0] as SetupOperationRow);
  }

  /**
   * Explicitly resume a durable setup after its first source sync failed.
   * The operation owns the source id and encrypted connector configuration, so
   * callers never need to resend credentials merely to retry.
   */
  async resume(operationId: string, identity: Identity): Promise<SetupResult | null> {
    if (!isRootOwner(identity)) {
      throw new SetupValidationError("verified setup retry requires a root owner identity");
    }
    const res = await this.deps.db.query(
      `SELECT * FROM setup_operations WHERE id = $1`,
      [operationId],
    );
    if (res.rows.length === 0) return null;
    let operation = res.rows[0] as SetupOperationRow;
    if (operation.source_id && operation.source_status !== "synced") {
      operation = await this.syncFirstSource(operation, identity);
    }
    return this.result(operation);
  }

  private async byIdempotencyKey(key: string): Promise<SetupOperationRow | null> {
    const res = await this.deps.db.query(
      `SELECT * FROM setup_operations WHERE idempotency_key = $1`,
      [key],
    );
    return res.rows.length === 0 ? null : res.rows[0] as SetupOperationRow;
  }

  private async createCore(
    input: SetupInput,
    publicUrl: string,
    hash: string,
  ): Promise<SetupOperationRow> {
    const operationId = ulid();
    const badgeKeyId = ulid();
    const sourceId = input.source ? ulid() : null;
    const plaintext = "hm_" + randomBytes(20).toString("hex");
    const encrypted = encryptBadge(plaintext, this.deps.signingKey, operationId, badgeKeyId);
    const now = new Date().toISOString();
    const tenantId = input.tenant.id;
    const tenantName = normalizedOrganizationName(input.tenant.name);
    const teamNamespace = `${tenantId}/${input.team.id}`;
    const retriever = input.retriever ?? "baseline";
    const actor = input.agentActor ?? `${tenantId}-${input.team.id}-agent`;
    const sealedSource = input.source && sourceId
      ? this.deps.sealSourceConfig(
          sourceId,
          teamNamespace,
          input.source.kind,
          input.source.config ?? {},
        )
      : null;

    const operation = await this.deps.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO tenants (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
         VALUES ($1, $2, 'active', $3, $4, $5)`,
        [tenantId, tenantName, input.tenant.monthlyBudgetUsd ?? null,
          input.tenant.rateLimitPerMin ?? null, now],
      );
      await tx.query(
        `INSERT INTO org_teams
           (id, namespace, organization_namespace, name, description, created_by, created_at)
         VALUES ($1, $2, $3, $4, '', $5, $6)
         ON CONFLICT (namespace) DO NOTHING`,
        [`setup:${teamNamespace}`, teamNamespace, tenantId, input.team.name, `setup:${operationId}`, now],
      );
      await tx.query(
        `INSERT INTO policies (namespace, yaml, updated_at) VALUES ($1, $2, $3)`,
        [teamNamespace, `retriever: ${JSON.stringify(retriever)}\n`, now],
      );
      await tx.query(
        `INSERT INTO api_keys
           (id, key_hash, namespace, actor, role, status, created_at, last_used)
         VALUES ($1, $2, $3, $4, 'agent', 'active', $5, NULL)`,
        [badgeKeyId, hashKey(plaintext), teamNamespace, actor, now],
      );
      if (input.source && sourceId) {
        await tx.query(
          `INSERT INTO sources
             (id, namespace, kind, config, created_at, last_sync, sync_status,
              last_sync_error, last_sync_started_at, config_ciphertext, config_iv,
              config_tag, config_kek_id, config_sha256, config_state)
           VALUES ($1, $2, $3, '{}'::jsonb, $4, NULL, 'pending', NULL, $4,
                   $5, $6, $7, $8, $9, 'encrypted')`,
          [sourceId, teamNamespace, input.source.kind, now,
            sealedSource!.ciphertext, sealedSource!.iv, sealedSource!.tag,
            sealedSource!.kekId, sealedSource!.sha256],
        );
      }
      const sourceStatus = input.source ? "pending" : "skipped";
      const status = input.source ? "source_pending" : "waiting_for_agent";
      const inserted = await tx.query(
        `INSERT INTO setup_operations
           (id, idempotency_key, request_hash, tenant_id, team_namespace,
            source_id, badge_key_id, retriever, public_url, status,
            source_status, source_result, source_error, badge_ciphertext,
            badge_iv, badge_tag, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, NULL,
                 $12, $13, $14, $15, $15)
         RETURNING *`,
        [operationId, input.idempotencyKey, hash, tenantId, teamNamespace,
          sourceId, badgeKeyId, retriever, publicUrl, status, sourceStatus,
          encrypted.ciphertext, encrypted.iv, encrypted.tag, now],
      );
      return inserted.rows[0] as SetupOperationRow;
    });
    // Seed the default skill library at the new tenant root AFTER commit —
    // the seeder opens its own transactions on the shared handle.
    await this.deps.seedDefaultSkills?.(tenantId);
    return operation;
  }

  private async syncFirstSource(
    operation: SetupOperationRow,
    identity: Identity,
  ): Promise<SetupOperationRow> {
    const started = new Date().toISOString();
    await this.deps.db.query(
      `UPDATE sources SET sync_status = 'pending', last_sync_error = NULL,
              last_sync_started_at = $2 WHERE id = $1`,
      [operation.source_id, started],
    );
    await this.deps.db.query(
      `UPDATE setup_operations SET status = 'source_pending', source_status = 'pending',
              source_error = NULL, updated_at = $2 WHERE id = $1`,
      [operation.id, started],
    );
    try {
      const syncResult = await this.deps.syncSource(operation.source_id!, identity);
      if (syncResult.errors.length > 0) {
        throw new Error(
          `source sync reported ${syncResult.errors.length} error(s): ${syncResult.errors[0]?.reason ?? "unknown error"}`,
        );
      }
      const completed = new Date().toISOString();
      await this.deps.db.query(
        `UPDATE sources SET sync_status = 'synced', last_sync_error = NULL WHERE id = $1`,
        [operation.source_id],
      );
      const updated = await this.deps.db.query(
        `UPDATE setup_operations
            SET status = 'waiting_for_agent', source_status = 'synced',
                source_result = $2, source_error = NULL, updated_at = $3
          WHERE id = $1 RETURNING *`,
        [operation.id, JSON.stringify(syncResult), completed],
      );
      return updated.rows[0] as SetupOperationRow;
    } catch (err) {
      const error = redactError(err);
      const failedAt = new Date().toISOString();
      await this.deps.db.query(
        `UPDATE sources SET sync_status = 'failed', last_sync_error = $2 WHERE id = $1`,
        [operation.source_id, error],
      );
      const updated = await this.deps.db.query(
        `UPDATE setup_operations
            SET status = 'source_failed', source_status = 'failed',
                source_error = $2, updated_at = $3
          WHERE id = $1 RETURNING *`,
        [operation.id, error, failedAt],
      );
      return updated.rows[0] as SetupOperationRow;
    }
  }

  private async result(initial: SetupOperationRow): Promise<SetupResult> {
    let operation = initial;
    const [tenantRes, teamRes, badgeRes, sourceRes] = await Promise.all([
      this.deps.db.query(
        `SELECT id, name, status, monthly_budget_usd, rate_limit_per_min, created_at
           FROM tenants WHERE id = $1`,
        [operation.tenant_id],
      ),
      this.deps.db.query(
        `SELECT namespace, name, created_at FROM org_teams WHERE namespace = $1`,
        [operation.team_namespace],
      ),
      this.deps.db.query(
        `SELECT id, namespace, actor, last_used FROM api_keys WHERE id = $1`,
        [operation.badge_key_id],
      ),
      operation.source_id
        ? this.deps.db.query(`SELECT id, namespace, kind FROM sources WHERE id = $1`, [operation.source_id])
        : Promise.resolve({ rows: [] }),
    ]);
    const tenantRow = tenantRes.rows[0] as Record<string, unknown>;
    const teamRow = teamRes.rows[0] as Record<string, unknown>;
    const badgeRow = badgeRes.rows[0] as Record<string, unknown>;
    const lastUsed = badgeRow.last_used == null ? null : toIso(badgeRow.last_used);
    if (lastUsed && operation.source_status !== "failed" && operation.status !== "complete") {
      const updated = await this.deps.db.query(
        `UPDATE setup_operations SET status = 'complete', updated_at = $2
          WHERE id = $1 RETURNING *`,
        [operation.id, new Date().toISOString()],
      );
      operation = updated.rows[0] as SetupOperationRow;
    }
    const tenant: Tenant = {
      id: String(tenantRow.id),
      name: String(tenantRow.name),
      status: tenantRow.status as Tenant["status"],
      monthlyBudgetUsd: tenantRow.monthly_budget_usd == null ? null : Number(tenantRow.monthly_budget_usd),
      rateLimitPerMin: tenantRow.rate_limit_per_min == null ? null : Number(tenantRow.rate_limit_per_min),
      onboardingCompletedAt:
        (tenantRow as { onboarding_completed_at?: Date | string | null }).onboarding_completed_at == null
          ? null
          : toIso((tenantRow as { onboarding_completed_at?: Date | string }).onboarding_completed_at!),
      createdAt: toIso(tenantRow.created_at),
    };
    const teamNamespace = String(teamRow.namespace);
    const team: Team = {
      id: teamNamespace.split("/")[1] ?? "",
      tenantId: operation.tenant_id,
      namespace: teamNamespace,
      name: String(teamRow.name),
      createdAt: toIso(teamRow.created_at),
    };
    const driver = this.deps.registry.capabilities().find((item) => item.name === operation.retriever);
    if (!driver) throw new Error(`configured retriever '${operation.retriever}' is no longer mounted`);
    const plaintext = decryptBadge(operation, this.deps.signingKey);
    const mcpUrl = new URL("/mcp", operation.public_url).toString();
    const mcpSnippet = JSON.stringify({
      mcpServers: {
        halomem: {
          url: mcpUrl,
          headers: { Authorization: `Bearer ${plaintext}` },
          note: `HaloMem organizational memory for namespace '${operation.team_namespace}'`,
        },
      },
    }, null, 2);
    const sourceRow = sourceRes.rows[0] as Record<string, unknown> | undefined;
    return {
      operationId: operation.id,
      idempotencyKey: operation.idempotency_key,
      status: operation.status,
      tenant,
      team,
      retriever: driver,
      badge: {
        keyId: String(badgeRow.id),
        namespace: String(badgeRow.namespace),
        actor: String(badgeRow.actor),
        lastUsed,
      },
      source: sourceRow
        ? {
            id: String(sourceRow.id),
            kind: sourceRow.kind as SourceKind,
            namespace: String(sourceRow.namespace),
            status: operation.source_status as "pending" | "synced" | "failed",
            syncResult: parseJson<SyncResult>(operation.source_result),
            error: operation.source_error,
          }
        : null,
      mcpSnippet,
    };
  }
}
