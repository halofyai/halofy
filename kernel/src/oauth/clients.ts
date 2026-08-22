/**
 * M9 parity #11b (D29) — OAuth client registration over `oauth_clients`
 * (migration 038 "mintlify-parity-m9").
 *
 * A client is created PENDING and must be approved by an owner/admin before
 * the token endpoint will mint anything for it. The client secret is generated
 * server-side; ONLY its sha256 hex is stored, and the plaintext is returned
 * exactly once at creation (same discipline as `src/auth/index.ts` API keys).
 *
 * D9: the client's namespace is the CALLER's resolved namespace — never a
 * request-body value. D4: create / approve / revoke / list-denial each append
 * an audit row (there is no oauth-specific AuditOp, so the same verbs the key
 * lifecycle uses apply: 'share' = credential handed out, 'approve' = admin
 * approval, 'retract' = revocation, 'reject' = denied).
 *
 * E23: only sha256(secret) at rest. E24: revoking a client transitively
 * revokes every token minted for it (same transaction). E25: `token_role` is
 * CHECK-constrained to 'assistant' | 'read-only' — an admin/owner-role client
 * cannot exist.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import type { AuditLog } from "../audit/index.js";
import type { Identity, Namespace } from "../types.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";

/** Local (report for promotion to src/types.ts): the two grantable token roles. */
export type OAuthTokenRole = "assistant" | "read-only";

export const OAUTH_TOKEN_ROLES: readonly OAuthTokenRole[] = ["assistant", "read-only"];

export function isOAuthTokenRole(value: string): value is OAuthTokenRole {
  return (OAUTH_TOKEN_ROLES as readonly string[]).includes(value);
}

export type OAuthClientStatus = "pending" | "approved" | "revoked";

/** OA2: how the client authenticates at the token endpoint. `none` = public
 *  (PKCE-only) client — its `client_secret_hash` is NULL by construction. */
export type OAuthClientAuthMethod = "client_secret_basic" | "none";

/** OA2: who created the client — an admin in S17, or RFC 7591 self-registration. */
export type OAuthClientOrigin = "admin" | "dcr";

/** Local (report for promotion): one row of `oauth_clients`, secret hash omitted. */
export interface OAuthClientRecord {
  id: string;
  namespace: Namespace;
  clientId: string;
  name: string;
  description: string;
  redirectUris: string[];
  /** Exact server-enforced tool allowlist (E27). Empty = NO tools allowed. */
  allowedTools: string[];
  tokenRole: OAuthTokenRole;
  tokenTtlSeconds: number;
  status: OAuthClientStatus;
  authMethod: OAuthClientAuthMethod;
  /** Grants this client may use at the token endpoint (OA1/OA2). */
  grantTypes: string[];
  origin: OAuthClientOrigin;
  requestedBy: string;
  approvedBy: string | null;
  approvedAt: string | null;
  revokedBy: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Console-facing record with token rollups (S17). */
export interface OAuthClientWithStats extends OAuthClientRecord {
  tokenCount: number;
  activeTokenCount: number;
  lastTokenUsed: string | null;
}

export interface CreateOAuthClientInput {
  name: string;
  description?: string;
  redirectUris?: string[];
  allowedTools?: string[];
  tokenRole: OAuthTokenRole;
  tokenTtlSeconds?: number;
  /**
   * OA1 — which lane this client may use at the token endpoint. Omitted, it is
   * DERIVED from `redirectUris`: a client that registered a return address is a
   * user-delegated connector (`authorization_code` + `refresh_token`), one that
   * did not is a service client (`client_credentials`). Admin-registered
   * connectors exist so an operator can hand a fixed client_id/secret to a
   * client that cannot self-register (RFC 7591 DCR remains the default path).
   */
  grantTypes?: string[];
}

/** 400-mapped input failure (server.ts maps by error name). */
export class OAuthClientInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthClientInputError";
  }
}

const AGENT_ID = "oauth";
const MAX_ALLOWED_TOOLS = 64;
const MAX_REDIRECT_URIS = 16;
const MIN_TTL = 60;
const MAX_TTL = 86_400;
const DEFAULT_TTL = 3_600;
/** OA2: hard cap on self-registered clients — an open endpoint is not an
 *  unbounded INSERT lane. Raise deliberately, never implicitly. */
const MAX_DCR_CLIENTS = 500;
/** OA2: DCR clients never get client_credentials — consent is their only lane. */
const DCR_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
/** OA1: the whole grant vocabulary this AS speaks (metadata advertises these). */
const GRANT_TYPES = ["client_credentials", "authorization_code", "refresh_token"] as const;

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Constant-time comparison of two sha256 hex digests. */
export function digestsEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

interface OAuthClientRow {
  id: string;
  namespace: string;
  client_id: string;
  client_secret_hash?: string | null;
  name: string;
  description: string;
  redirect_uris: unknown;
  allowed_tools: unknown;
  token_role: string;
  token_ttl_seconds: number | string;
  status: string;
  auth_method: string;
  grant_types: unknown;
  origin: string;
  requested_by: string;
  approved_by: string | null;
  approved_at: Date | string | null;
  revoked_by: string | null;
  revoked_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toIsoOrNull(value: Date | string | null): string | null {
  return value === null || value === undefined ? null : toIso(value);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

export function rowToClientRecord(r: unknown): OAuthClientRecord {
  const row = r as OAuthClientRow;
  return {
    id: row.id,
    namespace: row.namespace,
    clientId: row.client_id,
    name: row.name,
    description: row.description ?? "",
    redirectUris: stringArray(row.redirect_uris),
    allowedTools: stringArray(row.allowed_tools),
    tokenRole: row.token_role as OAuthTokenRole,
    tokenTtlSeconds: Number(row.token_ttl_seconds),
    status: row.status as OAuthClientStatus,
    authMethod: (row.auth_method as OAuthClientAuthMethod) ?? "client_secret_basic",
    grantTypes: stringArray(row.grant_types).length
      ? stringArray(row.grant_types)
      : ["client_credentials"],
    origin: (row.origin as OAuthClientOrigin) ?? "admin",
    requestedBy: row.requested_by,
    approvedBy: row.approved_by ?? null,
    approvedAt: toIsoOrNull(row.approved_at),
    revokedBy: row.revoked_by ?? null,
    revokedAt: toIsoOrNull(row.revoked_at),
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

const CLIENT_COLUMNS = `id, namespace, client_id, name, description, redirect_uris,
  allowed_tools, token_role, token_ttl_seconds, status, auth_method, grant_types,
  origin, requested_by, approved_by, approved_at, revoked_by, revoked_at,
  created_at, updated_at`;

function validateInput(input: CreateOAuthClientInput): {
  name: string;
  description: string;
  redirectUris: string[];
  allowedTools: string[];
  tokenRole: OAuthTokenRole;
  tokenTtlSeconds: number;
  grantTypes: string[];
} {
  const name = String(input.name ?? "").trim();
  if (!name || name.length > 200) {
    throw new OAuthClientInputError("client 'name' is required (1..200 chars)");
  }
  if (!isOAuthTokenRole(input.tokenRole)) {
    throw new OAuthClientInputError(
      "tokenRole must be 'assistant' or 'read-only' - admin/owner clients cannot exist (E25)",
    );
  }
  const ttl = input.tokenTtlSeconds ?? DEFAULT_TTL;
  if (!Number.isInteger(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) {
    throw new OAuthClientInputError(`tokenTtlSeconds must be an integer in [${MIN_TTL}, ${MAX_TTL}]`);
  }
  const allowedTools = [...new Set(stringArray(input.allowedTools).map((t) => t.trim()).filter(Boolean))];
  if (allowedTools.length > MAX_ALLOWED_TOOLS) {
    throw new OAuthClientInputError(`allowedTools is capped at ${MAX_ALLOWED_TOOLS} entries`);
  }
  const redirectUris = stringArray(input.redirectUris).map((u) => u.trim()).filter(Boolean);
  if (redirectUris.length > MAX_REDIRECT_URIS) {
    throw new OAuthClientInputError(`redirectUris is capped at ${MAX_REDIRECT_URIS} entries`);
  }
  for (const uri of redirectUris) {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new OAuthClientInputError(`redirect URI '${uri}' is not a valid absolute URL`);
    }
    const isLoopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    if (parsed.protocol !== "https:" && !isLoopback) {
      throw new OAuthClientInputError("redirect URIs must be https:// (or loopback for dev)");
    }
  }
  // OA1 — grant lane. Derived from the presence of a return address unless the
  // caller states it; either way the invariants below hold, so a client can
  // never be handed a lane it structurally cannot complete.
  const requested = [...new Set(stringArray(input.grantTypes).map((g) => g.trim()).filter(Boolean))];
  const grantTypes = requested.length
    ? requested
    : redirectUris.length
      ? [...DCR_GRANT_TYPES]
      : ["client_credentials"];
  for (const grant of grantTypes) {
    if (!(GRANT_TYPES as readonly string[]).includes(grant)) {
      throw new OAuthClientInputError(
        `grantTypes entries must be one of ${GRANT_TYPES.join(", ")}`,
      );
    }
  }
  if (grantTypes.includes("authorization_code") && redirectUris.length === 0) {
    throw new OAuthClientInputError(
      "a client granted authorization_code must register at least one redirect URI",
    );
  }
  if (grantTypes.includes("refresh_token") && !grantTypes.includes("authorization_code")) {
    // Refresh tokens are only ever minted by the consent lane (OA6); a
    // client_credentials client re-authenticates instead of refreshing.
    throw new OAuthClientInputError(
      "refresh_token requires authorization_code - client_credentials clients re-authenticate instead",
    );
  }
  const description = String(input.description ?? "").trim().slice(0, 2_000);
  return {
    name, description, redirectUris, allowedTools,
    tokenRole: input.tokenRole, tokenTtlSeconds: ttl, grantTypes,
  };
}

export class OAuthClientService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
  ) {}

  private async record(
    op: "share" | "approve" | "retract" | "reject",
    result: "ok" | "denied" | "error",
    caller: Identity | null,
    namespace: Namespace,
    detail: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: caller?.actor ?? "unknown",
      agentId: AGENT_ID,
      op,
      memoryId: null,
      namespace,
      purpose: null,
      result,
      detail,
    });
  }

  /** Owner/admin acting inside their own subtree (root owner is global). */
  private async assertMayAdminister(
    caller: Identity,
    namespace: Namespace,
    what: string,
  ): Promise<void> {
    const roleOk = caller.role === "owner" || caller.role === "admin";
    const inScope = isRootOwner(caller) || isSelfOrDescendant(namespace, caller.namespace);
    if (!roleOk || !inScope) {
      await this.record(
        "reject",
        "denied",
        caller,
        caller.namespace,
        `oauth client ${what} denied: role '${caller.role}' out of scope for '${namespace}'`,
      );
      throw new AuthzError(`oauth client ${what} requires an owner or admin identity in scope`);
    }
  }

  /**
   * Register a new client in the CALLER's namespace (D9), status 'pending'.
   * Returns the record plus the plaintext secret — shown exactly once; only
   * its sha256 is stored (E23).
   */
  async create(
    input: CreateOAuthClientInput,
    caller: Identity,
  ): Promise<{ record: OAuthClientRecord; clientSecret: string }> {
    await this.assertMayAdminister(caller, caller.namespace, "create");
    const valid = validateInput(input);

    const id = ulid();
    const clientId = "hmc_" + randomBytes(12).toString("hex");
    const clientSecret = "hmcs_" + randomBytes(32).toString("hex");
    const now = new Date().toISOString();
    await this.db.query(
      `INSERT INTO oauth_clients
         (id, namespace, client_id, client_secret_hash, name, description,
          redirect_uris, allowed_tools, token_role, token_ttl_seconds,
          status, grant_types, requested_by, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10,
               'pending', $11::jsonb, $12, $13, $13)`,
      [
        id,
        caller.namespace,
        clientId,
        sha256Hex(clientSecret),
        valid.name,
        valid.description,
        JSON.stringify(valid.redirectUris),
        JSON.stringify(valid.allowedTools),
        valid.tokenRole,
        valid.tokenTtlSeconds,
        JSON.stringify(valid.grantTypes),
        caller.actor,
        now,
      ],
    );
    await this.record(
      "share",
      "ok",
      caller,
      caller.namespace,
      `oauth client created (pending approval): id=${id} clientId=${clientId} ` +
        `name=${valid.name} tokenRole=${valid.tokenRole} tools=${valid.allowedTools.length} ` +
        `grants=${valid.grantTypes.join("+")} redirectUris=${valid.redirectUris.length}`,
    );
    const record: OAuthClientRecord = {
      id,
      namespace: caller.namespace,
      clientId,
      name: valid.name,
      description: valid.description,
      redirectUris: valid.redirectUris,
      allowedTools: valid.allowedTools,
      tokenRole: valid.tokenRole,
      tokenTtlSeconds: valid.tokenTtlSeconds,
      status: "pending",
      authMethod: "client_secret_basic",
      grantTypes: valid.grantTypes,
      origin: "admin",
      requestedBy: caller.actor,
      approvedBy: null,
      approvedAt: null,
      revokedBy: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    return { record, clientSecret };
  }

  /**
   * OA2 — RFC 7591 dynamic client registration. UNAUTHENTICATED by design
   * (MCP clients self-register); the kernel wrapper rate-limits per caller
   * address and this method enforces the hard total cap. The client is
   * created `approved` but POWERLESS on its own: grant_types never includes
   * client_credentials, so every token it obtains flows through a human's
   * consent screen (OA3). `token_endpoint_auth_method`:
   *  - "none"  → public client, client_secret_hash NULL, PKCE-only;
   *  - "client_secret_basic" → secret generated server-side, sha256 at rest,
   *    plaintext returned exactly once (E23).
   */
  async registerDynamic(input: {
    clientName: string;
    redirectUris: string[];
    tokenEndpointAuthMethod?: string;
    scope?: string;
  }): Promise<{ record: OAuthClientRecord; clientSecret: string | null }> {
    const name = String(input.clientName ?? "").trim();
    if (!name || name.length > 200) {
      throw new OAuthClientInputError("client_name is required (1..200 chars)");
    }
    const redirectUris = stringArray(input.redirectUris).map((u) => u.trim()).filter(Boolean);
    if (redirectUris.length === 0 || redirectUris.length > MAX_REDIRECT_URIS) {
      throw new OAuthClientInputError(
        `redirect_uris is required (1..${MAX_REDIRECT_URIS} entries)`,
      );
    }
    for (const uri of redirectUris) {
      let parsed: URL;
      try {
        parsed = new URL(uri);
      } catch {
        throw new OAuthClientInputError(`redirect URI '${uri.slice(0, 200)}' is not a valid absolute URL`);
      }
      const isLoopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      if (parsed.protocol !== "https:" && !isLoopback) {
        throw new OAuthClientInputError("redirect URIs must be https:// (or loopback for dev)");
      }
    }
    const method = input.tokenEndpointAuthMethod ?? "none";
    if (method !== "none" && method !== "client_secret_basic" && method !== "client_secret_post") {
      throw new OAuthClientInputError(
        "token_endpoint_auth_method must be 'none', 'client_secret_basic', or 'client_secret_post'",
      );
    }
    // client_secret_post authenticates with the same stored secret as basic —
    // one storage shape covers both; only "none" is secretless.
    const authMethod: OAuthClientAuthMethod = method === "none" ? "none" : "client_secret_basic";
    // OA4: the scope hint may narrow the DEFAULT role to read-only; consent
    // re-derives the effective role, so this is a label, not authority.
    const tokenRole: OAuthTokenRole =
      String(input.scope ?? "").split(/\s+/).includes("read-only") ? "read-only" : "assistant";

    // Hard total cap — an open endpoint must not be an unbounded INSERT lane.
    const count = await this.db.query(
      `SELECT COUNT(*) AS n FROM oauth_clients WHERE origin = 'dcr'`,
    );
    if (Number((count.rows[0] as { n: unknown }).n) >= MAX_DCR_CLIENTS) {
      await this.record("reject", "denied", null, "",
        `dcr registration denied: cap of ${MAX_DCR_CLIENTS} self-registered clients reached`);
      throw new OAuthClientInputError("registration is temporarily closed");
    }

    const id = ulid();
    const clientId = "hmc_" + randomBytes(12).toString("hex");
    const clientSecret = authMethod === "none" ? null : "hmcs_" + randomBytes(32).toString("hex");
    const now = new Date().toISOString();
    await this.db.query(
      `INSERT INTO oauth_clients
         (id, namespace, client_id, client_secret_hash, name, description,
          redirect_uris, allowed_tools, token_role, token_ttl_seconds,
          status, auth_method, grant_types, origin, requested_by,
          approved_by, approved_at, created_at, updated_at)
       VALUES ($1, '', $2, $3, $4, '', $5::jsonb, '[]'::jsonb, $6, $7,
               'approved', $8, $9::jsonb, 'dcr', 'dcr',
               'dcr', $10, $10, $10)`,
      [
        id,
        clientId,
        clientSecret === null ? null : sha256Hex(clientSecret),
        name,
        JSON.stringify(redirectUris),
        tokenRole,
        DEFAULT_TTL,
        authMethod,
        JSON.stringify(DCR_GRANT_TYPES),
        now,
      ],
    );
    await this.record("share", "ok", null, "",
      `oauth client self-registered (dcr): id=${id} clientId=${clientId} ` +
        `name=${name.slice(0, 80)} authMethod=${authMethod} redirectUris=${redirectUris.length}`);
    const record: OAuthClientRecord = {
      id,
      namespace: "",
      clientId,
      name,
      description: "",
      redirectUris,
      allowedTools: [],
      tokenRole,
      tokenTtlSeconds: DEFAULT_TTL,
      status: "approved",
      authMethod,
      grantTypes: [...DCR_GRANT_TYPES],
      origin: "dcr",
      requestedBy: "dcr",
      approvedBy: "dcr",
      approvedAt: now,
      revokedBy: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    return { record, clientSecret };
  }

  /**
   * Public lookup by client_id for the authorize/token flows — a PUBLIC
   * client authenticates by PKCE, not by secret, so the flows need the row
   * without any credential check. Never exposes the secret hash.
   */
  async loadByClientId(clientId: string): Promise<OAuthClientRecord | null> {
    const res = await this.db.query(
      `SELECT ${CLIENT_COLUMNS} FROM oauth_clients WHERE client_id = $1`,
      [clientId],
    );
    return res.rows.length ? rowToClientRecord(res.rows[0]) : null;
  }

  /** The row, or null. Never exposes client_secret_hash to callers of the service API. */
  private async load(id: string): Promise<OAuthClientRecord | null> {
    const res = await this.db.query(
      `SELECT ${CLIENT_COLUMNS} FROM oauth_clients WHERE id = $1`,
      [id],
    );
    return res.rows.length ? rowToClientRecord(res.rows[0]) : null;
  }

  /** A pending client becomes approved; only then can it obtain tokens. */
  async approve(id: string, caller: Identity): Promise<OAuthClientRecord> {
    const existing = await this.load(id);
    if (!existing) {
      await this.record("reject", "denied", caller, caller.namespace,
        `oauth client approve denied: ${id} not found`);
      throw new AuthzError("oauth client not found");
    }
    await this.assertMayAdminister(caller, existing.namespace, "approve");
    if (existing.status !== "pending") {
      await this.record("reject", "denied", caller, existing.namespace,
        `oauth client approve denied: ${id} is '${existing.status}', not pending`);
      throw new OAuthClientInputError(`client is '${existing.status}' - only a pending client can be approved`);
    }
    const now = new Date().toISOString();
    await this.db.query(
      `UPDATE oauth_clients
         SET status = 'approved', approved_by = $1, approved_at = $2, updated_at = $2
       WHERE id = $3 AND status = 'pending'`,
      [caller.actor, now, id],
    );
    await this.record("approve", "ok", caller, existing.namespace,
      `oauth client approved: id=${id} clientId=${existing.clientId} name=${existing.name}`);
    return { ...existing, status: "approved", approvedBy: caller.actor, approvedAt: now, updatedAt: now };
  }

  /**
   * Revoke a client AND transitively revoke every token minted for it, in one
   * transaction (E24). Idempotent on an already-revoked client (tokens are
   * still swept — belt and braces).
   */
  async revoke(
    id: string,
    reason: string,
    caller: Identity,
  ): Promise<{ record: OAuthClientRecord; tokensRevoked: number }> {
    const existing = await this.load(id);
    if (!existing) {
      await this.record("reject", "denied", caller, caller.namespace,
        `oauth client revoke denied: ${id} not found`);
      throw new AuthzError("oauth client not found");
    }
    await this.assertMayAdminister(caller, existing.namespace, "revoke");
    const now = new Date().toISOString();
    const cleanReason = String(reason ?? "").trim().slice(0, 500);
    let tokensRevoked = 0;
    await this.db.transaction(async (tx) => {
      await tx.query(
        `UPDATE oauth_clients
           SET status = 'revoked', revoked_by = $1, revoked_at = $2, updated_at = $2
         WHERE id = $3 AND status <> 'revoked'`,
        [caller.actor, now, id],
      );
      const swept = await tx.query(
        `UPDATE oauth_tokens
           SET status = 'revoked', revoked_reason = 'client-revoked', revoked_at = $1
         WHERE client_ref = $2 AND status = 'active'
         RETURNING id`,
        [now, id],
      );
      tokensRevoked = swept.rows.length;
      // OA6/EO8 — the E24 transitive sweep covers the whole credential
      // surface: refresh tokens die and pending authorization codes are
      // voided in the SAME transaction as the access tokens.
      const refreshSwept = await tx.query(
        `UPDATE oauth_refresh_tokens
           SET status = 'revoked', revoked_reason = 'client-revoked', revoked_at = $1
         WHERE client_ref = $2 AND status IN ('active','rotated')
         RETURNING id`,
        [now, id],
      );
      const codesVoided = await tx.query(
        `UPDATE oauth_authorization_codes
           SET status = 'void'
         WHERE client_ref = $1 AND status = 'pending'
         RETURNING id`,
        [id],
      );
      await this.audit.appendTo(tx, {
        ts: now,
        actor: caller.actor,
        agentId: AGENT_ID,
        op: "retract",
        memoryId: null,
        namespace: existing.namespace,
        purpose: null,
        result: "ok",
        detail:
          `oauth client revoked: id=${id} clientId=${existing.clientId} ` +
          `tokensRevoked=${tokensRevoked} refreshRevoked=${refreshSwept.rows.length} ` +
          `codesVoided=${codesVoided.rows.length}` +
          (cleanReason ? ` reason=${cleanReason}` : ""),
      });
    });
    return {
      record: {
        ...existing,
        status: "revoked",
        revokedBy: caller.actor,
        revokedAt: now,
        updatedAt: now,
      },
      tokensRevoked,
    };
  }

  /**
   * Clients visible to the caller: root owner sees all; a tenant owner/admin
   * sees their subtree (same escaped-LIKE idiom as AuthService.list — `_`/`%`
   * in a namespace must never act as wildcards); other roles are denied
   * (audited).
   */
  async list(caller: Identity): Promise<OAuthClientRecord[]> {
    const rows = await this.visibleRows(caller);
    return rows.map(rowToClientRecord);
  }

  /** S17 view: each visible client with token count / active count / last use. */
  async listWithStats(caller: Identity): Promise<OAuthClientWithStats[]> {
    const clients = await this.list(caller);
    if (clients.length === 0) return [];
    const placeholders = clients.map((_, i) => `$${i + 1}`).join(", ");
    const stats = await this.db.query(
      `SELECT client_ref,
              COUNT(*) AS total,
              COUNT(*) FILTER (WHERE status = 'active' AND expires_at > NOW()) AS active,
              MAX(last_used) AS last_used
       FROM oauth_tokens WHERE client_ref IN (${placeholders})
       GROUP BY client_ref`,
      clients.map((client) => client.id),
    );
    const byRef = new Map<string, { total: number; active: number; lastUsed: string | null }>();
    for (const raw of stats.rows) {
      const row = raw as { client_ref: string; total: unknown; active: unknown; last_used: Date | string | null };
      byRef.set(row.client_ref, {
        total: Number(row.total),
        active: Number(row.active),
        lastUsed: toIsoOrNull(row.last_used),
      });
    }
    return clients.map((client) => {
      const stat = byRef.get(client.id);
      return {
        ...client,
        tokenCount: stat?.total ?? 0,
        activeTokenCount: stat?.active ?? 0,
        lastTokenUsed: stat?.lastUsed ?? null,
      };
    });
  }

  private async visibleRows(caller: Identity): Promise<unknown[]> {
    if (isRootOwner(caller)) {
      const res = await this.db.query(
        `SELECT ${CLIENT_COLUMNS} FROM oauth_clients ORDER BY created_at`,
      );
      return res.rows;
    }
    if (caller.role === "owner" || caller.role === "admin") {
      const res = await this.db.query(
        `SELECT ${CLIENT_COLUMNS} FROM oauth_clients
         WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
         ORDER BY created_at`,
        [caller.namespace, escapeLikePattern(caller.namespace) + "/%"],
      );
      return res.rows;
    }
    await this.record("reject", "denied", caller, caller.namespace,
      `oauth client list denied: role '${caller.role}' may not list clients`);
    throw new AuthzError(`role '${caller.role}' may not list oauth clients`);
  }

  /**
   * Credential check for the token endpoint: client_id + secret → the full
   * row (including status) or null. Constant-time digest comparison; the
   * caller decides how to audit the outcome. Internal to src/oauth/.
   */
  async verifySecret(
    clientId: string,
    clientSecret: string,
  ): Promise<OAuthClientRecord | null> {
    const res = await this.db.query(
      `SELECT ${CLIENT_COLUMNS}, client_secret_hash FROM oauth_clients WHERE client_id = $1`,
      [clientId],
    );
    const row = res.rows[0] as (OAuthClientRow & { client_secret_hash: string | null }) | undefined;
    // Always burn a hash + comparison so unknown client_id is not a timing
    // oracle. A NULL hash (public client, OA2) can never secret-authenticate —
    // the decoy digest guarantees the comparison fails at constant cost.
    const stored = row?.client_secret_hash ?? sha256Hex("hmcs_missing");
    const ok = digestsEqual(stored, sha256Hex(clientSecret));
    if (!row || row.client_secret_hash === null || !ok) return null;
    return rowToClientRecord(row);
  }
}
