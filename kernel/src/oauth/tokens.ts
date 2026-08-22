/**
 * M9 parity #11b (D29) — client-credentials token issuance + resolution over
 * `oauth_tokens` (migration 038 "mintlify-parity-m9").
 *
 * Tokens are OPAQUE bearer credentials: plaintext `hmt_` + 64 hex chars,
 * hashed with sha256 at rest (E23 — the table has no plaintext column, and no
 * code path here ever logs or audits a token; failure paths record only
 * `error.name`). Short-lived: `expires_at` comes from the client's
 * `token_ttl_seconds` at issue time.
 *
 * Resolution mirrors `AuthService.resolve` (D9): the plaintext resolves
 * SERVER-side to an Identity; the caller asserts nothing. E24: resolve
 * re-checks the issuing client's status (plus the token row's own status), so
 * revoking a client transitively kills its tokens even before the sweep in
 * `clients.ts` lands. E25: token_role maps ONLY to the 'agent' (assistant) or
 * 'auditor' (read-only) kernel roles — never admin/owner (same mapping the
 * product key types use, src/auth/key-types.ts).
 *
 * Brownout: an unavailable token store degrades to deny-with-audit — resolve
 * returns null, issue throws a typed OAuthTokenError — never a crash that
 * takes the kernel down.
 */

import { randomBytes } from "node:crypto";
import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import type { AuditLog } from "../audit/index.js";
import type { Identity, Namespace, Role } from "../types.js";
import {
  digestsEqual,
  sha256Hex,
  type OAuthClientRecord,
  type OAuthClientService,
  type OAuthTokenRole,
} from "./clients.js";
import type { ConsumedAuthorizationCode } from "./codes.js";

const AGENT_ID = "oauth";
const TOKEN_PREFIX = "hmt_";
const REFRESH_PREFIX = "hmrt_";
/** OA6 — refresh lifetime per rotation (a fresh 30 days on every use). */
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * Local (report for promotion to src/types.ts): the Identity an OAuth token
 * resolves to. It IS an Identity (every existing syscall accepts it), plus the
 * server-side tool allowlist that E27 enforces — carried on the resolved
 * identity so callers can never widen it.
 */
export interface OAuthTokenIdentity extends Identity {
  /** ULID of the oauth_tokens row (also encoded in keyId as `oauth:<id>`). */
  tokenId: string;
  /** ULID of the issuing oauth_clients row. */
  clientRef: string;
  /** Public client_id of the issuing client. */
  clientId: string;
  /** The client's product-level role label ('assistant' | 'read-only'). */
  tokenRole: OAuthTokenRole;
  /** Exact server-enforced tool allowlist snapshot. Empty = NO tools (E27). */
  allowedTools: readonly string[];
}

/** E25 — the ONLY roles an OAuth token can carry. Never admin/owner. */
export const OAUTH_ROLE_MAP: Readonly<Record<OAuthTokenRole, Role>> = Object.freeze({
  assistant: "agent",
  "read-only": "auditor",
});

/** RFC 6749 §5.2-shaped failure; `code` is the OAuth error code. */
export class OAuthTokenError extends Error {
  readonly code:
    | "invalid_request"
    | "invalid_client"
    | "invalid_grant"
    | "unauthorized_client"
    | "unsupported_grant_type"
    | "temporarily_unavailable";
  constructor(code: OAuthTokenError["code"], message: string) {
    super(message);
    this.name = "OAuthTokenError";
    this.code = code;
  }
}

export interface IssuedOAuthToken {
  /** Plaintext bearer token — returned exactly once, never stored or logged. */
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  tokenId: string;
  clientId: string;
  namespace: Namespace;
  role: Role;
  expiresAt: string;
}

/** OA6 — the pair an authorization_code / refresh_token grant returns. */
export interface IssuedOAuthTokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  scope: string;
  accessTokenId: string;
  refreshTokenId: string;
}

/** RFC 7662 introspection view; no token material is ever echoed. */
export interface OAuthIntrospection {
  active: boolean;
  clientId?: string;
  tokenRole?: OAuthTokenRole;
  role?: Role;
  actor?: string;
  issuedAt?: string;
  expiresAt?: string;
  allowedTools?: readonly string[];
}

interface OAuthTokenRow {
  id: string;
  namespace: string;
  client_ref: string;
  actor: string;
  token_role: string;
  allowed_tools: unknown;
  status: string;
  issued_at: Date | string;
  expires_at: Date | string;
  last_used: Date | string | null;
  client_id: string;
  client_status: string;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toolList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

const TOKEN_JOIN = `SELECT t.id, t.namespace, t.client_ref, t.actor, t.token_role,
    t.allowed_tools, t.status, t.issued_at, t.expires_at, t.last_used,
    c.client_id AS client_id, c.status AS client_status
  FROM oauth_tokens t JOIN oauth_clients c ON c.id = t.client_ref`;

export class OAuthTokenService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly clients: OAuthClientService,
  ) {}

  private async record(
    op: "share" | "read" | "retract" | "reject",
    result: "ok" | "denied" | "miss" | "error",
    actor: string,
    namespace: Namespace,
    detail: string,
  ): Promise<void> {
    try {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor,
        agentId: AGENT_ID,
        op,
        memoryId: null,
        namespace,
        purpose: null,
        result,
        detail,
      });
    } catch (err) {
      // Brownout: the audit store itself is down. Log ONLY the error name —
      // never token material — and keep degrading rather than crashing.
      console.error("oauth audit append failed:", (err as Error).name);
    }
  }

  /**
   * Client-credentials grant. Verifies the secret (constant-time), requires
   * an APPROVED client, mints an opaque short-lived token, stores ONLY its
   * sha256 (E23), audits ok and every denial (E26/D4).
   */
  async issue(clientIdParam: string, clientSecret: string): Promise<IssuedOAuthToken> {
    let client: OAuthClientRecord | null;
    try {
      client = await this.clients.verifySecret(clientIdParam, clientSecret);
    } catch (err) {
      await this.record("reject", "error", "unknown", "unknown",
        `token issue degraded: store unavailable (${(err as Error).name})`);
      throw new OAuthTokenError("temporarily_unavailable", "token store unavailable");
    }
    if (!client) {
      await this.record("reject", "denied", "unknown", "unknown",
        "token issue denied: unknown client_id or bad client_secret");
      throw new OAuthTokenError("invalid_client", "client authentication failed");
    }
    if (client.status !== "approved") {
      await this.record("reject", "denied", `oauth-client:${client.clientId}`, client.namespace,
        `token issue denied: client ${client.id} is '${client.status}', not approved`);
      throw new OAuthTokenError(
        "unauthorized_client",
        client.status === "pending"
          ? "client is pending admin approval"
          : "client is revoked",
      );
    }

    const plaintext = TOKEN_PREFIX + randomBytes(32).toString("hex");
    const id = ulid();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + client.tokenTtlSeconds * 1000);
    const actor = `oauth-client:${client.clientId}`;
    try {
      await this.db.query(
        `INSERT INTO oauth_tokens
           (id, namespace, client_ref, token_hash, actor, token_role,
            allowed_tools, status, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'active', $8, $9)`,
        [
          id,
          client.namespace,
          client.id,
          sha256Hex(plaintext),
          actor,
          client.tokenRole,
          JSON.stringify(client.allowedTools),
          issuedAt.toISOString(),
          expiresAt.toISOString(),
        ],
      );
    } catch (err) {
      await this.record("reject", "error", actor, client.namespace,
        `token issue degraded: store unavailable (${(err as Error).name})`);
      throw new OAuthTokenError("temporarily_unavailable", "token store unavailable");
    }
    await this.record("share", "ok", actor, client.namespace,
      `oauth token issued: tokenId=${id} clientId=${client.clientId} ` +
        `role=${client.tokenRole} ttl=${client.tokenTtlSeconds}s`);
    return {
      accessToken: plaintext,
      tokenType: "Bearer",
      expiresIn: client.tokenTtlSeconds,
      tokenId: id,
      clientId: client.clientId,
      namespace: client.namespace,
      role: OAUTH_ROLE_MAP[client.tokenRole],
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Resolve a plaintext bearer token to a server-side Identity (D9), or null
   * (transport maps to 401). Checks, in order: row exists → token not revoked
   * → not expired → issuing client still approved (E24 transitive revocation
   * at resolve time). Every miss/denial audits; success updates last_used and
   * is audited by the syscall the identity goes on to perform (same contract
   * as AuthService.resolve).
   */
  async resolve(plaintext: string): Promise<OAuthTokenIdentity | null> {
    if (!plaintext.startsWith(TOKEN_PREFIX)) return null;
    let row: OAuthTokenRow | undefined;
    try {
      const res = await this.db.query(`${TOKEN_JOIN} WHERE t.token_hash = $1`, [
        sha256Hex(plaintext),
      ]);
      row = res.rows[0] as OAuthTokenRow | undefined;
    } catch (err) {
      // Brownout (E-deny-with-audit): store down → deny, never crash.
      await this.record("reject", "error", "unknown", "unknown",
        `token resolve degraded: store unavailable (${(err as Error).name})`);
      return null;
    }
    if (!row) {
      await this.record("reject", "miss", "unknown", "unknown",
        "token resolve denied: unknown token");
      return null;
    }
    if (row.status !== "active") {
      await this.record("reject", "denied", row.actor, row.namespace,
        `token resolve denied: token ${row.id} is revoked`);
      return null;
    }
    if (new Date(toIso(row.expires_at)).getTime() <= Date.now()) {
      await this.record("reject", "denied", row.actor, row.namespace,
        `token resolve denied: token ${row.id} is expired`);
      return null;
    }
    if (row.client_status !== "approved") {
      // Transitive revocation: the client died after this token was minted.
      await this.record("reject", "denied", row.actor, row.namespace,
        `token resolve denied: client ${row.client_ref} is '${row.client_status}' (transitive revoke)`);
      return null;
    }
    const tokenRole = row.token_role as OAuthTokenRole;
    const role = OAUTH_ROLE_MAP[tokenRole];
    if (!role || role === ("admin" as Role) || role === ("owner" as Role)) {
      // E25 belt-and-braces: a corrupted row must never escalate.
      await this.record("reject", "denied", row.actor, row.namespace,
        `token resolve denied: token ${row.id} has unmappable role '${row.token_role}'`);
      return null;
    }
    try {
      await this.db.query(`UPDATE oauth_tokens SET last_used = $1 WHERE id = $2`, [
        new Date().toISOString(),
        row.id,
      ]);
    } catch (err) {
      // last_used is telemetry, not authority — degrade silently but named.
      console.error("oauth last_used update failed:", (err as Error).name);
    }
    return {
      keyId: `oauth:${row.id}`,
      namespace: row.namespace,
      actor: row.actor,
      role,
      credentialExpiresAt: toIso(row.expires_at),
      tokenId: row.id,
      clientRef: row.client_ref,
      clientId: row.client_id,
      tokenRole,
      allowedTools: Object.freeze(toolList(row.allowed_tools)),
    };
  }

  /**
   * Credential-active re-check by token ROW id (the `oauth:<id>` keyId the
   * resolved Identity carries) — the seam the kernel's per-syscall gate uses,
   * mirroring AuthService.isActive for API keys. Re-verifies token status,
   * expiry, AND the issuing client's approval (E24: a transitive revocation
   * bites mid-flight, not just at the next resolve). Store down → false
   * (deny, never crash).
   */
  async isActiveId(tokenId: string): Promise<boolean> {
    try {
      const res = await this.db.query(`${TOKEN_JOIN} WHERE t.id = $1`, [tokenId]);
      const row = res.rows[0] as OAuthTokenRow | undefined;
      if (!row) return false;
      return row.status === "active" &&
        new Date(toIso(row.expires_at)).getTime() > Date.now() &&
        row.client_status === "approved";
    } catch (err) {
      console.error("oauth isActiveId degraded:", (err as Error).name);
      return false;
    }
  }

  /**
   * RFC 7662 introspection, scoped to the AUTHENTICATED client: a client may
   * introspect only tokens minted to itself; anything else is `active: false`
   * (the RFC-mandated non-leaky answer). Audited as a read (E26).
   */
  async introspect(
    plaintext: string,
    authenticatedClient: OAuthClientRecord,
  ): Promise<OAuthIntrospection> {
    const inactive: OAuthIntrospection = { active: false };
    let row: OAuthTokenRow | undefined;
    try {
      const res = await this.db.query(`${TOKEN_JOIN} WHERE t.token_hash = $1`, [
        sha256Hex(plaintext),
      ]);
      row = res.rows[0] as OAuthTokenRow | undefined;
    } catch (err) {
      await this.record("read", "error", `oauth-client:${authenticatedClient.clientId}`,
        authenticatedClient.namespace,
        `introspection degraded: store unavailable (${(err as Error).name})`);
      return inactive;
    }
    const owned = row !== undefined && row.client_ref === authenticatedClient.id;
    const live = owned && row !== undefined && row.status === "active"
      && new Date(toIso(row.expires_at)).getTime() > Date.now()
      && row.client_status === "approved";
    await this.record("read", live ? "ok" : "miss",
      `oauth-client:${authenticatedClient.clientId}`, authenticatedClient.namespace,
      `token introspection: ${live ? `active tokenId=${row!.id}` : "inactive/unknown/foreign token"}`);
    if (!live || row === undefined) return inactive;
    const tokenRole = row.token_role as OAuthTokenRole;
    return {
      active: true,
      clientId: row.client_id,
      tokenRole,
      role: OAUTH_ROLE_MAP[tokenRole],
      actor: row.actor,
      issuedAt: toIso(row.issued_at),
      expiresAt: toIso(row.expires_at),
      allowedTools: toolList(row.allowed_tools),
    };
  }

  /**
   * RFC 7009 revocation, scoped to the AUTHENTICATED client: revoking a token
   * you do not own is a silent no-op (per the RFC, the endpoint still answers
   * 200) but the attempt is audited as denied.
   */
  async revokeByPlaintext(
    plaintext: string,
    authenticatedClient: OAuthClientRecord,
  ): Promise<{ revoked: boolean }> {
    const actor = `oauth-client:${authenticatedClient.clientId}`;
    try {
      const res = await this.db.query(
        `UPDATE oauth_tokens
           SET status = 'revoked', revoked_reason = 'manual', revoked_at = $1
         WHERE token_hash = $2 AND client_ref = $3 AND status = 'active'
         RETURNING id`,
        [new Date().toISOString(), sha256Hex(plaintext), authenticatedClient.id],
      );
      const revoked = res.rows.length > 0;
      if (revoked) {
        await this.record("retract", "ok", actor, authenticatedClient.namespace,
          `oauth token revoked by its client: tokenId=${(res.rows[0] as { id: string }).id}`);
        return { revoked };
      }
      // OA6: RFC 7009 accepts refresh tokens too. Revoking a refresh token
      // kills its whole family plus the access tokens it minted.
      const refresh = await this.db.query(
        `SELECT id, family_id FROM oauth_refresh_tokens
          WHERE token_hash = $1 AND client_ref = $2`,
        [sha256Hex(plaintext), authenticatedClient.id],
      );
      if (refresh.rows.length > 0) {
        const family = (refresh.rows[0] as { family_id: string }).family_id;
        await this.revokeFamily(family, "manual");
        await this.record("retract", "ok", actor, authenticatedClient.namespace,
          `oauth refresh token revoked by its client: family=${family}`);
        return { revoked: true };
      }
      await this.record("retract", "denied", actor, authenticatedClient.namespace,
        "oauth token revocation no-op: token unknown, already revoked, or owned by another client");
      return { revoked: false };
    } catch (err) {
      await this.record("retract", "error", actor, authenticatedClient.namespace,
        `token revocation degraded: store unavailable (${(err as Error).name})`);
      return { revoked: false };
    }
  }

  // -------------------------------------------------------------------------
  // CONTRACTS-OAUTH-CONNECT — authorization_code exchange + refresh rotation
  // -------------------------------------------------------------------------

  /**
   * OA3/OA6 — mint the access+refresh pair for a consumed, fully verified
   * authorization code. The subject snapshot (user, namespace, actor, role,
   * tool allowlist) comes from the CODE row — nothing in the exchange request
   * can widen it. The caller stamps the minted ids back onto the code row
   * (codes.bindTokens) so a replay can revoke them.
   */
  async issueForCode(
    code: ConsumedAuthorizationCode,
    client: OAuthClientRecord,
  ): Promise<IssuedOAuthTokenPair> {
    return this.mintPair({
      client,
      grantKind: "authorization_code",
      userId: code.userId,
      namespace: code.namespace,
      actor: code.actor,
      tokenRole: code.tokenRole,
      allowedTools: code.allowedTools,
      scope: code.scope,
      familyId: ulid(),
    });
  }

  /**
   * OA6 — the refresh_token grant. Every use ROTATES: the presented refresh
   * token becomes `rotated`, the access token it carried is revoked
   * (`superseded`), and a fresh pair is minted in the same family. Presenting
   * a rotated/revoked refresh token is treated as theft: the entire family
   * and its access tokens are revoked (audited) before the deny.
   */
  async refresh(
    plaintext: string,
    client: OAuthClientRecord,
  ): Promise<IssuedOAuthTokenPair> {
    if (!plaintext.startsWith(REFRESH_PREFIX)) {
      throw new OAuthTokenError("invalid_request", "refresh_token is malformed");
    }
    interface RefreshRow {
      id: string;
      namespace: string;
      client_ref: string;
      user_id: string | null;
      actor: string;
      token_role: string;
      allowed_tools: unknown;
      family_id: string;
      access_token_ref: string | null;
      status: string;
      expires_at: Date | string;
      client_status: string;
    }
    let row: RefreshRow | undefined;
    try {
      const res = await this.db.query(
        `SELECT r.id, r.namespace, r.client_ref, r.user_id, r.actor,
                r.token_role, r.allowed_tools, r.family_id, r.access_token_ref,
                r.status, r.expires_at, c.status AS client_status
           FROM oauth_refresh_tokens r
           JOIN oauth_clients c ON c.id = r.client_ref
          WHERE r.token_hash = $1`,
        [sha256Hex(plaintext)],
      );
      row = res.rows[0] as RefreshRow | undefined;
    } catch (err) {
      await this.record("reject", "error", "unknown", "unknown",
        `refresh degraded: store unavailable (${(err as Error).name})`);
      throw new OAuthTokenError("temporarily_unavailable", "token store unavailable");
    }
    if (!row) {
      await this.record("reject", "miss", "unknown", "unknown",
        "refresh denied: unknown refresh token");
      throw new OAuthTokenError("invalid_grant", "refresh token is invalid");
    }
    if (row.client_ref !== client.id) {
      await this.record("reject", "denied", row.actor, row.namespace,
        `refresh denied: token family ${row.family_id} belongs to another client`);
      throw new OAuthTokenError("invalid_grant", "refresh token is invalid");
    }
    if (row.client_status !== "approved") {
      await this.record("reject", "denied", row.actor, row.namespace,
        `refresh denied: client ${row.client_ref} is '${row.client_status}' (transitive revoke)`);
      throw new OAuthTokenError("invalid_grant", "refresh token is invalid");
    }
    if (row.status !== "active") {
      // Theft signal (OA6): a rotated/revoked token came back. Kill the family.
      await this.revokeFamily(row.family_id, "reuse-detected");
      await this.record("retract", "denied", row.actor, row.namespace,
        `refresh REUSE detected: family ${row.family_id} revoked`);
      throw new OAuthTokenError("invalid_grant", "refresh token is invalid");
    }
    if (new Date(row.expires_at instanceof Date ? row.expires_at.toISOString() : row.expires_at).getTime() <= Date.now()) {
      await this.db.query(
        `UPDATE oauth_refresh_tokens
           SET status = 'revoked', revoked_reason = 'manual', revoked_at = $1
         WHERE id = $2`,
        [new Date().toISOString(), row.id],
      );
      await this.record("reject", "denied", row.actor, row.namespace,
        `refresh denied: token ${row.id} expired`);
      throw new OAuthTokenError("invalid_grant", "refresh token is invalid");
    }

    const tokenRole = row.token_role as OAuthTokenRole;
    return this.mintPair({
      client,
      grantKind: "refresh_token",
      userId: row.user_id,
      namespace: row.namespace,
      actor: row.actor,
      tokenRole,
      allowedTools: Array.isArray(row.allowed_tools)
        ? (row.allowed_tools as unknown[]).filter((t): t is string => typeof t === "string")
        : [],
      scope: tokenRole === "assistant" ? "assistant" : "read-only",
      familyId: row.family_id,
      rotateFrom: { refreshId: row.id, accessRef: row.access_token_ref },
    });
  }

  /** OA6 — one transaction mints the pair (and applies the rotation, if any). */
  private async mintPair(input: {
    client: OAuthClientRecord;
    grantKind: "authorization_code" | "refresh_token";
    userId: string | null;
    namespace: Namespace;
    actor: string;
    tokenRole: OAuthTokenRole;
    allowedTools: readonly string[];
    scope: string;
    familyId: string;
    rotateFrom?: { refreshId: string; accessRef: string | null };
  }): Promise<IssuedOAuthTokenPair> {
    const accessPlain = TOKEN_PREFIX + randomBytes(32).toString("hex");
    const refreshPlain = REFRESH_PREFIX + randomBytes(32).toString("hex");
    const accessId = ulid();
    const refreshId = ulid();
    const now = new Date();
    const nowIso = now.toISOString();
    const accessExpires = new Date(now.getTime() + input.client.tokenTtlSeconds * 1000);
    const refreshExpires = new Date(now.getTime() + REFRESH_TOKEN_TTL_SECONDS * 1000);
    const tools = JSON.stringify([...input.allowedTools]);
    try {
      await this.db.transaction(async (tx) => {
        // Inserts FIRST: `rotated_to` references the NEW refresh row, so the
        // rotation stamp must come after it exists (FKs check per-statement).
        await tx.query(
          `INSERT INTO oauth_tokens
             (id, namespace, client_ref, token_hash, actor, token_role,
              allowed_tools, status, issued_at, expires_at, user_id, grant_kind)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'active', $8, $9, $10, $11)`,
          [
            accessId,
            input.namespace,
            input.client.id,
            sha256Hex(accessPlain),
            input.actor,
            input.tokenRole,
            tools,
            nowIso,
            accessExpires.toISOString(),
            input.userId,
            input.grantKind,
          ],
        );
        await tx.query(
          `INSERT INTO oauth_refresh_tokens
             (id, namespace, client_ref, user_id, actor, token_role,
              allowed_tools, token_hash, family_id, access_token_ref, status,
              issued_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, 'active', $11, $12)`,
          [
            refreshId,
            input.namespace,
            input.client.id,
            input.userId,
            input.actor,
            input.tokenRole,
            tools,
            sha256Hex(refreshPlain),
            input.familyId,
            accessId,
            nowIso,
            refreshExpires.toISOString(),
          ],
        );
        if (input.rotateFrom) {
          await tx.query(
            `UPDATE oauth_refresh_tokens
               SET status = 'rotated', rotated_to = $1, last_used = $2
             WHERE id = $3 AND status = 'active'`,
            [refreshId, nowIso, input.rotateFrom.refreshId],
          );
          if (input.rotateFrom.accessRef !== null) {
            await tx.query(
              `UPDATE oauth_tokens
                 SET status = 'revoked', revoked_reason = 'superseded', revoked_at = $1
               WHERE id = $2 AND status = 'active'`,
              [nowIso, input.rotateFrom.accessRef],
            );
          }
        }
      });
    } catch (err) {
      await this.record("reject", "error", input.actor, input.namespace,
        `${input.grantKind} issue degraded: store unavailable (${(err as Error).name})`);
      throw new OAuthTokenError("temporarily_unavailable", "token store unavailable");
    }
    await this.record("share", "ok", input.actor, input.namespace,
      `oauth token pair issued (${input.grantKind}): accessId=${accessId} ` +
        `family=${input.familyId} clientId=${input.client.clientId} role=${input.tokenRole}`);
    return {
      accessToken: accessPlain,
      refreshToken: refreshPlain,
      tokenType: "Bearer",
      expiresIn: input.client.tokenTtlSeconds,
      scope: input.scope,
      accessTokenId: accessId,
      refreshTokenId: refreshId,
    };
  }

  /** OA6 — kill a rotation family and every access token it ever carried. */
  private async revokeFamily(familyId: string, reason: string): Promise<void> {
    const now = new Date().toISOString();
    try {
      await this.db.query(
        `UPDATE oauth_tokens
           SET status = 'revoked', revoked_reason = 'superseded', revoked_at = $1
         WHERE status = 'active' AND id IN (
           SELECT access_token_ref FROM oauth_refresh_tokens
            WHERE family_id = $2 AND access_token_ref IS NOT NULL
         )`,
        [now, familyId],
      );
      await this.db.query(
        `UPDATE oauth_refresh_tokens
           SET status = 'revoked', revoked_reason = $1, revoked_at = $2
         WHERE family_id = $3 AND status IN ('active','rotated')`,
        [reason.slice(0, 100), now, familyId],
      );
    } catch (err) {
      console.error("oauth family revoke degraded:", (err as Error).name);
    }
  }
}
