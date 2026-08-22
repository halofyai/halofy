/**
 * CONTRACTS-OAUTH-CONNECT OA5 — the authorization-code store.
 *
 * Codes are `hmcd_` + 48 hex, sha256-hashed at rest (E23 discipline: the table
 * has no plaintext column), 300 s TTL, SINGLE-USE: consumption is a
 * transactional `UPDATE … WHERE status='pending'` so two racing exchanges can
 * never both win. A code binds, at mint time, everything the exchange must
 * re-verify: issuing client, exact redirect_uri, PKCE S256 challenge, and the
 * consenting user's subject snapshot (user id, namespace, actor, token role,
 * tool allowlist — OA3/OA4).
 *
 * Replay (exchanging a code that was already consumed) is treated as theft:
 * the tokens minted from the first exchange are revoked via the backrefs
 * stamped by `bindTokens`, and the attempt audits. Every deny path records
 * only error names/ids — never code, verifier, or token material.
 */

import { createHash, randomBytes } from "node:crypto";
import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import type { AuditLog } from "../audit/index.js";
import type { Namespace } from "../types.js";
import { sha256Hex, type OAuthTokenRole } from "./clients.js";

const AGENT_ID = "oauth";
const CODE_PREFIX = "hmcd_";
/** OA5 — RFC 6749 §4.1.2 recommends ≤10 min; we mint far tighter. */
export const AUTHORIZATION_CODE_TTL_SECONDS = 300;

/** The subject snapshot a consent mints a code for (OA3/OA4). */
export interface AuthorizationCodeGrant {
  clientRef: string;
  clientId: string;
  userId: string;
  namespace: Namespace;
  actor: string;
  tokenRole: OAuthTokenRole;
  allowedTools: readonly string[];
  redirectUri: string;
  codeChallenge: string;
  scope: string;
}

/** A consumed, fully verified code — the exchange mints tokens from this. */
export interface ConsumedAuthorizationCode extends AuthorizationCodeGrant {
  id: string;
}

export class OAuthCodeError extends Error {
  readonly code: "invalid_grant" | "invalid_request" | "temporarily_unavailable";
  constructor(code: OAuthCodeError["code"], message: string) {
    super(message);
    this.name = "OAuthCodeError";
    this.code = code;
  }
}

/** RFC 7636 §4.2 — BASE64URL(SHA256(ascii(verifier))), no padding. */
export function pkceChallengeFor(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/** RFC 7636 §4.1 verifier shape: 43..128 unreserved characters. */
export function isValidCodeVerifier(verifier: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

interface CodeRow {
  id: string;
  client_ref: string;
  user_id: string;
  namespace: string;
  actor: string;
  token_role: string;
  allowed_tools: unknown;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  status: string;
  access_token_ref: string | null;
  refresh_token_ref: string | null;
  expires_at: Date | string;
}

function toolList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

export class OAuthCodeService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
  ) {}

  private async record(
    result: "ok" | "denied" | "miss" | "error",
    actor: string,
    namespace: Namespace,
    detail: string,
    op: "share" | "reject" | "retract" = result === "ok" ? "share" : "reject",
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
      console.error("oauth code audit append failed:", (err as Error).name);
    }
  }

  /** Mint a single-use code for an approved consent. Plaintext returned once. */
  async mint(grant: AuthorizationCodeGrant): Promise<string> {
    const plaintext = CODE_PREFIX + randomBytes(24).toString("hex");
    const id = ulid();
    const now = new Date();
    const expires = new Date(now.getTime() + AUTHORIZATION_CODE_TTL_SECONDS * 1000);
    await this.db.query(
      `INSERT INTO oauth_authorization_codes
         (id, code_hash, client_ref, user_id, namespace, actor, token_role,
          allowed_tools, redirect_uri, code_challenge, scope, status,
          issued_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11,
               'pending', $12, $13)`,
      [
        id,
        sha256Hex(plaintext),
        grant.clientRef,
        grant.userId,
        grant.namespace,
        grant.actor,
        grant.tokenRole,
        JSON.stringify([...grant.allowedTools]),
        grant.redirectUri,
        grant.codeChallenge,
        grant.scope,
        now.toISOString(),
        expires.toISOString(),
      ],
    );
    await this.record("ok", grant.actor, grant.namespace,
      `authorization code minted: codeId=${id} clientId=${grant.clientId} ` +
        `role=${grant.tokenRole} tools=${grant.allowedTools.length}`);
    return plaintext;
  }

  /**
   * Consume + verify in one shot. Order matters:
   *  1. transactional pending→consumed flip (the single-use fence);
   *  2. if the flip found nothing but a CONSUMED row exists → replay: revoke
   *     the minted tokens (OA5) and deny;
   *  3. post-flip checks (expiry, client binding, redirect_uri exact match,
   *     PKCE) mark the row `void` on failure so a half-verified code can
   *     never be retried.
   */
  async consume(input: {
    code: string;
    clientRef: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
  }): Promise<ConsumedAuthorizationCode> {
    if (!input.code.startsWith(CODE_PREFIX)) {
      throw new OAuthCodeError("invalid_grant", "authorization code is invalid");
    }
    const hash = sha256Hex(input.code);
    let row: CodeRow | undefined;
    try {
      const res = await this.db.query(
        `UPDATE oauth_authorization_codes
           SET status = 'consumed', consumed_at = $1
         WHERE code_hash = $2 AND status = 'pending'
         RETURNING id, client_ref, user_id, namespace, actor, token_role,
                   allowed_tools, redirect_uri, code_challenge, scope, status,
                   access_token_ref, refresh_token_ref, expires_at`,
        [new Date().toISOString(), hash],
      );
      row = res.rows[0] as CodeRow | undefined;
    } catch (err) {
      await this.record("error", "unknown", "",
        `code exchange degraded: store unavailable (${(err as Error).name})`);
      throw new OAuthCodeError("temporarily_unavailable", "code store unavailable");
    }

    if (!row) {
      // Not pending. Replay of a consumed code revokes what it minted (OA5).
      const prior = await this.db.query(
        `SELECT id, client_ref, user_id, namespace, actor, token_role,
                allowed_tools, redirect_uri, code_challenge, scope, status,
                access_token_ref, refresh_token_ref, expires_at
           FROM oauth_authorization_codes WHERE code_hash = $1`,
        [hash],
      );
      const seen = prior.rows[0] as CodeRow | undefined;
      if (seen && seen.status === "consumed") {
        await this.revokeMintedTokens(seen);
        await this.record("denied", seen.actor, seen.namespace,
          `code REPLAY detected: codeId=${seen.id} - minted tokens revoked`, "retract");
      } else {
        await this.record("miss", "unknown", "", "code exchange denied: unknown or voided code");
      }
      throw new OAuthCodeError("invalid_grant", "authorization code is invalid");
    }

    const voidAndDeny = async (why: string): Promise<never> => {
      await this.db.query(
        `UPDATE oauth_authorization_codes SET status = 'void' WHERE id = $1`,
        [row!.id],
      );
      await this.record("denied", row!.actor, row!.namespace,
        `code exchange denied: codeId=${row!.id} ${why}`);
      throw new OAuthCodeError("invalid_grant", "authorization code is invalid");
    };

    if (new Date(toIso(row.expires_at)).getTime() <= Date.now()) {
      return voidAndDeny("code expired");
    }
    if (row.client_ref !== input.clientRef) {
      return voidAndDeny("client mismatch");
    }
    if (row.redirect_uri !== input.redirectUri) {
      return voidAndDeny("redirect_uri mismatch");
    }
    if (
      !isValidCodeVerifier(input.codeVerifier) ||
      pkceChallengeFor(input.codeVerifier) !== row.code_challenge
    ) {
      return voidAndDeny("PKCE verification failed");
    }

    return {
      id: row.id,
      clientRef: row.client_ref,
      clientId: input.clientId,
      userId: row.user_id,
      namespace: row.namespace,
      actor: row.actor,
      tokenRole: row.token_role as OAuthTokenRole,
      allowedTools: Object.freeze(toolList(row.allowed_tools)),
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      scope: row.scope,
    };
  }

  /** Stamp the minted token ids so a later replay can revoke them (OA5). */
  async bindTokens(
    codeId: string,
    accessTokenId: string,
    refreshTokenId: string | null,
  ): Promise<void> {
    await this.db.query(
      `UPDATE oauth_authorization_codes
         SET access_token_ref = $1, refresh_token_ref = $2
       WHERE id = $3`,
      [accessTokenId, refreshTokenId, codeId],
    );
  }

  /** Replay response: kill everything the first exchange handed out. */
  private async revokeMintedTokens(row: CodeRow): Promise<void> {
    const now = new Date().toISOString();
    try {
      if (row.access_token_ref !== null) {
        await this.db.query(
          `UPDATE oauth_tokens
             SET status = 'revoked', revoked_reason = 'manual', revoked_at = $1
           WHERE id = $2 AND status = 'active'`,
          [now, row.access_token_ref],
        );
      }
      if (row.refresh_token_ref !== null) {
        // The whole family: replay means the code leaked, so every rotation
        // descended from it is suspect.
        await this.db.query(
          `UPDATE oauth_refresh_tokens
             SET status = 'revoked', revoked_reason = 'code-replay', revoked_at = $1
           WHERE family_id = (
             SELECT family_id FROM oauth_refresh_tokens WHERE id = $2
           ) AND status IN ('active','rotated')`,
          [now, row.refresh_token_ref],
        );
        await this.db.query(
          `UPDATE oauth_tokens
             SET status = 'revoked', revoked_reason = 'manual', revoked_at = $1
           WHERE status = 'active' AND id IN (
             SELECT access_token_ref FROM oauth_refresh_tokens
              WHERE family_id = (
                SELECT family_id FROM oauth_refresh_tokens WHERE id = $2
              ) AND access_token_ref IS NOT NULL
           )`,
          [now, row.refresh_token_ref],
        );
      }
    } catch (err) {
      // Brownout: the deny still stands; only the sweep degraded.
      console.error("oauth replay sweep degraded:", (err as Error).name);
    }
  }
}
