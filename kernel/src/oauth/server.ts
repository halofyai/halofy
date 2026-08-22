/**
 * M9 parity #11b (D29) — the hosted OAuth Authorization Server surface, as
 * PURE handler functions the HTTP integrator mounts:
 *
 *   POST /oauth/token                              → handleTokenRequest
 *   POST /oauth/introspect                         → handleIntrospectionRequest
 *   POST /oauth/revoke                             → handleRevocationRequest
 *   GET  /.well-known/oauth-authorization-server   → authorizationServerMetadata
 *   GET  /.well-known/oauth-protected-resource     → protectedResourceMetadata
 *
 * Handlers take a minimal transport-agnostic request shape and return a
 * {status, headers, body} envelope — no Node http types, no framework, so the
 * existing src/http/server.ts can adapt them with a few lines.
 *
 * E26: every gated call audits, including denied — issuance/introspection/
 * revocation audit inside the services; client authentication failures audit
 * here before the RFC error is returned. E27: `enforceAllowedTools` is the
 * single server-side chokepoint for the client's tool allowlist — the list
 * lives on the resolved OAuthTokenIdentity (snapshotted at issue time),
 * so no request payload can widen it. No token or secret ever appears in a
 * log, an audit row, or an error body; failure paths carry only error names.
 *
 * D2/D1 are untouched: nothing here retrieves or assembles anything — the AS
 * only mints and resolves credentials that feed the existing reference-monitor
 * and syscall layers (coordinated with src/gateway/, which is not modified).
 */

import type { AuditLog } from "../audit/index.js";
import {
  OAuthClientInputError,
  type OAuthClientRecord,
  type OAuthClientService,
} from "./clients.js";
import { OAuthCodeError, type OAuthCodeService } from "./codes.js";
import { OAUTH_SCOPES } from "./authorize.js";
import { trimTrailingRepeatedCharacter } from "../strings.js";
import {
  OAuthTokenError,
  type OAuthTokenIdentity,
  type OAuthTokenService,
} from "./tokens.js";

const AGENT_ID = "oauth";

/** Transport-agnostic request view the HTTP layer adapts to. */
export interface OAuthHttpRequest {
  /** Parsed body params (application/x-www-form-urlencoded or JSON). */
  body: Record<string, unknown>;
  /** The Authorization header value, if any (for client_secret_basic). */
  authorization?: string;
}

export interface OAuthHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

export interface OAuthServerDeps {
  clients: OAuthClientService;
  tokens: OAuthTokenService;
  /** OA5 — the authorization-code store (absent only in legacy wiring). */
  codes?: OAuthCodeService;
  audit: AuditLog;
}

/** RFC 6749 token responses must never be cached. */
const NO_STORE: Record<string, string> = {
  "content-type": "application/json",
  "cache-control": "no-store",
  pragma: "no-cache",
};

function oauthError(
  status: number,
  code: string,
  description: string,
): OAuthHttpResponse {
  const response: OAuthHttpResponse = {
    status,
    headers: { ...NO_STORE },
    body: { error: code, error_description: description },
  };
  if (status === 401) {
    response.headers["www-authenticate"] = 'Basic realm="halomem-oauth"';
  }
  return response;
}

function bodyString(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  return typeof value === "string" ? value : "";
}

/**
 * Client credentials from client_secret_basic (RFC 6749 §2.3.1, form-encoded
 * inside the Basic pair) or client_secret_post body params. Returns null when
 * neither is present/parsable.
 */
export function extractClientCredentials(
  req: OAuthHttpRequest,
): { clientId: string; clientSecret: string } | null {
  const header = req.authorization ?? "";
  if (/^basic\s/i.test(header)) {
    try {
      const decoded = Buffer.from(header.replace(/^basic\s+/i, ""), "base64").toString("utf8");
      const split = decoded.indexOf(":");
      if (split > 0) {
        const clientId = decodeURIComponent(decoded.slice(0, split));
        const clientSecret = decodeURIComponent(decoded.slice(split + 1));
        if (clientId && clientSecret) return { clientId, clientSecret };
      }
    } catch {
      return null;
    }
    return null;
  }
  const clientId = bodyString(req.body, "client_id");
  const clientSecret = bodyString(req.body, "client_secret");
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

/**
 * Authenticate the CALLING client for introspection/revocation. Denials audit
 * here (E26); the service layers audit their own outcomes.
 */
async function authenticateClient(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
  endpoint: string,
): Promise<OAuthClientRecord | OAuthHttpResponse> {
  const credentials = extractClientCredentials(req);
  if (!credentials) {
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} denied: missing client credentials`);
    return oauthError(401, "invalid_client", "client authentication required");
  }
  let client: OAuthClientRecord | null;
  try {
    client = await deps.clients.verifySecret(credentials.clientId, credentials.clientSecret);
  } catch (err) {
    // Brownout: store unavailable → deny with audit, never crash (only the
    // error NAME is recorded — no credential material).
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} degraded: store unavailable (${(err as Error).name})`, "error");
    return oauthError(503, "temporarily_unavailable", "token store unavailable");
  }
  if (!client) {
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} denied: unknown client_id or bad client_secret`);
    return oauthError(401, "invalid_client", "client authentication failed");
  }
  if (client.status !== "approved") {
    await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
      `${endpoint} denied: client is '${client.status}', not approved`);
    return oauthError(401, "unauthorized_client", "client is not approved");
  }
  return client;
}

async function auditDenied(
  audit: AuditLog,
  actor: string,
  namespace: string,
  detail: string,
  result: "denied" | "error" = "denied",
): Promise<void> {
  try {
    await audit.append({
      ts: new Date().toISOString(),
      actor,
      agentId: AGENT_ID,
      op: "reject",
      memoryId: null,
      namespace,
      purpose: null,
      result,
      detail,
    });
  } catch (err) {
    console.error("oauth audit append failed:", (err as Error).name);
  }
}

function tokenErrorResponse(err: unknown): OAuthHttpResponse | null {
  if (err instanceof OAuthTokenError || err instanceof OAuthCodeError) {
    const status =
      err.code === "invalid_client" ? 401
      : (err as OAuthTokenError).code === "unauthorized_client" ? 403
      : err.code === "temporarily_unavailable" ? 503
      : 400;
    return oauthError(status, err.code, err.message);
  }
  return null;
}

/**
 * OA2 — resolve the CALLING client for the code/refresh grants. Confidential
 * clients (auth_method client_secret_basic) MUST secret-authenticate; public
 * clients (auth_method none) identify by client_id alone — their proof is
 * PKCE. A secretless request for a confidential client is invalid_client:
 * downgrade is never silent.
 */
async function resolveTokenClient(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
  endpoint: string,
): Promise<OAuthClientRecord | OAuthHttpResponse> {
  const credentials = extractClientCredentials(req);
  if (credentials) {
    const authed = await authenticateClient(deps, req, endpoint);
    return authed;
  }
  const clientId = bodyString(req.body, "client_id");
  if (!clientId) {
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} denied: missing client identification`);
    return oauthError(401, "invalid_client", "client authentication required");
  }
  let client: OAuthClientRecord | null;
  try {
    client = await deps.clients.loadByClientId(clientId);
  } catch (err) {
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} degraded: store unavailable (${(err as Error).name})`, "error");
    return oauthError(503, "temporarily_unavailable", "token store unavailable");
  }
  if (!client || client.status !== "approved") {
    await auditDenied(deps.audit, "unknown", "unknown",
      `${endpoint} denied: unknown or non-approved client_id`);
    return oauthError(401, "invalid_client", "client authentication failed");
  }
  if (client.authMethod !== "none") {
    await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
      `${endpoint} denied: confidential client sent no secret`);
    return oauthError(401, "invalid_client", "client authentication required");
  }
  return client;
}

/**
 * POST /oauth/token — client_credentials (RFC 6749 §4.4), authorization_code
 * + PKCE (OA1/OA5), and refresh_token with rotation (OA6). Success returns
 * plaintext tokens EXACTLY once with no-store caching headers; every failure
 * maps to the RFC §5.2 error envelope.
 */
export async function handleTokenRequest(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
): Promise<OAuthHttpResponse> {
  const grantType = bodyString(req.body, "grant_type");
  try {
    if (grantType === "client_credentials") {
      const credentials = extractClientCredentials(req);
      if (!credentials) {
        await auditDenied(deps.audit, "unknown", "unknown",
          "token endpoint denied: missing client credentials");
        return oauthError(401, "invalid_client", "client authentication required");
      }
      // OA2: DCR clients never hold this grant — consent is their only lane.
      const registered = await deps.clients.loadByClientId(credentials.clientId);
      if (registered && !registered.grantTypes.includes("client_credentials")) {
        await auditDenied(deps.audit, `oauth-client:${registered.clientId}`, registered.namespace,
          "token endpoint denied: client not granted client_credentials");
        return oauthError(403, "unauthorized_client",
          "this client may only use the authorization_code flow");
      }
      const issued = await deps.tokens.issue(credentials.clientId, credentials.clientSecret);
      return {
        status: 200,
        headers: { ...NO_STORE },
        body: {
          access_token: issued.accessToken,
          token_type: issued.tokenType,
          expires_in: issued.expiresIn,
        },
      };
    }

    if (grantType === "authorization_code") {
      if (!deps.codes) {
        return oauthError(400, "unsupported_grant_type",
          "authorization_code is not enabled on this deployment");
      }
      const client = await resolveTokenClient(deps, req, "token(code)");
      if (!("clientId" in client)) return client;
      if (!client.grantTypes.includes("authorization_code")) {
        await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
          "token endpoint denied: client not granted authorization_code");
        return oauthError(403, "unauthorized_client", "grant not allowed for this client");
      }
      const code = bodyString(req.body, "code");
      const codeVerifier = bodyString(req.body, "code_verifier");
      const redirectUri = bodyString(req.body, "redirect_uri");
      if (!code || !codeVerifier) {
        return oauthError(400, "invalid_request", "'code' and 'code_verifier' are required");
      }
      const consumed = await deps.codes.consume({
        code,
        clientRef: client.id,
        clientId: client.clientId,
        // When the client registered exactly one redirect_uri it may omit the
        // parameter here IF it also omitted it at authorize time — the code
        // row carries the resolved value either way (OA5 exact binding).
        redirectUri: redirectUri !== "" ? redirectUri
          : client.redirectUris.length === 1 ? client.redirectUris[0] : "",
        codeVerifier,
      });
      const pair = await deps.tokens.issueForCode(consumed, client);
      await deps.codes.bindTokens(consumed.id, pair.accessTokenId, pair.refreshTokenId);
      return {
        status: 200,
        headers: { ...NO_STORE },
        body: {
          access_token: pair.accessToken,
          refresh_token: pair.refreshToken,
          token_type: pair.tokenType,
          expires_in: pair.expiresIn,
          scope: pair.scope,
        },
      };
    }

    if (grantType === "refresh_token") {
      const client = await resolveTokenClient(deps, req, "token(refresh)");
      if (!("clientId" in client)) return client;
      if (!client.grantTypes.includes("refresh_token")) {
        await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
          "token endpoint denied: client not granted refresh_token");
        return oauthError(403, "unauthorized_client", "grant not allowed for this client");
      }
      const refreshToken = bodyString(req.body, "refresh_token");
      if (!refreshToken) {
        return oauthError(400, "invalid_request", "'refresh_token' is required");
      }
      const pair = await deps.tokens.refresh(refreshToken, client);
      return {
        status: 200,
        headers: { ...NO_STORE },
        body: {
          access_token: pair.accessToken,
          refresh_token: pair.refreshToken,
          token_type: pair.tokenType,
          expires_in: pair.expiresIn,
          scope: pair.scope,
        },
      };
    }

    await auditDenied(deps.audit, "unknown", "unknown",
      `token endpoint denied: unsupported grant_type '${grantType.slice(0, 40)}'`);
    return oauthError(400, "unsupported_grant_type",
      "supported grants: client_credentials, authorization_code, refresh_token");
  } catch (err) {
    const mapped = tokenErrorResponse(err);
    if (mapped) return mapped;
    // Unknown failure: deny-with-audit brownout; only the error name escapes.
    await auditDenied(deps.audit, "unknown", "unknown",
      `token endpoint degraded: ${(err as Error).name}`, "error");
    return oauthError(503, "temporarily_unavailable", "token issuance unavailable");
  }
}

/**
 * OA2 — POST /oauth/register (RFC 7591). Unauthenticated by design; the
 * kernel wrapper rate-limits per caller address and the client service
 * enforces the hard cap. Response is the RFC's registration payload; the
 * secret (confidential registrations only) appears exactly once.
 */
export async function handleRegistrationRequest(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
): Promise<OAuthHttpResponse> {
  const body = req.body;
  const redirectUris = Array.isArray(body.redirect_uris)
    ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string")
    : [];
  const clientName = typeof body.client_name === "string" && body.client_name.trim() !== ""
    ? body.client_name
    : typeof body.software_id === "string" ? body.software_id : "";
  try {
    const { record, clientSecret } = await deps.clients.registerDynamic({
      clientName,
      redirectUris,
      ...(typeof body.token_endpoint_auth_method === "string"
        ? { tokenEndpointAuthMethod: body.token_endpoint_auth_method }
        : {}),
      ...(typeof body.scope === "string" ? { scope: body.scope } : {}),
    });
    return {
      status: 201,
      headers: { ...NO_STORE },
      body: {
        client_id: record.clientId,
        ...(clientSecret !== null
          ? { client_secret: clientSecret, client_secret_expires_at: 0 }
          : {}),
        client_id_issued_at: Math.floor(Date.parse(record.createdAt) / 1000),
        client_name: record.name,
        redirect_uris: record.redirectUris,
        grant_types: record.grantTypes,
        response_types: ["code"],
        token_endpoint_auth_method:
          record.authMethod === "none" ? "none" : "client_secret_basic",
        scope: OAUTH_SCOPES.join(" "),
      },
    };
  } catch (err) {
    if (err instanceof OAuthClientInputError) {
      return {
        status: 400,
        headers: { ...NO_STORE },
        body: { error: "invalid_client_metadata", error_description: err.message },
      };
    }
    await auditDenied(deps.audit, "unknown", "unknown",
      `registration degraded: ${(err as Error).name}`, "error");
    return {
      status: 503,
      headers: { ...NO_STORE },
      body: { error: "temporarily_unavailable", error_description: "registration unavailable" },
    };
  }
}

/**
 * POST /oauth/introspect (RFC 7662). Requires client authentication; a client
 * sees only its own tokens — anything else is `active: false`.
 */
export async function handleIntrospectionRequest(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
): Promise<OAuthHttpResponse> {
  const client = await authenticateClient(deps, req, "introspection");
  if (!(typeof client === "object" && "clientId" in client)) return client;
  const token = bodyString(req.body, "token");
  if (!token) {
    return oauthError(400, "invalid_request", "'token' parameter is required");
  }
  const view = await deps.tokens.introspect(token, client);
  const body: Record<string, unknown> = { active: view.active };
  if (view.active) {
    body.client_id = view.clientId;
    body.token_type = "Bearer";
    body.sub = view.actor;
    body.iat = view.issuedAt ? Math.floor(Date.parse(view.issuedAt) / 1000) : undefined;
    body.exp = view.expiresAt ? Math.floor(Date.parse(view.expiresAt) / 1000) : undefined;
    body.halomem_role = view.role;
    body.halomem_token_role = view.tokenRole;
    body.halomem_allowed_tools = view.allowedTools;
  }
  return { status: 200, headers: { ...NO_STORE }, body };
}

/**
 * POST /oauth/revoke (RFC 7009). Requires client authentication; always 200
 * on a well-formed request whether or not anything was revoked (the RFC's
 * anti-probing rule) — but the attempt is audited either way.
 */
export async function handleRevocationRequest(
  deps: OAuthServerDeps,
  req: OAuthHttpRequest,
): Promise<OAuthHttpResponse> {
  const client = await authenticateClient(deps, req, "revocation");
  if (!(typeof client === "object" && "clientId" in client)) return client;
  const token = bodyString(req.body, "token");
  if (!token) {
    return oauthError(400, "invalid_request", "'token' parameter is required");
  }
  await deps.tokens.revokeByPlaintext(token, client);
  return { status: 200, headers: { ...NO_STORE }, body: {} };
}

/** GET /.well-known/oauth-authorization-server (RFC 8414). Pure — no store. */
export function authorizationServerMetadata(issuerBaseUrl: string): OAuthHttpResponse {
  const issuer = trimTrailingRepeatedCharacter(issuerBaseUrl, "/");
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      introspection_endpoint: `${issuer}/oauth/introspect`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
      response_types_supported: ["code"],
      authorization_response_iss_parameter_supported: true,
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...OAUTH_SCOPES],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    },
  };
}

/**
 * GET /.well-known/oauth-protected-resource (RFC 9728). Pure — no store.
 * `resourceSuffix` ("/mcp") serves the MCP-surface document (OA7): its
 * `resource` is the exact URL MCP clients connect to, which is what the
 * WWW-Authenticate challenge on a /mcp 401 points at.
 */
export function protectedResourceMetadata(
  issuerBaseUrl: string,
  resourceSuffix = "",
): OAuthHttpResponse {
  const issuer = trimTrailingRepeatedCharacter(issuerBaseUrl, "/");
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: {
      resource: `${issuer}${resourceSuffix}`,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
      scopes_supported: [...OAUTH_SCOPES],
      resource_documentation: `${issuer}/console/login`,
      // Display metadata: `resource_name` is RFC 9728; `logo_uri` is an
      // extension some connector UIs read instead of probing the favicon.
      // Both exist so a client cards this server as Halo, not as its host.
      resource_name: "Halo Memory",
      logo_uri: `${issuer}/icon.png`,
    },
  };
}

/** OA7 — the WWW-Authenticate value a 401 on /mcp carries (RFC 9728 §5.1). */
export function mcpChallengeHeader(issuerBaseUrl: string): string {
  const issuer = trimTrailingRepeatedCharacter(issuerBaseUrl, "/");
  return `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource/mcp"`;
}

/**
 * Resolve an incoming `Authorization: Bearer hmt_…` header to a server-side
 * OAuthTokenIdentity, exactly the seam AuthService.resolve fills for API keys
 * (D9). Returns null (→ 401) on anything else; the token service audits every
 * miss/denial internally.
 */
export async function resolveBearer(
  deps: OAuthServerDeps,
  authorization: string | undefined,
): Promise<OAuthTokenIdentity | null> {
  if (!authorization || !/^bearer\s/i.test(authorization)) return null;
  const token = authorization.replace(/^bearer\s+/i, "").trim();
  if (!token.startsWith("hmt_")) return null;
  return deps.tokens.resolve(token);
}

/**
 * E27 — the single server-side chokepoint for a client's tool allowlist.
 * The list rides on the RESOLVED identity (snapshotted from the client at
 * issue time), so no request payload can widen it. Empty list = NO tools.
 * Denials audit (D4); the caller maps `false` to its own 403.
 */
export async function enforceAllowedTools(
  audit: AuditLog,
  identity: OAuthTokenIdentity,
  tool: string,
): Promise<boolean> {
  const allowed = identity.allowedTools.includes(tool);
  if (!allowed) {
    await auditDenied(audit, identity.actor, identity.namespace,
      `tool '${tool.slice(0, 100)}' denied for oauth client ${identity.clientId}: ` +
        `not in allowedTools (${identity.allowedTools.length} granted)`);
  }
  return allowed;
}
