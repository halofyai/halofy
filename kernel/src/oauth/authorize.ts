/**
 * CONTRACTS-OAUTH-CONNECT OA1/OA3/OA4/OA8 — the authorization endpoint and
 * consent surface:
 *
 *   GET  /oauth/authorize          → login bounce | consent page | error
 *   POST /oauth/authorize/decision → allow (mint code, redirect) | deny
 *
 * Handlers are PURE of the transport: they take parsed params + the
 * cookie-session Identity the HTTP layer resolved (or null) and return a
 * {status, headers, body} page/redirect envelope.
 *
 * Error routing follows RFC 6749 §4.1.2.1 exactly: an unknown client_id or an
 * unregistered redirect_uri renders an error PAGE — the user agent is NEVER
 * redirected to an unvalidated URI. Only after the redirect_uri is proven
 * registered do failures redirect with `error=…&state=…`.
 *
 * The consent page is string-rendered with every dynamic value HTML-escaped,
 * carries no inline JS, and is served with X-Frame-Options: DENY +
 * frame-ancestors 'none' (OA8). CSRF: the decision POST rides the
 * SameSite=Lax session cookie (cross-site POSTs carry no session) AND every
 * hidden field is re-validated against the client row server-side — the form
 * is treated as untrusted input, not as authority.
 */

import { escapeHtml, renderHaloFrame, renderHaloStatusPage } from "../branding/halo-page.js";
import type { AuditLog } from "../audit/index.js";
import type { Identity, Namespace } from "../types.js";
import type { OAuthClientRecord, OAuthClientService, OAuthTokenRole } from "./clients.js";
import type { OAuthCodeService } from "./codes.js";

const AGENT_ID = "oauth";

/**
 * OA4 — the two scopes ARE the two token roles; each maps to a fixed
 * server-side tool list snapshotted at consent time and fenced per-syscall by
 * the E27 chokepoint. `copilot_complete` (the billable HTTP copilot lane) is
 * deliberately absent from both: connectors get the MCP toolset, nothing more.
 */
export const ASSISTANT_SCOPE_TOOLS: readonly string[] = Object.freeze([
  "mem_policy",
  "mem_policy_ack",
  "mem_search",
  "source_list",
  "source_search",
  "mem_read",
  "mem_write",
  "mem_write_status",
  "mem_assemble",
  "mem_manifest",
  "mem_stats",
  "mem_fault",
  "mem_live_result",
  "source_read",
  "request_access",
]);

export const READONLY_SCOPE_TOOLS: readonly string[] = Object.freeze([
  "mem_policy",
  "mem_search",
  "source_list",
  "source_search",
  "mem_read",
  "mem_stats",
  "mem_manifest",
  "source_read",
]);

export const OAUTH_SCOPES: readonly string[] = Object.freeze(["assistant", "read-only"]);

export function toolsForRole(role: OAuthTokenRole): readonly string[] {
  return role === "assistant" ? ASSISTANT_SCOPE_TOOLS : READONLY_SCOPE_TOOLS;
}

/** Transport-ready page/redirect envelope (body is HTML or empty). */
export interface OAuthPageResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface AuthorizeDeps {
  clients: OAuthClientService;
  codes: OAuthCodeService;
  audit: AuditLog;
}

// ---------------------------------------------------------------------------
// Shared rendering
// ---------------------------------------------------------------------------

const PAGE_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  pragma: "no-cache",
  "x-frame-options": "DENY",
  "content-security-policy": "frame-ancestors 'none'",
};

/** Wrap panel markup (already escaped by the caller) in the Halo frame. */
function page(status: number, title: string, inner: string): OAuthPageResponse {
  return {
    status,
    headers: { ...PAGE_HEADERS },
    body: renderHaloFrame(title, inner),
  };
}

function errorPage(message: string): OAuthPageResponse {
  return {
    status: 400,
    headers: { ...PAGE_HEADERS },
    body: renderHaloStatusPage({
      title: "Connection error - Halofy",
      eyebrow: "Connection error",
      heading: "Can’t continue",
      messages: [message, "Close this window and retry from the app you were connecting."],
    }),
  };
}

function redirect(location: string): OAuthPageResponse {
  return {
    status: 302,
    headers: { location, "cache-control": "no-store", pragma: "no-cache" },
    body: "",
  };
}

/** Redirect back to the (already validated) redirect_uri with an RFC error. */
function redirectError(
  redirectUri: string,
  error: string,
  description: string,
  state: string,
  issuer: string,
): OAuthPageResponse {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state !== "") url.searchParams.set("state", state);
  url.searchParams.set("iss", issuer.replace(/\/+$/, ""));
  return redirect(url.toString());
}

// ---------------------------------------------------------------------------
// Parameter validation (shared by GET page and POST decision — OA8 requires
// the POST to re-validate everything; hidden fields are untrusted)
// ---------------------------------------------------------------------------

interface AuthorizeParams {
  client: OAuthClientRecord;
  redirectUri: string;
  scopeRole: OAuthTokenRole;
  scopeString: string;
  state: string;
  codeChallenge: string;
  resource: string;
}

type Validated =
  | { ok: true; params: AuthorizeParams }
  | { ok: false; response: OAuthPageResponse };

function str(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  return typeof value === "string" ? value : "";
}

async function auditDenied(
  audit: AuditLog,
  actor: string,
  namespace: Namespace,
  detail: string,
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
      result: "denied",
      detail,
    });
  } catch (err) {
    console.error("oauth authorize audit append failed:", (err as Error).name);
  }
}

async function validateAuthorizeParams(
  deps: AuthorizeDeps,
  source: Record<string, unknown>,
  issuer: string,
): Promise<Validated> {
  const clientId = str(source, "client_id");
  if (!clientId) {
    await auditDenied(deps.audit, "unknown", "", "authorize denied: missing client_id");
    return { ok: false, response: errorPage("The connecting app sent no client id.") };
  }
  let client: OAuthClientRecord | null;
  try {
    client = await deps.clients.loadByClientId(clientId);
  } catch (err) {
    await auditDenied(deps.audit, "unknown", "",
      `authorize degraded: store unavailable (${(err as Error).name})`);
    return { ok: false, response: errorPage("The service is temporarily unavailable.") };
  }
  if (!client || client.status !== "approved") {
    await auditDenied(deps.audit, "unknown", "",
      `authorize denied: unknown or non-approved client_id`);
    return { ok: false, response: errorPage("This app is not registered with this deployment.") };
  }
  if (!client.grantTypes.includes("authorization_code")) {
    await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
      "authorize denied: client not granted authorization_code");
    return { ok: false, response: errorPage("This app may not request user authorization.") };
  }

  // redirect_uri: exact-string match against the registered list; when the
  // client registered exactly one, it may be omitted (RFC 6749 §3.1.2.3).
  let redirectUri = str(source, "redirect_uri");
  if (redirectUri === "" && client.redirectUris.length === 1) {
    redirectUri = client.redirectUris[0];
  }
  if (redirectUri === "" || !client.redirectUris.includes(redirectUri) || redirectUri.includes("#")) {
    await auditDenied(deps.audit, `oauth-client:${client.clientId}`, client.namespace,
      "authorize denied: redirect_uri missing or not registered");
    return {
      ok: false,
      response: errorPage("The app's return address does not match what it registered."),
    };
  }

  // From here the redirect_uri is proven — failures redirect per the RFC.
  const state = str(source, "state").slice(0, 512);
  if (str(source, "response_type") !== "code") {
    return {
      ok: false,
      response: redirectError(redirectUri, "unsupported_response_type",
        "only response_type=code is supported", state, issuer),
    };
  }
  const codeChallenge = str(source, "code_challenge");
  const method = str(source, "code_challenge_method") || "S256";
  if (!codeChallenge || method !== "S256" || !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)) {
    return {
      ok: false,
      response: redirectError(redirectUri, "invalid_request",
        "PKCE with S256 is required", state, issuer),
    };
  }
  const scopeString = str(source, "scope").trim();
  const scopeTokens = scopeString === "" ? [] : scopeString.split(/\s+/);
  if (scopeTokens.some((token) => !OAUTH_SCOPES.includes(token))) {
    return {
      ok: false,
      response: redirectError(redirectUri, "invalid_scope",
        "supported scopes: assistant, read-only", state, issuer),
    };
  }
  // Default assistant; mixed requests resolve to the wider role (OA4).
  const scopeRole: OAuthTokenRole =
    scopeTokens.length === 0 || scopeTokens.includes("assistant") ? "assistant" : "read-only";

  const resource = str(source, "resource");
  if (resource !== "" && resource !== issuer && resource !== `${issuer}/mcp`) {
    return {
      ok: false,
      response: redirectError(redirectUri, "invalid_target",
        "resource must identify this deployment", state, issuer),
    };
  }

  return {
    ok: true,
    params: { client, redirectUri, scopeRole, scopeString, state, codeChallenge, resource },
  };
}

/** OA3: which humans may consent, and to what. Fail closed on anything odd. */
function effectiveRoleFor(identity: Identity, requested: OAuthTokenRole): OAuthTokenRole | null {
  if (identity.role === "auditor") return "read-only"; // may never grant writes
  if (identity.role === "owner" || identity.role === "admin" || identity.role === "member") {
    return requested;
  }
  return null; // machine/agent identities never consent
}

// ---------------------------------------------------------------------------
// GET /oauth/authorize
// ---------------------------------------------------------------------------

export async function handleAuthorizePage(
  deps: AuthorizeDeps,
  query: Record<string, unknown>,
  rawQuery: string,
  identity: Identity | null,
  issuer: string,
): Promise<OAuthPageResponse> {
  const validated = await validateAuthorizeParams(deps, query, issuer);
  if (!validated.ok) return validated.response;
  const { client, redirectUri, scopeRole, scopeString, state, codeChallenge } = validated.params;

  // Signed out (or a non-console credential): bounce through the console
  // login. `next` is a same-origin path; login.html re-validates it (OA8).
  if (identity === null || identity.sessionUserId === undefined) {
    return redirect("/console/login?next=" + encodeURIComponent("/oauth/authorize?" + rawQuery));
  }
  const effective = effectiveRoleFor(identity, scopeRole);
  if (effective === null) {
    await auditDenied(deps.audit, identity.actor, identity.namespace,
      `authorize denied: role '${identity.role}' may not consent`);
    return redirectError(redirectUri, "access_denied",
      "this account may not authorize connections", state, issuer);
  }

  const tools = toolsForRole(effective);
  const toolItems = tools
    .map((tool) => `<li><code>${escapeHtml(tool)}</code></li>`)
    .join("");
  const roleLabel = effective === "assistant"
    ? "Assistant - read, search, and write through the governed write path"
    : "Read-only - search and read, write nothing";
  const hidden = [
    ["client_id", client.clientId],
    ["redirect_uri", redirectUri],
    ["response_type", "code"],
    ["scope", scopeString],
    ["state", state],
    ["code_challenge", codeChallenge],
    ["code_challenge_method", "S256"],
    ["resource", validated.params.resource],
  ]
    .map(([name, value]) =>
      `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("");

  return page(200, `Connect ${client.name} - Halofy`,
    `<div class="eyebrow">Authorize connection</div>` +
    `<h1>Connect ${escapeHtml(client.name)}</h1>` +
    `<p>${escapeHtml(client.name)} wants access to your team’s memory as <b>${escapeHtml(roleLabel)}</b>.</p>` +
    `<div class="halo-note">Signed in as ${escapeHtml(identity.actor)}` +
    (identity.namespace !== "" ? ` · space <code>${escapeHtml(identity.namespace)}</code>` : "") +
    `</div>` +
    `<ul class="halo-list">${toolItems}</ul>` +
    `<form method="post" action="/oauth/authorize/decision">${hidden}` +
    `<div class="halo-acts">` +
    `<button class="btn btn--outline" name="decision" value="deny">Deny</button>` +
    `<button class="btn btn--solid" name="decision" value="allow">Allow</button>` +
    `</div></form>`);
}

// ---------------------------------------------------------------------------
// POST /oauth/authorize/decision
// ---------------------------------------------------------------------------

export async function handleAuthorizeDecision(
  deps: AuthorizeDeps,
  body: Record<string, unknown>,
  identity: Identity | null,
  issuer: string,
): Promise<OAuthPageResponse> {
  // No session on the POST (expired mid-consent, or a cross-site forgery that
  // carried no Lax cookie): render, never redirect — nothing is trusted yet.
  if (identity === null || identity.sessionUserId === undefined) {
    await auditDenied(deps.audit, "unknown", "", "consent decision denied: no session");
    return errorPage("Your session expired. Retry the connection from the app.");
  }
  // OA8: the hidden fields are untrusted — re-validate everything.
  const validated = await validateAuthorizeParams(deps, body, issuer);
  if (!validated.ok) return validated.response;
  const { client, redirectUri, scopeRole, scopeString, state, codeChallenge } = validated.params;

  if (str(body, "decision") !== "allow") {
    await auditDenied(deps.audit, identity.actor, identity.namespace,
      `consent DENIED by user for client ${client.clientId}`);
    return redirectError(redirectUri, "access_denied", "the user denied the request", state, issuer);
  }

  const effective = effectiveRoleFor(identity, scopeRole);
  if (effective === null) {
    await auditDenied(deps.audit, identity.actor, identity.namespace,
      `consent denied: role '${identity.role}' may not consent`);
    return redirectError(redirectUri, "access_denied",
      "this account may not authorize connections", state, issuer);
  }

  const grantedScope = effective === "assistant" ? "assistant" : "read-only";
  let code: string;
  try {
    code = await deps.codes.mint({
      clientRef: client.id,
      clientId: client.clientId,
      userId: identity.sessionUserId,
      namespace: identity.namespace,
      // OA3: attribution names both the client and the consenting human.
      actor: `oauth:${client.clientId}:${identity.actor}`,
      tokenRole: effective,
      allowedTools: toolsForRole(effective),
      redirectUri,
      codeChallenge,
      scope: grantedScope,
    });
  } catch (err) {
    await auditDenied(deps.audit, identity.actor, identity.namespace,
      `consent degraded: code mint failed (${(err as Error).name})`);
    return redirectError(redirectUri, "temporarily_unavailable",
      "the service could not complete the request", state, issuer);
  }

  try {
    await deps.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: AGENT_ID,
      op: "approve",
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: "ok",
      detail:
        `consent GRANTED: client ${client.clientId} (${client.name.slice(0, 80)}) ` +
        `scope=${grantedScope} by ${identity.actor}`,
    });
  } catch (err) {
    console.error("oauth consent audit append failed:", (err as Error).name);
  }

  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  if (state !== "") url.searchParams.set("state", state);
  url.searchParams.set("iss", issuer.replace(/\/+$/, ""));
  return redirect(url.toString());
}
