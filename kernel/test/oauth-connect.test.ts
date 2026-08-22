/**
 * CONTRACTS-OAUTH-CONNECT (EO1–EO10) — the user-delegated half of the D29 AS:
 * authorization_code + PKCE, dynamic client registration, consent, refresh
 * rotation, replay/theft revocation, and MCP discovery. Hermetic: in-memory
 * PGlite, zero network beyond the local test server.
 *
 * Split-level on purpose: HTTP-level where the wire shape matters (register,
 * metadata, /mcp WWW-Authenticate, token grants), kernel-level for the consent
 * surface (the transport passes a resolved session Identity — tests craft it
 * the same way sessionToIdentity does).
 */

import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { sha256Hex } from "../src/oauth/clients.js";
import {
  ASSISTANT_SCOPE_TOOLS,
  READONLY_SCOPE_TOOLS,
} from "../src/oauth/authorize.js";
import { AuthzError } from "../src/auth/index.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let server: HaloHttpServer | undefined;
let baseUrl = "";
let owner: Identity;

/** A console member the way sessionToIdentity mints one (cookie session). */
const member: Identity = {
  keyId: "sess-member",
  namespace: "acme/marketing",
  actor: "pat@acme.com",
  role: "member",
  sessionUserId: "user-pat",
};

const auditorUser: Identity = {
  keyId: "sess-aud",
  namespace: "acme",
  actor: "aud@acme.com",
  role: "auditor",
  sessionUserId: "user-aud",
};

const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString("base64url");
  return {
    verifier,
    challenge: createHash("sha256").update(verifier, "ascii").digest("base64url"),
  };
}

function authorizeQuery(clientId: string, challenge: string, extra: Record<string, string> = {}) {
  return {
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    scope: "assistant",
    state: "st-123",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...extra,
  };
}

function raw(query: Record<string, string>): string {
  return new URLSearchParams(query).toString();
}

/**
 * Register a public (PKCE-only) client through the kernel handler with a
 * UNIQUE caller address per call — the per-address DCR throttle is real (it
 * 429'd this very suite when every registration shared 127.0.0.1) and gets
 * its own wire-level test at the end of the file.
 */
let dcrCounter = 0;
async function registerPublicClient(name = "ChatGPT"): Promise<string> {
  const res = await kernel.oauthRegister({
    body: {
      client_name: name,
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
    },
    clientAddress: `test-addr-${dcrCounter++}`,
  });
  expect(res.status).toBe(201);
  expect(String(res.body.client_id)).toMatch(/^hmc_/);
  expect(res.body.client_secret).toBeUndefined();
  return res.body.client_id as string;
}

/** Full consent → code for a client, at kernel level (cookie-session shape). */
async function consentCode(
  clientId: string,
  challenge: string,
  identity: Identity = member,
  scope = "assistant",
): Promise<string> {
  const decision = await kernel.oauthAuthorizeDecision(
    { ...authorizeQuery(clientId, challenge, { scope }), decision: "allow" },
    identity,
    baseUrl,
  );
  expect(decision.status).toBe(302);
  const location = new URL(decision.headers.location);
  expect(location.origin + location.pathname).toBe(REDIRECT);
  expect(location.searchParams.get("state")).toBe("st-123");
  expect(location.searchParams.get("iss")).toBe(baseUrl);
  const code = location.searchParams.get("code");
  expect(code).toMatch(/^hmcd_/);
  return code!;
}

async function exchange(
  clientId: string,
  code: string,
  verifier: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
    }),
  });
  return { status: res.status, body: await res.json() };
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  owner = { keyId: "root", namespace: "", actor: "root-owner", role: "owner" };
  server = createHttpServer(buildHttpDeps(kernel));
  const port = await server.start(0);
  baseUrl = `http://127.0.0.1:${port}`;
}, 120_000);

afterAll(async () => {
  await server?.stop();
  await kernel.close();
});

describe("EO1 - discovery is spec-shaped", () => {
  it("AS metadata advertises authorize/register/code/S256/refresh/none", async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.authorization_endpoint).toBe(`${baseUrl}/oauth/authorize`);
    expect(body.registration_endpoint).toBe(`${baseUrl}/oauth/register`);
    expect(body.response_types_supported).toEqual(["code"]);
    expect(body.authorization_response_iss_parameter_supported).toBe(true);
    expect(body.grant_types_supported).toContain("authorization_code");
    expect(body.grant_types_supported).toContain("refresh_token");
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.token_endpoint_auth_methods_supported).toContain("none");
    expect(body.scopes_supported).toEqual(["assistant", "read-only"]);
  });

  it("serves the MCP-surface PRM document and points the /mcp 401 at it", async () => {
    const prm = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(prm.status).toBe(200);
    const prmBody = await prm.json();
    expect(prmBody.resource).toBe(`${baseUrl}/mcp`);
    expect(prmBody.authorization_servers).toEqual([baseUrl]);

    const unauth = await fetch(`${baseUrl}/mcp`, { method: "POST" });
    expect(unauth.status).toBe(401);
    expect(unauth.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it("uses the canonical public origin behind a reverse proxy", async () => {
    const canonical = "https://app.halofy.ai";
    const proxied = createHttpServer(buildHttpDeps(kernel, { publicUrl: canonical }));
    const port = await proxied.start(0);
    const proxyBase = `http://127.0.0.1:${port}`;
    try {
      const metadata = await fetch(
        `${proxyBase}/.well-known/oauth-authorization-server`,
      );
      expect(metadata.status).toBe(200);
      const body = await metadata.json();
      expect(body.issuer).toBe(canonical);
      expect(body.authorization_endpoint).toBe(`${canonical}/oauth/authorize`);

      const unauth = await fetch(`${proxyBase}/mcp`, { method: "POST" });
      expect(unauth.status).toBe(401);
      expect(unauth.headers.get("www-authenticate")).toBe(
        `Bearer resource_metadata="${canonical}/.well-known/oauth-protected-resource/mcp"`,
      );
    } finally {
      await proxied.stop();
    }
  });
});

describe("EO2 - registration boundaries", () => {
  it("registers a public client; client_credentials stays closed to it", async () => {
    const clientId = await registerPublicClient("boundary-bot");
    const denied = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: "hmcs_guessing",
      }),
    });
    // Secretless public client: authentication itself fails before any grant.
    expect([401, 403]).toContain(denied.status);
    const body = await denied.json();
    expect(["invalid_client", "unauthorized_client"]).toContain(body.error);
  });

  it("refuses a confidential client's secretless code exchange (no silent downgrade)", async () => {
    const { record } = await kernel.oauthClients.create(
      { name: "confidential-svc", tokenRole: "assistant", allowedTools: ["mem_search"] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);
    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: record.clientId,
        code: "hmcd_" + "0".repeat(48),
        code_verifier: randomBytes(48).toString("base64url"),
        redirect_uri: REDIRECT,
      }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_client");
  });

  it("validates DCR metadata (bad redirect scheme rejected)", async () => {
    const res = await fetch(`${baseUrl}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "evil",
        redirect_uris: ["http://attacker.example/cb"],
        token_endpoint_auth_method: "none",
      }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_client_metadata");
  });
});

describe("EO3/EO9 - the consent surface", () => {
  it("bounces a signed-out visitor to login with a validated next", async () => {
    const clientId = await registerPublicClient("bounce-bot");
    const { challenge } = pkcePair();
    const query = authorizeQuery(clientId, challenge);
    const page = await kernel.oauthAuthorizePage(query, raw(query), null, baseUrl);
    expect(page.status).toBe(302);
    expect(page.headers.location.startsWith("/console/login?next=%2Foauth%2Fauthorize%3F")).toBe(true);
  });

  it("renders the consent page for a session, hostile client name escaped", async () => {
    const clientId = await registerPublicClient('<script>alert(1)</script>');
    const { challenge } = pkcePair();
    const query = authorizeQuery(clientId, challenge);
    const page = await kernel.oauthAuthorizePage(query, raw(query), member, baseUrl);
    expect(page.status).toBe(200);
    expect(page.headers["x-frame-options"]).toBe("DENY");
    expect(page.body).toContain("&lt;script&gt;");
    expect(page.body).not.toContain("<script>alert");
    // The assistant tool list is shown in full.
    for (const tool of ASSISTANT_SCOPE_TOOLS) expect(page.body).toContain(tool);
  });

  it("unknown client or unregistered redirect_uri → error PAGE, never a redirect", async () => {
    const { challenge } = pkcePair();
    const unknown = await kernel.oauthAuthorizePage(
      authorizeQuery("hmc_does_not_exist", challenge),
      "", member, baseUrl);
    expect(unknown.status).toBe(400);
    expect(unknown.headers["content-type"]).toContain("text/html");

    const clientId = await registerPublicClient("uri-bot");
    const bad = await kernel.oauthAuthorizePage(
      authorizeQuery(clientId, challenge, { redirect_uri: "https://evil.example/cb" }),
      "", member, baseUrl);
    expect(bad.status).toBe(400);
    expect(bad.headers.location).toBeUndefined();
  });

  it("PKCE is mandatory and S256-only (redirect error, state intact)", async () => {
    const clientId = await registerPublicClient("pkce-bot");
    const query = authorizeQuery(clientId, "");
    delete (query as Record<string, unknown>).code_challenge;
    const page = await kernel.oauthAuthorizePage(query, raw(query as never), member, baseUrl);
    expect(page.status).toBe(302);
    const url = new URL(page.headers.location);
    expect(url.searchParams.get("error")).toBe("invalid_request");
    expect(url.searchParams.get("state")).toBe("st-123");
    expect(url.searchParams.get("iss")).toBe(baseUrl);
  });

  it("deny → access_denied redirect with state (EO9)", async () => {
    const clientId = await registerPublicClient("deny-bot");
    const { challenge } = pkcePair();
    const decision = await kernel.oauthAuthorizeDecision(
      { ...authorizeQuery(clientId, challenge), decision: "deny" },
      member,
      baseUrl,
    );
    expect(decision.status).toBe(302);
    const url = new URL(decision.headers.location);
    expect(url.searchParams.get("error")).toBe("access_denied");
    expect(url.searchParams.get("state")).toBe("st-123");
    expect(url.searchParams.get("iss")).toBe(baseUrl);
  });

  it("a decision POST without a session renders, never redirects (CSRF posture)", async () => {
    const clientId = await registerPublicClient("csrf-bot");
    const { challenge } = pkcePair();
    const page = await kernel.oauthAuthorizeDecision(
      { ...authorizeQuery(clientId, challenge), decision: "allow" },
      null,
      baseUrl,
    );
    expect(page.status).toBe(400);
    expect(page.headers.location).toBeUndefined();
  });
});

describe("EO4/EO5 - code exchange, PKCE, replay", () => {
  it("allow → code → tokens; the identity is the consenting user's namespace (EO7)", async () => {
    const clientId = await registerPublicClient("happy-bot");
    const { verifier, challenge } = pkcePair();
    const code = await consentCode(clientId, challenge);

    const ok = await exchange(clientId, code, verifier);
    expect(ok.status).toBe(200);
    const access = String(ok.body.access_token);
    expect(access.startsWith("hmt_")).toBe(true);
    expect(String(ok.body.refresh_token).startsWith("hmrt_")).toBe(true);
    expect(ok.body.scope).toBe("assistant");

    // Only sha256 at rest for both halves (E23 discipline).
    const stored = await kernel.db.query(
      `SELECT grant_kind, user_id FROM oauth_tokens WHERE token_hash = $1`,
      [sha256Hex(access)],
    );
    expect(stored.rows.length).toBe(1);
    expect((stored.rows[0] as { grant_kind: string }).grant_kind).toBe("authorization_code");
    expect((stored.rows[0] as { user_id: string }).user_id).toBe("user-pat");

    const identity = await kernel.resolveOAuthIdentity(access);
    expect(identity).not.toBeNull();
    expect(identity!.role).toBe("agent");
    expect(identity!.namespace).toBe("acme/marketing");
    expect([...identity!.allowedTools]).toEqual([...ASSISTANT_SCOPE_TOOLS]);
  });

  it("wrong verifier and mismatched redirect_uri → invalid_grant", async () => {
    const clientId = await registerPublicClient("sad-bot");
    const first = pkcePair();
    const codeA = await consentCode(clientId, first.challenge);
    const bad = await exchange(clientId, codeA, randomBytes(48).toString("base64url"));
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe("invalid_grant");

    // A failed verification voids the code — the RIGHT verifier is now dead too.
    const retry = await exchange(clientId, codeA, first.verifier);
    expect(retry.status).toBe(400);

    const second = pkcePair();
    const codeB = await consentCode(clientId, second.challenge);
    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code: codeB,
        code_verifier: second.verifier,
        redirect_uri: "https://evil.example/other",
      }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_grant");
  });

  it("replaying a consumed code revokes the tokens it minted (EO5)", async () => {
    const clientId = await registerPublicClient("replay-bot");
    const { verifier, challenge } = pkcePair();
    const code = await consentCode(clientId, challenge);
    const ok = await exchange(clientId, code, verifier);
    expect(ok.status).toBe(200);
    const access = String(ok.body.access_token);
    expect(await kernel.resolveOAuthIdentity(access)).not.toBeNull();

    const replay = await exchange(clientId, code, verifier);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    // The first exchange's tokens are dead.
    expect(await kernel.resolveOAuthIdentity(access)).toBeNull();
    const audit = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM audit_log WHERE detail LIKE '%code REPLAY detected%'`,
    );
    expect(Number((audit.rows[0] as { n: unknown }).n)).toBeGreaterThan(0);
  });
});

describe("EO6 - refresh rotation and theft detection", () => {
  it("rotates on every use; reusing a rotated token kills the family", async () => {
    const clientId = await registerPublicClient("rotate-bot");
    const { verifier, challenge } = pkcePair();
    const code = await consentCode(clientId, challenge);
    const first = await exchange(clientId, code, verifier);
    expect(first.status).toBe(200);
    const access1 = String(first.body.access_token);
    const refresh1 = String(first.body.refresh_token);

    const doRefresh = (token: string) =>
      fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: token,
        }),
      });

    const second = await doRefresh(refresh1);
    expect(second.status).toBe(200);
    const body2 = await second.json();
    const access2 = String(body2.access_token);
    const refresh2 = String(body2.refresh_token);
    expect(refresh2).not.toBe(refresh1);
    // Rotation revoked the superseded access token.
    expect(await kernel.resolveOAuthIdentity(access1)).toBeNull();
    expect(await kernel.resolveOAuthIdentity(access2)).not.toBeNull();

    // Theft: the OLD refresh token comes back → whole family dies.
    const theft = await doRefresh(refresh1);
    expect(theft.status).toBe(400);
    expect((await theft.json()).error).toBe("invalid_grant");
    expect(await kernel.resolveOAuthIdentity(access2)).toBeNull();
    const fresh = await doRefresh(refresh2);
    expect(fresh.status).toBe(400);
  });
});

describe("EO7 - consent authority boundaries", () => {
  it("an auditor's consent downgrades to read-only; ungranted tools are fenced", async () => {
    const clientId = await registerPublicClient("auditor-bot");
    const { verifier, challenge } = pkcePair();
    // Client ASKS for assistant; the auditor may only grant read-only (OA3).
    const code = await consentCode(clientId, challenge, auditorUser, "assistant");
    const ok = await exchange(clientId, code, verifier);
    expect(ok.status).toBe(200);
    expect(ok.body.scope).toBe("read-only");

    const identity = await kernel.resolveOAuthIdentity(String(ok.body.access_token));
    expect(identity).not.toBeNull();
    expect(identity!.role).toBe("auditor");
    expect([...identity!.allowedTools]).toEqual([...READONLY_SCOPE_TOOLS]);
    // mem_assemble is assistant-only — the E27 chokepoint denies it.
    await expect(
      kernel.memAssemble({ taskHint: "anything" }, identity!),
    ).rejects.toThrow(AuthzError);
  });
});

describe("EO8 - transitive client revocation covers the whole surface", () => {
  it("revoking the client kills access tokens, refresh tokens, and pending codes", async () => {
    const clientId = await registerPublicClient("revoke-bot");
    const { verifier, challenge } = pkcePair();
    const code = await consentCode(clientId, challenge);
    const ok = await exchange(clientId, code, verifier);
    expect(ok.status).toBe(200);
    const access = String(ok.body.access_token);
    const refresh = String(ok.body.refresh_token);
    // A second, unconsumed code sits pending.
    const pending = pkcePair();
    await consentCode(clientId, pending.challenge);

    const row = await kernel.db.query(
      `SELECT id FROM oauth_clients WHERE client_id = $1`, [clientId]);
    const { tokensRevoked } = await kernel.oauthClients.revoke(
      (row.rows[0] as { id: string }).id, "cleanup", owner);
    expect(tokensRevoked).toBeGreaterThan(0);

    expect(await kernel.resolveOAuthIdentity(access)).toBeNull();
    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: refresh,
      }),
    });
    // A revoked client fails CLIENT authentication (401 invalid_client) —
    // it never even reaches grant validation.
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_client");
    const codes = await kernel.db.query(
      `SELECT status FROM oauth_authorization_codes
        WHERE client_ref = $1 AND status = 'pending'`,
      [(row.rows[0] as { id: string }).id],
    );
    expect(codes.rows.length).toBe(0);
  });
});

// Kept LAST: the per-address throttle fills the shared 127.0.0.1 bucket, so
// nothing after this could register over the wire from the test host.
describe("OA2 - the open registration endpoint is rate-limited on the wire", () => {
  it("returns the RFC 7591 shape once, then 429s a hammering address", async () => {
    const post = () =>
      fetch(`${baseUrl}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "wire-bot",
          redirect_uris: [REDIRECT],
          token_endpoint_auth_method: "none",
        }),
      });
    const first = await post();
    expect(first.status).toBe(201);
    const body = await first.json();
    expect(String(body.client_id)).toMatch(/^hmc_/);
    expect(body.client_secret).toBeUndefined();
    expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(body.response_types).toEqual(["code"]);
    expect(body.token_endpoint_auth_method).toBe("none");

    let throttled = false;
    for (let i = 0; i < 12 && !throttled; i++) {
      const res = await post();
      if (res.status === 429) {
        expect(res.headers.get("retry-after")).toBeTruthy();
        throttled = true;
      }
    }
    expect(throttled).toBe(true);
  });
});

/**
 * OA1 — the admin-registered connector lane.
 *
 * Regression: an S17-registered client was inserted with the column default
 * `["client_credentials"]` and no redirect URI, so pointing a hand-configured
 * MCP client at it died on the consent page with "This app may not request
 * user authorization" — a registration choice that read as a server fault.
 * An admin registering a client WITH return addresses now gets the consent
 * lane, and the lane invariants are enforced at creation, not at /authorize.
 */
describe("OA1 - an admin-registered client can hold the consent lane", () => {
  it("defaults to client_credentials and is refused at /authorize (the reported failure)", async () => {
    const { record } = await kernel.oauthClients.create(
      { name: "service-only", tokenRole: "assistant" },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);
    expect(record.grantTypes).toEqual(["client_credentials"]);

    const { challenge } = pkcePair();
    const query = authorizeQuery(record.clientId, challenge);
    const page = await kernel.oauthAuthorizePage(query, raw(query), member, baseUrl);
    expect(page.status).toBe(400);
    expect(page.body).toContain("This app may not request user authorization.");
  });

  it("registering with redirect URIs yields authorization_code + refresh_token", async () => {
    const { record } = await kernel.oauthClients.create(
      { name: "hand-wired connector", tokenRole: "assistant", redirectUris: [REDIRECT] },
      owner,
    );
    expect(record.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    const stored = await kernel.oauthClients.loadByClientId(record.clientId);
    expect(stored?.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(stored?.redirectUris).toEqual([REDIRECT]);
  });

  it("runs the whole consent → code → token flow as a confidential client", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "Claude Code (hand-registered)", tokenRole: "assistant", redirectUris: [REDIRECT] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);

    const { verifier, challenge } = pkcePair();
    const query = authorizeQuery(record.clientId, challenge);
    const page = await kernel.oauthAuthorizePage(query, raw(query), member, baseUrl);
    expect(page.status).toBe(200);
    expect(page.body).toContain("Claude Code (hand-registered)");

    const code = await consentCode(record.clientId, challenge);
    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization:
          "Basic " + Buffer.from(`${record.clientId}:${clientSecret}`).toString("base64"),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        redirect_uri: REDIRECT,
      }),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(String(body.access_token)).toMatch(/^hmt_/);
    expect(body.refresh_token).toBeTruthy();

    // The token is the CONSENTING user's, never the registering admin's (OA4).
    const identity = await kernel.resolveOAuthIdentity(String(body.access_token));
    expect(identity).not.toBeNull();
    expect(identity!.actor).toBe(`oauth:${record.clientId}:${member.actor}`);
    expect(identity!.namespace).toBe(member.namespace);
    expect(identity!.role).toBe("agent");
  });

  it("refuses lanes a client structurally cannot complete", async () => {
    await expect(kernel.oauthClients.create(
      { name: "no-return-address", tokenRole: "assistant", grantTypes: ["authorization_code"] },
      owner,
    )).rejects.toThrow(/at least one redirect URI/);

    await expect(kernel.oauthClients.create(
      { name: "refresh-without-code", tokenRole: "assistant", grantTypes: ["refresh_token"] },
      owner,
    )).rejects.toThrow(/refresh_token requires authorization_code/);

    await expect(kernel.oauthClients.create(
      { name: "made-up-grant", tokenRole: "assistant", grantTypes: ["implicit"] },
      owner,
    )).rejects.toThrow(/grantTypes entries must be one of/);
  });
});
