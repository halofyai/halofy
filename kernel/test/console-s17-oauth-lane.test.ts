/**
 * S17 (OA1) — the OAuth-client screen must make the GRANT LANE visible and
 * choosable.
 *
 * Regression: the register form offered no redirect URI and no lane, so every
 * hand-registered client landed on client_credentials. Pointing an MCP client
 * at one died on the consent page ("This app may not request user
 * authorization") with nothing in the console explaining why. These tests pin
 * that the form can register a connector, that the payload carries the lane,
 * and that each card states which lane it is on.
 *
 * Pure Node: the screen is a string renderer; only `actions` touch the DOM, and
 * those get hand-built stubs.
 */

import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

const CONNECTOR = {
  id: "01CONNECTOR",
  clientId: "hmc_connector",
  name: "Claude Code",
  status: "approved",
  origin: "admin",
  namespace: "halofy/tech",
  tokenRole: "assistant",
  tokenTtlSeconds: 3600,
  grantTypes: ["authorization_code", "refresh_token"],
  redirectUris: [REDIRECT],
  allowedTools: [],
  createdAt: "2026-08-01T12:00:00.000Z",
};

const SERVICE = {
  id: "01SERVICE",
  clientId: "hmc_service",
  name: "reporting-service",
  status: "approved",
  origin: "admin",
  namespace: "halofy/tech",
  tokenRole: "read-only",
  tokenTtlSeconds: 3600,
  grantTypes: ["client_credentials"],
  redirectUris: [],
  allowedTools: ["mem_search"],
  createdAt: "2026-08-01T12:00:00.000Z",
};

async function loadS17() {
  return import(fileURLToPath(new URL("../console/screens/s17.js", import.meta.url))) as Promise<{
    render(ctx: unknown): Promise<string>;
    actions: Record<string, (ctx: unknown, el: unknown) => unknown>;
  }>;
}

function ctxFor(clients: unknown[]) {
  return {
    esc,
    identity: { role: "owner" },
    api: { get: async () => clients, post: async () => ({}) },
    go: async () => undefined,
  };
}

describe("S17 surfaces the OAuth grant lane", () => {
  it("offers both lanes and a redirect-URI field on the register form", async () => {
    const s17 = await loadS17();
    const html = await s17.render(ctxFor([]));
    expect(html).toContain('name="oauth-grant-lane"');
    expect(html).toContain('value="authorization_code"');
    expect(html).toContain('value="client_credentials"');
    expect(html).toContain('id="oauth-redirects"');
    expect(html).toContain(REDIRECT);
  });

  /**
   * The default lane is load-bearing, not cosmetic. When the form defaulted to
   * client_credentials, hand-registering Claude/ChatGPT produced a client that
   * failed at /oauth/authorize with "This app may not request user
   * authorization" — a dead end that read as a server fault. The sign-in lane
   * must be the pre-checked one.
   */
  it("pre-checks the sign-in lane, not the backend-service lane", async () => {
    const s17 = await loadS17();
    const html = await s17.render(ctxFor([]));
    const authIdx = html.indexOf('value="authorization_code"');
    const svcIdx = html.indexOf('value="client_credentials"');
    expect(authIdx).toBeGreaterThan(-1);
    expect(authIdx).toBeLessThan(svcIdx);
    // The checked marker sits on the authorization_code input, which is the
    // first radio rendered in the lane group.
    expect(html).toContain('value="authorization_code" checked');
    expect(html).not.toContain('value="client_credentials" checked');
  });

  it("states the lane on every card, and the return addresses on a connector", async () => {
    const s17 = await loadS17();
    const html = await s17.render(ctxFor([CONNECTOR, SERVICE]));
    expect(html).toContain("An app a person signs in to");
    expect(html).toContain("A backend service, on its own behalf");
    expect(html).toContain(REDIRECT);
    expect(html).toContain("authorization_code, refresh_token");
  });

  it("flags a connector that registered no return address", async () => {
    const s17 = await loadS17();
    const html = await s17.render(ctxFor([{ ...CONNECTOR, redirectUris: [] }]));
    expect(html).toContain("None registered");
  });

  it("escapes a hostile redirect URI", async () => {
    const s17 = await loadS17();
    const hostile = 'https://evil.example/"><img src=x onerror=alert(1)>';
    const html = await s17.render(ctxFor([{ ...CONNECTOR, redirectUris: [hostile] }]));
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });
});

describe("S17 registration payload carries the lane", () => {
  /** Minimal DOM stub: field values by selector + a radio checked-state map. */
  function domFor(fields: Record<string, string>, lane: string) {
    const statusNode = { textContent: "" };
    const root = {
      querySelector(selector: string) {
        if (selector === "#oauth-create-status") return statusNode;
        if (selector in fields) return { value: fields[selector] };
        return null;
      },
      querySelectorAll(selector: string) {
        if (selector === 'input[name="oauth-grant-lane"]') {
          return [{ checked: true, value: lane }];
        }
        if (selector === 'input[name="oauth-token-role"]') {
          return [{ checked: true, value: "assistant" }];
        }
        return [];
      },
    };
    return { root, statusNode };
  }

  function triggerFor(root: unknown) {
    return { closest: () => root, disabled: false, textContent: "Register client" };
  }

  it("sends authorization_code + refresh_token and the redirect URIs", async () => {
    const s17 = await loadS17();
    const { root } = domFor(
      {
        "#oauth-name": "Claude Code",
        "#oauth-ttl": "3600",
        "#oauth-description": "",
        "#oauth-tools": "",
        "#oauth-redirects": `${REDIRECT}\nhttps://claude.com/api/mcp/auth_callback`,
      },
      "authorization_code",
    );
    let sent: Record<string, unknown> | null = null;
    const ctx = {
      esc,
      identity: { role: "owner" },
      api: {
        get: async () => [],
        post: async (_path: string, body: Record<string, unknown>) => {
          sent = body;
          return { clientSecret: "hmcs_x", record: { clientId: "hmc_x", name: "Claude Code" } };
        },
      },
      go: async () => undefined,
    };
    await s17.actions["oauth-client-submit"](ctx, triggerFor(root));
    expect(sent).not.toBeNull();
    expect(sent!.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(sent!.redirectUris).toEqual([REDIRECT, "https://claude.com/api/mcp/auth_callback"]);
  });

  it("refuses a connector with no redirect URI instead of registering a dead one", async () => {
    const s17 = await loadS17();
    const { root, statusNode } = domFor(
      { "#oauth-name": "Claude Code", "#oauth-ttl": "3600", "#oauth-description": "", "#oauth-tools": "", "#oauth-redirects": "" },
      "authorization_code",
    );
    let posted = false;
    const ctx = {
      esc,
      identity: { role: "owner" },
      api: { get: async () => [], post: async () => { posted = true; return {}; } },
      go: async () => undefined,
    };
    await s17.actions["oauth-client-submit"](ctx, triggerFor(root));
    expect(posted).toBe(false);
    expect(statusNode.textContent).toContain("at least one redirect URI");
  });

  it("keeps a service client on client_credentials with no redirect URIs", async () => {
    const s17 = await loadS17();
    const { root } = domFor(
      {
        "#oauth-name": "reporting-service",
        "#oauth-ttl": "3600",
        "#oauth-description": "",
        "#oauth-tools": "mem_search",
        // Typed then switched lanes — the payload must not carry it.
        "#oauth-redirects": REDIRECT,
      },
      "client_credentials",
    );
    let sent: Record<string, unknown> | null = null;
    const ctx = {
      esc,
      identity: { role: "owner" },
      api: {
        get: async () => [],
        post: async (_path: string, body: Record<string, unknown>) => {
          sent = body;
          return { clientSecret: "hmcs_x", record: { clientId: "hmc_x", name: "reporting-service" } };
        },
      },
      go: async () => undefined,
    };
    await s17.actions["oauth-client-submit"](ctx, triggerFor(root));
    expect(sent!.grantTypes).toEqual(["client_credentials"]);
    expect(sent!.redirectUris).toEqual([]);
  });
});
