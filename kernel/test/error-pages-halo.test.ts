/**
 * Every page a HUMAN can land on renders in the Halofy design language.
 *
 * The regression this guards: server-rendered pages (OAuth consent + failures,
 * console static 4xx/5xx, the public memory index, browser navigations that hit
 * an HTTP error) used an ad-hoc dark palette that belonged to no design system,
 * so a connector failure looked like a different product than the console the
 * user had just signed in to.
 *
 * Assertions are on the DESIGN CONTRACT, not on pixel values: Halo tokens
 * present, the retired palette absent, no inline JS, and the API's JSON error
 * envelope unchanged for non-browser callers.
 */

import { describe, expect, it } from "vitest";
import { createServer, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { renderHaloStatusPage } from "../src/branding/halo-page.js";
import { handleAuthorizePage } from "../src/oauth/authorize.js";
import { serveStatic } from "../src/http/console.js";
import { servePublicDiscovery } from "../src/discovery/public.js";
import { handleHttpRequest, type HttpServerDeps } from "../src/http/server.js";
import type { AuditEvent, MemoryObject, Tenant } from "../src/types.js";

const CONSOLE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "console");

/** Tokens every Halo-rendered page must carry, and the palette it replaced. */
const EVERGREEN = "--evergreen:#123a2e";
const MINERAL = "--mineral:#f3f6ee";
const RETIRED = ["#0b0e14", "#7aa2f7", "#11151f", "#f7768e"];

function expectHaloPage(body: string): void {
  expect(body).toContain(EVERGREEN);
  expect(body).toContain(MINERAL);
  expect(body).toContain('font-family:"Inter"');
  expect(body).toContain("InterVariable.woff2");
  expect(body).toContain("halo-card");
  // The retired split "story rail" landing-page frame must never come back.
  expect(body).not.toContain("halo-story");
  expect(body).not.toContain("Every agent starts with the right context");
  expect(body).not.toContain("<script");
  for (const dead of RETIRED) expect(body).not.toContain(dead);
}

// ---------------------------------------------------------------------------
// The shared renderer
// ---------------------------------------------------------------------------

describe("halo status page", () => {
  it("escapes its copy and stays inline-JS free", () => {
    const body = renderHaloStatusPage({
      title: `<script>alert("x")</script>`,
      eyebrow: "Not found",
      heading: `A & B <b>`,
      messages: [`"quoted" <em>markup</em>`],
      action: { href: `/console/?a="b"`, label: "Back" },
    });
    expectHaloPage(body);
    expect(body).toContain("&lt;script&gt;");
    expect(body).toContain("A &amp; B &lt;b&gt;");
    expect(body).toContain("&quot;quoted&quot;");
  });
});

// ---------------------------------------------------------------------------
// OAuth consent + failure pages
// ---------------------------------------------------------------------------

const CLIENT = {
  id: "row1",
  clientId: "hmc_test",
  name: "Claude",
  status: "approved",
  namespace: "org",
  redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
  grantTypes: ["authorization_code", "refresh_token"],
};

const QUERY = {
  response_type: "code",
  client_id: CLIENT.clientId,
  redirect_uri: CLIENT.redirectUris[0],
  code_challenge: "G2PuECQ781JlLWrfXY_9GrzRStybd4DVVNM4y5BUTLo",
  code_challenge_method: "S256",
  state: "st",
  scope: "assistant",
};

const IDENTITY = {
  actor: "owner@org.test",
  namespace: "org",
  role: "owner",
  sessionUserId: "u1",
} as never;

function oauthDeps(client: unknown): never {
  return {
    clients: { loadByClientId: async () => client },
    codes: { mint: async () => "code" },
    audit: { append: async () => {} },
  } as never;
}

describe("oauth pages", () => {
  it("renders the consent screen in the Halo design language", async () => {
    const page = await handleAuthorizePage(
      oauthDeps(CLIENT), QUERY, "", IDENTITY, "https://halomem.test",
    );
    expect(page.status).toBe(200);
    expectHaloPage(page.body);
    // The decision buttons are the design system's, not bare <button>s.
    expect(page.body).toContain(`class="btn btn--solid"`);
    expect(page.body).toContain(`class="btn btn--outline"`);
  });

  it("renders authorization failures in the Halo design language", async () => {
    const page = await handleAuthorizePage(
      oauthDeps({ ...CLIENT, grantTypes: ["client_credentials"] }),
      QUERY, "", IDENTITY, "https://halomem.test",
    );
    expect(page.status).toBe(400);
    expectHaloPage(page.body);
    // The RFC-accurate reason still reaches the human.
    expect(page.body).toContain("This app may not request user authorization.");
    expect(page.headers["content-type"]).toContain("text/html");
  });
});

// ---------------------------------------------------------------------------
// Console static errors
// ---------------------------------------------------------------------------

function captureResponse(): { res: ServerResponse; body: () => string; status: () => number } {
  let body = "";
  let status = 0;
  const res = {
    writeHead(code: number) {
      status = code;
      return res;
    },
    end(chunk: string) {
      body = chunk ?? "";
    },
    headersSent: false,
    destroy() {},
  } as unknown as ServerResponse;
  return { res, body: () => body, status: () => status };
}

describe("console static errors", () => {
  it("serves a Halo page for a missing console route", async () => {
    const cap = captureResponse();
    await serveStatic(CONSOLE_DIR, "/console/no-such-screen", cap.res);
    expect(cap.status()).toBe(404);
    expectHaloPage(cap.body());
    expect(cap.body()).toContain("Back to the console");
  });

  it("serves a Halo page for a traversal attempt (still 403)", async () => {
    const cap = captureResponse();
    await serveStatic(CONSOLE_DIR, "/console/%2e%2e%2fserver.ts", cap.res);
    expect(cap.status()).toBe(403);
    expectHaloPage(cap.body());
    // Never names what it refused to serve.
    expect(cap.body()).not.toContain("server.ts");
  });
});

// ---------------------------------------------------------------------------
// Public discovery
// ---------------------------------------------------------------------------

const TENANT: Tenant = { id: "acme", name: "Acme Corp", status: "active" } as Tenant;

const PUBLIC_ROW = {
  id: "01J",
  tier: "L2",
  type: "fact",
  content: "Halo Mem delegates retrieval to swappable engines.",
  namespace: "acme",
  assertionTime: "2026-07-18T00:00:00.000Z",
  tValidFrom: "2026-07-18T00:00:00.000Z",
  tValidTo: null,
  status: "active",
  version: 1,
  supersedes: null,
  classification: {
    sensitivity: "public",
    piiSubjects: [],
    secretKinds: [],
    allowedDestinations: [],
  },
  provenance: [{ actor: "alice@acme.com", sourceId: "notion:wiki", ts: "2026-07-18T00:00:00.000Z" }],
  confidence: 1,
  embedding: null,
} as unknown as MemoryObject;

function publicDeps(tenant: Tenant | null, rows: MemoryObject[]): never {
  const audits: AuditEvent[] = [];
  return {
    index: { listCandidates: async () => rows },
    tenants: { get: async () => tenant },
    audit: { append: async (e: AuditEvent) => void audits.push(e) },
  } as never;
}

describe("public discovery", () => {
  it("renders the org index in the Halo design language", async () => {
    const res = await servePublicDiscovery(publicDeps(TENANT, [PUBLIC_ROW]), "acme", "page");
    expect(res.status).toBe(200);
    expect(res.contentType).toContain("text/html");
    expect(res.body).toContain(EVERGREEN);
    expect(res.body).toContain(MINERAL);
    expect(res.body).not.toContain("<script");
    for (const dead of RETIRED) expect(res.body).not.toContain(dead);
  });

  it("keeps the 404 byte-identical across causes and names no org (E30)", async () => {
    const unknown = await servePublicDiscovery(publicDeps(null, []), "acme", "page");
    const suspended = await servePublicDiscovery(
      publicDeps({ ...TENANT, status: "suspended" } as Tenant, [PUBLIC_ROW]), "acme", "page",
    );
    const empty = await servePublicDiscovery(publicDeps(TENANT, []), "acme", "page");

    expect(unknown.status).toBe(404);
    expect(suspended).toEqual(unknown);
    expect(empty).toEqual(unknown);
    expectHaloPage(unknown.body);
    expect(unknown.body).not.toContain("Acme");
    expect(unknown.body).not.toContain("acme");
  });

  it("leaves llms.txt as plain text for machine callers", async () => {
    const res = await servePublicDiscovery(publicDeps(null, []), "acme", "llms");
    expect(res.status).toBe(404);
    expect(res.contentType).toContain("text/plain");
    expect(res.body).toBe("Not found.\n");
  });
});

// ---------------------------------------------------------------------------
// HTTP transport: browser navigations negotiate to HTML, API callers do not
// ---------------------------------------------------------------------------

describe("http error negotiation", () => {
  const deps = {
    auth: { resolve: async () => null },
    audit: { append: async () => {} },
    syscalls: {},
  } as unknown as HttpServerDeps;

  async function withServer<T>(fn: (base: string) => Promise<T>): Promise<T> {
    const server = createServer((req, res) => {
      void handleHttpRequest(deps, req, res);
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const addr = server.address();
    const port = typeof addr === "object" && addr !== null ? addr.port : 0;
    try {
      return await fn(`http://127.0.0.1:${port}`);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }

  it("renders a Halo page for a browser navigation to a dead URL", async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/no-such-page`, {
        headers: { accept: "text/html,application/xhtml+xml" },
      });
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.headers.get("content-type")).toContain("text/html");
      expectHaloPage(await res.text());
    });
  });

  it("keeps the JSON envelope for API callers on the same URL", async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/no-such-page`);
      expect(res.headers.get("content-type")).toContain("application/json");
      const body = (await res.json()) as { error: string; code: string };
      expect(typeof body.code).toBe("string");
    });
  });

  it("keeps the JSON envelope for non-navigation methods even from a browser", async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/no-such-page`, {
        method: "POST",
        headers: { accept: "text/html", "content-type": "application/json" },
        body: "{}",
      });
      expect(res.headers.get("content-type")).toContain("application/json");
    });
  });
});
