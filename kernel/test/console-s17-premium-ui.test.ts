import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function render(clients: unknown[] = []): Promise<string> {
  const screen = await import(
    fileURLToPath(new URL("../console/screens/s17.js", import.meta.url))
  ) as { render(ctx: unknown): Promise<string> };

  return screen.render({
    esc,
    identity: { role: "owner" },
    api: { get: async () => clients },
  });
}

const CONNECTED_APP = {
  id: "01CONNECTED",
  clientId: "hmc_connected",
  name: "Claude",
  description: "Company memory in Claude",
  status: "approved",
  origin: "dcr",
  namespace: "halofy",
  tokenRole: "assistant",
  tokenTtlSeconds: 3600,
  tokenCount: 4,
  activeTokenCount: 1,
  grantTypes: ["authorization_code", "refresh_token"],
  redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
  allowedTools: [],
  createdAt: "2026-08-01T12:00:00.000Z",
};

const DISCONNECTED_APP = {
  ...CONNECTED_APP,
  id: "01DISCONNECTED",
  clientId: "hmc_disconnected",
  name: "Legacy service",
  status: "revoked",
};

describe("S17 premium connected-apps experience", () => {
  it("leads with the connection journey and one consolidated security disclosure", async () => {
    const html = await render([CONNECTED_APP]);

    expect(html).toContain('class="oauth-screen"');
    expect(html).toContain('class="oauth-journey card"');
    expect(html).toContain("Connect in three steps");
    expect(html).toContain("Copy connection URL");
    expect(html).toContain("Add it to your agent");
    expect(html).toContain("Approve here");
    expect(html).toContain('class="btn btn--outline btn--sm oauth-journey__guide"');
    expect(html).not.toContain('class="oauth-journey__footer"');
    expect(html.match(/<summary>Connection security<\/summary>/g)).toHaveLength(1);
    expect(html).not.toContain("<summary>Policy</summary>");
  });

  it("shows authoritative lifecycle counts and purposeful empty states", async () => {
    const html = await render([CONNECTED_APP]);

    expect(html).toContain('data-oauth-count="pending">0</');
    expect(html).toContain('data-oauth-count="approved">1</');
    expect(html).toContain('data-oauth-count="revoked">0</');
    expect(html).not.toContain('aria-label="Waiting for approval"');
    expect(html).not.toContain("New connection requests will appear here");
  });

  it("keeps disconnected history in a closed archive", async () => {
    const html = await render([CONNECTED_APP, DISCONNECTED_APP]);

    expect(html).toContain('<details class="oauth-archive" aria-label="Disconnected apps">');
    expect(html).toContain("Legacy service");
    expect(html).not.toContain('<section class="oauth-group oauth-group--revoked"');
  });

  it("keeps visible guidance concise", async () => {
    const html = await render([CONNECTED_APP]);

    expect(html).toContain("Manage access for agents and apps.");
    expect(html).toContain("Manual apps need approval before access.");
    expect(html).not.toContain("Give Claude, ChatGPT, coding tools, and backend services");
    expect(html).not.toContain("Most agent environments register themselves");
    expect(html).not.toContain("Need your review");
    expect(html).not.toContain("Can access Halofy");
    expect(html).not.toContain("Access removed");
  });

  it("keeps protocol controls behind an advanced-settings disclosure", async () => {
    const html = await render();
    const advancedStart = html.indexOf('<details class="oauth-advanced"');
    const lifetime = html.indexOf('id="oauth-ttl"');
    const tools = html.indexOf('id="oauth-tools"');

    expect(advancedStart).toBeGreaterThan(-1);
    expect(lifetime).toBeGreaterThan(advancedStart);
    expect(tools).toBeGreaterThan(advancedStart);
    expect(html).toContain("Advanced OAuth settings");
    expect(html).toContain("Add app for approval");
  });
});
