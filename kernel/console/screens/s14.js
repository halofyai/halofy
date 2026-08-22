import { organizationScopeLabel } from "../identity-labels.js";
import { screenIdFromHash } from "../routes.js";

// S14 - Integrations. Connect coding agents and MCP clients to this deployment.
//
// The kernel already speaks MCP over Streamable HTTP at /mcp (bearer-key auth,
// identity resolved server-side per D9). This screen turns that into a
// connect surface: one card per client, each opening a modal with copy-paste
// setup generated from THIS deployment's origin and a freshly minted agent
// badge. Config formats follow each vendor's official docs:
//   Claude Code    - `claude mcp add --transport http … --header` / .mcp.json
//   Codex CLI      - config.toml [mcp_servers.*] with bearer_token_env_var
//   Cursor         - ~/.cursor/mcp.json url+headers
//   VS Code        - .vscode/mcp.json "servers" + ${input:} secret prompt
//   Cline          - type "streamableHttp" (omitting type falls back to SSE)
//   Gemini CLI     - httpUrl (NOT url, that's SSE) + headers
//   Antigravity    - ~/.gemini/config/mcp_config.json serverUrl + headers
//   Claude Desktop - stdio bridge via npx mcp-remote (config file is stdio-only)
//   Hermes Agents  - ~/.hermes/config.yaml mcp_servers.* url+headers
//   OpenClaw       - ~/.openclaw/openclaw.json mcp.servers.* streamable-http
//   ChatGPT        - developer-mode connectors are OAuth-only: served by the
//                    kernel's hosted AS (authorization_code + PKCE + dynamic
//                    registration), consent at /oauth/authorize — no key paste
// Keys: minted via the typed POST /v1/admin/keys path (type "assistant" -
// plaintext held in the browser for 90s), revealed again from its encrypted
// server envelope, claimed from an organization-assigned handoff, or pasted
// locally - the pasted value never leaves the browser. A
// member's assigned badges live in their own card directly below Connected
// agents; claiming one fills every client recipe on this page for the same
// 90-second window without creating a second credential path. E58 surfaces the
// three product key types (Admin /
// Assistant / Read-only, prefix-marked) with the same vocabulary as s3.
// The "Connected agents" card at the top lists the live agent badges THIS
// caller connected (GET /v1/admin/keys, owner/admin or member-exact, filtered
// to `createdBy` = the signed-in actor or a recipient-only claimed handoff)
// with their api_keys.last_used signal -
// bumped on every bearer-key resolution, so it doubles as "last connected".
// The scope-wide ledger - every badge in the subtree, whoever minted it - is
// s3's job; an admin's own connections are what this screen is about, and the
// full scope-wide ledger remains available through a compact Manage action.
// Revoked badges are dead credentials, not connections: the card hides them
// (the full ledger stays on s3) and offers an inline Revoke for live ones,
// without adding credential-ledger prose below the table.
// Each row leads with the client's brand logo, matched from the agent name.
// MCP is stateless and last_used is per key, not per client app; the card
// says so rather than faking a per-client connection status.

let mintedKey = null; // { plaintext, actor, label, source, keyId?, handoffId?, revealed } - retained briefly
let manualKey = "";
let manualKeyRevealed = false;
let mintClearTimer = null;
let keydownDoc = null;
let keydownHandler = null;

const KEY_PLACEHOLDER = "{{HALOMEM_API_KEY}}";
const BEARER_MASK = "•••• •••• •••• •••• •••• ••••";
/** "Active" = the badge authenticated within this window. MCP is stateless,
 * so api_keys.last_used (bumped on every bearer-key resolution) is the only
 * liveness signal there is. */
const ACTIVE_WINDOW_MS = 15 * 60 * 1000;
/** The connected-agents card caps its rows; the full list lives on s3. */
const CONNECTED_PAGE = 8;
const TABLE_FILTER_SVG =
  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2.5 3.25h11l-4.2 4.9v3.5l-2.6 1.35V8.15L2.5 3.25Z" stroke-linejoin="round"/></svg>';
let tableFilters = {
  connected: { connection: "", badge: "" },
  assigned: { assignment: "", access: "" },
};
let tablePages = { connected: 0, assigned: 0 };
// `mem_policy` leads the list on purpose: it is the guardrail read an agent
// should make before it acts, and its delivery is what the S4 compliance view
// scores.
const ENDPOINT_TOOLS = ["mem_policy", "mem_search", "mem_write", "mem_read", "source_read", "request_access"];

/**
 * M9 #23 (E58 - the s14 half of E52): the three product key types are LABELS
 * over the existing roles. src/auth/key-types.ts is the server-side source of
 * truth and s3.js established the console vocabulary - this table mirrors both
 * for display only; the server never trusts these values. Minting here goes
 * through the typed POST /v1/admin/keys path (type, not role), so role mapping
 * and the ownerOnly gate stay server-side.
 */
const KEY_TYPES = [
  { type: "admin", label: "Admin", prefix: "hm_adm_",
    hint: "Full team control: minted from Team & agents, not here." },
  { type: "assistant", label: "Assistant", prefix: "hm_agt_",
    hint: "For agents and MCP clients: read, search, and write through the governed write path." },
  { type: "read-only", label: "Read-only", prefix: "hm_ro_",
    hint: "Audit and reporting: read memory and the audit trail, write nothing." },
];

const CONNECTED_FILTER_SECTIONS = [
  {
    field: "connection",
    label: "Connection",
    options: [
      { value: "", label: "All connections" },
      { value: "active", label: "Active now" },
      { value: "seen", label: "Seen before" },
      { value: "never", label: "Never connected" },
    ],
  },
  {
    field: "badge",
    label: "Badge",
    options: [
      { value: "", label: "All badges" },
      { value: "live", label: "Live" },
      { value: "expired", label: "Expired" },
    ],
  },
];

const ASSIGNED_FILTER_SECTIONS = [
  {
    field: "assignment",
    label: "Assignment",
    options: [
      { value: "", label: "All assignments" },
      { value: "ready", label: "Ready" },
      { value: "claimed", label: "Claimed" },
      { value: "expired", label: "Claim expired" },
      { value: "revoked", label: "Revoked" },
    ],
  },
  {
    field: "access",
    label: "Access",
    options: [
      { value: "", label: "All access" },
      { value: "read", label: "Read only" },
      { value: "write", label: "Read + write" },
    ],
  },
];

/** Best-effort type of an already-minted key, from its plaintext prefix alone. */
function keyTypeForPlaintext(value) {
  const plaintext = String(value || "");
  return KEY_TYPES.find((spec) => plaintext.startsWith(spec.prefix)) || null;
}

/** Text for the manual-key type readout (set via textContent - never HTML). */
function manualTypeText(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  const spec = keyTypeForPlaintext(trimmed);
  return spec
    ? spec.label + " key · " + spec.prefix + "…"
    : "Unrecognized prefix: pre-typed keys carry no type marker.";
}

function baseUrl() {
  // Pure-Node render tests have no window; any absolute https origin works
  // there because snippets are assertion targets, not live config.
  return typeof window === "undefined" ? "https://halomem.example" : window.location.origin;
}
function mcpUrl() {
  return baseUrl() + "/mcp";
}
function keyValue() {
  if (mintedKey && mintedKey.plaintext) return mintedKey.plaintext;
  return manualKey.trim();
}
function keyOrPlaceholder() {
  return keyValue() || KEY_PLACEHOLDER;
}

// ---------------------------------------------------------------------------
// Client catalog. build(base, key) returns steps: { title, note?, code?, copy? }.
// `code` is the raw clipboard text; rendering escapes it. `copy: false` for
// prose-only steps.
// ---------------------------------------------------------------------------

export const CLIENTS = [
  {
    id: "claude-code",
    logo: "https://cdn.simpleicons.org/claude",
    name: "Claude Code",
    vendor: "Anthropic",
    kind: "CLI",
    sub: "One command for Claude Code",
    icon: "terminal",
    docs: "https://code.claude.com/docs/en/mcp",
    build(base, key) {
      return [
        {
          title: "Add over HTTP (one command)",
          note: "Scopes: --scope local (default), project (.mcp.json, checked in), or user (~/.claude.json).",
          code:
            "claude mcp add --transport http halomem " + base + "/mcp \\\n" +
            '  --header "Authorization: Bearer ' + key + '"',
        },
        {
          title: "Or merge into .mcp.json at the project root",
          note: 'Keys can stay out of the file: "Bearer ${HALOMEM_API_KEY}" expands from the environment.',
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "type": "http",\n      "url": "' +
            base + '/mcp",\n      "headers": {\n        "Authorization": "Bearer ' + key +
            '"\n      }\n    }\n  }\n}',
        },
        {
          title: "Verify",
          code: "claude mcp list",
        },
      ];
    },
  },
  {
    id: "codex",
    logo: "",
    name: "Codex CLI",
    vendor: "OpenAI",
    kind: "CLI",
    sub: "Native Streamable HTTP",
    icon: "terminal",
    docs: "https://developers.openai.com/codex/mcp",
    build(base, key) {
      return [
        {
          title: "Save the key in your shell profile",
          code: 'export HALOMEM_API_KEY="' + key + '"',
        },
        {
          title: "Add the server (one command)",
          code: "codex mcp add halomem --url " + base + "/mcp --bearer-token-env-var HALOMEM_API_KEY",
        },
        {
          title: "Or merge into ~/.codex/config.toml",
          note: "Codex reads the env var at connect time; the key never sits in the file.",
          code:
            "[mcp_servers.halomem]\nurl = \"" + base + "/mcp\"\nbearer_token_env_var = \"HALOMEM_API_KEY\"",
        },
      ];
    },
  },
  {
    id: "cursor",
    logo: "https://cdn.simpleicons.org/cursor",
    name: "Cursor",
    vendor: "Anysphere",
    kind: "AI IDE",
    sub: "Project or global mcp.json",
    icon: "ide",
    docs: "https://cursor.com/docs/context/mcp",
    build(base, key) {
      return [
        {
          title: "Merge into ~/.cursor/mcp.json (global) or .cursor/mcp.json (project)",
          note: 'Env indirection works here too: "Bearer ${env:HALOMEM_API_KEY}".',
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "url": "' + base +
            '/mcp",\n      "headers": {\n        "Authorization": "Bearer ' + key +
            '"\n      }\n    }\n  }\n}',
        },
      ];
    },
  },
  {
    id: "vscode",
    logo: "https://cdn.simpleicons.org/vscodium",
    name: "VS Code",
    vendor: "GitHub Copilot",
    kind: "IDE",
    sub: "Native MCP",
    icon: "ide",
    docs: "https://code.visualstudio.com/docs/copilot/customization/mcp-servers",
    build(base) {
      return [
        {
          title: "Merge into .vscode/mcp.json",
          note: "VS Code prompts once for the key (masked) and stores it; nothing lands in the file.",
          code:
            '{\n  "inputs": [\n    {\n      "type": "promptString",\n      "id": "halomem-key",\n      "description": "Halofy API key",\n      "password": true\n    }\n  ],\n  "servers": {\n    "halomem": {\n      "type": "http",\n      "url": "' +
            base + '/mcp",\n      "headers": {\n        "Authorization": "Bearer ${input:halomem-key}"\n      }\n    }\n  }\n}',
        },
        {
          title: "Or add from the command line",
          code:
            'code --add-mcp "{\\"name\\":\\"halomem\\",\\"type\\":\\"http\\",\\"url\\":\\"' +
            base + '/mcp\\",\\"headers\\":{\\"Authorization\\":\\"Bearer ${input:halomem-key}\\"}}"',
        },
      ];
    },
  },
  {
    id: "cline",
    logo: "https://cdn.simpleicons.org/cline",
    name: "Cline",
    vendor: "VS Code extension",
    kind: "Extension",
    sub: "Streamable HTTP",
    icon: "ide",
    docs: "https://docs.cline.bot/mcp/configuring-mcp-servers",
    build(base, key) {
      return [
        {
          title: "Open Cline → MCP Servers → Configured → Configure MCP Servers",
          copy: false,
        },
        {
          title: "Merge into cline_mcp_settings.json",
          note: 'The "type": "streamableHttp" line is required; a bare url entry falls back to legacy SSE.',
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "type": "streamableHttp",\n      "url": "' +
            base + '/mcp",\n      "headers": {\n        "Authorization": "Bearer ' + key +
            '"\n      },\n      "disabled": false,\n      "autoApprove": []\n    }\n  }\n}',
        },
      ];
    },
  },
  {
    id: "gemini-cli",
    logo: "https://cdn.simpleicons.org/googlegemini",
    name: "Gemini CLI",
    vendor: "Google",
    kind: "CLI",
    sub: "httpUrl transport",
    icon: "terminal",
    docs: "https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md",
    build(base, key) {
      return [
        {
          title: "Add the server (one command)",
          code:
            'gemini mcp add --transport http --header "Authorization: Bearer ' + key +
            '" halomem ' + base + "/mcp",
        },
        {
          title: "Or merge into ~/.gemini/settings.json",
          note: 'Use httpUrl, not url: in Gemini CLI "url" means legacy SSE.',
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "httpUrl": "' + base +
            '/mcp",\n      "headers": {\n        "Authorization": "Bearer ' + key +
            '"\n      }\n    }\n  }\n}',
        },
      ];
    },
  },
  {
    id: "antigravity",
    logo: "https://cdn.simpleicons.org/googlegemini",
    name: "Antigravity",
    vendor: "Google",
    kind: "AI IDE",
    sub: "Shared Gemini config",
    icon: "ide",
    docs: "https://antigravity.google/docs/mcp",
    build(base, key) {
      return [
        {
          title: "Agent panel → Manage MCP Servers → View raw config",
          copy: false,
        },
        {
          title: "Merge into ~/.gemini/config/mcp_config.json",
          note: "Antigravity's field is serverUrl (not url or httpUrl).",
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "serverUrl": "' + base +
            '/mcp",\n      "headers": {\n        "Authorization": "Bearer ' + key +
            '"\n      }\n    }\n  }\n}',
        },
      ];
    },
  },
  {
    id: "claude-desktop",
    logo: "https://cdn.simpleicons.org/claude",
    name: "Claude Desktop",
    vendor: "Anthropic",
    kind: "Desktop app",
    sub: "Bridge with mcp-remote",
    icon: "desktop",
    docs: "https://github.com/geelen/mcp-remote",
    build(base, key) {
      return [
        {
          title: "Merge into claude_desktop_config.json",
          note:
            "Windows: %APPDATA%\\Claude\\ · macOS: ~/Library/Application Support/Claude/. " +
            "The env indirection is deliberate: spaces inside args break on Windows. Needs Node installed; restart the app after saving.",
          code:
            '{\n  "mcpServers": {\n    "halomem": {\n      "command": "npx",\n      "args": [\n        "-y",\n        "mcp-remote",\n        "' +
            base + '/mcp",\n        "--header",\n        "Authorization:${AUTH_HEADER}",\n        "--transport",\n        "http-only"\n      ],\n      "env": {\n        "AUTH_HEADER": "Bearer ' +
            key + '"\n      }\n    }\n  }\n}',
        },
      ];
    },
  },
  {
    id: "hermes-agents",
    // The official Hermes icon, vendored locally — Nous Research ships no
    // logo-CDN slug (source: hermes-agent.nousresearch.com/icon.png).
    logo: "assets/marks/hermes.png",
    name: "Hermes Agents",
    vendor: "Nous Research",
    kind: "Agent",
    sub: "Native MCP client config",
    icon: "bot",
    docs: "https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference",
    build(base, key) {
      return [
        {
          title: "Merge into ~/.hermes/config.yaml",
          note:
            "Hermes reads remote HTTP MCP servers from mcp_servers. The Authorization header is sent on every MCP request.",
          code:
            'mcp_servers:\n  halomem:\n    url: "' + base +
            '/mcp"\n    headers:\n      Authorization: "Bearer ' + key +
            '"\n    timeout: 120\n    connect_timeout: 60\n    tools:\n      resources: true\n      prompts: true',
        },
        {
          title: "Reload MCP after saving",
          code: "/reload-mcp",
        },
      ];
    },
  },
  {
    id: "openclaw",
    logo: "",
    name: "OpenClaw",
    vendor: "OpenClaw",
    kind: "Agent",
    sub: "mcp.servers registry",
    icon: "bot",
    docs: "https://docs.openclaw.ai/cli/mcp",
    build(base, key) {
      return [
        {
          title: "Merge into ~/.openclaw/openclaw.json",
          note:
            'OpenClaw consumes this as a saved outbound MCP server. Use transport: "streamable-http" for Halofy.',
          code:
            '{\n  mcp: {\n    servers: {\n      halomem: {\n        url: "' + base +
            '/mcp",\n        transport: "streamable-http",\n        headers: {\n          Authorization: "Bearer ' +
            key + '"\n        },\n        requestTimeoutMs: 120000,\n        connectionTimeoutMs: 60000\n      }\n    }\n  }\n}',
        },
        {
          title: "Or save it with the CLI",
          code:
            "openclaw mcp set halomem " +
            "'{\"url\":\"" + base + "/mcp\",\"transport\":\"streamable-http\",\"headers\":{\"Authorization\":\"Bearer " +
            key + "\"},\"requestTimeoutMs\":120000,\"connectionTimeoutMs\":60000}'",
        },
        {
          title: "Verify",
          note: "probe opens a live MCP connection and lists capabilities; status only checks saved config.",
          code: "openclaw mcp probe halomem",
        },
      ];
    },
  },
  {
    id: "chatgpt",
    logo: "",
    name: "ChatGPT",
    vendor: "OpenAI",
    kind: "Web app",
    sub: "Developer-mode connector",
    icon: "chat",
    docs: "https://developers.openai.com/api/docs/guides/developer-mode",
    build(base, _key, ctx) {
      const revokeNote = isMember(ctx)
        ? "disconnect it from ChatGPT at any time."
        : "revoke it any time from Connected apps.";
      return [
        {
          title: "Settings → Apps & Connectors → enable Developer mode",
          note: "Available on ChatGPT plans that support custom connectors.",
          copy: false,
        },
        {
          title: "Add a connector with this MCP server URL",
          code: base + "/mcp",
        },
        {
          title: "Authorize in the browser",
          note:
            "ChatGPT discovers this deployment's OAuth endpoints automatically, registers itself, " +
            "and opens Halofy's consent page. Sign in with your console account and click Allow - " +
            "the connector runs on a short-lived, tool-scoped token in your space. No API key is pasted; " +
            revokeNote,
          copy: false,
        },
      ];
    },
  },
  {
    id: "mcp-url",
    logo: "https://cdn.simpleicons.org/modelcontextprotocol",
    name: "MCP URL",
    vendor: "Any client",
    kind: "Custom",
    sub: "Raw Streamable HTTP endpoint",
    icon: "link",
    docs: "",
    build(base, key) {
      return [
        {
          title: "Endpoint",
          code: base + "/mcp",
        },
        {
          title: "Auth header (every request)",
          code: "Authorization: Bearer " + key,
        },
        {
          title: "Stdio-only client? Bridge with mcp-remote",
          code:
            "npx -y mcp-remote " + base + '/mcp --header "Authorization: Bearer ' + key +
            '" --transport http-only',
        },
      ];
    },
  },
];

const PLUGINS = [
  {
    id: "plugin-claude-code",
    logo: "https://cdn.simpleicons.org/claude",
    name: "Claude Code plugin",
    vendor: "Halofy",
    kind: "Session hooks",
    sub: "Recall and capture hooks",
    icon: "bot",
    docs: "",
    build(base, key) {
      return [
        {
          title: "Point the plugin at this deployment",
          code:
            'export HALOMEM_URL="' + base + '"\nexport HALOMEM_API_KEY="' + key + '"',
        },
        {
          title: "Add the marketplace bundled with your Halofy checkout, then install",
          note:
            "Ships in kernel/integrations of this repository. SessionStart injects the organization's governed policy " +
            "as binding guardrails and then the relevant memories as context; " +
            "Stop captures the session through the governed write path (extraction, verification, supersedence; D10). " +
            "Hooks fail open: if the kernel is unreachable the agent keeps running.",
          code:
            "claude plugin marketplace add <path-to-halomem>/kernel/integrations\nclaude plugin install halomem@halomem-integrations",
        },
        {
          title: "MCP tools ride along",
          note: "Registers mem_policy, mem_search, and mem_write.",
          copy: false,
        },
      ];
    },
  },
  {
    id: "plugin-codex",
    logo: "",
    name: "Codex wiring",
    vendor: "Halofy",
    kind: "Installer",
    sub: "Installer for Codex CLI",
    icon: "bot",
    docs: "",
    build(base, key) {
      return [
        {
          title: "Save key",
          code: 'export HALOMEM_API_KEY="' + key + '"',
        },
        {
          title: "Run the installer from your Halofy checkout",
          note:
            "Idempotently merges [mcp_servers.halomem] into ~/.codex/config.toml using bearer_token_env_var: " +
            "the key stays in your environment, never in the file.",
          code: "node <path-to-halomem>/kernel/integrations/codex/install.mjs --url " + base,
        },
      ];
    },
  },
];

const API_CARD = {
  id: "http-api",
  name: "HTTP API",
  vendor: "curl, Shortcuts, Raycast, anything",
  kind: "REST",
  sub: "Governed syscalls over JSON",
  icon: "link",
  docs: "",
  build(base, key) {
    return [
      {
        title: "Remember something",
        note: "Namespace and actor come from the key (D9); the body never asserts identity.",
        code:
          "curl -s " + base + "/v1/mem/write \\\n" +
          '  -H "Authorization: Bearer ' + key + '" \\\n' +
          '  -H "Content-Type: application/json" \\\n' +
          "  -d '{\"scope\":\"user\",\"content\":\"Acme prefers weekly invoicing\"}'",
      },
      {
        title: "Recall",
        code:
          "curl -s " + base + "/v1/mem/search \\\n" +
          '  -H "Authorization: Bearer ' + key + '" \\\n' +
          '  -H "Content-Type: application/json" \\\n' +
          "  -d '{\"query\":\"invoicing preferences\",\"k\":5}'",
      },
    ];
  },
};

function allEntries() {
  return CLIENTS.concat(PLUGINS, [API_CARD]);
}
function findEntry(id) {
  return allEntries().find((entry) => entry.id === id) || null;
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/** @param {import('../app.js').Ctx} ctx @returns {Promise<string>} */
export async function render(ctx) {
  const { esc, ui } = ctx;
  const namespace = (ctx.identity && ctx.identity.namespace) || "";
  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const head = ui.head({
    eyebrow: "Operate · " + esc(nsLabel),
    title: "Agent connections",
    acts: ui.pill("Streamable HTTP · Bearer auth", "live"),
  });
  // The connected-agents card reads the badge listing, which the server gates
  // to owner/admin or a member's exact namespace — an auditor doesn't get the card, and a
  // failed fetch browns out to a note inside the card rather than taking the
  // whole screen down with it.
  const handoffPayload = isMember(ctx) ? await safeGet(ctx, "/v1/admin/key-handoffs") : null;
  const handoffsAvailable = !isMember(ctx) || handoffPayload !== null;
  const handoffs = arrayFrom(handoffPayload, "handoffs");
  const claimedKeyIds = new Set(
    handoffs
      .filter((entry) => String((entry && entry.status) || "").toLowerCase() === "claimed")
      .map((entry) => String((entry && entry.claimedKeyId) || ""))
      .filter(Boolean),
  );
  const badges = canMutate(ctx) ? await loadAgentBadges(ctx, claimedKeyIds) : null;

  return (
    '<div class="intg-screen screen-flow">' +
    head +
    endpointCard(ctx) +
    (badges ? connectedAgentsCard(ctx, badges) : "") +
    (isMember(ctx) ? assignedBadgesCard(ctx, handoffs, handoffsAvailable) : "") +
    connectionLibrary(ctx) +
    '<div id="integration-modal" class="source-wizard-overlay" hidden aria-hidden="true"></div>' +
    "</div>"
  );
}

export function cleanup(reason) {
  if (typeof document !== "undefined") closeModal(document);
  if (reason === "refresh") return;
  mintedKey = null;
  manualKey = "";
  manualKeyRevealed = false;
  tableFilters = {
    connected: { connection: "", badge: "" },
    assigned: { assignment: "", access: "" },
  };
  tablePages = { connected: 0, assigned: 0 };
  if (mintClearTimer) clearTimeout(mintClearTimer);
  mintClearTimer = null;
}

function connectionLibrary(ctx) {
  return (
    '<section class="card intg-library" aria-labelledby="intg-library-title">' +
    '<div class="intg-library-head"><h2 id="intg-library-title">Connect an agent</h2></div>' +
    libraryGroup("MCP clients", CLIENTS.map((entry) => card(ctx, entry)).join("")) +
    keyCard(ctx) +
    libraryGroup("Agent plugins", PLUGINS.map((entry) => card(ctx, entry)).join("")) +
    libraryGroup("Other connections", sourcesCard(ctx) + card(ctx, API_CARD)) +
    "</section>"
  );
}

function libraryGroup(title, cards) {
  return (
    '<div class="intg-library-group"><h3>' + title + "</h3>" +
    '<div class="intg-grid">' + cards + "</div></div>"
  );
}

function endpointCard(ctx) {
  const esc = ctx.esc;
  const tools = ENDPOINT_TOOLS.map((t) => '<span class="intg-tool mono">' + esc(t) + "</span>").join("");
  return (
    '<div class="card intg-endpoint"><div class="between"><h3>Your MCP endpoint' +
    headingInfo("Your MCP endpoint", "Identity comes from the bearer key. Every call is audited.") + "</h3>" +
    '<button class="btn btn--outline btn--sm" data-action="intg-copy-endpoint">Copy URL</button></div>' +
    '<div class="snippet">' + esc(mcpUrl()) + "</div>" +
    '<div class="intg-tools">' + tools + "</div></div>"
  );
}

// ---------------------------------------------------------------------------
// Connected agents — the badge listing with its last-used signal.
// ---------------------------------------------------------------------------

/** Agent badges THIS caller connected, most recently used first.
 *
 * This card is the caller's own connections - an admin sees the agents it
 * deployed, a member sees the agents it deployed, and neither sees the other's.
 * The scope-wide ledger (every badge in the subtree, whoever minted it) is
 * Scoped memory's job; duplicating it here made an admin's own list unreadable.
 * Attribution is `createdBy` (api_keys.created_by, migration 76 - the ISSUING
 * actor, not the actor the badge acts as), plus a claimed key ID from this
 * member's recipient-only handoff listing. The latter matters because the
 * public console identity intentionally omits the internal session user ID.
 * A badge with neither signal is nobody's connection: it is treated as
 * out-of-scope, never shown here.
 *
 * Revoked badges are dropped - a revoked credential is not a connection - but
 * counted so the all-revoked empty state remains honest. `unavailable` marks a
 * refused or failed listing so the card can say so instead of lying with an
 * empty state. */
async function loadAgentBadges(ctx, claimedKeyIds = new Set()) {
  const value = await safeGet(ctx, "/v1/admin/keys");
  if (value === null) {
    return { unavailable: true, list: [], revokedCount: 0 };
  }
  const agents = arrayFrom(value, "keys")
    .filter((key) => String((key && key.role) || "") === "agent");
  const mine = agents.filter((key) => connectedByViewer(ctx, key, claimedKeyIds));
  const revokedCount = mine.filter((key) => isRevoked(key)).length;
  const list = mine
    .filter((key) => !isRevoked(key))
    .sort((a, b) => lastUsedMs(b) - lastUsedMs(a));
  return { unavailable: false, list, revokedCount };
}

/** Did the signed-in human mint this badge? Compared on the issuing actor,
 * which for a console session is the account email. Trimmed and case-folded
 * because the two sides are typed by people, not machines. */
function connectedByViewer(ctx, badge, claimedKeyIds) {
  if (claimedKeyIds.has(String((badge && badge.id) || ""))) return true;
  const viewer = normalizeActor(ctx.identity && ctx.identity.actor);
  const issuer = normalizeActor(badge && badge.createdBy);
  return viewer !== "" && issuer !== "" && viewer === issuer;
}

function normalizeActor(value) {
  return String(value == null ? "" : value).trim().toLowerCase();
}

function isRevoked(badge) {
  return String((badge && badge.status) || "").toLowerCase() === "revoked";
}

function lastUsedMs(badge) {
  const time = Date.parse(String((badge && badge.lastUsed) || ""));
  return Number.isFinite(time) ? time : 0;
}

function connectedAgentsCard(ctx, badges) {
  const esc = ctx.esc;
  const member = isMember(ctx);
  const info = member
    ? "Agents and MCP clients you connected or claimed, and when each last authenticated. Organization-assigned badges appear below until you claim them."
    : "Agents and MCP clients you connected, and when each last authenticated. Badges connected by other people live in Scoped memory. Revoked badges are hidden.";
  const { unavailable, list, revokedCount } = badges;
  const now = Date.now();
  const filtered = list.filter((badge) => connectedBadgeMatches(badge, now));
  const page = tablePage("connected", filtered);

  let body;
  if (unavailable) {
    body = '<div class="sub">Couldn\'t load agent badges. Connecting still works - mint a key under Connection key below.</div>';
  } else if (list.length === 0) {
    body = '<div class="sub">' +
      (revokedCount > 0
        ? "You have revoked every badge you connected. Mint a fresh one under Connection key below" +
          (member ? "." : ", or create one on the Scoped memory screen.")
        : "You haven't connected an agent yet. Mint a badge under Connection key below" +
          (member ? "." : ", or create one on the Scoped memory screen.")) +
      "</div>";
  } else {
    const rows = page.rows.map((badge) => {
      const id = esc(String(badge.id || ""));
      const reveal = badge.bearerRevealable === true && !badge.expired
        ? '<button class="btn btn--outline btn--sm" data-action="intg-reveal-badge" data-id="' +
          id + '">Reveal</button>'
        : '<button class="btn btn--outline btn--sm" disabled title="Rotate this legacy badge once to enable repeated reveal">Reveal unavailable</button>';
      return '<tr><td class="intg-connected-logo">' + logoTile(ctx, agentLogoFor(badge.actor)) + "</td>" +
      "<td><b>" + esc(String(badge.actor || "Unnamed agent")) + "</b></td>" +
      '<td class="mono subtle">' + esc(organizationScopeLabel(
        badge.namespace,
        ctx.organizationName,
        ctx.identity?.namespace,
      )) + "</td>" +
      "<td>" + badgeStatusPill(ctx, badge) + "</td>" +
      "<td>" + connectionCell(ctx, badge, now) + "</td>" +
      '<td><span class="row" style="gap:var(--s2);flex-wrap:nowrap">' + reveal +
        '<button class="btn btn--danger btn--sm" data-action="intg-revoke-badge" data-id="' +
        id + '">Revoke</button></span></td></tr>';
    }).join("");
    body = renderActiveTableFilters(ctx, "connected", CONNECTED_FILTER_SECTIONS) +
      (page.total === 0
        ? '<div class="intg-ledger-empty">No connected agents match these filters.</div>'
        : '<div class="tblwrap intg-ledger-table"><table data-grid-chrome="off"><thead><tr><th>Logo</th><th>Agent</th><th>Namespace</th><th>Badge</th><th>Connection</th><th></th></tr></thead>' +
          "<tbody>" + rows + "</tbody></table></div>" + renderTablePager(ctx, "connected", page)) +
      '<div class="hint" id="intg-connected-status" role="status" aria-live="polite"></div>';
  }

  return (
    '<section class="card intg-connected" aria-labelledby="connected-agents-title">' +
    '<div class="between intg-connected-head"><div><h3 id="connected-agents-title">Connected agents' +
    headingInfo("Connected agents", info) +
    "</h3></div>" +
    '<div class="intg-connected-actions">' +
    (!unavailable && list.length > 0 ? renderTableFilterMenu(ctx, "connected", CONNECTED_FILTER_SECTIONS) : "") +
    (member ? "" : '<button class="btn btn--ghost btn--sm" data-action="intg-manage-agents" aria-label="Manage agents in Scoped memory">Manage</button>') +
    "</div></div>" +
    body +
    "</section>"
  );
}

// ---------------------------------------------------------------------------
// Assigned badges — member-only recipient view over agent_key_handoffs.
// ---------------------------------------------------------------------------

/**
 * Organization-assigned badges are deliberately separate from Connected
 * agents: a pending handoff is not a credential yet, while a claimed handoff
 * is custody history rather than connection liveness. The bearer is minted by
 * the server only when the exact recipient claims it and is rendered once in
 * this card; every client recipe reads the same in-memory `mintedKey`.
 */
function assignedBadgesCard(ctx, handoffs, handoffsAvailable) {
  const esc = ctx.esc;
  const now = Date.now();
  const rows = handoffs.filter(Boolean);
  const filtered = rows.filter((entry) => assignedBadgeMatches(entry, now));
  const page = tablePage("assigned", filtered);
  const ready = rows.filter((entry) => assignmentState(entry, now) === "ready").length;
  const pill = !handoffsAvailable
    ? '<span class="pill pill--warn"><i class="dot"></i>Unavailable</span>'
    : ready > 0
      ? '<span class="pill pill--live"><i class="dot"></i>' + esc(String(ready)) + " ready</span>"
      : rows.length > 0
        ? '<span class="pill pill--ok"><i class="dot"></i>' + esc(String(rows.length)) +
          (rows.length === 1 ? " record" : " records") + "</span>"
        : '<span class="pill"><i class="dot"></i>No assignments</span>';

  const revealed = mintedKey && mintedKey.source === "assignment"
    ? mintedKeyPanel(ctx)
    : "";

  let body;
  if (!handoffsAvailable) {
    body = '<div class="intg-assigned-empty"><b>Assigned badges unavailable</b>' +
      '<div class="subtle">Refresh to try loading badges assigned to your account.</div></div>';
  } else if (rows.length === 0) {
    body = '<div class="intg-assigned-empty"><b>No badges have been assigned to you yet.</b>' +
      '<div class="subtle">An owner or admin can assign a member-scoped Assistant badge to this account.</div></div>';
  } else {
    const tableRows = page.rows.map((entry) => {
      const state = assignmentState(entry, now);
      const action = state === "ready"
        ? '<button class="btn btn--outline btn--sm" data-action="intg-claim-assigned-key" data-id="' +
          esc(String(entry.id || "")) + '">Reveal bearer</button>'
        : state === "claimed" && mintedKey && mintedKey.source === "assignment" &&
            mintedKey.handoffId === String(entry.id || "")
          ? '<span class="subtle">Ready for connection</span>'
          : '<span class="subtle">' + assignmentActionCopy(state) + "</span>";
      const access = entry.agentCanWrite === false ? "Read only" : "Read + write";
      const expiresAt = Date.parse(String(entry.expiresAt || ""));
      const expiry = !entry.expiresAt
        ? "Standing access"
        : Number.isFinite(expiresAt) && expiresAt <= now
          ? "Access period ended"
          : "Expires in " + formatUntil(entry.expiresAt);
      return '<tr><td class="intg-connected-logo">' + logoTile(ctx, agentLogoFor(entry.actor)) + "</td>" +
        "<td><b>" + esc(String(entry.actor || "Assigned agent")) + '</b><div class="subtle">' +
        esc(expiry) + "</div></td>" +
        '<td class="mono subtle">' + esc(organizationScopeLabel(
          entry.namespace,
          ctx.organizationName,
          ctx.identity?.namespace,
        )) + "</td>" +
        '<td><span class="tag">' + esc(access) + "</span></td>" +
        "<td>" + assignmentStatusPill(ctx, state) + "</td>" +
        '<td class="intg-assigned-row-action">' + action + "</td></tr>";
    }).join("");
    body = renderActiveTableFilters(ctx, "assigned", ASSIGNED_FILTER_SECTIONS) +
      (page.total === 0
        ? '<div class="intg-ledger-empty">No assigned badges match these filters.</div>'
        : '<div class="tblwrap intg-ledger-table"><table data-grid-chrome="off"><thead><tr><th>Logo</th><th>Agent</th><th>Scope</th>' +
          "<th>Access</th><th>Assignment</th><th></th></tr></thead><tbody>" + tableRows +
          "</tbody></table></div>" + renderTablePager(ctx, "assigned", page));
  }

  return (
    '<section class="card intg-assigned" aria-labelledby="assigned-badges-title">' +
    '<div class="between intg-assigned-head"><div><h3 id="assigned-badges-title">Badges assigned to you' +
    headingInfo(
      "Badges assigned to you",
      "Member-scoped Assistant badges assigned by your organization. Claim an assignment once, then reveal its bearer again from Connected agents whenever needed.",
    ) +
    '</h3><p>Claim a ready badge. Its bearer fills every connection recipe for 90 seconds and can be revealed again later.</p></div>' +
    '<div class="intg-connected-actions">' + pill +
    (handoffsAvailable && rows.length > 0 ? renderTableFilterMenu(ctx, "assigned", ASSIGNED_FILTER_SECTIONS) : "") +
    "</div></div>" +
    revealed + body +
    '<div class="hint" id="intg-assigned-status" role="status" aria-live="polite"></div>' +
    "</section>"
  );
}

function assignmentState(entry, now = Date.now()) {
  const status = String((entry && entry.status) || "").toLowerCase();
  if (status === "claimed") return "claimed";
  if (status === "revoked") return "revoked";
  if (status !== "pending") return "unavailable";
  const claimExpiresAt = Date.parse(String((entry && entry.claimExpiresAt) || ""));
  return Number.isFinite(claimExpiresAt) && claimExpiresAt > now ? "ready" : "expired";
}

function assignmentStatusPill(ctx, state) {
  if (state === "ready") return '<span class="pill pill--live"><i class="dot"></i>Ready</span>';
  if (state === "claimed") return '<span class="pill pill--ok"><i class="dot"></i>Claimed</span>';
  if (state === "revoked") return '<span class="pill pill--crit"><i class="dot"></i>Revoked</span>';
  if (state === "expired") return '<span class="pill pill--warn"><i class="dot"></i>Claim expired</span>';
  return '<span class="pill pill--warn"><i class="dot"></i>' + ctx.esc(state) + "</span>";
}

function assignmentActionCopy(state) {
  if (state === "claimed") return "Available under Connected agents";
  if (state === "revoked") return "Assignment withdrawn";
  if (state === "expired") return "Ask an admin to reassign";
  return "Not available";
}

function connectedBadgeMatches(badge, now) {
  const current = tableFilters.connected;
  const usedAt = lastUsedMs(badge);
  const connection = usedAt === 0
    ? "never"
    : now - usedAt <= ACTIVE_WINDOW_MS
      ? "active"
      : "seen";
  const badgeState = badge && badge.expired ? "expired" : "live";
  return (!current.connection || current.connection === connection) &&
    (!current.badge || current.badge === badgeState);
}

function assignedBadgeMatches(entry, now) {
  const current = tableFilters.assigned;
  const state = assignmentState(entry, now);
  const access = entry && entry.agentCanWrite === false ? "read" : "write";
  return (!current.assignment || current.assignment === state) &&
    (!current.access || current.access === access);
}

function tablePage(table, rows) {
  const pages = Math.max(1, Math.ceil(rows.length / CONNECTED_PAGE));
  const current = Math.min(Math.max(0, tablePages[table] || 0), pages - 1);
  tablePages[table] = current;
  const start = current * CONNECTED_PAGE;
  return {
    current,
    pages,
    start,
    total: rows.length,
    rows: rows.slice(start, start + CONNECTED_PAGE),
  };
}

function renderTablePager(ctx, table, page) {
  const esc = ctx.esc;
  const first = page.total === 0 ? 0 : page.start + 1;
  const last = page.start + page.rows.length;
  const pageButtons = Array.from({ length: page.pages }, (_, index) =>
    '<button type="button" class="usage-page' + (index === page.current ? " is-active" : "") +
    '" data-action="intg-table-page" data-table="' + table + '" data-page="' +
    esc(String(index)) + '"' + (index === page.current ? ' aria-current="page"' : "") + ">" +
    esc(String(index + 1)) + "</button>",
  ).join("");
  const step = (target, label, enabled, aria) =>
    '<button type="button" class="usage-page usage-page--step" data-action="intg-table-page" data-table="' +
    table + '" data-page="' + esc(String(target)) + '" aria-label="' + aria + '"' +
    (enabled ? "" : " disabled") + ">" + label + "</button>";
  return '<div class="usage-pager intg-table-pager"><span class="subtle usage-page-count">Showing ' +
    esc(String(first)) + "-" + esc(String(last)) + " of " + esc(String(page.total)) +
    '</span><span class="usage-page-nums">' +
    step(page.current - 1, "&lsaquo;", page.current > 0, "Previous page") + pageButtons +
    step(page.current + 1, "&rsaquo;", page.current + 1 < page.pages, "Next page") +
    "</span></div>";
}

function renderTableFilterMenu(ctx, table, sections) {
  const esc = ctx.esc;
  const current = tableFilters[table];
  const active = sections.filter((section) => current[section.field]).length;
  const badge = active > 0
    ? '<span class="usage-filter-badge" aria-hidden="true">' + esc(String(active)) + "</span>"
    : "";
  const id = "intg-" + table + "-filters";
  return '<span class="usage-filter intg-table-filter"><button type="button" ' +
    'class="halo-icon-control usage-filter-trigger intg-table-filter-trigger" popovertarget="' + id +
    '" aria-label="Filter ' + table + ' table" title="Filter">' + TABLE_FILTER_SVG + badge +
    '</button><div class="usage-filter-pop intg-table-filter-pop" id="' + id +
    '" popover aria-label="Filter ' + table + ' table">' +
    sections.map((section) => renderTableFilterSection(ctx, table, section)).join("") +
    "</div></span>";
}

function renderTableFilterSection(ctx, table, section) {
  const esc = ctx.esc;
  const current = tableFilters[table][section.field] || "";
  const options = section.options.map((option) => {
    const selected = current === option.value;
    return '<button type="button" class="usage-filter-option' + (selected ? " is-active" : "") +
      '" data-action="intg-table-filter" data-table="' + table + '" data-field="' +
      esc(section.field) + '" data-value="' + esc(option.value) + '"' +
      (selected ? ' aria-current="true"' : "") +
      '><span class="usage-filter-check" aria-hidden="true">' + (selected ? "✓" : "") +
      '</span><span class="usage-filter-option-label">' + esc(option.label) + "</span></button>";
  }).join("");
  return '<div class="usage-filter-group"><div class="usage-filter-pop-label">' +
    esc(section.label) + "</div>" + options + "</div>";
}

function renderActiveTableFilters(ctx, table, sections) {
  const esc = ctx.esc;
  const current = tableFilters[table];
  const chips = sections.flatMap((section) => {
    const value = current[section.field];
    if (!value) return [];
    const option = section.options.find((entry) => entry.value === value);
    return ['<button type="button" class="usage-active-filter" data-action="intg-table-filter" ' +
      'data-table="' + table + '" data-field="' + esc(section.field) + '" data-value="" ' +
      'aria-label="Clear the ' + esc(section.label.toLowerCase()) + ' filter">' +
      esc(section.label.toLowerCase() + ": " + (option ? option.label : value)) +
      '<span aria-hidden="true">✕</span></button>'];
  });
  if (chips.length === 0) return "";
  return '<div class="filter-strip usage-active-filters intg-active-filters">' + chips.join("") +
    '<button type="button" class="btn btn--sm btn--ghost" data-action="intg-table-filter-clear" ' +
    'data-table="' + table + '">Clear all</button></div>';
}

/** Name → brand logo, best-effort. CDN slugs verified to resolve, plus the
 * Hermes mark vendored under console assets (Nous Research ships no logo CDN
 * slug; the file is the official icon from hermes-agent.nousresearch.com).
 * OpenAI/OpenClaw marks exist in neither place — those fall back to the
 * generic agent glyph. */
const AGENT_LOGO_MATCHERS = [
  { pattern: /claude/i, logo: "https://cdn.simpleicons.org/claude", icon: "terminal" },
  { pattern: /herme/i, logo: "assets/marks/hermes.png", icon: "bot" },
  { pattern: /cursor/i, logo: "https://cdn.simpleicons.org/cursor", icon: "ide" },
  { pattern: /cline/i, logo: "https://cdn.simpleicons.org/cline", icon: "ide" },
  { pattern: /gemini|antigravity/i, logo: "https://cdn.simpleicons.org/googlegemini", icon: "terminal" },
  { pattern: /vs\s*code|vscode/i, logo: "https://cdn.simpleicons.org/vscodium", icon: "ide" },
];

function agentLogoFor(actor) {
  const name = String(actor || "");
  return AGENT_LOGO_MATCHERS.find((matcher) => matcher.pattern.test(name)) || { logo: "", icon: "bot" };
}

/** Same Live/Expired/Revoked vocabulary as the s3 credentials table. */
function badgeStatusPill(ctx, badge) {
  const value = String((badge && badge.status) || "").toLowerCase();
  if (value === "revoked") return '<span class="pill pill--crit"><i class="dot"></i>Revoked</span>';
  if (badge && badge.expired) return '<span class="pill pill--warn"><i class="dot"></i>Expired</span>';
  if (value === "active" || value === "") return '<span class="pill pill--live"><i class="dot"></i>Live</span>';
  return '<span class="pill pill--warn"><i class="dot"></i>' + ctx.esc(value) + "</span>";
}

/** The activity half: Active inside the window, relative time after, honest
 * "Never connected" for a badge no client has presented yet. */
function connectionCell(ctx, badge, now) {
  const time = lastUsedMs(badge);
  if (!time) return '<span class="subtle">Never connected</span>';
  if (now - time <= ACTIVE_WINDOW_MS) return '<span class="pill pill--live"><i class="dot"></i>Active</span>';
  return '<span class="subtle">Last seen ' + ctx.esc(formatWhen(badge.lastUsed)) + "</span>";
}

/** Human "time ago" from an ISO timestamp (same shape as s6). */
function formatWhen(iso) {
  const time = Date.parse(String(iso));
  if (!Number.isFinite(time)) return String(iso);
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return minutes + (minutes === 1 ? " minute ago" : " minutes ago");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + (hours === 1 ? " hour ago" : " hours ago");
  const days = Math.floor(hours / 24);
  return days + (days === 1 ? " day ago" : " days ago");
}

/** Human duration until a future ISO timestamp. */
function formatUntil(iso) {
  const time = Date.parse(String(iso));
  if (!Number.isFinite(time)) return String(iso);
  const minutes = Math.max(0, Math.ceil((time - Date.now()) / 60000));
  if (minutes < 1) return "the reveal window closes";
  if (minutes < 60) return minutes + (minutes === 1 ? " minute" : " minutes");
  const hours = Math.ceil(minutes / 60);
  if (hours < 24) return hours + (hours === 1 ? " hour" : " hours");
  const days = Math.ceil(hours / 24);
  return days + (days === 1 ? " day" : " days");
}

async function safeGet(ctx, path) {
  try {
    return await ctx.api.get(path);
  } catch {
    return null;
  }
}

function arrayFrom(value, key) {
  if (Array.isArray(value)) return value;
  return Array.isArray(value && value[key]) ? value[key] : [];
}

function mintedKeyPanel(ctx) {
  if (!mintedKey) return "";
  const esc = ctx.esc;
  const revealed = mintedKey.revealed === true;
  const mintedSpec = keyTypeForPlaintext(mintedKey.plaintext);
  const mintedType = '<span class="badge badge--role">' +
    esc((mintedSpec && mintedSpec.label) || mintedKey.label || "Assistant") + "</span>";
  const label = mintedKey.source === "assignment" ? "Bearer ready" : "Key ready";
  return '<div class="intg-minted"><div class="between"><b>' + mintedType + " " + label + "</b>" +
    '<span class="pill pill--warn"><i class="dot"></i>90s</span></div>' +
    '<div class="snippet" data-minted-key tabindex="-1" role="status" aria-live="polite" aria-label="Bearer token ' + (revealed ? "revealed" : "hidden") + '">' +
    (revealed ? esc(mintedKey.plaintext) : '<span aria-hidden="true">' + BEARER_MASK + "</span>") + "</div>" +
    '<div class="row" style="margin-top:var(--s3)">' +
    '<button class="btn btn--outline btn--sm" data-action="intg-toggle-key-visibility" aria-pressed="' +
    String(revealed) + '">' + (revealed ? "Hide bearer" : "Reveal bearer") + "</button>" +
    '<button class="btn btn--primary btn--sm" data-action="intg-copy-key">Copy bearer</button>' +
    '<button class="btn btn--ghost btn--sm" data-action="intg-clear-key">Clear now</button>' +
    '<span class="subtle" id="intg-key-status" role="status"></span></div></div>';
}

function keyCard(ctx) {
  const esc = ctx.esc;
  const canWrite = canMutate(ctx);
  const member = isMember(ctx);
  const namespace = (ctx.identity && ctx.identity.namespace) || "";
  const hasKey = Boolean(keyValue());
  const minted = mintedKey && mintedKey.source !== "assignment" ? mintedKeyPanel(ctx) : "";

  const mintForm = canWrite
    ? '<div class="row intg-mint" style="align-items:flex-end;flex-wrap:wrap">' +
      '<div class="field" style="margin:0;flex:1;min-width:180px"><label for="intg-actor">Agent name</label>' +
      '<input class="input" id="intg-actor" value="coding-agent" autocomplete="off"></div>' +
      '<div class="field" style="margin:0;min-width:170px"><label for="intg-ns">Namespace</label>' +
      '<input class="input mono" id="intg-ns" value="' + esc(namespace) + '" placeholder="acme/engineering" autocomplete="off"' +
      (member ? " readonly aria-readonly=\"true\"" : "") + "></div>" +
      '<button class="btn btn--solid" data-action="intg-mint">Mint Assistant key</button></div>' +
        '<div class="hint" id="intg-mint-status" role="status" aria-live="polite">' +
      (namespace === "" ? "Agents live in a namespace: name one inside your organization, e.g. <span class=\"mono\">acme</span>." : "") +
      "</div>"
    : '<div class="sub">Read-only. Owner or admin required.</div>';
  return (
    '<div class="intg-keycard"><details class="compact-disclosure intg-key-disclosure"' +
    (mintedKey ? " open" : "") + '><summary>Connection key' +
    (hasKey ? ' <span class="pill pill--ok"><i class="dot"></i>Ready</span>' : "") +
    '</summary><div class="compact-disclosure__body intg-key-disclosure-body">' +
    minted +
    mintForm +
    '<div class="row" style="margin-top:var(--s3);flex-wrap:wrap;align-items:flex-end">' +
    '<div class="field" style="margin:0;flex:1;min-width:220px"><label for="intg-manual-key">Existing key</label>' +
    '<input class="input mono" id="intg-manual-key" type="' + (manualKeyRevealed ? "text" : "password") +
    '" placeholder="paste key" autocomplete="off" data-input-action="intg-manual-key" value="' + esc(manualKey) + '"></div>' +
    '<button class="btn btn--outline btn--sm" data-action="intg-toggle-manual-key-visibility" aria-controls="intg-manual-key" aria-pressed="' +
    String(manualKeyRevealed) + '">' + (manualKeyRevealed ? "Hide bearer" : "Reveal bearer") + "</button></div>" +
    '<div class="subtle" id="intg-manual-type" role="status">' + esc(manualTypeText(manualKey)) + "</div></div></details></div>"
  );
}

/** Brand logo tile: CDN image over a glyph fallback (the shared stage error
 * listener flips data-logo-kind when the image fails - same contract as S6). */
function logoTile(ctx, entry) {
  const esc = ctx.esc;
  const glyph = iconSvg(entry.icon);
  if (!entry.logo) {
    return '<span class="source-logo intg-logo" data-logo-kind="glyph" aria-hidden="true">' + glyph + "</span>";
  }
  return (
    '<span class="source-logo intg-logo" data-logo-kind="image" data-logo-fallback-kind="glyph" aria-hidden="true">' +
    '<span class="source-logo-fallback">' + glyph + "</span>" +
    '<img class="source-logo-image" data-connector-logo-image src="' + esc(entry.logo) +
    '" alt="" decoding="async" referrerpolicy="no-referrer"></span>'
  );
}

function card(ctx, entry) {
  const esc = ctx.esc;
  return (
    '<button class="intg-card" data-action="intg-open" data-id="' + esc(entry.id) +
    '" aria-label="Connect ' + esc(entry.name) + '">' +
    logoTile(ctx, entry) +
    '<span class="intg-card-body"><span class="intg-card-title">' + esc(entry.name) +
    "<em>" + esc(entry.kind) + "</em></span></span>" +
    '<span class="intg-card-cta">Connect</span></button>'
  );
}

function sourcesCard(ctx) {
  return (
    '<button class="intg-card" data-action="intg-open-sources" aria-label="Open Knowledge bases">' +
    logoTile(ctx, { icon: "db" }) +
    '<span class="intg-card-body"><span class="intg-card-title">Knowledge bases<em>Connectors</em></span></span>' +
    '<span class="intg-card-cta">Open</span></button>'
  );
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------

function modalHtml(ctx, entry) {
  const esc = ctx.esc;
  const steps = entry.build(baseUrl(), keyOrPlaceholder(), ctx);
  const placeholderNote = keyValue()
    ? ""
    : '<div class="intg-placeholder-note">Snippets show <span class="mono">' + esc(KEY_PLACEHOLDER) +
      "</span>. Open Connection key, mint or paste a key, then reopen this client.</div>";
  const stepsHtml = steps
    .map((step, i) => {
      const copyBtn =
        step.copy === false || !step.code
          ? ""
          : '<button class="btn btn--outline btn--sm" data-action="intg-copy-step" data-id="' +
            esc(entry.id) + '" data-step="' + i + '">Copy</button>';
      const codeHtml = step.code ? '<div class="snippet">' + esc(step.code) + "</div>" : "";
      return (
        '<li><div class="between"><b>' + esc(step.title) + "</b>" + copyBtn + "</div>" +
        (step.note ? '<div class="intg-step-note">' + esc(step.note) + "</div>" : "") +
        codeHtml + "</li>"
      );
    })
    .join("");
  const docsLink = entry.docs
    ? '<a class="btn btn--ghost btn--sm" href="' + esc(entry.docs) + '" target="_blank" rel="noreferrer noopener">Vendor docs</a>'
    : "";
  return (
    '<button class="source-wizard-backdrop" data-action="intg-close" aria-label="Close"></button>' +
    '<div class="source-wizard-dialog intg-dialog" role="dialog" aria-modal="true" aria-label="Set up ' + esc(entry.name) + '">' +
    '<div class="between source-wizard-head"><div class="row" style="align-items:center">' + logoTile(ctx, entry) +
    '<div><div class="eyebrow">' + esc(entry.vendor) + " · " + esc(entry.kind) + "</div>" +
    "<h3>Set up " + esc(entry.name) + "</h3></div></div>" +
    '<div class="row">' + docsLink +
    '<button class="source-wizard-close halo-icon-control" data-action="intg-close" data-wizard-focus aria-label="Return to integrations"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Close</span></button></div></div>' +
    placeholderNote +
    '<ol class="intg-steps">' + stepsHtml + "</ol></div>"
  );
}

function openModal(ctx, id) {
  const entry = findEntry(id);
  if (!entry) return;
  const modal = document.getElementById("integration-modal");
  if (!modal) return;
  modal.innerHTML = modalHtml(ctx, entry);
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("source-modal-open");
  const focus = modal.querySelector("[data-wizard-focus]");
  if (focus) focus.focus();
  keydownDoc = document;
  keydownHandler = (ev) => {
    if (ev.key === "Escape") closeModal(document);
  };
  document.addEventListener("keydown", keydownHandler);
}

function closeModal(doc) {
  const modal = doc && doc.getElementById ? doc.getElementById("integration-modal") : null;
  if (modal) {
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML = "";
  }
  if (doc && doc.body) doc.body.classList.remove("source-modal-open");
  if (keydownDoc && keydownHandler) keydownDoc.removeEventListener("keydown", keydownHandler);
  keydownDoc = null;
  keydownHandler = null;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export const actions = {
  "intg-open"(ctx, el) {
    openModal(ctx, el.getAttribute("data-id"));
  },
  "intg-close"() {
    closeModal(document);
  },
  async "intg-open-sources"(ctx) {
    await ctx.go("s6");
  },

  async "intg-manage-agents"(ctx) {
    await ctx.go("s3");
  },

  async "intg-table-filter"(ctx, el) {
    const table = el.getAttribute("data-table");
    const field = el.getAttribute("data-field");
    const value = el.getAttribute("data-value") || "";
    const sections = table === "connected"
      ? CONNECTED_FILTER_SECTIONS
      : table === "assigned"
        ? ASSIGNED_FILTER_SECTIONS
        : null;
    const section = sections && sections.find((entry) => entry.field === field);
    if (!section || !section.options.some((option) => option.value === value)) return;
    tableFilters[table] = { ...tableFilters[table], [field]: value };
    tablePages[table] = 0;
    await refreshS14(ctx);
  },

  async "intg-table-filter-clear"(ctx, el) {
    const table = el.getAttribute("data-table");
    if (table === "connected") tableFilters.connected = { connection: "", badge: "" };
    else if (table === "assigned") tableFilters.assigned = { assignment: "", access: "" };
    else return;
    tablePages[table] = 0;
    await refreshS14(ctx);
  },

  async "intg-table-page"(ctx, el) {
    const table = el.getAttribute("data-table");
    const page = Number(el.getAttribute("data-page"));
    if ((table !== "connected" && table !== "assigned") || !Number.isInteger(page) || page < 0) return;
    tablePages[table] = page;
    await refreshS14(ctx);
  },

  // Inline revoke for a live badge - same DELETE path as the s3 credentials
  // table; the card re-renders without the dead credential.
  async "intg-revoke-badge"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".intg-screen") || document;
    const status = root.querySelector("#intg-connected-status");
    setBusy(el, true, "Revoking…");
    try {
      await ctx.api.del("/v1/admin/keys/" + encodeURIComponent(id));
      await refreshS14(ctx);
    } catch (err) {
      setText(status, "Revoke failed: " + msgOf(err));
      setBusy(el, false, "Revoke");
    }
  },

  async "intg-reveal-badge"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".intg-screen") || document;
    const status = root.querySelector("#intg-connected-status");
    setBusy(el, true, "Revealing…");
    try {
      const response = await ctx.api.post(
        "/v1/admin/keys/" + encodeURIComponent(id) + "/reveal",
        {},
      );
      if (!response || !response.plaintext) throw new Error("server returned no key");
      mintedKey = {
        plaintext: response.plaintext,
        actor: response.record && response.record.actor || "Agent",
        label: response.record && response.record.keyTypeLabel || "Assistant",
        source: "stored",
        keyId: id,
        revealed: true,
      };
      scheduleMintClear(ctx);
      await refreshS14(ctx);
      focusRevealedBearer();
    } catch (err) {
      setText(status, "Reveal failed: " + msgOf(err));
      setBusy(el, false, "Reveal");
    }
  },

  async "intg-copy-endpoint"(ctx, el) {
    return copyText(mcpUrl(), el, "Copy URL");
  },

  async "intg-copy-step"(ctx, el) {
    const entry = findEntry(el.getAttribute("data-id"));
    const index = Number(el.getAttribute("data-step"));
    if (!entry) return false;
    const steps = entry.build(baseUrl(), keyOrPlaceholder(), ctx);
    const step = steps[index];
    if (!step || !step.code) return false;
    return copyText(step.code, el, "Copy");
  },

  async "intg-mint"(ctx, el) {
    const root = el.closest(".intg-screen") || document;
    const status = root.querySelector("#intg-mint-status");
    const actorInput = root.querySelector("#intg-actor");
    const actor = actorInput && actorInput.value ? actorInput.value.trim() : "";
    if (!actor) {
      setText(status, "Give the agent a name first.");
      return;
    }
    const nsInput = root.querySelector("#intg-ns");
    const namespace = isMember(ctx)
      ? String((ctx.identity && ctx.identity.namespace) || "").trim()
      : nsInput && nsInput.value ? nsInput.value.trim() : "";
    if (!namespace) {
      setText(status, "Agents live in a namespace: name one, e.g. acme or acme/support.");
      return;
    }
    setBusy(el, true, "Minting…");
    setText(status, "Issuing an Assistant key bound to your namespace…");
    try {
      // E58: typed issuance - the server maps type→role and audits (E52/D4).
      const response = await ctx.api.post("/v1/admin/keys", {
        type: "assistant",
        namespace,
        actor,
      });
      if (!response || !response.plaintext) throw new Error("server returned no key");
      mintedKey = {
        plaintext: response.plaintext,
        actor,
        label: (response.record && response.record.keyTypeLabel) || "Assistant",
        source: "mint",
        revealed: false,
      };
      scheduleMintClear(ctx);
      await refreshS14(ctx);
    } catch (err) {
      setText(status, "Mint failed: " + msgOf(err));
      setBusy(el, false, "Mint Assistant key");
    }
  },

  async "intg-claim-assigned-key"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    setBusy(el, true, "Revealing…");
    try {
      const response = await ctx.api.post(
        "/v1/admin/key-handoffs/" + encodeURIComponent(id) + "/claim",
        {},
      );
      if (!response || !response.plaintext) throw new Error("server returned no key");
      mintedKey = {
        plaintext: response.plaintext,
        actor: response.record && response.record.actor || "Assigned agent",
        label: response.record && response.record.keyTypeLabel || "Assistant",
        source: "assignment",
        handoffId: id,
        // The claim button itself is the member's explicit reveal request.
        revealed: true,
      };
      scheduleMintClear(ctx);
      await refreshS14(ctx);
    } catch (err) {
      setBusy(el, false, "Reveal key");
      el.textContent = "Reveal failed";
      el.setAttribute("title", msgOf(err));
    }
  },

  async "intg-copy-key"(ctx, el) {
    const root = el.closest(".intg-screen") || document;
    const status = root.querySelector("#intg-key-status");
    try {
      await copyRaw(mintedKey ? mintedKey.plaintext : "");
      setText(status, "Copied.");
      return true;
    } catch {
      setText(status, "Copy failed. Select it manually.");
      return false;
    }
  },

  "intg-toggle-key-visibility"(ctx, el) {
    if (!mintedKey) return;
    mintedKey.revealed = mintedKey.revealed !== true;
    const root = el.closest(".intg-screen") || document;
    const node = root.querySelector("[data-minted-key]");
    if (node) {
      node.textContent = mintedKey.revealed ? mintedKey.plaintext : BEARER_MASK;
      node.setAttribute("aria-label", "Bearer token " + (mintedKey.revealed ? "revealed" : "hidden"));
    }
    el.textContent = mintedKey.revealed ? "Hide bearer" : "Reveal bearer";
    el.setAttribute("aria-pressed", String(mintedKey.revealed));
  },

  async "intg-clear-key"(ctx) {
    mintedKey = null;
    if (mintClearTimer) {
      clearTimeout(mintClearTimer);
      mintClearTimer = null;
    }
    await refreshS14(ctx);
  },

  // data-input-action shares the actions map (app.js dispatches both there).
  "intg-manual-key"(ctx, el) {
    manualKey = el.value || "";
    // E58: live type readout from the prefix - textContent only, never HTML.
    const root = el.closest(".intg-screen") || document;
    if (!manualKey) {
      manualKeyRevealed = false;
      el.type = "password";
      const toggle = root.querySelector('[data-action="intg-toggle-manual-key-visibility"]');
      if (toggle) {
        toggle.textContent = "Reveal bearer";
        toggle.setAttribute("aria-pressed", "false");
      }
    }
    setText(root.querySelector("#intg-manual-type"), manualTypeText(manualKey));
  },

  "intg-toggle-manual-key-visibility"(ctx, el) {
    manualKeyRevealed = !manualKeyRevealed;
    const root = el.closest(".intg-screen") || document;
    const input = root.querySelector("#intg-manual-key");
    if (input) input.type = manualKeyRevealed ? "text" : "password";
    el.textContent = manualKeyRevealed ? "Hide bearer" : "Reveal bearer";
    el.setAttribute("aria-pressed", String(manualKeyRevealed));
  },
};

function scheduleMintClear(ctx) {
  if (mintClearTimer) clearTimeout(mintClearTimer);
  mintClearTimer = setTimeout(() => {
    mintedKey = null;
    mintClearTimer = null;
    // Only refresh if the user is still on this screen. Routes use canonical
    // public hashes (for example #agentconnections), not internal screen IDs.
    if (typeof window !== "undefined" && screenIdFromHash(window.location.hash) === "s14") {
      void refreshS14(ctx);
    }
  }, 90_000);
}

function refreshS14(ctx) {
  return typeof ctx.refresh === "function" ? ctx.refresh() : ctx.go("s14");
}

function focusRevealedBearer() {
  if (typeof document === "undefined") return;
  const node = document.querySelector("[data-minted-key]");
  if (!node) return;
  if (typeof node.scrollIntoView === "function") {
    node.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  if (typeof node.focus === "function") node.focus({ preventScroll: true });
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin" || role === "member";
}

function isMember(ctx) {
  return Boolean(ctx.identity && ctx.identity.role === "member");
}

async function copyRaw(text) {
  await navigator.clipboard.writeText(text || "");
}

async function copyText(text, el, restoreLabel) {
  try {
    await copyRaw(text);
    if (el) {
      el.textContent = "Copied";
      setTimeout(() => {
        el.textContent = restoreLabel;
      }, 1500);
    }
    return true;
  } catch {
    if (el) el.textContent = "Copy failed";
    return false;
  }
}

function setText(node, text) {
  if (node) node.textContent = text;
}

function setBusy(el, busy, label) {
  if (!el) return;
  el.disabled = busy;
  el.textContent = label;
}

function msgOf(err) {
  return err && err.message ? String(err.message) : "request failed";
}

function iconSvg(name) {
  const bodies = {
    terminal:
      '<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7 9l3 3-3 3M12.5 15H17" stroke-linecap="round" stroke-linejoin="round"/>',
    ide:
      '<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M9 4v16M3 9h6"/><path d="M13 10l2.5 2.5L13 15" stroke-linecap="round" stroke-linejoin="round"/>',
    desktop:
      '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4" stroke-linecap="round"/>',
    chat:
      '<path d="M4 6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H9l-5 4z" stroke-linejoin="round"/><path d="M8 9h8M8 12h5" stroke-linecap="round"/>',
    link:
      '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.6l-1.2 1.2M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.6l1.2-1.2" stroke-linecap="round"/>',
    bot:
      '<rect x="5" y="8" width="14" height="10" rx="3"/><path d="M12 8V4M9 13h.01M15 13h.01" stroke-linecap="round" stroke-linejoin="round"/>',
    db:
      '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6"/><path d="M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6"/>',
  };
  return (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">' +
    (bodies[name] || bodies.link) +
    "</svg>"
  );
}
import { headingInfo } from "../heading-info.js";
