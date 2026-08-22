# Halofy agent integrations

Client-side wiring for coding agents. Everything here talks to the kernel's
existing surfaces — the Streamable HTTP MCP endpoint at `/mcp` and the
`/v1/mem/*` syscalls — with a bearer agent badge. Identity is resolved
server-side from the key (D9); every call is audited (D4); captures go through
the governed write path (D10). The console's **Integrations** screen (S14)
generates ready-to-paste setup for each client from these packages.

## Claude Code plugin (`claude-code/`)

A Claude Code plugin distributed from this directory (it doubles as a plugin
marketplace):

```bash
export HALOMEM_URL="https://your-halomem.example.com"
export HALOMEM_API_KEY="<agent badge key>"

claude plugin marketplace add /path/to/halomem/kernel/integrations
claude plugin install halomem@halomem-integrations
```

What it does:

- **SessionStart** — `scripts/session-start.mjs` searches memory for the
  project's conventions/decisions and injects the top hits as
  `additionalContext`.
- **Stop** — `scripts/session-end.mjs` reads the session transcript and writes
  it through `/v1/mem/write`; the kernel extracts durable facts, verifies,
  dedupes, and supersedes (never overwrites — D7).
- **MCP tools** — `.mcp.json` registers the `halomem` server, so
  `mem_search` / `mem_write` / `mem_read` are callable mid-session.

Both hooks fail open: no env vars, unreachable kernel, or a non-OK response →
exit 0, no output, the agent keeps working (brownout, never hard-fail).

## Codex CLI (`codex/`)

Codex speaks Streamable HTTP MCP natively — no bridge process. The installer
merges the server into `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`)
idempotently:

```bash
node kernel/integrations/codex/install.mjs --url https://your-halomem.example.com
export HALOMEM_API_KEY="<agent badge key>"
codex mcp list   # verify
```

`--remove` takes the block back out. The key is referenced via
`bearer_token_env_var` and never written to disk.

## Other clients

Cursor, VS Code, Cline, Gemini CLI, Antigravity, Claude Desktop, Hermes Agents,
OpenClaw, and generic MCP clients need only a config snippet — the console
Integrations screen
generates each client's exact dialect (field names differ per client) with
your deployment URL and a freshly minted agent badge.

## Obsidian (`halomem-sync/`)

The Halofy Sync community-plugin package is the local bridge for the
`obsidian_vault` source. An owner/admin creates a pairing from **Sources →
Obsidian**, then pastes the one-time bundle into the plugin settings. The
plugin sends selected Markdown notes, bounded frontmatter, and outgoing links
through the signed `/v1/ingest/obsidian/:sourceId` endpoint.

The integration is one-way and does not require an Obsidian account or Sync
subscription. See [`halomem-sync/README.md`](halomem-sync/README.md) for the
development build and manual-install steps.
