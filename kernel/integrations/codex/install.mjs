#!/usr/bin/env node
// Wire the OpenAI Codex CLI to a HaloMem deployment's MCP endpoint.
//
// Idempotently merges an [mcp_servers.halomem] block into ~/.codex/config.toml
// (or $CODEX_HOME/config.toml) using bearer_token_env_var, so the key lives in
// the environment — never in the file.
//
//   node install.mjs --url https://halomem.example.com
//   node install.mjs --url https://halomem.example.com --remove

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const BLOCK_HEADER = "[mcp_servers.halomem]";
const ENV_VAR = "HALOMEM_API_KEY";

function fail(message) {
  console.error("halomem: " + message);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { url: "", remove: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--url") args.url = argv[++i] || "";
    else if (argv[i] === "--remove") args.remove = true;
    else fail("unknown argument '" + argv[i] + "' (expected --url <base-url> [--remove])");
  }
  return args;
}

function stripBlock(toml) {
  // Remove the halomem table: from its header to the next table header or EOF.
  const lines = toml.split("\n");
  const out = [];
  let skipping = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === BLOCK_HEADER) {
      skipping = true;
      continue;
    }
    if (skipping && trimmed.startsWith("[")) skipping = false;
    if (!skipping) out.push(line);
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n");
}

const args = parseArgs(process.argv.slice(2));
if (!args.remove) {
  if (!args.url) fail("--url is required, e.g. --url https://halomem.example.com");
  if (!/^https?:\/\//.test(args.url)) fail("--url must start with http:// or https://");
}
const base = args.url.replace(/\/+$/, "");

const codexHome = process.env.CODEX_HOME || join(homedir(), ".codex");
const configPath = join(codexHome, "config.toml");

let existing = "";
try {
  existing = await readFile(configPath, "utf8");
} catch {
  // No config yet — we'll create it.
}

const had = existing.includes(BLOCK_HEADER);
let next = had ? stripBlock(existing) : existing;

if (!args.remove) {
  const block =
    BLOCK_HEADER + "\n" +
    'url = "' + base + '/mcp"\n' +
    'bearer_token_env_var = "' + ENV_VAR + '"\n';
  next = (next.trimEnd() + "\n\n" + block).replace(/^\n+/, "");
}

await mkdir(codexHome, { recursive: true });
await writeFile(configPath, next.trimEnd() + "\n", "utf8");

if (args.remove) {
  console.log(had ? "halomem: removed from " + configPath : "halomem: nothing to remove in " + configPath);
} else {
  console.log("halomem: " + (had ? "updated" : "added") + " [mcp_servers.halomem] in " + configPath);
  console.log("halomem: endpoint " + base + "/mcp");
  console.log("");
  console.log("Next: make sure the key is in the environment that launches codex:");
  console.log('  export ' + ENV_VAR + '="<your agent badge key>"');
  console.log("Then verify with: codex mcp list");
}
