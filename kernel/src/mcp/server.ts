/**
 * HaloMem MCP stdio server (M1, D9).
 *
 * Local-dev transport: resolves `HALOMEM_API_KEY` ONCE at boot to a
 * server-side Identity (CONTRACTS-M1.md). Missing/invalid/revoked key → the
 * server still starts, but every tool returns a clear error telling the
 * operator to set a valid key. Tool schemas have no namespace/actor params —
 * definitions live in ./tools.ts, shared verbatim with the HTTP /mcp
 * transport.
 *
 * The kernel boots lazily on first use so importing this module (e.g. in
 * tests) starts neither the kernel nor the stdio transport. When executed
 * directly (`tsx src/mcp/server.ts` or the `halomem` bin), it boots and
 * connects at load.
 */
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { pathToFileURL } from "node:url";

import { Kernel } from "../kernel.js";
import type { KernelConfig } from "../config.js";
import type { Identity } from "../types.js";
import { buildMcpServer } from "./tools.js";

const AGENT_ID = "mcp";

// ---------------------------------------------------------------------------
// Lazily-booted singleton kernel
// ---------------------------------------------------------------------------

let kernelPromise: Promise<Kernel> | null = null;
let kernelOverrides: Partial<KernelConfig> = {};

/** Optional pre-boot configuration hook (must be called before first tool call). */
export function configureKernel(overrides: Partial<KernelConfig>): void {
  kernelOverrides = overrides;
}

export function getKernel(): Promise<Kernel> {
  kernelPromise ??= Kernel.boot(kernelOverrides);
  return kernelPromise;
}

// ---------------------------------------------------------------------------
// Boot-time identity resolution (stdio: env key, resolved once)
// ---------------------------------------------------------------------------

async function resolveBootIdentity(kernel: Kernel): Promise<Identity | null> {
  const plaintext = process.env.HALOMEM_API_KEY ?? "";
  if (!plaintext) {
    console.error(
      "halomem: HALOMEM_API_KEY is not set - server starts, but every tool will return an error",
    );
    return null;
  }
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) {
    console.error(
      "halomem: HALOMEM_API_KEY is invalid or revoked - server starts, but every tool will return an error",
    );
  }
  return identity;
}

// ---------------------------------------------------------------------------
// Direct execution: boot kernel, resolve identity, connect stdio transport.
// ---------------------------------------------------------------------------

export async function startMcpServer(): Promise<void> {
  const kernel = await getKernel();
  const identity = await resolveBootIdentity(kernel);
  serveStdio(() => buildMcpServer(kernel, identity, AGENT_ID), {
    legacy: "serve",
    onerror(error) {
      console.error("halomem MCP stdio error:", error.name);
    },
  });
  // stdout carries the MCP protocol; diagnostics go to stderr only.
  console.error(
    identity
      ? `halomem MCP server listening on stdio (namespace=${identity.namespace} actor=${identity.actor} role=${identity.role})`
      : "halomem MCP server listening on stdio WITHOUT an identity",
  );
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  startMcpServer().catch((err) => {
    console.error("halomem MCP server failed to start:", err);
    process.exit(1);
  });
}
