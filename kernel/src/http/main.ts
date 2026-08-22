/**
 * HaloMem HTTP service entrypoint — `npm run serve`.
 *
 * Boots the full kernel (migrations included), wires the real dependencies
 * into module B's transport, and listens on HALOMEM_PORT (default 8787).
 * Structured JSON startup log goes to stderr (module F logger).
 */

import { fileURLToPath } from "node:url";
import { Kernel } from "../kernel.js";
import { createHttpServer } from "./server.js";
import { buildHttpDeps } from "./adapter.js";
import { createLogger } from "../metrics/index.js";

const log = createLogger({ fields: { mod: "http-main" } });

async function main(): Promise<void> {
  const kernel = await Kernel.boot();
  // M5: the control-room static dir (<kernel>/console) + cookie security. On
  // localhost over http, Secure cookies would never be sent, so derive it from
  // HALOMEM_SECURE_COOKIES (opt-in behind TLS). The dir may be overridden via
  // HALOMEM_CONSOLE_DIR; it defaults to the packaged console/ two levels up.
  const consoleDir =
    process.env.HALOMEM_CONSOLE_DIR ??
    fileURLToPath(new URL("../../console", import.meta.url));
  const secureCookies = process.env.HALOMEM_SECURE_COOKIES === "true";
  const server = createHttpServer(
    buildHttpDeps(kernel, {
      consoleDir,
      secureCookies,
      publicUrl: kernel.config.channelPublicUrl || undefined,
    }),
  );

  const port = Number(process.env.HALOMEM_PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid HALOMEM_PORT '${process.env.HALOMEM_PORT}'`);
  }
  const bound = await server.start(port);

  log.info("halomem http server listening", {
    port: bound,
    embedder: kernel.embedder.name,
    embedDim: kernel.embedder.dim,
    llm: kernel.llm.name,
    database: kernel.config.databaseUrl ? "postgres" : "pglite",
    knowledgeDir: kernel.config.knowledgeDir,
  });

  let stopping = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    log.info("shutting down", { signal });
    try {
      await server.stop();
      await kernel.close();
      process.exit(0);
    } catch (err) {
      log.error("shutdown failed", { error: err instanceof Error ? err.message : String(err) });
      process.exit(1);
    }
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((err) => {
  log.error("halomem http server failed to start", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
