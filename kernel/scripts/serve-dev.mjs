#!/usr/bin/env node
import { fileURLToPath } from "node:url";

/**
 * Dev-only launcher: defaults PGlite to an ignored repository-local data
 * directory before booting the HTTP server, so local accounts and seeded data
 * survive restarts. Pure JS env-set avoids shell-specific `set VAR=` syntax.
 */

try {
  process.loadEnvFile(new URL("../.env", import.meta.url));
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

// Repo-local (kernel/data is gitignored) so the seeded state survives temp
// cleanups; scripts/seed-from-prod.mjs writes into this same directory.
process.env.HALOMEM_DATA_DIR ??=
  fileURLToPath(new URL("../data/pglite-local", import.meta.url));

// A durable data dir refuses an ephemeral source-config KEK, so connecting a
// source fails without one. Dev keys are never hardcoded here: run
// `npm run env:init` once to generate them into the git-ignored .env, which
// is loaded above. Refuse to start rather than fall back to a shared secret.
for (const name of ["HALOMEM_SOURCE_CONFIG_KEK", "HALOMEM_MODEL_CREDENTIAL_KEK"]) {
  if (!process.env[name]) {
    process.stderr.write(
      `serve:dev: ${name} is not set. Run \`npm run env:init\` to generate local dev secrets into kernel/.env, then retry.\n`,
    );
    process.exit(1);
  }
}

await import("../src/http/main.ts");
