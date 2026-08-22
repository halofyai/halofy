import { randomBytes, generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs/promises";

const target = new URL("../.env", import.meta.url);
const { privateKey } = generateKeyPairSync("ed25519");
const signingKey = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
const lines = [
  "# Generated for local self-hosting. Store production values in a secret manager.",
  `POSTGRES_PASSWORD=${randomBytes(24).toString("base64url")}`,
  `HALOMEM_BOOTSTRAP_TOKEN=${randomBytes(32).toString("base64url")}`,
  `HALOMEM_SIGNING_KEY=${signingKey}`,
  `HALOMEM_COLD_KEK=${randomBytes(32).toString("base64")}`,
  `HALOMEM_SOURCE_CONFIG_KEK=${randomBytes(32).toString("base64")}`,
  `HALOMEM_MODEL_CREDENTIAL_KEK=${randomBytes(32).toString("base64")}`,
  "HALOMEM_NANGO_CONNECT_API_KEY=",
  "HALOMEM_NANGO_PROXY_API_KEY=",
  "HALOMEM_NANGO_INTEGRATIONS={}",
  "HALOMEM_NANGO_CONNECTION_LIMIT=10",
  "HALOMEM_NANGO_ENVIRONMENT_ID=",
  "HALOMEM_NOTION_CLIENT_ID=",
  "HALOMEM_NOTION_CLIENT_SECRET=",
  "HALOMEM_NOTION_SYNC_INTERVAL_SECONDS=14400",
  "HALOMEM_MODEL_ALLOWED_HOSTS=",
  "HALOMEM_PUBLIC_URL=http://localhost:8787",
  "HALOMEM_HALO_AGENTS_URL=",
  "HALOMEM_HALO_AGENTS_SSO_SECRET=",
  "HALOMEM_SECURE_COOKIES=false",
  "",
];

try {
  await writeFile(target, lines.join("\n"), { encoding: "utf8", flag: "wx", mode: 0o600 });
  process.stdout.write("Created kernel/.env. Keep it private; run docker compose up --build.\n");
} catch (error) {
  if (error?.code === "EEXIST") {
    process.stderr.write("kernel/.env already exists; refusing to overwrite secrets.\n");
    process.exitCode = 1;
  } else {
    throw error;
  }
}
