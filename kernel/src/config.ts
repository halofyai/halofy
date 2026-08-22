/**
 * Kernel configuration — resolved once at boot from environment.
 * D5: one database. PGlite (embedded Postgres) unless DATABASE_URL is set.
 */

import { fileURLToPath } from "node:url";
import { assertSecurePostgresDsn } from "./security/postgres.js";

export interface KernelConfig {
  /** Postgres connection string; empty → embedded PGlite. */
  databaseUrl: string;
  /**
   * How the kernel authenticates to Postgres.
   *  - `password` (default): the credential embedded in `databaseUrl`.
   *  - `entra`: a managed-identity access token minted per connection, so no
   *    long-lived database password exists to leak. Requires Entra auth to be
   *    enabled on the server and `dbEntraUser` to name a database role mapped
   *    to this workload's identity. Falls back to the DSN password if the
   *    token endpoint is unreachable AND the server still accepts passwords.
   */
  dbAuthMode: "password" | "entra";
  /** Entra principal name to log in as (the role created for the identity). */
  dbEntraUser: string;
  /** Client id of the user-assigned identity; empty → system-assigned. */
  dbEntraClientId: string;
  /** Filesystem path for PGlite data (ignored when databaseUrl set). In-memory when "". */
  pgliteDataDir: string;
  /** Path to the L3 cold-tier git repo of OKF markdown concepts. */
  knowledgeDir: string;
  /** Base64-encoded 32-byte KEK used only to wrap private L3 concept DEKs. */
  coldKek: string;
  /** Base64-encoded 32-byte KEK used only for connector configuration. */
  sourceConfigKek: string;
  /** Base64-encoded 32-byte KEK used only for organization model credentials. */
  modelCredentialKek: string;
  /** Exact hostnames permitted for self-hosted/private model endpoints. */
  modelAllowedHosts: string[];
  /** Hermetic test seam; production leaves this undefined for pinned DNS transport. */
  modelFetch?: typeof fetch;
  /** Shared Azure Mastra V2 turn service. Empty keeps the in-process runtime. */
  mastraV2RuntimeBaseUrl: string;
  /** Service-to-service bearer for HaloMem -> shared Mastra. */
  mastraV2InternalApiToken: string;
  /** HMAC key for 60-second, organization-bound MCP delegation credentials. */
  mastraV2CapabilitySecret: string;
  /** Public HaloMem MCP endpoint handed to the shared harness per turn. */
  mastraV2PublicMcpUrl: string;
  /** Managed model used when the caller does not select an explicit organization profile. */
  mastraV2ManagedModel: string;
  /** Picker label for the sidecar-backed platform default. */
  mastraV2ManagedLabel: string;
  /** Outer sidecar request deadline. */
  mastraV2TimeoutMs: number;
  /**
   * Second platform-managed default, on the native Anthropic Messages contract.
   *
   * Azure AI Foundry serves Claude deployments at `/anthropic/v1`, not on the
   * OpenAI-shaped route the Mastra sidecar is pinned to, so this profile runs on
   * the kernel's own harness with a platform-held key. All three must be set
   * together or the profile is not published. Empty model keeps it off.
   */
  managedAnthropicModel: string;
  managedAnthropicBaseUrl: string;
  managedAnthropicApiKey: string;
  /** Picker label for the Anthropic platform default. */
  managedAnthropicLabel: string;
  /** Strong out-of-band credential for the permanently single-use first boot. */
  bootstrapToken: string;
  /** Embedding dimension — must match the active embedder. */
  embedDim: number;
  /** Default per-namespace token budget for working sets. */
  defaultTokenBudget: number;
  /** Cosine similarity threshold above which a new fact is a duplicate. */
  dedupeThreshold: number;
  /** Anthropic key enables the real extractor/verifier LLM. */
  anthropicApiKey: string;
  /**
   * Any OpenAI-compatible vendor (DeepSeek, Kimi, Qwen, Groq, OpenRouter, a
   * local vLLM…) as the write-path extractor/verifier. Base URL + key + model
   * ids come from the BYOK catalog (src/model-runtime/catalog.ts). Takes
   * precedence over Anthropic; Azure still wins over both.
   */
  llmBaseUrl: string;
  llmApiKey: string;
  llmModel: string;
  /** OpenAI key enables real embeddings (dim 1536); otherwise HashEmbedder (256). */
  openaiApiKey: string;
  /** Azure OpenAI chat deployment for extraction/verification — takes precedence over Anthropic. */
  azureOpenaiLlmApiKey: string;
  azureOpenaiLlmEndpoint: string;
  azureOpenaiLlmDeployment: string;
  /** Azure OpenAI embeddings deployment (dim 3072, text-embedding-3-large) — takes precedence over OpenAI. */
  azureOpenaiEmbedApiKey: string;
  azureOpenaiEmbedEndpoint: string;
  azureOpenaiEmbedDeployment: string;
  azureOpenaiApiVersion: string;
  /** Server-only key scoped to connect-session creation and connection listing. */
  nangoConnectApiKey: string;
  /** Server-only key scoped only to Nango Proxy requests. */
  nangoProxyApiKey: string;
  /** Environment-global connection guard; free validation defaults to ten. */
  nangoConnectionLimit: number;
  /** Stable operator-owned Nango environment identifier; survives API-key rotation. */
  nangoEnvironmentId: string;
  /** Halo connector connectionKey -> Nango integration unique key. */
  nangoIntegrations: Readonly<Record<string, string>>;
  /** Hermetic Nango test seam; production uses global fetch. */
  nangoFetch?: typeof fetch;
  /** HaloMem-owned Airtable OAuth application. Both values are required together. */
  airtableClientId: string;
  airtableClientSecret: string;
  /** Hermetic direct-Airtable transport seam; production uses global fetch. */
  airtableFetch?: typeof fetch;
  /** HaloMem-owned Notion public OAuth application. Both values are required together. */
  notionClientId: string;
  notionClientSecret: string;
  /** Hermetic direct-Notion transport seam; production uses global fetch. */
  notionFetch?: typeof fetch;
  /** HaloMem-owned Google Drive OAuth application; separate from channel OAuth. */
  googleDriveClientId: string;
  googleDriveClientSecret: string;
  /** Hermetic direct-Drive transport seam; production uses global fetch. */
  googleDriveFetch?: typeof fetch;
  /** Azure OpenAI GPT-5.5 deployment for the S16 v2 skill-vetting LLM lane (D32/D33). */
  azureOpenaiScanApiKey: string;
  azureOpenaiScanEndpoint: string;
  azureOpenaiScanDeployment: string;
  /** Halo-owned Azure OpenAI GPT-5.6 Luna lane for semantic conflict judgement. */
  azureOpenaiConflictApiKey: string;
  azureOpenaiConflictEndpoint: string;
  azureOpenaiConflictDeployment: string;
  /**
   * OpenAI-compatible scan endpoint for the S16 v2 skill-vetting LLM lane —
   * takes precedence over the Azure triple when set (2026-07-19 decision:
   * Kimi `k3` via https://api.kimi.com/coding/v1). Also drives the external
   * scanners' LLM analyzers (OPENAI_BASE_URL / SKILL_SCANNER_LLM_BASE_URL).
   */
  skillScanLlmBaseUrl: string;
  skillScanLlmApiKey: string;
  skillScanLlmModel: string;
  /**
   * D35 ladder: `auto` (missing lane skipped-and-recorded, keyless → v1
   * fallback) | `required` (prod: missing lane = lane error, fail closed) |
   * `off` (v1 only).
   */
  skillVettingV2: "auto" | "required" | "off";
  /** Hermetic test seam: inject v2 lanes directly instead of probing (never from env). */
  skillVettingV2Lanes?: import("./skills/vetting.js").SkillVettingLanes;
  /** Hermetic conflict-scan semantic judge seam; production resolves Azure from env. */
  conflictClassifier?: import("./conflict-scans/classifier.js").ConflictClassifier | null;
  /** Hermetic test seam; production defaults to the five-minute durable cooldown. */
  conflictScanRequestCooldownMs?: number;
  /** Communication channel subsystem is opt-in and fail-closed. */
  channelsEnabled: boolean;
  channelEnvironment: "development" | "staging" | "production";
  /** Exact public HTTPS origin used for channel ingress and OAuth redirects. */
  channelPublicUrl: string;
  /** Base64-encoded 32-byte KEK dedicated to installation-scoped channel secrets. */
  channelSecretKek: string;
  channelSecretKekId: string;
  channelSecretKeyVersion: number;
  /** Global outbound kill switch; defaults off. */
  channelOutboundEnabled: boolean;
  /**
   * Discord gateway sockets. Off by default: it opens one long-lived
   * websocket per active Discord connection, which only one process in a
   * multi-replica deployment should do.
   */
  channelDiscordGatewayEnabled: boolean;
  channelBacklogLimit: number;
  channelPinnedBacklogReserve: number;
  channelLeaseMs: number;
  channelReceiptLeaseMs: number;
  channelWorkerPollMs: number;
  channelTelemetrySalt: string;
  channelDeploymentVersion: string;
  channelConfigVersion: string;
  channelInfrastructureVersion: string;
  /** Halofy-owned Google Chat app configuration and mutually exclusive auth lanes. */
  channelGoogleChatProjectNumber: string;
  channelGoogleChatInstallUrl: string;
  channelGoogleChatRouteKey: string;
  channelGoogleChatServiceAccountJson: string;
  channelGoogleChatAzureClientId: string;
  channelGoogleChatAzureAppIdUri: string;
  channelGoogleChatWorkloadIdentityProvider: string;
  channelGoogleChatServiceAccountEmail: string;
  /** Azure Container Apps injects these at runtime; operators do not configure them. */
  channelGoogleChatAzureIdentityEndpoint: string;
  channelGoogleChatAzureIdentityHeader: string;
  /** Hermetic channel provider transport seam; production uses global fetch. */
  channelFetch?: typeof fetch;
}

export const AZURE_EMBED_DIM = 3072;

/** SKILL_VETTING_V2: invalid values fall back to `auto` (never a boot failure). */
function parseSkillVettingV2(raw: string | undefined): "auto" | "required" | "off" {
  return raw === "required" || raw === "off" ? raw : "auto";
}

function parseNangoIntegrations(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("HALOMEM_NANGO_INTEGRATIONS must be a JSON object");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("HALOMEM_NANGO_INTEGRATIONS must be a JSON object");
  }
  const integrations: Record<string, string> = {};
  for (const [connectionKey, integrationId] of Object.entries(parsed)) {
    if (!/^[a-z0-9_]+$/.test(connectionKey) || typeof integrationId !== "string" ||
        !/^[a-zA-Z0-9_-]+$/.test(integrationId)) {
      throw new Error("HALOMEM_NANGO_INTEGRATIONS contains an invalid mapping");
    }
    integrations[connectionKey] = integrationId;
  }
  return integrations;
}

function isCanonicalBase64Key(value: string, byteLength: number): boolean {
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.length === byteLength && decoded.toString("base64") === value;
  } catch {
    return false;
  }
}

function parseBoolean(name: string, raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw === "") return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be 'true' or 'false'`);
}

function parseBoundedInteger(
  name: string,
  raw: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = raw === undefined || raw === "" ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function parseChannelEnvironment(raw: string | undefined): KernelConfig["channelEnvironment"] {
  const value = raw ?? "development";
  if (value !== "development" && value !== "staging" && value !== "production") {
    throw new Error("HALOMEM_CHANNEL_ENVIRONMENT must be development, staging, or production");
  }
  return value;
}

function assertChannelPublicUrl(value: string): void {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password ||
        url.pathname !== "/" || url.search || url.hash || value !== url.origin) {
      throw new Error("invalid");
    }
  } catch {
    throw new Error("HALOMEM_PUBLIC_URL must be an origin-only HTTPS URL");
  }
}

function assertImmutableChannelVersion(name: string, value: string): void {
  if (!/^[A-Za-z0-9._:@/-]{1,200}$/.test(value)) {
    throw new Error(`${name} is required and malformed`);
  }
}

/** Fail closed for deployment shapes that cannot preserve kernel invariants. */
export function assertSupportedDeployment(
  config: KernelConfig,
  env: Readonly<Record<string, string | undefined>> = process.env,
): void {
  if (env.VERCEL || env.AWS_LAMBDA_FUNCTION_NAME || env.FUNCTIONS_WORKER_RUNTIME) {
    throw new Error(
      "serverless deployment is unsupported for the stateful HaloMem kernel; " +
      "deploy the container image with shared Postgres and persistent cold storage",
    );
  }
  if (env.NODE_ENV !== "production") return;
  if (!config.databaseUrl) {
    throw new Error("production requires DATABASE_URL (embedded PGlite is development-only)");
  }
  assertSecurePostgresDsn(config.databaseUrl, "production DATABASE_URL");
  if (!config.coldKek) throw new Error("production requires HALOMEM_COLD_KEK");
  if (!config.sourceConfigKek) {
    throw new Error("production requires HALOMEM_SOURCE_CONFIG_KEK");
  }
  if (!isCanonicalBase64Key(config.modelCredentialKek, 32)) {
    throw new Error("production requires HALOMEM_MODEL_CREDENTIAL_KEK as a canonical base64 32-byte key");
  }
  if (!env.HALOMEM_SIGNING_KEY) {
    throw new Error("production requires HALOMEM_SIGNING_KEY");
  }
  if (env.HALOMEM_COLD_STORAGE !== "shared-persistent") {
    throw new Error(
      "production requires HALOMEM_COLD_STORAGE=shared-persistent and a shared durable knowledge volume",
    );
  }
  if (config.channelsEnabled) {
    if (!config.databaseUrl) throw new Error("production channels require DATABASE_URL");
    if (config.channelEnvironment !== "production") {
      throw new Error("production channels require HALOMEM_CHANNEL_ENVIRONMENT=production");
    }
    assertChannelPublicUrl(config.channelPublicUrl);
    if (!isCanonicalBase64Key(config.channelSecretKek, 32)) {
      throw new Error("production channels require a base64 32-byte HALOMEM_CHANNEL_SECRET_KEK");
    }
    if (!config.channelSecretKekId.trim()) {
      throw new Error("production channels require HALOMEM_CHANNEL_SECRET_KEK_ID");
    }
    if (!Number.isSafeInteger(config.channelSecretKeyVersion) || config.channelSecretKeyVersion < 1) {
      throw new Error("HALOMEM_CHANNEL_SECRET_KEY_VERSION must be a positive integer");
    }
    if (Buffer.byteLength(config.channelTelemetrySalt, "utf8") < 32) {
      throw new Error("production channels require HALOMEM_CHANNEL_TELEMETRY_SALT");
    }
    assertImmutableChannelVersion(
      "HALOMEM_CHANNEL_DEPLOYMENT_VERSION",
      config.channelDeploymentVersion,
    );
    assertImmutableChannelVersion("HALOMEM_CHANNEL_CONFIG_VERSION", config.channelConfigVersion);
    assertImmutableChannelVersion(
      "HALOMEM_CHANNEL_INFRASTRUCTURE_VERSION",
      config.channelInfrastructureVersion,
    );
    if ((env.HALOMEM_CHANNEL_OUTBOUND_ENABLED !== "true" &&
         env.HALOMEM_CHANNEL_OUTBOUND_ENABLED !== "false") ||
        config.channelOutboundEnabled !== (env.HALOMEM_CHANNEL_OUTBOUND_ENABLED === "true")) {
      throw new Error(
        "production channels require explicit matching HALOMEM_CHANNEL_OUTBOUND_ENABLED",
      );
    }
  }
}

export function loadConfig(overrides: Partial<KernelConfig> = {}): KernelConfig {
  const openaiApiKey = process.env.OPENAI_API_KEY ?? "";
  const azureOpenaiEmbedApiKey = process.env.AZURE_OPENAI_EMBED_API_KEY ?? "";
  const conflictTriple = [
    process.env.AZURE_OPENAI_CONFLICT_API_KEY,
    process.env.AZURE_OPENAI_CONFLICT_ENDPOINT,
    process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT,
  ];
  if (conflictTriple.some(Boolean) && !conflictTriple.every(Boolean)) {
    throw new Error(
      "AZURE_OPENAI_CONFLICT_API_KEY, AZURE_OPENAI_CONFLICT_ENDPOINT, and " +
      "AZURE_OPENAI_CONFLICT_DEPLOYMENT must be configured together",
    );
  }
  const config: KernelConfig = {
    databaseUrl: process.env.DATABASE_URL ?? "",
    // Anything other than an explicit "entra" keeps the existing password
    // path, so a typo degrades to today's behaviour rather than to a kernel
    // that cannot reach its database.
    dbAuthMode: process.env.HALOMEM_DB_AUTH === "entra" ? "entra" : "password",
    dbEntraUser: process.env.HALOMEM_DB_ENTRA_USER ?? "",
    dbEntraClientId: process.env.HALOMEM_DB_ENTRA_CLIENT_ID ?? "",
    pgliteDataDir: process.env.HALOMEM_DATA_DIR ?? "",
    knowledgeDir:
      process.env.HALOMEM_KNOWLEDGE_DIR ??
      fileURLToPath(new URL("../knowledge", import.meta.url)),
    coldKek: process.env.HALOMEM_COLD_KEK ?? "",
    sourceConfigKek: process.env.HALOMEM_SOURCE_CONFIG_KEK ?? "",
    modelCredentialKek: process.env.HALOMEM_MODEL_CREDENTIAL_KEK ?? "",
    modelAllowedHosts: (process.env.HALOMEM_MODEL_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter((host) => host.length > 0),
    mastraV2RuntimeBaseUrl: process.env.HALOMEM_MASTRA_V2_RUNTIME_BASE_URL ?? "",
    mastraV2InternalApiToken: process.env.HALOMEM_MASTRA_V2_INTERNAL_API_TOKEN ?? "",
    mastraV2CapabilitySecret: process.env.HALOMEM_MASTRA_V2_CAPABILITY_SECRET ?? "",
    mastraV2PublicMcpUrl: process.env.HALOMEM_MASTRA_V2_PUBLIC_MCP_URL ?? "",
    mastraV2ManagedModel: process.env.HALOMEM_MASTRA_V2_MANAGED_MODEL ?? "gpt-5-mini",
    mastraV2ManagedLabel: process.env.HALOMEM_MASTRA_V2_MANAGED_LABEL ?? "GPT-5.6 Luna",
    managedAnthropicModel: process.env.HALOMEM_MANAGED_ANTHROPIC_MODEL ?? "",
    managedAnthropicBaseUrl: process.env.HALOMEM_MANAGED_ANTHROPIC_BASE_URL ?? "",
    managedAnthropicApiKey: process.env.HALOMEM_MANAGED_ANTHROPIC_API_KEY ?? "",
    managedAnthropicLabel: process.env.HALOMEM_MANAGED_ANTHROPIC_LABEL ?? "Claude Sonnet 5",
    // The sidecar reads a complete SSE result, so this is a deadline on the
    // model's whole generation. 30s cut reasoning models off mid-thought and
    // surfaced it as an outage.
    mastraV2TimeoutMs: Number(process.env.HALOMEM_MASTRA_V2_TIMEOUT_MS ?? 120_000),
    bootstrapToken: process.env.HALOMEM_BOOTSTRAP_TOKEN ?? "",
    embedDim: openaiApiKey ? 1536 : 256,
    defaultTokenBudget: Number(process.env.HALOMEM_TOKEN_BUDGET ?? 3000),
    dedupeThreshold: Number(process.env.HALOMEM_DEDUPE_THRESHOLD ?? 0.92),
    anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "",
    llmBaseUrl: process.env.HALOMEM_LLM_BASE_URL ?? "",
    llmApiKey: process.env.HALOMEM_LLM_API_KEY ?? "",
    llmModel: process.env.HALOMEM_LLM_MODEL ?? "",
    openaiApiKey,
    azureOpenaiLlmApiKey: process.env.AZURE_OPENAI_LLM_API_KEY ?? "",
    azureOpenaiLlmEndpoint: process.env.AZURE_OPENAI_LLM_ENDPOINT ?? "",
    azureOpenaiLlmDeployment: process.env.AZURE_OPENAI_LLM_DEPLOYMENT ?? "",
    azureOpenaiEmbedApiKey,
    azureOpenaiEmbedEndpoint: process.env.AZURE_OPENAI_EMBED_ENDPOINT ?? "",
    azureOpenaiEmbedDeployment: process.env.AZURE_OPENAI_EMBED_DEPLOYMENT ?? "",
    azureOpenaiApiVersion: process.env.AZURE_OPENAI_API_VERSION ?? "2025-04-01-preview",
    nangoConnectApiKey: process.env.HALOMEM_NANGO_CONNECT_API_KEY ?? "",
    nangoProxyApiKey: process.env.HALOMEM_NANGO_PROXY_API_KEY ?? "",
    nangoConnectionLimit: Number(process.env.HALOMEM_NANGO_CONNECTION_LIMIT ?? 10),
    nangoEnvironmentId: process.env.HALOMEM_NANGO_ENVIRONMENT_ID ?? "",
    nangoIntegrations: parseNangoIntegrations(process.env.HALOMEM_NANGO_INTEGRATIONS),
    airtableClientId: process.env.HALOMEM_AIRTABLE_CLIENT_ID ?? "",
    airtableClientSecret: process.env.HALOMEM_AIRTABLE_CLIENT_SECRET ?? "",
    notionClientId: process.env.HALOMEM_NOTION_CLIENT_ID ?? "",
    notionClientSecret: process.env.HALOMEM_NOTION_CLIENT_SECRET ?? "",
    googleDriveClientId: process.env.HALOMEM_GOOGLE_DRIVE_CLIENT_ID ?? "",
    googleDriveClientSecret: process.env.HALOMEM_GOOGLE_DRIVE_CLIENT_SECRET ?? "",
    azureOpenaiScanApiKey: process.env.AZURE_OPENAI_API_KEY ?? "",
    azureOpenaiScanEndpoint: process.env.AZURE_OPENAI_ENDPOINT ?? "",
    azureOpenaiScanDeployment: process.env.AZURE_OPENAI_SCAN_DEPLOYMENT ?? "",
    azureOpenaiConflictApiKey:
      process.env.AZURE_OPENAI_CONFLICT_API_KEY ?? process.env.AZURE_OPENAI_API_KEY ?? "",
    azureOpenaiConflictEndpoint:
      process.env.AZURE_OPENAI_CONFLICT_ENDPOINT ?? process.env.AZURE_OPENAI_ENDPOINT ?? "",
    azureOpenaiConflictDeployment:
      process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT ??
      process.env.AZURE_OPENAI_SCAN_DEPLOYMENT ??
      "",
    skillScanLlmBaseUrl: process.env.SKILL_SCAN_LLM_BASE_URL ?? "",
    skillScanLlmApiKey: process.env.SKILL_SCAN_LLM_API_KEY ?? "",
    skillScanLlmModel: process.env.SKILL_SCAN_LLM_MODEL ?? "",
    skillVettingV2: parseSkillVettingV2(process.env.SKILL_VETTING_V2),
    channelsEnabled: parseBoolean(
      "HALOMEM_CHANNELS_ENABLED",
      process.env.HALOMEM_CHANNELS_ENABLED,
      false,
    ),
    channelEnvironment: parseChannelEnvironment(process.env.HALOMEM_CHANNEL_ENVIRONMENT),
    channelPublicUrl: process.env.HALOMEM_PUBLIC_URL ?? "",
    channelSecretKek: process.env.HALOMEM_CHANNEL_SECRET_KEK ?? "",
    channelSecretKekId: process.env.HALOMEM_CHANNEL_SECRET_KEK_ID ?? "",
    channelSecretKeyVersion: parseBoundedInteger(
      "HALOMEM_CHANNEL_SECRET_KEY_VERSION",
      process.env.HALOMEM_CHANNEL_SECRET_KEY_VERSION,
      1,
      1,
      1_000_000,
    ),
    channelOutboundEnabled: parseBoolean(
      "HALOMEM_CHANNEL_OUTBOUND_ENABLED",
      process.env.HALOMEM_CHANNEL_OUTBOUND_ENABLED,
      false,
    ),
    channelDiscordGatewayEnabled: parseBoolean(
      "HALOMEM_CHANNEL_DISCORD_GATEWAY_ENABLED",
      process.env.HALOMEM_CHANNEL_DISCORD_GATEWAY_ENABLED,
      false,
    ),
    channelBacklogLimit: parseBoundedInteger(
      "HALOMEM_CHANNEL_BACKLOG_LIMIT",
      process.env.HALOMEM_CHANNEL_BACKLOG_LIMIT,
      10_000,
      100,
      1_000_000,
    ),
    channelPinnedBacklogReserve: parseBoundedInteger(
      "HALOMEM_CHANNEL_PINNED_BACKLOG_RESERVE",
      process.env.HALOMEM_CHANNEL_PINNED_BACKLOG_RESERVE,
      250,
      1,
      10_000,
    ),
    channelLeaseMs: parseBoundedInteger(
      "HALOMEM_CHANNEL_LEASE_MS",
      process.env.HALOMEM_CHANNEL_LEASE_MS,
      60_000,
      1_000,
      300_000,
    ),
    channelReceiptLeaseMs: parseBoundedInteger(
      "HALOMEM_CHANNEL_RECEIPT_LEASE_MS",
      process.env.HALOMEM_CHANNEL_RECEIPT_LEASE_MS,
      30_000,
      1_000,
      300_000,
    ),
    channelWorkerPollMs: parseBoundedInteger(
      "HALOMEM_CHANNEL_WORKER_POLL_MS",
      process.env.HALOMEM_CHANNEL_WORKER_POLL_MS,
      1_000,
      100,
      60_000,
    ),
    channelTelemetrySalt: process.env.HALOMEM_CHANNEL_TELEMETRY_SALT ?? "",
    channelDeploymentVersion: process.env.HALOMEM_CHANNEL_DEPLOYMENT_VERSION ?? "",
    channelConfigVersion: process.env.HALOMEM_CHANNEL_CONFIG_VERSION ?? "",
    channelInfrastructureVersion: process.env.HALOMEM_CHANNEL_INFRASTRUCTURE_VERSION ?? "",
    channelGoogleChatProjectNumber:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_PROJECT_NUMBER ?? "",
    channelGoogleChatInstallUrl:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_INSTALL_URL ?? "",
    channelGoogleChatRouteKey:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_ROUTE_KEY ?? "",
    channelGoogleChatServiceAccountJson:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_SERVICE_ACCOUNT_JSON ?? "",
    channelGoogleChatAzureClientId:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_AZURE_CLIENT_ID ?? "",
    channelGoogleChatAzureAppIdUri:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_AZURE_APP_ID_URI ?? "",
    channelGoogleChatWorkloadIdentityProvider:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_WIF_PROVIDER ?? "",
    channelGoogleChatServiceAccountEmail:
      process.env.HALOMEM_GOOGLE_CHAT_MANAGED_SERVICE_ACCOUNT_EMAIL ?? "",
    channelGoogleChatAzureIdentityEndpoint: process.env.IDENTITY_ENDPOINT ?? "",
    channelGoogleChatAzureIdentityHeader: process.env.IDENTITY_HEADER ?? "",
    ...overrides,
  };
  // embedDim must track the embedder actually selected by the EFFECTIVE
  // key precedence (azure > openai, env or override) — otherwise migrate()
  // creates vector(N) columns that mismatch the embedder's dimension and
  // every insert/search fails. An explicit embedDim override still wins.
  if (overrides.embedDim === undefined) {
    config.embedDim = config.azureOpenaiEmbedApiKey
      ? AZURE_EMBED_DIM
      : config.openaiApiKey
        ? 1536
        : 256;
  }
  if (!Number.isSafeInteger(config.nangoConnectionLimit) || config.nangoConnectionLimit < 1 ||
      config.nangoConnectionLimit > 10_000) {
    throw new Error("HALOMEM_NANGO_CONNECTION_LIMIT must be an integer from 1 to 10000");
  }
  if (Object.keys(config.nangoIntegrations).length > 0 &&
      !/^[a-zA-Z0-9_-]{1,64}$/.test(config.nangoEnvironmentId)) {
    throw new Error(
      "HALOMEM_NANGO_ENVIRONMENT_ID is required when managed integrations are configured",
    );
  }
  if (Boolean(config.notionClientId) !== Boolean(config.notionClientSecret)) {
    throw new Error(
      "HALOMEM_NOTION_CLIENT_ID and HALOMEM_NOTION_CLIENT_SECRET must be set together",
    );
  }
  if (Boolean(config.airtableClientId) !== Boolean(config.airtableClientSecret)) {
    throw new Error(
      "HALOMEM_AIRTABLE_CLIENT_ID and HALOMEM_AIRTABLE_CLIENT_SECRET must be set together",
    );
  }
  if (Boolean(config.googleDriveClientId) !== Boolean(config.googleDriveClientSecret)) {
    throw new Error(
      "HALOMEM_GOOGLE_DRIVE_CLIENT_ID and HALOMEM_GOOGLE_DRIVE_CLIENT_SECRET must be set together",
    );
  }
  validateMastraV2Config(config);
  validateManagedAnthropicConfig(config);
  parseBoundedInteger(
    "HALOMEM_CHANNEL_SECRET_KEY_VERSION",
    String(config.channelSecretKeyVersion),
    1,
    1,
    1_000_000,
  );
  parseBoundedInteger(
    "HALOMEM_CHANNEL_BACKLOG_LIMIT",
    String(config.channelBacklogLimit),
    10_000,
    100,
    1_000_000,
  );
  parseBoundedInteger(
    "HALOMEM_CHANNEL_PINNED_BACKLOG_RESERVE",
    String(config.channelPinnedBacklogReserve),
    250,
    1,
    10_000,
  );
  if (config.channelPinnedBacklogReserve > Math.min(config.channelBacklogLimit, 10_000)) {
    throw new Error(
      "HALOMEM_CHANNEL_PINNED_BACKLOG_RESERVE must not exceed the channel backlog limit",
    );
  }
  parseBoundedInteger(
    "HALOMEM_CHANNEL_LEASE_MS",
    String(config.channelLeaseMs),
    60_000,
    1_000,
    300_000,
  );
  parseBoundedInteger(
    "HALOMEM_CHANNEL_RECEIPT_LEASE_MS",
    String(config.channelReceiptLeaseMs),
    30_000,
    1_000,
    300_000,
  );
  parseBoundedInteger(
    "HALOMEM_CHANNEL_WORKER_POLL_MS",
    String(config.channelWorkerPollMs),
    1_000,
    100,
    60_000,
  );
  if (config.channelsEnabled && config.channelPublicUrl) {
    assertChannelPublicUrl(config.channelPublicUrl);
  }
  const googleChatManagedBaseValues = [
    config.channelGoogleChatProjectNumber,
    config.channelGoogleChatInstallUrl,
    config.channelGoogleChatRouteKey,
  ];
  const googleChatManagedBaseCount = googleChatManagedBaseValues
    .filter((value) => value.length > 0).length;
  const googleChatFederationValues = [
    config.channelGoogleChatAzureClientId,
    config.channelGoogleChatAzureAppIdUri,
    config.channelGoogleChatWorkloadIdentityProvider,
    config.channelGoogleChatServiceAccountEmail,
  ];
  const googleChatFederationCount = googleChatFederationValues
    .filter((value) => value.length > 0).length;
  const hasServiceAccountKey = config.channelGoogleChatServiceAccountJson.length > 0;
  const hasAnyManagedGoogleChat = googleChatManagedBaseCount > 0 || hasServiceAccountKey ||
    googleChatFederationCount > 0;
  if (hasAnyManagedGoogleChat && googleChatManagedBaseCount !== googleChatManagedBaseValues.length) {
    throw new Error(
      "managed Google Chat requires project number, install URL, route key, and exactly one complete authentication method",
    );
  }
  if (googleChatFederationCount !== 0 &&
      googleChatFederationCount !== googleChatFederationValues.length) {
    throw new Error("managed Google Chat requires all four Azure federation values");
  }
  if (hasAnyManagedGoogleChat && hasServiceAccountKey === (googleChatFederationCount > 0)) {
    throw new Error(
      "managed Google Chat requires project number, install URL, route key, and exactly one complete authentication method",
    );
  }
  if (hasAnyManagedGoogleChat) {
    if (!/^\d{6,30}$/.test(config.channelGoogleChatProjectNumber)) {
      throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_PROJECT_NUMBER must be numeric");
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(config.channelGoogleChatRouteKey)) {
      throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_ROUTE_KEY must be an opaque 16-128 character key");
    }
    let installUrl: URL;
    try {
      installUrl = new URL(config.channelGoogleChatInstallUrl);
    } catch {
      throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_INSTALL_URL must be a valid URL");
    }
    if (installUrl.protocol !== "https:") {
      throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_INSTALL_URL must use https");
    }
    if (hasServiceAccountKey) try {
      const serviceAccount = JSON.parse(config.channelGoogleChatServiceAccountJson) as {
        client_email?: unknown;
        private_key?: unknown;
      };
      if (typeof serviceAccount.client_email !== "string" ||
          typeof serviceAccount.private_key !== "string" ||
          !serviceAccount.private_key.includes("PRIVATE KEY")) {
        throw new Error("invalid");
      }
    } catch {
      throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_SERVICE_ACCOUNT_JSON is invalid");
    }
    if (googleChatFederationCount > 0) {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
        .test(config.channelGoogleChatAzureClientId)) {
        throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_AZURE_CLIENT_ID must be a UUID");
      }
      if (!config.channelGoogleChatAzureAppIdUri.startsWith("api://")) {
        throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_AZURE_APP_ID_URI must use api://");
      }
      if (!/^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/
        .test(config.channelGoogleChatWorkloadIdentityProvider)) {
        throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_WIF_PROVIDER is invalid");
      }
      if (!/^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$/
        .test(config.channelGoogleChatServiceAccountEmail)) {
        throw new Error("HALOMEM_GOOGLE_CHAT_MANAGED_SERVICE_ACCOUNT_EMAIL is invalid");
      }
      if (config.channelGoogleChatAzureIdentityEndpoint.length === 0 ||
          config.channelGoogleChatAzureIdentityHeader.length === 0) {
        throw new Error("managed Google Chat federation requires the Azure managed identity runtime");
      }
    }
  }
  if (config.channelsEnabled) {
    const inMemoryDevelopment = config.channelEnvironment === "development" &&
      config.databaseUrl.length === 0 && config.pgliteDataDir.length === 0;
    if (!config.channelSecretKek && !inMemoryDevelopment) {
      throw new Error(
        "HALOMEM_CHANNEL_SECRET_KEK is required when channel storage survives restart",
      );
    }
    if (config.channelSecretKek && !isCanonicalBase64Key(config.channelSecretKek, 32)) {
      throw new Error("HALOMEM_CHANNEL_SECRET_KEK must be a base64 32-byte key");
    }
    if (!config.channelSecretKekId.trim()) {
      throw new Error("enabled channels require HALOMEM_CHANNEL_SECRET_KEK_ID");
    }
  }
  if (config.channelsEnabled && config.channelEnvironment !== "development") {
    if (!config.channelPublicUrl) {
      throw new Error("enabled staging/production channels require HALOMEM_PUBLIC_URL");
    }
    if (!isCanonicalBase64Key(config.channelSecretKek, 32)) {
      throw new Error(
        "enabled staging/production channels require a base64 32-byte HALOMEM_CHANNEL_SECRET_KEK",
      );
    }
    if (!config.channelSecretKekId.trim()) {
      throw new Error("enabled staging/production channels require HALOMEM_CHANNEL_SECRET_KEK_ID");
    }
    if (Buffer.byteLength(config.channelTelemetrySalt, "utf8") < 32) {
      throw new Error("enabled staging/production channels require HALOMEM_CHANNEL_TELEMETRY_SALT");
    }
    assertImmutableChannelVersion(
      "HALOMEM_CHANNEL_DEPLOYMENT_VERSION",
      config.channelDeploymentVersion,
    );
    assertImmutableChannelVersion("HALOMEM_CHANNEL_CONFIG_VERSION", config.channelConfigVersion);
    assertImmutableChannelVersion(
      "HALOMEM_CHANNEL_INFRASTRUCTURE_VERSION",
      config.channelInfrastructureVersion,
    );
  }
  return config;
}

function validateMastraV2Config(config: KernelConfig): void {
  const configured = [
    config.mastraV2RuntimeBaseUrl,
    config.mastraV2InternalApiToken,
    config.mastraV2CapabilitySecret,
    config.mastraV2PublicMcpUrl,
  ].filter((value) => value.length > 0).length;
  if (configured === 0) return;
  if (configured !== 4) {
    throw new Error(
      "Mastra V2 requires runtime URL, internal token, capability secret, and public MCP URL",
    );
  }
  if (Buffer.byteLength(config.mastraV2CapabilitySecret, "utf8") < 32) {
    throw new Error("HALOMEM_MASTRA_V2_CAPABILITY_SECRET must be at least 32 bytes");
  }
  if (!config.mastraV2ManagedModel.trim() || config.mastraV2ManagedModel.length > 300) {
    throw new Error("HALOMEM_MASTRA_V2_MANAGED_MODEL is invalid");
  }
  if (!config.mastraV2ManagedLabel.trim() || config.mastraV2ManagedLabel.length > 120) {
    throw new Error("HALOMEM_MASTRA_V2_MANAGED_LABEL is invalid");
  }
  if (!Number.isSafeInteger(config.mastraV2TimeoutMs) || config.mastraV2TimeoutMs < 5_000 ||
      config.mastraV2TimeoutMs > 300_000) {
    throw new Error("HALOMEM_MASTRA_V2_TIMEOUT_MS must be an integer from 5000 to 300000");
  }
  const runtime = secureUrl(config.mastraV2RuntimeBaseUrl, "HALOMEM_MASTRA_V2_RUNTIME_BASE_URL");
  if (runtime.search || runtime.hash) {
    throw new Error("HALOMEM_MASTRA_V2_RUNTIME_BASE_URL cannot contain query or fragment");
  }
  const mcp = secureUrl(config.mastraV2PublicMcpUrl, "HALOMEM_MASTRA_V2_PUBLIC_MCP_URL");
  if (mcp.pathname !== "/mcp" || mcp.search || mcp.hash) {
    throw new Error("HALOMEM_MASTRA_V2_PUBLIC_MCP_URL must end at /mcp");
  }
}

/**
 * The Anthropic platform default is all-or-nothing. A half-configured profile
 * would still be published to every tenant's picker and then fail the turn, so
 * a missing field is a boot error rather than a runtime surprise.
 */
function validateManagedAnthropicConfig(config: KernelConfig): void {
  const configured = [
    config.managedAnthropicModel,
    config.managedAnthropicBaseUrl,
    config.managedAnthropicApiKey,
  ].filter((value) => value.length > 0);
  if (configured.length === 0) return;
  if (configured.length !== 3) {
    throw new Error(
      "HALOMEM_MANAGED_ANTHROPIC_MODEL, _BASE_URL and _API_KEY must be set together",
    );
  }
  if (config.managedAnthropicModel.length > 300) {
    throw new Error("HALOMEM_MANAGED_ANTHROPIC_MODEL is invalid");
  }
  if (!config.managedAnthropicLabel.trim() || config.managedAnthropicLabel.length > 120) {
    throw new Error("HALOMEM_MANAGED_ANTHROPIC_LABEL is invalid");
  }
  const base = secureUrl(config.managedAnthropicBaseUrl, "HALOMEM_MANAGED_ANTHROPIC_BASE_URL");
  if (base.search || base.hash) {
    throw new Error("HALOMEM_MANAGED_ANTHROPIC_BASE_URL cannot contain query or fragment");
  }
}

function secureUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(`${label} must be a credential-free HTTPS URL`);
  }
  return url;
}
