/**
 * Config tests — embedDim must always match the embedder selected by the
 * EFFECTIVE openaiApiKey (env or override), or migrate() creates vector(N)
 * columns that mismatch the embedder dimension and every write/search fails.
 */

import { describe, it, expect } from "vitest";
import { assertSupportedDeployment, loadConfig } from "../src/config.js";

describe("conflict classifier model routing", () => {
  it("prefers the dedicated Halo-owned GPT-5.6 Luna resource without moving skill vetting", () => {
    const previousConflict = process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
    const previousEndpoint = process.env.AZURE_OPENAI_CONFLICT_ENDPOINT;
    const previousKey = process.env.AZURE_OPENAI_CONFLICT_API_KEY;
    const previousScan = process.env.AZURE_OPENAI_SCAN_DEPLOYMENT;
    process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT = "gpt-5.6-luna-1";
    process.env.AZURE_OPENAI_CONFLICT_ENDPOINT = "https://halo-tech-resource.cognitiveservices.azure.com/";
    process.env.AZURE_OPENAI_CONFLICT_API_KEY = "halo-owned-test-key";
    process.env.AZURE_OPENAI_SCAN_DEPLOYMENT = "gpt-5.5-1";
    try {
      const config = loadConfig();
      expect(config.azureOpenaiConflictDeployment).toBe("gpt-5.6-luna-1");
      expect(config.azureOpenaiConflictEndpoint).toContain("halo-tech-resource");
      expect(config.azureOpenaiConflictApiKey).toBe("halo-owned-test-key");
      expect(config.azureOpenaiScanDeployment).toBe("gpt-5.5-1");
    } finally {
      if (previousConflict === undefined) delete process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
      else process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT = previousConflict;
      if (previousEndpoint === undefined) delete process.env.AZURE_OPENAI_CONFLICT_ENDPOINT;
      else process.env.AZURE_OPENAI_CONFLICT_ENDPOINT = previousEndpoint;
      if (previousKey === undefined) delete process.env.AZURE_OPENAI_CONFLICT_API_KEY;
      else process.env.AZURE_OPENAI_CONFLICT_API_KEY = previousKey;
      if (previousScan === undefined) delete process.env.AZURE_OPENAI_SCAN_DEPLOYMENT;
      else process.env.AZURE_OPENAI_SCAN_DEPLOYMENT = previousScan;
    }
  });

  it("keeps the existing scan deployment as a backwards-compatible conflict fallback", () => {
    const previousConflict = process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
    const previousScan = process.env.AZURE_OPENAI_SCAN_DEPLOYMENT;
    delete process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
    process.env.AZURE_OPENAI_SCAN_DEPLOYMENT = "legacy-scan-deployment";
    try {
      expect(loadConfig().azureOpenaiConflictDeployment).toBe("legacy-scan-deployment");
    } finally {
      if (previousConflict === undefined) delete process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
      else process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT = previousConflict;
      if (previousScan === undefined) delete process.env.AZURE_OPENAI_SCAN_DEPLOYMENT;
      else process.env.AZURE_OPENAI_SCAN_DEPLOYMENT = previousScan;
    }
  });

  it("rejects a partially configured conflict resource instead of mixing Azure accounts", () => {
    const previous = process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
    const previousEndpoint = process.env.AZURE_OPENAI_CONFLICT_ENDPOINT;
    const previousKey = process.env.AZURE_OPENAI_CONFLICT_API_KEY;
    process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT = "gpt-5.6-luna-1";
    delete process.env.AZURE_OPENAI_CONFLICT_ENDPOINT;
    delete process.env.AZURE_OPENAI_CONFLICT_API_KEY;
    try {
      expect(() => loadConfig()).toThrow(/must be configured together/);
    } finally {
      if (previous === undefined) delete process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT;
      else process.env.AZURE_OPENAI_CONFLICT_DEPLOYMENT = previous;
      if (previousEndpoint === undefined) delete process.env.AZURE_OPENAI_CONFLICT_ENDPOINT;
      else process.env.AZURE_OPENAI_CONFLICT_ENDPOINT = previousEndpoint;
      if (previousKey === undefined) delete process.env.AZURE_OPENAI_CONFLICT_API_KEY;
      else process.env.AZURE_OPENAI_CONFLICT_API_KEY = previousKey;
    }
  });
});

describe("loadConfig embedDim / openaiApiKey coupling", () => {
  it("overriding openaiApiKey alone selects the matching embedDim", () => {
    // OpenAI embedder (dim 1536) regardless of what the env var says.
    expect(loadConfig({ openaiApiKey: "sk-test" }).embedDim).toBe(1536);
    // Forcing offline mode selects the HashEmbedder dim (256).
    expect(loadConfig({ openaiApiKey: "" }).embedDim).toBe(256);
  });

  it("an explicit embedDim override still wins", () => {
    expect(loadConfig({ openaiApiKey: "sk-test", embedDim: 256 }).embedDim).toBe(256);
    expect(loadConfig({ openaiApiKey: "", embedDim: 1536 }).embedDim).toBe(1536);
  });
});

describe("loadConfig Azure Mastra V2 harness", () => {
  it("loads an explicitly complete shared-harness configuration", () => {
    const config = loadConfig({
      mastraV2RuntimeBaseUrl: "https://mastra.example.test",
      mastraV2InternalApiToken: "internal-token",
      mastraV2CapabilitySecret: "capability-secret-with-at-least-thirty-two-bytes",
      mastraV2PublicMcpUrl: "https://memory.example.test/mcp",
      mastraV2ManagedModel: "gpt-5-mini",
      mastraV2TimeoutMs: 30_000,
    });

    expect(config.mastraV2RuntimeBaseUrl).toBe("https://mastra.example.test");
    expect(config.mastraV2ManagedModel).toBe("gpt-5-mini");
  });

  it("fails closed for a partially configured shared harness", () => {
    expect(() => loadConfig({
      mastraV2RuntimeBaseUrl: "https://mastra.example.test",
    })).toThrow(/Mastra V2/);
  });

  it("rejects unsafe harness and MCP endpoints", () => {
    const common = {
      mastraV2InternalApiToken: "internal-token",
      mastraV2CapabilitySecret: "capability-secret-with-at-least-thirty-two-bytes",
      mastraV2ManagedModel: "gpt-5-mini",
      mastraV2TimeoutMs: 30_000,
    };
    expect(() => loadConfig({
      ...common,
      mastraV2RuntimeBaseUrl: "http://127.0.0.1:8789",
      mastraV2PublicMcpUrl: "https://memory.example.test/mcp",
    })).toThrow(/HTTPS/);
    expect(() => loadConfig({
      ...common,
      mastraV2RuntimeBaseUrl: "https://mastra.example.test",
      mastraV2PublicMcpUrl: "https://memory.example.test/v1/admin",
    })).toThrow(/\/mcp/);
  });
});

describe("loadConfig Anthropic platform default", () => {
  const COMPLETE = {
    managedAnthropicModel: "claude-sonnet-5-1",
    managedAnthropicBaseUrl:
      "https://halo-tech-resource.cognitiveservices.azure.com/anthropic/v1",
    managedAnthropicApiKey: "platform-anthropic-key",
  };

  it("stays off when nothing is configured", () => {
    expect(loadConfig({ managedAnthropicModel: "" }).managedAnthropicModel).toBe("");
  });

  it("loads a complete configuration and defaults the picker label", () => {
    const config = loadConfig(COMPLETE);
    expect(config.managedAnthropicModel).toBe("claude-sonnet-5-1");
    expect(config.managedAnthropicLabel).toBe("Claude Sonnet 5");
  });

  it("fails closed rather than publishing a half-configured default to every tenant", () => {
    expect(() => loadConfig({
      managedAnthropicModel: COMPLETE.managedAnthropicModel,
      managedAnthropicBaseUrl: COMPLETE.managedAnthropicBaseUrl,
      managedAnthropicApiKey: "",
    })).toThrow(/set together/);
  });

  it("rejects an unsafe or credential-bearing base URL", () => {
    expect(() => loadConfig({
      ...COMPLETE,
      managedAnthropicBaseUrl: "http://127.0.0.1:8080/anthropic/v1",
    })).toThrow(/HTTPS/);
    expect(() => loadConfig({
      ...COMPLETE,
      managedAnthropicBaseUrl: "https://foundry.example.test/anthropic/v1?api-version=2026-05-01",
    })).toThrow(/query or fragment/);
  });
});

describe("Nango proxy configuration", () => {
  it("keeps connect and proxy keys server-only and defaults the free validation cap to ten", () => {
    const config = loadConfig({
      nangoConnectApiKey: "connect-test-key",
      nangoProxyApiKey: "proxy-test-key",
      nangoEnvironmentId: "dev",
      nangoIntegrations: { shopify: "shopify" },
    });

    expect(config.nangoConnectApiKey).toBe("connect-test-key");
    expect(config.nangoProxyApiKey).toBe("proxy-test-key");
    expect(config.nangoConnectionLimit).toBe(10);
    expect(config.nangoEnvironmentId).toBe("dev");
    expect(config.nangoIntegrations).toEqual({ shopify: "shopify" });
  });

  it("requires a stable environment identifier when managed integrations are configured", () => {
    expect(() => loadConfig({
      nangoConnectApiKey: "connect-test-key",
      nangoProxyApiKey: "proxy-test-key",
      nangoEnvironmentId: "",
      nangoIntegrations: { shopify: "shopify" },
    })).toThrow(/NANGO_ENVIRONMENT_ID/);
  });

  it("rejects a disabled or malformed local connection guard", () => {
    expect(() => loadConfig({ nangoConnectionLimit: 0 })).toThrow(/integer/);
    expect(() => loadConfig({ nangoConnectionLimit: 1.5 })).toThrow(/integer/);
  });
});

describe("direct Notion OAuth configuration", () => {
  it("accepts the client pair only when both server-side values are present", () => {
    expect(loadConfig({
      notionClientId: "notion-client",
      notionClientSecret: "notion-secret",
    })).toMatchObject({
      notionClientId: "notion-client",
      notionClientSecret: "notion-secret",
    });
    expect(() => loadConfig({
      notionClientId: "notion-client",
      notionClientSecret: "",
    })).toThrow(/HALOMEM_NOTION_CLIENT_ID.*HALOMEM_NOTION_CLIENT_SECRET/);
    expect(() => loadConfig({
      notionClientId: "",
      notionClientSecret: "notion-secret",
    })).toThrow(/HALOMEM_NOTION_CLIENT_ID.*HALOMEM_NOTION_CLIENT_SECRET/);
  });
});

describe("direct Airtable OAuth configuration", () => {
  it("accepts the client pair only when both server-side values are present", () => {
    expect(loadConfig({
      airtableClientId: "airtable-client",
      airtableClientSecret: "airtable-secret",
    })).toMatchObject({
      airtableClientId: "airtable-client",
      airtableClientSecret: "airtable-secret",
    });
    expect(() => loadConfig({
      airtableClientId: "airtable-client",
      airtableClientSecret: "",
    })).toThrow(/HALOMEM_AIRTABLE_CLIENT_ID.*HALOMEM_AIRTABLE_CLIENT_SECRET/);
    expect(() => loadConfig({
      airtableClientId: "",
      airtableClientSecret: "airtable-secret",
    })).toThrow(/HALOMEM_AIRTABLE_CLIENT_ID.*HALOMEM_AIRTABLE_CLIENT_SECRET/);
  });
});

describe("direct Google Drive OAuth configuration", () => {
  it("uses a dedicated server-side client pair and fails closed when partial", () => {
    expect(loadConfig({
      googleDriveClientId: "drive-client",
      googleDriveClientSecret: "drive-secret",
    })).toMatchObject({
      googleDriveClientId: "drive-client",
      googleDriveClientSecret: "drive-secret",
    });
    expect(() => loadConfig({
      googleDriveClientId: "drive-client", googleDriveClientSecret: "",
    })).toThrow(/HALOMEM_GOOGLE_DRIVE_CLIENT_ID.*HALOMEM_GOOGLE_DRIVE_CLIENT_SECRET/);
    expect(() => loadConfig({
      googleDriveClientId: "", googleDriveClientSecret: "drive-secret",
    })).toThrow(/HALOMEM_GOOGLE_DRIVE_CLIENT_ID.*HALOMEM_GOOGLE_DRIVE_CLIENT_SECRET/);
  });
});

describe("managed Google Chat configuration", () => {
  const complete = {
    channelGoogleChatProjectNumber: "123456789",
    channelGoogleChatInstallUrl: "https://workspace.google.com/marketplace/app/halofy/123",
    channelGoogleChatRouteKey: "managed-google-chat-route-key",
    channelGoogleChatServiceAccountJson: JSON.stringify({
      client_email: "halofy@example.iam.gserviceaccount.com",
      private_key: "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----",
    }),
  };

  const federated = {
    channelGoogleChatProjectNumber: "385356623358",
    channelGoogleChatInstallUrl: "https://chat.google.com/",
    channelGoogleChatRouteKey: "managed-google-chat-route-key",
    channelGoogleChatServiceAccountJson: "",
    channelGoogleChatAzureClientId: "2797aa92-d773-4cd8-a8c3-8185fe09cc3e",
    channelGoogleChatAzureAppIdUri: "api://halofy-google-chat",
    channelGoogleChatWorkloadIdentityProvider:
      "projects/385356623358/locations/global/workloadIdentityPools/halofy-azure/providers/halomem-kernel",
    channelGoogleChatServiceAccountEmail:
      "halofy-chat-runtime@halofy-chat-a813-7f3c9b.iam.gserviceaccount.com",
    channelGoogleChatAzureIdentityEndpoint: "http://localhost:42356/msi/token/",
    channelGoogleChatAzureIdentityHeader: "platform-injected-header",
  };

  it("accepts only the complete deployment-owned credential set", () => {
    expect(loadConfig(complete)).toMatchObject(complete);
    expect(loadConfig(federated)).toMatchObject(federated);
    expect(() => loadConfig({
      ...complete,
      channelGoogleChatServiceAccountJson: "",
    })).toThrow(/requires project number, install URL, route key, and exactly one complete authentication method/);
    expect(() => loadConfig({
      ...federated,
      channelGoogleChatServiceAccountEmail: "",
    })).toThrow(/all four Azure federation values/);
    expect(() => loadConfig({
      ...federated,
      channelGoogleChatServiceAccountJson: complete.channelGoogleChatServiceAccountJson,
    })).toThrow(/exactly one complete authentication method/);
  });

  it("rejects non-HTTPS install URLs and short route keys", () => {
    expect(() => loadConfig({
      ...complete,
      channelGoogleChatInstallUrl: "http://workspace.google.test/install",
    })).toThrow(/must use https/);
    expect(() => loadConfig({
      ...complete,
      channelGoogleChatRouteKey: "short",
    })).toThrow(/opaque 16-128 character key/);
  });
});

describe("enterprise deployment guard", () => {
  it("rejects stateful kernel boot inside ephemeral serverless functions", () => {
    const config = loadConfig({ databaseUrl: "postgres://example/halomem" });
    expect(() => assertSupportedDeployment(config, { VERCEL: "1" })).toThrow(
      /serverless/i,
    );
    expect(() => assertSupportedDeployment(config, { AWS_LAMBDA_FUNCTION_NAME: "fn" })).toThrow(
      /serverless/i,
    );
  });

  it("requires external Postgres and stable keys in production", () => {
    expect(() => assertSupportedDeployment(loadConfig({ databaseUrl: "" }), {
      NODE_ENV: "production",
    })).toThrow(/DATABASE_URL/);
    expect(() => assertSupportedDeployment(loadConfig({
      databaseUrl: "postgres://example/halomem",
      coldKek: "",
      sourceConfigKek: "",
    }), { NODE_ENV: "production" })).toThrow(/sslmode=verify-full/);
  });

  it("requires stable keys after certificate-verified Postgres", () => {
    expect(() => assertSupportedDeployment(loadConfig({
      databaseUrl: "postgres://example/halomem?sslmode=verify-full",
      coldKek: "",
      sourceConfigKek: "",
    }), { NODE_ENV: "production" })).toThrow(/HALOMEM_COLD_KEK/);
  });

  it("requires model credential encryption before production can accept BYOK keys", () => {
    expect(() => assertSupportedDeployment(loadConfig({
      databaseUrl: "postgres://example/halomem?sslmode=verify-full",
      coldKek: "cold-kek",
      sourceConfigKek: "source-kek",
      modelCredentialKek: "",
    }), {
      NODE_ENV: "production",
      HALOMEM_SIGNING_KEY: "stable-signing-key",
      HALOMEM_COLD_STORAGE: "shared-persistent",
    })).toThrow(/HALOMEM_MODEL_CREDENTIAL_KEK/);

    expect(() => assertSupportedDeployment(loadConfig({
      databaseUrl: "postgres://example/halomem?sslmode=verify-full",
      coldKek: "cold-kek",
      sourceConfigKek: "source-kek",
      modelCredentialKek: "not-a-canonical-key",
    }), {
      NODE_ENV: "production",
      HALOMEM_SIGNING_KEY: "stable-signing-key",
      HALOMEM_COLD_STORAGE: "shared-persistent",
    })).toThrow(/canonical base64 32-byte key/);
  });
});
