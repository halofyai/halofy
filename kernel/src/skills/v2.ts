/**
 * v2 lane resolution (CONTRACTS-S16-VETTING-V2.md, D35).
 *
 * Builds the SkillVettingLanes for a booted kernel from config + environment
 * availability: the LLM lane when a scan model is configured (the
 * OpenAI-compatible triple — Kimi `k3` per the 2026-07-19 decision — takes
 * precedence over the Azure deployment), each external scanner when its
 * pinned CLI probes present. The scanners' own LLM analyzers share the SAME
 * endpoint and key via OPENAI_BASE_URL / SKILL_SCANNER_LLM_BASE_URL — one
 * key surface for the whole pipeline. Absence is never an error here — the
 * D35 ladder in vetting.ts decides what a missing lane means. Tests inject
 * lanes via the `skillVettingV2Lanes` config seam instead of probing.
 */

import type { KernelConfig } from "../config.js";
import { trimTrailingRepeatedCharacter } from "../strings.js";
import {
  CISCO_SPEC,
  SKILLSPECTOR_SPEC,
  createNodeProcessRunner,
  probeExternalLane,
  type ProcessRunner,
  type ScannerLlmOptions,
} from "./external.js";
import {
  AzureOpenAiScanClient,
  LlmSkillScanLane,
  OpenAiCompatibleScanClient,
} from "./llm-scan.js";
import type { SkillVettingLanes } from "./vetting.js";

interface ScanProvider {
  /** Base URL the scanners' openai-compatible providers use. */
  baseUrl: string;
  apiKey: string;
  model: string;
  /** engine_versions stamp for the kernel's own llm lane. */
  stamp: string;
}

/** The configured scan provider, or null when no scan model is configured. */
function scanProvider(config: KernelConfig): ScanProvider | null {
  if (config.skillScanLlmBaseUrl && config.skillScanLlmApiKey && config.skillScanLlmModel) {
    const base = trimTrailingRepeatedCharacter(config.skillScanLlmBaseUrl, "/");
    const host = /^https?:\/\/([^/]+)/.exec(base)?.[1] ?? base;
    return {
      baseUrl: base,
      apiKey: config.skillScanLlmApiKey,
      model: config.skillScanLlmModel,
      stamp: `openai-compatible:${config.skillScanLlmModel}@${host}`,
    };
  }
  if (
    config.azureOpenaiScanApiKey &&
    config.azureOpenaiScanEndpoint &&
    config.azureOpenaiScanDeployment
  ) {
    const base = `${trimTrailingRepeatedCharacter(config.azureOpenaiScanEndpoint, "/")}/openai/v1/`;
    return {
      baseUrl: base,
      apiKey: config.azureOpenaiScanApiKey,
      model: config.azureOpenaiScanDeployment,
      stamp: `azure-openai-scan@${config.azureOpenaiScanDeployment}`,
    };
  }
  return null;
}

/** Per-engine env pointing the scanner's LLM analyzer at the shared provider. */
function scannerLlmOptions(lane: "cisco" | "skillspector", provider: ScanProvider): ScannerLlmOptions {
  if (lane === "cisco") {
    return {
      env: {
        SKILL_SCANNER_LLM_API_KEY: provider.apiKey,
        SKILL_SCANNER_LLM_BASE_URL: provider.baseUrl,
        SKILL_SCANNER_LLM_MODEL: provider.model,
        // Kimi k3 rejects any temperature parameter; "none" makes the
        // scanner omit it (cisco 2.0.12 _resolve_temperature omit list).
        SKILL_SCANNER_LLM_TEMPERATURE: "none",
      },
    };
  }
  return {
    env: {
      SKILLSPECTOR_PROVIDER: "openai",
      OPENAI_API_KEY: provider.apiKey,
      OPENAI_BASE_URL: provider.baseUrl,
      SKILLSPECTOR_MODEL: provider.model,
    },
  };
}

export async function resolveVettingLanes(
  config: KernelConfig,
  runner: ProcessRunner = createNodeProcessRunner(),
): Promise<SkillVettingLanes> {
  const lanes: SkillVettingLanes = {};
  const provider = scanProvider(config);

  if (provider) {
    const client =
      config.skillScanLlmBaseUrl && config.skillScanLlmApiKey && config.skillScanLlmModel
        ? new OpenAiCompatibleScanClient(provider.apiKey, provider.baseUrl, provider.model)
        : new AzureOpenAiScanClient(
            provider.apiKey,
            config.azureOpenaiScanEndpoint,
            config.azureOpenaiScanDeployment,
            config.azureOpenaiApiVersion,
          );
    lanes.llm = new LlmSkillScanLane(client, provider.stamp);
  }

  const [cisco, skillspector] = await Promise.all([
    probeExternalLane(
      CISCO_SPEC, runner, provider ? scannerLlmOptions("cisco", provider) : undefined,
    ).catch(() => null),
    probeExternalLane(
      SKILLSPECTOR_SPEC, runner, provider ? scannerLlmOptions("skillspector", provider) : undefined,
    ).catch(() => null),
  ]);
  if (cisco) lanes.cisco = cisco;
  if (skillspector) lanes.skillspector = skillspector;
  return lanes;
}
