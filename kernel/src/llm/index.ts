/**
 * Module E — LLM clients + prompt templates.
 *
 * StubLlm: deterministic, zero-network client used whenever no
 * ANTHROPIC_API_KEY is configured (and in all tests). It recognizes the
 * prompt kind by a marker string embedded in the system prompt.
 *
 * AnthropicLlm: real client over the Anthropic Messages API.
 */

import type { DisputeCategory, LlmClient, LlmUsage } from "../types.js";
import type { KernelConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Prompt-kind markers (StubLlm dispatches on these)
// ---------------------------------------------------------------------------

export const EXTRACT_MARKER = "[HALOMEM-EXTRACT]";
export const VERIFY_MARKER = "[HALOMEM-VERIFY]";
export const VERIFY_BATCH_MARKER = "[HALOMEM-VERIFY-BATCH]";
export const ENTITY_MARKER = "[HALOMEM-ENTITY-TIEBREAK]";
export const CLASSIFY_MARKER = "[HALOMEM-DISPUTE-CATEGORY]";
export const RELATIONSHIP_MARKER = "[HALOMEM-RELATIONSHIP-TYPE]";

// ---------------------------------------------------------------------------
// Prompt templates
// ---------------------------------------------------------------------------

export const EXTRACT_SYSTEM = `${EXTRACT_MARKER} You extract atomic facts from a conversation transcript.
Rules:
- One fact per distinct assertion; keep each fact self-contained and close to the source wording.
- Extract durable claims about the organization, people, products, policies, or events. Do not create facts about the document itself, such as its filename, title, heading, test marker, sensitivity label, or business-function metadata.
- Speaker attribution matters: facts stated by the user are "user" facts; facts stated by the assistant are "assistant" facts. Keep them distinct - never merge across speakers.
- Bi-temporal: if the transcript states WHEN a fact became true in the world, set "eventTime" to that ISO-8601 timestamp; otherwise use null. Do not confuse event time with the time of the conversation.
- List the proper-noun entities mentioned in each fact.
- Output STRICT JSON: an array of objects of the shape
  {"content": string, "speaker": "user" | "assistant", "eventTime": string | null, "entities": string[], "confidence": number}
No prose, no code fences, no trailing commentary.`;

export const VERIFY_SYSTEM = `${VERIFY_MARKER} You are a strict verifier. Given a transcript and a candidate fact, decide whether the fact is actually stated in the transcript with this timestamp. Reject inferences, embellishments, and anything not grounded in the transcript text.
Output STRICT JSON: {"verified": boolean, "reason": string}. No prose, no code fences.`;

export const VERIFY_BATCH_SYSTEM = `${VERIFY_BATCH_MARKER} You are a strict verifier. Given a transcript and a JSON array of candidate facts, decide FOR EACH candidate whether it is actually stated in the transcript with this timestamp. Judge every candidate independently. Reject inferences, embellishments, and anything not grounded in the transcript text.
Output STRICT JSON: an array with exactly one entry per candidate, of the shape
  {"id": number, "verified": boolean}
using each candidate's given id. No prose, no code fences, no trailing commentary.`;

export const ENTITY_SYSTEM = `${ENTITY_MARKER} You decide whether two entity names refer to the same real-world entity (e.g. an alias, abbreviation, or alternative spelling of the same person/company/place).
Output STRICT JSON: {"same": boolean}. No prose, no code fences.`;

export const CLASSIFY_SYSTEM = `${CLASSIFY_MARKER} You label a factual conflict for a human review queue. Given two conflicting facts, pick the single best team bucket:
- "policies-legal": policies, refunds, terms, warranties, compliance, legal.
- "order-management": orders, shipping, delivery, returns processing, invoices.
- "product-info": product features, pricing, specifications, availability.
- "other": anything else.
Output STRICT JSON: {"category": "policies-legal" | "order-management" | "product-info" | "other"}. No prose, no code fences.`;

// ---------------------------------------------------------------------------
// Prompt builders (the write path uses these; StubLlm parses the same format)
// ---------------------------------------------------------------------------

export function buildVerifyPrompt(
  transcript: string,
  candidate: string,
  timestamp: string,
): string {
  return `TRANSCRIPT:\n<<<\n${transcript}\n>>>\nCANDIDATE FACT:\n<<<\n${candidate}\n>>>\nTIMESTAMP: ${timestamp}`;
}

/**
 * Batched verification: all of one document's candidates in a single prompt.
 * Candidates are serialized as JSON (not numbered lines) so multi-line fact
 * text can never break the framing, and the ids echo back in the response.
 * Ids are 1-based positions within THIS prompt's array.
 */
export function buildVerifyBatchPrompt(
  transcript: string,
  candidates: readonly string[],
  timestamp: string,
): string {
  const items = candidates.map((content, index) => ({ id: index + 1, content }));
  return `TRANSCRIPT:\n<<<\n${transcript}\n>>>\nCANDIDATE FACTS (JSON):\n<<<\n${JSON.stringify(items)}\n>>>\nTIMESTAMP: ${timestamp}`;
}

export function buildEntityPrompt(a: string, b: string): string {
  return `ENTITY A: ${a}\nENTITY B: ${b}`;
}

export function buildClassifyPrompt(newFact: string, incumbentFact: string): string {
  return `DISPUTED CLAIM:\n<<<\n${newFact}\n>>>\nCURRENT FACT:\n<<<\n${incumbentFact}\n>>>`;
}

// ---------------------------------------------------------------------------
// Shared shapes & defensive JSON parsing
// ---------------------------------------------------------------------------

/** Shape emitted by the EXTRACT prompt (and by StubLlm). */
export interface ExtractedFact {
  content: string;
  speaker: "user" | "assistant";
  eventTime: string | null;
  entities: string[];
  confidence: number;
}

/**
 * Parse LLM output defensively: strip code fences, slice from the first
 * '{'/'[' to the last '}'/']', JSON.parse. Returns null on failure.
 */
export function parseLooseJson(text: string): unknown {
  const cleaned = text.replace(/```[a-zA-Z]*\r?\n?/g, "").replace(/```/g, "");
  const firstObj = cleaned.indexOf("{");
  const firstArr = cleaned.indexOf("[");
  let start = -1;
  let end = -1;
  if (firstArr !== -1 && (firstObj === -1 || firstArr < firstObj)) {
    start = firstArr;
    end = cleaned.lastIndexOf("]");
  } else if (firstObj !== -1) {
    start = firstObj;
    end = cleaned.lastIndexOf("}");
  }
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1)) as unknown;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// StubLlm — deterministic, zero network
// ---------------------------------------------------------------------------

const DIALOGUE_LINE = /^([A-Za-z][A-Za-z0-9 _.-]{0,40}?):\s+(.+)$/;
const ASSISTANT_LABELS = new Set([
  "assistant",
  "ai",
  "bot",
  "agent",
  "system",
  "claude",
]);

/**
 * Deterministic proper-noun entity mentions in a piece of text: distinct
 * capitalized words, in first-seen order. This is the SAME heuristic the stub
 * extractor uses for conversation facts, exported so the write path's verbatim
 * lane (imports + brownout/LLM-outage fallback) can derive entity mentions
 * without an LLM call — otherwise verbatim facts land with entities:[] and are
 * invisible to entity-grouped contradiction detection.
 */
export function capitalizedWords(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of text.matchAll(/\b[A-Z][a-zA-Z]+\b/g)) {
    if (!seen.has(m[0])) {
      seen.add(m[0]);
      out.push(m[0]);
    }
  }
  return out;
}

/** Lowercase, alphanumeric + spaces only. */
function normalizeForVerify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

const DISPUTE_CATEGORY_KEYWORDS: readonly [DisputeCategory, readonly string[]][] = [
  [
    "policies-legal",
    ["policy", "policies", "refund", "terms", "warranty", "legal", "compliance", "gdpr", "contract"],
  ],
  [
    "order-management",
    ["order", "orders", "shipping", "shipment", "delivery", "return", "invoice", "tracking"],
  ],
  [
    "product-info",
    ["product", "price", "pricing", "feature", "spec", "specification", "availability", "stock", "menu", "item"],
  ],
];

/**
 * Deterministic dispute-category classifier: first keyword bucket with the
 * most hits wins; no hits → "other". Used by StubLlm and by the write path's
 * verbatim/brownout lanes, which must classify without an LLM call.
 */
export function heuristicDisputeCategory(text: string): DisputeCategory {
  const normalized = ` ${normalizeForVerify(text)} `;
  let best: DisputeCategory = "other";
  let bestHits = 0;
  for (const [category, keywords] of DISPUTE_CATEGORY_KEYWORDS) {
    let hits = 0;
    for (const kw of keywords) {
      if (normalized.includes(` ${kw} `)) hits += 1;
    }
    if (hits > bestHits) {
      best = category;
      bestHits = hits;
    }
  }
  return best;
}

export class StubLlm implements LlmClient {
  readonly name = "stub";

  async complete(system: string, user: string): Promise<string> {
    if (system.includes(EXTRACT_MARKER)) {
      return JSON.stringify(this.extract(user));
    }
    if (system.includes(VERIFY_BATCH_MARKER)) {
      return JSON.stringify(this.verifyBatch(user));
    }
    if (system.includes(VERIFY_MARKER)) {
      return JSON.stringify(this.verify(user));
    }
    if (system.includes(ENTITY_MARKER)) {
      return JSON.stringify({ same: false });
    }
    if (system.includes(CLASSIFY_MARKER)) {
      return JSON.stringify({ category: heuristicDisputeCategory(user) });
    }
    if (system.includes(RELATIONSHIP_MARKER)) {
      return JSON.stringify(this.relationship(user));
    }
    return "{}";
  }

  private relationship(user: string): Record<string, unknown> {
    const match = /<<<RELATIONSHIP_CANDIDATE_JSON\s*\n([\s\S]*?)\nRELATIONSHIP_CANDIDATE_JSON/.exec(user);
    let parsed: unknown;
    try {
      parsed = match?.[1] ? JSON.parse(match[1]) as unknown : null;
    } catch {
      parsed = null;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const candidate = parsed as Record<string, unknown>;
    const subjectEntityId = candidate.subjectEntityId;
    const objectEntityId = candidate.objectEntityId;
    const evidenceMemoryIds = candidate.evidenceMemoryIds;
    const signals = candidate.deterministicSignals;
    if (
      typeof subjectEntityId !== "string" ||
      typeof objectEntityId !== "string" ||
      !Array.isArray(evidenceMemoryIds) ||
      !evidenceMemoryIds.every((id) => typeof id === "string") ||
      !Array.isArray(signals) ||
      !signals.every((signal) => typeof signal === "string")
    ) {
      return {};
    }
    const strong = signals.some((signal) =>
      signal === "shared_stable_id" ||
      signal === "shared_sku" ||
      signal === "shared_public_https_url" ||
      signal === "shared_canonical_name"
    );
    return {
      decision: strong ? "accept" : "reject",
      subjectEntityId,
      objectEntityId,
      relationship: strong ? "same_as" : null,
      confidence: strong ? 0.95 : 0,
      evidenceMemoryIds,
    };
  }

  private extract(transcript: string): ExtractedFact[] {
    const facts: ExtractedFact[] = [];
    for (const rawLine of transcript.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0) continue;
      const m = DIALOGUE_LINE.exec(line);
      if (!m) continue;
      const label = m[1]!.trim().toLowerCase();
      const utterance = m[2]!.trim();
      facts.push({
        content: utterance,
        speaker: ASSISTANT_LABELS.has(label) ? "assistant" : "user",
        eventTime: null,
        entities: capitalizedWords(utterance),
        confidence: 0.9,
      });
    }
    if (facts.length === 0) {
      // Non-dialogue input → single user fact.
      facts.push({
        content: transcript.trim(),
        speaker: "user",
        eventTime: null,
        entities: capitalizedWords(transcript),
        confidence: 0.9,
      });
    }
    return facts;
  }

  private verify(user: string): { verified: boolean; reason: string } {
    const tm = /TRANSCRIPT:\s*<<<([\s\S]*?)>>>/.exec(user);
    const cm = /CANDIDATE FACT:\s*<<<([\s\S]*?)>>>/.exec(user);
    const transcript = tm?.[1] ?? user;
    const candidate = cm?.[1] ?? "";
    const transcriptWords = new Set(
      normalizeForVerify(transcript).split(/\s+/).filter(Boolean),
    );
    return StubLlm.grounded(transcriptWords, candidate);
  }

  /** Same word-overlap heuristic as `verify`, applied per batched candidate. */
  private verifyBatch(user: string): { id: number; verified: boolean }[] {
    const tm = /TRANSCRIPT:\s*<<<([\s\S]*?)>>>/.exec(user);
    const cm = /CANDIDATE FACTS \(JSON\):\s*<<<([\s\S]*?)>>>/.exec(user);
    const transcript = tm?.[1] ?? user;
    let items: unknown;
    try {
      items = JSON.parse(cm?.[1]?.trim() ?? "[]");
    } catch {
      items = [];
    }
    if (!Array.isArray(items)) return [];
    const transcriptWords = new Set(
      normalizeForVerify(transcript).split(/\s+/).filter(Boolean),
    );
    return items.flatMap((item) => {
      if (item === null || typeof item !== "object") return [];
      const { id, content } = item as { id?: unknown; content?: unknown };
      if (typeof id !== "number" || typeof content !== "string") return [];
      return [{ id, verified: StubLlm.grounded(transcriptWords, content).verified }];
    });
  }

  private static grounded(
    transcriptWords: ReadonlySet<string>,
    candidate: string,
  ): { verified: boolean; reason: string } {
    const candidateWords = normalizeForVerify(candidate)
      .split(/\s+/)
      .filter(Boolean);
    if (candidateWords.length === 0) {
      return { verified: true, reason: "empty candidate" };
    }
    const present = candidateWords.filter((w) => transcriptWords.has(w)).length;
    const ratio = present / candidateWords.length;
    return ratio >= 0.8
      ? { verified: true, reason: `grounded (${present}/${candidateWords.length} words present)` }
      : { verified: false, reason: `not grounded (${present}/${candidateWords.length} words present)` };
  }
}

// ---------------------------------------------------------------------------
// AnthropicLlm — real client (only constructed when an API key is present)
// ---------------------------------------------------------------------------

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_MODEL = "claude-haiku-4-5-20251001";
const ANTHROPIC_VERSION = "2023-06-01";
const ANTHROPIC_MAX_TOKENS = 1024;

interface AnthropicContentBlock {
  type: string;
  text?: string;
}

interface AnthropicResponse {
  content: AnthropicContentBlock[];
  usage?: { input_tokens?: number; output_tokens?: number };
}

export class AnthropicLlm implements LlmClient {
  readonly name = "anthropic";

  constructor(
    private readonly apiKey: string,
    private readonly model: string = ANTHROPIC_MODEL,
  ) {}

  async complete(
    system: string,
    user: string,
    opts?: { signal?: AbortSignal; onUsage?: (usage: LlmUsage) => void },
  ): Promise<string> {
    const res = await fetch(ANTHROPIC_URL, {
      method: "POST",
      signal: opts?.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: ANTHROPIC_MAX_TOKENS,
        system,
        messages: [{ role: "user", content: user }],
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`anthropic api error ${res.status}: ${body}`);
    }
    const data = (await res.json()) as AnthropicResponse;
    reportUsage(opts?.onUsage, data.usage?.input_tokens, data.usage?.output_tokens);
    return data.content
      .filter((b) => b.type === "text")
      .map((b) => b.text ?? "")
      .join("");
  }
}

// ---------------------------------------------------------------------------
// AzureOpenAiLlm — real client over an Azure OpenAI chat deployment
// ---------------------------------------------------------------------------

interface AzureChatChoice {
  message?: { content?: string };
}

interface AzureChatResponse {
  choices: AzureChatChoice[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

/** Forward provider-reported usage to the caller when the response carries it. */
function reportUsage(
  onUsage: ((usage: { inputTokens: number; outputTokens: number }) => void) | undefined,
  input: number | undefined,
  output: number | undefined,
): void {
  if (!onUsage || typeof input !== "number" || typeof output !== "number") return;
  try {
    onUsage({ inputTokens: input, outputTokens: output });
  } catch {
    // Accounting must never fail a successful completion.
  }
}

/**
 * Reasoning deployments (GPT-5.5/5.6) spend the completion budget on reasoning
 * tokens BEFORE emitting content. When the budget runs out mid-answer the
 * request returns empty or truncated `content`, which the extractor reads as
 * "no facts" and silently degrades to a verbatim write — an outage that looks
 * like a working pipeline. 4096 was sized for non-reasoning models and caused
 * exactly that outage on multi-KB documents: reasoning tokens plus a long fact
 * list overran it. Pinned to the completion ceiling reasoning deployments
 * advertise — they reject anything above 128000 ("This model supports at most
 * 128000 completion tokens"). Spend is bounded by tokens actually generated,
 * not by the cap.
 */
const AZURE_LLM_MAX_COMPLETION_TOKENS = 128_000;

export class AzureOpenAiLlm implements LlmClient {
  readonly name = "azure-openai";

  constructor(
    private readonly apiKey: string,
    private readonly endpoint: string,
    private readonly deployment: string,
    private readonly apiVersion: string,
  ) {}

  async complete(
    system: string,
    user: string,
    opts?: { signal?: AbortSignal; onUsage?: (usage: LlmUsage) => void },
  ): Promise<string> {
    const base = this.endpoint.replace(/\/+$/, "");
    const url = `${base}/openai/deployments/${this.deployment}/chat/completions?api-version=${this.apiVersion}`;
    const res = await fetch(url, {
      method: "POST",
      // Closing the connection on abort is what stops Azure from generating
      // (and billing) a completion whose caller already timed out and moved on.
      signal: opts?.signal,
      headers: {
        "content-type": "application/json",
        "api-key": this.apiKey,
      },
      body: JSON.stringify({
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
        // No temperature: GPT-5.5 rejects any non-default value, and the
        // extractor/verifier prompts are deterministic enough without one.
        max_completion_tokens: AZURE_LLM_MAX_COMPLETION_TOKENS,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`azure openai chat request failed: ${res.status} ${body}`);
    }
    const data = (await res.json()) as AzureChatResponse;
    // completion_tokens includes reasoning tokens — the billing-relevant count.
    reportUsage(opts?.onUsage, data.usage?.prompt_tokens, data.usage?.completion_tokens);
    return data.choices[0]?.message?.content ?? "";
  }
}

// ---------------------------------------------------------------------------
// OpenAiCompatibleLlm — any BYOK vendor speaking /chat/completions
// ---------------------------------------------------------------------------

interface OpenAiChatResponse {
  choices?: Array<{ message?: { content?: string } }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

/**
 * Write-path extractor/verifier over any OpenAI-compatible endpoint: DeepSeek,
 * Kimi, Qwen, Groq, Together, Fireworks, OpenRouter, a local vLLM, and so on.
 * The endpoint and model come from the same BYOK vocabulary the console offers
 * (src/model-runtime/catalog.ts); the key is optional so a keyless local server
 * works unchanged.
 */
export class OpenAiCompatibleLlm implements LlmClient {
  readonly name = "openai-compatible";

  constructor(
    private readonly baseUrl: string,
    private readonly model: string,
    private readonly apiKey: string,
  ) {}

  async complete(
    system: string,
    user: string,
    opts?: { signal?: AbortSignal; onUsage?: (usage: LlmUsage) => void },
  ): Promise<string> {
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      signal: opts?.signal,
      headers: {
        "content-type": "application/json",
        ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`openai-compatible chat request failed: ${res.status} ${body}`);
    }
    const data = (await res.json()) as OpenAiChatResponse;
    reportUsage(opts?.onUsage, data.usage?.prompt_tokens, data.usage?.completion_tokens);
    return data.choices?.[0]?.message?.content ?? "";
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createLlm(config: KernelConfig): LlmClient {
  if (config.azureOpenaiLlmApiKey && config.azureOpenaiLlmEndpoint && config.azureOpenaiLlmDeployment) {
    return new AzureOpenAiLlm(
      config.azureOpenaiLlmApiKey,
      config.azureOpenaiLlmEndpoint,
      config.azureOpenaiLlmDeployment,
      config.azureOpenaiApiVersion,
    );
  }
  if (config.llmBaseUrl && config.llmModel) {
    return new OpenAiCompatibleLlm(config.llmBaseUrl, config.llmModel, config.llmApiKey);
  }
  return config.anthropicApiKey
    ? new AnthropicLlm(config.anthropicApiKey)
    : new StubLlm();
}
