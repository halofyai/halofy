/**
 * Module C (part 1) — embeddings.
 *
 * HashEmbedder: deterministic, offline, dim 256 — the default lane whenever
 * no OPENAI_API_KEY is configured (and always in tests).
 * OpenAIEmbedder: text-embedding-3-small, dim 1536, batched fetch.
 */

import type { Embedder } from "../types.js";
import type { KernelConfig } from "../config.js";
import { trimTrailingRepeatedCharacter } from "../strings.js";

export const HASH_EMBED_DIM = 256;
export const OPENAI_EMBED_DIM = 1536;
/** A conservative provider batch, matching the proven Cognee default. */
export const PROVIDER_EMBED_BATCH_SIZE = 36;
export const PROVIDER_EMBED_MAX_CONCURRENT_BATCHES = 4;
/**
 * A provider socket must never outlive the write-path attempt that owns it.
 * Azure embedding responses are normally sub-second; 30 seconds leaves ample
 * service headroom while releasing a coalescing slot early enough for the
 * resilient wrapper to retry inside its three-minute attempt budget.
 */
export const PROVIDER_EMBED_REQUEST_TIMEOUT_MS = 30_000;
const EMBED_BATCH_WINDOW_MS = 8;
const OPENAI_EMBED_URL = "https://api.openai.com/v1/embeddings";
const OPENAI_EMBED_MODEL = "text-embedding-3-small";

export type EmbeddingProviderFailureCode =
  | "rate_limited"
  | "timeout"
  | "input_too_large"
  | "authentication"
  | "invalid_request"
  | "provider_unavailable";

/** Content-free provider failure safe for retry decisions and operational logs. */
export class EmbeddingProviderError extends Error {
  constructor(
    readonly code: EmbeddingProviderFailureCode,
    readonly status: number | null,
    readonly retryable: boolean,
    readonly retryAfterMs: number | null = null,
  ) {
    super(`embedding provider ${code}${status === null ? "" : ` (HTTP ${status})`}`);
    this.name = "EmbeddingProviderError";
  }
}

export function isRetryableEmbeddingError(error: unknown): boolean {
  return !(error instanceof EmbeddingProviderError) || error.retryable;
}

export function embeddingRetryAfterMs(error: unknown): number | null {
  return error instanceof EmbeddingProviderError ? error.retryAfterMs : null;
}

function retryAfterMs(response: Response): number | null {
  const raw = response.headers.get("retry-after")?.trim();
  if (!raw) return null;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1_000);
  const at = Date.parse(raw);
  return Number.isFinite(at) ? Math.max(0, at - Date.now()) : null;
}

function providerError(response: Response, detail: string): EmbeddingProviderError {
  const normalized = detail.toLowerCase();
  const tooLarge = response.status === 400 && [
    "context length", "context window", "maximum context", "maximum tokens",
    "max tokens", "too many tokens", "input is too long",
  ].some((value) => normalized.includes(value));
  if (tooLarge) {
    return new EmbeddingProviderError("input_too_large", response.status, false);
  }
  if (response.status === 401 || response.status === 403) {
    return new EmbeddingProviderError("authentication", response.status, false);
  }
  if (response.status === 408) {
    return new EmbeddingProviderError("timeout", response.status, true);
  }
  if (response.status === 429) {
    return new EmbeddingProviderError(
      "rate_limited",
      response.status,
      true,
      retryAfterMs(response),
    );
  }
  if (response.status >= 500) {
    return new EmbeddingProviderError("provider_unavailable", response.status, true);
  }
  return new EmbeddingProviderError("invalid_request", response.status, false);
}

async function fetchEmbeddingProvider(
  input: string | URL | Request,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    return await fetch(input, { ...init, signal });
  } catch (error) {
    if (signal.aborted) {
      throw new EmbeddingProviderError("timeout", null, true);
    }
    throw new EmbeddingProviderError("provider_unavailable", null, true);
  }
}

function averageVectors(left: number[], right: number[]): number[] {
  if (left.length !== right.length) {
    throw new EmbeddingProviderError("invalid_request", null, false);
  }
  return left.map((value, index) => (value + right[index]!) / 2);
}

async function embedBatchWithRecovery(
  texts: string[],
  request: (batch: string[]) => Promise<number[][]>,
): Promise<number[][]> {
  try {
    return await request(texts);
  } catch (error) {
    if (!(error instanceof EmbeddingProviderError) || error.code !== "input_too_large") {
      throw error;
    }
    if (texts.length > 1) {
      const middle = Math.ceil(texts.length / 2);
      const left = await embedBatchWithRecovery(texts.slice(0, middle), request);
      const right = await embedBatchWithRecovery(texts.slice(middle), request);
      return [...left, ...right];
    }
    const text = texts[0] ?? "";
    if (text.length < 2) throw error;
    const middle = Math.floor(text.length / 2);
    const left = await embedBatchWithRecovery([text.slice(0, middle)], request);
    const right = await embedBatchWithRecovery([text.slice(middle)], request);
    if (!left[0] || !right[0]) throw error;
    return [averageVectors(left[0], right[0])];
  }
}

interface PendingEmbedding {
  text: string;
  resolve(vector: number[]): void;
  reject(error: unknown): void;
}

/**
 * Coalesce simultaneous small writes into bounded provider batches. Each caller
 * still receives only its own vectors and keeps its own namespace cost entry.
 */
export class BatchingEmbedder implements Embedder {
  readonly name: string;
  readonly dim: number;
  private readonly pending: PendingEmbedding[] = [];
  private activeBatches = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly inner: Embedder,
    private readonly batchSize = PROVIDER_EMBED_BATCH_SIZE,
    private readonly maxConcurrentBatches = PROVIDER_EMBED_MAX_CONCURRENT_BATCHES,
    private readonly windowMs = EMBED_BATCH_WINDOW_MS,
  ) {
    this.name = inner.name;
    this.dim = inner.dim;
  }

  async embed(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];
    const vectors = texts.map((text) => new Promise<number[]>((resolve, reject) => {
      this.pending.push({ text, resolve, reject });
    }));
    this.schedule();
    return Promise.all(vectors);
  }

  private schedule(): void {
    if (this.timer !== null || this.pending.length === 0) return;
    if (this.activeBatches >= this.maxConcurrentBatches) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.drain();
    }, this.windowMs);
  }

  private drain(): void {
    while (
      this.activeBatches < this.maxConcurrentBatches &&
      this.pending.length > 0
    ) {
      const batch = this.pending.splice(0, this.batchSize);
      this.activeBatches++;
      void this.inner.embed(batch.map((item) => item.text)).then((vectors) => {
        if (vectors.length !== batch.length) {
          throw new EmbeddingProviderError("invalid_request", null, false);
        }
        batch.forEach((item, index) => item.resolve(vectors[index]!));
      }).catch((error: unknown) => {
        batch.forEach((item) => item.reject(error));
      }).finally(() => {
        this.activeBatches--;
        this.schedule();
      });
    }
  }
}

/**
 * Shared tokenizer: lowercase, split on runs of non-alphanumerics.
 * BM25 in src/retrieval/ uses the exact same function so lexical and
 * hash-vector lanes agree on term boundaries.
 */
export function tokenize(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 0);
}

/** FNV-1a 32-bit hash — simple, stable, well distributed for short tokens. */
function fnv1a(token: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < token.length; i++) {
    h ^= token.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** 32-bit left rotation — used to derive a second smoothing bucket. */
function rotl32(x: number, bits: number): number {
  return ((x << bits) | (x >>> (32 - bits))) >>> 0;
}

function l2Normalize(vec: number[]): number[] {
  let sumSq = 0;
  for (const v of vec) sumSq += v * v;
  if (sumSq === 0) return vec; // empty text → zero vector, leave as-is
  const norm = Math.sqrt(sumSq);
  return vec.map((v) => v / norm);
}

/**
 * Deterministic bag-of-hashed-tokens embedder. Same text always yields the
 * same unit vector; texts sharing tokens share buckets and therefore have
 * positive cosine similarity.
 */
export class HashEmbedder implements Embedder {
  readonly name = "hash";
  readonly dim: number;

  constructor(dim = HASH_EMBED_DIM) {
    if (!Number.isInteger(dim) || dim <= 0) {
      throw new Error("HashEmbedder dimension must be a positive integer");
    }
    this.dim = dim;
  }

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((text) => this.embedOne(text));
  }

  private embedOne(text: string): number[] {
    const vec = new Array<number>(this.dim).fill(0);
    for (const token of tokenize(text)) {
      const h = fnv1a(token);
      vec[h % this.dim] += 1;
      // Second, rotated hash smooths collisions between unrelated tokens.
      vec[rotl32(h, 13) % this.dim] += 1;
    }
    return l2Normalize(vec);
  }
}

interface OpenAIEmbeddingResponse {
  data: { index: number; embedding: number[] }[];
}

/** Real embeddings via the OpenAI API with bounded provider batches. */
export class OpenAIEmbedder implements Embedder {
  readonly name = "openai";
  readonly dim = OPENAI_EMBED_DIM;

  constructor(
    private readonly apiKey: string,
    private readonly requestTimeoutMs = PROVIDER_EMBED_REQUEST_TIMEOUT_MS,
  ) {}

  async embed(texts: string[]): Promise<number[][]> {
    const out: number[][] = [];
    for (let i = 0; i < texts.length; i += PROVIDER_EMBED_BATCH_SIZE) {
      const batch = texts.slice(i, i + PROVIDER_EMBED_BATCH_SIZE);
      const vectors = await embedBatchWithRecovery(batch, async (input) => {
        const res = await fetchEmbeddingProvider(OPENAI_EMBED_URL, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify({ model: OPENAI_EMBED_MODEL, input }),
        }, this.requestTimeoutMs);
        if (!res.ok) throw providerError(res, await res.text().catch(() => ""));
        const json = (await res.json()) as OpenAIEmbeddingResponse;
        return [...json.data].sort((a, b) => a.index - b.index).map((item) => item.embedding);
      });
      out.push(...vectors);
    }
    return out;
  }
}

export const AZURE_EMBED_DIM = 3072;

/** Real embeddings via an Azure OpenAI embeddings deployment (text-embedding-3-large). */
export class AzureOpenAiEmbedder implements Embedder {
  readonly name = "azure-openai";
  readonly dim = AZURE_EMBED_DIM;

  constructor(
    private readonly apiKey: string,
    private readonly endpoint: string,
    private readonly deployment: string,
    private readonly apiVersion: string,
    private readonly requestTimeoutMs = PROVIDER_EMBED_REQUEST_TIMEOUT_MS,
  ) {}

  async embed(texts: string[]): Promise<number[][]> {
    const base = trimTrailingRepeatedCharacter(this.endpoint, "/");
    const url = `${base}/openai/deployments/${this.deployment}/embeddings?api-version=${this.apiVersion}`;
    const out: number[][] = [];
    for (let i = 0; i < texts.length; i += PROVIDER_EMBED_BATCH_SIZE) {
      const batch = texts.slice(i, i + PROVIDER_EMBED_BATCH_SIZE);
      const vectors = await embedBatchWithRecovery(batch, async (input) => {
        const res = await fetchEmbeddingProvider(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "api-key": this.apiKey,
          },
          body: JSON.stringify({ input }),
        }, this.requestTimeoutMs);
        if (!res.ok) throw providerError(res, await res.text().catch(() => ""));
        const json = (await res.json()) as OpenAIEmbeddingResponse;
        return [...json.data].sort((a, b) => a.index - b.index).map((item) => item.embedding);
      });
      out.push(...vectors);
    }
    return out;
  }
}

/** Azure OpenAI when configured, else direct OpenAI, else the deterministic hash embedder. */
export function createEmbedder(config: KernelConfig): Embedder {
  if (config.azureOpenaiEmbedApiKey && config.azureOpenaiEmbedEndpoint && config.azureOpenaiEmbedDeployment) {
    return new BatchingEmbedder(new AzureOpenAiEmbedder(
      config.azureOpenaiEmbedApiKey,
      config.azureOpenaiEmbedEndpoint,
      config.azureOpenaiEmbedDeployment,
      config.azureOpenaiApiVersion,
    ));
  }
  return config.openaiApiKey
    ? new BatchingEmbedder(new OpenAIEmbedder(config.openaiApiKey))
    : new HashEmbedder();
}

/** Cosine similarity; 0 when either vector has zero norm. */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error(`cosineSimilarity: dimension mismatch (${a.length} vs ${b.length})`);
  }
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}
