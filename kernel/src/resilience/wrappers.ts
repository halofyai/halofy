/**
 * Module E (M1) — resilient decorators for LlmClient and Embedder.
 *
 * Both wrap the inner call in circuit-breaker + retry and append a
 * cost_ledger row on success (best-effort: a ledger failure never fails a
 * successful upstream call).
 *
 * Flat cost model (documented constants, not real provider pricing):
 *   LLM   → $1.00 per 1M tokens, tokens = estimateTokens(system+user+result)
 *   Embed → $0.10 per 1M tokens, tokens = estimateTokens(texts joined by "\n")
 *
 * Degradation semantics on breaker-open:
 *   LLM      → throws LlmUnavailableError; the write path catches it and
 *              falls back to verbatim storage (brownout, never hard-fail).
 *   Embedder → rethrows CircuitOpenError; the vector lane degrades but BM25
 *              keyword search still works.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import type { Embedder, LlmClient, LlmUsage, Namespace } from "../types.js";
import { estimateTokens } from "../types.js";
import {
  CircuitBreaker,
  CircuitOpenError,
  TimeoutError,
  withRetry,
  type CircuitBreakerOptions,
  type RetryOptions,
} from "./retry.js";

/** Flat LLM rate: USD per 1M estimated tokens. */
export const LLM_USD_PER_MILLION_TOKENS = 1.0;
/** Flat embedding rate: USD per 1M estimated tokens. */
export const EMBED_USD_PER_MILLION_TOKENS = 0.1;

/**
 * D38 usage context for a cost row: which caller (actor + trace) the spend
 * belongs to. Absent for background lanes (ingest, imports, WriteQueue
 * worker) — those rows stay namespace-only, which remains legal (E5).
 */
export interface UsageContext {
  actor?: string;
  traceId?: string;
  /** D49: model spend joins the exact Assistant invocation when applicable. */
  invocationId?: string;
  /** Recycle/purge generation captured when the Assistant turn was accepted. */
  lifecycleGeneration?: number;
  /**
   * Source attribution for ingestion lanes: the `sources.id` whose document
   * triggered this spend. Lets the console answer "Linear cost this team X
   * this week" — the dimension that would have surfaced the Aug 2026 spike
   * from inside the product. Absent for chat/assistant and platform lanes.
   */
  source?: string;
}

/**
 * Run `fn` with `source` merged into the ambient usage context, preserving
 * any actor/trace already present. No-op passthrough when source is absent.
 */
export function runWithCostSource<T>(
  source: string | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  if (!source) return fn();
  const current = usageContextStorage.getStore();
  return usageContextStorage.run({ ...current, source }, fn);
}

/**
 * D38: the usage context of the syscall running on THIS async context. The
 * Kernel facade wraps each syscall invocation in `usageContextStorage.run()`,
 * so two concurrent syscalls — even in the SAME namespace, whose
 * ResilientLlm / ResilientEmbedder wrappers are per-namespace singletons —
 * each read their own context at ledger-append time. Async work STARTED
 * inside the run inherits the store (the fire-and-forget D39 trace
 * summarizer intentionally stamps its LLM cost to the trace it summarizes);
 * lanes started outside any run (the async WriteQueue worker, ingest,
 * imports) see no store and stay namespace-only (E5).
 */
export const usageContextStorage = new AsyncLocalStorage<UsageContext>();

/** How a cost row's token count was obtained. */
export type TokenBasis = "provider" | "estimate";

/** Split + basis detail for a cost row (absent on legacy estimate-only rows). */
export interface CostDetail {
  inputTokens?: number;
  outputTokens?: number;
  basis?: TokenBasis;
}

/** Minimal cost-ledger sink (module D owns the real cost_ledger table). */
export interface CostLedger {
  append(
    namespace: Namespace,
    kind: "llm" | "embed",
    tokens: number,
    usd: number,
    ctx?: UsageContext,
    detail?: CostDetail,
  ): Promise<void>;
}

/** Thrown when the LLM circuit is open — callers degrade to verbatim storage. */
export class LlmUnavailableError extends Error {
  constructor(message = "LLM unavailable (circuit open)", cause?: unknown) {
    super(message);
    this.name = "LlmUnavailableError";
    if (cause !== undefined) this.cause = cause;
  }
}

export interface ResilienceOptions {
  retry?: RetryOptions;
  breaker?: CircuitBreakerOptions;
}

export class ResilientLlm implements LlmClient {
  readonly name: string;
  private readonly breaker: CircuitBreaker;
  private readonly retryOpts: RetryOptions;

  constructor(
    private readonly inner: LlmClient,
    private readonly ledger: CostLedger,
    private readonly ns: Namespace,
    opts: ResilienceOptions = {},
  ) {
    this.name = `resilient(${inner.name})`;
    this.breaker = new CircuitBreaker(opts.breaker);
    this.retryOpts = opts.retry ?? {};
  }

  async complete(
    system: string,
    user: string,
    opts?: { signal?: AbortSignal; onUsage?: (usage: LlmUsage) => void },
  ): Promise<string> {
    let result: string;
    // Real usage from the WINNING attempt. A timed-out attempt is aborted
    // before its response parses, so it can never report usage here.
    let usage: LlmUsage | undefined;
    try {
      result = await this.breaker.exec(() =>
        // The per-attempt signal cancels the in-flight provider request when
        // the attempt times out — an abandoned completion otherwise keeps
        // generating billable tokens the caller will never read. A caller
        // signal (opts.signal) is honored on top when provided.
        withRetry(
          (signal) => this.inner.complete(system, user, {
            signal: opts?.signal ? AbortSignal.any([signal, opts.signal]) : signal,
            onUsage: (u) => {
              usage = u;
              opts?.onUsage?.(u);
            },
          }),
          this.retryOpts,
        ),
      );
    } catch (err) {
      if (err instanceof CircuitOpenError) {
        throw new LlmUnavailableError(
          "LLM unavailable (circuit open) - degrade to verbatim storage",
          err,
        );
      }
      // A provider slow enough to exhaust every attempt is unavailable for
      // this write, exactly like an open circuit — and non-negotiable 5 says
      // degrade, never hard-fail. Only LlmUnavailableError reaches the
      // verbatim fallback in performWrite, so a raw TimeoutError escaping
      // here failed the whole write instead. A long document (a Linear spec,
      // a policy PDF) is precisely the input that exceeds the per-attempt
      // budget, so this was the common case, not the rare one.
      if (err instanceof TimeoutError) {
        throw new LlmUnavailableError(
          "LLM unavailable (attempt timeout exhausted retries) - degrade to verbatim storage",
          err,
        );
      }
      // `withRetry` returns the LAST provider failure. A slow Azure request can
      // consume the first attempts and then end on a quick 429/5xx; treating
      // only TimeoutError as unavailable made that final status decide the
      // whole write and failed document ingestion instead of taking the
      // governed verbatim brownout. Preserve an explicit caller cancellation,
      // but every retry-exhausted provider failure is unavailable for this
      // write and must reach performWrite's safe fallback.
      if (opts?.signal?.aborted) throw err;
      throw new LlmUnavailableError(
        "LLM unavailable (provider retries exhausted) - degrade to verbatim storage",
        err,
      );
    }
    // Provider-reported counts when the response carried them (the estimate
    // recorded 1/17th of the Azure bill — it never saw reasoning tokens);
    // text-length estimate only as the fallback for usage-less providers.
    const tokens = usage
      ? usage.inputTokens + usage.outputTokens
      : estimateTokens(system + user + result);
    const usd = (tokens / 1e6) * LLM_USD_PER_MILLION_TOKENS;
    try {
      await this.ledger.append(
        this.ns, "llm", tokens, usd, usageContextStorage.getStore() ?? undefined,
        usage
          ? { inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, basis: "provider" }
          : { basis: "estimate" },
      );
    } catch {
      // Best-effort accounting: never fail a successful completion.
    }
    return result;
  }
}

export class ResilientEmbedder implements Embedder {
  readonly name: string;
  readonly dim: number;
  private readonly breaker: CircuitBreaker;
  private readonly retryOpts: RetryOptions;

  constructor(
    private readonly inner: Embedder,
    private readonly ledger: CostLedger,
    private readonly ns: Namespace,
    opts: ResilienceOptions = {},
  ) {
    this.name = `resilient(${inner.name})`;
    this.dim = inner.dim;
    this.breaker = new CircuitBreaker(opts.breaker);
    this.retryOpts = opts.retry ?? {};
  }

  async embed(texts: string[]): Promise<number[][]> {
    // Breaker-open → CircuitOpenError propagates as-is: the caller's vector
    // lane degrades while BM25 keeps working.
    const result = await this.breaker.exec(() =>
      withRetry(() => this.inner.embed(texts), this.retryOpts),
    );
    const tokens = estimateTokens(texts.join("\n"));
    const usd = (tokens / 1e6) * EMBED_USD_PER_MILLION_TOKENS;
    try {
      await this.ledger.append(this.ns, "embed", tokens, usd, usageContextStorage.getStore() ?? undefined);
    } catch {
      // Best-effort accounting: never fail a successful embed.
    }
    return result;
  }
}
