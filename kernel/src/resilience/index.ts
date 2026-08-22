/**
 * Module E (M1) — resilience: retry/backoff, circuit breaker, resilient
 * LLM/embedder decorators with cost-ledger accounting, async write queue.
 */

export {
  CircuitBreaker,
  CircuitOpenError,
  TimeoutError,
  withRetry,
  type CircuitBreakerOptions,
  type CircuitState,
  type RetryOptions,
} from "./retry.js";

export {
  EMBED_USD_PER_MILLION_TOKENS,
  LLM_USD_PER_MILLION_TOKENS,
  LlmUnavailableError,
  ResilientEmbedder,
  ResilientLlm,
  runWithCostSource,
  usageContextStorage,
  type CostDetail,
  type CostLedger,
  type ResilienceOptions,
  type TokenBasis,
  type UsageContext,
} from "./wrappers.js";

export {
  WriteQueue,
  type WriteQueueState,
  type WriteQueueStatus,
} from "./queue.js";
