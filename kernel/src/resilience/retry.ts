/**
 * Module E (M1) — resilience primitives: retry with backoff + circuit breaker.
 *
 * withRetry: exponential backoff with jitter and a per-attempt timeout
 * implemented via Promise.race. Each attempt receives an AbortSignal that
 * fires when its timeout expires: a fn that forwards it to fetch stops the
 * provider from generating (and billing) an answer nobody will read. A fn
 * may still ignore the signal — the losing promise is left to settle in the
 * background with its rejection swallowed so it never surfaces as unhandled.
 *
 * CircuitBreaker: closed → open after N consecutive failures; while open,
 * calls fast-fail with CircuitOpenError; after `halfOpenAfterMs` a single
 * probe call is let through (half-open). Probe success closes the circuit,
 * probe failure re-opens it. The clock is injectable (`now`) so tests never
 * sleep a real 30 s.
 */

/** Thrown when the circuit is open (or a half-open probe is already in flight). */
export class CircuitOpenError extends Error {
  constructor(message = "circuit breaker is open") {
    super(message);
    this.name = "CircuitOpenError";
  }
}

/** Thrown by withRetry when a single attempt exceeds its per-attempt timeout. */
export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

export interface RetryOptions {
  /** Additional attempts after the first (default 2 → up to 3 attempts total). */
  retries?: number;
  /** Base backoff delay; attempt i waits ~baseDelayMs * 2^i with jitter (default 200). */
  baseDelayMs?: number;
  /** Per-attempt timeout (default 15000). */
  timeoutMs?: number;
  /** Injectable sleep for tests (default: real setTimeout). */
  sleep?: (ms: number) => Promise<void>;
  /** Return false for permanent failures such as authentication or invalid input. */
  shouldRetry?: (error: unknown) => boolean;
  /** Provider-directed minimum delay (for example Retry-After on HTTP 429). */
  retryAfterMs?: (error: unknown) => number | null;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Race a single attempt against a timeout. When the timeout wins, the
 * attempt's AbortSignal fires so a signal-aware fn cancels its in-flight
 * request; the losing promise's eventual rejection is swallowed either way. */
async function attemptWithTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const controller = new AbortController();
  const attempt = fn(controller.signal);
  // Detached rejection guard: if the attempt loses the race and later
  // rejects (typically with the abort error), don't let it become an
  // unhandled rejection.
  attempt.catch(() => {});
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      // Abort BEFORE rejecting: from this tick the attempt is unobserved,
      // and an uncancelled provider call keeps generating billable tokens.
      controller.abort(new TimeoutError(`attempt timed out after ${timeoutMs}ms`));
      reject(new TimeoutError(`attempt timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([attempt, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run `fn` with up to `retries` re-attempts, exponential backoff + full
 * jitter (each wait is uniform in [0.5x, 1x] of the exponential step), and a
 * per-attempt timeout. Throws the last error when all attempts fail.
 */
export async function withRetry<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  opts: RetryOptions = {},
): Promise<T> {
  const retries = opts.retries ?? 2;
  const baseDelayMs = opts.baseDelayMs ?? 200;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const sleep = opts.sleep ?? defaultSleep;
  const shouldRetry = opts.shouldRetry ?? (() => true);

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await attemptWithTimeout(fn, timeoutMs);
    } catch (err) {
      lastError = err;
      if (attempt < retries && shouldRetry(err)) {
        const step = baseDelayMs * 2 ** attempt;
        const jittered = step / 2 + Math.random() * (step / 2);
        const providerDelay = Math.max(0, opts.retryAfterMs?.(err) ?? 0);
        await sleep(Math.max(jittered, providerDelay));
      } else {
        break;
      }
    }
  }
  throw lastError;
}

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerOptions {
  /** Consecutive failures that trip the breaker (default 5). */
  failureThreshold?: number;
  /** How long the breaker stays fully open before allowing one probe (default 30000). */
  halfOpenAfterMs?: number;
  /** Injectable clock (ms epoch) so tests never sleep real time. */
  now?: () => number;
}

export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly halfOpenAfterMs: number;
  private readonly now: () => number;

  private consecutiveFailures = 0;
  private openedAt = 0;
  private open = false;
  private probeInFlight = false;

  constructor(opts: CircuitBreakerOptions = {}) {
    this.failureThreshold = opts.failureThreshold ?? 5;
    this.halfOpenAfterMs = opts.halfOpenAfterMs ?? 30_000;
    this.now = opts.now ?? (() => Date.now());
  }

  get state(): CircuitState {
    if (!this.open) return "closed";
    return this.now() - this.openedAt >= this.halfOpenAfterMs
      ? "half-open"
      : "open";
  }

  async exec<T>(fn: () => Promise<T>): Promise<T> {
    if (this.open) {
      if (this.now() - this.openedAt < this.halfOpenAfterMs) {
        throw new CircuitOpenError(
          `circuit open (retry after ${this.halfOpenAfterMs}ms)`,
        );
      }
      // Half-open: exactly one probe at a time.
      if (this.probeInFlight) {
        throw new CircuitOpenError("circuit half-open, probe already in flight");
      }
      this.probeInFlight = true;
      try {
        const result = await fn();
        this.open = false;
        this.consecutiveFailures = 0;
        return result;
      } catch (err) {
        this.trip(); // probe failed → re-open, restart the cool-down window
        throw err;
      } finally {
        this.probeInFlight = false;
      }
    }

    // Closed.
    try {
      const result = await fn();
      this.consecutiveFailures = 0;
      return result;
    } catch (err) {
      this.consecutiveFailures++;
      if (this.consecutiveFailures >= this.failureThreshold) {
        this.trip();
      }
      throw err;
    }
  }

  private trip(): void {
    this.open = true;
    this.openedAt = this.now();
    this.consecutiveFailures = 0;
  }
}
