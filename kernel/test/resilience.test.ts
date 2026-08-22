/**
 * Module E (M1) — resilience tests: retry/backoff+timeout, circuit breaker
 * with fake clock (never sleeps a real 30 s), resilient LLM/embedder cost
 * accounting, async write queue. Hermetic: no DB, no network.
 */

import { describe, expect, it } from "vitest";
import {
  CircuitBreaker,
  CircuitOpenError,
  TimeoutError,
  withRetry,
} from "../src/resilience/retry.js";
import {
  EMBED_USD_PER_MILLION_TOKENS,
  LLM_USD_PER_MILLION_TOKENS,
  LlmUnavailableError,
  ResilientEmbedder,
  ResilientLlm,
  runWithCostSource,
  usageContextStorage,
  type CostDetail,
  type CostLedger,
  type UsageContext,
} from "../src/resilience/wrappers.js";
import { WriteQueue } from "../src/resilience/queue.js";
import type { Embedder, Identity, LlmClient } from "../src/types.js";
import { estimateTokens } from "../src/types.js";

const FAST = { retries: 2, baseDelayMs: 1, timeoutMs: 5_000 };

const identity: Identity = {
  keyId: "01TESTKEY0000000000000000",
  namespace: "org/team-a",
  actor: "tester",
  role: "agent",
};

class FakeLedger implements CostLedger {
  rows: { ns: string; kind: "llm" | "embed"; tokens: number; usd: number }[] =
    [];
  details: (CostDetail | undefined)[] = [];
  contexts: (UsageContext | undefined)[] = [];
  async append(
    ns: string,
    kind: "llm" | "embed",
    tokens: number,
    usd: number,
    ctx?: UsageContext,
    detail?: CostDetail,
  ): Promise<void> {
    this.rows.push({ ns, kind, tokens, usd });
    this.contexts.push(ctx);
    this.details.push(detail);
  }
}

// ---------------------------------------------------------------------------
// withRetry
// ---------------------------------------------------------------------------

describe("withRetry", () => {
  it("succeeds on the 2nd attempt after one failure", async () => {
    let calls = 0;
    const result = await withRetry(async () => {
      calls++;
      if (calls < 2) throw new Error("transient");
      return "ok";
    }, FAST);
    expect(result).toBe("ok");
    expect(calls).toBe(2);
  });

  it("per-attempt timeout triggers a retry that then succeeds", async () => {
    let calls = 0;
    const result = await withRetry(
      async () => {
        calls++;
        if (calls === 1) {
          // Hangs well past the per-attempt timeout; fn ignores any abort.
          return new Promise<string>((resolve) =>
            setTimeout(() => resolve("late"), 60_000).unref?.(),
          );
        }
        return "recovered";
      },
      { retries: 2, baseDelayMs: 1, timeoutMs: 30 },
    );
    expect(result).toBe("recovered");
    expect(calls).toBe(2);
  });

  it("throws the last error (TimeoutError) when every attempt times out", async () => {
    let calls = 0;
    await expect(
      withRetry(
        () => {
          calls++;
          return new Promise<never>(() => {
            /* never settles */
          });
        },
        { retries: 1, baseDelayMs: 1, timeoutMs: 20 },
      ),
    ).rejects.toBeInstanceOf(TimeoutError);
    expect(calls).toBe(2);
  });

  it("throws the last underlying error after exhausting retries", async () => {
    let calls = 0;
    await expect(
      withRetry(async () => {
        calls++;
        throw new Error(`boom ${calls}`);
      }, FAST),
    ).rejects.toThrow("boom 3");
    expect(calls).toBe(3); // 1 + 2 retries
  });

  it("does not retry a failure classified as permanent", async () => {
    let calls = 0;
    await expect(withRetry(async () => {
      calls++;
      throw new Error("permanent");
    }, {
      ...FAST,
      shouldRetry: () => false,
    })).rejects.toThrow("permanent");
    expect(calls).toBe(1);
  });

  it("honors a provider-directed retry delay", async () => {
    const waits: number[] = [];
    let calls = 0;
    await expect(withRetry(async () => {
      calls++;
      if (calls === 1) throw new Error("rate limited");
      return "ok";
    }, {
      retries: 1,
      baseDelayMs: 1,
      timeoutMs: 100,
      sleep: async (ms) => { waits.push(ms); },
      retryAfterMs: () => 2_000,
    })).resolves.toBe("ok");
    expect(waits).toEqual([2_000]);
  });

  it("aborts the losing attempt's signal when its timeout fires", async () => {
    // The whole point of the abort wiring: a timed-out attempt must CANCEL
    // its in-flight provider request, not leave it generating billable
    // tokens in the background.
    const signals: AbortSignal[] = [];
    const result = await withRetry(
      (signal) => {
        signals.push(signal);
        if (signals.length === 1) {
          // Hangs past the per-attempt timeout.
          return new Promise<string>((resolve) =>
            setTimeout(() => resolve("late"), 60_000).unref?.(),
          );
        }
        return Promise.resolve("recovered");
      },
      { retries: 2, baseDelayMs: 1, timeoutMs: 30 },
    );
    expect(result).toBe("recovered");
    expect(signals).toHaveLength(2);
    expect(signals[0].aborted).toBe(true); // timed-out attempt was cancelled
    expect(signals[1].aborted).toBe(false); // the winner was not
  });

  it("a successful attempt's signal never fires, even after the race is over", async () => {
    let captured: AbortSignal | undefined;
    const result = await withRetry(
      (signal) => {
        captured = signal;
        return Promise.resolve("ok");
      },
      { retries: 0, baseDelayMs: 1, timeoutMs: 30 },
    );
    expect(result).toBe("ok");
    await new Promise((r) => setTimeout(r, 60));
    expect(captured?.aborted).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CircuitBreaker (fake clock — never sleeps real time)
// ---------------------------------------------------------------------------

describe("CircuitBreaker", () => {
  const failing = () => Promise.reject(new Error("downstream down"));

  async function tripBreaker(breaker: CircuitBreaker): Promise<void> {
    for (let i = 0; i < 5; i++) {
      await expect(breaker.exec(failing)).rejects.toThrow("downstream down");
    }
  }

  it("opens after 5 consecutive failures and fast-fails", async () => {
    let t = 0;
    const breaker = new CircuitBreaker({ now: () => t });
    expect(breaker.state).toBe("closed");
    await tripBreaker(breaker);
    expect(breaker.state).toBe("open");

    // Fast-fail: the wrapped fn must NOT be invoked while open.
    let probed = false;
    await expect(
      breaker.exec(async () => {
        probed = true;
        return 1;
      }),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    expect(probed).toBe(false);
  });

  it("a success resets the consecutive-failure count while closed", async () => {
    let t = 0;
    const breaker = new CircuitBreaker({ now: () => t });
    for (let i = 0; i < 4; i++) {
      await expect(breaker.exec(failing)).rejects.toThrow();
    }
    await breaker.exec(async () => "fine"); // resets the streak
    for (let i = 0; i < 4; i++) {
      await expect(breaker.exec(failing)).rejects.toThrow();
    }
    expect(breaker.state).toBe("closed");
  });

  it("half-open after 30s lets one probe through; success closes the circuit", async () => {
    let t = 0;
    const breaker = new CircuitBreaker({ now: () => t });
    await tripBreaker(breaker);
    expect(breaker.state).toBe("open");

    t += 29_999;
    await expect(breaker.exec(async () => 1)).rejects.toBeInstanceOf(
      CircuitOpenError,
    );

    t += 1; // exactly 30s since trip
    expect(breaker.state).toBe("half-open");
    const result = await breaker.exec(async () => "probe-ok");
    expect(result).toBe("probe-ok");
    expect(breaker.state).toBe("closed");
    // Fully recovered: subsequent calls flow normally.
    expect(await breaker.exec(async () => 42)).toBe(42);
  });

  it("a failed half-open probe re-opens the circuit for another 30s", async () => {
    let t = 0;
    const breaker = new CircuitBreaker({ now: () => t });
    await tripBreaker(breaker);

    t += 30_000;
    await expect(breaker.exec(failing)).rejects.toThrow("downstream down");
    expect(breaker.state).toBe("open");

    // Still open until another full window elapses from the failed probe.
    t += 29_999;
    await expect(breaker.exec(async () => 1)).rejects.toBeInstanceOf(
      CircuitOpenError,
    );
    t += 1;
    expect(await breaker.exec(async () => "back")).toBe("back");
    expect(breaker.state).toBe("closed");
  });

  it("only one probe runs at a time in half-open", async () => {
    let t = 0;
    const breaker = new CircuitBreaker({ now: () => t });
    await tripBreaker(breaker);
    t += 30_000;

    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const probe = breaker.exec(async () => {
      await gate;
      return "slow-probe";
    });
    await expect(breaker.exec(async () => "second")).rejects.toBeInstanceOf(
      CircuitOpenError,
    );
    release();
    expect(await probe).toBe("slow-probe");
  });
});

// ---------------------------------------------------------------------------
// ResilientLlm / ResilientEmbedder
// ---------------------------------------------------------------------------

class FlakyLlm implements LlmClient {
  readonly name = "flaky-llm";
  calls = 0;
  constructor(private readonly failFirst: number) {}
  async complete(system: string, user: string): Promise<string> {
    this.calls++;
    if (this.calls <= this.failFirst) throw new Error("llm 500");
    return `echo:${system.length}:${user.length}`;
  }
}

class DeadLlm implements LlmClient {
  readonly name = "dead-llm";
  async complete(): Promise<string> {
    throw new Error("llm down");
  }
}

class StubEmbedderOk implements Embedder {
  readonly name = "stub-embed";
  readonly dim = 4;
  async embed(texts: string[]): Promise<number[][]> {
    return texts.map(() => [0, 0, 0, 0]);
  }
}

class DeadEmbedder implements Embedder {
  readonly name = "dead-embed";
  readonly dim = 4;
  async embed(): Promise<number[][]> {
    throw new Error("embed down");
  }
}

describe("ResilientLlm", () => {
  it("retries through transient failures and appends a cost row", async () => {
    const inner = new FlakyLlm(1);
    const ledger = new FakeLedger();
    const llm = new ResilientLlm(inner, ledger, "org/team-a", {
      retry: FAST,
    });
    const system = "SYSTEM PROMPT";
    const user = "user question";
    const result = await llm.complete(system, user);

    expect(result).toBe(`echo:${system.length}:${user.length}`);
    expect(inner.calls).toBe(2);
    expect(ledger.rows).toHaveLength(1);
    const row = ledger.rows[0];
    const expectedTokens = estimateTokens(system + user + result);
    expect(row).toEqual({
      ns: "org/team-a",
      kind: "llm",
      tokens: expectedTokens,
      usd: (expectedTokens / 1e6) * LLM_USD_PER_MILLION_TOKENS,
    });
  });

  it("wraps exhausted provider failures and breaker-open failures for verbatim brownout", async () => {
    const ledger = new FakeLedger();
    let t = 0;
    const llm = new ResilientLlm(new DeadLlm(), ledger, "org/team-a", {
      retry: { retries: 0, baseDelayMs: 1, timeoutMs: 1_000 },
      breaker: { now: () => t },
    });
    for (let i = 0; i < 5; i++) {
      const error = await llm.complete("s", "u").catch((err: unknown) => err);
      expect(error).toBeInstanceOf(LlmUnavailableError);
      expect((error as LlmUnavailableError).cause).toMatchObject({ message: "llm down" });
    }
    // Breaker now open → fast LlmUnavailableError, inner never called.
    await expect(llm.complete("s", "u")).rejects.toBeInstanceOf(
      LlmUnavailableError,
    );
    expect(ledger.rows).toHaveLength(0);
  });

  it("degrades when timeouts are followed by a retry-exhausting provider error", async () => {
    // Production document uploads hit this mixed sequence: slow attempts used
    // most of the request window, then Azure returned a quick status error.
    // The last error is not TimeoutError, but the provider is still unavailable
    // for this write and performWrite must receive LlmUnavailableError.
    const ledger = new FakeLedger();
    let calls = 0;
    const inner: LlmClient = {
      name: "mixed-failure-llm",
      complete: () => {
        calls += 1;
        if (calls < 3) return new Promise<string>(() => {});
        throw new Error("azure openai chat request failed: 429");
      },
    };
    const llm = new ResilientLlm(inner, ledger, "org/design", {
      retry: { retries: 2, baseDelayMs: 1, timeoutMs: 5 },
    });

    const error = await llm.complete("extract", "design system").catch((err: unknown) => err);

    expect(calls).toBe(3);
    expect(error).toBeInstanceOf(LlmUnavailableError);
    expect((error as LlmUnavailableError).cause).toMatchObject({
      message: "azure openai chat request failed: 429",
    });
    expect(String((error as Error).message)).toContain("verbatim");
    expect(ledger.rows).toHaveLength(0);
  });

  it("degrades a retry-exhausting timeout to LlmUnavailableError, not a raw TimeoutError", async () => {
    // Only LlmUnavailableError reaches the verbatim fallback in performWrite.
    // A provider too slow to finish any attempt is unavailable for this write
    // exactly like an open circuit; surfacing TimeoutError instead failed the
    // whole write, which is what a long ingested document reliably triggered.
    const ledger = new FakeLedger();
    const slow: LlmClient = {
      name: "slow-llm",
      complete: () => new Promise<string>(() => {}),
    };
    const llm = new ResilientLlm(slow, ledger, "org/team-a", {
      retry: { retries: 1, baseDelayMs: 1, timeoutMs: 5 },
    });

    const error = await llm.complete("s", "u").catch((err: unknown) => err);

    expect(error).toBeInstanceOf(LlmUnavailableError);
    expect((error as LlmUnavailableError).cause).toBeInstanceOf(TimeoutError);
    expect(String((error as Error).message)).toContain("verbatim");
    // A degraded call produced no completion, so it must not be billed.
    expect(ledger.rows).toHaveLength(0);
  });

  it("hands the inner client a per-attempt signal that aborts on timeout", async () => {
    // ResilientLlm must thread withRetry's per-attempt signal through to the
    // real client so the provider request dies with the attempt.
    const ledger = new FakeLedger();
    const seen: (AbortSignal | undefined)[] = [];
    const inner: LlmClient = {
      name: "capture-llm",
      complete: (_s, _u, opts) => {
        seen.push(opts?.signal);
        return seen.length === 1
          ? new Promise<string>(() => {}) // first attempt hangs → timeout
          : Promise.resolve("ok");
      },
    };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", {
      retry: { retries: 1, baseDelayMs: 1, timeoutMs: 20 },
    });
    expect(await llm.complete("s", "u")).toBe("ok");
    expect(seen).toHaveLength(2);
    expect(seen[0]?.aborted).toBe(true);
    expect(seen[1]?.aborted).toBe(false);
  });

  it("honors a caller-supplied signal alongside the per-attempt one", async () => {
    const ledger = new FakeLedger();
    let seen: AbortSignal | undefined;
    const inner: LlmClient = {
      name: "caller-abort-llm",
      complete: (_s, _u, opts) => {
        seen = opts?.signal;
        return new Promise<string>(() => {}); // hangs until timeout
      },
    };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", {
      retry: { retries: 0, baseDelayMs: 1, timeoutMs: 30 },
    });
    const caller = new AbortController();
    const pending = llm.complete("s", "u", { signal: caller.signal }).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 5));
    caller.abort();
    expect(seen?.aborted).toBe(true); // caller abort reached the inner client
    await pending; // settles via the attempt timeout; no unhandled rejection
  });

  it("records provider-reported usage when the client supplies it", async () => {
    // The estimate recorded 1/17th of the Azure bill — it guessed from text
    // length and never saw reasoning tokens. Real counts win when present.
    const ledger = new FakeLedger();
    const inner: LlmClient = {
      name: "usage-llm",
      complete: async (_s, _u, opts) => {
        opts?.onUsage?.({ inputTokens: 1200, outputTokens: 4800 });
        return "short";
      },
    };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", { retry: FAST });

    await llm.complete("s", "u");

    expect(ledger.rows).toHaveLength(1);
    expect(ledger.rows[0]!.tokens).toBe(6000); // real, not estimateTokens("sushort")
    expect(ledger.details[0]).toEqual({
      inputTokens: 1200,
      outputTokens: 4800,
      basis: "provider",
    });
  });

  it("falls back to the text-length estimate when the client reports no usage", async () => {
    const ledger = new FakeLedger();
    const inner: LlmClient = {
      name: "usageless-llm",
      complete: async () => "result",
    };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", { retry: FAST });

    await llm.complete("sys", "usr");

    expect(ledger.rows[0]!.tokens).toBe(estimateTokens("sys" + "usr" + "result"));
    expect(ledger.details[0]).toEqual({ basis: "estimate" });
  });

  it("stamps the ambient cost source onto ledger rows and preserves the outer context", async () => {
    const ledger = new FakeLedger();
    const inner: LlmClient = { name: "ok-llm", complete: async () => "ok" };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", { retry: FAST });

    await usageContextStorage.run({ actor: "alice" }, () =>
      runWithCostSource("01SOURCELINEAR0000000000000", () => llm.complete("s", "u")),
    );
    // No source → passthrough, outer context untouched.
    await runWithCostSource(undefined, () => llm.complete("s", "u"));

    expect(ledger.contexts[0]).toEqual({
      actor: "alice",
      source: "01SOURCELINEAR0000000000000",
    });
    expect(ledger.contexts[1]).toBeUndefined();
  });

  it("recovers via half-open probe after 30s (fake clock)", async () => {
    const ledger = new FakeLedger();
    let t = 0;
    let healthy = false;
    const inner: LlmClient = {
      name: "toggle-llm",
      async complete() {
        if (!healthy) throw new Error("llm down");
        return "alive";
      },
    };
    const llm = new ResilientLlm(inner, ledger, "org/team-a", {
      retry: { retries: 0, baseDelayMs: 1, timeoutMs: 1_000 },
      breaker: { now: () => t },
    });
    for (let i = 0; i < 5; i++) {
      await expect(llm.complete("s", "u")).rejects.toBeInstanceOf(LlmUnavailableError);
    }
    await expect(llm.complete("s", "u")).rejects.toBeInstanceOf(
      LlmUnavailableError,
    );
    healthy = true;
    t += 30_000;
    expect(await llm.complete("s", "u")).toBe("alive");
    expect(ledger.rows).toHaveLength(1);
    expect(ledger.rows[0].kind).toBe("llm");
  });
});

describe("ResilientEmbedder", () => {
  it("appends an embed cost row at the 0.1/1M rate", async () => {
    const ledger = new FakeLedger();
    const embedder = new ResilientEmbedder(
      new StubEmbedderOk(),
      ledger,
      "org/team-a",
      { retry: FAST },
    );
    const texts = ["alpha beta", "gamma delta epsilon"];
    const vectors = await embedder.embed(texts);
    expect(vectors).toHaveLength(2);
    expect(embedder.dim).toBe(4);

    expect(ledger.rows).toHaveLength(1);
    const expectedTokens = estimateTokens(texts.join("\n"));
    expect(ledger.rows[0]).toEqual({
      ns: "org/team-a",
      kind: "embed",
      tokens: expectedTokens,
      usd: (expectedTokens / 1e6) * EMBED_USD_PER_MILLION_TOKENS,
    });
  });

  it("rethrows CircuitOpenError when the breaker is open (vector lane degrades)", async () => {
    const ledger = new FakeLedger();
    let t = 0;
    const embedder = new ResilientEmbedder(
      new DeadEmbedder(),
      ledger,
      "org/team-a",
      {
        retry: { retries: 0, baseDelayMs: 1, timeoutMs: 1_000 },
        breaker: { now: () => t },
      },
    );
    for (let i = 0; i < 5; i++) {
      await expect(embedder.embed(["x"])).rejects.toThrow("embed down");
    }
    // NOT wrapped in LlmUnavailableError — callers fall back to BM25.
    await expect(embedder.embed(["x"])).rejects.toBeInstanceOf(
      CircuitOpenError,
    );
    expect(ledger.rows).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// WriteQueue
// ---------------------------------------------------------------------------

describe("WriteQueue", () => {
  it("processes jobs sequentially in enqueue order", async () => {
    const order: string[] = [];
    let concurrent = 0;
    let maxConcurrent = 0;
    const queue = new WriteQueue<string, string>(async (req) => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((r) => setTimeout(r, 5));
      order.push(req);
      concurrent--;
      return `done:${req}`;
    });

    const t1 = queue.enqueue("a", identity);
    const t2 = queue.enqueue("b", identity);
    const t3 = queue.enqueue("c", identity);
    expect(t1.ticket).not.toBe(t2.ticket);

    await queue.drain();
    expect(order).toEqual(["a", "b", "c"]);
    expect(maxConcurrent).toBe(1);
    expect(queue.status(t3.ticket)).toEqual({
      state: "done",
      result: "done:c",
    });
  });

  it("status transitions queued → running → done with the result", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const queue = new WriteQueue<string, string>(async (req) => {
      await gate;
      return `ok:${req}`;
    });

    const { ticket: first } = queue.enqueue("one", identity);
    const { ticket: second } = queue.enqueue("two", identity);

    // Let the worker pick up the first job.
    await new Promise((r) => setImmediate(r));
    expect(queue.status(first)?.state).toBe("running");
    expect(queue.status(second)?.state).toBe("queued");

    release();
    await queue.drain();
    expect(queue.status(first)).toEqual({ state: "done", result: "ok:one" });
    expect(queue.status(second)).toEqual({ state: "done", result: "ok:two" });
  });

  it("a failed job records the error and does not kill the worker", async () => {
    const queue = new WriteQueue<string, string>(async (req) => {
      if (req === "bad") throw new Error("write exploded");
      return `ok:${req}`;
    });
    const { ticket: badTicket } = queue.enqueue("bad", identity);
    const { ticket: goodTicket } = queue.enqueue("good", identity);
    await queue.drain();

    expect(queue.status(badTicket)).toEqual({
      state: "failed",
      error: "write exploded",
    });
    expect(queue.status(goodTicket)).toEqual({
      state: "done",
      result: "ok:good",
    });
  });

  it("returns undefined for unknown tickets", () => {
    const queue = new WriteQueue<string, string>(async () => "x");
    expect(queue.status("01NOTATICKET00000000000000")).toBeUndefined();
  });

  it("retains only the most recent results (LRU) and status() refreshes recency", async () => {
    // Cap of 3 exercises the same LRU path as the production cap of 500.
    const queue = new WriteQueue<string, string>(async (req) => req, 3);
    const tickets: string[] = [];
    for (const req of ["a", "b", "c"]) {
      tickets.push(queue.enqueue(req, identity).ticket);
    }
    await queue.drain();

    // Touch "a" so it becomes most-recently-used.
    expect(queue.status(tickets[0])?.result).toBe("a");

    // Adding "d" evicts the least-recently-used terminal entry: "b".
    const { ticket: d } = queue.enqueue("d", identity);
    await queue.drain();
    expect(queue.status(tickets[1])).toBeUndefined(); // b evicted
    expect(queue.status(tickets[0])?.result).toBe("a"); // survived via touch
    expect(queue.status(tickets[2])?.result).toBe("c");
    expect(queue.status(d)?.result).toBe("d");
  });

  it("worker restarts for jobs enqueued after a drain", async () => {
    const queue = new WriteQueue<string, string>(async (req) => `r:${req}`);
    const { ticket: a } = queue.enqueue("a", identity);
    await queue.drain();
    const { ticket: b } = queue.enqueue("b", identity);
    await queue.drain();
    expect(queue.status(a)?.result).toBe("r:a");
    expect(queue.status(b)?.result).toBe("r:b");
  });
});
