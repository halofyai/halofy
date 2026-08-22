/**
 * HaloMem observability (M1 module F).
 *
 * In-process latency histograms + NFR gate evaluation. Zero dependencies,
 * zero I/O — the syscall layer records durations here and `snapshot()` is
 * served verbatim from `GET /metrics` and the perf suite.
 *
 * NFR gates (CONTRACTS-M1.md, in-process budgets):
 *   index-read → index_read_p95_ms  < 10ms
 *   assemble → assemble_p95_ms    < 300ms
 *   fault    → fault_p95_ms       < 500ms
 */

export { Logger, createLogger, log, type LogFields, type LogLevel, type LoggerOptions } from "./log.js";

// ---------------------------------------------------------------------------
// Histogram — fixed-size ring buffer of duration samples (ms)
// ---------------------------------------------------------------------------

const DEFAULT_CAPACITY = 1024;

export class Histogram {
  private readonly capacity: number;
  private readonly samples: number[];
  /** Next write slot in the ring. */
  private next = 0;
  /** Total samples ever recorded (may exceed capacity). */
  private total = 0;

  constructor(capacity: number = DEFAULT_CAPACITY) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      throw new RangeError(`Histogram capacity must be a positive integer, got ${capacity}`);
    }
    this.capacity = capacity;
    this.samples = [];
  }

  /** Record one duration in milliseconds. Oldest sample evicted when full. */
  record(ms: number): void {
    if (!Number.isFinite(ms)) return; // never poison percentiles with NaN/Inf
    if (this.samples.length < this.capacity) {
      this.samples.push(ms);
    } else {
      this.samples[this.next] = ms;
    }
    this.next = (this.next + 1) % this.capacity;
    this.total += 1;
  }

  /** Total samples ever recorded (not capped at ring capacity). */
  get count(): number {
    return this.total;
  }

  /**
   * Nearest-rank percentile over the retained window (last `capacity`
   * samples). `p` in (0, 100]. Empty histogram → 0.
   */
  percentile(p: number): number {
    const n = this.samples.length;
    if (n === 0) return 0;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const clamped = Math.min(100, Math.max(0, p));
    const rank = Math.max(1, Math.ceil((clamped / 100) * n));
    return sorted[rank - 1]!;
  }
}

// ---------------------------------------------------------------------------
// NFR gates
// ---------------------------------------------------------------------------

export interface NfrGateResult {
  gate: string;
  budget: number;
  actual: number;
  pass: boolean;
}

export interface OpStats {
  count: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface MetricsSnapshot {
  ops: Record<string, OpStats>;
  nfr: NfrGateResult[];
  /** ISO-8601 timestamp of registry construction (≈ kernel boot). */
  startedAt: string;
  uptimeSec: number;
}

/** op → gate mapping with in-process p95 budgets (ms). */
const NFR_GATES: ReadonlyArray<{ gate: string; op: string; budget: number }> = [
  { gate: "index_read_p95_ms", op: "index-read", budget: 10 },
  { gate: "assemble_p95_ms", op: "assemble", budget: 300 },
  { gate: "fault_p95_ms", op: "fault", budget: 500 },
];

// ---------------------------------------------------------------------------
// MetricsRegistry — one histogram per syscall op
// ---------------------------------------------------------------------------

export class MetricsRegistry {
  private readonly histograms = new Map<string, Histogram>();
  private readonly startedAtMs = Date.now();

  /** Get-or-create the histogram for an op. */
  histogram(op: string): Histogram {
    let h = this.histograms.get(op);
    if (!h) {
      h = new Histogram();
      this.histograms.set(op, h);
    }
    return h;
  }

  /**
   * Manual recorder: `const done = registry.timer("read"); ...; done(ms)`.
   * The returned function may be called any number of times; each call
   * records one sample.
   */
  timer(op: string): (durationMs: number) => void {
    const h = this.histogram(op);
    return (durationMs: number) => h.record(durationMs);
  }

  /**
   * Async wrapper: times `fn` with performance.now() and records the duration
   * even when `fn` throws/rejects (latency of failures counts against gates).
   */
  async time<T>(op: string, fn: () => T | Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      this.histogram(op).record(performance.now() - start);
    }
  }

  /** Point-in-time stats + NFR gate table. Safe to serve as JSON verbatim. */
  snapshot(): MetricsSnapshot {
    const ops: Record<string, OpStats> = {};
    for (const [op, h] of this.histograms) {
      ops[op] = {
        count: h.count,
        p50: h.percentile(50),
        p95: h.percentile(95),
        p99: h.percentile(99),
      };
    }

    const nfr: NfrGateResult[] = NFR_GATES.map(({ gate, op, budget }) => {
      const h = this.histograms.get(op);
      // No traffic on the op yet → vacuously passing with actual 0.
      const actual = h && h.count > 0 ? h.percentile(95) : 0;
      return { gate, budget, actual, pass: actual <= budget };
    });

    return {
      ops,
      nfr,
      startedAt: new Date(this.startedAtMs).toISOString(),
      uptimeSec: Math.floor((Date.now() - this.startedAtMs) / 1000),
    };
  }
}
