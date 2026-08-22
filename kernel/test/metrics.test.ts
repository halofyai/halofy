/**
 * Module F unit spec — Histogram percentile math, MetricsRegistry snapshot /
 * NFR gate evaluation, structured logger. Pure in-process, zero I/O.
 */

import { describe, it, expect, afterEach } from "vitest";
import {
  Histogram,
  MetricsRegistry,
  createLogger,
  type MetricsSnapshot,
} from "../src/metrics/index.js";

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

describe("Histogram", () => {
  it("computes nearest-rank percentiles on known values 1..100", () => {
    const h = new Histogram();
    // Insert shuffled so ordering cannot be accidental.
    const values = Array.from({ length: 100 }, (_, i) => i + 1);
    for (let i = values.length - 1; i > 0; i--) {
      const j = (i * 7919) % (i + 1); // deterministic pseudo-shuffle
      [values[i], values[j]] = [values[j]!, values[i]!];
    }
    for (const v of values) h.record(v);

    expect(h.count).toBe(100);
    expect(h.percentile(50)).toBe(50);
    expect(h.percentile(95)).toBe(95);
    expect(h.percentile(99)).toBe(99);
    expect(h.percentile(100)).toBe(100);
    expect(h.percentile(1)).toBe(1);
  });

  it("single sample: every percentile returns that sample", () => {
    const h = new Histogram();
    h.record(42);
    expect(h.percentile(50)).toBe(42);
    expect(h.percentile(95)).toBe(42);
    expect(h.percentile(99)).toBe(42);
  });

  it("empty histogram: percentile is 0, count is 0", () => {
    const h = new Histogram();
    expect(h.count).toBe(0);
    expect(h.percentile(50)).toBe(0);
    expect(h.percentile(95)).toBe(0);
  });

  it("ring buffer evicts oldest beyond 1024 samples; count keeps totals", () => {
    const h = new Histogram();
    for (let i = 1; i <= 2048; i++) h.record(i);
    expect(h.count).toBe(2048);
    // Window is the last 1024 samples: 1025..2048.
    expect(h.percentile(1)).toBeGreaterThanOrEqual(1025);
    expect(h.percentile(100)).toBe(2048);
    expect(h.percentile(50)).toBe(1025 + 511); // nearest-rank median of 1025..2048
  });

  it("ignores non-finite samples", () => {
    const h = new Histogram();
    h.record(Number.NaN);
    h.record(Number.POSITIVE_INFINITY);
    h.record(5);
    expect(h.count).toBe(1);
    expect(h.percentile(95)).toBe(5);
  });

  it("rejects non-positive capacity", () => {
    expect(() => new Histogram(0)).toThrow(RangeError);
    expect(() => new Histogram(-1)).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// MetricsRegistry
// ---------------------------------------------------------------------------

function gate(snapshot: MetricsSnapshot, name: string) {
  const g = snapshot.nfr.find((x) => x.gate === name);
  expect(g, `gate ${name} present`).toBeDefined();
  return g!;
}

describe("MetricsRegistry", () => {
  it("timer(op) returns a recorder that feeds the op histogram", () => {
    const reg = new MetricsRegistry();
    const done = reg.timer("read");
    done(3);
    done(5);
    const snap = reg.snapshot();
    expect(snap.ops["read"]!.count).toBe(2);
    expect(snap.ops["read"]!.p95).toBe(5);
  });

  it("time(op, fn) records duration and returns fn's value", async () => {
    const reg = new MetricsRegistry();
    const result = await reg.time("search", async () => "hits");
    expect(result).toBe("hits");
    expect(reg.snapshot().ops["search"]!.count).toBe(1);
    expect(reg.snapshot().ops["search"]!.p95).toBeGreaterThanOrEqual(0);
  });

  it("time(op, fn) still records when fn throws", async () => {
    const reg = new MetricsRegistry();
    await expect(
      reg.time("write", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(reg.snapshot().ops["write"]!.count).toBe(1);
  });

  it("snapshot exposes all three NFR gates with budgets", () => {
    const snap = new MetricsRegistry().snapshot();
    expect(gate(snap, "index_read_p95_ms").budget).toBe(10);
    expect(gate(snap, "assemble_p95_ms").budget).toBe(300);
    expect(gate(snap, "fault_p95_ms").budget).toBe(500);
    // No traffic → vacuous pass with actual 0.
    for (const g of snap.nfr) {
      expect(g.actual).toBe(0);
      expect(g.pass).toBe(true);
    }
  });

  it("gates flip pass → fail when p95 blows the budget, per mapped op", () => {
    const reg = new MetricsRegistry();
    const read = reg.timer("index-read");
    for (let i = 0; i < 100; i++) read(2); // well under 10ms
    let snap = reg.snapshot();
    expect(gate(snap, "index_read_p95_ms").pass).toBe(true);
    expect(gate(snap, "index_read_p95_ms").actual).toBe(2);

    for (let i = 0; i < 100; i++) read(50); // blow the 10ms budget
    snap = reg.snapshot();
    expect(gate(snap, "index_read_p95_ms").pass).toBe(false);
    expect(gate(snap, "index_read_p95_ms").actual).toBe(50);

    // index-read traffic must not touch the other gates.
    expect(gate(snap, "assemble_p95_ms").pass).toBe(true);
    expect(gate(snap, "fault_p95_ms").pass).toBe(true);

    const assemble = reg.timer("assemble");
    for (let i = 0; i < 20; i++) assemble(400); // > 300ms budget
    const fault = reg.timer("fault");
    for (let i = 0; i < 20; i++) fault(100); // < 500ms budget
    snap = reg.snapshot();
    expect(gate(snap, "assemble_p95_ms").pass).toBe(false);
    expect(gate(snap, "assemble_p95_ms").actual).toBe(400);
    expect(gate(snap, "fault_p95_ms").pass).toBe(true);
    expect(gate(snap, "fault_p95_ms").actual).toBe(100);
  });

  it("snapshot carries startedAt (ISO) and non-negative uptimeSec", () => {
    const snap = new MetricsRegistry().snapshot();
    expect(new Date(snap.startedAt).toISOString()).toBe(snap.startedAt);
    expect(snap.uptimeSec).toBeGreaterThanOrEqual(0);
  });

  it("ops not mapped to a gate appear in ops but not in nfr", () => {
    const reg = new MetricsRegistry();
    reg.timer("stats")(1);
    const snap = reg.snapshot();
    expect(snap.ops["stats"]!.count).toBe(1);
    expect(snap.nfr.map((g) => g.gate)).toEqual([
      "index_read_p95_ms",
      "assemble_p95_ms",
      "fault_p95_ms",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

describe("structured logger", () => {
  const ENV_KEY = "HALOMEM_LOG_LEVEL";
  const originalEnv = process.env[ENV_KEY];

  afterEach(() => {
    if (originalEnv === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = originalEnv;
  });

  function capture() {
    const lines: string[] = [];
    return { lines, sink: (line: string) => lines.push(line) };
  }

  it("emits single-line parseable JSON with ts, level, msg, fields", () => {
    const { lines, sink } = capture();
    const logger = createLogger({ level: "info", sink });
    logger.info("kernel booted", { op: "boot", tookMs: 12 });

    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("\n");
    const entry = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(entry.level).toBe("info");
    expect(entry.msg).toBe("kernel booted");
    expect(entry.op).toBe("boot");
    expect(entry.tookMs).toBe(12);
    expect(new Date(entry.ts as string).toISOString()).toBe(entry.ts);
  });

  it("filters below the configured level", () => {
    const { lines, sink } = capture();
    const logger = createLogger({ level: "warn", sink });
    logger.debug("d");
    logger.info("i");
    logger.warn("w");
    logger.error("e");
    expect(lines.map((l) => (JSON.parse(l) as { level: string }).level)).toEqual([
      "warn",
      "error",
    ]);
  });

  it("defaults to info and respects HALOMEM_LOG_LEVEL from env", () => {
    const { lines, sink } = capture();
    const logger = createLogger({ sink }); // no explicit level → env-driven

    delete process.env[ENV_KEY];
    logger.debug("hidden by default info");
    logger.info("visible");
    expect(lines).toHaveLength(1);

    process.env[ENV_KEY] = "debug";
    logger.debug("now visible");
    expect(lines).toHaveLength(2);

    process.env[ENV_KEY] = "error";
    logger.warn("suppressed");
    logger.error("kept");
    expect(lines).toHaveLength(3);

    process.env[ENV_KEY] = "not-a-level";
    logger.info("falls back to info");
    expect(lines).toHaveLength(4);
  });

  it("child(fields) binds fields; call-site fields win on collision", () => {
    const { lines, sink } = capture();
    const base = createLogger({ level: "info", sink });
    const child = base.child({ op: "write", namespace: "halo/team" });

    child.info("stored");
    child.info("override", { op: "supersede", extra: true });

    const first = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(first.op).toBe("write");
    expect(first.namespace).toBe("halo/team");

    const second = JSON.parse(lines[1]!) as Record<string, unknown>;
    expect(second.op).toBe("supersede");
    expect(second.namespace).toBe("halo/team");
    expect(second.extra).toBe(true);
  });

  it("bound/call fields cannot shadow ts/level/msg", () => {
    const { lines, sink } = capture();
    const logger = createLogger({ level: "info", sink });
    logger.info("real message", { msg: "fake", level: "error", ts: "0000" });
    const entry = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(entry.msg).toBe("real message");
    expect(entry.level).toBe("info");
    expect(entry.ts).not.toBe("0000");
  });

  it("survives unserializable fields without throwing", () => {
    const { lines, sink } = capture();
    const logger = createLogger({ level: "info", sink });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => logger.info("circular", { circular })).not.toThrow();
    const entry = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(entry.msg).toBe("circular");
  });
});
