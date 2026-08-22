/**
 * E10 perf gate — the usage rollup is timed on COLD computes at usage scale.
 *
 * Fixture: 1,000,000 usage_events + 200,000 query_traces when
 * TEST_DATABASE_URL points at real Postgres (the CI perf lane) — there the
 * p95 ≤ 500 ms cold gate applies. The hermetic PGlite lane seeds a smaller
 * 150,000 / 30,000 fixture and runs the SAME cold-path timing, but gates
 * against a PGlite-scaled bound instead: measured 2026-07-22, PGlite's wasm
 * serializer aggregates ~50k rows/s (a 12-aggregate GROUP BY over 150k rows
 * costs ~7 s; even a 20k-row fixture cold-computes in ~2.7 s), so a 500 ms
 * cold gate on PGlite would require a toy fixture that exercises nothing.
 * The hermetic bound (30 s) still fails the lane on a pathological
 * regression — row-at-a-time fetches, a dropped cursor chunk, an accidental
 * raw-event pull — which is what this test exists to catch.
 *
 * Every TIMED iteration is a cold compute: between runs we insert one fresh
 * usage_events row, which moves the max(audit_seq) high-water mark and
 * exactly invalidates the watermark+TTL result cache (migration v49). The
 * gate therefore guards the exact incremental team aggregation path, not a
 * stale result-cache hit.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KNOWLEDGE_DIR = path.resolve(__dirname, "..", "knowledge");

const ON_REAL_PG = Boolean(process.env.TEST_DATABASE_URL);
const EVENT_COUNT = ON_REAL_PG ? 1_000_000 : 150_000;
const TRACE_COUNT = ON_REAL_PG ? 200_000 : 30_000;
const EVENT_BATCH = ON_REAL_PG ? 250_000 : 150_000;
const WARM_UP = 1;
// Cold PGlite computes cost ~15 s each at 150k rows; keep the hermetic lane
// to 3 timed runs (p95 = max) so the suite stays fast. Real PG: 10 runs.
const RUNS = ON_REAL_PG ? 10 : 3;
/** Cold p95 gate: 500 ms on real Postgres (the E10 target); see header. */
const GATE_P95_MS = ON_REAL_PG ? 500 : 30_000;

const ROOT: Identity = {
  keyId: "usage-perf-root",
  namespace: "",
  actor: "owner:root",
  role: "owner",
};

let kernel: Kernel;

const NS_CASE = `CASE g % 5
    WHEN 0 THEN 'acme/support'
    WHEN 1 THEN 'acme/sales'
    WHEN 2 THEN 'acme/eng'
    WHEN 3 THEN 'globex'
    ELSE 'acme/support/triage' END`;

describe(`E10 usage rollup perf gate (${EVENT_COUNT} usage_events, ${ON_REAL_PG ? "real Postgres" : "in-process PGlite"})`, () => {
  beforeAll(async () => {
    const t0 = performance.now();
    kernel = await Kernel.boot({
      databaseUrl: process.env.TEST_DATABASE_URL ?? "",
      pgliteDataDir: "",
      knowledgeDir: KNOWLEDGE_DIR,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });

    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
       VALUES ('team-acme', 'acme', 'Acme', '', 'usage-perf', now()),
              ('team-support', 'acme/support', 'Support', '', 'usage-perf', now())
       ON CONFLICT (id) DO NOTHING`,
    );
    // audit_seq FK targets (usage_events.audit_seq REFERENCES audit_log(seq)).
    await kernel.db.query(
      `INSERT INTO audit_log (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail)
       SELECT now(), 'usage-perf', 'usage-perf', 'search', NULL, 'acme', 'usage-perf', 'ok', NULL
         FROM generate_series(1, 1000)`,
    );
    await kernel.db.query(
      `INSERT INTO query_traces
         (trace_id, ts, namespace, actor, query_sha256, query_summary, events,
          latency_ms, tokens, usd, outcome)
       SELECT
         'trace-' || g,
         now() - ((g % 2592000) * interval '1 second'),
         ${NS_CASE},
         'actor-' || (g % 20),
         NULL,
         'perf question ' || (g % 500),
         5,
         100 + (g % 400),
         25,
         (g % 100) * 0.001,
         CASE WHEN g % 7 = 0 THEN 'weak' ELSE NULL END
       FROM generate_series(1, ${TRACE_COUNT}) g`,
    );
    for (let start = 1; start <= EVENT_COUNT; start += EVENT_BATCH) {
      await kernel.db.query(
        `INSERT INTO usage_events
           (id, audit_seq, trace_id, ts, namespace, actor, principal, caller_class,
            op, tool, result, latency_ms, tokens, returned, driver, source_tier,
            source_ids, top_score)
         SELECT
           'evt-' || g,
           1 + (g % 1000),
           'trace-' || (1 + (g % ${TRACE_COUNT})),
           now() - ((g % 2592000) * interval '1 second'),
           ${NS_CASE},
           'actor-' || (g % 20),
           CASE WHEN g % 3 = 0 THEN 'agent' ELSE 'human' END,
           CASE g % 4 WHEN 0 THEN 'internal' WHEN 1 THEN 'external' ELSE 'unclassified' END,
           'search',
           NULL,
           CASE WHEN g % 17 = 0 THEN 'denied' ELSE 'ok' END,
           5 + ((g * 7) % 900),
           g % 50,
           CASE WHEN g % 4 = 0 THEN 0 ELSE 1 + (g % 6) END,
           CASE WHEN g % 2 = 0 THEN 'baseline' ELSE 'mem0' END,
           CASE g % 5 WHEN 0 THEN NULL WHEN 1 THEN 'L2' WHEN 2 THEN 'L3' WHEN 3 THEN 'live' ELSE 'warm' END,
           NULL,
           NULL
         FROM generate_series(${start}, ${start + EVENT_BATCH - 1}) g`,
      );
    }
    const seeded = await kernel.db.query(
      `SELECT (SELECT count(*) FROM usage_events) AS events,
              (SELECT count(*) FROM query_traces) AS traces`,
    );
    const counts = seeded.rows[0] as { events: unknown; traces: unknown };
    expect(Number(counts.events)).toBeGreaterThanOrEqual(EVENT_COUNT);
    expect(Number(counts.traces)).toBeGreaterThanOrEqual(TRACE_COUNT);
    console.log(
      `[usage-perf] seeded ${EVENT_COUNT} events + ${TRACE_COUNT} traces in ${Math.round(performance.now() - t0)} ms`,
    );
  }, 300_000);

  afterAll(async () => {
    await kernel.close();
  });

  /**
   * Move the max(audit_seq) watermark so the next rollup call can NOT be
   * served from the result cache — the timed run is a true cold compute.
   */
  async function invalidateRollupCache(tag: number): Promise<void> {
    const seq = await kernel.db.query(
      `INSERT INTO audit_log (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail)
       VALUES (now(), 'usage-perf', 'usage-perf', 'search', NULL, 'acme', 'usage-perf', 'ok', NULL)
       RETURNING seq`,
    );
    await kernel.db.query(
      `INSERT INTO usage_events
         (id, audit_seq, trace_id, ts, namespace, actor, principal, caller_class,
          op, result, latency_ms)
       VALUES ($1, $2, 'trace-1', now(), 'acme', 'actor-1', 'human', 'internal', 'search', 'ok', 1)`,
      [`evt-invalidate-${tag}`, Number((seq.rows[0] as { seq: unknown }).seq)],
    );
  }

  it(`usageRollup COLD p95 ≤ ${GATE_P95_MS} ms (${RUNS} cache-invalidated runs, ${ON_REAL_PG ? "E10 gate" : "PGlite-scaled bound"})`, async () => {
    for (let i = 0; i < WARM_UP; i += 1) {
      await kernel.usageRollup(ROOT, { days: 30, groupBy: "team" });
    }
    const samples: number[] = [];
    let last;
    for (let i = 0; i < RUNS; i += 1) {
      await invalidateRollupCache(i);
      const t0 = performance.now();
      last = await kernel.usageRollup(ROOT, { days: 30, groupBy: "team" });
      samples.push(performance.now() - t0);
    }
    const sorted = [...samples].sort((a, b) => a - b);
    const p50 = sorted[Math.max(0, Math.ceil(0.5 * sorted.length) - 1)] ?? 0;
    const p95 = sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)] ?? 0;
    console.log(
      `[usage-perf] COLD rollup wall ms (${ON_REAL_PG ? "pg" : "pglite"}, ${EVENT_COUNT} rows): min=${Math.round(sorted[0] ?? 0)} p50=${Math.round(p50)} p95=${Math.round(p95)} max=${Math.round(sorted[sorted.length - 1] ?? 0)}`,
    );

    // Shape sanity: the whole seeded scope is rolled up.
    expect(last?.totals.events).toBeGreaterThanOrEqual(EVENT_COUNT);
    expect(last?.totals.queries).toBeGreaterThan(0);
    expect(last?.groups.length).toBeGreaterThan(0);

    expect(p95).toBeLessThanOrEqual(GATE_P95_MS);
  }, 120_000);
});
