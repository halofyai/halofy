/**
 * Module F NFR perf spec — boots the REAL Kernel on in-memory PGlite
 * (HashEmbedder + StubLlm, zero network), seeds ~30 verbatim facts, then runs
 * 200 mixed syscalls (read/search/fault/assemble) recorded through
 * MetricsRegistry and FAILS if any in-process p95 gate blows:
 *
 *   index_read_p95_ms  < 10    assemble_p95_ms < 300    fault_p95_ms < 500
 *
 * M1 (D9): syscalls take a resolved Identity — an owner key is issued at
 * setup (bootstrap path) and the perf namespace's policy raises
 * rateLimitPerMin so the measurement loop is not throttled (we are measuring
 * syscall latency, not the token bucket). The measurement loop, 50/50/50/50
 * op mix, warm-up, and gate assertions are unchanged from v0.1.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Kernel } from "../src/kernel.js";
import { MetricsRegistry } from "../src/metrics/index.js";
import type { Identity, WriteResult } from "../src/types.js";
import type { MemWriteResult } from "../src/syscalls/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KNOWLEDGE_DIR = path.resolve(__dirname, "..", "knowledge");

const NS = "halo/perf/agent1";
const ACTOR = "perf-tester";
const AGENT = "vitest-perf";

const FACT_COUNT = 30;
const SYSCALL_COUNT = 200;
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const TOPICS = [
  "refund policy window is 30 days for standard plans",
  "customer Priya Sharma prefers email over phone",
  "the on-call rotation swaps every Monday at 09:00 UTC",
  "invoice disputes escalate to the billing team lead",
  "enterprise SLA guarantees 99.9 percent uptime",
  "the support macro for password resets is SR-114",
  "quarterly business reviews happen in the second week",
  "shipping to EU regions adds two business days",
  "the churn dashboard refreshes hourly at minute 15",
  "priority tickets must get a first response in 1 hour",
];

function factContent(i: number): string {
  return `Perf fact ${i}: ${TOPICS[i % TOPICS.length]} (variant ${Math.floor(i / TOPICS.length)}).`;
}

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

let kernel: Kernel;
let registry: MetricsRegistry;
let identity: Identity;
const storedIds: string[] = [];

describe(`NFR perf gates (${TEST_DATABASE_URL ? "real Postgres/pgvector" : "in-process PGlite"})`, () => {
  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: TEST_DATABASE_URL,
      pgliteDataDir: "", // in-memory PGlite when TEST_DATABASE_URL is absent
      knowledgeDir: KNOWLEDGE_DIR,
      anthropicApiKey: "", // StubLlm
      openaiApiKey: "", // HashEmbedder, dim 256
      embedDim: 256,
    });
    registry = new MetricsRegistry();

    // Bootstrap owner key bound to the perf namespace (D9).
    const { plaintext } = await kernel.auth.issueKey(NS, ACTOR, "owner");
    identity = (await kernel.auth.resolve(plaintext))!;
    expect(identity).toBeTruthy();

    // The default 60/min token bucket would throttle a tight 270-call loop;
    // we are gating syscall latency, not the rate limiter.
    await kernel.setPolicy(NS, "rateLimitPerMin: 1000000\n");

    // Seed ~30 verbatim facts (writes are NOT part of the measured gates).
    for (let i = 0; i < FACT_COUNT; i++) {
      const result = sync(
        await kernel.memWrite(
          { scope: "user", content: factContent(i), hints: { verbatim: true, type: "fact" } },
          identity,
          AGENT,
        ),
      );
      for (const obj of result.stored) storedIds.push(obj.id);
    }
    expect(storedIds.length).toBeGreaterThanOrEqual(FACT_COUNT * 0.8);

    // Later variants can legitimately supersede earlier seeded rows. Normal
    // reads now hide closed history, so the latency lane must sample the active
    // working set rather than stale ids retained only for D7 history.
    const active = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL
        ORDER BY id`,
      [NS],
    );
    storedIds.splice(0, storedIds.length, ...active.rows.map((row) => String(row.id)));
    expect(storedIds.length).toBeGreaterThan(0);

    // Unmeasured warm-up: first calls pay one-time V8/PGlite compile + plan
    // costs (amplified inside the vitest worker) that are not steady-state
    // latency. Ten rounds settles the JIT before the measured loop.
    for (let i = 0; i < 10; i++) {
      await kernel.memRead({ id: storedIds[i % storedIds.length]! }, identity, AGENT);
      await kernel.memSearch({ query: TOPICS[i % TOPICS.length]! }, identity, AGENT);
      await kernel.memFault({ query: TOPICS[(i + 1) % TOPICS.length]! }, identity, AGENT);
      await kernel.memAssemble({ taskHint: TOPICS[(i + 2) % TOPICS.length] }, identity, AGENT);
    }
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
  });

  it(
    `runs ${SYSCALL_COUNT} mixed syscalls and passes every p95 gate`,
    async () => {
      for (let i = 0; i < SYSCALL_COUNT; i++) {
        switch (i % 4) {
          case 0: {
            const id = storedIds[i % storedIds.length]!;
            const res = await registry.time("read", () =>
              kernel.memRead({ id }, identity, AGENT),
            );
            expect(res.found).toBe(true);
            break;
          }
          case 1: {
            const query = TOPICS[i % TOPICS.length]!;
            const refs = await registry.time("search", () =>
              kernel.memSearch({ query, k: 5 }, identity, AGENT),
            );
            expect(refs.length).toBeGreaterThan(0);
            break;
          }
          case 2: {
            const query = TOPICS[(i + 3) % TOPICS.length]!;
            const res = await registry.time("fault", () =>
              kernel.memFault({ query, k: 3 }, identity, AGENT),
            );
            expect(res.hit).toBe(true);
            break;
          }
          case 3: {
            const ws = await registry.time("assemble", () =>
              kernel.memAssemble(
                { taskHint: TOPICS[(i + 7) % TOPICS.length] },
                identity,
                AGENT,
              ),
            );
            expect(ws.namespace).toBe(NS);
            break;
          }
        }
      }

      const snap = registry.snapshot();

      // All 200 syscalls were recorded, 50 per op.
      expect(snap.ops["read"]!.count).toBe(SYSCALL_COUNT / 4);
      expect(snap.ops["search"]!.count).toBe(SYSCALL_COUNT / 4);
      expect(snap.ops["fault"]!.count).toBe(SYSCALL_COUNT / 4);
      expect(snap.ops["assemble"]!.count).toBe(SYSCALL_COUNT / 4);

      // The point of this suite: every NFR gate must pass in-process.
      // Evaluate the kernel's instrumented boundaries. The index gate measures
      // getById itself, excluding auth and the atomic telemetry/audit commit.
      for (const g of kernel.metrics.snapshot().nfr) {
        expect(
          g.pass,
          `${g.gate}: p95=${g.actual.toFixed(2)}ms exceeds budget ${g.budget}ms`,
        ).toBe(true);
      }
    },
    180_000,
  );
});
