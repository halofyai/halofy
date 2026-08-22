/**
 * M2 exit criteria (CONTRACTS-M2.md, integrator wiring §5) — the whole
 * cartridge story through the REAL kernel:
 *
 *   (a) setPolicy retriever:'graph' → the very next search runs on the graph
 *       driver (audit detail proves it) with no reboot;
 *   (b) abTest 50/50 → both arms observed across 40 distinct queries and the
 *       SAME query always lands on the SAME driver (deterministic FNV split);
 *   (c) sibling-namespace canaries are unreachable through baseline AND graph
 *       AND a mounted fake-mem0 whose sidecar actively tries to inject them;
 *   (d) the fake sidecar dies mid-test → mem0 falls back to baseline, the
 *       fallback is audited, and the caller still gets results;
 *   (e) the conformance kit passes baseline + graph and FAILS a deliberately
 *       broken driver;
 *   (f) the referee scorecard runs on a demo-shaped corpus with real numbers
 *       (table printed in the test output) and persists its row — also
 *       exercised over POST /v1/admin/scorecard.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm; the mem0 sidecar is a
 * node:http fake on an ephemeral loopback port (never python).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { Kernel } from "../src/kernel.js";
import { BaselineDriver } from "../src/driver/index.js";
import { GraphDriver } from "../src/driver/graph.js";
import { Mem0Driver } from "../src/driver/mem0.js";
import { pickDriverName } from "../src/routing/index.js";
import {
  buildConformanceHarness,
  runConformance,
  type ConformanceHarness,
} from "../src/conformance/index.js";
import { LeakyBudgetBusterDriver } from "./conformance-drivers.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/server.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import type { Identity } from "../src/types.js";
import type { WriteResult } from "../src/types.js";

const AGENT = "m2-exit";
const NS_A = "exit/team-a/agent";
const NS_B = "exit/team-b/agent";
const NS_DEMO = "m2demo/support/agent-1";

const FACTS_A = [
  "The quarterly launch review for Project Falcon happens every second Tuesday",
  "Rosalind keeps the deployment runbook in the shared vault folder",
  "The Springfield depot stores fourteen crates of amber resin",
  "Order 4127 for Dana Whitfield ships to 99 Elm Street in Springfield",
  "The telemetry cron job rotates its logfile at three in the morning",
] as const;

const CANARIES_B = [
  "CANARY-ZEBRA the vault passphrase is nightingale-obsidian",
  "CANARY-YANKEE the payroll ledger hides in the mango folder",
  "CANARY-XRAY the acquisition target is Meridian Robotics",
] as const;

/** Demo-corpus-shaped facts (mirrors demo.ts's support conversation). */
const FACTS_DEMO = [
  "customer Dana Whitfield's current shipping address for order 4127 is 12 Elm Street, Springfield",
  "Dana Whitfield's loyalty tier is Gold and her preferred contact channel is email",
  "order 4127 contains a jade planter and two ceramic mugs from the autumn catalog",
  "the Springfield fulfillment center hands parcels to the courier at seven each evening",
  "refund requests for damaged ceramics route to the pottery claims queue",
  "the support rotation for weekend escalations belongs to the crimson pod",
  "Dana Whitfield reported the first mug arrived chipped on the northeast corner",
  "replacement shipments for chipped ceramics leave within two business days",
] as const;

let kernel: Kernel;
let idOwner: Identity;
let ownerKey: string;
let idA: Identity;
let idB: Identity;
let idDemo: Identity;
let memberKeyA: string;
let canaryIds: string[] = [];

// ---------------------------------------------------------------------------
// Fake mem0 sidecar: reorders what it is sent AND tries to inject refs it was
// never given (the canaries) — the driver must drop those.
// ---------------------------------------------------------------------------

interface FakeSidecar {
  url: string;
  server: Server;
  requests: number;
  close(): Promise<void>;
}

function startFakeSidecar(injectRefs: () => string[]): Promise<FakeSidecar> {
  return new Promise((resolve) => {
    const state = { requests: 0 };
    const server = createServer((req, res) => {
      state.requests++;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          candidates: { ref: string; content: string }[];
        };
        const refs = [
          // Injection attempt: refs the sidecar was NEVER sent, top-scored.
          ...injectRefs().map((ref) => ({ ref, score: 1 })),
          ...body.candidates.map((c, i) => ({ ref: c.ref, score: 0.9 - i * 0.001 })),
        ];
        const payload = JSON.stringify({ refs });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(payload);
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        server,
        get requests() {
          return state.requests;
        },
        close: () =>
          new Promise<void>((r) => {
            server.closeAllConnections?.();
            server.close(() => r());
          }),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sync(result: Awaited<ReturnType<Kernel["memWrite"]>>): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function writeFact(identity: Identity, content: string): Promise<string> {
  const res = sync(
    await kernel.memWrite(
      { scope: "team", content, hints: { verbatim: true } },
      identity,
      AGENT,
    ),
  );
  expect(res.stored).toHaveLength(1);
  return res.stored[0].id;
}

/** detail of the most recent 'search' audit row in a namespace. */
async function lastSearchDetail(namespace: string): Promise<string> {
  const events = await kernel.audit.list(namespace, { limit: 25 });
  const ev = events.find((e) => e.op === "search");
  expect(ev, "expected a search audit row").toBeDefined();
  return ev?.detail ?? "";
}

/** driver=<name> tokens recorded for every search with this exact purpose. */
async function driversForQuery(namespace: string, query: string): Promise<string[]> {
  const res = await kernel.db.query(
    `SELECT detail FROM audit_log
     WHERE op = 'search' AND namespace = $1 AND purpose = $2
     ORDER BY seq ASC`,
    [namespace, query],
  );
  return (res.rows as Array<{ detail: string | null }>).map((r) => {
    const m = /driver=(\S+)/.exec(r.detail ?? "");
    return m ? m[1] : "<none>";
  });
}

// ---------------------------------------------------------------------------
// Boot + seed
// ---------------------------------------------------------------------------

beforeAll(async () => {
  delete process.env.HALOMEM_MEM0_URL; // mem0 is mounted manually mid-suite

  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "", // in-memory PGlite
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });

  const owner = await kernel.auth.issueKey("", "owner:m2-platform", "owner");
  ownerKey = owner.plaintext;
  const resolved = await kernel.auth.resolve(ownerKey);
  if (!resolved) throw new Error("owner key failed to resolve");
  idOwner = resolved;

  const issue = async (ns: string, actor: string): Promise<[Identity, string]> => {
    const { plaintext } = await kernel.auth.issueKey(ns, actor, "member", idOwner);
    const id = await kernel.auth.resolve(plaintext);
    if (!id) throw new Error(`key for ${ns} failed to resolve`);
    return [id, plaintext];
  };
  [idA, memberKeyA] = await issue(NS_A, "agent:a");
  [idB] = await issue(NS_B, "agent:b");
  [idDemo] = await issue(NS_DEMO, "agent:demo");

  // The suite makes far more than 60 calls/min — raise the subtree limits.
  await kernel.setPolicy("exit", "rateLimitPerMin: 100000\n");
  await kernel.setPolicy("m2demo", "rateLimitPerMin: 100000\n");

  for (const f of FACTS_A) await writeFact(idA, f);
  for (const c of CANARIES_B) canaryIds.push(await writeFact(idB, c));
  for (const f of FACTS_DEMO) await writeFact(idDemo, f);
}, 120_000);

afterAll(async () => {
  await kernel.close();
});

// ---------------------------------------------------------------------------
// (a) retriever swap via setPolicy — no reboot
// ---------------------------------------------------------------------------

describe("M2 exit (a) - config-only retriever swap", () => {
  it("boot mounts baseline + graph (no mem0 without HALOMEM_MEM0_URL)", () => {
    expect(kernel.registry.list()).toEqual(["baseline", "graph"]);
  });

  it("default policy routes search through the baseline driver", async () => {
    const hits = await kernel.memSearch(
      { query: "where does order 4127 for Dana Whitfield ship" },
      idA,
      AGENT,
    );
    expect(hits.length).toBeGreaterThan(0);
    expect(await lastSearchDetail(NS_A)).toContain("driver=baseline");
  });

  it("setPolicy retriever:'graph' takes effect on the NEXT search, no reboot", async () => {
    await kernel.setPolicy(NS_A, "retriever: graph\n");
    const hits = await kernel.memSearch(
      { query: "where does order 4127 for Dana Whitfield ship" },
      idA,
      AGENT,
    );
    expect(hits.length).toBeGreaterThan(0);
    expect(await lastSearchDetail(NS_A)).toContain("driver=graph");

    // ...and swapping back is just as immediate (cache invalidated by set()).
    await kernel.setPolicy(NS_A, "retriever: baseline\n");
    await kernel.memSearch({ query: "amber resin crates depot" }, idA, AGENT);
    expect(await lastSearchDetail(NS_A)).toContain("driver=baseline");
  });

  it("the fault L2 lane routes through the policy driver too", async () => {
    await kernel.setPolicy(NS_A, "retriever: graph\n");
    const res = await kernel.memFault(
      { query: "Springfield depot amber resin crates" },
      idA,
      AGENT,
    );
    expect(res.hit).toBe(true);
    const events = await kernel.audit.list(NS_A, { limit: 10 });
    const ev = events.find((e) => e.op === "fault");
    expect(ev?.detail).toContain("driver=graph");
    await kernel.setPolicy(NS_A, "retriever: baseline\n");
  });
});

// ---------------------------------------------------------------------------
// (b) deterministic A/B split
// ---------------------------------------------------------------------------

describe("M2 exit (b) - abTest 50/50 routing", () => {
  const AB_POLICY = "abTest:\n  a: baseline\n  b: graph\n  pctB: 50\n";
  const queries = Array.from(
    { length: 40 },
    (_, i) => `ab probe ${i} falcon resin runbook telemetry depot`,
  );

  it("routes 40 distinct queries across BOTH arms, deterministically", async () => {
    await kernel.setPolicy(NS_A, AB_POLICY);

    for (const q of queries) {
      await kernel.memSearch({ query: q, k: 3 }, idA, AGENT);
    }

    const observed = new Map<string, string>();
    for (const q of queries) {
      const drivers = await driversForQuery(NS_A, q);
      expect(drivers).toHaveLength(1);
      observed.set(q, drivers[0]);
      // The audit-proven arm matches the pure routing function.
      const predicted = pickDriverName(
        { abTest: { a: "baseline", b: "graph", pctB: 50 } },
        q,
      );
      expect(drivers[0]).toBe(predicted);
    }
    const arms = new Set(observed.values());
    expect(arms).toEqual(new Set(["baseline", "graph"]));
  }, 60_000);

  it("the SAME query always routes to the SAME driver", async () => {
    // Re-run a sample of the queries — every purpose must now have exactly
    // two search rows carrying the same driver.
    for (const q of queries.slice(0, 8)) {
      await kernel.memSearch({ query: q, k: 3 }, idA, AGENT);
      const drivers = await driversForQuery(NS_A, q);
      expect(drivers).toHaveLength(2);
      expect(new Set(drivers).size).toBe(1);
    }
    await kernel.setPolicy(NS_A, "retriever: baseline\n");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (c) canary isolation through EVERY mounted driver + (d) mem0-down fallback
// ---------------------------------------------------------------------------

describe("M2 exit (c)+(d) - canary isolation and mem0 fallback", () => {
  let sidecar: FakeSidecar;
  const mem0Warnings: string[] = [];
  const CANARY_QUERY =
    "CANARY-ZEBRA vault passphrase nightingale obsidian payroll Meridian Robotics";

  beforeAll(async () => {
    sidecar = await startFakeSidecar(() => canaryIds);
    kernel.registry.mount(
      new Mem0Driver({
        url: sidecar.url,
        timeoutMs: 1000,
        warn: (m) => mem0Warnings.push(m),
      }),
    );
  });

  it("sanity: the canaries ARE reachable from their own namespace", async () => {
    const hits = await kernel.memSearch({ query: CANARY_QUERY, k: 5 }, idB, AGENT);
    expect(hits.some((h) => h.content.includes("CANARY"))).toBe(true);
  });

  for (const driver of ["baseline", "graph", "mem0"] as const) {
    it(`ns-B canaries are unreachable through the ${driver} driver`, async () => {
      await kernel.setPolicy(NS_A, `retriever: ${driver}\n`);
      const hits = await kernel.memSearch({ query: CANARY_QUERY, k: 10 }, idA, AGENT);
      for (const h of hits) {
        expect(canaryIds).not.toContain(h.ref);
        expect(h.content).not.toContain("CANARY");
      }
      expect(await lastSearchDetail(NS_A)).toContain(`driver=${driver}`);
    });
  }

  it("the fake sidecar really tried to inject - the driver dropped every alien ref", () => {
    expect(sidecar.requests).toBeGreaterThan(0);
    const dropped = mem0Warnings.filter((m) => m.includes("not in the sent candidate set"));
    expect(dropped.length).toBeGreaterThanOrEqual(canaryIds.length);
  });

  it("(d) sidecar killed mid-test → baseline fallback, audited, caller still served", async () => {
    await sidecar.close(); // mem0 is now dead; policy still says retriever: mem0

    const hits = await kernel.memSearch(
      { query: "where does order 4127 for Dana Whitfield ship" },
      idA,
      AGENT,
    );
    expect(hits.length).toBeGreaterThan(0); // caller never sees the outage

    const detail = await lastSearchDetail(NS_A);
    expect(detail).toContain("driver=baseline");
    expect(detail).toContain("driver_fallback=mem0->baseline");

    await kernel.setPolicy(NS_A, "retriever: baseline\n");
  }, 30_000);
});

// ---------------------------------------------------------------------------
// (e) conformance kit — passes the real drivers, fails a broken one
// ---------------------------------------------------------------------------

describe("M2 exit (e) - conformance kit", () => {
  let harness: ConformanceHarness;
  const srcDir = fileURLToPath(new URL("../src/driver", import.meta.url));

  beforeAll(async () => {
    harness = await buildConformanceHarness();
  }, 60_000);

  afterAll(async () => {
    await harness.close();
  });

  it("baseline and graph pass all six checks", async () => {
    const cases = [
      { driver: new BaselineDriver(), source: join(srcDir, "baseline.ts") },
      { driver: new GraphDriver(), source: join(srcDir, "graph.ts") },
    ];
    for (const { driver, source } of cases) {
      const report = await runConformance(driver, {
        harness,
        quiet: true,
        sourcePath: source,
        latencyBudgetMs: 5000, // generous local/CI bound; default 150ms is the prod gate
      });
      for (const c of report.checks) {
        expect(c.pass, `${driver.name} ${c.id}: ${c.detail}`).toBe(true);
      }
      expect(report.pass).toBe(true);
    }
  }, 60_000);

  it("a leaky, budget-busting driver FAILS the kit", async () => {
    const leaky = new LeakyBudgetBusterDriver([...harness.canaryRefs]);
    const report = await runConformance(leaky, { harness, quiet: true, latencyBudgetMs: 5000 });
    expect(report.pass).toBe(false);
    expect(report.checks.find((c) => c.id === "respects-scoped-view")?.pass).toBe(false);
    expect(report.checks.find((c) => c.id === "budget-discipline")?.pass).toBe(false);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (f) referee scorecard on the demo corpus — real numbers, persisted row,
// admin route
// ---------------------------------------------------------------------------

describe("M2 exit (f) - referee scorecard", () => {
  it("runs every mounted driver over the demo corpus and names a winner", async () => {
    const card = await kernel.runScorecard(NS_DEMO);

    // Print the real table into the test output (exit criterion 5: numbers
    // must be traceable to the run).
    // eslint-disable-next-line no-console
    console.log("\n" + kernel.renderScorecard(card));

    expect(card.namespace).toBe(NS_DEMO);
    expect(card.questionCount).toBeGreaterThanOrEqual(5);
    const names = card.drivers.map((d) => d.driver);
    expect(names).toContain("baseline");
    expect(names).toContain("graph");

    const winner = card.drivers.find((d) => d.driver === card.winner);
    expect(winner).toBeDefined();
    expect(winner!.hitAt3).toBeGreaterThan(0);
    expect(winner!.errors).toBe(0);
    expect(winner!.meanTokens).toBeGreaterThan(0);
    // mem0 (mounted in (c), sidecar killed in (d)) crashes every question —
    // the referee survives and the dead driver cannot win.
    const mem0 = card.drivers.find((d) => d.driver === "mem0");
    if (mem0) {
      expect(mem0.errors).toBe(card.questionCount);
      expect(card.winner).not.toBe("mem0");
    }

    const res = await kernel.db.query(
      `SELECT count(*)::int AS n FROM scorecards WHERE namespace = $1`,
      [NS_DEMO],
    );
    expect(Number((res.rows[0] as { n: unknown }).n)).toBeGreaterThanOrEqual(1);

    // D4: the scorecard read real fact contents — it must leave an audit row
    // like every other content-reading path.
    const auditEvents = await kernel.audit.list(NS_DEMO, { limit: 50 });
    const scorecardAudit = auditEvents.find(
      (e) => e.op === "read" && e.purpose === "scorecard" && e.detail?.includes(card.id),
    );
    expect(scorecardAudit, "expected an audit row for the scorecard run").toBeDefined();
  }, 120_000);

  it("POST /v1/admin/scorecard {namespace} - owner 200, member 403", async () => {
    const http: HaloHttpServer = createHttpServer(buildHttpDeps(kernel));
    const port = await http.start(0);
    try {
      const post = (key: string) =>
        fetch(`http://127.0.0.1:${port}/v1/admin/scorecard`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ namespace: NS_DEMO }),
        });

      const ok = await post(ownerKey);
      expect(ok.status).toBe(200);
      const card = (await ok.json()) as {
        winner: string;
        benchmarkWinner: string;
        effectiveLiveRetriever: {
          mode: "fixed";
          configured: string;
          serving: string;
        };
        namespace: string;
        drivers: Array<{ driver: string }>;
      };
      expect(card.namespace).toBe(NS_DEMO);
      expect(card.drivers.map((d) => d.driver)).toContain(card.winner);
      expect(card.benchmarkWinner).toBe(card.winner);
      expect(card.effectiveLiveRetriever).toEqual({
        mode: "fixed",
        configured: "baseline",
        serving: "baseline",
      });

      const denied = await post(memberKeyA);
      expect(denied.status).toBe(403);
    } finally {
      await http.stop();
    }
  }, 120_000);
});
