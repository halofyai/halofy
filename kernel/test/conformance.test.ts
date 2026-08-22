/**
 * Module D (M2) — conformance kit tests.
 *
 * Hermetic: the harness boots an in-memory PGlite (+ pgvector) with the
 * HashEmbedder; no network, no python. Proves the kit passes a compliant
 * driver AND fails a deliberately-broken one (leaks canary refs not in its
 * view / blows the token budget) on exactly respects-scoped-view and
 * budget-discipline.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { RetrieverDriver } from "../src/types.js";
import {
  CONFORMANCE_CHECK_IDS,
  buildConformanceHarness,
  checkReadOnlySource,
  runConformance,
  renderConformanceReport,
  type ConformanceCheckId,
  type ConformanceHarness,
  type ConformanceReport,
} from "../src/conformance/index.js";
import {
  LeakyBudgetBusterDriver,
  ReferenceHybridDriver,
} from "./conformance-drivers.js";

const DRIVER_FIXTURE_PATH = fileURLToPath(
  new URL("./conformance-drivers.ts", import.meta.url),
);
// Loose local bound: CI boxes and Windows filesystems jitter; the check
// still RUNS and measures — the default 150ms bound stays for real runs.
const LOOSE_LATENCY_MS = 2000;

let harness: ConformanceHarness;

beforeAll(async () => {
  harness = await buildConformanceHarness();
});

afterAll(async () => {
  await harness.close();
});

function check(report: ConformanceReport, id: ConformanceCheckId) {
  const found = report.checks.find((c) => c.id === id);
  expect(found, `check ${id} missing from report`).toBeDefined();
  return found!;
}

describe("conformance harness fixture", () => {
  it("plants 10 facts in conf/a and 5 canaries in the sibling conf/b", () => {
    expect(harness.namespace).toBe("conf/a");
    expect(harness.canaryNamespace).toBe("conf/b");
    expect(harness.planted).toHaveLength(10);
    expect(harness.canaries).toHaveLength(5);
    // Sibling canaries are NOT reachable through the view's candidate set.
    for (const canary of harness.canaries) {
      expect(harness.allowedRefs.has(canary.ref)).toBe(false);
    }
    for (const fact of harness.planted) {
      expect(harness.allowedRefs.has(fact.ref)).toBe(true);
    }
  });

  it("view is ACL-scoped: canary content never surfaces via vectorSearch", async () => {
    for (const canary of harness.canaries) {
      const [emb] = await harness.view.embed([canary.content]);
      const hits = await harness.view.vectorSearch(emb, 15);
      expect(hits.map((h) => h.ref)).not.toContain(canary.ref);
    }
  });
});

describe("runConformance", () => {
  it("compliant hybrid driver passes all six checks", async () => {
    const report = await runConformance(new ReferenceHybridDriver(), {
      harness,
      sourcePath: DRIVER_FIXTURE_PATH,
      latencyBudgetMs: LOOSE_LATENCY_MS,
      quiet: true,
    });
    expect(report.driver).toBe("ref-hybrid");
    expect(report.checks.map((c) => c.id)).toEqual([...CONFORMANCE_CHECK_IDS]);
    for (const c of report.checks) {
      expect(c.pass, `${c.id}: ${c.detail}`).toBe(true);
    }
    expect(report.pass).toBe(true);
  });

  it("broken driver FAILS respects-scoped-view and budget-discipline", async () => {
    const broken = new LeakyBudgetBusterDriver([...harness.canaryRefs]);
    const report = await runConformance(broken, {
      harness,
      sourcePath: DRIVER_FIXTURE_PATH,
      latencyBudgetMs: LOOSE_LATENCY_MS,
      quiet: true,
    });

    expect(report.pass).toBe(false);
    const scoped = check(report, "respects-scoped-view");
    expect(scoped.pass).toBe(false);
    expect(scoped.detail).toMatch(/canary ref/);
    const budget = check(report, "budget-discipline");
    expect(budget.pass).toBe(false);
    expect(budget.detail).toMatch(/over-budget/);

    // The latency check still RAN with a real measurement (loose local bound)
    const latency = check(report, "latency-envelope");
    expect(latency.detail).toMatch(/p95 \d/);
    expect(latency.pass).toBe(true);
    // Clean imports → the failure is targeted, not a read-only artifact.
    expect(check(report, "read-only").pass).toBe(true);
    expect(check(report, "deterministic-k").pass).toBe(true);
  });

  it("a driver whose plan() throws yields failed checks, not a crash", async () => {
    const bomb: RetrieverDriver = {
      name: "bomb",
      capabilities: () => ({ graph: false, streaming: false }),
      plan: async () => {
        throw new Error("boom");
      },
    };
    const report = await runConformance(bomb, {
      harness,
      latencyBudgetMs: LOOSE_LATENCY_MS,
      quiet: true,
    });
    expect(report.pass).toBe(false);
    expect(check(report, "finds-planted-fact").pass).toBe(false);
    expect(check(report, "finds-planted-fact").detail).toMatch(/boom/);
  });

  it("renders a console table with one row per check and a verdict", async () => {
    const report = await runConformance(new ReferenceHybridDriver(), {
      harness,
      sourcePath: DRIVER_FIXTURE_PATH,
      latencyBudgetMs: LOOSE_LATENCY_MS,
      quiet: true,
    });
    const table = renderConformanceReport(report, harness.viewSource);
    for (const id of CONFORMANCE_CHECK_IDS) expect(table).toContain(id);
    expect(table).toMatch(/result: PASS \(6\/6 checks\)/);
  });
});

describe("read-only static scan", () => {
  it("flags each forbidden kernel-internal import", () => {
    const cases = [
      `import { MemoryIndex } from "../index/index.js";`,
      `import { createDb } from "../db/client.js";`,
      `import { WritePath } from "../write/index.js";`,
      `import { AuditLog } from "../audit/index.js";`,
      `import { ColdStore } from "../cold/index.js";`,
      `const w = await import("../write/index.js");`,
      `const { Db } = require("../db/client.js");`,
      `import { rowToMemoryObject } from "../../src/index/index.js";`,
    ];
    for (const src of cases) {
      expect(checkReadOnlySource(src).pass, src).toBe(false);
    }
  });

  it("flags the src barrel and kernel facade (file-form imports)", () => {
    const cases = [
      `import { Kernel } from "../index.js";`,
      `import { Kernel } from "../kernel.js";`,
      `import { memWrite } from "../../src/index.js";`,
      `const k = await import("../kernel.js");`,
    ];
    for (const src of cases) {
      expect(checkReadOnlySource(src).pass, src).toBe(false);
    }
  });

  it("flags createRequire indirection even across lines", () => {
    const src = [
      `import { createRequire } from "node:module";`,
      `const req = createRequire(import.meta.url);`,
      `const { createDb } = req("../db/client.js");`,
    ].join("\n");
    const res = checkReadOnlySource(src);
    expect(res.pass).toBe(false);
    // Both the createRequire escape hatch AND the forbidden literal are hit.
    expect(res.detail).toMatch(/createRequire/);
    // The literal alone (no import/from/require word on its line) is caught.
    expect(checkReadOnlySource(`const { createDb } = req("../db/client.js");`).pass).toBe(false);
  });

  it("flags computed/concatenated/template dynamic import specifiers", () => {
    const cases = [
      `const mod = await import("../d" + "b/client.js");`,
      "const mod = await import(`../${seg}/client.js`);",
      `const mod = await import(spec);`,
      `const mod = require(path.join(dir, "client.js"));`,
      "const p = `../db/client.js`;", // forbidden path in a template literal
    ];
    for (const src of cases) {
      expect(checkReadOnlySource(src).pass, src).toBe(false);
    }
  });

  it("allows the sanctioned driver imports (types, retrieval, embed)", () => {
    const clean = [
      `import type { ScopedView, RetrieverDriver } from "../types.js";`,
      `import { bm25Rank, hybridMerge } from "../retrieval/index.js";`,
      `import { tokenize } from "../embed/index.js";`,
      `import { DriverUnavailableError } from "./index.js";`,
      `const mod = await import("../retrieval/index.js");`,
      `// a comment mentioning ../db/client.js is not an import line`,
    ].join("\n");
    expect(checkReadOnlySource(clean).pass).toBe(true);
  });

  it("still passes every shipped driver source (no false positives)", () => {
    for (const name of ["baseline", "graph", "mem0"]) {
      const path = fileURLToPath(new URL(`../src/driver/${name}.ts`, import.meta.url));
      if (!existsSync(path)) continue;
      const res = checkReadOnlySource(readFileSync(path, "utf8"));
      expect(res.pass, `${name}: ${res.detail}`).toBe(true);
    }
  });
});

describe("real baseline driver (module A), when present", () => {
  it("passes conformance", async () => {
    // Non-literal specifier: module A may not be built yet in this checkout;
    // in that case this test is a no-op (the m2-exit suite pins the real
    // baseline once integrated).
    const spec = ["..", "src", "driver", "baseline.js"].join("/");
    let mod: Record<string, unknown> | null = null;
    try {
      mod = (await import(spec)) as Record<string, unknown>;
    } catch {
      return; // module A not built yet
    }
    let driver: RetrieverDriver | null = null;
    for (const value of Object.values(mod)) {
      if (
        typeof value === "function" &&
        typeof (value as { prototype?: { plan?: unknown } }).prototype?.plan ===
          "function"
      ) {
        try {
          driver = new (value as new () => RetrieverDriver)();
          break;
        } catch {
          continue;
        }
      }
    }
    if (!driver) return;

    const sourceTs = fileURLToPath(
      new URL("../src/driver/baseline.ts", import.meta.url),
    );
    const report = await runConformance(driver, {
      harness,
      sourcePath: existsSync(sourceTs) ? sourceTs : undefined,
      latencyBudgetMs: LOOSE_LATENCY_MS,
      quiet: true,
    });
    for (const c of report.checks) {
      expect(c.pass, `baseline ${c.id}: ${c.detail}`).toBe(true);
    }
    expect(report.pass).toBe(true);
  });
});
