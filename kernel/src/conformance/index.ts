/**
 * Module D (M2) — conformance kit for halomem-driver/v1 cartridges.
 *
 * `runConformance(driver, opts)` runs the six contract checks over a
 * kernel-in-memory fixture (see ./fixture.ts) and returns a
 * ConformanceReport, also rendering a console table unless opts.quiet.
 *
 * Checks (CONTRACTS-M2.md, module D row):
 *   finds-planted-fact   10 planted facts, >= 8/10 queries rank the right
 *                        ref in the top-3.
 *   respects-scoped-view canary rows in a sibling namespace never appear;
 *                        every returned ref must be reachable through the
 *                        driver's ScopedView.
 *   latency-envelope     p95 of 20 plan() calls < budget (150ms default,
 *                        in-process).
 *   budget-discipline    sum of tokenEstimate <= tokenBudget for every call.
 *   read-only            static scan of the driver's source for forbidden
 *                        kernel-internal imports (../{index,kernel,db,write,
 *                        audit,cold} in directory OR file form, createRequire,
 *                        computed dynamic import()/require() specifiers).
 *   deterministic-k      the same query twice yields the same top-3.
 */

import { readFileSync } from "node:fs";
import type { RetrieverDriver, ScoredRef } from "../types.js";
import {
  buildConformanceHarness,
  type ConformanceHarness,
} from "./fixture.js";

export {
  buildConformanceHarness,
  HARNESS_NAMESPACE,
  CANARY_NAMESPACE,
  PLANTED_FACTS,
  CANARY_FACTS,
} from "./fixture.js";
export type {
  BuildHarnessOptions,
  ConformanceHarness,
  HarnessDeps,
  PlantedFact,
  PlantedSpec,
} from "./fixture.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ConformanceCheckId =
  | "finds-planted-fact"
  | "respects-scoped-view"
  | "latency-envelope"
  | "budget-discipline"
  | "read-only"
  | "deterministic-k";

export const CONFORMANCE_CHECK_IDS: readonly ConformanceCheckId[] = [
  "finds-planted-fact",
  "respects-scoped-view",
  "latency-envelope",
  "budget-discipline",
  "read-only",
  "deterministic-k",
] as const;

export interface ConformanceCheck {
  id: ConformanceCheckId;
  pass: boolean;
  detail: string;
}

export interface ConformanceReport {
  driver: string;
  checks: ConformanceCheck[];
  pass: boolean;
}

export interface ConformanceOptions {
  /**
   * Reuse a pre-built harness (tests). When omitted the kit builds — and
   * closes — its own in-memory fixture.
   */
  harness?: ConformanceHarness;
  /**
   * Path to the driver's source file for the read-only static scan. When
   * omitted the check is recorded as passed with a "skipped" detail (there
   * is nothing to scan) — CI callers should always provide it.
   */
  sourcePath?: string;
  /** p95 latency bound in ms for latency-envelope. Default 150. */
  latencyBudgetMs?: number;
  /** tokenBudget handed to plan() for budget-discipline. Default 120. */
  budgetTokens?: number;
  /** Suppress the console table. */
  quiet?: boolean;
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

const GENEROUS_BUDGET = 2000;

async function guard(
  id: ConformanceCheckId,
  fn: () => Promise<ConformanceCheck> | ConformanceCheck,
): Promise<ConformanceCheck> {
  try {
    return await fn();
  } catch (err) {
    return {
      id,
      pass: false,
      detail: `check threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function checkFindsPlanted(
  driver: RetrieverDriver,
  harness: ConformanceHarness,
): Promise<ConformanceCheck> {
  return guard("finds-planted-fact", async () => {
    let hits = 0;
    const misses: string[] = [];
    for (const fact of harness.planted) {
      const refs = (
        await driver.plan({
          query: fact.query,
          view: harness.view,
          tokenBudget: GENEROUS_BUDGET,
          k: 5,
        })
      )
        .slice(0, 3)
        .map((r) => r.ref);
      if (refs.includes(fact.ref)) hits++;
      else misses.push(fact.query);
    }
    const pass = hits >= 8;
    const missNote = misses.length > 0 ? `; missed: ${misses.join(" | ")}` : "";
    return {
      id: "finds-planted-fact",
      pass,
      detail: `${hits}/${harness.planted.length} planted refs in top-3 (need >= 8)${missNote}`,
    };
  });
}

async function checkScopedView(
  driver: RetrieverDriver,
  harness: ConformanceHarness,
): Promise<ConformanceCheck> {
  return guard("respects-scoped-view", async () => {
    const violations: string[] = [];
    const queries = [...harness.planted, ...harness.canaries].map((f) => f.query);
    for (const query of queries) {
      const results = await driver.plan({
        query,
        view: harness.view,
        tokenBudget: GENEROUS_BUDGET,
        k: 8,
      });
      for (const r of results) {
        if (harness.canaryRefs.has(r.ref)) {
          violations.push(`canary ref ${r.ref} leaked for "${query}"`);
        } else if (!harness.allowedRefs.has(r.ref)) {
          violations.push(`ref ${r.ref} outside the ScopedView for "${query}"`);
        }
      }
    }
    return {
      id: "respects-scoped-view",
      pass: violations.length === 0,
      detail:
        violations.length === 0
          ? `0 violations across ${queries.length} queries (5 canaries in sibling ns unreachable)`
          : `${violations.length} violation(s): ${violations.slice(0, 3).join("; ")}${violations.length > 3 ? "; ..." : ""}`,
    };
  });
}

async function checkLatency(
  driver: RetrieverDriver,
  harness: ConformanceHarness,
  budgetMs: number,
): Promise<ConformanceCheck> {
  return guard("latency-envelope", async () => {
    const n = 20;
    const durations: number[] = [];
    for (let i = 0; i < n; i++) {
      const fact = harness.planted[i % harness.planted.length];
      const start = performance.now();
      await driver.plan({
        query: fact.query,
        view: harness.view,
        tokenBudget: GENEROUS_BUDGET,
        k: 5,
      });
      durations.push(performance.now() - start);
    }
    durations.sort((a, b) => a - b);
    const p95 = durations[Math.min(n - 1, Math.ceil(0.95 * n) - 1)];
    return {
      id: "latency-envelope",
      pass: p95 < budgetMs,
      detail: `p95 ${p95.toFixed(1)}ms over ${n} plan() calls (bound ${budgetMs}ms)`,
    };
  });
}

async function checkBudget(
  driver: RetrieverDriver,
  harness: ConformanceHarness,
  tokenBudget: number,
): Promise<ConformanceCheck> {
  return guard("budget-discipline", async () => {
    let worst = 0;
    const violations: string[] = [];
    for (const fact of harness.planted) {
      const results = await driver.plan({
        query: fact.query,
        view: harness.view,
        tokenBudget,
        k: 10,
      });
      const sum = results.reduce((acc, r: ScoredRef) => acc + r.tokenEstimate, 0);
      if (sum > worst) worst = sum;
      if (sum > tokenBudget) {
        violations.push(`"${fact.query}" -> ${sum} tokens (budget ${tokenBudget})`);
      }
    }
    return {
      id: "budget-discipline",
      pass: violations.length === 0,
      detail:
        violations.length === 0
          ? `max sum(tokenEstimate) ${worst}/${tokenBudget} across ${harness.planted.length} queries`
          : `${violations.length} over-budget response(s): ${violations.slice(0, 3).join("; ")}${violations.length > 3 ? "; ..." : ""}`,
    };
  });
}

/**
 * Static read-only scan of driver source text. A driver is a read-only
 * cartridge: it may import src/types.js, src/retrieval, src/embed — never
 * the storage/write/audit internals, the kernel facade, or the src barrel.
 *
 * Hardened against the known obfuscation bypasses:
 *   - EVERY quoted or backtick literal is scanned (not only import-ish
 *     lines), so `const { createDb } = req("../db/client.js")` is caught
 *     even when the surrounding line has no import/from/require keyword;
 *   - the forbidden-module set matches barrel/facade forms too: both
 *     `../db/client.js` (directory) and `../index.js` / `../kernel.js`
 *     (file), since the src barrel and kernel facade re-export the full
 *     storage/write surface (Kernel.boot, createDb, WritePath, ...);
 *   - `createRequire` is banned outright (CommonJS escape hatch);
 *   - dynamic `import(...)` / `require(...)` whose specifier is not a plain
 *     single string literal is banned (computed/concatenated/template
 *     specifiers such as `import("../d" + "b/client.js")` or
 *     `import(\`../${'${seg}'}/client.js\`)` cannot be verified statically,
 *     so they are conservatively rejected).
 */
export function checkReadOnlySource(source: string): { pass: boolean; detail: string } {
  // A quoted/backtick literal that reaches a kernel-internal module: the
  // segment right after `../` (any depth) or `src/` is one of the forbidden
  // module names, followed by `/`, `.` (file form: ../index.js, ../kernel.js)
  // or the closing quote (extension-less form).
  const forbidden =
    /["'`][^"'`\n]*(?:\.\.\/|src\/)(?:index|kernel|db|write|audit|cold)(?:[/.]|["'`])/;
  // CommonJS escape hatch: createRequire lets a driver re-acquire require()
  // and load storage internals without an import statement.
  const createRequire = /\bcreateRequire\b/;
  // Dynamic import()/require() with anything but a single plain string
  // literal as the specifier (identifier, concatenation, template, ...).
  const dynamicNonLiteral = /\b(?:import|require)\s*\(\s*(?!["'][^"'\n]*["']\s*[),])/;

  const offenders: string[] = [];
  for (const line of source.split(/\r?\n/)) {
    if (forbidden.test(line) || createRequire.test(line) || dynamicNonLiteral.test(line)) {
      offenders.push(line.trim());
    }
  }
  return {
    pass: offenders.length === 0,
    detail:
      offenders.length === 0
        ? "no forbidden imports (../{index,kernel,db,write,audit,cold}[/.]*, createRequire, computed dynamic import)"
        : `forbidden import(s): ${offenders.slice(0, 3).join(" | ")}${offenders.length > 3 ? " | ..." : ""}`,
  };
}

function checkReadOnly(sourcePath: string | undefined): ConformanceCheck {
  if (!sourcePath) {
    return {
      id: "read-only",
      pass: true,
      detail: "skipped: no sourcePath provided (pass opts.sourcePath to scan)",
    };
  }
  try {
    const source = readFileSync(sourcePath, "utf8");
    const res = checkReadOnlySource(source);
    return { id: "read-only", pass: res.pass, detail: `${sourcePath}: ${res.detail}` };
  } catch (err) {
    return {
      id: "read-only",
      pass: false,
      detail: `cannot read driver source ${sourcePath}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function checkDeterministic(
  driver: RetrieverDriver,
  harness: ConformanceHarness,
): Promise<ConformanceCheck> {
  return guard("deterministic-k", async () => {
    const probes = harness.planted.slice(0, 3);
    for (const fact of probes) {
      const run = () =>
        driver.plan({
          query: fact.query,
          view: harness.view,
          tokenBudget: GENEROUS_BUDGET,
          k: 3,
        });
      const first = (await run()).slice(0, 3).map((r) => r.ref);
      const second = (await run()).slice(0, 3).map((r) => r.ref);
      if (JSON.stringify(first) !== JSON.stringify(second)) {
        return {
          id: "deterministic-k",
          pass: false,
          detail: `"${fact.query}": run1 [${first.join(", ")}] != run2 [${second.join(", ")}]`,
        };
      }
    }
    return {
      id: "deterministic-k",
      pass: true,
      detail: `same top-3 across repeated runs of ${probes.length} queries`,
    };
  });
}

// ---------------------------------------------------------------------------
// Runner + report rendering
// ---------------------------------------------------------------------------

export async function runConformance(
  driver: RetrieverDriver,
  opts: ConformanceOptions = {},
): Promise<ConformanceReport> {
  const ownHarness = opts.harness === undefined;
  const harness = opts.harness ?? (await buildConformanceHarness());
  try {
    const checks: ConformanceCheck[] = [
      await checkFindsPlanted(driver, harness),
      await checkScopedView(driver, harness),
      await checkLatency(driver, harness, opts.latencyBudgetMs ?? 150),
      await checkBudget(driver, harness, opts.budgetTokens ?? 120),
      checkReadOnly(opts.sourcePath),
      await checkDeterministic(driver, harness),
    ];
    const report: ConformanceReport = {
      driver: driver.name,
      checks,
      pass: checks.every((c) => c.pass),
    };
    if (!opts.quiet) {
      // eslint-disable-next-line no-console
      console.log(renderConformanceReport(report, harness.viewSource));
    }
    return report;
  } finally {
    if (ownHarness) await harness.close();
  }
}

/** Plain-text console table for a report. */
export function renderConformanceReport(
  report: ConformanceReport,
  viewSource?: string,
): string {
  const idWidth = Math.max(...report.checks.map((c) => c.id.length), 5);
  const lines: string[] = [];
  lines.push(
    `conformance report - driver '${report.driver}'` +
      (viewSource ? ` (view: ${viewSource})` : ""),
  );
  lines.push(`${"check".padEnd(idWidth)}  result  detail`);
  lines.push(`${"-".repeat(idWidth)}  ------  ${"-".repeat(40)}`);
  for (const c of report.checks) {
    lines.push(`${c.id.padEnd(idWidth)}  ${(c.pass ? "PASS" : "FAIL").padEnd(6)}  ${c.detail}`);
  }
  const passed = report.checks.filter((c) => c.pass).length;
  lines.push(
    `result: ${report.pass ? "PASS" : "FAIL"} (${passed}/${report.checks.length} checks)`,
  );
  return lines.join("\n");
}
