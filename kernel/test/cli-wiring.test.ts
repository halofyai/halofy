/**
 * CLI wiring regression guards.
 *
 * `src/cli.ts` runs main() at import time, so its wiring cannot be exercised
 * in-process the way kernel modules are. These are deliberate SOURCE-level
 * pins for invariants that silently regressed once:
 *
 *   - the scorecard path must wrap createEmbedder in ResilientEmbedder with a
 *     cost_ledger sink (BudgetGuard's month-to-date brownout sums cost_ledger;
 *     a raw embedder bypasses both the accounting and the circuit breaker);
 *   - the scorecard path must pass the audit sink + caller attribution to
 *     runScorecard (D4: every content-reading path leaves an audit row).
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CLI_SOURCE = readFileSync(
  fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
  "utf8",
);

describe("cli.ts scorecard wiring (source pins)", () => {
  it("wraps the embedder in ResilientEmbedder with a cost_ledger sink", () => {
    expect(CLI_SOURCE).toMatch(
      /new ResilientEmbedder\(\s*createEmbedder\(config\),\s*costLedger,\s*namespace\s*\)/,
    );
    expect(CLI_SOURCE).toMatch(/INSERT INTO cost_ledger/);
    // The raw embedder must never be handed to the view directly.
    expect(CLI_SOURCE).not.toMatch(/const embedder = createEmbedder\(config\);/);
  });

  it("passes the audit sink and caller attribution to runScorecard", () => {
    expect(CLI_SOURCE).toMatch(
      /runScorecard\(\s*\{\s*db,\s*drivers,\s*view,\s*audit,\s*actor:\s*caller\.actor,\s*agentId:\s*"cli"\s*\}/,
    );
  });
});
