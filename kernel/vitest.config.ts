import { defineConfig } from "vitest/config";

const hermeticLane = process.env.HALOMEM_TEST_LANE === "hermetic";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: hermeticLane
      ? ["test/pg-lane.test.ts", "test/perf.test.ts", "test/usage-perf.test.ts"]
      : [],
    setupFiles: ["./test/setup-hermetic.ts"],
    testTimeout: 30000,
    hookTimeout: 30000,
    // Test files create and close their own in-memory PGlite instance. Keep
    // each file in an isolated child-process environment so those databases,
    // module state, and environment mutations cannot leak between files.
    pool: "forks",
    isolate: true,
    fileParallelism: true,
    // Two concurrent PGlite WASM runtimes were fastest in the DB-heavy lane;
    // higher counts add contention. Override from the CLI when benchmarking.
    maxWorkers: 2,
  },
});
