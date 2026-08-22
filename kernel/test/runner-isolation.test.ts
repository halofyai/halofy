import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import vitestConfig from "../vitest.config.js";

interface PackageManifest {
  scripts?: Record<string, string>;
}

describe("hermetic test runner isolation", () => {
  it("uses the environment-sanitizing hermetic runner by default", () => {
    const packageJson = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as PackageManifest;
    const testScript = packageJson.scripts?.test;

    expect(testScript).toBe("node scripts/run-hermetic-tests.mjs");
    expect(testScript).not.toMatch(/--maxWorkers(?:=|\s+)1\b/);

    const runner = readFileSync(
      new URL("../scripts/run-hermetic-tests.mjs", import.meta.url),
      "utf8",
    );
    expect(runner).toContain('HALOMEM_TEST_LANE = "hermetic"');
    expect(runner).toContain('delete testEnvironment.DATABASE_URL');
    expect(runner).toContain('delete testEnvironment.TEST_DATABASE_URL');
    expect(runner).toContain('delete testEnvironment.HALOMEM_DATA_DIR');
    expect(runner).toContain('delete testEnvironment.HALOMEM_KNOWLEDGE_DIR');
  });

  it("runs test files in bounded isolated worker processes", () => {
    expect(vitestConfig.test?.pool).toBe("forks");
    expect(vitestConfig.test?.isolate).toBe(true);
    expect(vitestConfig.test?.fileParallelism).toBe(true);
    expect(vitestConfig.test?.maxWorkers).toBe(2);
    expect(vitestConfig.test?.exclude).toEqual(
      process.env.HALOMEM_TEST_LANE === "hermetic"
        ? ["test/pg-lane.test.ts", "test/perf.test.ts", "test/usage-perf.test.ts"]
        : [],
    );
  });
});
