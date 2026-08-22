import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";

const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
const configPath = fileURLToPath(new URL("../vitest.config.ts", import.meta.url));
const openDbs: Db[] = [];

afterEach(async () => {
  await Promise.all(openDbs.splice(0).map((db) => db.close()));
});

describe("parallel test isolation", () => {
  it("gives every in-memory PGlite handle an independent database", async () => {
    const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 8 });
    const first = await createDb(config);
    const second = await createDb(config);
    openDbs.push(first, second);

    await Promise.all([
      first.query("CREATE TABLE worker_probe (id integer PRIMARY KEY, owner text NOT NULL)"),
      second.query("CREATE TABLE worker_probe (id integer PRIMARY KEY, owner text NOT NULL)"),
    ]);
    await Promise.all([
      first.query("INSERT INTO worker_probe (id, owner) VALUES (1, 'first')"),
      second.query("INSERT INTO worker_probe (id, owner) VALUES (1, 'second')"),
    ]);

    await expect(first.query("SELECT id, owner FROM worker_probe")).resolves.toEqual({
      rows: [{ id: 1, owner: "first" }],
    });
    await expect(second.query("SELECT id, owner FROM worker_probe")).resolves.toEqual({
      rows: [{ id: 1, owner: "second" }],
    });
  });

  it("keeps the main Vitest lane isolated and parallel", async () => {
    const [packageText, configText] = await Promise.all([
      readFile(packagePath, "utf8"),
      readFile(configPath, "utf8"),
    ]);
    const pkg = JSON.parse(packageText) as { scripts?: Record<string, string> };

    expect(pkg.scripts?.test).toBe("node scripts/run-hermetic-tests.mjs");
    expect(pkg.scripts?.["test:serial"]).toBe(
      "node scripts/run-hermetic-tests.mjs --maxWorkers=1",
    );
    expect(configText).toContain('HALOMEM_TEST_LANE === "hermetic"');
    expect(configText).toContain('pool: "forks"');
    expect(configText).toContain("isolate: true");
    expect(configText).toMatch(/maxWorkers:\s*[2-9]/);
  });
});
