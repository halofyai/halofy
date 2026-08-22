import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const launcherUrl = new URL("../scripts/serve-dev.mjs", import.meta.url);

describe("serve:dev storage", () => {
  it("defaults PGlite to the repository-local ignored data directory", async () => {
    const launcher = await readFile(launcherUrl, "utf8");

    expect(launcher).toContain(
      'fileURLToPath(new URL("../data/pglite-local", import.meta.url))',
    );
    expect(launcher.match(/import \{ fileURLToPath \} from "node:url";/g)).toHaveLength(1);
    expect(launcher).not.toContain("AppData/Local/Temp");
  });
});
