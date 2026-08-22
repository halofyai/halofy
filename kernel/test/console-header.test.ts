import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

describe("console page headers", () => {
  it("renders no descriptive subtext element on any tab", async () => {
    const appSource = await readFile(`${CONSOLE_DIR}/app.js`, "utf8");
    const screenNames = (await readdir(`${CONSOLE_DIR}/screens`)).filter((name) =>
      /^s\d+\.js$/.test(name),
    );
    const screenSources = await Promise.all(
      screenNames.map((name) => readFile(`${CONSOLE_DIR}/screens/${name}`, "utf8")),
    );

    expect(appSource).not.toMatch(/desc\s*\?\s*`<p>\$\{desc\}<\/p>`/);
    for (const source of screenSources) {
      expect(source).not.toMatch(/\bdesc\s*:/);
      expect(source).not.toMatch(/<h1>[^<]*<\/h1>\s*<p>/);
    }
  });
});
