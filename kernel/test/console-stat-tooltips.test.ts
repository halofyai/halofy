import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const consoleUrl = new URL("../console/", import.meta.url);

async function source(path: string): Promise<string> {
  return readFile(fileURLToPath(new URL(path, consoleUrl)), "utf8");
}

describe("console stat subtext tooltips", () => {
  it("moves shared stat context beside the label instead of below the value", async () => {
    const app = await source("app.js");
    const statRenderer = app.slice(app.indexOf("  stat({"), app.indexOf("  /** Pill chip"));

    expect(statRenderer).toContain("statInfo(k, foot)");
    expect(statRenderer).toContain('class="stat-label"');
    expect(statRenderer).not.toContain('class="foot"');
    expect(app).toMatch(/function statInfo[\s\S]*?class="metric-info stat-info"/);
    expect(app).toMatch(/function statInfo[\s\S]*?tabindex="0"/);
    expect(app).toMatch(/function statInfo[\s\S]*?data-tip=/);
  });

  it("uses the same accessible tooltip contract in every stat renderer", async () => {
    const [home, sources, scorecard] = await Promise.all([
      source("screens/s2.js"),
      source("screens/s6.js"),
      source("screens/s9.js"),
    ]);

    expect(home).toContain('import { metricCard as stat } from "../metric-card.js";');
    expect(home).not.toContain('<div class="foot">');
    expect(sources).toMatch(/function statCard[\s\S]*?class="metric-info stat-info"/);
    expect(sources).not.toContain('<div class="foot">');
    expect(scorecard).toContain('class="metric-info stat-info"');
    expect(scorecard).not.toContain('<div class="foot">');
  });

  it("opens the shared tooltip for pointer and keyboard users", async () => {
    const css = await source("app.css");

    expect(css).toMatch(/\.metric-info::after\{[^}]*content:attr\(data-tip\)/);
    expect(css).toMatch(/\.metric-info:hover::after,\.metric-info:focus-visible::after\{[^}]*opacity:1/);
    expect(css).toMatch(/\.metric-info:focus-visible\{[^}]*box-shadow:var\(--focus\)/);
  });
});
