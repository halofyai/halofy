import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));
const homeScreenPath = fileURLToPath(new URL("../console/screens/s2.js", import.meta.url));

describe("Home desktop density", () => {
  it("uses the shared white canvas around the Home content", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(
      /body:has\(\.home-overview\) \.stage\{[^}]*background:var\(--canvas\)/,
    );
    expect(css).toMatch(/\.home-overview\{--home-canvas:var\(--surface-soft\)/);
  });

  it("keeps the 80-percent composition readable at normal browser zoom", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toContain("@media(min-width:861px) and (max-width:1400px)");
    expect(css).toMatch(/\.app\{grid-template-columns:200px minmax\(0,1fr\)\}/);
    expect(css).toMatch(/\.navgroup\{min-height:27px;padding:4px 7px;font-size:10px/);
    expect(css).toMatch(/\.nav button\{min-height:25px;gap:8px;padding:4px 7px;font-size:12px/);
    expect(css).toMatch(/body:has\(\.home-overview\) \.stage\{--s7:32px/);
    expect(css).toMatch(/\.home-metrics\{grid-template-columns:repeat\(5,minmax\(0,1fr\)\);gap:10px\}/);
    expect(css).toMatch(/\.home-metrics \.metric-card\{padding:14px;gap:10px/);
    expect(css).toMatch(/\.home-metrics \.metric-card-shell\{gap:8px;padding:10px/);
    expect(css).toMatch(/\.home-metrics \.metric-card \.v\{font-size:21px;white-space:nowrap/);
    expect(css).toMatch(/\.rail-help\{min-height:120px;padding:10px\}/);
  });

  it("vertically centers Home summary values inside their inset boxes", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(
      /\.home-metrics \.metric-card-shell\{display:flex;flex:1;flex-direction:column;justify-content:center/,
    );
  });

  it("uses a larger, consistent gap between Home dashboard section rows", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(
      /\.home-overview>\.screen-flow,\s*\.home-overview \.home-dashboard\{\s*row-gap:var\(--s5\)/,
    );
  });

  it("keeps lookup summary boxes compact and on one horizontal line", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.home-lookup-pills\{[^}]*flex-wrap:nowrap[^}]*overflow-x:auto/);
    expect(css).toMatch(
      /\.home-lookup-pills \.pill\{[^}]*flex:0 0 auto[^}]*border-radius:8px[^}]*white-space:nowrap/,
    );
  });

  it("distributes Memory Lookups content evenly through the full card height", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.home-lookups\{[^}]*display:flex[^}]*flex-direction:column/);
    expect(css).toMatch(
      /\.home-lookups \.home-card-body\{[^}]*display:flex[^}]*flex:1[^}]*flex-direction:column/,
    );
    expect(css).toMatch(
      /\.home-recent-queries\{[^}]*flex:1[^}]*flex-direction:column[^}]*justify-content:space-between/,
    );
    expect(css).toMatch(/\.home-lookups \.home-card-foot\{[^}]*margin-top:18px/);
  });

  it("uses a neutral grey reporting-range control", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(
      /\.home-range-control\{[^}]*border:1px solid #dfe3e7[^}]*background:var\(--neutral-soft\)/,
    );
    expect(css).toMatch(
      /\.home-range-control \.home-range-option\.is-active\{[^}]*background:var\(--home-panel\)[^}]*color:var\(--home-text\)/,
    );
    expect(css).toMatch(/\.home-range-control \.home-range-option\{[^}]*color:#6b7280/);
    expect(css).not.toMatch(/\.home-range-control\{[^}]*background:var\(--home-soft\)/);
  });

  it("keeps Memory Health bars clean, evenly spaced, and free of readiness detail", async () => {
    const [css, screen] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(homeScreenPath, "utf8"),
    ]);

    expect(css).toMatch(/\.home-factor-track\{height:8px;background:var\(--home-soft\)\}/);
    expect(css).toMatch(/\.home-factor-list\{gap:18px;/);
    expect(css).toMatch(
      /@media\(min-width:861px\) and \(max-width:1400px\)[\s\S]*?\.home-factor-list\{gap:14px;/,
    );
    expect(css).not.toContain(".home-factor-axis");
    expect(screen).not.toContain("home-factor-axis");
    expect(screen).not.toContain("home-health-note");
  });
});
