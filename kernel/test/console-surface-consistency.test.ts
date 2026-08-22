import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("shared console surface system", () => {
  it("uses white shared panels and nested boxes", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/--panel:#fff/);
    expect(css).not.toMatch(/--panel:#fbfcf7/);
    expect(css).toMatch(/--surface-soft:#fff/);
    expect(css).toMatch(/--mineral:#f3f6ee/);
    expect(css).toMatch(/--neutral-soft:#eef0f2/);
    expect(css).toMatch(/--sage-soft:var\(--neutral-soft\)/);
    expect(css).toMatch(/--line:#d9dfcf/);
    expect(css).toMatch(/--stone:#e6e6e1/);
  });

  it("defines one geometry and type hierarchy for reusable boxes", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/--panel-padding:var\(--s5\)/);
    expect(css).toMatch(/--panel-radius:var\(--r-lg\)/);
    expect(css).toMatch(/--subpanel-padding:var\(--s4\)/);
    expect(css).toMatch(/--subpanel-radius:var\(--r-md\)/);
    expect(css).toMatch(/--section-title-size:16px/);
    expect(css).toMatch(/--section-subtitle-size:13px/);
    expect(css).toMatch(
      /\.card\{[^}]*background:var\(--panel\)[^}]*border:1px solid var\(--line\)[^}]*border-radius:var\(--panel-radius\)[^}]*padding:var\(--panel-padding\)[^}]*box-shadow:var\(--sh-1\),var\(--sh-2\)/,
    );
  });

  it("uses the Usage Analytics reference for content without repainting navigation chrome", async () => {
    const css = await readFile(cssPath, "utf8");
    const contract = css.match(
      /\/\* ---- platform surface contract[\s\S]*?\/\* ---- end platform surface contract ---- \*\//,
    )?.[0] ?? "";

    expect(css).toMatch(
      /\.home-overview\{--home-canvas:var\(--surface-soft\);--home-panel:var\(--panel\);--home-border:var\(--line\)/,
    );
    for (const selector of [
      ".policy-panel",
      ".teams-overview",
      ".source-connector-card",
      ".skills-screen .skill-library",
      ".audit-trail-card",
      ".audit-compliance-card",
    ]) {
      expect(contract).toContain(selector);
    }
    expect(contract).toContain("--content-font:var(--font-sans)");
    expect(contract).toContain("--content-panel:#fff");
    expect(contract).toContain("--content-subpanel:#fff");
    expect(contract).toContain("--content-inset:#f9fafb");
    expect(contract).toContain("--content-border:#e5e7eb");
    expect(contract).toContain("--content-text:#111827");
    expect(contract).toContain("--content-muted:#6b7280");
    expect(contract).toContain("--content-faint:#9ca3af");
    expect(contract).toContain("--content-radius:14px");
    expect(contract).toContain(".home-metrics");
    expect(contract).toContain(".home-dashboard");
    expect(contract).toContain(".source-standalone");
    expect(contract).toContain('[role="tabpanel"]>.compact-disclosure');
    expect(contract).toContain("background:var(--content-panel)");
    expect(contract).toContain("border-color:var(--content-border)");
    expect(contract).toContain("border-radius:var(--content-radius)");
    expect(contract).toContain("box-shadow:var(--content-shadow)");
    expect(contract).toContain("font-size:var(--section-title-size)");
    expect(contract).not.toContain(".rail{");
    expect(contract).not.toContain(".workspace-bar{");
    expect(contract).not.toContain(".mobile-topbar{");
    expect(contract).not.toContain("#screen-content .head{");
  });

  it("normalizes nested boxes without recoloring dark or semantic-state surfaces", async () => {
    const css = await readFile(cssPath, "utf8");
    const contract = css.match(
      /\/\* ---- platform surface contract[\s\S]*?\/\* ---- end platform surface contract ---- \*\//,
    )?.[0] ?? "";

    for (const selector of [
      ".stat",
      ".home-metrics .metric-card-shell",
      ".memory-summary-metrics .metric-card-shell",
      ".policy-tile",
      ".source-tile",
      ".audit-stat-card",
      ".ex20-tile",
    ]) {
      expect(contract).toContain(selector);
    }
    expect(contract).toContain("background:var(--content-subpanel)");
    expect(contract).toContain("border:1px solid var(--content-border)");
    expect(contract).toContain("border-radius:var(--subpanel-radius)");
    expect(contract).toContain("box-shadow:var(--content-shadow-lift)");
    expect(contract).not.toContain(".memory-topology");
    expect(contract).not.toContain(".copilot-");
    expect(contract).not.toContain(".pill--warn");
    expect(contract).not.toContain(".pill--crit");
  });

  it("keeps the public authentication shell outside the console refresh", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.auth-shell\{--panel:var\(--canvas\)\}/);
  });

  // Regression: the sticky workspace bar and every in-content popover both sat
  // at z-index:20. #screen-content comes AFTER the bar in the DOM, so an open
  // popover won the tie and painted over the header the moment the page
  // scrolled - the S5 space picker rode up into the workspace bar. The bar has
  // to outrank the popover tier; it must still sit under the rail, the S5
  // preview banner, and the mobile drawer.
  it("stacks the sticky workspace bar above in-content popovers", async () => {
    const css = await readFile(cssPath, "utf8");

    const zOf = (label: string, rule: RegExp): number => {
      const match = css.match(rule);
      expect(match, label).not.toBeNull();
      return Number(match![1]);
    };

    const bar = zOf("workspace bar", /\.workspace-bar\{[^}]*?z-index:(\d+)/);
    const popovers: Array<[string, RegExp]> = [
      ["space picker", /\.memory-scope-menu\{[^}]*?z-index:(\d+)/],
      ["home query filter", /\.home-query-filter-menu\{[^}]*?z-index:(\d+)/],
      ["skill filter", /\.skill-filter-popover\{[^}]*?z-index:(\d+)/],
    ];

    for (const [label, rule] of popovers) {
      expect(bar, label + " must sit under the workspace bar").toBeGreaterThan(zOf(label, rule));
    }

    // ...and still below the surfaces that are meant to cover it.
    expect(bar).toBeLessThan(zOf("preview banner", /\.preview-banner\{[^}]*?z-index:(\d+)/));
    expect(bar).toBeLessThan(40); // mobile rail drawer
  });
});
