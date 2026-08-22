import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const consoleUrl = new URL("../console/", import.meta.url);

async function source(path: string): Promise<string> {
  return readFile(fileURLToPath(new URL(path, consoleUrl)), "utf8");
}

describe("console heading subtext tooltips", () => {
  it("provides one shared accessible tooltip primitive for page and section headings", async () => {
    const [app, helper, css] = await Promise.all([
      source("app.js"),
      source("heading-info.js"),
      source("app.css"),
    ]);

    expect(app).toMatch(/info\(label, detail\)[\s\S]*?headingInfo\(label, detail\)/);
    expect(helper).toMatch(/heading-info[\s\S]*?role="note"[\s\S]*?tabindex="0"/);
    expect(helper).toMatch(/heading-info[\s\S]*?aria-label=/);
    expect(helper).toMatch(/heading-info[\s\S]*?data-tip=/);
    expect(css).toMatch(/\.heading-info::after\{[^}]*content:attr\(data-tip\)/);
    expect(css).toMatch(/\.heading-info:hover::after,\.heading-info:focus-visible::after\{[^}]*opacity:1/);
    expect(css).toMatch(/@media\(max-width:640px\)[\s\S]*?\.heading-info::after\{position:fixed;left:16px;right:16px/);
  });

  it("moves page and section explanations into the shared heading tooltip contract", async () => {
    const expectations = [
      ["screens/policy-compliance.js", "Every agent that assembles context", 1],
      ["screens/policy-library.js", "These files reached memory through an import or connector", 1],
      ["screens/s2.js", "How freshness, coverage, retrieval", 1],
      ["screens/s3.js", "Grant your team scoped access", 2],
      ["screens/s6.js", "public websites that agents can use", 1],
      // 2026-08 knowledge-operations redesign: the update card's tooltip now
      // describes the three-step flow (find → organize → draft for review).
      ["screens/s7.js", "Processes new saved memories", 1],
      ["screens/s8.js", "Every read, write, deletion", 1],
      ["screens/s12.js", "new or saved provider connection", 2],
      ["screens/s14.js", "Agents and MCP clients you connected", 2],
      ["screens/s15.js", "Every traced query in scope", 1],
      ["screens/s16.js", "Every skill your teams have added", 1],
      ["screens/s17.js", "Most apps add themselves", 2],
      ["screens/s21.js", "Put Halo Assistant where your customers already talk", 4],
    ] as const;

    for (const [path, phrase, minimumInfoCalls] of expectations) {
      const screen = await source(path);
      expect(screen, path).toContain(phrase);
      expect(screen.match(/headingInfo\(/g)?.length ?? 0, path).toBeGreaterThanOrEqual(minimumInfoCalls);
    }
  });

  it("keeps operational errors, live states, field help, and irreversible-action warnings visible", async () => {
    const [audit, channels, models] = await Promise.all([
      source("screens/s8.js"),
      source("screens/s21.js"),
      source("screens/s12.js"),
    ]);

    // The erase card's long description moved into the title tooltip (design
    // decision, 2026-08-07); the VISIBLE irreversible-action warning is the
    // crit pill, which must never migrate into a tooltip.
    expect(audit).toContain('<i class="dot"></i>Cannot be undone');
    expect(audit).toContain("Right to be forgotten. Permanently removes the matching memory");
    expect(channels).toContain('<div class="hint" data-s21-status role="status"');
    expect(models).toContain('role="alert"><h3>Could not load model runtime</h3>');
  });

  // Regression: the S15 instrument panel clipped itself to its own 14px radius
  // with overflow:hidden. That clip is inherited by absolutely positioned
  // descendants, so the band heading tooltip - which opens up and out of the
  // 116px label column - was cut off at the panel's left and top edges and the
  // reader lost the opening words of the tip. The panel now rounds its four
  // outer children instead of clipping, and the band tooltips anchor to the
  // left edge of their icon so a 280px tip cannot reach under the nav rail.
  it("lets the S15 band tooltips escape the stat panel instead of clipping them", async () => {
    const css = await source("app.css");

    const panel = css.match(
      /body\[data-console-screen="s15"\] #screen-content \.usage-stat-block\{[^}]*\}/,
    );
    expect(panel, "s15 .usage-stat-block rule").not.toBeNull();
    expect(panel![0]).not.toMatch(/overflow:hidden/);
    expect(panel![0]).toMatch(/overflow:visible/);

    for (const corner of [
      /\.usage-stat-section:first-child>:first-child\{[\s\S]*?border-top-left-radius:13px/,
      /\.usage-stat-section:first-child>:last-child\{[\s\S]*?border-top-right-radius:13px/,
      /\.usage-stat-section:last-child>:first-child\{[\s\S]*?border-bottom-left-radius:13px/,
      /\.usage-stat-section:last-child>:last-child\{[\s\S]*?border-bottom-right-radius:13px/,
    ]) {
      expect(css, String(corner)).toMatch(corner);
    }

    // Left-anchored, and only above the 640px bottom-sheet breakpoint.
    expect(css).toMatch(
      /@media\(min-width:641px\)\{[\s\S]*?\.usage-stat-section-head h3 \.heading-info::after\{[\s\S]*?left:auto;right:auto;margin-left:-14px/,
    );
  });
});
