import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

describe("shared console page header", () => {
  it("uses one header geometry for Home, Audit, Teams, and Skills", async () => {
    const [css, home, audit, teams] = await Promise.all([
      readFile(`${CONSOLE_DIR}/app.css`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s2.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s8.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s13.js`, "utf8"),
    ]);

    expect(home).toContain('class="head home-head"');
    expect(audit).toContain('class="head audit-page-head"');
    expect(teams).toContain('class="head teams-v2__head"');
    expect(css).toMatch(
      /\.head\{[^}]*min-height:72px[^}]*align-items:flex-start[^}]*padding:0 0 var\(--s4\)[^}]*margin:0!important/,
    );
    expect(css).toMatch(/\.head h1\{[^}]*font-size:var\(--text-h1\)/);
    expect(css).not.toContain(".audit-page-head h1");
    expect(css).not.toContain(".teams-v2__title-row h1");
    expect(css).not.toContain('.skills-head .eyebrow{display:block}');
    expect(css).not.toContain(".source-screen .head{align-items:center");
    expect(css).not.toContain(".policy-page-head{align-items:");
    expect(css).not.toContain(".policy-page-head h1{");
    expect(css).not.toContain(".oauth-screen>.head{align-items:");
    expect(css).not.toContain(".oauth-screen>.head .acts{padding-top:");
  });

  it("keeps page-specific controls in the same shared right-side action slot", async () => {
    const [audit, teams] = await Promise.all([
      readFile(`${CONSOLE_DIR}/screens/s8.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s13.js`, "utf8"),
    ]);

    expect(audit).toContain('class="acts audit-page-head__actions"');
    expect(teams).toContain('class="acts teams-v2__head-actions"');
  });

  it("does not repeat the navigation group or organization above page titles", async () => {
    const [audit, teams] = await Promise.all([
      readFile(`${CONSOLE_DIR}/screens/s8.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s13.js`, "utf8"),
    ]);

    expect(audit).not.toContain('<div class="eyebrow">Govern');
    expect(teams).not.toContain('<div class="eyebrow">Govern');
  });
});
