import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const appPath = fileURLToPath(new URL("../console/app.js", import.meta.url));
const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("console rail section accordion", () => {
  it("groups every role-filtered destination into Operate, Govern, or Account", async () => {
    const app = await readFile(appPath, "utf8");
    const nav = app.slice(app.indexOf("const NAV = ["), app.indexOf("];", app.indexOf("const NAV = [")) + 2);

    expect(nav.match(/group: "/g)).toHaveLength(3);
    expect(nav).toContain('group: "Operate"');
    expect(nav).toContain('group: "Govern"');
    expect(nav).toContain('group: "Account"');
    expect(nav).toMatch(/group: "Operate",\s+icon: "spark"/);
    expect(nav).toMatch(/group: "Govern",\s+icon: "shield"/);
    expect(nav).toMatch(/group: "Account",\s+icon: "people"/);
    expect(nav).not.toContain('group: "Onboard"');
    expect(nav).toMatch(/group: "Account",[\s\S]*?\{ s: "s1", icon: "wand", label: "Setup" \}/);
    expect(nav).toMatch(/group: "Account",[\s\S]*?\{ s: "s18", icon: "gear", label: "Settings" \}/);
  });

  it("renders accessible rectangular group toggles with plus and minus states", async () => {
    const app = await readFile(appPath, "utf8");

    expect(app).toContain('class="navsection" data-nav-section="${groupKey}"');
    expect(app).toContain('class="navgroup" type="button" data-nav-group="${groupKey}"');
    expect(app).toContain('aria-expanded="${expanded}"');
    expect(app).toContain('aria-controls="${panelId}"');
    expect(app).toContain('class="navgroup-heading"');
    expect(app).toContain('class="navgroup-symbol"');
    expect(app).toContain('iconSvg(grp.icon)');
    expect(app).toContain('class="navgroup-icon__horizontal"');
    expect(app).toContain('class="navgroup-icon__vertical"');
    expect(app).toContain('class="nav" id="${panelId}" data-nav-panel');
  });

  it("keeps one group open, supports retraction, and reveals the active route", async () => {
    const app = await readFile(appPath, "utf8");

    expect(app).toContain('let expandedRailGroup = "operate";');
    expect(app).toContain('function setExpandedRailGroup(groupKey)');
    expect(app).toContain('panel.hidden = !expanded;');
    expect(app).toContain('function expandRailGroupForScreen(screenId)');
    expect(app).toContain('expandRailGroupForScreen(screenId);');
    expect(app).toContain('button[data-nav-group]');
    expect(app).toContain('setExpandedRailGroup(isExpanded ? null : groupKey);');
  });

  it("uses compact bordered boxes and preserves mobile target size", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.navsection\{[^}]*display:grid[^}]*gap:/);
    expect(css).toMatch(/\.navgroup\{[^}]*all:unset[^}]*border:1px solid[^}]*border-radius:/);
    expect(css).toMatch(/\.navgroup\[aria-expanded="true"\]\{[^}]*background:/);
    expect(css).toMatch(/\.navgroup-heading\{[^}]*display:flex[^}]*align-items:center/);
    expect(css).toMatch(/\.navgroup-symbol svg\{[^}]*width:14px[^}]*height:14px/);
    expect(css).toMatch(/\.navgroup\[aria-expanded="true"\] \.navgroup-icon__vertical\{[^}]*opacity:0/);
    expect(css).toMatch(/body\.rail-collapsed \.navgroup-icon\{[^}]*display:none/);
    expect(css).toMatch(/\.nav\[hidden\]\{display:none/);
    expect(css).toMatch(/@media\(max-width:860px\)[\s\S]*?\.navgroup,\.nav button,[^}]*min-height:44px/);
  });
});
