import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

async function consoleFile(path: string): Promise<string> {
  return readFile(fileURLToPath(new URL(`../console/${path}`, import.meta.url)), "utf8");
}

describe("console UX audit report regressions", () => {
  it("keeps login and navigation honest on small screens", async () => {
    const [login, index, css] = await Promise.all([
      consoleFile("login.html"),
      consoleFile("index.html"),
      consoleFile("app.css"),
    ]);
    expect(login).toContain('<meta name="viewport" content="width=device-width, initial-scale=1"');
    expect(login.match(/class="brand auth-brand"/g) ?? []).toHaveLength(0);
    expect(index).not.toContain("M6 9l6 6 6-6");
    expect(index).not.toContain('id="orgpick"');
    expect(css).not.toMatch(/\.orgpick(?:\s|\{|,)/s);
    expect(css).toMatch(/\.head h1\{font-size:clamp\(26px,7vw,28px\)/s);
  });

  it("keeps the memory graph spatial and standardizes filter controls on mobile", async () => {
    const [css, topology, conflicts, usage] = await Promise.all([
      consoleFile("app.css"),
      consoleFile("screens/s5-topology.js"),
      consoleFile("screens/s11.js"),
      consoleFile("screens/s15.js"),
    ]);
    // The plane grows with its row (a long inspector makes the row taller) but
    // never collapses below the authored composition, which stays 800px and
    // centres inside the plane instead of leaving a stranded black column.
    expect(css).toMatch(/\.memory-graph-viewport\{position:relative;[^}]*min-height:800px/s);
    expect(css).toMatch(/\.memory-graph-canvas\{[^}]*top:50%;height:800px/s);
    expect(css).toMatch(/\.memory-graph-canvas\{[^}]*translate\(var\(--pan-x,0px\),calc\(-50% \+ var\(--pan-y,0px\)\)\)/s);
    expect(css).toMatch(/\.memory-graph-node\{position:absolute/s);
    expect(css).not.toMatch(/\.memory-graph-viewport\{height:auto;display:grid;grid-template-columns:1fr/s);
    expect(css).not.toMatch(/\.memory-graph-node\{position:static/s);
    expect(topology).toContain("filter-strip filter-strip--scroll");
    expect(conflicts).toContain('class="filter-strip"');
    expect(usage).toContain('acts: \'<div class="filter-strip">\'');
  });

  it("keeps connected sources first and the catalog secondary", async () => {
    const source = await consoleFile("screens/s6.js");
    expect(source.indexOf("connectedSources(ctx")).toBeLessThan(source.indexOf("catalogSection(ctx"));
    expect(source).toContain('class="compact-disclosure source-browser source-catalog-disclosure"');
    expect(source).toContain('data-action="open-source-catalog"');
    expect(source).not.toContain("syncOverviewCard(ctx, overview");
    expect(source).not.toContain('<ul class="source-connections">');
  });

  it("uses one stat hierarchy and live policy filters", async () => {
    const [css, policy, app] = await Promise.all([
      consoleFile("app.css"),
      consoleFile("screens/policy-library.js"),
      consoleFile("app.js"),
    ]);
    expect(css).toContain(".stat--secondary .v{font-size:28px}");
    expect(css).toMatch(/\.btn:disabled\{opacity:\.72/);
    expect(css).toContain(
      ".policy-summary .metric-card-shell{box-shadow:0 2px 4px rgb(16 24 40/8%),0 8px 18px -12px rgb(18 58 46/20%)}",
    );
    expect(policy).toContain('class="grid g4 policy-summary"');
    // Search is the register's only filter control now (the scope typeahead,
    // the type select and the state tabs are gone) and it still applies live.
    expect(policy).toContain('data-input-action="policy-library-filter"');
    expect(policy).not.toContain("Apply filters");
    expect(app).toContain('priority = "secondary"');
  });

  it("keeps setup, assistant, model, usage, and audit empty/detail states actionable", async () => {
    const [setup, home, audit, copilot, models, usage] = await Promise.all([
      consoleFile("screens/s1.js"),
      consoleFile("screens/s2.js"),
      consoleFile("screens/s8.js"),
      consoleFile("screens/s10.js"),
      consoleFile("screens/s12.js"),
      consoleFile("screens/s15.js"),
    ]);
    expect(setup).not.toContain("Not started");
    const wizard = setup.slice(setup.indexOf("function wizardPanel"), setup.indexOf("function sourceStep"));
    expect(wizard).not.toContain('class="grid g2"');
    // Home's lookup figures used to sit behind an "Activity breakdown"
    // disclosure. They are a top-level card now, and the full ledger is one
    // labelled click away on S15 instead of a second dashboard on Home.
    expect(home).toContain("const lookupsCard");
    expect(home).not.toContain("const activityBreakdown");
    expect(home).toContain('goBtn("s15", "View all in Usage analytics');
    expect(audit).toContain("formatTimestamp");
    expect(audit).toContain('data-action="audit-copy"');
    expect(await consoleFile("app.css")).toMatch(/\.audit-result\{[^}]*white-space:normal;[^}]*overflow-wrap:anywhere/s);
    expect(copilot).toContain('data-action="copilot-open-models"');
    expect(models).toContain('data-action="model-open-setup"');
    expect(models).toContain('class="card model-empty"');
    expect(usage).toContain("/v1/admin/usage/rollup?days=");
    expect(usage).toContain("/v1/admin/usage/queries");
  });
});
