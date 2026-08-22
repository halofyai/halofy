import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { renderTopology } from "../console/screens/s5-topology.js";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));

const esc = (value: unknown): string => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/\"/g, "&quot;")
  .replace(/'/g, "&#39;");

const topology = {
  pinned: [],
  governedPins: [],
  topology: {
    scope: "selected-subtree",
    sources: [],
    policies: [],
    memories: [],
    knowledgeBases: [],
    skills: [],
    agents: [],
    activeFacts: 0,
    activityFacts: 0,
    companyPublishedFacts: 0,
    routing: { mode: "fixed", name: "baseline" },
  },
};

describe("S5 graph filter controls", () => {
  it("renders category-colored square icon tiles inside rounded rectangles", async () => {
    const html = renderTopology({ esc } as never, topology);
    const css = await readFile(cssPath, "utf8");

    for (const kind of ["policy", "backend", "knowledge", "skill", "retrieval", "agent"]) {
      expect(html).toContain(`class="memory-graph-filter" data-action="topo-filter" data-kind="${kind}"`);
    }
    expect((html.match(/class="memory-graph-filter-icon"/g) ?? [])).toHaveLength(6);
    expect((html.match(/class="memory-graph-filter-icon"[^>]*><svg/g) ?? [])).toHaveLength(6);
    expect(css).toMatch(/\.memory-graph-filter\{[^}]*min-height:36px[^}]*border-radius:var\(--r-sm\)/);
    expect(css).toMatch(/\.memory-graph-filter-icon\{[^}]*width:22px[^}]*height:22px[^}]*border-radius:var\(--r-xs\)/);
    expect(css).not.toMatch(/\.memory-graph-filter\{[^}]*border-radius:var\(--r-pill\)/);
    expect(css).toMatch(/\.memory-graph-toolbar\{[^}]*border-bottom:1px solid #e5e7eb[^}]*background:#fff[^}]*color:#111827/);
    expect(css).toMatch(/\.memory-graph-filter\{[^}]*border:1px solid #e5e7eb[^}]*background:#fff[^}]*color:#111827/);
    expect(css).toMatch(/\.memory-graph-viewport\{[^}]*background:#07110e/);
    expect(css).toMatch(/\.memory-graph-legend\{[^}]*border-left:1px solid #e5e7eb[^}]*background:#fff[^}]*color:#111827/);
    expect(css).toMatch(/\.memory-graph-stat\{[^}]*border:1px solid #e5e7eb[^}]*background:#f9fafb/);
    expect(css).toMatch(/\.memory-graph-find-input\{[^}]*border:1px solid #e5e7eb[^}]*background:#fff[^}]*color:#111827/);
    expect(css).not.toMatch(/\.memory-graph-(?:toolbar|legend)\{[^}]*background:var\(--mineral\)/);
    expect(html).not.toContain('<div class="eyebrow">Effective access</div>');
    expect(html).not.toContain("<h2>Memory graph</h2>");
  });

  it("keeps the graph toolbar and legend text comfortably readable", async () => {
    const html = renderTopology({ esc } as never, topology);
    const css = await readFile(cssPath, "utf8");

    for (const label of [
      "Active guardrails",
      "Connected backends",
      "Backend files",
      "Knowledge uploads",
      "Connected skills",
      "Connected agents",
    ]) {
      expect(html).toContain(`class="memory-graph-stat-label">${label}</span>`);
    }
    expect(css).toMatch(/\.memory-graph-toolbar>span\{[^}]*font:600 12px var\(--font-sans\)[^}]*text-transform:none/);
    expect(css).toMatch(/\.memory-graph-panel-title\{[^}]*font:600 12px var\(--font-sans\)[^}]*text-transform:none/);
    expect(css).toMatch(/\.memory-graph-stat-label\{[^}]*color:var\(--ink\)[^}]*font-size:12\.5px/);
    expect(css).toMatch(/\.memory-graph-lane small\{[^}]*color:var\(--muted\)[^}]*font:11px\/1\.45 var\(--font-sans\)/);
    expect(css).toMatch(/\.memory-graph-stats\{[^}]*font:500 12\.5px\/1\.4 var\(--font-sans\)/);
    expect(css).toMatch(/\.memory-graph-head \.pill\{[^}]*font:600 12px var\(--font-sans\)[^}]*text-transform:none/);
  });
});
