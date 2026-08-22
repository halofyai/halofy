import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { actions, cleanup, render } from "../console/screens/s5.js";

const esc = (value: unknown): string => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/\"/g, "&quot;")
  .replace(/'/g, "&#39;");

const topology = {
  scope: "selected-subtree",
  sources: [],
  policies: [],
  memories: [],
  knowledgeBases: [],
  skills: [],
  agents: [],
  activeFacts: 14,
  activityFacts: 0,
  companyPublishedFacts: 14,
  routing: { mode: "fixed", name: "baseline" },
};

const savedMemories = Array.from({ length: 14 }, (_, index) => {
  const n = index + 1;
  return {
    id: `memory-${n}`,
    tier: n % 3 === 0 ? "L3" : "L2",
    status: n % 3 === 0 ? "Governed" : "Current",
    summary: `Saved memory summary ${n}`,
    title: `Saved memory ${n}`,
    body: n === 11 ? `Canonical memory statement ${n}. ${"Long governed context ".repeat(12)}` : `Canonical memory statement ${n}.`,
    team: n === 1 ? "Customer Support Team" : "Support",
    source: n === 1 ? "Customer Refunds Handbook.md" : "Refunds.md",
    author: n === 11 ? "Claude code pratz test" : "Ananya Rao",
    authorRole: n === 11 ? "Conversation capture" : "Document capture",
    origin: n === 11 ? "Conversation" : "Refunds.md",
    createdAt: "2026-02-12T00:00:00.000Z",
    updatedAt: "2026-08-06T00:00:00.000Z",
    version: 4,
    confidence: 0.96,
    accessCount: 214,
    facts: [n === 11 ? `Canonical memory statement ${n}. ${"Long extracted fact ".repeat(9)}` : `Canonical memory statement ${n}.`],
    links: n === 11
      ? []
      : [{ id: "src-refunds", label: "Refunds.md", kind: "source", role: "Source" }],
  };
});

function context() {
  let refreshes = 0;
  const graph = {
    title: "Company memory",
    scopes: [],
    counts: { nodes: 14, edges: 1 },
    topology,
    savedMemories,
  };
  const ctx = {
    esc,
    identity: { namespace: "halofy", role: "owner" },
    organizationName: "Halofy",
    api: {
      get: async (path: string) => path.startsWith("/v1/memory-graph")
        ? graph
        : { pinned: [], governedPins: [], topology },
    },
    refresh: async () => {
      cleanup("refresh");
      refreshes += 1;
    },
    ui: {
      head: ({ title }: { title: string }) => `<header>${title}</header>`,
      empty: (message: string) => `<div>${message}</div>`,
    },
  };
  return { ctx: ctx as never, refreshes: () => refreshes };
}

describe("S5 saved memories", () => {
  it("keeps the saved-memory detail content clear of the drawer header", () => {
    const css = readFileSync(new URL("../console/app.css", import.meta.url), "utf8");

    expect(css).toMatch(/\.saved-memory-drawer \.console-right-panel__body\{padding:16px 24px 24px/);
    expect(css).toMatch(/\.saved-memory-row\{[^}]*grid-template-columns:26px minmax\(220px,1fr\) 112px 114px 68px 104px 18px/);
    expect(css).toMatch(/\.saved-memory-source,\.saved-memory-used,\.saved-memory-date\{[^}]*line-height:1\.45/);
    expect(css).toMatch(/@media\(max-width:760px\)[\s\S]*\.saved-memory-drawer \.console-right-panel__body\{padding:16px 16px 20px/);
  });

  it("renders ten rows per page, query-ledger pagination, and a graph-linked detail drawer", async () => {
    const { ctx, refreshes } = context();
    const first = await render(ctx);

    expect(first).toContain('class="home-overview memory-overview"');
    expect(first).toContain('aria-label="Memory summary"');
    expect(first).toContain("Current Memories");
    expect(first).toContain("Warm L2");
    expect(first).toContain("Cold L3");
    expect(first).toContain("Connected Sources");
    expect(first).toContain('class="saved-memories"');
    expect(first).toContain("Saved Memories");
    expect(first).toContain('class="saved-memory-search"');
    expect(first).toContain('data-input-action="saved-memory-search"');
    expect(first).toContain('placeholder="Search memories..."');
    expect(first).not.toContain("Summaries of everything held in warm and cold memory across this view.");
    expect(first).toContain('popovertarget="saved-memory-filter"');
    expect(first).toContain('id="saved-memory-filter" popover');
    expect(first).toContain('class="halo-icon-control saved-memory-filter-trigger"');
    expect(first).toContain('aria-label="Filter saved memories by team"');
    expect(first).toContain('aria-label="Filter saved memories by created date"');
    expect(first).toContain(">All teams</option>");
    expect(first).toContain(">Customer Support Team</option>");
    expect(first).toContain(">Support</option>");
    expect(first).toContain('aria-label="Created Feb 12, 2026"');
    expect(first).toContain("Showing 1–10 of 14 Memories");
    expect(first.match(/data-action="saved-memory-open"/g)).toHaveLength(10);
    expect(first).toContain("Saved memory 10");
    expect(first).not.toContain("Saved memory 11");
    expect(first).toContain(">Customer Supp…</span>");
    expect(first).toContain(">Customer Refu…</span>");
    expect(first).toContain('aria-label="Page 1" aria-current="page"');
    expect(first).toContain('aria-label="Page 2"');

    await actions["saved-memory-page"](
      ctx,
      { getAttribute: (name: string) => name === "data-page" ? "2" : null } as never,
    );
    expect(refreshes()).toBe(1);

    const second = await render(ctx);
    expect(second).toContain("Showing 11–14 of 14 Memories");
    expect(second.match(/data-action="saved-memory-open"/g)).toHaveLength(4);
    expect(second).toContain("Saved memory 11");
    expect(second).not.toContain("Saved memory 10");

    await actions["saved-memory-open"](
      ctx,
      { getAttribute: (name: string) => name === "data-memory-id" ? "memory-11" : null } as never,
    );
    expect(refreshes()).toBe(1);
    const detail = await render(ctx);
    expect(detail).toContain('id="saved-memory-panel"');
    expect(detail).toContain('role="dialog" aria-modal="true"');
    expect(detail).toContain("EXTRACTION CONFIDENCE");
    expect(detail).toContain("1 Extracted Fact");
    expect(detail).toContain("GRAPH LINKAGE");
    expect(detail.match(/data-collapsible-text/g)).toHaveLength(2);
    expect(detail.match(/data-action="saved-memory-text-toggle"/g)).toHaveLength(4);
    expect(detail.match(/aria-expanded="false">See more<\/button>/g)).toHaveLength(2);
    expect(detail).toContain('class="saved-memory-linkage"');
    expect(detail).toContain("Claude code pratz test");
    expect(detail).toContain("Conversation");
    expect(detail).toContain("Came from");
    expect(detail).toContain("Captured by");
    expect(detail).toContain("L2 Warm memory");
    expect(detail).toContain("Stored in");
    expect(detail).toContain('data-node-id="t:L2" data-node-kind="tier"');
    expect(detail).toContain('marker-end="url(#saved-memory-lineage-arrow)"');
    expect(detail).not.toContain("No direct graph links recorded.");
    expect(detail).not.toContain("background-image:radial-gradient");
    expect(detail).not.toContain("background-size:20px 20px");

    const css = await readFile(
      fileURLToPath(new URL("../console/app.css", import.meta.url)),
      "utf8",
    );
    expect(css).toMatch(/\.saved-memory-linkage\{[^}]*background:#07110e/);
    expect(css).toMatch(/\.saved-memory-linkage::before\{[^}]*radial-gradient\([^}]*filter:blur/);
    expect(css).toMatch(/\.saved-memory-link-core\{[^}]*box-shadow:[^}]*0 0 28px/);
    expect(css).toMatch(/\.saved-memory-text\.is-collapsible \.saved-memory-body[^}]*-webkit-line-clamp:3/);
    expect(css).toMatch(/\.saved-memory-drawer \.console-right-panel__body\{padding:16px 24px 24px/);
    expect(css).toMatch(/\.saved-memories-head\{[^}]*display:grid[^}]*grid-template-columns:minmax\(128px,1fr\) minmax\(220px,380px\) minmax\(128px,1fr\)/);
    expect(css).toMatch(/\.saved-memory-search\{[^}]*justify-self:center[^}]*width:100%/);
    expect(css).toMatch(/@media\(max-width:760px\)[\s\S]*\.saved-memory-drawer \.console-right-panel__body\{padding:16px 16px 20px/);
    cleanup();
  });

  it("filters saved memories by exact team and created date before paginating", async () => {
    cleanup();
    const { ctx, refreshes } = context();

    await actions["saved-memory-filter"](
      ctx,
      {
        value: "Customer Support Team",
        getAttribute: (name: string) => name === "data-filter" ? "team" : null,
      } as never,
    );
    expect(refreshes()).toBe(1);

    const byTeam = await render(ctx);
    expect(byTeam).toContain("1 OF 14 MEMORIES");
    expect(byTeam).toContain('class="saved-memory-filter-badge" aria-hidden="true">1</span>');
    expect(byTeam).toContain('value="Customer Support Team" selected');
    expect(byTeam).toContain("Saved memory 1");
    expect(byTeam).not.toContain("Saved memory 2");
    expect(byTeam).toContain("Showing 1–1 of 1 matching Memories");

    await actions["saved-memory-filter"](
      ctx,
      {
        value: "2026-02-13",
        getAttribute: (name: string) => name === "data-filter" ? "created-date" : null,
      } as never,
    );
    const noMatches = await render(ctx);
    expect(noMatches).toContain("0 OF 14 MEMORIES");
    expect(noMatches).toContain("No memories match these filters.");
    expect(noMatches).not.toContain('data-action="saved-memory-open"');

    await actions["saved-memory-filter-clear"](ctx, {} as never);
    const cleared = await render(ctx);
    expect(cleared).toContain("14 MEMORIES");
    expect(cleared).not.toContain("OF 14 MEMORIES");
    expect(cleared).toContain("Showing 1–10 of 14 Memories");
    cleanup();
  });

  it("ranks keyword matches and repaints the saved-memory list on every input", async () => {
    cleanup();
    const { ctx, refreshes } = context();
    await render(ctx);

    const results = { innerHTML: "" };
    const count = { textContent: "" };
    const section = {
      querySelector: (selector: string) => selector === "[data-saved-memory-results]" ? results : count,
    };
    const search = (value: string) => actions["saved-memory-search"](
      ctx,
      { value, closest: () => section } as never,
    );

    search("Claude pratz");
    expect(refreshes()).toBe(0);
    expect(count.textContent).toBe("1 OF 14 MEMORIES");
    expect(results.innerHTML).toContain('data-memory-id="memory-11"');
    expect(results.innerHTML).not.toContain('data-memory-id="memory-1"');
    expect(results.innerHTML).toContain("Showing 1–1 of 1 matching Memories");

    search("saved memory 11");
    expect(results.innerHTML.indexOf('data-memory-id="memory-11"'))
      .toBeLessThan(results.innerHTML.indexOf('data-memory-id="memory-1"'));

    search("no such memory keyword");
    expect(count.textContent).toBe("0 OF 14 MEMORIES");
    expect(results.innerHTML).toContain("No memories match your search.");
    cleanup();
  });

  it("expands long drawer text and collapses it again from the text area", () => {
    const classes = new Set<string>();
    const button = {
      textContent: "See more",
      setAttribute(name: string, value: string) {
        if (name === "aria-expanded") this.ariaExpanded = value;
      },
      ariaExpanded: "false",
    };
    const container = {
      classList: { toggle: (name: string) => classes.has(name) ? (classes.delete(name), false) : (classes.add(name), true) },
      querySelector: () => button,
    };
    const target = { closest: () => container };

    actions["saved-memory-text-toggle"]({} as never, target as never);
    expect(classes.has("is-expanded")).toBe(true);
    expect(button).toMatchObject({ textContent: "See less", ariaExpanded: "true" });

    actions["saved-memory-text-toggle"]({} as never, target as never);
    expect(classes.has("is-expanded")).toBe(false);
    expect(button).toMatchObject({ textContent: "See more", ariaExpanded: "false" });
  });
});
