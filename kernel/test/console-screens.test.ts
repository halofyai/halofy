/**
 * M5 frontend — pure-Node screen render tests (no browser, no jsdom).
 *
 * Each `console/screens/s<N>.js` is a pure string-returning renderer:
 *   `export async function render(ctx) -> Promise<string>` (an HTML fragment).
 * We import each module and call `render(mockCtx)` where `mockCtx.api` returns
 * canned shapes matching `src/console/api.ts` (and the referee/cert shapes the
 * screens read), and `mockCtx.esc` is the REAL escape from app.js. We then
 * assert the returned HTML string:
 *   (a) contains the seeded values, and
 *   (b) ESCAPES a hostile fact content `<img src=x onerror=alert(1)>` — the raw
 *       `<img` must NOT appear anywhere in the output (proves ctx.esc() is the
 *       only interpolation path for every API-derived value).
 *
 * Role cases: with `identity.role='auditor'` the mutation controls (Pin, Sync,
 * Run report, Connect, Switch, Invite, Issue, Revoke, Erase) are ABSENT — the
 * same role contract the server enforces, encoded defensively in the UI.
 *
 * These screens import NOTHING but the passed ctx, so they load and run in plain
 * Node. The only browser globals they touch (document/navigator/window/
 * URLSearchParams-with-filters) live inside `actions`, never in a default
 * `render()` path — so importing + rendering is browser-free.
 */

import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { GRAPH_VIEW_HEIGHT, GRAPH_VIEW_WIDTH } from "../console/screens/s5-topology.js";

// ---------------------------------------------------------------------------
// The real esc() from app.js — replicated here as the module is an ES-module
// shell that boots on import (touches document/fetch), so we cannot import it
// in Node. This MUST stay byte-identical to app.js's esc(); a divergence would
// make the escape assertion test the wrong function. Guarded by escParity below.
// ---------------------------------------------------------------------------

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** The XSS probe fed into every attacker-influenced text field. */
const XSS = "<img src=x onerror=alert(1)>";
/** The escaped form the output MUST contain instead of the raw payload. */
const XSS_ESCAPED = "&lt;img src=x onerror=alert(1)&gt;";

const SCREEN_URL = (n: string) =>
  fileURLToPath(new URL(`../console/screens/${n}.js`, import.meta.url));

/** Load a screen module (dynamic import of the served .js file). */
async function loadScreen(n: string): Promise<{
  render(ctx: unknown): Promise<string>;
  actions?: Record<string, unknown>;
}> {
  return import(SCREEN_URL(n));
}

// ---------------------------------------------------------------------------
// Mock ctx factory. `api.get`/`api.post`/`api.patch`/`api.put`/`api.del` are dispatched by
// (method, path) against a caller-supplied route table; an unmatched route
// throws (so a screen calling the wrong endpoint fails loudly).
// ---------------------------------------------------------------------------

type Role = "owner" | "admin" | "auditor" | "member";
type Handler = (body?: unknown) => unknown;
interface Routes {
  get?: Record<string, Handler | unknown>;
  post?: Record<string, Handler | unknown>;
  patch?: Record<string, Handler | unknown>;
  put?: Record<string, Handler | unknown>;
  del?: Record<string, Handler | unknown>;
}

function resolve(table: Record<string, Handler | unknown> | undefined, path: string, body?: unknown): unknown {
  if (!table || !(path in table)) {
    throw { status: 404, message: `no canned response for ${path}` };
  }
  const v = table[path];
  return typeof v === "function" ? (v as Handler)(body) : v;
}

function makeCtx(opts: { role?: Role; namespace?: string; routes?: Routes } = {}) {
  const routes = opts.routes ?? {};
  let durableConversationSequence = 0;
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const refreshCalls: string[] = [];
  const ctx = {
    esc,
    identity: {
      keyId: "sess_test",
      namespace: opts.namespace ?? "acme",
      actor: "owner@acme.test",
      role: (opts.role ?? "owner") as Role,
    },
    go() {
      /* navigation is a no-op in the pure render test */
    },
    async refresh() {
      refreshCalls.push("refresh");
    },
    api: {
      async get(path: string) {
        calls.push({ method: "GET", path });
        return resolve(routes.get, path);
      },
      async post(path: string, body?: unknown) {
        calls.push({ method: "POST", path, body });
        if (path === "/v1/copilot/conversations" &&
            (!routes.post || !(path in routes.post))) {
          durableConversationSequence += 1;
          const seed = "01KYMHE0000000000000000001";
          return {
            id: seed.slice(0, -1) + String(durableConversationSequence),
            title: "New chat",
            turns: 0,
            createdAt: "2026-08-02T00:00:00.000Z",
            updatedAt: "2026-08-02T00:00:00.000Z",
          };
        }
        return resolve(routes.post, path, body);
      },
      async patch(path: string, body?: unknown) {
        calls.push({ method: "PATCH", path, body });
        return resolve(routes.patch, path, body);
      },
      async put(path: string, body?: unknown) {
        calls.push({ method: "PUT", path, body });
        return resolve(routes.put, path, body);
      },
      async del(path: string) {
        calls.push({ method: "DELETE", path });
        return resolve(routes.del, path);
      },
    },
    ui: makeUi(),
  };
  return { ctx, calls, refreshCalls };
}

/**
 * A faithful-enough replica of app.js's ui.* helpers (only the two the operate
 * screens actually use — head + empty — are consumed by the render paths that
 * B reports; the govern screens build their own markup). Helpers do NOT escape
 * (callers pre-esc), mirroring app.js.
 */
function makeUi() {
  return {
    head({ eyebrow, title, acts }: { eyebrow?: string; title?: string; acts?: string } = {}) {
      const left =
        `<div>` +
        (eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : "") +
        (title ? `<h1>${title}</h1>` : "") +
        `</div>`;
      const right = acts ? `<div class="acts">${acts}</div>` : "";
      return `<div class="head">${left}${right}</div>`;
    },
    empty(msg: string) {
      return `<div class="card"><div class="sub" style="margin:0">${msg}</div></div>`;
    },
    pill(text: string, kind?: string) {
      const cls = kind ? `pill pill--${kind}` : "pill";
      return `<span class="${cls}"><i class="dot"></i>${text}</span>`;
    },
    // Mirrors app.js's ui.stat/ui.field markup so screens that compose them
    // are asserted against the same escaping surface the browser renders.
    stat(
      {
        k,
        v,
        foot,
        delta,
        tone,
        priority = "secondary",
      }: {
        k?: string;
        v?: string;
        foot?: string;
        delta?: string;
        tone?: string;
        priority?: string;
      } = {},
    ) {
      const toneClass = tone ? ` ${tone}` : "";
      const deltaHtml = delta ? ` <span class="d${toneClass}">${delta}</span>` : "";
      const valueToneClass = !delta && tone ? ` ${tone}` : "";
      return (
        `<div class="stat${priority === "primary" ? "" : " stat--secondary"}">` +
        `<div class="stat-label"><div class="k">${k ?? ""}</div>` +
        (foot ? `<span class="metric-info stat-info" role="note" tabindex="0" aria-label="${k ?? "Metric"}: ${foot}" data-tip="${foot}"></span>` : "") +
        `</div>` +
        `<div class="v num${valueToneClass}">${v ?? ""}${deltaHtml}</div>` +
        `</div>`
      );
    },
    field({ label, control, hint }: { label?: string; control?: string; hint?: string } = {}) {
      return (
        `<div class="field">` +
        (label ? `<label>${label}</label>` : "") +
        (control ?? "") +
        (hint ? `<div class="hint">${hint}</div>` : "") +
        `</div>`
      );
    },
  };
}

/** No raw <img should ever survive into rendered HTML. */
function assertNoRawImg(html: string): void {
  expect(html).not.toContain("<img");
  expect(html).toContain(XSS_ESCAPED);
}

// ---------------------------------------------------------------------------
// esc parity guard — the replicated esc MUST match app.js's esc byte-for-byte.
// ---------------------------------------------------------------------------

describe("esc parity with app.js", () => {
  it("the test's esc() matches console/app.js esc() on the probe + metacharacters", async () => {
    const appSrc = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.js", import.meta.url)), "utf8"),
    );
    // The app.js esc() is defined with these exact five replaces; assert the
    // source contains each so a future edit to app.js's esc() forces a re-check.
    for (const rep of [
      String.raw`.replace(/&/g, "&amp;")`,
      String.raw`.replace(/</g, "&lt;")`,
      String.raw`.replace(/>/g, "&gt;")`,
      String.raw`.replace(/"/g, "&quot;")`,
      String.raw`.replace(/'/g, "&#39;")`,
    ]) {
      expect(appSrc).toContain(rep);
    }
    expect(esc(XSS)).toBe(XSS_ESCAPED);
    expect(esc(`a&b<c>d"e'f`)).toBe(`a&amp;b&lt;c&gt;d&quot;e&#39;f`);
  });
});

// ---------------------------------------------------------------------------
// S2 — Home / overview
// ---------------------------------------------------------------------------

describe("s2 - overview", () => {
  const assistantMonthRollup = (extra: Record<string, unknown> = {}) => ({
    namespace: "acme",
    windowDays: 31,
    period: "month",
    since: "2026-08-01T00:00:00.000Z",
    groupBy: "sourceApp",
    totals: {
      turns: 8,
      inputTokens: 200,
      outputTokens: 100,
      totalUsd: 4.25,
      unavailableCostTurns: 0,
    },
    groups: [],
    ...extra,
  });
  const overview = (extra: Record<string, unknown> = {}) => ({
    namespace: "acme",
    children: [{ namespace: "acme/support", l2Active: 7 }],
    l2Active: 42,
    faultCount: 10,
    faultHitRate: 0.6,
    spend: { monthToDateUsd: 90, effectiveCapUsd: 100 },
    assembledTokens: 123456,
    usage: { totalTokens: 987654, totalUsd: 12.3456 },
    models: [
      {
        profileId: "mp1",
        name: "default-writer",
        provider: "anthropic",
        model: "claude-sonnet-5",
        isDefault: true,
        completions: 31,
      },
      {
        profileId: "mp2",
        name: "cheap-summarizer",
        provider: "openai-compatible",
        model: "gpt-5-mini",
        isDefault: false,
        completions: 4,
      },
    ],
    sourcesSummary: {
      connectedCount: 2,
      connected: [
        { id: "src1", kind: "notion", namespace: "acme", syncStatus: "synced", lastSync: null },
        { id: "src2", kind: "slack", namespace: "acme", syncStatus: "failed", lastSync: null },
      ],
      top: [
        { id: "src1", kind: "notion", namespace: "acme", facts: 12 },
        { id: "conversation", kind: "conversation", namespace: null, facts: 30 },
      ],
    },
    topTeams: [
      { name: "acme/support", count: 55 },
      { name: XSS, count: 3 },
    ],
    topActors: [
      { name: "agent:triage", count: 41 },
      { name: XSS, count: 2 },
    ],
    queryCategories: [
      { category: "Support", count: 9 },
      { category: "Sales", count: 4 },
    ],
    querySummary: {
      total: 13,
      hits: 9,
      misses: 4,
      hitRate: 9 / 13,
      topQueries: [{ query: XSS, count: 6 }],
    },
    memoryWrites: {
      total: 20,
      teams: [
        { name: "acme/support", count: 12 },
        { name: "acme/product", count: 8 },
      ],
    },
    homeCounts: { skills: 6, channels: 3, agents: 3, policies: 4, conflicts: 2 },
    agentAccess: {
      totalAgents: 3,
      withinPolicy: 3,
      overreaching: [],
      accessEvents: { allowed: 8, denied: 0, error: 0 },
      accessRequests: { pending: 0, approved: 2, denied: 0, expired: 0, consumed: 1 },
    },
    ...extra,
  });

  it("renders the usage dashboard and escapes hostile actors/teams/queries", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({ routes: { get: {
      "/v1/admin/overview": overview(),
      "/v1/admin/usage/ai-rollup?days=90&groupBy=team": { totals: { turns: 560 } },
      "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup(),
    } } });
    const html = await s2.render(ctx);
    expect(html).toContain("42"); // facts under management
    expect(html).toContain("Assistant Spend");
    expect(html).toContain("$4.25");
    expect(html).toContain("300 model tokens");
    expect(html).toContain("Halofy Assistant only");
    expect(html).toContain("external AI tools are not included");
    // The 2026-08 Home is five tiles and five cards. Model, source-contributor
    // and query-category detail moved to their own screens (S12/S6/S15), so
    // Home names the sources it counts and links to the ledger instead of
    // re-rendering all three here.
    expect(html).toContain("Connected Sources");
    expect(html).toContain("notion, slack");
    expect(html).toContain("Overall Queries");
    expect(html).toContain("58"); // 55 + 3 = every memory call on the leaderboard
    expect(html).not.toContain("Top teams");
    expect(html).toContain("support");
    expect(html).not.toContain("acme/support");
    expect(html).not.toContain("Top individuals &amp; agents");
    expect(html).toContain("Top Memory Queries");
    expect(html).toContain('<div class="between home-panel-head home-top-queries-head"><h3>Top Memory Queries</h3><div class="home-query-filter-wrap">');
    expect(html).toContain('aria-label="Filter Top Memory Queries: Individuals"');
    expect(html).toContain("agent:triage");
    expect(html).toContain("Memory Lookups");
    expect(html).toContain('<div class="between home-panel-head"><h3>Memory Lookups</h3></div>');
    expect(html).toContain('aria-label="9 memory lookups answered"');
    expect(html).toContain('<span class="num">9</span> Answered');
    expect(html).toContain('<span class="num">4</span> Missed');
    expect(html).toContain('<span class="num">560</span> Turns');
    expect(html).not.toContain("assistant turns · 90d rolling</span>");
    expect(html).toContain("View all in Usage analytics");
    expect(html).not.toContain("Access safety");
    expect(html).toContain("Memory Writes");
    expect(html).toContain('class="home-writes-donut"');
    expect(html).toContain("20 Total Writes");
    expect(html).toContain("Track Activity");
    expect(html).toContain("Overview");
    expect(html).toContain('<div class="between home-panel-head"><h3>Overview</h3></div>');
    expect(html).not.toContain("Across acme");
    expect(html).toContain("Skills");
    expect(html).toContain("Channels");
    expect(html).toContain("Policies");
    expect(html).toContain("Conflicts");
    expect(html).toContain('class="home-range-control"');
    expect(html).toContain('data-action="home-range"');
    expect(html).toContain("Overall");
    expect(html).toContain("Halofy Assistant Billing &amp; Limits");
    expect(html).toContain("Halofy Assistant spend this month");
    expect(html).toContain("shared paid-AI cap");
    expect(html).not.toContain("90% of shared cap");
    expect(html).toContain('class="home-cap-ring home-cap-ring--warn"');
    expect(html).toContain('role="progressbar" tabindex="0" aria-label="Shared paid-AI cap used"');
    expect(html).toContain('stroke-dasharray="90 100"');
    expect(html).toContain('<span class="home-cap-ring-value"><strong class="num">90%</strong><span>Cap Used</span></span>');
    expect(html).toContain('<span class="home-usage-label">Assistant spend this month</span>');
    expect(html).not.toContain('class="home-cap-axis"');
    expect(html).not.toContain('class="home-usage-amount"><span class="num">$4.25</span><span class="subtle">');
    expect(html).not.toContain('<span class="subtle home-text-xs">90% of the shared paid-AI cap');
    expect(html).toContain('class="home-usage-amount" role="note" tabindex="0"');
    expect(html).toContain('data-tip="90% of the shared paid-AI cap used this month · alert threshold reached."');
    expect(html).toContain('id="home-cap-panel" class="source-wizard-overlay console-right-panel" hidden');
    expect(html).toContain('class="btn btn--solid btn--sm" type="button" data-action="usage-cap-save"');
    expect(html).toContain('class="btn btn--ghost btn--sm" type="button" data-action="home-cap-close"');
    expect(html).toContain('class="home-metrics"');
    const metricCount = (html.match(/role="listitem"/g) ?? []).length;
    expect(metricCount).toBeGreaterThanOrEqual(4);
    expect(html.match(/class="metric-card-head"/g) ?? []).toHaveLength(metricCount);
    expect(html.match(/class="metric-info metric-card-info"/g) ?? []).toHaveLength(metricCount);
    expect(html).not.toContain('<div class="foot">');
    expect(html).toContain('class="home-dashboard"');
    expect(html).toContain('class="card home-panel home-writes"');
    expect(html).toContain('class="home-avatar home-avatar--person"');
    expect(html).toContain('class="home-writes-dot home-writes-dot--1"');
    expect(html).not.toContain("Top models");
    expect(html).not.toContain("Data sources");
    expect(html).not.toContain("Activity breakdown");
    expect(html).not.toMatch(/\bpaus(?:e|ed)\b/i);
    // The hostile team/actor/query strings are escaped, never raw.
    expect(html).not.toContain(XSS);
    expect(html).toContain(XSS_ESCAPED);
    assertNoRawImg(html);
  });

  it("shows the signed-in user's Assistant questions and external-agent summaries instead of turn ids", async () => {
    const s2 = await loadScreen("s2");
    const conversationId = "01KZ8K5TQ61E57YMMJQNNX1Z7A";
    const turnRef = "assistant-turn:01KZ8K5TQ61E57YMMJQNNX1Z7B";
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            querySummary: {
              total: 14,
              hits: 14,
              misses: 0,
              hitRate: 1,
              topQueries: [{ query: turnRef, count: 13 }],
            },
          }),
          "/v1/admin/usage/queries?days=90&limit=8": {
            queries: [{
              summary: "Product launch readiness and open risks",
              principal: "agent",
              callerClass: "external",
            }],
          },
          "/v1/copilot/conversations?limit=3&offset=0": {
            conversations: [{
              id: conversationId,
              title: "Launch readiness",
              turns: 1,
              createdAt: "2026-08-06T08:00:00.000Z",
              updatedAt: "2026-08-06T08:02:00.000Z",
            }],
            nextOffset: null,
          },
          [`/v1/copilot/conversations/${conversationId}`]: {
            id: conversationId,
            title: "Launch readiness",
            turns: 1,
            createdAt: "2026-08-06T08:00:00.000Z",
            updatedAt: "2026-08-06T08:02:00.000Z",
            messages: [
              { role: "user", text: "Are we ready to launch the new product?", hits: [] },
              { role: "assistant", text: "Here is the current launch assessment.", hits: [] },
              { role: "user", text: `Summarize ${XSS}`, hits: [] },
              { role: "assistant", text: "Here is the safe summary.", hits: [] },
            ],
            hits: [],
            operations: [],
            runtime: "mastra-v2",
            degradedReason: "",
          },
        },
      },
    });

    const html = await s2.render(ctx);

    expect(html).toContain("Are we ready to launch the new product?");
    expect(html).toContain("Product launch readiness and open risks");
    expect(html).toContain(`Summarize ${XSS_ESCAPED}`);
    expect(html).not.toContain(`Summarize ${XSS}`);
    expect(html).toContain("Your Assistant question");
    expect(html).toContain("External agent summary");
    expect(html).not.toContain(turnRef);
    expect(calls).toContainEqual({
      method: "GET",
      path: "/v1/copilot/conversations?limit=3&offset=0",
    });
    expect(calls).toContainEqual({
      method: "GET",
      path: `/v1/copilot/conversations/${conversationId}`,
    });
  });

  it("filters internal Assistant turn references when private history is unavailable", async () => {
    const s2 = await loadScreen("s2");
    const turnRef = "assistant-turn:01KZ8K5TQ61E57YMMJQNNX1Z7C";
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            querySummary: {
              total: 6,
              hits: 6,
              misses: 0,
              hitRate: 1,
              topQueries: [
                { query: turnRef, count: 5 },
                { query: "Quarterly product feedback", count: 1 },
              ],
            },
          }),
        },
      },
    });

    const html = await s2.render(ctx);

    expect(html).not.toContain(turnRef);
    expect(html).toContain("Quarterly product feedback");
  });

  it("shows compact hover and keyboard summaries for Memory Writes segments", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            memoryWrites: {
              total: 30,
              teams: [
                { name: "acme/support", count: 12 },
                { name: "acme", count: 10 },
                { name: XSS, count: 8 },
              ],
            },
          }),
        },
      },
    });
    const html = await s2.render(ctx);
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(html).toContain('class="home-writes-donut" role="group"');
    expect(html).toContain('class="home-writes-segment home-writes-segment--1" role="img"');
    expect(html).toContain('aria-label="support: 40%, 12 items"');
    expect(html).toContain('aria-label="acme: 33%, 10 items"');
    expect(html).toContain('class="home-writes-legend" role="group" aria-label="Memory Writes by team"');
    expect(html).toContain('class="home-writes-legend-row home-writes-legend-row--1" role="img" tabindex="0" aria-label="support: 40%, 12 items"');
    expect(html.match(/class="home-writes-tooltip home-writes-tooltip--/g) ?? []).toHaveLength(3);
    expect(html).toContain('<strong>support</strong><span><b>40%</b><i aria-hidden="true">&#183;</i>12 items</span>');
    expect(html).toContain('<strong>acme</strong><span><b>33%</b><i aria-hidden="true">&#183;</i>10 items</span>');
    expect(html).not.toContain("acme/support");
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain(XSS);
    expect(css).toMatch(/\.home-writes-tooltip\{[^}]*max-width:160px[^}]*pointer-events:none/s);
    expect(css).toContain('.home-writes-donut:has(.home-writes-segment--1:hover) .home-writes-tooltip--1');
    expect(css).toContain('.home-writes-body:has(.home-writes-legend-row--1:hover) .home-writes-tooltip--1');
    expect(css).toContain('.home-writes-body:has(.home-writes-legend-row--1:focus-visible) .home-writes-tooltip--1');
    expect(css).toContain('.home-writes-body:has(.home-writes-legend-row--1:hover) .home-writes-segment--1');
    expect(css).toMatch(/\.home-writes-legend-row:hover\{[^}]*border-color:var\(--olive\)[^}]*transform:translateY\(-1px\)/s);
  });

  it("uses the shared readable type scale on Home without a screen-specific downscale", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({ routes: { get: { "/v1/admin/overview": overview() } } });
    const html = await s2.render(ctx);
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(html).toContain('class="home-overview"');
    expect(css).toContain("--text-body-size:16px");
    expect(css).toContain("--text-small:13px");
    expect(css).toContain("--text-label:12px");
    expect(css).toContain("--text-h1:34px");
    expect(css).toContain(".home-overview{font-size:var(--text-body-size)}");
    expect(css).toMatch(/\.home-head h1\{[^}]*font-size:var\(--text-h1\)/);
    expect(css).not.toMatch(/\.home-head h1\{[^}]*font-size:\d+px/);
    expect(css).not.toContain("Home keeps its heading hierarchy while making dense dashboard copy 15% smaller");
    expect(html).toContain("Assistant Spend");
    expect(html).toContain("Saved Knowledge");
    expect(html).toContain("answered from memory");
    expect(html).not.toContain("L2 warm tier");
    expect(html).not.toContain("brown out");
    expect(html).not.toContain("governed write path");
    expect(html).not.toContain("provenance");
  });

  it("matches the supplied Home prototype visual contract", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview(),
          "/v1/admin/people": { users: [], badges: [] },
        },
      },
    });
    const html = await s2.render(ctx);
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(html).toContain("Everything, At A Glance");
    expect(html).toContain('class="head home-head"');
    expect(html).not.toContain('class="home-breadcrumb"');
    expect(html).not.toContain("Home ·");
    expect(html).toContain('class="metric-card-shell"');
    expect(html).toContain('class="home-card-link"');
    expect(html).toContain('class="home-query-filter-button"');
    expect(html).not.toContain('</svg><span>Individuals</span>');
    expect(css).toContain(".home-query-filter-button{gap:6px;min-width:30px");

    const spend = html.indexOf("Assistant Spend");
    const queries = html.indexOf("Overall Queries");
    const seats = html.indexOf("Seats");
    const saved = html.indexOf("Saved Knowledge");
    const sources = html.indexOf("Connected Sources");
    expect(spend).toBeGreaterThan(-1);
    expect(spend).toBeLessThan(queries);
    expect(queries).toBeLessThan(seats);
    expect(seats).toBeLessThan(saved);
    expect(saved).toBeLessThan(sources);

    expect(css).toContain("--home-canvas:var(--surface-soft)");
    expect(css).toContain("--home-panel:var(--panel)");
    expect(css).toContain("--home-border:var(--line)");
    expect(css).toContain("--home-text:var(--ink)");
    expect(css).toContain("grid-template-columns:repeat(5,minmax(0,1fr));gap:12px");
    expect(css).toContain("grid-template-columns:repeat(2,minmax(0,1fr));gap:18px");
    expect(css).toContain("background:var(--home-panel)");
    expect(css).toContain("background:var(--home-canvas)");
    expect(css).toContain("box-shadow:var(--sh-1),var(--sh-2)");
    expect(css).toContain("--content-font:var(--font-sans)");
    expect(css).toContain("--content-text:#111827");
    expect(css).toContain("--content-muted:#6b7280");
  });

  it("keeps the Home typography scope when the overview is unavailable", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx();
    const html = await s2.render(ctx);

    expect(html).toContain('class="home-overview"');
    expect(html).toContain("Overview is unavailable right now");
  });

  it("renders the four-factor Memory Health card inline without the old drawer", async () => {
    const s2 = await loadScreen("s2");
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview(),
          "/v1/admin/readiness": {
            score: 80.4,
            band: "healthy",
            windowDays: 30,
            pillars: [
              {
                id: "freshness",
                label: "Freshness",
                score: 70.7,
                band: "healthy",
                available: true,
                detail: "735 of 735 active facts asserted in the last 90 days.",
              },
              { id: "coverage", label: "Coverage", score: 51.1, band: "fair", available: true, detail: "Coverage detail." },
              { id: "trust", label: "Trust", score: 100, band: "excellent", available: true, detail: "No facts contested." },
              { id: "structure", label: "Structure", score: 100, band: "excellent", available: true, detail: "No duplication." },
            ],
            trend: { direction: "up", deltaPoints: 13.5, previousScore: 66.9, windowDays: 30 },
          },
        },
      },
    });
    const html = await s2.render(ctx);

    expect(html).toContain('class="card home-panel home-health"');
    expect(html).toContain('class="home-health-meter"');
    expect(html).toContain('role="progressbar"');
    expect(html).toContain('aria-valuenow="80.4"');
    expect(html).toContain('aria-valuemin="0" aria-valuemax="100"');
    expect(html).toContain('style="--home-health-progress:80.4%"');
    expect(html).toContain("Factual Validity");
    expect(html).toContain("Hygiene &amp; Deduplication");
    expect(html).toContain("Recency &amp; Decay");
    expect(html).toContain("Intake Completeness");
    expect(html).toMatch(/Factual Validity[\s\S]*?<span class="num">100<\/span>/);
    expect(html).toMatch(/Hygiene &amp; Deduplication[\s\S]*?<span class="num">100<\/span>/);
    expect(html).toMatch(/Recency &amp; Decay[\s\S]*?<span class="num">70.7<\/span>/);
    expect(html).toMatch(/Intake Completeness[\s\S]*?<span class="num">51.1<\/span>/);
    expect(html).toContain("+13.5 vs 30d");
    expect(calls.some((call) => call.path === "/v1/admin/memory-health")).toBe(false);
    expect(html).toContain("Improve Your Memory Health");
    expect(html).toContain('data-screen="s6"');
    expect(html).not.toContain('data-action="home-health-open"');
    expect(html).not.toContain('class="home-health-drawer"');
    expect(html).not.toContain('<details class="compact-disclosure"');
    expect(html).not.toContain("735 of 735 active facts asserted in the last 90 days.");
    expect(html).not.toContain('class="subtle home-health-note"');
  });

  it("changes the global Home range through the delegated shared control", async () => {
    const mod = await loadScreen("s2") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: any, el: any) => Promise<void>>;
      cleanup(reason?: "refresh"): void;
    };
    const { ctx, refreshCalls } = makeCtx({ routes: { get: { "/v1/admin/overview": overview() } } });
    let refreshedHtml = "";
    ctx.refresh = async () => {
      refreshCalls.push("refresh");
      mod.cleanup("refresh");
      refreshedHtml = await mod.render(ctx);
    };
    await mod.actions["home-range"](ctx, {
      getAttribute(name: string) { return name === "data-range" ? "30" : null; },
    });
    expect(refreshCalls).toEqual(["refresh"]);
    expect(refreshedHtml).toContain('data-range="30" aria-pressed="true"');
  });

  // The standalone "Needs your attention" card is gone; each warning is now
  // carried by the card that owns the number, so a near-cap month warns from
  // "Halofy Assistant Billing & Limits" and the answered rate is always on the stat row rather
  // than only when it drops.
  it("a spend-near-cap overview warns from the usage card and offers the cap editor", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            spend: { monthToDateUsd: 95, effectiveCapUsd: 100 },
            faultHitRate: 0.5,
          }),
          "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup(),
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).toContain("Halofy Assistant Billing &amp; Limits");
    expect(html).not.toContain("95% of shared cap");
    expect(html).toContain("alert threshold reached");
    expect(html).toContain('class="home-cap-ring home-cap-ring--warn"');
    expect(html).toContain('stroke-dasharray="95 100"');
    expect(html).toContain('data-action="home-cap-edit"');
    expect(html).not.toMatch(/\bpaus(?:e|ed)\b/i);
    // The hit rate is a permanent tile now, not a conditional warning row.
    expect(html).toContain("answered from memory");
  });

  it("renders a true empty ring when shared cap usage is zero", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            spend: { monthToDateUsd: 0, effectiveCapUsd: 100 },
          }),
          "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup(),
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).toContain('aria-valuenow="0"');
    expect(html).toContain('<strong class="num">0%</strong><span>Cap Used</span>');
    expect(html).not.toContain('class="home-cap-ring-fill"');
  });

  it("opens and closes the monthly cap right panel with focus restoration", async () => {
    const mod = await loadScreen("s2") as {
      actions: Record<string, (ctx: unknown, el: any) => void>;
    };
    let panelFocus = 0;
    let triggerFocus = 0;
    const attrs = new Map<string, string>();
    const panelAttrs = new Map<string, string>();
    const focusTarget = { focus() { panelFocus += 1; } };
    const classNames = new Set<string>();
    const doc = {
      body: {
        classList: {
          add(value: string) { classNames.add(value); },
          remove(value: string) { classNames.delete(value); },
        },
      },
      addEventListener() {},
      removeEventListener() {},
      querySelector() { return null; },
    };
    const panel = {
      hidden: true,
      ownerDocument: doc,
      setAttribute(name: string, value: string) { panelAttrs.set(name, value); },
      querySelector(selector: string) {
        return selector === "[data-right-panel-focus], input, select, textarea, button" ? focusTarget : null;
      },
    };
    const trigger = {
      closest(selector: string) { return selector === ".home-overview" ? root : null; },
      setAttribute(name: string, value: string) { attrs.set(name, value); },
      focus() { triggerFocus += 1; },
    };
    const root = {
      querySelector(selector: string) {
        return selector === "#home-cap-panel" ? panel : null;
      },
    };

    vi.stubGlobal("document", doc);
    try {
      mod.actions["home-cap-edit"]({}, trigger);
      expect(panel.hidden).toBe(false);
      expect(panelAttrs.get("aria-hidden")).toBe("false");
      expect(attrs.get("aria-expanded")).toBe("true");
      expect(classNames.has("source-modal-open")).toBe(true);
      expect(panelFocus).toBe(1);

      mod.actions["home-cap-close"]({}, {});
      expect(panel.hidden).toBe(true);
      expect(panelAttrs.get("aria-hidden")).toBe("true");
      expect(attrs.get("aria-expanded")).toBe("false");
      expect(classNames.has("source-modal-open")).toBe(false);
      expect(triggerFocus).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("a cap breach says memory stays available while paid AI falls back", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            spend: { monthToDateUsd: 140, effectiveCapUsd: 100 },
          }),
          "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup(),
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).not.toContain("pill--crit");
    expect(html).toContain('class="home-cap-ring home-cap-ring--crit"');
    expect(html).toContain("Shared paid-AI cap reached. Paid Halofy AI features fall back at the limit; memory stays available.");
  });

  it("renders unavailable rather than a partial Assistant billing total", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({ routes: { get: {
      "/v1/admin/overview": overview(),
      "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup({
        totals: {
          turns: 8,
          inputTokens: 200,
          outputTokens: 100,
          totalUsd: null,
          unavailableCostTurns: 2,
        },
      }),
    } } });

    const html = await s2.render(ctx);
    expect(html).toContain("Unavailable");
    expect(html).toContain("2 Assistant turns are missing prices");
    expect(html).not.toContain("$0.00 Halofy Assistant spend");
  });

  it("shows the priced floor plus the shortfall when only some turns priced", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({ routes: { get: {
      "/v1/admin/overview": overview(),
      "/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp": assistantMonthRollup({
        totals: {
          turns: 26,
          inputTokens: 50762,
          outputTokens: 1349,
          totalUsd: null,
          pricedUsd: 12.4,
          pricedTurns: 18,
          unavailableCostTurns: 8,
        },
      }),
    } } });

    const html = await s2.render(ctx);
    // 18 priced turns are real money the reader can act on. Blanking the whole
    // card because 8 models lack a catalog price reads as an outage.
    expect(html).toContain("$12.40 so far");
    expect(html).toContain("18 of 26 Assistant turns priced");
    expect(html).toContain("8 have no catalog price");
    expect(html).not.toContain("8 Assistant turns are missing prices");
  });

  it("filters the merged Top Memory Queries card using real agent badges", async () => {
    const s2 = await loadScreen("s2");
    const rows = [
      { name: "ana", count: 40 },
      { name: "ben", count: 30 },
      { name: "cara", count: 20 },
      { name: "codex-bot", count: 10 },
    ];
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({ topActors: rows, topTeams: rows }),
          "/v1/admin/people": {
            users: [
              { id: "u1", email: "a@acme.test", namespace: "acme", role: "owner", status: "active" },
              { id: "u2", email: "b@acme.test", namespace: "acme", role: "member", status: "active" },
              { id: "u3", email: "c@acme.test", namespace: "acme", role: "member", status: "revoked" },
            ],
            badges: [
              {
                id: "k1",
                namespace: "acme",
                actor: "codex-bot",
                role: "agent",
                status: "active",
                description: "codex",
                createdAt: "2026-01-01T00:00:00.000Z",
                lastUsed: null,
              },
            ],
          },
        },
      },
    });
    const mod = s2 as unknown as {
      render(c: unknown): Promise<string>;
      actions: Record<string, (c: unknown, el: unknown) => Promise<void>>;
    };

    let html = await mod.render(ctx);
    // Seats counts non-revoked humans only, and the filter uses the
    // server-proven agent badge rather than guessing from actor names.
    expect(html).toContain("Seats");
    expect(html).toContain("users across the org");
    expect(html).toContain("1–3 of 3 people");
    expect(html).toContain('data-action="home-query-filter"');
    expect(html).not.toContain("codex-bot");

    const el = (attrs: Record<string, string>) => ({
      getAttribute: (n: string) => attrs[n] ?? null,
    });
    await mod.actions["home-query-filter"](ctx, el({ "data-filter": "agents" }));
    html = await mod.render(ctx);
    expect(html).toContain("codex-bot");
    expect(html).toContain('class="tag">codex</span>');
    expect(html).toContain("1 of 1 agent");

    // Teams share the same card and pager.
    await mod.actions["home-query-filter"](ctx, el({ "data-filter": "teams" }));
    await mod.actions["home-page"](ctx, el({ "data-list": "queries", "data-dir": "1" }));
    html = await mod.render(ctx);
    expect(html).toContain("4 of 4 teams");
    await mod.actions["home-page"](ctx, el({ "data-list": "queries", "data-dir": "-1" }));
    html = await mod.render(ctx);
    expect(html).toContain("1–3 of 4 teams");
  });

  it("without the people directory Home drops Seats and never guesses at agents", async () => {
    const s2 = await loadScreen("s2");
    const { ctx, calls } = makeCtx({
      role: "member",
      routes: { get: { "/v1/admin/overview": overview() } },
    });
    const html = await s2.render(ctx);
    expect(html).not.toContain("users across the org");
    expect(html).not.toContain('data-filter="agents"');
    expect(html).toContain("Top Memory Queries");
    expect(html).toContain("agent:triage");
    expect(calls.map((call) => call.path)).not.toContain("/v1/admin/people");
    expect(calls.map((call) => call.path)).not.toContain("/v1/admin/readiness");
    expect(calls.map((call) => call.path)).not.toContain("/v1/admin/usage");
  });

  it("reuses the boot directory on the initial Home render", async () => {
    const s2 = await loadScreen("s2");
    const { ctx, calls } = makeCtx({
      routes: { get: { "/v1/admin/overview": overview() } },
    });
    (ctx as typeof ctx & { initialPeopleDirectoryRequest: Promise<unknown> })
      .initialPeopleDirectoryRequest = Promise.resolve({
        users: [{ id: "u1", email: "owner@acme.test", role: "owner", status: "active" }],
        badges: [],
      });

    const html = await s2.render(ctx);

    expect(html).toContain("users across the org");
    expect(calls.map((call) => call.path)).not.toContain("/v1/admin/people");
  });

  it("does not keep Access Safety content after Memory Writes replaces it", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": overview({
            agentAccess: {
              totalAgents: 3,
              withinPolicy: 1,
              overreaching: [
                { actor: XSS, denied: 7 },
                { actor: "agent:scraper", denied: 2 },
              ],
              accessEvents: { allowed: 8, denied: 9, error: 1 },
              accessRequests: { pending: 2, approved: 1, denied: 1, expired: 0, consumed: 0 },
            },
          }),
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).toContain("Memory Writes");
    expect(html).not.toContain("Access safety");
    expect(html).not.toContain("over-asking");
    expect(html).not.toContain("Review requests");
    expect(html).not.toContain(XSS);
  });

  it("an older server payload without the new aggregates still renders", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": {
            namespace: "acme",
            children: [{ namespace: "acme/support", l2Active: 7 }],
            l2Active: 42,
            faultCount: 10,
            faultHitRate: 0.6,
            spend: { monthToDateUsd: 90, effectiveCapUsd: 100 },
            assembledTokens: 123456,
          },
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).toContain("Everything, At A Glance");
    expect(html).toContain("42");
    expect(html).toContain("Assistant Spend");
  });

  it("the attention CTA buttons are live: a 'go' action navigates to data-screen", async () => {
    const s2 = await loadScreen("s2");
    const mod = s2 as unknown as {
      actions?: Record<string, (ctx: unknown, el: unknown) => void>;
    };
    // The dead-button bug: goBtn() emits data-action="go" but no "go" handler
    // existed, so clicking "Adjust caps"/"Open memory map" did nothing. The
    // screen MUST export a "go" action wired to the shell's delegated listener.
    expect(mod.actions).toBeDefined();
    expect(typeof mod.actions!.go).toBe("function");
    // It reads data-screen off the clicked element and calls ctx.go(screen).
    let navigated: string | null = null;
    const fakeCtx = { go: (s: string) => (navigated = s) };
    const fakeEl = { getAttribute: (n: string) => (n === "data-screen" ? "s4" : null) };
    mod.actions!.go(fakeCtx, fakeEl);
    expect(navigated).toBe("s4");
    // A button with no data-screen is a safe no-op (no throw, no navigation).
    navigated = null;
    mod.actions!.go(fakeCtx, { getAttribute: () => null });
    expect(navigated).toBeNull();
  });

  it("a fresh tenant keeps the redesigned Home structure with honest empty states", async () => {
    const s2 = await loadScreen("s2");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/overview": {
            namespace: "acme",
            children: [],
            l2Active: 0,
            faultCount: 0,
            faultHitRate: 0,
            spend: { monthToDateUsd: 0, effectiveCapUsd: null },
            assembledTokens: 0,
          },
        },
      },
    });
    const html = await s2.render(ctx);
    expect(html).toContain("Memory Writes");
    expect(html).toContain("Top Memory Queries");
    expect(html).toContain("No memory queries recorded yet.");
    expect(html).toContain("No memory writes recorded yet.");
  });
});

// ---------------------------------------------------------------------------
// S5 — Memory map
// ---------------------------------------------------------------------------

describe("s5 - memory map", () => {
  const map = () => ({
    namespace: "acme",
    pinned: ["refund policy"],
    governedPins: [],
    hottest: [{ id: "01J00000000000000000000000", content: XSS, accessCount: 9, pinnable: true }],
    repeatLookups: [{ query: XSS, count: 5 }],
    gaps: [{ query: "unanswered question", count: 3 }],
    topology: {
      scope: "selected-subtree",
      sources: [
        {
          id: "src-filesystem",
          namespace: "acme",
          kind: "filesystem",
          syncStatus: "synced",
          lastSync: "2026-07-16T12:00:00.000Z",
          lastSyncError: null,
          lifecycleState: "active",
        },
        {
          id: "src-postgres",
          namespace: "acme/support",
          kind: "postgres",
          syncStatus: "pending",
          lastSync: null,
          lastSyncError: null,
          lifecycleState: "active",
        },
      ],
      activeFacts: 128,
      activityFacts: 34,
      companyPublishedFacts: 0,
      memories: [
        {
          id: "01J00000000000000000000001",
          namespace: "acme",
          label: "Refunds close after 30 days",
          type: "fact",
          tier: "L2",
          accessCount: 9,
          state: "current",
          supersedes: "01J00000000000000000000002",
          sourceIds: ["src-filesystem"],
        },
        {
          id: "01J00000000000000000000002",
          namespace: "acme",
          label: "Refunds close after 14 days",
          type: "fact",
          tier: "L2",
          accessCount: 2,
          state: "older",
          supersedes: null,
          sourceIds: ["src-filesystem"],
        },
      ],
      knowledgeBases: [
        {
          id: "kb-support",
          namespace: "acme",
          name: "Support library",
          kind: "file",
          status: "ready",
          sourceId: "src-filesystem",
          files: [
            {
              id: "file-refunds",
              sourceId: "src-filesystem",
              name: "refunds.md",
              status: "ready",
              factCount: 18,
            },
          ],
        },
      ],
      skills: [
        {
          id: "skill-citations",
          namespace: "acme",
          key: "answer-with-citations",
          name: "Answer with citations",
          vettingStatus: "vetted",
          safetyScore: 96,
        },
      ],
      agents: [
        { id: "key-triage", namespace: "acme/support", actor: "agent:triage" },
      ],
      routing: { mode: "ab-test", a: "graph", b: "baseline", pctB: 20 },
    },
  });

  /**
   * The M10 role-scoped read model: GET /v1/memory-graph returns the
   * server-filtered view (title, authorized scopes, post-filter counts, and
   * the filtered topology the dot-node renderer draws). The client renders
   * exactly what came back — it never invents a scope or widens a fetch.
   */
  const graphView = (
    m?: { topology?: unknown },
    extra: Record<string, unknown> = {},
  ) => ({
    title: "Company memory",
    scopes: [],
    counts: { nodes: 12, edges: 14 },
    topology: m?.topology,
    ...extra,
  });

  // Saved memories now sit directly below the graph. The removed activity
  // rails and pin controls stay absent, with no second activity fetch.
  it("renders saved memories below the graph without restoring the activity rail", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain('class="memory-graph"');
    expect(html).toContain('class="saved-memories"');
    expect(html).toContain("Saved Memories");
    expect(html).not.toContain("Memory activity");
    expect(html).not.toContain("Asked again");
    expect(html).not.toContain("Needs attention");
    expect(html).not.toContain("Useful information");
    expect(html).not.toContain("Kept handy");
    expect(html).not.toContain("See what people ask, what needs an answer, and what information helps.");
    expect(html).not.toContain('data-action="pin-memory"');
    expect(html).not.toContain('data-action="unpin"');
    expect(s5.actions).not.toHaveProperty("pin");
    expect(s5.actions).not.toHaveProperty("pin-memory");
    expect(s5.actions).not.toHaveProperty("unpin");
    expect(calls.map((c) => c.path)).not.toContain("/v1/admin/gaps");
    // The hostile fixture text (lookup + hottest content) no longer reaches
    // the DOM at all now that the rail is gone.
    expect(html).not.toContain("<img");
  });

  it("renders a living selected-subtree memory graph with system-level relationships", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain('class="memory-graph"');
    expect(html).toContain('aria-label="Live memory network"');
    expect(html).not.toContain("<h2>Memory graph</h2>");
    expect(html).toContain("Backends");
    expect(html).toContain("Knowledge base");
    expect(html).toContain("Skills");
    expect(html).toContain("RAG / cache");
    expect(html).toContain("Agents");
    expect(html).toContain("filesystem");
    expect(html).toContain("postgres");
    expect(html).toContain("Common memories");
    expect(html).toContain("128 active, 34 used");
    expect(html).toContain("128");
    expect(html).toContain("34");
    expect(html).toContain("graph");
    expect(html).toContain("baseline");
    expect(html).toContain("20% B");
    expect(html).toContain("agent:triage");
    expect(html).toContain("Support library");
    expect(html).toContain("refunds.md");
    expect(html).toContain("Answer with citations");
    expect(html).toContain("Pinned knowledge");
    expect(html).toContain("1 pinned ref");
    expect(html).toContain("Flow online");
    expect(html).toContain("Synced");
    expect(html).toContain("Syncing");
    expect(html).toContain('class="memory-graph-viewport" data-action="topo-clear"');
    expect(html).not.toContain('id="memory-graph-drag-help"');
    expect(html).toContain('class="memory-graph-links"');
    expect(html).toContain('class="memory-graph-edge');
    expect(html).toContain('<svg class="memory-graph-links" aria-hidden="true"');
    expect(html).toContain('data-pointer-action="topo-drag"');
    expect(html).not.toContain('aria-describedby="memory-graph-drag-help"');
    expect(html).toContain('data-action="topo-filter"');
    expect(html).toContain('data-kind="backend"');
    expect(html).toContain('data-kind="knowledge"');
    expect(html).toContain('data-kind="skill"');
    expect(html).toContain('data-kind="retrieval"');
    expect(html).toContain('data-kind="agent"');
    // Provenance and supersedence edges name their real endpoints.
    expect(html).toContain('data-action="topo-focus"');
    expect(html).toContain('data-node-id="core:governed"');
    expect(html).toContain('data-node-id="g:backends"');
    expect(html).toContain('data-node-id="g:knowledge"');
    expect(html).toContain('data-node-id="g:skills"');
    expect(html).toContain('data-node-id="g:rag"');
    expect(html).toContain('data-node-id="g:agents"');
    expect(html).toContain('data-node-id="b:src-filesystem"');
    expect(html).toContain('data-node-id="kb:kb-support"');
    expect(html).toContain('data-node-id="f:file-refunds"');
    expect(html).toContain('data-node-id="s:skill-citations"');
    expect(html).toContain('data-node-id="mem:common"');
    expect(html).toContain('data-node-id="mem:pinned"');
    for (const tier of ["L0", "L1", "L2", "L3"]) {
      expect(html).toContain(`data-tier="${tier}"`);
    }
    expect(html).toContain('data-from="core:governed" data-to="g:backends"');
    expect(html).toContain('data-from="core:governed" data-to="g:knowledge"');
    expect(html).toContain('data-from="core:governed" data-to="g:skills"');
    expect(html).toContain('data-from="core:governed" data-to="g:rag"');
    // Edge endpoints are derived from the nodes' final relaxed positions, so
    // they must agree with what the nodes actually render at - a stale
    // hard-coded pair would draw ribbons that miss their own dots.
    const nodePoint = (id: string) => {
      const match = html.match(new RegExp(
        `data-node-id="${id}"[^>]*style="--x:([0-9.]+)%;--y:([0-9.]+)%`,
      ));
      expect(match, `missing node ${id}`).not.toBeNull();
      return { x: Number(match?.[1]), y: Number(match?.[2]) };
    };
    const hub = nodePoint("core:governed");
    const rag = nodePoint("g:rag");
    const round = (value: number) => Math.round(value * 10) / 10;
    const unitX = GRAPH_VIEW_WIDTH / 100;
    const unitY = GRAPH_VIEW_HEIGHT / 100;
    expect(html).toContain(
      `data-x1="${round(hub.x * unitX)}" data-y1="${round(hub.y * unitY)}" data-x2="${round(rag.x * unitX)}" data-y2="${round(rag.y * unitY)}"`,
    );
    expect(html).toContain('data-bend-direction="1"');
    expect(html).toContain('data-from="g:rag" data-to="g:agents"');
    expect(html).toContain('data-from="g:knowledge" data-to="kb:kb-support"');
    expect(html).toContain('data-from="kb:kb-support" data-to="f:file-refunds"');
    expect(html).toContain('data-from="b:src-filesystem" data-to="kb:kb-support"');
    expect(html).toContain('data-from="g:skills" data-to="s:skill-citations"');
    expect(html).toContain('data-from="t:L2" data-to="mem:common"');
    expect(html).toContain('data-from="t:L3" data-to="mem:pinned"');
    // Individual memories are nodes in their lane's orbit: the current fact,
    // the older version it superseded (D7 - a visible relationship, never an
    // overwrite), and provenance back to the source that produced them.
    expect(html).toContain('data-node-id="m:01J00000000000000000000001"');
    expect(html).toContain('data-node-id="m:01J00000000000000000000002"');
    expect(html).toContain("Refunds close after 30 days");
    expect(html).toContain("Refunds close after 14 days");
    expect(html).toContain('data-from="t:L2" data-to="m:01J00000000000000000000001"');
    expect(html).toMatch(/data-from="m:01J00000000000000000000001" data-to="m:01J00000000000000000000002"[^>]*data-relation="update"/);
    expect(html).toMatch(/data-from="b:src-filesystem" data-to="m:01J00000000000000000000001"[^>]*data-relation="provenance"/);
    expect(html).toContain('data-node-id="a:key-triage"');
    expect(html).toContain(">80%<");
    expect(html).toContain(">20%<");
    expect(s5.actions).toHaveProperty("topo-focus");
    expect(s5.actions).toHaveProperty("topo-filter");
    expect(s5.actions).toHaveProperty("topo-drag");
    expect(html).not.toContain("memory-topology-stage");
    expect(html).not.toContain("memory-funnel");
    expect(html).not.toContain("Live memory routing topology");
    expect(calls).toEqual([
      { method: "GET", path: "/v1/admin/memory-map?namespace=acme" },
      { method: "GET", path: "/v1/memory-graph" },
    ]);
  });

  it("gives every graph node a concise plain-language tooltip on hover and keyboard focus", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });

    const html = await s5.render(ctx);
    const nodeCount = html.match(/class="memory-graph-node-hit"/g)?.length ?? 0;
    const describedNodeCount = html.match(
      /class="memory-graph-node-hit"[^>]*aria-describedby="memory-graph-tooltip-[^"]+"/g,
    )?.length ?? 0;
    const tooltipCount = html.match(/class="memory-graph-tooltip"[^>]*role="tooltip"/g)?.length ?? 0;

    expect(nodeCount).toBeGreaterThan(0);
    expect(describedNodeCount).toBe(nodeCount);
    expect(tooltipCount).toBe(nodeCount);
    expect(html).toMatch(/id="memory-graph-tooltip-b-src-filesystem-[a-z0-9]+"/);
    expect(html).toContain("Filesystem");
    // Node copy is a short literal line, not an explanatory paragraph: the
    // inspector already carries the type, the space, and the link counts.
    expect(html).toContain("A connected system and the files it syncs into this space.");
    expect(html).toContain("Acme space");
    expect(html).toContain("Updated Jul 16, 2026");
  });

  it("keeps tooltip relationships unique when different node ids normalize to the same readable text", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const seedSkill = response.topology.skills[0];
    response.topology.skills = [
      { ...seedSkill, id: "x:y", key: "colon", name: "Colon skill" },
      { ...seedSkill, id: "x-y", key: "dash", name: "Dash skill" },
    ];
    const { ctx } = makeCtx({
      routes: { get: {
        "/v1/admin/memory-map?namespace=acme": response,
        "/v1/memory-graph": graphView(response),
      } },
    });

    const html = await s5.render(ctx);
    const ids = Array.from(html.matchAll(/id="(memory-graph-tooltip-s-x-y-[a-z0-9]+)"/g), (match) => match[1]);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
    for (const id of ids) expect(html).toContain(`aria-describedby="${id}"`);
  });

  it("keeps the default legend until selection and ships bounded safe data for one reusable inspector", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.topology.policies = [{
      id: "retention",
      namespace: "acme",
      title: "Retention",
      enforcement: "required",
      status: "active",
      factCount: 1,
      inherited: false,
    }];
    const seedSkill = response.topology.skills[0];
    response.topology.skills = Array.from({ length: 8 }, (_, index) => ({
      ...seedSkill,
      id: `skill-${index + 1}`,
      key: `skill-${index + 1}`,
      name: `Skill ${index + 1}`,
    }));
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });

    const html = await s5.render(ctx);
    const overview = html.match(
      /<div[^>]*data-graph-panel="overview"[^>]*>[\s\S]*?<\/div>\s*<section/,
    )?.[0] ?? "";
    const panelPayload = html.match(
      /<script type="application\/json" data-graph-panel-data>([\s\S]*?)<\/script>/,
    )?.[1] ?? "";
    const panelData = JSON.parse(panelPayload) as Record<string, {
      label: string;
      space: string;
      summary: string;
      search: string;
      updated: { iso: string | null; long: string };
      childCount: number;
      children: { label: string }[];
      remaining: number;
      degree: { in: number; out: number };
      incoming: { id: string; relation: string }[];
      outgoing: { id: string; relation: string }[];
    }>;

    expect(overview).not.toBe("");
    expect(overview).not.toMatch(/\shidden(?:\s|>)/);
    expect(overview).toContain("Active guardrails");
    expect(overview).toContain("Connected backends");
    expect(overview).toContain("Cold knowledge");

    expect(html.match(/data-graph-panel="/g) ?? []).toHaveLength(2);
    expect(html).toContain('data-graph-panel="details" hidden');
    expect(panelData["b:src-filesystem"]).toMatchObject({
      label: "Filesystem",
      space: "acme",
      summary: "A connected system and the files it syncs into this space.",
      updated: { iso: "2026-07-16T12:00:00.000Z", long: "Jul 16, 2026" },
      childCount: 0,
      children: [],
    });
    // The inspector lists real links, not only nested children, and search
    // reads the same payload — so it can never surface an unauthorized node.
    expect(panelData["b:src-filesystem"].degree.in).toBeGreaterThan(0);
    expect(panelData["b:src-filesystem"].incoming[0]).toMatchObject({
      id: "g:backends",
      relation: "branch",
    });
    expect(panelData["b:src-filesystem"].search).toContain("filesystem");
    expect(panelData["g:skills"].outgoing.length).toBeLessThanOrEqual(6);

    expect(panelData["g:skills"].childCount).toBe(8);
    expect(panelData["g:skills"].children).toHaveLength(5);
    expect(panelData["g:skills"].remaining).toBe(3);
    for (let index = 1; index <= 5; index += 1) {
      expect(panelData["g:skills"].children[index - 1]?.label).toBe(`Skill ${index}`);
    }
    expect(panelData["g:skills"].children.some((child) => child.label === "Skill 6")).toBe(false);
    expect(panelData["g:policies"].childCount).toBe(1);
    expect(panelData["g:policies"].children.map((child) => child.label)).toEqual(["Retention"]);
  });

  it("switches the legend to node details for pointer or keyboard selection and restores it on deselection", async () => {
    const s5 = await loadScreen("s5") as {
      actions: Record<string, (ctx: unknown, el: unknown, event?: unknown) => void>;
    };
    const classes = () => ({ toggle() {} });
    const overview = {
      hidden: false,
      getAttribute(name: string) {
        return name === "data-graph-panel" ? "overview" : null;
      },
    };
    const detailsAttrs = new Map<string, string>([["data-graph-panel", "details"]]);
    const textTarget = () => ({
      textContent: "",
      hidden: false,
      setAttribute() {},
      removeAttribute() {},
    });
    const panelTargets = new Map([
      ["[data-node-type]", textTarget()],
      ["[data-node-title]", textTarget()],
      ["[data-node-detail]", textTarget()],
      ["[data-node-summary]", textTarget()],
      ["[data-node-space]", textTarget()],
      ["[data-node-updated]", textTarget()],
      ["[data-node-connections]", textTarget()],
      ["[data-node-empty]", textTarget()],
      ["[data-node-more]", textTarget()],
    ]);
    const details = {
      hidden: true,
      getAttribute(name: string) {
        return detailsAttrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        detailsAttrs.set(name, value);
      },
      removeAttribute(name: string) {
        detailsAttrs.delete(name);
      },
      querySelector(selector: string) {
        return panelTargets.get(selector) ?? null;
      },
    };
    const panels = [overview, details];
    let backFocusCount = 0;
    const panelPayload = {
      textContent: JSON.stringify({
        "b:src-filesystem": { label: "Filesystem", type: "Connected source", detail: "Synced source", summary: "Source summary", space: "acme", updated: { iso: "2026-07-16T12:00:00.000Z", long: "Jul 16, 2026" }, childCount: 0, children: [], remaining: 0 },
        "g:skills": { label: "Skills", type: "Graph group", detail: "8 connected", summary: "Skills summary", space: "All accessible spaces", updated: { iso: null, long: "Not available" }, childCount: 8, children: [], remaining: 3 },
      }),
    };
    const wrap = {
      querySelectorAll(selector: string) {
        return selector === "[data-graph-panel]" ? panels : [];
      },
      querySelector(selector: string) {
        if (selector === "[data-graph-panel-data]") return panelPayload;
        if (selector === '[data-action="topo-panel-clear"]') return { focus() { backFocusCount += 1; } };
        return null;
      },
    };
    const attrs = new Map<string, string>([
      ["data-node-id", "b:src-filesystem"],
      ["aria-pressed", "false"],
    ]);
    const selectedHit = {
      classList: classes(),
      getAttribute(name: string) {
        return attrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        attrs.set(name, value);
      },
      closest(selector: string) {
        return selector === ".memory-graph-viewport" ? viewport : null;
      },
    };
    const skillAttrs = new Map<string, string>([
      ["data-node-id", "g:skills"],
      ["aria-expanded", "false"],
      ["data-expand-label", "Expand Skills"],
      ["data-collapse-label", "Collapse Skills"],
    ]);
    const skillToggle = {
      classList: classes(),
      getAttribute(name: string) {
        return skillAttrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        skillAttrs.set(name, value);
      },
      closest(selector: string) {
        return selector === ".memory-graph-viewport" ? viewport : null;
      },
    };
    const viewportAttrs = new Map<string, string>();
    const viewport = {
      getAttribute(name: string) {
        return viewportAttrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        viewportAttrs.set(name, value);
      },
      removeAttribute(name: string) {
        viewportAttrs.delete(name);
      },
      closest(selector: string) {
        return selector === ".memory-graph-wrap" ? wrap : null;
      },
      querySelectorAll(selector: string) {
        if (selector === ".memory-graph-node-hit") return [selectedHit, skillToggle];
        return [];
      },
    };

    // Native buttons generate detail=0 clicks for Enter/Space, so the same
    // action must serve keyboard and pointer selection without a second path.
    s5.actions["topo-focus"]({}, selectedHit, { detail: 0 });
    expect(overview.hidden).toBe(true);
    expect(details.hidden).toBe(false);
    expect(detailsAttrs.get("data-selected-node")).toBe("b:src-filesystem");
    expect(backFocusCount).toBe(1);

    s5.actions["topo-clear"]({}, viewport);
    expect(overview.hidden).toBe(false);
    expect(details.hidden).toBe(true);

    // Expandable group nodes use topo-toggle, but selection must still open
    // the same inspector after their child disclosure state changes.
    s5.actions["topo-toggle"]({}, skillToggle, { detail: 0 });
    expect(overview.hidden).toBe(true);
    expect(details.hidden).toBe(false);
    expect(detailsAttrs.get("data-selected-node")).toBe("g:skills");
    expect(backFocusCount).toBe(2);

    s5.actions["topo-toggle"]({}, skillToggle, { detail: 0 });
    expect(overview.hidden).toBe(false);
    expect(details.hidden).toBe(true);

    // A branch can be reselected after another node without getting stuck:
    // collapse/reselect, then activate again to return to the overview.
    s5.actions["topo-toggle"]({}, skillToggle, { detail: 1 });
    s5.actions["topo-focus"]({}, selectedHit, { detail: 1 });
    s5.actions["topo-toggle"]({}, skillToggle, { detail: 1 });
    expect(detailsAttrs.get("data-selected-node")).toBe("g:skills");
    expect(skillAttrs.get("aria-expanded")).toBe("false");
    s5.actions["topo-toggle"]({}, skillToggle, { detail: 1 });
    expect(overview.hidden).toBe(false);
    expect(details.hidden).toBe(true);
    expect(viewportAttrs.has("data-focus")).toBe(false);
  });

  it("collapses graph branches after five direct children and exposes an accessible toggle", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const seedSkill = response.topology.skills[0];
    response.topology.skills = Array.from({ length: 8 }, (_, index) => ({
      ...seedSkill,
      id: `skill-${index + 1}`,
      key: `skill-${index + 1}`,
      name: `Skill ${index + 1}`,
    }));
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });

    const html = await s5.render(ctx);

    expect(html).toContain(
      'data-action="topo-toggle" data-node-id="g:skills" aria-expanded="false"',
    );
    expect(html).toContain(
      'class="memory-graph-node memory-graph-node--branch memory-graph-node--expandable"',
    );
    expect(html).toContain('aria-label="Expand Skills. Show 3 more connections"');
    expect(html).toContain('class="memory-graph-expand-icon"');
    expect(html).toMatch(
      /class="memory-graph-node memory-graph-node--skill"[^>]*data-node-id="s:skill-5"/,
    );
    expect(html).toMatch(
      /class="memory-graph-node memory-graph-node--skill is-collapsed"[^>]*data-node-id="s:skill-6"[^>]*data-collapse-parents="g:skills"/,
    );
    expect(html).toContain(
      'data-from="g:skills" data-to="s:skill-6" data-from-kind="skill" data-to-kind="skill" data-relation="branch" data-collapse-parents="g:skills"',
    );
    expect(s5.actions).toHaveProperty("topo-toggle");
  });

  it("expands and collapses an overflowing graph branch from the parent node", async () => {
    const s5 = await loadScreen("s5") as {
      actions: Record<string, (ctx: unknown, el: unknown) => void>;
    };
    const classes = (initial: string[] = []) => {
      const names = new Set(initial);
      return {
        names,
        toggle(name: string, force: boolean) {
          if (force) names.add(name);
          else names.delete(name);
        },
      };
    };
    const childClasses = classes(["is-collapsed"]);
    const edgeClasses = classes(["is-collapsed"]);
    const child = {
      classList: childClasses,
      getAttribute(name: string) {
        return name === "data-collapse-parents" ? "g:skills" : null;
      },
    };
    const edge = {
      classList: edgeClasses,
      getAttribute(name: string) {
        return name === "data-collapse-parents" ? "g:skills" : null;
      },
    };
    const viewportAttrs = new Map<string, string>();
    const viewport = {
      getAttribute(name: string) {
        return viewportAttrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        viewportAttrs.set(name, value);
      },
      removeAttribute(name: string) {
        viewportAttrs.delete(name);
      },
      querySelectorAll(selector: string) {
        if (selector === "[data-collapse-parents]") return [child, edge];
        if (selector === ".memory-graph-edge") return [];
        if (selector === ".memory-graph-node-hit") return [];
        return [];
      },
    };
    const attrs = new Map<string, string>([
      ["data-node-id", "g:skills"],
      ["aria-expanded", "false"],
      ["data-expand-label", "Expand Skills. Show 3 more connections"],
      ["data-collapse-label", "Collapse Skills. Hide 3 connections"],
    ]);
    const toggle = {
      getAttribute(name: string) {
        return attrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        attrs.set(name, value);
      },
      closest(selector: string) {
        return selector === ".memory-graph-viewport" ? viewport : null;
      },
    };

    s5.actions["topo-toggle"]({}, toggle);
    expect(attrs.get("aria-expanded")).toBe("true");
    expect(attrs.get("aria-label")).toBe("Collapse Skills. Hide 3 connections");
    expect(viewportAttrs.get("data-expanded")).toBe("g:skills");
    expect(childClasses.names.has("is-collapsed")).toBe(false);
    expect(edgeClasses.names.has("is-collapsed")).toBe(false);

    s5.actions["topo-toggle"]({}, toggle);
    expect(attrs.get("aria-expanded")).toBe("false");
    expect(attrs.get("aria-label")).toBe("Expand Skills. Show 3 more connections");
    expect(viewportAttrs.has("data-expanded")).toBe(false);
    expect(childClasses.names.has("is-collapsed")).toBe(true);
    expect(edgeClasses.names.has("is-collapsed")).toBe(true);
  });

  it("restores the full graph when empty viewport space is selected", async () => {
    const s5 = await loadScreen("s5") as {
      actions: Record<string, (ctx: unknown, el: unknown) => void>;
    };
    const classes = () => {
      const names = new Set<string>();
      return {
        names,
        toggle(name: string, force: boolean) {
          if (force) names.add(name);
          else names.delete(name);
        },
      };
    };
    const edgeClasses = classes();
    const edge = {
      getAttribute(name: string) {
        if (name === "data-from") return "core:governed";
        if (name === "data-to") return "g:backends";
        return null;
      },
      classList: edgeClasses,
    };
    const hit = (id: string) => {
      const attrs = new Map<string, string>([
        ["data-node-id", id],
        ["aria-pressed", "false"],
      ]);
      return {
        attrs,
        classList: classes(),
        getAttribute(name: string) {
          return attrs.get(name) ?? null;
        },
        setAttribute(name: string, value: string) {
          attrs.set(name, value);
        },
      };
    };
    const core = hit("core:governed");
    const backend = hit("g:backends");
    const unrelated = hit("g:knowledge");
    const viewportAttrs = new Map<string, string>();
    const viewport = {
      getAttribute(name: string) {
        return viewportAttrs.get(name) ?? null;
      },
      setAttribute(name: string, value: string) {
        viewportAttrs.set(name, value);
      },
      removeAttribute(name: string) {
        viewportAttrs.delete(name);
      },
      querySelectorAll(selector: string) {
        if (selector === ".memory-graph-edge") return [edge];
        if (selector === ".memory-graph-node-hit") return [core, backend, unrelated];
        return [];
      },
    };
    const node = {
      ...core,
      closest(selector: string) {
        return selector === ".memory-graph-viewport" ? viewport : null;
      },
    };

    s5.actions["topo-focus"]({}, node);
    expect(viewportAttrs.get("data-focus")).toBe("core:governed");
    expect(edgeClasses.names.has("is-on")).toBe(true);
    expect(core.attrs.get("aria-pressed")).toBe("true");
    expect(backend.classList.names.has("is-on")).toBe(true);
    expect(unrelated.classList.names.has("is-on")).toBe(false);

    s5.actions["topo-clear"]({}, viewport);
    expect(viewportAttrs.has("data-focus")).toBe(false);
    expect(edgeClasses.names.has("is-on")).toBe(false);
    for (const graphNode of [core, backend, unrelated]) {
      expect(graphNode.classList.names.has("is-on")).toBe(false);
      expect(graphNode.attrs.get("aria-pressed")).toBe("false");
    }
  });

  it("renders company-published memory as an aggregate lane only", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.topology.companyPublishedFacts = 7;
    // M10: S5 renders the graph from /v1/memory-graph — mirror the sibling
    // fixtures and serve the same topology through graphView.
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });

    const html = await s5.render(ctx);
    expect(html).toContain('data-node-id="mem:company-published"');
    expect(html).toContain("Company-published");
    expect(html).toContain("7 shared items");
    expect(html).not.toContain("Publishing team");
  });


  it("escapes source and routing labels inside the topology", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.topology.sources[0].kind = XSS;
    response.topology.sources[0].id = XSS;
    response.topology.routing = {
      mode: "ab-test",
      a: XSS,
      b: "baseline",
      pctB: 20,
    };
    response.topology.memories[0].label = XSS;
    response.topology.knowledgeBases[0].name = XSS;
    response.topology.knowledgeBases[0].files[0].name = XSS;
    response.topology.skills[0].name = XSS;
    response.topology.agents[0].actor = XSS;
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, { title: XSS }),
        },
      },
    });
    const html = await s5.render(ctx);
    assertNoRawImg(html);
    expect(html).not.toContain('data-node-id="b:<img');
    expect(html).not.toContain('data-from="b:<img');
  });

  it("describes a single backend correctly without claiming an observed route edge", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.topology.sources = response.topology.sources.slice(0, 1);
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("Team topology connects 1 backend");
    expect(html).toContain("Effective memory access includes 0 company-published items");
    expect(html).toContain("Publishing-team systems and files stay hidden");
    expect(html).not.toContain("1 backend feeds");
    expect(html).not.toContain("1 backends feed");
  });

  it("reports source attention in visible text instead of color alone", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.topology.sources = [
      {
        id: "src-disabled",
        namespace: "acme",
        kind: "filesystem",
        syncStatus: "never_synced",
        lastSync: null,
        lastSyncError: null,
        lifecycleState: "disabled",
      },
      {
        id: "src-failed",
        namespace: "acme",
        kind: "postgres",
        syncStatus: "failed",
        lastSync: null,
        lastSyncError: "provider unavailable",
        lifecycleState: "active",
      },
    ];
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("Source attention");
    expect(html).toContain(">Disabled<");
    expect(html).toContain(">Attention<");
    expect(html).not.toContain("Flow online");
  });

  it("browns out when topology is absent or incomplete instead of inventing zeroes", async () => {
    const s5 = await loadScreen("s5");
    const absent = map();
    delete (absent as { topology?: unknown }).topology;
    const absentCtx = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": absent,
          "/v1/memory-graph": graphView(absent),
        },
      },
    });
    const absentHtml = await s5.render(absentCtx.ctx);
    expect(absentHtml).toContain("Topology unavailable");
    expect(absentHtml).not.toContain("0 connected");
    expect(absentHtml).not.toContain("Fixed baseline retrieval");

    const incomplete = map();
    delete (incomplete.topology as { routing?: unknown }).routing;
    const incompleteCtx = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": incomplete,
          "/v1/memory-graph": graphView(incomplete),
        },
      },
    });
    expect(await s5.render(incompleteCtx.ctx)).toContain("Topology unavailable");

    const partialSource = map();
    partialSource.topology.sources = [{}] as typeof partialSource.topology.sources;
    const partialSourceCtx = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": partialSource,
          "/v1/memory-graph": graphView(partialSource),
        },
      },
    });
    const partialSourceHtml = await s5.render(partialSourceCtx.ctx);
    expect(partialSourceHtml).toContain("Topology unavailable");
    expect(partialSourceHtml).not.toContain("Organization root");

    const blankRoute = map();
    blankRoute.topology.routing = {
      mode: "fixed",
      name: "",
    } as typeof blankRoute.topology.routing;
    const blankRouteCtx = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": blankRoute,
          "/v1/memory-graph": graphView(blankRoute),
        },
      },
    });
    const blankRouteHtml = await s5.render(blankRouteCtx.ctx);
    expect(blankRouteHtml).toContain("Topology unavailable");
    expect(blankRouteHtml).not.toContain("Fixed baseline retrieval");
  });

  it("ships responsive graph styles and disables its motion when requested", async () => {
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );
    const screenSource = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/screens/s5.js", import.meta.url)), "utf8"),
    );
    expect(css).toContain(".memory-graph");
    expect(css).toContain(".memory-graph-edge");
    expect(css).toContain(".memory-graph-source-state");
    expect(css).toContain(".memory-graph-unavailable");
    expect(css).toContain(".memory-graph-node--branch");
    expect(css).toContain(".memory-graph-node--tier");
    expect(css).toContain(".memory-graph-node--common-memory");
    expect(css).toContain(".memory-graph-node--pin-summary");
    expect(css).toContain(".memory-graph-expand-icon");
    // The disclosure control also has to win against a node it overlaps while
    // hovered or focused, so the raised stacking covers those states too.
    expect(css).toContain(
      ".memory-graph-node--expandable,.memory-graph-node--expandable:hover,.memory-graph-node--expandable:focus-within{z-index:13}",
    );
    expect(css).toContain(
      ".memory-graph-node.is-collapsed,.memory-graph-edge.is-collapsed",
    );
    expect(css).not.toContain(".memory-graph-node--memory-current");
    expect(css).not.toContain(".memory-graph-node--memory-older");
    expect(css).toContain(".memory-graph-node-hit{position:relative;display:grid;place-items:center;width:14px;height:14px");
    expect(css).toContain(".memory-graph-node-hit:hover .memory-graph-tooltip");
    expect(css).toContain("pointer-events:auto");
    expect(css).toContain("cursor:grab");
    expect(css).toContain("touch-action:none");
    expect(css).toContain(".memory-graph-node.is-dragging");
    const narrowGraphStart = css.indexOf("@media(max-width:720px){.memory-graph-head");
    const narrowGraphEnd = css.indexOf("@media(prefers-reduced-motion:reduce)", narrowGraphStart);
    const graphStyles = css.slice(
      css.indexOf("/* S5 memory topology"),
      css.indexOf("/* S7 knowledge review sync activity."),
    );
    expect(narrowGraphStart).toBeGreaterThan(-1);
    expect(narrowGraphEnd).toBeGreaterThan(narrowGraphStart);
    const narrowGraphStyles = css.slice(narrowGraphStart, narrowGraphEnd);
    expect(narrowGraphStyles).not.toMatch(/\.memory-graph-viewport\{[^}]*display:grid/);
    expect(narrowGraphStyles).not.toContain(".memory-graph-grid,.memory-graph-links{display:none}");
    expect(narrowGraphStyles).not.toContain(".memory-graph-node{position:static");
    expect(narrowGraphStyles).not.toContain("touch-action:manipulation");
    expect(graphStyles).not.toContain("min-width:156px");
    expect(graphStyles).not.toContain("min-width:112px");
    // Every chip the toolbar renders must be toggleable, policies included.
    expect(screenSource).toContain('["policy", "backend", "knowledge", "skill", "retrieval", "agent"]');
    expect(css).toContain("--memory-tier-l0:var(--gold)");
    expect(css).toContain("--memory-tier-l1:var(--sage)");
    expect(css).toContain("--memory-tier-l2:var(--olive)");
    expect(css).toContain("--memory-tier-l3:var(--slate)");
    expect(css).not.toContain(".memory-funnel");
    expect(css).not.toMatch(/\.memory-graph-shell\{[^}]*box-shadow:var\(--sh-3\)/);
    expect(css).toContain("@media(max-width:720px)");
    expect(css).toContain(".memory-graph-layout{grid-template-columns:1fr}");
    expect(css).toContain("vector-effect:non-scaling-stroke");
    expect(css).toMatch(/\.memory-graph-filter\{[^}]*min-height:36px[^}]*border-radius:var\(--r-sm\)/);
    expect(css).toMatch(/@media\(max-width:860px\)[\s\S]*?\.memory-graph-filter,[^}]*min-height:44px/);
    expect(css).toMatch(/\.memory-graph-stat\{[^}]*border:1px solid #e5e7eb[^}]*border-radius:var\(--r-sm\)[^}]*background:#f9fafb[^}]*box-shadow:0 1px 2px rgb\(16 24 40\/4%\)/s);
    expect(css).toContain("@media(max-width:960px)");
    expect(css).toMatch(
      /@media\(prefers-reduced-motion:reduce\)[\s\S]*\.memory-graph-edge[\s\S]*animation:none/,
    );
  });

  it("auditor sees the map read-only - NO Pin control", async () => {
    const s5 = await loadScreen("s5");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: { get: { "/v1/admin/memory-map?namespace=acme": map() } },
    });
    const html = await s5.render(ctx);
    expect(html).not.toContain('data-action="pin"');
    expect(html).not.toContain('data-action="pin-memory"');
    expect(html).not.toContain(">Pin<");
    expect(html).not.toContain("<img");
  });

  it("a fresh tenant renders an empty state", async () => {
    const s5 = await loadScreen("s5");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": {
            namespace: "acme",
            pinned: [],
            hottest: [],
            repeatLookups: [],
            gaps: [],
          },
          "/v1/memory-graph": graphView(),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("Topology unavailable");
    expect(html).not.toContain("No memory activity yet");
  });

  it("labels durable rows as controls without claiming stale targets are in context", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    response.pinned = [];
    response.governedPins = [{
      id: "01J00000000000000000000009",
      target: { kind: "memory", ref: "01J00000000000000000000008" },
    }];
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    // The pin rail is gone; the graph still summarizes durable rows as a
    // single node without claiming a stale target is in context.
    expect(html).toContain('data-node-id="mem:pinned"');
    expect(html).toContain("Pinned knowledge");
    expect(html).not.toContain("Kept handy");
    expect(html).not.toContain("Saved for quick access");
    expect(html).not.toContain('data-node-id="p:0"');
    expect(html).not.toContain("01J00000000000000000000008</b>");
    expect(html).not.toContain("Context ready");
    expect(html).not.toContain("always in context");
  });

  // -------------------------------------------------------------------------
  // M10 role-scoped memory graph: server title, authorized scopes only, root
  // View-as preview, read-only preview state, brownout, jargon-free copy.
  // -------------------------------------------------------------------------

  /** Minimal element stub for state-driven actions (no DOM in Node). */
  const fakeEl = (attrs: Record<string, string> = {}, value = "") => ({
    value,
    getAttribute: (name: string) => attrs[name] ?? null,
    setAttribute: () => {},
    closest: () => null,
  });

  it("member: server title renders, single scope hides the selector, no View as", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, {
            title: "Your memory",
            scopes: [{ id: "fn-marketing", label: "Marketing" }],
          }),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("<h1>Your memory</h1>");
    expect(html).not.toContain("data-space-picker");
    expect(html).not.toContain("View as");
    expect(html).not.toContain('data-action="viewas-open"');
    expect(html).not.toContain('data-action="pin-memory"');
  });

  it("admin: function title and a selector listing only server-authorized scopes", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "admin",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, {
            title: "Marketing memory",
            scopes: [
              { id: "fn-marketing", label: "Marketing" },
              { id: "fn-events", label: XSS },
            ],
          }),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("<h1>Marketing memory</h1>");
    expect(html).toContain("data-space-picker");
    // In the title row's action slot - a standalone row left an empty band
    // down the left of the page between the title and the graph.
    expect(html).toMatch(/class="acts"><div class="memory-scope"/);
    expect(html).toContain("All accessible<");
    expect(html).toContain("Marketing<");
    // Exactly the server-sent options plus the union default — never invented.
    expect((html.match(/data-action="scope-pick"/g) ?? []).length).toBe(3);
    expect(html).not.toContain("View as");
    assertNoRawImg(html); // hostile scope label is escaped
  });

  it("root: Company memory title with the View as control", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
        },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("<h1>Company memory</h1>");
    expect(html).toContain('data-action="viewas-open"');
    expect(html).toContain(">View as<");
  });

  it("scope narrowing refetches with the opaque server id only", async () => {
    const s5 = await loadScreen("s5") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: unknown, el?: unknown) => Promise<void> | void>;
    };
    const response = map();
    const scoped = {
      title: "Events memory",
      scopes: [
        { id: "fn-marketing", label: "Marketing" },
        { id: "fn-events", label: "Events" },
      ],
      counts: { nodes: 4, edges: 3 },
      topology: response.topology,
    };
    const { ctx, calls } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, { scopes: scoped.scopes }),
          "/v1/memory-graph?scope=fn-events": scoped,
        },
      },
    });
    try {
      await s5.actions["scope"](ctx, fakeEl({}, "fn-events"));
      const html = await s5.render(ctx);
      expect(calls.some((c) => c.path === "/v1/memory-graph?scope=fn-events")).toBe(true);
      expect(html).toContain("<h1>Events memory</h1>");
      expect(html).toContain('data-scope="fn-events" aria-selected="true"');
    } finally {
      await s5.actions["scope"](ctx, fakeEl({}, ""));
    }
  });

  it("graph brownout renders the fixed short line and never a broader fetch", async () => {
    const s5 = await loadScreen("s5");
    const { ctx, calls } = makeCtx({
      role: "member",
      routes: {
        get: { "/v1/admin/memory-map?namespace=acme": map() },
      },
    });
    const html = await s5.render(ctx);
    expect(html).toContain("Access view unavailable.");
    expect(html).not.toContain("Topology unavailable");
    expect(calls.map((c) => c.path)).toEqual([
      "/v1/admin/memory-map?namespace=acme",
      "/v1/memory-graph",
    ]);
  });

  it("platform operator (namespace '') keeps the memory-map topology when the access view fails closed", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "owner",
      namespace: "",
      routes: {
        get: { "/v1/admin/memory-map?namespace=": response },
      },
    });
    const html = await s5.render(ctx);
    // /v1/memory-graph 503s for the tenant-less platform owner by design;
    // the org-wide memory-map view is already server-authorized for it, so
    // the dot-node graph still renders instead of a dead end.
    expect(html).not.toContain("Access view unavailable.");
    expect(html).toContain("data-node-id=");
  });

  it("a revoked scope id recovers to the granted union instead of wedging the screen", async () => {
    const s5 = await loadScreen("s5") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: unknown, el?: unknown) => Promise<void> | void>;
    };
    const response = map();
    const { ctx, calls } = makeCtx({
      role: "admin",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, {
            scopes: [
              { id: "fn-marketing", label: "Marketing" },
              { id: "fn-events", label: "Events" },
            ],
          }),
          // NO route for scope=fn-gone: the server answers a revoked/foreign
          // scope with the uniform 404.
        },
      },
    });
    try {
      await s5.actions["scope"](ctx, fakeEl({}, "fn-gone"));
      const html = await s5.render(ctx);
      expect(calls.some((c) => c.path === "/v1/memory-graph?scope=fn-gone")).toBe(true);
      // One retry on the full granted union — the screen recovers with the
      // scope selector rendered again; no permanent "Access view unavailable."
      expect(html).not.toContain("Access view unavailable.");
      expect(html).toContain("data-space-picker");
    } finally {
      await s5.actions["scope"](ctx, fakeEl({}, ""));
    }
  });

  it("a dead preview credential exits the preview - never root's own graph under the banner", async () => {
    const s5 = await loadScreen("s5") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: unknown, el?: unknown) => Promise<void> | void>;
    };
    const response = map();
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/admin/gaps": { items: [], counts: { missing: 0, wrongOpen: 0, wrongResolved: 0 }, degraded: false },
          "/v1/memory-graph": graphView(response),
          "/v1/root/view-as/targets": {
            people: [{ id: "u-dana", name: "Dana Reyes", email: "dana@acme.test", role: "member" }],
            functions: [],
          },
        },
        post: {
          "/v1/root/view-as/sessions": {
            id: "pv-exp",
            token: "tok_expired_preview",
            subjectLabel: "Dana Reyes",
            scopeLabel: "Member",
          },
        },
        del: { "/v1/root/view-as/sessions/pv-exp": {} },
      },
    });
    try {
      await s5.actions["viewas-open"](ctx, fakeEl());
      s5.actions["viewas-pick-person"](ctx, fakeEl({ "data-user-id": "u-dana" }));
      s5.actions["viewas-reason"](ctx, fakeEl({}, "expiry check"));
      await s5.actions["viewas-start"](ctx, fakeEl());
      // The server 404s a presented-but-dead credential (D43/E6) instead of
      // silently answering with root's own view.
      const api = (ctx as {
        api: { get(path: string, opts?: { headers?: Record<string, string> }): Promise<unknown> };
      }).api;
      const realGet = api.get.bind(api);
      api.get = async (path, opts) => {
        if (opts?.headers?.["x-halomem-preview-token"]) {
          throw { status: 404, message: "not found" };
        }
        return realGet(path);
      };
      const html = await s5.render(ctx);
      expect(html).not.toContain("Viewing as");
      expect(html).toContain("Preview ended.");
      expect(html).toContain('data-action="viewas-open"');
    } finally {
      await s5.actions["viewas-exit"](ctx, fakeEl());
      await s5.actions["viewas-close"](ctx, fakeEl());
    }
  });

  it("an empty access view says nothing was shared - not that memory is missing", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(undefined, {
            title: "Your memory",
            counts: { nodes: 0, edges: 0 },
          }),
        },
      },
    });
    const html = await s5.render(ctx);
    // CONTRACTS-M10-ACCESS console-s5 row: the empty state says memory has
    // not been granted — never that the company graph is empty.
    expect(html).toContain("Nothing shared with you yet.");
    expect(html).not.toContain("No memory here yet.");
    expect(html).not.toContain("Topology unavailable");
    expect(html.toLowerCase()).not.toContain("company graph");
  });

  it("rendered S5 output never uses access jargon", async () => {
    const s5 = await loadScreen("s5");
    const response = map();
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response, {
            scopes: [
              { id: "fn-marketing", label: "Marketing" },
              { id: "fn-events", label: "Events" },
            ],
          }),
        },
      },
    });
    const html = (await s5.render(ctx)).toLowerCase();
    for (const word of ["projection", "entitlement", "authorization"]) {
      expect(html).not.toContain(word);
    }
  });

  it("root View as: person search + role/function picker, Start gated, read-only preview, exit restores", async () => {
    const s5 = await loadScreen("s5") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: unknown, el?: unknown) => Promise<void> | void>;
    };
    const response = map();
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/memory-map?namespace=acme": response,
          "/v1/memory-graph": graphView(response),
          "/v1/root/view-as/targets": {
            people: [
              { id: "u-dana", name: "Dana Reyes", email: "dana@acme.test" },
              { id: "u-xss", name: XSS, email: "xss@acme.test" },
            ],
            functions: [
              { id: "fn-marketing", label: "Marketing" },
              { id: "fn-events", label: "Events" },
            ],
          },
        },
        post: {
          "/v1/root/view-as/sessions": {
            id: "pv1",
            token: "tok_secret_preview",
            subjectLabel: "Admin",
            scopeLabel: "Marketing",
          },
        },
        del: { "/v1/root/view-as/sessions/pv1": {} },
      },
    });
    try {
      // Open the picker: person tab first, Start disabled, names escaped.
      await s5.actions["viewas-open"](ctx, fakeEl());
      let html = await s5.render(ctx);
      expect(html).toContain("data-viewas");
      expect(html).toContain('data-action="viewas-pick-person" data-user-id="u-dana"');
      expect(html).toContain("Dana Reyes");
      expect(html).toContain('data-input-action="viewas-search"');
      expect(html).toContain('data-input-action="viewas-reason"');
      expect(html).toContain('data-action="viewas-start" disabled');
      assertNoRawImg(html); // hostile person name escaped

      // Role tab: a bare role plus reason still cannot start (needs a function).
      s5.actions["viewas-tab"](ctx, fakeEl({ "data-tab": "role" }));
      s5.actions["viewas-role"](ctx, fakeEl({ "data-role": "admin" }));
      s5.actions["viewas-reason"](ctx, fakeEl({}, "Quarterly access review"));
      html = await s5.render(ctx);
      expect(html).toContain('data-action="viewas-start" disabled');
      const postsBefore = calls.filter((c) => c.method === "POST").length;
      await s5.actions["viewas-start"](ctx, fakeEl());
      expect(calls.filter((c) => c.method === "POST").length).toBe(postsBefore);

      // Adding a function makes it valid; Start posts exactly the picked ids.
      s5.actions["viewas-func"](ctx, fakeEl({ "data-func-id": "fn-marketing" }));
      html = await s5.render(ctx);
      expect(html).not.toContain('data-action="viewas-start" disabled');
      await s5.actions["viewas-start"](ctx, fakeEl());
      const post = calls.find(
        (c) => c.method === "POST" && c.path === "/v1/root/view-as/sessions",
      );
      expect(post?.body).toEqual({
        role: "admin",
        functionalAreaIds: ["fn-marketing"],
        reason: "Quarterly access review",
      });

      // Active preview: banner + Exit only; no admin fetches, no mutations,
      // no credential in the markup; the why line ships hidden.
      const previewView = makeCtx({
        role: "owner",
        routes: {
          get: {
            "/v1/memory-graph": graphView(response, {
              title: "Marketing memory",
              why: { "src-filesystem": "Marketing shared → admin grant" },
            }),
          },
          del: { "/v1/root/view-as/sessions/pv1": {} },
        },
      });
      const previewHtml = await s5.render(previewView.ctx);
      expect(previewHtml).toContain("Viewing as Admin · Marketing");
      expect(previewHtml).toContain('data-action="viewas-exit"');
      expect(previewHtml).toContain(">Exit<");
      expect(previewHtml).toContain("<h1>Marketing memory</h1>");
      expect(previewHtml).not.toContain('data-action="pin-memory"');
      expect(previewHtml).not.toContain('data-action="unpin"');
      expect(previewHtml).not.toContain('data-action="viewas-open"');
      expect(previewHtml).not.toContain("Kept handy");
      expect(previewHtml).not.toContain("tok_secret_preview");
      expect(previewHtml).toContain('data-why-for="src-filesystem" hidden');
      expect(previewHtml).toContain("Marketing shared → admin grant");
      expect(previewView.calls.map((c) => c.path)).toEqual(["/v1/memory-graph"]);

      // Exit revokes the session server-side and restores the root view.
      await s5.actions["viewas-exit"](previewView.ctx, fakeEl());
      expect(
        previewView.calls.some(
          (c) => c.method === "DELETE" && c.path === "/v1/root/view-as/sessions/pv1",
        ),
      ).toBe(true);
      const after = await s5.render(ctx);
      expect(after).toContain('data-action="viewas-open"');
      expect(after).not.toContain("Viewing as");
    } finally {
      // Always clear module preview/picker state for later tests.
      await s5.actions["viewas-exit"](ctx, fakeEl());
      await s5.actions["viewas-close"](ctx, fakeEl());
    }
  });
});

// ---------------------------------------------------------------------------
// S6 — Sources & imports
// ---------------------------------------------------------------------------

describe("s6 - sources", () => {
  const view = () => ({
    sources: [{ id: XSS, namespace: "acme", kind: "shopify", lastSync: null, createdAt: "2026-01-01T00:00:00Z" }],
    latestFragmentation: { factCount: 100, duplicateClusters: 4, contradictions: 2 },
  });

  it("owner sees the platform catalog and source controls; a hostile source id is escaped", async () => {
    const s6 = await loadScreen("s6");
    const { ctx } = makeCtx({ role: "owner", routes: { get: {
      "/v1/admin/sources": view(),
      "/v1/admin/connectors": { connectors: [{
        id: "shopify", connectionKey: "shopify", name: "Shopify", category: "commerce",
        description: "Commerce memory", auth: { type: "oauth", fields: [] },
        dataPoints: [{ key: "products", label: "Products", description: "Catalog", defaultEnabled: true }],
        capabilities: { sourceAcl: false },
      }] },
      "/v1/admin/source-credentials": [],
    } } });
    const html = await s6.render(ctx);
    expect(html).toContain("Shopify");
    // Connections are tiles; the lifecycle controls live in the drawer a tile
    // opens (asserted in console-s6-ui).
    expect(html).toContain('data-action="open-source-detail"');
    expect(html).toContain('<div id="source-detail-panel"');
    expect(html).toContain('data-action="update-all-sources"');
    expect(html).toContain('data-input-action="filter-connectors"');
    expect(html).toContain('class="source-category-summary"');
    expect(html).toContain("Add a source");
    expect(html).toContain("Shopify");
    expect(html).not.toContain("<h3>Data quality</h3>");
    expect(html).not.toContain('data-action="run-data-quality-check"');
    expect(html).toContain('<span class="source-tile-status pill--ok">Connected</span>');
    expect(html).toContain("Live systems that can refresh automatically.");
    expect(html).toContain('data-connector-logo-image');
    expect(html).toContain('src="https://cdn.simpleicons.org/shopify"');
    expect(html).not.toContain('src="javascript:');
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain(XSS);
    expect(html).not.toContain('data-id="<img');
  });

  it("auditor sees sources read-only - no Sync/Run/Connect controls", async () => {
    const s6 = await loadScreen("s6");
    const { ctx } = makeCtx({ role: "auditor", routes: { get: { "/v1/admin/sources": view() } } });
    const html = await s6.render(ctx);
    expect(html).not.toContain('data-action="sync-source"');
    expect(html).not.toContain('data-action="update-all-sources"');
    expect(html).not.toContain('data-action="run-data-quality-check"');
    expect(html).not.toContain('data-action="toggle-catalog"');
    // The connection card now renders a trusted brand logo <img>; the hostile
    // source id must still be escaped and never reach a raw tag or attribute.
    expect(html).toContain(XSS_ESCAPED);
    const rawImgs = html.match(/<img[^>]*>/g) ?? [];
    expect(rawImgs.length).toBeGreaterThan(0);
    for (const tag of rawImgs) {
      expect(tag).toContain("data-connector-logo-image");
      expect(tag).toContain('src="https://cdn.simpleicons.org/shopify"');
      expect(tag).not.toContain(XSS);
    }
  });

  it("ignores legacy fragmentation data now that quality review lives outside Sources", async () => {
    const s6 = await loadScreen("s6");
    const { ctx } = makeCtx({
      routes: { get: { "/v1/admin/sources": { sources: [], latestFragmentation: null } } },
    });
    const html = await s6.render(ctx);
    expect(html).toContain("Connection status");
    expect(html).not.toContain("<h3>Data quality</h3>");
    expect(html).not.toContain('data-action="run-data-quality-check"');
  });

  it("distinguishes a completed manual sync from a failed sync", async () => {
    const s6 = await loadScreen("s6");
    const response = {
      sources: [
        { id: "ok", namespace: "acme", kind: "postgres", createdAt: "2026-01-01T00:00:00Z", lastSync: "2026-07-01T00:00:00Z" },
        { id: "bad", namespace: "acme", kind: "postgres", createdAt: "2026-01-02T00:00:00Z", lastSync: null, syncStatus: "failed", lastSyncError: "permission denied" },
      ],
      latestFragmentation: null,
    };
    const { ctx } = makeCtx({ routes: { get: { "/v1/admin/sources": response } } });
    const html = await s6.render(ctx);
    // Each tile states its own health. The provider's raw message is machine
    // detail: it belongs in the drawer, not on a wall of tiles.
    expect(html).toContain("Up to date");
    expect(html).toContain("Needs attention");
    expect(html).not.toContain("permission denied");
  });
});

// ---------------------------------------------------------------------------
// S9 — Retriever scorecard
// ---------------------------------------------------------------------------

describe("s9 - scorecard", () => {
  const card = () => ({
    id: "01CARD",
    namespace: "acme",
    ranAt: "2026-07-01T00:00:00Z",
    questionCount: 12,
    drivers: [
      { driver: "graph", questions: 12, hitAt3: 0.83, meanTokens: 410, p95LatencyMs: 22, errors: 0 },
      { driver: XSS, questions: 12, hitAt3: 0.5, meanTokens: 900, p95LatencyMs: 40, errors: 1 },
    ],
    winner: "graph",
  });

  it("shows the benchmark winner separately from the effective live retriever", async () => {
    const s9 = await loadScreen("s9");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        post: { "/v1/admin/scorecard": card() },
        get: { "/v1/admin/policy?namespace=acme": { namespace: "acme", retriever: "baseline" } },
      },
    });
    const html = await s9.render(ctx);
    expect(html).toContain("graph"); // winner engine name
    expect(html).toContain("0.83"); // hit@3, 2dp
    expect(html).toContain('data-action="switch-retriever"');
    expect(html).toContain("Benchmark winner");
    expect(html).toContain("Effective live retriever");
    expect(html).toContain("baseline");
    expect(html).not.toContain("Winner · live");
    expect(html).not.toContain("already the live retriever");
    assertNoRawImg(html);
    expect(html).not.toContain('data-retriever="<img');
  });

  it("auditor sees the scorecard read-only - no Switch control", async () => {
    const s9 = await loadScreen("s9");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: {
        post: { "/v1/admin/scorecard": card() },
        get: { "/v1/admin/policy?namespace=acme": { namespace: "acme", retriever: "baseline" } },
      },
    });
    const html = await s9.render(ctx);
    expect(html).not.toContain('data-action="switch-retriever"');
    assertNoRawImg(html);
  });

  it("a 'no facts' 400 becomes an honest empty state", async () => {
    const s9 = await loadScreen("s9");
    const { ctx } = makeCtx({
      routes: {
        post: {
          "/v1/admin/scorecard": () => {
            throw { status: 400, message: "namespace 'acme' has no facts with enough distinctive tokens" };
          },
        },
      },
    });
    const html = await s9.render(ctx);
    expect(html).toContain("Not enough facts");
  });

  it("switches the selected child policy and preserves that scorecard scope", async () => {
    const s9 = await loadScreen("s9") as {
      render(ctx: unknown): Promise<string>;
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const { ctx, calls } = makeCtx({
      namespace: "",
      routes: { put: { "/v1/admin/policy": {} } },
    });
    const navigations: string[] = [];
    ctx.go = ((screen: string) => { navigations.push(screen); }) as typeof ctx.go;
    const el = {
      getAttribute(name: string) {
        if (name === "data-retriever") return "graph";
        if (name === "data-namespace") return "acme/support";
        return null;
      },
    };

    await s9.actions["switch-retriever"](ctx, el);

    expect(calls).toContainEqual({
      method: "PUT",
      path: "/v1/admin/policy",
      body: { yaml: JSON.stringify({ retriever: "graph" }), namespace: "acme/support" },
    });
    expect(navigations).toEqual(["s9?scope=acme%2Fsupport"]);
  });

});

describe("s18 - profile", () => {
  it("recognizes the profile deep link used by the workspace account menu", async () => {
    const s18 = await loadScreen("s18");

    expect(s18.settingsTabFromHash("#settings?tab=profile")).toBe("profile");
    expect(s18.settingsTabFromHash("#settings?tab=organization")).toBe("organization");
    expect(s18.settingsTabFromHash("#s18?tab=profile")).toBe("profile");
    expect(s18.settingsTabFromHash("#s18?tab=organization")).toBe("organization");
    expect(s18.settingsTabFromHash("#s18?tab=unknown")).toBeNull();
    expect(s18.settingsTabFromHash("#s18")).toBeNull();
  });

  it("shows the identity and a connected GitHub account (escaped)", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": {
            identities: [{
              id: "e1",
              userId: "u1",
              provider: "github",
              providerAccountId: "123",
              login: XSS,
              email: "owner@acme.test",
              createdAt: "2026-07-20T00:00:00.000Z",
            }],
            email: "owner@acme.test",
            hasPassword: true,
          },
          "/auth/sso/config": { enabled: false, github: true },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain("Profile");
    expect(html).toContain("Connected");
    expect(html).toContain('data-action="github-disconnect"');
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain(XSS);
  });

  it("lists every sign-in method, connected or not", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": {
            identities: [{
              id: "e2",
              userId: "u1",
              provider: "google",
              providerAccountId: "g-1",
              login: "owner@acme.test",
              email: "owner@acme.test",
              createdAt: "2026-07-20T00:00:00.000Z",
            }],
            email: "owner@acme.test",
            hasPassword: false,
          },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    const html = await s18.render(ctx);
    // Password not set, Google connected, GitHub offered → 1 of 3.
    expect(html).toContain("1 of 3 connected");
    expect(html).toContain("Email and password");
    expect(html).toContain("Google");
    expect(html).toContain("GitHub");
    expect(html).toContain('data-method-lock="google"');
    expect(html).not.toContain('data-action="google-disconnect"');
    expect(html).toContain('data-action="github-connect"');
    expect(html).not.toContain('data-action="google-connect"');
  });

  it("keeps every method tile compact and opens details in the right drawer", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    const html = await s18.render(ctx);
    const methodTiles = html.match(
      /<button class="intg-card intg-card--status-only"[^>]*[\s\S]*?<\/button>/g,
    ) ?? [];
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(methodTiles).toHaveLength(3);
    expect(html).toContain('aria-label="Email and password sign-in method, Connected, Details"');
    expect(html).toContain('aria-label="Google sign-in method, Not connected, Connect"');
    expect(html).toContain('aria-label="GitHub sign-in method, Not connected, Connect"');
    expect(methodTiles.join("\n")).not.toContain('class="intg-card-title"');
    expect(methodTiles.join("\n")).not.toContain('class="intg-card-sub"');
    expect(html).toContain('class="profile-method-modal source-wizard-overlay"');
    expect(css).toMatch(/\.settings-bento-methods \.intg-grid\{[^}]*grid-template-columns:repeat\(3,minmax\(0,1fr\)\)/);
    expect(css).toMatch(/\.settings-bento-methods \.intg-card\{[^}]*min-height:72px/);
    expect(css).toMatch(/\.source-wizard-overlay\{[^}]*justify-content:flex-end/);
  });

  it("renders a premium method drawer with account-change and alternative sign-in paths", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": {
            identities: [{
              id: "google-1",
              userId: "u1",
              provider: "google",
              providerAccountId: "g-1",
              login: "owner@acme.test",
              email: "owner@acme.test",
              createdAt: "2026-07-20T00:00:00.000Z",
            }],
            email: "owner@acme.test",
            hasPassword: true,
          },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });

    const html = await s18.render(ctx);
    const passwordDrawer = html.match(
      /<div class="profile-method-modal source-wizard-overlay" id="profile-method-password"[\s\S]*?<\/div><div class="profile-method-modal/,
    )?.[0] ?? "";
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(passwordDrawer).toContain('class="source-wizard-dialog profile-method-panel"');
    expect(passwordDrawer).toContain('class="profile-method-header"');
    expect(passwordDrawer).toContain('class="profile-method-header-actions"');
    expect(passwordDrawer).toContain('class="profile-method-status"');
    expect(passwordDrawer).toContain('class="profile-method-body"');
    expect(passwordDrawer).toContain("Need to change this email?");
    expect(passwordDrawer).toContain('class="metric-info profile-method-info"');
    expect(passwordDrawer).toContain('role="note" tabindex="0"');
    expect(passwordDrawer).toContain('data-tip="Email changes require an assisted account migration so your access and audit history stay attached."');
    expect(passwordDrawer).toContain("Request email change");
    expect(passwordDrawer).toContain('href="mailto:contactus@halofy.ai?subject=Request%20email%20change"');
    expect(passwordDrawer).not.toContain("calendly.com");
    expect(passwordDrawer).toContain("Other sign-in methods");
    expect(html).not.toContain('class="profile-method-lead"');
    expect(html).not.toContain("Connect another secure way to access this same account.");
    expect(html.match(/class="profile-method-header-actions"/g) ?? []).toHaveLength(3);
    expect(passwordDrawer).toContain('data-action="profile-method-open" data-method="google"');
    expect(passwordDrawer).toContain('data-action="profile-method-open" data-method="github"');
    expect(html).toContain('data-action="google-disconnect"');
    expect(css).toMatch(/\.profile-method-modal \.source-wizard-dialog\{[^}]*width:min\(620px,100vw\)/);
    expect(css).toMatch(/\.profile-method-header-actions\{[^}]*justify-items:end/);
    expect(css).toMatch(/\.profile-method-status\{[^}]*justify-content:flex-end/);
  });

  it("renders a grammatical profile bento and counts only real teams", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      namespace: "halofy",
      routes: {
        get: {
          "/auth/profile": {
            homeNamespace: "halofy",
            displayName: "Koushik",
            avatar: null,
            teams: [
              { id: "org-root", name: "halofy", namespace: "halofy", isHome: true },
              { id: "marketing", name: "marketing", namespace: "halofy/marketing", isHome: false },
            ],
          },
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    (ctx.identity as { role: string }).role = "root";

    const html = await s18.render(ctx);
    const teamsCard = html.match(
      /<section class="card settings-bento-card settings-bento-teams"[\s\S]*?<\/section>/,
    )?.[0];
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(html).toContain('class="settings-profile-bento"');
    expect(html).toContain('<span class="badge badge--role">Root</span>');
    expect(html).toContain('<dt>Role</dt><dd>Root</dd>');
    expect(html).toContain('<dt>Workspace</dt><dd>Halofy</dd>');
    expect(teamsCard).toBeDefined();
    expect(teamsCard).toContain("1 team");
    expect(teamsCard).toContain("Marketing");
    expect(teamsCard).not.toContain("2 teams");
    expect(teamsCard).not.toContain("halofy/marketing");
    expect(teamsCard).not.toContain(">halofy<");
    expect(css).toMatch(/\.settings-profile-bento\{[^}]*display:grid[^}]*grid-template-columns:/);
  });

  it("offers Connect Google and Connect GitHub when unlinked and configured", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain("Not connected");
    expect(html).toContain('data-action="github-connect"');
    expect(html).toContain('data-action="google-connect"');
  });

  it("blocks disconnect in the UI only when the provider is the last sign-in method", async () => {
    const s18 = await loadScreen("s18");
    const googleIdentity = {
      id: "google-1",
      userId: "u1",
      provider: "google",
      providerAccountId: "g-1",
      login: "owner@gmail.test",
      email: "owner@gmail.test",
      createdAt: "2026-07-20T00:00:00.000Z",
    };
    const lastMethod = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [googleIdentity], email: "owner@acme.test", hasPassword: false },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    const lastHtml = await s18.render(lastMethod.ctx);
    expect(lastHtml).toContain("At least one sign-in method must remain connected.");
    expect(lastHtml).toContain('data-method-lock="google"');
    expect(lastHtml).not.toContain('data-action="google-disconnect"');

    const replaceable = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [googleIdentity], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });
    const replaceableHtml = await s18.render(replaceable.ctx);
    expect(replaceableHtml).toContain('data-action="google-disconnect"');
    expect(replaceableHtml).not.toContain('data-method-lock="google"');
  });

  it("moves the last-method rule into an accessible tooltip beside the heading", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: true, github: true },
        },
      },
    });

    const html = await s18.render(ctx);
    expect(html).toContain('<h3 style="margin:0">Sign-in methods<span class="heading-info"');
    expect(html).toContain(
      'aria-label="Sign-in methods: At least one sign-in method must remain connected."',
    );
    expect(html).not.toContain(
      '<div class="sub">At least one sign-in method must remain connected.</div>',
    );
  });

  it("refreshes in place after disconnecting either external provider", async () => {
    const s18 = await loadScreen("s18");
    const { ctx, calls } = makeCtx({
      routes: {
        del: {
          "/auth/identities/google": { ok: true },
          "/auth/identities/github": { ok: true },
        },
      },
    });
    const refresh = vi.fn(async () => {});
    const go = vi.fn();
    const status = { textContent: "" };
    const button = {
      disabled: false,
      textContent: "Disconnect",
      closest(selector: string) {
        return selector === ".source-wizard-dialog"
          ? { querySelector: () => status }
          : null;
      },
    };
    const actions = s18.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>;

    await actions["google-disconnect"]!({ ...ctx, refresh, go }, button);
    button.disabled = false;
    button.textContent = "Disconnect";
    await actions["github-disconnect"]!({ ...ctx, refresh, go }, button);

    expect(calls.slice(-2)).toEqual([
      { method: "DELETE", path: "/auth/identities/google" },
      { method: "DELETE", path: "/auth/identities/github" },
    ]);
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(go).not.toHaveBeenCalled();
  });

  it("hides a connect button when that provider is unconfigured", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: false, github: false },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain("not configured");
    expect(html).not.toContain('data-action="github-connect"');
    expect(html).not.toContain('data-action="google-connect"');
  });

  it("splits into an Organization and a Profile tab, with the profile panel hidden by default", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: false, github: false },
          "/v1/admin/organization": {
            organization: {
              id: "acme",
              name: "Acme",
              icon: null,
              status: "active",
              createdAt: "2026-07-20T00:00:00.000Z",
              canEdit: true,
            },
          },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain("<h1>Settings</h1>");
    expect(html).toContain('data-action="settings-tab" data-tab="organization"');
    expect(html).toContain('data-action="settings-tab" data-tab="profile"');
    // Organization opens first; the profile panel is present but hidden, so
    // switching tabs never refetches.
    expect(html).toContain('data-settings-panel="organization"');
    expect(html).toContain('data-settings-panel="profile" hidden');
    // Editable organization → the name control and the upload control exist.
    expect(html).toContain('id="org-name-input"');
    expect(html).toContain('data-action="org-name-save"');
    expect(html).toContain('data-change-action="org-icon-pick"');
    expect(html).toContain("<dt>Handle</dt>");
    expect(html).toContain("<dt>Created</dt>");
    expect(html).not.toContain("<dt>Status</dt>");
    // The profile half still carries the account facts and the method grid.
    expect(html).toContain('id="profile-name-input"');
    expect(html).toContain('data-action="profile-method-open"');
  });

  it("renders the organization read-only for a role without organization:write", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "member@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: false, github: false },
          "/v1/admin/organization": {
            organization: {
              id: "acme",
              name: XSS,
              icon: null,
              status: "active",
              createdAt: "2026-07-20T00:00:00.000Z",
              canEdit: false,
            },
          },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain(XSS);
    expect(html).not.toContain('id="org-name-input"');
    expect(html).not.toContain('data-change-action="org-icon-pick"');
    // Its own name stays editable — that is self-service for every role.
    expect(html).toContain('id="profile-name-input"');
  });

  it("shows the stored organization mark and a way to remove it", async () => {
    const s18 = await loadScreen("s18");
    const icon = "data:image/png;base64,iVBORw0KGgo=";
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: false, github: false },
          "/v1/admin/organization": {
            organization: {
              id: "acme",
              name: "Acme",
              icon,
              status: "active",
              createdAt: "2026-07-20T00:00:00.000Z",
              canEdit: true,
            },
          },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain(icon);
    expect(html).toContain('data-action="org-icon-clear"');
  });

  it("says so plainly when no organization resolves for the account", async () => {
    const s18 = await loadScreen("s18");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/auth/identities": { identities: [], email: "owner@acme.test", hasPassword: true },
          "/auth/sso/config": { enabled: false, github: false },
          "/v1/admin/organization": { organization: null },
        },
      },
    });
    const html = await s18.render(ctx);
    expect(html).toContain("No organization resolves for this account.");
    expect(html).not.toContain('id="org-name-input"');
  });
});

describe("console role matrix", () => {
  it("keeps commercial-only screens out and limits setup to the root owner", async () => {
    const appSrc = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.js", import.meta.url)), "utf8"),
    );
    // S16 member surface: list/submit/download live on the non-admin
    // /v1/skills routes, so members legitimately get the skills screen;
    // governance actions (approve/vet/retire) stay owner/admin server-side.
    expect(appSrc).toContain('member: ["s2", "s5", "s6", "s14", "s16", "s18"]');
    // M9: s15 (user analytics) is read-only for the auditor via a server-side
    // console-route carve-out. s16 (skills) and s17 (OAuth clients) must NOT
    // appear in the auditor rail: their primary GETs are owner/admin-gated
    // server-side, so listing them advertised dead 403 screens (audit
    // finding — the rail must match the server role gate). s12 stays
    // owner/admin-only. s18 (profile) is self-service and rides every role.
    // s21 (channels) has a true auditor read model: the channel catalog and
    // connection GETs allow owner/admin/auditor server-side; mutations
    // re-assert owner/admin.
    expect(appSrc).toContain('auditor: ["s2", "s5", "s6", "s14", "s3", "s13", "s4", "s7", "s8", "s11", "s20", "s18"]');
    expect(appSrc).not.toMatch(/auditor:\s*\[[^\]]*"s16"/);
    expect(appSrc).not.toMatch(/auditor:\s*\[[^\]]*"s17"/);
    // s19 (alerts) rides the owner/admin rails only: both of its reads and both
    // of its decisions are owner/admin server-side, and an inbox that renders
    // "all clear" because the read was refused is worse than no inbox at all.
    expect(appSrc).toContain('admin: ["s2", "s5", "s6", "s14", "s16", "s9", "s3", "s19", "s13", "s4", "s7", "s8", "s11", "s17", "s20", "s18"]');
    // s22 (billing) is OWNER-ONLY: it is the tenant's commercial surface
    // (early access period, allowances, later plan/payment state). admin,
    // auditor, and member rails must never carry it.
    expect(appSrc).toContain('owner: ["s2", "s5", "s6", "s14", "s16", "s9", "s3", "s19", "s13", "s4", "s7", "s8", "s11", "s17", "s20", "s18"]');
    expect(appSrc).not.toMatch(/admin:\s*\[[^\]]*"s22"/);
    expect(appSrc).not.toMatch(/auditor:\s*\[[^\]]*"s22"/);
    expect(appSrc).not.toMatch(/member:\s*\[[^\]]*"s22"/);
    expect(appSrc).not.toContain('{ s: "s22", icon: "card", label: "Billing" }');
    expect(appSrc).not.toContain('{ s: "s21", icon: "plug", label: "Channels" }');
    expect(appSrc).not.toMatch(/auditor:\s*\[[^\]]*"s19"/);
    expect(appSrc).not.toMatch(/member:\s*\[[^\]]*"s19"/);
    expect(appSrc).toContain('{ s: "s19", icon: "shield", label: "Alerts" }');
    // s20 (export) rides owner/admin/auditor — exactly the server's
    // EXPORT_ROLES (src/export/index.ts). member/agent must never see it: the
    // server 403s them, and advertising a dead screen is the same rail/gate
    // mismatch the s16/s17 auditor finding closed.
    expect(appSrc).not.toMatch(/member:\s*\[[^\]]*"s21"/);
    expect(appSrc).toContain('{ s: "s20", icon: "download", label: "Export" }');
    // s18 is the Settings screen (organization + profile tabs), not "Profile".
    expect(appSrc).toContain('{ s: "s18", icon: "gear", label: "Settings" }');
    expect(appSrc).not.toMatch(/auditor:\s*\[[^\]]*"s12"/);
    expect(appSrc).not.toMatch(/member:\s*\[[^\]]*"s12"/);
    expect(appSrc).not.toContain('{ s: "s12", icon: "model", label: "AI models" }');
    expect(appSrc).toContain('{ s: "s4", icon: "dial", label: "Policies" }');
    expect(appSrc).toContain('{ s: "s7", icon: "check", label: "Knowledge operations" }');
    expect(appSrc).not.toContain('{ s: "s7", icon: "check", label: "Approvals" }');
    expect(appSrc).not.toContain('{ s: "s4", icon: "dial", label: "Policy dials" }');
    expect(appSrc).not.toContain('auditor: ["s2", "s5", "s6", "s10", "s9"');
    // M10 (D41): the session payload now carries product roles, so the
    // platform-setup screen gate accepts `root` (the product spelling of the
    // internal owner) alongside legacy `owner` fixtures — still restricted
    // to the organization-root namespace. Same gate, product-role aware.
    expect(appSrc).toContain('(identity.role === "owner" || identity.role === "root") &&');
    expect(appSrc).toContain('identity.namespace === ""');
    expect(appSrc).toContain('screens.push("s1")');
    expect(appSrc).not.toContain('roles: ["owner", "admin"]');
  });

  // S9 is BOXED, not deleted. The rail literals above still carry "s9" so that
  // un-boxing is a one-line change; the boxing is enforced downstream in
  // screensFor(), which is what actually feeds the nav AND the hash-route
  // guard. This test pins the enforcement, not the literals.
  it("boxes s9 out of every rail while leaving the screen buildable", async () => {
    const appSrc = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.js", import.meta.url)), "utf8"),
    );

    // The box itself, and the fact that it is applied to the rail.
    expect(appSrc).toContain('const BOXED_SCREENS = new Set(["s9"]);');
    expect(appSrc).toContain(
      "return screens.filter((s) => !BOXED_SCREENS.has(s));",
    );

    // Boxing must be the LAST step in screensFor, so it also strips the
    // owner-only s1 push path — no rail may re-admit a boxed id.
    const body = appSrc.slice(
      appSrc.indexOf("function screensFor(identity)"),
      appSrc.indexOf("const NAV = ["),
    );
    expect(body.indexOf('screens.push("s1")')).toBeLessThan(
      body.indexOf("BOXED_SCREENS.has(s)"),
    );

    // The nav renders from screensFor's output, so a boxed id cannot reach the
    // sidebar in either gate mode.
    expect(appSrc).toContain("const fullAccess = new Set(screensFor(identity));");

    // The screen module stays on disk and stays loadable — boxing is a
    // withdrawal from the product, not a deletion of the work.
    const s9 = await loadScreen("s9");
    expect(typeof s9.render).toBe("function");
  });

  it("points the readiness retrieval pillar away from the boxed scorecard", async () => {
    const card = await import("node:fs/promises").then((fs) =>
      fs.readFile(
        fileURLToPath(new URL("../console/screens/readiness-card.js", import.meta.url)),
        "utf8",
      ),
    );

    // A drill-in button targeting a boxed screen is a dead control: the route
    // guard rejects the id, so the click does nothing.
    expect(card).not.toMatch(/retrieval:\s*"s9"/);
    expect(card).toMatch(/retrieval:\s*"s6"/);
    expect(card).not.toMatch(/retrieval:\s*"Scorecard"/);
  });
});

// ---------------------------------------------------------------------------
// S10 — Copilot harness
// ---------------------------------------------------------------------------

describe("s1 - setup", () => {
  const checklist = {
    namespace: "",
    organization: "acme",
    steps: [
      { id: "team-space", title: "Create your team space", detail: "At least one team exists.", state: "outstanding", evidence: "no teams exist yet", screen: "s13", optional: false },
      { id: "source", title: "Connect and sync a source", detail: "At least one sync done.", state: "complete", evidence: "1 of 1 sources synced", screen: "s6", optional: false },
    ],
    remaining: 1,
    completed: 1,
    total: 2,
    complete: false,
    degraded: false,
    derivedAt: "2026-07-31T00:00:00.000Z",
  };

  it("renders only the standing checklist - the one-shot wizard is gone", async () => {
    const s1 = await loadScreen("s1");
    const { ctx, calls } = makeCtx({
      routes: { get: { "/v1/admin/setup-checklist": checklist } },
    });
    const html = await s1.render(ctx);
    expect(html).toContain("Set up Halofy");
    expect(html).toContain("Organization · acme");
    expect(html).toContain("no teams exist yet");
    // The only CTA is on the up-next step; done steps carry no action.
    expect(html).toContain('href="#teams">Start</a>');
    expect(html).not.toContain('href="#sources"');
    // Every trace of the old verified-setup wizard is gone.
    expect(html).not.toContain('data-action="setup-submit"');
    expect(html).not.toContain("Select a mounted retriever");
    expect(html).not.toContain('id="setup-org"');
    expect(html).not.toContain("Create and verify setup");
    expect(s1.actions).toBeUndefined();
    expect(calls.some((c) => String(c.path).includes("/v1/admin/setup/capabilities"))).toBe(false);
    expect(html).not.toContain("<img");
  });

  it("reuses the shell's initial checklist read during first paint", async () => {
    const s1 = await loadScreen("s1");
    const { ctx, calls } = makeCtx();
    (ctx as typeof ctx & { initialSetupChecklist: Promise<unknown> }).initialSetupChecklist =
      Promise.resolve(checklist);

    const html = await s1.render(ctx);

    expect(html).toContain("Organization");
    expect(calls.map((call) => call.path)).not.toContain("/v1/admin/setup-checklist");
  });
});

// ---------------------------------------------------------------------------
// S3 - Scoped memory
// ---------------------------------------------------------------------------

describe("s3 - scoped memory", () => {
  // The screen keeps its draft, filter and one-time key in module scope on
  // purpose (see s3.js: app.js calls cleanup() on same-screen re-renders, so a
  // reset there would erase the key). Tests therefore drive it through its own
  // actions and reset it between cases.
  type Action = (ctx: unknown, el: unknown) => Promise<void> | void;

  const people = () => ({
    users: [{ email: XSS, namespace: "acme", role: "member", status: "active" }],
    badges: [{ id: "01BADGE", actor: XSS, namespace: "acme", role: "agent", status: "active", lastUsed: null }],
  });

  const oversight = {
    maxRequestsPerMinute: 60,
    usageAlertThreshold: 100,
    deniedAlertThreshold: 1,
    recipientRoles: ["owner", "admin"],
    accessRequests: "allowed",
    approvalTtlSeconds: 3600,
  };

  const agentControlRoutes = () => ({
    "/v1/admin/people": people(),
    "/v1/admin/sources": {
      sources: [{ id: "source-1", kind: "postgres", namespace: "acme", lifecycleState: "active" }],
    },
    "/v1/admin/agent-connections": [{
      id: "grant-1",
      keyId: "01BADGE",
      namespace: "acme",
      connectorId: "source-1",
      allowedOperations: ["source-read", "search"],
      allowedSourceRefs: ["support.refunds"],
      allowedFields: { "support.refunds": ["ticket_id", "status"] },
      allowedPurposes: ["resolve refunds"],
      maxSensitivity: "confidential",
      maxRows: 25,
      maxBytes: 1048576,
      policyVersion: 1,
      status: "active",
      expiresAt: "2026-08-17T00:00:00.000Z",
      oversight,
    }],
    "/v1/admin/agent-access/alerts?status=open&limit=50": [{
      id: "alert-1",
      eventId: "event-2",
      grantId: "grant-1",
      keyId: "01BADGE",
      namespace: "acme",
      kind: "outside-scope",
      severity: "critical",
      recipientRoles: ["owner", "admin"],
      status: "open",
      createdAt: "2026-07-17T10:05:00.000Z",
    }],
    "/v1/admin/agent-access/requests?status=pending&limit=50": [{
      id: "request-1",
      keyId: "01BADGE",
      namespace: "acme",
      grantId: "grant-1",
      connectorId: "source-1",
      sourceRef: "support.chargebacks",
      operation: "source-read",
      purpose: "review chargeback",
      requestedFields: ["case_id", "status"],
      requestedRows: 10,
      requestedBytes: 102400,
      justification: "Customer escalation",
      requestedDurationSeconds: 1800,
      status: "pending",
      approvedUntil: null,
      maxUses: 1,
      usedCount: 0,
      createdAt: "2026-07-17T10:06:00.000Z",
      decidedAt: null,
      decidedBy: null,
    }],
  });

  /** Module state is shared between cases, so put it back to the default view. */
  const reset = async (s3: Awaited<ReturnType<typeof loadScreen>>) => {
    await (s3.actions!["badge-panel-close"] as Action)(makeCtx().ctx, {} as never);
    await (s3.actions!["badge-issued-dismiss"] as Action)(makeCtx().ctx, {} as never);
    await (s3.actions!["agent-source-cancel"] as Action)(makeCtx().ctx, {} as never);
    await (s3.actions!["badge-filter"] as Action)(
      makeCtx().ctx, { getAttribute: () => "active" } as never,
    );
  };

  it("leads with scoped memory access, not with a wizard", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ routes: { get: agentControlRoutes() } });
    const html = await s3.render(ctx);
    expect(html).toContain("<h1>Scope Memory</h1>");
    expect(html).toContain("Scope memory access");
    expect(html).toContain("Grant your team scoped access to its shared memory.");
    expect(html).toContain("Create scoped badge");
    expect(html).toContain("You can revoke it instantly at any time.");
    expect(html).toContain(
      'class="row scope-memory-create-action" style="margin-top:var(--s4)"',
    );
    expect(html).toContain(
      'class="btn btn--solid btn--sm" data-action="badge-create"',
    );
    expect(html).toContain(
      'class="subtle home-text-xs scope-memory-create-hint"',
    );
    // The three-step wizard is gone: the whole badge is one row of fields.
    for (const label of [
      "Step 1 of 3",
      "Step 2 of 3",
      "Step 3 of 3",
      "Deploy an agent",
      "Data it can reach",
      "Review and issue",
    ]) expect(html).not.toContain(label);
    // No level essay under the form, and no "Members - and the agents they
    // connect - ..." second sentence under the heading.
    expect(html).not.toContain("No agent can be given owner rights");
    expect(html).not.toContain("Members");
    expect(calls.map((call) => call.path)).toEqual([
      "/v1/admin/people",
      "/v1/admin/sources",
      "/v1/admin/agent-connections",
      "/v1/admin/agent-access/alerts?status=open&limit=50",
      "/v1/admin/agent-access/requests?status=pending&limit=50",
      "/v1/admin/keys",
      // D50: the team field is a fixed list of registered teams, not free text,
      // so a badge can only be bound to a team the caller actually has.
      "/v1/admin/teams",
      "/v1/admin/key-handoffs",
    ]);
  });

  it("asks six scoped-access questions and nothing else", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({
      routes: { get: { ...agentControlRoutes(), "/v1/admin/teams": [
        { namespace: "acme", name: "Acme" },
        { namespace: "acme/support", name: "Support" },
      ] } },
    });
    const html = await s3.render(ctx);
    for (const label of [
      "Badge name", "Team", "Assigned to", "Memory access", "Agent role", "Access ends",
    ]) expect(html).toContain(label);
    expect(html).not.toContain("Who will connect it?");
    expect(html).not.toContain("How much can it do?");
    expect(html).toContain('<option value="acme" selected>Acme</option>');
    expect(html).toContain("Same as a teammate");
    expect(html).toContain("Teammate plus oversight");
    // Everything the old connector step asked for is simply not asked here.
    expect(html).not.toContain("Columns allowed in each table");
    expect(html).not.toContain("What is it for?");
  });

  it("offers only active members of the selected team and delegates without exposing a key", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/people"] = {
      users: [
        { id: "user-active", email: "active@acme.test", displayName: "Active Member", namespace: "acme", role: "member", status: "active" },
        { id: "user-disabled", email: "disabled@acme.test", displayName: "Disabled Member", namespace: "acme", role: "member", status: "disabled" },
        { id: "user-auditor", email: "audit@acme.test", displayName: "Audit Reader", namespace: "acme", role: "member", entitlements: ["audit:read"], status: "active" },
      ],
      badges: [],
    };
    routes["/v1/admin/teams"] = [{
      namespace: "acme",
      name: "Acme",
      members: [
        { userId: "user-active", role: "member", status: "active", displayName: "Active Member" },
        { userId: "user-disabled", role: "member", status: "disabled", displayName: "Disabled Member" },
        { userId: "user-other", role: "member", status: "active", displayName: "Other Team", email: "other@acme.test" },
        { userId: "user-auditor", role: "member", status: "active", entitlements: ["audit:read"], displayName: "Audit Reader" },
      ],
    }];
    const { ctx, calls } = makeCtx({ routes: {
      get: routes,
      post: { "/v1/admin/keys": { handoff: {
        id: "handoff-1", actor: "support-copilot", recipientLabel: "Active Member",
      } } },
    } });

    const before = await s3.render(ctx);
    expect(before).toContain('<option value="user-active">Active Member</option>');
    expect(before).not.toContain("Disabled Member");
    // Additional membership is enough even when the broader People directory
    // cannot see the person's home namespace: this selected roster is the
    // authorized and authoritative membership view.
    expect(before).toContain('<option value="user-other">Other Team</option>');
    expect(before).not.toContain("Audit Reader");

    const values: Record<string, { value?: string; tagName?: string; getAttribute?: () => null }> = {
      "#badge-name": { value: "support-copilot" },
      "#badge-team": { value: "acme" },
      "#badge-recipient": { value: "user-active", tagName: "SELECT" },
      "#badge-access": { value: "readwrite" },
      "#badge-level": { value: "member", tagName: "SELECT" },
      "#badge-expiry": { value: "30" },
    };
    const root = { querySelector: (selector: string) => values[selector] ?? null };
    await (s3.actions!["badge-create"] as Action)(
      ctx, { disabled: false, textContent: "", closest: () => root } as never,
    );
    const posted = calls.at(-1) as { body: Record<string, unknown> };
    expect(posted.body).toMatchObject({
      type: "assistant", actor: "support-copilot", namespace: "acme",
      recipientUserId: "user-active", agentAccessLevel: "member",
    });
    expect(String(posted.body.idempotencyKey)).toMatch(/.+/);

    const after = await s3.render(ctx);
    expect(after).toContain("Assigned to <b>Active Member</b>");
    expect(after).toContain("They can claim it, then reveal it again on demand in <b>Agent connections</b>.");
    expect(after).not.toContain("hm_agt_");
    await reset(s3);
  });

  it("shows pending assignments as unavailable when their security read fails", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/key-handoffs"] = () => { throw { status: 503, message: "unavailable" }; };
    const { ctx } = makeCtx({ routes: { get: routes } });
    const html = await s3.render(ctx);
    expect(html).toContain("Pending assignments unavailable");
    expect(html).not.toContain("No pending assignments");
  });

  it("D50: a member creates a badge only in its own team, at its own level", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ role: "member", namespace: "acme/marketing" });
    const html = await s3.render(ctx);

    // It never asks for people/badges - the server would refuse those.
    expect(calls.map((call) => call.path)).toEqual(["/v1/admin/keys", "/v1/admin/teams"]);
    expect(html).toContain("Badges &amp; credentials");
    // Its team is fixed, not typed or picked. The field shows the team on its
    // own - the tenant root is implied by being signed in - but still carries
    // the namespace that gets posted.
    expect(html).toContain('id="badge-team" value="marketing" data-namespace="acme/marketing" readonly');
    expect(html).not.toContain('value="acme/marketing" readonly');
    // No manager-scope choice to make, and no other key type to pick.
    expect(html).toContain('id="badge-level" value="Same as a teammate" readonly');
    expect(html).not.toContain("Teammate plus oversight");
    expect(html).not.toContain('value="read-only"');
  });

  it("posts the namespace behind the short team label, not the label itself", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ routes: { post: {
      "/v1/admin/keys": { plaintext: "hm_agt_x", record: { id: "01M", actor: "n", namespace: "halofy/marketing" } },
    } } });
    // What a member's readonly field looks like: label on screen, namespace on
    // the element. Posting the label would bind the badge to a team that does
    // not exist.
    const values: Record<string, unknown> = {
      "#badge-name": { value: "marketing-copilot" },
      "#badge-team": {
        value: "marketing",
        getAttribute: (name: string) => name === "data-namespace" ? "halofy/marketing" : null,
      },
    };
    const root = { querySelector: (selector: string) => values[selector] ?? null };
    await (s3.actions!["badge-create"] as Action)(
      ctx, { disabled: false, textContent: "", closest: () => root } as never,
    );
    const posted = calls.at(-1) as { body: Record<string, unknown> };
    expect(posted.body.namespace).toBe("halofy/marketing");
    await reset(s3);
  });

  it("drops the tenant root from every team it prints, but never from what it posts", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/teams"] = [
      { namespace: "halofy/sales/team" },
      { namespace: "halofy/marketing" },
      { namespace: "halofy" },
    ];
    routes["/v1/admin/keys"] = [
      { id: "01NESTED", actor: "sales-copilot", namespace: "halofy/sales/team", role: "agent", status: "active" },
      { id: "01ORG", actor: "org-copilot", namespace: "halofy", role: "agent", status: "active" },
    ];
    const { ctx } = makeCtx({ routes: { get: routes } });
    const html = await s3.render(ctx);

    // The operator is signed in to the one organization, so naming it on every
    // row is width spent saying nothing.
    expect(html).toContain('<span class="subtle">sales/team</span>');
    expect(html).not.toContain("halofy/sales/team<");
    expect(html).not.toContain('>halofy/marketing<');
    // A namespace with no `/` IS the root: that badge is scoped org-wide.
    expect(html).toContain('<span class="subtle">Organization</span>');
    // The select's option TEXT is short; its VALUE stays the real namespace,
    // because that is what the create POST sends.
    expect(html).toContain('<option value="halofy/sales/team"');
    expect(html).toContain('>sales/team</option>');
    expect(html).toContain('<option value="halofy/marketing"');
    expect(html).toContain('>marketing</option>');
  });

  it("puts scope, source access and attention counts in the badge right panel", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({ routes: { get: agentControlRoutes() } });
    const html = await s3.render(ctx);
    expect(html).toContain('data-action="badge-expand" data-id="01BADGE"');
    expect(html).toContain('id="badge-detail-panel"');
    await (s3.actions!["badge-expand"] as Action)(ctx, {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
    } as never);
    const detailHtml = await s3.render(ctx);
    expect(detailHtml).toContain('class="badge-detail-grid"');
    expect(detailHtml).toContain('class="badge-detail-cell"');
    expect(detailHtml).toContain('class="badge-detail-value"');
    expect(detailHtml).not.toContain('class="badge-detail-grid" style=');
    expect(detailHtml).toContain("source-1 - 25 rows / 1 MB / 60 per min");
    expect(detailHtml).toContain("1 open · 1 pending");
    expect(detailHtml).toContain("Bearer key · gateway enforced");
    // S19 owns the approval inbox; this screen only counts.
    expect(html).not.toContain('data-action="agent-alert-acknowledge"');
    expect(html).not.toContain('data-action="agent-request-approve"');
    expect(html).not.toContain('data-action="agent-request-deny"');
    assertNoRawImg(detailHtml);
  });

  it("opens a badge row in the right panel without route navigation", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const focus = vi.fn();
    const doc = {
      body: { classList: { add: vi.fn(), remove: vi.fn() } },
      addEventListener: vi.fn(), removeEventListener: vi.fn(),
      getElementById: (id: string) => id === "badge-detail-panel" ? panel : null,
      querySelector: () => button,
    };
    const panel = { hidden: true, ownerDocument: doc, setAttribute: vi.fn(), querySelector: () => ({ focus }) };
    const attrs: Record<string, string> = {};
    const button = {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
      setAttribute: (name: string, value: string) => { attrs[name] = value; },
      focus: vi.fn(),
    };
    const { ctx, calls, refreshCalls } = makeCtx();
    vi.stubGlobal("document", doc);
    try {
      await (s3.actions!["badge-expand"] as Action)(ctx, button as never);
      expect(panel.hidden).toBe(false);
      expect(attrs["aria-expanded"]).toBe("true");
      expect(focus).toHaveBeenCalledOnce();
      expect(refreshCalls).toEqual(["refresh"]);
      expect(calls).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("labels a human API key by its type instead of pretending it is a badge", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    // Human credentials reach the ledger through the key listing; the badge
    // listing on /people is agent-only and stays that way.
    routes["/v1/admin/keys"] = [
      { id: "01ADMIN", actor: "human-admin-key", namespace: "acme", role: "admin", status: "active" },
    ];
    routes["/v1/admin/people"].badges.push({
      id: "01ADMIN",
      actor: "human-admin-key",
      namespace: "acme",
      role: "admin",
      status: "active",
      lastUsed: null,
    });
    const { ctx } = makeCtx({ routes: { get: routes } });
    const html = await s3.render(ctx);
    // It is listed - it is a credential - but it gets no scoped-memory detail.
    expect(html).toContain("human-admin-key");
    expect(html).toContain('<span class="badge badge--role">Admin</span>');
    expect(html).not.toContain('data-action="badge-expand" data-id="01ADMIN"');
    expect(html).not.toContain('id="badge-detail-01ADMIN"');
  });

  it("D51: creating a badge posts one typed credential with a bounded lifetime", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ routes: { post: {
      "/v1/admin/keys": {
        plaintext: "hm_agt_once",
        record: {
          id: "01NEW", actor: "support-copilot", namespace: "acme/support",
          role: "agent", agentAccessLevel: "member",
          expiresAt: "2026-10-23T00:00:00.000Z",
        },
      },
    } } });
    const values: Record<string, { value?: string; tagName?: string }> = {
      "#badge-name": { value: "support-copilot" },
      "#badge-team": { value: "acme/support" },
      "#badge-access": { value: "readwrite" },
      "#badge-level": { value: "member", tagName: "SELECT" },
      "#badge-expiry": { value: "90" },
    };
    const status = { textContent: "" };
    const root = {
      querySelector: (selector: string) =>
        values[selector] ?? (selector === "#badge-status" ? status : null),
    };
    const button = { disabled: false, textContent: "Create scoped badge", closest: () => root };
    await (s3.actions!["badge-create"] as Action)(ctx, button);

    const posted = calls.at(-1) as { method: string; path: string; body: Record<string, unknown> };
    expect(posted.method).toBe("POST");
    expect(posted.path).toBe("/v1/admin/keys");
    expect(posted.body.type).toBe("assistant");
    expect(posted.body.actor).toBe("support-copilot");
    expect(posted.body.namespace).toBe("acme/support");
    expect(posted.body.agentAccessLevel).toBe("member");
    // ~90 days out, computed from now rather than typed into a datetime field.
    const days = (Date.parse(String(posted.body.expiresAt)) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89.9);
    expect(days).toBeLessThan(90.1);
    // D54 defaults to read and write; the control exists, it is just already
    // answered for the common case.
    expect(posted.body.agentCanWrite).toBe(true);
    // Nothing about connectors, rows, bytes, or alert thresholds is sent.
    expect(Object.keys(posted.body).sort()).toEqual([
      "actor", "agentAccessLevel", "agentCanWrite", "expiresAt", "namespace", "type",
    ]);
    await reset(s3);
  });

  it("masks plaintext until an admin reveals it and points at Agent connections", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({ routes: {
      get: agentControlRoutes(),
      post: { "/v1/admin/keys": {
        plaintext: "hm_agt_shownonce",
        record: {
          id: "01NEW", actor: "support-copilot", namespace: "acme/support",
          role: "agent", agentCanWrite: true,
        },
      } },
    } });
    const values: Record<string, { value?: string }> = {
      "#badge-name": { value: "support-copilot" },
      "#badge-team": { value: "acme/support" },
    };
    const root = { querySelector: (selector: string) => values[selector] ?? null };
    await (s3.actions!["badge-create"] as Action)(
      ctx, { disabled: false, textContent: "", closest: () => root } as never,
    );
    const html = await s3.render(ctx);
    expect(html).toContain("Badge created");
    expect(html).not.toContain("hm_agt_shownonce");
    expect(html).toContain('aria-label="Bearer token hidden"');
    expect(html).toContain('data-action="badge-key-visibility" aria-pressed="false">Reveal bearer</button>');
    expect(html).toContain("Agent connections");
    expect(html).toContain("hidden by default and can be revealed again on demand");
    // The create form is not also on screen behind it.
    expect(html).not.toContain('data-action="badge-create"');

    const keyNode = { textContent: "", setAttribute: vi.fn() };
    const attrs: Record<string, string> = {};
    const button = {
      textContent: "Reveal bearer",
      closest: () => ({ querySelector: () => keyNode }),
      setAttribute: (name: string, value: string) => { attrs[name] = value; },
    };
    (s3.actions!["badge-key-visibility"] as Action)(ctx, button as never);
    expect(keyNode.textContent).toBe("hm_agt_shownonce");
    expect(button.textContent).toBe("Hide bearer");
    expect(attrs["aria-pressed"]).toBe("true");
    expect(await s3.render(ctx)).toContain("hm_agt_shownonce");

    (s3.actions!["badge-key-visibility"] as Action)(ctx, button as never);
    expect(keyNode.textContent).toContain("••••");
    expect(await s3.render(ctx)).not.toContain("hm_agt_shownonce");
    await reset(s3);
  });

  it("refuses to create a badge with no name and says so", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ routes: { get: agentControlRoutes() } });
    const values: Record<string, { value?: string }> = {
      "#badge-name": { value: "" },
      "#badge-team": { value: "acme" },
    };
    const root = { querySelector: (selector: string) => values[selector] ?? null };
    await (s3.actions!["badge-create"] as Action)(
      ctx, { disabled: false, textContent: "", closest: () => root } as never,
    );
    expect(calls.every((call) => call.method !== "POST")).toBe(true);
    const html = await s3.render(ctx);
    expect(html).toContain("Give the badge a name.");
    // What was already chosen survives the repaint.
    expect(html).toContain('id="badge-team"');
    await reset(s3);
  });

  it("B1: a connector in another namespace is never offered to this badge", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    // The badge lives in `acme`; the only connector belongs to another tenant.
    routes["/v1/admin/sources"] = {
      sources: [{ id: "source-other", kind: "postgres", namespace: "halofy", lifecycleState: "active" }],
    };
    routes["/v1/admin/agent-connections"] = [];
    const { ctx } = makeCtx({ routes: { get: routes } });
    const html = await s3.render(ctx);
    expect(html).toContain('data-action="badge-expand" data-id="01BADGE"');
    await (s3.actions!["badge-expand"] as Action)(ctx, {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
    } as never);
    const detailHtml = await s3.render(ctx);
    expect(detailHtml).toContain("Memory only");
    expect(detailHtml).not.toContain("source-other");
    expect(detailHtml).not.toContain('data-action="agent-source-open"');
    await reset(s3);
  });

  it("lets an admin reveal the same encrypted badge bearer repeatedly", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/keys"] = [{
      id: "01BADGE", actor: "repeat-agent", namespace: "acme", role: "agent",
      status: "active", bearerRevealable: true,
    }];
    const { ctx, calls } = makeCtx({ routes: {
      get: routes,
      post: { "/v1/admin/keys/01BADGE/reveal": {
        plaintext: "hm_agt_repeatable",
        record: {
          id: "01BADGE", actor: "repeat-agent", namespace: "acme", role: "agent",
          agentAccessLevel: "member", agentCanWrite: true,
        },
      } },
    } });
    await (s3.actions!["badge-expand"] as Action)(ctx, {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
    } as never);
    const detail = await s3.render(ctx);
    expect(detail).toContain('data-action="key-reveal" data-id="01BADGE"');

    const status = { textContent: "" };
    const button = {
      disabled: false,
      textContent: "Reveal bearer",
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
      closest: () => ({ querySelector: () => status }),
    };
    await (s3.actions!["key-reveal"] as Action)(ctx, button as never);
    expect(button.disabled).toBe(false);
    expect(button.textContent).toBe("Reveal bearer");
    expect(await s3.render(ctx)).toContain("hm_agt_repeatable");
    await (s3.actions!["key-reveal"] as Action)(ctx, button as never);
    expect(calls.filter((call) => call.path === "/v1/admin/keys/01BADGE/reveal")).toHaveLength(2);
    await reset(s3);
  });

  it("tells admins that legacy badges need rotation before reveal", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/keys"] = [{
      id: "01BADGE", actor: "legacy-agent", namespace: "acme", role: "agent",
      status: "active", bearerRevealable: false,
    }];
    const { ctx } = makeCtx({ routes: { get: routes } });
    await (s3.actions!["badge-expand"] as Action)(ctx, {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
    } as never);
    const detail = await s3.render(ctx);
    expect(detail).toContain("Reveal unavailable");
    expect(detail).toContain("Rotate this legacy badge once to enable repeated reveal");
    expect(detail).not.toContain('data-action="key-reveal"');
    await reset(s3);
  });

  it("grants source access against the existing badge, not a fresh one", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ routes: { post: { "/v1/admin/agent-connections": { id: "grant-2" } } } });
    const values: Record<string, { value?: string }> = {
      "#src-connector-01BADGE": { value: "source-1" },
      "#src-refs-01BADGE": { value: "support.refunds" },
      "#src-fields-01BADGE": { value: "support.refunds: ticket_id, status" },
      "#src-purposes-01BADGE": { value: "resolve refunds" },
      "#src-sensitivity-01BADGE": { value: "confidential" },
      "#src-rows-01BADGE": { value: "25" },
      "#src-mb-01BADGE": { value: "1" },
      "#src-rate-01BADGE": { value: "60" },
    };
    const root = { querySelector: (selector: string) => values[selector] ?? null };
    const button = {
      disabled: false, textContent: "Grant source access",
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
      closest: () => root,
    };
    await (s3.actions!["agent-source-submit"] as Action)(ctx, button);
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: "/v1/admin/agent-connections",
      body: {
        keyId: "01BADGE",
        connectorId: "source-1",
        allowedOperations: ["source-read"],
        allowedSourceRefs: ["support.refunds"],
        allowedFields: { "support.refunds": ["ticket_id", "status"] },
        allowedPurposes: ["resolve refunds"],
        maxSensitivity: "confidential",
        maxRows: 25,
        maxBytes: 1048576,
        expiresAt: null,
        oversight: {
          maxRequestsPerMinute: 60,
          usageAlertThreshold: 100,
          deniedAlertThreshold: 1,
          recipientRoles: ["owner", "admin"],
          accessRequests: "allowed",
          approvalTtlSeconds: 3600,
        },
      },
    });
    await reset(s3);
  });

  it("D51: an expired credential reads as expired and cannot be rotated", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/keys"] = [{
      id: "01OLD", actor: "stale-agent", namespace: "acme", role: "agent",
      status: "active", createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-02-01T00:00:00.000Z", expired: true,
    }];
    const { ctx } = makeCtx({ routes: { get: routes } });
    const html = await s3.render(ctx);
    expect(html).toContain('<span class="pill pill--warn"><i class="dot"></i>expired</span>');
    expect(html).not.toContain('data-action="key-rotate" data-id="01OLD"');
    expect(html).toContain('data-action="key-revoke" data-id="01OLD"');
  });

  it("the filter strip narrows the ledger to live or revoked badges", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const routes = agentControlRoutes();
    routes["/v1/admin/keys"] = [
      { id: "01LIVE", actor: "live-agent", namespace: "acme", role: "agent", status: "active" },
      { id: "01DEAD", actor: "dead-agent", namespace: "acme", role: "agent", status: "revoked" },
    ];
    const { ctx } = makeCtx({ routes: { get: routes } });

    let html = await s3.render(ctx);
    expect(html).toContain("Active 2");
    expect(html).toContain("Revoked 1");
    expect(html).toContain("live-agent");
    expect(html).not.toContain("dead-agent");

    await (s3.actions!["badge-filter"] as Action)(ctx, { getAttribute: () => "revoked" } as never);
    html = await s3.render(ctx);
    expect(html).toContain("dead-agent");
    expect(html).not.toContain("live-agent");

    await (s3.actions!["badge-filter"] as Action)(ctx, { getAttribute: () => "all" } as never);
    html = await s3.render(ctx);
    expect(html).toContain("dead-agent");
    expect(html).toContain("live-agent");
    await reset(s3);
  });

  it("owner sees create/revoke but no human invitation controls; hostile actor is escaped", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({ role: "owner", routes: { get: { "/v1/admin/people": people() } } });
    const html = await s3.render(ctx);
    expect(html).not.toContain('data-action="people-invite"');
    expect(html).toContain('data-action="badge-create"');
    expect(html).toContain('data-action="key-revoke"');
    expect(html).not.toContain("Create an activation link");
    expect(html).not.toContain("Human logins");
    assertNoRawImg(html);
  });

  it("auditor sees the badge ledger read-only and never fetches the key listing", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx, calls } = makeCtx({ role: "auditor", routes: { get: agentControlRoutes() } });
    const html = await s3.render(ctx);
    expect(html).toContain('data-action="badge-expand" data-id="01BADGE"');
    await (s3.actions!["badge-expand"] as Action)(ctx, {
      getAttribute: (name: string) => name === "data-id" ? "01BADGE" : null,
    } as never);
    const detailHtml = await s3.render(ctx);
    expect(detailHtml).toContain("source-1 - 25 rows / 1 MB / 60 per min");
    expect(html).not.toContain('data-action="people-invite"');
    expect(html).not.toContain('data-action="badge-create"');
    expect(html).not.toContain('data-action="key-revoke"');
    expect(html).not.toContain('data-action="key-rotate"');
    expect(html).not.toContain('data-action="agent-source-open"');
    // GET /v1/admin/keys is owner/admin-only server-side: the auditor must
    // neither fetch it (the 403 would be swallowed) nor be shown a false
    // "No credentials yet." empty state (audit finding).
    expect(detailHtml).not.toContain("Scope memory access");
    const readCycle = [
      "/v1/admin/people",
      "/v1/admin/sources",
      "/v1/admin/agent-connections",
      "/v1/admin/agent-access/alerts?status=open&limit=50",
      "/v1/admin/agent-access/requests?status=pending&limit=50",
    ];
    expect(calls.map((call) => call.path)).toEqual([...readCycle, ...readCycle]);
    expect(calls.some((call) => call.path === "/v1/admin/keys")).toBe(false);
    assertNoRawImg(detailHtml);
    await reset(s3);
  });

  it("member sees badge identities read-only", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({ role: "member", routes: { get: { "/v1/admin/people": people() } } });
    const html = await s3.render(ctx);
    expect(html).not.toContain('data-action="badge-revoke"');
  });

  it("a fresh tenant does not render a human roster", async () => {
    const s3 = await loadScreen("s3");
    await reset(s3);
    const { ctx } = makeCtx({ routes: { get: { "/v1/admin/people": { users: [], badges: [] } } } });
    const html = await s3.render(ctx);
    expect(html).not.toContain("No people yet");
    expect(html).not.toContain("Human logins");
    expect(html).toContain("No active badges.");
  });
});

// ---------------------------------------------------------------------------
// S19 - Alerts inbox
// ---------------------------------------------------------------------------

describe("s19 - alerts", () => {
  type Action = (ctx: unknown, el: unknown) => Promise<void> | void;

  // The 2026-08 overhaul turned S19 from the agent gateway's private inbox into
  // the platform inbox: two lanes ("Action Required" / "For Your Information")
  // over nine feeds that already existed on other screens. No new authority —
  // every read and every decision below is an endpoint the server already gated.
  const REQUESTS = "/v1/admin/agent-access/requests?limit=100&status=pending";
  const CLIENTS = "/v1/admin/oauth/clients";
  const CONFLICTS = "/v1/admin/conflicts";
  const PROPOSALS = "/v1/admin/proposals";
  const ALERTS = "/v1/admin/agent-access/alerts?limit=100&status=open";
  const OVERVIEW = "/v1/admin/overview";
  const SOURCES = "/v1/admin/sources";
  const AUDIT = "/v1/admin/audit?limit=50";
  const KEYS = "/v1/admin/keys";
  const FEEDS = [REQUESTS, CLIENTS, CONFLICTS, PROPOSALS, ALERTS, OVERVIEW, SOURCES, AUDIT, KEYS];

  const routes = () => ({
    [ALERTS]: [{
      id: "alert-1",
      keyId: "01BADGE",
      kind: "outside-scope",
      severity: "critical",
      recipientRoles: ["owner", "admin"],
      status: "open",
      createdAt: "2026-07-17T10:05:00.000Z",
    }],
    [REQUESTS]: [{
      id: "request-1",
      keyId: "01BADGE",
      sourceRef: "support.chargebacks",
      purpose: "review chargeback",
      requestedFields: ["case_id"],
      requestedRows: 10,
      justification: XSS,
      requestedDurationSeconds: 1800,
      status: "pending",
      createdAt: "2026-07-17T10:06:00.000Z",
    }],
    [CLIENTS]: [{ id: "client-1", name: "Claude Desktop", status: "pending", createdAt: "2026-07-17T10:07:00.000Z" }],
    [CONFLICTS]: { disputes: [], findings: [] },
    [PROPOSALS]: [],
    [OVERVIEW]: { spend: { effectiveCapUsd: 100, monthToDateUsd: 10 } },
    [SOURCES]: [],
    [AUDIT]: [],
    [KEYS]: [
      { id: "01BADGE", actor: "support-copilot", namespace: "acme", role: "agent", status: "active" },
    ],
  });

  const emptyRoutes = () => ({
    [ALERTS]: [],
    [REQUESTS]: [],
    [CLIENTS]: [],
    [CONFLICTS]: { disputes: [], findings: [] },
    [PROPOSALS]: [],
    [OVERVIEW]: { spend: { effectiveCapUsd: 100, monthToDateUsd: 10 } },
    [SOURCES]: [],
    [AUDIT]: [],
    [KEYS]: [],
  });

  it("collects every platform alert into two lanes, named in plain language", async () => {
    const s19 = await loadScreen("s19");
    const { ctx, calls } = makeCtx({ routes: { get: routes() } });
    const html = await s19.render(ctx);

    expect(html).toContain("<h1>Alerts</h1>");
    expect(html).toContain("Action Required");
    expect(html).toContain("For Your Information");
    // The agent is named, never identified by its key id.
    expect(html).toContain("support-copilot is asking for access");
    expect(html).toContain("support-copilot tried to reach data outside its access");
    // A second subsystem's approval now lands in the same inbox.
    expect(html).toContain("Claude Desktop wants to connect");
    expect(html).toContain('data-action="alerts-approve"');
    expect(html).toContain('data-action="alerts-deny"');
    expect(html).toContain('data-action="alerts-acknowledge"');
    expect(html).toContain('data-action="alerts-app-approve"');
    expect(calls.map((call) => call.path).sort()).toEqual(FEEDS.slice().sort());
    assertNoRawImg(html);
  });

  it("rides Home's design system rather than inventing a second one", async () => {
    const s19 = await loadScreen("s19");
    const { ctx } = makeCtx({ routes: { get: routes() } });
    const html = await s19.render(ctx);

    expect(html).toContain('class="home-overview alert-inbox"');
    expect(html).toContain('class="head home-head"');
    expect(html).toContain('class="home-metrics"');
    expect(html).toContain('class="home-dashboard"');
    expect(html).toContain("card home-panel alert-lane");
    // Status is carried by the shared pill, never painted onto the row.
    expect(html).not.toContain("alert-item--crit");
    // No status filter: an inbox shows open work, and the old toggle only
    // relaxed a filter so both of its states rendered the identical lanes.
    expect(html).not.toContain("home-range-control");
    expect(html).not.toContain("alerts-tab");
  });

  it("says nothing is waiting instead of leaving an empty lane bare", async () => {
    const s19 = await loadScreen("s19");
    const { ctx } = makeCtx({ routes: { get: emptyRoutes() } });
    const html = await s19.render(ctx);

    expect(html).toContain("No items are awaiting your decision.");
    expect(html).toContain("Nothing to report.");
    expect(html).not.toContain("Unavailable");
  });

  it("renders an unavailable feed distinctly from a real zero", async () => {
    const s19 = await loadScreen("s19");
    const partial = emptyRoutes() as Record<string, unknown>;
    delete partial[ALERTS];
    const { ctx } = makeCtx({ routes: { get: partial } });
    const html = await s19.render(ctx);

    // One refusal costs exactly one group, and says so where that group lives.
    expect(html).toContain("Agent activity");
    expect(html).toContain("1 check unavailable");
    expect(html).toContain("Unavailable");
    expect(html).not.toContain("Nothing to report.");
    // The lane that answered still reports its real zero.
    expect(html).toContain("No items are awaiting your decision.");
  });

  it("treats a malformed successful payload as unavailable", async () => {
    const s19 = await loadScreen("s19");
    const broken = emptyRoutes() as Record<string, unknown>;
    broken[PROPOSALS] = { proposals: null };
    broken[SOURCES] = { sources: 7 };
    const { ctx } = makeCtx({ routes: { get: broken } });
    const html = await s19.render(ctx);

    expect(html).toContain("Knowledge awaiting review");
    expect(html).toContain("Connected sources and channels");
    expect(html).toContain("2 checks unavailable");
  });

  it("keeps already-decided rows out of Action Required", async () => {
    const s19 = await loadScreen("s19");
    const decided = routes() as Record<string, unknown>;
    // Every one of these endpoints returns settled rows alongside open ones.
    decided[CLIENTS] = [
      { id: "client-1", name: "Claude Desktop", status: "pending", createdAt: "2026-07-17T10:07:00.000Z" },
      { id: "client-2", name: "Old Integration", status: "revoked", createdAt: "2026-07-01T10:00:00.000Z" },
      { id: "client-3", name: "Live Integration", status: "approved", createdAt: "2026-07-02T10:00:00.000Z" },
    ];
    decided[PROPOSALS] = [
      { id: "p-1", status: "published", draft: { title: "Already published" } },
      { id: "p-2", status: "rejected", draft: { title: "Already rejected" } },
    ];
    decided[CONFLICTS] = {
      disputes: [{ id: "d-1", status: "resolved", reason: "Already settled" }],
      findings: [],
    };
    const { ctx } = makeCtx({ routes: { get: decided } });
    const html = await s19.render(ctx);

    expect(html).toContain("Claude Desktop wants to connect");
    // A decided row carries no buttons, so it would sit in a lane titled
    // "Action Required" with nothing to action. It must not appear at all.
    expect(html).not.toContain("Old Integration");
    expect(html).not.toContain("Live Integration");
    expect(html).not.toContain("Already published");
    expect(html).not.toContain("Already rejected");
    expect(html).not.toContain("Already settled");
  });

  it("posts the decision the operator actually clicked", async () => {
    const s19 = await loadScreen("s19");
    const { ctx, calls } = makeCtx({ routes: {
      get: routes(),
      post: {
        "/v1/admin/agent-access/requests/request-1/approve": {},
        "/v1/admin/agent-access/alerts/alert-1/acknowledge": {},
        "/v1/admin/oauth/clients/client-1/approve": {},
        "/v1/admin/oauth/clients/client-1/revoke": {},
      },
    } });
    const status = { textContent: "" };
    const card = { querySelector: () => status };
    const el = (id: string) => ({
      disabled: false,
      textContent: "",
      getAttribute: (name: string) => name === "data-id" ? id : null,
      closest: () => card,
    });
    await (s19.actions!["alerts-approve"] as Action)(ctx, el("request-1"));
    await (s19.actions!["alerts-acknowledge"] as Action)(ctx, el("alert-1"));
    await (s19.actions!["alerts-app-approve"] as Action)(ctx, el("client-1"));
    await (s19.actions!["alerts-app-deny"] as Action)(ctx, el("client-1"));

    expect(calls.filter((call) => call.method === "POST")).toEqual([
      { method: "POST", path: "/v1/admin/agent-access/requests/request-1/approve", body: {} },
      { method: "POST", path: "/v1/admin/agent-access/alerts/alert-1/acknowledge", body: {} },
      { method: "POST", path: "/v1/admin/oauth/clients/client-1/approve", body: {} },
      {
        method: "POST",
        path: "/v1/admin/oauth/clients/client-1/revoke",
        body: { reason: "Denied from Alerts" },
      },
    ]);
  });

  it("refuses to render a false all-clear for a role the server would block", async () => {
    const s19 = await loadScreen("s19");
    const { ctx, calls } = makeCtx({ role: "auditor" });
    const html = await s19.render(ctx);
    expect(calls).toEqual([]);
    expect(html).toContain("Alerts are an owner and admin view");
    expect(html).not.toContain("Nothing to report.");
  });
});

// ---------------------------------------------------------------------------
// S4 — Policy dials
// ---------------------------------------------------------------------------

describe("s4 - policy", () => {
  const documentsPath =
    "/v1/admin/policy-documents?namespace=acme&page=1&pageSize=20";
  const policy = (extra: Record<string, unknown> = {}) => ({
    namespace: "acme",
    tokenBudget: 8000,
    ttlDefaultsSeconds: { user: 2592000 },
    pinnedConcepts: [],
    verifierEnabled: true,
    rateLimitPerMin: 60,
    monthlyBudgetUsd: 500,
    retriever: "graph",
    ...extra,
  });

  const documents = (extra: Record<string, unknown> = {}) => ({
    data: [
      {
        id: "01J00000000000000000000041",
        sourceId: "01J00000000000000000000042",
        namespace: "acme",
        title: "Customer returns policy",
        kind: "policy",
        status: "active",
        fileName: "returns-policy.md",
        mediaType: "text/markdown",
        byteSize: 18432,
        contentSha256: "a".repeat(64),
        factCount: 14,
        failureCode: null,
        createdBy: "owner@acme.test",
        createdAt: "2026-07-16T12:00:00.000Z",
        loadedAt: "2026-07-16T12:00:02.000Z",
      },
    ],
    pagination: { page: 1, pageSize: 20, total: 1, totalPages: 1 },
    summary: { total: 1, active: 1, needsReview: 0, failed: 0 },
    ...extra,
  });

  it("leads with a scalable policy register and governed upload, with no scope or state controls", async () => {
    const s4 = await loadScreen("s4");
    const hostile = documents();
    hostile.data[0]!.title = XSS;
    hostile.data[0]!.fileName = `guide-${XSS}.md`;
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          [documentsPath]: hostile,
          "/v1/admin/policy?namespace=acme": policy(),
        },
      },
    });

    const html = await s4.render(ctx);
    expect(html).toContain("<h1>Policies</h1>");
    expect(html).toContain("Policy Register");
    // The scope typeahead, the document-type cut and the state tab strip are
    // gone from the register head; the scope now comes from the hash alone, so
    // the screen no longer spends a round trip discovering namespaces.
    expect(html).not.toContain('id="policy-scope"');
    expect(html).not.toContain('id="policy-filter-kind"');
    expect(html).not.toContain('class="policy-filters"');
    expect(html).not.toContain('data-action="policy-status-tab"');
    expect(html).not.toContain("Current scope:");
    expect(calls).not.toContainEqual({
      method: "GET",
      path: "/v1/admin/policy-scopes?limit=50",
    });
    // The state the register filters on survives as a field the needs-review
    // flag and the clear action still drive.
    expect(html).toContain('id="policy-filter-status"');
    expect(html).toContain('type="file"');
    expect(html).toContain(".txt,.md,.markdown,.csv,.json,.yaml,.yml");
    expect(html).toContain('data-action="policy-file-upload"');
    expect(html).toContain("Classify &amp; Extract");
    expect(html).toContain("Verify &amp; Provenance");
    expect(html).toContain("Agent-Ready");
    expect(html).toContain('<details class="policy-runtime">');
    expect(html).not.toContain('<details class="policy-runtime" open>');
    assertNoRawImg(html);
  });

  it("shows an honest empty register and keeps upload absent for read-only roles", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: {
        get: {
          "/v1/admin/policy-scopes?limit=50": { data: [], hasMore: false },
          [documentsPath]: documents({
            data: [],
            pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 },
            summary: { total: 0, active: 0, needsReview: 0, failed: 0 },
          }),
          "/v1/admin/policy?namespace=acme": policy(),
        },
      },
    });

    const html = await s4.render(ctx);
    expect(html).toContain("No policy files");
    expect(html).toContain("Read-only policy register");
    expect(html).not.toContain('data-action="policy-file-upload"');
    expect(html).not.toContain('id="policy-file"');
    expect(html).toContain('id="dial-retriever" disabled');
  });

  it("renders one card per policy file, with the delete that retracts its facts", async () => {
    const s4 = await loadScreen("s4");
    const registered = documents();
    registered.data[0]!.origin = "adopted";
    registered.data[0]!.fileName = `returns-${XSS}.md`;
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/policy-scopes?limit=50": { data: [], hasMore: false },
          [documentsPath]: registered,
          "/v1/admin/policy?namespace=acme": policy(),
        },
      },
    });

    const html = await s4.render(ctx);
    expect(html).toContain('class="policy-rows"');
    expect(html).toContain('data-policy-document="01J00000000000000000000041"');
    expect(html).toContain("Customer returns policy");
    // The whole point of the card: the delete is on screen, not behind a row
    // action, and it names how many facts leave active memory with it.
    expect(html).toContain('data-action="policy-document-delete"');
    expect(html).toContain('data-facts="14"');
    expect(html).toContain("Adopted From Memory");
    expect(html).toContain("Facts in memory");
    assertNoRawImg(html);
  });

  it("surfaces policy files that are in memory but absent from the register", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/policy-scopes?limit=50": { data: [], hasMore: false },
          [documentsPath]: documents({
            data: [],
            pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 },
            summary: { total: 0, active: 0, needsReview: 0, failed: 0 },
          }),
          "/v1/admin/policy-adoption-candidates?namespace=acme&limit=25": {
            data: [
              {
                sourceId: "01J00000000000000000000042",
                namespace: "acme",
                fileName: `policies-${XSS}.csv`,
                title: XSS,
                mediaType: "text/csv",
                documentCount: 5,
                factCount: 5,
                byteSize: 900,
                signal: "both",
                firstSeenAt: "2026-07-11T07:53:59.000Z",
                lastSeenAt: "2026-07-11T07:54:00.000Z",
              },
            ],
            hasMore: false,
          },
          "/v1/admin/policy?namespace=acme": policy(),
        },
      },
    });

    const html = await s4.render(ctx);
    expect(html).toContain("Found In Memory");
    expect(html).toContain("In Memory, Unregistered");
    expect(html).toContain('data-action="policy-adopt"');
    expect(html).toContain("Matched by file name and content");
    // An empty REGISTER is still reported honestly next to the found files.
    expect(html).toContain("No policy files");
    expect(html).not.toContain(XSS);
    assertNoRawImg(html);
  });

  it("adopts an already-landed file by pointer only, never by content", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const status = { textContent: "", setAttribute() {} };
    const root = {
      querySelector: (selector: string) =>
        selector === "[data-policy-adoption-status]" ? status : null,
    };
    const attributes = new Map([
      ["data-file", "policies.csv"],
      ["data-source", "01J00000000000000000000042"],
      ["data-namespace", "acme"],
      ["data-title", "Policies"],
    ]);
    const el = {
      disabled: false,
      closest: () => root,
      getAttribute: (name: string) => attributes.get(name) ?? null,
    };
    const { ctx, calls } = makeCtx({
      routes: {
        post: { "/v1/admin/policy-documents/adopt": { id: "doc-2", status: "active" } },
      },
    });

    await s4.actions["policy-adopt"]!(ctx, el);

    expect(calls).toContainEqual({
      method: "POST",
      path: "/v1/admin/policy-documents/adopt",
      body: { namespace: "acme", fileName: "policies.csv", sourceId: "01J00000000000000000000042" },
    });
  });

  it("renders a bounded library error without hiding the runtime dials", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/policy-scopes?limit=50": { data: [], hasMore: false },
          [documentsPath]: () => {
            throw { status: 503, message: XSS };
          },
          "/v1/admin/policy?namespace=acme": policy(),
        },
      },
    });

    const html = await s4.render(ctx);
    expect(html).toContain("Policy files are temporarily unavailable");
    expect(html).toContain('data-action="policy-library-retry"');
    expect(html).toContain("Runtime");
    assertNoRawImg(html);
  });

  it("validates a text file and posts only the governed upload contract", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const status = { textContent: "", setAttribute() {} };
    const controls = new Map<string, unknown>([
      ["#policy-file", {
        files: [{
          name: "agent-guidance.md",
          size: 29,
          async text() { return "Agents must cite source policy."; },
        }],
        value: "selected",
      }],
      ["#policy-title", { value: "Agent citation guide" }],
      ["#policy-kind", { value: "guideline" }],
      ["#policy-enforcement", { value: "advisory" }],
      // The upload reads its scope off the rendered section, not a control:
      // the scope picker is gone and the hash is the only scope authority.
      [".policy-library", { getAttribute: () => "acme" }],
      ["[data-policy-upload-status]", status],
    ]);
    const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
    const el = { disabled: false, closest: () => root };
    const { ctx, calls } = makeCtx({
      routes: { post: { "/v1/admin/policy-documents": { id: "doc-1", status: "active" } } },
    });

    await s4.actions["policy-file-upload"]!(ctx, el);

    expect(calls).toContainEqual({
      method: "POST",
      path: "/v1/admin/policy-documents",
      body: {
        // The guardrail level rides the same governed upload contract; the
        // server re-derives every other field and never trusts the caller.
        enforcement: "advisory",
        namespace: "acme",
        title: "Agent citation guide",
        kind: "guideline",
        fileName: "agent-guidance.md",
        content: "Agents must cite source policy.",
      },
    });
    expect(status.textContent).toContain("loaded");
    expect(status.textContent).toContain("agent-ready");
  });

  it("announces failed and needs-review upload responses without claiming agent readiness", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };

    for (const scenario of [
      { response: "failed", expected: "could not be loaded" },
      { response: "needs_review", expected: "needs review" },
    ]) {
      const status = { textContent: "", role: "", setAttribute(_name: string, value: string) { this.role = value; } };
      const controls = new Map<string, unknown>([
        ["#policy-file", {
          files: [{ name: "safety-policy.md", size: 20, async text() { return "Never expose secrets."; } }],
        }],
        ["#policy-title", { value: "" }],
        ["#policy-kind", { value: "policy" }],
        ["#policy-scope", { value: "acme" }],
        ["[data-policy-upload-status]", status],
      ]);
      const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
      const el = { disabled: false, closest: () => root };
      const { ctx } = makeCtx({
        routes: { post: { "/v1/admin/policy-documents": { id: "doc-state", status: scenario.response } } },
      });

      await s4.actions["policy-file-upload"]!(ctx, el);

      expect(status.textContent).toContain(scenario.expected);
      expect(status.textContent).not.toContain("agent-ready");
      if (scenario.response === "failed") expect(status.role).toBe("alert");
    }
  });

  it("rejects unsupported and oversized files before any API call", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const status = { textContent: "", setAttribute() {} };
    const fileInput: {
      files: { name: string; size: number; text(): Promise<string> }[];
    } = {
      files: [{ name: "policy.pdf", size: 100, async text() { return "pdf"; } }],
    };
    const controls = new Map<string, unknown>([
      ["#policy-file", fileInput],
      ["#policy-title", { value: "" }],
      ["#policy-kind", { value: "policy" }],
      ["#policy-scope", { value: "acme" }],
      ["[data-policy-upload-status]", status],
    ]);
    const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
    const el = { disabled: false, closest: () => root };
    const { ctx, calls } = makeCtx();

    await s4.actions["policy-file-upload"]!(ctx, el);
    expect(status.textContent).toContain("supported text file");
    expect(calls).toEqual([]);

    fileInput.files = [{
      name: "policy.md",
      size: 524289,
      async text() { return "too large"; },
    }];
    await s4.actions["policy-file-upload"]!(ctx, el);
    expect(status.textContent).toContain("512 KiB");
    expect(calls).toEqual([]);
  });

  it("applies literal filters through the paginated policy-document endpoint", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const register = { innerHTML: "", setAttribute() {} };
    const pagination = { innerHTML: "" };
    const summary = { outerHTML: "" };
    const controls = new Map<string, unknown>([
      ["[data-policy-register]", register],
      ["[data-policy-pagination]", pagination],
      ["[data-policy-summary]", summary],
      ["#policy-scope", { value: "acme" }],
      ["#policy-query", { value: "refund & returns" }],
      ["#policy-filter-kind", { value: "guideline" }],
      ["#policy-filter-status", { value: "active" }],
    ]);
    const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
    const el = { closest: () => root };
    const filteredPath =
      "/v1/admin/policy-documents?namespace=acme&page=1&pageSize=20&query=refund+%26+returns&kind=guideline&status=active";
    const { ctx, calls } = makeCtx({ routes: { get: { [filteredPath]: documents() } } });

    await s4.actions["policy-library-filter"]!(ctx, el);

    expect(calls).toEqual([{ method: "GET", path: filteredPath }]);
    expect(register.innerHTML).toContain("Customer returns policy");
    expect(register.innerHTML).not.toContain("<img");
  });

  it("distinguishes a filtered miss and clears stale summary state after load errors", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const register = { innerHTML: "", setAttribute() {} };
    const pagination = { innerHTML: "stale pagination" };
    const summary = { outerHTML: "stale summary" };
    const controls = new Map<string, unknown>([
      ["[data-policy-register]", register],
      ["[data-policy-pagination]", pagination],
      ["[data-policy-summary]", summary],
      ["#policy-query", { value: "missing" }],
      ["#policy-filter-kind", { value: "" }],
      ["#policy-filter-status", { value: "" }],
    ]);
    const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
    const el = { closest: () => root };
    const filteredPath =
      "/v1/admin/policy-documents?namespace=acme&page=1&pageSize=20&query=missing";
    const { ctx } = makeCtx({
      routes: { get: { [filteredPath]: documents({
        data: [],
        pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 },
        summary: { total: 3, active: 3, needsReview: 0, failed: 0 },
      }) } },
    });

    await s4.actions["policy-library-filter"]!(ctx, el);
    expect(register.innerHTML).toContain("No policies match these filters");
    expect(register.innerHTML).toContain('data-action="policy-library-clear"');

    ctx.api.get = async () => {
      throw { status: 503, message: "temporary outage" };
    };
    pagination.innerHTML = "stale pagination";
    await s4.actions["policy-library-retry"]!(ctx, el);
    expect(register.innerHTML).toContain("temporarily unavailable");
    expect(pagination.innerHTML).toBe("");
    expect(summary.outerHTML).toContain("summary unavailable");
  });

  it("ignores an older filter response that completes after a newer request", async () => {
    const s4 = await loadScreen("s4") as unknown as {
      actions: Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    };
    const register = { innerHTML: "", setAttribute() {} };
    const pagination = { innerHTML: "" };
    const summary = { outerHTML: "" };
    const query = { value: "first" };
    const controls = new Map<string, unknown>([
      ["[data-policy-register]", register],
      ["[data-policy-pagination]", pagination],
      ["[data-policy-summary]", summary],
      ["#policy-query", query],
      ["#policy-filter-kind", { value: "" }],
      ["#policy-filter-status", { value: "" }],
    ]);
    const root = { querySelector: (selector: string) => controls.get(selector) ?? null };
    const el = { closest: () => root };
    let resolveFirst!: (value: unknown) => void;
    let resolveSecond!: (value: unknown) => void;
    const first = new Promise((resolve) => { resolveFirst = resolve; });
    const second = new Promise((resolve) => { resolveSecond = resolve; });
    const { ctx } = makeCtx();
    ctx.api.get = async (path: string) => path.includes("query=first") ? first : second;

    const older = s4.actions["policy-library-filter"]!(ctx, el);
    query.value = "second";
    const newer = s4.actions["policy-library-filter"]!(ctx, el);
    const newerRows = documents();
    newerRows.data[0]!.title = "Newer result";
    resolveSecond(newerRows);
    await newer;
    const olderRows = documents();
    olderRows.data[0]!.title = "Older result";
    resolveFirst(olderRows);
    await older;

    expect(register.innerHTML).toContain("Newer result");
    expect(register.innerHTML).not.toContain("Older result");
  });

  it("ships a compact pagination control and responsive mobile register styles", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({ routes: { get: {
      "/v1/admin/policy-scopes?limit=50": { data: [], hasMore: false },
      [documentsPath]: documents({
        pagination: { page: 1, pageSize: 20, total: 41, totalPages: 3 },
      }),
      "/v1/admin/policy?namespace=acme": policy(),
    } } });
    const html = await s4.render(ctx);
    expect(html).toContain("Page 1 of 3");
    expect(html).toContain('data-action="policy-library-page" data-page="2"');

    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );
    expect(css).toMatch(/@media\(max-width:720px\)[\s\S]*\.policy-table td::before/);
    expect(css).toContain(".policy-upload-fields{display:grid;grid-template-columns:minmax(0,1fr)");
  });

  it("keeps the platform owner's empty namespace as the register's scope", async () => {
    const s4 = await loadScreen("s4");
    const rootDocumentsPath =
      "/v1/admin/policy-documents?namespace=&page=1&pageSize=20";
    const { ctx, calls } = makeCtx({
      namespace: "",
      routes: { get: {
        [rootDocumentsPath]: documents({ data: [] }),
        "/v1/admin/policy?namespace=": policy({ namespace: "" }),
      } },
    });

    const html = await s4.render(ctx);
    // The section attribute is the scope authority now that the picker is
    // gone - the upload and every in-place refresh read it from here.
    expect(html).toContain('<section class="policy-library" data-policy-scope=""');
    expect(calls).toContainEqual({ method: "GET", path: rootDocumentsPath });
    expect(calls).toContainEqual({ method: "GET", path: "/v1/admin/policy?namespace=" });
  });

  it("renders the dials seeded with the effective policy; save control present", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({ routes: { get: { "/v1/admin/policy?namespace=acme": policy() } } });
    const html = await s4.render(ctx);
    expect(html).toContain('data-action="policy-save"');
    expect(html).toContain("graph"); // effective retriever
    expect(html).toContain("500"); // effective cap
    expect(html).toContain("LLM fact verifier");
    expect(html).toContain("Verify extracted (non-verbatim) facts before storage");
    expect(html).not.toContain("Handbook visibility");
    expect(html).not.toMatch(/inherited from/i);
    expect(html).not.toContain("Every dial shows");
    // Owner's dials are live (editable) — no disabled attribute on the inputs.
    expect(html).not.toContain("disabled");
    expect(html).not.toContain("<img");
  });

  it("auditor sees the dials read-only - NO Save button, every dial disabled", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: { get: { "/v1/admin/policy?namespace=acme": policy() } },
    });
    const html = await s4.render(ctx);
    // The one mutating control must be gone — an auditor gets no live-looking Save.
    expect(html).not.toContain('data-action="policy-save"');
    expect(html).not.toContain(">Save changes<");
    expect(html).toContain("Read-only");
    // Every editable dial is disabled (defense in depth — the server 403s too).
    expect(html).toContain('id="dial-retriever" disabled');
    expect(html).toContain('id="dial-expiry" disabled');
    expect(html).toContain('inputmode="decimal" disabled'); // spend input
    expect(html).toContain('inputmode="numeric" disabled'); // rate input
    expect(html).toContain('id="dial-verifier"'); // verifier toggle present
    // No live, non-disabled dial input survives for an auditor.
    expect(html).not.toContain('inputmode="decimal">');
    // The dials still render the effective policy for reading.
    expect(html).toContain("graph");
    expect(html).not.toContain("<img");
  });

  it("member sees the dials read-only too - no Save", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      role: "member",
      routes: { get: { "/v1/admin/policy?namespace=acme": policy() } },
    });
    const html = await s4.render(ctx);
    expect(html).not.toContain('data-action="policy-save"');
  });

  it("a hostile retriever value never reaches the dial markup", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      routes: { get: { "/v1/admin/policy?namespace=acme": policy({ retriever: XSS }) } },
    });
    const html = await s4.render(ctx);
    // The effective-value hint that used to echo this back is gone, so the
    // server's value now only picks a <option selected> out of the fixed
    // RETRIEVERS list. It must not appear in the output in ANY form - raw
    // (an injection) or escaped (a value the dial never offered).
    expect(html).not.toContain("<img");
    expect(html).not.toContain(XSS);
    expect(html).not.toContain(XSS_ESCAPED);
  });

  it("a policy with no retriever/cap/ttl still renders (fresh-tenant defaults)", async () => {
    const s4 = await loadScreen("s4");
    const { ctx } = makeCtx({
      routes: { get: { "/v1/admin/policy?namespace=acme": { namespace: "acme", pinnedConcepts: [], tokenBudget: 8000 } } },
    });
    const html = await s4.render(ctx);
    expect(html).toContain("Runtime");
    expect(html).toContain("none"); // no cap → "none"
  });
});

// ---------------------------------------------------------------------------
// S7 — Knowledge operations
// ---------------------------------------------------------------------------

describe("s7 - knowledge operations", () => {
  const readiness = {
    score: 80.4,
    band: "healthy",
    windowDays: 30,
    pillars: [
      { id: "freshness", label: "Freshness", score: 70.7, band: "healthy", available: true, detail: "Recent facts." },
      { id: "coverage", label: "Coverage", score: 51.1, band: "fair", available: true, detail: "Coverage detail." },
      { id: "trust", label: "Trust", score: 100, band: "excellent", available: true, detail: "No facts contested." },
      { id: "structure", label: "Structure", score: 100, band: "excellent", available: true, detail: "No duplication." },
    ],
    trend: { direction: "up", deltaPoints: 13.5, previousScore: 66.9, windowDays: 30 },
  };

  it("renders real pending proposals and measured approval outcomes", async () => {
    const s7 = await loadScreen("s7");
    const proposal = {
      id: "01J00000000000000000000001",
      namespace: "acme",
      status: "pending_review",
      rowVersion: 1,
      confidence: 0.94,
      evidenceIds: ["01J00000000000000000000002", "01J00000000000000000000003"],
      draft: { slug: "refund-window", title: XSS, body: "Refunds close after 30 days." },
    };
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          "/v1/admin/proposals": [proposal],
          "/v1/admin/teams": [{ id: "team-support", name: "Support", namespace: "acme/support" }],
          "/v1/admin/proposals/metrics?namespace=acme": {
            approvals: 4,
            mergeWithoutEdit: 3,
            mergeWithoutEditRatio: 0.75,
          },
          "/v1/admin/readiness": readiness,
          "/v1/admin/knowledge-sync": {
            runs: [],
            totals: { queued: 0, running: 0, completed: 0, failed: 0, scheduled: 0 },
          },
        },
      },
    });
    const html = await s7.render(ctx);
    expect(html).toContain('<div class="home-overview knowledge-operations">');
    expect(html).toContain("<h1>Knowledge Operations</h1>");
    expect(html).toContain("75.0%");
    expect(html).toContain('<span class="knowledge-metric-value-only">1</span>');
    expect(html).toContain('<span class="knowledge-metric-value-only">75.0%</span>');
    expect(html).not.toContain('<span class="knowledge-metric-value-only">80.4</span>');
    expect(html).toContain("3 of 4 approved drafts were accepted without edits.");
    expect(html).toContain("Approve unchanged");
    expect(html).toContain("Edit &amp; approve");
    expect(html).toContain("Update team memory");
    expect(html).toContain('<option value="organization">Entire organization</option>');
    expect(html.indexOf('value="organization"')).toBeLessThan(html.indexOf('value="team-support"'));
    expect(html).toContain("Run update");
    expect(html).not.toContain("Turn newly saved team memories into organized knowledge drafts.");
    expect(html).not.toContain("Search indexing remains automatic when memories enter Halofy;");
    expect(html).toContain("Factual Validity");
    expect(html).toContain("Low usage is not treated as a negative signal.");
    expect(html.match(/role="progressbar"/g)).toHaveLength(4);
    expect(html).not.toContain("home-factor-axis");
    expect(html).toContain('id="knowledge-update-panel"');
    expect(html).toContain('id="knowledge-health-panel"');
    const reviewRow = html.match(/<article class="knowledge-review-row"[\s\S]*?<\/article>/)?.[0] ?? "";
    expect(reviewRow).toContain('data-tip="Refunds close after 30 days."');
    expect(reviewRow).not.toContain("<p>");
    expect(reviewRow).not.toContain("evidence item");
    expect(reviewRow).not.toContain("confidence");
    expect(html).not.toContain("Exact namespace");
    expect(html).not.toContain("Evidence memory ULIDs");
    assertNoRawImg(html);
    expect(calls.map((call) => call.path)).toEqual([
      "/v1/admin/proposals",
      "/v1/admin/proposals/metrics?namespace=acme",
      "/v1/admin/readiness",
      "/v1/admin/teams",
      "/v1/admin/knowledge-sync",
    ]);
  });

  it("keeps review work usable when the existing health read is unavailable", async () => {
    const s7 = await loadScreen("s7");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: {
        get: {
          "/v1/admin/proposals": [{
            id: "01J00000000000000000000021",
            namespace: "acme",
            status: "pending_review",
            rowVersion: 1,
            confidence: 0.8,
            evidenceIds: [],
            draft: { slug: "support-hours", title: "Support hours", body: "Support closes at 6pm." },
          }],
          "/v1/admin/proposals/metrics?namespace=acme": {
            approvals: 0, mergeWithoutEdit: 0, mergeWithoutEditRatio: 0,
          },
        },
      },
    });

    const html = await s7.render(ctx);
    expect(html).toContain("Support hours");
    expect(html).toContain("Memory health could not be checked. Refresh to try again.");
    expect(html).toContain("Unavailable");
    expect(html).not.toContain("No drafts are waiting for review or publication recovery.");
  });

  it("shows unavailable instead of empty counts when team and activity reads fail", async () => {
    const s7 = await loadScreen("s7");
    const { ctx } = makeCtx({
      routes: {
        get: {
          "/v1/admin/proposals": [],
          "/v1/admin/proposals/metrics?namespace=acme": {
            approvals: 0, mergeWithoutEdit: 0, mergeWithoutEditRatio: 0,
          },
          "/v1/admin/readiness": readiness,
        },
      },
    });

    const html = await s7.render(ctx);
    expect(html).toContain("Team directory unavailable. Refresh to try again.");
    expect(html).toMatch(/Updates Running[\s\S]*?Unavailable/);
    expect(html).toContain("Activity unavailable");
    expect(html).not.toContain("No memory updates have been queued yet.");
  });

  it("opens operation details in Home's shared right panel and restores focus", async () => {
    const mod = await loadScreen("s7") as {
      actions: Record<string, (ctx: unknown, el: any) => void>;
    };
    let panelFocus = 0;
    let triggerFocus = 0;
    const attrs = new Map<string, string>();
    const panelAttrs = new Map<string, string>();
    const classNames = new Set<string>();
    const focusTarget = { focus() { panelFocus += 1; } };
    const doc = {
      body: {
        classList: {
          add(value: string) { classNames.add(value); },
          remove(value: string) { classNames.delete(value); },
        },
      },
      addEventListener() {},
      removeEventListener() {},
      querySelector() { return null; },
      getElementById(id: string) { return id === "knowledge-update-panel" ? panel : null; },
    };
    const panel = {
      hidden: true,
      ownerDocument: doc,
      setAttribute(name: string, value: string) { panelAttrs.set(name, value); },
      querySelector(selector: string) {
        return selector === "[data-right-panel-focus], input, select, textarea, button" ? focusTarget : null;
      },
    };
    const root = { contains(value: unknown) { return value === panel; } };
    const trigger = {
      ownerDocument: doc,
      getAttribute(name: string) { return name === "data-panel" ? "knowledge-update-panel" : null; },
      closest(selector: string) { return selector === ".knowledge-operations" ? root : null; },
      setAttribute(name: string, value: string) { attrs.set(name, value); },
      focus() { triggerFocus += 1; },
    };

    vi.stubGlobal("document", doc);
    try {
      mod.actions["knowledge-update-open"]({}, trigger);
      expect(panel.hidden).toBe(false);
      expect(panelAttrs.get("aria-hidden")).toBe("false");
      expect(attrs.get("aria-expanded")).toBe("true");
      expect(classNames.has("source-modal-open")).toBe(true);
      expect(panelFocus).toBe(1);

      mod.actions["knowledge-panel-close"]({}, {});
      expect(panel.hidden).toBe(true);
      expect(panelAttrs.get("aria-hidden")).toBe("true");
      expect(attrs.get("aria-expanded")).toBe("false");
      expect(classNames.has("source-modal-open")).toBe(false);
      expect(triggerFocus).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("keeps sync activity visible as a durable record after a reload", async () => {
    const s7 = await loadScreen("s7");
    const { ctx } = makeCtx({
      namespace: "",
      routes: {
        get: {
          "/v1/admin/proposals": [],
          "/v1/admin/teams": [{ id: "team-support", name: "Support", namespace: "support" }],
          "/v1/admin/knowledge-sync": {
            runs: [{
              id: "team-support",
              name: "Support",
              status: "running",
              queuedAt: "2026-07-22T04:20:00.000Z",
              startedAt: "2026-07-22T04:20:05.000Z",
              completedAt: null,
              nextRunAt: null,
              lastRunStatus: null,
              lastError: null,
              processed: 12,
              proposals: 2,
              hasMore: true,
            }],
            totals: { queued: 0, running: 1, completed: 0, failed: 0, scheduled: 0 },
            retentionDays: 30,
          },
        },
      },
    });

    const html = await s7.render(ctx);
    expect(html).toContain("Updates Running");
    expect(html).toMatch(/Updates Running[\s\S]*?>1</);
    expect(html).toContain("Support");
    expect(html).toContain("12 evidence checked · 2 drafts");
    expect(html).toContain("More batches queued");
    expect(html).toContain("running");
    expect(html).toContain("Last 30 days");
    expect(html).toContain('aria-labelledby="knowledge-activity-title"');
    expect(html).toContain('role="listitem"');
  });

  it("does not present missing live counters as completed work", async () => {
    const s7 = await loadScreen("s7");
    const { ctx } = makeCtx({
      namespace: "",
      routes: {
        get: {
          "/v1/admin/proposals": [],
          "/v1/admin/teams": [],
          "/v1/admin/knowledge-sync": {
            runs: [{
              id: "organization-root",
              name: "Organization memory",
              status: "queued",
              queuedAt: "2026-07-22T04:20:00.000Z",
              startedAt: null,
              completedAt: null,
              nextRunAt: null,
              lastRunStatus: null,
              lastError: null,
              processed: null,
              proposals: null,
              hasMore: null,
            }],
            totals: { queued: 1, running: 0, completed: 0, failed: 0, scheduled: 0 },
            retentionDays: 30,
          },
        },
      },
    });

    const html = await s7.render(ctx);
    expect(html).toContain("Waiting for the worker");
    expect(html).not.toContain("0 evidence checked · 0 drafts");
  });

  it("lets the organization owner queue company delta sync without entering a namespace", async () => {
    const s7 = await loadScreen("s7");
    const { ctx, calls, refreshCalls } = makeCtx({
      namespace: "",
      routes: {
        get: {
          "/v1/admin/proposals": [],
          "/v1/admin/teams": [
            { id: "team-marketing", name: "Marketing", namespace: "marketing" },
            { id: "team-support", name: "Support", namespace: "support" },
          ],
          "/v1/admin/knowledge-sync": {
            runs: [],
            totals: { queued: 0, running: 0, completed: 0, failed: 0, scheduled: 0 },
          },
        },
        post: {
          "/v1/admin/knowledge-sync": {
            status: "queued",
            scope: "organization",
            queuedSpaces: [
              { id: "organization-root", name: "Organization memory" },
              { id: "team-marketing", name: "Marketing" },
              { id: "team-support", name: "Support" },
            ],
          },
        },
      },
    });
    const html = await s7.render(ctx);
    expect(html).toContain("Update company memory");
    expect(html).toContain('value="organization"');
    expect(html).toContain("Entire organization");
    expect(html).not.toContain("namespace");

    const status = { textContent: "" };
    const button = { disabled: false, textContent: "Run update" };
    const select = { value: "organization" };
    const card = {
      querySelector(selector: string) {
        if (selector === "[data-knowledge-sync-target]") return select;
        if (selector === "[data-knowledge-sync-status]") return status;
        if (selector === '[data-action="knowledge-sync"]') return button;
        return null;
      },
    };
    await s7.actions["knowledge-sync"]!(ctx, { closest: () => card });
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: "/v1/admin/knowledge-sync",
      body: { scope: "organization" },
    });
    expect(status.textContent).toContain("3 memory spaces queued");
    expect(refreshCalls).toEqual(["refresh"]);
    expect(button.disabled).toBe(false);
  });

  it("shows a truthful empty queue and keeps auditors read-only", async () => {
    const s7 = await loadScreen("s7");
    const { ctx } = makeCtx({
      role: "auditor",
      routes: {
        get: {
          "/v1/admin/proposals": [],
          "/v1/admin/proposals/metrics?namespace=acme": {
            approvals: 0, mergeWithoutEdit: 0, mergeWithoutEditRatio: 0,
          },
        },
      },
    });
    const html = await s7.render(ctx);
    expect(html).toContain("No drafts are waiting for review or publication recovery.");
    expect(html).toContain("Not measured");
    expect(html).toContain("Only an owner can start a memory update.");
    expect(html).not.toContain("Updates Running");
    expect(html).not.toContain("Run update");
    expect(html).not.toContain("Approve unchanged");
  });

  it("renders an interrupted publication and retries its current row version", async () => {
    const s7 = await loadScreen("s7");
    const proposal = {
      id: "01J00000000000000000000011",
      namespace: "acme",
      status: "publishing",
      rowVersion: 4,
      confidence: 0.91,
      evidenceIds: ["01J00000000000000000000012", "01J00000000000000000000013"],
      baseDraft: { body: "Refunds close after 14 days." },
      draft: { slug: "refund-window", title: "Refund window", body: "Refunds close after 30 days." },
    };
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          "/v1/admin/proposals": [proposal],
          "/v1/admin/proposals/metrics?namespace=acme": {
            approvals: 0, mergeWithoutEdit: 0, mergeWithoutEditRatio: 0,
          },
        },
        post: {
          "/v1/admin/proposals/01J00000000000000000000011/approve": proposal,
        },
      },
    });
    const html = await s7.render(ctx);
    expect(html).toContain("Recovery needed");
    expect(html).toContain("Previous official knowledge");
    expect(html).toContain("Refunds close after 14 days.");
    expect(html).toContain("Proposed knowledge");
    expect(html).toContain('data-action="proposal-retry"');
    expect(html).not.toContain("Approve unchanged");

    const status = { textContent: "" };
    const card = {
      getAttribute: (name: string) => name === "data-proposal-id" ? proposal.id : "4",
      querySelector: (selector: string) => selector === "[data-proposal-status]" ? status : null,
    };
    await s7.actions["proposal-retry"]!(ctx, { closest: () => card });
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: "/v1/admin/proposals/01J00000000000000000000011/approve",
      body: { expectedRowVersion: 4 },
    });
  });
});

// ---------------------------------------------------------------------------
// S11 — Conflict review (trust disputes)
// ---------------------------------------------------------------------------

function disputeView(overrides: Record<string, unknown> = {}) {
  return {
    id: "01J00000000000000000000021",
    namespace: "acme/support",
    team: "acme/support",
    category: "policies-legal",
    reason: "document(40) outranks conversation(10)",
    rowVersion: 1,
    createdAt: "2026-07-10T12:00:00.000Z",
    disputed: {
      id: "01J00000000000000000000022",
      content: "The refund window is 14 days.",
      scope: "team",
      source: "conversation",
      actor: "agent-7",
      confidence: 1,
      tValidFrom: "2026-07-10T12:00:00.000Z",
      tValidTo: null,
    },
    incumbent: {
      id: "01J00000000000000000000023",
      content: "The refund window is 30 days.",
      scope: "team",
      source: "document",
      actor: "connector:fs",
      confidence: 1,
      tValidFrom: "2026-07-01T00:00:00.000Z",
      tValidTo: null,
    },
    incumbentCurrent: true,
    ...overrides,
  };
}

describe("s11 - conflict review", () => {
  it("renders both facts under the team bucket with escaped content and category chips", async () => {
    const s11 = await loadScreen("s11");
    const { ctx, calls } = makeCtx({
      routes: {
        get: {
          "/v1/admin/disputes": [
            disputeView({ disputed: { ...disputeView().disputed, content: XSS } }),
          ],
        },
      },
    });
    const html = await s11.render(ctx);
    expect(html).toContain("acme/support · 1 conflict");
    expect(html).toContain("Current fact");
    expect(html).toContain("The refund window is 30 days.");
    expect(html).toContain("New claim — held for review");
    // The write path's trust-rank trace ("document(40) outranks
    // conversation(10)") is an engineering internal, not a reviewer's label;
    // S11 states the reason in words instead.
    expect(html).not.toContain("document(40) outranks conversation(10)");
    expect(html).toContain("more trusted source");
    expect(html).toContain("Policies &amp; legal (1)");
    expect(html).toContain("Keep the new claim");
    expect(html).toContain("Keep the current fact");
    expect(html).toContain("Edit &amp; replace");
    assertNoRawImg(html);
    expect(calls.map((call) => call.path)).toEqual([
      "/v1/admin/conflicts",
      "/v1/admin/disputes",
    ]);
  });

  it("keeps auditors read-only and disables uphold on a stale incumbent", async () => {
    const s11 = await loadScreen("s11");
    const auditor = makeCtx({
      role: "auditor",
      routes: { get: { "/v1/admin/disputes": [disputeView()] } },
    });
    const auditorHtml = await s11.render(auditor.ctx);
    expect(auditorHtml).toContain("Read-only");
    expect(auditorHtml).not.toContain("Uphold new");
    expect(auditorHtml).not.toContain("data-action=\"dispute-keep\"");

    const admin = makeCtx({
      role: "admin",
      routes: {
        get: { "/v1/admin/disputes": [disputeView({ incumbentCurrent: false })] },
      },
    });
    const staleHtml = await s11.render(admin.ctx);
    expect(staleHtml).toContain("Stale");
    expect(staleHtml).toContain('data-action="dispute-uphold" disabled');
  });

  it("shows a truthful empty queue", async () => {
    const s11 = await loadScreen("s11");
    const { ctx } = makeCtx({ routes: { get: { "/v1/admin/disputes": [] } } });
    const html = await s11.render(ctx);
    expect(html).toContain("No open conflicts");
  });

  it("posts the resolution with the card's row version", async () => {
    const s11 = await loadScreen("s11");
    const view = disputeView({ rowVersion: 3 });
    const { ctx, calls } = makeCtx({
      routes: {
        get: { "/v1/admin/disputes": [view] },
        post: {
          [`/v1/admin/disputes/${view.id}/resolve`]: { id: view.id, action: "keep-old" },
        },
      },
    });
    const status = { textContent: "" };
    const card = {
      getAttribute: (name: string) => (name === "data-dispute-id" ? view.id : "3"),
      querySelector: (selector: string) =>
        selector === "[data-dispute-status]" ? status : null,
    };
    await (s11.actions as Record<string, (c: unknown, e: unknown) => Promise<void>>)[
      "dispute-keep"
    ]!(ctx, { closest: () => card });
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: `/v1/admin/disputes/${view.id}/resolve`,
      body: { action: "keep-old", expectedRowVersion: 3 },
    });
  });

  it("sends the edited content only for Edit & replace", async () => {
    const s11 = await loadScreen("s11");
    const view = disputeView();
    const { ctx, calls } = makeCtx({
      routes: {
        get: { "/v1/admin/disputes": [view] },
        post: {
          [`/v1/admin/disputes/${view.id}/resolve`]: { id: view.id, action: "edit" },
        },
      },
    });
    const status = { textContent: "" };
    const textarea = { value: "The refund window is 30 days, extended to 45 in December." };
    const card = {
      getAttribute: (name: string) => (name === "data-dispute-id" ? view.id : "1"),
      querySelector: (selector: string) =>
        selector === "[data-dispute-status]" ? status
          : selector === "[data-dispute-edit]" ? textarea
            : null,
    };
    await (s11.actions as Record<string, (c: unknown, e: unknown) => Promise<void>>)[
      "dispute-edit"
    ]!(ctx, { closest: () => card });
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: `/v1/admin/disputes/${view.id}/resolve`,
      body: {
        action: "edit",
        expectedRowVersion: 1,
        editedContent: "The refund window is 30 days, extended to 45 in December.",
      },
    });
  });
});

// ---------------------------------------------------------------------------
// S8 — Audit & erasure
// ---------------------------------------------------------------------------

describe("s8 - audit & erasure", () => {
  // The screen asks for the server's maximum page, so every canned route below
  // is keyed with it (the unfiltered search the screen actually issues).
  const AUDIT_PATH = "/v1/admin/audit?limit=500";
  const AUDIT_SUMMARY_PATH = "/v1/admin/audit/summary";
  const auditRows = () => [
    {
      ts: "2026-07-01T00:00:00Z",
      actor: "user:dana",
      agentId: "agent:refunds",
      op: "write",
      namespace: "acme",
      result: "ok",
      // detail is attacker-influenced — a fact's content can land here.
      detail: XSS,
    },
  ];

  it("owner sees the erase card + escapes a hostile audit detail", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ role: "owner", routes: { get: { [AUDIT_PATH]: auditRows() } } });
    const html = await s8.render(ctx);
    expect(html).toContain("<h1>Audit</h1>");
    expect(html).not.toContain("Audit &amp; deletion");
    expect(html).toContain("user:dana");
    expect(html).toContain('data-action="audit-erase"'); // erase control for owner
    expect(html).toContain('data-action="cert-verify"'); // cert viewer always present
    expect(html).toContain('id="audit-filter-panel"');
    expect(html).toContain('class="audit-table" data-table-static');
    expect(html).not.toContain('data-grid-filter-source="audit-filter-panel"');
    assertNoRawImg(html);
  });

  it("renders audit labels as plain colored text and resolves human actor names", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ role: "owner", routes: { get: { [AUDIT_PATH]: auditRows() } } });
    (ctx as typeof ctx & { personLabel: (subject: unknown, principal?: string) => string }).personLabel =
      (subject, principal) => principal === "human" && subject === "user:dana"
        ? "Dana Rivera"
        : String(subject ?? "");

    const html = await s8.render(ctx);
    expect(html).toContain('<span class="audit-op-label audit-op-label--write">Saved to memory</span>');
    expect(html).toContain('<span class="audit-outcome-label audit-outcome-label--ok">Allowed</span>');
    expect(html).toContain("<strong>Dana Rivera</strong>");
    expect(html).not.toContain("audit-op-pill");
    expect(html).not.toContain('class="audit-outcome ');
  });

  it("auditor keeps the certificate viewer but LOSES the erase card", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ role: "auditor", routes: { get: { [AUDIT_PATH]: auditRows() } } });
    const html = await s8.render(ctx);
    expect(html).not.toContain('data-action="audit-erase"');
    expect(html).not.toContain("Right to be forgotten");
    // The viewer stays — a regulator reads certs.
    expect(html).toContain('data-action="cert-verify"');
    assertNoRawImg(html);
  });

  it("member loses the erase card too", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ role: "member", routes: { get: { [AUDIT_PATH]: auditRows() } } });
    const html = await s8.render(ctx);
    expect(html).not.toContain('data-action="audit-erase"');
  });

  it("a fresh trail renders 'No matching audit events'", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ routes: { get: { [AUDIT_PATH]: [] } } });
    const html = await s8.render(ctx);
    expect(html).toContain("No matching audit events");
    expect(html.match(/<strong>Unavailable<\/strong>/g)).toHaveLength(4);
    expect(html).not.toContain("<strong>0</strong>");
  });

  it("shows exact totals without plus signs through 20,000", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ routes: { get: {
      [AUDIT_PATH]: [],
      [AUDIT_SUMMARY_PATH]: { events: 500, blocked: 1_000, deletions: 2_000, exports: 20_000 },
    } } });
    const html = await s8.render(ctx);
    expect(html).toContain("<strong>500</strong>");
    expect(html).toContain("<strong>1,000</strong>");
    expect(html).toContain("<strong>2,000</strong>");
    expect(html).toContain("<strong>20,000</strong>");
    expect(html).not.toMatch(/<strong>[^<]*\+<\/strong>/);
  });

  it("uses compact thousands from 30,000 onward", async () => {
    const s8 = await loadScreen("s8");
    const { ctx } = makeCtx({ routes: { get: {
      [AUDIT_PATH]: [],
      [AUDIT_SUMMARY_PATH]: { events: 30_000, blocked: 30_500, deletions: 100_000, exports: 0 },
    } } });
    const html = await s8.render(ctx);
    expect(html).toContain("<strong>30K</strong>");
    expect(html).toContain("<strong>30.5K</strong>");
    expect(html).toContain("<strong>100K</strong>");
    expect(html).toContain("<strong>0</strong>");
  });

  // The trail is read a page at a time. The fetch is unchanged (still the
  // server maximum), so paging can never hide a row a filter admitted — it only
  // decides how many are on screen, and SAYS which ones those are.
  describe("paging", () => {
    const manyRows = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        ts: `2026-07-01T00:00:0${i % 10}Z`,
        actor: `user${i}@acme.test`,
        agentId: "agent:refunds",
        op: "read",
        namespace: "acme",
        result: "ok",
      }));
    const rowCount = (html: string) => (html.match(/class="audit-when"/g) ?? []).length;

    it("shows 8 prototype rows a page and names the window it is showing", async () => {
      const s8 = await loadScreen("s8");
      await s8.actions!["audit-reset"]!(makeCtx({ routes: { get: { [AUDIT_PATH]: [] } } }).ctx);
      const { ctx } = makeCtx({ routes: { get: { [AUDIT_PATH]: manyRows(25) } } });
      const html = await s8.render(ctx);
      expect(rowCount(html)).toBe(8);
      expect(html).toContain("Showing 1–8 of 25 events");
      expect(html).toContain('aria-current="page">1 / 4<');
      // Previous is dead on the first page; the compact pager reports 4 pages.
      expect(html).toMatch(/data-page="0"[^>]*disabled/);
      expect(html).toContain('data-page="2"');
      // The window is a reading aid, never a second filter: the fetch is still
      // the server's maximum page.
      expect(html).not.toContain("user8@acme.test");
    });

    it("audit-page moves the window; a search snaps back to page 1", async () => {
      const s8 = await loadScreen("s8");
      const actions = s8.actions as Record<string, (ctx: unknown, el?: unknown) => Promise<void>>;
      await actions["audit-page"]!(makeCtx().ctx, { getAttribute: () => "4" });
      const paged = makeCtx({ routes: { get: { [AUDIT_PATH]: manyRows(25) } } });
      const pagedHtml = await s8.render(paged.ctx);
      expect(rowCount(pagedHtml)).toBe(1);
      expect(pagedHtml).toContain("Showing 25–25 of 25 events");
      expect(pagedHtml).toContain("user24@acme.test");
      expect(pagedHtml).toMatch(/data-page="5"[^>]*disabled/); // Next is dead

      // A new search is a new question — it must not land on page 3 of it.
      const root = { querySelector: () => ({ value: "" }) };
      await actions["audit-search"]!(makeCtx().ctx, { closest: () => root });
      const fresh = makeCtx({ routes: { get: { [AUDIT_PATH]: manyRows(25) } } });
      expect(await s8.render(fresh.ctx)).toContain("Showing 1–8 of 25 events");
    });

    it("clamps a page past the end instead of rendering an empty table", async () => {
      const s8 = await loadScreen("s8");
      const actions = s8.actions as Record<string, (ctx: unknown, el?: unknown) => Promise<void>>;
      await actions["audit-page"]!(makeCtx().ctx, { getAttribute: () => "99" });
      const { ctx } = makeCtx({ routes: { get: { [AUDIT_PATH]: manyRows(25) } } });
      const html = await s8.render(ctx);
      expect(rowCount(html)).toBe(1);
      expect(html).toContain("Showing 25–25 of 25 events");
      await actions["audit-reset"]!(makeCtx({ routes: { get: { [AUDIT_PATH]: [] } } }).ctx);
    });

    it("renders no pager when the whole trail already fits", async () => {
      const s8 = await loadScreen("s8");
      const { ctx } = makeCtx({ routes: { get: { [AUDIT_PATH]: manyRows(4) } } });
      const html = await s8.render(ctx);
      expect(html).not.toContain("audit-pager");
      expect(html).toContain("Showing 1–4 of 4 events");
    });
  });

  it("renders only the backend trusted verification result for certificates", async () => {
    const s8 = await loadScreen("s8");
    const actions = s8.actions as Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    const certificate = {
      id: "cert-1",
      target: { kind: "actor", value: "user:dana" },
      namespace: "acme",
      erasedCount: 2,
      issuedAt: "2026-07-01T00:00:00Z",
      actor: "owner@acme.test",
      algorithm: "ed25519",
      publicKey: "inline-key-is-display-only",
    };
    const root = (value: string) => ({
      querySelector: (selector: string) => selector === "#cert-id" ? { value } : null,
    });

    const trusted = makeCtx({
      routes: {
        get: {
          [AUDIT_PATH]: [],
          "/v1/admin/certificate/trusted": { ...certificate, verified: true },
        },
      },
    });
    await actions["cert-verify"]!(trusted.ctx, { closest: () => root("trusted") });
    const trustedHtml = await s8.render(trusted.ctx);
    expect(trustedHtml).toContain("Genuine - signed by this system");
    expect(trustedHtml).not.toContain("verifiable against the inline public key");

    const tampered = makeCtx({
      routes: {
        get: {
          [AUDIT_PATH]: [],
          "/v1/admin/certificate/tampered": { ...certificate, verified: false },
        },
      },
    });
    await actions["cert-verify"]!(tampered.ctx, { closest: () => root("tampered") });
    const tamperedHtml = await s8.render(tampered.ctx);
    expect(tamperedHtml).toContain("Does not match this system's signature");
    expect(tamperedHtml).not.toContain("Genuine - signed by this system");
  });

  it("submits person, agent, operation, result, and full time-window filters", async () => {
    const s8 = await loadScreen("s8");
    const values: Record<string, string> = {
      "#audit-actor": "user:dana",
      "#audit-agent": "agent:refunds",
      "#audit-op": "publish",
      "#audit-result": "error",
      "#audit-since": "2026-07-01",
      "#audit-until": "2026-07-31",
    };
    const root = {
      querySelector: (selector: string) => ({ value: values[selector] ?? "" }),
    };
    const first = makeCtx();
    await s8.actions["audit-search"]!(first.ctx, { closest: () => root });
    // Every filter travels, AND the screen asks for the server's maximum page:
    // a compliance table that silently showed the default first 100 rows reads
    // as "this is everything".
    const filteredPath = "/v1/admin/audit?actor=user%3Adana&agentId=agent%3Arefunds&op=publish&result=error&since=2026-07-01&until=2026-07-31&limit=500";
    const second = makeCtx({ routes: { get: { [filteredPath]: [] } } });
    const html = await s8.render(second.ctx);
    expect(second.calls[0]?.path).toBe(filteredPath);
    expect(html).toContain('id="audit-agent"');
    expect(html).toContain('id="audit-result"');
    expect(html).toContain('id="audit-until"');

    for (const key of Object.keys(values)) values[key] = "";
    await s8.actions["audit-search"]!(second.ctx, { closest: () => root });
  });

  it("wires the prototype date tabs, including a true all-time reset", async () => {
    const s8 = await loadScreen("s8");
    const actions = s8.actions as Record<string, (ctx: unknown, el: unknown) => Promise<void>>;
    const root = {
      querySelector: () => ({ value: "" }),
    };

    await actions["audit-range"]!(makeCtx().ctx, {
      closest: () => root,
      getAttribute: (name: string) => name === "data-days" ? "1" : null,
    });
    const oneDay = makeCtx();
    const oneDayHtml = await s8.render(oneDay.ctx);
    expect(oneDay.calls[0]?.path).toMatch(/^\/v1\/admin\/audit\?since=\d{4}-\d{2}-\d{2}&limit=500$/);
    expect(oneDayHtml).toContain('data-days="1" class="audit-range-tab is-active" aria-pressed="true"');

    await actions["audit-range"]!(makeCtx().ctx, {
      closest: () => root,
      getAttribute: (name: string) => name === "data-days" ? "all" : null,
    });
    const allTime = makeCtx();
    const allTimeHtml = await s8.render(allTime.ctx);
    expect(allTime.calls[0]?.path).toBe(AUDIT_PATH);
    expect(allTimeHtml).toContain('data-days="all" class="audit-range-tab is-active" aria-pressed="true"');
  });
});

// ---------------------------------------------------------------------------
// S14 — Integrations (MCP clients, agent plugins, key minting)
// ---------------------------------------------------------------------------

describe("s14 integrations", () => {
  it("keeps every client card compact and vertically aligned", async () => {
    const css = await import("node:fs/promises").then((fs) =>
      fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
    );

    expect(css).toMatch(/\.intg-card\{[^}]*align-items:center/);
    expect(css).toMatch(/\.intg-card\{[^}]*min-height:76px/);
    expect(css).toMatch(/\.intg-card\{[^}]*min-width:0/);
    expect(css).not.toMatch(/\.intg-card\{[^}]*align-items:flex-start/);
  });

  it("renders the endpoint, every MCP client card, plugin cards, and the mint form for an owner", async () => {
    const s14 = await loadScreen("s14");
    const { ctx } = makeCtx({ role: "owner", namespace: "acme" });
    const html = await s14.render(ctx);
    expect(html).toContain("https://halomem.example/mcp");
    for (const name of [
      "Claude Code", "Codex CLI", "Cursor", "VS Code", "Cline",
      "Gemini CLI", "Antigravity", "Claude Desktop", "Hermes Agents",
      "OpenClaw", "ChatGPT", "MCP URL",
    ]) {
      expect(html).toContain(name);
    }
    expect(html).toContain("Claude Code plugin");
    expect(html).toContain("Codex wiring");
    expect(html).toContain("Knowledge bases");
    expect(html).toContain('data-action="intg-mint"');
    expect(html).toContain("mem_search");
  });

  it("hides key minting from an auditor", async () => {
    const s14 = await loadScreen("s14");
    const { ctx } = makeCtx({ role: "auditor", namespace: "acme" });
    const html = await s14.render(ctx);
    expect(html).not.toContain('data-action="intg-mint"');
    expect(html).toContain("Read-only");
  });

  it("escapes a hostile namespace everywhere it is interpolated", async () => {
    const s14 = await loadScreen("s14");
    const { ctx } = makeCtx({ role: "owner", namespace: XSS });
    const html = await s14.render(ctx);
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain("onerror=alert(1)>");
  });
});

// ---------------------------------------------------------------------------
// S16 — Skills: member submission, approval queue, monitoring bands, and the
// approved+vetted distribution gate (download / add-to-integrations).
// ---------------------------------------------------------------------------

describe("s16 skills", () => {
  const skill = (over: Record<string, unknown> = {}) => ({
    id: "skill_1",
    namespace: "acme",
    skillKey: "summarize-ticket",
    name: "Summarize ticket",
    description: "Summarizes a support ticket",
    version: 1,
    vettingStatus: "vetted",
    safetyScore: 92,
    approvalStatus: "approved",
    status: "active",
    tValidTo: null,
    riskBand: "good",
    usage: { agents: 2, invocations: 10, denials: 1 },
    ...over,
  });

  const modalHarness = () => {
    const status = { textContent: "" };
    const focus = { focus: vi.fn() };
    const modal = {
      hidden: true,
      innerHTML: "",
      attributes: new Map<string, string>(),
      setAttribute(name: string, value: string) {
        this.attributes.set(name, value);
      },
      querySelector(selector: string) {
        return selector === "[data-wizard-focus]" ? focus : null;
      },
    };
    const body = { classList: { add: vi.fn(), remove: vi.fn() } };
    vi.stubGlobal("document", {
      getElementById: (id: string) => id === "skill-modal" ? modal : null,
      querySelector: (selector: string) => selector === "[data-skill-status]" ? status : null,
      body,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    return { modal, status, focus, body };
  };

  it("member: lists via /v1/skills, sees the submit form and monitoring strip", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "member",
      routes: { get: { "/v1/skills": [skill()] } },
    });
    const html = await s16.render(ctx);
    expect(calls.some((c) => c.path === "/v1/skills")).toBe(true);
    expect(calls.some((c) => c.path.startsWith("/v1/admin/"))).toBe(false);
    expect(html).toContain("Safety checks");
    expect(html).toContain('data-action="skill-new"');
    expect(html).not.toContain("Pending approval</h3>");
  });

  it("badges curated defaults in the library row; member submissions stay unbadged", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/v1/skills": [
            skill({ id: "skill_default", createdBy: "system-default-skills" }),
            skill({ id: "skill_member", name: "Member skill", skillKey: "member-skill", createdBy: "mira" }),
          ],
        },
      },
    });
    const html = await s16.render(ctx);
    const badge = 'title="Ships with Halofy as a curated default">Default</span>';
    expect(html.split(badge).length - 1).toBe(1);
  });

  it("renders skill registration as a designed file-first workflow", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "owner",
      routes: { get: { "/v1/admin/skills": [skill()] } },
    });
    const toggle = (s16.actions as Record<string, (c: unknown) => Promise<void>>)["skill-new"]!;
    await toggle(ctx);
    try {
      const [html, css] = await Promise.all([
        s16.render(ctx),
        import("node:fs/promises").then((fs) =>
          fs.readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
        ),
      ]);
      expect(html).toContain('class="card skill-register" id="skill-form"');
      expect(html).toContain('class="skill-file-input" id="skill-file"');
      expect(html).toContain('class="skill-upload" for="skill-file"');
      expect(html).toContain('data-skill-file-name aria-live="polite"');
      expect(html).not.toContain('class="input mono" id="skill-file"');
      expect(html).not.toContain('id="skill-form" style=');
      expect(css).toContain(".skill-register{");
      expect(css).toContain(".skill-file-input{");
      expect(css).toContain(".skill-upload{");
    } finally {
      await toggle(ctx);
    }
  });

  it("member: pending submission shows waiting state, not admin actions", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "member",
      routes: {
        get: {
          "/v1/skills": [
            skill({ vettingStatus: "unvetted", approvalStatus: "pending", riskBand: "risky", safetyScore: null }),
          ],
        },
      },
    });
    const html = await s16.render(ctx);
    expect(html).toContain("Pending approval");
    expect(html).toContain("Available once approved and checked");
    expect(html).toContain('class="skill-lock-note"');
    expect(html).not.toContain('data-action="skill-approve"');
    expect(html).not.toContain('data-action="skill-vet"');
  });

  it("admin: pending submissions carry an inline approve action; reject lives in the detail modal", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "admin",
      routes: {
        get: {
          "/v1/admin/skills": [
            skill({ vettingStatus: "unvetted", approvalStatus: "pending", riskBand: "risky", safetyScore: null }),
          ],
          "/v1/admin/skills/skill_1": {
            skill: skill({ vettingStatus: "unvetted", approvalStatus: "pending", riskBand: "risky", safetyScore: null }),
            vettingRuns: [], agents: [], history: [], events: [],
          },
        },
      },
    });
    const html = await s16.render(ctx);
    // Pending review is filterable from the header pill…
    expect(html).toContain('data-action="skill-approval"');
    expect(html).toContain("pending review");
    // …and approvable straight from the library row.
    expect(html).toContain('data-action="skill-approve" data-id="skill_1"');
    // Rejection requires an audited reason, so it lives in the modal panel.
    expect(html).not.toContain('data-action="skill-reject"');
    const select = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-select"
    ]!;
    const { modal } = modalHarness();
    try {
      await select(ctx, { getAttribute: () => "skill_1", setAttribute: vi.fn(), focus: vi.fn() });
      expect(modal.innerHTML).toContain('role="dialog" aria-modal="true"');
      expect(modal.innerHTML).toContain('data-action="skill-reject" data-id="skill_1"');
      expect(modal.innerHTML).toContain('data-skill-reject-reason="skill_1"');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("monitoring strip counts good / risky / critical from riskBand", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": [
            skill({ id: "a", riskBand: "good" }),
            skill({ id: "b", riskBand: "risky", vettingStatus: "unvetted", approvalStatus: "pending", safetyScore: null }),
            skill({ id: "c", riskBand: "critical", vettingStatus: "blocked", safetyScore: 12 }),
          ],
        },
      },
    });
    const html = await s16.render(ctx);
    expect(html).toContain('data-action="skill-band" data-band="good"');
    expect(html).toContain('data-action="skill-band" data-band="critical"');
    expect(html).toContain('class="skill-risk-card skill-risk-card--good"');
    expect(html).toContain("Passed checks");
    expect(html).toContain("Checks pending");
    expect(html).toContain("Action required");
    expect(html).toContain("All security checks passed.");
  });

  it("refreshes local S16 filters and toggles in place instead of route navigating", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({ role: "owner" });
    const refresh = vi.fn(async () => undefined);
    const go = vi.fn(async () => undefined);
    const actionCtx = { ...ctx, refresh, go };
    const actions = s16.actions as Record<string, (c: unknown, el?: unknown) => Promise<void>>;

    await actions["skill-new"]!(actionCtx);
    await actions["skill-new"]!(actionCtx);
    await actions["skill-band"]!(actionCtx, { getAttribute: () => "critical" });
    await actions["skill-band"]!(actionCtx, { getAttribute: () => "all" });
    await actions["skill-team"]!(actionCtx, { value: "acme/support" });
    await actions["skill-team"]!(actionCtx, { value: "all" });
    await actions["skill-approval"]!(actionCtx);
    await actions["skill-approval"]!(actionCtx);

    expect(refresh).toHaveBeenCalledTimes(8);
    expect(go).not.toHaveBeenCalled();
  });

  it("renders the library as a compact summary table", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "member",
      routes: { get: { "/v1/skills": [skill()] } },
    });
    const html = await s16.render(ctx);
    expect(html).toContain('class="skill-table" role="table"');
    expect(html).toContain('<div role="columnheader">Skill</div><div role="columnheader">Category</div><div role="columnheader">Tags</div><div role="columnheader">Team</div><div role="columnheader">Status</div><div role="columnheader">Agents</div><div role="columnheader">Last checked</div><div role="columnheader">Share</div>');
    expect(html).toContain('class="skill-status-cluster"');
    // Members get a static table: no row expansion, no governance actions.
    expect(html).not.toContain('data-action="skill-select"');
    expect(html).not.toContain('class="skill-expand"');
  });

  it("admin: opens skill detail in a modal without route navigation", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": [skill()],
          "/v1/admin/skills/skill_1": {
            skill: skill(),
            vettingRuns: [], agents: [], history: [], events: [],
          },
        },
      },
    });
    const html = await s16.render(ctx);
    expect(html).toContain('class="skill-expand halo-icon-control"');
    expect(html).toContain('aria-controls="skill-modal" aria-expanded="false" aria-haspopup="dialog"');
    expect(html).not.toContain("skill-detail-row");
    const select = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-select"
    ]!;
    const go = vi.fn();
    const opener = { getAttribute: () => "skill_1", setAttribute: vi.fn(), focus: vi.fn() };
    const { modal, body, focus } = modalHarness();
    try {
      await select({ ...ctx, go }, opener);
      expect(go).not.toHaveBeenCalled();
      expect(calls.at(-1)).toEqual({ method: "GET", path: "/v1/admin/skills/skill_1" });
      expect(modal.hidden).toBe(false);
      expect(modal.attributes.get("aria-hidden")).toBe("false");
      expect(modal.innerHTML).toContain('class="source-wizard-dialog skill-detail-dialog"');
      expect(modal.innerHTML).toContain('class="skill-detail-panel"');
      expect(body.classList.add).toHaveBeenCalledWith("source-modal-open");
      expect(focus.focus).toHaveBeenCalledOnce();
      expect(opener.setAttribute).toHaveBeenCalledWith("aria-expanded", "true");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("admin: loads the authoritative team directory and offers a team target", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "owner",
      namespace: "acme",
      routes: {
        get: {
          "/v1/admin/skills": [skill()],
          "/v1/admin/teams": [
            { id: "team_support", namespace: "acme/support", name: "Support", members: [] },
            { id: "team_hostile", namespace: "acme/hostile", name: XSS, members: [] },
          ],
        },
      },
    });
    const toggle = (s16.actions as Record<string, (c: unknown) => Promise<void>>)["skill-new"]!;
    await toggle(ctx);
    try {
      const html = await s16.render(ctx);
      expect(calls.some((call) => call.path === "/v1/admin/teams")).toBe(true);
      expect(html).toContain('id="skill-team" data-skill-team');
      expect(html).toContain('<option value="team_support">Support · acme/support</option>');
      expect(html).toContain(XSS_ESCAPED);
      expect(html).not.toContain("onerror=alert(1)>");
    } finally {
      await toggle(ctx);
    }
  });

  it("admin: submits the selected team id without asserting a namespace", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        post: {
          "/v1/admin/skills": { skill: skill({ id: "skill_team" }) },
        },
      },
    });
    const values: Record<string, { value: string }> = {
      "[data-skill-key]": { value: "team-summary" },
      "[data-skill-name]": { value: "Team summary" },
      "[data-skill-desc]": { value: "Summarizes the team's work" },
      "[data-skill-def]": { value: "Summarize the team's open work." },
      "[data-skill-team]": { value: "team_support" },
      "[data-skill-purpose]": { value: "Use when a team needs a concise summary of open work." },
      "[data-skill-category]": { value: "Content & Drafting" },
      "[data-skill-tags]": { value: "summary, teamwork, reporting" },
    };
    vi.stubGlobal("document", {
      querySelector(selector: string) {
        return values[selector] ?? null;
      },
    });
    try {
      const create = (s16.actions as Record<string, (c: unknown) => Promise<void>>)["skill-create"]!;
      await create(ctx);
      const call = calls.find((entry) => entry.method === "POST" && entry.path === "/v1/admin/skills");
      expect(call?.body).toEqual({
        skillKey: "team-summary",
        name: "Team summary",
        description: "Summarizes the team's work",
        definition: "Summarize the team's open work.",
        labels: {
          purpose: "Use when a team needs a concise summary of open work.",
          category: "Content & Drafting",
          tags: ["summary", "teamwork", "reporting"],
        },
        teamId: "team_support",
      });
      expect(call?.body).not.toHaveProperty("namespace");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("admin: edit file form opens from detail and is prefilled for the current skill", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": [skill({ definition: "current instructions" })],
          "/v1/admin/skills/skill_1": {
            skill: skill({ definition: "current instructions" }),
            vettingRuns: [], agents: [], history: [], events: [],
          },
        },
      },
    });
    const edit = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-edit"
    ]!;
    const { modal } = modalHarness();
    const editButton = {
      getAttribute: () => "skill_1",
      setAttribute: vi.fn(),
      focus: vi.fn(),
      closest: (selector: string) => selector === "#skill-modal",
    };
    try {
      await edit(ctx, editButton);
      const html = modal.innerHTML;
      expect(html).toContain('data-action="skill-edit" data-id="skill_1" aria-expanded="true"');
      expect(html).toContain('class="skill-edit" data-skill-form data-skill-mode="update"');
      expect(html).toContain('data-input-action="skill-file"');
      expect(html).toContain('data-action="skill-update"');
      expect(html).toContain('data-skill-key value="summarize-ticket" autocomplete="off" readonly');
      expect(html).toContain(">current instructions</textarea>");
      expect(html).toContain("v2 next");
    } finally {
      await edit(ctx, editButton);
      vi.unstubAllGlobals();
    }
  });

  it("re-uploading an exported SKILL.md loads only its instruction body", async () => {
    const s16 = await loadScreen("s16");
    const fields: Record<string, { value?: string; textContent?: string; readOnly?: boolean }> = {
      "[data-skill-key]": { value: "summarize-ticket", readOnly: true },
      "[data-skill-name]": { value: "Old name" },
      "[data-skill-desc]": { value: "Old description" },
      "[data-skill-def]": { value: "old instructions" },
      "[data-skill-file-name]": { textContent: "Current file loaded" },
      "[data-skill-form-status]": { textContent: "" },
    };
    const upload = { classList: { add: vi.fn() } };
    const root = {
      getAttribute: (name: string) => name === "data-skill-mode" ? "update" : null,
      querySelector: (selector: string) => selector === ".skill-upload" ? upload : fields[selector] ?? null,
    };
    const file = {
      name: "SKILL.md",
      size: 180,
      text: async () => [
        "---",
        'name: "Replacement name"',
        'description: "Replacement description"',
        "---",
        "",
        "Use only the replacement instructions.",
      ].join("\n"),
    };
    const loadFile = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-file"
    ]!;

    await loadFile({}, { files: [file], closest: () => root });

    expect(fields["[data-skill-name]"]?.value).toBe("Replacement name");
    expect(fields["[data-skill-desc]"]?.value).toBe("Replacement description");
    expect(fields["[data-skill-def]"]?.value).toBe("Use only the replacement instructions.");
    expect(fields["[data-skill-def]"]?.value).not.toContain("---");
  });

  it("rejects an oversized skill file before reading it", async () => {
    const s16 = await loadScreen("s16");
    const status = { textContent: "" };
    const root = {
      querySelector: (selector: string) => selector === "[data-skill-form-status]" ? status : null,
    };
    const text = vi.fn(async () => "must not be read");
    const input = {
      files: [{ name: "oversized.md", size: 256_001, text }],
      value: "C:\\fakepath\\oversized.md",
      closest: () => root,
    };
    const loadFile = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-file"
    ]!;

    await loadFile({}, input);

    expect(text).not.toHaveBeenCalled();
    expect(input.value).toBe("");
    expect(status.textContent).toBe("File is too large. Use a file under 256 KB.");
  });

  it("admin: update skill patches the selected row without a client-owned key", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: { "/v1/admin/skills": [skill()] },
        patch: {
          "/v1/admin/skills/skill_1": {
            skill: skill({ id: "skill_2", version: 2, definition: "new instructions" }),
            superseded: true,
          },
        },
      },
    });
    const refresh = vi.fn(async () => undefined);
    const go = vi.fn(async () => undefined);
    const status = { textContent: "" };
    const fields: Record<string, { value?: string; textContent?: string }> = {
      "[data-skill-key]": { value: "summarize-ticket" },
      "[data-skill-name]": { value: "Summarize ticket" },
      "[data-skill-desc]": { value: "Updated helper" },
      "[data-skill-def]": { value: "new instructions" },
      "[data-skill-form-status]": status,
    };
    const root = {
      getAttribute: (name: string) => name === "data-skill-current-id" ? "skill_1" : null,
      querySelector: (selector: string) => fields[selector] ?? null,
    };
    const update = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-update"
    ]!;
    await update({ ...ctx, refresh, go }, { closest: () => root });

    expect(calls.at(-1)).toEqual({
      method: "PATCH",
      path: "/v1/admin/skills/skill_1",
      body: {
        name: "Summarize ticket",
        description: "Updated helper",
        definition: "new instructions",
      },
    });
    expect(status.textContent).toBe("Updating…");
    expect(refresh).toHaveBeenCalledOnce();
    expect(go).not.toHaveBeenCalled();
  });

  it("download + add-to-integrations only render for approved AND vetted skills", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": [
            skill({ id: "dist", approvalStatus: "approved", vettingStatus: "vetted" }),
            skill({ id: "unvetted", approvalStatus: "approved", vettingStatus: "unvetted", safetyScore: null, riskBand: "risky" }),
            skill({ id: "pending", approvalStatus: "pending", vettingStatus: "vetted", riskBand: "good" }),
          ],
        },
      },
    });
    const html = await s16.render(ctx);
    expect(html).toContain('data-action="skill-download" data-id="dist"');
    expect(html).toMatch(/data-action="skill-integrations"\s+data-id="dist"/);
    expect(html).not.toContain('data-action="skill-download" data-id="unvetted"');
    expect(html).not.toContain('data-action="skill-download" data-id="pending"');
    expect(html).not.toMatch(/data-action="skill-integrations"\s+data-id="pending"/);
  });

  it("escapes attacker-controlled skill fields", async () => {
    const s16 = await loadScreen("s16");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: { "/v1/admin/skills": [skill({ name: XSS, skillKey: XSS, namespace: XSS })] },
      },
    });
    const html = await s16.render(ctx);
    expect(html).toContain(XSS_ESCAPED);
    expect(html).not.toContain("onerror=alert(1)>");
  });

  it("E74: detail shows plain-language lane verdicts + engine versions without scores", async () => {
    const s16 = await loadScreen("s16");
    const startedAt = "2026-07-19T03:00:00.000Z";
    const run = (mode: string, score: number, engineVersions: string) => ({
      id: `run_${mode}`, mode, status: "passed", safetyScore: score,
      findings: [], detail: null, engineVersions, ranBy: "ada",
      startedAt, finishedAt: startedAt,
    });
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": {
            skills: [skill({ id: "skill_1" })],
            lastSweptAt: "2026-07-01T03:00:00.000Z",
          },
          "/v1/admin/skills/skill_1": {
            skill: skill({ id: "skill_1" }),
            vettingRuns: [
              run("llm", 100, "azure-openai-scan@gpt-5.5"),
              run("cisco", 92, "cisco@1.4.2"),
              run("skillspector", 88, "skillspector@0.9.1"),
            ],
            agents: [], history: [], events: [],
          },
        },
      },
    });
    const list = await s16.render(ctx);
    // Timestamps render human and locale-independent, not as a raw ISO slice.
    expect(list).toContain("Last full scan 1 Jul 2026, 03:00");

    const select = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-select"
    ]!;
    const { modal } = modalHarness();
    try {
      await select(ctx, { getAttribute: () => "skill_1", setAttribute: vi.fn(), focus: vi.fn() });
      const detail = modal.innerHTML;
    expect(detail).toContain("Good to go");
    expect(detail).toContain("LLM");
    expect(detail).toContain("Cisco");
    expect(detail).toContain("NVIDIA SkillSpector");
    expect(detail).toContain("Passed");
    expect(detail).not.toContain("LLM · 100");
    expect(detail).not.toContain("Cisco · 92");
    expect(detail).not.toContain("NVIDIA SkillSpector · 88");
    expect(detail).not.toContain("<th>Score</th>");
    expect(detail).not.toContain("Safety score");
    expect(detail).toContain("aria-label=\"Cisco\"");
    expect(detail).toContain("aria-label=\"NVIDIA\"");
    expect(detail).toContain("azure-openai-scan@gpt-5.5");
    expect(detail).toContain("cisco@1.4.2");
      expect(detail).toContain("skillspector@0.9.1");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows Cisco as not run when only SkillSpector executed in the latest check", async () => {
    const s16 = await loadScreen("s16");
    const startedAt = "2026-07-22T04:35:10.000Z";
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: {
          "/v1/admin/skills": [skill({ id: "skill_1" })],
          "/v1/admin/skills/skill_1": {
            skill: skill({ id: "skill_1" }),
            vettingRuns: [{
              id: "run_skillspector", mode: "skillspector", status: "passed", safetyScore: 100,
              findings: [], detail: null, engineVersions: "skillspector@2.3.1", ranBy: "ada",
              startedAt, finishedAt: startedAt,
            }],
            agents: [], history: [], events: [],
          },
        },
      },
    });
    const select = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
      "skill-select"
    ]!;
    const { modal } = modalHarness();
    try {
      await select(ctx, { getAttribute: () => "skill_1", setAttribute: vi.fn(), focus: vi.fn() });
      const detail = modal.innerHTML;
      expect(detail).toContain("Cisco");
      expect(detail).toContain("Not run");
      expect(detail).toContain("NVIDIA SkillSpector");
      expect(detail).toContain("skillspector@2.3.1");
      expect(detail).not.toContain("NVIDIA SkillSpector · 100");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("refreshes S16 in place after checks instead of navigating through the route loader", async () => {
    const s16 = await loadScreen("s16");
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: { post: { "/v1/admin/skills/skill_1/vet": {} } },
    });
    const refresh = vi.fn(async () => undefined);
    const go = vi.fn(async () => undefined);
    const status = { textContent: "" };
    vi.stubGlobal("document", {
      querySelector(selector: string) {
        return selector === "[data-skill-status]" ? status : null;
      },
    });
    const button = {
      disabled: false,
      textContent: "Run checks",
      getAttribute: () => "skill_1",
      setAttribute: vi.fn(),
    };
    try {
      const vet = (s16.actions as Record<string, (c: unknown, el: unknown) => Promise<void>>)[
        "skill-vet"
      ]!;
      await vet({ ...ctx, refresh, go }, button);
      expect(calls.at(-1)).toEqual({
        method: "POST",
        path: "/v1/admin/skills/skill_1/vet",
        body: {},
      });
      expect(refresh).toHaveBeenCalledOnce();
      expect(go).not.toHaveBeenCalled();
      expect(button.disabled).toBe(true);
      expect(button.setAttribute).toHaveBeenCalledWith("aria-busy", "true");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

// ---------------------------------------------------------------------------
// S20 — Export (governed egress view)
// ---------------------------------------------------------------------------

describe("s20 - export", () => {
  const overview = () => ({
    namespace: "acme",
    l2Active: 42,
    spend: { monthToDateUsd: 0, effectiveCapUsd: null },
  });

  const exportResult = (extra: Record<string, unknown> = {}) => ({
    markdown: "# HaloMem memory export\n\n### 01FACT (fact)\n\n" + XSS + "\n",
    filename: "halomem-export-acme-2026-07-21.md",
    sha256: "a".repeat(64),
    portableJson: '{"schema":"halomem.memory-export/v1","l2":[],"l3":[]}\n',
    portableFilename: "halomem-export-acme-2026-07-21.json",
    portableSha256: "b".repeat(64),
    includedL2: 3,
    includedL3: 1,
    excluded: { role: 0, source: 1, classification: 2 },
    excludedByTier: {
      L2: { role: 0, source: 1, classification: 1 },
      L3: { role: 0, source: 0, classification: 1 },
    },
    ...extra,
  });

  // A fake export form so generate() can read the tier checkboxes + purpose
  // without a DOM (the render tests run in plain Node — no jsdom).
  function fakeForm(
    { l2 = true, l3 = true, purpose = "" }: { l2?: boolean; l3?: boolean; purpose?: string } = {},
  ) {
    return {
      querySelector(sel: string) {
        if (sel === '[data-tier="L2"]') return { checked: l2 };
        if (sel === '[data-tier="L3"]') return { checked: l3 };
        if (sel === "[data-export-purpose]") return { value: purpose };
        return null;
      },
    };
  }
  const elFor = (form: unknown) => ({ closest: () => form });

  type Mod = {
    render(ctx: unknown): Promise<string>;
    actions: Record<string, (ctx: unknown, el?: unknown) => Promise<void>>;
  };

  it("renders the export controls without an intro card, and NEVER exports on render", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: { get: { "/v1/admin/teams": [] } },
    });
    const html = await s20.render(ctx);
    expect(html).toContain("<h1>Export</h1>");
    expect(html).not.toContain("ex20-roles-pill");
    expect(html).not.toContain("Owners, admins &amp; auditors only");
    expect(html).not.toContain("Download your entire memory");
    expect(html).not.toContain("currently under management");
    expect(html).toContain('data-tier="L2"');
    expect(html).toContain('data-tier="L3"');
    expect(html).toContain('data-action="generate"');
    // Render reads only the scope roster — never overview data or export egress.
    expect(calls).toEqual([{ method: "GET", path: "/v1/admin/teams" }]);
    expect(html).not.toContain("Your export is ready");
    expect(html).not.toContain('data-action="download"');
  });

  it("generate() POSTs the selected tiers; the result card reports counts, checksum + withheld, content escaped", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({
      role: "owner",
      routes: {
        get: { "/v1/admin/overview": overview() },
        post: {
          "/v1/mem/export": (body) => {
            expect(body).toEqual({ tiers: ["L2", "L3"] });
            return exportResult();
          },
        },
      },
    });
    await s20.actions.generate(ctx, elFor(fakeForm({ l2: true, l3: true })));
    expect(calls.at(-1)).toMatchObject({ method: "POST", path: "/v1/mem/export" });
    const html = await s20.render(ctx);
    expect(html).toContain("Your export is ready");
    expect(html).toContain("Facts included");
    expect(html).toContain("Knowledge included");
    expect(html).toContain("halomem-export-acme-2026-07-21.md");
    expect(html).toContain("a".repeat(64)); // sha256 egress evidence
    expect(html).toContain("halomem-export-acme-2026-07-21.json");
    expect(html).toContain("b".repeat(64)); // portable JSON egress evidence
    expect(html).toContain("withheld by policy"); // 3 withheld (source 1, classification 2)
    expect(html).toContain("Facts withheld");
    expect(html).toContain("Knowledge withheld");
    expect(html).toContain('data-action="download-json"');
    expect(html).toContain('data-action="download"');
    expect(html).toContain('data-action="copy"');
    // The hostile fact content inside the markdown preview is escaped, never raw.
    assertNoRawImg(html);
  });

  it("generate() forwards a trimmed purpose when provided", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({
      role: "admin",
      routes: {
        get: { "/v1/admin/overview": overview() },
        post: {
          "/v1/mem/export": (body) => {
            expect(body).toEqual({ tiers: ["L2"], purpose: "audit review" });
            return exportResult();
          },
        },
      },
    });
    await s20.actions.generate(ctx, elFor(fakeForm({ l2: true, l3: false, purpose: "  audit review  " })));
    expect(calls.at(-1)).toMatchObject({
      method: "POST",
      path: "/v1/mem/export",
      body: { tiers: ["L2"], purpose: "audit review" },
    });
  });

  it("a no-tier selection never fires an export", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({ role: "owner", routes: {} });
    await s20.actions.generate(ctx, elFor(fakeForm({ l2: false, l3: false })));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("an empty/withheld outcome is honest and offers no download", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: { "/v1/admin/overview": overview() },
        post: {
          "/v1/mem/export": exportResult({
            includedL2: 0,
            includedL3: 0,
            markdown: "# HaloMem memory export\n",
            excluded: { role: 0, source: 0, classification: 2 },
          }),
        },
      },
    });
    await s20.actions.generate(ctx, elFor(fakeForm({ l2: true, l3: true })));
    const html = await s20.render(ctx);
    expect(html).toContain("nothing eligible to export");
    expect(html).not.toContain('data-action="download"');
  });

  it("the auditor MAY export - the read-only role keeps the Generate control", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx } = makeCtx({ role: "auditor", routes: { get: { "/v1/admin/overview": overview() } } });
    const html = await s20.render(ctx);
    expect(html).toContain('data-action="generate"');
    expect(html).toContain("What to include");
  });

  it("root - the product spelling of owner that /v1/me returns (D41) - MAY export", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx } = makeCtx({ role: "root", routes: { get: { "/v1/admin/overview": overview() } } });
    const html = await s20.render(ctx);
    expect(html).toContain('data-action="generate"');
    expect(html).toContain("What to include");
    expect(html).not.toContain("limited to owners, admins, and auditors");
  });

  it("a non-exporting role gets an honest notice and NO controls or reads", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({ role: "member", routes: {} });
    const html = await s20.render(ctx);
    expect(html).toContain("limited to owners, admins, and auditors");
    expect(html).not.toContain('data-action="generate"');
    expect(calls).toEqual([]); // a barred role never even reads the overview
  });

  it("exports generate/download/copy actions and a failed export shows an honest message", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    expect(typeof s20.actions.generate).toBe("function");
    expect(typeof s20.actions["download-json"]).toBe("function");
    expect(typeof s20.actions.download).toBe("function");
    expect(typeof s20.actions.copy).toBe("function");
    const { ctx } = makeCtx({
      role: "owner",
      routes: {
        get: { "/v1/admin/overview": overview() },
        post: {
          "/v1/mem/export": () => {
            throw { status: 403, message: "role 'member' may not export" };
          },
        },
      },
    });
    await s20.actions.generate(ctx, elFor(fakeForm({ l2: true, l3: true })));
    const html = await s20.render(ctx);
    expect(html).toContain("Export didn't run");
    expect(html).toContain("may not export");
  });

  // --- scoped export (team / person) ---------------------------------------

  const teamsFixture = () => [
    { namespace: "acme", name: "Acme", members: [{ email: "root@acme.co" }] },
    {
      namespace: "acme/support",
      name: "Support",
      members: [{ email: "bob@acme.co" }, { email: "root@acme.co" }],
    },
  ];

  // fakeForm plus the scope controls (radio group + team/person selects).
  function scopeForm(
    opts: {
      kind?: string;
      team?: string;
      user?: string;
      l2?: boolean;
      l3?: boolean;
      purpose?: string;
    } = {},
  ) {
    const { kind = "org", team = "", user = "", l2 = true, l3 = true, purpose = "" } = opts;
    return {
      querySelector(sel: string) {
        if (sel === '[data-tier="L2"]') return { checked: l2 };
        if (sel === '[data-tier="L3"]') return { checked: l3 };
        if (sel === "[data-export-purpose]") return { value: purpose };
        if (sel === 'input[name="export-scope"]:checked') return { value: kind };
        if (sel === "[data-scope-team]") return { value: team };
        if (sel === "[data-scope-user]") return { value: user };
        return null;
      },
    };
  }

  it("renders the scope picker with teams and people from the roster (reads only)", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({
      role: "admin",
      routes: { get: { "/v1/admin/overview": overview(), "/v1/admin/teams": teamsFixture() } },
    });
    (ctx as typeof ctx & { personLabel: (subject: unknown, principal?: string) => string }).personLabel =
      (subject, principal) => principal === "human" && subject === "bob@acme.co"
        ? "Bob Builder"
        : String(subject ?? "");
    await s20.actions["set-scope"](ctx, elFor(scopeForm({ kind: "org" })));
    const html = await s20.render(ctx);
    expect(html).toContain('data-scope-kind="org"');
    expect(html).toContain('data-scope-kind="team"');
    expect(html).toContain('data-scope-kind="user"');
    // The select for the chosen kind lists the roster data.
    await s20.actions["set-scope"](ctx, elFor(scopeForm({ kind: "team" })));
    expect(await s20.render(ctx)).toContain("Support");
    await s20.actions["set-scope"](ctx, elFor(scopeForm({ kind: "user" })));
    const peopleHtml = await s20.render(ctx);
    expect(peopleHtml).toContain('value="bob@acme.co"');
    expect(peopleHtml).toContain("Bob Builder");
    expect(calls.every((c) => c.method === "GET")).toBe(true); // still no egress on render
  });

  it("browns out to whole-organization only when the teams read fails", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx } = makeCtx({ role: "admin", routes: { get: { "/v1/admin/overview": overview() } } });
    const html = await s20.render(ctx);
    expect(html).toContain('data-action="generate"');
    expect(html).toContain("No teams available");
  });

  it("selecting a person disables the Knowledge tier and generate() posts the user scope", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({
      role: "admin",
      routes: {
        get: { "/v1/admin/overview": overview(), "/v1/admin/teams": teamsFixture() },
        post: {
          "/v1/mem/export": (body) => {
            expect(body).toEqual({
              tiers: ["L2"],
              scope: { kind: "user", actor: "bob@acme.co" },
            });
            return exportResult();
          },
        },
      },
    });
    await s20.actions["set-scope"](ctx, elFor(scopeForm({ kind: "user", user: "bob@acme.co" })));
    const html = await s20.render(ctx);
    expect(html).toMatch(/data-tier="L3"[^>]*disabled/);
    expect(html).toContain("team-level");
    await s20.actions.generate(ctx, elFor(scopeForm({ kind: "user", user: "bob@acme.co" })));
    expect(calls.at(-1)).toMatchObject({ method: "POST", path: "/v1/mem/export" });
  });

  it("generate() posts the team scope; whole-organization posts no scope key", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const bodies: unknown[] = [];
    const { ctx } = makeCtx({
      role: "admin",
      routes: {
        get: { "/v1/admin/overview": overview(), "/v1/admin/teams": teamsFixture() },
        post: {
          "/v1/mem/export": (body) => {
            bodies.push(body);
            return exportResult();
          },
        },
      },
    });
    await s20.actions.generate(
      ctx,
      elFor(scopeForm({ kind: "team", team: "acme/support" })),
    );
    expect(bodies.at(-1)).toEqual({
      tiers: ["L2", "L3"],
      scope: { kind: "team", namespace: "acme/support" },
    });
    const html = await s20.render(ctx);
    expect(html).toContain("Team memory export:");
    expect(html).toContain("team and sub-teams only");
    expect(html).toContain("inherited organization memory is excluded");
    await s20.actions.generate(ctx, elFor(scopeForm({ kind: "org" })));
    expect(bodies.at(-1)).toEqual({ tiers: ["L2", "L3"] });
  });

  it("a team/person choice without a selection never fires an export", async () => {
    const s20 = (await loadScreen("s20")) as unknown as Mod;
    const { ctx, calls } = makeCtx({ role: "admin", routes: {} });
    await s20.actions.generate(ctx, elFor(scopeForm({ kind: "team", team: "" })));
    await s20.actions.generate(ctx, elFor(scopeForm({ kind: "user", user: "" })));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });
});
