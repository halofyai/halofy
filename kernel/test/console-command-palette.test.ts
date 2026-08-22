import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildActionItems,
  buildMetricItems,
  buildPaletteItems,
  buildScreenItems,
  decodeNavLabel,
  flattenGroups,
  isPaletteShortcut,
  rankItems,
  scoreItem,
  shortcutLabel,
} from "../console/command-palette.js";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

/** The live shape of GET /v1/admin/overview, trimmed to the fields we read. */
const OVERVIEW = {
  namespace: "halofy",
  children: [
    { namespace: "halofy/marketing", l2Active: 2 },
    { namespace: "halofy/sales-team", l2Active: 12 },
  ],
  l2Active: 710,
  faultCount: 0,
  faultHitRate: 0.25,
  spend: { monthToDateUsd: 0.07430201, effectiveCapUsd: null },
  tokensSavedEstimate: 2912,
  usage: { totalTokens: 197491, totalUsd: 0.08501973 },
  models: [],
  sourcesSummary: { connectedCount: 30 },
};

const NAV = [
  {
    group: "Operate",
    items: [
      { s: "s2", icon: "home", label: "Home" },
      { s: "s5", icon: "map", label: "Memory" },
      { s: "s15", icon: "score", label: "Usage analytics" },
      { action: "haloAgents", capability: "haloAgents", icon: "bot", label: "Halo Agents" },
    ],
  },
  {
    group: "Govern",
    items: [
      { s: "s8", icon: "shield", label: "Audit" },
      { s: "s13", icon: "teams", label: "Teams" },
    ],
  },
];

const ALL = new Set(["s2", "s5", "s6", "s8", "s10", "s12", "s13", "s15"]);

describe("command palette metrics", () => {
  it("renders the live overview numbers the operator came looking for", () => {
    const items = buildMetricItems(OVERVIEW, ALL);
    const byId = new Map(items.map((i) => [i.id, i]));
    expect(byId.get("metric:memories")?.value).toBe("710");
    expect(byId.get("metric:sources")?.value).toBe("30");
    expect(byId.get("metric:tokens")?.value).toBe("197,491");
    expect(byId.get("metric:tokens-saved")?.value).toBe("2,912");
    expect(byId.get("metric:fault-rate")?.value).toBe("25%");
  });

  it("keeps sub-dollar spend legible instead of rounding it to nothing", () => {
    const items = buildMetricItems(OVERVIEW, ALL);
    expect(items.find((i) => i.id === "metric:spend")?.value).toBe("$0.0743");
    // Fixed decimals, so two sub-dollar figures stacked in the list align.
    expect(items.find((i) => i.id === "metric:usage-usd")?.value).toBe("$0.0850");
  });

  it("switches back to cents once the figure clears a dollar", () => {
    const items = buildMetricItems(
      { ...OVERVIEW, spend: { monthToDateUsd: 1240.5, effectiveCapUsd: 2000 } },
      ALL,
    );
    expect(items.find((i) => i.id === "metric:spend")?.value).toBe("$1,240.50");
    expect(items.find((i) => i.id === "metric:cap")?.value).toBe("$2,000.00");
  });

  it("reports a real zero but never invents a value the server omitted", () => {
    const items = buildMetricItems(OVERVIEW, ALL);
    // faultCount is genuinely 0 — that is a fact, and it renders.
    expect(items.find((i) => i.id === "metric:faults")?.value).toBe("0");
    // effectiveCapUsd is null — no cap is configured, so no row at all.
    expect(items.some((i) => i.id === "metric:cap")).toBe(false);
  });

  it("drops a metric whose owning screen the role may not open", () => {
    const memberish = new Set(["s2", "s5", "s6"]);
    const items = buildMetricItems(OVERVIEW, memberish);
    expect(items.some((i) => i.id === "metric:memories")).toBe(true);
    // s15 is not in the rail, so no usage/spend rows are advertised.
    expect(items.some((i) => i.perform.screen === "s15")).toBe(false);
    expect(items.some((i) => i.id === "metric:tokens")).toBe(false);
  });

  it("carries per-team memory counts only when Teams is reachable", () => {
    const withTeams = buildMetricItems(OVERVIEW, ALL);
    expect(withTeams.find((i) => i.id === "metric:team:halofy/sales-team")?.value).toBe("12");
    const withoutTeams = buildMetricItems(OVERVIEW, new Set(["s2", "s5"]));
    expect(withoutTeams.some((i) => i.id.startsWith("metric:team:"))).toBe(false);
  });

  it("returns nothing when the overview fetch browned out", () => {
    expect(buildMetricItems(null, ALL)).toEqual([]);
    expect(buildMetricItems(undefined, ALL)).toEqual([]);
  });
});

describe("command palette screens and actions", () => {
  it("offers exactly the screens the router would allow", () => {
    const items = buildScreenItems({ navigation: NAV, allowedScreens: new Set(["s2", "s5"]) });
    expect(items.map((i) => i.perform.screen)).toEqual(["s2", "s5"]);
  });

  it("lists a screen once even when the rail carries it in two groups", () => {
    // The real NAV puts s15 under both Operate and Govern (memberOperate vs
    // governance); the palette must not offer it twice.
    const twice = [
      { group: "Operate", items: [{ s: "s15", label: "Usage analytics" }] },
      { group: "Govern", items: [{ s: "s15", label: "Usage analytics" }] },
    ];
    const items = buildScreenItems({ navigation: twice, allowedScreens: ALL });
    expect(items).toHaveLength(1);
    expect(items[0].hint).toBe("Operate");
  });

  it("decodes pre-escaped rail labels and keeps the Audit screen name concise", () => {
    expect(decodeNavLabel("Policies &amp; controls")).toBe("Policies & controls");
    const items = buildScreenItems({ navigation: NAV, allowedScreens: ALL });
    expect(items.find((i) => i.perform.screen === "s8")?.label).toBe("Audit");
  });

  it("includes a capability launcher only when the capability is granted", () => {
    const without = buildScreenItems({ navigation: NAV, allowedScreens: ALL, capabilities: {} });
    expect(without.some((i) => i.label === "Halo Agents")).toBe(false);
    const withCap = buildScreenItems({
      navigation: NAV,
      allowedScreens: ALL,
      capabilities: { haloAgents: true },
    });
    expect(withCap.find((i) => i.label === "Halo Agents")?.perform).toEqual({
      type: "haloAgents",
    });
  });

  it("withholds actions whose screen is outside the role's rail", () => {
    const items = buildActionItems({ allowedScreens: new Set(["s10", "s6"]) });
    const labels = items.map((i) => i.label);
    expect(labels).toContain("Ask the assistant");
    expect(labels).toContain("Connect a source");
    expect(labels).not.toContain("Export memory");
  });

  it("always offers sign out - every session owns its own logout", () => {
    const items = buildActionItems({ allowedScreens: new Set() });
    expect(items).toHaveLength(1);
    expect(items[0].perform).toEqual({ type: "signout" });
  });

  it("never emits an item pointing at a screen outside allowedScreens", () => {
    const allowed = new Set(["s2", "s5", "s13"]);
    const items = buildPaletteItems({
      navigation: NAV,
      allowedScreens: allowed,
      capabilities: {},
      overview: OVERVIEW,
    });
    for (const item of items) {
      if (item.perform.type !== "screen") continue;
      expect(allowed.has(item.perform.screen)).toBe(true);
    }
  });
});

describe("command palette matching", () => {
  const items = buildPaletteItems({
    navigation: NAV,
    allowedScreens: ALL,
    capabilities: {},
    overview: OVERVIEW,
  });

  it("shows metrics first when nothing is typed", () => {
    const groups = rankItems(items, "");
    expect(groups.map((g) => g.group)).toEqual(["Metrics", "Screens", "Actions"]);
  });

  it("ranks a prefix hit above a mid-label hit", () => {
    const memories = { label: "Active memories", keywords: [] };
    const teamMemories = { label: "sales-team memories", keywords: [] };
    expect(scoreItem(memories, "active")).toBeGreaterThan(scoreItem(teamMemories, "memories"));
  });

  it("finds a metric by a keyword that is not in its label", () => {
    const groups = rankItems(items, "billing");
    const labels = flattenGroups(groups).map((i) => i.label);
    expect(labels).toContain("Spend month to date");
  });

  it("floats the matching group to the top", () => {
    const groups = rankItems(items, "spend");
    expect(groups[0].group).toBe("Metrics");
    expect(groups[0].items[0].label).toBe("Spend month to date");
  });

  it("matches a loose subsequence but rejects a genuine miss", () => {
    const audit = { label: "Search the audit trail", keywords: [] };
    expect(scoreItem(audit, "audtr")).toBeGreaterThan(0);
    expect(scoreItem(audit, "zzq")).toBe(-1);
    expect(rankItems(items, "zzzzqqq")).toEqual([]);
  });
});

describe("command palette shortcut", () => {
  const mac = { platform: "MacIntel" };
  const pc = { platform: "Win32" };

  it("spells the shortcut ⌘K on every platform", () => {
    expect(shortcutLabel(mac)).toBe("⌘K");
    expect(shortcutLabel(pc)).toBe("⌘K");
    expect(shortcutLabel()).toBe("⌘K");
  });

  it("honours the advertised Command+K on Windows as well as macOS", () => {
    // A Windows user reads "⌘K", presses the key in that position, and the
    // browser reports metaKey. That must open the palette.
    expect(isPaletteShortcut({ key: "k", metaKey: true }, mac)).toBe(true);
    expect(isPaletteShortcut({ key: "k", metaKey: true }, pc)).toBe(true);
  });

  it("keeps Ctrl+K working off macOS, since Windows eats Win+K itself", () => {
    expect(isPaletteShortcut({ key: "k", ctrlKey: true }, pc)).toBe(true);
    // On macOS Ctrl+K is delete-to-end-of-line; the palette must not steal it.
    expect(isPaletteShortcut({ key: "k", ctrlKey: true }, mac)).toBe(false);
  });

  it("accepts a capitalised K and ignores every other key", () => {
    expect(isPaletteShortcut({ key: "K", ctrlKey: true }, pc)).toBe(true);
    expect(isPaletteShortcut({ key: "j", ctrlKey: true }, pc)).toBe(false);
    expect(isPaletteShortcut({ key: "k", ctrlKey: true, altKey: true }, pc)).toBe(false);
    expect(isPaletteShortcut(null, pc)).toBe(false);
  });
});

describe("command palette shell wiring", () => {
  it("uses the Usage Analytics gray-and-white language without green states", async () => {
    const css = await readFile(CONSOLE_DIR + "app.css", "utf8");
    const paletteStart = css.indexOf(".cmdk{position:fixed");
    const paletteEnd = css.indexOf("/* ---------------------------------------------------------------------------\n   S18 Settings", paletteStart);
    const paletteCss = css.slice(paletteStart, paletteEnd);

    expect(paletteCss).toMatch(/\.cmdk__panel\{[^}]*border:1px solid #e5e7eb[^}]*background:#fff[^}]*color:#111827/);
    expect(paletteCss).toMatch(/\.cmdk__input\{[^}]*background:transparent[^}]*color:#111827/);
    expect(paletteCss).toContain(".cmdk__row.is-active{background:#f3f4f6;color:#111827}");
    expect(paletteCss).toMatch(/\.cmdk__foot\{[^}]*background:#f8f8f7[^}]*color:#6b7280/);
    expect(paletteCss).not.toMatch(/var\(--(?:sage|sage-soft|evergreen|olive|panel|mineral|ink)\)/);
  });

  it("mounts outside the router-repainted stage, like the assistant dock", async () => {
    const html = await readFile(CONSOLE_DIR + "index.html", "utf8");
    const stageEnd = html.indexOf("</main>");
    const mount = html.indexOf('id="command-palette"');
    expect(mount).toBeGreaterThan(stageEnd);
  });

  it("prints the Command glyph on the keycap, not a platform guess", async () => {
    const html = await readFile(CONSOLE_DIR + "index.html", "utf8");
    expect(html).toContain("<kbd data-cmdk-hint>&#8984;K</kbd>");
    expect(html).not.toContain("Ctrl K");
  });

  it("ships desktop topbar and mobile triggers, both hidden until available", async () => {
    const html = await readFile(CONSOLE_DIR + "index.html", "utf8");
    expect(html).toContain('class="workspace-search"');
    expect(html).toContain('class="mobile-search"');
    expect(html.match(/data-cmdk-open/g)?.length).toBe(2);
    // Both triggers ship hidden — setAvailable() reveals them.
    for (const chunk of html.split("data-cmdk-open").slice(1)) {
      expect(chunk.slice(0, chunk.indexOf(">"))).toContain("hidden");
    }
  });

  it("is withheld while the mandatory setup gate is locked", async () => {
    const app = await readFile(CONSOLE_DIR + "app.js", "utf8");
    expect(app).toContain("commandPalette.setAvailable(gateMode === null)");
  });

  it("reads the router's live guard set rather than a boot-time snapshot", async () => {
    const app = await readFile(CONSOLE_DIR + "app.js", "utf8");
    expect(app).toContain("allowedScreens: () => allowedScreens");
  });
});
