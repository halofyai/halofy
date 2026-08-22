import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CSS = readFileSync(
  fileURLToPath(new URL("../console/app.css", import.meta.url)),
  "utf8",
);
const APP = readFileSync(
  fileURLToPath(new URL("../console/app.js", import.meta.url)),
  "utf8",
);
const INDEX = readFileSync(
  fileURLToPath(new URL("../console/index.html", import.meta.url)),
  "utf8",
);
const ACCESSIBLE_SCREENS = ["s6.js", "s14.js"]
  .map((name) =>
    readFileSync(
      fileURLToPath(new URL(`../console/screens/${name}`, import.meta.url)),
      "utf8",
    ),
  )
  .join("\n");

const COMPACT_CSS = CSS.replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\s+/g, " ")
  .replace(/\s*([{}:;,])\s*/g, "$1")
  .trim();

function cssToken(name: string): string {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return COMPACT_CSS.match(new RegExp(`--${escaped}:([^;}]+)`))?.[1] ?? "";
}

function cssRule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return COMPACT_CSS.match(new RegExp(`(?:^|})${escaped}\\{([^{}]*)\\}`))?.[1] ?? "";
}

describe("console minimalist UI contract", () => {
  it("declares an existing local favicon so clean page loads do not request /favicon.ico", () => {
    expect(INDEX).toContain('<link rel="icon" href="assets/marks/halofy-mark-green.svg" type="image/svg+xml" />');
  });
  it("carries the canonical Halofy color, spacing, elevation, and type tokens", () => {
    expect(cssToken("evergreen-rgb")).toMatch(/^18\s+58\s+46$/);
    expect(cssToken("s8")).toBe("64px");
    expect(cssToken("s9")).toBe("96px");
    expect(cssToken("sh-4")).toMatch(
      /^0 30px 70px -36px rgba\(15,?\s*24,?\s*16,?\s*(?:\.22|0\.22)\)$/,
    );
    expect(cssToken("metal-shadow")).toContain("var(--evergreen-rgb)");
    expect(cssToken("metal-shadow")).toContain("inset 0 1px 0");

    expect(cssToken("font-sans")).toContain('"Inter"');
    expect(cssToken("font-sans")).toContain("-apple-system");
    expect(cssToken("font-sans")).toContain("BlinkMacSystemFont");
    expect(cssToken("font-body")).toBe("var(--font-sans)");
    expect(cssToken("font-cta")).toBe("var(--font-sans)");
    expect(cssToken("font-mono")).toBe("var(--font-sans)");
    expect(CSS).toMatch(
      /font-family:"Inter";[\s\S]*?InterVariable\.woff2[\s\S]*?font-weight:100 900/,
    );
    expect(cssRule("body")).toContain("font-family:var(--font-body)");
    expect(cssRule(".btn")).toContain("font-family:var(--font-cta)");
  });

  it("uses the restrained radius, elevation, and control scale", () => {
    expect(cssToken("r-sm")).toBe("8px");
    expect(cssToken("r-md")).toBe("12px");
    expect(cssToken("r-lg")).toBe("16px");

    const card = cssRule(".card");
    expect(card).toContain("border-radius:var(--panel-radius)");
    expect(card).toContain("box-shadow:var(--sh-1),var(--sh-2)");

    expect(cssRule(".stat")).toContain("border-radius:var(--r-md)");

    const controls = cssRule(".input,.select");
    expect(controls).toContain("font-size:14px");
    expect(controls).toContain("border-radius:var(--r-sm)");
    expect(cssRule(".btn")).toContain("font-size:14px");
  });

  it("uses metallic black shell chrome and keeps primary buttons flat", () => {
    expect(INDEX).toContain('class="mark" src="assets/marks/halofy-mark-white.svg"');
    expect(cssRule(".brand .mark")).not.toContain("filter");
    expect(cssToken("dl-rail")).toBe("#050607");
    expect(cssToken("dl-rail-metal")).toContain("radial-gradient");
    expect(cssToken("dl-rail-metal")).toContain("0 0/8px 8px");
    expect(cssToken("dl-rail-metal")).toContain("linear-gradient");
    expect(cssRule(".rail")).toContain("background:var(--dl-rail-metal)");
    expect(cssRule(".rail")).toContain("background-color:var(--dl-rail)");
    expect(cssRule(".rail")).toContain("color:var(--dl-rail-ink)");
    expect(cssRule(".nav button")).toContain("color:var(--dl-rail-ink-70)");
    expect(cssToken("dl-shell-control")).toBe("#d4d7d8");
    expect(cssRule('.navgroup[aria-expanded="true"]')).toContain("background:var(--dl-shell-control)");
    expect(cssRule(".nav button.on")).toContain("background:var(--dl-shell-control)");
    expect(cssRule(".nav button.on")).toContain("color:var(--ink)");
    expect(cssRule(".workspace-bar")).toContain("background:var(--dl-rail-metal)");
    expect(cssRule(".workspace-bar")).toContain("background-color:var(--dl-rail)");
    expect(cssRule(".workspace-search")).toContain("background:#fff");
    expect(cssRule(".workspace-account")).toContain("gap:var(--s3)");
    expect(cssRule(".workspace-account-trigger")).toContain("background:var(--dl-shell-control)");
    expect(cssRule(".rail-collapse.halo-icon-control")).toContain("background:var(--dl-shell-control)");
    expect(cssRule(".workspace-account-copy>span")).toContain("color:var(--ink)");
    expect(cssRule(".auth-story")).toContain("background:var(--metal)");

    const primary = cssRule(".btn--primary");
    expect(primary).toContain("background:var(--evergreen)");
    expect(primary).not.toMatch(/gradient|var\(--metal\)/);

    expect(COMPACT_CSS.match(/var\(--metal\)/g) ?? []).toHaveLength(1);
  });

  it("keeps page headers compact with room for one right-aligned CTA", () => {
    const head = cssRule(".head");
    expect(head).toContain("align-items:flex-start");
    expect(head).toContain("gap:var(--s3)");
    expect(head).toContain("padding:0 0 var(--s4)");
    expect(head).toContain("margin:0!important");
    expect(head).not.toContain("border-bottom");

    const actions = cssRule(".head .acts");
    expect(actions).toContain("flex:none");
    expect(actions).toContain("justify-content:flex-end");
  });

  it("keeps the shell full width and centers desktop content in a bounded frame", () => {
    const stage = cssRule(".stage");
    expect(stage).toContain("max-width:none");
    expect(stage).toContain("margin:0");

    const content = cssRule("#screen-content");
    expect(content).toContain("max-width:1184px");
    expect(content).toContain("margin-inline:auto");
  });

  it("applies one global reduced-motion safety net", () => {
    const reducedMotion = COMPACT_CSS.match(
      /@media\(prefers-reduced-motion:reduce\)\{\*,\*::before,\*::after\{([^{}]*)\}\}/,
    )?.[1];

    expect(reducedMotion).toBeDefined();
    expect(reducedMotion).toContain("animation-duration:.01ms!important");
    expect(reducedMotion).toContain("animation-iteration-count:1!important");
    expect(reducedMotion).toContain("transition-duration:.01ms!important");
    expect(reducedMotion).toContain("scroll-behavior:auto!important");
  });

  it("does not tile decorative gradients across console surfaces", () => {
    const repeatedGradientSelectors = Array.from(
      COMPACT_CSS.matchAll(/([^{}]+)\{([^{}]+)\}/g),
    )
      .filter(([, , declarations]) => {
        return (
          declarations.includes("gradient(") &&
          declarations.includes("background-size:") &&
          !declarations.includes("background-repeat:no-repeat")
        );
      })
      .map(([, selector]) => selector.trim())
      // The memory graph's coordinate grid is functional data-visualization
      // chrome, not a decorative surface treatment.
      .filter((selector) => selector !== ".memory-graph-grid");

    expect(repeatedGradientSelectors).toEqual([]);
  });

  it("keeps helper copy visible while retaining explicit accessibility-only text", () => {
    const visuallyHidden = /display:none|visibility:hidden|opacity:0|clip:/;
    for (const selector of [".head p", ".card .sub", ".hint"]) {
      const declarations = cssRule(selector);
      expect(declarations, `${selector} must remain a visible helper style`).not.toBe("");
      expect(declarations, `${selector} must not be globally hidden`).not.toMatch(
        visuallyHidden,
      );
    }

    expect(APP).toContain('<div class="sub">');

    const screenReaderOnly = cssRule(".sr-only");
    expect(screenReaderOnly).toContain("position:absolute");
    expect(screenReaderOnly).toContain("overflow:hidden");
    expect(screenReaderOnly).toContain("clip:rect(0,0,0,0)");
    expect(ACCESSIBLE_SCREENS).toContain('class="sr-only"');
  });

  it("keeps the scoped badge action and its helper copy compact", () => {
    const badgeForm = cssRule(".sm-form");
    expect(badgeForm).toContain("grid-template-columns:repeat(3,minmax(0,1fr))");

    expect(COMPACT_CSS).toContain(
      ".sm-form:is(.input,.select){height:42px;min-height:42px}",
    );

    const badgeSelect = cssRule(".sm-form .select");
    expect(badgeSelect).toContain("text-overflow:ellipsis");
    expect(badgeSelect).toContain("white-space:nowrap");

    const action = cssRule(".scope-memory-create-action .btn");
    expect(action).toContain("min-height:32px");
    expect(action).toContain("padding:4px 10px");
    expect(action).toContain("font-size:12px");
    expect(COMPACT_CSS).toContain(
      ".toggle,.scope-memory-create-action .btn{min-height:44px}",
    );

    const helper = cssRule(".scope-memory-create-hint");
    expect(helper).toContain("font-size:var(--text-label)");
    expect(helper).toContain("line-height:1.4");
  });
});
