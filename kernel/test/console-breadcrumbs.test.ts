import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  breadcrumbMarkup,
  buildBreadcrumbTrail,
} from "../console/breadcrumbs.js";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

const navigation = [
  {
    group: "Operate",
    items: [
      { s: "s2", label: "Home" },
      { s: "s6", label: "Sources &amp; imports" },
      { s: "s16", label: "Skills" },
    ],
  },
  {
    group: "Govern",
    items: [{ s: "s4", label: "Policies" }],
  },
];

const esc = (value: unknown) =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

describe("console breadcrumbs", () => {
  it("shows Home and the current top-level page as the shared path", () => {
    const trail = buildBreadcrumbTrail({
      navigation,
      allowedScreens: new Set(["s2", "s6", "s16"]),
      screenId: "s6",
    });

    expect(trail).toEqual([
      { label: "Home", screenId: "s2", home: true },
      { label: "Sources & imports", screenId: "s6" },
    ]);
    const html = breadcrumbMarkup(trail, esc);
    expect(html).toContain('class="breadcrumb-home"');
    expect(html).toContain('data-breadcrumb-screen="s2"');
    expect(html).toContain('aria-current="page">Sources &amp; imports</span>');
  });

  it("grows for nested detail and keeps the collection as a clickable ancestor", () => {
    const trail = buildBreadcrumbTrail({
      navigation,
      allowedScreens: new Set(["s2", "s16"]),
      screenId: "s16",
      tail: ["Research <assistant>"],
    });
    const html = breadcrumbMarkup(trail, esc);

    expect(trail).toEqual([
      { label: "Home", screenId: "s2", home: true },
      { label: "Skills", screenId: "s16" },
      { label: "Research <assistant>" },
    ]);
    expect(html).toContain('data-breadcrumb-screen="s2"');
    expect(html).toContain('data-breadcrumb-screen="s16"');
    expect(html).toContain("Research &lt;assistant&gt;");
    expect(html).not.toContain("Research <assistant>");
    expect(html).toContain('aria-current="page"');
  });

  it("decodes only one layer of pre-escaped navigation text", () => {
    const trail = buildBreadcrumbTrail({
      navigation: [
        {
          group: "Govern",
          items: [{ s: "s6", label: "Sources &amp;lt; imports" }],
        },
      ],
      allowedScreens: new Set(["s6"]),
      screenId: "s6",
    });

    expect(trail[0]?.label).toBe("Sources &lt; imports");
  });

  it("does not invent an inaccessible Home ancestor for restricted roles", () => {
    const trail = buildBreadcrumbTrail({
      navigation,
      allowedScreens: new Set(["s6"]),
      screenId: "s6",
    });

    expect(trail).toEqual([{ label: "Sources & imports", screenId: "s6" }]);
  });

  it("shows Home as the current location on the Home screen", () => {
    const trail = buildBreadcrumbTrail({
      navigation,
      allowedScreens: new Set(["s2", "s6"]),
      screenId: "s2",
    });

    expect(trail).toEqual([{ label: "Home", screenId: "s2", home: true }]);
    expect(breadcrumbMarkup(trail, esc)).toContain(
      'class="breadcrumb-current breadcrumb-home" aria-current="page"',
    );
  });

  it("mounts the trail in the shared shell and lets nested screens extend it", async () => {
    const [html, css, app, skills] = await Promise.all([
      readFile(`${CONSOLE_DIR}/index.html`, "utf8"),
      readFile(`${CONSOLE_DIR}/app.css`, "utf8"),
      readFile(`${CONSOLE_DIR}/app.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/s16.js`, "utf8"),
    ]);

    expect(html).toContain('id="console-breadcrumbs"');
    expect(html).toContain('aria-label="Breadcrumb"');
    expect(html).toContain('id="screen-content"');
    expect(css).toContain(".breadcrumbs{");
    expect(css).toContain(".breadcrumbs:empty{display:none}");
    expect(css).toContain(".breadcrumb-current");
    expect(app).toContain('from "./breadcrumbs.js"');
    expect(app).toContain("paintBreadcrumbs(id)");
    expect(app).toContain('typeof mod.breadcrumbs === "function"');
    expect(app).toContain("data-breadcrumb-screen");
    expect(skills).toContain("export function breadcrumbs()");
    expect(skills).toContain("export function onBreadcrumbBack()");
  });

  it("contains the setup progress badge inside the collapsed rail", async () => {
    const [css, app, setupChecklist] = await Promise.all([
      readFile(`${CONSOLE_DIR}/app.css`, "utf8"),
      readFile(`${CONSOLE_DIR}/app.js`, "utf8"),
      readFile(`${CONSOLE_DIR}/screens/setup-checklist.js`, "utf8"),
    ]);

    expect(setupChecklist).toContain('class="pill pill--warn setup-badge"');
    expect(app).toContain('aria-label="${item.label}"');
    expect(css).toMatch(/#rail-nav \.setup-badge\{[^}]*max-width:48px[^}]*padding:0[^}]*font:inherit/);
    expect(css).toMatch(/#rail-nav \.setup-badge\{[^}]*color:var\(--gold\)/);
    expect(css).toContain("#rail-nav .setup-badge .dot{display:none}");
    expect(css).toContain("body.rail-collapsed #rail-nav .setup-badge{");
    expect(css).toContain("body.rail-collapsed #rail-nav .setup-badge .dot{");
  });
});
