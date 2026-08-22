import { describe, expect, it } from "vitest";

import {
  clampZoom,
  consumeGraphPanClick,
  fitGraph,
  graphTransform,
  handleGraphPan,
  toggleGraphFullscreen,
  zoomGraph,
  zoomGraphBy,
} from "../console/screens/s5-viewport.js";
import { renderTopology } from "../console/screens/s5-topology.js";
import { actions, graphSearchMatches } from "../console/screens/s5.js";

const esc = (value: unknown): string => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");

function classes(initial: string[] = []) {
  const names = new Set(initial);
  return {
    names,
    add(name: string) { names.add(name); },
    remove(name: string) { names.delete(name); },
    contains(name: string) { return names.has(name); },
    toggle(name: string, force?: boolean) {
      if (force === undefined ? !names.has(name) : force) names.add(name);
      else names.delete(name);
    },
  };
}

/** A viewport with one canvas child, enough for the transform maths. */
function viewportFixture() {
  const canvasStyle = new Map<string, string>();
  const canvas = {
    style: {
      setProperty(name: string, value: string) { canvasStyle.set(name, value); },
    },
  };
  const attributes = new Map<string, string>([["data-zoom", "1"]]);
  const section = {
    classList: classes(),
    querySelectorAll() { return [] as unknown[]; },
    querySelector() { return null; },
  };
  const viewport = {
    canvasStyle,
    classList: classes(),
    getAttribute: (name: string) => attributes.get(name) ?? null,
    setAttribute: (name: string, value: string) => { attributes.set(name, value); },
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 1000, height: 600 }),
    querySelector: (selector: string) => (selector === "[data-graph-canvas]" ? canvas : null),
    closest: (selector: string) => (selector === ".memory-graph" ? section : null),
    setPointerCapture() {},
    releasePointerCapture() {},
  };
  return { viewport, section, canvasStyle };
}

function pointer(type: string, x: number, y: number) {
  return {
    type,
    pointerId: 1,
    isPrimary: true,
    button: 0,
    clientX: x,
    clientY: y,
    preventDefault() {},
  };
}

describe("S5 graph viewport", () => {
  it("clamps zoom to a legible band in both directions", () => {
    expect(clampZoom(0.05)).toBe(0.4);
    expect(clampZoom(12)).toBe(3);
    expect(clampZoom(Number.NaN)).toBe(1);

    const { viewport } = viewportFixture();
    for (let step = 0; step < 20; step += 1) zoomGraphBy(viewport as never, 1);
    expect(graphTransform(viewport as never).zoom).toBe(3);
    for (let step = 0; step < 40; step += 1) zoomGraphBy(viewport as never, -1);
    expect(graphTransform(viewport as never).zoom).toBe(0.4);
  });

  it("zooms around the pointer so the anchor point stays put", () => {
    const { viewport, canvasStyle } = viewportFixture();
    // Anchor on the left edge: zooming in must pan right to hold it in place.
    zoomGraph(viewport as never, 2, { x: 0, y: 300 });
    const after = graphTransform(viewport as never);
    expect(after.zoom).toBe(2);
    expect(after.panX).toBe(500);
    expect(after.panY).toBe(0);
    expect(canvasStyle.get("--zoom")).toBe("2");
    expect(canvasStyle.get("--pan-x")).toBe("500px");
  });

  it("fits back to the authored composition", () => {
    const { viewport } = viewportFixture();
    zoomGraph(viewport as never, 2, { x: 0, y: 0 });
    fitGraph(viewport as never);
    expect(graphTransform(viewport as never)).toEqual({ zoom: 1, panX: 0, panY: 0 });
  });

  it("pans the canvas and swallows the click that ends the pan", () => {
    const { viewport } = viewportFixture();
    expect(handleGraphPan(pointer("pointerdown", 100, 100), viewport as never)).toBe(true);
    handleGraphPan(pointer("pointermove", 160, 130), viewport as never);
    expect(graphTransform(viewport as never)).toMatchObject({ panX: 60, panY: 30 });
    expect(handleGraphPan(pointer("pointerup", 160, 130), viewport as never)).toBe(true);

    // The deselect-on-empty-space click must not fire after a real drag...
    expect(consumeGraphPanClick(viewport as never)).toBe(true);
    // ...and the suppression is single-use, so the next real click lands.
    expect(consumeGraphPanClick(viewport as never)).toBe(false);
  });

  it("leaves a click through when the pointer never moved", () => {
    const { viewport } = viewportFixture();
    handleGraphPan(pointer("pointerdown", 40, 40), viewport as never);
    handleGraphPan(pointer("pointermove", 41, 40), viewport as never);
    expect(handleGraphPan(pointer("pointerup", 41, 40), viewport as never)).toBe(false);
    expect(consumeGraphPanClick(viewport as never)).toBe(false);
  });

  // Capturing the pointer on the viewport retargets the follow-up click to the
  // viewport, which swallowed zoom / fit / full screen entirely.
  it("never starts a pan from the control stack, so the buttons keep their click", () => {
    const { viewport } = viewportFixture();
    const button = { closest: (selector: string) => (selector.includes("button") ? button : null) };
    const onButton = { ...pointer("pointerdown", 20, 20), target: button };
    expect(handleGraphPan(onButton as never, viewport as never)).toBe(false);

    // Empty canvas still pans, and the pointer id was never consumed above.
    const onCanvas = { ...pointer("pointerdown", 20, 20), target: { closest: () => null } };
    expect(handleGraphPan(onCanvas as never, viewport as never)).toBe(true);
    handleGraphPan(pointer("pointerup", 20, 20), viewport as never);
  });

  it("zooms a fifth more gently on the wheel than on the buttons", () => {
    const { viewport } = viewportFixture();
    const wheel = { deltaY: -100, clientX: 500, clientY: 300, preventDefault() {} };
    actions["topo-zoom"](null as never, viewport as never, wheel as never);
    expect(graphTransform(viewport as never).zoom).toBe(1.096);

    actions["topo-zoom"](null as never, viewport as never, { ...wheel, deltaY: 100 } as never);
    expect(graphTransform(viewport as never).zoom).toBe(1);
  });

  it("toggles full screen on the section and refits", () => {
    const { viewport, section } = viewportFixture();
    zoomGraph(viewport as never, 2, { x: 0, y: 0 });
    const labels = new Map<string, string>([
      ["data-expand-label", "Full screen"],
      ["data-collapse-label", "Exit full screen"],
    ]);
    const button = {
      getAttribute: (name: string) => labels.get(name) ?? null,
      setAttribute: (name: string, value: string) => { labels.set(name, value); },
      querySelector: () => null,
    };
    expect(toggleGraphFullscreen(viewport as never, button as never)).toBe(true);
    expect(section.classList.contains("is-fullscreen")).toBe(true);
    expect(labels.get("aria-pressed")).toBe("true");
    expect(labels.get("aria-label")).toBe("Exit full screen");
    // Entering full screen resizes the box, so the transform starts clean.
    expect(graphTransform(viewport as never)).toEqual({ zoom: 1, panX: 0, panY: 0 });

    expect(toggleGraphFullscreen(viewport as never, button as never)).toBe(false);
    expect(section.classList.contains("is-fullscreen")).toBe(false);
  });
});

describe("S5 graph search", () => {
  const data = {
    "b:src-1": { label: "Filesystem", type: "Connected source", search: "filesystem connected source acme space" },
    "s:skill-1": { label: "File exporter", type: "Skill", search: "file exporter skill acme space" },
    "a:agent-1": { label: "Support bot", type: "Agent", search: "support bot agent acme space" },
  };

  it("returns null for an empty query so the canvas goes back to normal", () => {
    expect(graphSearchMatches(data, "")).toBeNull();
    expect(graphSearchMatches(data, "   ")).toBeNull();
  });

  it("matches on name, type, and space, and ranks prefix hits first", () => {
    expect(graphSearchMatches(data, "file")?.map((match) => match.id))
      .toEqual(["s:skill-1", "b:src-1"]);
    expect(graphSearchMatches(data, "AGENT")?.map((match) => match.id)).toEqual(["a:agent-1"]);
    expect(graphSearchMatches(data, "acme")).toHaveLength(3);
    expect(graphSearchMatches(data, "nothing-here")).toEqual([]);
  });

  it("only ever searches the payload the server already sent", () => {
    // Nothing in the search path fetches; an empty payload can match nothing.
    expect(graphSearchMatches({}, "filesystem")).toEqual([]);
  });
});

describe("S5 graph markup", () => {
  const topology = {
    pinned: [],
    governedPins: [],
    topology: {
      scope: "selected-subtree",
      sources: [{
        id: "src-1", namespace: "acme", kind: "filesystem", syncStatus: "synced",
        lastSync: "2026-07-16T12:00:00.000Z", lastSyncError: null, lifecycleState: "active",
      }],
      policies: [],
      memories: [],
      knowledgeBases: [],
      skills: [],
      agents: [{ id: "agent-1", namespace: "acme", actor: "Support bot" }],
      activeFacts: 4,
      activityFacts: 1,
      companyPublishedFacts: 2,
      routing: { mode: "fixed", name: "baseline" },
    },
  };

  it("ships the viewport controls, the hint, and the search field", () => {
    const html = renderTopology({ esc } as never, topology);

    expect(html).toContain('data-wheel-action="topo-zoom"');
    expect(html).toContain('data-pointer-action="topo-pan"');
    expect(html).toContain("memory-graph-canvas");
    for (const action of ["topo-zoom-in", "topo-zoom-out", "topo-fit", "topo-fullscreen"]) {
      expect(html).toContain(`data-action="${action}"`);
    }
    expect(html).toContain("drag to pan · scroll to zoom");
    expect(html).toContain('data-input-action="topo-search"');
    expect(html).toContain('data-hotkey="/"');
    // The header states the size of the graph the reader is looking at.
    expect(html).toMatch(/class="memory-graph-stats">[0-9]+ nodes · [0-9]+ links/);
  });

  it("gives the legend counts and memory lanes icons and plain-language detail", () => {
    const html = renderTopology({ esc } as never, topology);

    // Every count carries its kind, so the icon picks up the graph's colour.
    for (const kind of ["policy", "backend", "knowledge", "skill", "agent"]) {
      expect(html).toContain(`<li class="memory-graph-stat" data-kind="${kind}">`);
    }
    expect((html.match(/class="memory-graph-stat-icon"/g) ?? []).length).toBe(6);
    expect(html).toContain("Backend files");
    expect(html).toContain("Knowledge uploads");
    // Each lane says what it holds instead of standing as a bare colour swatch.
    expect((html.match(/class="memory-graph-lane"/g) ?? []).length).toBe(4);
    expect(html).toContain("Packed into every agent call");
    expect(html).toContain("Git-governed long-term store");
  });
});
