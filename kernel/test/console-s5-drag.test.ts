import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cancelTopologyDrags,
  consumeTopologyDragClick,
  elasticTopologyOffset,
  handleTopologyPointer,
} from "../console/screens/s5-drag.js";
import { topologyEdgePath } from "../console/screens/s5-topology.js";

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

function styles(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    setProperty(name: string, value: string) { values.set(name, value); },
    removeProperty(name: string) {
      const value = values.get(name) ?? "";
      values.delete(name);
      return value;
    },
    getPropertyValue(name: string) { return values.get(name) ?? ""; },
  };
}

function graphFixture(options: {
  reducedMotion?: boolean;
  mobile?: boolean;
  fromId?: string;
  toId?: string;
  captureThrows?: boolean;
  unrelatedEdgeCount?: number;
} = {}) {
  const fromId = options.fromId ?? "node:a";
  const toId = options.toId ?? "node:b";
  const frames: Array<{ id: number; callback: (time: number) => void }> = [];
  const timers: Array<() => void> = [];
  const viewListeners = new Map<string, Set<(event: ReturnType<typeof pointer>) => void>>();
  let nextFrameId = 1;
  const view = {
    addEventListener(type: string, listener: (event: ReturnType<typeof pointer>) => void) {
      const listeners = viewListeners.get(type) || new Set();
      listeners.add(listener);
      viewListeners.set(type, listeners);
    },
    removeEventListener(type: string, listener: (event: ReturnType<typeof pointer>) => void) {
      viewListeners.get(type)?.delete(listener);
    },
    matchMedia(query: string) {
      return {
        matches:
          (query.includes("prefers-reduced-motion") && options.reducedMotion === true) ||
          (query.includes("max-width") && options.mobile === true),
      };
    },
    requestAnimationFrame(callback: (time: number) => void) {
      const id = nextFrameId++;
      frames.push({ id, callback });
      return id;
    },
    cancelAnimationFrame(id: number) {
      const index = frames.findIndex((entry) => entry.id === id);
      if (index >= 0) frames.splice(index, 1);
    },
    setTimeout(callback: () => void) {
      timers.push(callback);
      return timers.length;
    },
  };
  const links = {
    viewBox: { baseVal: { width: 1000, height: 600 } },
    getBoundingClientRect() {
      return linkRect;
    },
  };
  const linkRect = { width: 800, height: 300 };
  const node = (id: string) => {
    const attrs = new Map([["data-node-id", id]]);
    return {
      attrs,
      classList: classes(),
      style: styles({ "--x": id === fromId ? "10%" : "40%", "--y": id === fromId ? "16.67%" : "50%" }),
      getAttribute(name: string) { return attrs.get(name) ?? null; },
    };
  };
  const fromNode = node(fromId);
  const toNode = node(toId);
  const otherNode = node("node:other");
  const edge = (
    from: string,
    to: string,
    x1: string,
    y1: string,
    x2: string,
    y2: string,
    d: string,
  ) => {
    const attrs = new Map([
      ["data-from", from],
      ["data-to", to],
      ["data-x1", x1],
      ["data-y1", y1],
      ["data-x2", x2],
      ["data-y2", y2],
      ["d", d],
    ]);
    return {
      attrs,
      getAttribute(name: string) { return attrs.get(name) ?? null; },
      setAttribute: vi.fn((name: string, value: string) => { attrs.set(name, value); }),
    };
  };
  const original = topologyEdgePath(100, 100, 400, 300);
  const baseEdge = edge(fromId, toId, "100", "100", "400", "300", original);
  const pulseEdge = edge(fromId, toId, "100", "100", "400", "300", original);
  const unrelatedEdges = Array.from(
    { length: options.unrelatedEdgeCount ?? 1 },
    (_, index) => {
      const x1 = 600 + index;
      const x2 = 700 + index;
      return edge(
        `node:other-${index}`,
        `node:last-${index}`,
        String(x1),
        "50",
        String(x2),
        "80",
        topologyEdgePath(x1, 50, x2, 80),
      );
    },
  );
  const unrelatedEdge = unrelatedEdges[0];
  const unrelatedD = unrelatedEdge.getAttribute("d") || "";
  const invalidD = "M0 0 L1 1";
  const invalidEdge = edge(fromId, "node:invalid", "not-a-number", "0", "10", "10", invalidD);
  const viewportClasses = classes();
  const edges = [baseEdge, pulseEdge, ...unrelatedEdges, invalidEdge];
  const nodes = [fromNode, toNode, otherNode];
  const viewport = {
    classList: viewportClasses,
    ownerDocument: { defaultView: view },
    querySelector(selector: string) {
      return selector === ".memory-graph-links" ? links : null;
    },
    querySelectorAll(selector: string) {
      if (selector === ".memory-graph-edge") return edges;
      if (selector === ".memory-graph-node") return nodes;
      return [];
    },
  };
  const hit = (id: string, graphNode: typeof fromNode) => {
    const attrs = new Map([["data-node-id", id]]);
    const captured = new Set<number>();
    return {
      attrs,
      captured,
      classList: classes(),
      getAttribute(name: string) { return attrs.get(name) ?? null; },
      closest(selector: string) {
        if (selector === ".memory-graph-viewport") return viewport;
        if (selector === ".memory-graph-node") return graphNode;
        return null;
      },
      setPointerCapture: vi.fn((pointerId: number) => {
        if (options.captureThrows) throw new Error("capture unavailable");
        captured.add(pointerId);
      }),
      hasPointerCapture: vi.fn((pointerId: number) => captured.has(pointerId)),
      releasePointerCapture: vi.fn((pointerId: number) => captured.delete(pointerId)),
    };
  };
  const fromHit = hit(fromId, fromNode);
  const toHit = hit(toId, toNode);

  return {
    baseEdge,
    dispatchView(event: ReturnType<typeof pointer>) {
      for (const listener of viewListeners.get(event.type) || []) listener(event);
    },
    frames,
    fromHit,
    fromNode,
    invalidD,
    invalidEdge,
    original,
    pulseEdge,
    runNextFrame(time: number) {
      const next = frames.shift();
      expect(next, "expected a queued animation frame").toBeDefined();
      next?.callback(time);
    },
    setLinkSize(width: number, height: number) {
      linkRect.width = width;
      linkRect.height = height;
    },
    timers,
    toHit,
    toNode,
    unrelatedD,
    unrelatedEdge,
    unrelatedEdges,
    viewport,
  };
}

function pointer(
  type: string,
  pointerId: number,
  clientX: number,
  clientY: number,
  overrides: Record<string, unknown> = {},
) {
  return {
    type,
    pointerId,
    clientX,
    clientY,
    button: 0,
    isPrimary: true,
    pointerType: "mouse",
    preventDefault: vi.fn(),
    ...overrides,
  };
}

describe("S5 elastic memory graph drag", () => {
  afterEach(() => {
    cancelTopologyDrags();
  });

  it("moves a node and both attached paths, then restores the exact fixed layout on cancel", () => {
    const fixture = graphFixture({ reducedMotion: true, unrelatedEdgeCount: 250 });
    expect(handleTopologyPointer(pointer("pointerdown", 1, 100, 100), fixture.fromHit)).toBe(true);
    const move = pointer("pointermove", 1, 200, 150);
    expect(handleTopologyPointer(move, fixture.fromHit)).toBe(true);
    fixture.runNextFrame(16);

    const dx = elasticTopologyOffset(100);
    const dy = elasticTopologyOffset(50);
    expect(parseFloat(fixture.fromNode.style.getPropertyValue("--drag-x"))).toBeCloseTo(dx);
    expect(parseFloat(fixture.fromNode.style.getPropertyValue("--drag-y"))).toBeCloseTo(dy);
    const expected = topologyEdgePath(
      100 + dx * (1000 / 800),
      100 + dy * (600 / 300),
      400,
      300,
    );
    expect(fixture.baseEdge.getAttribute("d")).toBe(expected);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(expected);
    expect(fixture.unrelatedEdge.getAttribute("d")).toBe(fixture.unrelatedD);
    for (const edge of fixture.unrelatedEdges) {
      expect(edge.setAttribute).not.toHaveBeenCalled();
    }
    expect(fixture.invalidEdge.getAttribute("d")).toBe(fixture.invalidD);
    expect(move.preventDefault).toHaveBeenCalledOnce();

    expect(handleTopologyPointer(pointer("pointercancel", 1, 200, 150), fixture.fromHit)).toBe(true);
    expect(fixture.fromNode.style.getPropertyValue("--drag-x")).toBe("");
    expect(fixture.fromNode.style.getPropertyValue("--drag-y")).toBe("");
    expect(fixture.fromNode.style.getPropertyValue("--x")).toBe("10%");
    expect(fixture.fromNode.style.getPropertyValue("--y")).toBe("16.67%");
    expect(fixture.baseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.fromHit.releasePointerCapture).toHaveBeenCalledWith(1);
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(false);
  });

  it("suppresses exactly the pointer click after maximum drag excursion", () => {
    const fixture = graphFixture({ reducedMotion: true });
    handleTopologyPointer(pointer("pointerdown", 2, 50, 50), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 2, 110, 50), fixture.fromHit);
    fixture.runNextFrame(16);
    handleTopologyPointer(pointer("pointermove", 2, 50, 50), fixture.fromHit);
    fixture.runNextFrame(32);
    handleTopologyPointer(pointer("pointerup", 2, 50, 50), fixture.fromHit);

    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 0 })).toBe(false);
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(true);
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(false);

    handleTopologyPointer(pointer("pointerdown", 3, 50, 50), fixture.fromHit);
    handleTopologyPointer(pointer("pointerup", 3, 50, 50), fixture.fromHit);
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(false);
  });

  it("keeps coarse-pointer movement inside native click slop as a tap", () => {
    const fixture = graphFixture({ reducedMotion: true });
    handleTopologyPointer(
      pointer("pointerdown", 13, 50, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    handleTopologyPointer(
      pointer("pointermove", 13, 65, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    fixture.runNextFrame(16);
    handleTopologyPointer(
      pointer("pointerup", 13, 65, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(false);

    handleTopologyPointer(
      pointer("pointerdown", 17, 50, 50, { pointerType: "pen" }),
      fixture.fromHit,
    );
    handleTopologyPointer(
      pointer("pointermove", 17, 55, 50, { pointerType: "pen" }),
      fixture.fromHit,
    );
    fixture.runNextFrame(32);
    handleTopologyPointer(
      pointer("pointerup", 17, 55, 50, { pointerType: "pen" }),
      fixture.fromHit,
    );
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(false);

    handleTopologyPointer(
      pointer("pointerdown", 18, 50, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    handleTopologyPointer(
      pointer("pointermove", 18, 70, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    fixture.runNextFrame(48);
    handleTopologyPointer(
      pointer("pointerup", 18, 70, 50, { pointerType: "touch" }),
      fixture.fromHit,
    );
    expect(consumeTopologyDragClick(fixture.fromHit, { detail: 1 })).toBe(true);
  });

  it("derives a connector from both node offsets while an earlier node springs home", () => {
    const fixture = graphFixture();
    handleTopologyPointer(pointer("pointerdown", 4, 100, 100), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 4, 180, 100), fixture.fromHit);
    fixture.runNextFrame(16);
    handleTopologyPointer(pointer("pointerup", 4, 180, 100), fixture.fromHit);
    fixture.runNextFrame(0);
    fixture.runNextFrame(0);

    handleTopologyPointer(pointer("pointerdown", 5, 400, 300), fixture.toHit);
    handleTopologyPointer(pointer("pointermove", 5, 360, 330), fixture.toHit);
    fixture.runNextFrame(80);
    fixture.runNextFrame(80);

    const fromX = parseFloat(fixture.fromNode.style.getPropertyValue("--drag-x"));
    const fromY = parseFloat(fixture.fromNode.style.getPropertyValue("--drag-y"));
    const toX = parseFloat(fixture.toNode.style.getPropertyValue("--drag-x"));
    const toY = parseFloat(fixture.toNode.style.getPropertyValue("--drag-y"));
    const expected = topologyEdgePath(
      100 + fromX * (1000 / 800),
      100 + fromY * (600 / 300),
      400 + toX * (1000 / 800),
      300 + toY * (600 / 300),
    );
    expect(fixture.baseEdge.getAttribute("d")).toBe(expected);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(expected);
  });

  it("finishes the ordinary spring and restores exact geometry", () => {
    const fixture = graphFixture();
    handleTopologyPointer(pointer("pointerdown", 10, 100, 100), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 10, 180, 130), fixture.fromHit);
    fixture.runNextFrame(16);
    handleTopologyPointer(pointer("pointerup", 10, 180, 130), fixture.fromHit);

    fixture.runNextFrame(100);
    fixture.runNextFrame(116);
    fixture.runNextFrame(540);

    expect(fixture.fromNode.style.getPropertyValue("--drag-x")).toBe("");
    expect(fixture.fromNode.style.getPropertyValue("--drag-y")).toBe("");
    expect(fixture.fromNode.classList.contains("is-returning")).toBe(false);
    expect(fixture.baseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.frames).toHaveLength(0);
  });

  it("re-grabs a returning node without snapping it to the origin", () => {
    const fixture = graphFixture();
    handleTopologyPointer(pointer("pointerdown", 14, 100, 100), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 14, 180, 130), fixture.fromHit);
    fixture.runNextFrame(16);
    handleTopologyPointer(pointer("pointerup", 14, 180, 130), fixture.fromHit);
    fixture.runNextFrame(100);
    fixture.runNextFrame(116);
    const beforeX = parseFloat(fixture.fromNode.style.getPropertyValue("--drag-x"));
    const beforeY = parseFloat(fixture.fromNode.style.getPropertyValue("--drag-y"));

    handleTopologyPointer(pointer("pointerdown", 15, 180, 130), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 15, 180, 130), fixture.fromHit);
    fixture.runNextFrame(132);

    expect(parseFloat(fixture.fromNode.style.getPropertyValue("--drag-x"))).toBeCloseTo(beforeX);
    expect(parseFloat(fixture.fromNode.style.getPropertyValue("--drag-y"))).toBeCloseTo(beforeY);
    handleTopologyPointer(pointer("pointercancel", 15, 180, 130), fixture.fromHit);
  });

  it("restores stretched paths when the SVG becomes temporarily unmeasurable", () => {
    const fixture = graphFixture({ reducedMotion: true });
    handleTopologyPointer(pointer("pointerdown", 16, 100, 100), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 16, 180, 130), fixture.fromHit);
    fixture.runNextFrame(16);
    expect(fixture.baseEdge.getAttribute("d")).not.toBe(fixture.original);

    fixture.setLinkSize(0, 0);
    handleTopologyPointer(pointer("pointercancel", 16, 180, 130), fixture.fromHit);

    expect(fixture.baseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(fixture.original);
  });

  it("keeps the original connector bend direction after endpoints cross", () => {
    const crossed = topologyEdgePath(160, 100, 110, 100, 1);
    expect(crossed).toContain("C178 100");
  });

  it("does not start without pointer capture and tears down active graph state exactly", () => {
    const unavailable = graphFixture({ captureThrows: true });
    expect(handleTopologyPointer(
      pointer("pointerdown", 11, 100, 100),
      unavailable.fromHit,
    )).toBe(false);
    expect(unavailable.fromNode.classList.contains("is-dragging")).toBe(false);
    expect(unavailable.viewport.classList.contains("is-dragging")).toBe(false);
    expect(handleTopologyPointer(
      pointer("pointermove", 11, 180, 130),
      unavailable.fromHit,
    )).toBe(false);

    const fixture = graphFixture();
    handleTopologyPointer(pointer("pointerdown", 12, 100, 100), fixture.fromHit);
    handleTopologyPointer(pointer("pointermove", 12, 180, 130), fixture.fromHit);
    fixture.runNextFrame(16);
    expect(fixture.baseEdge.getAttribute("d")).not.toBe(fixture.original);

    cancelTopologyDrags();

    expect(fixture.fromNode.style.getPropertyValue("--drag-x")).toBe("");
    expect(fixture.fromNode.style.getPropertyValue("--drag-y")).toBe("");
    expect(fixture.fromNode.classList.contains("is-dragging")).toBe(false);
    expect(fixture.viewport.classList.contains("is-dragging")).toBe(false);
    expect(fixture.baseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.pulseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.fromHit.releasePointerCapture).toHaveBeenCalledWith(12);
    expect(handleTopologyPointer(
      pointer("pointermove", 12, 200, 160),
      fixture.fromHit,
    )).toBe(false);
    expect(fixture.frames).toHaveLength(0);
  });

  it("continues and ends a captured drag when events retarget outside the node", () => {
    const fixture = graphFixture({ reducedMotion: true });
    handleTopologyPointer(pointer("pointerdown", 19, 100, 100), fixture.fromHit);

    fixture.dispatchView(pointer("pointermove", 19, 180, 130));
    fixture.runNextFrame(16);
    expect(fixture.baseEdge.getAttribute("d")).not.toBe(fixture.original);

    fixture.dispatchView(pointer("pointerup", 19, 180, 130));
    expect(fixture.baseEdge.getAttribute("d")).toBe(fixture.original);
    expect(fixture.fromNode.classList.contains("is-dragging")).toBe(false);
    expect(fixture.fromHit.releasePointerCapture).toHaveBeenCalledWith(19);
  });

  it("handles hostile node ids without selectors and ignores unsafe pointer modes", () => {
    const hostileId = 'node:"] .memory-graph-node';
    const fixture = graphFixture({ reducedMotion: true, fromId: hostileId });
    expect(handleTopologyPointer(pointer("pointerdown", 6, 20, 20), fixture.fromHit)).toBe(true);
    handleTopologyPointer(pointer("pointermove", 6, 60, 20), fixture.fromHit);
    fixture.runNextFrame(16);
    expect(fixture.baseEdge.getAttribute("d")).not.toBe(fixture.original);
    expect(fixture.invalidEdge.getAttribute("d")).toBe(fixture.invalidD);
    handleTopologyPointer(pointer("lostpointercapture", 6, 60, 20), fixture.fromHit);

    expect(handleTopologyPointer(
      pointer("pointerdown", 7, 20, 20, { button: 2 }),
      fixture.fromHit,
    )).toBe(false);
    expect(handleTopologyPointer(
      pointer("pointerdown", 8, 20, 20, { isPrimary: false }),
      fixture.fromHit,
    )).toBe(false);
    const mobile = graphFixture({ mobile: true });
    expect(handleTopologyPointer(pointer("pointerdown", 9, 20, 20), mobile.fromHit)).toBe(false);
  });
});
