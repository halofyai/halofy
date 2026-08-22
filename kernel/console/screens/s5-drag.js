import {
  GRAPH_VIEW_HEIGHT,
  GRAPH_VIEW_WIDTH,
  topologyEdgePath,
} from "./s5-topology.js";

const MAX_ELASTIC_OFFSET = 72;
const POINTER_DRAG_THRESHOLD = 4;
const COARSE_POINTER_DRAG_THRESHOLD = 16;
const RETURN_DURATION_MS = 440;

const activeDrags = new Map();
const graphStates = new WeakMap();
const liveGraphStates = new Set();
const suppressedPointerClicks = new WeakSet();

/** Resist long pulls while keeping short pointer movements direct. */
export function elasticTopologyOffset(delta) {
  const value = Number(delta);
  if (!Number.isFinite(value) || value === 0) return 0;
  const offset =
    Math.sign(value) *
    MAX_ELASTIC_OFFSET *
    (1 - Math.exp(-Math.abs(value) / MAX_ELASTIC_OFFSET));
  return Math.round(offset * 1000) / 1000;
}

/** Consume only the pointer-generated click that follows a completed drag. */
export function consumeTopologyDragClick(hit, event) {
  if (!hit || !event || Number(event.detail) <= 0 || !suppressedPointerClicks.has(hit)) {
    return false;
  }
  suppressedPointerClicks.delete(hit);
  return true;
}

/** Restore every transient graph transform before navigation or a re-render. */
export function cancelTopologyDrags() {
  for (const [pointerId, drag] of activeDrags) {
    activeDrags.delete(pointerId);
    drag.removeFallback?.();
    drag.node.classList?.remove("is-dragging");
    suppressedPointerClicks.delete(drag.hit);
    releaseCapture(drag.hit, pointerId);
  }
  for (const graph of liveGraphStates) {
    if (graph.renderFrame !== null) {
      graph.view.cancelAnimationFrame?.(graph.renderFrame);
      graph.renderFrame = null;
    }
    for (const spring of graph.springs.values()) {
      if (spring.frame !== null) graph.view.cancelAnimationFrame?.(spring.frame);
    }
    graph.springs.clear();
    for (const motion of graph.motions.values()) {
      resetNode(motion.node);
    }
    graph.motions.clear();
    graph.dirtyNodes.clear();
    for (const edge of graph.edges) {
      edge.path.setAttribute?.("d", edge.originalD);
    }
    graph.viewport.classList?.remove("is-dragging");
    graphStates.delete(graph.viewport);
  }
  liveGraphStates.clear();
}

/** Handle the complete delegated pointer lifecycle for one graph node. */
export function handleTopologyPointer(event, hit) {
  if (!event || !hit) return false;
  if (event.type === "pointerdown") return beginDrag(event, hit);
  if (event.type === "pointermove") return moveDrag(event);
  if (
    event.type === "pointerup" ||
    event.type === "pointercancel" ||
    event.type === "lostpointercapture"
  ) {
    return endDrag(event);
  }
  return false;
}

function beginDrag(event, hit) {
  if (event.isPrimary !== true || event.button !== 0 || !Number.isFinite(event.pointerId)) {
    return false;
  }
  if (activeDrags.has(event.pointerId)) return false;
  const viewport = hit.closest?.(".memory-graph-viewport");
  const node = hit.closest?.(".memory-graph-node");
  const nodeId = hit.getAttribute?.("data-node-id") || "";
  const view = viewport?.ownerDocument?.defaultView;
  if (!viewport || !node || !nodeId || !view || isStaticList(view)) return false;

  const graph = graphState(viewport);
  if (!graph || !graphScale(graph) || typeof hit.setPointerCapture !== "function") {
    forgetGraphIfIdle(graph);
    return false;
  }
  try {
    hit.setPointerCapture(event.pointerId);
  } catch {
    forgetGraphIfIdle(graph);
    return false;
  }

  const currentMotion = graph.motions.get(nodeId);
  cancelSpring(graph, nodeId, false);
  node.classList?.remove("is-returning");

  const drag = {
    baseRawX: inverseElasticTopologyOffset(currentMotion?.dx),
    baseRawY: inverseElasticTopologyOffset(currentMotion?.dy),
    clickThreshold:
      event.pointerType === "touch" || event.pointerType === "pen"
        ? COARSE_POINTER_DRAG_THRESHOLD
        : POINTER_DRAG_THRESHOLD,
    graph,
    hit,
    maxExcursion: 0,
    node,
    nodeId,
    pointerId: event.pointerId,
    startX: finite(event.clientX),
    startY: finite(event.clientY),
  };
  activeDrags.set(event.pointerId, drag);
  drag.removeFallback = installDragFallback(drag);
  node.classList?.add("is-dragging");
  viewport.classList?.add("is-dragging");
  return true;
}

function moveDrag(event) {
  const drag = activeDrags.get(event.pointerId);
  if (!drag) return false;
  const rawX = finite(event.clientX) - drag.startX;
  const rawY = finite(event.clientY) - drag.startY;
  drag.maxExcursion = Math.max(drag.maxExcursion, Math.hypot(rawX, rawY));
  drag.graph.motions.set(drag.nodeId, {
    dx: elasticTopologyOffset(drag.baseRawX + rawX),
    dy: elasticTopologyOffset(drag.baseRawY + rawY),
    node: drag.node,
  });
  markNodeDirty(drag.graph, drag.nodeId);
  queueGraphRender(drag.graph);
  if (drag.maxExcursion >= drag.clickThreshold) event.preventDefault?.();
  return true;
}

function endDrag(event) {
  const drag = activeDrags.get(event.pointerId);
  if (!drag) return false;
  activeDrags.delete(event.pointerId);
  drag.removeFallback?.();
  drag.node.classList?.remove("is-dragging");
  if (!Array.from(activeDrags.values()).some((entry) => entry.graph === drag.graph)) {
    drag.graph.viewport.classList?.remove("is-dragging");
  }
  if (event.type !== "lostpointercapture") {
    releaseCapture(drag.hit, event.pointerId);
  }
  flushGraphRender(drag.graph);

  if (event.type === "pointerup" && drag.maxExcursion >= drag.clickThreshold) {
    suppressedPointerClicks.add(drag.hit);
    drag.graph.view.setTimeout?.(() => {
      suppressedPointerClicks.delete(drag.hit);
    }, 0);
  }
  springHome(drag.graph, drag.nodeId, drag.node);
  return true;
}

function graphState(viewport) {
  const existing = graphStates.get(viewport);
  if (existing) return existing;
  const links = viewport.querySelector?.(".memory-graph-links");
  if (!links) return null;
  const edges = Array.from(viewport.querySelectorAll?.(".memory-graph-edge") || [])
    .map(readEdge)
    .filter(Boolean);
  const incidentEdges = new Map();
  for (const edge of edges) {
    for (const nodeId of new Set([edge.from, edge.to])) {
      if (!nodeId) continue;
      const entries = incidentEdges.get(nodeId) || new Set();
      entries.add(edge);
      incidentEdges.set(nodeId, entries);
    }
  }
  const state = {
    dirtyNodes: new Set(),
    edges,
    incidentEdges,
    links,
    motions: new Map(),
    renderFrame: null,
    springs: new Map(),
    view: viewport.ownerDocument.defaultView,
    viewport,
  };
  graphStates.set(viewport, state);
  liveGraphStates.add(state);
  return state;
}

function readEdge(path) {
  const x1 = Number(path.getAttribute?.("data-x1"));
  const y1 = Number(path.getAttribute?.("data-y1"));
  const x2 = Number(path.getAttribute?.("data-x2"));
  const y2 = Number(path.getAttribute?.("data-y2"));
  const originalD = path.getAttribute?.("d");
  const storedDirection = Number(path.getAttribute?.("data-bend-direction"));
  if (![x1, y1, x2, y2].every(Number.isFinite) || typeof originalD !== "string") {
    return null;
  }
  return {
    bendDirection:
      storedDirection === -1 || storedDirection === 1
        ? storedDirection
        : x2 >= x1 ? 1 : -1,
    from: path.getAttribute?.("data-from") || "",
    originalD,
    path,
    to: path.getAttribute?.("data-to") || "",
    x1,
    x2,
    y1,
    y2,
  };
}

function graphScale(graph) {
  const rect = graph.links.getBoundingClientRect?.();
  const base = graph.links.viewBox?.baseVal;
  const rectWidth = Number(rect?.width);
  const rectHeight = Number(rect?.height);
  const viewWidth = Number(base?.width ?? GRAPH_VIEW_WIDTH);
  const viewHeight = Number(base?.height ?? GRAPH_VIEW_HEIGHT);
  if (
    ![rectWidth, rectHeight, viewWidth, viewHeight].every(Number.isFinite) ||
    rectWidth <= 0 ||
    rectHeight <= 0 ||
    viewWidth <= 0 ||
    viewHeight <= 0
  ) {
    return null;
  }
  return {
    x: viewWidth / rectWidth,
    y: viewHeight / rectHeight,
  };
}

function queueGraphRender(graph) {
  if (graph.renderFrame !== null) return;
  if (typeof graph.view.requestAnimationFrame !== "function") {
    renderGraph(graph);
    return;
  }
  graph.renderFrame = graph.view.requestAnimationFrame(() => {
    graph.renderFrame = null;
    renderGraph(graph);
  });
}

function flushGraphRender(graph) {
  if (graph.renderFrame !== null) {
    graph.view.cancelAnimationFrame?.(graph.renderFrame);
    graph.renderFrame = null;
  }
  renderGraph(graph);
}

function renderGraph(graph) {
  const dirtyEdges = new Set();
  for (const nodeId of graph.dirtyNodes) {
    const motion = graph.motions.get(nodeId);
    if (motion) {
      motion.node.style?.setProperty("--drag-x", `${cssNumber(motion.dx)}px`);
      motion.node.style?.setProperty("--drag-y", `${cssNumber(motion.dy)}px`);
    }
    for (const edge of graph.incidentEdges.get(nodeId) || []) dirtyEdges.add(edge);
  }
  const scale = graphScale(graph);
  if (!scale) {
    for (const edge of dirtyEdges) edge.path.setAttribute?.("d", edge.originalD);
    graph.dirtyNodes.clear();
    return;
  }
  for (const edge of dirtyEdges) {
    const from = graph.motions.get(edge.from);
    const to = graph.motions.get(edge.to);
    if (!from && !to) {
      edge.path.setAttribute?.("d", edge.originalD);
      continue;
    }
    edge.path.setAttribute?.(
      "d",
      topologyEdgePath(
        edge.x1 + (from?.dx || 0) * scale.x,
        edge.y1 + (from?.dy || 0) * scale.y,
        edge.x2 + (to?.dx || 0) * scale.x,
        edge.y2 + (to?.dy || 0) * scale.y,
        edge.bendDirection,
      ),
    );
  }
  graph.dirtyNodes.clear();
}

function springHome(graph, nodeId, node) {
  const motion = graph.motions.get(nodeId);
  if (!motion) {
    clearNodeMotion(graph, nodeId, node);
    return;
  }
  const reducedMotion = graph.view.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
  if (reducedMotion || typeof graph.view.requestAnimationFrame !== "function") {
    clearNodeMotion(graph, nodeId, node);
    flushGraphRender(graph);
    return;
  }

  cancelSpring(graph, nodeId, false);
  node.classList?.add("is-returning");
  const origin = { dx: motion.dx, dy: motion.dy };
  const spring = { frame: null, startedAt: null };
  const step = (time) => {
    if (spring.startedAt === null) spring.startedAt = time;
    const progress = Math.min(1, Math.max(0, (time - spring.startedAt) / RETURN_DURATION_MS));
    if (progress >= 1) {
      graph.springs.delete(nodeId);
      clearNodeMotion(graph, nodeId, node);
      flushGraphRender(graph);
      return;
    }
    const factor = Math.exp(-7 * progress) * Math.cos(10 * progress);
    graph.motions.set(nodeId, {
      dx: origin.dx * factor,
      dy: origin.dy * factor,
      node,
    });
    markNodeDirty(graph, nodeId);
    renderGraph(graph);
    spring.frame = graph.view.requestAnimationFrame(step);
  };
  graph.springs.set(nodeId, spring);
  spring.frame = graph.view.requestAnimationFrame(step);
}

function cancelSpring(graph, nodeId, reset) {
  const spring = graph.springs.get(nodeId);
  if (!spring) return;
  if (spring.frame !== null) graph.view.cancelAnimationFrame?.(spring.frame);
  graph.springs.delete(nodeId);
  if (reset) {
    const motion = graph.motions.get(nodeId);
    clearNodeMotion(graph, nodeId, motion?.node);
    flushGraphRender(graph);
  }
}

function clearNodeMotion(graph, nodeId, node) {
  graph.motions.delete(nodeId);
  resetNode(node);
  markNodeDirty(graph, nodeId);
}

function markNodeDirty(graph, nodeId) {
  if (nodeId) graph.dirtyNodes.add(nodeId);
}

function resetNode(node) {
  node?.style?.removeProperty("--drag-x");
  node?.style?.removeProperty("--drag-y");
  node?.classList?.remove("is-dragging");
  node?.classList?.remove("is-returning");
}

function installDragFallback(drag) {
  const view = drag.graph.view;
  if (typeof view.addEventListener !== "function") return () => {};
  const onMove = (event) => {
    if (activeDrags.get(event.pointerId) === drag) moveDrag(event);
  };
  const onEnd = (event) => {
    if (activeDrags.get(event.pointerId) === drag) endDrag(event);
  };
  view.addEventListener("pointermove", onMove, true);
  view.addEventListener("pointerup", onEnd, true);
  view.addEventListener("pointercancel", onEnd, true);
  view.addEventListener("lostpointercapture", onEnd, true);
  return () => {
    view.removeEventListener?.("pointermove", onMove, true);
    view.removeEventListener?.("pointerup", onEnd, true);
    view.removeEventListener?.("pointercancel", onEnd, true);
    view.removeEventListener?.("lostpointercapture", onEnd, true);
  };
}

function releaseCapture(hit, pointerId) {
  try {
    if (!hit.hasPointerCapture || hit.hasPointerCapture(pointerId)) {
      hit.releasePointerCapture?.(pointerId);
    }
  } catch {
    // Capture may already be gone after a platform cancellation.
  }
}

function forgetGraphIfIdle(graph) {
  if (
    !graph ||
    graph.motions.size ||
    graph.springs.size ||
    Array.from(activeDrags.values()).some((drag) => drag.graph === graph)
  ) {
    return;
  }
  liveGraphStates.delete(graph);
  graphStates.delete(graph.viewport);
}

function isStaticList(view) {
  return view.matchMedia?.("(max-width: 720px)")?.matches === true;
}

function cssNumber(value) {
  return Math.round(value * 1000) / 1000;
}

function inverseElasticTopologyOffset(offset) {
  const value = Number(offset);
  if (!Number.isFinite(value) || value === 0) return 0;
  const ratio = Math.min(0.999999, Math.abs(value) / MAX_ELASTIC_OFFSET);
  return Math.sign(value) * -MAX_ELASTIC_OFFSET * Math.log(1 - ratio);
}

function finite(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}
