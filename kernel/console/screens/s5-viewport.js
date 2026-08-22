// S5 graph viewport: zoom, pan, fit, and full screen.
//
// Every control here is a pure client-side transform over the graph the server
// already returned - nothing refetches, and nothing can widen the view. The
// transform lives on `.memory-graph-canvas` (clusters + edges + nodes) so the
// dotted backdrop and the control stack stay pinned to the viewport.

const MIN_ZOOM = 0.4;
const MAX_ZOOM = 3;
const ZOOM_STEP = 1.25;

const activePans = new Map();
const suppressedPanClicks = new WeakSet();

/** A pan that moved must not also read as "clicked empty space to deselect". */
export function consumeGraphPanClick(viewport) {
  if (!viewport || !suppressedPanClicks.has(viewport)) return false;
  suppressedPanClicks.delete(viewport);
  return true;
}

export function graphViewport(el) {
  if (!el || typeof el.closest !== "function") return null;
  const inside = el.closest(".memory-graph-viewport");
  if (inside) return inside;
  const graph = el.closest(".memory-graph");
  return graph && typeof graph.querySelector === "function"
    ? graph.querySelector(".memory-graph-viewport")
    : null;
}

function canvasOf(viewport) {
  return viewport && typeof viewport.querySelector === "function"
    ? viewport.querySelector("[data-graph-canvas]")
    : null;
}

/** Current transform, read back from the DOM so state survives a re-render. */
export function graphTransform(viewport) {
  const zoom = Number(viewport?.getAttribute?.("data-zoom"));
  const panX = Number(viewport?.getAttribute?.("data-pan-x"));
  const panY = Number(viewport?.getAttribute?.("data-pan-y"));
  return {
    zoom: Number.isFinite(zoom) && zoom > 0 ? zoom : 1,
    panX: Number.isFinite(panX) ? panX : 0,
    panY: Number.isFinite(panY) ? panY : 0,
  };
}

export function clampZoom(value) {
  const zoom = Number(value);
  if (!Number.isFinite(zoom)) return 1;
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round(zoom * 1000) / 1000));
}

function applyTransform(viewport, next) {
  const canvas = canvasOf(viewport);
  const zoom = clampZoom(next.zoom);
  const panX = Math.round(Number(next.panX) || 0);
  const panY = Math.round(Number(next.panY) || 0);
  viewport.setAttribute("data-zoom", String(zoom));
  viewport.setAttribute("data-pan-x", String(panX));
  viewport.setAttribute("data-pan-y", String(panY));
  if (canvas && canvas.style) {
    canvas.style.setProperty("--zoom", String(zoom));
    canvas.style.setProperty("--pan-x", `${panX}px`);
    canvas.style.setProperty("--pan-y", `${panY}px`);
  }
  syncZoomControls(viewport, zoom);
  return { zoom, panX, panY };
}

function syncZoomControls(viewport, zoom) {
  const graph = typeof viewport.closest === "function" ? viewport.closest(".memory-graph") : null;
  const scope = graph && typeof graph.querySelectorAll === "function" ? graph : viewport;
  if (!scope || typeof scope.querySelectorAll !== "function") return;
  scope.querySelectorAll('[data-action="topo-zoom-in"]').forEach(function (button) {
    button.disabled = zoom >= MAX_ZOOM;
  });
  scope.querySelectorAll('[data-action="topo-zoom-out"]').forEach(function (button) {
    button.disabled = zoom <= MIN_ZOOM;
  });
}

/**
 * Zoom around a fixed point of the viewport (the pointer for a wheel gesture,
 * the centre for the buttons) so the graph does not slide out from under the
 * thing the reader was looking at.
 */
export function zoomGraph(viewport, factor, origin) {
  if (!viewport) return null;
  const current = graphTransform(viewport);
  const zoom = clampZoom(current.zoom * factor);
  if (zoom === current.zoom) return current;
  const rect = viewport.getBoundingClientRect?.();
  const width = Number(rect?.width) || 0;
  const height = Number(rect?.height) || 0;
  // Distance from the viewport centre to the anchor, in screen pixels.
  const anchorX = origin && Number.isFinite(origin.x) ? origin.x - width / 2 : 0;
  const anchorY = origin && Number.isFinite(origin.y) ? origin.y - height / 2 : 0;
  const ratio = zoom / current.zoom;
  return applyTransform(viewport, {
    zoom,
    panX: anchorX - (anchorX - current.panX) * ratio,
    panY: anchorY - (anchorY - current.panY) * ratio,
  });
}

export function zoomGraphBy(viewport, direction) {
  return zoomGraph(viewport, direction > 0 ? ZOOM_STEP : 1 / ZOOM_STEP, null);
}

/** Back to the authored layout: the graph is composed to fill its box at 1x. */
export function fitGraph(viewport) {
  if (!viewport) return null;
  return applyTransform(viewport, { zoom: 1, panX: 0, panY: 0 });
}

/** Centre one node in the viewport without changing the zoom level. */
export function centerGraphNode(viewport, nodeId) {
  if (!viewport || typeof viewport.querySelector !== "function") return null;
  const node = viewport.querySelector(`.memory-graph-node[data-node-id="${cssEscape(nodeId)}"]`);
  const canvas = canvasOf(viewport);
  if (!node || !canvas) return null;
  const nodeRect = node.getBoundingClientRect?.();
  const viewRect = viewport.getBoundingClientRect?.();
  if (!nodeRect || !viewRect || !Number.isFinite(nodeRect.width)) return null;
  const current = graphTransform(viewport);
  const dx = viewRect.left + viewRect.width / 2 - (nodeRect.left + nodeRect.width / 2);
  const dy = viewRect.top + viewRect.height / 2 - (nodeRect.top + nodeRect.height / 2);
  return applyTransform(viewport, {
    zoom: current.zoom,
    panX: current.panX + dx,
    panY: current.panY + dy,
  });
}

/** Pointer-driven panning on empty canvas. Node drags own their own pointers. */
export function handleGraphPan(event, viewport) {
  if (!event || !viewport) return false;
  if (event.type === "pointerdown") {
    if (event.isPrimary !== true || event.button !== 0 || !Number.isFinite(event.pointerId)) return false;
    if (activePans.has(event.pointerId)) return false;
    // A press on the control stack must never start a pan. The pan captures the
    // pointer on the viewport, and pointer capture retargets the follow-up
    // click to the capture element - so zoom, fit, and full screen were being
    // swallowed by the viewport's own "click empty space to deselect".
    const origin = event.target;
    if (origin && typeof origin.closest === "function" && origin.closest("button,[data-action]:not(.memory-graph-viewport)")) {
      return false;
    }
    const current = graphTransform(viewport);
    activePans.set(event.pointerId, {
      viewport,
      startX: Number(event.clientX) || 0,
      startY: Number(event.clientY) || 0,
      panX: current.panX,
      panY: current.panY,
      moved: false,
    });
    try {
      viewport.setPointerCapture?.(event.pointerId);
    } catch {
      // Capture is an optimisation; the move handler still works without it.
    }
    return true;
  }
  const pan = activePans.get(event.pointerId);
  if (!pan) return false;
  if (event.type === "pointermove") {
    const dx = (Number(event.clientX) || 0) - pan.startX;
    const dy = (Number(event.clientY) || 0) - pan.startY;
    if (!pan.moved && Math.hypot(dx, dy) < 3) return true;
    pan.moved = true;
    viewport.classList?.add("is-panning");
    applyTransform(viewport, {
      zoom: graphTransform(viewport).zoom,
      panX: pan.panX + dx,
      panY: pan.panY + dy,
    });
    event.preventDefault?.();
    return true;
  }
  activePans.delete(event.pointerId);
  viewport.classList?.remove("is-panning");
  try {
    viewport.releasePointerCapture?.(event.pointerId);
  } catch {
    // Already released by the platform.
  }
  if (pan.moved) suppressedPanClicks.add(viewport);
  return pan.moved;
}

export function cancelGraphPans() {
  for (const [pointerId, pan] of activePans) {
    activePans.delete(pointerId);
    pan.viewport.classList?.remove("is-panning");
  }
}

export function toggleGraphFullscreen(viewport, button) {
  const graph = viewport && typeof viewport.closest === "function" ? viewport.closest(".memory-graph") : null;
  if (!graph || !graph.classList) return false;
  const next = !graph.classList.contains("is-fullscreen");
  graph.classList.toggle("is-fullscreen", next);
  if (button && typeof button.setAttribute === "function") {
    button.setAttribute("aria-pressed", String(next));
    const label = button.getAttribute(next ? "data-collapse-label" : "data-expand-label");
    if (label) {
      button.setAttribute("aria-label", label);
      const tip = button.querySelector?.(".memory-graph-control-tip");
      if (tip) tip.textContent = label;
    }
  }
  fitGraph(viewport);
  return next;
}

/** Attribute-selector-safe id, without depending on CSS.escape in old engines. */
export function cssEscape(value) {
  return String(value == null ? "" : value).replace(/["\\]/g, "\\$&");
}
