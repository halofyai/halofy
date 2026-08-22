/**
 * The lineage graph: one hub node with its inbound origins on the left and
 * where it landed on the right, drawn on the dark canvas.
 *
 * Written for the S5 saved-memory drawer ("where did this memory come from,
 * where is it stored"), and reused unchanged by the S6 connection drawer
 * ("what did this source sync, where did it land"). The class names keep the
 * `saved-memory-*` prefix they shipped with: they name ONE component with one
 * block of CSS, and renaming them would churn the stylesheet and the S5
 * contract test without changing a pixel.
 *
 * Callers own their data and their escaping; this module owns the geometry.
 */

/** Node colour by kind — the only hue family the graph uses. */
export function lineageKindColor(kind) {
  return {
    source: "#71b7c8",
    memory: "#a9c18c",
    policy: "#d8b86a",
    agent: "#ae8fd4",
    knowledge: "#dfaa70",
    skill: "#8dadd1",
    actor: "#9ed8b0",
    origin: "#71b7c8",
    tier: "#a9c18c",
  }[String(kind)] || "#a9c18c";
}

/** Truncate a node label to the width the pill can actually show. */
function shortLabel(value, max) {
  const text = String(value ?? "").trim() || "Unavailable";
  return text.length <= max ? text : text.slice(0, max - 1).trimEnd() + "…";
}

/**
 * Place each link on its side and give it a path to (or from) the hub. Both
 * sides are distributed independently, so one left node and three right nodes
 * still read as a balanced fan rather than a cluster.
 */
export function lineageLayout(links) {
  const rows = (count) => {
    if (count <= 1) return [50];
    return Array.from({ length: count }, (_, index) => 16 + (68 * index) / (count - 1));
  };
  const sides = links.map((link) => link.side === "right" ? "right" : "left");
  const left = rows(sides.filter((side) => side === "left").length);
  const right = rows(sides.filter((side) => side === "right").length);
  let leftIndex = 0;
  let rightIndex = 0;
  return links.map((link, index) => {
    const isLeft = sides[index] === "left";
    const x = isLeft ? 17 : 83;
    const y = isLeft ? left[leftIndex++] : right[rightIndex++];
    const path = isLeft
      ? `M${x * 3} ${y * 2} L150 100`
      : `M150 100 L${x * 3} ${y * 2}`;
    return { ...link, x, y, path };
  });
}

/**
 * The dark canvas: edges, the hub pill, and one pill per placed link.
 *
 * `arrowId` must be unique in the document — two graphs sharing a marker id
 * would make the second one's arrowheads reference the first one's defs.
 * `nodeAttrs(link)` returns the extra attributes for an interactive node
 * (already escaped by the caller); an empty string renders a plain span.
 */
export function lineageCanvasHtml({ esc, core, links, arrowId, nodeAttrs, labelMax = 22 }) {
  const nodes = links.map((link) => {
    const attrs = typeof nodeAttrs === "function" ? String(nodeAttrs(link) || "") : "";
    const tag = attrs === "" ? "span" : "button";
    const fallback = attrs === "" ? ` aria-label="${esc(link.label)}"` : "";
    return `<${tag} class="saved-memory-link-node"${attrs}${fallback} style="left:${link.x}%;top:${link.y}%">
      <i style="background:${lineageKindColor(link.kind)}"></i><span>${esc(shortLabel(link.label, labelMax))}</span>
    </${tag}>`;
  }).join("");
  const paths = links.map((link) =>
    `<path d="${link.path}" fill="none" stroke="rgba(199,215,178,0.38)" stroke-width="1" marker-end="url(#${arrowId})" vector-effect="non-scaling-stroke"></path>`,
  ).join("");
  return `<div class="saved-memory-linkage">
        <svg viewBox="0 0 300 200" preserveAspectRatio="none" aria-hidden="true"><defs><marker id="${arrowId}" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="rgba(199,215,178,0.55)"></path></marker></defs>${paths}</svg>
        <span class="saved-memory-link-core">${esc(shortLabel(core, 28))}</span>${nodes}
      </div>`;
}

/** The reading list under the canvas: colour, label, and what the link means. */
export function lineageLegendHtml({ esc, links, nodeAttrs, empty }) {
  if (links.length === 0) {
    return `<p class="saved-memory-link-empty">${esc(empty)}</p>`;
  }
  return links.map((link) => {
    const attrs = typeof nodeAttrs === "function" ? String(nodeAttrs(link) || "") : "";
    const tag = attrs === "" ? "span" : "button";
    return `<${tag} class="saved-memory-link-legend"${attrs}>
        <i style="background:${lineageKindColor(link.kind)}"></i><span>${esc(link.label)}</span><small>${esc(link.role)}</small>
      </${tag}>`;
  }).join("");
}
