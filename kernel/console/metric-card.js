/**
 * Shared metric card: icon chip + label + info tooltip + a nested value shell.
 *
 * The composition came from the supplied Halomem Home prototype and shipped
 * first on S2 (Home). S15's usage bands are the same card, so the markup and
 * the glyph registry live here rather than being forked into both screens.
 * Styling is `.metric-card*` in app.css; the base rules there are the
 * token-driven console treatment and the later block is the prototype's.
 *
 * This is deliberately NOT `ui.stat` in app.js. That primitive is the plain
 * label+value tile the rest of the console uses, and 22 of its 25 call sites
 * are S15's own; folding the icon and the shell into it would have made every
 * caller carry a composition only two screens want.
 *
 * Callers pass already-escaped strings, matching the console UI helper
 * contract: `v`, `foot` and `cap` are interpolated verbatim.
 */

/** Metric context stays available to pointer and keyboard users without persistent subtext. */
export function metricInfo(label, detail) {
  if (!detail) return "";
  return (
    '<span class="metric-info metric-card-info" role="note" tabindex="0" aria-label="' +
    label +
    ": " +
    detail +
    '" data-tip="' +
    detail +
    '"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span>'
  );
}

/**
 * Compact, monochrome metric glyphs keep a summary strip scannable.
 *
 * The first five are Home's. The rest are S15's usage bands, lifted from the
 * prototype's `uaBands[].cards[].icon` — `spend` already carried the
 * prototype's Memory Cost path verbatim, so it is shared rather than
 * duplicated under a second name.
 */
const METRIC_ICON_PATHS = {
  // Home
  spend: '<path d="M12 3v18M16 7.5c0-1.4-1.8-2.5-4-2.5S8 6.1 8 7.5 9.8 10 12 10s4 1.1 4 2.5S14.2 15 12 15s-4-1.1-4-2.5"/>',
  people: '<path d="M16 20v-1.5a4.5 4.5 0 0 0-9 0V20M11.5 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM18 8a3 3 0 0 1 0 6"/>',
  memory: '<path d="M5 4.5A2.5 2.5 0 0 1 7.5 2H19v17H7.5A2.5 2.5 0 0 0 5 21.5v-17Zm0 0V21M9 7h6M9 11h5"/>',
  source: '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
  query: '<path d="M4 17V9M9 17V5M14 17v-4M19 17V7M3 21h18"/>',
  // S15 usage bands
  reads: '<path d="M12 4v10m0 0 4-4m-4 4-4-4M4 17v1.5A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5V17"/>',
  writes: '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  tokensIn: '<path d="M3 12h13m0 0-4-4m4 4-4 4M21 4v16"/>',
  tokensOut: '<path d="M21 12H8m0 0 4-4m-4 4 4 4M3 4v16"/>',
  agent: '<path d="M9 4h6M12 2v2M5 11a7 7 0 0 1 14 0v7H5v-7ZM9 14h.01M15 14h.01"/>',
  bill: '<path d="M2 8h20M2 6h20v12H2zM6 15h4"/>',
  latency: '<path d="M12 6v6l4 2M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18Z"/>',
  denied: '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3ZM9.5 9.5l5 5m0-5-5 5"/>',
  // S4 policies. Verbatim from the prototype's `poStats[].icon` paths.
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5"/>',
  guardrail: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4"/>',
  review: '<path d="M12 9v4M12 16.5h.01M12 3a9 9 0 1 0 .01 0"/>',
  bypass: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0ZM12 9v4M12 17h.01"/>',
};

export function metricIcon(name) {
  return (
    '<span class="metric-card-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    (METRIC_ICON_PATHS[name] || METRIC_ICON_PATHS.query) +
    "</svg></span>"
  );
}

/**
 * One metric card.
 *
 * `foot` goes into the info tooltip. `cap` is the optional caption painted
 * inside the shell under the value — Home deliberately leaves it unset and
 * keeps all its context in the tooltip, so passing nothing reproduces Home's
 * markup exactly. `capTone: "warn"` tints the caption for a figure that needs
 * attention (a refusal, an unpriced turn) and `"crit"` for one that is already
 * a failure (a guardrail bypass); neither changes the value.
 */
export function metricCard({ k, v, foot, cap, capTone, icon } = {}) {
  const caption = cap
    ? '<div class="metric-card-cap' +
      (capTone === "warn" ? " metric-card-cap--warn" : "") +
      (capTone === "crit" ? " metric-card-cap--crit" : "") +
      '">' +
      cap +
      "</div>"
    : "";
  return (
    '<div class="stat stat--secondary metric-card metric-card--' +
    (icon || "query") +
    '" role="listitem">' +
    '<div class="metric-card-head">' +
    metricIcon(icon) +
    '<div class="metric-card-label"><div class="k">' +
    (k ?? "") +
    "</div></div>" +
    metricInfo(k, foot) +
    "</div>" +
    '<div class="metric-card-shell"><div class="v num">' +
    (v ?? "") +
    "</div>" +
    caption +
    "</div>" +
    "</div>"
  );
}
