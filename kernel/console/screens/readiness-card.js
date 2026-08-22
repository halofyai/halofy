// Memory readiness card (M9-parity decision #8, E43).
//
// A composite 0..100 banded memory-health score with six pillar sub-scores and
// a window-over-window trend. Mounted on S2 (Home) above the stat row - see
// `renderReadinessCard` below; S2 imports it the same way S5 imports
// `s5-topology.js`.
//
// Reads GET /v1/admin/readiness:
//   { namespace, score, band, windowDays, degraded, degradedReasons:[...],
//     computedAt,
//     trend:{ direction, deltaPoints, previousScore, windowDays, basis:[...] },
//     pillars:[{ id,label,score,band,weight,available,detail,metrics{...} }] }
//
// Every interpolated API value passes through ctx.esc() before entering HTML,
// including data-* attributes. No inline JS - the one interaction (drill into
// the screen that fixes a weak pillar) is a delegated `data-action`, and the
// host screen owns the handler (see `readinessActions`).
//
// Defensive by construction: an older server that lacks the route, a payload
// missing `pillars`, or a browned-out pillar (`available:false`) all render -
// the card never throws and never blanks the page it is mounted on.

/** Band → pill kind + a human phrase. Mirrors ReadinessBand in src/readiness. */
const BANDS = {
  excellent: { kind: "ok", label: "Excellent" },
  healthy: { kind: "ok", label: "Healthy" },
  fair: { kind: "warn", label: "Fair" },
  "at-risk": { kind: "crit", label: "At risk" },
};

/** Pillar → the screen that actually fixes it (delegated nav target). */
const PILLAR_TARGET = {
  freshness: "s6",
  coverage: "s6",
  // `retrieval` used to drill into S9 (the scorecard), which is now boxed - see
  // BOXED_SCREENS in app.js. The pillar itself is unaffected: it is hit-vs-miss
  // over the audited lookup ops, not a scorecard reading. A weak score means
  // lookups are coming back empty, and the actionable fix is more/better
  // source coverage, so it drills into Sources alongside freshness/coverage.
  retrieval: "s6",
  gaps: "s5",
  trust: "s11",
  structure: "s5",
};

/** Pillar → the label on its drill-in button. */
const PILLAR_CTA = {
  freshness: "Sources",
  coverage: "Sources",
  retrieval: "Sources",
  gaps: "Memory map",
  trust: "Conflict review",
  structure: "Memory map",
};

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function bandMeta(band) {
  return BANDS[band] ?? { kind: null, label: "Unknown" };
}

/** "+4.2" / "-1.0" / "0.0" - always signed so the direction reads at a glance. */
function signed(n) {
  const v = num(n);
  return (v > 0 ? "+" : "") + v.toFixed(1);
}

function trendTone(direction) {
  return direction === "up" ? "ok" : direction === "down" ? "crit" : null;
}

function trendGlyph(direction) {
  return direction === "up" ? "▲" : direction === "down" ? "▼" : "■";
}

/** Keep operational readiness detail accurate while translating internal terms. */
function plainReadinessDetail(value) {
  return String(value || "")
    .replace(/distinct provenance sources/gi, "sources")
    .replace(/active facts/gi, "saved memories")
    .replace(/facts contested/gi, "saved memories challenged")
    .replace(/cross-source duplication/gi, "duplicate knowledge")
    .replace(/searches or faults/gi, "memory lookups")
    .replace(/reads came back empty, denied or errored/gi, "lookups found no usable memory")
    .replace(/connected sources have synced/gi, "connected sources are up to date")
    .replace(/sources synced/gi, "sources refreshed")
    .replace(/hit rate unproven/gi, "success rate not measured")
    .replace(/asserted/gi, "added")
    .replace(/detected/gi, "found")
    .replace(/\s*\u2014\s*([a-z])/g, function (_match, letter) {
      return ". " + String(letter).toUpperCase();
    })
    .replace(/\s*\u2014\s*/g, ". ");
}

/**
 * One pillar row: a band-colored severity bar, the label + score, the
 * server-written detail sentence, and a delegated drill-in button.
 * @param {import('../app.js').Ctx} ctx
 * @param {Record<string, unknown>} p
 */
function pillarRow(ctx, p) {
  const { esc, ui } = ctx;
  const id = String(p && p.id ? p.id : "");
  const label = String(p && p.label ? p.label : id);
  const available = p && p.available !== false;
  const band = available && p && p.band ? String(p.band) : null;
  const meta = bandMeta(band);
  const score = available && p && p.score !== null && p.score !== undefined
    ? num(p.score).toFixed(1)
    : "-";
  const weightPct = Math.round(num(p && p.weight) * 100);
  const detail = plainReadinessDetail(p && p.detail);

  // Severity bar color comes from the band, not from anything server-written.
  const color =
    band === "excellent" || band === "healthy"
      ? "var(--ok, #2e9e6b)"
      : band === "fair"
        ? "var(--warn, #c98a15)"
        : band === "at-risk"
          ? "var(--crit, #d1493f)"
          : "var(--muted, #8a8f98)";

  const target = PILLAR_TARGET[id];
  const cta =
    target && available
      ? `<button class="btn btn--outline btn--sm" data-action="go"` +
        ` data-screen="${esc(target)}">${esc(PILLAR_CTA[id] ?? "Open")}</button>`
      : "";

  const head =
    `<div style="display:flex;align-items:baseline;gap:.5rem;flex-wrap:wrap">` +
    `<strong>${esc(label)}</strong>` +
    `<span class="num">${esc(score)}</span>` +
    (available ? ui.pill(esc(meta.label), meta.kind) : ui.pill("Unavailable", "warn")) +
    `<span class="sub" style="margin:0">weight ${esc(String(weightPct))}%</span>` +
    `</div>` +
    `<div class="sub" style="margin:0">${esc(detail)}</div>`;

  return ui.sevRow(color, head, cta);
}

/**
 * Render the readiness card. Pass `data` when the host screen already fetched
 * the payload; omit it and the card fetches `/v1/admin/readiness` itself.
 *
 * @param {import('../app.js').Ctx} ctx
 * @param {Record<string, unknown>} [data]
 * @returns {Promise<string>} card html (never throws)
 */
export async function renderReadinessCard(ctx, data) {
  const { esc, ui } = ctx;

  let r = data;
  if (!r) {
    try {
      r = await ctx.api.get("/v1/admin/readiness");
    } catch (err) {
      return ui.empty(
        "Readiness unavailable" +
          (err && err.message ? ": " + esc(err.message) : "."),
      );
    }
  }
  if (!r || typeof r !== "object") {
    return ui.empty("Readiness unavailable.");
  }

  const score = num(r.score);
  const band = r.band ? String(r.band) : "at-risk";
  const meta = bandMeta(band);
  const windowDays = num(r.windowDays) || 30;
  const trend = (r && r.trend) || {};
  const direction = String(trend.direction || "flat");
  const pillars = Array.isArray(r.pillars) ? r.pillars : [];

  const headline =
    `<div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">` +
    ui.stat({
      k: "Readiness",
      v: esc(score.toFixed(1)),
      delta: esc(trendGlyph(direction) + " " + signed(trend.deltaPoints)),
      tone: trendTone(direction),
      foot:
        esc(meta.label) +
        " · vs " +
        esc(num(trend.previousScore).toFixed(1)) +
        " in the prior " +
        esc(String(windowDays)) +
        "d",
    }) +
    `</div>`;

  const rows = pillars.length
    ? pillars.map((p) => pillarRow(ctx, p)).join("")
    : `<div class="sub" style="margin:0">No detail.</div>`;

  // Brownout is stated, not hidden: a partial score is still shown, but the
  // card says which pillars were dropped and why.
  const reasons = Array.isArray(r.degradedReasons) ? r.degradedReasons : [];
  const degradedNote =
    r.degraded === true
      ? `<div class="sub" style="margin:.5rem 0 0">` +
        `Partial score: ${esc(String(reasons.length))} ` +
        `${reasons.length === 1 ? "signal" : "signals"} unavailable; ` +
        `pillars were reweighted. ${esc(reasons.join("; "))}</div>`
      : "";

  // Only the pillars that actually differ across the two compared windows.
  const basis = Array.isArray(trend.basis) ? trend.basis : [];
  const trendNote = basis.length
    ? `<div class="sub" style="margin:.5rem 0 0">Trend: last ` +
      `${esc(String(windowDays))} days, ${esc(basis.join(", "))}.</div>`
    : "";

  return ui.card({
    title: "Memory health",
    body: headline + rows + trendNote + degradedNote,
  });
}

/**
 * Delegated actions this card needs. The card's only interaction is a
 * navigation, and it reuses S2's existing `data-action="go" data-screen="s<N>"`
 * convention verbatim - so mounting it on S2 needs NO actions wiring at all.
 * This export exists only for a host screen that does not already define `go`;
 * such a host spreads it into its own exported `actions` map. The signature is
 * app.js's delegated-action signature, `(ctx, el)`.
 */
export const readinessActions = {
  go(ctx, el) {
    const screen = el.getAttribute("data-screen");
    if (screen) ctx.go(screen);
  },
};
