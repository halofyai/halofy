// Standing setup checklist (M9 decision #5, E42; restyled as the mandatory
// setup gate's guided stepper — CONTRACTS-SETUP-GATE.md).
//
// A partial, not a nav destination: `card(ctx)` renders the guided stepper —
// which on S1 IS the whole screen, header included — and `badge(ctx)` renders
// the persistent "N steps remaining" sidebar chip. `render(ctx)` exists so the
// checklist can also be opened on its own.
//
// The count is NEVER computed here. It comes from
// GET /v1/admin/setup-checklist, which derives it server-side for the caller's
// own namespace (D9) - the client cannot pass a namespace and cannot dismiss a
// step. There is no skip control anywhere in this UI: the console unlocks
// only when the server derives `complete`.

import { screenTargetHash } from "../routes.js";

/** Where a stuck operator goes — the same support link as the rail footer. */
const BOOKING_URL = "https://github.com/halofyai/halofy/discussions";

/** Rough per-step time expectations (minutes), shown so setup feels finite. */
const STEP_ETA = {
  "team-space": 1,
  source: 3,
  memory: 2,
  team: 2,
  badge: 1,
};

/** Fetch the server-derived checklist. Returns null on brownout. */
export async function load(ctx) {
  try {
    const view = await (
      ctx.initialSetupChecklist ?? ctx.api.get("/v1/admin/setup-checklist")
    );
    return view && Array.isArray(view.steps) ? view : null;
  } catch {
    return null;
  }
}

/**
 * Persistent sidebar chip. Empty string when setup is genuinely complete -
 * that is the only condition under which the badge disappears.
 * @param {{ remaining: number, complete: boolean } | null} view
 */
export function badge(ctx, view) {
  if (!view || view.complete) return "";
  const n = Number(view.remaining) || 0;
  if (n <= 0) return "";
  // The visible chip stays compact ("3 left") so it fits the rail row; the
  // full phrase lives in the tooltip and for assistive tech.
  const full = n === 1 ? "1 step left" : n + " steps left";
  return (
    '<span class="pill pill--warn setup-badge" data-setup-badge title="' +
    ctx.esc("Setup is incomplete - " + full) + '" aria-label="' + ctx.esc(full) + '">' +
    '<i class="dot"></i><span aria-hidden="true">' + ctx.esc(n + " left") + "</span></span>"
  );
}

/**
 * The guided setup stepper. Always expanded - on S1 this IS the screen body; the
 * page title bar is the shared `.head` S1 renders above it, so this header
 * carries only the organization line and the progress meter.
 * The first outstanding required step is spotlighted with the primary CTA;
 * completed steps quiet down to a checked row with no action left on them.
 */
export function card(ctx, view) {
  const { esc } = ctx;
  if (!view) {
    return (
      '<section class="setup-stepper">' +
      header(ctx, null) +
      '<div class="card setup-stepper__unavailable">' +
      '<div class="sub">Setup status is unavailable right now - the console unlocks as soon as the checks can run again.</div>' +
      "</div></section>"
    );
  }

  if (view.complete) return celebration(ctx, view);

  const nextId = nextStepId(view);

  const degraded = view.degraded
    ? '<div class="setup-stepper__degraded" role="status">Some checks could not run - they are counted as not done rather than skipped.</div>'
    : "";

  const steps = (view.steps || [])
    .map((step, index) => row(ctx, step, index, step.id === nextId))
    .join("");

  return (
    '<section class="setup-stepper">' +
    header(ctx, view) +
    degraded +
    '<ol class="setup-stepper__steps">' + steps + "</ol>" +
    '<div class="setup-stepper__foot">Steps check themselves off as signals arrive. Stuck? ' +
    '<a class="setup-stepper__book" href="' + esc(BOOKING_URL) + '" target="_blank" rel="noopener noreferrer">Book a call' +
    '<span class="sr-only"> (opens in a new tab)</span></a> and we\'ll set it up with you.</div>' +
    "</section>"
  );
}

/**
 * Stepper header: which organization this applies to, and how much is left —
 * the progress meter is part of the header, not a corner widget.
 */
function header(ctx, view) {
  const { esc } = ctx;
  const completed = Number(view && view.completed) || 0;
  const total = Number(view && view.total) || 0;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

  const org = view && view.organization
    ? '<div class="setup-stepper__org">Organization · ' + esc(String(view.organization)) + "</div>"
    : "";

  const progress = view
    ? '<div class="setup-stepper__progress"' +
      (view.derivedAt ? ' title="Derived live at ' + esc(String(view.derivedAt)) + '"' : "") +
      ">" +
      '<b class="num">' + esc(String(completed)) + "</b> of " +
      '<span class="num">' + esc(String(total)) + "</span> done" +
      minutesLeft(ctx, view) +
      "</div>" +
      '<div class="setup-stepper__bar" role="progressbar" aria-valuemin="0" aria-valuemax="' +
      esc(String(total)) + '" aria-valuenow="' + esc(String(completed)) +
      '" aria-label="Setup progress"><span style="width:' + esc(String(pct)) + '%"></span></div>'
    : '<div class="setup-stepper__progress">Checking your organization…</div>';

  // No heading here: S1 renders the shared `.head` title bar above this card,
  // in the same position every other tab puts it.
  return (
    '<header class="setup-stepper__head">' +
    org +
    progress +
    "</header>"
  );
}

/** " · about 5 minutes left", summed from the ETAs of what is actually left. */
function minutesLeft(ctx, view) {
  const steps = Array.isArray(view.steps) ? view.steps : [];
  const mins = steps.reduce((sum, s) => {
    if (s.optional || s.state === "complete") return sum;
    return sum + (STEP_ETA[s.id] || 0);
  }, 0);
  if (mins <= 0) return "";
  const unit = mins === 1 ? "minute" : "minutes";
  return " · about " + ctx.esc(String(mins)) + " " + unit + " left";
}

/** The first required step that is not complete — the "up next" spotlight. */
function nextStepId(view) {
  const steps = Array.isArray(view.steps) ? view.steps : [];
  const next = steps.find((s) => !s.optional && s.state !== "complete");
  return next ? next.id : null;
}

function row(ctx, step, index, isNext) {
  const { esc } = ctx;
  const done = step.state === "complete";
  const screen = typeof step.screen === "string" ? step.screen : "";
  const screenHash = screenTargetHash(screen);
  const linkable = screenHash && !done;

  const cls = done
    ? "setup-step is-done"
    : isNext
      ? "setup-step is-next"
      : step.state === "unknown"
        ? "setup-step is-unknown"
        : "setup-step is-pending";

  const marker = done
    ? '<span class="setup-step__marker" aria-hidden="true">✓</span>'
    : '<span class="setup-step__marker" aria-hidden="true">' + esc(String(index + 1)) + "</span>";

  // State is carried by the marker and the title weight, not by a pill on
  // every row. Only the two facts a row cannot show visually stay as text:
  // that a step is optional, and (while it is open) what the server saw.
  const optional = step.optional
    ? '<span class="setup-step__optional">Optional</span>'
    : "";

  const eta = !done && STEP_ETA[step.id]
    ? '<span class="setup-step__eta">' + esc(String(STEP_ETA[step.id])) + " min</span>"
    : "";

  const action = linkable
    ? isNext
      ? '<a class="btn btn--solid btn--sm setup-step__go" href="' + esc(screenHash) + '">Start</a>'
      : '<a class="btn btn--outline btn--sm setup-step__go" href="' + esc(screenHash) + '">Open</a>'
    : "";

  const evidence = !done && step.evidence
    ? '<div class="setup-step__evidence">' + esc(String(step.evidence)) + "</div>"
    : "";

  return (
    '<li class="' + cls + '" data-step="' + esc(String(step.id)) + '"' +
    (isNext ? ' aria-current="step"' : "") + ">" +
    marker +
    '<div class="setup-step__body">' +
    '<div class="setup-step__titleline">' +
    '<span class="setup-step__title">' + esc(String(step.title)) + "</span>" +
    optional +
    "</div>" +
    '<div class="setup-step__detail">' + esc(String(step.detail)) + "</div>" +
    evidence +
    "</div>" +
    eta +
    action +
    "</li>"
  );
}

/**
 * Completion state: the gate has lifted (the server latched the flag on the
 * same derivation), so point at the now-unlocked console.
 */
function celebration(ctx, view) {
  const { esc } = ctx;
  return (
    '<section class="setup-stepper setup-stepper--complete">' +
    '<div class="card setup-celebration" role="status">' +
    '<span class="setup-celebration__burst" aria-hidden="true">' +
    '<i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i>' +
    "</span>" +
    '<span class="setup-celebration__check" aria-hidden="true">✓</span>' +
    "<h3>You're all set</h3>" +
    '<div class="sub">All ' + esc(String(view.total)) +
    " setup steps are complete - the whole console is unlocked.</div>" +
    '<div class="row" style="justify-content:center;margin-top:var(--s4)">' +
    '<a class="btn btn--solid" href="#home">Enter your console</a>' +
    "</div>" +
    '<div class="setup-stepper__foot">Verified live from your organization at ' +
    esc(String(view.derivedAt || "")) +
    ". If a step regresses later it re-opens here - no need to repeat setup.</div>" +
    "</div></section>"
  );
}

/** Standalone screen form, for when the checklist is opened directly. */
export async function render(ctx) {
  return card(ctx, await load(ctx));
}
