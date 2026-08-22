/**
 * S19 — Alerts. Everything the platform wants to tell you, in one place.
 *
 * 2026-08 overhaul. The screen used to be the agent gateway's private inbox:
 * two lists, both from /v1/admin/agent-access/*. Every other approval and every
 * other threshold in the product lived on the screen that produced it, so an
 * operator had to already suspect a problem to go find one. An alert that has
 * to be hunted for is not an alert.
 *
 * It is now the whole platform's inbox, split by the only question a non-technical
 * operator actually asks:
 *
 *   ACTION REQUIRED       someone or something is blocked until you choose
 *   FOR YOUR INFORMATION  the system already decided; you should simply see it
 *
 * Ten alert types, eight of them wired (see alert-inbox.js for the two that are
 * deliberately absent rather than faked). The feed is shared with the workspace
 * notification drawer, so the bell and this screen can never disagree.
 *
 * This introduces NO new authority. Every read and every decision is an
 * endpoint that already existed and was already owner/admin gated server-side.
 * Decisions are taken inline only where a one-click yes is genuinely safe —
 * an access request and an app connection. Anything whose decision depends on
 * reading content (which draft, which fact wins) deep-links to the screen that
 * shows that content instead of offering a blind Approve.
 *
 * There is no status filter. An inbox shows OPEN work; a decided row is history
 * and lives on the screen that owns it, which every card deep-links to. The old
 * "Needs attention / Everything" toggle only relaxed a status filter, so both
 * states rendered the identical two lanes — and let already-decided rows fall
 * into "Action Required" with no buttons on them.
 *
 * Design: the Home design system, verbatim. Same `.home-overview` shell, same
 * `.head`, same `metricCard` summary strip, same `.home-panel` cards, same
 * `ui.pill` tones. No new colours, no new type scale.
 *
 * Every API-derived string is escaped before interpolation.
 */

import { metricCard as stat } from "../metric-card.js";
import {
  alertIcon as icon,
  alertVisual,
  clearAlertInboxCache,
  formatAlertAge,
  formatAlertWait,
  loadAlertInbox,
} from "../alert-inbox.js";

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

export async function render(ctx) {
  if (!canMutate(ctx)) {
    return shell(
      head() +
      '<div class="card home-panel"><div class="between home-panel-head"><h3>Alerts are an owner and admin view</h3></div>' +
      '<p class="subtle home-text-sm">Your role can read the full history under Audit.</p></div>',
    );
  }

  const inbox = await loadAlertInbox(ctx);

  return shell(
    head() +
    summary(inbox) +
    '<div class="home-dashboard">' +
    lane(ctx, {
      id: "act",
      title: "Action Required",
      meta: "Each item is blocked until you approve or deny it",
      empty: "No items are awaiting your decision.",
      items: inbox.needsYou,
      groups: inbox.groups.filter((group) => group.lane === "act"),
    }) +
    lane(ctx, {
      id: "info",
      title: "For Your Information",
      meta: "Nothing here waits on a decision from you",
      empty: "Nothing to report.",
      items: inbox.justSoYouKnow,
      groups: inbox.groups.filter((group) => group.lane === "info"),
    }) +
    "</div>",
  );
}

/** Home's page shell, so the canvas, width and rhythm match Home exactly. */
function shell(content) {
  return '<div class="home-overview alert-inbox"><div class="screen-flow">' + content + "</div></div>";
}

function head() {
  return '<div class="head home-head"><div><div class="eyebrow">Govern</div><h1>Alerts</h1></div></div>';
}

/** Three tiles, same component and same grid treatment Home uses. */
function summary(inbox) {
  const waiting = inbox.actionCount;
  const known = inbox.infoCount;
  const missing = inbox.unavailable.length;
  return '<div class="home-metrics" role="list" aria-label="Alert summary">' +
    stat({
      k: "Action Required",
      v: String(waiting),
      foot: waiting === 0
        ? "Nothing is waiting on a person right now."
        : "Each of these is blocked until someone approves or denies it.",
      icon: "review",
    }) +
    stat({
      k: "For Your Information",
      v: String(known),
      // Not "already handled": this lane also carries failures (a source that
      // stopped syncing) that need a fix on their own screen — what they have
      // in common is only that nothing here waits on an approve/deny.
      foot: "Nothing here waits on a decision. Follow a link to act on it.",
      icon: "guardrail",
    }) +
    stat({
      k: "Longest Waiting",
      v: waiting === 0 ? "—" : formatAlertWait(inbox.oldest),
      foot: missing > 0
        ? "We could not check: " + inbox.unavailable.join(", ") + "."
        : "How long the oldest undecided item has been sitting.",
      icon: "latency",
      cap: missing > 0 ? String(missing) + " check" + (missing === 1 ? "" : "s") + " unavailable" : "",
      capTone: missing > 0 ? "warn" : undefined,
    }) +
    "</div>";
}

function lane(ctx, view) {
  const broken = view.groups.filter(function (group) { return !group.available; });
  const body = view.items.length === 0 && broken.length === 0
    ? '<div class="home-card-empty">' + ctx.esc(view.empty) + "</div>"
    : '<div class="alert-list">' +
      broken.map(function (group) { return unavailableRow(ctx, group); }).join("") +
      view.items.map(function (item) { return row(ctx, item); }).join("") +
      "</div>";
  const count = view.items.length;
  return '<section class="card home-panel alert-lane alert-lane--' + view.id +
    '" aria-labelledby="alert-lane-' + view.id + '">' +
    '<div class="between home-panel-head"><h3 id="alert-lane-' + view.id + '">' + ctx.esc(view.title) + "</h3>" +
    '<span class="home-panel-meta">' + ctx.esc(count === 0 ? view.meta : count + " · " + view.meta) + "</span></div>" +
    body + "</section>";
}

/**
 * A read that failed gets its own row. Showing nothing here would fold an
 * unknown into the all-clear the empty state promises.
 */
function unavailableRow(ctx, group) {
  return '<article class="alert-item alert-item--muted">' +
    '<span class="home-overview-row-icon" aria-hidden="true">' + icon("unavailable") + "</span>" +
    '<div class="alert-item-copy"><div class="alert-item-head"><b>' + ctx.esc(group.check) + "</b>" +
    ctx.ui.pill("Unavailable") + "</div>" +
    '<p class="subtle home-text-sm alert-item-body">We could not check this just now, so nothing from it is counted above. Refresh to try again.</p></div>' +
    '<div class="alert-item-acts">' + (group.screen ? goLink(ctx, group.screen, group.screenLabel) : "") + "</div></article>";
}

function row(ctx, item) {
  const acts = item.actions.map(function (action) {
    return '<button class="btn btn--' + (action.variant === "solid" ? "solid" : "outline") +
      ' btn--sm" type="button" data-action="' + ctx.esc(action.action) +
      '" data-id="' + ctx.esc(String(action.id || "")) + '">' + ctx.esc(action.label) + "</button>";
  }).join("");
  const meta = item.meta
    .filter(Boolean)
    .concat(item.when ? [formatAlertAge(item.when)] : [])
    .map(function (value) { return ctx.esc(value); })
    .join(" · ");
  // The row itself stays neutral chrome; the pill is the design language's one
  // status treatment, so severity is never painted onto the container.
  return '<article class="alert-item">' +
    '<span class="home-overview-row-icon" aria-hidden="true">' + alertVisual(item) + "</span>" +
    '<div class="alert-item-copy">' +
    '<div class="alert-item-head"><b>' + ctx.esc(item.title) + "</b>" +
    (item.state ? ctx.ui.pill(ctx.esc(item.state), item.tone) : "") + "</div>" +
    (item.subject ? '<div class="alert-item-subject">' + ctx.esc(item.subject) + "</div>" : "") +
    (item.body ? '<p class="subtle home-text-sm alert-item-body">' + ctx.esc(item.body) + "</p>" : "") +
    (meta ? '<div class="subtle home-text-xs alert-item-meta">' + meta + "</div>" : "") +
    "</div>" +
    '<div class="alert-item-acts">' + acts +
    (item.screen ? goLink(ctx, item.screen, item.screenLabel) : "") + "</div>" +
    '<div class="hint alert-item-status" data-alerts-status role="status" aria-live="polite"></div>' +
    "</article>";
}

function goLink(ctx, screen, label) {
  return '<button class="home-card-link" type="button" data-action="alerts-go" data-screen="' +
    ctx.esc(screen) + '"><span>' + ctx.esc(label || "Open") + '</span>' +
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 18 6-6-6-6"></path></svg></button>';
}

// ---------------------------------------------------------------------------
// Decisions. Every path here already existed and is owner/admin gated on the
// server; the inbox only stops making people go looking for it.
// ---------------------------------------------------------------------------

export const actions = {
  "alerts-go"(ctx, el) {
    const screen = el.getAttribute("data-screen");
    if (screen) ctx.go(screen);
  },

  async "alerts-approve"(ctx, el) {
    await decide(ctx, el, (id) => "/v1/admin/agent-access/requests/" + id + "/approve", {}, "Approve");
  },
  async "alerts-deny"(ctx, el) {
    await decide(ctx, el, (id) => "/v1/admin/agent-access/requests/" + id + "/deny", {}, "Deny");
  },
  async "alerts-acknowledge"(ctx, el) {
    await decide(ctx, el, (id) => "/v1/admin/agent-access/alerts/" + id + "/acknowledge", {}, "Got it");
  },
  async "alerts-app-approve"(ctx, el) {
    await decide(ctx, el, (id) => "/v1/admin/oauth/clients/" + id + "/approve", {}, "Approve");
  },
  async "alerts-app-deny"(ctx, el) {
    await decide(
      ctx,
      el,
      (id) => "/v1/admin/oauth/clients/" + id + "/revoke",
      { reason: "Denied from Alerts" },
      "Deny",
    );
  },
};

async function decide(ctx, el, path, body, label) {
  const id = el.getAttribute("data-id");
  if (!id) return;
  const card = el.closest ? el.closest(".alert-item") : null;
  const status = card && card.querySelector ? card.querySelector("[data-alerts-status]") : null;
  setBusy(el, true, "Working…");
  try {
    await ctx.api.post(path(encodeURIComponent(id)), body);
    // The decision just invalidated the feed both surfaces read from; a repaint
    // from cache would show the item still waiting.
    clearAlertInboxCache();
    await repaint(ctx);
    await ctx.refreshNotifications?.();
  } catch (err) {
    setText(status, "That did not go through: " + (err && err.message ? err.message : "unknown error"));
    setBusy(el, false, label);
  }
}

/** Same-screen actions refresh in place, never through the route loader. */
async function repaint(ctx) {
  if (typeof ctx.refresh === "function") await ctx.refresh();
  else await ctx.go("s19");
}

function setBusy(el, busy, label) {
  if (!el) return;
  el.disabled = busy;
  if (label && "textContent" in el) el.textContent = label;
}

function setText(node, text) {
  if (node) node.textContent = text;
}
