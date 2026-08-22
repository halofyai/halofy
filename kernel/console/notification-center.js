import {
  alertVisual,
  formatAlertWait,
  formatAlertWhen,
  loadAlertInbox,
} from "./alert-inbox.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "./right-panel.js";

// ---------------------------------------------------------------------------
// Clearing
//
// Nothing in this inbox is stored server-side — every row is derived from a live
// feed — so "clear" is a per-browser mute, held in localStorage.
//
// It applies to the "For Your Information" lane ONLY. The other lane is pending
// decisions (an agent asking for access, an app asking to connect, a draft
// awaiting review); muting those would let one click hide an approval nobody
// ever sees again. Those rows leave the inbox by being decided, not by being
// dismissed.
// ---------------------------------------------------------------------------

const CLEARED_KEY = "halomem:notifications-cleared";

/**
 * Tone is part of the identity, not just the id: `spend:month` keeps its id when
 * an 85% warning becomes a 100% breach, and a cleared warning must not swallow
 * the breach.
 */
export function notificationFingerprint(item) {
  return String(item.id || "") + "|" + String(item.tone || "");
}

function store() {
  try {
    const value = globalThis.localStorage;
    return value && typeof value.getItem === "function" ? value : null;
  } catch {
    // Access itself throws when storage is blocked by policy.
    return null;
  }
}

export function readClearedNotifications() {
  const storage = store();
  if (!storage) return new Set();
  try {
    const raw = JSON.parse(storage.getItem(CLEARED_KEY) || "[]");
    return new Set(Array.isArray(raw) ? raw.map(String) : []);
  } catch {
    return new Set();
  }
}

function writeClearedNotifications(keys) {
  const storage = store();
  if (!storage) return;
  try {
    storage.setItem(CLEARED_KEY, JSON.stringify([...keys]));
  } catch {
    // Quota or a read-only store. Clearing is a convenience, never a blocker.
  }
}

/** Mute every informational row currently on screen. Returns the new mute set. */
export function clearInformationalNotifications(inbox) {
  const keys = new Set(inbox.justSoYouKnow.map(notificationFingerprint));
  writeClearedNotifications(keys);
  return keys;
}

/**
 * Drop mutes for rows that are no longer being reported, so a connection that
 * fails, recovers, and fails again alerts the second time.
 *
 * Skipped while any feed is Unavailable: an incomplete read is not evidence that
 * a row went away, and discarding the mute on that basis would make a cleared
 * alert flap back every time a feed hiccups.
 */
export function pruneClearedNotifications(inbox) {
  const keys = readClearedNotifications();
  if (keys.size === 0 || !inbox.available) return keys;
  const live = new Set(inbox.justSoYouKnow.map(notificationFingerprint));
  const kept = new Set([...keys].filter((key) => live.has(key)));
  if (kept.size !== keys.size) writeClearedNotifications(kept);
  return kept;
}

/** What the drawer and the bell both count — the inbox minus what's muted. */
export function visibleNotifications(inbox, cleared = readClearedNotifications()) {
  const justSoYouKnow = inbox.justSoYouKnow.filter(
    (item) => !cleared.has(notificationFingerprint(item)),
  );
  return {
    needsYou: inbox.needsYou,
    justSoYouKnow,
    total: inbox.needsYou.length + justSoYouKnow.length,
  };
}

/**
 * The drawer is Home's Overview card, scaled down — not a bespoke list.
 *
 * It reuses Home's own primitives verbatim: the `.home-overview` token scope,
 * `.home-panel` cards with `.home-panel-head`, and `.home-overview-row` items
 * with the neutral 30px icon chip. Only two things are added, both scoped: a
 * button reset (Home's rows are divs; these navigate) and tighter padding for a
 * 380px panel.
 *
 * Content stays a glance — title, one supporting line, relative time. Detail and
 * buttons live on S19, which every row opens.
 */
export function notificationPanelHtml(ctx, inbox, cleared = readClearedNotifications()) {
  const view = visibleNotifications(inbox, cleared);
  const unavailable = inbox.available
    ? ""
    : '<div class="notification-center__unavailable" role="status">Some notifications are unavailable. Refresh or open Alerts to try again.</div>';
  const groups = [
    { title: "Action Required", items: view.needsYou, clearable: false },
    { title: "For Your Information", items: view.justSoYouKnow, clearable: true },
  ].filter((group) => group.items.length > 0);
  const body = groups.length > 0
    ? groups.map((group) => panel(ctx, group)).join("")
    : inbox.available
      ? '<section class="card home-panel"><div class="home-card-empty">No notifications need attention.</div></section>'
      : "";
  return `${unavailable}<div class="home-overview notification-center__scope">${body}</div>`;
}

function panel(ctx, group) {
  // Scoped to the card it sits in, so the label can never read as a promise to
  // clear the decisions in the lane above.
  const clear = group.clearable
    ? `<button type="button" class="notification-center__clear" data-notification-clear aria-label="Clear all ${ctx.esc(group.title)} notifications">Clear all</button>`
    : "";
  return `<section class="card home-panel">
    <div class="between home-panel-head"><h3>${ctx.esc(group.title)}</h3><span class="home-panel-head-actions"><span class="home-panel-meta">${group.items.length}</span>${clear}</span></div>
    <div class="home-overview-list">${group.items.map((item) => row(ctx, item)).join("")}</div>
  </section>`;
}

function row(ctx, item) {
  // One supporting line, in order of how specific it is.
  const line = item.subject || item.body || item.meta.filter(Boolean).join(" · ");
  return `<button type="button" class="home-overview-row" data-notification-view-alerts>
    <span class="home-overview-row-icon" aria-hidden="true">${alertVisual(item)}</span>
    <span class="notification-center__copy">
      <strong>${ctx.esc(item.title)}</strong>
      ${line ? `<span class="subtle home-text-xs">${ctx.esc(line)}</span>` : ""}
    </span>
    <span class="subtle home-text-xs"${item.when ? ` title="${ctx.esc(formatAlertWhen(item.when))}"` : ""}>${ctx.esc(item.when ? formatAlertWait(item.when) : "")}</span>
  </button>`;
}

export function createNotificationCenter({
  ctx,
  root,
  trigger,
  canOpen,
  onOpenAlerts,
  initialRefresh = true,
  doc = globalThis.document,
}) {
  if (!ctx || !root || !trigger || !doc) return null;
  root.innerHTML = rightPanelHtml({
    id: "workspace-notification-panel",
    eyebrow: "Alerts",
    title: "Notifications",
    closeAction: "notification-close",
    className: "notification-center__dialog",
    navigationIcon: false,
    body: '<div class="notification-center__loading" role="status">Loading notifications…</div>',
  });
  const panel = root.querySelector("#workspace-notification-panel");
  const body = panel && panel.querySelector(".console-right-panel__body");
  const count = trigger.querySelector("[data-notification-count]");
  let refreshOwner = 0;
  let refreshPromise = null;
  let lastInbox = null;

  function paintTrigger(inbox, cleared) {
    if (!count) return;
    if (!inbox.available) {
      count.textContent = "!";
      count.hidden = false;
      trigger.setAttribute("aria-label", "Notifications unavailable");
      return;
    }
    // The badge counts what the drawer shows. A cleared row that still ticked
    // the bell would make clearing look broken.
    const total = visibleNotifications(inbox, cleared).total;
    count.textContent = String(total);
    count.hidden = total === 0;
    trigger.setAttribute(
      "aria-label",
      total === 0
        ? "Open notifications"
        : `Open notifications: ${total} need attention`,
    );
  }

  function paint(inbox, cleared) {
    paintTrigger(inbox, cleared);
    if (body) body.innerHTML = notificationPanelHtml(ctx, inbox, cleared);
  }

  async function refresh(options = {}) {
    if (refreshPromise && options.force !== true) return refreshPromise;
    const owner = ++refreshOwner;
    const pending = loadAlertInbox(ctx).then((inbox) => {
      if (owner !== refreshOwner) return inbox;
      lastInbox = inbox;
      paint(inbox, pruneClearedNotifications(inbox));
      return inbox;
    });
    refreshPromise = pending;
    try {
      return await pending;
    } finally {
      if (refreshPromise === pending) refreshPromise = null;
    }
  }

  async function open() {
    if (!canOpen()) return;
    openRightPanel(panel, trigger, doc);
    if (body) body.innerHTML = '<div class="notification-center__loading" role="status">Loading notifications…</div>';
    await refresh();
  }

  trigger.addEventListener("click", () => {
    if (panel && !panel.hidden) closeRightPanel(doc);
    else void open();
  });
  root.addEventListener("click", (event) => {
    if (event.target.closest('[data-action="notification-close"]')) {
      closeRightPanel(doc);
      return;
    }
    if (event.target.closest("[data-notification-clear]")) {
      // Local mute only — repaint from the inbox already in hand rather than
      // refetching nine feeds to render a list we just filtered ourselves.
      if (lastInbox) paint(lastInbox, clearInformationalNotifications(lastInbox));
      return;
    }
    if (event.target.closest("[data-notification-view-alerts]")) {
      closeRightPanel(doc);
      onOpenAlerts();
    }
  });

  const controller = {
    refresh,
    syncAccess(options = {}) {
      const enabled = canOpen();
      trigger.hidden = !enabled;
      if (!enabled) {
        closeRightPanel(doc);
        return;
      }
      if (options.refresh !== false) void refresh();
    },
  };
  controller.syncAccess({ refresh: initialRefresh });
  return controller;
}
