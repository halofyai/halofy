import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { clearAlertInboxCache, loadAlertInbox } from "../console/alert-inbox.js";
import {
  clearInformationalNotifications,
  createNotificationCenter,
  notificationFingerprint,
  notificationPanelHtml,
  pruneClearedNotifications,
  readClearedNotifications,
  visibleNotifications,
} from "../console/notification-center.js";

// The 2026-08 overhaul made S19 the whole platform's inbox rather than the agent
// gateway's private one, so this drawer reads the same nine feeds the screen
// does. The contract these tests pin is the one that matters: the bell and the
// screen share ONE read model, and a refused feed shows as Unavailable rather
// than being folded into an all-clear.
const REQUESTS_PATH = "/v1/admin/agent-access/requests?limit=100&status=pending";
const CLIENTS_PATH = "/v1/admin/oauth/clients";
const CONFLICTS_PATH = "/v1/admin/conflicts";
const PROPOSALS_PATH = "/v1/admin/proposals";
const ALERTS_PATH = "/v1/admin/agent-access/alerts?limit=100&status=open";
const OVERVIEW_PATH = "/v1/admin/overview";
const SOURCES_PATH = "/v1/admin/sources";
const AUDIT_PATH = "/v1/admin/audit?limit=50";
const KEYS_PATH = "/v1/admin/keys";

const ALL_PATHS = [
  REQUESTS_PATH,
  CLIENTS_PATH,
  CONFLICTS_PATH,
  PROPOSALS_PATH,
  ALERTS_PATH,
  OVERVIEW_PATH,
  SOURCES_PATH,
  AUDIT_PATH,
  KEYS_PATH,
];

function fixtures(): Record<string, unknown> {
  return {
    [REQUESTS_PATH]: [{
      id: "request-1",
      keyId: "key-1",
      sourceRef: "postgres/orders",
      purpose: "Review failed payments",
      justification: "A customer disputed a charge.",
      requestedFields: ["customers.email"],
      requestedRows: 200,
      requestedDurationSeconds: 3600,
      status: "pending",
      createdAt: "2026-08-06T08:02:00.000Z",
    }],
    [CLIENTS_PATH]: [
      { id: "client-1", name: "Claude Desktop", status: "pending", createdAt: "2026-08-06T08:01:00.000Z" },
      { id: "client-2", name: "Already in", status: "approved", createdAt: "2026-08-01T08:00:00.000Z" },
    ],
    [CONFLICTS_PATH]: { disputes: [], findings: [] },
    [PROPOSALS_PATH]: [],
    [ALERTS_PATH]: [{
      id: "alert-1",
      keyId: "key-1",
      kind: "outside-scope",
      severity: "critical",
      detail: "Tried to read billing.card_number.",
      status: "open",
      createdAt: "2026-08-06T08:00:00.000Z",
    }],
    [OVERVIEW_PATH]: { spend: { effectiveCapUsd: 100, monthToDateUsd: 92 } },
    [SOURCES_PATH]: [],
    [AUDIT_PATH]: [],
    [KEYS_PATH]: [{ id: "key-1", actor: "billing-agent" }],
  };
}

function api(routes: Record<string, unknown>, calls?: string[]) {
  return {
    api: {
      get: async (path: string) => {
        calls?.push(path);
        if (!(path in routes)) throw new Error("missing route");
        return routes[path];
      },
    },
  };
}

describe("shared notification center", () => {
  it("loads every platform alert feed the Alerts screen loads", async () => {
    const calls: string[] = [];
    const inbox = await loadAlertInbox(api(fixtures(), calls));

    expect(calls.sort()).toEqual(ALL_PATHS.slice().sort());
    // One access request + one pending app = decisions; one gateway alert +
    // one spend threshold = information. The approved app is not a decision.
    expect(inbox.needsYou).toHaveLength(2);
    expect(inbox.justSoYouKnow).toHaveLength(2);
    expect(inbox.total).toBe(4);
    expect(inbox.actionCount).toBe(2);
    expect(inbox.names.get("key-1")).toBe("billing-agent");
    expect(inbox.available).toBe(true);
    // Back-compat surface the gateway decisions still read.
    expect(inbox.pending).toHaveLength(1);
    expect(inbox.open).toHaveLength(1);
  });

  it("can defer initial hydration and shares an immediate follow-up refresh", async () => {
    const calls: string[] = [];
    const body = { innerHTML: "" };
    const panel = {
      hidden: true,
      setAttribute() {},
      querySelector: (selector: string) =>
        selector === ".console-right-panel__body" ? body : null,
    };
    const root = {
      innerHTML: "",
      querySelector: (selector: string) =>
        selector === "#workspace-notification-panel" ? panel : null,
      addEventListener() {},
    };
    const count = { textContent: "", hidden: true };
    const trigger = {
      hidden: true,
      querySelector: (selector: string) =>
        selector === "[data-notification-count]" ? count : null,
      addEventListener() {},
      setAttribute() {},
    };
    const doc = {
      body: { classList: { add() {}, remove() {} } },
      addEventListener() {},
      removeEventListener() {},
      querySelector() { return null; },
    };
    const ctx = { ...api(fixtures(), calls), esc: escapeHtml };
    const controller = createNotificationCenter({
      ctx,
      root,
      trigger,
      canOpen: () => true,
      onOpenAlerts() {},
      initialRefresh: false,
      doc,
    });

    expect(controller).not.toBeNull();
    expect(trigger.hidden).toBe(false);
    expect(calls).toEqual([]);

    controller!.syncAccess();
    await controller!.refresh();
    expect(calls.slice().sort()).toEqual(ALL_PATHS.slice().sort());
  });

  it("keeps a forced post-decision refresh newer than an older in-flight inbox", async () => {
    let releaseOld!: () => void;
    const oldGate = new Promise<void>((resolve) => {
      releaseOld = resolve;
    });
    const oldRoutes = fixtures();
    const freshRoutes = fixtures();
    freshRoutes[REQUESTS_PATH] = [];
    freshRoutes[CLIENTS_PATH] = [];
    freshRoutes[CONFLICTS_PATH] = { disputes: [], findings: [] };
    freshRoutes[PROPOSALS_PATH] = [];
    freshRoutes[ALERTS_PATH] = [];
    freshRoutes[OVERVIEW_PATH] = { spend: { effectiveCapUsd: 100, monthToDateUsd: 0 } };

    let phase: "old" | "fresh" = "old";
    const ctx = {
      esc: escapeHtml,
      api: {
        get: async (path: string) => {
          const requestPhase = phase;
          if (requestPhase === "old") await oldGate;
          return (requestPhase === "old" ? oldRoutes : freshRoutes)[path];
        },
      },
    };
    const body = { innerHTML: "" };
    const panel = {
      hidden: true,
      setAttribute() {},
      querySelector: (selector: string) =>
        selector === ".console-right-panel__body" ? body : null,
    };
    const root = {
      innerHTML: "",
      querySelector: (selector: string) =>
        selector === "#workspace-notification-panel" ? panel : null,
      addEventListener() {},
    };
    const count = { textContent: "", hidden: true };
    const trigger = {
      hidden: true,
      querySelector: (selector: string) =>
        selector === "[data-notification-count]" ? count : null,
      addEventListener() {},
      setAttribute() {},
    };
    const doc = {
      body: { classList: { add() {}, remove() {} } },
      addEventListener() {},
      removeEventListener() {},
      querySelector() { return null; },
    };
    clearAlertInboxCache();
    const controller = createNotificationCenter({
      ctx,
      root,
      trigger,
      canOpen: () => true,
      onOpenAlerts() {},
      initialRefresh: false,
      doc,
    });

    const oldRefresh = controller!.refresh();
    await Promise.resolve();
    phase = "fresh";
    clearAlertInboxCache();
    const freshRefresh = controller!.refresh({ force: true });
    await freshRefresh;
    expect(count.hidden).toBe(true);

    releaseOld();
    await oldRefresh;
    expect(count.hidden).toBe(true);
    await expect(loadAlertInbox(ctx)).resolves.toMatchObject({ total: 0 });
  });

  it("renders both lanes as escaped notifications", async () => {
    const routes = fixtures();
    (routes[ALERTS_PATH] as Array<Record<string, unknown>>)[0]!.detail =
      '<img src=x onerror="alert(1)">';
    const inbox = await loadAlertInbox(api(routes));
    const html = notificationPanelHtml({ esc: escapeHtml }, inbox);

    expect(html).toContain("billing-agent is asking for access");
    expect(html).toContain("postgres/orders");
    expect(html).toContain("Claude Desktop wants to connect");
    expect(html).toContain("billing-agent tried to reach data outside its access");
    expect(html).toContain("nearing your monthly spend limit");
    // Home's own card + row primitives, not a bespoke notification list.
    expect(html).toContain('class="home-overview notification-center__scope"');
    expect(html).toContain('class="card home-panel"');
    expect(html).toContain('class="home-overview-list"');
    expect(html).toContain('class="home-overview-row"');
    expect(html).toContain("home-overview-row-icon");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(html).not.toContain('<img src=x onerror="alert(1)">');
    expect(html.match(/data-notification-view-alerts/g) ?? []).toHaveLength(4);
    // Phone-notification density: one supporting line per row. The requested
    // fields and row caps are detail, and detail belongs on S19.
    expect(html).not.toContain("customers.email");
    expect(html).not.toContain("200 rows");
  });

  it("presents direct source ids as provider names and logos", async () => {
    const routes = fixtures();
    routes[SOURCES_PATH] = [{
      id: "source-notion",
      kind: "notion_direct",
      namespace: "acme",
      syncStatus: "failed",
      lifecycleState: "active",
      lastSyncError: "Authorization expired.",
    }];
    const inbox = await loadAlertInbox(api(routes));
    const html = notificationPanelHtml({ esc: escapeHtml }, inbox);

    expect(html).toContain("Notion stopped working");
    expect(html).not.toContain("Notion_direct");
    expect(html).toContain('class="alert-provider-logo"');
    expect(html).toContain("https://cdn.simpleicons.org/notion/000000");
  });

  it("shows unavailable instead of a false all-clear when a feed refuses", async () => {
    const routes = fixtures();
    delete routes[ALERTS_PATH];
    const inbox = await loadAlertInbox(api(routes));
    const html = notificationPanelHtml({ esc: escapeHtml }, inbox);

    expect(inbox.available).toBe(false);
    expect(inbox.unavailable).toContain("Agent activity");
    expect(html).toContain("Some notifications are unavailable");
    // The feeds that DID answer still render — one refusal costs one group.
    expect(html).toContain("billing-agent is asking for access");
    expect(html).not.toContain("No notifications need attention");
  });

  it("treats a malformed 200 as unavailable rather than as nothing to report", async () => {
    const routes = fixtures();
    routes[PROPOSALS_PATH] = { proposals: null };
    const inbox = await loadAlertInbox(api(routes));

    expect(inbox.available).toBe(false);
    expect(inbox.unavailable).toContain("Knowledge awaiting review");
  });

  it("wires the shared workspace bell and drawer controller", async () => {
    const root = fileURLToPath(new URL("../console/", import.meta.url));
    const [shell, app, alerts, css] = await Promise.all([
      readFile(root + "index.html", "utf8"),
      readFile(root + "app.js", "utf8"),
      readFile(root + "screens/s19.js", "utf8"),
      readFile(root + "app.css", "utf8"),
    ]);

    expect(shell).toContain('data-notification-trigger');
    expect(shell).toContain('aria-controls="workspace-notification-panel"');
    expect(shell).toContain('id="notification-center"');
    expect(shell).toMatch(/<\/main>\s*<\/div>\s*<div id="notification-center"><\/div>/);
    expect(app).toContain("createNotificationCenter");
    expect(app).toContain('go("s19")');
    expect(app).toContain("refreshNotifications");
    expect(alerts).toContain("ctx.refreshNotifications");
    expect(css).toMatch(/\.source-wizard-dialog\.notification-center__dialog\{width:min\(380px,100vw\)/);
    // The drawer borrows Home's primitives rather than restyling a second list:
    // the only scoped rules are a button reset and drawer-scale padding.
    expect(css).toMatch(/\.notification-center__scope \.home-overview-row\{[^}]*cursor:pointer/);
    expect(css).toMatch(/\.notification-center__copy>\*\{[^}]*text-overflow:ellipsis/);
    expect(css).toMatch(/\.notification-center__clear\{[^}]*cursor:pointer/);
  });

  it("wires clearing to the drawer, not to a second alert model", async () => {
    const root = fileURLToPath(new URL("../console/", import.meta.url));
    const center = await readFile(root + "notification-center.js", "utf8");

    expect(center).toContain("data-notification-clear");
    // Clearing repaints from the inbox already in hand: no refetch, and no
    // server call that could be mistaken for a decision.
    expect(center).toContain("clearInformationalNotifications(lastInbox)");
    expect(center).not.toMatch(/data-notification-clear[\s\S]{0,400}api\.(post|del)/);
  });
});

// The inbox is derived from live feeds, so "clear" is a per-browser mute rather
// than server state. The contract worth pinning: it reaches the informational
// lane only — a pending approval must never be dismissable into invisibility —
// and a mute expires when the thing it muted stops being reported.
describe("clearing notifications", () => {
  beforeEach(() => {
    (globalThis as { localStorage?: unknown }).localStorage = fakeStorage();
  });
  afterEach(() => {
    delete (globalThis as { localStorage?: unknown }).localStorage;
  });

  it("clears the informational lane and leaves pending decisions alone", async () => {
    const inbox = await loadAlertInbox(api(fixtures()));
    expect(visibleNotifications(inbox).total).toBe(4);

    clearInformationalNotifications(inbox);
    const view = visibleNotifications(inbox);

    expect(view.justSoYouKnow).toHaveLength(0);
    expect(view.needsYou).toHaveLength(2);
    // The bell counts what the drawer shows, so the badge drops to the decisions.
    expect(view.total).toBe(2);

    const html = notificationPanelHtml({ esc: escapeHtml }, inbox);
    expect(html).toContain("Action Required");
    expect(html).toContain("billing-agent is asking for access");
    expect(html).not.toContain("For Your Information");
    expect(html).not.toContain("nearing your monthly spend limit");
    expect(html).not.toContain("tried to reach data outside its access");
  });

  it("offers the control on the informational card only", async () => {
    const inbox = await loadAlertInbox(api(fixtures()));
    const html = notificationPanelHtml({ esc: escapeHtml }, inbox);

    expect(html.match(/data-notification-clear/g) ?? []).toHaveLength(1);
    expect(html).toContain(
      'aria-label="Clear all For Your Information notifications"',
    );
    // It sits in the informational card's head, after that card's own title.
    expect(html.indexOf("For Your Information")).toBeLessThan(
      html.indexOf("data-notification-clear"),
    );
    expect(html).toContain("Clear all</button>");
  });

  it("says nothing needs attention once everything is cleared and decided", async () => {
    const routes = fixtures();
    routes[REQUESTS_PATH] = [];
    routes[CLIENTS_PATH] = [];
    const inbox = await loadAlertInbox(api(routes));
    clearInformationalNotifications(inbox);

    expect(visibleNotifications(inbox).total).toBe(0);
    expect(notificationPanelHtml({ esc: escapeHtml }, inbox))
      .toContain("No notifications need attention");
  });

  it("re-alerts when a cleared warning escalates", async () => {
    const warned = await loadAlertInbox(api(fixtures()));
    clearInformationalNotifications(warned);
    expect(visibleNotifications(warned).justSoYouKnow).toHaveLength(0);

    // Same row id (`spend:month`), new severity. A cleared 92% warning must not
    // swallow the breach that follows it.
    const routes = fixtures();
    routes[OVERVIEW_PATH] = { spend: { effectiveCapUsd: 100, monthToDateUsd: 140 } };
    const breached = await loadAlertInbox(api(routes));
    const spend = visibleNotifications(breached).justSoYouKnow
      .filter((item: { feed: string }) => item.feed === "spend");

    expect(spend).toHaveLength(1);
    expect(spend[0]!.title).toContain("You've reached your monthly spend limit");
  });

  it("drops a mute once the row stops being reported", async () => {
    const inbox = await loadAlertInbox(api(fixtures()));
    clearInformationalNotifications(inbox);
    expect(readClearedNotifications().size).toBe(2);

    // The failing source recovered and the alert was acknowledged server-side.
    const routes = fixtures();
    routes[ALERTS_PATH] = [];
    routes[OVERVIEW_PATH] = { spend: { effectiveCapUsd: 100, monthToDateUsd: 1 } };
    pruneClearedNotifications(await loadAlertInbox(api(routes)));

    expect(readClearedNotifications().size).toBe(0);
  });

  it("keeps mutes while a feed is unavailable rather than flapping them back", async () => {
    const inbox = await loadAlertInbox(api(fixtures()));
    clearInformationalNotifications(inbox);
    const muted = new Set(inbox.justSoYouKnow.map(notificationFingerprint));

    const routes = fixtures();
    delete routes[ALERTS_PATH];
    const degraded = await loadAlertInbox(api(routes));
    expect(degraded.available).toBe(false);
    pruneClearedNotifications(degraded);

    // An incomplete read is not evidence that anything went away.
    expect(readClearedNotifications()).toEqual(muted);
  });

  it("degrades to no clearing when storage is blocked", async () => {
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get() {
        throw new Error("blocked by policy");
      },
    });
    const inbox = await loadAlertInbox(api(fixtures()));

    expect(() => clearInformationalNotifications(inbox)).not.toThrow();
    expect(readClearedNotifications().size).toBe(0);
    // Nothing is hidden, and the drawer still renders both lanes.
    expect(visibleNotifications(inbox).total).toBe(4);
  });
});

function fakeStorage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
}

function escapeHtml(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
