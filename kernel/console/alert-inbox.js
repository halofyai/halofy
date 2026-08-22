/**
 * The platform alert feed — one read model behind BOTH the Alerts screen (S19)
 * and the workspace notification drawer, so the shell can never invent a second
 * alert system that disagrees with the screen.
 *
 * Ten alert types, grouped by what the person does about them rather than by
 * which subsystem produced them:
 *
 *   Needs you (a decision unblocks it)
 *     1  An agent is asking for access      /agent-access/requests   approve · deny
 *     2  An app wants to connect            /oauth/clients           approve · deny
 *     3  Two facts disagree                 /conflicts               review in S11
 *     4  Something's waiting for review     /proposals               review in S7
 *     5  A message didn't go out            — NOT WIRED (no admin route yet)
 *
 *   Just so you know (acknowledge, no decision)
 *     6  You're nearing your spend limit    /overview (spend)
 *     7  A connection stopped working       /sources
 *     8  An agent went out of bounds        /agent-access/alerts     acknowledge
 *     9  Someone accessed more than usual   — NOT WIRED (no detector yet)
 *     10 Something changed in your org      /audit
 *
 * Types 5 and 9 are deliberately absent rather than faked: neither has a
 * server-side source today, and an inbox that renders an empty group for a
 * detector that was never built reads as "all clear" when nothing was checked.
 *
 * Every feed settles on its own. One refused read costs ONE group, which then
 * renders `Unavailable` — never a silent zero folded into an all-clear.
 *
 * This module returns raw API strings. Escaping is the renderer's job, and both
 * renderers pass every interpolated value through ctx.esc().
 */

const KEYS_PATH = "/v1/admin/keys";

/** Spend is only worth saying out loud from here up. */
const SPEND_WARN_PCT = 80;

/** Audit rows that describe an organization change a person should see. */
const ORG_CHANGE_ROWS = [
  { match: (row) => row.op === "forget", title: "Memory was deleted" },
  { match: (row) => row.op === "assistant_purge", title: "Assistant history was purged" },
  { match: (row) => row.op === "export", title: "Data was exported" },
  { match: (row) => row.purpose === "console-invitation-create", title: "Someone was invited" },
  { match: (row) => row.purpose === "console-team-member-role-change", title: "Someone's role changed" },
  { match: (row) => row.purpose === "usage-cap", title: "The monthly cap was changed" },
];

// ---------------------------------------------------------------------------
// Feeds
//
// `build` returns an array of items, or null when a 200 came back in a shape
// this console cannot read. Null means Unavailable, exactly like a refusal —
// a malformed payload must never be counted as "nothing to report".
// ---------------------------------------------------------------------------

const FEEDS = [
  {
    id: "agent-access",
    lane: "act",
    group: "An agent is asking for access",
    check: "Agent access requests",
    screen: null,
    path: () => "/v1/admin/agent-access/requests?limit=100&status=pending",
    build(value, shared) {
      const rows = listFrom(value, "requests");
      if (!rows) return null;
      return rows.map((row) => {
        const pending = String(row.status || "pending") === "pending";
        const agent = alertAgentName(shared.names, row.keyId);
        return {
          id: "agent-access:" + String(row.id || ""),
          feed: "agent-access",
          lane: "act",
          resolved: !pending,
          tone: pending ? "warn" : undefined,
          state: pending ? "Waiting for you" : String(row.status || ""),
          title: agent + " is asking for access",
          subject: row.sourceRef || "More access",
          body: row.justification || row.purpose || "No reason supplied.",
          meta: [
            fieldList(row.requestedFields),
            plural(row.requestedRows, "row"),
            formatAlertDuration(row.requestedDurationSeconds),
          ],
          when: row.createdAt || "",
          actions: pending
            ? [
              { label: "Approve", action: "alerts-approve", id: row.id, variant: "solid" },
              { label: "Deny", action: "alerts-deny", id: row.id, variant: "outline" },
            ]
            : [],
        };
      });
    },
  },

  {
    id: "app-connect",
    lane: "act",
    group: "An app wants to connect",
    check: "App connection requests",
    screen: "s17",
    screenLabel: "Open Connected apps",
    path: () => "/v1/admin/oauth/clients",
    build(value, shared) {
      const rows = listFrom(value, "clients");
      if (!rows) return null;
      return rows.map((row) => {
          const pending = String(row.status || "") === "pending";
          return {
            id: "app-connect:" + String(row.id || ""),
            feed: "app-connect",
            lane: "act",
            resolved: !pending,
            tone: pending ? "warn" : undefined,
            state: pending ? "Waiting for you" : String(row.status || ""),
            title: (row.name || "An app") + " wants to connect",
            subject: row.namespace || "Organization",
            body: "An outside tool is asking to link to your workspace. Approve it only if you recognise it.",
            meta: [],
            when: row.createdAt || "",
            actions: pending
              ? [
                { label: "Approve", action: "alerts-app-approve", id: row.id, variant: "solid" },
                { label: "Deny", action: "alerts-app-deny", id: row.id, variant: "outline" },
              ]
              : [],
          };
        });
    },
  },

  {
    id: "fact-conflict",
    lane: "act",
    group: "Two facts disagree",
    check: "Contradictions in your memory",
    screen: "s11",
    screenLabel: "Open Conflicts",
    path: () => "/v1/admin/conflicts",
    build(value, shared) {
      if (!value || typeof value !== "object" || Array.isArray(value)) return null;
      const disputes = Array.isArray(value.disputes) ? value.disputes : null;
      if (!disputes) return null;
      const findings = Array.isArray(value.findings)
        ? value.findings
        : Array.isArray(value.scanFindings) ? value.scanFindings : [];
      // A scan finding and a write-time dispute are the same sentence to an
      // operator: something we hold contradicts something else we hold.
      return disputes.concat(findings).map((row, index) => {
        const settled = String(row.status || "open") !== "open";
        return {
        id: "fact-conflict:" + String(row.id || index),
        feed: "fact-conflict",
        lane: "act",
        resolved: settled,
        tone: settled ? undefined : "warn",
        state: settled ? String(row.status || "") : "Needs a decision",
        title: "Two facts disagree",
        subject: row.team || row.namespace || "Organization",
        body: row.reason || row.summary || "Two saved memories contradict each other.",
        meta: [row.category ? readableCategory(row.category) : ""],
        when: row.createdAt || row.created_at || "",
        actions: [],
        };
      });
    },
  },

  {
    id: "needs-review",
    lane: "act",
    group: "Something's waiting for review",
    check: "Knowledge awaiting review",
    screen: "s7",
    screenLabel: "Open Knowledge operations",
    path: () => "/v1/admin/proposals",
    build(value, shared) {
      const rows = listFrom(value, "proposals");
      if (!rows) return null;
      return rows.map((row) => {
          const status = String(row.status || "");
          const awaiting = status === "pending_review" || status === "publishing";
          const draft = row.draft && typeof row.draft === "object" ? row.draft : {};
          const interrupted = status === "publishing";
          return {
            id: "needs-review:" + String(row.id || ""),
            feed: "needs-review",
            lane: "act",
            resolved: !awaiting,
            tone: awaiting ? "warn" : undefined,
            state: interrupted
              ? "Publication interrupted"
              : awaiting ? "Waiting for you" : status,
            title: "New knowledge is waiting for review",
            subject: draft.title || "Untitled draft",
            body: interrupted
              ? "This was approved but never finished publishing. Open it to retry."
              : "Nothing is saved as official knowledge until someone approves it.",
            meta: [row.namespace ? String(row.namespace) : ""],
            when: row.createdAt || row.updatedAt || "",
            actions: [],
          };
        });
    },
  },

  {
    id: "agent-bounds",
    lane: "info",
    group: "An agent went out of bounds",
    check: "Agent activity",
    screen: null,
    path: () => "/v1/admin/agent-access/alerts?limit=100&status=open",
    build(value, shared) {
      const rows = listFrom(value, "alerts");
      if (!rows) return null;
      return rows.map((row) => {
        const open = String(row.status || "open") === "open";
        const soft = row.kind === "usage-threshold" && row.severity !== "critical";
        return {
          id: "agent-bounds:" + String(row.id || ""),
          feed: "agent-bounds",
          lane: "info",
          resolved: !open,
          tone: open ? (soft ? "warn" : "crit") : undefined,
          state: open ? (soft ? "Worth a look" : "Blocked") : "Acknowledged",
          title: alertAgentName(shared.names, row.keyId) + " " + alertLabel(row.kind),
          subject: "",
          body: row.detail || alertExplain(row.kind),
          meta: [roleList(row.recipientRoles)],
          when: row.createdAt || "",
          actions: open
            ? [{ label: "Got it", action: "alerts-acknowledge", id: row.id, variant: "outline" }]
            : [],
        };
      });
    },
  },

  {
    id: "spend",
    lane: "info",
    group: "You're nearing your spend limit",
    // The organization overview, not /v1/admin/usage: that route requires an
    // explicit target namespace and 400s without one, which would have made
    // this feed permanently Unavailable. Overview carries the same two figures.
    check: "Spend and credit limits",
    screen: "s15",
    screenLabel: "Open Usage analytics",
    path: () => "/v1/admin/overview",
    build(value) {
      if (!value || typeof value !== "object" || Array.isArray(value)) return null;
      const spend = value.spend && typeof value.spend === "object" ? value.spend : {};
      const capUsd = finite(spend.effectiveCapUsd);
      const spentUsd = finite(spend.monthToDateUsd);
      if (capUsd === null || spentUsd === null || capUsd <= 0) return [];
      const pct = Math.round((spentUsd / capUsd) * 100);
      if (pct < SPEND_WARN_PCT) return [];
      const over = pct >= 100;
      return [{
        id: "spend:month",
        feed: "spend",
        lane: "info",
        resolved: false,
        tone: over ? "crit" : "warn",
        state: pct + "% of the cap",
        title: over
          ? "You've reached your monthly spend limit"
          : "You're nearing your monthly spend limit",
        subject: "",
        body: over
          ? "Paid AI features fall back at the limit. Your memory stays available."
          : "Paid AI features stop at the limit. Raise the cap from Home if you need more room.",
        meta: [money(spentUsd) + " of " + money(capUsd) + " used this month"],
        when: "",
        actions: [],
      }];
    },
  },

  {
    id: "connection",
    lane: "info",
    group: "A connection stopped working",
    check: "Connected sources and channels",
    screen: "s6",
    screenLabel: "Open Sources",
    path: () => "/v1/admin/sources",
    build(value) {
      const rows = listFrom(value, "sources");
      if (!rows) return null;
      return rows
        .filter((row) =>
          String(row.syncStatus || "") === "failed" &&
          String(row.lifecycleState || "active") === "active"
        )
        .map((row) => ({
          id: "connection:" + String(row.id || ""),
          feed: "connection",
          lane: "info",
          resolved: false,
          tone: "crit",
          state: "Not syncing",
          title: sourceName(row.kind) + " stopped working",
          sourceKind: String(row.kind || ""),
          subject: row.namespace || "",
          body: row.lastSyncError
            ? String(row.lastSyncError)
            : "The last refresh failed, so anything new from here is missing.",
          meta: [],
          when: row.lastSync || "",
          actions: [],
        }));
    },
  },

  {
    id: "org-change",
    lane: "info",
    group: "Something changed in your org",
    check: "Recent organization changes",
    screen: "s8",
    screenLabel: "Open Audit",
    path: () => "/v1/admin/audit?limit=50",
    build(value) {
      const rows = listFrom(value, "events");
      if (!rows) return null;
      const items = [];
      for (const row of rows) {
        if (String(row.result || "") !== "ok") continue;
        const match = ORG_CHANGE_ROWS.find((rule) =>
          rule.match({ op: String(row.op || ""), purpose: String(row.purpose || "") })
        );
        if (!match) continue;
        items.push({
          id: "org-change:" + String(row.ts || "") + ":" + items.length,
          feed: "org-change",
          lane: "info",
          resolved: false,
          tone: undefined,
          state: "",
          title: match.title,
          subject: row.actor ? String(row.actor) : "",
          body: "",
          meta: [],
          when: row.ts || "",
          actions: [],
        });
        if (items.length === 5) break;
      }
      return items;
    },
  },
];

// ---------------------------------------------------------------------------
// Read cache. The drawer refreshes on every route change and the screen refetches
// after every decision; nine round trips per paint made the bell feel dead.
// Any decision clears it, so an approval never repaints from a stale copy.
// ---------------------------------------------------------------------------

const CACHE_TTL_MS = 20_000;
let cache = null;
let cacheGeneration = 0;

export function clearAlertInboxCache() {
  cache = null;
  cacheGeneration += 1;
}

/**
 * Every alert the console knows about, in one shape.
 *
 * @returns {Promise<object>} needsYou / justSoYouKnow / groups / counts, plus
 *   the agent-gateway fields the notification drawer and its tests still read.
 */
export async function loadAlertInbox(ctx) {
  // Keyed on the ctx identity, the same way Home scopes its read cache: a new
  // session (or a new test harness) never inherits the previous one's reads.
  if (cache && cache.ctx === ctx && Date.now() - cache.at < CACHE_TTL_MS) {
    return cache.inbox;
  }
  const generation = cacheGeneration;

  const keyResult = listOf(ctx, KEYS_PATH, "keys");
  const feedResults = FEEDS.map((feed) => readFeed(ctx, feed));
  const [keys, ...settled] = await Promise.all([keyResult, ...feedResults]);

  const names = new Map();
  for (const row of keys.items) {
    if (row && row.id) names.set(String(row.id), String(row.actor || row.id));
  }
  const shared = { names };

  const groups = [];
  const items = [];
  for (let index = 0; index < FEEDS.length; index += 1) {
    const feed = FEEDS[index];
    const result = settled[index];
    let built = null;
    if (result.available) {
      try {
        built = feed.build(result.value, shared);
      } catch {
        built = null;
      }
    }
    const available = Array.isArray(built);
    // A decided row (revoked app, resolved dispute, published draft) is history,
    // not an alert. Showing it under "Action Required" put a row with no buttons
    // in a lane whose title promises a pending decision.
    const rows = available ? built.filter((row) => !row.resolved) : [];
    groups.push({
      id: feed.id,
      lane: feed.lane,
      title: feed.group,
      // What we tried to CHECK, which is what an Unavailable row must say. The
      // group title is the alert's headline and would read as though it fired.
      check: feed.check,
      screen: feed.screen ?? null,
      screenLabel: feed.screenLabel ?? "",
      available,
      count: rows.length,
    });
    for (const row of rows) {
      items.push({ ...row, screen: feed.screen ?? null, screenLabel: feed.screenLabel ?? "" });
    }
  }

  const needsYou = sortByAge(items.filter((item) => item.lane === "act"));
  const justSoYouKnow = sortByAge(items.filter((item) => item.lane === "info"));
  const unavailable = groups.filter((group) => !group.available).map((group) => group.check);

  // Back-compat surface. The drawer and the agent-gateway decisions still read
  // these; keeping them here is what stops a second alert model from appearing.
  const agentRequests = items.filter((item) => item.feed === "agent-access");
  const agentAlerts = items.filter((item) => item.feed === "agent-bounds");
  const groupOf = (id) => groups.find((group) => group.id === id);

  const inbox = {
    items,
    groups,
    needsYou,
    justSoYouKnow,
    unavailable,
    total: needsYou.length + justSoYouKnow.length,
    actionCount: needsYou.length,
    infoCount: justSoYouKnow.length,
    oldest: oldestWaiting(needsYou),
    available: unavailable.length === 0,
    names,
    keysAvailable: keys.available,
    alertsAvailable: !!groupOf("agent-bounds")?.available,
    requestsAvailable: !!groupOf("agent-access")?.available,
    pending: agentRequests,
    open: agentAlerts,
  };
  // A decision may invalidate the inbox while this older read is still in
  // flight. Never let that pre-decision result repopulate the shared cache.
  if (generation === cacheGeneration) cache = { ctx, at: Date.now(), inbox };
  return inbox;
}

async function readFeed(ctx, feed) {
  try {
    return { available: true, value: await ctx.api.get(feed.path()) };
  } catch {
    return { available: false, value: null };
  }
}

async function listOf(ctx, path, key) {
  try {
    const value = await ctx.api.get(path);
    if (Array.isArray(value)) return { items: value, available: true };
    if (value && Array.isArray(value[key])) return { items: value[key], available: true };
    return { items: [], available: false };
  } catch {
    return { items: [], available: false };
  }
}

/** An array payload, tolerating the `{ key: [...] }` envelope. Null = unusable. */
function listFrom(value, key) {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (value && typeof value === "object" && Array.isArray(value[key])) {
    return value[key].filter(isRecord);
  }
  return null;
}

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Oldest first: the thing that has been waiting longest is the most overdue. */
function sortByAge(items) {
  return items.slice().sort((left, right) => {
    const a = Date.parse(String(left.when || ""));
    const b = Date.parse(String(right.when || ""));
    if (!Number.isFinite(a) && !Number.isFinite(b)) return 0;
    if (!Number.isFinite(a)) return 1;
    if (!Number.isFinite(b)) return -1;
    return a - b;
  });
}

function oldestWaiting(items) {
  for (const item of items) {
    const at = Date.parse(String(item.when || ""));
    if (Number.isFinite(at)) return item.when;
  }
  return "";
}

function finite(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function money(value) {
  return "$" + Number(value).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function plural(value, noun) {
  const count = Number(value) || 0;
  return count + " " + noun + (count === 1 ? "" : "s");
}

function fieldList(values) {
  const list = Array.isArray(values) ? values.map(String) : [];
  if (list.length === 0) return "";
  if (list.length <= 3) return list.join(", ");
  return list.slice(0, 3).join(", ") + " +" + (list.length - 3) + " more";
}

function roleList(values) {
  const list = Array.isArray(values) ? values.map(String) : [];
  return list.length ? "Told: " + list.join(", ") : "";
}

function readableCategory(value) {
  return ({
    "policies-legal": "Policies and legal",
    "order-management": "Order management",
    "product-info": "Product information",
    other: "Other",
  })[String(value)] || String(value);
}

function sourceName(kind) {
  const value = String(kind || "").trim();
  if (!value) return "A connection";
  const provider = value.replace(/_(direct|catalogue|knowledge)$/i, "");
  return ({
    google_drive: "Google Drive",
    google_sheets: "Google Sheets",
    google_docs: "Google Docs",
    google_calendar: "Google Calendar",
    microsoft_teams: "Microsoft Teams",
  })[provider] || provider
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

// ---------------------------------------------------------------------------
// Shared labels. Exported because S19 and the drawer both speak them, and the
// gateway alert vocabulary is server-owned — it must be translated in exactly
// one place.
// ---------------------------------------------------------------------------

/**
 * One glyph per alert type, shared by S19 and the drawer so the same alert never
 * wears two different icons. Neutral chrome per the design language — the chip
 * stays gray and colour is carried by the pill.
 */
const ALERT_ICONS = {
  "agent-access": '<rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M8 12h.01M16 12h.01"/>',
  "app-connect": '<path d="M9 3v6M15 3v6M6 9h12v4a6 6 0 0 1-12 0zM12 19v2"/>',
  "fact-conflict": '<path d="M12 3 3.8 19h16.4z"/><path d="M12 9v4M12 16h.01"/>',
  "needs-review": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M9 15l2 2 4-4"/>',
  "agent-bounds": '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3ZM9.5 9.5l5 5m0-5-5 5"/>',
  spend: '<path d="M12 3v18M16 7.5c0-1.4-1.8-2.5-4-2.5S8 6.1 8 7.5 9.8 10 12 10s4 1.1 4 2.5S14.2 15 12 15s-4-1.1-4-2.5"/>',
  connection: '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
  "org-change": '<path d="M16 20v-1.5a4.5 4.5 0 0 0-9 0V20M11.5 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM18 8a3 3 0 0 1 0 6"/>',
  unavailable: '<path d="M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18ZM12 8v5M12 16h.01"/>',
};

export function alertIcon(name) {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    (ALERT_ICONS[name] || ALERT_ICONS.unavailable) + "</svg>";
}

const SOURCE_LOGOS = Object.freeze({
  linear: "https://cdn.simpleicons.org/linear",
  notion: "https://cdn.simpleicons.org/notion/000000",
  slack: "https://cdn.simpleicons.org/slack",
  google_drive: "https://cdn.simpleicons.org/googledrive",
  google_sheets: "https://cdn.simpleicons.org/googlesheets",
  google_docs: "https://cdn.simpleicons.org/googledocs",
  google_calendar: "https://cdn.simpleicons.org/googlecalendar",
  github: "https://cdn.simpleicons.org/github",
  shopify: "https://cdn.simpleicons.org/shopify",
});

/** Use the provider's mark for connection alerts; other alert types keep their shared glyph. */
export function alertVisual(item) {
  if (!item || item.feed !== "connection") return alertIcon(item && item.feed);
  const kind = String(item.sourceKind || "").replace(/_(direct|catalogue|knowledge)$/i, "");
  const logo = SOURCE_LOGOS[kind];
  return logo
    ? '<img class="alert-provider-logo" src="' + logo + '" alt="">'
    : alertIcon("connection");
}

export function alertAgentName(names, keyId) {
  const id = String(keyId || "");
  return (names && names.get ? names.get(id) : null) || id || "Unknown agent";
}

export function alertLabel(kind) {
  return ({
    "outside-scope": "tried to reach data outside its access",
    "repeated-denial": "was blocked repeatedly",
    "rate-limit": "crossed its request limit",
    "usage-threshold": "reached its usage alert level",
    "authority-change": "had its access change mid-request",
  })[kind] || "needs attention";
}

/** Plain-language "so what" for an agent alert with no server detail line. */
export function alertExplain(kind) {
  return ({
    "outside-scope": "It asked for data it was never given access to. The read was refused.",
    "repeated-denial": "It kept asking for the same refused data. That is worth a look.",
    "rate-limit": "It sent more requests than its limit allows, so it was throttled.",
    "usage-threshold": "Nothing was refused — it is simply reading a lot more than usual.",
    "authority-change": "Its permission was withdrawn while a read was in flight, so the read was stopped.",
  })[kind] || "This agent did something worth a human glance.";
}

export function formatAlertWhen(value) {
  const time = Date.parse(String(value || ""));
  if (!Number.isFinite(time)) return String(value || "Unknown time");
  return new Date(time).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
}

/** "3 days ago" reads faster than a timestamp when triaging a queue. */
export function formatAlertAge(value) {
  const time = Date.parse(String(value || ""));
  if (!Number.isFinite(time)) return "";
  const minutes = Math.floor((Date.now() - time) / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return minutes + (minutes === 1 ? " min ago" : " mins ago");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + (hours === 1 ? " hour ago" : " hours ago");
  const days = Math.floor(hours / 24);
  return days + (days === 1 ? " day ago" : " days ago");
}

/** Compact age for the summary tile: "3d", "5h", "12m". */
export function formatAlertWait(value) {
  const time = Date.parse(String(value || ""));
  if (!Number.isFinite(time)) return "—";
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60_000));
  if (minutes < 60) return minutes + "m";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h";
  return Math.floor(hours / 24) + "d";
}

export function formatAlertDuration(seconds) {
  const value = Number(seconds) || 0;
  if (value % 3600 === 0) return `${value / 3600}h`;
  return `${Math.round(value / 60)}m`;
}
