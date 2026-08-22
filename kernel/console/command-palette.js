/**
 * The console command palette - one keystroke to every screen, metric, and action.
 *
 * Cmd+K (macOS) / Ctrl+K (Windows, Linux) opens an overlay that searches three
 * things at once:
 *
 *   1. SCREENS  - the role-filtered rail. The palette reads the SAME
 *                 `allowedScreens` set the router guards with, so it can never
 *                 offer a screen the rail withheld. It grants no new authority.
 *   2. METRICS  - live numbers from GET /v1/admin/overview, rendered with their
 *                 value inline ("Active memories  710") and wired to the screen
 *                 that owns them. A metric whose owning screen is not allowed is
 *                 dropped, so the palette never advertises a 403.
 *   3. ACTIONS  - verb-shaped jumps ("Connect a source", "Review conflicts"),
 *                 each likewise pinned to an allowed screen.
 *
 * Like the assistant dock, it mounts OUTSIDE #screen-content so the router never
 * repaints it, and it stays hidden while the mandatory setup gate is locked.
 *
 * Brownout, never hard-fail: if the overview fetch fails the palette opens
 * anyway with screens and actions. It never renders a fabricated zero - a metric
 * the server did not report is simply absent.
 *
 * Rendering is string-based and every value crosses ctx.esc, the same single XSS
 * defense the screens use. The builders and the matcher below are pure so the
 * suite can exercise them without a browser DOM.
 */

const GROUP_SCREENS = "Screens";
const GROUP_METRICS = "Metrics";
const GROUP_ACTIONS = "Actions";

/** Natural group order when the query is empty. */
const GROUP_ORDER = [GROUP_METRICS, GROUP_SCREENS, GROUP_ACTIONS];

/** How long a fetched overview stays fresh enough to reuse across opens (ms). */
const OVERVIEW_TTL_MS = 30_000;

// ---------------------------------------------------------------------------
// Value formatting. Every formatter refuses non-finite input by returning null,
// which is how a metric drops out of the list instead of rendering "NaN" or a
// zero the server never reported.
// ---------------------------------------------------------------------------

function formatCount(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return new Intl.NumberFormat("en-US").format(Math.round(value));
}

function formatUsd(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return null;
  // Sub-dollar spend is the common case on a young tenant; rounding it to $0.00
  // would report "nothing spent" for a real charge.
  // Fixed (not trimmed) decimals so two sub-dollar figures sitting next to each
  // other line up: $0.0743 above $0.0850, never $0.0743 above $0.085.
  const digits = value > 0 && value < 1 ? 4 : 2;
  return (
    "$" +
    new Intl.NumberFormat("en-US", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(value)
  );
}

function formatPercent(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const pct = value * 100;
  return (Number.isInteger(pct) ? String(pct) : pct.toFixed(1)) + "%";
}

const FORMATTERS = {
  count: formatCount,
  usd: formatUsd,
  percent: formatPercent,
};

// ---------------------------------------------------------------------------
// Metric catalog. Each entry names the overview field it reads and the screen
// that OWNS it - the screen the palette navigates to and the screen whose
// permission decides whether the metric is offered at all.
// ---------------------------------------------------------------------------

export const METRIC_SPECS = [
  {
    id: "metric:memories",
    label: "Active memories",
    screen: "s5",
    format: "count",
    read: (o) => o.l2Active,
    keywords: ["memory", "memories", "facts", "l2", "stored", "knowledge"],
  },
  {
    id: "metric:sources",
    label: "Connected sources",
    screen: "s6",
    format: "count",
    read: (o) => o.sourcesSummary && o.sourcesSummary.connectedCount,
    keywords: ["source", "sources", "connector", "connectors", "ingest", "sync"],
  },
  {
    id: "metric:faults",
    label: "Memory faults",
    screen: "s2",
    format: "count",
    read: (o) => o.faultCount,
    keywords: ["fault", "faults", "miss", "misses", "gap", "gaps"],
  },
  {
    id: "metric:fault-rate",
    label: "Fault hit rate",
    screen: "s2",
    format: "percent",
    read: (o) => o.faultHitRate,
    keywords: ["fault", "hit", "rate", "recall", "coverage"],
  },
  {
    id: "metric:tokens",
    label: "Tokens used",
    screen: "s15",
    format: "count",
    read: (o) => o.usage && o.usage.totalTokens,
    keywords: ["token", "tokens", "usage", "consumption"],
  },
  {
    id: "metric:tokens-saved",
    label: "Tokens saved",
    screen: "s2",
    format: "count",
    read: (o) => o.tokensSavedEstimate,
    keywords: ["token", "tokens", "saved", "savings", "efficiency"],
  },
  {
    id: "metric:spend",
    label: "Spend month to date",
    screen: "s15",
    format: "usd",
    read: (o) => o.spend && o.spend.monthToDateUsd,
    keywords: ["spend", "cost", "billing", "usd", "dollar", "month"],
  },
  {
    id: "metric:cap",
    label: "Effective spend cap",
    screen: "s15",
    format: "usd",
    read: (o) => o.spend && o.spend.effectiveCapUsd,
    keywords: ["cap", "limit", "budget", "spend", "ceiling"],
  },
  {
    id: "metric:usage-usd",
    label: "Usage charged",
    screen: "s15",
    format: "usd",
    read: (o) => o.usage && o.usage.totalUsd,
    keywords: ["usage", "charged", "cost", "billing", "usd"],
  },
  {
    id: "metric:models",
    label: "Model connections",
    screen: "s12",
    format: "count",
    read: (o) => (Array.isArray(o.models) ? o.models.length : undefined),
    keywords: ["model", "models", "llm", "provider", "connection"],
  },
];

/**
 * Live metric rows for the current overview payload.
 *
 * A row survives only when (a) its owning screen is in `allowedScreens` and
 * (b) the server actually reported a finite value. Per-team memory counts ride
 * along from `overview.children` when the Teams screen is allowed.
 */
export function buildMetricItems(overview, allowedScreens) {
  if (!overview || typeof overview !== "object") return [];
  const allowed = allowedScreens ?? new Set();
  const items = [];
  for (const spec of METRIC_SPECS) {
    if (!allowed.has(spec.screen)) continue;
    const format = FORMATTERS[spec.format];
    const value = format ? format(spec.read(overview)) : null;
    if (value === null) continue;
    items.push({
      id: spec.id,
      group: GROUP_METRICS,
      label: spec.label,
      value,
      hint: spec.screen,
      keywords: spec.keywords,
      perform: { type: "screen", screen: spec.screen },
    });
  }
  if (allowed.has("s13") && Array.isArray(overview.children)) {
    for (const child of overview.children) {
      if (!child || typeof child.namespace !== "string" || child.namespace === "") continue;
      const value = formatCount(child.l2Active);
      if (value === null) continue;
      const leaf = child.namespace.split("/").pop() || child.namespace;
      items.push({
        id: "metric:team:" + child.namespace,
        group: GROUP_METRICS,
        label: leaf + " memories",
        value,
        hint: child.namespace,
        keywords: ["team", "namespace", "memories", child.namespace, leaf],
        perform: { type: "screen", screen: "s13" },
      });
    }
  }
  return items;
}

// ---------------------------------------------------------------------------
// Screens + actions.
// ---------------------------------------------------------------------------

/** Extra search terms per screen, so "billing" finds Usage analytics. */
const SCREEN_KEYWORDS = {
  s2: ["home", "overview", "dashboard", "start"],
  s5: ["memory", "map", "graph", "facts"],
  s6: ["source", "connector", "ingest", "upload", "knowledge base"],
  s14: ["agent", "connection", "mcp", "api key", "client"],
  s10: ["assistant", "chat", "ask", "copilot"],
  s21: ["channel", "slack", "whatsapp", "email"],
  s16: ["skill", "skills", "library"],
  s15: ["usage", "analytics", "billing", "spend", "tokens", "cost"],
  s13: ["team", "teams", "people", "member", "namespace"],
  s3: ["scoped memory", "scope", "badge", "agent", "agents", "roster"],
  s19: ["alert", "alerts", "inbox", "request"],
  s4: ["policy", "policies", "rule", "governance"],
  s7: ["review", "knowledge", "approve", "queue"],
  s11: ["conflict", "conflicts", "dispute", "supersede"],
  s8: ["audit", "trail", "log", "deletion", "forget", "erasure"],
  s20: ["export", "download", "dump"],
  s17: ["connected apps", "oauth", "client", "app"],
  s12: ["model", "models", "llm", "provider"],
  s1: ["setup", "onboarding", "checklist", "getting started"],
  s18: ["profile", "settings", "account", "me", "sign-in", "password", "organization"],
};

/**
 * One row per rail entry the current role may open. `navigation` is app.js's
 * NAV array; `allowedScreens` is the router's own guard set, so the palette and
 * the rail can never disagree about what exists.
 */
export function buildScreenItems({ navigation, allowedScreens, capabilities } = {}) {
  const allowed = allowedScreens ?? new Set();
  const caps = capabilities ?? {};
  const items = [];
  const seen = new Set();
  for (const group of navigation ?? []) {
    for (const item of group.items ?? []) {
      if (!item.s) {
        // Capability-gated launchers (Halo Agents) carry no screen id.
        if (item.capability && caps[item.capability] === true && !seen.has(item.label)) {
          seen.add(item.label);
          items.push({
            id: "screen:" + item.capability,
            group: GROUP_SCREENS,
            label: item.label,
            value: "",
            hint: group.group,
            keywords: ["halo", "agents", "workflow"],
            perform: { type: item.action },
          });
        }
        continue;
      }
      if (!allowed.has(item.s) || seen.has(item.s)) continue;
      seen.add(item.s);
      items.push({
        id: "screen:" + item.s,
        group: GROUP_SCREENS,
        // NAV labels may be authored HTML; the palette
        // needs the plain text so matching and escaping both behave.
        label: decodeNavLabel(item.label),
        value: "",
        hint: group.group,
        keywords: SCREEN_KEYWORDS[item.s] ?? [],
        perform: { type: "screen", screen: item.s },
      });
    }
  }
  return items;
}

/** NAV labels are pre-escaped for direct innerHTML use; undo that for search. */
export function decodeNavLabel(label) {
  return String(label ?? "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

const ACTION_SPECS = [
  { id: "ask", label: "Ask the assistant", screen: "s10", keywords: ["chat", "question", "copilot"] },
  { id: "connect-source", label: "Connect a source", screen: "s6", keywords: ["add", "integration", "import"] },
  { id: "connect-agent", label: "Connect an agent", screen: "s14", keywords: ["mcp", "claude", "codex", "api key"] },
  { id: "invite", label: "Invite a teammate", screen: "s13", keywords: ["add", "member", "people", "seat"] },
  { id: "review-knowledge", label: "Review pending knowledge", screen: "s7", keywords: ["approve", "queue"] },
  { id: "resolve-conflicts", label: "Resolve conflicts", screen: "s11", keywords: ["dispute", "supersede"] },
  { id: "search-audit", label: "Search the audit trail", screen: "s8", keywords: ["log", "who", "history"] },
  { id: "set-cap", label: "Set a usage cap", screen: "s15", keywords: ["budget", "limit", "spend"] },
  { id: "export", label: "Export memory", screen: "s20", keywords: ["download", "dump", "backup"] },
  { id: "manage-apps", label: "Manage connected apps", screen: "s17", keywords: ["oauth", "client"] },
  { id: "finish-setup", label: "Finish setup", screen: "s1", keywords: ["onboarding", "checklist"] },
  // Label stays surface-neutral so it survives the Profile/Settings rename that
  // the rail itself carries; the Screens row already tracks NAV verbatim.
  { id: "profile", label: "Open your account", screen: "s18", keywords: ["profile", "settings", "password", "sign-in"] },
];

/** Verb-shaped rows, each dropped when its screen is outside the role's rail. */
export function buildActionItems({ allowedScreens } = {}) {
  const allowed = allowedScreens ?? new Set();
  const items = ACTION_SPECS.filter((spec) => allowed.has(spec.screen)).map((spec) => ({
    id: "action:" + spec.id,
    group: GROUP_ACTIONS,
    label: spec.label,
    value: "",
    hint: "",
    keywords: spec.keywords,
    perform: { type: "screen", screen: spec.screen },
  }));
  // Sign out needs no screen grant - every session owns its own logout.
  items.push({
    id: "action:signout",
    group: GROUP_ACTIONS,
    label: "Sign out",
    value: "",
    hint: "",
    keywords: ["logout", "log out", "leave", "exit"],
    perform: { type: "signout" },
  });
  return items;
}

/** The full candidate list for one open, in natural (empty-query) order. */
export function buildPaletteItems({
  navigation,
  allowedScreens,
  capabilities,
  overview,
} = {}) {
  const byGroup = {
    [GROUP_METRICS]: buildMetricItems(overview, allowedScreens),
    [GROUP_SCREENS]: buildScreenItems({ navigation, allowedScreens, capabilities }),
    [GROUP_ACTIONS]: buildActionItems({ allowedScreens }),
  };
  return GROUP_ORDER.flatMap((group) => byGroup[group] ?? []);
}

// ---------------------------------------------------------------------------
// Matching. A subsequence matcher with prefix/word-boundary bonuses - the same
// shape every palette uses, kept pure so its ranking is testable.
// ---------------------------------------------------------------------------

function haystack(item) {
  return [item.label, item.hint, ...(item.keywords ?? [])]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

/**
 * Score one item against a lowercased query. Returns -1 when the query is not a
 * subsequence of the item's searchable text (label + hint + keywords).
 */
export function scoreItem(item, query) {
  const q = String(query ?? "").trim().toLowerCase();
  if (q === "") return 0;
  const label = String(item.label ?? "").toLowerCase();
  const hay = haystack(item);

  const labelIndex = label.indexOf(q);
  if (labelIndex === 0) return 1000 - label.length;
  if (labelIndex > 0) {
    // A match that starts a word ("hit rate" for "rate") beats one mid-word.
    const boundary = labelIndex === 0 || /[\s\-/]/.test(label[labelIndex - 1]);
    return (boundary ? 800 : 640) - labelIndex;
  }
  const hayIndex = hay.indexOf(q);
  if (hayIndex >= 0) return 500 - Math.min(hayIndex, 200);

  // Subsequence fallback: "adtr" still finds "Search the audit trail".
  let cursor = 0;
  let gaps = 0;
  for (const ch of q) {
    const at = hay.indexOf(ch, cursor);
    if (at === -1) return -1;
    gaps += at - cursor;
    cursor = at + 1;
  }
  return Math.max(1, 300 - gaps);
}

/**
 * Rank and group. Groups are ordered by their best-scoring member so a strong
 * metric match can outrank the screen list; an empty query keeps the natural
 * GROUP_ORDER (metrics first - the live numbers are the point of the palette).
 */
export function rankItems(items, query, limit = 50) {
  const q = String(query ?? "").trim();
  const scored = [];
  for (const item of items ?? []) {
    const score = scoreItem(item, q);
    if (score < 0) continue;
    scored.push({ item, score });
  }
  if (q === "") {
    return groupInOrder(
      scored.map((s) => s.item).slice(0, limit),
      GROUP_ORDER,
    );
  }
  scored.sort((a, b) => b.score - a.score);
  const best = new Map();
  for (const { item, score } of scored) {
    if (!best.has(item.group)) best.set(item.group, score);
  }
  const order = [...best.entries()].sort((a, b) => b[1] - a[1]).map(([group]) => group);
  return groupInOrder(
    scored.map((s) => s.item).slice(0, limit),
    order,
  );
}

function groupInOrder(items, order) {
  const groups = [];
  for (const group of order) {
    const members = items.filter((item) => item.group === group);
    if (members.length > 0) groups.push({ group, items: members });
  }
  return groups;
}

/** Flatten grouped results back to the keyboard-navigable sequence. */
export function flattenGroups(groups) {
  return (groups ?? []).flatMap((g) => g.items);
}

// ---------------------------------------------------------------------------
// Shortcut. The console shows ⌘K on EVERY platform - it is the recognised name
// for this control, and one label keeps docs, screenshots, and support answers
// identical for every user.
//
// The binding is deliberately wider than the label. On Windows and Linux the
// key in the Command position reports as `metaKey` (the Windows/Super key), so
// a user who reads "⌘K" and presses it is honoured. Ctrl+K stays bound there as
// well, because Windows itself swallows Win+K for the Cast panel and the
// browser may never see the event - without the Ctrl alias the advertised
// shortcut would simply not work for most Windows users.
//
// Ctrl+K is NOT bound on macOS: it is the readline "delete to end of line"
// binding, and stealing it would break text editing in the assistant composer.
// ---------------------------------------------------------------------------

export const SHORTCUT_LABEL = "⌘K";

export function isMacPlatform(nav) {
  const source = nav ?? (typeof navigator === "undefined" ? null : navigator);
  if (!source) return false;
  const platform =
    (source.userAgentData && source.userAgentData.platform) ||
    source.platform ||
    source.userAgent ||
    "";
  return /mac|iphone|ipad|ipod/i.test(String(platform));
}

/** One spelling everywhere. The parameter is accepted and ignored. */
export function shortcutLabel() {
  return SHORTCUT_LABEL;
}

/**
 * True when a keydown should open the palette: Command/Meta+K anywhere, plus
 * Ctrl+K off macOS. See the block comment above for why the two differ.
 */
export function isPaletteShortcut(event, nav) {
  if (!event) return false;
  const key = String(event.key ?? "").toLowerCase();
  if (key !== "k") return false;
  if (event.altKey) return false;
  if (event.metaKey === true) return true;
  return event.ctrlKey === true && !isMacPlatform(nav);
}

// ---------------------------------------------------------------------------
// The DOM shell.
// ---------------------------------------------------------------------------

/**
 * @param {object} options
 * @param {import('./app.js').Ctx} options.ctx        shell context (api, esc, go)
 * @param {HTMLElement} options.root                  the palette mount point
 * @param {() => Array} options.navigation            the NAV array
 * @param {() => Set<string>} options.allowedScreens  the router's live guard set
 * @param {() => void} [options.onSignOut]            sign-out handler from app.js
 * @param {(action: string) => void} [options.onAction] non-screen launcher (Halo Agents)
 */
export function createCommandPalette({
  ctx,
  root,
  navigation,
  allowedScreens,
  onSignOut,
  onAction,
  doc = typeof document === "undefined" ? null : document,
  win = typeof window === "undefined" ? null : window,
  now = () => Date.now(),
}) {
  const esc = ctx.esc;

  let available = false;
  let open = false;
  let query = "";
  let items = [];
  let groups = [];
  let flat = [];
  let activeIndex = 0;
  let overview = null;
  let overviewAt = 0;
  let overviewPending = null;
  let restoreFocusTo = null;

  root.className = "cmdk";
  root.hidden = true;
  root.innerHTML =
    '<div class="cmdk__scrim" data-cmdk-scrim></div>' +
    '<div class="cmdk__panel" role="dialog" aria-modal="true" aria-label="Command palette">' +
    '<div class="cmdk__prompt">' +
    '<span class="cmdk__caret" aria-hidden="true">&gt;</span>' +
    '<input class="cmdk__input" data-cmdk-input type="text" autocomplete="off" ' +
    'autocorrect="off" autocapitalize="off" spellcheck="false" role="combobox" ' +
    'aria-expanded="true" aria-controls="cmdk-list" aria-autocomplete="list" ' +
    'placeholder="Jump to a screen, find a metric, or run an action…" />' +
    '<kbd class="cmdk__esc" aria-hidden="true">esc</kbd>' +
    "</div>" +
    '<div class="cmdk__list" id="cmdk-list" role="listbox" aria-label="Results" data-cmdk-list></div>' +
    '<div class="cmdk__foot" aria-hidden="true">' +
    '<span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>' +
    "<span><kbd>↵</kbd> open</span>" +
    "<span><kbd>esc</kbd> close</span>" +
    "</div></div>";

  const input = root.querySelector("[data-cmdk-input]");
  const list = root.querySelector("[data-cmdk-list]");

  // -- rendering ------------------------------------------------------------

  function rowHtml(item, index) {
    const active = index === activeIndex;
    const value = item.value
      ? '<span class="cmdk__value num">' + esc(item.value) + "</span>"
      : "";
    const hint =
      !item.value && item.hint
        ? '<span class="cmdk__hint">' + esc(item.hint) + "</span>"
        : "";
    return (
      '<div class="cmdk__row' +
      (active ? " is-active" : "") +
      '" role="option" id="cmdk-opt-' +
      index +
      '" aria-selected="' +
      (active ? "true" : "false") +
      '" data-cmdk-index="' +
      index +
      '">' +
      '<span class="cmdk__label">' +
      esc(item.label) +
      "</span>" +
      value +
      hint +
      "</div>"
    );
  }

  function paint() {
    if (flat.length === 0) {
      list.innerHTML =
        '<div class="cmdk__empty">No screen, metric, or action matches that.</div>';
      input.removeAttribute("aria-activedescendant");
      return;
    }
    let index = 0;
    let html = "";
    for (const group of groups) {
      html += '<div class="cmdk__group">' + esc(group.group) + "</div>";
      for (const item of group.items) html += rowHtml(item, index++);
    }
    list.innerHTML = html;
    input.setAttribute("aria-activedescendant", "cmdk-opt-" + activeIndex);
    const active = list.querySelector(".cmdk__row.is-active");
    if (active && typeof active.scrollIntoView === "function") {
      active.scrollIntoView({ block: "nearest" });
    }
  }

  function recompute({ resetActive = true } = {}) {
    items = buildPaletteItems({
      navigation: navigation(),
      allowedScreens: allowedScreens(),
      capabilities: (ctx.identity && ctx.identity.capabilities) || {},
      overview,
    });
    groups = rankItems(items, query);
    flat = flattenGroups(groups);
    if (resetActive || activeIndex >= flat.length) activeIndex = 0;
    paint();
  }

  // -- live metrics ---------------------------------------------------------

  /**
   * Fetch the overview once per open (cached briefly). Failure is silent by
   * design: the palette is a navigation surface first, and an unreachable
   * metrics endpoint must not cost the user their keyboard shortcut.
   */
  function loadOverview() {
    if (overview && now() - overviewAt < OVERVIEW_TTL_MS) return;
    if (overviewPending) return;
    overviewPending = ctx.api
      .get("/v1/admin/overview")
      .then((data) => {
        overview = data && typeof data === "object" ? data : null;
        overviewAt = now();
        if (open) recompute({ resetActive: false });
      })
      .catch(() => {
        // Brownout: screens and actions still list.
      })
      .finally(() => {
        overviewPending = null;
      });
  }

  // -- open / close ---------------------------------------------------------

  /**
   * The dialog is modal, so everything behind the scrim is made inert while it
   * is open - otherwise a screen reader or a Tab could still reach the rail and
   * the stage underneath.
   */
  function setBackgroundInert(inert) {
    if (!doc) return;
    for (const selector of [".app", ".assistant-dock"]) {
      const el = doc.querySelector(selector);
      if (el) el.inert = inert;
    }
  }

  function show() {
    if (!available || open) return;
    open = true;
    restoreFocusTo = doc && doc.activeElement;
    root.hidden = false;
    root.classList.add("is-open");
    query = "";
    input.value = "";
    recompute();
    loadOverview();
    setBackgroundInert(true);
    input.focus();
  }

  function hide() {
    if (!open) return;
    open = false;
    root.hidden = true;
    root.classList.remove("is-open");
    setBackgroundInert(false);
    if (restoreFocusTo && typeof restoreFocusTo.focus === "function") {
      restoreFocusTo.focus({ preventScroll: true });
    }
    restoreFocusTo = null;
  }

  function move(delta) {
    if (flat.length === 0) return;
    activeIndex = (activeIndex + delta + flat.length) % flat.length;
    paint();
  }

  function run(index) {
    const item = flat[index];
    if (!item) return;
    hide();
    const perform = item.perform ?? {};
    if (perform.type === "screen") {
      if (!allowedScreens().has(perform.screen)) return; // stale row, re-guarded
      ctx.go(perform.screen);
      return;
    }
    if (perform.type === "signout") {
      if (typeof onSignOut === "function") onSignOut();
      return;
    }
    if (perform.type && typeof onAction === "function") onAction(perform.type);
  }

  // -- wiring ---------------------------------------------------------------

  input.addEventListener("input", () => {
    query = input.value;
    recompute();
  });

  root.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      hide();
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      activeIndex = 0;
      paint();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      activeIndex = Math.max(0, flat.length - 1);
      paint();
      return;
    }
    if (event.key === "Tab") {
      // The dialog is a single focus stop; Tab cycles the list instead of
      // escaping into the page behind the scrim.
      event.preventDefault();
      move(event.shiftKey ? -1 : 1);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      run(activeIndex);
    }
  });

  root.addEventListener("click", (event) => {
    if (event.target.closest("[data-cmdk-scrim]")) {
      hide();
      return;
    }
    const row = event.target.closest("[data-cmdk-index]");
    if (!row) return;
    run(Number(row.getAttribute("data-cmdk-index")));
  });

  root.addEventListener("mousemove", (event) => {
    const row = event.target.closest("[data-cmdk-index]");
    if (!row) return;
    const next = Number(row.getAttribute("data-cmdk-index"));
    if (next === activeIndex || Number.isNaN(next)) return;
    activeIndex = next;
    paint();
  });

  const onGlobalKeydown = (event) => {
    if (!isPaletteShortcut(event, win && win.navigator)) return;
    event.preventDefault();
    if (open) hide();
    else show();
  };
  if (doc) doc.addEventListener("keydown", onGlobalKeydown);

  return {
    open: show,
    close: hide,
    isOpen: () => open,
    /** Mirrors the assistant dock: hidden while the setup gate is locked. */
    setAvailable(next) {
      available = Boolean(next);
      if (!available) hide();
      for (const trigger of doc ? doc.querySelectorAll("[data-cmdk-open]") : []) {
        trigger.hidden = !available;
      }
    },
    destroy() {
      if (doc) doc.removeEventListener("keydown", onGlobalKeydown);
    },
  };
}
