import { organizationScopeLabel, personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";
import { metricCard as stat } from "../metric-card.js";

// S2 - Home / overview: the company-wide usage dashboard.
//
// 2026-08 redesign. Home is now five stat tiles and five cards, in this order:
//
//   head
//   -> stat row      [Assistant spend · Seats · Saved knowledge · Sources · Queries]
//   -> Memory health (readiness score + banded pillar breakdown)
//   -> Top teams | Top individuals & agents      (paged, 3 rows a page)
//   -> Memory lookups | Access safety
//   -> Halofy Assistant billing & limits
//
// The old per-model, per-source and activity-breakdown cards moved off Home
// entirely: model profiles live on S12, sources on S6, query categories and
// the full ledger on S15 (the "View all in Usage analytics" link). The old
// standalone attention card is gone too - the same signals are now carried by
// the card they belong to (a pending escalation shows inside Access safety, a
// cap breach inside Halofy Assistant billing & limits), so nothing that used to warn an
// operator stopped warning them.
//
// The 7/30/90 control at the head is the screen's ONE window: it is sent to
// /v1/admin/overview as `?days=`, so every activity figure below (leaderboards,
// writes, lookups, queries, saved knowledge) is counted over that window rather
// than all-time. "Overall" sends no `days` and keeps the all-time read. What
// the window deliberately does NOT move is inventory and billing — connected
// sources, seats, the Overview card's skills/channels/agents/policies/conflicts
// counts, memory health, and month-to-date spend describe the org as it stands
// now. Windowed tiles say which window they used.
//
// Reads GET /v1/admin/overview[?days=7|30|90]:
//   { namespace, children:[{namespace,l2Active}], l2Active, faultCount,
//     faultHitRate, spend:{monthToDateUsd, effectiveCapUsd|null},
//     assembledTokens,
//     usage:{totalTokens,totalUsd},
//     models:[...], sourcesSummary:{connectedCount,connected:[...],top:[...]},
//     topTeams:[{name,count}], topActors:[{name,count}],
//     queryCategories:[{category,count}],
//     querySummary:{total,hits,misses,hitRate,topQueries:[{query,count}]},
//     agentAccess:{totalAgents,withinPolicy,overreaching:[{actor,denied}],
//                  accessEvents:{allowed,denied,error},
//                  accessRequests:{pending,approved,denied,expired,consumed}} }
//
// plus OPTIONAL reads, each fetched defensively so an older server - or a
// role the route refuses - loses one tile or one line, never the dashboard:
//   GET /v1/admin/readiness                     -> Memory health card
//   GET /v1/admin/usage                         -> effective + own monthly cap
//   GET /v1/admin/people                        -> seat count + agent badges
//   GET /v1/admin/usage/queries?days=&limit=    -> recent query text
//   GET /v1/admin/usage/ai-rollup?days=&groupBy -> assistant turns in-window
//   GET /v1/admin/usage/ai-rollup?period=month  -> Assistant-only billing MTD
//   GET /v1/copilot/conversations(+ detail)     -> signed-in actor's questions
//
// `people` is owner/admin/auditor-only (a member is refused at the transport):
// without it the Seats tile is omitted and the individuals/agents toggle
// collapses to one combined leaderboard rather than guessing which caller is
// a machine.
//
// Every interpolated API value passes through ctx.esc() before entering HTML.
// The screen's only interactions dispatch through the delegated `actions` map
// at the bottom of this file - no inline JS, no per-render listeners.

/** Leaderboard rows shown per page (both leaderboards). */
const PAGE_SIZE = 3;

/**
 * Window for the two windowed reads (recent queries, assistant turns). Home's
 * own figures are all-time, so anything sourced from a window is labelled with
 * that window rather than presented as an all-time total.
 */
const WINDOW_DAYS = 90;

/** Stable internal correlation refs are never useful human-facing questions. */
const INTERNAL_ASSISTANT_TURN = /^assistant-turn:[0-9A-HJKMNP-TV-Z]{26}$/i;

// ---------------------------------------------------------------------------
// Module state. Survives the ctx.refresh() re-render that follows every
// action; the pagers are clamped against the freshly fetched rows each render,
// so a page that no longer exists collapses back into range instead of
// rendering blank.
//
// cleanup() below therefore does NOT reset any of it. app.js runs cleanup()
// immediately before re-rendering the SAME screen in place (see
// renderRefreshedScreen), so a cleanup that reset the range would throw away
// the click that triggered the refresh — every range/filter/page action would
// repaint as "Overall / Individuals / page 1". S3 documents the same rule for
// the same reason. A genuinely new ctx (a different session) still resets,
// through ensureHomeContext.
// ---------------------------------------------------------------------------

/** Home range and merged-query-card state survive in-place refreshes. */
let homeRange = "overall";
let queryFilter = "individuals";
let queryPage = 0;
let homeContext = null;

function ensureHomeContext(ctx) {
  if (homeContext === ctx) return;
  homeContext = ctx;
  homeRange = "overall";
  queryFilter = "individuals";
  queryPage = 0;
  clearHomeReadCache();
}

// ---------------------------------------------------------------------------
// Read cache. Home issues nine reads; only four of them depend on the
// reporting window, and paging/filtering the leaderboard depends on none of
// them. Without a cache every range click, page click and filter change paid
// for all nine round trips, which is what made the control feel dead.
//
// Two buckets, both short-lived: the window-independent reads are shared by
// every range, and the windowed reads are kept per range so switching back to
// a range you already looked at repaints from memory.
// ---------------------------------------------------------------------------

/** How long a cached read stays good. Home is a dashboard, not a live tail. */
const READ_CACHE_TTL_MS = 60_000;

let sharedReadCache = null; // { at, reads }
let rangeReadCache = new Map(); // range -> { at, reads }

function clearHomeReadCache() {
  sharedReadCache = null;
  rangeReadCache = new Map();
}

/** The cached reads, or null once they are older than the TTL. */
function freshReads(entry) {
  return entry && Date.now() - entry.at < READ_CACHE_TTL_MS ? entry.reads : null;
}

/**
 * The four reads the reporting window actually changes. Every one settles on
 * its own so a single refusal or older-server 404 costs one tile, never the
 * dashboard.
 */
async function windowedReads(ctx, range, rangeDays) {
  const [overviewRes, recentRes, rangeRollupRes, turnsRes] = await Promise.allSettled([
    ctx.api.get(
      range === "overall"
        ? "/v1/admin/overview"
        : "/v1/admin/overview?days=" + rangeDays,
    ),
    ctx.api.get("/v1/admin/usage/queries?days=" + rangeDays + "&limit=8"),
    ctx.api.get("/v1/admin/usage/rollup?days=" + rangeDays + "&groupBy=team"),
    ctx.api.get("/v1/admin/usage/ai-rollup?days=" + rangeDays + "&groupBy=team"),
  ]);
  return { overviewRes, recentRes, rangeRollupRes, turnsRes };
}

function canReadAdminHomeDetails(ctx) {
  const identity = ctx && ctx.identity ? ctx.identity : {};
  return identity.role !== "member" ||
    (Array.isArray(identity.entitlements) && identity.entitlements.includes("audit:read"));
}

/** The reads the window never changes — fetched once, shared by every range. */
async function windowIndependentReads(ctx) {
  // Memory Health reads from /v1/admin/readiness — the card is rendered from
  // the readiness pillars alone, so there is no separate health read to make.
  // Ordinary members are denied the first three routes server-side. Preserve
  // their existing Unavailable cards without paying three guaranteed 403s.
  const canReadAdminDetails = canReadAdminHomeDetails(ctx);
  const denied = () => Promise.reject({ status: 403, message: "forbidden" });
  // Boot starts this directory request as soon as identity is known. Folding
  // the same promise into Home's existing batch preserves people-card failure
  // semantics while overlapping it with readiness, usage, and rollup reads.
  const initialPeople = ctx.initialPeopleDirectoryRequest;
  const [readinessRes, usageRes, peopleRes, assistantMonthRes, assistantQuestionsRes] =
    await Promise.allSettled([
      canReadAdminDetails ? ctx.api.get("/v1/admin/readiness") : denied(),
      canReadAdminDetails ? ctx.api.get("/v1/admin/usage") : denied(),
      canReadAdminDetails
        ? initialPeople ?? ctx.api.get("/v1/admin/people")
        : denied(),
      ctx.api.get("/v1/admin/usage/ai-rollup?period=month&groupBy=sourceApp"),
      loadOwnAssistantQuestions(ctx),
    ]);
  return {
    readinessRes,
    usageRes,
    peopleRes,
    assistantMonthRes,
    assistantQuestionsRes,
  };
}

/**
 * @param {import('../app.js').Ctx} ctx
 * @returns {Promise<string>}
 */
export async function render(ctx) {
  ensureHomeContext(ctx);
  const { esc, ui } = ctx;

  // One window drives the whole screen. `overall` keeps the historical
  // all-time overview read (no `days`), while the windowed reads below still
  // need a concrete day count, so they fall back to WINDOW_DAYS.
  const rangeDays = homeRange === "overall" ? WINDOW_DAYS : Number(homeRange);
  // Every activity figure on this screen is counted over this window, so it is
  // named on the tiles rather than left to the control at the top of the page.
  const windowTag = overviewRangeTag(homeRange);

  // Both groups start together, so the screen costs ONE round trip rather than
  // a blocking overview read followed by a second wave. Anything already
  // cached resolves immediately and is awaited alongside the rest.
  const cachedShared = freshReads(sharedReadCache);
  const cachedRange = freshReads(rangeReadCache.get(homeRange));
  const [shared, ranged] = await Promise.all([
    cachedShared ?? windowIndependentReads(ctx),
    cachedRange ?? windowedReads(ctx, homeRange, rangeDays),
  ]);
  if (!cachedShared) sharedReadCache = { at: Date.now(), reads: shared };
  // A refused window must be retried on the next click, never remembered.
  if (!cachedRange && ranged.overviewRes.status === "fulfilled") {
    rangeReadCache.set(homeRange, { at: Date.now(), reads: ranged });
  }

  if (ranged.overviewRes.status === "rejected") {
    // The head (and with it the range control) survives a failed read, so a
    // window the server cannot serve is always one click away from one it can.
    const err = ranged.overviewRes.reason;
    return homeOverview(
      homeHead(
        organizationScopeLabel(
          ctx.identity?.namespace ?? "",
          ctx.organizationName,
          ctx.identity?.namespace,
        ),
        homeRange,
        esc,
      ) +
        ui.empty(
          "Overview is unavailable right now" +
            (err && err.message ? ": " + esc(err.message) : "."),
        ),
    );
  }
  const ov = ranged.overviewRes.value;
  const readiness = valueOf(shared.readinessRes);
  const usageBilling = valueOf(shared.usageRes);
  const people = valueOf(shared.peopleRes);
  const assistantMonth = valueOf(shared.assistantMonthRes);
  const assistantQuestions = valueOf(shared.assistantQuestionsRes);
  const recent = valueOf(ranged.recentRes);
  const rangeRollup = valueOf(ranged.rangeRollupRes);
  const turns = valueOf(ranged.turnsRes);

  const namespace = ov && ov.namespace ? String(ov.namespace) : "";
  const l2Active = num(ov && ov.l2Active);
  const faultCount = num(ov && ov.faultCount);
  const faultHitRate = num(ov && ov.faultHitRate); // 0..1

  const usage = (ov && ov.usage) || {};
  const totalTokens = num(usage.totalTokens);
  const assistantSpend = assistantSpendView(homeRange === "overall" ? assistantMonth : turns);
  const sourcesSummary = (ov && ov.sourcesSummary) || {};
  const connectedCount = num(sourcesSummary.connectedCount);
  const connectedSources = Array.isArray(sourcesSummary.connected)
    ? sourcesSummary.connected
    : [];
  const topTeams = Array.isArray(ov && ov.topTeams) ? ov.topTeams : [];
  const topActors = Array.isArray(ov && ov.topActors) ? ov.topActors : [];
  const querySummary = (ov && ov.querySummary) || {};
  const rangeTotals = homeRange !== "overall" && rangeRollup && rangeRollup.totals
    ? rangeRollup.totals
    : null;
  const queryTotal = rangeTotals ? num(rangeTotals.queries) : num(querySummary.total);
  const topQueries = Array.isArray(querySummary.topQueries)
    ? querySummary.topQueries
    : [];
  const memoryWrites = ov && ov.memoryWrites ? ov.memoryWrites : { total: 0, teams: [] };
  const homeCounts = ov && ov.homeCounts ? ov.homeCounts : {};

  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const healthHtml = memoryHealthCard(readiness, ctx);

  // --- stat row -------------------------------------------------------------
  // "Overall queries" is every memory call in the audit trail: both
  // leaderboards bucket exactly those rows, so either sum is the same total.
  // querySummary counts only the purpose-carrying subset, so it is the
  // last-resort figure rather than the first.
  const totalCalls =
    sumCounts(topTeams) || sumCounts(topActors) || queryTotal || faultCount;
  const answeredPct = Math.round(
    (queryTotal > 0 ? num(querySummary.hitRate) : faultHitRate) * 100,
  );
  const seats = seatCount(people);

  const stats =
    '<div class="home-metrics" role="list" aria-label="Organization summary">' +
    stat({
      k: "Assistant Spend",
      v: assistantSpend.value,
      foot: assistantSpend.tooltip,
      icon: "spend",
      metric: true,
    }) +
    stat({
      k: "Overall Queries",
      v: fmt(totalCalls),
      foot:
        totalCalls === 0
          ? "no memory calls " + (homeRange === "overall" ? "yet" : "in this range")
          : answeredPct + "% answered from memory · " + windowTag,
      icon: "query",
      metric: true,
    }) +
    (seats === null
      ? ""
      : stat({
          k: "Seats",
          v: fmt(seats),
          foot: "users across the org",
          icon: "people",
          metric: true,
        })) +
    stat({
      k: "Saved Knowledge",
      v: fmt(l2Active),
      // Windowed, this counts what was SAVED in the range rather than
      // everything the org can read — say so instead of reusing the
      // all-time wording for a smaller number.
      foot:
        homeRange === "overall"
          ? "Available to " + esc(nsLabel)
          : "saved " + windowTag + " · available to " + esc(nsLabel),
      icon: "memory",
      metric: true,
    }) +
    stat({
      k: "Connected Sources",
      v: fmt(connectedCount),
      foot:
        connectedCount === 0
          ? "no sources connected yet"
          : topSourceKinds(connectedSources, esc),
      icon: "source",
      metric: true,
    }) +
    "</div>";

  // --- merged Top Memory Queries -------------------------------------------
  const agents = agentDirectory(people);
  const individualRows = agents
    ? topActors.filter((r) => !agents.has(actorKey(r)))
    : topActors;
  const agentRows = agents
    ? topActors.filter((r) => agents.has(actorKey(r)))
    : [];
  if (agents === null && queryFilter === "agents") queryFilter = "individuals";
  const queryRows = queryFilter === "teams"
    ? topTeams
    : queryFilter === "agents"
      ? agentRows
      : individualRows;
  const showingAgents = queryFilter === "agents";
  const showingTeams = queryFilter === "teams";
  queryPage = clampPage(queryPage, queryRows.length);
  const queryNoun = showingTeams
    ? queryRows.length === 1 ? "team" : "teams"
    : showingAgents
      ? queryRows.length === 1 ? "agent" : "agents"
      : queryRows.length === 1 ? "person" : "people";
  const queryFilterLabel = showingTeams ? "Teams" : showingAgents ? "Agents" : "Individuals";
  const queryFilterMenu =
    '<div class="home-query-filter-wrap"><button class="home-query-filter-button" type="button" data-action="home-query-filter-toggle" aria-controls="home-query-filter-menu" aria-haspopup="menu" aria-expanded="false" aria-label="Filter Top Memory Queries: ' + queryFilterLabel + '">' +
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 6h16M7 12h10M10 18h4" stroke-linecap="round"/></svg></button>' +
    '<div id="home-query-filter-menu" class="home-query-filter-menu" role="menu" hidden>' +
    queryFilterOption("individuals", "Individuals", queryFilter) +
    (agents === null ? "" : queryFilterOption("agents", "Agents", queryFilter)) +
    queryFilterOption("teams", "Teams", queryFilter) +
    "</div></div>";
  const topQueriesCard =
    '<div class="card home-panel home-top-queries"><div class="between home-panel-head home-top-queries-head"><h3>Top Memory Queries</h3>' +
    queryFilterMenu + "</div>" +
    leaderboardRows({
      rows: queryRows,
      page: queryPage,
      max: maxCount(queryRows),
      tags: showingAgents ? agents : null,
      empty:
        homeRange === "overall"
          ? "No memory queries recorded yet."
          : "No memory queries in the " + windowTag + ". Try a wider range.",
      avatar: showingTeams ? "team" : showingAgents ? "agent" : "person",
      esc,
      personLabel: ctx.personLabel,
      personAvatarUrl: showingTeams || showingAgents ? null : ctx.personAvatarUrl,
    }) +
    pager({ list: "queries", page: queryPage, total: queryRows.length, noun: queryNoun, esc }) +
    "</div>";

  // --- memory lookups -------------------------------------------------------
  const hits = rangeTotals && rangeTotals.hitRate != null
    ? Math.round(queryTotal * num(rangeTotals.hitRate))
    : num(querySummary.hits);
  const misses = rangeTotals ? Math.max(0, queryTotal - hits) : num(querySummary.misses);
  const assistantTurns = turnCount(turns);
  const recentQueries = recentQueryList(recent, topQueries, assistantQuestions);
  const lookupsCard =
    '<div class="card home-panel home-lookups"><div class="between home-panel-head"><h3>Memory Lookups</h3></div>' +
    '<div class="home-card-body">' +
    '<div class="home-lookup-pills">' +
    lookupSummaryBox(hits, "Answered", queryTotal > 0 ? "ok" : undefined, fmt(hits) + " memory lookups answered", esc) +
    lookupSummaryBox(misses, "Missed", misses > 0 ? "warn" : undefined, fmt(misses) + " memory lookups missed", esc) +
    (assistantTurns === null
      ? ""
      : lookupSummaryBox(
          assistantTurns,
          "Turns",
          undefined,
          fmt(assistantTurns) + " assistant turns · " + rangeTag(homeRange),
          esc,
        )) +
    "</div>" +
    (recentQueries.rows.length === 0
      ? '<div class="subtle home-text-sm home-lookups-empty">' +
        (homeRange === "overall"
          ? "No queries recorded yet."
          : "No queries in the " + windowTag + ". Try a wider range.") +
        "</div>"
      : '<div class="home-recent-queries-label">' +
        recentQueries.legend +
        "</div>" +
        '<div class="home-recent-queries">' +
        recentQueries.rows
          .map(function (q) {
            return (
              '<div class="home-query-bubble">' +
              '<span class="home-query-bubble-copy">' +
              '<span class="home-query-bubble-label">' + esc(q.label) + "</span>" +
              '<span class="home-query-bubble-text">' + esc(q.text) + "</span>" +
              "</span>" +
              (q.count > 1
                ? '<span class="num subtle">×' + fmt(q.count) + "</span>"
                : "") +
              "</div>"
            );
          })
          .join("") +
        "</div>") +
    "</div>" +
    '<div class="home-card-foot">' +
    goBtn("s15", "View all in Usage analytics →") +
    "</div></div>";

  const writesCard = memoryWritesCard(memoryWrites, ctx, homeRange);
  const summaryCard = overviewCard(homeCounts, ctx);

  return homeOverview(
    homeHead(nsLabel, homeRange, esc) +
      stats +
      '<div class="home-dashboard">' +
      healthHtml +
      writesCard +
      summaryCard +
      topQueriesCard +
      lookupsCard +
      usageCard(usageBilling, ov, assistantMonth, ctx) +
      "</div>",
  );
}

// --- local helpers (all data already esc()'d by callers; these format only) ---

/** Scope Home-only presentation rules without changing the shared console shell. */
function homeOverview(content) {
  return '<div class="home-overview"><div class="screen-flow">' + content + "</div></div>";
}

function homeHead(namespaceLabel, activeRange, esc) {
  return '<div class="head home-head"><div><div class="eyebrow">Operate · ' +
    esc(namespaceLabel) + '</div><h1>Everything, At A Glance</h1></div>' +
    '<div class="acts home-head-actions">' + rangeControl(activeRange) + "</div></div>";
}

/** The value of a settled promise, or null when it rejected / came back empty. */
function valueOf(settled) {
  return settled && settled.status === "fulfilled" && settled.value
    ? settled.value
    : null;
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Group-separated integer (or 1-decimal for fractional). Safe: numeric only. */
function fmt(n) {
  const x = Number(n) || 0;
  if (Number.isInteger(x)) return x.toLocaleString("en-US");
  return x.toLocaleString("en-US", { maximumFractionDigits: 1 });
}

/** Dollar-formatted amount with cents. Safe: numeric only. */
function fmtUsd(n) {
  const x = Number(n) || 0;
  return (
    "$" +
    x.toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })
  );
}

/**
 * Truthful Halofy Assistant billing projection. The rollup deliberately
 * excludes external hosts and returns `totalUsd` null when any included turn is
 * unpriced; Home must preserve that unknown instead of formatting it as $0.00.
 *
 * Three states, the same ones the S15 AI-spend tile paints (the AI spend floor,
 * CONTRACTS-USAGE-ANALYTICS 2026-08-05): the bill when every turn priced,
 * `pricedUsd` + " so far" when only some did, and Unavailable when nothing
 * priced. A single model without a catalog price used to blank the whole card,
 * which threw away every priced turn in the month and read as an outage.
 */
function assistantSpendView(rollup) {
  const totals = rollup && rollup.totals ? rollup.totals : null;
  const missing = totals ? num(totals.unavailableCostTurns) : 0;
  const rawUsd = totals ? totals.totalUsd : null;
  const complete = typeof rawUsd === "number" && Number.isFinite(rawUsd) && missing === 0;
  const tokens = totals ? num(totals.inputTokens) + num(totals.outputTokens) : 0;
  const turns = totals ? num(totals.turns) : 0;
  const pricedTurns = totals ? num(totals.pricedTurns) : 0;
  const pricedUsd = totals ? totals.pricedUsd : null;
  const hasFloor =
    !complete &&
    pricedTurns > 0 &&
    typeof pricedUsd === "number" &&
    Number.isFinite(pricedUsd);
  if (complete) {
    return {
      available: true,
      floor: false,
      value: fmtUsd(rawUsd),
      tooltip: fmt(tokens) + " model tokens · Halofy Assistant only; external AI tools are not included.",
    };
  }
  if (hasFloor) {
    return {
      available: false,
      floor: true,
      value: fmtUsd(pricedUsd) + " so far",
      tooltip:
        fmt(pricedTurns) + " of " + fmt(turns) + " Assistant turns priced · " +
        fmt(missing) + " " + (missing === 1 ? "has" : "have") +
        " no catalog price, so the real amount is higher. External AI tools are not included.",
    };
  }
  const missingCopy = missing > 0
    ? missing + " Assistant " + (missing === 1 ? "turn is" : "turns are") + " missing prices. "
    : "Halofy Assistant billing is unavailable right now. ";
  return {
    available: false,
    floor: false,
    value: "Unavailable",
    tooltip: missingCopy + "External AI tools are not included.",
  };
}

/** A thin usage bar scaled against the section max. Numeric-only input. */
function bar(value, max) {
  const pct = max > 0 ? Math.max(4, Math.round((num(value) / max) * 100)) : 0;
  return (
    '<div style="height:3px;border-radius:2px;background:color-mix(in srgb, currentColor 12%, transparent);margin-top:5px;overflow:hidden">' +
    '<div style="height:100%;width:' +
    pct +
    '%;border-radius:2px;background:var(--sage, #7c9082)"></div></div>'
  );
}

/** Sum of a leaderboard's counts (0 for an absent/empty list). */
function sumCounts(rows) {
  return (Array.isArray(rows) ? rows : []).reduce(function (n, r) {
    return n + num(r && r.count);
  }, 0);
}

/** Largest count in a leaderboard, for the shared bar scale. */
function maxCount(rows) {
  return (Array.isArray(rows) ? rows : []).reduce(function (m, r) {
    return Math.max(m, num(r && r.count));
  }, 0);
}

/** A leaderboard row's actor key (the audit `actor`, never a display string). */
function actorKey(row) {
  return row && row.name ? String(row.name) : "";
}

/** Keep a stored page inside the range the freshly fetched rows support. */
function clampPage(page, total) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const p = Number.isFinite(page) ? Math.floor(page) : 0;
  return Math.min(Math.max(0, p), pages - 1);
}

/** Distinct kinds of the connected sources, e.g. "notion, slack, postgres". */
function topSourceKinds(connected, esc) {
  const kinds = [];
  for (const s of connected) {
    const kind = s && s.kind ? String(s.kind) : "";
    if (kind && kinds.indexOf(kind) < 0) kinds.push(kind);
    if (kinds.length === 3) break;
  }
  return esc(kinds.join(", "));
}

/**
 * Seats = the human users the organization directory returns. Null when
 * /v1/admin/people is unavailable (an older server, or a member role the
 * transport refuses) - the tile is then omitted rather than guessed.
 */
function seatCount(people) {
  const users = people && Array.isArray(people.users) ? people.users : null;
  if (!users) return null;
  return users.filter(function (u) {
    const status = u && u.status ? String(u.status) : "active";
    return status !== "revoked" && status !== "disabled" && status !== "removed";
  }).length;
}

/**
 * actor -> short tag for every ACTIVE agent badge, so the leaderboard can be
 * split into people and machines from real credentials instead of a guess at
 * the shape of a name. Null when /v1/admin/people is unavailable.
 */
function agentDirectory(people) {
  const badges = people && Array.isArray(people.badges) ? people.badges : null;
  if (!badges) return null;
  const map = new Map();
  for (const b of badges) {
    if (!b || String(b.role || "") !== "agent") continue;
    if (String(b.status || "active") === "revoked") continue;
    const actor = b.actor ? String(b.actor) : "";
    if (!actor || map.has(actor)) continue;
    const description = b.description ? String(b.description) : "";
    const namespace = b.namespace ? String(b.namespace) : "";
    map.set(actor, description || namespace || "agent");
  }
  return map;
}

/** Assistant turns inside the window, or null when the rollup is unavailable. */
function turnCount(turnsRollup) {
  const totals = turnsRollup && turnsRollup.totals ? turnsRollup.totals : null;
  if (!totals || totals.turns === undefined || totals.turns === null) return null;
  return num(totals.turns);
}

/**
 * The query bubbles. Prefers the real recency of the usage ledger; falls back
 * to the overview's most-asked list, and says which of the two it is showing
 * rather than labelling a ranking as history.
 */
function recentQueryList(recent, topQueries, assistantQuestions) {
  const seen = new Set();
  const rows = [];
  let hasAssistantQuestion = false;
  let hasAgentSummary = false;
  const add = function (textValue, label, count) {
    const text = String(textValue || "").replace(/\s+/g, " ").trim();
    if (!text || INTERNAL_ASSISTANT_TURN.test(text) || seen.has(text)) return;
    seen.add(text);
    rows.push({ text, label, count: num(count) || 1 });
  };

  for (const question of Array.isArray(assistantQuestions) ? assistantQuestions : []) {
    add(question && question.text, "Your Assistant question", 1);
    hasAssistantQuestion = rows.length > 0;
    if (rows.length === 3) break;
  }

  const queries = recent && Array.isArray(recent.queries) ? recent.queries : null;
  if (queries && rows.length < 3) {
    for (const q of queries) {
      const external = q && (q.principal === "agent" || q.callerClass === "external");
      const before = rows.length;
      add(q && q.summary, external ? "External agent summary" : "Memory lookup", 1);
      if (external && rows.length > before) hasAgentSummary = true;
      if (rows.length === 3) break;
    }
  }

  if (rows.length > 0) {
    const legend = hasAssistantQuestion && hasAgentSummary
      ? "Recent questions and summaries"
      : hasAssistantQuestion
        ? "Recent Assistant questions"
        : "Recent lookup summaries";
    return { legend, rows };
  }

  for (const q of Array.isArray(topQueries) ? topQueries : []) {
    add(q && q.query, "Memory lookup", q && q.count);
    if (rows.length === 3) break;
  }
  return { legend: "Most asked", rows };
}

/**
 * Load only the signed-in actor's encrypted Assistant history. The existing
 * conversation API enforces exact (namespace, actor) ownership, so Home can
 * show the user's own words without widening organization oversight into
 * transcript access.
 */
async function loadOwnAssistantQuestions(ctx) {
  const list = await ctx.api.get("/v1/copilot/conversations?limit=3&offset=0");
  const conversations = list && Array.isArray(list.conversations)
    ? list.conversations.slice(0, 3)
    : [];
  if (conversations.length === 0) return [];
  const details = await Promise.allSettled(
    conversations.map(function (conversation) {
      const id = conversation && conversation.id ? String(conversation.id) : "";
      if (!id) return Promise.reject(new Error("invalid conversation"));
      return ctx.api.get("/v1/copilot/conversations/" + encodeURIComponent(id));
    }),
  );
  const seen = new Set();
  const questions = [];
  for (const detail of details) {
    if (detail.status !== "fulfilled" || !detail.value || !Array.isArray(detail.value.messages)) continue;
    const messages = detail.value.messages;
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index];
      const text = message && message.role === "user" && message.text
        ? String(message.text).replace(/\s+/g, " ").trim()
        : "";
      if (!text || seen.has(text)) continue;
      seen.add(text);
      questions.push({ text });
      if (questions.length === 3) return questions;
    }
  }
  return questions;
}

/** One page of leaderboard rows: name (+ optional agent tag), count, bar. */
function leaderboardRows(o) {
  const esc = o.esc;
  const rows = Array.isArray(o.rows) ? o.rows : [];
  if (rows.length === 0) {
    return (
      '<div class="subtle home-card-body" style="margin-top:var(--s3)">' +
      o.empty +
      "</div>"
    );
  }
  const start = o.page * PAGE_SIZE;
  return (
    '<div class="home-card-body" style="display:grid;gap:var(--s3);margin-top:var(--s3)">' +
    rows
      .slice(start, start + PAGE_SIZE)
      .map(function (r) {
        const count = num(r && r.count);
        const name = actorKey(r);
        const visibleName = personDisplayName(r, o.personLabel);
        const label = visibleName === "" ? "Organization root" : visibleName;
        const tag = o.tags ? o.tags.get(name) : null;
        return (
          "<div>" +
          '<div class="between" style="gap:var(--s3)">' +
          '<span class="home-leaderboard-identity">' +
          homeAvatar(label, o.avatar || "person", esc, r, o.personAvatarUrl) +
          '<b class="home-text-sm" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
          esc(label) +
          "</b>" +
          (tag ? '<span class="tag">' + esc(tag) + "</span>" : "") +
          "</span>" +
          '<span class="num">' +
          fmt(count) +
          "</span></div>" +
          bar(count, o.max) +
          "</div>"
        );
      })
      .join("") +
    "</div>"
  );
}

function homeAvatar(label, kind, esc, subject, avatarUrl) {
  if (kind === "team") {
    return '<span class="home-avatar home-avatar--team" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg></span>';
  }
  if (kind === "agent") {
    return '<span class="home-avatar home-avatar--agent" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M8 12h.01M16 12h.01M9 16h6" stroke-linecap="round"/></svg></span>';
  }
  const parts = String(label).trim().split(/[\s@._:\/-]+/).filter(Boolean);
  const initials = parts.length > 1
    ? parts[0].slice(0, 1) + parts[1].slice(0, 1)
    : String(label).slice(0, 2);
  const image = typeof avatarUrl === "function" ? avatarUrl(subject) : null;
  return '<span class="home-avatar home-avatar--person" aria-hidden="true">' + (image
    ? '<img class="home-avatar__image" data-person-avatar-image src="' + esc(image) + '" alt="" decoding="async">'
    : esc(initials.toUpperCase())) + "</span>";
}

/** The "1-3 of 5 people" line plus the two page arrows. */
function pager(o) {
  const total = o.total;
  const start = o.page * PAGE_SIZE;
  const end = Math.min(total, start + PAGE_SIZE);
  const label =
    total === 0
      ? "nothing to show"
      : (start + 1 === end ? String(end) : start + 1 + "–" + end) +
        " of " +
        fmt(total) +
        " " +
        o.noun;
  const atStart = o.page === 0;
  const atEnd = end >= total;
  return (
    '<div class="between home-card-foot">' +
    '<span class="subtle home-text-xs">' +
    o.esc(label) +
    "</span>" +
    '<div class="row" style="gap:var(--s2)">' +
    pageBtn(o.list, -1, atStart, "Previous", "M15 6l-6 6 6 6") +
    pageBtn(o.list, 1, atEnd, "Next", "M9 6l6 6-6 6") +
    "</div></div>"
  );
}

/** One page arrow. `list` selects which pager the action advances. */
function pageBtn(list, dir, disabled, label, path) {
  return (
    '<button class="btn btn--ghost btn--sm" type="button" data-action="home-page"' +
    ' data-list="' +
    list +
    '" data-dir="' +
    dir +
    '" aria-label="' +
    label +
    '"' +
    (disabled ? " disabled" : "") +
    '><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true">' +
    '<path d="' +
    path +
    '" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>'
  );
}

/** The Individuals / Agents toggle over the people leaderboard. */
function actorTabs(showingAgents) {
  const tab = function (id, text, active) {
    return (
      '<button class="source-category-tab' +
      (active ? " is-active" : "") +
      '" type="button" data-action="home-actor-tab" data-tab="' +
      id +
      '" aria-pressed="' +
      (active ? "true" : "false") +
      '" style="min-height:30px;padding:4px 12px;font-size:12px">' +
      text +
      "</button>"
    );
  };
  return (
    '<div class="row" style="gap:var(--s2)">' +
    tab("individuals", "Individuals", !showingAgents) +
    tab("agents", "Agents", showingAgents) +
    "</div>"
  );
}

/** Pill tone for a readiness band. */
function bandTone(band) {
  if (band === "excellent" || band === "healthy") return "ok";
  if (band === "fair") return "warn";
  if (band === "at-risk") return "crit";
  return undefined;
}

/** Display label for a readiness band value. */
function bandLabel(band) {
  if (band === "at-risk") return "At risk";
  const s = String(band || "");
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
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
    .replace(/\s*—\s*([a-z])/g, function (_match, letter) {
      return ". " + String(letter).toUpperCase();
    })
    .replace(/\s*—\s*/g, ". ");
}

/**
 * The "Memory health" score card (E43): composite banded score plus the six
 * pillar sub-scores from GET /v1/admin/readiness. Returns "" when the payload
 * is absent or malformed. All API strings pass through esc().
 */
function readinessCard(r, esc, ui) {
  if (!r || !Number.isFinite(Number(r.score)) || !r.band) return "";
  const score = num(r.score);
  const band = String(r.band);
  const pillars = Array.isArray(r.pillars) ? r.pillars : [];
  const trend = r.trend || {};
  const delta = num(trend.deltaPoints);
  const windowDays = num(r.windowDays) || 30;
  const degraded = !!r.degraded;
  const progress = Math.max(0, Math.min(100, score));
  const progressValue = fmt(progress);

  const trendHtml =
    trend.direction === "up"
      ? '<span class="num" style="color:var(--sage)">▲ +' + fmt(delta) + "</span>"
      : trend.direction === "down"
        ? '<span class="num" style="color:var(--rust)">▼ ' + fmt(delta) + "</span>"
        : '<span class="num subtle">flat</span>';

  const pillarRows = pillars
    .map(function (p) {
      const available = !(p && p.available === false);
      const pScore = available ? num(p && p.score) : null;
      const pBand = available && p && p.band ? String(p.band) : null;
      return (
        '<div class="row" style="gap:var(--s3);align-items:center">' +
        '<div style="flex:1;min-width:0"><b>' +
        esc(p && p.label ? String(p.label) : (p && p.id ? String(p.id) : "")) +
        "</b>" +
        (pBand
          ? ' <span class="tag">' + esc(bandLabel(pBand)) + "</span>"
          : available
            ? ""
            : ' <span class="tag">unavailable</span>') +
        '<div class="subtle home-text-xs" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        esc(plainReadinessDetail(p && p.detail)) +
        "</div></div>" +
        '<div style="text-align:right;min-width:90px"><span class="num">' +
        (pScore === null ? "–" : fmt(pScore)) +
        "</span>" +
        bar(pScore === null ? 0 : pScore, 100) +
        "</div></div>"
      );
    })
    .join("");

  return (
    '<div class="card home-panel home-health"><div class="between"><h3>Memory health</h3>' +
    ui.pill(esc(bandLabel(band)), bandTone(band)) +
    "</div>" +
    '<div class="home-health-meter" role="progressbar" aria-label="Memory health score" aria-valuenow="' +
    progressValue +
    '" aria-valuemin="0" aria-valuemax="100" style="--home-health-progress:' +
    progressValue +
    '%"><div class="home-health-meter-head"><span class="home-health-meter-score"><span class="num home-score">' +
    fmt(score) +
    '</span><span class="subtle">/ 100</span></span><span class="home-health-trend">' +
    trendHtml +
    ' <span class="subtle home-text-xs">vs ' +
    fmt(windowDays) +
    'd</span></span></div><div class="home-health-track" aria-hidden="true"><span class="home-health-fill"></span></div></div>' +
    (pillarRows
      ? '<button class="home-health-trigger" type="button" data-action="home-health-open" aria-haspopup="dialog" aria-controls="home-health-drawer" aria-expanded="false">' +
        '<span>Health breakdown</span><span class="home-health-trigger-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="m9 18 6-6-6-6"/></svg></span></button>'
      : "") +
    (degraded
      ? '<div class="subtle home-text-xs" style="margin-top:var(--s3)">Partial data: ' +
        "some pillars were unavailable and their weight was redistributed.</div>"
      : "") +
    "</div>" +
    (pillarRows
      ? '<dialog class="home-health-drawer" id="home-health-drawer" data-home-health-drawer data-action="home-health-backdrop" aria-labelledby="home-health-drawer-title">' +
        '<header class="home-health-drawer-head"><div><span class="eyebrow">Memory health</span><h2 id="home-health-drawer-title">Health breakdown' + headingInfo("Health breakdown", "How freshness, coverage, retrieval, gaps, trust, and structure contribute to this score.") + '</h2></div>' +
        '<button class="home-health-drawer-close" type="button" data-action="home-health-close" aria-label="Close health breakdown and return to Home"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg></button></header>' +
        '<div class="home-health-drawer-body"><div class="home-health-drawer-summary"><span class="num home-score">' + fmt(score) + '</span><span class="subtle">/ 100</span><span style="margin-left:auto">' + ui.pill(esc(bandLabel(band)), bandTone(band)) + '</span></div>' +
        '<div class="home-health-drawer-list">' + pillarRows + "</div></div></dialog>"
      : "")
  );
}

function rangeTag(range) {
  return range === "overall" ? WINDOW_DAYS + "d rolling" : range + "d";
}

/** Compact one-word lookup summary with the fuller context kept accessible. */
function lookupSummaryBox(value, label, kind, accessibleLabel, esc) {
  const cls = kind ? "pill pill--" + kind : "pill";
  return '<span class="' + cls + '" aria-label="' + esc(accessibleLabel) + '"><i class="dot"></i><span class="num">' +
    fmt(value) + "</span> " + label + "</span>";
}

/**
 * Label for the figures that come from the windowed overview read. "Overall"
 * really is all-time there (the read sends no `days`), so it must NOT borrow
 * rangeTag's "90d rolling" wording, which belongs to the two reads that always
 * need a concrete window.
 */
function overviewRangeTag(range) {
  return range === "overall" ? "all time" : "last " + range + "d";
}

/**
 * Paint the pressed range immediately, before the re-render that will paint it
 * again from the fetched data. Pure DOM, defensive: the same action runs under
 * the contract tests against a plain object element.
 */
function pressRangeOption(el) {
  const group = el && el.closest ? el.closest(".home-range-control") : null;
  if (!group || typeof group.querySelectorAll !== "function") return;
  const options = group.querySelectorAll(".home-range-option");
  for (const option of options) {
    const selected = option === el;
    option.classList.toggle("is-active", selected);
    option.setAttribute("aria-pressed", selected ? "true" : "false");
  }
}

function rangeControl(active) {
  const options = [
    ["overall", "Overall"],
    ["7", "7 Days"],
    ["30", "30 Days"],
    ["90", "90 Days"],
  ];
  return '<div class="home-range-control" role="group" aria-label="Home reporting range">' +
    options.map(function (option) {
      const selected = active === option[0];
      return '<button class="btn btn--sm home-range-option' + (selected ? " is-active" : "") +
        '" type="button" data-action="home-range" data-range="' + option[0] +
        '" aria-pressed="' + (selected ? "true" : "false") + '">' + option[1] + "</button>";
    }).join("") + "</div>";
}

function queryFilterOption(id, label, active) {
  const selected = id === active;
  return '<button class="home-query-filter-option" type="button" role="menuitemradio" data-action="home-query-filter" data-filter="' +
    id + '" aria-checked="' + (selected ? "true" : "false") + '"><span>' + label + '</span><span aria-hidden="true">' +
    (selected ? "✓" : "") + "</span></button>";
}

const HEALTH_FACTORS = [
  { id: "validity", pillarId: "trust", label: "Factual Validity", weight: 0.40, tip: "Whether your saved knowledge contradicts itself." },
  { id: "hygiene", pillarId: "structure", label: "Hygiene & Deduplication", weight: 0.25, tip: "How clean the store is." },
  { id: "recency", pillarId: "freshness", label: "Recency & Decay", weight: 0.25, tip: "Whether what we hold is still current." },
  { id: "intake", pillarId: "coverage", label: "Intake Completeness", weight: 0.10, tip: "Whether submitted knowledge actually made it into memory." },
];

function axisScoreBar(value, label) {
  const available = typeof value === "number" && Number.isFinite(value);
  const safe = available ? Math.max(0, Math.min(100, value)) : 0;
  return '<div class="home-factor-chart"><div class="home-factor-track"' +
    (available ? ' role="progressbar" aria-label="' + label + '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + fmt(safe) + '"' : "") +
    '><span style="width:' + safe + '%"></span><i></i><i></i><i></i></div></div>';
}

function memoryHealthCard(readiness, ctx) {
  const esc = ctx.esc;
  const ui = ctx.ui;
  const score = readiness && Number.isFinite(Number(readiness.score)) ? num(readiness.score) : null;
  const band = readiness && readiness.band ? String(readiness.band) : "";
  const progress = score === null ? 0 : Math.max(0, Math.min(100, score));
  const trend = readiness && readiness.trend ? readiness.trend : null;
  const trendWindowDays = trend && Number.isFinite(Number(trend.windowDays))
    ? num(trend.windowDays)
    : readiness && Number.isFinite(Number(readiness.windowDays))
      ? num(readiness.windowDays)
      : null;
  const trendWindow = trendWindowDays === null ? "the prior window" : trendWindowDays + "d";
  const trendHtml = !trend
    ? '<span class="subtle home-text-xs">Trend unavailable</span>'
    : trend.direction === "up"
      ? '<span class="home-health-trend home-health-trend--up">▲ +' + fmt(num(trend.deltaPoints)) + " vs " + trendWindow + "</span>"
      : trend.direction === "down"
        ? '<span class="home-health-trend home-health-trend--down">▼ ' + fmt(num(trend.deltaPoints)) + " vs " + trendWindow + "</span>"
        : '<span class="subtle home-text-xs">Flat vs ' + trendWindow + "</span>";
  // Home's four business labels project the authoritative readiness pillars;
  // a second health endpoint would duplicate ACL, brownout, and trend rules.
  const pillars = readiness && Array.isArray(readiness.pillars) ? readiness.pillars : [];
  const factorRows = HEALTH_FACTORS.map(function (definition) {
    const factor = pillars.find(function (item) { return item && item.id === definition.pillarId; });
    const available = !!factor && factor.available !== false && Number.isFinite(Number(factor.score));
    const factorScore = available ? num(factor.score) : null;
    const factorBand = available && factor.band ? String(factor.band) : "";
    return '<div class="home-factor-row"><div class="home-factor-head"><div class="home-factor-title"><b>' +
      esc(definition.label) + '</b>' +
      (factorBand ? ui.pill(esc(bandLabel(factorBand)), bandTone(factorBand)) : '<span class="tag">Unavailable</span>') +
      headingInfo(definition.label, definition.tip) + '</div><div class="home-factor-value">' +
      '<span class="num">' + (factorScore === null ? "—" : fmt(factorScore)) + '</span><span class="subtle">/ 100</span></div></div>' +
      axisScoreBar(factorScore, esc(definition.label) + " score") + "</div>";
  }).join("");
  return '<div class="card home-panel home-health"><div class="between home-panel-head"><h3>Memory Health</h3>' +
    (band ? ui.pill(esc(bandLabel(band)), bandTone(band)) : ui.pill("Unavailable")) + '</div>' +
    '<div class="home-health-scoreline"><div><span class="num home-score">' + (score === null ? "—" : fmt(score)) +
    '</span><span class="subtle"> / 100</span></div>' + trendHtml + '</div>' +
    '<div class="home-health-meter" role="progressbar" aria-label="Memory health score" aria-valuenow="' + fmt(progress) +
    '" aria-valuemin="0" aria-valuemax="100" style="--home-health-progress:' + fmt(progress) + '%"><div class="home-health-track" aria-hidden="true"><span class="home-health-fill"></span></div></div>' +
    '<div class="home-factor-list">' + factorRows + '</div>' +
    '<div class="home-card-foot home-card-foot--full">' +
    goBtn("s6", "Improve Your Memory Health") + "</div></div>";
}

/** Home already establishes the organization context, so team rows only need
 * the organization-relative path. Keep the organization aggregate itself as
 * the root label and preserve any deeper team path below that root. */
function memoryWritesTeamLabel(namespace, ctx) {
  const label = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const separator = label.indexOf("/");
  return separator === -1 ? label : label.slice(separator + 1) || label;
}

function memoryWritesCard(view, ctx, range) {
  const esc = ctx.esc;
  const teams = view && Array.isArray(view.teams) ? view.teams : [];
  const total = view ? num(view.total) : 0;
  const meta = "By Team · " + overviewRangeTag(range);
  if (total === 0 || teams.length === 0) {
    return '<div class="card home-panel home-writes"><div class="between home-panel-head"><h3>Memory Writes</h3><span class="home-panel-meta">' +
      meta + '</span></div><div class="home-card-empty">No memory writes recorded ' +
      (range === "overall" ? "yet." : "in this range.") + "</div>" +
      '<div class="home-card-foot home-card-foot--full">' + goBtn("s15", "Track Activity") + "</div></div>";
  }
  const visible = teams.slice(0, 4).map(function (team) {
    return {
      name: team && team.name
        ? memoryWritesTeamLabel(team.name, ctx)
        : "Unassigned",
      count: num(team && team.count),
    };
  });
  if (teams.length > 4) {
    visible[3] = {
      name: "Other teams",
      count: teams.slice(3).reduce(function (sum, team) { return sum + num(team && team.count); }, 0),
    };
  }
  let offset = 0;
  const segments = visible.map(function (team, index) {
    const share = total > 0 ? (team.count / total) * 100 : 0;
    const roundedShare = Math.round(share);
    const itemLabel = team.count === 1 ? "item" : "items";
    const segment = '<circle class="home-writes-segment home-writes-segment--' + (index + 1) +
      '" role="img" aria-label="' + esc(team.name) + ": " + roundedShare + "%, " + fmt(team.count) + " " + itemLabel +
      '" cx="105" cy="105" r="85" pathLength="100" fill="none" stroke-width="22" stroke-dasharray="' +
      share.toFixed(2) + ' ' + (100 - share).toFixed(2) + '" stroke-dashoffset="-' + offset.toFixed(2) + '"></circle>';
    offset += share;
    return segment;
  }).join("");
  const tooltips = visible.map(function (team, index) {
    const share = total > 0 ? Math.round((team.count / total) * 100) : 0;
    const itemLabel = team.count === 1 ? "item" : "items";
    return '<div class="home-writes-tooltip home-writes-tooltip--' + (index + 1) + '" aria-hidden="true"><strong>' +
      esc(team.name) + '</strong><span><b>' + share + '%</b><i aria-hidden="true">&#183;</i>' +
      fmt(team.count) + " " + itemLabel + "</span></div>";
  }).join("");
  const legend = visible.map(function (team, index) {
    const share = total > 0 ? Math.round((team.count / total) * 100) : 0;
    const itemLabel = team.count === 1 ? "item" : "items";
    return '<div class="home-writes-legend-row home-writes-legend-row--' + (index + 1) + '" role="img" tabindex="0" aria-label="' +
      esc(team.name) + ": " + share + "%, " + fmt(team.count) + " " + itemLabel + '"><span class="home-writes-dot home-writes-dot--' + (index + 1) + '" aria-hidden="true"></span><span class="home-writes-team">' +
      esc(team.name) + '</span><span class="num">' + fmt(team.count) + '</span><span class="subtle home-text-xs">' + share + "%</span></div>";
  }).join("");
  return '<div class="card home-panel home-writes"><div class="between home-panel-head"><h3>Memory Writes</h3><span class="home-panel-meta">By Team</span></div><div class="home-writes-body"><div class="home-writes-donut" role="group" aria-label="' +
    fmt(total) + ' Total Writes by team"><svg viewBox="0 0 210 210"><circle class="home-writes-track" aria-hidden="true" cx="105" cy="105" r="85" fill="none" stroke-width="22"/>' +
    segments + '</svg><div class="home-writes-center"><strong class="num">' + fmt(total) + '</strong><span>Total Writes</span></div>' + tooltips + '</div>' +
    '<div class="home-writes-legend" role="group" aria-label="Memory Writes by team">' + legend + '</div></div><div class="home-card-foot home-card-foot--full">' +
    goBtn("s15", "Track Activity") + "</div></div>";
}

function overviewCard(counts, ctx) {
  const esc = ctx.esc;
  const rows = [
    ["skills", "Skills"],
    ["channels", "Channels"],
    ["agents", "Agents"],
    ["policies", "Policies"],
    ["conflicts", "Conflicts"],
  ];
  return '<div class="card home-panel home-overview-card"><div class="between home-panel-head"><h3>Overview</h3></div><div class="home-overview-list">' +
    rows.map(function (row) {
      const value = counts && counts[row[0]] != null ? fmt(num(counts[row[0]])) : "Unavailable";
      return '<div class="home-overview-row"><span class="home-overview-row-icon" aria-hidden="true">' + homeOverviewIcon(row[0]) +
        '</span><span>' + esc(row[1]) + '</span><strong class="num">' + value + "</strong></div>";
    }).join("") + "</div></div>";
}

function homeOverviewIcon(kind) {
  const paths = {
    skills: '<path d="m13.4 3.2-7.2 10.4h5.1l-1 7.2 7.5-10.6h-5z"/>',
    channels: '<path d="M5 8.5h14M8 5v14M16 5v14M5 15.5h14"/>',
    agents: '<rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M8 12h.01M16 12h.01"/>',
    policies: '<path d="M12 3 5.5 5.8v5.4c0 3.9 2.7 7.1 6.5 8.3 3.8-1.2 6.5-4.4 6.5-8.3V5.8z"/><path d="m9 12 2 2 4-4"/>',
    conflicts: '<path d="M12 3 3.8 19h16.4z"/><path d="M12 9v4M12 16h.01"/>',
  };
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    (paths[kind] || paths.skills) + "</svg>";
}

/**
 * Halofy Assistant-only month-to-date billing plus the existing shared
 * paid-AI cap. Those values intentionally come from different authorities:
 * the Assistant invocation ledger for billing, and cost_ledger for the cap.
 */
function usageCard(usage, ov, assistantRollup, ctx) {
  const esc = ctx.esc;
  const ui = ctx.ui;
  const assistant = assistantSpendView(assistantRollup);
  const assistantTotals = assistantRollup && assistantRollup.totals ? assistantRollup.totals : null;
  const missingPrices = assistantTotals ? num(assistantTotals.unavailableCostTurns) : 0;

  // Two authorities can answer for the cap: /v1/admin/usage, else the
  // overview's server-resolved spend block. When NEITHER answered, "no cap"
  // is not a fact we hold — painting it would turn a failed read into an
  // affirmative statement, the one thing a console read must never do.
  const capAvailable = Boolean((usage && usage.cap) || (ov && ov.spend));
  const spendObj = usage && usage.spend ? usage.spend : (ov && ov.spend) || {};
  const rawSharedSpend = spendObj.monthToDateUsd;
  const sharedSpendUsd = typeof rawSharedSpend === "number" && Number.isFinite(rawSharedSpend)
    ? rawSharedSpend
    : null;
  const capUsd =
    usage && usage.cap && usage.cap.effectiveMonthlyBudgetUsd != null
      ? num(usage.cap.effectiveMonthlyBudgetUsd)
      : ov && ov.spend && ov.spend.effectiveCapUsd != null
        ? num(ov.spend.effectiveCapUsd)
        : null;
  const pct = sharedSpendUsd !== null && capUsd !== null && capUsd > 0
    ? Math.round((sharedSpendUsd / capUsd) * 100)
    : null;

  const role = ctx.identity && ctx.identity.role ? String(ctx.identity.role) : "";
  const canEdit = role === "" || role === "owner" || role === "root" || role === "admin";
  const ownCap = usage && usage.cap && usage.cap.ownMonthlyBudgetUsd != null
    ? num(usage.cap.ownMonthlyBudgetUsd)
    : null;
  const capKnown = capUsd !== null;
  const capTone = pct !== null ? (pct >= 100 ? "crit" : pct >= 80 ? "warn" : "ok") : undefined;
  const capCopy = !capAvailable
    ? "The shared paid-AI cap could not be read right now."
    : !capKnown
      ? "Set a shared paid-AI cap to control paid Halofy features."
      : pct === null
        ? "Shared paid-AI cap usage is unavailable right now."
        : pct >= 100
          ? "Shared paid-AI cap reached. Paid Halofy AI features fall back at the limit; memory stays available."
          : pct >= 80
            ? pct + "% of the shared paid-AI cap used this month · alert threshold reached."
            : pct + "% of the shared paid-AI cap used this month.";
  const capNote = !capAvailable
    ? "cap unavailable"
    : capKnown
      ? "shared paid-AI cap " + fmtUsd(capUsd)
      : "no shared paid-AI cap";
  const pricedTurns = assistantTotals ? num(assistantTotals.pricedTurns) : 0;
  const assistantTurns = assistantTotals ? num(assistantTotals.turns) : 0;
  const amountNote = assistant.available
    ? "Halofy Assistant spend this month · " + capNote
    : assistant.floor
      // The headline already carries "so far"; the note carries the shortfall
      // that makes it a floor rather than the bill.
      ? fmt(pricedTurns) + " of " + fmt(assistantTurns) + " Assistant turns priced · " +
        missingPrices + " " + (missingPrices === 1 ? "has" : "have") + " no catalog price · " + capNote
      : missingPrices > 0
        ? missingPrices + " Assistant " + (missingPrices === 1 ? "turn is" : "turns are") + " missing prices · " + capNote
        : "Halofy Assistant billing unavailable · " + capNote;
  const tooltip = "Dollar amount: Halofy Assistant billing only. ChatGPT, Claude Code, Codex, and other external AI tools are not included. The cap tracks all paid Halofy AI usage.";
  const ringProgress = pct === null ? null : Math.min(100, Math.max(0, pct));

  const capRing = ringProgress === null
    ? ""
    : '<div class="home-cap-ring home-cap-ring--' + capTone + '" role="progressbar" tabindex="0" aria-label="Shared paid-AI cap used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
      ringProgress + '" aria-valuetext="' + esc(capCopy) + '" data-tip="' + esc(capCopy) + '"><svg viewBox="0 0 210 210" aria-hidden="true"><circle class="home-cap-ring-track" cx="105" cy="105" r="85" pathLength="100"></circle>' +
      (ringProgress > 0
        ? '<circle class="home-cap-ring-fill" cx="105" cy="105" r="85" pathLength="100" stroke-dasharray="' + ringProgress + ' 100"></circle>'
        : "") + '</svg><span class="home-cap-ring-value"><strong class="num">' + esc(String(pct)) +
      '%</strong><span>Cap Used</span></span></div>';

  const capFooter = !canEdit
    ? ""
    : '<div class="home-usage-footer"><div class="home-cap-summary" data-home-cap-summary><button class="btn btn--outline btn--sm" type="button" data-action="home-cap-edit" aria-controls="home-cap-panel" aria-haspopup="dialog" aria-expanded="false">' +
      (capKnown ? "Change The Monthly Cap" : "Set The Monthly Cap") + "</button></div></div>";
  const capPanel = canEdit
    ? rightPanelHtml({
      id: "home-cap-panel",
      eyebrow: "Home",
      title: capKnown ? "Change the monthly cap" : "Set the monthly cap",
      closeAction: "home-cap-close",
      className: "home-cap-drawer",
      body:
      '<div class="field home-cap-field"><label for="usage-cap-input">Monthly Cap (USD)</label><input id="usage-cap-input" class="input" type="number" min="0" step="1" value="' +
      esc(ownCap === null ? "" : String(ownCap)) + '" placeholder="' + esc(capKnown ? String(capUsd) : "No cap") + '"></div>' +
      '<span id="usage-cap-status" class="subtle home-cap-status" role="status" aria-live="polite"></span>' +
      '<div class="home-cap-actions"><button class="btn btn--solid btn--sm" type="button" data-action="usage-cap-save">Save</button>' +
      '<button class="btn btn--ghost btn--sm" type="button" data-action="home-cap-close">Cancel</button></div>',
    })
    : "";

  return (
    '<div class="card home-panel home-usage"><div class="between home-panel-head home-usage-head"><h3>Halofy Assistant Billing &amp; Limits' +
    headingInfo("Halofy Assistant Billing & Limits", tooltip) + "</h3></div>" +
    '<div class="home-usage-main">' + capRing + '<div class="home-usage-amount" role="note" tabindex="0" aria-label="' + esc(amountNote) + '" data-tip="' + esc(amountNote) + '"><span class="home-usage-label">Assistant spend this month</span><span class="num">' + assistant.value + "</span></div></div>" +
    capFooter + "</div>" + capPanel
  );
}

/** A "go to screen" outline button, dispatched by this screen's `go` action. */
function goBtn(screen, label) {
  return (
    '<button class="home-card-link" type="button" data-action="go" data-screen="' +
    screen +
    '"><span>' +
    label +
    '</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 18 6-6-6-6"></path></svg></button>'
  );
}

// Home's range, query filter, pagination, and cap editor stay local to the
// route. app.js's delegated listener dispatches data-action to this map;
// module state lets ctx.refresh() repaint without changing route.
export const actions = {
  go(ctx, el) {
    const screen = el.getAttribute("data-screen");
    if (screen) ctx.go(screen);
  },

  async "home-range"(ctx, el) {
    ensureHomeContext(ctx);
    const range = el.getAttribute("data-range");
    if (!["overall", "7", "30", "90"].includes(range)) return;
    if (range === homeRange) return; // already showing it — don't refetch
    homeRange = range;
    queryPage = 0;
    // Move the selection NOW. The re-render below has to wait on the network,
    // and app.js makes the stage inert while it does, so without this the
    // button the user just pressed stays visibly unselected for the whole
    // round trip — the "nothing happened" feeling.
    pressRangeOption(el);
    await ctx.refresh();
  },

  "home-query-filter-toggle"(_ctx, el) {
    const wrap = el.closest(".home-query-filter-wrap");
    const menu = wrap?.querySelector(".home-query-filter-menu");
    if (!menu) return;
    const willOpen = menu.hidden;
    menu.hidden = !willOpen;
    el.setAttribute("aria-expanded", willOpen ? "true" : "false");
  },

  async "home-query-filter"(ctx, el) {
    ensureHomeContext(ctx);
    const filter = el.getAttribute("data-filter");
    if (!["individuals", "agents", "teams"].includes(filter)) return;
    queryFilter = filter;
    queryPage = 0;
    await ctx.refresh();
  },

  /** Advance the merged memory-query leaderboard by a page. */
  async "home-page"(ctx, el) {
    ensureHomeContext(ctx);
    const list = el.getAttribute("data-list");
    const dir = Number(el.getAttribute("data-dir")) || 0;
    if (dir === 0) return;
    if (list !== "queries") return;
    queryPage = Math.max(0, queryPage + dir);
    await ctx.refresh();
  },

  /** Open the monthly-cap editor in the shared management right panel. */
  "home-cap-edit"(_ctx, el) {
    const root = (el.closest && el.closest(".home-overview")) || globalThis.document;
    const panel = root && root.querySelector ? root.querySelector("#home-cap-panel") : null;
    openRightPanel(panel, el);
  },

  "home-cap-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
  },

  /**
   * E56 - save the customer-editable monthly cap. PUT /v1/admin/usage/cap
   * { monthlyBudgetUsd: number|null } (null clears this namespace's own
   * override). The change is audited server-side (D4) and the namespace is
   * session-resolved (D9) - the body never carries a namespace.
   */
  async "usage-cap-save"(ctx, el) {
    const root = (el.closest && el.closest("#home-cap-panel")) || document;
    const input = root.querySelector("#usage-cap-input");
    const status = root.querySelector("#usage-cap-status");
    const raw = input ? String(input.value).trim() : "";
    let value = null;
    if (raw !== "") {
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 0) {
        if (status) status.textContent = "Cap must be a non-negative number.";
        return;
      }
      value = n;
    }
    if (status) status.textContent = "Saving…";
    try {
      await ctx.api.put("/v1/admin/usage/cap", { monthlyBudgetUsd: value });
    } catch (err) {
      if (status) {
        status.textContent =
          "Save failed: " + (err && err.message ? err.message : "unknown error");
      }
      return;
    }
    // The cap the save just changed is inside the cached reads, so a repaint
    // from cache would show the old one back.
    clearHomeReadCache();
    await ctx.refresh();
  },
};

/**
 * Called with "refresh" immediately before an IN-PLACE re-render, and with no
 * reason on route exit. Cached reads survive either way: they are TTL-bounded
 * and cleared on a new session or a cap save.
 */
export function cleanup(reason) {
  if (typeof document !== "undefined") closeRightPanel(document);
  // In-place refreshes must retain the selected reporting range, query filter,
  // and page. A route exit still resets Home for the next visit.
  if (reason === "refresh") return;
  homeContext = null;
  homeRange = "overall";
  queryFilter = "individuals";
  queryPage = 0;
}
