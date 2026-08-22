import { renderTopology } from "./s5-topology.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";
import { organizationScopeLabel } from "../identity-labels.js";
import { metricCard } from "../metric-card.js";
import {
  lineageCanvasHtml,
  lineageLayout,
  lineageLegendHtml,
} from "../lineage-graph.js";
import {
  cancelTopologyDrags,
  consumeTopologyDragClick,
  handleTopologyPointer,
} from "./s5-drag.js";
import {
  cancelGraphPans,
  centerGraphNode,
  consumeGraphPanClick,
  fitGraph,
  graphViewport,
  handleGraphPan,
  toggleGraphFullscreen,
  zoomGraph,
  zoomGraphBy,
} from "./s5-viewport.js";

// S5 - Memory map.
//
// The screen is the graph followed by its projection-safe saved-memory list:
// title row, space picker, optional View-as preview, topology, paginated rows,
// and one shared detail drawer. The old activity rail (repeat lookups, the
// unified gap feed, hottest facts, and pinned list) stays removed, so
// GET /v1/admin/gaps is not called here. Conflict review still lives on S11.
//
// Reads GET /v1/admin/memory-map?namespace=<caller's namespace> only for what
// the topology itself needs:
//   { namespace, pinned:[string], governedPins:[…], topology }
//
// M10 role-scoped view: the graph itself now comes from GET /v1/memory-graph
// (server-filtered per subject — D40). The response carries the role-adaptive
// title, the authorized scope options, post-filter counts, and the filtered
// topology; the client never invents or widens a scope. On a graph failure it
// retries once without a stale scope/preview credential, then browns out to
// "Access view unavailable." — never a broader fetch (the one exception: the
// platform operator, namespace "", has no tenant projection and falls back to
// its already-authorized memory-map topology).
// Root gets a "View as" preview (read-only, credential travels only in
// the x-halomem-preview-token header, never rendered or logged). While a
// preview is active the admin activity endpoints are not called and every
// mutation control is absent.
//
// Every interpolated API value passes through ctx.esc().

// Module UI state for scope selection and the root View-as preview. All ids
// are opaque and re-resolved server-side (D9); the preview token exists only
// here and in the request header.
const state = {
  scope: "",
  scopeMenu: false,
  picker: null,
  preview: null,
  savedPage: 1,
  savedOpen: null,
  savedGraph: null,
  savedTeam: "",
  savedCreatedDate: "",
  savedQuery: "",
};

/** Zoom applied per wheel notch. Deliberately gentler than the button step. */
const WHEEL_ZOOM_STEP = 1.096;

/** The bootstrap/platform operator: namespace "" with the root/owner role. */
function isPlatformRoot(ctx) {
  const id = ctx && ctx.identity ? ctx.identity : {};
  const namespace = id.namespace != null ? String(id.namespace) : "";
  return namespace === "" && (id.role === "owner" || id.role === "root");
}

async function fetchGraph(ctx) {
  const path = state.scope
    ? "/v1/memory-graph?scope=" + encodeURIComponent(state.scope)
    : "/v1/memory-graph";
  if (state.preview && state.preview.token) {
    return ctx.api.get(path, {
      headers: { "x-halomem-preview-token": state.preview.token },
    });
  }
  return ctx.api.get(path);
}

/** The org topology read. Browns out to null - S5 renders without pins. */
function fetchMap(ctx, namespace) {
  return ctx.api
    .get("/v1/admin/memory-map?namespace=" + encodeURIComponent(namespace))
    .catch(() => null);
}

/**
 * @param {import('../app.js').Ctx} ctx
 * @returns {Promise<string>}
 */
export async function render(ctx) {
  cancelTopologyDrags();
  cancelGraphPans();
  const { esc, ui } = ctx;
  const namespace = (ctx.identity && ctx.identity.namespace) || "";
  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );

  // The org topology is independent of the graph projection - it keys off the
  // caller's namespace only. Firing it here instead of after the graph takes
  // it off the critical path: back to back the two round trips doubled the
  // wait on every scope change, which is what made a pick feel like a freeze.
  // Under an ACTIVE preview it must not fire at all (admin endpoints are not
  // called while previewing), so it is started only when there is no preview.
  const mapPromise = state.preview ? null : fetchMap(ctx, namespace);

  let graph = null;
  let graphFailed = false;
  let previewEnded = false;
  try {
    graph = await fetchGraph(ctx);
  } catch {
    if (state.preview) {
      // The preview credential is no longer valid (expired, ended, or
      // foreign): drop the preview locally rather than ever labeling a
      // non-preview response with the "Viewing as" banner (D43/E6).
      state.preview = null;
      state.scope = "";
      state.savedTeam = "";
      state.savedCreatedDate = "";
      state.savedQuery = "";
      previewEnded = true;
      try {
        graph = await fetchGraph(ctx);
      } catch {
        graphFailed = true;
      }
    } else if (state.scope) {
      // A remembered scope id can outlive its grant (revocation, org
      // switch). Retry once on the full granted union so the screen
      // recovers without a hard reload; never a wider request.
      state.scope = "";
      state.savedTeam = "";
      state.savedCreatedDate = "";
      state.savedQuery = "";
      try {
        graph = await fetchGraph(ctx);
      } catch {
        graphFailed = true;
      }
    } else {
      graphFailed = true;
    }
  }
  state.savedGraph = graph;
  const previewNotice = previewEnded
    ? '<div class="model-notice" role="status">Preview ended.</div>'
    : "";

  const title =
    graph && typeof graph.title === "string" && graph.title.trim() !== ""
      ? esc(graph.title)
      : "Memory";
  const scopeControl = renderScopeControl(esc, graph);

  // Active preview: banner + the subject's graph, nothing else. Admin
  // endpoints are not called; no mutation control renders.
  if (state.preview) {
    return (
      '<div class="home-overview memory-overview"><div class="screen-flow"><div class="memory-preview">' +
      ui.head({ eyebrow: "Operate · " + esc(nsLabel), title, acts: scopeControl }) +
      renderMemoryMetrics(graph, graphFailed) +
      renderPreviewBanner(esc) +
      renderGraphBlock(ctx, graph, graphFailed, null) +
      renderSavedMemories(ctx, graph, graphFailed) +
      renderSavedMemoryPanel(ctx, graph) +
      "</div></div></div>"
    );
  }

  const role = ctx.identity && ctx.identity.role;
  const isRoot = role === "owner" || role === "root";
  // The space picker rides in the title row's action slot: on its own line it
  // left an empty band between the title and the graph.
  const head = ui.head({
    eyebrow: "Operate · " + esc(nsLabel),
    title,
    acts:
      scopeControl +
      (isRoot
        ? '<button type="button" class="btn btn--outline btn--sm" data-action="viewas-open" aria-controls="viewas-panel" aria-haspopup="dialog" aria-expanded="false">View as</button>'
        : ""),
  });
  const picker = isRoot
    ? rightPanelHtml({
        id: "viewas-panel",
        eyebrow: "Memory access",
        title: "View as",
        closeAction: "viewas-close",
        className: "viewas-drawer",
        body: state.picker
          ? renderViewAsPicker(esc)
          : '<div class="sub">Choose a person or role to preview their memory access.</div>',
      })
    : "";

  // Started before the graph fetch above. The one case with no in-flight
  // request is a preview that ended mid-render: it began as a preview (no
  // topology call) and finished as a normal view, which still needs one.
  const map = await (mapPromise ?? fetchMap(ctx, namespace));
  const graphHtml = renderGraphBlock(ctx, graph, graphFailed, map);
  return '<div class="home-overview memory-overview"><div class="screen-flow">' + head +
    renderMemoryMetrics(graph, graphFailed) + picker + previewNotice + graphHtml +
    renderSavedMemories(ctx, graph, graphFailed) +
    renderSavedMemoryPanel(ctx, graph) + "</div></div>";
}

function renderMemoryMetrics(graph, graphFailed) {
  const unavailable = graphFailed || !graph;
  const rows = unavailable ? [] : savedRows(graph);
  const value = (count) => unavailable ? "Unavailable" : String(count);
  const sourceCount = Array.isArray(graph?.topology?.sources) ? graph.topology.sources.length : 0;
  return '<div class="memory-summary-metrics" role="list" aria-label="Memory summary">' +
    metricCard({ k: "Current Memories", v: value(rows.length), icon: "memory", foot: "Current memories visible in this governed view." }) +
    metricCard({ k: "Warm L2", v: value(rows.filter((row) => row?.tier !== "L3").length), icon: "memory", foot: "Authoritative warm memories stored in L2." }) +
    metricCard({ k: "Cold L3", v: value(rows.filter((row) => row?.tier === "L3").length), icon: "file", foot: "Cold governed knowledge represented in this view." }) +
    metricCard({ k: "Connected Sources", v: value(sourceCount), icon: "source", foot: "Sources represented in the current memory topology." }) + "</div>";
}

export function cleanup(reason) {
  cancelTopologyDrags();
  if (typeof document !== "undefined") closeRightPanel(document);
  if (reason !== "refresh") {
    state.savedOpen = null;
    state.savedGraph = null;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedQuery = "";
  }
}

// (clearTopologyFocus / topologyExpandedParents / syncTopologyDisclosure live
// below with the actions — the M10 variants also sync the "Why visible?"
// lines during a root preview.)

// ---------------------------------------------------------------------------
// Role-scoped graph helpers (M10). The server filters everything; these only
// lay out what came back.
// ---------------------------------------------------------------------------

function renderGraphBlock(ctx, graph, graphFailed, map) {
  if (graphFailed || !graph) {
    // The platform operator (namespace "") has no tenant, so /v1/memory-graph
    // fails closed for it by design. Its org-wide memory-map response is
    // already server-authorized (console/api.ts allows the platform root
    // owner), so render that topology instead of a dead end. Every OTHER
    // caller keeps the brownout line — never a broader view (rule 12).
    if (map && map.topology && isPlatformRoot(ctx)) {
      return renderTopology(ctx, {
        topology: map.topology,
        pinned: Array.isArray(map.pinned) ? map.pinned : [],
        governedPins: Array.isArray(map.governedPins) ? map.governedPins : [],
      });
    }
    return ctx.ui.empty("Access view unavailable.");
  }
  if (graph.counts && graph.counts.nodes === 0) {
    // The subject's view is empty because nothing is GRANTED - never a claim
    // about the company graph (CONTRACTS-M10-ACCESS console-s5 row).
    return ctx.ui.empty("Nothing shared with you yet.");
  }
  const section = renderTopology(ctx, {
    topology: graph.topology,
    pinned: map && Array.isArray(map.pinned) ? map.pinned : [],
    governedPins: map && Array.isArray(map.governedPins) ? map.governedPins : [],
  });
  return (
    '<div class="memory-graph-wrap">' +
    section +
    renderWhyLines(ctx.esc, graph) +
    "</div>"
  );
}

const SAVED_MEMORY_PAGE_SIZE = 10;

const SAVED_MEMORY_FILTER_SVG =
  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2.5 3.25h11l-4.2 4.9v3.5l-2.6 1.35V8.15L2.5 3.25Z" stroke-linejoin="round"/></svg>';

const SAVED_MEMORY_SEARCH_SVG =
  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="7" cy="7" r="4.25"/><path d="m10.25 10.25 3 3" stroke-linecap="round"/></svg>';

const SAVED_MEMORY_SEARCH_INDEX = new WeakMap();

function savedRows(graph) {
  return graph && Array.isArray(graph.savedMemories) ? graph.savedMemories : [];
}

function shortCell(value, max = 14) {
  const text = String(value ?? "").trim() || "Unavailable";
  return text.length <= max ? text : text.slice(0, max - 1).trimEnd() + "…";
}

function memoryDate(value) {
  const date = new Date(String(value ?? ""));
  if (!Number.isFinite(date.getTime())) return "Unavailable";
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  });
}

function memoryDateValue(value) {
  const raw = String(value ?? "");
  const day = raw.slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : "";
}

function normalizedSearchText(value) {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLocaleLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

function indexedSavedMemoryFields(memory) {
  if (memory && typeof memory === "object" && SAVED_MEMORY_SEARCH_INDEX.has(memory)) {
    return SAVED_MEMORY_SEARCH_INDEX.get(memory);
  }
  const fields = [
    [memory?.title, 20],
    [memory?.summary, 12],
    [memory?.source, 8],
    [memory?.team, 6],
    [memory?.author, 5],
    [memory?.origin, 5],
    [memory?.body, 3],
    [Array.isArray(memory?.facts) ? memory.facts.join(" ") : "", 3],
  ].map(([value, weight]) => {
    const text = normalizedSearchText(value);
    return { text, weight, words: text.split(" ") };
  });
  if (memory && typeof memory === "object") SAVED_MEMORY_SEARCH_INDEX.set(memory, fields);
  return fields;
}

function savedMemorySearchScore(memory, query) {
  const phrase = normalizedSearchText(query);
  if (!phrase) return 0;
  const tokens = [...new Set(phrase.split(/\s+/).filter(Boolean))];
  const fields = indexedSavedMemoryFields(memory);

  let score = 0;
  let matched = 0;
  for (const token of tokens) {
    let best = 0;
    for (const field of fields) {
      if (!field.text) continue;
      const quality = field.words.includes(token)
        ? 3
        : field.words.some((word) => word.startsWith(token))
          ? 2
          : token.length >= 3 && field.text.includes(token) ? 1 : 0;
      best = Math.max(best, field.weight * quality);
    }
    if (best > 0) {
      matched += 1;
      score += best;
    }
  }
  if (matched === 0) return -1;
  if (matched / tokens.length < 0.5) return -1;

  const title = normalizedSearchText(memory?.title);
  const summary = normalizedSearchText(memory?.summary);
  if (title.includes(phrase)) score += 100;
  else if (summary.includes(phrase)) score += 60;
  score += Math.round((matched / tokens.length) * 80);
  if (matched === tokens.length) score += 40;
  return score;
}

function filteredSavedRows(rows) {
  return rows
    .map((memory, index) => ({
      memory,
      index,
      score: savedMemorySearchScore(memory, state.savedQuery),
    }))
    .filter(({ memory, score }) => {
      if (state.savedTeam && String(memory?.team ?? "") !== state.savedTeam) return false;
      if (state.savedCreatedDate && memoryDateValue(memory?.createdAt) !== state.savedCreatedDate) return false;
      return score >= 0;
    })
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .map(({ memory }) => memory);
}

function renderSavedMemoryFilters(esc, rows) {
  const teams = [...new Set(rows.map((memory) => String(memory?.team ?? "").trim()).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right));
  const active = Boolean(state.savedTeam || state.savedCreatedDate);
  const activeCount = Number(Boolean(state.savedTeam)) + Number(Boolean(state.savedCreatedDate));
  const badge = activeCount
    ? `<span class="saved-memory-filter-badge" aria-hidden="true">${activeCount}</span>`
    : "";
  const clear = active
    ? '<div class="saved-memory-filter-footer"><button type="button" class="btn btn--ghost btn--sm saved-memory-filter-clear" data-action="saved-memory-filter-clear">Clear filters</button></div>'
    : "";
  return `<span class="saved-memory-filter-shell">
    <button type="button" class="halo-icon-control saved-memory-filter-trigger" popovertarget="saved-memory-filter" aria-label="Filter saved memories" title="Filter saved memories">${SAVED_MEMORY_FILTER_SVG}${badge}</button>
    <div class="saved-memory-filter-pop" id="saved-memory-filter" popover aria-label="Filter saved memories">
      <label><span>Team</span><select class="select" data-change-action="saved-memory-filter" data-filter="team" aria-label="Filter saved memories by team">
        <option value="">All teams</option>
        ${teams.map((team) => `<option value="${esc(team)}"${state.savedTeam === team ? " selected" : ""}>${esc(team)}</option>`).join("")}
      </select></label>
      <label><span>Created date</span><input class="input" type="date" data-change-action="saved-memory-filter" data-filter="created-date" aria-label="Filter saved memories by created date" value="${esc(state.savedCreatedDate)}"></label>
      ${clear}
    </div>
  </span>`;
}

function pageNumbers(page, pages) {
  if (pages <= 7) return Array.from({ length: pages }, (_, index) => index + 1);
  const candidates = new Set([1, pages, page - 1, page, page + 1]);
  const values = [...candidates].filter((value) => value >= 1 && value <= pages).sort((a, b) => a - b);
  const result = [];
  for (const value of values) {
    if (result.length && value - result[result.length - 1] > 1) result.push("…");
    result.push(value);
  }
  return result;
}

function savedMemoryView(graph, graphFailed) {
  const rows = savedRows(graph);
  const filtered = filteredSavedRows(rows);
  const filtersActive = Boolean(state.savedTeam || state.savedCreatedDate);
  const queryActive = normalizedSearchText(state.savedQuery) !== "";
  const selectionActive = filtersActive || queryActive;
  const pages = Math.max(1, Math.ceil(filtered.length / SAVED_MEMORY_PAGE_SIZE));
  const page = Math.min(Math.max(1, Number(state.savedPage) || 1), pages);
  state.savedPage = page;
  const start = (page - 1) * SAVED_MEMORY_PAGE_SIZE;
  const visible = filtered.slice(start, start + SAVED_MEMORY_PAGE_SIZE);
  const count = graphFailed || !graph
    ? "UNAVAILABLE"
    : selectionActive ? `${filtered.length} OF ${rows.length} MEMORIES` : `${rows.length} MEMORIES`;
  return { rows, filtered, filtersActive, queryActive, selectionActive, page, pages, start, visible, count };
}

function renderSavedMemoryResults(ctx, view, unavailable) {
  const { esc } = ctx;
  const { filtered, filtersActive, queryActive, selectionActive, page, pages, start, visible } = view;
  const body = unavailable
    ? '<div class="saved-memories-empty">Saved memories unavailable.</div>'
    : visible.length === 0
      ? selectionActive
        ? `<div class="saved-memories-empty" role="status">${queryActive
            ? filtersActive ? "No memories match your search and filters." : "No memories match your search."
            : "No memories match these filters."}</div>`
        : '<div class="saved-memories-empty">No memories held in this space yet.</div>'
      : visible.map((memory) => {
          const id = String(memory.id ?? "");
          const tier = memory.tier === "L3" ? "L3" : "L2";
          const team = String(memory.team ?? "Unavailable");
          const source = String(memory.source ?? "Unavailable");
          const open = state.savedOpen === id;
          return `<button type="button" class="saved-memory-row" data-action="saved-memory-open" data-memory-id="${esc(id)}" aria-haspopup="dialog" aria-controls="saved-memory-panel" aria-expanded="${open}">
            <span class="saved-memory-tier saved-memory-tier--${tier.toLowerCase()}">${tier}</span>
            <span class="saved-memory-summary">${esc(memory.title ?? memory.summary ?? "Unavailable")}</span>
            <span class="saved-memory-team" title="${esc(team)}">${esc(shortCell(team))}</span>
            <span class="saved-memory-source" title="${esc(source)}">${esc(shortCell(source))}</span>
            <span class="saved-memory-used">Used ${esc(Math.max(0, Number(memory.accessCount) || 0))}×</span>
            <time class="saved-memory-date" datetime="${esc(memory.createdAt ?? "")}" aria-label="Created ${esc(memoryDate(memory.createdAt))}">${esc(memoryDate(memory.createdAt))}</time>
            <span class="saved-memory-chevron" aria-hidden="true">›</span>
          </button>`;
        }).join("");
  const from = filtered.length === 0 ? 0 : start + 1;
  const to = Math.min(filtered.length, start + SAVED_MEMORY_PAGE_SIZE);
  const pagination = unavailable || filtered.length === 0 ? "" : `
    <div class="saved-memory-pagination">
      <div>Showing ${from}–${to} of ${filtered.length}${selectionActive ? " matching" : ""} Memories</div>
      <div class="saved-memory-pages" aria-label="Saved memory pages">
        <button type="button" data-action="saved-memory-page" data-page="${Math.max(1, page - 1)}" aria-label="Previous page" ${page === 1 ? "disabled" : ""}>‹</button>
        ${pageNumbers(page, pages).map((value) => value === "…"
          ? '<span class="saved-memory-page-gap" aria-hidden="true">…</span>'
          : `<button type="button" data-action="saved-memory-page" data-page="${value}" aria-label="Page ${value}"${value === page ? ' aria-current="page"' : ""}>${value}</button>`).join("")}
        <button type="button" data-action="saved-memory-page" data-page="${Math.min(pages, page + 1)}" aria-label="Next page" ${page === pages ? "disabled" : ""}>›</button>
      </div>
    </div>`;
  return `<div class="saved-memory-list">${body}</div>${pagination}`;
}

function renderSavedMemories(ctx, graph, graphFailed) {
  const { esc } = ctx;
  const view = savedMemoryView(graph, graphFailed);
  return `<section class="saved-memories" aria-labelledby="saved-memories-title">
    <div class="saved-memories-head">
      <h2 id="saved-memories-title">Saved Memories</h2>
      <label class="saved-memory-search">${SAVED_MEMORY_SEARCH_SVG}<span class="sr-only">Search saved memories</span><input type="search" value="${esc(state.savedQuery)}" placeholder="Search memories..." autocomplete="off" spellcheck="false" data-input-action="saved-memory-search" aria-label="Search saved memories" aria-controls="saved-memory-results"${graphFailed || !graph ? " disabled" : ""}></label>
      <div class="saved-memories-head-actions"><span data-saved-memory-count aria-live="polite">${view.count}</span>${graphFailed || !graph ? "" : renderSavedMemoryFilters(esc, view.rows)}</div>
    </div>
    <div id="saved-memory-results" data-saved-memory-results>${renderSavedMemoryResults(ctx, view, graphFailed || !graph)}</div>
  </section>`;
}

function initials(value) {
  const words = String(value ?? "").trim().split(/\s+/).filter(Boolean);
  return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase() || "—";
}

function savedMemoryLineage(memory) {
  const direct = Array.isArray(memory.links) ? memory.links : [];
  const inbound = [];
  const labels = new Set();
  const addInbound = (link) => {
    const label = String(link && link.label || "").trim();
    if (!label || label === "Unavailable") return;
    const key = label.toLocaleLowerCase();
    if (labels.has(key)) return;
    labels.add(key);
    inbound.push({ ...link, label, side: "left" });
  };

  addInbound({
    id: `origin:${String(memory.origin ?? "")}`,
    label: memory.origin,
    kind: "origin",
    role: "Came from",
  });
  addInbound({
    id: `actor:${String(memory.author ?? "")}`,
    label: memory.author,
    kind: "actor",
    role: "Captured by",
  });
  for (const link of direct) addInbound(link);

  const tier = memory.tier === "L3" ? "L3" : "L2";
  return [
    ...inbound.slice(0, 5),
    {
      id: tier,
      label: `${tier} ${tier === "L3" ? "Cold knowledge" : "Warm memory"}`,
      kind: "tier",
      role: "Stored in",
      side: "right",
    },
  ];
}

function graphTopologyNodeId(link) {
  if (link && link.kind === "tier" && /^L[0-3]$/.test(String(link.id))) {
    return `t:${link.id}`;
  }
  const prefixes = {
    source: "b",
    policy: "p",
    knowledge: "kb",
    skill: "s",
    agent: "a",
  };
  const prefix = prefixes[String(link && link.kind)];
  return prefix && link && link.id ? `${prefix}:${link.id}` : null;
}

function renderSavedMemoryPanel(ctx, graph) {
  const { esc } = ctx;
  const memory = savedRows(graph).find((row) => String(row.id) === state.savedOpen);
  if (!memory) return "";
  const tier = memory.tier === "L3" ? "L3" : "L2";
  const status = memory.status === "Governed" ? "Governed" : "Current";
  const confidence = Math.max(0, Math.min(100, Math.round((Number(memory.confidence) || 0) * 100)));
  const facts = Array.isArray(memory.facts) ? memory.facts : [];
  const links = lineageLayout(savedMemoryLineage(memory));
  const metadata = [
    ["Captured", memoryDate(memory.createdAt)],
    ["Last updated", memoryDate(memory.updatedAt)],
    ["Team", memory.team ?? "Unavailable"],
    ["Memory lane", `${tier} · ${tier === "L3" ? "Cold knowledge" : "Warm memory"}`],
    ["Version", `v${Math.max(1, Number(memory.version) || 1)}`],
    ["Recall count", `${Math.max(0, Number(memory.accessCount) || 0)}×`],
  ];
  // A link that names a node the memory graph itself carries is clickable: it
  // focuses that node. One that does not (a bare origin string, an author) is
  // inert — never a button that would do nothing.
  const canvasAttrs = (link) => {
    const topologyId = graphTopologyNodeId(link);
    return topologyId
      ? ` type="button" data-action="saved-memory-link" data-node-id="${esc(topologyId)}" data-node-kind="${esc(link.kind)}" title="Show ${esc(link.label)} on the memory graph"`
      : "";
  };
  const legendAttrs = (link) => {
    const topologyId = graphTopologyNodeId(link);
    return topologyId
      ? ` type="button" data-action="saved-memory-link" data-node-id="${esc(topologyId)}" data-node-kind="${esc(link.kind)}"`
      : "";
  };
  const canvas = lineageCanvasHtml({
    esc,
    core: memory.title ?? memory.summary,
    links,
    arrowId: "saved-memory-lineage-arrow",
    nodeAttrs: canvasAttrs,
  });
  const legend = lineageLegendHtml({
    esc,
    links,
    nodeAttrs: legendAttrs,
    empty: "No direct graph links recorded.",
  });
  const memoryBody = String(memory.body ?? memory.summary ?? "Unavailable");
  const bodyCanExpand = memoryBody.length > 180;
  const body = `<div class="saved-memory-detail">
    <div class="saved-memory-badges"><span class="saved-memory-tier saved-memory-tier--${tier.toLowerCase()}">${tier}</span><span class="saved-memory-status saved-memory-status--${status.toLowerCase()}">${status}</span></div>
    <div class="saved-memory-text${bodyCanExpand ? " is-collapsible" : ""}"${bodyCanExpand ? ' data-collapsible-text' : ""}><p class="saved-memory-body"${bodyCanExpand ? ' data-action="saved-memory-text-toggle"' : ""}>${esc(memoryBody)}</p>${bodyCanExpand ? '<button type="button" class="saved-memory-text-toggle" data-action="saved-memory-text-toggle" aria-expanded="false">See more</button>' : ""}</div>
    <div class="saved-memory-author"><span>${esc(initials(memory.author))}</span><div><strong>${esc(memory.author ?? "Unavailable")}</strong><small>${esc(memory.authorRole ?? "Memory capture")} · ${esc(memory.origin ?? "Unavailable")}</small></div></div>
    <dl class="saved-memory-meta">${metadata.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd title="${esc(value)}">${esc(value)}</dd></div>`).join("")}</dl>
    <section class="saved-memory-detail-section"><div class="saved-memory-section-title"><span>EXTRACTION CONFIDENCE</span><strong>${confidence}%</strong></div><div class="saved-memory-confidence"><i style="width:${confidence}%"></i></div></section>
    <section class="saved-memory-detail-section"><div class="saved-memory-section-title"><span>${facts.length} Extracted ${facts.length === 1 ? "Fact" : "Facts"}</span></div><div class="saved-memory-facts">${facts.length === 0 ? '<p class="saved-memory-link-empty">No extracted facts available.</p>' : facts.map((fact, index) => { const text = String(fact ?? ""); const canExpand = text.length > 120; return `<div${canExpand ? ' class="is-collapsible" data-collapsible-text' : ""}><b>${index + 1}</b><span${canExpand ? ' data-action="saved-memory-text-toggle"' : ""}>${esc(text)}</span><small>v${Math.max(1, Number(memory.version) || 1)} Latest</small>${canExpand ? '<button type="button" class="saved-memory-text-toggle" data-action="saved-memory-text-toggle" aria-expanded="false">See more</button>' : ""}</div>`; }).join("")}</div></section>
    <section class="saved-memory-detail-section"><div class="saved-memory-section-title"><span>GRAPH LINKAGE</span></div>
      ${canvas}<div class="saved-memory-link-legend-list">${legend}</div>
    </section>
  </div>`;
  return rightPanelHtml({
    id: "saved-memory-panel",
    eyebrow: "Saved memory",
    title: esc(memory.title ?? memory.summary ?? "Memory"),
    closeAction: "saved-memory-close",
    className: "saved-memory-drawer",
    body,
  });
}

// The space picker. Options are exactly the scopes the server authorized for
// this subject - the client never invents, widens, or remembers one that the
// server stopped offering (D9/D42).
function renderScopeControl(esc, graph) {
  const scopes =
    graph && Array.isArray(graph.scopes)
      ? graph.scopes.filter((s) => s && s.id != null && String(s.id) !== "")
      : [];
  // Only when there is a real choice; options come from the server only.
  if (scopes.length < 2) return "";
  const known = scopes.some((s) => String(s.id) === state.scope);
  const selected = known ? state.scope : "";
  const labelFor = (scope) => {
    const id = String(scope.id);
    return scope.label != null && String(scope.label) !== "" ? String(scope.label) : id;
  };
  const current = selected === ""
    ? "All accessible"
    : labelFor(scopes.find((s) => String(s.id) === selected));
  const option = (id, label) =>
    '<button type="button" class="memory-scope-option" role="option" data-action="scope-pick" data-scope="' +
    esc(id) + '" aria-selected="' + String(selected === id) + '">' +
    '<span class="memory-scope-tick" aria-hidden="true"></span>' + esc(label) + "</button>";

  return (
    '<div class="memory-scope" data-space-picker>' +
    '<button type="button" class="memory-scope-trigger" data-action="scope-open" aria-haspopup="listbox" aria-expanded="' +
    String(Boolean(state.scopeMenu)) + '">' +
    '<span>Space</span><b>' + esc(current) + "</b>" +
    '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m7 10 5 5 5-5"></path></svg>' +
    "</button>" +
    '<div class="memory-scope-menu" role="listbox" aria-label="Spaces you can see"' +
    (state.scopeMenu ? "" : " hidden") + ">" +
    option("", "All accessible") +
    scopes.map((s) => option(String(s.id), labelFor(s))).join("") +
    "</div></div>"
  );
}

/**
 * Close the menu and move the trigger to the picked label immediately, then
 * mark the picker busy for the round trip. Pure DOM on the live node - the
 * next render rebuilds it from the server response regardless.
 */
function markScopePending(el) {
  const picker =
    el && typeof el.closest === "function" ? el.closest("[data-space-picker]") : null;
  if (!picker || typeof picker.querySelector !== "function") return;
  const menu = picker.querySelector(".memory-scope-menu");
  if (menu) menu.hidden = true;
  const trigger = picker.querySelector(".memory-scope-trigger");
  if (trigger) {
    trigger.setAttribute("aria-expanded", "false");
    const label = trigger.querySelector("b");
    const picked = typeof el.textContent === "string" ? el.textContent.trim() : "";
    if (label && picked !== "") label.textContent = picked;
  }
  picker.classList.add("is-loading");
  picker.setAttribute("aria-busy", "true");
}

function renderWhyLines(esc, graph) {
  const why = graph && graph.why && typeof graph.why === "object" ? graph.why : null;
  if (!why) return "";
  const entries = Object.keys(why).filter(
    (key) => typeof why[key] === "string" && why[key].trim() !== "",
  );
  if (entries.length === 0) return "";
  return (
    '<div class="memory-why-list">' +
    entries
      .map(
        (key) =>
          '<p class="memory-why" data-why-for="' + esc(key) + '" hidden><b>Why visible?</b> ' +
          esc(why[key]) + "</p>",
      )
      .join("") +
    "</div>"
  );
}

function renderPreviewBanner(esc) {
  const p = state.preview;
  // PRD §8.2: person previews show name + role; the "· …" segment is dropped
  // entirely when the server returned no label — never a scope claim.
  return (
    '<div class="preview-banner" role="status"><span>Viewing as ' +
    esc(p.name || "") + (p.scope ? " · " + esc(p.scope) : "") +
    '</span><button type="button" class="btn btn--sm" data-action="viewas-exit">Exit</button></div>'
  );
}

function pickerValid() {
  const p = state.picker;
  if (!p) return false;
  const reason = String(p.reason || "").trim();
  if (reason.length === 0 || reason.length > 200) return false;
  if (p.tab === "role") return Boolean(p.role) && p.funcs.size > 0;
  return Boolean(p.pick);
}

function syncStart(panel) {
  if (!panel || typeof panel.querySelector !== "function") return;
  const btn = panel.querySelector('[data-action="viewas-start"]');
  if (btn) btn.disabled = !pickerValid();
}

function renderViewAsPicker(esc) {
  const p = state.picker;
  const personRows =
    p.people.length === 0
      ? '<div class="subtle">No people.</div>'
      : p.people
          .map((person) => {
            const id = person && person.id != null ? String(person.id) : "";
            const name = person && person.name != null ? String(person.name) : "";
            const email = person && person.email != null ? String(person.email) : "";
            // Users may have no separate display name (name === email): show
            // the address once, never the same string twice.
            const primary = name !== "" ? name : email;
            const secondary = email !== "" && email !== primary ? email : "";
            return (
              '<button type="button" class="viewas-person" data-action="viewas-pick-person" data-user-id="' +
              esc(id) + '" data-search="' + esc((name + " " + email).toLowerCase()) +
              '" aria-pressed="' + (p.pick === id ? "true" : "false") + '"><span>' +
              esc(primary) + "</span>" +
              (secondary ? "<small>" + esc(secondary) + "</small>" : "") +
              "</button>"
            );
          })
          .join("");
  const roleChips = [["admin", "Admin"], ["member", "Member"]]
    .map(
      ([value, label]) =>
        '<button type="button" class="btn btn--outline btn--sm viewas-chip" data-action="viewas-role" data-role="' +
        value + '" aria-pressed="' + (p.role === value ? "true" : "false") + '">' +
        label + "</button>",
    )
    .join("");
  const funcChips =
    p.functions.length === 0
      ? '<div class="subtle">No areas yet.</div>'
      : p.functions
          .map((fn) => {
            const id = fn && fn.id != null ? String(fn.id) : "";
            const label = fn && fn.label != null && String(fn.label) !== "" ? String(fn.label) : id;
            return (
              '<button type="button" class="btn btn--outline btn--sm viewas-chip" data-action="viewas-func" data-func-id="' +
              esc(id) + '" aria-pressed="' + (p.funcs.has(id) ? "true" : "false") + '">' +
              esc(label) + "</button>"
            );
          })
          .join("");
  return (
    '<div class="viewas" data-viewas>' +
    '<div class="viewas-tabs">' +
    '<button type="button" class="btn btn--outline btn--sm viewas-chip" data-action="viewas-tab" data-tab="person" aria-pressed="' +
    (p.tab === "person" ? "true" : "false") + '">Person</button>' +
    '<button type="button" class="btn btn--outline btn--sm viewas-chip" data-action="viewas-tab" data-tab="role" aria-pressed="' +
    (p.tab === "role" ? "true" : "false") + '">Role</button>' +
    "</div>" +
    '<div data-viewas-panel="person"' + (p.tab === "person" ? "" : " hidden") + ">" +
    '<input class="input" type="search" data-input-action="viewas-search" placeholder="Search name or email" aria-label="Search people">' +
    '<div class="viewas-list">' + personRows + "</div></div>" +
    '<div data-viewas-panel="role"' + (p.tab === "role" ? "" : " hidden") + ">" +
    '<div class="viewas-chips">' + roleChips + "</div>" +
    '<div class="viewas-chips">' + funcChips + "</div></div>" +
    '<div class="viewas-foot">' +
    '<input class="input" data-input-action="viewas-reason" maxlength="200" placeholder="Reason" aria-label="Reason" value="' +
    esc(p.reason) + '">' +
    '<button type="button" class="btn btn--sm" data-action="viewas-start"' +
    (pickerValid() ? "" : " disabled") + ">Start</button>" +
    "</div></div>"
  );
}

// Reveal the focused node's one-line reason during a preview; hide the rest.
// Keys are entity ids as the server knows them; DOM node ids carry a short
// "kind:" prefix, so both exact and suffix matches count.
function syncWhyLines(viewport, id) {
  const wrap =
    viewport && typeof viewport.closest === "function"
      ? viewport.closest(".memory-graph-wrap")
      : null;
  if (!wrap || typeof wrap.querySelectorAll !== "function") return;
  wrap.querySelectorAll(".memory-why").forEach(function (line) {
    const target = line.getAttribute("data-why-for") || "";
    line.hidden =
      id === null || !(target === id || String(id).endsWith(":" + target));
  });
}

const topologyPanelDataCache = new WeakMap();

function topologyPanelData(graph) {
  if (topologyPanelDataCache.has(graph)) return topologyPanelDataCache.get(graph);
  const payload = graph.querySelector("[data-graph-panel-data]");
  let data = {};
  try {
    data = JSON.parse(payload?.textContent || "{}");
  } catch {
    data = {};
  }
  topologyPanelDataCache.set(graph, data);
  return data;
}

function setPanelText(panel, selector, value) {
  const target = panel.querySelector(selector);
  if (target) target.textContent = value == null ? "" : String(value);
}

// Relation wording the panel shows next to a neighbour. The graph's own
// relation vocabulary is internal; these are the human readings.
const LINK_RELATIONS = {
  branch: "contains",
  memory: "contains",
  flow: "feeds",
  source: "syncs",
  provenance: "came from",
  update: "updates",
};

function fillLinkList(panel, selector, entries) {
  const list = panel.querySelector(selector);
  if (!list || typeof list.replaceChildren !== "function") return;
  const doc = list.ownerDocument;
  const rows = Array.isArray(entries) ? entries : [];
  list.replaceChildren(...rows.map(function (entry) {
    const row = doc.createElement("li");
    const button = doc.createElement("button");
    button.type = "button";
    button.className = "memory-graph-link";
    button.setAttribute("data-action", "topo-jump");
    button.setAttribute("data-node-id", String(entry.id || ""));
    const dot = doc.createElement("span");
    dot.className = "memory-graph-child-dot";
    dot.setAttribute("data-kind", String(entry.kind || ""));
    dot.setAttribute("aria-hidden", "true");
    const relation = doc.createElement("small");
    relation.textContent = LINK_RELATIONS[String(entry.relation || "")] || "links";
    const name = doc.createElement("b");
    name.textContent = String(entry.label || "");
    button.append(dot, relation, name);
    row.append(button);
    return row;
  }));
  list.hidden = rows.length === 0;
}

function renderGraphPanel(graph, panel, id) {
  if (!graph || typeof graph.querySelector !== "function" || !panel || typeof panel.querySelector !== "function") return false;
  const data = topologyPanelData(graph)[id];
  if (!data) return false;
  setPanelText(panel, "[data-node-type]", data.type);
  setPanelText(panel, "[data-node-title]", data.label);
  setPanelText(panel, "[data-node-detail]", data.detail);
  setPanelText(panel, "[data-node-summary]", data.summary);
  setPanelText(panel, "[data-node-space]", data.space);
  const updated = panel.querySelector("[data-node-updated]");
  if (updated) {
    updated.textContent = data.updated?.long || "Not available";
    if (data.updated?.iso) updated.setAttribute("datetime", data.updated.iso);
    else updated.removeAttribute("datetime");
  }
  const degreeIn = Number(data.degree && data.degree.in) || 0;
  const degreeOut = Number(data.degree && data.degree.out) || 0;
  setPanelText(
    panel,
    "[data-node-degree]",
    degreeIn + degreeOut === 0
      ? "None"
      : `${degreeIn + degreeOut} · ${degreeOut} out, ${degreeIn} in`,
  );
  setPanelText(panel, "[data-node-out-count]", String(degreeOut));
  setPanelText(panel, "[data-node-in-count]", String(degreeIn));
  fillLinkList(panel, "[data-node-outgoing]", data.outgoing);
  fillLinkList(panel, "[data-node-incoming]", data.incoming);
  const linkEmpty = panel.querySelector("[data-node-linkempty]");
  if (linkEmpty) linkEmpty.hidden = degreeIn + degreeOut !== 0;

  const childCount = Number(data.childCount) || 0;
  setPanelText(panel, "[data-node-connections]", `${childCount} ${childCount === 1 ? "sub-node" : "sub-nodes"}`);
  const list = panel.querySelector("[data-node-children]");
  if (list && typeof list.replaceChildren === "function") {
    const doc = list.ownerDocument;
    const children = Array.isArray(data.children) ? data.children : [];
    list.replaceChildren(...children.map(function (child) {
      const row = doc.createElement("li");
      row.className = "memory-graph-child";
      const dot = doc.createElement("span");
      dot.className = "memory-graph-child-dot";
      dot.setAttribute("data-kind", String(child.kind || ""));
      dot.setAttribute("aria-hidden", "true");
      const copy = doc.createElement("span");
      const name = doc.createElement("b");
      name.textContent = String(child.label || "");
      const type = doc.createElement("small");
      type.textContent = String(child.type || "");
      copy.append(name, type);
      row.append(dot, copy);
      return row;
    }));
  }
  const empty = panel.querySelector("[data-node-empty]");
  if (empty) empty.hidden = childCount !== 0;
  const more = panel.querySelector("[data-node-more]");
  const remaining = Number(data.remaining) || 0;
  if (more) {
    more.hidden = remaining === 0;
    more.textContent = remaining ? `${remaining} more shown in the graph` : "";
  }
  panel.setAttribute("data-selected-node", id);
  return true;
}

const MAX_SEARCH_RESULTS = 8;

/**
 * Search runs entirely over the panel payload the server already sent, so it
 * can never surface a node the reader is not allowed to see. Every match is
 * lit on the canvas; the list names the first few.
 */
export function graphSearchMatches(data, query) {
  const needle = String(query || "").trim().toLowerCase();
  if (needle === "") return null;
  const matches = [];
  for (const id of Object.keys(data || {})) {
    const entry = data[id];
    const haystack = typeof entry?.search === "string"
      ? entry.search
      : String(entry?.label || "").toLowerCase();
    if (haystack.includes(needle)) matches.push({ id, entry });
  }
  matches.sort(function (a, b) {
    const aStarts = String(a.entry?.label || "").toLowerCase().startsWith(needle);
    const bStarts = String(b.entry?.label || "").toLowerCase().startsWith(needle);
    if (aStarts !== bStarts) return aStarts ? -1 : 1;
    return String(a.entry?.label || "").localeCompare(String(b.entry?.label || ""));
  });
  return matches;
}

function runGraphSearch(input) {
  const graph = input && typeof input.closest === "function" ? input.closest(".memory-graph") : null;
  if (!graph || typeof graph.querySelector !== "function") return;
  const viewport = graph.querySelector(".memory-graph-viewport");
  const results = graph.querySelector("[data-find-results]");
  const status = graph.querySelector("[data-find-status]");
  const matches = graphSearchMatches(topologyPanelData(graph), input.value);

  if (matches === null) {
    if (results && typeof results.replaceChildren === "function") results.replaceChildren();
    if (results) results.hidden = true;
    if (status) {
      status.hidden = true;
      status.textContent = "";
    }
    highlightSearchMatches(viewport, null);
    return;
  }

  const shown = matches.slice(0, MAX_SEARCH_RESULTS);
  if (results && typeof results.replaceChildren === "function") {
    const doc = results.ownerDocument;
    results.replaceChildren(...shown.map(function (match) {
      const row = doc.createElement("li");
      const button = doc.createElement("button");
      button.type = "button";
      button.className = "memory-graph-find-result";
      button.setAttribute("data-action", "topo-jump");
      button.setAttribute("data-node-id", match.id);
      const dot = doc.createElement("span");
      dot.className = "memory-graph-child-dot";
      dot.setAttribute("data-kind", String(match.entry?.kind || ""));
      dot.setAttribute("aria-hidden", "true");
      const name = doc.createElement("b");
      name.textContent = String(match.entry?.label || "");
      const type = doc.createElement("small");
      type.textContent = String(match.entry?.type || "");
      button.append(dot, name, type);
      row.append(button);
      return row;
    }));
    results.hidden = shown.length === 0;
  }
  if (status) {
    status.hidden = false;
    status.textContent = matches.length === 0
      ? "No node matches that."
      : matches.length === shown.length
        ? `${matches.length} ${matches.length === 1 ? "match" : "matches"} · lit on the canvas`
        : `Showing ${shown.length} of ${matches.length} matches · all lit on the canvas`;
  }
  highlightSearchMatches(viewport, new Set(matches.map((match) => match.id)));
}

function highlightSearchMatches(viewport, ids) {
  if (!viewport || typeof viewport.querySelectorAll !== "function") return;
  viewport.classList.toggle("is-searching", ids !== null && ids.size > 0);
  viewport.querySelectorAll(".memory-graph-node").forEach(function (node) {
    const id = node.getAttribute("data-node-id");
    node.classList.toggle("is-match", ids !== null && ids.has(id));
  });
}

function syncGraphPanel(viewport, id) {
  if (!viewport || typeof viewport.closest !== "function") return;
  const graph = viewport.closest(".memory-graph") || viewport.closest(".memory-graph-wrap");
  if (!graph || typeof graph.querySelectorAll !== "function") return;
  const panels = Array.from(graph.querySelectorAll("[data-graph-panel]"));
  const overview = panels.find((panel) => panel.getAttribute("data-graph-panel") === "overview");
  const details = panels.find((panel) => panel.getAttribute("data-graph-panel") === "details");
  const showDetails = Boolean(id && details && renderGraphPanel(graph, details, id));
  if (overview) overview.hidden = showDetails;
  if (details) {
    details.hidden = !showDetails;
    if (!showDetails) details.removeAttribute("data-selected-node");
  }
}

function focusGraphPanelBack(viewport) {
  if (!viewport || typeof viewport.closest !== "function") return;
  const graph = viewport.closest(".memory-graph") || viewport.closest(".memory-graph-wrap");
  const back = graph && typeof graph.querySelector === "function"
    ? graph.querySelector('[data-action="topo-panel-clear"]')
    : null;
  if (back && typeof back.focus === "function") back.focus();
}

function clearTopologyFocus(viewport) {
  if (!viewport) return;
  syncWhyLines(viewport, null);
  syncGraphPanel(viewport, null);
  viewport.removeAttribute("data-focus");
  viewport.querySelectorAll(".memory-graph-edge").forEach(function (path) {
    path.classList.toggle("is-on", false);
  });
  viewport.querySelectorAll(".memory-graph-node-hit").forEach(function (hit) {
    hit.classList.toggle("is-on", false);
    if (hit.getAttribute("aria-pressed") !== null) {
      hit.setAttribute("aria-pressed", "false");
    }
  });
}

function focusTopologyNode(viewport, id) {
  viewport.setAttribute("data-focus", id);
  const connected = new Set([id]);
  viewport.querySelectorAll(".memory-graph-edge").forEach(function (path) {
    const from = path.getAttribute("data-from");
    const to = path.getAttribute("data-to");
    const on = from === id || to === id;
    path.classList.toggle("is-on", on);
    if (on) {
      connected.add(from);
      connected.add(to);
    }
  });
  viewport.querySelectorAll(".memory-graph-node-hit").forEach(function (hit) {
    const nodeId = hit.getAttribute("data-node-id");
    hit.classList.toggle("is-on", connected.has(nodeId));
    if (hit.getAttribute("aria-pressed") !== null) {
      hit.setAttribute("aria-pressed", String(nodeId === id));
    }
  });
  syncWhyLines(viewport, id);
  syncGraphPanel(viewport, id);
}

function topologyExpandedParents(viewport) {
  return new Set(
    String(viewport?.getAttribute("data-expanded") || "")
      .split(/\s+/)
      .filter(Boolean),
  );
}

function syncTopologyDisclosure(viewport, expandedParents) {
  viewport.querySelectorAll("[data-collapse-parents]").forEach(function (entry) {
    const collapseParents = String(entry.getAttribute("data-collapse-parents") || "")
      .split(/\s+/)
      .filter(Boolean);
    entry.classList.toggle(
      "is-collapsed",
      collapseParents.some((parentId) => !expandedParents.has(parentId)),
    );
  });
}

// ---------------------------------------------------------------------------
// Actions (wired by app.js via data-action). Pin the clicked concept.
// ---------------------------------------------------------------------------

export const actions = {
  // Cross-screen navigation (same contract as S2): the unified gap feed's
  // "Review" button routes the human to the S11 conflict-review flow. Pure
  // navigation - resolving a dispute happens ONLY there, never here.
  go(ctx, el) {
    const screen = el.getAttribute("data-screen");
    if (screen) ctx.go(screen);
  },
  // Spotlight a topology node: dim every ribbon except the clicked node's
  // edges and neighbors. Pure DOM state - no re-render, no API call. Clicking
  // the focused node again clears the spotlight.
  "topo-focus"(ctx, el, event) {
    if (consumeTopologyDragClick(el, event)) return;
    const viewport = el.closest(".memory-graph-viewport");
    if (!viewport) return;
    const id = el.getAttribute("data-node-id") || "";
    const clear = viewport.getAttribute("data-focus") === id;
    if (clear) {
      clearTopologyFocus(viewport);
      return;
    }
    focusTopologyNode(viewport, id);
    if (event?.detail === 0) focusGraphPanelBack(viewport);
  },
  // High-cardinality branches show five direct children by default. The parent
  // node itself is the disclosure control, so mouse, touch, and keyboard users
  // get the same compact + / - interaction without loading data again.
  "topo-toggle"(ctx, el, event) {
    if (consumeTopologyDragClick(el, event)) return;
    const viewport = el.closest(".memory-graph-viewport");
    if (!viewport) return;
    const id = el.getAttribute("data-node-id") || "";
    if (!id) return;
    const wasFocused = viewport.getAttribute("data-focus") === id;
    clearTopologyFocus(viewport);
    const expandedParents = topologyExpandedParents(viewport);
    if (wasFocused) {
      if (expandedParents.has(id)) {
        expandedParents.delete(id);
        if (expandedParents.size) viewport.setAttribute("data-expanded", Array.from(expandedParents).join(" "));
        else viewport.removeAttribute("data-expanded");
        syncTopologyDisclosure(viewport, expandedParents);
        el.setAttribute("aria-expanded", "false");
        const expandLabel = el.getAttribute("data-expand-label");
        if (expandLabel) el.setAttribute("aria-label", expandLabel);
      }
      return;
    }
    const willExpand = !expandedParents.has(id);
    if (willExpand) expandedParents.add(id);
    else expandedParents.delete(id);
    if (expandedParents.size) {
      viewport.setAttribute("data-expanded", Array.from(expandedParents).join(" "));
    } else {
      viewport.removeAttribute("data-expanded");
    }
    syncTopologyDisclosure(viewport, expandedParents);
    el.setAttribute("aria-expanded", String(willExpand));
    const label = el.getAttribute(
      willExpand ? "data-collapse-label" : "data-expand-label",
    );
    if (label) el.setAttribute("aria-label", label);
    focusTopologyNode(viewport, id);
    if (event?.detail === 0) focusGraphPanelBack(viewport);
  },
  // Selecting empty graph space returns to the complete relationship view.
  // A drag that panned the canvas ends on the same element and must not.
  "topo-clear"(ctx, el) {
    if (consumeGraphPanClick(el)) return;
    clearTopologyFocus(el);
  },
  // ---- Viewport: zoom, pan, fit, full screen. Pure client-side transforms. ----
  "topo-zoom-in"(ctx, el) {
    zoomGraphBy(graphViewport(el), 1);
  },
  "topo-zoom-out"(ctx, el) {
    zoomGraphBy(graphViewport(el), -1);
  },
  "topo-fit"(ctx, el) {
    fitGraph(graphViewport(el));
  },
  "topo-fullscreen"(ctx, el) {
    toggleGraphFullscreen(graphViewport(el), el);
  },
  "topo-zoom"(ctx, el, event) {
    const delta = Number(event && event.deltaY);
    if (!Number.isFinite(delta) || delta === 0) return;
    const rect = el.getBoundingClientRect?.();
    const origin = rect
      ? { x: Number(event.clientX) - rect.left, y: Number(event.clientY) - rect.top }
      : null;
    event.preventDefault?.();
    // A wheel notch moves the zoom 9.6% (a fifth gentler than the 12% we
    // started with), so a trackpad flick lands where the reader expects.
    zoomGraph(el, delta < 0 ? WHEEL_ZOOM_STEP : 1 / WHEEL_ZOOM_STEP, origin);
  },
  "topo-pan"(ctx, el, event) {
    handleGraphPan(event, el);
  },
  // Jump to a node named in the search results or in the inspector's link
  // lists: spotlight it and bring it to the middle of the viewport.
  "topo-jump"(ctx, el) {
    const viewport = graphViewport(el);
    const id = el.getAttribute("data-node-id") || "";
    if (!viewport || !id) return;
    focusTopologyNode(viewport, id);
    centerGraphNode(viewport, id);
  },
  // Client-side search over the nodes already rendered. Matches light up on
  // the canvas; the list offers the first few by name.
  "topo-search"(ctx, el) {
    runGraphSearch(el);
  },
  "topo-panel-clear"(ctx, el) {
    const graph = el.closest(".memory-graph");
    const viewport = graph && graph.querySelector(".memory-graph-viewport");
    clearTopologyFocus(viewport);
    if (viewport && typeof viewport.focus === "function") viewport.focus();
  },
  "topo-drag"(ctx, el, event) {
    handleTopologyPointer(event, el);
  },
  // Filters are presentational only. The full selected-subtree payload stays
  // loaded; toggling a kind hides its nodes and every touching edge.
  "topo-filter"(ctx, el) {
    const graph = el.closest(".memory-graph");
    if (!graph) return;
    const kind = el.getAttribute("data-kind") || "";
    if (!["policy", "backend", "knowledge", "skill", "retrieval", "agent"].includes(kind)) return;
    const viewport = graph.querySelector(".memory-graph-viewport");
    clearTopologyFocus(viewport);
    const enabled = el.getAttribute("aria-pressed") !== "false";
    el.setAttribute("aria-pressed", String(!enabled));
    el.classList.toggle("is-off", enabled);
    graph.querySelectorAll(`.memory-graph-node[data-kind="${kind}"]`).forEach(function (node) {
      node.classList.toggle("is-filtered", enabled);
    });
    graph.querySelectorAll(".memory-graph-edge").forEach(function (edge) {
      const touchesKind =
        edge.getAttribute("data-from-kind") === kind ||
        edge.getAttribute("data-to-kind") === kind;
      if (touchesKind) edge.classList.toggle(`is-filtered-${kind}`, enabled);
      edge.classList.toggle("is-filtered", Array.from(edge.classList).some((name) => name.startsWith("is-filtered-")));
    });
  },
  // Narrow the view to one server-offered scope. "" = the full granted union.
  async scope(ctx, el) {
    state.scope = el && el.value != null ? String(el.value) : "";
    state.scopeMenu = false;
    state.savedPage = 1;
    state.savedOpen = null;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedQuery = "";
    await ctx.refresh();
  },
  "scope-open"(ctx, el) {
    const picker = el.closest("[data-space-picker]");
    const menu = picker && picker.querySelector(".memory-scope-menu");
    if (!menu) return;
    const open = el.getAttribute("aria-expanded") === "true";
    state.scopeMenu = !open;
    el.setAttribute("aria-expanded", String(!open));
    menu.hidden = open;
  },
  async "scope-pick"(ctx, el) {
    state.scope = String(el.getAttribute("data-scope") || "");
    state.scopeMenu = false;
    state.savedPage = 1;
    state.savedOpen = null;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedQuery = "";
    // Paint the choice NOW. ctx.refresh() only swaps the DOM once the graph
    // comes back, and it marks the stage inert for the whole wait - without
    // this the menu stays open under a dead pointer and the screen reads as
    // frozen. The optimistic label is the option's own text, never a scope
    // the server did not offer; the re-render overwrites it either way.
    markScopePending(el);
    await ctx.refresh();
  },
  async "saved-memory-page"(ctx, el) {
    const page = Number(el && el.getAttribute ? el.getAttribute("data-page") : 1);
    if (!Number.isInteger(page) || page < 1 || page === state.savedPage) return;
    state.savedPage = page;
    state.savedOpen = null;
    await ctx.refresh();
  },
  "saved-memory-search"(ctx, el) {
    state.savedQuery = typeof el?.value === "string" ? el.value.slice(0, 160) : "";
    state.savedPage = 1;
    state.savedOpen = null;
    const section = el?.closest?.(".saved-memories");
    if (!section) return;
    const unavailable = !state.savedGraph;
    const view = savedMemoryView(state.savedGraph, unavailable);
    const results = section.querySelector?.("[data-saved-memory-results]");
    if (results && typeof results.innerHTML === "string") {
      results.innerHTML = renderSavedMemoryResults(ctx, view, unavailable);
    }
    const count = section.querySelector?.("[data-saved-memory-count]");
    if (count) count.textContent = view.count;
  },
  async "saved-memory-filter"(ctx, el) {
    const filter = String(el?.getAttribute?.("data-filter") || "");
    const value = String(el?.value ?? "");
    if (filter === "team") state.savedTeam = value;
    else if (filter === "created-date") state.savedCreatedDate = /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : "";
    else return;
    state.savedPage = 1;
    state.savedOpen = null;
    await ctx.refresh();
  },
  async "saved-memory-filter-clear"(ctx) {
    if (!state.savedTeam && !state.savedCreatedDate) return;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedPage = 1;
    state.savedOpen = null;
    await ctx.refresh();
  },
  async "saved-memory-open"(ctx, el) {
    const id = String(el && el.getAttribute ? el.getAttribute("data-memory-id") || "" : "");
    if (!id) return;
    state.savedOpen = id;
    if (typeof document !== "undefined") {
      document.getElementById("saved-memory-panel")?.remove();
      const list = el?.closest?.(".saved-memories") ?? document.querySelector(".saved-memories");
      const panelHtml = renderSavedMemoryPanel(ctx, state.savedGraph);
      if (list && panelHtml) list.insertAdjacentHTML("afterend", panelHtml);
      const panel = document.getElementById("saved-memory-panel");
      const opener = Array.from(document.querySelectorAll("[data-memory-id]"))
        .find((entry) => entry.getAttribute("data-memory-id") === id) || el;
      openRightPanel(panel, opener);
    }
  },
  "saved-memory-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
    state.savedOpen = null;
  },
  "saved-memory-text-toggle"(ctx, el) {
    const container = el?.closest?.("[data-collapsible-text]");
    if (!container) return;
    const expanded = container.classList.toggle("is-expanded");
    const toggle = container.querySelector(".saved-memory-text-toggle");
    toggle?.setAttribute?.("aria-expanded", String(expanded));
    if (toggle) toggle.textContent = expanded ? "See less" : "See more";
  },
  "saved-memory-link"(ctx, el) {
    const id = String(el && el.getAttribute ? el.getAttribute("data-node-id") || "" : "");
    if (!id || typeof document === "undefined") return;
    closeRightPanel(document);
    state.savedOpen = null;
    const viewport = document.querySelector(".memory-graph-viewport");
    if (!viewport) return;
    focusTopologyNode(viewport, id);
    centerGraphNode(viewport, id);
  },
  // ---- Root "View as" (read-only preview) ----
  async "viewas-open"(ctx, el) {
    const role = ctx.identity && ctx.identity.role;
    if (role !== "owner" && role !== "root") return;
    let targets = null;
    try {
      targets = await ctx.api.get("/v1/root/view-as/targets");
    } catch {
      targets = null;
    }
    state.picker = {
      tab: "person",
      pick: null,
      role: null,
      funcs: new Set(),
      reason: "",
      people: targets && Array.isArray(targets.people) ? targets.people : [],
      functions: targets && Array.isArray(targets.functions) ? targets.functions : [],
    };
    await ctx.refresh();
    if (typeof document !== "undefined") {
      const panel = document.getElementById("viewas-panel");
      const opener = document.querySelector('[data-action="viewas-open"]') || el;
      openRightPanel(panel, opener);
    }
  },
  async "viewas-close"(ctx) {
    if (typeof document !== "undefined") closeRightPanel(document);
    state.picker = null;
    await ctx.refresh();
  },
  "viewas-tab"(ctx, el) {
    const tab = el && el.getAttribute ? el.getAttribute("data-tab") : null;
    if ((tab !== "person" && tab !== "role") || !state.picker) return;
    state.picker.tab = tab;
    const panel = el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null;
    if (!panel || typeof panel.querySelectorAll !== "function") return;
    panel.querySelectorAll("[data-tab]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", String(btn.getAttribute("data-tab") === tab));
    });
    panel.querySelectorAll("[data-viewas-panel]").forEach(function (pane) {
      pane.hidden = pane.getAttribute("data-viewas-panel") !== tab;
    });
    syncStart(panel);
  },
  // Client-side filter over the root-visible people list. Pure DOM.
  "viewas-search"(ctx, el) {
    const q = String((el && el.value) || "").trim().toLowerCase();
    const panel = el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null;
    if (!panel || typeof panel.querySelectorAll !== "function") return;
    panel.querySelectorAll("[data-search]").forEach(function (row) {
      row.hidden =
        q !== "" && !String(row.getAttribute("data-search") || "").includes(q);
    });
  },
  "viewas-pick-person"(ctx, el) {
    if (!state.picker) return;
    const id = el && el.getAttribute ? el.getAttribute("data-user-id") || "" : "";
    state.picker.pick = state.picker.pick === id ? null : id;
    const panel = el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null;
    if (!panel || typeof panel.querySelectorAll !== "function") return;
    panel.querySelectorAll('[data-action="viewas-pick-person"]').forEach(function (btn) {
      btn.setAttribute(
        "aria-pressed",
        String(btn.getAttribute("data-user-id") === state.picker.pick),
      );
    });
    syncStart(panel);
  },
  "viewas-role"(ctx, el) {
    if (!state.picker) return;
    const value = el && el.getAttribute ? el.getAttribute("data-role") : null;
    if (value !== "admin" && value !== "member") return;
    state.picker.role = value;
    const panel = el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null;
    if (!panel || typeof panel.querySelectorAll !== "function") return;
    panel.querySelectorAll('[data-action="viewas-role"]').forEach(function (btn) {
      btn.setAttribute("aria-pressed", String(btn.getAttribute("data-role") === value));
    });
    syncStart(panel);
  },
  "viewas-func"(ctx, el) {
    if (!state.picker) return;
    const id = el && el.getAttribute ? el.getAttribute("data-func-id") || "" : "";
    if (!id) return;
    if (state.picker.funcs.has(id)) state.picker.funcs.delete(id);
    else state.picker.funcs.add(id);
    if (el && el.setAttribute) {
      el.setAttribute("aria-pressed", String(state.picker.funcs.has(id)));
    }
    syncStart(el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null);
  },
  "viewas-reason"(ctx, el) {
    if (!state.picker) return;
    state.picker.reason = String((el && el.value) || "");
    syncStart(el && typeof el.closest === "function" ? el.closest("[data-viewas]") : null);
  },
  async "viewas-start"(ctx) {
    const p = state.picker;
    if (!pickerValid()) return;
    const reason = String(p.reason).trim();
    const body =
      p.tab === "role"
        ? { role: p.role, functionalAreaIds: Array.from(p.funcs), reason }
        : { subjectUserId: p.pick, reason };
    const session = await ctx.api.post("/v1/root/view-as/sessions", body);
    if (!session || typeof session.token !== "string" || session.token === "") return;
    let name = session.subjectLabel != null ? String(session.subjectLabel) : "";
    let scope = session.scopeLabel != null ? String(session.scopeLabel) : "";
    if (name === "") {
      if (p.tab === "role") {
        name = p.role === "admin" ? "Admin" : "Member";
      } else {
        const person = p.people.find((entry) => entry && String(entry.id) === p.pick);
        name = person && person.name != null ? String(person.name) : "";
      }
    }
    if (scope === "") {
      // Person previews carry the subject's ROLE label (PRD §8.2) — never
      // "All accessible". With no server label the segment is dropped.
      scope =
        p.tab === "role"
          ? Array.from(p.funcs)
              .map((id) => {
                const fn = p.functions.find((entry) => entry && String(entry.id) === id);
                return fn && fn.label != null ? String(fn.label) : id;
              })
              .join(", ")
          : "";
    }
    state.preview = {
      id: session.id != null ? String(session.id) : "",
      token: session.token,
      name,
      scope,
    };
    state.picker = null;
    state.scope = "";
    state.savedPage = 1;
    state.savedOpen = null;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedQuery = "";
    await ctx.refresh();
  },
  async "viewas-exit"(ctx) {
    const preview = state.preview;
    state.preview = null;
    state.scope = "";
    state.savedPage = 1;
    state.savedOpen = null;
    state.savedTeam = "";
    state.savedCreatedDate = "";
    state.savedQuery = "";
    if (preview && preview.id) {
      try {
        await ctx.api.del(
          "/v1/root/view-as/sessions/" + encodeURIComponent(preview.id),
        );
      } catch {
        // Local state is already cleared; the server expires the credential.
      }
    }
    await ctx.refresh();
  },
};
