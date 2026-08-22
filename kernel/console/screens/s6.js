import { organizationScopeLabel, personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { isLimitError } from "../limit-toast.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";
import { lineageCanvasHtml, lineageLayout, lineageLegendHtml } from "../lineage-graph.js";

// S6 - Sources & imports. Platform catalog is global; connections are per org.

let catalogCache = [];
let credentialCache = [];
let sourceCache = [];
let sourceOverviewCache = [];
let knowledgeBaseCache = [];
let companyFileCache = [];
let companyFileUploadCache = [];
let knowledgePieceCache = [];
let teamCache = [];
let activeTeamCache = [];
let teamLoadUnavailable = false;
let activeSourceFlow = "backends";
// Scope filter for the connected-backends list: "all" or a source namespace.
let activeSourceScope = "all";
// Result of the most recent bulk refresh. It survives only the in-place
// repaint caused by that action so its success/partial-failure result remains
// next to the control that started it.
let bulkUpdateNotice = null;
/**
 * The connection whose drawer is open, kept across an in-place refresh so a
 * pause or a schedule change repaints the drawer instead of dismissing it.
 * Cleared when the screen is left.
 */
let openSourceId = null;
/**
 * Per-source lineage, keyed by source id: `undefined` = not fetched yet,
 * `null` = the read failed. The drawer draws the three states differently and
 * must never render a failure as an empty graph.
 */
const lineageCache = new Map();
const pendingCompanyFiles = new Map();
// Browser-selected bytes stay in the worker closures, while this content-free
// projection keeps an active batch visible after its upload drawer closes.
// It intentionally survives S6 cleanup so navigating away does not cancel the
// batch; returning to the knowledge base can reopen the live server progress.
const activeCompanyFileBatches = new Map();
const trackedCompanyFileUploads = new Map();
let companyFileTrackingEpoch = 0;
export const COMPANY_FILE_POST_TIMEOUT_MS = 30_000;
export const COMPANY_FILE_STATUS_TIMEOUT_MS = 15 * 60_000;
export const COMPANY_FILE_STATUS_POLL_MS = 2_000;
const COMPANY_FILE_UPLOAD_STEPS = [
  { id: "queued", label: "Accepted", help: "Safely queued on the server" },
  { id: "parsing", label: "Parsing", help: "Reading and validating the file" },
  { id: "extracting", label: "Extraction", help: "Extracting governed facts" },
  { id: "embedding", label: "Embeddings", help: "Creating vectors for semantic search" },
  { id: "finalizing", label: "Finalizing", help: "Saving provenance and the final result" },
];
let activeCategory = "all";
let wizardReturnFocus = null;
let wizardKeydownDocument = null;
let wizardKeydownHandler = null;
let wizardBackgroundState = [];
/**
 * Breadcrumb for the one-dialog-at-a-time modal stack. Every drill-down (base
 * → file, base → add knowledge, detail → delete confirm) replaces the dialog
 * in place, so without this the only exit is Close and the user loses the
 * knowledge base they were reading. Each frame records HOW to re-open the
 * parent, not its markup: Back re-renders from the live cache, so a rename or
 * a replaced file is reflected on the way back rather than restoring a stale
 * snapshot. Cleared whenever the modal closes.
 */
let wizardTrail = [];

const KNOWLEDGE_SOURCE_KINDS = new Set(["filesystem", "file-upload", "doc_site"]);
// Legacy Airtable/Notion/Google Workspace Nango cartridges remain registered
// so existing sources stay manageable, but new connections use HaloMem-owned
// direct cards. Never show both lanes to an operator.
const HIDDEN_BACKEND_CATALOG_IDS = new Set([
  "csv_sheet_import",
  "airtable",
  "notion_catalogue",
  "notion_knowledge",
  "google_drive_catalogue",
  "google_drive_knowledge",
  "google_docs_catalogue",
  "google_docs_knowledge",
  "google_sheets",
]);

const CATEGORY_COPY = {
  all: ["All sources", "Choose a service to connect."],
  commerce: ["Sales", "Orders, products, and customers."],
  pos: ["In-store sales", "In-store sales and payments."],
  support: ["Customer support", "Tickets and customer conversations."],
  crm: ["Customer relationships", "Accounts and sales activity."],
  messaging: ["Messages", "Team and customer messages."],
  marketing: ["Marketing", "Campaigns and audiences."],
  catalogue: ["Products", "Products and catalog details."],
  payments: ["Payments", "Payments and refunds."],
  fulfilment: ["Shipping", "Shipments, deliveries, and returns."],
  knowledge: ["Files and documents", "Documents and reference files."],
  productivity: ["Work and tasks", "Workspaces, projects, and tasks."],
  custom: ["Other", "Private services and files."],
};

const TRUSTED_LOGO_HOSTS = new Set(["cdn.brandfetch.io", "cdn.simpleicons.org"]);
const CONNECTOR_LOGO_FALLBACKS = Object.freeze({
  shopify: "https://cdn.simpleicons.org/shopify",
  shopify_catalogue: "https://cdn.simpleicons.org/shopify",
  woocommerce: "https://cdn.simpleicons.org/woocommerce",
  woocommerce_catalogue: "https://cdn.simpleicons.org/woocommerce",
  bigcommerce: "https://cdn.simpleicons.org/bigcommerce",
  squarespace_commerce: "https://cdn.simpleicons.org/squarespace",
  magento: "https://cdn.brandfetch.io/magento.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  rista: "https://cdn.brandfetch.io/dotpe.in/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  urbanpiper: "https://cdn.brandfetch.io/urbanpiper.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  petpooja: "https://cdn.brandfetch.io/petpooja.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  toast: "https://cdn.brandfetch.io/toasttab.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  square_pos: "https://cdn.simpleicons.org/square",
  square_payments: "https://cdn.simpleicons.org/square",
  gorgias: "https://cdn.brandfetch.io/gorgias.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  close: "https://cdn.brandfetch.io/close.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  twilio: "https://cdn.brandfetch.io/twilio.com/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  private_api_nango: "https://cdn.brandfetch.io/nango.dev/w/512/h/512?c=1idpFJMAHJJKsSfltxW",
  // The direct Linear connector is not a catalog cartridge, so it carries no
  // `entry.logo`; without this the card falls back to initials. Simple Icons
  // serves the official Linear mark in Linear's own brand colour (#5E6AD2);
  // the brandfetch host answers linear.app with HTML, not an image.
  linear_direct: "https://cdn.simpleicons.org/linear",
  airtable_direct: "https://cdn.simpleicons.org/airtable/18BFFF",
  notion: "https://cdn.simpleicons.org/notion/000000",
  notion_catalogue: "https://cdn.simpleicons.org/notion/000000",
  notion_knowledge: "https://cdn.simpleicons.org/notion/000000",
  notion_direct: "https://cdn.simpleicons.org/notion/000000",
  google_drive_direct: "https://cdn.simpleicons.org/googledrive",
  google_docs_direct: "https://cdn.simpleicons.org/googledocs",
  google_sheets_direct: "https://cdn.simpleicons.org/googlesheets",
  obsidian_vault: "https://cdn.simpleicons.org/obsidian/7C3AED",
});

/** @param {import('../app.js').Ctx} ctx @returns {Promise<string>} */
export async function render(ctx) {
  const { esc, ui } = ctx;
  const namespace = (ctx.identity && ctx.identity.namespace) || "";
  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const canWrite = canMutate(ctx);
  // A full render is a fresh page: the knowledge filters are a view concern and
  // must not survive it, or a stale team id silently empties the register.
  kbView = defaultKnowledgeView();

  // These groups are independent. Start them together so the slowest one sets
  // the critical path instead of making every later group wait its turn. Each
  // promise converts its own failure to the same brownout state used below.
  const sourceRequest = ctx.api.get("/v1/admin/sources").then(
    (view) => ({ view, sourceLoadError: null }),
    (sourceLoadError) => ({
      view: { sources: [], overview: [], latestFragmentation: null },
      sourceLoadError,
    }),
  );
  const knowledgeRequest = ctx.api.get("/v1/admin/knowledge-bases").then(
    (knowledgeResponse) => ({ knowledgeResponse, knowledgeLoadError: null }),
    (knowledgeLoadError) => ({ knowledgeResponse: { data: [] }, knowledgeLoadError }),
  );
  const teamRequest = (async () => {
    try {
      if (isOperatingMember(ctx)) {
        const profile = await ctx.api.get("/auth/profile");
        return {
          teams: Array.isArray(profile && profile.teams) ? profile.teams : [],
          teamLoadUnavailable: false,
        };
      }
      return {
        teams: await ctx.api.get("/v1/admin/teams"),
        teamLoadUnavailable: false,
      };
    } catch {
      return { teams: [], teamLoadUnavailable: true };
    }
  })();
  const catalogRequest = (async () => {
    let catalogResponse = { connectors: [] };
    let credentialResponse = [];
    try {
      catalogResponse = await ctx.api.get("/v1/admin/connectors");
      if (canWrite) credentialResponse = await ctx.api.get("/v1/admin/source-credentials");
    } catch {
      // Connected sources remain manageable during a catalog brownout.
    }
    return { catalogResponse, credentialResponse };
  })();

  const { knowledgeResponse, knowledgeLoadError } = await knowledgeRequest;
  const returnedKnowledgeBases = Array.isArray(knowledgeResponse)
    ? knowledgeResponse
    : Array.isArray(knowledgeResponse && knowledgeResponse.data)
      ? knowledgeResponse.data
      : [];
  // Deleting a knowledge base archives it (D7 — rows are never removed), so the
  // console hides archived bases instead of relying on a server-side filter.
  const loadedKnowledgeBases = returnedKnowledgeBases.filter(
    (base) => String((base && base.lifecycleState) || "active") !== "archived",
  );

  // Item reads depend only on the knowledge-base ids, not on the slower source
  // overview. Start them as soon as the base register arrives so the source
  // rollup and all 2N item calls overlap on a cold page load.
  const fileResponsesRequest = knowledgeLoadError
    ? Promise.resolve([])
    : Promise.all(loadedKnowledgeBases.map(async (base) => {
        const id = encodeURIComponent(String(base.id || ""));
        const [fileResult, pieceResult] = await Promise.all([
          ctx.api.get("/v1/admin/company-files?knowledgeBaseId=" + id + "&lifecycleState=active&includeUploads=true&pageSize=50")
            .then((files) => ({ files, fileError: null }), (fileError) => ({ files: null, fileError })),
          ctx.api.get("/v1/admin/knowledge-bases/" + id + "/sources?pageSize=50")
            .then((pieces) => ({ pieces, pieceError: null }), (pieceError) => ({ pieces: null, pieceError })),
        ]);
        return { ...fileResult, ...pieceResult };
      }));

  const { view, sourceLoadError } = await sourceRequest;

  const loadedCompanyFiles = [];
  const loadedCompanyFileUploads = [];
  const loadedKnowledgePieces = [];
  let companyFileLoadError = null;
  let knowledgePieceLoadError = null;
  if (!knowledgeLoadError) {
    const fileResponses = await fileResponsesRequest;
    for (const result of fileResponses) {
      const files = Array.isArray(result.files)
        ? result.files
        : Array.isArray(result.files && result.files.data)
          ? result.files.data
          : [];
      const pieces = Array.isArray(result.pieces)
        ? result.pieces
        : Array.isArray(result.pieces && result.pieces.data)
          ? result.pieces.data
          : [];
      loadedCompanyFiles.push(...files);
      const uploads = Array.isArray(result.files && result.files.uploads)
        ? result.files.uploads
        : [];
      loadedCompanyFileUploads.push(...uploads);
      loadedKnowledgePieces.push(...pieces);
      if (!companyFileLoadError && result.fileError) companyFileLoadError = result.fileError;
      if (!knowledgePieceLoadError && result.pieceError) knowledgePieceLoadError = result.pieceError;
    }
  }

  const teamResult = await teamRequest;
  const teams = teamResult.teams;
  teamLoadUnavailable = teamResult.teamLoadUnavailable;
  const { catalogResponse, credentialResponse } = await catalogRequest;

  const sources = Array.isArray(view && view.sources) ? view.sources : [];
  const overview = Array.isArray(view && view.overview) ? view.overview : [];
  const overviewDegraded = Boolean(view && view.overviewDegraded);
  catalogCache = Array.isArray(catalogResponse)
    ? catalogResponse
    : Array.isArray(catalogResponse && catalogResponse.connectors)
      ? catalogResponse.connectors
      : [];
  credentialCache = Array.isArray(credentialResponse)
    ? credentialResponse
    : Array.isArray(credentialResponse && credentialResponse.credentials)
      ? credentialResponse.credentials
      : [];
  sourceCache = sources;
  sourceOverviewCache = overview;
  knowledgeBaseCache = loadedKnowledgeBases;
  companyFileCache = loadedCompanyFiles;
  companyFileUploadCache = loadedCompanyFileUploads;
  knowledgePieceCache = loadedKnowledgePieces;
  teamCache = Array.isArray(teams) ? teams : [];
  activeTeamCache = teamCache
    .filter((team) => String((team && team.status) || "active") === "active");
  const backendSources = sources.filter(isBackendConnectionSource);
  const backendCatalog = catalogCache.filter(isBackendCatalogEntry);
  const isTeamIdentity = isTeamScopedSourceIdentity(ctx);
  const identityNamespace = String((ctx.identity && ctx.identity.namespace) || "");
  const teamPlacementBlocked = canWrite && (
    teamLoadUnavailable ||
    (isTeamIdentity
      ? !activeTeamCache.some((team) => String((team && team.namespace) || "") === identityNamespace)
      : activeTeamCache.length === 0)
  );

  const acts = canWrite && backendCatalog.length > 0
    ? '<button class="btn btn--solid" data-action="open-source-catalog" data-source-catalog-trigger' +
      (activeSourceFlow === "backends" ? "" : " hidden") +
      (teamPlacementBlocked ? ' disabled aria-disabled="true" title="Team placement unavailable"' : "") +
      '>Add a source</button>'
    : "";
  const head = ui.head({ eyebrow: "Operate · " + esc(nsLabel), title: "Sources", acts });
  const placementNotice = teamPlacementBlocked
    ? '<div class="source-sync-notice" role="alert"><b>' +
      (teamLoadUnavailable ? "Team list unavailable." : "No active teams are available.") +
      '</b> Backend connections are disabled until team placement is available.</div>'
    : "";
  const sourceBrowser = placementNotice +
    connectedSources(ctx, backendSources, canWrite, backendCatalog.length === 0 && canWrite) +
    (canWrite && backendCatalog.length > 0
      ? catalogSection(ctx, backendSources, canWrite, backendCatalog, teamPlacementBlocked)
      : "");

  const backendContent = sourceLoadError
    ? '<section class="card" role="alert">Backends are unavailable' + errorSuffix(sourceLoadError, esc) + "</section>"
    : (overviewDegraded ? '<div class="source-sync-notice">Some connection details could not load.</div>' : "") + sourceBrowser;
  knowledgeItemLoadError = companyFileLoadError || knowledgePieceLoadError;
  const knowledgeContent = knowledgeBaseSection(
    ctx,
    knowledgeLoadError,
    knowledgeItemLoadError,
    canWrite,
  );

  // A connection that vanished between renders (deleted, or filtered out of the
  // caller's scope) must not leave a drawer pointing at nothing.
  if (openSourceId !== null &&
      !backendSources.some((source) => String((source && source.id) || "") === openSourceId)) {
    openSourceId = null;
  }

  return (
    '<div class="source-screen screen-flow">' +
    '<div data-source-page-content>' +
    head + sourceFlowTabs(esc) +
    '<div id="source-flow-backends" role="tabpanel" aria-labelledby="source-tab-backends" data-source-flow-panel="backends"' +
    (activeSourceFlow === "backends" ? "" : " hidden") + ">" + backendContent + "</div>" +
    '<div id="source-flow-knowledge" role="tabpanel" aria-labelledby="source-tab-knowledge" data-source-flow-panel="knowledge"' +
    (activeSourceFlow === "knowledge" ? "" : " hidden") + ">" + knowledgeContent + "</div>" +
    "</div>" +
    (sourceLoadError ? "" : sourceDetailPanel(ctx, backendSources, canWrite)) +
    '<div id="connector-wizard" class="source-wizard-overlay" hidden aria-hidden="true"></div>' +
    "</div>"
  );
}

function sourceFlowTabs(esc) {
  return '<nav class="source-category-tabs filter-strip" role="tablist" aria-label="Source type">' +
    sourceFlowTab(esc, "backends", "Backends") +
    sourceFlowTab(esc, "knowledge", "Knowledge bases") + "</nav>";
}

function isOperatingMember(ctx) {
  const identity = (ctx && ctx.identity) || {};
  const audit = Array.isArray(identity.entitlements) && identity.entitlements.includes("audit:read");
  return identity.role === "member" && !audit;
}

function sourceFlowTab(esc, flow, label) {
  const selected = activeSourceFlow === flow;
  return '<button type="button" class="source-category-tab' + (selected ? " is-active" : "") +
    '" id="source-tab-' + flow + '" role="tab" data-action="switch-source-flow" data-flow="' + flow +
    '" aria-controls="source-flow-' + flow + '" aria-selected="' + (selected ? "true" : "false") +
    '" tabindex="' + (selected ? "0" : "-1") + '">' + esc(label) + "</button>";
}

// ---------------------------------------------------------------------------
// Knowledge bases. The list is a browsable register: unfiltered totals on top,
// a filter/sort strip that repaints only [data-kb-list] from the module caches
// (no refetch, so the search box keeps focus), and one row per base. Everything
// about a base — its items, its facts, delete — lives in the detail modal.
// ---------------------------------------------------------------------------

const KB_PAGE_SIZE = 10;
const KB_SORTS = [
  ["updated", "Recently updated"],
  ["name", "Name A–Z"],
  ["items", "Most items"],
  ["size", "Largest"],
];

function defaultKnowledgeView() {
  return { query: "", team: "all", type: "all", sensitivity: "all", sort: "updated", page: 0 };
}

let kbView = defaultKnowledgeView();
let knowledgeItemLoadError = null;

function hasKnowledgeFilters() {
  return kbView.query.trim() !== "" || kbView.team !== "all" ||
    kbView.type !== "all" || kbView.sensitivity !== "all";
}

/** One enriched row per base, joined against the file and piece caches. */
function knowledgeBaseModel() {
  const teamNames = new Map(teamCache.map((team) =>
    [String((team && team.id) || ""), String((team && (team.name || team.namespace)) || "Team")]));
  return knowledgeBaseCache.map((base) => {
    const id = String((base && base.id) || "");
    const files = companyFileCache.filter((file) => String(file && file.knowledgeBaseId) === id);
    const uploads = companyFileUploadCache.filter((upload) =>
      String(upload && upload.knowledgeBaseId) === id);
    const pieces = knowledgePieceCache.filter((piece) => String(piece && piece.knowledgeBaseId) === id);
    const teamId = base && base.targetTeamId ? String(base.targetTeamId) : "";
    const formats = [...new Set([
      ...files.map((file) => companyFileFormat(file)),
      ...uploads.map((upload) => companyFileFormat(upload)),
      ...pieces.map((piece) => (String(piece && piece.kind) === "website" ? "Website" : "Folder")),
    ])].sort();
    const status = String((base && base.status) || "empty");
    return {
      id,
      base: base || {},
      files,
      uploads,
      pieces,
      formats,
      teamId,
      name: String((base && base.name) || "Untitled"),
      purpose: String((base && (base.description || base.primaryBusinessFunction)) || "No description yet."),
      team: teamId ? teamNames.get(teamId) || "Restricted team" : "Organization",
      teamNames,
      sensitive: Boolean(base && base.dataSensitive),
      itemCount: Math.max(files.length, num(base && base.fileCount)) + uploads.length + pieces.length,
      byteSize: files.reduce((total, file) => total + num(file && file.byteSize), 0),
      factCount: num(base && base.factCount),
      updatedAt: String((base && (base.updatedAt || base.createdAt)) || ""),
      status,
      needsAttention: status === "failed" ||
        files.some((file) => String(file && file.status) === "failed") ||
        uploads.some((upload) => String(upload && upload.status) === "failed") ||
        pieces.some((piece) => String(piece && piece.status) === "failed"),
    };
  });
}

function knowledgeSearchText(row) {
  return [
    row.name,
    row.purpose,
    row.team,
    String(row.base.primaryBusinessFunction || ""),
    ...row.files.map((file) => String((file && (file.title || file.fileName)) || "")),
    ...row.files.map((file) => String((file && file.fileName) || "")),
    ...row.uploads.map((upload) => String((upload && (upload.title || upload.fileName)) || "")),
    ...row.pieces.map((piece) => String((piece && piece.name) || "")),
  ].join(" ").toLowerCase();
}

function filterKnowledgeRows(rows) {
  const query = kbView.query.trim().toLowerCase();
  return rows.filter((row) => {
    if (kbView.team === "org" && row.teamId) return false;
    if (kbView.team !== "all" && kbView.team !== "org" && row.teamId !== kbView.team) return false;
    if (kbView.sensitivity === "sensitive" && !row.sensitive) return false;
    if (kbView.sensitivity === "standard" && row.sensitive) return false;
    if (kbView.type !== "all" && !row.formats.includes(kbView.type)) return false;
    if (query && !knowledgeSearchText(row).includes(query)) return false;
    return true;
  });
}

function sortKnowledgeRows(rows) {
  const when = (value) => { const time = Date.parse(value); return Number.isFinite(time) ? time : 0; };
  const sorted = [...rows];
  if (kbView.sort === "name") sorted.sort((left, right) => left.name.localeCompare(right.name));
  else if (kbView.sort === "items") sorted.sort((left, right) => right.itemCount - left.itemCount);
  else if (kbView.sort === "size") sorted.sort((left, right) => right.byteSize - left.byteSize);
  else {
    sorted.sort((left, right) =>
      when(right.updatedAt) - when(left.updatedAt) || left.name.localeCompare(right.name));
  }
  return sorted;
}

function knowledgeBaseSection(ctx, error, itemError, canWrite) {
  const { esc } = ctx;
  const actions = canWrite
    ? '<button class="btn btn--solid btn--sm" data-action="open-knowledge-base" aria-controls="connector-wizard" aria-expanded="false">New knowledge base</button>'
    : '<span class="subtle">Read only</span>';
  const header = '<section class="source-standalone kb-manager"><div class="source-standalone-head"><div>' +
    '<h2>Knowledge bases' + headingInfo("Knowledge bases", "Files, folders, and public websites that agents can use as governed memory.") + '</h2></div>' +
    actions + "</div>";
  if (error) {
    return header + '<div class="source-catalog-empty" role="alert">Knowledge bases are unavailable' +
      errorSuffix(error, esc) + "</div></section>";
  }
  const rows = knowledgeBaseModel();
  if (!rows.length) {
    return header + '<div class="source-catalog-empty" role="status">No knowledge bases yet.</div></section>';
  }
  return header + knowledgeStatsHtml(rows, esc) + knowledgeFilterBarHtml(rows, esc) +
    "<div data-kb-list>" + knowledgeListHtml(rows, itemError, esc) + "</div></section>";
}

/** Totals are deliberately unfiltered — they describe the whole estate. */
function knowledgeStatsHtml(rows, esc) {
  const items = rows.reduce((total, row) => total + row.itemCount, 0);
  const sensitive = rows.filter((row) => row.sensitive).length;
  const attention = rows.filter((row) => row.needsAttention).length;
  return '<div class="grid g4 kb-stats">' +
    statCard("Knowledge bases", esc(fmt(rows.length))) +
    statCard("Items", esc(fmt(items))) +
    statCard("Sensitive", esc(fmt(sensitive))) +
    statCard("Needs attention", esc(fmt(attention)), "", attention > 0 ? "down" : "") +
    "</div>";
}

function knowledgeFilterBarHtml(rows, esc) {
  const option = (value, label, current) =>
    '<option value="' + esc(value) + '"' + (current === value ? " selected" : "") + ">" + esc(label) + "</option>";
  const teams = [...new Map(rows.filter((row) => row.teamId).map((row) => [row.teamId, row.team]))]
    .sort((left, right) => left[1].localeCompare(right[1]));
  const teamOptions = [option("all", "All teams", kbView.team)]
    .concat(rows.some((row) => !row.teamId) ? [option("org", "Organization", kbView.team)] : [])
    .concat(teams.map(([id, name]) => option(id, name, kbView.team))).join("");
  const typeOptions = [option("all", "All types", kbView.type)]
    .concat([...new Set(rows.flatMap((row) => row.formats))].sort()
      .map((format) => option(format, format, kbView.type))).join("");
  const sensitivityOptions = [
    option("all", "All data", kbView.sensitivity),
    option("sensitive", "Sensitive only", kbView.sensitivity),
    option("standard", "Standard only", kbView.sensitivity),
  ].join("");
  const sortOptions = KB_SORTS.map(([value, label]) => option(value, label, kbView.sort)).join("");
  const select = (key, label, options) =>
    '<select class="select kb-filter" aria-label="' + esc(label) + '" data-change-action="kb-filter" data-kb-filter="' +
    key + '">' + options + "</select>";
  return '<div class="kb-filters filter-strip">' +
    '<input class="input kb-search" type="search" autocomplete="off" data-input-action="kb-search"' +
    ' placeholder="Search knowledge bases, items, purpose" aria-label="Search knowledge bases" value="' +
    esc(kbView.query) + '">' +
    select("team", "Team", teamOptions) +
    select("type", "Item type", typeOptions) +
    select("sensitivity", "Sensitivity", sensitivityOptions) +
    select("sort", "Sort", sortOptions) +
    '<button type="button" class="btn btn--ghost btn--sm kb-clear" data-action="kb-clear-filters"' +
    (hasKnowledgeFilters() ? "" : " hidden") + ">Clear</button></div>";
}

function knowledgeListHtml(rows, itemError, esc) {
  const filtered = sortKnowledgeRows(filterKnowledgeRows(rows));
  const pages = Math.max(1, Math.ceil(filtered.length / KB_PAGE_SIZE));
  const page = Math.min(Math.max(0, kbView.page), pages - 1);
  kbView.page = page;
  const visible = filtered.slice(page * KB_PAGE_SIZE, (page + 1) * KB_PAGE_SIZE);
  const note = itemError
    ? '<p class="hint kb-item-note" role="status">Some knowledge items could not be loaded.</p>'
    : "";
  if (!filtered.length) {
    return '<div class="source-catalog-empty" role="status">No knowledge bases match these filters. ' +
      '<button type="button" class="btn btn--ghost btn--sm" data-action="kb-clear-filters">Clear filters</button></div>' + note;
  }
  return '<div class="tblwrap kb-wrap"><table class="kb-table" data-grid-chrome="off"><thead><tr>' +
    "<th>Knowledge base</th><th>Team</th><th>Items</th><th>Size</th><th>Sensitivity</th><th>Updated</th>" +
    '<th><span class="sr-only">Open</span></th></tr></thead><tbody>' +
    visible.map((row) => knowledgeRowHtml(row, esc)).join("") + "</tbody></table></div>" +
    knowledgePagerHtml(page, pages, esc) + note;
}

function knowledgeRowHtml(row, esc) {
  // The whole row is a pointer target; the name button carries the same action
  // so keyboard and assistive-technology users get the identical affordance.
  const open = ' data-action="open-knowledge-base-detail" data-id="' + esc(row.id) + '"';
  return '<tr class="kb-row" data-knowledge-base="' + esc(row.id) + '"' + open + ">" +
    '<td data-label="Knowledge base"><span class="kb-row-main">' +
    '<span class="kb-mark' + (row.sensitive ? " kb-mark--sensitive" : "") + '" aria-hidden="true">' +
    esc(providerInitials(row.name)) + '</span><span class="kb-row-text">' +
    '<button type="button" class="kb-row-open"' + open +
    ' aria-controls="connector-wizard" aria-expanded="false">' + esc(row.name) + "</button>" +
    '<span class="kb-row-purpose" title="' + esc(row.purpose) + '">' + esc(row.purpose) +
    "</span></span></span></td>" +
    '<td data-label="Team">' + esc(row.team) + "</td>" +
    '<td class="num" data-label="Items">' + esc(fmt(row.itemCount)) + "</td>" +
    '<td class="num" data-label="Size">' + esc(formatBytes(row.byteSize)) + "</td>" +
    '<td data-label="Sensitivity"><span class="pill' + (row.sensitive ? " pill--warn" : "") + '">' +
    (row.sensitive ? "Sensitive" : "Standard") + "</span></td>" +
    '<td data-label="Updated">' + esc(row.updatedAt ? formatWhen(row.updatedAt) : "-") + "</td>" +
    '<td class="kb-row-chevron" aria-hidden="true">' + chevronIcon() + "</td></tr>";
}

function knowledgePagerHtml(page, pages, esc) {
  if (pages < 2) return "";
  return '<div class="kb-pager">' +
    '<button type="button" class="btn btn--outline btn--sm" data-action="kb-page" data-page="' + (page - 1) + '"' +
    (page === 0 ? " disabled" : "") + ">Previous</button>" +
    '<span class="kb-pager-label mono">' + esc("Page " + (page + 1) + " of " + pages) + "</span>" +
    '<button type="button" class="btn btn--outline btn--sm" data-action="kb-page" data-page="' + (page + 1) + '"' +
    (page === pages - 1 ? " disabled" : "") + ">Next</button></div>";
}

/**
 * How many items in THIS base are still moving through the five-stage pipeline
 * (accepted, parsing, extraction, embeddings, finalizing). Counts durable
 * server-side uploads and files first; falls back to the in-page batch when a
 * fresh upload has not landed in the caches yet.
 */
function knowledgeBaseIngestCount(row) {
  const inFlight = (upload) => ["queued", "processing"].includes(String((upload && upload.status) || ""));
  const pending = (row.uploads || []).filter(inFlight).length + (row.files || []).filter(inFlight).length;
  if (pending) return pending;
  const batch = visibleCompanyFileBatch(row.id);
  return batch ? Math.max(1, batch.total - batch.settled) : 0;
}

/**
 * Ingestion takes minutes, and a base mid-run looks identical to a stalled one.
 * While anything is in flight every dialog opened on that base carries a ribbon
 * across its very top so the operator knows to wait; it disappears the moment
 * the last item settles. Scoped to one base's dialogs on purpose - it is never
 * a platform-wide banner.
 */
function kbIngestRibbonHtml(row) {
  if (!knowledgeBaseIngestCount(row)) return "";
  return '<p class="kb-ingest-ribbon" role="status" aria-live="polite">' +
    '<span class="kb-ingest-ribbon-icon" aria-hidden="true">' + ingestSpinnerIcon() + "</span>" +
    '<span class="kb-ingest-ribbon-text">Hang in tight, ingestions and embeddings in process</span></p>';
}

/** Open arc on a track: the ribbon's one moving part, and it turns, never blinks. */
function ingestSpinnerIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="8.4" fill="none" stroke="currentColor" stroke-width="2.3" opacity=".35"/>' +
    '<path d="M20.4 12A8.4 8.4 0 0 0 12 3.6" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/></svg>';
}

/**
 * The slot every knowledge dialog reserves at the top of its panel. Rendering
 * it empty still matters: the ribbon has to be able to arrive later, in place,
 * without re-rendering the dialog the operator is working in.
 */
function kbIngestRibbonSlotHtml(row) {
  return '<div data-kb-ingest-ribbon>' + (row ? kbIngestRibbonHtml(row) : "") + "</div>";
}

/** Same slot, for the dialogs that hold a raw base rather than a built row. */
function kbIngestRibbonSlotForBase(knowledgeBaseId) {
  const id = String(knowledgeBaseId || "");
  return kbIngestRibbonSlotHtml(knowledgeBaseModel().find((candidate) => candidate.id === id));
}

/** Swap the ribbon in place when server progress changes what is in flight. */
function refreshKbIngestRibbon(wizard, row) {
  const slot = wizard && wizard.querySelector && wizard.querySelector("[data-kb-ingest-ribbon]");
  if (slot) slot.innerHTML = kbIngestRibbonHtml(row);
}

/**
 * Repaint whichever dialog is open on this base. An upload starts from the file
 * dialog, not the base detail, so waiting for the operator to walk back to the
 * detail is what made the ribbon look like it only arrived on a page reload.
 */
function paintKbIngestRibbonForBase(doc, knowledgeBaseId) {
  const wizard = doc && typeof doc.getElementById === "function"
    ? doc.getElementById("connector-wizard")
    : null;
  // Every upload row update lands here, so rule the dialog out before building
  // the model: the wrong base, or no slot at all, is the common case.
  if (!wizard || typeof wizard.getAttribute !== "function") return;
  const id = String(knowledgeBaseId || "");
  if (String(wizard.getAttribute("data-knowledge-base-id") || "") !== id) return;
  if (!wizard.querySelector || !wizard.querySelector("[data-kb-ingest-ribbon]")) return;
  const row = knowledgeBaseModel().find((candidate) => candidate.id === id);
  if (row) refreshKbIngestRibbon(wizard, row);
}

/** The detail modal: facts about the base, then everything inside it. */
function knowledgeBaseDetailHtml(ctx, row, canWrite) {
  const { esc } = ctx;
  const createdBy = String(row.base.createdBy || "Unknown");
  const uploadBatch = visibleCompanyFileBatch(row.id);
  const details = [
    { label: "Team", value: row.team },
    uploadBatch
      ? { label: "Processing files", html: companyUploadBatchLinkHtml(uploadBatch, esc) }
      : { label: "Business function", value: String(row.base.primaryBusinessFunction || "General") },
    {
      label: "Created by",
      html: '<span class="kb-creator" title="' + esc(createdBy) + '">' +
        esc(creatorDisplayName(row.base, ctx.personLabel)) + "</span>",
    },
    { label: "Last updated", value: row.updatedAt ? formatWhen(row.updatedAt) : "-" },
  ].map((fact) =>
    "<div><dt>" + esc(fact.label) + "</dt><dd>" + (fact.html || esc(fact.value)) + "</dd></div>").join("");
  const stats = [
    { label: "Items", value: fmt(row.itemCount), foot: "Files and connected knowledge" },
    { label: "Facts", value: fmt(row.factCount), foot: "Governed memories extracted" },
    { label: "Total size", value: formatBytes(row.byteSize), foot: "Active uploaded files" },
    {
      label: "Sensitivity",
      value: row.sensitive ? "Sensitive" : "Standard",
      foot: row.sensitive ? "Restricted handling" : "Normal handling",
      tone: row.sensitive ? " kb-detail-stat--warn" : "",
    },
  ].map((stat) =>
    '<div class="kb-detail-stat' + (stat.tone || "") + '"><span class="k">' + esc(stat.label) +
    '</span><strong class="v">' + esc(stat.value) + '</strong><span class="kb-detail-stat-foot">' +
    esc(stat.foot) + "</span></div>").join("");
  const addKnowledge = canWrite
    ? '<button type="button" class="btn btn--outline btn--sm" data-action="open-knowledge-piece" data-id="' +
      esc(row.id) + '" aria-controls="connector-wizard" aria-expanded="false">Add knowledge</button>'
    : "";
  const footer = '<div class="source-wizard-actions kb-detail-actions">' +
    (canWrite
      ? '<button type="button" class="btn btn--ghost btn--sm knowledge-delete" data-action="delete-knowledge-base"' +
        ' aria-controls="connector-wizard" aria-label="Delete ' + esc(row.name) + '" title="Delete ' +
        esc(row.name) + '">' + trashIcon() + "<span>Delete knowledge base</span></button>"
      : '<span class="subtle">Read only</span>') +
    '<span class="kb-detail-actions-spacer"></span>' +
    (canWrite
      ? '<button type="button" class="btn btn--solid" data-action="open-knowledge-piece" data-id="' +
        esc(row.id) + '" aria-controls="connector-wizard">Add knowledge</button>'
      : "") + "</div>";
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close knowledge base details"></button>' +
    '<section class="source-wizard-dialog kb-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-detail-title">' +
    kbIngestRibbonSlotHtml(row) +
    '<div class="between source-wizard-head"><div><span class="source-category">Knowledge base</span>' +
    '<h3 id="kb-detail-title" tabindex="-1" data-wizard-focus>' + esc(row.name) + '</h3><p>' + esc(row.team) + '</p></div>' +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" data-wizard-focus aria-label="Close knowledge base details">' +
    closeIcon() + "<span>Close</span></button></div>" +
    '<div class="kb-detail-body"><section class="kb-detail-summary" aria-label="Knowledge base summary"><div class="kb-detail-stats">' +
    stats + '</div></section><section class="kb-detail-section"><h4>Details</h4><dl class="kb-detail-meta">' +
    details + '</dl></section><section class="kb-detail-section kb-detail-library"><div class="between kb-detail-items-head"><div><h4>Knowledge</h4><p>' +
    esc(fmt(row.files.length + row.uploads.length + row.pieces.length)) + ' items in this base</p></div><div class="row"><input class="input kb-file-search" type="search" autocomplete="off"' +
    ' data-input-action="kb-file-search" placeholder="Find an item" aria-label="Find an item in this knowledge base">' +
    addKnowledge + '</div></div><div data-kb-detail-items>' + knowledgeItemsHtml(row, canWrite, esc, "") +
    '</div></section></div>' + footer + "</section>";
}

function knowledgeItemsHtml(row, canWrite, esc, query) {
  const items = [
    ...row.files.map((file) => ({
      id: String((file && file.id) || ""),
      file: true,
      theme: String((file && (file.title || file.fileName)) || "Untitled file"),
      fileName: String((file && file.fileName) || "-"),
      format: companyFileFormat(file),
      size: formatBytes(file && file.byteSize),
      teamId: String((file && file.targetTeamId) || row.teamId || ""),
      status: String((file && file.status) || "processing"),
    })),
    ...row.uploads.map((upload) => ({
      id: String((upload && upload.uploadId) || ""),
      file: false,
      upload: true,
      theme: String((upload && (upload.title || upload.fileName)) || "File upload"),
      fileName: String((upload && upload.fileName) || "File name unavailable"),
      format: companyFileFormat(upload),
      size: "-",
      teamId: row.teamId,
      status: String((upload && upload.status) || "queued"),
      progress: upload,
    })),
    ...row.pieces.map((piece) => ({
      id: String((piece && piece.id) || ""),
      file: false,
      theme: String((piece && piece.name) || "Untitled knowledge"),
      fileName: "-",
      format: String(piece && piece.kind) === "website" ? "Website" : "Folder",
      size: "-",
      teamId: row.teamId,
      status: String((piece && piece.status) || "processing"),
    })),
  ].sort((left, right) => left.theme.localeCompare(right.theme));
  const needle = String(query || "").trim().toLowerCase();
  const shown = needle
    ? items.filter((item) => (item.theme + " " + item.fileName).toLowerCase().includes(needle))
    : items;
  if (!shown.length) {
    return '<div class="knowledge-base-empty" role="status">' +
      (knowledgeItemLoadError
        ? "Knowledge pieces are unavailable."
        : items.length
          ? "No items match that search."
          : "No knowledge added yet.") + "</div>";
  }
  return '<div class="kb-item-list" aria-label="Knowledge in this base">' + shown.map((item) => {
    const team = item.teamId ? row.teamNames.get(item.teamId) || "Restricted team" : "Organization";
    const activeUpload = item.upload && ["queued", "processing"].includes(item.status);
    const failedUpload = item.upload && item.status === "failed";
    const state = activeUpload
      ? '<span class="kb-item-upload-state"><span data-persisted-upload-status>' +
        esc(companyFileStageDetail(item.progress && item.progress.stage)) + '</span>' +
        companyFileStepsMarkup(esc, item.progress) + '</span>'
      : '<span class="pill' + knowledgeStatusTone(item.status) + '"><i class="dot"></i>' +
        esc(title(item.status)) + "</span>";
    const failure = failedUpload
      ? '<span class="kb-item-failure" role="alert"><strong>Why it failed:</strong> ' +
        esc(companyFileFailureText(item.progress && item.progress.failureCode, item.fileName)) + '</span>'
      : "";
    const body = '<span class="kb-item-main"><span class="kb-item-theme">' + esc(item.theme) +
      '</span><span class="kb-item-file mono">' + esc(item.fileName) + "</span></span>" +
      '<span class="kb-item-type">' + esc(item.format) + "</span>" +
      '<span class="kb-item-size num">' + esc(item.size) + "</span>" +
      state +
      '<span class="kb-item-team">' + esc(team) + "</span>" + failure;
    if (item.upload) {
      return '<div class="kb-item kb-item--upload" data-company-file-upload="' + esc(item.id) + '">' + body + "</div>";
    }
    if (!item.file) {
      return '<div class="kb-item" data-knowledge-piece="' + esc(item.id) + '">' + body + "</div>";
    }
    return '<button type="button" class="kb-item kb-item--open" data-knowledge-piece="' + esc(item.id) +
      '" data-action="open-company-file" data-id="' + esc(item.id) + '" aria-label="' +
      (canWrite ? "Edit " : "View ") + esc(item.theme) + '">' + body + "</button>";
  }).join("") + "</div>";
}

/** Repaint just the list from the caches — no refetch, so focus survives. */
function repaintKnowledgeList(ctx, el) {
  const doc = el && el.ownerDocument;
  const list = doc && typeof doc.querySelector === "function" ? doc.querySelector("[data-kb-list]") : null;
  if (!list) return;
  list.innerHTML = knowledgeListHtml(knowledgeBaseModel(), knowledgeItemLoadError, ctx.esc);
  const clear = doc.querySelector(".kb-clear");
  if (clear) clear.hidden = !hasKnowledgeFilters();
}

function companyFileRegister(bases, files, error, ctx) {
  const { esc } = ctx;
  const baseNames = new Map(bases.map((base) => [String(base.id || ""), String(base.name || "Untitled")]));
  const heading = '<div class="between source-file-register-head"><div><span class="source-category">Private company files</span>' +
    '<h3 id="source-file-register-title">Uploaded knowledge</h3></div><span class="pill pill--ok"><i class="dot"></i>Organization-scoped</span></div>';
  if (error && files.length === 0) {
    return '<section class="source-file-register" aria-labelledby="source-file-register-title">' + heading +
      '<div class="source-catalog-empty" role="alert">Uploaded files are unavailable' + errorSuffix(error, esc) + "</div></section>";
  }
  if (files.length === 0) {
    return '<section class="source-file-register" aria-labelledby="source-file-register-title">' + heading +
      '<div class="source-catalog-empty" role="status">Uploaded files will appear here.</div></section>';
  }
  const rows = files.map((file) => {
    const status = title(String((file && file.status) || "processing"));
    const statusTone = file && file.status === "ready" ? " pill--ok" : file && file.status === "failed" ? " pill--crit" : " pill--warn";
    const knowledgeBaseName = baseNames.get(String((file && file.knowledgeBaseId) || "")) || "Knowledge base";
    const uploadedBy = String((file && file.uploadedBy) || "Unknown");
    const uploader = typeof ctx.personAvatar === "function"
      ? ctx.personAvatar({ actor: uploadedBy }, "human")
      : esc(uploadedBy);
    return '<tr data-company-file="' + esc(String((file && file.id) || "")) + '"><td data-label="File"><strong>' +
      esc(String((file && file.title) || (file && file.fileName) || "Untitled file")) + '</strong><br><span class="subtle">' +
      esc(String((file && file.fileName) || "")) + '</span></td><td data-label="Knowledge base">' + esc(knowledgeBaseName) +
      '</td><td data-label="Purpose">' + esc(String((file && file.purpose) || "-")) +
      '</td><td data-label="Size">' + esc(formatBytes(file && file.byteSize)) +
      '</td><td class="num" data-label="Facts">' + esc(fmt(num(file && file.factCount))) +
      '</td><td data-label="Status"><span class="pill' + statusTone + '"><i class="dot"></i>' + esc(status) +
      '</span></td><td class="person-avatar-cell" data-label="Uploaded">' + uploader +
      '<span class="sr-only">Uploaded </span><span class="subtle person-avatar-date">' +
      esc(formatWhen(file && file.createdAt)) + "</span></td></tr>";
  }).join("");
  return '<section class="source-file-register" aria-labelledby="source-file-register-title">' + heading +
    '<div class="tblwrap"><table><thead><tr><th>File</th><th>Knowledge base</th><th>Purpose</th><th>Size</th><th>Facts</th><th>Status</th><th>Uploaded</th>' +
    '</tr></thead><tbody>' + rows + "</tbody></table></div>" +
    (error ? '<div class="subtle source-file-register-note" role="status">Some uploaded files could not be loaded.</div>' : "") + "</section>";
}

export function cleanup(reason) {
  const doc = wizardKeydownDocument;
  const wizard = doc && typeof doc.getElementById === "function"
    ? doc.getElementById("connector-wizard")
    : null;
  closeWizard(doc, wizard, false);
  pendingCompanyFiles.clear();
  companyFileTrackingEpoch += 1;
  trackedCompanyFileUploads.clear();
  activeSourceScope = "all";
  kbView = defaultKnowledgeView();
  knowledgeItemLoadError = null;
  // An in-place refresh repaints the drawer for the same connection, so its
  // identity and its already-read lineage survive. Leaving the screen does not.
  if (typeof document !== "undefined") closeRightPanel(document);
  if (reason !== "refresh") {
    openSourceId = null;
    bulkUpdateNotice = null;
    lineageCache.clear();
  }
}

const FAILURE_COPY = {
  none: ["Up to date", "pill--ok"],
  auth: ["Sign-in needed", "pill--crit"],
  config: ["Setup needed", "pill--crit"],
  "rate-limit": ["Try again later", "pill--warn"],
  network: ["Connection issue", "pill--warn"],
  "not-found": ["Source not found", "pill--crit"],
  unknown: ["Needs attention", "pill--crit"],
};

const DRIVER_COPY = {
  rest: "REST pull",
  webhook: "Webhook push",
  file: "File upload",
  builtin: "Built-in",
};

function friendlySourceError(error, failure, esc) {
  const raw = String(error || "");
  const normalized = raw.toLowerCase();
  // This block only renders because a sync FAILED. `none` reaches it when the
  // overview rollup is degraded and the class could not be derived — heading a
  // recorded failure "Up to date" is the one thing it must never say.
  let title = FAILURE_COPY[failure] && failure !== "none"
    ? FAILURE_COPY[failure][0]
    : FAILURE_COPY.unknown[0];
  let help = "Check this connection's setup, then test it again.";
  if (/enoent|no such file or directory|scandir/.test(normalized)) {
    title = "Folder unavailable";
    help = "Check that the folder still exists and Halo can access it.";
  } else if (/401|403|unauthori[sz]ed|credential|api key|token/.test(normalized)) {
    title = "Sign-in needed";
    help = "Reconnect this source or update its sign-in details.";
  } else if (/timeout|timed out|network|econn|dns/.test(normalized)) {
    title = "Could not connect";
    help = "Check the connection and try again.";
  }
  return '<strong class="source-sync-message">' + esc(title) + '</strong><span class="source-sync-help">' +
    esc(help) + '</span><details class="compact-disclosure source-technical-details"><summary>Technical details</summary>' +
    '<div class="compact-disclosure__body"><code>' +
    esc(raw) + "</code></div></details>";
}

/** Human label for the durable scheduler's next queued run. */
function nextRunLabel(row) {
  const state = String(row.nextRunState || "none");
  if (state === "running") return "Running now";
  if (state === "queued" && row.nextRunAt) return formatUntil(row.nextRunAt);
  const interval = num(row.syncIntervalSeconds);
  if (interval >= 60) return "Not queued · " + scheduleLabel(interval);
  return "Not scheduled";
}

function catalogSection(ctx, sources, canWrite, catalog = catalogCache, placementBlocked = false) {
  const { esc } = ctx;
  if (!canWrite) return "";
  const categories = [...new Set(catalog.map((entry) => String(entry.category || "custom")))];
  if (activeCategory !== "all" && !categories.includes(activeCategory)) activeCategory = "all";
  const categoryCounts = catalog.reduce((counts, entry) => {
    const category = String(entry.category || "custom");
    counts.set(category, (counts.get(category) || 0) + 1);
    return counts;
  }, new Map());
  const sourcesByKind = sources.reduce((groups, source) => {
    const kind = String((source && source.kind) || "");
    if (!groups.has(kind)) groups.set(kind, []);
    groups.get(kind).push(source);
    return groups;
  }, new Map());
  const sorted = [...catalog].sort((a, b) => {
    const delta = Number(sourcesByKind.has(String(b.id))) - Number(sourcesByKind.has(String(a.id)));
    return delta || String(a.name || a.id).localeCompare(String(b.name || b.id));
  });
  const initiallyVisible = sorted.filter((entry) =>
    activeCategory === "all" || String(entry.category || "custom") === activeCategory,
  );
  const connectedConnectorCount = initiallyVisible.filter((entry) => sourcesByKind.has(String(entry.id))).length;
  const [summaryTitle, summaryDescription] = categoryDetails(activeCategory);

  const filters = ["all", ...categories]
    .map((category) => {
      const count = category === "all" ? catalog.length : categoryCounts.get(category) || 0;
      const label = category === "all" ? "All" : categoryDetails(category)[0];
      const [categoryTitle, categoryDescription] = categoryDetails(category);
      return '<button class="source-category-tab' + (category === activeCategory ? " is-active" : "") +
      '" data-action="filter-connectors" data-category="' + esc(category) +
      '" data-label="' + esc(categoryTitle) + '" data-description="' + esc(categoryDescription) +
      '" aria-label="' + esc(label + ", " + count + " " + (count === 1 ? "service" : "services")) +
      '" aria-pressed="' + (category === activeCategory ? "true" : "false") + '">' +
      '<span class="source-category-icon" aria-hidden="true">' + categoryIcon(category) + "</span>" +
      '<span class="source-category-label">' + esc(label) + "</span>" +
      '<span class="source-category-count" aria-hidden="true">' + esc(String(count)) + "</span></button>";
    })
    .join("");

  const cards = sorted.length
    ? sorted.map((entry) => connectorCard(
        entry,
        sourcesByKind.get(String(entry.id)) || [],
        canWrite,
        esc,
        activeCategory === "all" || String(entry.category || "custom") === activeCategory,
        placementBlocked,
      )).join("")
    : '<div class="source-catalog-empty">Available services could not load. Existing connections are unaffected.</div>';
  return (
    '<details class="compact-disclosure source-browser source-catalog-disclosure" id="connector-catalog">' +
    '<summary><span><b>Add a source</b><small>' + esc(String(catalog.length)) + ' available services</small></span></summary>' +
    '<div class="compact-disclosure__body"><label class="source-page-search"><span class="sr-only">Search sources</span>' +
      searchIcon() +
      '<input name="connectorSearch" autocomplete="off" data-connector-search data-input-action="filter-connectors" placeholder="Search sources"></label>' +
    '<div class="source-category-tabs filter-strip filter-strip--scroll" aria-label="Source categories">' + filters + "</div>" +
    '<section class="source-category-summary" aria-labelledby="source-category-title">' +
    '<div class="source-summary-copy"><div class="source-summary-eyebrow" data-summary-eyebrow>Sources</div>' +
    '<h2 id="source-category-title" data-summary-title>' + esc(summaryTitle) + "</h2>" +
    '<p class="sr-only" data-summary-description>' + esc(summaryDescription) + "</p></div>" +
    '<div class="source-summary-stats"><div><span>available</span><strong data-summary-visible>' +
    esc(String(initiallyVisible.length)) + '</strong></div><div class="is-connected"><span>Connected</span><strong data-summary-connected>' +
    esc(String(connectedConnectorCount)) + "</strong></div></div></section>" +
    '<div class="source-results-line"><span data-connector-results role="status" aria-live="polite">' +
    esc(String(initiallyVisible.length)) + " " + (initiallyVisible.length === 1 ? "service" : "services") + "</span>" +
    '<span class="source-governed-label">' + shieldIcon() + "Secure connection</span></div>" +
    '<div class="source-catalog-empty" data-connector-no-results hidden>No sources match this search.</div>' +
    '<div class="source-connector-grid" data-connector-grid>' + cards + "</div>" +
    "</div></details>"
  );
}

function connectorCard(entry, sources, canWrite, esc, initiallyShown = true, placementBlocked = false) {
  const id = String(entry.id || "");
  const name = String(entry.name || id);
  const category = String(entry.category || "custom");
  const points = Array.isArray(entry.dataPoints) ? entry.dataPoints : [];
  const connectionCount = sources.length;
  const search = [id, name, category, entry.description || "", ...points.map((point) => point.label || point.key || "")]
    .join(" ")
    .toLowerCase();
  const description = categoryDetails(category)[1];
  return (
    '<article class="source-connector-card" data-connector-card data-category="' + esc(category) +
    '" data-search="' + esc(search) + '" data-connected-count="' + esc(String(connectionCount)) + '"' +
    (initiallyShown ? "" : ' style="display:none"') + ">" +
    '<div class="source-connector-top">' + connectorLogo(entry, esc) +
    (connectionCount > 0
      ? '<span class="source-connected-badge"><i></i>' + esc(String(connectionCount)) + " connected</span>"
      : '<span class="source-available-badge">Available</span>') + "</div>" +
    '<div class="source-connector-copy"><span class="source-category">' + esc(categoryDetails(category)[0]) + "</span><h3>" + esc(name) + "</h3>" +
    '<p class="sr-only">' + esc(description) + "</p></div>" +
    '<div class="source-card-footer">' +
    '<button class="source-card-action" data-action="choose-connector" data-id="' + esc(id) +
    '" aria-controls="connector-wizard" aria-expanded="false"' +
    (placementBlocked ? ' disabled aria-disabled="true" title="Team placement unavailable"' : "") + '>' +
    (connectionCount > 0 ? "Add another" : "Connect") + arrowIcon() + "</button></div>" +
    "</article>"
  );
}

function connectedSources(ctx, sources, canWrite, catalogUnavailable = false, heading = "Connection status") {
  const { esc } = ctx;
  const failing = sources.filter((source) => {
    const overview = sourceOverviewCache.find((row) => String(row && row.id || "") === String(source && source.id || ""));
    return overview && String(overview.failureClass || "none") !== "none";
  }).length;
  const awaitingObsidian = sources.filter((source) =>
    String(source && source.kind || "") === "obsidian_vault" &&
    String(source && source.syncStatus || "never_synced") === "never_synced" &&
    !source?.lastSync).length;
  // A source belongs to exactly one scope (its namespace), so the filter is a
  // client-side pass over already-loaded rows — no refetch, no server filter.
  const scopes = connectedScopeFilters(sources);
  if (activeSourceScope !== "all" && !scopes.some((scope) => scope.value === activeSourceScope)) {
    activeSourceScope = "all";
  }
  const visible = sources.filter((source) => matchesSourceScope(source, activeSourceScope));
  const refreshable = refreshableBackendSources(sources, esc);
  const rows = sources.length
    ? sources.map((source) => '<li data-source-scope-row data-scope="' +
        esc(sourceScopeKey(source)) + '"' +
        (matchesSourceScope(source, activeSourceScope) ? "" : ' style="display:none"') + ">" +
        sourceTile(source, esc) + "</li>").join("")
    : '<li class="source-catalog-empty">No connected services yet.</li>';
  const statePill = failing > 0
    ? '<span class="pill pill--crit"><i class="dot"></i>' + esc(String(failing)) + " needs attention</span>"
    : awaitingObsidian > 0
      ? '<span class="pill pill--warn"><i class="dot"></i>' + esc(String(awaitingObsidian)) +
        " awaiting Obsidian</span>"
      : '<span class="pill pill--ok"><i class="dot"></i>' + esc(String(sources.length)) + " connected</span>";
  const updateAll = canWrite && refreshable.length > 0
    ? '<button type="button" class="btn btn--outline btn--sm" data-action="update-all-sources"' +
      ' title="Update all active connections that support on-demand refresh"' +
      ' aria-controls="source-bulk-update-status" aria-label="Update all ' + esc(String(refreshable.length)) +
      ' refreshable ' + (refreshable.length === 1 ? "connection" : "connections") + '">Update all</button>'
    : "";
  const bulkMessage = bulkUpdateNotice ? bulkUpdateMessage(bulkUpdateNotice) : "";
  const headerActions = '<div class="source-standalone-head-actions"><div class="source-standalone-controls">' +
    statePill + updateAll + '</div><span id="source-bulk-update-status" class="subtle source-bulk-update-status"' +
    ' role="' + (bulkUpdateNotice && bulkUpdateNotice.failed > 0 ? "alert" : "status") + '" aria-live="polite"' +
    (bulkMessage ? "" : " hidden") + ">" + esc(bulkMessage) + "</span></div>";
  return (
    '<section class="source-standalone"><div class="source-standalone-head"><div><span class="source-category">' +
    (catalogUnavailable ? "Catalog unavailable" : "Organization sources") + "</span><h2>" + esc(heading) + "</h2>" +
    '<p>Live systems that can refresh automatically.</p></div>' +
    headerActions + "</div>" +
    connectedScopeFilterStrip(esc, scopes, visible.length) +
    '<ul class="source-standalone-list">' + rows + "</ul>" +
    '<div class="source-catalog-empty" data-scope-no-results' +
    (sources.length && visible.length === 0 ? "" : " hidden") +
    ' role="status">No connected services in this scope.</div>' +
    "</section>"
  );
}

/** Active pull connections are the exact set the bulk control may queue. */
function refreshableBackendSources(sources, esc) {
  return sources.filter((source) => {
    if (!isBackendConnectionSource(source)) return false;
    const facts = sourceFacts(source, esc);
    return Boolean(facts.id) && facts.lifecycle === "active" && facts.delivery === "rest" &&
      !facts.isWebhook && !facts.isCsvImport && !facts.isObsidian;
  });
}

function bulkUpdateMessage(result) {
  const started = Number(result && result.started) || 0;
  const failed = Number(result && result.failed) || 0;
  if (started === 0 && failed > 0) return "No updates could be started.";
  const startedCopy = started + " " + (started === 1 ? "update" : "updates") + " started.";
  return failed > 0
    ? startedCopy + " " + failed + " could not start."
    : startedCopy;
}

/** Stable per-source filter key: the namespace the source was placed in. */
function sourceScopeKey(source) {
  return String((source && source.namespace) || "");
}

function matchesSourceScope(source, scope) {
  return scope === "all" || sourceScopeKey(source) === scope;
}

/**
 * One filter chip per scope that actually has a connection, ordered with the
 * organization root first and teams after it alphabetically. Scopes with no
 * connections are omitted — an empty chip is noise, not a filter.
 */
function connectedScopeFilters(sources) {
  const counts = new Map();
  for (const source of sources) {
    const key = sourceScopeKey(source);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({
      value,
      count,
      label: sourceScopeLabel(value),
      isOrg: value.split("/").filter(Boolean).length <= 1,
    }))
    .sort((left, right) =>
      Number(right.isOrg) - Number(left.isOrg) || left.label.localeCompare(right.label));
}

function connectedScopeFilterStrip(esc, scopes, visibleCount) {
  // One scope means the filter can only ever show the same list — skip it.
  if (scopes.length < 2) return "";
  const total = scopes.reduce((sum, scope) => sum + scope.count, 0);
  const chip = (value, label, count) => {
    const selected = activeSourceScope === value;
    return '<button type="button" class="source-category-tab' + (selected ? " is-active" : "") +
      '" data-action="filter-source-scope" data-scope="' + esc(value) +
      '" aria-pressed="' + (selected ? "true" : "false") +
      '" aria-label="' + esc(label + ", " + count + " " + (count === 1 ? "connection" : "connections")) + '">' +
      '<span class="source-category-label">' + esc(label) + "</span>" +
      '<span class="source-category-count" aria-hidden="true">' + esc(String(count)) + "</span></button>";
  };
  return '<div class="source-scope-filter"><div class="source-category-tabs filter-strip filter-strip--scroll" role="group" aria-label="Filter connections by scope">' +
    chip("all", "All scopes", total) +
    scopes.map((scope) => chip(scope.value, scope.label, scope.count)).join("") +
    '</div><span class="subtle" data-scope-results role="status" aria-live="polite">' +
    esc(String(visibleCount)) + " " + (visibleCount === 1 ? "connection" : "connections") + "</span></div>";
}

/**
 * The facts every S6 surface reads off one connection. Derived once here so the
 * tile and the drawer can never disagree about a connection's health, delivery
 * or schedule — the previous single card computed them inline, which is exactly
 * the duplication that would have drifted once the two were split apart.
 */
function sourceFacts(source, esc) {
  const id = String((source && source.id) || "");
  const kind = String((source && source.kind) || "");
  const namespace = String((source && source.namespace) || "");
  const entry = catalogCache.find((candidate) => String(candidate.id) === kind);
  const isCsvImport = kind === "csv_sheet_import";
  const isWebhook = kind === "webhook_source";
  const isObsidian = kind === "obsidian_vault";
  const overview = sourceOverviewCache.find((row) => String(row && row.id || "") === id) || null;
  const overviewFailure = String(overview && overview.failureClass || "none");
  const failureCopy = FAILURE_COPY[overviewFailure] || FAILURE_COPY.unknown;
  const lifecycle = String((source && source.lifecycleState) || "active");
  // A disconnected source stays disconnected even if its final sync failed.
  // The old failure remains available in the drawer without obscuring the
  // operator-controlled lifecycle state on the tile and heading.
  const status = lifecycle === "paused"
    ? sourceStatus(source)
    : overviewFailure !== "none"
      ? { label: failureCopy[0], tone: failureCopy[1], icon: "alert", detail: "Needs attention" }
      : sourceStatus(source);
  const interval = Number(source && source.syncIntervalSeconds);
  const displayName = sourceDisplayName(kind);
  return {
    id,
    kind,
    namespace,
    entry,
    isCsvImport,
    isWebhook,
    isObsidian,
    overview,
    overviewFailure,
    status,
    interval,
    displayName,
    lifecycle,
    delivery: isWebhook
      ? "webhook"
      : isCsvImport
        ? "file"
        : entry && entry.delivery
          ? String(entry.delivery)
          : "rest",
    lastUpdated: overview
      ? overview.lastSync ? formatWhen(overview.lastSync) : "Not synced yet"
      : status.detail,
    nextUpdate: overview ? nextRunLabel(overview) : "Not scheduled",
    // A degraded rollup reports null, which must read as "not reported" — never
    // as a zero the operator would take for "this source synced nothing".
    itemCount: overview && overview.recordCount !== null && overview.recordCount !== undefined
      ? fmt(num(overview.recordCount))
      : "Not reported",
    schedule: Number.isFinite(interval) && interval >= 60 ? scheduleLabel(interval) : "Manual",
    scopeLabel: sourceScopeLabel(namespace),
    lastSyncError: (overview && overview.lastSyncError) || (source && source.lastSyncError) || null,
    consecutiveFailures: num(overview && overview.consecutiveFailures),
    brandLogo: connectorLogo(entry || { id: kind, name: displayName }, esc),
  };
}

/**
 * One connection, at a glance: mark, name, scope, health. Everything a reader
 * has to act on — details, volume, lifecycle controls — lives one click away in
 * the side panel, so a page of connections stays a page rather than a stack of
 * full-height cards.
 */
function sourceTile(source, esc) {
  const f = sourceFacts(source, esc);
  return (
    '<button type="button" class="source-tile" data-source-tile data-source-id="' + esc(f.id) +
    '" data-source-kind="' + esc(f.kind) + '" data-source-namespace="' + esc(f.namespace) +
    '" data-action="open-source-detail" data-id="' + esc(f.id) +
    '" aria-controls="source-detail-panel" aria-haspopup="dialog" aria-expanded="false">' +
    '<span class="source-connection-brand">' + f.brandLogo +
    '<span class="source-connection-state ' + f.status.tone + '" data-state-icon="' + esc(f.status.icon) +
    '" aria-hidden="true">' + sourceStateIcon(f.status.icon) + "</span></span>" +
    '<span class="source-tile-identity"><span class="source-tile-name">' + esc(f.displayName) + "</span>" +
    '<span class="source-tile-scope">' + esc(f.scopeLabel) + "</span></span>" +
    '<span class="source-tile-status ' + f.status.tone + '">' + esc(f.status.label) + "</span>" +
    "</button>"
  );
}

/**
 * The connection drawer: the same shared right panel S15 opens on a ledger row.
 * The shell is rendered with the screen (so the markup is auditable without a
 * click) and the body is repainted per connection when a tile is opened.
 */
function sourceDetailPanel(ctx, sources, canWrite) {
  const open = sources.find((source) => String((source && source.id) || "") === openSourceId) || null;
  return rightPanelHtml({
    id: "source-detail-panel",
    eyebrow: '<span data-source-detail-eyebrow>Connection</span>',
    title:
      '<span data-source-detail-title>Connection details</span>' +
      '<small data-source-detail-facts>Select a connection to manage it and see what it synced.</small>',
    closeAction: "source-detail-close",
    className: "source-detail-drawer",
    navigationIcon: false,
    body: '<div data-source-detail-body>' +
      (open
        ? sourceDetailBody(ctx, open, canWrite)
        : '<div class="sub">Select a connection to manage it and see what it synced.</div>') +
      "</div>",
  });
}

/**
 * The drawer body for one connection: health, volume, the connection facts, the
 * lineage of what it put into memory, and the controls that change it.
 *
 * `data-source-connection` is what the shared action helpers close() onto, so
 * the status region a test or a lifecycle button writes to is found here
 * exactly as it was found on the old card.
 */
function sourceDetailBody(ctx, source, canWrite) {
  const { esc } = ctx;
  const f = sourceFacts(source, esc);
  const headingId = controlId("source-name", f.id || f.kind || "connection");
  const scheduleCell = f.delivery !== "rest"
    ? '<span class="subtle">' + (f.isWebhook || f.isObsidian ? "Push events" : "On demand") + "</span>"
    : canWrite
      ? '<div class="source-schedule"><select class="select" aria-label="Update frequency for ' +
        esc(f.displayName) + '" data-source-schedule="' + esc(f.id) + '">' +
        scheduleOptions(Number.isFinite(f.interval) ? f.interval : 0) +
        '</select><button class="btn btn--ghost btn--sm" data-action="schedule-source" data-id="' +
        esc(f.id) + '">Save</button></div>'
      : esc(f.schedule);
  const actions = canWrite
    ? '<div class="source-row-actions"><button class="btn btn--outline btn--sm" data-action="test-source" data-id="' + esc(f.id) + '">Test connection</button>' +
      (f.lifecycle === "paused"
        ? '<button class="btn btn--outline btn--sm" data-action="resume-source" data-id="' + esc(f.id) + '">Reconnect</button>'
        : '<button class="btn btn--ghost btn--sm" data-action="pause-source" data-id="' + esc(f.id) + '">Disconnect</button>') +
      (f.isCsvImport
        ? '<button class="btn btn--solid btn--sm" data-action="open-csv-import" data-id="' + esc(f.id) +
          '" aria-controls="connector-wizard" aria-expanded="false">Import CSV</button>'
        : f.delivery === "rest"
          ? '<button class="btn btn--solid btn--sm" data-action="sync-source" data-id="' + esc(f.id) + '">Update now</button>'
          : "") + "</div>"
    : '<span class="subtle">Read only</span>';
  return (
    '<div class="source-detail" data-source-connection data-source-id="' + esc(f.id) +
    '" data-source-kind="' + esc(f.kind) + '" data-source-namespace="' + esc(f.namespace) +
    '" aria-labelledby="' + esc(headingId) + '">' +
    '<div class="source-detail-head"><span class="source-connection-brand">' + f.brandLogo +
    '<span class="source-connection-state ' + f.status.tone + '" data-state-icon="' + esc(f.status.icon) +
    '" aria-hidden="true">' + sourceStateIcon(f.status.icon) + "</span></span>" +
    '<div class="source-connection-identity"><h4 id="' + esc(headingId) + '">' + esc(f.displayName) +
    '</h4><span class="source-connection-scope">' + esc(f.scopeLabel) + " · " +
    esc(DRIVER_COPY[f.delivery] || DRIVER_COPY.rest) + "</span>" +
    (f.isWebhook
      ? '<span class="mono">POST /v1/webhooks/sources/' + esc(f.id) + "</span>"
      : f.isObsidian
        ? '<span class="mono">POST /v1/ingest/obsidian/' + esc(f.id) + "</span>"
        : "") + "</div>" +
    '<span class="pill ' + f.status.tone + '"><i class="dot"></i>' + esc(f.status.label) + "</span></div>" +
    (f.lastSyncError
      ? '<div class="source-connection-error">' +
        friendlySourceError(f.lastSyncError, f.overviewFailure, esc) +
        (f.consecutiveFailures > 1
          ? '<span class="subtle">' + esc(fmt(f.consecutiveFailures)) + " failed attempts</span>"
          : "") + "</div>"
      : "") +
    '<div class="grid g3 source-detail-stats">' +
    sourceDetailStat("Items", esc(f.itemCount), "In memory now") +
    sourceDetailStat("Last updated", esc(f.lastUpdated), "Most recent run") +
    sourceDetailStat("Next update", esc(f.nextUpdate), "Scheduled run") +
    "</div>" +
    // Volume and timing are the stat row above; repeating them here was the
    // one thing the drawer said twice.
    sourceDetailSection("Connection details",
      '<dl class="source-connection-details">' +
      '<div><dt>Service</dt><dd>' + esc(f.displayName) + "</dd></div>" +
      '<div><dt>Scope</dt><dd>' + esc(f.scopeLabel) + "</dd></div>" +
      '<div><dt>Delivery</dt><dd>' + esc(DRIVER_COPY[f.delivery] || DRIVER_COPY.rest) + "</dd></div>" +
      '<div><dt>Update frequency</dt><dd>' + scheduleCell + "</dd></div></dl>") +
    sourceDetailSection("Data synced",
      '<div data-source-lineage>' + sourceLineageHtml(ctx, f, lineageCache.get(f.id)) + "</div>") +
    sourceDetailSection("Manage",
      '<div class="source-connection-actions">' + actions +
      '<div class="subtle" data-source-action-status="' + esc(f.id) +
      '" role="status" aria-live="polite" tabindex="-1"></div></div>') +
    "</div>"
  );
}

function sourceDetailStat(label, value, foot) {
  return '<div class="stat stat--secondary source-detail-stat"><div class="k">' + label +
    '</div><div class="v">' + value + '</div><div class="source-detail-stat-foot">' + foot + "</div></div>";
}

function sourceDetailSection(title, body) {
  return '<section class="source-detail-section"><div class="source-detail-section-title"><span>' +
    title + "</span></div>" + body + "</section>";
}

/**
 * What this connection put into memory, drawn as the lineage graph the memory
 * drawer uses for a single saved memory: the documents and record kinds that
 * came in on the left, the storage lanes they landed in on the right.
 *
 * Every node is a server number. A rollup that browned out says so — an empty
 * graph means "this source has written nothing", and the two must never be
 * confused.
 */
function sourceLineageHtml(ctx, facts, lineage) {
  const { esc } = ctx;
  if (lineage === undefined) {
    return '<p class="saved-memory-link-empty" data-source-lineage-pending>Loading what this connection synced…</p>';
  }
  if (lineage === null || lineage.degraded === true) {
    return '<p class="saved-memory-link-empty">What this connection synced is unavailable right now.</p>';
  }
  const records = num(lineage.records);
  if (records === 0) {
    return '<p class="saved-memory-link-empty">This connection has not written anything into memory yet.</p>';
  }
  const documents = num(lineage.documents);
  const links = [];
  if (documents > 0) {
    links.push({
      label: fmt(documents) + (documents === 1 ? " document" : " documents"),
      kind: "knowledge",
      role: "Pulled from " + facts.displayName,
      side: "left",
    });
  }
  for (const bucket of Array.isArray(lineage.types) ? lineage.types : []) {
    const count = num(bucket && bucket.count);
    if (count === 0) continue;
    links.push({
      label: fmt(count) + " " + title(String((bucket && bucket.key) || "record")),
      kind: "memory",
      role: "Extracted",
      side: "left",
    });
  }
  for (const bucket of Array.isArray(lineage.tiers) ? lineage.tiers : []) {
    const count = num(bucket && bucket.count);
    if (count === 0) continue;
    const tier = String((bucket && bucket.key) || "L2");
    links.push({
      label: fmt(count) + " " + tier + (tier === "L3" ? " cold" : " warm"),
      kind: "tier",
      role: "Stored in",
      side: "right",
    });
  }
  const placed = lineageLayout(links);
  return lineageCanvasHtml({
    esc,
    core: facts.displayName,
    links: placed,
    arrowId: "source-lineage-arrow",
  }) +
    '<div class="saved-memory-link-legend-list">' +
    lineageLegendHtml({ esc, links: placed, empty: "No synced data recorded." }) +
    "</div>" +
    (lineage.lastRecordAt
      ? '<p class="source-lineage-foot">Newest record ' + esc(formatWhen(lineage.lastRecordAt)) + "</p>"
      : "");
}

export const actions = {
  "open-source-catalog"(_ctx, el) {
    const doc = el && el.ownerDocument;
    const catalog = doc && doc.getElementById("connector-catalog");
    if (!catalog) return;
    catalog.open = true;
    catalog.scrollIntoView({ behavior: "smooth", block: "start" });
    const input = catalog.querySelector("[data-connector-search]");
    if (input && typeof input.focus === "function") input.focus({ preventScroll: true });
  },

  "switch-source-flow"(_ctx, el) {
    const flow = el && el.getAttribute ? String(el.getAttribute("data-flow") || "") : "";
    const doc = el && el.ownerDocument;
    if (!doc || !["backends", "knowledge"].includes(flow)) return;
    activeSourceFlow = flow;
    doc.querySelectorAll("[data-source-flow-panel]").forEach((panel) => {
      panel.hidden = panel.getAttribute("data-source-flow-panel") !== flow;
    });
    doc.querySelectorAll('[data-action="switch-source-flow"]').forEach((tab) => {
      const selected = tab.getAttribute("data-flow") === flow;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.setAttribute("tabindex", selected ? "0" : "-1");
    });
    const search = doc.querySelector(".source-page-search");
    if (search) search.hidden = flow !== "backends";
    const catalogTrigger = doc.querySelector("[data-source-catalog-trigger]");
    if (catalogTrigger) catalogTrigger.hidden = flow !== "backends";
    const panel = doc.querySelector('[data-source-flow-panel="' + flow + '"]');
    const heading = panel && panel.querySelector && panel.querySelector("h2");
    if (heading && typeof heading.focus === "function") {
      heading.setAttribute("tabindex", "-1");
      heading.focus({ preventScroll: true });
    }
  },

  "open-knowledge-base"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!wizard || !canMutate(ctx)) return;
    restoreWizardTrigger(false);
    wizardReturnFocus = el;
    el.setAttribute?.("aria-expanded", "true");
    openWizard(el.ownerDocument, wizard, knowledgeBaseWizardHtml(ctx), {
      "data-kb-kind": "file",
    });
  },

  "toggle-kb-team-form"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const form = wizard && wizard.querySelector("[data-kb-team-form]");
    if (!form || !canMutate(ctx)) return;
    form.hidden = !form.hidden;
    el.setAttribute?.("aria-expanded", form.hidden ? "false" : "true");
    const input = !form.hidden && form.querySelector && form.querySelector('[name="newTeamName"]');
    if (input && typeof input.focus === "function") input.focus({ preventScroll: true });
  },

  async "create-kb-team"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!wizard || !canMutate(ctx)) return;
    const name = fieldValue(wizard, '[name="newTeamName"]');
    const status = wizard.querySelector("[data-kb-team-status]");
    if (!name) {
      if (status) status.textContent = "Team name is required.";
      return;
    }
    setBusy(el, true, "Creating…");
    try {
      const created = await ctx.api.post("/v1/admin/teams", { name });
      const id = created && created.id ? String(created.id) : "";
      const createdName = created && created.name ? String(created.name) : name;
      if (!id) throw { status: 502, message: "Team was not created" };
      teamCache = teamCache.filter((team) => String(team && team.id) !== id).concat(created);
      const select = wizard.querySelector('[name="targetTeamId"]');
      if (select && wizard.ownerDocument && typeof wizard.ownerDocument.createElement === "function") {
        const option = wizard.ownerDocument.createElement("option");
        option.value = id;
        option.textContent = createdName;
        select.append(option);
        select.value = id;
      }
      const form = wizard.querySelector("[data-kb-team-form]");
      if (form) form.hidden = true;
      const toggle = wizard.querySelector('[data-action="toggle-kb-team-form"]');
      toggle?.setAttribute?.("aria-expanded", "false");
      const createButton = wizard.querySelector('[data-action="create-knowledge-base"]');
      if (createButton) {
        createButton.disabled = false;
        createButton.removeAttribute?.("disabled");
      }
      const createNote = wizard.querySelector("[data-kb-create-note]");
      if (createNote) createNote.textContent = "";
      if (status) {
        status.className = "hint";
        status.textContent = "Assigned to " + createdName + ".";
      }
      select?.focus?.({ preventScroll: true });
    } catch (err) {
      if (status) {
        status.className = "source-error";
        status.textContent = "Team creation failed: " + (err && err.message ? String(err.message) : "Try again.");
      }
    } finally {
      setBusy(el, false);
    }
  },

  "open-knowledge-base-detail"(ctx, el) {
    const id = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    const row = knowledgeBaseModel().find((candidate) => candidate.id === id);
    if (!row || !wizard) return;
    restoreWizardTrigger(false);
    wizardReturnFocus = el;
    el.setAttribute?.("aria-expanded", "true");
    openWizard(doc, wizard, knowledgeBaseDetailHtml(ctx, row, canMutate(ctx)), {
      "data-knowledge-base-id": id,
    });
    resumeCompanyFileUploadTracking(ctx, wizard, row);
  },

  "kb-search"(ctx, el) {
    kbView.query = String((el && el.value) || "");
    kbView.page = 0;
    repaintKnowledgeList(ctx, el);
  },

  "kb-filter"(ctx, el) {
    const key = el && el.getAttribute ? String(el.getAttribute("data-kb-filter") || "") : "";
    const value = String((el && el.value) || "");
    if (key === "sort") kbView.sort = value;
    else if (key === "team" || key === "type" || key === "sensitivity") kbView[key] = value;
    else return;
    kbView.page = 0;
    repaintKnowledgeList(ctx, el);
  },

  "kb-clear-filters"(ctx, el) {
    kbView = defaultKnowledgeView();
    const doc = el && el.ownerDocument;
    const search = doc && doc.querySelector && doc.querySelector('[data-input-action="kb-search"]');
    if (search) search.value = "";
    doc?.querySelectorAll?.("[data-kb-filter]").forEach((select) => {
      select.value = select.getAttribute("data-kb-filter") === "sort" ? "updated" : "all";
    });
    repaintKnowledgeList(ctx, el);
  },

  "kb-page"(ctx, el) {
    const page = Number(el && el.getAttribute ? el.getAttribute("data-page") : NaN);
    if (!Number.isFinite(page) || page < 0) return;
    kbView.page = page;
    repaintKnowledgeList(ctx, el);
  },

  "kb-file-search"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    const target = wizard && wizard.querySelector("[data-kb-detail-items]");
    const id = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    const row = knowledgeBaseModel().find((candidate) => candidate.id === id);
    if (!target || !row) return;
    target.innerHTML = knowledgeItemsHtml(row, canMutate(ctx), ctx.esc, String((el && el.value) || ""));
  },

  "open-knowledge-piece"(ctx, el) {
    const id = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const base = knowledgeBaseCache.find((candidate) => String(candidate.id) === id);
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!base || !wizard || !canMutate(ctx)) return;
    pendingCompanyFiles.clear();
    // Same rule as open-company-file: reached from inside the base dialog, Back
    // returns there; reached from the page, this is the top of the stack.
    if (el.closest?.("#connector-wizard")) {
      trailPush(trailBaseFrame(base));
    } else {
      restoreWizardTrigger(false);
      wizardReturnFocus = el;
      el.setAttribute?.("aria-expanded", "true");
    }
    openWizard(el.ownerDocument, wizard, knowledgeBaseChooserHtml(ctx, base), {
      "data-knowledge-base-id": id,
    });
  },

  "open-company-file"(ctx, el) {
    const id = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const file = companyFileCache.find((candidate) => String(candidate && candidate.id) === id);
    const base = file && knowledgeBaseCache.find((candidate) =>
      String(candidate && candidate.id) === String(file.knowledgeBaseId || ""));
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!file || !base || !wizard) return;
    const teamId = String((file && file.targetTeamId) || (base && base.targetTeamId) || "");
    const team = teamId
      ? teamCache.find((candidate) => String(candidate && candidate.id) === teamId)
      : null;
    // Opened from inside the knowledge-base dialog the trigger is about to be
    // replaced, so keep the page-level trigger as the focus-return target — and
    // leave a trail frame, because that base is where Back has to land.
    if (el.closest?.("#connector-wizard")) {
      trailPush(trailBaseFrame(base));
    } else {
      restoreWizardTrigger(false);
      wizardReturnFocus = el;
      el.setAttribute?.("aria-expanded", "true");
    }
    openWizard(el.ownerDocument, wizard, companyFileDetailHtml(ctx, file, base, team), {
      "data-company-file-id": id,
      "data-knowledge-base-id": String(file.knowledgeBaseId || ""),
    });
  },

  "select-knowledge-kind"(ctx, el) {
    const kind = el && el.getAttribute ? String(el.getAttribute("data-kind") || "") : "";
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const knowledgeBaseId = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    const base = knowledgeBaseCache.find((candidate) => String(candidate.id) === knowledgeBaseId);
    if (!wizard || !base || !["file", "folder", "url"].includes(kind) || !canMutate(ctx)) return;
    const activeBatch = kind === "file" ? visibleCompanyFileBatch(knowledgeBaseId) : null;
    wizard.innerHTML = kind === "file"
      ? activeBatch
        ? companyUploadProgressDialogHtml(ctx, base, activeBatch)
        : fileUploadWizardHtml(ctx, base)
      : knowledgePieceWizardHtml(ctx, base, kind);
    wizard.setAttribute?.("data-kb-kind", kind);
    focusWizard(wizard);
  },

  "back-to-knowledge-kinds"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!wizard || !canMutate(ctx)) return;
    pendingCompanyFiles.clear();
    const knowledgeBaseId = String(wizard.getAttribute("data-knowledge-base-id") || "");
    const base = knowledgeBaseCache.find((candidate) => String(candidate.id) === knowledgeBaseId);
    if (!base) return;
    wizard.removeAttribute?.("data-kb-kind");
    wizard.innerHTML = knowledgeBaseChooserHtml(ctx, base);
    focusWizard(wizard);
  },

  "open-file-upload"(ctx, el) {
    actions["open-knowledge-piece"](ctx, el);
  },

  "clear-company-upload-purpose-error"(_ctx, el) {
    const wizard = el && typeof el.closest === "function" ? el.closest("#connector-wizard") : null;
    if (wizard && fieldValue(wizard, '[name="purpose"]')) setCompanyUploadFieldError(wizard, "purpose", "");
  },

  "select-company-files"(_ctx, el) {
    const wizard = el && typeof el.closest === "function" ? el.closest("#connector-wizard") : null;
    const queue = wizard && wizard.querySelector("[data-upload-queue]");
    const summary = wizard && wizard.querySelector("[data-upload-summary]");
    const files = [...(el && el.files ? el.files : [])];
    if (wizard && files.length) setCompanyUploadFieldError(wizard, "files", "");
    if (!queue) return;
    queue.innerHTML = files.length
      ? files.map((file, index) => uploadTitleRow(String(index), file.name, file.size, wizard)).join("")
      : '<div class="company-upload-empty">Choose one or more files to prepare them for upload.</div>';
    if (summary) summary.textContent = files.length
      ? files.length + " " + (files.length === 1 ? "file selected" : "files selected")
      : "No files selected";
  },

  async "create-knowledge-base"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!wizard || !canMutate(ctx)) return;
    const input = readKnowledgeBaseInput(wizard);
    setBusy(el, true, "Creating…");
    try {
      const created = await ctx.api.post("/v1/admin/knowledge-bases", {
        name: input.name,
        kind: "file",
        targetTeamId: input.targetTeamId,
        primaryBusinessFunction: input.primaryBusinessFunction,
        description: input.description,
        dataSensitive: input.dataSensitive,
      });
      const knowledgeBaseId = created && created.id ? String(created.id) : "";
      if (!knowledgeBaseId) throw { status: 502, message: "Knowledge base was not created" };
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } finally {
      setBusy(el, false);
    }
  },

  async "attach-knowledge-source"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const knowledgeBaseId = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    const kind = wizard && String(wizard.getAttribute("data-kb-kind") || "");
    if (!wizard || !knowledgeBaseId || !["folder", "url"].includes(kind) || !canMutate(ctx)) return;
    const input = readKnowledgePieceInput(wizard, kind);
    setBusy(el, true, "Adding…");
    try {
      let sourceId = input.sourceId;
      if (kind === "url") {
        // A website source inherits the knowledge base's team placement so
        // its crawled facts stay inside the base's scope.
        const base = knowledgeBaseCache.find((candidate) => String(candidate.id) === knowledgeBaseId);
        const baseTeamId = base && base.targetTeamId ? String(base.targetTeamId) : "";
        const source = await ctx.api.post("/v1/admin/sources", {
          kind: "doc_site",
          config: { url: input.url },
          ...(baseTeamId ? { targetTeamId: baseTeamId } : {}),
        });
        sourceId = source && source.id ? String(source.id) : "";
        if (!sourceId) throw { status: 502, message: "Website connection did not return a source" };
      }
      await ctx.api.post(
        "/v1/admin/knowledge-bases/" + encodeURIComponent(knowledgeBaseId) + "/sources",
        {
          kind: kind === "url" ? "website" : "folder",
          sourceId,
          name: input.name,
          description: input.description,
          purpose: input.purpose,
        },
      );
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } finally { setBusy(el, false); }
  },

  async "upload-company-files"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const knowledgeBaseId = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    if (!wizard || !knowledgeBaseId || !canMutate(ctx)) return;
    if (!validateCompanyUploadInput(wizard)) return;
    setBusy(el, true, "Uploading…");
    try {
      const complete = await uploadSelectedCompanyFiles(ctx, wizard, knowledgeBaseId);
      if (complete) {
        closeWizard(wizard.ownerDocument, wizard, false);
        if (sourceScreenIsCurrent(wizard.ownerDocument) && typeof ctx.go === "function") ctx.go("s6");
      }
    } finally { setBusy(el, false); }
  },

  "open-company-upload-batch"(ctx, el) {
    const id = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const batch = visibleCompanyFileBatch(id);
    const base = knowledgeBaseCache.find((candidate) => String(candidate && candidate.id) === id);
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    if (!batch || !base || !wizard) return;
    if (el.closest?.("#connector-wizard")) trailPush(trailBaseFrame(base));
    openWizard(doc, wizard, companyUploadProgressDialogHtml(ctx, base, batch), {
      "data-knowledge-base-id": id,
      "data-company-upload-batch-id": batch.id,
    });
  },

  async "replace-company-file"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const fileId = wizard && String(wizard.getAttribute("data-company-file-id") || "");
    const knowledgeBaseId = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    const current = companyFileCache.find((candidate) => String(candidate && candidate.id) === fileId);
    const status = wizard && wizard.querySelector("[data-replacement-status]");
    if (!wizard || !fileId || !knowledgeBaseId || !current || !canMutate(ctx)) return;
    const input = wizard.querySelector('[name="replacementFile"]');
    const replacement = input && input.files && input.files[0];
    const replacementTitle = fieldValue(wizard, '[name="replacementTitle"]');
    if (!replacement) {
      if (status) {
        status.className = "source-error";
        status.textContent = "Choose a replacement file.";
      }
      return;
    }
    if (!replacementTitle) {
      if (status) {
        status.className = "source-error";
        status.textContent = "Display name is required.";
      }
      return;
    }
    setBusy(el, true, "Replacing…");
    try {
      assertSafeCompanyFile(replacement);
      let replacementId = String(wizard.getAttribute("data-replacement-created-id") || "");
      if (!replacementId) {
        if (status) {
          status.className = "hint";
          status.textContent = "Uploading replacement…";
        }
        const replacementBytes = await replacement.arrayBuffer();
        const replacementFingerprint = await companyFileReplacementFingerprint({
          knowledgeBaseId,
          fileName: String(replacement.name),
          bytes: replacementBytes,
          title: replacementTitle,
          description: String(current.description || ""),
          purpose: String(current.purpose || "Company knowledge"),
        });
        const priorFingerprint = String(wizard.getAttribute("data-replacement-request-fingerprint") || "");
        let replacementPayload = {
          knowledgeBaseId,
          fileName: String(replacement.name),
          contentBase64: base64FromBytes(replacementBytes),
          idempotencyKey: priorFingerprint === replacementFingerprint
            ? String(wizard.getAttribute("data-replacement-idempotency-key") || "") || companyFileIdempotencyKey()
            : companyFileIdempotencyKey(),
          title: replacementTitle,
          description: String(current.description || ""),
          purpose: String(current.purpose || "Company knowledge"),
        };
        wizard.setAttribute("data-replacement-idempotency-key", replacementPayload.idempotencyKey);
        wizard.setAttribute("data-replacement-request-fingerprint", replacementFingerprint);
        let recovered;
        try {
          recovered = await createCompanyFileWithRecovery(ctx, replacementPayload);
        } catch (error) {
          if (!companyFileRequestEndedBeforeReservation(error)) throw error;
          replacementPayload = { ...replacementPayload, idempotencyKey: companyFileIdempotencyKey() };
          wizard.setAttribute("data-replacement-idempotency-key", replacementPayload.idempotencyKey);
          recovered = await createCompanyFileWithRecovery(ctx, replacementPayload);
        }
        const created = recovered.file;
        if (created && String(created.status || "") === "failed") {
          clearCompanyFileReplacementIdentity(wizard);
          throw new Error("Replacement file did not finish processing");
        }
        if (!created || !created.id) {
          throw new Error("Replacement file did not finish processing");
        }
        replacementId = String(created.id);
        wizard.setAttribute("data-replacement-created-id", replacementId);
        if (recovered.confirmedAfterTimeout && status) {
          status.className = "hint";
          status.textContent = "Replacement upload confirmed after the connection timed out…";
        }
      }
      if (status) status.textContent = "Finishing replacement…";
      await ctx.api.post(
        "/v1/admin/company-files/" + encodeURIComponent(fileId) + "/archive",
        {},
      );
      if (status) {
        status.className = "hint";
        status.textContent = "File replaced.";
      }
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } catch (error) {
      if (status) {
        status.className = "source-error";
        status.textContent = wizard.getAttribute("data-replacement-created-id")
          ? "The new file uploaded, but the old version could not be archived. Try again."
          : "Replacement failed: " + (error && error.message ? String(error.message) : "Try again.");
        notifyCompanyFileOutcome(ctx, "danger", "Replacement failed", status.textContent);
      }
    } finally {
      setBusy(el, false);
    }
  },

  "delete-knowledge-base"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    // Delete lives in the detail dialog, which already carries the base id; a
    // row-level trigger (if one is ever added back) carries its own data-id.
    const rowId = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const id = rowId || (wizard && String(wizard.getAttribute("data-knowledge-base-id") || "")) || "";
    const base = knowledgeBaseCache.find((candidate) => String(candidate && candidate.id) === id);
    if (!base || !wizard || !canMutate(ctx)) return;
    if (rowId) {
      restoreWizardTrigger(false);
      wizardReturnFocus = el;
      el.setAttribute?.("aria-expanded", "true");
    } else {
      // Opened from the base's own dialog: "Keep it" must return there.
      trailPush(trailBaseFrame(base));
    }
    openWizard(doc, wizard, deleteKnowledgeBaseConfirmHtml(ctx, base), {
      "data-knowledge-base-id": id,
    });
  },

  async "confirm-delete-knowledge-base"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const id = wizard && String(wizard.getAttribute("data-knowledge-base-id") || "");
    if (!wizard || !id || !canMutate(ctx)) return;
    const status = wizard.querySelector("[data-delete-status]");
    setBusy(el, true, "Deleting…");
    try {
      await ctx.api.post("/v1/admin/knowledge-bases/" + encodeURIComponent(id) + "/archive", {});
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } catch (error) {
      if (status) {
        status.className = "source-error";
        status.textContent = "Delete failed: " + (error && error.message ? String(error.message) : "Try again.");
      }
    } finally {
      setBusy(el, false);
    }
  },

  "delete-company-file"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    // The row button carries the file id; the button inside the file detail
    // dialog reuses the id the dialog was opened with.
    const rowId = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const id = rowId || (wizard && String(wizard.getAttribute("data-company-file-id") || "")) || "";
    const file = companyFileCache.find((candidate) => String(candidate && candidate.id) === id);
    const base = file && knowledgeBaseCache.find((candidate) =>
      String(candidate && candidate.id) === String(file.knowledgeBaseId || ""));
    if (!wizard || !file || !canMutate(ctx)) return;
    if (rowId) {
      restoreWizardTrigger(false);
      wizardReturnFocus = el;
      el.setAttribute?.("aria-expanded", "true");
    } else {
      // Opened from the file's own dialog: "Keep it" must return there.
      trailPush({
        kind: "company-file",
        id,
        label: "Back to " + String(file.title || file.fileName || "file"),
      });
    }
    openWizard(doc, wizard, deleteCompanyFileConfirmHtml(ctx, file, base), {
      "data-company-file-id": id,
      "data-knowledge-base-id": String(file.knowledgeBaseId || ""),
    });
  },

  async "confirm-delete-company-file"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const id = wizard && String(wizard.getAttribute("data-company-file-id") || "");
    if (!wizard || !id || !canMutate(ctx)) return;
    const status = wizard.querySelector("[data-delete-status]");
    setBusy(el, true, "Deleting…");
    try {
      await ctx.api.post("/v1/admin/company-files/" + encodeURIComponent(id) + "/archive", {});
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } catch (error) {
      if (status) {
        status.className = "source-error";
        status.textContent = "Delete failed: " + (error && error.message ? String(error.message) : "Try again.");
      }
    } finally {
      setBusy(el, false);
    }
  },

  async "retry-company-file"(ctx, el) {
    const key = el && el.getAttribute ? String(el.getAttribute("data-upload-key") || "") : "";
    const pending = pendingCompanyFiles.get(key);
    if (!pending) return;
    setBusy(el, true, "Retrying…");
    try {
      try {
        // Replay the exact durable request first. A fresh identity is safe only
        // when the server proves the prior request ended before reserving a
        // file, so no accepted work can later appear under the old key.
        await uploadOneCompanyFile(ctx, pending.wizard, key, pending.file, pending.payload);
      } catch (error) {
        if (!companyFileRequestEndedBeforeReservation(error)) throw error;
        pending.payload = { ...pending.payload, idempotencyKey: companyFileIdempotencyKey() };
        await uploadOneCompanyFile(ctx, pending.wizard, key, pending.file, pending.payload);
      }
      const hasRemaining = [...pendingCompanyFiles.values()].some((entry) => entry.wizard === pending.wizard);
      if (!hasRemaining) {
        const knowledgeBaseId = String(pending.wizard.getAttribute?.("data-knowledge-base-id") || "");
        const batch = activeCompanyFileBatches.get(knowledgeBaseId);
        if (batch) {
          batch.complete = true;
          batch.failed = batch.entries.filter((entry) => entry.status === "Failed").length;
          syncCompanyUploadBatchDom(batch);
          activeCompanyFileBatches.delete(knowledgeBaseId);
        }
        const summary = pending.wizard.querySelector("[data-upload-summary]");
        if (summary) summary.textContent = "All files uploaded";
        closeWizard(pending.wizard.ownerDocument, pending.wizard, false);
        if (sourceScreenIsCurrent(pending.wizard.ownerDocument) && typeof ctx.go === "function") ctx.go("s6");
      }
    } catch (error) {
      if (companyFileRequestStillProcessing(error)) {
        updateUploadRow(pending.wizard, key, "Processing", "the server is still working; retry to check again", true);
        return;
      }
      if (companyFileErrorIsRetryable(error)) {
        updateUploadRow(pending.wizard, key, "Failed", uploadFailureDetail(error), true);
        return;
      }
      pendingCompanyFiles.delete(key);
      updateUploadRow(pending.wizard, key, "Failed", uploadFailureDetail(error), false);
      notifyCompanyFileOutcome(ctx, "danger", "File not uploaded",
        String(pending.file.name) + ": " + uploadFailureDetail(error));
      return;
    }
    finally { setBusy(el, false); }
  },

  "toggle-catalog"(_ctx, el) {
    const panel = el && el.ownerDocument && el.ownerDocument.getElementById("connector-catalog");
    if (!panel) return;
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    const heading = panel.querySelector && panel.querySelector("#connector-catalog-title");
    if (heading && typeof heading.focus === "function") {
      heading.setAttribute("tabindex", "-1");
      heading.focus({ preventScroll: true });
    }
  },

  "filter-connectors"(ctx, el) {
    const doc = el && el.ownerDocument;
    if (!doc) return;
    const category = el.getAttribute && el.getAttribute("data-category");
    if (category) activeCategory = category;
    const searchEl = doc.querySelector("[data-connector-search]");
    const query = searchEl && searchEl.value ? String(searchEl.value).trim().toLowerCase() : "";
    let visible = 0;
    let connected = 0;
    doc.querySelectorAll("[data-connector-card]").forEach((card) => {
      const matchCategory = activeCategory === "all" || card.getAttribute("data-category") === activeCategory;
      const matchSearch = !query || String(card.getAttribute("data-search") || "").includes(query);
      const shown = matchCategory && matchSearch;
      card.style.display = shown ? "" : "none";
      if (shown) {
        visible += 1;
        if (Number(card.getAttribute("data-connected-count")) > 0) connected += 1;
      }
    });
    const wizardCard = wizardReturnFocus && typeof wizardReturnFocus.closest === "function"
      ? wizardReturnFocus.closest("[data-connector-card]")
      : null;
    if (wizardCard && wizardCard.style && wizardCard.style.display === "none") {
      const wizard = doc.getElementById && doc.getElementById("connector-wizard");
      closeWizard(doc, wizard, false);
    }
    doc.querySelectorAll("[data-action=filter-connectors][data-category]").forEach((button) => {
      const selected = button.getAttribute("data-category") === activeCategory;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-pressed", selected ? "true" : "false");
    });
    const results = doc.querySelector("[data-connector-results]");
    if (results) results.textContent = visible + " " + (visible === 1 ? "service" : "services");
    const empty = doc.querySelector("[data-connector-no-results]");
    if (empty) empty.hidden = visible !== 0;
    const visibleStat = doc.querySelector("[data-summary-visible]");
    if (visibleStat) visibleStat.textContent = String(visible);
    const connectedStat = doc.querySelector("[data-summary-connected]");
    if (connectedStat) connectedStat.textContent = String(connected);
    const [summaryTitle, summaryDescription] = categoryDetails(activeCategory);
    const summaryEyebrow = doc.querySelector("[data-summary-eyebrow]");
    if (summaryEyebrow) summaryEyebrow.textContent = "Sources";
    const summaryTitleEl = doc.querySelector("[data-summary-title]");
    if (summaryTitleEl) summaryTitleEl.textContent = summaryTitle;
    const summaryDescriptionEl = doc.querySelector("[data-summary-description]");
    if (summaryDescriptionEl) summaryDescriptionEl.textContent = summaryDescription;
  },

  "choose-connector"(ctx, el) {
    const id = el && el.getAttribute ? el.getAttribute("data-id") : "";
    const entry = catalogCache.find((candidate) => String(candidate.id) === id);
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!entry || !wizard) return;
    const identityNamespace = String((ctx.identity && ctx.identity.namespace) || "");
    const activeOwnTeam = activeTeamCache.some((team) =>
      String((team && team.namespace) || "") === identityNamespace);
    if (teamLoadUnavailable ||
        (isTeamScopedSourceIdentity(ctx) ? !activeOwnTeam : activeTeamCache.length === 0)) return;
    restoreWizardTrigger(false);
    wizardReturnFocus = el;
    if (el.setAttribute) el.setAttribute("aria-expanded", "true");
    openWizard(el.ownerDocument, wizard, wizardHtml(ctx, entry), {
      "data-connector-id": String(entry.id),
    });
  },

  "cancel-connector"(_ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    closeWizard(doc, wizard, true);
  },

  async "copy-obsidian-pairing"(_ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    const field = wizard && wizard.querySelector("[data-obsidian-pairing-bundle]");
    const status = wizard && wizard.querySelector("[data-obsidian-copy-status]");
    if (!field) return;
    const value = String(field.value || field.textContent || "");
    if (doc.defaultView?.navigator?.clipboard?.writeText) {
      await doc.defaultView.navigator.clipboard.writeText(value);
    } else {
      field.focus?.();
      field.select?.();
      doc.execCommand?.("copy");
    }
    if (status) status.textContent = "Pairing bundle copied.";
  },

  "finish-obsidian-pairing"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    closeWizard(doc, wizard, false);
    if (typeof ctx.go === "function") ctx.go("s6");
  },

  /** Step back one dialog. If the parent has since been deleted, close out. */
  "wizard-back"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    const frame = wizardTrail.pop();
    if (!wizard || !frame) return;
    pendingCompanyFiles.clear();
    if (!reopenTrailFrame(ctx, doc, wizard, frame)) closeWizard(doc, wizard, true);
  },

  async "connect-source"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    if (!wizard) return;
    const connectorId = String(wizard.getAttribute("data-connector-id") || "");
    const entry = catalogCache.find((candidate) => String(candidate.id) === connectorId);
    if (!entry) throw { status: 400, message: "Unknown connector" };

    if (entry.connect && entry.connect.kind === "local-pairing") {
      const vaultNameInput = wizard.querySelector("[data-obsidian-vault-name]");
      const vaultName = String((vaultNameInput && vaultNameInput.value) || "").trim();
      if (!vaultName) {
        vaultNameInput?.focus?.();
        throw { status: 400, message: "Vault name is required" };
      }
      const folders = (selector) => [...new Set(String((wizard.querySelector(selector) || {}).value || "")
        .split(/[\n,]+/)
        .map((value) => value.trim().replace(/\/$/, ""))
        .filter(Boolean))];
      const targetTeamId = readRequiredSourceTeam(wizard, "Choose which team can use this vault");
      const approval = wizard.querySelector("[data-namespace-open]");
      if (!approval || !approval.checked) {
        approval?.focus?.();
        throw { status: 400, message: "Approve vault-wide visibility before pairing" };
      }
      setBusy(el, true, "Creating…");
      try {
        const created = await ctx.api.post("/v1/admin/connectors/obsidian/pair", {
          vaultName,
          includedFolders: folders("[data-obsidian-included-folders]"),
          excludedFolders: folders("[data-obsidian-excluded-folders]"),
          targetTeamId,
          sourceAccessMode: "namespace-open",
        });
        const pairing = created && created.pairing;
        if (!pairing || !pairing.secret || !pairing.path || !pairing.sourceId) {
          throw { status: 502, message: "Obsidian pairing details were not returned" };
        }
        const origin = String(doc.defaultView?.location?.origin || "http://localhost");
        const bundle = {
          version: 1,
          endpoint: new URL(String(pairing.path), origin).href,
          sourceId: String(pairing.sourceId),
          secret: String(pairing.secret),
          includedFolders: Array.isArray(pairing.includedFolders) ? pairing.includedFolders : [],
          excludedFolders: Array.isArray(pairing.excludedFolders) ? pairing.excludedFolders : [],
        };
        wizard.innerHTML = obsidianPairingResultHtml(ctx, entry, bundle);
        focusWizard(wizard);
      } finally {
        setBusy(el, false);
      }
      return;
    }

    // HaloMem-owned direct OAuth: the kernel mints the provider authorize URL
    // bound to a single-use state and the caller's own identity (D9). Nothing
    // is created until the provider redirects back to the kernel callback.
    if (entry.connect && entry.connect.kind === "direct-oauth") {
      const targetTeamId = readRequiredSourceTeam(wizard, "Choose which team can use this source");
      const request = targetTeamId ? { targetTeamId } : {};
      if (entry.connect.provider === "google_drive") {
        request.sourceKind = String(entry.id || "google_drive_direct");
        const input = wizard.querySelector("[data-drive-selection]");
        const values = String((input && input.value) || "").split(/[\n,]+/)
          .map((value) => value.trim()).filter(Boolean);
        const ids = [...new Set(values.map((value) => {
          const match = value.match(/(?:\/folders\/|\/d\/)([A-Za-z0-9_-]{10,128})/) ||
            value.match(/(?:[?&]id=)([A-Za-z0-9_-]{10,128})/) ||
            value.match(/^([A-Za-z0-9_-]{10,128})$/);
          return match ? match[1] : "";
        }).filter(Boolean))];
        if (ids.length !== values.length || ids.length < 1 || ids.length > 100) {
          if (input && typeof input.focus === "function") input.focus();
          throw { status: 400, message: "Paste 1 to 100 valid Google Drive file or folder URLs or IDs" };
        }
        request.selectedItemIds = ids;
      }
      setBusy(el, true);
      try {
        const started = await ctx.api.post(
          "/v1/admin/connectors/oauth/" + encodeURIComponent(String(entry.connect.provider)) + "/start",
          request,
        );
        const authorizeUrl = String((started && started.authorizeUrl) || "");
        if (!authorizeUrl) throw { status: 502, message: "No authorization URL was returned" };
        const status = wizard.querySelector("[data-direct-connect-status]");
        if (status) status.textContent = "Opening " + String(entry.name) + " to authorize…";
        window.location.assign(authorizeUrl);
      } finally {
        setBusy(el, false);
      }
      return;
    }

    let authorizationLinkCreated = false;
    setBusy(el, true);
    try {
      const setup = await readSourceSetup(wizard, entry);
      const credentialSelect = wizard.querySelector("[data-credential-id]");
      let credentialId = credentialSelect && credentialSelect.value ? String(credentialSelect.value) : "";
      const manual = entry.auth && entry.auth.type === "manual";
      const managedNango = entry.auth && entry.auth.managedBy === "nango";
      if (!credentialId && managedNango) {
        if (entry.managedAuth && entry.managedAuth.configured === false) {
          throw { status: 503, message: "This managed connector is not configured" };
        }
        const session = await ctx.api.post("/v1/admin/nango/connect-sessions", {
          connectorId: entry.id,
          name: credentialName(wizard, entry),
        });
        showNangoConnectLink(ctx, wizard, entry, session);
        authorizationLinkCreated = true;
        return;
      }
      if (!credentialId && !manual) {
        const config = {};
        for (const field of entry.auth.fields || []) {
          if (field.role === "source") continue;
          const input = wizard.querySelector('[data-auth-key="' + cssEscape(String(field.key)) + '"]');
          const value = input && input.value != null ? String(input.value).trim() : "";
          if (field.required && !value) {
            if (input && typeof input.focus === "function") input.focus();
            throw { status: 400, message: String(field.label || field.key) + " is required" };
          }
          if (value) config[field.key] = value;
        }
        const credential = await ctx.api.post("/v1/admin/source-credentials", {
          connectorId: entry.id,
          connectionKey: entry.connectionKey,
          name: credentialName(wizard, entry),
          config,
        });
        credentialId = String(credential.id || "");
      }
      await createConfiguredSource(ctx, entry, setup, credentialId, wizard);
    } finally {
      setBusy(el, false);
      if (authorizationLinkCreated) {
        el.disabled = true;
        el.textContent = "Authorization link created";
        el.setAttribute("aria-disabled", "true");
      }
    }
  },

  async "complete-nango-connect"(ctx, el) {
    const doc = el && el.ownerDocument;
    const wizard = doc && doc.getElementById("connector-wizard");
    if (!wizard) return;
    const connectorId = String(wizard.getAttribute("data-connector-id") || "");
    const attemptId = String(wizard.getAttribute("data-nango-attempt-id") || "");
    const entry = catalogCache.find((candidate) => String(candidate.id) === connectorId);
    if (!entry || !(entry.auth && entry.auth.managedBy === "nango")) {
      throw { status: 400, message: "Unknown managed connector" };
    }
    if (!attemptId) throw { status: 400, message: "Create a new authorization link" };

    setBusy(el, true, "Completing…");
    try {
      const setup = await readSourceSetup(wizard, entry);
      const credential = await ctx.api.post(
        "/v1/admin/nango/connect-sessions/" + encodeURIComponent(attemptId) + "/complete",
        {},
      );
      const credentialId = credential && typeof credential.id === "string"
        ? credential.id
        : "";
      if (!credentialId) throw { status: 502, message: "Nango connection did not return a credential" };
      await createConfiguredSource(ctx, entry, setup, credentialId, wizard);
    } finally {
      setBusy(el, false);
    }
  },

  "filter-source-scope"(_ctx, el) {
    const scope = el && el.getAttribute ? String(el.getAttribute("data-scope") || "") : "";
    const doc = el && el.ownerDocument;
    if (!doc || !scope) return;
    activeSourceScope = scope;
    let visible = 0;
    doc.querySelectorAll("[data-source-scope-row]").forEach((row) => {
      const shown = scope === "all" || row.getAttribute("data-scope") === scope;
      row.style.display = shown ? "" : "none";
      if (shown) visible += 1;
    });
    doc.querySelectorAll('[data-action="filter-source-scope"]').forEach((chip) => {
      const selected = chip.getAttribute("data-scope") === scope;
      chip.classList.toggle("is-active", selected);
      chip.setAttribute("aria-pressed", selected ? "true" : "false");
    });
    const results = doc.querySelector("[data-scope-results]");
    if (results) results.textContent = visible + " " + (visible === 1 ? "connection" : "connections");
    const empty = doc.querySelector("[data-scope-no-results]");
    if (empty) empty.hidden = visible > 0;
  },

  "update-source-scope-copy"(_ctx, el) {
    const wizard = el && typeof el.closest === "function" ? el.closest("#connector-wizard") : null;
    const copy = wizard && wizard.querySelector("[data-scope-copy]");
    if (!copy) return;
    const value = String(el.value || "");
    if (!value) {
      copy.textContent = "the scope chosen above";
      return;
    }
    const team = teamCache.find((candidate) => String(candidate && candidate.id) === value);
    copy.textContent = "everyone in " + String((team && team.name) || "the chosen team") + " only";
  },

  async "sync-source"(ctx, el) { await sourceAction(ctx, el, "sync"); },
  async "update-all-sources"(ctx, el) {
    const sources = refreshableBackendSources(sourceCache, ctx.esc);
    if (sources.length === 0) return;
    bulkUpdateNotice = null;
    setBusy(el, true, "Updating " + sources.length + "…");
    try {
      const results = await Promise.allSettled(sources.map((source) =>
        Promise.resolve().then(() => ctx.api.post(
          "/v1/admin/sources/" + encodeURIComponent(String(source.id)) + "/sync",
          {},
        )),
      ));
      const failed = results.filter((result) => result.status === "rejected").length;
      bulkUpdateNotice = { started: results.length - failed, failed };
      results.forEach((result, index) => {
        if (result.status === "fulfilled") lineageCache.delete(String(sources[index].id));
      });
      await refreshSourceScreen(ctx);
    } finally {
      setBusy(el, false);
    }
  },
  async "test-source"(ctx, el) { await sourceAction(ctx, el, "test"); },
  async "pause-source"(ctx, el) { await sourceAction(ctx, el, "pause"); },
  async "resume-source"(ctx, el) { await sourceAction(ctx, el, "resume"); },

  /**
   * Open one connection in the shared right panel. The body paints immediately
   * from what the screen already loaded; the lineage graph is the only part
   * that waits on a request, so a slow rollup never delays the controls.
   */
  async "open-source-detail"(ctx, el) {
    const id = el && el.getAttribute ? String(el.getAttribute("data-id") || "") : "";
    const doc = el && el.ownerDocument;
    const source = sourceCache.find((row) => String((row && row.id) || "") === id);
    const panel = doc && typeof doc.getElementById === "function"
      ? doc.getElementById("source-detail-panel")
      : null;
    const body = panel && panel.querySelector ? panel.querySelector("[data-source-detail-body]") : null;
    if (!id || !source || !panel || !body) return;
    openSourceId = id;
    body.innerHTML = sourceDetailBody(ctx, source, canMutate(ctx));
    updateSourceDetailHeader(ctx, panel, source);
    openRightPanel(panel, el, doc);
    await loadSourceLineage(ctx, id, doc);
  },

  "source-detail-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
    openSourceId = null;
  },

  "open-csv-import"(ctx, el) {
    const id = el && el.getAttribute ? el.getAttribute("data-id") : "";
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    if (!id || !wizard) return;
    restoreWizardTrigger(false);
    wizardReturnFocus = el;
    if (el.setAttribute) el.setAttribute("aria-expanded", "true");
    openWizard(el.ownerDocument, wizard, csvImportHtml(ctx, id), {
      "data-source-id": String(id),
    });
  },

  async "import-csv"(ctx, el) {
    const wizard = el && el.ownerDocument && el.ownerDocument.getElementById("connector-wizard");
    const sourceId = wizard && wizard.getAttribute("data-source-id");
    if (!wizard || !sourceId) return;
    setBusy(el, true);
    try {
      const payload = await readCsvWizardPayload(wizard);
      await ctx.api.post(
        "/v1/admin/sources/" + encodeURIComponent(String(sourceId)) + "/import-csv",
        payload,
      );
      closeWizard(wizard.ownerDocument, wizard, false);
      if (typeof ctx.go === "function") ctx.go("s6");
    } finally { setBusy(el, false); }
  },

  async "schedule-source"(ctx, el) {
    const id = el && el.getAttribute ? el.getAttribute("data-id") : "";
    const doc = el && el.ownerDocument;
    const select = doc && doc.querySelector('[data-source-schedule="' + cssEscape(id) + '"]');
    if (!id || !select) return;
    const value = Number(select.value);
    bulkUpdateNotice = null;
    setBusy(el, true);
    try {
      await ctx.api.post("/v1/admin/sources/" + encodeURIComponent(id) + "/schedule", {
        intervalSeconds: Number.isFinite(value) && value >= 60 ? value : null,
      });
      await refreshSourceScreen(ctx);
    } finally { setBusy(el, false); }
  },

};

function knowledgeBaseChooserHtml(ctx, base) {
  const { esc } = ctx;
  const options = [
    {
      kind: "file",
      label: "File",
      title: "Upload files",
      description: "Add TXT, Markdown, CSV, JSON, or YAML documents.",
    },
    {
      kind: "folder",
      label: "Folder",
      title: "Connect a folder",
      description: "Use an existing governed folder connection.",
    },
    {
      kind: "url",
      label: "Website",
      title: "Add a website",
      description: "Import public documentation from an HTTPS address.",
    },
  ];
  const choices = options.map((option) =>
    '<button type="button" class="source-knowledge-option" data-action="select-knowledge-kind" data-kind="' + esc(option.kind) + '">' +
      '<span class="source-category">' + esc(option.label) + '</span><strong>' + esc(option.title) + '</strong>' +
      '<small>' + esc(option.description) + '</small><span class="source-knowledge-option-action">Continue ' + arrowIcon() + '</span></button>',
  ).join("");
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close knowledge upload"></button>' +
    '<section class="source-wizard-dialog source-knowledge-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-kind-dialog-title">' +
    '<div class="between source-wizard-head"><div><span class="source-category">Company knowledge</span>' +
    '<h3 id="kb-kind-dialog-title" tabindex="-1" data-wizard-focus>Add knowledge</h3>' +
    '<p>Add to ' + esc(String((base && base.name) || "this knowledge base")) + ".</p></div>" +
    wizardHeadActions(esc, "Close knowledge upload") +
    '</div><div class="source-knowledge-options" role="group" aria-label="Knowledge type">' + choices + "</div></section>";
}

function knowledgeBaseWizardHtml(ctx) {
  const { esc } = ctx;
  const rootNeedsTeam = (ctx.identity && ctx.identity.namespace) === "";
  const canCreate = !rootNeedsTeam || teamCache.length > 0;
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close knowledge base"></button>' +
    '<section class="source-wizard-dialog source-knowledge-form-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-dialog-title"><div class="between source-wizard-head"><div>' +
    '<span class="source-category">Company knowledge</span><h3 id="kb-dialog-title" tabindex="-1" data-wizard-focus>New knowledge base</h3>' +
    '<p>Create the container first. You can add files, folders, and websites next.</p></div>' +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Close knowledge base">' + closeIcon() + '<span>Close</span></button></div>' +
    '<div class="source-knowledge-form">' + knowledgeMetadataFields(esc, rootNeedsTeam) + '</div>' +
    '<div class="source-wizard-actions"><span style="flex:1" data-kb-create-note>' +
    (canCreate ? "" : '<span class="subtle">Create a team before adding company knowledge.</span>') +
    '</span><button class="btn btn--solid" data-action="create-knowledge-base"' + (canCreate ? "" : " disabled") +
    '>Create knowledge base</button></div></section>';
}

function knowledgePieceWizardHtml(ctx, base, kind) {
  const { esc } = ctx;
  const isFolder = kind === "folder";
  const label = isFolder ? "Connect folder" : "Add website";
  const sourceField = isFolder
    ? folderSourceField(esc)
    : '<div class="field"><label for="kb-url">Public HTTPS URL</label><input class="input" id="kb-url" name="url" type="url" inputmode="url" placeholder="https://docs.example.com" required></div>';
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close ' + esc(label) + '"></button>' +
    '<section class="source-wizard-dialog source-knowledge-form-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-piece-dialog-title"><div class="between source-wizard-head"><div>' +
    '<span class="source-category">' + esc(String((base && base.name) || "Knowledge base")) + '</span><h3 id="kb-piece-dialog-title" tabindex="-1" data-wizard-focus>' + esc(label) + '</h3></div>' +
    wizardHeadActions(esc, "Close " + label, '<button type="button" class="btn btn--ghost btn--sm" data-action="back-to-knowledge-kinds">Change type</button>') +
    "</div>" +
    '<div class="source-knowledge-form"><div class="field"><label for="kb-piece-name">Name</label><input class="input" id="kb-piece-name" name="name" maxlength="200" required></div>' +
    '<div class="field"><label for="kb-piece-description">Description</label><textarea class="input" id="kb-piece-description" name="description" maxlength="2000"></textarea></div>' +
    '<div class="field"><label for="kb-purpose">Purpose</label><input class="input" id="kb-purpose" name="purpose" maxlength="500" required></div>' + sourceField + '</div>' +
    '<div class="source-wizard-actions"><span style="flex:1"></span><button class="btn btn--solid" data-action="attach-knowledge-source">' + esc(label) + '</button></div></section>';
}

function fileUploadWizardHtml(ctx, base) {
  const { esc } = ctx;
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close file upload"></button>' +
    '<section class="source-wizard-dialog company-upload-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-upload-title">' +
    kbIngestRibbonSlotForBase(base && base.id) +
    '<div class="between source-wizard-head"><div>' +
    '<span class="source-category">' + esc(String(base.name || "File library")) + '</span><h3 id="kb-upload-title" tabindex="-1" data-wizard-focus>Add files</h3>' +
    '</div>' + wizardCloseHtml(esc, "Close file upload") +
    '</div><div class="company-upload-body">' +
    '<aside class="company-upload-server-note"><span class="company-upload-server-mark" aria-hidden="true">' + serverProgressIcon() + '</span><div><strong>Progress comes from the server</strong></div></aside>' +
    fileFields(esc) +
    '<section class="company-upload-section company-upload-files" aria-labelledby="company-upload-files-title"><div class="company-upload-section-head"><div><span>02</span>' +
    '<h4 id="company-upload-files-title">Selected files</h4></div><small>Files safely queue two at a time</small></div>' +
    '<div class="company-upload-queue" data-upload-queue role="status" aria-live="polite"><div class="company-upload-empty">Choose one or more files to prepare them for upload.</div></div></section></div>' +
    '<div class="source-wizard-actions company-upload-footer"><span data-upload-summary role="status" aria-live="polite">No files selected</span>' +
    '<button class="btn btn--solid" data-action="upload-company-files">Upload files</button></div></section>';
}

function companyUploadProgressDialogHtml(ctx, base, batch) {
  const { esc } = ctx;
  const rows = batch.entries.map((entry) => uploadQueueRow(
    entry.key,
    entry.name,
    entry.status,
    entry.retry,
    null,
    entry.progress,
    entry.detail,
  )).join("");
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close file processing"></button>' +
    '<section class="source-wizard-dialog company-upload-dialog company-upload-progress-dialog" role="dialog" aria-modal="true" aria-labelledby="kb-upload-progress-title"' +
    ' data-company-upload-batch-progress="' + esc(batch.knowledgeBaseId) + '">' +
    kbIngestRibbonSlotForBase(batch.knowledgeBaseId) +
    '<div class="between source-wizard-head"><div>' +
    '<span class="source-category">' + esc(String(base.name || "Knowledge base")) + '</span><h3 id="kb-upload-progress-title" tabindex="-1" data-wizard-focus>Processing files</h3>' +
    '<p><span data-company-upload-settled>' + esc(String(batch.settled)) + '</span> of <span data-company-upload-total>' +
    esc(String(batch.total)) + '</span> files finished</p></div>' + wizardCloseHtml(esc, "Close file processing") +
    '</div><div class="company-upload-body"><aside class="company-upload-server-note"><span class="company-upload-server-mark" aria-hidden="true">' +
    serverProgressIcon() + '</span><div><strong>Processing continues in the background</strong></div></aside>' +
    '<section class="company-upload-section company-upload-files" aria-labelledby="company-upload-progress-files-title"><div class="company-upload-section-head"><div><span>01</span>' +
    '<h4 id="company-upload-progress-files-title">Processing files</h4></div><small>Server-reported progress</small></div>' +
    '<div class="company-upload-queue" data-upload-queue role="status" aria-live="polite">' + rows + '</div></section></div>' +
    '<div class="source-wizard-actions company-upload-footer"><span data-upload-summary role="status" aria-live="polite">' +
    esc(companyUploadBatchSummary(batch)) + '</span><button type="button" class="btn btn--outline" data-action="cancel-connector">Close</button></div></section>';
}

function visibleCompanyFileBatch(knowledgeBaseId) {
  const batch = activeCompanyFileBatches.get(String(knowledgeBaseId || ""));
  if (!batch) return null;
  if (!batch.complete || batch.entries.some((entry) => entry.retry)) return batch;
  return null;
}

function companyUploadBatchLinkHtml(batch, esc) {
  return '<button type="button" class="kb-processing-files" data-action="open-company-upload-batch" data-id="' +
    esc(batch.knowledgeBaseId) + '" aria-controls="connector-wizard"><strong><span data-company-upload-settled>' +
    esc(String(batch.settled)) + '</span> / <span data-company-upload-total>' + esc(String(batch.total)) +
    '</span></strong><span class="kb-processing-files-note">' + esc(batch.failed ? batch.failed + " need attention" : "View live progress") +
    '</span></button>';
}

export function companyUploadBatchSummary(batch) {
  if (!batch) return "No active files";
  if (batch.failed) {
    const uploaded = Math.max(0, batch.settled - batch.failed);
    const processing = Math.max(0, batch.total - batch.settled);
    return [
      uploaded + " uploaded",
      processing ? processing + " processing" : "",
      batch.failed + " failed",
    ].filter(Boolean).join(" · ");
  }
  return "Processing " + batch.settled + " of " + batch.total;
}

function sourceScreenIsCurrent(doc) {
  const hash = String((doc && doc.defaultView && doc.defaultView.location && doc.defaultView.location.hash) || "");
  return !hash || hash === "#sources" || hash.startsWith("#sources?");
}

function companyFileDetailHtml(ctx, file, base, team) {
  const { esc } = ctx;
  const theme = String((file && (file.title || file.fileName)) || "Untitled file");
  const status = String((file && file.status) || "processing");
  const statusTone = knowledgeStatusTone(status);
  const sensitive = Boolean(base && base.dataSensitive);
  const teamName = team
    ? String(team.name || team.namespace || "Restricted team")
    : "Organization";
  const details = [
    { label: "File name", value: String((file && file.fileName) || "-") },
    { label: "File type", value: companyFileFormat(file) },
    { label: "Team", value: teamName },
    { label: "Uploaded by", value: String((file && file.uploadedBy) || "Unknown") },
    { label: "Uploaded", value: formatWhen(file && file.createdAt) },
    { label: "Connection", value: '<span class="pill pill--ok"><i class="dot"></i>Uploaded</span>', html: true },
  ];
  const metadata = details.map((detail) =>
    '<div><dt>' + esc(detail.label) + '</dt><dd>' + (detail.html ? detail.value : esc(detail.value)) + "</dd></div>",
  ).join("");
  const stats = [
    { label: "Status", value: title(status), tone: statusTone, pill: true },
    { label: "Facts", value: fmt(num(file && file.factCount)), foot: "Governed memories" },
    { label: "Size", value: formatBytes(file && file.byteSize), foot: "Uploaded document" },
    { label: "Sensitivity", value: sensitive ? "Sensitive" : "Standard", foot: sensitive ? "Restricted handling" : "Normal handling" },
  ].map((stat) =>
    '<div class="source-file-stat"><span class="k">' + esc(stat.label) + '</span>' +
    (stat.pill
      ? '<span class="pill' + stat.tone + '"><i class="dot"></i>' + esc(stat.value) + '</span>'
      : '<strong class="v">' + esc(stat.value) + '</strong>') +
    (stat.foot ? '<span class="source-file-stat-foot">' + esc(stat.foot) + '</span>' : '') + '</div>',
  ).join("");
  const failure = status === "failed"
    ? '<div class="source-file-alert" role="alert"><strong>Processing failed</strong><span>' +
      esc(companyFileFailureText(file && file.failureCode, file && file.fileName)) + '</span></div>'
    : "";
  const replace = canMutate(ctx)
    ? '<section class="source-file-replace" aria-labelledby="source-file-replace-title">' +
      '<div><h4 id="source-file-replace-title">Replace file</h4><p>The new file stays in this knowledge base. The current file is archived only after the replacement uploads successfully.</p></div>' +
      '<div class="field"><label for="source-file-replacement-title">Display name</label><input class="input" id="source-file-replacement-title" name="replacementTitle" maxlength="255" value="' +
      esc(theme) + '" required></div><div class="field"><label for="source-file-replacement">New file</label>' +
      '<div class="source-file-replacement-control"><input class="sr-only source-file-replacement-input" id="source-file-replacement" name="replacementFile" type="file" accept=".txt,.md,.markdown,.csv,.json,.yaml,.yml,.pdf,.docx" required>' +
      '<label class="btn btn--outline btn--sm source-file-replacement-button" for="source-file-replacement">Choose file</label></div>' +
      '<p class="hint">TXT, Markdown, CSV, JSON, YAML, PDF, or Word (DOCX) · 512 KiB maximum for text formats, 5 MiB for PDF/Word.</p></div>' +
      '<div class="source-wizard-actions"><span data-replacement-status role="status" aria-live="polite"></span>' +
      '<button class="btn btn--solid" data-action="replace-company-file">Replace file</button></div></section>' +
      '<div class="source-file-remove"><button type="button" class="btn btn--ghost btn--sm knowledge-delete" data-action="delete-company-file" aria-label="Delete ' +
      esc(theme) + '">' + trashIcon() + "<span>Delete file</span></button></div>"
    : "";
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close file details"></button>' +
    '<section class="source-wizard-dialog source-file-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="source-file-detail-title">' +
    '<div class="between source-wizard-head"><div><h3 id="source-file-detail-title" tabindex="-1" data-wizard-focus>' + esc(theme) + "</h3></div>" +
    wizardHeadActions(esc, "Close file details") +
    '</div><div class="source-file-detail-body">' + failure + '<section class="source-file-summary" aria-label="File summary"><div class="source-file-stats">' +
    stats + '</div></section><section class="source-file-section"><h4>File details</h4><dl class="source-file-meta">' + metadata +
    '</dl></section><section class="source-file-section"><h4>Usage</h4><div class="source-file-detail-copy"><div><span>Description</span><p>' +
    esc(String((file && file.description) || "No description provided.")) + '</p></div><div><span>Purpose</span><p>' +
    esc(String((file && file.purpose) || "No purpose provided.")) + "</p></div></div></section>" + replace + "</div></section>";
}

function deleteKnowledgeBaseConfirmHtml(ctx, base) {
  const name = String((base && base.name) || "this knowledge base");
  const items = num(base && base.itemCount) || num(base && base.fileCount) + num(base && base.sourceCount);
  const detail = items > 0
    ? "Its " + fmt(items) + " " + (items === 1 ? "item stops" : "items stop") + " being listed here."
    : "It has no knowledge attached.";
  return deleteConfirmHtml(ctx, {
    eyebrow: "Delete knowledge base",
    name,
    body: detail + " Facts already learned from it stay in memory and in the audit trail - deleting does not erase them.",
    confirmLabel: "Delete knowledge base",
    confirmAction: "confirm-delete-knowledge-base",
  });
}

function deleteCompanyFileConfirmHtml(ctx, file, base) {
  const name = String((file && (file.title || file.fileName)) || "this file");
  const baseName = String((base && base.name) || "this knowledge base");
  return deleteConfirmHtml(ctx, {
    eyebrow: "Delete file",
    name,
    body: "It stops appearing in " + baseName +
      ". Facts already learned from it stay in memory and in the audit trail - deleting does not erase them.",
    confirmLabel: "Delete file",
    confirmAction: "confirm-delete-company-file",
  });
}

function deleteConfirmHtml(ctx, options) {
  const { esc } = ctx;
  const label = "Delete " + options.name;
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Cancel delete"></button>' +
    '<section class="source-wizard-dialog source-delete-dialog" role="alertdialog" aria-modal="true" aria-labelledby="source-delete-title" aria-describedby="source-delete-body">' +
    '<div class="between source-wizard-head"><div><span class="source-category">' + esc(options.eyebrow) + "</span>" +
    '<h3 id="source-delete-title" tabindex="-1" data-wizard-focus>' + esc(label) + "?</h3></div>" +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Cancel delete">' +
    closeIcon() + "<span>Close</span></button></div>" +
    '<p id="source-delete-body" class="source-delete-body">' + esc(options.body) + "</p>" +
    '<div class="source-wizard-actions"><span data-delete-status role="status" aria-live="polite"></span>' +
    // Backing out of a confirm should return to what you were reading, not
    // dump you back on the page — the head's Close still does that.
    '<button type="button" class="btn btn--ghost" data-action="' +
    (trailTop() ? "wizard-back" : "cancel-connector") + '">Keep it</button>' +
    '<button type="button" class="btn btn--danger" data-action="' + esc(options.confirmAction) + '">' +
    esc(options.confirmLabel) + "</button></div></section>";
}

function knowledgeMetadataFields(esc, rootNeedsTeam) {
  const choices = (rootNeedsTeam
    ? ['<option value="" disabled selected>Choose a team</option>']
    : ['<option value="">Organization</option>']).concat(teamCache.map((team) =>
      '<option value="' + esc(String(team.id || "")) + '">' + esc(String(team.name || team.namespace || "Team")) + "</option>",
    )).join("");
  const accessField = '<div class="field"><label for="kb-visibility">Team</label>' +
    '<div class="source-access-control"><select class="select" id="kb-visibility" name="targetTeamId">' + choices + '</select>' +
    '<button type="button" class="btn btn--outline btn--sm" data-action="toggle-kb-team-form" aria-controls="kb-team-form" aria-expanded="false">New team</button></div>' +
    (rootNeedsTeam ? '<p class="hint">Choose the organization or team that owns this knowledge.</p>' : '') +
    '<div class="source-inline-team" id="kb-team-form" data-kb-team-form hidden><label for="kb-new-team-name">New team name</label>' +
    '<div class="source-access-control"><input class="input" id="kb-new-team-name" name="newTeamName" maxlength="80" autocomplete="off">' +
    '<button type="button" class="btn btn--solid btn--sm" data-action="create-kb-team">Create &amp; assign</button></div>' +
    '<div class="hint" data-kb-team-status role="status" aria-live="polite"></div></div></div>';
  return '<div class="field"><label for="kb-name">Name</label><input class="input" id="kb-name" name="name" maxlength="200" required></div>' +
    '<div class="field"><label for="kb-business-function">Primary business function</label><input class="input" id="kb-business-function" name="primaryBusinessFunction" maxlength="120" required></div>' +
    '<div class="field"><label for="kb-description">Description</label><textarea class="input" id="kb-description" name="description" maxlength="2000"></textarea></div>' +
    accessField +
    '<div class="field"><label><input type="checkbox" name="dataSensitive"> Expected to contain sensitive data</label></div>';
}

function folderSourceField(esc) {
  const folders = sourceCache.filter((source) => String(source.kind) === "filesystem" && String(source.lifecycleState || "active") === "active");
  return '<div class="field"><label for="kb-folder-source">Connected folder</label><select class="select" id="kb-folder-source" name="sourceId" required>' +
    '<option value="">Choose a folder</option>' + folders.map((source) => '<option value="' + esc(String(source.id || "")) + '">' +
      esc(sourceDisplayName(source.kind) + " · " + sourceScopeLabel(source.namespace)) + "</option>").join("") + "</select></div>";
}

function fileFields(_esc) {
  return '<section class="company-upload-section" aria-labelledby="company-upload-details-title"><div class="company-upload-section-head"><div><span>01</span>' +
    '<h4 id="company-upload-details-title">Upload details</h4></div></div>' +
    '<div class="field"><label for="kb-purpose">Purpose</label><input class="input" id="kb-purpose" name="purpose" maxlength="500" placeholder="Example: Product design reference" required aria-describedby="kb-purpose-error" data-input-action="clear-company-upload-purpose-error">' +
    '<p class="field-error" id="kb-purpose-error" data-field-error="purpose" role="status" aria-live="polite"></p>' +
    '</div>' +
    '<div class="field"><label for="kb-files">Files</label><label class="company-upload-picker" for="kb-files"><span class="company-upload-picker-icon" aria-hidden="true">+</span>' +
    '<span><strong>Choose files</strong><small>TXT, Markdown, CSV, JSON, YAML, PDF, or Word</small></span></label>' +
    '<input class="company-upload-file-input" id="kb-files" name="files" type="file" accept=".txt,.md,.markdown,.csv,.json,.yaml,.yml,.pdf,.docx" multiple required aria-describedby="kb-files-error" data-input-action="select-company-files">' +
    '<p class="field-error" id="kb-files-error" data-field-error="files" role="status" aria-live="polite"></p>' +
    '<p class="hint">Up to 512 KiB for text formats and 5 MiB for PDF or Word. You can set a display name for each file next.</p></div></section>';
}

// Validation feedback stays inside the upload drawer: the page-level
// [data-screen-error] card renders behind the open panel where it is unreadable.
function setCompanyUploadFieldError(wizard, field, message) {
  if (!wizard || typeof wizard.querySelector !== "function") return;
  const region = wizard.querySelector('[data-field-error="' + field + '"]');
  if (region) region.textContent = message || "";
  const input = wizard.querySelector(field === "purpose" ? '[name="purpose"]' : '[name="files"]');
  if (!input) return;
  if (input.classList && typeof input.classList.toggle === "function") {
    input.classList.toggle("input--invalid", Boolean(message));
  }
  if (message && typeof input.setAttribute === "function") input.setAttribute("aria-invalid", "true");
  else if (!message && typeof input.removeAttribute === "function") input.removeAttribute("aria-invalid");
}

function validateCompanyUploadInput(wizard) {
  const purpose = fieldValue(wizard, '[name="purpose"]');
  const filesInput = wizard && typeof wizard.querySelector === "function" ? wizard.querySelector('[name="files"]') : null;
  const hasFiles = Boolean(filesInput && filesInput.files && filesInput.files.length);
  setCompanyUploadFieldError(wizard, "purpose", purpose ? "" : "Purpose is required.");
  setCompanyUploadFieldError(wizard, "files", hasFiles ? "" : "Choose at least one supported file.");
  const firstInvalid = !purpose
    ? wizard.querySelector('[name="purpose"]')
    : (hasFiles ? null : filesInput);
  if (firstInvalid && typeof firstInvalid.focus === "function") firstInvalid.focus();
  return Boolean(purpose && hasFiles);
}

function readKnowledgeBaseInput(wizard) {
  const name = fieldValue(wizard, '[name="name"]');
  const primaryBusinessFunction = fieldValue(wizard, '[name="primaryBusinessFunction"]');
  const description = fieldValue(wizard, '[name="description"]');
  const targetTeamIdValue = fieldValue(wizard, '[name="targetTeamId"]');
  const sensitive = wizard.querySelector('[name="dataSensitive"]');
  if (!name || !primaryBusinessFunction) throw { status: 400, message: "Name and primary business function are required" };
  return {
    name,
    primaryBusinessFunction,
    description,
    dataSensitive: Boolean(sensitive && sensitive.checked),
    targetTeamId: targetTeamIdValue || null,
  };
}

function readKnowledgePieceInput(wizard, kind) {
  const name = fieldValue(wizard, '[name="name"]');
  const description = fieldValue(wizard, '[name="description"]');
  const purpose = fieldValue(wizard, '[name="purpose"]');
  const sourceId = fieldValue(wizard, '[name="sourceId"]');
  const url = fieldValue(wizard, '[name="url"]');
  if (!name || !purpose) throw { status: 400, message: "Name and purpose are required" };
  if (kind === "folder" && !sourceId) throw { status: 400, message: "Choose a connected folder" };
  if (kind === "url") assertPublicHttpsInput(url);
  return { name, description, purpose, sourceId, url };
}

function assertPublicHttpsInput(raw) {
  let url;
  try { url = new URL(raw); } catch { throw { status: 400, message: "Enter a valid public HTTPS URL" }; }
  if (url.protocol !== "https:" || url.username || url.password || !url.hostname) {
    throw { status: 400, message: "Enter a public HTTPS URL without credentials" };
  }
}

async function uploadSelectedCompanyFiles(ctx, wizard, knowledgeBaseId) {
  const input = wizard.querySelector('[name="files"]');
  const files = [...(input && input.files ? input.files : [])];
  const purpose = fieldValue(wizard, '[name="purpose"]');
  const description = fieldValue(wizard, '[name="description"]');
  if (!purpose) throw { status: 400, message: "Purpose is required" };
  if (!files.length) throw { status: 400, message: "Choose at least one supported file" };
  const titles = files.map((file, index) =>
    fieldValue(wizard, '[data-upload-title="' + String(index) + '"]') || readableFileTheme(file && file.name),
  );
  const batch = {
    id: companyFileIdempotencyKey(),
    knowledgeBaseId: String(knowledgeBaseId),
    document: wizard.ownerDocument,
    total: files.length,
    settled: 0,
    failed: 0,
    complete: false,
    entries: files.map((file, index) => ({
      key: String(index),
      name: String(file && file.name || "Untitled file"),
      status: "Waiting",
      detail: "",
      retry: false,
      progress: null,
      settled: false,
    })),
  };
  activeCompanyFileBatches.set(String(knowledgeBaseId), batch);
  // Raise the wait ribbon here, not on the first row update: reading a 5 MiB
  // PDF into base64 is an await, and that gap is exactly when the operator is
  // looking for proof the click landed.
  syncCompanyUploadBatchDom(batch);
  const queue = wizard.querySelector("[data-upload-queue]");
  if (queue) queue.innerHTML = files.map((file, index) => uploadQueueRow(String(index), file.name, "Waiting", false, wizard)).join("");
  let cursor = 0;
  let settled = 0;
  let failed = 0;
  const processing = [];
  const summary = wizard.querySelector("[data-upload-summary]");
  if (summary) summary.textContent = "Processing 0 of " + files.length;
  const settle = (index, didFail) => {
    const entry = batch.entries[index];
    if (!entry || entry.settled) return;
    entry.settled = true;
    settled += 1;
    if (didFail) failed += 1;
    batch.settled = settled;
    batch.failed = batch.entries.filter((candidate) => candidate.status === "Failed").length;
    syncCompanyUploadBatchDom(batch);
    if (summary) summary.textContent = "Processing " + settled + " of " + files.length;
  };
  const fail = (index, key, file, payload, error) => {
    const retryable = companyFileErrorIsRetryable(error);
    if (retryable) pendingCompanyFiles.set(key, { file, payload, wizard });
    if (companyFileRequestStillProcessing(error)) {
      updateUploadRow(wizard, key, "Processing", "the server is still working; retry to check again", true);
    } else {
      updateUploadRow(wizard, key, "Failed", uploadFailureDetail(error), retryable);
      notifyCompanyFileOutcome(ctx, "danger", "File not uploaded",
        String(file.name) + ": " + uploadFailureDetail(error));
    }
    settle(index, true);
  };
  const worker = async () => {
    while (cursor < files.length) {
      const index = cursor++;
      const file = files[index];
      const key = String(index);
      const payload = {
        knowledgeBaseId,
        fileName: String(file.name),
        contentBase64: "",
        idempotencyKey: companyFileIdempotencyKey(),
        title: titles[index],
        description,
        purpose,
      };
      try {
        assertSafeCompanyFile(file);
        // Original bytes, never browser-decoded text: the server validates
        // and hashes exactly what the user selected.
        const bytes = await file.arrayBuffer();
        payload.contentBase64 = base64FromBytes(bytes);
        updateUploadRow(wizard, key, "Uploading", "", false, null);
        const accepted = await submitCompanyFileWithRecovery(ctx, payload);
        updateUploadRow(
          wizard,
          key,
          accepted && accepted.status === "queued" ? "Queued" : "Processing",
          companyFileStageDetail(accepted && accepted.stage),
          false,
          accepted,
        );
        // Admission and processing are deliberately separated. Once this POST
        // is durable, submit the next selected file immediately; polling this
        // upload must not hold one of the browser's two admission lanes.
        processing.push((async () => {
          try {
            const resolved = await pollCompanyFileUpload(ctx, accepted, (progress) => {
              updateUploadRow(
                wizard,
                key,
                progress && progress.status === "queued" ? "Queued" : "Processing",
                companyFileStageDetail(progress && progress.stage),
                false,
                progress,
              );
            });
            const terminalFailed = recordCompanyFileResult(ctx, wizard, key, file, resolved, false);
            settle(index, terminalFailed);
          } catch (error) {
            fail(index, key, file, payload, error);
          }
        })());
      } catch (error) {
        fail(index, key, file, payload, error);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(2, files.length) }, () => worker()));
  await Promise.all(processing);
  batch.complete = true;
  batch.failed = batch.entries.filter((entry) => entry.status === "Failed").length;
  syncCompanyUploadBatchDom(batch);
  if (!batch.entries.some((entry) => entry.retry)) {
    activeCompanyFileBatches.delete(String(knowledgeBaseId));
  }
  if (summary) summary.textContent = failed ? (files.length - failed) + " uploaded · " + failed + " failed" : files.length + " uploaded";
  return failed === 0;
}

/** A random request identity, deliberately separate from the file's SHA-256. */
function companyFileIdempotencyKey() {
  const crypto = globalThis.crypto;
  if (crypto && typeof crypto.randomUUID === "function") {
    return "file_" + crypto.randomUUID().replaceAll("-", "");
  }
  if (crypto && typeof crypto.getRandomValues === "function") {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return "file_" + [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
  }
  return "file_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2);
}

async function companyFileReplacementFingerprint(input) {
  const bytesHash = await companyFileSha256(input.bytes);
  return companyFileSha256(new TextEncoder().encode(JSON.stringify([
    input.knowledgeBaseId,
    input.fileName,
    bytesHash,
    input.title,
    input.description,
    input.purpose,
  ])));
}

function clearCompanyFileReplacementIdentity(wizard) {
  if (!wizard || typeof wizard.removeAttribute !== "function") return;
  wizard.removeAttribute("data-replacement-idempotency-key");
  wizard.removeAttribute("data-replacement-request-fingerprint");
}

/** Prefer the stable replay code; retain the exact message for older kernels. */
function companyFileRequestEndedBeforeReservation(error) {
  if (Number(error && error.status) !== 409) return false;
  if (String(error && error.code || "") === "company_file_upload_unreserved") return true;
  return String(error && error.message || "").trim().toLocaleLowerCase() ===
    "previous upload request ended before file reservation";
}

/** An accepted request may still be finishing; polling must retain its key. */
function companyFileRequestStillProcessing(error) {
  if (Number(error && error.status) !== 409) return false;
  if (String(error && error.code || "") === "company_file_upload_processing") return true;
  const message = String(error && error.message || "").trim().toLocaleLowerCase();
  return message === "upload request is still processing" ||
    message === "upload request is already processing";
}

function companyFileErrorIsRetryable(error) {
  if (companyFileRequestStillProcessing(error) || companyFileRequestEndedBeforeReservation(error)) return true;
  const status = Number(error && error.status);
  return status === 0 || status === 408 || status === 429 || status >= 500 || !Number.isFinite(status);
}

function assertSafeCompanyFile(file) {
  const name = String(file && file.name || "");
  if (!/\.(txt|md|markdown|csv|json|ya?ml|pdf|docx)$/i.test(name)) throw { status: 400, message: "Unsupported file type" };
  const binary = /\.(pdf|docx)$/i.test(name);
  const size = Number(file && file.size);
  const maxBytes = binary ? 5 * 1024 * 1024 : 512 * 1024;
  if (size < 1 || size > maxBytes) {
    throw { status: 400, message: binary ? "PDF and Word files must be between 1 byte and 5 MiB" : "File must be between 1 byte and 512 KiB" };
  }
}

/**
 * Terminal label for one uploaded file. The POST resolves after server-side
 * finalize, so its summary already carries the outcome; an idempotent replay
 * can additionally return a failed row so its reason is shown instead of a stall.
 */
function companyFileTerminalRow(file, fileName) {
  const status = String(file && file.status || "");
  if (status === "failed") {
    return { label: "Failed", detail: companyFileFailureText(file && file.failureCode, fileName) };
  }
  if (status === "needs_review") return { label: "Needs review", detail: "" };
  if (status === "ready") return { label: "Uploaded", detail: "" };
  return { label: "Processing", detail: "" };
}

function companyFileFailureText(code, fileName) {
  const csvParseFailure = String(code || "") === "parse_failed" && /\.csv$/i.test(String(fileName || ""));
  const messages = {
    duplicate_content: "this exact content is already in the knowledge base",
    quota_exceeded: "storage quota exceeded for this knowledge base",
    lease_expired: "upload expired before completion; retry",
    parse_failed: csvParseFailure
      ? "Invalid CSV format. Re-export it with at least two named columns and one data row."
      : "the document could not be read; check the file and retry",
    extraction_failed: "text extraction could not finish; retry the upload",
    embedding_failed: "the embedding service could not index this file; retry the upload",
    finalization_failed: "processing finished, but the result could not be saved; retry",
    processing_recovery: "the server is recovering an earlier processing attempt",
    processing_failed: "the server could not finish processing this file; retry",
    reservation_failed: "the server could not reserve storage for this file",
    ingest_failed: "the file could not be processed; retry the upload",
    no_facts_landed: "no usable facts were found in this file",
    classification_denied: "blocked by data policy: the file contains credential- or PII-like content this workspace may not send to processing; remove it or allowlist the destination",
  };
  return messages[String(code || "")] || "the file could not be processed";
}

/** Surface one file's outcome through the shared toast flow (no-op without it). */
function notifyCompanyFileOutcome(ctx, tone, title, message) {
  if (ctx && typeof ctx.notify === "function") ctx.notify({ title, message, tone });
}

async function uploadOneCompanyFile(ctx, wizard, key, file, payload, bytes) {
  updateUploadRow(wizard, key, "Uploading", "", false, null);
  if (!payload.contentBase64) {
    bytes = bytes || await file.arrayBuffer();
    payload.contentBase64 = base64FromBytes(bytes);
  }
  const recovered = await createCompanyFileWithRecovery(ctx, payload, (progress) => {
    updateUploadRow(
      wizard,
      key,
      progress && progress.status === "queued" ? "Queued" : "Processing",
      companyFileStageDetail(progress && progress.stage),
      false,
      progress,
    );
  });
  recordCompanyFileResult(ctx, wizard, key, file, recovered, recovered.confirmedAfterTimeout);
}

/**
 * Fold one settled upload into the caches the knowledge model reads. A file
 * whose upload row is done can still be parsing server-side, and without this
 * the page only learns that on the next route load - which is what made the
 * ingestion ribbon look like it needed a browser refresh to appear.
 */
function absorbSettledCompanyFile(uploadId, progress, file) {
  const id = String(uploadId || "");
  if (file && file.id) {
    const fileId = String(file.id);
    const index = companyFileCache.findIndex((candidate) => String(candidate && candidate.id) === fileId);
    if (index >= 0) companyFileCache[index] = file;
    else companyFileCache.push(file);
    if (id) {
      companyFileUploadCache = companyFileUploadCache.filter((upload) =>
        String(upload && upload.uploadId) !== id);
    }
    return;
  }
  const index = id
    ? companyFileUploadCache.findIndex((upload) => String(upload && upload.uploadId) === id)
    : -1;
  if (index < 0) return;
  const staged = companyFileUploadCache[index];
  companyFileUploadCache[index] = {
    ...staged,
    status: String((progress && progress.status) || "failed"),
    stage: String((progress && progress.stage) || staged.stage || "queued"),
    failureCode: (progress && progress.failureCode) || staged.failureCode || null,
  };
}

function recordCompanyFileResult(ctx, wizard, key, file, recovered, confirmedAfterTimeout) {
  pendingCompanyFiles.delete(key);
  absorbSettledCompanyFile(
    recovered.progress && recovered.progress.uploadId,
    recovered.progress,
    recovered.file,
  );
  const terminal = companyFileTerminalRow(recovered.file, file && file.name);
  const timeoutNote = confirmedAfterTimeout ? "confirmed after connection timed out" : "";
  const detail = [terminal.detail, timeoutNote].filter(Boolean).join(" · ");
  updateUploadRow(wizard, key, terminal.label, detail, false, recovered.progress);
  if (terminal.label === "Failed") {
    notifyCompanyFileOutcome(ctx, "danger", "File failed",
      String(file.name) + ": " + terminal.detail);
  } else if (terminal.label === "Needs review") {
    notifyCompanyFileOutcome(ctx, "default", "Needs review",
      String(file.name) + " was uploaded; some facts await review before they become active memory.");
  }
  return terminal.label === "Failed";
}

function base64FromBytes(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < view.length; index += chunk) {
    binary += String.fromCharCode.apply(null, view.subarray(index, index + chunk));
  }
  return btoa(binary);
}

async function companyFileSha256(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", view);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function transientCompanyFileError(error) {
  // 409 conflicts (duplicate content, quota, lease) carry a specific server
  // message and must surface as-is; only genuine transport/timeout failures
  // enter the recovery read.
  const status = Number(error && error.status);
  return status === 0 || status === 408 || status >= 500;
}

/**
 * POST one company file with a bounded wait. Browsers never time out fetch()
 * on their own, which is how uploads sat on "Uploading" indefinitely.
 */
function postCompanyFileWithTimeout(ctx, payload) {
  return Promise.race([
    ctx.api.post("/v1/admin/company-files", payload),
    new Promise((_, reject) => {
      setTimeout(() => reject({ status: 0, message: "Upload is taking longer than expected" }), COMPANY_FILE_POST_TIMEOUT_MS);
    }),
  ]);
}

async function submitCompanyFileWithRecovery(ctx, payload) {
  try {
    return await postCompanyFileWithTimeout(ctx, payload);
  } catch (error) {
    if (!transientCompanyFileError(error)) throw error;
    return postCompanyFileWithTimeout(ctx, payload);
  }
}

function waitForCompanyFilePoll() {
  return new Promise((resolve) => setTimeout(resolve, COMPANY_FILE_STATUS_POLL_MS));
}

async function pollCompanyFileUpload(ctx, accepted, onProgress) {
  if (!accepted || typeof accepted.uploadId !== "string") {
    return {
      file: accepted,
      progress: { status: accepted && accepted.status, stage: "complete" },
    };
  }
  const deadline = Date.now() + COMPANY_FILE_STATUS_TIMEOUT_MS;
  let status = accepted;
  if (typeof onProgress === "function") onProgress(status);
  while (status && (status.status === "queued" || status.status === "processing")) {
    if (Date.now() >= deadline) {
      throw { status: 0, message: "The upload is still processing. You can safely close this window and check again later." };
    }
    try {
      status = await ctx.api.get("/v1/admin/company-file-uploads/" + encodeURIComponent(accepted.uploadId));
      if (typeof onProgress === "function") onProgress(status);
    } catch (error) {
      if (!transientCompanyFileError(error)) throw error;
      await waitForCompanyFilePoll();
      continue;
    }
    if (status && (status.status === "queued" || status.status === "processing")) {
      await waitForCompanyFilePoll();
    }
  }
  if (status && status.file) return { file: status.file, progress: status };
  if (status && status.status === "failed") {
    return {
      file: { status: "failed", failureCode: status.failureCode || "processing_failed" },
      progress: status,
    };
  }
  throw { status: 0, message: "Upload status became unavailable" };
}

async function createCompanyFileWithRecovery(ctx, payload, onAccepted) {
  try {
    const accepted = await postCompanyFileWithTimeout(ctx, payload);
    const resolved = await pollCompanyFileUpload(ctx, accepted, onAccepted);
    return { ...resolved, confirmedAfterTimeout: false };
  } catch (error) {
    if (!transientCompanyFileError(error)) throw error;
    // The stable request key is authoritative. Replaying the exact body lets
    // the server return this request's durable result without guessing from a
    // same-byte row that may belong to different metadata or another client.
    const accepted = await postCompanyFileWithTimeout(ctx, payload);
    const resolved = await pollCompanyFileUpload(ctx, accepted, onAccepted);
    return { ...resolved, confirmedAfterTimeout: true };
  }
}

function uploadTitleRow(key, name, size, wizard) {
  const esc = wizard && wizard.ownerDocument && wizard.ownerDocument.defaultView
    ? (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char])
    : (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const theme = readableFileTheme(name);
  return '<div class="source-upload-title-row" data-upload-key="' + esc(key) + '"><span class="company-upload-file-mark" aria-hidden="true">' +
    esc(companyFileExtension(name)) + '</span><span class="company-upload-file-identity"><strong title="' + esc(name) + '">' + esc(name) +
    '</strong><small>' + esc(formatBytes(size)) + '</small></span><label><span>Display name</span><input class="input" data-upload-title="' +
    esc(key) + '" maxlength="255" value="' + esc(theme) + '" required></label></div>';
}

function readableFileTheme(value) {
  const fileName = String(value || "");
  const dot = fileName.lastIndexOf(".");
  const stem = dot > 0 ? fileName.slice(0, dot) : fileName;
  return stem.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() || "Untitled file";
}

function uploadQueueRow(key, name, status, retry, wizard, progress, detail) {
  const esc = wizard && wizard.ownerDocument && wizard.ownerDocument.defaultView
    ? (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char])
    : (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  return '<div class="company-upload-row" data-upload-key="' + esc(key) + '"><span class="company-upload-file-mark" aria-hidden="true">' +
    esc(companyFileExtension(name)) + '</span><span class="company-upload-file-identity"><strong class="company-upload-name">' + esc(name) +
    '</strong><small class="company-upload-status" data-upload-status>' + esc(detail ? status + ": " + detail : status) + '</small></span>' + companyFileStepsMarkup(esc, progress) +
    (retry ? '<button class="btn btn--outline btn--sm" data-action="retry-company-file" data-upload-key="' + esc(key) + '">Retry</button>' : "") + "</div>";
}

function companyFileExtension(value) {
  const name = String(value || "");
  const dot = name.lastIndexOf(".");
  const extension = dot >= 0 ? name.slice(dot + 1) : "FILE";
  return extension.slice(0, 5).toUpperCase() || "FILE";
}

function serverProgressIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5c0 4.6 2.8 8.2 7 10 4.2-1.8 7-5.4 7-10V6l-7-3Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m8.7 12 2.1 2.1 4.6-4.7" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function companyFileStepsMarkup(esc, progress) {
  const stage = String(progress && progress.stage || "");
  const current = stage === "complete"
    ? COMPANY_FILE_UPLOAD_STEPS.length
    : COMPANY_FILE_UPLOAD_STEPS.findIndex((step) => step.id === stage);
  const failed = String(progress && progress.status || "") === "failed";
  return '<span class="company-upload-steps" role="list" aria-label="Upload progress">' +
    COMPANY_FILE_UPLOAD_STEPS.map((step, index) => {
      const done = current === COMPANY_FILE_UPLOAD_STEPS.length || index < current;
      const active = current >= 0 && index === current;
      const tone = done ? " is-complete" : active && failed ? " is-failed" : active ? " is-active" : "";
      return '<span class="company-upload-step' + tone + '" role="listitem" tabindex="0" data-upload-step="' + esc(step.id) +
      '" aria-label="' + esc(step.label + ": " + step.help) + '"><span class="company-upload-step-tip" role="tooltip"><b>' +
      esc(step.label) + '</b><span>' + esc(step.help) + '</span></span></span>';
    }).join("") + '</span>';
}

function companyFileStageDetail(stage) {
  const labels = {
    queued: "Waiting for a worker",
    parsing: "Reading the file",
    extracting: "Extracting facts",
    embedding: "Creating embeddings",
    finalizing: "Saving the result",
    complete: "Complete",
  };
  return labels[String(stage || "")] || "The server is working";
}

function updateCompanyFileSteps(row, progress) {
  if (!row || !progress || !row.querySelectorAll) return;
  const stage = String(progress.stage || "queued");
  const current = stage === "complete"
    ? COMPANY_FILE_UPLOAD_STEPS.length
    : COMPANY_FILE_UPLOAD_STEPS.findIndex((step) => step.id === stage);
  const failed = String(progress.status || "") === "failed";
  for (const [index, node] of [...row.querySelectorAll("[data-upload-step]")].entries()) {
    const done = current === COMPANY_FILE_UPLOAD_STEPS.length || index < current;
    const active = current >= 0 && index === current;
    node.classList.toggle("is-complete", done);
    node.classList.toggle("is-active", active && !failed);
    node.classList.toggle("is-failed", active && failed);
    node.setAttribute("aria-current", active ? "step" : "false");
  }
}

/**
 * Failure text for one upload row. A throttled upload (429) carries the
 * server's retry-after, so the row says WHEN to retry instead of leaving the
 * operator to guess and re-trip the limit immediately.
 */
function uploadFailureDetail(error) {
  // An allowance denial (402) is named by the shared limit toast; the row
  // stays neutral. A throttle (429) keeps its per-row retry timing so the
  // operator knows WHICH file to retry and when.
  if (isLimitError(error) && Number(error.status) === 402) return "Not uploaded";
  const message = error && error.message ? String(error.message) : "Upload failed";
  const wait = error && Number(error.retryAfter) > 0 ? Number(error.retryAfter) : 0;
  return wait > 0 ? message + " - try again in " + wait + "s" : message;
}

function updateUploadRow(wizard, key, status, detail, retry, progress) {
  const knowledgeBaseId = wizard && typeof wizard.getAttribute === "function"
    ? String(wizard.getAttribute("data-knowledge-base-id") || "")
    : "";
  const batch = activeCompanyFileBatches.get(knowledgeBaseId);
  const entry = batch && batch.entries.find((candidate) => candidate.key === key);
  if (entry) {
    entry.status = status;
    entry.detail = detail || "";
    entry.retry = Boolean(retry);
    entry.progress = progress || entry.progress;
    batch.failed = batch.entries.filter((candidate) => candidate.status === "Failed").length;
    syncCompanyUploadBatchDom(batch);
  }
  const row = wizard.querySelector('[data-upload-key="' + cssEscape(key) + '"]');
  if (!row) return;
  const statusNode = row.querySelector && row.querySelector("[data-upload-status]");
  if (statusNode) statusNode.textContent = detail ? status + ": " + detail : status;
  updateCompanyFileSteps(row, progress);
  const oldRetry = row.querySelector && row.querySelector('[data-action="retry-company-file"]');
  if (retry && !oldRetry && typeof row.insertAdjacentHTML === "function") {
    row.insertAdjacentHTML("beforeend", '<button class="btn btn--outline btn--sm" data-action="retry-company-file" data-upload-key="' + key + '">Retry</button>');
  } else if (!retry && oldRetry && typeof oldRetry.remove === "function") oldRetry.remove();
}

function syncCompanyUploadBatchDom(batch) {
  const doc = batch && batch.document;
  if (!doc || typeof doc.querySelectorAll !== "function") return;
  for (const node of doc.querySelectorAll('[data-company-upload-batch-progress="' + cssEscape(batch.knowledgeBaseId) + '"]')) {
    node.querySelectorAll?.("[data-company-upload-settled]").forEach((value) => { value.textContent = String(batch.settled); });
    node.querySelectorAll?.("[data-company-upload-total]").forEach((value) => { value.textContent = String(batch.total); });
    const summary = node.querySelector?.("[data-upload-summary]");
    if (summary) summary.textContent = companyUploadBatchSummary(batch);
  }
  for (const button of doc.querySelectorAll('[data-action="open-company-upload-batch"][data-id="' + cssEscape(batch.knowledgeBaseId) + '"]')) {
    button.querySelectorAll?.("[data-company-upload-settled]").forEach((value) => { value.textContent = String(batch.settled); });
    button.querySelectorAll?.("[data-company-upload-total]").forEach((value) => { value.textContent = String(batch.total); });
    const note = button.querySelector?.(".kb-processing-files-note");
    if (note) note.textContent = batch.failed ? batch.failed + " need attention" : "View live progress";
  }
  paintKbIngestRibbonForBase(doc, batch.knowledgeBaseId);
}

/** Continue server-owned upload progress after a reload or return to S6. */
function resumeCompanyFileUploadTracking(ctx, wizard, base) {
  const epoch = companyFileTrackingEpoch;
  for (const upload of base.uploads || []) {
    if (!["queued", "processing"].includes(String(upload && upload.status))) continue;
    const id = String((upload && upload.uploadId) || "");
    const row = id && wizard.querySelector &&
      wizard.querySelector('[data-company-file-upload="' + cssEscape(id) + '"]');
    if (!id || !row || typeof row.querySelectorAll !== "function" || trackedCompanyFileUploads.has(id)) {
      continue;
    }
    const task = trackCompanyFileUpload(ctx, wizard, base.id, upload, epoch)
      .catch(() => undefined)
      .finally(() => trackedCompanyFileUploads.delete(id));
    trackedCompanyFileUploads.set(id, task);
  }
}

async function trackCompanyFileUpload(ctx, wizard, knowledgeBaseId, initial, epoch) {
  let progress = initial;
  const id = String(initial.uploadId || "");
  while (
    companyFileTrackingEpoch === epoch &&
    ["queued", "processing"].includes(String(progress && progress.status))
  ) {
    paintPersistedCompanyFileUpload(wizard, id, progress);
    await waitForCompanyFilePoll();
    if (companyFileTrackingEpoch !== epoch) return;
    try {
      progress = await ctx.api.get(
        "/v1/admin/company-file-uploads/" + encodeURIComponent(id),
      );
    } catch (error) {
      if (transientCompanyFileError(error)) continue;
      const row = wizard.querySelector &&
        wizard.querySelector('[data-company-file-upload="' + cssEscape(id) + '"]');
      const status = row && row.querySelector && row.querySelector("[data-persisted-upload-status]");
      if (status) status.textContent = "Status unavailable";
      return;
    }
  }
  if (companyFileTrackingEpoch !== epoch || !progress) return;

  absorbSettledCompanyFile(id, progress, progress.file);

  const currentBase = String(wizard.getAttribute && wizard.getAttribute("data-knowledge-base-id") || "");
  const target = currentBase === String(knowledgeBaseId) && wizard.querySelector &&
    wizard.querySelector("[data-kb-detail-items]");
  const row = knowledgeBaseModel().find((candidate) => candidate.id === String(knowledgeBaseId));
  if (target && row) {
    target.innerHTML = knowledgeItemsHtml(row, canMutate(ctx), ctx.esc, "");
    refreshKbIngestRibbon(wizard, row);
  }
}

function paintPersistedCompanyFileUpload(wizard, id, progress) {
  const row = wizard.querySelector &&
    wizard.querySelector('[data-company-file-upload="' + cssEscape(id) + '"]');
  if (!row) return;
  updateCompanyFileSteps(row, progress);
  const status = row.querySelector && row.querySelector("[data-persisted-upload-status]");
  if (status) status.textContent = companyFileStageDetail(progress && progress.stage);
}

/**
 * A HaloMem-owned direct-OAuth card (Linear today). There is no credential to
 * collect and no data-point matrix to choose: the operator authorizes once at
 * the provider and the kernel exchanges the code server-side. The dialog is
 * therefore a plain explanation plus one button.
 */
function directWizardHtml(ctx, entry) {
  const { esc } = ctx;
  const connectorId = String(entry.id || "connector");
  const titleId = controlId("connector", connectorId, "dialog-title");
  const name = String(entry.name || "Connector");
  const configured = !entry.managedAuth || entry.managedAuth.configured !== false;
  const adminNamespace = String((ctx.identity && ctx.identity.namespace) || "");
  const isTeamAdmin = isTeamScopedSourceIdentity(ctx);
  const scopeId = controlId("connector", connectorId, "scope");
  const scopeField = isTeamAdmin
    ? '<div class="source-trust"><b>Team: ' + esc(sourceScopeLabel(adminNamespace)) +
      '</b><span>Memory from this source is visible to your team only.</span></div>'
    : '<div class="field"><label for="' + esc(scopeId) + '">Which team can use this source *</label>' +
      '<select class="select" id="' + esc(scopeId) + '" data-source-scope required>' +
      '<option value="" disabled selected>Choose a team</option>' +
      activeTeamCache.map((team) => '<option value="' + esc(String(team.id || "")) + '">' +
        esc(sourceTeamLabel(team.name || team.namespace || "Team")) + " only</option>").join("") +
      '</select><div class="subtle">Every backend must belong to one team. OAuth access and imported memory stay inside that team.</div></div>';
  const driveSelection = entry.connect && entry.connect.provider === "google_drive"
    ? '<div class="field"><label for="google-drive-selection">Google Drive files or folders *</label>' +
      '<textarea class="textarea" id="google-drive-selection" data-drive-selection rows="5" ' +
      'placeholder="Paste one Google Drive file/folder URL or ID per line" required></textarea>' +
      '<div class="subtle">Only these files and the contents of these folders will be imported. Paste up to 100 URLs or IDs.</div></div>'
    : "";
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close ' +
    esc(name) + ' configuration"></button><section class="source-wizard-dialog" role="dialog" aria-modal="true" aria-labelledby="' +
    esc(titleId) + '"><div class="between source-wizard-head"><div><span class="source-category">Connect</span><h3 id="' +
    esc(titleId) + '" tabindex="-1" data-wizard-focus>' + esc(name) +
    '</h3></div><button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Close ' +
    esc(name) + ' configuration">' + closeIcon() + "<span>Close</span></button></div>" +
    '<div class="stack"><p class="sub">' + esc(String(entry.description || "")) + "</p>" + driveSelection +
    (entry.dataSummary
      ? '<div class="source-trust"><b>What enters memory</b><span>' + esc(String(entry.dataSummary)) + "</span></div>"
      : "") +
    '<div class="source-trust"><b>Authorization stays with ' + esc(name) + '</b><span>You approve access in ' +
    esc(name) + "; Halo never sees your password and the access token is stored encrypted, never shown back to the browser.</span></div>" +
    scopeField +
    '<div class="source-trust"><b>Team-wide visibility</b><span>' + esc(name) +
    " does not expose complete per-item permissions, so imported records are readable by anyone who can read " +
    (isTeamAdmin ? "your team's memory." : "the selected team's memory.") + "</span></div>" +
    '<div data-direct-connect-status role="status" aria-live="polite">' +
    (configured ? "" : "This connection is not configured by your Halo administrator yet.") + "</div></div>" +
    '<div class="source-wizard-actions"><a class="btn btn--ghost btn--sm" href="' + esc(String(entry.docsUrl || "#")) +
    '" target="_blank" rel="noreferrer">API docs</a><span style="flex:1"></span>' +
    '<button class="btn btn--solid" data-action="connect-source"' +
    (configured ? "" : ' disabled aria-disabled="true"') + ">Connect " + esc(name) + "</button></div></section>";
}

/** Local vault pairing never asks for an Obsidian account or filesystem path. */
function obsidianWizardHtml(ctx, entry) {
  const { esc } = ctx;
  const connectorId = String(entry.id || "obsidian_vault");
  const titleId = controlId("connector", connectorId, "dialog-title");
  const adminNamespace = String((ctx.identity && ctx.identity.namespace) || "");
  const isTeamAdmin = adminNamespace.split("/").filter(Boolean).length >= 2;
  const ownScopeLabel = isTeamAdmin
    ? sourceScopeLabel(adminNamespace)
    : "Selected team";
  const scopeId = controlId("connector", connectorId, "scope");
  const scopeField = isTeamAdmin
    ? '<div class="source-trust"><b>Scope: ' + esc(ownScopeLabel) +
      '</b><span>Memory from this vault is visible to your team only.</span></div>'
    : '<div class="field"><label for="' + esc(scopeId) +
      '">Which team can use this vault *</label><select class="select" id="' +
      esc(scopeId) + '" data-source-scope required>' +
      '<option value="" disabled selected>Choose a team</option>' +
      activeTeamCache.map((team) => '<option value="' +
        esc(String(team.id || "")) + '">' +
        esc(sourceTeamLabel(team.name || team.namespace || "Team")) +
        " only</option>").join("") +
      '</select><div class="subtle">Every backend must belong to one team. The server fixes this placement before accepting any note.</div></div>';
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close Obsidian configuration"></button>' +
    '<section class="source-wizard-dialog" role="dialog" aria-modal="true" aria-labelledby="' +
    esc(titleId) + '">' +
    '<div class="between source-wizard-head"><div><span class="source-category">Pair local vault</span><h3 id="' +
    esc(titleId) + '" tabindex="-1" data-wizard-focus>Obsidian</h3></div>' +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Close Obsidian configuration">' +
    closeIcon() + '<span>Close</span></button></div>' +
    '<div class="source-wizard-grid"><div><h4>1. Select the vault data</h4>' +
    '<div class="field"><label for="obsidian-vault-name">Vault name *</label><input class="input" id="obsidian-vault-name" data-obsidian-vault-name maxlength="120" required autocomplete="off" placeholder="Company knowledge"></div>' +
    '<div class="field"><label for="obsidian-included-folders">Include folders</label><textarea class="input" id="obsidian-included-folders" data-obsidian-included-folders rows="3" placeholder="Projects, Handbook"></textarea><div class="subtle">Optional comma- or line-separated vault-relative folders.</div></div>' +
    '<div class="field"><label for="obsidian-excluded-folders">Exclude folders</label><textarea class="input" id="obsidian-excluded-folders" data-obsidian-excluded-folders rows="3" placeholder="Private, Templates"></textarea></div>' +
    '</div><div><h4>2. Approve memory placement</h4>' + scopeField +
    '<div class="source-wizard-trusts"><div class="source-trust source-trust--stack"><b>Local, one-way connection</b><span>The HaloMem Sync plugin reads selected Markdown notes through Obsidian’s Vault API and pushes them over HTTPS. HaloMem never receives an Obsidian password, vault path, settings, plugins, trash or binary attachments.</span></div>' +
    '<label class="source-trust source-trust--warn"><input type="checkbox" data-namespace-open required><span><b>Approve vault-wide visibility</b><small>Obsidian does not provide per-note ACLs. Imported notes become visible to everyone who can read the scope selected above.</small></span></label>' +
    '</div></div></div><div class="source-wizard-actions"><a class="btn btn--ghost btn--sm" href="' +
    esc(String(entry.docsUrl || "#")) +
    '" target="_blank" rel="noreferrer">How Obsidian stores data</a>' +
    '<span style="flex:1"></span><button class="btn btn--solid" data-action="connect-source">Create pairing</button></div></section>';
}

function obsidianPairingResultHtml(ctx, entry, bundle) {
  const { esc } = ctx;
  const titleId = controlId("connector", "obsidian_vault", "paired-title");
  const json = JSON.stringify(bundle, null, 2);
  return '<button type="button" class="source-wizard-backdrop" data-action="finish-obsidian-pairing" tabindex="-1" aria-label="Close Obsidian pairing"></button>' +
    '<section class="source-wizard-dialog" role="dialog" aria-modal="true" aria-labelledby="' +
    esc(titleId) + '">' +
    '<div class="between source-wizard-head"><div><span class="source-category">Pairing ready — not connected yet</span><h3 id="' +
    esc(titleId) + '" tabindex="-1" data-wizard-focus>Finish in Obsidian</h3></div></div>' +
    '<div class="stack"><div class="source-trust source-trust--warn"><b>Copy this bundle now</b><span>The signing secret is shown once. HaloMem stores only an encrypted copy and cannot show it again.</span></div>' +
    '<ol><li><a href="' + esc(String(entry.docsUrl || "#")) +
    '" target="_blank" rel="noreferrer"><b>Install HaloMem Sync</b></a> in the intended vault.</li><li>Open its settings, paste this pairing bundle, and choose <b>Pair & sync</b>.</li><li>Keep Obsidian open while the first sync completes.</li></ol>' +
    '<div class="source-trust"><b>How confirmation works</b><span>After the first sync, this source changes from Awaiting Obsidian to Connected.</span></div>' +
    '<div class="field"><label for="obsidian-pairing-bundle">Pairing bundle</label><textarea class="input mono" id="obsidian-pairing-bundle" data-obsidian-pairing-bundle rows="10" readonly spellcheck="false">' +
    esc(json) +
    '</textarea></div><div data-obsidian-copy-status role="status" aria-live="polite"></div></div>' +
    '<div class="source-wizard-actions"><a class="btn btn--ghost btn--sm" href="' +
    esc(String(entry.docsUrl || "#")) +
    '" target="_blank" rel="noreferrer">Manual install guide</a><span style="flex:1"></span>' +
    '<button class="btn btn--outline" data-action="copy-obsidian-pairing">Copy bundle</button>' +
    '<button class="btn btn--solid" data-action="finish-obsidian-pairing">I’ll finish in Obsidian</button></div></section>';
}

function wizardHtml(ctx, entry) {
  const { esc } = ctx;
  const connectorId = String(entry.id || "connector");
  if (entry.connect && entry.connect.kind === "direct-oauth") return directWizardHtml(ctx, entry);
  if (entry.connect && entry.connect.kind === "local-pairing") return obsidianWizardHtml(ctx, entry);
  const managedNango = entry.auth && entry.auth.managedBy === "nango";
  const nangoConfigured = !managedNango || !entry.managedAuth || entry.managedAuth.configured !== false;
  const credentials = credentialCache.filter((credential) => credential.connectionKey === entry.connectionKey);
  const credentialOptions = ['<option value="">Create a new credential</option>']
    .concat(credentials.map((credential) => '<option value="' + esc(String(credential.id)) + '">' + esc(String(credential.name)) + "</option>"))
    .join("");
  const renderField = (field) => {
    const key = String(field.key || "field");
    const inputId = controlId("connector", connectorId, key);
    const helpId = inputId + "-help";
    const type = field.secret ? "password" : field.input === "url" || field.input === "email" || field.input === "number" ? field.input : "text";
    return '<div class="field"><label for="' + esc(inputId) + '">' + esc(String(field.label || field.key)) + (field.required ? " *" : "") + "</label>" +
      '<input class="input" type="' + esc(type) + '" autocomplete="' + (field.secret ? "new-password" : "off") +
      '" id="' + esc(inputId) + '" name="' + esc(key) + '" data-auth-key="' + esc(key) +
      '" placeholder="' + esc(String(field.placeholder || "")) + '"' +
      (field.required ? " required" : "") +
      (Number.isFinite(Number(field.minLength)) ? ' minlength="' + esc(String(field.minLength)) + '"' : "") +
      (field.help ? ' aria-describedby="' + esc(helpId) + '"' : "") + ">" +
      (field.help ? '<div class="subtle" id="' + esc(helpId) + '">' + esc(String(field.help)) + "</div>" : "") + "</div>";
  };
  const credentialFields = managedNango
    ? ""
    : (entry.auth.fields || [])
      .filter((field) => field.role !== "source")
      .map(renderField)
      .join("");
  const sourceFields = (entry.auth.fields || [])
    .filter((field) => field.role === "source")
    .map(renderField)
    .join("");
  const points = (entry.dataPoints || []).map((point) =>
    '<label class="source-point"><input type="checkbox" name="selectedDataPoints" data-point-key="' + esc(String(point.key)) + '" ' +
    (point.defaultEnabled ? "checked" : "") + '><span><b>' + esc(String(point.label || point.key)) + "</b>" +
    '<small>' + esc(String(point.description || "")) + " · " + esc(String(point.memoryMode || "snapshot")) + " memory</small></span></label>",
  ).join("");
  // Namespace shape decides who chooses placement: "" (platform root) and
  // single-segment namespaces (an organization) administer teams below them;
  // two or more segments is a team admin whose only possible scope is their
  // own team (the server enforces this regardless of what the client sends).
  const adminNamespace = String((ctx.identity && ctx.identity.namespace) || "");
  const isTeamAdmin = adminNamespace.split("/").filter(Boolean).length >= 2;
  const ownScopeLabel = isTeamAdmin ? sourceScopeLabel(adminNamespace) : "Selected team";
  const scopeSelectId = controlId("connector", connectorId, "scope");
  // Org admins must choose a placement explicitly — no preselected default,
  // because an accidental placement is not cleanly reversible once facts have
  // been ingested. New backends are team-only, so organization is absent.
  const scopeField = isTeamAdmin
    ? '<div class="source-trust"><b>Scope: ' + esc(ownScopeLabel) +
      '</b><span>Memory from this source is visible to your team only.</span></div>'
    : '<div class="field"><label for="' + esc(scopeSelectId) + '">Which team can use this source *</label>' +
      '<select class="select" id="' + esc(scopeSelectId) + '" name="sourceTargetTeamId" data-source-scope data-input-action="update-source-scope-copy" required>' +
      '<option value="" disabled selected>Choose a team</option>' +
      activeTeamCache.map((team) => '<option value="' + esc(String(team.id || "")) + '">' +
        esc(sourceTeamLabel(team.name || team.namespace || "Team")) + " only</option>").join("") +
      '</select><div class="subtle">Every backend must belong to one team. Memory is visible only inside the chosen team.</div></div>';
  const acl = entry.capabilities && entry.capabilities.sourceAcl
    ? '<div class="source-trust"><b>Native source ACLs preserved</b><span>Principals and groups travel with each record.</span></div>'
    : '<label class="source-trust source-trust--warn"><input type="checkbox" name="namespaceOpen" data-namespace-open required><span><b>Approve source-wide visibility</b><small>This API cannot prove native object ACLs. Everything it imports becomes visible to <b data-scope-copy>' +
      esc(isTeamAdmin ? "everyone in " + ownScopeLabel : "the scope chosen above") + "</b>.</small></span></label>";
  const isManual = entry.auth && entry.auth.type === "manual";
  const savedCredentialId = controlId("connector", connectorId, "credential");
  const credentialNameId = controlId("connector", connectorId, "credential-name");
  const scheduleId = controlId("connector", connectorId, "sync-schedule");
  const credentialPane = isManual && entry.id === "csv_sheet_import"
    ? csvFields(esc, "connector-csv")
    : '<div class="field"><label for="' + esc(savedCredentialId) + '">Saved credential</label><select class="select" id="' +
      esc(savedCredentialId) + '" name="credentialId" data-credential-id>' + credentialOptions + "</select></div>" +
      '<div class="field"><label for="' + esc(credentialNameId) + '">Credential name</label><input class="input" id="' +
      esc(credentialNameId) + '" name="credentialName" data-credential-name value="' + esc(String(entry.name) + " connection") + '"></div>' +
      (managedNango
        ? '<div class="source-trust"><b>Halo-managed authorization</b><span>' +
          (nangoConfigured
            ? "Halo opens a short-lived Nango authorization link and manages the platform connection credentials."
            : "This connector is not configured in the current Halo Nango environment.") +
          '</span></div><div data-nango-connect-status role="status" aria-live="polite"></div>'
        : "") +
      '<div data-credential-fields>' + credentialFields + "</div>" +
      (sourceFields ? '<h4>Source scope</h4><div data-source-fields>' + sourceFields + "</div>" : "");
  const scheduleField = entry.delivery === "rest"
    ? '<div class="field"><label for="' + esc(scheduleId) + '">Sync schedule</label><select class="select" id="' +
      esc(scheduleId) + '" name="syncInterval" data-sync-interval><option value="0">Manual</option><option value="900">Every 15 minutes</option><option value="3600" selected>Hourly</option><option value="21600">Every 6 hours</option><option value="86400">Daily</option></select></div>'
    : '<div class="source-trust"><b>' + (entry.delivery === "webhook" ? "Push delivery" : "Manual snapshot") + '</b><span>' + (entry.delivery === "webhook" ? "Events arrive through the signed source endpoint." : "Choose a CSV now; later imports replace this governed source snapshot.") + "</span></div>";
  const titleId = controlId("connector", connectorId, "dialog-title");
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close ' +
    esc(String(entry.name)) + ' configuration"></button><section class="source-wizard-dialog" role="dialog" aria-modal="true" aria-labelledby="' +
    esc(titleId) + '"><div class="between source-wizard-head"><div><span class="source-category">Configure</span><h3 id="' +
    esc(titleId) + '" tabindex="-1" data-wizard-focus>' + esc(String(entry.name)) +
    '</h3></div><button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Close ' +
    esc(String(entry.name)) + ' configuration">' + closeIcon() + "<span>Close</span></button></div>" +
    '<div class="source-wizard-grid"><div><h4>1. ' + (isManual ? "Import file" : "Credential") + "</h4>" + credentialPane + "</div>" +
    '<div><h4>2. Memory data</h4>' + scopeField + '<div class="source-points">' + points + "</div>" + acl +
    scheduleField + "</div></div>" +
    '<div class="source-wizard-actions"><a class="btn btn--ghost btn--sm" href="' + esc(String(entry.docsUrl || "#")) + '" target="_blank" rel="noreferrer">API docs</a>' +
    '<span style="flex:1"></span><button class="btn btn--solid" data-action="connect-source"' +
    (nangoConfigured ? "" : ' disabled aria-disabled="true"') + ">" +
    (isManual ? "Connect & import" : managedNango ? "Connect source" : "Test & connect") +
    "</button></div></section>";
}

async function readSourceSetup(wizard, entry) {
  const selectedDataPoints = [...wizard.querySelectorAll("[data-point-key]:checked")]
    .map((input) => String(input.getAttribute("data-point-key") || ""))
    .filter(Boolean);
  if (selectedDataPoints.length === 0) throw { status: 400, message: "Select at least one data set" };
  // Root admins see a scope select with no default; a missing choice blocks
  // the connect. Team admins have no select — the server places the source in
  // their own namespace.
  const targetTeamId = readRequiredSourceTeam(wizard, "Choose which team can use this source");
  if (!(entry.capabilities && entry.capabilities.sourceAcl)) {
    const approval = wizard.querySelector("[data-namespace-open]");
    if (!approval || !approval.checked) {
      throw { status: 400, message: "Approve source-wide visibility for this source" };
    }
  }
  const sourceConfig = {};
  for (const field of entry.auth.fields || []) {
    if (field.role !== "source") continue;
    const input = wizard.querySelector('[data-auth-key="' + cssEscape(String(field.key)) + '"]');
    const value = input && input.value != null ? String(input.value).trim() : "";
    if (field.required && !value) {
      if (input && typeof input.focus === "function") input.focus();
      throw { status: 400, message: String(field.label || field.key) + " is required" };
    }
    if (value) sourceConfig[field.key] = value;
  }
  const csvImport = entry.id === "csv_sheet_import"
    ? await readCsvWizardPayload(wizard)
    : null;
  const schedule = wizard.querySelector("[data-sync-interval]");
  return {
    selectedDataPoints,
    sourceConfig,
    csvImport,
    intervalSeconds: Number(schedule && schedule.value),
    targetTeamId,
  };
}

function readRequiredSourceTeam(wizard, message) {
  const scopeSelect = wizard.querySelector("[data-source-scope]");
  if (!scopeSelect) return null;
  const targetTeamId = String(scopeSelect.value || "");
  if (!targetTeamId) {
    scopeSelect.focus?.();
    throw { status: 400, message };
  }
  return targetTeamId;
}

function credentialName(wizard, entry) {
  const input = wizard.querySelector("[data-credential-name]");
  const value = input && input.value != null ? String(input.value).trim() : "";
  return value || String(entry.name) + " connection";
}

function showNangoConnectLink(ctx, wizard, entry, session) {
  const attemptId = session && typeof session.attemptId === "string" ? session.attemptId.trim() : "";
  const rawLink = session && typeof session.connectLink === "string" ? session.connectLink : "";
  let link;
  try {
    link = new URL(rawLink);
  } catch {
    throw { status: 502, message: "Nango returned an invalid connect link" };
  }
  if (
    !attemptId ||
    link.origin !== "https://connect.nango.dev" ||
    link.username !== "" ||
    link.password !== ""
  ) {
    throw { status: 502, message: "Nango returned an invalid connect link" };
  }
  const status = wizard.querySelector("[data-nango-connect-status]");
  if (!status) throw { status: 500, message: "Authorization status is unavailable" };
  wizard.setAttribute("data-nango-attempt-id", attemptId);
  const expiresAt = session && typeof session.expiresAt === "string" ? session.expiresAt : "";
  status.innerHTML =
    '<div class="source-trust"><b>Authorization link ready</b><span>Authorize ' + ctx.esc(String(entry.name)) +
    " in the Nango-hosted window" + (expiresAt ? " before " + ctx.esc(expiresAt) : "") + ".</span></div>" +
    '<div class="source-wizard-actions"><a class="btn btn--outline" href="' + ctx.esc(link.href) +
    '" target="_blank" rel="noopener noreferrer">Authorize ' + ctx.esc(String(entry.name)) + "</a>" +
    '<button class="btn btn--solid" data-action="complete-nango-connect">I\'ve finished authorization</button></div>';
  const authorize = typeof status.querySelector === "function" ? status.querySelector("a") : null;
  if (authorize && typeof authorize.focus === "function") authorize.focus({ preventScroll: true });
}

async function createConfiguredSource(ctx, entry, setup, credentialId, wizard) {
  const existingSourceId = wizard && wizard.getAttribute
    ? String(wizard.getAttribute("data-created-source-id") || "")
    : "";
  const attemptId = wizard && wizard.getAttribute
    ? String(wizard.getAttribute("data-nango-attempt-id") || "")
    : "";
  const source = existingSourceId
    ? { id: existingSourceId }
    : await ctx.api.post("/v1/admin/sources", {
        kind: entry.id,
        config: {
          ...(credentialId ? { credentialId } : {}),
          ...setup.sourceConfig,
          selectedDataPoints: setup.selectedDataPoints,
          sourceAccessMode: entry.capabilities && entry.capabilities.sourceAcl ? "native" : "namespace-open",
        },
        ...(attemptId ? { idempotencyKey: attemptId } : {}),
        ...(setup.targetTeamId ? { targetTeamId: setup.targetTeamId } : {}),
      });
  if (!existingSourceId && source && source.id && wizard && wizard.setAttribute) {
    wizard.setAttribute("data-created-source-id", String(source.id));
  }
  if (setup.csvImport && source && source.id) {
    await ctx.api.post(
      "/v1/admin/sources/" + encodeURIComponent(String(source.id)) + "/import-csv",
      setup.csvImport,
    );
  }
  if (
    entry.delivery === "rest" && source && source.id &&
    Number.isFinite(setup.intervalSeconds) && setup.intervalSeconds >= 60
  ) {
    await ctx.api.post(
      "/v1/admin/sources/" + encodeURIComponent(String(source.id)) + "/schedule",
      { intervalSeconds: setup.intervalSeconds },
    );
  }
  closeWizard(wizard && wizard.ownerDocument, wizard, false);
  if (typeof ctx.go === "function") ctx.go("s6");
}

function csvFields(esc, prefix) {
  const fileId = controlId(prefix, "file");
  const stableId = controlId(prefix, "stable-id");
  const textId = controlId(prefix, "text-columns");
  const textHelpId = textId + "-help";
  const updatedId = controlId(prefix, "updated-at");
  const classificationId = controlId(prefix, "classification");
  return '<div class="field"><label for="' + esc(fileId) + '">CSV file *</label><input class="input" id="' + esc(fileId) + '" name="csvFile" type="file" accept=".csv,text/csv" data-csv-file required></div>' +
    '<div class="field"><label for="' + esc(stableId) + '">Stable ID column *</label><input class="input" id="' + esc(stableId) + '" name="idColumn" data-csv-id-column placeholder="id" required></div>' +
    '<div class="field"><label for="' + esc(textId) + '">Text columns *</label><input class="input" id="' + esc(textId) + '" name="textColumns" data-csv-text-columns placeholder="title, description, notes" aria-describedby="' + esc(textHelpId) + '" required><div class="subtle" id="' + esc(textHelpId) + '">Columns admitted into memory. Credentials are blocked.</div></div>' +
    '<div class="field"><label for="' + esc(updatedId) + '">Updated-at column</label><input class="input" id="' + esc(updatedId) + '" name="updatedAtColumn" data-csv-updated-column placeholder="updated_at"></div>' +
    '<div class="field"><label for="' + esc(classificationId) + '">Classification column</label><input class="input" id="' + esc(classificationId) + '" name="classificationColumn" data-csv-classification-column placeholder="classification"></div>';
}

function csvImportHtml(ctx, sourceId) {
  const { esc } = ctx;
  const titleId = controlId("source", sourceId, "csv-dialog-title");
  return '<button type="button" class="source-wizard-backdrop" data-action="cancel-connector" tabindex="-1" aria-label="Close CSV import"></button>' +
    '<section class="source-wizard-dialog" role="dialog" aria-modal="true" aria-labelledby="' + esc(titleId) +
    '"><div class="between source-wizard-head"><div><span class="source-category">Manual snapshot</span><h3 id="' +
    esc(titleId) + '" tabindex="-1" data-wizard-focus>Import CSV</h3></div>' +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="Close CSV import">' +
    closeIcon() + '<span>Close</span></button></div><div class="source-wizard-grid"><div>' + csvFields(esc, "source-csv") +
    '</div><div class="source-trust source-trust--warn"><b>Snapshot semantics</b><span>Rows missing from this import retire their prior source versions. Namespace, actor, ACL, and credential columns cannot be mapped.</span></div></div>' +
    '<div class="source-wizard-actions"><span style="flex:1"></span><button class="btn btn--solid" data-action="import-csv">Import governed snapshot</button></div></section>';
}

async function readCsvWizardPayload(wizard) {
  const fileInput = wizard.querySelector("[data-csv-file]");
  const file = fileInput && fileInput.files && fileInput.files[0];
  if (!file) throw { status: 400, message: "Choose a CSV file" };
  if (Number(file.size) > 512 * 1024) throw { status: 400, message: "CSV files must be 512KiB or smaller" };
  const idColumn = fieldValue(wizard, "[data-csv-id-column]");
  const textColumns = fieldValue(wizard, "[data-csv-text-columns]").split(",").map((value) => value.trim()).filter(Boolean);
  if (!idColumn || textColumns.length === 0) throw { status: 400, message: "ID and text columns are required" };
  const updatedAtColumn = fieldValue(wizard, "[data-csv-updated-column]");
  const classificationColumn = fieldValue(wizard, "[data-csv-classification-column]");
  return {
    csv: await file.text(),
    mapping: {
      idColumn,
      textColumns,
      ...(updatedAtColumn ? { updatedAtColumn } : {}),
      ...(classificationColumn ? { classificationColumn } : {}),
    },
  };
}

function fieldValue(root, selector) {
  const input = root.querySelector(selector);
  return input && input.value != null ? String(input.value).trim() : "";
}

async function sourceAction(ctx, el, action) {
  const id = el && el.getAttribute ? el.getAttribute("data-id") : "";
  if (!id) return;
  bulkUpdateNotice = null;
  setBusy(el, true, busyLabel(action));
  try {
    const result = await ctx.api.post("/v1/admin/sources/" + encodeURIComponent(id) + "/" + action, {});
    if (action === "test") {
      showSourceTestResult(el, result);
      return;
    }
    // A lifecycle change moves the numbers this connection reports, so its
    // cached lineage is stale the moment the call returns.
    lineageCache.delete(String(id));
    await refreshSourceScreen(ctx);
  } finally { setBusy(el, false); }
}

/**
 * Repaint the screen after a mutation and put the drawer back where the reader
 * left it. Refresh is preferred over navigation: a same-screen action must not
 * go through the route loader (it would scroll the page and drop the drawer).
 */
async function refreshSourceScreen(ctx) {
  if (typeof ctx.refresh === "function") {
    await ctx.refresh();
    reopenSourceDetail();
    return;
  }
  if (typeof ctx.go === "function") ctx.go("s6");
}

/** Re-open the drawer for `openSourceId` after the screen was re-rendered. */
function reopenSourceDetail() {
  if (openSourceId === null || typeof document === "undefined") return;
  const panel = document.getElementById("source-detail-panel");
  if (!panel) return;
  const opener = document.querySelector(
    '[data-source-tile][data-source-id="' + cssEscape(openSourceId) + '"]',
  );
  openRightPanel(panel, opener);
}

/** Drawer heading for the open connection. Values are set as text, never HTML. */
function updateSourceDetailHeader(ctx, panel, source) {
  if (!panel || typeof panel.querySelector !== "function") return;
  const facts = sourceFacts(source, ctx.esc);
  const eyebrow = panel.querySelector("[data-source-detail-eyebrow]");
  const title = panel.querySelector("[data-source-detail-title]");
  const line = panel.querySelector("[data-source-detail-facts]");
  if (eyebrow) eyebrow.textContent = "Connection";
  if (title) title.textContent = facts.displayName;
  if (line) {
    line.textContent = [
      facts.scopeLabel,
      DRIVER_COPY[facts.delivery] || DRIVER_COPY.rest,
      facts.status.label,
    ].join(" · ");
  }
}

/**
 * Fetch (once) and paint what a connection has written into memory. A failed
 * read is cached as `null` so the drawer says "unavailable" instead of retrying
 * on every open — and never so it reads as "nothing was synced".
 */
async function loadSourceLineage(ctx, id, doc) {
  if (!lineageCache.has(id)) {
    try {
      const lineage = await ctx.api.get("/v1/admin/sources/" + encodeURIComponent(id) + "/lineage");
      lineageCache.set(id, lineage && typeof lineage === "object" ? lineage : null);
    } catch {
      lineageCache.set(id, null);
    }
  }
  // The reader may have closed the drawer, or opened another connection, while
  // the rollup was in flight: never paint one connection's lineage into
  // another's drawer.
  if (openSourceId !== id || !doc || typeof doc.querySelector !== "function") return;
  const target = doc.querySelector("#source-detail-panel [data-source-lineage]");
  const source = sourceCache.find((row) => String((row && row.id) || "") === id);
  if (!target || !source) return;
  target.innerHTML = sourceLineageHtml(ctx, sourceFacts(source, ctx.esc), lineageCache.get(id));
}

function setBusy(el, busy, label = "Working…") {
  if (!el) return;
  if (busy) {
    if (el.dataset && !el.dataset.idleLabel) el.dataset.idleLabel = String(el.textContent || "");
    if ("textContent" in el) el.textContent = label;
  } else if (el.dataset && el.dataset.idleLabel) {
    if ("textContent" in el) el.textContent = el.dataset.idleLabel;
    delete el.dataset.idleLabel;
  }
  el.disabled = Boolean(busy);
  el.setAttribute("aria-busy", busy ? "true" : "false");
}

function showSourceTestResult(el, result) {
  const row = el && typeof el.closest === "function"
    ? el.closest("[data-source-connection]") || el.closest("tr")
    : null;
  const region = row && row.querySelector ? row.querySelector("[data-source-action-status]") : null;
  if (!region) return;
  const ok = Boolean(result && result.ok === true);
  const detail = result && result.detail ? String(result.detail) : "";
  region.className = "subtle" + (ok ? "" : " source-error");
  region.textContent = (ok ? "Connection test passed" : "Connection test failed") + (detail ? ": " + detail : ".");
  region.setAttribute("role", ok ? "status" : "alert");
  if (typeof region.focus === "function") region.focus({ preventScroll: true });
}

function busyLabel(action) {
  return ({ sync: "Syncing…", test: "Testing…", pause: "Pausing…", resume: "Resuming…" })[action] || "Working…";
}

function focusWizard(wizard) {
  const target = wizard && wizard.querySelector && wizard.querySelector("[data-wizard-focus]");
  if (target && typeof target.focus === "function") target.focus({ preventScroll: true });
}

/** Remember the dialog we are leaving so the next one can offer a way back. */
function trailPush(frame) {
  if (frame && frame.kind && frame.id) wizardTrail.push(frame);
}

function trailTop() {
  return wizardTrail.length ? wizardTrail[wizardTrail.length - 1] : null;
}

function trailBaseFrame(base) {
  return {
    kind: "knowledge-base",
    id: String((base && base.id) || ""),
    label: "Back to " + String((base && base.name) || "knowledge base"),
  };
}

/** Head control rendered by every dialog that can be reached from another one. */
function wizardBackHtml(esc) {
  const frame = trailTop();
  if (!frame) return "";
  return '<button type="button" class="btn btn--ghost btn--sm source-wizard-back" data-action="wizard-back" aria-label="' +
    esc(frame.label) + '" title="' + esc(frame.label) + '">' + backIcon() + "<span>Back</span></button>";
}

function wizardCloseHtml(esc, closeLabel) {
  return '<div class="row source-wizard-head-acts"><button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="' +
    esc(closeLabel) + '">' + closeIcon() + "<span>Close</span></button></div>";
}

/** The head's control cluster: Back (when there is somewhere to go) then Close. */
function wizardHeadActions(esc, closeLabel, extra) {
  return '<div class="row source-wizard-head-acts">' + wizardBackHtml(esc) + (extra || "") +
    '<button type="button" class="source-wizard-close halo-icon-control" data-action="cancel-connector" aria-label="' +
    esc(closeLabel) + '">' + closeIcon() + "<span>Close</span></button></div>";
}

/** Re-render a popped frame from the live cache. False means it is gone. */
function reopenTrailFrame(ctx, doc, wizard, frame) {
  if (!frame) return false;
  if (frame.kind === "knowledge-base") {
    const row = knowledgeBaseModel().find((candidate) => candidate.id === frame.id);
    if (!row) return false;
    openWizard(doc, wizard, knowledgeBaseDetailHtml(ctx, row, canMutate(ctx)), {
      "data-knowledge-base-id": frame.id,
    });
    return true;
  }
  if (frame.kind === "company-file") {
    const file = companyFileCache.find((candidate) => String(candidate && candidate.id) === frame.id);
    const base = file && knowledgeBaseCache.find((candidate) =>
      String(candidate && candidate.id) === String(file.knowledgeBaseId || ""));
    if (!file || !base) return false;
    const teamId = String(file.targetTeamId || base.targetTeamId || "");
    const team = teamId
      ? teamCache.find((candidate) => String(candidate && candidate.id) === teamId)
      : null;
    openWizard(doc, wizard, companyFileDetailHtml(ctx, file, base, team), {
      "data-company-file-id": frame.id,
      "data-knowledge-base-id": String(file.knowledgeBaseId || ""),
    });
    return true;
  }
  return false;
}

function openWizard(doc, wizard, html, attributes) {
  if (!wizard) return;
  for (const name of ["data-connector-id", "data-source-id", "data-created-source-id", "data-nango-attempt-id", "data-kb-kind", "data-knowledge-base-id", "data-company-file-id", "data-company-upload-batch-id", "data-replacement-created-id"]) {
    if (typeof wizard.removeAttribute === "function") wizard.removeAttribute(name);
  }
  for (const [name, value] of Object.entries(attributes || {})) {
    if (typeof wizard.setAttribute === "function") wizard.setAttribute(name, value);
  }
  wizard.innerHTML = html;
  wizard.inert = false;
  wizard.hidden = false;
  if (wizard.style) wizard.style.display = "grid";
  if (typeof wizard.setAttribute === "function") wizard.setAttribute("aria-hidden", "false");
  bindWizardKeydown(doc, wizard);
  // Move focus into the dialog before hiding the page behind it. Otherwise
  // the launch button is briefly a focused descendant of an aria-hidden node.
  focusWizard(wizard);
  setWizardBackground(doc, true);
}

function closeWizard(doc, wizard, shouldFocus) {
  unbindWizardKeydown();
  // Make the page operable and return/clear focus before hiding the dialog.
  // Chrome rejects aria-hidden when a close or backdrop button still owns
  // focus, which also leaves assistive-technology users in a hidden subtree.
  setWizardBackground(doc, false);
  restoreWizardTrigger(shouldFocus);
  const active = doc && doc.activeElement;
  const focusStillInside = Boolean(
    wizard && active &&
    (active === wizard || wizard.contains?.(active) || active.closest?.("#connector-wizard") === wizard),
  );
  if (focusStillInside && typeof active.blur === "function") active.blur();
  if (wizard) {
    wizard.inert = true;
    wizard.hidden = true;
    if (wizard.style) wizard.style.display = "none";
    if (typeof wizard.setAttribute === "function") wizard.setAttribute("aria-hidden", "true");
  }
  wizardTrail = [];
}

function setWizardBackground(doc, modalOpen) {
  const targets = doc && typeof doc.querySelectorAll === "function"
    ? [...doc.querySelectorAll("[data-source-page-content], #app-rail, #mobile-topbar")]
    : doc && typeof doc.querySelector === "function"
      ? [doc.querySelector("[data-source-page-content]")].filter(Boolean)
      : [];
  if (modalOpen && wizardBackgroundState.length === 0) {
    wizardBackgroundState = targets.map((target) => ({
      target,
      inert: Boolean(target.inert),
      hadAriaHidden: typeof target.hasAttribute === "function" && target.hasAttribute("aria-hidden"),
      ariaHidden: typeof target.getAttribute === "function" ? target.getAttribute("aria-hidden") : null,
    }));
  }
  if (modalOpen) {
    for (const target of targets) {
      target.inert = true;
      if (typeof target.setAttribute === "function") {
        target.setAttribute("aria-hidden", "true");
      }
    }
  } else {
    const previous = wizardBackgroundState;
    wizardBackgroundState = [];
    for (const state of previous) {
      state.target.inert = state.inert;
      if (state.hadAriaHidden && typeof state.target.setAttribute === "function") {
        state.target.setAttribute("aria-hidden", state.ariaHidden || "true");
      } else if (typeof state.target.removeAttribute === "function") {
        state.target.removeAttribute("aria-hidden");
      }
    }
  }
  const classList = doc && doc.body && doc.body.classList;
  if (classList && typeof classList.toggle === "function") {
    classList.toggle("source-modal-open", modalOpen);
  }
}

function bindWizardKeydown(doc, wizard) {
  unbindWizardKeydown();
  if (!doc || typeof doc.addEventListener !== "function") return;
  wizardKeydownDocument = doc;
  wizardKeydownHandler = (event) => {
    if (!event || !wizard || wizard.hidden) return;
    if (event.key === "Escape") {
      if (typeof event.preventDefault === "function") event.preventDefault();
      closeWizard(doc, wizard, true);
      return;
    }
    if (event.key === "Tab") trapWizardFocus(doc, wizard, event);
  };
  doc.addEventListener("keydown", wizardKeydownHandler);
}

function unbindWizardKeydown() {
  if (
    wizardKeydownDocument && wizardKeydownHandler &&
    typeof wizardKeydownDocument.removeEventListener === "function"
  ) {
    wizardKeydownDocument.removeEventListener("keydown", wizardKeydownHandler);
  }
  wizardKeydownDocument = null;
  wizardKeydownHandler = null;
}

function trapWizardFocus(doc, wizard, event) {
  if (!wizard || typeof wizard.querySelectorAll !== "function") return;
  const focusable = [...wizard.querySelectorAll(
    'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])',
  )].filter((element) => !element.hidden && element.getAttribute?.("aria-hidden") !== "true");
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const initial = typeof wizard.querySelector === "function"
    ? wizard.querySelector("[data-wizard-focus]")
    : null;
  const active = doc && doc.activeElement;
  if (event.shiftKey && (active === first || active === initial)) {
    event.preventDefault();
    last.focus({ preventScroll: true });
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus({ preventScroll: true });
  }
}

function restoreWizardTrigger(shouldFocus) {
  const trigger = wizardReturnFocus;
  wizardReturnFocus = null;
  if (!trigger) return;
  if (trigger.setAttribute) trigger.setAttribute("aria-expanded", "false");
  if (shouldFocus && typeof trigger.scrollIntoView === "function") trigger.scrollIntoView({ block: "nearest" });
  if (shouldFocus && typeof trigger.focus === "function") trigger.focus({ preventScroll: true });
}

function connectorName(kind) {
  const entry = catalogCache.find((candidate) => String(candidate.id) === kind);
  return entry ? String(entry.name) : kind;
}

function sourceDisplayName(kind) {
  const friendly = {
    filesystem: "Local files",
    "file-upload": "Uploaded file",
    doc_site: "Website",
    csv_sheet_import: "CSV file",
    webhook_source: "Webhook",
    obsidian_vault: "Obsidian",
    linear_direct: "Linear",
    google_drive_direct: "Google Drive",
    google_docs_direct: "Google Docs",
    google_sheets_direct: "Google Sheets",
  }[String(kind || "")];
  return friendly || connectorName(kind) || "Source";
}

function isBackendConnectionSource(source) {
  return !KNOWLEDGE_SOURCE_KINDS.has(String(source && source.kind || ""));
}

function isBackendCatalogEntry(entry) {
  return !HIDDEN_BACKEND_CATALOG_IDS.has(String(entry && entry.id || ""));
}

function sourceScopeLabel(namespace) {
  const ns = String(namespace || "");
  const team = teamCache.find((candidate) => String((candidate && candidate.namespace) || "") === ns);
  if (team && team.name) return sourceTeamLabel(team.name);
  const parts = ns.split("/").filter(Boolean);
  if (parts.length <= 1) return "Organization";
  return sourceTeamLabel(title(parts[parts.length - 1]));
}

function sourceTeamLabel(value) {
  const label = String(value || "").trim();
  return /\bteam$/i.test(label) ? label : label + " team";
}

function isTeamScopedSourceIdentity(ctx) {
  return String((ctx && ctx.identity && ctx.identity.namespace) || "")
    .split("/").filter(Boolean).length >= 2;
}

function sourceStatus(source) {
  if (source && source.lifecycleState === "paused") return { label: "Disconnected", detail: "Updates stopped", tone: "pill--warn", icon: "pause" };
  if (source && (source.syncStatus === "failed" || source.lastSyncError)) return { label: "Needs attention", detail: source.lastSync ? formatWhen(source.lastSync) : "Last update failed", tone: "pill--crit", icon: "error" };
  if (source && source.syncStatus === "pending") return { label: "Updating", detail: "In progress", tone: "pill--live", icon: "sync" };
  if (source && source.lastSync) return { label: "Up to date", detail: formatWhen(source.lastSync), tone: "pill--ok", icon: "check" };
  if (source && source.kind === "obsidian_vault") return { label: "Awaiting Obsidian", detail: "Finish pairing in Obsidian", tone: "pill--warn", icon: "ready" };
  return { label: "Connected", detail: "Not synced yet", tone: "pill--ok", icon: "check" };
}

function knowledgeStatusTone(status) {
  const value = String(status || "");
  if (value === "ready" || value === "active") return " pill--ok";
  if (value === "failed" || value === "archived") return " pill--crit";
  return " pill--warn";
}

function knowledgePieceConnection(piece, sources) {
  const sourceId = String((piece && piece.sourceId) || "");
  const source = sourceId
    ? sources.find((candidate) => String(candidate && candidate.id || "") === sourceId)
    : null;
  if (!source) return { label: "Linked", tone: " pill--warn" };
  const status = sourceStatus(source);
  if (status.tone === "pill--ok" || status.tone === "pill--live") {
    return { label: status.label === "Up to date" ? "Connected" : status.label, tone: " pill--ok" };
  }
  return { label: status.label, tone: " " + status.tone };
}

function companyFileFormat(file) {
  const media = String((file && file.mediaType) || "");
  const fileName = String((file && file.fileName) || "");
  const extMatch = /\.([A-Za-z0-9]+)$/.exec(fileName);
  const ext = extMatch ? extMatch[1].toLowerCase() : "";
  const names = {
    csv: "CSV",
    docx: "DOCX",
    json: "JSON",
    md: "Markdown",
    markdown: "Markdown",
    pdf: "PDF",
    txt: "Text",
    yaml: "YAML",
    yml: "YAML",
  };
  if (names[ext]) return names[ext];
  const mediaNames = {
    "application/pdf": "PDF",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
    "text/csv": "CSV",
    "text/markdown": "Markdown",
    "text/plain": "Text",
  };
  if (mediaNames[media]) return mediaNames[media];
  if (media) return title(media.split("/").pop() || media);
  return "File";
}

function categoryDetails(category) {
  const key = String(category || "custom");
  return CATEGORY_COPY[key] || [
    title(key),
    "Browse " + title(key).toLowerCase() + " systems available to this organization.",
  ];
}

function categoryIcon(category) {
  const key = String(category || "custom");
  const paths = {
    all: '<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/>',
    commerce: '<path d="M5 8h14l-1 12H6z"/><path d="M9 8a3 3 0 0 1 6 0"/>',
    pos: '<path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h3M14 12h2M8 16h2M13 16h3"/>',
    support: '<path d="M4 13v-2a8 8 0 0 1 16 0v2"/><path d="M4 13a2 2 0 0 1 2-2h1v6H6a2 2 0 0 1-2-2zM20 13a2 2 0 0 0-2-2h-1v6h1a2 2 0 0 0 2-2zM17 17c0 2-2 3-5 3"/>',
    messaging: '<path d="M5 5h14v10H9l-4 4z"/><path d="M9 9h6M9 12h4"/>',
    marketing: '<path d="M4 13h3l8 4V7l-8 4H4z"/><path d="M8 15l1 5h3l-1-4"/>',
    payments: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18M7 15h3"/>',
    fulfilment: '<path d="M4 8l8-4 8 4v9l-8 4-8-4z"/><path d="M4 8l8 4 8-4M12 12v9"/>',
    knowledge: '<path d="M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M8 4v16M11 8h4M11 12h4"/>',
  };
  const body = paths[key] || paths.all;
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + body + "</svg>";
}

function searchIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/></svg>';
}

function shieldIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>';
}

function sourceStateIcon(icon) {
  const paths = {
    check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l2.5 2.5L16 9"/>',
    error: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    pause: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9v6M14.5 9v6"/>',
    sync: '<path d="M19 8a8 8 0 0 0-13-2l-2 2M5 4v4h4M5 16a8 8 0 0 0 13 2l2-2M19 20v-4h-4"/>',
    ready: '<circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/>',
  };
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">' +
    (paths[icon] || paths.ready) + "</svg>";
}

function trashIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">' +
    '<path d="M4 7h16M10 4h4M9 7l.7 12h4.6L15 7M10 10.5v5M14 10.5v5" stroke-linecap="round"/></svg>';
}

function arrowIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5"/></svg>';
}

function backIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function closeIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function chevronIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m9 5 7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function authLabel(type) {
  return ({ oauth: "OAuth", api_key: "API key", basic_auth: "Basic auth", private_api: "Private API", webhook: "Webhook", manual: "Manual" })[type] || type;
}

function title(value) { return String(value).replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()); }
function providerInitials(value) {
  const initials = String(value)
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => Array.from(word)[0] || "")
    .join("")
    .toUpperCase();
  return initials || "?";
}
function connectorLogo(entry, esc) {
  const id = String((entry && entry.id) || "");
  const name = String((entry && entry.name) || id);
  const mark = providerInitials(name);
  const glyph = connectorProductGlyph(id);
  const fallbackKind = glyph ? "glyph" : "fallback";
  const fallback = glyph || esc(mark);
  const logo = trustedLogoUrl(entry && entry.logo) ||
    trustedLogoUrl(CONNECTOR_LOGO_FALLBACKS[id]);
  if (logo) {
    return '<span class="source-logo" data-provider-mark="' + esc(mark) +
      '" data-logo-kind="image" data-logo-fallback-kind="' + fallbackKind +
      '" aria-hidden="true"><span class="source-logo-fallback">' + fallback +
      '</span><img class="source-logo-image" data-connector-logo-image src="' +
      esc(logo) + '" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer"></span>';
  }
  if (glyph) {
    return '<span class="source-logo" data-provider-mark="' + esc(mark) +
      '" data-logo-kind="glyph" aria-hidden="true">' + glyph + "</span>";
  }
  return '<span class="source-logo" data-provider-mark="' + esc(mark) +
    '" data-logo-kind="fallback" aria-hidden="true">' + esc(mark) + "</span>";
}
function trustedLogoUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(String(value));
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      !TRUSTED_LOGO_HOSTS.has(url.hostname)
    ) return "";
    return url.href;
  } catch {
    return "";
  }
}
function connectorProductGlyph(id) {
  const paths = {
    custom_api: '<path d="M8 5H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2M16 5h2a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-2M9 15l6-6M10 9h5v5"/>',
    webhook_source: '<path d="M8 8a4 4 0 1 1 6.7 2.9L12 13.5M16 16a4 4 0 1 1-6.7-2.9L12 10.5"/><circle cx="12" cy="12" r="1.5"/>',
    csv_sheet_import: '<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v5h5M9 12h6M9 16h6M9 8h2"/>',
  };
  const body = paths[id];
  return body
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
      body + "</svg>"
    : "";
}
function shortId(id) { const value = String(id); return value.length > 8 ? "…" + value.slice(-8) : value; }
function canMutate(ctx) { const role = ctx.identity && ctx.identity.role; return role === "owner" || role === "root" || role === "admin"; }
function num(value) { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : 0; }
function fmt(value) { return (Number(value) || 0).toLocaleString("en-US"); }
function formatBytes(value) {
  const bytes = num(value);
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(bytes % 1048576 ? 1 : 0) + " MB";
  if (bytes >= 1024) return Math.round(bytes / 1024) + " KB";
  return bytes + " B";
}
function creatorDisplayName(value, resolve) {
  const actor = value && typeof value === "object"
    ? String(value.createdBy || "").trim()
    : String(value || "").trim();
  const displayName = value && typeof value === "object"
    ? value.createdByDisplayName
    : null;
  return personDisplayName({ actor, displayName }, resolve, "human") || "Unknown";
}
function scheduleLabel(seconds) {
  if (seconds % 86400 === 0) {
    const days = seconds / 86400;
    return days === 1 ? "Every day" : "Every " + days + " days";
  }
  if (seconds % 3600 === 0) {
    const hours = seconds / 3600;
    return hours === 1 ? "Every hour" : "Every " + hours + " hours";
  }
  const minutes = Math.round(seconds / 60);
  return "Every " + minutes + " minutes";
}
function scheduleOptions(selected) { return [[0, "Manual"], [900, "15m"], [3600, "Hourly"], [21600, "6h"], [86400, "Daily"]].map(([value, label]) => '<option value="' + value + '" ' + (value === selected ? "selected" : "") + ">" + label + "</option>").join(""); }
function formatWhen(iso) {
  const time = Date.parse(String(iso));
  if (!Number.isFinite(time)) return String(iso);
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return minutes + (minutes === 1 ? " minute ago" : " minutes ago");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + (hours === 1 ? " hour ago" : " hours ago");
  const days = Math.floor(hours / 24);
  return days + (days === 1 ? " day ago" : " days ago");
}
function formatUntil(iso) {
  const time = Date.parse(String(iso));
  if (!Number.isFinite(time)) return String(iso);
  const minutes = Math.round((time - Date.now()) / 60000);
  if (minutes <= 0) return "Due now";
  if (minutes < 60) return "In " + minutes + (minutes === 1 ? " minute" : " minutes");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return "In " + hours + (hours === 1 ? " hour" : " hours");
  const days = Math.floor(hours / 24);
  return "In " + days + (days === 1 ? " day" : " days");
}
function errorSuffix(err, esc) { return err && err.message ? ": " + esc(String(err.message)) : "."; }
function cssEscape(value) { return String(value).replace(/["\\]/g, "\\$&"); }
function controlId(...parts) { return parts.map((part) => String(part).replace(/[^A-Za-z0-9_-]/g, "-")).join("-"); }
function statCard(key, value, foot, tone) {
  return '<div class="stat"><div class="stat-label"><div class="k">' + key + "</div>" + statInfo(key, foot) + '</div><div class="v num' + (tone ? " " + tone : "") + '">' + value + "</div></div>";
}
function statInfo(label, detail) {
  if (!detail) return "";
  return '<span class="metric-info stat-info" role="note" tabindex="0" aria-label="' + label + ": " + detail + '" data-tip="' + detail + '"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span>';
}
