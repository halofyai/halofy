/**
 * S4 policy-document register. Content is rendered as metadata only.
 *
 * Layout, ordering, control shapes and copy follow the supplied Halomem
 * console prototype's Policies screen one-for-one: stat strip, register card
 * (title + search + state pills over a row-card table), "Found In Memory",
 * agent compliance, runtime dials, and intake in a right-side drawer.
 */

import { headingInfo } from "../heading-info.js";
import { organizationScopeLabel } from "../identity-labels.js";
import { metricCard } from "../metric-card.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";
import { screenTargetHash } from "../routes.js";
import { refreshPolicyCompliance } from "./policy-compliance.js";

const ALLOWED_EXTENSIONS = [".txt", ".md", ".markdown", ".csv", ".json", ".yaml", ".yml"];
const MAX_FILE_BYTES = 512 * 1024;
const KINDS = ["policy", "guideline", "procedure", "standard", "handbook", "other"];
const STATUSES = ["processing", "active", "needs_review", "failed"];
// How hard a loaded document lands on an agent. `required` is the default:
// the directive is delivered on every working-set assembly and an agent that
// acts without reading it is recorded as a bypass.
const ENFORCEMENTS = ["required", "advisory"];

const STATUS_LABEL = {
  active: "Agent-Ready",
  processing: "Processing",
  needs_review: "Needs Review",
  failed: "Failed",
};

let registerGeneration = 0;

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

function isInAdministrativeSubtree(candidate, base) {
  if (base === "") return true;
  return candidate === base || candidate.startsWith(base + "/");
}

function stateFromHash(ctx) {
  const base = String((ctx.identity && ctx.identity.namespace) || "");
  const hash = typeof window === "undefined" ? "" : String(window.location.hash || "");
  const raw = hash.split("?", 2)[1] || "";
  const params = new URLSearchParams(raw);
  const requestedScope = params.has("scope") ? String(params.get("scope")) : base;
  const namespace = isInAdministrativeSubtree(requestedScope, base) ? requestedScope : base;
  const rawPage = Number(params.get("page") || 1);
  const kind = String(params.get("kind") || "");
  const status = String(params.get("status") || "");
  return {
    namespace,
    page: Number.isInteger(rawPage) && rawPage > 0 ? rawPage : 1,
    query: String(params.get("query") || "").trim().slice(0, 200),
    kind: KINDS.includes(kind) ? kind : "",
    status: STATUSES.includes(status) ? status : "",
  };
}

/**
 * The scope the screen is pointed at, resolvable before any read. S4 needs it
 * to fan the register, compliance and dial reads out in parallel rather than
 * waiting for the register to name the scope for the other two.
 */
export function policyScopeNamespace(ctx) {
  return stateFromHash(ctx).namespace;
}

function stateHash(ctx, state) {
  const base = String((ctx.identity && ctx.identity.namespace) || "");
  const params = new URLSearchParams();
  if (state.namespace !== base) params.set("scope", state.namespace);
  if (state.query) params.set("query", state.query);
  if (state.kind) params.set("kind", state.kind);
  if (state.status) params.set("status", state.status);
  if (state.page > 1) params.set("page", String(state.page));
  const query = params.toString();
  return String(screenTargetHash("s4" + (query ? "?" + query : ""))).replace(/^#/, "");
}

function persistState(ctx, state) {
  if (typeof history === "undefined") return;
  history.replaceState(null, "", "#" + stateHash(ctx, state));
}

function adoptionPath(namespace) {
  return "/v1/admin/policy-adoption-candidates?" + new URLSearchParams({
    namespace,
    limit: "25",
  }).toString();
}

function listPath(namespace, { page = 1, query = "", kind = "", status = "" } = {}) {
  const params = new URLSearchParams({
    namespace,
    page: String(page),
    pageSize: "20",
  });
  if (query) params.set("query", query);
  if (kind) params.set("kind", kind);
  if (status) params.set("status", status);
  return "/v1/admin/policy-documents?" + params.toString();
}

function normalizedResult(value) {
  const data = Array.isArray(value && value.data) ? value.data : [];
  const rawPage = value && value.pagination ? value.pagination : {};
  const rawSummary = value && value.summary ? value.summary : {};
  const number = (candidate, fallback = 0) => {
    const parsed = Number(candidate);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
  };
  return {
    data,
    pagination: {
      page: Math.max(1, number(rawPage.page, 1)),
      pageSize: Math.max(1, number(rawPage.pageSize, 20)),
      total: number(rawPage.total),
      totalPages: number(rawPage.totalPages),
    },
    summary: {
      total: number(rawSummary.total),
      active: number(rawSummary.active),
      needsReview: number(rawSummary.needsReview),
      failed: number(rawSummary.failed),
    },
  };
}

function normalizedCandidates(value) {
  const data = Array.isArray(value && value.data) ? value.data : [];
  return { data, hasMore: Boolean(value && value.hasMore) };
}

/**
 * Policy files already in memory but missing from the register. The register
 * only ever knew about its own upload lane, so a file that arrived through an
 * import or connector was invisible here while agents could already read it.
 * A brownout in this lane must not blank the register, so it degrades to empty.
 */
async function discoverAdoptable(ctx, namespace) {
  try {
    return normalizedCandidates(await ctx.api.get(adoptionPath(namespace)));
  } catch {
    return { data: [], hasMore: false };
  }
}

/**
 * @param bypasses guardrail bypasses in scope, from the compliance ledger.
 *   `null` when that ledger is unreadable for this caller — the stat card says
 *   Unavailable rather than turning an unknown into a zero.
 */
export async function renderPolicyLibrary(ctx, bypasses = null) {
  const state = stateFromHash(ctx);

  // The register and the "found in memory" lane are independent reads, so they
  // share one round trip rather than stacking two.
  const [listed, candidates] = await Promise.all([
    ctx.api.get(listPath(state.namespace, state)).then(
      (value) => ({ result: normalizedResult(value) }),
      (error) => ({ error }),
    ),
    discoverAdoptable(ctx, state.namespace),
  ]);
  const result = listed.result ?? null;
  const loadError = listed.error ?? null;

  return {
    namespace: state.namespace,
    headActions: headActionsMarkup(ctx, result),
    html: libraryMarkup(ctx, state, result, loadError, candidates, bypasses),
  };
}

/**
 * Title-bar actions: the amber needs-review count (a filter, not a badge) and
 * the primary that opens the intake drawer. Both sit where the prototype puts
 * them, on the title row rather than inside the register card.
 */
function headActionsMarkup(ctx, result) {
  const needsReview = result ? result.summary.needsReview : 0;
  // Always rendered, hidden at zero: the count refreshes in place when the
  // register reloads, so it has to survive the state where nothing is waiting.
  const review = `<button type="button" class="policy-flag" data-action="policy-needs-review"
    data-policy-review-flag${needsReview > 0 ? "" : " hidden"}>${ctx.esc(
      needsReview,
    )} Needs Review</button>`;
  const add = canMutate(ctx)
    ? `<button type="button" class="policy-primary" data-action="policy-add-open" aria-controls="policy-add-panel"
        aria-haspopup="dialog" aria-expanded="false">Add Policy File</button>`
    : "";
  return review + add;
}

/** The prototype's 28px file chip. Used by both register and candidate rows. */
function fileChip() {
  return `<span class="policy-chip" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><path d="M14 2v6h6"></path></svg></span>`;
}

function libraryMarkup(ctx, state, result, loadError, candidates, bypasses) {
  const { esc } = ctx;
  const writable = canMutate(ctx);
  return `<section class="policy-library" data-policy-scope="${esc(state.namespace)}" aria-labelledby="policy-library-title">
    ${result ? summaryMarkup(esc, result.summary, bypasses) : summaryUnavailableMarkup()}
    ${writable ? "" : readOnlyMarkup()}
    <div class="policy-panel policy-register-card">
      <div class="policy-panel__head">
        <div class="policy-panel__title">
          <h2 id="policy-library-title">Policy Register</h2>${headingInfo(
            "Policy Register",
            "One row per governed file. Deleting a policy retracts exactly the facts it contributed &mdash; they close their validity and move into retracted history.",
          )}
        </div>
        <div class="policy-panel__controls">
          <div class="policy-search">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="6.5"></circle><path d="m16 16 4 4" stroke-linecap="round"></path></svg>
            <label class="sr-only" for="policy-query">Search policies</label>
            <input id="policy-query" type="search" autocomplete="off" data-input-action="policy-library-filter"
              value="${esc(state.query)}" placeholder="Search title, file or scope">
          </div>
          ${statusFieldMarkup(ctx, state)}
        </div>
      </div>
      <div class="policy-register" data-policy-register aria-live="polite">
        ${loadError ? errorMarkup(ctx, loadError) : registerMarkup(ctx, result, hasFilters(state))}
      </div>
      <div data-policy-pagination>${result ? paginationMarkup(esc, result.pagination) : ""}</div>
    </div>
    <div data-policy-adoption>${adoptionMarkup(ctx, candidates)}</div>
    ${writable ? intakeDrawerMarkup() : ""}
  </section>`;
}

/**
 * The stat strip, card-for-card with the prototype: tracked, agent-ready,
 * needs review, and guardrail bypasses. Failed is deliberately not a card -
 * it is a state pill and a filter tab, not a headline number.
 */
function summaryMarkup(esc, summary, bypasses) {
  const cards = [
    {
      k: "Tracked Policies",
      v: esc(summary.total),
      icon: "file",
      cap: "Governed Files In This Scope",
      foot: "Every policy file the register tracks in your subtree, whatever its state.",
    },
    {
      k: "Agent-Ready",
      v: esc(summary.active),
      icon: "guardrail",
      cap: "Delivered As Guardrails",
      foot: "Extracted, verified and handed to every agent before it acts in scope.",
    },
    {
      k: "Needs Review",
      v: esc(summary.needsReview),
      icon: "review",
      cap: summary.needsReview > 0 ? "Extraction Needs A Human" : "Nothing Waiting",
      capTone: summary.needsReview > 0 ? "warn" : undefined,
      foot: "Loaded files whose extracted directives need a human check before agents rely on them.",
    },
    {
      k: "Bypasses",
      v: bypasses === null ? "Unavailable" : esc(bypasses),
      icon: "bypass",
      cap: bypasses === null ? "Ledger Not Readable Here" : "Agent Actions Without Reading",
      capTone: bypasses === null ? undefined : bypasses > 0 ? "crit" : undefined,
      foot: "Times an agent wrote or read a backend without ever being handed the current policy version. Counted off the append-only ledger.",
    },
  ];
  return `<div class="grid g4 policy-summary" data-policy-summary role="list" aria-label="Policy file summary">${cards
    .map((card) => metricCard(card))
    .join("")}</div>`;
}

function summaryUnavailableMarkup() {
  return `<div class="grid policy-summary policy-summary--stale" data-policy-summary aria-label="Policy file summary unavailable">
    <div class="stat stat--secondary"><div class="k">Unavailable</div><div class="v num">-</div></div>
  </div>`;
}

/**
 * Intake lives in the platform's right-side drawer, as the prototype has it:
 * one task with its own four-step flow, off the page so the register - what an
 * operator came to read - starts above the fold.
 */
function intakeDrawerMarkup() {
  return rightPanelHtml({
    id: "policy-add-panel",
    eyebrow: "Policies",
    title: "Add Policy File",
    closeAction: "policy-add-close",
    className: "policy-add-drawer",
    body: uploadMarkup(),
  });
}

function uploadMarkup() {
  const kindOptions = KINDS.map((kind) => `<option value="${kind}">${titleCase(kind)}</option>`).join("");
  return `<div class="policy-intake">
    <div class="policy-intake__sub">Text, Markdown, CSV, JSON or YAML &middot; Maximum 512 KiB</div>
    <div class="policy-flow" aria-label="Governed policy upload flow">
      <span><b>1</b>Upload</span><i aria-hidden="true">&rarr;</i>
      <span><b>2</b>Classify &amp; Extract</span><i aria-hidden="true">&rarr;</i>
      <span><b>3</b>Verify &amp; Provenance</span><i aria-hidden="true">&rarr;</i>
      <span><b>4</b>Agent-Ready</span>
    </div>
    <div class="policy-upload-fields">
      <div class="policy-field policy-file-field">
        <label for="policy-file">Policy File <span class="policy-req">*</span></label>
        <label class="policy-dropzone">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><path d="M14 2v6h6"></path></svg>
          <span class="policy-dropzone__name" data-policy-file-name>Choose A File&hellip;</span>
          <span class="policy-dropzone__hint">Click to browse</span>
          <input class="policy-dropzone__input" id="policy-file" type="file"
            accept=".txt,.md,.markdown,.csv,.json,.yaml,.yml" data-change-action="policy-file-pick">
        </label>
      </div>
      <div class="policy-field"><label for="policy-title">Display Title <span class="subtle">(Optional)</span></label>
        <input class="policy-control" id="policy-title" maxlength="200" autocomplete="off" placeholder="Use the file name"></div>
      <div class="policy-field"><label for="policy-kind">Document Type</label>
        <select class="select policy-control" id="policy-kind">${kindOptions}</select></div>
      <div class="policy-field"><label for="policy-enforcement">Guardrail</label>
        <select class="select policy-control" id="policy-enforcement">
          <option value="required">Required &middot; Agents Must Read It</option>
          <option value="advisory">Advisory &middot; Delivered, Not Tracked</option>
        </select>
        <div class="policy-hint">A required policy is delivered on every working-set assembly; acting without reading it is recorded as a bypass.</div></div>
    </div>
    <div class="policy-upload-status" data-policy-upload-status role="status" aria-live="polite"></div>
  </div>
  <div class="policy-intake-actions">
    <button type="button" class="policy-ghost" data-action="policy-add-close">Cancel</button>
    <button type="button" class="policy-primary policy-upload-button" data-action="policy-file-upload">Load Policy File</button>
  </div>`;
}

function readOnlyMarkup() {
  return `<div class="policy-readonly"><span class="pill"><i class="dot"></i>Read-only policy register</span></div>`;
}

/**
 * State is a field, not a visible strip. The cut is still driven - by the
 * title-bar needs-review flag, the empty-state clear action and the ?status=
 * hash - so the value has to survive a re-render even with no tabs to click.
 */
function statusFieldMarkup(ctx, state) {
  return `<input type="hidden" id="policy-filter-status" value="${ctx.esc(state.status)}">`;
}

/** Point the register at one state. */
function setStatusFilter(root, value) {
  const field = root.querySelector?.("#policy-filter-status");
  if (field) field.value = value;
}

function hasFilters(state) {
  return Boolean(state.query || state.kind || state.status);
}

const REGISTER_COLUMNS =
  `<span>Policy</span><span>Type</span><span>Scope</span><span class="num">` +
  `<abbr title="Facts in memory">Facts</abbr></span><span>Guardrail</span>` +
  `<span>Status</span><span>Loaded</span><span></span>`;

function registerMarkup(ctx, result, filtered = false) {
  if (!result || result.data.length === 0) {
    const writable = canMutate(ctx);
    if (filtered && result && result.summary.total > 0) {
      return `<div class="policy-empty" role="status">No policies match these filters.
        <button type="button" class="policy-ghost" data-action="policy-library-clear">Clear Filters</button></div>`;
    }
    return `<div class="policy-empty" role="status">No policy files in this scope.
      <p>${writable
        ? "Load the first policy, guide, or standard from Add Policy File. Runtime dials remain available below."
        : "No governed policy documents have been loaded for this scope yet."}</p></div>`;
  }

  const writable = canMutate(ctx);
  const rows = result.data
    .map((document) => documentRow(ctx, document, writable))
    .join("");
  return `<div class="policy-rowscroll"><div class="policy-rowset">
    <div class="policy-rowhead policy-row--register" aria-hidden="true">${REGISTER_COLUMNS}</div>
    <div class="policy-rows" role="list" aria-label="Policy files">${rows}</div>
  </div></div>`;
}

/**
 * One row per policy FILE, in the prototype's column order: what it is, its
 * type and scope, how much memory it contributed, how hard it lands, its
 * state, when it landed, and the delete that retracts exactly those facts.
 */
function documentRow(ctx, document, writable) {
  const { esc } = ctx;
  const status = STATUSES.includes(document && document.status) ? document.status : "processing";
  const id = (document && document.id) || "";
  const title = (document && document.title) || "Untitled policy";
  const factCount = Number.isFinite(Number(document && document.factCount))
    ? Number(document.factCount)
    : 0;
  const adopted = (document && document.origin) === "adopted";
  const failure = status === "failed" && document && document.failureCode
    ? `<span class="policy-row__fail">${esc(document.failureCode)}</span>`
    : "";
  const deleteButton = writable
    ? `<button type="button" class="policy-row__delete" data-action="policy-document-delete"
        data-document="${esc(id)}" data-title="${esc(title)}" data-facts="${esc(factCount)}"
        aria-label="Delete policy" title="Remove this policy and retract its facts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6"></path></svg>
      </button>`
    : "<span></span>";
  return `<div class="policy-row policy-row--register" role="listitem" data-policy-document="${esc(id)}">
    <span class="policy-row__ident">
      ${fileChip()}
      <span class="policy-row__text">
        <strong>${esc(title)}</strong>
        <small>${esc((document && document.fileName) || "Unknown file")} &middot; ${esc(
          formatBytes(document && document.byteSize),
        )} &middot; ${esc(adopted ? "Adopted From Memory" : "Uploaded Here")}</small>
        ${failure}
      </span>
    </span>
    <span class="policy-row__cell">${esc(titleCase((document && document.kind) || "other"))}</span>
    <span class="policy-row__cell">${esc(
      organizationScopeLabel(
        document && document.namespace,
        ctx.organizationName,
        ctx.identity?.namespace,
      ),
    )}</span>
    <span class="policy-row__cell num strong" title="Facts in memory">${esc(factCount)}</span>
    <span>${enforcementControl(ctx, document, writable, status)}</span>
    <span><span class="policy-state policy-state--${esc(status)}"><i aria-hidden="true"></i>${esc(
      STATUS_LABEL[status] || titleCase(status),
    )}</span></span>
    <span class="policy-row__cell policy-row__when">${esc(
      formatDate((document && document.loadedAt) || (document && document.createdAt)),
    )}</span>
    ${deleteButton}
  </div>`;
}

/**
 * The guardrail level is the control, not a label beside one: one pill that
 * flips required <-> advisory in place. A failed or still-processing file has
 * nothing to enforce yet, so its pill is inert and says why.
 */
function enforcementControl(ctx, document, writable, status) {
  const { esc } = ctx;
  const level = (document && document.enforcement) === "advisory" ? "advisory" : "required";
  const tone = level === "required" ? "required" : "advisory";
  const changeable = writable && (status === "active" || status === "needs_review");
  if (!changeable) {
    return `<span class="policy-level policy-level--${tone}" title="Only an agent-ready policy can change level">${esc(
      titleCase(level),
    )}</span>`;
  }
  const next = level === "required" ? "advisory" : "required";
  return `<button type="button" class="policy-level policy-level--${tone} policy-level--flip"
    data-action="policy-enforcement-toggle" data-document="${esc((document && document.id) || "")}"
    data-enforcement="${esc(next)}" title="Click to make this policy ${esc(next)}">${esc(
      titleCase(level),
    )}</button>`;
}

/**
 * The "found in memory" lane. These files reached memory through another
 * governed lane (an import or connector, D10), so their facts are already
 * agent-visible; adopting one registers it here so it becomes a tracked
 * guardrail and can be deleted as a unit.
 */
function adoptionMarkup(ctx, candidates) {
  const { esc } = ctx;
  const rows = candidates && Array.isArray(candidates.data) ? candidates.data : [];
  if (rows.length === 0) return "";
  const writable = canMutate(ctx);
  const cards = rows.map((candidate) => {
    const fileName = (candidate && candidate.fileName) || "";
    const factCount = Number.isFinite(Number(candidate && candidate.factCount))
      ? Number(candidate.factCount)
      : 0;
    const action = writable
      ? `<button type="button" class="policy-ghost" data-action="policy-adopt"
          data-file="${esc(fileName)}" data-source="${esc((candidate && candidate.sourceId) || "")}"
          data-namespace="${esc((candidate && candidate.namespace) || "")}"
          data-title="${esc((candidate && candidate.title) || fileName)}"
          title="Track this file in the register and hand it to agents as a guardrail">Add To Register</button>`
      : "";
    return `<div class="policy-row policy-row--candidate" role="listitem">
      <span class="policy-row__ident">
        ${fileChip()}
        <span class="policy-row__text">
          <strong>${esc((candidate && candidate.title) || fileName || "Untitled file")}</strong>
          <small>${esc(fileName || "Unknown file")} &middot; ${esc(
            formatBytes(candidate && candidate.byteSize),
          )} &middot; Landed ${esc(formatDate(candidate && candidate.lastSeenAt))}</small>
        </span>
      </span>
      <span><span class="policy-state policy-state--unregistered"><i aria-hidden="true"></i>In Memory, Unregistered</span></span>
      <span class="policy-row__cell num strong" title="Facts in memory">${esc(factCount)}</span>
      <span class="policy-row__cell policy-row__signal">${esc(signalLabel(candidate && candidate.signal))}</span>
      <span class="policy-row__act">${action}</span>
    </div>`;
  }).join("");
  return `<section class="policy-panel policy-adoption" aria-labelledby="policy-adoption-title">
    <div class="policy-panel__head">
      <div class="policy-panel__title">
        <h3 id="policy-adoption-title">Found In Memory</h3>${headingInfo(
          "Found In Memory",
          "These files reached memory through an import or connector, so agents can already read them &mdash; but they are not tracked here or handed out as guardrails. Registering one adopts the existing facts; nothing is re-imported.",
        )}
      </div>
    </div>
    <div class="policy-rowscroll"><div class="policy-rowset policy-rowset--candidates">
      <div class="policy-rows" role="list">${cards}</div>
    </div></div>
    ${candidates && candidates.hasMore
      ? '<p class="policy-hint">More files match than are shown. Register these first.</p>'
      : ""}
    <div class="policy-adoption-status" data-policy-adoption-status role="status" aria-live="polite"></div>
  </section>`;
}

function signalLabel(signal) {
  if (signal === "both") return "Matched by file name and content";
  if (signal === "content") return "Matched by fact content";
  return "Matched by file name";
}

function errorMarkup(ctx, error) {
  const detail = ctx.esc(error && error.message ? error.message : "The register could not be loaded.");
  return `<div class="policy-error" role="alert"><div><h3>Policy files are temporarily unavailable</h3>
    <p>${detail}</p></div><button type="button" class="policy-ghost" data-action="policy-library-retry">Retry</button></div>`;
}

function paginationMarkup(esc, pagination) {
  if (!pagination || pagination.totalPages <= 1) return "";
  const page = Math.min(pagination.page, pagination.totalPages);
  return `<nav class="policy-pagination" aria-label="Policy file pages">
    <span>Page ${esc(page)} of ${esc(pagination.totalPages)} &middot; ${esc(pagination.total)} files</span>
    <div><button type="button" class="policy-ghost" data-action="policy-library-page" data-page="${esc(page - 1)}"${page <= 1 ? " disabled" : ""}>Previous</button>
    <button type="button" class="policy-ghost" data-action="policy-library-page" data-page="${esc(page + 1)}"${page >= pagination.totalPages ? " disabled" : ""}>Next</button></div>
  </nav>`;
}

function stateFromControls(ctx, root, requestedPage) {
  const current = stateFromHash(ctx);
  return {
    namespace: String(root.querySelector(".policy-library")?.getAttribute("data-policy-scope") ?? current.namespace),
    page: Math.max(1, Number(requestedPage) || 1),
    query: String(root.querySelector("#policy-query")?.value ?? "").trim().slice(0, 200),
    kind: String(root.querySelector("#policy-filter-kind")?.value ?? ""),
    status: String(root.querySelector("#policy-filter-status")?.value ?? ""),
  };
}

async function refreshRegister(ctx, root, requestedPage) {
  const generation = ++registerGeneration;
  const register = root.querySelector("[data-policy-register]");
  const pagination = root.querySelector("[data-policy-pagination]");
  const state = stateFromControls(ctx, root, requestedPage);
  persistState(ctx, state);
  if (register) {
    register.setAttribute("aria-busy", "true");
    register.innerHTML = '<div class="policy-loading" role="status">Loading policy files&hellip;</div>';
  }
  try {
    const result = normalizedResult(await ctx.api.get(listPath(state.namespace, state)));
    if (generation !== registerGeneration) return;
    if (register) register.innerHTML = registerMarkup(ctx, result, hasFilters(state));
    if (pagination) pagination.innerHTML = paginationMarkup(ctx.esc, result.pagination);
    updateSummaryCounts(ctx, root, result.summary);
  } catch (error) {
    if (generation !== registerGeneration) return;
    const summary = root.querySelector("[data-policy-summary]");
    if (register) register.innerHTML = errorMarkup(ctx, error);
    if (pagination) pagination.innerHTML = "";
    if (summary) summary.outerHTML = summaryUnavailableMarkup();
  } finally {
    if (generation === registerGeneration && register) {
      register.setAttribute("aria-busy", "false");
    }
  }
}

/**
 * Move the three register figures and the title-bar flag onto the numbers the
 * server just returned. The bypass card is not touched here - it belongs to
 * the compliance ledger, which this read knows nothing about.
 */
function updateSummaryCounts(ctx, root, summary) {
  const cards = root.querySelectorAll?.("[data-policy-summary] .metric-card") ?? [];
  const values = [summary.total, summary.active, summary.needsReview];
  Array.from(cards).slice(0, 3).forEach((card, index) => {
    const value = card.querySelector?.(".v");
    if (value) value.textContent = String(values[index]);
  });
  const review = Array.from(cards)[2]?.querySelector?.(".metric-card-cap");
  if (review) {
    review.textContent = summary.needsReview > 0 ? "Extraction Needs A Human" : "Nothing Waiting";
    review.classList?.toggle?.("metric-card-cap--warn", summary.needsReview > 0);
  }
  // The title-bar flag reads the same figure as the card, so it must move with
  // it - a stale "3 Needs Review" over an empty queue is a lie.
  const flag = root.querySelector("[data-policy-review-flag]");
  if (flag) {
    flag.textContent = summary.needsReview + " Needs Review";
    flag.hidden = summary.needsReview === 0;
  }
}

/**
 * Re-read the "found in memory" lane. Only mutations change it (adopting a
 * file removes it; deleting a registered file may return it), so filter typing
 * deliberately does not pay for this request.
 */
async function refreshAdoption(ctx, root, namespace) {
  const host = root.querySelector("[data-policy-adoption]");
  if (!host) return;
  const candidates = await discoverAdoptable(ctx, namespace);
  host.innerHTML = adoptionMarkup(ctx, candidates);
}

function uploadValidation(file) {
  const name = String(file && file.name || "");
  if (!name || /[\\/\u0000-\u001f\u007f]/.test(name)) {
    return "Choose a file with a plain filename (no folders or control characters).";
  }
  const lower = name.toLowerCase();
  if (!ALLOWED_EXTENSIONS.some((extension) => lower.endsWith(extension))) {
    return "Choose a supported text file: TXT, Markdown, CSV, JSON, YAML, or YML.";
  }
  if (!Number.isFinite(file.size) || file.size <= 0) return "Choose a non-empty policy file.";
  if (file.size > MAX_FILE_BYTES) return "Policy files must be 512 KiB or smaller.";
  return null;
}

export const policyLibraryActions = {
  "policy-add-open"(_ctx, el) {
    const root = el.closest?.(".policy-screen") ?? (typeof document === "undefined" ? null : document);
    const panel = root && root.querySelector ? root.querySelector("#policy-add-panel") : null;
    openRightPanel(panel, el);
  },

  "policy-add-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
  },

  /** Name the chosen file in the dropzone, the way the prototype's does. */
  "policy-file-pick"(_ctx, el) {
    const root = el.closest?.(".policy-screen") ?? document;
    const label = root.querySelector?.("[data-policy-file-name]");
    if (!label) return;
    const file = el.files && el.files[0] ? el.files[0] : null;
    label.textContent = file ? file.name : "Choose A File…";
    label.classList?.toggle?.("is-chosen", Boolean(file));
  },

  async "policy-needs-review"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    setStatusFilter(root, "needs_review");
    await refreshRegister(ctx, root, 1);
  },

  async "policy-library-filter"(ctx, el) {
    await refreshRegister(ctx, el.closest(".policy-screen") ?? document, 1);
  },

  async "policy-library-clear"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    const query = root.querySelector("#policy-query");
    const kind = root.querySelector("#policy-filter-kind");
    if (query) query.value = "";
    if (kind) kind.value = "";
    setStatusFilter(root, "");
    await refreshRegister(ctx, root, 1);
  },

  async "policy-library-page"(ctx, el) {
    await refreshRegister(
      ctx,
      el.closest(".policy-screen") ?? document,
      Number(el.getAttribute("data-page") || 1),
    );
  },

  async "policy-enforcement-toggle"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    const documentId = String(el.getAttribute("data-document") || "");
    const enforcement = String(el.getAttribute("data-enforcement") || "");
    if (!documentId || !ENFORCEMENTS.includes(enforcement)) return;
    el.disabled = true;
    try {
      await ctx.api.put(
        "/v1/admin/policy-documents/" + encodeURIComponent(documentId) + "/enforcement",
        { enforcement },
      );
      await refreshRegister(ctx, root, stateFromHash(ctx).page);
      await refreshPolicyCompliance(ctx, root, stateFromHash(ctx).namespace);
    } finally {
      el.disabled = false;
    }
  },

  async "policy-document-delete"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    const documentId = String(el.getAttribute("data-document") || "");
    const title = String(el.getAttribute("data-title") || "this policy");
    const facts = Number(el.getAttribute("data-facts") || 0);
    if (!documentId) return;
    // Deletion retracts (D7) — the facts close their validity and move into
    // retracted history rather than disappearing. Say that, so the operator is
    // not warned about a permanence the kernel does not actually apply.
    const factsClause = Number.isFinite(facts) && facts > 0
      ? `Its ${facts} fact${facts === 1 ? "" : "s"} stop being served to agents and move into retracted history.`
      : "Any facts it contributed stop being served to agents and move into retracted history.";
    const confirmed = window.confirm(
      `Delete ${title}?\n\n${factsClause}\n\nThe register row is removed and the deletion is audited.`,
    );
    if (!confirmed) return;
    el.disabled = true;
    try {
      await ctx.api.del(
        "/v1/admin/policy-documents/" + encodeURIComponent(documentId),
      );
      await refreshRegister(ctx, root, 1);
      await refreshAdoption(ctx, root, stateFromHash(ctx).namespace);
      await refreshPolicyCompliance(ctx, root, stateFromHash(ctx).namespace);
    } finally {
      el.disabled = false;
    }
  },

  async "policy-adopt"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    const fileName = String(el.getAttribute("data-file") || "");
    const sourceId = String(el.getAttribute("data-source") || "");
    const namespace = String(el.getAttribute("data-namespace") || "");
    const title = String(el.getAttribute("data-title") || fileName);
    if (!fileName || !sourceId) return;
    const status = root.querySelector("[data-policy-adoption-status]");
    const announce = (message, alert = false) => {
      if (!status) return;
      status.textContent = message;
      status.setAttribute("role", alert ? "alert" : "status");
    };
    el.disabled = true;
    announce(`Adding ${title} to the register\u2026`);
    try {
      await ctx.api.post("/v1/admin/policy-documents/adopt", {
        namespace,
        fileName,
        sourceId,
      });
      await refreshRegister(ctx, root, 1);
      // Adoption changes the governing digest, so every agent's standing moves
      // with it — the compliance panel must not keep the previous numbers.
      await refreshPolicyCompliance(ctx, root, stateFromHash(ctx).namespace);
      await refreshAdoption(ctx, root, stateFromHash(ctx).namespace);
    } catch (error) {
      announce(
        "Could not add that file: " + (error && error.message ? error.message : "unknown error"),
        true,
      );
      el.disabled = false;
    }
  },

  async "policy-library-retry"(ctx, el) {
    await refreshRegister(
      ctx,
      el.closest(".policy-screen") ?? document,
      stateFromHash(ctx).page,
    );
  },

  async "policy-file-upload"(ctx, el) {
    const root = el.closest(".policy-screen") ?? document;
    const input = root.querySelector("#policy-file");
    const file = input && input.files ? input.files[0] : null;
    const statusRegion = root.querySelector("[data-policy-upload-status]");
    const announce = (message, alert = false) => {
      if (!statusRegion) return;
      statusRegion.textContent = message;
      statusRegion.setAttribute("role", alert ? "alert" : "status");
    };
    const invalid = uploadValidation(file);
    if (invalid) {
      announce(invalid, true);
      return;
    }

    el.disabled = true;
    announce("Loading file into the governed write path\u2026");
    try {
      const content = await file.text();
      const bytes = new TextEncoder().encode(content).byteLength;
      if (bytes === 0 || content.includes("\u0000")) {
        announce("Choose a non-empty text file without NUL characters.", true);
        return;
      }
      if (bytes > MAX_FILE_BYTES) {
        announce("Policy files must be 512 KiB or smaller.", true);
        return;
      }
      const kind = String(root.querySelector("#policy-kind")?.value ?? "policy");
      const enforcement = String(
        root.querySelector("#policy-enforcement")?.value ?? "required",
      );
      const body = {
        enforcement: ENFORCEMENTS.includes(enforcement) ? enforcement : "required",
        namespace: String(
          root.querySelector(".policy-library")?.getAttribute("data-policy-scope") ?? "",
        ),
        kind: KINDS.includes(kind) ? kind : "other",
        fileName: file.name,
        content,
      };
      const title = String(root.querySelector("#policy-title")?.value ?? "").trim();
      if (title) body.title = title;
      const created = await ctx.api.post("/v1/admin/policy-documents", body);
      await refreshRegister(ctx, root, 1);
      // A new document changes the governing digest, so every agent's standing
      // changes with it — refresh the compliance panel rather than leave the
      // previous version's numbers on screen.
      await refreshPolicyCompliance(ctx, root, body.namespace);
      await refreshAdoption(ctx, root, body.namespace);
      if (input) input.value = "";
      const fileLabel = root.querySelector("[data-policy-file-name]");
      if (fileLabel) fileLabel.textContent = "Choose A File…";
      const titleInput = root.querySelector("#policy-title");
      if (titleInput) titleInput.value = "";
      if (created && created.status === "active") {
        announce("Policy file loaded and is agent-ready.");
      } else if (created && created.status === "needs_review") {
        announce("Policy file loaded and needs review.");
      } else if (created && created.status === "failed") {
        announce("Policy file could not be loaded. Its failed state is in the register.", true);
      } else {
        announce("Policy file accepted and is processing.");
      }
    } catch (error) {
      announce("Upload failed: " + (error && error.message ? error.message : "unknown error"), true);
    } finally {
      el.disabled = false;
    }
  },
};

function titleCase(value) {
  return String(value).replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KiB`;
}

function formatDate(value) {
  if (!value) return "Not loaded yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
