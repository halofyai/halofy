import { organizationScopeLabel, personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";

/**
 * S8 - Audit (Module C / govern).
 *
 * `render(ctx)` fetches GET /v1/admin/audit?<filters> → AuditEvent[]:
 * { ts, actor, agentId, op, memoryId, namespace, purpose, result, detail? }.
 * A search form (person, app, operation, outcome, date range) re-fetches on
 * Search. Results land in a table with EVERY field escaped (detail is
 * attacker-influenced - a fact's content can end up in an audit detail - so it
 * is the primary XSS target here).
 *
 * The screen is read by finance, legal and HR admins, not only engineers, so
 * every op is rendered through OP_LABELS ("conversation_read" → "Read assistant
 * history"). OP_LABELS mirrors AUDIT_OP_LABELS in src/console/api.ts and
 * test/console-s8-audit.test.ts asserts BOTH cover the canonical AUDIT_OPS -
 * a new op cannot ship unlabelled on either surface.
 *
 * Three honesty rules this screen exists to keep:
 *   1. It asks for the server's maximum page (500) and SAYS SO when it fills
 *      it. A compliance screen that shows the first 100 rows silently reads as
 *      "this is everything".
 *   2. Download CSV goes to GET /v1/admin/audit/export.csv, which walks the WHOLE
 *      filtered trail server-side (past that cap) and reports its own row count
 *      and truncation flag in response headers - the screen never guesses.
 *   3. Person/app filters are EXACT-match server-side (the ACL query layer
 *      stays a parameterised equality, never a LIKE). The prototype select
 *      controls therefore submit the exact ids supplied by the API.
 *
 * A certificate viewer: type a cert id → GET /v1/admin/certificate/:id →
 * render the DeletionCertificate fields and the backend's verification result
 * against the trusted boot key. An inline key is never treated as a trust root.
 *
 * An Erase action → POST /v1/admin/forget {target:{kind,value}} - HIDDEN for
 * auditor and member (the server also 403s; UI hiding is defense in depth).
 *
 * The audit filters + last results are kept module-scoped so a re-render after a
 * search shows the current result set.
 */

/**
 * Plain-English label per audited operation, grouped the way an administrator
 * thinks about them. The flat op list is derived from this, so the picker can
 * never fall behind the trail again.
 */
const OP_GROUPS = [
  {
    label: "Everyday use",
    ops: [
      ["read", "Read a memory"],
      ["search", "Searched memory"],
      ["fault", "Recalled memory mid-task"],
      ["assemble", "Assembled context"],
      ["stats", "Viewed memory stats"],
      ["complete", "Asked the assistant"],
    ],
  },
  {
    label: "Adding & changing memory",
    ops: [
      ["write", "Saved to memory"],
      ["propose", "Proposed a change"],
      ["edit", "Edited a memory"],
      ["approve", "Approved a change"],
      ["reject", "Rejected a proposal"],
      ["publish", "Published knowledge"],
      ["supersede", "Replaced an outdated fact"],
      ["retract", "Retracted a memory"],
      ["pin", "Pinned a memory"],
      ["unpin", "Unpinned a memory"],
      ["move", "Moved memory between teams"],
      ["share", "Shared memory"],
      ["dispute", "Flagged a conflicting fact"],
      ["resolve", "Resolved a conflict"],
      ["conflict_scan", "Scanned for conflicts"],
      ["answer_outcome", "Recorded an answer outcome"],
    ],
  },
  {
    label: "Deletion & data leaving",
    ops: [
      ["forget", "Deleted memory permanently"],
      ["export", "Exported data"],
      ["assistant_recycle", "Moved an employee's data to the recycle bin"],
      ["assistant_restore", "Restored an employee's data"],
      ["assistant_purge", "Purged an employee's data permanently"],
    ],
  },
  {
    label: "Assistant conversations",
    ops: [
      ["conversation_read", "Read assistant history"],
      ["conversation_write", "Saved an assistant message"],
      ["conversation_clear", "Cleared assistant history"],
      ["session_capture", "Recorded an agent session"],
    ],
  },
  {
    label: "Rules & guardrails",
    ops: [
      ["policy", "Received guardrails"],
      ["policy_ack", "Acknowledged guardrails"],
      ["policy_enforcement", "Changed a guardrail level"],
      ["policy_delete", "Deleted a policy document"],
      ["policy_adopt", "Added a policy file to the register"],
    ],
  },
  {
    label: "Skills & automations",
    ops: [
      ["skill_invoke", "Used a skill"],
      ["skill_vet", "Vetted a skill"],
      ["skill_approve", "Approved a skill"],
      ["skill_reject", "Rejected a skill"],
      ["skill_override", "Allowed an unvetted skill"],
      ["automation_run", "Ran an automation"],
    ],
  },
  {
    label: "Channels & billing",
    ops: [
      ["channel.lifecycle", "Changed a channel"],
      ["credit_debit", "Used paid credit"],
    ],
  },
];

/** op → label, flattened once. */
const OP_LABELS = Object.fromEntries(
  OP_GROUPS.flatMap((group) => group.ops.map(([op, label]) => [op, label])),
);

/** Outcome vocabulary, in the words an administrator uses. */
const RESULTS = [
  ["", "All"],
  ["ok", "Allowed"],
  ["denied", "Blocked"],
  ["miss", "Nothing found"],
  ["error", "Failed"],
];

/** The server's own per-search maximum (AUDIT_SEARCH_MAX_LIMIT). */
const PAGE_LIMIT = 500;

/**
 * Rows on screen at once. The fetch still asks for the server maximum - paging
 * is a READING aid over the same fenced result set, never a second filter - so
 * the "newest 500" honesty note keeps meaning exactly what it did.
 */
const ROWS_PER_PAGE = 8;

/** Quick date ranges, so nobody has to know the ISO format to look at a week. */
const QUICK_RANGES = [
  ["1", "24 Hours"],
  ["7", "7 Days"],
  ["30", "30 Days"],
  ["all", "All Time"],
];

// Current filters, so a re-render (after Search) reflects the last query. The
// audit rows themselves are ALWAYS fetched fresh in render() - never cached
// across render calls - so an integrator calling render() twice with different
// canned data sees each one honestly.
let currentFilters = {};
// Visual state for the prototype's compact date tabs. The unfiltered trail is
// the truthful initial state, so All Time starts selected.
let currentRange = "all";
// 1-based page of the current result set. Reset to 1 by anything that changes
// WHICH events are being read (search, reset, quick range) - never by paging.
let currentPage = 1;
// The last looked-up certificate (or an error marker), rendered under the viewer.
let certState = null;
// The last erase result (a signed certificate), surfaced after a forget.
let eraseState = null;
// Outcome of the last CSV download, reported next to the button.
let downloadState = null;

/** True when the caller may erase (owner/admin); false for auditor/member. */
function canErase(ctx) {
  const r = ctx.identity && ctx.identity.role;
  return r === "owner" || r === "root" || r === "admin";
}

function buildQuery(filters, extra) {
  const params = new URLSearchParams();
  if (filters.actor) params.set("actor", filters.actor);
  if (filters.agentId) params.set("agentId", filters.agentId);
  if (filters.op) params.set("op", filters.op);
  if (filters.result) params.set("result", filters.result);
  if (filters.since) params.set("since", filters.since);
  if (filters.until) params.set("until", filters.until);
  for (const key of Object.keys(extra ?? {})) params.set(key, String(extra[key]));
  const q = params.toString();
  return q ? "?" + q : "";
}

/** A GET whose failure must not take the screen down (brownout, never hard-fail). */
async function optional(ctx, path) {
  try {
    return await ctx.api.get(path);
  } catch {
    return null;
  }
}

export async function render(ctx) {
  // Always fetch the audit rows fresh for the current filters (default empty =
  // the caller's whole subtree). Never cache across render calls. `limit` asks
  // for the server maximum so the "showing the newest N" notice below is the
  // only truncation the reader has to reason about.
  let rows;
  let summary = null;
  let keys = null;
  let teams = null;
  try {
    const [events, auditSummary, keyList, teamList] = await Promise.all([
      ctx.api.get("/v1/admin/audit" + buildQuery(currentFilters, { limit: PAGE_LIMIT })),
      optional(ctx, "/v1/admin/audit/summary" + buildQuery(currentFilters)),
      // Names for the raw key ids in the Agent column, and the two pickers.
      // Both are optional: a 403/404 costs labels, never the trail.
      optional(ctx, "/v1/admin/keys"),
      optional(ctx, "/v1/admin/teams"),
    ]);
    rows = Array.isArray(events) ? events : [];
    summary = auditSummary;
    keys = keyList;
    teams = teamList;
  } catch (err) {
    rows = { error: err && err.message ? err.message : "audit unavailable" };
  }

  const erase = canErase(ctx);
  const names = agentNames(keys);
  const people = rosterActors(ctx, teams);
  const agents = agentOptions(keys);
  const opOpts = OP_GROUPS.map((group) => {
    const options = group.ops
      .map(([op, label]) => {
        const sel = op === (currentFilters.op ?? "") ? " selected" : "";
        return `<option value="${ctx.esc(op)}"${sel}>${ctx.esc(label)}</option>`;
      })
      .join("");
    return `<optgroup label="${ctx.esc(group.label)}">${options}</optgroup>`;
  }).join("");
  const allSelected = (currentFilters.op ?? "") === "" ? " selected" : "";
  const resultOpts = RESULTS.map(([value, label]) => {
    const selected = value === (currentFilters.result ?? "") ? " selected" : "";
    return `<option value="${ctx.esc(value)}"${selected}>${ctx.esc(label)}</option>`;
  }).join("");
  const stats = auditStats(summary);

  return `
    <div class="head audit-page-head">
      <div><h1>Audit</h1></div>
      <div class="acts audit-page-head__actions">
        <span class="audit-access-pill"><i class="dot"></i>Owners, Admins &amp; Auditors Only</span>
      </div>
    </div>

    <div class="audit-stat-grid" role="list" aria-label="Audit overview">
      ${auditStatCard(ctx, "Events recorded", stats.events, "Current filters · exact total")}
      ${auditStatCard(ctx, "Blocked attempts", stats.blocked, "Guardrail outcomes in this trail")}
      ${auditStatCard(ctx, "Permanent deletions", stats.deletions, "Signed deletion events")}
      ${auditStatCard(ctx, "Data exports", stats.exports, "Recorded export events")}
    </div>

    <section class="card audit-trail-card" aria-labelledby="audit-trail-title">
      <div class="audit-trail-head">
        <h2 id="audit-trail-title">Who did what with your memory${headingInfo("Who did what with your memory", `Every read, write, deletion and blocked attempt, newest first. The download is the complete trail for these filters - the pages below cover the newest ${PAGE_LIMIT}, ${ROWS_PER_PAGE} at a time.`)}</h2>
        <div class="audit-trail-actions">
          <div class="audit-range-tabs" role="group" aria-label="Audit date range">
            ${QUICK_RANGES.map(([days, label]) => `<button type="button" data-action="audit-range" data-days="${ctx.esc(days)}" class="audit-range-tab${currentRange === days ? " is-active" : ""}" aria-pressed="${currentRange === days ? "true" : "false"}">${ctx.esc(label)}</button>`).join("")}
          </div>
          <button class="btn btn--outline btn--sm audit-download" data-action="audit-csv">${downloadIcon()}Download CSV</button>
        </div>
      </div>
      <div id="audit-filter-panel" class="audit-filter-grid" data-filter-count="${activeFilterCount()}">
        <label for="audit-actor"><span class="sr-only">Person</span><select class="select" id="audit-actor" data-change-action="audit-search"><option value="">Person · Everyone</option>${selectOptions(ctx, people, currentFilters.actor)}</select></label>
        <label for="audit-agent"><span class="sr-only">App or agent</span><select class="select" id="audit-agent" data-change-action="audit-search"><option value="">App · All Apps</option>${selectOptions(ctx, agents, currentFilters.agentId)}</select></label>
        <label for="audit-op"><span class="sr-only">What happened</span><select class="select" id="audit-op" data-change-action="audit-search"><option value=""${allSelected}>What Happened · Anything</option>${opOpts}</select></label>
        <label for="audit-result"><span class="sr-only">Outcome</span><select class="select" id="audit-result" data-change-action="audit-search">${resultOpts.replace(">All<", ">Outcome · Any<")}</select></label>
      </div>
      <input type="hidden" id="audit-since" value="${ctx.esc(dateOnly(currentFilters.since))}">
      <input type="hidden" id="audit-until" value="${ctx.esc(dateOnly(currentFilters.until))}">
      <div class="hint audit-download-status" id="audit-status" role="status" aria-live="polite">${downloadState ? ctx.esc(downloadState) : ""}</div>
      ${resultsTable(ctx, rows, names)}
    </section>

    <div class="audit-compliance-grid">
      ${erase ? eraseCard(ctx) : ""}
      ${certViewer(ctx)}
    </div>
    ${erase ? eraseResult(ctx) : ""}`;
}

function auditStats(summary) {
  if (!summary || typeof summary !== "object") {
    return { events: "Unavailable", blocked: "Unavailable", deletions: "Unavailable", exports: "Unavailable" };
  }
  return {
    events: formatAuditCount(summary.events),
    blocked: formatAuditCount(summary.blocked),
    deletions: formatAuditCount(summary.deletions),
    exports: formatAuditCount(summary.exports),
  };
}

/** Exact comma-separated counts stay readable until compact notation helps. */
export function formatAuditCount(value) {
  if (!Number.isSafeInteger(value) || value < 0) return "Unavailable";
  if (value < 30_000) return value.toLocaleString("en-US");
  return `${(value / 1_000).toLocaleString("en-US", { maximumFractionDigits: 1 })}K`;
}

function auditStatCard(ctx, label, value, detail) {
  return `<div class="audit-stat-card" role="listitem"><span>${ctx.esc(label)}</span><strong>${ctx.esc(value)}</strong><small>${ctx.esc(detail)}</small></div>`;
}

function selectOptions(ctx, entries, selectedValue) {
  const selected = String(selectedValue ?? "");
  const values = new Set(entries.map((entry) => String(entry.value)));
  const current = selected && !values.has(selected)
    ? [{ value: selected, label: selected }, ...entries]
    : entries;
  return current.map((entry) => `<option value="${ctx.esc(entry.value)}"${String(entry.value) === selected ? " selected" : ""}>${ctx.esc(entry.label || entry.value)}</option>`).join("");
}

function downloadIcon() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3v11m0 0 4-4m-4 4-4-4M5 18v2h14v-2" stroke-linecap="round" stroke-linejoin="round"></path></svg>';
}

function activeFilterCount() {
  return Object.keys(currentFilters).filter((key) => (currentFilters[key] ?? "") !== "").length;
}

/** keyId → the human-readable actor behind it (S19 uses the same join). */
function agentNames(keys) {
  const names = new Map();
  const list = Array.isArray(keys) ? keys : Array.isArray(keys && keys.keys) ? keys.keys : [];
  for (const key of list) {
    if (key && key.id) names.set(String(key.id), String(key.actor || key.id));
  }
  return names;
}

function agentOptions(keys) {
  const list = Array.isArray(keys) ? keys : Array.isArray(keys && keys.keys) ? keys.keys : [];
  const seen = new Map();
  for (const key of list) {
    if (key && key.id) seen.set(String(key.id), String(key.actor || key.id));
  }
  return [...seen.entries()].map(([value, label]) => ({ value, label }));
}

/** Distinct member emails across the visible teams (the exact actor strings). */
function rosterActors(ctx, teams) {
  const list = Array.isArray(teams) ? teams : Array.isArray(teams && teams.teams) ? teams.teams : [];
  const seen = new Map();
  for (const team of list) {
    for (const member of Array.isArray(team && team.members) ? team.members : []) {
      const email = member && typeof member.email === "string" ? member.email : "";
      if (email !== "") seen.set(email, personDisplayName(member, ctx.personLabel) || email);
    }
  }
  return [...seen.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([value, label]) => ({ value, label }));
}

/** The `YYYY-MM-DD` a `<input type="date">` accepts, from either bound form. */
function dateOnly(value) {
  const raw = String(value ?? "");
  return raw.length >= 10 ? raw.slice(0, 10) : raw;
}

function resultsTable(ctx, rows, names) {
  if (rows && rows.error) {
    return `<p class="audit-empty">Could not load the trail: ${ctx.esc(
      rows.error,
    )}</p>`;
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    return `<p class="audit-empty">${emptyMessage(ctx)}</p>`;
  }
  // Clamp here rather than at click time: the trail moves between renders, so a
  // page that existed a moment ago may not now. Clamping in the one place that
  // knows the real row count keeps the table and the pager telling one story.
  const totalPages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  const start = (currentPage - 1) * ROWS_PER_PAGE;
  const pageRows = rows.slice(start, start + ROWS_PER_PAGE);
  const body = pageRows
    .map((e) => {
      const rawTs = String(e.ts ?? "");
      const ts = ctx.esc(formatTimestamp(rawTs));
      const op = String(e.op ?? "");
      const rawActor = String(e.actor ?? "");
      const actorAvatar = typeof ctx.personAvatar === "function"
        ? ctx.personAvatar(e.actor, "human")
        : `<span class="audit-person-fallback" aria-hidden="true">${ctx.esc(initials(rawActor))}</span>`;
      const actorName = ctx.esc(
        personDisplayName(rawActor, ctx.personLabel, "human") || rawActor || "-",
      );
      const agent = agentDisplay(ctx, e.agentId, names);
      const result = ctx.esc(resultLabel(e.result));
      // detail and purpose are attacker-influenced (a fact's content can land
      // in either) - escape them; NEVER interpolate raw.
      const detail = e.detail ? ctx.esc(e.detail) : "";
      const purpose = e.purpose ? ctx.esc(e.purpose) : "";
      const label = ctx.esc(OP_LABELS[op] ?? op);
      const opCell = `<span class="audit-op-label audit-op-label--${ctx.esc(opTone(op))}">${label}</span>`;
      const memoryId = e.memoryId ? agentDisplay(ctx, e.memoryId) : "";
      const why = purpose || memoryId;
      const resultCell = `<span class="audit-outcome-label audit-outcome-label--${ctx.esc(resultTone(e.result))}">${result}</span>${detail ? `<small>${detail}</small>` : ""}`;
      return `<tr>
        <td class="audit-when"><time datetime="${ctx.esc(rawTs)}" title="${ctx.esc(rawTs)}">${ts}</time></td>
        <td class="audit-event">${opCell}${why ? `<small>${why}</small>` : ""}</td>
        <td><span class="audit-person" title="${ctx.esc(rawActor)}">${actorAvatar}<strong>${actorName}</strong></span></td>
        <td class="audit-agent">${agent}</td>
        <td class="audit-team">${ctx.esc(organizationScopeLabel(
          e.namespace,
          ctx.organizationName,
          ctx.identity?.namespace,
        ))}</td>
        <td class="audit-result">${resultCell}</td>
      </tr>`;
    })
    .join("");
  const first = start + 1;
  const last = start + pageRows.length;
  const summary =
    rows.length >= PAGE_LIMIT
      ? `<p>Showing ${first}–${last} of the newest ${PAGE_LIMIT} events · more are available in the CSV</p>`
      : `<p>Showing ${first}–${last} of ${rows.length} event${
          rows.length === 1 ? "" : "s"
        }</p>`;
  return `
    <div class="audit-table-scroll"><table class="audit-table" data-table-static>
      <thead><tr><th>When</th><th>What happened</th><th>Who</th><th>App or agent</th><th>Team</th><th>Outcome</th></tr></thead>
      <tbody>${body}</tbody>
    </table></div><div class="audit-table-footer">${summary}${pager(ctx, currentPage, totalPages)}</div>`;
}

/** Prototype pager: two compact arrows with one honest page count. */
function pager(ctx, page, total) {
  if (total <= 1) return "";
  const step = (target, label, glyph, disabled) =>
    `<button type="button" class="audit-page-step" data-action="audit-page" data-page="${ctx.esc(
      target,
    )}" aria-label="${ctx.esc(label)}"${disabled ? " disabled" : ""}>${ctx.esc(glyph)}</button>`;
  return `<nav class="audit-pager" aria-label="Audit trail pages">
    ${step(page - 1, "Previous page", "‹", page <= 1)}
    <span aria-current="page">${ctx.esc(page)} / ${ctx.esc(total)}</span>
    ${step(page + 1, "Next page", "›", page >= total)}
  </nav>`;
}

function agentDisplay(ctx, value, names) {
  const raw = String(value ?? "");
  if (!raw) return "-";
  const named = names?.get(raw);
  const display = named || personDisplayName(raw, ctx.personLabel) || raw;
  const visible = display.length > 32 ? `${display.slice(0, 13)}…${display.slice(-8)}` : display;
  const escaped = ctx.esc(raw);
  return `<span title="${escaped}">${ctx.esc(visible)}</span>${raw.length > 20 || named
    ? ` <button class="audit-copy" type="button" data-action="audit-copy" data-copy="${escaped}" aria-label="Copy full identifier">Copy</button>`
    : ""}`;
}

function initials(value) {
  const bits = String(value ?? "").split(/[^A-Za-z0-9]+/).filter(Boolean);
  return (bits.slice(0, 2).map((part) => part[0]).join("") || "?").toUpperCase();
}

function opTone(op) {
  if (["forget", "assistant_purge"].includes(op)) return "danger";
  if (["export", "publish"].includes(op)) return "export";
  if (["write", "edit", "approve", "share"].includes(op)) return "write";
  return "neutral";
}

function resultTone(value) {
  return { ok: "ok", denied: "blocked", miss: "miss", error: "failed" }[String(value ?? "")] ?? "neutral";
}

/**
 * The zero-row message preserves the exact-match boundary for callers whose
 * current id is retained as a selected option even if an optional roster read
 * browns out.
 */
function emptyMessage(ctx) {
  if (currentFilters.actor || currentFilters.agentId) {
    return `No events matched. Person and app filters use full ids exactly.`;
  }
  return "No matching audit events.";
}

function resultLabel(value) {
  return (
    { ok: "Allowed", denied: "Blocked", miss: "Nothing found", error: "Failed" }[
      String(value ?? "")
    ] ?? String(value ?? "")
  );
}

function formatTimestamp(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

/** The erase form (owner/admin only). */
function eraseCard(ctx) {
  return `
    <section class="card audit-compliance-card audit-erasure" aria-labelledby="audit-erasure-title">
      <div class="audit-compliance-head"><div><h2 id="audit-erasure-title">Delete someone's memory for good${headingInfo(
        "Delete someone's memory for good",
        "Right to be forgotten. Permanently removes the matching memory and issues a signed receipt you can hand to a regulator. The record that it happened stays in the trail above; the content does not come back.",
      )}</h2></div>
        <span class="pill pill--crit"><i class="dot"></i>Cannot be undone</span></div>
      <div class="audit-compliance-form">
        <div class="field"><label for="erase-kind">Delete everything for</label>
          <select class="select" id="erase-kind">
            <option value="actor">A person</option>
            <option value="entity">A subject (customer, project)</option>
            <option value="namespace">A whole team</option>
            <option value="memory">One specific memory</option>
          </select></div>
        <div class="field"><label for="erase-value">Their exact id</label>
          <input class="input mono" id="erase-value" placeholder="dana@acme.com" autocomplete="off"></div>
        <div class="hint">Must match the full id exactly — deletion never guesses from a partial name.</div>
        <button class="btn btn--danger" data-action="audit-erase">Delete permanently</button>
      </div>
      <div class="hint" id="erase-status" role="status" aria-live="polite"></div>
    </section>`;
}

/** After an erase, render the returned certificate fields. */
function eraseResult(ctx) {
  if (!eraseState) return "";
  if (eraseState.error) {
    return `<div class="card" style="margin-bottom:var(--s4)"><div class="sub">Nothing was deleted.</div><p>${ctx.esc(
      eraseState.error,
    )}</p></div>`;
  }
  const cert = eraseState.certificate;
  return `
    <div class="card" style="margin-bottom:var(--s4)"><div class="between">
      <div><div class="eyebrow">Deletion receipt · ${ctx.esc(
        cert.algorithm ?? "ed25519",
      )}</div><h3 style="margin-top:6px">Deleted ${ctx.esc(
        eraseState.erasedCount ?? cert.erasedCount ?? 0,
      )} memories</h3></div>
      <span class="pill pill--ok"><i class="dot"></i>Signed</span></div>
      <div class="sub" style="margin-top:6px">Keep the receipt id below - it proves the deletion happened, and anyone can re-check it in the viewer.</div>
      ${certBody(ctx, cert)}</div>`;
}

/** The certificate lookup viewer + last-looked-up cert (or error). */
function certViewer(ctx) {
  let panel = "";
  if (certState) {
    if (certState.error) {
      panel = `<p class="subtle" style="margin-top:var(--s4)">${ctx.esc(
        certState.error,
      )}</p>`;
    } else {
      const cert = certState.certificate;
      const trusted = certState.verified === true;
      panel = `
        <div class="between" style="margin-top:var(--s4)">
          <h3 style="font-size:16px">Receipt ${ctx.esc(cert.id ?? "")}</h3>
          <span class="pill ${trusted ? "pill--ok" : "pill--crit"}"><i class="dot"></i>${
            trusted ? "Genuine - signed by this system" : "Does not match this system's signature"
          }</span></div>
        ${certBody(ctx, cert)}`;
    }
  }
  return `
    <section class="card audit-compliance-card certificate-viewer" aria-labelledby="certificate-viewer-title">
      <div class="audit-compliance-head"><div><h2 id="certificate-viewer-title">Check a deletion receipt${headingInfo(
        "Check a deletion receipt",
        "Certificate viewer. Paste a receipt id to confirm it is genuine.",
      )}</h2></div></div>
      <div class="audit-certificate-form">
        <div class="field"><label for="cert-id">Receipt id</label>
          <input class="input mono" id="cert-id" placeholder="01KX0WP00CE6PK5859WATMN6JJ" autocomplete="off"></div>
        <button class="btn btn--outline" data-action="cert-verify">Check it</button>
      </div>
      <div class="audit-certificate-note"><span aria-hidden="true">✓</span><p>Receipts are signed with this system's own key (ed25519). A receipt not issued here — or altered after the fact — will not verify.</p></div>
      ${panel}</section>`;
}

/** Shared certificate field dump (every field escaped). */
function certBody(ctx, cert) {
  const target = cert.target ?? {};
  const lines = [
    `receipt     ${ctx.esc(cert.id ?? "")}`,
    `  covered     ${ctx.esc(target.kind ?? "")}: ${ctx.esc(target.value ?? "")}`,
    `  team        ${ctx.esc(cert.namespace ?? "")}`,
    `  deleted     ${ctx.esc(cert.erasedCount ?? 0)} memories`,
    `  issued      ${ctx.esc(cert.issuedAt ?? "")}  by ${ctx.esc(cert.actor ?? "")}`,
    `  signature   ${ctx.esc(cert.algorithm ?? "ed25519")}`,
    `  public key  ${ctx.esc(cert.publicKey ?? "")}`,
  ];
  return `<div class="snippet" style="margin-top:var(--s3)">${lines.join("\n")}</div>`;
}

function errMsg(err) {
  return err && err.message ? err.message : "unknown error";
}

function readFilters(root) {
  return {
    actor: (root.querySelector("#audit-actor")?.value ?? "").trim(),
    agentId: (root.querySelector("#audit-agent")?.value ?? "").trim(),
    op: root.querySelector("#audit-op")?.value ?? "",
    result: root.querySelector("#audit-result")?.value ?? "",
    since: (root.querySelector("#audit-since")?.value ?? "").trim(),
    until: (root.querySelector("#audit-until")?.value ?? "").trim(),
  };
}

function setStatus(root, message) {
  const node = root && root.querySelector ? root.querySelector("#audit-status") : null;
  if (node) node.textContent = message;
}

/** `YYYY-MM-DD`, `days` before today, in the viewer's own calendar. */
function daysAgo(days) {
  const date = new Date();
  date.setDate(date.getDate() - Number(days));
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function saveDownload(bytes, filename, contentType) {
  if (typeof document === "undefined" || typeof URL === "undefined" || typeof Blob === "undefined") {
    return;
  }
  const blob = new Blob([bytes], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const actions = {
  async "audit-copy"(_ctx, el) {
    const value = el.getAttribute("data-copy") ?? "";
    if (!value) return false;
    await navigator.clipboard.writeText(value);
    el.textContent = "Copied";
    return true;
  },

  /** Read the search form, refetch the audit trail, re-render. */
  async "audit-search"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    currentFilters = readFilters(root);
    currentPage = 1;
    downloadState = null;
    await ctx.go("s8"); // render() always refetches with the new filters
  },

  /** Clear every filter back to the whole visible trail. */
  async "audit-reset"(ctx) {
    currentFilters = {};
    currentRange = "all";
    currentPage = 1;
    downloadState = null;
    await ctx.go("s8");
  },

  /** A one-click date window; everything else in the form is preserved. */
  async "audit-range"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    const range = el.getAttribute("data-days") ?? "7";
    currentFilters = {
      ...readFilters(root),
      since: range === "all" ? "" : daysAgo(range),
      until: "",
    };
    currentRange = range;
    currentPage = 1;
    downloadState = null;
    await ctx.go("s8");
  },

  /**
   * Move to another page of the SAME filtered trail. The rows are refetched
   * (render() never caches), so a page is always the trail as it stands now;
   * render() clamps a page that no longer exists.
   */
  async "audit-page"(ctx, el) {
    const requested = Number(el.getAttribute("data-page") ?? "1");
    currentPage = Number.isFinite(requested) && requested >= 1 ? Math.floor(requested) : 1;
    await ctx.go("s8");
  },

  /**
   * Download the COMPLETE filtered trail as CSV. The server walks past the
   * screen's page limit and states the row count and whether its own ceiling
   * cut the export short - reported verbatim, never inferred from the bytes.
   */
  async "audit-csv"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    setStatus(root, "Preparing the download…");
    try {
      const res = await ctx.api.raw("/v1/admin/audit/export.csv" + buildQuery(currentFilters));
      const rowCount = Number(res.header("x-audit-rows") ?? "0");
      const truncated = res.header("x-audit-truncated") === "true";
      const disposition = res.header("content-disposition") ?? "";
      const match = /filename="([^"]+)"/.exec(disposition);
      saveDownload(res.text, match ? match[1] : "halomem-audit.csv", "text/csv;charset=utf-8");
      downloadState = truncated
        ? `Downloaded ${rowCount} events - that is this export's maximum, so older events were left out. Narrow the dates and download again.`
        : `Downloaded ${rowCount} event${rowCount === 1 ? "" : "s"} - the complete trail for these filters.`;
    } catch (err) {
      downloadState = "Download failed: " + errMsg(err);
    }
    setStatus(root, downloadState);
  },

  /** Look up a certificate by id and render its fields. */
  async "cert-verify"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    const id = (root.querySelector("#cert-id")?.value ?? "").trim();
    if (!id) {
      certState = { error: "Enter a receipt id." };
      await ctx.go("s8");
      return;
    }
    try {
      const payload = await ctx.api.get(
        "/v1/admin/certificate/" + encodeURIComponent(id),
      );
      const certificate = payload && payload.certificate ? payload.certificate : payload;
      certState = {
        certificate,
        verified: !!(payload && (payload.verified === true || payload.trustedVerified === true)),
      };
    } catch (err) {
      certState = { error: "No receipt found for that id: " + errMsg(err) };
    }
    await ctx.go("s8");
  },

  /** Erase a target and surface the returned signed certificate. */
  async "audit-erase"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    const kind = root.querySelector("#erase-kind")?.value ?? "actor";
    const value = (root.querySelector("#erase-value")?.value ?? "").trim();
    const status = root.querySelector("#erase-status");
    if (!value) {
      if (status) status.textContent = "Enter the id of whoever or whatever you are deleting.";
      return;
    }
    if (status) status.textContent = "Deleting…";
    try {
      const res = await ctx.api.post("/v1/admin/forget", {
        target: { kind, value },
      });
      eraseState = res;
    } catch (err) {
      eraseState = { error: errMsg(err) };
    }
    await ctx.go("s8");
  },
};
