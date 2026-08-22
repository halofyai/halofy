import { organizationScopeLabel, personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { isLimitError } from "../limit-toast.js";

// S20 - Export (Govern).
//
// A governed, downloadable snapshot of the selected scope's authoritative
// memory. A team export contains only that namespace subtree's L2 facts and L3
// knowledge; organization/ancestor memory is deliberately excluded. The JSON
// bundle preserves the allowed objects and provenance for reuse, while the
// Markdown file is a readable companion. Superseded/tombstoned history, warm
// mirrors and live-fetch caches are never included.
//
// Export is a GOVERNED EGRESS EVENT (D28), never a passive view:
//   - Only owner/admin/auditor may export; the server audits and 403s the rest.
//   - Every row is gated by role/source/classification BEFORE it is rendered;
//     withheld rows are tallied by reason and reported, never silently dropped.
//   - Each generate writes an append-only `export` audit row (ok/denied/miss).
// Because generating both egresses AND audits, this screen NEVER exports on
// render - only on an explicit "Generate export" click. The download button
// then saves the bytes already in the browser locally (no second egress).
//
// The export can also be SCOPED: a specific team (that team's own namespace
// subtree) or a specific person (the facts they authored). The scope is a
// target selection the server gates to the caller's downward subtree (D9) -
// the picker's teams/people come from GET /v1/admin/teams, a roster read.
// A person's export never includes the L3 knowledge tier (it is team-level).
//
// render() reads the teams roster for the scope picker (browning out to
// whole-organization only). Generate POSTs /v1/mem/export {tiers, purpose?,
// scope?} and reports included/withheld counts, the sha256 egress evidence,
// and an escaped markdown preview.
//
// Every interpolated API value passes through ctx.esc().

// Roles the server's EXPORT_ROLES admits (src/export/index.ts), plus "root" -
// the product spelling of "owner" that /v1/me returns (D41), as everywhere
// else in the console. Mirrored here as defense in depth; the rail already
// hides this screen from member/agent.
const EXPORT_ROLES = ["owner", "root", "admin", "auditor"];

// Module-scoped so a re-render after Generate reflects the current result.
// "Your export is ready" is tied to an explicit Generate click in the current
// visit: any fresh navigation to this screen clears the result (see
// keepResult), so a stale card never greets a user who didn't ask for one.
let lastExport = null;
let lastError = null;
// The scope the last generated export ran under ({kind, value}), for the
// result card; null = whole organization.
let lastScope = null;
// Scope picker draft. Radios re-render the screen via set-scope so the
// team/person selects and the tier rules can follow the chosen kind.
let scopeDraft = { kind: "org", team: "", user: "", l2: true, l3: true, purpose: "" };

// True only while one of this screen's own actions re-renders in place
// (generate, set-scope). A router-driven render, arriving fresh from the
// rail or a reload, consumes it as false and drops any earlier result.
let keepResult = false;

// The full document always downloads in full; the on-screen preview is bounded
// so a 2000-row export never renders an unbounded block into the DOM.
const PREVIEW_CHARS = 6000;

// Descriptive copy collapsed behind the accessible info icons (heading-info).
const HEAD_TIP =
  "Exporting is a governed egress event, never a passive view. Every row is " +
  "gated by role, source and classification before it renders; withheld rows " +
  "are tallied by reason, never silently dropped. Each generate writes an " +
  "append-only audit row.";
const SCOPE_TIP =
  "A team export contains only that namespace subtree&#39;s facts and " +
  "knowledge; inherited organization memory is deliberately excluded. " +
  "A person&#39;s export covers the facts they authored. Superseded history, " +
  "warm mirrors and live-fetch caches are never included.";

/**
 * @param {import('../app.js').Ctx} ctx
 * @returns {Promise<string>}
 */
export async function render(ctx) {
  const { esc, ui } = ctx;
  const role = (ctx.identity && ctx.identity.role) || "";
  const namespace = (ctx.identity && ctx.identity.namespace) || "";
  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  // Built by hand (not ui.head) so the h1 stays plain text with the info icon.
  const head =
    '<div class="head"><div>' +
    '<div class="eyebrow">Govern &middot; ' + esc(nsLabel) + "</div>" +
    '<div class="ex20-titlerow"><h1>Export</h1>' + headingInfo("Export", HEAD_TIP) + "</div>" +
    "</div></div>";

  // Defense in depth: the rail hides this screen from member/agent, but a
  // hash-navigation attempt still renders an honest, control-free notice.
  if (!EXPORT_ROLES.includes(role)) {
    return (
      head +
      ui.empty("Exporting memory is limited to owners, admins, and auditors.")
    );
  }

  // A fresh visit (not an in-place action re-render) never shows a result
  // card the user didn't just ask for.
  if (!keepResult) {
    lastExport = null;
    lastError = null;
    lastScope = null;
  }
  keepResult = false;

  // Roster read for the scope picker (a read, never an egress). Browns out
  // to whole-organization only when the teams listing is unavailable.
  let teams = null;
  try {
    const res = await ctx.api.get("/v1/admin/teams");
    teams = Array.isArray(res) ? res : null;
  } catch {
    teams = null;
  }
  const haveTeams = teams !== null && teams.length > 0;
  const people = haveTeams ? rosterEmails(teams) : [];
  const draft = scopeDraft;
  const userScope = draft.kind === "user";

  // Selectable option card: a radio dressed as a card, its dot drawn in CSS
  // (.ex20-opt:has(input:checked)). The input stays in the tree for keyboard
  // access and for readDraft().
  const scopeRadio = (kind, label, hint) =>
    '<label class="ex20-opt"><input type="radio" name="export-scope" value="' + kind + '" ' +
    'data-change-action="set-scope" data-scope-kind="' + kind + '"' +
    (draft.kind === kind ? " checked" : "") +
    (kind !== "org" && !haveTeams ? " disabled" : "") +
    '><span class="ex20-dot" aria-hidden="true"></span>' +
    '<span class="ex20-opt-body"><span class="ex20-opt-label">' + label + "</span>" +
    '<span class="ex20-opt-hint">' + hint + "</span></span></label>";

  const checkSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.4" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5 9-10"></path></svg>';
  const tierCheck = (tier, checkedAttr, off, label, hint) =>
    '<label class="ex20-opt' + (off ? " ex20-opt--off" : "") + '">' +
    '<input type="checkbox" data-tier="' + tier + '"' + checkedAttr + ">" +
    '<span class="ex20-box" aria-hidden="true">' + checkSvg + "</span>" +
    '<span class="ex20-opt-body"><span class="ex20-opt-label">' + label + "</span>" +
    '<span class="ex20-opt-hint">' + hint + "</span></span></label>";

  const teamSelect =
    draft.kind === "team" && haveTeams
      ? '<div class="ex20-sel"><label class="ex20-lab" for="ex20-team">Team to export</label>' +
        '<select class="select" id="ex20-team" data-scope-team>' +
        '<option value=""' + (draft.team === "" ? " selected" : "") + ">Choose a team&hellip;</option>" +
        teams
          .map(
            (t) =>
              '<option value="' + esc(String(t.namespace || "")) + '"' +
              (draft.team === t.namespace ? " selected" : "") + ">" +
              esc(String(t.name || t.namespace || "")) + "</option>",
          )
          .join("") +
        "</select></div>"
      : "";
  const userSelect =
    userScope && haveTeams
      ? '<div class="ex20-sel"><label class="ex20-lab" for="ex20-user">Person to export</label>' +
        '<select class="select" id="ex20-user" data-scope-user>' +
        '<option value=""' + (draft.user === "" ? " selected" : "") + ">Choose a person&hellip;</option>" +
        people
          .map(
            (email) =>
              '<option value="' + esc(email) + '"' +
              (draft.user === email ? " selected" : "") + ">" +
              esc(personDisplayName(email, ctx.personLabel, "human") || email) + "</option>",
          )
          .join("") +
        "</select></div>"
      : "";

  const scopeBlock =
    '<div class="ex20-sec">' +
    '<div class="ex20-sec-title">What to export' + headingInfo("What to export", SCOPE_TIP) + "</div>" +
    '<div class="ex20-grid3">' +
    scopeRadio("org", "Whole organization", "Everything visible to your namespace.") +
    scopeRadio("team", "A specific team", "Only one team&#39;s namespace subtree and its sub-teams.") +
    scopeRadio("user", "A specific person", "Only the facts one person authored.") +
    "</div>" +
    (haveTeams ? "" : '<span class="hint">No teams available</span>') +
    teamSelect +
    userSelect +
    "</div>";

  const includeBlock =
    '<div class="ex20-sec">' +
    '<div class="ex20-sec-title">What to include</div>' +
    '<div class="ex20-grid2">' +
    tierCheck("L2", draft.l2 ? " checked" : "", false, "Facts", "Individual remembered facts (L2).") +
    tierCheck(
      "L3",
      userScope ? " disabled" : draft.l3 ? " checked" : "",
      userScope,
      "Knowledge",
      userScope
        ? "Knowledge is team-level; a person&#39;s export covers their facts."
        : "Consolidated knowledge concepts (L3).",
    ) +
    "</div></div>";

  const footRow =
    '<div class="ex20-foot">' +
    '<div class="ex20-foot-purpose">' +
    '<label class="ex20-lab" for="ex20-purpose">Purpose (optional)</label>' +
    '<input class="input" type="text" id="ex20-purpose" data-export-purpose maxlength="500" ' +
    'placeholder="e.g. quarterly compliance review" autocomplete="off">' +
    '<div class="ex20-note">Recorded on the audit entry so the reason for this export is on record.</div>' +
    "</div>" +
    '<div class="ex20-foot-gen">' +
    '<button type="button" class="btn btn--primary" data-action="generate">Generate export</button>' +
    '<div class="ex20-note">Writes one audited export row.</div>' +
    "</div></div>";

  // --- controls (the export is fired only from here, never on render) ---
  const controls =
    '<div class="card ex20-card" data-export-form style="margin-top:var(--s4)">' +
    scopeBlock +
    includeBlock +
    footRow +
    '<div class="ex20-status" data-export-status role="status" aria-live="polite"></div>' +
    "</div>";

  return head + controls + resultCard(ctx, teams);
}

// ---------------------------------------------------------------------------
// Result card - only after an explicit Generate. Shows the governance outcome
// (included / withheld / checksum) and a bounded, fully-escaped preview.
// ---------------------------------------------------------------------------

function resultCard(ctx, teams = null) {
  const { esc } = ctx;

  if (lastError !== null) {
    return (
      '<div class="card" style="margin-top:var(--s4)">' +
      "<h3>Export didn't run</h3>" +
      '<div class="sub" style="margin:0">' +
      esc(lastError) +
      "</div></div>"
    );
  }

  if (lastExport === null) return "";

  const includedL2 = num(lastExport.includedL2);
  const includedL3 = num(lastExport.includedL3);
  const excluded =
    lastExport.excluded && typeof lastExport.excluded === "object"
      ? lastExport.excluded
      : {};
  const withheldRole = num(excluded.role);
  const withheldSource = num(excluded.source);
  const withheldClass = num(excluded.classification);
  const withheldTotal = withheldRole + withheldSource + withheldClass;
  const includedTotal = includedL2 + includedL3;
  const excludedByTier =
    lastExport.excludedByTier && typeof lastExport.excludedByTier === "object"
      ? lastExport.excludedByTier
      : null;
  const userScoped = lastScope !== null && lastScope.kind === "user";

  // Name the scope the export actually ran under, so a scoped file is never
  // mistaken for the whole organization's memory.
  let scopeLine;
  if (lastScope === null) {
    scopeLine =
      "Whole organization &middot; superseded history, warm mirrors and caches excluded";
  } else if (lastScope.kind === "team") {
    const match = Array.isArray(teams)
      ? teams.find((t) => t && t.namespace === lastScope.value)
      : null;
    const teamLabel = match && match.name ? String(match.name) : lastScope.value;
    scopeLine =
      "Team memory export: <b>" + esc(teamLabel) + "</b> &middot; " +
      "team and sub-teams only; inherited organization memory is excluded";
  } else {
    const personLabel =
      personDisplayName(lastScope.value, ctx.personLabel, "human") || lastScope.value;
    scopeLine =
      "Facts authored by <b>" + esc(personLabel) + "</b> &middot; " +
      "the knowledge tier is team-level and not included";
  }

  const tile = (label, value, cap, warn) =>
    '<div class="ex20-tile"><div class="ex20-tile-k">' + label + "</div>" +
    '<div class="ex20-tile-v' + (warn ? " ex20-tile-v--warn" : "") + '">' + value + "</div>" +
    '<div class="ex20-tile-cap">' + cap + "</div></div>";
  const stats =
    '<div class="ex20-grid4">' +
    tile("Facts included", fmt(includedL2), "L2 &middot; Allowed after gating", false) +
    tile(
      "Knowledge included",
      fmt(includedL3),
      userScoped
        ? "Team-level &middot; Not in a person export"
        : "L3 &middot; Consolidated concepts",
      false,
    ) +
    tile(
      "Withheld by policy",
      fmt(withheldTotal),
      "Role " + fmt(withheldRole) +
        " &middot; Source " + fmt(withheldSource) +
        " &middot; Class " + fmt(withheldClass),
      withheldTotal > 0,
    ) +
    tile("Audit rows written", "1", "Append-only export event", false) +
    "</div>";

  // Withheld items stay named by reason and by tier, so the export is honest
  // about coverage; never silently dropped.
  const withheldReasons = [];
  if (withheldRole > 0) withheldReasons.push("role " + fmt(withheldRole));
  if (withheldSource > 0) withheldReasons.push("source " + fmt(withheldSource));
  if (withheldClass > 0)
    withheldReasons.push("classification " + fmt(withheldClass));
  const withheldLine =
    withheldTotal === 0
      ? '<div class="ex20-note">Nothing was withheld by policy - every eligible item is in this export.</div>'
      : '<div class="ex20-note">' +
        fmt(withheldTotal) +
        (withheldTotal === 1 ? " item was" : " items were") +
        " withheld by policy (" +
        esc(withheldReasons.join(", ")) +
        ").</div>";
  const tierWithheldLine =
    excludedByTier === null
      ? ""
      : '<div class="ex20-note"><b>Facts withheld:</b> ' +
        fmt(exclusionTotal(excludedByTier.L2)) +
        " &middot; <b>Knowledge withheld:</b> " +
        fmt(exclusionTotal(excludedByTier.L3)) +
        "</div>";

  // A genuine empty outcome: eligible role, but nothing matched or all withheld.
  const emptyNote =
    includedTotal === 0
      ? '<div class="sub" style="margin:0">There was nothing eligible to export' +
        (withheldTotal > 0 ? " after policy checks" : " yet") +
        ".</div>"
      : "";

  const sha = typeof lastExport.sha256 === "string" ? lastExport.sha256 : "";
  const filename =
    typeof lastExport.filename === "string" && lastExport.filename !== ""
      ? lastExport.filename
      : "halomem-export.md";
  const portableSha =
    typeof lastExport.portableSha256 === "string" ? lastExport.portableSha256 : "";
  const portableFilename =
    typeof lastExport.portableFilename === "string" &&
    lastExport.portableFilename !== ""
      ? lastExport.portableFilename
      : "halomem-export.json";
  const evRow = (label, value) =>
    '<div class="ex20-ev-row"><span class="ex20-ev-k">' + label + "</span>" +
    '<span class="ex20-ev-v" title="' + esc(value) + '">' + esc(value) + "</span></div>";
  const evidence =
    '<div class="ex20-evidence">' +
    '<div class="ex20-lab">Egress evidence</div>' +
    evRow("Portable file", portableFilename) +
    (portableSha === "" ? "" : evRow("Portable checksum (sha256)", portableSha)) +
    evRow("Readable file", filename) +
    (sha === "" ? "" : evRow("Readable checksum (sha256)", sha)) +
    "</div>";

  const downloadActs =
    includedTotal > 0
      ? '<div class="ex20-acts">' +
        '<button type="button" class="btn btn--primary btn--sm" data-action="download-json">Download portable .json</button>' +
        '<button type="button" class="btn btn--outline btn--sm" data-action="download">Download readable .md</button>' +
        '<button type="button" class="btn btn--outline btn--sm" data-action="copy">Copy to clipboard</button>' +
        '<span class="ex20-note">Downloads save the bytes already generated, never a second egress.</span>' +
        "</div>"
      : "";

  // Preview: bounded slice of the rendered markdown, fully escaped inside <pre>.
  const md = typeof lastExport.markdown === "string" ? lastExport.markdown : "";
  const truncated = md.length > PREVIEW_CHARS;
  const shown = truncated ? md.slice(0, PREVIEW_CHARS) : md;
  const previewNote = truncated
    ? '<div class="ex20-note">Showing the first ' +
      fmt(PREVIEW_CHARS) +
      " of " +
      fmt(md.length) +
      " characters. Download the file for the complete export.</div>"
    : "";
  const preview =
    md === ""
      ? ""
      : '<div class="ex20-preview"><div class="ex20-lab">Preview</div>' +
        '<pre class="ex20-pre">' +
        esc(shown) +
        "</pre>" +
        previewNote +
        "</div>";

  return (
    '<div class="card ex20-result" style="margin-top:var(--s4)">' +
    '<div class="ex20-res-head">' +
    '<div class="ex20-res-title"><b>Your export is ready</b>' +
    '<span class="ex20-res-sub">' + scopeLine + "</span></div>" +
    '<span class="ex20-pill-ok"><i></i>' +
    fmt(includedTotal) + (includedTotal === 1 ? " item" : " items") +
    "</span></div>" +
    stats +
    withheldLine +
    tierWithheldLine +
    emptyNote +
    evidence +
    preview +
    downloadActs +
    "</div>"
  );
}

// ---------------------------------------------------------------------------
// Actions (wired by app.js via data-action).
// ---------------------------------------------------------------------------

export const actions = {
  // A scope radio changed: capture the whole form as the new draft and
  // re-render so the selects and tier rules follow the chosen kind. A state
  // change only - never a read of anything new, never an egress.
  async "set-scope"(ctx, el) {
    const root =
      (el && typeof el.closest === "function" && el.closest("[data-export-form]")) ||
      (typeof document !== "undefined" ? document : null);
    scopeDraft = readDraft(root);
    keepResult = true;
    await ctx.go("s20");
  },

  // Explicit, audited egress. Reads the scope + tier checkboxes + purpose
  // from the form and POSTs the ONLY export call this screen ever makes.
  async generate(ctx, el) {
    const root =
      (el && typeof el.closest === "function" && el.closest("[data-export-form]")) ||
      (typeof document !== "undefined" ? document : null);
    const draft = readDraft(root);
    scopeDraft = draft;
    const tiers = [];
    if (draft.l2) tiers.push("L2");
    // The knowledge tier is team-level: a person's export never sends L3.
    if (draft.kind !== "user" && draft.l3) tiers.push("L3");
    if (tiers.length === 0) {
      setStatus("Select at least one tier to export.");
      return;
    }
    if (draft.kind === "team" && draft.team === "") {
      setStatus("Choose a team to export.");
      return;
    }
    if (draft.kind === "user" && draft.user === "") {
      setStatus("Choose a person to export.");
      return;
    }
    const body = { tiers };
    if (draft.purpose !== "") body.purpose = draft.purpose.slice(0, 500);
    if (draft.kind === "team") body.scope = { kind: "team", namespace: draft.team };
    if (draft.kind === "user") body.scope = { kind: "user", actor: draft.user };

    setStatus("Generating your export…", "info");
    try {
      const result = await ctx.api.post("/v1/mem/export", body);
      lastExport = result && typeof result === "object" ? result : null;
      lastScope =
        draft.kind === "org"
          ? null
          : { kind: draft.kind, value: draft.kind === "team" ? draft.team : draft.user };
      lastError = null;
    } catch (err) {
      if (isLimitError(err)) {
        // Announced by the shared limit toast; no result card, no stale result.
        lastError = null;
        lastExport = null;
      } else {
        lastError = err && err.message ? String(err.message) : "Export failed.";
      }
    }
    keepResult = true;
    await ctx.go("s20");
  },

  // Primary portable artifact: the complete allowed L2/L3 objects, metadata,
  // provenance and tier-specific withholding evidence in a versioned schema.
  async "download-json"(ctx) {
    if (!lastExport || typeof lastExport.portableJson !== "string") {
      setStatus("Generate an export first.");
      return;
    }
    saveDownload(
      lastExport.portableJson,
      typeof lastExport.portableFilename === "string" &&
        lastExport.portableFilename !== ""
        ? lastExport.portableFilename
        : "halomem-export.json",
      "application/json;charset=utf-8",
    );
    return true;
  },

  // Local save of the bytes already generated - NOT a second egress (the audit
  // row and checksum were recorded when Generate ran). Mirrors S16's download.
  async download(ctx) {
    if (!lastExport || typeof lastExport.markdown !== "string") {
      setStatus("Generate an export first.");
      return;
    }
    const filename =
      typeof lastExport.filename === "string" && lastExport.filename !== ""
        ? lastExport.filename
        : "halomem-export.md";
    saveDownload(lastExport.markdown, filename, "text/markdown;charset=utf-8");
    return true;
  },

  async copy(ctx) {
    if (!lastExport || typeof lastExport.markdown !== "string") {
      setStatus("Generate an export first.");
      return;
    }
    try {
      if (
        typeof navigator !== "undefined" &&
        navigator.clipboard &&
        navigator.clipboard.writeText
      ) {
        await navigator.clipboard.writeText(lastExport.markdown);
        setStatus("Copied the export to your clipboard.", "ok");
        return true;
      }
      setStatus("Clipboard is unavailable; use Download .md instead.");
      return false;
    } catch {
      setStatus("Couldn't copy to the clipboard; use Download .md instead.");
      return false;
    }
  },
};

// --- helpers ---------------------------------------------------------------

// The full export form state (scope radio, selects, tiers, purpose) from the
// live DOM. Missing controls fall back to the whole-organization defaults so
// the pre-scope form shape keeps working.
function readDraft(root) {
  const q = (sel) => (root && root.querySelector ? root.querySelector(sel) : null);
  const checked = (sel) => {
    const node = q(sel);
    return !!(node && node.checked);
  };
  const val = (sel) => {
    const node = q(sel);
    return node && typeof node.value === "string" ? node.value : "";
  };
  const kindRaw = val('input[name="export-scope"]:checked');
  const kind = kindRaw === "team" || kindRaw === "user" ? kindRaw : "org";
  return {
    kind,
    team: val("[data-scope-team]"),
    user: val("[data-scope-user]"),
    l2: checked('[data-tier="L2"]'),
    l3: checked('[data-tier="L3"]'),
    purpose: val("[data-export-purpose]").trim(),
  };
}

// Distinct member emails across the visible teams, for the person picker.
function rosterEmails(teams) {
  const seen = new Set();
  for (const team of teams) {
    const members = Array.isArray(team && team.members) ? team.members : [];
    for (const member of members) {
      const email = member && typeof member.email === "string" ? member.email : "";
      if (email !== "") seen.add(email);
    }
  }
  return [...seen].sort();
}

// tone: "bad" (default, validation/failure), "info" (in progress), "ok".
function setStatus(msg, tone = "bad") {
  if (typeof document === "undefined") return;
  const el = document.querySelector("[data-export-status]");
  if (!el) return;
  el.textContent = msg;
  el.setAttribute("data-tone", tone);
}

function saveDownload(bytes, filename, contentType) {
  if (
    typeof document === "undefined" ||
    typeof URL === "undefined" ||
    typeof Blob === "undefined"
  ) {
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

function exclusionTotal(value) {
  if (!value || typeof value !== "object") return 0;
  return num(value.role) + num(value.source) + num(value.classification);
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function fmt(n) {
  const x = Number(n) || 0;
  return x.toLocaleString("en-US");
}
