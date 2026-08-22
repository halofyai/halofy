/**
 * S3 - Scoped memory. Grant a team scoped access to its shared memory, see
 * every badge that holds such access, and revoke one instantly.
 *
 * The screen answers one question: "who can reach our memory, and how much of
 * it?" Creating a badge is a single inline row of fields - there is no wizard,
 * because there is nothing to sequence: a badge is `(team, access, level,
 * lifetime)` and every one of those is a one-click choice.
 *
 * Two things are deliberately NOT here:
 *
 *  - CONNECTING an agent. The badge is a bearer key; turning it into MCP
 *    configuration for Claude Code, Codex, Cursor and the rest is S14's job
 *    ("Agent connections"), which already renders per-client setup for a key.
 *  - APPROVING alerts and access requests. S19 ("Alerts") owns that inbox.
 *    This screen only shows the counts so a badge's row says whether it needs
 *    attention.
 *
 * What stays: a SCOPE BADGE is `(team, memory access, level)`. It governs
 * MEMORY - mem_search, mem_read, mem_write - through the namespace ancestor
 * ACL. A CONNECTOR GRANT names tables, columns and row caps on a connected
 * source; it governs `source_read` - raw backend rows - and NOT memory. The
 * grant only makes sense once a source is connected in the same namespace, so
 * it lives inside the badge's expanded row, not in the create form.
 *
 * All API-derived strings are escaped before interpolation.
 */

import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";

/**
 * Glyphs for the three summary tiles, verbatim from the prototype's
 * `smStats[].icon` paths. Not the shared `metric-card.js` registry: that
 * component is Home's tile (mono uppercase label, evergreen-tinted chip,
 * stacked value) and this screen reproduces the prototype's tile instead —
 * neutral chip, sentence-case label, value and unit on one baseline.
 */
const STAT_ICONS = {
  scope: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  lock: "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
  status: "M9 12l2 2 4-4M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
};

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

/**
 * M10 (D41): the session role for an internal auditor now crosses the
 * boundary as "member" plus the "audit:read" entitlement. Both the legacy
 * spelling and the translated pair keep the read-only control room.
 */
function isAuditReader(ctx) {
  const id = ctx.identity;
  if (!id) return false;
  if (id.role === "auditor") return true;
  return Array.isArray(id.entitlements) && id.entitlements.indexOf("audit:read") !== -1;
}

function canReadControl(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin" || isAuditReader(ctx);
}

/**
 * D50 (CONTRACTS-AGENT-SCOPE.md): a member may create badges in its OWN scope,
 * so it reaches this screen too - restricted, by the server, to Assistant keys
 * at its own namespace with member-level scope.
 */
function canDeployAgents(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return canMutate(ctx) || role === "member";
}

/** D50: the two scope levels a badge can carry. Never owner. */
const AGENT_LEVELS = [
  { level: "member", label: "Same as a teammate" },
  { level: "manager", label: "Teammate plus oversight" },
];

/** D54: what a badge may do with the team's memory. */
const MEMORY_ACCESS = [
  { value: "readwrite", label: "Read &amp; write" },
  { value: "read", label: "Read only" },
];

/** D51: the lifetime choices. Value is days; "" means standing access. */
const LIFETIMES = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "", label: "No expiry" },
];

/**
 * M9 #23 (E52) - the three product key types are LABELS over the existing five
 * roles (src/auth/key-types.ts is the server-side source of truth; this table
 * mirrors it for display only - the server never trusts these values).
 */
const KEY_TYPES = [
  { type: "admin", label: "Admin", prefix: "hm_adm_", roles: ["admin", "owner"] },
  { type: "assistant", label: "Assistant", prefix: "hm_agt_", roles: ["agent"] },
  { type: "read-only", label: "Read-only", prefix: "hm_ro_", roles: ["auditor"] },
];

function keyTypeForRole(role) {
  return KEY_TYPES.find((spec) => spec.roles.includes(String(role || ""))) || null;
}

const EMPTY_CONTROL = Object.freeze({ sources: [], grants: [], alerts: [], requests: [] });

/*
 * The ledger grid and the create row both live in app.css (`.sm-thead`/`.sm-row`
 * and `.sm-form`): §07 of docs/design/console-design-language.md makes the track list the contract,
 * and one CSS rule shared by the header and every row keeps them aligned by
 * construction. CSS (not an inline style) so the track list can drop columns at
 * narrow widths — an inline grid held the five-field form and eight-column
 * ledger at full width on phones, squeezing selects to 36px.
 *
 * The actions track there is a FIXED width, not `auto`: a content-sized track
 * resolves to 0 in the (empty) header and ~120px on a row that carries both
 * Rotate and Revoke, and the `fr` name column silently absorbs the difference
 * — so the two grids stop lining up. 128px fits the compact action pair.
 */

// ---------------------------------------------------------------------------
// Module state. Survives the ctx.go("s3") re-render that follows every action.
// ---------------------------------------------------------------------------

const EMPTY_DRAFT = Object.freeze({
  actor: "", namespace: "", recipientUserId: "", idempotencyKey: "",
  level: "member", lifetime: "30", memoryAccess: "readwrite",
});

let draft = { ...EMPTY_DRAFT };
let draftError = "";
let issued = null; // briefly held self/revealed key OR delegated handoff confirmation
let issuedTimer = null;
const BEARER_MASK = "•••• •••• •••• •••• •••• ••••";
let ledgerFilter = "active"; // active | revoked | all
/**
 * Free-text narrowing over the visible ledger. Kept in module state so the
 * ctx.go("s3") re-render after any action (filter, rotate, revoke, create)
 * repaints the input and the hidden rows instead of silently dropping the
 * query. Keystrokes still never re-render: `app.js` replaces the stage's
 * innerHTML on refresh, which would lose focus and the caret, so the action
 * below hides rows in place and this state only matters on the next render.
 */
let ledgerSearch = "";
let selectedBadgeId = ""; // badge whose detail is open in the right panel
let sourceFormKeyId = ""; // which badge has the connector panel open
let assignableRecipients = new Map(); // team namespace -> safe recipient summaries

/**
 * cleanup() below closes only the shared drawer. It deliberately does not reset
 * this module state, because a refresh must not erase a briefly revealed key.
 */

export async function render(ctx) {
  const mutate = canMutate(ctx);
  const deploy = canDeployAgents(ctx);
  const readControl = canReadControl(ctx);
  // D50: a member reaches this screen for its own badges only. It may not
  // enumerate people or badges (the server 403s /v1/admin/people for it), so
  // that fetch is skipped rather than turned into an error screen.
  let people = null;
  if (readControl) {
    try {
      people = await ctx.api.get("/v1/admin/people");
    } catch (err) {
      return errorScreen(ctx, err);
    }
  }
  const control = readControl ? await loadAgentControl(ctx) : EMPTY_CONTROL;
  // GET /v1/admin/keys is owner/admin-only server-side, plus the D50 member
  // carve-out (agent keys at the member's own namespace). Fetching it for an
  // auditor 403s, and safeGet would render the denial as an authoritative
  // "No credentials yet." (audit finding) - so the ledger falls back to the
  // badge listing for roles the server would refuse.
  const keys = deploy ? arrayFrom(await safeGet(ctx, "/v1/admin/keys"), "keys") : [];
  const teams = deploy ? arrayFrom(await safeGet(ctx, "/v1/admin/teams"), "teams") : [];
  const handoffPayload = mutate ? await safeGet(ctx, "/v1/admin/key-handoffs") : null;
  const handoffsAvailable = !mutate || handoffPayload !== null;
  const handoffs = arrayFrom(handoffPayload, "handoffs")
    .filter((handoff) => handoff && handoff.status === "pending");
  const badges = (Array.isArray(people && people.badges) ? people.badges : [])
    .filter((badge) => !badge.role || badge.role === "agent");
  const rows = mergeRows(badges, keys, control, handoffs);

  if (selectedBadgeId && !rows.some((row) => String(row.id || "") === selectedBadgeId)) {
    selectedBadgeId = "";
    sourceFormKeyId = "";
  }
  const selectedBadge = rows.find((row) => String(row.id || "") === selectedBadgeId) || null;
  const detailPanel = rightPanelHtml({
    id: "badge-detail-panel",
    eyebrow: "Scoped memory",
    title: selectedBadge ? ctx.esc(String(selectedBadge.actor || selectedBadge.id || "Badge details")) : "Badge details",
    closeAction: "badge-panel-close",
    className: "badge-detail-drawer",
    body: selectedBadge
      ? ledgerDetail(ctx, selectedBadge, control, mutate)
      : '<div class="sub">Select a badge to inspect its scope and controls.</div>',
  });

  return shell(`
    <div class="head"><div><div class="eyebrow">Govern</div><h1>Scope Memory</h1></div></div>
    ${readControl ? statStrip(rows, control) : ""}
    ${deploy ? scopeAccessCard(ctx, teams, people, mutate) : ""}
    ${readControl || deploy ? ledgerCard(ctx, rows, control, mutate, deploy, handoffsAvailable) : ""}
    ${detailPanel}`);
}

/**
 * The prototype's own screen container: a 1160px column with an 18px rhythm.
 * Not `.screen-flow` — that carries the console's section spacing, which is
 * not what the prototype draws.
 *
 * The page head inside it stays the platform's `.head` (eyebrow + h1) rather
 * than the prototype's breadcrumb-and-action header: titles, paths and
 * subtitles follow the platform's own convention.
 */
function shell(content) {
  return `<div class="sm-screen">${content}</div>`;
}

/**
 * The three-tile hero, lifted from the prototype's `smStats`.
 *
 * The prototype counts facts; this screen governs the badges that reach them,
 * so the triple keeps the prototype's SHAPE — how much exists, how much of it
 * is the sensitive kind, how much needs a person — over badge data:
 *
 *   Scoped badges   live credentials holding scoped memory access
 *   Source access   the restricted tier: badges that also reach raw source rows
 *   Needs attention expiring, expired, out-of-policy, or carrying open alerts
 *
 * Rendered only for a role that actually READ the control endpoints. A member
 * gets `EMPTY_CONTROL`, and painting that as three zeros would turn "not
 * fetched" into "none" — the one thing CLAUDE.md forbids a console read to do.
 */
function statTile({ label, value, unit, icon }) {
  return `<div class="sm-tile">
    <div class="sm-tile-head">
      <span class="sm-tile-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="${STAT_ICONS[icon]}"></path></svg></span>
      <span class="sm-tile-k">${label}</span>
    </div>
    <div class="sm-tile-shell"><span class="sm-tile-v">${value}</span><span class="sm-tile-u">${unit}</span></div>
  </div>`;
}

function statStrip(rows, control) {
  const live = rows.filter((row) => rowStatus(row) === "live");
  const granted = new Set(
    control.grants
      .filter((grant) => String(grant.status || "active") === "active")
      .map((grant) => String(grant.keyId || "")),
  );
  const withSource = live.filter((row) => granted.has(String(row.id || ""))).length;
  const flagged = new Set([
    ...control.alerts.map((alert) => String(alert.keyId || "")),
    ...control.requests.map((request) => String(request.keyId || "")),
  ]);
  const attention = live.filter(
    (row) => row.expired || row.outOfPolicy || expiringSoon(row) || flagged.has(String(row.id || "")),
  ).length;
  return `<div class="sm-stats">
    ${statTile({ label: "Scoped Badges", value: String(live.length), unit: "hold scoped access", icon: "scope" })}
    ${statTile({ label: "Source Access", value: String(withSource), unit: "reach raw source rows", icon: "lock" })}
    ${statTile({ label: "Needs Attention", value: String(attention), unit: "pending or expiring", icon: "status" })}
  </div>`;
}

/** Inside 14 days. Matches the shortest lifetime the create form offers (30d). */
function expiringSoon(row) {
  const time = Date.parse(String(row.expiresAt || ""));
  if (!Number.isFinite(time)) return false;
  return time - Date.now() < 14 * 86_400_000;
}

async function loadAgentControl(ctx) {
  const endpoints = [
    "/v1/admin/sources",
    "/v1/admin/agent-connections",
    "/v1/admin/agent-access/alerts?status=open&limit=50",
    "/v1/admin/agent-access/requests?status=pending&limit=50",
  ];
  const values = await Promise.all(endpoints.map((path) => safeGet(ctx, path)));
  return {
    sources: arrayFrom(values[0], "sources"),
    grants: arrayFrom(values[1], "grants"),
    alerts: arrayFrom(values[2], "alerts"),
    requests: arrayFrom(values[3], "requests"),
  };
}

async function safeGet(ctx, path) {
  try {
    return await ctx.api.get(path);
  } catch {
    return null;
  }
}

function arrayFrom(value, key) {
  if (Array.isArray(value)) return value;
  return Array.isArray(value && value[key]) ? value[key] : [];
}

/**
 * One row per issued credential. The badge listing (/v1/admin/people) is the
 * only source an auditor can read; the key listing carries the fields it does
 * not (level, expiry, description, type), so the two are merged rather than
 * shown as two tables. A grant with no matching key still earns a row, because
 * something is holding source access and the operator must be able to see it.
 */
function mergeRows(badges, keys, control, handoffs = []) {
  const rows = [];
  const known = new Set();
  const add = (entry) => {
    const id = String(entry.id || "");
    if (!id || known.has(id)) return;
    known.add(id);
    rows.push(entry);
  };
  for (const key of keys) add(key);
  for (const badge of badges) add(badge);
  for (const handoff of handoffs) add({ ...handoff, role: "agent", handoffPending: true });
  for (const grant of control.grants) {
    const keyId = String(grant.keyId || "");
    if (keyId) add({ id: keyId, actor: keyId, namespace: grant.namespace, status: grant.status });
  }
  return rows;
}

/**
 * A namespace, written for someone who is already signed in to the one
 * organization it belongs to. Every namespace the console can show sits under
 * that tenant root - the ACL guarantees it - so repeating the root on every row
 * costs a column's worth of width and says nothing: `halofy/sales/team` reads
 * as `sales/team` here. A namespace with no `/` IS the root, which means the
 * badge is scoped to the whole organization rather than to a team.
 *
 * Display only. The raw namespace is what gets posted, and what the readonly
 * team field carries in `data-namespace`.
 */
function teamLabel(namespace) {
  const value = String(namespace || "");
  const cut = value.indexOf("/");
  return cut === -1 ? "Organization" : value.slice(cut + 1);
}

// ---------------------------------------------------------------------------
// Scope memory access - the create form, and the briefly held key it produces.
// ---------------------------------------------------------------------------

/**
 * Which team the form is actually on. The caller's own namespace is the natural
 * default, but a root owner sits at `""` - which is no team at all, and is the
 * one binding D50 forbids. Falling back to the first team in the list keeps the
 * select honest about what the server will accept.
 */
function selectedTeam(ctx, teams) {
  const own = (ctx.identity && ctx.identity.namespace) || "";
  const known = teams.filter((team) => team && typeof team.namespace === "string" && team.namespace);
  const candidates = known.map((team) => team.namespace);
  if (draft.namespace && (!candidates.length || candidates.includes(draft.namespace))) {
    return draft.namespace;
  }
  if (own && (!candidates.length || candidates.includes(own))) return own;
  draft.namespace = candidates[0] ?? own;
  return draft.namespace;
}

/**
 * The team field. D50 makes this a fixed list rather than free text - a badge
 * binds to a registered team, and a member may bind only to its own. The server
 * re-decides regardless; this only stops the console from offering a scope the
 * server would refuse.
 */
function teamField(ctx, teams, mutate) {
  const own = (ctx.identity && ctx.identity.namespace) || "";
  const selected = selectedTeam(ctx, teams);
  if (!mutate) {
    // Shows the short label but carries the real namespace, because this value
    // is what gets posted. readDraft() prefers data-namespace for that reason.
    return `<input class="input" id="badge-team" value="${ctx.esc(teamLabel(own))}" data-namespace="${ctx.esc(own)}" readonly aria-readonly="true">`;
  }
  const known = teams.filter((team) => team && typeof team.namespace === "string" && team.namespace);
  if (!known.length) {
    // No team is registered yet, so this is the one field where the operator
    // types a namespace outright - it stays raw and monospaced.
    return `<input class="input mono" id="badge-team" value="${ctx.esc(selected)}" autocomplete="off" placeholder="support">`;
  }
  const options = known.map((team) => {
    const value = ctx.esc(team.namespace);
    const label = ctx.esc(team.name || teamLabel(team.namespace));
    return `<option value="${value}"${team.namespace === selected ? " selected" : ""}>${label}</option>`;
  }).join("");
  return `<select class="select" id="badge-team" data-change-action="badge-team-change">${options}</select>`;
}

function recipientField(ctx, teams, people, mutate) {
  if (!mutate) {
    return '<input class="input" id="badge-recipient" value="Me" readonly aria-readonly="true">';
  }
  const namespace = selectedTeam(ctx, teams);
  assignableRecipients = new Map(teams.map((team) => [
    String((team && team.namespace) || ""),
    eligibleRecipients(team, people),
  ]));
  const members = assignableRecipients.get(namespace) || [];
  if (draft.recipientUserId && !members.some((member) => member.userId === draft.recipientUserId)) {
    draft.recipientUserId = "";
  }
  const options = members.map((member) => {
    const label = member.displayName || "Member";
    return `<option value="${ctx.esc(member.userId)}"${member.userId === draft.recipientUserId ? " selected" : ""}>${ctx.esc(label)}</option>`;
  }).join("");
  return `<select class="select" id="badge-recipient"><option value="">I'll connect it myself</option>${options}</select>`;
}

function eligibleRecipients(team, people) {
  const peopleById = new Map(
    (Array.isArray(people && people.users) ? people.users : [])
      .filter((user) => user && user.id)
      .map((user) => [user.id, user]),
  );
  return (Array.isArray(team && team.members) ? team.members : []).flatMap((member) => {
    if (!member || !member.userId) return [];
    const person = peopleById.get(member.userId) || {};
    const role = member.role || person.role;
    const status = member.status || person.status;
    const entitlements = Array.isArray(member.entitlements)
      ? member.entitlements
      : person.entitlements;
    if (role !== "member" || status !== "active" ||
        (Array.isArray(entitlements) && entitlements.includes("audit:read"))) return [];
    return [{
      ...person,
      ...member,
      displayName: member.displayName || person.displayName || "Member",
      email: member.email || person.email || "",
    }];
  });
}

function scopeAccessCard(ctx, teams, people, mutate) {
  return `<section class="sm-card sm-create" aria-labelledby="scope-access-title">
    <div class="sm-card-head"><h3 id="scope-access-title" class="sm-card-title">Scope memory access${headingInfo("Scope memory access", "Grant your team scoped access to its shared memory.")}</h3>
      <span class="pill"><i class="dot"></i>${mutate ? "Admin &amp; managers" : "Your team"}</span></div>
    <div data-scope-access-body>${issued ? issuedPanel(ctx) : badgeForm(ctx, teams, people, mutate)}</div>
  </section>`;
}

function badgeForm(ctx, teams, people, mutate) {
  // Manager scope is an admin's to grant: a member may only create a badge at
  // its own level, so the choice is not offered (and the server refuses it).
  const levelField = mutate
    ? `<div class="field" style="margin:0"><label for="badge-level">Agent role</label>
        <select class="select" id="badge-level">${AGENT_LEVELS.map((entry) =>
          `<option value="${entry.level}"${draft.level === entry.level ? " selected" : ""}>${entry.label}</option>`).join("")}</select></div>`
    : `<div class="field" style="margin:0"><label for="badge-level">Agent role</label>
        <input class="input" id="badge-level" value="Same as a teammate" readonly aria-readonly="true"></div>`;
  return `
    <div class="sm-form">
      <div class="field" style="margin:0"><label for="badge-name">Badge name</label>
        <input class="input" id="badge-name" placeholder="Sales memory badge" autocomplete="off" value="${ctx.esc(draft.actor)}"></div>
      <div class="field" style="margin:0"><label for="badge-team">Team</label>${teamField(ctx, teams, mutate)}</div>
      <div class="field" style="margin:0"><label for="badge-recipient">Assigned to</label>${recipientField(ctx, teams, people, mutate)}</div>
      <div class="field" style="margin:0"><label for="badge-access">Memory access</label>
        <select class="select" id="badge-access">${MEMORY_ACCESS.map((entry) =>
          `<option value="${entry.value}"${draft.memoryAccess === entry.value ? " selected" : ""}>${entry.label}</option>`).join("")}</select></div>
      ${levelField}
      <div class="field" style="margin:0"><label for="badge-expiry">Access ends</label>
        <select class="select" id="badge-expiry">${LIFETIMES.map((entry) =>
          `<option value="${entry.value}"${draft.lifetime === entry.value ? " selected" : ""}>${entry.label}</option>`).join("")}</select></div>
    </div>
    ${draftError ? `<div class="hint hint--error" role="alert">${ctx.esc(draftError)}</div>` : ""}
    <div class="row scope-memory-create-action" style="margin-top:var(--s4)">
      <button class="btn btn--solid btn--sm" data-action="badge-create">Create scoped badge</button>
      <span class="subtle home-text-xs scope-memory-create-hint">You can revoke it instantly at any time.</span>
    </div>
    <div class="hint" id="badge-status" role="status" aria-live="polite"></div>`;
}

/**
 * The plaintext is masked until the operator asks to reveal it and clears from
 * browser memory after a minute. New and rotated badges can retrieve the same
 * value again through the audited reveal route; legacy badges need one rotation.
 * Turning it into per-client MCP configuration is S14's job.
 */
function issuedPanel(ctx) {
  if (issued.delegated) {
    return `
      <div style="border:1px solid var(--line);border-radius:var(--r-md);background:var(--sage-soft);padding:var(--s4);display:grid;gap:var(--s3)">
        <div class="row"><span class="pill pill--ok"><i class="dot"></i>Badge assigned</span>
          <b>${ctx.esc(issued.actor || "")}</b></div>
        <div class="subtle">Assigned to <b>${ctx.esc(issued.recipientLabel || "the member")}</b>. No bearer token was created for you. They can claim it, then reveal it again on demand in <b>Agent connections</b>.</div>
        <div class="row"><button class="btn btn--danger btn--sm" data-action="handoff-revoke" data-id="${ctx.esc(issued.handoffId || "")}">Revoke assignment</button>
          <button class="btn btn--ghost btn--sm" data-action="badge-issued-dismiss">Done</button></div>
      </div>`;
  }
  const access = issued.canWrite === false ? "Read only" : "Read &amp; write";
  const expiry = issued.expiresAt ? ctx.esc(formatDay(issued.expiresAt)) : "No expiry";
  const revealed = issued.revealed === true;
  return `
    <div style="border:1px solid var(--line);border-radius:var(--r-md);background:var(--sage-soft);padding:var(--s4);display:grid;gap:var(--s3)">
      <div class="row"><span class="pill pill--ok"><i class="dot"></i>Badge created</span>
        <b>${ctx.esc(issued.actor || "")}</b><span class="subtle">·</span>
        <span class="subtle">${ctx.esc(teamLabel(issued.namespace))} · ${access} · ${expiry}</span></div>
      <div class="row" style="gap:var(--s3)">
        <code class="mono" data-issued-key aria-label="Bearer token ${revealed ? "revealed" : "hidden"}" style="flex:1;min-width:0;padding:9px 12px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--panel);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${revealed ? ctx.esc(issued.plaintext || "") : BEARER_MASK}</code>
        <button class="btn btn--outline btn--sm" data-action="badge-key-visibility" aria-pressed="${String(revealed)}">${revealed ? "Hide bearer" : "Reveal bearer"}</button>
        <button class="btn btn--primary btn--sm" data-action="badge-key-copy">Copy key</button>
      </div>
      <div class="subtle" style="font-size:12.5px">Paste this bearer token into the agent's setup code under
        <b>Agent connections</b>, which generates the configuration for each client. It is hidden by default and can be revealed again on demand.</div>
      <div class="row"><button class="btn btn--ghost btn--sm" data-action="badge-issued-dismiss">Done</button>
        <span class="subtle" id="badge-copy-status" role="status"></span></div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Badges & credentials - the ledger.
// ---------------------------------------------------------------------------

function rowStatus(row) {
  const status = String(row.status || "active").toLowerCase();
  if (status === "revoked") return "revoked";
  return "live";
}

function passesFilter(row) {
  if (ledgerFilter === "all") return true;
  return rowStatus(row) === (ledgerFilter === "active" ? "live" : "revoked");
}

/** What the in-place search matches: exactly the string each row carries in `data-search`. */
function rowSearchText(row) {
  const name = String(row.actor || row.id || "Unnamed badge");
  return `${name} ${teamLabel(row.namespace)} ${row.namespace || ""}`.toLowerCase();
}

function ledgerCard(ctx, rows, control, mutate, deploy, handoffsAvailable = true) {
  const activeCount = rows.filter((row) => rowStatus(row) === "live").length;
  const revokedCount = rows.filter((row) => rowStatus(row) === "revoked").length;
  const visible = rows.filter(passesFilter);
  const query = ledgerSearch.trim().toLowerCase();
  const matchesSearch = (row) => !query || rowSearchText(row).includes(query);
  const shownCount = visible.filter(matchesSearch).length;
  // The prototype's FilterBar chip: selected is the evergreen wash, unselected
  // a plain bordered pill. Label and count stay one text run — the ledger's
  // filter reads "Active 2", and splitting it into styled segments would break
  // that into two nodes for no visual gain on a single-option chip.
  const filterBtn = (value, label, count) =>
    `<button class="sm-chip${ledgerFilter === value ? " is-on" : ""}" data-action="badge-filter" data-filter="${value}" aria-pressed="${ledgerFilter === value}">${label}${count === null ? "" : ` ${count}`}</button>`;
  // The empty state keeps its sentence for every filter ("No active badges.")
  // and only offers the reset when a filter is what emptied the list.
  const body = visible.length
    ? visible.map((row) => ledgerRow(ctx, row, control, mutate, deploy, matchesSearch(row))).join("")
    : `<div class="sm-empty" data-ledger-empty>
        <b>No ${ledgerFilter === "all" ? "" : ledgerFilter + " "}badges.</b>
        ${ledgerFilter === "all" ? "" : '<button class="sm-empty-reset" data-action="badge-filter" data-filter="all">Clear all filters</button>'}
      </div>`;
  // The search no-match state is always in the DOM (hidden unless it applies)
  // so the keystroke action only ever toggles it, never builds markup.
  const noMatch = `<div class="sm-empty" data-ledger-nomatch${query && shownCount === 0 && visible.length ? "" : " hidden"}>
        <b>No badge matches that search.</b>
        <button class="sm-empty-reset" data-action="badge-search-clear">Clear search</button>
      </div>`;
  return `<section class="sm-card" aria-labelledby="badge-ledger-title">
    <div class="sm-card-head"><h3 id="badge-ledger-title" class="sm-card-title">Badges &amp; credentials${headingInfo("Badges &amp; credentials", "One row per issued badge - team scope, access and lifecycle in one place.")}</h3>
      <label class="sm-search">
        <svg viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4" stroke-linecap="round"/></svg>
        <span class="sr-only">Search badges</span>
        <input type="search" placeholder="Search badges, teams, owners" autocomplete="off" data-input-action="badge-search" value="${ctx.esc(ledgerSearch)}">
      </label></div>

    ${handoffsAvailable ? "" : '<div class="sm-empty"><b>Pending assignments unavailable</b><span> Refresh to try again.</span></div>'}
    <div class="sm-filterslot"><div class="sm-filterbar">
      ${filterBtn("active", "Active", activeCount)}
      ${filterBtn("revoked", "Revoked", revokedCount)}
      ${filterBtn("all", "All", null)}
      <div class="sm-filterbar-tail">
        <span class="sm-result" data-ledger-result>${shownCount}${shownCount === 1 ? " badge" : " badges"}</span>
        <button class="sm-clear" data-action="badge-filter" data-filter="all">Clear</button>
      </div>
    </div></div>

    <div class="sm-scroll"><div class="sm-table">
      <div class="sm-thead">
        <span class="eyebrow">Badge</span><span class="eyebrow">Team</span><span class="eyebrow">Access</span>
        <span class="eyebrow">Status</span><span class="eyebrow">Last seen</span><span class="eyebrow">Expires</span>
        <span></span><span></span>
      </div>
      <div class="sm-tbody" data-ledger-body>${body}${noMatch}</div>
      <div class="sm-tfoot">
        <span data-ledger-count data-ledger-total="${rows.length}">Showing ${shownCount} of ${rows.length} ${rows.length === 1 ? "badge" : "badges"}</span>
      </div>
    </div></div>
    <div class="hint" id="key-status" role="status" aria-live="polite"></div>
  </section>`;
}

function ledgerRow(ctx, row, control, mutate, deploy, matchesSearch = true) {
  const id = ctx.esc(String(row.id || ""));
  const status = rowStatus(row);
  const spec = keyTypeForRole(row.role);
  const isAgent = String(row.role || "agent") === "agent";
  const access = isAgent
    ? (row.agentCanWrite === false ? "Read only" : "Read &amp; write")
    : `<span class="badge badge--role">${ctx.esc(spec ? spec.label : "Member")}</span>`;
  // A grandfathered organization-root badge can only be revoked - rotating it
  // would re-issue authority the current rules refuse to grant (D50). The same
  // is true of an expired credential (D51): its replacement would inherit the
  // lapsed expiry and be dead on arrival.
  const rotate = deploy && spec && !row.outOfPolicy && !row.expired && !row.handoffPending
    ? `<button class="btn btn--outline btn--sm" data-action="key-rotate" data-id="${id}">Rotate</button>`
    : "";
  const acts = deploy && status !== "revoked"
    ? row.handoffPending
      ? `<button class="btn btn--danger btn--sm" data-action="handoff-revoke" data-id="${id}">Revoke</button>`
      : `${rotate}<button class="btn btn--danger btn--sm" data-action="key-revoke" data-id="${id}">Revoke</button>`
    : "";
  const chevron = isAgent && !row.handoffPending
    ? `<button class="usage-expand halo-icon-control" data-action="badge-expand" data-id="${id}" aria-expanded="false" aria-controls="badge-detail-panel" aria-haspopup="dialog" aria-label="Details for ${ctx.esc(row.actor || row.id || "badge")}"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" width="14" height="14" aria-hidden="true"><path d="m6 3 5 5-5 5" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>`
    : "<span></span>";
  const name = String(row.actor || row.id || "Unnamed badge");
  const team = teamLabel(row.namespace);
  // The prototype's first cell is two lines: the subject, then a tabular meta
  // line. Here that is what the credential IS, plus when it was issued.
  const meta = `${row.handoffPending ? "Pending assignment" : spec ? spec.label : "Credential"}${row.createdAt ? ` · issued ${formatDay(row.createdAt)}` : ""}`;
  // Lowercased haystack for the in-place search below, so the filter never has
  // to re-derive what a row says.
  const haystack = ctx.esc(rowSearchText(row));
  return `
    <div class="sm-row${status === "revoked" ? " sm-row--revoked" : ""}${selectedBadgeId && selectedBadgeId === String(row.id || "") ? " is-selected" : ""}" data-badge-row data-search="${haystack}"${matchesSearch ? "" : " hidden"}>
      <div class="sm-cell-subject">
        <div class="sm-cell-name">${ctx.esc(name)}</div>
        <div class="sm-cell-meta">${ctx.esc(meta)}</div>
      </div>
      <span class="subtle">${ctx.esc(team)}</span>
      <span class="sm-cell-dim">${access}</span>
      <span>${statusPill(ctx, row)}</span>
      <span class="subtle">${ctx.esc(lastSeenShort(row.lastUsed))}</span>
      <span class="subtle">${row.expiresAt ? ctx.esc(formatDay(row.expiresAt)) : "No expiry"}</span>
      <span class="sm-cell-acts">${acts}</span>
      ${chevron}
    </div>`;
}

function ledgerDetail(ctx, row, control, mutate) {
  const keyIdRaw = String(row.id || "");
  const namespace = String(row.namespace || "");
  const grants = control.grants.filter((item) => String(item.keyId || "") === keyIdRaw);
  const grant = grants.find((item) => String(item.status || "") === "active") || grants[0] || null;
  const alerts = control.alerts.filter((item) => String(item.keyId || "") === keyIdRaw).length;
  const requests = control.requests.filter((item) => String(item.keyId || "") === keyIdRaw).length;
  const level = row.agentAccessLevel === "manager" ? "Teammate plus oversight" : "Same as a teammate";
  const cell = (label, value) =>
    `<div class="badge-detail-cell"><div class="eyebrow">${label}</div><div class="badge-detail-value">${value}</div></div>`;
  const revealCredential = row.bearerRevealable === true && rowStatus(row) === "live" && !row.expired
    ? `Bearer key · gateway enforced <button class="btn btn--outline btn--sm" data-action="key-reveal" data-id="${ctx.esc(keyIdRaw)}">Reveal bearer</button>`
    : 'Bearer key · gateway enforced <button class="btn btn--outline btn--sm" disabled title="Rotate this legacy badge once to enable repeated reveal">Reveal unavailable</button>';
  return `
    <div class="badge-detail-grid">
      ${cell("Team", ctx.esc(teamLabel(row.namespace)))}
      ${cell("Memory access", row.agentCanWrite === false ? "Read only" : "Read &amp; write")}
      ${cell("Agent role", level)}
      ${cell("Access ends", row.expiresAt ? ctx.esc(formatDay(row.expiresAt)) : "No expiry")}
      ${cell("Source access", sourceAccessCell(ctx, keyIdRaw, namespace, grant, control, mutate))}
      ${cell("Alerts &amp; requests", `${alerts} open · ${requests} pending`)}
      ${cell("Credential", revealCredential)}
      ${cell("Created", row.createdAt ? ctx.esc(formatDay(row.createdAt)) : "Unknown")}
      ${row.description ? cell("Purpose", ctx.esc(row.description)) : ""}
      ${row.outOfPolicy ? cell("Policy", '<span class="pill pill--warn"><i class="dot"></i>Out of policy</span> Bound to the organization root. Revoke and re-create it on a team.') : ""}
      ${sourceFormKeyId === keyIdRaw ? `<div class="badge-detail-form">${sourceForm(ctx, keyIdRaw, connectorsFor(control, namespace))}</div>` : ""}
    </div>`;
}

// ---------------------------------------------------------------------------
// Connector grants - the optional, advanced path. Source access is NOT memory
// access, so it is never part of creating a badge.
// ---------------------------------------------------------------------------

/**
 * Connectors this badge could actually be granted. The server derives the
 * grant's namespace from the key and refuses a connector registered elsewhere,
 * so offering every connector produces a dead-end error for any badge whose
 * team has no source of its own.
 */
function connectorsFor(control, namespace) {
  return control.sources.filter((source) => {
    if (String(source.lifecycleState || "active") === "disabled") return false;
    return String(source.namespace || "") === String(namespace || "");
  });
}

function sourceAccessCell(ctx, keyId, namespace, grant, control, mutate) {
  if (grant) return grantSummary(ctx, grant);
  const available = connectorsFor(control, namespace);
  if (!mutate || !available.length) return "Memory only";
  if (sourceFormKeyId === keyId) return "Memory only";
  return `Memory only <button class="btn btn--outline btn--sm" data-action="agent-source-open" data-id="${ctx.esc(keyId)}">Expose a source</button>`;
}

function grantSummary(ctx, grant) {
  const oversight = grant.oversight || {};
  return `${ctx.esc(grant.connectorId || "-")} - ${ctx.esc(String(grant.maxRows || 0))} rows / ${ctx.esc(formatBytes(grant.maxBytes))} / ${ctx.esc(String(oversight.maxRequestsPerMinute || 0))} per min`;
}

function sourceForm(ctx, keyId, sources) {
  const options = sources.map((source) => {
    const id = ctx.esc(source.id || "");
    const name = ctx.esc(source.name || source.kind || source.id || "Connected source");
    return `<option value="${id}">${name}</option>`;
  }).join("");
  return `
    <div class="m8a-issue" data-source-form="${ctx.esc(keyId)}">
      <p class="subtle">This is separate from memory: it lets the badge read raw rows from a
      connected system, limited to the tables, columns, and volume you name here.</p>
      <div class="field"><label for="src-connector-${ctx.esc(keyId)}">Connected source</label>
        <select class="select" id="src-connector-${ctx.esc(keyId)}">${options}</select></div>
      <div class="field"><label for="src-refs-${ctx.esc(keyId)}">Tables it may read</label>
        <textarea class="input mono" id="src-refs-${ctx.esc(keyId)}" rows="2" placeholder="support.refunds, support.orders"></textarea>
        <div class="subtle">Exact names, comma separated. No wildcards.</div></div>
      <div class="field"><label for="src-fields-${ctx.esc(keyId)}">Columns allowed in each table</label>
        <textarea class="input mono" id="src-fields-${ctx.esc(keyId)}" rows="3" placeholder="support.refunds: ticket_id, status&#10;support.orders: order_id, status"></textarea>
        <div class="subtle">One line per table. Every table needs at least one column.</div></div>
      <div class="field"><label for="src-purposes-${ctx.esc(keyId)}">Allowed reasons for access</label>
        <input class="input" id="src-purposes-${ctx.esc(keyId)}" placeholder="Resolve refunds" autocomplete="off"></div>
      <div class="field"><label for="src-sensitivity-${ctx.esc(keyId)}">Most sensitive data allowed</label>
        <select class="select" id="src-sensitivity-${ctx.esc(keyId)}">
          <option value="public">Public</option><option value="internal">Internal</option>
          <option value="confidential" selected>Confidential</option><option value="restricted">Restricted</option>
        </select></div>
      <div class="m8a-fields-3">
        ${numberField(`src-rows-${ctx.esc(keyId)}`, "Rows per request", "25", 1, 1000)}
        ${numberField(`src-mb-${ctx.esc(keyId)}`, "Megabytes per request", "1", 0.01, 10, "0.01")}
        ${numberField(`src-rate-${ctx.esc(keyId)}`, "Requests per minute", "60", 1, 10000)}
      </div>
      <div class="row">
        <button class="btn btn--solid btn--sm" data-action="agent-source-submit" data-id="${ctx.esc(keyId)}">Grant source access</button>
        <button class="btn btn--ghost btn--sm" data-action="agent-source-cancel">Cancel</button>
        <span class="subtle" data-source-status role="status"></span>
      </div>
    </div>`;
}

function numberField(id, label, value, min, max, step) {
  return `<div class="field"><label for="${id}">${label}</label><input class="input" id="${id}" type="number" value="${value}" min="${min}" max="${max}"${step ? ` step="${step}"` : ""}></div>`;
}

function statusPill(ctx, key) {
  const value = String((key && key.status) || "").toLowerCase();
  if (value === "revoked") return '<span class="pill pill--crit"><i class="dot"></i>revoked</span>';
  if (key && key.expired) return '<span class="pill pill--warn"><i class="dot"></i>expired</span>';
  if (value === "active" || value === "") return '<span class="pill pill--live"><i class="dot"></i>live</span>';
  return `<span class="pill pill--warn"><i class="dot"></i>${ctx.esc(value)}</span>`;
}

function errorScreen(ctx, err) {
  const message = ctx.esc(err && err.message ? err.message : "Could not load scoped memory.");
  return `<div class="head"><div><div class="eyebrow">Govern</div><h1>Scope Memory</h1></div></div>
    <div class="card"><div class="sub">Something went wrong.</div><p>${message}</p></div>`;
}

// ---------------------------------------------------------------------------
// Actions.
// ---------------------------------------------------------------------------

/**
 * Apply `ledgerSearch` to the rendered ledger in place: hide non-matching
 * rows, keep the filter-bar tail and the footer telling the same story, and
 * toggle the no-match state. Shared by the keystroke action, its clear
 * button, and nothing else — the render pass produces identical output from
 * the same state, so a re-render and an in-place pass can never disagree.
 */
function applyLedgerSearch(root) {
  const query = ledgerSearch.trim().toLowerCase();
  const rows = root.querySelectorAll("[data-badge-row]");
  let shown = 0;
  for (const row of rows) {
    const hit = !query || String(row.getAttribute("data-search") || "").includes(query);
    row.hidden = !hit;
    if (hit) shown += 1;
  }
  const none = root.querySelector("[data-ledger-nomatch]");
  if (none) none.hidden = !(query && shown === 0 && rows.length > 0);
  const count = root.querySelector("[data-ledger-count]");
  if (count) {
    const total = Number(count.getAttribute("data-ledger-total")) || rows.length;
    count.textContent = `Showing ${shown} of ${total} ${total === 1 ? "badge" : "badges"}`;
  }
  const result = root.querySelector("[data-ledger-result]");
  if (result) result.textContent = `${shown}${shown === 1 ? " badge" : " badges"}`;
}

export const actions = {
  async "badge-team-change"(ctx, el) {
    draft.namespace = String(el && el.value || "");
    draft.recipientUserId = "";
    draft.idempotencyKey = "";
    if (typeof document === "undefined") return;
    const root = (el && el.closest && el.closest(".screen")) || document;
    const recipient = root.querySelector && root.querySelector("#badge-recipient");
    if (!recipient || typeof recipient.replaceChildren !== "function") return;
    const self = document.createElement("option");
    self.value = "";
    self.textContent = "I'll connect it myself";
    const options = [self];
    for (const member of assignableRecipients.get(draft.namespace) || []) {
      const option = document.createElement("option");
      option.value = String(member.userId || "");
      option.textContent = String(member.displayName || "Member");
      options.push(option);
    }
    recipient.replaceChildren(...options);
  },
  async "badge-create"(ctx, el) {
    const root = (el && el.closest && el.closest(".screen")) || (typeof document === "undefined" ? null : document);
    readDraft(root);
    if (!draft.actor) {
      draftError = "Give the badge a name.";
      return ctx.go("s3");
    }
    if (!draft.namespace) {
      draftError = "Choose the team this badge is scoped to.";
      return ctx.go("s3");
    }
    const status = root && root.querySelector ? root.querySelector("#badge-status") : null;
    setBusy(el, true, "Creating…");
    setText(status, "Creating the scoped badge…");
    try {
      if (draft.recipientUserId && !draft.idempotencyKey) {
        draft.idempotencyKey = newIdempotencyKey();
      }
      const body = {
        type: "assistant",
        actor: draft.actor,
        namespace: draft.namespace,
        agentAccessLevel: draft.level === "manager" ? "manager" : "member",
        agentCanWrite: draft.memoryAccess !== "read",
        ...(draft.recipientUserId ? {
          recipientUserId: draft.recipientUserId,
          idempotencyKey: draft.idempotencyKey,
        } : {}),
        ...(expiryIso(draft.lifetime) ? { expiresAt: expiryIso(draft.lifetime) } : {}),
      };
      const response = await ctx.api.post("/v1/admin/keys", body);
      if (response && response.handoff) {
        issued = {
          delegated: true,
          handoffId: response.handoff.id || "",
          actor: response.handoff.actor || draft.actor,
          recipientLabel: response.handoff.recipientLabel || "the member",
        };
        scheduleIssuedClear();
        draft = { ...EMPTY_DRAFT };
        draftError = "";
        await ctx.go("s3");
        return;
      }
      if (!response || !response.plaintext) throw new Error("server returned no key");
      const record = response.record || {};
      issued = {
        plaintext: response.plaintext,
        actor: record.actor || draft.actor,
        namespace: record.namespace || draft.namespace,
        level: record.agentAccessLevel || draft.level,
        canWrite: record.agentCanWrite !== false,
        expiresAt: record.expiresAt || null,
        revealed: false,
      };
      scheduleIssuedClear();
      draft = { ...EMPTY_DRAFT };
      draftError = "";
      await ctx.go("s3");
    } catch (err) {
      draftError = "Could not create the badge: " + msgOf(err);
      setBusy(el, false, "Create scoped badge");
      await ctx.go("s3");
    }
  },

  async "badge-key-copy"(ctx, el) {
    const root = (el && el.closest && el.closest(".screen")) || document;
    const status = root.querySelector("#badge-copy-status");
    const node = root.querySelector("[data-issued-key]");
    try {
      await copyText(issued ? issued.plaintext || "" : "", node);
      setText(status, "Key copied.");
      return true;
    } catch {
      setText(status, "Copy failed. Select it manually.");
      return false;
    }
  },

  "badge-key-visibility"(ctx, el) {
    if (!issued || issued.delegated) return;
    issued.revealed = issued.revealed !== true;
    const root = (el && el.closest && el.closest(".screen")) || document;
    const node = root.querySelector("[data-issued-key]");
    if (node) {
      node.textContent = issued.revealed ? issued.plaintext || "" : BEARER_MASK;
      node.setAttribute("aria-label", "Bearer token " + (issued.revealed ? "revealed" : "hidden"));
    }
    el.textContent = issued.revealed ? "Hide bearer" : "Reveal bearer";
    el.setAttribute("aria-pressed", String(issued.revealed));
  },

  async "key-reveal"(ctx, el) {
    const id = (el && el.getAttribute("data-id")) || "";
    if (!id) return;
    const root = (el && el.closest && el.closest(".screen")) || document;
    const status = root.querySelector("#key-status");
    setBusy(el, true, "Revealing…");
    try {
      const response = await ctx.api.post(
        "/v1/admin/keys/" + encodeURIComponent(id) + "/reveal",
        {},
      );
      if (!response || !response.plaintext) throw new Error("server returned no key");
      const record = response.record || {};
      issued = {
        plaintext: response.plaintext,
        actor: record.actor || "Agent",
        namespace: record.namespace || "",
        level: record.agentAccessLevel || "member",
        canWrite: record.agentCanWrite !== false,
        expiresAt: record.expiresAt || null,
        revealed: true,
      };
      scheduleIssuedClear();
      const body = root.querySelector("[data-scope-access-body]");
      if (body) body.innerHTML = issuedPanel(ctx);
      setBusy(el, false, "Reveal bearer");
    } catch (err) {
      setText(status, "Reveal failed: " + msgOf(err));
      setBusy(el, false, "Reveal bearer");
    }
  },

  async "badge-issued-dismiss"(ctx) {
    clearIssued();
    await ctx.go("s3");
  },

  async "badge-filter"(ctx, el) {
    ledgerFilter = (el && el.getAttribute("data-filter")) || "active";
    await ctx.go("s3");
  },

  /**
   * Narrow the ledger without a re-render. `app.js` refresh replaces the
   * stage's innerHTML, which would drop focus and the caret on every
   * keystroke, so this hides rows in place and repaints only the counts.
   */
  "badge-search"(ctx, el) {
    const root = (el && el.closest && el.closest(".sm-card")) || null;
    if (!root) return;
    ledgerSearch = String((el && el.value) || "");
    applyLedgerSearch(root);
  },

  /** The no-match state's way out: clear the query, show every row again. */
  "badge-search-clear"(ctx, el) {
    const root = (el && el.closest && el.closest(".sm-card")) || null;
    if (!root) return;
    ledgerSearch = "";
    const input = root.querySelector('[data-input-action="badge-search"]');
    if (input) input.value = "";
    applyLedgerSearch(root);
  },

  async "badge-expand"(ctx, el) {
    const id = (el && el.getAttribute("data-id")) || "";
    if (!id) return;
    selectedBadgeId = id;
    await refreshBadgePanel(ctx, id, el);
  },

  "badge-panel-close"() {
    selectedBadgeId = "";
    sourceFormKeyId = "";
    if (typeof document !== "undefined") closeRightPanel(document);
  },

  async "agent-source-open"(ctx, el) {
    sourceFormKeyId = el.getAttribute("data-id") || "";
    if (sourceFormKeyId) selectedBadgeId = sourceFormKeyId;
    await refreshBadgePanel(ctx, selectedBadgeId, el);
  },
  async "agent-source-cancel"(ctx) {
    sourceFormKeyId = "";
    await refreshBadgePanel(ctx, selectedBadgeId);
  },

  async "agent-source-submit"(ctx, el) {
    const root = el.closest(".screen") || document;
    const keyId = el.getAttribute("data-id") || "";
    const status = root.querySelector("[data-source-status]");
    let payload;
    try {
      payload = readSourcePayload(root, keyId);
    } catch (err) {
      return setText(status, msgOf(err));
    }
    setBusy(el, true, "Granting…");
    try {
      await ctx.api.post("/v1/admin/agent-connections", payload);
      sourceFormKeyId = "";
      await ctx.go("s3");
    } catch (err) {
      setText(status, "Could not grant: " + msgOf(err));
      setBusy(el, false, "Grant source access");
    }
  },

  async "badge-revoke"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    setBusy(el, true, "Revoking…");
    try { await ctx.api.del("/v1/admin/keys/" + encodeURIComponent(id)); await ctx.go("s3"); }
    catch { setBusy(el, false, "Revoke"); }
  },

  async "key-rotate"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#key-status");
    setBusy(el, true, "Rotating…");
    try {
      const response = await ctx.api.post("/v1/admin/keys/" + encodeURIComponent(id) + "/rotate", {});
      if (!response || !response.plaintext) throw new Error("server returned no key");
      const record = response.record || {};
      issued = {
        plaintext: response.plaintext,
        actor: record.actor || "",
        namespace: record.namespace || "",
        level: record.agentAccessLevel || "member",
        canWrite: record.agentCanWrite !== false,
        expiresAt: record.expiresAt || null,
        revealed: false,
      };
      scheduleIssuedClear();
      await ctx.go("s3");
    } catch (err) {
      setText(status, "Rotate failed: " + msgOf(err));
      setBusy(el, false, "Rotate");
    }
  },

  async "key-revoke"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#key-status");
    setBusy(el, true, "Revoking…");
    try { await ctx.api.del("/v1/admin/keys/" + encodeURIComponent(id)); await ctx.go("s3"); }
    catch (err) {
      setText(status, "Revoke failed: " + msgOf(err));
      setBusy(el, false, "Revoke");
    }
  },

  async "handoff-revoke"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#key-status");
    setBusy(el, true, "Revoking…");
    try {
      await ctx.api.del("/v1/admin/key-handoffs/" + encodeURIComponent(id));
      if (issued && issued.handoffId === id) clearIssued();
      await ctx.go("s3");
    } catch (err) {
      setText(status, "Revoke failed: " + msgOf(err));
      setBusy(el, false, "Revoke");
    }
  },
};

async function refreshBadgePanel(ctx, id, fallbackOpener = null) {
  if (typeof ctx.refresh === "function") await ctx.refresh();
  else await ctx.go("s3");
  if (typeof document === "undefined") return;
  const panel = document.getElementById("badge-detail-panel");
  const opener = document.querySelector(`[data-action="badge-expand"][data-id="${cssEscape(id)}"]`) || fallbackOpener;
  openRightPanel(panel, opener);
}

export function cleanup() {
  if (typeof document !== "undefined") closeRightPanel(document);
}

/**
 * Pull whatever the operator has typed into the module-level draft. A failed
 * create repaints the card, so anything not captured here is lost - this runs
 * before the POST.
 */
function readDraft(root) {
  if (!root || !root.querySelector) return;
  if (root.querySelector("#badge-name")) draft.actor = value(root, "#badge-name");
  const team = root.querySelector("#badge-team");
  if (team) {
    // The readonly member field displays the short team label, so its posted
    // namespace rides on data-namespace. A select's value already IS the
    // namespace; so is the free-text field a team-less tenant gets.
    const pinned = team.getAttribute ? team.getAttribute("data-namespace") : null;
    draft.namespace = pinned ? String(pinned).trim() : value(root, "#badge-team");
  }
  const access = root.querySelector("#badge-access");
  if (access) draft.memoryAccess = String(access.value || "readwrite");
  const level = root.querySelector("#badge-level");
  if (level && level.tagName !== "INPUT") draft.level = String(level.value || "member");
  const lifetime = root.querySelector("#badge-expiry");
  if (lifetime) draft.lifetime = String(lifetime.value || "");
  const recipient = root.querySelector("#badge-recipient");
  if (recipient && recipient.tagName !== "INPUT") {
    const recipientUserId = String(recipient.value || "");
    if (recipientUserId !== draft.recipientUserId) draft.idempotencyKey = "";
    draft.recipientUserId = recipientUserId;
  }
}

function newIdempotencyKey() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `handoff-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** Days-from-now as an ISO instant; "" means standing access. */
function expiryIso(lifetime) {
  const days = Number(lifetime);
  if (!lifetime || !Number.isFinite(days) || days <= 0) return null;
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

function readSourcePayload(root, keyId) {
  const connectorId = value(root, `#src-connector-${cssEscape(keyId)}`);
  const allowedSourceRefs = commaList(value(root, `#src-refs-${cssEscape(keyId)}`));
  const allowedFields = parseFields(value(root, `#src-fields-${cssEscape(keyId)}`));
  const allowedPurposes = commaList(value(root, `#src-purposes-${cssEscape(keyId)}`));
  if (!connectorId) throw new Error("Choose a connected source.");
  if (!allowedSourceRefs.length) throw new Error("Name at least one table.");
  if (allowedSourceRefs.some((source) => !allowedFields[source] || !allowedFields[source].length)) {
    throw new Error("Add allowed columns for every table.");
  }
  if (!allowedPurposes.length) throw new Error("Add at least one allowed reason.");
  const rate = boundedNumber(root, `#src-rate-${cssEscape(keyId)}`, 1, 10000);
  return {
    keyId,
    connectorId,
    allowedOperations: ["source-read"],
    allowedSourceRefs,
    allowedFields,
    allowedPurposes,
    maxSensitivity: value(root, `#src-sensitivity-${cssEscape(keyId)}`) || "confidential",
    maxRows: boundedNumber(root, `#src-rows-${cssEscape(keyId)}`, 1, 1000),
    maxBytes: Math.round(boundedNumber(root, `#src-mb-${cssEscape(keyId)}`, 0.01, 10) * 1024 * 1024),
    expiresAt: null,
    oversight: {
      maxRequestsPerMinute: rate,
      usageAlertThreshold: 100,
      deniedAlertThreshold: 1,
      recipientRoles: ["owner", "admin"],
      accessRequests: "allowed",
      approvalTtlSeconds: 3600,
    },
  };
}

/** ULIDs are alphanumeric, so this only guards against a malformed id. */
function cssEscape(value) {
  return String(value || "").replace(/[^A-Za-z0-9_-]/g, "");
}

function parseFields(raw) {
  const result = {};
  for (const line of String(raw || "").split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator < 1) continue;
    const source = line.slice(0, separator).trim();
    const fields = commaList(line.slice(separator + 1));
    if (source && fields.length) result[source] = fields;
  }
  return result;
}

function value(root, selector) {
  const input = root && root.querySelector ? root.querySelector(selector) : null;
  return input && input.value != null ? String(input.value).trim() : "";
}
function commaList(raw) { return [...new Set(String(raw || "").split(",").map((part) => part.trim()).filter(Boolean))]; }
function boundedNumber(root, selector, min, max) {
  const parsed = Number(value(root, selector));
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) throw new Error("Check the numeric limits and try again.");
  return parsed;
}

function scheduleIssuedClear() {
  if (issuedTimer) clearTimeout(issuedTimer);
  issuedTimer = setTimeout(() => {
    issued = null;
    issuedTimer = null;
  }, 60_000);
  if (issuedTimer && typeof issuedTimer.unref === "function") issuedTimer.unref();
}
function clearIssued() {
  issued = null;
  if (issuedTimer) clearTimeout(issuedTimer);
  issuedTimer = null;
}

async function copyText(text, node) {
  if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  if (!node) throw new Error("clipboard unavailable");
  const range = document.createRange(); range.selectNodeContents(node);
  const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
  document.execCommand("copy"); selection.removeAllRanges();
}
function setBusy(el, busy, label) { if (!el) return; el.disabled = busy; if (label && "textContent" in el) el.textContent = label; }
function setText(node, text) { if (node) node.textContent = text; }
function msgOf(err) { return err && err.message ? err.message : "unknown error"; }
function formatBytes(value) { const bytes = Number(value) || 0; if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(bytes % 1048576 ? 1 : 0)} MB`; if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`; return `${bytes} B`; }
/** Date only - the ledger has 100px for it, and a badge's lifetime is in days. */
function formatDay(value) { const time = Date.parse(String(value || "")); if (!Number.isFinite(time)) return String(value || "Unknown"); return new Date(time).toLocaleDateString("en-US", { dateStyle: "medium" }); }
/**
 * api_keys.last_used, compressed to fit a 90px column: it is bumped on every
 * bearer-key resolution, so it doubles as "last connected". `Never` for a
 * credential no client has presented yet.
 */
function lastSeenShort(value) {
  const time = Date.parse(String(value || ""));
  if (!Number.isFinite(time)) return "Never";
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDay(value);
}
import { headingInfo } from "../heading-info.js";
