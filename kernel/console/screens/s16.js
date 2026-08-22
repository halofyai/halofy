import { personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";

/**
 * S16: Skills. The deduped company-wide skill library: what exists across
 * every team (ancestor-prefix namespace), its public safety score, risk band
 * and approval state, which agents use it, and the governance actions.
 *
 * Governance model:
 *  - Anyone (owner/admin/member) can SUBMIT a skill file; member submissions
 *    land as `pending` and are blocked from agent use until an owner/admin
 *    over that team namespace approves (audited). Owner/admin submissions are
 *    auto-approved.
 *  - The monitoring strip classifies every visible skill good / risky /
 *    critical from its vetting state (server-computed `riskBand`).
 *  - A skill is distributable (download / add-to-integrations) only when it is
 *    approved AND vetted; the server enforces the same gate on the download
 *    route, and the console merely hides the buttons otherwise.
 *  - Unvetted or failed-vetting skills remain blocked from agent use unless an
 *    audited admin override exists, granted here with a reason.
 *
 * Layout: a compact safety strip on top, then one roomy library TABLE with
 * summary columns only (skill, status, usage, sharing). Owner/admin rows open a
 * modal detail view: per-lane check verdicts with icons, structured findings,
 * and collapsed sections for instructions, check history, agents, versions,
 * and activity. Pending submissions carry an inline Approve action; rejection
 * (reason required) lives in the modal detail view.
 *
 * Copy is plain language for non-technical readers. No em dashes anywhere.
 *
 * Pure string renderer. Every API-derived value goes through ctx.esc(),
 * including data-* attributes. No inline JS; delegated actions only.
 */

let selectedSkillId = null;
let showRegisterForm = false;
let editingSkillId = null;
let editingLabelsId = null;
let bandFilter = "all"; // "all" | "good" | "risky" | "critical"
let approvalFilter = "all"; // "all" | "pending"
let searchQuery = "";
let filtersOpen = false;
let categoryFilter = "all";
let teamFilters = [];
let tagFilters = [];
let usedByFilter = "all";
let addedByFilter = "all";
let unusedOnly = false;
let libraryPage = 0;
const SKILL_PAGE_SIZE = 8;
const MAX_SKILL_FILE_BYTES = 256_000;
const MAX_SKILL_DEFINITION_CHARS = 200_000;

const SKILL_CATEGORIES = [
  "Research & Analysis",
  "Content & Drafting",
  "Engineering & Code",
  "Workflow Automation",
  "Governance & Compliance",
  "Customer & Revenue Ops",
  "Memory Operations",
  "Retrieval Engines",
  "Data Import & Connectors",
  "Agent Setup & Clients",
  "Deployment & Storage",
  "Reporting & Delivery",
];

const FALLBACK_LABELS = {
  category: "Workflow Automation",
  purpose: "Use this skill to complete its documented workflow.",
  tags: ["workflow", "automation", "skill"],
  handling: [],
};

function labelsFor(skill) {
  const labels = skill?.labels && typeof skill.labels === "object" ? skill.labels : FALLBACK_LABELS;
  return {
    category: String(labels.category || FALLBACK_LABELS.category),
    purpose: String(labels.purpose || skill?.description || FALLBACK_LABELS.purpose),
    tags: Array.isArray(labels.tags) ? labels.tags.map(String).filter(Boolean) : FALLBACK_LABELS.tags,
    handling: Array.isArray(labels.handling) ? labels.handling.map(String).filter(Boolean) : [],
  };
}

function allSkillTags(skill) {
  const labels = labelsFor(skill);
  return [...labels.tags, ...labels.handling];
}

function skillMatches(skill, omitted = "") {
  const labels = labelsFor(skill);
  const namespace = String(skill?.namespace ?? "");
  const usage = skill?.usage || {};
  const query = searchQuery.trim().toLowerCase();
  if (omitted !== "search" && query) {
    const haystack = [skill?.name, skill?.skillKey, skill?.description, namespace, labels.category, labels.purpose, ...labels.tags, ...labels.handling]
      .map((value) => String(value ?? "").toLowerCase()).join(" ");
    if (!haystack.includes(query)) return false;
  }
  if (omitted !== "category" && categoryFilter !== "all" && labels.category !== categoryFilter) return false;
  if (omitted !== "teams" && teamFilters.length > 0 && !teamFilters.includes(namespace)) return false;
  if (omitted !== "tags" && tagFilters.some((tag) => !allSkillTags(skill).includes(tag))) return false;
  if (omitted !== "usedBy" && usedByFilter !== "all") {
    const actors = Array.isArray(usage.agentActors) ? usage.agentActors.map(String) : [];
    if (!actors.includes(usedByFilter)) return false;
  }
  if (omitted !== "addedBy" && addedByFilter !== "all" && String(skill?.createdBy ?? "") !== addedByFilter) return false;
  if (omitted !== "unused" && unusedOnly && Number(usage.agents ?? 0) !== 0) return false;
  if (omitted !== "band" && bandFilter !== "all" && skill?.riskBand !== bandFilter) return false;
  if (omitted !== "approval" && approvalFilter !== "all" && skill?.approvalStatus !== "pending") return false;
  return true;
}

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

/** Distributable = approved AND vetted (mirrors the server-side export gate). */
function isDistributable(skill) {
  return (
    skill &&
    skill.approvalStatus === "approved" &&
    skill.vettingStatus === "vetted" &&
    skill.status === "active" &&
    !skill.tValidTo
  );
}

export async function render(ctx) {
  const { esc } = ctx;
  const mutate = canMutate(ctx);
  let skills = [];
  let lastSweptAt = null;
  let teamDirectory = [];
  try {
    const rows = await ctx.api.get(mutate ? "/v1/admin/skills" : "/v1/skills");
    skills = Array.isArray(rows) ? rows : Array.isArray(rows && rows.skills) ? rows.skills : [];
    lastSweptAt = rows && !Array.isArray(rows) && rows.lastSweptAt ? String(rows.lastSweptAt) : null;
  } catch (err) {
    return `<div class="card"><h3>Skills unavailable</h3><div class="sub">${esc(err?.message ?? "Unable to load the skill library")}</div></div>`;
  }

  if (mutate && showRegisterForm) {
    try {
      const rows = await ctx.api.get("/v1/admin/teams");
      teamDirectory = Array.isArray(rows) ? rows : [];
    } catch {
      teamDirectory = [];
    }
  }

  if (selectedSkillId && !skills.some((skill) => skill.id === selectedSkillId)) selectedSkillId = null;

  const pending = skills.filter((s) => s.approvalStatus === "pending");
  if (approvalFilter === "pending" && pending.length === 0) approvalFilter = "all";
  const teams = [...new Set(skills.map((s) => String(s.namespace ?? "")))].sort();
  teamFilters = teamFilters.filter((team) => teams.includes(team));
  const visible = skills.filter((skill) => skillMatches(skill));

  const acts = `<button class="btn btn--solid btn--sm" data-action="skill-new" aria-controls="skill-register-panel" aria-haspopup="dialog" aria-expanded="false">Add skill</button>`;
  const pendingPill = pending.length === 0
    ? ""
    : mutate
      ? `<button class="pill pill--warn skill-pending-btn${approvalFilter === "pending" ? " is-active" : ""}" data-action="skill-approval"
          aria-pressed="${approvalFilter === "pending" ? "true" : "false"}"
          title="Show only skills waiting for approval"><i class="dot"></i>${pending.length} pending review</button>`
      : `<span class="pill pill--warn"><i class="dot"></i>${pending.length} pending</span>`;

  const organization = String(ctx.identity?.namespace ?? "").split("/")[0] || "Organization";
  return `<div class="skills-screen screen-flow">
    <div class="head skills-head"><div><div class="eyebrow">Operate · ${esc(organization)}</div><h1>Skills${headingInfo("Skills", "Every skill your teams have added, with its checks and usage.")}</h1></div>
      <div class="acts">${pendingPill}${acts}</div></div>
    ${mutate ? "" : '<aside class="skill-member-note"><div class="eyebrow">Your access</div><b>Admin review required</b></aside>'}
    ${monitoringStrip(ctx, skills, lastSweptAt)}
    ${libraryList(ctx, visible, skills, teams)}
    <div id="skill-modal" class="source-wizard-overlay" hidden aria-hidden="true"></div>
    ${rightPanelHtml({ id: "skill-register-panel", eyebrow: "Skills", title: mutate ? "Add a skill" : "Submit a skill", closeAction: "skill-register-close", className: "skill-register-drawer", body: showRegisterForm ? registerForm(ctx, mutate, teamDirectory) : '<div class="sub">Upload a skill file or type the instructions.</div>' })}</div>`;
}

export function breadcrumbs() {
  return [];
}

export function onBreadcrumbBack() {
  selectedSkillId = null;
}

// ---------------------------------------------------------------------------
// Safety strip: the security overview (good / risky / critical)
// ---------------------------------------------------------------------------

// `hint` is the full sentence a screen reader hears; `sub` is the short line
// printed under the title. The card doubles as the band filter, so the printed
// line says what the band MEANS, and the pressed state says it is filtering.
const BANDS = [
  {
    id: "good",
    label: "Passed checks",
    sub: "Agents can use these",
    hint: "All security checks passed.",
  },
  {
    id: "risky",
    label: "Checks pending",
    sub: "Blocked until checks finish",
    hint: "Checks have not run yet or are still running. Agents cannot use these skills.",
  },
  {
    id: "critical",
    label: "Action required",
    sub: "Blocked until someone fixes it",
    hint: "A check failed. Agents cannot use these skills.",
  },
];

function bandIcon(id) {
  if (id === "good") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 6 9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  }
  if (id === "critical") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 9v4m0 4h.01M10.3 3.7 2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.7a2 2 0 0 0-3.4 0Z" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 8v5m0 4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function monitoringStrip(ctx, skills, lastSweptAt) {
  const counts = { good: 0, risky: 0, critical: 0 };
  for (const s of skills) {
    if (s.riskBand === "good" || s.riskBand === "critical") counts[s.riskBand] += 1;
    else counts.risky += 1;
  }
  const cards = BANDS.map((b) => {
    const on = bandFilter === b.id;
    const count = counts[b.id];
    return `<button class="skill-risk-card skill-risk-card--${b.id}${on ? " is-active" : ""}" data-action="skill-band" data-band="${b.id}"
        aria-pressed="${on ? "true" : "false"}" aria-label="${ctx.esc(`${RISK_LABELS[b.id]}: ${count} ${count === 1 ? "skill" : "skills"}. ${b.hint} Select to filter the library.`)}">
      <span class="skill-risk-icon">${bandIcon(b.id)}</span>
      <span class="skill-risk-copy"><span class="skill-risk-title">${ctx.esc(b.label)}</span>
        <span class="skill-risk-state">${on ? "Filtering the library" : ctx.esc(b.sub)}</span></span>
      <span class="skill-risk-count num">${count}<small>${count === 1 ? "skill" : "skills"}</small></span>
    </button>`;
  }).join("");
  const clear = bandFilter === "all"
    ? ""
    : `<button class="btn btn--ghost btn--sm" data-action="skill-band" data-band="all">Show all skills</button>`;
  const swept = lastSweptAt
    ? ` Last full scan ${ctx.esc(shortTs(lastSweptAt))} · runs monthly.`
    : "";
  const guide = `<p class="skill-security-guide"><strong>How checks work.</strong> Every skill is checked before agents can use it.${swept}</p>`;
  return `<section class="skill-security" aria-labelledby="skill-security-title">
    <div class="skill-section-head"><div><div class="eyebrow">Security posture</div>
      <h2 id="skill-security-title">Safety checks</h2>
      ${guide}</div>${clear}</div>
    <div class="skill-risk-grid">${cards}</div>
  </section>`;
}

// ---------------------------------------------------------------------------
// Library table: one column per concern; owner/admin rows expand in place
// ---------------------------------------------------------------------------

const RISK_LABELS = { good: "Good", risky: "Risky", critical: "Critical" };

// Seeded product defaults are marked server-side by this actor (no schema
// flag); the badge is derived, never stored. Static markup — nothing to esc.
const DEFAULT_SKILL_ACTOR = "system-default-skills";

function defaultBadge(skill) {
  return String(skill?.createdBy ?? "") === DEFAULT_SKILL_ACTOR
    ? '<span class="pill" title="Ships with Halofy as a curated default">Default</span>'
    : "";
}

function riskBadge(ctx, skill) {
  const band = RISK_LABELS[skill?.riskBand] ? skill.riskBand : "risky";
  const tone = band === "good" ? "pill--ok" : band === "critical" ? "pill--crit" : "pill--warn";
  return `<span class="pill ${tone}" title="Safety level"><i class="dot"></i>${ctx.esc(RISK_LABELS[band])}</span>`;
}

function readinessBadge(ctx, skill) {
  const archived = skill?.status === "archived" || skill?.tValidTo;
  if (archived) return '<span class="pill">Retired</span>';
  const ready = isDistributable(skill);
  const checking = skill?.vettingStatus === "vetting";
  const reason = skill?.approvalStatus === "pending"
    ? "Pending approval"
    : skill?.approvalStatus === "rejected"
      ? "Rejected"
      : skill?.vettingStatus === "blocked"
        ? "Checks failed"
        : skill?.vettingStatus !== "vetted"
          ? "Checks pending"
          : "Approved and checked";
  const label = ready ? "Good to go" : checking ? "Checking" : "Not ready";
  const tone = ready ? "pill--ok" : skill?.vettingStatus === "blocked" || skill?.approvalStatus === "rejected" ? "pill--crit" : "pill--warn";
  return `<span class="pill ${tone}" aria-label="${ctx.esc(`${label}: ${reason}`)}" title="${ctx.esc(reason)}">${ctx.esc(label)}</span>`;
}

function distributeButtons(ctx, skill) {
  if (!isDistributable(skill)) {
    return '<span class="skill-lock-note" aria-label="Available once approved and checked" title="Available once approved and checked"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3.25" y="7" width="9.5" height="7" rx="2"/><path d="M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7" stroke-linecap="round"/></svg>Locked</span>';
  }
  const id = ctx.esc(String(skill.id ?? ""));
  return `<div class="skill-distribute-actions">
    <button class="btn btn--outline btn--sm" data-action="skill-download" data-id="${id}">Download</button>
    <button class="btn btn--outline btn--sm" data-action="skill-integrations"
      data-id="${id}" data-key="${ctx.esc(String(skill.skillKey ?? ""))}"
      data-name="${ctx.esc(String(skill.name ?? ""))}" aria-label="Install ${ctx.esc(String(skill.name ?? ""))} in an agent client">Install</button></div>`;
}

/** The slug a name would produce, used only to spot a key that adds nothing. */
function slugOf(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

const CHEVRON_SVG = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="m6 3 5 5-5 5" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function activeFilterCount() {
  return (categoryFilter !== "all" ? 1 : 0) + teamFilters.length + tagFilters.length +
    (usedByFilter !== "all" ? 1 : 0) + (addedByFilter !== "all" ? 1 : 0) +
    (unusedOnly ? 1 : 0) + (approvalFilter !== "all" ? 1 : 0) + (bandFilter !== "all" ? 1 : 0);
}

function libraryReadinessBadge(ctx, skill) {
  const archived = skill?.status === "archived" || skill?.tValidTo;
  if (archived) return '<span class="skill-library-status">Retired</span>';
  const ready = isDistributable(skill);
  const checking = skill?.vettingStatus === "vetting";
  const reason = skill?.approvalStatus === "pending"
    ? "Pending approval"
    : skill?.approvalStatus === "rejected"
      ? "Rejected"
      : skill?.vettingStatus === "blocked"
        ? "Checks failed"
        : skill?.vettingStatus !== "vetted"
          ? "Checks pending"
          : "Approved and checked";
  const label = ready ? "Good To Go" : checking ? "Checking" : "Not Ready";
  const tone = ready ? "good" : skill?.vettingStatus === "blocked" || skill?.approvalStatus === "rejected" ? "critical" : "pending";
  return `<span class="skill-library-status skill-library-status--${tone}" aria-label="${ctx.esc(`${label}: ${reason}`)}" title="${ctx.esc(reason)}">${ctx.esc(label)}</span>`;
}

function filterPopover(ctx, allSkills, teams) {
  const { esc } = ctx;
  const categoryRows = SKILL_CATEGORIES.map((category) => {
    const count = allSkills.filter((skill) => skillMatches(skill, "category") && labelsFor(skill).category === category).length;
    return `<button class="skill-filter-option${categoryFilter === category ? " is-active" : ""}" data-action="skill-filter-category" data-category="${esc(category)}" aria-pressed="${categoryFilter === category}"><span>${esc(category)}</span><b>${count}</b></button>`;
  }).join("");
  const teamRows = teams.map((team) => {
    const count = allSkills.filter((skill) => skillMatches(skill, "teams") && String(skill.namespace ?? "") === team).length;
    return `<label class="skill-filter-check"><input type="checkbox" data-change-action="skill-filter-team" data-team="${esc(team)}"${teamFilters.includes(team) ? " checked" : ""}><span>${esc(team || "Organization root")}</span><b>${count}</b></label>`;
  }).join("");
  const tagNames = [...new Set(allSkills.flatMap(allSkillTags))].sort((a, b) => a.localeCompare(b));
  const tagRows = tagNames.map((tag) => {
    const count = allSkills.filter((skill) => skillMatches(skill, "tags") && allSkillTags(skill).includes(tag)).length;
    return `<label class="skill-filter-check"><input type="checkbox" data-change-action="skill-filter-tag" data-tag="${esc(tag)}"${tagFilters.includes(tag) ? " checked" : ""}><span>${esc(tag)}</span><b>${count}</b></label>`;
  }).join("");
  const agents = [...new Set(allSkills.flatMap((skill) => Array.isArray(skill?.usage?.agentActors) ? skill.usage.agentActors.map(String) : []))].sort();
  const adders = [...new Set(allSkills.map((skill) => String(skill.createdBy ?? "")).filter(Boolean))].sort();
  return `<div class="skill-filter-panel"${filtersOpen ? "" : " hidden"} role="region" aria-label="Skill filters">
    <section class="skill-filter-section skill-filter-section--category"><div class="skill-filter-title"><b>Category</b><button class="btn btn--ghost btn--sm" data-action="skill-filter-category" data-category="all">Any</button></div><div class="skill-filter-options-grid">${categoryRows}</div></section>
    <section class="skill-filter-section"><div class="skill-filter-title"><b>Team</b></div><div class="skill-filter-scroll">${teamRows || '<span class="subtle">No teams available</span>'}</div></section>
    <section class="skill-filter-section"><div class="skill-filter-title"><b>Tags</b></div><div class="skill-filter-scroll">${tagRows || '<span class="subtle">No tags available</span>'}</div></section>
    <section class="skill-filter-section skill-filter-advanced"><div class="skill-filter-selects"><label>Used by<select class="select" data-input-action="skill-filter-used-by"><option value="all">Any agent</option>${agents.map((agent) => `<option value="${esc(agent)}"${usedByFilter === agent ? " selected" : ""}>${esc(agent)}</option>`).join("")}</select></label>
      <label>Added by<select class="select" data-input-action="skill-filter-added-by"><option value="all">Anyone</option>${adders.map((actor) => `<option value="${esc(actor)}"${addedByFilter === actor ? " selected" : ""}>${esc(personDisplayName(actor, ctx.personLabel, "human"))}</option>`).join("")}</select></label></div>
      <label class="skill-filter-check skill-filter-unused"><input type="checkbox" data-change-action="skill-filter-unused"${unusedOnly ? " checked" : ""}><span>Unused by agents</span></label></section>
    <footer class="skill-filter-panel-footer"><button class="btn btn--ghost btn--sm" data-action="skill-manage-tags">Manage tags</button><button class="btn btn--outline btn--sm" data-action="skill-filters-clear">Clear all</button></footer>
  </div>`;
}

function activeFilterChips(ctx) {
  const chips = [];
  if (categoryFilter !== "all") chips.push(["category", categoryFilter, `Category: ${categoryFilter}`]);
  for (const team of teamFilters) chips.push(["team", team, `Team: ${team || "Organization root"}`]);
  for (const tag of tagFilters) chips.push(["tag", tag, `Tag: ${tag}`]);
  if (usedByFilter !== "all") chips.push(["usedBy", usedByFilter, `Used by: ${usedByFilter}`]);
  if (addedByFilter !== "all") chips.push(["addedBy", addedByFilter, `Added by: ${personDisplayName(addedByFilter, ctx.personLabel, "human")}`]);
  if (unusedOnly) chips.push(["unused", "true", "Unused by agents"]);
  if (approvalFilter !== "all") chips.push(["approval", approvalFilter, "Pending review"]);
  if (bandFilter !== "all") chips.push(["band", bandFilter, `Safety: ${RISK_LABELS[bandFilter]}`]);
  if (chips.length === 0) return "";
  return `<div class="skill-active-filters" aria-label="Active filters">${chips.map(([kind, value, label]) => `<button class="skill-filter-chip" data-action="skill-filter-remove" data-filter-kind="${ctx.esc(kind)}" data-filter-value="${ctx.esc(value)}">${ctx.esc(label)}<span aria-hidden="true">×</span></button>`).join("")}<button class="btn btn--ghost btn--sm" data-action="skill-filters-clear">Clear all</button></div>`;
}

function libraryList(ctx, skills, allSkills, teams) {
  const { esc } = ctx;
  const inspect = canMutate(ctx);
  const pageCount = Math.max(1, Math.ceil(skills.length / SKILL_PAGE_SIZE));
  libraryPage = Math.min(libraryPage, pageCount - 1);
  const pageStart = libraryPage * SKILL_PAGE_SIZE;
  const pageSkills = skills.slice(pageStart, pageStart + SKILL_PAGE_SIZE);
  const rows = pageSkills.map((s) => {
    const usage = s.usage || {};
    const labels = labelsFor(s);
    const namespace = String(s.namespace ?? "");
    const agentCount = Number(usage.agents ?? 0);
    const id = esc(String(s.id ?? ""));
    const name = esc(String(s.name ?? ""));
    const isPending = s.approvalStatus === "pending";
    const hot = labels.handling.some((tag) => tag === "writes-externally" || tag === "credentials-required");
    const shownTags = labels.tags.slice(0, 2);
    const remainingTags = labels.tags.slice(2);
    const tagHtml = shownTags.map((tag) => `<span class="skill-tag">${esc(tag)}</span>`).join("") +
      (remainingTags.length ? `<span class="skill-tag skill-tag--more" title="${esc(remainingTags.join(", "))}">+${remainingTags.length}</span>` : "");
    const nameControl = inspect
      ? `<button class="skill-library-name" data-action="skill-select" data-id="${id}" aria-controls="skill-modal" aria-expanded="false" aria-haspopup="dialog"><span>${name}</span></button>`
      : `<span class="skill-library-name skill-library-name--static"><span>${name}</span></span>`;
    const approvalCell = isPending && inspect ? `<button class="btn btn--primary btn--sm" data-action="skill-approve" data-id="${id}">Approve</button>` : "";
    return `<div class="skill-row skill-row-grid${isPending ? " is-pending" : ""}" role="row">
      <div class="skill-cell-name" role="cell" data-label="Skill"><div class="skill-cell-name-main">${nameControl}${defaultBadge(s)}</div><div class="skill-library-meta">${hot ? '<span class="skill-handling-dot" title="Sensitive handling requirements" aria-label="Sensitive handling requirements"></span>' : ""}<span>v${esc(String(s.version ?? 1))}</span></div></div>
      <div class="skill-cell-category" role="cell" data-label="Category" title="${esc(labels.category)}">${esc(labels.category)}</div>
      <div class="skill-cell-tags" role="cell" data-label="Tags"><div class="skill-tags" title="${esc(labels.tags.join(", "))}">${tagHtml || '<span class="subtle">None</span>'}</div></div>
      <div class="skill-cell-team" role="cell" data-label="Team"><span class="skill-team-name" title="${esc(namespace)}">${esc(namespace || "Organization root")}</span></div>
      <div class="skill-cell-status" role="cell" data-label="Status"><div class="skill-status-cluster">${libraryReadinessBadge(ctx, s)}${approvalCell}</div></div>
      <div class="skill-cell-agents" role="cell" data-label="Agents"><strong class="num" title="${esc(`${usage.invocations ?? 0} uses, ${usage.denials ?? 0} blocked`)}">${esc(String(agentCount))}</strong></div>
      <div class="skill-cell-checked" role="cell" data-label="Last checked"><span class="skill-checked">${s.lastVettedAt ? esc(compactDate(s.lastVettedAt)) : "Never"}</span></div>
      <div class="skill-cell-share" role="cell" data-label="Share">${distributeButtons(ctx, s)}</div>
      <div class="skill-expand-cell" role="cell">${inspect ? `<button class="skill-expand halo-icon-control" data-action="skill-select" data-id="${id}" aria-controls="skill-modal" aria-expanded="false" aria-haspopup="dialog" aria-label="View details for ${name}">${CHEVRON_SVG}</button>` : ""}</div>
    </div>`;
  }).join("");
  const lead = inspect ? "Find, govern, and share every skill your teams have added." : "Find approved skills and install them in an agent client.";
  const count = activeFilterCount();
  const empty = allSkills.length === 0
    ? '<div class="skill-library-empty"><h3>No skills yet.</h3><p>Add one to make it available to your teams.</p></div>'
    : '<div class="skill-library-empty"><h3>No skills match these filters.</h3><p>Clear a filter or try a broader search.</p><button class="btn btn--outline btn--sm" data-action="skill-filters-clear">Clear filters</button></div>';
  const firstShown = skills.length === 0 ? 0 : pageStart + 1;
  const lastShown = pageStart + pageSkills.length;
  const previousDisabled = libraryPage === 0;
  const nextDisabled = libraryPage >= pageCount - 1;
  return `<section class="card skill-library" aria-labelledby="skill-library-title">
    <div class="skill-library-head"><div class="skill-library-title"><h2 id="skill-library-title">Library${headingInfo("Library", lead)}</h2>
      <span class="subtle" data-skill-status role="status" aria-live="polite"></span></div>
      <div class="skill-library-tools"><label class="skill-search"><svg class="skill-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4" stroke-linecap="round"/></svg><span class="sr-only">Search skills</span><input type="search" value="${esc(searchQuery)}" placeholder="Search skills, tags, purpose" autocomplete="off" data-input-action="skill-search"></label>
        <div class="skill-filter-wrap"><button class="skill-filter-button${filtersOpen ? " is-active" : ""}" data-action="skill-filter-toggle" aria-expanded="${filtersOpen}" aria-haspopup="true"><svg class="skill-filter-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2.5 3.25h11l-4.2 4.9v3.5L6.7 13V8.15L2.5 3.25Z" stroke-linejoin="round"/></svg>Filters${count ? `<span class="skill-filter-count">${count}</span>` : ""}</button></div></div></div>
    ${filterPopover(ctx, allSkills, teams)}
    ${activeFilterChips(ctx)}
    ${skills.length === 0 ? empty : `<div class="skill-table-wrap"><div class="skill-table" role="table" aria-label="Skill library">
      <div class="skill-table-head" role="row"><div role="columnheader">Skill</div><div role="columnheader">Category</div><div role="columnheader">Tags</div><div role="columnheader">Team</div><div role="columnheader">Status</div><div role="columnheader">Agents</div><div role="columnheader">Last checked</div><div role="columnheader">Share</div><div role="columnheader" aria-label="Open"></div></div>
      <div class="skill-table-body" role="rowgroup">${rows}</div></div></div>
      <footer class="skill-library-pagination"><span>${firstShown}–${lastShown} of ${skills.length} Skills</span><div><button data-action="skill-page-prev"${previousDisabled ? " disabled" : ""} aria-label="Previous skills page">‹</button><button data-action="skill-page-next"${nextDisabled ? " disabled" : ""} aria-label="Next skills page">›</button></div></footer>`}
  </section>`;
}

// ---------------------------------------------------------------------------
// Add / submit form (all roles; file-first)
// ---------------------------------------------------------------------------

function registerForm(ctx, mutate, teamDirectory = []) {
  const approvalNote = mutate
    ? "Approved right away. Updates must pass the checks again before agents can use them."
    : "A team admin reviews it first. Agents can use it once it is approved and checked.";
  const mode = mutate ? "Auto-approved" : "Needs review";
  const currentScope = String(ctx.identity?.namespace ?? "");
  const teamOptions = teamDirectory
    .map((team) => {
      const name = String(team.name ?? team.namespace ?? "Team");
      const namespace = String(team.namespace ?? "");
      const label = namespace && namespace !== name ? `${name} · ${namespace}` : name;
      return `<option value="${ctx.esc(String(team.id ?? ""))}">${ctx.esc(label)}</option>`;
    })
    .join("");
  const teamField = mutate
    ? `<div class="field skill-register-target"><label for="skill-team">Team <span>Required</span></label>
        <select class="select" id="skill-team" data-skill-team required>
          <option value="__current__">${ctx.esc(currentScope || "Organization root")}</option>${teamOptions}
        </select></div>`
    : "";
  return `<section class="card skill-register" id="skill-form" aria-labelledby="skill-register-title">
    <header class="skill-register-head"><div><div class="eyebrow">New capability</div>
      <h2 id="skill-register-title">Upload a skill file, or type the instructions in</h2></div>
      <span class="pill${mutate ? " pill--ok" : " pill--warn"}"><i class="dot"></i>${mode}</span></header>
    <div class="skill-register-body">
      ${teamField}
      <details class="compact-disclosure skill-register-policy-disclosure">
        <summary><span><b>Publishing policy</b></span></summary>
        <div class="compact-disclosure__body"><aside class="skill-register-policy" aria-label="Publishing policy"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M10 2.5 16 5v4.2c0 3.8-2.5 6.7-6 8.3-3.5-1.6-6-4.5-6-8.3V5l6-2.5Z" stroke-linejoin="round"/><path d="m7.4 10 1.7 1.7 3.6-4" stroke-linecap="round" stroke-linejoin="round"/></svg><span>${approvalNote}</span></aside></div>
      </details>
      <div class="skill-register-block">
        <div class="skill-register-block-head"><div class="eyebrow">Skill file</div><h3>Add from a file</h3></div>
        <div class="skill-file-field">
          <input class="skill-file-input" id="skill-file" type="file" accept=".md,.markdown,.txt" data-input-action="skill-file" aria-describedby="skill-file-help">
          <label class="skill-upload" for="skill-file">
            <span class="skill-upload-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
            <span class="skill-upload-copy"><strong>Browse skill file</strong><small id="skill-file-help">Markdown or plain text · .md, .markdown, .txt</small></span>
            <span class="skill-upload-action" aria-hidden="true">Browse</span>
          </label>
          <div class="skill-file-state"><span class="skill-file-state-dot" aria-hidden="true"></span><span data-skill-file-name aria-live="polite">No file selected</span></div>
        </div>
      </div>
      <div class="skill-register-divider"><span>or type it in</span></div>
      <div class="skill-register-block">
        <div class="skill-register-block-head"><div class="eyebrow">Skill details</div><h3>Check the details</h3></div>
        <div class="skill-register-grid">
          <div class="field"><label for="skill-key">Key <span>Required</span></label>
            <input class="input mono" id="skill-key" data-skill-key placeholder="summarize-ticket" autocomplete="off" required></div>
          <div class="field"><label for="skill-name">Name <span>Required</span></label>
            <input class="input" id="skill-name" data-skill-name placeholder="Summarize ticket" autocomplete="off" required></div>
        </div>
        <div class="field"><label for="skill-desc">Description <span>Optional</span></label>
          <input class="input" id="skill-desc" data-skill-desc placeholder="What this skill helps an agent do" autocomplete="off"></div>
        <div class="field"><label for="skill-purpose">Purpose <span data-skill-purpose-count>0/140</span></label>
          <input class="input" id="skill-purpose" data-skill-purpose data-input-action="skill-purpose" maxlength="140" placeholder="Use when…" autocomplete="off"></div>
        <div class="skill-register-label-grid">
          <div class="field"><label for="skill-category">Category <span>Required</span></label>
            <select class="select" id="skill-category" data-skill-category data-input-action="skill-category">${SKILL_CATEGORIES.map((category) => `<option value="${ctx.esc(category)}">${ctx.esc(category)}</option>`).join("")}<option value="__new__">+ New category</option></select>
            <input class="input" data-skill-new-category maxlength="60" placeholder="Category name" hidden></div>
          <div class="field"><label for="skill-tags">Tags <span>3 to 10</span></label>
            <input class="input" id="skill-tags" data-skill-tags placeholder="workflow, automation, support" autocomplete="off" aria-describedby="skill-tags-help">
            <small id="skill-tags-help" class="subtle">Separate tags with commas.</small></div>
        </div>
        <div class="skill-label-suggestions" data-skill-label-suggestions hidden>
          <div><b>Suggested Labels</b><span>Review before adding</span></div>
          <button class="skill-tag" data-action="skill-suggestion-add" data-tag="workflow">workflow <span>+</span></button>
          <button class="skill-tag" data-action="skill-suggestion-add" data-tag="automation">automation <span>+</span></button>
          <button class="skill-tag" data-action="skill-suggestion-add" data-tag="operations">operations <span>+</span></button>
          <button class="btn btn--ghost btn--sm" data-action="skill-suggestion-dismiss">Dismiss</button>
        </div>
        <p class="skill-label-note">Labels help people find this skill. They are not part of the skill file and changing them does not create a new version.</p>
        <div class="field skill-definition-field"><label for="skill-def">Instructions <span>Required</span></label>
          <textarea class="input mono" id="skill-def" data-skill-def data-input-action="skill-instructions" rows="8" placeholder="What the agent should do, step by step" required></textarea></div>
      </div>
    </div>
    <footer class="skill-register-footer">
      <span class="skill-register-status" data-skill-form-status role="status" aria-live="polite"></span>
      <div class="row"><button class="btn btn--outline" data-action="skill-new">Cancel</button>
        <button class="btn btn--primary" data-action="skill-create">${mutate ? "Add skill" : "Send for review"}</button></div>
    </footer></section>`;
}

// ---------------------------------------------------------------------------
// Detail panel (owner/admin), rendered inside the expanded library row.
// Per-lane check verdicts (E74), structured findings, and collapsed sections
// for instructions, check history, agents, versions, and activity.
// ---------------------------------------------------------------------------

function approvalLine(ctx, skill) {
  const { esc } = ctx;
  if (skill.approvalStatus === "pending") {
    return `<div class="subtle">Waiting for a team admin to approve. Agents cannot use it yet.</div>`;
  }
  if (skill.approvalStatus === "rejected") {
    return `<div class="subtle">Rejected by a team admin. See the activity log below.</div>`;
  }
  return "";
}

const LANE_LABELS = { llm: "LLM", cisco: "Cisco", skillspector: "NVIDIA SkillSpector" };

function ciscoLogo() {
  return `<svg class="skill-vendor-logo skill-vendor-logo--cisco" viewBox="0 0 84 28" role="img" aria-label="Cisco">
    <path d="M12 9v8M20 5v16M28 8v10M36 4v17M44 9v8" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>
    <text x="48" y="20" fill="currentColor" font-family="Arial, sans-serif" font-size="10" font-weight="700" letter-spacing="1.2">CISCO</text>
  </svg>`;
}

function nvidiaLogo(useScannerName = false) {
  const ariaLabel = useScannerName ? "NVIDIA SkillSpector" : "NVIDIA";
  return `<svg class="skill-vendor-logo skill-vendor-logo--nvidia" viewBox="0 0 112 28" role="img" aria-label="${ariaLabel}">
    <rect x="1" y="3" width="26" height="22" rx="4" fill="currentColor" opacity=".14"/>
    <path d="M5.5 14c4.2-5.2 11-6.8 17.8-4.4-5.5.3-9.6 2.2-12.2 5.6 2.6 2.6 6.1 3.1 9.5 1.2-2.2-2-4.7-2.2-7.1-.8 1.9-3 5.5-4 10-2.5-2.3 7.2-11.4 8.6-18 1Z" fill="currentColor"/>
    <circle cx="17.3" cy="14.2" r="1.7" fill="currentColor"/>
    <text x="34" y="19" fill="currentColor" font-family="Arial, sans-serif" font-size="11" font-weight="800" letter-spacing="1">NVIDIA</text>
  </svg>`;
}

function laneIcon(mode) {
  if (mode === "llm") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="M12 2.5 13.8 8l5.7 1.8-5.7 1.8L12 17.5 10.2 11.8 4.5 10 10.2 8.2 12 2.5Z" stroke-linejoin="round"/><path d="m18.6 15.4.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7.7-2Z" stroke-linejoin="round"/></svg>';
  }
  if (mode === "cisco") {
    return ciscoLogo();
  }
  if (mode === "skillspector") {
    return nvidiaLogo();
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L4 16l4 4 4.3-5.3a4 4 0 0 0 5.4-5.4L15 12l-3-3 2.7-2.7Z" stroke-linejoin="round"/></svg>';
}

function laneIconClass(mode) {
  return mode === "cisco" || mode === "skillspector" ? ` skill-lane-icon--brand skill-lane-icon--${mode}` : "";
}

function findingLaneSource(ctx, lane) {
  if (lane === LANE_LABELS.cisco) {
    return `<span class="skill-finding-source">${ciscoLogo()}</span>`;
  }
  if (lane === LANE_LABELS.skillspector) {
    return `<span class="skill-finding-source">${nvidiaLogo(true)}</span>`;
  }
  return `<span class="skill-finding-source subtle">${ctx.esc(lane)}</span>`;
}

function sevIcon(tone) {
  if (tone === "crit") return bandIcon("critical");
  if (tone === "warn") return bandIcon("risky");
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5m0-8.5h.01" stroke-linecap="round"/></svg>';
}

function sevTone(severity) {
  const s = String(severity ?? "").toLowerCase();
  if (s === "critical" || s === "high") return "crit";
  if (s === "medium" || s === "warning" || s === "warn") return "warn";
  return "info";
}

/** The newest check batch: all runs sharing the max startedAt. */
function latestBatch(runs) {
  const latestTs = runs.reduce((m, r) => {
    const t = String(r?.startedAt ?? "");
    return t > m ? t : m;
  }, "");
  return { latestTs, latest: runs.filter((r) => String(r?.startedAt ?? "") === latestTs) };
}

// Per-lane verdict cards for the latest check batch (E74): one card per
// executed v2 lane with its plain-language verdict; the legacy static+sandbox
// fallback collapses into a single "Legacy" card at its worst lane result.
function laneCards(ctx, runs) {
  const { esc } = ctx;
  if (!Array.isArray(runs) || runs.length === 0) return "";
  const { latestTs, latest } = latestBatch(runs);
  if (latest.length === 0) return "";
  const card = (label, mode, r) => {
    const status = r ? String(r.status ?? "") : "not-run";
    const tone = status === "error" || status === "failed"
      ? "crit"
      : status === "passed"
        ? "ok"
        : "warn";
    const verdict = status === "passed"
      ? "Passed"
      : status === "failed"
        ? "Needs attention"
        : status === "error"
          ? "Could not complete"
          : status === "running"
            ? "Running"
            : "Not run";
    // Verdict and engine build are two different facts: the verdict is what a
    // reviewer acts on, the build is provenance. They no longer share a line.
    return `<div class="skill-lane skill-lane--${tone}">
      <span class="skill-lane-icon${laneIconClass(mode)}">${laneIcon(mode)}</span>
      <div class="skill-lane-info"><div class="skill-lane-name">${esc(label)}</div>
        <span class="skill-lane-verdict">${esc(verdict)}</span>
        ${r?.engineVersions ? `<div class="skill-lane-sub">${esc(String(r.engineVersions))}</div>` : ""}</div></div>`;
  };
  const byMode = new Map(latest.map((r) => [String(r?.mode ?? ""), r]));
  const cards = [];
  if (byMode.has("llm")) cards.push(card(LANE_LABELS.llm, "llm", byMode.get("llm")));
  for (const mode of ["cisco", "skillspector"]) {
    cards.push(card(LANE_LABELS[mode], mode, byMode.get(mode)));
  }
  const legacy = latest.filter((r) => !LANE_LABELS[String(r?.mode ?? "")]);
  if (legacy.length > 0) {
    const worst = legacy.reduce((a, b) =>
      Number(a?.safetyScore ?? 0) <= Number(b?.safetyScore ?? 0) ? a : b);
    cards.push(card("Legacy", "legacy", worst));
  }
  return `<section class="skill-checks"><div class="skill-lane-head"><span class="eyebrow">Latest Checks</span>
      <span class="subtle">${esc(compactTs(latestTs))}</span></div>
    <div class="skill-lane-grid">${cards.join("")}</div></section>`;
}

function findingsBlock(ctx, runs) {
  const { esc } = ctx;
  if (!Array.isArray(runs) || runs.length === 0) return "";
  const { latest } = latestBatch(runs);
  const findings = latest.flatMap((r) =>
    (Array.isArray(r?.findings) ? r.findings : [])
      .map((f) => ({ f, lane: LANE_LABELS[String(r?.mode ?? "")] ?? "Legacy" })));
  if (findings.length === 0) {
    return `<div class="skill-clean"><span class="skill-clean-icon">${bandIcon("good")}</span>
      All checks passed. Nothing to flag.</div>`;
  }
  const items = findings
    .map(({ f, lane }) => {
      const tone = sevTone(f?.severity);
      return `<div class="skill-finding skill-finding--${tone}">
        <span class="skill-finding-icon">${sevIcon(tone)}</span>
        <div class="skill-finding-body">
          <div class="skill-finding-top"><b>${esc(String(f?.rule ?? "finding"))}</b>
            <span class="pill ${tone === "crit" ? "pill--crit" : tone === "warn" ? "pill--warn" : ""}">${esc(String(f?.severity ?? "info"))}</span>
            ${findingLaneSource(ctx, lane)}</div>
          ${f?.message ? `<div class="skill-finding-msg">${esc(String(f.message))}</div>` : ""}
          ${f?.excerpt ? `<code class="skill-finding-excerpt">${esc(String(f.excerpt))}</code>` : ""}
        </div></div>`;
    })
    .join("");
  return `<div class="skill-findings"><div class="skill-lane-head"><span class="eyebrow">What the checks found</span>
      <span class="subtle">${findings.length} finding${findings.length === 1 ? "" : "s"}</span></div>${items}</div>`;
}

function skillLabelSummary(ctx, skill) {
  const labels = labelsFor(skill);
  const id = ctx.esc(String(skill.id ?? ""));
  const userTags = labels.tags.map((tag) => `<span class="skill-tag">${ctx.esc(tag)}</span>`).join("");
  const handlingTags = labels.handling.map((tag) => `<span class="skill-tag skill-tag--handling" title="Set by the safety checks"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3.25" y="7" width="9.5" height="6.5" rx="2"/><path d="M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7"/></svg>${ctx.esc(tag)}</span>`).join("");
  return `<div class="skill-detail-labels" title="${ctx.esc(labels.purpose)}">
    <div class="skill-tags skill-tags--detail">${userTags}${handlingTags}</div>
    <button class="skill-label-edit" data-action="skill-labels-edit" data-id="${id}" aria-expanded="${editingLabelsId === String(skill.id ?? "")}">Edit Labels</button>
  </div>`;
}

function skillLabelEditor(ctx, skill) {
  if (editingLabelsId !== String(skill.id ?? "")) return "";
  const labels = labelsFor(skill);
  const id = ctx.esc(String(skill.id ?? ""));
  return `<section class="skill-label-editor" data-skill-label-form data-skill-id="${id}" aria-labelledby="skill-label-editor-title">
    <div class="skill-edit-head"><div><div class="eyebrow">Discovery labels</div><h4 id="skill-label-editor-title">Edit labels</h4></div><span class="pill skill-label-version-note">Does not change the file</span></div>
    <div class="field"><label for="skill-label-purpose">Purpose <span>${ctx.esc(String(labels.purpose.length))}/140</span></label><input class="input" id="skill-label-purpose" data-skill-purpose maxlength="140" value="${ctx.esc(labels.purpose)}"></div>
    <div class="skill-register-label-grid"><div class="field"><label for="skill-label-category">Category</label><select class="select" id="skill-label-category" data-skill-category>${SKILL_CATEGORIES.map((category) => `<option value="${ctx.esc(category)}"${labels.category === category ? " selected" : ""}>${ctx.esc(category)}</option>`).join("")}</select></div>
      <div class="field"><label for="skill-label-tags">Tags <span>3 to 10</span></label><input class="input" id="skill-label-tags" data-skill-tags value="${ctx.esc(labels.tags.join(", "))}"></div></div>
    <p class="skill-label-note">Handling tags are locked and updated only by safety checks.</p>
    <div class="skill-edit-footer"><span data-skill-label-status role="status" aria-live="polite"></span><div class="row"><button class="btn btn--outline btn--sm" data-action="skill-labels-edit" data-id="${id}">Cancel</button><button class="btn btn--primary btn--sm" data-action="skill-labels-save" data-id="${id}">Save labels</button></div></div>
  </section>`;
}

function labelHistorySection(ctx, history) {
  const entries = Array.isArray(history) ? history : [];
  const rows = entries.map((entry) => {
    const before = Array.isArray(entry.before) ? entry.before.join(", ") : String(entry.before ?? "");
    const after = Array.isArray(entry.after) ? entry.after.join(", ") : String(entry.after ?? "");
    const change = before && after ? `${before} → ${after}` : after || before || "None";
    return [ctx.esc(compactTs(entry.changedAt)), ctx.esc(String(entry.field ?? "")), ctx.esc(personDisplayName(entry.changedBy, ctx.personLabel, "human")), ctx.esc(change)];
  });
  return sectionShell("Label History", `${entries.length} Change${entries.length === 1 ? "" : "s"}`, detailGrid("Label history", "labels", ["When", "Field", "By", "Change"], rows, "No label changes yet"), true);
}

function detailPanel(ctx, d) {
  const { esc } = ctx;
  const skill = d && d.skill ? d.skill : null;
  if (!skill) return "";
  const runs = Array.isArray(d.vettingRuns) ? d.vettingRuns : [];
  const agents = Array.isArray(d.agents) ? d.agents : [];
  const history = Array.isArray(d.history) ? d.history : [];
  const events = Array.isArray(d.events) ? d.events : [];
  const labelHistory = Array.isArray(d.labelHistory) ? d.labelHistory : [];
  const id = String(skill.id ?? "");
  const current = !skill.tValidTo && skill.status === "active";
  const blocked = skill.vettingStatus !== "vetted";
  const isPending = skill.approvalStatus === "pending";
  const editing = editingSkillId === id;

  const defPreview = String(skill.definition ?? "");
  const truncated = defPreview.length > 4000;

  const actions = current
    ? `<div class="skill-detail-action-rail">
        <button class="btn btn--outline btn--sm" data-action="skill-edit" data-id="${esc(id)}" aria-expanded="${editing ? "true" : "false"}">${editing ? "Close Editor" : "Edit File"}</button>
        <button class="btn btn--primary btn--sm" data-action="skill-vet" data-id="${esc(id)}">Run Checks</button>
        ${isPending ? `<button class="btn btn--solid btn--sm" data-action="skill-approve" data-id="${esc(id)}">Approve</button>` : ""}
        <span class="subtle" data-skill-status role="status" aria-live="polite"></span>
        <button class="btn btn--outline btn--sm skill-retire" data-action="skill-retire" data-id="${esc(id)}">Retire</button>
      </div>`
    : "";

  // The two override paths sit AFTER the evidence: nobody should be asked to
  // reject a skill or wave one through above the findings that justify it.
  const governance = current
    ? `${isPending ? `<div class="skill-gov-row">
        <span class="skill-gov-icon skill-gov-icon--warn">${bandIcon("risky")}</span>
        <div class="skill-gov-body"><b>Reject this skill</b>
          <p>The reason is saved in the activity log.</p>
          <div class="skill-gov-controls"><input class="input" data-skill-reject-reason="${esc(id)}" placeholder="Why it is rejected">
            <button class="btn btn--danger btn--sm" data-action="skill-reject" data-id="${esc(id)}">Reject</button></div>
        </div></div>` : ""}
      ${blocked ? `<div class="skill-gov-row">
        <span class="skill-gov-icon">${sevIcon("info")}</span>
        <div class="skill-gov-body"><b>Allow anyway</b>
          <p>This skill has not passed its checks. You can allow it anyway; your reason is recorded.</p>
          <div class="skill-gov-controls"><input class="input" data-skill-override-reason placeholder="Why it should be allowed">
            <button class="btn btn--outline btn--sm" data-action="skill-override" data-id="${esc(id)}">Save</button></div>
        </div></div>` : ""}`
    : "";

  const neverVetted = runs.length === 0
    ? `<div class="skill-clean skill-clean--warn"><span class="skill-clean-icon">${bandIcon("risky")}</span>
        Not checked yet. Agents cannot use this skill until checks pass or an admin allows it.</div>`
    : "";

  return `<div class="skill-detail-panel" data-skill-id="${esc(id)}">
    <header class="skill-detail-header">
      <div class="skill-detail-identity">
        <div class="eyebrow mono">${esc(String(skill.namespace ?? "")) || "(org root)"} · ${esc(String(skill.skillKey ?? ""))}</div>
        <h3 id="skill-detail-modal-title">${esc(String(skill.name ?? skill.skillKey ?? "Skill details"))}</h3>
        <div class="skill-detail-state"><span class="skill-category"><i aria-hidden="true">◆</i>${esc(labelsFor(skill).category)}</span>${readinessBadge(ctx, skill)}${defaultBadge(skill)}<span class="pill">v${esc(String(skill.version ?? 1))}</span></div>
        <div class="skill-detail-facts">Added By <b>${esc(personDisplayName(skill.createdBy, ctx.personLabel, "human") || "unknown")}</b> On <b>${esc(compactDate(skill.createdAt))}</b> · Last Checked <b>${skill.lastVettedAt ? esc(compactDate(skill.lastVettedAt)) : "Never"}</b></div>
        ${skillLabelSummary(ctx, skill)}
        ${approvalLine(ctx, skill)}
      </div>
      <button class="skill-detail-close" data-action="skill-modal-close" data-wizard-focus aria-label="Close skill details"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke-linecap="round"/></svg></button>
    </header>
    ${actions}
    <div class="skill-detail-scroll">
      ${skillLabelEditor(ctx, skill)}
      ${editing ? editForm(ctx, skill) : ""}
      ${neverVetted}
      ${laneCards(ctx, runs)}
      ${findingsBlock(ctx, runs)}
      ${governance}
      <div class="skill-detail-sections">
        ${definitionSection(ctx, defPreview, truncated)}
        ${vettingSection(ctx, runs)}
        ${agentsSection(ctx, agents)}
        ${historySection(ctx, history)}
        ${labelHistorySection(ctx, labelHistory)}
        ${eventsSection(ctx, events)}
      </div>
    </div>
  </div>`;
}

function editForm(ctx, skill) {
  const { esc } = ctx;
  const id = String(skill.id ?? "");
  const safeId = id.replace(/[^A-Za-z0-9_-]/g, "-") || "skill";
  const fileId = `skill-edit-file-${safeId}`;
  const nextVersion = Number(skill.version ?? 1) + 1;
  return `<section class="skill-edit" data-skill-form data-skill-mode="update" data-skill-current-id="${esc(id)}" aria-labelledby="skill-edit-title-${esc(safeId)}">
    <div class="skill-edit-head"><div><div class="eyebrow">Skill file</div>
      <h4 id="skill-edit-title-${esc(safeId)}">Edit current file</h4></div>
      <span class="pill"><i class="dot"></i>v${esc(String(nextVersion))} next</span></div>
    <div class="skill-edit-grid">
      <div class="skill-file-field">
        <input class="skill-file-input" id="${esc(fileId)}" type="file" accept=".md,.markdown,.txt" data-input-action="skill-file" aria-describedby="${esc(fileId)}-help">
        <label class="skill-upload skill-upload--compact" for="${esc(fileId)}">
          <span class="skill-upload-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <span class="skill-upload-copy"><strong>Replace file</strong><small id="${esc(fileId)}-help">Markdown or plain text</small></span>
          <span class="skill-upload-action" aria-hidden="true">Upload</span>
        </label>
        <div class="skill-file-state"><span class="skill-file-state-dot" aria-hidden="true"></span><span data-skill-file-name aria-live="polite">Current file loaded</span></div>
      </div>
      <div class="skill-edit-fields">
        <div class="skill-register-grid">
          <div class="field"><label for="skill-edit-key-${esc(safeId)}">Key <span>Fixed</span></label>
            <input class="input mono" id="skill-edit-key-${esc(safeId)}" data-skill-key value="${esc(String(skill.skillKey ?? ""))}" autocomplete="off" readonly></div>
          <div class="field"><label for="skill-edit-name-${esc(safeId)}">Name <span>Required</span></label>
            <input class="input" id="skill-edit-name-${esc(safeId)}" data-skill-name value="${esc(String(skill.name ?? ""))}" autocomplete="off" required></div>
        </div>
        <div class="field"><label for="skill-edit-desc-${esc(safeId)}">Description <span>Optional</span></label>
          <input class="input" id="skill-edit-desc-${esc(safeId)}" data-skill-desc value="${esc(String(skill.description ?? ""))}" autocomplete="off"></div>
      </div>
    </div>
    <div class="field skill-definition-field"><label for="skill-edit-def-${esc(safeId)}">Instructions <span>Required</span></label>
      <textarea class="input mono" id="skill-edit-def-${esc(safeId)}" data-skill-def rows="10" required>${esc(String(skill.definition ?? ""))}</textarea></div>
    <div class="skill-edit-footer">
      <span class="skill-register-status" data-skill-form-status role="status" aria-live="polite"></span>
      <div class="row"><button class="btn btn--outline btn--sm" data-action="skill-edit" data-id="${esc(id)}">Cancel</button>
        <button class="btn btn--primary btn--sm" data-action="skill-update">Update skill</button></div>
    </div>
  </section>`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/**
 * Human timestamp: "1 Jul 2026, 03:00" — read off the ISO string rather than
 * through Date, so every machine renders the identical string (UTC, as
 * stored) and nothing here depends on the viewer's locale. Anything that does
 * not parse falls back to the raw slice.
 */
function shortTs(value) {
  const raw = String(value ?? "");
  const parts = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/.exec(raw);
  if (!parts) return raw.slice(0, 19).replace("T", " ");
  return `${Number(parts[3])} ${MONTHS[Number(parts[2]) - 1] ?? parts[2]} ${parts[1]}, ${parts[4]}:${parts[5]}`;
}

function compactTs(value) {
  return shortTs(value).replace(/ (\d{4}),/, ",");
}

function compactDate(value) {
  return compactTs(value).split(",")[0];
}

function sectionShell(summary, meta, body, open = false) {
  return `<details class="skill-sec"${open ? " open" : ""}><summary>${CHEVRON_SVG}${summary}<span class="skill-sec-meta">${meta}</span></summary>
    <div class="skill-sec-body">${body}</div></details>`;
}

function detailGrid(label, kind, headings, rows, emptyText) {
  const header = headings.map((heading) => `<div role="columnheader">${heading}</div>`).join("");
  const body = rows.length
    ? rows.map((cells) => `<div class="skill-detail-grid-row" role="row">${cells.map((cell) => {
      const value = cell && typeof cell === "object" ? cell.html : cell;
      const className = cell && typeof cell === "object" && cell.className ? ` class="${cell.className}"` : "";
      return `<div${className} role="cell">${value ?? ""}</div>`;
    }).join("")}</div>`).join("")
    : `<div class="skill-detail-grid-row skill-detail-grid-empty" role="row"><div role="cell"><span>—</span>${emptyText}</div></div>`;
  return `<div class="skill-detail-grid skill-detail-grid--${kind}" role="table" aria-label="${label}">
    <div class="skill-detail-grid-head" role="row">${header}</div>
    <div class="skill-detail-grid-body" role="rowgroup">${body}</div>
  </div>`;
}

function definitionSection(ctx, defPreview, truncated) {
  const { esc } = ctx;
  if (!defPreview) return "";
  const chars = defPreview.length >= 1000
    ? `${(defPreview.length / 1000).toFixed(1)}k chars`
    : `${defPreview.length} chars`;
  return sectionShell("Skill Instructions", chars, `
    <div class="snippet mono skill-definition">${esc(truncated ? `${defPreview.slice(0, 4000)}…` : defPreview)}</div>
    ${truncated ? `<div class="subtle">${esc(String(defPreview.length))} characters (preview shortened)</div>` : ""}`);
}

function vettingSection(ctx, runs) {
  const { esc } = ctx;
  if (runs.length === 0) return "";
  const rows = runs.map((r) => {
      const findings = Array.isArray(r.findings) ? r.findings : [];
      const findingList = findings
        .map((f) => `<div class="subtle">[${esc(String(f?.severity ?? ""))}] ${esc(String(f?.rule ?? ""))}: ${esc(String(f?.message ?? ""))} <span class="mono">${esc(String(f?.excerpt ?? ""))}</span></div>`)
        .join("");
      return [
        esc(compactTs(r.startedAt)),
        { html: `${esc(String(r.mode ?? ""))}${r.engineVersions ? `<div class="subtle mono">${esc(String(r.engineVersions))}</div>` : ""}`, className: "skill-detail-grid-check" },
        esc(String(r.status ?? "")),
        { html: typeof ctx.personAvatar === "function" ? ctx.personAvatar(r.ranBy, "human") : esc(String(r.ranBy ?? "")), className: "person-avatar-cell" },
        { html: `${findings.length === 0 ? '<span class="subtle">clean</span>' : findingList}${r.detail ? `<div class="subtle">${esc(String(r.detail))}</div>` : ""}`, className: "skill-detail-grid-findings" },
      ];
    });
  return sectionShell("Check History", `${runs.length} Run${runs.length === 1 ? "" : "s"}`, detailGrid("Check history", "checks", ["When", "Check", "Status", "By", "Findings"], rows, "No checks have run yet"));
}

function agentsSection(ctx, agents) {
  const { esc } = ctx;
  const rows = agents.map((a) => [
    `${esc(String(a.actor ?? ""))}<div class="subtle mono">${esc(String(a.keyId ?? ""))}</div>`,
    { html: esc(String(a.namespace ?? "")) || "(org root)", className: "mono" },
    esc(String(a.invocations ?? 0)),
    esc(String(a.denials ?? 0)),
    esc(String(a.overrides ?? 0)),
    esc(compactDate(a.lastInvokedAt) || "-"),
  ]);
  return sectionShell("Agents Using This Skill", `${agents.length} Agent${agents.length === 1 ? "" : "s"}`, detailGrid("Agents using this skill", "agents", ["Agent", "Team", "Uses", "Blocked", "Overrides", "Last used"], rows, "No agents use this skill yet"), true);
}

function historySection(ctx, history) {
  const { esc } = ctx;
  const rows = history.map((h) => [
    `v${esc(String(h.version ?? ""))}`,
    { html: esc(String(h.contentSha256 ?? "").slice(0, 12)), className: "mono" },
    esc(compactDate(h.tValidFrom)),
    h.tValidTo ? esc(compactDate(h.tValidTo)) : "Current",
    { html: typeof ctx.personAvatar === "function" ? ctx.personAvatar(h.createdBy, "human") : esc(personDisplayName(h.createdBy, ctx.personLabel, "human")), className: "person-avatar-cell" },
  ]);
  return sectionShell("Earlier Versions", `${history.length} Version${history.length === 1 ? "" : "s"}`, detailGrid("Earlier versions", "versions", ["Version", "Hash", "From", "To", "By"], rows, "No versions available"), true);
}

function eventsSection(ctx, events) {
  const { esc } = ctx;
  const rows = events.map((e) => [
    esc(compactTs(e.ts)),
    { html: esc(String(e.op ?? "")), className: "mono" },
    esc(String(e.result ?? "")),
    { html: typeof ctx.personAvatar === "function" ? ctx.personAvatar(e.actor, "human") : esc(personDisplayName(e.actor, ctx.personLabel)), className: "person-avatar-cell" },
    { html: esc(String(e.detail ?? "")), className: "subtle" },
  ]);
  return sectionShell("Activity Log", `${events.length} Event${events.length === 1 ? "" : "s"}`, detailGrid("Activity log", "events", ["When", "Action", "Result", "Who", "Detail"], rows, "No activity recorded yet"), true);
}

// ---------------------------------------------------------------------------
// Add-to-integrations modal: per-client install snippets for the skill file
// (mirrors S14's client catalog; download itself is the governed route above)
// ---------------------------------------------------------------------------

function skillBaseUrl() {
  return typeof window === "undefined" ? "https://halomem.example" : window.location.origin;
}

const SKILL_CLIENTS = [
  {
    id: "claude-code", name: "Claude Code", vendor: "Anthropic", kind: "CLI",
    docs: "https://code.claude.com/docs/en/skills",
    steps: (key, cmd) => [
      { title: "Download the approved skill file", code: cmd },
      { title: "Install into the project (checked in) or user scope",
        code: `mkdir -p .claude/skills/${key}\nmv SKILL.md .claude/skills/${key}/SKILL.md` },
      { title: "Verify", code: "claude skills list" },
    ],
  },
  {
    id: "codex", name: "Codex CLI", vendor: "OpenAI", kind: "CLI",
    docs: "https://developers.openai.com/codex/cli/",
    steps: (key, cmd) => [
      { title: "Download the approved skill file", code: cmd },
      { title: "Install into your Codex skills directory",
        note: "Codex reads skill folders containing a SKILL.md. See the vendor docs for your version.",
        code: `mkdir -p ~/.codex/skills/${key}\nmv SKILL.md ~/.codex/skills/${key}/SKILL.md` },
    ],
  },
  {
    id: "cursor", name: "Cursor", vendor: "Anysphere", kind: "IDE",
    docs: "https://cursor.com/docs",
    steps: (key, cmd) => [
      { title: "Download the approved skill file", code: cmd },
      { title: "Add it as a project rule/skill",
        note: "Cursor picks up markdown instructions from .cursor. See the vendor docs for your version.",
        code: `mkdir -p .cursor/skills/${key}\nmv SKILL.md .cursor/skills/${key}/SKILL.md` },
    ],
  },
  {
    id: "vscode", name: "VS Code", vendor: "Microsoft", kind: "IDE",
    docs: "https://code.visualstudio.com/docs/copilot/customization/custom-instructions",
    steps: (key, cmd) => [
      { title: "Download the approved skill file", code: cmd },
      { title: "Add it as Copilot custom instructions",
        code: `mkdir -p .github/instructions\nmv SKILL.md .github/instructions/${key}.instructions.md` },
    ],
  },
  {
    id: "gemini", name: "Gemini CLI", vendor: "Google", kind: "CLI",
    docs: "https://github.com/google-gemini/gemini-cli",
    steps: (key, cmd) => [
      { title: "Download the approved skill file", code: cmd },
      { title: "Install into your Gemini skills directory",
        note: "Gemini CLI reads skill folders containing a SKILL.md. See the vendor docs for your version.",
        code: `mkdir -p ~/.gemini/skills/${key}\nmv SKILL.md ~/.gemini/skills/${key}/SKILL.md` },
    ],
  },
];

let modalClientId = null;
let modalSkill = null; // { id, key, name }
let modalOpener = null;
let keydownDoc = null;
let keydownHandler = null;

function downloadCommand(skill) {
  return `curl -fsSL -H "Authorization: Bearer {{HALOMEM_API_KEY}}" \\\n  "${skillBaseUrl()}/v1/skills/${skill.id}/download" -o SKILL.md`;
}

function modalHtml(ctx) {
  const { esc } = ctx;
  const entry = SKILL_CLIENTS.find((c) => c.id === modalClientId) ?? null;
  if (!entry || !modalSkill) return "";
  const steps = entry.steps(modalSkill.key, downloadCommand(modalSkill));
  const stepsHtml = steps
    .map((step, i) => {
      const copyBtn = !step.code
        ? ""
        : `<button class="btn btn--outline btn--sm" data-action="skill-copy-step" data-step="${i}">Copy</button>`;
      return `<li><div class="between"><b>${esc(step.title)}</b>${copyBtn}</div>
        ${step.note ? `<div class="intg-step-note">${esc(step.note)}</div>` : ""}
        ${step.code ? `<div class="snippet">${esc(step.code)}</div>` : ""}</li>`;
    })
    .join("");
  const picker = SKILL_CLIENTS
    .map((c) => `<button class="btn ${c.id === entry.id ? "btn--solid" : "btn--outline"} btn--sm"
        data-action="skill-integrations-client" data-client="${esc(c.id)}">${esc(c.name)}</button>`)
    .join("");
  return `<button class="source-wizard-backdrop" data-action="skill-modal-close" aria-label="Close"></button>
    <div class="source-wizard-dialog intg-dialog" role="dialog" aria-modal="true" aria-label="Add ${esc(modalSkill.name)} to a client">
    <div class="between source-wizard-head"><div>
      <div class="eyebrow">Ready to share</div>
      <h3>Add “${esc(modalSkill.name)}” to ${esc(entry.name)}</h3></div>
      <div class="row"><a class="btn btn--ghost btn--sm" href="${esc(entry.docs)}" target="_blank" rel="noreferrer noopener">Vendor docs</a>
      <button class="source-wizard-close halo-icon-control" data-action="skill-modal-close" data-wizard-focus aria-label="Return to skills"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Close</span></button></div></div>
    <div class="row" style="flex-wrap:wrap;margin-bottom:var(--s3)">${picker}</div>
    <div class="intg-placeholder-note">Downloads are protected: only approved, checked skills are served. Replace <span class="mono">{{HALOMEM_API_KEY}}</span> with a key from the Integrations screen.</div>
    <ol class="intg-steps">${stepsHtml}</ol></div>`;
}

function detailModalHtml(ctx, detail, label) {
  const body = String(detail).includes('id="skill-detail-modal-title"')
    ? detail
    : `<div class="skill-detail-panel skill-detail-panel--error">
        <header class="skill-detail-header">
          <div class="skill-detail-identity"><div class="eyebrow mono">Skill</div><h3 id="skill-detail-modal-title">${ctx.esc(label || "Skill details")}</h3></div>
          <button class="skill-detail-close" data-action="skill-modal-close" data-wizard-focus aria-label="Close skill details"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke-linecap="round"/></svg></button>
        </header>
        <div class="skill-detail-scroll">${detail}</div>
      </div>`;
  return `<button class="source-wizard-backdrop" data-action="skill-modal-close" aria-label="Close"></button>
    <div class="source-wizard-dialog skill-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="skill-detail-modal-title">
      ${body}
    </div>`;
}

async function openSkillDetailModal(ctx, id, opener) {
  if (!id) return;
  selectedSkillId = id;
  if (opener && typeof opener.setAttribute === "function") opener.setAttribute("aria-expanded", "true");
  setStatus("[data-skill-status]", "Loading details…");
  try {
    const d = await ctx.api.get(`/v1/admin/skills/${encodeURIComponent(id)}`);
    const skill = d && d.skill ? d.skill : null;
    const label = skill ? String(skill.name || skill.skillKey || "Skill details") : "Skill details";
    showModalHtml(detailModalHtml(ctx, detailPanel(ctx, d), label), opener);
    setStatus("[data-skill-status]", "");
  } catch (err) {
    const message = ctx.esc(err?.message ?? "Unable to load this skill");
    showModalHtml(detailModalHtml(ctx, `<div class="skill-detail-error"><b>Skill detail unavailable</b><div class="sub">${message}</div></div>`, "Skill details"), opener);
    setStatus("[data-skill-status]", err?.message ?? "Unable to load this skill");
  }
}

function showModalHtml(html, opener) {
  const modal = document.getElementById("skill-modal");
  if (!modal) return;
  if (keydownDoc && keydownHandler) keydownDoc.removeEventListener("keydown", keydownHandler);
  modalOpener = opener || null;
  modal.innerHTML = html;
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("source-modal-open");
  const focus = modal.querySelector("[data-wizard-focus]");
  if (focus) focus.focus();
  keydownDoc = document;
  keydownHandler = (ev) => {
    if (ev.key === "Escape") closeModal(document);
  };
  document.addEventListener("keydown", keydownHandler);
}

function openModal(ctx, opener) {
  if (!modalSkill) return;
  showModalHtml(modalHtml(ctx), opener);
}

function closeModal(doc) {
  const modal = doc && doc.getElementById ? doc.getElementById("skill-modal") : null;
  if (modal) {
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML = "";
  }
  if (doc && doc.body) doc.body.classList.remove("source-modal-open");
  if (keydownDoc && keydownHandler) keydownDoc.removeEventListener("keydown", keydownHandler);
  if (modalOpener && typeof modalOpener.setAttribute === "function") modalOpener.setAttribute("aria-expanded", "false");
  if (modalOpener && typeof modalOpener.focus === "function") modalOpener.focus({ preventScroll: true });
  modalOpener = null;
  keydownDoc = null;
  keydownHandler = null;
}

export function cleanup() {
  closeModal(document);
  closeRightPanel(document);
}

// ---------------------------------------------------------------------------
// Actions (delegated; no inline JS)
// ---------------------------------------------------------------------------

function setStatus(selector, text) {
  const el = document.querySelector(selector);
  if (el) el.textContent = text;
}

function formRoot(el) {
  return el && typeof el.closest === "function"
    ? (el.closest("[data-skill-form]") ?? document)
    : document;
}

function setFormStatus(root, text) {
  const el = root && typeof root.querySelector === "function"
    ? root.querySelector("[data-skill-form-status]")
    : null;
  if (el) el.textContent = text;
}

/** Parse `---\nname: …\ndescription: …\n---` frontmatter; tolerant, no deps. */
function parseFrontmatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!match) return { name: "", description: "", body: text };
  const fields = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+)\s*:\s*(.*)$/.exec(line);
    if (kv) fields[kv[1].toLowerCase()] = kv[2].trim().replace(/^["']|["']$/g, "");
  }
  return {
    name: fields.name ?? "",
    description: fields.description ?? "",
    // Exported SKILL.md files use one blank separator after frontmatter.
    body: text.slice(match[0].length).replace(/^\r?\n/, ""),
  };
}

function keyFromFilename(filename) {
  return String(filename ?? "")
    .replace(/\.[^.]+$/, "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/^[^a-z0-9]+/, "")
    .slice(0, 200);
}

async function refreshS16(ctx) {
  if (typeof document !== "undefined") closeModal(document);
  if (typeof document !== "undefined") closeRightPanel(document);
  if (ctx && typeof ctx.refresh === "function") {
    await ctx.refresh();
    return;
  }
  await ctx.go("s16");
}

export const actions = {
  async "skill-select"(ctx, el) {
    const id = el.getAttribute("data-id");
    await openSkillDetailModal(ctx, id, el);
  },

  async "skill-new"(ctx, el) {
    const opening = !showRegisterForm;
    showRegisterForm = opening;
    await refreshS16(ctx);
    if (opening && typeof document !== "undefined") {
      const panel = document.getElementById("skill-register-panel");
      const opener = document.querySelector('[data-action="skill-new"][aria-controls="skill-register-panel"]') || el;
      openRightPanel(panel, opener);
    }
  },

  async "skill-register-close"(ctx) {
    if (typeof document !== "undefined") closeRightPanel(document);
    showRegisterForm = false;
    await refreshS16(ctx);
  },

  async "skill-band"(ctx, el) {
    bandFilter = el.getAttribute("data-band") ?? "all";
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-search"(ctx, el) {
    searchQuery = String(el.value ?? "");
    libraryPage = 0;
    await refreshS16(ctx);
  },

  // Compatibility for callers holding the former single-team control. The
  // v2 UI uses the unified multi-team filter above.
  async "skill-team"(ctx, el) {
    const team = el.value || "all";
    teamFilters = team === "all" ? [] : [team];
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-toggle"(ctx) {
    filtersOpen = !filtersOpen;
    await refreshS16(ctx);
  },

  async "skill-filter-category"(ctx, el) {
    categoryFilter = el.getAttribute("data-category") || "all";
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-team"(ctx, el) {
    const team = el.getAttribute("data-team") ?? "";
    teamFilters = el.checked ? [...new Set([...teamFilters, team])] : teamFilters.filter((value) => value !== team);
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-tag"(ctx, el) {
    const tag = el.getAttribute("data-tag") ?? "";
    tagFilters = el.checked ? [...new Set([...tagFilters, tag])] : tagFilters.filter((value) => value !== tag);
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-used-by"(ctx, el) {
    usedByFilter = el.value || "all";
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-added-by"(ctx, el) {
    addedByFilter = el.value || "all";
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-unused"(ctx, el) {
    unusedOnly = Boolean(el.checked);
    filtersOpen = true;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filter-remove"(ctx, el) {
    const kind = el.getAttribute("data-filter-kind");
    const value = el.getAttribute("data-filter-value") ?? "";
    if (kind === "category") categoryFilter = "all";
    if (kind === "team") teamFilters = teamFilters.filter((item) => item !== value);
    if (kind === "tag") tagFilters = tagFilters.filter((item) => item !== value);
    if (kind === "usedBy") usedByFilter = "all";
    if (kind === "addedBy") addedByFilter = "all";
    if (kind === "unused") unusedOnly = false;
    if (kind === "approval") approvalFilter = "all";
    if (kind === "band") bandFilter = "all";
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-filters-clear"(ctx) {
    searchQuery = "";
    categoryFilter = "all";
    teamFilters = [];
    tagFilters = [];
    usedByFilter = "all";
    addedByFilter = "all";
    unusedOnly = false;
    bandFilter = "all";
    approvalFilter = "all";
    filtersOpen = false;
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-page-prev"(ctx) {
    libraryPage = Math.max(0, libraryPage - 1);
    await refreshS16(ctx);
  },

  async "skill-page-next"(ctx) {
    libraryPage += 1;
    await refreshS16(ctx);
  },

  async "skill-manage-tags"(ctx, el) {
    try {
      const response = await ctx.api.get("/v1/admin/skills");
      const skills = Array.isArray(response) ? response : Array.isArray(response?.skills) ? response.skills : [];
      const counts = new Map();
      for (const skill of skills) {
        for (const tag of labelsFor(skill).tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
      }
      const rows = [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([tag, count]) => [
        `<span class="skill-tag">${ctx.esc(tag)}</span>`,
        ctx.esc(String(count)),
        `<span class="subtle">Used on ${count} skill${count === 1 ? "" : "s"}</span>`,
      ]);
      const body = `<div class="skill-detail-panel skill-tag-manager"><p class="sub">User tags are shared across this organization. Edit a skill's labels to add or remove a tag.</p>${detailGrid("Organization tags", "tags", ["Tag", "Skills", "Scope"], rows, "No user tags yet.")}<p class="skill-label-note">Handling tags are system-managed and do not appear here.</p></div>`;
      showModalHtml(detailModalHtml(ctx, body, "Manage tags"), el);
    } catch (err) {
      setStatus("[data-skill-status]", err?.message ?? "Unable to load tags");
    }
  },

  async "skill-approval"(ctx) {
    approvalFilter = approvalFilter === "pending" ? "all" : "pending";
    libraryPage = 0;
    await refreshS16(ctx);
  },

  async "skill-file"(ctx, el) {
    const file = el.files && el.files[0];
    if (!file) return;
    const root = formRoot(el);
    if (Number(file.size ?? 0) > MAX_SKILL_FILE_BYTES) {
      setFormStatus(root, "File is too large. Use a file under 256 KB.");
      el.value = "";
      return;
    }
    const text = await file.text();
    const parsed = parseFrontmatter(text);
    if (parsed.body.length > MAX_SKILL_DEFINITION_CHARS) {
      setFormStatus(root, "Instructions are too long. Keep them under 200,000 characters.");
      el.value = "";
      return;
    }
    const fileName = root.querySelector("[data-skill-file-name]");
    const upload = root.querySelector(".skill-upload");
    if (fileName) fileName.textContent = file.name;
    if (upload) upload.classList.add("is-loaded");
    const keyInput = root.querySelector("[data-skill-key]");
    const nameInput = root.querySelector("[data-skill-name]");
    const descInput = root.querySelector("[data-skill-desc]");
    const defInput = root.querySelector("[data-skill-def]");
    const updateMode = root.getAttribute && root.getAttribute("data-skill-mode") === "update";
    if (keyInput && !keyInput.value && !keyInput.readOnly) keyInput.value = keyFromFilename(file.name);
    if (nameInput && (parsed.name || !updateMode)) nameInput.value = parsed.name || keyFromFilename(file.name);
    if (descInput && parsed.description) descInput.value = parsed.description;
    if (defInput) defInput.value = parsed.body;
    const suggestions = root.querySelector("[data-skill-label-suggestions]");
    if (suggestions) suggestions.hidden = false;
    setFormStatus(root, `Loaded ${file.name}.`);
  },

  async "skill-purpose"(_ctx, el) {
    const root = formRoot(el);
    const count = root.querySelector("[data-skill-purpose-count]");
    if (count) count.textContent = `${String(el.value ?? "").length}/140`;
  },

  async "skill-instructions"(_ctx, el) {
    const root = formRoot(el);
    const suggestions = root.querySelector("[data-skill-label-suggestions]");
    if (suggestions && String(el.value ?? "").trim().length >= 60) suggestions.hidden = false;
  },

  async "skill-category"(_ctx, el) {
    const root = formRoot(el);
    const custom = root.querySelector("[data-skill-new-category]");
    if (custom) custom.hidden = el.value !== "__new__";
  },

  async "skill-suggestion-add"(_ctx, el) {
    const root = formRoot(el);
    const input = root.querySelector("[data-skill-tags]");
    if (!input) return;
    const tag = el.getAttribute("data-tag") ?? "";
    const tags = String(input.value ?? "").split(",").map((value) => value.trim()).filter(Boolean);
    if (tag && !tags.includes(tag) && tags.length < 10) input.value = [...tags, tag].join(", ");
    el.disabled = true;
  },

  async "skill-suggestion-dismiss"(_ctx, el) {
    const suggestions = formRoot(el).querySelector("[data-skill-label-suggestions]");
    if (suggestions) suggestions.hidden = true;
  },

  async "skill-create"(ctx, el) {
    const root = formRoot(el);
    const skillKey = (root.querySelector("[data-skill-key]")?.value ?? "").trim();
    const name = (root.querySelector("[data-skill-name]")?.value ?? "").trim();
    const description = (root.querySelector("[data-skill-desc]")?.value ?? "").trim();
    const definition = root.querySelector("[data-skill-def]")?.value ?? "";
    const purpose = (root.querySelector("[data-skill-purpose]")?.value ?? "").trim();
    const categorySelect = root.querySelector("[data-skill-category]");
    const category = categorySelect?.value === "__new__"
      ? (root.querySelector("[data-skill-new-category]")?.value ?? "").trim()
      : String(categorySelect?.value ?? "").trim();
    const tags = String(root.querySelector("[data-skill-tags]")?.value ?? "").split(",").map((value) => value.trim()).filter(Boolean);
    const selectedTeam = (root.querySelector("[data-skill-team]")?.value ?? "__current__").trim();
    const teamId = selectedTeam === "__current__" ? "" : selectedTeam;
    if (!skillKey || !name || !definition.trim()) {
      setFormStatus(root, "Key, name, and instructions are required.");
      return;
    }
    if (!purpose || !category || tags.length < 3 || tags.length > 10) {
      setFormStatus(root, "Add a purpose, category, and 3 to 10 tags.");
      return;
    }
    const mutate = canMutate(ctx);
    setFormStatus(root, mutate ? "Saving…" : "Sending for review…");
    try {
      const path = mutate ? "/v1/admin/skills" : "/v1/skills";
      const body = { skillKey, name, description, definition, labels: { purpose, category, tags }, ...(mutate && teamId ? { teamId } : {}) };
      const result = await ctx.api.post(path, body);
      showRegisterForm = false;
      bandFilter = "all";
      approvalFilter = "all";
      selectedSkillId = result?.skill?.id ?? selectedSkillId;
      await refreshS16(ctx);
    } catch (err) {
      setFormStatus(root, err?.message ?? "Could not save the skill");
    }
  },

  async "skill-edit"(ctx, el) {
    const id = el.getAttribute("data-id");
    editingSkillId = editingSkillId === id ? null : id;
    selectedSkillId = id || selectedSkillId;
    if (el && typeof el.closest === "function" && el.closest("#skill-modal")) {
      await openSkillDetailModal(ctx, selectedSkillId, modalOpener || el);
      return;
    }
    await refreshS16(ctx);
  },

  async "skill-labels-edit"(ctx, el) {
    const id = el.getAttribute("data-id");
    editingLabelsId = editingLabelsId === id ? null : id;
    selectedSkillId = id || selectedSkillId;
    await openSkillDetailModal(ctx, selectedSkillId, modalOpener || el);
  },

  async "skill-labels-save"(ctx, el) {
    const id = el.getAttribute("data-id");
    const root = el.closest && el.closest("[data-skill-label-form]");
    if (!id || !root) return;
    const purpose = String(root.querySelector("[data-skill-purpose]")?.value ?? "").trim();
    const category = String(root.querySelector("[data-skill-category]")?.value ?? "").trim();
    const tags = String(root.querySelector("[data-skill-tags]")?.value ?? "").split(",").map((value) => value.trim()).filter(Boolean);
    const status = root.querySelector("[data-skill-label-status]");
    if (!purpose || purpose.length > 140 || !category || tags.length < 3 || tags.length > 10) {
      if (status) status.textContent = "Add a purpose, category, and 3 to 10 tags.";
      return;
    }
    if (status) status.textContent = "Saving labels…";
    try {
      await ctx.api.patch(`/v1/admin/skills/${encodeURIComponent(id)}/labels`, { purpose, category, tags });
      editingLabelsId = null;
      await openSkillDetailModal(ctx, id, modalOpener || el);
    } catch (err) {
      if (status) status.textContent = err?.message ?? "Could not save labels";
    }
  },

  async "skill-update"(ctx, el) {
    const root = formRoot(el);
    const currentId = root.getAttribute && root.getAttribute("data-skill-current-id");
    const name = (root.querySelector("[data-skill-name]")?.value ?? "").trim();
    const description = (root.querySelector("[data-skill-desc]")?.value ?? "").trim();
    const definition = root.querySelector("[data-skill-def]")?.value ?? "";
    if (!currentId || !name || !definition.trim()) {
      setFormStatus(root, "Name and instructions are required.");
      return;
    }
    setFormStatus(root, "Updating…");
    try {
      const result = await ctx.api.patch(
        `/v1/admin/skills/${encodeURIComponent(currentId)}`,
        { name, description, definition },
      );
      editingSkillId = null;
      bandFilter = "all";
      approvalFilter = "all";
      selectedSkillId = result?.skill?.id ?? selectedSkillId;
      await refreshS16(ctx);
    } catch (err) {
      setFormStatus(
        root,
        err?.status === 409
          ? "This skill changed while you were editing. Reload it and try again."
          : (err?.message ?? "Could not update the skill"),
      );
    }
  },

  async "skill-approve"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    setStatus("[data-skill-status]", "Approving…");
    try {
      await ctx.api.post(`/v1/admin/skills/${encodeURIComponent(id)}/approve`, {});
      await refreshS16(ctx);
    } catch (err) {
      setStatus("[data-skill-status]", err?.message ?? "Approve failed");
    }
  },

  async "skill-reject"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const reason = (document.querySelector(`[data-skill-reject-reason="${id}"]`)?.value ?? "").trim();
    if (!reason) {
      setStatus("[data-skill-status]", "Add a reason first. It is saved in the activity log.");
      return;
    }
    setStatus("[data-skill-status]", "Rejecting…");
    try {
      await ctx.api.post(`/v1/admin/skills/${encodeURIComponent(id)}/reject`, { reason });
      if (selectedSkillId === id) selectedSkillId = null;
      await refreshS16(ctx);
    } catch (err) {
      setStatus("[data-skill-status]", err?.message ?? "Reject failed");
    }
  },

  async "skill-download"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return false;
    try {
      const res = await fetch(`/v1/skills/${encodeURIComponent(id)}/download`, {
        credentials: "include",
      });
      if (res.status === 401) {
        window.location = "/console/login";
        return false;
      }
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? `download failed (${res.status})`);
      }
      const blob = await res.blob();
      const disposition = res.headers.get("content-disposition") ?? "";
      const match = /filename="?([^";]+)"?/.exec(disposition);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = match ? match[1] : "SKILL.md";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      return true;
    } catch (err) {
      setStatus("[data-skill-status]", err?.message ?? "Download failed");
      return false;
    }
  },

  async "skill-integrations"(ctx, el) {
    modalSkill = {
      id: el.getAttribute("data-id"),
      key: el.getAttribute("data-key") || "skill",
      name: el.getAttribute("data-name") || "skill",
    };
    modalClientId = modalClientId ?? "claude-code";
    openModal(ctx, el);
  },

  async "skill-integrations-client"(ctx, el) {
    modalClientId = el.getAttribute("data-client") ?? modalClientId;
    openModal(ctx, modalOpener || el);
  },

  async "skill-modal-close"() {
    closeModal(document);
  },

  async "skill-copy-step"(ctx, el) {
    const entry = SKILL_CLIENTS.find((c) => c.id === modalClientId);
    if (!entry || !modalSkill) return false;
    const step = entry.steps(modalSkill.key, downloadCommand(modalSkill))[Number(el.getAttribute("data-step"))];
    if (!step || !step.code) return false;
    try {
      await navigator.clipboard.writeText(step.code);
      el.textContent = "Copied";
      setTimeout(() => {
        el.textContent = "Copy";
      }, 1500);
      return true;
    } catch {
      el.textContent = "Copy failed";
      return false;
    }
  },

  async "skill-vet"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    el.disabled = true;
    el.textContent = "Checking…";
    el.setAttribute("aria-busy", "true");
    setStatus("[data-skill-status]", "Checking…");
    try {
      await ctx.api.post(`/v1/admin/skills/${encodeURIComponent(id)}/vet`, {});
      await refreshS16(ctx);
    } catch (err) {
      el.disabled = false;
      el.textContent = "Run checks";
      el.setAttribute("aria-busy", "false");
      setStatus("[data-skill-status]", err?.message ?? "Checks failed to run");
    }
  },

  async "skill-override"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const reason = (document.querySelector("[data-skill-override-reason]")?.value ?? "").trim();
    if (!reason) {
      setStatus("[data-skill-status]", "Add a reason first. It is saved in the activity log.");
      return;
    }
    setStatus("[data-skill-status]", "Saving…");
    try {
      await ctx.api.post(`/v1/admin/skills/${encodeURIComponent(id)}/override`, { reason });
      await refreshS16(ctx);
    } catch (err) {
      setStatus("[data-skill-status]", err?.message ?? "Could not save");
    }
  },

  async "skill-retire"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    // Retiring pulls the skill from every agent that uses it, so the click is
    // confirmed once rather than firing straight off a same-size button.
    if (el.getAttribute("data-confirm") !== "yes") {
      el.setAttribute("data-confirm", "yes");
      el.textContent = "Retire for everyone?";
      setStatus("[data-skill-status]", "Agents lose this skill. Click again to confirm.");
      return;
    }
    setStatus("[data-skill-status]", "Retiring…");
    try {
      await ctx.api.post(`/v1/admin/skills/${encodeURIComponent(id)}/retire`, {});
      selectedSkillId = null;
      await refreshS16(ctx);
    } catch (err) {
      el.setAttribute("data-confirm", "no");
      el.textContent = "Retire";
      setStatus("[data-skill-status]", err?.message ?? "Retire failed");
    }
  },
};
