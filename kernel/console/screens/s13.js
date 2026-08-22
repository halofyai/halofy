import { organizationScopeLabel, personDisplayName } from "../identity-labels.js";

/**
 * S13 — Teams. Humans and organization roles only; agents remain in S3.
 * The renderer mirrors the v2 Teams prototype while keeping authority at the
 * Teams v2 lifecycle reads and mutations stay server-resolved and audited.
 */

let selectedTeamId = null;
let teamsView = "team";
let peopleTab = "members";
let membersPage = 0;
let lastTeamInvite = null;
let undoRemoval = null;

const MEMBERS_PAGE_SIZE = 6;
const HUMAN_ROLES = ["owner", "admin", "auditor", "member"];
const ROLE_REFERENCE_ROLES = ["owner", "admin", "member"];
const ASSIGNABLE_ROLES = ["root", "admin", "member"];
const ROLE_COPY = Object.freeze({
  owner: {
    label: "Owner",
    scope: "Exactly one active owner, organization-wide",
    detail: "Full control of teams, membership, roles, access, and organization settings.",
  },
  admin: {
    label: "Admin",
    scope: "Organization-wide",
    detail: "Manages teams, people, and invitations. Cannot change the Owner.",
  },
  auditor: {
    label: "Auditor",
    scope: "Read only",
    detail: "Reviews teams and access without changing organization state.",
  },
  member: {
    label: "Member",
    scope: "Assigned teams",
    detail: "Works in assigned teams and uses the memory granted to those teams.",
  },
});
const PERMISSION_LABELS = Object.freeze({
  "teams:read": "View teams",
  "teams:write": "Create teams",
  "members:invite": "Invite people",
  "members:write": "Manage members",
  "roles:write": "Assign roles",
});

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

function canAssignRoles(ctx) {
  return Boolean(ctx.identity && (ctx.identity.role === "owner" || ctx.identity.role === "root"));
}

function canArchive(ctx) {
  return Boolean(ctx.identity && (ctx.identity.role === "owner" || ctx.identity.role === "root"));
}

export async function render(ctx) {
  let teams;
  let directory;
  try {
    [teams, directory] = await Promise.all([
      ctx.api.get("/v1/admin/teams"),
      ctx.api.get("/v1/admin/team-directory"),
    ]);
  } catch (err) {
    return errorScreen(ctx, err);
  }
  if (!Array.isArray(teams)) teams = [];
  if (!directory || typeof directory !== "object") directory = { users: [] };
  const users = Array.isArray(directory.users) ? directory.users : [];
  const accessModel = normalizeAccessModel(directory.accessModel);
  const mutate = canMutate(ctx);
  const assignRoles = canAssignRoles(ctx);
  const archive = canArchive(ctx);

  restoreSelectedTeam();
  if (selectedTeamId && !teams.some((team) => team.id === selectedTeamId)) selectedTeamId = null;
  const selected = teams.find((team) => team.id === selectedTeamId) || teams[0] || null;
  if (selected) rememberSelectedTeam(selected.id);

  const org = organizationLabel(ctx);
  const activeView = teamsView === "people" ? "people" : "team";
  const newTeam = mutate
    ? `<button class="btn btn--solid btn--sm" data-action="team-modal-open" data-modal-target="team-create-modal"
        aria-controls="team-create-modal" aria-expanded="false" aria-haspopup="dialog">New Team</button>`
    : "";

  return `<section class="teams-v2">
    <header class="head teams-v2__head">
      <div class="teams-v2__title">
        <div class="teams-v2__title-row"><h1>Teams</h1>
          <span class="teams-info" title="A team is a memory scope" aria-label="A team is a memory scope">${infoIcon()}</span></div>
      </div>
      <div class="acts teams-v2__head-actions">
        <div class="teams-segmented" role="tablist" aria-label="Teams view">
          ${viewButton("team", "By Team", activeView === "team")}
          ${viewButton("people", "All People", activeView === "people")}
        </div>
        ${newTeam}
      </div>
    </header>
    ${lastTeamInvite ? inviteResultBanner(ctx) : ""}
    ${teams.length === 0
      ? emptyTeams(ctx, mutate)
      : activeView === "people"
        ? allPeopleView(ctx, teams, selected, users, mutate, assignRoles, org)
        : byTeamView(ctx, teams, selected, users, mutate, assignRoles, archive)}
    ${mutate ? teamForm(ctx) : ""}
    ${selected && mutate ? teamMemberDialog(ctx, selected, users, teams) : ""}
    ${selected && mutate ? invitePersonDialog(ctx, selected) : ""}
    ${selected && mutate ? renameTeamDialog(ctx, selected) : ""}
    ${selected && mutate ? invitationActionDialog(ctx) : ""}
    ${rolesDialog(ctx, accessModel)}
    ${mutate ? suspendDialog(ctx) : ""}
  </section>`;
}

function viewButton(id, label, active) {
  return `<button class="teams-segmented__item${active ? " is-active" : ""}" role="tab"
    aria-selected="${active ? "true" : "false"}" data-action="teams-view" data-view="${id}">${label}</button>`;
}

function emptyTeams(ctx, mutate) {
  return `<div class="card teams-empty">
    <span class="teams-empty__mark" aria-hidden="true">T</span>
    <h2>No teams yet</h2>
    <p>${mutate
      ? "Create the first team to give people a shared, permanent memory address."
      : "No teams are visible in this organization."}</p>
    ${mutate ? `<button class="btn btn--solid" data-action="team-modal-open" data-modal-target="team-create-modal"
      aria-controls="team-create-modal" aria-expanded="false" aria-haspopup="dialog">Create a team</button>` : ""}
  </div>`;
}

function byTeamView(ctx, teams, selected, users, mutate, assignRoles, archive) {
  return `<div class="teams-v2__flow">
    ${teamSelector(ctx, teams, selected)}
    ${selected ? teamOverview(ctx, selected, mutate, archive) : ""}
    ${selected ? membersCard(ctx, selected, teams, users, mutate, assignRoles) : ""}
    ${selected ? waitingCard(ctx, selected, mutate && !isArchived(selected)) : ""}
  </div>`;
}

function teamSelector(ctx, teams, selected) {
  const active = teams.filter((team) => !isArchived(team));
  const archived = teams.filter(isArchived);
  const count = selected && Array.isArray(selected.members) ? selected.members.length : 0;
  return `<div class="teams-selector">
    <button class="teams-selector__trigger" data-action="team-selector-toggle" aria-haspopup="listbox"
      aria-expanded="false" aria-controls="team-selector-panel">
      <span class="teams-selector__value"><span class="teams-selector__trigger-label">Team</span>
        <span class="teams-selector__trigger-meta"><b>${ctx.esc(selected ? selected.name : "Choose a team")}</b>
          <small>${selected ? `· ${count} Member${count === 1 ? "" : "s"}` : "· No team selected"}</small></span></span>
      <span class="teams-selector__chevron" aria-hidden="true">${chevronIcon()}</span>
    </button>
    <button class="teams-selector__backdrop" data-action="team-selector-close" aria-label="Close team picker" hidden></button>
    <div class="teams-selector__panel" id="team-selector-panel" role="listbox" hidden>
      <label class="teams-selector__search">${searchIcon()}<span class="sr-only">Search teams</span>
        <input class="input" type="search" placeholder="Search teams" autocomplete="off"
          data-input-action="team-selector-search" aria-label="Search teams"></label>
      <div class="teams-selector__list">${active.map((team) => selectorOption(ctx, team, selected)).join("")}</div>
      ${archived.length ? `<details class="teams-selector__archived"><summary>Archived (${archived.length})</summary>
        <div class="teams-selector__list">${archived.map((team) => selectorOption(ctx, team, selected, true)).join("")}</div></details>` : ""}
    </div>
  </div>`;
}

function selectorOption(ctx, team, selected, archived = false) {
  const members = Array.isArray(team.members) ? team.members : [];
  const waiting = inviteCount(team);
  const label = String(team.name || "Team");
  return `<button class="teams-selector__option${archived ? " is-archived" : ""}"
    data-action="team-select" data-id="${ctx.esc(team.id || "")}" data-team-name="${ctx.esc(label.toLowerCase())}"
    role="option" aria-selected="${selected && selected.id === team.id ? "true" : "false"}">
    <span class="teams-selector__option-copy"><b>${ctx.esc(label)}</b><small>${members.length} member${members.length === 1 ? "" : "s"}</small></span>
    ${waiting !== null && waiting > 0 ? `<span class="pill pill--warn">${waiting} waiting</span>` : ""}
    ${archived ? `<span class="teams-selector__archive-icon" aria-hidden="true">${archiveIcon()}</span>` : ""}
  </button>`;
}

function teamOverview(ctx, team, mutate, archive) {
  const members = Array.isArray(team.members) ? team.members : [];
  const archived = isArchived(team);
  return `<article class="card teams-overview${archived ? " is-archived" : ""}">
    ${archived ? `<div class="teams-archived-banner"><b>This team is archived.</b>
      The roster and its memory are kept, but nothing can change until it is unarchived.</div>` : ""}
    <div class="teams-overview__primary">
      <div class="teams-overview__identity">
        <div class="teams-overview__title-row"><h2>${ctx.esc(team.name || "Team")}</h2>
          ${mutate && !archived ? `<button class="teams-icon-button" type="button" data-action="team-modal-open"
            data-modal-target="team-rename-modal" aria-label="Rename ${ctx.esc(team.name || "team")}">${editIcon()}</button>` : ""}
        </div>
        <p>${ctx.esc(team.description || "Shared memory scope.")}</p>
      </div>
      <div class="teams-overview__controls">
        ${archive ? `<button class="btn btn--ghost btn--sm teams-archive-button" type="button"
          data-action="team-archive" data-team="${ctx.esc(team.id || "")}" data-archived="${archived}">
          ${archived ? "Restore" : "Archive"}</button>` : ""}
        ${teamMemoryAccess(ctx, team, mutate && !archived)}
      </div>
    </div>
    <div class="teams-meta-strip">
      <div class="teams-meta-strip__address"><span>Address
        <span class="teams-meta-info" title="Memory is filed under it, so it never changes — even if you rename the team.">${infoIcon()}</span></span>
        <b class="mono"><span class="teams-address-lock" aria-hidden="true">${lockIcon()}</span> ${ctx.esc(scopeLabel(ctx, team.namespace))}</b></div>
      <div><span>Created By</span><b>${ctx.esc(personDisplayName(team.createdBy, ctx.personLabel, "human") || "Unavailable")}</b></div>
      <div><span>Created On</span><b>${ctx.esc(formatWhen(team.createdAt))}</b></div>
      <div><span>Members</span><b>${members.length}</b></div>
    </div>
  </article>`;
}

function teamMemoryAccess(ctx, team, mutate) {
  const access = team && team.memoryAccess && typeof team.memoryAccess === "object" ? team.memoryAccess : {};
  const mode = access.mode === "company-published" ? "company-published" : "related";
  const enabled = mode === "company-published";
  const canChange = mutate && (enabled ? access.canTighten === true : access.canBroaden === true);
  return `<section class="teams-memory-access" aria-labelledby="team-memory-access-title">
    <div class="teams-memory-access__copy">
      <h3 id="team-memory-access-title">Company-Wide Memory<span class="sr-only"> — Company memory</span></h3>
      <p id="team-memory-access-description">${memoryAccessDescription(mode)}</p>
    </div>
    <label class="toggle teams-memory-access__toggle">
      <input type="checkbox" role="switch" data-change-action="team-memory-access"
        data-team="${ctx.esc(team.id || "")}" data-current-mode="${mode}"
        aria-describedby="team-memory-access-description team-memory-access-status"
        ${enabled ? "checked" : ""} ${canChange ? "" : "disabled"}>
      <span class="track" aria-hidden="true"></span>
      <span>${enabled ? "Company-Wide" : "Team Only"}</span>
    </label>
    <span id="team-memory-access-status" class="hint teams-memory-access__status"
      role="status" aria-live="polite" aria-atomic="true">${canChange ? "" : "Only authorized organization managers can change this."}</span>
  </section>`;
}

function membersCard(ctx, team, teams, users, mutate, assignRoles) {
  const members = Array.isArray(team.members) ? team.members : [];
  const userByEmail = new Map(users.map((user) => [normalizeEmail(user.email), user]));
  const archived = isArchived(team);
  const lastPage = Math.max(0, Math.ceil(members.length / MEMBERS_PAGE_SIZE) - 1);
  const page = Math.min(Math.max(0, membersPage), lastPage);
  const pageStart = page * MEMBERS_PAGE_SIZE;
  const visibleMembers = members.slice(pageStart, pageStart + MEMBERS_PAGE_SIZE);
  const firstVisible = members.length ? pageStart + 1 : 0;
  const lastVisible = pageStart + visibleMembers.length;
  return `<article class="card teams-directory-card teams-card">
    <div class="teams-card-head teams-card-head--compact">
      <div class="teams-members-title"><h2>Members</h2>
        <button class="teams-role-help" data-action="team-modal-open" data-modal-target="team-roles-modal"
          aria-controls="team-roles-modal" aria-expanded="false" aria-haspopup="dialog">What Can Each Role Do?</button></div>
      ${mutate && !archived ? `<div class="teams-card-actions">
        <button class="btn btn--ghost btn--sm" data-action="team-modal-open" data-modal-target="team-member-modal"
          aria-controls="team-member-modal" aria-expanded="false" aria-haspopup="dialog">Add Existing Member</button>
        <button class="btn btn--ghost btn--sm teams-invite-button" data-action="team-modal-open" data-modal-target="team-invite-modal"
          aria-controls="team-invite-modal" aria-expanded="false" aria-haspopup="dialog"><span aria-hidden="true">${plusIcon()}</span> Invite Person</button>
      </div>` : ""}
    </div>
    ${undoBar(ctx, team)}
    <div class="teams-table-scroll"><div class="teams-members-grid__canvas" role="table" aria-label="${ctx.esc(team.name || "Team")} members">
      <div class="teams-members-grid__head" role="row"><span role="columnheader">Person</span>
        <span role="columnheader" title="Roles apply across the whole organization">Role</span>
        <span role="columnheader" title="Other teams this person belongs to">Also In</span>
        <span role="columnheader">Last Seen</span><span role="columnheader">Status</span>
        <span role="columnheader"><span class="sr-only">Actions</span></span></div>
      <div class="teams-members-grid__body" role="rowgroup">${visibleMembers.length
        ? visibleMembers.map((member) => rosterRow(ctx, team, teams, member, userByEmail.get(normalizeEmail(member.email)), mutate && !archived, assignRoles)).join("")
        : `<div class="teams-members-grid__empty">No one is in this team yet. Invite someone to get started.</div>`}</div>
    </div></div>
    <div class="teams-members-footer">
      <span>${firstVisible}–${lastVisible} of ${members.length} Members</span>
      <div class="teams-members-pagination" aria-label="Member pages">
        <button class="teams-members-page-button" data-action="team-members-page" data-page="${page - 1}"
          aria-label="Previous member page" ${page === 0 ? "disabled" : ""}>‹</button>
        <button class="teams-members-page-button" data-action="team-members-page" data-page="${page + 1}"
          aria-label="Next member page" ${page >= lastPage ? "disabled" : ""}>›</button>
      </div>
    </div>
    ${assignRoles ? '<div class="hint teams-action-status" id="team-role-status" role="status" aria-live="polite"></div>' : ""}
  </article>`;
}

function rosterRow(ctx, team, teams, member, directoryUser, mutate, assignRoles) {
  const email = String(member.email || "");
  const person = directoryUser || member;
  const name = memberDisplayLabel(ctx, person);
  const status = String(directoryUser && directoryUser.status || "active").toLowerCase();
  const suspended = status === "disabled" || status === "suspended";
  const role = publicRole(member.role || directoryUser && directoryUser.role);
  const owner = role === "root";
  const otherTeams = teamsForEmail(teams, email).filter((item) => item.id !== team.id);
  const actorIsTarget = normalizeEmail(ctx.identity && ctx.identity.actor) === normalizeEmail(email);
  return `<div class="teams-members-grid__row${suspended ? " is-suspended" : ""}" role="row" data-person-row
    data-filter-text="${ctx.esc(`${name} ${email} ${otherTeams.map((item) => item.name).join(" ")}`.toLowerCase())}">
    <div role="cell">${personCell(ctx, person, name, email, "teams-person--member")}</div>
    <div role="cell">${assignRoles && !owner && !suspended ? roleSelect(ctx, team, member) : rolePill(ctx, role, member)}</div>
    <div role="cell">${rosterTeamsSummary(ctx, otherTeams)}</div>
    <div class="teams-member-last-seen" role="cell">${lastSeen(directoryUser)}</div>
    <div role="cell">${statusPill(suspended ? "suspended" : "active")}</div>
    <div role="cell">${owner ? protectedLabel()
      : suspended && mutate ? `<button class="btn btn--ghost btn--sm" data-action="person-reinstate"
          data-user="${ctx.esc(member.userId || "")}">Reinstate</button>`
      : suspended ? `<span class="teams-action-spacer" aria-hidden="true"></span>`
      : mutate ? `<div class="teams-row-actions">
          <button class="btn btn--ghost btn--sm" title="This team only — they keep their account and other teams"
            data-action="team-member-remove" data-team="${ctx.esc(team.id)}" data-user="${ctx.esc(member.userId || "")}"
            data-email="${ctx.esc(email)}" data-name="${ctx.esc(name)}">Remove</button>
          ${actorIsTarget ? `<span class="teams-action-spacer" aria-hidden="true"></span>` : personActionMenu(ctx, {
            userId: member.userId,
            name,
            email,
            teams: teamsForEmail(teams, email),
          })}
        </div>` : `<span class="teams-action-spacer" aria-hidden="true"></span>`}</div>
  </div>`;
}

function rosterTeamsSummary(ctx, teams) {
  if (!teams.length) return `<span class="teams-only-here">Only Here</span>`;
  const names = teams.map((item) => String(item.name || "Team"));
  return `<div class="teams-roster-memberships" title="${ctx.esc(names.join(", "))}">
    <span class="teams-team-pill">${ctx.esc(names[0])}</span>
    ${names.length > 1 ? `<span class="teams-team-more">+${names.length - 1}</span>` : ""}</div>`;
}

function allPeopleView(ctx, teams, selected, users, mutate, assignRoles, org) {
  const tab = peopleTab === "waiting" ? "waiting" : "members";
  const members = dedupePeople(users, teams);
  const invitations = organizationInvitations(teams);
  const invitationCount = invitations.filter((invite) => invite.status !== "revoked").length;
  return `<article class="card teams-people-card">
    <div class="teams-people-intro"><h2>People</h2>
      <p>Manage people at ${ctx.esc(org)} and their roles.
        <button class="teams-inline-link" data-action="team-modal-open" data-modal-target="team-roles-modal"
          aria-controls="team-roles-modal" aria-expanded="false" aria-haspopup="dialog">What can each role do?</button></p>
    </div>
    <div class="teams-people-tools">
      <div class="teams-subtabs" role="tablist" aria-label="People status">
        <button role="tab" aria-selected="${tab === "members"}" class="${tab === "members" ? "is-active" : ""}"
          data-action="people-tab" data-tab="members">Members <span>${members.length}</span></button>
        <button role="tab" aria-selected="${tab === "waiting"}" class="${tab === "waiting" ? "is-active" : ""}"
          data-action="people-tab" data-tab="waiting">Waiting To Join <span>${invitationCount}</span></button>
      </div>
      <div class="teams-people-toolbar-actions">
        <label class="teams-people-search"><span class="sr-only">Search people or teams</span>
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"></circle><path d="m16 16 4 4"></path></svg>
          <input type="search" placeholder="Search people or teams" autocomplete="off"
            data-input-action="people-search" aria-label="Search people or teams"></label>
        ${mutate && selected ? `<button class="btn btn--solid btn--sm teams-people-add" data-action="team-modal-open" data-modal-target="team-invite-modal"
          aria-controls="team-invite-modal" aria-expanded="false" aria-haspopup="dialog">Add Members</button>` : ""}
      </div>
    </div>
    ${tab === "waiting" ? invitationsTable(ctx, invitations, mutate, true) : peopleTable(ctx, teams, members, mutate, assignRoles)}
    ${assignRoles ? '<div class="hint teams-action-status" id="team-role-status" role="status" aria-live="polite"></div>' : ""}
  </article>`;
}

function peopleTable(ctx, teams, people, mutate, assignRoles) {
  return `<div class="teams-table-scroll"><div class="teams-people-grid__canvas" role="table" aria-label="Organization people">
    <div class="teams-people-grid__head" role="row"><span role="columnheader">Person</span><span role="columnheader">Role</span>
      <span role="columnheader">Teams</span><span role="columnheader">Last Seen</span><span role="columnheader">Status</span><span role="columnheader"><span class="sr-only">Actions</span></span></div>
    <div class="teams-people-grid__body" role="rowgroup">${people.length
      ? people.map((person) => personRow(ctx, teams, person, mutate, assignRoles)).join("")
      : `<div role="row" class="teams-people-grid__empty"><span role="cell">No people match this organization view.</span></div>`}</div>
  </div></div>`;
}

function personRow(ctx, teams, person, mutate, assignRoles) {
  const personTeams = teamsForEmail(teams, person.email);
  const teamForRole = personTeams[0] || null;
  const role = publicRole(person.role);
  const owner = role === "root";
  const suspended = String(person.status || "active").toLowerCase() === "disabled";
  const name = memberDisplayLabel(ctx, person);
  const actorIsTarget = normalizeEmail(ctx.identity && ctx.identity.actor) === normalizeEmail(person.email);
  return `<div class="teams-people-grid__row${suspended ? " is-suspended" : ""}" role="row" data-person-row
    data-filter-text="${ctx.esc(`${name} ${person.email || ""} ${personTeams.map((team) => team.name).join(" ")}`.toLowerCase())}">
    <div role="cell">${personCell(ctx, person, name, String(person.email || ""), "teams-person--directory")}</div>
    <div role="cell">${assignRoles && !owner && !suspended && teamForRole
      ? roleSelect(ctx, teamForRole, { ...person, userId: person.id })
      : rolePill(ctx, role, person)}</div>
    <div role="cell">${peopleTeamsSummary(ctx, personTeams, name)}</div>
    <div role="cell" class="teams-people-last-seen">${lastSeen(person)}</div>
    <div role="cell">${statusPill(suspended ? "suspended" : "active")}</div>
    <div role="cell" class="teams-people-row-actions">${owner ? protectedLabel()
      : suspended && mutate ? `<button class="btn btn--ghost btn--sm" data-action="person-reinstate"
          data-user="${ctx.esc(person.id || "")}">Reinstate</button>`
      : suspended ? `<span class="teams-action-spacer" aria-hidden="true"></span>`
      : mutate && !actorIsTarget ? personActionMenu(ctx, {
        userId: person.id,
        name,
        email: person.email,
        teams: personTeams,
      })
      : `<span class="teams-action-spacer" aria-hidden="true"></span>`}</div>
  </div>`;
}

function personActionMenu(ctx, person) {
  const teams = Array.isArray(person.teams) ? person.teams : [];
  return `<div class="teams-person-menu">
    <button class="teams-kebab" aria-label="More actions for ${ctx.esc(person.name)}" aria-haspopup="menu" aria-expanded="false"
      data-action="person-action-toggle">⋯</button>
    <button class="teams-person-menu__backdrop" data-action="person-action-close" aria-label="Close actions menu" hidden></button>
    <div class="teams-person-menu__popover" role="menu" hidden>
      <button role="menuitem" data-action="person-suspend-open" data-user="${ctx.esc(person.userId || "")}" data-name="${ctx.esc(person.name)}"
        data-email="${ctx.esc(person.email || "")}" data-teams="${ctx.esc(teams.map((team) => team.name).join(", "))}">Suspend Access…</button>
    </div>
  </div>`;
}

function protectedLabel() {
  return `<span class="teams-protected" title="You can't suspend yourself, and every organization needs an active owner.">${lockIcon()} Protected</span>`;
}

function waitingCard(ctx, team, mutate) {
  const invitations = Array.isArray(team.invitations) ? team.invitations : [];
  const pending = invitations.filter((invite) => invite.status === "waiting" || invite.status === "expired")
    .map((invite) => ({ ...invite, teamId: team.id, teamName: team.name }));
  const history = invitations.filter((invite) => invite.status === "joined" || invite.status === "revoked")
    .map((invite) => ({ ...invite, teamId: team.id, teamName: team.name }));
  return `<article class="card teams-waiting-card">
    <div class="teams-waiting-title"><h2>Waiting To Join</h2>
      <span title="People invited to this team who haven't made it in yet. Invite links expire after 7 days." aria-label="Pending invitation help">${infoIcon()}</span></div>
    ${invitationsTable(ctx, pending, mutate, false)}
    ${history.length ? `<details class="teams-invitation-history"><summary>Invitation history (${history.length})</summary>
      ${invitationsTable(ctx, history, false, false)}</details>` : ""}
  </article>`;
}

function organizationInvitations(teams) {
  return teams.flatMap((team) => (Array.isArray(team.invitations) ? team.invitations : [])
    .map((invite) => ({ ...invite, teamId: team.id, teamName: team.name })));
}

function invitationsTable(ctx, invitations, mutate, showTeam) {
  if (!invitations.length) return `<div class="teams-invitations-empty" role="status">No one is waiting. Everyone you invited is in.</div>`;
  return `<div class="teams-table-scroll"><div class="teams-invitations-grid__canvas ${showTeam ? "teams-invitations-grid__canvas--org" : "teams-invitations-grid__canvas--team"}"
    role="table" aria-label="${showTeam ? "Organization invitations" : "Team invitations"}">
    <div class="teams-invitations-grid__head" role="row"><span role="columnheader">Invited Email</span>
      ${showTeam ? '<span role="columnheader">Team</span>' : ""}<span role="columnheader">State</span>
      <span role="columnheader">When</span><span role="columnheader"><span class="sr-only">Actions</span></span></div>
    <div class="teams-invitations-grid__body" role="rowgroup">${invitations.map((invite) => invitationRow(ctx, invite, mutate, showTeam)).join("")}</div>
  </div></div>`;
}

function invitationRow(ctx, invite, mutate, showTeam) {
  const status = String(invite.status || "waiting");
  const action = status === "waiting" ? "reminder" : status === "expired" ? "reinvite" : null;
  const historical = status === "joined" || status === "revoked";
  return `<div class="teams-invitations-grid__row${historical ? " is-history" : ""}" role="row" data-invitation-row
    data-filter-text="${ctx.esc(`${invite.displayName || ""} ${invite.email || ""} ${invite.teamName || ""}`.toLowerCase())}">
    <div class="teams-invite-email" role="cell"><b>${ctx.esc(invite.displayName || "Invited person")}</b><small>${ctx.esc(invite.email || "Unavailable")}</small></div>
    ${showTeam ? `<div class="teams-invite-team" role="cell">${ctx.esc(invite.teamName || "Team")}</div>` : ""}
    <div role="cell">${invitationStatusPill(status)}</div>
    <div class="teams-invite-when" role="cell">${ctx.esc(formatWhen(invite.createdAt))}</div>
    <div class="teams-invite-actions" role="cell">${mutate && action ? `<div class="teams-row-actions">
      <button class="btn btn--ghost btn--sm" data-action="team-invite-action-open"
        data-team="${ctx.esc(invite.teamId || "")}" data-invitation="${ctx.esc(invite.id || "")}" data-kind="${action}"
        data-email="${ctx.esc(invite.email || "")}">${action === "reminder" ? "Send Reminder" : "Re-Invite"}</button>
      <button class="btn btn--ghost btn--sm" data-action="team-invite-revoke"
        data-team="${ctx.esc(invite.teamId || "")}" data-invitation="${ctx.esc(invite.id || "")}">Revoke</button>
    </div>` : `<span class="teams-history-label">History</span>`}</div>
  </div>`;
}

function undoBar(ctx, team) {
  if (!undoRemoval || undoRemoval.teamId !== team.id) return "";
  return `<div class="teams-undo" role="status" aria-live="polite">
    <span><b>${ctx.esc(undoRemoval.name)}</b> removed from ${ctx.esc(team.name)}. They keep their account and other teams and can be re-added.</span>
    <button data-action="team-member-undo">Undo</button>
    <button data-action="team-member-undo-dismiss" aria-label="Dismiss removal message">×</button>
  </div>`;
}

function personCell(ctx, person, name, email, className = "") {
  const avatar = typeof ctx.personAvatar === "function"
    ? ctx.personAvatar(person, "human")
    : `<span class="teams-avatar" aria-hidden="true">${ctx.esc(initial(name))}</span>`;
  return `<div class="teams-person${className ? ` ${className}` : ""}">${avatar}<span><b>${ctx.esc(name)}</b><small>${ctx.esc(email || "Unavailable")}</small></span></div>`;
}

function roleSelect(ctx, team, member) {
  const current = publicRole(member.role);
  const options = ASSIGNABLE_ROLES.includes(current) ? ASSIGNABLE_ROLES : [current, ...ASSIGNABLE_ROLES];
  const userId = member.userId || member.id || "unknown";
  return `<label class="sr-only" for="team-role-${ctx.esc(userId)}">Role for ${ctx.esc(personDisplayName(member, ctx.personLabel) || "member")}</label>
    <select class="select teams-role-select" id="team-role-${ctx.esc(userId)}"
      title="Roles apply across the whole organization, not just this team."
      data-action="team-member-role" data-change-action="team-member-role"
      data-team="${ctx.esc(team.id || "")}" data-user="${ctx.esc(userId)}" data-current-role="${ctx.esc(current)}">
      ${options.map((role) => `<option value="${ctx.esc(role)}"${role === current ? " selected" : ""}>${ctx.esc(roleLabel(role))}</option>`).join("")}
    </select>${auditBadge(ctx, member)}`;
}

function rolePill(ctx, role, member) {
  return `<span class="badge badge--role">${ctx.esc(roleLabel(role))}</span>${auditBadge(ctx, member)}`;
}

function auditBadge(ctx, member) {
  const entitlements = Array.isArray(member && member.entitlements) ? member.entitlements : [];
  return entitlements.includes("audit:read") ? ` <span class="pill">Audit access</span>` : "";
}

function teamsSummary(ctx, teams, name) {
  if (!teams.length) return `<span class="subtle">No teams yet</span>`;
  if (teams.length === 1) return `<span>${ctx.esc(teams[0].name || "Team")}</span>`;
  const id = `person-teams-${safeId(name)}`;
  return `<div class="teams-memberships"><button data-action="person-teams-toggle" aria-expanded="false" aria-controls="${id}">
      ${teams.length} Teams <span aria-hidden="true">⌄</span></button>
    <div class="teams-memberships__popover" id="${id}" hidden>${teams.map((team) => `<span>${ctx.esc(team.name || "Team")}</span>`).join("")}</div></div>`;
}

function peopleTeamsSummary(ctx, teams, name) {
  if (!teams.length) return `<span class="subtle">No teams yet</span>`;
  const id = `people-teams-${safeId(name)}`;
  const count = `${teams.length} Team${teams.length === 1 ? "" : "s"}`;
  return `<div class="teams-memberships teams-memberships--people"><button data-action="person-teams-toggle" aria-expanded="false" aria-controls="${id}">
      ${count} <span aria-hidden="true">⌄</span></button>
    <div class="teams-memberships__popover" id="${id}" hidden>${teams.map((team) => `<span>${ctx.esc(team.name || "Team")}</span>`).join("")}</div></div>`;
}

function statusPill(status) {
  if (status === "suspended") return `<span class="pill pill--danger">Suspended</span>`;
  if (status === "expired") return `<span class="pill pill--warn">Expired</span>`;
  if (status === "revoked") return `<span class="pill pill--muted">Revoked</span>`;
  if (status === "joined") return `<span class="pill pill--live">Joined</span>`;
  if (status === "waiting") return `<span class="pill pill--warn">Waiting</span>`;
  return `<span class="pill pill--live">Active</span>`;
}

function invitationStatusPill(status) {
  if (status === "expired") return `<span class="pill pill--warn" title="The link timed out before they used it.">Invite Expired</span>`;
  if (status === "joined") return `<span class="pill pill--live" title="Their account exists but they have never signed in.">Joined · Never Signed In</span>`;
  if (status === "revoked") return `<span class="pill pill--muted" title="This invite was cancelled. Kept for history.">Revoked</span>`;
  return `<span class="pill pill--warn" title="Link sent, not accepted yet. Expires 7 days after sending.">Invited · Waiting</span>`;
}

function lastSeen(person) {
  if (person && typeof person.lastSeen === "string" && person.lastSeen) return escapeStatic(formatLastSeen(person.lastSeen));
  if (person && Object.prototype.hasOwnProperty.call(person, "lastSeen") && person.lastSeen === null) {
    return `<span class="teams-never">Never Signed In</span>`;
  }
  return `<span class="teams-unavailable-text">Unavailable</span>`;
}

function formatLastSeen(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  const now = new Date();
  const day = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const seenDay = new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
  const days = Math.max(0, Math.round((day - seenDay) / 86_400_000));
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days}d Ago`;
  return formatWhen(value);
}

function teamMemberDialog(ctx, team, users, teams) {
  const memberEmails = new Set((team.members || []).map((member) => normalizeEmail(member.email)));
  const addable = users.filter((user) => String(user.status || "active").toLowerCase() === "active" && !memberEmails.has(normalizeEmail(user.email)));
  return `<dialog class="console-modal teams-modal" id="team-member-modal" role="dialog" aria-modal="true" aria-labelledby="team-member-title">
    ${modalHeader("Team Access", "team-member-title", "Add Existing Member", "Return to teams")}
    <div class="console-modal__body">
      <p class="subtle">Add an organization member to <b>${ctx.esc(team.name || "this team")}</b>. Their account and other teams do not change.</p>
      <div class="teams-addable-list">${addable.length ? addable.map((user) => {
        const name = memberDisplayLabel(ctx, user);
        const other = teamsForEmail(teams, user.email).map((item) => item.name);
        return `<div class="teams-addable-person">${personCell(ctx, user, name, user.email)}
          <span class="subtle">${other.length ? `Already in ${ctx.esc(other.join(", "))}` : "No teams yet"}</span>
          <button class="btn btn--ghost btn--sm" data-action="team-member-add" data-team="${ctx.esc(team.id)}"
            data-email="${ctx.esc(user.email || "")}">Add</button></div>`;
      }).join("") : `<div class="teams-table-empty">Everyone at ${ctx.esc(organizationLabel(ctx))} is already in this team. Invite someone new instead.</div>`}</div>
      <div class="console-modal__actions"><span class="hint teams-action-status" id="team-member-status" role="status" aria-live="polite"></span>
        <button class="btn btn--ghost" data-action="team-modal-close">Close</button></div>
    </div>
  </dialog>`;
}

function invitePersonDialog(ctx, team) {
  const role = ctx.identity && ctx.identity.role;
  const roles = role === "owner" || role === "root" ? ASSIGNABLE_ROLES : ASSIGNABLE_ROLES.filter((value) => value !== "root");
  return `<dialog class="console-modal teams-modal" id="team-invite-modal" role="dialog" aria-modal="true" aria-labelledby="team-invite-title">
    ${modalHeader("Team Access", "team-invite-title", "Invite Person", "Return to teams")}
    <div class="console-modal__body">
      <p class="subtle">Create a one-time link for <b>${ctx.esc(team.name || "this team")}</b>. The server resolves the permanent team address.</p>
      <div class="field"><label for="team-invite-name">Name</label>
        <input class="input" id="team-invite-name" type="text" placeholder="Person name" autocomplete="name" maxlength="80" required
          data-modal-focus></div>
      <div class="field"><label for="team-invite-email">Email</label>
        <input class="input" id="team-invite-email" type="email" placeholder="person@org.co" autocomplete="email"
          data-input-action="team-invite-email"></div>
      <div class="field"><label for="team-invite-role">Organization role</label>
        <select class="select" id="team-invite-role">${roles.map((value) => `<option value="${value}"${value === "member" ? " selected" : ""}>${roleLabel(value)}</option>`).join("")}</select>
        <small>Roles apply across the whole organization, not just this team.</small></div>
      <div class="teams-delivery-options">
        <div class="teams-delivery-option is-disabled"><span>Email The Invite</span><small>Coming Soon</small></div>
        <div class="teams-delivery-option is-active"><span>Copy An Invite Link</span><small>Available now</small></div>
      </div>
      <div class="teams-invite-result" id="team-invite-result" hidden>
        <b>Copy this invitation link now</b><p>This link is shown once — it can't be retrieved later. Copy it before you close this panel.</p>
        <div class="snippet" id="team-invite-url"></div>
        <button class="btn btn--ghost btn--sm" data-action="team-invite-copy">Copy link</button>
        <span class="hint" id="team-invite-copy-status" role="status" aria-live="polite"></span>
      </div>
      <div class="console-modal__actions"><span class="hint" id="team-invite-status" role="status" aria-live="polite"></span>
        <button class="btn btn--ghost" data-action="team-modal-close">Cancel</button>
        <button class="btn btn--solid" data-action="team-invite-submit" data-team="${ctx.esc(team.id || "")}">Create invite link</button></div>
    </div>
  </dialog>`;
}

function inviteResultBanner(ctx) {
  return `<div class="teams-invite-banner" role="status" aria-live="polite"><span><b>Invitation link created for ${ctx.esc(lastTeamInvite.email)}.</b>
      It is shown once and cannot be retrieved later.</span>
    <button class="btn btn--ghost btn--sm" data-action="team-invite-copy">Copy link</button>
    <button class="teams-undo__close" data-action="team-invite-dismiss" aria-label="Dismiss invitation link">×</button>
    <span id="team-invite-copy-status" class="hint"></span></div>`;
}

function rolesDialog(ctx, accessModel) {
  return `<dialog class="console-modal teams-modal" id="team-roles-modal" role="dialog" aria-modal="true" aria-labelledby="team-roles-title">
    ${modalHeader("Organization Access", "team-roles-title", "Roles & Permissions", "Return to teams")}
    <div class="console-modal__body"><p class="subtle">Roles apply across the whole organization. Enforced by the server.</p>
      <div class="teams-role-cards">${ROLE_REFERENCE_ROLES.map((role) => {
        const copy = ROLE_COPY[role];
        const permissions = accessModel ? accessModel[role] : null;
        return `<article class="teams-role-card"><div><h3>${ctx.esc(copy.label)}</h3><span>${ctx.esc(copy.scope)}</span></div>
          <p>${ctx.esc(copy.detail)}</p><small>${permissions
            ? permissions.length ? ctx.esc(permissions.map((item) => PERMISSION_LABELS[item] || item).join(" · ")) : "No control-room access"
            : "Permission detail unavailable"}</small></article>`;
      }).join("")}</div>
      <div class="console-modal__actions"><button class="btn btn--ghost" data-action="team-modal-close">Close</button></div>
    </div>
  </dialog>`;
}

function renameTeamDialog(ctx, team) {
  return `<dialog class="console-modal teams-modal" id="team-rename-modal" role="dialog" aria-modal="true" aria-labelledby="team-rename-title">
    ${modalHeader("Team", "team-rename-title", "Rename Team", "Return to teams")}
    <div class="console-modal__body">
      <div class="teams-rename-note"><b>The address will not change.</b><p>Renaming changes the label everywhere. The address ${ctx.esc(scopeLabel(ctx, team.namespace))} stays the same — memory is already filed under it.</p></div>
      <div class="field"><label for="team-rename-name">Team name</label>
        <input class="input" id="team-rename-name" value="${ctx.esc(team.name || "")}" data-modal-focus maxlength="80"></div>
      <div class="console-modal__actions"><span class="hint" id="team-rename-status" role="status" aria-live="polite"></span>
        <button class="btn btn--ghost" data-action="team-modal-close">Cancel</button>
        <button class="btn btn--solid" data-action="team-rename" data-team="${ctx.esc(team.id || "")}">Save Name</button></div>
    </div>
  </dialog>`;
}

function invitationActionDialog(ctx) {
  return `<dialog class="console-modal teams-modal" id="team-invite-action-modal" role="dialog" aria-modal="true" aria-labelledby="team-invite-action-title">
    ${modalHeader("Invitation", "team-invite-action-title", "Send Reminder", "Return to invitations")}
    <div class="console-modal__body">
      <p id="team-invite-action-copy">This creates a new invitation link and immediately invalidates the old one.</p>
      <div class="teams-callout"><b>Share the new link.</b><p>The previous link will stop working as soon as you confirm.</p></div>
      <div class="teams-invite-result" id="team-invite-action-result" hidden>
        <b>Copy this new invitation link now</b><p>This link is shown once — it can't be retrieved later. The previous link no longer works.</p>
        <div class="snippet" id="team-invite-action-url"></div>
        <button class="btn btn--ghost btn--sm" data-action="team-invite-copy">Copy link</button>
        <span class="hint" id="team-invite-action-copy-status" role="status" aria-live="polite"></span>
      </div>
      <div class="console-modal__actions"><span class="hint" id="team-invite-action-status" role="status" aria-live="polite"></span>
        <button class="btn btn--ghost" data-action="team-modal-close">Cancel</button>
        <button class="btn btn--solid" data-action="team-invite-action-done" hidden>Done</button>
        <button class="btn btn--solid" data-action="team-invite-action-confirm">Confirm</button></div>
    </div>
  </dialog>`;
}

function suspendDialog(ctx) {
  return `<dialog class="console-modal teams-modal teams-suspend-modal" id="team-suspend-modal" role="dialog" aria-modal="true" aria-labelledby="team-suspend-title">
    <div class="console-modal__head teams-suspend-head"><div>
      <span class="teams-suspend-kicker">Access · ${ctx.esc(organizationLabel(ctx))}</span>
      <h2 id="team-suspend-title">Suspend Access</h2>
      <p id="team-suspend-summary">Sign-in refused, live sessions killed, all memory access gone — everywhere, immediately. Reversible.</p>
    </div><button class="halo-icon-control teams-suspend-close" data-action="team-modal-close" aria-label="Close suspension drawer">
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
    </button></div>
    <div class="console-modal__body" aria-live="polite">
      <div class="teams-impact-loading"><p>Checking what this touches — live sessions, teams, agent keys…</p>
        <div class="teams-impact-skeletons" aria-hidden="true"><i></i><i></i><i></i></div></div>
      <div class="teams-suspend-impact" id="team-suspend-impact" hidden></div>
      <div class="teams-suspend-key-card" id="team-suspend-revoke-wrap" hidden>
        <div class="teams-suspend-impact__row"><b>Agent Keys They Created</b><span id="team-suspend-key-count">0 keys keep running</span></div>
        <label class="teams-checkbox"><input type="checkbox" id="team-suspend-revoke-keys">
          <span>Also revoke these keys. Agents using them stop working immediately — this can break live automations.</span></label>
      </div>
      <div class="teams-impact-warning" id="team-suspend-idp-warning" hidden></div>
      <div class="teams-unavailable teams-suspend-unavailable" hidden><span aria-hidden="true">—</span><div><b>Unavailable — try again</b>
        <p>Impact could not be loaded, so suspension stays disabled and never fires blind.</p></div></div>
      <div class="field"><label for="team-suspend-reason">Reason <span class="subtle">· Optional, kept in the audit record</span></label>
        <input class="input" id="team-suspend-reason" maxlength="500" placeholder="e.g. Left the company on 4 Aug" disabled></div>
    </div>
    <div class="console-modal__actions teams-suspend-footer"><span class="hint">Reversible — reinstate anytime.</span>
      <button class="btn btn--ghost" data-action="team-modal-close">Cancel</button>
      <button class="btn btn--danger" data-action="person-suspend-confirm" disabled>Suspend Access</button></div>
  </dialog>`;
}

function teamForm(ctx) {
  const ns = (ctx.identity && ctx.identity.namespace) || "";
  return `<dialog class="console-modal teams-modal" id="team-create-modal" role="dialog" aria-modal="true" aria-labelledby="team-form-title">
    ${modalHeader("Organization", "team-form-title", "Create A Team", "Return to teams")}
    <div class="console-modal__body" id="team-form">
      <p class="subtle">The name can change later. The permanent memory address cannot.</p>
      <div class="field"><label for="team-name">Team name</label>
        <input class="input" id="team-name" placeholder="Support" autocomplete="off" data-modal-focus data-input-action="team-name-preview"></div>
      <div class="field"><label for="team-description">Description <span class="subtle">(optional)</span></label>
        <input class="input" id="team-description" placeholder="Handles customer support" autocomplete="off"></div>
      <div class="teams-namespace-preview"><span>Permanent address</span>
        <b class="mono" data-team-ns-preview>${ns ? ctx.esc(ns) + "/…" : "…"}</b>
        <small>Memory gets filed under this address, so it can't change later. The name can.</small></div>
      <div class="console-modal__actions"><span class="hint" id="team-create-status" role="status" aria-live="polite"></span>
        <button class="btn btn--ghost" data-action="team-modal-close">Cancel</button>
        <button class="btn btn--solid" data-action="team-create">Create Team</button></div>
    </div>
  </dialog>`;
}

function modalHeader(eyebrow, titleId, title, closeLabel) {
  return `<div class="console-modal__head"><div><span class="eyebrow">${eyebrow}</span><h2 id="${titleId}">${title}</h2></div>
    <button class="halo-icon-control" data-action="team-modal-close" aria-label="${closeLabel}">${closeIcon()}</button></div>`;
}

function normalizeAccessModel(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
  const model = {};
  for (const role of HUMAN_ROLES) {
    if (!Array.isArray(candidate[role])) return null;
    model[role] = candidate[role].filter((permission) => typeof permission === "string");
  }
  return model;
}

function normalizeSuspendImpact(impact) {
  if (!impact || typeof impact !== "object") throw new Error("impact data is incomplete");
  const activeSessions = Number(impact.activeSessions);
  const createdAgentKeys = Number(impact.createdAgentKeys);
  if (!Number.isInteger(activeSessions) || activeSessions < 0 ||
      !Number.isInteger(createdAgentKeys) || createdAgentKeys < 0 ||
      !Array.isArray(impact.teams) || !Array.isArray(impact.externalIdentityProviders) ||
      typeof impact.protected !== "boolean") {
    throw new Error("impact data is incomplete");
  }
  return {
    activeSessions,
    createdAgentKeys,
    teams: impact.teams,
    externalIdentityProviders: impact.externalIdentityProviders.filter((provider) => typeof provider === "string" && provider),
    protected: impact.protected,
  };
}

export const actions = {
  "teams-view": async (ctx, el) => {
    teamsView = el.getAttribute("data-view") === "people" ? "people" : "team";
    await refreshScreen(ctx);
  },
  "people-tab": async (ctx, el) => {
    peopleTab = el.getAttribute("data-tab") === "waiting" ? "waiting" : "members";
    await refreshScreen(ctx);
  },
  "team-selector-toggle"(ctx, el) {
    const root = el.closest(".teams-selector") || document;
    const panel = root.querySelector("#team-selector-panel");
    if (!panel) return;
    const open = panel.hasAttribute("hidden");
    panel.toggleAttribute("hidden", !open);
    root.querySelector(".teams-selector__backdrop")?.toggleAttribute("hidden", !open);
    el.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) panel.querySelector("input")?.focus();
  },
  "team-selector-close"(ctx, el) {
    const root = el.closest(".teams-selector") || document;
    root.querySelector("#team-selector-panel")?.setAttribute("hidden", "");
    el.setAttribute("hidden", "");
    const trigger = root.querySelector(".teams-selector__trigger");
    trigger?.setAttribute("aria-expanded", "false");
    trigger?.focus();
  },
  "team-selector-search"(ctx, el) {
    const root = el.closest(".teams-selector__panel") || document;
    const query = String(el.value || "").trim().toLowerCase();
    root.querySelectorAll(".teams-selector__option").forEach((option) => {
      option.hidden = query !== "" && !(option.getAttribute("data-team-name") || "").includes(query);
    });
  },
  async "team-select"(ctx, el) {
    rememberSelectedTeam(el.getAttribute("data-id") || null);
    membersPage = 0;
    teamsView = "team";
    await refreshScreen(ctx);
  },
  async "team-members-page"(ctx, el) {
    const nextPage = Number.parseInt(el.getAttribute("data-page") || "0", 10);
    membersPage = Number.isFinite(nextPage) ? Math.max(0, nextPage) : 0;
    await refreshScreen(ctx);
  },
  "people-search"(ctx, el) {
    const root = el.closest(".teams-people-card") || document;
    const query = String(el.value || "").trim().toLowerCase();
    root.querySelectorAll("[data-person-row]").forEach((row) => {
      row.hidden = query !== "" && !(row.getAttribute("data-filter-text") || "").includes(query);
    });
  },
  "person-teams-toggle"(ctx, el) {
    const popover = el.parentElement && el.parentElement.querySelector(".teams-memberships__popover");
    if (!popover) return;
    const open = popover.hasAttribute("hidden");
    popover.toggleAttribute("hidden", !open);
    el.setAttribute("aria-expanded", open ? "true" : "false");
  },
  "person-action-toggle"(ctx, el) {
    const menu = el.closest(".teams-person-menu");
    if (!menu) return;
    const open = menu.querySelector(".teams-person-menu__popover")?.hasAttribute("hidden") === true;
    closePersonMenus(el.closest(".screen") || document, menu);
    setPersonMenuOpen(menu, open);
  },
  "person-action-close"(ctx, el) {
    setPersonMenuOpen(el.closest(".teams-person-menu"), false);
  },
  "team-modal-open"(ctx, el) { openTeamModal(el); },
  "team-modal-close"(ctx, el) { closeTeamModal(el.closest("dialog")); },
  "team-invite-email"(ctx, el) {
    setText((el.closest("dialog") || document).querySelector("#team-invite-status"), "");
  },
  "team-name-preview"(ctx, el) {
    const root = el.closest("#team-form") || document;
    const preview = root.querySelector("[data-team-ns-preview]");
    if (!preview) return;
    const ns = (ctx.identity && ctx.identity.namespace) || "";
    const slug = slugify(el.value || "");
    preview.textContent = slug ? (ns ? `${ns}/${slug}` : slug) : (ns ? `${ns}/…` : "…");
  },
  async "team-create"(ctx, el) {
    const root = el.closest(".screen") || document;
    const name = value(root, "#team-name");
    const description = value(root, "#team-description");
    const status = root.querySelector("#team-create-status");
    if (!name) return setText(status, "Team name is required.");
    setBusy(el, true, "Creating…");
    try {
      const team = await ctx.api.post("/v1/admin/teams", description ? { name, description } : { name });
      if (team && team.id) rememberSelectedTeam(team.id);
      closeTeamModal(el.closest("dialog"), false);
      await refreshScreen(ctx);
    } catch (err) {
      setText(status, "Create failed: " + msgOf(err));
      setBusy(el, false, "Create Team");
    }
  },
  async "team-rename"(ctx, el) {
    const modal = el.closest("dialog");
    const name = value(modal, "#team-rename-name");
    const teamId = el.getAttribute("data-team");
    const status = modal && modal.querySelector("#team-rename-status");
    if (!teamId || !name) return setText(status, "Team name is required.");
    setBusy(el, true, "Saving…");
    try {
      await ctx.api.put(`/v1/admin/teams/${encodeURIComponent(teamId)}`, { name });
      closeTeamModal(modal, false);
      await refreshScreen(ctx);
    } catch (err) {
      setText(status, "Rename failed: " + msgOf(err));
      setBusy(el, false, "Save Name");
    }
  },
  async "team-archive"(ctx, el) {
    const teamId = el.getAttribute("data-team");
    const archived = el.getAttribute("data-archived") === "true";
    if (!teamId) return;
    setBusy(el, true, archived ? "Restoring…" : "Archiving…");
    try {
      await ctx.api.put(`/v1/admin/teams/${encodeURIComponent(teamId)}`, { archived: !archived });
      await refreshScreen(ctx);
    } catch (err) {
      setBusy(el, false, archived ? "Restore" : "Archive");
      announceRowError(el, "Team update failed: " + msgOf(err));
    }
  },
  async "team-member-add"(ctx, el) {
    const root = el.closest(".screen") || document;
    const teamId = el.getAttribute("data-team");
    const email = el.getAttribute("data-email") || value(root, "#team-member-email");
    const status = root.querySelector("#team-member-status");
    if (!teamId || !email) return setText(status, "Choose a person to add.");
    setBusy(el, true, "Adding…");
    try {
      await ctx.api.post(`/v1/admin/teams/${encodeURIComponent(teamId)}/members`, { email });
      closeTeamModal(el.closest("dialog"), false);
      await refreshScreen(ctx);
    } catch (err) {
      setText(status, "Add failed: " + msgOf(err));
      setBusy(el, false, "Add");
    }
  },
  async "team-member-remove"(ctx, el) {
    const teamId = el.getAttribute("data-team");
    const userId = el.getAttribute("data-user");
    const email = el.getAttribute("data-email") || "";
    const name = el.getAttribute("data-name") || email || "Member";
    if (!teamId || !userId) return;
    setBusy(el, true, "Removing…");
    try {
      await ctx.api.del(`/v1/admin/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`);
      undoRemoval = { teamId, userId, email, name };
      await refreshScreen(ctx);
    } catch (err) {
      setBusy(el, false, "Remove");
      announceRowError(el, "Remove failed: " + msgOf(err));
    }
  },
  async "team-member-undo"(ctx) {
    if (!undoRemoval || !undoRemoval.teamId || !undoRemoval.email) return;
    const record = undoRemoval;
    try {
      await ctx.api.post(`/v1/admin/teams/${encodeURIComponent(record.teamId)}/members`, { email: record.email });
      undoRemoval = null;
      await refreshScreen(ctx);
    } catch {
      undoRemoval = record;
      await refreshScreen(ctx);
    }
  },
  async "team-member-undo-dismiss"(ctx) {
    undoRemoval = null;
    await refreshScreen(ctx);
  },
  async "team-invite-submit"(ctx, el) {
    const root = el.closest(".screen") || document;
    const teamId = el.getAttribute("data-team");
    const displayName = value(root, "#team-invite-name");
    const email = value(root, "#team-invite-email");
    const role = value(root, "#team-invite-role") || "member";
    const status = root.querySelector("#team-invite-status");
    if (!teamId || !displayName || !email) return setText(status, "Enter the person's name and email address.");
    setBusy(el, true, "Creating…");
    try {
      const response = await ctx.api.post(`/v1/admin/teams/${encodeURIComponent(teamId)}/invitations`, { displayName, email, role });
      if (!response || !response.activationToken) throw new Error("server returned no activation credential");
      const origin = typeof window !== "undefined" && window.location ? window.location.origin : "";
      lastTeamInvite = { email, url: `${origin}/console/login?invite=${encodeURIComponent(response.activationToken)}` };
      const result = root.querySelector("#team-invite-result");
      const url = root.querySelector("#team-invite-url");
      if (url) url.textContent = lastTeamInvite.url;
      if (result) result.hidden = false;
      setText(status, "Invitation link created. Copy it before closing this panel.");
      setBusy(el, false, "Create invite link");
    } catch (err) {
      const message = msgOf(err);
      setText(status, /live invitation pending/i.test(message) ? message : "Invite failed: " + message);
      setBusy(el, false, "Create invite link");
    }
  },
  "team-invite-action-open"(ctx, el) {
    const root = el.closest(".screen") || document;
    const modal = root.querySelector("#team-invite-action-modal");
    if (!modal) return;
    const kind = el.getAttribute("data-kind") === "reinvite" ? "reinvite" : "reminder";
    modal.dataset.team = el.getAttribute("data-team") || "";
    modal.dataset.invitation = el.getAttribute("data-invitation") || "";
    modal.dataset.kind = kind;
    modal.dataset.email = el.getAttribute("data-email") || "";
    setText(modal.querySelector("#team-invite-action-title"), kind === "reinvite" ? "Re-Invite Person" : "Send Reminder");
    setText(modal.querySelector("#team-invite-action-copy"), kind === "reinvite"
      ? "This invitation expired. Re-inviting creates a fresh link and invalidates the expired one."
      : "Sending a reminder creates a fresh link and immediately invalidates the previous one.");
    setText(modal.querySelector("#team-invite-action-status"), "");
    modal.querySelector("#team-invite-action-result")?.setAttribute("hidden", "");
    const confirm = modal.querySelector('[data-action="team-invite-action-confirm"]');
    const done = modal.querySelector('[data-action="team-invite-action-done"]');
    const cancel = modal.querySelector('[data-action="team-modal-close"]');
    if (confirm) { confirm.hidden = false; confirm.disabled = false; confirm.textContent = "Confirm"; }
    if (done) done.hidden = true;
    if (cancel) cancel.hidden = false;
    openTeamModal({
      closest: () => root,
      getAttribute: (key) => key === "data-modal-target" ? "team-invite-action-modal" : null,
      setAttribute: (key, value) => el.setAttribute(key, value),
      focus: () => el.focus(),
    });
  },
  async "team-invite-action-confirm"(ctx, el) {
    const modal = el.closest("dialog");
    const teamId = modal && modal.dataset.team;
    const invitationId = modal && modal.dataset.invitation;
    const kind = modal && modal.dataset.kind === "reinvite" ? "reinvite" : "reminder";
    const status = modal && modal.querySelector("#team-invite-action-status");
    if (!teamId || !invitationId) return setText(status, "Invitation is unavailable.");
    setBusy(el, true, kind === "reinvite" ? "Re-inviting…" : "Sending…");
    try {
      const response = await ctx.api.put(
        `/v1/admin/teams/${encodeURIComponent(teamId)}/invitations/${encodeURIComponent(invitationId)}/rotation`,
        { kind },
      );
      if (!response || !response.activationToken) throw new Error("server returned no activation credential");
      const origin = typeof window !== "undefined" && window.location ? window.location.origin : "";
      lastTeamInvite = {
        email: modal.dataset.email || "Invitee",
        url: `${origin}/console/login?invite=${encodeURIComponent(response.activationToken)}`,
      };
      const result = modal.querySelector("#team-invite-action-result");
      const url = modal.querySelector("#team-invite-action-url");
      if (url) url.textContent = lastTeamInvite.url;
      if (result) result.hidden = false;
      setText(status, "New invitation link created. Copy it before closing this panel.");
      el.hidden = true;
      const cancel = modal.querySelector('[data-action="team-modal-close"]');
      const done = modal.querySelector('[data-action="team-invite-action-done"]');
      if (cancel) cancel.hidden = true;
      if (done) done.hidden = false;
    } catch (err) {
      setText(status, "Could not rotate invitation: " + msgOf(err));
      setBusy(el, false, "Confirm");
    }
  },
  async "team-invite-action-done"(ctx, el) {
    closeTeamModal(el.closest("dialog"), false);
    await refreshScreen(ctx);
  },
  async "team-invite-revoke"(ctx, el) {
    const teamId = el.getAttribute("data-team");
    const invitationId = el.getAttribute("data-invitation");
    if (!teamId || !invitationId) return;
    if (typeof window !== "undefined" && typeof window.confirm === "function" &&
        !window.confirm("Revoke this invitation? Its current link will stop working.")) return;
    setBusy(el, true, "Revoking…");
    try {
      await ctx.api.del(`/v1/admin/teams/${encodeURIComponent(teamId)}/invitations/${encodeURIComponent(invitationId)}`);
      await refreshScreen(ctx);
    } catch (err) {
      setBusy(el, false, "Revoke");
      announceRowError(el, "Revoke failed: " + msgOf(err));
    }
  },
  async "team-member-role"(ctx, el) {
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#team-role-status");
    const teamId = el.getAttribute("data-team");
    const userId = el.getAttribute("data-user");
    const role = String(el.value || "").trim();
    const currentRole = el.getAttribute("data-current-role") || "";
    if (!teamId || !userId || !ASSIGNABLE_ROLES.includes(role) || role === currentRole) return;
    setText(status, "");
    setBusy(el, true);
    try {
      await ctx.api.put(`/v1/admin/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}/role`, { role });
      await refreshScreen(ctx);
    } catch (err) {
      el.value = currentRole;
      setText(status, "Role change failed: " + msgOf(err));
      setBusy(el, false);
    }
  },
  async "team-memory-access"(ctx, el) {
    const section = el.closest(".teams-memory-access") || el.closest(".screen") || document;
    const description = section.querySelector("#team-memory-access-description");
    const status = section.querySelector("#team-memory-access-status");
    const teamId = el.getAttribute("data-team");
    const currentMode = el.getAttribute("data-current-mode") === "company-published" ? "company-published" : "related";
    const requestedMode = el.checked ? "company-published" : "related";
    if (!teamId || requestedMode === currentMode) return;
    setText(status, "");
    section.setAttribute("aria-busy", "true");
    el.disabled = true;
    try {
      const updated = await ctx.api.put(`/v1/admin/teams/${encodeURIComponent(teamId)}/memory-access`, { mode: requestedMode });
      const access = updated && updated.memoryAccess && typeof updated.memoryAccess === "object" ? updated.memoryAccess : {};
      const serverMode = access.mode === "company-published" ? "company-published" : "related";
      el.checked = serverMode === "company-published";
      el.setAttribute("data-current-mode", serverMode);
      setText(description, memoryAccessDescription(serverMode));
      setText(status, serverMode === "company-published" ? "Company memory is on." : "Company memory is off.");
      el.disabled = serverMode === "company-published" ? access.canTighten !== true : access.canBroaden !== true;
    } catch (err) {
      el.checked = currentMode === "company-published";
      el.setAttribute("data-current-mode", currentMode);
      setText(description, memoryAccessDescription(currentMode));
      setText(status, "Memory access update failed: " + msgOf(err));
      el.disabled = false;
    } finally {
      section.removeAttribute("aria-busy");
    }
  },
  async "person-suspend-open"(ctx, el) {
    setPersonMenuOpen(el.closest(".teams-person-menu"), false);
    const root = el.closest(".screen") || document;
    const modal = root.querySelector("#team-suspend-modal");
    if (!modal) return;
    const userId = el.getAttribute("data-user") || "";
    const name = el.getAttribute("data-name") || "This person";
    const firstName = name.trim().split(/\s+/)[0] || "them";
    const title = modal.querySelector("#team-suspend-title");
    const summary = modal.querySelector("#team-suspend-summary");
    if (title) title.textContent = `Suspend ${name}'s Access`;
    if (summary) summary.textContent = `Sign-in refused, live sessions killed, all memory access gone — everywhere, immediately. Reversible: you can reinstate ${firstName} at any time.`;
    modal.dataset.user = userId;
    modal.setAttribute("aria-busy", "true");
    modal.querySelector(".teams-impact-loading")?.removeAttribute("hidden");
    modal.querySelector(".teams-suspend-unavailable")?.setAttribute("hidden", "");
    modal.querySelector("#team-suspend-impact")?.setAttribute("hidden", "");
    modal.querySelector("#team-suspend-revoke-wrap")?.setAttribute("hidden", "");
    modal.querySelector("#team-suspend-idp-warning")?.setAttribute("hidden", "");
    const revokeKeys = modal.querySelector("#team-suspend-revoke-keys");
    if (revokeKeys) revokeKeys.checked = false;
    const reason = modal.querySelector("#team-suspend-reason");
    const confirm = modal.querySelector('[data-action="person-suspend-confirm"]');
    if (reason) { reason.disabled = true; reason.value = ""; }
    if (confirm) confirm.disabled = true;
    openTeamModal({
      closest: () => root,
      getAttribute: (key) => key === "data-modal-target" ? "team-suspend-modal" : null,
      setAttribute: (key, value) => el.setAttribute(key, value),
      focus: () => el.focus(),
    });
    try {
      const impact = normalizeSuspendImpact(await ctx.api.get(`/v1/admin/people/${encodeURIComponent(userId)}/access-impact`));
      const impactNode = modal.querySelector("#team-suspend-impact");
      const teams = impact.teams;
      const activeSessions = impact.activeSessions;
      const createdAgentKeys = impact.createdAgentKeys;
      if (impactNode) {
        impactNode.innerHTML = `<div class="teams-suspend-impact__card">
            <b>Loses Access To</b><div class="teams-suspend-team-chips">${teams.length
              ? teams.map((team) => `<span>${ctx.esc(team.name || "Team")}</span>`).join("")
              : "<span>None</span>"}</div></div>
          <div class="teams-suspend-impact__card teams-suspend-impact__row"><b>Live Sessions</b>
            <span>${activeSessions === 0 ? "None right now" : `${activeSessions} session${activeSessions === 1 ? "" : "s"} signed out immediately`}</span></div>`;
        impactNode.removeAttribute("hidden");
      }
      modal.querySelector(".teams-impact-loading")?.setAttribute("hidden", "");
      const revokeWrap = modal.querySelector("#team-suspend-revoke-wrap");
      const revokeCount = modal.querySelector("#team-suspend-key-count");
      if (revokeCount) revokeCount.textContent = `${createdAgentKeys} key${createdAgentKeys === 1 ? "" : "s"} keep running`;
      if (revokeWrap && createdAgentKeys > 0) revokeWrap.removeAttribute("hidden");
      const providers = impact.externalIdentityProviders;
      const idpWarning = modal.querySelector("#team-suspend-idp-warning");
      if (idpWarning && providers.length) {
        idpWarning.textContent = `This account uses ${providers.join(", ")} sign-in. Halofy will refuse access here; suspend them at the provider too.`;
        idpWarning.removeAttribute("hidden");
      }
      if (reason) reason.disabled = false;
      if (confirm) confirm.disabled = impact.protected === true;
    } catch {
      modal.querySelector(".teams-impact-loading")?.setAttribute("hidden", "");
      modal.querySelector(".teams-suspend-unavailable")?.removeAttribute("hidden");
    } finally {
      modal.removeAttribute("aria-busy");
    }
  },
  async "person-suspend-confirm"(ctx, el) {
    const modal = el.closest("dialog");
    const userId = modal && modal.dataset.user;
    if (!userId) return;
    setBusy(el, true, "Suspending…");
    try {
      await ctx.api.put(`/v1/admin/people/${encodeURIComponent(userId)}/access-state`, {
        status: "disabled",
        revokeCreatedKeys: Boolean(modal.querySelector("#team-suspend-revoke-keys")?.checked),
        reason: value(modal, "#team-suspend-reason") || undefined,
      });
      closeTeamModal(modal, false);
      await refreshScreen(ctx);
    } catch (err) {
      const unavailable = modal.querySelector(".teams-suspend-unavailable");
      if (unavailable) {
        unavailable.removeAttribute("hidden");
        setText(unavailable.querySelector("p"), "Suspend failed: " + msgOf(err));
      }
      setBusy(el, false, "Suspend Access");
    }
  },
  async "person-reinstate"(ctx, el) {
    const userId = el.getAttribute("data-user");
    if (!userId) return;
    setBusy(el, true, "Reinstating…");
    try {
      await ctx.api.put(`/v1/admin/people/${encodeURIComponent(userId)}/access-state`, { status: "active" });
      await refreshScreen(ctx);
    } catch (err) {
      setBusy(el, false, "Reinstate");
      announceRowError(el, "Reinstate failed: " + msgOf(err));
    }
  },
  async "team-invite-copy"(ctx, el) {
    const root = el.closest("dialog") || el.closest(".teams-invite-banner") || el.closest(".screen") || document;
    const status = root.querySelector("#team-invite-copy-status, #team-invite-action-copy-status");
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(lastTeamInvite ? lastTeamInvite.url : "");
      setText(status, "Copied.");
      return true;
    } catch {
      setText(status, "Copy failed. Select the link manually.");
      return false;
    }
  },
  async "team-invite-dismiss"(ctx) {
    lastTeamInvite = null;
    await refreshScreen(ctx);
  },
};

async function refreshScreen(ctx) {
  if (typeof ctx.refresh === "function") await ctx.refresh();
  else await ctx.go("s13");
}

function errorScreen(ctx, err) {
  const message = ctx.esc(err && err.message ? err.message : "Could not load teams.");
  return `<section class="teams-v2"><header class="head teams-v2__head"><div><h1>Teams</h1></div></header>
    <div class="card teams-unavailable"><span aria-hidden="true">—</span><div><b>Unavailable</b><p>${message}</p></div></div></section>`;
}

function openTeamModal(el) {
  const doc = typeof document !== "undefined" ? document : null;
  const viewport = typeof window !== "undefined" ? { x: window.scrollX, y: window.scrollY } : null;
  const root = el && el.closest ? (el.closest(".screen") || doc) : doc;
  const targetId = el && el.getAttribute ? el.getAttribute("data-modal-target") : "";
  const modal = targetId && root && root.querySelector ? root.querySelector(`#${targetId}`) : null;
  if (!modal) return;
  modal.__halomemOpener = el;
  modal.__halomemRestoreFocus = true;
  modal.__halomemViewport = viewport;
  if (typeof modal.addEventListener === "function" && !modal.__halomemCloseSync) {
    modal.addEventListener("close", () => finalizeTeamModal(modal));
    modal.__halomemCloseSync = true;
  }
  if (doc && doc.body && doc.body.classList) {
    if (viewport && doc.body.style) doc.body.style.setProperty("--console-modal-scroll-y", `${viewport.y}px`);
    doc.body.classList.add("console-modal-open");
  }
  if (typeof modal.showModal === "function") modal.showModal();
  else modal.setAttribute("open", "");
  el.setAttribute("aria-expanded", "true");
  const focusTarget = modal.querySelector("[data-modal-focus]") || modal.querySelector("button");
  if (focusTarget && typeof focusTarget.focus === "function") focusTarget.focus({ preventScroll: true });
  if (viewport && typeof window.scrollTo === "function") window.scrollTo(viewport.x, viewport.y);
}

function closeTeamModal(modal, restoreFocus = true) {
  if (!modal) return;
  modal.__halomemRestoreFocus = restoreFocus;
  if (modal.open && typeof modal.close === "function") modal.close();
  else if (typeof modal.removeAttribute === "function") {
    modal.removeAttribute("open");
    finalizeTeamModal(modal);
  }
}

function finalizeTeamModal(modal) {
  const doc = typeof document !== "undefined" ? document : null;
  const viewport = modal && modal.__halomemViewport;
  if (doc && doc.body && doc.body.classList) {
    doc.body.classList.remove("console-modal-open");
    if (doc.body.style) doc.body.style.removeProperty("--console-modal-scroll-y");
  }
  if (viewport && typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(viewport.x, viewport.y);
  const opener = modal && modal.__halomemOpener;
  if (opener && typeof opener.setAttribute === "function") opener.setAttribute("aria-expanded", "false");
  if (modal && modal.__halomemRestoreFocus !== false && opener && typeof opener.focus === "function") opener.focus({ preventScroll: true });
  if (modal) {
    modal.__halomemRestoreFocus = true;
    modal.__halomemViewport = null;
  }
}

function restoreSelectedTeam() {
  if (selectedTeamId || typeof window === "undefined" || !window.localStorage) return;
  try { selectedTeamId = window.localStorage.getItem("halomem:selected-team") || null; } catch { /* storage may be blocked */ }
}

function rememberSelectedTeam(id) {
  selectedTeamId = id || null;
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    if (selectedTeamId) window.localStorage.setItem("halomem:selected-team", selectedTeamId);
    else window.localStorage.removeItem("halomem:selected-team");
  } catch { /* storage may be blocked */ }
}

function closePersonMenus(root, except = null) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  root.querySelectorAll(".teams-person-menu").forEach((menu) => {
    if (menu !== except) setPersonMenuOpen(menu, false);
  });
}

function setPersonMenuOpen(menu, open) {
  if (!menu || typeof menu.querySelector !== "function") return;
  const trigger = menu.querySelector('[data-action="person-action-toggle"]');
  const backdrop = menu.querySelector(".teams-person-menu__backdrop");
  const popover = menu.querySelector(".teams-person-menu__popover");
  if (trigger) trigger.setAttribute("aria-expanded", open ? "true" : "false");
  if (backdrop) backdrop.toggleAttribute("hidden", !open);
  if (popover) {
    popover.toggleAttribute("hidden", !open);
    if (open) positionPersonMenu(trigger, popover);
  }
}

function positionPersonMenu(trigger, popover) {
  if (typeof window === "undefined" || !trigger?.getBoundingClientRect || !popover?.getBoundingClientRect) return;
  const triggerRect = trigger.getBoundingClientRect();
  const popoverRect = popover.getBoundingClientRect();
  const margin = 8;
  const gap = 4;
  const width = popoverRect.width || 190;
  const height = popoverRect.height || 45;
  const below = triggerRect.bottom + gap;
  const above = triggerRect.top - gap - height;
  const top = below + height <= window.innerHeight - margin ? below : Math.max(margin, above);
  const left = Math.max(margin, Math.min(triggerRect.right - width, window.innerWidth - margin - width));
  popover.style.top = `${Math.round(top)}px`;
  popover.style.left = `${Math.round(left)}px`;
  popover.style.right = "auto";
}

function memoryAccessDescription(mode) {
  return mode === "company-published"
    ? "Reads company-published memory"
    : "Reads own scope only";
}

function dedupePeople(users, teams) {
  const byEmail = new Map();
  for (const user of users) {
    const key = normalizeEmail(user.email);
    if (key) byEmail.set(key, { ...user });
  }
  for (const team of teams) {
    for (const member of Array.isArray(team.members) ? team.members : []) {
      const key = normalizeEmail(member.email);
      if (key && !byEmail.has(key)) byEmail.set(key, { ...member, id: member.userId });
    }
  }
  return [...byEmail.values()].sort((a, b) => String(a.email || "").localeCompare(String(b.email || "")));
}

function teamsForEmail(teams, email) {
  const normalized = normalizeEmail(email);
  return teams.filter((team) => (Array.isArray(team.members) ? team.members : [])
    .some((member) => normalizeEmail(member.email) === normalized));
}

function normalizeEmail(value) { return String(value || "").trim().toLowerCase(); }
function memberDisplayLabel(ctx, subject) {
  const email = String(subject && subject.email || "").trim();
  const explicit = String(subject && subject.displayName || "").trim();
  if (explicit) return explicit;
  const resolved = personDisplayName(subject, ctx.personLabel);
  if (resolved && normalizeEmail(resolved) !== normalizeEmail(email)) return resolved;
  const localPart = email.split("@")[0].trim();
  return localPart ? localPart.slice(0, 5) : "Unknown person";
}
function publicRole(value) { return value === "owner" ? "root" : value === "auditor" ? "member" : String(value || "member"); }
function roleLabel(value) { return value === "root" ? "Owner" : value ? value[0].toUpperCase() + value.slice(1) : "Member"; }
function isArchived(team) { return team && (team.status === "archived" || Boolean(team.archivedAt)); }
function inviteCount(team) {
  if (!team || !Array.isArray(team.invitations)) return null;
  return team.invitations.filter((invite) => invite.status === "waiting" || invite.status === "expired").length;
}
function organizationLabel(ctx) { return ctx.organizationName || organizationScopeLabel(ctx.identity && ctx.identity.namespace, null, null) || "Organization"; }
function scopeLabel(ctx, namespace) { return organizationScopeLabel(namespace, ctx.organizationName, ctx.identity && ctx.identity.namespace) || namespace || "Unavailable"; }
function initial(name) { const text = String(name || "").trim(); return text ? text[0].toUpperCase() : "T"; }
function safeId(value) { return String(value || "person").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "person"; }
function slugify(name) { return String(name || "").trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "").replace(/-+/g, "-").replace(/^-|-$/g, ""); }
function value(root, selector) { const node = root && root.querySelector ? root.querySelector(selector) : null; return node && "value" in node ? String(node.value || "").trim() : ""; }
function setText(node, text) { if (node) node.textContent = text; }
function setBusy(el, busy, label) { if (!el) return; el.disabled = busy; if (label !== undefined) el.textContent = label; }
function msgOf(err) { return err && err.message ? err.message : String(err || "Unknown error"); }
function formatWhen(value) { if (!value) return "Unavailable"; const date = new Date(value); return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric" }); }
function escapeStatic(value) { return String(value || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function announceRowError(el, message) { const card = el && el.closest ? el.closest(".teams-card") : null; const status = card && card.querySelector ? card.querySelector("#team-role-status") : null; setText(status, message); }
function closeIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M13 8H3M7 12l-4-4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'; }
function lockIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3.5" y="7" width="9" height="6.5" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.25"/><path d="M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/></svg>'; }
function archiveIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2.5 4.5h11v8h-11zM2 2.5h12v2H2zM6 7h4" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/></svg>'; }
function searchIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.25" fill="none" stroke="currentColor" stroke-width="1.35"/><path d="m10.25 10.25 3 3" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round"/></svg>'; }
function chevronIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>'; }
function editIcon() { return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'; }
function plusIcon() { return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'; }
function infoIcon() { return '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.7" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8 7.2v3.3M8 5.1h.01" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>'; }
