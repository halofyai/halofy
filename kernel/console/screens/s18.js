/**
 * S18 - Settings.
 *
 * Two tabs over one screen, because a person signing in has exactly two
 * identities to manage and they answer different questions:
 *
 *  - ORGANIZATION - what this workspace is called and what mark it carries.
 *    Readable by every human in the tenant; writable by owner/admin
 *    (`organization:write`). Renaming never moves the handle: the tenant id is
 *    the root namespace every memory row hangs off.
 *  - PROFILE - your own name, your account facts, your teams, and every
 *    SIGN-IN METHOD that lands on this account, connected or not - email +
 *    password, Google, GitHub. One account, three doors: connecting a provider
 *    here means signing in with it later resolves to THIS account instead of a
 *    separate one.
 *
 * The methods render as the same square tile grid the backend connections tab
 * (S14) uses - one `intg-card` per method with its live status - and each tile
 * opens a pop-up (the shared `source-wizard-overlay` modal) carrying the
 * connection details and the connect/disconnect action, so the grid itself
 * stays scannable.
 *
 * Connect flows differ because the providers do:
 *  - GitHub goes through the kernel's own OAuth redirect (GET
 *    /auth/github?mode=link - a full-page navigation, not fetch).
 *  - Google goes through Supabase Auth, which must return to an allow-listed
 *    redirect URL, so the round-trip lands on /console/login with a one-shot
 *    sessionStorage marker; that page POSTs the token to
 *    /auth/identities/google and bounces back here.
 * Both disconnect through DELETE /auth/identities/<provider>, which refuses
 * (409) to remove the last remaining way to sign in.
 *
 * The callback returns here with a one-shot status marker in the hash
 * (#settings?linked=google / #settings?error=github_conflict / ...) - a marker forces the
 * Profile tab, since that is where the round-trip started. Every server-derived
 * value is ctx.esc()'d; all interactivity is delegated `actions` (no inline JS).
 */

import { headingInfo } from "../heading-info.js";

/** Key the login page reads to tell a link round-trip from a sign-in. */
const LINK_FLAG = "halomem.link-provider";

/** Longest data URL the kernel stores; the client downscales far below it. */
const MAX_ICON_CHARS = 256_000;

/** Square edge the uploaded mark is downscaled to before it is sent. */
const ICON_EDGE = 256;

/** Assisted account-identity changes go to product support, not sales booking. */
const EMAIL_CHANGE_SUPPORT_URL = "mailto:contactus@halofy.ai?subject=Request%20email%20change";

/** Compact rule disclosed beside the section heading on pointer or keyboard focus. */
const LAST_SIGN_IN_METHOD_NOTE = "At least one sign-in method must remain connected.";

/** Which tab is showing. Module state, like S6's source-flow strip. */
let activeTab = "organization";

const TABS = [
  ["organization", "Organization"],
  ["profile", "Profile"],
];

export function settingsTabFromHash(hash) {
  const query = String(hash || "").split("?")[1] || "";
  const requested = new URLSearchParams(query).get("tab");
  return TABS.some(([id]) => id === requested) ? requested : null;
}

export async function render(ctx) {
  const identity = ctx.identity || {};
  const requestedTab = settingsTabFromHash(
    typeof window !== "undefined" && window.location ? window.location.hash : "",
  );
  if (requestedTab) activeTab = requestedTab;
  const marker = markerBanner(ctx);
  if (marker) activeTab = "profile";
  const [portfolio, organization] = await Promise.all([
    loadPortfolio(ctx, identity),
    loadOrganization(ctx),
  ]);
  let identities = [];
  let hasPassword = false;
  let loadError = null;
  try {
    const response = await ctx.api.get("/auth/identities");
    identities = Array.isArray(response && response.identities) ? response.identities : [];
    hasPassword = Boolean(response && response.hasPassword);
  } catch (err) {
    loadError = err;
  }
  let githubEnabled = false;
  let googleEnabled = false;
  try {
    // Open discovery endpoint (same one the login page uses) — hides a connect
    // button on deployments where that provider is not configured.
    const config = await ctx.api.get("/auth/sso/config");
    githubEnabled = Boolean(config && config.github === true);
    googleEnabled = Boolean(config && config.enabled === true);
  } catch {
    githubEnabled = false;
    googleEnabled = false;
  }

  const linked = (provider) =>
    identities.find((entry) => String((entry && entry.provider) || "") === provider) || null;
  const state = {
    identities,
    hasPassword,
    loadError,
    githubEnabled,
    googleEnabled,
    connectedCount: identities.length + (hasPassword ? 1 : 0),
    google: linked("google"),
    github: linked("github"),
    email: String(identity.actor || ""),
  };
  const specs = loadError ? [] : [passwordSpec(state), googleSpec(state), githubSpec(state)];

  return `
    <div class="head"><div><div class="eyebrow">Account</div><h1>Settings</h1></div></div>
    ${marker}
    ${tabStrip(ctx)}
    <div id="settings-panel-organization" role="tabpanel" aria-labelledby="settings-tab-organization"
      data-settings-panel="organization"${activeTab === "organization" ? "" : " hidden"}>
      ${organizationPanel(ctx, organization)}
    </div>
    <div id="settings-panel-profile" role="tabpanel" aria-labelledby="settings-tab-profile"
      data-settings-panel="profile"${activeTab === "profile" ? "" : " hidden"}>
      <div class="settings-profile-bento">
        ${accountCard(ctx, identity, portfolio, organization)}
        ${portfolioCard(ctx, portfolio)}
        ${methodsCard(ctx, state, specs)}
      </div>
    </div>
    <div class="hint" id="profile-status" role="status" aria-live="polite"></div>
    ${specs.map((spec) => methodModal(ctx, spec, specs)).join("")}`;
}

function tabStrip(ctx) {
  return '<nav class="source-category-tabs filter-strip settings-tabs" role="tablist" aria-label="Settings">' +
    TABS.map(([id, label]) => {
      const selected = activeTab === id;
      return '<button type="button" class="source-category-tab' + (selected ? " is-active" : "") +
        '" id="settings-tab-' + id + '" role="tab" data-action="settings-tab" data-tab="' + id +
        '" aria-controls="settings-panel-' + id + '" aria-selected="' + (selected ? "true" : "false") +
        '" tabindex="' + (selected ? "0" : "-1") + '">' + ctx.esc(label) + "</button>";
    }).join("") + "</nav>";
}

// ---------------------------------------------------------------------------
// Organization tab
// ---------------------------------------------------------------------------

async function loadOrganization(ctx) {
  try {
    const response = await ctx.api.get("/v1/admin/organization");
    const organization = response && response.organization;
    if (!organization || typeof organization !== "object") return null;
    return {
      id: String(organization.id || ""),
      name: String(organization.name || ""),
      icon: typeof organization.icon === "string" && organization.icon !== ""
        ? organization.icon
        : null,
      status: String(organization.status || ""),
      createdAt: String(organization.createdAt || ""),
      canEdit: organization.canEdit === true,
    };
  } catch {
    return null;
  }
}

function organizationPanel(ctx, organization) {
  if (organization === null) {
    return '<div class="card"><h3 style="margin:0">Organization</h3>' +
      '<div class="sub">No organization resolves for this account.</div></div>';
  }
  const esc = ctx.esc;
  const editable = organization.canEdit;
  return '<section class="card settings-card" aria-labelledby="org-identity-heading">' +
    '<div class="settings-row">' +
      '<h3 id="org-identity-heading" style="margin:0">Organization</h3>' +
    "</div>" +
    '<div class="settings-row">' +
      '<p class="eyebrow">Icon</p>' +
      '<div class="settings-mark-row">' +
        markTile(ctx, organization.icon, initialsOf(organization.name || organization.id)) +
        (editable
          ? '<div class="row settings-mark-actions">' +
            '<label class="btn btn--sm settings-upload">Upload image' +
            '<input type="file" accept="image/png,image/jpeg,image/webp" data-change-action="org-icon-pick"' +
            ' aria-label="Upload an organization icon"></label>' +
            (organization.icon
              ? '<button class="btn btn--ghost btn--sm" data-action="org-icon-clear">Remove</button>'
              : "") +
            "</div>"
          : "") +
      "</div>" +
    "</div>" +
    '<div class="settings-row">' +
      '<p class="eyebrow">Name</p>' +
      (editable
        ? '<div class="settings-inline-form">' +
          '<input class="input" id="org-name-input" maxlength="100"' +
          ' value="' + esc(organization.name) + '" aria-label="Organization name">' +
          '<button class="btn btn--solid btn--sm" type="button" data-action="org-name-save">Save</button>' +
          "</div>"
        : '<div class="settings-static">' + esc(organization.name) + "</div>") +
    "</div>" +
    '<dl class="settings-facts">' +
      fact(esc, "Handle", '<span class="mono">' + esc(organizationDisplayHandle(ctx, organization)) + "</span>") +
      fact(esc, "Created", esc(formatDay(organization.createdAt))) +
    "</dl>" +
    '<div class="hint" data-settings-status="organization" role="status" aria-live="polite"></div>' +
    "</section>";
}

function organizationDisplayHandle(ctx, organization) {
  return organizationScopeLabel(
    organization.id,
    organization.name,
    ctx.identity?.namespace,
  );
}

function fact(esc, label, valueHtml) {
  return "<div><dt>" + esc(label) + "</dt><dd>" + valueHtml + "</dd></div>";
}

/** The square mark: the stored image when there is one, initials when not. */
function markTile(ctx, icon, initials) {
  if (icon) {
    return '<span class="settings-mark"><img src="' + ctx.esc(icon) + '" alt="" decoding="async"></span>';
  }
  return '<span class="settings-mark settings-mark--initials" aria-hidden="true">' +
    ctx.esc(initials) + "</span>";
}

function initialsOf(value) {
  const parts = String(value || "").trim().split(/[\s@._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const letters = parts.slice(0, 2).map((part) => part[0]).join("");
  return letters.toUpperCase();
}

// ---------------------------------------------------------------------------
// Profile tab
// ---------------------------------------------------------------------------

function accountCard(ctx, identity, portfolio, organization) {
  const esc = ctx.esc;
  const email = String(identity.actor || "");
  const name = portfolio.displayName || "";
  const role = capitalizeLabel(identity.role);
  const workspace = organization && organization.name
    ? String(organization.name)
    : capitalizeLabel(teamName(portfolio.homeNamespace));
  return '<section class="card settings-card settings-bento-card settings-bento-account" aria-labelledby="profile-identity-heading">' +
    '<div class="settings-row between">' +
      '<h3 id="profile-identity-heading" style="margin:0">You</h3>' +
      '<span class="badge badge--role">' + esc(role) + "</span>" +
    "</div>" +
    '<div class="settings-row">' +
      '<div class="settings-mark-row">' +
        markTile(ctx, portfolio.avatar, initialsOf(name || email)) +
        '<div class="settings-profile-controls">' +
          '<div class="settings-inline-form">' +
            '<input class="input" id="profile-name-input" maxlength="80" required' +
            ' value="' + esc(name) + '" placeholder="Your name" aria-label="Your name">' +
            '<button class="btn btn--solid btn--sm" type="button" data-action="profile-name-save">Save</button>' +
          "</div>" +
          '<div class="row settings-mark-actions">' +
            '<label class="btn btn--sm settings-upload">Upload photo' +
            '<input type="file" accept="image/png,image/jpeg,image/webp" data-change-action="profile-avatar-pick"' +
            ' aria-label="Upload your profile photo"></label>' +
            (portfolio.avatar
              ? '<button class="btn btn--ghost btn--sm" data-action="profile-avatar-clear">Remove</button>'
              : "") +
          "</div>" +
        "</div>" +
      "</div>" +
    "</div>" +
    '<dl class="settings-facts">' +
      fact(esc, "Email", '<span class="mono">' + esc(email) + "</span>") +
      fact(esc, "Role", esc(role)) +
      fact(esc, "Workspace", esc(workspace)) +
    "</dl>" +
    '<div class="hint" data-settings-status="profile" role="status" aria-live="polite"></div>' +
    "</section>";
}

async function loadPortfolio(ctx, identity) {
  const fallbackNamespace = String(identity.namespace || "");
  try {
    const response = await ctx.api.get("/auth/profile");
    const homeNamespace = String((response && response.homeNamespace) || fallbackNamespace);
    const displayName =
      response && typeof response.displayName === "string" && response.displayName !== ""
        ? response.displayName
        : "";
    const avatar = response && typeof response.avatar === "string" && response.avatar !== ""
      ? response.avatar
      : null;
    const teams = Array.isArray(response && response.teams)
      ? response.teams
          .filter((team) => team && typeof team === "object")
          .map((team) => ({
            id: String(team.id || ""),
            name: String(team.name || team.namespace || "Team"),
            namespace: String(team.namespace || ""),
            isHome: team.isHome === true || String(team.namespace || "") === homeNamespace,
          }))
      : [];
    return { homeNamespace, displayName, avatar, teams, unavailable: false };
  } catch {
    return {
      homeNamespace: fallbackNamespace,
      displayName: "",
      avatar: null,
      teams: fallbackNamespace
        ? [{ id: "", name: teamName(fallbackNamespace), namespace: fallbackNamespace, isHome: true }]
        : [],
      unavailable: true,
    };
  }
}

function portfolioCard(ctx, portfolio) {
  const esc = ctx.esc;
  const teams = portfolio.teams.filter((team) => !isOrganizationRoot(team.namespace));
  const rows = teams.length > 0
    ? teams.map((team) =>
        '<div class="settings-team-item" role="listitem">' +
          '<span class="settings-team-mark" aria-hidden="true">' + esc(initialsOf(team.name)) + "</span>" +
          '<strong>' + esc(capitalizeLabel(team.name || teamName(team.namespace))) + "</strong>" +
          (team.isHome ? '<span class="pill pill--ok"><i class="dot"></i>Home</span>' : "") +
        "</div>",
      ).join("")
    : '<div class="sub">No active team memberships.</div>';
  const unavailable = portfolio.unavailable
    ? '<div class="sub settings-team-note">Additional team memberships are temporarily unavailable.</div>'
    : "";
  return '<section class="card settings-bento-card settings-bento-teams" aria-labelledby="profile-teams-heading">' +
    '<div class="between settings-bento-head"><h3 id="profile-teams-heading" style="margin:0">Your teams</h3><span class="subtle">' +
    esc(String(teams.length)) + (teams.length === 1 ? " team" : " teams") + "</span></div>" +
    '<div class="settings-team-list" role="list">' + rows + "</div>" +
    unavailable + "</section>";
}

function isOrganizationRoot(namespace) {
  return String(namespace || "").split("/").filter(Boolean).length <= 1;
}

function teamName(namespace) {
  const parts = String(namespace).split("/").filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : "Organization root";
}

function capitalizeLabel(value) {
  const label = String(value || "").trim();
  return label ? label[0].toUpperCase() + label.slice(1) : "";
}

function methodsCard(ctx, state, specs) {
  if (state.loadError) {
    return `<section class="card settings-bento-card settings-bento-methods"><h3 style="margin:0 0 2px">Sign-in methods</h3>
      <div class="sub">Could not load connections: ${ctx.esc(msgOf(state.loadError))}</div></section>`;
  }
  return `<section class="card settings-bento-card settings-bento-methods">
    <div class="between"><h3 style="margin:0">Sign-in methods${headingInfo("Sign-in methods", LAST_SIGN_IN_METHOD_NOTE)}</h3>
      <span class="subtle">${state.connectedCount} of 3 connected</span></div>
    <div class="intg-grid" style="margin-top:var(--s4)">${specs.map((spec) => methodCard(ctx, spec)).join("")}</div>
  </section>`;
}

// ---------------------------------------------------------------------------
// Method specs — one per sign-in door, connected or not.
// ---------------------------------------------------------------------------

function passwordSpec(state) {
  return {
    method: "password",
    title: "Email and password",
    icon: "mail",
    connected: state.hasPassword,
    sub: state.hasPassword
      ? "Sign in with your email address and password."
      : "No password set - this account signs in through a connected provider.",
    details: state.hasPassword ? [["Email", state.email, true]] : null,
    cta: "Details",
    action: "",
  };
}

function googleSpec(state) {
  const google = state.google;
  return {
    method: "google",
    title: "Google",
    icon: "google",
    connected: Boolean(google),
    sub: google ? "Google sign-in lands on this account." : "Connect Google to sign in with it.",
    details: google
      ? [
          ["Google account", String(google.login || ""), true],
          ["Connected", formatWhen(google.createdAt), false],
        ]
      : null,
    cta: google ? "Manage" : state.googleEnabled ? "Connect" : "Unavailable",
    action: google
      ? disconnectAction(state, "google", "Google")
      : state.googleEnabled
        ? `<button class="btn btn--solid btn--sm" data-action="google-connect">Connect Google</button>`
        : `<span class="subtle">Google sign-in is not configured on this deployment.</span>`,
  };
}

function githubSpec(state) {
  const github = state.github;
  return {
    method: "github",
    title: "GitHub",
    icon: "github",
    connected: Boolean(github),
    sub: github
      ? "GitHub sign-in lands on this account."
      : "GitHub sign-in remains a separate account until connected.",
    details: github
      ? [
          ["GitHub user", "@" + String(github.login || ""), true],
          ...(github.email ? [["GitHub email", String(github.email), true]] : []),
          ["Connected", formatWhen(github.createdAt), false],
        ]
      : null,
    cta: github ? "Manage" : state.githubEnabled ? "Connect" : "Unavailable",
    action: github
      ? disconnectAction(state, "github", "GitHub")
      : state.githubEnabled
        ? `<button class="btn btn--solid btn--sm" data-action="github-connect">Connect GitHub</button>`
        : `<span class="subtle">GitHub sign-in is not configured on this deployment.</span>`,
  };
}

// ---------------------------------------------------------------------------
// Tiles + pop-ups
// ---------------------------------------------------------------------------

/** One method tile — same square card the S14 connection grid uses. */
function methodCard(ctx, spec) {
  const esc = ctx.esc;
  const connectionLabel = spec.connected ? "Connected" : "Not connected";
  const accessibleLabel = `${spec.title} sign-in method, ${connectionLabel}, ${spec.cta}`;
  return `<button class="intg-card intg-card--status-only" data-action="profile-method-open" data-method="${esc(spec.method)}" aria-label="${esc(accessibleLabel)}">
    ${logoTile(spec)}
    <span class="intg-card-status">${statusPill(spec)}</span>
    <span class="intg-card-cta">${esc(spec.cta)}</span>
  </button>`;
}

import { organizationScopeLabel } from "../identity-labels.js";

/**
 * The server owns the invariant, but the drawer should not offer an action it
 * already knows will fail. A second verified method makes this provider
 * replaceable; after removal, the normal Connect flow can bind another account.
 */
function disconnectAction(state, provider, label) {
  if (state.connectedCount > 1) {
    return `<button class="btn btn--danger btn--sm" data-action="${provider}-disconnect">Disconnect</button>`;
  }
  return `<div class="profile-method-lock" data-method-lock="${provider}">
    <button class="btn btn--danger btn--sm" type="button" disabled aria-disabled="true">Disconnect</button>
    <span class="subtle">Connect another sign-in method before disconnecting ${label}.</span>
  </div>`;
}

function statusPill(spec) {
  return spec.connected
    ? `<span class="pill pill--live"><i class="dot"></i>Connected</span>`
    : `<span class="pill pill--warn"><i class="dot"></i>Not connected</span>`;
}

/** The right drawer behind each tile: status, connection details, the
 * connect/disconnect action, and direct paths to every other sign-in method. */
function methodModal(ctx, spec, specs) {
  const esc = ctx.esc;
  const details = spec.details
    ? `<div class="profile-method-detail-list">${spec.details
        .map(
          ([label, value, mono]) =>
            `<div class="profile-method-detail-row"><span>${esc(label)}</span><strong${mono ? ` class="mono"` : ""}>${esc(String(value))}</strong></div>`,
        )
        .join("")}</div>`
    : '<div class="profile-method-empty">This sign-in method is not connected yet.</div>';
  const related = specs
    .filter((candidate) => candidate.method !== spec.method)
    .map((candidate) => relatedMethodCard(ctx, candidate))
    .join("");
  const emailChangeNote = "Email changes require an assisted account migration so your access and audit history stay attached.";
  const emailChange = spec.method === "password"
    ? `<section class="profile-method-email-change" aria-labelledby="profile-email-change-heading">
        <div><div class="eyebrow">Account identity</div>
          <div class="profile-method-email-heading"><h4 id="profile-email-change-heading">Need to change this email?</h4>
            <span class="metric-info profile-method-info" role="note" tabindex="0"
              aria-label="Email change: ${esc(emailChangeNote)}" data-tip="${esc(emailChangeNote)}"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span></div></div>
        <a class="btn btn--sm profile-method-support" href="${EMAIL_CHANGE_SUPPORT_URL}"
          aria-label="Request email change by email">Request email change</a>
      </section>`
    : "";
  return `<div class="profile-method-modal source-wizard-overlay" id="profile-method-${esc(spec.method)}" hidden aria-hidden="true">
    <button class="source-wizard-backdrop" data-action="profile-method-close" aria-label="Close"></button>
    <div class="source-wizard-dialog profile-method-panel" role="dialog" aria-modal="true" aria-label="${esc(spec.title)} sign-in method">
      <header class="profile-method-header">
        <div class="between profile-method-titlebar">
          <div class="profile-method-identity">${logoTile(spec)}
            <div><div class="eyebrow">Sign-in method</div><h3>${esc(spec.title)}</h3></div></div>
          <div class="profile-method-header-actions">
            <button class="source-wizard-close halo-icon-control" data-action="profile-method-close" data-wizard-focus aria-label="Return to profile"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Close</span></button>
            <div class="profile-method-status">${statusPill(spec)}</div>
          </div>
        </div>
      </header>
      <div class="profile-method-body">
        <section class="profile-method-section" aria-labelledby="profile-method-${esc(spec.method)}-details-heading">
          <div class="profile-method-section-head"><div class="eyebrow">Current method</div>
            <h4 id="profile-method-${esc(spec.method)}-details-heading">Connection details</h4></div>
          ${details}
          ${spec.action ? `<div class="profile-method-primary-action">${spec.action}</div>` : ""}
        </section>
        ${emailChange}
        <section class="profile-method-related" aria-labelledby="profile-method-${esc(spec.method)}-related-heading">
          <div class="profile-method-related-head"><div><div class="eyebrow">Access options</div>
            <h4 id="profile-method-${esc(spec.method)}-related-heading">Other sign-in methods</h4></div></div>
          <div class="profile-method-options">${related}</div>
        </section>
        <div class="hint profile-method-modal-status" role="status" aria-live="polite"></div>
      </div>
    </div>
  </div>`;
}

function relatedMethodCard(ctx, spec) {
  const esc = ctx.esc;
  const status = spec.connected ? "Connected" : "Not connected";
  return `<button type="button" class="profile-method-option" data-action="profile-method-open" data-method="${esc(spec.method)}"
    aria-label="Open ${esc(spec.title)} sign-in details">
    ${logoTile(spec)}
    <span class="profile-method-option-copy"><strong>${esc(spec.title)}</strong><span>${status}</span></span>
    <span class="profile-method-option-action">${esc(spec.cta)}</span>
  </button>`;
}

/**
 * Provider mark. These are drawn inline rather than fetched from a logo CDN:
 * the Google "G" is a four-colour mark and the monochrome CDN glyph read as a
 * different product entirely. Inline also means the tile is correct offline and
 * on the first paint, with no external asset in the console.
 */
function logoTile(entry) {
  return '<span class="source-logo intg-logo" data-logo-kind="glyph" aria-hidden="true">' +
    iconSvg(entry.icon) + "</span>";
}

function iconSvg(name) {
  if (name === "google") {
    return '<svg viewBox="0 0 48 48" aria-hidden="true">' +
      '<path fill="#4285F4" d="M45.1 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h11.8c-.5 2.7-2.1 5-4.4 6.6v5.5h7.1c4.2-3.8 6.6-9.5 6.6-16.1z"/>' +
      '<path fill="#34A853" d="M24 46c6 0 11-2 14.5-5.4l-7.1-5.5c-2 1.3-4.5 2.1-7.4 2.1-5.7 0-10.6-3.9-12.3-9.1H4.4v5.7C7.9 41.1 15.4 46 24 46z"/>' +
      '<path fill="#FBBC05" d="M11.7 28.1c-.4-1.3-.7-2.7-.7-4.1s.2-2.8.7-4.1V14H4.4C2.9 17 2 20.4 2 24s.9 7 2.4 10l7.3-5.9z"/>' +
      '<path fill="#EA4335" d="M24 10.8c3.2 0 6.1 1.1 8.4 3.3l6.3-6.3C34.9 4.2 30 2 24 2 15.4 2 7.9 6.9 4.4 14l7.3 5.7c1.7-5.2 6.6-8.9 12.3-8.9z"/>' +
      "</svg>";
  }
  if (name === "github") {
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path fill="currentColor" d="M12 1.5a10.5 10.5 0 0 0-3.32 20.47c.53.1.72-.23.72-.5v-1.8c-2.92.63-3.54-1.4-3.54-1.4-.48-1.21-1.17-1.54-1.17-1.54-.95-.65.07-.64.07-.64 1.06.08 1.61 1.09 1.61 1.09.94 1.6 2.46 1.14 3.06.87.1-.68.37-1.14.66-1.4-2.33-.27-4.78-1.17-4.78-5.19 0-1.15.41-2.09 1.08-2.82-.11-.27-.47-1.34.1-2.79 0 0 .88-.28 2.88 1.08a9.9 9.9 0 0 1 5.24 0c2-1.36 2.88-1.08 2.88-1.08.57 1.45.21 2.52.1 2.79.67.73 1.08 1.67 1.08 2.82 0 4.03-2.46 4.92-4.8 5.18.38.33.72.97.72 1.96v2.9c0 .28.19.61.73.5A10.5 10.5 0 0 0 12 1.5z"/>' +
      "</svg>";
  }
  const bodies = {
    mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M4 7.5l8 5.5 8-5.5" stroke-linecap="round" stroke-linejoin="round"/>',
  };
  return (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">' +
    (bodies[name] || bodies.mail) +
    "</svg>"
  );
}

// ---------------------------------------------------------------------------
// Modal open/close
// ---------------------------------------------------------------------------

let keydownDoc = null;
let keydownHandler = null;

export function cleanup() {
  closeMethodModals(document);
}

function openMethodModal(method) {
  const modal = document.getElementById("profile-method-" + method);
  if (!modal) return;
  closeMethodModals(document);
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("source-modal-open");
  const focus = modal.querySelector("[data-wizard-focus]");
  if (focus) focus.focus();
  keydownDoc = document;
  keydownHandler = (ev) => {
    if (ev.key === "Escape") closeMethodModals(document);
  };
  document.addEventListener("keydown", keydownHandler);
}

function closeMethodModals(doc) {
  const modals = doc && typeof doc.querySelectorAll === "function" ? doc.querySelectorAll(".profile-method-modal") : [];
  for (const modal of modals) {
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
  }
  if (doc && doc.body) doc.body.classList.remove("source-modal-open");
  if (keydownDoc && keydownHandler) keydownDoc.removeEventListener("keydown", keydownHandler);
  keydownDoc = null;
  keydownHandler = null;
}

/** One-shot banner from the connect callback hash marker. */
function markerBanner(ctx) {
  const hash = String((typeof window !== "undefined" && window.location.hash) || "");
  const q = hash.indexOf("?");
  if (q < 0) return "";
  const params = new URLSearchParams(hash.slice(q + 1));
  const messages = {
    "linked:github": ["GitHub connected. Signing in with GitHub now lands on this account.", true],
    "linked:google": ["Google connected. Signing in with Google now lands on this account.", true],
    "error:github_conflict": ["That GitHub account is already connected to a different user.", false],
    "error:google_conflict": ["That Google account is already connected to a different user.", false],
    "error:github": ["GitHub connection failed. Please try again.", false],
    "error:google": ["Google connection failed. Please try again.", false],
  };
  const key = params.get("linked")
    ? "linked:" + params.get("linked")
    : params.get("error")
      ? "error:" + params.get("error")
      : "";
  const entry = messages[key];
  if (!entry) return "";
  return `<div class="card ${entry[1] ? "m8a-issued" : ""}" style="margin-bottom:var(--s4)">
    <div class="sub" style="margin:0">${ctx.esc(entry[0])}</div></div>`;
}

export const actions = {
  "settings-tab"(_ctx, el) {
    const tab = el && el.getAttribute ? String(el.getAttribute("data-tab") || "") : "";
    const doc = el && el.ownerDocument;
    if (!doc || !TABS.some(([id]) => id === tab)) return;
    activeTab = tab;
    doc.querySelectorAll("[data-settings-panel]").forEach((panel) => {
      panel.hidden = panel.getAttribute("data-settings-panel") !== tab;
    });
    doc.querySelectorAll('[data-action="settings-tab"]').forEach((button) => {
      const selected = button.getAttribute("data-tab") === tab;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-selected", selected ? "true" : "false");
      button.setAttribute("tabindex", selected ? "0" : "-1");
    });
  },

  async "org-name-save"(ctx, el) {
    const input = fieldNear(el, "#org-name-input");
    const status = panelStatus(el, "organization");
    setBusy(el, true, "Saving…");
    try {
      const response = await ctx.api.patch("/v1/admin/organization", {
        name: input ? input.value : "",
      });
      const savedName = response?.organization?.name;
      if (typeof savedName === "string" && typeof ctx.setCurrentOrganizationName === "function") {
        ctx.setCurrentOrganizationName(savedName);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not save: " + msgOf(err));
      setBusy(el, false, "Save");
    }
  },

  async "org-icon-pick"(ctx, el) {
    const status = panelStatus(el, "organization");
    const file = el.files && el.files[0];
    if (!file) return;
    setText(status, "Uploading…");
    let icon;
    try {
      icon = await downscaleToDataUrl(file);
    } catch (err) {
      setText(status, "Could not read that image: " + msgOf(err));
      return;
    }
    if (icon.length > MAX_ICON_CHARS) {
      setText(status, "That image is too large. Use a smaller one.");
      return;
    }
    try {
      await ctx.api.patch("/v1/admin/organization", { icon });
      if (typeof ctx.setCurrentOrganizationIcon === "function") {
        ctx.setCurrentOrganizationIcon(icon);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not save the icon: " + msgOf(err));
    }
  },

  async "org-icon-clear"(ctx, el) {
    const status = panelStatus(el, "organization");
    setBusy(el, true, "Removing…");
    try {
      await ctx.api.patch("/v1/admin/organization", { icon: null });
      if (typeof ctx.setCurrentOrganizationIcon === "function") {
        ctx.setCurrentOrganizationIcon(null);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not remove the icon: " + msgOf(err));
      setBusy(el, false, "Remove");
    }
  },

  async "profile-name-save"(ctx, el) {
    const input = fieldNear(el, "#profile-name-input");
    const status = panelStatus(el, "profile");
    if (!input || !String(input.value || "").trim()) {
      setText(status, "Your account needs a name.");
      if (input && typeof input.focus === "function") input.focus();
      return;
    }
    setBusy(el, true, "Saving…");
    try {
      const updated = await ctx.api.patch("/auth/profile", { displayName: input ? input.value : "" });
      if (typeof ctx.setCurrentPersonDisplayName === "function") {
        ctx.setCurrentPersonDisplayName(updated && updated.displayName);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not save: " + msgOf(err));
      setBusy(el, false, "Save");
    }
  },

  async "profile-avatar-pick"(ctx, el) {
    const status = panelStatus(el, "profile");
    const file = el.files && el.files[0];
    if (!file) return;
    setText(status, "Uploading...");
    let avatar;
    try {
      avatar = await downscaleToDataUrl(file);
    } catch (err) {
      setText(status, "Could not read that image: " + msgOf(err));
      return;
    }
    if (avatar.length > MAX_ICON_CHARS) {
      setText(status, "That image is too large. Use a smaller one.");
      return;
    }
    try {
      const updated = await ctx.api.patch("/auth/profile", { avatar });
      if (typeof ctx.setCurrentPersonAvatar === "function") {
        ctx.setCurrentPersonAvatar(updated && updated.avatar);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not save the photo: " + msgOf(err));
    }
  },

  async "profile-avatar-clear"(ctx, el) {
    const status = panelStatus(el, "profile");
    setBusy(el, true, "Removing...");
    try {
      const updated = await ctx.api.patch("/auth/profile", { avatar: null });
      if (typeof ctx.setCurrentPersonAvatar === "function") {
        ctx.setCurrentPersonAvatar(updated && updated.avatar);
      }
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not remove the photo: " + msgOf(err));
      setBusy(el, false, "Remove");
    }
  },

  "profile-method-open"(ctx, el) {
    openMethodModal(el.getAttribute("data-method"));
  },

  "profile-method-close"() {
    closeMethodModals(document);
  },

  "github-connect"() {
    // Full-page navigation into the kernel's OAuth redirect flow (mode=link
    // binds the callback to the active session).
    window.location.href = "/auth/github?mode=link";
  },

  async "google-connect"(ctx, el) {
    const status = statusFor(el);
    setBusy(el, true, "Redirecting…");
    let config = null;
    try {
      config = await ctx.api.get("/auth/sso/config");
    } catch (err) {
      setText(status, "Could not start Google connect: " + msgOf(err));
      setBusy(el, false, "Connect Google");
      return;
    }
    if (!config || config.enabled !== true || !config.url) {
      setText(status, "Google sign-in is not configured on this deployment.");
      setBusy(el, false, "Connect Google");
      return;
    }
    // The marker tells /console/login that the returning token connects an
    // account instead of minting a session. Session-scoped and read once.
    try {
      window.sessionStorage.setItem(LINK_FLAG, "google");
    } catch {
      setText(status, "Connecting Google needs session storage enabled in this browser.");
      setBusy(el, false, "Connect Google");
      return;
    }
    const redirect = window.location.origin + "/console/login";
    window.location.href =
      String(config.url).replace(/\/+$/, "") +
      "/auth/v1/authorize?provider=google&redirect_to=" +
      encodeURIComponent(redirect);
  },

  "github-disconnect": disconnect("github", "GitHub"),
  "google-disconnect": disconnect("google", "Google"),
};

/**
 * Downscale the picked file to a square PNG data URL in the browser. The kernel
 * caps what it stores; sending a 4 MB phone photo just to be refused is a worse
 * failure than never sending it, so the shrink happens before the request.
 */
async function downscaleToDataUrl(file) {
  if (!/^image\//.test(String(file.type || ""))) throw new Error("not an image");
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement("canvas");
  canvas.width = ICON_EDGE;
  canvas.height = ICON_EDGE;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("canvas unavailable");
  // Cover-crop: the mark is square everywhere it appears, so a letterboxed
  // rectangle would render as a small image floating in a big empty tile.
  const scale = Math.max(ICON_EDGE / bitmap.width, ICON_EDGE / bitmap.height);
  const width = bitmap.width * scale;
  const height = bitmap.height * scale;
  context.drawImage(bitmap, (ICON_EDGE - width) / 2, (ICON_EDGE - height) / 2, width, height);
  bitmap.close?.();
  return canvas.toDataURL("image/png");
}

/** Shared disconnect handler — the server owns the last-method refusal. */
function disconnect(provider, label) {
  return async function (ctx, el) {
    const status = statusFor(el);
    setBusy(el, true, "Disconnecting…");
    try {
      await ctx.api.del("/auth/identities/" + provider);
      await ctx.refresh();
    } catch (err) {
      setText(status, "Could not disconnect " + label + ": " + msgOf(err));
      setBusy(el, false, "Disconnect");
    }
  };
}

/** The input this button saves: its own row first, then the screen. */
function fieldNear(el, selector) {
  const row = el && typeof el.closest === "function" ? el.closest(".settings-inline-form") : null;
  return (
    (row && row.querySelector(selector)) ||
    (typeof document !== "undefined" ? document.querySelector(selector) : null)
  );
}

/** The live region inside the settings card the control belongs to. */
function panelStatus(el, panel) {
  const card = el && typeof el.closest === "function" ? el.closest(".settings-card") : null;
  return (
    (card && card.querySelector("[data-settings-status]")) ||
    (typeof document !== "undefined"
      ? document.querySelector('[data-settings-status="' + panel + '"]')
      : null)
  );
}

/** Errors surface inside the open pop-up when there is one, else on the
 * screen-level status line. */
function statusFor(el) {
  const dialog = el && typeof el.closest === "function" ? el.closest(".source-wizard-dialog") : null;
  const root = el && typeof el.closest === "function" ? el.closest(".screen") : null;
  return (
    (dialog && dialog.querySelector(".profile-method-modal-status")) ||
    (root && root.querySelector("#profile-status")) ||
    (typeof document !== "undefined" ? document.getElementById("profile-status") : null)
  );
}

function setBusy(el, busy, label) { if (!el) return; el.disabled = busy; if (label && "textContent" in el) el.textContent = label; }
function setText(node, text) { if (node) node.textContent = text; }
function msgOf(err) { return err && err.message ? err.message : "unknown error"; }
function formatWhen(value) { const time = Date.parse(String(value || "")); if (!Number.isFinite(time)) return "Unknown time"; return new Date(time).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }); }
function formatDay(value) { const time = Date.parse(String(value || "")); if (!Number.isFinite(time)) return "Unknown"; return new Date(time).toLocaleDateString("en-US", { dateStyle: "medium" }); }
