import { personDisplayName } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";

/**
 * S17 - Connected apps (M9 #11b, D29; CONTRACTS-OAUTH-CONNECT).
 *
 * The govern-side register of every app that holds a connection to this
 * deployment: awaiting approval / connected / disconnected, approve + revoke
 * (with reason), per-app token count and last use, and the server-enforced
 * tool list.
 *
 * Framing note: the nav says "Connected apps", not "OAuth clients", because
 * the thing an operator manages here is an APP (Claude, ChatGPT, a backend
 * service) — OAuth is the mechanism, not the subject. The jargon survives only
 * where it is load-bearing (the mono grant strings an admin may need to match
 * against a vendor's docs).
 *
 * Most apps never appear here by hand: an MCP client discovers this
 * deployment, registers itself, and a person approves it on the consent
 * screen. Hand-registration exists for the apps that cannot, and it leads with
 * the CONNECTOR lane on purpose — a hand-made client on the service-client
 * lane fails at /oauth/authorize with "may not request user authorization",
 * which reads as a server fault rather than the registration choice it is.
 *
 * A hand-registered app is created PENDING and mints nothing until approved.
 * The client secret is shown exactly once after creation (only its sha256 is
 * stored) - same one-shot banner discipline as the S3 key screens. Every
 * server-derived value is ctx.esc()'d; all interactivity is delegated
 * `actions` (no inline JS).
 */

function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

let lastSecret = null;
let lastSecretTimer = null;

const TOKEN_ROLES = [
  { value: "assistant", label: "Assistant", hint: "Read, search, and write governed memory." },
  { value: "read-only", label: "Read-only", hint: "Read memory and audit history only." },
];

// OA1 - the two lanes an app can be registered on. A connector must carry
// return addresses; a service client must not. The server re-derives and
// re-validates both, so this form is a guide, not the authority.
//
// ORDER IS LOAD-BEARING: the connector lane is first, and therefore the
// default. Nearly every app a human hand-registers here is an MCP client
// (Claude, ChatGPT, Gemini), and those can ONLY use the connector lane —
// defaulting to the service lane silently produced clients that failed at
// /oauth/authorize with "This app may not request user authorization".
const GRANT_LANES = [
  {
    value: "authorization_code",
    label: "App a person signs in to",
    hint: "For Claude, ChatGPT, Gemini, and other sign-in apps.",
    grants: ["authorization_code", "refresh_token"],
    needsRedirect: true,
    mono: "authorization code + PKCE",
  },
  {
    value: "client_credentials",
    label: "Backend service (no human)",
    hint: "For scripts and services without sign-in.",
    grants: ["client_credentials"],
    needsRedirect: false,
    mono: "client credentials",
  },
];

export async function render(ctx) {
  let clients;
  try {
    const response = await ctx.api.get("/v1/admin/oauth/clients");
    clients = Array.isArray(response) ? response : Array.isArray(response && response.clients) ? response.clients : [];
  } catch (err) {
    return errorScreen(ctx, err);
  }
  const mutate = canMutate(ctx);
  const pending = clients.filter((client) => String(client.status || "") === "pending");
  const approved = clients.filter((client) => String(client.status || "") === "approved");
  const revoked = clients.filter((client) => String(client.status || "") === "revoked");
  const acts = mutate
    ? `<div class="acts"><button class="btn btn--solid btn--sm" data-action="oauth-client-create" aria-controls="oauth-client-panel" aria-haspopup="dialog" aria-expanded="false">Add manually</button></div>`
    : "";
  // No subtext under the h1: console-header.test.ts enforces that rule across
  // every tab. The journey card immediately below carries the explanation.
  return `<div class="oauth-screen">
    <div class="head"><div><div class="eyebrow">Govern</div><h1>Connected apps</h1></div>${acts}</div>
    ${connectionJourney(ctx)}
    ${statusOverview(pending.length, approved.length, revoked.length)}
    ${securityPolicy()}
    ${secretBanner(ctx)}
    ${mutate ? rightPanelHtml({ id: "oauth-client-panel", eyebrow: "Connected apps", title: "Add an app manually", closeAction: "oauth-client-close", className: "oauth-client-drawer", body: createForm(ctx) }) : ""}
    ${section(ctx, "Waiting for approval", pending, mutate, "pending")}
    ${section(ctx, "Connected", approved, mutate, "approved")}
    ${archiveSection(ctx, revoked)}
    <div class="hint" id="oauth-status" role="status" aria-live="polite"></div>
  </div>`;
}

function connectionJourney(ctx) {
  const origin = typeof window === "undefined" ? "https://halomem.example" : window.location.origin;
  return `<section class="oauth-journey card" aria-labelledby="oauth-journey-title">
    <div class="oauth-journey__intro">
      <div><span class="eyebrow">Recommended setup</span>
        <h2 id="oauth-journey-title">Connect in three steps${headingInfo("Connect in three steps", "Manage access for agents and apps.")}</h2></div>
      <a class="btn btn--outline btn--sm oauth-journey__guide" href="#agentconnections">Setup guides</a>
    </div>
    <ol class="oauth-journey__steps">
      <li><span class="oauth-step-number" aria-hidden="true">1</span><div><b>Copy connection URL</b>
        <code class="oauth-endpoint">${ctx.esc(origin)}/mcp</code></div></li>
      <li><span class="oauth-step-number" aria-hidden="true">2</span><div><b>Add it to your agent</b>
        <span>Use any MCP-compatible app.</span></div></li>
      <li><span class="oauth-step-number" aria-hidden="true">3</span><div><b>Approve here</b>
        <span>Review the requested access.</span></div></li>
    </ol>
  </section>`;
}

function statusOverview(pending, approved, revoked) {
  return `<dl class="oauth-status-overview" aria-label="Connection status">
    <div><dt>Waiting</dt><dd><strong data-oauth-count="pending">${pending}</strong></dd></div>
    <div><dt>Connected</dt><dd><strong data-oauth-count="approved">${approved}</strong></dd></div>
    <div><dt>Disconnected</dt><dd><strong data-oauth-count="revoked">${revoked}</strong></dd></div>
  </dl>`;
}

function securityPolicy() {
  return `<div class="oauth-security"><details class="compact-disclosure oauth-guidance">
    <summary>Connection security</summary>
    <div class="compact-disclosure__body">
      <div><b>Consent required.</b><span>Sign-in apps ask before connecting.</span></div>
      <div><b>Access is scoped.</b><span>Team, role, and tool limits apply.</span></div>
      <div><b>Revocation is immediate.</b><span>Disconnecting removes all access.</span></div>
    </div>
  </details></div>`;
}

/**
 * The lede. Answers the question an operator actually arrives with — "how do
 * I put this in Claude / ChatGPT / Gemini?" — before the register below it.
 * Deliberately does NOT restate S14's per-client recipes; it points there.
 */
function howToConnect(ctx) {
  const origin = typeof window === "undefined" ? "https://halomem.example" : window.location.origin;
  return `<div class="card" style="margin-bottom:var(--s5)">
    <h3 style="margin-top:0">Connecting an app${headingInfo("Connecting an app", "Most apps add themselves. In Claude, ChatGPT, Gemini, or any MCP client, add a connector with this server URL - the app registers itself, then sends you here to sign in and approve it. Nothing is pasted by hand, and no API key is involved.")}</h3>
    <div class="snippet mono" style="margin-top:var(--s3)">${ctx.esc(origin)}/mcp</div>
    <div class="subtle" style="margin-top:var(--s3)">Per-client setup steps live on
      <a href="#agentconnections">Agent connections</a>. Use <b>Add an app manually</b> only for an app that cannot register itself.</div>
  </div>`;
}

function section(ctx, title, clients, mutate, kind) {
  if (!clients.length && kind === "pending") return "";
  const cards = clients.length
    ? clients.map((client) => clientCard(ctx, client, mutate)).join("")
    : `<div class="oauth-empty"><span class="oauth-empty__mark" aria-hidden="true">+</span><div>
          <b>No connected apps.</b></div></div>`;
  return `<section class="oauth-group oauth-group--${ctx.esc(kind)}" aria-label="${ctx.esc(title)}">
    <div class="oauth-group__head"><div><h2>${ctx.esc(title)}</h2></div>
      <span class="oauth-group__count">${clients.length}</span></div>
    ${cards}</section>`;
}

function archiveSection(ctx, clients) {
  if (!clients.length) return "";
  return `<details class="oauth-archive" aria-label="Disconnected apps">
    <summary><span>Disconnected</span><span class="oauth-archive__meta">
      <span class="oauth-group__count">${clients.length}</span><span aria-hidden="true">+</span></span></summary>
    <div class="oauth-archive__body">${clients.map((client) => clientCard(ctx, client, false)).join("")}</div>
  </details>`;
}

function clientCard(ctx, client, mutate) {
  const id = ctx.esc(String(client.id || ""));
  const status = String(client.status || "").toLowerCase();
  const isDcr = String(client.origin || "") === "dcr";
  const tools = Array.isArray(client.allowedTools) ? client.allowedTools : [];
  // DCR (connector) clients hold no standing tool list — each user consent
  // snapshots the scope's tools onto the tokens it mints (OA4).
  const toolChips = tools.length
    ? tools.map((tool) => `<span class="badge badge--role mono">${ctx.esc(tool)}</span>`).join(" ")
    : isDcr
      ? '<span class="sub">Per-consent: set by the scope each user approves</span>'
      : '<span class="pill pill--crit"><i class="dot"></i>No tools allowed</span>';
  const actions = mutate && status === "pending"
    ? `<div class="row"><button class="btn btn--primary btn--sm" data-action="oauth-client-approve" data-id="${id}">Approve</button>
        ${revokeControls(ctx, id, "Reject")}</div>`
    : mutate && status === "approved"
      ? `<div class="row">${revokeControls(ctx, id, "Disconnect")}</div>`
      : "";
  const approval = status === "approved" && client.approvedBy
    ? `<div class="m8a-kv"><span>Approved</span><b>${ctx.esc(personDisplayName(client.approvedBy, ctx.personLabel, "human"))} · ${ctx.esc(formatWhen(client.approvedAt))}</b></div>` : "";
  const revocation = status === "revoked"
    ? `<div class="m8a-kv"><span>Revoked</span><b>${ctx.esc(personDisplayName(client.revokedBy, ctx.personLabel, "human") || "-")} · ${ctx.esc(formatWhen(client.revokedAt))}</b></div>` : "";
  const originPill = isDcr
    ? '<span class="badge badge--role">Added itself</span> '
    : "";
  // The lane is the single most load-bearing fact on this card: an app on the
  // wrong one fails at /oauth/authorize with "may not request user
  // authorization", which reads as a server fault rather than a registration
  // choice. Show it in plain words, keep the mono grant strings underneath for
  // anyone matching this against a vendor's OAuth docs.
  const grants = Array.isArray(client.grantTypes) && client.grantTypes.length
    ? client.grantTypes
    : ["client_credentials"];
  const isConnector = grants.indexOf("authorization_code") !== -1;
  const redirects = Array.isArray(client.redirectUris) ? client.redirectUris : [];
  const grantRow = `<div class="m8a-kv"><span>Connects as</span><b>${
    isConnector
      ? "An app a person signs in to"
      : "A backend service, on its own behalf"
  }<br><small class="subtle mono">${ctx.esc(grants.join(", "))}</small></b></div>`;
  const redirectRow = isConnector
    ? `<div class="m8a-kv"><span>Returns to</span><b class="mono">${
        redirects.length
          ? redirects.map((uri) => ctx.esc(String(uri))).join("<br>")
          : '<span class="pill pill--crit"><i class="dot"></i>None registered</span>'
      }</b></div>`
    : "";
  return `<details class="compact-disclosure card oauth-client" style="margin-bottom:var(--s3)">
    <summary><span class="oauth-client-summary-copy"><b>${ctx.esc(String(client.name || "Unnamed client"))}</b>
      <span class="mono subtle">${originPill}${ctx.esc(String(client.clientId || ""))}</span></span>${statusPill(ctx, status)}</summary>
    <div class="compact-disclosure__body">
      ${client.description ? `<div class="sub">${ctx.esc(String(client.description))}</div>` : ""}
      <div class="m8a-grant" style="margin-top:var(--s3)">
        <div class="m8a-kv"><span>Team</span><b class="mono">${ctx.esc(String(client.namespace || "")) || "Organization root"}</b></div>
        ${grantRow}${redirectRow}
        <div class="m8a-kv"><span>Access level</span><b>${ctx.esc(roleLabel(client.tokenRole))}</b></div>
        <div class="m8a-kv"><span>Token lifetime</span><b>${ctx.esc(ttlLabel(client.tokenTtlSeconds))}</b></div>
        <div class="m8a-kv"><span>Tokens issued</span><b>${ctx.esc(String(Number(client.tokenCount) || 0))} total · ${ctx.esc(String(Number(client.activeTokenCount) || 0))} active</b></div>
        <div class="m8a-kv"><span>Last used</span><b>${client.lastTokenUsed ? ctx.esc(formatWhen(client.lastTokenUsed)) : "Never"}</b></div>
        <div class="m8a-kv"><span>Added by</span><b>${ctx.esc(personDisplayName(client.requestedBy, ctx.personLabel, "human") || "-")} · ${ctx.esc(formatWhen(client.createdAt))}</b></div>
        ${approval}${revocation}
        <div class="m8a-kv"><span>Can use</span><b>${toolChips}</b></div>
      </div>
      ${actions}
    </div>
  </details>`;
}

function revokeControls(ctx, id, label) {
  return `<div class="row" style="align-items:flex-end;flex-wrap:wrap;gap:var(--s2)">
    <div class="field" style="margin:0;min-width:220px"><label for="oauth-reason-${id}">Reason</label>
      <input class="input" id="oauth-reason-${id}" placeholder="Why is this app being disconnected?" autocomplete="off"></div>
    <button class="btn btn--danger btn--sm" data-action="oauth-client-revoke" data-id="${id}">${ctx.esc(label)}</button></div>`;
}

function createForm(ctx) {
  const roleOptions = TOKEN_ROLES.map((role, index) =>
    `<label class="m8a-check" for="oauth-role-${ctx.esc(role.value)}">
      <input id="oauth-role-${ctx.esc(role.value)}" type="radio" name="oauth-token-role" value="${ctx.esc(role.value)}"${index === 0 ? " checked" : ""}>
      <span><b>${ctx.esc(role.label)}</b><br><small class="subtle">${ctx.esc(role.hint)}</small></span></label>`).join("");
  const laneOptions = GRANT_LANES.map((lane, index) =>
    `<label class="m8a-check" for="oauth-lane-${ctx.esc(lane.value)}">
      <input id="oauth-lane-${ctx.esc(lane.value)}" type="radio" name="oauth-grant-lane" value="${ctx.esc(lane.value)}"${index === 0 ? " checked" : ""}>
      <span><b>${ctx.esc(lane.label)}</b> <small class="subtle mono">${ctx.esc(lane.mono)}</small>
        <br><small class="subtle">${ctx.esc(lane.hint)}</small></span></label>`).join("");
  return `<div class="oauth-create" id="oauth-client-form">
      <div class="sub">Manual apps need approval before access.</div>
      <div class="field"><label for="oauth-name">App name</label>
        <input class="input" id="oauth-name" placeholder="For example, Claude for the sales team" autocomplete="off"></div>
      <div class="field"><label for="oauth-description">Description</label>
        <input class="input" id="oauth-description" placeholder="What does this app do?" autocomplete="off"></div>
      <div class="field"><span class="m8a-field-label">How it connects</span><div class="m8a-checks">${laneOptions}</div></div>
      <div class="field"><label for="oauth-redirects">Where it returns to</label>
        <textarea class="input mono" id="oauth-redirects" rows="2" placeholder="https://claude.ai/api/mcp/auth_callback"></textarea>
        <div class="subtle">Sign-in apps only. Paste the app's exact callback URL.</div></div>
      <div class="field"><span class="m8a-field-label">Access level</span><div class="m8a-checks">${roleOptions}</div></div>
      <details class="oauth-advanced">
        <summary>Advanced OAuth settings</summary>
        <div class="oauth-advanced__body">
          <div class="field"><label for="oauth-ttl">Session length</label>
            <select class="input" id="oauth-ttl">
              <option value="900">15 minutes</option><option value="3600" selected>1 hour</option>
              <option value="14400">4 hours</option><option value="86400">24 hours</option>
            </select>
            <div class="subtle">How long access tokens stay valid.</div></div>
          <div class="field"><label for="oauth-tools">Exact tool names</label>
            <textarea class="input mono" id="oauth-tools" rows="2" placeholder="mem_search, mem_read"></textarea>
            <div class="subtle">Comma-separated. Leave blank for sign-in apps.</div></div>
        </div>
      </details>
      <button class="btn btn--solid" data-action="oauth-client-submit">Add app for approval</button>
      <div class="hint" id="oauth-create-status" role="status" aria-live="polite"></div>
  </div>`;
}

function secretBanner(ctx) {
  if (!lastSecret) return "";
  return `<div class="card m8a-issued"><div class="between"><h3>App added: copy the secret now</h3>
    <span class="pill pill--warn"><i class="dot"></i>Shown once</span></div>
    <div class="sub">App <span class="mono">${ctx.esc(lastSecret.clientId || "")}</span> is waiting for approval. Secret clears after one minute.</div>
    <div class="m8a-kv"><span>client_id</span><b class="mono">${ctx.esc(lastSecret.clientId || "")}</b></div>
    <div class="snippet" id="oauth-secret">${ctx.esc(lastSecret.secret || "")}</div>
    <div class="row" style="margin-top:var(--s4)">
      <button class="btn btn--primary" data-action="oauth-secret-copy">Copy secret and clear</button>
      <button class="btn btn--ghost" data-action="oauth-secret-dismiss">Clear now</button>
      <span class="subtle" id="oauth-secret-status" role="status"></span></div></div>`;
}

function statusPill(ctx, status) {
  if (status === "approved") return '<span class="pill pill--live"><i class="dot"></i>Connected</span>';
  if (status === "revoked") return '<span class="pill pill--crit"><i class="dot"></i>Disconnected</span>';
  if (status === "pending") return '<span class="pill pill--warn"><i class="dot"></i>Waiting for approval</span>';
  return `<span class="pill pill--warn"><i class="dot"></i>${ctx.esc(status)}</span>`;
}

function errorScreen(ctx, err) {
  const message = ctx.esc(err && err.message ? err.message : "Could not load connected apps.");
  return `<div class="head"><div><div class="eyebrow">Govern</div><h1>Connected apps</h1></div></div>
    <div class="card"><div class="sub">Something went wrong.</div><p>${message}</p></div>`;
}

export const actions = {
  "oauth-client-create"(_ctx, el) {
    const root = el.closest(".screen") || document;
    openRightPanel(root.querySelector("#oauth-client-panel"), el);
  },

  "oauth-client-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
  },

  async "oauth-client-submit"(ctx, el) {
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#oauth-create-status");
    const name = value(root, "#oauth-name");
    if (!name) return setText(status, "A client name is required.");
    const ttl = Number(value(root, "#oauth-ttl") || "3600");
    if (!Number.isInteger(ttl) || ttl < 60 || ttl > 86400) {
      return setText(status, "Token lifetime must be 60..86400 seconds.");
    }
    const laneValue = checkedRadio(root, 'input[name="oauth-grant-lane"]') || "client_credentials";
    const lane = GRANT_LANES.filter((entry) => entry.value === laneValue)[0] || GRANT_LANES[0];
    const redirectUris = lineOrCommaList(value(root, "#oauth-redirects"));
    if (lane.needsRedirect && !redirectUris.length) {
      return setText(status, "A connector needs at least one redirect URI - copy it from the app you are connecting.");
    }
    const payload = {
      name,
      description: value(root, "#oauth-description"),
      tokenRole: checkedRadio(root, 'input[name="oauth-token-role"]') || "assistant",
      tokenTtlSeconds: ttl,
      allowedTools: commaList(value(root, "#oauth-tools")),
      grantTypes: lane.grants,
      redirectUris: lane.needsRedirect ? redirectUris : [],
    };
    setBusy(el, true, "Registering…");
    try {
      const response = await ctx.api.post("/v1/admin/oauth/clients", payload);
      if (!response || !response.clientSecret) throw new Error("server returned no client secret");
      const record = response.record || {};
      lastSecret = { secret: response.clientSecret, clientId: record.clientId || "", name: record.name || name };
      scheduleSecretClear();
      await ctx.go("s17");
    } catch (err) {
      setText(status, "Registration failed: " + msgOf(err));
    } finally { setBusy(el, false, "Register client"); }
  },

  async "oauth-client-approve"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const status = (el.closest(".screen") || document).querySelector("#oauth-status");
    setBusy(el, true, "Approving…");
    try {
      await ctx.api.post("/v1/admin/oauth/clients/" + encodeURIComponent(id) + "/approve", {});
      await ctx.go("s17");
    } catch (err) {
      setText(status, "Approve failed: " + msgOf(err));
      setBusy(el, false, "Approve");
    }
  },

  async "oauth-client-revoke"(ctx, el) {
    const id = el.getAttribute("data-id");
    if (!id) return;
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#oauth-status");
    const reason = value(root, "#oauth-reason-" + cssEscape(id));
    setBusy(el, true, "Revoking…");
    try {
      await ctx.api.post("/v1/admin/oauth/clients/" + encodeURIComponent(id) + "/revoke", { reason });
      await ctx.go("s17");
    } catch (err) {
      setText(status, "Revoke failed: " + msgOf(err));
      setBusy(el, false, "Revoke");
    }
  },

  async "oauth-secret-copy"(ctx, el) {
    const root = el.closest(".screen") || document;
    const status = root.querySelector("#oauth-secret-status");
    try {
      await copyText(lastSecret ? lastSecret.secret || "" : "", root.querySelector("#oauth-secret"));
      clearSecret(root);
      setText(status, "Copied and cleared.");
      return true;
    } catch {
      setText(status, "Copy failed. Select manually.");
      return false;
    }
  },
  async "oauth-secret-dismiss"(ctx, el) {
    clearSecret(el && el.closest ? el.closest(".screen") : null);
    await ctx.go("s17");
  },
};

export function cleanup() {
  if (typeof document !== "undefined") closeRightPanel(document);
}

function scheduleSecretClear() {
  if (lastSecretTimer) clearTimeout(lastSecretTimer);
  lastSecretTimer = setTimeout(() => clearSecret(typeof document === "undefined" ? null : document), 60_000);
  if (lastSecretTimer && typeof lastSecretTimer.unref === "function") lastSecretTimer.unref();
}
function clearSecret(root) {
  lastSecret = null;
  if (lastSecretTimer) clearTimeout(lastSecretTimer);
  lastSecretTimer = null;
  const node = root && root.querySelector ? root.querySelector("#oauth-secret") : null;
  if (node) node.textContent = "Cleared";
}
async function copyText(text, node) {
  if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
  const range = document.createRange(); range.selectNodeContents(node); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); document.execCommand("copy"); selection.removeAllRanges();
}
function cssEscape(id) {
  return typeof CSS !== "undefined" && CSS.escape ? CSS.escape(id) : String(id).replace(/[^A-Za-z0-9_-]/g, "");
}
function checkedRadio(root, selector) {
  const inputs = root && root.querySelectorAll ? root.querySelectorAll(selector) : [];
  for (const input of inputs) if (input.checked) return String(input.value || "");
  return "";
}
function value(root, selector) { const input = root && root.querySelector ? root.querySelector(selector) : null; return input && input.value != null ? String(input.value).trim() : ""; }
function commaList(raw) { return [...new Set(String(raw || "").split(",").map((part) => part.trim()).filter(Boolean))]; }
// Redirect URIs may legitimately contain commas in a query string, so newlines
// separate first; a single line still splits on commas for convenience.
function lineOrCommaList(raw) {
  const lines = String(raw || "").split(/[\r\n]+/).map((part) => part.trim()).filter(Boolean);
  return [...new Set(lines.length > 1 ? lines : commaList(lines[0] || ""))];
}
function setBusy(el, busy, label) { if (!el) return; el.disabled = busy; if (label && "textContent" in el) el.textContent = label; }
function setText(node, text) { if (node) node.textContent = text; }
function msgOf(err) { return err && err.message ? err.message : "unknown error"; }
function roleLabel(role) { const found = TOKEN_ROLES.find((entry) => entry.value === String(role || "")); return found ? found.label : String(role || "-"); }
function ttlLabel(seconds) { const ttl = Number(seconds) || 0; if (ttl % 3600 === 0) return `${ttl / 3600}h`; if (ttl % 60 === 0) return `${ttl / 60}m`; return `${ttl}s`; }
function formatWhen(value) { const time = Date.parse(String(value || "")); if (!Number.isFinite(time)) return "Unknown time"; return new Date(time).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }); }
