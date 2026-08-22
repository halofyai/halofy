/**
 * Halofy Control Room - shell + shared lib + auth (Module A).
 *
 * Vanilla ES module, no framework, no deps. On load it resolves the human
 * identity via GET /auth/me (cookie-only, httpOnly - the JS never reads the
 * token); a 401 redirects to /console/login. It then builds the `ctx` object every
 * screen renderer codes against (api, esc, identity, go, ui), renders the
 * role-filtered rail, and runs a hash/data-s router that dynamically imports
 * ./screens/s<N>.js, sets screen-content.innerHTML = await mod.render(ctx), and wires
 * data-action clicks through ONE delegated listener.
 *
 * Screens are PURE string-returning renderers: they receive `ctx`, import
 * nothing from each other, and every API-derived value they interpolate goes
 * through ctx.esc() - the only XSS defense.
 */

import { createAssistantDock } from "./assistant-dock.js";
import {
  confirmationFor,
  createActionToaster,
  shouldConfirmAction,
  trackActionRequests,
} from "./action-toast.js";
import {
  breadcrumbMarkup,
  buildBreadcrumbTrail,
} from "./breadcrumbs.js";
import { createCommandPalette, shortcutLabel } from "./command-palette.js";
import { fabricLoader } from "./fabric.js";
import { headingInfo } from "./heading-info.js";
import { createLimitNotifier, isLimitError } from "./limit-toast.js";
import { createMobileNavigation } from "./mobile-nav.js";
import { createNotificationCenter } from "./notification-center.js";
import {
  canonicalHash,
  screenIdFromHash,
  screenTargetHash,
} from "./routes.js";
import {
  createPersonDirectory,
  organizationScopeLabel,
  personAvatarHtml,
  personAvatarUrl,
  personDisplayName,
} from "./identity-labels.js";
import {
  load as loadSetupChecklist,
  badge as setupBadge,
} from "./screens/setup-checklist.js";

// ---------------------------------------------------------------------------
// esc - HTML-escape any value. The single escaping primitive every screen uses.
// ---------------------------------------------------------------------------

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Surface. The same module boots two pages: the full console (index.html) and
// the whitelabel chat page (chat.html, served at /chat), which sets
// data-surface="chat" on <body>. The chat surface is a VISUAL simplifier only:
// it locks the router to the Assistant screen and skips the console chrome
// (rail, breadcrumbs, dock, palette). Identity, RBAC, and the setup gate are
// untouched — every API call is the same cookie-authenticated call the console
// makes, and the server enforces its own gates regardless of surface.
// ---------------------------------------------------------------------------

const SURFACE =
  typeof document !== "undefined" &&
  document.body &&
  document.body.getAttribute("data-surface") === "chat"
    ? "chat"
    : "console";

/** Where a lost session lands. Chat users come back to /chat after sign-in. */
const LOGIN_URL =
  SURFACE === "chat" ? "/console/login?next=%2Fchat" : "/console/login";

// ---------------------------------------------------------------------------
// api - fetch wrappers. Cookie-only auth (credentials:'include'); parse JSON;
// throw { status, message, code?, retryAfter } on a non-2xx response. A 401 anywhere
// means the session is gone → bounce to login.
// ---------------------------------------------------------------------------

/**
 * Delta-seconds from a `retry-after` header, or 0 when absent/unusable. The
 * kernel always sends delta-seconds (never the HTTP-date form), so anything
 * non-numeric or non-positive is reported as "no guidance" rather than guessed.
 */
export function parseRetryAfter(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return Math.ceil(seconds);
}

function retryAfterOf(res) {
  if (!res || !res.headers || typeof res.headers.get !== "function") return 0;
  return parseRetryAfter(res.headers.get("retry-after"));
}

async function request(method, path, body, extra) {
  const opts = { method, credentials: "include", headers: {} };
  if (body !== undefined) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  // M10: per-request header merge (the View-as preview credential travels
  // ONLY in its dedicated header — never a query string or body).
  if (extra && extra.headers) {
    for (const name of Object.keys(extra.headers)) {
      opts.headers[name] = extra.headers[name];
    }
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (networkErr) {
    throw { status: 0, message: "network error" };
  }
  if (res.status === 401) {
    window.location = LOGIN_URL;
    // Reject so callers stop; navigation is already underway.
    throw { status: 401, message: "unauthorized" };
  }
  let data = null;
  const text = await res.text();
  if (text !== "") {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const message =
      data && typeof data === "object" && typeof data.error === "string"
        ? data.error
        : `request failed (${res.status})`;
    const code = data && typeof data === "object" && typeof data.code === "string"
      ? data.code
      : undefined;
    const failure = {
      status: res.status,
      message,
      ...(code ? { code } : {}),
      ...limitFields(data),
      retryAfter: retryAfterOf(res),
    };
    reportLimit(failure);
    throw failure;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Limit toasts. Every allowance denial (early-access 402, credits, the
// per-minute clamp, the one-turn Assistant guard) surfaces through the SAME
// top-right toaster as success confirmations, from this one choke point, so
// no screen carries limit copy of its own. Installed by boot(); before that
// (and in tests) it is a no-op.
// ---------------------------------------------------------------------------
let limitNotifier = null;

/** Test seam + boot wiring: the notifier that receives every failed response. */
export function setLimitNotifier(notifier) {
  limitNotifier = notifier && typeof notifier.notify === "function" ? notifier : null;
}

function reportLimit(failure) {
  try {
    limitNotifier?.notify(failure);
  } catch {
    /* a toast must never turn a typed failure into a different failure */
  }
}

/** The early-access denial body carries which allowance and its ceiling. */
function limitFields(data) {
  if (!data || typeof data !== "object") return {};
  return {
    ...(typeof data.feature === "string" ? { feature: data.feature } : {}),
    ...(typeof data.limit === "number" ? { limit: data.limit } : {}),
  };
}

// Share only identical GETs that are still in flight. The request headers are
// part of the key because preview/view-as credentials change the authorized
// projection of a route; sharing across those headers would cross a security
// boundary. Settled responses are removed immediately, so this is not a stale
// data cache. Mutations invalidate the map on both sides of the write so a
// refresh can never inherit a read that began against the pre-write state.
const inFlightGets = new Map();

function getRequestKey(path, extra) {
  const headers = extra && extra.headers && typeof extra.headers === "object"
    ? extra.headers
    : {};
  const normalizedHeaders = Object.keys(headers)
    .map((name) => [name.toLowerCase(), String(headers[name])])
    .sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify([path, normalizedHeaders]);
}

export function requestGet(path, extra) {
  const key = getRequestKey(path, extra);
  const existing = inFlightGets.get(key);
  if (existing) return existing;

  const pending = request("GET", path, undefined, extra);
  inFlightGets.set(key, pending);
  const clear = () => {
    if (inFlightGets.get(key) === pending) inFlightGets.delete(key);
  };
  pending.then(clear, clear);
  return pending;
}

export async function requestMutation(method, path, body) {
  inFlightGets.clear();
  try {
    return await request(method, path, body);
  } finally {
    inFlightGets.clear();
  }
}

/**
 * A GET whose RESPONSE METADATA matters as much as its body — a file download.
 * `request` parses and discards the response, so a caller could not tell a
 * complete export from a truncated one. This returns the body text plus the
 * headers that state it, keeping the same cookie auth and 401 bounce.
 */
async function requestRaw(path) {
  let res;
  try {
    res = await fetch(path, { method: "GET", credentials: "include" });
  } catch {
    throw { status: 0, message: "network error" };
  }
  if (res.status === 401) {
    window.location = LOGIN_URL;
    throw { status: 401, message: "unauthorized" };
  }
  const text = await res.text();
  if (!res.ok) {
    let message = `request failed (${res.status})`;
    let code;
    let parsed = null;
    try {
      parsed = JSON.parse(text);
      if (parsed && typeof parsed.error === "string") message = parsed.error;
      if (parsed && typeof parsed.code === "string") code = parsed.code;
    } catch {
      /* a non-JSON error body keeps the status message */
    }
    const failure = {
      status: res.status,
      message,
      ...(code ? { code } : {}),
      ...limitFields(parsed),
      retryAfter: retryAfterOf(res),
    };
    reportLimit(failure);
    throw failure;
  }
  return {
    text,
    header: (name) =>
      res.headers && typeof res.headers.get === "function" ? res.headers.get(name) : null,
  };
}

const api = {
  get: requestGet,
  raw: (path) => requestRaw(path),
  post: (path, body) => requestMutation("POST", path, body ?? {}),
  patch: (path, body) => requestMutation("PATCH", path, body ?? {}),
  put: (path, body) => requestMutation("PUT", path, body ?? {}),
  del: (path) => requestMutation("DELETE", path),
};

// ---------------------------------------------------------------------------
// ui - HTML-string component helpers. app.css classes, matching the prototype.
// Callers pass ALREADY-SAFE html (values run through ctx.esc first). The ui
// helpers only assemble structure; they do NOT escape (a helper can't know
// which arg is raw text vs. intentional markup), so screens escape at the source.
// ---------------------------------------------------------------------------

function attr(name, value) {
  return value === undefined || value === null || value === ""
    ? ""
    : ` ${name}="${esc(value)}"`;
}

/** Keep compact metric context available to pointer and keyboard users. */
function statInfo(label, detail) {
  if (!detail) return "";
  return (
    '<span class="metric-info stat-info" role="note" tabindex="0" aria-label="' +
    (label ?? "Metric") +
    ": " +
    detail +
    '" data-tip="' +
    detail +
    '"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span>'
  );
}

const ui = {
  /** Descriptive page/section copy, collapsed behind an accessible info icon. */
  info(label, detail) {
    return headingInfo(label, detail);
  },

  /** Page header: eyebrow + h1 + right-aligned action buttons. */
  head({ eyebrow, title, sub, acts } = {}) {
    const left =
      `<div>` +
      (eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : "") +
      (title ? `<h1>${title}${sub ? ui.info(title, sub) : ""}</h1>` : "") +
      `</div>`;
    const right = acts ? `<div class="acts">${acts}</div>` : "";
    return `<div class="head">${left}${right}</div>`;
  },

  /** Stat card: k (label) + v (value), with context in an info tooltip. */
  stat({ k, v, foot, delta, tone, priority = "secondary" } = {}) {
    const toneClass = tone ? ` ${tone}` : "";
    const deltaHtml = delta ? ` <span class="d${toneClass}">${delta}</span>` : "";
    const valueToneClass = !delta && tone ? ` ${tone}` : "";
    return (
      `<div class="stat${priority === "primary" ? "" : " stat--secondary"}">` +
      `<div class="stat-label"><div class="k">${k ?? ""}</div>${statInfo(k, foot)}</div>` +
      `<div class="v num${valueToneClass}">${v ?? ""}${deltaHtml}</div>` +
      `</div>`
    );
  },

  /** Pill chip. kind ∈ ok | live | warn | crit (else neutral). */
  pill(text, kind) {
    const cls = kind ? `pill pill--${kind}` : "pill";
    return `<span class="${cls}"><i class="dot"></i>${text}</span>`;
  },

  /** Panel card: title (h3) + optional sub + body html. */
  card({ title, sub, body } = {}) {
    return (
      `<div class="card">` +
      (title ? `<h3>${title}</h3>` : "") +
      (sub ? `<div class="sub">${sub}</div>` : "") +
      (body ?? "") +
      `</div>`
    );
  },

  /**
   * Table wrapped in .tblwrap. cols = array of header cells; a col may be
   * { label, num } to right-align. rows = array of arrays; a cell is a string
   * (already-safe html) or { html, num } to right-align that cell.
   *
   * `chrome: false` suppresses the shared grid toolbar and findbar for a table
   * whose own screen already carries the controls — a short rollup sitting
   * under its own tab strip does not need a second row of Find/Sort/Filter
   * above it. The table still gets .data-grid styling; only the chrome and the
   * client-side find/sort/filter/columns wiring are skipped.
   */
  table({ cols, rows, chrome = true } = {}) {
    const head = (cols ?? [])
      .map((c) => {
        const label = typeof c === "object" && c !== null ? c.label ?? "" : c;
        const numCls = typeof c === "object" && c !== null && c.num ? ' class="num"' : "";
        return `<th${numCls}>${label}</th>`;
      })
      .join("");
    const bodyRows = (rows ?? [])
      .map((r) => {
        const cells = (r ?? [])
          .map((cell) => {
            if (cell !== null && typeof cell === "object") {
              const numCls = cell.num ? ' class="num"' : "";
              return `<td${numCls}>${cell.html ?? ""}</td>`;
            }
            return `<td>${cell ?? ""}</td>`;
          })
          .join("");
        return `<tr>${cells}</tr>`;
      })
      .join("");
    return (
      `<div class="tblwrap"><table${chrome ? "" : ' data-grid-chrome="off"'}>` +
      `<thead><tr>${head}</tr></thead>` +
      `<tbody>${bodyRows}</tbody>` +
      `</table></div>`
    );
  },

  /** Labelled form field: label + control html + optional hint. */
  field({ label, control, hint } = {}) {
    return (
      `<div class="field">` +
      (label ? `<label>${label}</label>` : "") +
      (control ?? "") +
      (hint ? `<div class="hint">${hint}</div>` : "") +
      `</div>`
    );
  },

  /** Honest empty state - a card with a muted message (fresh-tenant safe). */
  empty(msg) {
    return `<div class="card"><div class="sub" style="margin:0">${msg}</div></div>`;
  },

  /**
   * Route pending state: skeleton in the shape of a typical page; status stays
   * accessible. The chat surface has one screen and no page furniture to
   * pre-draw, so it gets the Context Fabric instead of a skeleton of a page
   * that is not coming.
   */
  loading(label = "Loading page") {
    if (SURFACE === "chat") {
      // "Loading page" is console copy; the chat surface names what is actually
      // being waited on. An explicit label from a caller still wins.
      return fabricLoader(label === "Loading page" ? "Restoring your context" : label);
    }
    const stat =
      `<div class="page-skeleton__stat">` +
      `<span class="skel skel--stat-k"></span>` +
      `<span class="skel skel--stat-v"></span>` +
      `</div>`;
    return (
      `<div class="page-loader" role="status" aria-live="polite" aria-busy="true">` +
      `<div class="page-skeleton" aria-hidden="true">` +
      `<div class="page-skeleton__head">` +
      `<span class="skel skel--eyebrow"></span>` +
      `<span class="skel skel--title"></span>` +
      `<span class="skel skel--sub"></span>` +
      `</div>` +
      `<div class="page-skeleton__stats">${stat}${stat}${stat}</div>` +
      `<div class="page-skeleton__card">` +
      `<span class="skel skel--card-title"></span>` +
      `<span class="skel skel--line"></span>` +
      `<span class="skel skel--line skel--line--80"></span>` +
      `<span class="skel skel--line skel--line--60"></span>` +
      `</div>` +
      `</div>` +
      `<span class="sr-only">${esc(label)}</span>` +
      `</div>`
    );
  },

  /** Severity row: a colored sevbar + flexible html + optional trailing action. */
  sevRow(color, html, action) {
    return (
      `<div class="row">` +
      `<span class="sevbar" style="background:${esc(color)}"></span>` +
      `<div style="flex:1">${html}</div>` +
      (action ? action : "") +
      `</div>`
    );
  },
};

// ---------------------------------------------------------------------------
// Rail - role-filtered nav + inline SVG icons (reused from the prototype).
// ---------------------------------------------------------------------------

const ICONS = {
  home: '<path d="M3 10l9-7 9 7v9a2 2 0 0 1-2 2h-4v-6H9v6H5a2 2 0 0 1-2-2z" stroke-linejoin="round"/>',
  map: '<path d="M9 4L3 6v14l6-2 6 2 6-2V4l-6 2-6-2z" stroke-linejoin="round"/><path d="M9 4v14M15 6v14"/>',
  src: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  score: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2" stroke-linecap="round"/>',
  bot: '<rect x="5" y="8" width="14" height="10" rx="3"/><path d="M12 8V4M9 13h.01M15 13h.01M8 21h8" stroke-linecap="round" stroke-linejoin="round"/>',
  people: '<circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-5 6-5s6 1.7 6 5"/><path d="M16 5.5a3 3 0 0 1 0 5.5M21 20c0-2.6-1.4-4.2-3.5-4.8"/>',
  dial: '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h6M14 18h6" stroke-linecap="round"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="12" cy="18" r="2"/>',
  check: '<path d="M9 11l3 3L22 4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>',
  wand: '<path d="M15 4V2M15 10V8M20 7h-2M12 7h-2" stroke-linecap="round"/><path d="M5 21L16 10l-2-2L3 19z" stroke-linejoin="round"/>',
  scales: '<path d="M12 3v18M4 21h16" stroke-linecap="round"/><path d="M7 6h10" stroke-linecap="round"/><path d="M7 6l-3 6a3 3 0 0 0 6 0zM17 6l-3 6a3 3 0 0 0 6 0z" stroke-linejoin="round"/>',
  model: '<rect x="4" y="5" width="16" height="14" rx="3"/><path d="M8 9h8M8 13h5M9 2v3M15 2v3M9 19v3M15 19v3" stroke-linecap="round"/>',
  teams: '<rect x="3" y="3" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="2"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2"/>',
  plug: '<path d="M9 7V3M15 7V3" stroke-linecap="round"/><path d="M6 7h12v4a6 6 0 0 1-6 6 6 6 0 0 1-6-6z" stroke-linejoin="round"/><path d="M12 17v4" stroke-linecap="round"/>',
  spark: '<path d="M12 3l1.9 5.6L19.5 10.5l-5.6 1.9L12 18l-1.9-5.6L4.5 10.5l5.6-1.9z" stroke-linejoin="round"/><path d="M19 17l.8 2.2L22 20l-2.2.8L19 23l-.8-2.2L16 20l2.2-.8z" stroke-linejoin="round"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 11l9-9M16 6l3 3M13 9l2.5 2.5" stroke-linecap="round" stroke-linejoin="round"/>',
  download: '<path d="M12 3v12m0 0l-4-4m4 4l4-4" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" stroke-linecap="round"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  card: '<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10.5h18" stroke-linecap="round"/><path d="M6.5 15h4" stroke-linecap="round"/>',
  gear: '<circle cx="12" cy="12" r="3.2"/><path d="M19.4 14.4a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.11a1.7 1.7 0 0 0-1.1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.11a1.7 1.7 0 0 0 1.55-1.1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34H9a1.7 1.7 0 0 0 1-1.56V3a2 2 0 1 1 4 0v.11a1.7 1.7 0 0 0 1 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87V9a1.7 1.7 0 0 0 1.56 1H21a2 2 0 1 1 0 4h-.11a1.7 1.7 0 0 0-1.49 1.4z" stroke-linejoin="round"/>',
};

/** Screen access mirrors the server role contract until a shared capability
 * response is available. Setup is added only for the organization-root owner. */
const ROLE_SCREENS = {
  // s16 (skills) is member-visible: the library list/submit/download live on
  // the non-admin /v1/skills routes; governance actions stay owner/admin.
  // s15 (usage analytics) is member-visible: the usage rollup/ledger GETs are
  // scoped server-side to the caller's own namespace subtree.
  member: ["s2", "s5", "s6", "s14", "s10", "s16", "s15", "s18"],
  // The policy library has a true auditor read model; scorecard remains hidden
  // because its current route runs a benchmark rather than performing a read.
  // s15 (user analytics) is a read-only GET the server carves out for the
  // auditor. s16 (skills) and s17 (connected apps) are NOT auditor screens:
  // their primary GETs (/v1/admin/skills, /v1/admin/oauth/clients) sit behind
  // the server's owner/admin gate, so listing them here would advertise dead
  // 403 screens - the rail must match the server role gate exactly.
  // s18 (settings) is self-service for every role: the profile half is the
  // session user's own account, and the organization half is read-only unless
  // the caller holds `organization:write` (owner/admin).
  // s20 (export) is owner/admin/auditor: the server's EXPORT_ROLES
  // (src/export/index.ts) admits exactly those three, so the rail matches the
  // gate and member/agent never see a screen that would 403.
  auditor: ["s2", "s5", "s6", "s14", "s10", "s21", "s3", "s13", "s4", "s7", "s8", "s11", "s15", "s20", "s18"],
  // s19 (alerts) is owner/admin only: both of its endpoints and both of its
  // decisions are owner/admin server-side, and an inbox that renders "all
  // clear" because the read was refused is worse than no inbox at all.
  admin: ["s2", "s5", "s6", "s14", "s10", "s21", "s16", "s9", "s3", "s19", "s13", "s4", "s7", "s8", "s11", "s15", "s17", "s12", "s20", "s18"],
  // s22 (billing) is OWNER-ONLY on purpose: it renders the tenant's early
  // access period, allowances, and (later) plan/payment state - commercial
  // terms are the account owner's surface, not an admin operating concern.
  owner: ["s2", "s5", "s6", "s14", "s10", "s21", "s16", "s9", "s3", "s19", "s13", "s4", "s7", "s8", "s11", "s15", "s17", "s12", "s20", "s18", "s22"],
};
// M10 (D41): the session payload now carries PRODUCT roles. `root` maps to
// the owner rail; a member holding the audit:read entitlement (a legacy
// auditor) keeps the auditor read rail. Internal "owner"/"auditor" values
// still resolve for older fixtures.
ROLE_SCREENS.root = ROLE_SCREENS.owner;

/**
 * Screens that are BOXED: built and still served, but withdrawn from the
 * product until they have a job to do. A boxed id is stripped from every role
 * rail below, which removes it from the nav AND makes its hash route
 * unreachable (the default-screen guard rejects ids outside `allowedScreens`).
 *
 * s9 (retrieval quality) — the referee scorecard benchmarks the mounted
 * retriever cartridges against each other and offers a one-click switch of the
 * live retriever. Today the only cartridges are OURS: `baseline` (the D1
 * control lane, and the default whenever policy is silent) and `graph`. There
 * is no third-party engine for a tenant to bring, so the screen asks an
 * operator to referee two of our own ranking strategies — an internal tuning
 * knob wearing a product hat, with a button that repoints production retrieval.
 * Un-box when a tenant can actually mount a competing engine; deleting the id
 * from this set restores the screen exactly as it was.
 *
 * The server side stays live on purpose: POST /v1/admin/scorecard, the CLI
 * `scorecard <ns>` command, and src/referee/ are the D1 evidence lane and are
 * pinned by the M2 exit tests. Nothing runs a scorecard on its own — the route
 * is the only trigger — so a boxed screen means zero runs, not idle cost.
 */
const BOXED_SCREENS = new Set(["s9"]);

function screensFor(identity) {
  const audit =
    Array.isArray(identity.entitlements) &&
    identity.entitlements.indexOf("audit:read") !== -1;
  const key = identity.role === "member" && audit ? "auditor" : identity.role;
  const screens = [...(ROLE_SCREENS[key] ?? ROLE_SCREENS.member ?? [])];
  if (
    (identity.role === "owner" || identity.role === "root") &&
    identity.namespace === ""
  ) {
    screens.push("s1");
  }
  // Boxing is applied last so it wins over every role rail, including the
  // owner-only additions above.
  return screens.filter((s) => !BOXED_SCREENS.has(s));
}

const NAV = [
  {
    group: "Operate",
    icon: "spark",
    items: [
      { s: "s2", icon: "home", label: "Home" },
      { s: "s5", icon: "map", label: "Memory" },
      { s: "s6", icon: "src", label: "Sources" },
      { s: "s14", icon: "plug", label: "Agent connections" },
      { s: "s10", icon: "bot", label: "Assistant" },
      { s: "s21", icon: "plug", label: "Channels" },
      {
        action: "haloAgents",
        capability: "haloAgents",
        icon: "bot",
        label: "Halo Agents",
      },
      { s: "s16", icon: "spark", label: "Skills" },
      { s: "s15", icon: "score", label: "Usage analytics", memberOperate: true },
      // BOXED — see BOXED_SCREENS. The entry stays so un-boxing is a one-line
      // change; screensFor() strips the id, so this never renders today.
      { s: "s9", icon: "score", label: "Retrieval quality" },
    ],
  },
  {
    group: "Govern",
    icon: "shield",
    items: [
      { s: "s13", icon: "teams", label: "Teams" },
      { s: "s3", icon: "bot", label: "Scoped memory" },
      { s: "s19", icon: "shield", label: "Alerts" },
      { s: "s4", icon: "dial", label: "Policies" },
      { s: "s7", icon: "check", label: "Knowledge operations" },
      { s: "s11", icon: "scales", label: "Conflicts" },
      { s: "s8", icon: "shield", label: "Audit" },
      { s: "s20", icon: "download", label: "Export" },
      { s: "s15", icon: "score", label: "Usage analytics", governance: true },
      { s: "s22", icon: "card", label: "Billing" },
      { s: "s17", icon: "key", label: "Connected apps" },
      { s: "s12", icon: "model", label: "AI models" },
    ],
  },
  {
    group: "Account",
    icon: "people",
    items: [
      { s: "s1", icon: "wand", label: "Setup" },
      { s: "s18", icon: "gear", label: "Settings" },
    ],
  },
];

/** The flat set of screen ids the current role may open (default-screen guard). */
let allowedScreens = new Set();
let currentScreenId = null;
let expandedRailGroup = "operate";

// ---------------------------------------------------------------------------
// Mandatory setup gate (CONTRACTS-SETUP-GATE.md). While the server-persisted
// onboarding latch says setup is incomplete, an owner/admin console locks
// itself to the setup surface plus the screens that can finish it; a member
// or auditor sees a waiting view instead. There is NO skip: the latch flips
// only when the live server checklist derives complete.
// ---------------------------------------------------------------------------

/** S1 plus every screen the checklist's step CTAs target. */
const SETUP_SCREENS = new Set(["s1", "s3", "s5", "s6", "s13"]);
const SETUP_SCREEN = "s1";

/** null = full console; "setup" = locked to SETUP_SCREENS; "waiting" = none. */
let gateMode = null;

/** Last server-derived checklist, so the banner can repaint on navigation. */
let lastChecklistView = null;

function iconSvg(name) {
  const body = ICONS[name] ?? "";
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">${body}</svg>`;
}

function railGroupKey(group) {
  return String(group).toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function railGroupIcon() {
  return (
    '<svg class="navgroup-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' +
    '<path class="navgroup-icon__horizontal" d="M3.5 8h9" stroke-linecap="round"/>' +
    '<path class="navgroup-icon__vertical" d="M8 3.5v9" stroke-linecap="round"/>' +
    "</svg>"
  );
}

function setExpandedRailGroup(groupKey) {
  expandedRailGroup = groupKey;
  document.querySelectorAll("#rail-nav button[data-nav-group]").forEach((button) => {
    const expanded = button.getAttribute("data-nav-group") === groupKey;
    button.setAttribute("aria-expanded", String(expanded));
    const panelId = button.getAttribute("aria-controls");
    const panel = panelId ? document.getElementById(panelId) : null;
    if (panel) panel.hidden = !expanded;
  });
}

function expandRailGroupForScreen(screenId) {
  const active = [...document.querySelectorAll("#rail-nav button[data-s]")].find(
    (button) => button.getAttribute("data-s") === screenId,
  );
  const section = active ? active.closest("[data-nav-section]") : null;
  const groupKey = section ? section.getAttribute("data-nav-section") : null;
  if (groupKey) setExpandedRailGroup(groupKey);
}

/**
 * Paint collapsed-rail labels outside the rail's clipping and scroll layers.
 * The visible text is already the control's accessible name; this floating
 * copy is presentation-only and follows both pointer and keyboard focus.
 */
function wireRailTooltip(rail) {
  const tooltip = document.createElement("div");
  tooltip.className = "rail-tooltip";
  tooltip.setAttribute("aria-hidden", "true");
  document.body.append(tooltip);

  let activeTarget = null;
  const desktop = window.matchMedia("(min-width: 861px)");

  function targetFrom(node) {
    const target = node?.closest?.("[data-tip]");
    return target && rail.contains(target) ? target : null;
  }

  function hide(target = null) {
    if (target && activeTarget !== target) return;
    activeTarget = null;
    tooltip.removeAttribute("data-open");
    tooltip.setAttribute("aria-hidden", "true");
  }

  function show(target) {
    const label = target?.getAttribute("data-tip")?.trim();
    if (!label || !desktop.matches || !document.body.classList.contains("rail-collapsed")) {
      hide();
      return;
    }

    activeTarget = target;
    tooltip.textContent = label;
    tooltip.setAttribute("aria-hidden", "false");

    const targetRect = target.getBoundingClientRect();
    const railRect = rail.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const edgeGap = 8;
    const targetGap = 12;
    const left = Math.min(
      window.innerWidth - tooltipRect.width - edgeGap,
      Math.max(targetRect.right, railRect.right) + targetGap,
    );
    const top = Math.max(
      edgeGap,
      Math.min(
        window.innerHeight - tooltipRect.height - edgeGap,
        targetRect.top + (targetRect.height - tooltipRect.height) / 2,
      ),
    );

    tooltip.style.left = `${Math.max(edgeGap, left)}px`;
    tooltip.style.top = `${top}px`;
    tooltip.setAttribute("data-open", "true");
  }

  rail.addEventListener("pointerover", (event) => {
    const target = targetFrom(event.target);
    if (target) show(target);
  });
  rail.addEventListener("pointerout", (event) => {
    const target = targetFrom(event.target);
    if (!target || target.contains(event.relatedTarget)) return;
    hide(target);
  });
  rail.addEventListener("focusin", (event) => {
    const target = targetFrom(event.target);
    if (target) show(target);
  });
  rail.addEventListener("focusout", (event) => hide(targetFrom(event.target)));
  window.addEventListener("resize", () => hide());
  document.addEventListener("scroll", () => hide(), true);

  return { hide };
}

function renderRail(identity) {
  const nav = document.getElementById("rail-nav");
  const fullAccess = new Set(screensFor(identity));
  if (gateMode === "waiting") {
    // A member/auditor cannot finish setup — no nav at all, just the rail
    // chrome (brand, org, sign out) around the waiting view.
    allowedScreens = new Set();
    nav.innerHTML = "";
    notificationCenter?.syncAccess({ refresh: initialScreenLoaded });
    paintBrandHome();
    return;
  }
  allowedScreens =
    gateMode === "setup"
      ? new Set([...fullAccess].filter((s) => SETUP_SCREENS.has(s)))
      : fullAccess;
  if (gateMode === "setup") allowedScreens.add(SETUP_SCREEN);
  let html = "";
  const auditMember =
    identity.role === "member" &&
    Array.isArray(identity.entitlements) &&
    identity.entitlements.indexOf("audit:read") !== -1;
  const operatingMember = identity.role === "member" && !auditMember;
  const groups = NAV.map((grp) => {
    const items = grp.items.filter((item) => {
      if (item.memberOperate === true && !operatingMember) return false;
      if (item.governance === true && operatingMember) return false;
      if (!item.s) {
        return gateMode === null && identity.capabilities?.[item.capability] === true;
      }
      // While gated, role-allowed screens render even when locked, so the
      // user can see what completing setup unlocks. S1 always shows.
      return gateMode === "setup"
        ? fullAccess.has(item.s) || item.s === SETUP_SCREEN
        : allowedScreens.has(item.s);
    });
    return { grp, items };
  }).filter(({ items }) => items.length > 0);
  const renderedGroupKeys = new Set(groups.map(({ grp }) => railGroupKey(grp.group)));
  if (!renderedGroupKeys.has(expandedRailGroup)) {
    const activeGroup = groups.find(({ items }) =>
      items.some((item) => item.s === currentScreenId),
    );
    expandedRailGroup = activeGroup
      ? railGroupKey(activeGroup.grp.group)
      : railGroupKey(groups[0]?.grp.group ?? "operate");
  }
  for (const { grp, items } of groups) {
    const groupKey = railGroupKey(grp.group);
    const panelId = `rail-group-${groupKey}`;
    const expanded = expandedRailGroup === groupKey;
    html +=
      `<section class="navsection" data-nav-section="${groupKey}">` +
      `<button class="navgroup" type="button" data-nav-group="${groupKey}" data-tip="${grp.group}" ` +
      `aria-label="${grp.group}" ` +
      `aria-expanded="${expanded}" aria-controls="${panelId}">` +
      `<span class="navgroup-heading"><span class="navgroup-symbol">${iconSvg(grp.icon)}</span>` +
      `<span class="navgroup-label">${grp.group}</span></span>${railGroupIcon()}</button>` +
      `<div class="nav" id="${panelId}" data-nav-panel${expanded ? "" : " hidden"}>`;
    for (const item of items) {
      if (item.action === "haloAgents") {
        html +=
          `<button type="button" data-halo-agents data-tip="${item.label}" aria-label="${item.label}">` +
          iconSvg(item.icon) +
          `<span class="lbl" data-halo-agents-label>${item.label}</span></button>`;
        continue;
      }
      const locked = !allowedScreens.has(item.s);
      html += locked
        ? `<button data-s="${item.s}" data-nav disabled class="locked" data-tip="${item.label}" aria-label="${item.label} - locked until setup is complete" aria-disabled="true">` +
          iconSvg("lock") +
          `<span class="lbl">${item.label}</span></button>`
        : `<button data-s="${item.s}" data-nav data-tip="${item.label}" aria-label="${item.label}">` +
          iconSvg(item.icon) +
          `<span class="lbl">${item.label}</span></button>`;
    }
    html += `</div></section>`;
  }
  nav.innerHTML = html;
  notificationCenter?.syncAccess({ refresh: initialScreenLoaded });
  paintBrandHome();
}

/**
 * The Halofy lockup follows the same reachability guard as every other Home
 * navigation target. During setup or the waiting view it becomes inert.
 */
function paintBrandHome() {
  const reachable = allowedScreens.has(DEFAULT_SCREEN);
  document.querySelectorAll("[data-brand-home]").forEach((btn) => {
    btn.disabled = !reachable;
    if (reachable && btn.closest(".rail")) btn.setAttribute("data-tip", "Home");
    else btn.removeAttribute("data-tip");
  });
}

/**
 * Persistent setup-checklist badge ("N steps remaining") on the S1 rail entry.
 * Count is server-derived (GET /v1/admin/setup-checklist, D9); the badge is
 * removed ONLY when the server reports the checklist genuinely complete.
 * Brownout (endpoint unavailable → view null) renders no badge rather than a
 * false count. Refreshed on every navigation so a completed step clears live.
 */
async function paintSetupBadge() {
  const btn = document.querySelector('#rail-nav button[data-s="s1"]');
  if (!btn) return; // rail has no Setup entry for this identity
  const view = await loadSetupChecklist(ctx);
  lastChecklistView = view;
  if (gateMode === "setup") {
    paintGateBanner(view);
    // The same fetch that derived `complete` server-side latched the flag —
    // the gate lifts live, without a reload or a localStorage flag.
    if (view && view.complete === true) {
      unlockConsole();
      return;
    }
  }
  const current = document.querySelector('#rail-nav button[data-s="s1"]');
  if (!current) return; // rail re-rendered while we were fetching
  const existing = current.querySelector("[data-setup-badge]");
  if (existing) existing.remove();
  const html = setupBadge(ctx, view); // "" only when view.complete === true
  if (!html) return;
  const lbl = current.querySelector(".lbl");
  if (lbl) lbl.insertAdjacentHTML("afterend", html);
  else current.insertAdjacentHTML("beforeend", html);
}

/**
 * The persistent gate banner above the stage while setup is incomplete: one
 * sentence of why the console is locked plus a way back to the setup surface.
 *
 * It is suppressed on the setup surface itself — S1's own header already
 * states the progress and every step's CTA, so the banner there would be a
 * second copy of the same sentence with a button that goes nowhere.
 */
function paintGateBanner(view) {
  const banner = document.getElementById("setup-gate-banner");
  if (!banner) return;
  if (gateMode !== "setup" || currentScreenId === SETUP_SCREEN) {
    banner.hidden = true;
    banner.innerHTML = "";
    return;
  }
  const remaining = view && typeof view.remaining === "number" ? view.remaining : null;
  const text =
    remaining === null
      ? "Finish setting up your organization to unlock the console."
      : remaining === 1
        ? "Finish setting up your organization - 1 step left."
        : `Finish setting up your organization - ${remaining} steps left.`;
  banner.innerHTML =
    `<span class="setup-gate-banner__text">${esc(text)}</span>` +
    '<button class="btn btn--solid btn--sm" type="button" data-gate-continue>Continue setup</button>';
  banner.hidden = false;
}

/** The gate lifts: full rail, no banner, and S1 renders its completion state. */
function unlockConsole() {
  if (gateMode !== "setup") return;
  gateMode = null;
  renderRail(ctx.identity);
  paintGateBanner(null);
  void loadScreen(SETUP_SCREEN, ctx);
}

/** What a member/auditor sees while their org's setup is incomplete. */
function waitingView() {
  const who = ctx.identity ? ctx.personLabel(ctx.identity, "human") : "";
  return (
    `<div class="card setup-waiting">` +
    `<div class="eyebrow">Setup in progress</div>` +
    `<h3>Your organization is being set up</h3>` +
    `<div class="sub">An owner or admin is finishing the initial setup${who ? ` for ${esc(who)}'s organization` : ""}. ` +
    `The console unlocks as soon as they are done - there is nothing for you to install or configure.</div>` +
    `<div class="row" style="margin-top:var(--s4)">` +
    `<button class="btn btn--outline btn--sm" type="button" data-gate-reload>Check again</button>` +
    `</div></div>`
  );
}

function setActiveNav(screenId) {
  document.querySelectorAll("#rail-nav button[data-s]").forEach((b) => {
    b.classList.toggle("on", b.getAttribute("data-s") === screenId);
  });
  expandRailGroupForScreen(screenId);
}

/** The chat surface's stand-in for both gate modes (setup + waiting). */
function chatGateView() {
  const role = ctx.identity ? ctx.identity.role : "";
  const canFinish = role === "owner" || role === "root" || role === "admin";
  return (
    `<div class="card setup-waiting">` +
    `<div class="eyebrow">Setup in progress</div>` +
    `<h3>Your workspace isn&#39;t ready yet</h3>` +
    `<div class="sub">` +
    (canFinish
      ? "Your organization&#39;s initial setup isn&#39;t finished. Finish it in the console, then come back here to chat."
      : "An owner or admin is finishing the initial setup. Chat unlocks as soon as they are done - there is nothing for you to configure.") +
    `</div>` +
    `<div class="row" style="margin-top:var(--s4)">` +
    (canFinish
      ? `<a class="btn btn--solid btn--sm" href="/console/">Continue setup</a>`
      : `<button class="btn btn--outline btn--sm" type="button" data-gate-reload>Check again</button>`) +
    `</div></div>`
  );
}

function paintBreadcrumbs(screenId, tail = []) {
  const container = document.getElementById("console-breadcrumbs");
  if (!container) return;
  const trail = buildBreadcrumbTrail({
    navigation: NAV,
    allowedScreens,
    screenId,
    tail,
  });
  container.innerHTML = breadcrumbMarkup(trail, esc);
  const list = container.querySelector("ol");
  if (list) list.scrollLeft = list.scrollWidth;
}

// ---------------------------------------------------------------------------
// Router - hash / data-s driven. Dynamically imports the screen module, calls
// render(ctx), sets stage.innerHTML, and remembers the module so the delegated
// listener can dispatch its actions.
// ---------------------------------------------------------------------------

const DEFAULT_SCREEN = "s2";
const ASSISTANT_SCREEN = "s10";
let currentModule = null;
let actionToaster = null;
const screenRefreshOwners = new WeakMap();

// ---------------------------------------------------------------------------
// Global assistant dock. A launcher bubble on every screen that opens the same
// Assistant the rail links to. It is deliberately NOT a new grant: it appears
// only where the role's rail already carries the Assistant, never while the
// setup gate is locked, and never on S10 itself (the full screen IS the dock,
// larger). Availability is re-derived on every navigation.
// ---------------------------------------------------------------------------

let assistantDock = null;

/**
 * The command palette. Like the dock it introduces no new authority: it offers
 * only screens already in `allowedScreens`, and it is withheld entirely while
 * the mandatory setup gate is locked (the console has exactly one destination
 * then, and a jump list to it would be noise).
 */
let commandPalette = null;
let notificationCenter = null;
let initialScreenLoaded = false;

function finishInitialScreenLoad() {
  if (initialScreenLoaded) return;
  initialScreenLoaded = true;
  ctx.initialPeopleDirectoryRequest = null;
  notificationCenter?.syncAccess();
}

function assistantDockAvailable() {
  return (
    gateMode === null &&
    allowedScreens.has(ASSISTANT_SCREEN) &&
    currentScreenId !== ASSISTANT_SCREEN
  );
}

function syncAssistantDock() {
  if (assistantDock) assistantDock.setAvailable(assistantDockAvailable());
  if (commandPalette) commandPalette.setAvailable(gateMode === null);
}

// ---------------------------------------------------------------------------
// Route-load sequencing. Loading a screen awaits twice (dynamic import, then
// render) and the LAST navigation must always win: each load stamps a token
// and re-checks it after every await, so a slower prior load can never paint
// over — or replace the action module of — the screen the user actually
// selected last. (The refresh path below has the same guard via owner tokens.)
// ---------------------------------------------------------------------------

let latestRouteLoad = 0;

/** Stamp the newest route load; the caller re-checks the token after each await. */
export function beginRouteLoad() {
  return ++latestRouteLoad;
}

/** True while `token` is still the newest stamped route load. */
export function isCurrentRouteLoad(token) {
  return token === latestRouteLoad;
}

function screenFromHash() {
  return screenIdFromHash(window.location.hash);
}

/** Replace a legacy numeric bookmark in place without adding history. */
function canonicalizeCurrentHash() {
  const readable = canonicalHash(window.location.hash);
  if (readable && readable !== window.location.hash) {
    window.history.replaceState(null, "", readable);
  }
}

/**
 * Apply one client-side table contract to every operational grid. The screen
 * modules keep ownership of fetching, pagination, mutation, and export; this
 * layer only standardizes current-page finding, sorting, filtering, and
 * column visibility. Comparison and chat tables are intentionally static.
 */
export function enhanceDataTables(root) {
  if (!root || typeof root.querySelectorAll !== "function") return 0;
  const tables = Array.from(root.querySelectorAll("table"));
  let enhanced = 0;

  tables.forEach((table, tableIndex) => {
    if (
      table.dataset?.tableEnhanced === "true" ||
      table.matches(".chat-table,.conflict-diff,[data-table-static]")
    ) return;

    const headers = Array.from(table.querySelectorAll("thead th"));
    const body = table.tBodies?.[0] ?? table.querySelector("tbody");
    const host = table.parentElement;
    if (headers.length === 0 || !body || !host) return;

    const filterSourceId = table.getAttribute("data-grid-filter-source");
    const serverFilterPanel = filterSourceId
      ? (root.ownerDocument || document).getElementById(filterSourceId)
      : null;

    table.dataset.tableEnhanced = "true";
    table.classList.add("data-grid");
    host.classList.add("data-grid-shell");

    // Chrome opted out (ui.table({ chrome: false })): the grid keeps the shared
    // shell styling, but gets no toolbar and no findbar. Everything below this
    // point exists only to build and wire that chrome, so there is nothing left
    // to do for this table.
    if (table.getAttribute("data-grid-chrome") === "off") {
      enhanced++;
      return;
    }

    const doc = root.ownerDocument || document;
    const gridId = table.id || `data-grid-${tableIndex + 1}`;
    table.id = gridId;
    const chrome = doc.createElement("div");
    chrome.className = "data-grid-chrome";
    chrome.innerHTML =
      `<div class="data-grid-toolbar" role="toolbar" aria-label="Table options">` +
      `<span class="data-grid-count" aria-live="polite"></span>` +
      `<div class="data-grid-actions">` +
      `<button type="button" class="data-grid-tool data-grid-search-jump" aria-label="Focus table search">` +
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="6.5"></circle><path d="m16 16 4 4" stroke-linecap="round"></path></svg>` +
      `</button>` +
      `<button type="button" class="data-grid-tool data-grid-icon-tool" data-grid-panel="sort" aria-expanded="false" aria-label="Sort table" title="Sort">` +
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M8 6h11M8 12h8M8 18h5" stroke-linecap="round"></path><path d="M4 5v14m0 0-2.5-2.5M4 19l2.5-2.5" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>` +
      `<button type="button" class="data-grid-tool data-grid-icon-tool" data-grid-panel="filters" aria-expanded="false" aria-label="Filter table" title="Filters">` +
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M3 5h18l-7 8v5l-4 2v-7L3 5Z" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>` +
      `<button type="button" class="data-grid-tool" data-grid-panel="columns" aria-expanded="false">Columns</button>` +
      `</div></div>` +
      `<div class="data-grid-findbar">` +
      `<strong>Find</strong>` +
      `<label><span class="sr-only">Find in table</span><input class="data-grid-search" type="search" autocomplete="off" placeholder="Search visible rows" aria-controls="${gridId}"></label>` +
      `</div>` +
      `<div class="data-grid-optionbar data-grid-sortbar" data-grid-options="sort" hidden>` +
      `<label><span>Sort rows</span><select class="select data-grid-sort" aria-label="Sort table rows"></select></label>` +
      `</div>` +
      `<div class="data-grid-optionbar data-grid-filterbar" data-grid-options="filters" hidden></div>` +
      `<div class="data-grid-optionbar data-grid-columnbar" data-grid-options="columns" hidden></div>`;
    host.insertBefore(chrome, table);

    const headerLabels = headers.map((header, index) =>
      (header.textContent || "").trim() || `Column ${index + 1}`,
    );
    const groups = [];
    let currentGroup = null;
    Array.from(body.rows).forEach((row, index) => {
      const isCompanion = headers.length > 1 && row.cells.length === 1 && row.cells[0].colSpan >= headers.length;
      if (isCompanion && currentGroup) {
        currentGroup.related.push({ row, hidden: row.hidden });
        return;
      }
      currentGroup = { row, related: [], index, hidden: row.hidden };
      groups.push(currentGroup);
    });

    const count = chrome.querySelector(".data-grid-count");
    const search = chrome.querySelector(".data-grid-search");
    const sort = chrome.querySelector(".data-grid-sort");
    let filterbar = chrome.querySelector(".data-grid-filterbar");
    const columnbar = chrome.querySelector(".data-grid-columnbar");

    if (serverFilterPanel) {
      serverFilterPanel.classList.add(
        "data-grid-optionbar",
        "data-grid-filterbar",
        "data-grid-server-filterbar",
      );
      serverFilterPanel.setAttribute("data-grid-options", "filters");
      serverFilterPanel.hidden = true;
      filterbar.replaceWith(serverFilterPanel);
      filterbar = serverFilterPanel;

      const activeCount = Number(serverFilterPanel.getAttribute("data-filter-count") || "0");
      const filterButton = chrome.querySelector('[data-grid-panel="filters"]');
      if (filterButton && activeCount > 0) {
        filterButton.classList.add("has-active-filter");
        filterButton.setAttribute("data-filter-count", String(activeCount));
        filterButton.setAttribute(
          "aria-label",
          `Filter table, ${activeCount} active`,
        );
        filterButton.setAttribute("title", `Filters (${activeCount} active)`);
      }
    }

    const defaultSort = doc.createElement("option");
    defaultSort.value = "";
    defaultSort.textContent = "Original order";
    sort.append(defaultSort);
    headerLabels.forEach((label, index) => {
      [["asc", "A–Z"], ["desc", "Z–A"]].forEach(([direction, suffix]) => {
        const option = doc.createElement("option");
        option.value = `${index}:${direction}`;
        option.textContent = `${label} · ${suffix}`;
        sort.append(option);
      });

      if (!serverFilterPanel) {
        const filterLabel = doc.createElement("label");
        const filterName = doc.createElement("span");
        const filter = doc.createElement("input");
        filterName.textContent = label;
        filter.type = "search";
        filter.className = "input data-grid-column-filter";
        filter.placeholder = `Filter ${label}`;
        filter.setAttribute("data-grid-filter-col", String(index));
        filterLabel.append(filterName, filter);
        filterbar.append(filterLabel);
      }

      const columnLabel = doc.createElement("label");
      const checkbox = doc.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.setAttribute("data-grid-column", String(index));
      columnLabel.append(checkbox, doc.createTextNode(label));
      columnbar.append(columnLabel);
    });

    const rowText = (group) =>
      [group.row, ...group.related.map((entry) => entry.row)]
        .map((row) => (row.textContent || "").toLocaleLowerCase())
        .join(" ");
    const applyFilters = () => {
      const query = (search.value || "").trim().toLocaleLowerCase();
      const columnFilters = Array.from(chrome.querySelectorAll("[data-grid-filter-col]"))
        .map((input) => [Number(input.getAttribute("data-grid-filter-col")), input.value.trim().toLocaleLowerCase()])
        .filter(([, value]) => value !== "");
      let visible = 0;
      groups.forEach((group) => {
        const cells = Array.from(group.row.cells);
        const matchesQuery = query === "" || rowText(group).includes(query);
        const matchesColumns = columnFilters.every(([index, value]) =>
          ((cells[index]?.textContent || "").toLocaleLowerCase()).includes(value),
        );
        const matches = matchesQuery && matchesColumns;
        group.row.hidden = group.hidden || !matches;
        group.related.forEach((entry) => {
          entry.row.hidden = entry.hidden || !matches;
        });
        if (matches && !group.hidden) visible += 1;
      });
      count.textContent = `${visible} of ${groups.length} rows`;
    };

    search.addEventListener("input", applyFilters);
    filterbar.addEventListener("input", applyFilters);
    chrome.querySelector(".data-grid-search-jump").addEventListener("click", () => search.focus());
    sort.addEventListener("change", () => {
      const [rawIndex, direction] = sort.value.split(":");
      const columnIndex = Number(rawIndex);
      groups.sort((a, b) => {
        if (!direction) return a.index - b.index;
        const aText = (a.row.cells[columnIndex]?.textContent || "").trim();
        const bText = (b.row.cells[columnIndex]?.textContent || "").trim();
        const compared = aText.localeCompare(bText, undefined, { numeric: true, sensitivity: "base" });
        return direction === "desc" ? -compared : compared;
      });
      groups.forEach((group) => {
        body.append(group.row);
        group.related.forEach((entry) => body.append(entry.row));
      });
    });
    columnbar.addEventListener("change", (event) => {
      const visibleColumns = new Set(
        Array.from(columnbar.querySelectorAll("[data-grid-column]:checked"))
          .map((input) => Number(input.getAttribute("data-grid-column"))),
      );
      if (visibleColumns.size === 0) {
        event.target.checked = true;
        return;
      }
      headers.forEach((header, index) => { header.hidden = !visibleColumns.has(index); });
      groups.forEach((group) => {
        if (group.row.cells.length !== headers.length) return;
        Array.from(group.row.cells).forEach((cell, index) => { cell.hidden = !visibleColumns.has(index); });
      });
    });
    chrome.querySelectorAll("[data-grid-panel]").forEach((button) => {
      button.addEventListener("click", () => {
        const panelName = button.getAttribute("data-grid-panel");
        const panel = chrome.querySelector(`[data-grid-options="${panelName}"]`);
        const willOpen = panel.hidden;
        chrome.querySelectorAll("[data-grid-options]").forEach((candidate) => { candidate.hidden = true; });
        chrome.querySelectorAll("[data-grid-panel]").forEach((candidate) => candidate.setAttribute("aria-expanded", "false"));
        panel.hidden = !willOpen;
        button.setAttribute("aria-expanded", String(willOpen));
        if (willOpen) panel.querySelector("input,select")?.focus();
      });
    });

    applyFilters();
    enhanced += 1;
  });

  return enhanced;
}

/**
 * Expose only the resolved console route to CSS. The Home dashboard owns its
 * existing composition; every other screen can share one workspace language
 * without screen modules adding visual flags or changing their data contract.
 */
export function setConsoleScreenContext(id) {
  if (
    SURFACE !== "console" ||
    typeof document === "undefined" ||
    !document.body
  ) return;
  if (typeof id === "string" && id !== "") {
    document.body.setAttribute("data-console-screen", id);
    return;
  }
  document.body.removeAttribute("data-console-screen");
}

async function loadScreen(screenId, ctx) {
  const stage = document.getElementById("screen-content");
  invalidateRefreshedScreen(stage);
  const loadToken = beginRouteLoad();
  if (currentModule && typeof currentModule.cleanup === "function") {
    currentModule.cleanup();
  }
  currentModule = null;
  // Chat surface: while the org's setup gate is engaged there is no setup UI
  // here — the card sends owners/admins to the console (which enforces the
  // same server-persisted latch) and tells everyone else to wait.
  if (SURFACE === "chat" && gateMode !== null) {
    currentScreenId = null;
    setConsoleScreenContext(null);
    syncAssistantDock();
    stage.innerHTML = chatGateView();
    finishInitialScreenLoad();
    return;
  }
  // Setup gate: members/auditors get the waiting view instead of any screen.
  if (gateMode === "waiting") {
    currentScreenId = null;
    setConsoleScreenContext(null);
    setActiveNav(null);
    paintBreadcrumbs(null);
    syncAssistantDock();
    stage.innerHTML = waitingView();
    finishInitialScreenLoad();
    return;
  }
  // Guard: a screen the current role may not open falls back to the default —
  // which is the setup surface while the gate is locked.
  let id = screenId;
  if (!allowedScreens.has(id)) {
    id =
      gateMode === "setup"
        ? SETUP_SCREEN
        : allowedScreens.has(DEFAULT_SCREEN)
          ? DEFAULT_SCREEN
          : allowedScreens.values().next().value;
    if (id === undefined) {
      currentScreenId = null;
      setConsoleScreenContext(null);
      syncAssistantDock();
      stage.innerHTML = ui.empty("No screens are available for your role.");
      finishInitialScreenLoad();
      return;
    }
  }
  currentScreenId = id;
  setConsoleScreenContext(id);
  // The banner's visibility depends on the screen we just landed on, so it is
  // repainted here rather than only on the checklist fetch.
  if (gateMode === "setup") paintGateBanner(lastChecklistView);
  setActiveNav(id);
  paintBreadcrumbs(id);
  syncAssistantDock();
  stage.innerHTML = ui.loading();
  try {
    if (
      !initialScreenLoaded &&
      gateMode === null &&
      id !== DEFAULT_SCREEN &&
      ctx.initialPeopleDirectoryRequest
    ) {
      await ctx.initialPeopleDirectoryRequest.catch(() => null);
      if (!isCurrentRouteLoad(loadToken)) return;
    }
    const mod = await loadScreenModule(id);
    // A newer navigation superseded this one while the module was loading -
    // drop it before its render's API calls are even started.
    if (!isCurrentRouteLoad(loadToken)) return;
    currentModule = mod;
    const html = await mod.render(ctx);
    // The render outlived a newer navigation (slow API): never paint it.
    if (!isCurrentRouteLoad(loadToken)) return;
    stage.innerHTML = html;
    enhanceDataTables(stage);
    const tail = typeof mod.breadcrumbs === "function"
      ? mod.breadcrumbs(ctx)
      : [];
    paintBreadcrumbs(id, tail);
    finishInitialScreenLoad();
  } catch (err) {
    // A stale load's failure must not paint an error over the newer screen.
    if (!isCurrentRouteLoad(loadToken)) return;
    currentModule = null;
    if (err && err.status === 401) return; // already redirecting
    const message = err && err.message ? err.message : "Failed to load this screen.";
    stage.innerHTML =
      `<div class="card"><h3>Couldn't load this screen</h3>` +
      `<div class="sub" style="margin:0">${esc(message)}</div></div>`;
    finishInitialScreenLoad();
  }
}

const screenModulePromises = new Map();

function loadScreenModule(id) {
  const existing = screenModulePromises.get(id);
  if (existing) return existing;
  const pending = import(`./screens/${id}.js`);
  screenModulePromises.set(id, pending);
  pending.then(undefined, () => {
    if (screenModulePromises.get(id) === pending) screenModulePromises.delete(id);
  });
  return pending;
}

/** Begin downloading/parsing a route module without starting its API reads. */
export function preloadScreenModule(id) {
  return loadScreenModule(id).then(() => undefined);
}

/** Navigate: update the hash (→ hashchange re-renders) and scroll to top. */
function go(screenTarget) {
  const hash = screenTargetHash(screenTarget);
  const screenId = hash ? screenIdFromHash(hash) : null;
  if (!hash || !screenId) return;
  if (window.location.hash === hash) {
    // Same screen - hashchange won't fire; render directly.
    void loadScreen(screenId, ctx);
  } else {
    window.location.hash = hash;
  }
  window.scrollTo({ top: 0, behavior: "auto" });
}

/** Re-render the active screen atomically, without the route loader or scroll jump. */
async function refresh() {
  const stage = document.getElementById("screen-content");
  if (!stage || !currentModule || typeof currentModule.render !== "function") {
    await loadScreen(currentScreenId || DEFAULT_SCREEN, ctx);
    return;
  }
  const top = window.scrollY;
  const screenModule = currentModule;
  const html = await renderRefreshedScreen(
    stage,
    screenModule,
    ctx,
    () => currentModule === screenModule,
  );
  if (html === null) return;
  const tail = typeof screenModule.breadcrumbs === "function"
    ? screenModule.breadcrumbs(ctx)
    : [];
  paintBreadcrumbs(currentScreenId, tail);
  window.scrollTo({ top, behavior: "auto" });
}

/**
 * Keep the old screen non-interactive while its replacement is rendering.
 * This closes the async gap where a pointer action could attach to doomed DOM.
 */
export async function renderRefreshedScreen(stage, screenModule, actionCtx, isCurrent = () => true) {
  const owner = {};
  screenRefreshOwners.set(stage, owner);
  stage.setAttribute?.("inert", "");
  stage.setAttribute?.("aria-busy", "true");
  try {
    if (typeof screenModule.cleanup === "function") screenModule.cleanup("refresh");
    const html = await screenModule.render(actionCtx);
    if (screenRefreshOwners.get(stage) !== owner || !isCurrent()) return null;
    stage.innerHTML = html;
    enhanceDataTables(stage);
    return html;
  } finally {
    if (screenRefreshOwners.get(stage) === owner) {
      screenRefreshOwners.delete(stage);
      stage.removeAttribute?.("inert");
      stage.removeAttribute?.("aria-busy");
    }
  }
}

/** Invalidate pending refresh ownership before a route replaces the stage. */
export function invalidateRefreshedScreen(stage) {
  if (!stage) return;
  screenRefreshOwners.delete(stage);
  stage.removeAttribute?.("inert");
  stage.removeAttribute?.("aria-busy");
}

// ---------------------------------------------------------------------------
// ctx - the single object passed to every screen renderer.
// ---------------------------------------------------------------------------

const personDirectory = createPersonDirectory();
let currentOrganizationName = "";
let currentOrganizationIcon = null;

function setCurrentPersonDisplayName(value) {
  if (!ctx.identity) return;
  const displayName = typeof value === "string" && value.trim() ? value.trim() : null;
  ctx.identity.displayName = displayName;
  personDirectory.remember({
    actor: ctx.identity.actor,
    email: ctx.identity.actor,
    displayName,
  });
  if (SURFACE === "chat") paintChatIdentity(ctx.identity);
  else paintRailFoot(ctx.identity);
}

function setCurrentPersonAvatar(value) {
  if (!ctx.identity) return;
  const avatar = typeof value === "string" && value.trim() ? value.trim() : null;
  ctx.identity.avatar = avatar;
  personDirectory.remember({
    actor: ctx.identity.actor,
    email: ctx.identity.actor,
    displayName: ctx.identity.displayName,
    avatar,
  });
  if (SURFACE === "chat") paintChatIdentity(ctx.identity);
  else paintRailFoot(ctx.identity);
}

function setCurrentOrganizationName(value) {
  currentOrganizationName = typeof value === "string" ? value.trim() : "";
  ctx.organizationName = currentOrganizationName;
  const label = capitalizedOrganizationLabel(currentOrganizationName);
  const workspaceOrg = document.getElementById("workspace-org-name");
  if (workspaceOrg) workspaceOrg.textContent = label;
  paintWorkspaceOrgMark(label);
}

function setCurrentOrganizationIcon(value) {
  currentOrganizationIcon = typeof value === "string" && value.trim() ? value.trim() : null;
  paintWorkspaceOrgMark(capitalizedOrganizationLabel(currentOrganizationName));
}

/** The workspace mark beside the organization name. */
function paintWorkspaceOrgMark(label) {
  const mark = document.getElementById("workspace-org-mark");
  paintOrganizationMark(mark, label, currentOrganizationIcon);
}

/**
 * Paint either the uploaded organization image or its initials fallback.
 * Initials must not sit behind a transparent image; they return only if the
 * image fails to decode.
 */
export function paintOrganizationMark(mark, label, icon) {
  if (!mark) return;
  const fallback = initials(label);
  mark.textContent = fallback;
  if (!icon) return;
  const ownerDocument = mark.ownerDocument ||
    (typeof document !== "undefined" ? document : null);
  if (!ownerDocument || typeof ownerDocument.createElement !== "function") return;
  const image = ownerDocument.createElement("img");
  image.alt = "";
  image.decoding = "async";
  image.addEventListener("error", () => {
    // A newer paint may already have replaced this image.
    if (image.parentNode !== mark) return;
    image.remove();
    mark.textContent = fallback;
  });
  mark.textContent = "";
  mark.appendChild(image);
  image.src = icon;
}

const ctx = {
  api,
  esc,
  identity: null, // filled after /auth/me
  initialSetupChecklist: null,
  initialPeopleDirectoryRequest: null,
  organizationName: "",
  organizationScopeLabel: (namespace) =>
    organizationScopeLabel(namespace, currentOrganizationName, ctx.identity?.namespace),
  go,
  refresh,
  ui,
  personLabel: (subject, principal) =>
    personDisplayName(subject, (key) => personDirectory.label(key), principal),
  personAvatar: (subject, principal = "human") =>
    personAvatarHtml(subject, {
      esc,
      principal,
      label: (key) => personDirectory.label(key),
      avatar: (key) => personDirectory.avatar(key),
    }),
  personAvatarUrl: (subject, principal = "human") =>
    personAvatarUrl(subject, {
      principal,
      avatar: (key) => personDirectory.avatar(key),
    }),
  setCurrentPersonDisplayName,
  setCurrentPersonAvatar,
  setCurrentOrganizationName,
  setCurrentOrganizationIcon,
  notify: (notification) => actionToaster?.show(notification),
  // Decisions clear the shared inbox cache before calling this. Force a new
  // owner so an older pre-decision hydration can never repaint stale alerts.
  refreshNotifications: () => notificationCenter?.refresh({ force: true }),
  // "console" | "chat" — screens may hide console-only chrome on the chat
  // surface. NEVER an authorization input; the server ignores it entirely.
  surface: SURFACE,
};

// ---------------------------------------------------------------------------
// Delegated action listeners. Clicks use data-action; live form controls use
// data-input-action so screens can filter without attaching per-render handlers.
// ---------------------------------------------------------------------------

const POINTER_ACTION_EVENTS = new Set([
  "pointerdown",
  "pointermove",
  "pointerup",
  "pointercancel",
  "lostpointercapture",
]);

function wireDelegatedClicks() {
  const stage = document.getElementById("screen-content");
  stage.addEventListener("click", (ev) => {
    const el = ev.target.closest("[data-action]");
    if (!el || !stage.contains(el)) return;
    // Form controls dispatch their action from the input/change path below.
    // Avoid firing a select action before the user has chosen a new value.
    if (el.matches("[data-input-action], [data-change-action]")) return;
    const name = el.getAttribute("data-action");
    const actions = currentModule && currentModule.actions;
    if (actions && typeof actions[name] === "function") {
      ev.preventDefault();
      void runScreenAction(actions[name], ctx, el, stage, ev, name);
    }
  });
  POINTER_ACTION_EVENTS.forEach((type) => {
    stage.addEventListener(type, (ev) => {
      const actions = currentModule && currentModule.actions;
      try {
        runDelegatedPointerAction(ev, stage, actions, ctx);
      } catch (err) {
        showScreenActionError(stage, err);
      }
    });
  });
  stage.addEventListener("input", (ev) => {
    const el = ev.target.closest("[data-input-action]");
    if (!el || !stage.contains(el)) return;
    const name = el.getAttribute("data-input-action");
    const actions = currentModule && currentModule.actions;
    if (actions && typeof actions[name] === "function") {
      void runScreenAction(actions[name], ctx, el, stage, undefined, name);
    }
  });
  stage.addEventListener("change", (ev) => {
    const el = ev.target.closest("[data-change-action]");
    if (!el || !stage.contains(el)) return;
    const name = el.getAttribute("data-change-action");
    const actions = currentModule && currentModule.actions;
    if (actions && typeof actions[name] === "function") {
      void runScreenAction(actions[name], ctx, el, stage, undefined, name);
    }
  });
  stage.addEventListener("keydown", (ev) => {
    const actions = currentModule && currentModule.actions;
    void runDelegatedEnterAction(ev, stage, actions, ctx);
  });
  stage.addEventListener("wheel", (ev) => {
    const actions = currentModule && currentModule.actions;
    try {
      runDelegatedWheelAction(ev, stage, actions, ctx);
    } catch (err) {
      showScreenActionError(stage, err);
    }
  }, { passive: false });
  document.addEventListener("keydown", (ev) => {
    runDelegatedHotkey(ev, stage);
  });
  stage.addEventListener("error", (ev) => {
    if (!handlePersonAvatarError(ev.target, stage)) handleConnectorLogoError(ev.target, stage);
  }, true);
}

/**
 * Gate controls live outside the screen modules (the banner above the stage,
 * the member waiting view), so they get their own delegated listener instead
 * of riding currentModule.actions.
 */
function wireGateControls() {
  document.addEventListener("click", (ev) => {
    const reload = ev.target.closest("[data-gate-reload]");
    if (reload) {
      window.location.reload();
      return;
    }
    const cont = ev.target.closest("[data-gate-continue]");
    if (cont) {
      ev.preventDefault();
      go(SETUP_SCREEN);
    }
  });
}

/** Dispatch an opted-in pointer lifecycle without async work in the hot path. */
export function runDelegatedPointerAction(event, stage, actions, actionCtx) {
  if (!event || !POINTER_ACTION_EVENTS.has(event.type)) return false;
  const target = event.target;
  const element = target && typeof target.closest === "function"
    ? target.closest("[data-pointer-action]")
    : null;
  if (!element || !stage || typeof stage.contains !== "function" || !stage.contains(element)) return false;
  const name = typeof element.getAttribute === "function"
    ? element.getAttribute("data-pointer-action")
    : null;
  const action = name && actions && actions[name];
  if (typeof action !== "function") return false;
  action(actionCtx, element, event);
  return true;
}

/** Dispatch Enter from an opted-in textarea; Alt+Enter remains a newline. */
export async function runDelegatedEnterAction(event, stage, actions, actionCtx) {
  if (!event || event.key !== "Enter" || event.altKey || event.isComposing) return false;
  const target = event.target;
  const element = target && typeof target.closest === "function"
    ? target.closest("[data-enter-action]")
    : null;
  if (!element || !stage || typeof stage.contains !== "function" || !stage.contains(element)) return false;
  const name = typeof element.getAttribute === "function"
    ? element.getAttribute("data-enter-action")
    : null;
  const action = name && actions && actions[name];
  if (typeof action !== "function") return false;
  if (typeof event.preventDefault === "function") event.preventDefault();
  await runScreenAction(action, actionCtx, element, stage, undefined, name);
  return true;
}

/**
 * Dispatch a wheel gesture to an opted-in element. Screens that zoom a canvas
 * opt in with data-wheel-action; every other wheel keeps the page scrolling.
 */
export function runDelegatedWheelAction(event, stage, actions, actionCtx) {
  if (!event || event.type !== "wheel") return false;
  const target = event.target;
  const element = target && typeof target.closest === "function"
    ? target.closest("[data-wheel-action]")
    : null;
  if (!element || !stage || typeof stage.contains !== "function" || !stage.contains(element)) return false;
  const name = typeof element.getAttribute === "function"
    ? element.getAttribute("data-wheel-action")
    : null;
  const action = name && actions && actions[name];
  if (typeof action !== "function") return false;
  action(actionCtx, element, event);
  return true;
}

/**
 * Single-key shortcuts declared by the rendered screen (data-hotkey="/"). The
 * key never steals a keystroke that belongs to a form control, a modifier
 * chord, or a browser shortcut - it only moves focus to the declared target.
 */
export function runDelegatedHotkey(event, stage) {
  if (!event || event.altKey || event.ctrlKey || event.metaKey || event.isComposing) return false;
  // Only a conservative literal set is addressable, so the attribute selector
  // below can never be broken by a quote or bracket coming off the keyboard.
  const key = typeof event.key === "string" ? event.key : "";
  if (!/^[A-Za-z0-9/?.-]$/.test(key)) return false;
  const target = event.target;
  const tag = target && typeof target.tagName === "string" ? target.tagName.toLowerCase() : "";
  if (tag === "input" || tag === "textarea" || tag === "select" || target?.isContentEditable) return false;
  if (!stage || typeof stage.querySelector !== "function") return false;
  const element = stage.querySelector(`[data-hotkey="${key}"]`);
  if (!element || typeof element.focus !== "function") return false;
  if (typeof event.preventDefault === "function") event.preventDefault();
  element.focus();
  if (typeof element.select === "function") element.select();
  return true;
}

/** Reveal the local initials/product-glyph fallback when a remote logo fails. */
export function handleConnectorLogoError(target, stage) {
  const image = target && typeof target.closest === "function"
    ? target.closest("[data-connector-logo-image]")
    : null;
  if (!image || !stage || typeof stage.contains !== "function" || !stage.contains(image)) return false;
  image.hidden = true;
  const logo = typeof image.closest === "function" ? image.closest(".source-logo") : null;
  if (logo && typeof logo.setAttribute === "function") {
    logo.setAttribute(
      "data-logo-kind",
      (typeof logo.getAttribute === "function" && logo.getAttribute("data-logo-fallback-kind")) || "fallback",
    );
  }
  return true;
}

/** Run a delegated screen action without allowing a rejected promise to vanish. */
export async function runScreenAction(action, actionCtx, element, stage, event, actionName) {
  const previous = stage && stage.querySelector && stage.querySelector("[data-screen-error]");
  if (previous && typeof previous.remove === "function") previous.remove();
  const confirmation = confirmationFor(actionName);
  const tracked = confirmation ? trackActionRequests(actionCtx) : null;
  const runtimeCtx = tracked ? tracked.context : actionCtx;
  try {
    const result = event === undefined
      ? await action(runtimeCtx, element)
      : await action(runtimeCtx, element, event);
    enhanceDataTables(stage);
    if (
      confirmation &&
      shouldConfirmAction(confirmation, tracked.state, result) &&
      actionCtx &&
      typeof actionCtx.notify === "function"
    ) {
      actionCtx.notify(confirmation);
    }
  } catch (err) {
    // An allowance denial was already announced by the shared limit toast
    // from the API client; the generic failure card would say it twice.
    if (isLimitError(err)) return;
    showScreenActionError(stage, err);
  }
}

function showScreenActionError(stage, err) {
  if (!stage) return;
  let region = stage.querySelector && stage.querySelector("[data-screen-error]");
  if (!region) {
    const doc = stage.ownerDocument || (typeof document !== "undefined" ? document : null);
    if (!doc || typeof doc.createElement !== "function") return;
    region = doc.createElement("div");
    region.className = "card source-error";
    region.setAttribute("data-screen-error", "");
    region.setAttribute("role", "alert");
    region.setAttribute("tabindex", "-1");
    stage.prepend(region);
  }
  region.textContent = err && err.message ? String(err.message) : "Action failed. Try again.";
  if (typeof region.focus === "function") region.focus({ preventScroll: true });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function initials(text) {
  const parts = String(text).trim().split(/[\s@._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

/** Capitalized namespace fallback used only while the display-name read loads. */
function capitalizedOrganizationLabel(value) {
  const label = String(value ?? "").trim();
  if (!label) return "Organization root";
  const first = Array.from(label)[0];
  return first.toUpperCase() + label.slice(first.length);
}

/** Paint initials with the optional uploaded portrait layered above them. */
function paintAvatarTile(el, name, avatar) {
  if (!el) return;
  el.textContent = initials(name);
  if (!avatar) return;
  const image = document.createElement("img");
  image.className = "identity-av-image";
  image.setAttribute("data-person-avatar-image", "");
  image.alt = "";
  image.decoding = "async";
  image.addEventListener("error", () => { image.hidden = true; });
  image.src = avatar;
  el.appendChild(image);
}

function paintRailFoot(identity) {
  const who = ctx.personLabel(identity, "human") || identity.namespace || "You";
  const portrait = ctx.personAvatarUrl(identity, "human");
  const av = document.getElementById("rail-av");
  paintAvatarTile(av, who, portrait);
  av.setAttribute("data-tip", who);
  document.getElementById("rail-who").textContent = who;
  document.getElementById("rail-role").textContent = identity.role || "";
  const org = organizationScopeLabel(identity.namespace, "", identity.namespace);
  const workspaceAv = document.getElementById("workspace-av");
  const workspaceTrigger = document.querySelector(".workspace-account-trigger");
  const workspaceTriggerWho = document.getElementById("workspace-trigger-who");
  const workspaceTriggerRole = document.getElementById("workspace-trigger-role");
  const workspaceWho = document.getElementById("workspace-who");
  const workspaceRole = document.getElementById("workspace-role");
  paintAvatarTile(workspaceAv, who, portrait);
  if (workspaceTriggerWho) workspaceTriggerWho.textContent = who;
  if (workspaceTriggerRole) workspaceTriggerRole.textContent = identity.role || "";
  if (workspaceTrigger) {
    const accountLabel = who + (identity.role ? ", " + identity.role : "");
    workspaceTrigger.setAttribute("data-account-label", accountLabel);
    workspaceTrigger.setAttribute("aria-label", "Open account menu for " + accountLabel);
  }
  if (workspaceWho) workspaceWho.textContent = who;
  if (workspaceRole) workspaceRole.textContent = identity.role || "";
  setCurrentOrganizationName(org);
}

/** Replace the namespace fallback with the canonical organization display name. */
async function paintWorkspaceBrand() {
  try {
    const data = await api.get("/v1/admin/organization");
    const org = data && typeof data === "object" ? data.organization : null;
    if (!org || typeof org !== "object") return;
    if (typeof org.name === "string" && org.name.trim() !== "") {
      setCurrentOrganizationName(org.name);
    }
    setCurrentOrganizationIcon(org.icon);
  } catch {
    // Brownout: the capitalized namespace remains visible and the console works.
  }
}

/** Hide an unusable portrait so the initials underneath remain visible. */
export function handlePersonAvatarError(target, stage) {
  const image = target && typeof target.closest === "function"
    ? target.closest("[data-person-avatar-image]")
    : null;
  if (!image || !stage || typeof stage.contains !== "function" || !stage.contains(image)) return false;
  image.hidden = true;
  return true;
}

/** End the session. Shared by the rail control and the command palette. */
async function signOut() {
  try {
    await api.post("/auth/logout", {});
  } catch {
    // Even if the call fails, drop the user to login.
  }
  window.location = LOGIN_URL;
}

/** Open the compact workspace identity pill without changing its profile/logout menu. */
function wireWorkspaceAccountMenu() {
  const root = document.querySelector("[data-workspace-account]");
  const trigger = root && root.querySelector(".workspace-account-trigger");
  const menu = root && root.querySelector(".workspace-account-menu");
  const profile = root && root.querySelector("[data-account-profile]");
  const logout = root && root.querySelector("[data-logout]");
  if (!root || !trigger || !menu || !profile || !logout) return;

  const setOpen = (open, returnFocus = false) => {
    menu.hidden = !open;
    trigger.setAttribute("aria-expanded", String(open));
    const accountLabel = trigger.getAttribute("data-account-label");
    trigger.setAttribute(
      "aria-label",
      (open ? "Close account menu" : "Open account menu") + (accountLabel ? " for " + accountLabel : ""),
    );
    if (returnFocus) trigger.focus();
  };

  trigger.addEventListener("click", () => {
    setOpen(menu.hidden);
  });
  profile.addEventListener("click", () => {
    setOpen(false);
    const profileTab = document.getElementById("settings-tab-profile");
    if (screenFromHash() === "s18" && profileTab) {
      profileTab.click();
      profileTab.focus();
      window.scrollTo({ top: 0, behavior: "auto" });
      return;
    }
    go("s18?tab=profile");
  });
  logout.addEventListener("click", () => {
    setOpen(false);
    void signOut();
  });
  document.addEventListener("click", (event) => {
    if (!menu.hidden && !root.contains(event.target)) setOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !menu.hidden) setOpen(false, true);
  });
}

async function submitHaloAgentsHandoff() {
  const handoff = await api.post("/auth/halo-agents", {});
  if (
    !handoff ||
    typeof handoff.destination !== "string" ||
    typeof handoff.assertion !== "string" ||
    handoff.assertion.length === 0
  ) {
    throw new Error("Halo Agents handoff is unavailable.");
  }
  const destination = new URL(handoff.destination, window.location.href);
  if (destination.protocol !== "https:") {
    throw new Error("Halo Agents handoff destination is invalid.");
  }
  const form = document.createElement("form");
  form.method = "POST";
  form.action = destination.toString();
  form.hidden = true;
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "assertion";
  input.value = handoff.assertion;
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
}

// ---------------------------------------------------------------------------
// Chat surface boot (chat.html). Deliberately a SUBSET of the console boot:
// no rail, no breadcrumbs, no assistant dock (the screen IS the assistant),
// no command palette. The router still runs so the Assistant's own
// `#assistant?c=<ULID>`
// conversation handoff keeps working, but `allowedScreens` holds at most the
// Assistant — any other hash falls back to it via the existing guard.
// ---------------------------------------------------------------------------

function paintChatIdentity(identity) {
  const who = ctx.personLabel(identity, "human") || identity.namespace || "You";
  const av = document.getElementById("chat-av");
  if (av) {
    paintAvatarTile(av, who, ctx.personAvatarUrl(identity, "human"));
    av.setAttribute("data-tip", who);
  }
  const whoEl = document.getElementById("chat-who");
  if (whoEl) whoEl.textContent = who;
}

/**
 * Swap the neutral header for the organization's own name and mark (S18
 * settings, GET /v1/admin/organization — readable by every human role). The
 * icon is applied as an <img src> property after re-validating the data-URL
 * shape client-side; brownout or a tenant with no mark leaves the neutral
 * header in place.
 */
async function paintChatBrand() {
  const nameEl = document.getElementById("chat-org-name");
  const markEl = document.getElementById("chat-org-mark");
  if (!nameEl && !markEl) return;
  let org = null;
  try {
    const data = await api.get("/v1/admin/organization");
    org = data && typeof data === "object" ? data.organization : null;
  } catch {
    return; // brownout: the page still works, just unbranded
  }
  if (!org || typeof org !== "object") return;
  if (nameEl && typeof org.name === "string" && org.name.trim() !== "") {
    nameEl.textContent = org.name;
    document.title = org.name + " - Assistant";
  }
  if (
    markEl &&
    typeof org.icon === "string" &&
    /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(org.icon)
  ) {
    markEl.src = org.icon;
    markEl.hidden = false;
  }
}

/**
 * The people directory is privileged on the server. Product-role auditors are
 * exposed as members carrying audit:read, so include that entitlement while
 * keeping the guaranteed-403 ordinary-member path completely silent.
 */
export function canLoadPeopleDirectory(identity) {
  const role = identity && identity.role;
  return role === "owner" || role === "root" || role === "admin" || role === "auditor" ||
    (role === "member" && Array.isArray(identity.entitlements) &&
      identity.entitlements.includes("audit:read"));
}

async function hydratePeopleDirectory() {
  const people = await api.get("/v1/admin/people");
  personDirectory.remember(Array.isArray(people?.users) ? people.users : []);
  return people;
}

async function bootChatSurface() {
  // Role-derived, then locked to the Assistant. Empty when (if ever) a role
  // loses s10 — loadScreen renders its honest "no screens" state then.
  allowedScreens = new Set(
    screensFor(ctx.identity).filter((s) => s === ASSISTANT_SCREEN),
  );
  paintChatIdentity(ctx.identity);
  void paintChatBrand();
  wireDelegatedClicks();
  wireGateControls(); // the gate card's "Check again" reuses data-gate-reload
  const logout = document.querySelector("[data-logout]");
  if (logout) logout.addEventListener("click", () => void signOut());
  window.addEventListener("hashchange", () => {
    canonicalizeCurrentHash();
    void loadScreen(screenFromHash() ?? ASSISTANT_SCREEN, ctx);
  });
  canonicalizeCurrentHash();
  await loadScreen(screenFromHash() ?? ASSISTANT_SCREEN, ctx);
}

async function boot() {
  actionToaster = createActionToaster(document);
  setLimitNotifier(createLimitNotifier(actionToaster, {
    owner: () => ctx.identity?.role === "owner" || ctx.identity?.role === "root",
  }));
  const initialScreenId = screenFromHash() ??
    (SURFACE === "chat" ? ASSISTANT_SCREEN : DEFAULT_SCREEN);
  void preloadScreenModule(initialScreenId).catch(() => {});
  const meRequest = api.get("/auth/me");
  let me;
  try {
    me = await meRequest;
  } catch (err) {
    // request() already redirects on 401; any other failure → login too.
    if (!err || err.status !== 401) window.location = LOGIN_URL;
    return;
  }
  ctx.identity = {
    keyId: me.keyId,
    namespace: me.namespace,
    actor: me.actor,
    displayName: me.displayName ?? null,
    avatar: me.avatar ?? null,
    role: me.role,
    entitlements: Array.isArray(me.entitlements) ? me.entitlements : [],
    capabilities: me.capabilities ?? {},
  };
  personDirectory.remember(ctx.identity);

  // Mandatory setup gate (CONTRACTS-SETUP-GATE.md): the server-persisted
  // onboarding latch rides on /auth/me. There is no skip and no localStorage
  // escape hatch — the console unlocks only when the server-side checklist
  // derives complete (the same fetch that drives the Setup badge lifts the
  // gate live). A missing/garbled field is treated as NOT gated, so a flag
  // read failure never blocks the console.
  const onboarding =
    me && typeof me.onboarding === "object" && me.onboarding !== null
      ? me.onboarding
      : null;
  if (onboarding && onboarding.setupRequired === true) {
    gateMode =
      me.role === "owner" || me.role === "root" || me.role === "admin"
        ? "setup"
        : "waiting";
  }
  if (SURFACE === "console" && gateMode !== null) {
    void preloadScreenModule(SETUP_SCREEN).catch(() => {});
  }

  // Whitelabel chat page: same identity, same gate, one screen, no chrome.
  if (SURFACE === "chat") {
    await bootChatSurface();
    return;
  }

  if (gateMode === "setup") {
    ctx.initialSetupChecklist = api.get("/v1/admin/setup-checklist").catch(() => null);
  }

  // Start this only for roles the server admits. The request overlaps shell
  // construction and module preload; the first full-console render waits for
  // it so actor labels never regress to raw ids. Home consumes this exact
  // payload rather than issuing the same directory read a second time.
  const peopleDirectoryRequest = canLoadPeopleDirectory(ctx.identity)
    ? hydratePeopleDirectory()
    : Promise.resolve(null);
  // Deep links await this defensively; Home attaches it to its allSettled batch
  // below. Attach a handler now as well so a fast brownout is never unhandled.
  peopleDirectoryRequest.catch(() => {});
  ctx.initialPeopleDirectoryRequest = peopleDirectoryRequest;

  paintRailFoot(ctx.identity);
  void paintWorkspaceBrand();
  renderRail(ctx.identity);
  const railTooltip = wireRailTooltip(document.getElementById("app-rail"));
  wireDelegatedClicks();
  wireGateControls();
  void paintSetupBadge();

  // The dock is built before the first route so its availability is decided by
  // the same loadScreen() pass that paints the screen behind it.
  const dockRoot = document.getElementById("assistant-dock");
  if (dockRoot) {
    assistantDock = createAssistantDock({
      ctx,
      root: dockRoot,
      // Carry the dock's durable conversation into S10 so "open full assistant"
      // continues the thread instead of starting a new one.
      onExpand: (screenId, conversationId) =>
        go(conversationId ? screenId + "?c=" + encodeURIComponent(conversationId) : screenId),
    });
  }

  // The command palette. Built before the first route so the same loadScreen()
  // pass that paints the screen also decides whether the trigger is revealed.
  const paletteRoot = document.getElementById("command-palette");
  if (paletteRoot) {
    commandPalette = createCommandPalette({
      ctx,
      root: paletteRoot,
      navigation: () => NAV,
      // A getter, not a snapshot: the guard set is rebuilt whenever the rail
      // re-renders (role change, gate lift), and the palette must follow it.
      allowedScreens: () => allowedScreens,
      onSignOut: () => void signOut(),
      onAction: (action) => {
        if (action !== "haloAgents") return;
        void submitHaloAgentsHandoff().catch((error) => {
          showScreenActionError(document.getElementById("screen-content"), error);
        });
      },
    });
    // One spelling on every platform. Windows and Linux additionally accept
    // Ctrl+K, because the OS keeps Win+K for itself (see command-palette.js).
    const hint = shortcutLabel();
    document.querySelectorAll("[data-cmdk-hint]").forEach((el) => {
      el.textContent = hint;
    });
    document.querySelectorAll("[data-cmdk-open]").forEach((el) => {
      el.addEventListener("click", () => commandPalette.open());
      const tip = el.getAttribute("data-tip");
      if (tip) el.setAttribute("data-tip", `${tip} (${hint})`);
    });
  }

  wireWorkspaceAccountMenu();
  const notificationRoot = document.getElementById("notification-center");
  const notificationTrigger = document.querySelector("[data-notification-trigger]");
  if (notificationRoot && notificationTrigger) {
    notificationCenter = createNotificationCenter({
      ctx,
      root: notificationRoot,
      trigger: notificationTrigger,
      canOpen: () => gateMode === null && allowedScreens.has("s19"),
      onOpenAlerts: () => go("s19"),
      initialRefresh: false,
    });
  }

  document.getElementById("console-breadcrumbs").addEventListener("click", (ev) => {
    const crumb = ev.target.closest("[data-breadcrumb-screen]");
    if (!crumb) return;
    const target = crumb.getAttribute("data-breadcrumb-screen");
    if (!target || !allowedScreens.has(target)) return;
    if (
      target === currentScreenId &&
      currentModule &&
      typeof currentModule.onBreadcrumbBack === "function"
    ) {
      currentModule.onBreadcrumbBack();
    }
    go(target);
  });

  // Desktop rail collapse - icon-only mode with hover tooltips; persisted.
  const railCollapse = document.getElementById("rail-collapse");
  const COLLAPSE_KEY = "halofy.railCollapsed";
  function applyRailCollapsed(collapsed) {
    railTooltip.hide();
    document.body.classList.toggle("rail-collapsed", collapsed);
    railCollapse.setAttribute("aria-expanded", String(!collapsed));
    railCollapse.setAttribute(
      "aria-label",
      collapsed ? "Expand navigation" : "Collapse navigation",
    );
    railCollapse.setAttribute(
      "data-tip",
      collapsed ? "Expand navigation" : "Collapse navigation",
    );
  }
  let railCollapsed = false;
  try {
    railCollapsed = localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    // Storage unavailable (private mode) - state just won't persist.
  }
  applyRailCollapsed(railCollapsed);
  railCollapse.addEventListener("click", () => {
    railCollapsed = !railCollapsed;
    try {
      localStorage.setItem(COLLAPSE_KEY, railCollapsed ? "1" : "0");
    } catch {
      // Same: non-persistent fallback.
    }
    applyRailCollapsed(railCollapsed);
  });

  const mobileNavigation = createMobileNavigation({
    body: document.body,
    rail: document.getElementById("app-rail"),
    toggle: document.getElementById("mobile-nav-toggle"),
    close: document.getElementById("mobile-nav-close"),
    backdrop: document.getElementById("mobile-nav-backdrop"),
    eventTarget: document,
    media: window.matchMedia("(max-width: 860px)"),
    background: [
      document.getElementById("mobile-topbar"),
      document.getElementById("stage"),
    ],
  });

  // Both Halofy lockups route Home through the same shared reachability guard.
  document.querySelectorAll("[data-brand-home]").forEach((btn) => {
    const inRail = Boolean(btn.closest(".rail"));
    btn.addEventListener("click", () => {
      if (!allowedScreens.has(DEFAULT_SCREEN)) return;
      if (inRail) mobileNavigation.close({ returnFocus: true });
      go(DEFAULT_SCREEN);
    });
  });

  // Rail nav clicks → go(). (Delegated on the nav container so it survives
  // re-render.)
  document.getElementById("rail-nav").addEventListener("click", (ev) => {
    const groupToggle = ev.target.closest("button[data-nav-group]");
    if (groupToggle) {
      ev.preventDefault();
      const groupKey = groupToggle.getAttribute("data-nav-group");
      const isExpanded = groupToggle.getAttribute("aria-expanded") === "true";
      setExpandedRailGroup(isExpanded ? null : groupKey);
      return;
    }
    const haloAgents = ev.target.closest("button[data-halo-agents]");
    if (haloAgents) {
      ev.preventDefault();
      mobileNavigation.close({ returnFocus: false });
      const haloAgentsLabel = haloAgents.querySelector("[data-halo-agents-label]");
      const idleLabel = haloAgentsLabel?.textContent ?? "Halo Agents";
      haloAgents.disabled = true;
      haloAgents.setAttribute("aria-busy", "true");
      if (haloAgentsLabel) haloAgentsLabel.textContent = "Opening Halo Agents…";
      void submitHaloAgentsHandoff().catch((error) => {
        haloAgents.disabled = false;
        haloAgents.removeAttribute("aria-busy");
        if (haloAgentsLabel) haloAgentsLabel.textContent = idleLabel;
        showScreenActionError(document.getElementById("screen-content"), error);
      });
      return;
    }
    const btn = ev.target.closest("button[data-s]");
    if (btn) {
      mobileNavigation.close({ returnFocus: true });
      go(btn.getAttribute("data-s"));
    }
  });

  // Logout control.
  document.getElementById("logout").addEventListener("click", () => {
    void signOut();
  });

  // Re-render on hash change (back/forward + go()). The setup badge refreshes
  // alongside so a step completed on the previous screen clears it live.
  window.addEventListener("hashchange", () => {
    canonicalizeCurrentHash();
    void loadScreen(screenFromHash() ?? DEFAULT_SCREEN, ctx);
    void paintSetupBadge();
  });

  // Initial screen.
  canonicalizeCurrentHash();
  await loadScreen(screenFromHash() ?? DEFAULT_SCREEN, ctx);
  ctx.initialSetupChecklist = null;
}

if (typeof document !== "undefined" && typeof window !== "undefined") void boot();
