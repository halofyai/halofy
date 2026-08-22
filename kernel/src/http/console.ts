/**
 * HaloMem console transport helpers (M5 module C).
 *
 * Two concerns, both pure of the kernel:
 *
 *  1. Static serving of the control-room screens under a `console/` dir, mounted
 *     at `GET /console/*`. Path traversal is rejected structurally: the resolved
 *     real path must stay inside the root dir, so `/console/../server.ts` (and
 *     any symlink escape) → 403, a missing file → 404.
 *
 *  2. Opaque, HttpOnly session cookies. Humans sign in with email/password (D9:
 *     the server resolves their Identity); the browser then carries a random
 *     token in `halomem_session`. The token is stored HASHED at rest (that lives
 *     in module A / the kernel) — this file only shuttles the plaintext token in
 *     and out of the cookie header. Cookie is `HttpOnly; SameSite=Lax; Path=/`,
 *     `Secure` only off-localhost, with a server-side `Max-Age`.
 *
 * node:http + node:fs/node:path only. No kernel import (the integrator injects
 * the console dir path + the human-auth handlers through HttpServerDeps).
 */

import { renderHaloStatusPage } from "../branding/halo-page.js";
import { createReadStream } from "node:fs";
import { stat, realpath } from "node:fs/promises";
import { join, normalize, resolve, sep, extname } from "node:path";
import type { IncomingHttpHeaders, ServerResponse } from "node:http";

/** Cookie name for the opaque session token. */
export const SESSION_COOKIE = "halomem_session";
/** Short-lived verified-email capability used only to create a first org. */
export const SIGNUP_COOKIE = "halomem_signup";
export const SIGNUP_MAX_AGE_SECONDS = 10 * 60;

/**
 * Session cookie lifetime, in seconds (10 days).
 *
 * Must equal `DEFAULT_SESSION_TTL_SECONDS` in src/console/auth.ts — that is the
 * server's idle window, and this is the browser's copy of it. (Duplicated as a
 * literal on purpose: this module imports nothing from the kernel.) The two
 * slide together because the transport re-sends this cookie on every
 * cookie-authenticated request.
 *
 * Expiry is ALSO enforced server-side against the stored session — the cookie
 * Max-Age is a browser hint, never the authority.
 */
export const SESSION_MAX_AGE_SECONDS = 10 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Static serving
// ---------------------------------------------------------------------------

/** Extension → Content-Type. Anything else is served as octet-stream. */
const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".png": "image/png",
  ".webp": "image/webp",
};

function contentType(filePath: string): string {
  return CONTENT_TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

/**
 * Console static failures are BROWSER destinations (a mistyped `/console/…`
 * URL, a stale bookmark), so they render the Halo status page rather than a
 * bare string. The status code is the contract; the body is for the human.
 */
const STATIC_ERROR_COPY: Record<number, { eyebrow: string; heading: string; message: string }> = {
  400: {
    eyebrow: "Bad request",
    heading: "That link isn’t readable",
    message: "The address contains characters this console can’t interpret.",
  },
  403: {
    eyebrow: "Forbidden",
    heading: "That path is off limits",
    message: "The console only serves files from its own directory.",
  },
  404: {
    eyebrow: "Not found",
    heading: "That page doesn’t exist",
    message: "The address may be mistyped, or the page may have moved.",
  },
  500: {
    eyebrow: "Server error",
    heading: "Something went wrong",
    message: "The console couldn’t read that file. Try again in a moment.",
  },
};

function sendPlain(res: ServerResponse, status: number, message: string): void {
  const copy = STATIC_ERROR_COPY[status];
  if (copy === undefined) {
    res.writeHead(status, {
      "content-type": "text/plain; charset=utf-8",
      "content-length": Buffer.byteLength(message),
    });
    res.end(message);
    return;
  }
  const body = renderHaloStatusPage({
    title: `${copy.heading} - Halofy`,
    eyebrow: copy.eyebrow,
    heading: copy.heading,
    messages: [copy.message],
    tone: status >= 500 || status === 403 ? "alert" : "notice",
    action: { href: "/console/", label: "Back to the console" },
  });
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

/** Permanent redirect helper for URL canonicalization (`.html` → clean). */
function sendRedirect(res: ServerResponse, location: string): void {
  res.writeHead(308, { location, "content-length": 0 });
  res.end();
}

function ifNoneMatchMatches(
  value: string | string[] | undefined,
  etag: string,
): boolean {
  const joined = Array.isArray(value) ? value.join(",") : value;
  if (!joined) return false;
  const normalizedEtag = etag.replace(/^W\//, "");
  return joined.split(",").some((candidate) => {
    const token = candidate.trim();
    return token === "*" || token.replace(/^W\//, "") === normalizedEtag;
  });
}

/**
 * Serve a file under `rootDir` for the request path `urlPath`.
 *
 * `urlPath` is the full request pathname (e.g. `/console/app.css` or `/console`).
 * The `/console` prefix is stripped. Routes are CLEAN — the canonical URLs
 * never show `.html`:
 *
 *   - `/console/` → index.html; `/console` (no slash) → 308 `/console/` so
 *     relative asset links inside the page resolve against `/console/`.
 *   - `/console/login` (any extensionless name) → `login.html` on disk.
 *   - `/console/login.html` → 308 `/console/login`; `/console/index.html` →
 *     308 `/console/`. `search` (the request query string, e.g. an invite
 *     token) is carried through the redirect.
 *
 * The candidate is resolved and its realpath asserted to stay inside
 * `rootDir` — any escape (`..`, absolute smuggling, symlink) → 403. A file
 * that does not exist → 404.
 *
 * This never throws for the traversal/missing cases: it writes the response and
 * returns. The caller (server.ts) treats a returned promise as fully handled.
 */
export async function serveStatic(
  rootDir: string,
  urlPath: string,
  res: ServerResponse,
  search = "",
  requestHeaders: IncomingHttpHeaders = {},
): Promise<void> {
  // The old standalone signup document is retired. Keep stale bookmarks on
  // the login card, where the verified-email organization step now lives.
  if (urlPath === "/console/signup" || urlPath === "/console/signup.html") {
    return sendRedirect(res, "/console/login?signup=organization");
  }

  // Canonical dashboard URL is `/console/` — redirect the slashless form so
  // relative links in index.html resolve under the mount, not at `/`.
  if (urlPath === "/console") {
    return sendRedirect(res, "/console/" + search);
  }

  // Strip the mount prefix. `/console/` leaves an empty rel — the index
  // default is applied AFTER the `.html` canonicalization so the internal
  // index.html mapping never redirects to itself.
  let rel = urlPath;
  if (rel === "/console/") {
    rel = "";
  } else if (rel.startsWith("/console/")) {
    rel = rel.slice("/console/".length);
  } else if (rel.startsWith("/console")) {
    // e.g. "/consolexyz" — never our mount; treat as not found.
    rel = rel.slice("/console".length);
  }

  // Decode percent-encoding so `%2e%2e` can't sneak a `..` past normalize().
  let decoded: string;
  try {
    decoded = decodeURIComponent(rel);
  } catch {
    return sendPlain(res, 400, "bad request");
  }

  // Reject NUL bytes and CR/LF outright (path poisoning / header injection —
  // a decoded newline would otherwise reach the redirect Location header).
  if (/[\0\r\n]/.test(decoded)) {
    return sendPlain(res, 403, "forbidden");
  }

  // Normalize away `.`/`..` segments, then strip leading separators so the
  // join can't be treated as absolute (and trailing ones so `/login/` maps
  // like `/login`). An empty result → index.html.
  const cleaned = normalize(decoded)
    .replace(/^([/\\])+/, "")
    .replace(/([/\\])+$/, "");

  // Canonicalize: an EXPLICITLY requested `.html` URL permanently redirects to
  // its clean form, query string preserved (invite links arrive as
  // login.html?invite=…). Runs before the index default so the internal
  // index.html mapping below never redirects to itself.
  if (cleaned.toLowerCase().endsWith(".html")) {
    const clean = cleaned.slice(0, -".html".length).replace(/\\/g, "/");
    const location =
      clean === "index" || clean === ""
        ? "/console/"
        : "/console/" + clean.split("/").map(encodeURIComponent).join("/");
    return sendRedirect(res, location + search);
  }

  let target = cleaned === "" || cleaned === "." ? "index.html" : cleaned;

  // Clean route: an extensionless path serves its `.html` counterpart.
  if (extname(target) === "") {
    target += ".html";
  }

  const root = resolve(rootDir);
  const candidate = resolve(join(root, target));

  // First structural gate: the resolved candidate must be inside root even
  // before we touch the filesystem (defends against `..` that normalize missed
  // and absolute smuggling). `root + sep` prevents a sibling-prefix escape
  // (`/srv/consoleX` vs root `/srv/console`).
  if (candidate !== root && !candidate.startsWith(root + sep)) {
    return sendPlain(res, 403, "forbidden");
  }

  // Second gate: realpath (follows symlinks) must ALSO stay inside root. A
  // missing file makes realpath throw ENOENT → 404.
  let real: string;
  try {
    real = await realpath(candidate);
  } catch {
    return sendPlain(res, 404, "not found");
  }
  const realRoot = await realpath(root).catch(() => root);
  if (real !== realRoot && !real.startsWith(realRoot + sep)) {
    return sendPlain(res, 403, "forbidden");
  }

  let info;
  try {
    info = await stat(real);
  } catch {
    return sendPlain(res, 404, "not found");
  }
  if (!info.isFile()) {
    return sendPlain(res, 404, "not found");
  }

  const etag = `W/"${info.size.toString(16)}-${Math.trunc(info.mtimeMs).toString(16)}"`;
  const headers = {
    "content-type": contentType(real),
    "cache-control": "public, max-age=0, must-revalidate",
    etag,
    "last-modified": info.mtime.toUTCString(),
  };
  if (ifNoneMatchMatches(requestHeaders["if-none-match"], etag)) {
    res.writeHead(304, headers);
    res.end();
    return;
  }

  res.writeHead(200, { ...headers, "content-length": info.size });
  const stream = createReadStream(real);
  stream.on("error", () => {
    if (!res.headersSent) sendPlain(res, 500, "read error");
    else res.destroy();
  });
  stream.pipe(res);
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/**
 * Parse a `Cookie` header into a plain map. Hand-rolled (no dep): splits on
 * `;`, then on the first `=`, trims whitespace, and URL-decodes the value.
 * A missing header → {}. Later duplicates win.
 */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name === "") continue;
    let value = part.slice(eq + 1).trim();
    // Strip surrounding double quotes if present.
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

/**
 * Append a `Set-Cookie` for the session token.
 *
 * `HttpOnly` (no JS access) + `SameSite=Lax` (CSRF baseline) + `Path=/` +
 * `Max-Age`. `Secure` is added only when `secure` is true — the integrator
 * passes `false` on localhost so dev over http works, `true` behind TLS.
 *
 * Uses `res.appendHeader` so a prior `Set-Cookie` isn't clobbered.
 */
export function setSessionCookie(res: ServerResponse, token: string, secure: boolean): void {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
  ];
  if (secure) parts.push("Secure");
  appendSetCookie(res, parts.join("; "));
}

/**
 * Clear the session cookie: same name/path, empty value, `Max-Age=0` so the
 * browser drops it immediately. Keeps `HttpOnly`/`SameSite`/`Path` so the
 * attributes match the set cookie (some browsers require this to overwrite).
 */
export function clearSessionCookie(res: ServerResponse): void {
  appendSetCookie(
    res,
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
  );
}

export function setSignupCookie(res: ServerResponse, token: string, secure: boolean): void {
  const parts = [
    `${SIGNUP_COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SIGNUP_MAX_AGE_SECONDS}`,
  ];
  if (secure) parts.push("Secure");
  appendSetCookie(res, parts.join("; "));
}

export function clearSignupCookie(res: ServerResponse): void {
  appendSetCookie(
    res,
    `${SIGNUP_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
  );
}

/** Cookie name for the short-lived OAuth state nonce (GitHub login/link). */
export const OAUTH_STATE_COOKIE = "halomem_gh_state";

/** OAuth state cookie lifetime, in seconds (10 minutes — one redirect round). */
export const OAUTH_STATE_MAX_AGE_SECONDS = 600;

/**
 * Append a `Set-Cookie` for the OAuth state nonce. Same attributes as the
 * session cookie (`HttpOnly`, `SameSite=Lax` so the top-level OAuth redirect
 * back to us still carries it) but a 10-minute Max-Age.
 */
export function setOAuthStateCookie(res: ServerResponse, value: string, secure: boolean): void {
  const parts = [
    `${OAUTH_STATE_COOKIE}=${encodeURIComponent(value)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${OAUTH_STATE_MAX_AGE_SECONDS}`,
  ];
  if (secure) parts.push("Secure");
  appendSetCookie(res, parts.join("; "));
}

/**
 * CONTRACTS-OAUTH-CONNECT OA8 — the only post-login destination a caller may
 * steer us to.
 *
 * A signed-out visitor to `/oauth/authorize` is bounced through the console
 * login carrying `?next=/oauth/authorize?…`; every sign-in path must hand them
 * back to that exact URL or the connector never receives its code — the user
 * logs in, lands in the console, and the app that sent them stays disconnected.
 * That was the failure: the SSO round trips dropped `next` and fell back to
 * `/console/`.
 *
 * Only a same-origin PATH targeting this kernel's own authorize endpoint is
 * accepted. Absolute URLs, protocol-relative values, and any other path fall
 * back to the console. This MUST stay in agreement with the identical fence in
 * `console/login.html` — they are the same rule enforced on both sides.
 */
export function safeConsentReturn(value: string | null | undefined): string {
  const next = typeof value === "string" ? value : "";
  if (next.length > 2_048) return "";
  if (next.startsWith("//")) return "";
  // Exactly the whitelabel chat page — a chat user finishing a provider
  // sign-in returns to /chat instead of the console.
  if (next === "/chat") return next;
  if (!next.startsWith("/oauth/authorize?")) return "";
  return next;
}

/** Clear the OAuth state cookie (single-use — cleared on every callback). */
export function clearOAuthStateCookie(res: ServerResponse): void {
  appendSetCookie(
    res,
    `${OAUTH_STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
  );
}

/** Append a Set-Cookie header without dropping any already present. */
function appendSetCookie(res: ServerResponse, value: string): void {
  const existing = res.getHeader("set-cookie");
  if (existing === undefined) {
    res.setHeader("set-cookie", value);
  } else if (Array.isArray(existing)) {
    res.setHeader("set-cookie", [...existing, value]);
  } else {
    res.setHeader("set-cookie", [String(existing), value]);
  }
}
