/**
 * M9 parity #11a — public per-org discovery site (CONTRACTS-M9-PARITY.md
 * E28–E30). ORG TIER ONLY — the per-individual tier is explicitly DEFERRED
 * per the Wave 3 addenda ("#11 individual tier"), intentional, not a drop.
 *
 * Serves two UNAUTHENTICATED routes:
 *   GET /{orgSlug}            → HTML discovery page (redacted public tier)
 *   GET /{orgSlug}/llms.txt   → text/plain llms.txt (same redacted subset)
 *
 * Boundary (the review attacks this):
 *  - E28 — `orgSlug` resolves SERVER-SIDE to a tenant root namespace: the slug
 *    is exactly a registered tenant id (src/tenancy/ — a tenant IS a root
 *    namespace), looked up via TenantRegistry.get with a parameterized exact
 *    match. Nothing in the request body, query string, or headers can name a
 *    namespace or actor (D9); the path segment is the only input and it only
 *    selects WHICH org page, never what that page may contain.
 *  - E29 — renders ONLY public-classified, active, current-version canonical
 *    L2/L3 rows. Rows flow through the SAME fence stack as the badge manifest:
 *    MemoryIndex.listCandidates (status/TTL/supersedence/pointer/source-access/
 *    classification fences in SQL) → isManifestRow (canonical L2/L3, no
 *    pointer/cache provenance) → the PUBLIC redaction filter added here:
 *    classification.sensitivity === "public" EXPLICITLY (rows without a
 *    classification default to internal in rowToMemoryObject and are excluded),
 *    zero piiSubjects/secretKinds (belt: "public" with PII stamped is a
 *    labeling error, not publishable), open source-access only (no access
 *    subject is passed, so any row with source-native grants is excluded in
 *    SQL), and namespace === the tenant root exactly (mounted rows from other
 *    namespaces never leak onto a public page). Rendering reuses the
 *    manifest.ts renderer — no second renderer.
 *  - E30 — the unauthenticated response leaks nothing beyond the redacted
 *    subset:
 *      * no namespace names: only root-namespace rows render, and the only
 *        "namespace" shown is the slug the caller already typed;
 *      * no actor names / source ids: provenance is redacted to a single
 *        generic "public" source before rendering, so connector ids, actor
 *        ids, and session ids never appear;
 *      * no counts that fingerprint private content: every count in the output
 *        (entries, bytes) is computed AFTER the public filter, over the
 *        redacted subset only;
 *      * anti-fingerprinting 404: unknown slug, suspended tenant, and an org
 *        with ZERO public-classified rows all return the IDENTICAL 404 body,
 *        so probing slugs cannot confirm a tenant exists until that tenant
 *        has deliberately published public-classified memory;
 *      * errors return a generic 500 body — no messages, no stack.
 *  - D4 — every request audits, including denied (unknown/suspended/empty org,
 *    rate limit) and error outcomes: op "read", purpose "public-discovery",
 *    actor/agentId "public".
 *  - Read-only: no store handle, no write path, no SQL of its own. Data
 *    surface = MemoryIndex.listCandidates + TenantRegistry.get.
 *
 * The HTML page is string-rendered with every dynamic value HTML-escaped and
 * contains no inline JS (same discipline as the console).
 */

import type {
  AuditEvent,
  MemoryObject,
  Namespace,
  Tenant,
} from "../types.js";
import type { ListCandidatesOptions } from "../index/index.js";
import {
  escapeHtml,
  renderHaloStatusPage,
  HALO_TOKENS_CSS,
} from "../branding/halo-page.js";
import {
  DEFAULT_MANIFEST_MAX_BYTES,
  isManifestRow,
  renderManifestMarkdown,
} from "./manifest.js";

// ---------------------------------------------------------------------------
// Public types (local per parallel-safety rule — reported for promotion)
// ---------------------------------------------------------------------------

/** "page" = HTML discovery page; "llms" = llms.txt plain-text tier. */
export type PublicDiscoveryFormat = "page" | "llms";

/** Narrow structural deps so the integrator passes kernel-owned instances. */
export interface PublicDiscoveryDeps {
  /** The kernel's MemoryIndex (src/index/index.ts) — the ONLY row source. */
  index: {
    listCandidates(
      callerNamespace: Namespace,
      options?: ListCandidatesOptions,
    ): Promise<MemoryObject[]>;
  };
  /** The kernel's TenantRegistry (src/tenancy/) — E28 slug resolution. */
  tenants: { get(id: Namespace): Promise<Tenant | null> };
  /** The kernel's AuditLog — D4, every outcome audits. */
  audit: { append(event: AuditEvent): Promise<void> };
  /** Optional: SyscallDeps.rateLimiter — unauthenticated abuse damper. */
  rateLimiter?: { allow(key: string, limit: number): boolean | Promise<boolean> };
}

/** Transport-agnostic response the HTTP integrator writes verbatim. */
export interface PublicDiscoveryResponse {
  status: number;
  contentType: string;
  body: string;
}

export interface PublicDiscoveryMatch {
  orgSlug: string;
  format: PublicDiscoveryFormat;
}

// ---------------------------------------------------------------------------
// Limits + constants
// ---------------------------------------------------------------------------

/** Per-slug unauthenticated rate limit (requests/min). */
export const PUBLIC_DISCOVERY_RATE_LIMIT_PER_MIN = 120;
/** Same "all visible rows" bound the manifest uses against listCandidates. */
const ALL_ROWS = 2_147_483_647;
/** HTML page renders at most this many entries (llms.txt uses the byte cap). */
const PAGE_MAX_ENTRIES = 500;
const PURPOSE = "public-discovery";
/** Anonymous principal for audit rows — never a real actor name (E30). */
const PUBLIC_ACTOR = "public";

/**
 * Path segments that can never be org slugs. Defense in depth: the integrator
 * wires this matcher BELOW every real route (just above the identity
 * middleware), so real routes always win — this list is a second fence, not
 * the first.
 */
const RESERVED_SLUGS = new Set([
  "v1",
  "console",
  "oauth",
  "mcp",
  "health",
  "healthz",
  "metrics",
  "public",
  "static",
  "assets",
  "admin",
  "api",
  "docs",
  "login",
  "logout",
  "favicon.ico",
  "robots.txt",
  "llms.txt",
  ".well-known",
]);

// ---------------------------------------------------------------------------
// Route matching (pure — the HTTP integrator calls this)
// ---------------------------------------------------------------------------

/**
 * Match `GET /{orgSlug}` or `GET /{orgSlug}/llms.txt`. Returns null for
 * anything else (multi-segment paths, reserved names, empty/dot segments,
 * segments containing `/` after decoding), so the integrator simply falls
 * through to its normal 404.
 */
export function matchPublicDiscoveryPath(
  path: string,
): PublicDiscoveryMatch | null {
  const m = /^\/([^/]+)(\/llms\.txt)?\/?$/.exec(path);
  if (!m) return null;
  let slug: string;
  try {
    slug = decodeURIComponent(m[1]);
  } catch {
    return null;
  }
  if (
    slug.length === 0 ||
    slug.length > 128 ||
    slug.includes("/") ||
    slug.includes("\\") ||
    slug === "." ||
    slug === ".." ||
    slug.startsWith(".") ||
    RESERVED_SLUGS.has(slug.toLowerCase())
  ) {
    return null;
  }
  return { orgSlug: slug, format: m[2] ? "llms" : "page" };
}

// ---------------------------------------------------------------------------
// Redaction filter (E29 / E30)
// ---------------------------------------------------------------------------

/**
 * A row is publishable on the public tier iff it is a canonical manifest row
 * (isManifestRow: active, currently-valid, L2/L3, non-pointer, non-cache) AND
 * explicitly classified public AND carries no PII/secret stamps AND lives in
 * EXACTLY the tenant root namespace (mounted rows are excluded — they may
 * belong to another org).
 */
export function isPublicRow(obj: MemoryObject, tenantRoot: Namespace): boolean {
  if (!isManifestRow(obj)) return false;
  if (obj.namespace !== tenantRoot) return false;
  const c = obj.classification;
  if (c === undefined || c.sensitivity !== "public") return false;
  if (c.piiSubjects.length > 0 || c.secretKinds.length > 0) return false;
  return true;
}

/**
 * Strip everything a public reader must not see from a row before it reaches
 * the renderer: provenance (actor/session/connector-source ids) collapses to
 * one generic "public" entry, and source-access is emptied. Content, tier,
 * type, confidence, assertion date, and the row's own ULID remain — they are
 * metadata OF the public subset, not beyond it.
 */
export function redactForPublic(obj: MemoryObject): MemoryObject {
  return {
    ...obj,
    provenance: [
      // ts = the row's assertion date, which the renderer already shows;
      // never the original provenance timestamps of intermediate hops.
      { ts: obj.assertionTime, source: "manual", actor: PUBLIC_ACTOR, sourceId: "public" },
    ],
    sourceAccess: { principals: [], groups: [] },
  };
}

// ---------------------------------------------------------------------------
// HTML rendering (string-built, everything escaped, no inline JS)
// ---------------------------------------------------------------------------

function flat(text: string): string {
  return text.replace(/\r?\n/g, " ").trim();
}

function snippet(content: string, max = 200): string {
  const s = flat(content);
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

/** Halofy design language (tokens from console/app.css) + this page's layout. */
const PAGE_CSS = HALO_TOKENS_CSS + [
  "main{max-width:820px;margin:0 auto;padding:clamp(32px,6vw,64px) 20px}",
  ".mast{display:flex;align-items:center;gap:11px;padding-bottom:var(--s5);",
  "border-bottom:1px solid var(--line)}",
  ".mast img{width:30px;height:30px;object-fit:contain}",
  ".mast b{display:block;font-size:15px;font-weight:600;letter-spacing:-.015em}",
  ".mast small{display:block;margin-top:1px;color:var(--muted-2);font-family:var(--font-mono);",
  "font-size:9px;font-weight:500;letter-spacing:.18em;text-transform:uppercase}",
  "h1{margin:var(--s6) 0 var(--s2);font-size:clamp(28px,4vw,38px);letter-spacing:-.03em}",
  "p.meta{margin:0 0 var(--s5);color:var(--muted);font-size:13px}",
  "p.meta a{color:var(--evergreen);text-underline-offset:2px}",
  "ul.entries{list-style:none;padding:0;margin:0;border:1px solid var(--line);",
  "border-radius:var(--r-md);background:var(--panel);box-shadow:var(--sh-1);overflow:hidden}",
  "ul.entries li{padding:14px var(--s4);border-bottom:1px solid var(--line);font-size:14px}",
  "ul.entries li:last-child{border-bottom:0}",
  "span.tag{display:inline-block;margin-right:9px;padding:1px 7px;border:1px solid var(--line);",
  "border-radius:var(--r-pill);background:var(--sage-soft);color:var(--muted-2);",
  "font-family:var(--font-mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase}",
  "span.date{margin-left:8px;color:var(--muted-2);font-family:var(--font-mono);font-size:11px}",
  "footer{margin-top:var(--s6);padding-top:var(--s4);border-top:1px solid var(--line);",
  "color:var(--muted-2);font-size:12px}",
].join("");

function renderPublicPage(
  slug: string,
  orgName: string,
  rows: MemoryObject[],
  generatedAt: string,
): string {
  const shown = rows.slice(0, PAGE_MAX_ENTRIES);
  const items = shown
    .map(
      (obj) =>
        `<li><span class="tag">${escapeHtml(obj.tier)}/${escapeHtml(obj.type)}</span>` +
        `${escapeHtml(snippet(obj.content))}` +
        `<span class="date">${escapeHtml(obj.assertionTime.slice(0, 10))}</span></li>`,
    )
    .join("");
  const more =
    rows.length > shown.length
      ? `<p class="meta">Showing ${shown.length} of ${rows.length} public entries - the full list is in <a href="/${encodeURIComponent(slug)}/llms.txt">llms.txt</a>.</p>`
      : "";
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<link rel="icon" href="/icon.png">` +
    `<title>${escapeHtml(orgName)} - public memory</title>` +
    `<style>${PAGE_CSS}</style></head><body><main>` +
    `<div class="mast">` +
    `<img src="/console/assets/marks/halofy-mark-green.svg" alt="" aria-hidden="true">` +
    `<div><b>Halofy</b><small>Halo Mem</small></div></div>` +
    `<h1>${escapeHtml(orgName)}</h1>` +
    `<p class="meta">Public memory index · ${rows.length} entries · generated ${escapeHtml(generatedAt.slice(0, 10))} · ` +
    `<a href="/${encodeURIComponent(slug)}/llms.txt">llms.txt</a></p>` +
    `<ul class="entries">${items}</ul>` +
    more +
    `<footer>Only content this organization classified as public is listed. Served by Halofy.</footer>` +
    `</main></body></html>`
  );
}

// ---------------------------------------------------------------------------
// Responses (identical 404 body for every not-found flavor — E30)
// ---------------------------------------------------------------------------

/**
 * Failure copy. `llms.txt` is a MACHINE endpoint and keeps its bare text body;
 * the page flavor is a browser destination, so it renders the Halo status page.
 *
 * E30 anti-fingerprinting is preserved because the body depends only on the
 * requested FORMAT and the status — never on WHY the request failed. Unknown
 * slug, suspended tenant, and zero-public-rows still return byte-identical
 * responses to each other within a flavor, and the page copy names no org.
 */
type FailureKind = "not_found" | "rate_limited" | "error";

const FAILURE_TEXT: Record<FailureKind, { status: number; body: string }> = {
  not_found: { status: 404, body: "Not found.\n" },
  rate_limited: { status: 429, body: "Too many requests.\n" },
  error: { status: 500, body: "Internal error.\n" },
};

const FAILURE_PAGE_COPY: Record<
  FailureKind,
  { eyebrow: string; heading: string; message: string; tone: "alert" | "notice" }
> = {
  not_found: {
    eyebrow: "Not found",
    heading: "No public memory here",
    message: "This address has no published memory index.",
    tone: "notice",
  },
  rate_limited: {
    eyebrow: "Rate limited",
    heading: "Too many requests",
    message: "This page is being requested too quickly. Try again in a minute.",
    tone: "notice",
  },
  error: {
    eyebrow: "Server error",
    heading: "Something went wrong",
    message: "This page couldn’t be rendered. Try again in a moment.",
    tone: "alert",
  },
};

/** Build the failure response for a flavor — bodies are per-flavor constants. */
function failure(
  format: PublicDiscoveryFormat,
  kind: FailureKind,
): PublicDiscoveryResponse {
  const text = FAILURE_TEXT[kind];
  if (format === "llms") {
    return { status: text.status, contentType: "text/plain; charset=utf-8", body: text.body };
  }
  const copy = FAILURE_PAGE_COPY[kind];
  return {
    status: text.status,
    contentType: "text/html; charset=utf-8",
    body: renderHaloStatusPage({
      title: `${copy.heading} - Halofy`,
      eyebrow: copy.eyebrow,
      heading: copy.heading,
      messages: [copy.message],
      tone: copy.tone,
    }),
  };
}

// ---------------------------------------------------------------------------
// Audit (D4 — every outcome writes a row)
// ---------------------------------------------------------------------------

function discoveryEvent(
  slug: string,
  result: AuditEvent["result"],
  detail: string,
): AuditEvent {
  return {
    ts: new Date().toISOString(),
    actor: PUBLIC_ACTOR,
    agentId: PUBLIC_ACTOR,
    op: "read",
    memoryId: null,
    // The requested slug IS the (candidate) tenant root namespace; for an
    // unknown slug this records what was probed.
    namespace: slug,
    purpose: PURPOSE,
    result,
    detail: detail.slice(0, 500),
  };
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

/**
 * Serve one public-discovery request. Never throws: every outcome (ok /
 * denied / error) is audited and mapped to a transport-ready response.
 */
export async function servePublicDiscovery(
  deps: PublicDiscoveryDeps,
  orgSlug: string,
  format: PublicDiscoveryFormat,
): Promise<PublicDiscoveryResponse> {
  try {
    if (deps.rateLimiter) {
      const ok = await deps.rateLimiter.allow(
        `public-discovery:${orgSlug}`,
        PUBLIC_DISCOVERY_RATE_LIMIT_PER_MIN,
      );
      if (!ok) {
        await deps.audit.append(
          discoveryEvent(orgSlug, "denied", "rate limit exceeded"),
        );
        return failure(format, "rate_limited");
      }
    }

    // E28: slug → tenant root namespace, resolved server-side by exact,
    // parameterized lookup in the tenant registry. No fuzzy matching, no LIKE.
    const tenant = await deps.tenants.get(orgSlug);
    if (tenant === null || tenant.status !== "active") {
      await deps.audit.append(
        discoveryEvent(
          orgSlug,
          "denied",
          tenant === null ? "unknown org slug" : "tenant not active",
        ),
      );
      return failure(format, "not_found");
    }
    const root: Namespace = tenant.id;

    // E29: same fence stack as the badge manifest, then the public filter.
    // No access subject → rows with ANY source-native grant are excluded in
    // SQL; includePointers stays false; validOnly keeps D7 supersedence.
    const visible = await deps.index.listCandidates(root, {
      validOnly: true,
      limit: ALL_ROWS,
      includePointers: false,
    });
    const rows = visible.filter((obj) => isPublicRow(obj, root));

    if (rows.length === 0) {
      // E30 anti-fingerprinting: indistinguishable from an unknown slug.
      await deps.audit.append(
        discoveryEvent(orgSlug, "denied", "no public-classified content"),
      );
      return failure(format, "not_found");
    }

    const redacted = rows.map(redactForPublic);
    const generatedAt = new Date().toISOString();

    let response: PublicDiscoveryResponse;
    if (format === "llms") {
      const { markdown, renderedCount, truncated } = renderManifestMarkdown(
        root,
        redacted,
        "index",
        DEFAULT_MANIFEST_MAX_BYTES,
        generatedAt,
        {
          title: `# ${flat(tenant.name)} - public memory index`,
          description:
            `> Public tier: only content this organization classified as ` +
            `public is listed. Generated ${generatedAt}. ` +
            `${redacted.length} entries.`,
        },
      );
      await deps.audit.append(
        discoveryEvent(
          orgSlug,
          "ok",
          `llms.txt entries=${redacted.length} rendered=${renderedCount} truncated=${truncated}`,
        ),
      );
      response = {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: markdown,
      };
    } else {
      const html = renderPublicPage(orgSlug, tenant.name, redacted, generatedAt);
      await deps.audit.append(
        discoveryEvent(orgSlug, "ok", `page entries=${redacted.length}`),
      );
      response = {
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: html,
      };
    }
    return response;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      await deps.audit.append(discoveryEvent(orgSlug, "error", message));
    } catch {
      // Audit persistence failed on an unauthenticated read — nothing more
      // to do transport-side; the generic 500 leaks nothing either way.
    }
    return failure(format, "error");
  }
}
