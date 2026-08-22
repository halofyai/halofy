/**
 * The Halofy design language for server-rendered pages.
 *
 * Everything the kernel renders as HTML for a human — the OAuth consent screen,
 * every OAuth failure page, console static 4xx/5xx, the public memory index —
 * goes through this module so those pages look like the console the user just
 * came from (`console/app.css`), not like a stack trace.
 *
 * Rules this file keeps:
 *
 *  - Self-contained. The CSS is inlined, so a page still renders correctly when
 *    the console static mount is absent or the deployment serves `/oauth/*`
 *    only. The brand mark and the Inter family are progressive enhancement:
 *    both live under `/console/assets/`, and both degrade to the
 *    wordmark / system stack if that mount is missing.
 *  - No inline JS, ever. These pages are served with a `frame-ancestors 'none'`
 *    CSP and are reachable while unauthenticated.
 *  - Every dynamic value is escaped HERE, not by the caller — the status-page
 *    helpers take plain text. `renderHaloFrame` is the one escape hatch that
 *    takes markup, and its callers escape their own interpolations.
 *
 * Token values are copied from `console/app.css` (`NEW Halofy Design System/`
 * tokens): evergreen/mineral/sage/rust and Inter across every text role.
 */

/** HTML-escape a value for text or attribute position. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Design tokens + base element styling. Shared by every Halo-rendered page. */
export const HALO_TOKENS_CSS = [
  `@font-face{font-family:"Inter";`,
  `src:url("/console/assets/fonts/InterVariable.woff2") format("woff2");`,
  `font-weight:100 900;font-style:normal;font-display:swap}`,
  ":root{--evergreen:#123a2e;--evergreen-hover:#0e2f25;--olive:#7f9366;",
  "--sage:#c7d7b2;--sage-soft:#e7eddc;--rust:#e83c00;--slate:#5b6b82;",
  "--ink:#0b0d0b;--mineral:#f3f6ee;--panel:#fbfcf7;--muted:#596455;",
  "--muted-2:#53604f;--line:#d9dfcf;--stone:#e6e6e1;--evergreen-rgb:18 58 46;",
  `--font-sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;`,
  `--font-mono:var(--font-sans);`,
  `--font-cta:var(--font-sans);`,
  "--r-sm:8px;--r-md:12px;--r-lg:16px;--r-xl:20px;--r-pill:999px;",
  "--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;",
  "--sh-1:0 1px 0 rgba(15,24,16,.04);--sh-2:0 8px 22px -16px rgba(15,24,16,.18);",
  "--focus:0 0 0 3px rgb(var(--evergreen-rgb)/16%)}",
  "*{box-sizing:border-box}",
  "body{margin:0;background:var(--mineral);color:var(--ink);font-family:var(--font-sans);",
  "font-size:16px;line-height:1.55;-webkit-font-smoothing:antialiased}",
  "h1,h2,h3{margin:0;font-weight:500;letter-spacing:-.02em;text-wrap:balance}",
  "a{color:var(--evergreen)}",
  "code{font-family:var(--font-mono);font-size:.92em;color:var(--evergreen)}",
  ".eyebrow{font-family:var(--font-mono);font-size:12px;letter-spacing:.16em;",
  "text-transform:uppercase;color:var(--muted-2);font-weight:500}",
  ".eyebrow--alert{color:var(--rust)}",
].join("");

/**
 * A single centered card on the mineral console background. Deliberately NOT
 * the retired split "story rail" frame (evergreen marketing panel + tagline +
 * proof points): that layout imitated an old landing page the product no
 * longer uses, and a 404 dressed as a landing page read as a different
 * product. A status page states what happened and where to go — nothing else.
 */
const HALO_FRAME_CSS = [
  ".halo-shell{min-height:100vh;display:grid;place-items:center;padding:clamp(18px,4vw,52px)}",
  ".halo-card{width:min(480px,100%);padding:clamp(28px,5vw,44px);",
  "border:1px solid var(--line);border-radius:var(--r-lg);background:var(--panel);",
  "box-shadow:var(--sh-1),var(--sh-2)}",
  ".halo-brand{display:flex;align-items:center;gap:10px;margin-bottom:var(--s5)}",
  ".halo-brand img{width:28px;height:28px;object-fit:contain}",
  ".halo-brand b{display:block;font-size:15px;font-weight:600;letter-spacing:-.015em;color:var(--ink)}",
  ".halo-card h1{margin:var(--s3) 0 var(--s2);font-size:26px}",
  ".halo-card p{margin:0 0 var(--s3);color:var(--muted);font-size:14px}",
  ".halo-card p:last-of-type{margin-bottom:0}",
  ".halo-note{margin:var(--s4) 0 0;padding:10px 12px;border:1px solid var(--line);",
  "border-radius:var(--r-sm);background:var(--mineral);color:var(--muted-2);font-size:12.5px}",
  ".halo-list{list-style:none;margin:var(--s4) 0 0;padding:0;border:1px solid var(--line);",
  "border-radius:var(--r-md);background:var(--mineral);overflow:hidden}",
  ".halo-list li{padding:8px 12px;font-size:13px;color:var(--muted-2);border-bottom:1px solid var(--line)}",
  ".halo-list li:last-child{border-bottom:0}",
  ".halo-acts{display:flex;gap:10px;margin-top:var(--s5)}",
  ".btn{all:unset;box-sizing:border-box;flex:1;font-family:var(--font-cta);font-weight:500;font-size:14px;",
  "cursor:pointer;min-height:42px;padding:8px 15px;border:1px solid transparent;border-radius:var(--r-pill);",
  "display:inline-flex;align-items:center;justify-content:center;gap:7px;text-align:center;",
  "transition:background .12s,border-color .12s,box-shadow .12s}",
  ".btn:active{transform:translateY(1px)}",
  ".btn:focus-visible{box-shadow:var(--focus)}",
  ".btn--solid{background:var(--evergreen);color:var(--mineral)}",
  ".btn--solid:hover{background:var(--evergreen-hover)}",
  ".btn--outline{border-color:rgb(var(--evergreen-rgb)/28%);color:var(--evergreen);background:transparent}",
  ".btn--outline:hover{background:var(--sage-soft)}",
  ".halo-foot{margin-top:var(--s5);color:var(--muted-2);font-family:var(--font-mono);font-size:10px;",
  "letter-spacing:.16em;text-transform:uppercase}",
  "@media(max-width:560px){.halo-shell{display:block;padding:0;background:var(--panel)}",
  ".halo-card{min-height:100vh;border:0;border-radius:0;box-shadow:none;padding:32px var(--s5) 40px}",
  ".halo-acts{flex-direction:column}}",
].join("");

/** Brand row: the green mark and wordmark, same assets as the console. */
const BRAND_ROW =
  `<div class="halo-brand">` +
  `<img src="/console/assets/marks/halofy-mark-green.png" alt="" aria-hidden="true">` +
  `<b>Halofy</b></div>`;

/**
 * Wrap already-escaped panel markup in the full Halo document (one centered
 * card). Callers own the escaping of anything they interpolate.
 */
export function renderHaloFrame(title: string, panelInner: string): string {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<link rel="icon" href="/icon.png">` +
    `<title>${escapeHtml(title)}</title>` +
    `<style>${HALO_TOKENS_CSS}${HALO_FRAME_CSS}</style></head>` +
    `<body><main class="halo-shell"><div class="halo-card">` +
    BRAND_ROW +
    panelInner +
    `<div class="halo-foot">Halofy · organizational memory</div>` +
    `</div></main></body></html>`
  );
}

export interface HaloStatusPage {
  /** Document title (browser tab). */
  title: string;
  /** Mono eyebrow above the heading, e.g. "Connection error". */
  eyebrow: string;
  /** Headline, e.g. "Can’t continue". */
  heading: string;
  /** Body paragraphs, plain text — escaped here. */
  messages: readonly string[];
  /** `alert` paints the eyebrow rust; `notice` keeps it muted. */
  tone?: "alert" | "notice";
  /** Optional single link action rendered as the primary CTA. */
  action?: { href: string; label: string };
}

/**
 * The one error/notice page shape. Every failure a human can land on renders
 * through here so they all read as one product.
 */
export function renderHaloStatusPage(page: HaloStatusPage): string {
  const toneClass = page.tone === "notice" ? "eyebrow" : "eyebrow eyebrow--alert";
  const paragraphs = page.messages
    .map((line) => `<p>${escapeHtml(line)}</p>`)
    .join("");
  const action =
    page.action === undefined
      ? ""
      : `<div class="halo-acts"><a class="btn btn--solid" href="${escapeHtml(page.action.href)}">` +
        `${escapeHtml(page.action.label)}</a></div>`;
  return renderHaloFrame(
    page.title,
    `<div class="${toneClass}">${escapeHtml(page.eyebrow)}</div>` +
      `<h1>${escapeHtml(page.heading)}</h1>` +
      paragraphs +
      action,
  );
}
