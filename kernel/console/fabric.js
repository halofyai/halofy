/**
 * Context Fabric - the platform's sign-in / boot animation.
 *
 * One woven field of threads pinched through a single node: the "converge"
 * specimen the marketing site draws for Context Fabric (CF-01 in
 * websitev2 src/components/contextfabric/CFLiquidArt.tsx), ported here with no
 * build step and no dependencies so the console and the site draw the same
 * object. The geometry below is that component's, unchanged - thread count,
 * spacing, pinch drift, per-thread width and opacity.
 *
 * Why it is the sign-in screen: every source a tenant connects is a thread, and
 * signing in is the moment they resolve to one identity. The light packets
 * travel from both edges and are only visible near the waist, so the motion
 * reads as convergence on the core rather than traffic passing through.
 *
 * Two consumers:
 *   - login.html and chat.html mount it declaratively through [data-fabric]
 *     (auto-mount at the bottom), which keeps login.html's single inline script
 *     for the auth flow only.
 *   - app.js calls fabricMarkup() for the chat surface's route-pending state.
 *
 * All motion lives in app.css (.fabric-*), which is what puts it under the
 * app-wide prefers-reduced-motion rule instead of a private copy of one.
 */

/** Site parity: 35 threads, the 18th (index 17) is the waist. */
const THREADS = 35;
const WAIST = 17;

/** Distinct gradient ids per instance - two fabrics can share one page. */
let seq = 0;

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * The thread family, in the site's 640x420 view box. Each thread runs edge to
 * edge and is drawn toward the pinch (~x=316..416, y~210) in the middle; the
 * pinch drifts 0.7 per thread so the waist reads as a woven twist, not a knot.
 */
function threads() {
  const out = [];
  for (let i = 0; i < THREADS; i += 1) {
    const y = (72 + i * 8.1).toFixed(1);
    const distance = Math.abs(i - WAIST);
    const pinch = (210 + (i - WAIST) * 0.7).toFixed(1);
    out.push({
      i,
      d:
        `M 44 ${y} C 174 ${y}, 224 ${pinch}, 316 ${pinch} ` +
        `C 416 ${pinch}, 466 ${y}, 596 ${y}`,
      width: distance < 2 ? 1.15 : 0.82,
      opacity: Math.max(0.28, 0.9 - distance * 0.023).toFixed(2),
    });
  }
  return out;
}

/**
 * Inner markup for one fabric: the art, plus a status line when `label` is
 * given. Callers that own their own status node (login.html, whose script
 * rewrites the message as the auth flow moves) pass no label.
 */
export function fabricMarkup(label = "") {
  seq += 1;
  const id = `fab${seq}`;
  const field = threads();

  const weave = field
    .map(
      (t) =>
        `<path class="fabric-thread" style="--i:${t.i}" d="${t.d}" ` +
        `stroke="url(#${id}-thread)" stroke-width="${t.width}" ` +
        `stroke-opacity="${t.opacity}" />`,
    )
    .join("");

  // Odd threads run their packet the other way, so light arrives at the waist
  // from both edges at once.
  const sparks = field
    .map(
      (t) =>
        `<path class="fabric-spark${t.i % 2 ? " fabric-spark--rev" : ""}" ` +
        `style="--i:${t.i}" d="${t.d}" pathLength="1" ` +
        `stroke="url(#${id}-spark)" stroke-width="${(t.width + 0.6).toFixed(2)}" />`,
    )
    .join("");

  const art =
    `<div class="fabric-art" aria-hidden="true">` +
    `<svg viewBox="0 0 640 420" fill="none" xmlns="http://www.w3.org/2000/svg">` +
    `<defs>` +
    `<linearGradient id="${id}-thread" x1="0" y1="0" x2="1" y2="0">` +
    `<stop offset="0" stop-color="#123a2e" stop-opacity=".18" />` +
    `<stop offset=".22" stop-color="#7f9366" stop-opacity=".72" />` +
    `<stop offset=".5" stop-color="#1d4f3f" stop-opacity=".68" />` +
    `<stop offset=".78" stop-color="#7f9366" stop-opacity=".72" />` +
    `<stop offset="1" stop-color="#123a2e" stop-opacity=".18" />` +
    `</linearGradient>` +
    // The packet gradient is the convergence: transparent at both edges, white
    // at the waist, so a travelling dash only shows as it nears the core.
    `<linearGradient id="${id}-spark" x1="0" y1="0" x2="1" y2="0">` +
    `<stop offset="0" stop-color="#c7d7b2" stop-opacity="0" />` +
    `<stop offset=".34" stop-color="#a3b788" stop-opacity=".35" />` +
    `<stop offset=".5" stop-color="#ffffff" stop-opacity=".95" />` +
    `<stop offset=".66" stop-color="#a3b788" stop-opacity=".35" />` +
    `<stop offset="1" stop-color="#c7d7b2" stop-opacity="0" />` +
    `</linearGradient>` +
    `<radialGradient id="${id}-node" cx=".35" cy=".26" r=".9">` +
    `<stop offset="0" stop-color="#ffffff" stop-opacity=".98" />` +
    `<stop offset=".3" stop-color="#e7eddc" stop-opacity=".92" />` +
    `<stop offset=".7" stop-color="#a3b788" stop-opacity=".68" />` +
    `<stop offset="1" stop-color="#123a2e" stop-opacity=".42" />` +
    `</radialGradient>` +
    `<radialGradient id="${id}-halo" cx=".5" cy=".5" r=".5">` +
    `<stop offset="0" stop-color="#e7eddc" stop-opacity=".9" />` +
    `<stop offset=".55" stop-color="#c7d7b2" stop-opacity=".34" />` +
    `<stop offset="1" stop-color="#c7d7b2" stop-opacity="0" />` +
    `</radialGradient>` +
    `</defs>` +
    `<ellipse class="fabric-halo" cx="320" cy="210" rx="120" ry="86" fill="url(#${id}-halo)" />` +
    `<g class="fabric-weave">${weave}</g>` +
    `<g class="fabric-flow">${sparks}</g>` +
    `<circle class="fabric-ring" cx="320" cy="210" r="26" />` +
    `<circle class="fabric-core" cx="320" cy="210" r="15" fill="url(#${id}-node)" />` +
    `</svg>` +
    `</div>`;

  return label ? art + `<p class="fabric-status">${esc(label)}</p>` : art;
}

/** A standalone pending block: the fabric plus an accessible status. */
export function fabricLoader(label = "One moment") {
  return (
    `<div class="fabric fabric--page" role="status" aria-live="polite" aria-busy="true">` +
    fabricMarkup(label) +
    `</div>`
  );
}

/**
 * Paint one declarative mount point. The art is INSERTED, never assigned over
 * the container: the status line a page writes into (login.html) or ships as
 * static copy (chat.html) has to survive the mount, and has to be what the user
 * still sees if this file never loads.
 */
export function mountFabric(el) {
  if (!el || el.dataset.fabricMounted === "1") return;
  el.dataset.fabricMounted = "1";
  el.classList.add("fabric");
  el.insertAdjacentHTML("afterbegin", fabricMarkup());
}

function autoMount() {
  const nodes = document.querySelectorAll("[data-fabric]");
  for (let i = 0; i < nodes.length; i += 1) mountFabric(nodes[i]);
}

// Module scripts are deferred, so the DOM is normally parsed by now; the
// readyState guard covers the case where it is not. A page that never loads
// this file still shows its own status text - the fabric is decoration.
if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", autoMount);
  } else {
    autoMount();
  }
}
