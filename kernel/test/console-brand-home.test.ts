/**
 * Brand → Home. The Halofy orb is a route, not decoration: clicking it opens
 * the Home screen in the rail and in the mobile topbar. The control is guarded
 * by the same
 * `allowedScreens` set as every other nav target so the setup gate cannot be
 * clicked past.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

async function consoleSource() {
  const [html, css, app] = await Promise.all([
    readFile(`${CONSOLE_DIR}/index.html`, "utf8"),
    readFile(`${CONSOLE_DIR}/app.css`, "utf8"),
    readFile(`${CONSOLE_DIR}/app.js`, "utf8"),
  ]);
  return { html, css, app };
}

describe("Halofy brand routes home", () => {
  it("wraps the rail orb in one Home control", async () => {
    const { html } = await consoleSource();

    expect(html).toMatch(
      /<div class="brand">\s*<button\b[\s\S]*?class="brand-home"[\s\S]*?data-brand-home[\s\S]*?type="button"[\s\S]*?<img class="mark"[\s\S]*?<\/button>/,
    );
    // The collapse and mobile-close controls stay OUTSIDE the brand link -
    // nested buttons are invalid, and collapsing the rail is not "go home".
    const railBrand = html.match(/<div class="brand">([\s\S]*?)<\/div>/)?.[1] ?? "";
    const brandLink = railBrand.match(/<button\b[\s\S]*?<\/button>/)?.[0] ?? "";
    expect(brandLink).toContain("data-brand-home");
    expect(brandLink).not.toContain("<b>Halofy</b>");
    expect(brandLink).not.toContain('id="rail-collapse"');
    expect(brandLink).not.toContain('id="mobile-nav-close"');
    expect(railBrand).toContain('id="rail-collapse"');
  });

  it("uses the white rail orb on the dark shell", async () => {
    const { html } = await consoleSource();

    expect(html).toMatch(
      /<img class="mark" src="assets\/marks\/halofy-mark-white\.svg"/,
    );
  });

  it("uses the orb alone in the mobile topbar control", async () => {
    const { html } = await consoleSource();

    expect(html).toMatch(
      /<div class="mobile-brand"[^>]*>\s*<button\b[^>]*class="brand-home"[^>]*data-brand-home[\s\S]*?<img[\s\S]*?<\/button>/,
    );
  });

  it("names the destination for assistive tech on both marks", async () => {
    const { html } = await consoleSource();

    // Exactly two brand controls (rail + topbar), each naming its destination
    // rather than reading out as a bare "Halofy".
    expect(html.match(/data-brand-home/g) ?? []).toHaveLength(2);
    expect(html.match(/aria-label="Halofy - go to Home"/g) ?? []).toHaveLength(2);
  });

  it("routes to the Home screen behind the shared nav guard", async () => {
    const { app } = await consoleSource();

    // Home is the default screen; the brand must not hard-code a second id.
    expect(app).toContain('const DEFAULT_SCREEN = "s2"');
    expect(app).toContain('{ s: "s2", icon: "home", label: "Home" }');
    expect(app).toMatch(
      /\[data-brand-home\][\s\S]*?if \(!allowedScreens\.has\(DEFAULT_SCREEN\)\) return;[\s\S]*?go\(DEFAULT_SCREEN\);/,
    );
    // The rail copy is inside the mobile drawer, so it closes it like a nav
    // button; the topbar copy is not, and must not steal focus to the toggle.
    expect(app).toMatch(
      /if \(inRail\) mobileNavigation\.close\(\{ returnFocus: true \}\);/,
    );
  });

  it("goes inert whenever Home is out of reach", async () => {
    const { app, css } = await consoleSource();

    expect(app).toContain("function paintBrandHome()");
    expect(app).toMatch(/const reachable = allowedScreens\.has\(DEFAULT_SCREEN\);/);
    expect(app).toMatch(/btn\.disabled = !reachable;/);
    // Both renderRail exits repaint it: the waiting view (no nav at all) and
    // the normal/gated rail.
    expect(app.match(/paintBrandHome\(\);/g) ?? []).toHaveLength(2);
    expect(css).toMatch(/\.brand-home:disabled\{[^}]*cursor:default/);
  });

  it("keeps the lockup visually identical to the static brand", async () => {
    const { css } = await consoleSource();

    // `all:unset` so the button contributes no control chrome, then the same
    // flex alignment the .brand div used to provide directly.
    expect(css).toMatch(/\.brand-home\{all:unset;[^}]*display:flex;align-items:center;gap:10px/);
    expect(css).toMatch(/\.brand-home\{[^}]*cursor:pointer/);
    expect(css).toMatch(/\.brand-home:focus-visible\{[^}]*box-shadow/);
    expect(css).toMatch(/\.mobile-brand \.brand-home\{gap:var\(--s2\)\}/);
    // The standalone orb stays prominent at both desktop rail densities.
    expect(css).toMatch(/\.brand \.mark\{[^}]*width:24px;height:24px/);
    expect(css).toMatch(
      /@media\(min-width:861px\) and \(max-width:1400px\)\{[\s\S]*?\.brand \.mark\{width:24px;height:24px\}/,
    );
  });
});
