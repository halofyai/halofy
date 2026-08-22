import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const appPath = fileURLToPath(new URL("../console/app.js", import.meta.url));
const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));
const indexPath = fileURLToPath(new URL("../console/index.html", import.meta.url));

describe("console route loading treatment", () => {
  it("shows the skeleton pending state during boot and every screen transition", async () => {
    const [app, index] = await Promise.all([
      readFile(appPath, "utf8"),
      readFile(indexPath, "utf8"),
    ]);

    expect(app).toContain('loading(label = "Loading page")');
    expect(app).toContain("stage.innerHTML = ui.loading();");
    expect(app).not.toContain('<div class="sub">Loading&hellip;</div>');
    expect(index).toContain('class="page-loader" role="status" aria-live="polite" aria-busy="true"');
    expect(index).toContain('class="sr-only">Loading workspace</span>');
    expect(index).toContain('class="page-skeleton" aria-hidden="true"');
    expect(index).toContain('class="page-skeleton__stats"');
    expect(index).toContain('class="page-skeleton__card"');
  });

  it("renders skeleton placeholders with a shimmer and a reduced-motion fallback", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.skel\{[^}]*background:var\(--stone\)/);
    expect(css).toMatch(/\.skel\{[^}]*overflow:hidden/);
    expect(css).toMatch(
      /\.skel::after\{[^}]*background:linear-gradient\(90deg,transparent,rgb\(255 255 255\/65%\),transparent\)/,
    );
    expect(css).toContain("@keyframes skel-shimmer");
    expect(css).toMatch(/@media\(prefers-reduced-motion:reduce\)\{[\s\S]*?\.skel::after\{animation:none!important/);
  });

  it("preloads the initial screen with identity, keeps denied directory reads off the member path, and hydrates notifications after the page", async () => {
    const app = await readFile(appPath, "utf8");

    expect(app).toContain("preloadScreenModule(initialScreenId)");
    expect(app).toContain('if (SURFACE === "console" && gateMode !== null)');
    expect(app).toContain("void preloadScreenModule(SETUP_SCREEN)");
    expect(app).toContain('ctx.initialSetupChecklist = api.get("/v1/admin/setup-checklist")');
    expect(app).toContain('const meRequest = api.get("/auth/me");');
    expect(app).toContain("const peopleDirectoryRequest = canLoadPeopleDirectory(ctx.identity)");
    expect(app).toContain("initialRefresh: false");
    expect(app).toContain("notificationCenter?.syncAccess({ refresh: initialScreenLoaded });");

    const meRequest = app.indexOf('const meRequest = api.get("/auth/me");');
    const awaitIdentity = app.indexOf("me = await meRequest;");
    const peopleHydration = app.indexOf(
      "const peopleDirectoryRequest = canLoadPeopleDirectory(ctx.identity)",
    );
    expect(meRequest).toBeGreaterThan(-1);
    expect(meRequest).toBeLessThan(awaitIdentity);
    expect(peopleHydration).toBeGreaterThan(awaitIdentity);

    const screenPaint = app.indexOf("stage.innerHTML = html;");
    const pageReady = app.indexOf("finishInitialScreenLoad();", screenPaint);
    expect(screenPaint).toBeGreaterThan(-1);
    expect(pageReady).toBeGreaterThan(screenPaint);

    const finishStart = app.indexOf("function finishInitialScreenLoad");
    const finishEnd = app.indexOf("\n}", finishStart);
    const finishBody = app.slice(finishStart, finishEnd);
    expect(finishBody).toContain("initialScreenLoaded = true;");
    expect(finishBody).toContain("notificationCenter?.syncAccess();");
  });
});
