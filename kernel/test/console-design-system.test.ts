import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));
const appPath = fileURLToPath(new URL("../console/app.js", import.meta.url));
const indexPath = fileURLToPath(new URL("../console/index.html", import.meta.url));
const loginPath = fileURLToPath(new URL("../console/login.html", import.meta.url));
const memoryScreenPath = fileURLToPath(new URL("../console/screens/s5.js", import.meta.url));
const conflictsScreenPath = fileURLToPath(new URL("../console/screens/s11.js", import.meta.url));
const shellPath = fileURLToPath(new URL("../console/index.html", import.meta.url));
const sourcesScreenPath = fileURLToPath(new URL("../console/screens/s6.js", import.meta.url));
const skillsScreenPath = fileURLToPath(new URL("../console/screens/s16.js", import.meta.url));
const metricCardPath = fileURLToPath(new URL("../console/metric-card.js", import.meta.url));
const flowScreenPaths = ["s2", "s4", "s6", "s14", "s16"].map((screen) =>
  fileURLToPath(new URL(`../console/screens/${screen}.js`, import.meta.url)),
);

describe("console shared visual system", () => {
  it("renders shared status pills as plain colored text in the authored case", async () => {
    const css = await readFile(cssPath, "utf8");
    const plainStatusRule = css.lastIndexOf("html body .pill{");

    expect(plainStatusRule).toBeGreaterThan(css.lastIndexOf('body[data-console-screen="s15"] #usage-trace-panel .pill{'));
    expect(css.slice(plainStatusRule)).toMatch(/html body \.pill\{[^}]*padding:0!important;[^}]*border:0!important;[^}]*border-radius:0!important;[^}]*background:transparent!important;[^}]*box-shadow:none!important/);
    expect(css.slice(plainStatusRule)).toMatch(/html body \.pill\{[^}]*letter-spacing:0!important;[^}]*text-transform:none!important/);
    expect(css.slice(plainStatusRule)).toContain("html body .pill .dot{display:none!important}");
    expect(css.slice(plainStatusRule)).toMatch(/html body button\.pill\{[^}]*min-height:32px!important;[^}]*padding-block:6px!important;[^}]*text-decoration:underline/);
  });

  it("binds the shared metric-card DOM to compact Halofy card styles", async () => {
    const [css, metricCard] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(metricCardPath, "utf8"),
    ]);

    for (const className of [
      "metric-card",
      "metric-card-head",
      "metric-card-label",
      "metric-card-icon",
      "metric-card-shell",
    ]) {
      expect(metricCard).toContain(`class="${className}`);
      expect(css).toContain(`.${className}`);
    }

    expect(css).toMatch(/\.metric-card\{[^}]*display:flex[^}]*flex-direction:column/);
    expect(css).toMatch(/\.metric-card-icon svg\{width:18px;height:18px\}/);
    expect(css).toMatch(/\.home-metrics \.metric-card\{[^}]*border:1px solid var\(--home-border\)[^}]*background:var\(--home-panel\)/);
    expect(css).toMatch(/\.home-metrics \.metric-card-icon svg\{width:14px;height:14px\}/);
    expect(css).toMatch(/\.home-overview\{[^}]*--home-canvas:var\(--surface-soft\)[^}]*--home-panel:var\(--panel\)[^}]*font-family:var\(--font-body\)/);
    expect(css).toMatch(
      /\.home-overview \.home-metrics \.metric-card \.k\{[^}]*letter-spacing:0[^}]*text-transform:none/,
    );
  });

  it("uses white for shared canvas, panel, and nested surfaces", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toContain("--canvas:#fff");
    expect(css).toContain("--panel:#fff");
    expect(css).not.toContain("--panel:#fbfcf7");
    expect(css).toContain("--surface-soft:#fff");
    expect(css).toContain("--mineral:#f3f6ee");
    expect(css).toContain("--line:#d9dfcf");
    expect(css).toContain("--sage:#c7d7b2");
    expect(css).toMatch(/body\{[^}]*background:var\(--canvas\)/);
    expect(css).toMatch(/\.card\{background:var\(--panel\)/);
    expect(css).toMatch(/\.skill-risk-card\{[^}]*background:var\(--panel\)/);
    expect(css).toMatch(/\.skill-table thead th\{[^}]*background:var\(--surface-soft\)/);
    expect(css).toMatch(/\.workspace-bar\{[^}]*background:var\(--dl-rail-metal\)[^}]*background-color:var\(--dl-rail\)[^}]*border-bottom:1px solid rgb\(255 255 255\/16%\)/);
    expect(css).not.toMatch(/\.workspace-bar\{[^}]*backdrop-filter/);
    expect(css).toMatch(/\.stage\{[^}]*background:var\(--dl-page\)/);
    expect(css).toMatch(/\.mobile-topbar\{[^}]*background:rgb\(255 255 255\/94%\)/);
    expect(css).not.toContain("LoopAI-adjacent");
  });

  it("constrains identity photos to every shared avatar frame", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.railfoot \.av\{[^}]*position:relative[^}]*overflow:hidden/);
    expect(css).toMatch(/\.workspace-account-trigger \.av\{[^}]*position:relative[^}]*overflow:hidden/);
    expect(css).toMatch(/\.identity-av-image\{[^}]*position:absolute[^}]*inset:0[^}]*width:100%[^}]*height:100%[^}]*object-fit:cover/);
    expect(css).toContain(".identity-av-image[hidden]{display:none}");
    expect(css).toMatch(/\.home-avatar\{[^}]*position:relative[^}]*overflow:hidden/);
    expect(css).toMatch(/\.home-avatar__image\{[^}]*position:absolute[^}]*inset:0[^}]*width:100%[^}]*height:100%[^}]*object-fit:cover/);
    expect(css).toContain(".home-avatar__image[hidden]{display:none}");
  });

  it("aligns the uploaded organization mark with the workspace name without cropping it", async () => {
    const [css, shell, app] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(indexPath, "utf8"),
      readFile(appPath, "utf8"),
    ]);

    expect(shell).toContain('id="workspace-org-mark"');
    expect(app).toContain("paintOrganizationMark(mark, label, currentOrganizationIcon)");
    expect(css).toMatch(/\.workspace-org-mark\{[^}]*width:20px[^}]*height:20px[^}]*overflow:hidden/);
    expect(css).toMatch(/\.workspace-org-mark img\{[^}]*width:100%[^}]*height:100%[^}]*object-fit:contain/);
  });

  it("uses the Halofy readable type scale across shared primitives", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toContain("--text-body-size:16px");
    expect(css).toContain("--text-small:13px");
    expect(css).toContain("--text-label:12px");
    expect(css).toContain("--text-h1:34px");
    expect(css).toContain("--text-h2:24px");
    expect(css).toMatch(/body\{[^}]*font-size:var\(--text-body-size\)/);
    expect(css).toMatch(/\.head h1\{font-size:var\(--text-h1\)/);
    expect(css).not.toMatch(/\.head h1\{[^}]*font-size:28px/);
    expect(css).toMatch(/\.card \.sub\{[^}]*font-size:var\(--section-subtitle-size\)/);
    expect(css).toMatch(/\.stat \.k\{[^}]*font-size:var\(--text-label\)/);
    expect(css).toMatch(/\.field label\{[^}]*font-size:var\(--text-label\)/);
    expect(css).toMatch(/\.input,\.select\{[^}]*font-size:14px/);
  });

  it("keeps the layout roomy on desktop and readable on small screens", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(
      /\.stage\{[^}]*width:100%[^}]*max-width:none[^}]*margin:0[^}]*background:var\(--dl-page\)/,
    );
    expect(css).toMatch(/\n  #screen-content\{[^}]*max-width:1184px[^}]*margin-inline:auto/);
    expect(css).not.toMatch(
      /body\[data-console-screen\]:not\(\[data-console-screen="s1"\]\):not\(\[data-console-screen="s2"\]\) \.stage\{[^}]*max-width:/,
    );
    expect(css).toContain("@media(max-width:1180px){.g4{grid-template-columns:repeat(2,1fr)}");
    expect(css).toContain("@media(max-width:640px){.g4{grid-template-columns:1fr}");
    expect(css).toMatch(/@media\(max-width:860px\)[\s\S]*?\.head\{[^}]*align-items:flex-start/);
    expect(css).toMatch(/@media\(max-width:860px\)[\s\S]*?\.mobile-nav-toggle\{[^}]*min-height:44px/);
    expect(css).toMatch(/@media\(max-width:860px\)[\s\S]*?\.navgroup,\.nav button,\.rail-help__action,\.breadcrumbs button,\.btn,\.btn--sm,\.policy-screen \.btn,[^}]*min-height:44px/);
    expect(css).toMatch(/\.breadcrumbs button\{[^}]*min-width:44px/);
    expect(css).toMatch(/\.source-category-tab,\.source-card-action,[\s\S]*?\.toggle\{min-height:44px/);
    expect(css).toMatch(/\.copilot-send,\.copilot-clear,\.skill-expand\{min-width:44px/);
    // The measured column lives on the board; the stage is full width so S10's
    // `.head` starts at the same x as every other screen's title.
    expect(css).toMatch(/\.copilot-board\{[^}]*max-width:1180px/);
    // Two columns, one row: history rail + conversation share the full height
    // of the card. The activity inspector is a separate section below the
    // card, so the transcript is never truncated and the page scrolls to it.
    expect(css).toMatch(/\.copilot-workbench\{[^}]*grid-template-columns:minmax\(204px,236px\) minmax\(0,1fr\)[^}]*grid-template-rows:minmax\(0,1fr\)[^}]*height:min\([^}]*overflow:hidden/);
    expect(css).toMatch(/\.copilot-history\{grid-column:1;grid-row:1;/);
    expect(css).toMatch(/\.copilot-chat-shell\{grid-column:2;grid-row:1;[^}]*min-height:0[^}]*overflow:hidden/);
    expect(css).toMatch(/\.copilot-transcript\{[^}]*min-height:0[^}]*overflow-y:auto/);
    expect(css).toMatch(/\.copilot-composer\{[^}]*flex:none[^}]*border-top:1px solid var\(--line\)/);
    expect(css).toMatch(/\.copilot-inspector\{display:flex[^}]*border:1px solid var\(--line\)[^}]*border-radius/);
    expect(css).toMatch(/\.copilot-panels\{[^}]*grid-template-columns:minmax\(0,1fr\)/);
    expect(css).toMatch(/\.copilot-thread \.chat-msg\{[^}]*max-width:min\(92%,880px\)/);
    expect(css).toMatch(/\.copilot-thread \.chat-bubble\{[^}]*max-width:78ch/);
    expect(css).toMatch(/\.copilot-thread \.chat-bubble\{[^}]*min-width:0/);
    expect(css).toMatch(/\.chat-line\{[^}]*overflow-wrap:anywhere/);
    expect(css).toMatch(/\.chat-visualization\{[^}]*max-width:100%/);
    expect(css).toMatch(/\.chat-chart-meter\{[^}]*width:100%/);
    expect(css).toMatch(/\.chat-table-wrap\{[^}]*overflow-x:auto/);
    const mobileFloor = css.indexOf("/* Mobile target floor stays last");
    expect(mobileFloor).toBeGreaterThan(css.lastIndexOf(".source-wizard-close{"));
    expect(mobileFloor).toBeGreaterThan(css.lastIndexOf(".policy-upload-button{"));
    expect(mobileFloor).toBeGreaterThan(css.lastIndexOf(".google-signin{"));
  });

  it("draws every dropdown with one Halo treatment, closed and open", async () => {
    const [css, ...screens] = await Promise.all([
      readFile(cssPath, "utf8"),
      ...[
        "s1", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s11", "s13", "s16",
        "policy-library",
      ].map((screen) =>
        readFile(fileURLToPath(new URL(`../console/screens/${screen}.js`, import.meta.url)), "utf8"),
      ),
    ]);

    // Closed control: native chrome off, one shared chevron token.
    expect(css).toContain("--select-chevron:var(--chevron-ink)");
    expect(css).toMatch(
      /\.select,select\.input,\.copilot-history-view,\.copilot-model-select\{[^}]*appearance:none[^}]*background-image:var\(--select-chevron\)/,
    );
    // No dark-surface exception is left: S4's intake panel was the only one,
    // and it is now the prototype's light drawer. If a dark surface returns,
    // it swaps --select-chevron rather than redefining the chevron geometry.
    expect(css).not.toContain("--select-chevron:var(--chevron-light)");
    // Open picker: styled where the browser can draw it, native list otherwise.
    expect(css).toContain("@supports (appearance:base-select){");
    expect(css).toMatch(/select\.select,select\.input,select\.copilot-history-view,select\.copilot-model-select\{[^}]*appearance:base-select/);
    expect(css).toMatch(/\.select::picker\(select\),[\s\S]*?background:var\(--dl-page\)/);
    expect(css).toMatch(/\.select option,[\s\S]*?border-radius:var\(--r-xs\)/);
    // Custom menus use that same neutral inset rather than the green-tinted
    // panel surface, including the account menu visible on every screen.
    expect(css).toMatch(
      /:is\(\.workspace-account-menu,[^}]*\.home-query-filter-menu,[^}]*\.memory-scope-menu,[^}]*\.copilot-message-menu,[^}]*\.copilot-model-popover,[^}]*\.teams-selector__panel,[^}]*\.usage-filter-pop,[^}]*\.skill-filter-panel\)\{[^}]*background:var\(--dl-page\)/,
    );
    expect(css).toMatch(/body\[data-console-screen\] #screen-content select:is\(\.select,\.input,\.copilot-history-view\):not\(\.head \*,\.home-head \*\)\{[^}]*background-color:var\(--dl-page\)/);
    expect(css).toMatch(/\.teams-selector__panel :where\([^}]*\.teams-selector__option\)\{background:transparent\}/);
    // Every screen-level dropdown opts into that treatment.
    for (const screen of screens) {
      for (const tag of screen.match(/<select[^>]*/g) ?? []) {
        expect(tag).toMatch(/class="(select|input)\b|class="copilot-(history-view|model-select)"/);
      }
    }
  });

  it("keeps account controls visible while long navigation scrolls", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.brand b\{[^}]*line-height:16px/);
    expect(css).toMatch(/\.rail\{[^}]*height:100vh[^}]*overflow:hidden/);
    expect(css).toMatch(/#rail-nav\{[^}]*flex:1[^}]*min-height:0[^}]*overflow-y:auto/);
    expect(css).toMatch(/#rail-nav\{[^}]*overflow-x:hidden/);
    expect(css).toMatch(/\.railfoot\{[^}]*flex:none/);
  });

  it("renders collapsed-rail tooltips above clipping layers and inside the viewport", async () => {
    const [css, app, shell] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(appPath, "utf8"),
      readFile(indexPath, "utf8"),
    ]);

    expect(shell).toContain('id="rail-collapse"');
    expect(shell).toContain('data-tip="Expand navigation"');
    expect(shell).toContain('aria-label="Documentation (opens in a new tab)"');
    expect(shell).toContain('aria-label="Support (opens in a new tab)"');
    expect(app).toContain('function wireRailTooltip(rail)');
    expect(app).toContain('document.body.append(tooltip)');
    expect(app).toContain('rail.addEventListener("pointerover"');
    expect(app).toContain('rail.addEventListener("focusin"');
    expect(app).toContain('Math.max(targetRect.right, railRect.right) + targetGap');
    expect(app).toContain('window.innerWidth - tooltipRect.width - edgeGap');
    expect(app).toContain('window.innerHeight - tooltipRect.height - edgeGap');
    expect(app).toContain('aria-label="${grp.group}"');
    expect(app).toContain('class="locked" data-tip="${item.label}"');
    expect(css).toMatch(/\.rail-tooltip\{[^}]*position:fixed[^}]*z-index:90[^}]*pointer-events:none/);
    expect(css).toMatch(/\.rail-tooltip\[data-open="true"\]\{[^}]*opacity:1[^}]*visibility:visible/);
    expect(css).not.toContain('body.rail-collapsed .rail [data-tip]::after');
  });

  it("renders a static Halofy help card with documentation and support actions", async () => {
    const [css, shell] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(indexPath, "utf8"),
    ]);

    expect(shell).toContain('class="rail-help"');
    expect(shell).toContain('id="rail-help-title">Need help?</h2>');
    expect(shell).toMatch(
      /href="https:\/\/halofy\.ai\/usecases#general-faqs"[\s\S]*?>Documentation<\/span>/,
    );
    expect(shell).toMatch(/href="https:\/\/github\.com\/halofyai\/halofy\/discussions"[\s\S]*?>Support<\/span>/);
    expect(css).toMatch(
      /\.rail-help\{[^}]*color:var\(--mineral\)[^}]*url\("assets\/footer-planet\.webp"\)/,
    );
    expect(css).not.toMatch(/\.rail-help\{[^}]*var\(--dl-shell-control\)/);
    expect(css).toMatch(/body\.rail-collapsed \.rail-help__copy\{display:none\}/);
    expect(css).toMatch(/@media\(max-width:860px\)\{[\s\S]*?\.nav button,\.rail-help__action,[\s\S]*?min-height:44px/);
  });

  it("uses a compact enterprise shell with top-right identity and a non-scrolling desktop rail", async () => {
    const [css, shell, app] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(indexPath, "utf8"),
      readFile(appPath, "utf8"),
    ]);

    expect(shell).toContain('class="workspace-bar"');
    expect(app).toContain("paintWorkspaceBrand");
    expect(app).toContain("void paintWorkspaceBrand()");
    expect(shell).not.toContain('id="orgpick"');
    expect(shell).not.toContain('id="org-name"');
    expect(shell).toContain('class="workspace-search"');
    const workspaceBar = shell.slice(shell.indexOf('class="workspace-bar"'), shell.indexOf("</header>", shell.indexOf('class="workspace-bar"')));
    expect(workspaceBar).not.toContain(">Organization</span>");
    expect(shell).toMatch(/<div class="workspace-account"[^>]*data-workspace-account[\s\S]*?id="workspace-av"/);
    expect(shell).toContain('class="workspace-account-trigger"');
    expect(shell).toContain('class="workspace-account-copy"');
    expect(shell).toContain('id="workspace-trigger-who"');
    expect(shell).toContain('id="workspace-trigger-role"');
    expect(shell).toContain('aria-haspopup="menu"');
    expect(shell).toContain('aria-controls="workspace-account-menu"');
    expect(shell).toContain('id="workspace-account-menu" role="menu" hidden');
    expect(shell).toContain('data-account-profile role="menuitem"');
    expect(shell).toMatch(/id="workspace-account-menu"[\s\S]*?data-logout role="menuitem"/);
    expect(shell).not.toContain('class="workspace-signout"');
    expect(css).toMatch(/\.workspace-bar\{[^}]*position:sticky[^}]*top:0/);
    expect(css).toMatch(/\.workspace-bar\{[^}]*padding:0 var\(--s7\)/);
    expect(css).toMatch(/\.workspace-context\{[^}]*grid-column:1/);
    expect(css).toMatch(/\.workspace-search\{[^}]*grid-column:2[^}]*width:50%[^}]*min-width:180px[^}]*justify-self:center/);
    expect(css).toMatch(/\.workspace-search\{[^}]*background:#fff[^}]*border:1px solid var\(--dl-shell-control-line\)/);
    expect(css).toMatch(/\.workspace-account\{[^}]*grid-column:3[^}]*position:relative[^}]*margin-left:auto[^}]*gap:var\(--s3\)/);
    expect(css).toMatch(/\.workspace-bar\{[^}]*grid-template-columns:minmax\(0,1fr\) minmax\(220px,360px\) minmax\(0,1fr\)/);
    expect(css).toMatch(/\.workspace-account-trigger\{[^}]*width:180px[^}]*max-width:180px[^}]*border:1px solid var\(--dl-shell-control-line\)[^}]*display:flex[^}]*background:var\(--dl-shell-control\)/);
    expect(css).toMatch(/\.workspace-account-trigger \.av\{[^}]*width:30px[^}]*flex:none/);
    expect(css).toMatch(/\.workspace-account-copy\{[^}]*display:grid[^}]*flex:1[^}]*text-align:left/);
    expect(css).toMatch(/@media\(min-width:861px\) and \(max-width:1400px\)[\s\S]*?\.workspace-account-trigger\{width:160px;max-width:160px/);
    expect(css).toMatch(/\.workspace-account-menu\{[^}]*position:absolute[^}]*right:0/);
    expect(css).toMatch(/\.workspace-account-menu\[hidden\]\{display:none/);
    expect(app).toContain("function wireWorkspaceAccountMenu()");
    expect(app).toContain('document.getElementById("workspace-trigger-who")');
    expect(app).toContain('document.getElementById("workspace-trigger-role")');
    expect(app).toContain('workspaceTriggerRole.textContent = identity.role || ""');
    expect(app).toContain('workspaceTrigger.setAttribute("aria-label", "Open account menu for " + accountLabel)');
    expect(app).toContain('go("s18?tab=profile")');
    expect(app).toContain('document.getElementById("settings-tab-profile")');
    expect(css).toMatch(/\.nav button\{all:unset;box-sizing:border-box/);
    expect(css).toMatch(/\.home-dashboard\{[^}]*align-items:stretch/);
    expect(css).toMatch(/\.home-metrics\{[^}]*grid-template-columns:repeat\(5,minmax\(0,1fr\)\)[^}]*gap:var\(--s3\)[^}]*background:transparent/);
    expect(css).toMatch(/\.home-metrics \.metric-card\{[^}]*display:flex[^}]*flex-direction:column[^}]*border:1px solid var\(--line\)[^}]*border-radius:var\(--r-md\)/);
    expect(css).toMatch(/\.metric-card-head\{[^}]*display:flex/);
    expect(css).toMatch(/\.home-metrics \.metric-card-head\{[^}]*justify-content:space-between[^}]*min-height:30px/);
    expect(css).toMatch(/\.home-metrics \.metric-card \.k\{[^}]*font-size:var\(--text-label\)[^}]*font-weight:600/);
    expect(css).toMatch(/\.home-metrics \.metric-card \.k\{[^}]*white-space:normal/);
    expect(css).toMatch(/\.home-metrics \.metric-card-icon\{[^}]*position:absolute[^}]*right:var\(--s4\)[^}]*top:50%[^}]*width:40px[^}]*height:40px/);
    expect(css).toMatch(/\.home-metrics \.metric-card-icon svg\{width:20px;height:20px\}/);
    expect(css).toMatch(/\.home-metrics \.metric-card \.v\{[^}]*padding-right:52px/);
    expect(css).toMatch(/\.home-health-meter\{[^}]*display:grid[^}]*gap:var\(--s2\)/);
    expect(css).toMatch(/\.home-health-track\{[^}]*overflow:hidden[^}]*background:var\(--mineral\)/);
    expect(css).toMatch(/\.home-health-fill\{[^}]*width:var\(--home-health-progress\)[^}]*background:var\(--evergreen\)/);
    expect(css).toMatch(/\.metric-info::after\{[^}]*content:attr\(data-tip\)/);
    expect(css).toMatch(/\.metric-info:hover::after,\.metric-info:focus-visible::after\{[^}]*opacity:1/);
    expect(css).toMatch(/\.home-health-drawer\{[^}]*position:fixed[^}]*inset:0 0 0 auto/);
    expect(css).toMatch(/@media\(min-width:861px\)[\s\S]*?#rail-nav\{[^}]*overflow-y:hidden/);
    expect(css).toMatch(/@media\(min-width:861px\)[\s\S]*?\.navgroup\{[^}]*font-size:11px[^}]*line-height:15px/);
    expect(css).toMatch(/@media\(min-width:861px\)[\s\S]*?\.nav button\{[^}]*min-height:29px[^}]*font-size:13px[^}]*line-height:18px/);
    expect(css).toMatch(/@media\(min-width:861px\)[\s\S]*?\.nav button svg\{width:15px;height:15px/);
    expect(css).toMatch(/@media\(max-height:820px\) and \(min-width:861px\)[\s\S]*?#rail-nav\{[^}]*overflow-y:auto/);
    expect(css).toMatch(/@media\(max-height:820px\) and \(min-width:861px\)[\s\S]*?\.nav button\{[^}]*min-height:25px[^}]*font-size:13px/);
  });

  it("gives pages, related sections, and text stacks one non-additive rhythm", async () => {
    const [css, index, sources, ...flowScreens] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(indexPath, "utf8"),
      readFile(sourcesScreenPath, "utf8"),
      ...flowScreenPaths.map((path) => readFile(path, "utf8")),
    ]);

    expect(index).toContain('id="screen-content" class="screen-flow"');
    expect(css).toContain("--space-section:var(--s5)");
    expect(css).toContain("--space-group:var(--s4)");
    expect(css).toContain("--space-text:var(--s2)");
    expect(css).toMatch(/\.screen-flow\{[^}]*display:grid[^}]*gap:var\(--space-section\)/);
    expect(css).toMatch(/\.screen-flow>\*\{[^}]*min-width:0[^}]*margin-block:0!important/);
    expect(css).not.toMatch(/\.screen-flow>\*\+\*/);
    expect(css).not.toMatch(/\.screen-flow>\.intg-section/);
    expect(css).toMatch(/\.source-screen \[data-source-page-content\]\{[^}]*gap:var\(--space-section\)/);
    expect(css).toMatch(/\.source-category-tabs\{[^}]*margin:0/);
    expect(css).toMatch(/\.source-screen \[data-source-flow-panel\]:not\(\[hidden\]\)\{[^}]*gap:var\(--space-group\)/);
    expect(css).toMatch(/\.head p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.card > h3\{[^}]*margin-bottom:var\(--space-text\)/);
    expect(css).toMatch(
      /\.analytics-method\{[^}]*margin-bottom:var\(--space-group\)/,
    );
    expect(css).toMatch(/\.source-standalone-head p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.kb-manager\{[^}]*gap:var\(--s4\)/);
    expect(css).toMatch(/\.kb-row>td\{[^}]*padding:var\(--s3\) var\(--s4\)/);
    expect(css).toMatch(/\.kb-item\{[^}]*padding:var\(--s2\) var\(--s4\)/);
    expect(css).toMatch(/\.m8a-empty p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.policy-empty p,\.policy-error p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.copilot-hero p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.copilot-inspector-head p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(css).toMatch(/\.intg-library\{[^}]*display:grid[^}]*gap:var\(--s5\)/);
    expect(css).toMatch(/\.skill-section-head p,\.skill-library-head p\{[^}]*margin:var\(--space-text\) 0 0/);
    expect(sources).toContain('data-source-flow-panel="backends"');
    for (const source of flowScreens) {
      expect(source).toMatch(/class="[^"]*\bscreen-flow\b/);
    }
  });

  it("keeps dense platform labels at the 12px readability floor", async () => {
    const [css, memoryScreen] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(memoryScreenPath, "utf8"),
    ]);

    expect(css).toMatch(/\.memory-topology-stage header>span,[\s\S]*?\.memory-topology-bar,[\s\S]*?font-size:var\(--text-label\)/);
    expect(css).toMatch(/\.m8a-assurance span,[\s\S]*?\.m8a-state,[\s\S]*?\.policy-flow\{font-size:var\(--text-label\)/);
    expect(css).toMatch(/\.source-sync-card tbody td::before,[\s\S]*?\.policy-state,\.policy-table td::before,\.source-technical-details code,[\s\S]*?font-size:var\(--text-label\)/);
    expect(memoryScreen).not.toContain('style="font-size:11px"');
  });

  it("uses plain outcome-led labels without changing screen ids", async () => {
    const app = await readFile(appPath, "utf8");

    expect(app).toContain('{ s: "s5", icon: "map", label: "Memory" }');
    expect(app).toContain('{ s: "s6", icon: "src", label: "Sources" }');
    expect(app).toContain('{ s: "s9", icon: "score", label: "Retrieval quality" }');
    expect(app).toContain('{ s: "s13", icon: "teams", label: "Teams" }');
    expect(app).toContain('{ s: "s3", icon: "bot", label: "Scoped memory" }');
    expect(app).toContain('{ s: "s8", icon: "shield", label: "Audit" }');
  });

  it("uses one balanced Halo compact-control treatment across the platform", async () => {
    const [css, shell, login, sources, skills] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(shellPath, "utf8"),
      readFile(loginPath, "utf8"),
      readFile(sourcesScreenPath, "utf8"),
      readFile(skillsScreenPath, "utf8"),
    ]);

    expect(css).toContain("/* Shared Halo compact controls");
    // Rounded square, matching .data-grid-tool: a filter funnel in a card
    // corner and a filter button in a table toolbar are the same control and
    // must not read as two different shapes.
    expect(css).toMatch(/\.halo-icon-control\{[^}]*width:30px[^}]*height:30px[^}]*border-radius:var\(--r-xs\)/);
    expect(css).toMatch(/\.data-grid-tool\{[^}]*border-radius:var\(--r-xs\)/);
    // No icon-only control anywhere on the platform keeps the old pill.
    for (const rule of [
      ".rail-collapse{",
      ".mobile-nav-close{",
      ".home-health-drawer-close{",
      ".copilot-new-chat,.copilot-new-routine{",
      ".workspace-notification-trigger{",
    ]) {
      const start = css.indexOf(rule);
      expect(start, `${rule} missing`).toBeGreaterThan(-1);
      const block = css.slice(start, css.indexOf("}", start));
      expect(block, `${rule} still a pill`).not.toContain("border-radius:var(--r-pill)");
    }
    expect(css).toMatch(/\.compact-disclosure>summary::after,[\s\S]*?\.policy-runtime>summary>i\{[^}]*background-image:/);
    expect(css).not.toContain('.compact-disclosure[open]>summary::after{transform:rotate(45deg)}');
    expect(css).not.toContain('.m8a-agent[open]>summary::after{content:"-"');
    expect(css).not.toContain('.policy-runtime>summary>i::before{content:"+"');
    expect(shell).toMatch(/class="rail-collapse halo-icon-control"/);
    expect(css).toMatch(/\.rail-collapse\.halo-icon-control\{[^}]*width:15px[^}]*height:15px/);
    expect(css).toMatch(/\.rail-collapse\.halo-icon-control svg\{[^}]*width:10px[^}]*height:10px/);
    expect(shell).toMatch(/class="mobile-nav-close halo-icon-control"/);
    expect(shell).toContain('id="mobile-nav-close" type="button" aria-label="Return to content"');
    // Inline organization signup (setup gate SG1) shares the design tokens but
    // has no modal/icon controls of its own.
    expect(login).toContain('href="app.css?v=20260821-1"');
    expect(login).toContain('id="organization-signup"');
    expect(sources).toContain('class="source-wizard-close halo-icon-control"');
    expect(skills).toContain('class="skill-expand halo-icon-control"');
  });

  it("gives every operational table one enterprise grid treatment", async () => {
    const [css, app] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(appPath, "utf8"),
    ]);

    expect(css).toContain("/* Shared operational data grid");
    expect(css).toMatch(/\.data-grid-shell\{[^}]*border:1px solid var\(--line\)[^}]*background:var\(--panel\)/);
    expect(css).toMatch(/\.data-grid-toolbar\{[^}]*display:flex[^}]*justify-content:space-between/);
    expect(css).toMatch(/\.data-grid-findbar\{[^}]*display:flex[^}]*border-bottom:1px solid var\(--line\)/);
    expect(css).toMatch(/table\.data-grid th\{[^}]*background:var\(--mineral\)/);
    expect(css).toMatch(/table\.data-grid td\{[^}]*background:var\(--panel\)/);
    expect(css).toMatch(/table\.data-grid tbody tr:hover>td\{[^}]*background:var\(--sage-soft\)/);
    expect(css).toMatch(/@media\(max-width:720px\)[\s\S]*?\.data-grid-toolbar\{[^}]*align-items:stretch/);
    expect(css).toMatch(
      /@media\(max-width:720px\)\{[\s\S]*?\.source-sync-card table\.data-grid,[\s\S]*?\.policy-table\.data-grid\{display:block;min-width:0\}/,
    );
    expect(css).toMatch(
      /\.source-sync-card table\.data-grid thead,[\s\S]*?\.policy-table\.data-grid thead\{[^}]*position:absolute[^}]*clip-path:inset\(50%\)/,
    );
    expect(css).toMatch(
      /\.source-sync-card table\.data-grid tbody tr,[\s\S]*?\.policy-table\.data-grid tbody tr\{display:grid/,
    );

    expect(app).toContain("export function enhanceDataTables(root)");
    expect(app).toContain('root.querySelectorAll("table")');
    expect(app).toContain('table.matches(".chat-table,.conflict-diff,[data-table-static]")');
    expect(app).toContain('aria-label="Table options"');
    expect(app).toMatch(/data-grid-icon-tool" data-grid-panel="sort"[^>]*aria-label="Sort table"[^>]*title="Sort"[\s\S]*?<svg[^>]*>[\s\S]*?<\/svg><\/button>/);
    expect(app).toMatch(/data-grid-icon-tool" data-grid-panel="filters"[^>]*aria-label="Filter table"[^>]*title="Filters"[\s\S]*?<svg[^>]*>[\s\S]*?<\/svg><\/button>/);
    expect(app).not.toContain(">Sort</button>");
    expect(app).not.toContain(">Filters</button>");
    expect(app).toContain(">Columns</button>");
    expect(app).toContain("`Filter table, ${activeCount} active`");
    expect(app).toContain('`Filters (${activeCount} active)`');
    expect(css).toMatch(/\.data-grid-icon-tool\{[^}]*width:34px[^}]*padding:0/);
    expect(css).toMatch(/@media\(max-width:720px\)[\s\S]*?\.data-grid-search-jump,\.data-grid-icon-tool\{width:44px\}/);
    expect(app).toContain('table.getAttribute("data-grid-filter-source")');
    expect(app).toContain("if (serverFilterPanel)");
    expect(app).toContain("filterbar.replaceWith(serverFilterPanel)");
    expect(app).toMatch(/stage\.innerHTML = html;\s+enhanceDataTables\(stage\);/);
    expect(app).toMatch(/await action\(runtimeCtx, element[^;]*;\s+enhanceDataTables\(stage\);/);
    expect(app).toContain("if (visibleColumns.size === 0)");
  });

  it("applies the Halofy workspace language to every non-Home console screen only", async () => {
    const [css, app, conflicts] = await Promise.all([
      readFile(cssPath, "utf8"),
      readFile(appPath, "utf8"),
      readFile(conflictsScreenPath, "utf8"),
    ]);

    expect(app).toContain('document.body.setAttribute("data-console-screen", id)');
    expect(app).toContain('document.body.removeAttribute("data-console-screen")');
    expect(app).toMatch(/if \(SURFACE === "chat"\)[\s\S]*?setConsoleScreenContext\(null\)/);
    expect(app).toMatch(/if \(gateMode === "waiting"\)[\s\S]*?setConsoleScreenContext\(null\)/);
    expect(app).toMatch(/if \(!allowedScreens\.has\(id\)\)[\s\S]*?setConsoleScreenContext\(id\)/);

    const workspaceScope = 'body[data-console-screen]:not([data-console-screen="s2"])';
    expect(css).toContain("/* Shared Halofy workspace language");
    expect(css).toContain(`${workspaceScope} .app`);
    expect(css).toMatch(
      /body\[data-console-screen\]:not\(\[data-console-screen="s2"\]\) \.app\{[^}]*background:var\(--canvas\)/,
    );
    expect(css).toMatch(/\.head\{[^}]*min-height:72px[^}]*align-items:flex-start/);
    expect(css).not.toContain(`${workspaceScope} #screen-content .head{`);
    expect(css).toContain(`${workspaceScope} #screen-content .card`);
    expect(css).toContain(`${workspaceScope} .teams-rail`);
    expect(css).toContain(`${workspaceScope} .setup-step`);
    expect(css).toContain(`${workspaceScope} .data-grid-shell`);
    expect(css).toContain(`${workspaceScope} .filter-strip`);
    expect(css).toContain(`${workspaceScope} :where(.input,.select)`);
    expect(css).toContain(`${workspaceScope} .filter-strip>.btn:focus-visible`);
    expect(css).toContain(`${workspaceScope} .source-category-tab:focus-visible`);
    expect(css).toMatch(/body\[data-console-screen\]:not\(\[data-console-screen="s2"\]\) #screen-content \.card\{[^}]*background:var\(--panel\)[^}]*border-color:var\(--line\)/);
    expect(css).toMatch(/body\[data-console-screen\]:not\(\[data-console-screen="s2"\]\) table\.data-grid th\{[^}]*background:var\(--mineral\)/);
    expect(css).toContain(":not(.policy-upload-fields *)");
    expect(css).not.toContain("@keyframes console-workspace-enter");
    expect(css).not.toContain("animation:console-workspace-enter");
    expect(css).toMatch(/\.data-grid-tool:focus-visible\{[^}]*outline:2px solid var\(--evergreen\)/);
    expect(css).toMatch(/@media\(forced-colors:active\)\{[\s\S]*?\.source-category-tab\.is-active/);
    expect(conflicts).toContain('aria-pressed="${selectedCategory === category ? "true" : "false"}"');

    // Home owns its existing dashboard composition and must never opt into the
    // shared non-Home overrides through a second, positive selector.
    expect(css).not.toContain('body[data-console-screen="s2"] #screen-content');
  });

  it("keeps Usage Analytics on the shared page-header geometry", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/#screen-content\{width:100%;max-width:1184px/);
    expect(css).toMatch(/\.head\{[^}]*min-height:72px[^}]*align-items:flex-start/);
    expect(css).toMatch(/\.head \.eyebrow\{display:none\}/);
    expect(css).toMatch(/\.head h1\{font-size:var\(--text-h1\)/);
    expect(css).not.toContain('body[data-console-screen="s15"] #screen-content>.head{');
    expect(css).not.toContain('body[data-console-screen="s15"] #screen-content>.head .eyebrow{');
    expect(css).not.toContain('body[data-console-screen="s15"] #screen-content>.head h1{');
    expect(css).not.toContain('body[data-console-screen="s15"] #screen-content>.head .acts{');
    expect(css).not.toMatch(
      /body\[data-console-screen="s15"\] #screen-content\{[^}]*max-width:/,
    );
  });

  it("lets a grid opt out of the shared toolbar and findbar", async () => {
    const app = await readFile(appPath, "utf8");

    expect(app).toContain("table({ cols, rows, chrome = true } = {})");
    expect(app).toContain('data-grid-chrome="off"');
    expect(app).toContain('if (table.getAttribute("data-grid-chrome") === "off")');
    // The opt-out runs AFTER the shell/grid classes are applied, so an opted-out
    // table keeps its .data-grid styling and loses only the chrome.
    const classIndex = app.indexOf('host.classList.add("data-grid-shell")');
    const optOutIndex = app.indexOf('table.getAttribute("data-grid-chrome") === "off"');
    expect(classIndex).toBeGreaterThan(-1);
    expect(optOutIndex).toBeGreaterThan(classIndex);

  });
});
