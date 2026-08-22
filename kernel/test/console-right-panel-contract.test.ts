import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const root = new URL("../console/", import.meta.url);

async function source(path: string) {
  return readFile(new URL(path, root), "utf8");
}

describe("console right-panel interaction contract", () => {
  it("provides one shared accessible right-panel controller", async () => {
    const [panel, css] = await Promise.all([
      source("right-panel.js"),
      source("app.css"),
    ]);

    expect(panel).toContain('class="source-wizard-overlay console-right-panel"');
    expect(panel).toContain('role="dialog" aria-modal="true"');
    expect(panel).toContain('aria-label="Return to page"');
    expect(panel).toContain('class="console-right-panel__context"');
    expect(panel).toContain("data-right-panel-icon");
    expect(panel).toContain('#rail-nav button[data-s].on svg');
    expect(panel).toContain("cloneNode(true)");
    expect(panel).toContain('event.key === "Escape"');
    expect(panel).toContain('opener?.setAttribute?.("aria-expanded", "true")');
    expect(panel).toContain('state.opener?.setAttribute?.("aria-expanded", "false")');
    expect(css).toMatch(/\.console-right-panel__nav-icon\{[^}]*display:grid/);
  });

  it.each([
    ["screens/s2.js", "home-cap-panel"],
    ["screens/s3.js", "badge-detail-panel"],
    ["screens/s5.js", "viewas-panel"],
    ["screens/s16.js", "skill-register-panel"],
    ["screens/s17.js", "oauth-client-panel"],
  ])("routes %s management details through the right panel", async (path, id) => {
    const screen = await source(path);

    expect(screen).toContain(`id: "${id}"`);
    expect(screen).toContain(`aria-controls="${id}"`);
    expect(screen).toContain('aria-haspopup="dialog"');
  });

  it("does not render View as as a page card", async () => {
    const memory = await source("screens/s5.js");

    expect(memory).not.toContain('<div class="card viewas" data-viewas>');
  });
});
