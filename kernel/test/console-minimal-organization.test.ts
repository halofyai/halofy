import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));

async function screenSource(screen: string): Promise<string> {
  return readFile(
    fileURLToPath(new URL(`../console/screens/${screen}.js`, import.meta.url)),
    "utf8",
  );
}

describe("minimal organization console hierarchy", () => {
  it("keeps Teams primary while moving mutation forms and the RBAC reference into drawers", async () => {
    const source = await screenSource("s13");

    expect(source).toContain('<section class="teams-v2">');
    expect(source).toContain('id="team-create-modal" role="dialog" aria-modal="true"');
    expect(source).toContain('id="team-member-modal" role="dialog" aria-modal="true"');
    expect(source).toContain('id="team-invite-modal" role="dialog" aria-modal="true"');
    expect(source).toContain('id="team-roles-modal" role="dialog" aria-modal="true"');
    expect(source).not.toContain('<details class="compact-disclosure teams-invite"');
    expect(source).not.toContain('<details class="compact-disclosure card teams-rbac"');
  });

  it("keeps badge detail in the right panel and creates through one inline row", async () => {
    const source = await screenSource("s3");

    // Each badge's detail opens outside the ledger geometry in one shared panel.
    expect(source).toContain('data-action="badge-expand"');
    expect(source).toContain('id: "badge-detail-panel"');
    expect(source).toContain('aria-controls="badge-detail-panel" aria-haspopup="dialog"');

    // Creating a badge is no longer a disclosure holding a six-fieldset form,
    // nor a three-step wizard: it is one row of five fields, always on screen.
    expect(source).not.toContain('id="badge-form"');
    expect(source).not.toContain('id="key-form"');
    expect(source).not.toContain('<div id="agent-flow-host">');
    expect(source).not.toContain('class="wiz-rail"');
    expect(source).toContain('data-action="badge-create"');
  });

  it("discloses OAuth registration, client metadata, and profile connection detail", async () => {
    const [oauth, profile] = await Promise.all([
      screenSource("s17"),
      screenSource("s18"),
    ]);

    expect(oauth).toContain('id: "oauth-client-panel"');
    expect(oauth).toContain('aria-controls="oauth-client-panel" aria-haspopup="dialog"');
    expect(oauth).toContain('<details class="compact-disclosure card oauth-client"');
    expect(oauth).toContain('class="oauth-client-summary-copy"');
    expect(oauth).toContain('<details class="compact-disclosure oauth-guidance">');
    // S18 keeps the connection detail disclosed, but behind the tile grid's
    // per-method pop-up (the S14 overlay pattern) instead of an inline
    // <details> row.
    expect(profile).toContain('data-action="profile-method-open"');
    expect(profile).toContain('class="profile-method-modal source-wizard-overlay"');
  });

  it("opens manual OAuth setup in the shared right panel", async () => {
    const mod = await import("../console/screens/s17.js");
    const expanded: string[] = [];
    const focus = vi.fn();
    const doc = {
      body: { classList: { add: vi.fn(), remove: vi.fn() } },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    const panel = {
      hidden: true,
      ownerDocument: doc,
      setAttribute: vi.fn(),
      querySelector: () => ({ focus }),
    };
    const root = { querySelector: (selector: string) => selector === "#oauth-client-panel" ? panel : null };
    const trigger = {
      closest: () => root,
      setAttribute: (name: string, value: string) => {
        if (name === "aria-expanded") expanded.push(value);
      },
    };

    mod.actions["oauth-client-create"]({}, trigger);

    expect(panel.hidden).toBe(false);
    expect(expanded).toEqual(["true"]);
    expect(focus).toHaveBeenCalledOnce();
  });

  it("opens a Teams dialog in the top layer and focuses its first field", async () => {
    const mod = await import("../console/screens/s13.js");
    const expanded: string[] = [];
    const focus = vi.fn();
    const scrollTo = vi.fn();
    vi.stubGlobal("window", { scrollX: 18, scrollY: 42, scrollTo });
    let closeListener = () => undefined;
    const modal = {
      open: false,
      showModal() { this.open = true; },
      addEventListener(name: string, listener: () => void) {
        if (name === "close") closeListener = listener;
      },
      querySelector: () => ({ focus }),
    };
    const root = { querySelector: (selector: string) => selector === "#team-create-modal" ? modal : null };
    const trigger = {
      closest: () => root,
      getAttribute: (name: string) => name === "data-modal-target" ? "team-create-modal" : null,
      setAttribute: (name: string, value: string) => {
        if (name === "aria-expanded") expanded.push(value);
      },
    };

    try {
      mod.actions["team-modal-open"]({}, trigger);

      expect(modal.open).toBe(true);
      expect(expanded).toEqual(["true"]);
      expect(focus).toHaveBeenCalledOnce();
      expect(scrollTo).toHaveBeenCalledWith(18, 42);
      expect(closeListener).toBeTypeOf("function");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("keeps compact OAuth summaries shrinkable and the agent indicator upright", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.oauth-client-summary-copy\{[^}]*min-width:0[^}]*overflow:hidden/);
    expect(css).toMatch(/\.oauth-client-summary-copy \.mono\{[^}]*text-overflow:ellipsis/);
    expect(css).toMatch(/\.m8a-agent\[open\]>summary::after\{[^}]*transform:none/);
  });
});
