import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SCREEN_PATH = fileURLToPath(new URL("../console/screens/s13.js", import.meta.url));
const CSS_PATH = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("S13 stable modal interactions", () => {
  it("opens every Teams overlay as a right-hand dialog instead of an inline disclosure", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain('data-action="team-modal-open"');
    expect(source).toContain('aria-haspopup="dialog"');
    expect(source.match(/role="dialog" aria-modal="true"/g)).toHaveLength(7);
    expect(source).toContain('data-action="team-modal-close"');
    expect(source).toContain('"Return to teams"');
    expect(source).toContain('d="M13 8H3M7 12l-4-4 4-4"');
    expect(source).not.toContain('d="M3.5 3.5l9 9m0-9l-9 9"');
    expect(source).not.toContain('<details class="compact-disclosure teams-add"');
    expect(source).not.toContain('<details class="compact-disclosure teams-invite"');
    expect(source).not.toContain('<details class="compact-disclosure card teams-create"');
  });

  it("keeps every shared dialog in a right-hand drawer and lays out the roles reference as cards", async () => {
    const css = await readFile(CSS_PATH, "utf8");

    expect(css).toMatch(/\.console-modal\{[^}]*position:fixed[^}]*inset:0 0 0 auto/);
    expect(css).toMatch(/\.console-modal\{[^}]*height:100dvh;[^}]*max-height:none/);
    expect(css).toMatch(/\.console-modal\{[^}]*border-left:1px solid #e5e7eb;[^}]*border-radius:0/);
    expect(css).toMatch(/\.console-modal\{[^}]*background:#fff;[^}]*color:#111827;[^}]*font-family:var\(--font-sans\)/);
    expect(css).toMatch(/\.console-modal__head\{[^}]*border-bottom:1px solid #e5e7eb;[^}]*background:#fff/);
    expect(css).toMatch(/\.console-modal__body\{[^}]*background:#fff/);
    expect(css).toMatch(/@keyframes console-drawer-enter\{[\s\S]*translateX\(32px\)[\s\S]*translateX\(0\)/);
    expect(css).not.toMatch(/\.console-modal\{[^}]*top:50%;[^}]*left:50%/);
    expect(css).not.toMatch(/\.console-modal\{[^}]*translate\(-50%,-50%\)/);
    expect(css).toMatch(/\.console-modal::backdrop\{[^}]*background:/);
    expect(css).toMatch(/html\{[^}]*scrollbar-gutter:stable/);
    expect(css).toMatch(/body\.console-modal-open\{overflow:hidden\}/);
    expect(css).not.toMatch(/body\.console-modal-open\{[^}]*position:fixed/);
    expect(css).toMatch(/@media\(max-width:620px\)\{[\s\S]*\.console-modal\{[^}]*width:100vw;[^}]*border-left:0;[^}]*border-radius:0/);
    expect(css).toMatch(/@media\(max-width:680px\)\{[\s\S]*\.source-wizard-dialog\{[^}]*width:100vw;[^}]*border-left:0;[^}]*border-radius:0/);
    expect(css).toMatch(/\.teams-role-cards\{[^}]*display:grid/);
    expect(css).toMatch(/\.teams-role-card\{[^}]*border:1px solid #e5e7eb/);
  });
});
