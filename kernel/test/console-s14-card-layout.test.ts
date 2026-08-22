import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const cssPath = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("S14 connection card layout", () => {
  it("uses the available library width and keeps names, tags, and actions in separate tracks", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.intg-library\{[^}]*container:intg-library\/inline-size/);
    expect(css).toMatch(/\.intg-card\{[^}]*display:grid;grid-template-columns:38px minmax\(0,1fr\) auto/);
    expect(css).toMatch(/\.intg-card-title\{[^}]*display:grid;[^}]*overflow-wrap:anywhere/);
    expect(css).toMatch(/\.intg-card-title em\{[^}]*max-width:100%;[^}]*text-overflow:ellipsis/);
    expect(css).toMatch(/@container intg-library \(max-width:960px\)\{\s*\.intg-grid\{grid-template-columns:repeat\(2,minmax\(0,1fr\)\)\}/);
    expect(css).toMatch(/@container intg-library \(max-width:560px\)\{\s*\.intg-grid\{grid-template-columns:1fr\}/);
  });

  it("uses the Usage ledger table language for connected and assigned badges", async () => {
    const css = await readFile(cssPath, "utf8");

    expect(css).toMatch(/\.intg-assigned\{[^}]*display:grid;[^}]*background:#fff/);
    expect(css).toMatch(/\.intg-assigned-head p\{[^}]*color:var\(--muted\)/);
    expect(css).toMatch(/\.intg-ledger-table table\.data-grid\{[^}]*border-collapse:separate;[^}]*border-spacing:0 8px/);
    expect(css).toMatch(/\.intg-ledger-table table\.data-grid th\{[^}]*color:#9ca3af;[^}]*text-transform:none/);
    expect(css).toMatch(/\.intg-ledger-table table\.data-grid td\{[^}]*background:#fafafa/);
    expect(css).toMatch(/\.intg-ledger-table \.intg-logo\{[^}]*border-color:#e5e7eb;[^}]*background:#f3f4f6/);
    expect(css).toMatch(/\.intg-ledger-table :is\(\.pill,\.tag\):not\(\.pill--crit\)\{[^}]*background:#f3f4f6;[^}]*color:#374151/);
    expect(css).toMatch(/\.intg-connected-actions>\.pill\{[^}]*border-color:#e5e7eb;[^}]*background:#f3f4f6/);
    expect(css).toMatch(/\.intg-table-filter-trigger\{[^}]*width:32px;[^}]*border-radius:10px/);
    expect(css).toMatch(/\.intg-assigned-empty\{[^}]*background:var\(--mineral\)/);
    expect(css).toMatch(/@media\(max-width:680px\)\{[\s\S]*\.intg-assigned-head\{flex-direction:column\}/);
  });
});
