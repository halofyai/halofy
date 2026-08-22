import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const S8_PATH = fileURLToPath(new URL("../console/screens/s8.js", import.meta.url));
const CSS_PATH = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("S8 standalone audit design contract", () => {
  it("uses the standalone page hierarchy and its eight-row audit table", async () => {
    const source = await readFile(S8_PATH, "utf8");

    expect(source).toContain('class="head audit-page-head"');
    expect(source).toContain('class="acts audit-page-head__actions"');
    expect(source).toContain('class="audit-access-pill"');
    expect(source).toContain('class="audit-stat-grid"');
    expect(source).toContain("Events recorded");
    expect(source).toContain("Blocked attempts");
    expect(source).toContain("Permanent deletions");
    expect(source).toContain("Data exports");
    expect(source).toContain("const ROWS_PER_PAGE = 8");

    expect(source).toContain('class="audit-range-tabs"');
    expect(source).toContain('["1", "24 Hours"]');
    expect(source).toContain('["7", "7 Days"]');
    expect(source).toContain('["30", "30 Days"]');
    expect(source).toContain('["all", "All Time"]');
    expect(source.match(/data-change-action="audit-search"/g)).toHaveLength(4);

    expect(source).toContain('class="audit-table" data-table-static');
    expect(source).not.toContain('data-grid-filter-source="audit-filter-panel"');
  });

  it("keeps erasure and receipt verification visible in the prototype card pair", async () => {
    const source = await readFile(S8_PATH, "utf8");

    expect(source).toContain('class="audit-compliance-grid"');
    expect(source).toContain('class="card audit-compliance-card audit-erasure"');
    expect(source).toContain('class="card audit-compliance-card certificate-viewer"');
    expect(source).not.toContain('<details class="compact-disclosure card audit-erasure"');
    expect(source).not.toContain('<details class="compact-disclosure card certificate-viewer"');
    expect(source).toContain('data-action="audit-erase"');
    expect(source).toContain('data-action="cert-verify"');
  });

  it("has screen-owned styling for the standalone cards, filters, table, and responsive layout", async () => {
    const css = await readFile(CSS_PATH, "utf8");

    expect(css).toContain(".audit-stat-grid");
    expect(css).toContain(".audit-trail-card");
    expect(css).toContain(".audit-filter-grid");
    expect(css).toContain(".audit-table");
    expect(css).toContain(".audit-compliance-grid");
    expect(css).toContain("@media(max-width:720px)");
  });
});
