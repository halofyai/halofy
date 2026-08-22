import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const css = readFileSync(
  fileURLToPath(new URL("../console/app.css", import.meta.url)),
  "utf8",
);

describe("console View as banner", () => {
  it("keeps the sticky safety banner opaque while content scrolls underneath", () => {
    const rule = css.match(/\.preview-banner\{([^}]+)\}/)?.[1];

    expect(rule).toBeDefined();
    expect(rule).toContain("position:sticky");
    expect(rule).toContain("background:var(--panel)");
    expect(rule).not.toMatch(/background:[^;]*(?:rgba\(|\/\s*\d)/);
  });
});
