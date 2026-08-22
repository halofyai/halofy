import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const consoleDir = fileURLToPath(new URL("../console/", import.meta.url));

describe("console support link", () => {
  it("keeps the website booking calendar in the sidebar footer", async () => {
    const html = await readFile(`${consoleDir}/index.html`, "utf8");

    expect(html).toContain('class="rail-help"');
    expect(html).toContain('href="https://halofy.ai/usecases#general-faqs"');
    expect(html).toContain('href="https://github.com/halofyai/halofy/discussions"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('<span>Support</span>');
    expect(html.indexOf('class="rail-help"')).toBeGreaterThan(html.indexOf('id="rail-nav"'));
    expect(html.indexOf('class="rail-help"')).toBeLessThan(html.indexOf('class="railfoot"'));
  });

  it("keeps the booking action accessible when the rail collapses", async () => {
    const [html, css] = await Promise.all([
      readFile(`${consoleDir}/index.html`, "utf8"),
      readFile(`${consoleDir}/app.css`, "utf8"),
    ]);

    expect(html).toContain('data-tip="Support"');
    expect(html).toContain('<span class="sr-only"> (opens in a new tab)</span>');
    expect(css).toMatch(/\.rail-help\{[^}]*flex:none/);
    expect(css).toMatch(/body\.rail-collapsed \.rail-help\{[^}]*width:44px/);
    expect(css).toMatch(/body\.rail-collapsed \.rail-help__copy\{display:none/);
    expect(css).toMatch(/body\.rail-collapsed \.rail-help__action>span:not\(\.sr-only\),[^}]*display:none/);
  });
});
