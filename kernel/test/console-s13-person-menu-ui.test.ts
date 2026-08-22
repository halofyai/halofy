import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const SCREEN = fileURLToPath(new URL("../console/screens/s13.js", import.meta.url));
const CSS = fileURLToPath(new URL("../console/app.css", import.meta.url));

async function load() {
  return import(`${pathToFileURL(SCREEN).href}?person-menu=${Date.now()}-${Math.random()}`);
}

describe("S13 person action menu", () => {
  it("positions the open menu against the viewport so the table cannot clip it", async () => {
    const s13 = await load();
    const trigger = {
      setAttribute: vi.fn(),
      getBoundingClientRect: () => ({ top: 550, bottom: 576, left: 1305, right: 1331, width: 26, height: 26 }),
    };
    const backdrop = { toggleAttribute: vi.fn() };
    const popover = {
      style: {} as Record<string, string>,
      hasAttribute: (name: string) => name === "hidden",
      toggleAttribute: vi.fn(),
      getBoundingClientRect: () => ({ top: 0, bottom: 45, left: 0, right: 190, width: 190, height: 45 }),
    };
    const menu = {
      querySelector: (selector: string) => selector.includes("person-action-toggle")
        ? trigger
        : selector.includes("backdrop")
          ? backdrop
          : popover,
    };
    const root = { querySelectorAll: () => [] };
    const element = {
      closest: (selector: string) => selector === ".teams-person-menu" ? menu : selector === ".screen" ? root : null,
    };
    vi.stubGlobal("window", { innerWidth: 1444, innerHeight: 925 });

    try {
      s13.actions["person-action-toggle"]({}, element);

      expect(popover.style.top).toBe("580px");
      expect(popover.style.left).toBe("1141px");
      expect(popover.style.right).toBe("auto");
      const css = await readFile(CSS, "utf8");
      expect(css).toMatch(/\.teams-person-menu__popover\{[^}]*position:fixed/);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
