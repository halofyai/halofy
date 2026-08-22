import { afterEach, describe, expect, it, vi } from "vitest";

import { setConsoleScreenContext } from "../console/app.js";

describe("console screen visual context", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("marks resolved routes and clears the marker when no screen is active", () => {
    const attributes = new Map<string, string>();
    vi.stubGlobal("document", {
      body: {
        setAttribute(name: string, value: string) {
          attributes.set(name, value);
        },
        removeAttribute(name: string) {
          attributes.delete(name);
        },
      },
    });

    setConsoleScreenContext("s6");
    expect(attributes.get("data-console-screen")).toBe("s6");

    setConsoleScreenContext(null);
    expect(attributes.has("data-console-screen")).toBe(false);
  });
});
