import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createMobileNavigation } from "../console/mobile-nav.js";

const CONSOLE_DIR = fileURLToPath(new URL("../console/", import.meta.url));

type Listener = (event: { key?: string }) => void;

class FakeTarget {
  private readonly listeners = new Map<string, Set<Listener>>();

  addEventListener(type: string, listener: Listener) {
    const listeners = this.listeners.get(type) ?? new Set<Listener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: Listener) {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type: string, event: { key?: string } = {}) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

class FakeClassList {
  private readonly names = new Set<string>();

  toggle(name: string, force: boolean) {
    if (force) this.names.add(name);
    else this.names.delete(name);
  }

  contains(name: string) {
    return this.names.has(name);
  }
}

class FakeElement extends FakeTarget {
  readonly classList = new FakeClassList();
  readonly attributes = new Map<string, string>();
  inert = false;
  focusCount = 0;

  setAttribute(name: string, value: string) {
    this.attributes.set(name, value);
  }

  getAttribute(name: string) {
    return this.attributes.get(name) ?? null;
  }

  focus() {
    this.focusCount += 1;
  }
}

class FakeMediaQuery extends FakeTarget {
  constructor(public matches: boolean) {
    super();
  }
}

function makeNavigation(
  matches = true,
  defer: (callback: () => void) => void = queueMicrotask,
) {
  const body = new FakeElement();
  const rail = new FakeElement();
  const toggle = new FakeElement();
  const close = new FakeElement();
  const backdrop = new FakeElement();
  const mobileTopbar = new FakeElement();
  const stage = new FakeElement();
  const eventTarget = new FakeTarget();
  const media = new FakeMediaQuery(matches);
  const navigation = createMobileNavigation({
    body,
    rail,
    toggle,
    close,
    backdrop,
    eventTarget,
    media,
    defer,
    background: [mobileTopbar, stage],
  });
  return {
    backdrop,
    body,
    close,
    eventTarget,
    media,
    mobileTopbar,
    navigation,
    rail,
    stage,
    toggle,
  };
}

describe("mobile console navigation", () => {
  it("opens the mobile drawer and closes it with Escape while restoring focus", () => {
    const deferred: Array<() => void> = [];
    const { body, close, eventTarget, mobileTopbar, rail, stage, toggle } = makeNavigation(
      true,
      (callback) => deferred.push(callback),
    );

    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(rail.getAttribute("aria-hidden")).toBe("true");
    expect(rail.inert).toBe(true);

    toggle.dispatch("click");

    expect(body.classList.contains("nav-open")).toBe(true);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(rail.getAttribute("aria-hidden")).toBe("false");
    expect(rail.inert).toBe(false);
    expect(mobileTopbar.inert).toBe(true);
    expect(stage.inert).toBe(true);
    expect(close.focusCount).toBe(0);
    deferred.shift()?.();
    expect(close.focusCount).toBe(1);

    eventTarget.dispatch("keydown", { key: "Escape" });

    expect(body.classList.contains("nav-open")).toBe(false);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(rail.getAttribute("aria-hidden")).toBe("true");
    expect(mobileTopbar.inert).toBe(false);
    expect(stage.inert).toBe(false);
    expect(toggle.focusCount).toBe(0);
    deferred.shift()?.();
    expect(toggle.focusCount).toBe(1);
  });

  it("keeps the desktop rail accessible after crossing the mobile breakpoint", () => {
    const { body, media, mobileTopbar, rail, stage, toggle } = makeNavigation();
    toggle.dispatch("click");

    media.matches = false;
    media.dispatch("change");

    expect(body.classList.contains("nav-open")).toBe(false);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(rail.getAttribute("aria-hidden")).toBe("false");
    expect(rail.inert).toBe(false);
    expect(mobileTopbar.inert).toBe(false);
    expect(stage.inert).toBe(false);
  });

  it("ships an accessible trigger, drawer, return control, and backdrop", async () => {
    const [html, css, app] = await Promise.all([
      readFile(`${CONSOLE_DIR}/index.html`, "utf8"),
      readFile(`${CONSOLE_DIR}/app.css`, "utf8"),
      readFile(`${CONSOLE_DIR}/app.js`, "utf8"),
    ]);

    expect(html).toContain('id="mobile-nav-toggle"');
    expect(html).toContain('aria-controls="app-rail"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('id="mobile-nav-close"');
    expect(html).toMatch(/id="mobile-nav-close"[^>]*aria-label="Return to content"[\s\S]*?<path d="M14 6l-6 6 6 6"/);
    expect(html).not.toMatch(/id="mobile-nav-close"[\s\S]*?<path d="M6 6l12 12M18 6L6 18"/);
    expect(html).toContain('id="mobile-nav-backdrop"');
    expect(html).toContain('id="app-rail"');
    expect(html).toContain('<title>Halofy</title>');
    expect(html).toContain('<div class="mobile-brand" aria-label="Halofy">');
    expect(html).toContain('<img src="assets/marks/halofy-mark-green.svg" alt="" aria-hidden="true" />');
    expect(html).not.toContain('<span>Halofy</span>');
    expect(html).toContain('<aside class="rail" id="app-rail" aria-label="Halofy navigation">');
    expect(html).toContain('<img class="mark" src="assets/marks/halofy-mark-white.svg" alt="" aria-hidden="true" />');
    expect(html).not.toContain('<b>Halofy</b>');
    expect(html).not.toContain("HaloMem");
    expect(html).not.toContain("Halofy Halofy");
    expect(html).not.toContain("Control Room");
    expect(css).toContain("body.nav-open .rail");
    expect(css).toContain("body.nav-open .mobile-nav-backdrop");
    expect(css).toContain(
      ".mobile-topbar,.mobile-nav-backdrop,.mobile-nav-close.halo-icon-control{display:none}",
    );
    expect(css).toContain(
      ".rail-collapse.halo-icon-control,.mobile-nav-close.halo-icon-control{margin-left:auto}",
    );
    expect(css).toContain(
      "@media(max-width:860px){.rail-collapse.halo-icon-control{display:none}}",
    );
    expect(css).toMatch(/#rail-nav\{[^}]*overflow-y:auto/);
    expect(css).toMatch(/\.brand\{[^}]*display:flex;align-items:center/);
    expect(app).toContain("createMobileNavigation");
    expect(app).toContain("mobileNavigation.close({ returnFocus: true })");
  });
});
