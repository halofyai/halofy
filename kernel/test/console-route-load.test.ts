import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import {
  beginRouteLoad,
  canLoadPeopleDirectory,
  isCurrentRouteLoad,
  requestGet,
  requestMutation,
} from "../console/app.js";

const appPath = fileURLToPath(new URL("../console/app.js", import.meta.url));

/** Flush all pending microtasks (an import/render continuation per await). */
function tick() {
  return new Promise<void>((resolve) => setTimeout(resolve, 0));
}

/**
 * The exact two-await flow of app.js loadScreen(): stamp a token, paint the
 * skeleton, await the dynamic import, await render(), paint the HTML — with a
 * token re-check after every await. Extracted here so the race is testable
 * without a DOM; the wiring assertion at the bottom pins loadScreen to it.
 */
function makeLoader(stage: { innerHTML: string }) {
  return async function simulatedLoad(id: string, render: () => Promise<string>): Promise<void> {
    const loadToken = beginRouteLoad();
    stage.innerHTML = `skeleton:${id}`;
    await Promise.resolve(); // dynamic import
    if (!isCurrentRouteLoad(loadToken)) return;
    const html = await render();
    if (!isCurrentRouteLoad(loadToken)) return;
    stage.innerHTML = html;
  };
}

describe("console route-load sequencing", () => {
  it("only the latest stamped navigation is current", () => {
    const first = beginRouteLoad();
    expect(isCurrentRouteLoad(first)).toBe(true);
    const second = beginRouteLoad();
    expect(isCurrentRouteLoad(first)).toBe(false);
    expect(isCurrentRouteLoad(second)).toBe(true);
  });

  it("a slow prior navigation never paints over the screen selected last", async () => {
    const stage = { innerHTML: "previous screen" };
    const completions: Array<(html: string) => void> = [];
    const pendingRender = () =>
      new Promise<string>((resolve) => {
        completions.push(resolve);
      });
    const simulatedLoad = makeLoader(stage);

    // Click tab A: import resolves while A is still current, render starts (slow API).
    void simulatedLoad("a", pendingRender);
    await tick();
    expect(completions).toHaveLength(1);

    // Click tab B before A's render returns: nav + skeleton switch to B.
    void simulatedLoad("b", pendingRender);
    await tick();
    expect(stage.innerHTML).toBe("skeleton:b");
    expect(completions).toHaveLength(2);

    // B's render finishes first → B paints. (Navbar already shows B.)
    completions[1]?.("screen B");
    await tick();
    expect(stage.innerHTML).toBe("screen B");

    // A's render resolves late — the reported bug painted this over B.
    completions[0]?.("screen A (stale)");
    await tick();
    expect(stage.innerHTML).toBe("screen B");
  });

  it("a navigation superseded during the import never renders at all", async () => {
    const stage = { innerHTML: "previous screen" };
    const staleRender = vi.fn(() => Promise.resolve("stale html"));
    const freshRender = vi.fn(() => Promise.resolve("fresh html"));
    const simulatedLoad = makeLoader(stage);

    // Click A, then click B before A's module even finishes importing.
    void simulatedLoad("a", staleRender);
    void simulatedLoad("b", freshRender);
    await tick();

    expect(staleRender).not.toHaveBeenCalled();
    expect(freshRender).toHaveBeenCalledOnce();
    expect(stage.innerHTML).toBe("fresh html");
  });

  it("loadScreen stamps a token per navigation and re-checks it before every paint", async () => {
    const app = await readFile(appPath, "utf8");
    expect(app).toContain("const loadToken = beginRouteLoad();");
    // Four guards: after initial directory hydration, after the import, after
    // render, and in the error path.
    expect(app.match(/if \(!isCurrentRouteLoad\(loadToken\)\) return;/g) ?? []).toHaveLength(4);
  });

  it("coalesces only simultaneous identical GETs and never serves a stale response", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchMock = vi.fn(async () => {
      await gate;
      return new Response('{"ok":true}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const first = requestGet("/v1/example");
    const duplicate = requestGet("/v1/example");
    expect(fetchMock).toHaveBeenCalledOnce();

    release();
    await expect(first).resolves.toEqual({ ok: true });
    await expect(duplicate).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledOnce();

    await expect(requestGet("/v1/example")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const previewA = requestGet("/v1/example", {
      headers: { "x-halofy-preview": "preview-a" },
    });
    const previewB = requestGet("/v1/example", {
      headers: { "x-halofy-preview": "preview-b" },
    });
    await Promise.all([previewA, previewB]);
    expect(fetchMock).toHaveBeenCalledTimes(4);
    vi.unstubAllGlobals();
  });

  it("does not hydrate the privileged people directory for ordinary members", () => {
    expect(canLoadPeopleDirectory({ role: "member", entitlements: [] })).toBe(false);
    expect(canLoadPeopleDirectory({ role: "member", entitlements: ["audit:read"] })).toBe(true);
    expect(canLoadPeopleDirectory({ role: "auditor", entitlements: [] })).toBe(true);
    expect(canLoadPeopleDirectory({ role: "admin", entitlements: [] })).toBe(true);
    expect(canLoadPeopleDirectory({ role: "owner", entitlements: [] })).toBe(true);
  });

  it("never lets a post-mutation refresh reuse a pre-mutation GET", async () => {
    let releaseOld!: () => void;
    const oldGate = new Promise<void>((resolve) => {
      releaseOld = resolve;
    });
    let getCount = 0;
    const fetchMock = vi.fn(async (_path: string, options?: RequestInit) => {
      if (options?.method === "POST") {
        return new Response('{"saved":true}', { status: 200 });
      }
      getCount += 1;
      if (getCount === 1) {
        await oldGate;
        return new Response('{"version":"old"}', { status: 200 });
      }
      return new Response('{"version":"fresh"}', { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const oldRead = requestGet("/v1/example");
    await expect(requestMutation("POST", "/v1/example", {})).resolves.toEqual({ saved: true });
    await expect(requestGet("/v1/example")).resolves.toEqual({ version: "fresh" });
    expect(fetchMock).toHaveBeenCalledTimes(3);

    releaseOld();
    await expect(oldRead).resolves.toEqual({ version: "old" });
    vi.unstubAllGlobals();
  });
});
