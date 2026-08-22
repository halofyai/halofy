import { describe, expect, it, vi } from "vitest";

import {
  invalidateRefreshedScreen,
  renderRefreshedScreen,
  runDelegatedPointerAction,
} from "../console/app.js";

describe("console delegated pointer actions", () => {
  it("runs the declared pointer action synchronously with the native event", () => {
    const element = {
      closest: (selector: string) => selector === "[data-pointer-action]" ? element : null,
      getAttribute: (name: string) => name === "data-pointer-action" ? "topo-drag" : null,
    };
    const event = {
      type: "pointermove",
      pointerId: 7,
      target: element,
    };
    const stage = { contains: () => true };
    const action = vi.fn();
    const ctx = { identity: { namespace: "acme" } };

    expect(runDelegatedPointerAction(event, stage, { "topo-drag": action }, ctx)).toBe(true);
    expect(action).toHaveBeenCalledWith(ctx, element, event);
  });

  it("ignores unsupported events, detached targets, and undeclared actions", () => {
    const element = {
      closest: (selector: string) => selector === "[data-pointer-action]" ? element : null,
      getAttribute: (name: string) => name === "data-pointer-action" ? "topo-drag" : null,
    };
    const action = vi.fn();

    expect(runDelegatedPointerAction(
      { type: "click", target: element },
      { contains: () => true },
      { "topo-drag": action },
      {},
    )).toBe(false);
    expect(runDelegatedPointerAction(
      { type: "pointerdown", target: element },
      { contains: () => false },
      { "topo-drag": action },
      {},
    )).toBe(false);
    expect(runDelegatedPointerAction(
      { type: "pointerdown", target: element },
      { contains: () => true },
      {},
      {},
    )).toBe(false);
    expect(action).not.toHaveBeenCalled();
  });

  it("makes the old screen inert while an asynchronous refresh is pending", async () => {
    let finishRender: ((html: string) => void) | undefined;
    const render = vi.fn(() => new Promise<string>((resolve) => {
      finishRender = resolve;
    }));
    const cleanup = vi.fn();
    const attributes = new Map<string, string>();
    const stage = {
      innerHTML: "old graph",
      setAttribute(name: string, value: string) { attributes.set(name, value); },
      removeAttribute(name: string) { attributes.delete(name); },
    };

    const pending = renderRefreshedScreen(stage, { cleanup, render }, {});

    expect(cleanup).toHaveBeenCalledWith("refresh");
    expect(stage.innerHTML).toBe("old graph");
    expect(attributes.has("inert")).toBe(true);
    expect(attributes.get("aria-busy")).toBe("true");

    finishRender?.("new graph");
    expect(await pending).toBe("new graph");
    expect(stage.innerHTML).toBe("new graph");
    expect(attributes.has("inert")).toBe(false);
    expect(attributes.has("aria-busy")).toBe(false);
  });

  it("lets only the latest refresh own markup and inert state", async () => {
    const completions: Array<(html: string) => void> = [];
    const screenModule = {
      cleanup: vi.fn(),
      render: vi.fn(() => new Promise<string>((resolve) => completions.push(resolve))),
    };
    const attributes = new Map<string, string>();
    const stage = {
      innerHTML: "old graph",
      setAttribute(name: string, value: string) { attributes.set(name, value); },
      removeAttribute(name: string) { attributes.delete(name); },
    };

    const first = renderRefreshedScreen(stage, screenModule, {});
    const second = renderRefreshedScreen(stage, screenModule, {});
    completions[0]?.("stale graph");
    expect(await first).toBeNull();
    expect(stage.innerHTML).toBe("old graph");
    expect(attributes.has("inert")).toBe(true);

    completions[1]?.("fresh graph");
    expect(await second).toBe("fresh graph");
    expect(stage.innerHTML).toBe("fresh graph");
    expect(attributes.has("inert")).toBe(false);
  });

  it("invalidates a pending refresh before navigation replaces the stage", async () => {
    let finishRender: ((html: string) => void) | undefined;
    const attributes = new Map<string, string>();
    const stage = {
      innerHTML: "old graph",
      setAttribute(name: string, value: string) { attributes.set(name, value); },
      removeAttribute(name: string) { attributes.delete(name); },
    };
    const pending = renderRefreshedScreen(stage, {
      cleanup: vi.fn(),
      render: () => new Promise<string>((resolve) => { finishRender = resolve; }),
    }, {});

    invalidateRefreshedScreen(stage);
    stage.innerHTML = "navigated screen";
    finishRender?.("stale graph");

    expect(await pending).toBeNull();
    expect(stage.innerHTML).toBe("navigated screen");
    expect(attributes.has("inert")).toBe(false);
    expect(attributes.has("aria-busy")).toBe(false);
  });
});
