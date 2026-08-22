import { describe, expect, it, vi } from "vitest";

import { runDelegatedHotkey, runDelegatedWheelAction } from "../console/app.js";

function opted(attribute: string, name: string) {
  const element = {
    closest: (selector: string) => (selector === `[${attribute}]` ? element : null),
    getAttribute: (key: string) => (key === attribute ? name : null),
  };
  return element;
}

describe("console delegated wheel actions", () => {
  it("runs the declared action for an opted-in element", () => {
    const element = opted("data-wheel-action", "topo-zoom");
    const event = { type: "wheel", target: element, deltaY: -120 };
    const stage = { contains: () => true };
    const action = vi.fn();

    expect(runDelegatedWheelAction(event, stage, { "topo-zoom": action }, { id: 1 })).toBe(true);
    expect(action).toHaveBeenCalledWith({ id: 1 }, element, event);
  });

  it("leaves every other wheel gesture scrolling the page", () => {
    const bare = { closest: () => null, getAttribute: () => null };
    const action = vi.fn();
    const stage = { contains: () => true };

    expect(runDelegatedWheelAction({ type: "wheel", target: bare }, stage, { "topo-zoom": action }, {})).toBe(false);
    // An element outside the current screen never reaches a screen action.
    const outside = opted("data-wheel-action", "topo-zoom");
    expect(runDelegatedWheelAction(
      { type: "wheel", target: outside },
      { contains: () => false },
      { "topo-zoom": action },
      {},
    )).toBe(false);
    expect(action).not.toHaveBeenCalled();
  });
});

describe("console single-key hotkeys", () => {
  const focusable = () => ({ focus: vi.fn(), select: vi.fn() });

  it("moves focus to the element that declared the key", () => {
    const target = focusable();
    const stage = { querySelector: vi.fn(() => target) };
    const event = { key: "/", target: { tagName: "DIV" }, preventDefault: vi.fn() };

    expect(runDelegatedHotkey(event, stage)).toBe(true);
    expect(stage.querySelector).toHaveBeenCalledWith('[data-hotkey="/"]');
    expect(target.focus).toHaveBeenCalledOnce();
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it("never steals a keystroke from a form control or a modifier chord", () => {
    const target = focusable();
    const stage = { querySelector: () => target };

    expect(runDelegatedHotkey({ key: "/", target: { tagName: "INPUT" } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "/", target: { tagName: "TEXTAREA" } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "/", target: { isContentEditable: true } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "/", metaKey: true, target: { tagName: "DIV" } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "Enter", target: { tagName: "DIV" } }, stage)).toBe(false);
    expect(target.focus).not.toHaveBeenCalled();
  });

  it("only addresses a conservative literal key set, so the selector cannot be broken", () => {
    const stage = { querySelector: vi.fn(() => focusable()) };

    expect(runDelegatedHotkey({ key: '"', target: { tagName: "DIV" } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "]", target: { tagName: "DIV" } }, stage)).toBe(false);
    expect(runDelegatedHotkey({ key: "\\", target: { tagName: "DIV" } }, stage)).toBe(false);
    expect(stage.querySelector).not.toHaveBeenCalled();
  });
});
