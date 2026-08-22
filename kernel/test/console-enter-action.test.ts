import { describe, expect, it, vi } from "vitest";

import { runDelegatedEnterAction } from "../console/app.js";

describe("console delegated Enter actions", () => {
  it("runs the declared action for Enter and prevents a textarea newline", async () => {
    const element = {
      closest: (selector: string) => selector === "[data-enter-action]" ? element : null,
      getAttribute: (name: string) => name === "data-enter-action" ? "send-chat" : null,
    };
    const event = {
      key: "Enter",
      altKey: false,
      isComposing: false,
      target: element,
      preventDefault: vi.fn(),
    };
    const stage = { contains: () => true, querySelector: () => null };
    const action = vi.fn(async () => {});
    const ctx = { identity: { namespace: "acme" } };

    await expect(runDelegatedEnterAction(event, stage, { "send-chat": action }, ctx)).resolves.toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(action).toHaveBeenCalledWith(ctx, element);
  });

  it("leaves Alt+Enter and IME composition to the textarea", async () => {
    const element = {
      closest: (selector: string) => selector === "[data-enter-action]" ? element : null,
      getAttribute: (name: string) => name === "data-enter-action" ? "send-chat" : null,
    };
    const stage = { contains: () => true, querySelector: () => null };
    const action = vi.fn(async () => {});
    const altEvent = {
      key: "Enter",
      altKey: true,
      isComposing: false,
      target: element,
      preventDefault: vi.fn(),
    };
    const composingEvent = {
      key: "Enter",
      altKey: false,
      isComposing: true,
      target: element,
      preventDefault: vi.fn(),
    };

    await expect(runDelegatedEnterAction(altEvent, stage, { "send-chat": action }, {})).resolves.toBe(false);
    await expect(runDelegatedEnterAction(composingEvent, stage, { "send-chat": action }, {})).resolves.toBe(false);
    expect(altEvent.preventDefault).not.toHaveBeenCalled();
    expect(composingEvent.preventDefault).not.toHaveBeenCalled();
    expect(action).not.toHaveBeenCalled();
  });
});
