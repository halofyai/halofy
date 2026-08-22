/**
 * Limit toasts: every allowance denial the kernel returns surfaces through the
 * shared top-right toaster, from the API client's one choke point, with one
 * copy shape - no screen carries limit copy of its own.
 *
 * Pure Node tests. The mapping module has no DOM; the app.js wiring is driven
 * with a stubbed global fetch and the exported notifier seam.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  LIMIT_TOAST_DURATION_MS,
  createLimitNotifier,
  isLimitError,
  limitNotificationFor,
} from "../console/limit-toast.js";
import { requestGet, requestMutation, runScreenAction, setLimitNotifier } from "../console/app.js";

describe("limit toast mapping", () => {
  it("names the exhausted allowance, its ceiling, and who it belongs to", () => {
    const personal = limitNotificationFor(
      { status: 402, code: "quota_exhausted", feature: "export", limit: 2, message: "x" },
      { owner: true },
    );
    expect(personal).toMatchObject({
      tone: "danger",
      duration: LIMIT_TOAST_DURATION_MS,
      title: "Exports limit reached",
    });
    expect(personal?.message).toBe(
      "You have used all 2 exports included in early access. Open Billing to see every allowance.",
    );

    const team = limitNotificationFor(
      { status: 402, code: "quota_exhausted", feature: "ingest_bytes", limit: 64 * 1024 * 1024 },
      { owner: false },
    );
    expect(team?.title).toBe("Ingested content limit reached");
    expect(team?.message).toBe(
      "Your team has used all 64 MB ingested content included in early access. Ask your organization owner about allowances.",
    );
  });

  it("covers every early-access denial code plus credits, the rate clamp, and the turn guard", () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ status: 402, code: "trial_expired" }, "Early access trial ended"],
      [{ status: 402, code: "seat_limit", limit: 5 }, "Team seat limit reached"],
      [{ status: 402, code: "spend_cap", limit: 5 }, "Assistant spending cap reached"],
      [{ status: 402, code: "model_not_allowed" }, "Model not included in your plan"],
      [{ status: 402, code: "unpriced_model", message: "no trusted price" }, "Model unavailable right now"],
      [{ status: 402, code: "credits_exhausted", message: "no credits" }, "Credits exhausted"],
      [{ status: 402, code: "something_new", message: "nope" }, "Allowance reached"],
      [{ status: 429, code: "rate_limited", retryAfter: 7 }, "Request limit reached"],
      [{ status: 409, code: "turn_in_progress" }, "Assistant is still answering"],
    ];
    for (const [error, title] of cases) {
      const note = limitNotificationFor(error);
      expect(note?.title, JSON.stringify(error)).toBe(title);
      expect(note?.tone).toBe("danger");
      expect((note?.message ?? "").length).toBeGreaterThan(12);
    }
    expect(limitNotificationFor({ status: 429, retryAfter: 7 })?.message).toContain("Try again in 7s.");
    expect(limitNotificationFor({ status: 402, code: "seat_limit", limit: 5 })?.message)
      .toContain("5 seats per team");
  });

  it("leaves non-limit failures to the screen's own error region", () => {
    for (const error of [
      { status: 400, code: "invalid_body", message: "bad" },
      { status: 404, message: "missing" },
      { status: 409, code: "conflict", message: "busy" },
      { status: 500, message: "boom" },
      { status: 0, message: "network error" },
      null,
      undefined,
      "nope",
    ]) {
      expect(limitNotificationFor(error as never), JSON.stringify(error)).toBeNull();
      expect(isLimitError(error as never)).toBe(false);
    }
    expect(isLimitError({ status: 402, code: "quota_exhausted", feature: "retrieval", limit: 1 })).toBe(true);
  });

  it("dedupes identical limits inside the window and lets distinct ones through", () => {
    let clock = 1_000;
    const show = vi.fn();
    const notifier = createLimitNotifier({ show }, { now: () => clock, windowMs: 4000 });
    const denial = { status: 402, code: "trial_expired" };

    expect(notifier.notify(denial)).toBe(true);
    expect(notifier.notify(denial)).toBe(false);
    expect(notifier.notify({ status: 402, code: "quota_exhausted", feature: "file", limit: 25 })).toBe(true);
    clock += 4001;
    expect(notifier.notify(denial)).toBe(true);
    expect(notifier.notify({ status: 404, message: "nothing" })).toBe(false);
    expect(show).toHaveBeenCalledTimes(3);
  });
});

describe("API client wiring", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    setLimitNotifier(null);
  });

  function stubResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
      text: async () => JSON.stringify(body),
    }) as unknown as typeof fetch;
  }

  it("reports a 402 denial to the notifier with feature and limit, and still throws it", async () => {
    const notify = vi.fn();
    setLimitNotifier({ notify });
    stubResponse(402, {
      error: "The early-access export allowance has been exhausted.",
      code: "quota_exhausted",
      feature: "export",
      limit: 2,
    });

    await expect(requestMutation("POST", "/v1/mem/export", {})).rejects.toMatchObject({
      status: 402,
      code: "quota_exhausted",
      feature: "export",
      limit: 2,
    });
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify.mock.calls[0][0]).toMatchObject({ status: 402, feature: "export", limit: 2 });
  });

  it("reports a 429 with its retry-after and a 402 on GET reads too", async () => {
    const notify = vi.fn();
    setLimitNotifier({ notify });
    stubResponse(429, { error: "rate limit exceeded", code: "rate_limited" }, { "retry-after": "12" });
    await expect(requestGet("/v1/admin/usage?limit-probe=1")).rejects.toMatchObject({ status: 429 });
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ status: 429, retryAfter: 12 }));
  });

  it("never lets a notifier fault change the typed failure a screen receives", async () => {
    setLimitNotifier({ notify: () => { throw new Error("toaster exploded"); } });
    stubResponse(402, { error: "denied", code: "trial_expired" });
    await expect(requestMutation("POST", "/v1/mem/write", {})).rejects.toMatchObject({
      status: 402,
      code: "trial_expired",
    });
  });

  it("stays silent for ordinary failures", async () => {
    const notify = vi.fn();
    setLimitNotifier({ notify });
    stubResponse(404, { error: "not found" });
    await expect(requestGet("/v1/admin/nothing?limit-probe=2")).rejects.toMatchObject({ status: 404 });
    // The notifier is called for every failure; the mapping decides silence.
    expect(notify).toHaveBeenCalledTimes(1);
    expect(limitNotificationFor(notify.mock.calls[0][0])).toBeNull();
  });
});

describe("screen-action dispatcher", () => {
  function fakeStage() {
    const prepend = vi.fn();
    const created: Array<Record<string, unknown>> = [];
    return {
      prepend,
      created,
      stage: {
        prepend,
        querySelector: () => null,
        querySelectorAll: () => [],
        ownerDocument: {
          createElement: () => {
            const el = {
              className: "",
              textContent: "",
              setAttribute: vi.fn(),
              focus: vi.fn(),
            };
            created.push(el);
            return el;
          },
        },
      },
    };
  }

  it("paints no generic failure card for a limit denial - the toast already said it", async () => {
    const { stage, prepend } = fakeStage();
    const action = vi.fn().mockRejectedValue({
      status: 402,
      code: "quota_exhausted",
      feature: "export",
      limit: 2,
      message: "The early-access export allowance has been exhausted.",
    });
    await runScreenAction(action, { api: {} }, {}, stage, undefined, "generate");
    expect(action).toHaveBeenCalledTimes(1);
    expect(prepend).not.toHaveBeenCalled();
  });

  it("still paints the generic failure card for an ordinary failure", async () => {
    const { stage, prepend, created } = fakeStage();
    const action = vi.fn().mockRejectedValue({ status: 500, message: "export backend down" });
    await runScreenAction(action, { api: {} }, {}, stage, undefined, "generate");
    expect(prepend).toHaveBeenCalledTimes(1);
    expect(created[0]?.textContent).toBe("export backend down");
  });
});
