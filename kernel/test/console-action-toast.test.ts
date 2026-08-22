import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  confirmationFor,
  toastMarkup,
} from "../console/action-toast.js";
import { runScreenAction } from "../console/app.js";

const ROOT = resolve(import.meta.dirname, "..");

describe("console action confirmations", () => {
  it("defines relevant confirmations for mutation CTAs across the console", () => {
    const expected = {
      "org-name-save": "Organization updated",
      "policy-save": "Policy saved",
      "policy-adopt": "Policy adopted",
      "badge-create": "Agent key created",
      "create-knowledge-base": "Knowledge base created",
      "pause-source": "Source disconnected",
      "resume-source": "Source reconnected",
      "proposal-approve": "Knowledge approved",
      "audit-erase": "Erasure completed",
      "routine-create": "Routine created",
      "run-conflict-scan": "Conflict scan started",
      "model-connection-create": "Model deployed",
      "team-create": "Team created",
      "intg-mint": "Agent key created",
      "skill-create": "Skill submitted",
      "oauth-client-submit": "OAuth client created",
      "usage-cap-save": "Usage cap saved",
      "alerts-acknowledge": "Alert acknowledged",
      generate: "Export ready",
      "s21-create": "Channel created",
    };

    for (const [action, title] of Object.entries(expected)) {
      expect(confirmationFor(action)?.title, action).toBe(title);
      expect(confirmationFor(action)?.message.length, action).toBeGreaterThan(8);
    }
  });

  it("does not toast navigation, filtering, modal, or draft-only controls", () => {
    for (const action of [
      "settings-tab",
      "team-modal-open",
      "policy-library-filter",
      "topo-zoom-in",
      "set-scope",
      "profile-method-close",
    ]) {
      expect(confirmationFor(action), action).toBeNull();
    }
  });

  it("notifies only after a successful request-backed action", async () => {
    const notify = vi.fn();
    const api = { patch: vi.fn().mockResolvedValue({ name: "Halofy" }) };
    const stage = { querySelector: () => null };

    await runScreenAction(
      async (ctx) => { await ctx.api.patch("/v1/admin/organization", { name: "Halofy" }); },
      { api, notify },
      {},
      stage,
      undefined,
      "org-name-save",
    );

    expect(notify).toHaveBeenCalledWith(expect.objectContaining({
      title: "Organization updated",
      message: "The workspace name was saved.",
    }));
  });

  it("suppresses confirmation when a screen catches a failed request", async () => {
    const notify = vi.fn();
    const api = { patch: vi.fn().mockRejectedValue(new Error("offline")) };
    const stage = { querySelector: () => null };

    await runScreenAction(
      async (ctx) => {
        try { await ctx.api.patch("/v1/admin/organization", { name: "Halofy" }); }
        catch { /* the screen keeps its inline error */ }
      },
      { api, notify },
      {},
      stage,
      undefined,
      "org-name-save",
    );

    expect(notify).not.toHaveBeenCalled();
  });

  it("suppresses request-backed confirmation when validation exits before a request", async () => {
    const notify = vi.fn();
    const stage = { querySelector: () => null };

    await runScreenAction(
      async () => undefined,
      { api: { patch: vi.fn() }, notify },
      {},
      stage,
      undefined,
      "org-name-save",
    );

    expect(notify).not.toHaveBeenCalled();
  });

  it("requires an explicit true result for clipboard and download confirmations", async () => {
    const notify = vi.fn();
    const stage = { querySelector: () => null };
    const context = { api: {}, notify };

    await runScreenAction(async () => false, context, {}, stage, undefined, "audit-copy");
    expect(notify).not.toHaveBeenCalled();

    await runScreenAction(async () => true, context, {}, stage, undefined, "audit-copy");
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ title: "Audit ID copied" }));
  });

  it("renders escaped, dismissible, accessible Halofy toast markup", () => {
    const html = toastMarkup({
      title: '<Saved & ready>',
      message: 'The "workspace" changed.',
    }, "toast-7");

    expect(html).toContain('class="action-toast"');
    expect(html).toContain('data-action-toast-id="toast-7"');
    expect(html).toContain('aria-label="Dismiss notification"');
    expect(html).toContain("&lt;Saved &amp; ready&gt;");
    expect(html).toContain("The &quot;workspace&quot; changed.");
    expect(html).not.toContain("<Saved & ready>");
  });

  it("renders a visually distinct danger tone for failure notifications", () => {
    const html = toastMarkup({
      title: "File not uploaded",
      message: "dup.pdf: this exact content is already in the knowledge base",
      tone: "danger",
    }, "toast-9");

    expect(html).toContain("action-toast--danger");
    expect(html).toContain("File not uploaded");
    const css = readFileSync(resolve(ROOT, "console", "app.css"), "utf8");
    expect(css).toContain(".action-toast--danger");
    expect(css).toContain(".action-toast--danger .action-toast__mark");
  });

  it("pins the shared visual and live-region contracts", () => {
    const css = readFileSync(resolve(ROOT, "console", "app.css"), "utf8");
    const app = readFileSync(resolve(ROOT, "console", "app.js"), "utf8");

    expect(css).toContain(".action-toasts{");
    expect(css).toContain(".action-toast{");
    expect(css).toContain("prefers-reduced-motion:reduce");
    expect(app).toContain("createActionToaster");
    expect(app).toContain('actionName');
  });
});
