import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  createPersonDirectory,
  organizationScopeLabel,
  personAvatarHtml,
  personAvatarUrl,
  personDisplayName,
} from "../console/identity-labels.js";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function ui() {
  return {
    empty: (message: string) => `<div>${message}</div>`,
    head: ({ title }: { title?: string }) => `<h1>${title ?? ""}</h1>`,
    pill: (text: string) => `<span>${text}</span>`,
    table: ({ rows }: { rows: unknown[][] }) => JSON.stringify(rows),
  };
}

describe("shared console organization labels", () => {
  it("shows the canonical organization slug without the authority suffix", () => {
    const namespace = "halofy-demo-workspace-zze0nmav";

    expect(organizationScopeLabel(
      namespace,
      "Halofy Demo Workspace",
      namespace,
    )).toBe("halofy-demo-workspace");
    expect(organizationScopeLabel(
      `${namespace}/customer-success`,
      "Halofy Demo Workspace",
      namespace,
    )).toBe("halofy-demo-workspace/customer-success");
    expect(organizationScopeLabel(namespace)).toBe("halofy-demo-workspace");
  });

  it("does not rewrite an unrelated namespace as the current organization", () => {
    expect(organizationScopeLabel(
      "partner-space",
      "Halofy Demo Workspace",
      "halofy-demo-workspace-zze0nmav",
    )).toBe("partner-space");
    expect(organizationScopeLabel("", "Halofy Demo Workspace", "")).toBe(
      "Organization root",
    );
  });

  it("uses the shared organization labeler on organization-scoped screen headers", async () => {
    const files = [
      "screens/s2.js",
      "screens/s4.js",
      "screens/s5.js",
      "screens/s6.js",
      "screens/s8.js",
      "screens/s9.js",
      "screens/s13.js",
      "screens/s14.js",
      "screens/s18.js",
      "screens/s20.js",
    ];
    for (const relative of files) {
      const source = await readFile(
        fileURLToPath(new URL(`../console/${relative}`, import.meta.url)),
        "utf8",
      );
      expect(source, relative).toContain("organizationScopeLabel");
    }
  });
});

describe("shared console person labels", () => {
  it("resolves only safe explicit or human-directory portrait URLs", () => {
    const avatar = "data:image/png;base64,iVBORw0KGgo=";
    const directory = createPersonDirectory({
      email: "ana@halofy.ai",
      displayName: "Ana Ortiz",
      avatar,
    });

    expect(personAvatarUrl({ avatar })).toBe(avatar);
    expect(personAvatarUrl(
      { email: "ana@halofy.ai" },
      { avatar: directory.avatar, principal: "human" },
    )).toBe(avatar);
    expect(personAvatarUrl(
      { email: "ana@halofy.ai" },
      { avatar: directory.avatar, principal: "agent" },
    )).toBeNull();
    expect(personAvatarUrl({ avatar: "javascript:alert(1)" })).toBeNull();
  });

  it("renders a safe portrait with initials fallback and the full name on hover", () => {
    const avatar = "data:image/png;base64,iVBORw0KGgo=";
    const directory = createPersonDirectory({
      email: "ana@halofy.ai",
      displayName: "Ana Ortiz",
      avatar,
    });

    expect(directory.avatar("ana@halofy.ai")).toBe(avatar);
    expect(personAvatarHtml(
      { email: "ana@halofy.ai" },
      { esc, label: directory.label, avatar: directory.avatar },
    )).toBe(
      '<span class="person-avatar" role="img" aria-label="Ana Ortiz" title="Ana Ortiz">' +
      '<span class="person-avatar__fallback" aria-hidden="true">AO</span>' +
      '<img class="person-avatar__image" data-person-avatar-image src="data:image/png;base64,iVBORw0KGgo=" alt="" decoding="async">' +
      '</span>',
    );

    directory.remember({ email: "ana@halofy.ai", displayName: "Ana Ortiz", avatar: null });
    expect(directory.avatar("ana@halofy.ai")).toBeNull();
    expect(personAvatarHtml(
      { email: "ana@halofy.ai" },
      { esc, label: directory.label, avatar: directory.avatar },
    )).toContain('title="Ana Ortiz"><span class="person-avatar__fallback" aria-hidden="true">AO</span>');
    expect(personAvatarHtml(
      { email: "ana@halofy.ai", displayName: "<Ana & Co>" },
      { esc },
    )).toContain('aria-label="&lt;Ana &amp; Co&gt;"');
  });

  it("prefers a stored display name and keeps email as the fallback key", () => {
    const directory = createPersonDirectory({
      actor: "owner.one@acme.test",
      displayName: "Owner One",
    });
    directory.remember([
      { email: "ana@halofy.ai", displayName: "Ana Ortiz" },
      { email: "fallback@halofy.ai", displayName: null },
    ]);

    expect(directory.label("owner.one@acme.test")).toBe("Owner One");
    expect(directory.label({ email: "ana@halofy.ai" })).toBe("Ana Ortiz");
    expect(directory.label("fallback@halofy.ai")).toBe("fallback@halofy.ai");
    directory.remember({
      email: "owner.one@acme.test",
      displayName: null,
    });
    expect(directory.label("owner.one@acme.test")).toBe(
      "owner.one@acme.test",
    );
    expect(personDisplayName({
      email: "owner.one@acme.test",
      displayName: "  Owner One  ",
    })).toBe("Owner One");
  });

  it("does not apply a human directory label to an unverified or agent actor", () => {
    const directory = createPersonDirectory({
      email: "shared@halofy.ai",
      displayName: "Human Name",
    });

    expect(personDisplayName("shared@halofy.ai", directory.label)).toBe(
      "shared@halofy.ai",
    );
    expect(personDisplayName("shared@halofy.ai", directory.label, "agent")).toBe(
      "shared@halofy.ai",
    );
    expect(personDisplayName("shared@halofy.ai", directory.label, "human")).toBe(
      "Human Name",
    );
  });

  it("renders the Home leaderboard with the human name, not the email actor", async () => {
    const screen = await import(fileURLToPath(new URL("../console/screens/s2.js", import.meta.url)));
    const overview = {
      namespace: "halofy",
      children: [],
      l2Active: 1,
      faultCount: 0,
      faultHitRate: 1,
      spend: { monthToDateUsd: 0, effectiveCapUsd: null },
      usage: { totalTokens: 1, totalUsd: 0 },
      sourcesSummary: { connectedCount: 0, connected: [] },
      topTeams: [{ name: "halofy", count: 11 }],
      topActors: [{
        name: "owner.one@acme.test",
        displayName: "Owner One",
        count: 11,
      }],
      querySummary: { total: 1, hits: 1, misses: 0, hitRate: 1, topQueries: [] },
      agentAccess: {
        totalAgents: 0,
        withinPolicy: 0,
        overreaching: [],
        accessEvents: { allowed: 0, denied: 0, error: 0 },
        accessRequests: { pending: 0, approved: 0, denied: 0, expired: 0, consumed: 0 },
      },
    };
    const routes: Record<string, unknown> = {
      "/v1/admin/overview": overview,
      "/v1/admin/people": {
        users: [{
          id: "u1",
          email: "owner.one@acme.test",
          displayName: "Owner One",
          namespace: "halofy",
          role: "root",
          status: "active",
        }],
        badges: [],
      },
    };
    const ctx = {
      esc,
      ui: ui(),
      identity: { namespace: "halofy", actor: "owner.one@acme.test", role: "root" },
      api: {
        async get(path: string) {
          if (path in routes) return routes[path];
          throw { status: 404, message: "optional route unavailable" };
        },
      },
    };

    const html = await screen.render(ctx);
    expect(html).toContain("Owner One");
    expect(html).not.toContain(">owner.one@acme.test<");
  });

  it("names people in the audit filter without rewriting audit actor keys", async () => {
    const screen = await import(fileURLToPath(new URL("../console/screens/s8.js", import.meta.url)));
    const actor = "ana@halofy.ai";
    const ctx = {
      esc,
      identity: { namespace: "halofy", actor: "owner@halofy.ai", role: "owner" },
      personLabel(subject: unknown, principal?: string) {
        return principal === "human" && String(subject) === actor ? "Ana Ortiz" : String(subject ?? "");
      },
      api: {
        async get(path: string) {
          if (path.startsWith("/v1/admin/audit")) return [{
            ts: "2026-08-04T00:00:00.000Z",
            actor,
            agentId: "console",
            op: "read",
            memoryId: null,
            namespace: "halofy",
            purpose: null,
            result: "ok",
          }];
          if (path === "/v1/admin/keys") return { keys: [] };
          if (path === "/v1/admin/teams") return [{
            members: [{ email: actor, displayName: "Ana Ortiz" }],
          }];
          throw new Error(`unexpected GET ${path}`);
        },
      },
    };

    const html = await screen.render(ctx);
    expect(html).toContain(`<option value="${actor}">Ana Ortiz</option>`);
    expect(html).toContain(`title="${actor}"`);
    expect(html).not.toContain('title="Ana Ortiz"');
  });

  it("uses the shared person labeler on every console surface that paints human attribution", async () => {
    const files = [
      "app.js",
      "screens/s6.js",
      "screens/s8.js",
      "screens/s11.js",
      "screens/s13.js",
      "screens/s16.js",
      "screens/s17.js",
      "screens/s20.js",
    ];
    for (const relative of files) {
      const source = await readFile(
        fileURLToPath(new URL(`../console/${relative}`, import.meta.url)),
        "utf8",
      );
      expect(source, relative).toContain("personDisplayName");
    }
  });

  it("uses compact member avatars in every table that paints a human", async () => {
    const files = [
      "screens/s6.js",
      "screens/s8.js",
      "screens/s13.js",
      "screens/s16.js",
    ];
    for (const relative of files) {
      const source = await readFile(
        fileURLToPath(new URL(`../console/${relative}`, import.meta.url)),
        "utf8",
      );
      expect(source, relative).toContain("ctx.personAvatar");
    }
  });
});
