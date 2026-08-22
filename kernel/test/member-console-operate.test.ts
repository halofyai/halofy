import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { CLIENTS, render as renderConnections } from "../console/screens/s14.js";
import { render as renderProfile } from "../console/screens/s18.js";
import { render as renderSources } from "../console/screens/s6.js";

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
    head({ eyebrow, title, acts }: { eyebrow?: string; title?: string; acts?: string } = {}) {
      return `<div>${eyebrow ?? ""}<h1>${title ?? ""}</h1>${acts ?? ""}</div>`;
    },
    pill(text: string) {
      return `<span>${text}</span>`;
    },
  };
}

describe("member operating console", () => {
  it("gives members the exact operating screens and keeps usage analytics outside Govern", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../console/app.js", import.meta.url)),
      "utf8",
    );

    expect(source).toContain(
      'member: ["s2", "s5", "s6", "s14", "s10", "s16", "s15", "s18"]',
    );
    const operate = source.slice(source.indexOf('group: "Operate"'), source.indexOf('group: "Govern"'));
    const govern = source.slice(source.indexOf('group: "Govern"'), source.indexOf('group: "Onboard"'));
    expect(operate).toContain('{ s: "s15", icon: "score", label: "Usage analytics", memberOperate: true }');
    expect(govern).toContain('{ s: "s15", icon: "score", label: "Usage analytics", governance: true }');
    expect(source).toContain('if (item.memberOperate === true && !operatingMember) return false;');
    expect(source).toContain('if (item.governance === true && operatingMember) return false;');
    for (const governed of ["s13", "s3", "s19", "s4", "s7", "s11", "s8", "s20", "s17", "s12"]) {
      expect(source).not.toMatch(new RegExp(`member:\\s*\\[[^\\]]*"${governed}"`));
    }
  });

  it("renders member agent self-service at the exact readonly team scope", async () => {
    const get = vi.fn(async (path: string) => {
      if (path === "/v1/admin/keys") return { keys: [] };
      throw new Error(`unexpected GET ${path}`);
    });
    const html = await renderConnections({
      esc,
      identity: { role: "member", namespace: "acme/support" },
      ui: ui(),
      api: { get },
      go: vi.fn(),
    });

    expect(get).toHaveBeenCalledWith("/v1/admin/keys");
    expect(html).toContain('id="intg-ns" value="acme/support"');
    expect(html).toContain('readonly aria-readonly="true"');
    expect(html).toContain('data-action="intg-mint"');
    expect(html).toContain('id="intg-mint-status" role="status" aria-live="polite"');
    expect(html).not.toContain("Assistant access is fixed to your team");
    expect(html).not.toContain("Manage in Agents");
    expect(html).not.toContain("Connected apps");
    expect(html).not.toContain(">Admin</span>");
    expect(html).not.toContain(">Read-only</span>");
    const chatgpt = CLIENTS.find((client) => client.id === "chatgpt");
    const memberSteps = chatgpt?.build("https://halomem.example", "", {
      identity: { role: "member" },
    });
    const ownerSteps = chatgpt?.build("https://halomem.example", "", {
      identity: { role: "owner" },
    });
    expect(memberSteps?.map((step) => step.note).join(" ")).toContain(
      "disconnect it from ChatGPT at any time",
    );
    expect(ownerSteps?.map((step) => step.note).join(" ")).toContain(
      "revoke it any time from Connected apps",
    );
  });

  it("uses the self profile to label member knowledge without calling Teams governance", async () => {
    const get = vi.fn(async (path: string) => {
      if (path === "/v1/admin/sources") return { sources: [], overview: [], overviewDegraded: true };
      if (path === "/v1/admin/knowledge-bases") {
        return { data: [{ id: "kb-team", name: "Team playbook", targetTeamId: "team_support", status: "ready" }] };
      }
      if (path.startsWith("/v1/admin/company-files?")) return { data: [] };
      if (path.startsWith("/v1/admin/knowledge-bases/kb-team/sources")) return { data: [] };
      if (path === "/auth/profile") {
        return {
          homeNamespace: "acme/support",
          teams: [{ id: "team_support", name: "Support", namespace: "acme/support", isHome: true }],
        };
      }
      if (path === "/v1/admin/connectors") return { connectors: [] };
      throw new Error(`unexpected GET ${path}`);
    });
    const html = await renderSources({
      esc,
      identity: { role: "member", namespace: "acme/support" },
      ui: ui(),
      api: { get },
    });

    expect(get).toHaveBeenCalledWith("/auth/profile");
    expect(get).not.toHaveBeenCalledWith("/v1/admin/teams");
    expect(html).toContain("Support");
    expect(html).not.toContain("Restricted team");
  });

  it("shows only the signed-in profile response as a team portfolio", async () => {
    const get = vi.fn(async (path: string) => {
      if (path === "/auth/profile") {
        return {
          homeNamespace: "acme/support",
          teams: [
            { id: "team_support", name: "Support", namespace: "acme/support", isHome: true },
            { id: "team_launch", name: "Launch", namespace: "acme/launch", isHome: false },
          ],
        };
      }
      if (path === "/auth/identities") return { identities: [], hasPassword: true };
      if (path === "/auth/sso/config") return { enabled: false, github: false };
      throw new Error(`unexpected GET ${path}`);
    });

    const html = await renderProfile({
      esc,
      identity: { role: "member", actor: "member@acme.test", namespace: "acme/support" },
      api: { get },
    });

    expect(get).toHaveBeenCalledWith("/auth/profile");
    expect(html).toContain("Your teams");
    expect(html).toContain("Support");
    expect(html).toContain("Launch");
    expect(html).not.toContain("acme/support");
    expect(html).not.toContain("acme/launch");
    expect(html).toContain("Home</span>");
  });

  it("browns out profile memberships without hiding the resolved current team", async () => {
    const get = vi.fn(async (path: string) => {
      if (path === "/auth/profile") throw new Error("temporarily unavailable");
      if (path === "/auth/identities") return { identities: [], hasPassword: true };
      if (path === "/auth/sso/config") return { enabled: false, github: false };
      throw new Error(`unexpected GET ${path}`);
    });

    const html = await renderProfile({
      esc,
      identity: { role: "member", actor: "member@acme.test", namespace: "acme/support" },
      api: { get },
    });

    expect(html).toContain("<dt>Workspace</dt><dd>Support</dd>");
    expect(html).not.toContain("acme/support");
    expect(html).toContain("Additional team memberships are temporarily unavailable");
  });
});
