/**
 * Console information architecture: Teams owns humans; Agents owns machines.
 * Pure-Node render tests use the same string-rendered screen contract as the
 * existing console suite and make no browser/network calls.
 */

import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const team = {
  id: "team_platform",
  namespace: "acme/platform",
  name: "Platform",
  description: "Builds the product",
  createdBy: "owner@acme.test",
  createdAt: "2026-07-20T00:00:00.000Z",
  memoryAccess: {
    mode: "related",
    version: 1,
    canBroaden: true,
    canTighten: true,
  },
  members: [{
    userId: "user_human",
    email: "human@acme.test",
    displayName: "Human Person",
    namespace: "acme/platform",
    role: "member",
    addedAt: "2026-07-20T00:00:00.000Z",
  }, {
    userId: "user_email_only",
    email: "member-two@acme.test",
    displayName: "Second Member",
    namespace: "acme/platform",
    role: "member",
    addedAt: "2026-07-21T00:00:00.000Z",
  }],
};

const people = {
  users: [{
    id: "user_human",
    email: "human@acme.test",
    displayName: "Human Person",
    namespace: "acme/platform",
    role: "member",
    status: "active",
  }, {
    id: "user_email_only",
    email: "member-two@acme.test",
    displayName: "Second Member",
    namespace: "acme/platform",
    role: "member",
    status: "active",
  }],
  badges: [{
    id: "key_agent",
    actor: "support-agent",
    namespace: "acme/platform",
    role: "agent",
    status: "active",
  }],
  accessModel: {
    owner: ["teams:read", "teams:write", "members:invite", "members:write", "roles:write"],
    admin: ["teams:read", "teams:write", "members:invite", "members:write"],
    auditor: ["teams:read"],
    member: [],
  },
};

function makeCtx(role: "owner" | "admin" | "auditor" = "owner") {
  const calls: Array<{ method: string; path: string; body?: unknown }> = [];
  const ctx = {
    esc,
    identity: {
      keyId: "session",
      namespace: "acme",
      actor: `${role}@acme.test`,
      role,
    },
    async go() {},
    api: {
      async get(path: string) {
        calls.push({ method: "GET", path });
        if (path === "/v1/admin/teams") return [team];
        if (path === "/v1/admin/team-directory") return people;
        if (path === "/v1/admin/people") return people;
        if (path === "/v1/admin/keys") return { keys: [{
          id: "key_agent",
          actor: "support-agent",
          namespace: "acme/platform",
          role: "agent",
          status: "active",
          createdAt: "2026-07-20T00:00:00.000Z",
        }] };
        if (path === "/v1/admin/sources") return { sources: [] };
        if (path === "/v1/admin/agent-connections") return { grants: [] };
        if (path.includes("/v1/admin/agent-access/events")) return { events: [] };
        if (path.includes("/v1/admin/agent-access/alerts")) return { alerts: [] };
        if (path.includes("/v1/admin/agent-access/requests")) return { requests: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      async post(path: string, body?: unknown) {
        calls.push({ method: "POST", path, body });
        return { invite: { namespace: team.namespace }, activationToken: "one-time-token" };
      },
      async put(path: string, body?: unknown) {
        calls.push({ method: "PUT", path, body });
        return {};
      },
      async del(path: string) {
        calls.push({ method: "DELETE", path });
        return {};
      },
    },
    ui: {
      empty(message: string) { return `<div class="card">${message}</div>`; },
    },
  };
  return { ctx, calls };
}

async function render(screen: "s3" | "s13", role: "owner" | "admin" | "auditor" = "owner") {
  const path = fileURLToPath(new URL(`../console/screens/${screen}.js`, import.meta.url));
  const mod = await import(path) as {
    render(ctx: unknown): Promise<string>;
    actions?: Record<string, (ctx: unknown, el: unknown) => Promise<void> | void>;
  };
  const { ctx, calls } = makeCtx(role);
  return { html: await mod.render(ctx), calls, ctx, mod };
}

describe("Teams and Scoped memory navigation", () => {
  it("contains one Teams item and one Scoped memory item with no legacy people label", async () => {
    const app = await readFile(
      fileURLToPath(new URL("../console/app.js", import.meta.url)),
      "utf8",
    );
    expect(app.match(/label:\s*"Teams"/g)).toHaveLength(1);
    expect(app.match(/label:\s*"Scoped memory"/g)).toHaveLength(1);
    expect(app).not.toContain('label: "Agents"');
    expect(app).not.toContain('label: "Org &amp; people"');
    expect(app).not.toContain('label: "People &amp; access"');
  });

  it("keeps the Teams detail and roster bounded on mobile", async () => {
    const css = await readFile(
      fileURLToPath(new URL("../console/app.css", import.meta.url)),
      "utf8",
    );
    expect(css).toContain(".teams-detail,.teams-card{min-width:0}");
    expect(css).toContain(".teams-card .tblwrap{max-width:100%;overflow-x:auto}");
  });
});

describe("Teams screen owns human organization controls", () => {
  it("renders human members, invitations, and owner role controls only", async () => {
    const { html, calls } = await render("s13", "owner");
    expect(html).toContain("<h1>Teams</h1>");
    expect(html).toContain("Human Person");
    expect(html).toContain("human@acme.test");
    expect(html).toContain("member-two@acme.test");
    expect(html).toContain(">Second Member</b>");
    expect(html).not.toContain(">member-two</b>");
    expect(html).toContain('data-user="user_human"');
    expect(html).toContain("Invite Person");
    expect(html).toContain('id="team-invite-name"');
    expect(html).toContain('maxlength="80" required');
    expect(html).toContain('data-action="team-member-role"');
    expect(html).toContain("Assign roles");
    expect(html).not.toContain('id="invite-namespace"');

    expect(html).not.toContain("support-agent");
    expect(html).not.toContain("Agent badges");
    expect(html).not.toContain("Issue agent badge");
    expect(html).not.toContain("API keys");
    expect(calls).toContainEqual({ method: "GET", path: "/v1/admin/team-directory" });
    expect(calls).not.toContainEqual({ method: "GET", path: "/v1/admin/people" });
  });

  it("lets an admin manage people but does not render existing-role assignment", async () => {
    const { html } = await render("s13", "admin");
    expect(html).toContain("Invite Person");
    expect(html).toContain("Add Existing Member");
    expect(html).not.toContain('data-action="team-member-role"');
  });

  it("renders an auditor read-only with no invitation or mutation controls", async () => {
    const { html } = await render("s13", "auditor");
    expect(html).toContain("human@acme.test");
    expect(html).not.toContain("Invite Person");
    expect(html).not.toContain("Add Existing Member");
    expect(html).not.toContain("Remove");
    expect(html).not.toContain('data-action="team-member-role"');
    expect(html).toContain('role="switch"');
    expect(html).toContain("Company memory");
    expect(html).toContain("Reads own scope only");
    expect(html).toMatch(/data-change-action="team-memory-access"[^>]*disabled/);
  });

  it("renders an accessible company-memory switch with fail-closed related copy", async () => {
    const { html } = await render("s13", "owner");
    expect(html).toContain("Company memory");
    expect(html).toContain('type="checkbox"');
    expect(html).toContain('role="switch"');
    expect(html).toContain('data-change-action="team-memory-access"');
    expect(html).toContain('data-current-mode="related"');
    expect(html).toContain('aria-describedby="team-memory-access-description team-memory-access-status"');
    expect(html).toContain("Reads own scope only");
  });

  it("updates through the exact team route without sending namespace or navigating", async () => {
    const { ctx, calls, mod } = await render("s13", "owner");
    let navigated = false;
    ctx.go = async () => { navigated = true; };
    ctx.api.put = async (path: string, body?: unknown) => {
      calls.push({ method: "PUT", path, body });
      return {
        ...team,
        memoryAccess: {
          mode: "company-published",
          version: 2,
          canBroaden: true,
          canTighten: true,
        },
      };
    };
    const description = { textContent: "" };
    const status = { textContent: "" };
    const section = {
      setAttribute() {},
      removeAttribute() {},
      querySelector: (selector: string) => ({
        "#team-memory-access-description": description,
        "#team-memory-access-status": status,
      }[selector] ?? null),
    };
    const input = {
      checked: true,
      disabled: false,
      closest: () => section,
      getAttribute: (name: string) => ({
        "data-team": team.id,
        "data-current-mode": "related",
      }[name] ?? null),
      setAttribute() {},
    };

    await mod.actions?.["team-memory-access"]?.(ctx, input);

    expect(calls).toContainEqual({
      method: "PUT",
      path: `/v1/admin/teams/${team.id}/memory-access`,
      body: { mode: "company-published" },
    });
    expect(calls.find((call) => call.path.endsWith("/memory-access"))?.body)
      .not.toHaveProperty("namespace");
    expect(status.textContent).toBe("Company memory is on.");
    expect(description.textContent).toContain("company-published memory");
    expect(navigated).toBe(false);
  });

  it("restores the prior switch state and announces a failed update", async () => {
    const { ctx, mod } = await render("s13", "owner");
    ctx.api.put = async () => { throw new Error("policy write failed"); };
    const description = { textContent: "" };
    const status = { textContent: "" };
    const section = {
      setAttribute() {},
      removeAttribute() {},
      querySelector: (selector: string) => ({
        "#team-memory-access-description": description,
        "#team-memory-access-status": status,
      }[selector] ?? null),
    };
    const attributes = new Map<string, string>([
      ["data-team", team.id],
      ["data-current-mode", "related"],
    ]);
    const input = {
      checked: true,
      disabled: false,
      closest: () => section,
      getAttribute: (name: string) => attributes.get(name) ?? null,
      setAttribute: (name: string, value: string) => attributes.set(name, value),
    };

    await mod.actions?.["team-memory-access"]?.(ctx, input);

    expect(input.checked).toBe(false);
    expect(input.disabled).toBe(false);
    expect(attributes.get("data-current-mode")).toBe("related");
    expect(status.textContent).toBe("Memory access update failed: policy write failed");
  });

  it("invites through the selected-team route without sending a namespace", async () => {
    const { ctx, calls, mod } = await render("s13", "owner");
    const action = mod.actions?.["team-invite-submit"];
    expect(action).toBeTypeOf("function");

    const nodes: Record<string, { value?: string; textContent?: string }> = {
      "#team-invite-name": { value: "New Human" },
      "#team-invite-email": { value: "new-human@acme.test" },
      "#team-invite-role": { value: "member" },
      "#team-invite-status": { textContent: "" },
    };
    const root = { querySelector: (selector: string) => nodes[selector] ?? null };
    const button = {
      disabled: false,
      textContent: "Invite person",
      closest: () => root,
      getAttribute: (name: string) => name === "data-team" ? team.id : null,
    };
    await action!(ctx, button);

    expect(calls).toContainEqual({
      method: "POST",
      path: `/v1/admin/teams/${team.id}/invitations`,
      body: { displayName: "New Human", email: "new-human@acme.test", role: "member" },
    });
    const inviteCall = calls.find((call) => call.path.endsWith("/invitations"));
    expect(inviteCall?.body).not.toHaveProperty("namespace");
  });

  it("announces a rejected role change and restores the prior role", async () => {
    const { ctx, mod } = await render("s13", "owner");
    ctx.api.put = async () => { throw new Error("final active owner"); };
    const status = { textContent: "" };
    const root = { querySelector: (selector: string) => selector === "#team-role-status" ? status : null };
    const select = {
      value: "admin",
      disabled: false,
      closest: () => root,
      getAttribute: (name: string) => ({
        "data-team": team.id,
        "data-user": team.members[0].userId,
        "data-current-role": "owner",
      }[name] ?? null),
    };

    await mod.actions?.["team-member-role"]?.(ctx, select);

    expect(select.value).toBe("owner");
    expect(status.textContent).toContain("Role change failed: final active owner");
  });
});

describe("Scoped memory screen owns machine-principal controls", () => {
  it("keeps rotate and revoke actions compact on desktop", async () => {
    const [css, shell] = await Promise.all([
      readFile(fileURLToPath(new URL("../console/app.css", import.meta.url)), "utf8"),
      readFile(fileURLToPath(new URL("../console/index.html", import.meta.url)), "utf8"),
    ]);
    expect(css).toContain(".sm-cell-acts .btn{min-height:30px;padding:4px 9px;font-size:11.5px}");
    expect(css).toMatch(/\.sm-thead,\.sm-row\{grid-template-columns:[^}]* 128px 30px\}/);
    expect(shell).toContain('href="app.css?v=20260821-1"');
  });

  it("renders badge identity/access/keys without humans or invitations", async () => {
    const { html } = await render("s3", "owner");
    expect(html).toContain("<h1>Scope Memory</h1>");
    expect(html).toContain("support-agent");
    // Creating a badge is one inline row, always on screen - no wizard.
    expect(html).toContain("Create scoped badge");
    expect(html).not.toContain("Deploy an agent");
    expect(html).toContain("Badges &amp; credentials");

    expect(html).not.toContain("human@acme.test");
    expect(html).not.toContain("Invite person");
    expect(html).not.toContain("Human logins");
    expect(html).not.toContain("people-invite");
  });
});
