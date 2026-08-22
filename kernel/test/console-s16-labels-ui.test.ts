import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const SCREEN = fileURLToPath(new URL("../console/screens/s16.js", import.meta.url));

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function skill(over: Record<string, unknown> = {}) {
  return {
    id: "skill_1",
    namespace: "acme/support",
    skillKey: "summarize-ticket",
    name: "Summarize ticket",
    description: "Summarizes a support ticket",
    definition: "Read the ticket and return a factual summary.",
    version: 3,
    createdBy: "system-default-skills",
    createdAt: "2026-08-01T09:00:00.000Z",
    lastVettedAt: "2026-08-01T09:30:00.000Z",
    vettingStatus: "vetted",
    approvalStatus: "approved",
    status: "active",
    tValidTo: null,
    riskBand: "good",
    usage: { agents: 2, invocations: 10, denials: 1 },
    labels: {
      category: "Content & Drafting",
      purpose: "Use when a long support thread needs a short, factual recap.",
      tags: ["summarize", "tickets", "support", "zendesk"],
      handling: ["read-only"],
    },
    ...over,
  };
}

async function load() {
  return import(`${pathToFileURL(SCREEN).href}?labels=${Date.now()}-${Math.random()}`);
}

function context(list: unknown = [skill()]) {
  const calls: Array<{ method: string; path: string; body?: unknown }> = [];
  const detail = {
    skill: skill(),
    vettingRuns: [
      { mode: "llm", status: "passed", startedAt: "2026-08-01T03:30:00.000Z", engineVersions: "halo-llm-guard 3.2", findings: [] },
      { mode: "cisco", status: "passed", startedAt: "2026-08-01T03:30:00.000Z", engineVersions: "skill-scan 2.8.1", findings: [] },
      { mode: "skillspector", status: "passed", startedAt: "2026-08-01T03:30:00.000Z", engineVersions: "skillspector 1.4.0", findings: [] },
    ],
    agents: [
      { actor: "support-bot", namespace: "acme/support", invocations: 96, denials: 0, overrides: 0, lastInvokedAt: "2026-08-01T08:00:00.000Z" },
    ],
    history: [skill(), skill({ id: "skill_0", version: 2, tValidTo: "2026-08-01T09:00:00.000Z" })],
    events: [
      { ts: "2026-08-01T03:30:00.000Z", op: "vet", result: "ok", actor: "System Sweep", detail: "Monthly sweep · 3 lanes" },
    ],
    labelHistory: [
      {
        id: "change_1", field: "tags", before: ["summarize", "support"],
        after: ["summarize", "support", "zendesk"], changedBy: "ananya",
        changedAt: "2026-08-01T09:12:00.000Z",
      },
    ],
  };
  const ctx = {
    esc,
    identity: { keyId: "session", namespace: "acme", actor: "ada", role: "owner" },
    personLabel: (value: unknown) => String(value ?? ""),
    refresh: vi.fn(async () => {}),
    go: vi.fn(async () => {}),
    api: {
      get: vi.fn(async (path: string) => {
        calls.push({ method: "GET", path });
        if (path === "/v1/admin/skills") return list;
        if (path === "/v1/admin/teams") return [];
        if (path === "/v1/admin/skills/skill_1") return detail;
        throw new Error(`unexpected GET ${path}`);
      }),
      post: vi.fn(async (path: string, body?: unknown) => {
        calls.push({ method: "POST", path, body });
        return {};
      }),
      patch: vi.fn(async (path: string, body?: unknown) => {
        calls.push({ method: "PATCH", path, body });
        return { skill: skill() };
      }),
    },
  };
  return { ctx, calls, detail };
}

function modalHarness() {
  const focus = { focus: vi.fn() };
  const modal = {
    hidden: true,
    innerHTML: "",
    setAttribute: vi.fn(),
    querySelector: vi.fn(() => focus),
  };
  vi.stubGlobal("document", {
    getElementById: (id: string) => id === "skill-modal" ? modal : null,
    querySelector: vi.fn(() => null),
    body: { classList: { add: vi.fn(), remove: vi.fn() } },
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
  return modal;
}

describe("S16 labels redesign", () => {
  it("renders the compact reference library without the shared table module", async () => {
    const s16 = await load();
    const skills = Array.from({ length: 10 }, (_, index) => skill({
      id: `skill_${index + 1}`,
      skillKey: `skill-${index + 1}`,
      name: `Skill ${index + 1}`,
    }));
    const { ctx } = context(skills);
    const html = await s16.render(ctx);

    for (const heading of ["Skill", "Category", "Tags", "Team", "Status", "Agents", "Last checked", "Share"]) {
      expect(html).toContain(`role="columnheader">${heading}</div>`);
    }
    expect(html).toContain('class="skill-table-head" role="row"');
    expect(html).toContain('class="skill-row skill-row-grid" role="row"');
    expect(html).not.toContain('<table class="skill-table"');
    expect(html).not.toContain('class="tblwrap skill-table-wrap"');
    expect(html).toContain('class="skill-search-icon"');
    expect(html).toContain('class="skill-filter-icon"');
    expect(html).toContain("Content &amp; Drafting");
    expect(html).toContain(">summarize<");
    expect(html).toContain(">tickets<");
    expect(html).toContain("+2");
    expect(html).toContain('placeholder="Search skills, tags, purpose"');
    expect(html).toContain('data-action="skill-filter-toggle"');
    expect(html).toContain("1–8 of 10 Skills");
    expect(html).toContain('data-action="skill-page-prev" disabled');
    expect(html).toContain('data-action="skill-page-next"');
    expect(html).not.toContain("Skill 9</span>");
    expect(html).not.toContain('data-input-action="skill-team"');
  });

  it("adds purpose, category, tags, suggestions and the external-label note to Add skill", async () => {
    const s16 = await load();
    const { ctx } = context();
    await s16.actions["skill-new"](ctx, { setAttribute: vi.fn() });
    const html = await s16.render(ctx);

    expect(html).toContain('data-skill-purpose');
    expect(html).toContain('maxlength="140"');
    expect(html).toContain('data-skill-category');
    expect(html).toContain('data-skill-tags');
    expect(html).toContain("Suggested Labels");
    expect(html).toContain("Labels help people find this skill. They are not part of the skill file");
  });

  it("matches the compact reference drawer hierarchy and evidence cards", async () => {
    const s16 = await load();
    const { ctx } = context();
    const modal = modalHarness();
    await s16.actions["skill-select"](ctx, {
      getAttribute: () => "skill_1",
      setAttribute: vi.fn(),
      focus: vi.fn(),
    });

    expect(modal.innerHTML).toContain('class="skill-detail-identity"');
    expect(modal.innerHTML).toContain('class="skill-detail-header"');
    expect(modal.innerHTML).toContain('class="skill-detail-action-rail"');
    expect(modal.innerHTML).toContain('class="skill-checks"');
    expect(modal.innerHTML).toContain("Latest Checks");
    expect(modal.innerHTML).toContain("Agents Using This Skill");
    expect(modal.innerHTML).toContain("Earlier Versions");
    expect(modal.innerHTML).toContain("Label History");
    expect(modal.innerHTML).toContain("Activity Log");
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--checks" role="table"');
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--agents" role="table"');
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--versions" role="table"');
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--labels" role="table"');
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--events" role="table"');
    expect(modal.innerHTML).not.toContain("<table");
    expect(modal.innerHTML).not.toContain('class="tblwrap"');
    expect(modal.innerHTML).toContain("Content &amp; Drafting");
    expect(modal.innerHTML).toContain(">zendesk<");
    expect(modal.innerHTML).toContain("read-only");
    expect(modal.innerHTML).toContain('data-action="skill-labels-edit"');
    expect(modal.innerHTML).not.toContain('aria-label="Skill labels"');
    expect(modal.innerHTML.indexOf("Latest Checks")).toBeLessThan(modal.innerHTML.indexOf("Agents Using This Skill"));
    expect(modal.innerHTML.indexOf("Agents Using This Skill")).toBeLessThan(modal.innerHTML.indexOf("Earlier Versions"));
    expect(modal.innerHTML.indexOf("Earlier Versions")).toBeLessThan(modal.innerHTML.indexOf("Label History"));
    expect(modal.innerHTML.indexOf("Label History")).toBeLessThan(modal.innerHTML.indexOf("Activity Log"));
    await s16.actions["skill-manage-tags"](ctx, { setAttribute: vi.fn() });
    expect(modal.innerHTML).toContain('class="skill-detail-grid skill-detail-grid--tags" role="table"');
    expect(modal.innerHTML).not.toContain("<table");
    expect(modal.innerHTML).not.toContain('class="tblwrap"');
    await s16.actions["skill-labels-edit"](ctx, { getAttribute: () => "skill_1" });
    expect(modal.innerHTML).toContain("Does not change the file");
  });

  it("uses the Cisco and NVIDIA marks beside scanner findings", async () => {
    const s16 = await load();
    const { ctx, detail } = context();
    const runs = detail.vettingRuns as Array<{ mode: string; findings: Array<Record<string, unknown>> }>;
    runs.find((run) => run.mode === "cisco")!.findings = [
      { rule: "other", severity: "low", message: "Cisco finding" },
    ];
    runs.find((run) => run.mode === "skillspector")!.findings = [
      { rule: "download-run", severity: "medium", message: "SkillSpector finding" },
    ];
    const modal = modalHarness();

    await s16.actions["skill-select"](ctx, {
      getAttribute: () => "skill_1",
      setAttribute: vi.fn(),
      focus: vi.fn(),
    });

    expect(modal.innerHTML.match(/skill-vendor-logo--cisco/g)).toHaveLength(2);
    expect(modal.innerHTML.match(/skill-vendor-logo--nvidia/g)).toHaveLength(2);
    expect(modal.innerHTML).toContain('class="skill-finding-source"');
    expect(modal.innerHTML).toContain('aria-label="NVIDIA SkillSpector"');
  });

  it("renders active filter chips and the specific empty-filter state", async () => {
    const s16 = await load();
    const { ctx } = context([skill()]);
    await s16.actions["skill-filter-toggle"](ctx);
    let html = await s16.render(ctx);

    expect(html).toContain('class="skill-filter-panel"');
    expect(html).toContain('class="skill-filter-options-grid"');
    expect(html).toContain('class="skill-filter-panel-footer"');
    expect(html).not.toContain('class="skill-filter-popover"');
    expect(html.indexOf('class="skill-filter-panel"')).toBeLessThan(html.indexOf('class="skill-table-wrap"'));

    await s16.actions["skill-filter-category"](ctx, {
      getAttribute: (name: string) => name === "data-category" ? "Engineering & Code" : null,
    });
    html = await s16.render(ctx);

    expect(html).toContain("No skills match these filters.");
    expect(html).toContain("Category: Engineering &amp; Code");
    expect(html).toContain('data-action="skill-filters-clear"');
  });
});
