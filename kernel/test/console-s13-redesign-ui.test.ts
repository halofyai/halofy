import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const SCREEN_PATH = fileURLToPath(new URL("../console/screens/s13.js", import.meta.url));
const CSS_PATH = fileURLToPath(new URL("../console/app.css", import.meta.url));

describe("S13 Teams redesign v2", () => {
  it("uses the By Team and All People information architecture", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain("By Team");
    expect(source).toContain("All People");
    expect(source).toContain('data-action="teams-view"');
    expect(source).toContain('data-action="team-selector-toggle"');
    expect(source).toContain('data-input-action="team-selector-search"');
    expect(source).toContain("A team is a memory scope");
    expect(source).not.toContain('class="teams-rail"');
  });

  it("renders organization people with honest roles, teams, last-seen, and status states", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain("Manage people at");
    expect(source).toContain("What can each role do?");
    expect(source).toContain("Search people or teams");
    expect(source).toContain("Never Signed In");
    expect(source).toContain("Unavailable");
    expect(source).toContain("Roles apply across the whole organization, not just this team.");
    expect(source).toContain('data-action="person-teams-toggle"');
  });

  it("keeps team removal lightweight and wires verified suspension impact", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain("They keep their account and other teams");
    expect(source).toContain('data-action="team-member-undo"');
    expect(source).toContain('role="status" aria-live="polite"');
    expect(source).toContain("Checking what this touches");
    expect(source).toContain("/access-impact");
    expect(source).toContain("/access-state");
    expect(source).toContain('data-action="person-suspend-open"');
    expect(source).toMatch(/data-action="person-suspend-confirm"[^>]*disabled/);
  });

  it("matches the supplied suspension drawer and explains every real consequence", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const css = await readFile(CSS_PATH, "utf8");

    expect(source).toContain("Access · ${ctx.esc(organizationLabel(ctx))}");
    expect(source).toContain("Loses Access To");
    expect(source).toContain("signed out immediately");
    expect(source).toContain("Agent Keys They Created");
    expect(source).toContain("keys keep running");
    expect(source).toContain("this can break live automations");
    expect(source).toContain("suspend them at the provider too");
    expect(source).toContain("e.g. Left the company on 4 Aug");
    expect(source).toContain("Reversible — reinstate anytime.");
    expect(source).toContain('id="team-suspend-revoke-keys"');
    expect(source).toContain('data-action="person-reinstate"');
    expect(css).toMatch(/\.teams-suspend-modal\{[^}]*width:min\(460px,100vw\)/);
    expect(css).toMatch(/\.teams-suspend-modal \.console-modal__body\{[^}]*overflow-y:auto/);
    expect(css).toMatch(/\.teams-suspend-footer\{[^}]*margin-top:auto/);
  });

  it("renders durable invitation lifecycle states and explicit credential rotation", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain("No one is waiting.");
    expect(source).toContain("Invitation history");
    expect(source).toContain("Send Reminder");
    expect(source).toContain("Re-Invite");
    expect(source).toContain('data-action="team-invite-revoke"');
    expect(source).toContain("/rotation");
    expect(source).toContain("immediately invalidates the previous one");
    expect(source).not.toContain("Invitation history is not available from the current Teams API");
  });

  it("matches the prototype action, selector, archive, and role-reference controls", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const css = await readFile(CSS_PATH, "utf8");

    expect(source).toContain('data-action="person-action-toggle"');
    expect(source).toContain('data-action="person-action-close"');
    expect(source).toContain("Suspend Access…");
    expect(source).toContain("waiting > 0");
    expect(source).toContain("canArchive(ctx)");
    expect(source).toContain("ROLE_REFERENCE_ROLES.map");
    expect(source).toContain('class="teams-address-lock"');
    expect(source).toContain('class="teams-protected"');
    expect(css).toMatch(/\.teams-person-menu__backdrop\{[^}]*position:fixed/);
    expect(css).toMatch(/\.teams-person-menu__popover\{[^}]*width:190px/);
  });

  it("uses the four prototype invitation states and keeps rotated links in the drawer", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const rotation = source.slice(
      source.indexOf('async "team-invite-action-confirm"'),
      source.indexOf('async "team-invite-action-done"'),
    );

    expect(source).toContain("Invited Email");
    expect(source).toContain("Invited · Waiting");
    expect(source).toContain("Invite Expired");
    expect(source).toContain("Joined · Never Signed In");
    expect(source).toContain("This invite was cancelled. Kept for history.");
    expect(source).toContain('id="team-invite-action-result"');
    expect(source).toContain('id="team-invite-action-url"');
    expect(source).toContain('data-action="team-invite-action-done"');
    expect(rotation).not.toContain("closeTeamModal");
    expect(rotation).not.toContain("refreshScreen");
  });

  it("fails suspension closed when impact counts are unavailable", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");

    expect(source).toContain("function normalizeSuspendImpact");
    expect(source).toContain("Number.isInteger(activeSessions)");
    expect(source).toContain("impact data is incomplete");
    expect(source).not.toContain("Number(impact.activeSessions) || 0");
  });

  it("uses dense responsive cards, fixed custom grids, and selector/drawer layers", async () => {
    const css = await readFile(CSS_PATH, "utf8");

    expect(css).toMatch(/\.teams-v2\{[^}]*max-width:1160px/);
    expect(css).toMatch(/\.teams-segmented\{[^}]*display:inline-flex/);
    expect(css).toMatch(/\.teams-selector__panel\{[^}]*position:absolute/);
    expect(css).toMatch(/\.teams-members-grid__canvas\{[^}]*min-width:720px/);
    expect(css).toMatch(/\.teams-people-grid__canvas\{[^}]*min-width:860px/);
    expect(css).toMatch(/@media\(max-width:760px\)\{[\s\S]*\.teams-v2__head/);
  });

  it("uses the supplied bespoke All People grid instead of the default console table", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const css = await readFile(CSS_PATH, "utf8");
    const allPeople = source.slice(source.indexOf("function allPeopleView"), source.indexOf("function waitingCard"));

    expect(allPeople).toContain('class="teams-people-intro"');
    expect(allPeople).toContain('class="teams-people-toolbar-actions"');
    expect(allPeople).toContain('class="teams-people-grid__canvas" role="table"');
    expect(allPeople).toContain('class="teams-people-grid__head" role="row"');
    expect(allPeople).toContain('class="teams-people-grid__row');
    expect(allPeople).toContain("Person</span><span role=\"columnheader\">Role");
    expect(allPeople).toContain("Teams</span><span role=\"columnheader\">Last Seen");
    expect(allPeople).not.toContain("teams-directory-grid");
    expect(allPeople).not.toContain("Organization Directory");
    expect(css).toMatch(/\.teams-people-grid__head,.teams-people-grid__row\{[^}]*grid-template-columns:minmax\(160px,1\.7fr\) 96px minmax\(130px,1\.2fr\) minmax\(84px,110px\) 78px minmax\(120px,150px\)/);
    expect(css).toMatch(/\.teams-people-grid__row\{[^}]*border-radius:12px[^}]*background:#fafafa/);
    expect(css).toMatch(/\.teams-subtabs button\.is-active\{[^}]*background:#f3f4f6/);
  });

  it("matches the supplied compact team summary and paginated bespoke member grid", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const css = await readFile(CSS_PATH, "utf8");
    const overview = source.slice(source.indexOf("function teamOverview"), source.indexOf("function teamMemoryAccess"));
    const members = source.slice(source.indexOf("function membersCard"), source.indexOf("function allPeopleView"));

    expect(overview).toContain('class="teams-overview__primary"');
    expect(overview).toContain('class="teams-overview__controls"');
    expect(overview).not.toContain("Team Overview");
    expect(overview).not.toContain("pill pill--live");
    expect(members).toContain("What Can Each Role Do?");
    expect(members).toContain("Add Existing Member");
    expect(members).toContain("Invite Person");
    expect(members).toContain('class="teams-members-grid__canvas" role="table"');
    expect(members).toContain('class="teams-members-grid__head" role="row"');
    expect(members).toContain('class="teams-members-grid__row');
    expect(members).toContain('data-action="team-members-page"');
    expect(members).toContain("Only Here");
    expect(members).toContain('class="teams-team-pill"');
    expect(members).toContain("MEMBERS_PAGE_SIZE");
    expect(members).not.toContain("teams-roster-grid");
    expect(members).not.toContain("<table");
    expect(members).not.toContain('<div class="eyebrow">People</div>');
    expect(css).toMatch(/\.teams-members-grid__head,\.teams-members-grid__row\{[^}]*grid-template-columns:minmax\(140px,1\.6fr\) 92px minmax\(64px,90px\) minmax\(78px,100px\) 76px 112px/);
    expect(css).toMatch(/\.teams-members-grid__body\{[^}]*display:flex[^}]*gap:8px/);
    expect(css).toMatch(/\.teams-members-grid__row\{[^}]*border-radius:12px[^}]*background:#fafafa/);
    expect(css).toMatch(/\.teams-members-footer\{[^}]*justify-content:space-between[^}]*border-top:1px solid #f3f4f6/);
    expect(css).toMatch(/\.teams-members-page-button\{[^}]*width:28px[^}]*height:28px/);
    expect(css).toMatch(/\.teams-card-actions \.btn\{[^}]*border:1px solid #e5e7eb/);
  });

  it("pages selected-team members six at a time", async () => {
    const mod = await import("../console/screens/s13.js");
    const members = Array.from({ length: 8 }, (_, index) => ({
      userId: `user-${index + 1}`,
      displayName: `Person ${index + 1}`,
      email: `person${index + 1}@halofy.ai`,
      role: "member",
    }));
    const team = { id: "support", name: "Support", namespace: "halofy/support", members };
    const refresh = vi.fn();
    const ctx = {
      esc: (value: unknown) => String(value),
      organizationName: "halofy",
      identity: { role: "admin", namespace: "halofy", actor: "owner@halofy.ai" },
      refresh,
      api: {
        get: vi.fn(async (path: string) => path === "/v1/admin/teams"
          ? [team]
          : { users: members.map((member) => ({ ...member, status: "active", lastSeen: "2026-08-06T10:00:00.000Z" })) }),
      },
    };

    await mod.actions["team-select"](ctx, { getAttribute: () => team.id });
    const firstPage = await mod.render(ctx);
    expect(firstPage).toContain("Person 1");
    expect(firstPage).toContain("Person 6");
    expect(firstPage).not.toContain("Person 7");
    expect(firstPage).toContain("1–6 of 8 Members");

    await mod.actions["team-members-page"](ctx, { getAttribute: () => "1" });
    const secondPage = await mod.render(ctx);
    expect(secondPage).not.toContain("Person 1");
    expect(secondPage).toContain("Person 7");
    expect(secondPage).toContain("Person 8");
    expect(secondPage).toContain("7–8 of 8 Members");
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("uses the prototype heading, compact team picker, pills, and invitation grids one for one", async () => {
    const source = await readFile(SCREEN_PATH, "utf8");
    const css = await readFile(CSS_PATH, "utf8");
    const selector = source.slice(source.indexOf("function teamSelector"), source.indexOf("function teamOverview"));
    const waiting = source.slice(source.indexOf("function waitingCard"), source.indexOf("function organizationInvitations"));
    const invitations = source.slice(source.indexOf("function invitationsTable"), source.indexOf("function undoBar"));
    const statuses = source.slice(source.indexOf("function statusPill"), source.indexOf("function invitationStatusPill"));

    expect(css).toMatch(/\.teams-v2\{[^}]*display:flex[^}]*gap:18px/);
    expect(source).toContain('class="head teams-v2__head"');
    expect(source).toContain('class="acts teams-v2__head-actions"');
    expect(source).not.toContain('<div class="eyebrow">Govern');
    expect(css).not.toContain(".teams-v2__title-row h1");
    expect(css).toMatch(/\.teams-v2__flow\{[^}]*gap:14px/);
    expect(selector).toContain('class="teams-selector__trigger-label">Team</span>');
    expect(selector).toContain('class="teams-selector__trigger-meta"');
    expect(selector).not.toContain('class="teams-selector__label"');
    expect(selector).not.toContain('class="teams-selector__mark"');
    expect(css).toMatch(/\.teams-selector__trigger\{[^}]*min-width:280px[^}]*padding:9px 14px[^}]*border-radius:12px/);

    expect(waiting).toContain('class="teams-waiting-title"');
    expect(waiting).not.toContain('<div class="eyebrow">Invitations</div>');
    expect(waiting).not.toContain("Pending invitations for");
    expect(invitations).toContain('class="teams-invitations-grid__canvas');
    expect(invitations).toContain('role="table"');
    expect(invitations).toContain('class="teams-invitations-grid__row');
    expect(invitations).not.toContain("<table");
    expect(invitations).not.toContain('class="teams-avatar"');
    expect(statuses).not.toContain('<i class="dot"></i>');
    expect(css).toMatch(/\.teams-v2 \.badge--role\{[^}]*background:#f3f4f6[^}]*color:#374151/);
    expect(css).toMatch(/\.teams-v2 \.pill--live\{[^}]*background:#ecfdf3[^}]*color:#027a48/);
    expect(css).toMatch(/\.teams-person b\{[^}]*font-size:13px[^}]*font-weight:600/);
    expect(css).toMatch(/\.teams-person small\{[^}]*color:#9ca3af[^}]*font-size:11px/);
  });
});
