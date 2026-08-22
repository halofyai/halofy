/**
 * S14 "Connected agents" + S3 last-seen: the api_keys.last_used signal
 * (bumped on every bearer-key resolution, so it doubles as "last connected")
 * rendered for an operator. Pure-Node render tests with a mock ctx.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import { actions, cleanup, render } from "../console/screens/s14.js";
import { render as renderS3 } from "../console/screens/s3.js";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const MIN = 60_000;
const HOUR = 60 * MIN;
/** The signed-in human every S14 fixture renders as. */
const VIEWER = "operator@acme.test";

function agentKey(overrides: Record<string, unknown> = {}) {
  return {
    id: "key_1",
    role: "agent",
    status: "active",
    actor: "coding-agent",
    namespace: "acme",
    lastUsed: null,
    // Migration 76: the ISSUING actor. S14 lists the caller's own connections,
    // so a fixture badge belongs to the viewer unless a test says otherwise.
    createdBy: VIEWER,
    ...overrides,
  };
}

function makeUi() {
  return {
    head({ eyebrow, title, acts }: { eyebrow?: string; title?: string; acts?: string } = {}) {
      return `<div class="head"><div>${eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : ""}<h1>${title ?? ""}</h1></div>${acts ?? ""}</div>`;
    },
    pill(text: string, kind?: string) {
      return `<span class="pill pill--${kind ?? "ok"}"><i class="dot"></i>${text}</span>`;
    },
  };
}

function makeS14Ctx(options: {
  /** undefined => `{keys: []}`; null => the GET rejects (brownout path). */
  keys?: unknown[] | null;
  role?: string;
  namespace?: string;
  actor?: string;
  sessionUserId?: string;
  /** null => the assigned-key GET fails. */
  handoffs?: unknown[] | null;
  onPost?: (path: string) => unknown;
  onGet?: (path: string) => void;
  onDel?: (path: string) => void;
  /** When set, the DELETE rejects with this error (revoke failure path). */
  delError?: unknown;
} = {}) {
  const go = vi.fn();
  const refresh = vi.fn();
  return {
    go,
    refresh,
    ctx: {
      esc,
      identity: {
        namespace: options.namespace ?? "acme",
        role: options.role ?? "owner",
        actor: options.actor ?? VIEWER,
        sessionUserId: options.sessionUserId ?? "user-viewer",
      },
      go,
      refresh,
      ui: makeUi(),
      api: {
        async get(path: string) {
          options.onGet?.(path);
          if (path === "/v1/admin/keys") {
            if (options.keys === null) throw { status: 403, message: "denied" };
            return { keys: options.keys ?? [] };
          }
          if (path === "/v1/admin/key-handoffs") {
            if (options.handoffs === null) throw { status: 503, message: "unavailable" };
            return { handoffs: options.handoffs ?? [] };
          }
          throw new Error(`unexpected GET ${path}`);
        },
        async post(path: string) {
          return options.onPost?.(path) ?? {};
        },
        async del(path: string) {
          options.onDel?.(path);
          if (options.delError) throw options.delError;
          return {};
        },
      },
    },
  };
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("S14 connected agents", () => {
  it("lists live agent badges with badge state and connection state, excluding non-agent and revoked keys", async () => {
    const { ctx } = makeS14Ctx({
      keys: [
        agentKey({ id: "k_fresh", actor: "fresh-agent", lastUsed: null }),
        agentKey({ id: "k_idle", actor: "idle-agent", lastUsed: new Date(Date.now() - 3 * HOUR).toISOString() }),
        agentKey({ id: "k_live", actor: "live-agent", lastUsed: new Date(Date.now() - 2 * MIN).toISOString() }),
        agentKey({ id: "k_dead", actor: "revoked-agent", status: "revoked", lastUsed: new Date().toISOString() }),
        { id: "k_admin", role: "admin", status: "active", actor: "root-admin", namespace: "", lastUsed: new Date().toISOString() },
        { id: "k_ro", role: "auditor", status: "active", actor: "audit-reader", namespace: "acme", lastUsed: null },
      ],
    });

    const html = await render(ctx);

    expect(html).toContain('id="connected-agents-title">Connected agents');
    expect(html).toContain("live-agent");
    expect(html).toContain("idle-agent");
    expect(html).toContain("fresh-agent");
    expect(html).not.toContain("revoked-agent");
    expect(html).not.toContain("root-admin");
    expect(html).not.toContain("audit-reader");
    // Connection state belongs to each row; the card header carries no
    // duplicate active-count pill.
    expect(html).not.toContain(">1 active</span>");
    expect(html).not.toContain("None active yet");
    // Per-row connection state.
    expect(html).toContain('<span class="pill pill--live"><i class="dot"></i>Active</span>');
    expect(html).toContain("Last seen 3 hours ago");
    expect(html).toContain("Never connected");
    // Most recently used first.
    expect(html.indexOf("live-agent")).toBeLessThan(html.indexOf("idle-agent"));
    expect(html.indexOf("idle-agent")).toBeLessThan(html.indexOf("fresh-agent"));
    // The full ledger remains one action away without adding explanatory copy
    // beneath the operational table.
    expect(html).not.toContain("Connection state is per badge");
    expect(html).toContain('data-action="intg-manage-agents"');
  });

  it("reveals an encrypted bearer repeatedly for an owned live badge", async () => {
    const posts: string[] = [];
    const { ctx, refresh } = makeS14Ctx({
      keys: [agentKey({ id: "key-repeat", bearerRevealable: true })],
      onPost(path) {
        posts.push(path);
        return {
          plaintext: "hm_agt_repeatable",
          record: { id: "key-repeat", actor: "coding-agent", keyTypeLabel: "Assistant" },
        };
      },
    });
    const before = await render(ctx);
    expect(before).toContain('data-action="intg-reveal-badge" data-id="key-repeat">Reveal</button>');
    expect(before).not.toContain("hm_agt_repeatable");

    const status = { textContent: "" };
    const revealedNode = { scrollIntoView: vi.fn(), focus: vi.fn() };
    vi.stubGlobal("document", { querySelector: vi.fn(() => revealedNode) });
    const button = {
      disabled: false,
      textContent: "Reveal",
      getAttribute: (name: string) => name === "data-id" ? "key-repeat" : null,
      closest: () => ({ querySelector: () => status }),
    };
    await actions["intg-reveal-badge"](ctx, button);
    const afterReveal = await render(ctx);
    expect(afterReveal).toContain("hm_agt_repeatable");
    expect(afterReveal).toContain('data-action="intg-reveal-badge" data-id="key-repeat">Reveal</button>');
    expect(revealedNode.scrollIntoView).toHaveBeenCalledWith({
      behavior: "smooth",
      block: "center",
    });
    expect(revealedNode.focus).toHaveBeenCalledWith({ preventScroll: true });
    await actions["intg-reveal-badge"](ctx, button);
    expect(posts).toEqual([
      "/v1/admin/keys/key-repeat/reveal",
      "/v1/admin/keys/key-repeat/reveal",
    ]);
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("marks legacy badges as unavailable until they are rotated", async () => {
    const { ctx } = makeS14Ctx({ keys: [agentKey({ id: "key-legacy" })] });
    const html = await render(ctx);
    expect(html).toContain("Reveal unavailable");
    expect(html).toContain("Rotate this legacy badge once to enable repeated reveal");
    expect(html).not.toContain('data-action="intg-reveal-badge" data-id="key-legacy"');
  });

  it("keeps the connected-agent table compact without ledger prose below it", async () => {
    const { ctx } = makeS14Ctx({
      keys: [
        agentKey({ id: "k_mine", actor: "my-agent" }),
        agentKey({ id: "k_revoked", actor: "old-agent", status: "revoked" }),
        agentKey({ id: "k_theirs", actor: "peer-agent", createdBy: "peer@acme.test" }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain('<table data-grid-chrome="off">');
    expect(html).toContain('aria-label="Filter connected table"');
    expect(html).not.toContain('data-grid-panel="columns"');
    expect(html).toContain('data-action="intg-manage-agents"');
    expect(html).not.toContain("revoked badge hidden");
    expect(html).not.toContain("live badge in your scope was not connected by you");
    expect(html).not.toContain("dead credentials stay listed");
  });

  it("filters the admin ledger through one semantic funnel and keeps active state visible", async () => {
    const { ctx, refresh } = makeS14Ctx({
      role: "admin",
      keys: [
        agentKey({ id: "k_active", actor: "active-agent", lastUsed: new Date().toISOString() }),
        agentKey({ id: "k_never", actor: "never-agent", lastUsed: null }),
      ],
    });

    const attrs: Record<string, string> = {
      "data-table": "connected",
      "data-field": "connection",
      "data-value": "never",
    };
    await actions["intg-table-filter"](ctx, {
      getAttribute: (name: string) => attrs[name] ?? null,
    });

    expect(refresh).toHaveBeenCalledOnce();
    const html = await render(ctx);
    const connected = html.slice(
      html.indexOf('id="connected-agents-title"'),
      html.indexOf('id="intg-library-title"'),
    );
    expect(connected).toContain("never-agent");
    expect(connected).not.toContain("active-agent");
    expect(connected).toContain("connection: Never connected");
    expect(connected).toContain('data-action="intg-table-filter-clear"');
    expect(connected).toContain("Showing 1-1 of 1");
  });

  it("renders Live and Expired badge states; revoked badges never reach the card", async () => {
    const { ctx } = makeS14Ctx({
      keys: [
        agentKey({ id: "k_live", actor: "live-one" }),
        agentKey({ id: "k_exp", actor: "expired-one", expired: true, expiresAt: new Date(Date.now() - HOUR).toISOString() }),
        agentKey({ id: "k_rev", actor: "revoked-one", status: "revoked" }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain('<span class="pill pill--live"><i class="dot"></i>Live</span>');
    expect(html).toContain('<span class="pill pill--warn"><i class="dot"></i>Expired</span>');
    expect(html).not.toContain("revoked-one");
    expect(html).not.toContain('<span class="pill pill--crit"><i class="dot"></i>Revoked</span>');
    expect(html).not.toContain("1 revoked badge hidden");
  });

  it("says when every issued badge has been revoked instead of the first-run empty state", async () => {
    const { ctx } = makeS14Ctx({
      keys: [agentKey({ id: "k_rev", actor: "revoked-one", status: "revoked" })],
    });

    const html = await render(ctx);

    expect(html).not.toContain("No live badges");
    expect(html).toContain("You have revoked every badge you connected.");
    expect(html).not.toContain("You haven't connected an agent yet.");
  });

  it("renders the empty state when no agent badges exist", async () => {
    const { ctx } = makeS14Ctx({ keys: [] });

    const html = await render(ctx);

    expect(html).not.toContain("No live badges");
    expect(html).toContain("You haven't connected an agent yet. Mint a badge under Connection key below");
  });

  it("lists only the badges the signed-in human connected without rendering the rest", async () => {
    const { ctx } = makeS14Ctx({
      role: "admin",
      keys: [
        agentKey({ id: "k_mine", actor: "my-agent" }),
        // Same admin, typed with different case/whitespace at issuance time.
        agentKey({ id: "k_mine_2", actor: "my-other-agent", createdBy: "  Operator@Acme.test " }),
        agentKey({ id: "k_theirs", actor: "teammate-agent", createdBy: "someone.else@acme.test" }),
        agentKey({ id: "k_theirs_2", actor: "another-teammate-agent", createdBy: "third@acme.test" }),
        // No recorded issuer: nobody's connection, so nobody's list.
        agentKey({ id: "k_orphan", actor: "unattributed-agent", createdBy: undefined }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain("my-agent");
    expect(html).toContain("my-other-agent");
    expect(html).not.toContain("teammate-agent");
    expect(html).not.toContain("unattributed-agent");
    expect(html).not.toContain("3 live badges in your scope were not connected by you");
  });

  it("tells an admin who connected nothing why the card is empty", async () => {
    const { ctx } = makeS14Ctx({
      role: "admin",
      keys: [
        agentKey({ id: "k_theirs", actor: "teammate-agent", createdBy: "someone.else@acme.test" }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain("You haven't connected an agent yet.");
    expect(html).not.toContain("1 live badge in your scope was not connected by you");
    expect(html).not.toContain("teammate-agent");
  });

  it("scopes a member's card to its own connections, not its teammates'", async () => {
    const { ctx } = makeS14Ctx({
      role: "member",
      actor: "member@acme.test",
      keys: [
        agentKey({ id: "k_mine", actor: "member-agent", createdBy: "member@acme.test" }),
        agentKey({ id: "k_peer", actor: "peer-agent", createdBy: "peer@acme.test" }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain("member-agent");
    expect(html).not.toContain("peer-agent");
    expect(html).not.toContain("1 live badge in your scope was not connected by you.");
    // A member has no Scoped memory screen to be pointed at.
    expect(html).not.toContain('data-action="intg-manage-agents"');
  });

  it("includes a member's claimed assigned badge without exposing the session user id", async () => {
    const { ctx } = makeS14Ctx({
      role: "member",
      actor: "member@acme.test",
      sessionUserId: "",
      keys: [
        agentKey({ id: "key-self", actor: "member-agent", createdBy: "member@acme.test" }),
        agentKey({ id: "key-assigned", actor: "assigned-agent", createdBy: "owner@acme.test" }),
        agentKey({ id: "key-peer", actor: "peer-agent", createdBy: "peer@acme.test" }),
      ],
      handoffs: [{
        id: "handoff-claimed", actor: "assigned-agent", namespace: "acme/team",
        status: "claimed", claimedKeyId: "key-assigned",
      }],
    });

    const html = await render(ctx);
    const connected = html.slice(
      html.indexOf('id="connected-agents-title"'),
      html.indexOf('id="assigned-badges-title"'),
    );

    expect(connected).toContain("member-agent");
    expect(connected).toContain("assigned-agent");
    expect(html).not.toContain("peer-agent");
  });

  it("browns out to a note when the badge listing fails, keeping the client grid", async () => {
    const { ctx } = makeS14Ctx({ keys: null });

    const html = await render(ctx);

    expect(html).toContain("Couldn't load agent badges.");
    expect(html).not.toContain('aria-label="Filter connected table"');
    expect(html).not.toContain("No agent badges yet.");
    expect(html).toContain("MCP clients");
    expect(html).toContain("Claude Code");
    expect(html).toContain('data-action="intg-mint"');
  });

  it("hides the card for roles the server refuses and never fetches the listing", async () => {
    const requested: string[] = [];
    const { ctx } = makeS14Ctx({ role: "auditor", onGet: (path) => requested.push(path) });

    const html = await render(ctx);

    expect(html).not.toContain("connected-agents-title");
    expect(html).not.toContain("/v1/admin/keys");
    expect(requested).not.toContain("/v1/admin/keys");
    expect(html).toContain("Claude Code");
  });

  it("escapes API-derived strings in the connected-agents rows", async () => {
    const { ctx } = makeS14Ctx({
      keys: [agentKey({ actor: "<img src=x onerror=alert(1)>", namespace: "<b>ns</b>" })],
    });

    const html = await render(ctx);

    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;b&gt;ns&lt;/b&gt;");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
  });

  it("treats a hostile unparseable lastUsed value as never connected", async () => {
    const { ctx } = makeS14Ctx({
      keys: [agentKey({ lastUsed: "<script>alert(1)</script>" })],
    });

    const html = await render(ctx);

    // An unparseable timestamp falls into the null branch — the raw API
    // string never reaches the markup at all.
    expect(html).toContain("Never connected");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("alert(1)");
  });

  it("caps the rows without footer copy and links to the Agents screen for the full list", async () => {
    const keys = Array.from({ length: 10 }, (_, index) =>
      agentKey({
        id: `k_${index}`,
        actor: `agent-${String(index + 1).padStart(2, "0")}`,
        lastUsed: new Date(Date.now() - (index + 1) * HOUR).toISOString(),
      }),
    ).reverse();
    const { ctx, go } = makeS14Ctx({ keys });

    const html = await render(ctx);

    expect(html).toContain("agent-08");
    expect(html).not.toContain("agent-09");
    expect(html).not.toContain("Showing the 8 most recent of 10 badges you connected.");

    await actions["intg-manage-agents"](ctx);
    expect(go).toHaveBeenCalledWith("s3");
  });

  it("offers an inline revoke on every live row and revokes through the admin keys API", async () => {
    const deleted: string[] = [];
    const { ctx, refresh } = makeS14Ctx({
      keys: [agentKey({ id: "k_1", actor: "claude code pratz test" })],
      onDel: (path) => deleted.push(path),
    });

    const html = await render(ctx);
    expect(html).toContain(
      '<button class="btn btn--danger btn--sm" data-action="intg-revoke-badge" data-id="k_1">Revoke</button>',
    );

    await actions["intg-revoke-badge"](ctx, {
      getAttribute: (name: string) => (name === "data-id" ? "k_1" : null),
      closest: () => ({ querySelector: () => null }),
      disabled: false,
      textContent: "Revoke",
    });
    expect(deleted).toEqual(["/v1/admin/keys/k_1"]);
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("reports a failed revoke in place and re-enables the button", async () => {
    const { ctx, go } = makeS14Ctx({ keys: [agentKey()], delError: new Error("boom") });
    const status = { textContent: "" };
    const el = {
      getAttribute: (name: string) => (name === "data-id" ? "key_1" : null),
      closest: () => ({ querySelector: () => status }),
      disabled: false,
      textContent: "Revoke",
    };

    await actions["intg-revoke-badge"](ctx, el);

    expect(status.textContent).toBe("Revoke failed: boom");
    expect(el.disabled).toBe(false);
    expect(el.textContent).toBe("Revoke");
    expect(go).not.toHaveBeenCalledWith("s14");
  });

  it("leads each row with the client logo matched from the agent name, glyph otherwise", async () => {
    const { ctx } = makeS14Ctx({
      keys: [
        agentKey({ id: "k_claude", actor: "Claude code pratz test" }),
        agentKey({ id: "k_cursor", actor: "cursor ide" }),
        agentKey({ id: "k_hermes", actor: "Hermes Pratz" }),
        agentKey({ id: "k_plain", actor: "neg2-support" }),
      ],
    });

    const html = await render(ctx);

    expect(html).toContain("<th>Logo</th>");
    expect(html).toContain('src="https://cdn.simpleicons.org/claude"');
    expect(html).toContain('src="https://cdn.simpleicons.org/cursor"');
    // Hermes matches the vendored Nous mark; only truly unknown agents fall
    // back to the generic glyph.
    const rows = html.split("</tr>");
    expect(rows.find((row) => row.includes("Hermes Pratz"))).toContain('src="assets/marks/hermes.png"');
    expect(rows.find((row) => row.includes("neg2-support"))).toContain('data-logo-kind="glyph"');
  });

  it("matches the Hermez misspelling to the Hermes logo", async () => {
    const { ctx } = makeS14Ctx({ keys: [agentKey({ actor: "Hermez pratz" })] });

    const html = await render(ctx);

    expect(html.split("</tr>").find((row) => row.includes("Hermez pratz")))
      .toContain('src="assets/marks/hermes.png"');
  });
});

describe("S14 compact connection library", () => {
  it("groups clients in one boxed library and keeps cards to state and action", async () => {
    const { ctx } = makeS14Ctx();

    const html = await render(ctx);

    expect(html).toContain('class="card intg-library"');
    expect(html).toContain('aria-label="Connect Claude Code"');
    expect(html).toContain('aria-label="Connect Codex CLI"');
    expect(html).not.toContain('class="intg-card-sub"');
    expect(html).not.toContain("One command for Claude Code");
    expect(html).not.toContain("Native Streamable HTTP");
  });

  it("renders the connection-key disclosure as controls without a type explainer", async () => {
    const { ctx } = makeS14Ctx();

    const html = await render(ctx);

    expect(html).toContain('id="intg-actor"');
    expect(html).toContain('id="intg-ns"');
    expect(html).toContain('data-action="intg-mint"');
    expect(html).toContain('id="intg-manual-key"');
    expect(html).toContain('id="intg-manual-key" type="password"');
    expect(html).toContain('data-action="intg-toggle-manual-key-visibility"');
    expect(html).toContain('aria-controls="intg-manual-key" aria-pressed="false">Reveal bearer</button>');
    expect(html).not.toContain('class="intg-key-types"');
    expect(html).not.toContain("Snippets use");
    expect(html).not.toContain("Three key types");
    expect(html).not.toContain("Stays in this browser");
  });

  it("places recipient-bound assignments below Connected agents and turns a one-time claim into every connection recipe", async () => {
    const posts: string[] = [];
    const { ctx, refresh } = makeS14Ctx({
      role: "member",
      actor: "member@acme.test",
      sessionUserId: "user-member",
      handoffs: [{
        id: "handoff-1", actor: "assigned-agent", namespace: "acme/team",
        status: "pending", claimExpiresAt: new Date(Date.now() + HOUR).toISOString(),
      }],
      onPost(path) {
        posts.push(path);
        return {
          plaintext: "hm_agt_recipient_once",
          record: { actor: "assigned-agent", keyTypeLabel: "Assistant" },
        };
      },
    });
    const html = await render(ctx);
    expect(html).toContain('id="assigned-badges-title">Badges assigned to you');
    expect(html).toContain("assigned-agent");
    expect(html).toContain("Reveal bearer");
    expect(html).toContain("fills every connection recipe for 90 seconds and can be revealed again later");
    expect(html).toContain('aria-label="Filter assigned table"');
    expect(html).toContain('<table data-grid-chrome="off">');
    expect(html).not.toContain('data-grid-panel="columns"');
    expect(html).not.toContain("hm_agt_recipient_once");
    expect(html.indexOf('id="connected-agents-title"')).toBeLessThan(
      html.indexOf('id="assigned-badges-title"'),
    );
    expect(html.indexOf('id="assigned-badges-title"')).toBeLessThan(
      html.indexOf('id="intg-library-title"'),
    );

    const attrs: Record<string, string> = {};
    await actions["intg-claim-assigned-key"](ctx, {
      disabled: false,
      textContent: "Reveal bearer",
      getAttribute: (name: string) => name === "data-id" ? "handoff-1" : attrs[name] ?? null,
      setAttribute: (name: string, value: string) => { attrs[name] = value; },
    });
    expect(posts).toEqual(["/v1/admin/key-handoffs/handoff-1/claim"]);
    expect(refresh).toHaveBeenCalledOnce();
    const revealed = await render(ctx);
    expect(revealed).toContain("hm_agt_recipient_once");
    expect(revealed).toContain("Bearer ready");
    expect(revealed).toContain(">90s</span>");
    expect(revealed).not.toContain("Assigned bearer ready: shown once");
    expect(revealed).not.toContain("hm_agt_…");
    expect(revealed).toContain("Copy bearer");
    expect(revealed).toContain('aria-pressed="true">Hide bearer</button>');

    const keyNode = { textContent: "", setAttribute: vi.fn() };
    const visibilityAttrs: Record<string, string> = {};
    const visibilityButton = {
      textContent: "Hide bearer",
      closest: () => ({ querySelector: () => keyNode }),
      setAttribute: (name: string, value: string) => { visibilityAttrs[name] = value; },
    };
    actions["intg-toggle-key-visibility"](ctx, visibilityButton);
    const hidden = await render(ctx);
    expect(hidden).not.toContain("hm_agt_recipient_once");
    expect(hidden).toContain('aria-label="Bearer token hidden"');
    expect(hidden).toContain('aria-pressed="false">Reveal bearer</button>');
    expect(keyNode.textContent).toContain("••••");
    expect(visibilityAttrs["aria-pressed"]).toBe("false");

    actions["intg-toggle-key-visibility"](ctx, visibilityButton);
    expect(await render(ctx)).toContain("hm_agt_recipient_once");

    const modal = {
      innerHTML: "",
      hidden: true,
      setAttribute() {},
      querySelector: () => null,
    };
    vi.stubGlobal("document", {
      getElementById: () => modal,
      body: { classList: { add() {}, remove() {} } },
      addEventListener() {},
      removeEventListener() {},
    });
    actions["intg-open"](ctx, {
      getAttribute: (name: string) => name === "data-id" ? "claude-code" : null,
    });
    expect(modal.innerHTML).toContain("claude mcp add --transport http halomem");
    expect(modal.innerHTML).toContain("Authorization: Bearer hm_agt_recipient_once");
  });

  it("masks newly minted bearers by default for owners, admins, and members", async () => {
    for (const role of ["owner", "admin", "member"]) {
      cleanup();
      const plaintext = `hm_agt_${role}_hidden`;
      const { ctx } = makeS14Ctx({
        role,
        onPost: () => ({ plaintext, record: { actor: `${role}-agent`, keyTypeLabel: "Assistant" } }),
      });
      const status = { textContent: "" };
      const fields: Record<string, { value: string }> = {
        "#intg-actor": { value: `${role}-agent` },
        "#intg-ns": { value: "acme" },
      };
      const root = {
        querySelector: (selector: string) => fields[selector] ??
          (selector === "#intg-mint-status" ? status : null),
      };
      await actions["intg-mint"](ctx, {
        disabled: false,
        textContent: "Mint Assistant key",
        closest: () => root,
      });

      const hidden = await render(ctx);
      expect(hidden).not.toContain(plaintext);
      expect(hidden).toContain('aria-label="Bearer token hidden"');
      expect(hidden).toContain('aria-pressed="false">Reveal bearer</button>');

      const keyNode = { textContent: "", setAttribute: vi.fn() };
      actions["intg-toggle-key-visibility"](ctx, {
        textContent: "Reveal bearer",
        closest: () => ({ querySelector: () => keyNode }),
        setAttribute() {},
      });
      expect(await render(ctx)).toContain(plaintext);
      expect(keyNode.textContent).toBe(plaintext);
    }
  });

  it("lets a pasted bearer be revealed and hidden on demand", async () => {
    const { ctx } = makeS14Ctx();
    const typeStatus = { textContent: "" };
    actions["intg-manual-key"](ctx, {
      value: "hm_agt_pasted",
      closest: () => ({ querySelector: () => typeStatus }),
    });
    expect(await render(ctx)).toContain('id="intg-manual-key" type="password"');

    const input = { type: "password" };
    const attrs: Record<string, string> = {};
    const button = {
      textContent: "Reveal bearer",
      closest: () => ({ querySelector: () => input }),
      setAttribute: (name: string, value: string) => { attrs[name] = value; },
    };
    actions["intg-toggle-manual-key-visibility"](ctx, button);
    expect(input.type).toBe("text");
    expect(button.textContent).toBe("Hide bearer");
    expect(attrs["aria-pressed"]).toBe("true");
    expect(await render(ctx)).toContain('id="intg-manual-key" type="text"');

    const clearedInput = {
      value: "",
      type: "text",
      closest: () => ({
        querySelector: (selector: string) => selector === "#intg-manual-type" ? typeStatus : button,
      }),
    };
    actions["intg-manual-key"](ctx, clearedInput);
    expect(clearedInput.type).toBe("password");
    expect(button.textContent).toBe("Reveal bearer");
    expect(attrs["aria-pressed"]).toBe("false");

    actions["intg-manual-key"](ctx, {
      value: "hm_agt_pasted_again",
      closest: () => ({ querySelector: () => typeStatus }),
    });

    actions["intg-toggle-manual-key-visibility"](ctx, button);
    expect(input.type).toBe("text");
    actions["intg-toggle-manual-key-visibility"](ctx, button);
    expect(input.type).toBe("password");
    expect(button.textContent).toBe("Reveal bearer");
    expect(await render(ctx)).toContain('id="intg-manual-key" type="password"');
  });

  it("keeps claimed, expired, and revoked assignments visible without offering another reveal", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-14T12:00:00.000Z"));
    const { ctx } = makeS14Ctx({
      role: "member",
      handoffs: [
        {
          id: "handoff-claimed", actor: "claimed-agent", namespace: "acme/team",
          status: "claimed", claimExpiresAt: "2026-08-14T13:00:00.000Z",
          claimedKeyId: "key-claimed", agentCanWrite: true,
        },
        {
          id: "handoff-expired", actor: "expired-agent", namespace: "acme/team",
          status: "pending", claimExpiresAt: "2026-08-14T11:00:00.000Z",
          agentCanWrite: false,
        },
        {
          id: "handoff-revoked", actor: "revoked-agent", namespace: "acme/team",
          status: "revoked", claimExpiresAt: "2026-08-14T13:00:00.000Z",
          agentCanWrite: true,
        },
      ],
    });

    const html = await render(ctx);

    expect(html).toContain("claimed-agent");
    expect(html).toContain("expired-agent");
    expect(html).toContain("revoked-agent");
    expect(html).toContain(">Claimed</span>");
    expect(html).toContain(">Claim expired</span>");
    expect(html).toContain(">Revoked</span>");
    expect(html).toContain("Read + write");
    expect(html).toContain("Read only");
    expect(html).not.toContain('data-id="handoff-claimed">Reveal bearer</button>');
    expect(html).not.toContain('data-id="handoff-expired">Reveal bearer</button>');
    expect(html).not.toContain('data-id="handoff-revoked">Reveal bearer</button>');
  });

  it("renders an honest empty assigned-badge section for members only", async () => {
    const member = makeS14Ctx({ role: "member", handoffs: [] });
    const admin = makeS14Ctx({ role: "admin", handoffs: [] });

    const memberHtml = await render(member.ctx);
    const adminHtml = await render(admin.ctx);

    expect(memberHtml).toContain("No badges have been assigned to you yet.");
    expect(memberHtml).toContain("owner or admin can assign a member-scoped Assistant badge");
    expect(adminHtml).not.toContain("assigned-badges-title");
  });

  it("clears a claimed bearer on navigation and refreshes the canonical route after 90 seconds", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-14T12:00:00.000Z"));
    vi.stubGlobal("window", { location: { hash: "#agentconnections" } });
    const { ctx, refresh } = makeS14Ctx({
      role: "member",
      handoffs: [{
        id: "handoff-timer", actor: "timed-agent", namespace: "acme",
        status: "pending", claimExpiresAt: "2026-08-14T13:00:00.000Z",
      }],
      onPost: () => ({
        plaintext: "hm_agt_timer_once",
        record: { actor: "timed-agent", keyTypeLabel: "Assistant" },
      }),
    });
    await actions["intg-claim-assigned-key"](ctx, {
      disabled: false,
      textContent: "Reveal bearer",
      getAttribute: (name: string) => name === "data-id" ? "handoff-timer" : null,
      setAttribute() {},
    });
    expect(await render(ctx)).toContain("hm_agt_timer_once");

    cleanup();
    expect(await render(ctx)).not.toContain("hm_agt_timer_once");

    await actions["intg-claim-assigned-key"](ctx, {
      disabled: false,
      textContent: "Reveal bearer",
      getAttribute: (name: string) => name === "data-id" ? "handoff-timer" : null,
      setAttribute() {},
    });
    refresh.mockClear();
    await vi.advanceTimersByTimeAsync(90_000);
    expect(refresh).toHaveBeenCalledOnce();
    expect(await render(ctx)).not.toContain("hm_agt_timer_once");
  });

  it("renders a failed assigned-key read as unavailable instead of an empty list", async () => {
    const { ctx } = makeS14Ctx({ role: "member", handoffs: null });
    const html = await render(ctx);
    expect(html).toContain("Assigned badges unavailable");
    expect(html).not.toContain("No badges have been assigned to you yet.");
  });
});

// ---------------------------------------------------------------------------
// S3 — the same last_used signal on the governance surface.
// ---------------------------------------------------------------------------

function makeS3Ctx(options: { badges?: unknown[]; keys?: unknown[] } = {}) {
  const go = vi.fn();
  return {
    ctx: {
      esc,
      identity: { namespace: "", role: "root" },
      go,
      ui: makeUi(),
      api: {
        async get(path: string) {
          if (path === "/v1/admin/people") return { users: [], badges: options.badges ?? [] };
          if (path === "/v1/admin/keys") return { keys: options.keys ?? [] };
          if (path === "/v1/admin/teams") return { teams: [] };
          return []; // control endpoints: sources, grants, events, alerts, requests
        },
        async post() {
          return {};
        },
        async del() {
          return {};
        },
      },
    },
  };
}

describe("S3 last seen", () => {
  it("shows last-seen in the badge ledger, compressed to fit its column", async () => {
    const { ctx } = makeS3Ctx({
      badges: [
        agentKey({ id: "b_fresh", actor: "claude-code", lastUsed: null }),
        agentKey({ id: "b_busy", actor: "codex-cli", lastUsed: new Date(Date.now() - 5 * MIN).toISOString() }),
      ],
      keys: [
        agentKey({ id: "b_fresh", actor: "claude-code", lastUsed: null }),
        agentKey({ id: "b_busy", actor: "codex-cli", lastUsed: new Date(Date.now() - 5 * MIN).toISOString() }),
        { id: "k_admin", role: "admin", status: "active", actor: "root-admin", namespace: "", lastUsed: new Date(Date.now() - 2 * MIN).toISOString() },
      ],
    });

    const html = await renderS3(ctx);

    // The ledger carries the column.
    expect(html).toContain('<span class="eyebrow">Last seen</span>');
    // A badge no client has presented yet reads as never connected.
    expect(html).toContain('<span class="subtle">Never</span>');
    // Recent activity is relative, abbreviated to fit the 90px column.
    expect(html).toContain('<span class="subtle">2m ago</span>');
    expect(html).toContain('<span class="subtle">5m ago</span>');
    // Every credential is one row of the same ledger.
    expect(html).toContain("claude-code");
    expect(html).toContain("codex-cli");
    expect(html).toContain("root-admin");
  });

  it("says so plainly when the filtered ledger is empty", async () => {
    const { ctx } = makeS3Ctx({ badges: [], keys: [] });

    const html = await renderS3(ctx);

    expect(html).toContain('<span class="eyebrow">Last seen</span>');
    expect(html).toContain("No active badges.");
  });
});
