/**
 * S18 Settings — the organization/profile identity surface.
 *
 * What this pins:
 *  - the organization READ is open to every human in the tenant, and `canEdit`
 *    (not the read itself) is what differs by role;
 *  - the organization WRITE is owner/admin, and it NEVER moves the handle —
 *    the tenant id is the root namespace every memory row hangs off, so a
 *    rename that re-derived it would orphan the whole subtree;
 *  - the icon is raster-only and size-capped (an SVG mark would be arbitrary
 *    markup arriving from a form);
 *  - a profile update changes the SESSION user and nothing else (D9);
 *  - every accepted mutation leaves an audit row (D4).
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import type { Identity } from "../src/types.js";
import { actions as settingsActions } from "../console/screens/s18.js";

let kernel: Kernel;
let root: Identity;
let orgOwner: Identity;
let orgMember: Identity;
let memberUserId: string;

const TENANT = "acme";
/** A 1×1 PNG — the smallest thing that satisfies the raster data-URL rule. */
const PNG =
  "data:image/png;base64," +
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error(`key for ${namespace} failed to resolve`);
  return identity;
}

async function seedUser(email: string, namespace: string, role: string): Promise<string> {
  const id = ulid();
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5)`,
    [id, email, namespace, role, new Date().toISOString()],
  );
  return id;
}

/** How many audit rows carry a purpose, so a test can assert one was added. */
async function auditCount(purpose: string): Promise<number> {
  const res = await kernel.db.query(
    `SELECT COUNT(*) AS n FROM audit_log WHERE purpose = $1`,
    [purpose],
  );
  return Number(res.rows[0].n);
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolved = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolved) throw new Error("root owner failed to resolve");
  root = resolved;

  await kernel.tenants.register({ id: TENANT, name: "Acme" }, root);
  orgOwner = await issue(TENANT, "owner@acme.test", "owner");
  orgMember = await issue(`${TENANT}/support`, "member@acme.test", "member");
  memberUserId = await seedUser("member@acme.test", `${TENANT}/support`, "member");
});

afterAll(async () => {
  await kernel.close();
});

describe("organization settings", () => {
  it("updates the workspace header immediately after a saved name change", async () => {
    const setCurrentOrganizationName = vi.fn();
    const refresh = vi.fn(async () => undefined);
    const patch = vi.fn(async () => ({ organization: { name: "Halofy Labs" } }));
    const input = { value: "halofy Labs" };
    const status = { textContent: "" };
    const row = { querySelector: () => input };
    const card = { querySelector: () => status };
    const button = {
      disabled: false,
      textContent: "Save",
      closest: (selector: string) => selector === ".settings-inline-form" ? row : card,
    };

    await settingsActions["org-name-save"]({
      api: { patch },
      refresh,
      setCurrentOrganizationName,
    }, button);

    expect(patch).toHaveBeenCalledWith("/v1/admin/organization", { name: "halofy Labs" });
    expect(setCurrentOrganizationName).toHaveBeenCalledWith("Halofy Labs");
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("reads for any human in the tenant and marks only owner/admin editable", async () => {
    const asOwner = await kernel.organizationSettings(orgOwner);
    expect(asOwner).not.toBeNull();
    expect(asOwner!.id).toBe(TENANT);
    expect(asOwner!.name).toBe("Acme");
    expect(asOwner!.icon).toBeNull();
    expect(asOwner!.canEdit).toBe(true);

    // A member sees the same organization — it is the one they work in — but
    // may not write it.
    const asMember = await kernel.organizationSettings(orgMember);
    expect(asMember).not.toBeNull();
    expect(asMember!.name).toBe("Acme");
    expect(asMember!.canEdit).toBe(false);
  });

  it("renames without moving the handle, and audits the change", async () => {
    const before = await auditCount("console-organization-settings");
    const updated = await kernel.updateOrganizationSettings(orgOwner, {
      name: "  acme   Corporation  ",
    });
    // Whitespace collapsed, id untouched.
    expect(updated.name).toBe("Acme Corporation");
    expect(updated.id).toBe(TENANT);
    expect((await kernel.tenants.get(TENANT))!.name).toBe("Acme Corporation");
    expect(await auditCount("console-organization-settings")).toBe(before + 1);
  });

  it("stores a raster icon and clears it with null", async () => {
    const set = await kernel.updateOrganizationSettings(orgOwner, { icon: PNG });
    expect(set.icon).toBe(PNG);
    // The rename above must survive an icon-only write.
    expect(set.name).toBe("Acme Corporation");

    const cleared = await kernel.updateOrganizationSettings(orgOwner, { icon: null });
    expect(cleared.icon).toBeNull();
  });

  it("refuses an SVG icon, an oversized icon, and an unusable name", async () => {
    await expect(
      kernel.updateOrganizationSettings(orgOwner, {
        icon: "data:image/svg+xml;base64,PHN2Zy8+",
      }),
    ).rejects.toThrow(/PNG, JPEG, or WebP/);
    await expect(
      kernel.updateOrganizationSettings(orgOwner, {
        icon: "data:image/png;base64," + "A".repeat(300_000),
      }),
    ).rejects.toThrow(/too large/);
    await expect(
      kernel.updateOrganizationSettings(orgOwner, { name: "x" }),
    ).rejects.toThrow(/between 2 and 100/);
    await expect(kernel.updateOrganizationSettings(orgOwner, {})).rejects.toThrow(
      /supply 'name' and\/or 'icon'/,
    );
  });

  it("denies the write to a member and leaves the row untouched", async () => {
    await expect(
      kernel.updateOrganizationSettings(orgMember, { name: "Member Corp" }),
    ).rejects.toThrow(/owner or admin/);
    expect((await kernel.tenants.get(TENANT))!.name).toBe("Acme Corporation");
  });

  it("is human-only", async () => {
    const agent = await issue(TENANT, "agent:one", "agent");
    await expect(kernel.organizationSettings(agent)).rejects.toThrow(/human-only/);
  });
});

describe("profile settings", () => {
  it("updates the live shell identity immediately after a saved name change", async () => {
    const setCurrentPersonDisplayName = vi.fn();
    const refresh = vi.fn(async () => undefined);
    const patch = vi.fn(async () => ({ displayName: "Dana Ortiz" }));
    const input = { value: "Dana Ortiz" };
    const status = { textContent: "" };
    const row = { querySelector: () => input };
    const card = { querySelector: () => status };
    const button = {
      disabled: false,
      textContent: "Save",
      closest: (selector: string) => selector === ".settings-inline-form" ? row : card,
    };

    await settingsActions["profile-name-save"]({
      api: { patch },
      refresh,
      setCurrentPersonDisplayName,
    }, button);

    expect(patch).toHaveBeenCalledWith("/auth/profile", { displayName: "Dana Ortiz" });
    expect(setCurrentPersonDisplayName).toHaveBeenCalledWith("Dana Ortiz");
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("sets but cannot clear the session user's required display name", async () => {
    const session: Identity = { ...orgMember, sessionUserId: memberUserId };
    const before = await auditCount("console-profile-settings");

    const set = await kernel.updateMemberDisplayName(session, {
      displayName: "  Dana   Ortiz ",
    });
    expect(set.displayName).toBe("Dana Ortiz");
    expect((await kernel.memberProfile(session))!.displayName).toBe("Dana Ortiz");
    expect(await auditCount("console-profile-settings")).toBe(before + 1);

    await expect(
      kernel.updateMemberDisplayName(session, { displayName: "   " }),
    ).rejects.toThrow(/display name is required/i);
    expect((await kernel.memberProfile(session))!.displayName).toBe("Dana Ortiz");
    expect(await auditCount("console-profile-settings")).toBe(before + 1);
  });

  it("sets and clears the session user's own raster avatar, audited", async () => {
    const session: Identity = { ...orgMember, sessionUserId: memberUserId };
    const avatar = "data:image/webp;base64,UklGRg==";
    const before = await auditCount("console-profile-settings");

    const set = await kernel.updateMemberProfile(session, { avatar });
    expect(set.avatar).toBe(avatar);
    expect((await kernel.memberProfile(session))!.avatar).toBe(avatar);
    expect(await auditCount("console-profile-settings")).toBe(before + 1);

    const cleared = await kernel.updateMemberProfile(session, { avatar: null });
    expect(cleared.avatar).toBeNull();
    expect((await kernel.memberProfile(session))!.avatar).toBeNull();
  });

  it("rejects unsafe or oversized profile avatars", async () => {
    const session: Identity = { ...orgMember, sessionUserId: memberUserId };
    await expect(
      kernel.updateMemberProfile(session, {
        avatar: "data:image/svg+xml;base64,PHN2Zy8+",
      }),
    ).rejects.toThrow(/PNG, JPEG, or WebP/);
    await expect(
      kernel.updateMemberProfile(session, {
        avatar: "data:image/png;base64," + "A".repeat(256_001),
      }),
    ).rejects.toThrow(/too large/);
  });

  it("strips control characters and bounds the length", async () => {
    const session: Identity = { ...orgMember, sessionUserId: memberUserId };
    const stripped = await kernel.updateMemberDisplayName(session, {
      displayName: "Dana" + String.fromCharCode(7, 0) + " Ortiz",
    });
    expect(stripped.displayName).toBe("Dana Ortiz");
    await expect(
      kernel.updateMemberDisplayName(session, { displayName: "n".repeat(81) }),
    ).rejects.toThrow(/80 characters or fewer/);
  });

  it("refuses a session with no resolved user, and a missing field", async () => {
    // No sessionUserId = an API-key caller. There is no subject to update, and
    // the caller must not be able to name one.
    await expect(
      kernel.updateMemberDisplayName(orgMember, { displayName: "Nope" }),
    ).rejects.toThrow(/signed-in human session/);
    const session: Identity = { ...orgMember, sessionUserId: memberUserId };
    await expect(kernel.updateMemberDisplayName(session, {})).rejects.toThrow(
      /supply 'displayName'/,
    );
  });
});

/**
 * Transport half: the role matrix and the body rules the routes enforce before
 * any kernel code runs. Stub deps — this lane is about the gate, not the store.
 */
describe("settings HTTP boundary", () => {
  const OWNER: Identity = {
    keyId: "session-owner",
    namespace: TENANT,
    actor: "owner@acme.test",
    role: "owner",
    sessionUserId: "user-owner",
  };
  const MEMBER: Identity = {
    keyId: "session-member",
    namespace: `${TENANT}/support`,
    actor: "member@acme.test",
    role: "member",
    sessionUserId: "user-member",
  };

  let server: HaloHttpServer;
  let base: string;
  let writes: Record<string, unknown>[] = [];
  let profileWrites: unknown[] = [];

  beforeAll(async () => {
    const deps: HttpServerDeps = {
      consoleDir: new URL("../console", import.meta.url).pathname,
      secureCookies: false,
      auth: {
        resolve: async () => null,
        resolveSession: async (token) =>
          token === "owner-session" ? OWNER : token === "member-session" ? MEMBER : null,
        profile: async () => ({ homeNamespace: TENANT, displayName: "Dana Ortiz", avatar: null, teams: [] }),
        updateProfile: async (_identity, body) => {
          profileWrites.push(body);
          return {
            displayName: body.displayName ?? null,
            avatar: body.avatar ?? null,
          };
        },
      },
      syscalls: {
        memRead: async () => ({}),
        memSearch: async () => ({}),
        memWrite: async () => ({}),
        memFault: async () => ({}),
        memStats: async () => ({}),
        memAssemble: async () => ({}),
      },
      admin: {
        organizationSettings: async () => ({
          id: TENANT,
          name: "Acme",
          icon: null,
          status: "active",
          createdAt: "2026-07-20T00:00:00.000Z",
          canEdit: true,
        }),
        updateOrganizationSettings: async (body) => {
          writes.push(body);
          return { id: TENANT, name: String(body.name ?? "Acme"), icon: null };
        },
      },
      metrics: { snapshot: () => ({}) },
      audit: { append: async () => undefined },
      buildMcpServer: () => {
        throw new Error("not used");
      },
    };
    server = createHttpServer(deps);
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => server.stop());

  function as(session: string, path: string, init: RequestInit = {}): Promise<Response> {
    return fetch(base + path, {
      ...init,
      headers: { cookie: `halomem_session=${session}`, ...(init.headers ?? {}) },
    });
  }

  it("lets every human role read the organization", async () => {
    for (const session of ["owner-session", "member-session"]) {
      const response = await as(session, "/v1/admin/organization");
      expect(response.status, session).toBe(200);
      expect((await response.json()).organization.name).toBe("Acme");
    }
  });

  it("refuses the organization write to a member and accepts it from the owner", async () => {
    writes = [];
    const denied = await as("member-session", "/v1/admin/organization", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Member Corp" }),
    });
    expect(denied.status).toBe(403);
    expect(writes).toHaveLength(0);

    const allowed = await as("owner-session", "/v1/admin/organization", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Acme Corporation" }),
    });
    expect(allowed.status).toBe(200);
    expect(writes).toEqual([{ name: "Acme Corporation" }]);
  });

  it("accepts only profile presentation fields and still rejects selectors", async () => {
    profileWrites = [];
    const extra = await as("member-session", "/auth/profile", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: "Dana", userId: "someone-else" }),
    });
    expect(extra.status).toBe(400);
    expect(profileWrites).toHaveLength(0);

    const selector = await as("member-session", "/auth/profile?userId=other", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: "Dana" }),
    });
    expect(selector.status).toBe(400);
    expect(profileWrites).toHaveLength(0);

    const ok = await as("member-session", "/auth/profile", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: "Dana" }),
    });
    expect(ok.status).toBe(200);
    const avatar = "data:image/png;base64,iVBORw0KGgo=";
    const photo = await as("member-session", "/auth/profile", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ avatar }),
    });
    expect(photo.status).toBe(200);
    expect(profileWrites).toEqual([{ displayName: "Dana" }, { avatar }]);
  });
});
