/**
 * M10 preview module — root "View as" lifecycle (FR6, D43/D46/D47/D4/D9).
 *
 * Hermetic: in-memory PGlite, injected clock (no timers), zero network.
 * Uses migration v54's `access_preview_sessions` when landed; otherwise
 * creates the table in-test with the exact CONTRACTS-M10-ACCESS.md DDL
 * (CREATE TABLE IF NOT EXISTS keeps both orders safe).
 *
 * The review-critical assertions:
 *  - the raw token never lands in ANY column of ANY table row or audit detail;
 *  - expiry is enforced at the injected clock;
 *  - a non-root caller is rejected and audited;
 *  - a bare role (no functional area) is not a valid preview;
 *  - foreign-tenant / disabled / unknown subjects share ONE not-found shape;
 *  - `_` in a tenant namespace never acts as a LIKE wildcard;
 *  - enforcePreviewReadOnly passes only GET/HEAD;
 *  - every audit row is attributed to the ROOT actor, never the subject.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { ulid } from "ulid";

import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { AuditLog } from "../src/audit/index.js";
import type {
  AuditEvent,
  HumanRole,
  ProductHumanRole,
  Session,
} from "../src/types.js";
import {
  createPreviewSession,
  endPreviewSession,
  enforcePreviewReadOnly,
  hashPreviewToken,
  isExpired,
  listPreviewTargets,
  resolvePreview,
  rejectPreviewMutation,
  tenantRootOf,
  DEFAULT_PREVIEW_TTL_MS,
  type ViewAsDeps,
} from "../src/console/view-as.js";

const DIM = 8;

let db: Db;
let events: AuditEvent[] = [];
let clock: Date;
let deps: ViewAsDeps;

// The one D41 seam, stubbed exactly as src/iam/product-roles.ts defines it.
function toProductRole(role: HumanRole): ProductHumanRole {
  if (role === "owner") return "root";
  if (role === "auditor") return "member";
  return role;
}

function session(
  userId: string,
  namespace: string,
  actor: string,
  role: HumanRole,
): Session {
  return {
    id: `sess-${userId}`,
    userId,
    namespace,
    actor,
    role,
    createdAt: clock.toISOString(),
    expiresAt: new Date(clock.getTime() + 12 * 3600_000).toISOString(),
  };
}

async function seedUser(
  id: string,
  email: string,
  namespace: string,
  role: string,
  status: "active" | "disabled" = "active",
): Promise<void> {
  await db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
     VALUES ($1, $2, $3, $4, NULL, $5, $6)`,
    [id, email, namespace, role, status, clock.toISOString()],
  );
}

async function seedTeam(id: string, namespace: string, name: string): Promise<void> {
  await db.query(
    `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
     VALUES ($1, $2, $3, '', 'test', $4)`,
    [id, namespace, name, clock.toISOString()],
  );
}

const acmeRoot = () => session("u-root", "acme", "root@acme.co", "owner");
const acmeAdmin = () => session("u-admin", "acme/marketing", "mia@acme.co", "admin");
const globexRoot = () => session("u-groot", "globex", "root@globex.co", "owner");

beforeAll(async () => {
  clock = new Date("2026-07-24T10:00:00.000Z");
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  // Module B's migration v54 owns this table; create it here iff not landed
  // yet — exact CONTRACTS-M10-ACCESS.md DDL, idempotent either way.
  await db.query(`
    CREATE TABLE IF NOT EXISTS access_preview_sessions (
      id                    TEXT PRIMARY KEY,
      token_hash            TEXT NOT NULL UNIQUE,
      tenant_id             TEXT NOT NULL,
      root_user_id          TEXT NOT NULL,
      subject_user_id       TEXT,
      simulated_role        TEXT CHECK (simulated_role IN ('admin','member')),
      selected_resource_ids JSONB NOT NULL DEFAULT '[]',
      reason                TEXT NOT NULL,
      created_at            TIMESTAMPTZ NOT NULL,
      expires_at            TIMESTAMPTZ NOT NULL,
      ended_at              TIMESTAMPTZ
    )`);
  await db.query(`ALTER TABLE access_preview_sessions ENABLE ROW LEVEL SECURITY`);

  const audit = new AuditLog(db);
  deps = {
    db,
    audit: {
      async appendTo(handle, event) {
        events.push({ ...event });
        await audit.appendTo(handle, event); // real D4 row too - leak-scannable
      },
    },
    toProductRole,
    now: () => clock,
  };

  // The bootstrap/platform superuser (namespace "" — NO tenant).
  await seedUser("u-proot", "platform@halomem.test", "", "owner");
  // Tenant acme.
  await seedUser("u-root", "root@acme.co", "acme", "owner");
  await seedUser("u-admin", "mia@acme.co", "acme/marketing", "admin");
  await seedUser("u-ana", "ana@acme.co", "acme/marketing", "member");
  await seedUser("u-aud", "audrey@acme.co", "acme", "auditor");
  await seedUser("u-dan", "dan@acme.co", "acme/sales", "member", "disabled");
  await seedTeam("t-mkt", "acme/marketing", "Marketing");
  await seedTeam("t-sales", "acme/sales", "Sales");
  // Tenant globex (foreign to acme).
  await seedUser("u-groot", "root@globex.co", "globex", "owner");
  await seedUser("u-fred", "fred@globex.co", "globex/it", "member");
  await seedTeam("t-git", "globex/it", "IT");
  // LIKE-metacharacter tenants: "t_1" must never match "tx1" via `_`.
  await seedUser("u-troot", "root@t1.co", "t_1", "owner");
  await seedUser("u-tops", "ops@t1.co", "t_1/ops", "member");
  await seedUser("u-eve", "eve@tx1.co", "tx1/ops", "member");
  await seedTeam("t-t1ops", "t_1/ops", "Ops");
  await seedTeam("t-tx1", "tx1/ops", "NotOps");

  // Every customer org signup mints a `tenants` row (console/signup.ts) —
  // registration is what fences them off from the "" organization root.
  for (const [id, name] of [
    ["acme", "Acme"],
    ["globex", "Globex"],
    ["t_1", "T_1"],
    ["tx1", "Tx1"],
  ]) {
    await db.query(
      `INSERT INTO tenants (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
       VALUES ($1, $2, 'active', 100, 100, $3) ON CONFLICT (id) DO NOTHING`,
      [id, name, clock.toISOString()],
    );
  }
  // The "" ORGANIZATION (single-org install): a top-level team + member that
  // belong to the bootstrap owner's own workspace, not to any tenant.
  await seedUser("u-gina", "gina@halomem.test", "growth/people/gina", "member");
  await seedTeam("t-grow", "growth", "Growth");
});

afterAll(async () => {
  await db.close();
});

beforeEach(() => {
  events = [];
  clock = new Date("2026-07-24T10:00:00.000Z");
});

// ---------------------------------------------------------------------------
// Helpers for leak scanning
// ---------------------------------------------------------------------------

async function allStoredText(): Promise<string> {
  const rows = await db.query(`SELECT * FROM access_preview_sessions`);
  const audit = await db.query(`SELECT actor, purpose, detail, namespace FROM audit_log`);
  return JSON.stringify(rows.rows) + JSON.stringify(audit.rows) + JSON.stringify(events);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe("tenantRootOf", () => {
  it("takes the first /-segment; bare and empty stay as-is", () => {
    expect(tenantRootOf("acme/marketing/eu")).toBe("acme");
    expect(tenantRootOf("acme")).toBe("acme");
    expect(tenantRootOf("")).toBe("");
  });
});

describe("enforcePreviewReadOnly matrix", () => {
  it("passes ONLY GET and HEAD, case-insensitively", () => {
    expect(enforcePreviewReadOnly("GET")).toBe(true);
    expect(enforcePreviewReadOnly("get")).toBe(true);
    expect(enforcePreviewReadOnly("HEAD")).toBe(true);
    expect(enforcePreviewReadOnly("head")).toBe(true);
    for (const m of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", ""]) {
      expect(enforcePreviewReadOnly(m), m).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// createPreviewSession
// ---------------------------------------------------------------------------

describe("createPreviewSession", () => {
  it("mints a person preview: token returned once, only sha256 at rest", async () => {
    const { session: rec, token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "Quarterly access review",
    });
    expect(token).toMatch(/^[0-9a-f]{64}$/); // 32 random bytes, hex
    expect(rec.tenantId).toBe("acme");
    expect(rec.rootUserId).toBe("u-root");
    expect(rec.subject).toEqual({ kind: "user", subjectUserId: "u-ana" });
    expect(rec.createdAt).toBe("2026-07-24T10:00:00.000Z");
    expect(rec.expiresAt).toBe(
      new Date(clock.getTime() + DEFAULT_PREVIEW_TTL_MS).toISOString(),
    );
    expect(rec.endedAt).toBeNull();

    const row = (
      await db.query(`SELECT * FROM access_preview_sessions WHERE id = $1`, [rec.id])
    ).rows[0];
    expect(String(row.token_hash)).toBe(
      createHash("sha256").update(token, "utf8").digest("hex"),
    );
    expect(hashPreviewToken(token)).toBe(String(row.token_hash));

    // The raw token appears NOWHERE: not in any table column, audit row, or
    // emitted audit event.
    expect(await allStoredText()).not.toContain(token);

    const start = events.find((e) => e.purpose === "console-view-as-start");
    expect(start).toBeDefined();
    expect(start!.actor).toBe("root@acme.co"); // ROOT actor, never the subject
    expect(start!.result).toBe("ok");
    expect(start!.namespace).toBe("acme");
    expect(start!.detail).toContain(rec.id);
  });

  it("rejects a non-root caller (403) and audits the denial", async () => {
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeAdmin(),
        subjectUserId: "u-ana",
        reason: "nope",
      }),
    ).rejects.toMatchObject({ name: "AuthzError" });
    const denial = events.find(
      (e) => e.purpose === "console-view-as-start" && e.result === "denied",
    );
    expect(denial).toBeDefined();
    expect(denial!.actor).toBe("mia@acme.co");
  });

  it("rejects a bare role - a role preview needs >= 1 functional area", async () => {
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        simulatedRole: "admin",
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        simulatedRole: "member",
        functionalAreaIds: [],
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("rejects subject XOR role violations and person+areas mixes", async () => {
    await expect(
      createPreviewSession(deps, { rootSession: acmeRoot(), reason: "review" }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        subjectUserId: "u-ana",
        simulatedRole: "member",
        functionalAreaIds: ["t-mkt"],
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        subjectUserId: "u-ana",
        functionalAreaIds: ["t-mkt"],
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("requires a non-empty reason of at most 200 chars", async () => {
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        subjectUserId: "u-ana",
        reason: "   ",
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: acmeRoot(),
        subjectUserId: "u-ana",
        reason: "x".repeat(201),
      }),
    ).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("foreign, disabled, and unknown subjects share ONE not-found shape (D46)", async () => {
    const errors: Error[] = [];
    for (const subjectUserId of ["u-fred", "u-dan", "no-such-user"]) {
      try {
        await createPreviewSession(deps, {
          rootSession: acmeRoot(),
          subjectUserId,
          reason: "review",
        });
        expect.unreachable(`subject ${subjectUserId} must not resolve`);
      } catch (err) {
        errors.push(err as Error);
      }
    }
    for (const err of errors) {
      expect(err.name).toBe("PreviewNotFoundError");
      expect(err.message).toBe("not found"); // byte-identical, no oracle
    }
    // Each denial audited (D4 both ways).
    const denials = events.filter(
      (e) => e.purpose === "console-view-as-start" && e.result === "denied",
    );
    expect(denials).toHaveLength(3);
    for (const d of denials) expect(d.actor).toBe("root@acme.co");
  });

  it("foreign and unknown functional areas share the same not-found shape", async () => {
    const shapes: Array<[string, string]> = [];
    for (const area of ["t-git", "no-such-team"]) {
      try {
        await createPreviewSession(deps, {
          rootSession: acmeRoot(),
          simulatedRole: "admin",
          functionalAreaIds: [area, "t-mkt"],
          reason: "review",
        });
        expect.unreachable(`area ${area} must not resolve`);
      } catch (err) {
        shapes.push([(err as Error).name, (err as Error).message]);
      }
    }
    expect(shapes).toEqual([
      ["PreviewNotFoundError", "not found"],
      ["PreviewNotFoundError", "not found"],
    ]);
  });

  it("never lets `_` in a tenant namespace act as a LIKE wildcard", async () => {
    // Root of tenant "t_1" must NOT reach a user or team under "tx1".
    const troot = session("u-troot", "t_1", "root@t1.co", "owner");
    await expect(
      createPreviewSession(deps, {
        rootSession: troot,
        subjectUserId: "u-eve", // lives in tx1/ops
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "PreviewNotFoundError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: troot,
        simulatedRole: "member",
        functionalAreaIds: ["t-tx1"], // team under tx1/ops
        reason: "review",
      }),
    ).rejects.toMatchObject({ name: "PreviewNotFoundError" });
    // The in-tenant equivalents DO resolve.
    const ok = await createPreviewSession(deps, {
      rootSession: troot,
      simulatedRole: "member",
      functionalAreaIds: ["t-t1ops"],
      reason: "review",
    });
    expect(ok.session.tenantId).toBe("t_1");
  });
});

// ---------------------------------------------------------------------------
// resolvePreview
// ---------------------------------------------------------------------------

describe("resolvePreview", () => {
  it("resolves a live person-preview token for the minting root", async () => {
    const { session: rec, token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    const resolved = await resolvePreview(deps, token, acmeRoot());
    expect(resolved).not.toBeNull();
    expect(resolved!.sessionId).toBe(rec.id);
    expect(resolved!.subject).toEqual({ kind: "user", subjectUserId: "u-ana" });
    const read = events.find(
      (e) => e.purpose === "console-view-as-read" && e.result === "ok",
    );
    expect(read).toBeDefined();
    expect(read!.actor).toBe("root@acme.co"); // attributed to ROOT, not ana
  });

  it("resolves a role preview to role + resource IDs", async () => {
    const { token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      simulatedRole: "admin",
      functionalAreaIds: ["t-mkt", "t-sales"],
      reason: "review",
    });
    const resolved = await resolvePreview(deps, token, acmeRoot());
    expect(resolved!.subject).toEqual({
      kind: "role",
      role: "admin",
      functionalAreaIds: ["t-mkt", "t-sales"],
    });
  });

  it("absent or blank header is 'no preview' - null, no audit", async () => {
    expect(await resolvePreview(deps, undefined, acmeRoot())).toBeNull();
    expect(await resolvePreview(deps, "", acmeRoot())).toBeNull();
    expect(await resolvePreview(deps, "   ", acmeRoot())).toBeNull();
    expect(events).toHaveLength(0);
  });

  it("an unknown token is null + an audited denial", async () => {
    expect(await resolvePreview(deps, "deadbeef".repeat(8), acmeRoot())).toBeNull();
    const denial = events.find(
      (e) => e.purpose === "console-view-as-read" && e.result === "denied",
    );
    expect(denial).toBeDefined();
    expect(denial!.actor).toBe("root@acme.co");
  });

  it("is bound to the minting root user AND tenant", async () => {
    const { token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    // Another tenant's root: null.
    expect(await resolvePreview(deps, token, globexRoot())).toBeNull();
    // Same tenant, different (non-minting) session user: null.
    const impostor = session("u-other", "acme", "other@acme.co", "owner");
    expect(await resolvePreview(deps, token, impostor)).toBeNull();
    // Demoted minter (no longer root product role): null, fail-closed.
    const demoted = session("u-root", "acme", "root@acme.co", "member");
    expect(await resolvePreview(deps, token, demoted)).toBeNull();
    // The rightful root still resolves.
    expect(await resolvePreview(deps, token, acmeRoot())).not.toBeNull();
  });

  it("expires at the injected clock (15 min default) and audits the expiry", async () => {
    const { session: rec, token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    clock = new Date(clock.getTime() + DEFAULT_PREVIEW_TTL_MS - 1000);
    expect(isExpired(rec, clock)).toBe(false);
    expect(await resolvePreview(deps, token, acmeRoot())).not.toBeNull();

    clock = new Date(clock.getTime() + 2000); // past expiry
    expect(isExpired(rec, clock)).toBe(true);
    expect(await resolvePreview(deps, token, acmeRoot())).toBeNull();
    const expired = events.find((e) => e.purpose === "console-view-as-expired");
    expect(expired).toBeDefined();
    expect(expired!.result).toBe("denied");
    expect(expired!.actor).toBe("root@acme.co");
  });
});

// ---------------------------------------------------------------------------
// endPreviewSession
// ---------------------------------------------------------------------------

describe("endPreviewSession", () => {
  it("sets ended_at (never deletes), kills the token, and is idempotent", async () => {
    const { session: rec, token } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    clock = new Date(clock.getTime() + 60_000);
    const ended = await endPreviewSession(deps, rec.id, acmeRoot());
    expect(ended.endedAt).toBe(clock.toISOString());

    // D47: the row survives.
    const row = (
      await db.query(`SELECT id, ended_at FROM access_preview_sessions WHERE id = $1`, [rec.id])
    ).rows[0];
    expect(row).toBeDefined();
    expect(row.ended_at).not.toBeNull();

    // The credential is dead.
    expect(await resolvePreview(deps, token, acmeRoot())).toBeNull();

    // Idempotent second end — same endedAt, no error.
    const again = await endPreviewSession(deps, rec.id, acmeRoot());
    expect(again.endedAt).toBe(ended.endedAt);

    const exit = events.find(
      (e) => e.purpose === "console-view-as-exit" && e.result === "ok",
    );
    expect(exit).toBeDefined();
    expect(exit!.actor).toBe("root@acme.co");
  });

  it("a non-root caller is rejected 403", async () => {
    await expect(
      endPreviewSession(deps, "whatever", acmeAdmin()),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("unknown and foreign-tenant ids share the uniform not-found shape", async () => {
    const { session: rec } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    const shapes: Array<[string, string]> = [];
    for (const attempt of [
      () => endPreviewSession(deps, "no-such-id", acmeRoot()),
      () => endPreviewSession(deps, rec.id, globexRoot()), // foreign root
    ]) {
      try {
        await attempt();
        expect.unreachable("must not resolve");
      } catch (err) {
        shapes.push([(err as Error).name, (err as Error).message]);
      }
    }
    expect(shapes).toEqual([
      ["PreviewNotFoundError", "not found"],
      ["PreviewNotFoundError", "not found"],
    ]);
  });
});

// ---------------------------------------------------------------------------
// rejectPreviewMutation (transport guard evidence)
// ---------------------------------------------------------------------------

describe("rejectPreviewMutation", () => {
  it("throws the 403 shape and audits under the ROOT actor with the session id", async () => {
    const { session: rec } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    await expect(
      rejectPreviewMutation(deps, acmeRoot(), rec.id, "post", "/v1/mem/write"),
    ).rejects.toMatchObject({ name: "AuthzError" });
    const denial = events.find((e) => e.purpose === "console-view-as-mutation-denied");
    expect(denial).toBeDefined();
    expect(denial!.result).toBe("denied");
    expect(denial!.actor).toBe("root@acme.co"); // ROOT, never the subject
    expect(denial!.detail).toContain(rec.id);
    expect(denial!.detail).toContain("POST");
  });
});

// ---------------------------------------------------------------------------
// listPreviewTargets
// ---------------------------------------------------------------------------

describe("listPreviewTargets", () => {
  it("returns ONLY the root's own tenant: named active people (product roles) + areas", async () => {
    await db.query(`UPDATE users SET display_name = 'Ana Ortiz' WHERE id = 'u-ana'`);
    const targets = await listPreviewTargets(deps, acmeRoot());
    const emails = targets.people.map((p) => p.email);
    expect(emails).toContain("root@acme.co");
    expect(emails).toContain("ana@acme.co");
    expect(emails).toContain("mia@acme.co");
    expect(emails).not.toContain("dan@acme.co"); // disabled
    expect(emails).not.toContain("fred@acme.co"); // foreign tenant
    expect(emails).not.toContain("root@globex.co");

    // Product roles only — never internal owner/auditor (D41 via injected seam).
    expect(targets.people.find((p) => p.email === "ana@acme.co")?.displayName).toBe("Ana Ortiz");
    const byEmail = new Map(targets.people.map((p) => [p.email, p.role]));
    expect(byEmail.get("root@acme.co")).toBe("root");
    expect(byEmail.get("audrey@acme.co")).toBe("member"); // auditor -> member
    for (const p of targets.people) {
      expect(["root", "admin", "member"]).toContain(p.role);
    }

    const areaIds = targets.areas.map((a) => a.id);
    expect(areaIds).toContain("t-mkt");
    expect(areaIds).toContain("t-sales");
    expect(areaIds).not.toContain("t-git"); // foreign tenant
  });

  it("tenant `t_1` never sees `tx1` rows (escaped-prefix, not wildcard)", async () => {
    const targets = await listPreviewTargets(
      deps,
      session("u-troot", "t_1", "root@t1.co", "owner"),
    );
    const emails = targets.people.map((p) => p.email);
    expect(emails).toContain("ops@t1.co");
    expect(emails).not.toContain("eve@tx1.co");
    expect(targets.areas.map((a) => a.id)).not.toContain("t-tx1");
  });

  it("a non-root caller is rejected 403 and the denial audited", async () => {
    await expect(listPreviewTargets(deps, acmeAdmin())).rejects.toMatchObject({
      name: "AuthzError",
    });
    const denial = events.find(
      (e) => e.purpose === "console-view-as-targets" && e.result === "denied",
    );
    expect(denial).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// The "" owner is the ORGANIZATION ROOT of the unprefixed organization
// (single-org installs). Its View-as reaches ONLY namespaces whose first
// segment is not a registered tenant — customer tenants stay invisible
// (PRD §14.1, D43).
// ---------------------------------------------------------------------------

describe("'' organization root: own-org view-as, zero tenant reach", () => {
  const platformRoot = () =>
    session("u-proot", "", "platform@halomem.test", "owner");

  it("targets list the '' organization only - never a registered tenant's rows", async () => {
    const targets = await listPreviewTargets(deps, platformRoot());
    expect(targets.people.map((p) => p.id)).toEqual(["u-gina"]);
    expect(targets.areas.map((a) => a.id)).toEqual(["t-grow"]);
    const wire = JSON.stringify(targets);
    for (const marker of ["acme", "globex", "t_1", "tx1", "@acme.co", "@globex.co"]) {
      expect(wire).not.toContain(marker);
    }
  });

  it("cannot start a preview of a registered tenant's user or area (uniform miss)", async () => {
    await expect(
      createPreviewSession(deps, {
        rootSession: platformRoot(),
        subjectUserId: "u-fred", // lives in globex/it
        reason: "cross-tenant grab",
      }),
    ).rejects.toMatchObject({ name: "PreviewNotFoundError" });
    await expect(
      createPreviewSession(deps, {
        rootSession: platformRoot(),
        simulatedRole: "member",
        functionalAreaIds: ["t-git"],
        reason: "cross-tenant grab",
      }),
    ).rejects.toMatchObject({ name: "PreviewNotFoundError" });
    const rows = await db.query(
      `SELECT subject_user_id FROM access_preview_sessions WHERE tenant_id = ''`,
    );
    // No '' session ever binds a tenant subject.
    for (const row of rows.rows) {
      expect(row.subject_user_id).not.toBe("u-fred");
    }
  });

  it("can preview its OWN organization member and role+area simulation", async () => {
    const person = await createPreviewSession(deps, {
      rootSession: platformRoot(),
      subjectUserId: "u-gina",
      reason: "org access review",
    });
    expect(person.session.tenantId).toBe("");
    expect(person.token.length).toBeGreaterThan(0);

    const sim = await createPreviewSession(deps, {
      rootSession: platformRoot(),
      simulatedRole: "member",
      functionalAreaIds: ["t-grow"],
      reason: "org role review",
    });
    expect(sim.session.tenantId).toBe("");
    await endPreviewSession(deps, person.session.id, platformRoot());
    await endPreviewSession(deps, sim.session.id, platformRoot());
  });

  it("cannot end (or probe) another tenant's preview sessions", async () => {
    const { session: rec } = await createPreviewSession(deps, {
      rootSession: acmeRoot(),
      subjectUserId: "u-ana",
      reason: "review",
    });
    await expect(
      endPreviewSession(deps, rec.id, platformRoot()),
    ).rejects.toMatchObject({ name: "PreviewNotFoundError" });
  });
});
