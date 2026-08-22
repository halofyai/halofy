/**
 * M10 ACCESS — access-projection module tests (CONTRACTS-M10-ACCESS.md
 * module "projection"; exit criteria E2/E3/E4/E5/E10 slices that live in
 * this module).
 *
 * Hermetic: structural fake deps, injected fixed clock, and a tiny
 * in-memory PGlite table to prove the visibility predicate against real
 * SQL — including namespaces containing `_`, `%`, and `\` (literal-only
 * matching, D44) and the sibling `acme/functions/marketing2` never being
 * matched by govern root `acme/functions/marketing`.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import type { AccessGrantRecord, AccessProjection } from "../src/types.js";
import {
  buildVisibilityPredicate,
  hashProjection,
  projectionVersionFor,
  resolveProjection,
  ProjectionUnavailableError,
  type AccessProjectionDeps,
  type MembershipRoots,
} from "../src/access-projection/index.js";

const NOW = new Date("2026-07-24T12:00:00.000Z");
const TENANT = "acme";
const SUBJECT = "user_01";

let grantSeq = 0;
function grant(over: Partial<AccessGrantRecord>): AccessGrantRecord {
  grantSeq += 1;
  return {
    id: `01GRANT${String(grantSeq).padStart(4, "0")}`,
    tenantId: TENANT,
    principalType: "human",
    principalId: SUBJECT,
    resourceType: "function",
    resourceId: "res-marketing",
    accessMode: "consume",
    source: "direct",
    createdBy: "root_user",
    createdAt: "2026-07-01T00:00:00.000Z",
    expiresAt: null,
    revokedAt: null,
    ...over,
  };
}

interface DepsOverrides {
  role?: AccessProjectionDeps["roleOf"];
  tenant?: AccessProjectionDeps["tenantOf"];
  grants?: readonly AccessGrantRecord[];
  membership?: MembershipRoots;
  resourceRoots?: Record<string, string>;
  grantsVersion?: number;
  membershipVersion?: number;
  now?: () => Date;
}

const DEFAULT_RESOURCE_ROOTS: Record<string, string> = {
  "function:res-marketing": "acme/functions/marketing/shared",
  "function:res-sales": "acme/functions/sales/shared",
  "function:res-marketing-tree": "acme/functions/marketing",
  "function:res-under": "acme/func_x",
  "common:res-common": "acme/common",
  "personal:res-me": "acme/functions/marketing/people/user_01",
  "function:res-root-private": "acme/root-private/notes",
  "function:res-foreign": "other/functions/marketing",
  "audit:res-audit": "acme/functions/marketing",
};

function makeDeps(over: DepsOverrides = {}): AccessProjectionDeps {
  const roots = over.resourceRoots ?? DEFAULT_RESOURCE_ROOTS;
  return {
    tenantOf: over.tenant ?? (async () => TENANT),
    roleOf: over.role ?? (async () => "member"),
    grantsFor: async () => over.grants ?? [],
    membershipRootsFor: async () =>
      over.membership ?? { consumeRoots: [], personalRoots: [] },
    resourceRootOf: async (_tenant, resourceType, resourceId) =>
      roots[`${resourceType}:${resourceId}`] ?? null,
    grantsVersionFor: async () => over.grantsVersion ?? 1,
    membershipVersionFor: async () => over.membershipVersion ?? 1,
    now: over.now ?? (() => NOW),
  };
}

const subject = { subjectId: SUBJECT };

// ---------------------------------------------------------------------------
// Role ceiling × grant mode × operation matrix (D42)
// ---------------------------------------------------------------------------

describe("resolveProjection - role × mode × operation matrix", () => {
  it("member with no grants: graph:read only, empty roots", async () => {
    const p = await resolveProjection(makeDeps(), subject);
    expect(p.allowedOperations).toEqual(["graph:read"]);
    expect(p.consumeRoots).toEqual([]);
    expect(p.governRoots).toEqual([]);
    expect(p.personalRoots).toEqual([]);
    expect(p.role).toBe("member");
    expect(p.tenantId).toBe(TENANT);
  });

  it("member with a consume grant gets consume operations, never govern", async () => {
    const p = await resolveProjection(
      makeDeps({ grants: [grant({ accessMode: "consume" })] }),
      subject,
    );
    expect(p.consumeRoots).toEqual(["acme/functions/marketing/shared"]);
    expect(p.governRoots).toEqual([]);
    expect(p.allowedOperations).toContain("memory:read");
    expect(p.allowedOperations).toContain("memory:search");
    expect(p.allowedOperations).toContain("context:assemble");
    expect(p.allowedOperations).toContain("delegate:create");
    expect(p.allowedOperations).not.toContain("memory:govern");
    expect(p.allowedOperations).not.toContain("grants:manage");
    expect(p.allowedOperations).not.toContain("audit:read");
  });

  it("member with a poisoned govern grant is capped to consume (D42)", async () => {
    const p = await resolveProjection(
      makeDeps({
        grants: [grant({ accessMode: "govern", resourceId: "res-marketing-tree" })],
      }),
      subject,
    );
    expect(p.governRoots).toEqual([]);
    expect(p.consumeRoots).toEqual(["acme/functions/marketing"]);
    expect(p.allowedOperations).not.toContain("memory:govern");
    expect(p.allowedOperations).not.toContain("grants:manage");
  });

  it("admin with a govern grant gets govern + consume operations", async () => {
    const p = await resolveProjection(
      makeDeps({
        role: async () => "admin",
        grants: [grant({ accessMode: "govern", resourceId: "res-marketing-tree" })],
      }),
      subject,
    );
    expect(p.governRoots).toEqual(["acme/functions/marketing"]);
    expect(p.consumeRoots).toContain("acme/functions/marketing");
    expect(p.allowedOperations).toContain("memory:govern");
    expect(p.allowedOperations).toContain("grants:manage");
    expect(p.allowedOperations).toContain("memory:read");
  });

  it("admin with zero govern grants has no functional admin reach (D42)", async () => {
    const p = await resolveProjection(
      makeDeps({ role: async () => "admin", grants: [grant({ accessMode: "consume" })] }),
      subject,
    );
    expect(p.governRoots).toEqual([]);
    expect(p.allowedOperations).not.toContain("memory:govern");
    expect(p.allowedOperations).not.toContain("grants:manage");
  });

  it("audit_read grant adds audit:read only - no visibility roots (D41)", async () => {
    const p = await resolveProjection(
      makeDeps({
        grants: [grant({ accessMode: "audit_read", resourceType: "audit", resourceId: "res-audit" })],
      }),
      subject,
    );
    expect(p.allowedOperations).toContain("audit:read");
    expect(p.consumeRoots).toEqual([]);
    expect(p.governRoots).toEqual([]);
    expect(p.personalRoots).toEqual([]);
  });

  it("personal grant lands in personalRoots exactly", async () => {
    const p = await resolveProjection(
      makeDeps({
        grants: [grant({ resourceType: "personal", resourceId: "res-me" })],
      }),
      subject,
    );
    expect(p.personalRoots).toEqual(["acme/functions/marketing/people/user_01"]);
    expect(p.consumeRoots).toEqual([]);
    expect(p.allowedOperations).toContain("memory:read");
  });

  it("membership roots feed consume/personal roots", async () => {
    const p = await resolveProjection(
      makeDeps({
        membership: {
          consumeRoots: ["acme/functions/sales/shared"],
          personalRoots: ["acme/functions/sales/people/user_01"],
        },
      }),
      subject,
    );
    expect(p.consumeRoots).toEqual(["acme/functions/sales/shared"]);
    expect(p.personalRoots).toEqual(["acme/functions/sales/people/user_01"]);
  });

  it("root is tenant-wide, tenant-bound, all operations (E5)", async () => {
    const p = await resolveProjection(makeDeps({ role: async () => "root" }), subject);
    expect(p.consumeRoots).toContain(TENANT);
    expect(p.governRoots).toContain(TENANT);
    for (const op of [
      "graph:read",
      "memory:read",
      "memory:search",
      "context:assemble",
      "delegate:create",
      "memory:govern",
      "grants:manage",
      "audit:read",
    ]) {
      expect(p.allowedOperations).toContain(op);
    }
    for (const root of [...p.consumeRoots, ...p.governRoots]) {
      expect(root === TENANT || root.startsWith(`${TENANT}/`)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Poisoned / stale grant rows (D47, D48, cross-tenant)
// ---------------------------------------------------------------------------

describe("resolveProjection - defensive grant filtering", () => {
  it("ignores cross-tenant grant rows", async () => {
    const p = await resolveProjection(
      makeDeps({ grants: [grant({ tenantId: "other" })] }),
      subject,
    );
    expect(p.consumeRoots).toEqual([]);
    expect(p.allowedOperations).toEqual(["graph:read"]);
  });

  it("ignores grants whose resource resolves outside the tenant", async () => {
    const p = await resolveProjection(
      makeDeps({ grants: [grant({ resourceId: "res-foreign" })] }),
      subject,
    );
    expect(p.consumeRoots).toEqual([]);
  });

  it("ignores grants for a different principal", async () => {
    const p = await resolveProjection(
      makeDeps({ grants: [grant({ principalId: "someone_else" })] }),
      subject,
    );
    expect(p.consumeRoots).toEqual([]);
  });

  it("ignores revoked grants (D47: revocation is a row state)", async () => {
    const p = await resolveProjection(
      makeDeps({ grants: [grant({ revokedAt: "2026-07-02T00:00:00.000Z" })] }),
      subject,
    );
    expect(p.consumeRoots).toEqual([]);
  });

  it("ignores expired grants under the injected clock; honors unexpired", async () => {
    const expired = grant({ expiresAt: "2026-07-24T11:59:59.000Z" });
    const live = grant({ expiresAt: "2026-07-24T12:00:01.000Z", resourceId: "res-sales" });
    const p = await resolveProjection(makeDeps({ grants: [expired, live] }), subject);
    expect(p.consumeRoots).toEqual(["acme/functions/sales/shared"]);
  });

  it("a grant expires between two resolutions when the clock advances", async () => {
    let nowMs = Date.parse("2026-07-24T12:00:00.000Z");
    const deps = makeDeps({
      grants: [grant({ expiresAt: "2026-07-24T12:10:00.000Z" })],
      now: () => new Date(nowMs),
    });
    const before = await resolveProjection(deps, subject);
    expect(before.consumeRoots).toEqual(["acme/functions/marketing/shared"]);
    nowMs += 11 * 60 * 1000; // +11 minutes
    const after = await resolveProjection(deps, subject);
    expect(after.consumeRoots).toEqual([]);
    expect(after.hash).not.toBe(before.hash);
  });

  it("root-private never enters a member/admin projection, even poisoned (D48)", async () => {
    for (const role of ["member", "admin"] as const) {
      const p = await resolveProjection(
        makeDeps({
          role: async () => role,
          grants: [
            grant({ resourceId: "res-root-private", accessMode: role === "admin" ? "govern" : "consume" }),
          ],
        }),
        subject,
      );
      expect(p.consumeRoots).toEqual([]);
      expect(p.governRoots).toEqual([]);
    }
  });

  it("fails closed on dependency failure - never a broader projection", async () => {
    const deps = makeDeps({
      role: async () => {
        throw new Error("db down");
      },
    });
    await expect(resolveProjection(deps, subject)).rejects.toBeInstanceOf(
      ProjectionUnavailableError,
    );
  });

  it("fails closed on an empty tenant (never global)", async () => {
    await expect(
      resolveProjection(makeDeps({ tenant: async () => "" }), subject),
    ).rejects.toBeInstanceOf(ProjectionUnavailableError);
  });
});

// ---------------------------------------------------------------------------
// Hash stability + sensitivity (cache partitioning, contract rule 7)
// ---------------------------------------------------------------------------

describe("hashProjection", () => {
  const base: AccessProjection = {
    tenantId: TENANT,
    subjectId: SUBJECT,
    role: "member",
    consumeRoots: ["acme/functions/marketing/shared", "acme/common"],
    governRoots: ["acme/functions/marketing"],
    personalRoots: ["acme/functions/marketing/people/user_01"],
    allowedOperations: ["graph:read", "memory:read"],
    version: 3,
    hash: "",
  };

  it("is stable across array ordering and object key order", () => {
    const reorderedArrays: AccessProjection = {
      ...base,
      consumeRoots: ["acme/common", "acme/functions/marketing/shared"],
      allowedOperations: ["memory:read", "graph:read"],
    };
    // Different key insertion order entirely.
    const reorderedKeys = {
      hash: "",
      version: 3,
      allowedOperations: ["memory:read", "graph:read"],
      personalRoots: ["acme/functions/marketing/people/user_01"],
      governRoots: ["acme/functions/marketing"],
      consumeRoots: ["acme/common", "acme/functions/marketing/shared"],
      role: "member",
      subjectId: SUBJECT,
      tenantId: TENANT,
    } as AccessProjection;
    const h = hashProjection(base);
    expect(hashProjection(reorderedArrays)).toBe(h);
    expect(hashProjection(reorderedKeys)).toBe(h);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when any authorization-relevant field changes", () => {
    const h = hashProjection(base);
    const variants: AccessProjection[] = [
      { ...base, tenantId: "acme2" },
      { ...base, subjectId: "user_02" },
      { ...base, role: "admin" },
      { ...base, consumeRoots: [...base.consumeRoots, "acme/functions/sales/shared"] },
      { ...base, governRoots: [] },
      { ...base, personalRoots: [] },
      { ...base, allowedOperations: [...base.allowedOperations, "audit:read"] },
      { ...base, version: 4 },
      { ...base, sensitivityCeiling: "restricted" },
    ];
    const hashes = variants.map(hashProjection);
    for (const v of hashes) expect(v).not.toBe(h);
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it("resolveProjection embeds a matching hash and version = max(deps versions)", async () => {
    const p = await resolveProjection(
      makeDeps({ grantsVersion: 2, membershipVersion: 7 }),
      subject,
    );
    expect(p.version).toBe(7);
    expect(p.hash).toBe(hashProjection(p));
  });
});

// ---------------------------------------------------------------------------
// projectionVersionFor — invalidation seam
// ---------------------------------------------------------------------------

describe("projectionVersionFor", () => {
  it("returns the max of grant and membership counters", async () => {
    const deps = makeDeps({ grantsVersion: 9, membershipVersion: 4 });
    await expect(projectionVersionFor(deps, SUBJECT)).resolves.toBe(9);
  });

  it("a version bump changes the projection hash (stale caches strand)", async () => {
    const before = await resolveProjection(makeDeps({ grantsVersion: 1 }), subject);
    const after = await resolveProjection(makeDeps({ grantsVersion: 2 }), subject);
    expect(after.version).toBeGreaterThan(before.version);
    expect(after.hash).not.toBe(before.hash);
  });

  it("fails closed when a counter dep fails", async () => {
    const deps = makeDeps();
    deps.grantsVersionFor = async () => {
      throw new Error("db down");
    };
    await expect(projectionVersionFor(deps, SUBJECT)).rejects.toBeInstanceOf(
      ProjectionUnavailableError,
    );
  });
});

// ---------------------------------------------------------------------------
// buildVisibilityPredicate — proven against real SQL (PGlite)
// ---------------------------------------------------------------------------

const NAMESPACES = [
  "acme",
  "acme/common",
  "acme/common/notes",
  "acme/functions",
  "acme/functions/marketing",
  "acme/functions/marketing/shared",
  "acme/functions/marketing/people/user_01",
  "acme/functions/marketing/people/user_02",
  "acme/functions/marketing2",
  "acme/functions/marketing2/shared",
  "acme/functions/sales",
  "acme/functions/sales/shared",
  "acme/func_x",
  "acme/func_x/child",
  "acme/funcYx",
  "acme/funcYx/child",
  "acme/pct%team",
  "acme/pct%team/kid",
  "acme/pctXteam", // '%' as a wildcard would match this sibling family
  "acme/pctXteam/kid",
  "acme/back\\slash",
  "acme/back\\slash/kid",
  "acme/backslash",
  "acme/backslash/kid",
  "acme/root-private",
  "acme/root-private/notes",
  "other",
  "other/functions/marketing",
  "other/functions/marketing/shared",
];

function projection(over: Partial<AccessProjection>): AccessProjection {
  return {
    tenantId: TENANT,
    subjectId: SUBJECT,
    role: "member",
    consumeRoots: [],
    governRoots: [],
    personalRoots: [],
    allowedOperations: ["graph:read"],
    version: 1,
    hash: "x",
    ...over,
  };
}

describe("buildVisibilityPredicate (real SQL on PGlite)", () => {
  let pg: PGlite;

  async function visible(p: AccessProjection): Promise<string[]> {
    const pred = buildVisibilityPredicate(p);
    const res = await pg.query(
      `SELECT namespace FROM ns_rows WHERE ${pred.sql}`,
      pred.params,
    );
    // Sort in JS: SQL collation ordering of %, _, \ varies by build.
    return (res.rows as { namespace: string }[]).map((r) => r.namespace).sort();
  }

  beforeAll(async () => {
    pg = new PGlite();
    await pg.query("CREATE TABLE ns_rows (namespace TEXT PRIMARY KEY)");
    for (const ns of NAMESPACES) {
      await pg.query("INSERT INTO ns_rows (namespace) VALUES ($1)", [ns]);
    }
  });

  afterAll(async () => {
    await pg.close();
  });

  it("govern root does NOT match sibling acme/functions/marketing2 (D44)", async () => {
    const rows = await visible(
      projection({ role: "admin", governRoots: ["acme/functions/marketing"] }),
    );
    expect(rows).toEqual([
      "acme/functions/marketing",
      "acme/functions/marketing/people/user_01",
      "acme/functions/marketing/people/user_02",
      "acme/functions/marketing/shared",
    ]);
    expect(rows).not.toContain("acme/functions/marketing2");
    expect(rows).not.toContain("acme/functions/marketing2/shared");
  });

  it("underscore in a govern root is literal - funcYx sibling invisible", async () => {
    const rows = await visible(projection({ role: "admin", governRoots: ["acme/func_x"] }));
    expect(rows).toEqual(["acme/func_x", "acme/func_x/child"]);
  });

  it("percent in a govern root is literal", async () => {
    const rows = await visible(projection({ role: "admin", governRoots: ["acme/pct%team"] }));
    expect(rows).toEqual(["acme/pct%team", "acme/pct%team/kid"]);
  });

  it("backslash in a govern root is literal", async () => {
    const rows = await visible(
      projection({ role: "admin", governRoots: ["acme/back\\slash"] }),
    );
    expect(rows).toEqual(["acme/back\\slash", "acme/back\\slash/kid"]);
  });

  it("consume roots expand upward via exact ancestors, excluding the bare tenant (D48)", async () => {
    const rows = await visible(
      projection({ consumeRoots: ["acme/functions/marketing/shared"] }),
    );
    expect(rows).toEqual([
      "acme/functions",
      "acme/functions/marketing",
      "acme/functions/marketing/shared",
    ]);
    expect(rows).not.toContain("acme"); // no common/tenant grant -> no bare tenant
    expect(rows).not.toContain("acme/functions/marketing/people/user_02");
  });

  it("a common grant admits the bare tenant namespace", async () => {
    const rows = await visible(
      projection({ consumeRoots: ["acme/common", "acme/functions/marketing/shared"] }),
    );
    expect(rows).toContain("acme");
    expect(rows).toContain("acme/common");
    expect(rows).not.toContain("acme/common/notes"); // consume is upward, not subtree
  });

  it("personal roots are exact - sibling personal spaces invisible", async () => {
    const rows = await visible(
      projection({ personalRoots: ["acme/functions/marketing/people/user_01"] }),
    );
    expect(rows).toEqual(["acme/functions/marketing/people/user_01"]);
  });

  it("root role: tenant-wide but tenant-bound - no other tenant, ever (E5)", async () => {
    const rows = await visible(
      projection({ role: "root", consumeRoots: [TENANT], governRoots: [TENANT] }),
    );
    const expected = NAMESPACES.filter((n) => n === "acme" || n.startsWith("acme/")).sort();
    expect(rows).toEqual(expected);
    expect(rows.some((n) => n === "other" || n.startsWith("other/"))).toBe(false);
  });

  it("root-private never matches for member/admin, even if poisoned into roots", async () => {
    const rows = await visible(
      projection({
        role: "admin",
        consumeRoots: ["acme/root-private/notes"],
        governRoots: ["acme/root-private"],
      }),
    );
    expect(rows).toEqual([]);
  });

  it("empty projection matches nothing (fail closed)", async () => {
    const pred = buildVisibilityPredicate(projection({}));
    expect(pred.sql).toBe("(FALSE)");
    expect(pred.params).toEqual([]);
    const rows = await visible(projection({}));
    expect(rows).toEqual([]);
  });

  it("cross-tenant roots are dropped from the predicate", async () => {
    const rows = await visible(
      projection({
        role: "admin",
        consumeRoots: ["other/functions/marketing/shared"],
        governRoots: ["other/functions/marketing"],
      }),
    );
    expect(rows).toEqual([]);
  });

  it("throws on an empty tenant - a predicate is never global", () => {
    expect(() =>
      buildVisibilityPredicate(projection({ tenantId: "", role: "root", governRoots: [""] })),
    ).toThrow(ProjectionUnavailableError);
  });

  it("paramOffset shifts placeholders for composition into larger queries", async () => {
    const pred = buildVisibilityPredicate(
      projection({ role: "admin", governRoots: ["acme/functions/marketing"] }),
      { paramOffset: 2 },
    );
    expect(pred.sql).toContain("$3");
    expect(pred.sql).not.toContain("$1");
    const res = await pg.query(
      `SELECT namespace FROM ns_rows WHERE namespace <> $1 AND namespace <> $2 AND ${pred.sql}`,
      ["__none1__", "__none2__", ...pred.params],
    );
    expect((res.rows as { namespace: string }[]).map((r) => r.namespace).sort()).toEqual([
      "acme/functions/marketing",
      "acme/functions/marketing/people/user_01",
      "acme/functions/marketing/people/user_02",
      "acme/functions/marketing/shared",
    ]);
  });

  it("govern subtree subsumes redundant exact entries but keeps upward ancestors", async () => {
    const rows = await visible(
      projection({
        role: "admin",
        consumeRoots: ["acme/functions/marketing"],
        governRoots: ["acme/functions/marketing"],
      }),
    );
    // Subtree from govern + upward ancestor from consume; still no siblings.
    expect(rows).toEqual([
      "acme/functions",
      "acme/functions/marketing",
      "acme/functions/marketing/people/user_01",
      "acme/functions/marketing/people/user_02",
      "acme/functions/marketing/shared",
    ]);
  });
});
