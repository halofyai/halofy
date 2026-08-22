/**
 * Module A (M4) tests — tenancy core.
 *
 * Hermetic: fresh in-memory PGlite with migrations 1..6, zero network/Docker.
 * A tenant is a root namespace; isolation is the SAME ancestor-prefix ACL the
 * index uses (no parallel filter, no LIKE wildcard). These tests prove the
 * registry surface: owner-only register, single-segment id validation, root
 * extraction, ancestor-scoped list (an `acme` owner never sees `globex`), and
 * suspend/activate status flips.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import {
  InvalidTenantIdError,
  TenantAuthzError,
  TenantRegistry,
  isValidTenantId,
  tenantRootOf,
} from "../src/tenancy/index.js";
import type { Identity } from "../src/types.js";

const DIM = 8;

let db: Db;
let registry: TenantRegistry;

/** A root owner who can register tenants (D9: server-resolved identity). */
const rootOwner: Identity = {
  keyId: "k-root",
  namespace: "",
  actor: "founder",
  role: "owner",
};

const acmeOwner: Identity = {
  keyId: "k-acme",
  namespace: "acme",
  actor: "acme-admin",
  role: "owner",
};

const acmeMember: Identity = {
  keyId: "k-acme-m",
  namespace: "acme/support",
  actor: "agent-7",
  role: "member",
};

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  registry = new TenantRegistry(db);
});

afterAll(async () => {
  await db.close();
});

describe("tenantRootOf", () => {
  it("returns the first '/'-split segment", () => {
    expect(tenantRootOf("acme/support/a")).toBe("acme");
    expect(tenantRootOf("acme")).toBe("acme");
    expect(tenantRootOf("globex/team/agent/user")).toBe("globex");
  });

  it("returns '' for empty or blank namespaces", () => {
    expect(tenantRootOf("")).toBe("");
    expect(tenantRootOf("/")).toBe("");
    expect(tenantRootOf("//")).toBe("");
  });
});

describe("isValidTenantId", () => {
  it("accepts single-segment roots and rejects multi-segment / empty", () => {
    expect(isValidTenantId("acme")).toBe(true);
    expect(isValidTenantId("globex")).toBe(true);
    expect(isValidTenantId("a/b")).toBe(false);
    expect(isValidTenantId("")).toBe(false);
  });
});

describe("TenantRegistry.register", () => {
  it("registers two root tenants (acme + globex) as an owner", async () => {
    const acme = await registry.register({ id: "acme", name: "Acme Inc" }, rootOwner);
    const globex = await registry.register(
      { id: "globex", name: "Globex Corp", monthlyBudgetUsd: 50, rateLimitPerMin: 30 },
      rootOwner,
    );
    expect(acme.id).toBe("acme");
    expect(acme.status).toBe("active");
    expect(acme.monthlyBudgetUsd).toBeNull();
    expect(globex.monthlyBudgetUsd).toBe(50);
    expect(globex.rateLimitPerMin).toBe(30);

    expect((await registry.get("acme"))?.name).toBe("Acme Inc");
    expect((await registry.get("globex"))?.name).toBe("Globex Corp");
    expect(await registry.get("nope")).toBeNull();
  });

  it("rejects both non-owners and tenant-scoped owners", async () => {
    await expect(
      registry.register({ id: "evil", name: "Evil" }, acmeMember),
    ).rejects.toThrow(TenantAuthzError);
    await expect(
      registry.register({ id: "evil", name: "Evil" }, acmeOwner),
    ).rejects.toThrow(TenantAuthzError);
    expect(await registry.get("evil")).toBeNull();
  });

  it("rejects a multi-segment id 'a/b'", async () => {
    await expect(
      registry.register({ id: "a/b", name: "Bad" }, rootOwner),
    ).rejects.toThrow(InvalidTenantIdError);
    expect(await registry.get("a/b")).toBeNull();
  });

  it("rejects an empty id ''", async () => {
    await expect(
      registry.register({ id: "", name: "Empty" }, rootOwner),
    ).rejects.toThrow(InvalidTenantIdError);
  });
});

describe("TenantRegistry.list (ancestor-ACL scoped)", () => {
  it("an acme owner sees acme but NEVER a sibling globex", async () => {
    const seen = await registry.list(acmeOwner);
    const ids = seen.map((t) => t.id);
    expect(ids).toContain("acme");
    expect(ids).not.toContain("globex");
  });

  it("a caller inside the acme subtree still only sees acme (ancestor set)", async () => {
    const seen = await registry.list(acmeMember);
    const ids = seen.map((t) => t.id);
    expect(ids).toContain("acme");
    expect(ids).not.toContain("globex");
  });

  it("the platform root owner sees every tenant", async () => {
    const seen = await registry.list(rootOwner);
    expect(seen.map((t) => t.id)).toContain("acme");
    expect(seen.map((t) => t.id)).toContain("globex");
  });
});

describe("TenantRegistry.suspend / activate", () => {
  it("suspend then get shows status 'suspended', activate restores 'active'", async () => {
    const suspended = await registry.suspend("acme");
    expect(suspended?.status).toBe("suspended");
    expect((await registry.get("acme"))?.status).toBe("suspended");

    const activated = await registry.activate("acme");
    expect(activated?.status).toBe("active");
    expect((await registry.get("acme"))?.status).toBe("active");
  });

  it("returns null for an unknown tenant id", async () => {
    expect(await registry.suspend("ghost")).toBeNull();
    expect(await registry.activate("ghost")).toBeNull();
  });
});

describe("TenantRegistry.resolveTenant", () => {
  it("resolves a namespace to the tenant at its root", async () => {
    expect((await registry.resolveTenant("acme/support/a"))?.id).toBe("acme");
    expect((await registry.resolveTenant("globex/x/y"))?.id).toBe("globex");
  });

  it("returns null for an unregistered or empty root", async () => {
    expect(await registry.resolveTenant("unregistered/x")).toBeNull();
    expect(await registry.resolveTenant("")).toBeNull();
  });
});
