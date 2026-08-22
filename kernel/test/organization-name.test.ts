/**
 * Organization display names are presentation data, but their capitalization
 * is a platform-wide invariant. The stable tenant id remains lowercase and is
 * never rewritten: only `tenants.name` is normalized.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { normalizedOrganizationName } from "../src/console/org-name.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations.js";
import { TenantRegistry } from "../src/tenancy/index.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
const rootOwner: Identity = {
  keyId: "organization-name-root",
  namespace: "",
  actor: "root@example.test",
  role: "owner",
};

let db: Db;

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
});

afterAll(async () => {
  await db.close();
});

describe("organization display-name capitalization", () => {
  it("capitalizes the first character after whitespace normalization", () => {
    expect(normalizedOrganizationName("  halofy   organization  ")).toBe(
      "Halofy organization",
    );
  });

  it("preserves intentional brand casing after the first character", () => {
    expect(normalizedOrganizationName("OpenAI Research")).toBe("OpenAI Research");
  });

  it("normalizes the platform-root tenant registration path", async () => {
    const registry = new TenantRegistry(db);
    const created = await registry.register(
      { id: "lowercase-registration", name: "lowercase labs" },
      rootOwner,
    );

    expect(created.name).toBe("Lowercase labs");
    expect((await registry.get(created.id))?.name).toBe("Lowercase labs");
  });

  it("backfills legacy rows and prevents a lowercase first character at the database", async () => {
    const migration = MIGRATIONS.find((candidate) => candidate.version === 78);
    expect(migration?.name).toBe("organization-name-capitalization");

    // Recreate the state immediately before v78, seed the browser-visible
    // legacy value, then let the normal migration runner repair it.
    await db.query(
      `ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_name_initial_capital_check`,
    );
    await db.query(`DELETE FROM schema_migrations WHERE version = 78`);
    await db.query(
      `INSERT INTO tenants (id, name, status, created_at)
       VALUES ('legacy-lowercase', 'halofy-organization-xenc5e4w', 'active', NOW())`,
    );

    await migrate(db, DIM);

    const repaired = await db.query(`SELECT id, name FROM tenants WHERE id = 'legacy-lowercase'`);
    expect(repaired.rows).toEqual([
      { id: "legacy-lowercase", name: "Halofy-organization-xenc5e4w" },
    ]);
    await expect(
      db.query(
        `INSERT INTO tenants (id, name, status, created_at)
         VALUES ('still-lowercase', 'another org', 'active', NOW())`,
      ),
    ).rejects.toThrow();
  });
});
