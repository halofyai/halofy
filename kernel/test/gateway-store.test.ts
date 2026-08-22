/**
 * M8 durable grant-store executable contract.
 *
 * Hermetic: one in-memory PGlite/Postgres-compatible database, zero network.
 * Authority snapshots are immutable: creation and revocation are the only
 * writes, and every read re-validates the stored JSON before returning it.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import type {
  AgentConnectionGrant,
  GatewayAdministrativeIdentity,
} from "../src/gateway/contracts.js";
import { AgentConnectionGrantStore } from "../src/gateway/store.js";

const DIM = 8;
const FUTURE = "2099-01-01T00:00:00.000Z";
const OVERSIGHT = {
  maxRequestsPerMinute: 60,
  usageAlertThreshold: 100,
  deniedAlertThreshold: 1,
  recipientRoles: ["owner", "admin"],
  accessRequests: "allowed",
  approvalTtlSeconds: 3_600,
} as const;

let db: Db;

function admin(
  namespace: string,
  role: GatewayAdministrativeIdentity["role"] = "admin",
): GatewayAdministrativeIdentity {
  return { namespace, role };
}

function grant(overrides: Partial<AgentConnectionGrant> = {}): AgentConnectionGrant {
  return {
    id: "grant-1",
    keyId: "key-1",
    namespace: "acme/eng",
    connectorId: "postgres-primary",
    allowedOperations: ["read", "search", "source-read"],
    allowedSourceRefs: ["customers"],
    allowedFields: { customers: ["id", "name"] },
    allowedPurposes: ["support"],
    maxSensitivity: "confidential",
    maxRows: 25,
    maxBytes: 64_000,
    policyVersion: 1,
    status: "active",
    expiresAt: FUTURE,
    oversight: OVERSIGHT,
    ...overrides,
  };
}

async function seedKey(
  id: string,
  namespace: string,
  status: "active" | "revoked" = "active",
  role: "agent" | "auditor" = "agent",
  connectorId = "postgres-primary",
): Promise<void> {
  await db.query(
    `INSERT INTO api_keys
       (id, key_hash, namespace, actor, role, status, created_at, last_used)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
    [id, `hash-${id}`, namespace, `agent:${id}`, role, status, "2026-07-11T00:00:00.000Z"],
  );
  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at)
     VALUES ($1, $2, 'postgres', '{}', $3)
     ON CONFLICT (id) DO NOTHING`,
    [connectorId, namespace, "2026-07-11T00:00:00.000Z"],
  );
}

beforeEach(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
});

afterEach(async () => {
  await db.close();
});

describe("AgentConnectionGrantStore", () => {
  it("persists a valid immutable grant across store instances and exact key lookup", async () => {
    await seedKey("key-1", "acme/eng");
    const created = await new AgentConnectionGrantStore(db).create(grant(), admin("acme"));

    expect(created).toEqual(grant());
    await expect(new AgentConnectionGrantStore(db).getForKey("grant-1", "key-1"))
      .resolves.toEqual(grant());
    await expect(new AgentConnectionGrantStore(db).getForKey("grant-1", "key-other"))
      .resolves.toBeNull();
  });

  it("loads pre-M8A rows with the conservative oversight default", async () => {
    await seedKey("key-1", "acme/eng");
    await db.query(
      `INSERT INTO agent_connection_grants
         (id, key_id, namespace, connector_id, allowed_operations,
          allowed_source_refs, allowed_fields, allowed_purposes,
          max_sensitivity, max_rows, max_bytes, policy_version, status,
          expires_at, created_at, revoked_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb,
               $9, $10, $11, $12, 'active', $13, $14, NULL)`,
      [
        "legacy-grant",
        "key-1",
        "acme/eng",
        "postgres-primary",
        JSON.stringify(["source-read"]),
        JSON.stringify(["customers"]),
        JSON.stringify({ customers: ["id"] }),
        JSON.stringify(["support"]),
        "internal",
        10,
        4_096,
        1,
        FUTURE,
        "2026-07-11T00:00:00.000Z",
      ],
    );

    await expect(new AgentConnectionGrantStore(db).getForKey("legacy-grant", "key-1"))
      .resolves.toMatchObject({ oversight: OVERSIGHT });
  });

  it("fails closed when the badge, grant, or expiry is inactive", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    await store.revoke("grant-1", admin("acme"));
    await store.create(grant({ id: "expired", policyVersion: 2, expiresAt: "2020-01-01T00:00:00.000Z" }), admin("acme"));
    await store.revoke("expired", admin("acme"));
    await store.create(grant({ id: "revoked", policyVersion: 3 }), admin("acme"));
    expect(await store.revoke("revoked", admin("acme"))).toBe(true);

    await expect(store.getForKey("expired", "key-1")).resolves.toBeNull();
    await expect(store.getForKey("revoked", "key-1")).resolves.toBeNull();

    await db.query("UPDATE api_keys SET status = 'revoked' WHERE id = $1", ["key-1"]);
    await expect(store.getForKey("grant-1", "key-1")).resolves.toBeNull();
  });

  it("lists only the exact administrative subtree and escapes LIKE wildcards", async () => {
    for (const [keyId, namespace, connectorId] of [
      ["key-literal", "acme/eng_svc", "source-literal"],
      ["key-child", "acme/eng_svc/team", "source-child"],
      ["key-sibling", "acme/engXsvc", "source-sibling"],
    ] as const) {
      await seedKey(keyId, namespace, "active", "agent", connectorId);
    }
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant({ id: "literal", keyId: "key-literal", namespace: "acme/eng_svc", connectorId: "source-literal" }), admin("acme"));
    await store.create(grant({ id: "child", keyId: "key-child", namespace: "acme/eng_svc/team", connectorId: "source-child" }), admin("acme"));
    await store.create(grant({ id: "sibling", keyId: "key-sibling", namespace: "acme/engXsvc", connectorId: "source-sibling" }), admin("acme"));

    const visible = await store.listSubtree(admin("acme/eng_svc"));
    expect(visible.map((item) => item.id)).toEqual(["literal", "child"]);
    expect(visible.some((item) => item.id === "sibling")).toBe(false);
  });

  it("allows auditors to inspect grant history without granting mutation authority", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));

    await expect(store.listSubtree({ namespace: "acme", role: "auditor" }))
      .resolves.toEqual([grant()]);
  });

  it("enforces subtree scope on creation and revocation", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);

    await expect(store.create(grant(), admin("acme/sales"))).rejects.toThrow(/scope/i);
    await store.create(grant(), admin("acme"));
    await expect(store.revoke("grant-1", admin("acme/sales"))).resolves.toBe(false);
    await expect(store.revoke("grant-1", admin("acme"))).resolves.toBe(true);
  });

  it("rejects namespace/key binding mismatches and never creates revoked snapshots", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);

    await expect(store.create(grant({ namespace: "acme/sales" }), admin("acme")))
      .rejects.toThrow(/badge|namespace|binding/i);
    await expect(store.create(grant({ status: "revoked" }), admin("acme")))
      .rejects.toThrow(/active/i);
    const count = await db.query("SELECT COUNT(*) AS n FROM agent_connection_grants");
    expect(Number(count.rows[0]?.n)).toBe(0);
  });

  it("revocation changes only lifecycle state and exposes no general update method", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    const before = await db.query(
      `SELECT key_id, namespace, connector_id, allowed_operations, allowed_source_refs,
              allowed_fields, allowed_purposes, max_sensitivity, max_rows, max_bytes,
              policy_version, expires_at, oversight
         FROM agent_connection_grants WHERE id = $1`,
      ["grant-1"],
    );

    expect(await store.revoke("grant-1", admin("acme"))).toBe(true);
    expect(await store.revoke("grant-1", admin("acme"))).toBe(false);
    const after = await db.query(
      `SELECT key_id, namespace, connector_id, allowed_operations, allowed_source_refs,
              allowed_fields, allowed_purposes, max_sensitivity, max_rows, max_bytes,
              policy_version, expires_at, oversight
         FROM agent_connection_grants WHERE id = $1`,
      ["grant-1"],
    );
    expect(after.rows[0]).toEqual(before.rows[0]);
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(store));
    expect(methods).not.toContain("update");
    expect(methods).not.toContain("delete");
  });

  it("fails closed when durable JSON contains an invalid authority value", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    await db.query(
      "UPDATE agent_connection_grants SET allowed_operations = $1::jsonb WHERE id = $2",
      [JSON.stringify(["drop-tables"]), "grant-1"],
    );

    await expect(store.getForKey("grant-1", "key-1")).rejects.toThrow(/invalid.*grant/i);
    await expect(store.listSubtree(admin("acme"))).rejects.toThrow(/invalid.*grant/i);
  });

  it("denies global scope to a root admin but permits the root owner", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await expect(store.create(grant(), admin("", "admin"))).rejects.toThrow(/root owner|global/i);
    await expect(store.create(grant(), admin("", "owner"))).resolves.toEqual(grant());
  });

  it("requires an agent badge and a connector owned by the same namespace", async () => {
    await seedKey("auditor-1", "acme/eng", "active", "auditor");
    const store = new AgentConnectionGrantStore(db);
    await expect(store.create(grant({ keyId: "auditor-1" }), admin("acme")))
      .rejects.toThrow(/badge|binding/i);

    await seedKey("key-other", "acme/sales");
    await expect(store.create(grant({ connectorId: "unknown-source" }), admin("acme")))
      .rejects.toThrow(/connector|binding/i);
  });

  it("allows only one active policy version per badge and connector", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    await expect(store.create(grant({ id: "grant-2", policyVersion: 2 }), admin("acme")))
      .rejects.toThrow();
    expect(await store.revoke("grant-1", admin("acme"))).toBe(true);
    await expect(store.create(grant({ id: "grant-2", policyVersion: 2 }), admin("acme")))
      .resolves.toMatchObject({ id: "grant-2", policyVersion: 2 });
  });

  it("fails closed if a badge namespace changes after grant creation", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    await db.query("UPDATE api_keys SET namespace = 'acme/sales' WHERE id = 'key-1'");
    await expect(store.getForKey("grant-1", "key-1")).resolves.toBeNull();
  });

  it("returns only content-free historical metadata for revoked grants", async () => {
    await seedKey("key-1", "acme/eng");
    const store = new AgentConnectionGrantStore(db);
    await store.create(grant(), admin("acme"));
    await store.revoke("grant-1", admin("acme"));

    await expect(store.getForKey("grant-1", "key-1")).resolves.toBeNull();
    const historical = await store.getHistoricalMetadataForKey("grant-1", "key-1");
    expect(historical).toEqual({
      id: "grant-1",
      keyId: "key-1",
      namespace: "acme/eng",
      connectorId: "postgres-primary",
      policyVersion: 1,
      status: "revoked",
      expiresAt: FUTURE,
      oversight: OVERSIGHT,
    });
    expect(Object.keys(historical ?? {})).not.toContain("allowedFields");
    expect(Object.keys(historical ?? {})).not.toContain("allowedPurposes");
  });
});
