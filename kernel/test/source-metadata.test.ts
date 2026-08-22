import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  SourceRegistry,
  type SourceMetadataUpdate,
} from "../src/ingest/kernel-store.js";
import { SourceConfigCipher } from "../src/ingest/source-config.js";

describe("SourceRegistry source metadata", () => {
  let db: Db;
  let registry: SourceRegistry;

  beforeEach(async () => {
    db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 8 }));
    await migrate(db, 8);
    registry = new SourceRegistry(
      db,
      new SourceConfigCipher(randomBytes(32).toString("base64")),
    );
  });

  afterEach(async () => {
    await db.close();
  });

  it("round-trips trimmed metadata and includes conservative defaults in source rows", async () => {
    const source = await registry.register("acme/support", "notion", { token: "secret" });
    expect(source).toMatchObject({
      primaryBusinessFunction: "General",
      description: "",
      dataSensitive: false,
    });

    const updated = await registry.updateMetadata(source.id, "acme/support", {
      primaryBusinessFunction: "  Customer support  ",
      description: "  Escalation handbook  ",
      dataSensitive: true,
    });

    expect(updated).toEqual({
      id: source.id,
      namespace: "acme/support",
      primaryBusinessFunction: "Customer support",
      description: "Escalation handbook",
      dataSensitive: true,
    });
    await expect(registry.getMetadata(source.id, "acme/support")).resolves.toEqual(updated);
    await expect(registry.getRedacted(source.id)).resolves.toMatchObject({
      primaryBusinessFunction: "Customer support",
      description: "Escalation handbook",
      dataSensitive: true,
    });
    await expect(registry.list("acme/support")).resolves.toEqual([
      expect.objectContaining({
        primaryBusinessFunction: "Customer support",
        description: "Escalation handbook",
        dataSensitive: true,
      }),
    ]);
  });

  it("denies a sibling namespace at the store seam without mutating metadata", async () => {
    const source = await registry.register("acme/team-a", "notion", {});

    await expect(registry.updateMetadata(source.id, "acme/team-b", {
      primaryBusinessFunction: "Finance",
      description: "Should not land",
      dataSensitive: true,
    })).resolves.toBeNull();
    await expect(registry.getMetadata(source.id, "acme/team-b")).resolves.toBeNull();
    await expect(registry.getMetadata(source.id, "acme/team-a")).resolves.toMatchObject({
      primaryBusinessFunction: "General",
      description: "",
      dataSensitive: false,
    });
  });

  it("returns a metadata-only projection without connector config, credentials, or bodies", async () => {
    const source = await registry.register("acme", "notion", {
      token: "connector-secret-sentinel",
      body: "raw-body-sentinel",
    });

    const projection = await registry.updateMetadata(source.id, "acme", {
      primaryBusinessFunction: "Sales",
      description: "Pipeline data",
      dataSensitive: false,
    });
    const serialized = JSON.stringify(projection);

    expect(serialized).not.toContain("connector-secret-sentinel");
    expect(serialized).not.toContain("raw-body-sentinel");
    expect(projection).not.toHaveProperty("config");
    expect(projection).not.toHaveProperty("credentialId");
  });

  it("rejects unknown fields, invalid bounds, and control characters", async () => {
    const source = await registry.register("acme", "notion", {});
    const valid: SourceMetadataUpdate = {
      primaryBusinessFunction: "Operations",
      description: "Runbooks",
      dataSensitive: false,
    };

    await expect(registry.updateMetadata(source.id, "acme", {
      ...valid,
      extra: "not allowed",
    } as SourceMetadataUpdate)).rejects.toThrow(/exactly/i);
    await expect(registry.updateMetadata(source.id, "acme", {
      ...valid,
      primaryBusinessFunction: " ",
    })).rejects.toThrow(/business function/i);
    await expect(registry.updateMetadata(source.id, "acme", {
      ...valid,
      description: "unsafe\u0000text",
    })).rejects.toThrow(/control/i);
    await expect(registry.updateMetadata(source.id, "acme", {
      ...valid,
      dataSensitive: "false",
    } as unknown as SourceMetadataUpdate)).rejects.toThrow(/true or false/i);
  });

  it("does not let false lower a sensitivity flag once raised", async () => {
    const source = await registry.register("acme", "notion", {});
    await registry.updateMetadata(source.id, "acme", {
      primaryBusinessFunction: "Legal",
      description: "Contracts",
      dataSensitive: true,
    });

    const updated = await registry.updateMetadata(source.id, "acme", {
      primaryBusinessFunction: "Legal",
      description: "Public contract summaries",
      dataSensitive: false,
    });

    expect(updated?.dataSensitive).toBe(true);
  });
});
