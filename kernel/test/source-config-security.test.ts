import { randomBytes } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { SourceRegistry } from "../src/ingest/kernel-store.js";
import { SourceConfigCipher } from "../src/ingest/source-config.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

const cleanups: string[] = [];

async function temp(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  cleanups.push(path);
  return path;
}

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function boot(): Promise<{ kernel: Kernel; owner: Identity }> {
  const knowledgeDir = await temp("halomem-source-security-knowledge-");
  const kernel = await Kernel.boot({
    knowledgeDir,
    sourceConfigKek: randomBytes(32).toString("base64"),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root identity failed");
  await seedActiveSourceTeam(kernel, "secure/source-tests");
  const ownerKey = await kernel.auth.issueKey("secure/source-tests", "owner:secure", "owner", root);
  const owner = await kernel.auth.resolve(ownerKey.plaintext);
  if (!owner) throw new Error("tenant identity failed");
  return { kernel, owner };
}

describe("R4 source configuration protection", () => {
  it("encrypts config before insert, redacts public rows, and decrypts only for sync", async () => {
    const { kernel, owner } = await boot();
    const corpus = join(await temp("halomem-source-secret-parent-"), "sentinel-source-path-77");
    await mkdir(corpus);
    await writeFile(join(corpus, "handbook.txt"), "Escalations go to the support lead.");
    try {
      const registered = await kernel.registerSource("filesystem", { path: corpus }, owner);
      expect(registered.config).toEqual({});
      expect(registered.configState).toBe("encrypted");

      const raw = await kernel.db.query(`SELECT * FROM sources WHERE id = $1`, [registered.id]);
      expect(raw.rows[0].config).toEqual({});
      expect(raw.rows[0].config_state).toBe("encrypted");
      expect(raw.rows[0].config_ciphertext).toEqual(expect.any(String));
      expect(JSON.stringify(raw.rows[0])).not.toContain(corpus);

      const listed = await kernel.sources.list("secure/source-tests");
      expect(listed[0]?.config).toEqual({});
      const internal = await kernel.sources.get(registered.id);
      expect(internal?.config).toEqual({ path: corpus });

      const result = await kernel.syncSource(registered.id, owner);
      expect(result.scanned).toBe(1);
      const audit = await kernel.db.query(`SELECT * FROM audit_log`);
      expect(JSON.stringify(audit.rows)).not.toContain(corpus);
    } finally {
      await kernel.close();
    }
  }, 60_000);

  it("redacts connector values from thrown and persisted sync errors", async () => {
    const { kernel, owner } = await boot();
    const missing = join(await temp("halomem-source-error-parent-"), "missing-secret-path-99");
    try {
      const source = await kernel.registerSource("filesystem", { path: missing }, owner);
      await expect(kernel.syncSource(source.id, owner)).rejects.not.toThrow(missing);
      const row = await kernel.db.query(
        `SELECT last_sync_error FROM sources WHERE id = $1`,
        [source.id],
      );
      expect(String(row.rows[0].last_sync_error)).not.toContain(missing);
      expect(String(row.rows[0].last_sync_error)).toContain("[redacted]");
      const listed = await kernel.sources.list("secure/source-tests");
      expect(JSON.stringify(listed)).not.toContain(missing);
    } finally {
      await kernel.close();
    }
  }, 60_000);

  it("seals legacy plaintext with a key and removes the JSONB copy", async () => {
    const { kernel } = await boot();
    const legacySecret = "legacy-token-never-public";
    try {
      await kernel.db.query(
        `INSERT INTO sources
           (id, namespace, kind, config, created_at, config_state, last_sync_error)
         VALUES ('legacy-source', 'secure', 'notion', $1, $2, 'legacy_plaintext', $3)`,
        [JSON.stringify({ token: legacySecret }), new Date().toISOString(), `token=${legacySecret}`],
      );
      await kernel.sources.protectLegacyConfigs();
      const raw = await kernel.db.query(`SELECT * FROM sources WHERE id = 'legacy-source'`);
      expect(raw.rows[0].config).toEqual({});
      expect(raw.rows[0].config_state).toBe("encrypted");
      expect(JSON.stringify(raw.rows[0])).not.toContain(legacySecret);
      expect((await kernel.sources.get("legacy-source"))?.config).toEqual({ token: legacySecret });
      expect((await kernel.sources.list("secure")).find((row) => row.id === "legacy-source")?.config)
        .toEqual({});
    } finally {
      await kernel.close();
    }
  }, 60_000);

  it("quarantines legacy plaintext on a durable install without a usable KEK", async () => {
    const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 8 }));
    const legacySecret = "legacy-dsn-must-be-destroyed";
    try {
      await migrate(db, 8);
      await db.query(
        `INSERT INTO sources (id, namespace, kind, config, created_at, config_state)
         VALUES ('legacy-quarantine', 'secure', 'postgres', $1, $2, 'legacy_plaintext')`,
        [JSON.stringify({ dsn: legacySecret }), new Date().toISOString()],
      );
      const registry = new SourceRegistry(db, new SourceConfigCipher("", false));
      await registry.protectLegacyConfigs();
      const raw = await db.query(`SELECT * FROM sources WHERE id = 'legacy-quarantine'`);
      expect(raw.rows[0].config).toEqual({});
      expect(raw.rows[0].config_state).toBe("quarantined");
      expect(raw.rows[0].config_sha256).toEqual(expect.any(String));
      expect(JSON.stringify(raw.rows[0])).not.toContain(legacySecret);
      await expect(registry.get("legacy-quarantine")).resolves.toMatchObject({
        config: {},
        configState: "quarantined",
      });
    } finally {
      await db.close();
    }
  }, 60_000);
});
