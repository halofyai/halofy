import { createHash, createHmac, randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";

const kernels: Kernel[] = [];
const SOURCE_TEAM_ID = "team-obsidian-sources";
const SOURCE_TEAM_NAMESPACE = "acme/obsidian-sources";

afterEach(async () => {
  await Promise.all(kernels.splice(0).map((kernel) => kernel.close()));
});

function sign(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

async function seedSourceTeam(kernel: Kernel): Promise<void> {
  await kernel.db.query(
    `INSERT INTO org_teams
       (id, namespace, organization_namespace, name, description, created_by, created_at)
     VALUES ($1, $2, 'acme', 'Obsidian sources', '', 'owner:root', $3)`,
    [SOURCE_TEAM_ID, SOURCE_TEAM_NAMESPACE, new Date().toISOString()],
  );
}

describe("Obsidian local-vault backend", () => {
  it("pairs once, stores the secret encrypted, ingests ordered notes through D10, and reconciles deletion", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    const tenantKey = await kernel.auth.issueKey("acme", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");
    await kernel.setPolicy(
      "acme",
      "restrictedDestinations:\n  - llm-extraction\n  - embedding-provider\n",
    );
    await seedSourceTeam(kernel);

    const paired = await kernel.pairObsidianSource({
      vaultName: "Company vault",
      includedFolders: ["Handbook"],
      excludedFolders: ["Handbook/Private"],
      sourceAccessMode: "namespace-open",
      targetTeamId: SOURCE_TEAM_ID,
    }, owner);
    expect(paired.source).toMatchObject({
      kind: "obsidian_vault",
      namespace: SOURCE_TEAM_NAMESPACE,
      config: {},
      syncStatus: "never_synced",
    });
    expect(paired.pairing).toMatchObject({
      version: 1,
      sourceId: paired.source.id,
      path: `/v1/ingest/obsidian/${paired.source.id}`,
      includedFolders: ["Handbook"],
      excludedFolders: ["Handbook/Private"],
    });
    expect(paired.pairing.secret).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const rawSource = (await kernel.db.query(
      `SELECT config, config_ciphertext, config_state FROM sources WHERE id = $1`,
      [paired.source.id],
    )).rows[0];
    expect(rawSource.config).toEqual({});
    expect(rawSource.config_state).toBe("encrypted");
    expect(rawSource.config_ciphertext).toEqual(expect.any(String));
    expect(JSON.stringify(rawSource)).not.toContain(paired.pairing.secret);
    expect((await kernel.sources.get(paired.source.id))?.config).toMatchObject({
      signingSecret: paired.pairing.secret,
      sourceAccessMode: "namespace-open",
    });
    expect((await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM durable_jobs
        WHERE kind = 'source-sync' AND payload->>'sourceId' = $1`,
      [paired.source.id],
    )).rows[0].count).toBe(0);

    const timestamp = String(Date.now());
    const firstBody = JSON.stringify({
      version: 1,
      sequence: 1,
      kind: "changes",
      records: [{
        path: "Handbook/Support.md",
        content: "Escalations go to the support lead.",
        modifiedAt: "2026-08-13T08:00:00.000Z",
        properties: { owner: "Support", approved: true },
        links: ["Handbook/On-call"],
      }, {
        path: "Handbook/Private/Compensation.md",
        content: "Excluded by the server-owned folder configuration.",
      }],
      deleted: [],
    });
    const first = await kernel.ingestObsidianVault(
      paired.source.id,
      firstBody,
      timestamp,
      sign(paired.pairing.secret, timestamp, firstBody),
    );
    expect(first).toMatchObject({ records: 1, scanned: 1, changed: 1, errors: [] });
    expect((await kernel.db.query(
      `SELECT document_key, landing_namespace FROM source_documents WHERE source_id = $1`,
      [paired.source.id],
    )).rows).toEqual([{
      document_key: "Handbook/Support.md",
      landing_namespace: SOURCE_TEAM_NAMESPACE,
    }]);

    const retryTimestamp = String(Number(timestamp) + 1);
    const replay = await kernel.ingestObsidianVault(
      paired.source.id,
      firstBody,
      retryTimestamp,
      sign(paired.pairing.secret, retryTimestamp, firstBody),
    );
    expect(replay).toMatchObject({ idempotent: true, records: 0, errors: [] });
    expect((await kernel.db.query(
      `SELECT body_digest, committed_at FROM obsidian_ingress_receipts
        WHERE source_id = $1 AND sequence = 1`,
      [paired.source.id],
    )).rows).toEqual([{
      body_digest: createHash("sha256").update(firstBody).digest("hex"),
      committed_at: expect.anything(),
    }]);

    const reboundBody = JSON.stringify({
      version: 1,
      sequence: 1,
      kind: "changes",
      records: [{ path: "Handbook/Rebound.md", content: "must not be accepted" }],
      deleted: [],
    });
    const reboundTimestamp = String(Number(timestamp) + 2);
    await expect(kernel.ingestObsidianVault(
      paired.source.id,
      reboundBody,
      reboundTimestamp,
      sign(paired.pairing.secret, reboundTimestamp, reboundBody),
    )).rejects.toMatchObject({ name: "ObsidianValidationError" });

    const manifestTimestamp = String(Date.now());
    const manifestBody = JSON.stringify({
      version: 1,
      sequence: 2,
      kind: "manifest",
      paths: [],
    });
    const reconciled = await kernel.ingestObsidianVault(
      paired.source.id,
      manifestBody,
      manifestTimestamp,
      sign(paired.pairing.secret, manifestTimestamp, manifestBody),
    );
    expect(reconciled.removed).toEqual(["Handbook/Support.md"]);
    expect((await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM source_documents WHERE source_id = $1`,
      [paired.source.id],
    )).rows[0].count).toBe(0);
  }, 60_000);

  it("rejects invalid signatures, authority fields, hidden paths, and sequence gaps", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const key = await kernel.auth.issueKey("", "owner:root", "owner");
    const owner = await kernel.auth.resolve(key.plaintext);
    if (!owner) throw new Error("owner resolution failed");
    await seedSourceTeam(kernel);
    const paired = await kernel.pairObsidianSource({
      vaultName: "Security vault",
      includedFolders: [],
      excludedFolders: [],
      sourceAccessMode: "namespace-open",
      targetTeamId: SOURCE_TEAM_ID,
    }, owner);
    const timestamp = String(Date.now());
    const safeBody = JSON.stringify({
      version: 1,
      sequence: 1,
      kind: "changes",
      records: [],
      deleted: [],
    });
    await expect(kernel.ingestObsidianVault(
      paired.source.id,
      safeBody,
      timestamp,
      "sha256=" + "0".repeat(64),
    )).rejects.toMatchObject({ name: "ObsidianAuthorizationError" });

    for (const body of [
      JSON.stringify({
        version: 1,
        sequence: 1,
        kind: "changes",
        namespace: "victim",
        records: [],
        deleted: [],
      }),
      JSON.stringify({
        version: 1,
        sequence: 1,
        kind: "changes",
        records: [{ path: ".obsidian/plugins.md", content: "blocked" }],
        deleted: [],
      }),
    ]) {
      await expect(kernel.ingestObsidianVault(
        paired.source.id,
        body,
        timestamp,
        sign(paired.pairing.secret, timestamp, body),
      )).rejects.toMatchObject({ name: "ObsidianValidationError" });
    }

    const gapBody = JSON.stringify({
      version: 1,
      sequence: 2,
      kind: "changes",
      records: [],
      deleted: [],
    });
    await expect(kernel.ingestObsidianVault(
      paired.source.id,
      gapBody,
      timestamp,
      sign(paired.pairing.secret, timestamp, gapBody),
    )).rejects.toMatchObject({ name: "ObsidianDeliveryError" });
    expect((await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM source_documents WHERE source_id = $1`,
      [paired.source.id],
    )).rows[0].count).toBe(0);

    const now = new Date();
    await kernel.db.query(
      `INSERT INTO durable_rate_limits
         (bucket_key, window_started_at, window_ends_at, request_count, updated_at)
       VALUES ($1, $2, $3, 120, $2)
       ON CONFLICT (bucket_key) DO UPDATE SET
         window_started_at = EXCLUDED.window_started_at,
         window_ends_at = EXCLUDED.window_ends_at,
         request_count = EXCLUDED.request_count,
         updated_at = EXCLUDED.updated_at`,
      [
        `obsidian:source:${paired.source.id}`,
        now.toISOString(),
        new Date(now.getTime() + 60_000).toISOString(),
      ],
    );
    await expect(kernel.ingestObsidianVault(
      paired.source.id,
      safeBody,
      timestamp,
      sign(paired.pairing.secret, timestamp, safeBody),
    )).rejects.toMatchObject({ name: "RateLimitError" });
  }, 60_000);

  it("requires namespace-open acknowledgement and audits pairing outcomes without the secret", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const owner = await kernel.auth.resolve(rootKey.plaintext);
    if (!owner) throw new Error("owner resolution failed");
    const memberKey = await kernel.auth.issueKey("", "member:root", "member", owner);
    const member = await kernel.auth.resolve(memberKey.plaintext);
    if (!member) throw new Error("member resolution failed");
    await seedSourceTeam(kernel);

    await expect(buildHttpDeps(kernel).admin.pairObsidian?.({
      vaultName: "API-unapproved vault",
      includedFolders: [],
      excludedFolders: [],
    }, owner)).rejects.toMatchObject({ name: "BadRequestError" });
    await expect(kernel.pairObsidianSource({
      vaultName: "Unapproved vault",
      includedFolders: [],
      excludedFolders: [],
    } as never, owner)).rejects.toThrow(/namespace-open/);
    await expect(kernel.pairObsidianSource({
      vaultName: "Denied vault",
      includedFolders: [],
      excludedFolders: [],
      sourceAccessMode: "namespace-open",
    }, member)).rejects.toMatchObject({ name: "AuthzError" });

    const paired = await kernel.pairObsidianSource({
      vaultName: "Audited vault",
      includedFolders: [],
      excludedFolders: [],
      sourceAccessMode: "namespace-open",
      targetTeamId: SOURCE_TEAM_ID,
    }, owner);
    const audit = (await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE purpose = 'obsidian-pairing' ORDER BY seq`,
    )).rows;
    expect(audit.map((row) => row.result)).toEqual(["error", "denied", "ok"]);
    expect(JSON.stringify(audit)).not.toContain(paired.pairing.secret);
  }, 60_000);
});
