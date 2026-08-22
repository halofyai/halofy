import { createHmac, randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

const kernels: Kernel[] = [];

afterEach(async () => {
  await Promise.all(kernels.splice(0).map((kernel) => kernel.close()));
});

function signature(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

describe("authenticated webhook source ingestion", () => {
  it("verifies the source secret and lands a bounded server-owned envelope through D10", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    await seedActiveSourceTeam(kernel, "acme/webhooks");
    const tenantKey = await kernel.auth.issueKey("acme/webhooks", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");
    await kernel.setPolicy(
      "acme",
      "restrictedDestinations:\n  - llm-extraction\n  - embedding-provider\n",
    );

    const signingSecret = "whsec_" + "a".repeat(48);
    const credential = await kernel.createSourceCredential({
      connectorId: "webhook_source",
      connectionKey: "webhook_source",
      name: "Product events",
      config: { signingSecret },
    }, owner);
    const source = await kernel.registerSource("webhook_source", {
      credentialId: credential.id,
      selectedDataPoints: ["verified_events"],
      sourceAccessMode: "namespace-open",
    }, owner);

    const timestamp = String(Math.floor(Date.now() / 1_000));
    const rawBody = JSON.stringify({
      records: [{
        id: "evt_01",
        text: "Release window moved to Friday at 16:00 UTC.",
        eventTime: "2026-07-15T10:00:00.000Z",
        classification: "internal",
      }],
    });
    const result = await kernel.ingestWebhookSource(
      source.id,
      rawBody,
      timestamp,
      signature(signingSecret, timestamp, rawBody),
    );

    expect(result).toMatchObject({ records: 1, errors: [] });
    expect(result.stored + result.deduplicated + result.superseded).toBe(1);
    const documents = await kernel.db.query(
      `SELECT document_key, landing_namespace FROM source_documents WHERE source_id = $1`,
      [source.id],
    );
    expect(documents.rows).toEqual([{
      document_key: "webhook_source:verified_events:evt_01",
      landing_namespace: "acme/webhooks",
    }]);
    const landed = await kernel.db.query(
      `SELECT DISTINCT namespace FROM memory_objects
        WHERE provenance @> $1::jsonb`,
      [JSON.stringify([{ sourceId: source.id }])],
    );
    expect(landed.rows).toEqual([{ namespace: "acme/webhooks" }]);

    const secondBody = JSON.stringify({
      records: [{ id: "evt_02", text: "The migration completed successfully." }],
    });
    const second = await kernel.ingestWebhookSource(
      source.id,
      secondBody,
      timestamp,
      signature(signingSecret, timestamp, secondBody),
    );
    expect(second).toMatchObject({ records: 1, removed: [], errors: [] });
    expect((await kernel.db.query(
      `SELECT document_key FROM source_documents WHERE source_id = $1 ORDER BY document_key`,
      [source.id],
    )).rows).toEqual([
      { document_key: "webhook_source:verified_events:evt_01" },
      { document_key: "webhook_source:verified_events:evt_02" },
    ]);
    await expect(kernel.ingestWebhookSource(
      source.id,
      rawBody,
      timestamp,
      signature(signingSecret, timestamp, rawBody),
    )).rejects.toMatchObject({ name: "WebhookAuthorizationError" });
    await expect(kernel.syncSource(source.id, owner)).rejects.toThrow(/staged records are required/);
    expect((await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM source_documents WHERE source_id = $1`,
      [source.id],
    )).rows[0].count).toBe(2);
  }, 30_000);

  it("rejects bad signatures, stale timestamps, authority injection, and oversized batches", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    await seedActiveSourceTeam(kernel, "acme/webhooks");
    const tenantKey = await kernel.auth.issueKey("acme/webhooks", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");

    const signingSecret = "whsec_" + "b".repeat(48);
    const credential = await kernel.createSourceCredential({
      connectorId: "webhook_source",
      connectionKey: "webhook_source",
      name: "Security events",
      config: { signingSecret },
    }, owner);
    const source = await kernel.registerSource("webhook_source", {
      credentialId: credential.id,
      selectedDataPoints: ["verified_events"],
      sourceAccessMode: "namespace-open",
    }, owner);

    const timestamp = String(Math.floor(Date.now() / 1_000));
    const safeBody = JSON.stringify({ records: [{ id: "evt_safe", text: "safe" }] });
    await expect(kernel.ingestWebhookSource(
      source.id,
      safeBody,
      timestamp,
      "sha256=" + "0".repeat(64),
    )).rejects.toMatchObject({ name: "WebhookAuthorizationError" });
    await expect(kernel.ingestWebhookSource(
      source.id,
      safeBody,
      String(Number(timestamp) - 301),
      signature(signingSecret, String(Number(timestamp) - 301), safeBody),
    )).rejects.toMatchObject({ name: "WebhookAuthorizationError" });

    for (const body of [
      JSON.stringify({ namespace: "victim", records: [{ id: "evt_ns", text: "blocked" }] }),
      JSON.stringify({ records: [{ id: "evt_actor", text: "blocked", actor: "root" }] }),
      JSON.stringify({ records: Array.from({ length: 101 }, (_, i) => ({ id: `evt_${i}`, text: "x" })) }),
    ]) {
      await expect(kernel.ingestWebhookSource(
        source.id,
        body,
        timestamp,
        signature(signingSecret, timestamp, body),
      )).rejects.toMatchObject({ name: "WebhookValidationError" });
    }

    const rows = await kernel.db.query(`SELECT COUNT(*)::int AS count FROM source_documents WHERE source_id = $1`, [source.id]);
    expect(rows.rows[0].count).toBe(0);
  }, 30_000);
});
