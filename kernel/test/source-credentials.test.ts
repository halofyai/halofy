import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

const kernels: Kernel[] = [];
afterEach(async () => {
  await Promise.all(kernels.splice(0).map((kernel) => kernel.close()));
});

describe("platform source credential vault", () => {
  it("encrypts reusable provider credentials and never returns their values", async () => {
    const kernel = await Kernel.boot({
      sourceConfigKek: randomBytes(32).toString("base64"),
    });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    await seedActiveSourceTeam(kernel, "acme/source-tests");
    const tenantKey = await kernel.auth.issueKey("acme/source-tests", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");

    const secret = "woocommerce_secret_never_returned";
    await expect(kernel.createSourceCredential({
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "Invalid",
      config: {
        consumerKey: "consumer-key",
        consumerSecret: secret,
        storeUrl: "https://store.example",
      },
    }, owner)).rejects.toThrow("source field 'storeUrl'");
    const created = await kernel.createSourceCredential({
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "Primary store",
      config: {
        consumerKey: "consumer-key",
        consumerSecret: secret,
      },
    }, owner);
    expect(created).toMatchObject({
      namespace: "acme/source-tests",
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "Primary store",
    });
    expect(JSON.stringify(created)).not.toContain(secret);

    const listed = await kernel.listSourceCredentials(owner);
    expect(listed).toEqual([created]);
    expect(JSON.stringify(listed)).not.toContain(secret);

    const raw = await kernel.db.query(`SELECT * FROM source_credentials WHERE id = $1`, [created.id]);
    expect(raw.rows[0].config_ciphertext).toEqual(expect.any(String));
    expect(JSON.stringify(raw.rows[0])).not.toContain(secret);

    const internal = await kernel.sourceCredentials.get(created.id);
    expect(internal?.config).toEqual({
      consumerKey: "consumer-key",
      consumerSecret: secret,
    });

    await expect(kernel.registerSource("woocommerce", {
      selectedDataPoints: ["products"],
      sourceAccessMode: "namespace-open",
    }, owner)).rejects.toThrow("credentialId");
    const source = await kernel.registerSource("woocommerce", {
      credentialId: created.id,
      storeUrl: "https://store.example",
      selectedDataPoints: ["products"],
      sourceAccessMode: "namespace-open",
    }, owner);
    await kernel.pauseSource(source.id, owner);
    expect(source.credentialId).toBe(created.id);
    expect(source.config).toEqual({});
    const internalSource = await kernel.sources.get(source.id);
    expect(internalSource?.config).toMatchObject({ storeUrl: "https://store.example" });
    expect(internalSource?.config).not.toHaveProperty("consumerSecret");
    const sourceRaw = await kernel.db.query(`SELECT credential_id, config FROM sources WHERE id = $1`, [source.id]);
    expect(sourceRaw.rows[0]).toMatchObject({ credential_id: created.id, config: {} });
    expect(JSON.stringify(sourceRaw.rows[0])).not.toContain(secret);
  }, 30_000);

  it("keeps credentials inside the caller namespace and enforces connection families", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    await seedActiveSourceTeam(kernel, "a/source-tests");
    await seedActiveSourceTeam(kernel, "b/source-tests");
    const aKey = await kernel.auth.issueKey("a/source-tests", "owner:a", "owner", root);
    const bKey = await kernel.auth.issueKey("b/source-tests", "owner:b", "owner", root);
    const a = await kernel.auth.resolve(aKey.plaintext);
    const b = await kernel.auth.resolve(bKey.plaintext);
    if (!a || !b) throw new Error("tenant identity failed");

    const credential = await kernel.createSourceCredential({
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "A store",
      config: {
        consumerKey: "a-consumer-key",
        consumerSecret: "a-secret",
      },
    }, a);
    expect(await kernel.listSourceCredentials(b)).toEqual([]);
    await expect(kernel.resolveSourceCredential(credential.id, "shopify", b))
      .rejects.toThrow(/credential/);
    await expect(kernel.resolveSourceCredential(credential.id, "shopify", a))
      .rejects.toThrow(/connection family/);

    const sharedCredential = await kernel.createSourceCredential({
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "A second store",
      config: {
        consumerKey: "second-consumer-key",
        consumerSecret: "second-secret",
      },
    }, a);
    await expect(kernel.resolveSourceCredential(sharedCredential.id, "woocommerce_catalogue", a))
      .resolves.toMatchObject({ connectionKey: "woocommerce" });
    const sharedSource = await kernel.registerSource("woocommerce_catalogue", {
      credentialId: sharedCredential.id,
      storeUrl: "https://store.example",
      selectedDataPoints: ["product_content"],
      sourceAccessMode: "namespace-open",
    }, a);
    expect((await kernel.sources.get(sharedSource.id))?.config).toMatchObject({
      storeUrl: "https://store.example",
    });
  }, 30_000);

  it("never returns decrypted legacy source config from lifecycle mutations", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    const tenantKey = await kernel.auth.issueKey("acme", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");
    const secretPath = "C:/private/customer-export";
    const source = await kernel.sources.register("acme", "filesystem", {
      path: secretPath,
      token: "legacy-token-must-not-leak",
    });

    const paused = await kernel.pauseSource(source.id, owner);
    const scheduled = await kernel.scheduleSource(source.id, null, owner);
    for (const result of [paused, scheduled]) {
      expect(result.config).toEqual({});
      expect(JSON.stringify(result)).not.toContain(secretPath);
      expect(JSON.stringify(result)).not.toContain("legacy-token-must-not-leak");
    }
  }, 30_000);

  it("deduplicates source creation retries without crossing connector kinds", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    await seedActiveSourceTeam(kernel, "idempotency/source-tests");
    const ownerKey = await kernel.auth.issueKey(
      "idempotency/source-tests",
      "owner:idempotency",
      "owner",
      root,
    );
    const owner = await kernel.auth.resolve(ownerKey.plaintext);
    if (!owner) throw new Error("team identity failed");
    const idempotencyKey = "01JNA6G0ATTEMPT00000000000";

    const first = await kernel.registerSource("filesystem", {
      path: "C:/safe/customer-export",
    }, owner, idempotencyKey);
    const retry = await kernel.registerSource("filesystem", {
      path: "C:/safe/customer-export",
    }, owner, idempotencyKey);

    expect(retry.id).toBe(first.id);
    expect(Number((await kernel.db.query(
      `SELECT count(*) AS n FROM sources WHERE namespace = $1 AND idempotency_key = $2`,
      [owner.namespace, idempotencyKey],
    )).rows[0].n)).toBe(1);
    await expect(kernel.registerSource("postgres", {}, owner, idempotencyKey))
      .rejects.toThrow("already bound to another connector");
  }, 30_000);
});
