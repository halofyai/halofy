import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { createHttpServer } from "../src/http/server.js";
import { EXTRACT_SYSTEM, RELATIONSHIP_MARKER, StubLlm } from "../src/llm/index.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let acmeOwner: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const resolved = await kernel.auth.resolve(issued.plaintext);
  if (!resolved) throw new Error(`identity resolution failed for ${actor}`);
  return resolved;
}

async function issueWithKey(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<{ identity: Identity; plaintext: string }> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const identity = await kernel.auth.resolve(issued.plaintext);
  if (!identity) throw new Error(`identity resolution failed for ${actor}`);
  return { identity, plaintext: issued.plaintext };
}

async function entityId(namespace: string, canonicalName: string): Promise<string> {
  const result = await kernel.db.query(
    `SELECT id FROM entity_registry WHERE namespace = $1 AND canonical_name = $2`,
    [namespace, canonicalName],
  );
  const id = result.rows[0]?.id;
  if (typeof id !== "string") throw new Error(`missing entity ${canonicalName}`);
  return id;
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-relationship-integration-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
  });
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root identity resolution failed");
  root = resolvedRoot;
  acmeOwner = await issue("acme", "owner:acme", "owner", root);
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\nverifierEnabled: false\n");
}, 120_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("StubLlm supported-document extraction", () => {
  it("does not treat an inline HTTPS scheme as a dialogue speaker delimiter", async () => {
    const input = "CatalogEntity lists SKU FILE-4 at https://files.example.com/items/4";
    const output = JSON.parse(await new StubLlm().complete(EXTRACT_SYSTEM, input)) as Array<{
      content: string;
      entities: string[];
    }>;
    expect(output).toEqual([expect.objectContaining({
      content: input,
      entities: expect.arrayContaining(["CatalogEntity"]),
    })]);
  });
});

describe("governed ingestion to L2 relationship continuity", () => {
  it("links cross-source entities through shared SKU and public HTTPS URL with governed evidence", async () => {
    const first = await kernel.importDump("mem0-import", JSON.stringify({
      results: [{
        id: "shopify-product-42",
        memory: "Shopify lists SKU HALO-42 at https://catalog.example.com/products/halo-42",
      }],
    }), acmeOwner);
    const second = await kernel.importDump("mem0-import", JSON.stringify({
      results: [{
        id: "woocommerce-product-42",
        memory: "WooCommerce lists SKU HALO-42 at https://catalog.example.com/products/halo-42",
      }],
    }), acmeOwner);
    expect(first.stored).toBeGreaterThan(0);
    expect(second.stored).toBeGreaterThan(0);

    const shopify = await entityId("acme", "Shopify");
    const wooCommerce = await entityId("acme", "WooCommerce");
    const listed = await kernel.listEntityRelationships({ entityId: shopify }, acmeOwner);
    const edge = listed.data.find((relationship) =>
      relationship.relationship === "same_as" &&
      relationship.objectEntityId === wooCommerce
    );

    expect(edge).toBeDefined();
    expect(edge?.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceId: first.sourceId, documentKey: "shopify-product-42" }),
      expect.objectContaining({ sourceId: second.sourceId, documentKey: "woocommerce-product-42" }),
    ]));
    const evidence = await kernel.db.query(
      `SELECT source_id, document_key, content_hash
         FROM entity_relationship_evidence
        WHERE relationship_id = $1
        ORDER BY source_id`,
      [edge?.id],
    );
    expect(evidence.rows).toHaveLength(2);
    expect(evidence.rows.every((row) =>
      typeof row.source_id === "string" &&
      typeof row.document_key === "string" &&
      /^[0-9a-f]{64}$/.test(String(row.content_hash))
    )).toBe(true);
  }, 60_000);

  it("creates an append-only correction and deduplicates an unchanged recomputation", async () => {
    const owner = await issue("acme/correction", "owner:correction", "owner", acmeOwner);
    await kernel.setPolicy(owner.namespace, "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "shopify-correction",
      memory: "Shopify publishes SKU CORR-7 at https://correction.example.com/items/7",
    }] }), owner);
    await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "woocommerce-correction",
      memory: "WooCommerce publishes SKU CORR-7 at https://correction.example.com/items/7",
    }] }), owner);
    const shopify = await entityId(owner.namespace, "Shopify");
    const wooCommerce = await entityId(owner.namespace, "WooCommerce");
    const first = (await kernel.listEntityRelationships({ entityId: shopify }, owner)).data.find(
      (edge) => edge.objectEntityId === wooCommerce && edge.relationship === "same_as",
    );
    expect(first).toBeDefined();

    const correction = await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "cross-platform-reconciliation",
      memory: "Shopify reconciliation and WooCommerce migration independently confirm warehouse SKU CORR-7 at https://correction.example.com/items/7",
    }] }), owner);
    expect(correction.stored).toBeGreaterThan(0);
    const history = (await kernel.listEntityRelationships({
      entityId: shopify,
      includeArchived: true,
    }, owner)).data.filter((edge) =>
      edge.objectEntityId === wooCommerce && edge.relationship === "same_as"
    );
    expect(history).toHaveLength(2);
    const active = history.find((edge) => edge.status === "active");
    const archived = history.find((edge) => edge.status === "archived");
    expect(active?.supersedes).toBe(archived?.id);
    expect(archived?.tValidTo).not.toBeNull();

    await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "unrelated-recompute",
      memory: "Unrelated telemetry confirms the Bluebird scheduler is online",
    }] }), owner);
    const unchanged = await kernel.db.query(
      `SELECT id FROM entity_relationships
        WHERE namespace = $1 AND subject_entity_id = $2
          AND relationship = 'same_as' AND object_entity_id = $3`,
      [owner.namespace, shopify, wooCommerce],
    );
    expect(unchanged.rows).toHaveLength(2);
    const dedupeAudit = await kernel.db.query(
      `SELECT detail FROM audit_log
        WHERE namespace = $1 AND purpose = 'relationship-enrichment'
          AND detail LIKE '%deduplicated=1%'`,
      [owner.namespace],
    );
    expect(dedupeAudit.rows.length).toBeGreaterThan(0);
  }, 60_000);

  it("keeps sibling edges isolated while allowing an auditor read through the HTTP GET route", async () => {
    const teamAOwner = await issue("acme/team-a", "owner:team-a", "owner", acmeOwner);
    const teamB = await issue("acme/team-b", "owner:team-b", "owner", acmeOwner);
    const auditor = await issueWithKey("acme/team-a", "auditor:team-a", "auditor", teamAOwner);
    const admin = await issueWithKey("acme/team-a", "admin:team-a", "admin", teamAOwner);
    const member = await issueWithKey("acme/team-a", "member:team-a", "member", teamAOwner);
    await kernel.setPolicy(teamAOwner.namespace, "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "team-a-one", memory: "TeamAlpha lists SKU ACL-9 at https://acl.example.com/9",
    }] }), teamAOwner);
    await kernel.importDump("mem0-import", JSON.stringify({ results: [{
      id: "team-a-two", memory: "TeamBeta lists SKU ACL-9 at https://acl.example.com/9",
    }] }), teamAOwner);
    const teamAlpha = await entityId(teamAOwner.namespace, "TeamAlpha");

    expect((await kernel.listEntityRelationships({ entityId: teamAlpha }, auditor.identity)).data.length)
      .toBeGreaterThan(0);
    expect((await kernel.listEntityRelationships({ entityId: teamAlpha }, teamB)).data).toEqual([]);
    await expect(kernel.listEntityRelationships({ entityId: teamAlpha }, member.identity))
      .rejects.toMatchObject({ name: "AuthzError" });

    const server = createHttpServer(buildHttpDeps(kernel));
    const base = `http://127.0.0.1:${await server.start(0)}`;
    try {
      const read = await fetch(`${base}/v1/admin/entity-relationships?entityId=${encodeURIComponent(teamAlpha)}&limit=10`, {
        headers: { authorization: `Bearer ${auditor.plaintext}` },
      });
      expect(read.status).toBe(200);
      expect((await read.json() as { data: unknown[] }).data.length).toBeGreaterThan(0);
      const noWrite = await fetch(`${base}/v1/admin/entity-relationships`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${admin.plaintext}`,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(noWrite.status).toBe(404);
    } finally {
      await server.stop();
    }
  }, 60_000);

  it("persists entity mentions only when evidence resolves a real company-file knowledge base", async () => {
    const owner = await issue("acme/file-mentions", "owner:file-mentions", "owner", acmeOwner);
    await kernel.setPolicy(owner.namespace, "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    const base = await kernel.createKnowledgeBase({
      name: "Catalog files",
      kind: "file",
      targetTeamId: null,
      primaryBusinessFunction: "Sales",
      description: "Catalog evidence",
      dataSensitive: false,
    }, owner);
    const file = await kernel.uploadCompanyFile({
      knowledgeBaseId: base.id,
      fileName: "catalog.txt",
      content: "CatalogEntity lists SKU FILE-4 at https://files.example.com/items/4",
      description: "Catalog",
      purpose: "Sales lookup",
    }, owner);
    expect(file.status).toBe("ready");
    const mentions = await kernel.db.query(
      `SELECT knowledge_base_id, company_file_id, memory_id
         FROM entity_mentions
        WHERE namespace = $1 AND knowledge_base_id = $2`,
      [owner.namespace, base.id],
    );
    expect(mentions.rows.length).toBeGreaterThan(0);
    expect(mentions.rows.every((row) => row.company_file_id === file.id && typeof row.memory_id === "string"))
      .toBe(true);
  }, 60_000);

  it("browns out hostile-model failure without losing governed facts", async () => {
    const owner = await issue("acme/brownout", "owner:brownout", "owner", acmeOwner);
    await kernel.setPolicy(owner.namespace, "rateLimitPerMin: 100000\nverifierEnabled: false\n");
    const llm = kernel.llm;
    const original = llm.complete.bind(llm);
    llm.complete = async (system, user) => {
      if (system.includes(RELATIONSHIP_MARKER)) throw new Error("model body must not escape");
      return original(system, user);
    };
    try {
      await kernel.importDump("mem0-import", JSON.stringify({ results: [{
        id: "brownout-one", memory: "BrownoutOne lists SKU FAIL-2 at https://brownout.example.com/2",
      }] }), owner);
      const second = await kernel.importDump("mem0-import", JSON.stringify({ results: [{
        id: "brownout-two", memory: "BrownoutTwo lists SKU FAIL-2 at https://brownout.example.com/2",
      }] }), owner);
      expect(second.stored).toBeGreaterThan(0);
    } finally {
      llm.complete = original;
    }
    const facts = await kernel.db.query(
      `SELECT id FROM memory_objects
        WHERE namespace = $1 AND type = 'fact' AND status = 'active' AND t_valid_to IS NULL`,
      [owner.namespace],
    );
    expect(facts.rows).toHaveLength(2);
    const edges = await kernel.db.query(
      `SELECT id FROM entity_relationships WHERE namespace = $1`,
      [owner.namespace],
    );
    expect(edges.rows).toHaveLength(0);
    const audit = await kernel.db.query(
      `SELECT detail FROM audit_log
        WHERE namespace = $1 AND purpose = 'relationship-enrichment' AND result = 'error'`,
      [owner.namespace],
    );
    expect(audit.rows.some((row) => String(row.detail).includes("llm_unavailable"))).toBe(true);
    expect(JSON.stringify(audit.rows)).not.toContain("model body must not escape");
  }, 60_000);
});
