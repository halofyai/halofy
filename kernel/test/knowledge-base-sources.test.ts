import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  KnowledgeBaseSourceConflictError,
  KnowledgeBaseSourceStore,
  KnowledgeBaseSourceValidationError,
} from "../src/knowledge-bases/sources.js";
import { KnowledgeBaseStore } from "../src/knowledge-bases/index.js";

const DIM = 8;
let db: Db;
let bases: KnowledgeBaseStore;
let sources: KnowledgeBaseSourceStore;

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  bases = new KnowledgeBaseStore(db, () => new Date("2026-07-21T10:00:00.000Z"));
  sources = new KnowledgeBaseSourceStore(db, () => new Date("2026-07-21T10:05:00.000Z"));
});

beforeEach(async () => {
  await db.query("DELETE FROM company_files");
  await db.query("DELETE FROM knowledge_sources");
  await db.query("DELETE FROM knowledge_bases");
  await db.query("DELETE FROM org_teams");
  await db.query("DELETE FROM sources");
});

afterAll(async () => db.close());

async function createBase() {
  return bases.create({
    name: "Operations",
    kind: "file",
    primaryBusinessFunction: "Operations",
    description: "Company operations knowledge",
    dataSensitive: false,
  }, { namespace: "acme", actor: "owner@acme.test", targetTeamId: null });
}

async function createSource(id: string, namespace: string, kind: "filesystem" | "doc_site", sync = "synced") {
  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at, lifecycle_state, sync_status)
     VALUES ($1, $2, $3, '{}', $4, 'active', $5)`,
    [id, namespace, kind, "2026-07-21T09:00:00.000Z", sync],
  );
}

describe("KnowledgeBaseSourceStore", () => {
  it("attaches folder and website sources as pieces inside one knowledge base", async () => {
    const base = await createBase();
    await createSource("folder-1", "acme", "filesystem");
    await createSource("site-1", "acme", "doc_site", "pending");

    const folder = await sources.create({
      knowledgeBaseId: base.id,
      kind: "folder",
      sourceId: "folder-1",
      name: "Shared operations",
      description: "Runbooks",
      purpose: "Operational reference",
    }, { namespace: "acme", actor: "owner@acme.test" });
    const website = await sources.create({
      knowledgeBaseId: base.id,
      kind: "website",
      sourceId: "site-1",
      name: "Public documentation",
      description: "Product docs",
      purpose: "Product reference",
    }, { namespace: "acme", actor: "owner@acme.test" });

    expect(folder).toEqual(expect.objectContaining({ knowledgeBaseId: base.id, kind: "folder", status: "ready" }));
    expect(website).toEqual(expect.objectContaining({ knowledgeBaseId: base.id, kind: "website", status: "processing" }));
    expect((await sources.list(base.id, { namespace: "acme" })).data.map((item) => item.name)).toEqual([
      "Public documentation",
      "Shared operations",
    ]);
  });

  it("rejects mismatched kinds, sibling sources, and duplicate active attachments", async () => {
    const base = await createBase();
    await createSource("folder-1", "acme", "filesystem");
    await createSource("site-1", "acme", "doc_site");
    await createSource("sibling", "other", "doc_site");

    const input = {
      knowledgeBaseId: base.id,
      kind: "folder" as const,
      sourceId: "folder-1",
      name: "Shared operations",
      description: "",
      purpose: "Reference",
    };
    await sources.create(input, { namespace: "acme", actor: "owner@acme.test" });
    await expect(sources.create(input, { namespace: "acme", actor: "owner@acme.test" }))
      .rejects.toThrow(KnowledgeBaseSourceConflictError);
    await expect(sources.create({ ...input, sourceId: "site-1" }, { namespace: "acme", actor: "owner@acme.test" }))
      .rejects.toThrow(KnowledgeBaseSourceValidationError);
    await expect(sources.create({ ...input, kind: "website", sourceId: "sibling" }, { namespace: "acme", actor: "owner@acme.test" }))
      .rejects.toThrow(KnowledgeBaseSourceValidationError);
  });

  it("keeps source ownership discoverable when collection archival is retried", async () => {
    const base = await createBase();
    await createSource("folder-1", "acme", "filesystem");
    await sources.create({
      knowledgeBaseId: base.id,
      kind: "folder",
      sourceId: "folder-1",
      name: "Shared operations",
      description: "",
      purpose: "Reference",
    }, { namespace: "acme", actor: "owner@acme.test" });

    const context = { namespace: "acme", actor: "owner@acme.test" };
    expect(await sources.archiveForKnowledgeBase(base.id, context)).toEqual(["folder-1"]);
    expect((await sources.list(base.id, context)).data).toEqual([]);
    expect(await sources.archiveForKnowledgeBase(base.id, context)).toEqual(["folder-1"]);
  });
});
