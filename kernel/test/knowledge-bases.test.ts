import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  KnowledgeBaseConflictError,
  KnowledgeBaseNotFoundError,
  KnowledgeBaseStore,
  KnowledgeBaseValidationError,
} from "../src/knowledge-bases/index.js";
import { KnowledgeBaseSourceStore } from "../src/knowledge-bases/sources.js";

const DIM = 8;

let db: Db;
let store: KnowledgeBaseStore;
let sourceStore: KnowledgeBaseSourceStore;

beforeAll(async () => {
  db = await createDb(
    loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }),
  );
  await migrate(db, DIM);
  store = new KnowledgeBaseStore(db, () => new Date("2026-07-21T10:00:00.000Z"));
  sourceStore = new KnowledgeBaseSourceStore(db, () => new Date("2026-07-21T10:05:00.000Z"));
});

beforeEach(async () => {
  await db.query("DELETE FROM company_files");
  await db.query("DELETE FROM knowledge_sources");
  await db.query("DELETE FROM knowledge_bases");
  await db.query("DELETE FROM org_teams");
  await db.query("DELETE FROM sources");
});

afterAll(async () => {
  await db.close();
});

async function source(
  id: string,
  namespace: string,
  kind: "filesystem" | "doc_site",
  options: {
    lifecycle?: "active" | "paused" | "disabled";
    sync?: "never_synced" | "pending" | "synced" | "failed";
  } = {},
): Promise<void> {
  await db.query(
    `INSERT INTO sources
       (id, namespace, kind, config, created_at, lifecycle_state, sync_status)
     VALUES ($1, $2, $3, '{}', $4, $5, $6)`,
    [
      id,
      namespace,
      kind,
      "2026-07-20T00:00:00.000Z",
      options.lifecycle ?? "active",
      options.sync ?? "never_synced",
    ],
  );
}

function metadata(
  overrides: Partial<{
    name: string;
    kind: "file" | "folder" | "url";
    sourceId: string;
    primaryBusinessFunction: string;
    description: string;
    dataSensitive: boolean;
  }> = {},
) {
  return {
    name: "Support library",
    kind: "file" as const,
    primaryBusinessFunction: "Customer support",
    description: "Escalation and product knowledge",
    dataSensitive: true,
    ...overrides,
  };
}

function resolved(
  overrides: Partial<{
    namespace: string;
    actor: string;
    targetTeamId: string | null;
  }> = {},
) {
  return {
    namespace: "acme/support",
    actor: "user:owner",
    targetTeamId: null,
    ...overrides,
  };
}

async function companyFile(
  knowledgeBaseId: string,
  id: string,
  status: "processing" | "ready" | "needs_review" | "failed",
  factCount: number,
): Promise<void> {
  const sourceId = `upload-source-${id}`;
  await source(sourceId, "acme/support", "filesystem");
  const hash = createHash("sha256").update(id).digest("hex");
  await db.query(
    `INSERT INTO company_files
       (id, knowledge_base_id, source_id, namespace, title, description,
        purpose, status, lifecycle_state, file_name, media_type, byte_size,
        content_sha256, attempt_token, lease_expires_at, fact_count,
        t_valid_from, created_by, uploaded_by, created_at)
     VALUES
       ($1, $2, $3, 'acme/support', $1, '', 'Support operations', $4,
        'active', $5, 'text/plain', 10, $6, $7, $8, $9, $10, 'user:owner',
        'user:owner', $10)`,
    [
      id,
      knowledgeBaseId,
      sourceId,
      status,
      `${id}.txt`,
      hash,
      `attempt-${id}`,
      "2026-07-22T00:00:00.000Z",
      factCount,
      "2026-07-21T09:00:00.000Z",
    ],
  );
}

describe("KnowledgeBaseStore.create", () => {
  it("creates a metadata-only file library in server-resolved scope", async () => {
    const created = await store.create(
      metadata({
        name: "  Support library  ",
        primaryBusinessFunction: "  Customer support  ",
        description: "  Escalation knowledge  ",
      }),
      resolved(),
    );

    expect(created).toEqual(
      expect.objectContaining({
        namespace: "acme/support",
        targetTeamId: null,
        name: "Support library",
        kind: "file",
        status: "empty",
        lifecycleState: "active",
        sourceId: null,
        primaryBusinessFunction: "Customer support",
        description: "Escalation knowledge",
        dataSensitive: true,
        createdBy: "user:owner",
        fileCount: 0,
        factCount: 0,
      }),
    );
  });

  it("requires folder and URL cartridges with exact kind, namespace, and active lifecycle", async () => {
    await source("folder-ok", "acme/support", "filesystem");
    await source("url-ok", "acme/support", "doc_site");
    await source("wrong-kind", "acme/support", "filesystem");
    await source("sibling", "acme/sales", "doc_site");
    await source("paused", "acme/support", "doc_site", { lifecycle: "paused" });

    await expect(
      store.create(
        metadata({ kind: "folder", sourceId: "folder-ok" }),
        resolved(),
      ),
    ).resolves.toEqual(expect.objectContaining({ kind: "folder", sourceId: "folder-ok" }));
    await expect(
      store.create(metadata({ kind: "url", sourceId: "url-ok" }), resolved()),
    ).resolves.toEqual(expect.objectContaining({ kind: "url", sourceId: "url-ok" }));

    await expect(
      store.create(metadata({ kind: "url", sourceId: "wrong-kind" }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata({ kind: "url", sourceId: "sibling" }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata({ kind: "url", sourceId: "paused" }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata({ kind: "folder" }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata({ sourceId: "folder-ok" }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
  });

  it("proves a resolved team belongs to the exact landing namespace", async () => {
    await db.query(
      `INSERT INTO org_teams (id, namespace, name, created_by, created_at)
       VALUES ('support-team', 'acme/support', 'Support', 'user:owner', $1),
              ('sales-team', 'acme/sales', 'Sales', 'user:owner', $1)`,
      ["2026-07-20T00:00:00.000Z"],
    );

    await expect(
      store.create(metadata(), resolved({ targetTeamId: "support-team" })),
    ).resolves.toEqual(expect.objectContaining({ targetTeamId: "support-team" }));
    await expect(
      store.create(metadata(), resolved({ targetTeamId: "sales-team" })),
    ).rejects.toThrow(KnowledgeBaseValidationError);
  });

  it("rejects unbounded metadata and authority-like root scope", async () => {
    await expect(
      store.create(metadata({ name: " " }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(
        metadata({ primaryBusinessFunction: "x".repeat(121) }),
        resolved(),
      ),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata({ description: "x".repeat(2001) }), resolved()),
    ).rejects.toThrow(KnowledgeBaseValidationError);
    await expect(
      store.create(metadata(), resolved({ namespace: "" })),
    ).rejects.toThrow(KnowledgeBaseValidationError);
  });
});

describe("KnowledgeBaseStore reads", () => {
  it("derives file status by processing, review, ready, failed, then empty priority", async () => {
    const base = await store.create(metadata(), resolved());
    await companyFile(base.id, "ready", "ready", 4);
    await companyFile(base.id, "failed", "failed", 0);
    expect(await store.get(base.id, { visibleNamespaces: ["acme/support"] })).toEqual(
      expect.objectContaining({ status: "ready", fileCount: 2, factCount: 4 }),
    );

    await companyFile(base.id, "review", "needs_review", 2);
    expect(await store.get(base.id, { visibleNamespaces: ["acme/support"] })).toEqual(
      expect.objectContaining({ status: "needs_review", fileCount: 3, factCount: 6 }),
    );

    await companyFile(base.id, "pending", "processing", 0);
    expect(await store.get(base.id, { visibleNamespaces: ["acme/support"] })).toEqual(
      expect.objectContaining({ status: "processing", fileCount: 4, factCount: 6 }),
    );
  });

  it("includes attached folder and website pieces in collection status and item counts", async () => {
    const base = await store.create(metadata(), resolved());
    await source("folder-attached", "acme/support", "filesystem", { sync: "synced" });
    await source("site-attached", "acme/support", "doc_site", { sync: "pending" });
    await sourceStore.create({
      knowledgeBaseId: base.id, kind: "folder", sourceId: "folder-attached",
      name: "Runbooks", description: "", purpose: "Operations",
    }, { namespace: "acme/support", actor: "user:owner" });
    await sourceStore.create({
      knowledgeBaseId: base.id, kind: "website", sourceId: "site-attached",
      name: "Docs", description: "", purpose: "Reference",
    }, { namespace: "acme/support", actor: "user:owner" });

    expect(await store.get(base.id, { visibleNamespaces: ["acme/support"] })).toEqual(
      expect.objectContaining({ status: "processing", fileCount: 0, sourceCount: 2, itemCount: 2 }),
    );
  });

  it.each([
    ["never_synced", "empty"],
    ["pending", "processing"],
    ["synced", "ready"],
    ["failed", "failed"],
  ] as const)("derives folder/URL %s source state as %s", async (sync, status) => {
    await source(`source-${sync}`, "acme/support", "doc_site", { sync });
    const base = await store.create(
      metadata({ kind: "url", sourceId: `source-${sync}` }),
      resolved(),
    );

    expect(await store.get(base.id, { visibleNamespaces: ["acme/support"] })).toEqual(
      expect.objectContaining({ status }),
    );
  });

  it("uses only the caller's exact ancestor visibility list", async () => {
    const org = await store.create(metadata({ name: "Org" }), resolved({ namespace: "acme" }));
    const support = await store.create(metadata({ name: "Support" }), resolved());
    const sales = await store.create(metadata({ name: "Sales" }), resolved({ namespace: "acme/sales" }));

    const visible = { visibleNamespaces: ["acme", "acme/support"] };
    expect((await store.list({}, visible)).data.map((base) => base.id)).toEqual(
      expect.arrayContaining([org.id, support.id]),
    );
    expect((await store.list({}, visible)).data.map((base) => base.id)).not.toContain(sales.id);
    expect(await store.get(sales.id, visible)).toBeNull();
    expect((await store.list({}, { visibleNamespaces: [] })).data).toEqual([]);
  });

  it("treats wildcard characters in search as literals and paginates", async () => {
    await store.create(metadata({ name: "100% secure_ \\ guide" }), resolved());
    await store.create(metadata({ name: "100X secureY guide" }), resolved());
    await store.create(metadata({ name: "Other" }), resolved());

    const visible = { visibleNamespaces: ["acme/support"] };
    const literal = await store.list({ query: "% secure_ \\" }, visible);
    expect(literal.data.map((base) => base.name)).toEqual(["100% secure_ \\ guide"]);

    const page = await store.list({ page: 2, pageSize: 2 }, visible);
    expect(page.data).toHaveLength(1);
    expect(page.pagination).toEqual({ page: 2, pageSize: 2, total: 3, totalPages: 2 });
  });
});

describe("KnowledgeBaseStore lifecycle", () => {
  it("pauses and resumes only within the exact resolved namespace", async () => {
    const base = await store.create(metadata(), resolved());

    await expect(
      store.pause(base.id, { namespace: "acme/sales", actor: "user:admin" }),
    ).rejects.toThrow(KnowledgeBaseNotFoundError);
    expect(await store.pause(base.id, resolved())).toEqual(
      expect.objectContaining({ lifecycleState: "paused" }),
    );
    expect(await store.pause(base.id, resolved())).toEqual(
      expect.objectContaining({ lifecycleState: "paused" }),
    );
    expect(await store.resume(base.id, resolved())).toEqual(
      expect.objectContaining({ lifecycleState: "active" }),
    );
  });

  it("archives idempotently without deleting and never resumes an archived row", async () => {
    const base = await store.create(metadata(), resolved());
    const archived = await store.archive(base.id, resolved());
    expect(archived).toEqual(
      expect.objectContaining({ lifecycleState: "archived" }),
    );
    expect(await store.archive(base.id, resolved())).toEqual(
      expect.objectContaining({ lifecycleState: "archived" }),
    );
    expect(Number((await db.query("SELECT count(*) AS n FROM knowledge_bases WHERE id = $1", [base.id])).rows[0]?.n)).toBe(1);
    await expect(store.resume(base.id, resolved())).rejects.toThrow(
      KnowledgeBaseConflictError,
    );
  });
});
