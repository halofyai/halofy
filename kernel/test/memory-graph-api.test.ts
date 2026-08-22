/**
 * Module E (M10 ACCESS) — /v1/memory-graph read model: projection-filtered
 * topology (D40), both-endpoints edges (D45), post-filter counts + caps,
 * uniform not-found + D4 denial audit (D46), projection-in-graph-out purity.
 *
 * Two-function tenant `acme` (marketing + sales) plus a second tenant `beta`.
 * A Marketing member must see common + marketing-shared + own personal ONLY;
 * no sales node, edge, count, source name, skill, agent, or ID may appear
 * anywhere in the SERIALIZED response. A Marketing admin governs the whole
 * marketing subtree and still never sees sales. Tenant root sees tenant-wide
 * and zero foreign-tenant markers. Namespaces containing `_` prove the
 * escaped-prefix predicate never treats them as wildcards (D44).
 *
 * Hermetic: in-memory PGlite via Kernel.boot, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import type { AccessProjection } from "../src/types.js";
import {
  getMemoryGraph,
  memoryGraphTopology,
  memoryGraphScopeId,
  MemoryGraphNotFoundError,
  MEMORY_GRAPH_NODE_CAP,
  MEMORY_TOPOLOGY_NODE_CAP,
  type MemoryGraphDeps,
} from "../src/console/api.js";

let kernel: Kernel;
let deps: MemoryGraphDeps;

const TENANT = "acme";
const COMMON = "acme/common";
const MKT = "acme/functions/marketing";
const MKT_SHARED = "acme/functions/marketing/shared";
const MKT_U1 = "acme/functions/marketing/people/u1";
const MKT_U2 = "acme/functions/marketing/people/u2";
const SALES_SHARED = "acme/functions/sales/shared";
// D44 wildcard trap: govern `m_k` must not match sibling `mxk` via LIKE `_`.
const UNDERSCORE_FN = "acme/functions/m_k";
const UNDERSCORE_SHARED = "acme/functions/m_k/shared";
const TRAP_SHARED = "acme/functions/mxk/shared";

const SALES_SRC_ID = "src-sales-1";
const MKT_SRC_ID = "src-mkt-1";

async function seedMemory(
  id: string,
  namespace: string,
  content: string,
  extra?: { supersedes?: string; tValidTo?: string; provenance?: unknown[] },
): Promise<void> {
  const now = new Date().toISOString();
  await kernel.db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        assertion_time, t_valid_from, t_valid_to, supersedes, provenance)
     VALUES ($1, $2, 'team', 'L2', 'ref', $3, 'fact', 0.9, $4, $4, $5, $6, $7)`,
    [
      id,
      namespace,
      content,
      now,
      extra?.tValidTo ?? null,
      extra?.supersedes ?? null,
      JSON.stringify(extra?.provenance ?? []),
    ],
  );
}

function memberProjection(): AccessProjection {
  return {
    tenantId: TENANT,
    subjectId: "user-u1",
    role: "member",
    consumeRoots: [COMMON, MKT_SHARED],
    governRoots: [],
    personalRoots: [MKT_U1],
    allowedOperations: ["graph:read"],
    version: 1,
    hash: "member-hash-1",
  };
}

function adminProjection(): AccessProjection {
  return {
    tenantId: TENANT,
    subjectId: "user-admin",
    role: "admin",
    consumeRoots: [COMMON],
    governRoots: [MKT],
    personalRoots: [],
    allowedOperations: ["graph:read"],
    version: 1,
    hash: "admin-hash-1",
  };
}

function rootProjection(): AccessProjection {
  return {
    tenantId: TENANT,
    subjectId: "user-root",
    role: "root",
    consumeRoots: [],
    governRoots: [TENANT],
    personalRoots: [],
    allowedOperations: ["graph:read"],
    version: 1,
    hash: "root-hash-1",
  };
}

function underscoreAdminProjection(): AccessProjection {
  return {
    tenantId: TENANT,
    subjectId: "user-underscore",
    role: "admin",
    consumeRoots: [],
    governRoots: [UNDERSCORE_FN],
    personalRoots: [],
    allowedOperations: ["graph:read"],
    version: 1,
    hash: "underscore-hash-1",
  };
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  deps = {
    db: kernel.db,
    audit: kernel.audit,
    auditActor: "user-u1",
    auditAgentId: "test",
  };
  const now = new Date().toISOString();

  // --- memories -------------------------------------------------------------
  await seedMemory("mem-common-1", COMMON, "Handbook COMMONMARKER");
  await seedMemory("mem-mkt-shared-1", MKT_SHARED, "Campaign MKTSHAREDMARKER");
  await seedMemory("mem-u1-1", MKT_U1, "Note PERSONALMARKER");
  await seedMemory("mem-u2-1", MKT_U2, "Note OTHERPERSONALMARKER");
  await seedMemory("mem-sales-1", SALES_SHARED, "Pipeline SALESMARKER");
  await seedMemory("mem-beta-1", "beta/common", "Foreign FOREIGNMARKER");
  await seedMemory("mem-underscore-1", UNDERSCORE_SHARED, "Fact UNDERSCOREMARKER");
  await seedMemory("mem-trap-1", TRAP_SHARED, "Fact TRAPMARKER");

  // Supersedence across the marketing/sales boundary: the newer SALES fact
  // supersedes an older MARKETING fact — one endpoint hidden for the member.
  await seedMemory("mem-mkt-old-1", MKT_SHARED, "Old rate MKTOLDMARKER", {
    tValidTo: now,
  });
  await seedMemory("mem-sales-super-1", SALES_SHARED, "New rate SALESSUPERMARKER", {
    supersedes: "mem-mkt-old-1",
  });

  // A marketing-visible memory citing a SALES source: the provenance edge and
  // the source name must vanish for anyone who cannot see sales.
  await seedMemory("mem-mkt-cross-1", MKT_SHARED, "Cross MKTCROSSMARKER", {
    provenance: [{ sourceId: SALES_SRC_ID }],
  });

  // --- sources (marker in the kind = the "source name" on the node) ----------
  await kernel.db.query(
    `INSERT INTO sources (id, namespace, kind, created_at) VALUES
       ($1, $2, 'mktsrcmarker', $5),
       ($3, $4, 'salessrcmarker', $5),
       ('src-mkt-notion', $2, 'notion_direct', $5),
       ('src-mkt-kb-upload', $2, 'file-upload', $5)`,
    [MKT_SRC_ID, MKT_SHARED, SALES_SRC_ID, SALES_SHARED, now],
  );
  await kernel.db.query(
    `INSERT INTO source_documents
       (source_id, landing_namespace, document_key, content_hash, synced_at) VALUES
       ('src-mkt-notion', $1, 'page:notion-page-1', $2, $4),
       ('src-mkt-notion', $1, 'page:notion-page-2', $3, $4),
       ('src-mkt-kb-upload', $1, 'handbook-upload.pdf', $2, $4)`,
    [MKT_SHARED, "b".repeat(64), "c".repeat(64), now],
  );

  // Policy uploads are immutable provenance anchors, never connector
  // backends. Active documents belong under the Policies graph branch; an
  // orphaned/failed-attempt anchor must not surface as a backend either.
  await kernel.db.query(
    `INSERT INTO sources (id, namespace, kind, created_at) VALUES
       ('src-policy-common', $1, 'policy-upload', $5),
       ('src-policy-mkt-parent', $2, 'policy-upload', $5),
       ('src-policy-mkt-shared', $3, 'policy-upload', $5),
       ('src-policy-sales', $4, 'policy-upload', $5),
       ('src-policy-orphan', $3, 'policy-upload', $5)`,
    [COMMON, MKT, MKT_SHARED, SALES_SHARED, now],
  );
  await kernel.db.query(
    `INSERT INTO policy_documents
       (id, source_id, namespace, title, kind, status, file_name, media_type,
        byte_size, content_sha256, attempt_token, lease_expires_at, fact_count,
        created_by, created_at, loaded_at) VALUES
       ('policy-common', 'src-policy-common', $1, 'Common guardrail', 'policy',
        'active', 'common.md', 'text/markdown', 32, $5, 'attempt-common', $9, 1,
        'seed', $9, $9),
       ('policy-mkt-parent', 'src-policy-mkt-parent', $2, 'Marketing guardrail',
        'guideline', 'active', 'marketing.md', 'text/markdown', 32, $6,
        'attempt-mkt-parent', $9, 2, 'seed', $9, $9),
       ('policy-mkt-shared', 'src-policy-mkt-shared', $3,
        'Marketing shared guardrail', 'procedure', 'needs_review',
        'marketing-shared.md', 'text/markdown', 32, $7,
        'attempt-mkt-shared', $9, 3, 'seed', $9, $9),
       ('policy-sales', 'src-policy-sales', $4, 'Sales guardrail', 'policy',
        'active', 'sales.md', 'text/markdown', 32, $8, 'attempt-sales', $9, 4,
        'seed', $9, $9)`,
    [
      COMMON,
      MKT,
      MKT_SHARED,
      SALES_SHARED,
      "d".repeat(64),
      "e".repeat(64),
      "f".repeat(64),
      "9".repeat(64),
      now,
    ],
  );
  await seedMemory("mem-mkt-notion-page", MKT_SHARED, "Product roadmap\nLaunch milestones", {
    provenance: [{
      source: "document",
      sourceId: "src-mkt-notion",
      documentKey: "page:notion-page-1",
      ts: now,
    }],
  });

  await seedMemory("mem-mkt-saved-old", MKT_SHARED, "Refunds close after 14 days", {
    tValidTo: now,
    provenance: [{
      source: "document",
      actor: "ananya@acme.test",
      sourceId: MKT_SRC_ID,
      documentKey: "Refunds.md",
      ts: now,
    }],
  });
  await seedMemory("mem-mkt-saved-current", MKT_SHARED, "Annual refunds close after 30 days", {
    supersedes: "mem-mkt-saved-old",
    provenance: [{
      source: "document",
      actor: "ananya@acme.test",
      sourceId: MKT_SRC_ID,
      documentKey: "Refunds.md",
      ts: now,
    }],
  });
  await kernel.db.query(
    `UPDATE memory_objects
        SET confidence = 0.96, access_count = 214, last_accessed = $1,
            display_title = 'Thirty-Day Refund Window',
            display_title_model = 'gpt-5.6-luna-1', title_status = 'complete'
      WHERE id = 'mem-mkt-saved-current'`,
    [now],
  );

  // --- skills -----------------------------------------------------------------
  await kernel.db.query(
    `INSERT INTO skills (id, namespace, skill_key, name, definition, content_sha256,
                         t_valid_from, created_by, created_at, updated_at) VALUES
       ('skill-mkt-1', $1, 'mkt-skill', 'MKTSKILLMARKER', 'do things', $3, $4, 'seed', $4, $4),
       ('skill-sales-1', $2, 'sales-skill', 'SALESSKILLMARKER', 'do things', $3, $4, 'seed', $4, $4)`,
    [MKT_SHARED, SALES_SHARED, "a".repeat(64), now],
  );

  // --- agent badges -------------------------------------------------------------
  await kernel.db.query(
    `INSERT INTO api_keys (id, key_hash, namespace, actor, role, created_at) VALUES
       ('badge-mkt-1', 'hash-mkt-1', $1, 'mktagentmarker', 'agent', $3),
       ('badge-sales-1', 'hash-sales-1', $2, 'salesagentmarker', 'agent', $3)`,
    [MKT_SHARED, SALES_SHARED, now],
  );

  // --- knowledge bases -----------------------------------------------------------
  await kernel.db.query(
    `INSERT INTO knowledge_bases
       (id, namespace, name, kind, status, lifecycle_state, source_id,
        primary_business_function, description, t_valid_from, created_by,
        created_at, updated_at) VALUES
       ('kb-mkt-1', $1, 'MKTKBMARKER', 'folder', 'ready', 'active', $3,
        'marketing', '', $5, 'seed', $5, $5),
       ('kb-sales-1', $2, 'SALESKBMARKER', 'folder', 'ready', 'active', $4,
        'sales', '', $5, 'seed', $5, $5)`,
    [MKT_SHARED, SALES_SHARED, MKT_SRC_ID, SALES_SRC_ID, now],
  );

  // --- >500 visible nodes for the post-filter cap ------------------------------
  await kernel.db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        assertion_time, t_valid_from)
     SELECT 'bulk-' || lpad(g::text, 4, '0'), $1, 'team', 'L2', 'ref',
            'bulk fact ' || g, 'fact', 0.9, $2, $2
       FROM generate_series(1, 520) g`,
    [MKT_SHARED, now],
  );
});

afterAll(async () => {
  await kernel.close();
});

describe("memory-graph read model (M10 module E)", () => {
  it("keeps connector backends and their files separate from knowledge-base upload sources", async () => {
    const topology = await memoryGraphTopology(
      { db: kernel.db, getPolicy: (namespace) => kernel.getPolicy(namespace) },
      memberProjection(),
    );

    const notion = topology.sources.find((source) => source.id === "src-mkt-notion");
    expect(notion).toMatchObject({
      kind: "notion_direct",
      documentCount: 2,
      documents: [
        expect.objectContaining({ id: "page:notion-page-1", name: "Product roadmap" }),
        expect.objectContaining({ id: "page:notion-page-2", name: "Page notion-page-2" }),
      ],
    });
    expect(topology.sources.some((source) => source.id === "src-mkt-kb-upload")).toBe(false);
    expect(topology.sources.some((source) => source.kind === "policy-upload")).toBe(false);
    expect(topology.knowledgeBases.some((base) => base.id === "kb-mkt-1")).toBe(true);

    const page = await getMemoryGraph(deps, memberProjection());
    const next = page.cursor
      ? await getMemoryGraph(deps, memberProjection(), { cursor: page.cursor })
      : null;
    const projectedNodes = [...page.nodes, ...(next?.nodes ?? [])];
    expect(projectedNodes.some((node) => node.id === "src-mkt-notion")).toBe(true);
    expect(projectedNodes.some((node) => node.id === "src-mkt-kb-upload")).toBe(false);
    expect(projectedNodes.some((node) => node.id.startsWith("src-policy-"))).toBe(false);
  });

  it("projects policy documents under Policies through the same authorized visible set", async () => {
    const member = await memoryGraphTopology(
      { db: kernel.db, getPolicy: (namespace) => kernel.getPolicy(namespace) },
      memberProjection(),
    );
    expect(member.policies.map((policy) => policy.title)).toEqual([
      "Common guardrail",
      "Marketing guardrail",
      "Marketing shared guardrail",
    ]);
    expect(JSON.stringify(member)).not.toContain("Sales guardrail");
    expect(member.sources.some((source) => source.kind === "policy-upload")).toBe(false);

    const root = await memoryGraphTopology(
      { db: kernel.db, getPolicy: (namespace) => kernel.getPolicy(namespace) },
      rootProjection(),
    );
    expect(root.policies.map((policy) => policy.title)).toEqual([
      "Common guardrail",
      "Marketing guardrail",
      "Marketing shared guardrail",
      "Sales guardrail",
    ]);
    expect(root.sources.some((source) => source.kind === "policy-upload")).toBe(false);

    const marketingScope = memoryGraphScopeId(TENANT, MKT_SHARED);
    const narrowed = await memoryGraphTopology(
      { db: kernel.db, getPolicy: (namespace) => kernel.getPolicy(namespace) },
      memberProjection(),
      marketingScope,
    );
    expect(narrowed.policies).toEqual([
      expect.objectContaining({
        title: "Marketing guardrail",
        inherited: true,
      }),
      expect.objectContaining({
        title: "Marketing shared guardrail",
        inherited: false,
      }),
    ]);
    expect(JSON.stringify(narrowed)).not.toContain("Common guardrail");
    expect(JSON.stringify(narrowed)).not.toContain("Sales guardrail");
  });

  it("ships every ordinary visible memory to the topology instead of a 36-row sample", async () => {
    const topology = await memoryGraphTopology(
      { db: kernel.db, getPolicy: (namespace) => kernel.getPolicy(namespace) },
      memberProjection(),
    );

    expect(topology.memories.length).toBeGreaterThan(36);
    expect(topology.memories.length).toBeLessThanOrEqual(MEMORY_TOPOLOGY_NODE_CAP);
    expect(topology.memories.some((memory) => memory.id === "bulk-0520")).toBe(true);
  });

  it("returns current saved-memory metadata and only direct visible graph neighbors", async () => {
    const page = await getMemoryGraph(deps, memberProjection());
    const saved = page.savedMemories.find((row) => row.id === "mem-mkt-saved-current");

    expect(saved).toMatchObject({
      tier: "L2",
      status: "Current",
      summary: "Annual refunds close after 30 days",
      title: "Thirty-Day Refund Window",
      body: "Annual refunds close after 30 days",
      team: "Marketing",
      source: "Refunds.md",
      author: "ananya@acme.test",
      authorRole: "Document capture",
      version: 2,
      confidence: 0.96,
      accessCount: 214,
      facts: ["Annual refunds close after 30 days"],
    });
    expect(saved?.links).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: MKT_SRC_ID, kind: "source", role: "Source" }),
      expect.objectContaining({ id: "mem-mkt-saved-old", kind: "memory", role: "Previous version" }),
    ]));
    expect(page.savedMemories.some((row) => row.id === "mem-mkt-saved-old")).toBe(false);
    expect(JSON.stringify(page.savedMemories)).not.toContain(MKT_SHARED);
    expect(JSON.stringify(page.savedMemories)).not.toContain(SALES_SRC_ID);
  });

  it("member sees common + marketing-shared + own personal only; sales absent from the serialized response", async () => {
    const page = await getMemoryGraph(deps, memberProjection());
    // Full serialized-body scan (the wire payload for the member — D40).
    let wire = JSON.stringify(page);
    if (page.cursor) {
      const next = await getMemoryGraph(deps, memberProjection(), {
        cursor: page.cursor,
      });
      wire += JSON.stringify(next);
    }

    expect(wire).toContain("COMMONMARKER");
    expect(wire).toContain("MKTSHAREDMARKER");
    expect(wire).toContain("PERSONALMARKER");
    expect(wire).toContain("MKTSKILLMARKER");
    expect(wire).toContain("mktagentmarker");
    expect(wire).toContain("mktsrcmarker");
    expect(wire).toContain("MKTKBMARKER");

    // No sales node, edge, count, label, source name, skill, agent, or ID.
    expect(wire).not.toContain("SALESMARKER");
    expect(wire).not.toContain("SALESSUPERMARKER");
    expect(wire).not.toContain("salessrcmarker");
    expect(wire).not.toContain("SALESSKILLMARKER");
    expect(wire).not.toContain("salesagentmarker");
    expect(wire).not.toContain("SALESKBMARKER");
    expect(wire).not.toContain(SALES_SRC_ID);
    expect(wire).not.toContain("mem-sales");
    expect(wire).not.toContain("skill-sales");
    expect(wire).not.toContain("badge-sales");
    expect(wire).not.toContain("kb-sales");
    // Sibling personal space and foreign tenant are invisible too.
    expect(wire).not.toContain("OTHERPERSONALMARKER");
    expect(wire).not.toContain("FOREIGNMARKER");
    // No namespace strings leak onto the wire (opaque IDs only — D9).
    expect(wire).not.toContain(MKT_SHARED);

    expect(page.title).toBe("Your memory");
    const labels = page.scopes.map((s) => s.label).sort();
    expect(labels).toEqual(["Common", "Marketing", "Personal"]);
  });

  it("drops an edge when one endpoint is hidden; keeps it when both are visible", async () => {
    const member = await getMemoryGraph(deps, memberProjection());
    const memberEdges = [
      ...member.edges,
      ...(member.cursor
        ? (
            await getMemoryGraph(deps, memberProjection(), {
              cursor: member.cursor,
            })
          ).edges
        : []),
    ];
    // Supersedes edge: sales endpoint hidden → the edge does not exist.
    expect(
      memberEdges.some((e) => e.from === "mem-sales-super-1" || e.to === "mem-sales-super-1"),
    ).toBe(false);
    // Provenance edge to the sales source: hidden → absent.
    expect(memberEdges.some((e) => e.to === SALES_SRC_ID)).toBe(false);
    // Provenance edge to the visible marketing source is intact (via kb).
    expect(
      memberEdges.some((e) => e.from === "kb-mkt-1" && e.to === MKT_SRC_ID),
    ).toBe(true);

    // Root sees both endpoints → both edges exist.
    const root = await getMemoryGraph(deps, rootProjection());
    const rootEdges = [
      ...root.edges,
      ...(root.cursor
        ? (
            await getMemoryGraph(deps, rootProjection(), { cursor: root.cursor })
          ).edges
        : []),
    ];
    expect(
      rootEdges.some(
        (e) =>
          e.from === "mem-sales-super-1" &&
          e.to === "mem-mkt-old-1" &&
          e.relation === "supersedes",
      ),
    ).toBe(true);
    expect(
      rootEdges.some(
        (e) =>
          e.from === "mem-mkt-cross-1" &&
          e.to === SALES_SRC_ID &&
          e.relation === "from_source",
      ),
    ).toBe(true);
  });

  it("admin governs the marketing subtree (member subspaces included), never sales", async () => {
    const page = await getMemoryGraph(deps, adminProjection());
    let wire = JSON.stringify(page);
    if (page.cursor) {
      wire += JSON.stringify(
        await getMemoryGraph(deps, adminProjection(), { cursor: page.cursor }),
      );
    }
    expect(wire).toContain("MKTSHAREDMARKER");
    expect(wire).toContain("PERSONALMARKER");
    expect(wire).toContain("OTHERPERSONALMARKER"); // govern reaches subspaces
    expect(wire).toContain("COMMONMARKER");
    expect(wire).not.toContain("SALESMARKER");
    expect(wire).not.toContain("salessrcmarker");
    expect(wire).not.toContain("SALESSKILLMARKER");
    expect(wire).not.toContain("salesagentmarker");
    expect(wire).not.toContain("FOREIGNMARKER");
    expect(page.title).toBe("Marketing memory");
  });

  it("root sees tenant-wide and zero foreign-tenant markers", async () => {
    const first = await getMemoryGraph(deps, rootProjection());
    let wire = JSON.stringify(first);
    let cursor = first.cursor;
    while (cursor) {
      const next = await getMemoryGraph(deps, rootProjection(), { cursor });
      wire += JSON.stringify(next);
      cursor = next.cursor;
    }
    expect(wire).toContain("COMMONMARKER");
    expect(wire).toContain("MKTSHAREDMARKER");
    expect(wire).toContain("SALESMARKER");
    expect(wire).toContain("OTHERPERSONALMARKER");
    expect(wire).not.toContain("FOREIGNMARKER");
    expect(wire).not.toContain("mem-beta");
    expect(first.title).toBe("Company memory");
  });

  it("escaped-prefix govern predicate keeps `_` literal (no wildcard sibling leak)", async () => {
    const page = await getMemoryGraph(deps, underscoreAdminProjection());
    const wire = JSON.stringify(page);
    expect(wire).toContain("UNDERSCOREMARKER");
    expect(wire).not.toContain("TRAPMARKER");
  });

  it("poisoned scopeId → uniform not-found shape + D4 denial audit rows", async () => {
    const before = await kernel.db.query(
      `SELECT count(*) AS n FROM audit_log
        WHERE purpose = 'memory-graph' AND result = 'denied'`,
    );
    const beforeN = Number((before.rows[0] as { n: unknown }).n);

    // A REAL but unauthorized scope (sales) for the member...
    const salesScope = memoryGraphScopeId(TENANT, SALES_SHARED);
    let realErr: unknown;
    try {
      await getMemoryGraph(deps, memberProjection(), { scopeId: salesScope });
    } catch (err) {
      realErr = err;
    }
    // ...and a nonexistent one must be indistinguishable (D46).
    let fakeErr: unknown;
    try {
      await getMemoryGraph(deps, memberProjection(), { scopeId: "no-such-scope" });
    } catch (err) {
      fakeErr = err;
    }
    expect(realErr).toBeInstanceOf(MemoryGraphNotFoundError);
    expect(fakeErr).toBeInstanceOf(MemoryGraphNotFoundError);
    expect((realErr as Error).message).toBe((fakeErr as Error).message);
    expect((realErr as Error).name).toBe((fakeErr as Error).name);
    // The denial detail never names the hidden target.
    expect(JSON.stringify(realErr)).not.toContain(salesScope);

    const after = await kernel.db.query(
      `SELECT count(*) AS n, count(*) FILTER (WHERE detail LIKE '%' || $1 || '%') AS leaked
         FROM audit_log
        WHERE purpose = 'memory-graph' AND result = 'denied'`,
      [salesScope],
    );
    const row = after.rows[0] as { n: unknown; leaked: unknown };
    expect(Number(row.n)).toBe(beforeN + 2);
    expect(Number(row.leaked)).toBe(0);
  });

  it("scope selection narrows the union, never widens it", async () => {
    const scope = memoryGraphScopeId(TENANT, MKT_SHARED);
    const first = await getMemoryGraph(deps, memberProjection(), {
      scopeId: scope,
    });
    let wire = JSON.stringify(first);
    let cursor = first.cursor;
    while (cursor) {
      const next = await getMemoryGraph(deps, memberProjection(), {
        scopeId: scope,
        cursor,
      });
      wire += JSON.stringify(next);
      cursor = next.cursor;
    }
    expect(wire).toContain("MKTSHAREDMARKER");
    expect(wire).not.toContain("COMMONMARKER");
    expect(wire).not.toContain("PERSONALMARKER");
    expect(wire).not.toContain("SALESMARKER");
    expect(first.title).toBe("Marketing memory");
  });

  /**
   * The graph is read as "the company by team", so every named team inside a
   * subject's granted subtree is offered as its own scope — a tenant root gets
   * one option per team instead of a single company-wide root. Adding a team
   * option can only NARROW (it is already inside a granted root), and a team
   * outside the grant is never offered and never selectable (D42/D46).
   */
  describe("named teams as scopes", () => {
    beforeAll(async () => {
      const now = new Date().toISOString();
      await kernel.db.query(
        `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
         VALUES ($1, $2, 'Marketing crew', '', 'seed', $5),
                ($3, $4, 'Sales crew', '', 'seed', $5)`,
        ["team-mkt", MKT_SHARED, "team-sales", SALES_SHARED, now],
      );
    });

    it("offers each granted team under its real name and never a foreign one", async () => {
      const root = await getMemoryGraph(deps, rootProjection());
      const labels = root.scopes.map((s) => s.label);
      // Root governs the tenant, so BOTH teams are inside its grant.
      expect(labels).toContain("Marketing crew");
      expect(labels).toContain("Sales crew");
      // Opaque ids only — no namespace strings on the wire (D9).
      expect(JSON.stringify(root.scopes)).not.toContain(MKT_SHARED);

      const member = await getMemoryGraph(deps, memberProjection());
      const memberLabels = member.scopes.map((s) => s.label);
      expect(memberLabels).toContain("Marketing crew");
      expect(memberLabels).not.toContain("Sales crew");
      // The team name replaces the namespace-derived guess for that root.
      expect(memberLabels).not.toContain("Marketing");
    });

    it("selecting a team narrows the graph to that team's information", async () => {
      const teamScope = memoryGraphScopeId(TENANT, MKT_SHARED);
      const page = await getMemoryGraph(deps, rootProjection(), { scopeId: teamScope });
      let wire = JSON.stringify(page);
      let cursor = page.cursor;
      while (cursor) {
        const next = await getMemoryGraph(deps, rootProjection(), { scopeId: teamScope, cursor });
        wire += JSON.stringify(next);
        cursor = next.cursor;
      }
      expect(page.title).toBe("Marketing crew memory");
      expect(wire).toContain("MKTSHAREDMARKER");
      // Everything outside the team is gone, including what root can otherwise see.
      expect(wire).not.toContain("SALESMARKER");
      expect(wire).not.toContain("COMMONMARKER");
      expect(wire).not.toContain("OTHERPERSONALMARKER");
    });

    it("a team outside the subject's grant stays unselectable", async () => {
      const salesScope = memoryGraphScopeId(TENANT, SALES_SHARED);
      await expect(
        getMemoryGraph(deps, memberProjection(), { scopeId: salesScope }),
      ).rejects.toBeInstanceOf(MemoryGraphNotFoundError);
    });
  });

  it("caps apply post-filter with deterministic ordering and a continuation cursor", async () => {
    const p1a = await getMemoryGraph(deps, memberProjection());
    const p1b = await getMemoryGraph(deps, memberProjection());
    // Deterministic: identical serialized bytes for the same projection.
    expect(JSON.stringify(p1a)).toBe(JSON.stringify(p1b));

    expect(p1a.counts.nodes).toBeGreaterThan(MEMORY_GRAPH_NODE_CAP);
    expect(p1a.nodes.length).toBe(MEMORY_GRAPH_NODE_CAP);
    expect(p1a.cursor).toBeDefined();

    const p2 = await getMemoryGraph(deps, memberProjection(), {
      cursor: p1a.cursor,
    });
    expect(p2.counts.nodes).toBe(p1a.counts.nodes);
    expect(p2.nodes.length).toBe(p1a.counts.nodes - MEMORY_GRAPH_NODE_CAP);
    expect(p2.cursor).toBeUndefined();
    const ids1 = new Set(p1a.nodes.map((n) => n.id));
    expect(p2.nodes.some((n) => ids1.has(n.id))).toBe(false);
  });

  it("projection-in-graph-out purity: audit attribution never changes the body (preview equivalence)", async () => {
    const asSubject = await getMemoryGraph(
      { ...deps, auditActor: "user-u1" },
      memberProjection(),
    );
    const asRootPreview = await getMemoryGraph(
      { ...deps, auditActor: "user-root" },
      memberProjection(),
    );
    expect(JSON.stringify(asRootPreview)).toBe(JSON.stringify(asSubject));
  });

  it("writes a D4 ok audit row per allowed read", async () => {
    const before = await kernel.db.query(
      `SELECT count(*) AS n FROM audit_log
        WHERE purpose = 'memory-graph' AND result = 'ok'`,
    );
    const beforeN = Number((before.rows[0] as { n: unknown }).n);
    await getMemoryGraph(deps, memberProjection());
    const after = await kernel.db.query(
      `SELECT count(*) AS n FROM audit_log
        WHERE purpose = 'memory-graph' AND result = 'ok'`,
    );
    expect(Number((after.rows[0] as { n: unknown }).n)).toBe(beforeN + 1);
  });
});
