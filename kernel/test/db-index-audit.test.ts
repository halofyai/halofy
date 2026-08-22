/**
 * Module A tests — db client + migrations, MemoryIndex (ACL, supersedence,
 * vector search, telemetry), append-only AuditLog.
 * Hermetic: in-memory PGlite with the vector extension, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  MemoryIndex,
  namespaceAncestors,
  toVectorLiteral,
} from "../src/index/index.js";
import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import type { AuditEvent, MemoryObject } from "../src/types.js";

const DIM = 8;

function makeObj(overrides: Partial<MemoryObject> & { id: string }): MemoryObject {
  const now = "2026-07-07T00:00:00.000Z";
  return {
    namespace: "acme/support",
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: "test content",
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "manual", actor: "tester", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
    ...overrides,
  };
}

function unit(hot: number): number[] {
  const v = new Array<number>(DIM).fill(0);
  v[hot] = 1;
  return v;
}

let db: Db;
let index: MemoryIndex;
let audit: AuditLog;

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  // Idempotency: running migrate twice must not throw.
  await migrate(db, DIM);
  index = new MemoryIndex(db);
  audit = new AuditLog(db);
});

afterAll(async () => {
  await db.close();
});

describe("db + migrate", () => {
  it("creates all five tables", async () => {
    const res = await db.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const names = res.rows.map((r) => r.table_name as string);
    for (const t of ["memory_objects", "concepts", "entity_registry", "audit_log", "policies"]) {
      expect(names).toContain(t);
    }
  });

  it("rejects a non-positive embedDim", async () => {
    await expect(migrate(db, 0)).rejects.toThrow(/embedDim/);
  });
});

describe("namespace helpers", () => {
  it("computes prefix ancestors including self", () => {
    expect(namespaceAncestors("org/team/agent")).toEqual(["org", "org/team", "org/team/agent"]);
    expect(namespaceAncestors("org")).toEqual(["org"]);
  });

  it("formats pgvector literals", () => {
    expect(toVectorLiteral([0.1, 0.2, 0.3])).toBe("[0.1,0.2,0.3]");
  });
});

describe("MemoryIndex insert/getById with ACL", () => {
  it("persists classification and source ACL from governed provenance", async () => {
    const obj = makeObj({
      id: "mem-governed",
      namespace: "acme/legal",
      content: "Contact legal@example.com",
      provenance: [{
        source: "document",
        actor: "ingest",
        sourceId: "notion:legal",
        sourceAccess: {
          principals: ["user:42"],
          groups: ["legal"],
          inheritedFrom: "space:legal",
        },
        classification: {
          sensitivity: "restricted",
          piiSubjects: ["email"],
          secretKinds: [],
          residency: "eu",
          allowedDestinations: ["canonical-l2"],
        },
        ts: "2026-07-07T00:00:00.000Z",
      }],
    });

    await index.insert(obj, null);
    const stored = await db.query(
      `SELECT classification, source_access FROM memory_objects WHERE id = $1`,
      [obj.id],
    );

    expect(stored.rows[0]?.classification).toEqual({
      sensitivity: "restricted",
      piiSubjects: ["email"],
      secretKinds: [],
      residency: "eu",
      allowedDestinations: ["canonical-l2"],
    });
    expect(stored.rows[0]?.source_access).toEqual({
      principals: ["user:42"],
      groups: ["legal"],
      inheritedFrom: "space:legal",
    });
  });

  it("round-trips a memory object in the caller's own namespace", async () => {
    const obj = makeObj({ id: "mem-own", namespace: "acme/support", content: "own row" });
    await index.insert(obj, unit(0));
    const { obj: got, denied } = await index.getById("mem-own", "acme/support");
    expect(denied).toBe(false);
    expect(got).not.toBeNull();
    expect(got!.id).toBe("mem-own");
    expect(got!.content).toBe("own row");
    expect(got!.backendRef).toBe("inline");
    expect(got!.tValidTo).toBeNull();
    expect(got!.provenance).toEqual(obj.provenance);
    expect(got!.telemetry.accessCount).toBe(0);
    expect(got!.status).toBe("active");
  });

  it("allows reading a prefix-ancestor namespace row", async () => {
    const obj = makeObj({ id: "mem-org", namespace: "acme", scope: "org", content: "org-wide" });
    await index.insert(obj, null);
    const { obj: got, denied } = await index.getById("mem-org", "acme/support/agent1");
    expect(denied).toBe(false);
    expect(got!.content).toBe("org-wide");
  });

  it("denies a sibling namespace row (denied=true, obj=null)", async () => {
    const obj = makeObj({ id: "mem-sales", namespace: "acme/sales", content: "sibling secret" });
    await index.insert(obj, null);
    const { obj: got, denied } = await index.getById("mem-sales", "acme/support");
    expect(got).toBeNull();
    expect(denied).toBe(true);
  });

  it("denies a descendant namespace row (data never flows up)", async () => {
    const obj = makeObj({ id: "mem-child", namespace: "acme/support/agent1/user9", scope: "user" });
    await index.insert(obj, null);
    const { obj: got, denied } = await index.getById("mem-child", "acme/support");
    expect(got).toBeNull();
    expect(denied).toBe(true);
  });

  it("reports a miss (denied=false) for a nonexistent id", async () => {
    const { obj: got, denied } = await index.getById("no-such-id", "acme/support");
    expect(got).toBeNull();
    expect(denied).toBe(false);
  });
});

describe("supersedence via closeValidity + insert", () => {
  it("closes prior validity and links the successor", async () => {
    const oldObj = makeObj({
      id: "mem-old",
      namespace: "acme/hr",
      content: "PTO is 15 days",
    });
    await index.insert(oldObj, null);

    const ts = "2026-07-07T12:00:00.000Z";
    await index.closeValidity("mem-old", ts);
    const newObj = makeObj({
      id: "mem-new",
      namespace: "acme/hr",
      content: "PTO is 20 days",
      supersedes: "mem-old",
      assertionTime: ts,
      tValidFrom: ts,
    });
    await index.insert(newObj, null);

    const { obj: oldGot, denied: oldDenied } = await index.getById("mem-old", "acme/hr");
    expect(oldGot).toBeNull();
    expect(oldDenied).toBe(false);
    const historical = await db.query(
      `SELECT t_valid_to FROM memory_objects WHERE id = 'mem-old'`,
    );
    expect(new Date(historical.rows[0].t_valid_to as string).toISOString()).toBe(ts);
    const { obj: newGot } = await index.getById("mem-new", "acme/hr");
    expect(newGot!.supersedes).toBe("mem-old");
    expect(newGot!.tValidTo).toBeNull();

    // validOnly candidates exclude the closed row.
    const valid = await index.listCandidates("acme/hr");
    const ids = valid.map((o) => o.id);
    expect(ids).toContain("mem-new");
    expect(ids).not.toContain("mem-old");

    // validOnly=false includes both.
    const all = await index.listCandidates("acme/hr", { validOnly: false });
    const allIds = all.map((o) => o.id);
    expect(allIds).toContain("mem-old");
    expect(allIds).toContain("mem-new");
  });

  it("closeValidity is guarded: an already-closed row is never re-closed (D7)", async () => {
    await index.insert(
      makeObj({ id: "mem-guard", namespace: "acme/hr", content: "guarded row" }),
      null,
    );
    const t1 = "2026-07-07T13:00:00.000Z";
    const t2 = "2026-07-07T14:00:00.000Z";
    expect(await index.closeValidity("mem-guard", t1)).toBe(1);
    // A concurrent writer that lost the race matches ZERO rows — the closed
    // timestamp is never silently overwritten.
    expect(await index.closeValidity("mem-guard", t2)).toBe(0);
    const { obj } = await index.getById("mem-guard", "acme/hr");
    expect(obj).toBeNull();
    const historical = await db.query(
      `SELECT t_valid_to FROM memory_objects WHERE id = 'mem-guard'`,
    );
    expect(new Date(historical.rows[0].t_valid_to as string).toISOString()).toBe(t1);
  });
});

describe("listCandidates ACL scoping", () => {
  it("includes ancestor rows and excludes siblings", async () => {
    const rows = await index.listCandidates("acme/support");
    const namespaces = new Set(rows.map((o) => o.namespace));
    expect(namespaces.has("acme/sales")).toBe(false);
    expect(namespaces.has("acme/support/agent1/user9")).toBe(false);
    const ids = rows.map((o) => o.id);
    expect(ids).toContain("mem-own");
    expect(ids).toContain("mem-org"); // ancestor row flows down
  });

  it("respects the limit option", async () => {
    const rows = await index.listCandidates("acme/support", { limit: 1 });
    expect(rows.length).toBe(1);
  });

  it("finds pointer routes even when 500 newer ordinary facts fill the candidate window", async () => {
    const pointer = makeObj({
      id: "pointer-buried-route",
      namespace: "pointer-volume/team",
      type: "pointer",
      content: "Linear workspace issues live route",
      assertionTime: "2026-07-01T00:00:00.000Z",
      tValidFrom: "2026-07-01T00:00:00.000Z",
      provenance: [{
        source: "source-pointer",
        actor: "system",
        pointer: true,
        connectorId: "linear-volume",
        sourceRef: "issues",
        ts: "2026-07-01T00:00:00.000Z",
      }],
    });
    await index.insert(pointer, unit(0));
    for (let offset = 0; offset < 501; offset += 1) {
      await index.insert(makeObj({
        id: `pointer-volume-fact-${offset.toString().padStart(3, "0")}`,
        namespace: "pointer-volume/team",
        content: `newer ordinary memory ${offset}`,
        assertionTime: "2026-07-08T00:00:00.000Z",
        tValidFrom: "2026-07-08T00:00:00.000Z",
      }), unit(0));
    }

    const generalWindow = await index.listCandidates("pointer-volume/team", {
      limit: 500,
      includePointers: true,
    });
    expect(generalWindow.some((row) => row.id === pointer.id)).toBe(false);
    expect(await index.hasPointerCandidates("pointer-volume/team")).toBe(true);
    expect(await index.listPointerCandidates("pointer-volume/team"))
      .toContainEqual(expect.objectContaining({ id: pointer.id, type: "pointer" }));
    expect(await index.vectorSearchPointers("pointer-volume/team", unit(0), 3))
      .toContainEqual(expect.objectContaining({ obj: expect.objectContaining({ id: pointer.id }) }));
    expect(await index.hasPointerCandidates("pointer-volume/sibling")).toBe(false);
  }, 30_000);
});

describe("vectorSearch", () => {
  it("returns the nearest row first with similarity ~1", async () => {
    await index.insert(
      makeObj({ id: "vec-a", namespace: "acme/eng", content: "vector A" }),
      unit(1),
    );
    await index.insert(
      makeObj({ id: "vec-b", namespace: "acme/eng", content: "vector B" }),
      unit(2),
    );

    const hits = await index.vectorSearch("acme/eng", unit(1), 2);
    expect(hits.length).toBe(2);
    expect(hits[0].obj.id).toBe("vec-a");
    expect(hits[0].similarity).toBeCloseTo(1, 5);
    expect(hits[1].obj.id).toBe("vec-b");
    expect(hits[1].similarity).toBeLessThan(hits[0].similarity);
  });

  it("is ACL-scoped: sibling embeddings are invisible", async () => {
    // vec-a/vec-b live in acme/eng; a caller in acme/sales must not see them.
    const hits = await index.vectorSearch("acme/sales", unit(1), 10);
    const ids = hits.map((h) => h.obj.id);
    expect(ids).not.toContain("vec-a");
    expect(ids).not.toContain("vec-b");
  });

  it("excludes rows whose validity was closed when validOnly", async () => {
    await index.insert(
      makeObj({ id: "vec-old", namespace: "acme/eng", content: "stale vector" }),
      unit(1),
    );
    await index.closeValidity("vec-old", "2026-07-07T12:00:00.000Z");
    const hits = await index.vectorSearch("acme/eng", unit(1), 10, true);
    expect(hits.map((h) => h.obj.id)).not.toContain("vec-old");
    const allHits = await index.vectorSearch("acme/eng", unit(1), 10, false);
    expect(allHits.map((h) => h.obj.id)).toContain("vec-old");
  });

  it("ownNamespaceOnly restricts the query to exactly the caller's namespace", async () => {
    await index.insert(
      makeObj({ id: "vec-anc", namespace: "acme", scope: "org", content: "ancestor vector" }),
      unit(3),
    );
    await index.insert(
      makeObj({ id: "vec-own-child", namespace: "acme/own", content: "own vector" }),
      unit(4),
    );

    // ACL-scoped search from acme/own sees the (closer) ancestor row...
    const acl = await index.vectorSearch("acme/own", unit(3), 10);
    expect(acl.map((h) => h.obj.id)).toContain("vec-anc");

    // ...but the own-namespace query (used by dedupe/supersede targeting)
    // never returns ancestor rows, no matter how much closer they rank.
    const own = await index.vectorSearch("acme/own", unit(3), 10, true, true);
    expect(own.map((h) => h.obj.id)).toEqual(["vec-own-child"]);
  });
});

describe("telemetry counters", () => {
  it("bumpAccess increments access_count and sets last_accessed", async () => {
    await index.bumpAccess(["mem-own", "mem-org"]);
    await index.bumpAccess(["mem-own"]);
    const { obj } = await index.getById("mem-own", "acme/support");
    expect(obj!.telemetry.accessCount).toBe(2);
    expect(obj!.telemetry.lastAccessed).not.toBeNull();
    const { obj: org } = await index.getById("mem-org", "acme");
    expect(org!.telemetry.accessCount).toBe(1);
  });

  it("bumpAccess with an empty list is a no-op", async () => {
    await expect(index.bumpAccess([])).resolves.toBeUndefined();
  });

  it("bumpFault increments fault_count", async () => {
    await index.bumpFault("mem-own");
    const { obj } = await index.getById("mem-own", "acme/support");
    expect(obj!.telemetry.faultCount).toBe(1);
  });

  it("countByNamespace counts active rows in the exact namespace", async () => {
    expect(await index.countByNamespace("acme/support")).toBe(1);
    expect(await index.countByNamespace("acme/eng")).toBe(3);
    expect(await index.countByNamespace("nowhere")).toBe(0);
  });

  it("topAccessed orders by access_count desc", async () => {
    const top = await index.topAccessed("acme/eng", 2);
    expect(top.length).toBe(2);
    expect(top[0].accessCount).toBeGreaterThanOrEqual(top[1].accessCount);
    // mem-own is the most-accessed row in acme/support
    const supportTop = await index.topAccessed("acme/support", 1);
    expect(supportTop[0]).toMatchObject({ id: "mem-own", accessCount: 2 });
  });
});

describe("TTL expiry", () => {
  const expired = (id: string, namespace: string): MemoryObject =>
    makeObj({
      id,
      namespace,
      assertionTime: "2000-01-01T00:00:00.000Z",
      tValidFrom: "2000-01-01T00:00:00.000Z",
      ttlSeconds: 1,
    });

  it("treats an expired direct read as a miss", async () => {
    await index.insert(expired("ttl-get", "ttl/get"), unit(0));

    await expect(index.getById("ttl-get", "ttl/get")).resolves.toEqual({
      obj: null,
      denied: false,
    });
  });

  it("excludes expired rows from candidates even when historical validity is requested", async () => {
    await index.insert(expired("ttl-list", "ttl/list"), unit(1));

    const candidates = await index.listCandidates("ttl/list", {
      validOnly: false,
    });
    expect(candidates.map((candidate) => candidate.id)).not.toContain("ttl-list");
  });

  it("excludes expired rows from vector search even when historical validity is requested", async () => {
    await index.insert(expired("ttl-vector", "ttl/vector"), unit(2));

    const hits = await index.vectorSearch("ttl/vector", unit(2), 10, false);
    expect(hits.map((hit) => hit.obj.id)).not.toContain("ttl-vector");
  });

  it("excludes expired rows from namespace counts", async () => {
    await index.insert(expired("ttl-count", "ttl/count"), null);

    await expect(index.countByNamespace("ttl/count")).resolves.toBe(0);
  });

  it("excludes expired rows from top-accessed summaries", async () => {
    await index.insert(
      expired("ttl-top", "ttl/top"),
      null,
    );
    await index.bumpAccess(["ttl-top"]);

    await expect(index.topAccessed("ttl/top", 10)).resolves.toEqual([]);
  });
});

describe("AuditLog (append-only)", () => {
  const base: AuditEvent = {
    ts: "2026-07-07T01:00:00.000Z",
    actor: "user:nani",
    agentId: "agent-1",
    op: "read",
    memoryId: "mem-own",
    namespace: "acme/support",
    purpose: "test",
    result: "ok",
  };

  it("appends and counts events per namespace", async () => {
    await audit.append(base);
    await audit.append({ ...base, op: "search", memoryId: null, result: "miss" });
    await audit.append({ ...base, namespace: "acme/sales", result: "denied", detail: "acl" });
    expect(await audit.count("acme/support")).toBe(2);
    expect(await audit.count("acme/sales")).toBe(1);
    expect(await audit.count("empty/ns")).toBe(0);
  });

  it("keeps legacy appends void while exposing an explicit inserted sequence", async () => {
    const returnNamespace = "acme/return-test";
    await expect(audit.append({
      ...base,
      namespace: returnNamespace,
      purpose: "legacy-return",
    })).resolves.toBeUndefined();

    const seq = await audit.appendWithSeq({
      ...base,
      namespace: returnNamespace,
      purpose: "sequence-return",
    });
    expect(seq).toBeGreaterThan(0);
  });

  it("lists most recent first and round-trips fields", async () => {
    const events = await audit.list("acme/support", { limit: 10 });
    expect(events.length).toBe(2);
    expect(events[0].op).toBe("search");
    expect(events[0].result).toBe("miss");
    expect(events[0].memoryId).toBeNull();
    expect(events[1]).toMatchObject({
      op: "read",
      actor: "user:nani",
      agentId: "agent-1",
      memoryId: "mem-own",
      purpose: "test",
      result: "ok",
    });
    expect(events[1].ts).toBe(base.ts);
  });

  it("records denied outcomes with detail", async () => {
    const denied = await audit.list("acme/sales", { limit: 1 });
    expect(denied[0].result).toBe("denied");
    expect(denied[0].detail).toBe("acl");
  });

  it("exposes no update or delete methods", () => {
    // M5 Module B (sanctioned named exception): AuditLog gains an additive,
    // read-only `search()` for the control-room S8 screen. The append-only
    // invariant this test guards is intact — there is still NO update or
    // delete method; `appendTo` is the transaction-scoped append primitive,
    // and `search` is a filtered read alongside `list`/`count`.
    // `searchPage` and `summary` are reads for paginated export and exact
    // aggregate counts — still SELECTs, still no write path.
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(audit));
    expect(proto.sort()).toEqual([
      "append",
      "appendTo",
      "appendToWithSeq",
      "appendWithSeq",
      "constructor",
      "count",
      "list",
      "search",
      "searchPage",
      "summary",
      "verifyChain",
    ]);
  });
});
