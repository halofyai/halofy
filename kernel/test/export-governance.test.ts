/**
 * M9 #7 — governed markdown export (D28, E15–E18).
 *
 * Hermetic: in-memory PGlite, real MemoryIndex + AuditLog, zero network.
 * The L3 lister is a structural in-test double (the concrete ColdStore
 * satisfies the same ExportConceptsLike slice; its ACL is covered by
 * cold-store.test.ts — here we exercise the export gate over its output).
 */

import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MemoryIndex } from "../src/index/index.js";
import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { AuthzError } from "../src/auth/index.js";
import {
  canExport,
  CONCEPT_SOURCE,
  conceptClassification,
  exportSource,
  memExport,
  type ExporterDeps,
} from "../src/export/index.js";
import type {
  Concept,
  DataClassification,
  Identity,
  MemoryObject,
} from "../src/types.js";

const DIM = 8;

function classification(over: Partial<DataClassification> = {}): DataClassification {
  return {
    sensitivity: "internal",
    piiSubjects: [],
    secretKinds: [],
    allowedDestinations: [],
    ...over,
  };
}

function makeObj(over: Partial<MemoryObject> & { id: string }): MemoryObject {
  const now = "2026-07-01T00:00:00.000Z";
  return {
    namespace: "acme/support",
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: "exportable content",
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "manual", actor: "tester", ts: now }],
    classification: classification(),
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
    ...over,
  };
}

function identity(role: Identity["role"], namespace = "acme/support"): Identity {
  return { keyId: "01KEY", namespace, actor: "alice", role };
}

const publicConcept: Concept = {
  path: "concepts/refund-policy.md",
  type: "policy",
  title: "Refund policy",
  description: "How refunds work.",
  tags: ["policy"],
  visibility: "public",
  body: "Refunds are granted within 30 days.",
};

const secretConcept: Concept = {
  path: "concepts/leaked-key.md",
  type: "note",
  title: "Ops runbook",
  description: "",
  tags: [],
  visibility: "public",
  body: "token: ghp_ABCDEFGHIJKLMNOPQRSTUV123456",
};

let db: Db;
let index: MemoryIndex;
let audit: AuditLog;
let deps: ExporterDeps;

async function exportAuditRows(): Promise<
  { result: string; detail: string | null; namespace: string; actor: string }[]
> {
  const res = await db.query(
    `SELECT result, detail, namespace, actor FROM audit_log WHERE op = 'export' ORDER BY seq`,
  );
  return res.rows as { result: string; detail: string | null; namespace: string; actor: string }[];
}

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  index = new MemoryIndex(db);
  audit = new AuditLog(db);
  deps = {
    index,
    concepts: { listConcepts: async () => [publicConcept, secretConcept] },
    audit,
  };

  await index.insert(makeObj({ id: "01EXPORTOK", content: "the sky is blue" }), null);
  // Readable by agents (agent-context grant) but NOT exportable: the index's
  // read fence admits it, the export gate must still exclude it.
  await index.insert(
    makeObj({
      id: "01RESTRICT",
      content: "secret sauce recipe",
      classification: classification({
        sensitivity: "confidential",
        allowedDestinations: ["agent-context"],
      }),
    }),
    null,
  );
  // REAL l4WriteBack shape (src/kernel.ts): a cache fact always carries BOTH
  // source:'live-fetch' AND sourceId:<connectorId> (+ cache:true) on the same
  // entry. The audit found the earlier label-only fixture let exportSource
  // return the connectorId and walk straight past EXPORT_DENIED_SOURCES.
  await index.insert(
    makeObj({
      id: "01LIVEFTCH",
      content: "cached external row",
      provenance: [{
        source: "live-fetch",
        actor: "l4",
        ts: "2026-07-01T00:00:00.000Z",
        sourceId: "salesforce",
        connectorId: "salesforce",
        cache: true,
      }],
    }),
    null,
  );
  await index.insert(
    makeObj({ id: "01SIBLING", namespace: "acme/sales", content: "sibling only fact" }),
    null,
  );
  await index.insert(
    makeObj({
      id: "01GRANTED",
      content: "restricted but export-granted",
      classification: classification({
        sensitivity: "restricted",
        allowedDestinations: ["agent-context", "export"],
      }),
    }),
    null,
  );
});

afterAll(async () => {
  await db.close();
});

describe("canExport (D28 gate, pure)", () => {
  it("denies member and agent roles before anything else", () => {
    for (const role of ["member", "agent"] as const) {
      const d = canExport(role, null, classification({ sensitivity: "public" }));
      expect(d.allowed).toBe(false);
      expect(d.reason).toBe("role");
    }
  });

  it("allows owner/admin/auditor for internal data", () => {
    for (const role of ["owner", "admin", "auditor"] as const) {
      expect(canExport(role, "manual", classification()).allowed).toBe(true);
    }
  });

  it("denies the live-fetch and unknown source buckets", () => {
    expect(canExport("admin", "live-fetch", classification()).reason).toBe("source");
    expect(canExport("admin", "unknown", classification()).reason).toBe("source");
  });

  it("denies restricted/confidential without an explicit export destination grant", () => {
    expect(
      canExport("owner", "manual", classification({ sensitivity: "restricted" })).reason,
    ).toBe("classification");
    expect(
      canExport("owner", "manual", classification({ sensitivity: "confidential" })).reason,
    ).toBe("classification");
    expect(
      canExport(
        "owner",
        "manual",
        classification({ sensitivity: "restricted", allowedDestinations: ["export"] }),
      ).allowed,
    ).toBe(true);
  });

  it("fails closed on residency-tagged data (egress region unknown)", () => {
    expect(
      canExport("owner", "manual", classification({ residency: "eu" })).reason,
    ).toBe("classification");
  });
});

describe("source + concept classification derivation", () => {
  it("prefers the latest connector sourceId over the source kind", () => {
    const obj = makeObj({
      id: "01SRC",
      provenance: [
        { source: "conversation", actor: "a", ts: "2026-07-01T00:00:00.000Z" },
        { source: "document", actor: "b", ts: "2026-07-01T00:00:00.000Z", sourceId: "fs:handbook" },
      ],
    });
    expect(exportSource(obj)).toBe("fs:handbook");
    expect(exportSource(makeObj({ id: "01SRC2" }))).toBe("manual");
    expect(exportSource(makeObj({ id: "01SRC3", provenance: [] }))).toBe("unknown");
  });

  it("labels a D14 cache fact live-fetch even when a connector sourceId is present", async () => {
    const ts = "2026-07-01T00:00:00.000Z";
    // The production l4WriteBack stamp: sourceId must never shadow the label.
    const cacheFact = makeObj({
      id: "01CACHE",
      provenance: [{
        source: "live-fetch", actor: "l4", ts,
        sourceId: "salesforce", connectorId: "salesforce", cache: true,
      }],
    });
    expect(exportSource(cacheFact)).toBe("live-fetch");
    expect(canExport("admin", exportSource(cacheFact), classification()).reason).toBe("source");
    // The robust cache stamp alone (label lost/rewritten) still denies.
    const stampOnly = makeObj({
      id: "01CACHE2",
      provenance: [
        { source: "document", actor: "l4", ts, sourceId: "salesforce", cache: true },
      ],
    });
    expect(exportSource(stampOnly)).toBe("live-fetch");
  });

  it("classifies a concept body with the existing DLP classifier", () => {
    expect(conceptClassification(publicConcept).sensitivity).toBe("internal");
    const leaked = conceptClassification(secretConcept);
    expect(leaked.sensitivity).toBe("restricted");
    expect(canExport("owner", CONCEPT_SOURCE, leaked).allowed).toBe(false);
  });
});

describe("memExport syscall", () => {
  it("E15+E17: renders only ACL-visible, gate-passing rows, and audits ok (E18)", async () => {
    const result = await memExport(deps, identity("admin"), { purpose: "backup" });

    // Included: internal fact, restricted-with-export-grant fact, public concept.
    expect(result.markdown).toContain("the sky is blue");
    expect(result.markdown).toContain("restricted but export-granted");
    expect(result.markdown).toContain("Refunds are granted within 30 days.");
    // Excluded before render: restricted row, live-fetch row, secret concept.
    expect(result.markdown).not.toContain("secret sauce recipe");
    expect(result.markdown).not.toContain("cached external row");
    expect(result.markdown).not.toContain("ghp_");
    // ACL: the sibling namespace is invisible, not merely excluded.
    expect(result.markdown).not.toContain("sibling only fact");

    expect(result.includedL2).toBe(2);
    expect(result.includedL3).toBe(1);
    expect(result.excluded.classification).toBe(2);
    expect(result.excluded.source).toBe(1);
    expect(result.filename).toBe(
      `halomem-export-acme-support-${new Date().toISOString().slice(0, 10)}.md`,
    );

    const portable = JSON.parse(result.portableJson) as {
      schema: string;
      export: {
        namespace: string;
        purpose: string | null;
        scope: null;
        memoryState: string;
      };
      l2: Array<MemoryObject & { source: string }>;
      l3: Array<Concept & {
        source: string;
        classification: DataClassification;
      }>;
      counts: { includedL2: number; includedL3: number };
      excludedByTier: {
        L2: { source: number; classification: number };
        L3: { source: number; classification: number };
      };
    };
    expect(portable.schema).toBe("halomem.memory-export/v1");
    expect(portable.export).toMatchObject({
      namespace: "acme/support",
      purpose: "backup",
      scope: null,
      memoryState: "active-current",
    });
    expect(portable.l2.map((row) => row.id).sort()).toEqual([
      "01EXPORTOK",
      "01GRANTED",
    ]);
    expect(portable.l2[0]).toMatchObject({
      namespace: "acme/support",
      tier: "L2",
      provenance: [{ source: "manual", actor: "tester" }],
    });
    expect(portable.l3).toEqual([
      expect.objectContaining({
        path: "concepts/refund-policy.md",
        visibility: "public",
        source: "consolidation",
        classification: expect.objectContaining({ sensitivity: "internal" }),
      }),
    ]);
    expect(portable.counts).toEqual({ includedL2: 2, includedL3: 1 });
    expect(portable.excludedByTier).toEqual({
      L2: { role: 0, source: 1, classification: 1 },
      L3: { role: 0, source: 0, classification: 1 },
    });
    expect(result.excludedByTier).toEqual(portable.excludedByTier);
    expect(result.portableFilename).toBe(
      `halomem-export-acme-support-${new Date().toISOString().slice(0, 10)}.json`,
    );
    expect(result.portableSha256).toBe(
      createHash("sha256").update(result.portableJson, "utf8").digest("hex"),
    );

    const rows = await exportAuditRows();
    const last = rows[rows.length - 1];
    expect(last.result).toBe("ok");
    const detail = JSON.parse(last.detail ?? "{}") as {
      includedL2: number;
      sha256: string;
      portableSha256: string;
      excluded: { source: number };
      excludedByTier: {
        L2: { source: number };
        L3: { classification: number };
      };
    };
    expect(detail.includedL2).toBe(2);
    expect(detail.sha256).toBe(result.sha256);
    expect(detail.portableSha256).toBe(result.portableSha256);
    expect(detail.excluded.source).toBe(1);
    expect(detail.excludedByTier.L2.source).toBe(1);
    expect(detail.excludedByTier.L3.classification).toBe(1);
    // Audit detail never carries content.
    expect(last.detail).not.toContain("sky is blue");
  });

  it("E16: a role-denied export writes an audit row and never reads or renders", async () => {
    const before = (await exportAuditRows()).length;
    const trackingDeps: ExporterDeps = {
      index: {
        listCandidates: async () => {
          throw new Error("must not read for a role-denied export");
        },
      },
      concepts: {
        listConcepts: async () => {
          throw new Error("must not read for a role-denied export");
        },
      },
      audit,
    };
    await expect(memExport(trackingDeps, identity("agent"))).rejects.toThrow(AuthzError);
    const rows = await exportAuditRows();
    expect(rows.length).toBe(before + 1);
    expect(rows[rows.length - 1].result).toBe("denied");
    expect(rows[rows.length - 1].detail).toContain("may not export");
  });

  it("audits miss for an empty namespace and denied when everything is excluded", async () => {
    const empty = await memExport(deps, identity("owner", "acme/empty-team"), {
      tiers: ["L2"],
    });
    expect(empty.includedL2).toBe(0);
    let rows = await exportAuditRows();
    // acme/empty-team still sees ancestor 'acme' rows? No 'acme' rows exist —
    // all fixtures live in acme/support or acme/sales, both invisible siblings.
    expect(rows[rows.length - 1].result).toBe("miss");

    const auditorOnly = await memExport(
      { ...deps, concepts: { listConcepts: async () => [secretConcept] } },
      identity("auditor", "acme/sales"),
      { tiers: ["L3"] },
    );
    expect(auditorOnly.includedL3).toBe(0);
    expect(auditorOnly.excluded.classification).toBe(1);
    rows = await exportAuditRows();
    expect(rows[rows.length - 1].result).toBe("denied");
  });

  it("audits error on an invalid tier and on a read failure (D4 error outcomes)", async () => {
    await expect(
      memExport(deps, identity("admin"), { tiers: ["L9" as unknown as "L2"] }),
    ).rejects.toThrow(/invalid tier/);
    let rows = await exportAuditRows();
    expect(rows[rows.length - 1].result).toBe("error");

    const failingDeps: ExporterDeps = {
      ...deps,
      index: {
        listCandidates: async () => {
          throw new Error("pg down");
        },
      },
    };
    await expect(memExport(failingDeps, identity("admin"))).rejects.toThrow("pg down");
    rows = await exportAuditRows();
    expect(rows[rows.length - 1].result).toBe("error");
    expect(rows[rows.length - 1].detail).toContain("export failed");
  });

  it("D9: namespace and actor on the audit row come from the identity only", async () => {
    await memExport(deps, identity("owner"), { tiers: ["L2"], limit: 1 });
    const rows = await exportAuditRows();
    const last = rows[rows.length - 1];
    expect(last.namespace).toBe("acme/support");
    expect(last.actor).toBe("alice");
  });

  it("a default export is COMPLETE - no silent row cap (regression: former 500 default)", async () => {
    const TOTAL = 505; // one past the former default cap
    for (let i = 0; i < TOTAL; i++) {
      await index.insert(
        makeObj({
          id: `01BIG${String(i).padStart(5, "0")}`,
          namespace: "acme/big",
        }),
        null,
      );
    }
    const full = await memExport(deps, identity("owner", "acme/big"), {
      tiers: ["L2"],
    });
    expect(full.includedL2).toBe(TOTAL);
    // ...and an explicit limit still bounds the export when asked for.
    const capped = await memExport(deps, identity("owner", "acme/big"), {
      tiers: ["L2"],
      limit: 7,
    });
    expect(capped.includedL2).toBe(7);
  });
});

describe("scoped export - team subtree", () => {
  const now = "2026-07-01T00:00:00.000Z";

  beforeAll(async () => {
    await index.insert(
      makeObj({
        id: "01TIERONE",
        namespace: "acme/support/tier1",
        content: "tier1 fact",
        provenance: [{ source: "manual", actor: "bob", ts: now }],
      }),
      null,
    );
    await index.insert(
      makeObj({ id: "01TIERTWO", namespace: "acme/support/tier2", content: "tier2 fact" }),
      null,
    );
  });

  it("team scope exports ONLY the target subtree - siblings and the caller's own view dropped", async () => {
    const result = await memExport(deps, identity("admin"), {
      scope: { kind: "team", namespace: "acme/support/tier1" },
    });
    expect(result.markdown).toContain("tier1 fact");
    expect(result.markdown).not.toContain("tier2 fact");
    expect(result.markdown).not.toContain("the sky is blue"); // caller-ns row, outside the target subtree
    expect(result.markdown).toContain("- Scope: team `acme/support/tier1`");
    expect(result.filename).toMatch(
      /^halomem-export-acme-support-team-acme-support-tier1-\d{4}-\d{2}-\d{2}\.md$/,
    );
    expect(result.includedL2).toBe(1);

    const portable = JSON.parse(result.portableJson) as {
      export: {
        scope: { kind: string; namespace: string };
        scopeMode: string;
      };
      l2: Array<MemoryObject & { source: string }>;
    };
    expect(portable.export.scope).toEqual({
      kind: "team",
      namespace: "acme/support/tier1",
    });
    expect(portable.export.scopeMode).toBe("team-owned-subtree");
    expect(portable.l2).toEqual([
      expect.objectContaining({
        id: "01TIERONE",
        namespace: "acme/support/tier1",
        content: "tier1 fact",
        source: "manual",
        provenance: [expect.objectContaining({ actor: "bob" })],
      }),
    ]);
    expect(result.portableJson).not.toContain("tier2 fact");
    expect(result.portableJson).not.toContain("the sky is blue");
  });

  it("team scope L3 keeps only concepts owned inside the subtree (public + inherited dropped)", async () => {
    const teamConcept: Concept = {
      path: "concepts/t1.md",
      type: "note",
      title: "Tier1 playbook",
      description: "",
      tags: [],
      namespace: "acme/support/tier1",
      body: "escalation ladder",
    };
    const orgConcept: Concept = {
      path: "concepts/org.md",
      type: "note",
      title: "Org handbook",
      description: "",
      tags: [],
      namespace: "acme",
      body: "org-wide",
    };
    const scopedDeps: ExporterDeps = {
      ...deps,
      concepts: {
        listConcepts: async (ns) => {
          expect(ns).toBe("acme/support/tier1");
          return [teamConcept, orgConcept, publicConcept];
        },
      },
    };
    const result = await memExport(scopedDeps, identity("admin"), {
      scope: { kind: "team", namespace: "acme/support/tier1" },
      tiers: ["L3"],
    });
    expect(result.markdown).toContain("Tier1 playbook");
    expect(result.markdown).not.toContain("Org handbook");
    expect(result.markdown).not.toContain("Refund policy");
    expect(result.includedL3).toBe(1);

    const portable = JSON.parse(result.portableJson) as {
      l3: Array<Concept & { source: string; classification: DataClassification }>;
    };
    expect(portable.l3).toEqual([
      expect.objectContaining({
        path: "concepts/t1.md",
        namespace: "acme/support/tier1",
        body: "escalation ladder",
        source: "consolidation",
        classification: expect.objectContaining({ sensitivity: "internal" }),
      }),
    ]);
    expect(result.portableJson).not.toContain("org-wide");
  });

  it("a scoped export's audit detail records the scope (identifiers only)", async () => {
    await memExport(deps, identity("admin"), {
      scope: { kind: "team", namespace: "acme/support/tier1" },
    });
    const rows = await exportAuditRows();
    const detail = JSON.parse(rows[rows.length - 1].detail ?? "{}") as {
      scope?: { kind: string; value: string };
    };
    expect(detail.scope).toEqual({ kind: "team", value: "acme/support/tier1" });
  });

  it("an unscoped export carries no scope line and no scope audit key (unchanged behaviour)", async () => {
    const result = await memExport(deps, identity("admin"), { tiers: ["L2"] });
    expect(result.markdown).not.toContain("- Scope:");
    const detail = JSON.parse((await exportAuditRows()).slice(-1)[0].detail ?? "{}") as {
      scope?: unknown;
    };
    expect(detail.scope).toBeUndefined();
  });
});

describe("scoped export - user (provenance actor)", () => {
  it("exports only facts the actor authored, inside the caller's downward subtree", async () => {
    const result = await memExport(deps, identity("admin"), {
      scope: { kind: "user", actor: "bob" },
    });
    expect(result.markdown).toContain("tier1 fact"); // bob-authored, in the caller's subtree
    expect(result.markdown).not.toContain("tier2 fact"); // tester-authored
    expect(result.markdown).not.toContain("the sky is blue"); // tester-authored (caller ns)
    expect(result.markdown).toContain("- Scope: authored by `bob`");
    expect(result.filename).toContain("-user-bob-");
    expect(result.includedL2).toBe(1);
  });

  it("never reaches upward: an ancestor row by the same actor is excluded", async () => {
    await index.insert(
      makeObj({
        id: "01BOBORG00",
        namespace: "acme",
        content: "bob org fact",
        provenance: [{ source: "manual", actor: "bob", ts: "2026-07-01T00:00:00.000Z" }],
      }),
      null,
    );
    const result = await memExport(deps, identity("admin"), {
      scope: { kind: "user", actor: "bob" },
    });
    expect(result.markdown).not.toContain("bob org fact");
  });

  it("defaults to the Facts tier and rejects an explicit L3 request (audited error)", async () => {
    const result = await memExport(deps, identity("admin"), {
      scope: { kind: "user", actor: "bob" },
    });
    expect(result.includedL3).toBe(0);
    const before = (await exportAuditRows()).length;
    await expect(
      memExport(deps, identity("admin"), {
        scope: { kind: "user", actor: "bob" },
        tiers: ["L2", "L3"],
      }),
    ).rejects.toThrow(/knowledge/i);
    const rows = await exportAuditRows();
    expect(rows.length).toBe(before + 1);
    expect(rows[rows.length - 1].result).toBe("error");
  });
});

describe("scoped export - gate (E15/E16)", () => {
  it("denies a team scope outside the caller's subtree, audited, before any read", async () => {
    const before = (await exportAuditRows()).length;
    const noReadDeps: ExporterDeps = {
      index: {
        listCandidates: async () => {
          throw new Error("must not read for a scope-denied export");
        },
      },
      concepts: {
        listConcepts: async () => {
          throw new Error("must not read for a scope-denied export");
        },
      },
      audit,
    };
    await expect(
      memExport(noReadDeps, identity("admin"), {
        scope: { kind: "team", namespace: "acme/billing" },
      }),
    ).rejects.toThrow(AuthzError);
    const rows = await exportAuditRows();
    expect(rows.length).toBe(before + 1);
    expect(rows[rows.length - 1].result).toBe("denied");
    expect(rows[rows.length - 1].detail).toContain("outside");
  });

  it("denies an ancestor team scope (upward is not in the caller's subtree)", async () => {
    await expect(
      memExport(deps, identity("admin"), { scope: { kind: "team", namespace: "acme" } }),
    ).rejects.toThrow(AuthzError);
  });

  it("A1: a '' root caller without a server-resolved readScope is denied scoped export", async () => {
    await expect(
      memExport(deps, identity("owner", ""), { scope: { kind: "user", actor: "bob" } }),
    ).rejects.toThrow(AuthzError);
    const rows = await exportAuditRows();
    expect(rows[rows.length - 1].result).toBe("denied");
  });

  it("A1: a '' root caller may not target a team inside an excluded tenant prefix", async () => {
    const rootDeps: ExporterDeps = {
      ...deps,
      readScope: { exact: [], prefixes: [""], excludePrefixes: ["hostedco"] },
    };
    await expect(
      memExport(rootDeps, identity("owner", ""), {
        scope: { kind: "team", namespace: "hostedco/ops" },
      }),
    ).rejects.toThrow(AuthzError);
    const rows = await exportAuditRows();
    expect(rows[rows.length - 1].result).toBe("denied");
  });
});
