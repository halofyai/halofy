/**
 * Module D tests — ContextAllocator + FaultHandler.
 *
 * Hermetic: all collaborators are hand-rolled in-memory stubs satisfying the
 * structural ports; the embedder is a deterministic hash embedder. No DB, no
 * network.
 */

import { describe, expect, it } from "vitest";
import { ContextAllocator } from "../src/allocator/index.js";
import { FaultHandler, L2_SCORE_FLOOR } from "../src/fault/index.js";
import { cosineSim } from "../src/fault/scoring.js";
import type {
  AuditPort,
  L2IndexPort,
  L2ListOpts,
  L2MemoryLike,
  VectorHitLike,
} from "../src/fault/scoring.js";
import { estimateTokens } from "../src/types.js";
import type {
  AuditEvent,
  Concept,
  Embedder,
  Namespace,
  PolicyConfig,
  ScoredRef,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Deterministic stubs
// ---------------------------------------------------------------------------

/** HashEmbedder-style: bag-of-words hashed into a fixed-dim unit vector. */
class TestEmbedder implements Embedder {
  readonly name = "test-hash";
  readonly dim = 64;

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((text) => {
      const v = new Array<number>(this.dim).fill(0);
      const words = text
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter((w) => w.length > 0);
      for (const w of words) {
        let h = 0;
        for (let i = 0; i < w.length; i++) {
          h = (h * 31 + w.charCodeAt(i)) >>> 0;
        }
        v[h % this.dim] += 1;
      }
      const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1;
      return v.map((x) => x / norm);
    });
  }
}

const EMBEDDER = new TestEmbedder();

class StubIndex implements L2IndexPort {
  accessBumps: string[][] = [];
  faultBumps: string[] = [];
  vectorSearchCalls = 0;

  constructor(public rows: L2MemoryLike[]) {}

  async listCandidates(
    _ns: Namespace,
    opts: L2ListOpts = {},
  ): Promise<L2MemoryLike[]> {
    let out = this.rows;
    if (opts.validOnly !== false) {
      const now = Date.now();
      out = out.filter(
        (r) => r.tValidTo === null || Date.parse(r.tValidTo) > now,
      );
    }
    return out.slice(0, opts.limit ?? out.length);
  }

  async vectorSearch(
    _ns: Namespace,
    embedding: number[],
    k: number,
    _validOnly?: boolean,
  ): Promise<VectorHitLike[]> {
    this.vectorSearchCalls++;
    const vecs = await EMBEDDER.embed(this.rows.map((r) => r.content));
    const hits = this.rows.map((obj, i) => ({
      obj,
      similarity: cosineSim(embedding, vecs[i]),
    }));
    hits.sort((a, b) => b.similarity - a.similarity);
    return hits.slice(0, k);
  }

  async bumpAccess(ids: string[]): Promise<void> {
    this.accessBumps.push(ids);
  }

  async bumpFault(id: string): Promise<void> {
    this.faultBumps.push(id);
  }
}

class StubAudit implements AuditPort {
  events: AuditEvent[] = [];
  async append(e: AuditEvent): Promise<void> {
    this.events.push(e);
  }
}

class StubCold {
  searchCalls: string[] = [];
  searchNamespaces: Namespace[] = [];
  readNamespaces: Namespace[] = [];
  constructor(
    private concepts: Map<string, Concept>,
    private conceptHits: ScoredRef[] = [],
    private searchError: Error | null = null,
  ) {}

  async readConcept(namespace: Namespace, path: string): Promise<Concept | null> {
    this.readNamespaces.push(namespace);
    if (path.includes("..")) throw new Error("concept path escapes knowledge directory");
    return this.concepts.get(path) ?? null;
  }

  async searchConcepts(
    _db: null,
    _embedder: Embedder,
    namespace: Namespace,
    query: string,
    _k: number,
  ): Promise<ScoredRef[]> {
    this.searchCalls.push(query);
    this.searchNamespaces.push(namespace);
    if (this.searchError) throw this.searchError;
    return this.conceptHits;
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NS = "acme/support/agent-7";

const REFUND_CONCEPT: Concept = {
  path: "concepts/refund-policy.md",
  type: "policy",
  title: "Refund policy",
  description: "How refunds work",
  tags: ["policy"],
  body: "Refunds are allowed within 30 days.",
  visibility: "public",
};

function policy(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    namespace: NS,
    tokenBudget: 100,
    ttlDefaultsSeconds: { user: null, assistant: null, team: null, org: null },
    pinnedConcepts: [],
    dedupeSimilarityThreshold: 0.92,
    verifierEnabled: true,
    ...overrides,
  };
}

function row(
  id: string,
  content: string,
  extra: {
    tValidTo?: string | null;
    lastAccessed?: string | null;
    accessCount?: number;
  } = {},
): L2MemoryLike {
  return {
    id,
    content,
    scope: "user",
    tValidTo: extra.tValidTo ?? null,
    telemetry: {
      lastAccessed: extra.lastAccessed ?? null,
      accessCount: extra.accessCount ?? 0,
    },
  };
}

const PIN_TOKENS = estimateTokens(
  `${REFUND_CONCEPT.title}\n\n${REFUND_CONCEPT.body}`,
);

function makeAllocator(rows: L2MemoryLike[]) {
  const index = new StubIndex(rows);
  const audit = new StubAudit();
  const cold = new StubCold(new Map([[REFUND_CONCEPT.path, REFUND_CONCEPT]]));
  const allocator = new ContextAllocator({
    index,
    cold,
    audit,
    embedder: EMBEDDER,
  });
  return { allocator, index, audit, cold };
}

const SCOPE_ROWS: L2MemoryLike[] = [
  row("m1", "alpha memory content one", {
    lastAccessed: "2026-07-06T10:00:00Z",
    accessCount: 5,
  }),
  row("m2", "beta memory content two", {
    lastAccessed: "2026-07-05T10:00:00Z",
    accessCount: 3,
  }),
  // never accessed — should only enter via predicted-relevant lane
  row("m3", "database migration checklist steps"),
];

// ---------------------------------------------------------------------------
// ContextAllocator
// ---------------------------------------------------------------------------

describe("ContextAllocator.assemble", () => {
  it("assembles pinned, scope and predicted blocks in priority order under budget", async () => {
    const { allocator, audit, cold } = makeAllocator(SCOPE_ROWS);
    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({
        pinnedConcepts: [REFUND_CONCEPT.path],
        tokenBudget: 100,
      }),
      taskHint: "database migration checklist",
    });

    const kinds = ws.blocks.map((b) => b.kind);
    expect(kinds[0]).toBe("pinned-concept");
    expect(cold.readNamespaces).toContain(NS);
    expect(ws.blocks[0].ref).toBe(REFUND_CONCEPT.path);

    const scopeRefs = ws.blocks
      .filter((b) => b.kind === "scope-memory")
      .map((b) => b.ref);
    expect(scopeRefs).toEqual(["m1", "m2"]); // m3 never accessed

    const relRefs = ws.blocks
      .filter((b) => b.kind === "predicted-relevant")
      .map((b) => b.ref);
    expect(relRefs).toContain("m3");

    // no duplicate refs across lanes (dedupe)
    const refs = ws.blocks.map((b) => b.ref);
    expect(new Set(refs).size).toBe(refs.length);

    // budget respected, totals consistent
    expect(ws.totalTokens).toBeLessThanOrEqual(ws.budget);
    expect(ws.totalTokens).toBe(
      ws.blocks.reduce((s, b) => s + b.tokenEstimate, 0),
    );

    // audit row
    const ev = audit.events.at(-1)!;
    expect(ev.op).toBe("assemble");
    expect(ev.result).toBe("ok");
    expect(ev.namespace).toBe(NS);
    expect(ev.detail).toContain(`blocks=${ws.blocks.length}`);
    expect(ev.detail).toContain(`tokens=${ws.totalTokens}`);
  });

  it("packs greedily: skips blocks that do not fit, never splits", async () => {
    const { allocator } = makeAllocator(SCOPE_ROWS);
    // budget fits only the pinned concept (14 tokens); scope rows (6 each) overflow
    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({
        pinnedConcepts: [REFUND_CONCEPT.path],
        tokenBudget: PIN_TOKENS + 3,
      }),
    });
    expect(ws.blocks.map((b) => b.kind)).toEqual(["pinned-concept"]);
    expect(ws.totalTokens).toBe(PIN_TOKENS);
    expect(ws.totalTokens).toBeLessThanOrEqual(ws.budget);
  });

  it("skips an oversized pinned block but still packs later smaller blocks", async () => {
    const { allocator } = makeAllocator(SCOPE_ROWS);
    // budget too small for the pin (14) but fits one scope row (6)
    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({
        pinnedConcepts: [REFUND_CONCEPT.path],
        tokenBudget: 8,
      }),
    });
    expect(ws.blocks.map((b) => b.ref)).toEqual(["m1"]);
    expect(ws.totalTokens).toBeLessThanOrEqual(8);
  });

  it("returns blocks in stable orderKey order, identical across runs", async () => {
    const { allocator } = makeAllocator(SCOPE_ROWS);
    const args = {
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({ pinnedConcepts: [REFUND_CONCEPT.path] }),
      taskHint: "database migration checklist",
    };
    const a = await allocator.assemble(args);
    const b = await allocator.assemble(args);

    const keys = a.blocks.map((x) => x.orderKey);
    expect([...keys].sort()).toEqual(keys); // sorted by orderKey
    expect(b.blocks).toEqual(a.blocks); // stable across runs
  });

  it("ignores missing pinned concepts and expired memories", async () => {
    const rows = [
      ...SCOPE_ROWS,
      row("m4", "expired but recently accessed", {
        tValidTo: "2020-01-01T00:00:00Z",
        lastAccessed: "2026-07-07T00:00:00Z",
        accessCount: 99,
      }),
    ];
    const { allocator } = makeAllocator(rows);
    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({ pinnedConcepts: ["concepts/does-not-exist.md"] }),
    });
    const refs = ws.blocks.map((b) => b.ref);
    expect(refs).not.toContain("concepts/does-not-exist.md");
    expect(refs).not.toContain("m4");
    expect(ws.blocks.every((b) => b.kind === "scope-memory")).toBe(true);
  });

  it("brownouts a rejected pinned path instead of failing the working set", async () => {
    const { allocator } = makeAllocator(SCOPE_ROWS);
    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy({ pinnedConcepts: ["../outside.md"] }),
    });
    expect(ws.blocks.some((b) => b.kind === "pinned-concept")).toBe(false);
    expect(ws.blocks.some((b) => b.kind === "scope-memory")).toBe(true);
  });

  it("brownouts predicted relevance to BM25 when embeddings are unavailable", async () => {
    const index = new StubIndex(SCOPE_ROWS);
    const audit = new StubAudit();
    const allocator = new ContextAllocator({
      index,
      cold: new StubCold(new Map()),
      audit,
      embedder: {
        name: "dead",
        dim: 2,
        embed: async () => {
          throw new Error("embedding provider unavailable");
        },
      },
    });

    const ws = await allocator.assemble({
      namespace: NS,
      actor: "user:kay",
      agentId: "agent-7",
      policy: policy(),
      taskHint: "database migration checklist",
    });

    expect(ws.blocks.some((b) => b.ref === "m3" && b.kind === "predicted-relevant")).toBe(true);
    expect(audit.events.at(-1)?.detail).toContain("brownout=embedding_unavailable");
  });
});

// ---------------------------------------------------------------------------
// FaultHandler
// ---------------------------------------------------------------------------

const FAULT_ROWS: L2MemoryLike[] = [
  row("r1", "customer refund escalation procedure for support tickets", {
    accessCount: 2,
  }),
  row("r2", "weekly standup meeting notes for the platform team", {
    accessCount: 1,
  }),
];

const L3_HIT: ScoredRef = {
  id: null,
  tier: "L3",
  ref: "concepts/flux.md",
  score: 0.8,
  content: "Flux capacitor calibration guide",
  tokenEstimate: estimateTokens("Flux capacitor calibration guide"),
};

function makeFaultHandler(
  rows: L2MemoryLike[],
  conceptHits: ScoredRef[] = [],
  coldError: Error | null = null,
) {
  const index = new StubIndex(rows);
  const audit = new StubAudit();
  const cold = new StubCold(new Map(), conceptHits, coldError);
  const handler = new FaultHandler<null>({
    db: null,
    index,
    cold,
    audit,
    embedder: EMBEDDER,
  });
  return { handler, index, audit, cold };
}

const CALLER = { namespace: NS, actor: "user:kay", agentId: "agent-7" };

describe("FaultHandler.fault", () => {
  it("serves from L2 when the hybrid match is strong; bumps access; audits ok", async () => {
    const { handler, index, audit, cold } = makeFaultHandler(FAULT_ROWS);
    const res = await handler.fault({
      ...CALLER,
      query: "refund escalation procedure",
    });

    expect(res.hit).toBe(true);
    expect(res.source).toBe("L2");
    expect(res.injected.length).toBeGreaterThan(0);
    expect(res.injected[0].ref).toBe("r1");
    expect(res.injected[0].tier).toBe("L2");
    expect(res.injected[0].score).toBeGreaterThanOrEqual(L2_SCORE_FLOOR);
    expect(res.latencyMs).toBeGreaterThanOrEqual(0);
    expect(index.vectorSearchCalls).toBeGreaterThan(0);

    // telemetry: access bumped on injected ids, no fault pressure, no L3 call
    expect(index.accessBumps.length).toBe(1);
    expect(index.accessBumps[0]).toContain("r1");
    expect(index.faultBumps).toEqual([]);
    expect(cold.searchCalls).toEqual([]);

    const ev = audit.events.at(-1)!;
    expect(ev.op).toBe("fault");
    expect(ev.result).toBe("ok");
    expect(ev.detail).toContain("source=L2");
  });

  it("brownouts immediately to BM25 when embeddings fail before the breaker opens", async () => {
    const index = new StubIndex(FAULT_ROWS);
    const audit = new StubAudit();
    const handler = new FaultHandler<null>({
      db: null,
      index,
      cold: new StubCold(new Map(), []),
      audit,
      embedder: {
        name: "dead",
        dim: 2,
        embed: async () => {
          throw new Error("embedding provider unavailable");
        },
      },
    });

    const res = await handler.fault({
      ...CALLER,
      query: "refund escalation procedure",
    });

    expect(res.hit).toBe(true);
    expect(res.source).toBe("L2");
    expect(res.degradedReason).toBe("embedding_unavailable");
    expect(res.injected[0]?.ref).toBe("r1");
    expect(audit.events.at(-1)?.detail).toContain("brownout=embedding_unavailable");
  });

  it("falls back to L3 on weak L2 match; bumps fault on best L2 id", async () => {
    const { handler, index, audit, cold } = makeFaultHandler(FAULT_ROWS, [
      L3_HIT,
    ]);
    const res = await handler.fault({
      ...CALLER,
      query: "quantum flux capacitor calibration",
    });

    expect(res.hit).toBe(true);
    expect(res.source).toBe("L3");
    expect(cold.searchNamespaces).toContain(CALLER.namespace);
    expect(res.injected).toEqual([L3_HIT]);
    expect(cold.searchCalls).toEqual(["quantum flux capacitor calibration"]);

    // fault pressure on the single best (but insufficient) L2 memory
    expect(index.faultBumps.length).toBe(1);
    expect(["r1", "r2"]).toContain(index.faultBumps[0]);
    expect(index.accessBumps).toEqual([]);

    const ev = audit.events.at(-1)!;
    expect(ev.op).toBe("fault");
    expect(ev.result).toBe("ok");
    expect(ev.detail).toContain("source=L3");
  });

  it("reports a miss when neither tier clears the floor; audits miss", async () => {
    const { handler, index, audit } = makeFaultHandler(FAULT_ROWS, []);
    const res = await handler.fault({
      ...CALLER,
      query: "quantum flux capacitor calibration",
    });

    expect(res.hit).toBe(false);
    expect(res.source).toBeNull();
    expect(res.injected).toEqual([]);
    expect(res.latencyMs).toBeGreaterThanOrEqual(0);
    expect(index.faultBumps.length).toBe(1);

    const ev = audit.events.at(-1)!;
    expect(ev.op).toBe("fault");
    expect(ev.result).toBe("miss");
    expect(ev.detail).toContain("source=none");
  });

  it("brownouts to an explicit safe miss when the cold tier is unavailable", async () => {
    const { handler, index, audit } = makeFaultHandler(
      FAULT_ROWS,
      [],
      new Error("cold backend unavailable"),
    );
    const res = await handler.fault({
      ...CALLER,
      query: "quantum flux capacitor calibration",
    });

    expect(res).toMatchObject({
      hit: false,
      source: null,
      injected: [],
      degradedReason: "cold_unavailable",
    });
    expect(index.faultBumps.length).toBe(1);
    const ev = audit.events.at(-1)!;
    expect(ev.result).toBe("miss");
    expect(ev.detail).toContain("brownout=cold_unavailable");
  });

  it("misses cleanly on an empty index without telemetry writes", async () => {
    const { handler, index } = makeFaultHandler([], []);
    const res = await handler.fault({ ...CALLER, query: "anything at all" });

    expect(res.hit).toBe(false);
    expect(res.source).toBeNull();
    expect(res.injected).toEqual([]);
    expect(index.faultBumps).toEqual([]);
    expect(index.accessBumps).toEqual([]);
  });

  it("packs injected refs to the token budget, never splitting", async () => {
    const rows = [
      row("r1", "customer refund escalation procedure for support tickets"), // 14 tokens
      row("r3", "refund escalation steps"), // 6 tokens
    ];
    const { handler } = makeFaultHandler(rows);
    const res = await handler.fault({
      ...CALLER,
      query: "refund escalation procedure",
      tokenBudget: 10,
    });

    expect(res.hit).toBe(true);
    expect(res.source).toBe("L2");
    const total = res.injected.reduce((s, r) => s + r.tokenEstimate, 0);
    expect(total).toBeLessThanOrEqual(10);
    expect(res.injected.map((r) => r.ref)).toEqual(["r3"]);
  });

  it("driver-lane acceptance computes BM25 IDF over the full candidate pool (M1 parity), not just the returned refs", async () => {
    // Lexical-dominant match: the query term is RARE in the namespace
    // (2/30 docs) but present in every ref the driver returns. With IDF
    // computed over only the <=k returned refs (df == n), idf collapses to
    // ln(1.2) and the fault silently degrades to a miss; over the full
    // ~200-row pool (M1 lane) idf is ln(12.4) and the same fault clears
    // L2_SCORE_FLOOR.
    const QUERY = "zanzibar";
    const zdocs = [
      row("z1", "zanzibar shipment delayed weather"),
      row("z2", "zanzibar customs paperwork backlog"),
    ];
    const fillers = Array.from({ length: 28 }, (_, i) =>
      row(`f${i}`, `filler document number ${i}`),
    );
    const rows = [...zdocs, ...fillers];

    // Pin the vector term of the blend: cosine(query, any content) = 0.3
    // → 0.6·0.3 = 0.18. Acceptance then hinges entirely on the BM25 lane:
    //   ref-only IDF:  0.18 + 0.4·sat(ln 1.2)  ≈ 0.223  < 0.35  (old: miss)
    //   pool IDF:      0.18 + 0.4·sat(ln 12.4) ≈ 0.431  >= 0.35 (fixed: hit)
    const fixedCosine: Embedder = {
      name: "fixed-cos",
      dim: 2,
      embed: async (texts) =>
        texts.map((t) => (t === QUERY ? [1, 0] : [0.3, Math.sqrt(1 - 0.09)])),
    };

    const index = new StubIndex(rows);
    const audit = new StubAudit();
    const cold = new StubCold(new Map(), []);
    const planned: ScoredRef[] = zdocs.map((d, i) => ({
      id: d.id,
      tier: "L2",
      ref: d.id,
      score: 1 - i * 0.1, // driver scores are per-query normalized
      content: d.content,
      tokenEstimate: estimateTokens(d.content),
    }));
    const handler = new FaultHandler<null>({
      db: null,
      index,
      cold,
      audit,
      embedder: fixedCosine,
      l2Planner: async () => ({ refs: planned, driver: "baseline" }),
    });

    const res = await handler.fault({ ...CALLER, query: QUERY });

    expect(res.hit).toBe(true);
    expect(res.source).toBe("L2");
    expect(res.injected.map((r) => r.ref)).toEqual(["z1", "z2"]);
    expect(index.faultBumps).toEqual([]); // no phantom fault pressure
    expect(index.accessBumps[0]).toEqual(["z1", "z2"]);
    const ev = audit.events.at(-1)!;
    expect(ev.result).toBe("ok");
    expect(ev.detail).toContain("driver=baseline");
  });

  it("respects k for injected L2 hits", async () => {
    const rows = [
      row("r1", "refund escalation procedure alpha"),
      row("r2", "refund escalation procedure beta"),
      row("r3", "refund escalation procedure gamma"),
    ];
    const { handler } = makeFaultHandler(rows);
    const res = await handler.fault({
      ...CALLER,
      query: "refund escalation procedure",
      k: 2,
      tokenBudget: 5000,
    });
    expect(res.source).toBe("L2");
    expect(res.injected.length).toBe(2);
  });
});
