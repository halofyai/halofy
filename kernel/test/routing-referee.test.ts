/**
 * Module E (M2) tests — routing + referee. Hermetic: in-memory PGlite with
 * the vector extension, HashEmbedder, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";

import {
  pickDriver,
  pickDriverName,
  fnv1a32,
  DEFAULT_RETRIEVER,
  type DriverRegistryLike,
  type RoutingPolicy,
} from "../src/routing/index.js";
import {
  runScorecard,
  renderScorecardMarkdown,
  buildQuestions,
  percentile,
  rankDrivers,
  type DriverScore,
  type Scorecard,
} from "../src/referee/index.js";
import { parsePolicyYaml, PolicyStore } from "../src/policy/store.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { HashEmbedder, tokenize } from "../src/embed/index.js";
import { bm25Rank, hybridMerge } from "../src/retrieval/index.js";
import {
  estimateTokens,
  type RetrieverDriver,
  type RetrieverQuery,
  type ScopedView,
  type ScoredRef,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mkDriver(name: string): RetrieverDriver {
  return {
    name,
    capabilities: () => ({ graph: false, streaming: false }),
    plan: async () => [],
  };
}

/** Registry double implementing module A's fallback contract. */
function mkRegistry(...drivers: RetrieverDriver[]): DriverRegistryLike {
  const byName = new Map(drivers.map((d) => [d.name, d]));
  const baseline = byName.get("baseline") ?? mkDriver("baseline");
  return { get: (name: string) => byName.get(name) ?? baseline };
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

describe("pickDriver / pickDriverName", () => {
  const baseline = mkDriver("baseline");
  const a = mkDriver("alpha");
  const b = mkDriver("beta");
  const registry = mkRegistry(baseline, a, b);

  it("defaults to 'baseline' with an empty policy", () => {
    expect(pickDriverName({}, "any query")).toBe(DEFAULT_RETRIEVER);
    expect(pickDriver(registry, {}, "any query")).toBe(baseline);
  });

  it("uses the policy retriever when no abTest is present", () => {
    expect(pickDriverName({ retriever: "alpha" }, "q")).toBe("alpha");
    expect(pickDriver(registry, { retriever: "alpha" }, "q")).toBe(a);
  });

  it("unknown retriever names resolve through the registry fallback", () => {
    expect(pickDriver(registry, { retriever: "does-not-exist" }, "q")).toBe(baseline);
  });

  it("abTest overrides the fixed retriever field", () => {
    const policy: RoutingPolicy = {
      retriever: "alpha",
      abTest: { a: "alpha", b: "beta", pctB: 100 },
    };
    expect(pickDriverName(policy, "whatever")).toBe("beta");
  });

  it("is deterministic: the same query always routes to the same arm", () => {
    const policy: RoutingPolicy = { abTest: { a: "alpha", b: "beta", pctB: 50 } };
    for (const query of ["refund policy", "who owns the oslo lease", "q3 numbers"]) {
      const first = pickDriverName(policy, query);
      for (let i = 0; i < 50; i++) {
        expect(pickDriverName(policy, query)).toBe(first);
        expect(pickDriver(registry, policy, query).name).toBe(first);
      }
    }
  });

  it("pctB 0 → always a; pctB 100 → always b", () => {
    for (let i = 0; i < 100; i++) {
      const q = `query number ${i}`;
      expect(pickDriverName({ abTest: { a: "alpha", b: "beta", pctB: 0 } }, q)).toBe("alpha");
      expect(pickDriverName({ abTest: { a: "alpha", b: "beta", pctB: 100 } }, q)).toBe("beta");
    }
  });

  it("routes roughly pctB% of 200 distinct queries to arm b (±10pp)", () => {
    const pctB = 30;
    const policy: RoutingPolicy = { abTest: { a: "alpha", b: "beta", pctB } };
    let bCount = 0;
    for (let i = 0; i < 200; i++) {
      if (pickDriverName(policy, `distinct query number ${i} about topic ${i * 7}`) === "beta") {
        bCount++;
      }
    }
    const pct = (bCount / 200) * 100;
    expect(pct).toBeGreaterThanOrEqual(pctB - 10);
    expect(pct).toBeLessThanOrEqual(pctB + 10);
  });

  it("fnv1a32 is stable and 32-bit", () => {
    expect(fnv1a32("")).toBe(0x811c9dc5);
    expect(fnv1a32("abc")).toBe(fnv1a32("abc"));
    expect(fnv1a32("abc")).not.toBe(fnv1a32("abd"));
    expect(fnv1a32("anything")).toBeGreaterThanOrEqual(0);
    expect(fnv1a32("anything")).toBeLessThanOrEqual(0xffffffff);
  });
});

// ---------------------------------------------------------------------------
// Policy schema extension (retriever + abTest)
// ---------------------------------------------------------------------------

describe("policy YAML schema: retriever + abTest", () => {
  it("accepts retriever and a well-formed abTest", () => {
    const parsed = parsePolicyYaml(
      "org",
      ["retriever: graph", "abTest:", "  a: baseline", "  b: graph", "  pctB: 25"].join("\n"),
    );
    expect(parsed.retriever).toBe("graph");
    expect(parsed.abTest).toEqual({ a: "baseline", b: "graph", pctB: 25 });
  });

  it("accepts pctB boundary values 0 and 100", () => {
    for (const pctB of [0, 100]) {
      const parsed = parsePolicyYaml(
        "org",
        `abTest:\n  a: baseline\n  b: graph\n  pctB: ${pctB}`,
      );
      expect(parsed.abTest?.pctB).toBe(pctB);
    }
  });

  it("rejects out-of-range, non-integer, and incomplete abTest", () => {
    expect(() =>
      parsePolicyYaml("org", "abTest:\n  a: baseline\n  b: graph\n  pctB: 150"),
    ).toThrow(/abTest\.pctB/);
    expect(() =>
      parsePolicyYaml("org", "abTest:\n  a: baseline\n  b: graph\n  pctB: -5"),
    ).toThrow(/abTest\.pctB/);
    expect(() =>
      parsePolicyYaml("org", "abTest:\n  a: baseline\n  b: graph\n  pctB: 25.5"),
    ).toThrow(/abTest\.pctB/);
    expect(() =>
      parsePolicyYaml("org", "abTest:\n  a: baseline\n  pctB: 25"),
    ).toThrow(/abTest/);
    expect(() =>
      parsePolicyYaml("org", "abTest:\n  a: ''\n  b: graph\n  pctB: 25"),
    ).toThrow(/abTest\.a/);
  });

  it("rejects unknown keys inside abTest and non-mapping abTest", () => {
    expect(() =>
      parsePolicyYaml(
        "org",
        "abTest:\n  a: baseline\n  b: graph\n  pctB: 25\n  extra: nope",
      ),
    ).toThrow(/abTest/);
    expect(() => parsePolicyYaml("org", "abTest: fifty-fifty")).toThrow(/abTest/);
  });
});

// ---------------------------------------------------------------------------
// PGlite-backed suite: PolicyStore round-trip, migration 004, scorecard
// ---------------------------------------------------------------------------

const NS = "org/team";
const SIBLING_NS = "org/other";

const FACTS: { id: string; content: string }[] = [
  { id: "F01", content: "Zephyr Logistics signed the Oslo warehouse lease in March" },
  { id: "F02", content: "The quarterly churn dashboard tracks enterprise renewals weekly" },
  { id: "F03", content: "Priya approved the vendor contract with Meridian Robotics" },
  { id: "F04", content: "Refund requests above five hundred dollars require director signoff" },
  { id: "F05", content: "The Lisbon datacenter migration finishes before the audit window" },
  { id: "F06", content: "Kubernetes upgrade to version twenty nine is scheduled Thursday" },
  { id: "F07", content: "Marketing localized the onboarding emails into Portuguese and Danish" },
  { id: "F08", content: "The fraud model retrains nightly on anonymized transaction batches" },
  { id: "F09", content: "Support escalations route to the Krakow desk after midnight" },
  { id: "F10", content: "The design system deprecated the legacy button component library" },
  { id: "F11", content: "Sales pipeline reviews moved from Mondays to Wednesday mornings" },
  { id: "F12", content: "The compliance team archived the expired certificates in the vault" },
  { id: "F13", content: "Engineering froze deployments during the investor demo rehearsal" },
  { id: "F14", content: "The mobile release train ships biweekly from the develop branch" },
  { id: "F15", content: "Procurement negotiated bulk pricing for ergonomic standing desks" },
];

describe("PGlite-backed: schema round-trip + scorecard", () => {
  let db: Db;
  let view: ScopedView;
  const embedder = new HashEmbedder();

  /** Baseline-shaped driver over the view only (hybrid vector + BM25). */
  const baselineDriver: RetrieverDriver = {
    name: "baseline",
    capabilities: () => ({ graph: false, streaming: false }),
    async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
      const laneK = Math.max(q.k * 2, 10);
      const [emb] = await q.view.embed([q.query]);
      const [vec, cands] = await Promise.all([
        q.view.vectorSearch(emb, laneK),
        q.view.candidates(200),
      ]);
      const bm = bm25Rank(q.query, cands, laneK);
      const contentByRef = new Map(cands.map((c) => [c.ref, c.content]));
      const merged = hybridMerge(vec, bm, contentByRef, q.k, "L2");
      const out: ScoredRef[] = [];
      let total = 0;
      for (const hit of merged) {
        if (out.length > 0 && total + hit.tokenEstimate > q.tokenBudget) break;
        out.push(hit);
        total += hit.tokenEstimate;
      }
      return out;
    },
  };

  /** Stub that always finds the planted fact (max query-token overlap), k=1. */
  const perfectDriver: RetrieverDriver = {
    name: "stub-perfect",
    capabilities: () => ({ graph: false, streaming: false }),
    async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
      const queryTokens = new Set(tokenize(q.query));
      const cands = await q.view.candidates(200);
      let best: { ref: string; content: string } | null = null;
      let bestOverlap = -1;
      for (const c of cands) {
        const toks = new Set(tokenize(c.content));
        let overlap = 0;
        for (const t of queryTokens) if (toks.has(t)) overlap++;
        if (overlap > bestOverlap) {
          bestOverlap = overlap;
          best = c;
        }
      }
      if (!best) return [];
      return [
        {
          id: best.ref,
          tier: "L2",
          ref: best.ref,
          score: 1,
          content: best.content,
          tokenEstimate: estimateTokens(best.content),
        },
      ];
    },
  };

  /** Deliberately broken driver — referee must score it, not crash. */
  const brokenDriver: RetrieverDriver = {
    name: "stub-broken",
    capabilities: () => ({ graph: false, streaming: false }),
    plan: async () => {
      throw new Error("boom");
    },
  };

  beforeAll(async () => {
    const config = loadConfig({
      databaseUrl: "",
      pgliteDataDir: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    db = await createDb(config);
    await migrate(db, 256);

    const now = new Date().toISOString();
    const embeddings = await embedder.embed(FACTS.map((f) => f.content));
    for (let i = 0; i < FACTS.length; i++) {
      await db.query(
        `INSERT INTO memory_objects
           (id, namespace, scope, tier, backend_ref, content, type, confidence,
            assertion_time, t_valid_from, status, embedding)
         VALUES ($1, $2, 'team', 'L2', 'inline', $3, 'fact', 1,
                 $4, $4, 'active', $5::vector)`,
        [FACTS[i].id, NS, FACTS[i].content, now, `[${embeddings[i].join(",")}]`],
      );
    }
    // Canary row in a sibling namespace — must never surface via the view.
    const [canaryEmb] = await embedder.embed(["canary secret sibling payroll numbers"]);
    await db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          assertion_time, t_valid_from, status, embedding)
       VALUES ('CANARY', $1, 'team', 'L2', 'inline',
               'canary secret sibling payroll numbers', 'fact', 1, $2, $2,
               'active', $3::vector)`,
      [SIBLING_NS, now, `[${canaryEmb.join(",")}]`],
    );

    // Test ScopedView over the PGlite corpus, ACL-fixed to NS. (Module A's
    // buildScopedView is the production constructor; this double exists so
    // the referee test is hermetic and independent of module A's build.)
    view = {
      namespace: NS,
      async candidates(limit = 200) {
        const res = await db.query(
          `SELECT id, content FROM memory_objects
            WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL
            ORDER BY id LIMIT $2`,
          [NS, limit],
        );
        return res.rows.map((r: { id: string; content: string }) => ({
          ref: r.id,
          content: r.content,
        }));
      },
      async vectorSearch(embedding, k) {
        const res = await db.query(
          `SELECT id, content, 1 - (embedding <=> $2::vector) AS score
             FROM memory_objects
            WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL
            ORDER BY embedding <=> $2::vector LIMIT $3`,
          [NS, `[${embedding.join(",")}]`, k],
        );
        return res.rows.map((r: { id: string; content: string; score: number }) => ({
          ref: r.id,
          content: r.content,
          score: Number(r.score),
        }));
      },
      embed: (texts) => embedder.embed(texts),
      concepts: async () => [],
      entityFacts: async () => [],
    };
  });

  afterAll(async () => {
    await db.close();
  });

  it("migration 004 created the scorecards table", async () => {
    const versions = await db.query(`SELECT version FROM schema_migrations ORDER BY version`);
    expect(versions.rows.map((r: { version: number }) => Number(r.version))).toContain(4);
    const res = await db.query(`SELECT COUNT(*)::int AS n FROM scorecards`);
    expect(Number(res.rows[0].n)).toBe(0);
  });

  it("PolicyStore round-trips retriever + abTest and inherits down the chain", async () => {
    const store = new PolicyStore(db, { cacheTtlMs: 0 });
    await store.set(
      "org",
      ["retriever: graph", "abTest:", "  a: baseline", "  b: graph", "  pctB: 40"].join("\n"),
    );
    const own = await store.get("org");
    expect(own.retriever).toBe("graph");
    expect(own.abTest).toEqual({ a: "baseline", b: "graph", pctB: 40 });
    // Child namespace inherits the parent's routing config.
    const child = await store.get("org/team/agent");
    expect(child.abTest).toEqual({ a: "baseline", b: "graph", pctB: 40 });
    // Invalid abTest never persists.
    await expect(
      store.set("org", "abTest:\n  a: baseline\n  b: graph\n  pctB: 400"),
    ).rejects.toThrow(/abTest\.pctB/);
  });

  it("buildQuestions keeps the rarest 3-5 non-stopword tokens per fact", async () => {
    const corpus = await view.candidates(200);
    const questions = buildQuestions(corpus, 30);
    expect(questions.length).toBe(15); // every crafted fact is valid
    for (const q of questions) {
      const toks = q.query.split(" ");
      expect(toks.length).toBeGreaterThanOrEqual(3);
      expect(toks.length).toBeLessThanOrEqual(5);
      // Stopwords and short tokens dropped.
      for (const t of toks) {
        expect(t.length).toBeGreaterThanOrEqual(3);
        expect(["the", "and", "with", "for", "into"]).not.toContain(t);
      }
      // Every query token came from the planted fact.
      const fact = FACTS.find((f) => f.id === q.ref)!;
      const factTokens = new Set(tokenize(fact.content));
      for (const t of toks) expect(factTokens.has(t)).toBe(true);
    }
  });

  it("caps answer-only (df=1) tokens at 2 when shared tokens exist - the query is not a unique-token subsequence", () => {
    // Doc A carries 3 tokens that exist ONLY in A plus 3 tokens shared with
    // the other docs. The old rarest-first selection emitted xylophone,
    // quokka AND zephyr (all df=1) — a verbatim subsequence unique to A that
    // every lexical lane resolves trivially. Now at most 2 df=1 tokens are
    // kept and the rest come from the rarest SHARED tokens.
    const corpus = [
      { ref: "A", content: "xylophone quokka zephyr harbor market garden" },
      { ref: "B", content: "harbor market garden pricing" },
      { ref: "C", content: "harbor market garden inventory" },
    ];
    const [qa] = buildQuestions(corpus, 1);
    expect(qa.ref).toBe("A");
    const toks = qa.query.split(" ");
    const factA = new Set(tokenize(corpus[0].content));
    for (const t of toks) expect(factA.has(t)).toBe(true);
    const uniqueToA = toks.filter((t) => ["xylophone", "quokka", "zephyr"].includes(t));
    const shared = toks.filter((t) => ["harbor", "market", "garden"].includes(t));
    expect(uniqueToA.length).toBeLessThanOrEqual(2);
    expect(shared.length).toBeGreaterThanOrEqual(1);
  });

  it("backfills with unique tokens when the corpus shares nothing (old behavior preserved)", () => {
    const corpus = [
      { ref: "A", content: "aardvark bulldozer cardigan dolphin elephant" },
      { ref: "B", content: "ferret gramophone hologram iguana jackal" },
    ];
    const qs = buildQuestions(corpus, 2);
    expect(qs).toHaveLength(2);
    for (const q of qs) {
      expect(q.query.split(" ").length).toBe(5); // all 5 tokens still used
    }
  });

  it("skips facts with too few distinctive tokens", () => {
    const qs = buildQuestions(
      [
        { ref: "ok", content: "zeppelin hydraulics maintenance manual" },
        { ref: "thin", content: "it is so" }, // all stopwords / short
      ],
      30,
    );
    expect(qs.map((q) => q.ref)).toEqual(["ok"]);
  });

  it("scorecard: perfect stub wins with hit@3=1.0, row persisted, markdown table", async () => {
    const card = await runScorecard(
      { db, drivers: [baselineDriver, perfectDriver, brokenDriver], view },
      NS,
      { maxQuestions: 30 },
    );

    expect(card.namespace).toBe(NS);
    expect(card.questionCount).toBe(15);
    expect(card.drivers).toHaveLength(3);
    expect(card.winner).toBe("stub-perfect");

    const perfect = card.drivers.find((d) => d.driver === "stub-perfect")!;
    expect(perfect.hitAt3).toBe(1.0);
    expect(perfect.errors).toBe(0);
    expect(perfect.meanTokens).toBeGreaterThan(0);
    expect(perfect.p95LatencyMs).toBeGreaterThanOrEqual(0);

    const broken = card.drivers.find((d) => d.driver === "stub-broken")!;
    expect(broken.hitAt3).toBe(0);
    expect(broken.errors).toBe(15);

    const baseline = card.drivers.find((d) => d.driver === "baseline")!;
    expect(baseline.questions).toBe(15);
    // Even if baseline also hits 1.0, the stub returns a single ref per
    // question → strictly fewer mean tokens → tie-break keeps it the winner.
    if (baseline.hitAt3 === perfect.hitAt3) {
      expect(perfect.meanTokens).toBeLessThan(baseline.meanTokens);
    }

    // Persisted row is traceable to this exact run.
    const res = await db.query(`SELECT id, namespace, json FROM scorecards WHERE id = $1`, [
      card.id,
    ]);
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0].namespace).toBe(NS);
    const stored: Scorecard =
      typeof res.rows[0].json === "string" ? JSON.parse(res.rows[0].json) : res.rows[0].json;
    expect(stored.winner).toBe("stub-perfect");
    expect(stored.questionCount).toBe(15);

    // Markdown render contains the table and names the winner.
    const md = renderScorecardMarkdown(card);
    expect(md).toContain(`# Referee scorecard - ${NS}`);
    expect(md).toContain("| driver | hit@3 | mean tokens | p95 latency (ms) | errors |");
    expect(md).toContain("**stub-perfect**");
    expect(md).toContain("| 1.00 |");
  });

  it("the sibling-namespace canary never reaches any driver through the view", async () => {
    for (const driver of [baselineDriver, perfectDriver]) {
      const refs = await driver.plan({
        query: "canary secret sibling payroll numbers",
        view,
        tokenBudget: 2000,
        k: 8,
      });
      expect(refs.map((r) => r.ref)).not.toContain("CANARY");
    }
  });

  it("short-circuits a deterministically-failing driver after 3 consecutive errors", async () => {
    let planCalls = 0;
    const alwaysThrows: RetrieverDriver = {
      name: "stub-dead",
      capabilities: () => ({ graph: false, streaming: false }),
      plan: async () => {
        planCalls++;
        throw new Error("sidecar down");
      },
    };
    const card = await runScorecard(
      { db, drivers: [perfectDriver, alwaysThrows], view },
      NS,
      { maxQuestions: 30 },
    );
    const dead = card.drivers.find((d) => d.driver === "stub-dead")!;
    // Only 3 real plan() attempts — the remaining questions were skipped
    // WITHOUT calling the driver, but still count as errors/misses.
    expect(planCalls).toBe(3);
    expect(dead.errors).toBe(card.questionCount);
    expect(dead.hitAt3).toBe(0);
    // ...and the healthy driver still wins (errors tie-break).
    expect(card.winner).toBe("stub-perfect");
  });

  it("writes a D4 audit row when an audit sink is wired", async () => {
    const events: Array<{ op: string; namespace: string; purpose: string | null; detail?: string }> = [];
    const card = await runScorecard(
      {
        db,
        drivers: [perfectDriver],
        view,
        audit: { append: async (e) => void events.push(e) },
        actor: "admin:test",
        agentId: "referee-test",
      },
      NS,
    );
    expect(events).toHaveLength(1);
    expect(events[0].op).toBe("read");
    expect(events[0].namespace).toBe(NS);
    expect(events[0].purpose).toBe("scorecard");
    expect(events[0].detail).toContain(`scorecard=${card.id}`);
    expect(events[0].detail).toContain(`winner=${card.winner}`);
  });

  it("runScorecard throws with no drivers and with an empty corpus", async () => {
    await expect(runScorecard({ db, drivers: [], view }, NS)).rejects.toThrow(/no drivers/);
    const emptyView: ScopedView = {
      ...view,
      namespace: "org/empty",
      candidates: async () => [],
    };
    await expect(
      runScorecard({ db, drivers: [perfectDriver], view: emptyView }, "org/empty"),
    ).rejects.toThrow(/distinctive tokens/);
  });
});

// ---------------------------------------------------------------------------
// Referee helpers (pure)
// ---------------------------------------------------------------------------

describe("percentile / rankDrivers", () => {
  it("nearest-rank p95", () => {
    expect(percentile([], 95)).toBe(0);
    expect(percentile([7], 95)).toBe(7);
    const hundred = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(percentile(hundred, 95)).toBe(95);
  });

  it("winner = highest hit@3, ties broken by lower mean tokens", () => {
    const scores: DriverScore[] = [
      { driver: "fat", questions: 10, hitAt3: 0.9, meanTokens: 900, p95LatencyMs: 5, errors: 0 },
      { driver: "lean", questions: 10, hitAt3: 0.9, meanTokens: 100, p95LatencyMs: 9, errors: 0 },
      { driver: "weak", questions: 10, hitAt3: 0.5, meanTokens: 10, p95LatencyMs: 1, errors: 0 },
    ];
    expect(rankDrivers(scores).map((s) => s.driver)).toEqual(["lean", "fat", "weak"]);
  });

  it("a dead driver (all errors, 0 tokens) loses a hit@3 tie to a healthy driver", () => {
    const scores: DriverScore[] = [
      // Threw on every question: hitAt3 0, meanTokens 0 — the old
      // lower-mean-tokens tie-break crowned exactly this driver the winner.
      { driver: "dead", questions: 10, hitAt3: 0, meanTokens: 0, p95LatencyMs: 3000, errors: 10 },
      // Answered every question but scored no hits on a degenerate corpus.
      { driver: "healthy", questions: 10, hitAt3: 0, meanTokens: 250, p95LatencyMs: 12, errors: 0 },
    ];
    expect(rankDrivers(scores).map((s) => s.driver)).toEqual(["healthy", "dead"]);
  });

  it("fewer errors also wins hit@3 ties above zero (flaky drivers do not benefit from deflated meanTokens)", () => {
    const scores: DriverScore[] = [
      { driver: "flaky", questions: 10, hitAt3: 0.5, meanTokens: 50, p95LatencyMs: 5, errors: 5 },
      { driver: "steady", questions: 10, hitAt3: 0.5, meanTokens: 400, p95LatencyMs: 5, errors: 0 },
    ];
    expect(rankDrivers(scores).map((s) => s.driver)).toEqual(["steady", "flaky"]);
  });
});
