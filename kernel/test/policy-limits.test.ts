/**
 * Module D (M1) tests — PolicyStore (yaml roundtrip, inheritance, cache,
 * validation) + TokenBucket rate limiter + BudgetGuard over cost_ledger.
 * Hermetic: in-memory PGlite with the vector extension, zero network.
 */

import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import {
  DEFAULT_RATE_LIMIT_PER_MIN,
  namespaceChain,
  PolicyStore,
} from "../src/policy/store.js";
import { BudgetGuard, TokenBucket } from "../src/policy/limits.js";

const DIM = 8;
const NINETY_DAYS = 90 * 24 * 60 * 60;

let db: Db;

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM); // creates `policies`
  // cost_ledger belongs to module C (migration 003); create inline per contract.
  await db.query(`CREATE TABLE IF NOT EXISTS cost_ledger (
    id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('llm','embed')),
    tokens INTEGER NOT NULL, usd REAL NOT NULL, ts TIMESTAMPTZ NOT NULL
  )`);
  await db.query(
    `CREATE INDEX IF NOT EXISTS idx_cost_ns_ts ON cost_ledger(namespace, ts)`,
  );
});

afterAll(async () => {
  await db.close();
});

describe("namespaceChain", () => {
  it("walks org-first down to the namespace itself", () => {
    expect(namespaceChain("org/team/agent")).toEqual([
      "org",
      "org/team",
      "org/team/agent",
    ]);
    expect(namespaceChain("org")).toEqual(["org"]);
  });
});

describe("PolicyStore - set/get roundtrip", () => {
  it("returns pure kernel defaults for an unconfigured namespace", async () => {
    const store = new PolicyStore(db);
    const p = await store.get("nobody/here");
    expect(p.namespace).toBe("nobody/here");
    expect(p.tokenBudget).toBe(3000);
    expect(p.dedupeSimilarityThreshold).toBe(0.92);
    expect(p.verifierEnabled).toBe(true);
    expect(p.pinnedConcepts).toEqual([]);
    expect(p.ttlDefaultsSeconds).toEqual({
      org: null,
      team: null,
      user: NINETY_DAYS,
      assistant: NINETY_DAYS,
    });
    expect(p.rateLimitPerMin).toBe(DEFAULT_RATE_LIMIT_PER_MIN);
    expect(p.monthlyBudgetUsd).toBeUndefined();
    expect(p.retriever).toBeUndefined();
  });

  it("stores yaml and merges it over defaults on get", async () => {
    const store = new PolicyStore(db);
    await store.set(
      "acme",
      [
        "tokenBudget: 5000",
        "verifierEnabled: false",
        "rateLimitPerMin: 120",
        "retriever: baseline",
        "pinnedConcepts:",
        "  - concepts/refund-policy.md",
        "ttlDefaultsSeconds:",
        "  user: 3600",
      ].join("\n"),
    );
    const p = await store.get("acme");
    expect(p.tokenBudget).toBe(5000);
    expect(p.verifierEnabled).toBe(false);
    expect(p.rateLimitPerMin).toBe(120);
    expect(p.retriever).toBe("baseline");
    expect(p.pinnedConcepts).toEqual(["concepts/refund-policy.md"]);
    // Per-scope merge: overridden scope changes, others keep defaults.
    expect(p.ttlDefaultsSeconds.user).toBe(3600);
    expect(p.ttlDefaultsSeconds.org).toBeNull();
    expect(p.ttlDefaultsSeconds.assistant).toBe(NINETY_DAYS);
    // Untouched fields stay at defaults.
    expect(p.dedupeSimilarityThreshold).toBe(0.92);
  });

  it("upserts: setting the same namespace again replaces the row", async () => {
    const store = new PolicyStore(db);
    await store.set("acme", "tokenBudget: 7777");
    const p = await store.get("acme");
    expect(p.tokenBudget).toBe(7777);
    // Previous row's other overrides are gone (row replaced, not merged).
    expect(p.verifierEnabled).toBe(true);
    const rows = await store.list();
    expect(rows.filter((r) => r.namespace === "acme")).toHaveLength(1);
  });

  it("list() returns stored rows with yaml and timestamps", async () => {
    const store = new PolicyStore(db);
    await store.set("zeta", "tokenBudget: 1234");
    const rows = await store.list();
    const zeta = rows.find((r) => r.namespace === "zeta");
    expect(zeta).toBeDefined();
    expect(zeta!.yaml).toContain("1234");
    expect(new Date(zeta!.updatedAt).getTime()).toBeGreaterThan(0);
    // Ordered by namespace.
    const names = rows.map((r) => r.namespace);
    expect([...names].sort()).toEqual(names);
  });

  it("conflictReview: defaults to 'lower-trust', accepts the enum, rejects junk", async () => {
    const store = new PolicyStore(db);
    expect((await store.get("fresh/ns")).conflictReview).toBe("lower-trust");

    await store.set("dialed", 'conflictReview: "off"');
    expect((await store.get("dialed")).conflictReview).toBe("off");
    // Inherits down the tree like every other dial.
    expect((await store.get("dialed/child")).conflictReview).toBe("off");

    await store.set("dialed/child", "conflictReview: all");
    expect((await store.get("dialed/child")).conflictReview).toBe("all");

    await expect(store.set("dialed", "conflictReview: sometimes")).rejects.toThrow(
      /conflictReview/,
    );
  });
});

describe("PolicyStore - inheritance", () => {
  it("child inherits parent overrides; own row wins over ancestors", async () => {
    const store = new PolicyStore(db);
    await store.set("org", "monthlyBudgetUsd: 100\ntokenBudget: 4000");
    await store.set("org/team-a", "monthlyBudgetUsd: 50");

    const teamA = await store.get("org/team-a");
    expect(teamA.monthlyBudgetUsd).toBe(50); // own override wins
    expect(teamA.tokenBudget).toBe(4000); // inherited from org

    const teamB = await store.get("org/team-b"); // no row of its own
    expect(teamB.monthlyBudgetUsd).toBe(100); // inherited from org
    expect(teamB.tokenBudget).toBe(4000);

    const org = await store.get("org");
    expect(org.monthlyBudgetUsd).toBe(100);
  });

  it("merges deep chains org-first and per-scope for ttl", async () => {
    const store = new PolicyStore(db);
    await store.set("corp", "ttlDefaultsSeconds:\n  user: 1000\n  team: 2000");
    await store.set("corp/eng", "ttlDefaultsSeconds:\n  user: 500");
    const agent = await store.get("corp/eng/agent-1");
    expect(agent.ttlDefaultsSeconds.user).toBe(500); // nearest ancestor wins
    expect(agent.ttlDefaultsSeconds.team).toBe(2000); // from corp
    expect(agent.ttlDefaultsSeconds.assistant).toBe(NINETY_DAYS); // default
  });

  it("rejects a child monthly budget above the effective parent cap", async () => {
    const store = new PolicyStore(db);
    await store.set("monotonic-budget", "monthlyBudgetUsd: 10");

    await expect(
      store.set("monotonic-budget/team", "monthlyBudgetUsd: 20"),
    ).rejects.toThrow(/monthlyBudgetUsd.*effective parent/i);
  });

  it("allows a nested namespace with no stored ancestor to establish limits above kernel defaults", async () => {
    const store = new PolicyStore(db);
    await store.set(
      "baseline-without-parent/team",
      [
        "rateLimitPerMin: 100000",
        "tokenBudget: 6000",
        "ttlDefaultsSeconds:",
        `  user: ${NINETY_DAYS * 2}`,
      ].join("\n"),
    );

    const effective = await store.get("baseline-without-parent/team");
    expect(effective).toMatchObject({
      rateLimitPerMin: 100000,
      tokenBudget: 6000,
      ttlDefaultsSeconds: { user: NINETY_DAYS * 2 },
    });
  });

  it("does not turn unspecified fields in a stored ancestor into inherited default caps", async () => {
    const store = new PolicyStore(db);
    await store.set("baseline-partial-parent", "verifierEnabled: false");
    await store.set(
      "baseline-partial-parent/team",
      "rateLimitPerMin: 100000\ntokenBudget: 6000",
    );

    const effective = await store.get("baseline-partial-parent/team");
    expect(effective.rateLimitPerMin).toBe(100000);
    expect(effective.tokenBudget).toBe(6000);
    expect(effective.verifierEnabled).toBe(false);
  });

  it("rejects a child rate limit above the effective parent cap", async () => {
    const store = new PolicyStore(db);
    await store.set("monotonic-rate", "rateLimitPerMin: 10");

    await expect(
      store.set("monotonic-rate/team", "rateLimitPerMin: 20"),
    ).rejects.toThrow(/rateLimitPerMin.*effective parent/i);
  });

  it("rejects a child token budget above the effective parent cap", async () => {
    const store = new PolicyStore(db);
    await store.set("monotonic-token", "tokenBudget: 1000");

    await expect(
      store.set("monotonic-token/team", "tokenBudget: 2000"),
    ).rejects.toThrow(/tokenBudget.*effective parent/i);
  });

  it("rejects a child user TTL that raises or removes the effective parent limit", async () => {
    const store = new PolicyStore(db);
    await store.set(
      "monotonic-ttl",
      "ttlDefaultsSeconds:\n  user: 100",
    );

    await expect(
      store.set(
        "monotonic-ttl/raised",
        "ttlDefaultsSeconds:\n  user: 200",
      ),
    ).rejects.toThrow(/ttlDefaultsSeconds\.user.*effective parent/i);
    await expect(
      store.set(
        "monotonic-ttl/unlimited",
        "ttlDefaultsSeconds:\n  user: null",
      ),
    ).rejects.toThrow(/ttlDefaultsSeconds\.user.*effective parent/i);
  });

  it("persists tighter child caps and retention", async () => {
    const store = new PolicyStore(db);
    await store.set(
      "monotonic-safe",
      [
        "monthlyBudgetUsd: 100",
        "rateLimitPerMin: 100",
        "tokenBudget: 1000",
        "ttlDefaultsSeconds:",
        "  user: 1000",
      ].join("\n"),
    );
    await store.set(
      "monotonic-safe/team",
      [
        "monthlyBudgetUsd: 50",
        "rateLimitPerMin: 50",
        "tokenBudget: 500",
        "ttlDefaultsSeconds:",
        "  user: 500",
      ].join("\n"),
    );

    const effective = await store.get("monotonic-safe/team");
    expect(effective).toMatchObject({
      monthlyBudgetUsd: 50,
      rateLimitPerMin: 50,
      tokenBudget: 500,
      ttlDefaultsSeconds: { user: 500 },
    });
  });

  it("keeps existing child policy effective limits monotonic when its parent tightens", async () => {
    const store = new PolicyStore(db);
    const policy = (value: number) =>
      [
        `monthlyBudgetUsd: ${value}`,
        `rateLimitPerMin: ${value}`,
        `tokenBudget: ${value}`,
        "ttlDefaultsSeconds:",
        `  user: ${value}`,
      ].join("\n");
    await store.set("monotonic-parent-change", policy(100));
    await store.set("monotonic-parent-change/team", policy(90));

    await store.set("monotonic-parent-change", policy(50));

    const effective = await store.get("monotonic-parent-change/team");
    expect(effective).toMatchObject({
      monthlyBudgetUsd: 50,
      rateLimitPerMin: 50,
      tokenBudget: 50,
      ttlDefaultsSeconds: { user: 50 },
    });
  });

  it("set on a parent invalidates cached descendants", async () => {
    const store = new PolicyStore(db);
    await store.set("cachy", "tokenBudget: 1000");
    const before = await store.get("cachy/child"); // caches child merge
    expect(before.tokenBudget).toBe(1000);
    await store.set("cachy", "tokenBudget: 2000"); // invalidates subtree
    const after = await store.get("cachy/child");
    expect(after.tokenBudget).toBe(2000);
  });
});

describe("PolicyStore - cache + invalidate", () => {
  it("serves from cache within TTL and refreshes after invalidate()", async () => {
    const store = new PolicyStore(db); // default 30s TTL
    await store.set("cached-ns", "tokenBudget: 1111");
    expect((await store.get("cached-ns")).tokenBudget).toBe(1111);

    // Mutate the row BEHIND the store — cached value must still be served.
    await db.query(`UPDATE policies SET yaml = $1 WHERE namespace = $2`, [
      "tokenBudget: 2222",
      "cached-ns",
    ]);
    expect((await store.get("cached-ns")).tokenBudget).toBe(1111);

    store.invalidate("cached-ns");
    expect((await store.get("cached-ns")).tokenBudget).toBe(2222);
  });

  it("expires cache entries after the TTL (injected clock)", async () => {
    let t = 0;
    const store = new PolicyStore(db, { now: () => t });
    await store.set("ttl-ns", "tokenBudget: 3333");
    expect((await store.get("ttl-ns")).tokenBudget).toBe(3333);
    await db.query(`UPDATE policies SET yaml = $1 WHERE namespace = $2`, [
      "tokenBudget: 4444",
      "ttl-ns",
    ]);
    t = 29_999; // still cached
    expect((await store.get("ttl-ns")).tokenBudget).toBe(3333);
    t = 30_001; // past 30s TTL
    expect((await store.get("ttl-ns")).tokenBudget).toBe(4444);
  });

  it("callers mutating a returned policy do not poison the cache", async () => {
    const store = new PolicyStore(db);
    await store.set("mut-ns", "tokenBudget: 5555");
    const p1 = await store.get("mut-ns");
    p1.tokenBudget = 1;
    p1.pinnedConcepts.push("hacked");
    p1.ttlDefaultsSeconds.user = -99;
    const p2 = await store.get("mut-ns");
    expect(p2.tokenBudget).toBe(5555);
    expect(p2.pinnedConcepts).toEqual([]);
    expect(p2.ttlDefaultsSeconds.user).toBe(NINETY_DAYS);
  });
});

describe("PolicyStore - in-flight get() racing set()", () => {
  it("never re-caches the pre-set policy after set() invalidated it", async () => {
    // Wrap the db so the policies SELECT can be held AFTER it executed
    // (its continuation delayed) — the exact interleaving where get() read
    // the old row, set() completed (upsert + invalidate), and get() then
    // resumes to fill the cache.
    let holdSelect: Promise<void> | null = null;
    const wrapped: Db = {
      query: async (sql: string, params?: unknown[]) => {
        const res = await db.query(sql, params);
        if (holdSelect && sql.includes("FROM policies WHERE namespace IN")) {
          const wait = holdSelect;
          holdSelect = null;
          await wait;
        }
        return res;
      },
      transaction: (fn) => db.transaction(fn),
      close: async () => {},
    };

    const store = new PolicyStore(wrapped);
    await store.set("race-ns", "tokenBudget: 1000");

    let release!: () => void;
    holdSelect = new Promise<void>((r) => (release = r));
    const inflight = store.get("race-ns"); // SELECT reads tokenBudget: 1000, then parks

    // Admin change is acknowledged while the read is parked.
    await store.set("race-ns", "tokenBudget: 2000");
    release();

    const stale = await inflight;
    expect(stale.tokenBudget).toBe(1000); // the in-flight caller's own view - fine

    // The acknowledged change must be served NOW: the racing get() must not
    // have repopulated the cache with the pre-set merge for a full TTL.
    expect((await store.get("race-ns")).tokenBudget).toBe(2000);
  });
});

describe("PolicyStore - validation", () => {
  it("rejects malformed yaml with a clear error and persists nothing", async () => {
    const store = new PolicyStore(db);
    await expect(store.set("bad-ns", "tokenBudget: [unclosed")).rejects.toThrow(
      /Invalid policy YAML for namespace 'bad-ns'/,
    );
    const rows = await store.list();
    expect(rows.find((r) => r.namespace === "bad-ns")).toBeUndefined();
  });

  it("rejects empty and non-mapping documents", async () => {
    const store = new PolicyStore(db);
    await expect(store.set("bad-ns", "")).rejects.toThrow(/empty/);
    await expect(store.set("bad-ns", "- 1\n- 2")).rejects.toThrow(/sequence/);
    await expect(store.set("bad-ns", "just a string")).rejects.toThrow(/mapping/);
  });

  it("rejects out-of-shape fields via zod with field names in the message", async () => {
    const store = new PolicyStore(db);
    await expect(store.set("bad-ns", "tokenBudget: -5")).rejects.toThrow(
      /tokenBudget/,
    );
    await expect(store.set("bad-ns", "tokenBudget: 10.5")).rejects.toThrow(
      /tokenBudget/,
    );
    await expect(
      store.set("bad-ns", "dedupeSimilarityThreshold: 1.5"),
    ).rejects.toThrow(/dedupeSimilarityThreshold/);
    await expect(store.set("bad-ns", "rateLimitPerMin: 0")).rejects.toThrow(
      /rateLimitPerMin/,
    );
    await expect(store.set("bad-ns", "monthlyBudgetUsd: -1")).rejects.toThrow(
      /monthlyBudgetUsd/,
    );
    await expect(store.set("bad-ns", "verifierEnabled: maybe")).rejects.toThrow(
      /verifierEnabled/,
    );
    await expect(store.set("bad-ns", "unknownField: 1")).rejects.toThrow(
      /[Uu]nrecognized/,
    );
    await expect(store.set("", "tokenBudget: 1")).rejects.toThrow(/non-empty/);
  });
});

describe("TokenBucket", () => {
  it("allows a full burst then throttles at the limit", () => {
    let t = 0;
    const bucket = new TokenBucket({ now: () => t });
    for (let i = 0; i < 60; i++) {
      expect(bucket.allow("key-1", 60)).toBe(true);
    }
    expect(bucket.allow("key-1", 60)).toBe(false); // 61st in the same instant
  });

  it("refills continuously at limit/60s", () => {
    let t = 0;
    const bucket = new TokenBucket({ now: () => t });
    for (let i = 0; i < 60; i++) bucket.allow("key-2", 60);
    expect(bucket.allow("key-2", 60)).toBe(false);

    t += 1000; // 1s at 60/min → exactly 1 token back
    expect(bucket.allow("key-2", 60)).toBe(true);
    expect(bucket.allow("key-2", 60)).toBe(false);

    t += 500; // half a token - not enough
    expect(bucket.allow("key-2", 60)).toBe(false);
    t += 500; // now a full token
    expect(bucket.allow("key-2", 60)).toBe(true);

    t += 10 * 60_000; // long idle → capped at capacity, not unbounded
    for (let i = 0; i < 60; i++) {
      expect(bucket.allow("key-2", 60)).toBe(true);
    }
    expect(bucket.allow("key-2", 60)).toBe(false);
  });

  it("keys are independent and policy limit overrides apply per call", () => {
    let t = 0;
    const bucket = new TokenBucket({ now: () => t });
    expect(bucket.allow("slow-key", 1)).toBe(true);
    expect(bucket.allow("slow-key", 1)).toBe(false);
    expect(bucket.allow("other-key", 60)).toBe(true); // unaffected
    expect(bucket.allow("zero-key", 0)).toBe(false); // non-positive → deny
  });

  it("evicts stale buckets", () => {
    let t = 0;
    const bucket = new TokenBucket({
      now: () => t,
      evictAfterMs: 5_000,
      sweepIntervalMs: 1_000,
    });
    bucket.allow("stale", 60);
    bucket.allow("fresh", 60);
    expect(bucket.size).toBe(2);
    t += 6_000;
    bucket.allow("fresh", 60); // touches fresh + triggers sweep
    expect(bucket.size).toBe(1);
  });
});

describe("BudgetGuard", () => {
  const NOW = new Date("2026-07-15T12:00:00.000Z");
  const guard = () => new BudgetGuard(db, { now: () => NOW });

  async function ledger(id: string, ns: string, usd: number, ts: string) {
    await db.query(
      `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
       VALUES ($1, $2, 'llm', 100, $3, $4)`,
      [id, ns, usd, ts],
    );
  }

  it("sums only the current month, including the namespace subtree", async () => {
    await ledger("l1", "org/team-a", 30, "2026-07-05T00:00:00.000Z");
    await ledger("l2", "org/team-a", 40, "2026-06-20T00:00:00.000Z"); // last month
    await ledger("l3", "org/team-a/agent-1", 10, "2026-07-10T00:00:00.000Z"); // descendant
    await ledger("l4", "org/team-b", 999, "2026-07-01T00:00:00.000Z"); // sibling
    await ledger("l5", "organization", 999, "2026-07-01T00:00:00.000Z"); // prefix trap

    const g = guard();
    expect(await g.monthToDateUsd("org/team-a")).toBeCloseTo(40, 5); // 30 + 10
    expect(await g.monthToDateUsd("org")).toBeCloseTo(1039, 5); // subtree incl. team-b
    expect(await g.monthToDateUsd("empty/ns")).toBe(0);
  });

  it("transitions ok → over as ledger rows push spend past the cap", async () => {
    const g = guard();
    const policy = async (cap?: number) => {
      const store = new PolicyStore(db);
      const p = await store.get("budget/ns");
      return cap === undefined ? p : { ...p, monthlyBudgetUsd: cap };
    };

    expect(await g.state("budget/ns", await policy(50))).toBe("ok"); // 0 spent
    await ledger("b1", "budget/ns", 30, "2026-07-02T00:00:00.000Z");
    expect(await g.state("budget/ns", await policy(50))).toBe("ok"); // 30 < 50
    await ledger("b2", "budget/ns", 25, "2026-07-03T00:00:00.000Z");
    expect(await g.state("budget/ns", await policy(50))).toBe("over"); // 55 >= 50

    // No cap configured → always ok (never hard-fail the agent).
    expect(await g.state("budget/ns", await policy())).toBe("ok");
    // Zero cap → no LLM budget at all.
    expect(await g.state("budget/ns", await policy(0))).toBe("over");
  });

  it("never treats '_'/'%' in the namespace as LIKE wildcards", async () => {
    // 'org/teamXa/agent' LIKE 'org/team_a/%' is TRUE in raw SQL ('_' matches
    // 'X') — that sibling tenant's spend must NOT count against team_a's cap.
    await ledger("w1", "org/teamXa/agent", 60, "2026-07-06T00:00:00.000Z");
    await ledger("w2", "org/team_a/agent", 5, "2026-07-06T00:00:00.000Z");

    const g = guard();
    expect(await g.monthToDateUsd("org/team_a")).toBeCloseTo(5, 5); // w2 only
    expect(await g.monthToDateUsd("org/teamXa")).toBeCloseTo(60, 5);

    const store = new PolicyStore(db);
    const capped = { ...(await store.get("org/team_a")), monthlyBudgetUsd: 50 };
    // Without escaping, the foreign $60 would flip team_a into brownout.
    expect(await g.state("org/team_a", capped)).toBe("ok");
  });

  it("uses the inherited cap from PolicyStore end to end", async () => {
    const store = new PolicyStore(db);
    await store.set("bcorp", "monthlyBudgetUsd: 100");
    await store.set("bcorp/team-a", "monthlyBudgetUsd: 50");
    const g = guard();

    await ledger("e1", "bcorp/team-a", 60, "2026-07-04T00:00:00.000Z");
    // team-a: own cap 50, spent 60 → over.
    expect(await g.state("bcorp/team-a", await store.get("bcorp/team-a"))).toBe(
      "over",
    );
    // team-b: inherits org cap 100, spent 0 → ok.
    expect(await g.state("bcorp/team-b", await store.get("bcorp/team-b"))).toBe(
      "ok",
    );
    // org: cap 100, subtree spend 60 → ok.
    expect(await g.state("bcorp", await store.get("bcorp"))).toBe("ok");
  });
});
