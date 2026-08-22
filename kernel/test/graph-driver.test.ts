/**
 * Module B (M2) tests — GraphDriver over a hand-rolled ScopedView stub.
 *
 * Hermetic: no PGlite, no network — the view is a pure in-memory fake whose
 * embeddings are constructed by hand so we control every cosine exactly.
 */

import { describe, expect, it } from "vitest";
import type { ScopedView, ScoredRef } from "../src/types.js";
import { GraphDriver, extractMentions } from "../src/driver/graph.js";
import { cosineSimilarity } from "../src/embed/index.js";

// ---------------------------------------------------------------------------
// Hand-rolled ScopedView stub
// ---------------------------------------------------------------------------

interface StubDoc {
  ref: string;
  content: string;
  embedding: number[];
}

class StubView implements ScopedView {
  readonly namespace = "org/team";
  /** Call log so tests can assert fan-out behavior. */
  entityFactsCalls: { mention: string; hops: 1 | 2 }[] = [];

  constructor(
    private docs: StubDoc[],
    /** content/query text → embedding (for view.embed). */
    private embeddingsByText: Map<string, number[]>,
    /** lowercase mention → { hop1, hop2 } fact refs. */
    private graph: Map<string, { hop1: string[]; hop2: string[] }>,
  ) {}

  async candidates(limit?: number): Promise<{ ref: string; content: string }[]> {
    const all = this.docs.map((d) => ({ ref: d.ref, content: d.content }));
    return limit !== undefined ? all.slice(0, limit) : all;
  }

  async vectorSearch(
    embedding: number[],
    k: number,
  ): Promise<{ ref: string; content: string; score: number }[]> {
    return this.docs
      .map((d) => ({
        ref: d.ref,
        content: d.content,
        score: cosineSimilarity(embedding, d.embedding),
      }))
      .sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref))
      .slice(0, k);
  }

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((t) => {
      const known = this.embeddingsByText.get(t);
      if (known) return known;
      const byContent = this.docs.find((d) => d.content === t);
      return byContent ? byContent.embedding : [0, 0, 0, 0];
    });
  }

  async concepts(): Promise<ScoredRef[]> {
    return [];
  }

  async entityFacts(
    mention: string,
    hops: 1 | 2,
  ): Promise<{ ref: string; content: string; entity: string }[]> {
    this.entityFactsCalls.push({ mention, hops });
    const node = this.graph.get(mention.toLowerCase());
    if (!node) return [];
    const refs = hops === 1 ? node.hop1 : node.hop2;
    return refs.flatMap((ref) => {
      const doc = this.docs.find((d) => d.ref === ref);
      return doc ? [{ ref: doc.ref, content: doc.content, entity: mention }] : [];
    });
  }
}

// ---------------------------------------------------------------------------
// Fixture: Dana → order-4127 (hop 1) → shipping address (hop 2), plus a
// high-cosine distractor that pure vector search would rank first.
// ---------------------------------------------------------------------------

const QUERY = "Where does Dana order-4127 ship to";
// Unit vectors, dim 4. Query = [1,0,0,0]; cosine to query = first component.
const Q_EMB = [1, 0, 0, 0];

const F1 = {
  ref: "f1-dana-order",
  content: "Dana placed order-4127 last week",
  embedding: [0.5, Math.sqrt(1 - 0.25), 0, 0], // cos 0.5
};
const F2 = {
  ref: "f2-order-address",
  content: "order-4127 will ship to 99 Elm Street",
  embedding: [0.3, 0, Math.sqrt(1 - 0.09), 0], // cos 0.3
};
const DISTRACTOR = {
  ref: "zz-distractor",
  content: "Completely unrelated migratory bird trivia paragraph",
  embedding: [0.8, 0, 0, 0.6], // cos 0.8 - highest cosine in the corpus
};

function makeView(): StubView {
  return new StubView(
    [F1, F2, DISTRACTOR],
    new Map([
      [QUERY, Q_EMB],
      ["what happened recently in general", [0, 1, 0, 0]],
      ["Zorblax latest news", [0, 1, 0, 0]],
    ]),
    new Map([
      // hop 1: facts directly about Dana. hop 2 adds facts about entities
      // co-mentioned in hop-1 facts (order-4127 → its shipping address).
      ["dana", { hop1: [F1.ref], hop2: [F1.ref, F2.ref] }],
    ]),
  );
}

// ---------------------------------------------------------------------------
// Mention extraction
// ---------------------------------------------------------------------------

describe("extractMentions", () => {
  it("picks capitalized tokens and quoted spans, 2+ chars, deduped, cap 5", () => {
    expect(extractMentions(QUERY)).toEqual(["Where", "Dana"]);
    expect(extractMentions('find "order 4127" for Dana and dana again')).toEqual([
      "order 4127",
      "Dana",
    ]);
    expect(extractMentions("look up 'Elm Street' records")).toEqual(["Elm Street"]);
    // 1-char capitals are dropped; cap at 5.
    expect(
      extractMentions("A Bob Carol Dave Erin Frank Grace"),
    ).toEqual(["Bob", "Carol", "Dave", "Erin", "Frank"]);
    expect(extractMentions("no mentions here at all")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// GraphDriver
// ---------------------------------------------------------------------------

describe("GraphDriver", () => {
  const driver = new GraphDriver();

  it("declares graph capability, no streaming", () => {
    expect(driver.name).toBe("graph");
    expect(driver.capabilities()).toEqual({ graph: true, streaming: false });
  });

  it("multi-hop: hop-2 fact outranks a distractor that pure cosine prefers", async () => {
    const view = makeView();

    // Prove the premise: pure cosine ranks the distractor FIRST.
    const pureVector = await view.vectorSearch(Q_EMB, 10);
    expect(pureVector[0].ref).toBe(DISTRACTOR.ref);
    expect(pureVector[0].score).toBeGreaterThan(
      Math.max(pureVector[1].score, pureVector[2].score),
    );

    const results = await driver.plan({
      query: QUERY,
      view,
      tokenBudget: 2000,
      k: 3,
    });

    const refs = results.map((r) => r.ref);
    expect(refs).toContain(F2.ref);
    expect(refs).toContain(F1.ref);
    // The graph lane earns its keep: the hop-2 address fact ranks ABOVE the
    // unrelated high-cosine distractor.
    const idxF2 = refs.indexOf(F2.ref);
    const idxDistractor = refs.indexOf(DISTRACTOR.ref);
    expect(idxF2).toBeGreaterThanOrEqual(0);
    if (idxDistractor !== -1) expect(idxF2).toBeLessThan(idxDistractor);
    // Hop-1 fact (Dana ↔ order-4127) ranks first of all.
    expect(refs[0]).toBe(F1.ref);

    // Fan-out actually queried both hop depths for the Dana mention.
    expect(view.entityFactsCalls).toContainEqual({ mention: "Dana", hops: 1 });
    expect(view.entityFactsCalls).toContainEqual({ mention: "Dana", hops: 2 });

    // Scores are the contract blend, normalized into 0..1.
    for (const r of results) {
      expect(r.score).toBeGreaterThan(0);
      expect(r.score).toBeLessThanOrEqual(1);
      expect(r.tier).toBe("L2");
      expect(r.id).toBe(r.ref);
    }
  });

  it("is deterministic: same query twice gives the same ranking", async () => {
    const view = makeView();
    const a = await driver.plan({ query: QUERY, view, tokenBudget: 2000, k: 3 });
    const b = await driver.plan({ query: QUERY, view, tokenBudget: 2000, k: 3 });
    expect(b.map((r) => r.ref)).toEqual(a.map((r) => r.ref));
    expect(b.map((r) => r.score)).toEqual(a.map((r) => r.score));
  });

  it("falls back to the pure vector lane when the query has no mentions", async () => {
    const view = makeView();
    const query = "what happened recently in general"; // embeds to [0,1,0,0]
    const results = await driver.plan({ query, view, tokenBudget: 2000, k: 3 });

    // No mentions → zero entityFacts calls, ranking = cosine order.
    expect(view.entityFactsCalls).toEqual([]);
    // [0,1,0,0] is closest to F1's embedding; others are ~orthogonal.
    expect(results[0].ref).toBe(F1.ref);
    const expected = await view.vectorSearch([0, 1, 0, 0], 10);
    expect(results.map((r) => r.ref)).toEqual(expected.slice(0, 3).map((h) => h.ref));
  });

  it("falls back to the vector lane when mentions resolve to nothing", async () => {
    const view = makeView();
    const query = "Zorblax latest news"; // capitalized mention, not in registry
    const results = await driver.plan({ query, view, tokenBudget: 2000, k: 3 });

    // The mention WAS fanned out but resolved to no facts.
    expect(view.entityFactsCalls).toContainEqual({ mention: "Zorblax", hops: 1 });
    expect(results.length).toBeGreaterThan(0);
    const expected = await view.vectorSearch([0, 1, 0, 0], 10);
    expect(results.map((r) => r.ref)).toEqual(expected.slice(0, 3).map((h) => h.ref));
  });

  it("respects the token budget", async () => {
    const view = makeView();
    // F1 estimates to ceil(32/4)=8 tokens; budget 12 leaves no room for more.
    const results = await driver.plan({ query: QUERY, view, tokenBudget: 12, k: 3 });
    expect(results.length).toBe(1);
    expect(results[0].ref).toBe(F1.ref);
    const total = results.reduce((s, r) => s + r.tokenEstimate, 0);
    expect(total).toBeLessThanOrEqual(12);

    // Even a budget smaller than the best hit still returns the top result
    // (same first-hit discipline as the baseline lane).
    const tiny = await driver.plan({ query: QUERY, view, tokenBudget: 1, k: 3 });
    expect(tiny.length).toBe(1);
    expect(tiny[0].ref).toBe(F1.ref);
  });

  it("memoizes hop-fact content embeddings across plan() calls (no re-embed per query)", async () => {
    // 10 high-cosine fillers monopolize the vector lane (laneK = max(2k,10)
    // = 10 over 12 docs), so the 2 hop-linked facts arrive WITHOUT a cosine
    // and must be embedded driver-side.
    const fillers: StubDoc[] = Array.from({ length: 10 }, (_, i) => ({
      ref: `filler-${String(i).padStart(2, "0")}`,
      content: `filler document number ${i}`,
      embedding: [0.9, Math.sqrt(1 - 0.81), 0, 0],
    }));
    const hopA: StubDoc = {
      ref: "hop-a",
      content: "Dana filed the expense report",
      embedding: [0, 0, 1, 0],
    };
    const hopB: StubDoc = {
      ref: "hop-b",
      content: "Dana renewed the parking permit",
      embedding: [0, 0, 0, 1],
    };
    const view = new StubView(
      [...fillers, hopA, hopB],
      new Map([[QUERY, Q_EMB]]),
      new Map([["dana", { hop1: [hopA.ref], hop2: [hopA.ref, hopB.ref] }]]),
    );

    // Count every text that reaches the embedder.
    const embedded: string[] = [];
    const innerEmbed = view.embed.bind(view);
    view.embed = async (texts: string[]) => {
      embedded.push(...texts);
      return innerEmbed(texts);
    };

    const freshDriver = new GraphDriver();
    const first = await freshDriver.plan({ query: QUERY, view, tokenBudget: 2000, k: 3 });
    const afterFirst = embedded.filter((t) => t !== QUERY).length;
    expect(afterFirst).toBe(2); // both hop contents embedded exactly once

    const second = await freshDriver.plan({ query: QUERY, view, tokenBudget: 2000, k: 3 });
    const afterSecond = embedded.filter((t) => t !== QUERY).length;
    // Second identical plan() embeds ONLY the query — hop contents are memoized.
    expect(afterSecond).toBe(2);
    expect(second.map((r) => r.ref)).toEqual(first.map((r) => r.ref));
    expect(second.map((r) => r.score)).toEqual(first.map((r) => r.score));
  });

  it("respects k", async () => {
    const view = makeView();
    const one = await driver.plan({ query: QUERY, view, tokenBudget: 2000, k: 1 });
    expect(one.length).toBe(1);
    expect(one[0].ref).toBe(F1.ref);
    const zero = await driver.plan({ query: QUERY, view, tokenBudget: 2000, k: 0 });
    expect(zero).toEqual([]);
  });
});
