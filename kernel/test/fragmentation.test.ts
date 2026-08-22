/**
 * Module E tests — fragmentation report.
 *
 * Hermetic: a hand-rolled `FragmentationReader` returns a planted
 * `FragmentFact[]`; embeddings are small hand-built `number[]` vectors so
 * cosine is deterministic. Zero network, zero DB, zero LLM.
 *
 * Scenarios:
 *  (a) two near-identical facts, sourceId 'slack' vs 'notion', ~parallel
 *      embeddings          → exactly 1 duplicate cluster
 *  (b) two currently-valid non-duplicate facts, ~orthogonal embeddings, same
 *      entity 'order-4127', same scope → exactly 1 contradiction
 *  (c) a clean corpus (distinct facts, single source, distinct entities)
 *                          → 0 clusters, 0 contradictions
 *  (d) two near-dupes from the SAME sourceId → 0 clusters (not fragmentation)
 */

import { describe, expect, it } from "vitest";
import type {
  FragmentFact,
  FragmentationReader,
  Namespace,
  Scope,
} from "../src/types.js";
import {
  cosine,
  renderFragmentationMarkdown,
  runFragmentation,
} from "../src/ingest/fragmentation.js";

const NS = "org/team";

// ---------------------------------------------------------------------------
// Hand-rolled reader + fact builder.
// ---------------------------------------------------------------------------

class PlantedReader implements FragmentationReader {
  constructor(private readonly planted: FragmentFact[]) {}
  async facts(_namespace: Namespace): Promise<FragmentFact[]> {
    return this.planted;
  }
}

let seq = 0;
function fact(over: Partial<FragmentFact>): FragmentFact {
  seq += 1;
  return {
    ref: over.ref ?? `M${seq}`,
    namespace: over.namespace ?? NS,
    content: over.content ?? `fact ${seq}`,
    scope: over.scope ?? ("org" as Scope),
    embedding: over.embedding ?? null,
    entities: over.entities ?? [],
    sourceId: over.sourceId === undefined ? null : over.sourceId,
    source: over.source ?? "document",
    tValidFrom: over.tValidFrom ?? "2026-01-01T00:00:00.000Z",
    tValidTo: over.tValidTo === undefined ? null : over.tValidTo,
  };
}

// Deterministic hand-built embeddings. Nearly-parallel pair (cosine ≈ 1) vs
// orthogonal pair (cosine = 0).
const PARALLEL_A = [1, 0, 0, 0];
const PARALLEL_B = [0.999, 0.0447, 0, 0]; // cosine ≈ 0.999 with PARALLEL_A
const ORTHO_X = [1, 0, 0, 0];
const ORTHO_Y = [0, 1, 0, 0]; // cosine 0 with ORTHO_X

// ---------------------------------------------------------------------------
// cosine unit checks (deterministic).
// ---------------------------------------------------------------------------

describe("cosine", () => {
  it("computes dot/(norm*norm) and is ~1 for parallel, 0 for orthogonal", () => {
    expect(cosine([1, 0], [1, 0])).toBeCloseTo(1, 10);
    expect(cosine([1, 0], [0, 1])).toBeCloseTo(0, 10);
    expect(cosine(PARALLEL_A, PARALLEL_B)!).toBeGreaterThan(0.92);
    expect(cosine(ORTHO_X, ORTHO_Y)!).toBeLessThan(0.92);
  });

  it("returns null when either embedding is null or degenerate", () => {
    expect(cosine(null, [1, 0])).toBeNull();
    expect(cosine([1, 0], null)).toBeNull();
    expect(cosine([0, 0], [1, 0])).toBeNull(); // zero-norm has no direction
    expect(cosine([1, 0, 0], [1, 0])).toBeNull(); // length mismatch
  });
});

// ---------------------------------------------------------------------------
// (a) cross-source near-duplicates → exactly one cluster.
// ---------------------------------------------------------------------------

describe("runFragmentation - duplicate clusters", () => {
  it("(a) two near-identical facts from slack vs notion form exactly one cluster", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "A1",
        content: "The refund window is 30 days",
        sourceId: "slack",
        embedding: PARALLEL_A,
      }),
      fact({
        ref: "A2",
        content: "Refunds are accepted within 30 days",
        sourceId: "notion",
        embedding: PARALLEL_B,
      }),
    ]);

    const report = await runFragmentation(reader, NS);

    expect(report.duplicateClusters).toHaveLength(1);
    const cluster = report.duplicateClusters[0]!;
    expect(cluster.members.map((m) => m.ref).sort()).toEqual(["A1", "A2"]);
    expect(cluster.members.map((m) => m.sourceId).sort()).toEqual([
      "notion",
      "slack",
    ]);
    // cosine is the min pairwise cosine in the cluster (here the only edge).
    expect(cluster.cosine).toBeGreaterThanOrEqual(0.92);
    expect(cluster.cosine).toBeLessThanOrEqual(1);
    // These same facts are not a contradiction (they agree / are near-dupes).
    expect(report.contradictions).toHaveLength(0);
    expect(report.factCount).toBe(2);
    expect(report.sourceCounts).toEqual({ slack: 1, notion: 1 });
  });

  it("(d) two near-dupes from the SAME source produce zero clusters", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "D1",
        content: "The refund window is 30 days",
        sourceId: "slack",
        embedding: PARALLEL_A,
      }),
      fact({
        ref: "D2",
        content: "Refunds are accepted within 30 days",
        sourceId: "slack", // SAME source - write-path dedupe's job, not ours
        embedding: PARALLEL_B,
      }),
    ]);

    const report = await runFragmentation(reader, NS);
    expect(report.duplicateClusters).toHaveLength(0);
    expect(report.sourceCounts).toEqual({ slack: 2 });
  });

  it("two null-source near-dupes are same-source ('conversation') → zero clusters", async () => {
    const reader = new PlantedReader([
      fact({ ref: "N1", sourceId: null, embedding: PARALLEL_A }),
      fact({ ref: "N2", sourceId: null, embedding: PARALLEL_B }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.duplicateClusters).toHaveLength(0);
    expect(report.sourceCounts).toEqual({ conversation: 2 });
  });

  it("union-finds a 3-fact cross-source cluster and reports the MIN pairwise cosine", async () => {
    // Three facts across three sources, chained by near-dup edges. The reported
    // cosine must be the weakest (min) internal edge, not the strongest.
    const A = [1, 0, 0, 0];
    const B = [0.999, 0.0447, 0, 0]; // cos(A,B) ≈ 0.999
    const C = [0.97, 0.243, 0, 0]; // cos(A,C) ≈ 0.97, cos(B,C) ≈ 0.973
    const reader = new PlantedReader([
      fact({ ref: "T1", sourceId: "slack", embedding: A }),
      fact({ ref: "T2", sourceId: "notion", embedding: B }),
      fact({ ref: "T3", sourceId: "filesystem", embedding: C }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.duplicateClusters).toHaveLength(1);
    const cluster = report.duplicateClusters[0]!;
    expect(cluster.members.map((m) => m.ref).sort()).toEqual([
      "T1",
      "T2",
      "T3",
    ]);
    // Min of {cos(A,B)≈0.999, cos(A,C)≈0.97, cos(B,C)≈0.973} ≈ 0.97.
    const expectedMin = Math.min(
      cosine(A, B)!,
      cosine(A, C)!,
      cosine(B, C)!,
    );
    expect(cluster.cosine).toBeCloseTo(expectedMin, 6);
  });

  it("skips pairs where an embedding is null (not comparable, no cluster)", async () => {
    const reader = new PlantedReader([
      fact({ ref: "K1", sourceId: "slack", embedding: PARALLEL_A }),
      fact({ ref: "K2", sourceId: "notion", embedding: null }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.duplicateClusters).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// (b) same-entity, same-scope, non-duplicate, both valid → one contradiction.
// ---------------------------------------------------------------------------

describe("runFragmentation - contradictions", () => {
  it("(b) two valid non-dup facts about order-4127 in one scope form one contradiction", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "B1",
        content: "Order 4127 ships to 12 Oak St",
        scope: "org",
        entities: ["order-4127"],
        sourceId: "slack",
        embedding: ORTHO_X,
        tValidTo: null,
      }),
      fact({
        ref: "B2",
        content: "Order 4127 ships to 99 Pine Ave",
        scope: "org",
        entities: ["order-4127"],
        sourceId: "notion",
        embedding: ORTHO_Y, // orthogonal → NOT a near-duplicate
        tValidTo: null,
      }),
    ]);

    const report = await runFragmentation(reader, NS);

    expect(report.contradictions).toHaveLength(1);
    const c = report.contradictions[0]!;
    expect(c.entity).toBe("order-4127");
    expect(c.facts.map((f) => f.ref).sort()).toEqual(["B1", "B2"]);
    expect(c.facts.every((f) => f.tValidTo === null)).toBe(true);
    // Orthogonal embeddings are below threshold → not a duplicate cluster.
    expect(report.duplicateClusters).toHaveLength(0);
  });

  it("near-duplicate facts about one entity are agreement, NOT a contradiction", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "AG1",
        content: "Order 4127 ships to 12 Oak St",
        entities: ["order-4127"],
        sourceId: "slack",
        embedding: PARALLEL_A,
      }),
      fact({
        ref: "AG2",
        content: "Order 4127 delivers to 12 Oak Street",
        entities: ["order-4127"],
        sourceId: "notion",
        embedding: PARALLEL_B, // near-duplicate → same assertion, not conflict
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.contradictions).toHaveLength(0);
    // But cross-source near-dupes DO surface as a duplicate cluster.
    expect(report.duplicateClusters).toHaveLength(1);
  });

  it("does not flag a contradiction when the two facts are in DIFFERENT scopes", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "S1",
        content: "Order 4127 ships to 12 Oak St",
        scope: "org",
        entities: ["order-4127"],
        embedding: ORTHO_X,
      }),
      fact({
        ref: "S2",
        content: "Order 4127 ships to 99 Pine Ave",
        scope: "team", // different scope → different group, no contradiction
        entities: ["order-4127"],
        embedding: ORTHO_Y,
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.contradictions).toHaveLength(0);
  });

  it("ignores closed (superseded) facts: a valid fact alone is not a contradiction", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "C1",
        content: "Order 4127 ships to 12 Oak St",
        entities: ["order-4127"],
        embedding: ORTHO_X,
        tValidTo: "2026-06-01T00:00:00.000Z", // closed - not currently valid
      }),
      fact({
        ref: "C2",
        content: "Order 4127 ships to 99 Pine Ave",
        entities: ["order-4127"],
        embedding: ORTHO_Y,
        tValidTo: null,
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.contradictions).toHaveLength(0);
  });

  it("emits ONE contradiction per entity even across multiple scopes", async () => {
    const reader = new PlantedReader([
      fact({ ref: "E1", scope: "org", entities: ["order-4127"], embedding: ORTHO_X }),
      fact({ ref: "E2", scope: "org", entities: ["order-4127"], embedding: ORTHO_Y }),
      fact({ ref: "E3", scope: "team", entities: ["order-4127"], embedding: ORTHO_X }),
      fact({ ref: "E4", scope: "team", entities: ["order-4127"], embedding: ORTHO_Y }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.contradictions).toHaveLength(1);
    expect(report.contradictions[0]!.entity).toBe("order-4127");
    // All four participating facts merged under the single entity row.
    expect(report.contradictions[0]!.facts.map((f) => f.ref).sort()).toEqual([
      "E1",
      "E2",
      "E3",
      "E4",
    ]);
  });
});

// ---------------------------------------------------------------------------
// (c) clean corpus → zero of everything.
// ---------------------------------------------------------------------------

describe("runFragmentation - clean corpus", () => {
  it("(c) distinct facts, single source, distinct entities → 0 clusters, 0 contradictions", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "G1",
        content: "The office is in Berlin",
        entities: ["office"],
        sourceId: "notion",
        embedding: [1, 0, 0, 0],
      }),
      fact({
        ref: "G2",
        content: "The CEO is Dana",
        entities: ["ceo"],
        sourceId: "notion",
        embedding: [0, 1, 0, 0],
      }),
      fact({
        ref: "G3",
        content: "The product ships Q3",
        entities: ["product"],
        sourceId: "notion",
        embedding: [0, 0, 1, 0],
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    expect(report.duplicateClusters).toHaveLength(0);
    expect(report.contradictions).toHaveLength(0);
    expect(report.factCount).toBe(3);
    expect(report.sourceCounts).toEqual({ notion: 3 });
  });

  it("returns an empty report for an empty corpus", async () => {
    const report = await runFragmentation(new PlantedReader([]), NS);
    expect(report.factCount).toBe(0);
    expect(report.sourceCounts).toEqual({});
    expect(report.duplicateClusters).toHaveLength(0);
    expect(report.contradictions).toHaveLength(0);
    expect(report.namespace).toBe(NS);
    expect(typeof report.ranAt).toBe("string");
  });

  it("honours a custom dedupeThreshold", async () => {
    // cos(PARALLEL_A, PARALLEL_B) ≈ 0.999. With threshold 0.9995 the pair no
    // longer clusters; with the default 0.92 it does.
    const facts = [
      fact({ ref: "TH1", sourceId: "slack", embedding: PARALLEL_A }),
      fact({ ref: "TH2", sourceId: "notion", embedding: PARALLEL_B }),
    ];
    const strict = await runFragmentation(new PlantedReader(facts), NS, {
      dedupeThreshold: 0.9995,
    });
    expect(strict.duplicateClusters).toHaveLength(0);
    const loose = await runFragmentation(new PlantedReader(facts), NS);
    expect(loose.duplicateClusters).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Markdown rendering.
// ---------------------------------------------------------------------------

describe("renderFragmentationMarkdown", () => {
  it("renders both tables and a summary line with real counts", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "R1",
        content: "The refund window is 30 days",
        sourceId: "slack",
        embedding: PARALLEL_A,
      }),
      fact({
        ref: "R2",
        content: "Refunds are accepted within 30 days",
        sourceId: "notion",
        embedding: PARALLEL_B,
      }),
      fact({
        ref: "R3",
        content: "Order 4127 ships to 12 Oak St",
        entities: ["order-4127"],
        sourceId: "slack",
        embedding: ORTHO_X,
      }),
      fact({
        ref: "R4",
        content: "Order 4127 ships to 99 Pine Ave",
        entities: ["order-4127"],
        sourceId: "notion",
        embedding: ORTHO_Y,
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    const md = renderFragmentationMarkdown(report);

    expect(md).toContain("## Duplicate clusters");
    expect(md).toContain("## Contradictions");
    expect(md).toContain("| cosine | sources | snippet |");
    expect(md).toContain("| entity | sources | snippets |");
    expect(md).toContain("order-4127");
    // Summary: 4 facts across 2 sources: 1 duplicate clusters, 1 contradictions.
    expect(md).toContain(
      "4 facts across 2 sources: 1 duplicate clusters, 1 contradictions.",
    );
    // Sources are shown for the duplicate row (order-independent).
    expect(md).toMatch(/slack, notion|notion, slack/);
  });

  it("renders _None._ placeholders and a zero summary for a clean report", async () => {
    const report = await runFragmentation(new PlantedReader([]), NS);
    const md = renderFragmentationMarkdown(report);
    expect(md).toContain("## Duplicate clusters");
    expect(md).toContain("## Contradictions");
    expect(md).toContain("_None._");
    expect(md).toContain("0 facts across 0 sources: 0 duplicate clusters, 0 contradictions.");
  });

  it("escapes pipes in content so a table row never breaks the grid", async () => {
    const reader = new PlantedReader([
      fact({
        ref: "P1",
        content: "value a | value b",
        entities: ["thing"],
        embedding: ORTHO_X,
        sourceId: "slack",
      }),
      fact({
        ref: "P2",
        content: "value c | value d",
        entities: ["thing"],
        embedding: ORTHO_Y,
        sourceId: "notion",
      }),
    ]);
    const report = await runFragmentation(reader, NS);
    const md = renderFragmentationMarkdown(report);
    // The raw content pipe is escaped so it doesn't add a column.
    expect(md).toContain("value a \\| value b");
  });
});
