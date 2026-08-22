/**
 * Module C tests — retrieval + embeddings. Hermetic: in-memory PGlite with
 * the vector extension, HashEmbedder only, zero network.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { vector } from "@electric-sql/pglite/vector";

import {
  HashEmbedder,
  AzureOpenAiEmbedder,
  BatchingEmbedder,
  EmbeddingProviderError,
  createEmbedder,
  cosineSimilarity,
  tokenize,
  HASH_EMBED_DIM,
} from "../src/embed/index.js";
import {
  bm25Rank,
  normalizeScores,
  hybridMerge,
  lexicalOrQuery,
  searchL2,
  type L2IndexLike,
  type VectorHit,
} from "../src/retrieval/index.js";
import { loadConfig } from "../src/config.js";
import { estimateTokens, type SearchQuery } from "../src/types.js";
import type { Embedder } from "../src/types.js";

describe("HashEmbedder", () => {
  const embedder = new HashEmbedder();

  it("has the contract name and dim", () => {
    expect(embedder.name).toBe("hash");
    expect(embedder.dim).toBe(256);
    expect(HASH_EMBED_DIM).toBe(256);
  });

  it("can match a configured production vector dimension for local-only writes", async () => {
    const dimensionMatched = new HashEmbedder(3_072);
    const [vector] = await dimensionMatched.embed(["confidential local-only policy"]);
    expect(dimensionMatched.name).toBe("hash");
    expect(vector).toHaveLength(3_072);
    expect(() => new HashEmbedder(0)).toThrow(/positive integer/);
  });

  it("is deterministic: same text → identical vector", async () => {
    const [a] = await embedder.embed(["The refund policy allows 30-day returns."]);
    const [b] = await embedder.embed(["The refund policy allows 30-day returns."]);
    expect(a).toEqual(b);
    expect(a).toHaveLength(256);
  });

  it("produces L2-normalized vectors", async () => {
    const [v] = await embedder.embed(["quarterly revenue grew twelve percent"]);
    const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
    expect(norm).toBeCloseTo(1, 10);
  });

  it("is case/punctuation insensitive via tokenizer", async () => {
    const [a] = await embedder.embed(["Refund Policy!"]);
    const [b] = await embedder.embed(["refund   policy"]);
    expect(a).toEqual(b);
  });

  it("returns a zero vector for empty text", async () => {
    const [v] = await embedder.embed([""]);
    expect(v.every((x) => x === 0)).toBe(true);
  });

  it("related texts share buckets (higher cosine than unrelated)", async () => {
    const [refund, refundDetails, revenue] = await embedder.embed([
      "refund policy",
      "refund policy details for enterprise customers",
      "quarterly revenue projections",
    ]);
    const related = cosineSimilarity(refund, refundDetails);
    const unrelated = cosineSimilarity(refund, revenue);
    expect(related).toBeGreaterThan(unrelated);
    expect(related).toBeGreaterThan(0);
  });
});

describe("cosineSimilarity", () => {
  it("identical texts → cosine 1", async () => {
    const embedder = new HashEmbedder();
    const [a, b] = await embedder.embed(["halo memory kernel", "halo memory kernel"]);
    expect(cosineSimilarity(a, b)).toBeCloseTo(1, 10);
  });

  it("returns 0 for zero-norm input", () => {
    expect(cosineSimilarity([0, 0], [1, 1])).toBe(0);
  });

  it("throws on dimension mismatch", () => {
    expect(() => cosineSimilarity([1, 2], [1, 2, 3])).toThrow(/dimension mismatch/);
  });
});

describe("createEmbedder", () => {
  it("returns HashEmbedder when no OpenAI key", () => {
    const cfg = loadConfig({ openaiApiKey: "", embedDim: 256 });
    const e = createEmbedder(cfg);
    expect(e.name).toBe("hash");
    expect(e.dim).toBe(256);
  });

  it("returns OpenAIEmbedder when a key is present (no network call)", () => {
    const cfg = loadConfig({ openaiApiKey: "sk-test", embedDim: 1536 });
    const e = createEmbedder(cfg);
    expect(e.name).toBe("openai");
    expect(e.dim).toBe(1536);
  });
});

describe("provider embedding resilience", () => {
  it("coalesces simultaneous callers into bounded batches and preserves order", async () => {
    const calls: string[][] = [];
    const inner: Embedder = {
      name: "capture",
      dim: 1,
      async embed(texts) {
        calls.push([...texts]);
        return texts.map((text) => [Number(text)]);
      },
    };
    const batched = new BatchingEmbedder(inner, 3, 2, 0);
    const [first, second, third] = await Promise.all([
      batched.embed(["1"]),
      batched.embed(["2", "3"]),
      batched.embed(["4"]),
    ]);

    expect(calls).toEqual([["1", "2", "3"], ["4"]]);
    expect(first).toEqual([[1]]);
    expect(second).toEqual([[2], [3]]);
    expect(third).toEqual([[4]]);
  });

  it("splits an oversized provider batch and returns every vector", async () => {
    const calls: string[][] = [];
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const input = (JSON.parse(String(init?.body)) as { input: string[] }).input;
      calls.push(input);
      if (input.length > 1) {
        return new Response(JSON.stringify({ error: { message: "maximum context length" } }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ data: [{ index: 0, embedding: [input[0]!.length] }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const embedder = new AzureOpenAiEmbedder("key", "https://azure.example", "embed", "v1");
      await expect(embedder.embed(["alpha", "beta"])).resolves.toEqual([[5], [4]]);
      expect(calls).toEqual([["alpha", "beta"], ["alpha"], ["beta"]]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("returns a content-free permanent error for authentication failures", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("secret provider detail", {
      status: 401,
    })));
    try {
      const embedder = new AzureOpenAiEmbedder("key", "https://azure.example", "embed", "v1");
      const error = await embedder.embed(["private input"]).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(EmbeddingProviderError);
      expect(error).toMatchObject({ code: "authentication", retryable: false, status: 401 });
      expect(String(error)).not.toContain("secret provider detail");
      expect(String(error)).not.toContain("private input");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("aborts a lost provider socket and returns a retryable timeout", async () => {
    let providerSignal: AbortSignal | null = null;
    const fetchMock = vi.fn((_url: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        providerSignal = init?.signal ?? null;
        providerSignal?.addEventListener("abort", () => reject(providerSignal?.reason), {
          once: true,
        });
      }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const embedder = new AzureOpenAiEmbedder(
        "key",
        "https://azure.example",
        "embed",
        "v1",
        15,
      );
      const error = await embedder.embed(["private input"]).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(EmbeddingProviderError);
      expect(error).toMatchObject({ code: "timeout", retryable: true, status: null });
      expect(providerSignal?.aborted).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(String(error)).not.toContain("private input");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("tokenize", () => {
  it("lowercases and splits on non-alphanumerics", () => {
    expect(tokenize("Hello, World! v2.0")).toEqual(["hello", "world", "v2", "0"]);
    expect(tokenize("  ")).toEqual([]);
  });
});

describe("bm25Rank", () => {
  const docs = [
    { ref: "d1", content: "the refund policy allows returns within thirty days" },
    { ref: "d2", content: "quarterly revenue grew twelve percent this year" },
    { ref: "d3", content: "shipping times vary by region and carrier" },
  ];

  it("ranks the doc containing the query terms first", () => {
    const hits = bm25Rank("refund policy", docs, 3);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].ref).toBe("d1");
    // Docs with zero matching terms are excluded.
    expect(hits.every((h) => h.score > 0)).toBe(true);
    expect(hits.map((h) => h.ref)).not.toContain("d2");
  });

  it("respects k", () => {
    const many = [
      { ref: "a", content: "alpha beta" },
      { ref: "b", content: "alpha gamma" },
      { ref: "c", content: "alpha delta" },
    ];
    expect(bm25Rank("alpha", many, 2)).toHaveLength(2);
  });

  it("returns empty for empty docs or empty query", () => {
    expect(bm25Rank("refund", [], 5)).toEqual([]);
    expect(bm25Rank("", docs, 5)).toEqual([]);
  });
});

describe("lexicalOrQuery", () => {
  it("keeps bounded meaningful terms and strips tsquery operators", () => {
    expect(lexicalOrQuery("What traction does Halofy have? Include pilots & ARR."))
      .toBe("traction | halofy | pilots | arr");
    expect(lexicalOrQuery("' | & ! ( )")).toBeNull();
  });
});

describe("normalizeScores", () => {
  it("min-max normalizes to 0..1", () => {
    const out = normalizeScores([
      { ref: "a", score: 2 },
      { ref: "b", score: 4 },
      { ref: "c", score: 6 },
    ]);
    expect(out.map((e) => e.score)).toEqual([0, 0.5, 1]);
  });

  it("single entry → 1", () => {
    expect(normalizeScores([{ ref: "solo", score: 0.37 }])[0].score).toBe(1);
  });

  it("all-equal scores → all 1", () => {
    const out = normalizeScores([
      { ref: "a", score: 3 },
      { ref: "b", score: 3 },
    ]);
    expect(out.map((e) => e.score)).toEqual([1, 1]);
  });

  it("empty input → empty output", () => {
    expect(normalizeScores([])).toEqual([]);
  });
});

describe("hybridMerge", () => {
  const vectorHits: VectorHit[] = [
    { ref: "m1", score: 0.9, content: "refund policy is thirty days" },
    { ref: "m2", score: 0.5, content: "shipping is free over fifty dollars" },
  ];
  const bm25Hits = [
    { ref: "m1", score: 3.2 },
    { ref: "m3", score: 1.1 },
  ];
  const contentByRef = new Map([
    ["m1", "refund policy is thirty days"],
    ["m2", "shipping is free over fifty dollars"],
    ["m3", "support hours are nine to five"],
  ]);

  it("dedupes by ref and ranks the doc in both lanes first", () => {
    const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, 10);
    const refs = merged.map((r) => r.ref);
    expect(new Set(refs).size).toBe(refs.length); // deduped
    expect(refs).toHaveLength(3); // m1, m2, m3
    expect(merged[0].ref).toBe("m1"); // top of both lanes → 0.5*1 + 0.5*1 = 1
    expect(merged[0].score).toBeCloseTo(1, 10);
  });

  it("respects k", () => {
    const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, 2);
    expect(merged).toHaveLength(2);
    expect(merged[0].score).toBeGreaterThanOrEqual(merged[1].score);
  });

  it("fills ScoredRef shape: tier L2, id === ref, tokenEstimate", () => {
    const merged = hybridMerge(vectorHits, bm25Hits, contentByRef, 10);
    for (const r of merged) {
      expect(r.tier).toBe("L2");
      expect(r.id).toBe(r.ref);
      expect(r.tokenEstimate).toBe(estimateTokens(r.content));
      expect(r.score).toBeGreaterThanOrEqual(0);
      expect(r.score).toBeLessThanOrEqual(1);
    }
    // m3 only appeared in bm25 lane — content resolved via contentByRef.
    const m3 = merged.find((r) => r.ref === "m3");
    expect(m3?.content).toBe("support hours are nine to five");
  });

  it("a missing lane contributes 0", () => {
    const merged = hybridMerge(vectorHits, [], contentByRef, 10);
    // Only vector lane present: top vec hit normalizes to 1 → combined 0.5.
    expect(merged[0].ref).toBe("m1");
    expect(merged[0].score).toBeCloseTo(0.5, 10);
  });

  it("tier L3 → id is null", () => {
    const merged = hybridMerge(
      [{ ref: "concepts/refunds.md", score: 1, content: "refunds" }],
      [],
      new Map(),
      5,
      "L3",
    );
    expect(merged[0].id).toBeNull();
    expect(merged[0].tier).toBe("L3");
    expect(merged[0].ref).toBe("concepts/refunds.md");
  });
});

describe("searchL2 (in-memory PGlite + pgvector)", () => {
  let db: PGlite;
  let index: L2IndexLike;
  const embedder = new HashEmbedder();

  const rows = [
    { id: "01A", content: "the refund policy allows returns within thirty days" },
    { id: "01B", content: "quarterly revenue grew twelve percent this year" },
    { id: "01C", content: "shipping times vary by region and carrier" },
  ];

  beforeAll(async () => {
    db = new PGlite({ extensions: { vector } });
    await db.exec("CREATE EXTENSION IF NOT EXISTS vector;");
    await db.exec(
      `CREATE TABLE mem (id TEXT PRIMARY KEY, content TEXT NOT NULL, embedding vector(${HASH_EMBED_DIM}));`,
    );
    const embeddings = await embedder.embed(rows.map((r) => r.content));
    for (let i = 0; i < rows.length; i++) {
      await db.query(
        "INSERT INTO mem (id, content, embedding) VALUES ($1, $2, $3::vector)",
        [rows[i].id, rows[i].content, `[${embeddings[i].join(",")}]`],
      );
    }
    index = {
      async vectorSearch(_ns, queryEmbedding, k) {
        const literal = `[${queryEmbedding.join(",")}]`;
        const res = await db.query<{ id: string; content: string; score: number }>(
          `SELECT id, content, 1 - (embedding <=> $1::vector) AS score
             FROM mem ORDER BY embedding <=> $1::vector LIMIT $2`,
          [literal, k],
        );
        return res.rows.map((r) => ({ ref: r.id, score: Number(r.score), content: r.content }));
      },
      async listCandidates() {
        const res = await db.query<{ id: string; content: string }>(
          "SELECT id, content FROM mem",
        );
        return res.rows.map((r) => ({ ref: r.id, content: r.content }));
      },
    };
  });

  afterAll(async () => {
    await db.close();
  });

  it("returns the relevant memory first as tier L2 with id === ref", async () => {
    const q: SearchQuery = { namespace: "org/team", query: "refund policy returns" };
    const hits = await searchL2(index, embedder, q);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].ref).toBe("01A");
    expect(hits[0].id).toBe("01A");
    expect(hits[0].tier).toBe("L2");
    expect(hits[0].content).toBe(rows[0].content);
    expect(hits[0].tokenEstimate).toBe(estimateTokens(rows[0].content));
    // Sorted descending, deduped.
    const refs = hits.map((h) => h.ref);
    expect(new Set(refs).size).toBe(refs.length);
    for (let i = 1; i < hits.length; i++) {
      expect(hits[i - 1].score).toBeGreaterThanOrEqual(hits[i].score);
    }
  });

  it("respects k", async () => {
    const hits = await searchL2(index, embedder, {
      namespace: "org",
      query: "refund policy returns",
      k: 1,
    });
    expect(hits).toHaveLength(1);
    expect(hits[0].ref).toBe("01A");
  });

  it("enforces the token budget but always returns the top hit", async () => {
    const hits = await searchL2(index, embedder, {
      namespace: "org",
      query: "refund policy returns shipping revenue",
      k: 3,
      tokenBudget: 1, // smaller than any single hit
    });
    expect(hits).toHaveLength(1); // top hit always included, rest trimmed
    const total = hits.reduce((s, h) => s + h.tokenEstimate, 0);
    expect(total).toBe(hits[0].tokenEstimate);
  });
});
