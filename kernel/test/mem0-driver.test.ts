/**
 * Module C (M2) tests — mem0 sidecar driver. Hermetic: the "sidecar" is a
 * fake node:http server on an ephemeral port. Zero python, zero network
 * beyond loopback.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  Mem0Driver,
  DriverUnavailableError,
  MEM0_CANDIDATE_LIMIT,
} from "../src/driver/mem0.js";
import type { RetrieverQuery, ScopedView, ScoredRef } from "../src/types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DOCS = [
  { ref: "01AAA", content: "The refund policy allows returns within 30 days." },
  { ref: "01BBB", content: "Marcus prefers dark roast coffee in the morning." },
  { ref: "01CCC", content: "The Q3 launch was postponed to October." },
];

/** Minimal ScopedView: only candidates() matters to the mem0 driver. */
function fakeView(docs: { ref: string; content: string }[]): ScopedView {
  return {
    namespace: "acme/support",
    candidates: async (limit?: number) =>
      limit === undefined ? docs : docs.slice(0, limit),
    vectorSearch: async () => [],
    embed: async (texts: string[]) => texts.map(() => [0, 0, 0]),
    concepts: async () => [],
    entityFacts: async () => [],
  };
}

function makeQuery(view: ScopedView, over: Partial<RetrieverQuery> = {}): RetrieverQuery {
  return { query: "refund policy", view, tokenBudget: 2000, k: 8, ...over };
}

interface FakeSidecar {
  url: string;
  server: Server;
  requests: {
    path: string;
    body: unknown;
    requestId: string | undefined;
    authorization: string | undefined;
  }[];
  close(): Promise<void>;
}

/**
 * Fake sidecar on an ephemeral port. `respond` decides per-request behavior:
 * return an object to send as 200 JSON, a number to send as that status with
 * an error body, or "hang" to never respond (timeout path).
 */
async function startFakeSidecar(
  respond: (body: unknown, requestIndex: number) => unknown | number | "hang",
): Promise<FakeSidecar> {
  const requests: FakeSidecar["requests"] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let body: unknown = null;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
      } catch {
        body = null;
      }
      const index = requests.length;
      const requestIdHeader = req.headers["x-halomem-request-id"];
      requests.push({
        path: req.url ?? "",
        body,
        requestId: Array.isArray(requestIdHeader) ? requestIdHeader[0] : requestIdHeader,
        authorization: Array.isArray(req.headers.authorization)
          ? req.headers.authorization[0] : req.headers.authorization,
      });
      const outcome = respond(body, index);
      if (outcome === "hang") return; // never respond - drive the timeout
      if (typeof outcome === "number") {
        res.writeHead(outcome, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "boom" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(outcome));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    server,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

let sidecars: FakeSidecar[] = [];
async function sidecar(
  respond: (body: unknown, i: number) => unknown | number | "hang",
): Promise<FakeSidecar> {
  const s = await startFakeSidecar(respond);
  sidecars.push(s);
  return s;
}

afterEach(async () => {
  await Promise.all(sidecars.map((s) => s.close()));
  sidecars = [];
  vi.restoreAllMocks();
  delete process.env.HALOMEM_MEM0_URL;
});

// ---------------------------------------------------------------------------
// Happy path: sidecar reorders, driver maps back through the candidate set
// ---------------------------------------------------------------------------

describe("Mem0Driver plan()", () => {
  it("returns sidecar-reordered candidates mapped to ScoredRefs with scores", async () => {
    const s = await sidecar(() => ({
      refs: [
        { ref: "01CCC", score: 0.9 },
        { ref: "01AAA", score: 0.4 },
      ],
    }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS)));

    expect(out.map((r: ScoredRef) => r.ref)).toEqual(["01CCC", "01AAA"]);
    expect(out[0]).toMatchObject({
      id: "01CCC",
      tier: "L2",
      score: 0.9,
      content: DOCS[2].content,
    });
    expect(out[1].score).toBeCloseTo(0.4);
    expect(out[1].content).toBe(DOCS[0].content);
    expect(out[0].tokenEstimate).toBeGreaterThan(0);

    // Wire contract: query/candidates/budget/k all shipped.
    expect(s.requests).toHaveLength(1);
    expect(s.requests[0].path).toBe("/plan");
    expect(s.requests[0].body).toMatchObject({
      query: "refund policy",
      budget: 2000,
      k: 8,
      candidates: DOCS,
    });
  });

  it("sends bearer authentication when configured", async () => {
    const s = await sidecar(() => ({ refs: [{ ref: "01AAA", score: 1 }] }));
    const driver = new Mem0Driver({ url: s.url, authToken: "sidecar-secret" });
    await driver.plan(makeQuery(fakeView(DOCS)));
    expect(s.requests[0]?.authorization).toBe("Bearer sidecar-secret");
  });

  it("caps the candidates shipped to the sidecar at 200", async () => {
    const many = Array.from({ length: 250 }, (_, i) => ({
      ref: `01X${String(i).padStart(3, "0")}`,
      content: `fact number ${i}`,
    }));
    const s = await sidecar(() => ({ refs: [{ ref: "01X000", score: 1 }] }));
    const driver = new Mem0Driver({ url: s.url });
    await driver.plan(makeQuery(fakeView(many)));

    const sent = (s.requests[0].body as { candidates: unknown[] }).candidates;
    expect(sent).toHaveLength(MEM0_CANDIDATE_LIMIT);
  });

  it("respects k and tokenBudget kernel-side even if the sidecar over-returns", async () => {
    const s = await sidecar(() => ({
      refs: [
        { ref: "01AAA", score: 0.9 },
        { ref: "01BBB", score: 0.8 },
        { ref: "01CCC", score: 0.7 },
      ],
    }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS), { k: 2 }));
    expect(out).toHaveLength(2);
    expect(out.map((r) => r.ref)).toEqual(["01AAA", "01BBB"]);

    // Budget: first hit always admitted, second would exceed 1-token budget.
    const tight = await driver.plan(makeQuery(fakeView(DOCS), { tokenBudget: 1 }));
    expect(tight).toHaveLength(1);
  });

  it("returns [] without calling the sidecar when the view has no candidates", async () => {
    const s = await sidecar(() => ({ refs: [] }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView([])));
    expect(out).toEqual([]);
    expect(s.requests).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Ref whitelist: the sidecar cannot inject
// ---------------------------------------------------------------------------

describe("Mem0Driver ref whitelist", () => {
  it("drops refs outside the sent candidate set and warns", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const s = await sidecar(() => ({
      refs: [
        { ref: "01EVIL", score: 0.99 }, // never sent - must be dropped
        { ref: "01BBB", score: 0.5 },
      ],
    }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS)));

    expect(out.map((r) => r.ref)).toEqual(["01BBB"]);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0][0])).toContain("01EVIL");
  });

  it("collapses duplicate refs from the sidecar", async () => {
    const s = await sidecar(() => ({
      refs: [
        { ref: "01AAA", score: 0.9 },
        { ref: "01AAA", score: 0.2 },
      ],
    }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS)));
    expect(out).toHaveLength(1);
    expect(out[0].score).toBeCloseTo(0.9);
  });

  it("clamps out-of-range scores into 0..1", async () => {
    const s = await sidecar(() => ({
      refs: [
        { ref: "01AAA", score: 17 },
        { ref: "01BBB", score: -3 },
      ],
    }));
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS)));
    expect(out[0].score).toBe(1);
    expect(out[1].score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Failure: 500 / timeout → one retry → DriverUnavailableError
// ---------------------------------------------------------------------------

describe("Mem0Driver failure handling", () => {
  it("retries once on 500, then throws DriverUnavailableError", async () => {
    const s = await sidecar(() => 500);
    const driver = new Mem0Driver({ url: s.url });
    await expect(driver.plan(makeQuery(fakeView(DOCS)))).rejects.toBeInstanceOf(
      DriverUnavailableError,
    );
    expect(s.requests).toHaveLength(2); // initial attempt + exactly one retry
  });

  it("recovers when the retry succeeds after a first-attempt 500", async () => {
    const s = await sidecar((_body, i) =>
      i === 0 ? 500 : { refs: [{ ref: "01AAA", score: 0.8 }] },
    );
    const driver = new Mem0Driver({ url: s.url });
    const out = await driver.plan(makeQuery(fakeView(DOCS)));
    expect(out.map((r) => r.ref)).toEqual(["01AAA"]);
    expect(s.requests).toHaveLength(2);
  });

  it("times out a hung sidecar and throws DriverUnavailableError after the retry", async () => {
    const s = await sidecar(() => "hang");
    const driver = new Mem0Driver({ url: s.url, timeoutMs: 150 });
    const started = Date.now();
    await expect(driver.plan(makeQuery(fakeView(DOCS)))).rejects.toBeInstanceOf(
      DriverUnavailableError,
    );
    expect(Date.now() - started).toBeGreaterThanOrEqual(250); // 2 timed attempts
    expect(s.requests).toHaveLength(2);
  });

  it("sends the SAME x-halomem-request-id on both attempts (idempotent retry)", async () => {
    const s = await sidecar(() => 500);
    const driver = new Mem0Driver({ url: s.url });
    await expect(driver.plan(makeQuery(fakeView(DOCS)))).rejects.toBeInstanceOf(
      DriverUnavailableError,
    );
    expect(s.requests).toHaveLength(2);
    expect(s.requests[0].requestId).toBeTruthy();
    // The retry MUST reuse the first attempt's id so the sidecar can dedupe
    // the side-effectful ingestion instead of running it twice.
    expect(s.requests[1].requestId).toBe(s.requests[0].requestId);
  });

  it("uses a FRESH request id per plan() call", async () => {
    const s = await sidecar(() => ({ refs: [{ ref: "01AAA", score: 1 }] }));
    const driver = new Mem0Driver({ url: s.url });
    await driver.plan(makeQuery(fakeView(DOCS)));
    await driver.plan(makeQuery(fakeView(DOCS)));
    expect(s.requests).toHaveLength(2);
    expect(s.requests[0].requestId).toBeTruthy();
    expect(s.requests[1].requestId).toBeTruthy();
    expect(s.requests[1].requestId).not.toBe(s.requests[0].requestId);
  });

  it("treats a malformed response body as unavailability", async () => {
    const s = await sidecar(() => ({ nonsense: true }));
    const driver = new Mem0Driver({ url: s.url });
    await expect(driver.plan(makeQuery(fakeView(DOCS)))).rejects.toBeInstanceOf(
      DriverUnavailableError,
    );
  });

  it("throws DriverUnavailableError when the sidecar is not listening at all", async () => {
    // Grab a port that is immediately released — nothing listens there.
    const s = await sidecar(() => ({ refs: [] }));
    const url = s.url;
    await s.close();
    sidecars = [];
    const driver = new Mem0Driver({ url, timeoutMs: 300 });
    await expect(driver.plan(makeQuery(fakeView(DOCS)))).rejects.toBeInstanceOf(
      DriverUnavailableError,
    );
  });
});

// ---------------------------------------------------------------------------
// Configuration: documented choice — constructor THROWS without a URL
// ---------------------------------------------------------------------------

describe("Mem0Driver configuration", () => {
  it("rejects insecure or unauthenticated remote sidecars", () => {
    expect(() => new Mem0Driver({ url: "http://mem0.example.test" }))
      .toThrow(/requires HTTPS/);
    expect(() => new Mem0Driver({ url: "https://mem0.example.test" }))
      .toThrow(/authentication token/);
    expect(() => new Mem0Driver({
      url: "https://mem0.example.test",
      authToken: "secret",
    })).not.toThrow();
  });

  it("rejects URL credentials, queries, and fragments", () => {
    expect(() => new Mem0Driver({ url: "http://user:pass@localhost:8790" }))
      .toThrow(/must not contain credentials/);
    expect(() => new Mem0Driver({ url: "http://localhost:8790?tenant=a" }))
      .toThrow(/must not contain credentials/);
  });

  it("constructor throws DriverUnavailableError when HALOMEM_MEM0_URL is unset", () => {
    delete process.env.HALOMEM_MEM0_URL;
    expect(() => new Mem0Driver()).toThrowError(DriverUnavailableError);
  });

  it("reads HALOMEM_MEM0_URL from the environment", async () => {
    const s = await sidecar(() => ({ refs: [{ ref: "01AAA", score: 1 }] }));
    process.env.HALOMEM_MEM0_URL = s.url;
    const driver = new Mem0Driver();
    const out = await driver.plan(makeQuery(fakeView(DOCS)));
    expect(out.map((r) => r.ref)).toEqual(["01AAA"]);
  });

  it("reports name and capabilities per the driver contract", () => {
    const driver = new Mem0Driver({ url: "http://localhost:1" });
    expect(driver.name).toBe("mem0");
    expect(driver.capabilities()).toEqual({ graph: false, streaming: false });
  });
});
