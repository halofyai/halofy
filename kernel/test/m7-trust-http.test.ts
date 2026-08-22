import { afterEach, describe, expect, it } from "vitest";

import { BoundedHttpRedMetrics, type HttpRequestObservation } from "../src/observability/http.js";
import { createHttpServer, type HaloHttpServer, type HttpServerDeps } from "../src/http/server.js";

function deps(overrides: Partial<HttpServerDeps> = {}): HttpServerDeps {
  return {
    auth: { async resolve() { return null; } },
    syscalls: {
      async memRead() {}, async memSearch() {}, async memWrite() {},
      async memFault() {},
      async memStats() { throw new Error("db exploded: password=secret"); },
      async memAssemble() {},
    },
    admin: {
      async getPolicy() {}, async setPolicy() {}, async listKeys() {},
      async issueKey() {}, async revokeKey() {},
    },
    metrics: { snapshot() { return {}; } },
    audit: { async append() {} },
    buildMcpServer() {
      return { async connect() {}, async close() {} };
    },
    ...overrides,
  };
}

describe("M7 HTTP trust boundary", () => {
  const servers: HaloHttpServer[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => server.stop()));
  });

  async function start(serverDeps: HttpServerDeps): Promise<string> {
    const server = createHttpServer(serverDeps);
    servers.push(server);
    return `http://127.0.0.1:${await server.start(0)}`;
  }

  it("sets a validated request id, trace context, and production security headers", async () => {
    const observations: HttpRequestObservation[] = [];
    const base = await start(deps({
      secureCookies: true,
      telemetry: { observe(observation) { observations.push(observation); } },
    }));
    const response = await fetch(`${base}/healthz`, {
      headers: {
        "x-request-id": "edge-req-123",
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      },
    });
    await response.text();

    expect(response.headers.get("x-request-id")).toBe("edge-req-123");
    expect(response.headers.get("traceparent"))
      .toMatch(/^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/);
    const contentSecurityPolicy = response.headers.get("content-security-policy") ?? "";
    expect(contentSecurityPolicy).toContain("default-src 'none'");
    expect(contentSecurityPolicy).toContain(
      "img-src 'self' data: https://cdn.brandfetch.io https://cdn.simpleicons.org",
    );
    expect(contentSecurityPolicy).not.toMatch(/img-src[^;]*\shttps:(?:\s|;)/);
    expect(response.headers.get("strict-transport-security")).toContain("max-age=");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(observations[0]).toMatchObject({
      requestId: "edge-req-123", method: "GET", route: "/healthz", status: 200,
    });
  });

  it("does not echo invalid request ids and never exposes unexpected 5xx details", async () => {
    const identity = { keyId: "k", namespace: "acme", actor: "a", role: "agent" as const };
    const base = await start(deps({ auth: { async resolve() { return identity; } } }));
    const response = await fetch(`${base}/v1/mem/stats`, {
      method: "POST",
      headers: {
        authorization: "Bearer hm_valid",
        "content-type": "application/json",
        "x-request-id": "bad id with spaces",
      },
      body: "{}",
    });
    const body = await response.json() as { error: string; code: string };

    expect(response.status).toBe(500);
    expect(response.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(body).toEqual({ error: "internal server error", code: "internal" });
    expect(JSON.stringify(body)).not.toContain("secret");
  });

  it("uses a dedicated throttle before invoking public authentication handlers", async () => {
    let attempts = 0;
    let logins = 0;
    const base = await start(deps({
      auth: {
        async resolve() { return null; },
        async login() { logins += 1; return null; },
      },
      authThrottle: {
        async consume(bucket) {
          expect(bucket).toMatch(/^auth:/);
          attempts += 1;
          return attempts === 1
            ? { allowed: true, retryAfterSec: 0 }
            : { allowed: false, retryAfterSec: 42 };
        },
      },
    }));
    const request = () => fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "a@example.test", password: "wrong" }),
    });

    expect((await request()).status).toBe(401);
    const throttled = await request();
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get("retry-after")).toBe("42");
    expect(logins).toBe(1);
  });

  it("resets the authentication throttle after a successful login", async () => {
    const calls: string[] = [];
    const base = await start(deps({
      auth: {
        async resolve() { return null; },
        async login() { return { token: "session", user: { id: "user-1" } }; },
      },
      authThrottle: {
        async consume(bucket) {
          calls.push(`consume:${bucket}`);
          return { allowed: true, retryAfterSec: 0 };
        },
        async reset(bucket) { calls.push(`reset:${bucket}`); },
      },
    }));
    const response = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "a@example.test", password: "valid" }),
    });

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(2);
    expect(calls[0]?.replace("consume:", "")).toBe(calls[1]?.replace("reset:", ""));
  });

  // Behind a proxy every caller shares one socket peer, so bucketing on it
  // collapses the whole tenant base into ONE limit — a single actor tripping
  // it locks everyone out. These pin the address the bucket is derived from.
  describe("rate-limit bucketing behind a reverse proxy", () => {
    async function buckets(
      serverDeps: Partial<HttpServerDeps>,
      forwardedFor: readonly (string | undefined)[],
    ): Promise<string[]> {
      const seen: string[] = [];
      const base = await start(deps({
        auth: {
          async resolve() { return null; },
          async login() { return null; },
        },
        authThrottle: {
          async consume(bucket) {
            seen.push(bucket);
            return { allowed: true, retryAfterSec: 0 };
          },
        },
        ...serverDeps,
      }));
      for (const header of forwardedFor) {
        const response = await fetch(`${base}/auth/login`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(header === undefined ? {} : { "x-forwarded-for": header }),
          },
          body: JSON.stringify({ email: "a@example.test", password: "wrong" }),
        });
        expect(response.status).toBe(401);
      }
      return seen;
    }

    it("gives distinct clients distinct buckets when a proxy is trusted", async () => {
      const seen = await buckets(
        { trustedProxyHops: 1 },
        ["203.0.113.7", "203.0.113.8"],
      );
      expect(seen).toHaveLength(2);
      expect(seen[0]).not.toBe(seen[1]);
    });

    it("ignores a caller-forged prefix and keys on the proxy-appended address", async () => {
      // What Envoy actually produces when the caller sends its own header:
      // the forged value is first, the real peer is APPENDED last.
      const seen = await buckets(
        { trustedProxyHops: 1 },
        ["198.51.100.1, 203.0.113.7", "198.51.100.99, 203.0.113.7"],
      );
      expect(seen[0]).toBe(seen[1]);
    });

    it("ignores x-forwarded-for entirely when no proxy is trusted", async () => {
      const seen = await buckets({}, ["203.0.113.7", "203.0.113.8"]);
      expect(seen[0]).toBe(seen[1]);
    });

    it("falls back to the socket peer when the chain is shorter than the hop count", async () => {
      const seen = await buckets(
        { trustedProxyHops: 2 },
        ["203.0.113.7", undefined],
      );
      expect(seen[0]).toBe(seen[1]);
    });
  });
});

describe("bounded RED telemetry", () => {
  it("uses route templates and bounded series without request ids as labels", () => {
    const metrics = new BoundedHttpRedMetrics({ maxSeries: 2, sampleCapacity: 4 });
    const base = {
      method: "GET",
      status: 200,
      durationMs: 5,
      requestId: "unique-request",
      traceId: "unique-trace",
    };
    metrics.observe({ ...base, route: "/v1/mem/write/ticket-a" });
    metrics.observe({ ...base, route: "/v1/mem/write/ticket-b", status: 500, durationMs: 50 });
    metrics.observe({ ...base, route: "/healthz" });
    metrics.observe({ ...base, route: "/unbounded/user/value" });

    const snapshot = metrics.snapshot();
    expect(snapshot.series.length).toBeLessThanOrEqual(3); // two bounded + overflow
    expect(snapshot.series.find((series) => series.route === "/v1/mem/write/:ticket"))
      .toMatchObject({ requests: 2, errors: 1 });
    expect(JSON.stringify(snapshot)).not.toContain("unique-request");
    expect(JSON.stringify(snapshot)).not.toContain("unique-trace");
  });
});
