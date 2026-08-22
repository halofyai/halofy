/**
 * M9 #11a — public per-org discovery site (E28–E30).
 *
 * Hermetic unit tests over structural stub deps (no PGlite): the module's
 * data surface is MemoryIndex.listCandidates + TenantRegistry.get, both
 * stubbed here to attack the redaction fence directly. The SQL-side fences
 * (source-access, classification read gate, TTL, status) are MemoryIndex's
 * own and are covered by its tests; these tests attack what #11a adds.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent, MemoryObject, Tenant } from "../src/types.js";
import {
  isPublicRow,
  matchPublicDiscoveryPath,
  redactForPublic,
  servePublicDiscovery,
  type PublicDiscoveryDeps,
} from "../src/discovery/public.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let seq = 0;
function row(overrides: Partial<MemoryObject> = {}): MemoryObject {
  seq += 1;
  return {
    id: `01TESTROW${String(seq).padStart(17, "0")}`,
    namespace: "acme",
    scope: "org",
    tier: "L2",
    backendRef: "inline",
    content: `public fact ${seq}`,
    type: "semantic",
    confidence: 0.9,
    eventTime: null,
    assertionTime: "2026-07-01T00:00:00.000Z",
    tValidFrom: "2026-07-01T00:00:00.000Z",
    tValidTo: null,
    supersedes: null,
    provenance: [
      {
        ts: "2026-07-01T00:00:00.000Z",
        source: "conversation",
        actor: "alice@acme.com",
        sourceId: "notion:wiki",
      },
    ],
    classification: {
      sensitivity: "public",
      piiSubjects: [],
      secretKinds: [],
      allowedDestinations: [],
    },
    sourceAccess: { principals: [], groups: [] },
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
    ...overrides,
  };
}

const ACME: Tenant = {
  id: "acme",
  name: "Acme Corp",
  status: "active",
  monthlyBudgetUsd: null,
  rateLimitPerMin: null,
  createdAt: "2026-01-01T00:00:00.000Z",
};

function makeDeps(opts: {
  tenant?: Tenant | null;
  rows?: MemoryObject[];
  allow?: boolean;
}): { deps: PublicDiscoveryDeps; audits: AuditEvent[]; asked: string[] } {
  const audits: AuditEvent[] = [];
  const asked: string[] = [];
  const deps: PublicDiscoveryDeps = {
    index: {
      listCandidates: async (ns) => {
        asked.push(ns);
        return opts.rows ?? [];
      },
    },
    tenants: {
      get: async (id) =>
        opts.tenant !== undefined && opts.tenant !== null && opts.tenant.id === id
          ? opts.tenant
          : null,
    },
    audit: {
      append: async (e) => {
        audits.push(e);
      },
    },
    ...(opts.allow !== undefined
      ? { rateLimiter: { allow: () => opts.allow as boolean } }
      : {}),
  };
  return { deps, audits, asked };
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

describe("matchPublicDiscoveryPath", () => {
  it("matches page and llms.txt forms", () => {
    expect(matchPublicDiscoveryPath("/acme")).toEqual({
      orgSlug: "acme",
      format: "page",
    });
    expect(matchPublicDiscoveryPath("/acme/llms.txt")).toEqual({
      orgSlug: "acme",
      format: "llms",
    });
  });

  it("never matches reserved or multi-segment paths", () => {
    for (const p of [
      "/",
      "/v1",
      "/v1/mem/manifest",
      "/console",
      "/oauth",
      "/oauth/token",
      "/.well-known",
      "/.well-known/oauth-authorization-server",
      "/health",
      "/favicon.ico",
      "/robots.txt",
      "/llms.txt",
      "/acme/other",
      "/acme/llms.txt/extra",
      "/..",
      "/.hidden",
    ]) {
      expect(matchPublicDiscoveryPath(p), p).toBeNull();
    }
  });

  it("rejects encoded slashes and oversized slugs", () => {
    expect(matchPublicDiscoveryPath("/a%2Fb")).toBeNull();
    expect(matchPublicDiscoveryPath("/a%5Cb")).toBeNull();
    expect(matchPublicDiscoveryPath("/" + "a".repeat(200))).toBeNull();
    expect(matchPublicDiscoveryPath("/%ZZ")).toBeNull(); // bad encoding
  });
});

// ---------------------------------------------------------------------------
// Redaction filter (E29)
// ---------------------------------------------------------------------------

describe("isPublicRow", () => {
  it("accepts only explicitly public, clean, root-namespace canonical rows", () => {
    expect(isPublicRow(row(), "acme")).toBe(true);
    // internal / confidential / missing classification are all excluded
    expect(
      isPublicRow(
        row({
          classification: {
            sensitivity: "internal",
            piiSubjects: [],
            secretKinds: [],
            allowedDestinations: [],
          },
        }),
        "acme",
      ),
    ).toBe(false);
    const noClass = row();
    delete (noClass as { classification?: unknown }).classification;
    expect(isPublicRow(noClass, "acme")).toBe(false);
    // public-but-PII/secret-stamped is a labeling error, not publishable
    expect(
      isPublicRow(
        row({
          classification: {
            sensitivity: "public",
            piiSubjects: ["bob@acme.com"],
            secretKinds: [],
            allowedDestinations: [],
          },
        }),
        "acme",
      ),
    ).toBe(false);
    // mounted / descendant rows never surface on the org page
    expect(isPublicRow(row({ namespace: "globex" }), "acme")).toBe(false);
    expect(isPublicRow(row({ namespace: "acme/eng" }), "acme")).toBe(false);
    // superseded, non-canonical, pointer, cache rows excluded via isManifestRow
    expect(isPublicRow(row({ tValidTo: "2026-07-02T00:00:00.000Z" }), "acme")).toBe(false);
    expect(isPublicRow(row({ status: "archived" }), "acme")).toBe(false);
    expect(isPublicRow(row({ type: "pointer" }), "acme")).toBe(false);
    expect(
      isPublicRow(
        row({ provenance: [{ source: "live-fetch", actor: "a", cache: true } as never] }),
        "acme",
      ),
    ).toBe(false);
  });
});

describe("redactForPublic", () => {
  it("strips actor, session, and source identifiers", () => {
    const redacted = redactForPublic(row());
    expect(redacted.provenance).toHaveLength(1);
    expect(redacted.provenance[0].actor).toBe("public");
    expect(redacted.provenance[0].sourceId).toBe("public");
    expect(JSON.stringify(redacted)).not.toContain("alice@acme.com");
    expect(JSON.stringify(redacted)).not.toContain("notion:wiki");
  });
});

// ---------------------------------------------------------------------------
// servePublicDiscovery (E28 / E30 / D4)
// ---------------------------------------------------------------------------

describe("servePublicDiscovery", () => {
  it("unknown slug, inactive tenant, and empty org return the IDENTICAL 404 and audit denied", async () => {
    const unknown = makeDeps({ tenant: null });
    const suspended = makeDeps({ tenant: { ...ACME, status: "suspended" } });
    const empty = makeDeps({ tenant: ACME, rows: [] });

    const r1 = await servePublicDiscovery(unknown.deps, "acme", "llms");
    const r2 = await servePublicDiscovery(suspended.deps, "acme", "llms");
    const r3 = await servePublicDiscovery(empty.deps, "acme", "llms");

    expect(r1.status).toBe(404);
    expect(r2).toEqual(r1); // anti-fingerprinting: byte-identical
    expect(r3).toEqual(r1);
    for (const { audits } of [unknown, suspended, empty]) {
      expect(audits).toHaveLength(1);
      expect(audits[0].result).toBe("denied");
      expect(audits[0].op).toBe("read");
      expect(audits[0].purpose).toBe("public-discovery");
      expect(audits[0].actor).toBe("public");
    }
  });

  it("resolves the namespace server-side from the slug (E28)", async () => {
    const { deps, asked } = makeDeps({ tenant: ACME, rows: [row()] });
    await servePublicDiscovery(deps, "acme", "llms");
    expect(asked).toEqual(["acme"]); // tenant.id, never caller input beyond the slug
  });

  it("llms.txt renders only the public subset with no actor/source/namespace leakage (E29/E30)", async () => {
    const rows = [
      row({ content: "Our product supports SSO." }),
      row({
        content: "SECRET internal roadmap",
        classification: {
          sensitivity: "internal",
          piiSubjects: [],
          secretKinds: [],
          allowedDestinations: [],
        },
      }),
      row({ content: "mounted from elsewhere", namespace: "globex" }),
    ];
    const { deps, audits } = makeDeps({ tenant: ACME, rows });
    const res = await servePublicDiscovery(deps, "acme", "llms");

    expect(res.status).toBe(200);
    expect(res.contentType).toContain("text/plain");
    expect(res.body).toContain("Acme Corp - public memory index");
    expect(res.body).toContain("Our product supports SSO.");
    expect(res.body).not.toContain("SECRET internal roadmap");
    expect(res.body).not.toContain("mounted from elsewhere");
    expect(res.body).not.toContain("globex");
    expect(res.body).not.toContain("alice@acme.com");
    expect(res.body).not.toContain("notion:wiki");
    // count reflects the redacted subset only
    expect(res.body).toContain("1 entries");
    expect(audits).toHaveLength(1);
    expect(audits[0].result).toBe("ok");
  });

  it("HTML page escapes memory content and stays inline-JS free", async () => {
    const rows = [row({ content: `<script>alert("x")</script> & "quotes"` })];
    const { deps } = makeDeps({ tenant: ACME, rows });
    const res = await servePublicDiscovery(deps, "acme", "page");

    expect(res.status).toBe(200);
    expect(res.contentType).toContain("text/html");
    expect(res.body).not.toContain("<script>alert");
    expect(res.body).toContain("&lt;script&gt;");
    expect(res.body).toContain("Acme Corp");
    // style only — no script tags anywhere in the page
    expect(res.body).not.toContain("<script");
  });

  it("rate-limits with an audited denial (D4)", async () => {
    const { deps, audits } = makeDeps({ tenant: ACME, rows: [row()], allow: false });
    const res = await servePublicDiscovery(deps, "acme", "page");
    expect(res.status).toBe(429);
    expect(audits).toHaveLength(1);
    expect(audits[0].result).toBe("denied");
    expect(audits[0].detail).toContain("rate limit");
  });

  it("maps internal failures to a generic audited 500 (no message leakage)", async () => {
    const audits: AuditEvent[] = [];
    const deps: PublicDiscoveryDeps = {
      index: {
        listCandidates: async () => {
          throw new Error("pg: connection refused at 10.0.0.5");
        },
      },
      tenants: { get: async () => ACME },
      audit: {
        append: async (e) => {
          audits.push(e);
        },
      },
    };
    const res = await servePublicDiscovery(deps, "acme", "llms");
    expect(res.status).toBe(500);
    expect(res.body).not.toContain("10.0.0.5");
    expect(audits).toHaveLength(1);
    expect(audits[0].result).toBe("error");
    expect(audits[0].detail).toContain("connection refused");
  });
});
