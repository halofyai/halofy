/**
 * E6 — mem.forget erases derived usage rows (usage_events, query_traces).
 *
 * Hermetic: in-memory PGlite (vector ext), HashEmbedder, an ephemeral
 * ed25519 keypair. Zero network, zero Docker.
 *
 * Proves:
 *   - actor-target forget hard-deletes that actor's usage rows INSIDE the
 *     caller's subtree (even with zero stored memories), leaves another
 *     actor's rows and out-of-subtree rows, and the signed certificate
 *     enumerates the erased ids;
 *   - namespace-target forget erases the TARGET subtree's usage rows only;
 *   - memory-target forget erases NO usage rows (no linkage exists);
 *   - pre-E6 certificates (without the new fields) still verify.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ulid } from "ulid";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MemoryIndex } from "../src/index/index.js";
import { AuditLog } from "../src/audit/index.js";
import { HashEmbedder } from "../src/embed/index.js";
import { loadConfig } from "../src/config.js";
import { forget } from "../src/erasure/index.js";
import {
  signCertificate,
  verifyCertificate,
  type CertificatePayload,
} from "../src/erasure/certificate.js";
import { loadSigningKey } from "../src/erasure/keys.js";
import type {
  DeletionCertificate,
  Identity,
  MemoryObject,
} from "../src/types.js";

const DIM = 256; // HashEmbedder default dim

let db: Db;
let index: MemoryIndex;
let audit: AuditLog;
const embedder = new HashEmbedder();
const signingKey = loadSigningKey();

const NOW = "2026-07-22T00:00:00.000Z";

function ownerOf(namespace: string, actor = "owner:test"): Identity {
  return { keyId: `key-${namespace}`, namespace, actor, role: "owner" };
}

/** Seed one audit row + its companion usage_events row (FK audit_seq). */
async function seedUsageEvent(
  id: string,
  traceId: string,
  namespace: string,
  actor: string,
): Promise<void> {
  const seq = await audit.appendToWithSeq(db, {
    ts: NOW,
    actor,
    agentId: `key-${namespace}`,
    op: "search",
    memoryId: null,
    namespace,
    purpose: null,
    result: "ok",
  });
  await db.query(
    `INSERT INTO usage_events
       (id, audit_seq, trace_id, ts, namespace, actor, principal, caller_class,
        op, result, latency_ms)
     VALUES ($1, $2, $3, $4, $5, $6, 'human', 'unclassified', 'search', 'ok', 1)`,
    [id, seq, traceId, NOW, namespace, actor],
  );
}

async function seedTrace(traceId: string, namespace: string, actor: string): Promise<void> {
  await db.query(
    `INSERT INTO query_traces (trace_id, ts, namespace, actor, events)
     VALUES ($1, $2, $3, $4, 1)`,
    [traceId, NOW, namespace, actor],
  );
}

async function usageEventExists(id: string): Promise<boolean> {
  const res = await db.query(`SELECT 1 FROM usage_events WHERE id = $1`, [id]);
  return res.rows.length > 0;
}

async function traceExists(traceId: string): Promise<boolean> {
  const res = await db.query(`SELECT 1 FROM query_traces WHERE trace_id = $1`, [traceId]);
  return res.rows.length > 0;
}

/** Plant one L2 memory object directly (bypasses the write path). */
async function plant(id: string, namespace: string, content: string): Promise<void> {
  const obj: MemoryObject = {
    id,
    namespace,
    content,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: NOW,
    tValidFrom: NOW,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "conversation", actor: "alice", ts: NOW }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  const [embedding] = await embedder.embed([content]);
  await index.insert(obj, embedding);
}

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  index = new MemoryIndex(db);
  audit = new AuditLog(db);
});

afterAll(async () => {
  await db.close();
});

describe("forget by actor - E6 usage scrub", () => {
  it("erases the actor's usage rows in-subtree (no memories needed), enumerates them in the cert", async () => {
    const ns = "acme/usage-actor";
    const owner = ownerOf("acme");

    await seedUsageEvent("ue-a1", "trace-a1", ns, "alice");
    await seedTrace("trace-a1", ns, "alice");
    // Another actor in the same subtree — must survive.
    await seedUsageEvent("ue-b1", "trace-b1", ns, "bob");
    await seedTrace("trace-b1", ns, "bob");
    // Same actor OUTSIDE the caller's subtree — must survive.
    await seedUsageEvent("ue-a2", "trace-a2", "other/ns", "alice");
    await seedTrace("trace-a2", "other/ns", "alice");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "alice" },
      owner,
    );

    // No memory objects matched — the usage scrub still ran.
    expect(result.erasedCount).toBe(0);
    expect(await usageEventExists("ue-a1")).toBe(false);
    expect(await traceExists("trace-a1")).toBe(false);
    expect(await usageEventExists("ue-b1")).toBe(true);
    expect(await traceExists("trace-b1")).toBe(true);
    expect(await usageEventExists("ue-a2")).toBe(true);
    expect(await traceExists("trace-a2")).toBe(true);

    // The certificate enumerates the scrubbed derived rows (sorted) — and
    // usage rows get NO tombstones (they are not memory objects).
    expect(result.certificate.usageEventIds).toEqual(["ue-a1"]);
    expect(result.certificate.queryTraceIds).toEqual(["trace-a1"]);
    const tombstones = await db.query(
      `SELECT COUNT(*) AS n FROM tombstones WHERE certificate_id = $1`,
      [result.certificate.id],
    );
    expect(Number(tombstones.rows[0].n)).toBe(0);
    expect(verifyCertificate(result.certificate, signingKey.publicKeyBase64)).toBe(true);
  });

  it("erases only the in-subtree rows when a trace id collides across namespaces", async () => {
    const ns = "acme/usage-collide";
    const owner = ownerOf("acme");

    await seedUsageEvent("ue-c1", "trace-shared", ns, "erin");
    await seedTrace("trace-shared", ns, "erin");
    // Same trace id AND same actor OUTSIDE the caller's subtree — the
    // SQL-scoped scrub must not see these rows, and the composite-key delete
    // must not touch the foreign query_traces row.
    await seedUsageEvent("ue-c2", "trace-shared", "other/ns", "erin");
    await seedTrace("trace-shared", "other/ns", "erin");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "erin" },
      owner,
    );

    expect(await usageEventExists("ue-c1")).toBe(false);
    expect(await usageEventExists("ue-c2")).toBe(true);
    // The colliding foreign trace row survives (D37 composite key).
    expect(await traceExists("trace-shared")).toBe(true);
    const remaining = await db.query(
      `SELECT namespace FROM query_traces WHERE trace_id = $1`,
      ["trace-shared"],
    );
    expect(remaining.rows).toEqual([{ namespace: "other/ns" }]);
    expect(result.certificate.usageEventIds).toEqual(["ue-c1"]);
    expect(result.certificate.queryTraceIds).toEqual(["trace-shared"]);
    expect(verifyCertificate(result.certificate, signingKey.publicKeyBase64)).toBe(true);
  });
});

describe("forget by namespace - E6 usage scrub", () => {
  it("erases usage rows in the TARGET subtree only", async () => {
    const owner = ownerOf("acme");

    await seedUsageEvent("ue-n1", "trace-n1", "acme/usage-ns", "carol");
    await seedTrace("trace-n1", "acme/usage-ns", "carol");
    await seedUsageEvent("ue-n2", "trace-n2", "acme/usage-ns/sub", "carol");
    await seedTrace("trace-n2", "acme/usage-ns/sub", "carol");
    // Sibling subtree of the target — must survive.
    await seedUsageEvent("ue-n3", "trace-n3", "acme/usage-other", "carol");
    await seedTrace("trace-n3", "acme/usage-other", "carol");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "namespace", value: "acme/usage-ns" },
      owner,
    );

    expect(await usageEventExists("ue-n1")).toBe(false);
    expect(await usageEventExists("ue-n2")).toBe(false);
    expect(await traceExists("trace-n1")).toBe(false);
    expect(await traceExists("trace-n2")).toBe(false);
    expect(await usageEventExists("ue-n3")).toBe(true);
    expect(await traceExists("trace-n3")).toBe(true);

    expect(result.certificate.usageEventIds).toEqual(["ue-n1", "ue-n2"]);
    expect(result.certificate.queryTraceIds).toEqual(["trace-n1", "trace-n2"]);
    expect(verifyCertificate(result.certificate, signingKey.publicKeyBase64)).toBe(true);
  });

  it("a namespace target outside the caller's subtree scrubs nothing", async () => {
    const owner = ownerOf("acme/narrow");
    await seedUsageEvent("ue-x1", "trace-x1", "acme/elsewhere", "dana");
    await seedTrace("trace-x1", "acme/elsewhere", "dana");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "namespace", value: "acme/elsewhere" },
      owner,
    );

    expect(await usageEventExists("ue-x1")).toBe(true);
    expect(await traceExists("trace-x1")).toBe(true);
    expect(result.certificate.usageEventIds).toEqual([]);
    expect(result.certificate.queryTraceIds).toEqual([]);
    expect(verifyCertificate(result.certificate, signingKey.publicKeyBase64)).toBe(true);
  });
});

describe("forget by memory - E6 usage scrub", () => {
  it("erases NO usage rows (usage rows carry no memory linkage)", async () => {
    const ns = "acme/usage-memory";
    const owner = ownerOf("acme");
    await plant("01USAGE1", ns, "The halon suppression system inspection is annual.");
    await seedUsageEvent("ue-m1", "trace-m1", ns, "alice");
    await seedTrace("trace-m1", ns, "alice");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "memory", value: "01USAGE1" },
      owner,
    );

    expect(result.erasedCount).toBe(1);
    // The memory is gone; the usage rows stand.
    expect((await index.getById("01USAGE1", ns)).obj).toBeNull();
    expect(await usageEventExists("ue-m1")).toBe(true);
    expect(await traceExists("trace-m1")).toBe(true);
    expect(result.certificate.usageEventIds).toEqual([]);
    expect(result.certificate.queryTraceIds).toEqual([]);
    expect(verifyCertificate(result.certificate, signingKey.publicKeyBase64)).toBe(true);
  });
});

describe("certificate shape compatibility (E6)", () => {
  it("pre-E6 certificates (fields absent) still verify; new fields sign + verify", async () => {
    const base: CertificatePayload = {
      id: ulid(),
      target: { kind: "actor", value: "alice" },
      namespace: "acme",
      erasedIds: ["01A"],
      erasedCount: 1,
      actor: "owner:test",
      issuedAt: NOW,
      algorithm: "ed25519",
      publicKey: signingKey.publicKeyBase64,
    };
    // Old shape: no usageEventIds/queryTraceIds at all.
    const oldCert: DeletionCertificate = {
      ...base,
      signature: signCertificate(base, signingKey),
    };
    expect(verifyCertificate(oldCert, signingKey.publicKeyBase64)).toBe(true);

    // New shape: the derived-row enumerations are part of the signed payload.
    const withUsage: CertificatePayload = {
      ...base,
      usageEventIds: ["ue-1", "ue-2"],
      queryTraceIds: ["trace-1"],
    };
    const newCert: DeletionCertificate = {
      ...withUsage,
      signature: signCertificate(withUsage, signingKey),
    };
    expect(verifyCertificate(newCert, signingKey.publicKeyBase64)).toBe(true);
    // Tampering with the new fields breaks verification.
    const tampered: DeletionCertificate = { ...newCert, usageEventIds: ["ue-3"] };
    expect(verifyCertificate(tampered, signingKey.publicKeyBase64)).toBe(false);
  });
});
