/**
 * Module B (M4) tests — mem.forget erasure engine.
 *
 * Hermetic: in-memory PGlite (vector ext), HashEmbedder, an ephemeral generated
 * ed25519 keypair. Zero network, zero Docker.
 *
 * Proves:
 *   - forget({kind:"actor",...}) hard-deletes the matching rows: gone from
 *     index.getById AND index.vectorSearch;
 *   - one tombstone written per erased id (tombstones == erasedCount);
 *   - the DeletionCertificate verifies (verifyCertificate === true);
 *   - a tampered certificate (mutate erasedCount) verifies FALSE;
 *   - erasing ONE link of a supersede chain does NOT FK-crash (the surviving
 *     link's dangling supersedes is nulled);
 *   - a target outside the caller's subtree erases 0 rows;
 *   - the audit trail survives (D4 append-only): a pre-existing audit row for an
 *     erased memory is still present after forget, and a `forget` row is added.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
} from "../src/erasure/certificate.js";
import { generateSigningKey, loadSigningKey } from "../src/erasure/keys.js";
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
// One ephemeral keypair for the whole suite so every cert shares a public key.
const signingKey = loadSigningKey();

const NOW = "2026-07-08T00:00:00.000Z";

function ownerOf(namespace: string, actor = "owner:test"): Identity {
  return { keyId: `key-${namespace}`, namespace, actor, role: "owner" };
}

function makeObj(
  overrides: Partial<MemoryObject> & { id: string; namespace: string; content: string },
): MemoryObject {
  return {
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
    ...overrides,
  };
}

async function plant(
  obj: Partial<MemoryObject> & { id: string; namespace: string; content: string },
): Promise<MemoryObject> {
  const full = makeObj(obj);
  const [embedding] = await embedder.embed([full.content]);
  await index.insert(full, embedding);
  return full;
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

async function tombstoneCount(certificateId: string): Promise<number> {
  const res = await db.query(
    `SELECT COUNT(*) AS n FROM tombstones WHERE certificate_id = $1`,
    [certificateId],
  );
  return Number(res.rows[0].n);
}

/** True iff a row still physically exists (bypasses the upward ACL). */
async function rowExists(id: string): Promise<boolean> {
  const res = await db.query(`SELECT 1 FROM memory_objects WHERE id = $1`, [id]);
  return res.rows.length > 0;
}

/** Plant an entity_registry row directly (bypasses the write path). */
async function plantEntity(
  id: string,
  namespace: string,
  canonicalName: string,
  aliases: string[],
): Promise<void> {
  await db.query(
    `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, embedding, created_at)
     VALUES ($1, $2, $3, $4, NULL, $5)`,
    [id, namespace, canonicalName, JSON.stringify(aliases), NOW],
  );
}

async function entityExists(id: string): Promise<boolean> {
  const res = await db.query(`SELECT 1 FROM entity_registry WHERE id = $1`, [id]);
  return res.rows.length > 0;
}

// ---------------------------------------------------------------------------
// (1) forget by actor: hard-deletes, tombstones, verifiable certificate
// ---------------------------------------------------------------------------

describe("forget by actor", () => {
  it("hard-deletes matching rows, writes tombstones, mints a verifying cert", async () => {
    const ns = "acme/support";
    const owner = ownerOf(ns);

    // Four facts: 3 authored by alice, 1 by bob (bob survives).
    const f1 = await plant({
      id: "01F1",
      namespace: ns,
      content: "The Reno warehouse ships west-coast orders same day.",
      provenance: [{ source: "conversation", actor: "alice", ts: NOW }],
    });
    const f2 = await plant({
      id: "01F2",
      namespace: ns,
      content: "Refunds are processed within five business days.",
      provenance: [{ source: "conversation", actor: "alice", ts: NOW }],
    });
    const f3 = await plant({
      id: "01F3",
      namespace: ns,
      content: "Support hours are nine to five on weekdays.",
      provenance: [{ source: "conversation", actor: "alice", ts: NOW }],
    });
    const bobFact = await plant({
      id: "01B1",
      namespace: ns,
      content: "The loyalty program grants points per purchase.",
      provenance: [{ source: "conversation", actor: "bob", ts: NOW }],
    });

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "alice" },
      owner,
    );

    // Erased exactly the three alice facts.
    expect(result.erasedCount).toBe(3);
    expect(result.tombstones).toBe(3);
    expect(new Set(result.certificate.erasedIds)).toEqual(
      new Set([f1.id, f2.id, f3.id]),
    );

    // Gone from getById.
    for (const id of [f1.id, f2.id, f3.id]) {
      const got = await index.getById(id, ns);
      expect(got.obj).toBeNull();
      expect(got.denied).toBe(false); // truly absent, not merely hidden
    }
    // Bob's fact survives.
    expect((await index.getById(bobFact.id, ns)).obj).not.toBeNull();

    // Gone from vectorSearch — search for each erased fact's own content and
    // assert none of the erased ids come back.
    for (const f of [f1, f2, f3]) {
      const [emb] = await embedder.embed([f.content]);
      const hits = await index.vectorSearch(ns, emb, 10);
      const hitIds = hits.map((h) => h.obj.id);
      expect(hitIds).not.toContain(f.id);
    }

    // Tombstones == erasedCount, all tagged with the cert id.
    expect(await tombstoneCount(result.certificate.id)).toBe(3);

    // Certificate verifies against the separately trusted kernel public key.
    expect(
      verifyCertificate(result.certificate, signingKey.publicKeyBase64),
    ).toBe(true);
    expect(result.certificate.algorithm).toBe("ed25519");
    expect(result.certificate.namespace).toBe(ns);
    expect(result.certificate.actor).toBe(owner.actor);
  });
});

// ---------------------------------------------------------------------------
// (2) tampering: mutate a field → verification fails
// ---------------------------------------------------------------------------

describe("certificate tamper detection", () => {
  it("rejects an attacker-signed certificate against the trusted kernel key", async () => {
    const ns = "acme/forged-certificate";
    const owner = ownerOf(ns);
    await plant({
      id: "01FORGED1",
      namespace: ns,
      content: "A fact whose deletion certificate is used as the forgery template.",
      provenance: [{ source: "conversation", actor: "victim", ts: NOW }],
    });

    const { certificate } = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "victim" },
      owner,
    );
    const attackerKey = generateSigningKey();
    const { signature: _trustedSignature, ...trustedPayload } = certificate;
    const attackerPayload = {
      ...trustedPayload,
      publicKey: attackerKey.publicKeyBase64,
    };
    const forged: DeletionCertificate = {
      ...attackerPayload,
      signature: signCertificate(attackerPayload, attackerKey),
    };

    expect(
      verifyCertificate(forged, signingKey.publicKeyBase64),
    ).toBe(false);
  });

  it("a mutated erasedCount fails verification", async () => {
    const ns = "acme/tamper";
    const owner = ownerOf(ns);
    await plant({
      id: "01T1",
      namespace: ns,
      content: "A single fact to erase and then tamper the certificate.",
      provenance: [{ source: "conversation", actor: "carol", ts: NOW }],
    });

    const { certificate } = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "carol" },
      owner,
    );
    expect(
      verifyCertificate(certificate, signingKey.publicKeyBase64),
    ).toBe(true);

    // Tamper erasedCount.
    const tampered: DeletionCertificate = { ...certificate, erasedCount: 999 };
    expect(
      verifyCertificate(tampered, signingKey.publicKeyBase64),
    ).toBe(false);

    // Tampering other fields also fails.
    expect(
      verifyCertificate(
        { ...certificate, erasedIds: ["forged-id"] },
        signingKey.publicKeyBase64,
      ),
    ).toBe(false);
    expect(
      verifyCertificate(
        { ...certificate, actor: "mallory" },
        signingKey.publicKeyBase64,
      ),
    ).toBe(false);
    expect(
      verifyCertificate(
        { ...certificate, namespace: "acme/other" },
        signingKey.publicKeyBase64,
      ),
    ).toBe(false);
    // Flipping a byte of the signature fails.
    const badSig = Buffer.from(certificate.signature, "base64");
    badSig[0] ^= 0xff;
    expect(
      verifyCertificate(
        { ...certificate, signature: badSig.toString("base64") },
        signingKey.publicKeyBase64,
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (3) supersede chain: erasing ONE link does not FK-crash
// ---------------------------------------------------------------------------

describe("supersede chain FK safety", () => {
  it("erasing a superseded prior link nulls the surviving link's FK, no crash", async () => {
    const ns = "acme/chain";
    const owner = ownerOf(ns);

    // prior <- newer (newer.supersedes = prior.id). prior authored by dave,
    // newer authored by erin. Erasing dave removes ONLY prior; newer survives
    // and its supersedes must be nulled (else the DELETE FK-crashes).
    const prior = await plant({
      id: "01P1",
      namespace: ns,
      content: "The old policy allowed refunds within thirty days.",
      provenance: [{ source: "conversation", actor: "dave", ts: NOW }],
      tValidTo: NOW, // closed by supersedence
    });
    const newer = await plant({
      id: "01P2",
      namespace: ns,
      content: "The new policy allows refunds within fourteen days.",
      supersedes: prior.id,
      provenance: [{ source: "conversation", actor: "erin", ts: NOW }],
    });

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "dave" },
      owner,
    );

    expect(result.erasedCount).toBe(1);
    expect(result.certificate.erasedIds).toEqual([prior.id]);

    // prior gone; newer survives with supersedes nulled.
    expect((await index.getById(prior.id, ns)).obj).toBeNull();
    const survivor = await index.getById(newer.id, ns);
    expect(survivor.obj).not.toBeNull();
    expect(survivor.obj?.supersedes).toBeNull();
    expect(
      verifyCertificate(result.certificate, signingKey.publicKeyBase64),
    ).toBe(true);
  });

  it("erasing a WHOLE chain deletes both links together", async () => {
    const ns = "acme/wholechain";
    const owner = ownerOf(ns);
    const prior = await plant({
      id: "01W1",
      namespace: ns,
      content: "Frank once said the deadline was Monday.",
      provenance: [{ source: "conversation", actor: "frank", ts: NOW }],
      tValidTo: NOW,
    });
    const newer = await plant({
      id: "01W2",
      namespace: ns,
      content: "Frank now says the deadline is Wednesday.",
      supersedes: prior.id,
      provenance: [{ source: "conversation", actor: "frank", ts: NOW }],
    });

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "frank" },
      owner,
    );
    expect(result.erasedCount).toBe(2);
    expect((await index.getById(prior.id, ns)).obj).toBeNull();
    expect((await index.getById(newer.id, ns)).obj).toBeNull();
    expect(
      verifyCertificate(result.certificate, signingKey.publicKeyBase64),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (4) subtree scoping: out-of-subtree target erases 0
// ---------------------------------------------------------------------------

describe("subtree scoping", () => {
  it("an out-of-subtree namespace target erases 0 rows", async () => {
    // Two sibling roots. The caller lives under `globex`; a namespace target
    // naming `acme/...` is outside its subtree → 0 erased.
    await plant({
      id: "01A9",
      namespace: "acme/secret",
      content: "Acme confidential canary that globex must not erase.",
      provenance: [{ source: "conversation", actor: "acme-user", ts: NOW }],
    });
    const globexOwner = ownerOf("globex");

    const nsResult = await forget(
      { db, audit, signingKey },
      { kind: "namespace", value: "acme/secret" },
      globexOwner,
    );
    expect(nsResult.erasedCount).toBe(0);
    expect(nsResult.certificate.erasedIds).toEqual([]);
    // Still a valid, verifiable "erased nothing" certificate.
    expect(
      verifyCertificate(nsResult.certificate, signingKey.publicKeyBase64),
    ).toBe(true);

    // The acme row is physically untouched (it lives in acme's subtree; the
    // upward ACL means an "acme" caller can't SEE a descendant row, so we
    // check physical existence directly).
    expect(await rowExists("01A9")).toBe(true);
  });

  it("an actor target only erases rows within the caller's subtree", async () => {
    // Same actor name 'zed' authored a row under acme AND under globex. A
    // globex owner erasing actor=zed must NOT touch the acme row.
    await plant({
      id: "01Z1",
      namespace: "acme/team",
      content: "Zed wrote this acme note.",
      provenance: [{ source: "conversation", actor: "zed", ts: NOW }],
    });
    await plant({
      id: "01Z2",
      namespace: "globex/team",
      content: "Zed wrote this globex note.",
      provenance: [{ source: "conversation", actor: "zed", ts: NOW }],
    });

    const globexOwner = ownerOf("globex");
    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "zed" },
      globexOwner,
    );
    expect(result.erasedCount).toBe(1);
    expect(result.certificate.erasedIds).toEqual(["01Z2"]);
    // acme row survives (descendant of acme — check physical existence).
    expect(await rowExists("01Z1")).toBe(true);
    // globex row gone.
    expect(await rowExists("01Z2")).toBe(false);
    expect((await index.getById("01Z2", "globex/team")).obj).toBeNull();
  });

  it("a memory target outside the caller's subtree erases 0", async () => {
    await plant({
      id: "01M9",
      namespace: "acme/vault",
      content: "A single acme fact addressed by id.",
      provenance: [{ source: "conversation", actor: "acme-user", ts: NOW }],
    });
    const globexOwner = ownerOf("globex");
    const result = await forget(
      { db, audit, signingKey },
      { kind: "memory", value: "01M9" },
      globexOwner,
    );
    expect(result.erasedCount).toBe(0);
    expect(await rowExists("01M9")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (5) audit trail survives (D4 append-only)
// ---------------------------------------------------------------------------

describe("audit trail survives erasure", () => {
  it("pre-existing audit rows for erased memory stay; a forget row is appended", async () => {
    const ns = "acme/audited";
    const owner = ownerOf(ns);
    const f = await plant({
      id: "01AU1",
      namespace: ns,
      content: "A fact that was read before it was erased.",
      provenance: [{ source: "conversation", actor: "grace", ts: NOW }],
    });

    // Simulate the original write + a later read being audited (D4).
    await audit.append({
      ts: NOW,
      actor: "grace",
      agentId: "agent-1",
      op: "write",
      memoryId: f.id,
      namespace: ns,
      purpose: null,
      result: "ok",
    });
    await audit.append({
      ts: NOW,
      actor: "reader",
      agentId: "agent-2",
      op: "read",
      memoryId: f.id,
      namespace: ns,
      purpose: "support",
      result: "ok",
    });

    const before = await audit.count(ns);

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "grace" },
      owner,
    );
    expect(result.erasedCount).toBe(1);

    // The row is gone from memory_objects...
    expect((await index.getById(f.id, ns)).obj).toBeNull();

    // ...but its audit history survives, and a `forget` row was appended.
    const events = await audit.list(ns, { limit: 100 });
    const opsForMemory = events
      .filter((e) => e.memoryId === f.id)
      .map((e) => e.op);
    expect(opsForMemory).toContain("write");
    expect(opsForMemory).toContain("read");

    const after = await audit.count(ns);
    expect(after).toBe(before + 1); // exactly one new row: the forget
    expect(events.some((e) => e.op === "forget" && e.result === "ok")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (6) erasure completeness — content must not survive in DERIVED/unerased paths
// ---------------------------------------------------------------------------

describe("erasure scrubs derived paths", () => {
  it("scrubs a fragmentation_reports row in the subtree that embeds the erased content", async () => {
    const ns = "acme/frag";
    const owner = ownerOf(ns);
    const f = await plant({
      id: "01FR1",
      namespace: ns,
      content: "Dana Whitfield's shipping address is 99 Oak Street, Springfield.",
      provenance: [{ source: "conversation", actor: "ivan", ts: NOW }],
    });

    // A report generated BEFORE the erasure embeds the verbatim fact content
    // (as DbFragmentationReader copies content into member.content).
    const reportJson = JSON.stringify({
      namespace: ns,
      ranAt: NOW,
      duplicateClusters: [
        { members: [{ ref: f.id, content: f.content }], cosine: 0.99 },
      ],
      contradictions: [],
    });
    await db.query(
      `INSERT INTO fragmentation_reports (id, namespace, ran_at, json)
       VALUES ($1, $2, $3, $4::jsonb)`,
      ["01FRREPORT0000000000000001", ns, NOW, reportJson],
    );
    // A sibling tenant's report must be UNTOUCHED (no cross-tenant scrub).
    await db.query(
      `INSERT INTO fragmentation_reports (id, namespace, ran_at, json)
       VALUES ($1, $2, $3, $4::jsonb)`,
      ["01FRREPORT0000000000000002", "globex/frag", NOW, JSON.stringify({ note: "globex" })],
    );

    // Sanity: the content is in the report before the erasure.
    const before = await db.query(
      `SELECT json::text AS j FROM fragmentation_reports WHERE id = $1`,
      ["01FRREPORT0000000000000001"],
    );
    expect(String((before.rows[0] as { j: string }).j)).toContain("Dana Whitfield");

    const result = await forget(
      { db, audit, signingKey },
      { kind: "actor", value: "ivan" },
      owner,
    );
    expect(result.erasedCount).toBe(1);
    expect(await rowExists(f.id)).toBe(false);

    // The subtree report row is GONE — the erased content no longer survives.
    const gone = await db.query(
      `SELECT 1 FROM fragmentation_reports WHERE id = $1`,
      ["01FRREPORT0000000000000001"],
    );
    expect(gone.rows.length).toBe(0);
    // The sibling tenant's report is untouched.
    const sibling = await db.query(
      `SELECT 1 FROM fragmentation_reports WHERE id = $1`,
      ["01FRREPORT0000000000000002"],
    );
    expect(sibling.rows.length).toBe(1);
  });

  it("deletes the entity_registry naming row (canonical_name = the erased person's PII)", async () => {
    const ns = "acme/registry";
    const owner = ownerOf(ns);
    // A fact mentioning Zephyr, plus its entity_registry naming row.
    await plant({
      id: "01ER1",
      namespace: ns,
      content: "Zephyr requested account closure.",
      provenance: [{ source: "conversation", actor: "jane", ts: NOW }],
    });
    await plantEntity("ent-zephyr-acme", ns, "Zephyr", ["Zeph"]);
    // A sibling tenant's Zephyr registry row must NOT be deleted.
    await plantEntity("ent-zephyr-globex", "globex/registry", "Zephyr", []);

    const result = await forget(
      { db, audit, signingKey },
      { kind: "entity", value: "Zephyr" },
      owner,
    );
    expect(result.erasedCount).toBe(1);
    expect(await rowExists("01ER1")).toBe(false);

    // The naming row (the PII) is gone from the caller's subtree...
    expect(await entityExists("ent-zephyr-acme")).toBe(false);
    // ...but the sibling tenant's naming row survives (no cross-tenant delete).
    expect(await entityExists("ent-zephyr-globex")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (7) regression — a SIBLING tenant's alias graph must not widen erasure
// ---------------------------------------------------------------------------

describe("entity erasure is subtree-scoped against a sibling's alias graph", () => {
  it("a sibling alias link does NOT pull an unrelated caller fact into the erasure", async () => {
    // Sibling globex links Nimbus<->Falcon in ITS registry; acme has no such
    // link. acme/support holds two UNRELATED facts: one mentions Nimbus, one
    // mentions Falcon. Erasing entity 'Nimbus' as acme must erase ONLY the
    // Nimbus fact — the sibling's Falcon alias must not widen the match.
    const ns = "acme/support";
    const owner = ownerOf(ns);
    const nimbus = await plant({
      id: "01NB1",
      namespace: ns,
      content: "Nimbus is the internal codename for the launch.",
      provenance: [{ source: "conversation", actor: "kyle", ts: NOW }],
    });
    const falcon = await plant({
      id: "01FL1",
      namespace: ns,
      content: "Falcon is an unrelated project owned by another team.",
      provenance: [{ source: "conversation", actor: "kyle", ts: NOW }],
    });
    // Sibling registry: Nimbus aliases Falcon (the poison link).
    await plantEntity("ent-nimbus-globex", "globex/team", "Nimbus", ["Falcon"]);

    const result = await forget(
      { db, audit, signingKey },
      { kind: "entity", value: "Nimbus" },
      owner,
    );

    // ONLY the Nimbus fact is erased; the unrelated Falcon fact survives.
    expect(result.erasedCount).toBe(1);
    expect(result.certificate.erasedIds).toEqual([nimbus.id]);
    expect(await rowExists(nimbus.id)).toBe(false);
    expect(await rowExists(falcon.id)).toBe(true);
  });
});

describe("forget atomic audit", () => {
  it("rolls back content, tombstones, and certificate when the success audit cannot commit", async () => {
    const ns = "acme/atomic-audit";
    const owner = ownerOf(ns);
    await plant({
      id: "01ATOMICFORGET1",
      namespace: ns,
      content: "Atomic erasure audit canary.",
      provenance: [{ source: "conversation", actor: "atomic-user", ts: NOW }],
    });
    const failingDb: Db = {
      query: (sql, params) => db.query(sql, params),
      close: () => Promise.resolve(),
      transaction: (fn) => db.transaction((tx) => {
        const failingTx: Db = {
          query: (sql, params) => {
            if (/INSERT INTO audit_log/i.test(sql)) throw new Error("injected audit failure");
            return tx.query(sql, params);
          },
          transaction: tx.transaction.bind(tx),
          close: tx.close.bind(tx),
        };
        return fn(failingTx);
      }),
    };

    await expect(forget(
      { db: failingDb, audit, signingKey },
      { kind: "actor", value: "atomic-user" },
      owner,
    )).rejects.toThrow(/injected audit failure/);
    expect(await rowExists("01ATOMICFORGET1")).toBe(true);
    expect((await db.query(
      "SELECT count(*) AS n FROM tombstones WHERE memory_id = '01ATOMICFORGET1'",
    )).rows[0]!.n).toBe(0);
  });
});
