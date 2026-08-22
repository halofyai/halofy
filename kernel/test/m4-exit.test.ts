/**
 * M4 exit criteria (CONTRACTS-M4.md §Exit + §Integrator wiring item 6b) — the
 * whole erasure + governance story through the REAL kernel, hermetic (in-memory
 * PGlite, HashEmbedder, StubLlm, ephemeral signing key; zero network, zero
 * Docker):
 *
 *   (a) mem.forget HARD-DELETES matching content — it is unreachable through
 *       getById + vectorSearch + mem_search + mem_stats afterward — writes one
 *       tombstone per erased id, and mints a certificate that verifies;
 *   (b) a TAMPERED certificate (mutated erasedCount) fails verification;
 *   (c) an AUDITOR's mem.forget is denied AND audited ('denied');
 *   (d) the audit_log rows for the erased memory SURVIVE (append-only D4);
 *   (e) a SUSPENDED tenant's key is denied on EVERY syscall + ingestion;
 *   (f) a per-tenant budget cap BELOW the namespace policy cap trips write
 *       brownout to verbatim (the tenant cap can only lower the effective cap).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import {
  generateSigningKey,
  signCertificate,
  verifyCertificate,
} from "../src/erasure/index.js";
import type { DeletionCertificate, Identity, WriteResult } from "../src/types.js";

const AGENT = "m4-exit";

let kernel: Kernel;
let root: Identity;

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(namespace: string, actor: string, role: Identity["role"]): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

/** Physical-existence check that bypasses the ACL (proves a hard delete). */
async function rowExists(id: string): Promise<boolean> {
  const res = await kernel.db.query(
    `SELECT 1 FROM memory_objects WHERE id = $1`,
    [id],
  );
  return res.rows.length > 0;
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "", // in-memory PGlite
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;
}, 120_000);

afterAll(async () => {
  await kernel.close();
});

// ---------------------------------------------------------------------------
// (a) erasure removes content everywhere + tombstones + verifying certificate
// (b) tampered certificate fails
// (d) audit rows for the erased memory SURVIVE
// ---------------------------------------------------------------------------

describe("M4 exit (a/b/d) - erasure is complete, provable, and audit-preserving", () => {
  it("pins the kernel boot key instead of trusting a certificate's inline key", () => {
    const attackerKey = generateSigningKey();
    const attackerPayload = {
      id: ulid(),
      target: { kind: "actor" as const, value: "victim" },
      namespace: "exit4/forged",
      erasedIds: [ulid()],
      erasedCount: 1,
      actor: "attacker",
      issuedAt: new Date().toISOString(),
      algorithm: "ed25519" as const,
      publicKey: attackerKey.publicKeyBase64,
    };
    const forged: DeletionCertificate = {
      ...attackerPayload,
      signature: signCertificate(attackerPayload, attackerKey),
    };

    expect(
      verifyCertificate(forged, attackerKey.publicKeyBase64),
    ).toBe(true);
    expect(kernel.verifyCertificate(forged)).toBe(false);

    const trustedPayload = {
      ...attackerPayload,
      id: ulid(),
      publicKey: kernel.signingKey.publicKeyBase64,
    };
    const trusted: DeletionCertificate = {
      ...trustedPayload,
      signature: signCertificate(trustedPayload, kernel.signingKey),
    };
    expect(kernel.verifyCertificate(trusted)).toBe(true);
  });

  it("hard-deletes content from every read path, tombstones it, and mints a verifying cert", async () => {
    const ns = "exit4/erase";
    const id = await issue(ns, "owner:erase", "owner");
    await kernel.setPolicy(ns, "rateLimitPerMin: 100000\n");

    const w = sync(
      await kernel.memWrite(
        {
          scope: "org",
          content: "The exit4 vault passphrase is peregrine-samovar-tulip",
          hints: { verbatim: true },
        },
        id,
        AGENT,
      ),
    );
    const factId = w.stored[0]!.id;
    // Access it so it exists in the read paths (and topAccessed).
    await kernel.memRead({ id: factId }, id, AGENT);

    // Sanity: reachable before the erasure.
    const before = await kernel.memRead({ id: factId }, id, AGENT);
    expect(before.found).toBe(true);

    // --- forget by memory id -----------------------------------------------
    const result = await kernel.memForget({ target: { kind: "memory", value: factId } }, id, AGENT);
    expect(result.erasedCount).toBe(1);
    expect(result.tombstones).toBe(1);

    // Certificate verifies against the trusted kernel public key supplied out of band.
    expect(
      verifyCertificate(result.certificate, kernel.signingKey.publicKeyBase64),
    ).toBe(true);
    expect(kernel.verifyCertificate(result.certificate)).toBe(true);
    expect(result.certificate.erasedIds).toContain(factId);

    // (a) unreachable through EVERY read path.
    expect((await kernel.memRead({ id: factId }, id, AGENT)).found).toBe(false);
    expect(await rowExists(factId)).toBe(false); // physically gone (hard delete)

    const [embedding] = await kernel.embedder.embed(["peregrine samovar tulip vault passphrase"]);
    const vhits = await kernel.index.vectorSearch(ns, embedding, 20);
    expect(vhits.some((h) => /peregrine-samovar-tulip/.test(h.obj.content))).toBe(false);

    const shits = await kernel.memSearch({ query: "peregrine samovar tulip vault", k: 20 }, id, AGENT);
    expect(shits.some((h) => /peregrine-samovar-tulip/.test(h.content))).toBe(false);

    const stats = await kernel.memStats({}, id, AGENT);
    expect(stats.topAccessed.some((t) => /peregrine-samovar-tulip/.test(t.content))).toBe(false);

    // Tombstone written.
    const tomb = await kernel.db.query(
      `SELECT count(*)::int AS n FROM tombstones WHERE memory_id = $1`,
      [factId],
    );
    expect(Number((tomb.rows[0] as { n: number }).n)).toBe(1);

    // Certificate persisted + readable by id (within the caller's subtree).
    const persisted = await kernel.getCertificate(result.certificate.id, id);
    expect(persisted).not.toBeNull();
    expect(persisted!.id).toBe(result.certificate.id);

    // (b) a TAMPERED certificate fails verification.
    const tampered: DeletionCertificate = { ...result.certificate, erasedCount: 999 };
    expect(
      verifyCertificate(tampered, kernel.signingKey.publicKeyBase64),
    ).toBe(false);
    const tamperedIds: DeletionCertificate = {
      ...result.certificate,
      erasedIds: [...result.certificate.erasedIds, ulid()],
    };
    expect(
      verifyCertificate(tamperedIds, kernel.signingKey.publicKeyBase64),
    ).toBe(false);

    // (d) the audit_log rows for the erased memory SURVIVE (D4 append-only).
    // The write + read rows that reference factId are still there, plus one
    // new 'forget' row — the deleted content's history is never erased.
    const auditForId = await kernel.db.query(
      `SELECT op, result FROM audit_log WHERE memory_id = $1`,
      [factId],
    );
    expect(auditForId.rows.length).toBeGreaterThan(0);
    const forgetRows = await kernel.db.query(
      `SELECT count(*)::int AS n FROM audit_log WHERE op = 'forget' AND namespace = $1`,
      [ns],
    );
    expect(Number((forgetRows.rows[0] as { n: number }).n)).toBe(1);
  }, 60_000);

  it("lets the platform root owner erase and inspect a tenant certificate", async () => {
    const ns = "exit4/root-admin";
    const tenantOwner = await issue(ns, "owner:tenant", "owner");
    await kernel.setPolicy(ns, "rateLimitPerMin: 100000\n");
    const written = sync(
      await kernel.memWrite(
        {
          scope: "team",
          content: "root-owned compliance erasure target",
          hints: { verbatim: true },
        },
        tenantOwner,
        AGENT,
      ),
    );
    const factId = written.stored[0]!.id;

    const result = await kernel.memForget(
      { target: { kind: "memory", value: factId } },
      root,
      AGENT,
    );
    expect(result.erasedCount).toBe(1);
    expect(await kernel.getCertificate(result.certificate.id, root)).toEqual(
      result.certificate,
    );

    const sibling = await issue("exit4/sibling", "owner:sibling", "owner");
    expect(await kernel.getCertificate(result.certificate.id, sibling)).toBeNull();

    const second = sync(
      await kernel.memWrite(
        {
          scope: "team",
          content: "tenant-issued certificate visible to its parent owner",
          hints: { verbatim: true },
        },
        tenantOwner,
        AGENT,
      ),
    );
    const tenantResult = await kernel.memForget(
      { target: { kind: "memory", value: second.stored[0]!.id } },
      tenantOwner,
      AGENT,
    );
    const parentOwner = await issue("exit4", "owner:parent", "owner");
    expect(await kernel.getCertificate(tenantResult.certificate.id, parentOwner)).toEqual(
      tenantResult.certificate,
    );
  });

  it("erasing one link of a supersede chain does not FK-crash and leaves the survivor intact", async () => {
    const ns = "exit4/chain";
    const id = await issue(ns, "owner:chain", "owner");
    await kernel.setPolicy(ns, "rateLimitPerMin: 100000\n");

    const first = sync(
      await kernel.memWrite(
        { scope: "user", content: "The chain annex code is 1111", hints: { verbatim: true } },
        id,
        AGENT,
      ),
    );
    const second = sync(
      await kernel.memWrite(
        { scope: "user", content: "The chain annex code is now 2222 after the reset", hints: { verbatim: true } },
        id,
        AGENT,
      ),
    );
    expect(second.superseded.length).toBe(0);
    const oldId = first.stored[0]!.id;
    const newId = second.stored[0]!.id;

    // Erase one independent historical observation; the survivor is intact.
    const result = await kernel.memForget({ target: { kind: "memory", value: oldId } }, id, AGENT);
    expect(result.erasedCount).toBe(1);
    expect(await rowExists(oldId)).toBe(false);
    // The survivor is intact and its dangling supersedes link was nulled.
    expect(await rowExists(newId)).toBe(true);
    const survivor = await kernel.db.query(
      `SELECT supersedes FROM memory_objects WHERE id = $1`,
      [newId],
    );
    expect((survivor.rows[0] as { supersedes: string | null }).supersedes).toBeNull();
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (c) auditor mem.forget denied + audited
// ---------------------------------------------------------------------------

describe("M4 exit (c) - auditor cannot erase (denied + audited)", () => {
  it("an auditor's mem.forget throws AuthzError and writes a 'denied' forget audit row", async () => {
    const ns = "exit4/authz";
    const owner = await issue(ns, "owner:authz", "owner");
    await kernel.setPolicy(ns, "rateLimitPerMin: 100000\n");
    const auditor = await issue(ns, "auditor:authz", "auditor");

    const w = sync(
      await kernel.memWrite(
        { scope: "org", content: "The authz secret is cormorant-lattice", hints: { verbatim: true } },
        owner,
        AGENT,
      ),
    );
    const factId = w.stored[0]!.id;

    await expect(
      kernel.memForget({ target: { kind: "memory", value: factId } }, auditor, AGENT),
    ).rejects.toThrow(/may not erase/i);

    // The content is UNTOUCHED (the auditor erased nothing).
    expect(await rowExists(factId)).toBe(true);

    // A 'denied' forget audit row was written for the auditor's attempt.
    const denied = await kernel.db.query(
      `SELECT count(*)::int AS n FROM audit_log
       WHERE op = 'forget' AND result = 'denied' AND namespace = $1 AND actor = $2`,
      [ns, "auditor:authz"],
    );
    expect(Number((denied.rows[0] as { n: number }).n)).toBe(1);
  }, 60_000);

  it("a member and an agent are likewise denied erasure", async () => {
    const ns = "exit4/roles";
    const owner = await issue(ns, "owner:roles", "owner");
    await kernel.setPolicy(ns, "rateLimitPerMin: 100000\n");
    const member = await issue(ns, "member:roles", "member");
    const agent = await issue(ns, "agent:roles", "agent");

    const w = sync(
      await kernel.memWrite(
        { scope: "org", content: "roles secret gannet-obelisk", hints: { verbatim: true } },
        owner,
        AGENT,
      ),
    );
    const factId = w.stored[0]!.id;

    await expect(
      kernel.memForget({ target: { kind: "memory", value: factId } }, member, AGENT),
    ).rejects.toThrow(/may not erase/i);
    await expect(
      kernel.memForget({ target: { kind: "memory", value: factId } }, agent, AGENT),
    ).rejects.toThrow(/may not erase/i);
    expect(await rowExists(factId)).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (e) a suspended tenant's key is denied on every syscall + ingestion
// ---------------------------------------------------------------------------

describe("M4 exit (e) - a suspended tenant is a bulk revoke on every syscall", () => {
  it("every syscall + ingestion + fragmentation is denied while suspended, restored on reactivate", async () => {
    // Register a tenant and a key under it, plant a fact, then suspend it.
    await kernel.registerTenant({ id: "susp", name: "Suspendable" }, root);
    const id = await issue("susp/agent", "owner:susp", "owner");
    await kernel.setPolicy("susp", "rateLimitPerMin: 100000\n");

    const w = sync(
      await kernel.memWrite(
        { scope: "org", content: "susp fact osprey-cantilever", hints: { verbatim: true } },
        id,
        AGENT,
      ),
    );
    const factId = w.stored[0]!.id;

    // Suspend the tenant root — a bulk revoke of its whole keyspace.
    const suspended = await kernel.suspendTenant("susp");
    expect(suspended?.status).toBe("suspended");

    const suspendedErr = /is suspended/i;
    await expect(kernel.memRead({ id: factId }, id, AGENT)).rejects.toThrow(suspendedErr);
    await expect(kernel.memSearch({ query: "osprey cantilever", k: 5 }, id, AGENT)).rejects.toThrow(suspendedErr);
    await expect(
      kernel.memWrite({ scope: "org", content: "new fact while suspended", hints: { verbatim: true } }, id, AGENT),
    ).rejects.toThrow(suspendedErr);
    await expect(kernel.memFault({ query: "osprey" }, id, AGENT)).rejects.toThrow(suspendedErr);
    await expect(kernel.memStats({}, id, AGENT)).rejects.toThrow(suspendedErr);
    await expect(kernel.memAssemble({}, id, AGENT)).rejects.toThrow(suspendedErr);
    await expect(
      kernel.memForget({ target: { kind: "memory", value: factId } }, id, AGENT),
    ).rejects.toThrow(suspendedErr);
    await expect(
      kernel.importDump("mem0-import", JSON.stringify({ results: [{ id: "x", memory: "y" }] }), id),
    ).rejects.toThrow(suspendedErr);
    await expect(kernel.runFragmentation("susp/agent", id)).rejects.toThrow(suspendedErr);

    // The fact was never erased (the suspended forget was denied).
    expect(await rowExists(factId)).toBe(true);

    // Reactivate → the key works again.
    const active = await kernel.activateTenant("susp");
    expect(active?.status).toBe("active");
    const readAgain = await kernel.memRead({ id: factId }, id, AGENT);
    expect(readAgain.found).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (f) a per-tenant budget cap below the policy cap trips brownout to verbatim
// ---------------------------------------------------------------------------

describe("M4 exit (f) - a tenant budget cap below the policy cap trips brownout", () => {
  it("spend under the policy cap but over the tenant cap degrades the write to verbatim", async () => {
    // Namespace policy cap = 100 USD (generous). Tenant cap = 1 USD (tight).
    await kernel.registerTenant(
      { id: "brown", name: "Brownout", monthlyBudgetUsd: 1 },
      root,
    );
    const id = await issue("brown/agent", "owner:brown", "owner");
    await kernel.setPolicy("brown", "monthlyBudgetUsd: 100\nrateLimitPerMin: 100000\n");

    // Seed 5 USD of spend under the tenant subtree — UNDER the 100 policy cap,
    // but OVER the 1 USD tenant cap. effectiveBudgetUsd(100, tenant) === 1.
    await kernel.db.query(
      `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
       VALUES ($1, $2, 'llm', 1000, 5, $3)`,
      [ulid(), "brown/agent", new Date().toISOString()],
    );

    // A NON-verbatim write must brown out to verbatim: the write path emits a
    // 'reject'/'denied' budget_over audit row before storing verbatim.
    await kernel.memWrite(
      { scope: "org", content: "User: the brownout widget ships in blue and green" },
      id,
      AGENT,
    );

    const brownRows = await kernel.db.query(
      `SELECT count(*)::int AS n FROM audit_log
       WHERE op = 'reject' AND result = 'denied' AND namespace = 'brown/agent'
         AND detail LIKE 'budget_over%'`,
    );
    expect(Number((brownRows.rows[0] as { n: number }).n)).toBeGreaterThanOrEqual(1);
  }, 60_000);

  it("control: the SAME spend under a tenant with NO cap does NOT brown out (policy cap not reached)", async () => {
    // No tenant cap → effectiveBudgetUsd(100, tenant) === 100; 5 USD < 100 → ok.
    await kernel.registerTenant({ id: "nocap", name: "NoCap" }, root);
    const id = await issue("nocap/agent", "owner:nocap", "owner");
    await kernel.setPolicy("nocap", "monthlyBudgetUsd: 100\nrateLimitPerMin: 100000\n");

    await kernel.db.query(
      `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
       VALUES ($1, $2, 'llm', 1000, 5, $3)`,
      [ulid(), "nocap/agent", new Date().toISOString()],
    );

    await kernel.memWrite(
      { scope: "org", content: "User: the nocap gadget ships in red and yellow" },
      id,
      AGENT,
    );

    const brownRows = await kernel.db.query(
      `SELECT count(*)::int AS n FROM audit_log
       WHERE op = 'reject' AND result = 'denied' AND namespace = 'nocap/agent'
         AND detail LIKE 'budget_over%'`,
    );
    expect(Number((brownRows.rows[0] as { n: number }).n)).toBe(0);
  }, 60_000);
});
