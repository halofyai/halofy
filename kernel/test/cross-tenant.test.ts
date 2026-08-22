/**
 * M4 adversarial suite — a sibling tenant is unreachable through EVERY query
 * path (CONTRACTS-M4.md §"The two hard promises", exit criterion 1).
 *
 * Two tenants share ONE kernel: `acme` and `globex`. Each plants canary facts,
 * entities, concepts, and audit rows; a fake-mem0 driver is mounted alongside
 * baseline + graph. Then a `globex` identity attacks EACH read path and must
 * get ZERO `acme` rows. Isolation is the SAME ancestor-prefix ACL the index
 * enforces (namespaceAncestors → exact IN-list, never a LIKE) — this suite
 * proves it exhaustively rather than trusting it. One named test per path.
 *
 * The last block is the hardest attack: a crafted namespace like `acme%` /
 * `acme_` / `acme-evil` that would leak through a LIKE-based fence. The ACL is
 * exact-match, so these resolve to their OWN (empty/unregistered) ancestor set
 * and see NOTHING of acme.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import type {
  Identity,
  RetrieverDriver,
  RetrieverQuery,
  ScoredRef,
  WriteResult,
} from "../src/types.js";
import { estimateTokens } from "../src/types.js";

const AGENT = "xtenant";

// The acme canary tokens — if ANY of these surface for a globex caller, the
// tenant fence has leaked (P0).
const ACME_CANARIES = [
  "heliotrope", // fact token
  "quokka", // entity name
  "marzipan-vault", // audit purpose token
];

let kernel: Kernel;
let root: Identity;
let acme: Identity;
let globex: Identity;
let acmeFactId: string;

/**
 * A deliberately "greedy" fake mem0 driver: it returns EVERY candidate the
 * ScopedView hands it, in view order, scored 1.0. The point is adversarial —
 * even a driver that tries to surface everything it can see is fenced by the
 * ScopedView (which is ACL-scoped), so a globex caller's driver can never be
 * handed an acme row to leak.
 */
class GreedyFakeMem0 implements RetrieverDriver {
  readonly name = "mem0";
  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }
  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    const candidates = await q.view.candidates(200);
    return candidates.slice(0, q.k).map((c) => ({
      id: c.ref,
      tier: "L2" as const,
      ref: c.ref,
      score: 1,
      content: c.content,
      tokenEstimate: estimateTokens(c.content),
    }));
  }
}

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

/** True iff any acme canary token appears anywhere in the JSON of `value`. */
function leaksAcme(value: unknown): boolean {
  const hay = JSON.stringify(value ?? "").toLowerCase();
  return ACME_CANARIES.some((c) => hay.includes(c.toLowerCase()));
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "", // in-memory PGlite
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });

  // Mount the fake mem0 driver alongside baseline + graph so mem_search can be
  // routed through all three lanes.
  kernel.registry.mount(new GreedyFakeMem0());

  // Root owner (empty-namespace key issuance bootstrap).
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;

  // Two sibling tenants.
  await kernel.registerTenant({ id: "acme", name: "Acme" }, root);
  await kernel.registerTenant({ id: "globex", name: "Globex" }, root);

  acme = await issue("acme", "owner:acme", "owner");
  globex = await issue("globex", "owner:globex", "owner");

  // Lift rate limits so the suite's many writes don't 429.
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\n");
  await kernel.setPolicy("globex", "rateLimitPerMin: 100000\n");

  // --- plant acme canaries -------------------------------------------------
  // A distinctive fact (verbatim so the token survives extraction).
  const w = sync(
    await kernel.memWrite(
      {
        scope: "org",
        content: "The acme heliotrope reactor passphrase is quokka-marzipan-vault",
        hints: { verbatim: true },
      },
      acme,
      AGENT,
    ),
  );
  acmeFactId = w.stored[0]!.id;
  // Bump access so it tops the access ranking.
  await kernel.memRead({ id: acmeFactId }, acme, AGENT);
  await kernel.memRead({ id: acmeFactId }, acme, AGENT);

  // A second acme fact mentioning the quokka entity (for the graph + entity lanes).
  sync(
    await kernel.memWrite(
      { scope: "org", content: "quokka is the codename for the heliotrope project", hints: { verbatim: true } },
      acme,
      AGENT,
    ),
  );

  // An acme audit row carrying a canary in the purpose (marzipan-vault).
  await kernel.memSearch({ query: "marzipan-vault secret", k: 3 }, acme, AGENT);

  // --- plant globex facts (so globex paths return non-empty, proving the
  //     probe works — a leak would ADD acme rows on top) ----------------------
  sync(
    await kernel.memWrite(
      { scope: "org", content: "The globex sprocket calibration is forty-two", hints: { verbatim: true } },
      globex,
      AGENT,
    ),
  );
}, 120_000);

afterAll(async () => {
  await kernel.close();
});

// ---------------------------------------------------------------------------
// Every read path — a globex caller gets ZERO acme rows.
// ---------------------------------------------------------------------------

describe("M4 cross-tenant - sibling tenant unreachable through every path", () => {
  it("getById: globex cannot read an acme memory by its id (denied → miss)", async () => {
    const res = await kernel.memRead({ id: acmeFactId }, globex, AGENT);
    expect(res.found).toBe(false);
    expect(res.memory).toBeNull();
  });

  it("index.getById: raw ACL denies a globex caller the acme row", async () => {
    const { obj, denied } = await kernel.index.getById(acmeFactId, "globex");
    expect(obj).toBeNull();
    expect(denied).toBe(true);
  });

  it("listCandidates: globex candidate set contains no acme fact", async () => {
    const rows = await kernel.index.listCandidates("globex");
    expect(rows.length).toBeGreaterThan(0); // globex has its own facts
    expect(rows.some((r) => leaksAcme(r))).toBe(false);
  });

  it("vectorSearch: globex nearest-neighbours contain no acme fact", async () => {
    const [embedding] = await kernel.embedder.embed(["heliotrope reactor passphrase quokka"]);
    const hits = await kernel.index.vectorSearch("globex", embedding, 20);
    expect(hits.some((h) => leaksAcme(h.obj))).toBe(false);
  });

  it("topAccessed: globex top-accessed rows contain no acme fact", async () => {
    const top = await kernel.index.topAccessed("globex", 20);
    expect(top.some((t) => leaksAcme(t))).toBe(false);
  });

  it("mem_search (baseline): globex search returns no acme fact", async () => {
    await kernel.setPolicy("globex", "retriever: baseline\nrateLimitPerMin: 100000\n");
    const hits = await kernel.memSearch({ query: "heliotrope reactor passphrase quokka marzipan", k: 20 }, globex, AGENT);
    expect(hits.some((h) => leaksAcme(h))).toBe(false);
  });

  it("mem_search (graph): globex graph-routed search returns no acme fact", async () => {
    await kernel.setPolicy("globex", "retriever: graph\nrateLimitPerMin: 100000\n");
    const hits = await kernel.memSearch({ query: "quokka heliotrope codename project", k: 20 }, globex, AGENT);
    expect(hits.some((h) => leaksAcme(h))).toBe(false);
  });

  it("mem_search (mem0): a greedy globex-routed mem0 driver still sees no acme fact", async () => {
    await kernel.setPolicy("globex", "retriever: mem0\nrateLimitPerMin: 100000\n");
    const hits = await kernel.memSearch({ query: "heliotrope quokka marzipan vault", k: 20 }, globex, AGENT);
    expect(hits.some((h) => leaksAcme(h))).toBe(false);
    // Reset to baseline for the remaining tests.
    await kernel.setPolicy("globex", "retriever: baseline\nrateLimitPerMin: 100000\n");
  });

  it("mem_stats: globex stats + topAccessed leak no acme fact", async () => {
    const stats = await kernel.memStats({}, globex, AGENT);
    expect(stats.topAccessed.some((t) => leaksAcme(t))).toBe(false);
    // The acme reactor fact (access_count=2) must NOT be globex's top row.
    expect(leaksAcme(stats.topAccessed)).toBe(false);
  });

  it("audit.list: a globex audit list carries only globex-namespace rows (no acme row leaks)", async () => {
    // audit.list filters by EXACT namespace, so a globex list can only ever
    // carry globex rows. Note: a globex row MAY echo the acme fact id as the
    // memoryId of globex's OWN denied getById probe (that denied attempt is
    // itself audited under globex — D4) — but it carries result 'miss'/'denied'
    // and NEVER the acme content. The isolation property is the namespace fence
    // plus the absence of acme CONTENT.
    const events = await kernel.audit.list("globex", { limit: 100 });
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e) => e.namespace === "globex")).toBe(true);
    // A globex row that references the acme id must be a denied/miss probe (the
    // denied getById attempt is itself audited under globex — D4), NEVER a
    // successful read (result 'ok') that returned acme content.
    for (const e of events) {
      if (e.memoryId === acmeFactId) {
        expect(e.result).not.toBe("ok");
      }
    }
    // acme's own list references the acme fact (proves the probe is real).
    const acmeEvents = await kernel.audit.list("acme", { limit: 100 });
    expect(acmeEvents.some((e) => e.namespace === "acme")).toBe(true);
  });

  it("mem_fault: a globex page-fault injects no acme fact", async () => {
    const fault = await kernel.memFault({ query: "heliotrope reactor passphrase quokka marzipan" }, globex, AGENT);
    expect(fault.injected.some((r) => leaksAcme(r))).toBe(false);
  });

  it("runScorecard: a globex scorecard run touches no acme fact (or has no scorable facts)", async () => {
    // The scorecard reads candidates via the globex ScopedView only. It either
    // runs over globex's own facts or throws "no facts" — never surfaces acme.
    try {
      const card = await kernel.runScorecard("globex", { maxQuestions: 5 }, globex);
      expect(leaksAcme(card)).toBe(false);
    } catch (err) {
      expect(err instanceof Error && /no facts|distinctive tokens/.test(err.message)).toBe(true);
    }
  });

  it("importDump landing: an acme fact stays invisible after a globex import", async () => {
    const dump = JSON.stringify({
      results: [{ id: "gx-1", memory: "the globex widget torque spec is nine newton-metres" }],
    });
    const imp = await kernel.importDump("mem0-import", dump, globex);
    expect(imp.stored).toBeGreaterThan(0);
    // The import landed in globex; a re-search from globex still shows no acme.
    const hits = await kernel.memSearch({ query: "heliotrope quokka marzipan reactor", k: 20 }, globex, AGENT);
    expect(hits.some((h) => leaksAcme(h))).toBe(false);
  });

  it("runFragmentation: a globex fragmentation report attributes no acme fact", async () => {
    const report = await kernel.runFragmentation("globex", globex);
    expect(leaksAcme(report)).toBe(false);
    for (const cluster of report.duplicateClusters) {
      for (const m of cluster.members) expect(leaksAcme(m)).toBe(false);
    }
  });

  it("listTenants: a globex owner never sees the sibling acme tenant", async () => {
    const tenants = await kernel.listTenants(globex);
    expect(tenants.some((t) => t.id === "acme")).toBe(false);
    expect(tenants.some((t) => t.id === "globex")).toBe(true);
  });

  it("tenant owner cannot list sibling API keys", async () => {
    const visible = await kernel.auth.list(acme);
    expect(visible.length).toBeGreaterThan(0);
    expect(
      visible.every((key) => key.namespace === "acme" || key.namespace.startsWith("acme/")),
    ).toBe(true);
    expect(visible.some((key) => key.id === globex.keyId)).toBe(false);
  });

  it("tenant owner cannot issue or revoke sibling API keys", async () => {
    await expect(
      kernel.auth.issueKey("globex", "agent:acme-intruder", "agent", acme),
    ).rejects.toThrow(/owner identity|outside.*subtree/i);

    const sibling = await kernel.auth.issueKey(
      "globex",
      "agent:globex-revocation-target",
      "agent",
      root,
    );
    const deps = buildHttpDeps(kernel);
    await expect(deps.admin.revokeKey(sibling.record.id, acme)).rejects.toThrow(
      /not found.*subtree/i,
    );
    expect(await kernel.auth.isActive(sibling.record.id)).toBe(true);
  });

  it("tenant admin cannot escalate itself by issuing an owner key", async () => {
    const admin = await issue("acme/admin", "admin:acme", "admin");
    const deps = buildHttpDeps(kernel);
    await expect(
      deps.admin.issueKey(
        { namespace: "acme/admin", actor: "escalated-owner", role: "owner" },
        admin,
      ),
    ).rejects.toThrow(/only an owner/i);
  });

  it("tenant owner cannot administer a sibling namespace", async () => {
    const deps = buildHttpDeps(kernel);
    await expect(deps.admin.getPolicy("globex", acme)).rejects.toThrow(
      /outside your subtree/i,
    );
    await expect(
      deps.admin.setPolicy("globex", "rateLimitPerMin: 1\n", acme),
    ).rejects.toThrow(/outside your subtree/i);
  });

  it("getCertificate: a globex caller cannot read an acme deletion certificate by id (denied → miss)", async () => {
    // acme mints a real DeletionCertificate (embeds acme's namespace, the erased
    // target PII, and acme memory ULIDs). Its id is a non-secret ULID surfaced
    // in every forget response — so a sibling tenant can learn/enumerate it.
    // Erase a throwaway fact (NOT the shared canaries) so the other tests' acme
    // fixtures stay intact.
    sync(
      await kernel.memWrite(
        { scope: "org", content: "acme customer wendover-lane must be forgotten", hints: { verbatim: true } },
        acme,
        AGENT,
      ),
    );
    const forgetResult = await kernel.memForget(
      { target: { kind: "entity", value: "wendover-lane" } },
      acme,
      AGENT,
    );
    const acmeCertId = forgetResult.certificate.id;
    // acme (the issuing subtree) reads its own cert fine.
    const own = await kernel.getCertificate(acmeCertId, acme);
    expect(own).not.toBeNull();
    expect(own!.namespace).toBe("acme");

    // globex owner/admin/auditor — EVERY privileged role — is fenced out: the
    // cert collapses to null (a miss), leaking neither namespace, target, nor
    // erasedIds. This mirrors memRead's denied-collapses-to-miss pattern.
    for (const role of ["owner", "admin", "auditor"] as const) {
      const gx = await issue("globex", `${role}:globex`, role);
      const leaked = await kernel.getCertificate(acmeCertId, gx);
      expect(leaked).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// LIKE-injection: a crafted namespace like `acme%` / `acme_` / `acme-evil`
// must NOT wildcard-match acme rows (the exact-IN ACL has no LIKE hazard).
// ---------------------------------------------------------------------------

describe("M4 cross-tenant - crafted namespaces cannot wildcard-leak acme", () => {
  const attackers: string[] = ["acme%", "acme_", "acme-evil", "acmex", "acm"];

  for (const attackNs of attackers) {
    it(`namespace '${attackNs}': getById/listCandidates/vectorSearch/topAccessed see no acme row`, async () => {
      // getById via the raw index ACL.
      const g = await kernel.index.getById(acmeFactId, attackNs);
      expect(g.obj).toBeNull();

      // listCandidates — the attacker namespace's ancestor set never contains 'acme'.
      const cands = await kernel.index.listCandidates(attackNs);
      expect(cands.some((r) => leaksAcme(r))).toBe(false);

      // vectorSearch — same fence.
      const [embedding] = await kernel.embedder.embed(["heliotrope reactor passphrase quokka"]);
      const hits = await kernel.index.vectorSearch(attackNs, embedding, 20);
      expect(hits.some((h) => leaksAcme(h.obj))).toBe(false);

      // topAccessed — exact namespace match, so an attacker sees only its own (empty) rows.
      const top = await kernel.index.topAccessed(attackNs, 20);
      expect(top.some((t) => leaksAcme(t))).toBe(false);
    });
  }

  it("month-to-date budget: an 'acme%' namespace cannot absorb acme spend via LIKE", async () => {
    // A LIKE-based budget sum would match 'acme%' patterns; the guard escapes
    // the pattern, so the attacker's month-to-date is its own (0), never acme's.
    const attackerSpend = await kernel.budget.monthToDateUsd("acme%");
    // No cost_ledger rows were written under 'acme%' — it must be exactly 0
    // (a wildcard leak would pull in acme's LLM/embed spend).
    expect(attackerSpend).toBe(0);
  });
});
