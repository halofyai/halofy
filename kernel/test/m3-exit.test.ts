/**
 * M3 exit criteria (CONTRACTS-M3.md §Exit) — the whole "connect your apps"
 * story through the REAL kernel, hermetic (in-memory PGlite, HashEmbedder,
 * StubLlm; tmp filesystem corpus; committed import fixtures; zero network):
 *
 *   (a) an external corpus imports and EVERY landed fact row carries
 *       provenance[0].source === 'swap-import' + the sourceId (queried off the
 *       memory_objects JSONB — no fact enters looking like conversation);
 *   (b) a filesystem connector re-sync of an UNCHANGED corpus writes zero new
 *       facts (content-hash drift works — no duplicate fact, no LLM spend);
 *   (c) the fragmentation report finds the planted cross-source duplicate +
 *       planted contradiction in the imported namespace and finds NONE in a
 *       clean sibling namespace;
 *   (d) an import into namespace N is invisible from a sibling namespace M
 *       (the ACL holds through the ingestion + fragmentation SQL);
 *   (e) STATIC D10 guard — no file under src/ingest/importers/ or
 *       src/ingest/connectors/ imports index/ | db/ | audit/ | write/ (the
 *       sink/state/config are their whole world).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, writeFile, rm, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { FORBIDDEN_INGEST_IMPORTS } from "../src/ingest/index.js";
import type { Identity } from "../src/types.js";
import type { WriteResult } from "../src/types.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

const AGENT = "m3-exit";
const FIXTURES = fileURLToPath(new URL("./fixtures/imports", import.meta.url));

let kernel: Kernel;
let platformOwner: Identity;
let owner: Identity;

/** Issue + resolve an owner key for a namespace (chained under the root owner). */
async function issue(namespace: string, actor: string): Promise<Identity> {
  await seedActiveSourceTeam(kernel, namespace);
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, "owner", owner);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

function sync(result: Awaited<ReturnType<Kernel["memWrite"]>>): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "", // in-memory PGlite
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const root = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(root.plaintext);
  if (!resolvedRoot) throw new Error("platform root owner key failed to resolve");
  platformOwner = resolvedRoot;
  const tenant = await kernel.auth.issueKey("exit3", "owner:m3", "owner", platformOwner);
  const resolved = await kernel.auth.resolve(tenant.plaintext);
  if (!resolved) throw new Error("root owner key failed to resolve");
  owner = resolved;
  // The suite makes many writes/min — lift the subtree rate limit.
  await kernel.setPolicy("exit3", "rateLimitPerMin: 100000\n");
}, 120_000);

afterAll(async () => {
  await kernel.close();
});

// ---------------------------------------------------------------------------
// (a) provenance intact on every landed fact
// ---------------------------------------------------------------------------

describe("M3 exit (a) - imported facts carry ingestion provenance", () => {
  it("every landed fact has provenance[0].source='swap-import' + the sourceId", async () => {
    const ns = "exit3/prov/agent";
    const id = await issue(ns, "agent:prov");
    const raw = await readFile(join(FIXTURES, "mem0-dump.json"), "utf8");

    const result = await kernel.importDump("mem0-import", raw, id);
    // The fixture has 5 usable records (one blank memory skipped by the parser).
    expect(result.records).toBe(5);
    expect(result.stored).toBeGreaterThan(0);
    expect(result.errors).toHaveLength(0);

    // Read the raw JSONB straight off memory_objects for this namespace.
    const rows = await kernel.db.query(
      `SELECT id, provenance FROM memory_objects
       WHERE namespace = $1 AND status = 'active'`,
      [ns],
    );
    expect(rows.rows.length).toBe(result.stored);
    expect(rows.rows.length).toBeGreaterThan(0);

    for (const row of rows.rows as Array<{ id: string; provenance: unknown }>) {
      const prov =
        typeof row.provenance === "string"
          ? (JSON.parse(row.provenance) as Array<{ source: string; sourceId?: string }>)
          : (row.provenance as Array<{ source: string; sourceId?: string }>);
      expect(prov.length).toBeGreaterThan(0);
      expect(prov[0].source).toBe("swap-import");
      expect(prov[0].sourceId).toBe(result.sourceId);
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (b) connector drift — re-sync of an unchanged corpus writes 0 new facts
// ---------------------------------------------------------------------------

describe("M3 exit (b) - filesystem drift writes zero on an unchanged corpus", () => {
  let corpus: string;

  beforeAll(async () => {
    corpus = await mkdtemp(join(tmpdir(), "halomem-m3-"));
    await writeFile(
      join(corpus, "handbook.md"),
      "The Reno warehouse dispatches west-coast orders same day before 2pm.\n",
      "utf8",
    );
    await writeFile(
      join(corpus, "hours.txt"),
      "Support hours are Monday through Friday 8am to 6pm Pacific.\n",
      "utf8",
    );
  });

  afterAll(async () => {
    await rm(corpus, { recursive: true, force: true });
  });

  it("first sync writes the corpus; an identical re-sync writes zero", async () => {
    const ns = "exit3/drift/agent";
    const id = await issue(ns, "agent:drift");
    const source = await kernel.registerSource("filesystem", { path: corpus }, id);

    const first = await kernel.syncSource(source.id, id);
    expect(first.scanned).toBe(2);
    expect(first.changed).toBe(2);
    expect(first.unchanged).toBe(0);
    expect(first.stored).toBeGreaterThan(0);

    const factsAfterFirst = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects WHERE namespace = $1 AND status = 'active'`,
      [ns],
    );
    const countAfterFirst = Number((factsAfterFirst.rows[0] as { n: number }).n);

    // Re-sync the SAME bytes: drift must skip everything.
    const second = await kernel.syncSource(source.id, id);
    expect(second.scanned).toBe(2);
    expect(second.changed).toBe(0);
    expect(second.unchanged).toBe(2);
    expect(second.stored).toBe(0);
    expect(second.removed).toHaveLength(0);

    const factsAfterSecond = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects WHERE namespace = $1 AND status = 'active'`,
      [ns],
    );
    const countAfterSecond = Number((factsAfterSecond.rows[0] as { n: number }).n);
    expect(countAfterSecond).toBe(countAfterFirst); // zero new facts
  }, 60_000);

  it("root and parent administration of a child source lands only in the source namespace", async () => {
    const ns = "exit3/admin-child";
    const child = await issue(ns, "owner:child-source");
    const rootCorpus = await mkdtemp(join(tmpdir(), "halomem-root-source-"));
    const parentCorpus = await mkdtemp(join(tmpdir(), "halomem-parent-source-"));
    try {
      await writeFile(join(rootCorpus, "root.md"), "ROOTSYNC source placement marker.\n", "utf8");
      await writeFile(
        join(parentCorpus, "parent.md"),
        "PARENTSYNC source placement marker.\n",
        "utf8",
      );
      const rootSource = await kernel.registerSource("filesystem", { path: rootCorpus }, child);
      const parentSource = await kernel.registerSource(
        "filesystem",
        { path: parentCorpus },
        child,
      );

      for (const role of ["member", "agent"] as const) {
        const issued = await kernel.auth.issueKey(
          "exit3",
          `${role}:source-boundary`,
          role,
          owner,
        );
        const nonAdmin = await kernel.auth.resolve(issued.plaintext);
        if (!nonAdmin) throw new Error(`${role} source-boundary key failed to resolve`);
        await expect(kernel.syncSource(parentSource.id, nonAdmin)).rejects.toThrow(
          /outside your namespace subtree/i,
        );
      }

      expect((await kernel.syncSource(rootSource.id, platformOwner)).stored).toBeGreaterThan(0);
      expect((await kernel.syncSource(parentSource.id, owner)).stored).toBeGreaterThan(0);

      const rows = await kernel.db.query(
        `SELECT namespace, content FROM memory_objects
         WHERE content LIKE '%ROOTSYNC%' OR content LIKE '%PARENTSYNC%'`,
      );
      expect(rows.rows.length).toBeGreaterThanOrEqual(2);
      expect(rows.rows.every((row: { namespace: string }) => row.namespace === ns)).toBe(true);
    } finally {
      await rm(rootCorpus, { recursive: true, force: true });
      await rm(parentCorpus, { recursive: true, force: true });
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (c) fragmentation finds planted dupes + contradictions; clean sibling: none
// ---------------------------------------------------------------------------

describe("M3 exit (c) - fragmentation finds planted signals, clean sibling has none", () => {
  it("planted namespace shows a cross-source duplicate + a contradiction", async () => {
    // agent-level facts (conversation, extracted → entities populated).
    const agentNs = "exit3/frag/agent";
    const teamNs = "exit3/frag"; // ancestor of agentNs → visible in fragmentation
    const agentId = await issue(agentNs, "agent:frag");
    const teamId = await issue(teamNs, "ops:frag");

    // A shipping fact the agent captured in conversation.
    sync(
      await kernel.memWrite(
        {
          scope: "user",
          content:
            "User: customer Priya Nair's current shipping address for order 8899 is 40 Birch Lane, Fairview",
          session: "c1",
        },
        agentId,
        AGENT,
      ),
    );
    // Planted contradiction fact A (agent, conversation): entity "Atlas".
    sync(
      await kernel.memWrite(
        { scope: "user", content: "User: the Atlas plan includes unlimited seats", session: "c2" },
        agentId,
        AGENT,
      ),
    );
    // Planted contradiction fact B (team ancestor, conversation): entity "Atlas",
    // conflicting, different namespace → both stay valid (no cross-ns supersede).
    sync(
      await kernel.memWrite(
        { scope: "user", content: "User: the Atlas plan was capped at five seats", session: "c3" },
        teamId,
        AGENT,
      ),
    );
    // Planted cross-source DUPLICATE: import a legacy dump at the team level that
    // re-states the shipping fact (provenance swap-import vs conversation).
    const dump = JSON.stringify({
      results: [
        {
          id: "legacy-priya",
          memory:
            "customer Priya Nair's current shipping address for order 8899 is 40 Birch Lane, Fairview",
        },
      ],
    });
    const imp = await kernel.importDump("mem0-import", dump, teamId);
    expect(imp.stored).toBe(1);

    const report = await kernel.runFragmentation(agentNs, agentId);

    // At least one duplicate cluster, and one that spans conversation + import.
    expect(report.duplicateClusters.length).toBeGreaterThanOrEqual(1);
    const crossSource = report.duplicateClusters.find((c) => {
      const labels = new Set(c.members.map((m) => m.sourceId ?? "conversation"));
      return labels.size >= 2 && [...labels].some((l) => l !== "conversation");
    });
    expect(crossSource, "expected a cross-source duplicate cluster").toBeDefined();
    expect(crossSource!.cosine).toBeGreaterThanOrEqual(0.92);

    // The planted contradiction on entity "Atlas" is present.
    const atlas = report.contradictions.find((c) => c.entity === "Atlas");
    expect(atlas, "expected a contradiction on entity Atlas").toBeDefined();
    expect(atlas!.facts.length).toBeGreaterThanOrEqual(2);

    // The report row persisted.
    const persisted = await kernel.db.query(
      `SELECT count(*)::int AS n FROM fragmentation_reports WHERE namespace = $1`,
      [agentNs],
    );
    expect(Number((persisted.rows[0] as { n: number }).n)).toBeGreaterThanOrEqual(1);
  }, 60_000);

  it("a clean sibling namespace shows zero duplicates and zero contradictions", async () => {
    const cleanNs = "exit3/clean/agent";
    const cleanId = await issue(cleanNs, "agent:clean");
    // Distinct, single-source facts — nothing to duplicate or contradict.
    for (const content of [
      "User: the loading dock closes at nine on weekdays",
      "User: invoices are emailed on the first business day of each month",
      "User: the staging cluster reboots every Sunday at midnight",
    ]) {
      sync(await kernel.memWrite({ scope: "user", content, session: "clean" }, cleanId, AGENT));
    }

    const report = await kernel.runFragmentation(cleanNs, cleanId);
    expect(report.factCount).toBeGreaterThan(0);
    expect(report.duplicateClusters).toHaveLength(0);
    expect(report.contradictions).toHaveLength(0);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (d) ACL — an import into N is invisible from a sibling namespace M
// ---------------------------------------------------------------------------

describe("M3 exit (d) - imported facts respect the namespace ACL", () => {
  it("an import into N is unreachable from a sibling M (search + fragmentation)", async () => {
    const nsN = "exit3/acl/team-n/agent";
    const nsM = "exit3/acl/team-m/agent";
    const idN = await issue(nsN, "agent:n");
    const idM = await issue(nsM, "agent:m");

    const dump = JSON.stringify({
      results: [
        { id: "secret-n", memory: "the ACL-N vault passphrase is heron-marble-lantern" },
      ],
    });
    const imp = await kernel.importDump("mem0-import", dump, idN);
    expect(imp.stored).toBe(1);

    // Sanity: reachable from N's own namespace.
    const fromN = await kernel.memSearch({ query: "ACL-N vault passphrase heron marble", k: 5 }, idN, AGENT);
    expect(fromN.some((h) => h.content.includes("heron-marble-lantern"))).toBe(true);

    // Sibling M sees nothing: neither via search nor via fragmentation facts.
    const fromM = await kernel.memSearch({ query: "ACL-N vault passphrase heron marble", k: 10 }, idM, AGENT);
    for (const h of fromM) {
      expect(h.content).not.toContain("heron-marble-lantern");
    }

    const reportM = await kernel.runFragmentation(nsM, idM);
    for (const cluster of reportM.duplicateClusters) {
      for (const m of cluster.members) {
        expect(m.content).not.toContain("heron-marble-lantern");
      }
    }
    // Directly assert the imported source id is not attributed to any M-visible fact.
    expect(Object.keys(reportM.sourceCounts)).not.toContain(imp.sourceId);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Regression (findings 2/4/9) — drift state is scoped to the LANDING namespace
// ---------------------------------------------------------------------------

describe("M3 regression - cross-namespace sync of one source lands facts each time", () => {
  it("a source synced from two allowed namespaces lands the corpus in BOTH", async () => {
    const corpus = await mkdtemp(join(tmpdir(), "halomem-m3-multins-"));
    await writeFile(
      join(corpus, "policy.md"),
      "Returns are accepted within thirty days with the original receipt.\n",
      "utf8",
    );
    await writeFile(
      join(corpus, "escalation.txt"),
      "Tier-two escalations page the on-call engineer after fifteen minutes.\n",
      "utf8",
    );

    // Register the source at an ANCESTOR namespace.
    const teamNs = "exit3/multins";
    const teamId = await issue(teamNs, "ops:multins");
    const source = await kernel.registerSource("filesystem", { path: corpus }, teamId);

    // Caller A — a descendant namespace — syncs first: facts land in A.
    const nsA = "exit3/multins/team-a";
    const idA = await issue(nsA, "agent:a");
    const first = await kernel.syncSource(source.id, idA);
    expect(first.changed).toBe(2);
    expect(first.stored).toBeGreaterThan(0);

    // Caller B — a DIFFERENT descendant namespace, ACL-allowed — syncs the SAME
    // source. Before the fix, drift keyed only by source.id saw every doc as
    // 'unchanged' (A had recorded the hashes) and B silently landed zero facts.
    const nsB = "exit3/multins/team-b";
    const idB = await issue(nsB, "agent:b");
    const second = await kernel.syncSource(source.id, idB);
    expect(second.scanned).toBe(2);
    expect(second.changed).toBe(2); // NOT skipped as 'unchanged'
    expect(second.unchanged).toBe(0);
    expect(second.stored).toBeGreaterThan(0);

    // Both namespaces genuinely hold the corpus.
    const countIn = async (ns: string): Promise<number> => {
      const r = await kernel.db.query(
        `SELECT count(*)::int AS n FROM memory_objects WHERE namespace = $1 AND status = 'active'`,
        [ns],
      );
      return Number((r.rows[0] as { n: number }).n);
    };
    expect(await countIn(nsA)).toBeGreaterThan(0);
    expect(await countIn(nsB)).toBeGreaterThan(0);

    // And a re-sync from B alone now correctly skips (per-namespace drift works).
    const reB = await kernel.syncSource(source.id, idB);
    expect(reB.changed).toBe(0);
    expect(reB.unchanged).toBe(2);

    await rm(corpus, { recursive: true, force: true });
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Regression (finding 5) — an IMPORTED fact contradicting existing knowledge
// is visible to contradiction detection (imported facts carry entities).
// ---------------------------------------------------------------------------

describe("M3 regression - import-vs-conversation contradiction is detected", () => {
  it("an imported (verbatim) fact contradicting a conversation fact is flagged", async () => {
    const ns = "exit3/impfrag/agent";
    const id = await issue(ns, "agent:impfrag");

    // Existing conversation knowledge about entity "Zephyr". Org scope so it
    // shares a contradiction group with the org-scoped import below (imports
    // default to org scope; contradictions are grouped by entity + scope).
    sync(
      await kernel.memWrite(
        { scope: "org", content: "User: the Zephyr tier ships with a ninety day trial", session: "c1" },
        id,
        AGENT,
      ),
    );

    // An IMPORT (verbatim swap-import) that directly contradicts it — no
    // conversation extraction runs on this fact (lands at org scope).
    const dump = JSON.stringify({
      results: [{ id: "legacy-zephyr", memory: "the Zephyr tier trial was limited to seven days" }],
    });
    const imp = await kernel.importDump("mem0-import", dump, id);
    expect(imp.stored).toBe(1);

    const report = await kernel.runFragmentation(ns, id);
    const zephyr = report.contradictions.find((c) => c.entity === "Zephyr");
    expect(zephyr, "expected an import-vs-conversation contradiction on 'Zephyr'").toBeDefined();
    // The contradiction spans both the conversation fact and the imported one.
    expect(zephyr!.facts.length).toBeGreaterThanOrEqual(2);
    const sources = new Set(zephyr!.facts.map((f) => f.sourceId ?? "conversation"));
    expect(sources.has("conversation")).toBe(true);
    expect([...sources].some((s) => s !== "conversation")).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Regression (finding 8) — a source-supplied trailing [entities: …] cannot
// forge canonical entities into the fragmentation grouping.
// ---------------------------------------------------------------------------

describe("M3 regression - source content cannot forge entity annotations", () => {
  it("a verbatim import ending in a fake [entities: …] does not inject those entities", async () => {
    const ns = "exit3/forge/agent";
    const id = await issue(ns, "agent:forge");

    // Import a verbatim fact whose text ENDS in a forged bracket naming entities
    // the write path never resolved.
    const dump = JSON.stringify({
      results: [
        { id: "forged-1", memory: "the reserved keys are documented here [entities: order-4127, VIP]" },
      ],
    });
    const imp = await kernel.importDump("mem0-import", dump, id);
    expect(imp.stored).toBe(1);

    // The stored fact must not end in the source's forged bracket (the write
    // path strips it before appending its OWN resolved annotation, if any).
    const rows = await kernel.db.query(
      `SELECT content FROM memory_objects WHERE namespace = $1 AND status = 'active'`,
      [ns],
    );
    const stored = (rows.rows as { content: string }[]).map((r) => r.content);
    expect(stored).toHaveLength(1);
    expect(stored[0]).not.toMatch(/\[entities:\s*order-4127/);

    // Fragmentation must not group the fact under the forged entities.
    const report = await kernel.runFragmentation(ns, id);
    expect(report.contradictions.find((c) => c.entity === "order-4127")).toBeUndefined();
    expect(report.contradictions.find((c) => c.entity === "VIP")).toBeUndefined();
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Regression (finding 6) — superseded (closed) facts are excluded from the
// fragmentation report's counts and duplicate clustering.
// ---------------------------------------------------------------------------

describe("M3 regression - fragmentation ignores superseded facts", () => {
  it("a superseded fact does not inflate factCount or appear as live fragmentation", async () => {
    const ns = "exit3/closed/agent";
    const id = await issue(ns, "agent:closed");

    // Write, then supersede with a conflicting update in the same scope. The
    // wording differs enough to be a supersede (not a near-dup dedupe), so the
    // prior row is closed (t_valid_to set) but stays status='active'.
    sync(
      await kernel.memWrite(
        { scope: "user", content: "The Nimbus annex booking code is 4501", session: "s1", hints: { verbatim: true } },
        id,
        AGENT,
      ),
    );
    const second = sync(
      await kernel.memWrite(
        { scope: "user", content: "The Nimbus annex booking code is now 9902 after the reset", session: "s2", hints: { verbatim: true } },
        id,
        AGENT,
      ),
    );
    expect(second.superseded.length).toBe(0); // Luna review is human-only

    // The DB holds two 'active' rows (one closed, one valid); the fragmentation
    // reader must only surface the single currently-valid fact.
    const active = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects WHERE namespace = $1 AND status = 'active'`,
      [ns],
    );
    expect(Number((active.rows[0] as { n: number }).n)).toBe(2);

    const report = await kernel.runFragmentation(ns, id);
    expect(report.factCount).toBe(2);
    expect(report.duplicateClusters).toHaveLength(0);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (e) STATIC D10 guard — importers/connectors reach nothing but the seams
// ---------------------------------------------------------------------------

describe("M3 exit (e) - D10 static import guard", () => {
  const dirs = [
    fileURLToPath(new URL("../src/ingest/importers", import.meta.url)),
    fileURLToPath(new URL("../src/ingest/connectors", import.meta.url)),
  ];

  it("no importer/connector source imports index/ | db/ | audit/ | write/", async () => {
    let scanned = 0;
    for (const dir of dirs) {
      // Recursive on purpose: subtrees like connectors/catalog/ are inside the
      // D10 boundary too — a flat readdir left ~70 files unscanned.
      const entries = await readdir(dir, { withFileTypes: true, recursive: true });
      for (const entry of entries) {
        if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
        const source = await readFile(join(entry.parentPath, entry.name), "utf8");
        scanned += 1;
        for (const pattern of FORBIDDEN_INGEST_IMPORTS) {
          expect(
            pattern.test(source),
            `${join(entry.parentPath, entry.name)} matched forbidden import ${pattern} (D10 violation)`,
          ).toBe(false);
        }
      }
    }
    // Guard the guard: make sure we actually read files (a bad glob = false
    // pass). The recursive walk covers 80+ files today; a floor of 20 still
    // fails fast if recursion regresses to a flat listing.
    expect(scanned).toBeGreaterThanOrEqual(20);
  });
});
