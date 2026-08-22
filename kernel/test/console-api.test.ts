/**
 * Module B (M5 part 1) — management-API read models: subtree/ACL scoping.
 *
 * Two sibling subtrees share ONE kernel: `org/support` and `org/sales`. An
 * admin at `org/support` must see ONLY org/support* data through every screen
 * (overview / people / memoryMap / auditSearch / sourcesView); a `org/sales`
 * row must NEVER appear. auditSearch must honour its filters (op / result /
 * since) and the LIMIT cap. An owner at the root sees both subtrees.
 *
 * The console handlers depend on a structural KernelSlice; the real Kernel
 * satisfies all of it EXCEPT the integrator-wired `listUsers` (Module A). We
 * supply `listUsers` here directly off the `users` table (migration 007), so
 * this test is self-contained and does not depend on Module A landing.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { Identity, WriteResult } from "../src/types.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";
import {
  overview,
  people,
  memoryMap,
  auditSearch,
  sourcesView,
  sourceLineageView,
  categorizeQuery,
  type KernelSlice,
  type ConsoleUser,
} from "../src/console/api.js";

let kernel: Kernel;
let slice: KernelSlice;
let root: Identity; // owner, empty namespace
let orgOwner: Identity; // tenant owner @ org
let supportAdmin: Identity; // admin @ org/support
let salesAdmin: Identity; // admin @ org/sales
let salesFactId: string;

const AGENT = "console-test";

function sync(result: WriteResult | { ticket: string }): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const id = await kernel.auth.resolve(plaintext);
  if (!id) throw new Error(`key for ${namespace} failed to resolve`);
  return id;
}

/** Insert a human user row directly (stands in for Module A's UserStore). */
async function seedUser(
  email: string,
  namespace: string,
  role: string,
  displayName = "Member",
): Promise<void> {
  await kernel.db.query(
    `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at, display_name)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5, $6)`,
    [ulid(), email, namespace, role, new Date().toISOString(), displayName],
  );
}

/**
 * The integrator-wired human roster, replicated here off the `users` table
 * using the SAME ancestor-subtree ACL the rest of the console uses (owner →
 * everyone; else → own subtree + descendants, exact IN-list + escaped LIKE).
 */
async function listUsers(identity: Identity): Promise<ConsoleUser[]> {
  let where = "TRUE";
  const params: string[] = [];
  if (identity.namespace !== "") {
    const parts = identity.namespace.split("/").filter((p) => p.length > 0);
    const ancestors: string[] = [];
    for (let i = 1; i <= parts.length; i++) ancestors.push(parts.slice(0, i).join("/"));
    const inList = ancestors.map((_, i) => `$${i + 1}`).join(", ");
    params.push(...ancestors);
    const likeParam = `$${params.length + 1}`;
    const escaped = identity.namespace.replace(/[\\%_]/g, (c) => `\\${c}`);
    params.push(escaped + "/%");
    where = `(namespace IN (${inList}) OR namespace LIKE ${likeParam} ESCAPE '\\')`;
  }
  const res = await kernel.db.query(
    `SELECT id, email, namespace, role, status, created_at, display_name FROM users WHERE ${where} ORDER BY email`,
    params,
  );
  return (res.rows as Record<string, unknown>[]).map((r) => ({
    id: r.id as string,
    email: r.email as string,
    displayName: r.display_name === null ? null : String(r.display_name),
    namespace: r.namespace as string,
    role: r.role as string,
    status: r.status as string,
    createdAt:
      r.created_at instanceof Date
        ? r.created_at.toISOString()
        : new Date(r.created_at as string).toISOString(),
  }));
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });

  // Root owner (bootstrap key at the empty namespace).
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root owner failed to resolve");
  root = resolvedRoot;

  await seedActiveSourceTeam(kernel, "org/support");
  await seedActiveSourceTeam(kernel, "org/sales");
  supportAdmin = await issue("org/support", "admin:support", "admin");
  salesAdmin = await issue("org/sales", "admin:sales", "admin");
  orgOwner = await issue("org", "owner:org", "owner");

  // Lift rate limits so the seed's many syscalls don't 429.
  await kernel.setPolicy("org/support", "rateLimitPerMin: 100000\n");
  await kernel.setPolicy("org/sales", "rateLimitPerMin: 100000\n");

  // The KernelSlice: delegate to the real kernel for every existing method,
  // and supply the integrator-wired listUsers ourselves (Module A not landed).
  slice = {
    db: kernel.db,
    audit: kernel.audit,
    auth: { list: (id) => kernel.auth.list(id) },
    sources: { list: (ns, global) => kernel.sources.list(ns, global) },
    budget: { monthToDateUsd: (ns) => kernel.budget.monthToDateUsd(ns) },
    tenants: { resolveTenant: (ns) => kernel.tenants.resolveTenant(ns) },
    listUsers,
    getPolicy: (ns) => kernel.getPolicy(ns),
  };

  // --- seed org/support -----------------------------------------------------
  // Facts land in a child namespace so overview's per-child rollup has content.
  const supportAgent = await issue("org/support/triage", "agent:triage", "agent");
  await kernel.setPolicy("org/support/triage", "rateLimitPerMin: 100000\n");
  const w = sync(
    await kernel.memWrite(
      {
        scope: "team",
        content: "Support handbook: refunds are approved within 30 days SUPPORTMARKER",
        hints: { verbatim: true },
      },
      supportAgent,
      AGENT,
    ),
  );
  const supportFactId = w.stored[0]!.id;
  // Bump access so it tops the hottest list.
  await kernel.memRead({ id: supportFactId }, supportAgent, AGENT);
  await kernel.memRead({ id: supportFactId }, supportAgent, AGENT);

  // A repeat successful lookup (same query twice → repeatLookup candidate).
  await kernel.memSearch({ query: "refund window", k: 3 }, supportAgent, AGENT);
  await kernel.memSearch({ query: "refund window", k: 3 }, supportAgent, AGENT);

  // A genuine fault MISS in a fresh EMPTY support child (no L2 facts + a
  // nonsense query below the L3 concept floor) → a gap. (With HashEmbedder a
  // fault against a populated namespace almost always finds *something*.)
  const emptyAgent = await issue("org/support/empty", "agent:empty", "agent");
  await kernel.setPolicy("org/support/empty", "rateLimitPerMin: 100000\n");
  await kernel.memFault(
    { query: "zzqqxx nonexistent gibberish token GAPMARKER", k: 3 },
    emptyAgent,
    AGENT,
  );

  // Pin a concept via policy so memoryMap.pinned is non-empty.
  await kernel.setPolicy(
    "org/support",
    "rateLimitPerMin: 100000\npinnedConcepts:\n  - concepts/support-sla.md\n",
  );

  // A registered source + a fragmentation report in the support subtree.
  await kernel.registerSource("filesystem", { path: "/tmp/support-docs" }, supportAdmin);
  await seedActiveSourceTeam(kernel, "org/support/team");
  const supportChildAdmin = await issue("org/support/team", "admin:support-child", "admin");
  await kernel.registerSource(
    "filesystem",
    { path: "/tmp/support-team-docs" },
    supportChildAdmin,
  );
  await kernel.runFragmentation("org/support", supportAdmin);

  // Human users in both subtrees.
  await seedUser("agent-lead@support.example", "org/support", "member");
  await seedUser("triager@support.example", "org/support/triage", "member");
  await seedUser("rep@sales.example", "org/sales", "member");

  // --- seed org/sales (the sibling — must never leak into support views) ----
  const salesAgent = await issue("org/sales/deals", "agent:deals", "agent");
  await kernel.setPolicy("org/sales/deals", "rateLimitPerMin: 100000\n");
  const salesWrite = sync(
    await kernel.memWrite(
      {
        scope: "team",
        content: "Sales playbook: discount ceiling is 15 percent SALESMARKER",
        hints: { verbatim: true },
      },
      salesAgent,
      AGENT,
    ),
  );
  salesFactId = salesWrite.stored[0]!.id;
  await kernel.memSearch({ query: "discount ceiling SALESMARKER", k: 3 }, salesAgent, AGENT);
  await kernel.registerSource("filesystem", { path: "/tmp/sales-docs" }, salesAdmin);
}, 120_000);

afterAll(async () => {
  await kernel.close();
});

/** True iff a sales canary appears anywhere in the JSON of `value`. */
function leaksSales(value: unknown): boolean {
  const hay = JSON.stringify(value ?? "").toLowerCase();
  return (
    hay.includes("salesmarker") ||
    hay.includes("org/sales") ||
    hay.includes("sales.example")
  );
}

describe("overview (S2)", () => {
  it("scopes to the support subtree and never counts sales facts", async () => {
    const ov = await overview(slice, supportAdmin);
    expect(ov.namespace).toBe("org/support");
    expect(ov.l2Active).toBeGreaterThan(0);
    // The child rollup names org/support/triage, never org/sales.
    expect(ov.children.map((c) => c.namespace)).toContain("org/support/triage");
    expect(leaksSales(ov)).toBe(false);
    // Fault-rate reflects the support subtree's one miss.
    expect(ov.faultCount).toBeGreaterThanOrEqual(1);
  });

  it("owner at the root sees both subtrees", async () => {
    const ov = await overview(slice, root);
    const childNs = ov.children.map((c) => c.namespace);
    // At the root, immediate children are top-level segments: 'org'.
    expect(childNs).toContain("org");
    expect(ov.l2Active).toBeGreaterThanOrEqual(2);
  });

  it("an empty-namespace admin is not treated as a global owner", async () => {
    const rootAdmin: Identity = { ...root, keyId: "root-admin", role: "admin" };
    const ov = await overview(slice, rootAdmin);
    expect(ov.l2Active).toBe(0);
    expect(ov.children).toEqual([]);
  });

  it("does not count TTL-expired facts in overview summaries", async () => {
    const before = await overview(slice, supportAdmin);
    const ttlAgent = await issue("org/support/ttl", "agent:ttl", "agent");
    const written = sync(
      await kernel.memWrite(
        {
          scope: "team",
          content: "temporary console fact that must expire",
          hints: { verbatim: true },
        },
        ttlAgent,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    await kernel.db.query(
      `UPDATE memory_objects
       SET ttl_seconds = 1,
           assertion_time = CURRENT_TIMESTAMP - INTERVAL '2 seconds'
       WHERE id = $1`,
      [id],
    );

    const after = await overview(slice, supportAdmin);
    expect(after.l2Active).toBe(before.l2Active);
    expect(after.children).toEqual(before.children);
  });

  // S2's 7/30/90 control is a SERVER-side cut. Without it the screen re-rendered
  // the same all-time payload under a different button, which is what made the
  // range look broken.
  describe("reporting window (params.days)", () => {
    const ANCIENT_QUERY = "ANCIENT WINDOW MARKER";

    beforeAll(async () => {
      const old = new Date(Date.now() - 120 * 86_400_000).toISOString();
      // A read older than any window the console offers.
      await kernel.db.query(
        `INSERT INTO audit_log (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail)
         VALUES ($1, 'agent:ancient', $2, 'search', NULL, 'org/support/triage', $3, 'ok', NULL)`,
        [old, AGENT, ANCIENT_QUERY],
      );
      // ...and a fact saved that long ago, in its own child namespace.
      await kernel.db.query(
        `INSERT INTO memory_objects
           (id, namespace, scope, tier, backend_ref, content, type, confidence,
            assertion_time, t_valid_from, provenance, status)
         VALUES ($1, 'org/support/ancient', 'team', 'L2', $1, $2, 'fact', 0.9,
                 $3, $3, '[]'::jsonb, 'active')`,
        [ulid(), "Ancient support fact ANCIENTMARKER", old],
      );
    });

    it("counts activity only inside the window and leaves inventory alone", async () => {
      const allTime = await overview(slice, supportAdmin);
      const windowed = await overview(slice, supportAdmin, { days: 7 });

      expect(allTime.windowDays).toBeNull();
      expect(allTime.since).toBeNull();
      expect(windowed.windowDays).toBe(7);
      expect(new Date(windowed.since!).getTime()).toBeLessThan(Date.now());

      const sawAncient = (ov: { querySummary: { topQueries: { query: string }[] } }) =>
        ov.querySummary.topQueries.some((q) => q.query === ANCIENT_QUERY);
      expect(sawAncient(allTime)).toBe(true);
      expect(sawAncient(windowed)).toBe(false);
      expect(windowed.querySummary.total).toBe(allTime.querySummary.total - 1);

      // Memory counts follow t_valid_from, so the 120-day-old fact and the
      // namespace that owns it drop out of the 7-day cut.
      expect(allTime.children.map((c) => c.namespace)).toContain("org/support/ancient");
      expect(windowed.children.map((c) => c.namespace)).not.toContain("org/support/ancient");
      expect(windowed.l2Active).toBe(allTime.l2Active - 1);

      // Inventory and billing describe the org as it stands now — never windowed.
      expect(windowed.homeCounts.policies).toBe(allTime.homeCounts.policies);
      expect(windowed.homeCounts.skills).toBe(allTime.homeCounts.skills);
      expect(windowed.sourcesSummary.connectedCount).toBe(
        allTime.sourcesSummary.connectedCount,
      );
      expect(windowed.agentAccess.totalAgents).toBe(allTime.agentAccess.totalAgents);
      expect(windowed.spend.monthToDateUsd).toBe(allTime.spend.monthToDateUsd);

      // The window narrows scope; it never widens it.
      expect(leaksSales(windowed)).toBe(false);
    });

    it("falls back to all-time for a days value that is not a usable window", async () => {
      for (const days of [0, -5, Number.NaN]) {
        expect((await overview(slice, supportAdmin, { days })).windowDays).toBeNull();
      }
      // Clamped rather than refused, so a hand-edited URL cannot ask for an
      // unbounded scan.
      expect((await overview(slice, supportAdmin, { days: 99_999 })).windowDays).toBe(365);
      expect((await overview(slice, supportAdmin, { days: 7.9 })).windowDays).toBe(7);
    });
  });

  it("reports usage, sources, leaderboards, queries and compliance - subtree-scoped", async () => {
    const ov = await overview(slice, supportAdmin);

    // Metered usage comes straight off the cost ledger (numbers, never NaN).
    expect(Number.isFinite(ov.usage.totalTokens)).toBe(true);
    expect(Number.isFinite(ov.usage.totalUsd)).toBe(true);
    // v94 per-source split: every row well-formed, and the split never
    // invents spend the totals do not contain.
    expect(Array.isArray(ov.usage.bySource)).toBe(true);
    let bySourceTokens = 0;
    for (const row of ov.usage.bySource) {
      expect(row.sourceId === null || typeof row.sourceId === "string").toBe(true);
      expect(Number.isFinite(row.tokens)).toBe(true);
      expect(Number.isFinite(row.usd)).toBe(true);
      bySourceTokens += row.tokens;
    }
    expect(bySourceTokens).toBe(ov.usage.totalTokens);

    // No model profiles are configured in this kernel → an empty ranked list.
    expect(Array.isArray(ov.models)).toBe(true);

    // Both support-subtree filesystem sources are connected; sales' is not.
    expect(ov.sourcesSummary.connectedCount).toBe(2);
    expect(
      ov.sourcesSummary.connected.every((s) =>
        s.namespace.startsWith("org/support"),
      ),
    ).toBe(true);

    // The triage team tops the team leaderboard; the triage agent the actors.
    expect(ov.topTeams.map((t) => t.name)).toContain("org/support/triage");
    expect(ov.topActors.map((a) => a.name)).toContain("agent:triage");
    expect(ov.memoryWrites.total).toBeGreaterThan(0);
    expect(ov.memoryWrites.teams.map((team) => team.name)).toContain("org/support/triage");
    expect(Object.values(ov.homeCounts).every(Number.isFinite)).toBe(true);

    // The two "refund window" searches + the one gap fault are counted, and
    // "refund window" categorizes as Support.
    expect(ov.querySummary.total).toBeGreaterThanOrEqual(3);
    expect(ov.querySummary.hits).toBeGreaterThanOrEqual(2);
    expect(ov.querySummary.misses).toBeGreaterThanOrEqual(1);
    expect(ov.querySummary.topQueries.map((q) => q.query)).toContain(
      "refund window",
    );
    expect(ov.queryCategories.map((c) => c.category)).toContain("Support");

    // Agent badges exist in the subtree; nobody has overreached, and no
    // gateway access events/requests were recorded.
    expect(ov.agentAccess.totalAgents).toBeGreaterThanOrEqual(1);
    expect(ov.agentAccess.withinPolicy).toBe(ov.agentAccess.totalAgents);
    expect(ov.agentAccess.overreaching).toEqual([]);
    expect(ov.agentAccess.accessEvents).toEqual({
      allowed: 0,
      denied: 0,
      error: 0,
    });
    expect(ov.agentAccess.accessRequests.pending).toBe(0);

    // The sibling's data never leaks through any of the new aggregates.
    expect(leaksSales(ov)).toBe(false);
  });

  it("labels a human leaderboard actor with the saved display name while retaining its email key", async () => {
    await seedUser(
      "owner.one@acme.test",
      "org/support",
      "member",
      "Owner One",
    );
    await kernel.db.query(
      `INSERT INTO audit_log (ts, actor, agent_id, op, memory_id, namespace, purpose, result, detail)
       VALUES ($1, $2, 'console', 'search', NULL, $3, 'display-name regression', 'ok', NULL)`,
      [new Date().toISOString(), "owner.one@acme.test", "org/support"],
    );

    const ov = await overview(slice, supportAdmin);
    expect(ov.topActors).toContainEqual(expect.objectContaining({
      name: "owner.one@acme.test",
      displayName: "Owner One",
    }));
  });

  it("does not assign a human display name to a colliding agent actor", async () => {
    const actor = "collision@halofy.ai";
    await seedUser(actor, "org/support", "member", "Human Collision");
    // The overview includes descendant audit rows, while a member's key list
    // is exact-team only. Classification must use the same namespace scope as
    // the leaderboard, not the narrower key-list surface.
    const agent = await issue("org/support/child", actor, "agent");
    await kernel.memSearch({ query: "refund window" }, agent, AGENT);

    const ov = await overview(slice, { ...supportAdmin, role: "member" });
    expect(ov.topActors.find((row) => row.name === actor)).toEqual({
      name: actor,
      count: 1,
    });
  });

  it("a denied syscall marks the agent as overreaching in the compliance card", async () => {
    // An org/support agent tries to read the sales fact — the ACL denies it
    // and D4 writes the denied audit row this aggregate is built from. The
    // caller-facing result collapses to a miss (no cross-namespace existence
    // oracle), so the call resolves; only the audit row records the denial.
    const denied = await issue("org/support/denied", "agent:denied", "agent");
    await kernel.memRead({ id: salesFactId }, denied, AGENT);

    const ov = await overview(slice, supportAdmin);
    const over = ov.agentAccess.overreaching.find(
      (o) => o.actor === "agent:denied",
    );
    expect(over).toBeDefined();
    expect(over!.denied).toBeGreaterThanOrEqual(1);
    expect(ov.agentAccess.withinPolicy).toBeLessThan(ov.agentAccess.totalAgents);
  });

  it("owner at the root aggregates both subtrees' sources and teams", async () => {
    const ov = await overview(slice, root);
    expect(ov.sourcesSummary.connectedCount).toBeGreaterThanOrEqual(3);
    // Everything sits under the single top segment "org", so the team rollup
    // drills one level deeper and differentiates the real teams.
    const teams = ov.topTeams.map((t) => t.name);
    expect(teams).toContain("org/support");
    expect(teams).toContain("org/sales");
  });
});

describe("categorizeQuery", () => {
  it("buckets purposes into the expected categories", () => {
    expect(categorizeQuery("what is the refund window")).toBe("Support");
    expect(categorizeQuery("Q3 pipeline and deal status")).toBe("Sales");
    expect(categorizeQuery("latest campaign performance")).toBe("Marketing");
    expect(categorizeQuery("why does the deploy fail with this error")).toBe(
      "Coding",
    );
    expect(categorizeQuery("benchmark analysis of retrievers")).toBe("Research");
    expect(categorizeQuery("monthly budget forecast")).toBe("Finance");
    expect(categorizeQuery("zzqqxx gibberish")).toBe("Other");
  });
});

describe("people (S3)", () => {
  it("returns support users + badges only, no sales rows", async () => {
    const p = await people(slice, supportAdmin);
    const emails = p.users.map((u) => u.email);
    expect(emails).toContain("agent-lead@support.example");
    expect(emails).toContain("triager@support.example");
    expect(emails).not.toContain("rep@sales.example");
    // Badges (agent API keys) are scoped too — no sales badge.
    expect(p.badges.every((b) => b.namespace.startsWith("org/support"))).toBe(true);
    expect(leaksSales(p)).toBe(false);
  });

  it("owner sees every user", async () => {
    const p = await people(slice, root);
    const emails = p.users.map((u) => u.email);
    expect(emails).toContain("rep@sales.example");
    expect(emails).toContain("agent-lead@support.example");
  });
});

describe("memoryMap (S5)", () => {
  it("maps the support namespace: pins, hottest, repeats, gaps", async () => {
    const supportSource = (await kernel.sources.list("org/support"))[0]!;
    const createdAt = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO knowledge_bases
         (id, namespace, name, kind, status, lifecycle_state,
          primary_business_function, description, t_valid_from, created_by,
          created_at, updated_at)
       VALUES
         ('kb-console-map', 'org/support', 'Support playbooks', 'file', 'ready',
          'active', 'Customer support', 'Support operating knowledge', $1,
          'admin:support', $1, $1)`,
      [createdAt],
    );
    await kernel.db.query(
      `INSERT INTO company_files
         (id, knowledge_base_id, source_id, namespace, title, description,
          purpose, status, lifecycle_state, file_name, media_type, byte_size,
          content_sha256, attempt_token, lease_expires_at, fact_count,
          t_valid_from, created_by, uploaded_by, created_at)
       VALUES
         ('file-console-map', 'kb-console-map', $1, 'org/support',
          'Escalation runbook', '', 'Support operations', 'ready', 'active',
          'escalation-runbook.md', 'text/markdown', 128, $2,
          'attempt-console-map', $3, 12, $4, 'admin:support',
          'admin:support', $4)`,
      [supportSource.id, "a".repeat(64), new Date(Date.now() + 60_000).toISOString(), createdAt],
    );
    await kernel.db.query(
      `INSERT INTO skills
         (id, namespace, skill_key, name, description, definition,
          content_sha256, vetting_status, safety_score, t_valid_from, status,
          created_by, created_at, updated_at)
       VALUES
         ('skill-console-map', 'org/support', 'answer-with-citations',
          'Answer with citations', '', '# Answer with citations', $1, 'vetted',
          94, $2, 'active', 'admin:support', $2, $2)`,
      ["b".repeat(64), createdAt],
    );

    const beforeInherited = await memoryMap(slice, supportAdmin, "org/support");
    const inheritedId = ulid();
    const inheritedAt = new Date().toISOString();
    await kernel.db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
          provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
       VALUES ($1, 'org', 'org', 'L2', 'test', $2, 'fact', 1,
               NULL, $3, $3, NULL, NULL, '[]', NULL, $3, 10, 0, 'active', NULL)`,
      [inheritedId, "Tenant-wide inherited policy ANCESTORMARKER", inheritedAt],
    );
    const mm = await memoryMap(slice, supportAdmin, "org/support");
    expect(mm.pinned).toContain("concepts/support-sla.md");
    // Hottest includes the twice-read support fact.
    expect(mm.hottest.some((h) => h.content.includes("SUPPORTMARKER"))).toBe(true);
    expect(mm.hottest.some((h) => h.content.includes("ANCESTORMARKER"))).toBe(true);
    // The repeated "refund window" query surfaces as a repeat lookup.
    expect(mm.repeatLookups.some((r) => r.query.includes("refund window"))).toBe(true);
    // The missing-question fault (in the org/support/empty descendant) surfaces
    // as a gap — proving the map covers the namespace's whole subtree.
    expect(mm.gaps.some((g) => g.query.includes("GAPMARKER"))).toBe(true);
    expect(mm.topology.scope).toBe("selected-subtree");
    // Filesystem rows back knowledge-base folders/uploads; they are not
    // connector backends and therefore stay out of the backend branch.
    expect(mm.topology.sources).toEqual([]);
    expect(mm.topology.activeFacts).toBe(beforeInherited.topology.activeFacts);
    expect(mm.topology.activityFacts).toBe(beforeInherited.topology.activityFacts);
    expect(mm.topology.activeFacts).toBeGreaterThanOrEqual(1);
    expect(mm.topology.activityFacts).toBeGreaterThanOrEqual(1);
    expect(mm.topology.memories.some((memory) => memory.label.includes("SUPPORTMARKER"))).toBe(true);
    expect(mm.topology.memories.some((memory) => memory.label.includes("ANCESTORMARKER"))).toBe(false);
    expect(mm.topology.memories.some((memory) => memory.label.includes("SALESMARKER"))).toBe(false);
    expect(mm.topology.knowledgeBases).toContainEqual(expect.objectContaining({
      id: "kb-console-map",
      name: "Support playbooks",
      files: [expect.objectContaining({
        id: "file-console-map",
        sourceId: supportSource.id,
        name: "escalation-runbook.md",
        factCount: 12,
      })],
    }));
    expect(mm.topology.skills).toContainEqual(expect.objectContaining({
      id: "skill-console-map",
      key: "answer-with-citations",
      name: "Answer with citations",
      vettingStatus: "vetted",
      safetyScore: 94,
    }));
    expect(mm.topology.agents.some((agent) => agent.actor === "agent:triage")).toBe(true);
    expect(mm.topology.agents.every((agent) => agent.namespace.startsWith("org/support"))).toBe(true);
    expect(mm.topology.routing).toMatchObject({ mode: "fixed" });
    expect(leaksSales(mm)).toBe(false);
  });

  it("maps every child namespace for the organization root", async () => {
    const map = await memoryMap(slice, root, "");
    expect(map.topology.sources).toEqual([]);
    expect(map.hottest.some((fact) => fact.content.includes("SUPPORTMARKER"))).toBe(true);
    expect(map.hottest.some((fact) => fact.content.includes("SALESMARKER"))).toBe(true);
  });

  it("rejects organization-root memory expansion for every non-owner role", async () => {
    for (const role of ["admin", "auditor", "member"] as const) {
      await expect(memoryMap(slice, { ...root, role }, "")).rejects.toThrow(
        /platform root owner/i,
      );
    }
  });

  it("refuses a sibling namespace outside the caller's subtree", async () => {
    await expect(memoryMap(slice, supportAdmin, "org/sales")).rejects.toThrow(
      /outside your subtree/i,
    );

    const tenantOwner: Identity = {
      ...supportAdmin,
      keyId: "support-owner",
      role: "owner",
    };
    await expect(memoryMap(slice, tenantOwner, "org/sales")).rejects.toThrow(
      /outside your subtree/i,
    );
  });

  it("returns every connected agent instead of truncating the graph at eight", async () => {
    const actors = Array.from({ length: 9 }, (_, index) => `agent:map-${index + 1}`);
    for (const actor of actors) await issue("org/support/map-agents", actor, "agent");

    const mapped = await memoryMap(slice, supportAdmin, "org/support");
    for (const actor of actors) {
      expect(mapped.topology.agents.some((agent) => agent.actor === actor)).toBe(true);
    }
  });
});

describe("auditSearch (S8)", () => {
  it("scopes to the support subtree - no sales audit rows", async () => {
    const rows = await auditSearch(slice, supportAdmin, {});
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.namespace.startsWith("org/support"))).toBe(true);
    expect(leaksSales(rows)).toBe(false);
  });

  it("honours the op filter", async () => {
    const rows = await auditSearch(slice, supportAdmin, { op: "fault" });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.op === "fault")).toBe(true);
  });

  it("honours the result filter", async () => {
    const rows = await auditSearch(slice, supportAdmin, { op: "fault", result: "miss" });
    expect(rows.every((r) => r.op === "fault" && r.result === "miss")).toBe(true);
    expect(rows.some((r) => r.purpose?.includes("GAPMARKER"))).toBe(true);
  });

  it("honours the since filter", async () => {
    const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const none = await auditSearch(slice, supportAdmin, { since: future });
    expect(none).toEqual([]);
    const past = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const some = await auditSearch(slice, supportAdmin, { since: past });
    expect(some.length).toBeGreaterThan(0);
  });

  it("caps the LIMIT at 500 even when a larger limit is asked", async () => {
    // Ask for 10_000 — the cap must clamp it. We can't easily assert 500 rows
    // exist, but the query must not throw and must return a bounded result.
    const rows = await auditSearch(slice, supportAdmin, { limit: 10_000 });
    expect(rows.length).toBeLessThanOrEqual(500);
  });

  it("respects a small explicit limit", async () => {
    const rows = await auditSearch(slice, supportAdmin, { limit: 1 });
    expect(rows.length).toBeLessThanOrEqual(1);
  });

  it("owner searches org-wide (both subtrees visible)", async () => {
    const rows = await auditSearch(slice, root, {});
    const namespaces = new Set(rows.map((r) => r.namespace));
    expect([...namespaces].some((n) => n.startsWith("org/support"))).toBe(true);
    expect([...namespaces].some((n) => n.startsWith("org/sales"))).toBe(true);
  });
});

describe("sourcesView (S6)", () => {
  it("lists only support sources + the latest support fragmentation summary", async () => {
    const sv = await sourcesView(slice, supportAdmin);
    expect(sv.sources.length).toBeGreaterThan(0);
    expect(sv.sources.every((s) => s.namespace.startsWith("org/support"))).toBe(true);
    expect(
      sv.sources.every(
        (s) =>
          s.registrationState === "registered" &&
          s.syncMode === "manual" &&
          s.syncState === "never_synced" &&
          s.lastManualSyncAt === null,
      ),
    ).toBe(true);
    expect(sv.latestFragmentation).not.toBeNull();
    expect(sv.latestFragmentation!.namespace).toBe("org/support");
    expect(typeof sv.latestFragmentation!.factCount).toBe("number");
    expect(leaksSales(sv)).toBe(false);
  });

  it("carries the Conflicts screen's open count, and degrades to null instead of zero", async () => {
    // S6's data-quality tile must not compute a conflict number of its own —
    // the fragmentation report's `contradictions` figure is not one, and
    // publishing it produced an alarm with nothing behind it.
    const base = await sourcesView(slice, supportAdmin);
    expect(base.openConflicts).toBeNull();

    const counted = await sourcesView(
      { ...slice, countOpenConflicts: async () => 5 },
      supportAdmin,
    );
    expect(counted.openConflicts).toBe(5);
    expect(counted.latestFragmentation!.contradictions).not.toBe(5);

    const brownout = await sourcesView(
      { ...slice, countOpenConflicts: async () => { throw new Error("conflict queue offline"); } },
      supportAdmin,
    );
    expect(brownout.openConflicts).toBeNull();
    expect(brownout.sources.length).toBe(base.sources.length);
  });

  it("labels a completed sync as a last manual sync without claiming a schedule", async () => {
    const source = (await kernel.sources.list("org/support"))[0]!;
    const syncedAt = "2026-07-10T10:11:12.000Z";
    await kernel.sources.touchLastSync(source.id, syncedAt);

    const sv = await sourcesView(slice, supportAdmin);
    const row = sv.sources.find((candidate) => candidate.id === source.id)!;
    expect(row).toMatchObject({
      registrationState: "registered",
      syncMode: "manual",
      syncState: "last_manual_sync",
      lastManualSyncAt: syncedAt,
    });
    expect(JSON.stringify(row)).not.toContain("schedule");
  });

  it("exposes durable lifecycle, schedule, cursor health, and credential references", async () => {
    const source = (await kernel.sources.list("org/support"))[0]!;
    await kernel.sources.setSchedule(source.id, 3600);
    await kernel.sources.markSyncFailed(source.id, "provider-unreachable");
    const sv = await sourcesView(slice, supportAdmin);
    const row = sv.sources.find((candidate) => candidate.id === source.id)!;
    expect(row).toMatchObject({
      syncMode: "scheduled",
      syncStatus: "failed",
      lastSyncError: "provider-unreachable",
      lifecycleState: "active",
      syncIntervalSeconds: 3600,
      consecutiveFailures: 1,
      credentialId: null,
    });
    expect(row.nextSyncAt).toEqual(expect.any(String));
  });

  it("the sales admin sees its own source, not support's", async () => {
    const sv = await sourcesView(slice, salesAdmin);
    expect(sv.sources.every((s) => s.namespace.startsWith("org/sales"))).toBe(true);
    expect(sv.sources.some((s) => s.namespace.startsWith("org/support"))).toBe(false);
  });

  it("lets only the platform root owner see sources across tenants", async () => {
    const global = await sourcesView(slice, root);
    expect(global.sources.some((source) => source.namespace.startsWith("org/support"))).toBe(true);
    expect(global.sources.some((source) => source.namespace.startsWith("org/sales"))).toBe(true);

    const rootAdmin: Identity = { ...root, keyId: "root-admin-sources", role: "admin" };
    const deniedGlobal = await sourcesView(slice, rootAdmin);
    expect(deniedGlobal.sources).toEqual([]);
  });

});

/**
 * The S6 connection drawer's lineage graph. Every node it draws is one of
 * these numbers, so a leak here would be drawn on screen: the fact scan is
 * scoped independently of the source lookup, and a sibling subtree's fact
 * stamped with the SAME source id must not be counted.
 */
describe("sourceLineageView (S6 connection drawer)", () => {
  /** Stamp `sourceId`/`documentKey` provenance onto an existing fact. */
  async function stampSource(
    memoryId: string,
    sourceId: string,
    documentKey: string,
  ): Promise<void> {
    await kernel.db.query(
      "UPDATE memory_objects SET provenance = $2::jsonb WHERE id = $1",
      [
        memoryId,
        JSON.stringify([
          { source: "document", actor: "importer", sourceId, documentKey },
        ]),
      ],
    );
  }

  it("counts only the caller's own facts, split by kind and by tier", async () => {
    const source = (await kernel.sources.list("org/support"))[0]!;
    const supportAgent = await issue("org/support/triage", "agent:lineage", "agent");
    const salesAgent = await issue("org/sales/deals", "agent:lineage-sales", "agent");

    const mine = sync(await kernel.memWrite(
      {
        scope: "team",
        content: "Warehouse pallets are counted every Tuesday LINEAGEMARKER",
        hints: { verbatim: true },
      },
      supportAgent,
      AGENT,
    ));
    const alsoMine = sync(await kernel.memWrite(
      {
        scope: "team",
        content: "The night shift supervisor is Priya Raman LINEAGEMARKER",
        hints: { verbatim: true },
      },
      supportAgent,
      AGENT,
    ));
    const sibling = sync(await kernel.memWrite(
      {
        scope: "team",
        content: "Imported discount clause SALESMARKER",
        hints: { verbatim: true },
      },
      salesAgent,
      AGENT,
    ));

    await stampSource(mine.stored[0]!.id, source.id, "handbook.md");
    await stampSource(alsoMine.stored[0]!.id, source.id, "handbook.md");
    // The sibling subtree stamped with the SAME source id: visible to nobody
    // in org/support, however the id travelled.
    await stampSource(sibling.stored[0]!.id, source.id, "playbook.md");

    const lineage = await sourceLineageView(slice, supportAdmin, source.id);

    expect(lineage.sourceId).toBe(source.id);
    expect(lineage.namespace).toBe("org/support");
    expect(lineage.degraded).toBe(false);
    expect(lineage.records).toBe(2);
    // Two facts, one document — the document total is distinct, not a sum.
    expect(lineage.documents).toBe(1);
    expect(lineage.types.reduce((sum, bucket) => sum + bucket.count, 0)).toBe(2);
    expect(lineage.tiers.reduce((sum, bucket) => sum + bucket.count, 0)).toBe(2);
    expect(lineage.lastRecordAt).toEqual(expect.any(String));
    expect(leaksSales(lineage)).toBe(false);
  });

  it("reports a source that produced nothing as zero, not as unavailable", async () => {
    const quiet = await kernel.registerSource(
      "filesystem",
      { path: "/tmp/support-quiet" },
      supportAdmin,
    );
    const lineage = await sourceLineageView(slice, supportAdmin, quiet.id);
    expect(lineage.degraded).toBe(false);
    expect(lineage.records).toBe(0);
    expect(lineage.documents).toBe(0);
    expect(lineage.types).toEqual([]);
  });

  it("refuses a source the caller cannot see, exactly as it refuses one that does not exist", async () => {
    const salesSource = (await kernel.sources.list("org/sales"))[0]!;
    await expect(sourceLineageView(slice, supportAdmin, salesSource.id))
      .rejects.toThrow(/no source with id/);
    await expect(sourceLineageView(slice, supportAdmin, "no_such_source"))
      .rejects.toThrow(/no source with id/);
  });

  it("degrades to null counts instead of throwing when the rollup fails", async () => {
    const source = (await kernel.sources.list("org/support"))[0]!;
    const broken = {
      ...slice,
      db: {
        ...kernel.db,
        query: async () => { throw new Error("rollup offline"); },
      } as unknown as KernelSlice["db"],
    };
    const lineage = await sourceLineageView(broken, supportAdmin, source.id);
    expect(lineage.degraded).toBe(true);
    expect(lineage.records).toBeNull();
    expect(lineage.documents).toBeNull();
  });
});

describe("sourcesView (S6) — memory map", () => {
  it("shows an exact mounted current fact and hides it immediately after revoke", async () => {
    await kernel.db.query(
      "UPDATE memory_objects SET access_count = 999 WHERE id = $1",
      [salesFactId],
    );
    const beforeMount = await memoryMap(slice, supportAdmin, "org/support");
    const shared = await kernel.memShare(
      { kind: "memory", ref: salesFactId },
      "org/support",
      orgOwner,
    );
    const mounted = await memoryMap(slice, supportAdmin, "org/support");
    expect(mounted.hottest).toContainEqual(expect.objectContaining({
      id: salesFactId,
      pinnable: true,
    }));
    expect(mounted.topology.activeFacts).toBe(beforeMount.topology.activeFacts);
    expect(mounted.topology.activityFacts).toBe(beforeMount.topology.activityFacts);

    await kernel.sharing.revokeMount(orgOwner, shared.mount.id);
    const revoked = await memoryMap(slice, supportAdmin, "org/support");
    expect(revoked.hottest.some((fact) => fact.id === salesFactId)).toBe(false);
  });

  it("never displays a superseded fact as hot or pinnable", async () => {
    const supportAgent = await issue("org/support", "agent:map-current", "agent");
    const written = sync(await kernel.memWrite({
      scope: "team",
      content: "obsolete map canary",
      hints: { verbatim: true },
    }, supportAgent, AGENT));
    const obsoleteId = written.stored[0]!.id;
    await kernel.db.query(
      `UPDATE memory_objects
          SET access_count = 1000, t_valid_to = CURRENT_TIMESTAMP
        WHERE id = $1`,
      [obsoleteId],
    );

    const map = await memoryMap(slice, supportAdmin, "org/support");
    expect(map.hottest.some((fact) => fact.id === obsoleteId)).toBe(false);
    expect(map.topology.memories).toContainEqual(expect.objectContaining({
      id: obsoleteId,
      state: "older",
    }));
  });

  it("labels visible ancestor-human activity without widening the people roster", async () => {
    const actor = "ancestor.owner@halofy.ai";
    await seedUser(actor, "org", "owner", "Ancestor Owner");
    await kernel.audit.append({
      ts: new Date().toISOString(),
      actor,
      agentId: "console",
      op: "read",
      memoryId: null,
      namespace: "org",
      purpose: "ancestor display-name regression",
      result: "ok",
    });
    const productionSlice: KernelSlice = {
      ...slice,
      listUsers: (identity) => kernel.listUsers(identity),
    };

    const ov = await overview(productionSlice, supportAdmin);
    expect(ov.topActors).toContainEqual(expect.objectContaining({
      name: actor,
      displayName: "Ancestor Owner",
    }));
    expect((await kernel.listUsers(supportAdmin)).map((user) => user.email))
      .not.toContain(actor);
  });
});
