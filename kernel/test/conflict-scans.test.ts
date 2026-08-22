/**
 * Organization conflict scans (CONTRACTS-CONFLICT-SCAN.md CS-E1..E3).
 *
 * Integration-level RED tests over a real in-memory PGlite kernel. Facts are
 * planted directly because this suite exercises corpus selection,
 * materialization, and idempotence rather than the already-covered write path.
 * Hash/model network access is not used.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { AuditLog } from "../src/audit/index.js";
import {
  ConflictScanService,
  conflictGroupOrder,
  conflictPairIndexes,
  distinctStructuredRecords,
  isDegenerateEntity,
  structuredFields,
} from "../src/conflict-scans/index.js";
import type {
  ConflictClassificationCandidate,
  ConflictClassifier,
} from "../src/conflict-scans/classifier.js";
import { MemoryIndex } from "../src/index/index.js";
import type { Identity, MemoryObject, ProvenanceEntry } from "../src/types.js";

const ACME = "acme";
const ACME_SUPPORT = "acme/support";
const GLOBEX = "globex";

describe("candidate quality guards", () => {
  const metricRow = (id: string, date: string, impressions: number) =>
    `metric_id: ${id}, campaign_id: CMP-012, metric_date: ${date}, `
    + `channel: paid_search, impressions: ${impressions} [entities: MET, CMP]`;

  it("treats two rows of one table with different record ids as different observations", () => {
    expect(distinctStructuredRecords(
      metricRow("MET-012-01", "2026-04-06", 4055),
      metricRow("MET-012-03", "2026-04-08", 4245),
    )).toBe(true);
  });

  it("still compares two rows describing the SAME record with different values", () => {
    expect(distinctStructuredRecords(
      metricRow("MET-012-01", "2026-04-06", 4055),
      metricRow("MET-012-01", "2026-04-06", 9127),
    )).toBe(false);
  });

  it("never suppresses prose facts, whatever they contain", () => {
    expect(distinctStructuredRecords(
      "Priya Raghavan is the president of Halofy.",
      "Rahul Menon is the president of Halofy.",
    )).toBe(false);
    expect(structuredFields("Priya Raghavan is the president of Halofy.")).toBeNull();
  });

  it("rejects identifier fragments as canonical entities but keeps real subjects", () => {
    // `capitalizedWords` lifts these out of MET-012-01 / CMP-012; grouping on
    // them collapses an entire imported table into one candidate group.
    expect(isDegenerateEntity("MET")).toBe(true);
    expect(isDegenerateEntity("CMP")).toBe(true);
    expect(isDegenerateEntity("SKU12")).toBe(true);
    expect(isDegenerateEntity("Halofy")).toBe(false);
    expect(isDegenerateEntity("Priya Raghavan")).toBe(false);
    expect(isDegenerateEntity("Refund")).toBe(false);
  });
});

it("uses a full-cycle pair traversal beyond the per-scan pair cap", () => {
  const factCount = 202;
  const pairCap = 20_000;
  const seen = new Set<string>();
  for (let rotation = 0; rotation < factCount; rotation += 1) {
    let count = 0;
    for (const [left, right] of conflictPairIndexes(factCount, rotation)) {
      if (count >= pairCap) break;
      seen.add(left < right ? `${left}:${right}` : `${right}:${left}`);
      count += 1;
    }
  }
  expect(seen.size).toBe((factCount * (factCount - 1)) / 2);
});

it("advances fact rotation independently when multiple groups exhaust the pair cap", () => {
  const groupCount = 2;
  const factCount = 202;
  const pairCap = 20_000;
  const seen = Array.from({ length: groupCount }, () => new Set<string>());
  for (let scan = 0; scan < groupCount * factCount; scan += 1) {
    let budget = pairCap;
    for (const { groupIndex, factRotation } of conflictGroupOrder(groupCount, scan)) {
      for (const [left, right] of conflictPairIndexes(factCount, factRotation)) {
        if (budget === 0) break;
        seen[groupIndex]!.add(left < right ? `${left}:${right}` : `${right}:${left}`);
        budget -= 1;
      }
      if (budget === 0) break;
    }
  }
  const totalPairs = (factCount * (factCount - 1)) / 2;
  expect(seen.map((pairs) => pairs.size)).toEqual([totalPairs, totalPairs]);
});

let kernel: Kernel;
let knowledgeDir: string;
let acmeOwner: Identity;
let rootAdmin: Identity;
let rootOwner: Identity;

let acmeDocumentId: string;
let acmeConversationId: string;
let acmeCompatibleId: string;
let globexDocumentId: string;
let classificationCalls = 0;
let classificationHook: (() => Promise<void>) | null = null;

const conflictClassifier: ConflictClassifier = {
  model: "test-semantic-judge",
  async classify(candidates: readonly ConflictClassificationCandidate[]) {
    classificationCalls += 1;
    const hook = classificationHook;
    classificationHook = null;
    if (hook) await hook();
    return candidates.map((candidate) => {
      const pair = [candidate.left.content, candidate.right.content].join("\n");
      const contradiction = pair.includes("30 days") && pair.includes("14 days");
      return {
        candidateId: candidate.id,
        contradiction,
        confidence: contradiction && pair.includes("Lowconf") ? 0.5 : contradiction ? 0.97 : 0.91,
        reason: contradiction ? "conflicting_quantity" : "other_semantic_conflict",
      };
    });
  },
};

function vector(at: number): number[] {
  return Array.from({ length: 256 }, (_, index) => index === at ? 1 : 0);
}

async function seedFact(input: {
  namespace: string;
  content: string;
  source: ProvenanceEntry["source"];
  sourceId?: string;
  session?: string;
  embedding: number[];
}, targetKernel: Kernel = kernel): Promise<string> {
  const id = ulid();
  const now = new Date().toISOString();
  const fact: MemoryObject = {
    id,
    namespace: input.namespace,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: input.content,
    type: "fact",
    confidence: 1,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{
      source: input.source,
      actor: input.source === "conversation" ? "agent:support" : "connector:handbook",
      ...(input.sourceId ? { sourceId: input.sourceId } : {}),
      ...(input.session ? { session: input.session } : {}),
      ts: now,
    }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  await new MemoryIndex(targetKernel.db).insert(fact, input.embedding);
  return id;
}

async function runScan(): Promise<string> {
  const requested = await kernel.requestConflictScan(acmeOwner, {
    focus: "refund rules",
    include: ["knowledge-base", "agent-summary", "policy-manual"],
  });
  expect(requested.status).toBe("queued");

  const pass = await kernel.runConflictScanJobsOnce();
  expect(pass.claimed).toBe(1);
  expect(pass.completed).toBe(1);
  return requested.id;
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-conflict-scans-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
    conflictScanRequestCooldownMs: 0,
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
    conflictClassifier,
  });

  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root owner did not resolve");
  rootOwner = root;
  const rootAdminKey = await kernel.auth.issueKey("", "admin:root", "admin", root);
  const resolvedRootAdmin = await kernel.auth.resolve(rootAdminKey.plaintext);
  if (!resolvedRootAdmin) throw new Error("root admin did not resolve");
  rootAdmin = resolvedRootAdmin;
  const acmeKey = await kernel.auth.issueKey(ACME, "owner:acme", "owner", root);
  const resolvedAcmeOwner = await kernel.auth.resolve(acmeKey.plaintext);
  if (!resolvedAcmeOwner) throw new Error("acme owner did not resolve");
  acmeOwner = resolvedAcmeOwner;

  // Same canonical entity and scope, but contradictory claims from a connected
  // document and a captured agent session in an ACME descendant namespace.
  acmeDocumentId = await seedFact({
    namespace: ACME_SUPPORT,
    content: "The refund window is 30 days. [entities: refund-policy]",
    source: "document",
    sourceId: "kb:handbook",
    embedding: vector(0),
  });
  acmeConversationId = await seedFact({
    namespace: ACME_SUPPORT,
    content: "The refund window is 14 days. [entities: refund-policy]",
    source: "conversation",
    session: "agent-session-42",
    embedding: vector(1),
  });
  acmeCompatibleId = await seedFact({
    namespace: ACME_SUPPORT,
    content: "Refund requests are handled by the Support team. [entities: refund-policy]",
    source: "manual",
    sourceId: "manual:operations",
    embedding: vector(2),
  });

  // A sibling tenant deliberately carries the same entity and must never be
  // selected as evidence by the ACME organization scan.
  globexDocumentId = await seedFact({
    namespace: GLOBEX,
    content: "The refund window is 7 days. [entities: refund-policy]",
    source: "document",
    sourceId: "kb:globex-handbook",
    embedding: vector(3),
  });
});

afterAll(async () => {
  await kernel.close();
  await rm(knowledgeDir, { recursive: true, force: true });
});

describe("organization conflict scans", () => {
  it("reads descendant memory, excludes a sibling tenant, and pairs conversation with document evidence", async () => {
    const scanId = await runScan();
    const run = await kernel.getConflictScan(scanId, acmeOwner);

    expect(run).not.toBeNull();
    expect(run!.status).toMatch(/^completed(?:_with_gaps)?$/);
    expect(run!.progress.itemsScanned).toBe(3);
    expect(run!.progress.itemsTotal).toBe(3);
    expect(run!.progress.sourcesReached).toBeGreaterThanOrEqual(2);
    expect(run!.progress.agentSummaries).toBe(1);
    expect(run!.summary.newFindings).toBe(1);

    const rows = await kernel.db.query(
      `SELECT left_memory_id, right_memory_id
         FROM conflict_scan_findings
        WHERE target_namespace = $1 AND status = 'open'`,
      [ACME],
    );
    expect(rows.rows).toHaveLength(1);
    const evidence = new Set([
      String(rows.rows[0].left_memory_id),
      String(rows.rows[0].right_memory_id),
    ]);
    expect(evidence).toEqual(new Set([acmeDocumentId, acmeConversationId]));
    expect(evidence.has(acmeCompatibleId)).toBe(false);
    expect(evidence.has(globexDocumentId)).toBe(false);

    const unified = await kernel.listConflicts(acmeOwner);
    expect(unified.scanFindings).toHaveLength(1);
    expect(unified.disputes).toEqual([]);
    expect(unified.latestScan?.id).toBe(scanId);
    expect(unified.scans.map((scan) => scan.id)).toContain(scanId);
    expect(unified.scans[0]!.targetNamespace).toBe(ACME);
    expect(classificationCalls).toBeGreaterThan(0);
  });

  it("does not confuse same-entity compatible facts with contradictions", async () => {
    const rows = await kernel.db.query(
      `SELECT left_memory_id,right_memory_id FROM conflict_scan_findings
        WHERE target_namespace = $1 AND status = 'open'`,
      [ACME],
    );
    const evidencePairs = rows.rows.map((row) => new Set([
      String(row.left_memory_id),
      String(row.right_memory_id),
    ]));
    expect(evidencePairs.some((pair) => pair.has(acmeCompatibleId))).toBe(false);
  });

  it("re-running the same scan updates the existing finding instead of flooding S11", async () => {
    const scanId = await runScan();
    const run = await kernel.getConflictScan(scanId, acmeOwner);

    expect(run).not.toBeNull();
    expect(run!.summary.newFindings).toBe(0);
    expect(run!.summary.existingFindings).toBe(1);

    const rows = await kernel.db.query(
      `SELECT id, fingerprint, first_scan_id, last_scan_id
         FROM conflict_scan_findings
        WHERE target_namespace = $1 AND status = 'open'`,
      [ACME],
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0].first_scan_id).not.toBe(rows.rows[0].last_scan_id);

    const unified = await kernel.listConflicts(acmeOwner);
    expect(unified.scanFindings).toHaveLength(1);
  });

  it("persists evidence references and operational metadata without copied fact content", async () => {
    const columns = await kernel.db.query(
      `SELECT column_name
         FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'conflict_scan_findings'`,
    );
    const names = new Set(columns.rows.map((row) => String(row.column_name)));
    expect(names.size).toBeGreaterThan(0);
    expect(names.has("content")).toBe(false);
    expect(names.has("body")).toBe(false);
    expect(names.has("left_content")).toBe(false);
    expect(names.has("right_content")).toBe(false);

    const persisted = await kernel.db.query(`SELECT * FROM conflict_scan_findings`);
    const serialized = JSON.stringify(persisted.rows);
    expect(serialized).not.toContain("The refund window is 30 days");
    expect(serialized).not.toContain("The refund window is 14 days");
    expect(serialized).not.toContain("The refund window is 7 days");
  });

  it("does not grant global tenant visibility to an empty-namespace non-owner", async () => {
    await expect(kernel.requestConflictScan(rootAdmin, {})).rejects.toThrow(/root owner|global/i);
    const denied = await kernel.db.query(
      `SELECT result FROM audit_log WHERE actor = $1 AND op = 'conflict_scan' ORDER BY seq DESC LIMIT 1`,
      [rootAdmin.actor],
    );
    expect(denied.rows[0]?.result).toBe("denied");
  });

  it("stores only a digest of a natural-language focus", async () => {
    const secret = "quarterly-secret-project-aurora";
    const requested = await kernel.requestConflictScan(acmeOwner, { focus: secret });
    await kernel.runConflictScanJobsOnce();
    const persisted = await kernel.db.query(`SELECT focus FROM conflict_scan_runs WHERE id = $1`, [requested.id]);
    expect(JSON.stringify(persisted.rows)).not.toContain(secret);
    expect(String(persisted.rows[0].focus)).toMatch(/digest/);
  });

  it("reclaims a stale running scan after process interruption", async () => {
    const requested = await kernel.requestConflictScan(acmeOwner, {});
    await kernel.db.query(
      `UPDATE conflict_scan_runs SET status='running',phase='collecting',
          started_at=CURRENT_TIMESTAMP - INTERVAL '10 minutes',
          heartbeat_at=CURRENT_TIMESTAMP WHERE id=$1`,
      [requested.id],
    );
    expect(await kernel.runConflictScanJobsOnce()).toEqual({ claimed: 0, completed: 0, failed: 0 });
    await kernel.db.query(
      `UPDATE conflict_scan_runs SET heartbeat_at=CURRENT_TIMESTAMP - INTERVAL '10 minutes'
        WHERE id=$1`,
      [requested.id],
    );
    const pass = await kernel.runConflictScanJobsOnce();
    expect(pass).toEqual({ claimed: 1, completed: 1, failed: 0 });
    expect((await kernel.getConflictScan(requested.id, acmeOwner))?.status).toMatch(/^completed/);
  });

  it("hides open findings as soon as either evidence fact is no longer current", async () => {
    await kernel.db.query(`UPDATE memory_objects SET status='archived' WHERE id=$1`, [acmeConversationId]);
    const unified = await kernel.listConflicts(acmeOwner);
    expect(unified.scanFindings).toEqual([]);
  });

  it("sends near-identical high-similarity facts to the semantic judge", async () => {
    const highSimilarity = vector(77);
    const left = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Highsim refunds are allowed for 30 days. [entities: highsim-refund]",
      source: "manual",
      sourceId: "manual:highsim-30",
      embedding: highSimilarity,
    });
    const right = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Highsim refunds are allowed for 14 days. [entities: highsim-refund]",
      source: "conversation",
      sourceId: "conversation:highsim-14",
      embedding: highSimilarity,
    });
    const requested = await kernel.requestConflictScan(acmeOwner, { focus: "highsim" });
    await kernel.runConflictScanJobsOnce();
    const findings = (await kernel.listConflicts(acmeOwner)).scanFindings;
    expect(findings.some((finding) => {
      const ids = new Set([finding.left.id, finding.right.id]);
      return ids.has(left) && ids.has(right);
    })).toBe(true);
  });

  it("publishes nothing when evidence stops being current during model review", async () => {
    const left = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Changing refunds are allowed for 30 days. [entities: changing-refund]",
      source: "manual",
      sourceId: "manual:changing-30",
      embedding: vector(78),
    });
    const right = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Changing refunds are allowed for 14 days. [entities: changing-refund]",
      source: "conversation",
      sourceId: "conversation:changing-14",
      embedding: vector(78),
    });
    let release!: () => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    classificationHook = async () => { entered(); await releasePromise; };
    const requested = await kernel.requestConflictScan(acmeOwner, { focus: "changing" });
    const worker = kernel.runConflictScanJobsOnce();
    await enteredPromise;
    await kernel.db.query(`UPDATE memory_objects SET status='archived' WHERE id=$1`, [right]);
    release();
    await worker;
    const run = await kernel.getConflictScan(requested.id, acmeOwner);
    expect(run?.status).toBe("completed_with_gaps");
    expect(run?.summary.coverageGaps).toContain("evidence_changed_during_scan");
    const findings = (await kernel.listConflicts(acmeOwner)).scanFindings;
    expect(findings.some((finding) => {
      const ids = new Set([finding.left.id, finding.right.id]);
      return ids.has(left) && ids.has(right);
    })).toBe(false);
  });

  it("fences a stale worker after another attempt reclaims its lease", async () => {
    const left = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Leaseguard refunds are allowed for 30 days. [entities: leaseguard-refund]",
      source: "manual",
      sourceId: "manual:leaseguard-30",
      embedding: vector(79),
    });
    const right = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Leaseguard refunds are allowed for 14 days. [entities: leaseguard-refund]",
      source: "conversation",
      sourceId: "conversation:leaseguard-14",
      embedding: vector(79),
    });
    let release!: () => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    classificationHook = async () => { entered(); await releasePromise; };
    const requested = await kernel.requestConflictScan(acmeOwner, { focus: "leaseguard" });
    const oldWorker = kernel.runConflictScanJobsOnce();
    await enteredPromise;
    await kernel.db.query(
      `UPDATE conflict_scan_runs SET heartbeat_at=CURRENT_TIMESTAMP - INTERVAL '10 minutes' WHERE id=$1`,
      [requested.id],
    );
    const replacement = await kernel.conflictScans.runOnce();
    expect(replacement).toEqual({ claimed: 1, completed: 1, failed: 0 });
    release();
    expect(await oldWorker).toEqual({ claimed: 1, completed: 0, failed: 0 });
    expect((await kernel.getConflictScan(requested.id, acmeOwner))?.status).toMatch(/^completed/);
    const findings = (await kernel.listConflicts(acmeOwner)).scanFindings.filter((finding) => {
      const ids = new Set([finding.left.id, finding.right.id]);
      return ids.has(left) && ids.has(right);
    });
    expect(findings).toHaveLength(1);
  });

  it("deduplicates concurrent scan requests for the same target", async () => {
    const first = await kernel.requestConflictScan(acmeOwner, { focus: "no-such-focus" });
    const second = await kernel.requestConflictScan(acmeOwner, { focus: "another-focus" });
    expect(second.id).toBe(first.id);
    const audits = await kernel.db.query(
      `SELECT detail FROM audit_log WHERE op='conflict_scan'
        AND purpose='organization-conflict-scan-request' AND detail LIKE $1`,
      [`scan_id=${first.id}%`],
    );
    expect(audits.rows).toHaveLength(2);
    expect(audits.rows.some((row) => String(row.detail).includes("reused=true"))).toBe(true);
    await kernel.runConflictScanJobsOnce();
  });

  it("lets a reviewer keep one side, retiring the other by closing its validity", async () => {
    const kept = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Resolveme refunds are allowed for 30 days. [entities: resolveme-refund]",
      source: "manual",
      sourceId: "manual:resolveme-30",
      embedding: vector(81),
    });
    const retired = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Resolveme refunds are allowed for 14 days. [entities: resolveme-refund]",
      source: "conversation",
      sourceId: "conversation:resolveme-14",
      embedding: vector(81),
    });
    await kernel.requestConflictScan(acmeOwner, { focus: "resolveme" });
    await kernel.runConflictScanJobsOnce();
    const finding = (await kernel.listConflicts(acmeOwner)).scanFindings.find((entry) => {
      const ids = new Set([entry.left.id, entry.right.id]);
      return ids.has(kept) && ids.has(retired);
    });
    expect(finding).toBeDefined();

    const keep = finding!.left.id === kept ? "left" : "right";
    const result = await kernel.resolveConflictFinding(
      acmeOwner, finding!.id, keep, finding!.rowVersion,
    );
    expect(result).toMatchObject({
      status: "resolved", keptMemoryId: kept, retiredMemoryId: retired,
    });

    // D7: the retired fact is still there, its validity simply ends.
    const facts = await kernel.db.query(
      `SELECT id,status,t_valid_to,supersedes FROM memory_objects WHERE id = ANY($1::text[])`,
      [[kept, retired]],
    );
    const byId = new Map(facts.rows.map((row) => [String(row.id), row as Record<string, unknown>]));
    expect(byId.size).toBe(2);
    expect(byId.get(retired)!.t_valid_to).not.toBeNull();
    expect(byId.get(kept)!.t_valid_to).toBeNull();
    expect(String(byId.get(kept)!.supersedes)).toBe(retired);

    // The conflict leaves the queue because the disagreement left memory.
    const after = await kernel.listConflicts(acmeOwner);
    expect(after.scanFindings.some((entry) => entry.id === finding!.id)).toBe(false);
    expect(await kernel.countOpenConflicts(acmeOwner)).toBe(after.scanFindings.length + after.disputes.length);

    // One terminal resolution per finding, ever.
    await expect(kernel.resolveConflictFinding(
      acmeOwner, finding!.id, keep, finding!.rowVersion,
    )).rejects.toThrow(/refresh and try again/);

    const audit = await kernel.db.query(
      `SELECT op,detail FROM audit_log
        WHERE purpose='conflict-scan-finding-resolve' AND namespace=$1 ORDER BY op`,
      [ACME],
    );
    expect(audit.rows.map((row) => String(row.op))).toEqual(["resolve", "supersede"]);
    expect(String(audit.rows[0]!.detail)).toContain(`retired=${retired}`);
  });

  it("hands S6 the same open-conflict number S11 lists", async () => {
    // The console slice is assembled by hand, so a method that exists on the
    // kernel but is not wired into it silently degrades the S6 tile to
    // "count unavailable" — which is exactly what shipped until a live console
    // run caught it. Pin the seam, not just the counter.
    const view = await kernel.sourcesView(acmeOwner);
    expect(view.openConflicts).toBe(await kernel.countOpenConflicts(acmeOwner));
    expect(typeof view.openConflicts).toBe("number");
  });

  it("refuses a resolution from a caller outside the finding's subtree", async () => {
    const globexKey = await kernel.auth.issueKey(GLOBEX, "owner:globex", "owner", rootOwner);
    const globexOwner = await kernel.auth.resolve(globexKey.plaintext);
    if (!globexOwner) throw new Error("globex owner did not resolve");
    const acmeFindings = (await kernel.listConflicts(acmeOwner)).scanFindings;
    const target = acmeFindings[0];
    expect(target).toBeDefined();
    await expect(kernel.resolveConflictFinding(
      globexOwner, target!.id, "left", target!.rowVersion,
    )).rejects.toThrow(/outside the caller's subtree/);
    const still = await kernel.db.query(
      `SELECT status FROM conflict_scan_findings WHERE id=$1`, [target!.id],
    );
    expect(String(still.rows[0]!.status)).toBe("open");
  });

  it("does not use model confidence percentages as a publication gate", async () => {
    const left = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Lowconf refunds are allowed for 30 days. [entities: lowconf-refund]",
      source: "manual",
      sourceId: "manual:lowconf-30",
      embedding: vector(80),
    });
    const right = await seedFact({
      namespace: ACME_SUPPORT,
      content: "Lowconf refunds are allowed for 14 days. [entities: lowconf-refund]",
      source: "conversation",
      sourceId: "conversation:lowconf-14",
      embedding: vector(80),
    });
    const requested = await kernel.requestConflictScan(acmeOwner, { focus: "lowconf" });
    await kernel.runConflictScanJobsOnce();
    const run = await kernel.getConflictScan(requested.id, acmeOwner);
    expect(run?.summary.coverageGaps).not.toContain("low_confidence_model_positive");
    const findings = (await kernel.listConflicts(acmeOwner)).scanFindings;
    expect(findings.some((finding) => {
      const ids = new Set([finding.left.id, finding.right.id]);
      return ids.has(left) && ids.has(right);
    })).toBe(true);
  });
});

describe("conflict scan classifier brownout", () => {
  it("publishes no findings and reports a coverage gap when no semantic judge is configured", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-no-model-"));
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: null,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("brownout", "owner:brownout", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("brownout owner did not resolve");

      const index = new MemoryIndex(isolated.db);
      const now = new Date().toISOString();
      for (const [content, embedding] of [
        ["The refund window is 30 days. [entities: refund-policy]", vector(0)],
        ["The refund window is 14 days. [entities: refund-policy]", vector(1)],
      ] as const) {
        const id = ulid();
        await index.insert({
          id,
          namespace: "brownout",
          scope: "team",
          tier: "L2",
          backendRef: "inline",
          content,
          type: "fact",
          confidence: 1,
          eventTime: null,
          assertionTime: now,
          tValidFrom: now,
          tValidTo: null,
          supersedes: null,
          provenance: [{ source: "manual", actor: "owner:brownout", ts: now }],
          ttlSeconds: null,
          telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
          status: "active",
        }, embedding);
      }

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);
      expect(completed?.status).toBe("completed_with_gaps");
      expect(completed?.summary.coverageGaps).toContain("contradiction_model_unavailable");
      expect((await isolated.listConflicts(owner)).scanFindings).toEqual([]);
      const audit = await isolated.db.query(
        `SELECT detail FROM audit_log WHERE op='conflict_scan' AND purpose='organization-conflict-scan-complete'
          ORDER BY seq DESC LIMIT 1`,
      );
      expect(String(audit.rows[0]?.detail)).toContain("model_decisions=0");
      await expect(isolated.requestConflictScan(owner, {})).rejects.toThrow(/five minutes/i);
      const denied = await isolated.db.query(
        `SELECT detail FROM audit_log WHERE op='conflict_scan' AND result='denied' ORDER BY seq DESC LIMIT 1`,
      );
      expect(String(denied.rows[0]?.detail)).toBe("code=cooldown");
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("spends the judge budget on a cross-source disagreement, not on rows of one table", async () => {
    // Reproduces the production failure: an imported metrics table shares one
    // canonical entity across every row, and its adjacent rows are the most
    // textually similar pairs in the corpus. Under a similarity-first ranking
    // they consumed the entire model budget and were published as "conflicting
    // quantities", while the disagreement that actually matters — an agent's
    // claim against a connected document — was never judged at all.
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-table-noise-"));
    const seen: string[] = [];
    const judge: ConflictClassifier = {
      model: "test-semantic-judge",
      async classify(candidates: readonly ConflictClassificationCandidate[]) {
        return candidates.map((candidate) => {
          const pair = `${candidate.left.content}\n${candidate.right.content}`;
          seen.push(pair);
          const contradiction = pair.includes("president");
          return {
            candidateId: candidate.id,
            contradiction,
            confidence: contradiction ? 0.96 : 0.9,
            reason: contradiction ? "conflicting_value" : "other_semantic_conflict",
          };
        });
      },
    };
    const isolated = await Kernel.boot({
      databaseUrl: "", pgliteDataDir: "", knowledgeDir: dir,
      anthropicApiKey: "", openaiApiKey: "", embedDim: 256, conflictClassifier: judge,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("noise", "owner:noise", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("noise owner did not resolve");

      const index = new MemoryIndex(isolated.db);
      const now = new Date().toISOString();
      const plant = async (
        content: string,
        source: ProvenanceEntry["source"],
        embedding: number[],
      ) => {
        await index.insert({
          id: ulid(), namespace: "noise", scope: "team", tier: "L2", backendRef: "inline",
          content, type: "fact", confidence: 1, eventTime: null, assertionTime: now,
          tValidFrom: now, tValidTo: null, supersedes: null,
          provenance: [{
            source,
            actor: source === "conversation" ? "agent:sales" : "connector:metrics",
            ...(source === "document" ? { sourceId: "src-metrics" } : {}),
            ts: now,
          }],
          ttlSeconds: null, telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
          status: "active",
        }, embedding);
      };
      // Near-identical vectors: these are the corpus's highest-similarity pairs.
      const nearIdentical = (seed: number) =>
        Array.from({ length: 256 }, (_, i) => i === 0 ? 1 : i === (seed % 254) + 1 ? 0.05 : 0);
      for (let day = 1; day <= 30; day += 1) {
        await plant(
          `metric_id: MET-012-${String(day).padStart(2, "0")}, campaign_id: CMP-012, `
          + `metric_date: 2026-04-${String(day).padStart(2, "0")}, channel: paid_search, `
          + `impressions: ${4000 + day * 7}, clicks: ${110 + day} [entities: Autumn Campaign]`,
          "document",
          nearIdentical(day),
        );
      }
      await plant("Priya Raghavan is the president of Halofy. [entities: Halofy]",
        "document", vector(200));
      await plant("Rahul Menon is the president of Halofy. [entities: Halofy]",
        "conversation", vector(201));

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);
      expect(completed?.phase).toBe("complete");

      // Every row pair is a different observation of the same campaign, so none
      // of them may reach the judge — however similar their text.
      expect(seen.some((pair) => pair.includes("impressions"))).toBe(false);
      expect(seen).toHaveLength(1);
      expect(seen[0]).toContain("president");

      const findings = (await isolated.listConflicts(owner)).scanFindings;
      expect(findings).toHaveLength(1);
      expect(findings[0]?.entity).toBe("Halofy");
      expect(findings[0]?.flags).toContain("cross-source");
      expect(findings[0]?.flags).toContain("agent-derived");
      // Both evidence facts must be nameable in the UI without a ULID.
      expect(findings[0]?.left.sourceName ?? findings[0]?.left.source).toBeTruthy();
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("atomically caps the durable queued backlog under concurrent targets", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-queue-cap-"));
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: null,
      conflictScanRequestCooldownMs: 0,
    });
    try {
      const key = await isolated.auth.issueKey("", "owner:root", "owner");
      const owner = await isolated.auth.resolve(key.plaintext);
      if (!owner) throw new Error("root owner did not resolve");
      const failingAudit = {
        async append() { throw new Error("audit unavailable"); },
        async appendTo() { throw new Error("audit unavailable"); },
      } as unknown as AuditLog;
      const failingService = new ConflictScanService(isolated.db, failingAudit, null, 0);
      await expect(failingService.request(owner, {}, "queue/ghost")).rejects.toThrow(/audit unavailable/);
      const ghosts = await isolated.db.query(
        `SELECT COUNT(*)::int AS count FROM conflict_scan_runs WHERE target_namespace='queue/ghost'`,
      );
      expect(Number(ghosts.rows[0]?.count)).toBe(0);
      const requests = await Promise.allSettled(Array.from({ length: 25 }, (_, index) =>
        isolated.conflictScans.request(owner, {}, `queue/team-${index}`)));
      expect(requests.filter((result) => result.status === "fulfilled")).toHaveLength(20);
      expect(requests.filter((result) => result.status === "rejected")).toHaveLength(5);
      const firstQueued = requests.find((result) => result.status === "fulfilled");
      if (!firstQueued || firstQueued.status !== "fulfilled") throw new Error("queued scan missing");
      await isolated.db.query(
        `UPDATE conflict_scan_runs
            SET status='running',started_at=CURRENT_TIMESTAMP,heartbeat_at=CURRENT_TIMESTAMP,
                lease_token='test-running-lease'
          WHERE id=$1`,
        [firstQueued.value.id],
      );
      await isolated.conflictScans.request(owner, {}, "queue/team-extra");

      const queued = await isolated.db.query(
        `SELECT COUNT(*)::int AS count FROM conflict_scan_runs WHERE status='queued'`,
      );
      expect(Number(queued.rows[0]?.count)).toBe(20);
      const recent = await isolated.conflictScans.recent(owner);
      expect(recent).toHaveLength(21);
      expect(recent.some((run) => run.status === "running")).toBe(true);
      const denied = await isolated.db.query(
        `SELECT COUNT(*)::int AS count FROM audit_log
          WHERE op='conflict_scan' AND result='denied' AND detail='code=queue_full'`,
      );
      expect(Number(denied.rows[0]?.count)).toBe(5);
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("retrieves a bounded neighborhood and drains every candidate in batches of 50", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-bounded-"));
    let classified = 0;
    const batchSizes: number[] = [];
    const seenPairs = new Set<string>();
    const boundedClassifier: ConflictClassifier = {
      model: "test-bounded-judge",
      async classify(candidates) {
        classified += candidates.length;
        batchSizes.push(candidates.length);
        for (const candidate of candidates) {
          seenPairs.add([candidate.left.content, candidate.right.content].sort().join("\0"));
        }
        return candidates.map((candidate) => ({
          candidateId: candidate.id,
          contradiction: false,
          confidence: 0.9,
          reason: "other_semantic_conflict",
        }));
      },
    };
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      conflictScanRequestCooldownMs: 0,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: boundedClassifier,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("bounded", "owner:bounded", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("bounded owner did not resolve");

      for (let index = 0; index < 22; index += 1) {
        await seedFact({
          namespace: "bounded",
          content: `Policy statement ${index}. [entities: shared-policy]`,
          source: "manual",
          sourceId: `manual:${index}`,
          embedding: vector(index),
        }, isolated);
      }

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);
      expect(completed?.status).toBe("completed");
      expect(completed?.summary.coverageGaps).not.toContain("model_candidate_cap_reached");
      expect(classified).toBe(completed?.progress.candidatePairs);
      expect(classified).toBeGreaterThan(50);
      expect(classified).toBeLessThanOrEqual(22 * 8);
      expect(batchSizes[0]).toBe(50);
      expect(batchSizes.length).toBeGreaterThan(1);
      expect(batchSizes.every((size) => size > 0 && size <= 50)).toBe(true);
      expect(completed?.progress.modelPairsReviewed).toBe(classified);
      expect(seenPairs.size).toBe(classified);
      expect((await isolated.listConflicts(owner)).scanFindings).toEqual([]);
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps one global eight-neighbor queue when facts share several subjects", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-neighbor-scale-"));
    const batchSizes: number[] = [];
    const classifier: ConflictClassifier = {
      model: "test-neighbor-scale-judge",
      async classify(candidates) {
        batchSizes.push(candidates.length);
        return candidates.map((candidate) => ({
          candidateId: candidate.id,
          contradiction: false,
          confidence: 0.9,
          reason: "other_semantic_conflict",
        }));
      },
    };
    const isolated = await Kernel.boot({
      databaseUrl: "", pgliteDataDir: "", knowledgeDir: dir,
      conflictScanRequestCooldownMs: 0, anthropicApiKey: "", openaiApiKey: "",
      embedDim: 256, conflictClassifier: classifier,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("scale", "owner:scale", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("scale owner did not resolve");

      const now = new Date().toISOString();
      const provenance = JSON.stringify([{
        source: "document", sourceId: "kb:scale", actor: "connector:scale", ts: now,
      }]);
      const ids = Array.from({ length: 191 }, () => ulid());
      await isolated.db.query(
        `INSERT INTO memory_objects
           (id,namespace,scope,tier,backend_ref,content,type,confidence,
            assertion_time,t_valid_from,provenance,status,embedding)
         SELECT seed.id,'scale','team','L2','inline',
                'Shared policy statement ' || seed.ordinal || ' [entities: Shared Policy, Segment ' ||
                CASE (seed.ordinal - 1) % 4
                  WHEN 0 THEN 'Alpha' WHEN 1 THEN 'Beta'
                  WHEN 2 THEN 'Gamma' ELSE 'Delta'
                END || ']',
                'fact',1,$1,$1,$2::jsonb,'active',$3::vector
           FROM unnest($4::text[]) WITH ORDINALITY AS seed(id, ordinal)`,
        [now, provenance, `[${vector(0).join(",")}]`, ids],
      );

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);
      const theoreticalAllPairs = (191 * 190) / 2;

      expect(theoreticalAllPairs).toBe(18_145);
      expect(completed?.status).toBe("completed");
      expect(completed?.progress.candidatePairs).toBeLessThanOrEqual(191 * 8);
      expect(completed?.progress.candidatePairs).toBeLessThan(theoreticalAllPairs / 10);
      expect(completed?.progress.modelPairsReviewed).toBe(completed?.progress.candidatePairs);
      expect(batchSizes.length).toBeGreaterThan(1);
      expect(batchSizes.every((size) => size > 0 && size <= 50)).toBe(true);
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("deduplicates a shared evidence pair independently of display entity and omits same-source flags", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-fingerprint-"));
    const alwaysContradiction: ConflictClassifier = {
      model: "test-semantic-judge",
      async classify(candidates) {
        return candidates.map((candidate) => ({
          candidateId: candidate.id,
          contradiction: true,
          confidence: 0.97,
          reason: "conflicting_quantity",
        }));
      },
    };
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      conflictScanRequestCooldownMs: 0,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: alwaysContradiction,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("stable", "owner:stable", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("stable owner did not resolve");

      await seedFact({
        namespace: "stable",
        content: "Stable refunds are allowed for 30 days. [entities: alpha, bravo]",
        source: "document",
        sourceId: "kb:shared",
        embedding: vector(0),
      }, isolated);
      await seedFact({
        namespace: "stable",
        content: "Stable refunds are allowed for 14 days. [entities: alpha, bravo]",
        source: "document",
        sourceId: "kb:shared",
        embedding: vector(1),
      }, isolated);

      const first = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      expect((await isolated.getConflictScan(first.id, owner))?.summary.newFindings).toBe(1);

      await isolated.db.query(
        `INSERT INTO conflict_scan_findings
           (id,target_namespace,left_memory_id,right_memory_id,fingerprint,detector_version,
            entity,category,reason,confidence,flags,status,row_version,first_scan_id,last_scan_id,
            first_seen_at,last_seen_at)
         SELECT $2,target_namespace,left_memory_id,right_memory_id,$3,detector_version,
                'bravo',category,reason,confidence,flags,'open',1,first_scan_id,last_scan_id,
                first_seen_at,last_seen_at
           FROM conflict_scan_findings WHERE target_namespace = $1 LIMIT 1`,
        ["stable", ulid(), `legacy-${ulid()}`],
      );

      const second = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const secondRun = await isolated.getConflictScan(second.id, owner);
      const findings = (await isolated.listConflicts(owner)).scanFindings;

      expect(findings).toHaveLength(1);
      expect(secondRun?.summary.existingFindings).toBe(1);
      expect(findings[0]?.flags).not.toContain("cross-source");

      await isolated.db.query(
        `UPDATE conflict_scan_findings SET status='dismissed' WHERE target_namespace=$1`,
        ["stable"],
      );
      const third = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      expect((await isolated.getConflictScan(third.id, owner))?.summary.existingFindings).toBe(0);
      expect((await isolated.listConflicts(owner)).scanFindings).toEqual([]);
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("covers a corpus larger than the retired 2,000-fact window in one scan", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-total-"));
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      conflictScanRequestCooldownMs: 0,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: null,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("capped", "owner:capped", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("capped owner did not resolve");

      const now = new Date().toISOString();
      const provenance = JSON.stringify([{
        source: "document",
        sourceId: "kb:capped",
        actor: "connector:handbook",
        ts: now,
      }]);
      const ids = Array.from({ length: 2_001 }, () => ulid());
      await isolated.db.query(
        `INSERT INTO memory_objects
           (id,namespace,scope,tier,backend_ref,content,type,confidence,
            assertion_time,t_valid_from,provenance,status,embedding)
         SELECT seed.id,'capped','team','L2','inline',
                'Capped fact ' || seed.ordinal || ' [entities: capped-' || seed.ordinal || ']',
                'fact',1,$1,$1,$2::jsonb,'active',$3::vector
           FROM unnest($4::text[]) WITH ORDINALITY AS seed(id, ordinal)`,
        [now, provenance, `[${vector(0).join(",")}]`, ids],
      );

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);

      expect(completed?.status).toBe("completed");
      expect(completed?.progress.itemsScanned).toBe(2_001);
      expect(completed?.progress.itemsTotal).toBe(2_001);
      expect(completed?.summary.coverageGaps).not.toContain("fact_cap_reached");
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("checks entityless facts through the vector fallback without inventing a coverage gap", async () => {
    const dir = await mkdtemp(join(tmpdir(), "halomem-conflict-scan-uncovered-"));
    const isolated = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      conflictScanRequestCooldownMs: 0,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
      conflictClassifier: conflictClassifier,
    });
    try {
      const rootKey = await isolated.auth.issueKey("", "owner:root", "owner");
      const root = await isolated.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root owner did not resolve");
      const ownerKey = await isolated.auth.issueKey("uncovered", "owner:uncovered", "owner", root);
      const owner = await isolated.auth.resolve(ownerKey.plaintext);
      if (!owner) throw new Error("uncovered owner did not resolve");

      await seedFact({
        namespace: "uncovered",
        content: "The unannotated refund window is 30 days.",
        source: "document",
        sourceId: "kb:unannotated",
        embedding: vector(0),
      }, isolated);
      await seedFact({
        namespace: "uncovered",
        content: "The unannotated refund window is 14 days.",
        source: "manual",
        sourceId: "manual:unannotated",
        embedding: vector(1),
      }, isolated);

      const requested = await isolated.requestConflictScan(owner, {});
      await isolated.runConflictScanJobsOnce();
      const completed = await isolated.getConflictScan(requested.id, owner);

      expect(completed?.status).toBe("completed");
      expect(completed?.progress.itemsScanned).toBe(2);
      expect(completed?.progress.itemsTotal).toBe(2);
      expect(completed?.progress.agentSummaries).toBe(0);
      expect(completed?.summary.coverageGaps).not.toContain("entity_metadata_unavailable");
      expect(completed?.summary.coverageGaps).not.toContain("agent_capture_unavailable");
      expect((await isolated.listConflicts(owner)).scanFindings).toHaveLength(1);
    } finally {
      await isolated.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
