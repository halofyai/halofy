/**
 * HaloMem kernel demo — the PRD's "one chat, end to end" shape in miniature.
 *
 * Run: npm run demo
 *
 * Boots the kernel fully in-memory (embedded PGlite + pgvector, HashEmbedder,
 * StubLlm — zero network, zero disk) against the sample knowledge repo in
 * ./knowledge, then walks one support conversation through every syscall:
 *
 *   T-1 issue an owner API key (bootstrap path) and resolve it → Identity (D9)
 *   T0  pin encrypted concepts/refund-policy.okf.enc via policy + mem_assemble
 *   T1  mem_write: extract 2 facts from a fake support transcript
 *   T2  mem_search: hybrid vector+BM25 retrieval over the new facts
 *   T3  mem_fault: a question L2 cannot answer, served from the L3 cold tier
 *   T4  mem_write: capture a changed address with the deterministic stub
 *   T5  mem_stats + the audit trail (every op above left a row)
 *   T6  import + fragmentation (M3, D10): a legacy CRM dump is imported through
 *       the SAME write path (provenance source='swap-import'), a second team's
 *       conflicting fact lands org-wide, then runFragmentation shows the org its
 *       own cross-source duplicate + contradiction. Real numbers from the run.
 */

import { promises as fs, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Kernel } from "./kernel.js";
import { renderFragmentationMarkdown } from "./ingest/fragmentation.js";
import type { WriteResult } from "./types.js";
import type { MemWriteResult } from "./syscalls/index.js";

const NS = "org/support/agent-1";
const ACTOR = "user:dana";
const AGENT = "agent-1";

function trunc(s: string, n = 100): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length <= n ? one : `${one.slice(0, n - 1)}…`;
}

function step(label: string, title: string): void {
  console.log(`\n== ${label} ${"·".repeat(2)} ${title}`);
}

/** Demo writes are synchronous — narrow the union. */
function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async write ticket in demo");
  return result;
}

async function main(): Promise<void> {
  const knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-demo-knowledge-"));
  const coldKek = randomBytes(32).toString("base64");

  const kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "", // in-memory PGlite
    knowledgeDir,
    coldKek,
  });

  // -------------------------------------------------------------------------
  step("T-1", "bootstrap the platform owner, then issue and resolve a tenant-bound key");
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const rootIdentity = await kernel.auth.resolve(rootKey.plaintext);
  if (!rootIdentity) throw new Error("platform owner key failed to resolve");
  const demoConcepts = [
    {
      path: "concepts/refund-policy.okf.enc",
      namespace: "org",
      type: "policy",
      title: "Refund policy",
      description: "When and how Halo issues customer refunds.",
      tags: ["support", "payments", "policy"],
      owner: "ops",
      body: "Refunds are issued in full before preparation. Refunds over $50 require support lead approval.",
    },
    {
      path: "concepts/escalation-matrix.okf.enc",
      namespace: "org",
      type: "runbook",
      title: "Support escalation matrix",
      description: "Who handles each class of customer issue.",
      tags: ["support", "runbook"],
      owner: "support",
      body: "Allergy incidents page Tier 2 immediately. Platform outages and privacy requests escalate to Tier 3.",
    },
    {
      path: "concepts/ordering-platforms.okf.enc",
      namespace: "org",
      type: "reference",
      title: "Ordering platform integrations",
      description: "Supported delivery platform behavior.",
      tags: ["integrations", "reference"],
      owner: "platform",
      body: "Halo integrates with DoorDash, UberEats, and Grubhub. Sold-out items propagate within two minutes.",
    },
  ];
  for (const concept of demoConcepts) {
    await kernel.createPrivateConcept(concept, rootIdentity);
  }
  const { record, plaintext } = await kernel.auth.issueKey(
    NS,
    ACTOR,
    "owner",
    rootIdentity,
  );
  console.log(
    `issued key id=${record.id} namespace=${record.namespace} actor=${record.actor} role=${record.role}`,
  );
  console.log(`plaintext (shown once): ${plaintext.slice(0, 8)}…${plaintext.slice(-4)}`);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("freshly-issued key failed to resolve");
  console.log(
    `resolved identity: keyId=${identity.keyId} namespace=${identity.namespace} role=${identity.role} - namespace/actor now come ONLY from this key (D9)`,
  );

  // -------------------------------------------------------------------------
  step("T0", "boot in-memory, pin the refund policy, assemble the working set");
  console.log(
    `booted: embedder=${kernel.embedder.name}(dim=${kernel.embedder.dim}) llm=${kernel.llm.name} knowledge=${knowledgeDir}`,
  );

  await kernel.setPolicy(NS, 'pinnedConcepts:\n  - "concepts/refund-policy.okf.enc"\n');

  const ws = await kernel.memAssemble({}, identity, AGENT);
  console.log(
    `working set for ${NS}: ${ws.blocks.length} block(s), ${ws.totalTokens}/${ws.budget} tokens`,
  );
  for (const b of ws.blocks) {
    console.log(`  [${b.kind}] ${b.ref} (${b.tokenEstimate} tok): ${trunc(b.content, 80)}`);
  }

  // -------------------------------------------------------------------------
  step("T1", "mem_write - extract facts from a support-chat transcript");
  const transcript = [
    "User: my name is Dana Whitfield and my loyalty tier is Gold",
    "User: customer Dana Whitfield's current shipping address for order 4127 is 12 Elm Street, Springfield",
  ].join("\n");
  console.log(`transcript:\n${transcript.split("\n").map((l) => `  | ${l}`).join("\n")}`);

  const w1 = sync(
    await kernel.memWrite(
      { scope: "user", content: transcript, session: "chat-001" },
      identity,
      AGENT,
    ),
  );
  console.log(
    `write result: stored=${w1.stored.length} rejected=${w1.rejected.length} superseded=${w1.superseded.length} deduplicated=${w1.deduplicated}`,
  );
  for (const m of w1.stored) {
    console.log(`  + ${m.id} [${m.scope}/${m.type}, conf=${m.confidence}] ${trunc(m.content)}`);
  }

  // -------------------------------------------------------------------------
  step("T2", "mem_search - where does order 4127 ship?");
  const hits = await kernel.memSearch(
    { query: "shipping address for order 4127", k: 3 },
    identity,
    AGENT,
  );
  for (const h of hits) {
    console.log(`  score=${h.score.toFixed(3)} [${h.tier}] ${trunc(h.content)}`);
  }

  // -------------------------------------------------------------------------
  step("T3", "mem_fault - allergy escalation is NOT in L2; page it in from L3");
  const fault = await kernel.memFault(
    { query: "which support tier handles an allergy incident escalation?" },
    identity,
    AGENT,
  );
  console.log(
    `fault: hit=${fault.hit} source=${fault.source} injected=${fault.injected.length} latencyMs=${fault.latencyMs}`,
  );
  for (const r of fault.injected) {
    console.log(`  score=${r.score.toFixed(3)} [${r.tier}] ${r.ref}: ${trunc(r.content)}`);
  }

  // -------------------------------------------------------------------------
  step("T4", "mem_write - capture the customer's changed address");
  const w2 = sync(
    await kernel.memWrite(
      {
        scope: "user",
        content:
          "User: customer Dana Whitfield's current shipping address for order 4127 is 99 Oak Street, Springfield",
        session: "chat-002",
      },
      identity,
      AGENT,
    ),
  );
  console.log(
    `write result: stored=${w2.stored.length} superseded=${w2.superseded.length} deduplicated=${w2.deduplicated}`,
  );
  for (const m of w2.stored) {
    console.log(`  + ${m.id} supersedes=${m.supersedes} ${trunc(m.content)}`);
  }
  const oldId = w2.superseded[0];
  if (oldId) {
    // Normal memRead intentionally hides closed history. The demo proves D7
    // retention through an internal history query, not an active read path.
    const oldRes = await kernel.db.query(
      "SELECT t_valid_to, status FROM memory_objects WHERE id = $1",
      [oldId],
    );
    const old = oldRes.rows[0] as { t_valid_to: Date | string | null; status: string } | undefined;
    console.log(
      `  old fact ${oldId} kept for history (D7): tValidTo=${old?.t_valid_to ?? "missing"} status=${old?.status ?? "missing"}`,
    );
    if (!old || old.t_valid_to === null) throw new Error("superseded row was not retained as closed history");
  }

  // -------------------------------------------------------------------------
  step("T5", "mem_stats + audit trail");
  const stats = await kernel.memStats({}, identity, AGENT);
  console.log(
    `stats: l2=${stats.l2Count} l3Concepts=${stats.l3ConceptCount} faults=${stats.faultCount} ` +
      `faultHitRate=${stats.faultHitRate.toFixed(2)} avgWorkingSetTokens=${stats.avgWorkingSetTokens.toFixed(0)} ` +
      `auditEvents=${stats.auditEventCount}`,
  );
  console.log("top accessed:");
  for (const t of stats.topAccessed.slice(0, 3)) {
    console.log(`  ${t.accessCount}x ${trunc(t.content, 80)}`);
  }

  const events = await kernel.audit.list(NS, { limit: 10 });
  console.log(`last ${events.length} audit rows (most recent first):`);
  for (const e of events) {
    console.log(
      `  ${e.ts}  ${e.op.padEnd(9)} ${e.result.padEnd(6)} actor=${e.actor} ${e.detail ? trunc(e.detail, 70) : ""}`,
    );
  }

  // -------------------------------------------------------------------------
  step("T6", "import a legacy dump + a second team's fact, then show fragmentation");

  // (a) A second team records an org-wide fact about the Zephyr subscription
  //     that CONTRADICTS what agent-1 captured — different team, same entity,
  //     both currently valid. It lands at the org/support level (an ancestor of
  //     agent-1) so agent-1's fragmentation view sees it. Ingestion is a write:
  //     it flows through the same extraction/verification/provenance pipeline.
  const ORG_SUPPORT = "org/support";
  const orgKeyRec = await kernel.auth.issueKey(
    ORG_SUPPORT,
    "user:ops",
    "owner",
    rootIdentity,
  );
  const orgIdentity = await kernel.auth.resolve(orgKeyRec.plaintext);
  if (!orgIdentity) throw new Error("org/support key failed to resolve");
  await kernel.db.query(
    `INSERT INTO org_teams
       (id, namespace, organization_namespace, name, description, created_by, created_at)
     VALUES ('demo-support-team', $1, 'org', 'Support', '', $2, $3)`,
    [ORG_SUPPORT, orgIdentity.actor, new Date().toISOString()],
  );

  // agent-1's own record of the subscription (conversation, extracted).
  sync(
    await kernel.memWrite(
      { scope: "user", content: "User: the Zephyr subscription includes unlimited priority support", session: "chat-003" },
      identity,
      AGENT,
    ),
  );
  // the second team's conflicting record (org-wide, different namespace → both
  // stay valid; no cross-namespace supersedence).
  sync(
    await kernel.memWrite(
      { scope: "user", content: "User: the Zephyr subscription was discontinued and no longer offers support", session: "chat-ops" },
      orgIdentity,
      AGENT,
    ),
  );
  console.log(
    "planted a conflicting 'Zephyr subscription' fact at the org/support level (a different team, currently valid alongside agent-1's)",
  );

  // (b) Import a legacy CRM dump (a Mem0-shaped export) at the org/support
  //     level. It re-states Dana's shipping address that agent-1 already has —
  //     a CROSS-SOURCE duplicate (provenance source='swap-import' vs the
  //     conversation fact). D10: the import enters through the write path, so
  //     every landed fact carries its ingestion provenance.
  const dumpPath = fileURLToPath(
    new URL("../test/fixtures/imports/demo-swap-dump.json", import.meta.url),
  );
  const dump = readFileSync(dumpPath, "utf8");
  const importResult = await kernel.importDump("mem0-import", dump, orgIdentity);
  console.log(
    `imported ${importResult.records} record(s) from the legacy CRM dump ` +
      `(source ${importResult.sourceId}): stored=${importResult.stored} ` +
      `deduplicated=${importResult.deduplicated} superseded=${importResult.superseded} ` +
      `rejected=${importResult.rejected}`,
  );

  // (c) Run the fragmentation report over agent-1's view and print it. Numbers
  //     are REAL — computed from the facts actually landed above.
  const report = await kernel.runFragmentation(NS, identity);
  console.log(
    `\nfragmentation for ${NS}: ${report.factCount} facts across ` +
      `${Object.keys(report.sourceCounts).length} source(s) - ` +
      `${report.duplicateClusters.length} duplicate cluster(s), ` +
      `${report.contradictions.length} contradiction(s)`,
  );
  console.log(renderFragmentationMarkdown(report));
  const planted = report.duplicateClusters.find((c) =>
    c.members.some((m) => m.sourceId !== null),
  );
  if (planted) {
    console.log(
      `\n  ↳ planted cross-source duplicate: cosine=${planted.cosine.toFixed(3)}, ` +
        `sources=${[...new Set(planted.members.map((m) => m.sourceId ?? "conversation"))].join(" + ")}`,
    );
  }
  const zephyr = report.contradictions.find((c) => c.entity === "Zephyr");
  if (zephyr) {
    console.log(
      `  ↳ planted contradiction on entity "Zephyr": ${zephyr.facts.length} conflicting valid facts across teams`,
    );
  }

  // -------------------------------------------------------------------------
  step("T7", "mem.forget - erase the customer and mint a signed deletion certificate");

  // Before: agent-1 can still find Dana's shipping fact — captured in
  // conversation (T1/T4) AND re-imported from the legacy CRM (T6).
  const beforeForget = await kernel.memSearch(
    { query: "Dana Whitfield shipping address order 4127", k: 8 },
    identity,
    AGENT,
  );
  const beforeDana = beforeForget.filter((h) => /dana whitfield/i.test(h.content));
  console.log(
    `before forget: mem_search surfaces ${beforeDana.length} Dana Whitfield fact(s) ` +
      `(conversation + imported CRM)`,
  );

  // Right-to-be-forgotten: erase EVERYTHING mentioning the customer entity
  // "Dana Whitfield" across the whole org/support subtree — run as the
  // org/support owner so both agent-1's facts AND the ancestor-level imported
  // CRM fact are in scope. Hard-deletes the rows, writes tombstones, and
  // returns an ed25519-signed certificate (D3 — the ONE governed exception to
  // D7). Owner/admin only; the audit trail SURVIVES (D4).
  const forgetResult = await kernel.memForget(
    { target: { kind: "entity", value: "Dana Whitfield" } },
    orgIdentity,
    AGENT,
  );
  console.log(
    `forget (as ${orgIdentity.namespace}): erased ${forgetResult.erasedCount} row(s), ` +
      `wrote ${forgetResult.tombstones} tombstone(s)`,
  );

  // The certificate verifies against the kernel's trusted boot public key. A
  // regulator must obtain that trust anchor out of band; the signature is real
  // ed25519 over the canonical JSON.
  const verified = kernel.verifyCertificate(forgetResult.certificate);
  console.log(`certificate ${forgetResult.certificate.id} verifyCertificate === ${verified}`);
  console.log(
    `  algorithm=${forgetResult.certificate.algorithm} ` +
      `publicKey=${forgetResult.certificate.publicKey.slice(0, 16)}… ` +
      `signature=${forgetResult.certificate.signature.slice(0, 16)}…`,
  );
  if (!verified) throw new Error("deletion certificate failed to verify");

  // After: the content is gone from EVERY read path — search + getById.
  const afterForget = await kernel.memSearch(
    { query: "Dana Whitfield shipping address order 4127", k: 8 },
    identity,
    AGENT,
  );
  const stillDana = afterForget.filter((h) => /dana whitfield/i.test(h.content));
  console.log(
    `after forget: mem_search surfaces ${stillDana.length} Dana Whitfield fact(s) (expect 0)`,
  );
  if (stillDana.length !== 0) throw new Error("erased content still reachable via mem_search");
  for (const id of forgetResult.certificate.erasedIds) {
    const gone = await kernel.memRead({ id }, orgIdentity, AGENT);
    console.log(`  getById(${id}) found=${gone.found} (expect false - the row is hard-deleted)`);
    if (gone.found) throw new Error(`erased row ${id} still readable`);
  }

  // The audit trail for the erased memory SURVIVES — a 'forget' row now sits
  // alongside the read/write rows for those ids (who wrote it, who erased it).
  const forgetAudit = (await kernel.audit.list(ORG_SUPPORT, { limit: 20 })).filter(
    (e) => e.op === "forget",
  );
  console.log(
    `audit trail intact: ${forgetAudit.length} 'forget' row(s) recorded (the erased content's ` +
      `history is never deleted - D4)`,
  );

  await kernel.close();
  await fs.rm(knowledgeDir, { recursive: true, force: true });
  console.log("\ndemo complete - kernel closed.");
}

main().catch((err) => {
  console.error("demo failed:", err);
  process.exitCode = 1;
});
