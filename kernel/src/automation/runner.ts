/**
 * M9 #19 — automation runner (D30, D2, D4, D10, D20).
 *
 * Claims durable `automation` jobs (E37) and executes the enabled template.
 * Hard rules:
 *
 *  - E35: content output is ALWAYS a `pending_review` KnowledgeProposal via
 *    the existing consolidation review pipeline — never a direct store write.
 *    The runner is purely a PRODUCER for "proposes, never overwrites" (#20).
 *  - E36: recurrence is a durable `notBefore` re-arm committed atomically
 *    with the run outcome — never an in-kernel setInterval/timer.
 *  - E34: every run writes an `automation_run` audit row — ok, miss, and
 *    failed alike (D4).
 *  - Brownout: a failing template degrades (audited `error` outcome, next
 *    occurrence still armed); the worker loop keeps running.
 *
 * The `re-sync` template is the one non-proposal template: it re-queues
 * stale sources as durable `source-sync` jobs, so content still flows
 * connector → sink → write path (D10). It never touches memory rows.
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import { escapeLikePattern } from "../db/client.js";
import type { AuditEvent, Identity, Namespace } from "../types.js";
import { DurableJobStore } from "../durable/jobs.js";
import type {
  KnowledgeProposal,
  ManualConsolidationInput,
  PreparedConsolidation,
} from "../consolidation/index.js";
import {
  OrgAutomationStore,
  automationJobId,
  type AutomationJobPayload,
  type OrgAutomation,
} from "./store.js";
import { automationTemplate } from "./catalog.js";

/**
 * Structural seam over ConsolidationService — the ONLY way this module can
 * produce knowledge. `prepare` drafts + verifies + encrypts; committing the
 * prepared run inserts `pending_review` proposals and their `propose` audit
 * rows (E35). `approve` is the same governed pipeline humans use; it is
 * invoked only for org-opted `auto_approve` rows and still re-verifies and
 * audits `approve`/`publish` per proposal.
 */
export interface AutomationProposer {
  prepare(identity: Identity, input: ManualConsolidationInput): Promise<PreparedConsolidation>;
  get(identity: Identity, proposalId: string): Promise<KnowledgeProposal | null>;
  approve(
    identity: Identity,
    proposalId: string,
    input: { expectedRowVersion: number },
  ): Promise<KnowledgeProposal>;
}

interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

/**
 * Structural slice of CreditMeter.charge (E40 — #21): the automation_run
 * entitlement gate. Optional so hermetic unit tests run without billing;
 * absent → the lane is ungated (a deployment without the credit system).
 */
export interface AutomationEntitlementMeter {
  charge(
    identity: Identity,
    feature: "automation_run",
    opts?: { units?: number; reason?: string; idempotencyKey?: string },
  ): Promise<{ ok: boolean; state?: string }>;
}

export interface AutomationRunnerDeps {
  db: Db;
  audit: AuditWriter;
  store: OrgAutomationStore;
  proposer: AutomationProposer;
  /** E40: charges one automation_run per occurrence; empty balance degrades. */
  meter?: AutomationEntitlementMeter;
  /** Invite-only launch allowance. False degrades the occurrence before work. */
  earlyAccess?: (identity: Identity, idempotencyKey: string) => Promise<boolean>;
  now?: () => Date;
}

export interface AutomationRunSummary {
  claimed: number;
  completed: number;
  proposals: number;
}

interface TemplateOutcome {
  result: "ok" | "miss" | "error";
  status: "ok" | "degraded" | "failed";
  detail: string;
  proposalIds: string[];
  cursorValue?: string;
  hasMore?: boolean;
}

const MAX_EVIDENCE = 24;
const MAX_RESYNC_SOURCES = 10;

interface FreshSummaryCursor {
  assertionTime: string;
  memoryId: string;
}

function decodeFreshSummaryCursor(value: string | null, fallback: string): FreshSummaryCursor {
  if (value !== null) {
    try {
      const parsed = JSON.parse(value) as Record<string, unknown>;
      if (typeof parsed.assertionTime === "string" && typeof parsed.memoryId === "string") {
        return { assertionTime: iso(parsed.assertionTime), memoryId: parsed.memoryId };
      }
    } catch {
      // Pre-delta cursors were plain timestamps but advanced to the newest
      // selected row, so they cannot prove the preceding batch was drained.
    }
    const legacy = new Date(value);
    if (!Number.isNaN(legacy.getTime())) {
      // Rewind one configured window once. This may re-propose reviewed
      // evidence, but it recovers the legacy skipped tail instead of losing it.
      return { assertionTime: fallback, memoryId: "" };
    }
  }
  return { assertionTime: fallback, memoryId: "" };
}

function encodeFreshSummaryCursor(cursor: FreshSummaryCursor): string {
  return JSON.stringify(cursor);
}

/** Evidence predicate mirrors consolidation's selectEvidence exact scope. */
const ACTIVE_L2 = `namespace = $1 AND tier = 'L2' AND status = 'active'
  AND t_valid_to IS NULL
  AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > $2)`;

export class AutomationRunner {
  private readonly now: () => Date;

  constructor(private readonly deps: AutomationRunnerDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Claim and execute a bounded, replica-safe batch of due automation jobs.
   * Mirrors the connector worker's claim/heartbeat/complete shape.
   */
  async runAutomationJobsOnce(limit = 10): Promise<AutomationRunSummary> {
    const jobs = new DurableJobStore(this.deps.db);
    const workerId = `automation-worker:${process.pid}:${ulid()}`;
    const summary: AutomationRunSummary = { claimed: 0, completed: 0, proposals: 0 };
    for (let i = 0; i < Math.max(1, Math.min(100, limit)); i++) {
      const job = await jobs.claim<AutomationJobPayload>(workerId, {
        kinds: ["automation"],
        leaseMs: 120_000,
        now: this.now(),
      });
      if (!job) break;
      summary.claimed++;
      const heartbeat = setInterval(() => {
        void jobs.renew(job.id, workerId, 120_000).catch(() => undefined);
      }, 40_000);
      heartbeat.unref?.();
      try {
        const created = await this.runClaimedJob(job.payload.automationId, job.namespace, job.id);
        summary.proposals += created;
        if (await jobs.complete(job.id, workerId)) summary.completed++;
      } catch (error) {
        // Infra failure (audit/re-arm could not commit): durable retry with
        // backoff so the occurrence is never silently dropped.
        const delay = Math.min(3_600_000, 60_000 * 2 ** Math.min(job.attempts, 6));
        await jobs.fail(job.id, workerId, message(error), {
          retryAt: new Date(this.now().getTime() + delay).toISOString(),
        });
      } finally {
        clearInterval(heartbeat);
      }
    }
    return summary;
  }

  /** Returns the number of proposals produced by this occurrence. */
  private async runClaimedJob(
    automationId: string,
    jobNamespace: Namespace,
    jobId?: string,
  ): Promise<number> {
    const automation = await this.deps.store.getById(automationId);
    if (!automation || !automation.enabled || automation.namespace !== jobNamespace) {
      // A stale arm (row disabled/deleted after enqueue). Not a run — but the
      // skip is still an audited outcome (D4) and the chain deliberately ends
      // (no re-arm: re-enabling arms a fresh chain).
      await this.deps.db.transaction((tx) =>
        this.deps.audit.appendTo(tx, this.auditEvent(
          jobNamespace,
          this.workerIdentity(jobNamespace),
          "miss",
          `automation=${automationId} skipped=disabled-or-missing`,
        )),
      );
      return 0;
    }
    // E36/D30 single-chain invariant: the claimed arm must be the row's
    // CURRENT arm (its id encodes the notBefore instant recordRunOn /
    // configure committed). A mismatched id is an orphan from a superseded
    // chain (e.g. a re-configure raced a running occurrence) — audit the skip
    // and END that chain: no run, no re-arm.
    if (jobId !== undefined && automation.notBefore !== null &&
        jobId !== automationJobId(automation.id, automation.notBefore)) {
      await this.deps.db.transaction((tx) =>
        this.deps.audit.appendTo(tx, this.auditEvent(
          jobNamespace,
          this.workerIdentity(jobNamespace),
          "miss",
          `automation=${automationId} skipped=stale-arm job=${jobId}`,
        )),
      );
      return 0;
    }

    const identity = this.workerIdentity(automation.namespace);
    const ranAt = this.now();
    let outcome: TemplateOutcome;
    // E40 (#21): one automation_run debit per occurrence, BEFORE the
    // template executes. Empty balance → the occurrence degrades (audited
    // miss, recurrence still re-armed) — brownout, never hard-fail.
    let entitled = true;
    let entitlementDetail = "credits-exhausted feature=automation_run";
    if (this.deps.earlyAccess) {
      const allowanceIdentity: Identity = { ...identity, actor: automation.createdBy };
      entitled = await this.deps.earlyAccess(
        allowanceIdentity,
        `automation:${jobId ?? `${automation.id}:${ranAt.toISOString()}`}`,
      );
      if (!entitled) entitlementDetail = "early-access-exhausted feature=automation_run";
    }
    if (entitled && this.deps.meter) {
      const charge = await this.deps.meter.charge(identity, "automation_run", {
        reason: `automation ${automation.templateId}`,
        ...(jobId !== undefined ? { idempotencyKey: `automation-run:${jobId}` } : {}),
      });
      entitled = charge.ok || charge.state === "error";
      if (!entitled) entitlementDetail = "credits-exhausted feature=automation_run";
    }
    if (!entitled) {
      outcome = {
        result: "miss",
        status: "degraded",
        detail: entitlementDetail,
        proposalIds: [],
      };
    } else {
      try {
        outcome = await this.executeTemplate(identity, automation, ranAt);
      } catch (error) {
        outcome = {
          result: "error",
          status: "failed",
          detail: message(error).slice(0, 512),
          proposalIds: [],
        };
      }
    }

    let approved = 0;
    if (automation.autoApprove && outcome.proposalIds.length > 0) {
      approved = await this.autoApprove(identity, outcome);
    }

    // E36: outcome + audit + durable re-arm commit atomically. The recurrence
    // survives failures — a failed run is recorded and the next occurrence is
    // still armed at notBefore = ranAt + interval.
    // A bounded batch is a compute limit, never a completeness limit. When
    // more delta remains, re-arm immediately and keep walking the same cursor;
    // only a drained scope waits for the normal recurrence interval.
    const nextNotBefore = new Date(
      ranAt.getTime() + (outcome.hasMore ? 1 : automation.intervalSeconds * 1_000),
    ).toISOString();
    await this.deps.db.transaction(async (tx) => {
      await this.deps.audit.appendTo(tx, this.auditEvent(
        automation.namespace,
        identity,
        outcome.result,
        `run template=${automation.templateId} automation=${automation.id} ` +
          `proposals=${outcome.proposalIds.length} approved=${approved} ` +
          `next=${nextNotBefore} ${outcome.detail}`.trim(),
        ranAt,
      ));
      await this.deps.store.recordRunOn(tx, automation, {
        ranAt: ranAt.toISOString(),
        status: outcome.status,
        error: outcome.status === "ok" ? null : outcome.detail,
        ...(outcome.cursorValue !== undefined ? { cursorValue: outcome.cursorValue } : {}),
        nextNotBefore,
      });
    });
    return outcome.proposalIds.length;
  }

  private async executeTemplate(
    identity: Identity,
    automation: OrgAutomation,
    ranAt: Date,
  ): Promise<TemplateOutcome> {
    automationTemplate(automation.templateId); // throws on unknown/corrupt row
    switch (automation.templateId) {
      case "fresh-summaries":
        return this.runFreshSummaries(identity, automation, ranAt);
      case "weekly-contradictions":
        return this.runWeeklyContradictions(identity, automation, ranAt);
      case "fill-gaps":
        return this.runFillGaps(identity, automation, ranAt);
      case "re-sync":
        return this.runReSync(automation, ranAt);
      case "weekly-digest":
        return this.runWeeklyDigest(identity, automation, ranAt);
    }
  }

  // -- fresh-summaries ------------------------------------------------------

  private async runFreshSummaries(
    identity: Identity,
    automation: OrgAutomation,
    ranAt: Date,
  ): Promise<TemplateOutcome> {
    const cursor = decodeFreshSummaryCursor(
      automation.cursorValue,
      this.windowStart(automation, ranAt),
    );
    const maxEvidence = this.maxEvidence(automation);
    const result = await this.deps.db.query(
      `SELECT id, assertion_time FROM memory_objects
        WHERE ${ACTIVE_L2}
          AND (assertion_time > $3 OR (assertion_time = $3 AND id > $4))
        ORDER BY assertion_time ASC, id ASC
        LIMIT $5`,
      [
        automation.namespace,
        ranAt.toISOString(),
        cursor.assertionTime,
        cursor.memoryId,
        maxEvidence + 1,
      ],
    );
    const rows = result.rows as { id: string; assertion_time: string | Date }[];
    if (rows.length < 2) {
      return {
        result: "miss",
        status: "ok",
        detail: `evidence=${rows.length} since=${cursor.assertionTime}`,
        proposalIds: [],
      };
    }
    const batch = rows.slice(0, maxEvidence);
    const last = batch.at(-1)!;
    const cursorValue = encodeFreshSummaryCursor({
      assertionTime: iso(last.assertion_time),
      memoryId: last.id,
    });
    const proposalIds = await this.propose(
      identity,
      automation.namespace,
      batch.map((row) => row.id),
      cursor.assertionTime,
      ranAt,
    );
    return {
      result: "ok",
      status: "ok",
      detail: `evidence=${batch.length} more=${rows.length > maxEvidence}`,
      proposalIds,
      cursorValue,
      hasMore: rows.length > maxEvidence,
    };
  }

  // -- weekly-contradictions ------------------------------------------------

  private async runWeeklyContradictions(
    identity: Identity,
    automation: OrgAutomation,
    ranAt: Date,
  ): Promise<TemplateOutcome> {
    const since = this.windowStart(automation, ranAt);
    const superseders = await this.deps.db.query(
      `SELECT id FROM memory_objects
        WHERE ${ACTIVE_L2} AND supersedes IS NOT NULL AND t_valid_from > $3
        ORDER BY t_valid_from DESC
        LIMIT $4`,
      [automation.namespace, ranAt.toISOString(), since, this.maxEvidence(automation)],
    );
    const disputes = await this.deps.db.query(
      `SELECT memory_id, disputed_against FROM fact_disputes
        WHERE namespace = $1 AND status = 'open'
        ORDER BY created_at DESC
        LIMIT $2`,
      [automation.namespace, this.maxEvidence(automation)],
    );
    const candidates = new Set<string>();
    for (const row of superseders.rows as { id: string }[]) candidates.add(row.id);
    for (const row of disputes.rows as { memory_id: string; disputed_against: string }[]) {
      candidates.add(row.memory_id);
      candidates.add(row.disputed_against);
    }
    const evidenceIds = await this.filterToActiveL2(
      automation.namespace, [...candidates], ranAt,
    );
    if (evidenceIds.length < 2) {
      return {
        result: "miss",
        status: "ok",
        detail: `conflicts=${candidates.size} usable=${evidenceIds.length}`,
        proposalIds: [],
      };
    }
    const proposalIds = await this.propose(
      identity, automation.namespace, evidenceIds.slice(0, this.maxEvidence(automation)), since, ranAt,
    );
    return {
      result: "ok",
      status: "ok",
      detail: `conflicts=${candidates.size} evidence=${evidenceIds.length}`,
      proposalIds,
    };
  }

  // -- fill-gaps -------------------------------------------------------------

  private async runFillGaps(
    identity: Identity,
    automation: OrgAutomation,
    ranAt: Date,
  ): Promise<TemplateOutcome> {
    const since = this.windowStart(automation, ranAt);
    // The gap signal: audited misses (D4 writes them) in this exact namespace.
    const misses = await this.deps.db.query(
      `SELECT detail, purpose FROM audit_log
        WHERE namespace = $1 AND result = 'miss' AND op IN ('read', 'search', 'fault')
          AND ts > $2
        ORDER BY seq DESC
        LIMIT 100`,
      [automation.namespace, since],
    );
    const tokens = topicTokens(
      (misses.rows as { detail: string | null; purpose: string | null }[])
        .flatMap((row) => [row.detail ?? "", row.purpose ?? ""]),
    );
    if (tokens.length === 0) {
      return { result: "miss", status: "ok", detail: "misses=0", proposalIds: [] };
    }
    // Existing evidence touching the missed topics. ILIKE runs over CONTENT
    // (not namespaces) and every token passes escapeLikePattern + ESCAPE.
    const patterns = tokens.map((token) => `%${escapeLikePattern(token)}%`);
    const clauses = patterns
      .map((_, index) => `content ILIKE $${index + 3} ESCAPE '\\'`)
      .join(" OR ");
    const evidence = await this.deps.db.query(
      `SELECT id FROM memory_objects
        WHERE ${ACTIVE_L2} AND (${clauses})
        ORDER BY assertion_time DESC
        LIMIT ${this.maxEvidence(automation)}`,
      [automation.namespace, ranAt.toISOString(), ...patterns],
    );
    const evidenceIds = (evidence.rows as { id: string }[]).map((row) => row.id);
    if (evidenceIds.length < 2) {
      return {
        result: "miss",
        status: "ok",
        detail: `misses=${misses.rows.length} topics=${tokens.length} usable=${evidenceIds.length}`,
        proposalIds: [],
      };
    }
    const proposalIds = await this.propose(identity, automation.namespace, evidenceIds, since, ranAt);
    return {
      result: "ok",
      status: "ok",
      detail: `misses=${misses.rows.length} topics=${tokens.length} evidence=${evidenceIds.length}`,
      proposalIds,
    };
  }

  // -- re-sync ---------------------------------------------------------------

  /**
   * The one non-proposal template: durably re-queue stale ACTIVE sources for
   * a connector sync. The sync itself lands content via connector → sink →
   * write path (D10); this template never touches memory rows.
   */
  private async runReSync(automation: OrgAutomation, ranAt: Date): Promise<TemplateOutcome> {
    const staleAfter = configInt(automation.config, "staleAfterSeconds", automation.intervalSeconds);
    const maxSources = configInt(automation.config, "maxSources", MAX_RESYNC_SOURCES);
    const cutoff = new Date(ranAt.getTime() - staleAfter * 1_000).toISOString();
    const result = await this.deps.db.query(
      `SELECT id, namespace FROM sources
        WHERE namespace = $1 AND lifecycle_state = 'active'
          AND kind <> 'policy-upload'
          AND (last_sync IS NULL OR last_sync < $2)
        ORDER BY last_sync ASC NULLS FIRST
        LIMIT $3`,
      [automation.namespace, cutoff, Math.max(1, Math.min(100, maxSources))],
    );
    const rows = result.rows as { id: string; namespace: string }[];
    if (rows.length === 0) {
      return { result: "miss", status: "ok", detail: "stale_sources=0", proposalIds: [] };
    }
    const nowIso = ranAt.toISOString();
    const jobs = new DurableJobStore(this.deps.db);
    for (const row of rows) {
      // Same id/payload shape the kernel's connector worker consumes.
      await jobs.enqueue<{ sourceId: string }>({
        id: `source-sync:${row.id}:${nowIso}`,
        kind: "source-sync",
        namespace: row.namespace,
        payload: { sourceId: row.id },
        availableAt: nowIso,
      });
    }
    return { result: "ok", status: "ok", detail: `stale_sources=${rows.length}`, proposalIds: [] };
  }

  // -- weekly-digest ---------------------------------------------------------

  private async runWeeklyDigest(
    identity: Identity,
    automation: OrgAutomation,
    ranAt: Date,
  ): Promise<TemplateOutcome> {
    const since = this.windowStart(automation, ranAt);
    const result = await this.deps.db.query(
      `SELECT id FROM memory_objects
        WHERE ${ACTIVE_L2} AND assertion_time > $3
        ORDER BY confidence DESC, assertion_time DESC
        LIMIT $4`,
      [automation.namespace, ranAt.toISOString(), since, this.maxEvidence(automation)],
    );
    const evidenceIds = (result.rows as { id: string }[]).map((row) => row.id);
    if (evidenceIds.length < 2) {
      return { result: "miss", status: "ok", detail: `evidence=${evidenceIds.length}`, proposalIds: [] };
    }
    const proposalIds = await this.propose(identity, automation.namespace, evidenceIds, since, ranAt);
    return { result: "ok", status: "ok", detail: `evidence=${evidenceIds.length}`, proposalIds };
  }

  // -- shared helpers --------------------------------------------------------

  /**
   * E35 — the ONLY content-output path. Drafting/verification/encryption run
   * through ConsolidationService.prepare; commitPrepared inserts the
   * proposals as `pending_review` with their own `propose` audit rows. This
   * module owns no INSERT into any memory/knowledge table.
   */
  private async propose(
    identity: Identity,
    namespace: Namespace,
    evidenceIds: string[],
    windowStart: string,
    ranAt: Date,
  ): Promise<string[]> {
    const prepared = await this.deps.proposer.prepare(identity, {
      namespace,
      evidenceIds,
      windowStart,
      windowEnd: ranAt.toISOString(),
    });
    await this.deps.db.transaction((tx) => prepared.commitPrepared(tx));
    return [...prepared.proposalIds];
  }

  /**
   * `auto_approve` opt-in: proposals were ALREADY created `pending_review`
   * (E35); approval goes through the SAME governed pipeline a human uses
   * (re-verification against evidence + `approve`/`publish` audit rows).
   * Any approval failure browns out to `degraded` — the proposals simply
   * stay pending for a human.
   */
  private async autoApprove(identity: Identity, outcome: TemplateOutcome): Promise<number> {
    let approved = 0;
    for (const proposalId of outcome.proposalIds) {
      try {
        const proposal = await this.deps.proposer.get(identity, proposalId);
        if (proposal === null || proposal.status !== "pending_review") continue;
        await this.deps.proposer.approve(identity, proposalId, {
          expectedRowVersion: proposal.rowVersion,
        });
        approved++;
      } catch {
        outcome.status = "degraded";
        outcome.detail = `${outcome.detail} auto_approve_failed=${proposalId}`.trim();
      }
    }
    return approved;
  }

  private async filterToActiveL2(
    namespace: Namespace,
    ids: string[],
    ranAt: Date,
  ): Promise<string[]> {
    if (ids.length === 0) return [];
    const placeholders = ids.map((_, index) => `$${index + 3}`).join(", ");
    const result = await this.deps.db.query(
      `SELECT id FROM memory_objects
        WHERE ${ACTIVE_L2} AND id IN (${placeholders})`,
      [namespace, ranAt.toISOString(), ...ids],
    );
    const active = new Set((result.rows as { id: string }[]).map((row) => row.id));
    return ids.filter((id) => active.has(id));
  }

  private windowStart(automation: OrgAutomation, ranAt: Date): string {
    return new Date(ranAt.getTime() - automation.intervalSeconds * 1_000).toISOString();
  }

  private maxEvidence(automation: OrgAutomation): number {
    return Math.max(2, Math.min(100, configInt(automation.config, "maxEvidence", MAX_EVIDENCE)));
  }

  /**
   * D9: the run identity is KERNEL-OWNED, bound to the automation row's
   * namespace — mirrors the connector worker. Nothing caller-asserted.
   */
  private workerIdentity(namespace: Namespace): Identity {
    return {
      keyId: "halomem:automation-worker",
      namespace,
      actor: "halomem-automation-worker",
      role: "admin",
    };
  }

  private auditEvent(
    namespace: Namespace,
    identity: Identity,
    result: AuditEvent["result"],
    detail: string,
    ts?: Date,
  ): AuditEvent {
    return {
      ts: (ts ?? this.now()).toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "automation_run",
      memoryId: null,
      namespace,
      purpose: "automation",
      result,
      detail,
    };
  }
}

function configInt(
  config: Record<string, unknown>,
  key: string,
  fallback: number,
): number {
  const value = config[key];
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

/** Distinct lowercase topic tokens (>= 4 chars) from audited miss details. */
function topicTokens(texts: string[]): string[] {
  const stop = new Set([
    "with", "from", "this", "that", "have", "miss", "none", "null", "true",
    "false", "query", "result", "detail", "namespace", "recall",
  ]);
  const seen = new Set<string>();
  for (const text of texts) {
    for (const raw of text.toLowerCase().split(/[^a-z0-9]+/)) {
      if (raw.length < 4 || stop.has(raw)) continue;
      seen.add(raw);
      if (seen.size >= 8) return [...seen];
    }
  }
  return [...seen];
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function iso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
