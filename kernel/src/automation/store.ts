/**
 * M9 #19 — `org_automations` store (D30, D4, D5, D9).
 *
 * One row per (namespace, template). Enabling an automation arms a durable
 * `automation` job at `not_before` (E36/E37); disabling deletes the queued
 * arm. Recurrence never uses an in-kernel timer.
 *
 * Namespace is ALWAYS the server-resolved identity namespace or a descendant
 * the identity may manage — request bodies never assert it (D9). Every
 * configure call writes an audit row, including denied ones (D4).
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import type { AuditEvent, Identity, Namespace } from "../types.js";
import { namespaceAncestors } from "../index/index.js";
import { DurableJobStore } from "../durable/jobs.js";
import {
  AUTOMATION_TEMPLATES,
  automationTemplate,
  isAutomationTemplateId,
  type AutomationTemplateId,
} from "./catalog.js";

/** Payload of a durable `automation` job. LOCAL TYPE — candidate for promotion. */
export interface AutomationJobPayload {
  automationId: string;
}

/** Hydrated `org_automations` row. LOCAL TYPE — candidate for promotion. */
export interface OrgAutomation {
  id: string;
  namespace: Namespace;
  templateId: AutomationTemplateId;
  enabled: boolean;
  autoApprove: boolean;
  config: Record<string, unknown>;
  intervalSeconds: number;
  cursorValue: string | null;
  notBefore: string | null;
  lastRunAt: string | null;
  lastRunStatus: "ok" | "degraded" | "failed" | null;
  lastError: string | null;
  consecutiveFailures: number;
  rowVersion: number;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Catalog entry merged with the org's row (if any) — the console list shape. */
export interface AutomationView {
  templateId: AutomationTemplateId;
  name: string;
  description: string;
  defaultIntervalSeconds: number;
  producesProposals: boolean;
  enabled: boolean;
  autoApprove: boolean;
  intervalSeconds: number;
  notBefore: string | null;
  lastRunAt: string | null;
  lastRunStatus: "ok" | "degraded" | "failed" | null;
  lastError: string | null;
  consecutiveFailures: number;
  rowVersion: number | null;
}

export interface AutomationConfigureInput {
  templateId: string;
  enabled: boolean;
  autoApprove?: boolean;
  intervalSeconds?: number;
  config?: Record<string, unknown>;
}

export interface AutomationRunRecord {
  ranAt: string;
  status: "ok" | "degraded" | "failed";
  error: string | null;
  /** Advances the durable cursor only when provided. */
  cursorValue?: string;
  nextNotBefore: string;
}

export class AutomationAuthorizationError extends Error {
  constructor() {
    super("automation operation denied");
    this.name = "AutomationAuthorizationError";
  }
}

/** Same structural seam ConsolidationService uses for its injected audit. */
interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

interface AutomationRow extends Record<string, unknown> {
  id: string;
  namespace: string;
  template_id: string;
  enabled: boolean;
  auto_approve: boolean;
  config: unknown;
  interval_seconds: number | string;
  cursor_value: string | null;
  not_before: string | Date | null;
  last_run_at: string | Date | null;
  last_run_status: string | null;
  last_error: string | null;
  consecutive_failures: number | string;
  row_version: number | string;
  created_by: string;
  created_at: string | Date;
  updated_at: string | Date;
}

const AUTOMATION_SELECT = `
  SELECT id, namespace, template_id, enabled, auto_approve, config,
         interval_seconds, cursor_value, not_before, last_run_at,
         last_run_status, last_error, consecutive_failures, row_version,
         created_by, created_at, updated_at
    FROM org_automations`;

function isoOrNull(value: string | Date | null): string | null {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function jsonObject(value: unknown): Record<string, unknown> {
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  return parsed as Record<string, unknown>;
}

function rowToAutomation(row: AutomationRow): OrgAutomation {
  return {
    id: row.id,
    namespace: row.namespace,
    templateId: row.template_id as AutomationTemplateId,
    enabled: row.enabled === true || String(row.enabled) === "true",
    autoApprove: row.auto_approve === true || String(row.auto_approve) === "true",
    config: jsonObject(row.config),
    intervalSeconds: Number(row.interval_seconds),
    cursorValue: row.cursor_value,
    notBefore: isoOrNull(row.not_before),
    lastRunAt: isoOrNull(row.last_run_at),
    lastRunStatus: (row.last_run_status as OrgAutomation["lastRunStatus"]) ?? null,
    lastError: row.last_error,
    consecutiveFailures: Number(row.consecutive_failures),
    rowVersion: Number(row.row_version),
    createdBy: row.created_by,
    createdAt: isoOrNull(row.created_at) as string,
    updatedAt: isoOrNull(row.updated_at) as string,
  };
}

/** Deterministic durable-job id: dedupes double-arms for the same instant. */
export function automationJobId(automationId: string, notBefore: string): string {
  return `automation:${automationId}:${notBefore}`;
}

function canManage(identity: Identity, namespace: Namespace): boolean {
  if (identity.role !== "owner" && identity.role !== "admin") return false;
  if (identity.role === "owner" && identity.namespace === "") return true;
  return namespaceAncestors(namespace).includes(identity.namespace);
}

function canSyncKnowledge(identity: Identity, namespace: Namespace): boolean {
  // The empty namespace is platform authority, not a tenant-private L3 scope.
  // Fresh-summary consolidation may only target canonical private namespaces.
  if (namespace === "") return false;
  if (identity.role !== "owner") return false;
  if (identity.namespace === "") return true;
  return namespaceAncestors(namespace).includes(identity.namespace);
}

export class OrgAutomationStore {
  private readonly now: () => Date;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditWriter,
    now?: () => Date,
  ) {
    this.now = now ?? (() => new Date());
  }

  /** Full catalog merged with this namespace's rows — the console list. */
  async list(identity: Identity, namespace: Namespace): Promise<AutomationView[]> {
    if (!canManage(identity, namespace)) {
      await this.auditConfig(identity, namespace, "denied", "list");
      throw new AutomationAuthorizationError();
    }
    const result = await this.db.query(
      `${AUTOMATION_SELECT} WHERE namespace = $1`,
      [namespace],
    );
    const byTemplate = new Map(
      (result.rows as AutomationRow[]).map((row) => [row.template_id, rowToAutomation(row)]),
    );
    return AUTOMATION_TEMPLATES.map((template) => {
      const row = byTemplate.get(template.templateId);
      return {
        templateId: template.templateId,
        name: template.name,
        description: template.description,
        defaultIntervalSeconds: template.defaultIntervalSeconds,
        producesProposals: template.producesProposals,
        enabled: row?.enabled ?? false,
        autoApprove: row?.autoApprove ?? false,
        intervalSeconds: row?.intervalSeconds ?? template.defaultIntervalSeconds,
        notBefore: row?.notBefore ?? null,
        lastRunAt: row?.lastRunAt ?? null,
        lastRunStatus: row?.lastRunStatus ?? null,
        lastError: row?.lastError ?? null,
        consecutiveFailures: row?.consecutiveFailures ?? 0,
        rowVersion: row?.rowVersion ?? null,
      };
    });
  }

  /**
   * Flip a template on/off (upsert). Enabling arms a durable `automation` job
   * at `not_before = now` (first run at the next worker pass); disabling
   * clears `not_before` and deletes every queued (non-running) arm. All in
   * one transaction with the audit row (D4).
   */
  async configure(
    identity: Identity,
    namespace: Namespace,
    input: AutomationConfigureInput,
  ): Promise<OrgAutomation> {
    if (!isAutomationTemplateId(input.templateId)) {
      throw new Error(`unknown automation template '${input.templateId}'`);
    }
    const template = automationTemplate(input.templateId);
    if (!canManage(identity, namespace)) {
      await this.auditConfig(
        identity, namespace, "denied",
        `configure template=${template.templateId}`,
      );
      throw new AutomationAuthorizationError();
    }
    if (input.intervalSeconds !== undefined) {
      if (!Number.isSafeInteger(input.intervalSeconds) || input.intervalSeconds < 3_600) {
        throw new RangeError("intervalSeconds must be an integer >= 3600");
      }
    }
    if (input.config !== undefined) {
      if (input.config === null || typeof input.config !== "object" || Array.isArray(input.config)) {
        throw new Error("config must be a JSON object");
      }
    }
    const enabled = input.enabled === true;
    const autoApprove = input.autoApprove === true;
    const nowIso = this.now().toISOString();
    const notBefore = enabled ? nowIso : null;

    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `INSERT INTO org_automations
           (id, namespace, template_id, enabled, auto_approve, config,
            interval_seconds, cursor_value, not_before, created_by,
            created_at, updated_at, row_version)
         VALUES ($1, $2, $3, $4, $5, COALESCE($6::jsonb, '{}'::jsonb),
                 COALESCE($7::integer, $8::integer), NULL, $9, $10, $11, $11, 1)
         ON CONFLICT (namespace, template_id) DO UPDATE SET
           enabled = EXCLUDED.enabled,
           auto_approve = EXCLUDED.auto_approve,
           config = COALESCE($6::jsonb, org_automations.config),
           interval_seconds = COALESCE($7::integer, org_automations.interval_seconds),
           not_before = EXCLUDED.not_before,
           row_version = org_automations.row_version + 1,
           updated_at = EXCLUDED.updated_at
         RETURNING id, namespace, template_id, enabled, auto_approve, config,
                   interval_seconds, cursor_value, not_before, last_run_at,
                   last_run_status, last_error, consecutive_failures,
                   row_version, created_by, created_at, updated_at`,
        [
          ulid(),
          namespace,
          template.templateId,
          enabled,
          autoApprove,
          input.config === undefined ? null : JSON.stringify(input.config),
          input.intervalSeconds ?? null,
          template.defaultIntervalSeconds,
          notBefore,
          identity.actor,
          nowIso,
        ],
      );
      const automation = rowToAutomation(result.rows[0] as AutomationRow);
      const jobs = new DurableJobStore(tx);
      // E36/D30: recurrence is a SINGLE durable chain. Every configure —
      // enable AND re-configure-while-enabled — first sweeps any previously
      // queued arm (whose id encodes a different notBefore instant, so
      // ON CONFLICT dedupe can never catch it) before arming afresh.
      // Without this sweep each settings save forked a second permanent
      // parallel chain. A currently RUNNING arm survives the sweep (its
      // lease owns it); the runner's stale-arm check below ends that chain.
      await this.deleteQueuedArms(tx, automation.id);
      if (enabled) {
        await jobs.enqueue<AutomationJobPayload>({
          id: automationJobId(automation.id, notBefore as string),
          kind: "automation",
          namespace,
          payload: { automationId: automation.id },
          availableAt: notBefore as string,
        });
      }
      await this.audit.appendTo(tx, {
        ts: nowIso,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "automation_run",
        memoryId: null,
        namespace,
        purpose: "automation-config",
        result: "ok",
        detail:
          `configure template=${template.templateId} enabled=${enabled} ` +
          `auto_approve=${autoApprove} interval=${automation.intervalSeconds}`,
      });
      return automation;
    });
  }

  /**
   * Queue the fresh-summary chain immediately for one server-resolved scope.
   * Existing cursors/configuration are preserved; a first sync starts at the
   * beginning of retained L2 history. Sync also enables the normal recurring
   * delta chain so the manually requested catch-up stays current afterwards.
   */
  async syncNow(identity: Identity, namespace: Namespace): Promise<OrgAutomation> {
    const template = automationTemplate("fresh-summaries");
    if (!canSyncKnowledge(identity, namespace)) {
      await this.auditConfig(identity, namespace, "denied", "knowledge-sync");
      throw new AutomationAuthorizationError();
    }
    const nowIso = this.now().toISOString();
    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `INSERT INTO org_automations
           (id, namespace, template_id, enabled, auto_approve, config,
            interval_seconds, cursor_value, not_before, created_by,
            created_at, updated_at, row_version)
         VALUES ($1, $2, 'fresh-summaries', TRUE, FALSE, '{}'::jsonb,
                 $3, $4, $5, $6, $5, $5, 1)
         ON CONFLICT (namespace, template_id) DO UPDATE SET
           enabled = TRUE,
           cursor_value = COALESCE(org_automations.cursor_value, EXCLUDED.cursor_value),
           not_before = EXCLUDED.not_before,
           row_version = org_automations.row_version + 1,
           updated_at = EXCLUDED.updated_at
         RETURNING id, namespace, template_id, enabled, auto_approve, config,
                   interval_seconds, cursor_value, not_before, last_run_at,
                   last_run_status, last_error, consecutive_failures,
                   row_version, created_by, created_at, updated_at`,
        [
          ulid(),
          namespace,
          template.defaultIntervalSeconds,
          JSON.stringify({ assertionTime: "1970-01-01T00:00:00.000Z", memoryId: "" }),
          nowIso,
          identity.actor,
        ],
      );
      const automation = rowToAutomation(result.rows[0] as AutomationRow);
      await this.deleteQueuedArms(tx, automation.id);
      await new DurableJobStore(tx).enqueue<AutomationJobPayload>({
        id: automationJobId(automation.id, nowIso),
        kind: "automation",
        namespace,
        payload: { automationId: automation.id },
        availableAt: nowIso,
      });
      await this.audit.appendTo(tx, {
        ts: nowIso,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "automation_run",
        memoryId: null,
        namespace,
        purpose: "knowledge-sync",
        result: "ok",
        detail: "fresh-summaries queued now; recurring delta sync enabled",
      });
      return automation;
    });
  }

  async getById(id: string): Promise<OrgAutomation | null> {
    const result = await this.db.query(`${AUTOMATION_SELECT} WHERE id = $1`, [id]);
    const row = result.rows[0] as AutomationRow | undefined;
    return row ? rowToAutomation(row) : null;
  }

  /**
   * Persist a run's outcome and durably RE-ARM the next occurrence (E36):
   * `not_before` advances by the interval and a new `automation` job is
   * enqueued at exactly that instant. Runs inside the caller's transaction so
   * the run audit, the outcome row, and the re-arm commit atomically.
   */
  async recordRunOn(tx: Db, automation: OrgAutomation, run: AutomationRunRecord): Promise<void> {
    await tx.query(
      `UPDATE org_automations SET
         last_run_at = $2,
         last_run_status = $3,
         last_error = $4,
         consecutive_failures = CASE WHEN $3 = 'failed'
           THEN consecutive_failures + 1 ELSE 0 END,
         cursor_value = COALESCE($5, cursor_value),
         not_before = $6,
         row_version = row_version + 1,
         updated_at = $2
       WHERE id = $1`,
      [
        automation.id,
        run.ranAt,
        run.status,
        run.error === null ? null : run.error.slice(0, 2048),
        run.cursorValue ?? null,
        run.nextNotBefore,
      ],
    );
    await new DurableJobStore(tx).enqueue<AutomationJobPayload>({
      id: automationJobId(automation.id, run.nextNotBefore),
      kind: "automation",
      namespace: automation.namespace,
      payload: { automationId: automation.id },
      availableAt: run.nextNotBefore,
    });
  }

  /** Remove stale queued arms (never a running one — its lease owns it). */
  private async deleteQueuedArms(tx: Db, automationId: string): Promise<number> {
    const result = await tx.query(
      `DELETE FROM durable_jobs
        WHERE kind = 'automation'
          AND state <> 'running'
          AND payload->>'automationId' = $1
        RETURNING id`,
      [automationId],
    );
    return result.rows.length;
  }

  private async auditConfig(
    identity: Identity,
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> {
    await this.db.transaction((tx) =>
      this.audit.appendTo(tx, {
        ts: this.now().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "automation_run",
        memoryId: null,
        namespace,
        purpose: "automation-config",
        result,
        detail,
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Console/API endpoint functions (pure over the store — the integrator wires
// these from src/console/api.ts / the HTTP adapter; namespace is ALWAYS the
// server-resolved identity namespace, never read from the request body, D9).
// ---------------------------------------------------------------------------

export async function listAutomationsEndpoint(
  store: OrgAutomationStore,
  identity: Identity,
): Promise<AutomationView[]> {
  return store.list(identity, identity.namespace);
}

export async function configureAutomationEndpoint(
  store: OrgAutomationStore,
  identity: Identity,
  body: unknown,
): Promise<OrgAutomation> {
  if (body === null || typeof body !== "object") {
    throw new Error("automation configure body must be a JSON object");
  }
  const raw = body as Record<string, unknown>;
  if (typeof raw.templateId !== "string") throw new Error("templateId is required");
  if (typeof raw.enabled !== "boolean") throw new Error("enabled must be a boolean");
  // D9: any namespace/actor asserted in the body is ignored by construction —
  // the input type below simply has no such fields.
  const input: AutomationConfigureInput = {
    templateId: raw.templateId,
    enabled: raw.enabled,
  };
  if (raw.autoApprove !== undefined) {
    if (typeof raw.autoApprove !== "boolean") throw new Error("autoApprove must be a boolean");
    input.autoApprove = raw.autoApprove;
  }
  if (raw.intervalSeconds !== undefined) {
    if (typeof raw.intervalSeconds !== "number") throw new Error("intervalSeconds must be a number");
    input.intervalSeconds = raw.intervalSeconds;
  }
  if (raw.config !== undefined) {
    if (raw.config === null || typeof raw.config !== "object" || Array.isArray(raw.config)) {
      throw new Error("config must be a JSON object");
    }
    input.config = raw.config as Record<string, unknown>;
  }
  return store.configure(identity, identity.namespace, input);
}
