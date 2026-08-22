/**
 * Skill usage rollups (M9 decision #9) — read-side only.
 *
 * Answers "which agents access which skills, how often, and when last" from
 * the `skill_agent_usage` per-day rollup that {@link SkillStore.invoke}
 * maintains, supplemented by the append-only audit trail for the per-skill
 * activity feed (skill_vet / skill_invoke / skill_override rows).
 *
 * ACL: every result is filtered by the same ancestor-prefix rule as the
 * store — exact string computation via namespaceAncestors (the dispute-queue
 * mirror), never a SQL pattern predicate. This module performs no writes:
 * counters are owned by the invoke transaction in store.ts, and the audit
 * trail is owned by src/audit/.
 */

import type { AuditEvent, AuditOp, Identity, Namespace } from "../types.js";
import type { Db } from "../db/client.js";
import { canReadSkill } from "./store.js";

// ---------------------------------------------------------------------------
// Types (local; candidates for promotion)
// ---------------------------------------------------------------------------

/** One agent's lifetime totals against one skill. */
export interface SkillAgentUsage {
  skillId: string;
  /** The invoking agent's namespace (where the usage happened). */
  namespace: Namespace;
  keyId: string;
  actor: string;
  invocations: number;
  denials: number;
  overrides: number;
  lastInvokedAt: string | null;
  /** Days on which this agent touched the skill (rollup rows). */
  activeDays: number;
}

/** Library-table aggregate: one row per skill. */
export interface SkillUsageSummary {
  skillId: string;
  agents: number;
  invocations: number;
  denials: number;
  overrides: number;
  lastInvokedAt: string | null;
}

/** One audit event in a skill's activity feed. */
export interface SkillAuditEntry {
  ts: string;
  actor: string;
  agentId: string;
  op: AuditOp;
  namespace: Namespace;
  result: AuditEvent["result"];
  detail: string | null;
}

export interface SkillUsageDeps {
  db: Db;
}

const SKILL_AUDIT_OPS = ["skill_vet", "skill_invoke", "skill_override"] as const;
const MAX_FEED_LIMIT = 200;

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(value as string).toISOString();
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class SkillUsageService {
  constructor(private readonly deps: SkillUsageDeps) {}

  /**
   * Per-skill aggregates for every skill row the caller can see — keyed by
   * skill id so the console merges them into the library table. Usage rows
   * are grouped in SQL, then filtered by the caller's exact ancestor/subtree
   * visibility of the SKILL'S namespace (usage against a visible skill is
   * part of that skill's story; a sibling tenant's skills never appear).
   */
  async summary(identity: Identity): Promise<Map<string, SkillUsageSummary>> {
    const res = await this.deps.db.query(
      `SELECT u.skill_id, s.namespace AS skill_namespace,
              COUNT(DISTINCT u.key_id) AS agents,
              SUM(u.invocations) AS invocations,
              SUM(u.denials) AS denials,
              SUM(u.overrides) AS overrides,
              MAX(u.last_invoked_at) AS last_invoked_at
         FROM skill_agent_usage u
         JOIN skills s ON s.id = u.skill_id
        GROUP BY u.skill_id, s.namespace`,
    );
    const out = new Map<string, SkillUsageSummary>();
    for (const raw of res.rows) {
      const row = raw as {
        skill_id: string;
        skill_namespace: string;
        agents: number | string;
        invocations: number | string;
        denials: number | string;
        overrides: number | string;
        last_invoked_at: unknown;
      };
      if (!canReadSkill(identity, row.skill_namespace)) continue;
      out.set(row.skill_id, {
        skillId: row.skill_id,
        agents: Number(row.agents),
        invocations: Number(row.invocations),
        denials: Number(row.denials),
        overrides: Number(row.overrides),
        lastInvokedAt: toIsoOrNull(row.last_invoked_at),
      });
    }
    return out;
  }

  /**
   * Which agents use one skill: lifetime totals per (keyId, actor), most
   * recently active first. The skill's namespace gates visibility; each
   * usage row's own namespace is additionally checked so an admin of a
   * sibling subtree can never see an invoker outside their scope through a
   * shared ancestor skill.
   */
  async perAgent(identity: Identity, skillId: string): Promise<SkillAgentUsage[]> {
    const skillRes = await this.deps.db.query(
      `SELECT namespace FROM skills WHERE id = $1`,
      [skillId],
    );
    const skillNs = (skillRes.rows[0] as { namespace: string } | undefined)?.namespace;
    if (skillNs === undefined || !canReadSkill(identity, skillNs)) return [];

    const res = await this.deps.db.query(
      `SELECT namespace, key_id, actor,
              SUM(invocations) AS invocations,
              SUM(denials) AS denials,
              SUM(overrides) AS overrides,
              MAX(last_invoked_at) AS last_invoked_at,
              COUNT(*) AS active_days
         FROM skill_agent_usage
        WHERE skill_id = $1
        GROUP BY namespace, key_id, actor
        ORDER BY MAX(last_invoked_at) DESC NULLS LAST`,
      [skillId],
    );
    const out: SkillAgentUsage[] = [];
    for (const raw of res.rows) {
      const row = raw as {
        namespace: string;
        key_id: string;
        actor: string;
        invocations: number | string;
        denials: number | string;
        overrides: number | string;
        last_invoked_at: unknown;
        active_days: number | string;
      };
      if (!canReadSkill(identity, row.namespace)) continue;
      out.push({
        skillId,
        namespace: row.namespace,
        keyId: row.key_id,
        actor: row.actor,
        invocations: Number(row.invocations),
        denials: Number(row.denials),
        overrides: Number(row.overrides),
        lastInvokedAt: toIsoOrNull(row.last_invoked_at),
        activeDays: Number(row.active_days),
      });
    }
    return out;
  }

  /**
   * The append-only activity feed for one skill: its vetting runs, invoke
   * outcomes (ok / denied / miss), and admin overrides, newest first. Reads
   * the audit trail by exact `memory_id` + op list — the module never
   * writes audit rows here (read-side only).
   */
  async recentEvents(
    identity: Identity,
    skillId: string,
    limit = 50,
  ): Promise<SkillAuditEntry[]> {
    const skillRes = await this.deps.db.query(
      `SELECT namespace FROM skills WHERE id = $1`,
      [skillId],
    );
    const skillNs = (skillRes.rows[0] as { namespace: string } | undefined)?.namespace;
    if (skillNs === undefined || !canReadSkill(identity, skillNs)) return [];

    const capped = Math.max(1, Math.min(limit, MAX_FEED_LIMIT));
    const opPlaceholders = SKILL_AUDIT_OPS.map((_, i) => `$${i + 2}`).join(", ");
    const res = await this.deps.db.query(
      `SELECT ts, actor, agent_id, op, namespace, result, detail
         FROM audit_log
        WHERE memory_id = $1 AND op IN (${opPlaceholders})
        ORDER BY ts DESC
        LIMIT $${SKILL_AUDIT_OPS.length + 2}`,
      [skillId, ...SKILL_AUDIT_OPS, capped],
    );
    const out: SkillAuditEntry[] = [];
    for (const raw of res.rows) {
      const row = raw as {
        ts: unknown;
        actor: string;
        agent_id: string;
        op: string;
        namespace: string;
        result: string;
        detail: string | null;
      };
      if (!canReadSkill(identity, row.namespace)) continue;
      out.push({
        ts: toIsoOrNull(row.ts) ?? "",
        actor: row.actor,
        agentId: row.agent_id,
        op: row.op as AuditOp,
        namespace: row.namespace,
        result: row.result as AuditEvent["result"],
        detail: row.detail ?? null,
      });
    }
    return out;
  }
}
