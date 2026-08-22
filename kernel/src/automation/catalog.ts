/**
 * M9 #19 — the switch-on automations catalog (D30).
 *
 * Five fixed templates an org can flip on. A template NEVER writes memory
 * directly: every content-producing run emits `pending_review`
 * KnowledgeProposals through the existing consolidation review pipeline
 * ("proposes, never overwrites"). The one non-content template (`re-sync`)
 * only enqueues durable source-sync jobs, whose connectors feed the write
 * path via their sink (D10).
 *
 * Recurrence is a durable `notBefore` re-arm on the `automation` durable job
 * kind — never an in-kernel timer (D30/E36).
 */

/** Matches the `org_automations.template_id` CHECK constraint exactly. */
export type AutomationTemplateId =
  | "fresh-summaries"
  | "weekly-contradictions"
  | "fill-gaps"
  | "re-sync"
  | "weekly-digest";

export interface AutomationTemplate {
  readonly templateId: AutomationTemplateId;
  /** Human switch label surfaced by the console. */
  readonly name: string;
  readonly description: string;
  /** Per-template default; the DB floor is 3600s (1h). */
  readonly defaultIntervalSeconds: number;
  /**
   * True when a run's output is `pending_review` KnowledgeProposals (E35).
   * False only for `re-sync`, whose output is enqueued source-sync jobs.
   */
  readonly producesProposals: boolean;
}

const DAY = 86_400;
const WEEK = 604_800;

export const AUTOMATION_TEMPLATES: readonly AutomationTemplate[] = [
  {
    templateId: "fresh-summaries",
    name: "Keep summaries fresh",
    description:
      "Clusters newly landed evidence and proposes refreshed knowledge summaries. " +
      "Every draft lands as a pending-review proposal for a human to approve.",
    defaultIntervalSeconds: DAY,
    producesProposals: true,
  },
  {
    templateId: "weekly-contradictions",
    name: "Weekly contradiction flag",
    description:
      "Collects the week's supersedence conflicts and open disputes and proposes a " +
      "contradiction-flag document from the surviving current facts.",
    defaultIntervalSeconds: WEEK,
    producesProposals: true,
  },
  {
    templateId: "fill-gaps",
    name: "Fill detected gaps",
    description:
      "Mines recent audited misses, matches existing evidence that touches the missed " +
      "topics, and proposes gap-filling knowledge drafts.",
    defaultIntervalSeconds: DAY,
    producesProposals: true,
  },
  {
    templateId: "re-sync",
    name: "Scheduled re-sync",
    description:
      "Re-queues stale active sources for a connector sync. Content still flows " +
      "connector → sink → write path; the automation never touches the store.",
    defaultIntervalSeconds: 6 * 3_600,
    producesProposals: false,
  },
  {
    templateId: "weekly-digest",
    name: "Weekly digest",
    description:
      "Summarizes the week's active evidence into a digest proposal for review.",
    defaultIntervalSeconds: WEEK,
    producesProposals: true,
  },
];

const BY_ID = new Map(AUTOMATION_TEMPLATES.map((t) => [t.templateId, t]));

export function isAutomationTemplateId(value: string): value is AutomationTemplateId {
  return BY_ID.has(value as AutomationTemplateId);
}

export function automationTemplate(templateId: string): AutomationTemplate {
  const template = BY_ID.get(templateId as AutomationTemplateId);
  if (template === undefined) {
    throw new Error(`unknown automation template '${templateId}'`);
  }
  return template;
}
