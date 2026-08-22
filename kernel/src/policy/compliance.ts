/**
 * Policy compliance ledger.
 *
 * Every guardrail delivery, acknowledgement, and miss is an append-only row in
 * `policy_agent_events` (D4/D7: history is never rewritten), with a derived
 * per-(document, agent) rollup in `policy_agent_state` so the console reads one
 * indexed row per agent instead of scanning the ledger.
 *
 * Four event kinds:
 *   served       — the directive set was handed to an agent (assemble or mem_policy)
 *   acknowledged — the agent echoed the digest back via mem_policy_ack
 *   applied      — the agent reported acting under the digest (ack with applied)
 *   bypassed     — the agent acted in the namespace while a `required` directive
 *                  set was current and it had never been served that digest
 *
 * Bypass is EVIDENCE, not a denial. Guardrails brown out like everything else
 * (kernel rule 5): a ledger write must never be able to fail an agent's call.
 */

import { ulid } from "ulid";

import { escapeLikePattern, type Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import type {
  Namespace,
  PolicyComplianceAgent,
  PolicyComplianceDocument,
  PolicyComplianceEvent,
  PolicyComplianceReport,
  PolicyDirectiveSet,
  PolicyDocumentEnforcement,
  PolicyDocumentKind,
  PolicyDocumentStatus,
} from "../types.js";

export type PolicyEventKind =
  | "served"
  | "acknowledged"
  | "applied"
  | "bypassed";

export type PolicyEventChannel = "assemble" | "policy-call" | "ack" | "monitor";

export interface PolicyEventInput {
  namespace: Namespace;
  documentId: string;
  policyDigest: string;
  agentId: string;
  actor: string;
  principal: "human" | "agent";
  kind: PolicyEventKind;
  channel: PolicyEventChannel;
  traceId?: string | null;
  detail?: string | null;
}

const MAX_RECENT_EVENTS = 50;
const MAX_DETAIL_LENGTH = 500;

const COUNTER_BY_KIND: Record<PolicyEventKind, string> = {
  served: "served_count",
  acknowledged: "acknowledged_count",
  applied: "applied_count",
  bypassed: "bypass_count",
};

const TIMESTAMP_BY_KIND: Record<PolicyEventKind, string> = {
  served: "last_served_at",
  acknowledged: "last_acknowledged_at",
  applied: "last_applied_at",
  bypassed: "last_bypass_at",
};

export class PolicyComplianceStore {
  constructor(private readonly db: Db) {}

  /** Append one ledger row and fold it into the per-agent rollup. */
  async record(input: PolicyEventInput): Promise<void> {
    const ts = new Date().toISOString();
    const counter = COUNTER_BY_KIND[input.kind];
    const stamp = TIMESTAMP_BY_KIND[input.kind];
    const detail =
      input.detail === undefined || input.detail === null
        ? null
        : input.detail.slice(0, MAX_DETAIL_LENGTH);
    await this.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO policy_agent_events
           (id, namespace, document_id, policy_digest, agent_id, actor,
            principal, kind, channel, trace_id, ts, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          ulid(),
          input.namespace,
          input.documentId,
          input.policyDigest,
          input.agentId,
          input.actor,
          input.principal,
          input.kind,
          input.channel,
          input.traceId ?? null,
          ts,
          detail,
        ],
      );
      await tx.query(
        `INSERT INTO policy_agent_state
           (namespace, document_id, agent_id, actor, last_digest,
            last_served_digest, ${counter}, first_served_at, ${stamp}, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$8)
         ON CONFLICT (namespace, document_id, agent_id) DO UPDATE SET
           actor = EXCLUDED.actor,
           last_digest = EXCLUDED.last_digest,
           last_served_digest = COALESCE(EXCLUDED.last_served_digest,
                                         policy_agent_state.last_served_digest),
           ${counter} = policy_agent_state.${counter} + 1,
           first_served_at = COALESCE(policy_agent_state.first_served_at,
                                      EXCLUDED.first_served_at),
           ${stamp} = EXCLUDED.${stamp},
           updated_at = EXCLUDED.updated_at`,
        [
          input.namespace,
          input.documentId,
          input.agentId,
          input.actor,
          input.policyDigest,
          input.kind === "served" ? input.policyDigest : null,
          input.kind === "served" ? ts : null,
          ts,
        ],
      );
    });
  }

  /** Record one `served` row per document in a delivered directive set. */
  async recordDelivery(
    set: PolicyDirectiveSet,
    who: {
      agentId: string;
      actor: string;
      principal: "human" | "agent";
      channel: PolicyEventChannel;
      traceId?: string | null;
    },
  ): Promise<void> {
    for (const document of set.documents) {
      await this.record({
        namespace: set.namespace,
        documentId: document.documentId,
        policyDigest: set.digest,
        agentId: who.agentId,
        actor: who.actor,
        principal: who.principal,
        kind: "served",
        channel: who.channel,
        traceId: who.traceId ?? null,
        detail: `directives=${document.directiveCount} tokens=${document.tokenEstimate}`,
      });
    }
  }

  /**
   * True when this agent has already been served the exact digest. The bypass
   * monitor asks this before recording a miss.
   */
  async hasDelivery(
    namespace: Namespace,
    agentId: string,
    digest: string,
  ): Promise<boolean> {
    const result = await this.db.query(
      `SELECT 1 FROM policy_agent_state
        WHERE namespace = $1 AND agent_id = $2 AND last_served_digest = $3
        LIMIT 1`,
      [namespace, agentId, digest],
    );
    return result.rows.length > 0;
  }

  /**
   * True when the agent already has a bypass row for this digest — one miss
   * per (agent, digest) is the signal; repeating it every syscall is noise.
   */
  async hasBypass(
    namespace: Namespace,
    agentId: string,
    digest: string,
  ): Promise<boolean> {
    const result = await this.db.query(
      `SELECT 1 FROM policy_agent_events
        WHERE namespace = $1 AND agent_id = $2 AND policy_digest = $3
          AND kind = 'bypassed'
        LIMIT 1`,
      [namespace, agentId, digest],
    );
    return result.rows.length > 0;
  }

  /**
   * The S4 compliance read model for one namespace subtree: every governed
   * document plus every agent's standing against the CURRENT digest.
   */
  async report(
    namespace: Namespace,
    digest: string,
  ): Promise<PolicyComplianceReport> {
    const scopes = [...new Set(namespaceAncestors(namespace))];
    const placeholders = scopes.map((_, index) => `$${index + 1}`).join(", ");
    const documents = await this.db.query(
      `SELECT id, namespace, title, kind, enforcement, status, fact_count
         FROM policy_documents
        WHERE namespace IN (${placeholders})
          AND status IN ('active','needs_review')
        ORDER BY namespace ASC, created_at ASC, id ASC`,
      scopes,
    );
    const documentRows = documents.rows as Array<{
      id: string;
      namespace: string;
      title: string;
      kind: PolicyDocumentKind;
      enforcement: PolicyDocumentEnforcement;
      status: PolicyDocumentStatus;
      fact_count: number | string;
    }>;
    if (documentRows.length === 0) {
      return emptyReport(namespace, digest);
    }

    const documentIds = documentRows.map((row) => row.id);
    const idPlaceholders = documentIds
      .map((_, index) => `$${index + 1}`)
      .join(", ");
    // A document inherited from an ancestor is served to agents all over the
    // tree. Compliance rows are fenced to the SELECTED subtree so a team admin
    // reading org policy never sees a sibling team's agents. `_` and `%` in a
    // namespace are escaped — the ACL rule is never a bare LIKE.
    const subtree = (column: string): string =>
      namespace === ""
        ? "TRUE"
        : `(${column} = $${documentIds.length + 1} OR ${column} LIKE $${
            documentIds.length + 2
          } ESCAPE '\\')`;
    const subtreeParams =
      namespace === ""
        ? []
        : [namespace, `${escapeLikePattern(namespace)}/%`];
    const [state, recent] = await Promise.all([
      this.db.query(
        `SELECT * FROM policy_agent_state
          WHERE document_id IN (${idPlaceholders}) AND ${subtree("namespace")}
          ORDER BY last_served_at DESC NULLS LAST, agent_id ASC`,
        [...documentIds, ...subtreeParams],
      ),
      this.db.query(
        `SELECT e.*, d.title AS document_title
           FROM policy_agent_events e
           JOIN policy_documents d ON d.id = e.document_id
          WHERE e.document_id IN (${idPlaceholders})
            AND ${subtree("e.namespace")}
          ORDER BY e.ts DESC, e.id DESC
          LIMIT ${MAX_RECENT_EVENTS}`,
        [...documentIds, ...subtreeParams],
      ),
    ]);

    const byDocument = new Map<string, PolicyComplianceAgent[]>();
    for (const row of state.rows as StateRow[]) {
      const agent = toAgent(row, digest);
      const bucket = byDocument.get(row.document_id);
      if (bucket) bucket.push(agent);
      else byDocument.set(row.document_id, [agent]);
    }

    const summary = {
      documents: documentRows.length,
      agents: 0,
      acknowledged: 0,
      served: 0,
      stale: 0,
      bypassed: 0,
      neverServed: 0,
    };
    const seenAgents = new Set<string>();
    const reportDocuments: PolicyComplianceDocument[] = documentRows.map(
      (row) => {
        const agents = byDocument.get(row.id) ?? [];
        for (const agent of agents) {
          seenAgents.add(agent.agentId);
          if (agent.state === "bypassed") summary.bypassed++;
          else if (agent.state === "acknowledged") summary.acknowledged++;
          else if (agent.state === "served") summary.served++;
          else if (agent.state === "stale") summary.stale++;
          else summary.neverServed++;
        }
        return {
          documentId: row.id,
          namespace: row.namespace,
          title: row.title,
          kind: row.kind,
          enforcement:
            row.enforcement === "advisory" ? "advisory" : "required",
          status: row.status,
          factCount: Number(row.fact_count),
          agents,
        };
      },
    );
    summary.agents = seenAgents.size;

    return {
      namespace,
      digest,
      documents: reportDocuments,
      summary,
      recent: (recent.rows as EventRow[]).map(toEvent),
    };
  }
}

interface StateRow {
  namespace: string;
  document_id: string;
  agent_id: string;
  actor: string;
  last_digest: string;
  last_served_digest: string | null;
  served_count: number | string;
  acknowledged_count: number | string;
  applied_count: number | string;
  bypass_count: number | string;
  first_served_at: string | Date | null;
  last_served_at: string | Date | null;
  last_acknowledged_at: string | Date | null;
  last_applied_at: string | Date | null;
  last_bypass_at: string | Date | null;
}

interface EventRow {
  id: string;
  namespace: string;
  document_id: string;
  document_title: string;
  agent_id: string;
  actor: string;
  kind: PolicyEventKind;
  channel: PolicyEventChannel;
  policy_digest: string;
  trace_id: string | null;
  ts: string | Date;
  detail: string | null;
}

function emptyReport(
  namespace: Namespace,
  digest: string,
): PolicyComplianceReport {
  return {
    namespace,
    digest,
    documents: [],
    summary: {
      documents: 0,
      agents: 0,
      acknowledged: 0,
      served: 0,
      stale: 0,
      bypassed: 0,
      neverServed: 0,
    },
    recent: [],
  };
}

function toAgent(row: StateRow, digest: string): PolicyComplianceAgent {
  const served = Number(row.served_count);
  const acknowledged = Number(row.acknowledged_count);
  const applied = Number(row.applied_count);
  const bypassed = Number(row.bypass_count);
  // "Current" means this agent was SERVED the digest that governs right now —
  // a bypass row is evidence of the opposite and must never imply currency.
  const current = digest !== "" && row.last_served_digest === digest;
  let state: PolicyComplianceAgent["state"];
  if (served === 0 && bypassed > 0) state = "bypassed";
  else if (served === 0) state = "never-served";
  else if (!current) state = "stale";
  else if (acknowledged > 0 || applied > 0) state = "acknowledged";
  else state = "served";
  return {
    agentId: row.agent_id,
    actor: row.actor,
    lastDigest: row.last_served_digest ?? row.last_digest,
    current,
    servedCount: served,
    acknowledgedCount: acknowledged,
    appliedCount: applied,
    bypassCount: bypassed,
    firstServedAt: iso(row.first_served_at),
    lastServedAt: iso(row.last_served_at),
    lastAcknowledgedAt: iso(row.last_acknowledged_at),
    lastAppliedAt: iso(row.last_applied_at),
    lastBypassAt: iso(row.last_bypass_at),
    state,
  };
}

function toEvent(row: EventRow): PolicyComplianceEvent {
  return {
    id: row.id,
    namespace: row.namespace,
    documentId: row.document_id,
    documentTitle: row.document_title,
    agentId: row.agent_id,
    actor: row.actor,
    kind: row.kind,
    channel: row.channel,
    policyDigest: row.policy_digest,
    traceId: row.trace_id,
    ts: new Date(row.ts).toISOString(),
    detail: row.detail,
  };
}

function iso(value: string | Date | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}
