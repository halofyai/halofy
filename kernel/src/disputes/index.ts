/**
 * Trust-dispute review service — the human half of trust-ranked supersedence.
 *
 * The write path quarantines a lower-trust conflicting write as a
 * status:"disputed" memory row plus an open `fact_disputes` row (see
 * src/write/index.ts TRUST_RANK). This module owns the review queue and its
 * resolution state machine, modeled on the consolidation proposal service:
 * optimistic row_version locking, owner/admin subtree authorization (D9:
 * everything derives from the resolved Identity), and D4 audit rows for every
 * outcome inside the same transaction as the state change.
 *
 * Resolutions (each terminal; D7 — never delete):
 * - uphold-new: disputed fact → active, supersedes the incumbent (guarded
 *   close at resolution time; the incumbent must still be currently valid).
 * - keep-old:   disputed fact → archived; the incumbent is untouched.
 * - edit:       the reviewer's corrected content lands as a NEW active fact
 *               (provenance "manual", actor = reviewer) superseding the
 *               incumbent; the disputed fact → archived. Deliberately NOT
 *               routed through the write path: a reviewer rewording may fall
 *               below the supersedence band and would then land WITHOUT
 *               closing the incumbent, leaving an active contradiction.
 */

import { ulid } from "ulid";
import type {
  AuditEvent,
  DisputeCategory,
  Identity,
  MemoryId,
  MemoryObject,
  MemoryType,
  Namespace,
  ProvenanceEntry,
  Scope,
} from "../types.js";
import type { Db } from "../db/client.js";
import { MemoryIndex, namespaceAncestors } from "../index/index.js";

export class DisputeConflictError extends Error {
  constructor() {
    super("dispute changed or was already decided");
    this.name = "DisputeConflictError";
  }
}

export class DisputeAuthorizationError extends Error {
  constructor() {
    super("dispute operation denied");
    this.name = "DisputeAuthorizationError";
  }
}

export type DisputeResolution = "uphold-new" | "keep-old" | "edit" | "both-valid";

/** One side of a conflict as the review queue renders it. */
export interface DisputeFactView {
  id: MemoryId;
  content: string;
  scope: Scope;
  source: ProvenanceEntry["source"];
  actor: string;
  confidence: number;
  tValidFrom: string;
  tValidTo: string | null;
}

export interface DisputeView {
  id: string;
  namespace: Namespace;
  /**
   * Team bucket: the immediate-child namespace of the CALLER that contains
   * the dispute (the S2 "memory by team" grouping rule), or the dispute's own
   * namespace when it is not below the caller.
   */
  team: string;
  category: DisputeCategory;
  reason: string;
  rowVersion: number;
  createdAt: string;
  disputed: DisputeFactView;
  incumbent: DisputeFactView;
  /**
   * False when the incumbent is no longer the currently-valid fact (e.g. a
   * higher-trust write superseded it after the dispute opened). Uphold is
   * impossible then — the queue renders a stale badge and disables it.
   */
  incumbentCurrent: boolean;
  repairProposed: boolean;
  repairClassification: string | null;
}

export interface ResolveDisputeInput {
  action: DisputeResolution;
  expectedRowVersion: number;
  /** Required iff action === "edit": the reviewer's corrected fact text. */
  editedContent?: string;
}

export interface ResolveDisputeResult {
  id: string;
  action: DisputeResolution;
  /**
   * The fact now current for the claim: the (re-activated) disputed fact for
   * uphold-new, the reviewer's new fact for edit, null for keep-old.
   */
  resolutionMemoryId: MemoryId | null;
}

interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface DisputeDependencies {
  db: Db;
  audit: AuditWriter;
  /**
   * Per-namespace embedding for the edit lane. null entries = brownout: the
   * corrected fact still lands (BM25-findable) — never hard-fail (rule 5).
   */
  embed(namespace: Namespace, texts: string[]): Promise<(number[] | null)[]>;
  now?(): Date;
}

const MAX_EDIT_CONTENT_LENGTH = 100_000;

interface DisputeRow {
  id: string;
  namespace: string;
  memory_id: string;
  disputed_against: string;
  category: string;
  reason: string;
  status: string;
  row_version: number | string;
  created_at: unknown;
  d_content: string;
  d_scope: string;
  d_provenance: unknown;
  d_confidence: number | string;
  d_valid_from: unknown;
  d_valid_to: unknown;
  i_content: string;
  i_scope: string;
  i_provenance: unknown;
  i_confidence: number | string;
  i_valid_from: unknown;
  i_valid_to: unknown;
  incumbent_current: boolean;
  repair_proposal_id: string | null;
  repair_classification: string | null;
}

const DISPUTE_SELECT = `
  SELECT d.id, d.namespace, d.memory_id, d.disputed_against, d.category,
         d.reason, d.status, d.row_version, d.created_at,
         dm.content AS d_content, dm.scope AS d_scope,
         dm.provenance AS d_provenance, dm.confidence AS d_confidence,
         dm.t_valid_from AS d_valid_from, dm.t_valid_to AS d_valid_to,
         im.content AS i_content, im.scope AS i_scope,
         im.provenance AS i_provenance, im.confidence AS i_confidence,
         im.t_valid_from AS i_valid_from, im.t_valid_to AS i_valid_to,
         (im.status = 'active' AND im.t_valid_to IS NULL) AS incumbent_current
       , rp.id AS repair_proposal_id, rp.classification AS repair_classification
    FROM fact_disputes d
    JOIN memory_objects dm ON dm.id = d.memory_id
    JOIN memory_objects im ON im.id = d.disputed_against
    LEFT JOIN conflict_repair_proposals rp
      ON rp.source_type='dispute' AND rp.source_id=d.id
     AND rp.detector_version='luna-context-v1' AND rp.status='open'`;

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  throw new Error(`expected timestamp, got ${typeof value}`);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

function parseProvenance(value: unknown): ProvenanceEntry[] {
  if (value === null || value === undefined) return [];
  if (typeof value === "string") return JSON.parse(value) as ProvenanceEntry[];
  return value as ProvenanceEntry[];
}

function isRootOwner(identity: Identity): boolean {
  return identity.role === "owner" && identity.namespace === "";
}

function assertRowVersion(value: number): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("expectedRowVersion must be a positive integer");
  }
}

/** S2 "memory by team" grouping: the caller-visible child namespace bucket. */
function teamBucket(callerNs: Namespace, disputeNs: Namespace): string {
  if (disputeNs === callerNs) return disputeNs === "" ? "(org)" : disputeNs;
  const prefix = callerNs === "" ? "" : `${callerNs}/`;
  if (callerNs === "" || disputeNs.startsWith(prefix)) {
    const child = disputeNs.slice(prefix.length).split("/")[0]!;
    return callerNs === "" ? child : `${callerNs}/${child}`;
  }
  return disputeNs;
}

export class DisputeService {
  private readonly now: () => Date;

  constructor(private readonly deps: DisputeDependencies) {
    this.now = deps.now ?? (() => new Date());
  }

  /** Open disputes visible to the caller, newest first. */
  async list(identity: Identity): Promise<DisputeView[]> {
    const result = await this.deps.db.query(
      `${DISPUTE_SELECT} WHERE d.status = 'open' ORDER BY d.created_at DESC, d.id DESC`,
    );
    return (result.rows as unknown as DisputeRow[])
      .filter((row) => this.canRead(identity, row.namespace))
      .map((row) => this.toView(identity, row));
  }

  async resolve(
    identity: Identity,
    disputeId: string,
    input: ResolveDisputeInput,
  ): Promise<ResolveDisputeResult> {
    assertRowVersion(input.expectedRowVersion);
    if (input.action === "edit") {
      const content = input.editedContent?.trim() ?? "";
      if (content.length === 0 || content.length > MAX_EDIT_CONTENT_LENGTH) {
        throw new Error("editedContent must be 1..100000 characters for an edit resolution");
      }
    } else if (input.editedContent !== undefined) {
      throw new Error("editedContent is only valid with action 'edit'");
    }

    // Pre-transaction reads: authorization target + edit-lane embedding (the
    // embedder must never hold the transaction open; a failure is a brownout,
    // not an abort).
    const pre = await this.deps.db.query(
      `SELECT namespace, memory_id, disputed_against FROM fact_disputes WHERE id = $1`,
      [disputeId],
    );
    const preRow = pre.rows[0] as
      | { namespace: string; memory_id: string; disputed_against: string }
      | undefined;
    if (!preRow) throw new DisputeConflictError();
    if (!this.canManage(identity, preRow.namespace)) {
      throw new DisputeAuthorizationError();
    }
    const editedContent = input.action === "edit" ? input.editedContent!.trim() : null;
    let editedEmbedding: number[] | null = null;
    if (editedContent !== null) {
      try {
        const [vec] = await this.deps.embed(preRow.namespace, [editedContent]);
        editedEmbedding = vec ?? null;
      } catch {
        editedEmbedding = null; // brownout: land the fact BM25-only
      }
    }

    const ts = this.now().toISOString();
    const resolutionMemoryId =
      input.action === "uphold-new" || input.action === "both-valid"
        ? preRow.memory_id
        : input.action === "edit"
          ? ulid()
          : null;

    await this.deps.db.transaction(async (tx) => {
      // Guarded claim: one terminal resolution per dispute, ever.
      const claimed = await tx.query(
        `UPDATE fact_disputes
            SET status = 'resolved', resolution = $3, resolution_memory_id = $4,
                resolved_by = $5, resolved_at = $6, row_version = row_version + 1,
                updated_at = $6
          WHERE id = $1 AND status = 'open' AND row_version = $2
          RETURNING namespace, memory_id, disputed_against`,
        [
          disputeId,
          input.expectedRowVersion,
          input.action,
          resolutionMemoryId,
          identity.actor,
          ts,
        ],
      );
      const row = claimed.rows[0] as
        | { namespace: string; memory_id: string; disputed_against: string }
        | undefined;
      if (!row) throw new DisputeConflictError();
      // Re-assert scope against the transactional row (the pre-read is
      // advisory only; namespace is immutable but belt-and-braces).
      if (!this.canManage(identity, row.namespace)) {
        throw new DisputeAuthorizationError();
      }

      if (input.action === "uphold-new") {
        await this.activateDisputedFact(tx, row.memory_id, row.disputed_against, ts);
        await this.closeIncumbent(tx, row.disputed_against, ts);
        await this.audit(tx, identity, "supersede", row.disputed_against, row.namespace, "ok",
          `validity closed; dispute ${disputeId} upheld ${row.memory_id}`);
        await this.audit(tx, identity, "resolve", row.memory_id, row.namespace, "ok",
          `action=uphold-new dispute=${disputeId} against=${row.disputed_against}`);
        return;
      }

      if (input.action === "both-valid") {
        const proposal = await tx.query(
          `UPDATE conflict_repair_proposals
              SET status='applied',resolved_at=$2,resolved_by=$3
            WHERE source_type='dispute' AND source_id=$1
              AND detector_version='luna-context-v1' AND status='open'
            RETURNING id`,
          [disputeId, ts, identity.actor],
        );
        if (!proposal.rows[0]) throw new DisputeConflictError();
        const incumbent = await tx.query(
          `SELECT id FROM memory_objects
            WHERE id=$1 AND status='active' AND t_valid_to IS NULL`,
          [row.disputed_against],
        );
        if (!incumbent.rows[0]) throw new DisputeConflictError();
        const activated = await tx.query(
          `UPDATE memory_objects
              SET status='active',supersedes=NULL,t_valid_from=$2
            WHERE id=$1 AND status='disputed' RETURNING id`,
          [row.memory_id, ts],
        );
        if (!activated.rows[0]) throw new DisputeConflictError();
        await this.audit(tx, identity, "resolve", row.memory_id, row.namespace, "ok",
          `action=both-valid dispute=${disputeId} detector=luna-context-v1`);
        return;
      }

      if (input.action === "keep-old") {
        await this.archiveDisputedFact(tx, row.memory_id);
        await this.audit(tx, identity, "resolve", row.memory_id, row.namespace, "ok",
          `action=keep-old dispute=${disputeId} incumbent=${row.disputed_against} retained`);
        return;
      }

      // edit — the reviewer's corrected fact supersedes the incumbent.
      const incumbent = await tx.query(
        `SELECT scope, type, ttl_seconds FROM memory_objects WHERE id = $1`,
        [row.disputed_against],
      );
      const inc = incumbent.rows[0] as
        | { scope: string; type: string; ttl_seconds: number | null }
        | undefined;
      if (!inc) throw new DisputeConflictError();
      const obj: MemoryObject = {
        id: resolutionMemoryId!,
        namespace: row.namespace,
        scope: inc.scope as Scope,
        tier: "L2",
        backendRef: "inline",
        content: editedContent!,
        type: inc.type as MemoryType,
        confidence: 1,
        eventTime: null,
        assertionTime: ts,
        tValidFrom: ts,
        tValidTo: null,
        supersedes: row.disputed_against,
        provenance: [{ source: "manual", actor: identity.actor, ts }],
        ttlSeconds: inc.ttl_seconds === null ? null : Number(inc.ttl_seconds),
        telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
        status: "active",
      };
      await new MemoryIndex(tx).insert(obj, editedEmbedding);
      await this.closeIncumbent(tx, row.disputed_against, ts);
      await this.archiveDisputedFact(tx, row.memory_id);
      await this.audit(tx, identity, "write", obj.id, row.namespace, "ok",
        `manual replacement via dispute ${disputeId}`);
      await this.audit(tx, identity, "supersede", row.disputed_against, row.namespace, "ok",
        `validity closed; dispute ${disputeId} resolved by edit ${obj.id}`);
      await this.audit(tx, identity, "resolve", row.memory_id, row.namespace, "ok",
        `action=edit dispute=${disputeId} replacement=${obj.id} against=${row.disputed_against}`);
    });

    return { id: disputeId, action: input.action, resolutionMemoryId };
  }

  // -------------------------------------------------------------------------

  /** Disputed → active with the supersedence link and a fresh validity start. */
  private async activateDisputedFact(
    tx: Db,
    memoryId: string,
    incumbentId: string,
    ts: string,
  ): Promise<void> {
    const updated = await tx.query(
      `UPDATE memory_objects
          SET status = 'active', supersedes = $2, t_valid_from = $3
        WHERE id = $1 AND status = 'disputed'
        RETURNING id`,
      [memoryId, incumbentId, ts],
    );
    if (updated.rows.length !== 1) throw new DisputeConflictError();
  }

  private async archiveDisputedFact(tx: Db, memoryId: string): Promise<void> {
    const updated = await tx.query(
      `UPDATE memory_objects SET status = 'archived'
        WHERE id = $1 AND status = 'disputed'
        RETURNING id`,
      [memoryId],
    );
    if (updated.rows.length !== 1) throw new DisputeConflictError();
  }

  /**
   * Guarded close, same discipline as the write path's supersede lane: zero
   * rows means the incumbent stopped being currently valid since the dispute
   * opened — the whole resolution rolls back and the queue shows the stale
   * badge on refresh.
   */
  private async closeIncumbent(tx: Db, incumbentId: string, ts: string): Promise<void> {
    const closed = await tx.query(
      `UPDATE memory_objects SET t_valid_to = $2
        WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL
        RETURNING id`,
      [incumbentId, ts],
    );
    if (closed.rows.length !== 1) throw new DisputeConflictError();
  }

  /** Mirror of consolidation canRead: subtree owners/admins/auditors + ancestors. */
  private canRead(identity: Identity, namespace: Namespace): boolean {
    if (isRootOwner(identity)) return true;
    if (namespaceAncestors(identity.namespace).includes(namespace)) return true;
    return (
      (identity.role === "owner" || identity.role === "admin" || identity.role === "auditor") &&
      namespaceAncestors(namespace).includes(identity.namespace)
    );
  }

  private canManage(identity: Identity, namespace: Namespace): boolean {
    if (identity.role !== "owner" && identity.role !== "admin") return false;
    return isRootOwner(identity) || namespaceAncestors(namespace).includes(identity.namespace);
  }

  private toView(identity: Identity, row: DisputeRow): DisputeView {
    const dProv = parseProvenance(row.d_provenance);
    const iProv = parseProvenance(row.i_provenance);
    return {
      id: row.id,
      namespace: row.namespace,
      team: teamBucket(identity.namespace, row.namespace),
      category: row.category as DisputeCategory,
      reason: row.reason,
      rowVersion: Number(row.row_version),
      createdAt: toIso(row.created_at),
      disputed: {
        id: row.memory_id,
        content: row.d_content,
        scope: row.d_scope as Scope,
        source: dProv[0]?.source ?? "conversation",
        actor: dProv[0]?.actor ?? "",
        confidence: Number(row.d_confidence),
        tValidFrom: toIso(row.d_valid_from),
        tValidTo: toIsoOrNull(row.d_valid_to),
      },
      incumbent: {
        id: row.disputed_against,
        content: row.i_content,
        scope: row.i_scope as Scope,
        source: iProv[0]?.source ?? "conversation",
        actor: iProv[0]?.actor ?? "",
        confidence: Number(row.i_confidence),
        tValidFrom: toIso(row.i_valid_from),
        tValidTo: toIsoOrNull(row.i_valid_to),
      },
      incumbentCurrent: Boolean(row.incumbent_current),
      repairProposed: row.repair_proposal_id !== null,
      repairClassification: row.repair_classification,
    };
  }

  private audit(
    tx: Db,
    identity: Identity,
    op: AuditEvent["op"],
    memoryId: MemoryId | null,
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> {
    return this.deps.audit.appendTo(tx, {
      ts: this.now().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId,
      namespace,
      purpose: "dispute-review",
      result,
      detail,
    });
  }
}
