/**
 * R5C movement engine.
 *
 * Movement decides placement only. It does not rank retrieval results or
 * assemble prompts. Every manual action is a durable, leased, idempotent row.
 */
import { ulid } from "ulid";
import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { acquireErasureFence, writeFenceNamespaces } from "../erasure-fence.js";
import type { Identity, MemoryType, Scope } from "../types.js";

export type MovementActionKind =
  | "promote_pin"
  | "propose_cold"
  | "materialize_warm"
  | "archive_warm";

export type MovementActionStatus = "pending" | "running" | "complete" | "failed" | "degraded";

export interface MovementActionRecord {
  id: string;
  namespace: string;
  action: MovementActionKind;
  targetRef: string;
  idempotencyKey: string;
  status: MovementActionStatus;
  leaseUntil: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MovementInput {
  action: MovementActionKind;
  targetRef: string;
  idempotencyKey: string;
  /** Exact-scope L2 evidence used only by propose_cold. */
  evidenceIds?: string[];
}

export interface MaterializedVersion {
  content: string;
  embedding?: number[] | null;
  scope?: Scope;
  type?: MemoryType;
  confidence?: number;
}

export interface PreparedColdProposal {
  /** Commit only durable proposal state. External work belongs in prepare. */
  commitPrepared(db: Db): Promise<{ proposalId: string }>;
}

export interface MovementDependencies {
  /** Decrypt/load a published immutable L3 version before the DB transaction. */
  loadPublishedVersion?(versionId: string, namespace: string): Promise<MaterializedVersion>;
  /** Run LLM/embed work before the DB transaction; commit only the proposal row. */
  prepareColdProposal?(
    targetRef: string,
    evidenceIds: readonly string[],
    identity: Identity,
  ): Promise<PreparedColdProposal>;
}

export interface MovementOptions {
  leaseMs?: number;
  promotePin?: {
    enabled: boolean;
    minAccessCount: number;
    minSessionCount: number;
  };
}

interface ClaimedAction {
  record: MovementActionRecord;
  leaseToken: string | null;
}

function parseJsonObject(value: unknown): Record<string, unknown> | null {
  if (value === null || value === undefined) return null;
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : null;
}

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(value as string).toISOString();
}

function rowToAction(row: Record<string, unknown>): MovementActionRecord {
  return {
    id: row.id as string,
    namespace: row.namespace as string,
    action: row.action as MovementActionKind,
    targetRef: row.target_ref as string,
    idempotencyKey: row.idempotency_key as string,
    status: row.status as MovementActionStatus,
    leaseUntil: row.lease_until ? iso(row.lease_until) : null,
    result: parseJsonObject(row.result),
    error: (row.error as string | null) ?? null,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function isSteward(identity: Identity): boolean {
  return identity.role === "owner" || identity.role === "admin";
}

const STABLE_REF = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

function validateInput(input: MovementInput): void {
  if (!input.idempotencyKey.trim()) throw new Error("idempotencyKey is required");
  if (!STABLE_REF.test(input.targetRef.trim())) throw new Error("targetRef must be a stable ULID reference");
  if (input.action === "propose_cold") {
    const evidenceIds = input.evidenceIds;
    if (
      !Array.isArray(evidenceIds) || evidenceIds.length < 2 ||
      evidenceIds.some((id) => typeof id !== "string" || !STABLE_REF.test(id)) ||
      new Set(evidenceIds).size !== evidenceIds.length ||
      !evidenceIds.includes(input.targetRef)
    ) {
      throw new Error("propose_cold requires at least two unique stable evidenceIds including targetRef");
    }
  }
}

function vectorLiteral(value: number[] | null | undefined): string | null {
  if (!value) return null;
  if (value.some((part) => !Number.isFinite(part))) throw new Error("embedding must be finite");
  return `[${value.join(",")}]`;
}

function dependencyReason(error: unknown): string {
  // Persist a bounded operational category, never provider payloads or content.
  return error instanceof Error && error.name === "MovementDependencyUnavailable"
    ? "dependency_unavailable"
    : "dependency_failed";
}

export class MovementEngine {
  private readonly leaseMs: number;
  private readonly promotePin: NonNullable<MovementOptions["promotePin"]>;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly deps: MovementDependencies = {},
    options: MovementOptions = {},
  ) {
    this.leaseMs = Math.max(1_000, options.leaseMs ?? 30_000);
    this.promotePin = options.promotePin ?? {
      enabled: false,
      minAccessCount: Number.MAX_SAFE_INTEGER,
      minSessionCount: Number.MAX_SAFE_INTEGER,
    };
  }

  async get(identity: Pick<Identity, "namespace">, idempotencyKey: string): Promise<MovementActionRecord | null> {
    const result = await this.db.query(
      `SELECT * FROM movement_actions WHERE namespace = $1 AND idempotency_key = $2`,
      [identity.namespace, idempotencyKey],
    );
    return result.rows.length === 0
      ? null
      : rowToAction(result.rows[0] as Record<string, unknown>);
  }

  /** Execute one explicit manual movement action. No scheduler is implied. */
  async runManual(identity: Identity, input: MovementInput): Promise<MovementActionRecord> {
    try {
      validateInput(input);
    } catch (error) {
      return this.rethrowWithOutcome(error, identity, input.action, "error", "invalid_input");
    }
    if (!isSteward(identity)) {
      const error = new Error("movement requires owner or admin authority");
      return this.rethrowWithOutcome(error, identity, input.action, "denied", "role_denied");
    }

    let claim: ClaimedAction;
    try {
      claim = await this.claim(identity, input);
    } catch (error) {
      return this.rethrowWithOutcome(error, identity, input.action, "error", "idempotency_conflict");
    }
    if (claim.leaseToken === null) {
      await this.appendOutcome(
        identity,
        input.action,
        claim.record.status === "complete" ? "ok" : claim.record.status === "running" ? "miss" : "error",
        `replay status=${claim.record.status}; action=${claim.record.id}`,
      );
      return claim.record;
    }

    let preparedVersion: MaterializedVersion | null = null;
    let preparedProposal: PreparedColdProposal | null = null;
    try {
      if (input.action === "materialize_warm") {
        if (!this.deps.loadPublishedVersion) {
          throw Object.assign(new Error("materialization dependency unavailable"), {
            name: "MovementDependencyUnavailable",
          });
        }
        preparedVersion = await this.deps.loadPublishedVersion(input.targetRef, identity.namespace);
      } else if (input.action === "propose_cold") {
        if (!this.deps.prepareColdProposal) {
          throw Object.assign(new Error("proposal dependency unavailable"), {
            name: "MovementDependencyUnavailable",
          });
        }
        preparedProposal = await this.deps.prepareColdProposal(input.targetRef, input.evidenceIds!, identity);
      }
    } catch (error) {
      return this.finishDegraded(identity, claim, dependencyReason(error));
    }

    try {
      return await this.db.transaction(async (tx) => {
        const owned = await this.lockOwnedClaim(tx, claim);
        if (!owned) {
          const current = await tx.query(`SELECT * FROM movement_actions WHERE id = $1`, [claim.record.id]);
          await this.audit.appendTo(tx, {
            ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
            op: "move", memoryId: null, namespace: identity.namespace,
            purpose: `movement:${input.action}`, result: "miss",
            detail: `lease_lost; action=${claim.record.id}`,
          });
          return current.rows.length === 0
            ? claim.record
            : rowToAction(current.rows[0] as Record<string, unknown>);
        }

        let result: Record<string, unknown>;
        switch (input.action) {
          case "promote_pin":
            result = await this.promote(tx, identity, input.targetRef);
            break;
          case "propose_cold":
            result = await this.propose(tx, identity, input.targetRef, preparedProposal!);
            break;
          case "materialize_warm":
            result = await this.materialize(tx, identity, input.targetRef, preparedVersion!);
            break;
          case "archive_warm":
            result = await this.archive(tx, identity, input.targetRef);
            break;
        }

        const now = new Date().toISOString();
        const updated = await tx.query(
          `UPDATE movement_actions
           SET status = 'complete', lease_until = NULL, result = $1, error = NULL, updated_at = $2
           WHERE id = $3 AND status = 'running' AND lease_until = $4
           RETURNING *`,
          [JSON.stringify(result), now, claim.record.id, claim.leaseToken],
        );
        if (updated.rows.length === 0) throw new Error("movement lease was lost");
        await this.audit.appendTo(tx, {
          ts: now,
          actor: identity.actor,
          agentId: identity.keyId,
          op: "move",
          memoryId: input.action === "archive_warm" ? input.targetRef : null,
          namespace: identity.namespace,
          purpose: `movement:${input.action}`,
          result: result.reason === "target_unavailable" ? "miss" : "ok",
          detail: `action=${claim.record.id}`,
        });
        return rowToAction(updated.rows[0] as Record<string, unknown>);
      });
    } catch (error) {
      if (error instanceof Error && error.message === "movement lease was lost") {
        return (await this.get(identity, input.idempotencyKey)) ?? claim.record;
      }
      return this.finishFailed(identity, claim, "action_failed");
    }
  }

  private async claim(identity: Identity, input: MovementInput): Promise<ClaimedAction> {
    return this.db.transaction(async (tx) => {
      const now = new Date();
      await tx.query(
        `INSERT INTO movement_actions
           (id, namespace, action, target_ref, idempotency_key, status, lease_until,
            result, error, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'pending', NULL, NULL, NULL, $6, $6)
         ON CONFLICT (namespace, idempotency_key) DO NOTHING`,
        [ulid(), identity.namespace, input.action, input.targetRef, input.idempotencyKey, now.toISOString()],
      );
      const selected = await tx.query(
        `SELECT * FROM movement_actions WHERE namespace = $1 AND idempotency_key = $2 FOR UPDATE`,
        [identity.namespace, input.idempotencyKey],
      );
      const current = rowToAction(selected.rows[0] as Record<string, unknown>);
      if (
        current.namespace !== identity.namespace ||
        current.action !== input.action ||
        current.targetRef !== input.targetRef
      ) {
        throw new Error("idempotencyKey is already bound to another movement action");
      }
      if (current.status === "complete" || current.status === "degraded" || current.status === "failed") {
        return { record: current, leaseToken: null };
      }
      if (current.status === "running" && current.leaseUntil && new Date(current.leaseUntil) > now) {
        return { record: current, leaseToken: null };
      }
      const leaseToken = new Date(now.getTime() + this.leaseMs).toISOString();
      const claimed = await tx.query(
        `UPDATE movement_actions
         SET status = 'running', lease_until = $1, updated_at = $2
         WHERE id = $3 RETURNING *`,
        [leaseToken, now.toISOString(), current.id],
      );
      return {
        record: rowToAction(claimed.rows[0] as Record<string, unknown>),
        leaseToken,
      };
    });
  }

  private async lockOwnedClaim(tx: Db, claim: ClaimedAction): Promise<boolean> {
    const selected = await tx.query(`SELECT status, lease_until FROM movement_actions WHERE id = $1 FOR UPDATE`, [
      claim.record.id,
    ]);
    if (selected.rows.length === 0) return false;
    const row = selected.rows[0] as Record<string, unknown>;
    return row.status === "running" && iso(row.lease_until) === claim.leaseToken;
  }

  private async promote(tx: Db, identity: Identity, targetRef: string): Promise<Record<string, unknown>> {
    if (!this.promotePin.enabled) return { promoted: false, reason: "disabled" };
    const found = await tx.query(
      `SELECT id, access_count, provenance FROM memory_objects
       WHERE id = $1 AND namespace = $2 AND tier = 'L2' AND status = 'active'
         AND t_valid_to IS NULL
         AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)`,
      [targetRef, identity.namespace],
    );
    if (found.rows.length === 0) return { promoted: false, reason: "target_unavailable" };
    const row = found.rows[0] as Record<string, unknown>;
    const provenance = typeof row.provenance === "string" ? JSON.parse(row.provenance) : row.provenance;
    const sessions = new Set(
      (Array.isArray(provenance) ? provenance : [])
        .map((entry) => (entry as Record<string, unknown>).session)
        .filter((session): session is string => typeof session === "string" && session.length > 0),
    ).size;
    if (
      Number(row.access_count) < this.promotePin.minAccessCount ||
      sessions < this.promotePin.minSessionCount
    ) {
      return { promoted: false, reason: "threshold_not_met" };
    }
    const pinId = ulid();
    const now = new Date().toISOString();
    const inserted = await tx.query(
      `INSERT INTO memory_pins
         (id, namespace, target_kind, target_ref, source, created_by, created_at)
       VALUES ($1, $2, 'memory', $3, 'movement', $4, $5)
       ON CONFLICT (namespace, target_kind, target_ref) WHERE released_at IS NULL DO NOTHING
       RETURNING id`,
      [pinId, identity.namespace, targetRef, identity.actor, now],
    );
    if (inserted.rows.length === 0) {
      const existing = await tx.query(
        `SELECT id FROM memory_pins
         WHERE namespace = $1 AND target_kind = 'memory' AND target_ref = $2 AND released_at IS NULL`,
        [identity.namespace, targetRef],
      );
      return { promoted: true, pinId: (existing.rows[0] as Record<string, unknown>).id, existing: true };
    }
    return { promoted: true, pinId, existing: false };
  }

  private async propose(
    tx: Db,
    identity: Identity,
    targetRef: string,
    prepared: PreparedColdProposal,
  ): Promise<Record<string, unknown>> {
    const committed = await prepared.commitPrepared(tx);
    const checked = await tx.query(
      `SELECT id FROM knowledge_proposals
       WHERE id = $1 AND namespace = $2 AND status = 'pending_review'`,
      [committed.proposalId, identity.namespace],
    );
    if (checked.rows.length === 0) throw new Error("proposal dependency did not create a review proposal");
    return { proposed: true, proposalId: committed.proposalId, evidenceRef: targetRef };
  }

  private async materialize(
    tx: Db,
    identity: Identity,
    versionId: string,
    prepared: MaterializedVersion,
  ): Promise<Record<string, unknown>> {
    const version = await tx.query(
      `SELECT kv.id
       FROM knowledge_versions kv
       JOIN knowledge_concepts kc ON kc.id = kv.concept_id
       WHERE kv.id = $1 AND kv.state = 'published' AND kc.namespace = $2
         AND kc.status = 'active' AND kc.current_version_id = kv.id`,
      [versionId, identity.namespace],
    );
    if (version.rows.length === 0) throw new Error("published version is unavailable");
    const existing = await tx.query(
      `SELECT id FROM memory_objects
       WHERE namespace = $1 AND backend_ref = $2 AND tier = 'L2' AND status = 'active'
         AND t_valid_to IS NULL
         AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
       ORDER BY assertion_time DESC LIMIT 1`,
      [identity.namespace, `knowledge-version:${versionId}`],
    );
    if (existing.rows.length > 0) {
      return { materialized: true, memoryId: (existing.rows[0] as Record<string, unknown>).id, existing: true };
    }

    for (const namespace of writeFenceNamespaces(identity.namespace)) {
      await acquireErasureFence(tx, namespace);
    }
    const memoryId = ulid();
    const now = new Date().toISOString();
    await tx.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
          provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
       VALUES ($1, $2, $3, 'L2', $4, $5, $6, $7,
               NULL, $8, $8, NULL, NULL, $9, NULL, NULL, 0, 0, 'active', $10::vector)`,
      [
        memoryId,
        identity.namespace,
        prepared.scope ?? "team",
        `knowledge-version:${versionId}`,
        prepared.content,
        prepared.type ?? "concept",
        prepared.confidence ?? 1,
        now,
        JSON.stringify([{ source: "consolidation", actor: identity.actor, ts: now }]),
        vectorLiteral(prepared.embedding),
      ],
    );
    return { materialized: true, memoryId, versionId, existing: false };
  }

  private async archive(tx: Db, identity: Identity, targetRef: string): Promise<Record<string, unknown>> {
    const updated = await tx.query(
      `UPDATE memory_objects SET status = 'archived'
       WHERE id = $1 AND namespace = $2 AND tier = 'L2' AND status = 'active'
       RETURNING id`,
      [targetRef, identity.namespace],
    );
    if (updated.rows.length > 0) return { archived: true, memoryId: targetRef, existing: false };
    const existing = await tx.query(
      `SELECT status FROM memory_objects WHERE id = $1 AND namespace = $2 AND tier = 'L2'`,
      [targetRef, identity.namespace],
    );
    return existing.rows.length > 0 && (existing.rows[0] as Record<string, unknown>).status === "archived"
      ? { archived: true, memoryId: targetRef, existing: true }
      : { archived: false, reason: "target_unavailable" };
  }

  private async finishDegraded(
    identity: Identity,
    claim: ClaimedAction,
    reason: string,
  ): Promise<MovementActionRecord> {
    return this.finishWithState(identity, claim, "degraded", reason);
  }

  private async finishFailed(
    identity: Identity,
    claim: ClaimedAction,
    reason: string,
  ): Promise<MovementActionRecord> {
    return this.finishWithState(identity, claim, "failed", reason);
  }

  private async finishWithState(
    identity: Identity,
    claim: ClaimedAction,
    status: "failed" | "degraded",
    reason: string,
  ): Promise<MovementActionRecord> {
    return this.db.transaction(async (tx) => {
      const now = new Date().toISOString();
      const updated = await tx.query(
        `UPDATE movement_actions
         SET status = $1, lease_until = NULL, result = $2, error = $3, updated_at = $4
         WHERE id = $5 AND status = 'running' AND lease_until = $6
         RETURNING *`,
        [status, JSON.stringify({ skipped: true, reason }), reason, now, claim.record.id, claim.leaseToken],
      );
      if (updated.rows.length === 0) {
        const current = await tx.query(`SELECT * FROM movement_actions WHERE id = $1`, [claim.record.id]);
        return rowToAction(current.rows[0] as Record<string, unknown>);
      }
      await this.audit.appendTo(tx, {
        ts: now,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "move",
        memoryId: null,
        namespace: identity.namespace,
        purpose: `movement:${claim.record.action}`,
        result: "error",
        detail: `${status}:${reason}; action=${claim.record.id}`,
      });
      return rowToAction(updated.rows[0] as Record<string, unknown>);
    });
  }

  private async appendOutcome(
    identity: Identity,
    action: MovementActionKind,
    result: "ok" | "denied" | "miss" | "error",
    detail: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "move",
      memoryId: null,
      namespace: identity.namespace,
      purpose: `movement:${action}`,
      result,
      detail,
    });
  }

  private async rethrowWithOutcome(
    error: unknown,
    identity: Identity,
    action: MovementActionKind,
    result: "ok" | "denied" | "miss" | "error",
    detail: string,
  ): Promise<never> {
    try {
      await this.appendOutcome(identity, action, result, detail);
    } catch (auditError) {
      throw new AggregateError([error, auditError], "movement failed and its outcome audit could not be written");
    }
    throw error;
  }
}
