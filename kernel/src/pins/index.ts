/**
 * R5A governed pins.
 *
 * Pins name stable L2 memory ULIDs or stable logical-concept ULIDs. The
 * service owns authorization, target validation, idempotency and the atomic
 * mutation + D4 audit boundary. It deliberately does not accept display text
 * or cold-store version paths as identifiers.
 */

import { ulid } from "ulid";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import type {
  AccessSubject,
  Concept,
  Identity,
  MemoryPin,
  Namespace,
  PinTarget,
  ResolvedPin,
} from "../types.js";

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

export interface PinColdPort {
  readConcept(namespace: Namespace, path: string): Promise<Concept | null>;
}

export interface PinAuditPort {
  append(event: Parameters<AuditLog["append"]>[0]): Promise<void>;
  appendTo(db: Db, event: Parameters<AuditLog["appendTo"]>[1]): Promise<void>;
}

export interface PinOptions {
  /** Trusted destination selected by the server; defaults to Identity.namespace. */
  namespace?: Namespace;
  source?: MemoryPin["source"];
}

export interface PinResult {
  pin: MemoryPin;
  created: boolean;
}

export interface UnpinResult {
  pin: MemoryPin;
  released: boolean;
}

export interface ResolvedPins {
  pins: ResolvedPin[];
  /** Active rows whose targets are no longer safely readable. */
  rejected: number;
}

export class PinValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PinValidationError";
  }
}

interface PinRow {
  id: string;
  namespace: string;
  target_kind: "memory" | "concept";
  target_ref: string;
  source: MemoryPin["source"];
  created_by: string;
  created_at: Date | string;
  released_by: string | null;
  released_at: Date | string | null;
}

type ResolvedTarget =
  | { kind: "memory"; ref: string; content: string }
  | { kind: "concept"; ref: string; versionPath: string; content: string };

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function rowToPin(row: PinRow): MemoryPin {
  const target = row.target_kind === "memory"
    ? { kind: "memory" as const, ref: row.target_ref }
    : { kind: "concept" as const, ref: row.target_ref };
  return {
    id: row.id,
    namespace: row.namespace,
    target,
    source: row.source,
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    releasedBy: row.released_by,
    releasedAt: row.released_at === null ? null : toIso(row.released_at),
  };
}

function isStableRef(ref: string): boolean {
  return ULID_RE.test(ref);
}

export class PinService {
  constructor(
    private readonly db: Db,
    private readonly audit: PinAuditPort,
    private readonly cold: PinColdPort,
    private readonly isMounted?: (
      namespace: Namespace,
      target: PinTarget,
      db?: Db,
    ) => Promise<boolean>,
  ) {}

  async pin(target: PinTarget, identity: Identity, options: PinOptions = {}): Promise<PinResult> {
    const namespace = options.namespace ?? identity.namespace;
    await this.assertMutationScope(identity, namespace, "pin");
    if (!isStableRef(target.ref)) {
      await this.auditOutcome(identity, namespace, "pin", "miss", "target_ref_not_stable");
      throw new PinValidationError("pin target must be a stable ULID reference");
    }

    const now = new Date().toISOString();
    try {
      return await this.db.transaction(async (tx) => {
        // Lock the target through the pin commit. Erasure/archive may make the
        // pin stale immediately afterwards (the allocator browns that out),
        // but the create operation itself always linearizes against a readable
        // object rather than a preflight snapshot.
        await this.resolveTarget(namespace, target, tx, true, {
          principals: [identity.actor, identity.keyId, ...(identity.sourcePrincipals ?? [])],
          groups: identity.sourceGroups ?? [],
        });
        const inserted = await tx.query(
        `INSERT INTO memory_pins
           (id, namespace, target_kind, target_ref, source, created_by, created_at,
            released_by, released_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL)
         ON CONFLICT (namespace, target_kind, target_ref) WHERE released_at IS NULL
         DO NOTHING
         RETURNING id, namespace, target_kind, target_ref, source, created_by,
                   created_at, released_by, released_at`,
        [
          ulid(),
          namespace,
          target.kind,
          target.ref,
          options.source ?? "manual",
          identity.actor,
          now,
        ],
      );
        const created = inserted.rows.length === 1;
        const row = created
          ? inserted.rows[0]
          : (await tx.query(
            `SELECT id, namespace, target_kind, target_ref, source, created_by,
                    created_at, released_by, released_at
               FROM memory_pins
              WHERE namespace = $1 AND target_kind = $2 AND target_ref = $3
                AND released_at IS NULL`,
            [namespace, target.kind, target.ref],
          )).rows[0];
        if (!row) throw new Error("active pin disappeared during idempotent create");
        await this.audit.appendTo(tx, {
        ts: now,
        actor: identity.actor,
        agentId: identity.role === "agent" ? identity.keyId : "pin-service",
        op: "pin",
        memoryId: target.kind === "memory" ? target.ref : null,
        namespace,
        purpose: null,
        result: "ok",
        detail: `${created ? "created" : "idempotent"} kind=${target.kind} pinId=${String(row.id)}`,
        });
        return { pin: rowToPin(row as PinRow), created };
      });
    } catch (err) {
      const result = err instanceof AuthzError ? "denied" : err instanceof PinValidationError ? "miss" : "error";
      return this.auditFailure(identity, namespace, "pin", result, "pin_failed", err);
    }
  }

  async unpin(pinId: string, identity: Identity): Promise<UnpinResult> {
    if (!isStableRef(pinId)) {
      await this.auditOutcome(identity, identity.namespace, "unpin", "miss", "pin_id_not_stable");
      throw new PinValidationError("pin id must be a stable ULID reference");
    }
    const found = await this.db.query(
      `SELECT id, namespace, target_kind, target_ref, source, created_by,
              created_at, released_by, released_at
         FROM memory_pins WHERE id = $1`,
      [pinId],
    );
    const existing = found.rows[0] as PinRow | undefined;
    if (!existing) {
      await this.auditOutcome(identity, identity.namespace, "unpin", "miss", "pin_not_found");
      throw new PinValidationError("pin not found");
    }
    await this.assertMutationScope(identity, existing.namespace, "unpin");

    const now = new Date().toISOString();
    try {
      return await this.db.transaction(async (tx) => {
        const locked = await tx.query(
        `SELECT id, namespace, target_kind, target_ref, source, created_by,
                created_at, released_by, released_at
           FROM memory_pins WHERE id = $1 FOR UPDATE`,
        [pinId],
      );
        const row = locked.rows[0] as PinRow | undefined;
        if (!row) throw new Error("pin disappeared during unpin");
        let released = false;
        let resultRow = row;
        if (row.released_at === null) {
          const updated = await tx.query(
          `UPDATE memory_pins
              SET released_by = $2, released_at = $3
            WHERE id = $1 AND released_at IS NULL
          RETURNING id, namespace, target_kind, target_ref, source, created_by,
                    created_at, released_by, released_at`,
          [pinId, identity.actor, now],
        );
          released = updated.rows.length === 1;
          if (released) resultRow = updated.rows[0] as PinRow;
        }
        await this.audit.appendTo(tx, {
        ts: now,
        actor: identity.actor,
        agentId: identity.role === "agent" ? identity.keyId : "pin-service",
        op: "unpin",
        memoryId: row.target_kind === "memory" ? row.target_ref : null,
        namespace: row.namespace,
        purpose: null,
        result: "ok",
        detail: `${released ? "released" : "idempotent"} pinId=${pinId}`,
        });
        return { pin: rowToPin(resultRow), released };
      });
    } catch (err) {
      return this.auditFailure(identity, existing.namespace, "unpin", "error", "unpin_failed", err);
    }
  }

  async list(
    identity: Identity,
    namespace: Namespace = identity.namespace,
    includeReleased = false,
  ): Promise<MemoryPin[]> {
    await this.assertReadScope(identity, namespace);
    const result = await this.db.query(
      `SELECT id, namespace, target_kind, target_ref, source, created_by,
              created_at, released_by, released_at
         FROM memory_pins
        WHERE namespace = $1 ${includeReleased ? "" : "AND released_at IS NULL"}
        ORDER BY created_at, id`,
      [namespace],
    );
    return (result.rows as PinRow[]).map(rowToPin);
  }

  /** Allocator port: stale targets are counted and skipped, never thrown. */
  async resolve(namespace: Namespace, access?: AccessSubject): Promise<ResolvedPins> {
    const rows = await this.db.query(
      `SELECT id, namespace, target_kind, target_ref, source, created_by,
              created_at, released_by, released_at
         FROM memory_pins
        WHERE namespace = $1 AND released_at IS NULL
        ORDER BY created_at, id`,
      [namespace],
    );
    const pins: ResolvedPin[] = [];
    let rejected = 0;
    for (const row of rows.rows as PinRow[]) {
      try {
        const resolved = await this.resolveTarget(namespace, {
          kind: row.target_kind,
          ref: row.target_ref,
        }, this.db, false, access);
        pins.push({
          pinId: row.id,
          createdAt: toIso(row.created_at),
          ...resolved,
        } as ResolvedPin);
      } catch {
        rejected++;
      }
    }
    return { pins, rejected };
  }

  private async resolveTarget(
    namespace: Namespace,
    target: PinTarget,
    db: Db = this.db,
    lock = false,
    access?: AccessSubject,
  ): Promise<ResolvedTarget> {
    const visible = namespaceAncestors(namespace);
    if (target.kind === "memory") {
      const result = await db.query(
        `SELECT namespace, tier, content, status, t_valid_to, source_access, classification,
                CASE WHEN ttl_seconds IS NULL THEN FALSE
                     ELSE assertion_time + ttl_seconds * INTERVAL '1 second' <= CURRENT_TIMESTAMP
                 END AS expired
           FROM memory_objects WHERE id = $1${lock ? " FOR SHARE" : ""}`,
        [target.ref],
      );
      const row = result.rows[0] as Record<string, unknown> | undefined;
      if (!row) throw new PinValidationError("memory target does not exist or was erased");
      if (!visible.includes(String(row.namespace)) && !(await this.isMounted?.(namespace, target, db))) {
        throw new AuthzError("memory target is outside the destination namespace visibility");
      }
      const sourceAccess = typeof row.source_access === "string"
        ? JSON.parse(row.source_access) as { principals?: string[]; groups?: string[] }
        : row.source_access as { principals?: string[]; groups?: string[] } | undefined;
      const principals = sourceAccess?.principals ?? [];
      const groups = sourceAccess?.groups ?? [];
      if (principals.length > 0 || groups.length > 0) {
        const allowed = access !== undefined && (
          principals.some((value) => access.principals.includes(value)) ||
          groups.some((value) => access.groups.includes(value))
        );
        if (!allowed) throw new AuthzError("memory target source ACL denied");
      }
      const classification = typeof row.classification === "string"
        ? JSON.parse(row.classification) as { sensitivity?: string; allowedDestinations?: string[] }
        : row.classification as { sensitivity?: string; allowedDestinations?: string[] } | undefined;
      if ((classification?.sensitivity === "confidential" ||
           classification?.sensitivity === "restricted") &&
          !classification.allowedDestinations?.includes("agent-context")) {
        throw new AuthzError("memory target classification denied");
      }
      if (
        row.tier !== "L2" ||
        row.status !== "active" ||
        row.t_valid_to !== null ||
        row.expired === true ||
        row.expired === "true"
      ) {
        throw new PinValidationError("memory target is not currently readable");
      }
      return { kind: "memory", ref: target.ref, content: String(row.content) };
    }

    const result = await db.query(
      `SELECT kc.namespace, kc.status AS concept_status,
              kv.path, kv.state AS version_state
         FROM knowledge_concepts kc
         LEFT JOIN knowledge_versions kv ON kv.id = kc.current_version_id
        WHERE kc.id = $1${lock ? " FOR SHARE OF kc" : ""}`,
      [target.ref],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new PinValidationError("concept target does not exist");
    const ownerNamespace = String(row.namespace);
    if (
      ownerNamespace !== "" && !visible.includes(ownerNamespace) &&
      !(await this.isMounted?.(namespace, target, db))
    ) {
      throw new AuthzError("concept target is outside the destination namespace visibility");
    }
    if (row.concept_status !== "active" || row.version_state !== "published" || !row.path) {
      throw new PinValidationError("concept has no active published version");
    }
    const versionPath = String(row.path);
    const concept = await this.cold.readConcept(namespace, versionPath);
    if (!concept) throw new PinValidationError("concept version is not currently readable");
    const content = concept.title ? `${concept.title}\n\n${concept.body}` : concept.body;
    return { kind: "concept", ref: target.ref, versionPath, content };
  }

  private async assertMutationScope(
    identity: Identity,
    namespace: Namespace,
    op: "pin" | "unpin",
  ): Promise<void> {
    const allowedRole = identity.role === "owner" || identity.role === "admin" || identity.role === "agent";
    const inScope = isRootOwner(identity) ||
      (identity.role === "agent"
        ? namespace === identity.namespace
        : isSelfOrDescendant(namespace, identity.namespace));
    if (allowedRole && inScope) return;
    await this.auditOutcome(identity, identity.namespace, op, "denied", "mutation_scope_denied");
    throw new AuthzError(`${op} denied for role '${identity.role}' or destination namespace`);
  }

  private async assertReadScope(identity: Identity, namespace: Namespace): Promise<void> {
    const inScope = isRootOwner(identity) ||
      (identity.role === "agent"
        ? namespace === identity.namespace
        : isSelfOrDescendant(namespace, identity.namespace));
    if (inScope) return;
    throw new AuthzError("pin list namespace is outside caller subtree");
  }

  private async auditOutcome(
    identity: Identity,
    namespace: Namespace,
    op: "pin" | "unpin",
    result: "denied" | "miss" | "error",
    detail: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.role === "agent" ? identity.keyId : "pin-service",
      op,
      memoryId: null,
      namespace,
      purpose: null,
      result,
      detail,
    });
  }

  private async auditFailure(
    identity: Identity,
    namespace: Namespace,
    op: "pin" | "unpin",
    result: "denied" | "miss" | "error",
    detail: string,
    original: unknown,
  ): Promise<never> {
    try {
      await this.auditOutcome(identity, namespace, op, result, detail);
    } catch (auditError) {
      throw new AggregateError(
        [original, auditError],
        `${op} failed and its failure audit could not be persisted`,
      );
    }
    throw original;
  }
}
