/** R5D explicit, read-only segment mounts and copy-on-write lineage. */
import { ulid } from "ulid";
import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { acquireErasureFence, writeFenceNamespaces } from "../erasure-fence.js";
import { namespaceAncestors } from "../index/index.js";
import type { Identity, MemoryType, PinTarget, Scope } from "../types.js";

export interface MemorySegment {
  id: string;
  ownerNamespace: string;
  name: string;
  status: "active" | "revoked";
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface SegmentMember {
  id: string;
  segmentId: string;
  target: PinTarget;
  addedAt: string;
  removedAt: string | null;
}

export interface SegmentMount {
  id: string;
  segmentId: string;
  targetNamespace: string;
  access: "read";
  createdBy: string;
  createdAt: string;
  revokedBy: string | null;
  revokedAt: string | null;
}

/**
 * A resolver result is only an explicitly mounted stable ref. It deliberately
 * does not include ordinary ancestor-visible rows; callers union those through
 * their existing ACL path.
 */
export interface MountedStableRef {
  segmentId: string;
  mountId: string;
  kind: "memory" | "concept";
  ref: string;
  originNamespace: string;
  versionId: string | null;
}

export interface ForkInput {
  origin: PinTarget;
  targetNamespace: string;
  content: string;
  embedding?: number[] | null;
  scope?: Scope;
  type?: MemoryType;
  confidence?: number;
}

export interface MemoryFork {
  id: string;
  origin: PinTarget;
  targetMemoryId: string;
  targetNamespace: string;
  createdAt: string;
}

export interface DirectShareResult {
  segment: MemorySegment;
  member: SegmentMember;
  mount: SegmentMount;
}

/** A caller is authenticated but lacks authority for the requested share operation. */
export class SharingAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SharingAuthorizationError";
  }
}

/** The requested share operation is malformed or names an invalid resource state. */
export class SharingValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SharingValidationError";
  }
}

const STABLE_REF = /^[0-9A-HJKMNP-TV-Z]{26}$/;

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(value as string).toISOString();
}

function rowToSegment(row: Record<string, unknown>): MemorySegment {
  return {
    id: row.id as string,
    ownerNamespace: row.owner_namespace as string,
    name: row.name as string,
    status: row.status as MemorySegment["status"],
    createdBy: row.created_by as string,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function rowToMember(row: Record<string, unknown>): SegmentMember {
  return {
    id: row.id as string,
    segmentId: row.segment_id as string,
    target: { kind: row.target_kind as PinTarget["kind"], ref: row.target_ref as string },
    addedAt: iso(row.added_at),
    removedAt: row.removed_at ? iso(row.removed_at) : null,
  };
}

function rowToMount(row: Record<string, unknown>): SegmentMount {
  return {
    id: row.id as string,
    segmentId: row.segment_id as string,
    targetNamespace: row.target_namespace as string,
    access: "read",
    createdBy: row.created_by as string,
    createdAt: iso(row.created_at),
    revokedBy: (row.revoked_by as string | null) ?? null,
    revokedAt: row.revoked_at ? iso(row.revoked_at) : null,
  };
}

function tenantRoot(namespace: string): string | null {
  const root = namespace.split("/").filter(Boolean)[0];
  return root ?? null;
}

function isWithin(root: string, candidate: string): boolean {
  return root === "" || candidate === root || candidate.startsWith(`${root}/`);
}

function hasMutationAuthority(identity: Identity, namespace: string): boolean {
  return (
    (identity.role === "owner" || identity.role === "admin") &&
    isWithin(identity.namespace, namespace)
  );
}

function vectorLiteral(value: number[] | null | undefined): string | null {
  if (!value) return null;
  if (value.some((part) => !Number.isFinite(part))) {
    throw new SharingValidationError("embedding must be finite");
  }
  return `[${value.join(",")}]`;
}

export class MountedVisibilityResolver {
  constructor(private readonly db: Db) {}

  /**
   * Resolve only active explicitly mounted refs for this caller. Target mount
   * inheritance follows exact namespace ancestors and never uses LIKE.
   */
  async resolveMountedRefs(
    callerNamespace: string,
    db: Db = this.db,
  ): Promise<MountedStableRef[]> {
    const targets = namespaceAncestors(callerNamespace);
    const placeholders = targets.map((_, index) => `$${index + 1}`).join(", ");
    const rows = await db.query(
      `SELECT sm.id AS mount_id, sm.segment_id, member.target_kind, member.target_ref,
              CASE WHEN member.target_kind = 'memory' THEN mo.namespace ELSE kc.namespace END AS origin_namespace,
              CASE WHEN member.target_kind = 'concept' THEN kv.id ELSE NULL END AS version_id
       FROM segment_mounts sm
       JOIN memory_segments segment ON segment.id = sm.segment_id
       JOIN segment_members member ON member.segment_id = segment.id AND member.removed_at IS NULL
       LEFT JOIN memory_objects mo
         ON member.target_kind = 'memory' AND mo.id = member.target_ref
       LEFT JOIN knowledge_concepts kc
         ON member.target_kind = 'concept' AND kc.id = member.target_ref
       LEFT JOIN knowledge_versions kv
         ON member.target_kind = 'concept' AND kv.id = kc.current_version_id
       WHERE sm.target_namespace IN (${placeholders})
         AND sm.revoked_at IS NULL
         AND segment.status = 'active'
         AND (
           (member.target_kind = 'memory'
             AND mo.status = 'active' AND mo.t_valid_to IS NULL
             AND (mo.ttl_seconds IS NULL OR mo.assertion_time + mo.ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP))
           OR
           (member.target_kind = 'concept'
             AND kc.status = 'active' AND kv.state = 'published')
         )
       ORDER BY sm.created_at, member.added_at`,
      targets,
    );
    const seen = new Set<string>();
    const resolved: MountedStableRef[] = [];
    for (const raw of rows.rows) {
      const row = raw as Record<string, unknown>;
      const key = `${row.target_kind as string}:${row.target_ref as string}`;
      if (seen.has(key)) continue;
      seen.add(key);
      resolved.push({
        segmentId: row.segment_id as string,
        mountId: row.mount_id as string,
        kind: row.target_kind as MountedStableRef["kind"],
        ref: row.target_ref as string,
        originNamespace: row.origin_namespace as string,
        versionId: (row.version_id as string | null) ?? null,
      });
    }
    return resolved;
  }
}

export class SharingService {
  readonly resolver: MountedVisibilityResolver;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
  ) {
    this.resolver = new MountedVisibilityResolver(db);
  }

  /** Atomic convenience behind mem.share: one stable ref, one read-only mount. */
  async share(
    identity: Identity,
    target: PinTarget,
    targetNamespace: string,
  ): Promise<DirectShareResult> {
    if (!STABLE_REF.test(target.ref)) {
      return this.shareFailure(
        identity,
        "error",
        "target_ref_not_stable",
        new SharingValidationError("share target must be a stable ULID reference"),
      );
    }
    if (!hasMutationAuthority(identity, identity.namespace) ||
        !hasMutationAuthority(identity, targetNamespace)) {
      return this.denied(identity, "share", "share denied");
    }
    if (!tenantRoot(identity.namespace) || tenantRoot(identity.namespace) !== tenantRoot(targetNamespace)) {
      return this.denied(identity, "share", "cross-tenant mounts are denied");
    }
    try {
      return await this.db.transaction(async (tx) => {
        const originNamespace = await this.targetNamespace(tx, target);
        if (originNamespace === null || !isWithin(identity.namespace, originNamespace)) {
          throw new SharingAuthorizationError("share target is unavailable to its owner");
        }
        const now = new Date().toISOString();
        const segment = rowToSegment((await tx.query(
        `INSERT INTO memory_segments
           (id, owner_namespace, name, status, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, 'active', $4, $5, $5) RETURNING *`,
        [ulid(), identity.namespace, `share-${target.ref}`, identity.actor, now],
      )).rows[0] as Record<string, unknown>);
        const member = rowToMember((await tx.query(
        `INSERT INTO segment_members
           (id, segment_id, target_kind, target_ref, added_at, removed_at)
         VALUES ($1, $2, $3, $4, $5, NULL) RETURNING *`,
        [ulid(), segment.id, target.kind, target.ref, now],
      )).rows[0] as Record<string, unknown>);
        const mount = rowToMount((await tx.query(
        `INSERT INTO segment_mounts
           (id, segment_id, target_namespace, access, created_by, created_at, revoked_by, revoked_at)
         VALUES ($1, $2, $3, 'read', $4, $5, NULL, NULL) RETURNING *`,
        [ulid(), segment.id, targetNamespace, identity.actor, now],
      )).rows[0] as Record<string, unknown>);
        await this.successAudit(tx, identity, "share", target.kind === "memory" ? target.ref : null,
          `segment=${segment.id}; mount=${mount.id}`, now);
        return { segment, member, mount };
      });
    } catch (error) {
      if (error instanceof SharingAuthorizationError) {
        return this.shareFailure(identity, "denied", "target_unavailable", error);
      }
      return this.shareFailure(identity, "error", "share_failed", error);
    }
  }

  async createSegment(identity: Identity, name: string): Promise<MemorySegment> {
    if (!hasMutationAuthority(identity, identity.namespace)) {
      return this.denied(identity, "share:create_segment", "segment mutation denied");
    }
    const normalized = name.trim();
    if (!normalized) throw new SharingValidationError("segment name is required");
    return this.db.transaction(async (tx) => {
      const id = ulid();
      const now = new Date().toISOString();
      const inserted = await tx.query(
        `INSERT INTO memory_segments
           (id, owner_namespace, name, status, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, 'active', $4, $5, $5)
         RETURNING *`,
        [id, identity.namespace, normalized, identity.actor, now],
      );
      await this.successAudit(tx, identity, "share:create_segment", null, `segment=${id}`, now);
      return rowToSegment(inserted.rows[0] as Record<string, unknown>);
    });
  }

  async addMember(identity: Identity, segmentId: string, target: PinTarget): Promise<SegmentMember> {
    if (!STABLE_REF.test(target.ref)) {
      throw new SharingValidationError("member ref must be a stable ULID reference");
    }
    return this.db.transaction(async (tx) => {
      const segment = await this.lockSegment(tx, segmentId);
      if (!segment || segment.status !== "active") {
        throw new SharingValidationError("active segment not found");
      }
      if (!hasMutationAuthority(identity, segment.ownerNamespace)) {
        throw new SharingAuthorizationError("segment mutation denied");
      }
      const originNamespace = await this.targetNamespace(tx, target);
      if (originNamespace === null || !isWithin(segment.ownerNamespace, originNamespace)) {
        throw new SharingValidationError("segment member is unavailable to its owner");
      }
      const id = ulid();
      const now = new Date().toISOString();
      const inserted = await tx.query(
        `INSERT INTO segment_members
           (id, segment_id, target_kind, target_ref, added_at, removed_at)
         VALUES ($1, $2, $3, $4, $5, NULL)
         ON CONFLICT (segment_id, target_kind, target_ref) WHERE removed_at IS NULL DO NOTHING
         RETURNING *`,
        [id, segmentId, target.kind, target.ref, now],
      );
      const member = inserted.rows.length > 0
        ? rowToMember(inserted.rows[0] as Record<string, unknown>)
        : rowToMember(
            (
              await tx.query(
                `SELECT * FROM segment_members
                 WHERE segment_id = $1 AND target_kind = $2 AND target_ref = $3 AND removed_at IS NULL`,
                [segmentId, target.kind, target.ref],
              )
            ).rows[0] as Record<string, unknown>,
          );
      await this.successAudit(
        tx,
        identity,
        "share:add_member",
        target.kind === "memory" ? target.ref : null,
        `segment=${segmentId}; member=${member.id}`,
        now,
      );
      return member;
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:add_member", error.message);
      }
      throw error;
    });
  }

  async removeMember(identity: Identity, memberId: string): Promise<SegmentMember> {
    return this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT member.*, segment.owner_namespace, segment.status AS segment_status
         FROM segment_members member JOIN memory_segments segment ON segment.id = member.segment_id
         WHERE member.id = $1 FOR UPDATE`,
        [memberId],
      );
      if (selected.rows.length === 0) throw new SharingValidationError("segment member not found");
      const row = selected.rows[0] as Record<string, unknown>;
      if (!hasMutationAuthority(identity, row.owner_namespace as string)) {
        throw new SharingAuthorizationError("segment mutation denied");
      }
      const now = new Date().toISOString();
      const updated = row.removed_at
        ? selected
        : await tx.query(
            `UPDATE segment_members SET removed_at = $1 WHERE id = $2 RETURNING *`,
            [now, memberId],
          );
      const member = rowToMember(updated.rows[0] as Record<string, unknown>);
      await this.successAudit(tx, identity, "share:remove_member", null, `member=${memberId}`, now);
      return member;
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:remove_member", error.message);
      }
      throw error;
    });
  }

  async mount(identity: Identity, segmentId: string, targetNamespace: string): Promise<SegmentMount> {
    return this.db.transaction(async (tx) => {
      const segment = await this.lockSegment(tx, segmentId);
      if (!segment || segment.status !== "active") {
        throw new SharingValidationError("active segment not found");
      }
      if (
        !hasMutationAuthority(identity, segment.ownerNamespace) ||
        !hasMutationAuthority(identity, targetNamespace)
      ) {
        throw new SharingAuthorizationError("segment mount denied");
      }
      const sourceTenant = tenantRoot(segment.ownerNamespace);
      const targetTenant = tenantRoot(targetNamespace);
      if (!sourceTenant || sourceTenant !== targetTenant) {
        throw new SharingAuthorizationError("cross-tenant mounts are denied");
      }
      const id = ulid();
      const now = new Date().toISOString();
      const inserted = await tx.query(
        `INSERT INTO segment_mounts
           (id, segment_id, target_namespace, access, created_by, created_at, revoked_by, revoked_at)
         VALUES ($1, $2, $3, 'read', $4, $5, NULL, NULL)
         ON CONFLICT (segment_id, target_namespace) WHERE revoked_at IS NULL DO NOTHING
         RETURNING *`,
        [id, segmentId, targetNamespace, identity.actor, now],
      );
      const mount = inserted.rows.length > 0
        ? rowToMount(inserted.rows[0] as Record<string, unknown>)
        : rowToMount(
            (
              await tx.query(
                `SELECT * FROM segment_mounts
                 WHERE segment_id = $1 AND target_namespace = $2 AND revoked_at IS NULL`,
                [segmentId, targetNamespace],
              )
            ).rows[0] as Record<string, unknown>,
          );
      await this.successAudit(tx, identity, "share:mount", null, `mount=${mount.id}`, now);
      return mount;
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:mount", error.message);
      }
      throw error;
    });
  }

  async revokeMount(identity: Identity, mountId: string): Promise<SegmentMount> {
    return this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT sm.*, segment.owner_namespace
         FROM segment_mounts sm JOIN memory_segments segment ON segment.id = sm.segment_id
         WHERE sm.id = $1 FOR UPDATE`,
        [mountId],
      );
      if (selected.rows.length === 0) throw new SharingValidationError("segment mount not found");
      const row = selected.rows[0] as Record<string, unknown>;
      const canRevokeAsSourceOwner = hasMutationAuthority(identity, row.owner_namespace as string);
      const canUnmountOwnTarget = hasMutationAuthority(identity, row.target_namespace as string);
      if (!canRevokeAsSourceOwner && !canUnmountOwnTarget) {
        throw new SharingAuthorizationError("segment revoke denied");
      }
      const now = new Date().toISOString();
      const updated = row.revoked_at
        ? selected
        : await tx.query(
            `UPDATE segment_mounts SET revoked_by = $1, revoked_at = $2 WHERE id = $3 RETURNING *`,
            [identity.actor, now, mountId],
          );
      const mount = rowToMount(updated.rows[0] as Record<string, unknown>);
      await this.successAudit(tx, identity, "share:revoke", null, `mount=${mountId}`, now);
      return mount;
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:revoke", error.message);
      }
      if (error instanceof SharingValidationError) {
        try {
          await this.audit.append({
            ts: new Date().toISOString(),
            actor: identity.actor,
            agentId: identity.keyId,
            op: "share",
            memoryId: null,
            namespace: identity.namespace,
            purpose: "share:revoke",
            result: "miss",
            detail: "mount_not_found",
          });
        } catch (auditError) {
          throw new AggregateError(
            [error, auditError],
            "mount revoke failed and its outcome audit could not be persisted",
          );
        }
      }
      throw error;
    });
  }

  async revokeSegment(identity: Identity, segmentId: string): Promise<MemorySegment> {
    return this.db.transaction(async (tx) => {
      const segment = await this.lockSegment(tx, segmentId);
      if (!segment) throw new SharingValidationError("segment not found");
      if (!hasMutationAuthority(identity, segment.ownerNamespace)) {
        throw new SharingAuthorizationError("segment revoke denied");
      }
      const now = new Date().toISOString();
      const updated = segment.status === "revoked"
        ? await tx.query(`SELECT * FROM memory_segments WHERE id = $1`, [segmentId])
        : await tx.query(
            `UPDATE memory_segments SET status = 'revoked', updated_at = $1 WHERE id = $2 RETURNING *`,
            [now, segmentId],
          );
      const result = rowToSegment(updated.rows[0] as Record<string, unknown>);
      await this.successAudit(tx, identity, "share:revoke_segment", null, `segment=${segmentId}`, now);
      return result;
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:revoke_segment", error.message);
      }
      throw error;
    });
  }

  /** Create a target-owned L2 fork while retaining immutable source lineage. */
  async forkMountedRef(identity: Identity, input: ForkInput): Promise<MemoryFork> {
    if (!STABLE_REF.test(input.origin.ref)) {
      throw new SharingValidationError("fork origin must be a stable ULID reference");
    }
    if (!hasMutationAuthority(identity, input.targetNamespace)) {
      return this.denied(identity, "share:fork", "fork denied");
    }
    if (!input.content.trim()) throw new SharingValidationError("fork content is required");
    return this.db.transaction(async (tx) => {
      if (!(await this.lockActiveMount(tx, input.targetNamespace, input.origin))) {
        throw new SharingAuthorizationError("origin is not actively mounted");
      }
      let inherited: { scope: Scope; type: MemoryType; confidence: number } = {
        scope: "team",
        type: "concept",
        confidence: 1,
      };
      if (input.origin.kind === "memory") {
        const source = await tx.query(
          `SELECT scope, type, confidence FROM memory_objects
           WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL`,
          [input.origin.ref],
        );
        if (source.rows.length === 0) throw new SharingValidationError("mounted origin is unavailable");
        const row = source.rows[0] as Record<string, unknown>;
        inherited = {
          scope: row.scope as Scope,
          type: row.type as MemoryType,
          confidence: Number(row.confidence),
        };
      }

      for (const namespace of writeFenceNamespaces(input.targetNamespace)) {
        await acquireErasureFence(tx, namespace);
      }
      const targetMemoryId = ulid();
      const forkId = ulid();
      const now = new Date().toISOString();
      await tx.query(
        `INSERT INTO memory_objects
           (id, namespace, scope, tier, backend_ref, content, type, confidence,
            event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
            provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
         VALUES ($1, $2, $3, 'L2', $4, $5, $6, $7,
                 NULL, $8, $8, NULL, NULL, $9, NULL, NULL, 0, 0, 'active', $10::vector)`,
        [
          targetMemoryId,
          input.targetNamespace,
          input.scope ?? inherited.scope,
          `fork:${input.origin.kind}:${input.origin.ref}`,
          input.content,
          input.type ?? inherited.type,
          input.confidence ?? inherited.confidence,
          now,
          JSON.stringify([{ source: "manual", actor: identity.actor, ts: now }]),
          vectorLiteral(input.embedding),
        ],
      );
      await tx.query(
        `INSERT INTO memory_forks
           (id, origin_kind, origin_ref, target_memory_id, target_namespace, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [forkId, input.origin.kind, input.origin.ref, targetMemoryId, input.targetNamespace, now],
      );
      await this.successAudit(tx, identity, "share:fork", targetMemoryId, `fork=${forkId}`, now);
      return {
        id: forkId,
        origin: input.origin,
        targetMemoryId,
        targetNamespace: input.targetNamespace,
        createdAt: now,
      };
    }).catch(async (error: unknown) => {
      if (error instanceof SharingAuthorizationError) {
        return this.denied(identity, "share:fork", error.message);
      }
      throw error;
    });
  }

  /** Lock the granting mount so revoke and fork have a single commit order. */
  private async lockActiveMount(tx: Db, callerNamespace: string, origin: PinTarget): Promise<boolean> {
    const targets = namespaceAncestors(callerNamespace);
    const placeholders = targets.map((_, index) => `$${index + 3}`).join(", ");
    const selected = await tx.query(
      `SELECT sm.id
       FROM segment_mounts sm
       JOIN memory_segments segment ON segment.id = sm.segment_id
       JOIN segment_members member ON member.segment_id = segment.id
       WHERE member.target_kind = $1 AND member.target_ref = $2
         AND sm.target_namespace IN (${placeholders})
         AND sm.revoked_at IS NULL AND segment.status = 'active' AND member.removed_at IS NULL
         AND (
           ($1 = 'memory' AND EXISTS (
             SELECT 1 FROM memory_objects mo WHERE mo.id = $2
               AND mo.status = 'active' AND mo.t_valid_to IS NULL
               AND (mo.ttl_seconds IS NULL OR mo.assertion_time + mo.ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)
           ))
           OR
           ($1 = 'concept' AND EXISTS (
             SELECT 1 FROM knowledge_concepts kc
             JOIN knowledge_versions kv ON kv.id = kc.current_version_id
             WHERE kc.id = $2 AND kc.status = 'active' AND kv.state = 'published'
           ))
         )
       ORDER BY sm.created_at
       LIMIT 1
       FOR UPDATE OF sm`,
      [origin.kind, origin.ref, ...targets],
    );
    return selected.rows.length > 0;
  }

  private async lockSegment(tx: Db, id: string): Promise<MemorySegment | null> {
    const selected = await tx.query(`SELECT * FROM memory_segments WHERE id = $1 FOR UPDATE`, [id]);
    return selected.rows.length === 0
      ? null
      : rowToSegment(selected.rows[0] as Record<string, unknown>);
  }

  private async targetNamespace(tx: Db, target: PinTarget): Promise<string | null> {
    const selected = target.kind === "memory"
      ? await tx.query(
          `SELECT namespace FROM memory_objects
           WHERE id = $1 AND status = 'active' AND t_valid_to IS NULL
             AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP)`,
          [target.ref],
        )
      : await tx.query(
          `SELECT kc.namespace FROM knowledge_concepts kc
           JOIN knowledge_versions kv ON kv.id = kc.current_version_id
           WHERE kc.id = $1 AND kc.status = 'active' AND kv.state = 'published'`,
          [target.ref],
        );
    return selected.rows.length === 0
      ? null
      : ((selected.rows[0] as Record<string, unknown>).namespace as string);
  }

  private async successAudit(
    tx: Db,
    identity: Identity,
    purpose: string,
    memoryId: string | null,
    detail: string,
    ts: string,
  ): Promise<void> {
    await this.audit.appendTo(tx, {
      ts,
      actor: identity.actor,
      agentId: identity.keyId,
      op: "share",
      memoryId,
      namespace: identity.namespace,
      purpose,
      result: "ok",
      detail,
    });
  }

  private async denied<T>(identity: Identity, purpose: string, detail: string): Promise<T> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "share",
      memoryId: null,
      namespace: identity.namespace,
      purpose,
      result: "denied",
      detail,
    });
    throw new SharingAuthorizationError(detail);
  }

  /** Persist a bounded D4 failure outcome without leaking target or provider details. */
  private async shareFailure<T>(
    identity: Identity,
    result: "denied" | "error",
    detail: "target_ref_not_stable" | "target_unavailable" | "share_failed",
    original: unknown,
  ): Promise<T> {
    try {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "share",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "share",
        result,
        detail,
      });
    } catch (auditError) {
      throw new AggregateError(
        [original, auditError],
        "share failed and its failure audit could not be persisted",
      );
    }
    throw original;
  }
}
