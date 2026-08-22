/**
 * M10 grants module (CONTRACTS-M10-ACCESS.md) — the `access_grants`
 * repository.
 *
 * Grants are keyed by OPAQUE server-owned resource IDs. The mapping from a
 * resource ID to its namespace root lives server-side in the
 * `namespace_root` column, populated only by kernel code — no caller-supplied
 * namespace string ever crosses this API from a request (D9). Revocation
 * sets `revoked_at`; rows are never deleted or overwritten (D7/D47). Every
 * mutation appends a D4 audit event through the injected audit sink, inside
 * the SAME transaction as the state change.
 *
 * Integrator seam (one permission system, CONTRACTS-M10-ACCESS.md wiring):
 * `src/console/teams.ts` already wraps membership changes in
 * `slice.db.transaction(tx => ...)`:
 *   - `addTeamMember` (INSERT INTO org_team_members): call
 *     `store.syncMembershipGrant(tx, { tenantId, userId: user.id,
 *     teamOrFunctionId: team.id, action: "add", actor: identity.actor })`
 *     in that same tx.
 *   - `removeTeamMember` (DELETE FROM org_team_members): same call with
 *     `action: "remove"`.
 *   - `inviteTeamMember` delegates to `invitations.create`, so the grant is
 *     created where invitation ACCEPTANCE creates the user row.
 * A throw anywhere rolls back BOTH the roster row and the grant — roster and
 * grants can never drift.
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import type { AccessGrantRecord, AuditEvent, Namespace } from "../types.js";

const AGENT_ID = "access-grants";

/** Structural audit dep — `AuditLog` satisfies it (`appendTo`). */
export interface AccessGrantAuditSink {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface AccessGrantStoreDeps {
  db: Db;
  audit: AccessGrantAuditSink;
  /** Injectable clock (tests); defaults to the wall clock. */
  now?: () => Date;
  /** Injectable ID mint (tests); defaults to `ulid()`. */
  newId?: () => string;
}

/**
 * A stored grant row. Extends the scaffold-owned wire record with the
 * server-side `namespaceRoot` mapping — this field is for kernel-internal
 * authorization only and must NEVER be serialized to a client.
 */
export interface StoredAccessGrant extends AccessGrantRecord {
  namespaceRoot: Namespace;
}

/**
 * Server-resolved creation input. `namespaceRoot` is populated by kernel
 * code from an opaque resource ID (team/user/tenant lookup) — never copied
 * from a request body (D9).
 */
export interface CreateGrantInput {
  tenantId: string;
  principalType: AccessGrantRecord["principalType"];
  principalId: string;
  resourceType: AccessGrantRecord["resourceType"];
  resourceId: string;
  /** Server-resolved namespace root for the resource (D9). */
  namespaceRoot: Namespace;
  accessMode: AccessGrantRecord["accessMode"];
  source: AccessGrantRecord["source"];
  createdBy: string;
  expiresAt?: string | null;
}

export interface RevokeGrantInput {
  tenantId: string;
  grantId: string;
  /** Server-resolved actor for the D4 audit row. */
  actor: string;
}

export interface MembershipGrantSyncInput {
  tenantId: string;
  userId: string;
  /** Opaque functional-area ID — today, an `org_teams.id`. */
  teamOrFunctionId: string;
  action: "add" | "remove" | "update";
  /** Server-resolved actor (e.g. `identity.actor` at the teams.ts seam). */
  actor: string;
  /**
   * Grant mode for `add`/`update`, derived server-side from the member's
   * INTERNAL role at the seam (owner/admin -> govern, member/auditor ->
   * consume). Defaults to consume. PRD §11: the roster is the one
   * transactional source of functional grants — a roster role change must
   * re-sync the grant mode in the same tx, or roles and grants drift.
   */
  accessMode?: "consume" | "govern";
}

/** `''` is the platform root and contains every namespace. */
function withinTenant(ns: string, tenantId: string): boolean {
  return tenantId === "" || ns === tenantId || ns.startsWith(tenantId + "/");
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

interface GrantRow {
  id: string;
  tenant_id: string;
  principal_type: string;
  principal_id: string;
  resource_type: string;
  resource_id: string;
  namespace_root: string;
  access_mode: string;
  source: string;
  created_by: string;
  created_at: Date | string;
  expires_at: Date | string | null;
  revoked_at: Date | string | null;
}

function rowToGrant(r: unknown): StoredAccessGrant {
  const row = r as GrantRow;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    principalType: row.principal_type as AccessGrantRecord["principalType"],
    principalId: row.principal_id,
    resourceType: row.resource_type as AccessGrantRecord["resourceType"],
    resourceId: row.resource_id,
    namespaceRoot: row.namespace_root,
    accessMode: row.access_mode as AccessGrantRecord["accessMode"],
    source: row.source as AccessGrantRecord["source"],
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    expiresAt: toIsoOrNull(row.expires_at),
    revokedAt: toIsoOrNull(row.revoked_at),
  };
}

const GRANT_COLUMNS = `id, tenant_id, principal_type, principal_id, resource_type,
       resource_id, namespace_root, access_mode, source, created_by,
       created_at, expires_at, revoked_at`;

export class AccessGrantStore {
  private readonly db: Db;
  private readonly audit: AccessGrantAuditSink;
  private readonly now: () => Date;
  private readonly newId: () => string;

  constructor(deps: AccessGrantStoreDeps) {
    this.db = deps.db;
    this.audit = deps.audit;
    this.now = deps.now ?? (() => new Date());
    this.newId = deps.newId ?? (() => ulid());
  }

  /** Insert + D4 audit atomically in a fresh transaction. */
  async createGrant(input: CreateGrantInput): Promise<StoredAccessGrant> {
    return await this.db.transaction((tx) => this.createGrantIn(tx, input));
  }

  /**
   * Insert + D4 audit through a caller-supplied transaction handle, for
   * callers (membership sync, invitation acceptance) whose grant must commit
   * or roll back with a sibling state change.
   */
  async createGrantIn(tx: Db, input: CreateGrantInput): Promise<StoredAccessGrant> {
    const id = this.newId();
    const ts = this.now().toISOString();
    await tx.query(
      `INSERT INTO access_grants
         (id, tenant_id, principal_type, principal_id, resource_type,
          resource_id, namespace_root, access_mode, source, created_by,
          created_at, expires_at, revoked_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL)`,
      [
        id,
        input.tenantId,
        input.principalType,
        input.principalId,
        input.resourceType,
        input.resourceId,
        input.namespaceRoot,
        input.accessMode,
        input.source,
        input.createdBy,
        ts,
        input.expiresAt ?? null,
      ],
    );
    await this.audit.appendTo(tx, {
      ts,
      actor: input.createdBy,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: input.namespaceRoot,
      purpose: "grant.create",
      result: "ok",
      detail:
        `grant ${id}: ${input.accessMode} ${input.principalType}:${input.principalId}` +
        ` -> ${input.resourceType}:${input.resourceId} (tenant '${input.tenantId}',` +
        ` source ${input.source})`,
    });
    return {
      id,
      tenantId: input.tenantId,
      principalType: input.principalType,
      principalId: input.principalId,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      namespaceRoot: input.namespaceRoot,
      accessMode: input.accessMode,
      source: input.source,
      createdBy: input.createdBy,
      createdAt: ts,
      expiresAt: input.expiresAt ?? null,
      revokedAt: null,
    };
  }

  /**
   * Revocation is a row state — sets `revoked_at`, never DELETE (D7/D47).
   * Tenant-bound: a grant outside `tenantId` is indistinguishable from a
   * nonexistent one (uniform miss, D46). Both outcomes audit (D4).
   */
  async revokeGrant(input: RevokeGrantInput): Promise<StoredAccessGrant | null> {
    return await this.db.transaction((tx) => this.revokeGrantIn(tx, input));
  }

  /** Transaction-scoped twin of {@link revokeGrant}. */
  async revokeGrantIn(tx: Db, input: RevokeGrantInput): Promise<StoredAccessGrant | null> {
    const ts = this.now().toISOString();
    const res = await tx.query(
      `UPDATE access_grants
          SET revoked_at = $1
        WHERE id = $2 AND tenant_id = $3 AND revoked_at IS NULL
        RETURNING ${GRANT_COLUMNS}`,
      [ts, input.grantId, input.tenantId],
    );
    const row = res.rows[0];
    if (row === undefined) {
      // Unknown, foreign-tenant, and already-revoked are one uniform miss —
      // the denial detail never names a hidden target (D46).
      await this.audit.appendTo(tx, {
        ts,
        actor: input.actor,
        agentId: AGENT_ID,
        op: "write",
        memoryId: null,
        namespace: input.tenantId,
        purpose: "grant.revoke",
        result: "miss",
        detail: `no active grant '${input.grantId}'`,
      });
      return null;
    }
    const grant = rowToGrant(row);
    await this.audit.appendTo(tx, {
      ts,
      actor: input.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: grant.namespaceRoot,
      purpose: "grant.revoke",
      result: "ok",
      detail:
        `grant ${grant.id}: revoked ${grant.accessMode} ` +
        `${grant.principalType}:${grant.principalId} -> ` +
        `${grant.resourceType}:${grant.resourceId} (tenant '${grant.tenantId}')`,
    });
    return grant;
  }

  /**
   * Grants currently in force for a principal: not revoked, not expired at
   * the caller-supplied `now` (injected — never the wall clock implicitly).
   */
  async listEffectiveGrants(
    tenantId: string,
    principalId: string,
    now: Date,
  ): Promise<StoredAccessGrant[]> {
    const res = await this.db.query(
      `SELECT ${GRANT_COLUMNS}
         FROM access_grants
        WHERE tenant_id = $1
          AND principal_id = $2
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > $3)
        ORDER BY created_at, id`,
      [tenantId, principalId, now.toISOString()],
    );
    return res.rows.map(rowToGrant);
  }

  /**
   * Re-resolve opaque resource IDs to namespace roots INSIDE `tenantId`.
   * Sources: the server-populated `namespace_root` mapping on grant rows,
   * plus `org_teams` (functional areas are namespace-backed teams). Foreign-
   * tenant and unknown IDs are silently dropped — no existence oracle (D46).
   * Exact `IN (...)` lists and plain string comparison only — `_`, `%`, `\`
   * in namespaces are always literal.
   */
  async resolveResourceRoots(
    tenantId: string,
    resourceIds: readonly string[],
  ): Promise<Map<string, Namespace>> {
    const roots = new Map<string, Namespace>();
    const ids = [...new Set(resourceIds)].filter((id) => id.length > 0);
    if (ids.length === 0) return roots;

    const teamPlaceholders = ids.map((_, i) => `$${i + 1}`).join(", ");
    const teams = await this.db.query(
      `SELECT id, namespace FROM org_teams WHERE id IN (${teamPlaceholders})`,
      [...ids],
    );
    for (const raw of teams.rows) {
      const row = raw as { id: string; namespace: string };
      if (withinTenant(row.namespace, tenantId)) roots.set(row.id, row.namespace);
    }

    const grantPlaceholders = ids.map((_, i) => `$${i + 2}`).join(", ");
    const grants = await this.db.query(
      `SELECT DISTINCT resource_id, namespace_root
         FROM access_grants
        WHERE tenant_id = $1 AND resource_id IN (${grantPlaceholders})`,
      [tenantId, ...ids],
    );
    for (const raw of grants.rows) {
      const row = raw as { resource_id: string; namespace_root: string };
      if (withinTenant(row.namespace_root, tenantId)) {
        roots.set(row.resource_id, row.namespace_root);
      }
    }
    return roots;
  }

  /**
   * Membership <-> grant sync, designed to run INSIDE the same transaction
   * as the `org_team_members` change (teams.ts seam in the module header).
   * The namespace root is resolved server-side from `org_teams` in the same
   * tx — the caller never supplies it (D9). An unknown or foreign-tenant
   * area throws, rolling back the roster change with the grant (one
   * permission system — never drift).
   */
  async syncMembershipGrant(tx: Db, input: MembershipGrantSyncInput): Promise<void> {
    const res = await tx.query(
      `SELECT id, namespace FROM org_teams WHERE id = $1`,
      [input.teamOrFunctionId],
    );
    const team = res.rows[0] as { id: string; namespace: string } | undefined;
    if (team === undefined || !withinTenant(team.namespace, input.tenantId)) {
      throw new Error(`no functional area '${input.teamOrFunctionId}' in tenant`);
    }

    if (input.action === "add" || input.action === "update") {
      const mode = input.accessMode ?? "consume";
      const existing = await tx.query(
        `SELECT id, access_mode FROM access_grants
          WHERE tenant_id = $1 AND principal_type = 'human' AND principal_id = $2
            AND resource_type = 'function' AND resource_id = $3
            AND source = 'membership' AND revoked_at IS NULL`,
        [input.tenantId, input.userId, team.id],
      );
      const current = existing.rows[0] as { id: string; access_mode: string } | undefined;
      if (current !== undefined && current.access_mode === mode) return; // idempotent
      if (current !== undefined) {
        // Mode change (roster role change): revoke the old row and mint the
        // new one in the same tx — a row state, never an in-place mutation
        // (D7/D47). `update` on an absent grant falls through to a plain add.
        const ts = this.now().toISOString();
        await tx.query(
          `UPDATE access_grants SET revoked_at = $1 WHERE id = $2`,
          [ts, current.id],
        );
        await this.audit.appendTo(tx, {
          ts,
          actor: input.actor,
          agentId: AGENT_ID,
          op: "write",
          memoryId: null,
          namespace: team.namespace,
          purpose: "grant.revoke",
          result: "ok",
          detail:
            `membership grant sync: mode change human:${input.userId} -> ` +
            `function:${team.id} ('${current.access_mode}' revoked, ` +
            `'${mode}' follows in-tx)`,
        });
      }
      await this.createGrantIn(tx, {
        tenantId: input.tenantId,
        principalType: "human",
        principalId: input.userId,
        resourceType: "function",
        resourceId: team.id,
        namespaceRoot: team.namespace,
        accessMode: mode,
        source: "membership",
        createdBy: input.actor,
      });
      return;
    }

    const ts = this.now().toISOString();
    const revoked = await tx.query(
      `UPDATE access_grants
          SET revoked_at = $1
        WHERE tenant_id = $2 AND principal_type = 'human' AND principal_id = $3
          AND resource_type = 'function' AND resource_id = $4
          AND source = 'membership' AND revoked_at IS NULL
        RETURNING id`,
      [ts, input.tenantId, input.userId, team.id],
    );
    await this.audit.appendTo(tx, {
      ts,
      actor: input.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: team.namespace,
      purpose: "grant.revoke",
      result: revoked.rows.length > 0 ? "ok" : "miss",
      detail:
        `membership grant sync: remove human:${input.userId} -> ` +
        `function:${team.id} (tenant '${input.tenantId}', ` +
        `${revoked.rows.length} revoked)`,
    });
  }

  /**
   * D41 auditor helper: an internal `auditor` human surfaces at the product
   * boundary as `member` PLUS a scoped `audit_read` entitlement — this
   * ensures that entitlement row exists. Idempotent on an active grant.
   * Runs through the caller's handle so it can join a wider transaction.
   */
  async ensureAuditReadGrant(
    tx: Db,
    input: { tenantId: string; userId: string; actor: string },
  ): Promise<StoredAccessGrant | null> {
    const existing = await tx.query(
      `SELECT id FROM access_grants
        WHERE tenant_id = $1 AND principal_type = 'human' AND principal_id = $2
          AND resource_type = 'audit' AND access_mode = 'audit_read'
          AND revoked_at IS NULL`,
      [input.tenantId, input.userId],
    );
    if (existing.rows.length > 0) return null;
    return await this.createGrantIn(tx, {
      tenantId: input.tenantId,
      principalType: "human",
      principalId: input.userId,
      resourceType: "audit",
      resourceId: "audit",
      namespaceRoot: input.tenantId,
      accessMode: "audit_read",
      source: "system",
      createdBy: input.actor,
    });
  }
}
