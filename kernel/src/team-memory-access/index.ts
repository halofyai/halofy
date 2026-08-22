/** Server-owned per-team visibility policy for company-published memory. */

import type { AuditLog } from "../audit/index.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import type { Db } from "../db/client.js";
import type {
  Identity,
  Namespace,
  TeamMemoryAccessMode,
  TeamMemoryAccessView,
  TeamMemoryReadGrant,
} from "../types.js";

const AGENT_ID = "console";

interface TeamPolicyRow {
  id: string;
  namespace: string;
  organization_namespace: string;
  memory_access_mode: string;
  memory_access_version: number | string;
}

export class TeamMemoryAccessBadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

export function isTeamMemoryAccessMode(value: unknown): value is TeamMemoryAccessMode {
  return value === "related" || value === "company-published";
}

/**
 * The organization roots a PLATFORM-root (namespace "") action could attach
 * to. Root is not itself an organization, so anything it creates must name
 * one: zero tenants means a fresh install (nothing to attach to yet), one is
 * the unambiguous target, and two or more means the caller has to say which —
 * a guessed prefix would file data into the wrong org. Capped at 2 rows: the
 * callers only distinguish none / one / many.
 */
export async function tenantRoots(db: Db): Promise<Namespace[]> {
  const res = await db.query(`SELECT id FROM tenants ORDER BY id LIMIT 2`);
  return (res.rows as { id: string }[]).map((r) => r.id);
}

/** Exact tenant root for newly-created teams; never supplied by a request. */
export async function resolveOrganizationNamespace(
  db: Db,
  teamNamespace: Namespace,
): Promise<Namespace> {
  const first = teamNamespace.split("/").filter(Boolean)[0] ?? "";
  if (first !== "") {
    const tenant = await db.query(`SELECT id FROM tenants WHERE id = $1`, [first]);
    if (tenant.rows.length > 0) return first;
  }
  return teamNamespace.includes("/") ? first : "";
}

function permissions(identity: Identity, row: TeamPolicyRow): {
  canBroaden: boolean;
  canTighten: boolean;
} {
  const mutable = identity.role === "owner" || identity.role === "admin";
  const organizationAuthority = isRootOwner(identity) ||
    identity.namespace === row.organization_namespace;
  const teamAuthority = isSelfOrDescendant(row.namespace, identity.namespace);
  return {
    canBroaden: mutable && organizationAuthority,
    canTighten: mutable && (organizationAuthority || teamAuthority),
  };
}

function view(identity: Identity, row: TeamPolicyRow): TeamMemoryAccessView {
  const mode = isTeamMemoryAccessMode(row.memory_access_mode)
    ? row.memory_access_mode
    : "related";
  const version = Number(row.memory_access_version);
  return {
    mode,
    version: Number.isSafeInteger(version) && version > 0 ? version : 1,
    ...permissions(identity, row),
  };
}

function namespaceAncestors(namespace: Namespace): Namespace[] {
  const parts = namespace.split("/").filter(Boolean);
  const ancestors = parts.map((_, index) => parts.slice(0, index + 1).join("/"));
  return ancestors.length > 0 ? ancestors : [namespace];
}

export class TeamMemoryAccessPolicy {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
  ) {}

  accessView(identity: Identity, row: TeamPolicyRow): TeamMemoryAccessView {
    return view(identity, row);
  }

  private async auditDenied(
    identity: Identity,
    namespace: Namespace,
    detail: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace,
      purpose: "console-team-memory-access",
      result: "denied",
      detail,
    });
  }

  async resolve(identity: Identity): Promise<TeamMemoryReadGrant | null> {
    const ancestors = namespaceAncestors(identity.namespace);
    const placeholders = ancestors.map((_, index) => `$${index + 1}`).join(", ");
    const result = await this.db.query(
      `SELECT id, namespace, organization_namespace, memory_access_mode,
              memory_access_version
         FROM org_teams
        WHERE namespace IN (${placeholders})
        ORDER BY length(namespace) DESC
        LIMIT 1`,
      ancestors,
    );
    const row = result.rows[0] as unknown as TeamPolicyRow | undefined;
    if (!row || row.memory_access_mode !== "company-published") return null;
    const version = Number(row.memory_access_version);
    if (!Number.isSafeInteger(version) || version <= 0) return null;
    return { teamId: row.id, version };
  }

  async isCurrent(grant: TeamMemoryReadGrant): Promise<boolean> {
    const result = await this.db.query(
      `SELECT 1 FROM org_teams
        WHERE id = $1
          AND memory_access_mode = 'company-published'
          AND memory_access_version = $2`,
      [grant.teamId, grant.version],
    );
    return result.rows.length === 1;
  }

  async change(
    identity: Identity,
    teamId: string,
    mode: TeamMemoryAccessMode,
  ): Promise<TeamMemoryAccessView> {
    if (!isTeamMemoryAccessMode(mode)) {
      await this.auditDenied(identity, identity.namespace, "invalid team memory access mode");
      throw new TeamMemoryAccessBadRequestError("invalid team memory access mode");
    }
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditDenied(identity, identity.namespace, `role '${identity.role}' denied`);
      throw new AuthzError(`role '${identity.role}' may not change team memory access`);
    }

    // Authorize before opening the write transaction so a denial audit is
    // durable rather than rolled back with the rejected mutation.
    const result = await this.db.query(
      `SELECT id, namespace, organization_namespace, memory_access_mode,
              memory_access_version
         FROM org_teams WHERE id = $1`,
      [teamId],
    );
    const row = result.rows[0] as unknown as TeamPolicyRow | undefined;
    const visible = row && (isRootOwner(identity) ||
      identity.namespace === row.organization_namespace ||
      isSelfOrDescendant(row.namespace, identity.namespace));
    if (!row || !visible) {
      await this.auditDenied(identity, identity.namespace, "team memory access target unavailable");
      throw new TeamMemoryAccessBadRequestError(`no team with id '${teamId}'`);
    }

    const current = view(identity, row);
    const allowed = mode === "company-published"
      ? current.canBroaden
      : current.canTighten;
    if (!allowed) {
      await this.auditDenied(
        identity,
        row.namespace,
        "organization authority is required to broaden team memory access",
      );
      throw new AuthzError("organization authority is required to broaden team memory access");
    }
    if (current.mode === mode) return current;

    return this.db.transaction(async (tx) => {
      const locked = await tx.query(
        `SELECT id, namespace, organization_namespace, memory_access_mode,
                memory_access_version
           FROM org_teams WHERE id = $1 FOR UPDATE`,
        [teamId],
      );
      const lockedRow = locked.rows[0] as unknown as TeamPolicyRow | undefined;
      if (!lockedRow) throw new Error("team memory access changed concurrently");
      const lockedCurrent = view(identity, lockedRow);
      if (lockedCurrent.mode === mode) return lockedCurrent;

      const updatedAt = new Date().toISOString();
      const updated = await tx.query(
        `UPDATE org_teams
            SET memory_access_mode = $2,
                memory_access_version = memory_access_version + 1,
                memory_access_updated_by = $3,
                memory_access_updated_at = $4
          WHERE id = $1 AND memory_access_version = $5
          RETURNING id, namespace, organization_namespace, memory_access_mode,
                    memory_access_version`,
        [lockedRow.id, mode, identity.actor, updatedAt, lockedCurrent.version],
      );
      const next = updated.rows[0] as unknown as TeamPolicyRow | undefined;
      if (!next) throw new Error("team memory access changed concurrently");

      await this.audit.appendTo(tx, {
        ts: updatedAt,
        actor: identity.actor,
        agentId: AGENT_ID,
        op: "write",
        memoryId: null,
        namespace: lockedRow.namespace,
        purpose: "console-team-memory-access",
        result: "ok",
        detail: `${lockedCurrent.mode} -> ${mode}; version=${Number(next.memory_access_version)}`,
      });
      return view(identity, next);
    });
  }
}
