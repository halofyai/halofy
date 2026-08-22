/**
 * Durable immutable authority snapshots for the M8 agent gateway.
 *
 * This store owns persistence only. Callers pass a server-resolved
 * administrative namespace; untrusted agent payloads must never reach these
 * methods. Every durable JSON value is validated again on read so corrupt or
 * legacy rows fail closed instead of becoming authority.
 */

import type { Db } from "../db/client.js";
import { escapeLikePattern } from "../db/client.js";
import type {
  AgentConnectionGrant,
  AgentConnectionGrantHistoryMetadata,
  AgentGatewayOperation,
  GatewayAdministrativeIdentity,
  GatewayOversightViewerIdentity,
} from "./contracts.js";
import {
  validateAgentConnectionGrant,
  validateAgentConnectionOversight,
} from "./policy.js";

const GRANT_COLUMNS = `
  id, key_id, namespace, connector_id, allowed_operations, allowed_source_refs,
  allowed_fields, allowed_purposes, max_sensitivity, max_rows, max_bytes,
  policy_version, status, expires_at, oversight`;

const QUALIFIED_GRANT_COLUMNS = `
  g.id, g.key_id, g.namespace, g.connector_id, g.allowed_operations,
  g.allowed_source_refs, g.allowed_fields, g.allowed_purposes,
  g.max_sensitivity, g.max_rows, g.max_bytes, g.policy_version, g.status,
  g.expires_at, g.oversight`;

export class InvalidAgentConnectionGrantError extends Error {
  constructor(message = "invalid agent connection grant") {
    super(message);
    this.name = "InvalidAgentConnectionGrantError";
  }
}

export class AgentConnectionGrantScopeError extends Error {
  constructor(message = "agent connection grant is outside administrative scope") {
    super(message);
    this.name = "AgentConnectionGrantScopeError";
  }
}

function administrativeNamespace(identity: GatewayAdministrativeIdentity): string {
  if (identity.role !== "owner" && identity.role !== "admin") {
    throw new AgentConnectionGrantScopeError();
  }
  if (identity.namespace === "" && identity.role !== "owner") {
    throw new AgentConnectionGrantScopeError("only a root owner has global grant authority");
  }
  return identity.namespace;
}

function oversightViewerNamespace(identity: GatewayOversightViewerIdentity): string {
  if (
    identity.role !== "owner" &&
    identity.role !== "admin" &&
    identity.role !== "auditor"
  ) {
    throw new AgentConnectionGrantScopeError();
  }
  if (identity.namespace === "" && identity.role === "admin") {
    throw new AgentConnectionGrantScopeError("a root admin has no global grant visibility");
  }
  return identity.namespace;
}

function isInSubtree(namespace: string, administrator: GatewayAdministrativeIdentity): boolean {
  const scope = administrativeNamespace(administrator);
  return scope === "" || namespace === scope || namespace.startsWith(`${scope}/`);
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new InvalidAgentConnectionGrantError("invalid agent connection grant JSON");
  }
}

function asIsoOrNull(value: unknown): string | null | unknown {
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  return value;
}

function rowToGrant(value: unknown): AgentConnectionGrant {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidAgentConnectionGrantError();
  }
  const row = value as Record<string, unknown>;
  const candidate = {
    id: row.id,
    keyId: row.key_id,
    namespace: row.namespace,
    connectorId: row.connector_id,
    allowedOperations: parseJson(row.allowed_operations),
    allowedSourceRefs: parseJson(row.allowed_source_refs),
    allowedFields: parseJson(row.allowed_fields),
    allowedPurposes: parseJson(row.allowed_purposes),
    maxSensitivity: row.max_sensitivity,
    maxRows: row.max_rows,
    maxBytes: row.max_bytes,
    policyVersion: row.policy_version,
    status: row.status,
    expiresAt: asIsoOrNull(row.expires_at),
    oversight: parseJson(row.oversight),
  };
  if (!validateAgentConnectionGrant(candidate)) {
    throw new InvalidAgentConnectionGrantError();
  }
  return candidate;
}

export class AgentConnectionGrantStore {
  constructor(private readonly db: Db) {}

  /** Create one immutable active snapshot inside the administrator's subtree. */
  async create(
    grant: AgentConnectionGrant,
    administrator: GatewayAdministrativeIdentity,
  ): Promise<AgentConnectionGrant> {
    if (!validateAgentConnectionGrant(grant)) {
      throw new InvalidAgentConnectionGrantError();
    }
    if (grant.status !== "active") {
      throw new InvalidAgentConnectionGrantError("new agent connection grants must be active");
    }
    if (!isInSubtree(grant.namespace, administrator)) {
      throw new AgentConnectionGrantScopeError();
    }

    const createdAt = new Date().toISOString();
    const result = await this.db.query(
      `INSERT INTO agent_connection_grants
         (id, key_id, namespace, connector_id, allowed_operations,
          allowed_source_refs, allowed_fields, allowed_purposes,
          max_sensitivity, max_rows, max_bytes, policy_version, status,
          expires_at, oversight, created_at, revoked_at)
       SELECT $1, k.id, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb,
              $9, $10, $11, $12, 'active', $13, $14::jsonb, $15, NULL
         FROM api_keys k
         JOIN sources s ON s.id = $4
          AND (s.namespace = $3 OR left($3, length(s.namespace) + 1) = s.namespace || '/')
        WHERE k.id = $2 AND k.namespace = $3 AND k.status = 'active' AND k.role = 'agent'
       RETURNING ${GRANT_COLUMNS}`,
      [
        grant.id,
        grant.keyId,
        grant.namespace,
        grant.connectorId,
        JSON.stringify(grant.allowedOperations),
        JSON.stringify(grant.allowedSourceRefs),
        JSON.stringify(grant.allowedFields),
        JSON.stringify(grant.allowedPurposes),
        grant.maxSensitivity,
        grant.maxRows,
        grant.maxBytes,
        grant.policyVersion,
        grant.expiresAt,
        JSON.stringify(grant.oversight),
        createdAt,
      ],
    );
    if (result.rows.length !== 1) {
      throw new InvalidAgentConnectionGrantError(
        "agent connection grant badge binding is inactive or has a different namespace",
      );
    }
    return rowToGrant(result.rows[0]);
  }

  /** Resolve only an active, unexpired grant for this exact active badge. */
  async getForKey(id: string, keyId: string): Promise<AgentConnectionGrant | null> {
    const result = await this.db.query(
      `SELECT ${QUALIFIED_GRANT_COLUMNS}
         FROM agent_connection_grants g
         JOIN api_keys k ON k.id = g.key_id AND k.status = 'active'
          AND k.namespace = g.namespace AND k.role = 'agent'
        WHERE g.id = $1
          AND g.key_id = $2
          AND g.status = 'active'
          AND (g.expires_at IS NULL OR g.expires_at > CURRENT_TIMESTAMP)`,
      [id, keyId],
    );
    return result.rows.length === 1 ? rowToGrant(result.rows[0]) : null;
  }

  /**
   * Read content-free metadata for alert attribution after revoke/expiry.
   * This deliberately omits every authority allowlist and must never be used
   * to authorize a request.
   */
  async getHistoricalMetadataForKey(
    id: string,
    keyId: string,
  ): Promise<AgentConnectionGrantHistoryMetadata | null> {
    const result = await this.db.query(
      `SELECT id, key_id, namespace, connector_id, policy_version, status,
              expires_at, oversight
         FROM agent_connection_grants
        WHERE id = $1 AND key_id = $2`,
      [id, keyId],
    );
    if (result.rows.length !== 1) return null;
    const row = result.rows[0] as Record<string, unknown>;
    const oversight = parseJson(row.oversight);
    const expiresAt = asIsoOrNull(row.expires_at);
    if (
      typeof row.id !== "string" || row.id.length === 0 ||
      typeof row.key_id !== "string" || row.key_id.length === 0 ||
      typeof row.namespace !== "string" || row.namespace.length === 0 ||
      typeof row.connector_id !== "string" || row.connector_id.length === 0 ||
      typeof row.policy_version !== "number" ||
      !Number.isSafeInteger(row.policy_version) || row.policy_version <= 0 ||
      (row.status !== "active" && row.status !== "revoked") ||
      (expiresAt !== null && typeof expiresAt !== "string") ||
      !validateAgentConnectionOversight(oversight)
    ) {
      throw new InvalidAgentConnectionGrantError("invalid historical grant metadata");
    }
    return {
      id: row.id,
      keyId: row.key_id,
      namespace: row.namespace,
      connectorId: row.connector_id,
      policyVersion: Number(row.policy_version),
      status: row.status,
      expiresAt,
      oversight,
    };
  }

  /**
   * Return whether a badge has any active grant and whether one of those
   * grants explicitly allows an operation. Local memory calls remain
   * backwards-compatible when no M8 grant exists; once an organization opts
   * a badge into grants, every named operation is fail-closed.
   */
  async operationStatus(
    keyId: string,
    operation: AgentGatewayOperation,
  ): Promise<{ hasGrant: boolean; allowed: boolean }> {
    const result = await this.db.query(
      `SELECT ${QUALIFIED_GRANT_COLUMNS}
         FROM agent_connection_grants g
         JOIN api_keys k ON k.id = g.key_id AND k.status = 'active'
          AND k.namespace = g.namespace AND k.role = 'agent'
        WHERE g.key_id = $1`,
      [keyId],
    );
    const grants = result.rows.map((row) => rowToGrant(row));
    const now = Date.now();
    return {
      hasGrant: grants.length > 0,
      allowed: grants.some((grant) =>
        grant.status === "active" &&
        (grant.expiresAt === null || Date.parse(grant.expiresAt) > now) &&
        grant.allowedOperations.includes(operation)),
    };
  }

  /**
   * List the caller badge's own active, unexpired grants — the full authority
   * rows behind `describe_access`. A badge only ever sees grants bound to its
   * own still-active key; revoked, expired, and sibling-badge grants never
   * appear. Same query shape as `operationStatus`.
   */
  async listActiveForKey(keyId: string): Promise<AgentConnectionGrant[]> {
    const result = await this.db.query(
      `SELECT ${QUALIFIED_GRANT_COLUMNS}
         FROM agent_connection_grants g
         JOIN api_keys k ON k.id = g.key_id AND k.status = 'active'
          AND k.namespace = g.namespace AND k.role = 'agent'
        WHERE g.key_id = $1
          AND g.status = 'active'
          AND (g.expires_at IS NULL OR g.expires_at > CURRENT_TIMESTAMP)
        ORDER BY g.id`,
      [keyId],
    );
    return result.rows.map((row) => rowToGrant(row));
  }

  /** List immutable history in exactly one administrative namespace subtree. */
  async listSubtree(viewer: GatewayOversightViewerIdentity): Promise<AgentConnectionGrant[]> {
    const scope = oversightViewerNamespace(viewer);
    const pattern = `${escapeLikePattern(scope)}/%`;
    const result = await this.db.query(
      `SELECT ${GRANT_COLUMNS}
         FROM agent_connection_grants
        WHERE $1 = ''
           OR namespace = $1
           OR namespace LIKE $2 ESCAPE '\\'
        ORDER BY namespace, id`,
      [scope, pattern],
    );
    return result.rows.map(rowToGrant);
  }

  /** Revoke in scope. Authority fields remain immutable and are never updated. */
  async revoke(id: string, administrator: GatewayAdministrativeIdentity): Promise<boolean> {
    const scope = administrativeNamespace(administrator);
    const pattern = `${escapeLikePattern(scope)}/%`;
    const result = await this.db.query(
      `UPDATE agent_connection_grants
          SET status = 'revoked', revoked_at = $1
        WHERE id = $2
          AND status = 'active'
          AND ($3 = '' OR namespace = $3 OR namespace LIKE $4 ESCAPE '\\')
       RETURNING id`,
      [new Date().toISOString(), id, scope, pattern],
    );
    return result.rows.length === 1;
  }
}
