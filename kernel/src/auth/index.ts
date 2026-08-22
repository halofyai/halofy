/**
 * Module A (M1) — AuthService: API key issuance, resolution, revocation,
 * listing. D9: identity is resolved server-side from a credential; callers
 * never assert their own namespace or actor.
 *
 * Key format: plaintext `hm_` + 40 hex chars (crypto.randomBytes(20)).
 * Resolution uses only the sha256 hex of the plaintext. Product agent badges
 * may additionally retain a separately authenticated ciphertext for explicit,
 * audited human reveal; that envelope never participates in authentication.
 *
 * D4 audit discipline: every denial path in this module (failed resolve =
 * 401, authz failure = 403) appends an audit row with result 'denied'.
 */

import { createHash, randomBytes } from "node:crypto";
import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import type { AuditLog } from "../audit/index.js";
import type { AgentAccessLevel, ApiKeyRecord, Identity, Role } from "../types.js";

/** Thrown on role/scope denials (maps to HTTP 403 in the transport layer). */
export class AuthzError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthzError";
  }
}

export const ROLES: readonly Role[] = ["owner", "admin", "auditor", "member", "agent"];

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

/**
 * api_keys DDL (owned by module C as migration 002; duplicated here with
 * IF NOT EXISTS so the CLI and hermetic tests work before/without it).
 */
export const API_KEYS_DDL = `CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,
  namespace TEXT NOT NULL, actor TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','auditor','member','agent')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  principal_purpose TEXT NOT NULL DEFAULT 'general' CHECK (principal_purpose IN ('general','channel_verification','channel_assistant')),
  created_at TIMESTAMPTZ NOT NULL, last_used TIMESTAMPTZ,
  source_principals JSONB NOT NULL DEFAULT '[]',
  source_groups JSONB NOT NULL DEFAULT '[]',
  -- D50: NULL on a human key type; 'manager'|'member' on an agent credential.
  agent_access_level TEXT
    CHECK (agent_access_level IS NULL OR agent_access_level IN ('manager','member')),
  -- D51: NULL expiry is standing access; a past expiry stops resolving.
  expires_at TIMESTAMPTZ,
  description TEXT,
  -- D54: NULL means "may write" (every pre-D54 agent could); only FALSE restricts.
  agent_can_write BOOLEAN,
  created_by TEXT,
  custodian_user_id TEXT,
  bearer_ciphertext TEXT,
  bearer_iv TEXT,
  bearer_tag TEXT,
  CHECK (
    (bearer_ciphertext IS NULL AND bearer_iv IS NULL AND bearer_tag IS NULL)
    OR
    (bearer_ciphertext IS NOT NULL AND bearer_iv IS NOT NULL AND bearer_tag IS NOT NULL)
  )
)`;

/** Idempotent safety net; module C's numbered migration is authoritative. */
export async function ensureApiKeysTable(db: Db): Promise<void> {
  await db.query(API_KEYS_DDL);
}

export function hashKey(plaintext: string): string {
  return createHash("sha256").update(plaintext, "utf8").digest("hex");
}

/** True when `ns` equals `ancestor` or is a slash-delimited descendant of it. */
export function isSelfOrDescendant(ns: string, ancestor: string): boolean {
  return ns === ancestor || ns.startsWith(ancestor + "/");
}

/** Global authority requires both the owner role and the root namespace. */
export function isRootOwner(identity: Identity): boolean {
  return identity.role === "owner" && identity.namespace === "";
}

/**
 * The oversight roles: the personas whose job is reading OTHER callers'
 * activity. Everyone else — an operating member (D55) — is pinned to its own
 * `identity.actor` on the analytics read models (usage, Assistant turns,
 * accuracy: D40 in CONTRACTS-USAGE-ANALYTICS.md).
 *
 * Namespace scope is not enough on its own for those surfaces: a member's
 * namespace projection carries both its ancestors and its descendants, so an
 * unpinned read hands it every teammate's, sub-team's and agent's traffic.
 * This is a REPORTING pin, not the ACL — the namespace predicate still
 * applies, and this only ever narrows it further.
 */
export function isOversightRole(identity: Identity): boolean {
  return (
    identity.role === "owner" ||
    identity.role === "admin" ||
    identity.role === "auditor"
  );
}

interface ApiKeyRow {
  id: string;
  namespace: string;
  actor: string;
  role: string;
  status: string;
  principal_purpose?: string;
  created_at: Date | string;
  last_used: Date | string | null;
  source_principals?: unknown;
  source_groups?: unknown;
  caller_class?: unknown;
  agent_access_level?: unknown;
  expires_at?: Date | string | null;
  description?: unknown;
  agent_can_write?: unknown;
  created_by?: unknown;
  custodian_user_id?: unknown;
}

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

/**
 * D51: the columns every read of `api_keys` needs. Kept as one constant so a
 * new field can never be surfaced by `list()` but missed by `resolve()` — the
 * shape divergence that would let an expired key keep resolving.
 */
const KEY_COLUMNS =
  `id, namespace, actor, role, status, principal_purpose, created_at, last_used,
   source_principals, source_groups, agent_access_level, expires_at, description,
   agent_can_write, created_by, custodian_user_id`;

/**
 * D54: may this agent CHANGE memory? Only an explicit FALSE says no — a NULL
 * (a key minted before the capability existed, or by an older kernel mid-deploy)
 * keeps the ability it was issued with.
 */
function rowAgentCanWrite(role: string, value: unknown): boolean | undefined {
  if (role !== "agent") return undefined;
  return value === false ? false : true;
}

/**
 * D51: an expiry that has already passed. Read from the stored row, never from
 * a request — the same rule as every other authority field (D9). An unparseable
 * value is treated as expired: a credential whose lifetime cannot be read is
 * not a credential we keep honouring.
 */
function isExpired(row: ApiKeyRow, now: number): boolean {
  if (row.expires_at === null || row.expires_at === undefined) return false;
  const at = row.expires_at instanceof Date
    ? row.expires_at.getTime()
    : Date.parse(String(row.expires_at));
  return !Number.isFinite(at) || at <= now;
}

/**
 * D50: the level an agent row acts at. NULL on an agent row (pre-migration-59
 * key, or a mid-deploy insert) reads as the least-privileged 'member'; a level
 * on a non-agent row is ignored — role is what grants authority.
 * Kept local rather than imported from ./agent-scope.js so the base auth module
 * has no cycle back through its own scope-rule layer.
 */
function rowAgentLevel(role: string, value: unknown): AgentAccessLevel | undefined {
  if (role !== "agent") return undefined;
  return value === "manager" ? "manager" : "member";
}

function rowToRecord(row: ApiKeyRow): ApiKeyRecord {
  const agentAccessLevel = rowAgentLevel(row.role, row.agent_access_level);
  return {
    id: row.id,
    namespace: row.namespace,
    actor: row.actor,
    role: row.role as Role,
    ...(agentAccessLevel ? { agentAccessLevel } : {}),
    // D50 grandfathering: an agent bound to the organization root predates the
    // rule that forbids it. It still resolves; the console flags it.
    ...(row.role === "agent" && row.namespace === "" ? { outOfPolicy: true } : {}),
    status: row.status as ApiKeyRecord["status"],
    createdAt: toIso(row.created_at),
    lastUsed: row.last_used === null ? null : toIso(row.last_used),
    // D51: `expired` is derived here rather than stored so a listing never
    // shows a key as usable after its own expiry passed.
    ...(row.expires_at ? { expiresAt: toIso(row.expires_at), expired: isExpired(row, Date.now()) } : {}),
    ...(typeof row.description === "string" && row.description ? { description: row.description } : {}),
    // Migration 76: the issuer, when the row has one. Absent stays absent —
    // "nobody recorded" must not read as "issued by nobody in particular".
    ...(typeof row.created_by === "string" && row.created_by ? { createdBy: row.created_by } : {}),
    ...(typeof row.custodian_user_id === "string" && row.custodian_user_id
      ? { custodianUserId: row.custodian_user_id }
      : {}),
    ...(row.role === "agent" ? { agentCanWrite: rowAgentCanWrite(row.role, row.agent_can_write) } : {}),
    sourcePrincipals: Array.isArray(row.source_principals)
      ? row.source_principals.filter((value): value is string => typeof value === "string") : [],
    sourceGroups: Array.isArray(row.source_groups)
      ? row.source_groups.filter((value): value is string => typeof value === "string") : [],
  };
}

/**
 * Actor names with this prefix are reserved for server-side system
 * identities (e.g. 'system-default-skills', 'system-skills-sweep'). Those
 * identities are constructed in-process and never authenticate with a key,
 * so key issuance must never bind one — a key holder could otherwise
 * impersonate the system (e.g. forge the console "Default" skill badge).
 */
export const RESERVED_ACTOR_PREFIX = "system-";

export class AuthService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
  ) {}

  private async auditDenied(
    actor: string,
    namespace: string,
    detail: string,
  ): Promise<void> {
    // AuditOp has no dedicated auth op; 'reject' is the denial op (D4).
    await this.audit.append({
      ts: new Date().toISOString(),
      actor,
      agentId: "auth",
      op: "reject",
      memoryId: null,
      namespace,
      purpose: null,
      result: "denied",
      detail,
    });
  }

  /**
   * Issue a new API key bound to (namespace, actor, role).
   *
   * Bootstrap rule: requires an owner caller whose namespace contains the
   * target namespace, UNLESS the api_keys table is empty (first-boot path —
   * the very first key may be minted without any credential, by a process with
   * direct DB access). Only a root owner is global.
   *
   * Returns the stored record plus the plaintext key — shown exactly once,
   * never stored.
   */
  async issueKey(
    namespace: string,
    actor: string,
    role: Role,
    caller?: Identity | null,
    entitlements: {
      sourcePrincipals?: string[];
      sourceGroups?: string[];
      /** D50: persisted only for role 'agent'; defaults to least privilege. */
      agentAccessLevel?: AgentAccessLevel;
    } = {},
  ): Promise<{ record: ApiKeyRecord; plaintext: string }> {
    if (!isRole(role)) {
      throw new Error(`issueKey: invalid role '${role}'`);
    }
    if (actor.startsWith(RESERVED_ACTOR_PREFIX)) {
      throw new Error(`issueKey: actor '${actor}' is reserved`);
    }
    const countRes = await this.db.query(`SELECT COUNT(*) AS n FROM api_keys`);
    const empty = Number(countRes.rows[0].n) === 0;
    const callerMayIssue =
      caller?.role === "owner" &&
      (isRootOwner(caller) || isSelfOrDescendant(namespace, caller.namespace));
    if (!empty && !callerMayIssue) {
      await this.auditDenied(
        caller?.actor ?? actor,
        caller?.namespace ?? namespace,
        `issueKey denied: requires owner identity (caller role: ${caller?.role ?? "none"})`,
      );
      throw new AuthzError("issueKey requires an owner identity");
    }

    const plaintext = "hm_" + randomBytes(20).toString("hex");
    const id = ulid();
    const createdAt = new Date().toISOString();
    // D50: a level is meaningful only for a machine principal. Non-agent rows
    // store NULL so "not a machine principal" and "least-privileged agent" stay
    // distinguishable in the table.
    const agentAccessLevel: AgentAccessLevel | null =
      role === "agent" ? (entitlements.agentAccessLevel ?? "member") : null;
    // Migration 76: the issuer is the CALLER, never the actor the credential
    // acts as (D9) — and it is null on the first-boot bootstrap path, which by
    // definition has no caller.
    const createdBy = caller?.actor ?? null;
    await this.db.query(
      `INSERT INTO api_keys
         (id, key_hash, namespace, actor, role, status, principal_purpose,
          created_at, last_used, source_principals, source_groups, agent_access_level,
          created_by)
       VALUES ($1, $2, $3, $4, $5, 'active', 'general', $6, NULL, $7::jsonb, $8::jsonb, $9, $10)`,
      [id, hashKey(plaintext), namespace, actor, role, createdAt,
        JSON.stringify(entitlements.sourcePrincipals ?? []),
        JSON.stringify(entitlements.sourceGroups ?? []),
        agentAccessLevel, createdBy],
    );
    const record: ApiKeyRecord = {
      id,
      namespace,
      actor,
      role,
      status: "active",
      createdAt,
      lastUsed: null,
      sourcePrincipals: [...(entitlements.sourcePrincipals ?? [])],
      sourceGroups: [...(entitlements.sourceGroups ?? [])],
      ...(agentAccessLevel ? { agentAccessLevel } : {}),
      ...(role === "agent" && namespace === "" ? { outOfPolicy: true } : {}),
      ...(createdBy ? { createdBy } : {}),
    };
    return { record, plaintext };
  }

  /**
   * Resolve a plaintext key to an Identity. Updates last_used on success.
   * Returns null for unknown or revoked keys (transport maps to 401); both
   * miss paths write an audit row.
   */
  async resolve(plaintext: string): Promise<Identity | null> {
    const hash = hashKey(plaintext);
    const res = await this.db.query(
      `SELECT ${KEY_COLUMNS}, caller_class FROM api_keys WHERE key_hash = $1`,
      [hash],
    );
    const row = res.rows[0] as ApiKeyRow | undefined;
    // Verification-only principals (principal_purpose = 'channel_verification')
    // exist solely for in-process deterministic channel probes and must never
    // authenticate over the public API.
    if (!row || row.status !== "active" ||
        (row.principal_purpose !== undefined && row.principal_purpose !== "general")) {
      await this.auditDenied(
        "unknown",
        row?.namespace ?? "unknown",
        row
          ? `resolve denied: key ${row.id} is unavailable for public authentication`
          : "resolve denied: unknown key",
      );
      return null;
    }
    // D51: an expired key is indistinguishable from a revoked one at the
    // transport (401). It is NOT flipped to status 'revoked' here — resolve is
    // on the hot path for every request, and a write on each rejected call is
    // both a needless round trip and a lie about who revoked it. The audit row
    // names expiry explicitly so the two causes stay separable in the trail.
    if (isExpired(row, Date.now())) {
      await this.auditDenied(
        row.actor,
        row.namespace,
        `resolve denied: key ${row.id} expired at ${String(row.expires_at)}`,
      );
      return null;
    }
    await this.db.query(`UPDATE api_keys SET last_used = $1 WHERE id = $2`, [
      new Date().toISOString(),
      row.id,
    ]);
    const entitlements = rowToRecord(row);
    const sourcePrincipals = entitlements.sourcePrincipals ?? [];
    const sourceGroups = entitlements.sourceGroups ?? [];
    const agentAccessLevel = rowAgentLevel(row.role, row.agent_access_level);
    return {
      keyId: row.id,
      namespace: row.namespace,
      actor: row.actor,
      role: row.role as Role,
      ...(agentAccessLevel ? { agentAccessLevel } : {}),
      ...(row.role === "agent"
        ? { agentCanWrite: rowAgentCanWrite(row.role, row.agent_can_write) === true }
        : {}),
      callerClass: typeof row.caller_class === "string" ? row.caller_class : "unclassified",
      ...(sourcePrincipals.length > 0
        ? { sourcePrincipals }
        : {}),
      ...(sourceGroups.length > 0 ? { sourceGroups } : {}),
    };
  }

  /**
   * True when the key row exists and is active. Deferred-work executors
   * (e.g. the WriteQueue worker) re-check this before acting on an Identity
   * snapshotted at enqueue time — a key revoked after enqueue must not keep
   * writing.
   */
  async isActive(keyId: string): Promise<boolean> {
    const res = await this.db.query(
      `SELECT status, expires_at FROM api_keys WHERE id = $1`, [
      keyId,
    ]);
    const row = res.rows[0] as ApiKeyRow | undefined;
    return Boolean(row && row.status === "active" && !isExpired(row, Date.now()));
  }

  /**
   * Resolve deferred channel authority by opaque key id. This internal lookup
   * never accepts plaintext API keys and deliberately does not update last_used.
   */
  async resolveActiveIdentity(keyId: string): Promise<Identity | null> {
    const res = await this.db.query(
      `SELECT ${KEY_COLUMNS}
         FROM api_keys
        WHERE id = $1 AND status = 'active' AND role = 'agent'
          AND principal_purpose = 'general'`,
      [keyId],
    );
    const row = res.rows[0] as ApiKeyRow | undefined;
    if (!row || isExpired(row, Date.now())) return null;
    const record = rowToRecord(row);
    const sourcePrincipals = record.sourcePrincipals ?? [];
    const sourceGroups = record.sourceGroups ?? [];
    return {
      keyId: record.id,
      namespace: record.namespace,
      actor: record.actor,
      role: "agent",
      ...(record.agentAccessLevel ? { agentAccessLevel: record.agentAccessLevel } : {}),
      ...(record.agentCanWrite === false ? { agentCanWrite: false } : {}),
      ...(sourcePrincipals.length > 0 ? { sourcePrincipals } : {}),
      ...(sourceGroups.length > 0 ? { sourceGroups } : {}),
    };
  }

  /**
   * Resolve an identity used by the channel worker. In addition to ordinary
   * agent badges, this admits the server-minted Halo Assistant principal.
   * Neither purpose is inferred from caller input and the assistant purpose
   * remains excluded from plaintext API-key authentication.
   */
  async resolveChannelIdentity(keyId: string): Promise<Identity | null> {
    const res = await this.db.query(
      `SELECT ${KEY_COLUMNS}
         FROM api_keys
        WHERE id = $1 AND status = 'active' AND role = 'agent'
          AND principal_purpose IN ('general','channel_assistant')`,
      [keyId],
    );
    const row = res.rows[0] as ApiKeyRow | undefined;
    if (!row || isExpired(row, Date.now())) return null;
    const record = rowToRecord(row);
    const sourcePrincipals = record.sourcePrincipals ?? [];
    const sourceGroups = record.sourceGroups ?? [];
    return {
      keyId: record.id,
      namespace: record.namespace,
      actor: record.actor,
      role: "agent",
      ...(row.principal_purpose === "channel_assistant" ? { channelAssistant: true as const } : {}),
      ...(record.agentAccessLevel ? { agentAccessLevel: record.agentAccessLevel } : {}),
      ...(record.agentCanWrite === false ? { agentCanWrite: false } : {}),
      ...(sourcePrincipals.length > 0 ? { sourcePrincipals } : {}),
      ...(sourceGroups.length > 0 ? { sourceGroups } : {}),
    };
  }

  /**
   * Re-resolve an owner/admin API key by opaque id for a deferred privileged
   * callback. Unlike channel authority this deliberately excludes agents.
   */
  async resolveActiveAdministrativeIdentity(keyId: string): Promise<Identity | null> {
    const res = await this.db.query(
      `SELECT ${KEY_COLUMNS}
         FROM api_keys
        WHERE id = $1 AND status = 'active' AND role IN ('owner', 'admin')
          AND principal_purpose = 'general'`,
      [keyId],
    );
    const row = res.rows[0] as ApiKeyRow | undefined;
    if (!row || isExpired(row, Date.now())) return null;
    return {
      keyId: row.id,
      namespace: row.namespace,
      actor: row.actor,
      role: row.role as "owner" | "admin",
    };
  }

  /** Resolve the internal verification-only principal for deterministic dispatch. */
  async resolveVerificationIdentity(keyId: string): Promise<Identity | null> {
    const res = await this.db.query(
      `SELECT ${KEY_COLUMNS}
         FROM api_keys
        WHERE id = $1 AND status = 'active' AND role = 'agent'
          AND principal_purpose = 'channel_verification'`,
      [keyId],
    );
    const row = res.rows[0] as ApiKeyRow | undefined;
    if (!row) return null;
    return {
      keyId: row.id,
      namespace: row.namespace,
      actor: row.actor,
      role: "agent",
    };
  }

  /** Mark a key revoked. Idempotent; returns true if a row was active. */
  async revoke(id: string): Promise<boolean> {
    try {
      const res = await this.db.query(
        `UPDATE api_keys
            SET status = 'revoked', bearer_ciphertext = NULL, bearer_iv = NULL, bearer_tag = NULL
          WHERE id = $1 AND status = 'active' RETURNING id`,
        [id],
      );
      return res.rows.length > 0;
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error
        ? String((error as { code?: unknown }).code ?? "")
        : "";
      const message = error instanceof Error ? error.message : String(error);
      const missingEnvelopeColumn = code === "42703" ||
        /column ["']?bearer_(?:ciphertext|iv|tag)["']? does not exist/i.test(message);
      if (!missingEnvelopeColumn) throw error;
      // Compatibility for hermetic/pre-v98 schemas. There is no envelope to
      // scrub when these columns do not exist.
      const res = await this.db.query(
        `UPDATE api_keys SET status = 'revoked'
          WHERE id = $1 AND status = 'active' RETURNING id`,
        [id],
      );
      return res.rows.length > 0;
    }
  }

  /**
   * List key records visible to the caller.
   * root owner → all keys; tenant owner/admin → keys whose namespace is the
   * caller's namespace or a descendant of it; every other role → AuthzError
   * (audited).
   */
  async list(caller: Identity): Promise<ApiKeyRecord[]> {
    if (isRootOwner(caller)) {
      const res = await this.db.query(
        `SELECT ${KEY_COLUMNS} FROM api_keys
         WHERE principal_purpose = 'general' ORDER BY created_at`,
      );
      return (res.rows as ApiKeyRow[]).map(rowToRecord);
    }
    if (caller.role === "owner" || caller.role === "admin") {
      // The subtree pattern is built from the admin's own namespace, which is
      // an arbitrary string: `_`/`%` in it MUST NOT act as LIKE wildcards
      // (an admin of 'org/eng_svc' would otherwise list — and via the HTTP
      // adapter revoke — sibling 'org/engXsvc' keys). Escaped + ESCAPE '\'.
      const res = await this.db.query(
        `SELECT ${KEY_COLUMNS} FROM api_keys
         WHERE principal_purpose = 'general'
           AND (namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
         ORDER BY created_at`,
        [caller.namespace, escapeLikePattern(caller.namespace) + "/%"],
      );
      return (res.rows as ApiKeyRow[]).map(rowToRecord);
    }
    if (caller.role === "member") {
      // D50: a member may deploy agents in its own scope, so it must be able to
      // see and revoke them. Deliberately narrower than the admin branch — the
      // AGENT credentials the member personally created at its exact home
      // namespace, plus recipient-bound credentials it explicitly owns as
      // custodian through any active team membership. Never a human key type.
      const res = await this.db.query(
        `SELECT ${KEY_COLUMNS} FROM api_keys
         WHERE role = 'agent' AND principal_purpose = 'general'
           AND (
             custodian_user_id = $2
             OR (namespace = $1 AND custodian_user_id IS NULL AND created_by = $3)
           )
         ORDER BY created_at`,
        [caller.namespace, caller.sessionUserId ?? null, caller.actor],
      );
      return (res.rows as ApiKeyRow[]).map(rowToRecord);
    }
    await this.auditDenied(
      caller.actor,
      caller.namespace,
      `list denied: role '${caller.role}' may not list keys`,
    );
    throw new AuthzError(`role '${caller.role}' may not list keys`);
  }
}
