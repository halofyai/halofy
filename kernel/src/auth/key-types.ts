/**
 * M9 parity #23 (E52) — product key TYPES over the existing five ROLES.
 *
 * There is no new core auth here. `src/auth/index.ts` remains the only
 * issuer/resolver of credentials; this module is a naming + lifecycle layer:
 *
 *   admin      → role 'admin'   (an 'owner' key also reads back as admin)
 *   assistant  → role 'agent'
 *   read-only  → role 'auditor'
 *
 * Each type carries a plaintext PREFIX so a leaked or pasted key is
 * self-describing at a glance (`hm_adm_…`, `hm_agt_…`, `hm_ro_…`).
 * AuthService.resolve() hashes the whole plaintext, so prefixed keys resolve
 * through the unchanged path — the prefix is a label, never a permission.
 * Role 'member' is a human console role with no product key type; it maps to
 * null rather than being silently widened.
 *
 * D9: namespace/actor/role for every operation come from the caller's resolved
 * Identity and the stored row — never from a request body echo.
 * D4: issue, rotate, and revoke each append an audit row on success AND on
 * denial. There is no dedicated key AuditOp, so the closest existing verbs are
 * used: 'share' (a credential handed out), 'supersede' (rotation: the old key
 * is replaced by a new one), 'retract' (revocation), 'reject' (denied).
 */

import { createHash, randomBytes } from "node:crypto";
import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import type { AuditLog } from "../audit/index.js";
import type { AgentAccessLevel, ApiKeyRecord, Identity, Namespace, Role } from "../types.js";
import { AuthService, AuthzError, hashKey, isRootOwner, isSelfOrDescendant, RESERVED_ACTOR_PREFIX } from "./index.js";
import { assertAgentKeyScope } from "./agent-scope.js";
import {
  AgentBearerCipher,
  type AgentBearerEnvelope,
  type AgentBearerEnvelopeRow,
} from "./bearer-cipher.js";

export type ProductKeyType = "admin" | "assistant" | "read-only";

export interface ProductKeyTypeSpec {
  readonly type: ProductKeyType;
  /** Human label shown in the console. */
  readonly label: string;
  readonly description: string;
  /** Plaintext prefix, including the shared `hm_` vendor marker. */
  readonly prefix: string;
  /** The role a newly issued key of this type is bound to. */
  readonly role: Role;
  /** Every role that reads back as this type (admin absorbs owner). */
  readonly roles: readonly Role[];
  /**
   * Server-derived caller classification (D9) recorded on api_keys.caller_class
   * so usage analytics can split human-operated from agent-operated traffic.
   */
  readonly callerClass: "internal" | "external";
}

export const PRODUCT_KEY_TYPES: readonly ProductKeyTypeSpec[] = [
  {
    type: "admin",
    label: "Admin",
    description:
      "Full control of this team: issue keys, mount retrievers, change policy, resolve disputes.",
    prefix: "hm_adm_",
    role: "admin",
    roles: ["admin", "owner"],
    callerClass: "internal",
  },
  {
    type: "assistant",
    label: "Assistant",
    description:
      "For agents and apps: read, search, and write memory through the governed write path.",
    prefix: "hm_agt_",
    role: "agent",
    roles: ["agent"],
    callerClass: "external",
  },
  {
    type: "read-only",
    label: "Read-only",
    description: "Audit and reporting: read memory and the audit trail, write nothing.",
    prefix: "hm_ro_",
    role: "auditor",
    roles: ["auditor"],
    callerClass: "internal",
  },
];

export function isProductKeyType(value: string): value is ProductKeyType {
  return PRODUCT_KEY_TYPES.some((spec) => spec.type === value);
}

export function keyTypeSpec(type: ProductKeyType): ProductKeyTypeSpec {
  const spec = PRODUCT_KEY_TYPES.find((entry) => entry.type === type);
  if (!spec) throw new Error(`unknown key type '${type}'`);
  return spec;
}

/** The product type a stored role reads back as; null for 'member'. */
export function productKeyTypeForRole(role: Role): ProductKeyType | null {
  const spec = PRODUCT_KEY_TYPES.find((entry) => entry.roles.includes(role));
  return spec ? spec.type : null;
}

/** Best-effort type of an already-minted key, from its prefix alone. */
export function productKeyTypeForPlaintext(plaintext: string): ProductKeyType | null {
  const spec = PRODUCT_KEY_TYPES.find((entry) => plaintext.startsWith(entry.prefix));
  return spec ? spec.type : null;
}

/** An `ApiKeyRecord` decorated with its product type label. */
export interface TypedKeyRecord extends ApiKeyRecord {
  keyType: ProductKeyType | null;
  keyTypeLabel: string;
  /** True only when an authenticated bearer envelope exists for this row. */
  bearerRevealable: boolean;
}

export function decorate(record: ApiKeyRecord, bearerRevealable = false): TypedKeyRecord {
  const keyType = productKeyTypeForRole(record.role);
  return {
    ...record,
    keyType,
    keyTypeLabel: keyType ? keyTypeSpec(keyType).label : "Member",
    bearerRevealable,
  };
}

export interface IssueTypedKeyInput {
  type: ProductKeyType;
  /** Target namespace; must be the caller's own namespace or a descendant. */
  namespace: Namespace;
  actor: string;
  /**
   * D50: scope level for an `assistant` (agent) key. Ignored for the human key
   * types. Requested, never asserted — `assertAgentKeyScope` decides what the
   * caller may actually grant and the decision is what gets persisted.
   */
  agentAccessLevel?: AgentAccessLevel;
  /**
   * D51: ISO timestamp after which the credential stops resolving. Omit for
   * standing access. A value already in the past is refused at issuance rather
   * than silently minting a credential that is dead on arrival.
   */
  expiresAt?: string;
  /** D51: free-text purpose, shown on the agent's card. Trimmed and capped. */
  description?: string;
  /**
   * D54: `false` issues an agent that may read memory but never change it.
   * Ignored for the human key types, whose write rules come from their role.
   */
  agentCanWrite?: boolean;
}

/** D51: longest description the card can render without truncating mid-thought. */
const MAX_DESCRIPTION = 280;

/**
 * D51: validate a requested expiry. Returns null for "standing access" so the
 * column stays NULL rather than storing a sentinel far-future date.
 */
function normalizeExpiry(value: string | undefined): string | null {
  if (value === undefined || value === null || value === "") return null;
  const at = Date.parse(value);
  if (!Number.isFinite(at)) throw new Error("issue: 'expiresAt' is not a valid timestamp");
  if (at <= Date.now()) throw new Error("issue: 'expiresAt' is already in the past");
  return new Date(at).toISOString();
}

function normalizeDescription(value: string | undefined): string | null {
  const trimmed = String(value ?? "").trim();
  if (!trimmed) return null;
  return trimmed.slice(0, MAX_DESCRIPTION);
}

export interface TypedKeyIssue {
  record: TypedKeyRecord;
  /** Returned only to an authorized human; authentication still uses its sha256. */
  plaintext: string;
}

export interface TypedKeyRotation extends TypedKeyIssue {
  rotatedFromKeyId: string;
}

function toIsoValue(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function handoffRecord(row: Record<string, unknown>): AgentKeyHandoff {
  return {
    id: String(row.id),
    namespace: String(row.namespace),
    actor: String(row.actor),
    recipientUserId: String(row.recipient_user_id),
    recipientLabel: String(row.display_name),
    status: String(row.status) as AgentKeyHandoff["status"],
    claimExpiresAt: toIsoValue(row.claim_expires_at as Date | string),
    ...(row.credential_expires_at
      ? { expiresAt: toIsoValue(row.credential_expires_at as Date | string) }
      : {}),
    agentCanWrite: row.agent_can_write !== false,
    createdAt: toIsoValue(row.created_at as Date | string),
    ...(row.claimed_key_id ? { claimedKeyId: String(row.claimed_key_id) } : {}),
  };
}

export interface AssignAgentKeyInput {
  namespace: Namespace;
  actor: string;
  recipientUserId: string;
  idempotencyKey: string;
  expiresAt?: string;
  agentCanWrite?: boolean;
}

export interface AgentKeyHandoff {
  id: string;
  namespace: Namespace;
  actor: string;
  recipientUserId: string;
  recipientLabel: string;
  status: "pending" | "claimed" | "revoked";
  claimExpiresAt: string;
  expiresAt?: string;
  agentCanWrite: boolean;
  createdAt: string;
  claimedKeyId?: string;
}

export class BearerUnavailableError extends Error {
  constructor(message = "bearer is unavailable; rotate this legacy badge once to enable reveal") {
    super(message);
    this.name = "BearerUnavailableError";
  }
}

/**
 * Create / rotate / revoke over the existing api_keys table. Every path is
 * audited (D4); every authorization decision reuses the helpers exported by
 * AuthService rather than re-implementing a second policy.
 */
export class ProductKeyService {
  constructor(
    private readonly db: Db,
    private readonly auth: AuthService,
    private readonly audit: AuditLog,
    private readonly bearerCipher: AgentBearerCipher | null = null,
  ) {}

  private async record(
    op: "read" | "share" | "supersede" | "retract" | "reject",
    result: "ok" | "denied",
    caller: Identity | null,
    namespace: Namespace,
    detail: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(), actor: caller?.actor ?? "unknown", agentId: "auth",
      op, memoryId: null, namespace, purpose: null, result, detail,
    });
  }

  private async recordTo(
    db: Db,
    op: "read" | "share" | "supersede" | "retract" | "reject",
    result: "ok" | "denied",
    caller: Identity | null,
    namespace: Namespace,
    detail: string,
  ): Promise<void> {
    await this.audit.appendTo(db, {
      ts: new Date().toISOString(),
      actor: caller?.actor ?? "unknown",
      agentId: "auth",
      op,
      memoryId: null,
      namespace,
      purpose: null,
      result,
      detail,
    });
  }

  /** Keys the caller may see, decorated with their product type. */
  async list(caller: Identity): Promise<TypedKeyRecord[]> {
    const records = await this.auth.list(caller);
    if (records.length === 0) return [];
    const placeholders = records.map((_, index) => `$${index + 1}`).join(", ");
    const result = await this.db.query(
      `SELECT id FROM api_keys
        WHERE id IN (${placeholders}) AND status = 'active'
          AND bearer_ciphertext IS NOT NULL AND bearer_iv IS NOT NULL AND bearer_tag IS NOT NULL`,
      records.map((record) => record.id),
    );
    const revealable = new Set(result.rows.map((row) => String(row.id)));
    return records.map((record) => decorate(record, revealable.has(record.id)));
  }

  async issue(input: IssueTypedKeyInput, caller: Identity): Promise<TypedKeyIssue> {
    if (!isProductKeyType(input.type)) {
      throw new Error(`issue: unknown key type '${String(input.type)}'`);
    }
    const spec = keyTypeSpec(input.type);
    const actor = input.actor.trim();
    if (!actor) throw new Error("issue: 'actor' is required");
    if (actor.startsWith(RESERVED_ACTOR_PREFIX)) {
      throw new Error(`issue: actor '${actor}' is reserved`);
    }

    // D50: an agent credential is authorized by the agent-scope rules (no
    // organization-root agents, team ceiling, issuer-bounded level), which also
    // admit a `member` human issuing inside its own scope. Every other key type
    // keeps the owner/admin-subtree gate.
    const agentScope = spec.role === "agent"
      ? await this.authorizeAgentScope(caller, input)
      : null;
    if (!agentScope) await this.assertMayIssue(caller, input.namespace, spec);

    const namespace = agentScope?.namespace ?? input.namespace;
    const expiresAt = normalizeExpiry(input.expiresAt);
    const description = normalizeDescription(input.description);
    // D54: only meaningful for a machine principal, and only ever a
    // restriction — `undefined` on an agent means the default (may write).
    const agentCanWrite = spec.role === "agent" ? input.agentCanWrite !== false : null;
    const plaintext = spec.prefix + randomBytes(20).toString("hex");
    const id = ulid();
    const createdAt = new Date().toISOString();
    const bearerEnvelope = this.bearerCipher?.seal(plaintext, id, namespace, actor) ?? null;
    await this.insert(
      id,
      hashKey(plaintext),
      namespace,
      actor,
      spec,
      createdAt,
      [],
      [],
      agentScope?.level ?? null,
      expiresAt,
      description,
      agentCanWrite,
      caller.actor,
      null,
      bearerEnvelope,
    );

    const record: ApiKeyRecord = {
      id,
      namespace,
      actor,
      role: spec.role,
      status: "active",
      createdAt,
      lastUsed: null,
      createdBy: caller.actor,
      sourcePrincipals: [],
      sourceGroups: [],
      ...(agentScope ? { agentAccessLevel: agentScope.level } : {}),
      ...(expiresAt ? { expiresAt, expired: false } : {}),
      ...(description ? { description } : {}),
      ...(agentCanWrite === null ? {} : { agentCanWrite }),
    };
    await this.record(
      "share",
      "ok",
      caller,
      namespace,
      `key issued: type=${spec.type} role=${spec.role} keyId=${id} actor=${actor}` +
        (agentScope ? ` level=${agentScope.level}` : "") +
        (expiresAt ? ` expires=${expiresAt}` : "") +
        (agentCanWrite === false ? " access=read-only" : ""),
    );
    return { record: decorate(record, bearerEnvelope !== null), plaintext };
  }

  /**
   * Create a recipient-bound pending handoff. No API key exists yet, so there
   * is no bearer for the assigning administrator, database, or logs to leak.
   */
  async assignToMember(input: AssignAgentKeyInput, caller: Identity): Promise<AgentKeyHandoff> {
    if ((caller.role !== "owner" && caller.role !== "admin") || !caller.sessionUserId) {
      await this.record("reject", "denied", caller, caller.namespace,
        "key handoff denied: human owner/admin session required");
      throw new AuthzError("human owner or admin session required");
    }
    const actor = input.actor.trim();
    if (!actor || actor.startsWith(RESERVED_ACTOR_PREFIX)) {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: invalid agent name");
      throw new Error("handoff: valid agent name required");
    }
    if (!input.idempotencyKey.trim() || input.idempotencyKey.length > 128) {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: invalid idempotency key");
      throw new Error("handoff: idempotency key is required");
    }
    try {
      await assertAgentKeyScope(this.db, caller, { namespace: input.namespace, level: "member" });
    } catch (error) {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: agent scope is unavailable");
      throw error;
    }
    let expiresAt: string | null;
    try {
      expiresAt = normalizeExpiry(input.expiresAt);
    } catch (error) {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: invalid credential expiry");
      throw error;
    }
    const requestFingerprint = createHash("sha256").update(JSON.stringify({
      namespace: input.namespace,
      actor,
      recipientUserId: input.recipientUserId,
      expiresAt,
      agentCanWrite: input.agentCanWrite !== false,
    })).digest("hex");
    const users = await this.db.query(
      `SELECT id, email, display_name, namespace, role, status
         FROM users WHERE id = $1`,
      [caller.sessionUserId],
    );
    const assigner = users.rows.find((row) => row.id === caller.sessionUserId);
    const recipientResult = await this.db.query(
      `SELECT u.id, u.email, u.display_name, u.namespace, u.role, u.status
         FROM users u
         JOIN org_team_members tm ON tm.user_id = u.id
         JOIN org_teams t ON t.id = tm.team_id
        WHERE u.id = $1 AND t.namespace = $2 AND t.archived_at IS NULL`,
      [input.recipientUserId, input.namespace],
    );
    const recipient = recipientResult.rows[0];
    if (!assigner || assigner.status !== "active" || assigner.email !== caller.actor ||
        !recipient || recipient.status !== "active" || recipient.role !== "member") {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: recipient is unavailable or outside the exact team scope");
      throw new AuthzError("recipient is unavailable for this team");
    }
    const id = ulid();
    const createdAt = new Date().toISOString();
    const claimExpiresAt = new Date(Math.min(
      Date.now() + 7 * 86_400_000,
      expiresAt ? Date.parse(expiresAt) : Number.POSITIVE_INFINITY,
    )).toISOString();
    try {
      return await this.db.transaction(async (tx) => {
      const lockedUsers = await tx.query(
        `SELECT id, email, display_name, namespace, role, status
           FROM users WHERE id IN ($1, $2) ORDER BY id FOR UPDATE`,
        [caller.sessionUserId, input.recipientUserId],
      );
      const lockedAssigner = lockedUsers.rows.find((row) => row.id === caller.sessionUserId);
      const lockedRecipient = lockedUsers.rows.find((row) => row.id === input.recipientUserId);
      const membership = await tx.query(
        `SELECT 1 FROM org_team_members tm JOIN org_teams t ON t.id = tm.team_id
          WHERE tm.user_id = $1 AND t.namespace = $2 AND t.archived_at IS NULL`,
        [input.recipientUserId, input.namespace],
      );
      if (!lockedAssigner || lockedAssigner.status !== "active" ||
          lockedAssigner.email !== caller.actor || !lockedRecipient ||
          lockedRecipient.status !== "active" || lockedRecipient.role !== "member" ||
          membership.rows.length === 0) {
        throw new AuthzError("recipient is unavailable for this team");
      }
      const inserted = await tx.query(
        `INSERT INTO agent_key_handoffs
           (id, recipient_user_id, assigned_by_user_id, namespace, actor,
            agent_access_level, agent_can_write, credential_expires_at,
            claim_expires_at, idempotency_key, request_fingerprint, status, created_at)
         VALUES ($1,$2,$3,$4,$5,'member',$6,$7,$8,$9,$10,'pending',$11)
         ON CONFLICT (assigned_by_user_id, idempotency_key) DO NOTHING
         RETURNING *`,
        [id, input.recipientUserId, caller.sessionUserId, input.namespace, actor,
          input.agentCanWrite !== false, expiresAt, claimExpiresAt,
          input.idempotencyKey, requestFingerprint, createdAt],
      );
      let row = inserted.rows[0];
      if (!row) {
        const existing = await tx.query(
          `SELECT h.*, u.email, u.display_name
             FROM agent_key_handoffs h JOIN users u ON u.id = h.recipient_user_id
            WHERE h.assigned_by_user_id = $1 AND h.idempotency_key = $2`,
          [caller.sessionUserId, input.idempotencyKey],
        );
        row = existing.rows[0];
        if (!row || row.request_fingerprint !== requestFingerprint) {
          throw new Error("handoff: idempotency key is already bound to another request");
        }
        return handoffRecord(row);
      }
      await this.recordTo(tx, "share", "ok", caller, input.namespace,
        `key handoff assigned: handoffId=${id} actor=${actor} recipientUserId=${input.recipientUserId}`);
      return {
        id, namespace: input.namespace, actor,
        recipientUserId: input.recipientUserId,
        recipientLabel: String(lockedRecipient.display_name),
        status: "pending", claimExpiresAt,
        ...(expiresAt ? { expiresAt } : {}),
        agentCanWrite: input.agentCanWrite !== false,
        createdAt,
      };
      });
    } catch (error) {
      await this.record("reject", "denied", caller, input.namespace,
        "key handoff denied: assignment could not be completed");
      throw error;
    }
  }

  /** Pending/claimed summaries for exactly the signed-in recipient. */
  async listAssigned(caller: Identity): Promise<AgentKeyHandoff[]> {
    if (!caller.sessionUserId || caller.role === "agent") {
      await this.record("reject", "denied", caller, caller.namespace,
        "key handoff list denied: human session required");
      throw new AuthzError("human session required");
    }
    const adminScope = caller.role === "owner" || caller.role === "admin";
    const result = await this.db.query(
      `SELECT h.*, u.email, u.display_name
         FROM agent_key_handoffs h JOIN users u ON u.id = h.recipient_user_id
        WHERE ${adminScope
          ? isRootOwner(caller)
            ? "TRUE"
            : "(h.namespace = $1 OR h.namespace LIKE $2 ESCAPE '\\')"
          : "h.recipient_user_id = $1"}
        ORDER BY h.created_at DESC`,
      adminScope && !isRootOwner(caller)
        ? [caller.namespace, escapeLikePattern(caller.namespace) + "/%"]
        : adminScope ? [] : [caller.sessionUserId],
    );
    return result.rows.map(handoffRecord);
  }

  /** Revoke a still-pending assignment created by this administrator. */
  async revokeAssigned(handoffId: string, caller: Identity): Promise<{ revoked: true }> {
    if ((caller.role !== "owner" && caller.role !== "admin") || !caller.sessionUserId) {
      await this.record("reject", "denied", caller, caller.namespace,
        "key handoff revoke denied: human owner/admin session required");
      throw new AuthzError("human owner or admin session required");
    }
    try {
      return await this.db.transaction(async (tx) => {
        const found = await tx.query(
          `SELECT id, namespace, status FROM agent_key_handoffs WHERE id = $1 FOR UPDATE`,
          [handoffId],
        );
        const row = found.rows[0];
        if (!row || row.status !== "pending" ||
            (!isRootOwner(caller) && !isSelfOrDescendant(String(row.namespace), caller.namespace))) {
          throw new AuthzError("pending assignment not found");
        }
        const revokedAt = new Date().toISOString();
        await tx.query(
          `UPDATE agent_key_handoffs SET status = 'revoked', revoked_at = $1 WHERE id = $2`,
          [revokedAt, handoffId],
        );
        await this.recordTo(tx, "retract", "ok", caller, row.namespace,
          `key handoff revoked: handoffId=${handoffId}`);
        return { revoked: true };
      });
    } catch (error) {
      await this.record("reject", "denied", caller, caller.namespace,
        "key handoff revoke denied: pending assignment unavailable");
      throw error;
    }
  }

  /** Atomically mint the assigned bearer on the recipient's one-time claim. */
  async claimAssigned(handoffId: string, caller: Identity): Promise<TypedKeyIssue> {
    if (!caller.sessionUserId || caller.role !== "member") {
      await this.record("reject", "denied", caller, caller.namespace,
        "key handoff claim denied: member human session required");
      throw new AuthzError("member human session required");
    }
    let issued: TypedKeyIssue;
    try {
      issued = await this.db.transaction(async (tx) => {
        const result = await tx.query(
        `SELECT h.*, recipient.email AS recipient_email,
                recipient.namespace AS recipient_namespace,
                recipient.role AS recipient_role,
                recipient.status AS recipient_status,
                assigner.email AS assigner_email,
                assigner.namespace AS assigner_namespace,
                assigner.role AS assigner_role,
                assigner.status AS assigner_status
           FROM agent_key_handoffs h
           JOIN users recipient ON recipient.id = h.recipient_user_id
           JOIN users assigner ON assigner.id = h.assigned_by_user_id
           JOIN org_teams recipient_team
             ON recipient_team.namespace = h.namespace AND recipient_team.archived_at IS NULL
           JOIN org_team_members recipient_membership
             ON recipient_membership.team_id = recipient_team.id
            AND recipient_membership.user_id = recipient.id
          WHERE h.id = $1 AND h.recipient_user_id = $2
          FOR UPDATE`,
        [handoffId, caller.sessionUserId],
      );
        const row = result.rows[0];
        const unavailable = !row || row.status !== "pending" ||
          Date.parse(String(row.claim_expires_at)) <= Date.now() ||
          row.recipient_status !== "active" || row.recipient_role !== "member" ||
          row.recipient_namespace !== caller.namespace || row.recipient_email !== caller.actor ||
          row.assigner_status !== "active" ||
          (row.assigner_role !== "owner" && row.assigner_role !== "admin");
        if (unavailable) throw new AuthzError("assigned key is not available");
        const assigner: Identity = {
        keyId: `user:${row.assigned_by_user_id}`,
        namespace: String(row.assigner_namespace),
        actor: String(row.assigner_email),
        role: row.assigner_role,
        sessionUserId: String(row.assigned_by_user_id),
        };
        await assertAgentKeyScope(tx, assigner, { namespace: row.namespace, level: "member" });
        const plaintext = "hm_agt_" + randomBytes(20).toString("hex");
        const keyId = ulid();
        const createdAt = new Date().toISOString();
        const bearerEnvelope = this.bearerCipher?.seal(
          plaintext,
          keyId,
          String(row.namespace),
          String(row.actor),
        ) ?? null;
        await tx.query(
        `INSERT INTO api_keys
           (id, key_hash, namespace, actor, role, status, created_at, last_used,
            source_principals, source_groups, caller_class, agent_access_level,
            expires_at, description, agent_can_write, created_by, custodian_user_id,
            bearer_ciphertext, bearer_iv, bearer_tag)
         VALUES ($1,$2,$3,$4,'agent','active',$5,NULL,'[]'::jsonb,'[]'::jsonb,
                 'external','member',$6,NULL,$7,$8,$9,$10,$11,$12)`,
        [keyId, hashKey(plaintext), row.namespace, row.actor, createdAt,
          row.credential_expires_at, row.agent_can_write,
          row.assigner_email, row.recipient_user_id,
          bearerEnvelope?.ciphertext ?? null,
          bearerEnvelope?.iv ?? null,
          bearerEnvelope?.tag ?? null],
        );
        await tx.query(
        `UPDATE agent_key_handoffs
            SET status = 'claimed', claimed_key_id = $1, claimed_at = $2
          WHERE id = $3 AND status = 'pending'`,
        [keyId, createdAt, handoffId],
        );
        const claimedIssue: TypedKeyIssue = {
        plaintext,
        record: decorate({
          id: keyId, namespace: row.namespace, actor: row.actor, role: "agent",
          status: "active", createdAt, lastUsed: null,
          createdBy: row.assigner_email, custodianUserId: row.recipient_user_id,
          agentAccessLevel: "member", agentCanWrite: row.agent_can_write !== false,
          sourcePrincipals: [], sourceGroups: [],
          ...(row.credential_expires_at
            ? { expiresAt: toIsoValue(row.credential_expires_at), expired: false }
            : {}),
        }),
        };
        await this.recordTo(tx, "share", "ok", caller, row.namespace,
          `key handoff claimed: handoffId=${handoffId} keyId=${keyId}`);
        claimedIssue.record = decorate(claimedIssue.record, bearerEnvelope !== null);
        return claimedIssue;
      });
    } catch (error) {
      await this.record("reject", "denied", caller, caller.namespace,
        `key handoff claim denied: handoffId=${handoffId}`);
      throw error;
    }
    return issued;
  }

  /** Return a recoverable bearer only to a human who can already see the key. */
  async reveal(keyId: string, caller: Identity): Promise<TypedKeyIssue> {
    if (!caller.sessionUserId || caller.role === "agent" || caller.role === "auditor") {
      await this.record("reject", "denied", caller, caller.namespace,
        `key reveal denied: keyId=${keyId} human session required`);
      throw new AuthzError("human session required");
    }
    const existing = await this.requireVisible(keyId, caller, "reveal");
    if (existing.status !== "active" || existing.expired) {
      await this.record("reject", "denied", caller, existing.namespace,
        `key reveal denied: keyId=${keyId} credential is not active`);
      throw new AuthzError("only an active credential may be revealed");
    }
    if (!this.bearerCipher) {
      await this.record("reject", "denied", caller, existing.namespace,
        `key reveal denied: keyId=${keyId} bearer cipher unavailable`);
      throw new BearerUnavailableError();
    }
    try {
      const result = await this.db.query(
        `SELECT id, key_hash, namespace, actor, bearer_ciphertext, bearer_iv, bearer_tag
           FROM api_keys WHERE id = $1 AND status = 'active'`,
        [keyId],
      );
      const row = result.rows[0] as (AgentBearerEnvelopeRow & Record<string, unknown>) | undefined;
      if (!row || !row.bearer_ciphertext || !row.bearer_iv || !row.bearer_tag) {
        throw new BearerUnavailableError();
      }
      const plaintext = this.bearerCipher.open(
        row,
        keyId,
        String(row.namespace),
        String(row.actor),
      );
      if (hashKey(plaintext) !== String(row.key_hash)) {
        throw new Error("bearer envelope does not match its credential hash");
      }
      await this.record("read", "ok", caller, existing.namespace,
        `key bearer revealed: keyId=${keyId}`);
      return { record: decorate(existing, true), plaintext };
    } catch (error) {
      await this.record("reject", "denied", caller, existing.namespace,
        `key reveal denied: keyId=${keyId} bearer unavailable`);
      if (error instanceof BearerUnavailableError) throw error;
      throw new BearerUnavailableError("bearer could not be decrypted; rotate this badge to replace it");
    }
  }

  /**
   * Mint a replacement credential for an existing key and revoke the old one.
   * Type, namespace, and actor are read from the stored row (D9) — a rotation
   * can never quietly change scope or escalate a role.
   */
  async rotate(keyId: string, caller: Identity): Promise<TypedKeyRotation> {
    const existing = await this.requireVisible(keyId, caller, "rotate");
    const type = productKeyTypeForRole(existing.role);
    if (!type) {
      await this.record(
        "reject",
        "denied",
        caller,
        existing.namespace,
        `rotate denied: key ${keyId} has role '${existing.role}', which has no product key type`,
      );
      throw new AuthzError(`role '${existing.role}' keys cannot be rotated`);
    }
    const spec = keyTypeSpec(type);
    // D51: rotation re-issues the SAME authority, and expiry is part of that
    // authority — so a rotated key keeps the original expiry. Rotating one that
    // has already lapsed would therefore mint a credential that is dead on
    // arrival; refuse instead of handing back a key that cannot work.
    if (existing.expired) {
      await this.record(
        "reject",
        "denied",
        caller,
        existing.namespace,
        `rotate denied: key ${keyId} expired at ${existing.expiresAt ?? "unknown"}`,
      );
      throw new AuthzError("an expired credential cannot be rotated; deploy a new agent");
    }
    if (spec.role === "agent") {
      // D50: rotation is re-issuance of the SAME authority — so it must still
      // be authority the caller could grant today. A grandfathered org-root
      // agent therefore cannot be rotated: revoke it and deploy one in scope.
      await this.authorizeAgentScope(caller, {
        type,
        namespace: existing.namespace,
        actor: existing.actor,
        ...(existing.agentAccessLevel ? { agentAccessLevel: existing.agentAccessLevel } : {}),
      });
    } else {
      await this.assertMayIssue(caller, existing.namespace, spec);
    }

    const plaintext = spec.prefix + randomBytes(20).toString("hex");
    const id = ulid();
    const createdAt = new Date().toISOString();
    const bearerEnvelope = this.bearerCipher?.seal(
      plaintext,
      id,
      existing.namespace,
      existing.actor,
    ) ?? null;
    // The replacement keeps the STORED role (an owner key rotates to an owner
    // key), so rotation is scope-preserving in both directions.
    await this.insert(
      id,
      hashKey(plaintext),
      existing.namespace,
      existing.actor,
      { ...spec, role: existing.role },
      createdAt,
      existing.sourcePrincipals ?? [],
      existing.sourceGroups ?? [],
      existing.agentAccessLevel ?? null,
      existing.expiresAt ?? null,
      existing.description ?? null,
      existing.role === "agent" ? existing.agentCanWrite !== false : null,
      // Migration 76: rotation re-issues the SAME authority, so it keeps the
      // ORIGINAL issuer. Crediting the rotator would let an admin's routine
      // rotation quietly move someone else's agent into the admin's own
      // connections list. An unattributed key stays unattributed.
      existing.createdBy ?? null,
      existing.custodianUserId ?? null,
      bearerEnvelope,
    );
    await this.auth.revoke(keyId);

    const record: ApiKeyRecord = {
      id,
      namespace: existing.namespace,
      actor: existing.actor,
      role: existing.role,
      status: "active",
      createdAt,
      lastUsed: null,
      sourcePrincipals: [...(existing.sourcePrincipals ?? [])],
      sourceGroups: [...(existing.sourceGroups ?? [])],
      ...(existing.agentAccessLevel ? { agentAccessLevel: existing.agentAccessLevel } : {}),
      ...(existing.expiresAt ? { expiresAt: existing.expiresAt, expired: false } : {}),
      ...(existing.description ? { description: existing.description } : {}),
      ...(existing.role === "agent" ? { agentCanWrite: existing.agentCanWrite !== false } : {}),
      ...(existing.createdBy ? { createdBy: existing.createdBy } : {}),
      ...(existing.custodianUserId ? { custodianUserId: existing.custodianUserId } : {}),
    };
    await this.record(
      "supersede",
      "ok",
      caller,
      existing.namespace,
      `key rotated: type=${spec.type} from=${keyId} to=${id} actor=${existing.actor}`,
    );
    return {
      record: decorate(record, bearerEnvelope !== null),
      plaintext,
      rotatedFromKeyId: keyId,
    };
  }

  async revoke(keyId: string, caller: Identity): Promise<{ revoked: boolean }> {
    const existing = await this.requireVisible(keyId, caller, "revoke");
    const revoked = await this.auth.revoke(keyId);
    await this.record(
      "retract",
      "ok",
      caller,
      existing.namespace,
      `key revoke: keyId=${keyId} type=${productKeyTypeForRole(existing.role) ?? "none"} ` +
        `changed=${revoked}`,
    );
    return { revoked };
  }

  /**
   * D50 gate for agent credentials. Delegates the decision to the single rule
   * module and adds the D4 denial row the rules module deliberately does not
   * write (it stays pure so issuance, badges, and dry-runs share one shape).
   */
  private async authorizeAgentScope(
    caller: Identity,
    input: IssueTypedKeyInput,
  ): Promise<{ namespace: Namespace; level: AgentAccessLevel }> {
    try {
      return await assertAgentKeyScope(this.db, caller, {
        namespace: input.namespace,
        ...(input.agentAccessLevel ? { level: input.agentAccessLevel } : {}),
      });
    } catch (error) {
      await this.record(
        "reject",
        "denied",
        caller,
        input.namespace,
        // Same `key issue denied:` prefix as assertMayIssue — one audit
        // vocabulary for every refused credential, agent or human.
        `key issue denied: agent scope - role '${caller.role}' requested ` +
          `level=${input.agentAccessLevel ?? "member"} in '${input.namespace}': ` +
          (error instanceof Error ? error.message : String(error)),
      );
      throw error;
    }
  }

  /**
   * Admin-subtree gate, identical in shape to the HTTP adapter's: a root owner
   * is global, everyone else may act only inside their own namespace subtree,
   * and only an owner may hand out an admin-type key.
   */
  private async assertMayIssue(
    caller: Identity,
    namespace: Namespace,
    spec: ProductKeyTypeSpec,
  ): Promise<void> {
    const inScope = isRootOwner(caller) || isSelfOrDescendant(namespace, caller.namespace);
    const roleOk = caller.role === "owner" || caller.role === "admin";
    if (!inScope || !roleOk) {
      await this.record(
        "reject",
        "denied",
        caller,
        namespace,
        `key issue denied: role '${caller.role}' may not issue ${spec.type} keys in '${namespace}'`,
      );
      throw new AuthzError("issuing a key requires an owner or admin identity in scope");
    }
    if (spec.type === "admin" && caller.role !== "owner") {
      await this.record(
        "reject",
        "denied",
        caller,
        namespace,
        `key issue denied: only an owner may issue an admin key in '${namespace}'`,
      );
      throw new AuthzError("only an owner may issue an admin key");
    }
  }

  /** The caller may only touch keys AuthService.list() already shows them. */
  private async requireVisible(
    keyId: string,
    caller: Identity,
    op: "reveal" | "rotate" | "revoke",
  ): Promise<ApiKeyRecord> {
    const visible = await this.auth.list(caller);
    const found = visible.find((record) => record.id === keyId);
    if (!found) {
      await this.record(
        "reject",
        "denied",
        caller,
        caller.namespace,
        `${op} denied: key ${keyId} is not in your subtree`,
      );
      throw new AuthzError("key not found in your subtree");
    }
    return found;
  }

  /**
   * Insert with the server-derived caller_class (migration 038). Older
   * hermetic fixtures build api_keys from API_KEYS_DDL, which predates that
   * column — brownout to the classic insert rather than failing issuance.
   */
  private async insert(
    id: string,
    keyHash: string,
    namespace: Namespace,
    actor: string,
    spec: ProductKeyTypeSpec & { role: Role },
    createdAt: string,
    sourcePrincipals: string[] = [],
    sourceGroups: string[] = [],
    agentAccessLevel: AgentAccessLevel | null = null,
    expiresAt: string | null = null,
    description: string | null = null,
    agentCanWrite: boolean | null = null,
    createdBy: string | null = null,
    custodianUserId: string | null = null,
    bearerEnvelope: AgentBearerEnvelope | null = null,
  ): Promise<void> {
    const values = [
      id,
      keyHash,
      namespace,
      actor,
      spec.role,
      createdAt,
      JSON.stringify(sourcePrincipals),
      JSON.stringify(sourceGroups),
    ];
    // D50: a level is stored only for a machine principal, and only ever the
    // authorized one — never a value echoed from a request.
    const level = spec.role === "agent" ? (agentAccessLevel ?? "member") : null;
    try {
      await this.db.query(
        `INSERT INTO api_keys
           (id, key_hash, namespace, actor, role, status, created_at, last_used,
            source_principals, source_groups, caller_class, agent_access_level,
            expires_at, description, agent_can_write, created_by, custodian_user_id,
            bearer_ciphertext, bearer_iv, bearer_tag)
         VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL, $7::jsonb, $8::jsonb, $9, $10,
                 $11, $12, $13, $14, $15, $16, $17, $18)`,
        [...values, spec.callerClass, level, expiresAt, description, agentCanWrite, createdBy,
          custodianUserId, bearerEnvelope?.ciphertext ?? null, bearerEnvelope?.iv ?? null,
          bearerEnvelope?.tag ?? null],
      );
      return;
    } catch (error) {
      // A caller that requested a recoverable bearer must never silently
      // brown out to hash-only storage. Production must run migration 98.
      if (bearerEnvelope !== null) {
        throw new Error(
          "issue: encrypted bearer storage is unavailable; run migration 98",
          { cause: error },
        );
      }
      // Custody is an authorization relation, not display metadata. Rotation
      // may not brown out to an old schema and silently orphan the recipient.
      if (custodianUserId !== null) throw error;
      // Fall through to the narrower shapes below.
    }
    // Migration 76 (created_by) is display-only attribution, not authority, so
    // an older schema drops it rather than refusing to mint — unlike the expiry
    // and read-only checks below, where silently widening a credential is the
    // failure being prevented.
    // D51: a pre-migration-60 schema has no expiry column. An expiry that was
    // ASKED FOR must not be silently dropped — that would mint a standing
    // credential where the operator chose a bounded one. Fail loudly instead;
    // standing-access issuance still browns out to the older shapes.
    if (expiresAt !== null) {
      throw new Error(
        "issue: this database predates key expiry (migration 60); run migrations or issue standing access",
      );
    }
    // D54: same reasoning as the expiry above — a read-only agent that silently
    // becomes a read-write one is the failure this check exists to prevent.
    if (agentCanWrite === false) {
      throw new Error(
        "issue: this database predates read-only agents (migration 61); run migrations",
      );
    }
    try {
      await this.db.query(
        `INSERT INTO api_keys
           (id, key_hash, namespace, actor, role, status, created_at, last_used,
            source_principals, source_groups, caller_class, agent_access_level)
         VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL, $7::jsonb, $8::jsonb, $9, $10)`,
        [...values, spec.callerClass, level],
      );
    } catch {
      await this.db.query(
        `INSERT INTO api_keys
           (id, key_hash, namespace, actor, role, status, created_at, last_used,
            source_principals, source_groups)
         VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL, $7::jsonb, $8::jsonb)`,
        values,
      );
    }
  }
}
