/**
 * Durable M8A oversight records.
 *
 * Events are the content-free source of truth. Alert derivation happens in
 * the same transaction so in-product routing is synchronous and cannot drift
 * from the decision that triggered it. Temporary capabilities are stored as
 * exact, badge-bound requests and consumed with a conditional atomic update.
 */

import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import { escapeLikePattern } from "../db/client.js";
import {
  AGENT_GATEWAY_OPERATIONS,
  MAX_GATEWAY_BYTES,
  MAX_GATEWAY_FIELDS,
  MAX_GATEWAY_ROWS,
  type AgentAccessAlert,
  type AgentAccessApprovalInput,
  type AgentAccessDecisionInput,
  type AgentAccessEvent,
  type AgentAccessRequest,
  type AgentConnectionOversight,
  type CreateAgentAccessRequestInput,
  type CreateAgentAccessEventInput,
  type ExactAgentAccessRequest,
  type GatewayAdministrativeIdentity,
  type GatewayOversightViewerIdentity,
  type ResolvedAgentIdentity,
} from "./contracts.js";
import { validateAgentConnectionOversight } from "./policy.js";

const EVENT_INPUT_KEYS = [
  "grantId",
  "keyId",
  "namespace",
  "connectorId",
  "sourceRef",
  "operation",
  "purpose",
  "decision",
  "reasonCode",
  "rows",
  "bytes",
  "policyVersion",
  "accessRequestId",
] as const;

const EVENT_COLUMNS = `
  id, grant_id, key_id, namespace, connector_id, source_ref, operation,
  purpose, decision, reason_code, rows_count, bytes_count, policy_version,
  access_request_id, created_at`;

const ALERT_COLUMNS = `
  id, event_id, grant_id, key_id, namespace, kind, severity, recipient_roles,
  status, created_at`;

const REQUEST_COLUMNS = `
  id, key_id, namespace, grant_id, connector_id, source_ref, operation,
  purpose, requested_fields, requested_rows, requested_bytes, justification,
  requested_duration_seconds, status, approved_until, max_uses, used_count,
  created_at, decided_at, decided_by`;

const REQUEST_INPUT_KEYS = [
  "grantId",
  "connectorId",
  "sourceRef",
  "operation",
  "purpose",
  "requestedFields",
  "requestedRows",
  "requestedBytes",
  "justification",
  "requestedDurationSeconds",
] as const;

const EXACT_REQUEST_KEYS = [
  "grantId",
  "connectorId",
  "sourceRef",
  "operation",
  "purpose",
  "requestedFields",
  "requestedRows",
  "requestedBytes",
] as const;

const FIELD_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const OPERATION_SET = new Set<string>(AGENT_GATEWAY_OPERATIONS);
const AUTHORITY_CHANGE_REASONS = new Set([
  "key-mismatch",
  "namespace-mismatch",
  "grant-revoked",
  "grant-expired",
  "policy-version-mismatch",
  "authority-change",
  "unexpected-authority-field",
  "credential-inactive",
  "tenant-suspended",
  "agent-role-required",
  "authority-unavailable",
  "approval-unavailable",
  "approval-changed",
  "authority-revoked",
  "connector-unavailable",
  "connector-inactive",
  "source-authority-changed",
]);
const SOURCE_REF = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/;
const REASON_CODE = /^[a-z0-9][a-z0-9-]{0,63}$/;

type AccessAlertKind = AgentAccessAlert["kind"];

export interface AgentOversightStoreOptions {
  readonly now?: () => Date;
  readonly makeId?: () => string;
}

export interface AgentAccessEventRecord {
  readonly event: AgentAccessEvent;
  readonly alerts: readonly AgentAccessAlert[];
}

export interface AgentAccessEventFilter {
  readonly keyId?: string;
  readonly limit?: number;
}

export interface AgentAccessAlertFilter {
  readonly status?: AgentAccessAlert["status"];
  readonly limit?: number;
}

export interface AgentAccessRequestFilter {
  readonly status?: AgentAccessRequest["status"];
  readonly limit?: number;
}

export class InvalidAgentOversightRecordError extends Error {
  constructor(message = "invalid agent oversight record") {
    super(message);
    this.name = "InvalidAgentOversightRecordError";
  }
}

export class AgentOversightScopeError extends Error {
  constructor(message = "agent oversight record is outside administrative scope") {
    super(message);
    this.name = "AgentOversightScopeError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...keys, ...optional]);
  return (
    Object.keys(value).every((key) => allowed.has(key)) &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isNonEmptyString(value: unknown, maxLength = 512): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    value === value.trim()
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isUniqueFieldArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= MAX_GATEWAY_FIELDS &&
    value.every((field) =>
      typeof field === "string" && FIELD_IDENTIFIER.test(field)
    ) &&
    new Set(value).size === value.length
  );
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new InvalidAgentOversightRecordError("invalid agent oversight JSON");
  }
}

function asIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string" && Number.isFinite(Date.parse(value))) {
    return new Date(value).toISOString();
  }
  throw new InvalidAgentOversightRecordError("invalid agent oversight timestamp");
}

function asIsoOrNull(value: unknown): string | null {
  return value === null ? null : asIso(value);
}

function administrativeNamespace(identity: GatewayAdministrativeIdentity): string {
  if (identity.role !== "owner" && identity.role !== "admin") {
    throw new AgentOversightScopeError();
  }
  if (!isNonEmptyString(identity.namespace) && identity.namespace !== "") {
    throw new AgentOversightScopeError();
  }
  if (identity.namespace === "" && identity.role !== "owner") {
    throw new AgentOversightScopeError("only a root owner has global oversight authority");
  }
  return identity.namespace;
}

function viewerNamespace(identity: GatewayOversightViewerIdentity): string {
  if (
    identity.role !== "owner" &&
    identity.role !== "admin" &&
    identity.role !== "auditor"
  ) {
    throw new AgentOversightScopeError();
  }
  if (!isNonEmptyString(identity.namespace) && identity.namespace !== "") {
    throw new AgentOversightScopeError();
  }
  if (identity.namespace === "" && identity.role === "admin") {
    throw new AgentOversightScopeError("a root admin has no global oversight visibility");
  }
  return identity.namespace;
}

function resolveLimit(value: unknown): number {
  if (value === undefined) return 50;
  if (!isPositiveInteger(value) || value > 200) {
    throw new InvalidAgentOversightRecordError("invalid oversight list limit");
  }
  return value;
}

function validateEventInput(value: unknown): value is CreateAgentAccessEventInput {
  if (!isRecord(value) || !hasExactKeys(value, EVENT_INPUT_KEYS)) return false;
  if (value.grantId !== null && !isNonEmptyString(value.grantId)) return false;
  if (!isNonEmptyString(value.keyId)) return false;
  if (!isNonEmptyString(value.namespace)) return false;
  if (!isNonEmptyString(value.connectorId)) return false;
  if (!isNonEmptyString(value.sourceRef) || !SOURCE_REF.test(value.sourceRef)) return false;
  if (typeof value.operation !== "string" || !OPERATION_SET.has(value.operation)) return false;
  if (!isNonEmptyString(value.purpose, 256)) return false;
  if (
    value.decision !== "allowed" &&
    value.decision !== "denied" &&
    value.decision !== "error"
  ) return false;
  if (!isNonEmptyString(value.reasonCode, 64) || !REASON_CODE.test(value.reasonCode)) {
    return false;
  }
  if (!isNonNegativeInteger(value.rows) || value.rows > MAX_GATEWAY_ROWS) return false;
  if (!isNonNegativeInteger(value.bytes) || value.bytes > MAX_GATEWAY_BYTES) return false;
  if (
    value.policyVersion !== null &&
    (!isPositiveInteger(value.policyVersion))
  ) return false;
  return value.accessRequestId === null || isNonEmptyString(value.accessRequestId);
}

function validateRequestInput(value: unknown): value is CreateAgentAccessRequestInput {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, REQUEST_INPUT_KEYS, ["maxUses"])
  ) return false;
  if (!isNonEmptyString(value.grantId)) return false;
  if (!isNonEmptyString(value.connectorId)) return false;
  if (!isNonEmptyString(value.sourceRef) || !SOURCE_REF.test(value.sourceRef)) return false;
  if (value.operation !== "source-read") return false;
  if (!isNonEmptyString(value.purpose, 256)) return false;
  if (!isUniqueFieldArray(value.requestedFields)) return false;
  if (
    !isPositiveInteger(value.requestedRows) ||
    value.requestedRows > MAX_GATEWAY_ROWS
  ) return false;
  if (
    !isPositiveInteger(value.requestedBytes) ||
    value.requestedBytes > MAX_GATEWAY_BYTES
  ) return false;
  if (!isNonEmptyString(value.justification, 2_000)) return false;
  if (
    !isPositiveInteger(value.requestedDurationSeconds) ||
    value.requestedDurationSeconds < 60 ||
    value.requestedDurationSeconds > 86_400
  ) return false;
  return (
    value.maxUses === undefined ||
    (isPositiveInteger(value.maxUses) && value.maxUses <= 100)
  );
}

function validateExactRequest(value: unknown): value is ExactAgentAccessRequest {
  if (!isRecord(value) || !hasExactKeys(value, EXACT_REQUEST_KEYS)) return false;
  return validateRequestInput({
    ...value,
    justification: "exact temporary capability",
    requestedDurationSeconds: 60,
  });
}

function validateAgentIdentity(value: unknown): value is ResolvedAgentIdentity {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["keyId", "namespace", "role"]) &&
    isNonEmptyString(value.keyId) &&
    isNonEmptyString(value.namespace) &&
    value.role === "agent"
  );
}

function validateApprovalInput(value: unknown): value is AgentAccessApprovalInput {
  if (
    !isRecord(value) ||
    !Object.keys(value).every((key) =>
      ["durationSeconds", "maxUses", "note"].includes(key)
    )
  ) return false;
  if (
    value.durationSeconds !== undefined &&
    (
      !isPositiveInteger(value.durationSeconds) ||
      value.durationSeconds < 60 ||
      value.durationSeconds > 86_400
    )
  ) return false;
  if (
    value.maxUses !== undefined &&
    (!isPositiveInteger(value.maxUses) || value.maxUses > 100)
  ) return false;
  return value.note === undefined || isNonEmptyString(value.note, 1_000);
}

function validateDecisionInput(value: unknown): value is AgentAccessDecisionInput {
  return (
    isRecord(value) &&
    Object.keys(value).every((key) => key === "note") &&
    (value.note === undefined || isNonEmptyString(value.note, 1_000))
  );
}

function rowToEvent(value: unknown): AgentAccessEvent {
  if (!isRecord(value)) throw new InvalidAgentOversightRecordError();
  const event: AgentAccessEvent = {
    id: String(value.id),
    grantId: value.grant_id === null ? null : String(value.grant_id),
    keyId: String(value.key_id),
    namespace: String(value.namespace),
    connectorId: String(value.connector_id),
    sourceRef: String(value.source_ref),
    operation: String(value.operation) as AgentAccessEvent["operation"],
    purpose: String(value.purpose),
    decision: String(value.decision) as AgentAccessEvent["decision"],
    reasonCode: String(value.reason_code),
    rows: Number(value.rows_count),
    bytes: Number(value.bytes_count),
    policyVersion: value.policy_version === null ? null : Number(value.policy_version),
    accessRequestId: value.access_request_id === null
      ? null
      : String(value.access_request_id),
    createdAt: asIso(value.created_at),
  };
  if (!validateEventInput({
    grantId: event.grantId,
    keyId: event.keyId,
    namespace: event.namespace,
    connectorId: event.connectorId,
    sourceRef: event.sourceRef,
    operation: event.operation,
    purpose: event.purpose,
    decision: event.decision,
    reasonCode: event.reasonCode,
    rows: event.rows,
    bytes: event.bytes,
    policyVersion: event.policyVersion,
    accessRequestId: event.accessRequestId,
  }) || !isNonEmptyString(event.id)) {
    throw new InvalidAgentOversightRecordError("invalid durable agent access event");
  }
  return event;
}

function rowToAlert(value: unknown): AgentAccessAlert {
  if (!isRecord(value)) throw new InvalidAgentOversightRecordError();
  const roles = parseJson(value.recipient_roles);
  if (
    !Array.isArray(roles) ||
    !roles.every((role) => role === "owner" || role === "admin" || role === "auditor")
  ) {
    throw new InvalidAgentOversightRecordError("invalid durable alert recipients");
  }
  const kind = String(value.kind);
  const severity = String(value.severity);
  const status = String(value.status);
  if (
    ![
      "outside-scope",
      "rate-limit",
      "usage-threshold",
      "authority-change",
      "repeated-denial",
    ].includes(kind) ||
    !["warning", "critical"].includes(severity) ||
    !["open", "acknowledged", "resolved"].includes(status)
  ) {
    throw new InvalidAgentOversightRecordError("invalid durable agent access alert");
  }
  return {
    id: String(value.id),
    eventId: String(value.event_id),
    grantId: value.grant_id === null ? null : String(value.grant_id),
    keyId: String(value.key_id),
    namespace: String(value.namespace),
    kind: kind as AgentAccessAlert["kind"],
    severity: severity as AgentAccessAlert["severity"],
    recipientRoles: roles as AgentAccessAlert["recipientRoles"],
    status: status as AgentAccessAlert["status"],
    createdAt: asIso(value.created_at),
  };
}

function rowToRequest(value: unknown): AgentAccessRequest {
  if (!isRecord(value)) throw new InvalidAgentOversightRecordError();
  const requestedFields = parseJson(value.requested_fields);
  if (!isUniqueFieldArray(requestedFields)) {
    throw new InvalidAgentOversightRecordError("invalid durable request fields");
  }
  const status = String(value.status);
  if (!["pending", "approved", "denied", "expired", "consumed"].includes(status)) {
    throw new InvalidAgentOversightRecordError("invalid durable request status");
  }
  const request: AgentAccessRequest = {
    id: String(value.id),
    keyId: String(value.key_id),
    namespace: String(value.namespace),
    grantId: String(value.grant_id),
    connectorId: String(value.connector_id),
    sourceRef: String(value.source_ref),
    operation: "source-read",
    purpose: String(value.purpose),
    requestedFields,
    requestedRows: Number(value.requested_rows),
    requestedBytes: Number(value.requested_bytes),
    justification: String(value.justification),
    requestedDurationSeconds: Number(value.requested_duration_seconds),
    status: status as AgentAccessRequest["status"],
    approvedUntil: asIsoOrNull(value.approved_until),
    maxUses: Number(value.max_uses),
    usedCount: Number(value.used_count),
    createdAt: asIso(value.created_at),
    decidedAt: asIsoOrNull(value.decided_at),
    decidedBy: value.decided_by === null ? null : String(value.decided_by),
  };
  if (
    !isNonEmptyString(request.id) ||
    !isNonEmptyString(request.keyId) ||
    !isNonEmptyString(request.namespace) ||
    !validateRequestInput({
      grantId: request.grantId,
      connectorId: request.connectorId,
      sourceRef: request.sourceRef,
      operation: request.operation,
      purpose: request.purpose,
      requestedFields: request.requestedFields,
      requestedRows: request.requestedRows,
      requestedBytes: request.requestedBytes,
      justification: request.justification,
      requestedDurationSeconds: request.requestedDurationSeconds,
      maxUses: request.maxUses,
    }) ||
    !isNonNegativeInteger(request.usedCount) ||
    request.usedCount > request.maxUses
  ) {
    throw new InvalidAgentOversightRecordError("invalid durable agent access request");
  }
  return request;
}

function canonicalFields(fields: readonly string[]): string[] {
  return [...fields].sort((left, right) => left.localeCompare(right));
}

function resolveClock(value: Date | string | undefined, fallback: () => Date): Date {
  const date = value === undefined
    ? fallback()
    : value instanceof Date
      ? new Date(value.getTime())
      : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new InvalidAgentOversightRecordError("invalid request clock");
  }
  return date;
}

function floorWindow(date: Date, windowMs: number): string {
  return new Date(Math.floor(date.getTime() / windowMs) * windowMs).toISOString();
}

export class AgentOversightStore {
  private readonly now: () => Date;
  private readonly makeId: () => string;

  constructor(
    private readonly db: Db,
    options: AgentOversightStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.makeId = options.makeId ?? (() => ulid());
  }

  /**
   * Persist one content-free decision and synchronously derive every alert
   * required by the immutable oversight snapshot.
   */
  async recordEvent(
    input: CreateAgentAccessEventInput,
    oversight: AgentConnectionOversight,
  ): Promise<AgentAccessEventRecord> {
    if (!validateEventInput(input)) {
      throw new InvalidAgentOversightRecordError("invalid agent access event");
    }
    if (!validateAgentConnectionOversight(oversight)) {
      throw new InvalidAgentOversightRecordError("invalid agent connection oversight");
    }
    const createdAt = this.now();
    if (!Number.isFinite(createdAt.getTime())) {
      throw new InvalidAgentOversightRecordError("invalid oversight clock");
    }

    return this.db.transaction(async (tx) => {
      // D28 guarantees api_keys rows are durable identities even after revoke.
      // Locking that existing row serializes all event/count decisions for one
      // badge across replicas without inventing a second coordination store.
      const identityLock = await tx.query(
        "SELECT id FROM api_keys WHERE id = $1 FOR UPDATE",
        [input.keyId],
      );
      if (identityLock.rows.length !== 1) {
        throw new InvalidAgentOversightRecordError(
          "agent access event requires a durable badge identity",
        );
      }
      const inserted = await tx.query(
        `INSERT INTO agent_access_events
           (id, grant_id, key_id, namespace, connector_id, source_ref,
            operation, purpose, decision, reason_code, rows_count, bytes_count,
            policy_version, access_request_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         RETURNING ${EVENT_COLUMNS}`,
        [
          this.makeId(),
          input.grantId,
          input.keyId,
          input.namespace,
          input.connectorId,
          input.sourceRef,
          input.operation,
          input.purpose,
          input.decision,
          input.reasonCode,
          input.rows,
          input.bytes,
          input.policyVersion,
          input.accessRequestId,
          createdAt.toISOString(),
        ],
      );
      const event = rowToEvent(inserted.rows[0]);
      const alerts: AgentAccessAlert[] = [];

      if (event.decision === "denied" && event.reasonCode === "rate-limit") {
        alerts.push(await this.insertAlert(
          tx,
          event,
          oversight,
          "rate-limit",
          "critical",
          floorWindow(createdAt, 60_000),
        ));
      }

      if (event.decision === "denied" && event.reasonCode !== "rate-limit") {
        const immediateKind: AccessAlertKind = AUTHORITY_CHANGE_REASONS.has(
          event.reasonCode,
        )
          ? "authority-change"
          : "outside-scope";
        alerts.push(await this.insertAlert(
          tx,
          event,
          oversight,
          immediateKind,
          "critical",
          floorWindow(createdAt, 5 * 60_000),
        ));

        const windowStart = new Date(createdAt.getTime() - 5 * 60_000).toISOString();
        const count = await tx.query(
          `SELECT COUNT(*) AS n
             FROM agent_access_events
            WHERE key_id = $1
              AND grant_id IS NOT DISTINCT FROM $2
              AND source_ref = $3
              AND decision = 'denied'
              AND reason_code <> 'rate-limit'
              AND created_at >= $4`,
          [event.keyId, event.grantId, event.sourceRef, windowStart],
        );
        if (
          oversight.deniedAlertThreshold > 1 &&
          Number(count.rows[0]?.n) >= oversight.deniedAlertThreshold
        ) {
          alerts.push(await this.insertAlert(
            tx,
            event,
            oversight,
            "repeated-denial",
            "critical",
            floorWindow(createdAt, 5 * 60_000),
          ));
        }
      }

      if (event.decision === "allowed" && event.operation === "source-read") {
        const windowStart = new Date(createdAt.getTime() - 60 * 60_000).toISOString();
        const count = await tx.query(
          `SELECT COUNT(*) AS n
             FROM agent_access_events
            WHERE key_id = $1
              AND grant_id IS NOT DISTINCT FROM $2
              AND source_ref = $3
              AND decision = 'allowed'
              AND operation = 'source-read'
              AND created_at >= $4`,
          [event.keyId, event.grantId, event.sourceRef, windowStart],
        );
        if (Number(count.rows[0]?.n) >= oversight.usageAlertThreshold) {
          alerts.push(await this.insertAlert(
            tx,
            event,
            oversight,
            "usage-threshold",
            "warning",
            floorWindow(createdAt, 60 * 60_000),
          ));
        }
      }

      return { event, alerts };
    });
  }

  async listEvents(
    viewer: GatewayOversightViewerIdentity,
    filter: AgentAccessEventFilter = {},
  ): Promise<AgentAccessEvent[]> {
    const scope = viewerNamespace(viewer);
    const pattern = `${escapeLikePattern(scope)}/%`;
    if (filter.keyId !== undefined && !isNonEmptyString(filter.keyId)) {
      throw new InvalidAgentOversightRecordError("invalid event key filter");
    }
    const result = await this.db.query(
      `SELECT ${EVENT_COLUMNS}
         FROM agent_access_events
        WHERE ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND ($3::text IS NULL OR key_id = $3)
        ORDER BY created_at DESC, id DESC
        LIMIT $4`,
      [scope, pattern, filter.keyId ?? null, resolveLimit(filter.limit)],
    );
    return result.rows.map(rowToEvent);
  }

  async listAlerts(
    viewer: GatewayOversightViewerIdentity,
    filter: AgentAccessAlertFilter = {},
  ): Promise<AgentAccessAlert[]> {
    const scope = viewerNamespace(viewer);
    const pattern = `${escapeLikePattern(scope)}/%`;
    if (
      filter.status !== undefined &&
      !["open", "acknowledged", "resolved"].includes(filter.status)
    ) {
      throw new InvalidAgentOversightRecordError("invalid alert status filter");
    }
    const result = await this.db.query(
      `SELECT ${ALERT_COLUMNS}
         FROM agent_access_alerts
        WHERE ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND recipient_roles @> $3::jsonb
          AND ($4::text IS NULL OR status = $4)
        ORDER BY created_at DESC, id DESC
        LIMIT $5`,
      [
        scope,
        pattern,
        JSON.stringify([viewer.role]),
        filter.status ?? null,
        resolveLimit(filter.limit),
      ],
    );
    return result.rows.map(rowToAlert);
  }

  async acknowledgeAlert(
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
  ): Promise<boolean> {
    return this.db.transaction((tx) =>
      this.acknowledgeAlertInTransaction(tx, id, administrator, actor)
    );
  }

  async acknowledgeAlertInTransaction(
    tx: Db,
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
  ): Promise<boolean> {
    if (!isNonEmptyString(id) || !isNonEmptyString(actor)) {
      throw new InvalidAgentOversightRecordError("invalid alert acknowledgement");
    }
    const scope = administrativeNamespace(administrator);
    const pattern = `${escapeLikePattern(scope)}/%`;
    const result = await tx.query(
      `UPDATE agent_access_alerts
          SET status = 'acknowledged', acknowledged_at = $1, acknowledged_by = $2
        WHERE id = $3
          AND status = 'open'
          AND ($4 = '' OR namespace = $4 OR namespace LIKE $5 ESCAPE '\\')
       RETURNING id`,
      [this.now().toISOString(), actor, id, scope, pattern],
    );
    return result.rows.length === 1;
  }

  async createRequest(
    input: CreateAgentAccessRequestInput,
    identity: ResolvedAgentIdentity,
  ): Promise<AgentAccessRequest> {
    return this.db.transaction((tx) =>
      this.createRequestInTransaction(tx, input, identity)
    );
  }

  async createRequestInTransaction(
    tx: Db,
    input: CreateAgentAccessRequestInput,
    identity: ResolvedAgentIdentity,
  ): Promise<AgentAccessRequest> {
    if (!validateRequestInput(input) || !validateAgentIdentity(identity)) {
      throw new InvalidAgentOversightRecordError("invalid agent access request");
    }
    const createdAt = resolveClock(undefined, this.now);
    const expiresAt = new Date(
      createdAt.getTime() + input.requestedDurationSeconds * 1_000,
    );
    const requestedFields = canonicalFields(input.requestedFields);

    const binding = await tx.query(
        `SELECT g.oversight
           FROM agent_connection_grants g
           JOIN api_keys k ON k.id = g.key_id
            AND k.status = 'active'
            AND k.role = 'agent'
            AND k.namespace = g.namespace
          WHERE g.id = $1
            AND g.key_id = $2
            AND g.namespace = $3
            AND g.connector_id = $4
            AND g.status = 'active'
            AND (g.expires_at IS NULL OR g.expires_at > $5)
          FOR UPDATE`,
        [
          input.grantId,
          identity.keyId,
          identity.namespace,
          input.connectorId,
          createdAt.toISOString(),
        ],
      );
    if (binding.rows.length !== 1) {
      throw new InvalidAgentOversightRecordError(
        "agent access request grant binding is inactive or mismatched",
      );
    }
    const oversight = parseJson(binding.rows[0]?.oversight);
    if (!validateAgentConnectionOversight(oversight)) {
      throw new InvalidAgentOversightRecordError("invalid grant oversight");
    }
    if (oversight.accessRequests !== "allowed") {
      throw new InvalidAgentOversightRecordError("agent access requests are disabled");
    }

    const inserted = await tx.query(
        `INSERT INTO agent_access_requests
           (id, key_id, namespace, grant_id, connector_id, source_ref,
            operation, purpose, requested_fields, requested_rows,
            requested_bytes, justification, requested_duration_seconds,
            status, approved_until, max_uses, used_count, created_at,
            expires_at, decided_at, decided_by, decision_note)
         VALUES ($1, $2, $3, $4, $5, $6, 'source-read', $7, $8::jsonb, $9,
                 $10, $11, $12, 'pending', NULL, $13, 0, $14, $15,
                 NULL, NULL, NULL)
         RETURNING ${REQUEST_COLUMNS}`,
        [
          this.makeId(),
          identity.keyId,
          identity.namespace,
          input.grantId,
          input.connectorId,
          input.sourceRef,
          input.purpose,
          JSON.stringify(requestedFields),
          input.requestedRows,
          input.requestedBytes,
          input.justification,
          input.requestedDurationSeconds,
          input.maxUses ?? 1,
          createdAt.toISOString(),
          expiresAt.toISOString(),
        ],
      );
    return rowToRequest(inserted.rows[0]);
  }

  async listRequestsForAgent(
    identity: ResolvedAgentIdentity,
    filter: AgentAccessRequestFilter = {},
  ): Promise<AgentAccessRequest[]> {
    if (!validateAgentIdentity(identity)) {
      throw new InvalidAgentOversightRecordError("invalid agent identity");
    }
    await this.expireRequests(resolveClock(undefined, this.now));
    if (
      filter.status !== undefined &&
      !["pending", "approved", "denied", "expired", "consumed"].includes(filter.status)
    ) {
      throw new InvalidAgentOversightRecordError("invalid request status filter");
    }
    const result = await this.db.query(
      `SELECT ${REQUEST_COLUMNS.replace(/\b(id|key_id|namespace|grant_id|connector_id|source_ref|operation|purpose|requested_fields|requested_rows|requested_bytes|justification|requested_duration_seconds|status|approved_until|max_uses|used_count|created_at|decided_at|decided_by)\b/g, "r.$1")}
         FROM agent_access_requests r
         JOIN api_keys k ON k.id = r.key_id
          AND k.status = 'active'
          AND k.role = 'agent'
          AND k.namespace = r.namespace
        WHERE r.key_id = $1
          AND r.namespace = $2
          AND ($3::text IS NULL OR r.status = $3)
        ORDER BY r.created_at DESC, r.id DESC
        LIMIT $4`,
      [
        identity.keyId,
        identity.namespace,
        filter.status ?? null,
        resolveLimit(filter.limit),
      ],
    );
    return result.rows.map(rowToRequest);
  }

  async listRequests(
    viewer: GatewayOversightViewerIdentity,
    filter: AgentAccessRequestFilter = {},
  ): Promise<AgentAccessRequest[]> {
    await this.expireRequests(resolveClock(undefined, this.now));
    const scope = viewerNamespace(viewer);
    const pattern = `${escapeLikePattern(scope)}/%`;
    if (
      filter.status !== undefined &&
      !["pending", "approved", "denied", "expired", "consumed"].includes(filter.status)
    ) {
      throw new InvalidAgentOversightRecordError("invalid request status filter");
    }
    const result = await this.db.query(
      `SELECT ${REQUEST_COLUMNS}
         FROM agent_access_requests
        WHERE ($1 = '' OR namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND ($3::text IS NULL OR status = $3)
        ORDER BY created_at DESC, id DESC
        LIMIT $4`,
      [scope, pattern, filter.status ?? null, resolveLimit(filter.limit)],
    );
    return result.rows.map(rowToRequest);
  }

  async approveRequest(
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
    input: AgentAccessApprovalInput,
  ): Promise<AgentAccessRequest | null> {
    return this.db.transaction((tx) =>
      this.approveRequestInTransaction(tx, id, administrator, actor, input)
    );
  }

  async approveRequestInTransaction(
    tx: Db,
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
    input: AgentAccessApprovalInput,
  ): Promise<AgentAccessRequest | null> {
    if (
      !isNonEmptyString(id) ||
      !isNonEmptyString(actor) ||
      !validateApprovalInput(input)
    ) {
      throw new InvalidAgentOversightRecordError("invalid access request approval");
    }
    const decidedAt = resolveClock(undefined, this.now);
    const scope = administrativeNamespace(administrator);
    const pattern = `${escapeLikePattern(scope)}/%`;
    const selected = await tx.query(
        `SELECT r.*, g.oversight, g.status AS grant_status,
                g.expires_at AS grant_expires_at, k.status AS key_status
           FROM agent_access_requests r
           JOIN agent_connection_grants g ON g.id = r.grant_id
           JOIN api_keys k ON k.id = r.key_id
          WHERE r.id = $1
            AND ($2 = '' OR r.namespace = $2 OR r.namespace LIKE $3 ESCAPE '\\')
          FOR UPDATE`,
        [id, scope, pattern],
      );
    if (selected.rows.length !== 1) return null;
    const raw = selected.rows[0] as Record<string, unknown>;
    const request = rowToRequest(raw);
    if (
      request.status !== "pending" ||
      raw.key_status !== "active" ||
      raw.grant_status !== "active" ||
      Date.parse(asIso(raw.expires_at)) <= decidedAt.getTime() ||
      (
        raw.grant_expires_at !== null &&
        Date.parse(asIso(raw.grant_expires_at)) <= decidedAt.getTime()
      )
    ) {
      if (
        request.status === "pending" &&
        Date.parse(asIso(raw.expires_at)) <= decidedAt.getTime()
      ) {
        await tx.query(
          `UPDATE agent_access_requests
              SET status = 'expired'
            WHERE id = $1
              AND status = 'pending'
              AND ($2 = '' OR namespace = $2 OR namespace LIKE $3 ESCAPE '\\')`,
          [id, scope, pattern],
        );
      }
      return null;
    }
    const oversight = parseJson(raw.oversight);
    if (!validateAgentConnectionOversight(oversight)) {
      throw new InvalidAgentOversightRecordError("invalid grant oversight");
    }
    const durationSeconds = input.durationSeconds ??
      Math.min(request.requestedDurationSeconds, oversight.approvalTtlSeconds);
    const maxUses = input.maxUses ?? request.maxUses;
    if (
      durationSeconds > request.requestedDurationSeconds ||
      durationSeconds > oversight.approvalTtlSeconds ||
      maxUses > request.maxUses
    ) {
      throw new InvalidAgentOversightRecordError(
        "approval cannot widen the requested capability",
      );
    }
    const approvedUntil = new Date(
      decidedAt.getTime() + durationSeconds * 1_000,
    ).toISOString();
    const updated = await tx.query(
        `UPDATE agent_access_requests
            SET status = 'approved', approved_until = $1, max_uses = $2,
                decided_at = $3, decided_by = $4, decision_note = $5
          WHERE id = $6
            AND status = 'pending'
            AND ($7 = '' OR namespace = $7 OR namespace LIKE $8 ESCAPE '\\')
         RETURNING ${REQUEST_COLUMNS}`,
        [
          approvedUntil,
          maxUses,
          decidedAt.toISOString(),
          actor,
          input.note ?? null,
          id,
          scope,
          pattern,
        ],
      );
    return updated.rows.length === 1 ? rowToRequest(updated.rows[0]) : null;
  }

  async denyRequest(
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
    input: AgentAccessDecisionInput,
  ): Promise<AgentAccessRequest | null> {
    return this.db.transaction((tx) =>
      this.denyRequestInTransaction(tx, id, administrator, actor, input)
    );
  }

  async denyRequestInTransaction(
    tx: Db,
    id: string,
    administrator: GatewayAdministrativeIdentity,
    actor: string,
    input: AgentAccessDecisionInput,
  ): Promise<AgentAccessRequest | null> {
    if (
      !isNonEmptyString(id) ||
      !isNonEmptyString(actor) ||
      !validateDecisionInput(input)
    ) {
      throw new InvalidAgentOversightRecordError("invalid access request denial");
    }
    const scope = administrativeNamespace(administrator);
    const pattern = `${escapeLikePattern(scope)}/%`;
    const decidedAt = resolveClock(undefined, this.now).toISOString();
    const selected = await tx.query(
      `SELECT ${REQUEST_COLUMNS}
         FROM agent_access_requests
        WHERE id = $1
          AND ($2 = '' OR namespace = $2 OR namespace LIKE $3 ESCAPE '\\')
        FOR UPDATE`,
      [id, scope, pattern],
    );
    if (selected.rows.length !== 1) return null;
    const request = rowToRequest(selected.rows[0]);
    if (request.status !== "pending") return null;
    const result = await tx.query(
      `UPDATE agent_access_requests
          SET status = 'denied', decided_at = $1, decided_by = $2,
              decision_note = $3
        WHERE id = $4
          AND status = 'pending'
          AND expires_at > $1
          AND ($5 = '' OR namespace = $5 OR namespace LIKE $6 ESCAPE '\\')
       RETURNING ${REQUEST_COLUMNS}`,
      [
        decidedAt,
        actor,
        input.note ?? null,
        id,
        scope,
        pattern,
      ],
    );
    return result.rows.length === 1 ? rowToRequest(result.rows[0]) : null;
  }

  async validateApprovedRequest(
    id: string,
    expected: ExactAgentAccessRequest,
    identity: ResolvedAgentIdentity,
    now?: Date | string,
  ): Promise<AgentAccessRequest | null> {
    if (
      !isNonEmptyString(id) ||
      !validateExactRequest(expected) ||
      !validateAgentIdentity(identity)
    ) {
      throw new InvalidAgentOversightRecordError("invalid exact access request");
    }
    const checkedAt = resolveClock(now, this.now).toISOString();
    const result = await this.db.query(
      `SELECT ${REQUEST_COLUMNS.replace(/\b(id|key_id|namespace|grant_id|connector_id|source_ref|operation|purpose|requested_fields|requested_rows|requested_bytes|justification|requested_duration_seconds|status|approved_until|max_uses|used_count|created_at|decided_at|decided_by)\b/g, "r.$1")}
         FROM agent_access_requests r
         JOIN agent_connection_grants g ON g.id = r.grant_id
          AND g.key_id = r.key_id
          AND g.namespace = r.namespace
          AND g.connector_id = r.connector_id
          AND g.status = 'active'
          AND (g.expires_at IS NULL OR g.expires_at > $12)
         JOIN api_keys k ON k.id = r.key_id
          AND k.status = 'active'
          AND k.role = 'agent'
          AND k.namespace = r.namespace
        WHERE r.id = $1
          AND r.key_id = $2
          AND r.namespace = $3
          AND r.grant_id = $4
          AND r.connector_id = $5
          AND r.source_ref = $6
          AND r.operation = $7
          AND r.purpose = $8
          AND r.requested_fields = $9::jsonb
          AND r.requested_rows = $10
          AND r.requested_bytes = $11
          AND r.status = 'approved'
          AND r.approved_until > $12
          AND r.used_count < r.max_uses`,
      [
        id,
        identity.keyId,
        identity.namespace,
        expected.grantId,
        expected.connectorId,
        expected.sourceRef,
        expected.operation,
        expected.purpose,
        JSON.stringify(canonicalFields(expected.requestedFields)),
        expected.requestedRows,
        expected.requestedBytes,
        checkedAt,
      ],
    );
    return result.rows.length === 1 ? rowToRequest(result.rows[0]) : null;
  }

  async consumeApprovedRequest(
    id: string,
    expected: ExactAgentAccessRequest,
    identity: ResolvedAgentIdentity,
    now?: Date | string,
  ): Promise<AgentAccessRequest | null> {
    if (
      !isNonEmptyString(id) ||
      !validateExactRequest(expected) ||
      !validateAgentIdentity(identity)
    ) {
      throw new InvalidAgentOversightRecordError("invalid exact access request");
    }
    const checkedAt = resolveClock(now, this.now).toISOString();
    const result = await this.db.query(
      `UPDATE agent_access_requests r
          SET used_count = r.used_count + 1,
              status = CASE
                WHEN r.used_count + 1 >= r.max_uses THEN 'consumed'
                ELSE 'approved'
              END
         FROM agent_connection_grants g, api_keys k
        WHERE r.id = $1
          AND r.key_id = $2
          AND r.namespace = $3
          AND r.grant_id = $4
          AND r.connector_id = $5
          AND r.source_ref = $6
          AND r.operation = $7
          AND r.purpose = $8
          AND r.requested_fields = $9::jsonb
          AND r.requested_rows = $10
          AND r.requested_bytes = $11
          AND r.status = 'approved'
          AND r.approved_until > $12
          AND r.used_count < r.max_uses
          AND g.id = r.grant_id
          AND g.key_id = r.key_id
          AND g.namespace = r.namespace
          AND g.connector_id = r.connector_id
          AND g.status = 'active'
          AND (g.expires_at IS NULL OR g.expires_at > $12)
          AND k.id = r.key_id
          AND k.status = 'active'
          AND k.role = 'agent'
          AND k.namespace = r.namespace
       RETURNING ${REQUEST_COLUMNS.replace(/\b(id|key_id|namespace|grant_id|connector_id|source_ref|operation|purpose|requested_fields|requested_rows|requested_bytes|justification|requested_duration_seconds|status|approved_until|max_uses|used_count|created_at|decided_at|decided_by)\b/g, "r.$1")}`,
      [
        id,
        identity.keyId,
        identity.namespace,
        expected.grantId,
        expected.connectorId,
        expected.sourceRef,
        expected.operation,
        expected.purpose,
        JSON.stringify(canonicalFields(expected.requestedFields)),
        expected.requestedRows,
        expected.requestedBytes,
        checkedAt,
      ],
    );
    return result.rows.length === 1 ? rowToRequest(result.rows[0]) : null;
  }

  private async expireRequests(now: Date): Promise<void> {
    await this.db.query(
      `UPDATE agent_access_requests
          SET status = 'expired'
        WHERE (status = 'pending' AND expires_at <= $1)
           OR (status = 'approved' AND approved_until <= $1)`,
      [now.toISOString()],
    );
  }

  private async insertAlert(
    tx: Db,
    event: AgentAccessEvent,
    oversight: AgentConnectionOversight,
    kind: AccessAlertKind,
    severity: AgentAccessAlert["severity"],
    windowStart: string,
  ): Promise<AgentAccessAlert> {
    const dedupeKey = JSON.stringify([
      event.keyId,
      event.grantId,
      event.sourceRef,
      kind,
      windowStart,
    ]);
    const inserted = await tx.query(
      `INSERT INTO agent_access_alerts
         (id, event_id, grant_id, key_id, namespace, kind, severity,
          recipient_roles, status, dedupe_key, created_at,
          acknowledged_at, acknowledged_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'open', $9, $10, NULL, NULL)
       ON CONFLICT DO NOTHING
       RETURNING ${ALERT_COLUMNS}`,
      [
        this.makeId(),
        event.id,
        event.grantId,
        event.keyId,
        event.namespace,
        kind,
        severity,
        JSON.stringify(oversight.recipientRoles),
        dedupeKey,
        event.createdAt,
      ],
    );
    if (inserted.rows.length === 1) return rowToAlert(inserted.rows[0]);
    const existing = await tx.query(
      `SELECT ${ALERT_COLUMNS}
         FROM agent_access_alerts
        WHERE dedupe_key = $1 AND status = 'open'`,
      [dedupeKey],
    );
    if (existing.rows.length !== 1) {
      throw new InvalidAgentOversightRecordError("alert deduplication failed");
    }
    return rowToAlert(existing.rows[0]);
  }
}
