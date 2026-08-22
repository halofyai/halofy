import {
  AGENT_NOTIFICATION_ROLES,
  AGENT_GATEWAY_OPERATIONS,
  DATA_SENSITIVITIES,
  MAX_GATEWAY_BYTES,
  MAX_GATEWAY_FIELDS,
  MAX_GATEWAY_ROWS,
  type AgentAuthorizationDecision,
  type AgentAuthorizationInput,
  type AgentConnectionOversight,
  type AgentConnectionGrant,
  type AgentGatewayOperation,
  type AgentGatewayRequest,
  type GatewayDataSensitivity,
} from "./contracts.js";

const GRANT_KEYS = [
  "id",
  "keyId",
  "namespace",
  "connectorId",
  "allowedOperations",
  "allowedSourceRefs",
  "allowedFields",
  "allowedPurposes",
  "maxSensitivity",
  "maxRows",
  "maxBytes",
  "policyVersion",
  "status",
  "expiresAt",
  "oversight",
] as const;

const OVERSIGHT_KEYS = [
  "maxRequestsPerMinute",
  "usageAlertThreshold",
  "deniedAlertThreshold",
  "recipientRoles",
  "accessRequests",
  "approvalTtlSeconds",
] as const;

const REQUEST_KEYS = [
  "operation",
  "connectorId",
  "sourceRef",
  "purpose",
  "requestedFields",
  "requestedRows",
  "requestedBytes",
] as const;

const FIELD_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SOURCE_REF = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const OPERATION_SET = new Set<string>(AGENT_GATEWAY_OPERATIONS);
const NOTIFICATION_ROLE_SET = new Set<string>(AGENT_NOTIFICATION_ROLES);
const SENSITIVITY_RANK = new Map<GatewayDataSensitivity, number>(
  DATA_SENSITIVITIES.map((value, index) => [value, index]),
);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value === value.trim();
}

function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function isUniqueStringArray(
  value: unknown,
  itemValidator: (item: string) => boolean = isNonEmptyString,
  requireNonEmpty = true,
): value is string[] {
  if (!Array.isArray(value) || (requireNonEmpty && value.length === 0)) return false;
  if (!value.every((item) => typeof item === "string" && itemValidator(item))) return false;
  return new Set(value).size === value.length;
}

function isOperation(value: unknown): value is AgentGatewayOperation {
  return typeof value === "string" && OPERATION_SET.has(value);
}

function isSensitivity(value: unknown): value is GatewayDataSensitivity {
  return typeof value === "string" && SENSITIVITY_RANK.has(value as GatewayDataSensitivity);
}

function isIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    ISO_TIMESTAMP.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function validAllowedFields(
  value: unknown,
  allowedSourceRefs: readonly string[],
): value is Readonly<Record<string, readonly string[]>> {
  if (!isRecord(value)) return false;
  const fieldSources = Object.keys(value);
  if (fieldSources.length !== allowedSourceRefs.length) return false;
  const sourceSet = new Set(allowedSourceRefs);
  if (!fieldSources.every((sourceRef) => sourceSet.has(sourceRef))) return false;
  return allowedSourceRefs.every((sourceRef) =>
    isUniqueStringArray(value[sourceRef], (field) => FIELD_IDENTIFIER.test(field)) &&
    (value[sourceRef] as string[]).length <= MAX_GATEWAY_FIELDS
  );
}

/** Runtime validation for immutable monitoring settings loaded from JSON. */
export function validateAgentConnectionOversight(
  value: unknown,
): value is AgentConnectionOversight {
  if (!isRecord(value) || !hasOnlyKeys(value, OVERSIGHT_KEYS)) return false;
  if (!OVERSIGHT_KEYS.every((key) => Object.hasOwn(value, key))) return false;
  if (
    !isPositiveSafeInteger(value.maxRequestsPerMinute) ||
    value.maxRequestsPerMinute > 10_000
  ) return false;
  if (!isPositiveSafeInteger(value.usageAlertThreshold)) return false;
  if (!isPositiveSafeInteger(value.deniedAlertThreshold)) return false;
  if (
    !isUniqueStringArray(
      value.recipientRoles,
      (role) => NOTIFICATION_ROLE_SET.has(role),
    )
  ) return false;
  if (value.accessRequests !== "allowed" && value.accessRequests !== "disabled") {
    return false;
  }
  return (
    isPositiveSafeInteger(value.approvalTtlSeconds) &&
    value.approvalTtlSeconds >= 60 &&
    value.approvalTtlSeconds <= 86_400
  );
}

/** Runtime validation for authority loaded from durable JSON. */
export function validateAgentConnectionGrant(
  value: unknown,
): value is AgentConnectionGrant {
  if (!isRecord(value) || !hasOnlyKeys(value, GRANT_KEYS)) return false;
  if (!GRANT_KEYS.every((key) => Object.hasOwn(value, key))) return false;
  if (!isNonEmptyString(value.id)) return false;
  if (!isNonEmptyString(value.keyId)) return false;
  if (!isNonEmptyString(value.namespace)) return false;
  if (!isNonEmptyString(value.connectorId)) return false;
  if (!isUniqueStringArray(value.allowedOperations, isOperation)) return false;
  if (!isUniqueStringArray(value.allowedSourceRefs, (ref) => SOURCE_REF.test(ref))) return false;
  if (!validAllowedFields(value.allowedFields, value.allowedSourceRefs)) return false;
  if (!isUniqueStringArray(value.allowedPurposes)) return false;
  if (!isSensitivity(value.maxSensitivity)) return false;
  if (!isPositiveSafeInteger(value.maxRows) || value.maxRows > MAX_GATEWAY_ROWS) return false;
  if (!isPositiveSafeInteger(value.maxBytes) || value.maxBytes > MAX_GATEWAY_BYTES) return false;
  if (!isPositiveSafeInteger(value.policyVersion)) return false;
  if (value.status !== "active" && value.status !== "revoked") return false;
  if (value.expiresAt !== null && !isIsoTimestamp(value.expiresAt)) return false;
  return validateAgentConnectionOversight(value.oversight);
}

function validateAgentGatewayRequest(value: unknown): value is AgentGatewayRequest {
  if (!isRecord(value) || !hasOnlyKeys(value, REQUEST_KEYS)) return false;
  if (!REQUEST_KEYS.slice(0, 4).every((key) => Object.hasOwn(value, key))) return false;
  if (!isOperation(value.operation)) return false;
  if (!isNonEmptyString(value.connectorId)) return false;
  if (!isNonEmptyString(value.sourceRef) || !SOURCE_REF.test(value.sourceRef)) return false;
  if (!isNonEmptyString(value.purpose)) return false;
  if (
    value.requestedFields !== undefined &&
    !isUniqueStringArray(
      value.requestedFields,
      (field) => FIELD_IDENTIFIER.test(field),
      false,
    )
  ) return false;
  if (value.requestedRows !== undefined && !isPositiveSafeInteger(value.requestedRows)) return false;
  if (value.requestedBytes !== undefined && !isPositiveSafeInteger(value.requestedBytes)) return false;
  return true;
}

function denied(reason: Exclude<AgentAuthorizationDecision, { allowed: true }>["reason"]): AgentAuthorizationDecision {
  return { allowed: false, reason };
}

function resolveNow(value: AgentAuthorizationInput["now"]): number | null {
  if (value === undefined) return Date.now();
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  if (!isIsoTimestamp(value)) return null;
  return Date.parse(value);
}

/**
 * Pure, fail-closed authorization. This function narrows authority; it never
 * calls a connector, reads a database, mutates the grant, or trusts a caller
 * to supply identity or policy fields.
 */
export function authorizeAgentRequest(
  input: AgentAuthorizationInput,
): AgentAuthorizationDecision {
  if (!isRecord(input)) return denied("invalid-request");
  const grant = input.grant;
  if (!validateAgentConnectionGrant(grant)) return denied("invalid-grant");
  if (!validateAgentGatewayRequest(input.request)) return denied("invalid-request");
  if (!isRecord(input.identity)) return denied("invalid-request");
  if (!isNonEmptyString(input.identity.keyId) || !isNonEmptyString(input.identity.namespace)) {
    return denied("invalid-request");
  }
  if (input.identity.role !== "agent") return denied("invalid-request");
  if (!isSensitivity(input.resourceSensitivity)) return denied("invalid-request");

  const now = resolveNow(input.now);
  if (now === null) return denied("invalid-request");
  if (
    input.expectedPolicyVersion !== undefined &&
    !isPositiveSafeInteger(input.expectedPolicyVersion)
  ) return denied("invalid-request");

  if (input.identity.keyId !== grant.keyId) return denied("key-mismatch");
  if (input.identity.namespace !== grant.namespace) return denied("namespace-mismatch");
  if (grant.status !== "active") return denied("grant-revoked");
  if (grant.expiresAt !== null && Date.parse(grant.expiresAt) <= now) {
    return denied("grant-expired");
  }
  if (
    input.expectedPolicyVersion !== undefined &&
    input.expectedPolicyVersion !== grant.policyVersion
  ) return denied("policy-version-mismatch");

  const request = input.request;
  if (!grant.allowedOperations.includes(request.operation)) return denied("operation-denied");
  if (request.connectorId !== grant.connectorId) return denied("connector-denied");
  if (!grant.allowedSourceRefs.includes(request.sourceRef)) return denied("source-ref-denied");
  if (!grant.allowedPurposes.includes(request.purpose)) return denied("purpose-denied");
  if (
    (SENSITIVITY_RANK.get(input.resourceSensitivity) ?? Number.POSITIVE_INFINITY) >
    (SENSITIVITY_RANK.get(grant.maxSensitivity) ?? -1)
  ) return denied("sensitivity-denied");

  const allowlistedFields = grant.allowedFields[request.sourceRef] ?? [];
  const requested = request.requestedFields === undefined
    ? null
    : new Set(request.requestedFields);
  const effectiveFields = requested === null
    ? [...allowlistedFields]
    : allowlistedFields.filter((field) => requested.has(field));
  if (effectiveFields.length === 0) return denied("empty-field-intersection");

  return {
    allowed: true,
    grantId: grant.id,
    keyId: grant.keyId,
    namespace: grant.namespace,
    connectorId: grant.connectorId,
    sourceRef: request.sourceRef,
    purpose: request.purpose,
    operation: request.operation,
    effectiveFields,
    maxRows: Math.min(request.requestedRows ?? grant.maxRows, grant.maxRows),
    maxBytes: Math.min(request.requestedBytes ?? grant.maxBytes, grant.maxBytes),
    policyVersion: grant.policyVersion,
  };
}
