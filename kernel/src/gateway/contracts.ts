/**
 * Pure public contracts for the HaloMem Agent Connector reference monitor.
 *
 * Authority never comes from an agent payload. `AgentAuthorizationInput`
 * combines a server-resolved identity, an immutable stored grant, and the
 * narrow request shape agents are allowed to supply.
 */

export const AGENT_GATEWAY_OPERATIONS = [
  "read",
  "search",
  "write",
  "fault",
  "assemble",
  "stats",
  "live-result",
  "pin",
  "unpin",
  "share",
  "forget",
  "source-read",
] as const;

export type AgentGatewayOperation = (typeof AGENT_GATEWAY_OPERATIONS)[number];

export const DATA_SENSITIVITIES = [
  "public",
  "internal",
  "confidential",
  "restricted",
] as const;

export type GatewayDataSensitivity = (typeof DATA_SENSITIVITIES)[number];

export const AGENT_NOTIFICATION_ROLES = ["owner", "admin", "auditor"] as const;

export type AgentNotificationRole = (typeof AGENT_NOTIFICATION_ROLES)[number];

/** Immutable monitoring and step-up settings stored with a standing grant. */
export interface AgentConnectionOversight {
  readonly maxRequestsPerMinute: number;
  readonly usageAlertThreshold: number;
  readonly deniedAlertThreshold: number;
  readonly recipientRoles: readonly AgentNotificationRole[];
  readonly accessRequests: "allowed" | "disabled";
  readonly approvalTtlSeconds: number;
}

export const DEFAULT_AGENT_CONNECTION_OVERSIGHT: AgentConnectionOversight =
  Object.freeze({
    maxRequestsPerMinute: 60,
    usageAlertThreshold: 100,
    deniedAlertThreshold: 1,
    recipientRoles: Object.freeze(["owner", "admin"]) as readonly AgentNotificationRole[],
    accessRequests: "allowed",
    approvalTtlSeconds: 3_600,
  });

/** Hard platform ceilings; individual grants may only tighten them. */
export const MAX_GATEWAY_ROWS = 1_000;
export const MAX_GATEWAY_BYTES = 10 * 1024 * 1024;
export const MAX_GATEWAY_FIELDS = 64;
export const MAX_GATEWAY_QUERY_TERMS = 32;
export const MAX_GATEWAY_QUERY_TERM_LENGTH = 128;

/** Bounds for temporary access requests (M8A); the transport schemas mirror these. */
export const MIN_GATEWAY_REQUEST_DURATION_SECONDS = 60;
export const MAX_GATEWAY_REQUEST_DURATION_SECONDS = 86_400;
export const MAX_GATEWAY_REQUEST_USES = 100;

/** Immutable authority snapshot persisted for one badge and policy version. */
export interface AgentConnectionGrant {
  readonly id: string;
  readonly keyId: string;
  readonly namespace: string;
  readonly connectorId: string;
  readonly allowedOperations: readonly AgentGatewayOperation[];
  readonly allowedSourceRefs: readonly string[];
  readonly allowedFields: Readonly<Record<string, readonly string[]>>;
  readonly allowedPurposes: readonly string[];
  readonly maxSensitivity: GatewayDataSensitivity;
  readonly maxRows: number;
  readonly maxBytes: number;
  readonly policyVersion: number;
  readonly status: "active" | "revoked";
  readonly expiresAt: string | null;
  readonly oversight: AgentConnectionOversight;
}

/** Identity fields resolved from the badge by HaloMem, never from a payload. */
export interface ResolvedAgentIdentity {
  readonly keyId: string;
  readonly namespace: string;
  readonly role: "agent";
}

/** Server-resolved management identity accepted by the durable grant store. */
export interface GatewayAdministrativeIdentity {
  readonly namespace: string;
  readonly role: "owner" | "admin";
}

/** Read-only oversight identity; auditors may inspect but never mutate. */
export interface GatewayOversightViewerIdentity {
  readonly namespace: string;
  readonly role: "owner" | "admin" | "auditor";
}

/**
 * The policy-relevant untrusted request surface accepted by the evaluator.
 * Natural-language query content is deliberately handled by the bounded
 * connector executor, not by authorization.
 * It intentionally contains no badge, namespace, grant, credential, SQL,
 * backend URL, principal, group, predicate, or policy fields.
 */
export interface AgentGatewayRequest {
  readonly operation: AgentGatewayOperation;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly purpose: string;
  readonly requestedFields?: readonly string[];
  readonly requestedRows?: number;
  readonly requestedBytes?: number;
}

/** Untrusted source-read payload accepted over REST/MCP. */
export interface AgentSourceReadInput extends AgentGatewayRequest {
  readonly operation: "source-read";
  readonly grantId: string;
  readonly accessRequestId?: string;
  readonly query: string;
  readonly expectedPolicyVersion?: number;
}

/** Safe response projection; backend credentials and unselected fields never appear. */
export interface AgentSourceReadResult {
  readonly grantId: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly fields: readonly string[];
  readonly rows: readonly Record<string, unknown>[];
  readonly bytes: number;
  readonly truncated: boolean;
  readonly policyVersion: number;
}

/** Admin input whose identity/version fields are resolved server-side. */
export interface CreateAgentConnectionGrantInput {
  readonly keyId: string;
  readonly connectorId: string;
  readonly allowedOperations: readonly AgentGatewayOperation[];
  readonly allowedSourceRefs: readonly string[];
  readonly allowedFields: Readonly<Record<string, readonly string[]>>;
  readonly allowedPurposes: readonly string[];
  readonly maxSensitivity: GatewayDataSensitivity;
  readonly maxRows: number;
  readonly maxBytes: number;
  readonly expiresAt: string | null;
  /** Omission preserves compatibility and resolves to the conservative default. */
  readonly oversight?: AgentConnectionOversight;
}

export interface AgentAccessEvent {
  readonly id: string;
  readonly grantId: string | null;
  readonly keyId: string;
  readonly namespace: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly operation: AgentGatewayOperation;
  readonly purpose: string;
  readonly decision: "allowed" | "denied" | "error";
  readonly reasonCode: string;
  readonly rows: number;
  readonly bytes: number;
  readonly policyVersion: number | null;
  readonly accessRequestId: string | null;
  readonly createdAt: string;
}

export interface CreateAgentAccessEventInput {
  readonly grantId: string | null;
  readonly keyId: string;
  readonly namespace: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly operation: AgentGatewayOperation;
  readonly purpose: string;
  readonly decision: "allowed" | "denied" | "error";
  readonly reasonCode: string;
  readonly rows: number;
  readonly bytes: number;
  readonly policyVersion: number | null;
  readonly accessRequestId: string | null;
}

export interface AgentAccessAlert {
  readonly id: string;
  readonly eventId: string;
  readonly grantId: string | null;
  readonly keyId: string;
  readonly namespace: string;
  readonly kind:
    | "outside-scope"
    | "rate-limit"
    | "usage-threshold"
    | "authority-change"
    | "repeated-denial";
  readonly severity: "warning" | "critical";
  readonly recipientRoles: readonly AgentNotificationRole[];
  readonly status: "open" | "acknowledged" | "resolved";
  readonly createdAt: string;
}

/**
 * Content-free grant metadata for oversight after authority is no longer
 * active. This shape must never be passed to the authorization evaluator.
 */
export interface AgentConnectionGrantHistoryMetadata {
  readonly id: string;
  readonly keyId: string;
  readonly namespace: string;
  readonly connectorId: string;
  readonly policyVersion: number;
  readonly status: "active" | "revoked";
  readonly expiresAt: string | null;
  readonly oversight: AgentConnectionOversight;
}

export interface AgentAccessRequest {
  readonly id: string;
  readonly keyId: string;
  readonly namespace: string;
  readonly grantId: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly operation: "source-read";
  readonly purpose: string;
  readonly requestedFields: readonly string[];
  readonly requestedRows: number;
  readonly requestedBytes: number;
  readonly justification: string;
  readonly requestedDurationSeconds: number;
  readonly status: "pending" | "approved" | "denied" | "expired" | "consumed";
  readonly approvedUntil: string | null;
  readonly maxUses: number;
  readonly usedCount: number;
  readonly createdAt: string;
  readonly decidedAt: string | null;
  readonly decidedBy: string | null;
}

export interface CreateAgentAccessRequestInput {
  readonly grantId: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly operation: "source-read";
  readonly purpose: string;
  readonly requestedFields: readonly string[];
  readonly requestedRows: number;
  readonly requestedBytes: number;
  readonly justification: string;
  readonly requestedDurationSeconds: number;
  readonly maxUses?: number;
}

/** Exact temporary capability requested by a badge and rechecked before use. */
export interface ExactAgentAccessRequest {
  readonly grantId: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly operation: "source-read";
  readonly purpose: string;
  readonly requestedFields: readonly string[];
  readonly requestedRows: number;
  readonly requestedBytes: number;
}

export interface AgentAccessApprovalInput {
  readonly durationSeconds?: number;
  readonly maxUses?: number;
  readonly note?: string;
}

export interface AgentAccessDecisionInput {
  readonly note?: string;
}

/** Whether and how a badge may escalate for temporary extra access. */
export interface AgentAccessRequestPolicy {
  readonly enabled: boolean;
  readonly maxDurationSeconds: number;
  readonly approvalTtlSeconds: number;
  readonly maxUsesCap: number;
}

/**
 * Badge-visible description of one active grant (`describe_access`). Only
 * ever returned to the badge the grant is bound to; it mirrors the authority
 * the badge already holds and never enumerates other sources or badges.
 */
export interface AgentAccessDescription {
  readonly grantId: string;
  readonly connectorId: string;
  readonly allowedOperations: readonly AgentGatewayOperation[];
  readonly allowedSourceRefs: readonly string[];
  readonly allowedFields: Readonly<Record<string, readonly string[]>>;
  readonly allowedPurposes: readonly string[];
  readonly maxRows: number;
  readonly maxBytes: number;
  readonly maxSensitivity: GatewayDataSensitivity;
  readonly expiresAt: string | null;
  readonly policyVersion: number;
  readonly accessRequests: AgentAccessRequestPolicy;
  /** Present only when access requests are enabled for this grant. */
  readonly hint?: string;
}

export interface AgentAuthorizationInput {
  readonly identity: ResolvedAgentIdentity;
  readonly grant: AgentConnectionGrant;
  readonly request: AgentGatewayRequest;
  /** Server-resolved M7 classification for the selected resource/result. */
  readonly resourceSensitivity: GatewayDataSensitivity;
  /** Durable caller expectation used to reject a stale authority snapshot. */
  readonly expectedPolicyVersion?: number;
  /** Injectable clock for deterministic tests. Defaults to the current time. */
  readonly now?: string | Date;
}

export type AgentAuthorizationDenialReason =
  | "invalid-grant"
  | "invalid-request"
  | "key-mismatch"
  | "namespace-mismatch"
  | "grant-revoked"
  | "grant-expired"
  | "policy-version-mismatch"
  | "operation-denied"
  | "connector-denied"
  | "source-ref-denied"
  | "purpose-denied"
  | "sensitivity-denied"
  | "empty-field-intersection";

export interface AgentAuthorizationAllowed {
  readonly allowed: true;
  readonly grantId: string;
  readonly keyId: string;
  readonly namespace: string;
  readonly connectorId: string;
  readonly sourceRef: string;
  readonly purpose: string;
  readonly operation: AgentGatewayOperation;
  readonly effectiveFields: readonly string[];
  readonly maxRows: number;
  readonly maxBytes: number;
  readonly policyVersion: number;
}

export interface AgentAuthorizationDenied {
  readonly allowed: false;
  readonly reason: AgentAuthorizationDenialReason;
}

export type AgentAuthorizationDecision =
  | AgentAuthorizationAllowed
  | AgentAuthorizationDenied;
