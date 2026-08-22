import { describe, expect, it } from "vitest";

import type {
  AgentAuthorizationInput,
  AgentConnectionGrant,
} from "../src/gateway/contracts.js";
import {
  authorizeAgentRequest,
  validateAgentConnectionGrant,
  validateAgentConnectionOversight,
} from "../src/gateway/policy.js";

const OVERSIGHT = {
  maxRequestsPerMinute: 60,
  usageAlertThreshold: 100,
  deniedAlertThreshold: 1,
  recipientRoles: ["owner", "admin"],
  accessRequests: "allowed",
  approvalTtlSeconds: 3_600,
} as const;

const GRANT: AgentConnectionGrant = {
  id: "grant-01",
  keyId: "key-support-agent",
  namespace: "acme/support/agent-1",
  connectorId: "postgres-crm",
  allowedOperations: ["read", "search", "source-read"],
  allowedSourceRefs: ["customers", "orders"],
  allowedFields: {
    customers: ["customer_id", "display_name", "segment"],
    orders: ["order_id", "status"],
  },
  allowedPurposes: ["support-case", "order-status"],
  maxSensitivity: "confidential",
  maxRows: 25,
  maxBytes: 32_768,
  policyVersion: 3,
  status: "active",
  expiresAt: "2030-01-01T00:00:00.000Z",
  oversight: OVERSIGHT,
};

describe("validateAgentConnectionOversight", () => {
  it("accepts the conservative immutable oversight profile", () => {
    expect(validateAgentConnectionOversight(OVERSIGHT)).toBe(true);
  });

  it.each([
    ["unknown property", { ...OVERSIGHT, webhookUrl: "https://example.com" }],
    ["zero request rate", { ...OVERSIGHT, maxRequestsPerMinute: 0 }],
    ["excessive request rate", { ...OVERSIGHT, maxRequestsPerMinute: 10_001 }],
    ["zero usage threshold", { ...OVERSIGHT, usageAlertThreshold: 0 }],
    ["zero denial threshold", { ...OVERSIGHT, deniedAlertThreshold: 0 }],
    ["duplicate recipients", { ...OVERSIGHT, recipientRoles: ["owner", "owner"] }],
    ["invalid recipient", { ...OVERSIGHT, recipientRoles: ["member"] }],
    ["empty recipients", { ...OVERSIGHT, recipientRoles: [] }],
    ["invalid request policy", { ...OVERSIGHT, accessRequests: "silent" }],
    ["short approval TTL", { ...OVERSIGHT, approvalTtlSeconds: 59 }],
    ["long approval TTL", { ...OVERSIGHT, approvalTtlSeconds: 86_401 }],
  ])("fails closed for %s", (_label, candidate) => {
    expect(validateAgentConnectionOversight(candidate)).toBe(false);
  });
});

function input(
  overrides: Partial<AgentAuthorizationInput> = {},
): AgentAuthorizationInput {
  return {
    identity: { keyId: GRANT.keyId, namespace: GRANT.namespace, role: "agent" },
    grant: GRANT,
    request: {
      operation: "source-read",
      connectorId: GRANT.connectorId,
      sourceRef: "customers",
      purpose: "support-case",
      requestedFields: ["display_name", "not_allowed", "customer_id"],
      requestedRows: 10,
      requestedBytes: 4_096,
    },
    resourceSensitivity: "confidential",
    expectedPolicyVersion: GRANT.policyVersion,
    now: "2029-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("validateAgentConnectionGrant", () => {
  it("accepts a complete immutable authority snapshot", () => {
    expect(validateAgentConnectionGrant(GRANT)).toBe(true);
  });

  it.each([
    ["unknown property", { ...GRANT, callerNamespace: "acme" }],
    ["empty key", { ...GRANT, keyId: "" }],
    ["invalid operation", { ...GRANT, allowedOperations: ["sql"] }],
    ["duplicate operation", { ...GRANT, allowedOperations: ["read", "read"] }],
    ["empty source allowlist", { ...GRANT, allowedSourceRefs: [] }],
    [
      "source without fields",
      { ...GRANT, allowedFields: { customers: [], orders: ["order_id"] } },
    ],
    [
      "field mapping outside source allowlist",
      { ...GRANT, allowedFields: { ...GRANT.allowedFields, secrets: ["token"] } },
    ],
    [
      "unsafe field identifier",
      { ...GRANT, allowedFields: { customers: ["name; DROP TABLE x"], orders: ["order_id"] } },
    ],
    ["empty purpose", { ...GRANT, allowedPurposes: [""] }],
    ["invalid sensitivity", { ...GRANT, maxSensitivity: "secret" }],
    ["non-positive row cap", { ...GRANT, maxRows: 0 }],
    ["non-integral byte cap", { ...GRANT, maxBytes: 12.5 }],
    ["non-positive version", { ...GRANT, policyVersion: 0 }],
    ["invalid status", { ...GRANT, status: "paused" }],
    ["invalid expiry", { ...GRANT, expiresAt: "tomorrow-ish" }],
    ["missing oversight", Object.fromEntries(
      Object.entries(GRANT).filter(([key]) => key !== "oversight"),
    )],
    ["invalid oversight", { ...GRANT, oversight: { ...OVERSIGHT, deniedAlertThreshold: 0 } }],
  ])("fails closed for %s", (_label, candidate) => {
    expect(validateAgentConnectionGrant(candidate)).toBe(false);
  });
});

describe("authorizeAgentRequest", () => {
  it("returns only the requested-and-allowed fields with bounded row and byte caps", () => {
    const decision = authorizeAgentRequest(input());

    expect(decision).toEqual({
      allowed: true,
      grantId: GRANT.id,
      keyId: GRANT.keyId,
      namespace: GRANT.namespace,
      connectorId: GRANT.connectorId,
      sourceRef: "customers",
      purpose: "support-case",
      operation: "source-read",
      effectiveFields: ["customer_id", "display_name"],
      maxRows: 10,
      maxBytes: 4_096,
      policyVersion: GRANT.policyVersion,
    });
  });

  it("uses the grant projection and caps when optional request bounds are omitted", () => {
    const decision = authorizeAgentRequest(input({
      request: {
        operation: "source-read",
        connectorId: GRANT.connectorId,
        sourceRef: "orders",
        purpose: "order-status",
      },
      resourceSensitivity: "internal",
    }));

    expect(decision).toMatchObject({
      allowed: true,
      effectiveFields: ["order_id", "status"],
      maxRows: 25,
      maxBytes: 32_768,
    });
  });

  it("clamps caller-requested caps to the immutable grant ceilings", () => {
    const decision = authorizeAgentRequest(input({
      request: {
        operation: "source-read",
        connectorId: GRANT.connectorId,
        sourceRef: "customers",
        purpose: "support-case",
        requestedRows: 10_000,
        requestedBytes: 10_000_000,
      },
      resourceSensitivity: "public",
    }));

    expect(decision).toMatchObject({
      allowed: true,
      maxRows: GRANT.maxRows,
      maxBytes: GRANT.maxBytes,
    });
  });

  it.each([
    [
      "key-mismatch",
      input({ identity: { keyId: "key-other", namespace: GRANT.namespace, role: "agent" } }),
    ],
    [
      "namespace-mismatch",
      input({ identity: { keyId: GRANT.keyId, namespace: "acme/sales", role: "agent" } }),
    ],
    ["grant-revoked", input({ grant: { ...GRANT, status: "revoked" } })],
    ["grant-expired", input({ now: GRANT.expiresAt ?? undefined })],
    ["policy-version-mismatch", input({ expectedPolicyVersion: 2 })],
    [
      "operation-denied",
      input({ request: { ...input().request, operation: "write" } }),
    ],
    [
      "connector-denied",
      input({ request: { ...input().request, connectorId: "postgres-finance" } }),
    ],
    [
      "source-ref-denied",
      input({ request: { ...input().request, sourceRef: "employees" } }),
    ],
    [
      "purpose-denied",
      input({ request: { ...input().request, purpose: "model-training" } }),
    ],
    [
      "sensitivity-denied",
      input({ resourceSensitivity: "restricted" }),
    ],
    [
      "empty-field-intersection",
      input({ request: { ...input().request, requestedFields: ["ssn", "password_hash"] } }),
    ],
    [
      "empty-field-intersection",
      input({ request: { ...input().request, requestedFields: [] } }),
    ],
  ] as const)("denies with %s", (reason, candidate) => {
    expect(authorizeAgentRequest(candidate)).toEqual({ allowed: false, reason });
  });

  it.each([
    ["caller authority field", { ...input().request, keyId: GRANT.keyId }],
    ["caller sensitivity field", { ...input().request, sensitivity: "public" }],
    ["empty connector", { ...input().request, connectorId: "" }],
    ["invalid requested field", { ...input().request, requestedFields: ["name, secret"] }],
    ["zero requested rows", { ...input().request, requestedRows: 0 }],
    ["fractional requested bytes", { ...input().request, requestedBytes: 1.5 }],
  ])("rejects an invalid request with no authority expansion: %s", (_label, request) => {
    expect(authorizeAgentRequest(input({
      request: request as AgentAuthorizationInput["request"],
    }))).toEqual({ allowed: false, reason: "invalid-request" });
  });

  it("rejects a malformed stored grant before evaluating request authority", () => {
    const malformed = { ...GRANT, maxRows: -1 } as AgentConnectionGrant;

    expect(authorizeAgentRequest(input({ grant: malformed }))).toEqual({
      allowed: false,
      reason: "invalid-grant",
    });
  });

  it("rejects an invalid server-resolved resource classification", () => {
    expect(authorizeAgentRequest(input({
      resourceSensitivity: "secret" as AgentAuthorizationInput["resourceSensitivity"],
    }))).toEqual({ allowed: false, reason: "invalid-request" });
  });

  it.each([null, undefined, "request", []])("fails closed for malformed top-level input", (value) => {
    expect(authorizeAgentRequest(value as unknown as AgentAuthorizationInput)).toEqual({
      allowed: false,
      reason: "invalid-request",
    });
  });

  it("rejects a non-agent identity before granting gateway authority", () => {
    expect(authorizeAgentRequest(input({
      identity: { keyId: GRANT.keyId, namespace: GRANT.namespace, role: "auditor" as "agent" },
    }))).toEqual({ allowed: false, reason: "invalid-request" });
  });

  it.each([
    ["row cap", { maxRows: 1_001 }],
    ["byte cap", { maxBytes: 10 * 1024 * 1024 + 1 }],
  ])("rejects a grant above the platform %s", (_label, override) => {
    expect(validateAgentConnectionGrant({ ...GRANT, ...override })).toBe(false);
  });
});
