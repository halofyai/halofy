/**
 * HTTP → Kernel adapter (M1 integrator wiring).
 *
 * `buildHttpDeps(kernel)` produces the HttpServerDeps consumed by module B's
 * createHttpServer: bearer auth via AuthService, payload validation (zod) +
 * dispatch into the Identity-scoped syscalls, owner/admin management routes
 * over PolicyStore/AuthService, MetricsRegistry snapshot, denial audits, and
 * the shared per-identity MCP server factory for /mcp.
 *
 * Error → status mapping happens in server.ts by error NAME:
 *   AuthzError → 403, RateLimitError → 429, BadRequestError → 400,
 *   anything else → 500.
 */

import { z } from "zod";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { AgentAccessLevel, AuditOp, Identity, Namespace, PinTarget, Role, SetupInput, SourceKind, SyscallContext } from "../types.js";
// The S8 op filter allowlist is the CANONICAL vocabulary, never a local copy:
// a hand-maintained subset silently dropped every op added after M5.
import { AUDIT_OPS } from "../types.js";
import { Kernel } from "../kernel.js";
import { AuthzError, isRole, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import { assertAgentKeyScope } from "../auth/agent-scope.js";
import { isHumanRole } from "../console/auth.js";
// M10 (D41): the ONE product-role seam — user payloads crossing the console
// boundary carry root|admin|member (+ entitlements for legacy auditors).
import { fromProductRole, toPublicUser } from "../iam/product-roles.js";
import {
  GitHubOAuthService,
  githubOAuthFromEnv,
} from "../console/github-sso.js";
import {
  ExternalIdentityStore,
  IdentityConflictError,
  isExternalProvider,
} from "../console/identities.js";
import { SupabaseSsoService, supabaseSsoFromEnv } from "../console/sso.js";
import { organizationSignupAllowed } from "../console/signup.js";
import { buildMcpServer } from "../mcp/tools.js";
import type { HttpServerDeps, HttpSyscalls } from "./server.js";
import { BearerUnavailableError, isProductKeyType } from "../auth/key-types.js";
import type { MemManifestArgs } from "../discovery/manifest.js";
import { SetupConflictError, validatePublicUrl } from "../setup/index.js";
import { DurableRateLimitStore } from "../durable/rate-limit.js";
import { BoundedHttpRedMetrics } from "../observability/http.js";
import {
  OidcAuthenticator,
  type OidcAuthenticatorProvider,
} from "../iam/oidc.js";
import {
  DbScimDirectory,
  ScimProvisioningService,
  type ScimAuthorityBinding,
} from "../iam/scim.js";
import {
  AGENT_GATEWAY_OPERATIONS,
  DATA_SENSITIVITIES,
  MAX_GATEWAY_BYTES,
  MAX_GATEWAY_FIELDS,
  MAX_GATEWAY_QUERY_TERM_LENGTH,
  MAX_GATEWAY_QUERY_TERMS,
  MAX_GATEWAY_REQUEST_DURATION_SECONDS,
  MAX_GATEWAY_REQUEST_USES,
  MAX_GATEWAY_ROWS,
  MIN_GATEWAY_REQUEST_DURATION_SECONDS,
} from "../gateway/contracts.js";

const AGENT_ID = "http";
const MAX_OUTPUT_TOKENS_CEILING = 128_000;

/** 400-mapped payload validation failure (see server.ts name-based mapping). */
export class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

/** 409-mapped when a movement idempotency key is reused for different input. */
export class MovementConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MovementConflictError";
  }
}

// ---------------------------------------------------------------------------
// Payload schemas (namespace/actor are already rejected by the transport)
// ---------------------------------------------------------------------------

const readSchema = z.object({ id: z.string().min(1) });

const searchSchema = z.object({
  query: z.string().min(1),
  k: z.number().int().positive().optional(),
  tokenBudget: z.number().int().positive().optional(),
  validOnly: z.boolean().optional(),
  // M6 (D15, contract module F): 'off' guarantees no live-source dispatch;
  // 'auto' (default) may start one when the search misses locally.
  live: z.enum(["off", "auto"]).optional(),
});

const writeSchema = z.object({
  scope: z.enum(["user", "assistant", "team", "org"]),
  content: z.string().min(1),
  session: z.string().optional(),
  async: z.boolean().optional(),
  hints: z
    .object({
      type: z.enum(["fact", "preference", "episode", "entity", "concept"]).optional(),
      eventTime: z.string().optional(),
      verbatim: z.boolean().optional(),
    })
    .optional(),
});

const sourceTokensSchema = z.record(
  z.string().min(1).max(256),
  z.string().min(1).max(16_384),
).refine((tokens) => Object.keys(tokens).length <= 32, "at most 32 source tokens are allowed");

const gatewayIdentifier = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const gatewaySourceRef = z.string().regex(
  /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/,
);
const sourceReadSchema = z.object({
  grantId: z.string().trim().min(1).max(256),
  connectorId: z.string().trim().min(1).max(256),
  sourceRef: gatewaySourceRef,
  purpose: z.string().trim().min(1).max(256),
  query: z.string().trim().min(1).max(4_096).refine((query) => {
    const terms = query.split(/\s+/).filter(Boolean);
    return terms.length <= MAX_GATEWAY_QUERY_TERMS &&
      terms.every((term) => term.length <= MAX_GATEWAY_QUERY_TERM_LENGTH);
  }, "query has too many or overly long terms"),
  requestedFields: z.array(gatewayIdentifier).max(MAX_GATEWAY_FIELDS).optional(),
  requestedRows: z.number().int().positive().max(MAX_GATEWAY_ROWS).optional(),
  requestedBytes: z.number().int().positive().max(MAX_GATEWAY_BYTES).optional(),
  expectedPolicyVersion: z.number().int().positive().optional(),
  accessRequestId: z.string().trim().min(1).max(256).optional(),
}).strict();

const agentConnectionOversightSchema = z.object({
  maxRequestsPerMinute: z.number().int().min(1).max(10_000),
  usageAlertThreshold: z.number().int().min(1).max(1_000_000),
  deniedAlertThreshold: z.number().int().min(1).max(10_000),
  recipientRoles: z.array(z.enum(["owner", "admin", "auditor"])).min(1).max(3),
  accessRequests: z.enum(["allowed", "disabled"]),
  approvalTtlSeconds: z.number().int().min(60).max(86_400),
}).strict();

const createAgentConnectionSchema = z.object({
  keyId: z.string().trim().min(1).max(256),
  connectorId: z.string().trim().min(1).max(256),
  allowedOperations: z.array(z.enum(AGENT_GATEWAY_OPERATIONS)).min(1),
  allowedSourceRefs: z.array(gatewaySourceRef).min(1).max(1_000),
  allowedFields: z.record(
    gatewaySourceRef,
    z.array(gatewayIdentifier).min(1).max(MAX_GATEWAY_FIELDS),
  ),
  allowedPurposes: z.array(z.string().trim().min(1).max(256)).min(1).max(256),
  maxSensitivity: z.enum(DATA_SENSITIVITIES),
  maxRows: z.number().int().positive().max(MAX_GATEWAY_ROWS),
  maxBytes: z.number().int().positive().max(MAX_GATEWAY_BYTES),
  expiresAt: z.string().datetime({ offset: false }).nullable().default(null),
  oversight: agentConnectionOversightSchema.optional(),
}).strict();

const issueAgentBadgeSchema = z.object({
  badge: z.object({
    actor: z.string().trim().min(1).max(256),
    namespace: z.string().trim().min(1).max(1_024),
    // D50: requested scope level for the external agent this badge identifies.
    accessLevel: z.enum(["manager", "member"]).optional(),
  }).strict(),
  grant: z.object({
    connectorId: z.string().trim().min(1).max(256),
    allowedOperations: z.array(z.enum(AGENT_GATEWAY_OPERATIONS)).min(1),
    allowedSourceRefs: z.array(gatewaySourceRef).min(1).max(1_000),
    allowedFields: z.record(
      gatewaySourceRef,
      z.array(gatewayIdentifier).min(1).max(MAX_GATEWAY_FIELDS),
    ),
    allowedPurposes: z.array(z.string().trim().min(1).max(256)).min(1).max(256),
    maxSensitivity: z.enum(DATA_SENSITIVITIES),
    maxRows: z.number().int().positive().max(MAX_GATEWAY_ROWS),
    maxBytes: z.number().int().positive().max(MAX_GATEWAY_BYTES),
    expiresAt: z.string().datetime({ offset: false }).nullable(),
    oversight: agentConnectionOversightSchema,
  }).strict(),
}).strict();

const createAgentAccessRequestSchema = z.object({
  grantId: z.string().trim().min(1).max(256),
  connectorId: z.string().trim().min(1).max(256),
  sourceRef: gatewaySourceRef,
  purpose: z.string().trim().min(1).max(256),
  requestedFields: z.array(gatewayIdentifier).min(1).max(MAX_GATEWAY_FIELDS),
  requestedRows: z.number().int().positive().max(MAX_GATEWAY_ROWS),
  requestedBytes: z.number().int().positive().max(MAX_GATEWAY_BYTES),
  justification: z.string().trim().min(1).max(2_000),
  requestedDurationSeconds: z.number().int()
    .min(MIN_GATEWAY_REQUEST_DURATION_SECONDS).max(MAX_GATEWAY_REQUEST_DURATION_SECONDS),
  maxUses: z.number().int().min(1).max(MAX_GATEWAY_REQUEST_USES).optional(),
}).strict();

const agentAccessEventFiltersSchema = z.object({
  keyId: z.string().trim().min(1).max(256).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
}).strict();

const agentAccessAlertFiltersSchema = z.object({
  status: z.enum(["open", "acknowledged", "resolved"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
}).strict();

const agentAccessRequestFiltersSchema = z.object({
  status: z.enum(["pending", "approved", "denied", "expired", "consumed"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
}).strict();

const approveAgentAccessRequestSchema = z.object({
  durationSeconds: z.number().int().min(60).max(86_400).optional(),
  maxUses: z.number().int().min(1).max(100).optional(),
  note: z.string().trim().max(2_000).optional(),
}).strict();

const denyAgentAccessRequestSchema = z.object({
  note: z.string().trim().max(2_000).optional(),
}).strict();

const faultSchema = z.object({
  query: z.string().min(1),
  k: z.number().int().positive().optional(),
  tokenBudget: z.number().int().positive().optional(),
  // M6 (D15/D13): live-lane switch + per-request passthrough source tokens.
  // sourceTokens may arrive in the body or via the X-Halo-Source-Tokens
  // header (merged by withSourceTokens BEFORE dispatch) — either way they are
  // handed to the kernel verbatim and never logged, audited, or echoed.
  live: z.enum(["off", "auto"]).optional(),
  sourceTokens: sourceTokensSchema.optional(),
});

// M6 (D15): POST /v1/mem/live-result — redeem a phase-2 ticket.
const liveResultSchema = z.object({
  ticket: z.string().min(1),
  sourceTokens: sourceTokensSchema.optional(),
}).strict();

const assembleSchema = z.object({
  taskHint: z.string().optional(),
});

const policySchema = z.object({
  tokenBudget: z.number().int().positive().optional(),
});

const policyAckSchema = z.object({
  digest: z.string().min(1),
  applied: z.boolean().optional(),
  note: z.string().max(500).optional(),
});

const statsSchema = z.object({});

const pinSchema = z.object({
  target: z.object({ kind: z.enum(["memory", "concept"]), ref: z.string().min(1) }).strict(),
}).strict();

const adminPinSchema = z.object({
  target: z.object({ kind: z.enum(["memory", "concept"]), ref: z.string().min(1) }).strict(),
  namespace: z.string().min(1).optional(),
}).strict();

const unpinSchema = z.object({ pinId: z.string().min(1) }).strict();

const shareSchema = z.object({
  target: z.object({ kind: z.enum(["memory", "concept"]), ref: z.string().min(1) }).strict(),
  targetNamespace: z.string().min(1),
}).strict();

const issueKeySchema = z.object({
  namespace: z.string().min(1),
  actor: z.string().min(1),
  role: z.string().min(1),
  sourcePrincipals: z.array(z.string().min(1).max(512)).max(256).optional(),
  sourceGroups: z.array(z.string().min(1).max(512)).max(256).optional(),
  // D50: only meaningful with role 'agent'; authorized, never trusted.
  agentAccessLevel: z.enum(["manager", "member"]).optional(),
});

// M9 #23 (E52): typed product-key issuance — the `type` label is the caller's
// whole authority claim; role mapping happens server-side in ProductKeyService.
const issueTypedKeySchema = z.object({
  type: z.string().min(1).max(40),
  // Deliberately NOT `.min(1)`. The organization root is a namespace an agent
  // may not be bound to (D50) — but that is an AUTHORIZATION decision, and
  // rejecting it here would return 400 before `assertAgentKeyScope` runs, so
  // the D4 denial row the contract requires would never be written. The empty
  // string is allowed through the parser and refused, audibly, downstream.
  namespace: z.string(),
  actor: z.string().min(1),
  // D50: requested scope level for an assistant key. A REQUEST, not a claim —
  // assertAgentKeyScope decides what this caller may actually grant.
  agentAccessLevel: z.enum(["manager", "member"]).optional(),
  // D51: bounded lifetime and the human "why". Both optional; both re-validated
  // by ProductKeyService (a past expiry is refused, not silently accepted).
  expiresAt: z.string().datetime({ offset: true }).optional(),
  description: z.string().max(280).optional(),
  // D54: false issues a read-only agent. A REQUEST like the level above — the
  // service decides, and the decision is what gets stored.
  agentCanWrite: z.boolean().optional(),
  // Stable server-resolved human recipient for delegated one-time claim.
  recipientUserId: z.string().min(1).max(128).optional(),
  idempotencyKey: z.string().min(1).max(128).optional(),
}).strict();

// M9 #7 (D28): POST /v1/mem/export body — options only, never identity (D9).
// `scope` is a TARGET SELECTION (like the erasure ForgetTarget), not an
// identity assertion: the kernel gates it to the caller's downward subtree.
// MemoryReadScope stays server authority — .strict() rejects it in a body.
const exportScopeSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("team"),
    namespace: z.string().trim().min(1).max(512),
  }).strict(),
  z.object({
    kind: z.literal("user"),
    actor: z.string().trim().min(1).max(320),
  }).strict(),
]);
const exportOptionsSchema = z.object({
  purpose: z.string().trim().min(1).max(500).optional(),
  tiers: z.array(z.enum(["L2", "L3"])).min(1).max(2).optional(),
  limit: z.number().int().positive().max(10_000).optional(),
  scope: exportScopeSchema.optional(),
}).strict();

// M9 #19: PUT /v1/admin/automations body.
const automationConfigureSchema = z.object({
  templateId: z.string().min(1).max(100),
  enabled: z.boolean(),
  autoApprove: z.boolean().optional(),
  intervalSeconds: z.number().int().min(3_600).max(31_536_000).optional(),
  config: z.record(z.string(), z.unknown()).optional(),
}).strict();

const knowledgeSyncSchema = z.discriminatedUnion("scope", [
  z.object({ scope: z.literal("organization") }).strict(),
  z.object({
    scope: z.literal("team"),
    teamId: z.string().trim().min(1).max(256),
  }).strict(),
]);

// M9 W3 #22 (E56): PUT /v1/admin/usage/cap — the only editable field. The
// target is ALWAYS the caller's resolved namespace; no namespace in the body
// (D9). null clears this namespace's own override.
const usageCapSchema = z.object({
  monthlyBudgetUsd: z.number().min(0).max(1_000_000_000).nullable(),
}).strict();

// M9 W3 #22 (E53): PUT /v1/admin/usage/alerts — customer-editable thresholds.
const usageAlertSchema = z.object({
  kind: z.enum(["usage-threshold", "low-balance"]),
  thresholdUnit: z.enum(["percent", "credits"]),
  thresholdValue: z.number().int().min(1).max(1_000_000_000),
  enabled: z.boolean().optional(),
}).strict();

// M9 #1: GitHub App installation admin bodies.
const githubInstallStartSchema = z.object({
  name: z.string().trim().min(1).max(120),
}).strict();

const githubInstallApproveSchema = z.object({
  installationId: z.string().trim().min(1).max(64),
}).strict();

// M9 #11b (D29): OAuth client registration body — namespace comes from the
// caller's identity, never the body (D9). The service re-validates bounds.
const oauthClientCreateSchema = z.object({
  name: z.string().trim().min(1).max(200),
  description: z.string().max(2_000).optional(),
  redirectUris: z.array(z.string().min(1).max(2_000)).max(16).optional(),
  allowedTools: z.array(z.string().trim().min(1).max(200)).max(64).optional(),
  tokenRole: z.enum(["assistant", "read-only"]),
  tokenTtlSeconds: z.number().int().min(60).max(86_400).optional(),
  // OA1: omitted → derived from redirectUris by the service (connector vs
  // service client). The service enforces the lane invariants.
  grantTypes: z.array(z.enum(["client_credentials", "authorization_code", "refresh_token"]))
    .max(3).optional(),
}).strict();

const oauthClientRevokeSchema = z.object({
  reason: z.string().max(500).optional(),
}).strict();

// M9 #9 (E19): skill registration / invocation bodies (D9: no namespace).
const skillRegisterSchema = z.object({
  skillKey: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,199}$/),
  name: z.string().trim().min(1).max(200),
  description: z.string().max(4_000).optional(),
  definition: z.string().min(1).max(200_000),
  labels: z.object({
    category: z.string().trim().min(1).max(80),
    purpose: z.string().trim().min(1).max(140),
    tags: z.array(z.string().trim().min(1).max(64)).min(3).max(10),
  }).strict().optional(),
}).strict();

const skillUpdateSchema = skillRegisterSchema.omit({ skillKey: true, labels: true }).strict();

const skillLabelsUpdateSchema = z.object({
  category: z.string().trim().min(1).max(80),
  purpose: z.string().trim().max(140),
  tags: z.array(z.string().trim().min(1).max(64)).min(3).max(10),
}).strict();

const skillOverrideSchema = z.object({
  reason: z.string().trim().min(1).max(1_000),
}).strict();

// S16: reject carries the same mandatory 1..1000-char reason as override.
const skillRejectSchema = z.object({
  reason: z.string().trim().min(1).max(1_000),
}).strict();

const skillInvokeSchema = z.object({
  skillKey: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,199}$/),
}).strict();

const forgetSchema = z.object({
  target: z.object({
    kind: z.enum(["actor", "entity", "namespace", "memory"]),
    value: z.string().min(1),
  }),
});

// R6: POST /v1/admin/warmstores/:name/rebuild — subtree to reconstruct.
const warmRebuildSchema = z.object({
  namespace: z.string().trim().min(1),
}).strict();

const adoptOrganizationSchema = z.object({
  tenant: z.string().trim().min(1).max(200),
  namespaces: z.array(z.string().trim().min(1).max(500)).max(100).default([]),
  dryRun: z.boolean().optional(),
  rootSources: z.boolean().optional(),
}).strict();

const registerTenantSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  monthlyBudgetUsd: z.number().nullable().optional(),
  rateLimitPerMin: z.number().int().nullable().optional(),
});

// M5 control-room mutating-route payloads.
const invitePersonSchema = z.object({
  email: z.string().min(1),
  displayName: z.string().trim().min(1).max(80),
  namespace: z.string().min(1),
  role: z.string().min(1),
  ttlSeconds: z.number().int().min(60).max(30 * 24 * 3600).optional(),
}).strict();

const createTeamSchema = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().trim().max(280).optional(),
}).strict();

const personAccessStateSchema = z.object({
  status: z.enum(["active", "disabled"]),
  revokeCreatedKeys: z.boolean().optional(),
  reason: z.string().trim().max(500).optional(),
}).strict();

const updateTeamSchema = z.object({
  name: z.string().trim().min(1).max(80).optional(),
  archived: z.boolean().optional(),
}).strict().refine((value) => value.name !== undefined || value.archived !== undefined, {
  message: "name or archived is required",
});

const addTeamMemberSchema = z.object({
  email: z.string().trim().min(1).max(320),
}).strict();

// D41: role inputs are PRODUCT roles. The retired internal spellings
// ("owner"/"auditor") still parse here so the ONE seam (`fromProductRole`
// in src/iam/product-roles.ts) can reject them with its guidance message.
const inviteTeamMemberSchema = z.object({
  email: z.string().trim().min(1).max(320),
  displayName: z.string().trim().min(1).max(80),
  role: z.enum(["root", "admin", "member", "owner", "auditor"]),
}).strict();

const rotateTeamInvitationSchema = z.object({
  kind: z.enum(["reminder", "reinvite"]),
}).strict();

const changeTeamMemberRoleSchema = z.object({
  role: z.enum(["root", "admin", "member", "owner", "auditor"]),
}).strict();

const changeTeamMemoryAccessSchema = z.object({
  mode: z.enum(["related", "company-published"]),
}).strict();

const connectSourceSchema = z.object({
  kind: z.string().min(1),
  config: z.record(z.string(), z.unknown()).optional(),
  idempotencyKey: z.string().regex(/^[A-Za-z0-9_-]{1,256}$/).optional(),
  // Team placement: an id from org_teams, resolved to a namespace
  // server-side (D9). Never a raw namespace.
  targetTeamId: z.string().trim().min(1).max(128).nullable().optional(),
}).strict();

const sourceCredentialSchema = z.object({
  connectorId: z.string().regex(/^[a-z0-9_]+$/),
  connectionKey: z.string().regex(/^[a-z0-9_]+$/),
  name: z.string().trim().min(1).max(120),
  config: z.record(z.string(), z.unknown()),
}).strict();

const nangoConnectSessionSchema = z.object({
  connectorId: z.string().regex(/^[a-z0-9_]+$/),
  name: z.string().trim().min(1).max(120),
}).strict();

const sourceOAuthStartSchema = z.object({
  // Team placement resolved server-side from org_teams (D9), like sources.
  targetTeamId: z.string().trim().min(1).max(128).nullable().optional(),
  selectedItemIds: z.array(z.string().trim().min(10).max(128)).min(1).max(100).optional(),
  sourceKind: z.enum([
    "google_drive_direct",
    "google_docs_direct",
    "google_sheets_direct",
  ]).optional(),
}).strict();

const obsidianPairSchema = z.object({
  vaultName: z.string().trim().min(1).max(120),
  includedFolders: z.array(z.string().trim().min(1).max(512)).max(100).default([]),
  excludedFolders: z.array(z.string().trim().min(1).max(512)).max(100).default([]),
  // Explicit operator acknowledgement: Obsidian has no per-note ACL surface.
  sourceAccessMode: z.literal("namespace-open"),
  // Team placement is resolved server-side; raw namespaces are undeclared.
  targetTeamId: z.string().trim().min(1).max(128).nullable().optional(),
}).strict();

const emptyObjectSchema = z.object({}).strict();

const sourceScheduleSchema = z.object({
  intervalSeconds: z.number().int().min(60).nullable(),
}).strict();

const csvSourceImportSchema = z.object({
  csv: z.string().min(1).max(512 * 1024),
  mapping: z.object({
    idColumn: z.string().min(1).max(120),
    textColumns: z.array(z.string().min(1).max(120)).min(1).max(32),
    updatedAtColumn: z.string().min(1).max(120).optional(),
    classificationColumn: z.string().min(1).max(120).optional(),
  }).strict(),
}).strict();

const runFragmentationSchema = z.object({
  namespace: z.string().min(1).optional(),
});

const conflictScanSchema = z.object({
  targetTeamId: z.string().trim().min(1).max(200).nullable().optional(),
  focus: z.string().trim().max(500).optional(),
  include: z.array(z.enum(["knowledge-base", "agent-summary", "policy-manual"]))
    .min(1).max(3).optional(),
}).strict();

const agentSessionCompleteSchema = z.object({
  sessionId: z.string().min(1).max(256),
  startedAt: z.string().datetime({ offset: true }).optional(),
  endedAt: z.string().datetime({ offset: true }).optional(),
  turns: z.array(z.object({
    role: z.enum(["user", "assistant"]),
    content: z.string().min(1).max(16_000),
  }).strict()).min(1).max(128),
}).strict();

const conflictFindingReviewSchema = z.object({
  expectedRowVersion: z.number().int().positive(),
}).strict();

/** `keep` names the side the reviewer judged correct; the other is retired. */
const conflictFindingOverturnSchema = z.object({
  expectedRowVersion: z.number().int().positive(),
}).strict();

const conflictFindingResolveSchema = z.object({
  keep: z.enum(["left", "right"]),
  expectedRowVersion: z.number().int().positive(),
}).strict();

// Two ways in, and exactly one per request:
//   providerId — a BYOK catalog vendor (src/model-runtime/catalog.ts). Protocol,
//     default endpoint, and classification are server-derived; the control plane
//     rejects unknown ids and custom base URLs the vendor does not allow.
//   provider   — the raw wire protocol, for endpoints no catalog entry covers.
//     Unchanged legacy contract: hosting + modelSource are mandatory here.
const modelConnectionSchema = z.object({
  name: z.string().trim().min(1).max(200),
  providerId: z.string().trim().min(1).max(64).optional(),
  provider: z.enum([
    "anthropic",
    "openai-compatible",
    "google-gemini",
    "cohere",
    "azure-openai",
  ]).optional(),
  hosting: z.enum(["provider-hosted", "enterprise-hosted"]).optional(),
  modelSource: z.enum(["proprietary", "open-source", "mixed"]).optional(),
  baseUrl: z.string().trim().min(1).max(2_000).optional(),
  apiKey: z.string().min(1).max(20_000).optional(),
}).strict().superRefine((body, ctx) => {
  if ((body.providerId === undefined) === (body.provider === undefined)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["providerId"],
      message: "exactly one of providerId or provider is required",
    });
    return;
  }
  if (body.providerId !== undefined) return;
  if (body.hosting === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["hosting"], message: "hosting is required" });
  }
  if (body.modelSource === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["modelSource"], message: "modelSource is required" });
  }
  if (body.provider === "anthropic") {
    if (!body.apiKey) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["apiKey"], message: "apiKey is required" });
    }
    if (body.baseUrl !== undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["baseUrl"], message: "baseUrl is not accepted for Anthropic" });
    }
    if (body.hosting !== "provider-hosted" || body.modelSource !== "proprietary") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["hosting"], message: "Anthropic is provider-hosted and proprietary" });
    }
  } else if (!body.baseUrl) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["baseUrl"], message: "baseUrl is required" });
  }
});

const modelProfileSchema = z.object({
  name: z.string().trim().min(1).max(200),
  connectionId: z.string().trim().min(1).max(200),
  model: z.string().trim().min(1).max(300),
  isDefault: z.boolean().optional(),
  maxOutputTokens: z.number().int().min(1).max(MAX_OUTPUT_TOKENS_CEILING).optional(),
  temperature: z.number().min(0).max(2).optional(),
}).strict();

/** PATCH body: every field optional, at least one required. */
const modelProfileUpdateSchema = z.object({
  name: z.string().trim().min(1).max(200).optional(),
  model: z.string().trim().min(1).max(300).optional(),
  isDefault: z.boolean().optional(),
  assistantEnabled: z.boolean().optional(),
  maxOutputTokens: z.number().int().min(1).max(MAX_OUTPUT_TOKENS_CEILING).optional(),
  temperature: z.number().min(0).max(2).optional(),
}).strict()
  .refine(
    (body) => Object.values(body).some((value) => value !== undefined),
    { message: "at least one field must be supplied" },
  )
  .refine(
    (body) => !(body.isDefault === true && body.assistantEnabled === false),
    { message: "the default Assistant model must be enabled" },
  );

const copilotCompleteSchema = z.object({
  message: z.string().trim().min(1).max(20_000),
  // D50/D54: interactive Assistant inference is durable and idempotent. The
  // conversation is server-issued and the bounded client turn id identifies
  // only a transport retry; neither value carries identity or model metadata.
  conversationId: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/),
  turnId: z.string().trim().min(1).max(128),
  profileId: z.string().trim().min(1).max(200).optional(),
  history: z.array(z.object({
    role: z.enum(["user", "assistant"]),
    content: z.string().trim().min(1).max(20_000),
  }).strict()).max(16).optional(),
  allowWrites: z.boolean().optional().default(false),
  // M9 W3 #12 (E45): explicit capability lane; absent = pull-only invoke-chat.
  // Mirrors COPILOT_CAPABILITIES in src/model-runtime/copilot.ts — the
  // orchestrator re-validates and audits unknown capabilities as denied.
  capability: z.enum(["invoke-chat", "trigger-respond"]).optional(),
}).strict();

const copilotConversationCreateSchema = z.object({
  title: z.string().trim().min(1).max(120),
}).strict();

const copilotRoutineScheduleFields = {
  frequency: z.enum(["daily", "weekly"]),
  localTime: z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/),
  weekday: z.number().int().min(0).max(6).nullable().optional(),
  timeZone: z.string().trim().min(1).max(100),
};

const copilotRoutineCreateSchema = z.object({
  prompt: z.string().trim().min(1).max(20_000),
  ...copilotRoutineScheduleFields,
  profileId: z.string().trim().min(1).max(200).optional(),
}).strict().superRefine((body, ctx) => {
  if (body.frequency === "weekly" && body.weekday === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["weekday"], message: "weekday is required for weekly routines" });
  }
  if (body.frequency === "daily" && body.weekday !== undefined && body.weekday !== null) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["weekday"], message: "weekday is only valid for weekly routines" });
  }
});

const copilotRoutineUpdateSchema = z.object({
  frequency: copilotRoutineScheduleFields.frequency.optional(),
  localTime: copilotRoutineScheduleFields.localTime.optional(),
  weekday: copilotRoutineScheduleFields.weekday,
  timeZone: copilotRoutineScheduleFields.timeZone.optional(),
  profileId: z.string().trim().min(1).max(200).nullable().optional(),
  isEnabled: z.boolean().optional(),
}).strict().refine((body) => Object.keys(body).length > 0, "at least one field is required");

/** POST /v1/admin/setup — orchestrate tenant → source → retriever → snippet. */
const setupSchema = z.object({
  idempotencyKey: z.string().trim().min(8).max(200),
  tenant: registerTenantSchema,
  team: z.object({
    id: z.string().trim().min(1).max(100),
    name: z.string().trim().min(1).max(200),
  }).strict(),
  /** Optional first source connected in the tenant root. */
  source: z
    .object({
      kind: z.string().min(1),
      config: z.record(z.string(), z.unknown()).optional(),
    })
    .optional(),
  /** Named retriever to pick (defaults to the D1 baseline). */
  retriever: z.string().min(1).optional(),
  /** Actor label for the agent badge minted into the paste-ready snippet. */
  agentActor: z.string().min(1).optional(),
}).strict();

const consolidationRunSchema = z.object({
  namespace: z.string().min(1).refine((namespace) => {
    const parts = namespace.split("/");
    return !namespace.includes("\\") &&
      parts.every((part) => part.length > 0 && part !== "." && part !== "..");
  }, "must be a canonical private namespace"),
  evidenceIds: z.array(z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/i, "must be a stable ULID reference")).min(2),
  windowStart: z.string().datetime({ offset: true }),
  windowEnd: z.string().datetime({ offset: true }),
}).strict();

const proposalDraftSchema = z.object({
  slug: z.string().min(1),
  title: z.string().min(1),
  body: z.string().min(1),
}).strict();

const proposalEditSchema = z.object({
  expectedRowVersion: z.number().int().positive(),
  draft: proposalDraftSchema,
}).strict();

const proposalApproveSchema = z.object({
  expectedRowVersion: z.number().int().positive(),
  editedDraft: proposalDraftSchema.optional(),
}).strict();

const proposalRejectSchema = z.object({
  expectedRowVersion: z.number().int().positive(),
  reason: z.string().max(2000).optional(),
}).strict();

const disputeResolveSchema = z.object({
  action: z.enum(["uphold-new", "keep-old", "edit", "both-valid"]),
  expectedRowVersion: z.number().int().positive(),
  editedContent: z.string().trim().min(1).max(100_000).optional(),
}).strict().refine(
  (body) => (body.action === "edit") === (body.editedContent !== undefined),
  { message: "editedContent is required for action 'edit' and invalid otherwise" },
);

const movementSchema = z.object({
  action: z.enum(["promote_pin", "propose_cold", "materialize_warm", "archive_warm"]),
  targetRef: z.string().min(1),
  idempotencyKey: z.string().min(8).max(200),
  evidenceIds: z.array(z.string().min(1)).optional(),
}).strict();

const forkMountSchema = z.object({
  origin: z.object({
    kind: z.enum(["memory", "concept"]),
    ref: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/i, "must be a stable ULID reference"),
  }).strict(),
  targetNamespace: z.string().min(1),
  content: z.string().trim().min(1).max(100_000),
  embedding: z.array(z.number().finite()).max(4096).nullable().optional(),
  scope: z.enum(["user", "assistant", "team", "org"]).optional(),
  type: z.enum(["fact", "preference", "episode", "entity", "concept"]).optional(),
  confidence: z.number().min(0).max(1).optional(),
}).strict();

const policyDocumentKindSchema = z.enum([
  "policy",
  "guideline",
  "procedure",
  "standard",
  "handbook",
  "other",
]);

const policyDocumentStatusSchema = z.enum([
  "processing",
  "active",
  "needs_review",
  "failed",
]);

const policyDocumentListSchema = z.object({
  // Empty is valid only for a platform-root request and is checked by scope.
  namespace: z.string().max(512),
  page: z.number().int().positive().default(1),
  pageSize: z.number().int().positive().default(20).transform((value) => Math.min(value, 50)),
  query: z.string().trim().min(1).max(200).optional(),
  kind: policyDocumentKindSchema.optional(),
  status: policyDocumentStatusSchema.optional(),
}).strict();

const policyDocumentUploadSchema = z.object({
  namespace: z.string().max(512),
  title: z.string().trim().min(1).max(200).optional(),
  kind: policyDocumentKindSchema,
  fileName: z.string().min(1).max(255),
  // The store performs the authoritative UTF-8 byte limit. This character
  // bound rejects plainly oversized bodies early while preserving that check.
  content: z.string().min(1).max(524_288),
  enforcement: z.enum(["advisory", "required"]).optional(),
}).strict();

const policyEnforcementSchema = z.object({
  enforcement: z.enum(["advisory", "required"]),
}).strict();

const policyDocumentScopesSchema = z.object({
  query: z.string().trim().min(1).max(200).optional(),
  limit: z.number().int().positive().max(100).default(50),
}).strict();

const policyAdoptionCandidateSchema = z.object({
  namespace: z.string().max(512).optional(),
  limit: z.number().int().positive().max(100).default(25),
}).strict();

// Adoption names a file that is already in memory; it never carries content.
// Every durable attribute is re-derived from canonical provenance in the
// kernel, so the body is only a pointer plus optional presentation.
const policyDocumentAdoptSchema = z.object({
  namespace: z.string().max(512),
  fileName: z.string().min(1).max(255),
  sourceId: z.string().trim().min(1).max(512),
  title: z.string().trim().min(1).max(200).optional(),
  kind: policyDocumentKindSchema.optional(),
  enforcement: z.enum(["advisory", "required"]).optional(),
}).strict();

// Admin-only targeting uses an opaque team id. The kernel resolves its
// namespace inside the caller's subtree; a namespace never crosses D9.
const adminSkillRegisterSchema = skillRegisterSchema.extend({
  teamId: z.string().trim().min(1).max(200).optional(),
}).strict();

const knowledgeBaseKindSchema = z.enum(["file", "folder", "url"]);
const knowledgeBaseStatusSchema = z.enum(["empty", "processing", "ready", "needs_review", "failed"]);
const knowledgeBaseLifecycleSchema = z.enum(["active", "paused", "archived"]);
const companyFileStatusSchema = z.enum(["processing", "ready", "needs_review", "failed"]);
const companyFileLifecycleSchema = z.enum(["active", "archived"]);

const sourceMetadataText = (max: number) => z.string().trim().max(max).refine(
  (value) => !/[\u0000-\u001f\u007f-\u009f]/u.test(value),
  "must not contain control characters",
);

const sourceMetadataSchema = z.object({
  primaryBusinessFunction: sourceMetadataText(120).pipe(z.string().min(1)),
  description: sourceMetadataText(2_000),
  dataSensitive: z.boolean(),
}).strict();

const knowledgeBaseCreateSchema = sourceMetadataSchema.extend({
  name: z.string().trim().min(1).max(200),
  kind: knowledgeBaseKindSchema,
  targetTeamId: z.string().trim().min(1).max(128).nullable(),
  sourceId: z.string().trim().min(1).max(128).optional(),
}).strict();

const knowledgeBaseListSchema = z.object({
  query: z.string().trim().min(1).max(200).optional(),
  targetTeamId: z.string().trim().min(1).max(128).optional(),
  kind: knowledgeBaseKindSchema.optional(),
  status: knowledgeBaseStatusSchema.optional(),
  lifecycleState: knowledgeBaseLifecycleSchema.optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(100).optional(),
}).strict();

const knowledgeBaseSourceCreateSchema = z.object({
  kind: z.enum(["folder", "website"]),
  sourceId: z.string().trim().min(1).max(128),
  name: z.string().trim().min(1).max(200),
  description: z.string().trim().max(2_000),
  purpose: z.string().trim().min(1).max(500),
}).strict();

const knowledgeBaseSourceListSchema = z.object({
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(100).optional(),
}).strict();

const companyFileUploadSchema = z.object({
  knowledgeBaseId: z.string().trim().min(1).max(128),
  fileName: z.string().min(1).max(255),
  idempotencyKey: z.string().trim().min(8).max(128).regex(/^[A-Za-z0-9_-]+$/).optional(),
  // Exactly one of content / contentBase64; the kernel enforces exclusivity.
  content: z.string().min(1).max(524_288).optional(),
  // Base64 of the caller's original bytes; 5 MiB decoded ≈ 7 MB base64.
  contentBase64: z.string().min(1).max(7_200_000).optional(),
  title: z.string().trim().min(1).max(200).optional(),
  description: z.string().trim().max(2_000),
  purpose: z.string().trim().min(1).max(500),
}).strict();

const companyFileListSchema = z.object({
  knowledgeBaseId: z.string().trim().min(1).max(128).optional(),
  targetTeamId: z.string().trim().min(1).max(128).optional(),
  query: z.string().trim().min(1).max(200).optional(),
  status: companyFileStatusSchema.optional(),
  lifecycleState: companyFileLifecycleSchema.optional(),
  includeUploads: z.boolean().optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().positive().max(100).optional(),
}).strict().refine(
  (value) => value.includeUploads !== true || value.knowledgeBaseId !== undefined,
  { message: "includeUploads requires knowledgeBaseId", path: ["includeUploads"] },
);

const entityRelationshipListSchema = z.object({
  entityId: z.string().trim().min(1).max(128),
  relationship: z.enum([
    "same_as", "part_of", "contains", "uses", "depends_on", "owned_by", "served_by", "related_to",
  ]).optional(),
  direction: z.enum(["outgoing", "incoming", "both"]).optional(),
  includeArchived: z.boolean().optional(),
  limit: z.number().int().positive().max(100).optional(),
}).strict();

function parse<TSchema extends z.ZodTypeAny>(
  schema: TSchema,
  payload: unknown,
  what: string,
): z.output<TSchema> {
  const res = schema.safeParse(payload);
  if (!res.success) {
    const detail = res.error.issues
      .map((i) => (i.path.length ? `${i.path.join(".")}: ${i.message}` : i.message))
      .join("; ");
    throw new BadRequestError(`invalid ${what} body: ${detail}`);
  }
  return res.data as z.output<TSchema>;
}

async function auditModelFailure(
  kernel: Kernel,
  identity: Identity,
  detail: string,
  result: "denied" | "error" = "error",
): Promise<void> {
  try {
    await kernel.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "write",
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result,
      detail,
    });
  } catch {
    // Preserve the original validation/operational failure.
  }
}

// ---------------------------------------------------------------------------
// M6 — two-phase surface (D15) + passthrough source tokens (D13)
// ---------------------------------------------------------------------------

/**
 * HTTP header carrying per-request passthrough source tokens as a JSON object
 * (connectorId → token). Node lowercases incoming header names. RADIOACTIVE:
 * the parsed value goes to the kernel verbatim and must never be logged,
 * audited, echoed in a response, or included in an error message.
 */
export const SOURCE_TOKENS_HEADER = "x-halo-source-tokens";

/**
 * Defensively parse the X-Halo-Source-Tokens header. Anything that is not a
 * JSON object of string values (bad JSON, arrays, nested values, repeated
 * headers beyond the first, empty maps) → undefined — a malformed credential
 * header silently degrades to "no passthrough tokens" (the broker then audits
 * a CredentialMissingError denial downstream); it never 500s the fault and
 * never surfaces the raw header text anywhere.
 */
export function parseSourceTokensHeader(header: unknown): Record<string, string> | undefined {
  const raw = Array.isArray(header) ? header[0] : header;
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const out: Record<string, string> = {};
  for (const [connectorId, token] of Object.entries(parsed)) {
    if (typeof token === "string" && token.length > 0) out[connectorId] = token;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Merge header-borne source tokens into a mem-syscall payload before dispatch
 * (the transport calls this on POST /v1/mem/fault). A body-supplied
 * `sourceTokens` wins over the header. The RETURN VALUE contains raw tokens —
 * hand it straight to the syscall and nowhere else.
 */
export function withSourceTokens(
  payload: Record<string, unknown>,
  headers: Record<string, unknown>,
): Record<string, unknown> {
  if (Object.hasOwn(payload, "sourceTokens")) return payload;
  const tokens = parseSourceTokensHeader(headers[SOURCE_TOKENS_HEADER]);
  return tokens ? { ...payload, sourceTokens: tokens } : payload;
}

/** Admin scoping: root owner → anywhere; tenant owner/admin → own subtree. */
function assertAdminScope(identity: Identity, ns: Namespace): void {
  if (isRootOwner(identity)) return;
  if (
    (identity.role === "owner" || identity.role === "admin") &&
    isSelfOrDescendant(ns, identity.namespace)
  ) return;
  throw new AuthzError(
    `role '${identity.role}' may not manage namespace '${ns}' (outside your subtree)`,
  );
}

/**
 * Read-scope for the console read routes: root owner → anywhere; everyone else
 * (including tenant owner, admin, and auditor) → own subtree. Mirrors the
 * kernel's `assertInSubtree`
 * so an auditor — read-only everywhere in its scope — can reach the READ
 * screens (e.g. fragmentation GET), unlike `assertAdminScope` which is
 * owner/admin-only and belongs on the MUTATING routes.
 */
function assertReadScope(identity: Identity, ns: Namespace): void {
  if (isRootOwner(identity)) return;
  if (isSelfOrDescendant(ns, identity.namespace)) return;
  throw new AuthzError(
    `role '${identity.role}' may not view namespace '${ns}' (outside your subtree)`,
  );
}

/**
 * Issue an api key scoped to the caller's admin authority: assertAdminScope
 * (root owner anywhere; tenant owner/admin in its own subtree) is the
 * authoritative gate, THEN the issuance runs. AuthService.issueKey is
 * owner-only for direct callers, so
 * an in-scope non-owner admin is presented as an owner-role caller for the
 * AuthService call — the scope check already authorized the exact namespace, so
 * this grants nothing extra. Shared by POST /v1/admin/keys and the setup badge.
 */
async function issueKeyScoped(
  kernel: Kernel,
  identity: Identity,
  namespace: Namespace,
  actor: string,
  role: Role,
  entitlements: {
    sourcePrincipals?: string[];
    sourceGroups?: string[];
    agentAccessLevel?: AgentAccessLevel;
  } = {},
): Promise<{ record: unknown; plaintext: string }> {
  // D50: the legacy role-shaped body can also ask for an AGENT credential, so
  // it goes through the same scope rules as the typed path — otherwise the old
  // route would be a way to mint the organization-wide agent the new rules
  // forbid. Human roles keep the admin-subtree gate.
  if (role === "agent") {
    const decision = await assertAgentKeyScope(kernel.db, identity, {
      namespace,
      ...(entitlements.agentAccessLevel ? { level: entitlements.agentAccessLevel } : {}),
    });
    const agentCaller: Identity = { ...identity, role: "owner" };
    return kernel.auth.issueKey(decision.namespace, actor, role, agentCaller, {
      ...entitlements,
      agentAccessLevel: decision.level,
    });
  }
  assertAdminScope(identity, namespace);
  if (role === "owner" && identity.role !== "owner") {
    throw new AuthzError("only an owner may issue an owner key");
  }
  const caller: Identity =
    identity.role === "owner" ? identity : { ...identity, role: "owner" };
  return kernel.auth.issueKey(namespace, actor, role, caller, entitlements);
}

// ---------------------------------------------------------------------------
// M5 control-room helpers
// ---------------------------------------------------------------------------

const SOURCE_KINDS: readonly SourceKind[] = ["filesystem", "postgres", "obsidian_vault"];

function isSourceKind(value: string): value is SourceKind {
  return (SOURCE_KINDS as readonly string[]).includes(value);
}

const AUDIT_RESULTS: readonly string[] = ["ok", "denied", "miss", "error"];

/** `YYYY-MM-DD` — a whole calendar day, the only form the S8 date pickers emit. */
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Normalize an S8 date-range bound to an instant.
 *
 * `audit_log.ts` is TIMESTAMPTZ, so a bare `2026-07-31` binds as that day's
 * MIDNIGHT: as an `until` bound it silently discarded every event on the last
 * day of the range. A date-only bound is therefore widened to the day it
 * names — `since` to its first instant, `until` to its last.
 *
 * An unparseable bound is an ERROR, not a dropped filter: dropping it would
 * WIDEN the search behind the auditor's back (the opposite of the unknown-enum
 * rule, where dropping narrows nothing and the row set stays a superset).
 */
function normalizeAuditBound(value: string, edge: "since" | "until"): string {
  const trimmed = value.trim();
  if (trimmed === "") throw new BadRequestError(`admin/audit: empty ${edge} date`);
  if (DATE_ONLY.test(trimmed)) {
    return edge === "since"
      ? `${trimmed}T00:00:00.000Z`
      : `${trimmed}T23:59:59.999Z`;
  }
  if (!Number.isFinite(Date.parse(trimmed))) {
    throw new BadRequestError(
      `admin/audit: ${edge} must be a date (2026-07-31) or an ISO-8601 timestamp`,
    );
  }
  return trimmed;
}

/**
 * Coerce the raw query-string filters (all strings) into typed
 * AuditSearchFilters. Unknown op/result values are DROPPED (never widen the
 * search) rather than 400 — a screen sending a stale enum value should still
 * get a scoped result, not an error. `limit` is coerced to a positive int.
 * Date bounds are normalized (and rejected when unparseable) by
 * {@link normalizeAuditBound}.
 */
function coerceAuditFilters(raw: Record<string, unknown>): {
  actor?: string;
  agentId?: string;
  op?: import("../types.js").AuditOp;
  result?: "ok" | "denied" | "miss" | "error";
  since?: string;
  until?: string;
  limit?: number;
} {
  const out: {
    actor?: string;
    agentId?: string;
    op?: import("../types.js").AuditOp;
    result?: "ok" | "denied" | "miss" | "error";
    since?: string;
    until?: string;
    limit?: number;
  } = {};
  // An empty string is "no filter", never `actor = ''` (which matches nothing
  // and reads to the auditor as "this person did nothing").
  if (typeof raw.actor === "string" && raw.actor.trim() !== "") out.actor = raw.actor.trim();
  if (typeof raw.agentId === "string" && raw.agentId.trim() !== "") {
    out.agentId = raw.agentId.trim();
  }
  if (typeof raw.op === "string" && (AUDIT_OPS as readonly string[]).includes(raw.op)) {
    out.op = raw.op as import("../types.js").AuditOp;
  }
  if (typeof raw.result === "string" && AUDIT_RESULTS.includes(raw.result)) {
    out.result = raw.result as "ok" | "denied" | "miss" | "error";
  }
  if (typeof raw.since === "string") out.since = normalizeAuditBound(raw.since, "since");
  if (typeof raw.until === "string") out.until = normalizeAuditBound(raw.until, "until");
  if (typeof raw.limit === "number" && Number.isFinite(raw.limit) && raw.limit > 0) {
    out.limit = Math.floor(raw.limit);
  }
  return out;
}

/**
 * The latest persisted fragmentation summary for `namespace` (S6 GET). Reads
 * the sourcesView (which already carries the latest fragmentation for the
 * caller's subtree) is NOT namespace-targeted, so read the report directly for
 * the requested namespace here — the analysis is never re-run on a GET.
 */
async function latestFragmentation(
  kernel: Kernel,
  namespace: Namespace,
): Promise<unknown> {
  const res = await kernel.db.query(
    `SELECT namespace, ran_at, json FROM fragmentation_reports
     WHERE namespace = $1
     ORDER BY ran_at DESC
     LIMIT 1`,
    [namespace],
  );
  if (res.rows.length === 0) return null;
  const row = res.rows[0] as { namespace: string; ran_at: unknown; json: unknown };
  const report = typeof row.json === "string" ? JSON.parse(row.json) : row.json;
  return report;
}

/**
 * J1 setup orchestration: register the tenant, optionally connect a first
 * source, pick the retriever via policy, mint an agent badge, and return the
 * paste-ready MCP snippet. Every step reuses an existing kernel method.
 *
 * The tenant root MUST be inside the caller's subtree (an admin can only set up
 * a tenant it may manage; an owner anywhere). registerTenant is itself
 * owner-only in the registry, so a non-owner admin gets a clean 403 from there.
 */
async function runSetup(
  kernel: Kernel,
  options: BuildHttpDepsOptions,
  input: SetupInput,
  identity: Identity,
): Promise<unknown> {
  const fallback = `http://localhost:${process.env.HALOMEM_PORT ?? "8787"}`;
  const configured = options.publicUrl ?? process.env.HALOMEM_PUBLIC_URL ?? fallback;
  let publicUrl: string;
  try {
    publicUrl = validatePublicUrl(configured, options.secureCookies === true);
  } catch (err) {
    throw new BadRequestError(err instanceof Error ? err.message : String(err));
  }
  try {
    return await kernel.runVerifiedSetup(input, publicUrl, identity);
  } catch (err) {
    if (err instanceof SetupConflictError) throw err;
    if (err instanceof Error && err.name === "SetupValidationError") {
      throw new BadRequestError(err.message);
    }
    throw err;
  }

  /*
  // Scope: the tenant root must be inside the caller's subtree.
  assertAdminScope(identity, input.tenant.id);

  // 1. Register the tenant (owner-only in the registry → clean 403 for admin).
  let tenant: unknown;
  try {
    tenant = await kernel.registerTenant(
      {
        id: input.tenant.id,
        name: input.tenant.name,
        monthlyBudgetUsd: input.tenant.monthlyBudgetUsd ?? null,
        rateLimitPerMin: input.tenant.rateLimitPerMin ?? null,
      },
      identity,
    );
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    if (name === "TenantAuthzError") {
      throw new AuthzError(err instanceof Error ? err.message : String(err));
    }
    if (name === "InvalidTenantIdError") {
      throw new BadRequestError(err instanceof Error ? err.message : String(err));
    }
    throw err;
  }

  // A tenant-root identity to run the tenant-scoped setup steps under (source
  // connect + policy land in the NEW tenant root, not the caller's namespace).
  const tenantIdentity: Identity = {
    keyId: identity.keyId,
    namespace: input.tenant.id,
    actor: identity.actor,
    role: identity.role === "owner" ? "owner" : "admin",
  };

  // 2. Optionally connect a first source in the tenant root.
  let source: unknown = null;
  if (input.source) {
    if (!isSourceKind(input.source.kind)) {
      throw new BadRequestError(`invalid source kind '${input.source.kind}'`);
    }
    try {
      source = await kernel.registerSource(
        input.source.kind,
        input.source.config ?? {},
        tenantIdentity,
      );
    } catch (err) {
      if (err instanceof Error && /no connector for kind/.test(err.message)) {
        throw new BadRequestError(err.message);
      }
      throw err;
    }
  }

  // 3. Pick the retriever (D1 baseline unless overridden) via a policy override
  //    on the tenant root — reuses setPolicy, no bespoke path.
  const retriever = input.retriever ?? "baseline";
  try {
    await kernel.setPolicy(input.tenant.id, `retriever: ${JSON.stringify(retriever)}\n`);
  } catch (err) {
    throw new BadRequestError(err instanceof Error ? err.message : String(err));
  }

  // 4. Mint an agent badge in the tenant root so the snippet works out of the
  //    box (issueKey is owner-gated except bootstrap; the caller is owner/admin
  //    — an admin setting up its own subtree is allowed to issue there).
  const agentActor = input.agentActor ?? `${input.tenant.id}-agent`;
  const { plaintext } = await issueKeyScoped(
    kernel,
    identity,
    input.tenant.id,
    agentActor,
    "agent",
  );

  const mcpSnippet = buildMcpSnippet(input.tenant.id, plaintext, options);
  return { mcpSnippet, tenant, source, badge: { namespace: input.tenant.id, actor: agentActor } };
  */
}

/**
 * A paste-ready MCP client config snippet: the HaloMem Streamable-HTTP endpoint
 * plus the freshly minted bearer badge. The plaintext key is shown exactly ONCE
 * here (issueKey never persists it) — the console surfaces it and warns.
 */
function buildMcpSnippet(
  namespace: Namespace,
  plaintextKey: string,
  options: BuildHttpDepsOptions,
): string {
  const scheme = options.secureCookies ? "https" : "http";
  const port = process.env.HALOMEM_PORT ?? "8787";
  const host = process.env.HALOMEM_HOST ?? "localhost";
  const url = `${scheme}://${host}:${port}/mcp`;
  const config = {
    mcpServers: {
      halomem: {
        url,
        headers: { Authorization: `Bearer ${plaintextKey}` },
        note: `Halofy organizational memory for namespace '${namespace}'`,
      },
    },
  };
  return JSON.stringify(config, null, 2);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Options the HTTP entrypoint threads in (console dir + cookie security). */
export interface BuildHttpDepsOptions {
  /** Absolute path to the `console/` dir served at GET /console/* (M5). */
  consoleDir?: string;
  /** Set the cookie `Secure` attribute (true behind TLS, false on localhost). */
  secureCookies?: boolean;
  /** Validated public origin for generated MCP snippets. */
  publicUrl?: string;
  /** Override the env-derived Supabase SSO service (tests). Null disables SSO. */
  sso?: SupabaseSsoService | null;
  /** Override the env-derived GitHub OAuth service (tests). Null disables it. */
  github?: GitHubOAuthService | null;
}

export function buildHttpDeps(
  kernel: Kernel,
  options: BuildHttpDepsOptions = {},
): HttpServerDeps {
  const authRateLimits = new DurableRateLimitStore(kernel.db);
  // How many trusted reverse proxies sit in front of us. MUST match the real
  // topology: too low and every caller shares one rate-limit bucket (one actor
  // can 429 the whole tenant base); too high and a caller can forge its own
  // bucket through `x-forwarded-for`. Container Apps / most managed ingress = 1.
  // Default 0 keeps direct listens (tests, localhost, `npm run serve`) exact.
  const trustedProxyHops = (() => {
    const raw = Number(process.env.HALOMEM_TRUSTED_PROXY_HOPS ?? 0);
    return Number.isInteger(raw) && raw >= 0 ? raw : 0;
  })();
  const httpTelemetry = new BoundedHttpRedMetrics();
  // SSO (Supabase): built from SUPABASE_URL/SUPABASE_ANON_KEY unless a test
  // injects (or explicitly disables) it. Requires the real human-auth stores.
  // The link table is shared by both providers (GitHub + Google), so it is
  // built before the services that write to it.
  const externalIdentities = new ExternalIdentityStore(kernel.db);
  const sso =
    options.sso !== undefined
      ? options.sso
      : kernel.users && kernel.sessions && kernel.invitations
        ? supabaseSsoFromEnv({
            stores: { users: kernel.users, sessions: kernel.sessions },
            invitations: kernel.invitations,
            signup: kernel.organizationSignup,
            allowOrganizationSignup: organizationSignupAllowed(
              process.env,
              kernel.quota.isEnabled(),
            ),
            identities: externalIdentities,
          })
        : null;
  // GitHub OAuth: same shape as SSO — env-built unless a test injects (or
  // explicitly disables) the service. Unconfigured → undefined handlers → the
  // /auth/github* routes 404 and the login page hides the button.
  const github =
    options.github !== undefined
      ? options.github
      : kernel.users && kernel.sessions && kernel.invitations
        ? githubOAuthFromEnv({
            db: kernel.db,
            stores: { users: kernel.users, sessions: kernel.sessions },
            invitations: kernel.invitations,
            identities: externalIdentities,
          })
        : null;
  const oidcRaw = process.env.HALOMEM_OIDC_CONFIG;
  let oidc: OidcAuthenticator | null = null;
  if (oidcRaw) {
    const parsed = JSON.parse(oidcRaw) as { providers?: unknown };
    if (!Array.isArray(parsed.providers)) {
      throw new Error("HALOMEM_OIDC_CONFIG.providers must be an array");
    }
    oidc = new OidcAuthenticator(parsed.providers as OidcAuthenticatorProvider[]);
  }
  const scimRaw = process.env.HALOMEM_SCIM_CONFIG;
  let scim: Array<{ tokenHash: Buffer; service: ScimProvisioningService }> = [];
  if (scimRaw) {
    const parsed = JSON.parse(scimRaw) as {
      token?: unknown; groups?: unknown; defaultBinding?: unknown; tenants?: unknown;
    };
    const tenants = Array.isArray(parsed.tenants) ? parsed.tenants : [parsed];
    if (tenants.length === 0 || tenants.length > 100) {
      throw new Error("HALOMEM_SCIM_CONFIG.tenants must contain 1..100 tenant credentials");
    }
    scim = tenants.map((raw) => {
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw new Error("HALOMEM_SCIM_CONFIG tenant entry is invalid");
      }
      const entry = raw as { token?: unknown; groups?: unknown; defaultBinding?: unknown };
      if (typeof entry.token !== "string" || entry.token.length < 24 ||
          entry.groups === null || typeof entry.groups !== "object" || Array.isArray(entry.groups)) {
        throw new Error("HALOMEM_SCIM_CONFIG requires a strong token and group mappings per tenant");
      }
      const groups = entry.groups as Record<string, ScimAuthorityBinding>;
      const defaultBinding = entry.defaultBinding as ScimAuthorityBinding | undefined;
      return {
        tokenHash: createHash("sha256").update(entry.token).digest(),
        service: new ScimProvisioningService(new DbScimDirectory(kernel.db, groups, defaultBinding), {
          groups, ...(defaultBinding ? { defaultBinding } : {}),
        }),
      };
    });
    const unique = new Set(scim.map((entry) => entry.tokenHash.toString("hex")));
    if (unique.size !== scim.length) throw new Error("HALOMEM_SCIM_CONFIG tokens must be unique");
  }

  const syscalls: HttpSyscalls = {
    memRead: (payload, identity, ctx) =>
      kernel.memRead(parse(readSchema, payload, "mem/read"), identity, AGENT_ID, ctx),
    memSearch: (payload, identity, ctx) =>
      kernel.memSearch(parse(searchSchema, payload, "mem/search"), identity, AGENT_ID, ctx),
    // CA1: the conflict check is kicked AFTER the write resolves and its result
    // is never awaited — a slow or unavailable judge can delay detection, never
    // the caller's write.
    memWrite: async (payload, identity) => {
      const result = await kernel.memWrite(
        parse(writeSchema, payload, "mem/write"), identity, AGENT_ID,
      );
      void kernel.runConflictAutopilotOnce();
      return result;
    },
    memFault: (payload, identity, ctx) =>
      kernel.memFault(parse(faultSchema, payload, "mem/fault"), identity, AGENT_ID, ctx),
    memStats: (payload, identity) =>
      kernel.memStats(parse(statsSchema, payload, "mem/stats"), identity, AGENT_ID),
    memAssemble: (payload, identity, ctx) =>
      kernel.memAssemble(parse(assembleSchema, payload, "mem/assemble"), identity, AGENT_ID, ctx),
    memPolicy: (payload, identity, ctx) =>
      kernel.memPolicy(parse(policySchema, payload, "mem/policy"), identity, AGENT_ID, ctx),
    memPolicyAck: (payload, identity, ctx) =>
      kernel.memPolicyAck(
        parse(policyAckSchema, payload, "mem/policy-ack"),
        identity,
        AGENT_ID,
        ctx,
      ),
    memPin: (payload, identity) => {
      const { target } = parse(pinSchema, payload, "mem/pin");
      return kernel.memPin(target as PinTarget, identity);
    },
    memUnpin: (payload, identity) => {
      const { pinId } = parse(unpinSchema, payload, "mem/unpin");
      return kernel.memUnpin(pinId, identity);
    },
    memShare: (payload, identity) => {
      const { target, targetNamespace } = parse(shareSchema, payload, "mem/share");
      return kernel.memShare(target as PinTarget, targetNamespace, identity);
    },
    sourceRead: (payload, identity) => {
      const input = parse(sourceReadSchema, payload, "agent/source-read");
      return kernel.agentSourceRead({ operation: "source-read", ...input }, identity);
    },
    completeAgentSession: (payload, identity) =>
      kernel.completeAgentSession(
        identity,
        parse(agentSessionCompleteSchema, payload, "agent-sessions/complete"),
      ),
    requestAgentAccess: (payload, identity) =>
      kernel.createAgentAccessRequest(
        parse(createAgentAccessRequestSchema, payload, "agent/access-requests"),
        identity,
      ),
    listAgentAccessRequests: (identity) => kernel.listOwnAgentAccessRequests(identity),
    describeAgentAccess: (identity) => kernel.describeAgentAccess(identity),
    writeStatus: async (ticket, identity) => kernel.writeStatus(ticket, identity),
    // M9 #6: payload arrives pre-validated by parseManifestArgs at the route.
    memManifest: (payload, identity) =>
      kernel.memManifest(payload as unknown as MemManifestArgs, identity, AGENT_ID),
    // M9 #7 (D28): role/source/classification gating lives INSIDE the syscall
    // (owner/admin/auditor; member/agent audited-denied) — never duplicated here.
    memExport: (payload, identity) =>
      kernel.memExport(identity, parse(exportOptionsSchema, payload, "mem/export")),
    // M9 #18 (D31): parseAnswerOutcomeBody (kernel side) validates the
    // untrusted body and hard-rejects identity-shaped fields.
    recordAnswerOutcome: (payload, identity) =>
      kernel.recordAnswerOutcome(identity, payload),
    // M9 #9 (E20/E22): the audited skill gate. D9: only skillKey crosses.
    invokeSkill: (payload, identity) => {
      const input = parse(skillInvokeSchema, payload, "skills/invoke");
      return kernel.invokeSkill(identity, input.skillKey);
    },
    // S16: member-visible library surface — same registration body shape as
    // the admin lane; the STORE decides pending vs approved from the role,
    // and gates the download on approved+vetted. D9: no namespace crosses.
    listSkills: (identity) => kernel.listSkills(identity),
    registerSkill: (payload, identity) =>
      kernel.registerSkill(identity, parse(skillRegisterSchema, payload, "skills")),
    downloadSkill: (id, identity) => kernel.exportSkill(identity, id),
  };

  return {
    consoleDir: options.consoleDir,
    secureCookies: options.secureCookies,
    publicUrl: options.publicUrl,

    webhooks: {
      ingest: (sourceId, rawBody, timestamp, signature) =>
        kernel.ingestWebhookSource(sourceId, rawBody, timestamp, signature),
      obsidian: (sourceId, rawBody, timestamp, signature) =>
        kernel.ingestObsidianVault(sourceId, rawBody, timestamp, signature),
    },

    // M9 #13 (E47): S10 chips, derived per the caller's resolved namespace.
    suggestedQuestions: (identity) => kernel.suggestedQuestions(identity),

    // M9 #11a (E28–E30): unauthenticated public org discovery. The kernel
    // module resolves the slug server-side, fences to public-classified
    // canonical rows, redacts provenance, and audits every outcome (D4).
    publicDiscovery: (orgSlug, format) => kernel.publicDiscovery(orgSlug, format),

    // M9 #11b (D29): hosted OAuth AS envelopes — client authentication and
    // audits live inside src/oauth/; the transport only adapts shapes.
    oauth: {
      token: (request) => kernel.oauthToken(request),
      introspect: (request) => kernel.oauthIntrospect(request),
      revoke: (request) => kernel.oauthRevoke(request),
      // CONTRACTS-OAUTH-CONNECT: DCR + the consent surface (OA2/OA8).
      register: (request) => kernel.oauthRegister(request),
      authorizePage: (query, rawQuery, identity, issuer) =>
        kernel.oauthAuthorizePage(query, rawQuery, identity, issuer),
      authorizeDecision: (body, identity, issuer) =>
        kernel.oauthAuthorizeDecision(body, identity, issuer),
      metadata: (issuer) => kernel.oauthMetadata(issuer),
      resourceMetadata: (issuer, resourceSuffix) =>
        kernel.oauthResourceMetadata(issuer, resourceSuffix),
    },

    auth: {
      resolve: (plaintextKey) => kernel.auth.resolve(plaintextKey),
      resolveOidc: oidc ? (token) => oidc.authenticate(token) : undefined,
      // M9 #11b (D29): opaque hmt_ bearer → server-resolved Identity, exactly
      // the API-key seam. The token service audits every miss and denial.
      resolveOauth: (token) => kernel.resolveOAuthIdentity(token),
      // M5 human sign-in: session cookie ↔ D9 Identity. Expiry + disabled are
      // enforced server-side in the kernel/SessionStore, never trusted from the
      // cookie. login returns null on any failure (no enumeration oracle).
      resolveSession: (token) => kernel.resolveSessionIdentity(token),
      // M10 (D41/E1): every `user` payload leaving the console boundary is
      // translated through the ONE seam (owner → root, auditor → member +
      // audit:read). Internal storage and Identity stay untouched.
      login: async (email, password) => {
        const result = await kernel.login(email, password);
        return result === null
          ? null
          : { token: result.token, user: toPublicUser(result.user) };
      },
      bootstrap: async (input) => {
        const result = await kernel.bootstrapHuman(input);
        return result === null
          ? null
          : { ...result, user: toPublicUser(result.user) };
      },
      acceptInvite: async (token, password) => {
        const user = await kernel.acceptHumanInvite(token, password);
        return user === null ? null : toPublicUser(user);
      },
      logout: (token) => kernel.logout(token),
      // SSO (Supabase): authn at the IdP, authz in the kernel users table.
      // Unconfigured env → undefined handlers → /auth/sso 404s and the login
      // page falls back to native email+password.
      ssoConfig: sso ? () => sso.publicConfig() : undefined,
      ssoExchange: sso
        ? async (accessToken) => {
            const result = await sso.exchange(accessToken);
            return result.status === "ok"
              ? { ...result, user: toPublicUser(result.user as { role: string }) }
              : result;
          }
        : undefined,
      signupPending: (token) => kernel.organizationSignup.inspect(token),
      signupComplete: async (token, organizationName, displayName) => {
        const completed = await kernel.organizationSignup.complete(
          token,
          organizationName,
          displayName,
        );
        return completed === null
          ? null
          : {
              ...completed,
              user: toPublicUser(completed.user as unknown as { role: string }),
            };
      },
      // GitHub OAuth: the transport gets three closures that each run the
      // exchange + server-side profile read before touching kernel state.
      githubConfig: github ? () => true : undefined,
      githubAuthorize: github
        ? (state, redirectUri) => github.authorizeUrl(state, redirectUri)
        : undefined,
      githubLogin: github
        ? async (code, redirectUri) => {
            const accessToken = await github.exchangeCode(code, redirectUri);
            if (accessToken === null) return { status: "unauthenticated" as const };
            const profile = await github.fetchProfile(accessToken);
            if (profile === null) return { status: "unauthenticated" as const };
            const result = await github.loginWithGitHub(profile);
            // M10 (D41): the login user payload carries a product role.
            return result.status === "ok"
              ? { ...result, user: toPublicUser(result.user as { role: string }) }
              : result;
          }
        : undefined,
      githubLink: github
        ? async (code, redirectUri, identity) => {
            const accessToken = await github.exchangeCode(code, redirectUri);
            if (accessToken === null) return { status: "unauthenticated" as const };
            const profile = await github.fetchProfile(accessToken);
            if (profile === null) return { status: "unauthenticated" as const };
            const user = kernel.users ? await kernel.users.byEmail(identity.actor) : null;
            if (user === null) return { status: "unauthenticated" as const };
            try {
              const linked = await github.linkForUser(user.id, profile);
              return { status: "linked" as const, login: linked.login };
            } catch (err) {
              if (err instanceof IdentityConflictError) return { status: "conflict" as const };
              throw err;
            }
          }
        : undefined,
      // Google (Supabase SSO) linking from the Profile screen. The token proves
      // the Google account only — the kernel user comes from the session.
      ssoLinkGoogle: sso
        ? async (accessToken, identity) => {
            const user = kernel.users ? await kernel.users.byEmail(identity.actor) : null;
            if (user === null) return { status: "unauthenticated" as const };
            const result = await sso.linkGoogle(accessToken, user.id);
            return result.status === "linked"
              ? { status: "linked" as const, login: result.identity.login }
              : result;
          }
        : undefined,
      // The identity store exists regardless of OAuth config (the table is
      // always migrated), so the Profile screen can list/unlink even when the
      // connect buttons are hidden. `hasPassword` completes the picture: the
      // native email+password channel is a sign-in method too.
      listIdentities: async (identity) => {
        const user = kernel.users ? await kernel.users.byEmail(identity.actor) : null;
        if (user === null) return { identities: [], email: identity.actor, hasPassword: false };
        return {
          identities: await externalIdentities.listForUser(user.id),
          email: user.email,
          hasPassword: await kernel.users!.hasPassword(user.id),
        };
      },
      profile: (identity) => kernel.memberProfile(identity),
      updateProfile: (identity, body) => kernel.updateMemberProfile(identity, body),
      unlinkIdentity: async (identity, provider) => {
        if (!isExternalProvider(provider)) return false;
        const user = kernel.users ? await kernel.users.byEmail(identity.actor) : null;
        if (user === null) return false;
        // Never let a user disconnect their way out of their own account.
        const linked = await externalIdentities.listForUser(user.id);
        if (!linked.some((entry) => entry.provider === provider)) return false;
        const methods =
          linked.length + ((await kernel.users!.hasPassword(user.id)) ? 1 : 0);
        if (methods <= 1) return "last_method";
        return externalIdentities.unlink(user.id, provider);
      },
    },

    // M10 — role-scoped memory graph + root View-as. The transport reads the
    // preview header and the cookie; everything else is server-resolved
    // inside the kernel facades (D9). Raw tokens never reach handlers.
    access: {
      resolveConsoleSession: (token) => kernel.resolveConsoleSession(token),
      memoryGraph: (session, opts, previewToken) =>
        kernel.memoryGraphView(session, opts, previewToken),
      viewAsTargets: (session) => kernel.viewAsTargets(session),
      viewAsStart: (session, body) => kernel.viewAsStart(session, body),
      viewAsEnd: (session, id) => kernel.viewAsEnd(session, id),
      resolvePreview: (session, token) => kernel.viewAsResolve(session, token),
      rejectMutation: (session, previewSessionId, method, path) =>
        kernel.viewAsRejectMutation(session, previewSessionId, method, path),
    },

    syscalls,

    admin: {
      async getPolicy(ns, identity) {
        assertAdminScope(identity, ns);
        return kernel.policyStore.getFresh(ns);
      },
      async setPolicy(ns, yamlText, identity) {
        assertAdminScope(identity, ns);
        try {
          await kernel.setPolicy(ns, yamlText);
        } catch (err) {
          // Invalid YAML/shape is a caller error, not a 500.
          throw new BadRequestError(err instanceof Error ? err.message : String(err));
        }
        return { ok: true, namespace: ns };
      },
      async listPolicyDocuments(query, identity) {
        if (
          identity.role !== "owner" &&
          identity.role !== "admin" &&
          identity.role !== "auditor"
        ) {
          throw new AuthzError("owner, admin, or auditor role required");
        }
        const input = parse(
          policyDocumentListSchema,
          query,
          "admin/policy-documents query",
        );
        if (input.namespace === "" && !isRootOwner(identity)) {
          throw new AuthzError("only the platform root owner may use the global policy scope");
        }
        assertReadScope(identity, input.namespace);
        return kernel.listPolicyDocuments(input, identity);
      },
      async listPolicyDocumentScopes(query, identity) {
        if (
          identity.role !== "owner" &&
          identity.role !== "admin" &&
          identity.role !== "auditor"
        ) {
          throw new AuthzError("owner, admin, or auditor role required");
        }
        return kernel.listPolicyDocumentScopes(
          parse(policyDocumentScopesSchema, query, "admin/policy-scopes query"),
          identity,
        );
      },
      async uploadPolicyDocument(body, identity) {
        const input = parse(
          policyDocumentUploadSchema,
          body,
          "admin/policy-documents",
        );
        if (input.namespace === "" && !isRootOwner(identity)) {
          throw new AuthzError("only the platform root owner may upload to the platform root");
        }
        assertAdminScope(identity, input.namespace);
        try {
          return await kernel.uploadPolicyDocument(input, identity);
        } catch (error) {
          if (error instanceof Error && error.name === "PolicyDocumentValidationError") {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async policyCompliance(namespace, identity) {
        if (namespace === "" && !isRootOwner(identity)) {
          throw new AuthzError("only the platform root owner may use the global policy scope");
        }
        assertReadScope(identity, namespace);
        return kernel.policyComplianceReport(namespace, identity);
      },
      async setPolicyEnforcement(documentId, body, identity) {
        const input = parse(
          policyEnforcementSchema,
          body,
          "admin/policy-documents/:id/enforcement",
        );
        try {
          return await kernel.setPolicyDocumentEnforcement(
            documentId,
            input.enforcement,
            identity,
          );
        } catch (error) {
          if (error instanceof Error && error.name === "PolicyDocumentValidationError") {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async deletePolicyDocument(documentId, identity) {
        try {
          return await kernel.deletePolicyDocument(documentId, identity);
        } catch (error) {
          if (error instanceof Error && error.name === "PolicyDocumentValidationError") {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async listPolicyAdoptionCandidates(query, identity) {
        if (
          identity.role !== "owner" &&
          identity.role !== "admin" &&
          identity.role !== "auditor"
        ) {
          throw new AuthzError("owner, admin, or auditor role required");
        }
        const input = parse(
          policyAdoptionCandidateSchema,
          query,
          "admin/policy-adoption-candidates query",
        );
        const namespace = input.namespace ?? identity.namespace;
        if (namespace === "" && !isRootOwner(identity)) {
          throw new AuthzError("only the platform root owner may use the global policy scope");
        }
        assertReadScope(identity, namespace);
        try {
          return await kernel.listPolicyAdoptionCandidates(
            { namespace, limit: input.limit },
            identity,
          );
        } catch (error) {
          if (error instanceof Error && error.name === "PolicyDocumentValidationError") {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async adoptPolicyDocument(body, identity) {
        const input = parse(
          policyDocumentAdoptSchema,
          body,
          "admin/policy-documents/adopt",
        );
        if (input.namespace === "" && !isRootOwner(identity)) {
          throw new AuthzError("only the platform root owner may adopt into the platform root");
        }
        assertAdminScope(identity, input.namespace);
        try {
          return await kernel.adoptPolicyDocument(input, identity);
        } catch (error) {
          if (error instanceof Error && error.name === "PolicyDocumentValidationError") {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async listKeys(identity) {
        // M9 #23: same AuthService.list visibility, decorated with the product
        // key-type label (a pure read-side decoration — no scope change).
        return kernel.productKeys.list(identity);
      },
      async issueKey(params, identity) {
        // D58: members have one issuance surface only. The legacy role-based
        // body can carry source principals/groups that predate the product-key
        // projection, so it must not bypass the typed Assistant contract.
        if (
          identity.role === "member" &&
          (params as { type?: unknown }).type !== "assistant"
        ) {
          throw new AuthzError("members may only issue typed Assistant keys");
        }
        // M9 #23 (E52): a body carrying `type` is a typed product-key request —
        // routed through ProductKeyService (audited ok AND denied, D4). The
        // legacy role-based path below stays byte-identical for old callers.
        if (typeof (params as { type?: unknown }).type === "string") {
          const typed = parse(issueTypedKeySchema, params, "admin/keys");
          if (!isProductKeyType(typed.type)) {
            throw new BadRequestError(`invalid key type '${typed.type}'`);
          }
          // Only an agent credential has an authorization rule about the empty
          // namespace worth auditing. For the human key types it stays a plain
          // input error, exactly as before.
          if (typed.namespace === "" && typed.type !== "assistant") {
            throw new BadRequestError("namespace is required");
          }
          if (typed.recipientUserId) {
            if (typed.type !== "assistant") {
              throw new BadRequestError("only Assistant keys may be assigned to a member");
            }
            if (typed.agentAccessLevel === "manager") {
              throw new BadRequestError("delegated Assistant keys are member-scoped");
            }
            if (!typed.idempotencyKey) {
              throw new BadRequestError("idempotencyKey is required for delegated badges");
            }
            return {
              handoff: await kernel.productKeys.assignToMember({
                namespace: typed.namespace,
                actor: typed.actor,
                recipientUserId: typed.recipientUserId,
                idempotencyKey: typed.idempotencyKey,
                ...(typed.expiresAt ? { expiresAt: typed.expiresAt } : {}),
                ...(typed.agentCanWrite === undefined
                  ? {}
                  : { agentCanWrite: typed.agentCanWrite }),
              }, identity),
            };
          }
          return kernel.productKeys.issue(
            {
              type: typed.type,
              namespace: typed.namespace,
              actor: typed.actor,
              ...(typed.agentAccessLevel ? { agentAccessLevel: typed.agentAccessLevel } : {}),
              ...(typed.expiresAt ? { expiresAt: typed.expiresAt } : {}),
              ...(typed.description ? { description: typed.description } : {}),
              ...(typed.agentCanWrite === undefined ? {} : { agentCanWrite: typed.agentCanWrite }),
            },
            identity,
          );
        }
        const body = parse(issueKeySchema, params, "admin/keys");
        if (!isRole(body.role)) {
          throw new BadRequestError(`invalid role '${body.role}'`);
        }
        // M5 admin-subtree model: an admin may issue a badge INSIDE its own
        // subtree (only a root owner is global). assertAdminScope is the authoritative gate
        // (admin outside its subtree → 403; a member/agent never reaches here —
        // the transport already 403'd them). AuthService.issueKey is owner-only
        // for DIRECT callers, so once scope is verified we present an owner-role
        // caller for the issuance — no privilege is granted that the scope check
        // did not already authorize. A member issuing (M1) is still denied.
        const { record, plaintext } = await issueKeyScoped(
          kernel,
          identity,
          body.namespace,
          body.actor,
          body.role as Role,
          {
            sourcePrincipals: body.sourcePrincipals,
            sourceGroups: body.sourceGroups,
            ...(body.agentAccessLevel
              ? { agentAccessLevel: body.agentAccessLevel as AgentAccessLevel }
              : {}),
          },
        );
        // Plaintext is shown exactly once — here.
        return { record, plaintext };
      },
      async revokeKey(keyId, identity) {
        // M9 #23: delegated to ProductKeyService.revoke — the SAME
        // auth.list-visibility subtree gate as before, plus the D4 audit row
        // (ok and denied) the old inline revoke never wrote.
        return kernel.productKeys.revoke(keyId, identity);
      },
      async rotateKey(keyId, identity) {
        // M9 #23 (E52): scope-preserving rotation — type/namespace/actor are
        // read from the STORED row inside the service (D9); audited ok/denied.
        return kernel.productKeys.rotate(keyId, identity);
      },
      async revealKey(keyId, identity) {
        try {
          return await kernel.productKeys.reveal(keyId, identity);
        } catch (error) {
          if (error instanceof BearerUnavailableError) {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async listKeyHandoffs(identity) {
        return { handoffs: await kernel.productKeys.listAssigned(identity) };
      },
      async claimKeyHandoff(id, identity) {
        return kernel.productKeys.claimAssigned(id, identity);
      },
      async revokeKeyHandoff(id, identity) {
        return kernel.productKeys.revokeAssigned(id, identity);
      },
      async listAgentConnections(identity) {
        return kernel.listAgentConnectionGrants(identity);
      },
      async createAgentConnection(body, identity) {
        const input = parse(createAgentConnectionSchema, body, "admin/agent-connections");
        return kernel.createAgentConnectionGrant(
          { ...input, expiresAt: input.expiresAt ?? null },
          identity,
        );
      },
      async revokeAgentConnection(id, identity) {
        return { revoked: await kernel.revokeAgentConnectionGrant(id, identity) };
      },
      async issueAgentBadge(body, identity) {
        return kernel.issueAgentBadge(
          parse(issueAgentBadgeSchema, body, "admin/agent-badges"),
          identity,
        );
      },
      async listAgentAccessEvents(filters, identity) {
        return kernel.listAgentAccessEvents(
          parse(agentAccessEventFiltersSchema, filters, "admin/agent-access/events"),
          identity,
        );
      },
      async listAgentAccessAlerts(filters, identity) {
        return kernel.listAgentAccessAlerts(
          parse(agentAccessAlertFiltersSchema, filters, "admin/agent-access/alerts"),
          identity,
        );
      },
      async acknowledgeAgentAccessAlert(id, identity) {
        return { acknowledged: await kernel.acknowledgeAgentAccessAlert(id, identity) };
      },
      async listAgentAccessRequests(filters, identity) {
        return kernel.listAgentAccessRequests(
          parse(agentAccessRequestFiltersSchema, filters, "admin/agent-access/requests"),
          identity,
        );
      },
      async approveAgentAccessRequest(id, body, identity) {
        return kernel.approveAgentAccessRequest(
          id,
          parse(approveAgentAccessRequestSchema, body, "admin/agent-access/requests/approve"),
          identity,
        );
      },
      async denyAgentAccessRequest(id, body, identity) {
        return kernel.denyAgentAccessRequest(
          id,
          parse(denyAgentAccessRequestSchema, body, "admin/agent-access/requests/deny"),
          identity,
        );
      },
      async listPins(namespace, identity) {
        assertReadScope(identity, namespace);
        return kernel.listPins(identity, namespace);
      },
      async createPin(body, identity) {
        const input = parse(adminPinSchema, body, "admin/pins");
        const namespace = input.namespace ?? identity.namespace;
        assertAdminScope(identity, namespace);
        return kernel.pins.pin(input.target as PinTarget, identity, { namespace });
      },
      async deletePin(pinId, identity) {
        return kernel.memUnpin(pinId, identity);
      },
      async revokeMount(mountId, identity) {
        return kernel.sharing.revokeMount(identity, mountId);
      },
      async forkMount(body, identity) {
        const input = parse(forkMountSchema, body, "admin/mounts/fork");
        assertAdminScope(identity, input.targetNamespace);
        return kernel.sharing.forkMountedRef(identity, {
          ...input,
          origin: input.origin as PinTarget,
        });
      },
      async runMovement(body, identity) {
        try {
          return await kernel.movement.runManual(
            identity,
            parse(movementSchema, body, "admin/movement/run"),
          );
        } catch (error) {
          if (
            error instanceof Error &&
            error.message === "idempotencyKey is already bound to another movement action"
          ) {
            throw new MovementConflictError(error.message);
          }
          if (
            error instanceof Error &&
            (error.message === "targetRef must be a stable ULID reference" ||
              error.message === "idempotencyKey is required" ||
              error.message === "propose_cold requires at least two unique stable evidenceIds including targetRef")
          ) {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },
      async runScorecard(ns, identity) {
        // M2: referee run — same subtree rule as the other admin mutations.
        assertAdminScope(identity, ns);
        try {
          // D4: pass the caller identity so the scorecard's audit row is
          // attributed to the admin who ran it.
          const card = await kernel.runScorecard(ns, undefined, identity);
          const policy = await kernel.getPolicy(ns);
          const effectiveLiveRetriever = policy.abTest
            ? {
                mode: "ab-test" as const,
                configured: {
                  a: policy.abTest.a,
                  b: policy.abTest.b,
                  pctB: policy.abTest.pctB,
                },
                serving: {
                  a: kernel.registry.get(policy.abTest.a).name,
                  b: kernel.registry.get(policy.abTest.b).name,
                },
              }
            : {
                mode: "fixed" as const,
                configured: policy.retriever ?? "baseline",
                serving: kernel.registry.get(policy.retriever ?? "baseline").name,
              };
          return {
            ...card,
            benchmarkWinner: card.winner,
            effectiveLiveRetriever,
          };
        } catch (err) {
          // "namespace has no scorable facts" is a caller problem, not a 500.
          if (err instanceof Error && /no facts|no drivers/.test(err.message)) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      // M4: compliance erasure. The route already gated owner/admin; memForget
      // re-checks the role (auditor/member/agent denied + audited) and scopes
      // erasure to the caller's subtree via identity. Returns the signed cert.
      async forget(body, identity) {
        const { target } = parse(forgetSchema, body, "admin/forget");
        return kernel.memForget({ target }, identity);
      },

      // M4: read a persisted certificate. The route gated owner/admin/auditor;
      // the kernel then scopes the read to the caller's subtree (an auditor is
      // org-wide WITHIN its own tenant, never across the tenant fence). A cert
      // outside the caller's subtree — or an unknown id — → null → the route
      // maps to 404 (denied collapses to miss, no cross-tenant oracle).
      async getCertificate(id, identity) {
        const certificate = await kernel.getCertificate(id, identity);
        if (certificate === null) return null;
        return {
          ...certificate,
          verified: kernel.verifyCertificate(certificate),
        };
      },

      // M4: register a tenant. registerTenant is owner-only in the registry;
      // map its typed errors to 403/400 (a non-owner admin gets a clean 403,
      // a bad id a clean 400 — never a 500).
      async registerTenant(body, identity) {
        const input = parse(registerTenantSchema, body, "admin/tenants");
        assertAdminScope(identity, input.id);
        try {
          return await kernel.registerTenant(input, identity);
        } catch (err) {
          const name = err instanceof Error ? err.name : "";
          if (name === "TenantAuthzError") {
            throw new AuthzError(err instanceof Error ? err.message : String(err));
          }
          if (name === "InvalidTenantIdError") {
            throw new BadRequestError(err instanceof Error ? err.message : String(err));
          }
          throw err;
        }
      },

      // M4: list tenants visible to the caller (ancestor-ACL scoped in the
      // registry — a caller never sees a sibling tenant).
      async listTenants(identity) {
        return kernel.listTenants(identity);
      },

      // R6: warm-store mirror administration. Root-owner-only — the kernel
      // methods enforce it (AuthzError → 403); the mirror is process-global
      // infrastructure holding many tenants' rows.
      async warmStores(identity) {
        return kernel.warmStatus(identity);
      },
      async warmFlush(identity) {
        return kernel.warmFlush(identity);
      },
      async warmRebuild(name, body, identity) {
        const { namespace } = parse(warmRebuildSchema, body, "admin/warmstores/rebuild");
        try {
          return await kernel.warmRebuild(name, namespace, identity);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (err instanceof Error && err.name === "WarmStoreUnavailableError") {
            throw new BadRequestError(message);
          }
          if (/canonical - nothing to rebuild/.test(message)) {
            throw new BadRequestError(message);
          }
          throw err;
        }
      },

      // M4: suspend a tenant (bulk revoke its keyspace). Same subtree rule as
      // the other admin mutations — an admin may only suspend a tenant root
      // inside its own subtree; owner anywhere.
      async suspendTenant(id, identity) {
        assertAdminScope(identity, id);
        const tenant = await kernel.suspendTenant(id);
        if (tenant === null) {
          throw new BadRequestError(`no tenant with id '${id}'`);
        }
        return tenant;
      },

      // Organization adoption — orphan-namespace repair. Platform-root only
      // (the kernel enforces it); AdoptError input problems map to 400.
      async adoptOrganization(body, identity) {
        const input = parse(adoptOrganizationSchema, body, "admin/org/adopt");
        try {
          return await kernel.adoptOrganizationNamespaces(input, identity);
        } catch (err) {
          if (err instanceof Error && err.name === "AdoptError") {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      // --- M5 control-room management API -----------------------------------
      // Read handlers are subtree-scoped INSIDE the kernel (the caller's own
      // namespace + descendants + ancestors); the route already gated the role
      // to owner/admin/auditor. Mutating handlers were role-gated to owner/admin
      // by the route (auditor is read-only) and additionally scope to the
      // caller's subtree via assertAdminScope before touching the kernel.

      async overview(query, identity) {
        // Home's 7/30/90 control. A missing or unparseable `days` falls through
        // to the all-time view rather than an empty dashboard; the kernel
        // clamps the rest.
        const days =
          typeof query.days === "string" && query.days !== ""
            ? Number(query.days)
            : undefined;
        return kernel.overview(identity, { days });
      },
      async people(identity) {
        return kernel.people(identity);
      },
      async teamDirectory(identity) {
        return kernel.teamDirectory(identity);
      },

      // POST /v1/admin/people — invite a human user (S3). Owner/admin only (the
      // route denied auditor); the target namespace must be inside the caller's
      // subtree (assertAdminScope). D41: `role` is a PRODUCT role — the retired
      // internal spellings ('owner'/'auditor') are rejected by fromProductRole,
      // and `root` maps to internal 'owner' through this documented
      // root-assignment route. createUser is the second gate: minting an OWNER
      // still requires an owner caller (an admin minting an owner would
      // escalate a scoped admin to org owner). Because a resolved caller is
      // always present here, the empty-users bootstrap branch (no-caller/
      // direct-DB only) is never reachable.
      async invitePerson(body, identity) {
        const input = parse(invitePersonSchema, body, "admin/people");
        const internalRole = fromProductRole(String(input.role), {
          rootAssignment: true,
        });
        assertAdminScope(identity, input.namespace);
        try {
          return await kernel.inviteHuman(
            {
              email: input.email,
              displayName: input.displayName,
              namespace: input.namespace,
              role: internalRole,
              ttlSeconds: input.ttlSeconds,
            },
            identity,
          );
        } catch (err) {
          // UserStore throws AuthzError (name 'AuthzError' → 403) /
          // BadRequestError (name 'BadRequestError' → 400) — both already map in
          // server.ts. Rethrow untouched.
          throw err;
        }
      },
      async personAccessImpact(userId, identity) {
        return kernel.personAccessImpact(identity, userId);
      },
      async changePersonAccessState(userId, body, identity) {
        const input = parse(personAccessStateSchema, body, "admin/people/access-state");
        return kernel.changePersonAccessState(identity, userId, input);
      },

      // S13 teams. Reads are subtree-scoped inside the kernel; mutations are
      // additionally role-gated there (owner/admin only — the route already
      // denied auditor on mutating verbs). The team namespace is DERIVED from
      // the caller's identity, never read from the body (D9).
      async listTeams(identity) {
        return kernel.listTeams(identity);
      },
      async createTeam(body, identity) {
        const input = parse(createTeamSchema, body, "admin/teams");
        return kernel.createTeam(identity, input);
      },
      async updateTeam(teamId, body, identity) {
        const input = parse(updateTeamSchema, body, "admin/teams/update");
        if (input.name !== undefined) {
          if (input.archived !== undefined) {
            throw new Error("team update accepts one operation at a time");
          }
          return kernel.renameTeam(identity, teamId, input.name);
        }
        return kernel.setTeamArchived(identity, teamId, input.archived!);
      },
      async addTeamMember(teamId, body, identity) {
        const input = parse(addTeamMemberSchema, body, "admin/teams/members");
        return kernel.addTeamMember(identity, teamId, input.email);
      },
      async changeTeamMemoryAccess(teamId, body, identity) {
        const input = parse(
          changeTeamMemoryAccessSchema,
          body,
          "admin/teams/memory-access",
        );
        return kernel.changeTeamMemoryAccess(identity, teamId, input.mode);
      },
      async inviteTeamMember(teamId, body, identity) {
        const input = parse(inviteTeamMemberSchema, body, "admin/teams/invitations");
        return kernel.inviteTeamMember(identity, teamId, input);
      },
      async rotateTeamInvitation(teamId, invitationId, body, identity) {
        const input = parse(
          rotateTeamInvitationSchema,
          body,
          "admin/teams/invitations/rotation",
        );
        return kernel.rotateTeamInvitation(identity, teamId, invitationId, input.kind);
      },
      async revokeTeamInvitation(teamId, invitationId, identity) {
        return kernel.revokeTeamInvitation(identity, teamId, invitationId);
      },
      async changeTeamMemberRole(teamId, userId, body, identity) {
        const input = parse(changeTeamMemberRoleSchema, body, "admin/teams/members/role");
        return kernel.changeTeamMemberRole(identity, teamId, userId, input.role);
      },
      async removeTeamMember(teamId, userId, identity) {
        return kernel.removeTeamMember(identity, teamId, userId);
      },

      // GET /v1/admin/memory-map?namespace= — S5. The namespace is asserted
      // inside the caller's subtree by the kernel handler (a team admin can
      // never map a sibling).
      async memoryMap(namespace, identity) {
        return kernel.memoryMap(identity, namespace);
      },

      // GET /v1/admin/audit?...filters — S8. The filters are coerced/validated
      // to AuditSearchFilters here; visibility is the caller's subtree (kernel).
      async auditSearch(rawFilters, identity) {
        return kernel.auditSearch(identity, coerceAuditFilters(rawFilters));
      },

      async auditSummary(rawFilters, identity) {
        return kernel.auditSummary(identity, coerceAuditFilters(rawFilters));
      },

      // GET /v1/admin/audit/export.csv?...same filters — S8's download. Same coercion
      // and same fence as the table above; the kernel walks past the screen cap
      // and audits the egress itself (D4/D28).
      async auditExportCsv(rawFilters, identity) {
        return kernel.auditExportCsv(identity, coerceAuditFilters(rawFilters));
      },

      async sourcesView(identity) {
        return kernel.sourcesView(identity);
      },

      // GET /v1/admin/sources/:id/lineage — what one connection wrote into
      // memory (S6 drawer). An id the caller cannot see is a caller problem,
      // not a 500, and reads exactly like an id that does not exist: the
      // response never distinguishes "someone else's source" from "no source".
      async sourceLineage(id, identity) {
        try {
          return await kernel.sourceLineage(identity, id);
        } catch (err) {
          if (err instanceof Error && /^no source with id/.test(err.message)) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      async listKnowledgeBases(query, identity) {
        return kernel.listKnowledgeBases(
          parse(knowledgeBaseListSchema, query, "admin/knowledge-bases query"),
          identity,
        );
      },

      async createKnowledgeBase(body, identity) {
        return kernel.createKnowledgeBase(
          parse(knowledgeBaseCreateSchema, body, "admin/knowledge-bases"),
          identity,
        );
      },

      async listKnowledgeBaseSources(id, query, identity) {
        return kernel.listKnowledgeBaseSources(
          id,
          parse(knowledgeBaseSourceListSchema, query, "admin/knowledge-bases/sources query"),
          identity,
        );
      },

      async attachKnowledgeBaseSource(id, body, identity) {
        return kernel.attachKnowledgeBaseSource(
          id,
          parse(knowledgeBaseSourceCreateSchema, body, "admin/knowledge-bases/sources"),
          identity,
        );
      },

      async pauseKnowledgeBase(id, body, identity) {
        parse(emptyObjectSchema, body, "admin/knowledge-bases/pause");
        return kernel.pauseKnowledgeBase(id, identity);
      },

      async resumeKnowledgeBase(id, body, identity) {
        parse(emptyObjectSchema, body, "admin/knowledge-bases/resume");
        return kernel.resumeKnowledgeBase(id, identity);
      },

      async archiveKnowledgeBase(id, body, identity) {
        parse(emptyObjectSchema, body, "admin/knowledge-bases/archive");
        return kernel.archiveKnowledgeBase(id, identity);
      },

      async listCompanyFiles(query, identity) {
        return kernel.listCompanyFiles(
          parse(companyFileListSchema, query, "admin/company-files query"),
          identity,
        );
      },

      async listEntityRelationships(query, identity) {
        return kernel.listEntityRelationships(
          parse(entityRelationshipListSchema, query, "admin/entity-relationships query"),
          identity,
        );
      },

      async uploadCompanyFile(body, identity) {
        return kernel.submitCompanyFileUpload(
          parse(companyFileUploadSchema, body, "admin/company-files"),
          identity,
        );
      },

      async companyFileUploadStatus(id, identity) {
        return kernel.companyFileUploadStatus(id, identity);
      },

      async archiveCompanyFile(id, body, identity) {
        parse(emptyObjectSchema, body, "admin/company-files/archive");
        return kernel.archiveCompanyFile(id, identity);
      },

      async updateSourceMetadata(id, body, identity) {
        return kernel.updateSourceMetadata(
          id,
          parse(sourceMetadataSchema, body, "admin/sources/metadata"),
          identity,
        );
      },

      async connectors(_identity) {
        return {
          total: 1,
          categories: { knowledge: 1 },
          connectors: [{
            id: "obsidian_vault",
            connectionKey: "obsidian_vault",
            name: "Obsidian",
            category: "knowledge",
            description: "Pair a local Obsidian vault with Halofy.",
            auth: { type: "pairing", fields: [], managedBy: "local" },
            connect: { kind: "local-pairing" },
            managedAuth: { provider: "local", configured: true },
            capabilities: { incremental: true, liveQuery: false, sourceAcl: false, webhook: true, oauth: false },
            delivery: "webhook",
            readiness: "executable",
          }],
        };
      },

      async pairObsidian(body, identity) {
        const input = parse(obsidianPairSchema, body, "admin/connectors/obsidian/pair");
        try {
          return await kernel.pairObsidianSource(input, identity);
        } catch (err) {
          if (err instanceof Error &&
              /obsidian|active team|assigned to a team|own team|source-wide visibility/i.test(err.message)) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      // POST /v1/admin/sources — connect a source (S6). Owner/admin only.
      // Every new backend belongs to one server-resolved active team. Team
      // admins are pinned to their exact team; organization/root admins must
      // supply targetTeamId (D9).
      async connectSource(body, identity) {
        const input = parse(connectSourceSchema, body, "admin/sources");
        if (!isSourceKind(input.kind)) {
          throw new BadRequestError(`invalid source kind '${input.kind}'`);
        }
        if (input.kind === "obsidian_vault") {
          throw new BadRequestError(
            `connector '${input.kind}' must be created through its local pairing flow`,
          );
        }
        try {
          return await kernel.connectSource(
            input.kind,
            input.config ?? {},
            identity,
            input.idempotencyKey,
            input.targetTeamId ?? null,
          );
        } catch (err) {
          // "no connector for kind" is a caller problem, not a 500.
          if (err instanceof Error &&
              /no connector for kind|active team|assigned to a team|own team|administrative subtree|credentialId|credential field|source field|managed connection field|is required|public HTTPS|provider allowlist/.test(err.message)) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      // POST /v1/admin/sources/:id/sync — durably queue a registered source
      // sync. The worker can use the connector's full execution budget without
      // holding the browser/Vercel request open.
      async syncSource(id, identity) {
        try {
          return await kernel.requestSourceSync(id, identity);
        } catch (err) {
          if (err instanceof Error && /^no source with id/.test(err.message)) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },

      async importCsvSource(id, body, identity) {
        const input = parse(csvSourceImportSchema, body, "admin/sources/import-csv");
        try {
          return await kernel.importCsvSource(id, input, identity);
        } catch (error) {
          if (error instanceof Error &&
              (/^CSV /.test(error.message) || /CSV \/ Sheet Import source/.test(error.message))) {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },

      testSource: (id, identity) => kernel.testSource(id, identity),
      pauseSource: (id, identity) => kernel.pauseSource(id, identity),
      resumeSource: (id, identity) => kernel.resumeSource(id, identity),
      async scheduleSource(id, body, identity) {
        const input = parse(sourceScheduleSchema, body, "admin/sources/schedule");
        return kernel.scheduleSource(id, input.intervalSeconds, identity);
      },

      // GET /v1/admin/fragmentation?namespace= — the LATEST persisted report for
      // the namespace (read-only; the analysis is not re-run). Auditor-visible,
      // so it uses the read-scope check (admits auditor in its subtree), NOT
      // assertAdminScope (owner/admin-only, reserved for the mutating run route).
      async getFragmentation(namespace, identity) {
        assertReadScope(identity, namespace);
        return latestFragmentation(kernel, namespace);
      },

      // POST /v1/admin/fragmentation — RUN the report (a write: it persists a
      // fragmentation_reports row). Owner/admin only (route denied auditor).
      async runFragmentation(body, identity) {
        const input = parse(runFragmentationSchema, body, "admin/fragmentation");
        const ns = input.namespace ?? identity.namespace;
        assertAdminScope(identity, ns);
        return kernel.runFragmentation(ns, identity);
      },

      // POST /v1/admin/setup — the J1 zero-engineer onboarding orchestration:
      // register the tenant (owner-only in the registry), optionally connect a
      // first source, pick the retriever via policy, mint an agent badge, and
      // return the paste-ready MCP snippet. Reuses the M3/M4 kernel methods; it
      // reimplements none of them.
      async setup(body, identity) {
        const input = parse(setupSchema, body, "admin/setup");
        return runSetup(kernel, options, input as SetupInput, identity);
      },

      async setupCapabilities(identity) {
        if (!isRootOwner(identity)) throw new AuthzError("setup requires a root owner");
        return { retrievers: kernel.setupCapabilities() };
      },

      async setupStatus(operationId, identity) {
        const result = await kernel.setupStatus(operationId, identity);
        if (result === null) throw new BadRequestError("unknown setup operation");
        return result;
      },

      async setupRetry(operationId, identity) {
        const result = await kernel.resumeVerifiedSetup(operationId, identity);
        if (result === null) throw new BadRequestError("unknown setup operation");
        return result;
      },

      async listProposals(identity) {
        return kernel.listConsolidationProposals(identity);
      },

      async getProposal(proposalId, identity) {
        return kernel.getConsolidationProposal(identity, proposalId);
      },

      async proposalMetrics(namespace, identity) {
        if (!kernel.consolidation) return { approvals: 0, mergeWithoutEdit: 0, mergeWithoutEditRatio: 0 };
        return kernel.consolidation.metrics(identity, namespace);
      },

      async runConsolidation(body, identity) {
        if (!kernel.consolidation) {
          throw new BadRequestError("consolidation requires HALOMEM_COLD_KEK");
        }
        // Validate FIRST — a malformed request must never debit credits.
        const input = parse(consolidationRunSchema, body, "admin/consolidation/runs");
        await kernel.consumeQuota(
          identity,
          "consolidation",
          "automation_run",
          "manual-consolidation",
        );
        try {
          return await kernel.consolidation.runManual(identity, input);
        } catch (error) {
          if (
            error instanceof Error &&
            (/^evidence selection /.test(error.message) || error.message === "consolidation window is invalid")
          ) {
            throw new BadRequestError(error.message);
          }
          throw error;
        }
      },

      async editProposal(proposalId, body, identity) {
        if (!kernel.consolidation) throw new BadRequestError("consolidation requires HALOMEM_COLD_KEK");
        return kernel.consolidation.edit(
          identity, proposalId, parse(proposalEditSchema, body, "admin/proposals/edit"),
        );
      },

      async approveProposal(proposalId, body, identity) {
        if (!kernel.consolidation) throw new BadRequestError("consolidation requires HALOMEM_COLD_KEK");
        return kernel.consolidation.approve(
          identity, proposalId, parse(proposalApproveSchema, body, "admin/proposals/approve"),
        );
      },

      async rejectProposal(proposalId, body, identity) {
        if (!kernel.consolidation) throw new BadRequestError("consolidation requires HALOMEM_COLD_KEK");
        return kernel.consolidation.reject(
          identity, proposalId, parse(proposalRejectSchema, body, "admin/proposals/reject"),
        );
      },

      async listDisputes(identity) {
        return kernel.listDisputes(identity);
      },

      async listConflicts(identity) {
        const result = await kernel.listConflicts(identity);
        return { ...result, findings: result.scanFindings };
      },

      async requestConflictScan(body, identity) {
        const input = parse(conflictScanSchema, body, "admin/conflict-scans");
        const run = await kernel.requestConflictScan(identity, input);
        void kernel.runConflictScanJobsOnce();
        return run;
      },

      latestConflictScan(identity) {
        return kernel.latestConflictScan(identity);
      },

      async getConflictScan(scanId, identity) {
        const result = await kernel.getConflictScan(scanId, identity);
        if (!result) throw new BadRequestError("unknown conflict scan");
        return result;
      },

      async reviewConflictFinding(findingId, action, body, identity) {
        const input = parse(
          conflictFindingReviewSchema,
          body,
          "admin/conflict-findings/review",
        );
        return kernel.reviewConflictFinding(
          identity,
          findingId,
          action,
          input.expectedRowVersion,
        );
      },

      async resolveConflictFinding(findingId, body, identity) {
        const input = parse(
          conflictFindingResolveSchema,
          body,
          "admin/conflict-findings/resolve",
        );
        return kernel.resolveConflictFinding(
          identity,
          findingId,
          input.keep,
          input.expectedRowVersion,
        );
      },

      async overturnConflictFinding(findingId, body, identity) {
        const input = parse(
          conflictFindingOverturnSchema,
          body,
          "admin/conflict-findings/overturn",
        );
        return kernel.overturnConflictFinding(
          identity,
          findingId,
          input.expectedRowVersion,
        );
      },

      async resolveDispute(disputeId, body, identity) {
        return kernel.resolveDispute(
          identity, disputeId, parse(disputeResolveSchema, body, "admin/disputes/resolve"),
        );
      },

      // --- M9 parity console read models + admin surfaces -------------------

      // #8 (E43): composite banded readiness score (ACL-scoped aggregates).
      async readiness(identity) {
        return kernel.readiness(identity);
      },

      async assistantRecycleBin(identity) {
        return kernel.assistantRecycleBin(identity);
      },
      async recycleAssistantActor(actor, identity) {
        return kernel.recycleAssistantActor(actor, identity);
      },
      async restoreAssistantActor(actor, identity) {
        return kernel.restoreAssistantActor(actor, identity);
      },
      async purgeAssistantActor(actor, confirmation, identity) {
        return kernel.purgeAssistantActor(actor, confirmation, identity);
      },

      // #16 (E51): unified missing|wrong gap feed for S5.
      async gapFeed(identity) {
        return kernel.gapFeed(identity);
      },

      // #5 (E42): standing setup checklist for S1 + the sidebar badge.
      async setupChecklist(identity) {
        return kernel.setupChecklist(identity);
      },

      // The setup gate's server-side flag for /auth/me (CONTRACTS-SETUP-GATE).
      async onboardingState(identity) {
        return kernel.onboardingState(identity);
      },

      // S18 Settings → Organization. The read is open to every human in the
      // tenant (the name/mark of the org you work in is not privileged); the
      // write is owner/admin and audited inside the module.
      async organizationSettings(identity) {
        return kernel.organizationSettings(identity);
      },
      async updateOrganizationSettings(body, identity) {
        return kernel.updateOrganizationSettings(identity, body);
      },

      // #18 (E33): derived accuracy rollup; the service validates the window
      // (AnswerOutcomeValidationError → 400 via the server's name mapping).
      async accuracy(query, identity) {
        const window: { since?: string; until?: string } = {};
        if (typeof query.since === "string" && query.since !== "") window.since = query.since;
        if (typeof query.until === "string" && query.until !== "") window.until = query.until;
        return kernel.accuracyRollup(identity, window);
      },

      // #19: automation catalog + org rows / configure (owner-admin gated and
      // audited inside the store; validation errors map to 400 here).
      async listAutomations(identity) {
        return kernel.listAutomations(identity);
      },
      async configureAutomation(body, identity) {
        const input = parse(automationConfigureSchema, body, "admin/automations");
        try {
          return await kernel.configureAutomation(identity, input);
        } catch (err) {
          if (err instanceof RangeError) throw new BadRequestError(err.message);
          if (
            err instanceof Error &&
            err.name === "Error" &&
            /unknown automation template|must be|is required/.test(err.message)
          ) {
            throw new BadRequestError(err.message);
          }
          throw err;
        }
      },
      knowledgeSyncStatus(identity) {
        return kernel.knowledgeSyncStatus(identity);
      },
      async queueKnowledgeSync(body, identity) {
        const target = parse(knowledgeSyncSchema, body, "admin/knowledge-sync");
        return kernel.queueKnowledgeSync(identity, target);
      },

      // #11b (D29/E23–E24): OAuth client registry. The plaintext secret is
      // returned exactly once at creation; only sha256 is ever stored.
      async listOAuthClients(identity) {
        return kernel.oauthClients.listWithStats(identity);
      },
      async createOAuthClient(body, identity) {
        return kernel.oauthClients.create(
          parse(oauthClientCreateSchema, body, "admin/oauth/clients"),
          identity,
        );
      },
      async approveOAuthClient(id, identity) {
        return kernel.oauthClients.approve(id, identity);
      },
      async revokeOAuthClient(id, body, identity) {
        const input = parse(oauthClientRevokeSchema, body, "admin/oauth/clients/revoke");
        return kernel.oauthClients.revoke(id, input.reason ?? "", identity);
      },

      // #9 (E19–E22): company skill library management.
      async listSkills(identity) {
        // Object form carries the sweep timestamp for the S16 list header;
        // the console also tolerates the legacy bare-array form.
        const [skills, lastSweptAt] = await Promise.all([
          kernel.listSkills(identity),
          kernel.skillVetting.lastSweepAt(),
        ]);
        return { skills, lastSweptAt };
      },
      async registerSkill(body, identity) {
        const { teamId, ...input } = parse(adminSkillRegisterSchema, body, "admin/skills");
        return teamId
          ? kernel.registerSkillForTeam(identity, teamId, input)
          : kernel.registerSkill(identity, input);
      },

      async updateSkill(id, body, identity) {
        return kernel.updateSkill(
          identity,
          id,
          parse(skillUpdateSchema, body, "admin/skills/update"),
        );
      },
      async updateSkillLabels(id, body, identity) {
        return kernel.updateSkillLabels(
          identity,
          id,
          parse(skillLabelsUpdateSchema, body, "admin/skills/labels"),
        );
      },
      async getSkill(id, identity) {
        // Composite detail for the S16 detail card: the row itself carries
        // the ACL check; runs/history/agents/events hang off it.
        const skill = await kernel.getSkill(identity, id);
        const [vettingRuns, history, agents, events, labelHistory] = await Promise.all([
          kernel.skillVetting.listRuns(identity, id),
          kernel.skills.history(identity, id),
          kernel.skillUsage.perAgent(identity, id),
          kernel.skillUsage.recentEvents(identity, id),
          kernel.skillLabelHistory(identity, id),
        ]);
        return { skill, vettingRuns, history, agents, events, labelHistory };
      },
      async vetSkill(id, identity) {
        return kernel.vetSkill(identity, id);
      },
      async overrideSkill(id, body, identity) {
        const input = parse(skillOverrideSchema, body, "admin/skills/override");
        return kernel.overrideSkill(identity, id, input.reason);
      },
      async retireSkill(id, identity) {
        return kernel.retireSkill(identity, id);
      },
      // S16: approval workflow over pending member submissions.
      async approveSkill(id, identity) {
        return kernel.approveSkill(identity, id);
      },
      async rejectSkill(id, body, identity) {
        const input = parse(skillRejectSchema, body, "admin/skills/reject");
        return kernel.rejectSkill(identity, id, input.reason);
      },
    },

    metrics: {
      snapshot: () => ({
        kernel: kernel.metrics.snapshot(),
        http: httpTelemetry.snapshot(),
      }),
    },
    authThrottle: {
      consume: (bucket) => authRateLimits.consume(bucket, 10, 15 * 60 * 1000),
      reset: (bucket) => authRateLimits.reset(bucket),
    },
    webhookThrottle: {
      consume: (bucket) => authRateLimits.consume(bucket, 120, 60 * 1000),
    },
    trustedProxyHops,
    telemetry: httpTelemetry,
    scim: scim.length > 0 ? {
      resolve: (token) => {
        const candidate = createHash("sha256").update(token).digest();
        const matched = scim.find((entry) => timingSafeEqual(candidate, entry.tokenHash));
        if (!matched) return null;
        const service = matched.service;
        return {
          provisionUser: (body) => service.provisionUser(body),
          provisionGroup: (body) => service.provisionGroup(body),
          getUser: (id) => service.getUser(id),
          listUsers: (filter) => service.listUsers(filter),
          replaceUser: (id, body) => service.replaceUser(id, body),
          patchUser: (id, body) => service.patchUser(id, body),
          deleteUser: (id) => service.deleteUser(id),
          getGroup: (id) => service.getGroup(id),
          listGroups: (filter) => service.listGroups(filter),
          replaceGroup: (id, body) => service.replaceGroup(id, body),
          patchGroup: (id, body) => service.patchGroup(id, body),
          deleteGroup: (id) => service.deleteGroup(id),
        };
      },
    } : undefined,
    audit: kernel.audit,

    buildMcpServer: (identity, serverContext, publicBaseUrl) =>
      buildMcpServer(kernel, identity, "mcp-http", serverContext, publicBaseUrl),
  };
}

// ---------------------------------------------------------------------------
// C0 communication channels — transport adapter
// ---------------------------------------------------------------------------

/** Thrown when a channel connection is not visible to the caller (→ 404). */
export class ChannelConnectionNotFoundError extends Error {
  constructor() {
    super("unknown connection");
    this.name = "ChannelConnectionNotFoundError";
  }
}

const channelCreateSchema = z.object({
  kind: z.enum([
    "telegram", "slack", "gmail", "google_chat",
    "whatsapp_cloud", "instagram", "messenger", "x", "sms",
    "sendgrid_email", "outlook", "line", "microsoft_teams",
    "website_widget", "custom_api", "discord",
  ]),
  displayName: z.string().min(1).max(160).optional(),
  displayMetadata: z.record(z.string().max(64), z.string().max(400)).optional(),
  /** Optional for click-to-connect providers: OAuth binds the real key later. */
  providerInstallationKey: z.string().min(3).max(512).optional(),
}).strict();

const channelCredentialsSchema = z.object({
  secrets: z.record(z.string().min(1).max(64), z.string().min(1).max(4096)),
  expectedCredentialVersion: z.number().int().min(0).optional(),
}).strict();

const channelAssignSchema = z.object({
  keyId: z.string().min(1).max(64),
  inboundAllowed: z.boolean(),
  outboundAllowed: z.boolean(),
  memoryAllowed: z.boolean().optional(),
  expiresAt: z.string().datetime().nullish(),
  expectedRowVersion: z.number().int().positive().optional(),
  expectedAuthorityEpoch: z.number().int().min(0).optional(),
}).strict();

const channelTransitionSchema = z.object({
  expectedRowVersion: z.number().int().positive().optional(),
  expectedAuthorityEpoch: z.number().int().min(0).optional(),
}).strict();

const channelTelegramSetupSchema = channelTransitionSchema.extend({
  // Telegram tokens are write-only. Only the public numeric prefix is used
  // for the installation binding; the whole value goes directly to sealed
  // credential custody and is never returned or logged.
  botToken: z.string().trim().regex(/^\d{1,20}:[A-Za-z0-9_-]{20,256}$/),
}).strict();

type ChannelConnectionValue = import("../types.js").ChannelConnection;
type AgentChannelGrantValue = import("../types.js").AgentChannelGrant;

/**
 * Redacted read model: no route-key material, credential ciphertext, or raw
 * provider installation identifier. Installation ids are normally public,
 * but callers can accidentally paste credentials into the field; reflecting
 * that value would turn a setup mistake into a secret disclosure.
 */
export function projectChannelConnection(
  connection: ChannelConnectionValue,
  grant: AgentChannelGrantValue | null,
  managedDeliveryConfirmed = false,
): Record<string, unknown> {
  return {
    id: connection.id,
    kind: connection.kind,
    namespace: connection.namespace,
    displayName: connection.displayName,
    displayMetadata: connection.displayMetadata,
    lifecycleState: connection.lifecycleState,
    authorityState: connection.authorityState,
    outboundAuthority: connection.outboundAuthority,
    authorityEpoch: connection.authorityEpoch,
    credentialVersion: connection.credentialVersion,
    installationPending: connection.providerInstallationKey.startsWith("pending:oauth:"),
    verificationState: connection.verificationState,
    healthState: connection.healthState,
    healthDetail: connection.healthDetail,
    lastSuccessAt: connection.lastSuccessAt,
    lastFailureAt: connection.lastFailureAt,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
    rowVersion: connection.rowVersion,
    ...(connection.kind === "google_chat" &&
      connection.displayMetadata.installationMode === "managed"
      ? { managedDeliveryConfirmed }
      : {}),
    agent: grant === null ? null : {
      keyId: grant.keyId,
      revision: grant.revision,
      inboundAllowed: grant.inboundAllowed,
      outboundAllowed: grant.outboundAllowed,
      memoryAllowed: grant.memoryAllowed,
      systemTest: grant.systemTest,
      expiresAt: grant.expiresAt,
    },
  };
}
