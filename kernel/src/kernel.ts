/**
 * HaloMem Kernel facade (M1 integrator wiring).
 *
 * Boot wires every module together (D5: one database; D8: TS kernel):
 *   - numbered migrations (module C) — api_keys + cost_ledger included
 *   - AuthService (module A) — server-side Identity resolution (D9)
 *   - PolicyStore (module D) — DB-backed policies replace the in-memory map;
 *     kernel/config defaults stay the base of the merge chain
 *   - TokenBucket + BudgetGuard (module D) — per-key rate limits, brownout
 *   - MetricsRegistry (module F) — every syscall is timed
 *   - ResilientLlm/ResilientEmbedder (module E) — per-namespace wrappers with
 *     cost_ledger accounting and circuit breakers
 *   - WriteQueue (module E) — mem_write {async:true} lane
 *   - Db.transaction-backed supersedence (module C) — insert + closeValidity
 *     are atomic (exit criterion 3)
 *
 * Every syscall method takes a resolved Identity — no request path reaches
 * MemoryIndex without one (exit criterion 1).
 */

import { ulid } from "ulid";
import { access, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { assertSupportedDeployment, loadConfig, type KernelConfig } from "./config.js";
import { trimTrailingRepeatedCharacter } from "./strings.js";
import type {
  AccessSubject,
  ChannelAuthorityContext,
  ColdStoreDriver,
  Concept,
  CopilotSourceSearchResult,
  CopilotSourceSummary,
  ContextBlock,
  Embedder,
  GovernedSourceReadable,
  HumanRole,
  Identity,
  LiveDoc,
  LiveResult,
  LlmClient,
  MemStats,
  Namespace,
  PointerMatch,
  ScoredRef,
  SyscallContext,
  WorkingSet,
  WriteRequest,
  WriteResult,
  SetupInput,
  SetupResult,
  MountedRetrieverCapability,
  MemoryPin,
  MemoryObject,
  MemoryReadScope,
  PinTarget,
  PolicyAdoptionCandidateListResult,
  PolicyComplianceReport,
  PolicyDirectiveDocument,
  PolicyDirectiveSet,
  PolicyDocumentAdoptInput,
  PolicyDocumentEnforcement,
  PolicyDocumentListQuery,
  PolicyDocumentListResult,
  PolicyDocumentScopeListResult,
  PolicyDocumentSummary,
  PolicyDocumentUploadInput,
  CompanyFileListQuery,
  CompanyFileListResult,
  CompanyFileSummary,
  CompanyFileUploadAccepted,
  CompanyFileUploadInput,
  CompanyFileUploadStage,
  CompanyFileUploadStatusResult,
  DurableJob,
  KnowledgeBaseCreateInput,
  KnowledgeBaseListQuery,
  KnowledgeBaseListResult,
  KnowledgeBaseSummary,
  KnowledgeBaseSourceMetadata,
  KnowledgeBaseSourceCreateInput,
  KnowledgeBaseSourceListResult,
  KnowledgeBaseSourceSummary,
  EntityRelationshipListQuery,
  EntityRelationshipListResult,
  ConflictScanRequest,
  ConflictScanRunView,
  ConflictAutoDecisionView,
  ConflictLedgerView,
  ConflictScanFindingView,
  AgentSessionSummaryView,
  KnowledgeSyncTarget,
  KnowledgeSyncQueueResult,
  KnowledgeSyncRunRecord,
  KnowledgeSyncRunStatus,
  KnowledgeSyncStatusResult,
  TeamMemoryAccessMode,
} from "./types.js";
import { estimateTokens } from "./types.js";

import { createDb, escapeLikePattern, type Db } from "./db/client.js";
import { migrate } from "./db/migrate.js";
import { MemoryIndex, namespaceAncestors, readScopeAllows } from "./index/index.js";
import { AuditLog, TransactionAuditLog } from "./audit/index.js";
import { ColdStore } from "./cold/index.js";
import {
  createEmbedder,
  embeddingRetryAfterMs,
  isRetryableEmbeddingError,
} from "./embed/index.js";
import { runEmbeddingBackfillOnce, type BackfillResult } from "./embed/backfill.js";
import {
  MemoryTitleJobs,
  type MemoryTitleExecutor,
  type MemoryTitleRunResult,
} from "./memory-titles/index.js";
import { createLlm, parseLooseJson } from "./llm/index.js";
import { ContextAllocator } from "./allocator/index.js";
import { FaultHandler } from "./fault/index.js";
import { WritePath, type WritePathHooks } from "./write/index.js";
import { makeEntitiesReader } from "./write/entities.js";
import {
  BaselineDriver,
  DriverRegistry,
  buildScopedView,
  type ViewEntitiesLike,
} from "./driver/index.js";
import { GraphDriver } from "./driver/graph.js";
import { Mem0Driver } from "./driver/mem0.js";
import {
  runScorecard,
  renderScorecardMarkdown,
  type Scorecard,
  type ScorecardOptions,
} from "./referee/index.js";
import type { AgentAccessLevel, ScopedView } from "./types.js";
import {
  AuthService,
  AuthzError,
  isRootOwner,
  isSelfOrDescendant,
} from "./auth/index.js";
import { assertAgentKeyScope } from "./auth/agent-scope.js";
import {
  BudgetGuard,
  DEFAULT_RATE_LIMIT_PER_MIN,
  loadPolicyDirectives,
  normalizePolicyDocumentUpload,
  POLICY_DOCUMENT_LEASE_MS,
  PolicyComplianceStore,
  PolicyDocumentConflictError,
  PolicyDocumentLeaseExpiredError,
  PolicyDocumentQuotaError,
  PolicyDocumentStore,
  PolicyDocumentValidationError,
  PolicyStore,
  TokenBucket,
  type PolicyConfigX,
} from "./policy/index.js";
import {
  ResilientEmbedder,
  ResilientLlm,
  runWithCostSource,
  usageContextStorage,
  type CostDetail,
  type CostLedger,
  type UsageContext,
  type WriteQueueStatus,
} from "./resilience/index.js";
import { DurableWriteQueue } from "./durable/write-queue.js";
import { DurableJobStore } from "./durable/jobs.js";
import { DurableRateLimitStore } from "./durable/rate-limit.js";
import { MetricsRegistry, createLogger, type Logger } from "./metrics/index.js";

import {
  memAssemble,
  memFault,
  memForget,
  memRead,
  memSearch,
  memStats,
  memWrite,
  performWrite,
  gate as syscallGate,
  planViaDriver,
  RateLimitError,
  sourceAccessSubject,
  type MemAssembleArgs,
  type MemFaultArgs,
  type MemFaultResult,
  type MemForgetArgs,
  type MemReadArgs,
  type MemReadResult,
  type MemSearchArgs,
  type MemStatsArgs,
  type MemWriteArgs,
  type MemWriteResult,
  type NamespaceRuntime,
  type SyscallDeps,
} from "./syscalls/index.js";
import {
  recordUsageStandalone,
  recordUsageTx,
  resolveTraceId,
  type UsageRecorderDeps,
} from "./usage/index.js";
import { redactForOutbound } from "./skills/redact.js";

import { assertSecurePostgresDsn } from "./security/postgres.js";
import {
  AgentConnectionGrantStore,
  InvalidAgentConnectionGrantError,
} from "./gateway/store.js";
import { AgentOversightStore } from "./gateway/oversight.js";
import { authorizeAgentRequest } from "./gateway/policy.js";
import {
  MAX_GATEWAY_FIELDS,
  MAX_GATEWAY_QUERY_TERM_LENGTH,
  MAX_GATEWAY_QUERY_TERMS,
  MAX_GATEWAY_REQUEST_DURATION_SECONDS,
  MAX_GATEWAY_REQUEST_USES,
} from "./gateway/contracts.js";
import type {
  AgentAccessDescription,
  AgentConnectionGrant,
  AgentAccessAlert,
  AgentAccessApprovalInput,
  AgentAccessDecisionInput,
  AgentAccessEvent,
  AgentAccessRequest,
  AgentAuthorizationAllowed,
  AgentConnectionOversight,
  AgentSourceReadInput,
  AgentSourceReadResult,
  CreateAgentConnectionGrantInput,
  CreateAgentAccessRequestInput,
  ExactAgentAccessRequest,
  GatewayAdministrativeIdentity,
  GatewayOversightViewerIdentity,
  AgentGatewayOperation,
} from "./gateway/contracts.js";
import { DEFAULT_AGENT_CONNECTION_OVERSIGHT } from "./gateway/contracts.js";
import { FilesystemConnector } from "./ingest/connectors/filesystem.js";
import { bm25Rank } from "./retrieval/index.js";
import type { RetrievalSourceProjection } from "./retrieval/source-context.js";
import { TTL_ACTIVE_CLAUSE } from "./index/index.js";

// M4 tenancy + erasure — a tenant is a namespace root; the ancestor ACL already
// isolates sibling roots. TenantRegistry names them + carries caps; the tenant
// gate + effective caps are pure math wired into the syscall gate/brownout. The
// erasure engine mints signed DeletionCertificates against ONE boot-loaded key.
import { TenantRegistry, tenantRootOf } from "./tenancy/index.js";
import {
  TenantSuspendedError,
  effectiveBudgetUsd,
  effectiveRateLimit,
  tenantGate,
} from "./policy/tenant.js";
import {
  loadSigningKey,
  hardPurgeAssistantActor,
  listAssistantRecycleBin,
  recycleAssistantActor,
  restoreAssistantActor,
  verifyCertificate,
  type SigningKey,
} from "./erasure/index.js";
import type {
  DeletionCertificate,
  ForgetResult,
  Tenant,
} from "./types.js";

// M3 ingestion — D10: connectors/importers reach memory ONLY through the
// IngestSink; the kernel builds the sink over performWrite and provides the
// DB-backed SourceState / FragmentationReader / source registry.
import type {
  Importer,
  IngestRecord,
  IngestResult,
  SourceKind,
  SyncResult,
  FragmentationReport,
} from "./types.js";
import { makeIngestSink } from "./ingest/sink.js";
import {
  assertDestinationAllowed,
  classifyData,
  type IngestDestinationPolicy,
} from "./dlp/index.js";
import { runImport } from "./ingest/runner.js";
import { IMPORTERS } from "./ingest/importers/index.js";
import {
  makeBuiltinConnectorRegistry,
  validateConnectorConformance,
  type ConnectorRegistry,
} from "./ingest/connectors/index.js";
import { runFragmentation } from "./ingest/fragmentation.js";
import { ConflictScanService } from "./conflict-scans/index.js";
import {
  ConflictAutopilot,
  type ConflictAutopilotRunResult,
} from "./conflict-autopilot/index.js";
import { EntityTagger, type EntityTagRunResult } from "./entity-tagger/index.js";
import { LlmConflictClassifier } from "./conflict-scans/classifier.js";
import { AgentSessionSummaryService } from "./agent-sessions/index.js";
import {
  DbFragmentationReader,
  DbSourceState,
  SourceRegistry,
  type SourceRow,
} from "./ingest/kernel-store.js";
import { SourceConfigCipher, redactSourceError } from "./ingest/source-config.js";
import {
  WebhookAuthorizationError,
  WebhookDeliveryError,
  WebhookValidationError,
  verifyWebhookEnvelope,
} from "./ingest/webhook.js";
import {
  ObsidianAuthorizationError,
  ObsidianDeliveryError,
  ObsidianValidationError,
  verifyObsidianIngress,
} from "./ingest/obsidian.js";
import { mapCsvToConnectorRecords, type CsvImportInput } from "./ingest/csv-import.js";

function isStagedSourceKind(kind: SourceKind): boolean {
  return kind === "obsidian_vault" || kind === "csv_sheet_import";
}

function obsidianCursorSequence(value: string | null): number {
  if (!value) return 0;
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return parsed.version === 1 && Number.isSafeInteger(parsed.sequence)
      ? Number(parsed.sequence)
      : -1;
  } catch {
    return -1;
  }
}

function emptyObsidianSyncResult(sourceId: string): SyncResult {
  return {
    sourceId,
    records: 0,
    stored: 0,
    deduplicated: 0,
    superseded: 0,
    rejected: 0,
    disputed: 0,
    errors: [],
    scanned: 0,
    changed: 0,
    unchanged: 0,
    removed: [],
  };
}

// M5 control room — human sign-in (Module A) + the management-API read models
// (Module B). Humans reuse the D9 Identity: a resolved session yields the SAME
// { keyId, namespace, actor, role } shape the syscalls require. The read models
// are subtree-scoped faces on existing controls, not a second system.
import {
  UserStore,
  SessionStore,
  BootstrapService,
  InvitationStore,
  login as sessionLogin,
  logout as sessionLogout,
  resolveSessionIdentity as sessionResolve,
  type AuthStores,
  type CreateUserInput,
  type BootstrapInput,
  type BootstrapResult,
  type CreateInvitationInput,
  type IssuedInvitation,
} from "./console/auth.js";
import { OrganizationSignupService } from "./console/signup.js";
import {
  overview as consoleOverview,
  people as consolePeople,
  teamDirectory as consoleTeamDirectory,
  memoryMap as consoleMemoryMap,
  auditSearch as consoleAuditSearch,
  auditSummary as consoleAuditSummary,
  auditExportCsv as consoleAuditExportCsv,
  type AuditCsvExport,
  sourcesView as consoleSourcesView,
  sourceLineageView as consoleSourceLineageView,
  type SourceLineage,
  getMemoryGraph,
  memoryGraphTopology,
  memoryGraphWhy,
  type MemoryGraphPage,
  type MemoryGraphOptions,
  type MemoryTopology,
  type KernelSlice,
  type Overview,
  type OverviewParams,
  type People,
  type TeamDirectory,
  type MemoryMap,
  type SourcesView,
  type ConsoleUser,
} from "./console/api.js";
// M10 — role-scoped memory graph: server-owned grants, the projection
// service binding, product-role translation, and the root View-as lifecycle.
import { AccessGrantStore } from "./iam/access-grants.js";
import {
  simulatedRoleProjection,
  tenantRootOfNamespace,
  userProjectionDeps,
} from "./iam/projection-binding.js";
import { projectionReadRoots, resolveProjection } from "./access-projection/index.js";
import { productRoleLabel, toProductRole } from "./iam/product-roles.js";
import {
  createPreviewSession,
  endPreviewSession,
  listPreviewTargets,
  PreviewNotFoundError,
  rejectPreviewMutation,
  resolvePreview as viewAsResolvePreview,
  type CreatePreviewInput,
  type ResolvedPreview,
  type ViewAsDeps,
} from "./console/view-as.js";
import {
  TeamBadRequestError,
  listTeams as consoleListTeams,
  resolveTeamNamespace as consoleResolveTeamNamespace,
  createTeam as consoleCreateTeam,
  addTeamMember as consoleAddTeamMember,
  inviteTeamMember as consoleInviteTeamMember,
  renameTeam as consoleRenameTeam,
  setTeamArchived as consoleSetTeamArchived,
  rotateTeamInvitation as consoleRotateTeamInvitation,
  revokeTeamInvitation as consoleRevokeTeamInvitation,
  personAccessImpact as consolePersonAccessImpact,
  changePersonAccessState as consoleChangePersonAccessState,
  changeTeamMemberRole as consoleChangeTeamMemberRole,
  changeTeamMemoryAccess as consoleChangeTeamMemoryAccess,
  removeTeamMember as consoleRemoveTeamMember,
  type CreateTeamInput,
  type InviteTeamMemberInput,
  type PersonAccessImpact,
  type Team,
} from "./console/teams.js";
import {
  readOrganizationSettings as consoleReadOrganizationSettings,
  updateOrganizationSettings as consoleUpdateOrganizationSettings,
  updateMemberDisplayName as consoleUpdateMemberDisplayName,
  updateMemberProfile as consoleUpdateMemberProfile,
  type MemberProfileUpdate,
  type MemberProfileView,
  type OrganizationSettingsUpdate,
  type OrganizationSettingsView,
} from "./console/settings.js";
import { TeamMemoryAccessPolicy } from "./team-memory-access/index.js";
import type { AuditSearchFilters, AuditSummary } from "./audit/index.js";
import type {
  AccessProjection,
  AuditEvent,
  AuditOp,
  PreviewSubject,
  Session,
  User,
} from "./types.js";
import { SetupService } from "./setup/index.js";
import { PinService, type PinResult, type UnpinResult } from "./pins/index.js";
import {
  AesGcmDraftCipher,
  ConsolidationService,
  type KnowledgeProposal,
} from "./consolidation/index.js";
import {
  DisputeService,
  type DisputeView,
  type ResolveDisputeInput,
  type ResolveDisputeResult,
} from "./disputes/index.js";
import { KernelConsolidationEngine } from "./consolidation/kernel-engine.js";
import { SharingService, type DirectShareResult } from "./sharing/index.js";
import { MovementEngine } from "./movement/index.js";
import { PolicyPager, type PagerMovement } from "./movement/pager.js";
import { ContentAddressedL1Cache, contentAddress } from "./cache/index.js";
import { LocalColdStoreDriver } from "./cold/driver.js";

// R6 (halomem-warmstore/v1) — governed external warm-memory mirrors. Postgres
// stays the sole authority (D5); mounted external stores (mem0/supermemory
// sidecars) are rebuildable caches fed ONLY by kernel post-commit hooks.
import {
  Mem0WarmStore,
  PostgresWarmStore,
  SupermemoryWarmStore,
  WarmStoreManager,
  WarmStoreRegistry,
} from "./warmstore/index.js";
import type { WarmStoreStatus } from "./types.js";
// --- M9 parity (Mintlify-gap milestone) wiring --------------------------------
import { setupChecklist, onboardingState, type OnboardingState, type SetupChecklist } from "./setup/checklist.js";
import { adoptNamespaces, type AdoptReport } from "./tenancy/adopt.js";
import { computeReadiness, type MemoryReadiness } from "./readiness/index.js";
import { buildGapFeed, type GapFeed } from "./console/rollups/gaps.js";
import {
  suggestedQuestions as consoleSuggestedQuestions,
  type SuggestedQuestionsResult,
} from "./console/suggested-questions.js";
import { ProductKeyService } from "./auth/key-types.js";
import { AgentBearerCipher } from "./auth/bearer-cipher.js";
import {
  memManifest,
  type MemManifestArgs,
  type ManifestResult,
} from "./discovery/manifest.js";
import {
  EXPORT_ROLES,
  memExport,
  type ExportOptions,
  type ExportResult,
} from "./export/index.js";
import {
  AnswerOutcomeService,
  parseAnswerOutcomeBody,
  type AccuracyRollup,
  type AccuracyWindow,
  type RecordAnswerOutcomeResult,
} from "./feedback/index.js";
import {
  OrgAutomationStore,
  listAutomationsEndpoint,
  configureAutomationEndpoint,
  type AutomationView,
  type OrgAutomation,
} from "./automation/store.js";
import { AutomationRunner, type AutomationRunSummary } from "./automation/runner.js";
import { assistantActorHash } from "./erasure/actor-hash.js";
import {
  QuotaLimitError,
  UNMETERED,
  type MeterPort,
  type QuotaConsumeItem,
  type QuotaFeature,
  type QuotaPort,
} from "./policy/quota.js";
import {
  servePublicDiscovery,
  type PublicDiscoveryFormat,
  type PublicDiscoveryResponse,
} from "./discovery/public.js";
import {
  SkillStore,
  type RegisterSkillInput,
  type RegisterSkillResult,
  type UpdateSkillInput,
  type UpdateSkillLabelsInput,
  type SkillLabelHistoryRecord,
  type SkillExport,
  type SkillInvokeDecision,
  type SkillRecord,
  type SkillRiskBand,
} from "./skills/store.js";
import { SkillVetting, type VetSkillResult, type VettingV2Mode, type SkillVettingLanes } from "./skills/vetting.js";
import { resolveVettingLanes } from "./skills/v2.js";
import { AzureOpenAiScanClient } from "./skills/llm-scan.js";
import { SkillUsageService, type SkillUsageSummary } from "./skills/usage.js";
import { seedDefaultSkills } from "./skills/defaults.js";
import { OAuthClientService } from "./oauth/clients.js";
import { OAuthTokenService, type OAuthTokenIdentity } from "./oauth/tokens.js";
import { OAuthCodeService } from "./oauth/codes.js";
import {
  handleAuthorizeDecision,
  handleAuthorizePage,
  type OAuthPageResponse,
} from "./oauth/authorize.js";
import {
  authorizationServerMetadata,
  enforceAllowedTools,
  handleIntrospectionRequest,
  handleRegistrationRequest,
  handleRevocationRequest,
  handleTokenRequest,
  protectedResourceMetadata,
  type OAuthHttpRequest,
  type OAuthHttpResponse,
  type OAuthServerDeps,
} from "./oauth/server.js";
import {
  KnowledgeBaseNotFoundError,
  KnowledgeBaseStore,
} from "./knowledge-bases/index.js";
import { KnowledgeBaseSourceStore } from "./knowledge-bases/sources.js";
import {
  COMPANY_FILE_LEASE_MS,
  CompanyFileConflictError,
  CompanyFileIdempotencyError,
  CompanyFileLeaseExpiredError,
  CompanyFileQuotaError,
  CompanyFileRateLimitError,
  CompanyFileStore,
  type CompanyFileCompensator,
  type CompanyFileUploadAttemptSummary,
} from "./knowledge-bases/company-files.js";
import { CompanyFileIngestJobStore } from "./knowledge-bases/company-file-jobs.js";
import {
  CompanyFileValidationError,
  parseCompanyFileInput,
  validateCompanyFileInput,
} from "./ingest/company-file.js";
import { RelationshipKernelAdapter } from "./relationships/index.js";

/** Default agent attribution for direct (in-process) kernel calls. */
const DEFAULT_AGENT_ID = "kernel";
/** Staleness window for the write-path guardrail monitor's digest cache. */
const POLICY_DIGEST_CACHE_MS = 30_000;
/** Bound on both monitor caches; a full cache is cleared, never grown. */
const POLICY_CACHE_MAX_ENTRIES = 10_000;

const SOURCE_LABEL_OVERRIDES: Readonly<Record<string, string>> = {
  csv_sheet_import: "CSV / Sheet",
  custom_api: "Custom API",
  doc_site: "Documentation site",
  file_upload: "Company files",
  filesystem: "Filesystem",
  github: "GitHub",
  mem0_import: "Mem0 import",
  pgvector_import: "pgvector import",
  policy_upload: "Policy files",
  postgres: "PostgreSQL",
  private_api_nango: "Private API",
  webhook_source: "Webhook",
  woocommerce: "WooCommerce",
};

function canonicalSourceKind(kind: string): string {
  return kind.endsWith("_direct") ? kind.slice(0, -7) : kind;
}

function copilotSourceLabel(kind: string): string {
  const canonical = canonicalSourceKind(kind).replaceAll("-", "_");
  return SOURCE_LABEL_OVERRIDES[canonical] ?? canonical
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]!.toUpperCase() + part.slice(1))
    .join(" ");
}

function sourceMentioned(query: string, source: CopilotSourceSummary): boolean {
  const normalized = query.toLowerCase().replaceAll(/[^a-z0-9]+/g, " ").trim();
  if (!normalized) return false;
  const terms = new Set([
    canonicalSourceKind(source.kind).replaceAll(/[^a-z0-9]+/g, " "),
    source.label.toLowerCase().replaceAll(/[^a-z0-9]+/g, " "),
  ]);
  return [...terms].some((term) =>
    term.length > 0 && (` ${normalized} `).includes(` ${term} `));
}

function liveSourceAccessAllows(access: LiveDoc["sourceAccess"], subject: AccessSubject): boolean {
  if (!access || (access.principals.length === 0 && access.groups.length === 0)) return true;
  const principals = new Set(subject.principals);
  const groups = new Set(subject.groups);
  return access.principals.some((value) => principals.has(value)) ||
    access.groups.some((value) => groups.has(value));
}

/**
 * L1 cache partition for a caller namespace. The cache rejects empty keys, so
 * the "" ORGANIZATION root gets a reserved sentinel partition ("@" cannot
 * appear in a real namespace); every other namespace partitions as itself.
 */
function l1CachePartition(namespace: Namespace): string {
  return namespace === "" ? "@organization-root" : namespace;
}

/** Agent attribution for ingestion writes (importers/connectors, D10). */
const INGEST_AGENT = "ingest";
const DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN = 120;
const POLICY_LEASE_HEARTBEAT_MS = Math.floor(POLICY_DOCUMENT_LEASE_MS / 3);
const COMPANY_FILE_LEASE_HEARTBEAT_MS = Math.floor(COMPANY_FILE_LEASE_MS / 3);
const COMPANY_FILE_WORKER_CONCURRENCY = 4;
const COMPANY_FILE_WORKER_BATCH_WINDOW_MS = 25;

interface IngestRelationshipImpact {
  readonly memoryIds: Set<string>;
  readonly supersededMemoryIds: Set<string>;
  readonly documents: Map<string, {
    sourceId: string;
    namespace: Namespace;
    documentKey: string;
    contentHash: string;
  }>;
}

function relationshipImpact(): IngestRelationshipImpact {
  return {
    memoryIds: new Set(),
    supersededMemoryIds: new Set(),
    documents: new Map(),
  };
}

const COMPANY_UPLOAD_FIELDS = new Set([
  "knowledgeBaseId",
  "fileName",
  "idempotencyKey",
  "content",
  "contentBase64",
  "title",
  "description",
  "purpose",
]);

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

function normalizeCompanyFileUpload(input: CompanyFileUploadInput): {
  knowledgeBaseId: string;
  fileName: string;
  idempotencyKey?: string;
  content?: string;
  contentBase64?: string;
  title?: string;
  description: string;
  purpose: string;
} {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new CompanyFileValidationError("Company file upload input is required");
  }
  for (const key of Object.keys(input)) {
    if (!COMPANY_UPLOAD_FIELDS.has(key)) {
      throw new CompanyFileValidationError(`unknown company file field '${key}'`);
    }
  }
  const knowledgeBaseId = boundedCompanyText(input.knowledgeBaseId, "knowledgeBaseId", 128);
  const fileName = boundedCompanyText(input.fileName, "fileName", 255, false);
  const hasText = typeof input.content === "string";
  const hasBinary = typeof input.contentBase64 === "string";
  if (hasText === hasBinary) {
    throw new CompanyFileValidationError(
      "exactly one of content or contentBase64 is required",
    );
  }
  let content: string | undefined;
  let contentBase64: string | undefined;
  if (hasText) {
    content = input.content as string;
  } else {
    contentBase64 = (input.contentBase64 as string).replace(/[\r\n]/g, "");
    if (
      contentBase64.length % 4 !== 0 ||
      !BASE64_PATTERN.test(contentBase64)
    ) {
      throw new CompanyFileValidationError("contentBase64 must be valid base64");
    }
  }
  const description = boundedCompanyText(input.description, "description", 1_024, true);
  const purpose = boundedCompanyText(input.purpose, "purpose", 256);
  const title = input.title === undefined
    ? undefined
    : boundedCompanyText(input.title, "title", 255);
  const idempotencyKey = input.idempotencyKey === undefined
    ? undefined
    : boundedCompanyText(input.idempotencyKey, "idempotencyKey", 128);
  if (idempotencyKey !== undefined && !/^[A-Za-z0-9_-]{8,128}$/.test(idempotencyKey)) {
    throw new CompanyFileValidationError(
      "idempotencyKey must contain only letters, numbers, '_' or '-'",
    );
  }
  return {
    knowledgeBaseId,
    fileName,
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
    ...(content === undefined ? {} : { content }),
    ...(contentBase64 === undefined ? {} : { contentBase64 }),
    ...(title === undefined ? {} : { title }),
    description,
    purpose,
  };
}

function boundedCompanyText(
  value: unknown,
  name: string,
  maxBytes: number,
  allowEmpty = false,
): string {
  if (typeof value !== "string") {
    throw new CompanyFileValidationError(`${name} must be text`);
  }
  const normalized = value.trim();
  if ((!allowEmpty && normalized.length === 0) || /\p{Cc}/u.test(normalized)) {
    throw new CompanyFileValidationError(`${name} is invalid`);
  }
  if (Buffer.byteLength(normalized, "utf8") > maxBytes) {
    throw new CompanyFileValidationError(`${name} exceeds its ${maxBytes}-byte limit`);
  }
  return normalized;
}

function companyFileMediaType(fileName: string): string {
  const extension = fileName.slice(fileName.lastIndexOf(".")).toLowerCase();
  const mediaTypes: Record<string, string> = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  };
  const mediaType = mediaTypes[extension];
  if (!mediaType) throw new CompanyFileValidationError("unsupported company file format");
  return mediaType;
}

/** Map reservation failures to distinct, user-meaningful attempt codes. */
function reservationFailureCode(error: unknown): string {
  if (error instanceof CompanyFileQuotaError) return "quota_exceeded";
  if (error instanceof CompanyFileLeaseExpiredError) return "lease_expired";
  if (
    error instanceof CompanyFileConflictError &&
    error.message.includes("already active")
  ) {
    return "duplicate_content";
  }
  return "reservation_failed";
}

/** Stable, content-free reason derived from the last real processing boundary. */
function companyFileProcessingFailureCode(
  stage: CompanyFileUploadStage,
  error?: unknown,
): string {
  if (error instanceof CompanyFileValidationError || stage === "parsing") {
    return "parse_failed";
  }
  if (stage === "extracting") return "extraction_failed";
  if (stage === "embedding") return "embedding_failed";
  if (stage === "finalizing") return "finalization_failed";
  return "processing_failed";
}

/** Preserve admission/reservation reasons before falling back to stage errors. */
function companyFileWorkerFailureCode(
  stage: CompanyFileUploadStage,
  error: unknown,
): string {
  if (
    error instanceof CompanyFileQuotaError ||
    error instanceof CompanyFileLeaseExpiredError ||
    error instanceof CompanyFileConflictError
  ) {
    return reservationFailureCode(error);
  }
  return companyFileProcessingFailureCode(stage, error);
}

class CompanyFileProcessingRetryError extends Error {
  constructor(
    readonly stage: CompanyFileUploadStage,
    readonly failureCode: string,
    /** Underlying per-record reasons (error messages, never file content). */
    readonly reasons: string[] = [],
  ) {
    super(`company file ${failureCode}`);
    this.name = "CompanyFileProcessingRetryError";
  }
}

/**
 * Operational evidence for a failed upload: the first few per-record error
 * reasons. Reasons are exception messages (provider/DB/policy text), never
 * file content — `runImport` records `err.message`, and the write path's
 * errors are content-free by construction (D4 audit-safety discipline).
 */
function companyFileFailureReasons(errors: IngestResult["errors"]): string[] {
  return errors.slice(0, 3).map((e) => e.reason.slice(0, 300));
}

/**
 * Failure code for a finished-but-empty/failed ingest result. A run whose
 * every record was refused by the DLP destination gates is a policy outcome,
 * not a pipeline defect — labelling it by stage ("embedding_failed") sent
 * operators chasing provider outages that never happened.
 */
function companyFileResultFailureCode(
  stage: CompanyFileUploadStage,
  errors: IngestResult["errors"],
): string {
  if (errors.length === 0) return "no_facts_landed";
  if (errors.every((e) => e.reason.startsWith("classification denied"))) {
    return "classification_denied";
  }
  return companyFileProcessingFailureCode(stage);
}

function readableCompanyFileTitle(fileName: string): string {
  const dot = fileName.lastIndexOf(".");
  const stem = dot > 0 ? fileName.slice(0, dot) : fileName;
  return stem.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
}

function decodeCanonicalKey(encoded: string): Buffer | null {
  if (!encoded) return null;
  try {
    const key = Buffer.from(encoded, "base64");
    return key.length === 32 && key.toString("base64") === encoded ? key : null;
  } catch {
    return null;
  }
}

/**
 * Kernel-side runtime record: the resilient wrappers are kept CONCRETE (not
 * the Embedder/LlmClient faces of syscalls' NamespaceRuntime). The D38 usage
 * context reaches them through AsyncLocalStorage (usageContextStorage), not a
 * mutable slot — see withUsageContext.
 */
interface KernelNamespaceRuntime extends NamespaceRuntime {
  embedder: ResilientEmbedder;
  llm: ResilientLlm;
}

/** Maximum duration of one write-path extraction/verifier provider attempt. */
export const WRITE_PATH_LLM_ATTEMPT_TIMEOUT_MS = 3 * 60_000;
/** Maximum duration of one write-path embedding provider attempt. */
export const WRITE_PATH_EMBED_ATTEMPT_TIMEOUT_MS = 3 * 60_000;

/** cost_ledger sink for the resilient wrappers (module E generates no ids/ts). */
class DbCostLedger implements CostLedger {
  constructor(private readonly db: Db) {}

  async append(
    namespace: Namespace,
    kind: "llm" | "embed",
    tokens: number,
    usd: number,
    ctx?: UsageContext,
    detail?: CostDetail,
  ): Promise<void> {
    if (ctx?.invocationId && ctx.actor && ctx.lifecycleGeneration !== undefined) {
      const active = await this.db.query(
        `SELECT 1 FROM assistant_actor_lifecycle
         WHERE namespace = $1 AND actor_hash = $2 AND generation = $3
           AND recycled_at IS NULL AND purged_at IS NULL`,
        [namespace, assistantActorHash(ctx.actor), ctx.lifecycleGeneration],
      );
      if (active.rows.length !== 1) return;
    }
    // D38: the cost row joins the caller — actor + trace_id when the call ran
    // inside a syscall's usage context; NULL for background lanes (ingest,
    // imports, the WriteQueue worker), which stays legal (E5).
    const inserted = await this.db.query(
      `INSERT INTO cost_ledger
         (id, namespace, kind, tokens, usd, ts, actor, trace_id, invocation_id,
          input_tokens, output_tokens, basis, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING
       RETURNING id`,
      [ulid(), namespace, kind, Math.round(tokens), usd, new Date().toISOString(),
       ctx?.actor ?? null, ctx?.traceId ?? null, ctx?.invocationId ?? null,
       detail?.inputTokens ?? null, detail?.outputTokens ?? null,
       detail?.basis ?? null, ctx?.source ?? null],
    );
    if (ctx?.traceId !== undefined && inserted.rows.length === 1) {
      try {
        // D37: roll the spend into the trace rollup. Best-effort: a missing
        // query_traces row/table must never break the LLM call (brownout).
        await this.db.query(
          `UPDATE query_traces SET usd = usd + $1 WHERE trace_id = $2 AND namespace = $3`,
          [usd, ctx.traceId, namespace],
        );
      } catch {
        // The cost_ledger row above is the durable record; the rollup degrades.
      }
    }
  }
}

/** Job shape carried through the WriteQueue (agentId travels with the request). */
interface QueuedWrite {
  req: WriteRequest;
  agentId: string;
}

interface DurableLivePayload {
  query: string;
  identity: Identity;
  agentId: string;
  /** Server-derived, ACL-fenced source routes selected at admission. */
  routes?: Array<{
    sourceId: string;
    sourceRef: string;
    documentKeys: string[];
    evidenceRefs?: string[];
    documentOwnershipRequired?: boolean;
  }>;
  channelAuthority?: ChannelAuthorityContext;
  affinity?: string;
}

const KNOWLEDGE_SYNC_HISTORY_DAYS = 30;
const KNOWLEDGE_SYNC_HISTORY_MS = KNOWLEDGE_SYNC_HISTORY_DAYS * 24 * 60 * 60 * 1_000;

function knowledgeSyncIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function knowledgeSyncLastRunStatus(value: unknown): KnowledgeSyncRunRecord["lastRunStatus"] {
  return value === "ok" || value === "degraded" || value === "failed" ? value : null;
}

function parseKnowledgeSyncRunDetail(detail: string | null): {
  processed: number | null;
  proposals: number | null;
  hasMore: boolean | null;
} {
  const processed = detail?.match(/\bevidence=(\d+)/)?.[1];
  const proposals = detail?.match(/\bproposals=(\d+)/)?.[1];
  const more = detail?.match(/\bmore=(true|false)\b/)?.[1];
  return {
    processed: processed === undefined ? null : Number(processed),
    proposals: proposals === undefined ? null : Number(proposals),
    hasMore: more === undefined ? null : more === "true",
  };
}

function knowledgeSyncTotals(
  runs: KnowledgeSyncRunRecord[],
): KnowledgeSyncStatusResult["totals"] {
  return runs.reduce<KnowledgeSyncStatusResult["totals"]>(
    (totals, run) => {
      totals[run.status] += 1;
      return totals;
    },
    { queued: 0, running: 0, completed: 0, failed: 0, scheduled: 0 },
  );
}

export class Kernel {
  readonly config: KernelConfig;
  readonly db: Db;
  readonly index: MemoryIndex;
  readonly audit: AuditLog;
  /** Server-owned, versioned per-team company-memory read policy. */
  readonly teamMemoryAccess: TeamMemoryAccessPolicy;
  private readonly cold: ColdStore;
  /** Raw (un-wrapped) clients; syscalls use per-namespace resilient wrappers. */
  readonly embedder: Embedder;
  readonly llm: LlmClient;
  readonly auth: AuthService;
  readonly policyStore: PolicyStore;
  /** Governed policy-file metadata; document content lives only in canonical memory. */
  readonly policyDocuments: PolicyDocumentStore;
  /** Guardrail delivery + compliance ledger for governed policy documents. */
  readonly policyCompliance: PolicyComplianceStore;
  /** Short-lived governing-digest cache for the write-path policy monitor. */
  private readonly policyDigestCache = new Map<
    Namespace,
    {
      value: { digest: string; required: boolean; documents: PolicyDirectiveDocument[] };
      expiresAt: number;
    }
  >();
  /** `<namespace> <agentId> <digest>` triples the monitor has already settled. */
  private readonly policyExposureSettled = new Set<string>();
  /** Governed knowledge collections; authority is resolved by this facade. */
  readonly knowledgeBases: KnowledgeBaseStore;
  /** Connector-backed folder and website pieces attached to collections. */
  readonly knowledgeBaseSources: KnowledgeBaseSourceStore;
  /** Governed company-file attempts and metadata; raw bodies are never stored here. */
  readonly companyFiles: CompanyFileStore;
  /** Authenticated ciphertext staging for restart-safe asynchronous uploads. */
  readonly companyFileJobs: CompanyFileIngestJobStore;
  /** Optional, evidence-backed L2 graph enrichment over governed facts. */
  readonly relationships: RelationshipKernelAdapter;
  readonly metrics: MetricsRegistry;
  readonly rateLimiter: DurableRateLimitStore;
  readonly budget: BudgetGuard;
  readonly costLedger: CostLedger;
  readonly writeQueue: DurableWriteQueue<QueuedWrite, WriteResult>;
  readonly logger: Logger;
  /** M2: mounted retriever cartridges (baseline, graph, mem0 iff configured). */
  readonly registry: DriverRegistry;
  /** M3: register/get/list ingestion sources over the `sources` table. */
  readonly sources: SourceRegistry;
  private readonly sourceConfigCipher: SourceConfigCipher;
  /** M8: immutable badge-bound authority snapshots for governed agent access. */
  readonly gatewayGrants: AgentConnectionGrantStore;
  /** M8A: content-free access events, alerts, and exact temporary approvals. */
  readonly gatewayOversight: AgentOversightStore;
  readonly connectorRegistry: ConnectorRegistry;
  /** M4: tenant registry over the `tenants` table (owner-gated register). */
  readonly tenants: TenantRegistry;
  /** M4: the process-wide ed25519 signing key (loaded once at boot). */
  readonly signingKey: SigningKey;
  /** M5: human user store (bootstrap owner + roster) over the `users` table. */
  readonly users: UserStore;
  /** M5: opaque hashed-at-rest session store over the `sessions` table. */
  readonly sessions: SessionStore;
  readonly bootstrapService: BootstrapService;
  readonly invitations: InvitationStore;
  /** M10: server-owned access grants (create/revoke/list, D47 revocation). */
  readonly accessGrants: AccessGrantStore;
  /** M10: the root View-as dependency bundle (D43). */
  private readonly viewAsDeps: ViewAsDeps;
  /** Verified-email, short-lived first-organization provisioning capability. */
  readonly organizationSignup: OrganizationSignupService;
  /** R4C: durable, idempotent verified first-tenant/team setup. */
  readonly setupService: SetupService;
  /** R5A: stable, governed L2/L3 pins used directly by the allocator. */
  readonly pins: PinService;
  /** R5B: absent only when the private-L3 KEK is not configured. */
  readonly consolidation: ConsolidationService | null;
  /** Trust-dispute review queue (the human half of trust-ranked supersedence). */
  readonly disputes: DisputeService;
  /** Explicit bounded organization-memory scans; separate from write-time quarantine. */
  readonly conflictScans: ConflictScanService;
  readonly conflictAutopilot: ConflictAutopilot;
  readonly entityTagger: EntityTagger;
  /** Explicit agent-session completion; raw turns are never durable. */
  readonly agentSessions: AgentSessionSummaryService;
  readonly sharing: SharingService;
  readonly movement: MovementEngine;
  readonly pager: PolicyPager;
  /** R6: warm-store mirrors — outbox, write-through fan-out, flush, rebuild. */
  readonly warm: WarmStoreManager;
  /** M7/D20: bounded content-addressed hot tier, invalidated by governance changes. */
  readonly l1Cache: ContentAddressedL1Cache;
  private readonly l1ReadAliases = new Map<string, { key: string; version: string }>();
  /** M7/D20: immutable cold-object cartridge mounted behind a stable interface. */
  readonly coldDriver: ColdStoreDriver;
  /** M9 #23 (E52): typed product keys (admin/assistant/read-only) over api_keys. */
  readonly productKeys: ProductKeyService;
  private readonly agentBearerCipher: AgentBearerCipher;
  /** M9 #18 (D31): per-turn answer-outcome capture + derived accuracy rollup. */
  readonly feedback: AnswerOutcomeService;
  /** M9 #19 (D30): org automation store (org_automations + durable re-arm). */
  readonly automations: OrgAutomationStore;
  /** M9 #19: durable `automation` job worker; null without a consolidation lane. */
  readonly automationRunner: AutomationRunner | null;
  /** Optional packaging boundary. Standalone Halofy is unmetered by default. */
  readonly quota: QuotaPort;
  /** Optional commercial accounting; absent in the standalone build. */
  readonly meter: MeterPort | undefined;
  /** M9 #11b (D29/E23–E27): hosted OAuth AS — approved clients, sha256 tokens. */
  readonly oauthClients: OAuthClientService;
  readonly oauthTokens: OAuthTokenService;
  /** CONTRACTS-OAUTH-CONNECT OA5: single-use PKCE-bound authorization codes. */
  readonly oauthCodes: OAuthCodeService;
  /** M9 #9 (E19–E22): deduped company skill library + vetting + usage rollup. */
  readonly skills: SkillStore;
  /** Curated default-skill seeder for new tenant roots (brownout-wrapped). */
  private readonly seedDefaultSkills: (namespace: Namespace) => Promise<void>;
  readonly skillVetting: SkillVetting;
  readonly skillUsage: SkillUsageService;
  private conflictScanWorker: Promise<{ claimed: number; completed: number; failed: number }> | null = null;
  private conflictAutopilotWorker: Promise<ConflictAutopilotRunResult> | null = null;
  private entityTagWorker: Promise<EntityTagRunResult> | null = null;
  private companyFileWorker: Promise<{ claimed: number; completed: number }> | null = null;
  private companyFileWorkerWake = false;
  private relationshipEnrichmentWorker: Promise<{ claimed: number; completed: number }> | null = null;
  private readonly connectorJobPoller: NodeJS.Timeout;
  private readonly conflictScanJobPoller: NodeJS.Timeout;
  private readonly conflictAutopilotPoller: NodeJS.Timeout;
  private readonly entityTagPoller: NodeJS.Timeout;
  private readonly embeddingBackfillPoller: NodeJS.Timeout;
  private embeddingBackfillWorker: Promise<BackfillResult> | null = null;
  readonly memoryTitles: MemoryTitleJobs;
  private readonly memoryTitlePoller: NodeJS.Timeout;
  private memoryTitleWorker: Promise<MemoryTitleRunResult> | null = null;
  /** Stops the convergence log once there is nothing left to repair. */
  private embeddingBackfillIdle = false;
  private readonly runtimes = new Map<Namespace, KernelNamespaceRuntime>();
  private readonly deps: SyscallDeps;
  /** Read-only, ACL-scoped entity listing for ScopedViews (kernel-side SQL). */
  private readonly entitiesReader: ViewEntitiesLike;

  private constructor(parts: {
    config: KernelConfig;
    db: Db;
    index: MemoryIndex;
    audit: AuditLog;
    cold: ColdStore;
    coldDriver: ColdStoreDriver;
    embedder: Embedder;
    llm: LlmClient;
    signingKey: SigningKey;
    vettingV2: { mode: VettingV2Mode; lanes: SkillVettingLanes };
    quota?: QuotaPort;
    meter?: MeterPort;
  }) {
    this.config = parts.config;
    this.db = parts.db;
    this.index = parts.index;
    this.audit = parts.audit;
    this.memoryTitles = new MemoryTitleJobs(
      this.db,
      this.audit,
      `memory-title-worker:${process.pid}:${ulid()}`,
    );
    this.teamMemoryAccess = new TeamMemoryAccessPolicy(this.db, this.audit);
    this.cold = parts.cold;
    this.l1Cache = new ContentAddressedL1Cache();
    this.coldDriver = parts.coldDriver;
    this.embedder = parts.embedder;
    this.llm = parts.llm;
    this.signingKey = parts.signingKey;
    this.agentBearerCipher = new AgentBearerCipher(this.signingKey);

    this.logger = createLogger({ fields: { mod: "kernel" } });
    this.auth = new AuthService(this.db, this.audit);
    this.policyStore = new PolicyStore(this.db, {
      // Config env overrides stay authoritative as the base of the merge chain.
      defaults: {
        tokenBudget: this.config.defaultTokenBudget,
        dedupeSimilarityThreshold: this.config.dedupeThreshold,
      },
    });
    this.metrics = new MetricsRegistry();
    this.rateLimiter = new DurableRateLimitStore(this.db);
    this.budget = new BudgetGuard(this.db);
    this.costLedger = new DbCostLedger(this.db);
    this.entitiesReader = makeEntitiesReader(this.db);
    this.sourceConfigCipher = new SourceConfigCipher(
      this.config.sourceConfigKek,
      !this.config.databaseUrl && !this.config.pgliteDataDir,
    );
    this.sources = new SourceRegistry(
      this.db,
      this.sourceConfigCipher,
      (db, event) => this.audit.appendTo(db, event),
    );
    // M9 #23: typed key labels + audited create/rotate/revoke over api_keys.
    this.productKeys = new ProductKeyService(
      this.db,
      this.auth,
      this.audit,
      this.agentBearerCipher,
    );
    // M9 #11b (D29): OAuth clients are admin-approved; tokens are hashed at
    // rest and resolve server-side to an Identity exactly like an API key.
    this.oauthClients = new OAuthClientService(this.db, this.audit);
    this.oauthTokens = new OAuthTokenService(this.db, this.audit, this.oauthClients);
    this.oauthCodes = new OAuthCodeService(this.db, this.audit);
    // M9 #9 (E19/D10): the skill catalog's knowledge-bearing metadata enters
    // through the SAME write path as every ingested document; a write-path
    // brownout degrades the registration, never fails it.
    this.skills = new SkillStore({
      db: this.db,
      audit: this.audit,
      writeMemory: async (identity, req) => {
        const policy = await this.policyStore.getFresh(identity.namespace);
        return performWrite(this.deps, req, policy, identity, "skills");
      },
    });
    // Default skill library: every newly provisioned tenant root is seeded
    // with the curated pack (src/skills/defaults.ts), marked by
    // created_by=system-default-skills. A dedicated store WITHOUT the
    // writeMemory seam — seeding the pack must not push 29 extraction
    // writes through the write path at provisioning time. Brownout (rule 5):
    // a seed failure logs and never fails provisioning; the
    // `skills seed-defaults <namespace>` CLI is the ops escape hatch.
    const defaultSkillsStore = new SkillStore({ db: this.db, audit: this.audit });
    this.seedDefaultSkills = async (namespace) => {
      try {
        await seedDefaultSkills(defaultSkillsStore, this.db, namespace);
      } catch (err) {
        this.logger.warn("default skills seed failed", {
          namespace,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    };
    this.skillVetting = new SkillVetting({ db: this.db, audit: this.audit, v2: parts.vettingV2 });
    this.skillUsage = new SkillUsageService({ db: this.db });
    // M9 #18 (D31): governance rows in the one Postgres, same-tx audit.
    this.feedback = new AnswerOutcomeService({ db: this.db, audit: this.audit });
    this.quota = parts.quota ?? UNMETERED;
    this.meter = parts.meter;
    // M9 #19 (D30): org automation store; the runner is wired after the
    // consolidation lane exists (it is the ONLY way templates emit knowledge).
    this.automations = new OrgAutomationStore(this.db, this.audit);
    this.policyDocuments = new PolicyDocumentStore(this.db);
    this.policyCompliance = new PolicyComplianceStore(this.db);
    this.knowledgeBases = new KnowledgeBaseStore(this.db);
    this.knowledgeBaseSources = new KnowledgeBaseSourceStore(this.db);
    this.companyFiles = new CompanyFileStore(this.db);
    this.companyFileJobs = new CompanyFileIngestJobStore(this.db, this.sourceConfigCipher);
    // Metered + resilient, not the raw client: this lane previously bypassed
    // the cost ledger entirely (invisible spend) and had no retry/timeout/
    // breaker. Root-namespace attribution — it is a platform lane.
    this.relationships = new RelationshipKernelAdapter(
      this.db,
      new ResilientLlm(this.llm, this.costLedger, ""),
    );
    this.gatewayGrants = new AgentConnectionGrantStore(this.db);
    this.gatewayOversight = new AgentOversightStore(this.db);
    this.tenants = new TenantRegistry(this.db, { seedDefaultSkills: this.seedDefaultSkills });
    // M5: human auth stores share the ONE database (D5). login/session helpers
    // take the { users, sessions } bundle below.
    this.users = new UserStore(this.db);
    this.sessions = new SessionStore(this.db);
    this.bootstrapService = new BootstrapService(this.db, this.config.bootstrapToken);
    this.invitations = new InvitationStore(this.db);
    // M10: one grant store over the one database (D5); every mutation audits
    // inside its own transaction (D4). Invitation acceptance syncs the
    // membership grant in the SAME tx (one permission system).
    this.accessGrants = new AccessGrantStore({ db: this.db, audit: this.audit });
    this.invitations.membershipGrants = this.accessGrants;
    // The D41 translation is injected — view-as never inlines role ternaries.
    this.viewAsDeps = {
      db: this.db,
      audit: this.audit,
      toProductRole: (role) => toProductRole(role).role,
    };
    this.organizationSignup = new OrganizationSignupService(this.db, {
      seedDefaultSkills: this.seedDefaultSkills,
    });
    this.sharing = new SharingService(this.db, this.audit);
    this.index.setMountedMemoryResolver(async (namespace) =>
      (await this.sharing.resolver.resolveMountedRefs(namespace))
        .filter((item) => item.kind === "memory")
        .map((item) => item.ref),
    );
    this.cold.setMountedConceptResolver(async (namespace) => {
      const versionIds = (await this.sharing.resolver.resolveMountedRefs(namespace))
        .filter((item) => item.kind === "concept" && item.versionId)
        .map((item) => item.versionId as string);
      if (versionIds.length === 0) return [];
      const placeholders = versionIds.map((_, index) => `$${index + 1}`).join(", ");
      const rows = await this.db.query(
        `SELECT path FROM knowledge_versions WHERE id IN (${placeholders}) AND state = 'published'`,
        versionIds,
      );
      return rows.rows.map((row) => String(row.path));
    });
    this.pins = new PinService(this.db, this.audit, {
      readConcept: (namespace, path) => this.cold.readConcept(namespace, path),
    }, async (namespace, target, db) =>
      (await this.sharing.resolver.resolveMountedRefs(namespace, db))
        .some((item) => item.kind === target.kind && item.ref === target.ref),
    );
    const consolidationKey = decodeCanonicalKey(this.config.coldKek);
    this.consolidation = consolidationKey
      ? new ConsolidationService({
          db: this.db,
          audit: this.audit,
          // Metered + resilient for the same reason as this.relationships:
          // consolidation spend was invisible to the ledger.
          engine: new KernelConsolidationEngine(new ResilientLlm(this.llm, this.costLedger, "")),
          cipher: new AesGcmDraftCipher(
            consolidationKey,
            "cold:" + createHash("sha256").update(consolidationKey).digest("hex").slice(0, 24),
          ),
          publisher: {
            publish: async (input) => {
              const policy = await this.policyStore.getFresh(input.namespace);
              const classification = classifyData(input.body, {
                allowedDestinations: policy.restrictedDestinations ?? [],
              });
              assertDestinationAllowed(classification, "canonical-l3", {
                region: policy.dataRegion,
              });
              await this.cold.writePrivateConcept(this.db, {
                path: input.path,
                type: "concept",
                title: input.title,
                description: "Human-approved consolidation proposal",
                tags: ["consolidated"],
                namespace: input.namespace,
                owner: "halomem-consolidation",
                verifiedAgainst: input.versionId,
                verifiedAt: new Date().toISOString(),
                body: input.body,
              });
              await this.cold.syncToDb(this.db, this.embedder);
            },
          },
        })
      : null;
    // M9 #19 (D30/E35): automation output flows ONLY through the governed
    // consolidation review pipeline. Without a cold KEK there is no
    // consolidation lane, so the runner stays unmounted (brownout — configure
    // still works; enabled rows simply wait until the lane exists).
    this.automationRunner = this.consolidation
      ? new AutomationRunner({
          db: this.db,
          audit: this.audit,
          store: this.automations,
          proposer: this.consolidation,
          ...(this.meter === undefined ? {} : { meter: this.meter }),
        })
      : null;
    this.disputes = new DisputeService({
      db: this.db,
      audit: this.audit,
      // Edit-lane embedding through the per-namespace resilient embedder
      // (cost attribution + breaker). A failure is a brownout — the corrected
      // fact lands without a vector (BM25-findable), never blocks resolution.
      embed: async (namespace, texts) => {
        try {
          return await this.runtimeFor(namespace).embedder.embed(texts);
        } catch {
          return texts.map(() => null);
        }
      },
    });
    const conflictClassifier = this.config.conflictClassifier !== undefined
      ? this.config.conflictClassifier
      : this.config.azureOpenaiConflictApiKey &&
          this.config.azureOpenaiConflictEndpoint &&
          this.config.azureOpenaiConflictDeployment
        ? new LlmConflictClassifier(
            new AzureOpenAiScanClient(
              this.config.azureOpenaiConflictApiKey,
              this.config.azureOpenaiConflictEndpoint,
              this.config.azureOpenaiConflictDeployment,
              this.config.azureOpenaiApiVersion,
            ),
            `azure-openai-conflict@${this.config.azureOpenaiConflictDeployment}`,
          )
        : null;
    this.conflictScans = new ConflictScanService(
      this.db,
      this.audit,
      conflictClassifier,
      this.config.conflictScanRequestCooldownMs,
    );
    // CA5: detection is unconditional; the dial only decides how much the
    // lattice may settle unattended. "off" still gets lattice decisions — it
    // asks for no human gate, not for blind recency.
    this.entityTagger = new EntityTagger(this.db, this.audit);
    this.conflictAutopilot = new ConflictAutopilot(
      this.db,
      this.audit,
      conflictClassifier,
      async (namespace) => {
        const mode = (await this.policyStore.get(namespace)).conflictReview;
        return mode === "all" ? "all" : mode === "lower-trust" ? "lower-trust" : "auto";
      },
    );
    this.movement = new MovementEngine(this.db, this.audit, {
      loadPublishedVersion: async (versionId, namespace) => {
        const row = await this.db.query(
          `SELECT kv.id, kv.path, kc.id AS concept_id
             FROM knowledge_versions kv JOIN knowledge_concepts kc ON kc.id = kv.concept_id
            WHERE kv.id = $1 AND kv.state = 'published' AND kc.namespace = $2
              AND kc.status = 'active' AND kc.current_version_id = kv.id`,
          [versionId, namespace],
        );
        if (row.rows.length !== 1) throw new Error("published version unavailable");
        const concept = await this.cold.readConcept(namespace, String(row.rows[0].path));
        if (!concept) throw new Error("published concept unavailable");
        return {
          content: concept.body,
          conceptId: String(row.rows[0].concept_id),
          versionId,
          type: "concept" as const,
          scope: "team" as const,
          confidence: 1,
          embedding: (await this.embedder.embed([concept.body]))[0] ?? null,
        };
      },
      ...(this.consolidation
        ? {
            prepareColdProposal: async (
              _targetRef: string,
              evidenceIds: readonly string[],
              identity: Identity,
            ) => {
              const now = new Date();
              const prepared = await this.consolidation!.prepare(identity, {
                namespace: identity.namespace,
                evidenceIds: [...evidenceIds],
                windowStart: new Date(0).toISOString(),
                windowEnd: now.toISOString(),
              });
              if (prepared.proposalIds.length === 0) {
                throw new Error("consolidation produced no review proposal");
              }
              return {
                commitPrepared: async (tx: Db) => {
                  await prepared.commitPrepared(tx);
                  return { proposalId: prepared.proposalIds[0]! };
                },
              };
            },
          }
        : {}),
    }, {
      promotePin: { enabled: true, minAccessCount: 10, minSessionCount: 0 },
    });
    const pagerJobs = new DurableJobStore(this.db);
    this.pager = new PolicyPager({
      workerId: `pager:${process.pid}:${ulid()}`,
      leaseMs: 5 * 60_000,
      policy: {
        evaluate: (job) => {
          const payload = job.payload as { movement?: PagerMovement };
          return payload.movement ?? null;
        },
      },
      ports: {
        queue: {
          claim: async ({ workerId, leaseMs, limit }) => {
            const claimed = [];
            for (let i = 0; i < limit; i++) {
              const job = await pagerJobs.claim(workerId, { kinds: ["movement"], leaseMs });
              if (!job) break;
              claimed.push(job);
            }
            return claimed;
          },
          complete: async (jobId, workerId) => {
            if (!(await pagerJobs.complete(jobId, workerId))) {
              throw new Error("pager lease lost before completion");
            }
          },
          retry: async (jobId, workerId, reason, availableAt) => {
            if (!(await pagerJobs.fail(jobId, workerId, reason, { retryAt: availableAt }))) {
              throw new Error("pager lease lost before retry");
            }
          },
        },
        execute: async (job, movement) => {
          const result = await this.movement.runManual({
            keyId: "halomem:pager",
            namespace: job.namespace,
            actor: "halomem-pager",
            role: "admin",
          }, movement);
          if (result.status !== "complete" || result.result?.promoted === false) {
            throw new Error(`movement did not complete: ${result.status}`);
          }
          return result;
        },
        audit: (event) => this.audit.append({
          ts: event.ts,
          actor: "halomem-pager",
          agentId: event.workerId,
          op: "move",
          memoryId: null,
          namespace: event.namespace,
          purpose: event.action,
          result: event.result,
          detail: `pager job=${event.jobId} reason=${event.reason}`,
        }),
      },
    });

    // M2: mount the retriever cartridges. baseline + graph always; mem0 only
    // when HALOMEM_MEM0_URL points at a sidecar (its constructor throws
    // DriverUnavailableError without a URL — never construct it blind).
    this.registry = new DriverRegistry({
      warn: (message) => this.logger.warn(message),
    });
    this.registry.mount(new BaselineDriver());
    this.registry.mount(new GraphDriver());
    if (process.env.HALOMEM_MEM0_URL) {
      try {
        this.registry.mount(new Mem0Driver({
          authToken: process.env.HALOMEM_MEM0_TOKEN,
        }));
      } catch (err) {
        this.logger.warn("mem0 driver not mounted", {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // R6: warm-store mounts. The canonical Postgres lane is always mounted;
    // external mirrors mount iff their sidecar URL is configured (same
    // precedent as the mem0 retriever). HALOMEM_WARMSTORE_NAMESPACES
    // optionally restricts which subtrees are mirrored off-box.
    const warmRegistry = new WarmStoreRegistry();
    warmRegistry.mount(new PostgresWarmStore(this.db));
    for (const [name, envVar, tokenEnvVar] of [
      ["mem0", "HALOMEM_WARMSTORE_MEM0_URL", "HALOMEM_WARMSTORE_MEM0_TOKEN"],
      ["supermemory", "HALOMEM_WARMSTORE_SUPERMEMORY_URL", "HALOMEM_WARMSTORE_SUPERMEMORY_TOKEN"],
    ] as const) {
      const url = process.env[envVar];
      if (!url) continue;
      try {
        warmRegistry.mount(name === "mem0"
          ? new Mem0WarmStore({ url, authToken: process.env[tokenEnvVar] })
          : new SupermemoryWarmStore({ url, authToken: process.env[tokenEnvVar] }));
      } catch (err) {
        this.logger.warn(`${name} warm store not mounted`, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    this.warm = new WarmStoreManager({
      db: this.db,
      registry: warmRegistry,
      logger: this.logger,
      namespaceRoots: (process.env.HALOMEM_WARMSTORE_NAMESPACES ?? "")
        .split(",")
        .map((n) => n.trim())
        .filter((n) => n.length > 0),
    });

    this.setupService = new SetupService({
      db: this.db,
      registry: this.registry,
      signingKey: this.signingKey,
      preflightSource: (source) => this.preflightSetupSource(source),
      syncSource: (sourceId, identity) => this.syncSource(sourceId, identity),
      sealSourceConfig: (id, namespace, kind, config) =>
        this.sources.sealForStorage(id, namespace, kind, config),
      seedDefaultSkills: this.seedDefaultSkills,
    });

    this.deps = {
      config: this.config,
      db: this.db,
      index: this.index,
      audit: this.audit,
      cold: this.cold,
      metrics: this.metrics,
      rateLimiter: this.rateLimiter,
      budget: this.budget,
      logger: this.logger,
      quotaRateLimit: (current, actor) => this.quota.rateLimitPerMin(current, actor),
      isCredentialActive: (identity) => this.isIdentityActive(identity),
      getPolicy: (namespace) => this.policyStore.getFresh(namespace),
      resolveTenant: (namespace) => this.tenants.resolveTenant(namespace),
      signingKey: this.signingKey,
      runtimeFor: (namespace) => this.runtimeFor(namespace),
      enqueueWrite: (req, identity, agentId) =>
        this.writeQueue.enqueue({ req, agentId }, identity),
      registry: this.registry,
      buildView: (namespace, access, sourceProjection) =>
        this.buildView(namespace, access, sourceProjection),
      // R6: warm-store hooks. Purge ops enqueue INSIDE the erasure transaction
      // (atomic with the certificate); write-through and purge delivery run
      // post-commit and never throw (brownout).
      afterWriteCommit: async (result) => {
        for (const id of result.superseded) this.l1Cache.invalidateSuperseded(id);
        for (const memory of result.stored) this.l1Cache.eraseNamespace(memory.namespace);
        await this.warm.afterWrite(result);
      },
      afterAccessCommit: (ids, namespace) => this.scheduleAutomaticMovement(ids, namespace),
      // D39: undefined unless the extraction LLM lane is live (keyless stays
      // verbatim — the hermetic default).
      traceSummarizer: this.buildTraceSummarizer(),
      l1: {
        get: (id, identity, policyVersion) => {
          const alias = contentAddress({ id, namespace: identity.namespace,
            access: sourceAccessSubject(identity) });
          const mapped = this.l1ReadAliases.get(alias);
          if (!mapped) return null;
          const hit = this.l1Cache.get(mapped.key, {
            namespace: l1CachePartition(identity.namespace),
            version: mapped.version,
            policyVersion,
          });
          if (!hit) this.l1ReadAliases.delete(alias);
          return (hit?.value as MemoryObject | undefined) ?? null;
        },
        set: (obj, identity, policyVersion) => {
          const alias = contentAddress({ id: obj.id, namespace: identity.namespace,
            access: sourceAccessSubject(identity) });
          const entry = this.l1Cache.set({
            namespace: l1CachePartition(identity.namespace),
            value: obj,
            version: obj.assertionTime,
            policyVersion,
            ttlMs: 30_000,
            dependencies: [obj.id, ...(obj.supersedes ? [obj.supersedes] : [])],
          });
          this.l1ReadAliases.set(alias, { key: entry.key, version: entry.version });
        },
      },
      enqueueWarmPurges: (tx, erasedIds, namespace) =>
        this.warm.enqueuePurgesTx(tx, erasedIds, namespace),
      afterForgetCommit: async (erasedIds, namespace) => {
        this.l1Cache.eraseNamespace(l1CachePartition(namespace));
        return this.warm.afterForget(erasedIds, namespace);
      },
    };

    this.agentSessions = new AgentSessionSummaryService({
      db: this.db,
      audit: this.audit,
      summarize: async (turns, identity) => {
        const raw = await this.runtimeFor(identity.namespace).llm.complete(
          "You summarize completed AI-agent chats for governed organizational memory. " +
          "Return only JSON: {\"summary\":string,\"claims\":[{\"content\":string,\"role\":\"user\"|\"assistant\"}]}. " +
          "Keep the summary under 1200 characters. Include only durable organizational facts, decisions, rules, or outcomes. " +
          "Exclude secrets, credentials, personal data, greetings, and conversational filler. Never invent a claim.",
          JSON.stringify({ turns }),
        );
        const parsed = parseLooseJson(raw);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("agent session summarizer returned invalid JSON");
        }
        const value = parsed as Record<string, unknown>;
        if (typeof value.summary !== "string" || !Array.isArray(value.claims)) {
          throw new Error("agent session summarizer returned an invalid shape");
        }
        return {
          summary: value.summary,
          claims: value.claims.map((entry) => {
            if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
              throw new Error("agent session summarizer returned an invalid claim");
            }
            const claim = entry as Record<string, unknown>;
            if (typeof claim.content !== "string" ||
              (claim.role !== "user" && claim.role !== "assistant")) {
              throw new Error("agent session summarizer returned an invalid claim");
            }
            return { content: claim.content, role: claim.role };
          }),
        };
      },
      write: async (request, identity) => {
        const policy = await this.policyStore.getFresh(identity.namespace);
        const tenant = await this.tenants.resolveTenant(identity.namespace);
        return performWrite(this.deps, request, policy, identity, identity.keyId, tenant);
      },
    });

    this.writeQueue = new DurableWriteQueue<QueuedWrite, WriteResult>(
      this.db,
      async (job, identity) => {
        // The Identity was SNAPSHOTTED at enqueue time — re-validate the
        // credential now, so a key revoked after enqueue cannot keep writing
        // ('revoked key → 401 instantly' must also cover queued work).
        if (!(await this.isIdentityActive(identity))) {
          const message = "queued write denied: api key was revoked after enqueue";
          await this.auditQueuedWriteFailure(job, identity, "denied", message);
          throw new AuthzError(message);
        }
        if (identity.role === "agent") {
          try {
            await this.requireAgentOperation("write", identity);
          } catch (err) {
            const message = "queued write denied: connection grant is no longer active";
            await this.auditQueuedWriteFailure(job, identity, "denied", message);
            throw err;
          }
        }
        try {
          // Policy is re-resolved at execution time (it may have changed since
          // enqueue) and the write runs through the exact same Identity-scoped
          // path as a sync write, budget brownout included.
          const policy = await this.policyStore.getFresh(identity.namespace);
          return await performWrite(this.deps, job.req, policy, identity, job.agentId);
        } catch (err) {
          // D4: every syscall outcome leaves an audit row. The sync path
          // audits failures in memWrite's catch; the queue worker bypasses
          // memWrite, so a failed async write must audit here — otherwise it
          // vanishes into in-memory ticket state only.
          await this.auditQueuedWriteFailure(
            job,
            identity,
            "error",
            err instanceof Error ? err.message : String(err),
          );
          throw err;
        }
      },
    );
    this.connectorRegistry = makeBuiltinConnectorRegistry();
    this.connectorJobPoller = setInterval(
      () => {
        void this.runConnectorJobsOnce().catch(() => undefined);
        // M9 #19 (E36): the automation recurrence is a durable poll-and-claim
        // pass on the same cadence — never a per-automation timer.
        void this.runAutomationJobsOnce().catch(() => undefined);
        void this.runCompanyFileUploadJobsOnce().catch(() => undefined);
        void this.runRelationshipEnrichmentJobsOnce().catch(() => undefined);
      },
      5_000,
    );
    this.connectorJobPoller.unref?.();
    // Scan requests wake a worker immediately at the HTTP boundary. This slow
    // recovery poll handles restarts without adding a DB query to the 5-second
    // hot poller (which would perturb syscall p95 latency).
    this.conflictScanJobPoller = setInterval(
      () => void this.runConflictScanJobsOnce().catch(() => undefined),
      30_000,
    );
    this.conflictScanJobPoller.unref?.();
    // Writes kick the autopilot at the HTTP boundary, but a check that deferred
    // (judge outage, missing embedding) must not wait for the NEXT write to be
    // retried — on a quiet namespace that could be hours. This tick drains the
    // backlog on its own, and is also what recovers a lease abandoned by a
    // crashed replica.
    this.conflictAutopilotPoller = setInterval(
      () => void this.runConflictAutopilotOnce().catch(() => undefined),
      15_000,
    );
    this.conflictAutopilotPoller.unref?.();
    // CA8 backfill: migration 85 enrols every existing untagged fact, so this
    // tick is what actually drains ~1,500 rows on the first deployment and then
    // idles. Deliberately ahead of the conflict poller in cadence — a fact is
    // more useful to the scan once it has a subject.
    this.entityTagPoller = setInterval(
      () => void this.runEntityTagJobsOnce().catch(() => undefined),
      10_000,
    );
    this.entityTagPoller.unref?.();
    // Switching on a real embeddings deployment realigns the vector columns at
    // boot and leaves every existing row NULL. Repairing that cannot depend on
    // an operator running a CLI — semantic search is degraded org-wide until it
    // finishes — so the kernel converges on its own, a bounded batch at a time.
    // Idles to a no-op query once nothing is outstanding.
    this.embeddingBackfillPoller = setInterval(
      () => void this.runEmbeddingBackfillOnce().catch(() => undefined),
      15_000,
    );
    this.embeddingBackfillPoller.unref?.();
    this.memoryTitlePoller = setInterval(
      () => void this.runMemoryTitleJobsOnce().catch(() => undefined),
      5_000,
    );
    this.memoryTitlePoller.unref?.();
    void this.runConnectorJobsOnce().catch(() => undefined);
    void this.runEmbeddingBackfillOnce().catch(() => undefined);
    void this.runAutomationJobsOnce().catch(() => undefined);
    void this.runCompanyFileUploadJobsOnce().catch(() => undefined);
    void this.runRelationshipEnrichmentJobsOnce().catch(() => undefined);
  }

  /** Best-effort audit row for a failed/denied queued write (never masks the error). */
  private async auditQueuedWriteFailure(
    job: QueuedWrite,
    identity: Identity,
    result: "denied" | "error",
    detail: string,
  ): Promise<void> {
    try {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: job.agentId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: null,
        result,
        detail: detail.slice(0, 500),
      });
    } catch {
      // Audit-sink failure must not shadow the queue error.
    }
  }

  /** Boot the full kernel: config → db → migrate → embed/llm → L3 sync → modules. */
  static async boot(overrides: Partial<KernelConfig> = {}): Promise<Kernel> {
    const config = loadConfig(overrides);
    assertSupportedDeployment(config);

    const db = await createDb(config);
    await migrate(db, config.embedDim);

    const embedder = createEmbedder(config);
    const llm = createLlm(config);

    // In production the cartridge root is the mounted durable volume and the
    // legacy ColdStore reads/writes its objects/ subtree. The health-checked
    // cartridge therefore observes the actual authoritative cold bytes rather
    // than a disconnected facade. Development retains the repository layout.
    const sharedCold = process.env.HALOMEM_COLD_STORAGE === "shared-persistent";
    const coldDriverRoot = sharedCold
      ? config.knowledgeDir
      : join(config.knowledgeDir, ".halomem-coldstore");
    const coldKnowledgeDir = sharedCold ? join(coldDriverRoot, "objects") : config.knowledgeDir;
    const coldDriver = new LocalColdStoreDriver({ root: coldDriverRoot });
    const cold = new ColdStore(coldKnowledgeDir, config.coldKek);
    // Boot-time L3 sync uses the raw embedder: there is no caller identity to
    // attribute cost to, and a cold-start must not trip a namespace breaker.
    try {
      await cold.validateBootConfiguration(db);
      await cold.syncToDb(db, embedder);
    } catch (err) {
      await db.close();
      throw err;
    }

    const index = new MemoryIndex(db);
    const audit = new AuditLog(db);

    // M4: load the ed25519 signing key ONCE at boot so every DeletionCertificate
    // minted in this process shares one public key (a regulator can pin it). If
    // HALOMEM_SIGNING_KEY is unset an ephemeral keypair is generated (warn once).
    const signingKey = loadSigningKey();

    const kernel = new Kernel({
      config, db, index, audit, cold, coldDriver, embedder, llm, signingKey,
      // D35: tests inject stubbed lanes via the config seam; otherwise probe
      // the environment (Azure scan deployment + pinned scanner CLIs).
      // Probing is skipped under test runners — the hermetic suite must
      // never spawn a scanner that happens to be installed on a dev box.
      vettingV2: {
        mode: config.skillVettingV2,
        lanes: config.skillVettingV2Lanes ??
          (process.env.NODE_ENV === "test" || process.env.VITEST !== undefined
            ? {}
            : await resolveVettingLanes(config)),
      },
    });
    try {
      const coldHealth = await kernel.coldDriver.health();
      if (!coldHealth.ok) {
        throw new Error(`cold-store cartridge unavailable: ${coldHealth.detail ?? "unknown"}`);
      }
      await kernel.sources.protectLegacyConfigs();
    } catch (err) {
      await db.close();
      throw err;
    }
    return kernel;
  }

  /** D36 brownout sink: usage-write failures are logged, never thrown. */
  private usageRecorderDeps(): UsageRecorderDeps {
    return {
      onFailure: (err) =>
        this.logger.warn("usage event write failed - syscall outcome stands (brownout)", {
          error: err instanceof Error ? err.message : String(err),
        }),
    };
  }

  /**
   * D39: the optional LLM trace-summary upgrader. Wired only when the
   * extraction LLM lane is live (same key gating as createLlm); the
   * per-namespace ResilientLlm gives the call budget accounting and the
   * circuit breaker. Outbound text passes the shared D33 secret redaction.
   * Without keys the dep stays undefined and the verbatim summary stands
   * (the hermetic default).
   */
  private buildTraceSummarizer():
    | ((query: string, namespace: Namespace) => Promise<string>)
    | undefined {
    const live =
      (this.config.azureOpenaiLlmApiKey !== "" &&
        this.config.azureOpenaiLlmEndpoint !== "" &&
        this.config.azureOpenaiLlmDeployment !== "") ||
      this.config.anthropicApiKey !== "";
    if (!live) return undefined;
    return async (query, namespace) => {
      const llm = this.runtimeFor(namespace).llm;
      const { redacted } = redactForOutbound(query);
      return llm.complete(
        "Summarize the following agent memory query in at most 120 characters. " +
          "Reply with the summary only - no quotes, no preamble.",
        redacted,
      );
    };
  }

  /**
   * Per-namespace runtime: resilient LLM/embedder (cost rows attributed to the
   * caller's namespace, one circuit breaker per namespace) + the modules that
   * consume them. Cached per namespace.
   */
  private runtimeFor(namespace: Namespace): KernelNamespaceRuntime {
    let rt = this.runtimes.get(namespace);
    if (rt) return rt;

    // Chunking bounds document requests. Three minutes matches the extraction
    // attempt and allows a slow provider response to complete without turning
    // a valid large document into a terminal file failure.
    const embedder = new ResilientEmbedder(this.embedder, this.costLedger, namespace, {
      retry: {
        timeoutMs: WRITE_PATH_EMBED_ATTEMPT_TIMEOUT_MS,
        shouldRetry: isRetryableEmbeddingError,
        retryAfterMs: embeddingRetryAfterMs,
      },
    });
    // Three minutes per attempt: connector documents (a Linear spec, a policy
    // PDF, or a design-system guide) can legitimately need longer than the old
    // 45-second window to extract. The per-attempt AbortSignal still cancels an
    // abandoned provider request, and exhausted attempts still take the
    // governed verbatim fallback rather than failing the document upload.
    const llm = new ResilientLlm(this.llm, this.costLedger, namespace, {
      retry: { timeoutMs: WRITE_PATH_LLM_ATTEMPT_TIMEOUT_MS },
    });
    const allocator = new ContextAllocator({
      index: this.index,
      cold: this.cold,
      audit: this.audit,
      embedder,
      pins: this.pins,
      // Guardrail lane: governed policy documents already landed in memory
      // through the write path (D10); this reads them back as ordered
      // directives and records each delivery in the compliance ledger.
      policyDirectives: {
        load: (ns, tokenBudget) =>
          loadPolicyDirectives(this.db, ns, { tokenBudget }),
        onDelivered: (set, args) =>
          this.policyCompliance.recordDelivery(set, {
            agentId: args.agentId ?? DEFAULT_AGENT_ID,
            actor: args.actor ?? "unknown",
            principal: args.usage?.principal ?? "agent",
            channel: "assemble",
            traceId: args.usage?.traceId ?? null,
          }),
      },
      // D36: assemble audit row + companion usage row commit together.
      transact: (fn) =>
        this.db.transaction((tx) =>
          fn({ append: (event) => this.audit.appendToWithSeq(tx, event) }, tx),
        ),
      usage: (tx, input) => recordUsageTx(tx as Db, input, this.usageRecorderDeps()),
    });
    const faultHandler = new FaultHandler<Db>({
      db: this.db,
      index: this.index,
      cold: this.cold,
      audit: this.audit,
      embedder,
      // M2: the fault L2 lane routes through the policy-selected driver over
      // the caller's ScopedView (policy re-resolved per fault so a setPolicy
      // retriever swap bites without reboot). L3 fallback stays kernel-side
      // in FaultHandler exactly as before.
      l2Planner: async (query, k, tokenBudget, access) => {
        const policy = await this.policyStore.getFresh(namespace);
        return planViaDriver(
          {
            registry: this.registry,
            buildView: (ns, subject, sourceProjection) =>
              this.buildView(ns, subject, sourceProjection),
            logger: this.logger,
          },
          policy,
          namespace,
          query,
          k,
          tokenBudget,
          access,
        );
      },
      // D36: the fault usage hook rides the audit transaction (third arg).
      usage: (tx, input) => recordUsageTx(tx, input, this.usageRecorderDeps()),
      transact: (fn) =>
        this.db.transaction((tx) =>
          fn(new MemoryIndex(tx), {
            append: (event) => this.audit.appendToWithSeq(tx, event),
          }, tx),
        ),
    });
    const writePath = new WritePath({
      db: this.db,
      index: this.index,
      audit: this.audit,
      embedder,
      llm,
      config: this.config,
      // Exit criterion 3: insert + closeValidity are one transaction. The
      // tx-scoped MemoryIndex shares the prototype, so tests can still
      // monkey-patch MemoryIndex.prototype to inject mid-transaction failures.
      transact: (fn) =>
        this.db.transaction((tx) =>
          fn(
            new MemoryIndex(tx),
            { append: (event) => this.audit.appendTo(tx, event) },
            tx,
          ),
        ),
      beforeCommit: async (tx, req) => {
        if (req.writeFence?.kind === "policy-document") {
          const owned = await tx.query(
            `SELECT id FROM policy_documents
              WHERE id = $1 AND attempt_token = $2
                AND status = 'processing'
                AND lease_expires_at > CURRENT_TIMESTAMP
              FOR UPDATE`,
            [req.writeFence.documentId, req.writeFence.attemptToken],
          );
          if (owned.rows.length !== 1) {
            throw new PolicyDocumentLeaseExpiredError();
          }
          return;
        }
        if (req.writeFence?.kind === "company-document") {
          const owned = await tx.query(
            `SELECT f.id FROM company_files f
              JOIN company_file_upload_attempts attempt
                ON attempt.id = f.upload_attempt_id
             WHERE f.id = $1 AND f.attempt_token = $2
               AND f.status = 'processing' AND f.lifecycle_state = 'active'
               AND f.lease_expires_at > CURRENT_TIMESTAMP
               AND attempt.attempt_token = $2
               AND attempt.status IN ('pending','processing')
               AND attempt.lease_expires_at > CURRENT_TIMESTAMP
             FOR UPDATE`,
            [req.writeFence.documentId, req.writeFence.attemptToken],
          );
          if (owned.rows.length !== 1) {
            throw new CompanyFileLeaseExpiredError();
          }
          return;
        }
        if (req.writeFence?.kind === "source-active") {
          const active = await tx.query(
            `SELECT id FROM sources
              WHERE id = $1 AND lifecycle_state = 'active'
              FOR UPDATE`,
            [req.writeFence.sourceId],
          );
          if (active.rows.length !== 1) {
            throw new Error(`source '${req.writeFence.sourceId}' disconnected during sync`);
          }
        }
      },
    });

    rt = { embedder, llm, allocator, faultHandler, writePath };
    this.runtimes.set(namespace, rt);
    return rt;
  }

  /**
   * D38: run the syscall inside an AsyncLocalStorage usage context (actor +
   * resolved trace id), so the per-namespace resilient wrappers stamp their
   * cost_ledger rows with the caller (and the D37 query_traces rollup). The
   * trace id is resolved ONCE here — a well-formed caller hint survives
   * resolveTraceId verbatim, so the syscall's usage events and its cost rows
   * share one id.
   *
   * Why ALS and not a wrapper slot: the wrappers are per-namespace
   * singletons, so a mutable slot is shared by concurrent syscalls in the
   * SAME namespace and mis-stamps cross-trace. Explicit ctx threading was
   * rejected — it would ripple an extra parameter through every
   * Embedder/LlmClient consumer across the driver boundary (ScopedView),
   * retrieval, fault, allocator, and write modules. ALS gives per-async-
   * context isolation without the threading: concurrent syscalls keep their
   * own attribution, async work STARTED inside the run inherits it (the
   * fire-and-forget D39 trace summarizer intentionally bills the trace it
   * summarizes), and background lanes started outside any run (the
   * WriteQueue worker, ingest, imports) see no store and stay namespace-only
   * (E5). Namespace attribution (the dimension BudgetGuard sums) is always
   * correct.
   */
  private async withUsageContext<T>(
    identity: Identity,
    ctx: SyscallContext | undefined,
    fn: (resolved: SyscallContext) => Promise<T>,
  ): Promise<T> {
    const traceId = resolveTraceId(ctx?.traceId);
    const resolved: SyscallContext = { ...ctx, traceId };
    const usageCtx: UsageContext = { actor: identity.actor, traceId };
    return usageContextStorage.run(usageCtx, () => fn(resolved));
  }

  /**
   * M2: the ACL-scoped read fence for one caller namespace — the ONLY thing
   * a retriever driver ever sees. Built via module A's buildScopedView with
   * the per-namespace resilient embedder (cost attribution + breakers) and
   * the kernel-side entity_registry reader.
   */
  buildView(
    namespace: Namespace,
    access?: AccessSubject,
    sourceProjection?: RetrievalSourceProjection,
  ): ScopedView {
    return buildScopedView(
      {
        db: this.db,
        index: this.index,
        cold: this.cold,
        entities: this.entitiesReader,
        embedder: this.runtimeFor(namespace).embedder,
      },
      namespace,
      access,
      sourceProjection,
    );
  }

  /**
   * M2: referee scorecard — every mounted driver runs over the SAME
   * ScopedView for `namespace`; the result row persists into `scorecards`.
   * D4: the run reads real fact contents, so it writes an audit row —
   * `identity` (when the caller has one, e.g. the HTTP admin route) is used
   * for attribution.
   */
  async runScorecard(
    namespace: Namespace,
    opts?: ScorecardOptions,
    identity?: Identity,
  ): Promise<Scorecard> {
    const drivers = this.registry.list().map((name) => this.registry.get(name));
    return runScorecard(
      {
        db: this.db,
        drivers,
        view: this.buildView(namespace),
        audit: this.audit,
        actor: identity?.actor ?? "kernel",
        agentId: DEFAULT_AGENT_ID,
      },
      namespace,
      opts,
    );
  }

  /** Markdown table for a scorecard (CLI / logs convenience). */
  renderScorecard(card: Scorecard): string {
    return renderScorecardMarkdown(card);
  }

  /** Effective (merged, cached) policy for a namespace. */
  getPolicy(namespace: Namespace): Promise<PolicyConfigX> {
    return this.policyStore.getFresh(namespace);
  }

  /** Decide movement from canonical telemetry, then execute via a durable lease. */
  private async scheduleAutomaticMovement(ids: string[], namespace: Namespace): Promise<void> {
    if (ids.length === 0) return;
    const placeholders = ids.map((_, index) => `$${index + 2}`).join(", ");
    const rows = await this.db.query(
      `SELECT id, access_count FROM memory_objects
       WHERE namespace = $1 AND id IN (${placeholders})
         AND status = 'active' AND t_valid_to IS NULL`,
      [namespace, ...ids],
    );
    const jobs = new DurableJobStore(this.db);
    for (const raw of rows.rows as Array<{ id: string; access_count: number | string }>) {
      const accessCount = Number(raw.access_count);
      let movement: PagerMovement | null = null;
      if (accessCount >= 50 && this.consolidation) {
        const evidence = await this.db.query(
          `SELECT id FROM memory_objects
           WHERE namespace = $1 AND status = 'active' AND t_valid_to IS NULL
           ORDER BY access_count DESC, assertion_time DESC LIMIT 5`,
          [namespace],
        );
        const evidenceIds = [raw.id, ...evidence.rows.map((row) => String(row.id))]
          .filter((id, index, all) => all.indexOf(id) === index);
        if (evidenceIds.length >= 2) {
          movement = { action: "propose_cold", targetRef: raw.id, evidenceIds };
        }
      }
      movement ??= accessCount >= 10
        ? { action: "promote_pin", targetRef: raw.id }
        : null;
      if (!movement) continue;
      await jobs.enqueue({
        id: `pager:${movement.action}:${raw.id}`,
        kind: "movement",
        namespace,
        payload: { movement },
      });
    }
    await this.pager.runOnce();
  }

  /** Validate + persist a partial policy override (YAML) for a namespace. */
  async setPolicy(namespace: Namespace, yamlText: string): Promise<void> {
    await this.policyStore.set(namespace, yamlText);
    this.l1Cache.eraseNamespace(namespace);
  }

  /** Create one governed knowledge collection in a server-resolved scope. */
  async createKnowledgeBase(
    input: KnowledgeBaseCreateInput,
    identity: Identity,
  ): Promise<KnowledgeBaseSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "knowledge-base", "denied", "create_role");
      throw new AuthzError(`role '${identity.role}' may not create knowledge bases`);
    }
    try {
      const target = await this.resolveKnowledgeBaseTarget(input.targetTeamId, identity);
      const { targetTeamId: _targetTeamId, ...metadata } = input;
      const created = await this.knowledgeBases.create(metadata, {
        namespace: target.namespace,
        targetTeamId: target.targetTeamId,
        actor: identity.actor,
      });
      await this.auditKnowledge(identity, created.namespace, "knowledge-base", "ok", "create");
      return created;
    } catch (error) {
      await this.auditKnowledge(identity, identity.namespace, "knowledge-base", "error", "create_failed");
      throw error;
    }
  }

  /** Metadata visible to organization governance roles through exact namespace rows. */
  async listKnowledgeBases(
    query: KnowledgeBaseListQuery,
    identity: Identity,
  ): Promise<KnowledgeBaseListResult> {
    this.requireKnowledgeReadRole(identity);
    const visibleNamespaces = await this.knowledgeBaseVisibleNamespaces(identity);
    const result = await this.knowledgeBases.list(query, { visibleNamespaces });
    return {
      ...result,
      data: await this.withKnowledgeBaseCreatorNames(result.data),
    };
  }

  async getKnowledgeBase(
    id: string,
    identity: Identity,
  ): Promise<KnowledgeBaseSummary | null> {
    this.requireKnowledgeReadRole(identity);
    const visibleNamespaces = await this.knowledgeBaseVisibleNamespaces(identity);
    const base = await this.knowledgeBases.get(id, { visibleNamespaces });
    if (base === null) return null;
    return (await this.withKnowledgeBaseCreatorNames([base]))[0] ?? base;
  }

  /** Enrich only creator actors already present in the scoped response. */
  private async withKnowledgeBaseCreatorNames(
    bases: KnowledgeBaseSummary[],
  ): Promise<KnowledgeBaseSummary[]> {
    const actors = [...new Set(
      bases.map((base) => base.createdBy.trim().toLowerCase()).filter(Boolean),
    )];
    if (actors.length === 0) return bases;
    const placeholders = actors.map((_, index) => `$${index + 1}`).join(", ");
    const result = await this.db.query(
      `SELECT lower(email) AS actor_key, display_name
         FROM users
        WHERE lower(email) IN (${placeholders})
          AND display_name IS NOT NULL`,
      actors,
    );
    const labels = new Map(
      (result.rows as Array<{ actor_key: string; display_name: string }>).map((row) => [
        row.actor_key,
        row.display_name,
      ]),
    );
    return bases.map((base) => {
      const displayName = labels.get(base.createdBy.trim().toLowerCase());
      return displayName ? { ...base, createdByDisplayName: displayName } : base;
    });
  }

  /** List folder and website pieces after resolving the collection's exact scope. */
  async listKnowledgeBaseSources(
    knowledgeBaseId: string,
    query: { page?: number; pageSize?: number },
    identity: Identity,
  ): Promise<KnowledgeBaseSourceListResult> {
    this.requireKnowledgeReadRole(identity);
    const base = await this.getKnowledgeBase(knowledgeBaseId, identity);
    if (base === null) throw new KnowledgeBaseNotFoundError();
    return this.knowledgeBaseSources.list(knowledgeBaseId, { namespace: base.namespace }, query);
  }

  /** Attach a connector-backed piece; namespace and actor always come from identity. */
  async attachKnowledgeBaseSource(
    knowledgeBaseId: string,
    input: Omit<KnowledgeBaseSourceCreateInput, "knowledgeBaseId">,
    identity: Identity,
  ): Promise<KnowledgeBaseSourceSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "knowledge-base-source", "denied", "attach_role");
      throw new AuthzError(`role '${identity.role}' may not add knowledge pieces`);
    }
    const base = await this.getKnowledgeBase(knowledgeBaseId, identity);
    if (base === null) throw new KnowledgeBaseNotFoundError();
    try {
      const created = await this.knowledgeBaseSources.create(
        { ...input, knowledgeBaseId },
        { namespace: base.namespace, actor: identity.actor },
      );
      await this.auditKnowledge(identity, base.namespace, "knowledge-base-source", "ok", `attach_${created.kind}`);
      return created;
    } catch (error) {
      await this.auditKnowledge(identity, base.namespace, "knowledge-base-source", "error", "attach_failed");
      throw error;
    }
  }

  /** Update safe source metadata in a server-resolved exact namespace (D9). */
  async updateSourceMetadata(
    id: string,
    input: KnowledgeBaseSourceMetadata,
    identity: Identity,
  ): Promise<KnowledgeBaseSourceMetadata & { id: string; namespace: Namespace }> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "source-metadata", "denied", "update_role");
      throw new AuthzError(`role '${identity.role}' may not update source metadata`);
    }
    const source = await this.sources.get(id);
    if (source === null) throw new KnowledgeBaseNotFoundError("Source not found");
    if (!isRootOwner(identity) && !isSelfOrDescendant(source.namespace, identity.namespace)) {
      await this.auditKnowledge(identity, identity.namespace, "source-metadata", "denied", "update_scope");
      throw new AuthzError("source is outside the caller scope");
    }
    try {
      const updated = await this.sources.updateMetadata(id, source.namespace, input);
      if (updated === null) throw new KnowledgeBaseNotFoundError("Source not found");
      await this.auditKnowledge(identity, source.namespace, "source-metadata", "ok", "update");
      return updated;
    } catch (error) {
      await this.auditKnowledge(identity, source.namespace, "source-metadata", "error", "update_failed");
      throw error;
    }
  }

  async pauseKnowledgeBase(id: string, identity: Identity): Promise<KnowledgeBaseSummary> {
    return this.changeKnowledgeBaseLifecycle(id, identity, "paused");
  }

  async resumeKnowledgeBase(id: string, identity: Identity): Promise<KnowledgeBaseSummary> {
    return this.changeKnowledgeBaseLifecycle(id, identity, "active");
  }

  async archiveKnowledgeBase(id: string, identity: Identity): Promise<KnowledgeBaseSummary> {
    return this.changeKnowledgeBaseLifecycle(id, identity, "archived");
  }

  /** List content-free file metadata. A selected base supplies its exact namespace. */
  async listCompanyFiles(
    query: CompanyFileListQuery,
    identity: Identity,
  ): Promise<CompanyFileListResult> {
    this.requireKnowledgeReadRole(identity);
    let viewerNamespace = identity.namespace;
    let visibleNamespaces: Namespace[];
    let selectedBase: KnowledgeBaseSummary | null = null;
    if (query.knowledgeBaseId !== undefined) {
      selectedBase = await this.getKnowledgeBase(query.knowledgeBaseId, identity);
      if (selectedBase === null) throw new KnowledgeBaseNotFoundError();
      viewerNamespace = selectedBase.namespace;
      visibleNamespaces = [selectedBase.namespace];
    } else {
      visibleNamespaces = await this.knowledgeBaseVisibleNamespaces(identity);
    }
    const { includeUploads: _includeUploads, ...fileQuery } = query;
    const files = await this.companyFiles.list({
      ...fileQuery,
      viewerNamespace,
      visibleNamespaces,
    });
    if (!query.includeUploads) return files;
    if (selectedBase === null) {
      throw new CompanyFileValidationError(
        "includeUploads requires an exact knowledgeBaseId",
      );
    }
    const uploads = await this.companyFileJobs.listActive(
      selectedBase.id,
      selectedBase.namespace,
    );
    return { ...files, uploads };
  }

  /** ACL-scoped L2 relationship read; no public write surface exists. */
  async listEntityRelationships(
    query: EntityRelationshipListQuery,
    identity: Identity,
  ): Promise<EntityRelationshipListResult> {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "read", memoryId: null, namespace: identity.namespace,
        purpose: "relationship-list", result: "denied", detail: "role_denied",
      });
      throw new AuthzError(`role '${identity.role}' may not list entity relationships`);
    }
    try {
      const result = await this.relationships.list(namespaceAncestors(identity.namespace), query);
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "read", memoryId: null, namespace: identity.namespace,
        purpose: "relationship-list", result: "ok", detail: `count=${result.data.length}`,
      });
      return result;
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "read", memoryId: null, namespace: identity.namespace,
        purpose: "relationship-list", result: "error",
        detail: `code=${error instanceof Error ? error.name : "unknown"}`,
      });
      throw error;
    }
  }

  /**
   * Admit a company file quickly, persist its body as authenticated
   * ciphertext, and return a stable id before extraction starts.
   */
  async submitCompanyFileUpload(
    rawInput: CompanyFileUploadInput,
    identity: Identity,
  ): Promise<CompanyFileUploadAccepted> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "company-file", "denied", "upload_role");
      throw new AuthzError(`role '${identity.role}' may not upload company files`);
    }
    let auditNamespace = identity.namespace;
    try {
      const input = normalizeCompanyFileUpload(rawInput);
      const base = await this.getKnowledgeBase(input.knowledgeBaseId, identity);
      if (base === null || base.kind !== "file" || base.lifecycleState !== "active") {
        throw new CompanyFileConflictError("Knowledge base is unavailable for uploads");
      }
      auditNamespace = base.namespace;
      const bytes = input.contentBase64 === undefined
        ? Buffer.from(input.content ?? "", "utf8")
        : Buffer.from(input.contentBase64, "base64");
      // Local format/size/content validation belongs to admission. No model or
      // embedding call occurs before the durable acknowledgement.
      validateCompanyFileInput({
        fileName: input.fileName,
        content: bytes,
        purpose: input.purpose,
        ...(input.description === "" ? {} : { description: input.description }),
        businessFunction: base.primaryBusinessFunction,
        dataSensitive: base.dataSensitive,
      });
      const contentSha256 = createHash("sha256").update(bytes).digest("hex");
      const requestSha256 = createHash("sha256").update(JSON.stringify({
        version: 1,
        knowledgeBaseId: base.id,
        fileName: input.fileName,
        contentSha256,
        title: input.title ?? readableCompanyFileTitle(input.fileName),
        description: input.description,
        purpose: input.purpose,
      })).digest("hex");
      // One transaction debits file count AND payload bytes: a failed later
      // check can never strand an earlier debit. Without a client key, the
      // request fingerprint keys the reservation, so retrying the exact same
      // upload replays for free instead of burning the allowance again.
      const fileIdempotencyKey = input.idempotencyKey === undefined
        ? `company-file:sha:${requestSha256}`
        : `company-file:client:${input.idempotencyKey}`;
      await this.consumeQuotaMany(identity, [
        { feature: "file_bytes", units: Math.max(1, bytes.byteLength) },
        { feature: "file" },
      ], "write", "company-file-upload", { idempotencyKey: fileIdempotencyKey });
      const tenant = await this.tenants.resolveTenant(base.namespace);
      const uploadLimit = effectiveRateLimit(DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN, tenant) ??
        DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN;
      const accepted = await this.companyFileJobs.enqueue({
        namespace: base.namespace,
        knowledgeBaseId: base.id,
        idempotencyKey: input.idempotencyKey === undefined
          ? `company_attempt_${ulid()}`
          : `company_attempt_client_${input.idempotencyKey}`,
        requestSha256,
        payload: input,
        createdBy: identity.actor,
        rateLimit: {
          bucketKey: `company-file-upload:${identity.keyId}`,
          limit: uploadLimit,
          windowMs: 60_000,
        },
      });
      await this.auditKnowledge(identity, base.namespace, "company-file", "ok", "upload_queued");
      // Give uploads accepted by one browser action a tiny batching window so
      // the worker can claim two and process them concurrently.
      const workerKick = setTimeout(() => {
        void this.runCompanyFileUploadJobsOnce().catch(() => undefined);
      }, COMPANY_FILE_WORKER_BATCH_WINDOW_MS);
      workerKick.unref?.();
      return accepted;
    } catch (error) {
      if (error instanceof CompanyFileRateLimitError) {
        await this.auditKnowledge(identity, auditNamespace, "company-file", "denied", "upload_rate_limit");
        throw new RateLimitError(
          `company file upload rate limit exceeded; retry after ${error.retryAfterSec}s`,
          error.retryAfterSec,
        );
      }
      await this.auditKnowledge(identity, auditNamespace, "company-file", "error", "upload_queue_failed");
      throw error;
    }
  }

  /** Content-free, ACL-scoped state used by the console polling loop. */
  async companyFileUploadStatus(
    uploadId: string,
    identity: Identity,
  ): Promise<CompanyFileUploadStatusResult> {
    if (!["owner", "admin", "auditor"].includes(identity.role)) {
      await this.auditKnowledge(identity, identity.namespace, "company-file", "denied", "status_role_denied");
      throw new AuthzError(`role '${identity.role}' may not view company file uploads`);
    }
    const job = await this.companyFileJobs.get(uploadId);
    const base = job === null ? null : await this.getKnowledgeBase(job.knowledgeBaseId, identity);
    if (job === null || base === null || base.namespace !== job.namespace) {
      await this.auditKnowledge(identity, identity.namespace, "company-file", "error", "status_not_found");
      throw new KnowledgeBaseNotFoundError();
    }
    const file = job.fileId === null
      ? null
      : await this.companyFiles.get(job.fileId, base.namespace);
    await this.auditKnowledge(identity, base.namespace, "company-file", "ok", `status_${job.status}`);
    return {
      uploadId: job.id,
      status: job.status,
      stage: job.stage,
      submittedAt: job.createdAt,
      completedAt: job.completedAt,
      failureCode: job.failureCode,
      file,
    };
  }

  /** Claim and execute a bounded replica-safe batch of accepted file uploads. */
  async runCompanyFileUploadJobsOnce(
    limit = COMPANY_FILE_WORKER_CONCURRENCY,
  ): Promise<{ claimed: number; completed: number }> {
    if (this.companyFileWorker) {
      // A fresh upload arrived during this batch. Drain another bounded batch
      // immediately afterwards instead of waiting for the recovery poll.
      this.companyFileWorkerWake = true;
      return this.companyFileWorker;
    }
    const run = async (): Promise<{ claimed: number; completed: number }> => {
      const jobs = new DurableJobStore(this.db);
      const workerId = `company-file-worker:${process.pid}:${ulid()}`;
      let claimed = 0;
      let completed = 0;
      const processJob = async (job: DurableJob<{ uploadId: string }>): Promise<void> => {
          let currentStage: CompanyFileUploadStage = "queued";
          let stagedByteSize: number | null = null;
          const heartbeat = setInterval(() => {
            void jobs.renew(job.id, workerId, 12 * 60_000).catch(() => undefined);
          }, 60_000);
          heartbeat.unref?.();
          try {
            const staged = await this.companyFileJobs.open(job.payload.uploadId, job.namespace);
            stagedByteSize = staged.input.contentBase64 === undefined
              ? Buffer.byteLength(staged.input.content ?? "", "utf8")
              : Buffer.from(staged.input.contentBase64, "base64").byteLength;
            currentStage = staged.job.stage;
            const onProgress = (stage: Exclude<CompanyFileUploadStage, "queued" | "complete">) => {
              currentStage = stage;
              return this.companyFileJobs.advanceStage(staged.job.id, stage);
            };
            const file = await this.uploadCompanyFile(staged.input, {
              keyId: "halomem:company-file-worker",
              namespace: staged.job.namespace,
              actor: staged.job.createdBy,
              role: "admin",
            }, {
              skipRateLimit: true,
              onProgress,
              uploadId: staged.job.id,
              workerAttempt: job.attempts,
            });
            if (file.status === "processing") {
              throw new Error("company file upload returned a non-terminal result");
            }
            await this.companyFileJobs.complete(
              staged.job.id,
              file.id,
              file.status,
              file.failureCode,
            );
            if (await jobs.complete(job.id, workerId)) completed++;
          } catch (error) {
            const retryable = error instanceof CompanyFileProcessingRetryError ||
              (error instanceof CompanyFileIdempotencyError &&
                error.code === "company_file_upload_processing");
            const terminal = !retryable || job.attempts >= 3;
            const failureCode = error instanceof CompanyFileProcessingRetryError
              ? error.failureCode
              : retryable
              ? "processing_recovery"
              : companyFileWorkerFailureCode(currentStage, error);
            this.logger.warn("company file upload job failed", {
              uploadId: job.payload.uploadId,
              stage: currentStage,
              failureCode,
              errorName: error instanceof Error ? error.name : "unknown",
              stagedByteSize,
              // Validation messages are fixed server-owned copy (never file
              // content), so they are safe and useful operational evidence.
              ...(error instanceof Error && error.name === "CompanyFileValidationError"
                ? { validationReason: error.message }
                : {}),
              // Surface the discarded per-record error reasons: without them
              // every provider/DB/policy failure collapses into a bare stage
              // code and the real cause is unrecoverable from production.
              ...(error instanceof CompanyFileProcessingRetryError &&
                  error.reasons.length > 0
                ? { failureReasons: error.reasons }
                : {}),
            });
            await this.companyFileJobs.fail(job.payload.uploadId, failureCode, terminal);
            await jobs.fail(job.id, workerId, failureCode, terminal ? {} : {
              retryAt: new Date(Date.now() + 30_000).toISOString(),
            });
          } finally {
            clearInterval(heartbeat);
          }
      };
      const concurrency = Math.max(1, Math.min(10, limit));
      do {
        this.companyFileWorkerWake = false;
        // Independent lanes reclaim immediately after a short job finishes.
        // A slow extraction/embedding in one lane therefore cannot strand the
        // remaining accepted uploads behind a batch-wide Promise.all barrier.
        await Promise.all(Array.from({ length: concurrency }, async () => {
          while (true) {
            const job = await jobs.claim<{ uploadId: string }>(workerId, {
              kinds: ["company-file-upload"],
              leaseMs: 12 * 60_000,
            });
            if (!job) return;
            claimed++;
            await processJob(job);
          }
        }));
      } while (this.companyFileWorkerWake);
      return { claimed, completed };
    };
    this.companyFileWorker = run().finally(() => {
      this.companyFileWorker = null;
    });
    return this.companyFileWorker;
  }

  /** Drain optional graph enrichment independently of authoritative uploads. */
  async runRelationshipEnrichmentJobsOnce(
    limit = 1,
  ): Promise<{ claimed: number; completed: number }> {
    if (this.relationshipEnrichmentWorker) return this.relationshipEnrichmentWorker;
    const run = async (): Promise<{ claimed: number; completed: number }> => {
      const jobs = new DurableJobStore(this.db);
      const workerId = `relationship-enrichment-worker:${process.pid}:${ulid()}`;
      let claimed = 0;
      let completed = 0;
      for (let index = 0; index < Math.max(1, Math.min(4, limit)); index++) {
        const job = await jobs.claim<{
          actor: string;
          keyId: string;
          newMemoryIds: string[];
          supersededMemoryIds: string[];
        }>(workerId, {
          kinds: ["relationship-enrichment"],
          leaseMs: 12 * 60_000,
        });
        if (!job) break;
        claimed++;
        const heartbeat = setInterval(() => {
          void jobs.renew(job.id, workerId, 12 * 60_000).catch(() => undefined);
        }, 60_000);
        heartbeat.unref?.();
        try {
          const payload = job.payload;
          if (
            !payload || typeof payload.actor !== "string" ||
            typeof payload.keyId !== "string" ||
            !Array.isArray(payload.newMemoryIds) ||
            !Array.isArray(payload.supersededMemoryIds)
          ) {
            throw new Error("relationship enrichment payload is invalid");
          }
          await this.finalizeRelationshipImpact({
            namespace: job.namespace,
            actor: payload.actor,
            keyId: payload.keyId,
            role: "admin",
          }, {
            memoryIds: new Set(payload.newMemoryIds),
            supersededMemoryIds: new Set(payload.supersededMemoryIds),
            documents: new Map(),
          }, false);
          if (await jobs.complete(job.id, workerId)) completed++;
        } catch (error) {
          await jobs.fail(
            job.id,
            workerId,
            error instanceof Error ? error.name : "relationship_enrichment_failed",
          );
        } finally {
          clearInterval(heartbeat);
        }
      }
      return { claimed, completed };
    };
    this.relationshipEnrichmentWorker = run().finally(() => {
      this.relationshipEnrichmentWorker = null;
    });
    return this.relationshipEnrichmentWorker;
  }

  /**
   * Validate one bounded text file and send it through the canonical D10 write
   * path. Only derived metadata persists; the submitted body dies with this call.
   */
  async uploadCompanyFile(
    rawInput: CompanyFileUploadInput,
    identity: Identity,
    options: {
      skipRateLimit?: boolean;
      onProgress?: (
        stage: Exclude<CompanyFileUploadStage, "queued" | "complete">,
      ) => void | Promise<void>;
      /** Internal durable-job id; enables content-free per-chunk checkpoints. */
      uploadId?: string;
      /** One-based durable claim attempt; exhausted attempts finalize failed. */
      workerAttempt?: number;
    } = {},
  ): Promise<CompanyFileSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "company-file", "denied", "upload_role");
      throw new AuthzError(`role '${identity.role}' may not upload company files`);
    }

    let auditNamespace = identity.namespace;
    try {
      const input = normalizeCompanyFileUpload(rawInput);
      const base = await this.getKnowledgeBase(input.knowledgeBaseId, identity);
      if (base === null || base.kind !== "file") {
        throw new CompanyFileConflictError("Knowledge base is unavailable for uploads");
      }
      auditNamespace = base.namespace;

      const uploadStartedAt = Date.now();
      // contentBase64 carries the caller's original bytes; the legacy text
      // path is re-encoded and therefore cannot guarantee byte fidelity.
      const bytes = input.contentBase64 === undefined
        ? Buffer.from(input.content ?? "", "utf8")
        : Buffer.from(input.contentBase64, "base64");
      await options.onProgress?.("parsing");
      // The content hash anchors byte-true provenance. The separate request
      // hash binds the stable key to every normalized field that can affect
      // the durable result, so metadata changes cannot silently reuse a key.
      const contentSha256 = createHash("sha256").update(bytes).digest("hex");
      const requestTitle = input.title ?? readableCompanyFileTitle(input.fileName);
      const requestSha256 = createHash("sha256").update(JSON.stringify({
        version: 1,
        knowledgeBaseId: base.id,
        fileName: input.fileName,
        contentSha256,
        title: requestTitle,
        description: input.description,
        purpose: input.purpose,
      })).digest("hex");
      const attemptInput = {
        namespace: base.namespace,
        knowledgeBaseId: base.id,
        targetTeamId: base.targetTeamId,
        idempotencyKey: input.idempotencyKey === undefined
          ? `company_attempt_${ulid()}`
          : `company_attempt_client_${input.idempotencyKey}`,
        requestSha256,
        requestedFileCount: 1,
        createdBy: identity.actor,
      };
      const recoverReplay = async (reservation: {
        attempt: CompanyFileUploadAttemptSummary;
        attemptToken: string;
        replayed: boolean;
      } | null): Promise<CompanyFileSummary | null> => {
        if (reservation === null || !reservation.replayed) return null;
        let expired = false;
        if (reservation.attempt.status === "processing") {
          // A client may retry after the worker died. Reconcile an expired
          // lease through the same exact-provenance compensation path used by
          // normal ingestion, then return the stable failed row when present.
          expired = await this.companyFiles.expireAttempt(
            reservation.attempt.id,
            reservation.attemptToken,
            this.companyFileCompensator(identity),
          );
        }
        const priorFile = await this.companyFiles.getByAttempt(
          reservation.attempt.id,
          base.namespace,
        );
        if (priorFile === null) {
          if (reservation.attempt.status === "processing" && !expired) {
            throw new CompanyFileIdempotencyError(
              "company_file_upload_processing",
              "Upload request is already processing",
            );
          }
          throw new CompanyFileIdempotencyError(
            "company_file_upload_unreserved",
            "Previous upload request ended before file reservation",
          );
        }
        if (priorFile.status === "processing") {
          throw new CompanyFileIdempotencyError(
            "company_file_upload_processing",
            "Upload request is still processing",
          );
        }
        this.logger.info("company file upload replayed", {
          fileId: priorFile.id,
          attemptId: reservation.attempt.id,
          outcome: priorFile.status,
          byteSize: bytes.byteLength,
          totalMs: Date.now() - uploadStartedAt,
        });
        await this.auditKnowledge(
          identity,
          base.namespace,
          "company-file",
          priorFile.status === "failed" ? "error" : "ok",
          `upload_replayed_${priorFile.status}`,
        );
        return priorFile;
      };

      // A durable worker retry may resume the exact still-leased attempt and
      // file. Public/synchronous replays retain the old terminal-or-conflict
      // behavior and can never opt into this internal path.
      let resumable: {
        attempt: CompanyFileUploadAttemptSummary;
        attemptToken: string;
        file: CompanyFileSummary | null;
      } | null = null;
      if (input.idempotencyKey !== undefined) {
        const existing = await this.companyFiles.findAttempt(attemptInput);
        if (
          options.uploadId !== undefined &&
          existing?.attempt.status === "processing"
        ) {
          const expired = await this.companyFiles.expireAttempt(
            existing.attempt.id,
            existing.attemptToken,
            this.companyFileCompensator(identity),
          );
          const priorFile = await this.companyFiles.getByAttempt(
            existing.attempt.id,
            base.namespace,
          );
          if (!expired && (priorFile === null || priorFile.status === "processing")) {
            resumable = {
              attempt: existing.attempt,
              attemptToken: existing.attemptToken,
              file: priorFile,
            };
          } else {
            const recovered = await recoverReplay(existing);
            if (recovered !== null) return recovered;
          }
        } else {
          const recovered = await recoverReplay(existing);
          if (recovered !== null) return recovered;
        }
      }
      if (base.lifecycleState !== "active") {
        throw new CompanyFileConflictError("Knowledge base is unavailable for uploads");
      }
      const records = await parseCompanyFileInput({
        fileName: input.fileName,
        content: bytes,
        purpose: input.purpose,
        ...(input.description === "" ? {} : { description: input.description }),
        businessFunction: base.primaryBusinessFunction,
        dataSensitive: base.dataSensitive,
      });
      const parsedAt = Date.now();
      const ingestRecords = records.map((record) => ({
        ...record,
        contentHash: contentSha256,
      }));
      // Chunk ids carry a `#chunk-…` suffix for stable per-record provenance.
      // File metadata must retain the caller's real filename: deriving the
      // media type from a chunk id would turn `guide.docx#chunk-0001-…` into an
      // unsupported extension and fail every chunked binary document.
      const fileName = input.fileName;
      const title = input.title ?? readableCompanyFileTitle(fileName);
      const mediaType = companyFileMediaType(fileName);

      const tenant = await this.tenants.resolveTenant(base.namespace);
      const uploadLimit = effectiveRateLimit(DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN, tenant) ?? DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN;

      // Claim the durable request before rate admission and source creation.
      // This serializes concurrent first deliveries of the same key: the
      // winner proceeds, while the loser reconciles without consuming another
      // rate token or creating a source for a mismatched request.
      let attemptReservation: {
        attempt: CompanyFileUploadAttemptSummary;
        attemptToken: string;
        replayed: boolean;
      } | null = resumable === null
        ? null
        : { ...resumable, replayed: true };
      if (attemptReservation === null) {
        try {
          attemptReservation = await this.companyFiles.reserveAttempt({
            ...attemptInput,
            ...(options.skipRateLimit ? {} : { rateLimit: {
              bucketKey: `company-file-upload:${identity.keyId}`,
              limit: uploadLimit,
              windowMs: 60_000,
            } }),
          });
        } catch (error) {
          if (error instanceof CompanyFileRateLimitError) {
            await this.auditKnowledge(
              identity,
              base.namespace,
              "company-file",
              "denied",
              "upload_rate_limit",
            );
            throw new RateLimitError(
              `company file upload rate limit exceeded; retry after ${error.retryAfterSec}s`,
              error.retryAfterSec,
            );
          }
          throw error;
        }
        const recovered = await recoverReplay(attemptReservation);
        if (recovered !== null) return recovered;
      }
      if (attemptReservation === null) {
        throw new Error("company file attempt reservation is unavailable");
      }
      const { attempt, attemptToken } = attemptReservation;
      const failBeforeFile = async (failureCode: string): Promise<void> => {
        await this.db.query(
          `UPDATE company_file_upload_attempts
              SET status = 'failed', failed_file_count = requested_file_count,
                  failure_code = $3, completed_at = CURRENT_TIMESTAMP
            WHERE id = $1 AND attempt_token = $2 AND status IN ('pending','processing')`,
          [attempt.id, attemptToken, failureCode],
        );
      };

      const sourceKey = createHash("sha256")
        .update(`${base.id}\u0000${contentSha256}`)
        .digest("hex");
      let sourceId: string;
      let file: CompanyFileSummary;
      try {
        if (resumable?.file) {
          sourceId = resumable.file.sourceId;
          file = resumable.file;
        } else {
          const source = await this.sources.register(
            base.namespace,
            "file-upload",
            {
              knowledgeBaseId: base.id,
              fileName,
              mediaType,
              byteSize: bytes.byteLength,
              contentSha256,
            },
            `company_file_${sourceKey}`,
          );
          sourceId = source.id;
          const reservation = await this.companyFiles.reserveFile({
            namespace: base.namespace,
            knowledgeBaseId: base.id,
            sourceId,
            uploadAttemptId: attempt.id,
            attemptToken,
            title,
            description: input.description,
            purpose: input.purpose,
            fileName,
            mediaType,
            byteSize: bytes.byteLength,
            contentSha256,
            createdBy: identity.actor,
            uploadedBy: identity.actor,
          }, this.quota.isEnabled() ? {
            maxFiles: await this.quota.tenantCeiling(base.namespace, "file"),
            maxBytes: await this.quota.tenantCeiling(base.namespace, "file_bytes"),
          } : {});
          file = reservation.file;
        }
      } catch (error) {
        const failureCode = reservationFailureCode(error);
        await failBeforeFile(failureCode);
        throw error;
      }
      const landingIdentity: Identity = { ...identity, namespace: base.namespace };
      const impact = relationshipImpact();
      let latestWriteStage: CompanyFileUploadStage = "extracting";
      let reportedWriteStage: "extracting" | "embedding" | null = null;
      const writeHooks: WritePathHooks = {
        onStage: async (stage) => {
          latestWriteStage = stage === "extraction" ? "extracting" : "embedding";
          if (latestWriteStage === reportedWriteStage) return;
          reportedWriteStage = latestWriteStage;
          await options.onProgress?.(latestWriteStage);
        },
      };
      const writeRecord = await this.ingestWriteRecord(landingIdentity, {
        conflictReview: "all",
      }, impact, writeHooks);
      const destinationPolicy = await this.ingestDestinationPolicy(base.namespace);
      const sink = makeIngestSink({
        namespace: base.namespace,
        sourceId,
        sourceKind: "file-upload",
        writeRecord,
        destinationPolicy,
        onClassificationDenied: this.ingestDenyAudit(landingIdentity, sourceId),
        localBrownoutOnClassificationDenied: true,
        writeFence: {
          kind: "company-document",
          documentId: file.id,
          attemptToken,
        },
        provenanceAttemptToken: attemptToken,
      });
      const compensate = this.companyFileCompensator(identity);
      const heartbeat = setInterval(() => {
        void this.companyFiles.renewLease(attempt.id, attemptToken).catch((error: unknown) => {
          this.logger.warn("company file lease heartbeat failed", {
            fileId: file.id,
            error: error instanceof Error ? error.name : "unknown",
          });
        });
      }, COMPANY_FILE_LEASE_HEARTBEAT_MS);
      heartbeat.unref();
      let result: IngestResult;
      try {
        if (options.uploadId === undefined) {
          result = await runImport(ingestRecords, sink);
        } else {
          const checkpoints = await this.companyFileJobs.ensureChunks(
            options.uploadId,
            ingestRecords.length,
          );
          const completedByIndex = new Map(
            checkpoints
              .filter((checkpoint) => checkpoint.status === "complete")
              .map((checkpoint) => [checkpoint.chunkIndex, checkpoint]),
          );
          result = {
            sourceId,
            records: ingestRecords.length,
            stored: [...completedByIndex.values()].reduce(
              (total, checkpoint) => total + checkpoint.factCount,
              0,
            ),
            deduplicated: 0,
            superseded: 0,
            rejected: 0,
            disputed: 0,
            errors: [],
          };
          for (const [chunkIndex, record] of ingestRecords.entries()) {
            if (completedByIndex.has(chunkIndex)) continue;
            await this.companyFileJobs.startChunk(options.uploadId, chunkIndex);
            const chunk = await runImport([record], sink);
            const chunkFactCount = chunk.stored + chunk.deduplicated + (chunk.disputed ?? 0);
            if (chunk.errors.length > 0 || chunkFactCount === 0) {
              const failureCode = companyFileResultFailureCode(
                latestWriteStage,
                chunk.errors,
              );
              await this.companyFileJobs.failChunk(options.uploadId, chunkIndex, failureCode);
              result.errors.push(...chunk.errors);
              if (chunk.errors.length === 0) {
                result.errors.push({ docId: record.docId, reason: failureCode });
              }
              continue;
            }
            await this.companyFileJobs.completeChunk(
              options.uploadId,
              chunkIndex,
              chunkFactCount,
            );
            result.stored += chunk.stored;
            result.deduplicated += chunk.deduplicated;
            result.superseded += chunk.superseded;
            result.rejected += chunk.rejected;
            result.disputed = (result.disputed ?? 0) + (chunk.disputed ?? 0);
          }
        }
      } finally {
        clearInterval(heartbeat);
      }

      const factCount = result.stored + result.deduplicated + (result.disputed ?? 0);
      const ingestedAt = Date.now();
      if (result.errors.length > 0 || factCount === 0) {
        if (
          options.uploadId !== undefined &&
          (options.workerAttempt ?? 1) < 3
        ) {
          throw new CompanyFileProcessingRetryError(
            latestWriteStage,
            companyFileResultFailureCode(latestWriteStage, result.errors),
            companyFileFailureReasons(result.errors),
          );
        }
        const expired = await this.companyFiles.expireAttempt(
          attempt.id,
          attemptToken,
          compensate,
        );
        let failed: CompanyFileSummary;
        if (expired) {
          const current = await this.companyFiles.get(file.id, base.namespace);
          if (current === null) throw new CompanyFileLeaseExpiredError();
          failed = current;
        } else {
          failed = await this.companyFiles.finalize(
            file.id,
            attemptToken,
            {
              status: "failed",
              factCount: 0,
              failureCode: companyFileResultFailureCode(
                latestWriteStage,
                result.errors,
              ),
            },
            result.errors.length > 0 ? compensate : undefined,
          );
        }
        this.logger.info("company file upload finished", {
          fileId: file.id,
          attemptId: attempt.id,
          outcome: "failed",
          failureCode: failed.failureCode,
          byteSize: bytes.byteLength,
          parseMs: parsedAt - uploadStartedAt,
          ingestMs: ingestedAt - parsedAt,
          totalMs: Date.now() - uploadStartedAt,
          ...(result.errors.length > 0
            ? { failureReasons: companyFileFailureReasons(result.errors) }
            : {}),
        });
        await this.auditKnowledge(identity, base.namespace, "company-file", "error", `upload_${failed.failureCode ?? "failed"}`);
        return failed;
      }

      await options.onProgress?.("finalizing");
      if (options.uploadId !== undefined) {
        const landed = await this.db.query(
          `SELECT id FROM memory_objects
            WHERE namespace = $1 AND status IN ('active','disputed')
              AND t_valid_to IS NULL AND provenance @> $2::jsonb`,
          [base.namespace, JSON.stringify([{ attemptToken }])],
        );
        for (const row of landed.rows) impact.memoryIds.add(String(row.id));
        for (const record of ingestRecords) {
          const key = `${sourceId}\u0000${base.namespace}\u0000${record.docId}`;
          impact.documents.set(key, {
            sourceId,
            namespace: base.namespace,
            documentKey: record.docId,
            contentHash: contentSha256,
          });
        }
      }
      const completed = await this.companyFiles.finalize(file.id, attemptToken, {
        status: (result.disputed ?? 0) > 0 || result.rejected > 0
          ? "needs_review"
          : "ready",
        factCount,
      });
      this.logger.info("company file upload finished", {
        fileId: file.id,
        attemptId: attempt.id,
        outcome: completed.status,
        factCount,
        byteSize: bytes.byteLength,
        parseMs: parsedAt - uploadStartedAt,
        ingestMs: ingestedAt - parsedAt,
        totalMs: Date.now() - uploadStartedAt,
      });
      if (options.uploadId === undefined) {
        await this.finalizeRelationshipImpact(landingIdentity, impact, true);
      } else {
        // Source-document coordinates are authoritative and remain on the
        // upload path. Optional LLM graph enrichment is durable but separate:
        // it cannot keep a ready file stuck in `finalizing` or occupy one of
        // the bounded company-file workers.
        await this.finalizeRelationshipImpact(landingIdentity, {
          memoryIds: new Set(),
          supersededMemoryIds: new Set(),
          documents: impact.documents,
        }, true);
        await this.enqueueRelationshipImpact(
          landingIdentity,
          impact,
          `relationship-enrichment:${options.uploadId}`,
        );
      }
      await this.auditKnowledge(identity, base.namespace, "company-file", "ok", `upload_${completed.status}`);
      return completed;
    } catch (error) {
      await this.auditKnowledge(identity, auditNamespace, "company-file", "error", "upload_failed");
      throw error;
    }
  }

  async archiveCompanyFile(id: string, identity: Identity): Promise<CompanyFileSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "company-file", "denied", "archive_role");
      throw new AuthzError(`role '${identity.role}' may not archive company files`);
    }
    const row = await this.db.query(
      `SELECT f.id, f.namespace FROM company_files f WHERE f.id = $1`,
      [id],
    );
    const namespace = row.rows[0]?.namespace as Namespace | undefined;
    if (
      namespace === undefined ||
      (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace))
    ) {
      throw new KnowledgeBaseNotFoundError();
    }
    const archived = await this.companyFiles.archive(
      id,
      namespace,
      this.companyFileCompensator(identity),
    );
    if (archived === null) throw new KnowledgeBaseNotFoundError();
    this.l1Cache.eraseNamespace(l1CachePartition(namespace));
    await this.warm.afterRetraction();
    await this.auditKnowledge(identity, namespace, "company-file", "ok", "archive");
    return archived;
  }

  /** Paginated policy-file metadata within the caller's administrative subtree. */
  async listPolicyDocuments(
    query: PolicyDocumentListQuery,
    identity: Identity,
  ): Promise<PolicyDocumentListResult> {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      throw new AuthzError(`role '${identity.role}' may not list policy documents`);
    }
    if (query.namespace === "" && !isRootOwner(identity)) {
      throw new AuthzError("only the platform root owner may use the global policy scope");
    }
    if (
      !isRootOwner(identity) &&
      !isSelfOrDescendant(query.namespace, identity.namespace)
    ) {
      throw new AuthzError("policy document scope is outside your namespace subtree");
    }
    return this.policyDocuments.list(query);
  }

  /** Searchable, bounded namespace directory for the policy-library scope picker. */
  async listPolicyDocumentScopes(
    query: { query?: string; limit?: number },
    identity: Identity,
  ): Promise<PolicyDocumentScopeListResult> {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      throw new AuthzError(`role '${identity.role}' may not list policy scopes`);
    }
    return this.policyDocuments.listScopes(identity.namespace, {
      global: isRootOwner(identity),
      ...query,
    });
  }

  /**
   * Policy files that already exist in memory but were never registered.
   *
   * The register was only ever fed by its own upload lane, so a policy file
   * that arrived through a connector or import (D10 — same write path, same
   * provenance) stayed invisible on S4 even though agents could already read
   * its facts. This is the read model behind the "found in memory" lane.
   */
  async listPolicyAdoptionCandidates(
    query: { namespace?: string; limit?: number },
    identity: Identity,
  ): Promise<PolicyAdoptionCandidateListResult> {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      throw new AuthzError(
        `role '${identity.role}' may not list policy adoption candidates`,
      );
    }
    const namespace = query.namespace ?? identity.namespace;
    if (namespace === "" && !isRootOwner(identity)) {
      throw new AuthzError("only the platform root owner may use the global policy scope");
    }
    if (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace)) {
      throw new AuthzError("policy document scope is outside your namespace subtree");
    }
    return this.policyDocuments.listAdoptionCandidates(namespace, {
      global: isRootOwner(identity) && namespace === "",
      ...(query.limit === undefined ? {} : { limit: query.limit }),
    });
  }

  /**
   * Promote a policy file that is already in memory into the register.
   *
   * Nothing is re-ingested: the facts stay exactly as the write path landed
   * them, keeping their original provenance (D10/D7). Adoption only records
   * that this file is a governed policy file, which is what makes it show on
   * S4, ship as a directive through `mem_policy`, and become deletable.
   */
  async adoptPolicyDocument(
    input: PolicyDocumentAdoptInput,
    identity: Identity,
  ): Promise<PolicyDocumentSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      throw new AuthzError(`role '${identity.role}' may not adopt policy documents`);
    }
    if (input === null || typeof input !== "object") {
      throw new PolicyDocumentValidationError("Policy document input is required");
    }
    const namespace = String(input.namespace ?? "");
    if (namespace === "" && !isRootOwner(identity)) {
      throw new AuthzError("only the platform root owner may adopt into the platform root");
    }
    if (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace)) {
      throw new AuthzError("policy document scope is outside your namespace subtree");
    }
    const fileName = String(input.fileName ?? "");
    const sourceId = String(input.sourceId ?? "");
    if (!fileName || !sourceId) {
      throw new PolicyDocumentValidationError(
        "fileName and sourceId identify the file to adopt",
      );
    }

    // Re-derive every durable attribute from canonical provenance rather than
    // trusting the browser: the caller may only name a file, never describe it.
    const landed = await this.policyFileFacts(namespace, sourceId, fileName);
    if (landed.versions.length === 0 || landed.factCount === 0) {
      throw new PolicyDocumentValidationError(
        "that file has no active facts in this scope",
      );
    }

    const adopted = await this.policyDocuments.createAdopted({
      sourceId,
      namespace,
      fileName,
      ...(input.title === undefined ? {} : { title: input.title }),
      ...(input.kind === undefined ? {} : { kind: input.kind }),
      ...(input.enforcement === undefined ? {} : { enforcement: input.enforcement }),
      versions: landed.versions,
      factCount: landed.factCount,
      byteSize: landed.byteSize,
      loadedAt: landed.lastSeenAt,
      createdBy: identity.actor,
    });
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: DEFAULT_AGENT_ID,
      op: "policy_adopt",
      memoryId: null,
      namespace: adopted.namespace,
      purpose: null,
      result: "ok",
      detail: `document=${adopted.id} source=${adopted.sourceId} file=${adopted.fileName} facts=${adopted.factCount}`,
    });
    return adopted;
  }

  /**
   * The landed source-document versions of one file, plus the size and recency
   * of the facts attributable to them. Shared by adoption and its validation.
   */
  private async policyFileFacts(
    namespace: Namespace,
    sourceId: string,
    fileName: string,
  ): Promise<{
    versions: Array<{ documentKey: string; contentHash: string }>;
    factCount: number;
    byteSize: number;
    lastSeenAt: string | null;
  }> {
    const result = await this.db.query(
      `SELECT DISTINCT
              m.id                  AS memory_id,
              p->>'documentKey'     AS document_key,
              p->>'contentHash'     AS content_hash,
              length(m.content)     AS content_length,
              m.assertion_time      AS assertion_time
         FROM memory_objects m
         CROSS JOIN LATERAL jsonb_array_elements(m.provenance) AS p
        WHERE m.namespace = $1
          AND m.status = 'active'
          AND m.t_valid_to IS NULL
          AND p->>'sourceId' = $2
          AND p ? 'contentHash'
          AND (p->>'documentKey' = $3
               OR p->>'documentKey' LIKE $4 ESCAPE '\\')`,
      [namespace, sourceId, fileName, `${escapeLikePattern(fileName)}#%`],
    );
    const versions = new Map<string, string>();
    const facts = new Set<string>();
    let byteSize = 0;
    let lastSeenAt: string | null = null;
    for (const row of result.rows as Array<{
      memory_id: string;
      document_key: string;
      content_hash: string;
      content_length: number | string;
      assertion_time: string | Date | null;
    }>) {
      versions.set(row.document_key, row.content_hash);
      if (!facts.has(row.memory_id)) {
        facts.add(row.memory_id);
        byteSize += Number(row.content_length) || 0;
      }
      if (row.assertion_time !== null) {
        const seen = new Date(row.assertion_time).toISOString();
        if (lastSeenAt === null || seen > lastSeenAt) lastSeenAt = seen;
      }
    }
    return {
      versions: [...versions].map(([documentKey, contentHash]) => ({
        documentKey,
        contentHash,
      })),
      factCount: facts.size,
      byteSize,
      lastSeenAt,
    };
  }

  /**
   * Upload one bounded text policy through the canonical governed write path.
   * The policy_documents row stores operational metadata only; the raw file
   * body is discarded after ingestion and never enters source configuration.
   */
  async uploadPolicyDocument(
    input: PolicyDocumentUploadInput,
    identity: Identity,
  ): Promise<PolicyDocumentSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      throw new AuthzError(`role '${identity.role}' may not upload policy documents`);
    }

    // Validate and derive every file attribute before creating durable state.
    const upload = normalizePolicyDocumentUpload(input);
    if (upload.namespace === "" && !isRootOwner(identity)) {
      throw new AuthzError("only the platform root owner may upload to the platform root");
    }
    if (
      !isRootOwner(identity) &&
      !isSelfOrDescendant(upload.namespace, identity.namespace)
    ) {
      throw new AuthzError("policy document scope is outside your namespace subtree");
    }

    const tenant = await this.tenants.resolveTenant(upload.namespace);
    const uploadLimit = effectiveRateLimit(DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN, tenant) ?? DEFAULT_UPLOAD_RATE_LIMIT_PER_MIN;
    const uploadRate = await this.rateLimiter.consume(
      `policy-upload:${identity.keyId}`,
      uploadLimit,
      60_000,
    );
    if (!uploadRate.allowed) {
      await this.auditPolicyUploadDenied(
        identity,
        upload.namespace,
        "policy_upload_rate_limit",
      );
      throw new RateLimitError(
        `policy upload rate limit exceeded; retry after ${uploadRate.retryAfterSec}s`,
        uploadRate.retryAfterSec,
      );
    }
    const compensateAttempt = async (
      tx: Db,
      attempt: {
        sourceId: string;
        namespace: string;
        fileName: string;
        contentSha256: string;
        attemptToken: string;
      },
    ) => {
      const state = new DbSourceState(
        this.db,
        attempt.sourceId,
        attempt.namespace,
        (db, event) => this.audit.appendTo(db, event),
        identity.actor,
        INGEST_AGENT,
        (db, retiredIds, namespace) =>
          this.warm.enqueueInvalidationsTx(db, retiredIds, namespace),
      );
      await state.retractUncommittedVersionFrom(
        tx,
        attempt.fileName,
        attempt.contentSha256,
        new Date().toISOString(),
        attempt.attemptToken,
      );
    };
    await this.policyDocuments.claimExpiredProcessing(
      upload.namespace,
      upload.contentSha256,
      compensateAttempt,
    );
    try {
      await this.policyDocuments.assertWithinQuota(
        tenantRootOf(upload.namespace),
        upload.byteSize,
      );
    } catch (error) {
      if (error instanceof PolicyDocumentQuotaError) {
        await this.auditPolicyUploadDenied(
          identity,
          upload.namespace,
          "policy_document_quota",
        );
      }
      throw error;
    }

    const landingIdentity: Identity = { ...identity, namespace: upload.namespace };
    const writeRecord = await this.ingestWriteRecord(landingIdentity);
    const destinationPolicy = await this.ingestDestinationPolicy(upload.namespace);
    const source = await this.sources.register(
      upload.namespace,
      "policy-upload",
      {
        title: upload.title,
        kind: upload.kind,
        fileName: upload.fileName,
        mediaType: upload.mediaType,
        byteSize: upload.byteSize,
        contentSha256: upload.contentSha256,
      },
      `policy_${upload.contentSha256}`,
    );
    let attempt;
    try {
      attempt = await this.policyDocuments.createProcessingAttempt({
        sourceId: source.id,
        upload,
        createdBy: identity.actor,
        tenantRoot: tenantRootOf(upload.namespace),
      });
    } catch (error) {
      if (error instanceof PolicyDocumentQuotaError) {
        await this.auditPolicyUploadDenied(
          identity,
          upload.namespace,
          "policy_document_quota",
        );
      }
      throw error;
    }
    const { document, attemptToken } = attempt;
    const sink = makeIngestSink({
      namespace: upload.namespace,
      sourceId: source.id,
      sourceKind: "policy-upload",
      writeRecord,
      destinationPolicy,
      onClassificationDenied: this.ingestDenyAudit(landingIdentity, source.id),
      writeFence: {
        kind: "policy-document",
        documentId: document.id,
        attemptToken,
      },
      provenanceAttemptToken: attemptToken,
    });
    const heartbeat = setInterval(() => {
      void this.policyDocuments
        .renewLease(document.id, attemptToken)
        .catch((error: unknown) => {
          this.logger.warn("policy document lease heartbeat failed", {
            documentId: document.id,
            error: error instanceof Error ? error.name : "unknown",
          });
        });
    }, POLICY_LEASE_HEARTBEAT_MS);
    heartbeat.unref();
    let result: IngestResult;
    try {
      result = await runImport([{
        docId: upload.fileName,
        content: upload.content,
        scope: "org",
        verbatim: false,
      }], sink);
    } finally {
      clearInterval(heartbeat);
    }

    const factCount =
      result.stored +
      result.deduplicated +
      (result.disputed ?? 0);
    const failed =
      result.errors.length > 0 ||
      factCount === 0;
    if (failed) {
      let failedDocument: PolicyDocumentSummary;
      try {
        failedDocument = await this.policyDocuments.markFailed(
          document.id,
          result.errors.length > 0 ? "ingest-failed" : "no-facts-landed",
          attemptToken,
          result.errors.length > 0 ? compensateAttempt : undefined,
        );
      } catch (error) {
        if (!(error instanceof PolicyDocumentConflictError)) throw error;
        const current = await this.policyDocuments.get(document.id);
        if (current?.status !== "failed") throw error;
        failedDocument = current;
      }
      return failedDocument;
    }

    let completedDocument: PolicyDocumentSummary;
    try {
      completedDocument =
        (result.disputed ?? 0) > 0 || result.rejected > 0
          ? await this.policyDocuments.markNeedsReview(
              document.id,
              factCount,
              attemptToken,
            )
          : await this.policyDocuments.markActive(
              document.id,
              factCount,
              attemptToken,
            );
    } catch (error) {
      if (!(error instanceof PolicyDocumentConflictError)) throw error;
      const current = await this.policyDocuments.get(document.id);
      if (current?.status !== "failed") throw error;
      completedDocument = current;
    }
    if (completedDocument.status === "failed") {
      return completedDocument;
    }
    return completedDocument;
  }

  /** Mounted retriever choices for verified setup. No fallback names appear. */
  setupCapabilities(): MountedRetrieverCapability[] {
    return this.setupService.capabilities();
  }

  /** Durable R4C tenant/team setup. Identity is server-resolved (D9). */
  runVerifiedSetup(
    input: SetupInput,
    publicUrl: string,
    identity: Identity,
  ): Promise<SetupResult> {
    return this.setupService.run(input, publicUrl, identity);
  }

  /** Read and refresh the durable setup operation status. */
  setupStatus(operationId: string, identity: Identity): Promise<SetupResult | null> {
    return this.setupService.status(operationId, identity);
  }

  /** Retry the failed first-source sync without resending connector config. */
  resumeVerifiedSetup(operationId: string, identity: Identity): Promise<SetupResult | null> {
    return this.setupService.resume(operationId, identity);
  }

  /** Connector-specific, mutation-free checks run before setup core commits. */
  private async preflightSetupSource(
    source: NonNullable<SetupInput["source"]>,
  ): Promise<void> {
    const connector = this.connectorRegistry.get(source.kind);
    if (!connector) {
      throw new Error(`source preflight failed: no connector for kind '${source.kind}'`);
    }
    const config = source.config ?? {};
    const enterprise = this.connectorRegistry.require(source.kind);
    // A local filesystem mount has no upstream ACL surface: the explicit path
    // chosen by the root owner is itself the namespace-open boundary. Remote
    // connectors without ACL propagation still require an explicit approval.
    if (source.kind !== "filesystem" && !enterprise.capabilities().sourceAcl &&
        config.sourceAccessMode !== "namespace-open") {
      throw new Error(
        `source preflight failed: connector '${source.kind}' requires explicit ` +
        "sourceAccessMode='namespace-open' approval",
      );
    }
    if (source.kind === "filesystem") {
      const path = config.path;
      if (typeof path !== "string" || path.trim().length === 0) {
        throw new Error("source preflight failed: filesystem config.path is required");
      }
      try {
        const info = await stat(path);
        if (!info.isDirectory()) throw new Error("path is not a directory");
        await access(path);
      } catch (err) {
        throw new Error("source preflight failed: filesystem path is not readable");
      }
      await validateConnectorConformance(enterprise, config);
      return;
    }
    // A credential-free postgres setup intentionally introspects HaloMem's own
    // DB through the kernel-injected query surface used by syncSource.
    const availabilityConfig =
      source.kind === "postgres" && !config.dsn && !config.query
        ? { ...config, query: () => this.db.query("SELECT 1") }
        : config;
    await validateConnectorConformance(enterprise, availabilityConfig);
  }

  // -------------------------------------------------------------------------
  // M3 ingestion — D10: imported/connected data enters through the SAME write
  // path as agent conversation (extraction → verification → dedupe →
  // supersedence → provenance). Ingestion is a WRITE: the auditor role is
  // denied, policy is re-resolved per call, and every record goes through
  // performWrite so audit rows + brownout + supersedence all apply. The
  // provenance source (swap-import / document) + sourceId are stamped by the
  // sink, so no imported fact can be mistaken for conversation.
  // -------------------------------------------------------------------------

  /**
   * Bind the ingestion write surface for one source: a `writeRecord` that runs
   * every record through performWrite under the caller's Identity + freshly
   * re-resolved policy, attributed to actor "ingest". Shared by importDump and
   * syncSource so both honour brownout, supersedence, and audit identically.
   */
  private async ingestWriteRecord(
    identity: Identity,
    policyOverrides: Partial<PolicyConfigX> = {},
    relationshipImpact?: IngestRelationshipImpact,
    hooks?: WritePathHooks,
    quotaOptions: { enrollSeat?: boolean } = {},
  ): Promise<(req: WriteRequest) => Promise<WriteResult>> {
    // Ingestion is a write — the auditor role may not write memory (parity
    // with mem_write's role gate). Denied BEFORE any source I/O runs.
    if (identity.role === "auditor") {
      throw new AuthzError("role 'auditor' may not ingest memory");
    }
    // M4: a suspended tenant is a bulk revoke — ingestion is denied like every
    // other syscall. Resolve the owning tenant once and thread it into
    // performWrite so the tenant budget cap also lowers the brownout point.
    const tenant = await this.tenants.resolveTenant(identity.namespace);
    tenantGate(tenant);
    const policy = {
      ...await this.policyStore.getFresh(identity.namespace),
      ...policyOverrides,
    };
    return async (req: WriteRequest) => {
      const contentHash = req.provenance?.contentHash ??
        createHash("sha256").update(req.content, "utf8").digest("hex");
      const meteringKey = createHash("sha256").update(JSON.stringify({
        namespace: identity.namespace,
        sourceId: req.provenance?.sourceId ?? null,
        documentKey: req.provenance?.documentKey ?? null,
        contentHash,
      })).digest("hex");
      await this.consumeQuota(identity, "ingest_bytes", "write", "ingest-bytes", {
        idempotencyKey: `ingest:${meteringKey}`,
        units: Math.max(1, Buffer.byteLength(req.content, "utf8")),
        enrollSeat: quotaOptions.enrollSeat ?? identity.role !== "agent",
      });
      // Cost attribution: every LLM/embed call this write makes (extraction,
      // verification, entity resolution) stamps its ledger rows with the
      // triggering source, so the console can price each connector per team.
      const result = await runWithCostSource(
        req.provenance?.sourceId,
        () => performWrite(this.deps, req, policy, identity, INGEST_AGENT, tenant, hooks),
      );
      if (relationshipImpact) {
        // A DLP-triggered local-only write must not leak its newly landed
        // confidential body into the optional external relationship-enrichment
        // lane. Its source-document provenance still advances below.
        if (!req.hints?.localOnly) {
          for (const stored of result.stored) relationshipImpact.memoryIds.add(stored.id);
          for (const superseded of result.superseded) {
            relationshipImpact.supersededMemoryIds.add(superseded);
          }
        }
        const provenance = req.provenance;
        if (
          provenance?.sourceId &&
          provenance.documentKey &&
          provenance.contentHash
        ) {
          const key = `${provenance.sourceId}\u0000${identity.namespace}\u0000${provenance.documentKey}`;
          relationshipImpact.documents.set(key, {
            sourceId: provenance.sourceId,
            namespace: identity.namespace,
            documentKey: provenance.documentKey,
            contentHash: provenance.contentHash,
          });
        }
      }
      return result;
    };
  }

  /**
   * Optional post-write graph enrichment. The fact transaction has already
   * committed; every failure therefore browns out to a content-free audit row.
   */
  private async finalizeRelationshipImpact(
    identity: Identity,
    impact: IngestRelationshipImpact,
    recordDocuments: boolean,
  ): Promise<void> {
    const hasRelationshipChanges =
      impact.memoryIds.size > 0 || impact.supersededMemoryIds.size > 0;
    if (!hasRelationshipChanges && (!recordDocuments || impact.documents.size === 0)) return;
    try {
      if (recordDocuments) {
        const now = new Date().toISOString();
        for (const document of impact.documents.values()) {
          await this.db.query(
            `INSERT INTO source_documents
               (source_id, landing_namespace, document_key, content_hash, synced_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (source_id, landing_namespace, document_key)
             DO UPDATE SET content_hash = EXCLUDED.content_hash, synced_at = EXCLUDED.synced_at`,
            [
              document.sourceId,
              document.namespace,
              document.documentKey,
              document.contentHash,
              now,
            ],
          );
        }
      }
      if (!hasRelationshipChanges) return;
      const result = await this.relationships.enrich({
        namespace: identity.namespace,
        actor: identity.actor,
        newMemoryIds: [...impact.memoryIds],
        supersededMemoryIds: [...impact.supersededMemoryIds],
      });
      for (const outcome of result.outcomes) {
        await this.audit.append({
          ts: new Date().toISOString(),
          actor: identity.actor,
          agentId: identity.keyId,
          op: "write",
          memoryId: null,
          namespace: identity.namespace,
          purpose: "relationship-enrichment",
          result: outcome.status === "committed" ? "ok" : outcome.status === "rejected" ? "denied" : "error",
          detail: outcome.status === "committed"
            ? `relationship_enrichment candidate=${outcome.candidateId} relationship=${outcome.relationshipId} deduplicated=${outcome.deduplicated ? 1 : 0}`
            : `relationship_enrichment candidate=${outcome.candidateId} code=${outcome.code}`,
        });
      }
      if (result.pipelineError) {
        await this.audit.append({
          ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
          op: "write", memoryId: null, namespace: identity.namespace,
          purpose: "relationship-enrichment", result: "error",
          detail: `relationship_enrichment code=${result.pipelineError}`,
        });
      }
    } catch (error) {
      try {
        await this.audit.append({
          ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
          op: "write", memoryId: null, namespace: identity.namespace,
          purpose: "relationship-enrichment", result: "error",
          detail: `relationship_enrichment code=${error instanceof Error ? error.name : "unknown"}`,
        });
      } catch {
        // Optional graph enrichment and its audit sink never roll back facts.
      }
    }
  }

  /** Persist a content-free graph-enrichment job without weakening fact success. */
  private async enqueueRelationshipImpact(
    identity: Identity,
    impact: IngestRelationshipImpact,
    id: string,
  ): Promise<void> {
    if (impact.memoryIds.size === 0 && impact.supersededMemoryIds.size === 0) return;
    try {
      await new DurableJobStore(this.db).enqueue({
        id,
        kind: "relationship-enrichment",
        namespace: identity.namespace,
        payload: {
          actor: identity.actor,
          keyId: identity.keyId,
          newMemoryIds: [...impact.memoryIds],
          supersededMemoryIds: [...impact.supersededMemoryIds],
        },
      });
    } catch (error) {
      try {
        await this.audit.append({
          ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
          op: "write", memoryId: null, namespace: identity.namespace,
          purpose: "relationship-enrichment", result: "error",
          detail: `relationship_enrichment_enqueue code=${error instanceof Error ? error.name : "unknown"}`,
        });
      } catch {
        // Optional enrichment and its audit sink never roll back facts.
      }
    }
  }

  private async ingestDestinationPolicy(namespace: Namespace): Promise<IngestDestinationPolicy> {
    const policy = await this.policyStore.getFresh(namespace);
    return {
      canonicalDestination: "canonical-l2",
      allowedRestrictedDestinations: policy.restrictedDestinations ?? [],
      ...(policy.dataRegion ? { region: policy.dataRegion } : {}),
    };
  }

  private ingestDenyAudit(identity: Identity, sourceId: string) {
    return (detail: { sensitivity: string; destination: string }) => this.audit.append({
      ts: new Date().toISOString(),
      actor: "ingest",
      agentId: INGEST_AGENT,
      op: "write",
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: "denied",
      detail: `classification_denied sensitivity=${detail.sensitivity} destination=${detail.destination} source=${sourceId}`,
    });
  }

  /**
   * Bulk-import a vendor dump (Mem0 / pgvector) into the caller's namespace.
   * Picks the Importer, parses the raw text to IngestRecords, builds a sink
   * bound to performWrite, runs the batch, and records the source + last_sync.
   * Returns the aggregate IngestResult (stored/deduped/superseded/rejected).
   */
  async importDump(
    kind: SourceKind,
    raw: string,
    identity: Identity,
  ): Promise<IngestResult> {
    const importer: Importer | undefined = IMPORTERS[kind];
    if (!importer) {
      throw new Error(
        `no importer for kind '${kind}' (expected mem0-import | pgvector-import)`,
      );
    }
    const records: IngestRecord[] = importer.parse(raw);
    await this.consumeQuota(identity, "source", "write", "source-import", {
      idempotencyKey: `source-import:${kind}:${ulid()}`,
    });
    const impact = relationshipImpact();
    const writeRecord = await this.ingestWriteRecord(identity, {}, impact);

    // Register the source so provenance.sourceId points at a real row and the
    // import is auditable ("what do we know and where from").
    const source = await this.sources.register(identity.namespace, kind, {
      bytes: raw.length,
    });

    const sink = makeIngestSink({
      namespace: identity.namespace,
      sourceId: source.id,
      sourceKind: kind,
      writeRecord,
      destinationPolicy: await this.ingestDestinationPolicy(identity.namespace),
      onClassificationDenied: this.ingestDenyAudit(identity, source.id),
    });
    const result = await runImport(records, sink);

    await this.sources.touchLastSync(source.id, new Date().toISOString());
    await this.finalizeRelationshipImpact(identity, impact, true);
    return result;
  }

  private auditPolicyUploadDenied(
    identity: Identity,
    namespace: Namespace,
    reason: string,
  ): Promise<void> {
    return this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: INGEST_AGENT,
      op: "write",
      memoryId: null,
      namespace,
      purpose: "policy-upload",
      result: "denied",
      detail: reason,
    });
  }

  private requireKnowledgeReadRole(identity: Identity): void {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor" &&
      identity.role !== "member" &&
      identity.channelAssistant !== true
    ) {
      throw new AuthzError(`role '${identity.role}' may not read knowledge bases`);
    }
  }

  private async knowledgeBaseVisibleNamespaces(identity: Identity): Promise<Namespace[]> {
    if (isRootOwner(identity)) {
      const all = await this.db.query(
        `SELECT DISTINCT namespace FROM knowledge_bases ORDER BY namespace`,
      );
      return all.rows.map((row) => String(row.namespace) as Namespace);
    }
    if (identity.namespace === "") return [];
    if (identity.channelAssistant === true) {
      const descendantRows = await this.db.query(
        `SELECT DISTINCT namespace FROM knowledge_bases
          WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
          ORDER BY namespace`,
        [identity.namespace, `${escapeLikePattern(identity.namespace)}/%`],
      );
      return [...new Set([
        ...namespaceAncestors(identity.namespace),
        ...descendantRows.rows.map((row) => String(row.namespace) as Namespace),
      ])];
    }
    // D56/D57: a member consumes organization-shared metadata plus the exact
    // home-team projection. Unlike governance roles, members never read down
    // into descendant teams. Exact IN-list matching downstream also makes `%`,
    // `_`, and backslash literal namespace characters rather than wildcards.
    if (identity.role === "member") return namespaceAncestors(identity.namespace);
    const descendantRows = await this.db.query(
      `SELECT DISTINCT namespace FROM knowledge_bases
        WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
        ORDER BY namespace`,
      [identity.namespace, `${escapeLikePattern(identity.namespace)}/%`],
    );
    return [...new Set([
      ...namespaceAncestors(identity.namespace),
      ...descendantRows.rows.map((row) => String(row.namespace) as Namespace),
    ])];
  }

  private async resolveKnowledgeBaseTarget(
    targetTeamId: string | null,
    identity: Identity,
  ): Promise<{ namespace: Namespace; targetTeamId: string | null }> {
    if (targetTeamId === null) {
      if (identity.namespace === "") {
        throw new AuthzError("A company knowledge base requires an organization or team scope");
      }
      return { namespace: identity.namespace, targetTeamId: null };
    }
    const namespace = await this.resolveTeamNamespace(
      targetTeamId,
      identity,
      () => new KnowledgeBaseNotFoundError("Target team not found"),
    );
    return { namespace, targetTeamId };
  }

  /**
   * Resolve a team id to its namespace, enforcing the placement rule shared by
   * knowledge bases and backend sources: the target team's namespace must sit
   * inside the caller's administrative subtree. Root admins reach every team;
   * a team admin only their own team (and sub-teams). The namespace is always
   * derived server-side from org_teams — never accepted from a request body
   * (D9).
   */
  private async resolveTeamNamespace(
    targetTeamId: string,
    identity: Identity,
    notFound: () => Error,
  ): Promise<Namespace> {
    const team = await this.db.query(
      `SELECT id, namespace FROM org_teams WHERE id = $1`,
      [targetTeamId],
    );
    if (team.rows.length !== 1) throw notFound();
    const namespace = String(team.rows[0]!.namespace) as Namespace;
    if (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace)) {
      throw new AuthzError("Target team is outside your administrative subtree");
    }
    return namespace;
  }

  /**
   * Resolve mandatory backend placement without trusting a caller namespace.
   * Organization/root administrators must select one active team; team-scoped
   * identities are pinned to their exact namespace and may not target a child.
   */
  private async resolveBackendSourceNamespace(
    targetTeamId: string | null | undefined,
    identity: Identity,
  ): Promise<Namespace> {
    const isTeamIdentity = identity.namespace.split("/").filter(Boolean).length >= 2;
    if (!targetTeamId) {
      if (!isTeamIdentity) {
        throw new Error("Every backend source must be assigned to a team");
      }
      const ownTeam = await this.db.query(
        `SELECT id FROM org_teams WHERE namespace = $1 AND archived_at IS NULL`,
        [identity.namespace],
      );
      if (ownTeam.rows.length !== 1) {
        throw new AuthzError("Your active team could not be resolved");
      }
      return identity.namespace;
    }
    const team = await this.db.query(
      `SELECT id, namespace FROM org_teams WHERE id = $1 AND archived_at IS NULL`,
      [targetTeamId],
    );
    if (team.rows.length !== 1) throw new Error(`no active team with id '${targetTeamId}'`);
    const namespace = String(team.rows[0]!.namespace) as Namespace;
    if (isTeamIdentity && namespace !== identity.namespace) {
      throw new AuthzError("Team administrators may connect sources only to their own team");
    }
    if (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace)) {
      throw new AuthzError("Target team is outside your administrative subtree");
    }
    return namespace;
  }

  private async resolveAuditedBackendSourceNamespace(
    targetTeamId: string | null | undefined,
    identity: Identity,
  ): Promise<Namespace> {
    try {
      return await this.resolveBackendSourceNamespace(targetTeamId, identity);
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "source-connect",
        result: "denied",
        detail: "target_team_denied",
      });
      throw error;
    }
  }

  private async changeKnowledgeBaseLifecycle(
    id: string,
    identity: Identity,
    next: "active" | "paused" | "archived",
  ): Promise<KnowledgeBaseSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      await this.auditKnowledge(identity, identity.namespace, "knowledge-base", "denied", `${next}_role`);
      throw new AuthzError(`role '${identity.role}' may not change knowledge bases`);
    }
    let namespace = identity.namespace;
    try {
      const base = await this.getKnowledgeBase(id, identity);
      if (base === null) throw new KnowledgeBaseNotFoundError();
      namespace = base.namespace;
      const context = { namespace: base.namespace, actor: identity.actor };

      if (next === "paused") {
        const paused = await this.knowledgeBases.pause(id, context);
        if (base.sourceId !== null) await this.sources.pause(base.sourceId);
        await this.auditKnowledge(identity, base.namespace, "knowledge-base", "ok", "pause");
        return paused;
      }
      if (next === "active") {
        const resumed = await this.knowledgeBases.resume(id, context);
        if (base.sourceId !== null) await this.sources.resume(base.sourceId);
        await this.auditKnowledge(identity, base.namespace, "knowledge-base", "ok", "resume");
        return resumed;
      }
      if (base.lifecycleState === "archived") return base;

      // Pause first to close the admission gate before retiring attributable data.
      if (base.lifecycleState === "active") await this.knowledgeBases.pause(id, context);
      const attachedSourceIds = await this.knowledgeBaseSources.archiveForKnowledgeBase(
        base.id,
        context,
      );
      if (base.kind === "file") {
        const files = await this.db.query(
          `SELECT id FROM company_files
            WHERE knowledge_base_id = $1 AND lifecycle_state = 'active'
            ORDER BY created_at, id`,
          [base.id],
        );
        for (const row of files.rows) {
          await this.companyFiles.archive(
            String(row.id),
            base.namespace,
            this.companyFileCompensator(identity),
          );
        }
      }
      if (base.sourceId !== null) attachedSourceIds.push(base.sourceId);
      for (const sourceId of [...new Set(attachedSourceIds)]) {
        const shared = await this.db.query(
          `SELECT 1 FROM knowledge_sources attachment
            JOIN knowledge_bases collection ON collection.id = attachment.knowledge_base_id
           WHERE attachment.source_id = $1
             AND attachment.status <> 'archived' AND attachment.t_valid_to IS NULL
             AND collection.lifecycle_state <> 'archived' AND collection.t_valid_to IS NULL
           UNION ALL
           SELECT 1 FROM knowledge_bases
            WHERE source_id = $1 AND id <> $2
              AND lifecycle_state <> 'archived' AND t_valid_to IS NULL
           LIMIT 1`,
          [sourceId, base.id],
        );
        if (shared.rows.length > 0) continue;
        const source = await this.sources.get(sourceId);
        if (source === null) continue;
        await this.disconnectSource(source, identity);
      }
      const archived = await this.knowledgeBases.archive(id, context);
      this.l1Cache.eraseNamespace(l1CachePartition(base.namespace));
      await this.warm.afterRetraction();
      await this.auditKnowledge(identity, base.namespace, "knowledge-base", "ok", "archive");
      return archived;
    } catch (error) {
      await this.auditKnowledge(identity, namespace, "knowledge-base", "error", `${next}_failed`);
      throw error;
    }
  }

  private companyFileCompensator(identity: Identity): CompanyFileCompensator {
    return async (tx, exact) => {
      const state = new DbSourceState(
        this.db,
        exact.sourceId,
        exact.namespace,
        (db, event) => this.audit.appendTo(db, event),
        identity.actor,
        INGEST_AGENT,
        (db, retiredIds, namespace) =>
          this.warm.enqueueInvalidationsTx(db, retiredIds, namespace),
      );
      await state.retractUncommittedVersionFrom(
        tx,
        exact.documentKey,
        exact.contentHash,
        new Date().toISOString(),
        exact.attemptToken,
      );
    };
  }

  private auditKnowledge(
    identity: Identity,
    namespace: Namespace,
    purpose: "knowledge-base" | "knowledge-base-source" | "company-file" | "source-metadata",
    result: "ok" | "denied" | "error",
    detail: string,
  ): Promise<void> {
    return this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: INGEST_AGENT,
      op: "write",
      memoryId: null,
      namespace,
      purpose,
      result,
      detail,
    });
  }

  private async sourceConnectorConfig(
    kind: SourceKind,
    config: Record<string, unknown>,
    namespace: Namespace,
  ): Promise<Record<string, unknown>> {
    void kind;
    void namespace;
    for (const key of ["credentialId", "nangoIntegrationId", "nangoConnectionId"]) {
      if (Object.prototype.hasOwnProperty.call(config, key)) {
        throw new Error(
          `managed connection field '${key}' is unavailable in the standalone build`,
        );
      }
    }
    return { ...config };
  }

  /**
   * Register a scheduled source connector (filesystem / postgres / notion /
   * slack) for the caller's namespace without syncing it. Returns the row.
   */
  async registerSource(
    kind: SourceKind,
    config: Record<string, unknown>,
    identity: Identity,
    idempotencyKey?: string,
    targetTeamId?: string | null,
  ): Promise<SourceRow> {
    if (identity.role === "auditor") {
      throw new AuthzError("role 'auditor' may not register sources");
    }
    const namespace = await this.resolveAuditedBackendSourceNamespace(targetTeamId, identity);
    return this.registerSourceInNamespace(kind, config, identity, idempotencyKey, namespace);
  }

  private async registerSourceInNamespace(
    kind: SourceKind,
    config: Record<string, unknown>,
    identity: Identity,
    idempotencyKey: string | undefined,
    namespace: Namespace,
  ): Promise<SourceRow> {
    if (identity.role === "auditor") {
      throw new AuthzError("role 'auditor' may not register sources");
    }
    if (idempotencyKey) {
      const existing = await this.sources.getByIdempotencyKey(namespace, idempotencyKey);
      if (existing) {
        if (existing.kind !== kind) {
          throw new Error("source idempotency key is already bound to another connector");
        }
        return existing;
      }
    }
    const connector = this.connectorRegistry.require(kind);
    const resolvedConfig = await this.sourceConnectorConfig(kind, config, namespace);
    const testConfig = kind === "postgres" && !resolvedConfig.query && !resolvedConfig.dsn
      ? { ...resolvedConfig, query: (sql: string, params?: unknown[]) => this.db.query(sql, params) }
      : resolvedConfig;
    await connector.validateConfig(testConfig);
    await this.consumeQuota(identity, "source", "write", "source-register", {
      idempotencyKey: idempotencyKey ?? `source-register:${ulid()}`,
    });
    const source = await this.sources.register(namespace, kind, config, idempotencyKey);
    const stagedIngress = isStagedSourceKind(kind);
    if (!stagedIngress) {
      await new DurableJobStore(this.db).enqueue({
        id: `source-sync:${source.id}:${ulid()}`,
        kind: "source-sync",
        namespace: source.namespace,
        payload: { sourceId: source.id },
      });
    }
    return source;
  }

  /** Enterprise connect flow: conformance + live connection test before registration. */
  async connectSource(
    kind: SourceKind,
    config: Record<string, unknown>,
    identity: Identity,
    idempotencyKey?: string,
    targetTeamId?: string | null,
  ): Promise<SourceRow> {
    if (identity.role === "auditor") {
      throw new AuthzError("role 'auditor' may not register sources");
    }
    const connector = this.connectorRegistry.require(kind);
    const namespace = await this.resolveAuditedBackendSourceNamespace(targetTeamId, identity);
    const resolvedConfig = await this.sourceConnectorConfig(kind, config, namespace);
    if (!connector.capabilities().sourceAcl && resolvedConfig.sourceAccessMode !== "namespace-open") {
      throw new Error(
        `connector '${kind}' cannot prove source ACLs; set sourceAccessMode='namespace-open' ` +
        "only after approving namespace-wide visibility",
      );
    }
    const testConfig = kind === "postgres" && !resolvedConfig.query && !resolvedConfig.dsn
      ? { ...resolvedConfig, query: (sql: string, params?: unknown[]) => this.db.query(sql, params) }
      : resolvedConfig;
    await validateConnectorConformance(connector, testConfig);
    return this.registerSourceInNamespace(kind, config, identity, idempotencyKey, namespace);
  }

  /**
   * Create a local-vault pairing. The generated HMAC secret is returned once
   * and is otherwise retained only inside the source's encrypted config.
   */
  async pairObsidianSource(
    input: {
      vaultName: string;
      includedFolders: string[];
      excludedFolders: string[];
      sourceAccessMode: "namespace-open";
      targetTeamId?: string | null;
    },
    identity: Identity,
  ): Promise<{
    source: SourceRow;
    pairing: {
      version: 1;
      sourceId: string;
      path: string;
      secret: string;
      includedFolders: string[];
      excludedFolders: string[];
    };
  }> {
    let auditNamespace = identity.namespace;
    const auditPairing = async (
      result: "ok" | "denied" | "error",
      sourceId: string | null,
    ): Promise<void> => {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: auditNamespace,
        purpose: "obsidian-pairing",
        result,
        detail: sourceId
          ? `obsidian pairing source=${sourceId}`
          : "obsidian pairing rejected",
      });
    };
    try {
      if (identity.role !== "owner" && identity.role !== "admin") {
        throw new AuthzError("only an owner or admin may pair an Obsidian vault");
      }
      if (input.sourceAccessMode !== "namespace-open") {
        throw new Error(
          "Obsidian pairing requires explicit sourceAccessMode='namespace-open' approval",
        );
      }
      const signingSecret = randomBytes(32).toString("base64url");
      const includedFolders = [...input.includedFolders];
      const excludedFolders = [...input.excludedFolders];
      const source = await this.connectSource(
        "obsidian_vault",
        {
          signingSecret,
          vaultName: input.vaultName,
          includedFolders,
          excludedFolders,
          sourceAccessMode: input.sourceAccessMode,
        },
        identity,
        undefined,
        input.targetTeamId ?? null,
      );
      auditNamespace = source.namespace;
      await auditPairing("ok", source.id);
      return {
        source,
        pairing: {
          version: 1,
          sourceId: source.id,
          path: `/v1/ingest/obsidian/${encodeURIComponent(source.id)}`,
          secret: signingSecret,
          includedFolders,
          excludedFolders,
        },
      };
    } catch (error) {
      const denied = error instanceof AuthzError ||
        (error instanceof Error && /assigned to a team|active team|own team/i.test(error.message));
      await auditPairing(denied ? "denied" : "error", null);
      throw error;
    }
  }

  private async manageableSource(sourceId: string, identity: Identity): Promise<SourceRow> {
    const source = await this.sources.get(sourceId);
    if (!source) throw new Error(`no source with id '${sourceId}'`);
    const allowed = isRootOwner(identity) ||
      ((identity.role === "owner" || identity.role === "admin") &&
        isSelfOrDescendant(source.namespace, identity.namespace));
    if (!allowed) throw new AuthzError(`denied: source '${sourceId}' is outside your namespace subtree`);
    if (source.kind === "policy-upload" || source.kind === "file-upload") {
      throw new AuthzError(
        `source '${sourceId}' is managed by a document library and has no connector lifecycle`,
      );
    }
    return source;
  }

  async testSource(sourceId: string, identity: Identity): Promise<{ ok: boolean; detail?: string }> {
    const source = await this.manageableSource(sourceId, identity);
    const connector = this.connectorRegistry.require(source.kind);
    const resolvedConfig = await this.sourceConnectorConfig(
      source.kind,
      source.config,
      source.namespace,
    );
    const config = source.kind === "postgres" && !resolvedConfig.query && !resolvedConfig.dsn
      ? { ...resolvedConfig, query: (sql: string, params?: unknown[]) => this.db.query(sql, params) }
      : resolvedConfig;
    await connector.validateConfig(config);
    return connector.testConnection(config);
  }

  async pauseSource(sourceId: string, identity: Identity): Promise<SourceRow> {
    const source = await this.manageableSource(sourceId, identity);
    await this.disconnectSource(source, identity);
    return (await this.sources.getRedacted(sourceId))!;
  }

  private async disconnectSource(source: SourceRow, identity: Identity): Promise<void> {
    await this.sources.pause(source.id);
    await new DurableJobStore(this.db).cancelSourceSync(source.id);
    await this.retireSourceMemory(source, identity);
  }

  private async retireSourceMemory(source: SourceRow, identity: Identity): Promise<void> {
    const attributable = JSON.stringify([{ sourceId: source.id }]);
    const namespaces = await this.db.query(
      `SELECT DISTINCT landing_namespace AS namespace
         FROM source_documents
        WHERE source_id = $1
       UNION
       SELECT DISTINCT namespace
         FROM memory_objects
        WHERE provenance @> $2::jsonb`,
      [source.id, attributable],
    );
    for (const row of namespaces.rows) {
      const namespace = String(row.namespace) as Namespace;
      const state = new DbSourceState(
        this.db,
        source.id,
        namespace,
        (db, event) => this.audit.appendTo(db, event),
        identity.actor,
        INGEST_AGENT,
        (db, retiredIds, retiredNamespace) =>
          this.warm.enqueueInvalidationsTx(db, retiredIds, retiredNamespace),
      );
      const retired = await state.retireSource();
      if (retired.length > 0) {
        this.l1Cache.eraseNamespace(l1CachePartition(namespace));
      }
    }
    await this.warm.afterRetraction();
  }

  async resumeSource(sourceId: string, identity: Identity): Promise<SourceRow> {
    const source = await this.manageableSource(sourceId, identity);
    await this.testSource(sourceId, identity);
    await this.sources.resume(sourceId);
    const jobs = new DurableJobStore(this.db);
    await jobs.cancelSourceSync(sourceId);
    const stagedIngress = isStagedSourceKind(source.kind);
    if (!stagedIngress) {
      await jobs.enqueue({
        id: `source-sync:${sourceId}:${ulid()}`,
        kind: "source-sync",
        namespace: source.namespace,
        payload: { sourceId },
      });
    }
    return (await this.sources.getRedacted(sourceId))!;
  }

  async scheduleSource(
    sourceId: string,
    intervalSeconds: number | null,
    identity: Identity,
  ): Promise<SourceRow> {
    const manageable = await this.manageableSource(sourceId, identity);
    if (intervalSeconds !== null && isStagedSourceKind(manageable.kind)) {
      throw new Error(`source '${sourceId}' receives pushed or manual records and cannot be scheduled`);
    }
    await this.sources.setSchedule(sourceId, intervalSeconds);
    const jobs = new DurableJobStore(this.db);
    await jobs.cancelSourceSync(sourceId);
    const source = (await this.sources.get(sourceId))!;
    if (intervalSeconds !== null && source.nextSyncAt) {
      await jobs.enqueue({
        id: `source-sync:${source.id}:${source.nextSyncAt}`,
        kind: "source-sync",
        namespace: source.namespace,
        payload: { sourceId: source.id },
        availableAt: source.nextSyncAt,
      });
    }
    return (await this.sources.getRedacted(sourceId))!;
  }

  private async resolveSourceSyncTarget(sourceId: string, identity: Identity) {
    const source = await this.sources.get(sourceId);
    if (!source) throw new Error(`no source with id '${sourceId}'`);
    if (source.kind === "policy-upload" || source.kind === "file-upload") {
      throw new AuthzError(
        `source '${sourceId}' is managed by a document library and cannot be synced`,
      );
    }
    if (source.lifecycleState !== "active") {
      throw new Error(`source '${sourceId}' is ${source.lifecycleState}`);
    }

    const sourceIsAncestor = namespaceAncestors(identity.namespace).includes(source.namespace);
    const sourceIsDescendant = isSelfOrDescendant(source.namespace, identity.namespace);
    const canManageDescendant =
      (identity.role === "owner" || identity.role === "admin" ||
        identity.channelAssistant === true) && sourceIsDescendant;
    if (!isRootOwner(identity) && !sourceIsAncestor && !canManageDescendant) {
      throw new AuthzError(
        `denied: source '${sourceId}' is outside your namespace subtree`,
      );
    }

    const landingNamespace =
      isRootOwner(identity) || canManageDescendant
        ? source.namespace
        : identity.namespace;
    return { source, landingNamespace };
  }

  /**
   * Accept a manual sync without binding the caller's HTTP request to the
   * connector runtime. An existing queued job is promoted to run now and an
   * existing running job is reused, so repeated button presses do not fan out.
   */
  async requestSourceSync(
    sourceId: string,
    identity: Identity,
  ): Promise<{ accepted: true; jobId: string; status: "queued" | "running" }> {
    const { source, landingNamespace } = await this.resolveSourceSyncTarget(sourceId, identity);
    const now = new Date().toISOString();
    const active = await this.db.query(
      `UPDATE durable_jobs
          SET available_at = CASE WHEN state = 'queued' THEN $3 ELSE available_at END,
              updated_at = $3
        WHERE id = (
          SELECT id FROM durable_jobs
           WHERE kind = 'source-sync'
             AND namespace = $2
             AND payload->>'sourceId' = $1
             AND state IN ('queued', 'running')
           ORDER BY CASE WHEN state = 'running' THEN 0 ELSE 1 END, available_at, created_at
           LIMIT 1
        )
        RETURNING id, state`,
      [source.id, landingNamespace, now],
    );
    const existing = active.rows[0] as {
      id: string;
      state: "queued" | "running";
    } | undefined;
    const newJobId = `source-sync:manual:${source.id}:${ulid()}`;
    if (existing === undefined) {
      await this.consumeQuota(identity, "source_sync", "write", "source-sync", {
        idempotencyKey: newJobId,
      });
    }
    const job = existing ?? await new DurableJobStore(this.db).enqueue({
      id: newJobId,
      kind: "source-sync",
      namespace: landingNamespace,
      payload: { sourceId: source.id },
      availableAt: now,
    });
    const status = job.state === "running" ? "running" : "queued";

    try {
      await this.sources.markSyncPending(source.id, now);
    } catch (error) {
      this.logger.warn("source sync queued but pending status update browned out", {
        sourceId: source.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    void this.runConnectorJobsOnce(1).catch(() => undefined);
    return { accepted: true, jobId: job.id, status };
  }

  /** Claim and execute a bounded replica-safe batch of scheduled connector syncs. */
  async runConnectorJobsOnce(limit = 10): Promise<{ claimed: number; completed: number }> {
    const jobs = new DurableJobStore(this.db);
    const workerId = `connector-worker:${process.pid}:${ulid()}`;
    let claimed = 0;
    let completed = 0;
    for (let i = 0; i < Math.max(1, Math.min(100, limit)); i++) {
      const job = await jobs.claim<{ sourceId: string }>(workerId, {
        kinds: ["source-sync"], leaseMs: 60_000,
      });
      if (!job) break;
      claimed++;
      const heartbeat = setInterval(() => {
        void jobs.renew(job.id, workerId, 60_000).catch(() => undefined);
      }, 20_000);
      heartbeat.unref?.();
      try {
        const scheduledSource = await this.sources.get(job.payload.sourceId);
        if (
          !scheduledSource ||
          scheduledSource.lifecycleState !== "active" ||
          scheduledSource.kind === "policy-upload" ||
          scheduledSource.kind === "file-upload"
        ) {
          if (await jobs.complete(job.id, workerId)) completed++;
          continue;
        }
        const workerIdentity: Identity = {
          keyId: "halomem:connector-worker",
          namespace: job.namespace,
          actor: "halomem-connector-worker",
          role: "admin",
        };
        await this.consumeQuota(
          workerIdentity,
          "source_sync",
          "write",
          "source-sync",
          { idempotencyKey: job.id, enrollSeat: false },
        );
        const syncResult = await this.syncSource(job.payload.sourceId, workerIdentity);
        const refreshed = await this.sources.get(job.payload.sourceId);
        if (!syncResult.continuation &&
            refreshed?.lifecycleState === "active" && refreshed.nextSyncAt) {
          await jobs.enqueue({
            id: `source-sync:${refreshed.id}:${refreshed.nextSyncAt}`,
            kind: "source-sync",
            namespace: refreshed.namespace,
            payload: { sourceId: refreshed.id },
            availableAt: refreshed.nextSyncAt,
          });
        }
        if (await jobs.complete(job.id, workerId)) completed++;
      } catch (error) {
        if (error instanceof QuotaLimitError) {
          await this.sources.markSyncFailed(
            job.payload.sourceId,
            `early-access-${error.code}`,
          ).catch(() => undefined);
          await jobs.fail(job.id, workerId, `early-access-${error.code}`);
          continue;
        }
        const delay = Math.min(3_600_000, 60_000 * 2 ** Math.min(job.attempts, 6));
        await jobs.fail(job.id, workerId, "connector-sync-failed", {
          retryAt: new Date(Date.now() + delay).toISOString(),
        });
      } finally {
        clearInterval(heartbeat);
      }
    }
    return { claimed, completed };
  }

  /**
   * Sync a registered source: build a ConnectorContext (sink + DbSourceState +
   * the stored config), run the connector's drift-aware sync, persist last_sync,
   * and return the SyncResult. For the credential-free postgres case the kernel
   * injects `config.query = db.query` so the connector introspects the SAME
   * database through the injected query surface (never a raw Db handle — D10).
   */
  async syncSource(sourceId: string, identity: Identity): Promise<SyncResult> {
    return this.syncSourceWithOverrides(sourceId, identity);
  }

  /** Only authenticated kernel-owned ingress may add ephemeral connector config. */
  private async syncSourceWithOverrides(
    sourceId: string,
    identity: Identity,
    configOverrides: Readonly<Record<string, unknown>> = {},
  ): Promise<SyncResult> {
    const { source, landingNamespace } =
      await this.resolveSourceSyncTarget(sourceId, identity);

    const connector = this.connectorRegistry.require(source.kind);

    const landingIdentity: Identity = { ...identity, namespace: landingNamespace };
    const impact = relationshipImpact();
    const writeRecord = await this.ingestWriteRecord(
      landingIdentity,
      {},
      impact,
      undefined,
      { enrollSeat: false },
    );
    const sink = makeIngestSink({
      namespace: landingNamespace,
      sourceId: source.id,
      sourceKind: source.kind,
      writeRecord,
      destinationPolicy: await this.ingestDestinationPolicy(landingNamespace),
      onClassificationDenied: this.ingestDenyAudit(landingIdentity, source.id),
      // Brownout, never hard-fail. A record the DLP layer refuses to send to
      // the LLM extractor (an email address in a ticket makes the whole
      // document 'confidential') lands verbatim and local-only instead of
      // throwing: the content is preserved, the classified text still never
      // reaches the model or embedding provider, and the denial is audited.
      // Without this ONE such record failed an otherwise complete sync and
      // the source stayed 'failed' forever. This mirrors the company-file
      // upload path, which has always degraded this way.
      localBrownoutOnClassificationDenied: true,
      writeFence: { kind: "source-active", sourceId: source.id },
    });

    // The postgres connector's source-query surface is a kernel-injected query
    // fn: for the credential-free case (no external DSN) wire our OWN Db.query
    // in. An explicit config.dsn/query is left untouched (external DSN path).
    const config = await this.sourceConnectorConfig(
      source.kind,
      source.config,
      source.namespace,
    );
    Object.assign(config, configOverrides);
    if (source.kind === "postgres" && !config.query && !config.dsn) {
      config.query = (sql: string, params?: unknown[]) => this.db.query(sql, params);
    }

    const ctx = {
      sink,
      // Drift state is scoped to (source.id, actual landing namespace).
      state: new DbSourceState(
        this.db,
        source.id,
        landingNamespace,
        (tx, event) => this.audit.appendTo(tx, event),
        identity.actor,
        identity.keyId,
        (tx, retiredIds, namespace) =>
          this.warm.enqueueInvalidationsTx(tx, retiredIds, namespace),
      ),
      config,
    };
    await this.sources.markSyncPending(source.id, new Date().toISOString());
    try {
      const priorCursor = connector.capabilities().incremental
        ? await this.sources.loadCursor(source.id)
        : null;
      const incremental = connector.capabilities().incremental && connector.syncIncremental
        ? await connector.syncIncremental(
            ctx,
            priorCursor
              ? { value: priorCursor, updatedAt: source.lastSync ?? source.createdAt }
              : null,
          )
        : null;
      const result = incremental?.result ?? await connector.sync(ctx);
      if (result.removed.length > 0) {
        this.l1Cache.eraseNamespace(l1CachePartition(landingNamespace));
        await this.warm.afterRetraction();
      }
      if (result.errors.length > 0) {
        await this.sources.markSyncFailed(
          source.id,
          `sync reported ${result.errors.length} error(s): ${result.errors[0]?.reason ?? "unknown error"}`,
        );
        await this.audit.append({
          ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
          op: "write", memoryId: null, namespace: landingNamespace, purpose: null,
          result: "error",
          detail: `source_sync source=${source.id} kind=${source.kind} scanned=${result.scanned} errors=${result.errors.length}`,
        });
        await this.finalizeRelationshipImpact(landingIdentity, impact, false);
        return result;
      }
      if (incremental?.cursor) {
        const saved = await this.sources.saveCursor(
          source.id,
          incremental.cursor.value,
          priorCursor,
        );
        if (!saved) throw new Error("source cursor changed during sync");
      }
      if (result.continuation) {
        const now = new Date().toISOString();
        await new DurableJobStore(this.db).enqueue({
          id: `source-sync:${source.id}:continuation:${ulid()}`,
          kind: "source-sync",
          namespace: source.namespace,
          payload: { sourceId: source.id },
          availableAt: now,
        });
        await this.finalizeRelationshipImpact(landingIdentity, impact, false);
        await this.audit.append({
          ts: now, actor: identity.actor, agentId: identity.keyId,
          op: "write", memoryId: null, namespace: landingNamespace, purpose: null,
          result: "ok",
          detail: `source_sync_partial source=${source.id} kind=${source.kind} scanned=${result.scanned} changed=${result.changed}`,
        });
        return result;
      }
      await this.sources.touchLastSync(source.id, new Date().toISOString());
      await this.finalizeRelationshipImpact(landingIdentity, impact, false);
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "write", memoryId: null, namespace: landingNamespace, purpose: null,
        result: "ok",
        detail: `source_sync source=${source.id} kind=${source.kind} scanned=${result.scanned} changed=${result.changed} rejected=${result.rejected}`,
      });
      return result;
    } catch (err) {
      const safeError = redactSourceError(err, config);
      await this.sources.markSyncFailed(
        source.id,
        safeError,
      );
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "write", memoryId: null, namespace: landingNamespace, purpose: null,
        result: "error",
        detail: `source_sync source=${source.id} kind=${source.kind} failed`,
      });
      await this.finalizeRelationshipImpact(landingIdentity, impact, false);
      throw new Error(safeError);
    }
  }

  /**
   * Source-specific HMAC ingress for custom webhooks. The request body is
   * authenticated before JSON parsing, authority fields are rejected, and the
   * resulting records enter only through the ordinary connector + IngestSink
   * path. The caller never supplies an Identity (D9/D10).
   */
  async ingestWebhookSource(
    sourceId: string,
    rawBody: string,
    timestamp: string,
    signature: string,
  ): Promise<SyncResult> {
    const source = await this.sources.get(sourceId);
    const namespace = source?.namespace ?? "unknown";
    const auditDeniedWebhook = async (reason: string): Promise<void> => {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: `webhook:${sourceId}`,
        agentId: INGEST_AGENT,
        op: "write",
        memoryId: null,
        namespace,
        purpose: null,
        result: "denied",
        detail: `${reason} source=${sourceId}`,
      });
    };

    if (!source || source.kind !== "webhook_source" || source.lifecycleState !== "active") {
      await auditDeniedWebhook("webhook authentication rejected");
      throw new WebhookAuthorizationError("invalid webhook signature");
    }

    let config: Record<string, unknown>;
    try {
      config = await this.sourceConnectorConfig(source.kind, source.config, source.namespace);
    } catch {
      await auditDeniedWebhook("webhook authentication rejected");
      throw new WebhookAuthorizationError("invalid webhook signature");
    }
    const signingSecret = typeof config.signingSecret === "string" ? config.signingSecret : "";
    let records;
    try {
      records = verifyWebhookEnvelope(signingSecret, rawBody, timestamp, signature);
    } catch (error) {
      await auditDeniedWebhook(
        error instanceof WebhookValidationError
          ? "webhook payload rejected"
          : "webhook authentication rejected",
      );
      throw error;
    }

    // Timestamp freshness limits the replay window; this durable receipt closes
    // that remaining window across replicas and restarts. Normalize the hex
    // signature so case changes cannot bypass digest uniqueness.
    const requestDigest = createHash("sha256")
      .update(`${timestamp}.${signature.toLowerCase()}`)
      .digest("hex");
    const receivedAt = new Date().toISOString();
    await this.db.query(
      `DELETE FROM source_webhook_receipts
        WHERE received_at < $1::timestamptz - INTERVAL '1 day'`,
      [receivedAt],
    );
    const receipt = await this.db.query(
      `INSERT INTO source_webhook_receipts (source_id, request_digest, received_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (source_id, request_digest) DO NOTHING
       RETURNING request_digest`,
      [source.id, requestDigest, receivedAt],
    );
    if (receipt.rows.length === 0) {
      await auditDeniedWebhook("webhook replay rejected");
      throw new WebhookAuthorizationError("invalid webhook signature");
    }

    const identity: Identity = {
      keyId: `webhook:${source.id}`,
      namespace: source.namespace,
      actor: `webhook:${source.id}`,
      role: "agent",
    };
    try {
      const result = await this.syncSourceWithOverrides(source.id, identity, { records });
      if (result.errors.length > 0 || result.rejected > 0) {
        await this.db.query(
          `DELETE FROM source_webhook_receipts WHERE source_id = $1 AND request_digest = $2`,
          [source.id, requestDigest],
        );
        throw new WebhookDeliveryError("webhook events were not fully accepted");
      }
      return result;
    } catch (error) {
      await this.db.query(
        `DELETE FROM source_webhook_receipts WHERE source_id = $1 AND request_digest = $2`,
        [source.id, requestDigest],
      );
      if (error instanceof WebhookDeliveryError) throw error;
      throw new WebhookDeliveryError("webhook delivery is temporarily unavailable");
    }
  }

  /**
   * Public ingress for the paired Obsidian plugin. Authentication covers the
   * untouched body; server-owned source identity and namespace are resolved
   * before the normal connector/write path receives the payload.
   */
  async ingestObsidianVault(
    sourceId: string,
    rawBody: string,
    timestamp: string,
    signature: string,
  ): Promise<SyncResult & { idempotent?: boolean }> {
    const source = await this.sources.get(sourceId);
    const namespace = source?.namespace ?? "unknown";
    const auditObsidian = async (
      result: "ok" | "denied" | "error",
      reason: string,
    ): Promise<void> => {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: `obsidian:${sourceId}`,
        agentId: INGEST_AGENT,
        op: "write",
        memoryId: null,
        namespace,
        purpose: null,
        result,
        detail: `${reason} source=${sourceId}`,
      });
    };

    if (!source || source.kind !== "obsidian_vault" ||
        source.lifecycleState !== "active") {
      await auditObsidian("denied", "obsidian authentication rejected");
      throw new ObsidianAuthorizationError("invalid obsidian signature");
    }

    let config: Record<string, unknown>;
    try {
      config = await this.sourceConnectorConfig(
        source.kind,
        source.config,
        source.namespace,
      );
    } catch {
      await auditObsidian("denied", "obsidian authentication rejected");
      throw new ObsidianAuthorizationError("invalid obsidian signature");
    }
    const signingSecret =
      typeof config.signingSecret === "string" ? config.signingSecret : "";
    let payload;
    try {
      payload = verifyObsidianIngress(
        signingSecret,
        rawBody,
        timestamp,
        signature,
      );
    } catch (error) {
      await auditObsidian(
        "denied",
        error instanceof ObsidianValidationError
          ? "obsidian payload rejected"
          : "obsidian authentication rejected",
      );
      throw error;
    }

    // Only consume a source bucket after its server-owned record and signing
    // secret authenticated the raw body. Route ids cannot create buckets.
    const sourceRate = await this.rateLimiter.consume(
      `obsidian:source:${source.id}`,
      120,
      60_000,
    );
    if (!sourceRate.allowed) {
      await auditObsidian("denied", "obsidian rate limit exceeded");
      throw new RateLimitError(
        "Obsidian rate limit exceeded",
        sourceRate.retryAfterSec,
      );
    }

    // One durable receipt per source sequence serializes retries and competing
    // deliveries across replicas. Bind that sequence to the exact signed body:
    // a fresh timestamp/signature may retry the same bytes, but cannot rebind
    // the already-observed sequence to different content.
    const bodyDigest = createHash("sha256").update(rawBody).digest("hex");
    const receivedAt = new Date().toISOString();
    const receipt = await this.db.query(
      `INSERT INTO obsidian_ingress_receipts
         (source_id, sequence, body_digest, received_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (source_id, sequence) DO NOTHING
       RETURNING sequence`,
      [source.id, payload.sequence, bodyDigest, receivedAt],
    );
    if (receipt.rows.length === 0) {
      const existing = (await this.db.query(
        `SELECT body_digest, committed_at FROM obsidian_ingress_receipts
          WHERE source_id = $1 AND sequence = $2`,
        [source.id, payload.sequence],
      )).rows[0] as { body_digest?: string; committed_at?: unknown } | undefined;
      if (!existing || existing.body_digest !== bodyDigest) {
        await auditObsidian(
          "denied",
          `obsidian sequence payload mismatch sequence=${payload.sequence}`,
        );
        throw new ObsidianValidationError(
          "obsidian sequence is already bound to another payload",
        );
      }
      const committedSequence =
        obsidianCursorSequence(await this.sources.loadCursor(source.id));
      if (existing.committed_at || committedSequence >= payload.sequence) {
        if (!existing.committed_at) {
          await this.db.query(
            `UPDATE obsidian_ingress_receipts SET committed_at = $3
              WHERE source_id = $1 AND sequence = $2 AND body_digest = $4`,
            [source.id, payload.sequence, receivedAt, bodyDigest],
          );
        }
        await auditObsidian(
          "ok",
          `obsidian replay acknowledged sequence=${payload.sequence}`,
        );
        return { ...emptyObsidianSyncResult(source.id), idempotent: true };
      }
      await auditObsidian("error", "obsidian delivery already in progress");
      throw new ObsidianDeliveryError(
        "obsidian delivery is temporarily unavailable",
      );
    }

    const identity: Identity = {
      keyId: `obsidian:${source.id}`,
      namespace: source.namespace,
      actor: `obsidian:${source.id}`,
      role: "agent",
    };
    try {
      const result = await this.syncSourceWithOverrides(
        source.id,
        identity,
        { payload },
      );
      if (result.errors.length > 0 || result.rejected > 0) {
        throw new ObsidianDeliveryError(
          "obsidian records were not fully accepted",
        );
      }
      await this.db.query(
        `UPDATE obsidian_ingress_receipts SET committed_at = $3
          WHERE source_id = $1 AND sequence = $2 AND body_digest = $4`,
        [source.id, payload.sequence, new Date().toISOString(), bodyDigest],
      );
      return result;
    } catch (error) {
      await this.db.query(
        `DELETE FROM obsidian_ingress_receipts
          WHERE source_id = $1 AND sequence = $2 AND body_digest = $3
            AND committed_at IS NULL`,
        [source.id, payload.sequence, bodyDigest],
      );
      if (error instanceof ObsidianDeliveryError) throw error;
      throw new ObsidianDeliveryError(
        "obsidian delivery is temporarily unavailable",
      );
    }
  }

  /** Authenticated CSV snapshot replacement for a manual csv_sheet_import source. */
  async importCsvSource(
    sourceId: string,
    input: CsvImportInput,
    identity: Identity,
  ): Promise<SyncResult> {
    const source = await this.manageableSource(sourceId, identity);
    if (source.kind !== "csv_sheet_import") {
      throw new Error(`source '${sourceId}' is not a CSV / Sheet Import source`);
    }
    if (source.lifecycleState !== "active") {
      throw new Error(`source '${sourceId}' is ${source.lifecycleState}`);
    }
    const records = mapCsvToConnectorRecords(input);
    return this.syncSourceWithOverrides(source.id, identity, { records });
  }

  /**
   * Run the fragmentation report over the active facts visible from
   * `namespace` (same ancestor ACL as mem_stats), persist the report into
   * `fragmentation_reports`, and return it. The dedupe threshold comes from the
   * namespace's effective policy so it tracks the write path's dedupe band.
   */
  async runFragmentation(
    namespace: Namespace,
    _identity?: Identity,
  ): Promise<FragmentationReport> {
    // M4: a suspended tenant is denied here too (same bulk-revoke gate as the
    // syscalls + ingestion). A null tenant passes silently.
    tenantGate(await this.tenants.resolveTenant(namespace));
    const policy = await this.policyStore.getFresh(namespace);
    const report = await runFragmentation(
      new DbFragmentationReader(this.db),
      namespace,
      { dedupeThreshold: policy.dedupeSimilarityThreshold },
    );
    await this.db.query(
      `INSERT INTO fragmentation_reports (id, namespace, ran_at, json)
       VALUES ($1, $2, $3, $4)`,
      [ulid(), namespace, report.ranAt, JSON.stringify(report)],
    );
    return report;
  }

  // -------------------------------------------------------------------------
  // M8 agent connectivity gateway (D22-D27).
  // -------------------------------------------------------------------------

  private gatewayAdministrator(identity: Identity): GatewayAdministrativeIdentity {
    if (identity.role !== "owner" && identity.role !== "admin") {
      throw new AuthzError("owner or admin role required");
    }
    return { namespace: identity.namespace, role: identity.role };
  }

  private gatewayViewer(identity: Identity): GatewayOversightViewerIdentity {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      throw new AuthzError("owner, admin, or auditor role required");
    }
    return { namespace: identity.namespace, role: identity.role };
  }

  async createAgentConnectionGrant(
    input: CreateAgentConnectionGrantInput,
    identity: Identity,
  ): Promise<AgentConnectionGrant> {
    const administrator = this.gatewayAdministrator(identity);
    const key = (await this.auth.list(identity)).find((candidate) =>
      candidate.id === input.keyId && candidate.status === "active" && candidate.role === "agent",
    );
    if (!key) {
      throw new InvalidAgentConnectionGrantError("active agent badge not found");
    }
    const namespace = key.namespace;
    return this.db.transaction(async (tx) => {
      const version = await tx.query(
        `SELECT COALESCE(MAX(policy_version), 0) + 1 AS next_version
           FROM agent_connection_grants
          WHERE key_id = $1 AND connector_id = $2`,
        [input.keyId, input.connectorId],
      );
      const created = await new AgentConnectionGrantStore(tx).create({
        id: ulid(),
        keyId: input.keyId,
        namespace,
        connectorId: input.connectorId,
        allowedOperations: [...input.allowedOperations],
        allowedSourceRefs: [...input.allowedSourceRefs],
        allowedFields: Object.fromEntries(
          Object.entries(input.allowedFields).map(([sourceRef, fields]) => [sourceRef, [...fields]]),
        ),
        allowedPurposes: [...input.allowedPurposes],
        maxSensitivity: input.maxSensitivity,
        maxRows: input.maxRows,
        maxBytes: input.maxBytes,
        policyVersion: Number(version.rows[0]!.next_version),
        status: "active",
        expiresAt: input.expiresAt,
        oversight: input.oversight ?? DEFAULT_AGENT_CONNECTION_OVERSIGHT,
      }, administrator);
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-grant-create",
        result: "ok",
        detail:
          `gateway_grant=create grant=${created.id} badge=${created.keyId} ` +
          `connector=${created.connectorId} policy=${created.policyVersion}`,
      });
      return created;
    });
  }

  listAgentConnectionGrants(identity: Identity): Promise<AgentConnectionGrant[]> {
    return this.gatewayGrants.listSubtree(this.gatewayViewer(identity));
  }

  revokeAgentConnectionGrant(id: string, identity: Identity): Promise<boolean> {
    const administrator = this.gatewayAdministrator(identity);
    return this.db.transaction(async (tx) => {
      const revoked = await new AgentConnectionGrantStore(tx).revoke(id, administrator);
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-grant-revoke",
        result: revoked ? "ok" : "miss",
        detail: `gateway_grant=revoke grant=${id}`,
      });
      return revoked;
    });
  }

  async issueAgentBadge(
    input: {
      badge: { actor: string; namespace: string; accessLevel?: AgentAccessLevel };
      grant: Omit<CreateAgentConnectionGrantInput, "keyId"> & {
        oversight: AgentConnectionOversight;
      };
    },
    identity: Identity,
  ): Promise<{ plaintext: string; badge: unknown; grant: AgentConnectionGrant }> {
    const administrator = this.gatewayAdministrator(identity);
    // D50: a badge is an agent credential for an EXTERNAL agent, so it obeys
    // exactly the same scope rules as any other agent key — no organization-root
    // badge, team ceiling, issuer-bounded level. This replaces the old
    // subtree-only check (which allowed a root owner to badge the org root).
    const scope = await assertAgentKeyScope(this.db, identity, {
      namespace: input.badge.namespace,
      ...(input.badge.accessLevel ? { level: input.badge.accessLevel } : {}),
    });
    return this.db.transaction(async (tx) => {
      // Already inside a transaction: the audit sink must append through it,
      // not open a second one (Db.transaction refuses to nest).
      const txAudit = new TransactionAuditLog(tx);
      const txAuth = new AuthService(tx, txAudit);
      // A badge IS an Assistant credential, so it is minted by the same typed
      // issuer the console's deploy flow uses. Going through AuthService
      // directly used to hand back a bare `hm_` key with no type marker, which
      // the connect screen then reported as an unrecognized prefix — the one
      // credential the product issues for agents was the one it could not
      // identify. ProductKeyService also removes the old owner-impersonation
      // step: it authorizes an admin or member caller natively (D50).
      const issued = await new ProductKeyService(
        tx,
        txAuth,
        txAudit,
        this.agentBearerCipher,
      ).issue(
        {
          type: "assistant",
          namespace: scope.namespace,
          actor: input.badge.actor,
          agentAccessLevel: scope.level,
        },
        identity,
      );
      const version = await tx.query(
        `SELECT COALESCE(MAX(policy_version), 0) + 1 AS next_version
           FROM agent_connection_grants
          WHERE key_id = $1 AND connector_id = $2`,
        [issued.record.id, input.grant.connectorId],
      );
      const grant = await new AgentConnectionGrantStore(tx).create({
        id: ulid(),
        keyId: issued.record.id,
        namespace: issued.record.namespace,
        connectorId: input.grant.connectorId,
        allowedOperations: [...input.grant.allowedOperations],
        allowedSourceRefs: [...input.grant.allowedSourceRefs],
        allowedFields: Object.fromEntries(
          Object.entries(input.grant.allowedFields).map(([sourceRef, fields]) => [
            sourceRef,
            [...fields],
          ]),
        ),
        allowedPurposes: [...input.grant.allowedPurposes],
        maxSensitivity: input.grant.maxSensitivity,
        maxRows: input.grant.maxRows,
        maxBytes: input.grant.maxBytes,
        policyVersion: Number(version.rows[0]!.next_version),
        status: "active",
        expiresAt: input.grant.expiresAt,
        oversight: input.grant.oversight,
      }, administrator);
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: input.badge.namespace,
        purpose: "agent-badge-issue",
        result: "ok",
        detail:
          `agent_badge=issue badge=${issued.record.id} grant=${grant.id} ` +
          `connector=${grant.connectorId} policy=${grant.policyVersion}`,
      });
      return { plaintext: issued.plaintext, badge: issued.record, grant };
    });
  }

  async createAgentAccessRequest(
    input: Omit<CreateAgentAccessRequestInput, "operation">,
    identity: Identity,
  ): Promise<AgentAccessRequest> {
    if (identity.role !== "agent" || !(await this.isIdentityActive(identity))) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request",
        result: "denied",
        detail: "gateway_access_request=create reason=agent-credential-required",
      });
      throw new AuthzError("access request denied");
    }
    const grant = await this.gatewayGrants.getForKey(input.grantId, identity.keyId);
    if (
      !grant ||
      grant.connectorId !== input.connectorId ||
      grant.oversight.accessRequests !== "allowed"
    ) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request",
        result: "denied",
        detail: `gateway_access_request=create grant=${input.grantId} reason=authority-unavailable`,
      });
      throw new AuthzError("access request denied");
    }
    const pointer = await this.gatewayPointer(input, identity);
    if (!pointer) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request",
        result: "denied",
        detail:
          `gateway_access_request=create grant=${input.grantId} ` +
          `connector=${input.connectorId} source=${input.sourceRef} reason=source-unavailable`,
      });
      await this.recordAgentAccessEvent(
        identity,
        input,
        grant,
        "denied",
        "source-unavailable",
        0,
        0,
        grant.allowedPurposes.includes(input.purpose) ? input.purpose : null,
      );
      throw new AuthzError("access request denied");
    }
    return this.db.transaction(async (tx) => {
      const request = await this.gatewayOversight.createRequestInTransaction(
        tx,
        { operation: "source-read", ...input },
        { keyId: identity.keyId, namespace: identity.namespace, role: "agent" },
      );
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request",
        result: "ok",
        detail:
          `gateway_access_request=create request=${request.id} grant=${request.grantId} ` +
          `connector=${request.connectorId} source=${request.sourceRef}`,
      });
      return request;
    });
  }

  async listOwnAgentAccessRequests(identity: Identity): Promise<AgentAccessRequest[]> {
    if (identity.role !== "agent") {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request-list-own",
        result: "denied",
        detail: "gateway_access_request=list-own reason=agent-role-required",
      });
      throw new AuthzError("agent role required");
    }
    try {
      const requests = await this.gatewayOversight.listRequestsForAgent({
        keyId: identity.keyId,
        namespace: identity.namespace,
        role: "agent",
      });
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request-list-own",
        result: requests.length > 0 ? "ok" : "miss",
        detail: `gateway_access_request=list-own count=${requests.length}`,
      });
      return requests;
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request-list-own",
        result: "error",
        detail: "gateway_access_request=list-own reason=lookup-failed",
      });
      throw error;
    }
  }

  /**
   * `describe_access`: the badge-visible mirror of its own standing gateway
   * authority plus whether it may escalate for temporary extra access. Only
   * agent badges may call it, and it only ever returns grants bound to the
   * caller's own key (enforced in SQL by `listActiveForKey`) — no other
   * badge, source, or namespace is ever enumerated. Audited like the other
   * agent-facing oversight reads.
   */
  async describeAgentAccess(identity: Identity): Promise<AgentAccessDescription[]> {
    if (identity.role !== "agent") {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-describe-access",
        result: "denied",
        detail: "gateway_access=describe reason=agent-role-required",
      });
      throw new AuthzError("agent role required");
    }
    try {
      const grants = await this.gatewayGrants.listActiveForKey(identity.keyId);
      const description: AgentAccessDescription[] = grants.map((grant) => {
        const enabled = grant.oversight.accessRequests === "allowed";
        return {
          grantId: grant.id,
          connectorId: grant.connectorId,
          allowedOperations: grant.allowedOperations,
          allowedSourceRefs: grant.allowedSourceRefs,
          allowedFields: grant.allowedFields,
          allowedPurposes: grant.allowedPurposes,
          maxRows: grant.maxRows,
          maxBytes: grant.maxBytes,
          maxSensitivity: grant.maxSensitivity,
          expiresAt: grant.expiresAt,
          policyVersion: grant.policyVersion,
          accessRequests: {
            enabled,
            maxDurationSeconds: MAX_GATEWAY_REQUEST_DURATION_SECONDS,
            approvalTtlSeconds: grant.oversight.approvalTtlSeconds,
            maxUsesCap: MAX_GATEWAY_REQUEST_USES,
          },
          ...(enabled
            ? {
              hint:
                "This badge may ask a human owner/admin for temporary extra access: " +
                "call request_access (MCP) or POST /v1/agent/access-requests with the " +
                "grantId, connectorId, sourceRef, requestedFields, requestedRows, " +
                "requestedBytes, justification, and requestedDurationSeconds. Approval " +
                "is required, expires, and never changes this standing access.",
            }
            : {}),
        };
      });
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-describe-access",
        result: description.length > 0 ? "ok" : "miss",
        detail: `gateway_access=describe count=${description.length}`,
      });
      return description;
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "read",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-describe-access",
        result: "error",
        detail: "gateway_access=describe reason=lookup-failed",
      });
      throw error;
    }
  }

  async listAgentAccessEvents(
    filters: { keyId?: string; limit?: number },
    identity: Identity,
  ): Promise<AgentAccessEvent[]> {
    try {
      const events = await this.gatewayOversight.listEvents(this.gatewayViewer(identity), filters);
      await this.auditGatewayOversightList(identity, "gateway-access-event-list", events.length);
      return events;
    } catch (error) {
      await this.auditGatewayOversightList(identity, "gateway-access-event-list", null);
      throw error;
    }
  }

  async listAgentAccessAlerts(
    filters: { status?: AgentAccessAlert["status"]; limit?: number },
    identity: Identity,
  ): Promise<AgentAccessAlert[]> {
    try {
      const alerts = await this.gatewayOversight.listAlerts(this.gatewayViewer(identity), filters);
      await this.auditGatewayOversightList(identity, "gateway-access-alert-list", alerts.length);
      return alerts;
    } catch (error) {
      await this.auditGatewayOversightList(identity, "gateway-access-alert-list", null);
      throw error;
    }
  }

  async acknowledgeAgentAccessAlert(id: string, identity: Identity): Promise<boolean> {
    const administrator = this.gatewayAdministrator(identity);
    return this.db.transaction(async (tx) => {
      const acknowledged = await this.gatewayOversight.acknowledgeAlertInTransaction(
        tx,
        id,
        administrator,
        identity.actor,
      );
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-alert-acknowledge",
        result: acknowledged ? "ok" : "miss",
        detail: `gateway_alert=acknowledge alert=${id}`,
      });
      return acknowledged;
    });
  }

  async listAgentAccessRequests(
    filters: { status?: AgentAccessRequest["status"]; limit?: number },
    identity: Identity,
  ): Promise<AgentAccessRequest[]> {
    try {
      const requests = await this.gatewayOversight.listRequests(this.gatewayViewer(identity), filters);
      await this.auditGatewayOversightList(identity, "gateway-access-request-list", requests.length);
      return requests;
    } catch (error) {
      await this.auditGatewayOversightList(identity, "gateway-access-request-list", null);
      throw error;
    }
  }

  private async auditGatewayOversightList(
    identity: Identity,
    purpose: "gateway-access-event-list" | "gateway-access-alert-list" |
      "gateway-access-request-list",
    count: number | null,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "read",
      memoryId: null,
      namespace: identity.namespace,
      purpose,
      result: count === null ? "error" : count > 0 ? "ok" : "miss",
      detail: count === null
        ? "gateway_oversight=list reason=lookup-failed"
        : `gateway_oversight=list count=${count}`,
    });
  }

  async approveAgentAccessRequest(
    id: string,
    input: AgentAccessApprovalInput,
    identity: Identity,
  ): Promise<AgentAccessRequest | null> {
    const administrator = this.gatewayAdministrator(identity);
    return this.db.transaction(async (tx) => {
      const approved = await this.gatewayOversight.approveRequestInTransaction(
        tx,
        id,
        administrator,
        identity.actor,
        input,
      );
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request-approve",
        result: approved ? "ok" : "miss",
        detail: `gateway_access_request=approve request=${id}`,
      });
      return approved;
    });
  }

  async denyAgentAccessRequest(
    id: string,
    input: AgentAccessDecisionInput,
    identity: Identity,
  ): Promise<AgentAccessRequest | null> {
    const administrator = this.gatewayAdministrator(identity);
    return this.db.transaction(async (tx) => {
      const denied = await this.gatewayOversight.denyRequestInTransaction(
        tx,
        id,
        administrator,
        identity.actor,
        input,
      );
      await this.audit.appendTo(tx, {
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "gateway-access-request-deny",
        result: denied ? "ok" : "miss",
        detail: `gateway_access_request=deny request=${id}`,
      });
      return denied;
    });
  }

  private async recordAgentAccessEvent(
    identity: Identity,
    input: Pick<AgentSourceReadInput, "grantId" | "connectorId" | "sourceRef" | "purpose" | "accessRequestId"> |
      Pick<CreateAgentAccessRequestInput, "grantId" | "connectorId" | "sourceRef" | "purpose">,
    grant: Pick<
      AgentConnectionGrant,
      "id" | "policyVersion" | "oversight"
    > | null,
    decision: "allowed" | "denied" | "error",
    reasonCode: string,
    rows = 0,
    bytes = 0,
    trustedPurpose: string | null = null,
    trustedAccessRequestId: string | null = null,
  ): Promise<void> {
    const connectorId = input.connectorId === input.connectorId.trim() &&
      input.connectorId.length > 0 && input.connectorId.length <= 256
      ? input.connectorId
      : "invalid-connector";
    const sourceRef = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/.test(
      input.sourceRef,
    ) ? input.sourceRef : "invalid_source";
    const purpose = trustedPurpose !== null &&
      trustedPurpose === trustedPurpose.trim() &&
      trustedPurpose.length > 0 &&
      trustedPurpose.length <= 256
      ? trustedPurpose
      : "scope-denied";
    await this.gatewayOversight.recordEvent({
      grantId: grant?.id ?? null,
      keyId: identity.keyId,
      namespace: identity.namespace,
      connectorId,
      sourceRef,
      operation: "source-read",
      purpose,
      decision,
      reasonCode,
      rows,
      bytes,
      policyVersion: grant?.policyVersion ?? null,
      accessRequestId: trustedAccessRequestId,
    }, grant?.oversight ?? DEFAULT_AGENT_CONNECTION_OVERSIGHT);
  }

  private async gatewayAudit(
    identity: Identity,
    input: Pick<AgentSourceReadInput, "grantId" | "connectorId" | "sourceRef" | "purpose">,
    result: "ok" | "denied" | "miss" | "error",
    phase: string,
    detail?: string,
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op: "read",
      memoryId: null,
      namespace: identity.namespace,
      purpose: input.purpose,
      result,
      detail:
        `gateway_phase=${phase} grant=${input.grantId} connector=${input.connectorId} ` +
        `source=${input.sourceRef}` + (detail ? ` ${detail}` : ""),
    });
  }

  private async gatewayDenied(
    identity: Identity,
    input: AgentSourceReadInput,
    phase: string,
    reasonCode: string,
    grant?: AgentConnectionGrant | null,
    approvedRequest?: AgentAccessRequest | null,
  ): Promise<void> {
    const activeGrant = grant === undefined
      ? await this.gatewayGrants.getForKey(input.grantId, identity.keyId)
      : grant;
    const eventGrant = activeGrant ?? (
      grant === undefined
        ? await this.gatewayGrants.getHistoricalMetadataForKey(input.grantId, identity.keyId)
        : null
    );
    const standingPurpose = activeGrant?.allowedPurposes.includes(input.purpose)
      ? input.purpose
      : null;
    const trustedPurpose = approvedRequest?.purpose ?? standingPurpose ?? "scope-denied";
    await this.gatewayAudit(identity, {
      grantId: eventGrant?.id ?? "unmatched-grant",
      connectorId: eventGrant?.connectorId === input.connectorId
        ? input.connectorId
        : "unmatched-connector",
      sourceRef: /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/.test(
          input.sourceRef,
        )
        ? input.sourceRef
        : "invalid_source",
      purpose: trustedPurpose,
    }, "denied", phase, `reason=${reasonCode}`);
    await this.recordAgentAccessEvent(
      identity,
      input,
      eventGrant,
      "denied",
      reasonCode,
      0,
      0,
      trustedPurpose,
      approvedRequest?.id ?? null,
    );
  }

  /**
   * Actionable denial text for the authorize phase. A scope denial tells the
   * badge whether it may escalate (`oversight.accessRequests === "allowed"`)
   * and exactly how; the message only ever names values the agent itself
   * supplied (sourceRef) plus its own grant's escalation policy — it never
   * enumerates other sources or badges. Rate-limit denials keep the plain
   * message: a temporary access request cannot fix throttling.
   */
  private agentSourceReadDeniedMessage(
    reasonCode: string,
    sourceRef: string,
    grant: AgentConnectionGrant | null,
  ): string {
    if (reasonCode === "rate-limit") return "governed source read denied";
    const oversight = grant?.oversight;
    if (oversight?.accessRequests === "allowed") {
      return `governed source read denied: '${sourceRef}' is outside this badge's scope. ` +
        `This badge may request temporary access - call request_access (MCP) or ` +
        `POST /v1/agent/access-requests with the same grantId, connectorId, sourceRef, plus ` +
        `requestedFields, requestedRows, requestedBytes, justification, and ` +
        `requestedDurationSeconds (at most ${oversight.approvalTtlSeconds} seconds). ` +
        `A human owner/admin must approve before any read succeeds.`;
    }
    if (oversight) {
      return `governed source read denied: '${sourceRef}' is outside this badge's scope ` +
        `and this badge is not permitted to request additional access. ` +
        `Ask your operator to adjust the badge grant.`;
    }
    return "governed source read denied";
  }

  async rejectAgentSourceReadIngress(
    input: Pick<AgentSourceReadInput, "grantId" | "connectorId" | "sourceRef" | "purpose">,
    identity: Identity,
  ): Promise<never> {
    const fullInput: AgentSourceReadInput = {
      operation: "source-read",
      ...input,
      query: "rejected-before-parse",
    };
    await this.gatewayDenied(identity, fullInput, "ingress", "unexpected-authority-field");
    throw new AuthzError("governed source read denied");
  }

  private async gateAgentSourceRead(
    input: AgentSourceReadInput,
    identity: Identity,
  ): Promise<PolicyConfigX> {
    if (!(await this.isIdentityActive(identity))) {
      await this.gatewayDenied(identity, input, "authorize", "credential-inactive");
      throw new AuthzError("governed source read denied");
    }
    const tenant = await this.tenants.resolveTenant(identity.namespace);
    try {
      tenantGate(tenant);
    } catch {
      await this.gatewayDenied(identity, input, "authorize", "tenant-suspended");
      throw new AuthzError("governed source read denied");
    }
    const policy = await this.policyStore.getFresh(identity.namespace);
    const namespaceLimit = policy.rateLimitPerMin ?? DEFAULT_RATE_LIMIT_PER_MIN;
    const limit = this.quota.rateLimitPerMin(
      effectiveRateLimit(namespaceLimit, tenant) ?? namespaceLimit,
      identity.actor,
    );
    if (!(await this.rateLimiter.allow(identity.keyId, limit))) {
      await this.gatewayDenied(identity, input, "authorize", "rate-limit");
      throw new RateLimitError(`rate limit exceeded (${limit} requests/min for this key)`);
    }
    const terms = input.query.trim().split(/\s+/).filter(Boolean);
    if (
      terms.length === 0 || terms.length > MAX_GATEWAY_QUERY_TERMS ||
      terms.some((term) => term.length > MAX_GATEWAY_QUERY_TERM_LENGTH) ||
      (input.requestedFields?.length ?? 0) > MAX_GATEWAY_FIELDS
    ) {
      await this.gatewayDenied(identity, input, "authorize", "request-complexity");
      throw new AuthzError("governed source read denied");
    }
    return policy;
  }

  private async gatewayPointer(
    input: Pick<AgentSourceReadInput, "connectorId" | "sourceRef">,
    identity: Identity,
  ): Promise<PointerMatch | null> {
    const pointer = await this.index.getPointerBySource(
      identity.namespace,
      input.connectorId,
      input.sourceRef,
      sourceAccessSubject(identity),
    );
    if (!pointer) return null;
    return {
      ref: pointer.id,
      connectorId: input.connectorId,
      sourceRef: input.sourceRef,
      score: 1,
      content: pointer.content,
      sourceAccess: pointer.sourceAccess,
      classification: pointer.classification,
    };
  }

  private async currentExactApproval(
    consumed: AgentAccessRequest,
    input: AgentSourceReadInput,
    identity: Identity,
    decision: AgentAuthorizationAllowed,
  ): Promise<AgentAccessRequest | null> {
    const current = (await this.gatewayOversight.listRequestsForAgent({
      keyId: identity.keyId,
      namespace: identity.namespace,
      role: "agent",
    })).find((request) => request.id === consumed.id);
    if (!current || (current.status !== "approved" && current.status !== "consumed")) return null;
    const exact =
      current.keyId === identity.keyId &&
      current.namespace === identity.namespace &&
      current.grantId === input.grantId &&
      current.connectorId === input.connectorId &&
      current.sourceRef === input.sourceRef &&
      current.purpose === input.purpose &&
      current.requestedRows === decision.maxRows &&
      current.requestedBytes === decision.maxBytes &&
      current.requestedFields.length === decision.effectiveFields.length &&
      current.requestedFields.every((field, index) => field === decision.effectiveFields[index]) &&
      current.approvedUntil !== null &&
      Date.parse(current.approvedUntil) > Date.now() &&
      current.usedCount >= consumed.usedCount &&
      current.usedCount <= current.maxUses;
    return exact ? current : null;
  }

  async agentSourceRead(
    input: AgentSourceReadInput,
    identity: Identity,
  ): Promise<AgentSourceReadResult> {
    await this.gatewayDenied(identity, input, "authorize", "connector-unavailable");
    throw new AuthzError("governed source reads are unavailable in the standalone build");
  }

  registerTenant(
    input: Parameters<TenantRegistry["register"]>[0],
    identity: Identity,
  ): Promise<Tenant> {
    return this.tenants.register(input, identity);
  }

  /** List tenants visible to the caller (ancestor-ACL scoped — no siblings). */
  listTenants(identity: Identity): Promise<Tenant[]> {
    return this.tenants.list(identity);
  }

  /** Suspend a tenant (bulk-revoke its keyspace); null if the id is unknown. */
  suspendTenant(id: Namespace): Promise<Tenant | null> {
    return this.tenants.suspend(id);
  }

  /** Reactivate a suspended tenant; null if the id is unknown. */
  activateTenant(id: Namespace): Promise<Tenant | null> {
    return this.tenants.activate(id);
  }

  // -------------------------------------------------------------------------
  // R6 warm stores — mirror administration. Root-owner only: warm stores are
  // process-global infrastructure (the mirror holds many tenants' rows), so a
  // tenant-scoped owner may neither inspect nor rebuild them.
  // -------------------------------------------------------------------------

  private assertWarmAdmin(identity: Identity, op: string): void {
    if (!isRootOwner(identity)) {
      throw new AuthzError(`${op} requires the root owner`);
    }
  }

  /** Per-store health + pending outbox counts. */
  async warmStatus(identity: Identity): Promise<WarmStoreStatus[]> {
    this.assertWarmAdmin(identity, "warm-store status");
    return this.warm.status();
  }

  /** Retry every store's durable outbox now. Returns per-store remaining. */
  async warmFlush(identity: Identity): Promise<Record<string, number>> {
    this.assertWarmAdmin(identity, "warm-store flush");
    return this.warm.flush();
  }

  /**
   * Wipe + rebuild one external store's cache for a namespace subtree from
   * canonical rows ("rebuildable cache, never authority" as executable code).
   */
  async warmRebuild(
    storeName: string,
    namespace: Namespace,
    identity: Identity,
  ): Promise<{ store: string; namespace: Namespace; records: number }> {
    this.assertWarmAdmin(identity, "warm-store rebuild");
    // Normalize: a trailing slash would wipe the mirror subtree and then
    // stream back zero records (the ancestor relation never emits "acme/").
    const target = trimTrailingRepeatedCharacter(namespace.trim(), "/");
    if (target.length === 0) {
      throw new Error("warm-store rebuild requires a namespace");
    }
    return this.warm.rebuild(storeName, target);
  }

  // -------------------------------------------------------------------------
  // M4 erasure — certificate verification + read-back. Kernel verification
  // pins the signing key loaded at boot. External verifiers must supply that
  // trusted public key out of band. getCertificate reads a persisted cert.
  // -------------------------------------------------------------------------

  /** Verify a DeletionCertificate against this kernel's boot signing key. */
  verifyCertificate(cert: DeletionCertificate): boolean {
    return verifyCertificate(cert, this.signingKey.publicKeyBase64);
  }

  /**
   * Governed L3 write. Private concept plaintext enters through the kernel,
   * is encrypted before it reaches the repository, then projected for scoped
   * retrieval. Callers may only write inside their management subtree.
   */
  async createPrivateConcept(concept: Concept, identity: Identity): Promise<string> {
    if (
      (identity.role !== "owner" && identity.role !== "admin") ||
      !concept.namespace ||
      (!isRootOwner(identity) && !isSelfOrDescendant(concept.namespace, identity.namespace))
    ) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: null,
        result: "denied",
        detail: `private concept write denied path=${concept.path}`,
      });
      throw new AuthzError("owner/admin required in the concept namespace subtree");
    }
    try {
      const rel = await this.cold.writePrivateConcept(this.db, concept);
      await this.cold.syncToDb(this.db, this.embedder);
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: concept.namespace,
        purpose: null,
        result: "ok",
        detail: `private concept written path=${rel}`,
      });
      return rel;
    } catch (err) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: concept.namespace,
        purpose: null,
        result: "error",
        detail: `private concept write failed path=${concept.path} error=${(err as Error).message}`.slice(0, 500),
      });
      throw err;
    }
  }

  /**
   * Read a persisted DeletionCertificate by id, or null if unknown.
   *
   * ACL: scoped to the caller's management subtree — a cert is visible iff its
   * stored namespace is the caller's namespace or a descendant of it. A
   * cert outside the subtree collapses to `null` (a miss), so a sibling tenant
   * can never read another tenant's namespace, target PII, or erasedIds. An
   * `owner` (empty namespace) sees org-wide; an `auditor` is org-wide WITHIN its
   * own tenant, never across the tenant fence.
   */
  async getCertificate(
    id: string,
    identity: Identity,
  ): Promise<DeletionCertificate | null> {
    const res = await this.db.query(
      `SELECT json FROM deletion_certificates WHERE id = $1`,
      [id],
    );
    if (res.rows.length === 0) return null;
    const raw = (res.rows[0] as { json: unknown }).json;
    const cert = (typeof raw === "string" ? JSON.parse(raw) : raw) as DeletionCertificate;
    // Downward-subtree ACL (denied collapses to miss — no cross-tenant oracle).
    if (
      !isRootOwner(identity) &&
      !isSelfOrDescendant(cert.namespace, identity.namespace)
    ) {
      return null;
    }
    return cert;
  }

  // -------------------------------------------------------------------------
  // M5 control room — human sign-in (Module A) + management-API read models
  // (Module B). Humans reuse the D9 Identity: a resolved session yields the
  // SAME { keyId, namespace, actor, role } shape the syscalls require. The read
  // models are subtree-scoped and reuse existing kernel machinery — they never
  // reimplement retrieval/stats/audit/sources. The kernel is passed as the
  // structural KernelSlice the handlers accept (it satisfies it, with listUsers
  // wired below).
  // -------------------------------------------------------------------------

  /** The { users, sessions } bundle the console/auth free functions consume. */
  private get authStores(): AuthStores {
    return { users: this.users, sessions: this.sessions };
  }

  /** Permanently single-use first-root activation with an atomic session. */
  bootstrapHuman(input: BootstrapInput): Promise<BootstrapResult | null> {
    return this.bootstrapService.activate(input);
  }

  /** Issue a pending, namespace/role-bound activation credential. */
  inviteHuman(
    input: CreateInvitationInput,
    identity: Identity,
  ): Promise<IssuedInvitation> {
    return this.invitations.create(input, identity);
  }

  /** Consume an activation credential and create the bound active user. */
  acceptHumanInvite(token: string, password: string): Promise<User | null> {
    return this.invitations.accept({ token, password });
  }

  /**
   * Sign a human in with email + password. Returns `{ token, user }` (the raw
   * opaque session token for the cookie + the public user record) on success,
   * or `null` on ANY failure — an unknown email, wrong password, disabled user,
   * or passwordless (SSO) account all collapse to null (no enumeration oracle).
   * The token is hashed at rest by SessionStore; the plaintext is never stored
   * or logged.
   */
  async login(
    email: string,
    password: string,
  ): Promise<{ token: string; user: User } | null> {
    const result = await sessionLogin(this.authStores, email, password);
    if (result === null) return null;
    // The public user record for the /auth/login response (never the hash).
    const user = await this.users.byEmail(result.identity.actor);
    // byEmail cannot miss here (login just resolved the same row), but guard.
    if (user === null) return null;
    return { token: result.token, user };
  }

  /**
   * Resolve a raw session token to the D9 Identity the syscalls require
   * (`{ keyId: session.id, namespace, actor: email, role }`). Null for an
   * unknown/expired token or a disabled user — expiry + disabled are enforced
   * server-side in SessionStore.resolve, never trusted from the cookie.
   */
  resolveSessionIdentity(token: string): Promise<Identity | null> {
    return sessionResolve(this.authStores, token);
  }

  /** Invalidate a session token server-side (logout). Idempotent. */
  async logout(token: string): Promise<void> {
    await sessionLogout(this.authStores, token);
  }

  /**
   * Create a human user (S3 invite). Authorization is enforced in
   * UserStore.create: the empty-users bootstrap requires NO caller (direct-DB/
   * CLI only). With a caller, an OWNER may mint any human role and an ADMIN may
   * invite non-owner roles in its subtree, but only an owner may mint an owner
   * (else a subtree-admin could escalate to org owner). Other callers → 403.
   */
  createUser(input: CreateUserInput, caller?: Identity | null): Promise<User> {
    return this.users.create(input, caller);
  }

  /**
   * Human roster visible to the caller — the ancestor-subtree ACL UserStore.list
   * enforces (owner → everyone; else → own namespace + descendants, exact
   * IN-list + escaped LIKE so `_`/`%` never leak siblings). Shaped as the
   * ConsoleUser the console read models expect (a structural subset of User).
   */
  async listUsers(identity: Identity): Promise<ConsoleUser[]> {
    return this.users.list(identity);
  }

  /**
   * The KernelSlice the console read models consume. It is `this` for every
   * member EXCEPT `auth.list`: an AUDITOR is read-only EVERYWHERE in its scope
   * (M5 core invariant), so the people screen must show it the agent badges in
   * its subtree — but AuthService.list is owner/admin-only and DENIES an auditor
   * (that owner/admin gate is correct for the mutating `/v1/admin/keys` route,
   * which stays untouched). So for the console read model we present an auditor
   * as an admin at the SAME namespace purely for the badge LISTING (a read) —
   * granting no write and no wider scope than the auditor already has.
   */
  private consoleSlice(identity: Identity): KernelSlice {
    const kernel = this;
    return {
      db: this.db,
      audit: this.audit,
      auth: {
        list(caller: Identity) {
          const readCaller: Identity =
            caller.role === "auditor" ? { ...caller, role: "admin" } : caller;
          return kernel.auth.list(readCaller);
        },
      },
      sources: this.sources,
      budget: this.budget,
      tenants: this.tenants,
      listUsers: (id) => this.listUsers(id),
      getPolicy: (ns) => this.getPolicy(ns),
      // M10: team roster mutations sync access_grants in the SAME tx.
      membershipGrants: this.accessGrants,
      // S6's data-quality tile quotes the S11 queue rather than counting
      // conflicts itself. A role without conflict authority throws here and the
      // tile degrades to "unavailable" — it never invents a zero.
      countOpenConflicts: (id) => this.countOpenConflicts(id),
    };
  }

  /**
   * S2 overview aggregate for the caller's subtree (Module B, subtree-scoped).
   * `params.days` is Home's reporting window; omitted means all-time.
   */
  overview(identity: Identity, params: OverviewParams = {}): Promise<Overview> {
    return consoleOverview(this.consoleSlice(identity), identity, params);
  }

  /**
   * M9 #5 (E42): standing setup checklist derived from real signals for the
   * caller's org. Pure read; namespace comes only from the resolved identity.
   */
  setupChecklist(identity: Identity): Promise<SetupChecklist> {
    return setupChecklist(
      { db: this.db, sources: this.sources, tenants: this.tenants },
      identity,
    );
  }

  /**
   * Organization adoption (see src/tenancy/adopt.ts): re-root orphan
   * top-level namespaces under a tenant. Platform-root only — this rewrites
   * scoping labels across the whole database, which no org-scoped identity
   * may do. Every run (including dry runs) writes an audit row (D4).
   */
  async adoptOrganizationNamespaces(
    input: { tenant: string; namespaces: string[]; dryRun?: boolean; rootSources?: boolean },
    identity: Identity,
  ): Promise<AdoptReport> {
    if (!isRootOwner(identity)) {
      throw new AuthzError("org adopt requires the platform root owner");
    }
    const report = await adoptNamespaces(this.db, input);
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: "cli",
      op: "write",
      memoryId: null,
      namespace: input.tenant,
      purpose: "org-adopt",
      result: "ok",
      detail:
        `${report.dryRun ? "dry-run: " : ""}adopted [${report.namespaces.join(", ")}] ` +
        `into '${report.tenant}' - ${report.total} row(s) across ${report.changes.length} table.column(s)`,
    });
    return report;
  }

  /**
   * The mandatory-setup gate decision (CONTRACTS-SETUP-GATE.md): a cheap read
   * of the persisted `onboarding_completed_at` latch — no live probes — so it
   * is safe to call from `/auth/me` on every console boot.
   */
  onboardingState(identity: Identity): Promise<OnboardingState> {
    return onboardingState(
      { db: this.db, sources: this.sources, tenants: this.tenants },
      identity,
    );
  }

  /** M9 #8 (E43): composite banded memory-readiness score (ACL-scoped reads). */
  readiness(identity: Identity): Promise<MemoryReadiness> {
    return computeReadiness(this, identity);
  }

  assistantRecycleBin(identity: Identity) {
    return listAssistantRecycleBin(this.db, identity);
  }

  recycleAssistantActor(actor: string, identity: Identity) {
    return recycleAssistantActor({ db: this.db, audit: this.audit }, actor, identity);
  }

  restoreAssistantActor(actor: string, identity: Identity) {
    return restoreAssistantActor({ db: this.db, audit: this.audit }, actor, identity);
  }

  purgeAssistantActor(actor: string, confirmation: string, identity: Identity) {
    return hardPurgeAssistantActor(
      { db: this.db, audit: this.audit, signingKey: this.signingKey },
      actor,
      identity,
      confirmation,
    );
  }

  gapFeed(identity: Identity): Promise<GapFeed> {
    return buildGapFeed(this.db, identity);
  }

  /**
   * M9 #13 (E47): suggested copilot questions for the caller's own namespace.
   * Knowledge headings read through the ACL-scoped MemoryIndex (source-native
   * ACL + classification enforced in the query layer), never raw SQL.
   */
  suggestedQuestions(identity: Identity): Promise<SuggestedQuestionsResult> {
    return consoleSuggestedQuestions({ db: this.db, index: this.index }, identity);
  }

  // ---------------------------------------------------------------------------
  // M9 #11b (D29) — hosted OAuth authorization-server surface. Pure envelope
  // handlers the HTTP transport mounts at /oauth/* and /.well-known/*; every
  // issuance / introspection / revocation outcome audits inside src/oauth/.
  // ---------------------------------------------------------------------------

  private get oauthDeps(): OAuthServerDeps {
    return {
      clients: this.oauthClients,
      tokens: this.oauthTokens,
      codes: this.oauthCodes,
      audit: this.audit,
    };
  }

  oauthToken(req: OAuthHttpRequest): Promise<OAuthHttpResponse> {
    return handleTokenRequest(this.oauthDeps, req);
  }

  oauthIntrospect(req: OAuthHttpRequest): Promise<OAuthHttpResponse> {
    return handleIntrospectionRequest(this.oauthDeps, req);
  }

  oauthRevoke(req: OAuthHttpRequest): Promise<OAuthHttpResponse> {
    return handleRevocationRequest(this.oauthDeps, req);
  }

  /**
   * OA2 — RFC 7591 dynamic client registration. Open by design; the durable
   * per-address limiter is the abuse damper (the client service adds the hard
   * total cap). Store-down browns out to a 503 envelope, never a crash.
   */
  async oauthRegister(
    req: OAuthHttpRequest & { clientAddress?: string },
  ): Promise<OAuthHttpResponse> {
    try {
      const bucket = `oauth-dcr:${req.clientAddress ?? "unknown"}`;
      const rate = await this.rateLimiter.consume(bucket, 10, 60_000);
      if (!rate.allowed) {
        await this.audit.append({
          ts: new Date().toISOString(),
          actor: "unknown",
          agentId: "oauth",
          op: "reject",
          memoryId: null,
          namespace: "",
          purpose: null,
          result: "denied",
          detail: "dcr registration denied: rate limit exceeded",
        });
        return {
          status: 429,
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            "retry-after": String(rate.retryAfterSec ?? 60),
          },
          body: { error: "temporarily_unavailable", error_description: "slow down" },
        };
      }
    } catch (err) {
      // Limiter store down: fail toward registration (the hard cap still
      // holds) rather than locking the front door on a telemetry outage.
      console.error("oauth dcr rate limit degraded:", (err as Error).name);
    }
    return handleRegistrationRequest(this.oauthDeps, req);
  }

  /** OA8 — GET /oauth/authorize (login bounce | consent page | error page). */
  oauthAuthorizePage(
    query: Record<string, unknown>,
    rawQuery: string,
    identity: Identity | null,
    issuerBaseUrl: string,
  ): Promise<OAuthPageResponse> {
    return handleAuthorizePage(
      { clients: this.oauthClients, codes: this.oauthCodes, audit: this.audit },
      query,
      rawQuery,
      identity,
      issuerBaseUrl,
    );
  }

  /** OA8 — POST /oauth/authorize/decision (allow → code redirect | deny). */
  oauthAuthorizeDecision(
    body: Record<string, unknown>,
    identity: Identity | null,
    issuerBaseUrl: string,
  ): Promise<OAuthPageResponse> {
    return handleAuthorizeDecision(
      { clients: this.oauthClients, codes: this.oauthCodes, audit: this.audit },
      body,
      identity,
      issuerBaseUrl,
    );
  }

  oauthMetadata(issuerBaseUrl: string): OAuthHttpResponse {
    return authorizationServerMetadata(issuerBaseUrl);
  }

  oauthResourceMetadata(issuerBaseUrl: string, resourceSuffix = ""): OAuthHttpResponse {
    return protectedResourceMetadata(issuerBaseUrl, resourceSuffix);
  }

  /**
   * D29/D9: an `hmt_` bearer resolves SERVER-side to an Identity (assistant →
   * agent, read-only → auditor; never admin/owner) or null → 401. The token
   * service audits every miss/denial, including transitive client revocation.
   */
  resolveOAuthIdentity(plaintext: string): Promise<OAuthTokenIdentity | null> {
    return this.oauthTokens.resolve(plaintext);
  }

  // ---------------------------------------------------------------------------
  // M9 #9 (E19–E22) — company skill library. Registration flows through the
  // write path (E19/D10); vetting / invocation / override each audit (E20);
  // visibility is the ancestor-prefix ACL (E21); an unvetted skill is blocked
  // from invocation absent an audited admin override (E22).
  // ---------------------------------------------------------------------------

  registerSkill(identity: Identity, input: RegisterSkillInput): Promise<RegisterSkillResult> {
    return this.skills.register(identity, input);
  }

  /** Edit one exact current skill; scope and key resolve from its stored row. */
  updateSkill(
    identity: Identity,
    skillId: string,
    input: UpdateSkillInput,
  ): Promise<RegisterSkillResult> {
    return this.skills.update(identity, skillId, input);
  }

  /** Admin registration targeted at a server-resolved visible team (D9). */
  async registerSkillForTeam(
    identity: Identity,
    teamId: string,
    input: RegisterSkillInput,
  ): Promise<RegisterSkillResult> {
    let namespace: Namespace;
    try {
      namespace = await consoleResolveTeamNamespace(this.consoleSlice(identity), identity, teamId);
    } catch (err) {
      const denied = err instanceof AuthzError || err instanceof TeamBadRequestError;
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op: "write",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "skill-register",
        result: denied ? "denied" : "error",
        detail: denied
          ? "skill-register team target denied"
          : "skill-register team target resolution failed",
      });
      throw err;
    }
    return this.skills.register({ ...identity, namespace }, input);
  }

  /** Library view: every visible current skill merged with its usage rollup. */
  async listSkills(
    identity: Identity,
  ): Promise<Array<SkillRecord & { riskBand: SkillRiskBand; usage: SkillUsageSummary | null }>> {
    const [records, usage] = await Promise.all([
      this.skills.list(identity),
      this.skillUsage.summary(identity),
    ]);
    return records.map((record) => ({
      ...record,
      usage: usage.get(record.id) ?? null,
    }));
  }

  getSkill(identity: Identity, skillId: string): Promise<SkillRecord> {
    return this.skills.get(identity, skillId);
  }

  updateSkillLabels(
    identity: Identity,
    skillId: string,
    input: UpdateSkillLabelsInput,
  ): Promise<SkillRecord> {
    return this.skills.updateLabels(identity, skillId, input);
  }

  skillLabelHistory(
    identity: Identity,
    skillId: string,
  ): Promise<SkillLabelHistoryRecord[]> {
    return this.skills.labelHistory(identity, skillId);
  }

  /** E22 gate + E20 audit + usage rollup, atomically, for any resolved identity. */
  async invokeSkill(identity: Identity, skillKey: string): Promise<SkillInvokeDecision> {
    await this.requireOAuthTool(identity, "skill_invoke");
    return this.skills.invoke(identity, skillKey);
  }

  vetSkill(identity: Identity, skillId: string): Promise<VetSkillResult> {
    return this.skillVetting.vet(identity, skillId);
  }

  overrideSkill(identity: Identity, skillId: string, reason: string): Promise<SkillRecord> {
    return this.skills.override(identity, skillId, reason);
  }

  retireSkill(identity: Identity, skillId: string): Promise<SkillRecord> {
    return this.skills.retire(identity, skillId);
  }

  /** S16: team-admin approval of a pending member submission (audited, D4). */
  approveSkill(identity: Identity, skillId: string): Promise<SkillRecord> {
    return this.skills.approve(identity, skillId);
  }

  /** S16: team-admin rejection with a mandatory reason (audited, D4). */
  rejectSkill(identity: Identity, skillId: string, reason: string): Promise<SkillRecord> {
    return this.skills.reject(identity, skillId, reason);
  }

  /** S16: governed download — approved AND vetted current rows only (audited, D4). */
  exportSkill(identity: Identity, skillId: string): Promise<SkillExport> {
    return this.skills.exportSkill(identity, skillId);
  }

  /**
   * M9 #18 (D31/E31): record a per-turn answer outcome. The body is untrusted —
   * parseAnswerOutcomeBody rejects identity-shaped fields (D9); the service
   * audits ok/denied in the same transaction as the row (E32). E27: an OAuth
   * bearer needs the 'answer_outcome' tool grant — a governance write is a
   * tool like any other, and an empty allowlist grants NO tools.
   */
  async recordAnswerOutcome(
    identity: Identity,
    body: unknown,
  ): Promise<RecordAnswerOutcomeResult> {
    await this.requireOAuthTool(identity, "answer_outcome");
    return this.feedback.record(identity, parseAnswerOutcomeBody(body));
  }

  /** M9 #18 (E33): derived accuracy rollup — never asserted by a caller. */
  accuracyRollup(
    identity: Identity,
    window?: AccuracyWindow,
  ): Promise<AccuracyRollup> {
    return this.feedback.accuracy(identity, window ?? {});
  }

  /** M9 #19: automation catalog merged with the caller's org rows. */
  listAutomations(identity: Identity): Promise<AutomationView[]> {
    return listAutomationsEndpoint(this.automations, identity);
  }

  /** M9 #19: enable/disable/configure one automation template (owner/admin). */
  configureAutomation(identity: Identity, body: unknown): Promise<OrgAutomation> {
    return configureAutomationEndpoint(this.automations, identity, body);
  }

  /**
   * M9 #19 (E36/E37): claim and run due durable `automation` jobs. A kernel
   * without the consolidation lane has no runner — report an idle pass rather
   * than failing the poller (brownout).
   */
  runAutomationJobsOnce(limit = 10): Promise<AutomationRunSummary> {
    if (!this.automationRunner) {
      return Promise.resolve({ claimed: 0, completed: 0, proposals: 0 });
    }
    return this.automationRunner.runAutomationJobsOnce(limit);
  }

  /** S3 people roster (human users ∪ agent badges) for the caller's subtree. */
  people(identity: Identity): Promise<People> {
    return consolePeople(this.consoleSlice(identity), identity);
  }

  /** Human-only Teams directory; does not load or return machine principals. */
  teamDirectory(identity: Identity): Promise<TeamDirectory> {
    return consoleTeamDirectory(this.consoleSlice(identity), identity);
  }

  /** S13 teams inside the caller's subtree, each with its member roster. */
  listTeams(identity: Identity): Promise<Team[]> {
    return consoleListTeams(this.consoleSlice(identity), identity);
  }

  /** Read-only Knowledge Review sync activity for the caller's visible spaces. */
  async knowledgeSyncStatus(identity: Identity): Promise<KnowledgeSyncStatusResult> {
    const runs = await this.knowledgeSyncRunsForSpaces(
      await this.visibleKnowledgeSyncSpaces(identity),
    );
    return {
      runs,
      retentionDays: KNOWLEDGE_SYNC_HISTORY_DAYS,
      totals: knowledgeSyncTotals(runs),
    };
  }

  /**
   * Owner-triggered Knowledge Review catch-up. Team ids resolve to namespaces
   * server-side; an organization sync fans out into isolated per-team chains.
   */
  async queueKnowledgeSync(
    identity: Identity,
    target: KnowledgeSyncTarget,
  ): Promise<KnowledgeSyncQueueResult> {
    if (identity.role !== "owner") {
      throw new AuthzError("knowledge sync requires the owner role");
    }
    if (!this.consolidation || !this.automationRunner) {
      throw new Error("knowledge sync requires HALOMEM_COLD_KEK");
    }

    let spaces: Array<{ id: string; name: string; namespace: Namespace }>;
    if (target.scope === "organization") {
      const teamSpaces = (await consoleListTeams(this.consoleSlice(identity), identity))
        .map((team) => ({ id: team.id, name: team.name, namespace: team.namespace }));
      const teamLocalOwner = teamSpaces.some((space) => space.namespace === identity.namespace);
      if (!isRootOwner(identity) && (identity.namespace === "" || teamLocalOwner)) {
        throw new AuthzError("organization knowledge sync requires the organization owner");
      }
      spaces = identity.namespace === ""
        ? teamSpaces
        : [
            { id: "organization-root", name: "Organization memory", namespace: identity.namespace },
            ...teamSpaces,
          ];
    } else {
      const namespace = await consoleResolveTeamNamespace(
        this.consoleSlice(identity),
        identity,
        target.teamId,
      );
      const visible = await consoleListTeams(this.consoleSlice(identity), identity);
      const team = visible.find((candidate) =>
        candidate.id === target.teamId && candidate.namespace === namespace
      );
      if (!team) throw new TeamBadRequestError(`no team with id '${target.teamId}'`);
      spaces = [{ id: team.id, name: team.name, namespace: team.namespace }];
    }

    for (const space of spaces) {
      await this.automations.syncNow(identity, space.namespace);
    }
    const runs = await this.knowledgeSyncRunsForSpaces(spaces);
    return {
      status: "queued",
      scope: target.scope,
      queuedSpaces: spaces.map((space) => ({ id: space.id, name: space.name })),
      runs,
    };
  }

  private async visibleKnowledgeSyncSpaces(
    identity: Identity,
  ): Promise<Array<{ id: string; name: string; namespace: Namespace }>> {
    const teams = await consoleListTeams(this.consoleSlice(identity), identity);
    const spaces = teams.map((team) => ({ id: team.id, name: team.name, namespace: team.namespace }));
    const organizationOwner = identity.role === "owner" && identity.namespace !== "" &&
      !spaces.some((space) => space.namespace === identity.namespace);
    return organizationOwner
      ? [{ id: "organization-root", name: "Organization memory", namespace: identity.namespace }, ...spaces]
      : spaces;
  }

  private async knowledgeSyncRunsForSpaces(
    spaces: Array<{ id: string; name: string; namespace: Namespace }>,
  ): Promise<KnowledgeSyncRunRecord[]> {
    if (spaces.length === 0) return [];
    const namespaceParams = spaces.map((space) => space.namespace);
    const namespaceList = namespaceParams.map((_, index) => `$${index + 1}`).join(", ");
    const spaceByNamespace = new Map(spaces.map((space) => [space.namespace, space]));
    const automationResult = await this.db.query(
      `SELECT id, namespace, not_before, last_run_status, last_error
         FROM org_automations
        WHERE template_id = 'fresh-summaries'
          AND namespace IN (${namespaceList})`,
      namespaceParams,
    );
    const automations = (automationResult.rows as Record<string, unknown>[])
      .map((row) => ({
        id: String(row.id),
        namespace: String(row.namespace),
        notBefore: knowledgeSyncIsoOrNull(row.not_before),
        lastRunStatus: knowledgeSyncLastRunStatus(row.last_run_status),
        lastError: typeof row.last_error === "string" ? row.last_error : null,
      }));

    const automationIds = automations.map((automation) => automation.id);
    const jobsByAutomation = new Map<string, Record<string, unknown>[]>();
    if (automationIds.length > 0) {
      const automationIdList = automationIds.map((_, index) => `$${index + 1}`).join(", ");
      const jobResult = await this.db.query(
        `SELECT id, payload->>'automationId' AS automation_id, state,
                available_at, created_at, updated_at
           FROM durable_jobs
          WHERE kind = 'automation'
            AND state IN ('queued', 'running')
            AND payload->>'automationId' IN (${automationIdList})
          ORDER BY available_at ASC, created_at ASC`,
        automationIds,
      );
      for (const row of jobResult.rows as Record<string, unknown>[]) {
        const automationId = String(row.automation_id ?? "");
        if (!automationId) continue;
        const rows = jobsByAutomation.get(automationId) ?? [];
        rows.push(row);
        jobsByAutomation.set(automationId, rows);
      }
    }

    const cutoffParam = `$${namespaceParams.length + 1}`;
    const historyResult = await this.db.query(
      `SELECT seq, ts, namespace, result, detail
         FROM audit_log
        WHERE op = 'automation_run'
          AND purpose = 'automation'
          AND detail LIKE 'run template=fresh-summaries%'
          AND namespace IN (${namespaceList})
          AND ts >= ${cutoffParam}
        ORDER BY ts DESC, seq DESC`,
      [
        ...namespaceParams,
        new Date(Date.now() - KNOWLEDGE_SYNC_HISTORY_MS).toISOString(),
      ],
    );
    const automationByNamespace = new Map(automations.map((automation) => [
      automation.namespace,
      automation,
    ]));
    const nowMs = Date.now();
    const activeRuns: KnowledgeSyncRunRecord[] = [];
    const scheduledRuns: KnowledgeSyncRunRecord[] = [];
    for (const space of spaces) {
      const automation = automationByNamespace.get(space.namespace);
      if (!automation) continue;
      const jobs = jobsByAutomation.get(automation.id) ?? [];
      const activeJob =
        jobs.find((job) => job.state === "running") ??
        jobs.find((job) => {
          const availableAt = knowledgeSyncIsoOrNull(job.available_at);
          return job.state === "queued" &&
            availableAt !== null &&
            new Date(availableAt).getTime() <= nowMs;
        }) ?? null;
      const status: KnowledgeSyncRunStatus = activeJob?.state === "running"
        ? "running"
        : activeJob ? "queued" : "scheduled";
      const run: KnowledgeSyncRunRecord = {
        id: space.id,
        name: space.name,
        status,
        queuedAt: activeJob && activeJob.state === "queued"
          ? knowledgeSyncIsoOrNull(activeJob.created_at)
          : null,
        startedAt: activeJob && activeJob.state === "running"
          ? knowledgeSyncIsoOrNull(activeJob.updated_at)
          : null,
        completedAt: null,
        nextRunAt: status === "scheduled" ? automation.notBefore : null,
        lastRunStatus: automation.lastRunStatus,
        lastError: automation.lastError,
        processed: null,
        proposals: null,
        hasMore: null,
      };
      (activeJob ? activeRuns : scheduledRuns).push(run);
    }

    const historyRuns = (historyResult.rows as Record<string, unknown>[]).flatMap((row) => {
      const namespace = typeof row.namespace === "string" ? row.namespace : "";
      const space = spaceByNamespace.get(namespace);
      if (!space) return [];
      const detail = typeof row.detail === "string" ? row.detail : null;
      const counts = parseKnowledgeSyncRunDetail(detail);
      const failed = row.result === "error";
      const degraded = !failed && detail?.includes("credits-exhausted") === true;
      return [{
        id: space.id,
        name: space.name,
        status: failed ? "failed" as const : "completed" as const,
        queuedAt: null,
        startedAt: null,
        completedAt: knowledgeSyncIsoOrNull(row.ts),
        nextRunAt: null,
        lastRunStatus: failed ? "failed" as const : degraded ? "degraded" as const : "ok" as const,
        lastError: failed ? "Sync failed" : null,
        processed: counts.processed,
        proposals: counts.proposals,
        hasMore: counts.hasMore,
      }];
    });

    return [...activeRuns, ...historyRuns, ...scheduledRuns];
  }

  /** S13: create a team under the caller's namespace (owner/admin only, D9). */
  createTeam(identity: Identity, input: CreateTeamInput): Promise<Team> {
    return consoleCreateTeam(this.consoleSlice(identity), identity, input);
  }

  /** S13: rename display text without changing the permanent team address. */
  renameTeam(identity: Identity, teamId: string, name: string): Promise<Team> {
    return consoleRenameTeam(this.consoleSlice(identity), identity, teamId, name);
  }

  /** S13: owner-only reversible team archive. */
  setTeamArchived(identity: Identity, teamId: string, archived: boolean): Promise<Team> {
    return consoleSetTeamArchived(this.consoleSlice(identity), identity, teamId, archived);
  }

  /** S13: change a server-resolved team's company-memory visibility. */
  changeTeamMemoryAccess(
    identity: Identity,
    teamId: string,
    mode: TeamMemoryAccessMode,
  ): Promise<Team> {
    return consoleChangeTeamMemoryAccess(this.consoleSlice(identity), identity, teamId, mode);
  }

  /** S13: add a visible person to a subtree team (owner/admin only). */
  addTeamMember(identity: Identity, teamId: string, email: string): Promise<Team[]> {
    return consoleAddTeamMember(this.consoleSlice(identity), identity, teamId, email);
  }

  /** Invite a human into a server-resolved subtree team (owner/admin, D9). */
  inviteTeamMember(
    identity: Identity,
    teamId: string,
    input: InviteTeamMemberInput,
  ): Promise<IssuedInvitation> {
    return consoleInviteTeamMember(
      this.consoleSlice(identity),
      this.invitations,
      identity,
      teamId,
      input,
    );
  }

  rotateTeamInvitation(
    identity: Identity,
    teamId: string,
    invitationId: string,
    kind: "reminder" | "reinvite",
  ): Promise<IssuedInvitation> {
    return consoleRotateTeamInvitation(
      this.consoleSlice(identity),
      this.invitations,
      identity,
      teamId,
      invitationId,
      kind,
    );
  }

  revokeTeamInvitation(
    identity: Identity,
    teamId: string,
    invitationId: string,
  ): Promise<{ revoked: boolean }> {
    return consoleRevokeTeamInvitation(
      this.consoleSlice(identity),
      this.invitations,
      identity,
      teamId,
      invitationId,
    );
  }

  personAccessImpact(identity: Identity, userId: string): Promise<PersonAccessImpact> {
    return consolePersonAccessImpact(this.consoleSlice(identity), identity, userId);
  }

  changePersonAccessState(
    identity: Identity,
    userId: string,
    input: { status: "active" | "disabled"; revokeCreatedKeys?: boolean; reason?: string },
  ): Promise<PersonAccessImpact> {
    return consoleChangePersonAccessState(this.consoleSlice(identity), identity, userId, input);
  }

  /**
   * Change an existing team member's role (owner-only, subtree-scoped).
   * `role` is a PRODUCT role (`root`/`admin`/`member`, D41) — the internal
   * value is derived through `fromProductRole` inside the handler.
   */
  changeTeamMemberRole(
    identity: Identity,
    teamId: string,
    userId: string,
    role: string,
  ): Promise<Team[]> {
    return consoleChangeTeamMemberRole(
      this.consoleSlice(identity),
      identity,
      teamId,
      userId,
      role,
    );
  }

  /** S13: remove a person from a subtree team (owner/admin only). */
  removeTeamMember(identity: Identity, teamId: string, userId: string): Promise<Team[]> {
    return consoleRemoveTeamMember(this.consoleSlice(identity), identity, teamId, userId);
  }

  /**
   * S5 memory map for ONE namespace (asserted inside the caller's subtree by the
   * handler — a team admin can never map a sibling).
   */
  async memoryMap(identity: Identity, namespace: Namespace): Promise<MemoryMap> {
    return this.withTeamMemoryRead(identity, async (effectiveIdentity) => {
      const [map, governedPins] = await Promise.all([
        consoleMemoryMap(
          this.consoleSlice(effectiveIdentity),
          effectiveIdentity,
          namespace,
        ),
        this.pins.list(identity, namespace),
      ]);
      return { ...map, governedPins };
    });
  }

  // ---------------------------------------------------------------------------
  // M10 — role-scoped memory graph + root View-as (CONTRACTS-M10-ACCESS).
  // The transport resolves the cookie session; everything below is keyed on
  // server-owned ids only (D9). The projection is resolved FRESH per request
  // (no cross-request cache), so a revoked grant is effective on the next
  // call; the projection hash is the partition key for anything derived.
  // ---------------------------------------------------------------------------

  /** Raw session-cookie token → full console Session (userId + role), or null. */
  resolveConsoleSession(token: string): Promise<Session | null> {
    return this.sessions.resolve(token);
  }

  /**
   * D59: profile portfolio for the authenticated human session. There is no
   * caller-supplied subject: the user id comes only from the resolved Identity.
   * A user's home namespace is included even if an old install lacks the
   * corresponding membership row; additional rows require an actual durable
   * org_team_members membership.
   */
  async memberProfile(identity: Identity): Promise<{
    homeNamespace: Namespace;
    displayName: string;
    avatar: string | null;
    teams: Array<{ id: string; name: string; namespace: Namespace; isHome: boolean }>;
  } | null> {
    if (identity.role === "agent" || identity.sessionUserId === undefined) return null;
    const user = await this.db.query(
      `SELECT id, namespace, display_name, avatar FROM users WHERE id = $1 AND status = 'active'`,
      [identity.sessionUserId],
    );
    if (user.rows.length !== 1) return null;
    const homeNamespace = String(user.rows[0].namespace) as Namespace;
    const displayName = String(user.rows[0].display_name);
    const rawAvatar = user.rows[0].avatar;
    const avatar = rawAvatar === null || rawAvatar === undefined || String(rawAvatar) === ""
      ? null
      : String(rawAvatar);
    const memberships = await this.db.query(
      `SELECT t.id, t.name, t.namespace
         FROM org_teams t
        WHERE t.namespace = $2
           OR EXISTS (
                SELECT 1 FROM org_team_members tm
                 WHERE tm.team_id = t.id AND tm.user_id = $1
              )
        ORDER BY t.namespace ASC, t.name ASC, t.id ASC`,
      [identity.sessionUserId, homeNamespace],
    );
    const teams = memberships.rows.map((row) => {
      const namespace = String(row.namespace) as Namespace;
      return {
        id: String(row.id),
        name: String(row.name),
        namespace,
        isHome: namespace === homeNamespace,
      };
    });
    if (!teams.some((team) => team.isHome)) {
      const segments = homeNamespace.split("/").filter(Boolean);
      teams.push({
        id: "",
        name: segments.at(-1) ?? "Organization root",
        namespace: homeNamespace,
        isHome: true,
      });
    }
    return { homeNamespace, displayName, avatar, teams };
  }

  /** S18 Settings → Organization: the tenant's display identity for this caller. */
  organizationSettings(identity: Identity): Promise<OrganizationSettingsView | null> {
    return consoleReadOrganizationSettings(this.consoleSlice(identity), identity);
  }

  /** S18 Settings → Organization: rename / re-mark the tenant (owner/admin). */
  updateOrganizationSettings(
    identity: Identity,
    body: OrganizationSettingsUpdate,
  ): Promise<OrganizationSettingsView> {
    return consoleUpdateOrganizationSettings(this.consoleSlice(identity), body, identity);
  }

  /** S18 Settings → Profile: the session user's own display name (self-service). */
  updateMemberDisplayName(
    identity: Identity,
    body: { displayName?: unknown },
  ): Promise<{ displayName: string }> {
    return consoleUpdateMemberDisplayName(this.consoleSlice(identity), body, identity);
  }

  /** S18 Settings -> Profile: presentation-only name and/or avatar. */
  updateMemberProfile(
    identity: Identity,
    body: MemberProfileUpdate,
  ): Promise<MemberProfileView> {
    return consoleUpdateMemberProfile(this.consoleSlice(identity), body, identity);
  }

  /** Server-resolved projection for one human subject (fail-closed). */
  private projectionForUser(subjectUserId: string): Promise<AccessProjection> {
    return resolveProjection(
      userProjectionDeps({ db: this.db, grants: this.accessGrants }),
      { subjectId: subjectUserId },
    );
  }

  /** Projection for a preview subject: an actual user, or a role simulation. */
  private async projectionForSubject(
    subject: PreviewSubject,
    tenantId: Namespace,
  ): Promise<AccessProjection> {
    if (subject.kind === "user") return this.projectionForUser(subject.subjectUserId);
    // Opaque area ids re-resolved inside the ROOT'S tenant; unknown/foreign
    // ids resolve to nothing and contribute nothing (D9/D46).
    const areaRoots = await this.accessGrants.resolveResourceRoots(
      tenantId,
      subject.functionalAreaIds,
    );
    if (tenantId === "") {
      // The "" ORGANIZATION root (single-org installs): resolveResourceRoots
      // treats "" as containing everything, so drop any root that belongs to
      // a registered tenant — the org-root simulation must never span a
      // customer tenant (PRD §14.1, D43).
      const firsts = [...new Set(
        [...areaRoots.values()].map((ns) => ns.split("/")[0] ?? "").filter(Boolean),
      )];
      if (firsts.length > 0) {
        const placeholders = firsts.map((_, i) => `$${i + 1}`).join(", ");
        const registered = await this.db.query(
          `SELECT id FROM tenants WHERE id IN (${placeholders})`,
          firsts,
        );
        const blocked = new Set(registered.rows.map((r) => String((r as { id: unknown }).id)));
        for (const [areaId, ns] of [...areaRoots]) {
          const first = ns.split("/")[0] ?? "";
          if (ns === "" || blocked.has(first)) areaRoots.delete(areaId);
        }
      }
    }
    return simulatedRoleProjection(
      { db: this.db, grants: this.accessGrants },
      tenantId,
      subject.role,
      areaRoots,
    );
  }

  /**
   * GET /v1/memory-graph — one projection in, one graph out (D40). Under a
   * valid preview credential the SUBJECT'S projection feeds the SAME
   * function while audit stays attributed to the root session actor (D43).
   * The response adds the S5 topology (same shape as memory-map's) built
   * under the same predicate, plus per-entity "why" lines during previews.
   */
  async memoryGraphView(
    session: Session,
    opts: MemoryGraphOptions,
    previewToken: string | null,
  ): Promise<MemoryGraphPage & { topology: MemoryTopology; why?: Record<string, string> }> {
    let preview: ResolvedPreview | null = null;
    if (previewToken !== null && previewToken.trim() !== "") {
      // Invalid/expired/foreign tokens audit a denial and resolve to null.
      preview = await viewAsResolvePreview(this.viewAsDeps, previewToken, session);
      if (preview === null) {
        // D43/E6: a presented-but-dead credential must NEVER silently fall
        // back to the caller's own (wider) view — the client would keep its
        // "Viewing as <subject>" banner over root's full graph, the exact
        // misreading View-as exists to prevent. Uniform not-found (D46).
        throw new PreviewNotFoundError();
      }
    }
    const tenantId = tenantRootOfNamespace(session.namespace);
    const projection = preview === null
      ? await this.projectionForUser(session.userId)
      : await this.projectionForSubject(preview.subject, tenantId);
    // Two serializations of ONE already-resolved projection - neither feeds
    // the other, so they run together. Serially this doubled the wait behind
    // every S5 space pick.
    const pagePending = getMemoryGraph(
      {
        db: this.db,
        audit: { append: (event) => this.audit.append(event) },
        auditActor: session.actor,
        auditAgentId: "console",
      },
      projection,
      opts,
    );
    const topologyPending = memoryGraphTopology(
      { db: this.db, getPolicy: (ns) => this.getPolicy(ns) },
      projection,
      opts.scopeId,
    );
    // Both reject with the same uniform not-found on an unauthorized scope,
    // but only getMemoryGraph writes the D4 denial row. Awaiting the page
    // FIRST keeps that audit-then-throw order; the sink keeps the concurrent
    // topology rejection from surfacing as an unhandled rejection.
    topologyPending.catch(() => {});
    const page = await pagePending;
    const topology = await topologyPending;
    if (preview !== null) {
      return { ...page, topology, why: memoryGraphWhy(projection, topology) };
    }
    return { ...page, topology };
  }

  /** GET /v1/root/view-as/targets — root-only, tenant-scoped (D43/D9). */
  async viewAsTargets(session: Session): Promise<{
    people: Array<{ id: string; name: string; email: string; role: string }>;
    functions: Array<{ id: string; label: string }>;
  }> {
    const targets = await listPreviewTargets(this.viewAsDeps, session);
    return {
      people: targets.people.map((p) => ({
        id: p.id,
        name: p.displayName,
        email: p.email,
        role: p.role,
      })),
      functions: targets.areas.map((a) => ({ id: a.id, label: a.name })),
    };
  }

  /**
   * POST /v1/root/view-as/sessions — mint a preview (subject XOR
   * role+areas, reason required). The token is forwarded ONCE and never
   * logged; labels are short server-resolved display strings.
   */
  async viewAsStart(
    session: Session,
    body: Record<string, unknown>,
  ): Promise<{
    id: string;
    token: string;
    subjectLabel: string;
    scopeLabel: string;
    expiresAt: string;
  }> {
    const input: CreatePreviewInput = {
      rootSession: session,
      reason: typeof body.reason === "string" ? body.reason : "",
    };
    if (typeof body.subjectUserId === "string" && body.subjectUserId !== "") {
      input.subjectUserId = body.subjectUserId;
    }
    if (body.role !== undefined) {
      // Validated inside createPreviewSession (only admin|member pass).
      input.simulatedRole = body.role as CreatePreviewInput["simulatedRole"];
    }
    if (Array.isArray(body.functionalAreaIds)) {
      input.functionalAreaIds = body.functionalAreaIds.map((v) => String(v));
    }
    const created = await createPreviewSession(this.viewAsDeps, input);
    const subject = created.session.subject;
    let subjectLabel: string;
    let scopeLabel: string;
    if (subject.kind === "user") {
      const res = await this.db.query(`SELECT email, role FROM users WHERE id = $1`, [
        subject.subjectUserId,
      ]);
      const row = res.rows[0] as { email?: unknown; role?: unknown } | undefined;
      subjectLabel = String(row?.email ?? "");
      // PRD §8.2: a person banner shows display name + ROLE — never a scope
      // claim like "All accessible" (that string is the scope-picker default
      // only, §13/J3).
      scopeLabel = productRoleLabel(toProductRole(String(row?.role ?? "member")).role);
    } else {
      subjectLabel = productRoleLabel(subject.role);
      const ids = [...subject.functionalAreaIds];
      const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
      const res = await this.db.query(
        `SELECT name FROM org_teams WHERE id IN (${placeholders}) ORDER BY name ASC`,
        ids,
      );
      scopeLabel = (res.rows as Array<{ name: unknown }>)
        .map((r) => String(r.name))
        .join(", ");
    }
    return {
      id: created.session.id,
      token: created.token,
      subjectLabel,
      scopeLabel,
      expiresAt: created.session.expiresAt,
    };
  }

  /** DELETE /v1/root/view-as/sessions/:id — idempotent exit (D47). */
  async viewAsEnd(
    session: Session,
    id: string,
  ): Promise<{ ok: true; id: string; endedAt: string | null }> {
    const ended = await endPreviewSession(this.viewAsDeps, id, session);
    return { ok: true, id: ended.id, endedAt: ended.endedAt };
  }

  /** Transport seam: raw preview header value → preview subject, or null. */
  viewAsResolve(session: Session, token: string): Promise<ResolvedPreview | null> {
    return viewAsResolvePreview(this.viewAsDeps, token, session);
  }

  /** Transport seam: audit + reject a mutation under a preview credential. */
  viewAsRejectMutation(
    session: Session,
    previewSessionId: string,
    method: string,
    path: string,
  ): Promise<never> {
    return rejectPreviewMutation(this.viewAsDeps, session, previewSessionId, method, path);
  }

  /**
   * S8 audit search: the new AuditLog.search scoped to the caller's subtree
   * (own namespace + ancestors + descendants), enumerated to a pure IN-list.
   */
  auditSearch(
    identity: Identity,
    filters?: AuditSearchFilters,
  ): Promise<AuditEvent[]> {
    return consoleAuditSearch(this.consoleSlice(identity), identity, filters);
  }

  /** Exact S8 aggregates over the complete filtered, scoped audit trail. */
  auditSummary(
    identity: Identity,
    filters?: AuditSearchFilters,
  ): Promise<AuditSummary> {
    return consoleAuditSummary(this.consoleSlice(identity), identity, filters);
  }

  /**
   * S8 audit CSV: the COMPLETE filtered trail (keyset-paged past the screen's
   * 500-row cap), governed as egress — it appends its own `export` audit row.
   */
  auditExportCsv(
    identity: Identity,
    filters?: AuditSearchFilters,
  ): Promise<AuditCsvExport> {
    return consoleAuditExportCsv(this.consoleSlice(identity), identity, filters);
  }

  /** S6 sources view: governance subtree, or member ancestors + exact team. */
  async sourcesView(identity: Identity): Promise<SourcesView> {
    if (identity.role !== "member") {
      return consoleSourcesView(this.consoleSlice(identity), identity);
    }

    const visibleNamespaces = namespaceAncestors(identity.namespace);
    const rows = await this.sources.listExact(visibleNamespaces);
    const slice = {
      ...this.consoleSlice(identity),
      sources: { list: async () => rows },
    };
    const view = await consoleSourcesView(slice, identity, { skipSubtreeAggregates: true });
    return {
      ...view,
      // A reusable credential id is a secret reference. Members only need the
      // connection's content-free operational metadata, never that reference.
      sources: view.sources.map((source) => ({ ...source, credentialId: null })),
    };
  }

  /**
   * S6 connection drawer: the lineage of ONE source — what it wrote into
   * memory. Members are excluded at the transport (D56: subtree aggregates are
   * not part of the exact member projection), so this always runs the
   * governance path.
   */
  sourceLineage(identity: Identity, sourceId: string): Promise<SourceLineage> {
    return consoleSourceLineageView(this.consoleSlice(identity), identity, sourceId);
  }

  /** S11 conflict review: open trust disputes visible to the caller. */
  listDisputes(identity: Identity): Promise<DisputeView[]> {
    return this.disputes.list(identity);
  }

  /** Queue a D9-scoped organization or team memory conflict scan. */
  async requestConflictScan(
    identity: Identity,
    input: ConflictScanRequest,
  ): Promise<ConflictScanRunView> {
    await this.consumeQuota(identity, "conflict_scan", "write", "conflict-scan");
    const targetNamespace = input.targetTeamId
      ? await consoleResolveTeamNamespace(this.consoleSlice(identity), identity, input.targetTeamId)
      : identity.namespace;
    return this.conflictScans.request(identity, input, targetNamespace);
  }

  /**
   * One bounded vector-repair pass. Exposed for the process poller and for
   * hermetic tests; `cli.ts reembed` drives the same module for an operator who
   * wants to force convergence rather than wait for the poller.
   *
   * Single-flight: a slow embedding provider must not let passes pile up.
   */
  runEmbeddingBackfillOnce(): Promise<BackfillResult> {
    if (this.embeddingBackfillWorker) return this.embeddingBackfillWorker;
    // Attributed to the platform namespace, not the row's owner: this is
    // maintenance the platform caused by changing embedder, and billing a
    // tenant for it would be wrong.
    const worker = runEmbeddingBackfillOnce(this.db, this.embedder)
      .then((result) => {
        if (result.repaired > 0 || (result.remaining > 0 && !this.embeddingBackfillIdle)) {
          this.logger.warn("re-embedding rows left vectorless by an embedder change", {
            repaired: result.repaired,
            remaining: result.remaining,
          });
        }
        this.embeddingBackfillIdle = result.remaining === 0;
        return result;
      });
    this.embeddingBackfillWorker = worker;
    void worker.finally(() => {
      if (this.embeddingBackfillWorker === worker) this.embeddingBackfillWorker = null;
    }).catch(() => undefined);
    return worker;
  }

  /** Bind the application runtime's exact Azure title model lane. */
  attachMemoryTitleExecutor(executor: MemoryTitleExecutor): void {
    this.memoryTitles.attach(executor);
    void this.runMemoryTitleJobsOnce().catch(() => undefined);
  }

  /** One bounded, single-flight title pass; each memory is one provider call. */
  runMemoryTitleJobsOnce(options: { limit?: number } = {}): Promise<MemoryTitleRunResult> {
    if (this.memoryTitleWorker) return this.memoryTitleWorker;
    const worker = this.memoryTitles.runOnce(options);
    this.memoryTitleWorker = worker;
    void worker.finally(() => {
      if (this.memoryTitleWorker === worker) this.memoryTitleWorker = null;
    }).catch(() => undefined);
    return worker;
  }

  /** One durable worker pass; exposed for the process poller and hermetic tests. */
  runConflictScanJobsOnce(): Promise<{ claimed: number; completed: number; failed: number }> {
    if (this.conflictScanWorker) return this.conflictScanWorker;
    const worker = this.conflictScans.runOnce();
    this.conflictScanWorker = worker;
    void worker.finally(() => {
      if (this.conflictScanWorker === worker) this.conflictScanWorker = null;
    }).catch(() => undefined);
    return worker;
  }

  /**
   * One bounded, single-flight autopilot pass (CA1). Kicked after writes and
   * safe to call from every replica: claims are lease-fenced.
   */
  runConflictAutopilotOnce(options: { limit?: number } = {}): Promise<ConflictAutopilotRunResult> {
    if (this.conflictAutopilotWorker) return this.conflictAutopilotWorker;
    const worker = this.conflictAutopilot.runOnce(options);
    this.conflictAutopilotWorker = worker;
    void worker.finally(() => {
      if (this.conflictAutopilotWorker === worker) this.conflictAutopilotWorker = null;
    }).catch(() => undefined);
    return worker;
  }

  /** One bounded, single-flight subject-derivation pass (CA8). */
  runEntityTagJobsOnce(options: { limit?: number } = {}): Promise<EntityTagRunResult> {
    if (this.entityTagWorker) return this.entityTagWorker;
    const worker = this.entityTagger.runOnce(options);
    this.entityTagWorker = worker;
    void worker.finally(() => {
      if (this.entityTagWorker === worker) this.entityTagWorker = null;
    }).catch(() => undefined);
    return worker;
  }

  getConflictScan(id: string, identity: Identity): Promise<ConflictScanRunView | null> {
    return this.conflictScans.get(id, identity);
  }

  latestConflictScan(identity: Identity): Promise<ConflictScanRunView | null> {
    return this.conflictScans.latest(identity);
  }

  recentConflictScans(identity: Identity): Promise<ConflictScanRunView[]> {
    return this.conflictScans.recent(identity);
  }

  async completeAgentSession(identity: Identity, input: unknown): Promise<AgentSessionSummaryView> {
    if (identity.role !== "agent") {
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "session_capture", memoryId: null, namespace: identity.namespace,
        purpose: "agent-session-summary", result: "denied", detail: "agent role required",
      });
      throw new AuthzError("agent identity is required for session capture");
    }
    try {
      await this.requireOAuthTool(identity, "agent_session_complete");
      await this.requireAgentOperation("write", identity);
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(), actor: identity.actor, agentId: identity.keyId,
        op: "session_capture", memoryId: null, namespace: identity.namespace,
        purpose: "agent-session-summary", result: "denied", detail: "session capture gate denied",
      });
      throw error;
    }
    await syscallGate(this.deps, identity, identity.keyId, "session_capture");
    return this.agentSessions.complete(identity, input);
  }

  reviewConflictFinding(
    identity: Identity,
    id: string,
    action: "acknowledge" | "dismiss",
    expectedRowVersion: number,
  ): Promise<{ id: string; status: "acknowledged" | "dismissed"; rowVersion: number }> {
    return this.conflictScans.review(identity, id, action, expectedRowVersion);
  }

  /** S11 conflict review: keep one side of a scan finding, retire the other. */
  resolveConflictFinding(
    identity: Identity,
    id: string,
    keep: "left" | "right",
    expectedRowVersion: number,
  ): Promise<{
    id: string;
    status: "resolved";
    rowVersion: number;
    keptMemoryId: string;
    retiredMemoryId: string;
  }> {
    return this.conflictScans.resolve(identity, id, keep, expectedRowVersion);
  }

  /** S11 ledger: undo one automatic decision (CA4 — autonomy stays reversible). */
  overturnConflictFinding(
    identity: Identity,
    id: string,
    expectedRowVersion: number,
  ): Promise<{
    id: string;
    status: "overturned";
    rowVersion: number;
    keptMemoryId: string;
    retiredMemoryId: string;
  }> {
    return this.conflictScans.overturn(identity, id, expectedRowVersion);
  }

  /**
   * The single open-conflict number every screen quotes. S6's data-quality tile
   * and S11's queue read THIS, so a count can never disagree with the list it
   * summarises.
   */
  async countOpenConflicts(identity: Identity): Promise<number> {
    const [disputes, findings] = await Promise.all([
      this.disputes.list(identity),
      this.conflictScans.countOpenFindings(identity),
    ]);
    return disputes.length + findings;
  }

  /** Unified S11 read model. Existing dispute resolution semantics stay unchanged. */
  async listConflicts(identity: Identity): Promise<{
    disputes: DisputeView[];
    scanFindings: ConflictScanFindingView[];
    latestScan: ConflictScanRunView | null;
    scans: ConflictScanRunView[];
    autoDecisions: ConflictAutoDecisionView[];
    ledger: ConflictLedgerView;
  }> {
    const [disputes, scanFindings, latestScan, scans, autoDecisions, health] =
      await Promise.all([
        this.disputes.list(identity),
        this.conflictScans.listFindings(identity),
        this.conflictScans.latest(identity),
        this.conflictScans.recent(identity),
        this.conflictScans.listAutoDecisions(identity),
        this.conflictAutopilot.ledgerHealth({
          namespace: identity.namespace,
          pattern: `${escapeLikePattern(identity.namespace)}/%`,
        }),
      ]);
    return {
      disputes,
      scanFindings,
      latestScan,
      scans,
      autoDecisions,
      ledger: {
        autoResolved: autoDecisions.length,
        // Both review lanes: scan/write findings awaiting a person, plus
        // write-path quarantines. One number, because S11 shows one queue.
        needsReview: scanFindings.length + disputes.length,
        pendingChecks: health.pendingChecks,
        detectionDegraded: health.detectionDegraded,
      },
    };
  }

  /** S11 conflict review: resolve one dispute (uphold-new | keep-old | edit). */
  resolveDispute(
    identity: Identity,
    disputeId: string,
    input: ResolveDisputeInput,
  ): Promise<ResolveDisputeResult> {
    return this.disputes.resolve(identity, disputeId, input);
  }

  // -------------------------------------------------------------------------
  // Syscall surface — D9: every call requires a resolved Identity.
  // -------------------------------------------------------------------------

  /** Audited facade-denial ops that get a companion usage_events row (E1). */
  private static readonly FACADE_USAGE_TRACKED_OPS = new Set<string>([
    "read", "search", "fault", "assemble",
  ]);

  /** D23: syscall attribution is resolved from the credential, never transport input. */
  private syscallAgentId(identity: Identity, supplied: string): string {
    return identity.role === "agent" ? identity.keyId : supplied;
  }

  private async requireAgentOperation(
    operation: AgentGatewayOperation,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<void> {
    if (identity.role !== "agent") return;
    const status = await this.gatewayGrants.operationStatus(identity.keyId, operation);
    if (!status.hasGrant || status.allowed) return;
    const op = operation === "source-read"
      ? "read"
      : operation === "live-result" ? "fault" : operation;
    const ts = new Date().toISOString();
    const auditSeq = await this.audit.appendWithSeq({
      ts,
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: "denied",
      detail: `gateway operation denied operation=${operation}`,
    });
    await this.recordFacadeDenialUsage(identity, ctx, auditSeq, ts, op);
    throw new AuthzError("agent operation denied by connection grant");
  }

  /**
   * D36/E1: facade-level denials (grant gate, legacy live-result) are audited
   * BEFORE the syscall runs, so they cannot ride the syscall's transaction —
   * emit the companion usage row best-effort (own transaction, zeros) so the
   * denials observation and the query ledger do not undercount. Only the
   * usage-tracked ops get a row (same set as the syscall instrumentation).
   */
  private async recordFacadeDenialUsage(
    identity: Identity,
    ctx: SyscallContext | undefined,
    auditSeq: number,
    ts: string,
    op: string,
  ): Promise<void> {
    if (!Kernel.FACADE_USAGE_TRACKED_OPS.has(op)) return;
    await recordUsageStandalone(
      this.db,
      {
        auditSeq,
        traceId: resolveTraceId(ctx?.traceId),
        ts,
        namespace: identity.namespace,
        actor: identity.actor,
        principal: identity.role === "agent" ? "agent" : "human",
        callerClass: identity.callerClass ?? "unclassified",
        op,
        tool: ctx?.tool ?? "kernel",
        result: "denied",
        latencyMs: 0,
        tokens: 0,
        returned: 0,
        driver: null,
        sourceTier: null,
        sourceIds: null,
        topScore: null,
      },
      {
        onFailure: (err) =>
          this.logger.warn("usage event write failed - denial outcome stands (brownout)", {
            error: err instanceof Error ? err.message : String(err),
          }),
      },
    );
  }

  /**
   * E27 (D29): the single server-side chokepoint for an OAuth client's tool
   * allowlist. The list rides on the RESOLVED OAuthTokenIdentity (snapshotted
   * from the client at issue time) — never a request payload — so it fences
   * every transport (HTTP, MCP, in-process) at the kernel syscall layer.
   * API-key / session identities carry no allowedTools and pass untouched.
   * Public so the application runtime (copilot lane) fences its billable
   * entrypoint through the SAME chokepoint — see
   * HaloApplicationRuntime.completeCopilot ('copilot_complete').
   */
  async requireOAuthTool(identity: Identity, tool: string): Promise<void> {
    const allowed = (identity as Partial<OAuthTokenIdentity>).allowedTools;
    if (allowed === undefined) return;
    const ok = await enforceAllowedTools(this.audit, identity as OAuthTokenIdentity, tool);
    if (!ok) {
      throw new AuthzError(`tool '${tool}' is not granted to this oauth client`);
    }
  }

  /**
   * M9 #6 (E12–E14): ACL-scoped llms.txt / memory-index manifest. A read
   * syscall — same agent-operation gate as mem_read; the module re-audits
   * ok/denied/error itself (D4).
   */
  async memManifest(
    args: MemManifestArgs,
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
  ): Promise<ManifestResult> {
    await this.requireOAuthTool(identity, "mem_manifest");
    await this.requireAgentOperation("read", identity);
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      memManifest(
        this.deps,
        args,
        effectiveIdentity,
        this.syscallAgentId(identity, agentId),
      ));
  }

  /**
   * M9 #11a (E28–E30): the UNAUTHENTICATED public discovery tier. The org
   * slug is the only caller input and resolves server-side to a tenant root
   * namespace (E28); the module itself fences to explicitly public-classified
   * canonical rows, redacts provenance, and audits every outcome — including
   * the byte-identical 404 for unknown/suspended/empty orgs (E29/E30, D4).
   */
  publicDiscovery(
    orgSlug: string,
    format: PublicDiscoveryFormat,
  ): Promise<PublicDiscoveryResponse> {
    return servePublicDiscovery(
      {
        index: this.index,
        tenants: this.tenants,
        audit: this.audit,
        rateLimiter: this.rateLimiter,
      },
      orgSlug,
      format,
    );
  }

  /**
   * D28 boundary rule 4: the export egress lane runs the SAME per-syscall
   * gate as every read syscall — credential-active re-check, tenant
   * suspension, and the caller's token bucket — before any governance
   * decision or render. Without it a suspended tenant's key (denied on every
   * other route) could still bulk-export, with no rate limit. Every denial
   * writes an `export` audit row (D4).
   */
  private async gateExport(identity: Identity): Promise<void> {
    const auditExportDenied = async (detail: string): Promise<void> => {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: identity.role === "agent" ? identity.keyId : "export",
        op: "export",
        memoryId: null,
        namespace: identity.namespace,
        purpose: null,
        result: "denied",
        detail,
      });
    };
    if (!(await this.isIdentityActive(identity))) {
      const detail = "credential revoked or inactive";
      await auditExportDenied(detail);
      throw new AuthzError(detail);
    }
    const tenant = await this.tenants.resolveTenant(identity.namespace);
    try {
      tenantGate(tenant);
    } catch (err) {
      if (err instanceof TenantSuspendedError) await auditExportDenied(err.message);
      throw err;
    }
    const policy = await this.policyStore.getFresh(identity.namespace);
    const namespaceLimit = policy.rateLimitPerMin ?? DEFAULT_RATE_LIMIT_PER_MIN;
    const limit = this.quota.rateLimitPerMin(
      effectiveRateLimit(namespaceLimit, tenant) ?? namespaceLimit,
      identity.actor,
    );
    if (!(await this.rateLimiter.allow(identity.keyId, limit))) {
      await auditExportDenied(`rate limit exceeded (${limit}/min)`);
      throw new RateLimitError(`rate limit exceeded (${limit} requests/min for this key)`);
    }
  }

  /**
   * M9 #7 (D28/E15–E18): governed markdown export. Ordering is load-bearing:
   * (1) the per-syscall gate (credential / tenant-suspend / rate limit),
   * (2) the D28 role gate — a role that may never export is denied+audited
   *     BEFORE any credit debit, so denied callers cannot drain the balance,
   * (3) the export_run entitlement charge (E40): an exhausted balance
   *     REFUSES the metered lane (audited denial, typed 402 error — the
   *     brownout is "degrade the expensive lane", never a free export),
   * (4) render inside memExport, which re-audits every outcome (E16/D4).
   */
  async memExport(
    identity: Identity,
    options: ExportOptions = {},
  ): Promise<ExportResult> {
    await this.gateExport(identity);
    await this.requireOAuthTool(identity, "mem_export");
    await this.consumeQuota(identity, "export", "export", "mem-export");
    // A SCOPED export from the `""` organization root needs its downward
    // read authority resolved HERE (the module has no db): prefixes [""]
    // minus the registered tenants (Amendment A1) — the same reach the
    // owner branch of resolveMemoryReadScope grants. Non-root callers
    // derive their own subtree inside the module; nothing is injected.
    let readScope: MemoryReadScope | undefined;
    if (options.scope !== undefined && identity.namespace === "") {
      const registered = await this.db.query(`SELECT id FROM tenants`);
      readScope = {
        exact: [],
        prefixes: [""],
        excludePrefixes: registered.rows.map(
          (row) => String((row as { id: unknown }).id) as Namespace,
        ),
      };
    }
    const exporterDeps = {
      index: this.index,
      concepts: this.cold,
      audit: this.audit,
      ...(readScope === undefined ? {} : { readScope }),
    };
    if (!EXPORT_ROLES.includes(identity.role)) {
      // The module's own role gate audits the denial (E16) and throws — and
      // no credit was charged for a caller who can never export.
      return memExport(exporterDeps, identity, options);
    }
    const charge = await this.meter?.charge(identity, "export_run", {
      reason: "mem-export",
    });
    if (charge && !charge.ok && charge.state !== "error") {
      // empty-credits (or budget-over): degrade the lane — audited refusal.
      // state 'error' means the billing store itself is down: fail OPEN
      // (a billing outage must not disable governance-approved egress).
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: "export",
        op: "export",
        memoryId: null,
        namespace: identity.namespace,
        purpose: null,
        result: "denied",
        detail: `export refused: ${charge.state} (feature=export_run)`,
      });
      throw new QuotaLimitError(
        "credit_exhausted",
        "organization credit balance is exhausted (feature=export_run)",
        "export",
      );
    }
    return memExport(
      exporterDeps,
      identity,
      options,
    );
  }

  private async withTeamMemoryRead<T>(
    identity: Identity,
    run: (effectiveIdentity: Identity) => Promise<T>,
  ): Promise<T> {
    // Treat every incoming Identity as untrusted at this boundary. Only this
    // fresh server-side resolver may mint the effective grant and read scope.
    const {
      teamMemoryGrant: _untrustedGrant,
      memoryReadScope: _untrustedScope,
      ...strippedIdentity
    } = identity;
    const scope = await this.resolveMemoryReadScope(strippedIdentity);
    const baseIdentity: Identity = scope
      ? { ...strippedIdentity, memoryReadScope: scope }
      : strippedIdentity;
    const grant = await this.teamMemoryAccess.resolve(baseIdentity);
    if (!grant) return run(baseIdentity);
    const effectiveIdentity: Identity = { ...baseIdentity, teamMemoryGrant: grant };
    const result = await run(effectiveIdentity);
    if (await this.teamMemoryAccess.isCurrent(grant)) return result;
    // A concurrent revocation won the race. Discard the broadened result and
    // repeat under the fail-closed related view before returning any bytes.
    return run(baseIdentity);
  }

  /**
   * M10 (D42/D44) read widening for HUMAN identities, resolved fresh per
   * syscall — the retrieval-lane twin of the memory-graph projection, so the
   * Assistant/copilot evidence lane sees what S5 shows:
   * - `owner`: govern reach DOWNWARD from its OWN namespace (D44) — the
   *   tenant-root owner (E5) reads the whole tenant, a subtree owner reads
   *   its subtree, and sibling subtrees stay invisible either way. The ""
   *   ORGANIZATION root (Amendment A1) reads every namespace whose first
   *   segment is NOT a registered tenant — hosted customer tenants stay
   *   invisible.
   * - `admin`/`member`/`auditor` console sessions: the subject's real
   *   projection (membership + grants), translated to roots. API-key humans
   *   without a users row keep the base ancestor ACL.
   * - machine `agent` callers: never widened (Phase 4 deferred).
   * Fail-closed: any resolution failure returns undefined — the base
   * ancestor ACL floor, never a broader scope.
   */
  private async resolveMemoryReadScope(
    identity: Identity,
  ): Promise<MemoryReadScope | undefined> {
    if (identity.role === "agent") {
      return this.resolveChannelAssistantMemoryReadScope(identity);
    }
    try {
      if (identity.role === "owner") {
        if (identity.namespace !== "") {
          return { exact: [], prefixes: [identity.namespace] };
        }
        const registered = await this.db.query(`SELECT id FROM tenants`);
        return {
          exact: [],
          prefixes: [""],
          excludePrefixes: registered.rows.map((row) =>
            String((row as { id: unknown }).id) as Namespace,
          ),
        };
      }
      if (!identity.sessionUserId) return undefined;
      const projection = await this.projectionForUser(identity.sessionUserId);
      const roots = projectionReadRoots(projection);
      if (roots.exact.length === 0 && roots.prefixes.length === 0) return undefined;
      return { exact: roots.exact as Namespace[], prefixes: roots.prefixes as Namespace[] };
    } catch {
      return undefined;
    }
  }

  /**
   * The built-in channel Assistant is a server-owned presentation of Halo
   * Assistant, not a caller-minted general agent. Re-resolve that distinction
   * from the write-only key row before granting the connection namespace's
   * governed subtree. Caller-supplied Identity fields and ordinary agent keys
   * can never activate this exception; failures retain the ancestor-only
   * agent floor.
   */
  private async resolveChannelAssistantMemoryReadScope(
    identity: Identity,
  ): Promise<MemoryReadScope | undefined> {
    if (identity.namespace.length === 0 || identity.actor !== "system-halo-assistant") {
      return undefined;
    }
    try {
      const result = await this.db.query(
        `SELECT 1
           FROM api_keys
          WHERE id = $1 AND namespace = $2 AND actor = 'system-halo-assistant'
            AND role = 'agent' AND status = 'active'
            AND principal_purpose = 'channel_assistant'
          LIMIT 1`,
        [identity.keyId, identity.namespace],
      );
      if (result.rows.length !== 1) return undefined;
      return { exact: [], prefixes: [identity.namespace] };
    } catch {
      return undefined;
    }
  }

  async memRead(args: MemReadArgs, identity: Identity, agentId = DEFAULT_AGENT_ID, ctx?: SyscallContext): Promise<MemReadResult> {
    await this.requireOAuthTool(identity, "mem_read");
    await this.requireAgentOperation("read", identity, ctx);
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      memRead(
        this.deps,
        args,
        effectiveIdentity,
        this.syscallAgentId(identity, agentId),
        ctx,
      ));
  }

  async memSearch(args: MemSearchArgs, identity: Identity, agentId = DEFAULT_AGENT_ID, ctx?: SyscallContext): Promise<ScoredRef[]> {
    await this.requireOAuthTool(identity, "mem_search");
    await this.requireAgentOperation("search", identity, ctx);
    await this.consumeQuota(identity, "retrieval", "search", "mem-search");
    const governedArgs = identity.role === "agent" ? { ...args, live: "off" as const } : args;
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      this.withUsageContext(identity, ctx, (resolved) =>
        memSearch(
          this.deps,
          governedArgs,
          effectiveIdentity,
          this.syscallAgentId(identity, agentId),
          resolved,
        )));
  }

  /**
   * Assistant-safe source catalog. It exposes only the same content-free,
   * ACL-scoped projection as S6; connector configuration and credentials never
   * cross this boundary. The catalog lookup is audited as a search outcome.
   */
  async copilotSourceList(
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
    ctx?: SyscallContext,
  ): Promise<CopilotSourceSummary[]> {
    await this.requireOAuthTool(identity, "source_list");
    await this.requireAgentOperation("search", identity, ctx);
    try {
      const sources = await this.copilotSourceSummaries(identity);
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: this.syscallAgentId(identity, agentId),
        op: "search",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "assistant source catalog",
        result: sources.length > 0 ? "ok" : "miss",
        detail: `source_catalog returned=${sources.length}`,
      });
      return sources;
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: this.syscallAgentId(identity, agentId),
        op: "search",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "assistant source catalog",
        result: "error",
        detail: "source_catalog failed",
      });
      throw error;
    }
  }

  /**
   * Resolve a backend mention against the server-owned source catalog, then
   * route retrieval through the normal audited driver over a source-filtered
   * ScopedView. Callers provide only natural language — never a source id.
   */
  async copilotSourceSearch(
    query: string,
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
    ctx?: SyscallContext,
  ): Promise<CopilotSourceSearchResult> {
    await this.requireOAuthTool(identity, "source_search");
    await this.requireAgentOperation("search", identity, ctx);
    let catalog: CopilotSourceSummary[];
    try {
      catalog = await this.copilotSourceSummaries(identity);
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: this.syscallAgentId(identity, agentId),
        op: "search",
        memoryId: null,
        namespace: identity.namespace,
        purpose: ctx?.sensitiveTurnId
          ? `assistant-turn:${ctx.sensitiveTurnId}`.slice(0, 200)
          : query.slice(0, 200),
        result: "error",
        detail: "source_search catalog_failed",
      });
      throw error;
    }
    const sources = catalog.filter((source) => sourceMentioned(query, source));
    if (sources.length === 0) {
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: this.syscallAgentId(identity, agentId),
        op: "search",
        memoryId: null,
        namespace: identity.namespace,
        purpose: ctx?.sensitiveTurnId
          ? `assistant-turn:${ctx.sensitiveTurnId}`.slice(0, 200)
          : query.slice(0, 200),
        result: "miss",
        detail: "source_search matched_sources=0 returned=0",
      });
      return { sources: [], hits: [] };
    }

    const labels = [...new Set(sources.map((source) => source.label))];
    const projection: RetrievalSourceProjection = {
      label: labels.join(", "),
      sourceIds: sources.map((source) => source.id),
    };
    const governedArgs: MemSearchArgs = {
      query,
      k: 12,
      tokenBudget: 3_600,
      live: "off",
    };
    const hits = await this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      this.withUsageContext(identity, ctx, (resolved) =>
        memSearch(
          this.deps,
          governedArgs,
          effectiveIdentity,
          this.syscallAgentId(identity, agentId),
          resolved,
          projection,
        )));
    return { sources, hits };
  }

  private async copilotSourceSummaries(identity: Identity): Promise<CopilotSourceSummary[]> {
    const view = await this.sourcesView(identity);
    return view.sources.map((source) => ({
      id: source.id,
      kind: source.kind,
      label: copilotSourceLabel(source.kind),
      syncStatus: source.syncStatus,
      lifecycleState: source.lifecycleState,
      lastSync: source.lastSync,
      liveSearchSupported: false,
    }));
  }

  /**
   * D54: a read-only agent may search and read memory but never change it.
   *
   * Enforced HERE rather than deeper in the write path because the mutating
   * operations do not share one chokepoint: mem_write goes through the syscall
   * layer, while pin/unpin/share sit on their own services and forget has its
   * own erasure lane. A capability that is only checked on the busiest path is
   * not a capability. Every refusal writes a D4 row so a blocked agent is
   * visible in the trail rather than only in a 403 the caller may swallow.
   */
  private async requireAgentWrite(identity: Identity, op: AuditOp): Promise<void> {
    if (identity.role !== "agent" || identity.agentCanWrite !== false) return;
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId: null,
      namespace: identity.namespace,
      purpose: null,
      result: "denied",
      detail: "read-only agent may not change memory",
    });
    throw new AuthzError("this agent has read-only access to memory");
  }

  async consumeQuota(
    identity: Identity,
    feature: QuotaFeature,
    op: AuditOp,
    purpose: string,
    options: {
      idempotencyKey?: string;
      units?: number;
      enrollSeat?: boolean;
      reservedUsd?: number;
    } = {},
  ): Promise<void> {
    try {
      await this.quota.consume(identity, feature, {
        idempotencyKey: options.idempotencyKey ?? `${purpose}:${ulid()}`,
        ...(options.units === undefined ? {} : { units: options.units }),
        ...(options.enrollSeat === undefined ? {} : { enrollSeat: options.enrollSeat }),
        ...(options.reservedUsd === undefined ? {} : { reservedUsd: options.reservedUsd }),
      });
    } catch (error) {
      if (error instanceof QuotaLimitError) {
        await this.auditQuotaDenial(identity, op, purpose, {
          code: error.code,
          feature: error.feature,
          limit: error.limit,
        });
      }
      throw error;
    }
  }

  /** Debit several allowances in one guard transaction (all-or-nothing),
   * auditing a denial exactly like the single-feature path. */
  async consumeQuotaMany(
    identity: Identity,
    items: QuotaConsumeItem[],
    op: AuditOp,
    purpose: string,
    options: { idempotencyKey?: string; enrollSeat?: boolean } = {},
  ): Promise<void> {
    try {
      await this.quota.consumeMany(identity, items, {
        idempotencyKey: options.idempotencyKey ?? `${purpose}:${ulid()}`,
        ...(options.enrollSeat === undefined ? {} : { enrollSeat: options.enrollSeat }),
      });
    } catch (error) {
      if (error instanceof QuotaLimitError) {
        await this.auditQuotaDenial(identity, op, purpose, {
          code: error.code,
          feature: error.feature,
          limit: error.limit,
        });
      }
      throw error;
    }
  }

  async auditQuotaDenial(
    identity: Identity,
    op: AuditOp,
    purpose: string,
    denial: { code: string; feature?: QuotaFeature | null; limit?: number | null },
  ): Promise<void> {
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId: null,
      namespace: identity.namespace,
      purpose,
      result: "denied",
      detail: JSON.stringify({
        boundary: "quota",
        code: denial.code,
        feature: denial.feature ?? null,
        limit: denial.limit ?? null,
      }),
    });
  }

  async memWrite(args: MemWriteArgs, identity: Identity, agentId = DEFAULT_AGENT_ID, ctx?: SyscallContext): Promise<MemWriteResult> {
    await this.requireOAuthTool(identity, "mem_write");
    await this.requireAgentWrite(identity, "write");
    await this.requireAgentOperation("write", identity, ctx);
    await this.consumeQuota(identity, "memory_write", "write", "mem-write");
    // D38: ctx only scopes cost attribution for the SYNC write path's
    // extraction/embedding calls. The async WriteQueue worker runs outside
    // this window (a background lane) and stays namespace-only (E5).
    const resolvedAgentId = this.syscallAgentId(identity, agentId);
    const result = await this.withUsageContext(identity, ctx, () =>
      memWrite(this.deps, args, identity, resolvedAgentId));
    // Guardrail monitor: an agent that writes into a namespace whose required
    // policy it never read is recorded as a bypass (evidence, not a denial).
    await this.notePolicyExposure(identity, resolvedAgentId, "mem_write", ctx);
    return result;
  }

  async memFault(args: MemFaultArgs, identity: Identity, agentId = DEFAULT_AGENT_ID, ctx?: SyscallContext): Promise<MemFaultResult> {
    await this.requireOAuthTool(identity, "mem_fault");
    await this.requireAgentOperation("fault", identity, ctx);
    await this.consumeQuota(identity, "retrieval", "fault", "mem-fault");
    if (identity.role !== "agent" || identity.channelAssistant === true) {
      return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
        this.withUsageContext(identity, ctx, (resolved) =>
          memFault(
            this.deps,
            args,
            effectiveIdentity,
            this.syscallAgentId(identity, agentId),
            resolved,
          )));
    }
    const { sourceTokens: _sourceTokens, ...localArgs } = args;
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      this.withUsageContext(identity, ctx, (resolved) =>
        memFault(
          this.deps,
          { ...localArgs, live: "off" },
          effectiveIdentity,
          this.syscallAgentId(identity, agentId),
          resolved,
        )));
  }

  async memAssemble(args: MemAssembleArgs, identity: Identity, agentId = DEFAULT_AGENT_ID, ctx?: SyscallContext): Promise<WorkingSet> {
    await this.requireOAuthTool(identity, "mem_assemble");
    await this.requireAgentOperation("assemble", identity, ctx);
    await this.consumeQuota(identity, "retrieval", "assemble", "mem-assemble");
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      this.withUsageContext(identity, ctx, (resolved) =>
        memAssemble(
          this.deps,
          args,
          effectiveIdentity,
          this.syscallAgentId(identity, agentId),
          resolved,
        )));
  }

  /**
   * mem_policy: the guardrail set governing the caller's namespace.
   *
   * Same directive blocks `mem_assemble` ships in its reserved lane, returned
   * on their own so a client that owns its system prompt (the Claude Code
   * SessionStart hook, the Codex installer) can place them there instead. The
   * kernel still never builds the prompt (D2) — it hands over ranked blocks and
   * the digest to acknowledge.
   */
  async memPolicy(
    args: { tokenBudget?: number },
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
    ctx?: SyscallContext,
  ): Promise<PolicyDirectiveSet> {
    await this.requireOAuthTool(identity, "mem_policy");
    await this.requireAgentOperation("assemble", identity, ctx);
    const namespace = identity.namespace;
    const resolvedAgentId = this.syscallAgentId(identity, agentId);
    const tokenBudget =
      args.tokenBudget !== undefined && Number.isInteger(args.tokenBudget) &&
      args.tokenBudget > 0
        ? args.tokenBudget
        : undefined;
    let set: PolicyDirectiveSet;
    try {
      set = await loadPolicyDirectives(this.db, namespace, { tokenBudget });
    } catch (error) {
      // Brownout: an unreadable guardrail lane must not fail the agent.
      await this.audit.append({
        ts: new Date().toISOString(),
        actor: identity.actor,
        agentId: resolvedAgentId,
        op: "policy",
        memoryId: null,
        namespace,
        purpose: null,
        result: "error",
        detail: `policy_unavailable ${error instanceof Error ? error.name : "unknown"}`,
      });
      return { namespace, digest: "", documents: [], blocks: [], totalTokens: 0, required: false, truncated: 0 };
    }
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: resolvedAgentId,
      op: "policy",
      memoryId: null,
      namespace,
      purpose: null,
      result: set.documents.length > 0 ? "ok" : "miss",
      detail:
        `documents=${set.documents.length} directives=${set.blocks.length} ` +
        `tokens=${set.totalTokens} digest=${set.digest.slice(0, 12)}`,
    });
    if (set.documents.length > 0) {
      await this.policyCompliance
        .recordDelivery(set, {
          agentId: resolvedAgentId,
          actor: identity.actor,
          principal: identity.role === "agent" ? "agent" : "human",
          channel: "policy-call",
          traceId: ctx?.traceId ?? null,
        })
        .catch(() => undefined);
    }
    return set;
  }

  /**
   * mem_policy_ack: the agent echoes the digest it received back, optionally
   * declaring that it acted under those guardrails (`applied`). An ack for a
   * stale digest is rejected — that is exactly the signal the console needs.
   */
  async memPolicyAck(
    args: { digest: string; applied?: boolean; note?: string },
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
    ctx?: SyscallContext,
  ): Promise<{ acknowledged: boolean; digest: string; documents: number }> {
    await this.requireOAuthTool(identity, "mem_policy_ack");
    await this.requireAgentOperation("assemble", identity, ctx);
    const namespace = identity.namespace;
    const resolvedAgentId = this.syscallAgentId(identity, agentId);
    const digest = typeof args.digest === "string" ? args.digest.trim() : "";
    const current = await loadPolicyDirectives(this.db, namespace);
    const matches = digest !== "" && digest === current.digest;
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: resolvedAgentId,
      op: "policy_ack",
      memoryId: null,
      namespace,
      purpose: null,
      result: matches ? "ok" : "denied",
      detail: matches
        ? `digest=${digest.slice(0, 12)} applied=${args.applied === true}`
        : `stale_digest=${digest.slice(0, 12) || "none"} current=${current.digest.slice(0, 12) || "none"}`,
    });
    if (!matches) {
      throw new Error(
        current.digest === ""
          ? "no governed policy is active for this namespace"
          : "policy digest is stale - call mem_policy again before acknowledging",
      );
    }
    const note =
      typeof args.note === "string" && args.note.trim().length > 0
        ? args.note.trim()
        : null;
    for (const document of current.documents) {
      await this.policyCompliance.record({
        namespace,
        documentId: document.documentId,
        policyDigest: current.digest,
        agentId: resolvedAgentId,
        actor: identity.actor,
        principal: identity.role === "agent" ? "agent" : "human",
        kind: args.applied === true ? "applied" : "acknowledged",
        channel: "ack",
        traceId: ctx?.traceId ?? null,
        detail: note,
      });
    }
    return {
      acknowledged: true,
      digest: current.digest,
      documents: current.documents.length,
    };
  }

  /**
   * Guardrail reference monitor. Runs after an agent acts (write / source read)
   * and records ONE bypass per (agent, digest) when a `required` directive set
   * was current and this agent had never been served it.
   *
   * Never denies and never throws into the caller: policy is evidence here, not
   * authorization — the ACL in the query layer is what actually fences data.
   */
  private async notePolicyExposure(
    identity: Identity,
    agentId: string,
    operation: string,
    ctx?: SyscallContext,
  ): Promise<void> {
    try {
      const namespace = identity.namespace;
      const set = await this.governingDigest(namespace);
      if (!set.required || set.digest === "") return;
      // Once an agent is settled against a digest — served it, or already
      // recorded as having missed it — the monitor is a no-op for the rest of
      // this process's life. Keeps the write path off the ledger tables.
      const settled = `${namespace}\u0000${agentId}\u0000${set.digest}`;
      if (this.policyExposureSettled.has(settled)) return;
      if (await this.policyCompliance.hasDelivery(namespace, agentId, set.digest)) {
        this.rememberPolicyExposure(settled);
        return;
      }
      if (await this.policyCompliance.hasBypass(namespace, agentId, set.digest)) {
        this.rememberPolicyExposure(settled);
        return;
      }
      this.rememberPolicyExposure(settled);
      for (const document of set.documents) {
        if (document.enforcement !== "required") continue;
        await this.policyCompliance.record({
          namespace,
          documentId: document.documentId,
          policyDigest: set.digest,
          agentId,
          actor: identity.actor,
          principal: identity.role === "agent" ? "agent" : "human",
          kind: "bypassed",
          channel: "monitor",
          traceId: ctx?.traceId ?? null,
          detail: `acted via ${operation} without reading the current policy`,
        });
      }
      this.logger.warn("agent acted without reading required policy", {
        namespace,
        agentId,
        operation,
        digest: set.digest.slice(0, 12),
      });
    } catch {
      // Monitoring is best-effort by construction.
    }
  }

  /**
   * The governing digest for a namespace, cached briefly. The monitor runs on
   * the write path, so it must not re-read the whole directive set per call;
   * a short staleness window on EVIDENCE is the right trade (D50).
   */
  private async governingDigest(
    namespace: Namespace,
  ): Promise<{ digest: string; required: boolean; documents: PolicyDirectiveDocument[] }> {
    const cached = this.policyDigestCache.get(namespace);
    const now = Date.now();
    if (cached && cached.expiresAt > now) return cached.value;
    const set = await loadPolicyDirectives(this.db, namespace);
    const value = {
      digest: set.digest,
      required: set.required,
      documents: set.documents,
    };
    if (this.policyDigestCache.size >= POLICY_CACHE_MAX_ENTRIES) {
      this.policyDigestCache.clear();
    }
    this.policyDigestCache.set(namespace, {
      value,
      expiresAt: now + POLICY_DIGEST_CACHE_MS,
    });
    return value;
  }

  private rememberPolicyExposure(key: string): void {
    if (this.policyExposureSettled.size >= POLICY_CACHE_MAX_ENTRIES) {
      this.policyExposureSettled.clear();
    }
    this.policyExposureSettled.add(key);
  }

  /** S4 compliance read model: who was served what, who answered, who did not. */
  async policyComplianceReport(
    namespace: Namespace,
    identity: Identity,
  ): Promise<PolicyComplianceReport> {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      throw new AuthzError(
        `role '${identity.role}' may not read policy compliance`,
      );
    }
    if (!isRootOwner(identity) && !isSelfOrDescendant(namespace, identity.namespace)) {
      throw new AuthzError("policy scope is outside your namespace subtree");
    }
    const current = await loadPolicyDirectives(this.db, namespace);
    return this.policyCompliance.report(namespace, current.digest);
  }

  /** Flip one governed document between advisory and required guardrail levels. */
  async setPolicyDocumentEnforcement(
    documentId: string,
    enforcement: PolicyDocumentEnforcement,
    identity: Identity,
  ): Promise<PolicyDocumentSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      throw new AuthzError(
        `role '${identity.role}' may not change policy enforcement`,
      );
    }
    const existing = await this.policyDocuments.get(documentId);
    if (!existing) {
      throw new AuthzError("policy document is unknown");
    }
    if (
      !isRootOwner(identity) &&
      !isSelfOrDescendant(existing.namespace, identity.namespace)
    ) {
      throw new AuthzError("policy document is outside your namespace subtree");
    }
    const updated = await this.policyDocuments.setEnforcement(
      documentId,
      enforcement,
    );
    await this.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: DEFAULT_AGENT_ID,
      op: "policy_enforcement",
      memoryId: null,
      namespace: updated.namespace,
      purpose: null,
      result: "ok",
      detail: `document=${updated.id} enforcement=${updated.enforcement}`,
    });
    return updated;
  }

  /**
   * Permanently delete a governed policy document and retract every fact it
   * contributed to active memory. The policy file row is removed, quota is
   * released, and the deletion is audited.
   */
  async deletePolicyDocument(
    documentId: string,
    identity: Identity,
  ): Promise<PolicyDocumentSummary> {
    if (identity.role !== "owner" && identity.role !== "admin") {
      throw new AuthzError(
        `role '${identity.role}' may not delete policy documents`,
      );
    }
    const existing = await this.policyDocuments.get(documentId);
    if (!existing) {
      throw new AuthzError("policy document is unknown");
    }
    if (
      !isRootOwner(identity) &&
      !isSelfOrDescendant(existing.namespace, identity.namespace)
    ) {
      throw new AuthzError("policy document is outside your namespace subtree");
    }
    const retiredAt = new Date().toISOString();
    const deleted = await this.db.transaction(async (tx) => {
      const txStore = new PolicyDocumentStore(tx);
      const removed = await txStore.deleteInTransaction(tx, documentId);
      const state = new DbSourceState(
        tx,
        removed.sourceId,
        removed.namespace,
        (db, event) => this.audit.appendTo(db, event),
        identity.actor,
        DEFAULT_AGENT_ID,
        (db, retiredIds, namespace) =>
          this.warm.enqueueInvalidationsTx(db, retiredIds, namespace),
      );
      // An uploaded document owns its attempt, so its facts are matched by the
      // exact attempt token. An adopted document's facts predate the row and
      // may span many fragment documents of one file, so they are matched by
      // the file's landed (documentKey, contentHash) provenance instead.
      const retracted =
        removed.origin === "adopted"
          ? await state.retractCommittedFileInTransaction(
              tx,
              removed.fileName,
              retiredAt,
            )
          : await state
              .retractCommittedVersionInTransaction(
                tx,
                removed.fileName,
                removed.contentSha256,
                retiredAt,
                removed.attemptToken,
              )
              .then(() => [removed.fileName]);
      return { removed, retracted };
    });
    this.l1Cache.eraseNamespace(l1CachePartition(deleted.removed.namespace));
    await this.warm.afterRetraction();
    await this.audit.append({
      ts: retiredAt,
      actor: identity.actor,
      agentId: DEFAULT_AGENT_ID,
      op: "policy_delete",
      memoryId: null,
      namespace: deleted.removed.namespace,
      purpose: null,
      result: "ok",
      detail:
        `document=${deleted.removed.id} source=${deleted.removed.sourceId}` +
        ` file=${deleted.removed.fileName} origin=${deleted.removed.origin}` +
        ` documents=${deleted.retracted.length}`,
    });
    return existing;
  }

  async memStats(
    args: MemStatsArgs,
    identity: Identity,
    agentId = DEFAULT_AGENT_ID,
    ctx?: SyscallContext,
  ): Promise<MemStats> {
    await this.requireOAuthTool(identity, "mem_stats");
    await this.requireAgentOperation("stats", identity, ctx);
    return this.withTeamMemoryRead(identity, (effectiveIdentity) =>
      memStats(
        this.deps,
        args,
        effectiveIdentity,
        this.syscallAgentId(identity, agentId),
      ));
  }

  async memPin(target: PinTarget, identity: Identity): Promise<PinResult> {
    await this.requireOAuthTool(identity, "mem_pin");
    await this.requireAgentWrite(identity, "write");
    await this.requireAgentOperation("pin", identity);
    await this.assertActiveMemoryIdentity(identity, "pin");
    return this.pins.pin(target, identity);
  }

  async memUnpin(pinId: string, identity: Identity): Promise<UnpinResult> {
    await this.requireOAuthTool(identity, "mem_unpin");
    await this.requireAgentWrite(identity, "write");
    await this.requireAgentOperation("unpin", identity);
    await this.assertActiveMemoryIdentity(identity, "unpin");
    return this.pins.unpin(pinId, identity);
  }

  listPins(identity: Identity, namespace = identity.namespace): Promise<MemoryPin[]> {
    return this.pins.list(identity, namespace);
  }

  async memShare(
    target: PinTarget,
    targetNamespace: Namespace,
    identity: Identity,
  ): Promise<DirectShareResult> {
    await this.requireOAuthTool(identity, "mem_share");
    await this.requireAgentWrite(identity, "share");
    await this.requireAgentOperation("share", identity);
    await this.assertActiveMemoryIdentity(identity, "share");
    return this.sharing.share(identity, target, targetNamespace);
  }

  /**
   * Proposal read model for S7. A revision is enriched with the exact previous
   * immutable official version only after ConsolidationService has authorized
   * the caller. New concepts intentionally omit baseDraft.
   */
  async listConsolidationProposals(
    identity: Identity,
  ): Promise<Array<KnowledgeProposal & { baseDraft?: { title: string; body: string } }>> {
    if (!this.consolidation) return [];
    return Promise.all((await this.consolidation.list(identity)).map((proposal) =>
      this.enrichProposalBase(proposal),
    ));
  }

  async getConsolidationProposal(
    identity: Identity,
    proposalId: string,
  ): Promise<(KnowledgeProposal & { baseDraft?: { title: string; body: string } }) | null> {
    if (!this.consolidation) return null;
    const proposal = await this.consolidation.get(identity, proposalId);
    return proposal ? this.enrichProposalBase(proposal) : null;
  }

  private async enrichProposalBase(
    proposal: KnowledgeProposal,
  ): Promise<KnowledgeProposal & { baseDraft?: { title: string; body: string } }> {
    if (!proposal.baseVersionId) return proposal;
    const result = await this.db.query(
      `SELECT c.title, c.body
         FROM knowledge_versions kv
         JOIN knowledge_concepts kc ON kc.id = kv.concept_id
         JOIN concepts c ON c.path = kv.path AND c.namespace = kc.namespace
         JOIN cold_concept_keys ck ON ck.path = c.path AND ck.namespace = c.namespace
         JOIN cold_kek_state ks ON ks.singleton = TRUE
        WHERE kv.id = $1 AND kv.concept_id = $2 AND kc.namespace = $3
          AND kv.state IN ('published', 'archived')
          AND ck.write_state = 'committed' AND ck.envelope_version = 2
          AND ks.maintenance = FALSE AND ks.active_kek_id = ck.kek_id
          AND ks.generation = ck.kek_generation`,
      [proposal.baseVersionId, proposal.conceptId, proposal.namespace],
    );
    // The proposal's exact namespace is trusted only after the service ACL
    // above succeeds; this allows subtree auditors to inspect the comparison
    // without re-enabling obsolete versions in normal retrieval.
    return result.rows.length === 1
      ? {
          ...proposal,
          baseDraft: {
            title: String(result.rows[0].title ?? ""),
            body: String(result.rows[0].body ?? ""),
          },
        }
      : proposal;
  }

  private async assertActiveMemoryIdentity(
    identity: Identity,
    op: "pin" | "unpin" | "share",
  ): Promise<void> {
    const active = await this.isIdentityActive(identity);
    if (active) return;
    await this.audit.append({
      ts: new Date().toISOString(), actor: identity.actor,
      agentId: this.syscallAgentId(identity, DEFAULT_AGENT_ID),
      op, memoryId: null, namespace: identity.namespace, purpose: null,
      result: "denied", detail: "credential_inactive",
    });
    throw new AuthzError("credential is inactive or revoked");
  }

  private async isIdentityActive(identity: Identity): Promise<boolean> {
    if (identity.credentialKind === "copilot-capability") {
      if (!identity.keyId.startsWith("copilot:") || !identity.credentialExpiresAt) return false;
      const expiresAt = Date.parse(identity.credentialExpiresAt);
      return Number.isFinite(expiresAt) && expiresAt > Date.now();
    }
    // A scheduled routine run executes under a server-minted identity whose
    // keyId is no stored credential. The runner re-resolves the owning user's
    // row and role before minting, so the gate here only enforces the bound
    // lifetime — mirror of the copilot-capability bearer above.
    if (identity.credentialKind === "copilot-routine") {
      if (!identity.keyId.startsWith("routine:") || !identity.credentialExpiresAt) return false;
      const expiresAt = Date.parse(identity.credentialExpiresAt);
      return Number.isFinite(expiresAt) && expiresAt > Date.now();
    }
    if (identity.keyId.startsWith("oidc:")) {
      if (!identity.credentialExpiresAt) return false;
      const expiresAt = Date.parse(identity.credentialExpiresAt);
      return Number.isFinite(expiresAt) && expiresAt > Date.now();
    }
    // D29/E24: an OAuth-token identity re-checks its row AND the issuing
    // client's approval on every syscall — transitive revocation is instant.
    if (identity.keyId.startsWith("oauth:")) {
      return this.oauthTokens.isActiveId(identity.keyId.slice("oauth:".length));
    }
    return (await this.auth.isActive(identity.keyId)) ||
      (await this.sessions.isActiveId(identity.keyId));
  }

  /**
   * mem.forget (M4 / D3): owner/admin-only compliance erasure, subtree-scoped.
   * Hard-deletes the matching rows, writes tombstones, and mints a signed
   * DeletionCertificate. auditor/member/agent are denied + audited; the audit
   * trail for the erased content survives (D4).
   */
  async memForget(args: MemForgetArgs, identity: Identity, agentId = DEFAULT_AGENT_ID): Promise<ForgetResult> {
    await this.requireAgentWrite(identity, "forget");
    return memForget(this.deps, args, identity, this.syscallAgentId(identity, agentId));
  }

  /**
   * Status of an async write ticket (undefined = unknown/evicted → 404).
   * When `identity` is provided (transport callers MUST pass it), the ticket
   * is only visible to callers in the enqueuing namespace — a WriteResult
   * contains stored memory objects, so foreign tickets 404 like a miss.
   */
  async writeStatus(
    ticket: string,
    identity?: Identity,
  ): Promise<WriteQueueStatus<WriteResult> | undefined> {
    return this.writeQueue.status(ticket, identity);
  }

  async close(): Promise<void> {
    clearInterval(this.connectorJobPoller);
    clearInterval(this.conflictScanJobPoller);
    clearInterval(this.conflictAutopilotPoller);
    clearInterval(this.entityTagPoller);
    clearInterval(this.embeddingBackfillPoller);
    clearInterval(this.memoryTitlePoller);
    await this.writeQueue.drain();
    if (this.conflictScanWorker) await this.conflictScanWorker;
    if (this.conflictAutopilotWorker) await this.conflictAutopilotWorker;
    if (this.entityTagWorker) await this.entityTagWorker;
    if (this.companyFileWorker) await this.companyFileWorker;
    if (this.relationshipEnrichmentWorker) await this.relationshipEnrichmentWorker;
    if (this.embeddingBackfillWorker) await this.embeddingBackfillWorker;
    if (this.memoryTitleWorker) await this.memoryTitleWorker;
    this.writeQueue.stop();
    await this.db.close();
  }
}
