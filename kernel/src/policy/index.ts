/**
 * Module D (M1) — public surface: DB-backed policy store with namespace
 * inheritance + rate limiting and budget caps.
 */

export {
  DEFAULT_RATE_LIMIT_PER_MIN,
  namespaceChain,
  parsePolicyYaml,
  PolicyStore,
  type PolicyConfigX,
  type PolicyOverrides,
  type PolicyRow,
  type PolicyStoreOptions,
} from "./store.js";

export {
  BudgetGuard,
  TokenBucket,
  type BudgetGuardOptions,
  type BudgetState,
  type TokenBucketOptions,
} from "./limits.js";

export {
  MAX_POLICY_DOCUMENT_BYTES,
  MAX_POLICY_DOCUMENT_BYTES_PER_TENANT,
  MAX_POLICY_DOCUMENTS_PER_TENANT,
  MAX_POLICY_DOCUMENT_ROWS_PER_TENANT,
  POLICY_DOCUMENT_LEASE_MS,
  normalizePolicyDocumentUpload,
  PolicyDocumentConflictError,
  PolicyDocumentLeaseExpiredError,
  PolicyDocumentQuotaError,
  PolicyDocumentStore,
  PolicyDocumentValidationError,
  type AdoptedDocumentVersion,
  type AdoptPolicyDocumentInput,
  type CreatePolicyDocumentInput,
  type ExpiredPolicyDocumentAttempt,
  type NormalizedPolicyDocumentUpload,
  type PolicyDocumentAttempt,
  type PolicyDocumentQuotaLimits,
} from "./documents.js";

export {
  EMPTY_DIRECTIVE_SET,
  loadPolicyDirectives,
  POLICY_BUDGET_RATIO,
  policyTokenReserve,
  type PolicyDirectiveOptions,
} from "./directives.js";

export {
  PolicyComplianceStore,
  type PolicyEventChannel,
  type PolicyEventInput,
  type PolicyEventKind,
} from "./compliance.js";
