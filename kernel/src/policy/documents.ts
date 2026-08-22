import { createHash } from "node:crypto";
import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import type {
  PolicyAdoptionCandidate,
  PolicyAdoptionCandidateListResult,
  PolicyDocumentEnforcement,
  PolicyDocumentKind,
  PolicyDocumentListQuery,
  PolicyDocumentListResult,
  PolicyDocumentOrigin,
  PolicyDocumentScopeListResult,
  PolicyDocumentStatus,
  PolicyDocumentSummary,
  PolicyDocumentUploadInput,
} from "../types.js";

export const MAX_POLICY_DOCUMENT_BYTES = 512 * 1024;
export const MAX_CONCURRENT_POLICY_DOCUMENT_ATTEMPTS = 20;
export const MAX_POLICY_DOCUMENTS_PER_TENANT = 10_000;
export const MAX_POLICY_DOCUMENT_BYTES_PER_TENANT = 2 * 1024 * 1024 * 1024;
export const MAX_POLICY_DOCUMENT_ROWS_PER_TENANT = 50_000;
export const POLICY_DOCUMENT_LEASE_MS = 15 * 60 * 1_000;
const MAX_NAMESPACE_LENGTH = 512;
const MAX_TITLE_LENGTH = 200;
const MAX_FILE_NAME_BYTES = 255;
const MAX_SEARCH_LENGTH = 200;
const MAX_ACTOR_LENGTH = 512;
const MAX_PAGE_SIZE = 50;

const KINDS = new Set<PolicyDocumentKind>([
  "policy",
  "guideline",
  "procedure",
  "standard",
  "handbook",
  "other",
]);

const ENFORCEMENTS = new Set<PolicyDocumentEnforcement>([
  "advisory",
  "required",
]);

const STATUSES = new Set<PolicyDocumentStatus>([
  "processing",
  "active",
  "needs_review",
  "failed",
]);

const MEDIA_TYPES = new Map<string, string>([
  [".txt", "text/plain"],
  [".md", "text/markdown"],
  [".markdown", "text/markdown"],
  [".csv", "text/csv"],
  [".json", "application/json"],
  [".yaml", "application/yaml"],
  [".yml", "application/yaml"],
]);

const FAILURE_CODE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const CONTROL_OR_SEPARATOR = /[\\/\p{Cc}]/u;

export class PolicyDocumentValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyDocumentValidationError";
  }
}

export class PolicyDocumentConflictError extends Error {
  constructor(message = "This policy file is already loaded in the selected scope") {
    super(message);
    this.name = "PolicyDocumentConflictError";
  }
}

export class PolicyDocumentQuotaError extends Error {
  constructor(message = "Policy document storage quota exceeded") {
    super(message);
    this.name = "PolicyDocumentQuotaError";
  }
}

export class PolicyDocumentConcurrencyError extends Error {
  constructor(message = "Too many policy uploads in progress for this namespace") {
    super(message);
    this.name = "PolicyDocumentConcurrencyError";
  }
}

export class PolicyDocumentLeaseExpiredError extends Error {
  constructor(message = "Policy document processing lease is no longer active") {
    super(message);
    this.name = "PolicyDocumentLeaseExpiredError";
  }
}

export interface NormalizedPolicyDocumentUpload
  extends Omit<PolicyDocumentUploadInput, "title" | "enforcement"> {
  title: string;
  enforcement: PolicyDocumentEnforcement;
  mediaType: string;
  byteSize: number;
  contentSha256: string;
}

export interface CreatePolicyDocumentInput {
  sourceId: string;
  upload: NormalizedPolicyDocumentUpload;
  createdBy: string;
  tenantRoot?: string;
}

export interface PolicyDocumentAttempt {
  document: PolicyDocumentSummary;
  attemptToken: string;
}

export interface ExpiredPolicyDocumentAttempt {
  id: string;
  sourceId: string;
  namespace: string;
  fileName: string;
  contentSha256: string;
  attemptToken: string;
  byteSize: number;
}

export interface DeletedPolicyDocument {
  id: string;
  sourceId: string;
  namespace: string;
  fileName: string;
  contentSha256: string;
  attemptToken: string;
  byteSize: number;
  status: Exclude<PolicyDocumentStatus, "processing"> | "processing";
  origin: PolicyDocumentOrigin;
}

/** One already-landed source version of a file being adopted into the register. */
export interface AdoptedDocumentVersion {
  documentKey: string;
  contentHash: string;
}

export interface AdoptPolicyDocumentInput {
  sourceId: string;
  namespace: string;
  fileName: string;
  title?: string;
  kind?: PolicyDocumentKind;
  enforcement?: PolicyDocumentEnforcement;
  /** Every source document the file landed as, newest content hash per key. */
  versions: AdoptedDocumentVersion[];
  factCount: number;
  byteSize: number;
  loadedAt: string | null;
  createdBy: string;
  tenantRoot?: string;
}

export interface PolicyDocumentQuotaLimits {
  maxDocuments?: number;
  maxBytes?: number;
  maxRows?: number;
}

interface PolicyDocumentRow {
  id: string;
  source_id: string;
  namespace: string;
  title: string;
  kind: PolicyDocumentKind;
  status: PolicyDocumentStatus;
  enforcement: PolicyDocumentEnforcement;
  origin: PolicyDocumentOrigin | null;
  file_name: string;
  media_type: string;
  byte_size: number | string;
  content_sha256: string;
  attempt_token: string;
  lease_expires_at: string | Date;
  fact_count: number | string;
  failure_code: string | null;
  created_by: string;
  created_at: string | Date;
  loaded_at: string | Date | null;
}

export function normalizePolicyDocumentUpload(
  input: PolicyDocumentUploadInput,
): NormalizedPolicyDocumentUpload {
  if (input === null || typeof input !== "object") {
    throw new PolicyDocumentValidationError("Policy document input is required");
  }

  const namespace = normalizeNamespace(input.namespace);

  if (!KINDS.has(input.kind)) {
    throw new PolicyDocumentValidationError("Unsupported policy document kind");
  }

  const fileName = validateFileName(input.fileName);
  const extensionIndex = fileName.lastIndexOf(".");
  const extension = fileName.slice(extensionIndex).toLowerCase();
  const mediaType = MEDIA_TYPES.get(extension);
  if (mediaType === undefined) {
    throw new PolicyDocumentValidationError(
      "Unsupported policy document format",
    );
  }

  const stem = fileName.slice(0, extensionIndex).trim();
  if (!stem) {
    throw new PolicyDocumentValidationError("Policy document filename needs a name");
  }

  if (typeof input.content !== "string") {
    throw new PolicyDocumentValidationError("Policy document content must be text");
  }
  if (input.content.includes("\u0000")) {
    throw new PolicyDocumentValidationError(
      "Policy document content cannot contain NUL",
    );
  }
  if (input.content.trim().length === 0) {
    throw new PolicyDocumentValidationError("Policy document cannot be empty");
  }
  const byteSize = Buffer.byteLength(input.content, "utf8");
  if (byteSize > MAX_POLICY_DOCUMENT_BYTES) {
    throw new PolicyDocumentValidationError(
      "Policy document exceeds the 512 KiB limit",
    );
  }

  const title =
    input.title === undefined
      ? readableTitle(stem)
      : requiredTrimmedString(input.title, "title", MAX_TITLE_LENGTH);
  if (
    !title ||
    title.length > MAX_TITLE_LENGTH ||
    CONTROL_CHARACTER.test(title)
  ) {
    throw new PolicyDocumentValidationError(
      `title must be between 1 and ${MAX_TITLE_LENGTH} characters without controls`,
    );
  }

  // Guardrails are `required` by default: a policy a human loaded into the
  // register is meant to reach agents and be answered for. Downgrading to
  // advisory is an explicit act.
  const enforcement: PolicyDocumentEnforcement =
    input.enforcement === undefined ? "required" : input.enforcement;
  if (!ENFORCEMENTS.has(enforcement)) {
    throw new PolicyDocumentValidationError(
      "enforcement must be 'advisory' or 'required'",
    );
  }

  return {
    namespace,
    title,
    kind: input.kind,
    enforcement,
    fileName,
    content: input.content,
    mediaType,
    byteSize,
    contentSha256: createHash("sha256")
      .update(input.content, "utf8")
      .digest("hex"),
  };
}

export class PolicyDocumentStore {
  constructor(private readonly db: Db) {}

  async createProcessing(
    input: CreatePolicyDocumentInput,
  ): Promise<PolicyDocumentSummary> {
    return (await this.createProcessingAttempt(input)).document;
  }

  async createProcessingAttempt(
    input: CreatePolicyDocumentInput,
    limits: PolicyDocumentQuotaLimits = {},
  ): Promise<PolicyDocumentAttempt> {
    const sourceId = requiredTrimmedString(
      input.sourceId,
      "sourceId",
      MAX_NAMESPACE_LENGTH,
    );
    const createdBy = requiredTrimmedString(
      input.createdBy,
      "createdBy",
      MAX_ACTOR_LENGTH,
    );
    // Re-normalize so callers cannot forge byte size, type, or digest fields.
    const upload = normalizePolicyDocumentUpload(input.upload);
    const tenantRoot = normalizeNamespace(
      input.tenantRoot ?? tenantRootFor(upload.namespace),
    );
    if (tenantRoot !== tenantRootFor(upload.namespace)) {
      throw new PolicyDocumentValidationError(
        "tenantRoot must be the canonical root of the upload namespace",
      );
    }
    const quota = normalizedQuotaLimits(limits);
    const attemptToken = ulid();
    const createdAt = new Date().toISOString();
    const leaseExpiresAt = new Date(
      Date.parse(createdAt) + POLICY_DOCUMENT_LEASE_MS,
    ).toISOString();
    return this.db.transaction(async (tx) => {
      const concurrencyCheck = await tx.query(
        `SELECT count(*) as count FROM policy_documents
          WHERE namespace = $1 AND status = 'processing' AND lease_expires_at > now()`,
        [upload.namespace],
      );
      const activeCount = Number((concurrencyCheck.rows[0] as { count: string | number }).count);
      if (activeCount >= MAX_CONCURRENT_POLICY_DOCUMENT_ATTEMPTS) {
        throw new PolicyDocumentConcurrencyError();
      }

      await tx.query(
        `INSERT INTO policy_document_quota_usage
           (tenant_root, current_documents, current_bytes, total_rows, updated_at)
         VALUES ($1, 0, 0, 0, $2)
         ON CONFLICT (tenant_root) DO NOTHING`,
        [tenantRoot, createdAt],
      );
      const reserved = await tx.query(
        `UPDATE policy_document_quota_usage
            SET current_documents = current_documents + 1,
                current_bytes = current_bytes + $2,
                total_rows = total_rows + 1,
                updated_at = $3
          WHERE tenant_root = $1
            AND current_documents < $4
            AND current_bytes + $2 <= $5
            AND total_rows < $6
          RETURNING tenant_root`,
        [
          tenantRoot,
          upload.byteSize,
          createdAt,
          quota.maxDocuments,
          quota.maxBytes,
          quota.maxRows,
        ],
      );
      if (reserved.rows.length !== 1) {
        throw new PolicyDocumentQuotaError();
      }
      const inserted = await tx.query(
        `INSERT INTO policy_documents
           (id, source_id, namespace, title, kind, status, enforcement,
            file_name, media_type,
            byte_size, content_sha256, attempt_token, lease_expires_at,
            fact_count, failure_code, created_by, created_at, loaded_at)
         VALUES
           ($1, $2, $3, $4, $5, 'processing', $6, $7, $8, $9, $10, $11, $12,
            0, NULL, $13, $14, NULL)
         ON CONFLICT DO NOTHING
         RETURNING *`,
        [
          ulid(),
          sourceId,
          upload.namespace,
          upload.title,
          upload.kind,
          upload.enforcement,
          upload.fileName,
          upload.mediaType,
          upload.byteSize,
          upload.contentSha256,
          attemptToken,
          leaseExpiresAt,
          createdBy,
          createdAt,
        ],
      );
      if (inserted.rows.length !== 1) {
        throw new PolicyDocumentConflictError();
      }
      return {
        document: rowToSummary(inserted.rows[0] as PolicyDocumentRow),
        attemptToken,
      };
    });
  }

  async markActive(
    id: string,
    factCount: number,
    attemptToken?: string,
  ): Promise<PolicyDocumentSummary> {
    return this.complete(id, "active", factCount, null, attemptToken);
  }

  async markNeedsReview(
    id: string,
    factCount: number,
    attemptToken?: string,
  ): Promise<PolicyDocumentSummary> {
    return this.complete(id, "needs_review", factCount, null, attemptToken);
  }

  async markFailed(
    id: string,
    failureCode: string,
    attemptToken?: string,
    compensate?: (
      tx: Db,
      attempt: ExpiredPolicyDocumentAttempt,
    ) => Promise<void>,
  ): Promise<PolicyDocumentSummary> {
    if (typeof failureCode !== "string" || !FAILURE_CODE.test(failureCode)) {
      throw new PolicyDocumentValidationError(
        "failureCode must be a bounded machine-readable code",
      );
    }
    return this.complete(
      id,
      "failed",
      0,
      failureCode,
      attemptToken,
      compensate,
    );
  }

  async renewLease(
    rawId: string,
    rawAttemptToken: string,
    leaseMs = POLICY_DOCUMENT_LEASE_MS,
  ): Promise<boolean> {
    const id = requiredTrimmedString(rawId, "id", MAX_NAMESPACE_LENGTH);
    const attemptToken = requiredTrimmedString(
      rawAttemptToken,
      "attemptToken",
      MAX_NAMESPACE_LENGTH,
    );
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) {
      throw new PolicyDocumentValidationError("leaseMs must be a positive integer");
    }
    const result = await this.db.query(
      `UPDATE policy_documents
          SET lease_expires_at = CURRENT_TIMESTAMP + ($3 * INTERVAL '1 millisecond')
        WHERE id = $1 AND attempt_token = $2 AND status = 'processing'
          AND lease_expires_at > CURRENT_TIMESTAMP
        RETURNING id`,
      [id, attemptToken, leaseMs],
    );
    return result.rows.length === 1;
  }

  /**
   * Atomically fence and retire an expired attempt. The optional callback runs
   * under the same row lock and transaction so exact-provenance compensation,
   * quota release, and the failed status cannot be separated by a crash.
   */
  async claimExpiredProcessing(
    namespace: string,
    contentSha256: string,
    compensate?: (
      tx: Db,
      attempt: ExpiredPolicyDocumentAttempt,
    ) => Promise<void>,
  ): Promise<ExpiredPolicyDocumentAttempt[]> {
    const normalizedNamespace = normalizeNamespace(namespace);
    const hash = validateContentSha256(contentSha256);
    return this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT id, source_id, namespace, file_name, content_sha256,
                attempt_token, byte_size
           FROM policy_documents
          WHERE namespace = $1 AND content_sha256 = $2
            AND status = 'processing'
            AND lease_expires_at <= CURRENT_TIMESTAMP
          FOR UPDATE`,
        [normalizedNamespace, hash],
      );
      const attempts = selected.rows.map(expiredRow);
      for (const attempt of attempts) {
        await compensate?.(tx, attempt);
        await tx.query(
          `UPDATE policy_documents
              SET status = 'failed', failure_code = 'processing-timeout',
                  fact_count = 0, loaded_at = NULL
            WHERE id = $1 AND attempt_token = $2 AND status = 'processing'`,
          [attempt.id, attempt.attemptToken],
        );
        await releaseCurrentQuota(
          tx,
          tenantRootFor(attempt.namespace),
          attempt.byteSize,
        );
      }
      return attempts;
    });
  }

  async assertWithinQuota(
    tenantRoot: string,
    incomingBytes: number,
    limits: PolicyDocumentQuotaLimits = {},
  ): Promise<void> {
    const namespace = normalizeNamespace(tenantRoot);
    if (!Number.isSafeInteger(incomingBytes) || incomingBytes <= 0) {
      throw new PolicyDocumentValidationError("incomingBytes must be a positive integer");
    }
    const quota = normalizedQuotaLimits(limits);
    const usage = await this.db.query(
      `SELECT current_documents AS document_count, current_bytes AS byte_count,
              total_rows
         FROM policy_document_quota_usage
        WHERE tenant_root = $1`,
      [namespace],
    );
    const row = usage.rows[0] as
      | {
          document_count: number | string;
          byte_count: number | string;
          total_rows: number | string;
        }
      | undefined;
    if (
      Number(row?.document_count ?? 0) + 1 > quota.maxDocuments ||
      Number(row?.byte_count ?? 0) + incomingBytes > quota.maxBytes ||
      Number(row?.total_rows ?? 0) + 1 > quota.maxRows
    ) {
      throw new PolicyDocumentQuotaError();
    }
  }

  /**
   * Flip one document between advisory and required. This is the only mutable
   * field on the register — title, content, and provenance stay immutable
   * (D7): a changed policy is a new upload that supersedes its clauses.
   */
  async setEnforcement(
    rawId: string,
    enforcement: PolicyDocumentEnforcement,
  ): Promise<PolicyDocumentSummary> {
    const id = requiredTrimmedString(rawId, "id", MAX_NAMESPACE_LENGTH);
    if (!ENFORCEMENTS.has(enforcement)) {
      throw new PolicyDocumentValidationError(
        "enforcement must be 'advisory' or 'required'",
      );
    }
    const updated = await this.db.query(
      `UPDATE policy_documents SET enforcement = $2
        WHERE id = $1 AND status IN ('active','needs_review')
        RETURNING *`,
      [id, enforcement],
    );
    if (updated.rows.length !== 1) {
      throw new PolicyDocumentValidationError(
        "policy document is unknown or not agent-ready",
      );
    }
    return rowToSummary(updated.rows[0] as PolicyDocumentRow);
  }

  async get(rawId: string): Promise<PolicyDocumentSummary | null> {
    const id = requiredTrimmedString(rawId, "id", MAX_NAMESPACE_LENGTH);
    const result = await this.db.query(
      "SELECT * FROM policy_documents WHERE id = $1",
      [id],
    );
    return result.rows.length === 0
      ? null
      : rowToSummary(result.rows[0] as PolicyDocumentRow);
  }

  /**
   * Permanently remove a policy document and release its quota. This deletes
   * the operational metadata row; callers are responsible for retracting any
   * landed facts from memory so the policy is fully purged.
   */
  async delete(rawId: string): Promise<DeletedPolicyDocument> {
    return this.db.transaction(async (tx) => this.deleteInTransaction(tx, rawId));
  }

  /**
   * Transaction-scoped variant for callers that coordinate fact retraction and
   * audit in the same transaction.
   */
  async deleteInTransaction(
    tx: Db,
    rawId: string,
  ): Promise<DeletedPolicyDocument> {
    const id = requiredTrimmedString(rawId, "id", MAX_NAMESPACE_LENGTH);
    const selected = await tx.query(
      `SELECT id, source_id, namespace, file_name, content_sha256,
              attempt_token, byte_size, status, origin
         FROM policy_documents
        WHERE id = $1
        FOR UPDATE`,
      [id],
    );
    if (selected.rows.length !== 1) {
      throw new PolicyDocumentValidationError("policy document is unknown");
    }
    const row = selected.rows[0] as PolicyDocumentRow;
    const deleted: DeletedPolicyDocument = {
      id: row.id,
      sourceId: row.source_id,
      namespace: row.namespace,
      fileName: row.file_name,
      contentSha256: row.content_sha256,
      attemptToken: row.attempt_token,
      byteSize: Number(row.byte_size),
      status: row.status,
      origin: row.origin === "adopted" ? "adopted" : "upload",
    };
    await tx.query("DELETE FROM policy_documents WHERE id = $1", [id]);
    if (row.status !== "failed") {
      await releaseCurrentQuota(tx, tenantRootFor(row.namespace), Number(row.byte_size));
    }
    return deleted;
  }

  /**
   * Policy files that are already in memory but absent from the register.
   *
   * A file is a candidate when its landed facts are attributable to a source
   * document (`provenance.documentKey`) and either the file name or the facts
   * themselves read as policy material. Grouping is by FILE — the part of the
   * document key before `#` — so a CSV that landed one document per clause is
   * one adoptable row rather than one per clause.
   *
   * This reads only canonical provenance already written by the write path; it
   * never re-derives or re-classifies content.
   */
  async listAdoptionCandidates(
    rootNamespace: string,
    options: { global?: boolean; limit?: number } = {},
  ): Promise<PolicyAdoptionCandidateListResult> {
    const namespace = normalizeNamespace(rootNamespace);
    const global = options.global === true;
    const limit = options.limit ?? 25;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new PolicyDocumentValidationError("limit must be between 1 and 100");
    }
    const rows = await this.db.query(
      `WITH landed AS (
         SELECT DISTINCT
                m.id                                          AS memory_id,
                m.namespace                                   AS namespace,
                p->>'sourceId'                                AS source_id,
                p->>'documentKey'                             AS document_key,
                split_part(p->>'documentKey', '#', 1)         AS file_name,
                m.content                                     AS content,
                m.assertion_time                              AS assertion_time
           FROM memory_objects m
           -- This is the one policy query that scans ALL of a subtree's memory
           -- rather than a known source, so a single malformed provenance value
           -- would take the whole lane down. Unnest defensively instead.
           CROSS JOIN LATERAL jsonb_array_elements(
             CASE WHEN jsonb_typeof(m.provenance) = 'array'
                  THEN m.provenance ELSE '[]'::jsonb END
           ) AS p
          WHERE m.status = 'active'
            AND m.t_valid_to IS NULL
            AND p ? 'documentKey'
            AND p ? 'sourceId'
            AND p->>'documentKey' <> ''
            AND ($2::boolean OR m.namespace = $1
                 OR ($1 <> '' AND m.namespace LIKE $3 ESCAPE '\\'))
       ),
       files AS (
         SELECT source_id,
                namespace,
                file_name,
                COUNT(DISTINCT document_key)                        AS document_count,
                COUNT(DISTINCT memory_id)                           AS fact_count,
                COUNT(*) FILTER (WHERE content ILIKE '%polic%')     AS policy_facts,
                SUM(length(content))                                AS byte_size,
                MIN(assertion_time)                                 AS first_seen_at,
                MAX(assertion_time)                                 AS last_seen_at
           FROM landed
          WHERE file_name <> ''
          GROUP BY source_id, namespace, file_name
       )
       SELECT f.*,
              (f.file_name ~*
                '(polic|guideline|procedure|standard|handbook|compliance|guardrail)')
                AS file_signal,
              (f.policy_facts * 2 >= f.fact_count) AS content_signal
         FROM files f
        WHERE NOT EXISTS (
                SELECT 1 FROM policy_documents d
                 WHERE d.namespace = f.namespace
                   AND d.file_name = f.file_name
                   AND d.status <> 'failed'
              )
          AND (
                f.file_name ~*
                  '(polic|guideline|procedure|standard|handbook|compliance|guardrail)'
                OR f.policy_facts * 2 >= f.fact_count
              )
        ORDER BY f.fact_count DESC, f.file_name
        LIMIT $4`,
      [namespace, global, `${escapeLikePattern(namespace)}/%`, limit + 1],
    );
    return {
      data: rows.rows.slice(0, limit).map((row) => candidateRow(row)),
      hasMore: rows.rows.length > limit,
    };
  }

  /**
   * Promote a file that is already in memory into the register.
   *
   * No content is read, re-ingested, or copied (D10): the row points at the
   * existing source and records the exact source-document versions its facts
   * came from, which is what makes deletion able to retract precisely those
   * facts later. `content_sha256` is the digest of those versions, so the same
   * file cannot be adopted twice while it is live.
   */
  async createAdopted(
    input: AdoptPolicyDocumentInput,
  ): Promise<PolicyDocumentSummary> {
    const sourceId = requiredTrimmedString(
      input.sourceId,
      "sourceId",
      MAX_NAMESPACE_LENGTH,
    );
    const createdBy = requiredTrimmedString(
      input.createdBy,
      "createdBy",
      MAX_ACTOR_LENGTH,
    );
    const namespace = normalizeNamespace(input.namespace);
    const fileName = validateAdoptedFileName(input.fileName);
    const kind = input.kind ?? "policy";
    if (!KINDS.has(kind)) {
      throw new PolicyDocumentValidationError("Unsupported policy document kind");
    }
    const enforcement = input.enforcement ?? "required";
    if (!ENFORCEMENTS.has(enforcement)) {
      throw new PolicyDocumentValidationError(
        "enforcement must be 'advisory' or 'required'",
      );
    }
    if (!Array.isArray(input.versions) || input.versions.length === 0) {
      throw new PolicyDocumentValidationError(
        "an adopted policy file needs at least one landed source document",
      );
    }
    if (!Number.isInteger(input.factCount) || input.factCount <= 0) {
      throw new PolicyDocumentValidationError(
        "an adopted policy file needs at least one active fact",
      );
    }
    const stem = fileName.includes(".")
      ? fileName.slice(0, fileName.lastIndexOf("."))
      : fileName;
    const title =
      input.title === undefined
        ? readableTitle(stem) || fileName
        : requiredTrimmedString(input.title, "title", MAX_TITLE_LENGTH);
    if (CONTROL_CHARACTER.test(title)) {
      throw new PolicyDocumentValidationError("title cannot contain controls");
    }
    // The byte size is the size of the memory the file contributed, clamped to
    // the column's range: it feeds the tenant quota ledger, and the ledger must
    // stay releasable on delete.
    const byteSize = Math.min(
      MAX_POLICY_DOCUMENT_BYTES,
      Math.max(1, Math.round(Number(input.byteSize) || 1)),
    );
    const tenantRoot = normalizeNamespace(
      input.tenantRoot ?? tenantRootFor(namespace),
    );
    if (tenantRoot !== tenantRootFor(namespace)) {
      throw new PolicyDocumentValidationError(
        "tenantRoot must be the canonical root of the adopted namespace",
      );
    }
    const quota = normalizedQuotaLimits({});
    const createdAt = new Date().toISOString();
    const loadedAt = input.loadedAt ?? createdAt;
    return this.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO policy_document_quota_usage
           (tenant_root, current_documents, current_bytes, total_rows, updated_at)
         VALUES ($1, 0, 0, 0, $2)
         ON CONFLICT (tenant_root) DO NOTHING`,
        [tenantRoot, createdAt],
      );
      const reserved = await tx.query(
        `UPDATE policy_document_quota_usage
            SET current_documents = current_documents + 1,
                current_bytes = current_bytes + $2,
                total_rows = total_rows + 1,
                updated_at = $3
          WHERE tenant_root = $1
            AND current_documents < $4
            AND current_bytes + $2 <= $5
            AND total_rows < $6
          RETURNING tenant_root`,
        [
          tenantRoot,
          byteSize,
          createdAt,
          quota.maxDocuments,
          quota.maxBytes,
          quota.maxRows,
        ],
      );
      if (reserved.rows.length !== 1) {
        throw new PolicyDocumentQuotaError();
      }
      const duplicate = await tx.query(
        `SELECT id FROM policy_documents
          WHERE namespace = $1 AND file_name = $2 AND status <> 'failed'`,
        [namespace, fileName],
      );
      if (duplicate.rows.length > 0) {
        throw new PolicyDocumentConflictError(
          "This policy file is already in the register for the selected scope",
        );
      }
      const inserted = await tx.query(
        `INSERT INTO policy_documents
           (id, source_id, namespace, title, kind, status, enforcement, origin,
            file_name, media_type, byte_size, content_sha256, attempt_token,
            lease_expires_at, fact_count, failure_code, created_by, created_at,
            loaded_at)
         VALUES
           ($1, $2, $3, $4, $5, 'active', $6, 'adopted', $7, $8, $9, $10, $11,
            $12, $13, NULL, $14, $15, $16)
         ON CONFLICT DO NOTHING
         RETURNING *`,
        [
          ulid(),
          sourceId,
          namespace,
          title,
          kind,
          enforcement,
          fileName,
          mediaTypeFor(fileName),
          byteSize,
          adoptedContentDigest(namespace, fileName, input.versions),
          ulid(),
          // An adopted row is terminal on arrival: it never holds a live
          // ingestion lease, so the lease is already expired at insert.
          createdAt,
          input.factCount,
          createdBy,
          createdAt,
          loadedAt,
        ],
      );
      if (inserted.rows.length !== 1) {
        throw new PolicyDocumentConflictError(
          "This policy file is already in the register for the selected scope",
        );
      }
      return rowToSummary(inserted.rows[0] as PolicyDocumentRow);
    });
  }

  /**
   * Bounded canonical namespace directory for large organizations. It merges
   * namespaces already known to governance, identities, sources, and policy
   * files without returning the full people roster to the browser.
   */
  async listScopes(
    rootNamespace: string,
    options: { global?: boolean; query?: string; limit?: number } = {},
  ): Promise<PolicyDocumentScopeListResult> {
    const namespace = normalizeNamespace(rootNamespace);
    const global = options.global === true;
    const query = options.query?.trim() ?? "";
    if (query.length > MAX_SEARCH_LENGTH) {
      throw new PolicyDocumentValidationError(
        `query cannot exceed ${MAX_SEARCH_LENGTH} characters`,
      );
    }
    const limit = options.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new PolicyDocumentValidationError("limit must be between 1 and 100");
    }
    const rows = await this.db.query(
      `WITH namespaces AS (
         SELECT namespace FROM policy_documents
         UNION SELECT namespace FROM policies
         UNION SELECT namespace FROM users
         UNION SELECT namespace FROM api_keys
         UNION SELECT namespace FROM sources
         UNION SELECT $1::text AS namespace
       )
       SELECT n.namespace,
              (SELECT COUNT(*) FROM policy_documents d
                WHERE d.namespace = n.namespace
                  AND d.status IN ('processing','active','needs_review')) AS document_count
         FROM namespaces n
        WHERE (
          $2::boolean
          OR n.namespace = $1
          OR ($1 <> '' AND n.namespace LIKE $3 ESCAPE '\\')
        )
          AND ($4 = '' OR n.namespace ILIKE $5 ESCAPE '\\')
        ORDER BY CASE WHEN n.namespace = $1 THEN 0 ELSE 1 END, n.namespace
        LIMIT $6`,
      [
        namespace,
        global,
        `${escapeLikePattern(namespace)}/%`,
        query,
        `%${escapeLikePattern(query)}%`,
        limit + 1,
      ],
    );
    return {
      data: rows.rows.slice(0, limit).map((row) => {
        const value = row as { namespace: string; document_count: number | string };
        return {
          namespace: value.namespace,
          documentCount: Number(value.document_count),
        };
      }),
      hasMore: rows.rows.length > limit,
    };
  }

  async list(query: PolicyDocumentListQuery): Promise<PolicyDocumentListResult> {
    if (query === null || typeof query !== "object") {
      throw new PolicyDocumentValidationError("Policy document list query is required");
    }
    const namespace = normalizeNamespace(query.namespace);
    const page = query.page ?? 1;
    const pageSize = query.pageSize ?? 20;
    if (!Number.isInteger(page) || page < 1) {
      throw new PolicyDocumentValidationError("page must be a positive integer");
    }
    if (
      !Number.isInteger(pageSize) ||
      pageSize < 1 ||
      pageSize > MAX_PAGE_SIZE
    ) {
      throw new PolicyDocumentValidationError(
        `pageSize must be between 1 and ${MAX_PAGE_SIZE}`,
      );
    }
    if (query.kind !== undefined && !KINDS.has(query.kind)) {
      throw new PolicyDocumentValidationError("Unsupported policy document kind");
    }
    if (query.status !== undefined && !STATUSES.has(query.status)) {
      throw new PolicyDocumentValidationError(
        "Unsupported policy document status",
      );
    }

    let search: string | undefined;
    if (query.query !== undefined) {
      if (typeof query.query !== "string") {
        throw new PolicyDocumentValidationError("query must be text");
      }
      search = query.query.trim();
      if (search.length > MAX_SEARCH_LENGTH) {
        throw new PolicyDocumentValidationError(
          `query cannot exceed ${MAX_SEARCH_LENGTH} characters`,
        );
      }
      if (!search) search = undefined;
    }

    const scopeValues: unknown[] =
      namespace === ""
        ? []
        : [namespace, `${escapeLikePattern(namespace)}/%`];
    const scope =
      namespace === ""
        ? "TRUE"
        : `(namespace = $1 OR namespace LIKE $2 ESCAPE '\\')`;
    const predicates = [scope];
    const filteredValues = [...scopeValues];
    if (search !== undefined) {
      const position = filteredValues.push(
        `%${escapeLikePattern(search)}%`,
      );
      predicates.push(
        `(title ILIKE $${position} ESCAPE '\\' OR file_name ILIKE $${position} ESCAPE '\\')`,
      );
    }
    if (query.kind !== undefined) {
      const position = filteredValues.push(query.kind);
      predicates.push(`kind = $${position}`);
    }
    if (query.status !== undefined) {
      const position = filteredValues.push(query.status);
      predicates.push(`status = $${position}`);
    }
    const where = predicates.join(" AND ");
    const limitPosition = filteredValues.push(pageSize);
    const offsetPosition = filteredValues.push((page - 1) * pageSize);

    const [rows, count, summary] = await Promise.all([
      this.db.query(
        `SELECT * FROM policy_documents
          WHERE ${where}
          ORDER BY created_at DESC, id DESC
          LIMIT $${limitPosition} OFFSET $${offsetPosition}`,
        filteredValues,
      ),
      this.db.query(
        `SELECT COUNT(*) AS total FROM policy_documents
          WHERE ${where}`,
        filteredValues.slice(0, -2),
      ),
      this.db.query(
        `SELECT
           COUNT(*) AS total,
           COUNT(*) FILTER (WHERE status = 'active') AS active,
           COUNT(*) FILTER (WHERE status = 'needs_review') AS needs_review,
           COUNT(*) FILTER (WHERE status = 'failed') AS failed
         FROM policy_documents
         WHERE ${scope}`,
        scopeValues,
      ),
    ]);

    const total = Number(count.rows[0]?.total ?? 0);
    const summaryRow = summary.rows[0] as
      | {
          total: number | string;
          active: number | string;
          needs_review: number | string;
          failed: number | string;
        }
      | undefined;
    return {
      data: rows.rows.map((row) => rowToSummary(row as PolicyDocumentRow)),
      pagination: {
        page,
        pageSize,
        total,
        totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
      },
      summary: {
        total: Number(summaryRow?.total ?? 0),
        active: Number(summaryRow?.active ?? 0),
        needsReview: Number(summaryRow?.needs_review ?? 0),
        failed: Number(summaryRow?.failed ?? 0),
      },
    };
  }

  private async complete(
    rawId: string,
    status: Exclude<PolicyDocumentStatus, "processing">,
    factCount: number,
    failureCode: string | null,
    rawAttemptToken?: string,
    compensate?: (
      tx: Db,
      attempt: ExpiredPolicyDocumentAttempt,
    ) => Promise<void>,
  ): Promise<PolicyDocumentSummary> {
    const id = requiredTrimmedString(rawId, "id", MAX_NAMESPACE_LENGTH);
    const attemptToken =
      rawAttemptToken === undefined
        ? undefined
        : requiredTrimmedString(
            rawAttemptToken,
            "attemptToken",
            MAX_NAMESPACE_LENGTH,
          );
    if (!Number.isInteger(factCount) || factCount < 0) {
      throw new PolicyDocumentValidationError(
        "factCount must be a non-negative integer",
      );
    }
    const loadedAt =
      status === "failed" ? null : new Date().toISOString();
    return this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT id, source_id, namespace, file_name, content_sha256,
                attempt_token, byte_size
           FROM policy_documents
          WHERE id = $1 AND status = 'processing'
            AND ($2::text IS NULL OR attempt_token = $2)
          FOR UPDATE`,
        [id, attemptToken ?? null],
      );
      if (selected.rows.length !== 1) {
        throw new PolicyDocumentConflictError(
          "Policy document is unavailable or has already finished processing",
        );
      }
      const attempt = expiredRow(selected.rows[0]);
      if (status === "failed") {
        await compensate?.(tx, attempt);
      }
      const updated = await tx.query(
        `UPDATE policy_documents
            SET status = $2, fact_count = $3, failure_code = $4, loaded_at = $5
          WHERE id = $1 AND status = 'processing' AND attempt_token = $6
          RETURNING *`,
        [id, status, factCount, failureCode, loadedAt, attempt.attemptToken],
      );
      if (updated.rows.length !== 1) {
        throw new PolicyDocumentConflictError(
          "Policy document is unavailable or has already finished processing",
        );
      }
      if (status === "failed") {
        await releaseCurrentQuota(
          tx,
          tenantRootFor(attempt.namespace),
          attempt.byteSize,
        );
      }
      return rowToSummary(updated.rows[0] as PolicyDocumentRow);
    });
  }
}

function normalizedQuotaLimits(
  limits: PolicyDocumentQuotaLimits,
): Required<PolicyDocumentQuotaLimits> {
  const values = {
    maxDocuments:
      limits.maxDocuments ?? MAX_POLICY_DOCUMENTS_PER_TENANT,
    maxBytes: limits.maxBytes ?? MAX_POLICY_DOCUMENT_BYTES_PER_TENANT,
    maxRows: limits.maxRows ?? MAX_POLICY_DOCUMENT_ROWS_PER_TENANT,
  };
  for (const [name, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new PolicyDocumentValidationError(
        `${name} must be a positive integer`,
      );
    }
  }
  return values;
}

async function releaseCurrentQuota(
  db: Db,
  tenantRoot: string,
  byteSize: number,
): Promise<void> {
  const released = await db.query(
    `UPDATE policy_document_quota_usage
        SET current_documents = current_documents - 1,
            current_bytes = current_bytes - $2,
            updated_at = CURRENT_TIMESTAMP
      WHERE tenant_root = $1
        AND current_documents >= 1
        AND current_bytes >= $2
      RETURNING tenant_root`,
    [tenantRoot, byteSize],
  );
  if (released.rows.length !== 1) {
    throw new Error("policy document quota ledger is inconsistent");
  }
}

function expiredRow(row: unknown): ExpiredPolicyDocumentAttempt {
  const value = row as {
    id: string;
    source_id: string;
    namespace: string;
    file_name: string;
    content_sha256: string;
    attempt_token: string;
    byte_size: number | string;
  };
  return {
    id: value.id,
    sourceId: value.source_id,
    namespace: value.namespace,
    fileName: value.file_name,
    contentSha256: value.content_sha256,
    attemptToken: value.attempt_token,
    byteSize: Number(value.byte_size),
  };
}

function validateContentSha256(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new PolicyDocumentValidationError(
      "contentSha256 must be a lowercase SHA-256 digest",
    );
  }
  return value;
}

function tenantRootFor(namespace: string): string {
  if (namespace === "") return "";
  return namespace.split("/")[0]!;
}

/**
 * A file that is already in memory came from a connector or import, so its key
 * may legitimately carry directory segments. Path separators are therefore
 * allowed here (unlike an upload filename, which the browser supplies); control
 * characters never are.
 */
function validateAdoptedFileName(value: unknown): string {
  const fileName = requiredTrimmedString(value, "fileName", MAX_FILE_NAME_BYTES);
  if (Buffer.byteLength(fileName, "utf8") > MAX_FILE_NAME_BYTES) {
    throw new PolicyDocumentValidationError(
      `fileName cannot exceed ${MAX_FILE_NAME_BYTES} UTF-8 bytes`,
    );
  }
  if (CONTROL_CHARACTER.test(fileName) || fileName.includes("#")) {
    throw new PolicyDocumentValidationError(
      "fileName cannot contain control characters or a document fragment",
    );
  }
  return fileName;
}

/** Allowlisted media type, or plain text for a format the register did not define. */
function mediaTypeFor(fileName: string): string {
  const index = fileName.lastIndexOf(".");
  if (index < 0) return "text/plain";
  return MEDIA_TYPES.get(fileName.slice(index).toLowerCase()) ?? "text/plain";
}

/**
 * The identity of an adopted file version: the exact set of source documents
 * and content hashes its facts carry. Two adoptions of the same unchanged file
 * digest identically, which is what the partial unique index needs.
 */
function adoptedContentDigest(
  namespace: string,
  fileName: string,
  versions: AdoptedDocumentVersion[],
): string {
  const canonical = versions
    .map((version) => `${version.documentKey} ${version.contentHash}`)
    .sort()
    .join("\n");
  return createHash("sha256")
    .update(`adopted ${namespace} ${fileName} ${canonical}`, "utf8")
    .digest("hex");
}

function candidateRow(row: unknown): PolicyAdoptionCandidate {
  const value = row as {
    source_id: string;
    namespace: string;
    file_name: string;
    document_count: number | string;
    fact_count: number | string;
    byte_size: number | string | null;
    first_seen_at: string | Date | null;
    last_seen_at: string | Date | null;
    file_signal: boolean | null;
    content_signal: boolean | null;
  };
  const fileSignal = value.file_signal === true;
  const contentSignal = value.content_signal === true;
  const stem = value.file_name.includes(".")
    ? value.file_name.slice(0, value.file_name.lastIndexOf("."))
    : value.file_name;
  return {
    sourceId: value.source_id,
    namespace: value.namespace,
    fileName: value.file_name,
    title: readableTitle(stem) || value.file_name,
    mediaType: mediaTypeFor(value.file_name),
    documentCount: Number(value.document_count),
    factCount: Number(value.fact_count),
    byteSize: Number(value.byte_size ?? 0),
    signal: fileSignal && contentSignal ? "both" : fileSignal ? "file-name" : "content",
    firstSeenAt:
      value.first_seen_at === null
        ? null
        : new Date(value.first_seen_at).toISOString(),
    lastSeenAt:
      value.last_seen_at === null
        ? null
        : new Date(value.last_seen_at).toISOString(),
  };
}

function validateFileName(value: unknown): string {
  const fileName = requiredTrimmedString(value, "fileName", MAX_FILE_NAME_BYTES);
  if (Buffer.byteLength(fileName, "utf8") > MAX_FILE_NAME_BYTES) {
    throw new PolicyDocumentValidationError(
      `fileName cannot exceed ${MAX_FILE_NAME_BYTES} UTF-8 bytes`,
    );
  }
  if (CONTROL_OR_SEPARATOR.test(fileName)) {
    throw new PolicyDocumentValidationError(
      "fileName cannot contain path separators or control characters",
    );
  }
  return fileName;
}

function normalizeNamespace(value: unknown): string {
  if (typeof value !== "string") {
    throw new PolicyDocumentValidationError("namespace must be text");
  }
  // The authenticated platform root is represented by the exact empty
  // namespace. Whitespace-only input is not an alias for that privileged
  // scope.
  if (value === "") return "";
  const namespace = value.trim();
  if (!namespace || namespace.length > MAX_NAMESPACE_LENGTH) {
    throw new PolicyDocumentValidationError(
      `namespace must be empty for platform root or between 1 and ${MAX_NAMESPACE_LENGTH} characters`,
    );
  }
  if (CONTROL_CHARACTER.test(namespace)) {
    throw new PolicyDocumentValidationError(
      "namespace cannot contain control characters",
    );
  }
  return namespace;
}

function requiredTrimmedString(
  value: unknown,
  field: string,
  maxLength: number,
): string {
  if (typeof value !== "string") {
    throw new PolicyDocumentValidationError(`${field} must be text`);
  }
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength) {
    throw new PolicyDocumentValidationError(
      `${field} must be between 1 and ${maxLength} characters`,
    );
  }
  return normalized;
}

function readableTitle(stem: string): string {
  return stem
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function rowToSummary(row: PolicyDocumentRow): PolicyDocumentSummary {
  return {
    id: row.id,
    sourceId: row.source_id,
    namespace: row.namespace,
    title: row.title,
    kind: row.kind,
    status: row.status,
    enforcement: row.enforcement === "advisory" ? "advisory" : "required",
    origin: row.origin === "adopted" ? "adopted" : "upload",
    fileName: row.file_name,
    mediaType: row.media_type,
    byteSize: Number(row.byte_size),
    contentSha256: row.content_sha256,
    factCount: Number(row.fact_count),
    failureCode: row.failure_code,
    createdBy: row.created_by,
    createdAt: new Date(row.created_at).toISOString(),
    loadedAt:
      row.loaded_at === null ? null : new Date(row.loaded_at).toISOString(),
  };
}
