import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import { DurableRateLimitStore } from "../durable/rate-limit.js";
import type {
  CompanyFileLifecycleState,
  CompanyFileListResult,
  CompanyFileStatus,
  CompanyFileSummary,
} from "../types.js";

export const COMPANY_FILE_LEASE_MS = 15 * 60 * 1_000;
export const MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS = 20;
export const MAX_COMPANY_FILES_PER_TENANT = 10_000;
export const MAX_COMPANY_FILE_BYTES_PER_TENANT = 2 * 1024 * 1024 * 1024;
export const MAX_COMPANY_FILE_ROWS_PER_TENANT = 50_000;

const DIGEST = /^[0-9a-f]{64}$/;
const FAILURE_CODE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const CONTROL = /\p{Cc}/u;
const FILE_SEPARATOR_OR_CONTROL = /[\\/\p{Cc}]/u;
const MAX_PAGE_SIZE = 50;

export class CompanyFileValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CompanyFileValidationError";
  }
}

export class CompanyFileConflictError extends Error {
  constructor(message = "Company file operation conflicts with current state") {
    super(message);
    this.name = "CompanyFileConflictError";
  }
}

export type CompanyFileIdempotencyErrorCode =
  | "company_file_idempotency_conflict"
  | "company_file_upload_processing"
  | "company_file_upload_unreserved";

export class CompanyFileIdempotencyError extends CompanyFileConflictError {
  constructor(
    readonly code: CompanyFileIdempotencyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CompanyFileIdempotencyError";
  }
}

export class CompanyFileLeaseExpiredError extends Error {
  constructor(message = "Company file processing lease is no longer active") {
    super(message);
    this.name = "CompanyFileLeaseExpiredError";
  }
}

export class CompanyFileQuotaError extends Error {
  constructor(message = "Company file quota has been reached") {
    super(message);
    this.name = "CompanyFileQuotaError";
  }
}

export class CompanyFileConcurrencyError extends Error {
  constructor(message = "Too many uploads in progress for this namespace") {
    super(message);
    this.name = "CompanyFileConcurrencyError";
  }
}

export class CompanyFileRateLimitError extends Error {
  constructor(
    readonly retryAfterSec: number,
    message = "Company file upload rate limit has been reached",
  ) {
    super(message);
    this.name = "CompanyFileRateLimitError";
  }
}

export interface CompanyFileAttemptRateLimit {
  bucketKey: string;
  limit: number;
  windowMs: number;
}

export interface CompanyFileQuotaLimits {
  maxFiles?: number;
  maxBytes?: number;
  maxRows?: number;
}

export type CompanyFileAttemptStatus =
  | "pending"
  | "processing"
  | "completed"
  | "partially_failed"
  | "failed";

export interface CompanyFileUploadAttemptSummary {
  id: string;
  namespace: string;
  knowledgeBaseId: string;
  targetTeamId: string | null;
  idempotencyKey: string;
  requestSha256: string;
  status: CompanyFileAttemptStatus;
  requestedFileCount: number;
  acceptedFileCount: number;
  failedFileCount: number;
  failureCode: string | null;
  createdBy: string;
  createdAt: string;
  completedAt: string | null;
}

export interface ReserveCompanyFileAttemptInput {
  namespace: string;
  knowledgeBaseId: string;
  targetTeamId: string | null;
  idempotencyKey: string;
  requestSha256: string;
  requestedFileCount: number;
  createdBy: string;
  leaseMs?: number;
  rateLimit?: CompanyFileAttemptRateLimit;
}

export interface ReserveCompanyFileInput {
  namespace: string;
  knowledgeBaseId: string;
  sourceId: string;
  knowledgeSourceId?: string | null;
  uploadAttemptId: string;
  attemptToken: string;
  title: string;
  description: string;
  purpose: string;
  fileName: string;
  mediaType: string;
  byteSize: number;
  contentSha256: string;
  createdBy: string;
  uploadedBy: string;
  supersedes?: string | null;
}

export interface FinalizeCompanyFileInput {
  status: Exclude<CompanyFileStatus, "processing">;
  factCount: number;
  failureCode?: string;
}

/** Exact D10 coordinates supplied to kernel-owned compensation, never mutated here. */
export interface CompanyFileCompensation {
  id: string;
  sourceId: string;
  namespace: string;
  documentKey: string;
  contentHash: string;
  attemptToken: string;
  byteSize: number;
}

export type CompanyFileCompensator = (
  tx: Db,
  exact: CompanyFileCompensation,
) => Promise<void>;

export interface CompanyFileListInput {
  viewerNamespace: string;
  /**
   * Server-resolved read scope for governance views. When omitted, the store
   * retains the memory-read ancestor semantics used by lower-level callers.
   */
  visibleNamespaces?: readonly string[];
  knowledgeBaseId?: string;
  targetTeamId?: string;
  query?: string;
  status?: CompanyFileStatus;
  lifecycleState?: CompanyFileLifecycleState;
  page?: number;
  pageSize?: number;
}

interface AttemptRow {
  id: string;
  namespace: string;
  knowledge_base_id: string;
  target_team_id: string | null;
  idempotency_key: string;
  request_sha256: string;
  status: CompanyFileAttemptStatus;
  requested_file_count: number | string;
  accepted_file_count: number | string;
  failed_file_count: number | string;
  attempt_token: string;
  lease_expires_at: string | Date;
  failure_code: string | null;
  created_by: string;
  created_at: string | Date;
  completed_at: string | Date | null;
}

interface FileRow {
  id: string;
  knowledge_base_id: string;
  source_id: string;
  namespace: string;
  target_team_id: string | null;
  knowledge_source_id: string | null;
  upload_attempt_id: string | null;
  title: string;
  description: string;
  purpose: string;
  status: CompanyFileStatus;
  lifecycle_state: CompanyFileLifecycleState;
  file_name: string;
  media_type: string;
  byte_size: number | string;
  content_sha256: string;
  attempt_token: string;
  lease_expires_at: string | Date;
  fact_count: number | string;
  failure_code: string | null;
  supersedes: string | null;
  t_valid_from: string | Date;
  t_valid_to: string | Date | null;
  created_by: string;
  uploaded_by: string;
  created_at: string | Date;
  loaded_at: string | Date | null;
  archived_at: string | Date | null;
}

export class CompanyFileStore {
  constructor(private readonly db: Db) {}

  async reserveAttempt(
    raw: ReserveCompanyFileAttemptInput,
  ): Promise<{ attempt: CompanyFileUploadAttemptSummary; attemptToken: string; replayed: boolean }> {
    const input = normalizeAttemptInput(raw);
    const now = new Date().toISOString();
    const leaseExpiresAt = new Date(Date.parse(now) + input.leaseMs).toISOString();
    const token = ulid();

    return this.db.transaction(async (tx) => {
      const base = await tx.query(
        `SELECT id, target_team_id
           FROM knowledge_bases
          WHERE id = $1 AND namespace = $2 AND kind = 'file'
            AND lifecycle_state = 'active' AND t_valid_to IS NULL
          FOR UPDATE`,
        [input.knowledgeBaseId, input.namespace],
      );
      if (base.rows.length !== 1) {
        throw new CompanyFileConflictError("Knowledge base is unavailable for uploads");
      }
      const baseTeam = (base.rows[0] as { target_team_id: string | null }).target_team_id;
      if (baseTeam !== input.targetTeamId) {
        throw new CompanyFileConflictError("Upload target does not match the knowledge base");
      }

      // Reconciliation is not new work. Resolve a durable key before applying
      // the concurrency gate so an accepted upload remains recoverable while
      // the namespace is at capacity. The unique constraint below still closes
      // the race between concurrent first deliveries.
      const existing = await tx.query(
        `SELECT * FROM company_file_upload_attempts
          WHERE namespace = $1 AND idempotency_key = $2
          FOR UPDATE`,
        [input.namespace, input.idempotencyKey],
      );
      const existingAttempt = existing.rows[0] as AttemptRow | undefined;
      if (existingAttempt !== undefined) {
        assertMatchingAttempt(existingAttempt, input);
        return attemptReservation(existingAttempt, true);
      }

      const concurrencyCheck = await tx.query(
        `SELECT count(*) as count FROM company_file_upload_attempts
          WHERE namespace = $1 AND status = 'processing' AND lease_expires_at > now()`,
        [input.namespace],
      );
      const activeCount = Number((concurrencyCheck.rows[0] as { count: string | number }).count);
      if (activeCount >= MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS) {
        throw new CompanyFileConcurrencyError();
      }

      const inserted = await tx.query(
        `INSERT INTO company_file_upload_attempts
           (id, namespace, knowledge_base_id, target_team_id, idempotency_key,
            request_sha256, status, requested_file_count, accepted_file_count,
            failed_file_count, attempt_token, lease_expires_at, failure_code,
            created_by, created_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'processing', $7, 0, 0, $8, $9,
                 NULL, $10, $11, NULL)
         ON CONFLICT (namespace, idempotency_key) DO NOTHING
         RETURNING *`,
        [
          ulid(),
          input.namespace,
          input.knowledgeBaseId,
          input.targetTeamId,
          input.idempotencyKey,
          input.requestSha256,
          input.requestedFileCount,
          token,
          leaseExpiresAt,
          input.createdBy,
          now,
        ],
      );
      const row = inserted.rows[0] as AttemptRow | undefined;
      if (row !== undefined) {
        if (input.rateLimit !== null) {
          const rate = await new DurableRateLimitStore(tx).consume(
            input.rateLimit.bucketKey,
            input.rateLimit.limit,
            input.rateLimit.windowMs,
          );
          if (!rate.allowed) throw new CompanyFileRateLimitError(rate.retryAfterSec);
        }
        return attemptReservation(row, false);
      }

      const replay = await tx.query(
        `SELECT * FROM company_file_upload_attempts
          WHERE namespace = $1 AND idempotency_key = $2
          FOR UPDATE`,
        [input.namespace, input.idempotencyKey],
      );
      const prior = replay.rows[0] as AttemptRow | undefined;
      if (prior === undefined) {
        throw new CompanyFileIdempotencyError(
          "company_file_idempotency_conflict",
          "Idempotency key was already used for a different upload request",
        );
      }
      assertMatchingAttempt(prior, input);
      return attemptReservation(prior, true);
    });
  }

  /**
   * Reconcile an already-admitted request without consuming rate-limit or
   * concurrency capacity. `reserveAttempt` remains the atomic first-write
   * boundary when no matching row exists.
   */
  async findAttempt(
    raw: ReserveCompanyFileAttemptInput,
  ): Promise<{ attempt: CompanyFileUploadAttemptSummary; attemptToken: string; replayed: true } | null> {
    const input = normalizeAttemptInput(raw);
    const result = await this.db.query(
      `SELECT * FROM company_file_upload_attempts
        WHERE namespace = $1 AND idempotency_key = $2`,
      [input.namespace, input.idempotencyKey],
    );
    const prior = result.rows[0] as AttemptRow | undefined;
    if (prior === undefined) return null;
    assertMatchingAttempt(prior, input);
    return { ...attemptReservation(prior, true), replayed: true };
  }

  async reserveFile(
    raw: ReserveCompanyFileInput,
    rawLimits: CompanyFileQuotaLimits = {},
  ): Promise<{ file: CompanyFileSummary; attemptToken: string }> {
    const input = normalizeFileInput(raw);
    const limits = normalizeQuotaLimits(rawLimits);
    const now = new Date().toISOString();
    return this.db.transaction(async (tx) => {
      const attemptResult = await tx.query(
        `SELECT * FROM company_file_upload_attempts
          WHERE id = $1 AND namespace = $2 AND knowledge_base_id = $3
            AND attempt_token = $4 AND status IN ('pending','processing')
          FOR UPDATE`,
        [
          input.uploadAttemptId,
          input.namespace,
          input.knowledgeBaseId,
          input.attemptToken,
        ],
      );
      const attempt = attemptResult.rows[0] as AttemptRow | undefined;
      if (attempt === undefined) {
        throw new CompanyFileConflictError("Upload attempt is unavailable");
      }
      if (Date.parse(toIso(attempt.lease_expires_at)) <= Date.now()) {
        throw new CompanyFileLeaseExpiredError();
      }

      const base = await tx.query(
        `SELECT id FROM knowledge_bases
          WHERE id = $1 AND namespace = $2 AND kind = 'file'
            AND lifecycle_state = 'active' AND t_valid_to IS NULL`,
        [input.knowledgeBaseId, input.namespace],
      );
      const source = await tx.query(
        `SELECT id FROM sources
          WHERE id = $1 AND namespace = $2 AND kind = 'file-upload'`,
        [input.sourceId, input.namespace],
      );
      if (base.rows.length !== 1 || source.rows.length !== 1) {
        throw new CompanyFileConflictError("File provenance target is unavailable");
      }
      if (input.knowledgeSourceId !== null) {
        const linked = await tx.query(
          `SELECT id FROM knowledge_sources
            WHERE id = $1 AND knowledge_base_id = $2 AND namespace = $3
              AND status <> 'archived' AND t_valid_to IS NULL`,
          [input.knowledgeSourceId, input.knowledgeBaseId, input.namespace],
        );
        if (linked.rows.length !== 1) {
          throw new CompanyFileConflictError("Knowledge source is unavailable");
        }
      }
      const count = await tx.query(
        `SELECT count(*) AS n FROM company_files WHERE upload_attempt_id = $1`,
        [input.uploadAttemptId],
      );
      if (Number(count.rows[0]?.n ?? 0) >= Number(attempt.requested_file_count)) {
        throw new CompanyFileConflictError("Upload attempt has no remaining file slots");
      }

      const tenantRoot = tenantRootFor(input.namespace);
      await tx.query(
        `INSERT INTO company_file_quota_usage
           (tenant_root, current_files, current_bytes, total_rows, updated_at)
         VALUES ($1, 0, 0, 0, $2)
         ON CONFLICT (tenant_root) DO NOTHING`,
        [tenantRoot, now],
      );
      const quota = await tx.query(
        `UPDATE company_file_quota_usage
            SET current_files = current_files + 1,
                current_bytes = current_bytes + $2,
                total_rows = total_rows + 1,
                updated_at = $6
          WHERE tenant_root = $1
            AND current_files < $3
            AND current_bytes + $2 <= $4
            AND total_rows < $5
          RETURNING tenant_root`,
        [tenantRoot, input.byteSize, limits.maxFiles, limits.maxBytes, limits.maxRows, now],
      );
      if (quota.rows.length !== 1) throw new CompanyFileQuotaError();

      const inserted = await tx.query(
        `INSERT INTO company_files
           (id, knowledge_base_id, source_id, namespace, knowledge_source_id,
            upload_attempt_id, title, description, purpose, status,
            lifecycle_state, file_name, media_type, byte_size, content_sha256,
            attempt_token, lease_expires_at, fact_count, failure_code,
            supersedes, t_valid_from, t_valid_to, created_by, uploaded_by,
            created_at, loaded_at, archived_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processing', 'active',
                 $10, $11, $12, $13, $14, $15, 0, NULL, $16, $17, NULL, $18,
                 $19, $17, NULL, NULL)
         ON CONFLICT DO NOTHING
         RETURNING *`,
        [
          ulid(),
          input.knowledgeBaseId,
          input.sourceId,
          input.namespace,
          input.knowledgeSourceId,
          input.uploadAttemptId,
          input.title,
          input.description,
          input.purpose,
          input.fileName,
          input.mediaType,
          input.byteSize,
          input.contentSha256,
          input.attemptToken,
          toIso(attempt.lease_expires_at),
          input.supersedes,
          now,
          input.createdBy,
          input.uploadedBy,
        ],
      );
      const row = inserted.rows[0] as FileRow | undefined;
      if (row === undefined) {
        throw new CompanyFileConflictError(
          "This content is already active in the knowledge base",
        );
      }
      await tx.query(
        `UPDATE knowledge_bases SET status = 'processing', updated_at = $2
          WHERE id = $1 AND lifecycle_state = 'active'`,
        [input.knowledgeBaseId, now],
      );
      return {
        file: fileSummary(row, attempt.target_team_id),
        attemptToken: input.attemptToken,
      };
    });
  }

  async renewLease(
    rawAttemptId: string,
    rawAttemptToken: string,
    leaseMs = COMPANY_FILE_LEASE_MS,
  ): Promise<boolean> {
    const attemptId = text(rawAttemptId, "attemptId", 128);
    const attemptToken = text(rawAttemptToken, "attemptToken", 256);
    const duration = positiveInteger(leaseMs, "leaseMs", Number.MAX_SAFE_INTEGER);
    const leaseExpiresAt = new Date(Date.now() + duration).toISOString();
    return this.db.transaction(async (tx) => {
      const renewed = await tx.query(
        `UPDATE company_file_upload_attempts
            SET lease_expires_at = $3
          WHERE id = $1 AND attempt_token = $2
            AND status IN ('pending','processing')
            AND lease_expires_at > CURRENT_TIMESTAMP
          RETURNING id`,
        [attemptId, attemptToken, leaseExpiresAt],
      );
      if (renewed.rows.length !== 1) return false;
      await tx.query(
        `UPDATE company_files SET lease_expires_at = $3
          WHERE upload_attempt_id = $1 AND attempt_token = $2
            AND status = 'processing' AND lifecycle_state = 'active'`,
        [attemptId, attemptToken, leaseExpiresAt],
      );
      return true;
    });
  }

  async finalize(
    rawId: string,
    rawAttemptToken: string,
    rawOutcome: FinalizeCompanyFileInput,
    compensate?: CompanyFileCompensator,
  ): Promise<CompanyFileSummary> {
    const id = text(rawId, "id", 128);
    const attemptToken = text(rawAttemptToken, "attemptToken", 256);
    const outcome = normalizeOutcome(rawOutcome);
    return this.db.transaction(async (tx) => {
      const selected = await selectFileForUpdate(tx, id);
      if (
        selected === undefined ||
        selected.attempt_token !== attemptToken ||
        selected.lifecycle_state !== "active" ||
        selected.status !== "processing"
      ) {
        if (selected?.failure_code === "processing_timeout") {
          throw new CompanyFileLeaseExpiredError();
        }
        throw new CompanyFileConflictError("Company file has already finished processing");
      }
      const attemptResult = selected.upload_attempt_id === null
        ? { rows: [] }
        : await tx.query(
            `SELECT * FROM company_file_upload_attempts
              WHERE id = $1 AND attempt_token = $2
                AND status IN ('pending','processing')
              FOR UPDATE`,
            [selected.upload_attempt_id, attemptToken],
          );
      const attempt = attemptResult.rows[0] as AttemptRow | undefined;
      if (
        Date.parse(toIso(selected.lease_expires_at)) <= Date.now() ||
        (selected.upload_attempt_id !== null &&
          (attempt === undefined || Date.parse(toIso(attempt.lease_expires_at)) <= Date.now()))
      ) {
        throw new CompanyFileLeaseExpiredError();
      }

      if (outcome.status === "failed") {
        await compensate?.(tx, compensation(selected));
        await releaseCurrentQuota(tx, selected.namespace, Number(selected.byte_size));
      }
      const loadedAt = outcome.status === "failed" ? null : new Date().toISOString();
      const updated = await tx.query(
        `UPDATE company_files
            SET status = $3, fact_count = $4, failure_code = $5, loaded_at = $6
          WHERE id = $1 AND attempt_token = $2 AND status = 'processing'
            AND lifecycle_state = 'active'
          RETURNING *`,
        [
          id,
          attemptToken,
          outcome.status,
          outcome.factCount,
          outcome.failureCode,
          loadedAt,
        ],
      );
      if (updated.rows.length !== 1) {
        throw new CompanyFileConflictError("Company file has already finished processing");
      }
      if (attempt !== undefined) {
        await accountFinalizedFile(
          tx,
          attempt,
          outcome.status === "failed" ? "failed" : "accepted",
          outcome.failureCode,
        );
      }
      await refreshKnowledgeBaseStatus(tx, selected.knowledge_base_id);
      return fileSummary(updated.rows[0] as FileRow, selected.target_team_id);
    });
  }

  async expireAttempt(
    rawAttemptId: string,
    rawAttemptToken: string,
    compensate?: CompanyFileCompensator,
  ): Promise<boolean> {
    const attemptId = text(rawAttemptId, "attemptId", 128);
    const attemptToken = text(rawAttemptToken, "attemptToken", 256);
    return this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT * FROM company_file_upload_attempts
          WHERE id = $1 AND attempt_token = $2
            AND status IN ('pending','processing')
          FOR UPDATE`,
        [attemptId, attemptToken],
      );
      const attempt = selected.rows[0] as AttemptRow | undefined;
      if (attempt === undefined) return false;
      if (Date.parse(toIso(attempt.lease_expires_at)) > Date.now()) return false;

      const files = await tx.query(
        `${fileSelect()}
          WHERE f.upload_attempt_id = $1 AND f.attempt_token = $2
            AND f.status = 'processing' AND f.lifecycle_state = 'active'
          FOR UPDATE`,
        [attemptId, attemptToken],
      );
      for (const raw of files.rows) {
        const file = raw as FileRow;
        await compensate?.(tx, compensation(file));
        await releaseCurrentQuota(tx, file.namespace, Number(file.byte_size));
        await tx.query(
          `UPDATE company_files
              SET status = 'failed', fact_count = 0,
                  failure_code = 'processing_timeout', loaded_at = NULL
            WHERE id = $1 AND attempt_token = $2 AND status = 'processing'`,
          [file.id, attemptToken],
        );
      }
      const accepted = Number(attempt.accepted_file_count);
      const failed = Number(attempt.requested_file_count) - accepted;
      const status: CompanyFileAttemptStatus = accepted > 0
        ? "partially_failed"
        : "failed";
      await tx.query(
        `UPDATE company_file_upload_attempts
            SET status = $3, failed_file_count = $4,
                failure_code = 'processing_timeout', completed_at = CURRENT_TIMESTAMP
          WHERE id = $1 AND attempt_token = $2
            AND status IN ('pending','processing')`,
        [attemptId, attemptToken, status, failed],
      );
      await refreshKnowledgeBaseStatus(tx, attempt.knowledge_base_id);
      return true;
    });
  }

  async getAttempt(
    rawId: string,
    rawViewerNamespace: string,
  ): Promise<CompanyFileUploadAttemptSummary | null> {
    const id = text(rawId, "id", 128);
    const visible = namespaceAncestors(rawViewerNamespace);
    if (visible.length === 0) return null;
    const placeholders = visible.map((_, index) => `$${index + 2}`).join(", ");
    const result = await this.db.query(
      `SELECT * FROM company_file_upload_attempts
        WHERE id = $1 AND namespace IN (${placeholders})`,
      [id, ...visible],
    );
    return result.rows.length === 0
      ? null
      : attemptSummary(result.rows[0] as AttemptRow);
  }

  /** Resolve the immutable company-file row produced by one upload attempt. */
  async getByAttempt(
    rawAttemptId: string,
    rawNamespace: string,
  ): Promise<CompanyFileSummary | null> {
    const attemptId = text(rawAttemptId, "attemptId", 128);
    const exactNamespace = namespace(rawNamespace);
    const result = await this.db.query(
      `${fileSelect()}
        WHERE f.upload_attempt_id = $1 AND f.namespace = $2
        ORDER BY f.created_at DESC, f.id DESC
        LIMIT 1`,
      [attemptId, exactNamespace],
    );
    return result.rows.length === 0 ? null : fileSummary(result.rows[0] as FileRow);
  }

  async get(
    rawId: string,
    rawViewerNamespace: string,
  ): Promise<CompanyFileSummary | null> {
    const id = text(rawId, "id", 128);
    const visible = namespaceAncestors(rawViewerNamespace);
    if (visible.length === 0) return null;
    const placeholders = visible.map((_, index) => `$${index + 2}`).join(", ");
    const result = await this.db.query(
      `${fileSelect()} WHERE f.id = $1 AND f.namespace IN (${placeholders})`,
      [id, ...visible],
    );
    return result.rows.length === 0 ? null : fileSummary(result.rows[0] as FileRow);
  }

  async list(raw: CompanyFileListInput): Promise<CompanyFileListResult> {
    if (raw === null || typeof raw !== "object") {
      throw new CompanyFileValidationError("Company file list input is required");
    }
    const visible = raw.visibleNamespaces === undefined
      ? namespaceAncestors(raw.viewerNamespace)
      : [...new Set(raw.visibleNamespaces.map((value) => namespace(value)))];
    const page = positiveInteger(raw.page ?? 1, "page", Number.MAX_SAFE_INTEGER);
    const pageSize = positiveInteger(raw.pageSize ?? 20, "pageSize", MAX_PAGE_SIZE);
    if (visible.length === 0) return emptyList(page, pageSize);

    const values: unknown[] = [...visible];
    const placeholders = visible.map((_, index) => `$${index + 1}`).join(", ");
    const predicates = [`f.namespace IN (${placeholders})`];
    if (raw.knowledgeBaseId !== undefined) {
      const position = values.push(text(raw.knowledgeBaseId, "knowledgeBaseId", 128));
      predicates.push(`f.knowledge_base_id = $${position}`);
    }
    if (raw.targetTeamId !== undefined) {
      const position = values.push(text(raw.targetTeamId, "targetTeamId", 128));
      predicates.push(`kb.target_team_id = $${position}`);
    }
    if (raw.status !== undefined) {
      if (!FILE_STATUSES.has(raw.status)) {
        throw new CompanyFileValidationError("Unsupported company file status");
      }
      const position = values.push(raw.status);
      predicates.push(`f.status = $${position}`);
    }
    if (raw.lifecycleState !== undefined) {
      if (!FILE_LIFECYCLES.has(raw.lifecycleState)) {
        throw new CompanyFileValidationError("Unsupported company file lifecycle state");
      }
      const position = values.push(raw.lifecycleState);
      predicates.push(`f.lifecycle_state = $${position}`);
    }
    if (raw.query !== undefined) {
      const query = text(raw.query, "query", 200);
      const position = values.push(query);
      predicates.push(`(position(lower($${position}) in lower(f.title)) > 0 OR position(lower($${position}) in lower(f.file_name)) > 0)`);
    }
    const where = predicates.join(" AND ");
    const limitPosition = values.push(pageSize);
    const offsetPosition = values.push((page - 1) * pageSize);
    const [rows, totals] = await Promise.all([
      this.db.query(
        `${fileSelect()} WHERE ${where}
          ORDER BY f.created_at DESC, f.id DESC
          LIMIT $${limitPosition} OFFSET $${offsetPosition}`,
        values,
      ),
      this.db.query(
        `SELECT count(*) AS total,
                count(*) FILTER (WHERE f.status = 'ready') AS ready,
                count(*) FILTER (WHERE f.status = 'processing') AS processing,
                count(*) FILTER (WHERE f.status = 'needs_review') AS needs_review,
                count(*) FILTER (WHERE f.status = 'failed') AS failed
           FROM company_files f
           JOIN knowledge_bases kb ON kb.id = f.knowledge_base_id
          WHERE ${where}`,
        values.slice(0, -2),
      ),
    ]);
    const total = Number(totals.rows[0]?.total ?? 0);
    return {
      data: rows.rows.map((row) => fileSummary(row as FileRow)),
      pagination: {
        page,
        pageSize,
        total,
        totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
      },
      summary: {
        total,
        ready: Number(totals.rows[0]?.ready ?? 0),
        processing: Number(totals.rows[0]?.processing ?? 0),
        needsReview: Number(totals.rows[0]?.needs_review ?? 0),
        failed: Number(totals.rows[0]?.failed ?? 0),
      },
    };
  }

  async archive(
    rawId: string,
    rawViewerNamespace: string,
    compensate?: CompanyFileCompensator,
  ): Promise<CompanyFileSummary | null> {
    const id = text(rawId, "id", 128);
    const visible = namespaceAncestors(rawViewerNamespace);
    if (visible.length === 0) return null;
    return this.db.transaction(async (tx) => {
      const placeholders = visible.map((_, index) => `$${index + 2}`).join(", ");
      const result = await tx.query(
        `${fileSelect()} WHERE f.id = $1 AND f.namespace IN (${placeholders}) FOR UPDATE`,
        [id, ...visible],
      );
      const file = result.rows[0] as FileRow | undefined;
      if (file === undefined) return null;
      if (file.lifecycle_state === "archived") return fileSummary(file);

      await compensate?.(tx, compensation(file));
      if (file.status !== "failed") {
        await releaseCurrentQuota(tx, file.namespace, Number(file.byte_size));
      }
      const now = new Date().toISOString();
      const updated = await tx.query(
        `UPDATE company_files
            SET lifecycle_state = 'archived', archived_at = $2, t_valid_to = $2,
                status = CASE WHEN status = 'processing' THEN 'failed' ELSE status END,
                failure_code = CASE WHEN status = 'processing' THEN 'archived' ELSE failure_code END
          WHERE id = $1 AND lifecycle_state = 'active'
          RETURNING *`,
        [id, now],
      );
      if (file.status === "processing" && file.upload_attempt_id !== null) {
        const attemptResult = await tx.query(
          `SELECT * FROM company_file_upload_attempts WHERE id = $1 FOR UPDATE`,
          [file.upload_attempt_id],
        );
        const attempt = attemptResult.rows[0] as AttemptRow | undefined;
        if (attempt !== undefined && ["pending", "processing"].includes(attempt.status)) {
          await accountFinalizedFile(tx, attempt, "failed", "archived");
        }
      }
      await refreshKnowledgeBaseStatus(tx, file.knowledge_base_id);
      return fileSummary(updated.rows[0] as FileRow, file.target_team_id);
    });
  }
}

const FILE_STATUSES = new Set<CompanyFileStatus>([
  "processing",
  "ready",
  "needs_review",
  "failed",
]);
const FILE_LIFECYCLES = new Set<CompanyFileLifecycleState>(["active", "archived"]);

function normalizeQuotaLimits(raw: CompanyFileQuotaLimits): Required<CompanyFileQuotaLimits> {
  if (raw === null || typeof raw !== "object") {
    throw new CompanyFileValidationError("Company file quota limits must be an object");
  }
  return {
    maxFiles: positiveInteger(
      raw.maxFiles ?? MAX_COMPANY_FILES_PER_TENANT,
      "maxFiles",
      Number.MAX_SAFE_INTEGER,
    ),
    maxBytes: positiveInteger(
      raw.maxBytes ?? MAX_COMPANY_FILE_BYTES_PER_TENANT,
      "maxBytes",
      Number.MAX_SAFE_INTEGER,
    ),
    maxRows: positiveInteger(
      raw.maxRows ?? MAX_COMPANY_FILE_ROWS_PER_TENANT,
      "maxRows",
      Number.MAX_SAFE_INTEGER,
    ),
  };
}

function tenantRootFor(namespace: string): string {
  return namespace.split("/", 1)[0]!;
}

async function releaseCurrentQuota(db: Db, namespace: string, byteSize: number): Promise<void> {
  const released = await db.query(
    `UPDATE company_file_quota_usage
        SET current_files = current_files - 1,
            current_bytes = current_bytes - $2,
            updated_at = $3
      WHERE tenant_root = $1
        AND current_files > 0
        AND current_bytes >= $2
      RETURNING tenant_root`,
    [tenantRootFor(namespace), byteSize, new Date().toISOString()],
  );
  if (released.rows.length !== 1) {
    throw new CompanyFileConflictError("Company file quota usage is inconsistent");
  }
}

function normalizeAttemptInput(
  raw: ReserveCompanyFileAttemptInput,
): Required<Omit<ReserveCompanyFileAttemptInput, "targetTeamId" | "rateLimit">> & {
  targetTeamId: string | null;
  rateLimit: CompanyFileAttemptRateLimit | null;
} {
  if (raw === null || typeof raw !== "object") {
    throw new CompanyFileValidationError("Upload attempt input is required");
  }
  if (
    raw.rateLimit !== undefined &&
    (raw.rateLimit === null || typeof raw.rateLimit !== "object")
  ) {
    throw new CompanyFileValidationError("rateLimit must be an object");
  }
  return {
    namespace: namespace(raw.namespace),
    knowledgeBaseId: text(raw.knowledgeBaseId, "knowledgeBaseId", 128),
    targetTeamId: raw.targetTeamId === null
      ? null
      : text(raw.targetTeamId, "targetTeamId", 128),
    idempotencyKey: text(raw.idempotencyKey, "idempotencyKey", 256),
    requestSha256: digest(raw.requestSha256, "requestSha256"),
    requestedFileCount: positiveInteger(raw.requestedFileCount, "requestedFileCount", 100),
    createdBy: text(raw.createdBy, "createdBy", 512),
    leaseMs: positiveInteger(raw.leaseMs ?? COMPANY_FILE_LEASE_MS, "leaseMs", Number.MAX_SAFE_INTEGER),
    rateLimit: raw.rateLimit === undefined ? null : {
      bucketKey: text(raw.rateLimit.bucketKey, "rateLimit.bucketKey", 512),
      limit: positiveInteger(raw.rateLimit.limit, "rateLimit.limit", Number.MAX_SAFE_INTEGER),
      windowMs: positiveInteger(raw.rateLimit.windowMs, "rateLimit.windowMs", Number.MAX_SAFE_INTEGER),
    },
  };
}

function normalizeFileInput(
  raw: ReserveCompanyFileInput,
): Required<Omit<ReserveCompanyFileInput, "knowledgeSourceId" | "supersedes">> & {
  knowledgeSourceId: string | null;
  supersedes: string | null;
} {
  if (raw === null || typeof raw !== "object") {
    throw new CompanyFileValidationError("Company file metadata is required");
  }
  const fileName = text(raw.fileName, "fileName", 255);
  if (FILE_SEPARATOR_OR_CONTROL.test(fileName)) {
    throw new CompanyFileValidationError("fileName cannot contain path separators or controls");
  }
  return {
    namespace: namespace(raw.namespace),
    knowledgeBaseId: text(raw.knowledgeBaseId, "knowledgeBaseId", 128),
    sourceId: text(raw.sourceId, "sourceId", 128),
    knowledgeSourceId: raw.knowledgeSourceId == null
      ? null
      : text(raw.knowledgeSourceId, "knowledgeSourceId", 128),
    uploadAttemptId: text(raw.uploadAttemptId, "uploadAttemptId", 128),
    attemptToken: text(raw.attemptToken, "attemptToken", 256),
    title: text(raw.title, "title", 255),
    description: optionalText(raw.description, "description", 2_000),
    purpose: text(raw.purpose, "purpose", 500),
    fileName,
    mediaType: text(raw.mediaType, "mediaType", 200),
    // Text validation remains 512 KiB at the parser boundary. File metadata
    // must also accommodate the separately supported PDF/DOCX 5 MiB lane.
    byteSize: positiveInteger(raw.byteSize, "byteSize", 5 * 1_024 * 1_024),
    contentSha256: digest(raw.contentSha256, "contentSha256"),
    createdBy: text(raw.createdBy, "createdBy", 512),
    uploadedBy: text(raw.uploadedBy, "uploadedBy", 512),
    supersedes: raw.supersedes == null ? null : text(raw.supersedes, "supersedes", 128),
  };
}

function normalizeOutcome(raw: FinalizeCompanyFileInput): {
  status: Exclude<CompanyFileStatus, "processing">;
  factCount: number;
  failureCode: string | null;
} {
  if (raw === null || typeof raw !== "object") {
    throw new CompanyFileValidationError("A terminal company file outcome is required");
  }
  if (!["ready", "needs_review", "failed"].includes(raw.status)) {
    throw new CompanyFileValidationError("Unsupported company file outcome");
  }
  const factCount = nonNegativeInteger(raw.factCount, "factCount");
  if (raw.status === "failed") {
    if (raw.failureCode === undefined || !FAILURE_CODE.test(raw.failureCode)) {
      throw new CompanyFileValidationError("Failed files require a bounded failureCode");
    }
    if (factCount !== 0) {
      throw new CompanyFileValidationError("Failed files cannot retain a fact count");
    }
    return { status: raw.status, factCount, failureCode: raw.failureCode };
  }
  if (raw.failureCode !== undefined) {
    throw new CompanyFileValidationError("Successful files cannot have a failureCode");
  }
  return { status: raw.status, factCount, failureCode: null };
}

async function selectFileForUpdate(db: Db, id: string): Promise<FileRow | undefined> {
  const result = await db.query(`${fileSelect()} WHERE f.id = $1 FOR UPDATE`, [id]);
  return result.rows[0] as FileRow | undefined;
}

async function accountFinalizedFile(
  db: Db,
  attempt: AttemptRow,
  result: "accepted" | "failed",
  failureCode?: string | null,
): Promise<void> {
  const accepted = Number(attempt.accepted_file_count) + (result === "accepted" ? 1 : 0);
  const failed = Number(attempt.failed_file_count) + (result === "failed" ? 1 : 0);
  const requested = Number(attempt.requested_file_count);
  const finished = accepted + failed === requested;
  const status: CompanyFileAttemptStatus = !finished
    ? "processing"
    : failed === 0
      ? "completed"
      : accepted === 0
        ? "failed"
        : "partially_failed";
  await db.query(
    `UPDATE company_file_upload_attempts
        SET accepted_file_count = $2, failed_file_count = $3, status = $4,
            failure_code = $5,
            completed_at = CASE WHEN $6::boolean THEN CURRENT_TIMESTAMP ELSE NULL END
      WHERE id = $1 AND status IN ('pending','processing')`,
    [
      attempt.id,
      accepted,
      failed,
      status,
      finished && failed > 0 ? (failureCode ?? "file_failed") : null,
      finished,
    ],
  );
}

async function refreshKnowledgeBaseStatus(db: Db, knowledgeBaseId: string): Promise<void> {
  await db.query(
    `UPDATE knowledge_bases
        SET status = CASE
          WHEN EXISTS (
            SELECT 1 FROM company_files f WHERE f.knowledge_base_id = $1
              AND f.lifecycle_state = 'active' AND f.t_valid_to IS NULL
              AND f.status = 'processing'
          ) THEN 'processing'
          WHEN EXISTS (
            SELECT 1 FROM company_files f WHERE f.knowledge_base_id = $1
              AND f.lifecycle_state = 'active' AND f.t_valid_to IS NULL
              AND f.status = 'needs_review'
          ) THEN 'needs_review'
          WHEN EXISTS (
            SELECT 1 FROM company_files f WHERE f.knowledge_base_id = $1
              AND f.lifecycle_state = 'active' AND f.t_valid_to IS NULL
              AND f.status = 'ready'
          ) THEN 'ready'
          WHEN EXISTS (
            SELECT 1 FROM company_files f WHERE f.knowledge_base_id = $1
              AND f.lifecycle_state = 'active' AND f.t_valid_to IS NULL
          ) THEN 'failed'
          ELSE 'empty'
        END,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND lifecycle_state <> 'archived'`,
    [knowledgeBaseId],
  );
}

function fileSelect(): string {
  return `SELECT f.*, kb.target_team_id
            FROM company_files f
            JOIN knowledge_bases kb ON kb.id = f.knowledge_base_id`;
}

function compensation(row: FileRow): CompanyFileCompensation {
  return {
    id: row.id,
    sourceId: row.source_id,
    namespace: row.namespace,
    documentKey: row.file_name,
    contentHash: row.content_sha256,
    attemptToken: row.attempt_token,
    byteSize: Number(row.byte_size),
  };
}

function attemptReservation(row: AttemptRow, replayed: boolean) {
  return { attempt: attemptSummary(row), attemptToken: row.attempt_token, replayed };
}

function assertMatchingAttempt(
  prior: AttemptRow,
  input: ReturnType<typeof normalizeAttemptInput>,
): void {
  if (
    prior.request_sha256 !== input.requestSha256 ||
    prior.knowledge_base_id !== input.knowledgeBaseId ||
    (prior.target_team_id ?? null) !== input.targetTeamId ||
    Number(prior.requested_file_count) !== input.requestedFileCount ||
    prior.created_by !== input.createdBy
  ) {
    throw new CompanyFileIdempotencyError(
      "company_file_idempotency_conflict",
      "Idempotency key was already used for a different upload request",
    );
  }
}

function attemptSummary(row: AttemptRow): CompanyFileUploadAttemptSummary {
  return {
    id: row.id,
    namespace: row.namespace,
    knowledgeBaseId: row.knowledge_base_id,
    targetTeamId: row.target_team_id ?? null,
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    status: row.status,
    requestedFileCount: Number(row.requested_file_count),
    acceptedFileCount: Number(row.accepted_file_count),
    failedFileCount: Number(row.failed_file_count),
    failureCode: row.failure_code,
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    completedAt: nullableIso(row.completed_at),
  };
}

function fileSummary(
  row: FileRow,
  targetTeamId: string | null = row.target_team_id ?? null,
): CompanyFileSummary {
  return {
    id: row.id,
    knowledgeBaseId: row.knowledge_base_id,
    sourceId: row.source_id,
    namespace: row.namespace,
    targetTeamId,
    title: row.title,
    description: row.description,
    purpose: row.purpose,
    fileName: row.file_name,
    mediaType: row.media_type,
    byteSize: Number(row.byte_size),
    contentSha256: row.content_sha256,
    status: row.status,
    lifecycleState: row.lifecycle_state,
    factCount: Number(row.fact_count),
    failureCode: row.failure_code,
    uploadedBy: row.uploaded_by,
    createdAt: toIso(row.created_at),
    loadedAt: nullableIso(row.loaded_at),
    archivedAt: nullableIso(row.archived_at),
  };
}

function namespaceAncestors(raw: string): string[] {
  const value = namespace(raw);
  const parts = value.split("/").filter(Boolean);
  return parts.map((_, index) => parts.slice(0, index + 1).join("/"));
}

function namespace(value: unknown): string {
  return text(value, "namespace", 512);
}

function digest(value: unknown, name: string): string {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw new CompanyFileValidationError(`${name} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function text(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new CompanyFileValidationError(`${name} is required`);
  }
  const normalized = value.trim();
  if (normalized.length > max || CONTROL.test(normalized)) {
    throw new CompanyFileValidationError(`${name} is invalid or exceeds ${max} characters`);
  }
  return normalized;
}

function optionalText(value: unknown, name: string, max: number): string {
  if (typeof value !== "string") {
    throw new CompanyFileValidationError(`${name} must be text`);
  }
  const normalized = value.trim();
  if (normalized.length > max || CONTROL.test(normalized)) {
    throw new CompanyFileValidationError(`${name} is invalid or exceeds ${max} characters`);
  }
  return normalized;
}

function positiveInteger(value: unknown, name: string, max: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > max) {
    throw new CompanyFileValidationError(`${name} must be an integer between 1 and ${max}`);
  }
  return Number(value);
}

function nonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new CompanyFileValidationError(`${name} must be a non-negative integer`);
  }
  return Number(value);
}

function toIso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function nullableIso(value: string | Date | null): string | null {
  return value === null ? null : toIso(value);
}

function emptyList(page: number, pageSize: number): CompanyFileListResult {
  return {
    data: [],
    pagination: { page, pageSize, total: 0, totalPages: 0 },
    summary: { total: 0, ready: 0, processing: 0, needsReview: 0, failed: 0 },
  };
}
