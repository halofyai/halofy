import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import { DurableJobStore } from "../durable/jobs.js";
import { DurableRateLimitStore } from "../durable/rate-limit.js";
import { SourceConfigCipher } from "../ingest/source-config.js";
import type {
  CompanyFileUploadAccepted,
  CompanyFileUploadInput,
  CompanyFileUploadJobStatus,
  CompanyFileUploadListItem,
  CompanyFileUploadStage,
  Namespace,
} from "../types.js";
import {
  CompanyFileConcurrencyError,
  CompanyFileIdempotencyError,
  CompanyFileRateLimitError,
  MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS,
} from "./company-files.js";

interface IngestJobRow {
  id: string;
  namespace: Namespace;
  knowledge_base_id: string;
  idempotency_key: string;
  request_sha256: string;
  status: CompanyFileUploadJobStatus;
  stage: CompanyFileUploadStage;
  payload_ciphertext: string | null;
  payload_iv: string | null;
  payload_tag: string | null;
  payload_kek_id: string | null;
  file_id: string | null;
  failure_code: string | null;
  created_by: string;
  created_at: string | Date;
  completed_at: string | Date | null;
}

export interface CompanyFileIngestJobSummary {
  id: string;
  namespace: Namespace;
  knowledgeBaseId: string;
  status: CompanyFileUploadJobStatus;
  stage: CompanyFileUploadStage;
  fileId: string | null;
  failureCode: string | null;
  createdBy: string;
  createdAt: string;
  completedAt: string | null;
}

export interface CompanyFileChunkCheckpoint {
  chunkIndex: number;
  chunkCount: number;
  status: "pending" | "processing" | "complete" | "failed";
  attempts: number;
  factCount: number;
  failureCode: string | null;
}

export interface EnqueueCompanyFileJobInput {
  namespace: Namespace;
  knowledgeBaseId: string;
  idempotencyKey: string;
  requestSha256: string;
  payload: CompanyFileUploadInput;
  createdBy: string;
  rateLimit: { bucketKey: string; limit: number; windowMs: number };
}

function iso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function summary(row: IngestJobRow): CompanyFileIngestJobSummary {
  return {
    id: row.id,
    namespace: row.namespace,
    knowledgeBaseId: row.knowledge_base_id,
    status: row.status,
    stage: row.stage,
    fileId: row.file_id,
    failureCode: row.failure_code,
    createdBy: row.created_by,
    createdAt: iso(row.created_at),
    completedAt: row.completed_at === null ? null : iso(row.completed_at),
  };
}

/** Encrypted staging + durable queue boundary for asynchronous company files. */
export class CompanyFileIngestJobStore {
  constructor(
    private readonly db: Db,
    private readonly cipher: SourceConfigCipher,
  ) {}

  async enqueue(input: EnqueueCompanyFileJobInput): Promise<CompanyFileUploadAccepted> {
    const id = `company_upload_${ulid()}`;
    const now = new Date().toISOString();
    const sealed = this.cipher.seal(id, input.namespace, "file-upload", {
      input: input.payload,
    });
    return this.db.transaction(async (tx) => {
      const existing = await tx.query(
        `SELECT * FROM company_file_ingest_jobs
          WHERE namespace = $1 AND idempotency_key = $2
          FOR UPDATE`,
        [input.namespace, input.idempotencyKey],
      );
      const prior = existing.rows[0] as IngestJobRow | undefined;
      if (prior) {
        if (
          prior.request_sha256 !== input.requestSha256 ||
          prior.knowledge_base_id !== input.knowledgeBaseId
        ) {
          throw new CompanyFileIdempotencyError(
            "company_file_idempotency_conflict",
            "Idempotency key was already used for a different upload request",
          );
        }
        return {
          uploadId: prior.id,
          status: prior.status === "queued" ? "queued" : "processing",
          stage: prior.stage,
          submittedAt: iso(prior.created_at),
        };
      }

      const active = await tx.query(
        `SELECT count(*) AS count FROM company_file_ingest_jobs
          WHERE namespace = $1 AND status IN ('queued','processing')`,
        [input.namespace],
      );
      if (Number(active.rows[0]?.count ?? 0) >= MAX_CONCURRENT_COMPANY_FILE_ATTEMPTS) {
        throw new CompanyFileConcurrencyError();
      }
      const rate = await new DurableRateLimitStore(tx).consume(
        input.rateLimit.bucketKey,
        input.rateLimit.limit,
        input.rateLimit.windowMs,
      );
      if (!rate.allowed) throw new CompanyFileRateLimitError(rate.retryAfterSec);

      await tx.query(
        `INSERT INTO company_file_ingest_jobs
          (id, namespace, knowledge_base_id, idempotency_key, request_sha256,
           status, payload_ciphertext, payload_iv, payload_tag, payload_kek_id,
           file_id, failure_code, created_by, created_at, completed_at)
         VALUES ($1,$2,$3,$4,$5,'queued',$6,$7,$8,$9,NULL,NULL,$10,$11,NULL)`,
        [
          id, input.namespace, input.knowledgeBaseId, input.idempotencyKey,
          input.requestSha256, sealed.ciphertext, sealed.iv, sealed.tag,
          sealed.kekId, input.createdBy, now,
        ],
      );
      await new DurableJobStore(tx).enqueue({
        id: `company-file-upload:${id}`,
        kind: "company-file-upload",
        namespace: input.namespace,
        payload: { uploadId: id },
        availableAt: now,
      });
      return { uploadId: id, status: "queued", stage: "queued", submittedAt: now };
    });
  }

  async get(id: string): Promise<CompanyFileIngestJobSummary | null> {
    const result = await this.db.query(
      `SELECT * FROM company_file_ingest_jobs WHERE id = $1`,
      [id],
    );
    const row = result.rows[0] as IngestJobRow | undefined;
    return row ? summary(row) : null;
  }

  /**
   * Reload-safe progress for one ACL-resolved knowledge base. The encrypted
   * staging envelope is opened only to recover display metadata; content is
   * never returned from this boundary.
   */
  async listActive(
    knowledgeBaseId: string,
    namespace: Namespace,
  ): Promise<CompanyFileUploadListItem[]> {
    const result = await this.db.query(
      `SELECT * FROM company_file_ingest_jobs
        WHERE knowledge_base_id = $1 AND namespace = $2
          AND status IN ('queued','processing')
        ORDER BY created_at ASC, id ASC`,
      [knowledgeBaseId, namespace],
    );
    return result.rows.map((value) => {
      const row = value as IngestJobRow;
      let fileName = "File name unavailable";
      let title = "File upload";
      try {
        const payload = this.cipher.open({
          id: row.id,
          namespace: row.namespace,
          kind: "file-upload",
          config_ciphertext: row.payload_ciphertext,
          config_iv: row.payload_iv,
          config_tag: row.payload_tag,
          config_kek_id: row.payload_kek_id,
          config_sha256: "gcm-v1",
        });
        const input = payload.input;
        if (input && typeof input === "object" && !Array.isArray(input)) {
          const staged = input as Partial<CompanyFileUploadInput>;
          if (typeof staged.fileName === "string" && staged.fileName !== "") {
            fileName = staged.fileName;
          }
          if (typeof staged.title === "string" && staged.title !== "") {
            title = staged.title;
          } else if (fileName !== "File name unavailable") {
            title = fileName.replace(/\.[^.]+$/, "") || fileName;
          }
        }
      } catch {
        // The job remains visible even during a key/envelope brownout. Its
        // status is authoritative; only its presentation metadata is unknown.
      }
      return {
        uploadId: row.id,
        knowledgeBaseId: row.knowledge_base_id,
        fileName,
        title,
        status: row.status as "queued" | "processing",
        stage: row.stage,
        submittedAt: iso(row.created_at),
      };
    });
  }

  async open(id: string, namespace: Namespace): Promise<{
    job: CompanyFileIngestJobSummary;
    input: CompanyFileUploadInput;
  }> {
    const result = await this.db.query(
      `UPDATE company_file_ingest_jobs SET status = 'processing'
        WHERE id = $1 AND namespace = $2 AND status IN ('queued','processing')
        RETURNING *`,
      [id, namespace],
    );
    const row = result.rows[0] as IngestJobRow | undefined;
    if (!row) throw new Error("company file upload staging is unavailable");
    const payload = this.cipher.open({
      id: row.id,
      namespace: row.namespace,
      kind: "file-upload",
      config_ciphertext: row.payload_ciphertext,
      config_iv: row.payload_iv,
      config_tag: row.payload_tag,
      config_kek_id: row.payload_kek_id,
      config_sha256: "gcm-v1",
    });
    const input = payload.input;
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new Error("company file upload staging is unavailable");
    }
    return { job: summary(row), input: input as CompanyFileUploadInput };
  }

  /** Create deterministic, content-free chunk checkpoints exactly once. */
  async ensureChunks(id: string, chunkCount: number): Promise<CompanyFileChunkCheckpoint[]> {
    if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > 10_000) {
      throw new Error("company file chunk count is invalid");
    }
    const now = new Date().toISOString();
    return this.db.transaction(async (tx) => {
      const job = await tx.query(
        `SELECT id FROM company_file_ingest_jobs
          WHERE id = $1 AND status IN ('queued','processing') FOR UPDATE`,
        [id],
      );
      if (job.rows.length !== 1) throw new Error("company file upload staging is unavailable");
      const existing = await tx.query(
        `SELECT chunk_index, chunk_count, status, attempts, fact_count, failure_code
           FROM company_file_ingest_chunks WHERE upload_id = $1 ORDER BY chunk_index`,
        [id],
      );
      if (existing.rows.length === 0) {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
          await tx.query(
            `INSERT INTO company_file_ingest_chunks
              (upload_id, chunk_index, chunk_count, status, attempts,
               fact_count, failure_code, updated_at, completed_at)
             VALUES ($1,$2,$3,'pending',0,0,NULL,$4,NULL)`,
            [id, chunkIndex, chunkCount, now],
          );
        }
      } else if (
        existing.rows.length !== chunkCount ||
        existing.rows.some((row) => Number(row.chunk_count) !== chunkCount)
      ) {
        throw new Error("company file chunk plan changed during retry");
      }
      const rows = existing.rows.length === 0
        ? await tx.query(
            `SELECT chunk_index, chunk_count, status, attempts, fact_count, failure_code
               FROM company_file_ingest_chunks WHERE upload_id = $1 ORDER BY chunk_index`,
            [id],
          )
        : existing;
      return rows.rows.map(chunkCheckpoint);
    });
  }

  async startChunk(id: string, chunkIndex: number): Promise<void> {
    const result = await this.db.query(
      `UPDATE company_file_ingest_chunks
          SET status = 'processing', attempts = attempts + 1,
              failure_code = NULL, updated_at = CURRENT_TIMESTAMP,
              completed_at = NULL
        WHERE upload_id = $1 AND chunk_index = $2 AND status <> 'complete'
        RETURNING upload_id`,
      [id, chunkIndex],
    );
    if (result.rows.length !== 1) {
      throw new Error("company file chunk checkpoint is unavailable");
    }
  }

  async completeChunk(id: string, chunkIndex: number, factCount: number): Promise<void> {
    const result = await this.db.query(
      `UPDATE company_file_ingest_chunks
          SET status = 'complete', fact_count = $3, failure_code = NULL,
              updated_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP
        WHERE upload_id = $1 AND chunk_index = $2 AND status = 'processing'
        RETURNING upload_id`,
      [id, chunkIndex, Math.max(0, Math.floor(factCount))],
    );
    if (result.rows.length !== 1) {
      throw new Error("company file chunk checkpoint is unavailable");
    }
  }

  async failChunk(id: string, chunkIndex: number, failureCode: string): Promise<void> {
    const result = await this.db.query(
      `UPDATE company_file_ingest_chunks
          SET status = 'failed', fact_count = 0, failure_code = $3,
              updated_at = CURRENT_TIMESTAMP, completed_at = NULL
        WHERE upload_id = $1 AND chunk_index = $2 AND status = 'processing'
        RETURNING upload_id`,
      [id, chunkIndex, failureCode],
    );
    if (result.rows.length !== 1) {
      throw new Error("company file chunk checkpoint is unavailable");
    }
  }

  /** Advance progress monotonically so retries can never move the UI backward. */
  async advanceStage(id: string, stage: Exclude<CompanyFileUploadStage, "queued" | "complete">): Promise<void> {
    await this.db.query(
      `UPDATE company_file_ingest_jobs SET stage = $2
        WHERE id = $1 AND status IN ('queued','processing')
          AND CASE stage
            WHEN 'queued' THEN 0 WHEN 'parsing' THEN 1 WHEN 'extracting' THEN 2
            WHEN 'embedding' THEN 3 WHEN 'finalizing' THEN 4 WHEN 'complete' THEN 5
          END < CASE $2
            WHEN 'queued' THEN 0 WHEN 'parsing' THEN 1 WHEN 'extracting' THEN 2
            WHEN 'embedding' THEN 3 WHEN 'finalizing' THEN 4 WHEN 'complete' THEN 5
          END`,
      [id, stage],
    );
  }

  async complete(id: string, fileId: string, status: "ready" | "needs_review" | "failed", failureCode: string | null): Promise<void> {
    await this.db.query(
      `UPDATE company_file_ingest_jobs
          SET status = $2, stage = CASE WHEN $2 = 'failed' THEN stage ELSE 'complete' END,
              file_id = $3, failure_code = $4,
              payload_ciphertext = NULL, payload_iv = NULL,
              payload_tag = NULL, payload_kek_id = NULL,
              completed_at = CURRENT_TIMESTAMP
        WHERE id = $1`,
      [id, status, fileId, failureCode],
    );
  }

  async fail(id: string, failureCode: string, terminal: boolean): Promise<void> {
    await this.db.query(
      terminal
        ? `UPDATE company_file_ingest_jobs
              SET status = 'failed', failure_code = $2,
                  payload_ciphertext = NULL, payload_iv = NULL,
                  payload_tag = NULL, payload_kek_id = NULL,
                  completed_at = CURRENT_TIMESTAMP
            WHERE id = $1`
        : `UPDATE company_file_ingest_jobs
              SET status = 'queued', failure_code = $2
            WHERE id = $1`,
      [id, failureCode],
    );
  }
}

function chunkCheckpoint(row: Record<string, unknown>): CompanyFileChunkCheckpoint {
  return {
    chunkIndex: Number(row.chunk_index),
    chunkCount: Number(row.chunk_count),
    status: String(row.status) as CompanyFileChunkCheckpoint["status"],
    attempts: Number(row.attempts),
    factCount: Number(row.fact_count),
    failureCode: row.failure_code === null ? null : String(row.failure_code),
  };
}
