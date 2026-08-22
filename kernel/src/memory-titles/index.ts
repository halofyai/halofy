import { ulid } from "ulid";

import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";

export interface MemoryTitleInput {
  memoryId: string;
  namespace: string;
  content: string;
}

export interface MemoryTitleCompletion {
  title: string;
  profileId: string;
  providerId: string | null;
  model: string;
  inputTokens?: number;
  outputTokens?: number;
}

export type MemoryTitleExecutor = (
  input: MemoryTitleInput,
) => Promise<MemoryTitleCompletion>;

export interface MemoryTitleRunResult {
  claimed: number;
  completed: number;
  failed: number;
}

interface ClaimedMemory extends Record<string, unknown> {
  id: string;
  namespace: string;
  content: string;
  title_attempts: number;
}

const LEASE_MS = 5 * 60_000;
const MAX_ATTEMPTS = 5;

function normalizedTitle(value: string): string | null {
  const title = value
    .trim()
    .replace(/^(["'`])(.+)\1$/u, "$2")
    .replace(/\s+/gu, " ")
    .trim();
  if (title.length < 3 || title.length > 80) return null;
  if (/[<>\u0000-\u001f\u007f]/u.test(title)) return null;
  return title;
}

function tokenCount(value: number | undefined): number | null {
  return Number.isInteger(value) && Number(value) >= 0 ? Number(value) : null;
}

function failureCode(error: unknown): string {
  if (error instanceof Error && error.message === "invalid_model_output") {
    return "invalid_model_output";
  }
  return "provider_error";
}

/** Durable, lease-fenced title derivation over immutable memory content. */
export class MemoryTitleJobs {
  private executor: MemoryTitleExecutor | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    private readonly workerId: string,
  ) {}

  attach(executor: MemoryTitleExecutor): void {
    this.executor = executor;
  }

  async runOnce(options: { limit?: number } = {}): Promise<MemoryTitleRunResult> {
    if (!this.executor) return { claimed: 0, completed: 0, failed: 0 };
    const limit = Math.max(1, Math.min(25, Math.floor(options.limit ?? 10)));
    const claimed = await this.claim(limit);
    const outcomes = await Promise.all(claimed.map((memory) => this.process(memory)));
    return {
      claimed: claimed.length,
      completed: outcomes.filter(Boolean).length,
      failed: outcomes.filter((value) => !value).length,
    };
  }

  private async claim(limit: number): Promise<ClaimedMemory[]> {
    const now = new Date();
    const leaseUntil = new Date(now.getTime() + LEASE_MS).toISOString();
    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `WITH candidates AS (
           SELECT id
             FROM memory_objects
            WHERE display_title IS NULL
              AND (
                (title_status = 'pending' AND (title_retry_at IS NULL OR title_retry_at <= $1))
                OR (title_status = 'running' AND title_lease_until < $1)
              )
            ORDER BY assertion_time, id
            LIMIT $2
            FOR UPDATE SKIP LOCKED
         )
         UPDATE memory_objects AS memory
            SET title_status = 'running',
                title_attempts = title_attempts + 1,
                title_lease_owner = $3,
                title_lease_until = $4,
                title_last_error = NULL
           FROM candidates
          WHERE memory.id = candidates.id
         RETURNING memory.id, memory.namespace, memory.content, memory.title_attempts`,
        [now.toISOString(), limit, this.workerId, leaseUntil],
      );
      return result.rows as ClaimedMemory[];
    });
  }

  private async process(memory: ClaimedMemory): Promise<boolean> {
    let completion: MemoryTitleCompletion | null = null;
    const startedAt = new Date();
    try {
      completion = await this.executor!({
        memoryId: String(memory.id),
        namespace: String(memory.namespace),
        content: String(memory.content),
      });
      const title = normalizedTitle(completion.title);
      if (!title) throw new Error("invalid_model_output");
      const completedAt = new Date();
      await this.db.transaction(async (tx) => {
        const updated = await tx.query(
          `UPDATE memory_objects
              SET display_title = $1, display_title_model = $2,
                  display_title_generated_at = $3, title_status = 'complete',
                  title_lease_owner = NULL, title_lease_until = NULL,
                  title_retry_at = NULL, title_last_error = NULL
            WHERE id = $4 AND title_status = 'running' AND title_lease_owner = $5
            RETURNING id`,
          [title, completion!.model, completedAt.toISOString(), memory.id, this.workerId],
        );
        if (updated.rows.length !== 1) throw new Error("memory_title_lease_lost");
        await tx.query(
          `INSERT INTO memory_title_invocations
             (id, memory_id, namespace, profile_id, provider_id, model, status,
              input_tokens, output_tokens, started_at, completed_at, latency_ms)
           VALUES ($1,$2,$3,$4,$5,$6,'completed',$7,$8,$9,$10,$11)`,
          [ulid(), memory.id, memory.namespace, completion!.profileId,
            completion!.providerId, completion!.model,
            tokenCount(completion!.inputTokens), tokenCount(completion!.outputTokens),
            startedAt.toISOString(), completedAt.toISOString(),
            Math.max(0, completedAt.getTime() - startedAt.getTime())],
        );
        await this.audit.appendTo(tx, {
          ts: completedAt.toISOString(), actor: "memory-title-worker",
          agentId: this.workerId, op: "write", memoryId: String(memory.id),
          namespace: String(memory.namespace), purpose: "memory-display-title",
          result: "ok", detail: `model=${completion!.model}; profile=${completion!.profileId}`,
        });
      });
      return true;
    } catch (error) {
      const failedAt = new Date();
      const code = failureCode(error);
      const attempts = Number(memory.title_attempts);
      const terminal = attempts >= MAX_ATTEMPTS;
      const retryAt = new Date(failedAt.getTime() + Math.min(attempts, 5) * 60_000).toISOString();
      await this.db.transaction(async (tx) => {
        const updated = await tx.query(
          `UPDATE memory_objects
              SET title_status = $1, title_lease_owner = NULL,
                  title_lease_until = NULL, title_retry_at = $2,
                  title_last_error = $3
            WHERE id = $4 AND title_status = 'running' AND title_lease_owner = $5
            RETURNING id`,
          [terminal ? "failed" : "pending", terminal ? null : retryAt,
            code, memory.id, this.workerId],
        );
        if (updated.rows.length === 1 && completion) {
          await tx.query(
            `INSERT INTO memory_title_invocations
               (id, memory_id, namespace, profile_id, provider_id, model, status,
                failure_class, input_tokens, output_tokens, started_at, completed_at, latency_ms)
             VALUES ($1,$2,$3,$4,$5,$6,'failed',$7,$8,$9,$10,$11,$12)`,
            [ulid(), memory.id, memory.namespace, completion.profileId,
              completion.providerId, completion.model, code,
              tokenCount(completion.inputTokens), tokenCount(completion.outputTokens),
              startedAt.toISOString(), failedAt.toISOString(),
              Math.max(0, failedAt.getTime() - startedAt.getTime())],
          );
        }
        await this.audit.appendTo(tx, {
          ts: failedAt.toISOString(), actor: "memory-title-worker",
          agentId: this.workerId, op: "write", memoryId: String(memory.id),
          namespace: String(memory.namespace), purpose: "memory-display-title",
          result: "error", detail: `reason=${code}; attempt=${attempts}`,
        });
      });
      return false;
    }
  }
}
