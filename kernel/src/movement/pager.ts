/** M7/D18+D20: automatic tier movement over a replica-safe durable lease port. */
import type { DurableJob, Namespace } from "../types.js";

export type PagerMovementAction =
  | "promote_pin"
  | "propose_cold"
  | "materialize_warm"
  | "archive_warm";

export interface PagerMovement {
  action: PagerMovementAction;
  targetRef: string;
  evidenceIds?: string[];
  /** Always overwritten with `pager:<durable job id>` before execution. */
  idempotencyKey?: string;
}

export interface PagerPolicy {
  evaluate(job: DurableJob): Promise<PagerMovement | null> | PagerMovement | null;
}

export interface PagerAuditEvent {
  jobId: string;
  namespace: Namespace;
  workerId: string;
  action: PagerMovementAction | "none";
  result: "ok" | "miss" | "error";
  /** Bounded operational category; never provider errors or memory content. */
  reason: "moved" | "policy_noop" | "policy_failed" | "execution_failed" | "audit_failed";
  ts: string;
}

export interface DurablePagerQueue {
  claim(input: {
    kind: "movement";
    workerId: string;
    leaseMs: number;
    limit: number;
  }): Promise<DurableJob[]>;
  complete(jobId: string, workerId: string, result: unknown): Promise<void>;
  retry(jobId: string, workerId: string, reason: string, availableAt: string): Promise<void>;
}

export interface PagerPorts {
  queue: DurablePagerQueue;
  /** Must be idempotent by movement.idempotencyKey across lease recovery. */
  execute(job: DurableJob, movement: PagerMovement & { idempotencyKey: string }): Promise<unknown>;
  audit(event: PagerAuditEvent): Promise<void>;
}

export interface PolicyPagerOptions {
  workerId: string;
  policy: PagerPolicy;
  ports: PagerPorts;
  leaseMs?: number;
  batchSize?: number;
  retryDelayMs?: number;
  now?: () => Date;
}

export interface PagerRunResult { claimed: number; completed: number; retried: number }

export class PolicyPager {
  private readonly workerId: string;
  private readonly policy: PagerPolicy;
  private readonly ports: PagerPorts;
  private readonly leaseMs: number;
  private readonly batchSize: number;
  private readonly retryDelayMs: number;
  private readonly now: () => Date;

  constructor(options: PolicyPagerOptions) {
    if (!options.workerId.trim()) throw new Error("pager workerId is required");
    this.workerId = options.workerId;
    this.policy = options.policy;
    this.ports = options.ports;
    this.leaseMs = Math.max(1_000, options.leaseMs ?? 30_000);
    this.batchSize = Math.max(1, Math.min(100, options.batchSize ?? 10));
    this.retryDelayMs = Math.max(1_000, options.retryDelayMs ?? 30_000);
    this.now = options.now ?? (() => new Date());
  }

  /** Claims one bounded batch. Scheduling/cadence belongs to the host, never an instance-local timer. */
  async runOnce(): Promise<PagerRunResult> {
    const jobs = await this.ports.queue.claim({
      kind: "movement", workerId: this.workerId, leaseMs: this.leaseMs, limit: this.batchSize,
    });
    let completed = 0;
    let retried = 0;
    for (const job of jobs) {
      const outcome = await this.process(job);
      if (outcome === "completed") completed++;
      else retried++;
    }
    return { claimed: jobs.length, completed, retried };
  }

  private async process(job: DurableJob): Promise<"completed" | "retried"> {
    let movement: PagerMovement | null;
    try {
      movement = await this.policy.evaluate(job);
    } catch {
      await this.auditAndRetry(job, "none", "policy_failed");
      return "retried";
    }

    if (!movement) {
      const event = this.event(job, "none", "miss", "policy_noop");
      try {
        await this.ports.audit(event);
        await this.ports.queue.complete(job.id, this.workerId, { skipped: true, reason: "policy_noop" });
        return "completed";
      } catch {
        await this.retry(job, "audit_failed");
        return "retried";
      }
    }

    const idempotentMovement = { ...movement, idempotencyKey: `pager:${job.id}` };
    let result: unknown;
    try {
      result = await this.ports.execute(job, idempotentMovement);
    } catch {
      await this.auditAndRetry(job, movement.action, "execution_failed");
      return "retried";
    }

    try {
      await this.ports.audit(this.event(job, movement.action, "ok", "moved"));
      await this.ports.queue.complete(job.id, this.workerId, result);
      return "completed";
    } catch {
      // Execution is replay-safe because its idempotency key is derived from the durable job id.
      await this.retry(job, "audit_failed");
      return "retried";
    }
  }

  private async auditAndRetry(
    job: DurableJob,
    action: PagerMovementAction | "none",
    reason: "policy_failed" | "execution_failed",
  ): Promise<void> {
    try {
      await this.ports.audit(this.event(job, action, "error", reason));
    } catch {
      await this.retry(job, "audit_failed");
      return;
    }
    await this.retry(job, reason);
  }

  private retry(job: DurableJob, reason: string): Promise<void> {
    const availableAt = new Date(this.now().getTime() + this.retryDelayMs).toISOString();
    return this.ports.queue.retry(job.id, this.workerId, reason, availableAt);
  }

  private event(
    job: DurableJob,
    action: PagerMovementAction | "none",
    result: PagerAuditEvent["result"],
    reason: PagerAuditEvent["reason"],
  ): PagerAuditEvent {
    return {
      jobId: job.id, namespace: job.namespace, workerId: this.workerId,
      action, result, reason, ts: this.now().toISOString(),
    };
  }
}
