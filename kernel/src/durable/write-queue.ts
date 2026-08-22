import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import type { Identity, WriteResult } from "../types.js";
import type { WriteQueueStatus } from "../resilience/index.js";
import { DurableJobStore } from "./jobs.js";
import { DurableTicketStore } from "./tickets.js";

interface DurableWritePayload<Req> {
  req: Req;
  identity: Identity;
}

/**
 * Postgres-backed async-write worker. Claims use SKIP LOCKED leases, so every
 * kernel replica can run this worker and an abandoned job is reclaimed after
 * its lease expires. Ticket state is durable and namespace-fenced.
 */
export class DurableWriteQueue<Req, Res = WriteResult> {
  private readonly workerId = `write-worker:${process.pid}:${ulid()}`;
  private readonly jobs: DurableJobStore;
  private readonly tickets: DurableTicketStore;
  private running: Promise<void> | null = null;
  private stopped = false;
  private readonly poller: NodeJS.Timeout;

  constructor(
    private readonly db: Db,
    private readonly writeFn: (req: Req, identity: Identity) => Promise<Res>,
    private readonly options: { leaseMs?: number; pollMs?: number; ticketTtlMs?: number } = {},
  ) {
    this.jobs = new DurableJobStore(db);
    this.tickets = new DurableTicketStore(db);
    const pollMs = options.pollMs ?? 1_000;
    this.poller = setInterval(() => void this.kick(), pollMs);
    this.poller.unref?.();
    void this.kick();
  }

  async enqueue(req: Req, identity: Identity): Promise<{ ticket: string }> {
    if (this.stopped) throw new Error("durable write queue is stopped");
    const ticket = ulid();
    const expiresAt = new Date(
      Date.now() + (this.options.ticketTtlMs ?? 24 * 60 * 60 * 1000),
    ).toISOString();
    await this.db.transaction(async (tx) => {
      await new DurableTicketStore(tx).issue({
        id: ticket,
        kind: "write",
        namespace: identity.namespace,
        subjectKey: identity.keyId,
        expiresAt,
      });
      await new DurableJobStore(tx).enqueue<DurableWritePayload<Req>>({
        id: ticket,
        kind: "write",
        namespace: identity.namespace,
        payload: { req, identity },
      });
    });
    void this.kick();
    return { ticket };
  }

  async status(ticket: string, identity?: Identity): Promise<WriteQueueStatus<Res> | undefined> {
    if (!identity) {
      const job = await this.jobs.get<DurableWritePayload<Req>>(ticket);
      if (!job) return undefined;
      const row = await this.db.query(
        `SELECT state, result, error FROM durable_tickets WHERE id = $1`,
        [ticket],
      );
      return this.mapTicket(row.rows[0] as Record<string, unknown> | undefined, job.state);
    }
    const ticketRow = await this.tickets.resolve<Res>(ticket, identity);
    if (!ticketRow) return undefined;
    if (ticketRow.state === "running") {
      const job = await this.jobs.get(ticket);
      return { state: job?.state === "running" ? "running" : "queued" };
    }
    if (ticketRow.state === "done") return { state: "done", result: ticketRow.result as Res };
    return { state: "failed", error: ticketRow.error ?? "durable write failed" };
  }

  async drain(): Promise<void> {
    for (;;) {
      await this.kick();
      if (this.running) await this.running;
      const pending = await this.db.query(
        `SELECT 1 FROM durable_jobs
         WHERE kind = 'write' AND state IN ('queued', 'running')
         LIMIT 1`,
      );
      if (pending.rows.length === 0) return;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }

  stop(): void {
    this.stopped = true;
    clearInterval(this.poller);
  }

  private kick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (!this.running) {
      this.running = this.run().finally(() => {
        this.running = null;
      });
    }
    return this.running;
  }

  private async run(): Promise<void> {
    for (;;) {
      const job = await this.jobs.claim<DurableWritePayload<Req>>(this.workerId, {
        kinds: ["write"],
        leaseMs: this.options.leaseMs ?? 30_000,
      });
      if (!job) return;
      const leaseMs = this.options.leaseMs ?? 30_000;
      const heartbeat = setInterval(() => {
        void this.jobs.renew(job.id, this.workerId, leaseMs).catch(() => undefined);
      }, Math.max(1_000, Math.floor(leaseMs / 3)));
      heartbeat.unref?.();
      try {
        const result = await this.writeFn(job.payload.req, job.payload.identity);
        await this.db.transaction(async (tx) => {
          const completed = await new DurableJobStore(tx).complete(job.id, this.workerId);
          if (!completed) throw new Error("durable write lease was lost before completion");
          await new DurableTicketStore(tx).complete(job.id, result);
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await this.db.transaction(async (tx) => {
          const failed = await new DurableJobStore(tx).fail(job.id, this.workerId, message);
          if (failed) await new DurableTicketStore(tx).fail(job.id, message);
        });
      } finally {
        clearInterval(heartbeat);
      }
    }
  }

  private mapTicket(
    row: Record<string, unknown> | undefined,
    jobState: "queued" | "running" | "done" | "failed",
  ): WriteQueueStatus<Res> | undefined {
    if (!row) return undefined;
    if (row.state === "done") return { state: "done", result: row.result as Res };
    if (row.state === "failed") return { state: "failed", error: String(row.error ?? "durable write failed") };
    return { state: jobState === "running" ? "running" : "queued" };
  }
}
