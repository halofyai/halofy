/**
 * Module E (M1) — async write queue.
 *
 * WriteQueue serializes writes through a single sequential worker. enqueue()
 * returns a ticket (ulid) immediately; status(ticket) reports
 * queued|running|done|failed. Terminal results are retained for the last 500
 * tickets (LRU: a status() read refreshes recency). A failed job never kills
 * the worker — the next job still runs.
 */

import { ulid } from "ulid";
import type { Identity, WriteRequest, WriteResult } from "../types.js";

export type WriteQueueState = "queued" | "running" | "done" | "failed";

export interface WriteQueueStatus<Res = WriteResult> {
  state: WriteQueueState;
  result?: Res;
  error?: string;
}

interface Job<Req> {
  ticket: string;
  req: Req;
  identity: Identity;
}

const DEFAULT_MAX_RESULTS = 500;

export class WriteQueue<Req = WriteRequest, Res = WriteResult> {
  private readonly queue: Job<Req>[] = [];
  /** queued/running entries, keyed by ticket. */
  private readonly active = new Map<string, WriteQueueStatus<Res>>();
  /** terminal entries (done/failed), insertion order = LRU order. */
  private readonly results = new Map<string, WriteQueueStatus<Res>>();
  /**
   * Enqueuing Identity per ticket (evicted together with the result) — lets
   * transports scope status lookups to the ticket owner's namespace instead
   * of leaking WriteResults (stored memory objects) across tenants.
   */
  private readonly owners = new Map<string, Identity>();
  private running = false;

  constructor(
    private readonly writeFn: (req: Req, identity: Identity) => Promise<Res>,
    private readonly maxResults: number = DEFAULT_MAX_RESULTS,
  ) {}

  /** Accept a write immediately; the sequential worker processes it later. */
  enqueue(req: Req, identity: Identity): { ticket: string } {
    const ticket = ulid();
    this.active.set(ticket, { state: "queued" });
    this.owners.set(ticket, identity);
    this.queue.push({ ticket, req, identity });
    void this.run();
    return { ticket };
  }

  /** Identity that enqueued a ticket; undefined once the ticket is evicted. */
  owner(ticket: string): Identity | undefined {
    return this.owners.get(ticket);
  }

  /** Current status; undefined for unknown or evicted tickets. */
  status(ticket: string): WriteQueueStatus<Res> | undefined {
    const live = this.active.get(ticket);
    if (live) return live;
    const done = this.results.get(ticket);
    if (done) {
      // LRU touch: refresh recency on read.
      this.results.delete(ticket);
      this.results.set(ticket, done);
    }
    return done;
  }

  /** Resolve once every enqueued job has reached a terminal state (tests). */
  async drain(): Promise<void> {
    while (this.running || this.queue.length > 0) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }

  private async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      let job: Job<Req> | undefined;
      while ((job = this.queue.shift()) !== undefined) {
        this.active.set(job.ticket, { state: "running" });
        try {
          const result = await this.writeFn(job.req, job.identity);
          this.finish(job.ticket, { state: "done", result });
        } catch (err) {
          this.finish(job.ticket, {
            state: "failed",
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    } finally {
      this.running = false;
    }
  }

  private finish(ticket: string, status: WriteQueueStatus<Res>): void {
    this.active.delete(ticket);
    this.results.set(ticket, status);
    while (this.results.size > this.maxResults) {
      const oldest = this.results.keys().next().value;
      if (oldest === undefined) break;
      this.results.delete(oldest);
      this.owners.delete(oldest);
    }
  }
}
