import { describe, expect, it } from "vitest";
import type { DurableJob } from "../src/types.js";
import { PolicyPager, type PagerPorts } from "../src/movement/pager.js";

const job: DurableJob<{ targetRef: string; accessCount: number }> = {
  id: "job-1", kind: "movement", namespace: "acme/ops", state: "running",
  payload: { targetRef: "01ARZ3NDEKTSV4RRFFQ69G5FAV", accessCount: 9 }, attempts: 1,
  availableAt: "2026-01-01T00:00:00.000Z", leaseOwner: "replica-a",
  leaseExpiresAt: "2026-01-01T00:01:00.000Z", createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};

describe("M7 automatic policy pager", () => {
  it("claims durable leases, executes policy movement, audits, then completes", async () => {
    const events: string[] = [];
    const ports: PagerPorts = {
      queue: {
        claim: async () => [job],
        complete: async (_id, _owner, result) => { events.push(`complete:${String(result)}`); },
        retry: async () => { throw new Error("unexpected retry"); },
      },
      execute: async (_job, movement) => { events.push(`execute:${movement.action}`); return "moved"; },
      audit: async (event) => { events.push(`audit:${event.result}`); },
    };
    const pager = new PolicyPager({
      workerId: "replica-a",
      ports,
      policy: { evaluate: async () => ({ action: "promote_pin", targetRef: job.payload.targetRef }) },
    });

    await expect(pager.runOnce()).resolves.toEqual({ claimed: 1, completed: 1, retried: 0 });
    expect(events).toEqual(["execute:promote_pin", "audit:ok", "complete:moved"]);
  });

  it("durably retries failures and records a content-free audit reason", async () => {
    const seen: unknown[] = [];
    const pager = new PolicyPager({
      workerId: "replica-b",
      ports: {
        queue: {
          claim: async () => [{ ...job, leaseOwner: "replica-b" }],
          complete: async () => { throw new Error("unexpected complete"); },
          retry: async (...args) => { seen.push(args); },
        },
        execute: async () => { throw new Error("provider leaked content: customer@example.com"); },
        audit: async (event) => { seen.push(event); },
      },
      policy: { evaluate: async () => ({ action: "archive_warm", targetRef: job.payload.targetRef }) },
    });

    await expect(pager.runOnce()).resolves.toEqual({ claimed: 1, completed: 0, retried: 1 });
    expect(seen).toEqual([
      expect.objectContaining({ result: "error", reason: "execution_failed", jobId: "job-1" }),
      ["job-1", "replica-b", "execution_failed", expect.any(String)],
    ]);
    expect(JSON.stringify(seen)).not.toContain("customer@example.com");
  });

  it("keeps the durable job retryable when the audit sink is unavailable", async () => {
    const retries: string[] = [];
    const pager = new PolicyPager({
      workerId: "replica-c",
      ports: {
        queue: {
          claim: async () => [{ ...job, leaseOwner: "replica-c" }],
          complete: async () => undefined,
          retry: async (_id, _owner, reason) => { retries.push(reason); },
        },
        execute: async () => { throw new Error("provider failed"); },
        audit: async () => { throw new Error("audit unavailable"); },
      },
      policy: { evaluate: async () => ({ action: "archive_warm", targetRef: job.payload.targetRef }) },
    });

    await expect(pager.runOnce()).resolves.toEqual({ claimed: 1, completed: 0, retried: 1 });
    expect(retries).toEqual(["audit_failed"]);
  });
});
