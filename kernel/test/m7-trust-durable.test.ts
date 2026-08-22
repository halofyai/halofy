import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createDb, type Db } from "../src/db/client.js";
import {
  DURABLE_JOBS_DDL,
  DURABLE_RATE_LIMITS_DDL,
  DURABLE_TICKETS_DDL,
  DurableJobStore,
  DurableRateLimitStore,
  DurableTicketStore,
} from "../src/durable/index.js";
import type { Identity } from "../src/types.js";

const ACME: Identity = {
  keyId: "key-acme",
  namespace: "acme/eng",
  actor: "agent-a",
  role: "agent",
};
const GLOBEX: Identity = { ...ACME, keyId: "key-globex", namespace: "globex/eng" };
const ACME_OTHER: Identity = { ...ACME, keyId: "key-acme-other", actor: "agent-b" };

describe("M7 durable distributed state", () => {
  let db: Db;

  beforeEach(async () => {
    db = await createDb({ databaseUrl: "", pgliteDataDir: "" } as never);
    await db.query(DURABLE_JOBS_DDL);
    await db.query(DURABLE_TICKETS_DDL);
    await db.query(DURABLE_RATE_LIMITS_DDL);
  });

  afterEach(async () => {
    await db.close();
  });

  it("leases each due job to only one replica and survives a new store instance", async () => {
    const first = new DurableJobStore(db);
    const now = new Date("2026-07-11T10:00:00.000Z");
    await first.enqueue({
      id: "job-1",
      kind: "write",
      namespace: "acme/eng",
      payload: { content: "durable" },
      availableAt: now.toISOString(),
    });

    const claimed = await first.claim("replica-a", { now, leaseMs: 30_000 });
    expect(claimed).toMatchObject({
      id: "job-1",
      state: "running",
      leaseOwner: "replica-a",
      attempts: 1,
      payload: { content: "durable" },
    });
    expect(await new DurableJobStore(db).claim("replica-b", { now, leaseMs: 30_000 }))
      .toBeNull();

    const afterExpiry = new Date("2026-07-11T10:00:31.000Z");
    const reclaimed = await new DurableJobStore(db).claim("replica-b", {
      now: afterExpiry,
      leaseMs: 30_000,
    });
    expect(reclaimed).toMatchObject({ id: "job-1", leaseOwner: "replica-b", attempts: 2 });
    expect(await first.complete("job-1", "replica-a")).toBe(false);
    expect(await first.complete("job-1", "replica-b")).toBe(true);
    expect(await new DurableJobStore(db).get("job-1")).toMatchObject({ state: "done" });
  });

  it("keeps ticket results durable and fences redemption by namespace and subject", async () => {
    const tickets = new DurableTicketStore(db);
    await tickets.issue({
      id: "ticket-1",
      kind: "live-query",
      namespace: ACME.namespace,
      subjectKey: ACME.keyId,
      expiresAt: "2026-07-11T10:05:00.000Z",
    });
    await tickets.complete("ticket-1", { blocks: ["verified"] });

    expect(await new DurableTicketStore(db).resolve("ticket-1", ACME, {
      now: new Date("2026-07-11T10:01:00.000Z"),
    })).toMatchObject({ state: "done", result: { blocks: ["verified"] } });
    expect(await tickets.resolve("ticket-1", GLOBEX, {
      now: new Date("2026-07-11T10:01:00.000Z"),
    })).toBeNull();
    expect(await tickets.resolve("ticket-1", ACME_OTHER, {
      now: new Date("2026-07-11T10:01:00.000Z"),
    })).toBeNull();
    expect(await tickets.resolve("ticket-1", ACME, {
      now: new Date("2026-07-11T10:06:00.000Z"),
    })).toBeNull();

    await db.query(
      `INSERT INTO durable_tickets
         (id, kind, namespace, subject_key, state, result, error,
          expires_at, created_at, updated_at)
       VALUES ('legacy-null-subject', 'live-query', $1, NULL, 'done', '{}', NULL,
               '2026-07-11T10:05:00.000Z', '2026-07-11T10:00:00.000Z',
               '2026-07-11T10:00:00.000Z')`,
      [ACME.namespace],
    );
    expect(await tickets.resolve("legacy-null-subject", ACME, {
      now: new Date("2026-07-11T10:01:00.000Z"),
    })).toBeNull();
  });

  it("atomically shares a fixed-window rate limit across replicas", async () => {
    const a = new DurableRateLimitStore(db);
    const b = new DurableRateLimitStore(db);
    const now = new Date("2026-07-11T10:00:00.000Z");

    const outcomes = await Promise.all([
      a.consume("auth:127.0.0.1", 2, 60_000, now),
      b.consume("auth:127.0.0.1", 2, 60_000, now),
      a.consume("auth:127.0.0.1", 2, 60_000, now),
    ]);
    expect(outcomes.filter((outcome) => outcome.allowed)).toHaveLength(2);
    expect(outcomes.filter((outcome) => !outcome.allowed)).toHaveLength(1);

    const reset = await b.consume(
      "auth:127.0.0.1",
      2,
      60_000,
      new Date("2026-07-11T10:01:01.000Z"),
    );
    expect(reset).toMatchObject({ allowed: true, remaining: 1 });
  });
});
