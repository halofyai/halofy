import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

import { DurableJobStore } from "../src/durable/jobs.js";
import { Kernel } from "../src/kernel.js";

const kernels: Kernel[] = [];
afterEach(async () => Promise.all(kernels.splice(0).map((kernel) => kernel.close())));

describe("source scheduling lifecycle", () => {
  it("queues a manual sync and returns before the connector worker runs", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const owner = await kernel.auth.resolve(rootKey.plaintext);
    if (!owner) throw new Error("owner identity failed");
    const source = await kernel.sources.register("", "filesystem", { path: "C:/not-read" });
    kernel.runConnectorJobsOnce = async () => ({ claimed: 0, completed: 0 });

    const ticket = await kernel.requestSourceSync(source.id, owner);

    expect(ticket).toMatchObject({ accepted: true, status: "queued" });
    expect(ticket.jobId).toMatch(/^source-sync:manual:/);
    expect((await kernel.sources.get(source.id))?.syncStatus).toBe("pending");
    expect((await kernel.db.query(
      `SELECT state, namespace, payload FROM durable_jobs WHERE id = $1`,
      [ticket.jobId],
    )).rows).toEqual([expect.objectContaining({
      state: "queued",
      namespace: "",
      payload: { sourceId: source.id },
    })]);
    const repeated = await kernel.requestSourceSync(source.id, owner);
    expect(repeated.jobId).toBe(ticket.jobId);
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs
        WHERE kind = 'source-sync' AND state IN ('queued', 'running')
          AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toHaveLength(1);
  }, 30_000);

  it("keeps one queued schedule and cancels it on manual mode or pause", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const owner = await kernel.auth.resolve(rootKey.plaintext);
    if (!owner) throw new Error("owner identity failed");
    const source = await kernel.sources.register("", "filesystem", { path: "C:/not-read" });

    await kernel.scheduleSource(source.id, 3_600, owner);
    await kernel.scheduleSource(source.id, 7_200, owner);
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs WHERE kind = 'source-sync' AND state = 'queued'
        AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toHaveLength(1);
    await kernel.scheduleSource(source.id, null, owner);
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs WHERE kind = 'source-sync' AND state = 'queued'
        AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toHaveLength(0);

    await new DurableJobStore(kernel.db).enqueue({
      id: `source-sync:${source.id}:stale`,
      kind: "source-sync",
      namespace: source.namespace,
      payload: { sourceId: source.id },
    });
    await kernel.pauseSource(source.id, owner);
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs WHERE kind = 'source-sync' AND state = 'queued'
        AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toHaveLength(0);
  }, 30_000);

  it("completes a stale claimed job for a paused source instead of retrying", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const owner = await kernel.auth.resolve(rootKey.plaintext);
    if (!owner) throw new Error("owner identity failed");
    const source = await kernel.sources.register("", "filesystem", { path: "C:/not-read" });
    await kernel.sources.pause(source.id);
    const jobs = new DurableJobStore(kernel.db);
    const job = await jobs.enqueue({
      id: `source-sync:${source.id}:paused`,
      kind: "source-sync",
      namespace: source.namespace,
      payload: { sourceId: source.id },
    });
    expect(await kernel.runConnectorJobsOnce()).toEqual({ claimed: 1, completed: 1 });
    expect((await jobs.get(job.id))?.state).toBe("done");
  }, 30_000);

  it("runs scheduled sync jobs without hosted allowances", async () => {
    const priorEnabled = process.env.HALOMEM_EARLY_ACCESS;
    const priorLimit = process.env.HALOMEM_EARLY_ACCESS_SOURCE_SYNC_LIMIT;
    process.env.HALOMEM_EARLY_ACCESS = "true";
    process.env.HALOMEM_EARLY_ACCESS_SOURCE_SYNC_LIMIT = "1";
    try {
      const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
      kernels.push(kernel);
      const first = await kernel.sources.register("", "filesystem", { path: "C:/not-read-a" });
      const second = await kernel.sources.register("", "filesystem", { path: "C:/not-read-b" });
      const jobs = new DurableJobStore(kernel.db);
      const firstJob = await jobs.enqueue({
        id: `source-sync:${first.id}:scheduled-a`,
        kind: "source-sync",
        namespace: first.namespace,
        payload: { sourceId: first.id },
      });
      const secondJob = await jobs.enqueue({
        id: `source-sync:${second.id}:scheduled-b`,
        kind: "source-sync",
        namespace: second.namespace,
        payload: { sourceId: second.id },
      });

      await kernel.runConnectorJobsOnce(2);

      expect((await kernel.db.query(
        "SELECT units FROM early_access_usage WHERE feature = 'source_sync'",
      )).rows).toEqual([]);
      expect((await kernel.db.query("SELECT actor FROM early_access_members")).rows).toHaveLength(0);
      expect((await jobs.get(firstJob.id))?.state).not.toBe("failed");
      expect((await jobs.get(secondJob.id))?.state).not.toBe("failed");
    } finally {
      if (priorEnabled === undefined) delete process.env.HALOMEM_EARLY_ACCESS;
      else process.env.HALOMEM_EARLY_ACCESS = priorEnabled;
      if (priorLimit === undefined) delete process.env.HALOMEM_EARLY_ACCESS_SOURCE_SYNC_LIMIT;
      else process.env.HALOMEM_EARLY_ACCESS_SOURCE_SYNC_LIMIT = priorLimit;
    }
  }, 30_000);
});
