import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { AuditLog } from "../src/audit/index.js";
import { AutomationRunner } from "../src/automation/runner.js";
import { OrgAutomationStore } from "../src/automation/store.js";
import { loadConfig } from "../src/config.js";
import type { ManualConsolidationInput, PreparedConsolidation } from "../src/consolidation/index.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
const TEAM_ADMIN: Identity = {
  keyId: "key-support-admin",
  namespace: "acme/support",
  actor: "support-admin",
  role: "admin",
};
const TEAM_OWNER: Identity = {
  keyId: "key-support-owner",
  namespace: "acme/support",
  actor: "support-owner",
  role: "owner",
};
const PLATFORM_OWNER: Identity = {
  keyId: "key-platform-owner",
  namespace: "",
  actor: "platform-owner",
  role: "owner",
};

async function insertMemory(db: Db, id: string, assertionTime: string): Promise<void> {
  await db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
        provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
     VALUES ($1, $2, 'team', 'L2', $3, $4, 'fact', 0.9,
             NULL, $5, $5, NULL, NULL, '[]'::jsonb, NULL, NULL, 0, 0, 'active', NULL)`,
    [id, TEAM_ADMIN.namespace, `inline:${id}`, `fact ${id}`, assertionTime],
  );
}

describe("knowledge sync delta batching", () => {
  let db: Db;
  let audit: AuditLog;
  let store: OrgAutomationStore;
  let now: Date;
  let batches: string[][];

  beforeEach(async () => {
    db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    await migrate(db, DIM);
    audit = new AuditLog(db);
    now = new Date("2026-07-22T12:00:10.000Z");
    store = new OrgAutomationStore(db, audit, () => now);
    batches = [];
  });

  afterEach(async () => {
    await db.close();
  });

  it("processes every delta memory chronologically across bounded batches", async () => {
    const ids = ["mem-01", "mem-02", "mem-03", "mem-04", "mem-05", "mem-06"];
    const assertionTimes = [
      "2026-07-22T12:00:01.000Z",
      "2026-07-22T12:00:02.000Z",
      "2026-07-22T12:00:03.000Z",
      "2026-07-22T12:00:03.000Z",
      "2026-07-22T12:00:05.000Z",
      "2026-07-22T12:00:06.000Z",
    ];
    for (let index = 0; index < ids.length; index++) {
      await insertMemory(
        db,
        ids[index]!,
        assertionTimes[index]!,
      );
    }

    const automation = await store.configure(TEAM_ADMIN, TEAM_ADMIN.namespace, {
      templateId: "fresh-summaries",
      enabled: true,
      intervalSeconds: 3_600,
      config: { maxEvidence: 2 },
    });
    expect(automation.cursorValue).toBeNull();
    await expect(store.syncNow(TEAM_ADMIN, TEAM_ADMIN.namespace))
      .rejects.toMatchObject({ name: "AutomationAuthorizationError" });
    const firstSync = await store.syncNow(TEAM_OWNER, TEAM_OWNER.namespace);
    expect(firstSync.cursorValue).toContain("1970-01-01T00:00:00.000Z");
    const runner = new AutomationRunner({
      db,
      audit,
      store,
      now: () => now,
      proposer: {
        async prepare(_identity, input: ManualConsolidationInput): Promise<PreparedConsolidation> {
          batches.push([...input.evidenceIds]);
          return {
            runId: `run-${batches.length}`,
            namespace: input.namespace,
            proposalIds: [],
            async commitPrepared() {},
          };
        },
        async get() {
          return null;
        },
        async approve() {
          throw new Error("no proposal is emitted by this test double");
        },
      },
    });

    for (let pass = 0; pass < 3; pass++) {
      await runner.runAutomationJobsOnce(1);
      now = new Date(now.getTime() + 1_000);
    }

    expect(batches).toEqual([
      ["mem-01", "mem-02"],
      ["mem-03", "mem-04"],
      ["mem-05", "mem-06"],
    ]);
    const completedCursor = (await store.getById(automation.id))?.cursorValue;
    expect(completedCursor).toContain("mem-06");

    // A user clicking Sync again resumes from the checkpoint. It must not
    // reset the scope and pay to summarize the already reviewed history.
    const retriggered = await store.syncNow(TEAM_OWNER, TEAM_OWNER.namespace);
    expect(retriggered.cursorValue).toBe(completedCursor);
    expect(retriggered.config).toEqual({ maxEvidence: 2 });
  });

  it("rejects the platform root because private L3 drafts require a tenant namespace", async () => {
    await expect(store.syncNow(PLATFORM_OWNER, ""))
      .rejects.toMatchObject({ name: "AutomationAuthorizationError" });
  });
});

describe("knowledge sync ownership and target resolution", () => {
  let kernel: Kernel;
  let rootOwner: Identity;
  let organizationOwner: Identity;
  let supportOwner: Identity;
  let supportAdmin: Identity;
  let supportTeam: Awaited<ReturnType<Kernel["createTeam"]>>;
  let marketingTeam: Awaited<ReturnType<Kernel["createTeam"]>>;

  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
      coldKek: randomBytes(32).toString("base64"),
    });
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    rootOwner = (await kernel.auth.resolve(rootKey.plaintext))!;
    const organizationOwnerKey = await kernel.auth.issueKey("acme", "owner:acme", "owner", rootOwner);
    organizationOwner = (await kernel.auth.resolve(organizationOwnerKey.plaintext))!;
    await kernel.createTeam(organizationOwner, { name: "Finance" });
    supportTeam = await kernel.createTeam(rootOwner, { name: "Support" });
    marketingTeam = await kernel.createTeam(rootOwner, { name: "Marketing" });

    const ownerKey = await kernel.auth.issueKey(supportTeam.namespace, "owner:support", "owner", rootOwner);
    supportOwner = (await kernel.auth.resolve(ownerKey.plaintext))!;
    const adminKey = await kernel.auth.issueKey(supportTeam.namespace, "admin:support", "admin", rootOwner);
    supportAdmin = (await kernel.auth.resolve(adminKey.plaintext))!;
  });

  afterAll(async () => {
    await kernel.close();
  });

  it("lets a team owner queue only the selected team without exposing its namespace", async () => {
    const result = await kernel.queueKnowledgeSync(supportOwner, {
      scope: "team",
      teamId: supportTeam.id,
    });

    expect(result).toMatchObject({
      status: "queued",
      scope: "team",
      queuedSpaces: [{ id: supportTeam.id, name: "Support" }],
    });
    expect(result.runs).toEqual([expect.objectContaining({
      id: supportTeam.id,
      name: "Support",
      status: "queued",
      queuedAt: expect.any(String),
    })]);
    expect(JSON.stringify(result)).not.toContain(supportTeam.namespace);

    const queued = await kernel.knowledgeSyncStatus(supportOwner);
    expect(queued.runs).toEqual([expect.objectContaining({
      id: supportTeam.id,
      name: "Support",
      status: "queued",
      processed: null,
      proposals: null,
    })]);
    expect(queued.totals.queued).toBe(1);
    expect(JSON.stringify(queued)).not.toContain(supportTeam.namespace);

    await kernel.runAutomationJobsOnce(1);
    const completed = await kernel.knowledgeSyncStatus(supportOwner);
    expect(completed.runs[0]).toMatchObject({
      id: supportTeam.id,
      name: "Support",
      status: "completed",
      lastRunStatus: "ok",
    });
    await expect(kernel.queueKnowledgeSync(supportOwner, {
      scope: "team",
      teamId: marketingTeam.id,
    })).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("returns each visible sync execution from the last 30 days", async () => {
    const completedBefore = (await kernel.knowledgeSyncStatus(supportOwner)).runs
      .filter((run) => run.status === "completed").length;
    for (let run = 0; run < 2; run++) {
      await kernel.queueKnowledgeSync(supportOwner, {
        scope: "team",
        teamId: supportTeam.id,
      });
      await kernel.runAutomationJobsOnce(1);
    }

    await kernel.audit.append({
      ts: new Date(Date.now() - 31 * 24 * 60 * 60 * 1_000).toISOString(),
      actor: "automation:stale-history-fixture",
      agentId: "automation-worker",
      op: "automation_run",
      memoryId: null,
      namespace: supportTeam.namespace,
      purpose: "automation",
      result: "ok",
      detail:
        "run template=fresh-summaries automation=stale proposals=1 approved=0 " +
        "next=2026-01-01T00:00:00.000Z evidence=999 more=false",
    });

    const status = await kernel.knowledgeSyncStatus(supportOwner);
    const completed = status.runs.filter((run) => run.status === "completed");

    expect(status.retentionDays).toBe(30);
    expect(completed).toHaveLength(completedBefore + 2);
    expect(completed.every((run) => run.id === supportTeam.id && run.name === "Support")).toBe(true);
    expect(completed.map((run) => run.processed)).not.toContain(999);
    expect(JSON.stringify(status)).not.toContain(supportTeam.namespace);
  });

  it("reserves team/company sync for owners and queues only private team namespaces", async () => {
    await expect(kernel.queueKnowledgeSync(supportAdmin, {
      scope: "team",
      teamId: supportTeam.id,
    })).rejects.toMatchObject({ name: "AuthzError" });

    await expect(kernel.queueKnowledgeSync(supportOwner, {
      scope: "organization",
    })).rejects.toMatchObject({ name: "AuthzError" });

    const organizationResult = await kernel.queueKnowledgeSync(organizationOwner, {
      scope: "organization",
    });
    expect(organizationResult.queuedSpaces.map((space) => space.name)).toEqual([
      "Organization memory",
      "Finance",
    ]);
    expect(JSON.stringify(organizationResult)).not.toContain(organizationOwner.namespace);

    const result = await kernel.queueKnowledgeSync(rootOwner, { scope: "organization" });
    expect(result.status).toBe("queued");
    expect(result.scope).toBe("organization");
    expect(result.queuedSpaces.map((space) => space.name).sort()).toEqual([
      "Finance",
      "Marketing",
      "Support",
    ]);
    expect(JSON.stringify(result)).not.toContain("namespace");

    await kernel.runAutomationJobsOnce(10);
    const status = await kernel.knowledgeSyncStatus(rootOwner);
    expect(status.runs.some((run) => run.name === "Organization memory")).toBe(false);
    expect(status.runs.some((run) => run.status === "failed")).toBe(false);
    expect(status.runs).toContainEqual(expect.objectContaining({
      name: "Marketing",
      status: "completed",
    }));
    expect(status.runs).toContainEqual(expect.objectContaining({
      name: "Support",
      status: "completed",
    }));
  });
});
