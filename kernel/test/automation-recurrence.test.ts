/**
 * M9 #19 (E36/D30) — recurrence is a SINGLE durable chain.
 *
 * The adversarial review found re-configuring an ENABLED automation forked
 * the recurrence into permanent parallel chains: the enable branch enqueued a
 * fresh arm without sweeping the previously queued one (different notBefore
 * instant → different job id → ON CONFLICT never dedupes). These tests pin
 * the fix: every configure sweeps queued arms first, and the runner skips an
 * orphan arm whose id no longer matches the row's current notBefore.
 * Hermetic: in-memory PGlite, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { AuditLog } from "../src/audit/index.js";
import {
  OrgAutomationStore,
  automationJobId,
} from "../src/automation/store.js";
import { AutomationRunner } from "../src/automation/runner.js";
import { DurableJobStore } from "../src/durable/jobs.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
let db: Db;
let audit: AuditLog;
let store: OrgAutomationStore;

const admin: Identity = { keyId: "k-admin", namespace: "acme", actor: "ada", role: "admin" };

async function queuedArms(automationId: string): Promise<string[]> {
  const res = await db.query(
    `SELECT id FROM durable_jobs
      WHERE kind = 'automation' AND state = 'queued'
        AND payload->>'automationId' = $1
      ORDER BY id`,
    [automationId],
  );
  return res.rows.map((row) => String((row as { id: string }).id));
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  audit = new AuditLog(db);
  store = new OrgAutomationStore(db, audit);
});

afterAll(async () => {
  await db.close();
});

describe("E36 single durable recurrence chain", () => {
  it("re-configuring an enabled automation never forks a second chain", async () => {
    const first = await store.configure(admin, "acme", {
      templateId: "weekly-digest",
      enabled: true,
    });
    expect(await queuedArms(first.id)).toHaveLength(1);

    // A routine console settings save (still enabled, flip autoApprove):
    // previously this stacked a SECOND self-perpetuating chain forever.
    const second = await store.configure(admin, "acme", {
      templateId: "weekly-digest",
      enabled: true,
      autoApprove: true,
    });
    expect(second.id).toBe(first.id);
    const arms = await queuedArms(first.id);
    expect(arms).toHaveLength(1);
    expect(arms[0]).toBe(automationJobId(first.id, second.notBefore as string));

    // Ten more saves: still exactly one queued arm.
    for (let i = 0; i < 10; i++) {
      await store.configure(admin, "acme", { templateId: "weekly-digest", enabled: true });
    }
    expect(await queuedArms(first.id)).toHaveLength(1);

    // Disabling sweeps the chain entirely.
    await store.configure(admin, "acme", { templateId: "weekly-digest", enabled: false });
    expect(await queuedArms(first.id)).toHaveLength(0);
  });

  it("the runner ends an orphan chain: stale arm → audited skip, no re-arm", async () => {
    const automation = await store.configure(admin, "acme", {
      templateId: "weekly-digest",
      enabled: true,
    });
    // Plant an orphan arm from a superseded chain (a notBefore instant that
    // is NOT the row's current one — the pre-fix fork residue), due now.
    const stale = "2020-01-01T00:00:00.000Z";
    const jobs = new DurableJobStore(db);
    await jobs.enqueue({
      id: automationJobId(automation.id, stale),
      kind: "automation",
      namespace: "acme",
      payload: { automationId: automation.id },
      availableAt: stale,
    });

    const runner = new AutomationRunner({
      db,
      audit,
      store,
      proposer: {
        prepare: async () => { throw new Error("must not run for a stale arm"); },
        get: async () => null,
        approve: async () => { throw new Error("must not run for a stale arm"); },
      },
    });
    // The current arm is scheduled at configure-time `now` too, so claim
    // order is not guaranteed — but the stale arm must NEVER execute or
    // re-arm. After the pass: no arm with the stale instant survives, and a
    // stale-arm skip was audited.
    await runner.runAutomationJobsOnce(5);
    const arms = await queuedArms(automation.id);
    expect(arms).not.toContain(automationJobId(automation.id, stale));
    const skips = await db.query(
      `SELECT COUNT(*) AS n FROM audit_log
        WHERE op = 'automation_run' AND result = 'miss' AND detail LIKE '%skipped=stale-arm%'`,
    );
    expect(Number(skips.rows[0].n)).toBe(1);
  });
});
