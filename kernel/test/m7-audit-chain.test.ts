import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import type { AuditEvent } from "../src/types.js";

const opened: Db[] = [];

afterEach(async () => Promise.all(opened.splice(0).map((db) => db.close())));

async function fixture(): Promise<{ db: Db; audit: AuditLog }> {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 8 }));
  opened.push(db);
  await migrate(db, 8);
  return { db, audit: new AuditLog(db) };
}

function event(ts: string, detail: string): AuditEvent {
  return {
    ts,
    actor: "m7-auditor",
    agentId: "m7-agent",
    op: "stats",
    memoryId: null,
    namespace: "m7/audit",
    purpose: "chain-test",
    result: "ok",
    detail,
  };
}

describe("M7 tamper-evident audit chain", () => {
  it("chains every append and verifies an intact ledger", async () => {
    const { db, audit } = await fixture();
    await audit.append(event("2026-01-01T00:00:00.000Z", "first"));
    await audit.append(event("2026-01-01T00:00:01.000Z", "second"));

    const rows = await db.query(
      "SELECT prev_hash, event_hash FROM audit_log ORDER BY seq",
    );
    expect(rows.rows[0]?.event_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(rows.rows[1]?.prev_hash).toBe(rows.rows[0]?.event_hash);
    expect(await audit.verifyChain()).toEqual({ ok: true, checked: 2 });
  });

  it("detects mutation of an existing audit row", async () => {
    const { db, audit } = await fixture();
    await audit.append(event("2026-01-01T00:00:00.000Z", "original"));
    await db.query("UPDATE audit_log SET detail = 'tampered' WHERE namespace = 'm7/audit'");
    const result = await audit.verifyChain();
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ checked: 1, brokenSeq: 1 });
  });

  it("detects deletion of the newest hashed audit row", async () => {
    const { db, audit } = await fixture();
    await audit.append(event("2026-01-01T00:00:00.000Z", "first"));
    await audit.append(event("2026-01-01T00:00:01.000Z", "second"));
    await db.query("DELETE FROM audit_log WHERE detail = 'second'");

    expect(await audit.verifyChain()).toEqual({ ok: false, checked: 1 });
  });

  it("detects deletion of every hashed audit row", async () => {
    const { db, audit } = await fixture();
    await audit.append(event("2026-01-01T00:00:00.000Z", "only"));
    await db.query("DELETE FROM audit_log WHERE event_hash IS NOT NULL");

    expect(await audit.verifyChain()).toEqual({ ok: false, checked: 0 });
  });
});
