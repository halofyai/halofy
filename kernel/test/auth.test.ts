/**
 * Module A (M1) tests — AuthService: issue/resolve roundtrip, revocation,
 * bootstrap-empty-table rule, admin list scoping, audit rows on every deny.
 * Hermetic: in-memory PGlite with the vector extension, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { AuditLog } from "../src/audit/index.js";
import {
  AuthService,
  AuthzError,
  ensureApiKeysTable,
  hashKey,
  isSelfOrDescendant,
} from "../src/auth/index.js";
import type { Identity } from "../src/types.js";

const DIM = 8;

let db: Db;
let auth: AuthService;
let audit: AuditLog;

async function deniedAuditCount(): Promise<number> {
  const res = await db.query(
    `SELECT COUNT(*) AS n FROM audit_log WHERE result = 'denied' AND op = 'reject'`,
  );
  return Number(res.rows[0].n);
}

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  // Module C owns migration 002 (api_keys); tests create the table inline
  // with the exact CONTRACTS-M1.md DDL. Idempotency check: run twice.
  await ensureApiKeysTable(db);
  await ensureApiKeysTable(db);
  audit = new AuditLog(db);
  auth = new AuthService(db, audit);
});

afterAll(async () => {
  await db.close();
});

describe("bootstrap rule", () => {
  it("issues the first key with no caller identity while api_keys is empty", async () => {
    const countRes = await db.query(`SELECT COUNT(*) AS n FROM api_keys`);
    expect(Number(countRes.rows[0].n)).toBe(0);

    const { record, plaintext } = await auth.issueKey("org", "root", "owner");
    expect(record.role).toBe("owner");
    expect(record.namespace).toBe("org");
    expect(record.status).toBe("active");
    expect(plaintext).toMatch(/^hm_[0-9a-f]{40}$/);
    // Stash for later tests.
    ownerPlain = plaintext;
    ownerId = record.id;
  });

  it("denies keygen without an owner identity once the table is non-empty, and audits it", async () => {
    const before = await deniedAuditCount();
    await expect(auth.issueKey("org/team-a", "eve", "agent")).rejects.toThrow(AuthzError);
    await expect(
      auth.issueKey("org/team-a", "eve", "agent", {
        keyId: "x",
        namespace: "org/team-a",
        actor: "eve",
        role: "member",
      }),
    ).rejects.toThrow(AuthzError);
    expect(await deniedAuditCount()).toBe(before + 2);
  });

  it("rejects reserved system- actors at issuance", async () => {
    await expect(
      auth.issueKey("org", "system-default-skills", "owner"),
    ).rejects.toThrow(/reserved/);
    // The reserved name must never land in the table.
    const res = await db.query(
      `SELECT COUNT(*) AS n FROM api_keys WHERE actor LIKE 'system-%'`,
    );
    expect(Number(res.rows[0].n)).toBe(0);
  });
});

let ownerPlain = "";
let ownerId = "";

describe("issue → resolve roundtrip", () => {
  it("resolves a freshly issued key to the bound Identity and updates last_used", async () => {
    const owner = await auth.resolve(ownerPlain);
    expect(owner).not.toBeNull();

    const { record, plaintext } = await auth.issueKey(
      "org/team-a",
      "agent-1",
      "agent",
      owner,
    );
    expect(plaintext).toMatch(/^hm_[0-9a-f]{40}$/);
    expect(record.lastUsed).toBeNull();

    const identity = await auth.resolve(plaintext);
    expect(identity).toEqual<Identity>({
      keyId: record.id,
      namespace: "org/team-a",
      actor: "agent-1",
      role: "agent",
      // D50: an agent identity carries its scope level; an issuance that did
      // not name one is the least-privileged 'member'.
      agentAccessLevel: "member",
      // D54: an agent identity also carries whether it may CHANGE memory.
      // NULL on the row means "may write" — every pre-D54 agent could.
      agentCanWrite: true,
      // D36: the server-derived caller classification rides the resolved
      // identity for usage attribution; legacy keys default to unclassified.
      callerClass: "unclassified",
    });

    const row = await db.query(`SELECT last_used FROM api_keys WHERE id = $1`, [record.id]);
    expect(row.rows[0].last_used).not.toBeNull();
  });

  it("never stores the plaintext - only the sha256 hex", async () => {
    const res = await db.query(`SELECT id, key_hash, namespace, actor, role FROM api_keys`);
    for (const row of res.rows) {
      for (const value of Object.values(row)) {
        expect(String(value)).not.toContain(ownerPlain);
      }
      expect(row.key_hash).toMatch(/^[0-9a-f]{64}$/);
    }
    const hashRes = await db.query(`SELECT id FROM api_keys WHERE key_hash = $1`, [
      hashKey(ownerPlain),
    ]);
    expect(hashRes.rows[0].id).toBe(ownerId);
  });

  it("returns null for a wrong key and audits the deny", async () => {
    const before = await deniedAuditCount();
    const identity = await auth.resolve("hm_" + "0".repeat(40));
    expect(identity).toBeNull();
    expect(await deniedAuditCount()).toBe(before + 1);
  });
});

describe("revocation", () => {
  it("resolves to null after revoke, and audits the deny", async () => {
    const owner = await auth.resolve(ownerPlain);
    const { record, plaintext } = await auth.issueKey("org/team-a", "temp", "member", owner);
    expect(await auth.resolve(plaintext)).not.toBeNull();

    expect(await auth.revoke(record.id)).toBe(true);
    // Idempotent — second revoke finds no active row.
    expect(await auth.revoke(record.id)).toBe(false);

    const before = await deniedAuditCount();
    expect(await auth.resolve(plaintext)).toBeNull();
    expect(await deniedAuditCount()).toBe(before + 1);
  });
});

describe("list scoping", () => {
  let adminA: Identity;

  it("owner sees all keys", async () => {
    const owner = await auth.resolve(ownerPlain);
    expect(owner).not.toBeNull();

    const a = await auth.issueKey("org/team-a", "admin-a", "admin", owner);
    const b = await auth.issueKey("org/team-b", "agent-b", "agent", owner);
    await auth.issueKey("org/team-a/sub", "agent-sub", "agent", owner);

    const all = await auth.list(owner!);
    const namespaces = all.map((r) => r.namespace);
    expect(namespaces).toContain("org");
    expect(namespaces).toContain("org/team-a");
    expect(namespaces).toContain("org/team-b");
    expect(namespaces).toContain("org/team-a/sub");

    adminA = (await auth.resolve(a.plaintext))!;
    expect(adminA.role).toBe("admin");
    void b;
  });

  it("admin of org/team-a sees own subtree only - never org/team-b or org", async () => {
    const visible = await auth.list(adminA);
    expect(visible.length).toBeGreaterThan(0);
    for (const r of visible) {
      expect(isSelfOrDescendant(r.namespace, "org/team-a")).toBe(true);
    }
    const namespaces = visible.map((r) => r.namespace);
    expect(namespaces).not.toContain("org/team-b");
    expect(namespaces).not.toContain("org");
    expect(namespaces).toContain("org/team-a");
    expect(namespaces).toContain("org/team-a/sub");
  });

  it("does not leak sibling prefixes (org/team-a admin cannot see org/team-ab)", async () => {
    const owner = await auth.resolve(ownerPlain);
    await auth.issueKey("org/team-ab", "agent-ab", "agent", owner);
    const visible = await auth.list(adminA);
    expect(visible.map((r) => r.namespace)).not.toContain("org/team-ab");
  });

  it("never treats '_'/'%' in the admin's namespace as LIKE wildcards", async () => {
    const owner = await auth.resolve(ownerPlain);
    // Underscored namespaces are legal (no charset validation) and common.
    const svcAdmin = await auth.issueKey("org/eng_svc", "admin-svc", "admin", owner);
    await auth.issueKey("org/eng_svc/dev", "agent-svc", "agent", owner);
    // Sibling tenant: 'org/engXsvc/...' LIKE 'org/eng_svc/%' is TRUE in raw
    // SQL ('_' matches 'X') — these keys must stay invisible to the admin.
    await auth.issueKey("org/engXsvc/dev", "agent-x", "agent", owner);

    const adminSvc = (await auth.resolve(svcAdmin.plaintext))!;
    const visible = await auth.list(adminSvc);
    const namespaces = visible.map((r) => r.namespace);
    expect(namespaces).toContain("org/eng_svc");
    expect(namespaces).toContain("org/eng_svc/dev");
    expect(namespaces).not.toContain("org/engXsvc/dev");
    for (const r of visible) {
      expect(isSelfOrDescendant(r.namespace, "org/eng_svc")).toBe(true);
    }
  });

  it("denies list for agent/auditor roles and audits every deny", async () => {
    const before = await deniedAuditCount();
    for (const role of ["agent", "auditor"] as const) {
      const caller: Identity = {
        keyId: "k-" + role,
        namespace: "org/team-a",
        actor: "someone",
        role,
      };
      await expect(auth.list(caller)).rejects.toThrow(AuthzError);
    }
    expect(await deniedAuditCount()).toBe(before + 2);
  });

  // D58: a member may deploy agents, but exact namespace alone is not ownership.
  // A sibling member must not inherit authority over another member's agents.
  // Same-team keys remain hidden unless self-created or explicitly assigned.
  it("does not expose unassigned same-team agent keys to a member", async () => {
    const owner = await auth.resolve(ownerPlain);
    await auth.issueKey("org/team-m", "team-bot", "agent", owner);
    await auth.issueKey("org/team-m/sub", "descendant-bot", "agent", owner);
    await auth.issueKey("org/team-m", "team-admin", "admin", owner);

    const member: Identity = {
      keyId: "k-member",
      namespace: "org/team-m",
      actor: "person@example.com",
      role: "member",
    };
    const visible = await auth.list(member);
    expect(visible).toEqual([]);
  });
});
