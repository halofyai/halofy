import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ulid } from "ulid";
import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { SharingService } from "../src/sharing/index.js";
import type { AuditEvent, Identity } from "../src/types.js";

const DIM = 8;
const tenantOwner: Identity = {
  keyId: "tenant-owner",
  namespace: "acme",
  actor: "owner@acme.test",
  role: "owner",
};
const consumerAdmin: Identity = {
  keyId: "consumer-admin",
  namespace: "acme/consumer",
  actor: "admin@consumer.test",
  role: "admin",
};
const globalOwner: Identity = {
  keyId: "root-owner",
  namespace: "",
  actor: "root@halomem.test",
  role: "owner",
};

let db: Db;
let audit: AuditLog;
let sharing: SharingService;

async function seedMemory(namespace: string, content = "source policy"): Promise<string> {
  const id = ulid();
  const now = new Date().toISOString();
  await db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
        provenance, ttl_seconds, last_accessed, access_count, fault_count, status, embedding)
     VALUES ($1, $2, 'team', 'L2', 'inline', $3, 'fact', 0.9,
             NULL, $4, $4, NULL, NULL, '[]', NULL, NULL, 0, 0, 'active', NULL)`,
    [id, namespace, content, now],
  );
  return id;
}

beforeEach(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  audit = new AuditLog(db);
  sharing = new SharingService(db, audit);
});

afterEach(async () => {
  await db.close();
});

describe("R5D explicit segments", () => {
  it("resolves only explicitly mounted stable refs without widening ancestor ACL", async () => {
    const sharedMemory = await seedMemory("acme/source");
    await seedMemory("acme", "ordinary tenant ancestor");
    await seedMemory("acme/other", "unmounted sibling");
    const segment = await sharing.createSegment(tenantOwner, "Support policy");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: sharedMemory });
    const mount = await sharing.mount(tenantOwner, segment.id, "acme/consumer");

    expect(await sharing.resolver.resolveMountedRefs("acme/consumer/agent")).toEqual([
      {
        segmentId: segment.id,
        mountId: mount.id,
        kind: "memory",
        ref: sharedMemory,
        originNamespace: "acme/source",
        versionId: null,
      },
    ]);
    expect(await sharing.resolver.resolveMountedRefs("acme/other")).toEqual([]);
  });

  it("soft-removes stable members and revokes visibility on the next resolver call", async () => {
    const memoryId = await seedMemory("acme/source");
    const segment = await sharing.createSegment(tenantOwner, "Runbook");
    const member = await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: memoryId });
    const mount = await sharing.mount(tenantOwner, segment.id, "acme/consumer");
    expect(await sharing.resolver.resolveMountedRefs("acme/consumer")).toHaveLength(1);

    const removed = await sharing.removeMember(tenantOwner, member.id);
    expect(removed.removedAt).not.toBeNull();
    expect(await sharing.resolver.resolveMountedRefs("acme/consumer")).toEqual([]);

    const replacement = await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: memoryId });
    expect(replacement.id).not.toBe(member.id);
    expect(await sharing.resolver.resolveMountedRefs("acme/consumer")).toHaveLength(1);
    await sharing.revokeMount(tenantOwner, mount.id);
    expect(await sharing.resolver.resolveMountedRefs("acme/consumer")).toEqual([]);
    expect((await db.query(`SELECT revoked_at FROM segment_mounts WHERE id = $1`, [mount.id])).rows[0].revoked_at).not.toBeNull();
  });

  it("allows a target administrator to unmount only its own mounted view", async () => {
    const memoryId = await seedMemory("acme/source");
    const segment = await sharing.createSegment(tenantOwner, "Consumer controlled unmount");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: memoryId });
    const mount = await sharing.mount(tenantOwner, segment.id, consumerAdmin.namespace);

    const revoked = await sharing.revokeMount(consumerAdmin, mount.id);
    expect(revoked.revokedBy).toBe(consumerAdmin.actor);
    expect(await sharing.resolver.resolveMountedRefs(consumerAdmin.namespace)).toEqual([]);
    expect((await db.query(`SELECT status FROM memory_segments WHERE id = $1`, [segment.id])).rows[0])
      .toMatchObject({ status: "active" });
    expect(Number((await db.query(
      `SELECT count(*) AS n FROM segment_members WHERE segment_id = $1 AND removed_at IS NULL`,
      [segment.id],
    )).rows[0].n)).toBe(1);
  });

  it("audits a missing mount revoke as a miss", async () => {
    await expect(sharing.revokeMount(tenantOwner, ulid())).rejects.toMatchObject({
      name: "SharingValidationError",
    });
    expect((await audit.list(tenantOwner.namespace))[0]).toMatchObject({
      op: "share",
      result: "miss",
      purpose: "share:revoke",
      detail: "mount_not_found",
    });
  });

  it("denies cross-tenant mounts even to the global root authority and audits the denial", async () => {
    const memoryId = await seedMemory("acme/source");
    const segment = await sharing.createSegment(tenantOwner, "Tenant-only");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: memoryId });

    await expect(sharing.mount(globalOwner, segment.id, "globex/consumer")).rejects.toThrow(
      "cross-tenant mounts are denied",
    );
    expect(await sharing.resolver.resolveMountedRefs("globex/consumer")).toEqual([]);
    expect((await audit.list(""))[0]).toMatchObject({ op: "share", result: "denied", purpose: "share:mount" });
  });

  it("requires subtree authority for source and destination mutations", async () => {
    const memoryId = await seedMemory("acme/source");
    const segment = await sharing.createSegment(tenantOwner, "Controlled");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: memoryId });

    await expect(sharing.mount(consumerAdmin, segment.id, "acme/consumer")).rejects.toThrow(
      "segment mount denied",
    );
    const member: Identity = { ...consumerAdmin, role: "member" };
    await expect(sharing.createSegment(member, "Nope")).rejects.toThrow("segment mutation denied");
    expect((await audit.list(consumerAdmin.namespace)).filter((event) => event.result === "denied")).toHaveLength(2);
  });

  it("creates a target-owned copy-on-write fork without superseding the source", async () => {
    const sourceId = await seedMemory("acme/source", "Original policy");
    const segment = await sharing.createSegment(tenantOwner, "Editable downstream");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: sourceId });
    await sharing.mount(tenantOwner, segment.id, consumerAdmin.namespace);

    const fork = await sharing.forkMountedRef(consumerAdmin, {
      origin: { kind: "memory", ref: sourceId },
      targetNamespace: consumerAdmin.namespace,
      content: "Consumer-specific policy",
    });

    const source = (await db.query(`SELECT content, status, t_valid_to FROM memory_objects WHERE id = $1`, [sourceId])).rows[0];
    expect(source).toMatchObject({ content: "Original policy", status: "active", t_valid_to: null });
    const target = (
      await db.query(
        `SELECT namespace, content, backend_ref, supersedes, status FROM memory_objects WHERE id = $1`,
        [fork.targetMemoryId],
      )
    ).rows[0];
    expect(target).toMatchObject({
      namespace: consumerAdmin.namespace,
      content: "Consumer-specific policy",
      backend_ref: `fork:memory:${sourceId}`,
      supersedes: null,
      status: "active",
    });
    expect(
      (
        await db.query(
          `SELECT origin_kind, origin_ref, target_memory_id, target_namespace FROM memory_forks WHERE id = $1`,
          [fork.id],
        )
      ).rows[0],
    ).toMatchObject({
      origin_kind: "memory",
      origin_ref: sourceId,
      target_memory_id: fork.targetMemoryId,
      target_namespace: consumerAdmin.namespace,
    });
  });

  it("audits direct-share validation and unavailable-target outcomes with bounded details", async () => {
    await expect(sharing.share(tenantOwner, { kind: "memory", ref: "free text" }, "acme/consumer"))
      .rejects.toMatchObject({ name: "SharingValidationError" });
    await expect(sharing.share(tenantOwner, { kind: "memory", ref: ulid() }, "acme/consumer"))
      .rejects.toMatchObject({ name: "SharingAuthorizationError" });

    const events = await audit.list(tenantOwner.namespace);
    expect(events.slice(0, 2).map((event) => ({ result: event.result, detail: event.detail }))).toEqual([
      { result: "denied", detail: "target_unavailable" },
      { result: "error", detail: "target_ref_not_stable" },
    ]);
  });

  it("filters archived, expired, and revoked origins from mounted visibility", async () => {
    const active = await seedMemory("acme/source", "active");
    const archived = await seedMemory("acme/source", "archived");
    const expired = await seedMemory("acme/source", "expired");
    await db.query(`UPDATE memory_objects SET status = 'archived' WHERE id = $1`, [archived]);
    await db.query(`UPDATE memory_objects SET ttl_seconds = 1, assertion_time = $1 WHERE id = $2`, [
      new Date(Date.now() - 10_000).toISOString(),
      expired,
    ]);
    const segment = await sharing.createSegment(tenantOwner, "Filtered");
    await sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: active });
    // Unavailable objects cannot be newly added, which prevents stale grants.
    await expect(sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: archived })).rejects.toThrow(
      "segment member is unavailable",
    );
    await expect(sharing.addMember(tenantOwner, segment.id, { kind: "memory", ref: expired })).rejects.toThrow(
      "segment member is unavailable",
    );
    await sharing.mount(tenantOwner, segment.id, "acme/consumer");
    expect((await sharing.resolver.resolveMountedRefs("acme/consumer")).map((ref) => ref.ref)).toEqual([active]);
    await sharing.revokeSegment(tenantOwner, segment.id);
    expect(await sharing.resolver.resolveMountedRefs("acme/consumer")).toEqual([]);
  });

  it("rolls back segment mutation when its success audit fails", async () => {
    class FailingAudit extends AuditLog {
      override async appendTo(_tx: Db, _event: AuditEvent): Promise<void> {
        throw new Error("audit unavailable");
      }
    }
    const unsafe = new SharingService(db, new FailingAudit(db));
    await expect(unsafe.createSegment(tenantOwner, "Must not persist")).rejects.toThrow("audit unavailable");
    expect(Number((await db.query(`SELECT count(*) AS n FROM memory_segments`)).rows[0].n)).toBe(0);
  });

  it("keeps direct share atomic when its success audit fails", async () => {
    class FailingSuccessAudit extends AuditLog {
      private calls = 0;

      override async appendTo(_tx: Db, _event: AuditEvent): Promise<void> {
        this.calls++;
        if (this.calls === 1) throw new Error("audit unavailable");
        return super.appendTo(_tx, _event);
      }
    }
    const memoryId = await seedMemory("acme/source");
    const unsafe = new SharingService(db, new FailingSuccessAudit(db));

    await expect(unsafe.share(
      tenantOwner,
      { kind: "memory", ref: memoryId },
      consumerAdmin.namespace,
    )).rejects.toThrow("audit unavailable");
    expect(Number((await db.query(`SELECT count(*) AS n FROM memory_segments`)).rows[0].n)).toBe(0);
    expect((await audit.list(tenantOwner.namespace))[0]).toMatchObject({
      op: "share",
      result: "error",
      detail: "share_failed",
    });
  });
});
