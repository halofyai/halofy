import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ulid } from "ulid";

import { ContextAllocator } from "../src/allocator/index.js";
import { AuditLog } from "../src/audit/index.js";
import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { HashEmbedder } from "../src/embed/index.js";
import { MemoryIndex } from "../src/index/index.js";
import { PinService, PinValidationError, type PinColdPort } from "../src/pins/index.js";
import type {
  AuditEvent,
  Concept,
  Identity,
  MemoryObject,
  PolicyConfig,
} from "../src/types.js";

const DIM = 256;
const OWNER: Identity = { keyId: "owner", namespace: "acme", actor: "owner@acme.test", role: "owner" };
const TEAM_ADMIN: Identity = { keyId: "admin", namespace: "acme/support", actor: "admin@acme.test", role: "admin" };
const SIBLING_ADMIN: Identity = { keyId: "sales", namespace: "acme/sales", actor: "sales@acme.test", role: "admin" };
const AGENT: Identity = { keyId: "agent-badge", namespace: "acme/support", actor: "support-agent", role: "agent" };
const ROOT: Identity = { keyId: "root", namespace: "", actor: "root@halomem.test", role: "owner" };

let db: Db;
let index: MemoryIndex;
let audit: AuditLog;
let cold: TestCold;
let pins: PinService;

class TestCold implements PinColdPort {
  readonly concepts = new Map<string, Concept>();

  async readConcept(namespace: string, path: string): Promise<Concept | null> {
    const concept = this.concepts.get(path) ?? null;
    if (!concept) return null;
    if (concept.visibility === "public") return concept;
    const allowed = namespace === concept.namespace || namespace.startsWith(`${concept.namespace}/`);
    return allowed ? concept : null;
  }
}

function memory(overrides: Partial<MemoryObject> = {}): MemoryObject {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    namespace: "acme/support",
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: "Support refunds require a ticket reference.",
    type: "fact",
    confidence: 0.95,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "manual", actor: OWNER.actor, ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
    ...overrides,
  };
}

async function logicalConcept(
  namespace = "acme/support",
  body = "Escalate refund requests above $500.",
): Promise<{ conceptId: string; versionId: string; path: string }> {
  const conceptId = ulid();
  const versionId = ulid();
  const path = `concepts/${versionId}.okf.enc`;
  const now = new Date().toISOString();
  await db.query(
    `INSERT INTO knowledge_concepts
       (id, namespace, slug, title, current_version_id, status, created_at, updated_at)
     VALUES ($1, $2, $3, $4, NULL, 'active', $5, $5)`,
    [conceptId, namespace, `refund-${conceptId}`, "Refund escalation", now],
  );
  await db.query(
    `INSERT INTO knowledge_versions
       (id, concept_id, path, version, supersedes_version_id, content_hash,
        proposal_id, state, published_at, created_at)
     VALUES ($1, $2, $3, 1, NULL, $4, NULL, 'published', $5, $5)`,
    [versionId, conceptId, path, `hash-${versionId}`, now],
  );
  await db.query("UPDATE knowledge_concepts SET current_version_id = $2 WHERE id = $1", [
    conceptId,
    versionId,
  ]);
  cold.concepts.set(path, {
    path,
    type: "policy",
    title: "Refund escalation",
    description: "",
    tags: [],
    namespace,
    body,
  });
  return { conceptId, versionId, path };
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
});

beforeEach(async () => {
  await db.query("DELETE FROM memory_pins");
  await db.query("DELETE FROM knowledge_versions");
  await db.query("DELETE FROM knowledge_concepts");
  await db.query("DELETE FROM tombstones");
  await db.query("DELETE FROM memory_objects");
  await db.query("DELETE FROM audit_log");
  index = new MemoryIndex(db);
  audit = new AuditLog(db);
  cold = new TestCold();
  pins = new PinService(db, audit, cold);
});

afterAll(async () => db.close());

describe("PinService stable governed references", () => {
  it("binds agent pin and unpin audit attribution to the badge", async () => {
    const target = memory({ namespace: AGENT.namespace });
    await index.insert(target, null);
    const created = await pins.pin({ kind: "memory", ref: target.id }, AGENT);
    await pins.unpin(created.pin.id, AGENT);

    const events = await audit.list(AGENT.namespace);
    const pinEvents = events.filter((event) => event.op === "pin" || event.op === "unpin");
    expect(pinEvents).toHaveLength(2);
    expect(pinEvents.every((event) => event.agentId === AGENT.keyId)).toBe(true);
  });

  it("rejects raw lookup text and audits the miss", async () => {
    await expect(
      pins.pin({ kind: "memory", ref: "refund policy" }, TEAM_ADMIN),
    ).rejects.toBeInstanceOf(PinValidationError);
    expect(Number((await db.query("SELECT count(*) AS n FROM memory_pins")).rows[0].n)).toBe(0);
    const events = await audit.list(TEAM_ADMIN.namespace);
    expect(events[0]).toMatchObject({ op: "pin", result: "miss", detail: "target_ref_not_stable" });
  });

  it("pins and unpins idempotently while auditing every outcome", async () => {
    const target = memory();
    await index.insert(target, null);

    const first = await pins.pin({ kind: "memory", ref: target.id }, TEAM_ADMIN);
    const duplicate = await pins.pin({ kind: "memory", ref: target.id }, TEAM_ADMIN);
    expect(first.created).toBe(true);
    expect(duplicate.created).toBe(false);
    expect(duplicate.pin.id).toBe(first.pin.id);
    expect((await pins.list(TEAM_ADMIN))).toHaveLength(1);

    const released = await pins.unpin(first.pin.id, TEAM_ADMIN);
    const repeated = await pins.unpin(first.pin.id, TEAM_ADMIN);
    expect(released.released).toBe(true);
    expect(repeated.released).toBe(false);
    expect(await pins.list(TEAM_ADMIN)).toEqual([]);
    const history = await pins.list(TEAM_ADMIN, TEAM_ADMIN.namespace, true);
    expect(history[0].releasedBy).toBe(TEAM_ADMIN.actor);

    const replacement = await pins.pin({ kind: "memory", ref: target.id }, TEAM_ADMIN);
    expect(replacement.created).toBe(true);
    expect(replacement.pin.id).not.toBe(first.pin.id);
    const events = await audit.list(TEAM_ADMIN.namespace);
    expect(events.filter((event) => event.op === "pin")).toHaveLength(3);
    expect(events.filter((event) => event.op === "unpin")).toHaveLength(2);
  });

  it("enforces caller subtree and target visibility without sibling leakage", async () => {
    const support = memory();
    const sales = memory({ namespace: "acme/sales" });
    const foreign = memory({ namespace: "globex/support" });
    await index.insert(support, null);
    await index.insert(sales, null);
    await index.insert(foreign, null);

    await expect(pins.pin({ kind: "memory", ref: sales.id }, TEAM_ADMIN)).rejects.toThrow(
      /outside the destination namespace visibility/,
    );
    await expect(pins.pin({ kind: "memory", ref: foreign.id }, OWNER)).rejects.toThrow(
      /outside the destination namespace visibility/,
    );
    await expect(
      pins.pin({ kind: "memory", ref: support.id }, SIBLING_ADMIN, { namespace: "acme/support" }),
    ).rejects.toThrow(/denied/);

    const rootPin = await pins.pin(
      { kind: "memory", ref: support.id },
      ROOT,
      { namespace: "acme/support" },
    );
    expect(rootPin.pin.namespace).toBe("acme/support");
  });

  it("rejects expired/archived targets and browns out pins erased after creation", async () => {
    const expired = memory({
      assertionTime: "2020-01-01T00:00:00.000Z",
      tValidFrom: "2020-01-01T00:00:00.000Z",
      ttlSeconds: 1,
    });
    const archived = memory({ status: "archived" });
    const erasedLater = memory();
    await index.insert(expired, null);
    await index.insert(archived, null);
    await index.insert(erasedLater, null);

    await expect(pins.pin({ kind: "memory", ref: expired.id }, TEAM_ADMIN)).rejects.toThrow(
      /not currently readable/,
    );
    await expect(pins.pin({ kind: "memory", ref: archived.id }, TEAM_ADMIN)).rejects.toThrow(
      /not currently readable/,
    );

    await pins.pin({ kind: "memory", ref: erasedLater.id }, TEAM_ADMIN);
    await db.query("DELETE FROM memory_objects WHERE id = $1", [erasedLater.id]);
    const resolved = await pins.resolve(TEAM_ADMIN.namespace);
    expect(resolved).toEqual({ pins: [], rejected: 1 });
  });

  it("resolves a logical concept pin to its current immutable version", async () => {
    const logical = await logicalConcept();
    const created = await pins.pin({ kind: "concept", ref: logical.conceptId }, TEAM_ADMIN);
    expect(created.pin.target).toEqual({ kind: "concept", ref: logical.conceptId });
    let resolved = await pins.resolve(TEAM_ADMIN.namespace);
    expect(resolved.pins[0]).toMatchObject({
      kind: "concept",
      ref: logical.conceptId,
      versionPath: logical.path,
    });

    const version2 = ulid();
    const path2 = `concepts/${version2}.okf.enc`;
    const now = new Date().toISOString();
    await db.query(
      `INSERT INTO knowledge_versions
         (id, concept_id, path, version, supersedes_version_id, content_hash,
          proposal_id, state, published_at, created_at)
       VALUES ($1, $2, $3, 2, $4, $5, NULL, 'published', $6, $6)`,
      [version2, logical.conceptId, path2, logical.versionId, `hash-${version2}`, now],
    );
    await db.query("UPDATE knowledge_concepts SET current_version_id = $2 WHERE id = $1", [
      logical.conceptId,
      version2,
    ]);
    cold.concepts.set(path2, {
      path: path2,
      type: "policy",
      title: "Refund escalation",
      description: "",
      tags: [],
      namespace: TEAM_ADMIN.namespace,
      body: "Escalate refund requests above $250.",
    });
    resolved = await pins.resolve(TEAM_ADMIN.namespace);
    expect(resolved.pins[0]).toMatchObject({ versionPath: path2 });
    expect(resolved.pins[0].content).toContain("$250");
  });

  it("rolls pin and unpin mutations back when their success audit cannot commit", async () => {
    const target = memory();
    await index.insert(target, null);
    const failingAudit = {
      append: (event: AuditEvent) => audit.append(event),
      async appendTo(): Promise<void> {
        throw new Error("injected audit failure");
      },
    };
    const service = new PinService(db, failingAudit, cold);
    await expect(service.pin({ kind: "memory", ref: target.id }, TEAM_ADMIN)).rejects.toThrow(
      /injected audit failure/,
    );
    expect(Number((await db.query("SELECT count(*) AS n FROM memory_pins")).rows[0].n)).toBe(0);

    const created = await pins.pin({ kind: "memory", ref: target.id }, TEAM_ADMIN);
    await expect(service.unpin(created.pin.id, TEAM_ADMIN)).rejects.toThrow(
      /injected audit failure/,
    );
    const persisted = await db.query("SELECT released_at FROM memory_pins WHERE id = $1", [
      created.pin.id,
    ]);
    expect(persisted.rows[0].released_at).toBeNull();
  });
});

describe("ContextAllocator governed pin lane", () => {
  it("packs pinned L2 and current logical L3 before ordinary lanes and skips stale pins", async () => {
    const pinnedMemory = memory({ content: "Pinned customer promise." });
    const staleMemory = memory({ content: "A pin that will be erased." });
    const ordinary = memory({ content: "Ordinary recently used memory." });
    await index.insert(pinnedMemory, null);
    await index.insert(staleMemory, null);
    await index.insert(ordinary, null);
    await index.bumpAccess([ordinary.id]);
    const logical = await logicalConcept();
    await pins.pin({ kind: "memory", ref: pinnedMemory.id }, TEAM_ADMIN);
    await pins.pin({ kind: "concept", ref: logical.conceptId }, TEAM_ADMIN);
    await pins.pin({ kind: "memory", ref: staleMemory.id }, TEAM_ADMIN);

    // Simulate erasure after pin creation: resolver counts and skips it.
    await db.query("DELETE FROM memory_objects WHERE id = $1", [staleMemory.id]);

    const allocator = new ContextAllocator({
      index,
      cold,
      audit,
      embedder: new HashEmbedder(DIM),
      pins,
    });
    const policy: PolicyConfig = {
      namespace: TEAM_ADMIN.namespace,
      tokenBudget: 1000,
      ttlDefaultsSeconds: { user: null, assistant: null, team: null, org: null },
      pinnedConcepts: [],
      dedupeSimilarityThreshold: 0.92,
      verifierEnabled: true,
    };
    const assembled = await allocator.assemble({
      namespace: TEAM_ADMIN.namespace,
      actor: TEAM_ADMIN.actor,
      agentId: "agent-1",
      policy,
    });
    expect(assembled.blocks.slice(0, 2).map((block) => block.kind).sort()).toEqual([
      "pinned-concept",
      "pinned-memory",
    ]);
    expect(new Set(assembled.blocks.slice(0, 2).map((block) => block.ref))).toEqual(
      new Set([logical.conceptId, pinnedMemory.id]),
    );
    expect(assembled.blocks[2].kind).toBe("scope-memory");
    expect((await audit.list(TEAM_ADMIN.namespace))[0].detail).toContain("rejectedPins=1");
  });
});
