/**
 * R6 (halomem-warmstore/v1) tests — governed external warm-memory mirrors.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, an in-memory
 * RecordingWarmStore, injected fetch for the HTTP driver. Zero network.
 *
 * Proves the contract (CONTRACTS-WARMSTORE.md):
 *   - write-through: a committed L2 write lands in mounted external stores
 *   - erasure propagation: mem.forget purges the mirror and reports the
 *     per-store outcome on ForgetResult.warmPurges
 *   - brownout: a mirror failure never fails the syscall; the op stays in the
 *     durable warm_mirror_ops outbox and flush repairs it later
 *   - no resurrection: an id erased after a queued upsert never reappears in
 *     the mirror (purge priority + canonical re-read at send time)
 *   - rebuild: an external cache wiped to nothing is reconstructed from
 *     canonical rows, subtree-scoped
 *   - root-owner gate on the admin surface
 *   - namespace mirror scoping (HALOMEM_WARMSTORE_NAMESPACES semantics)
 *   - HttpWarmStore sidecar protocol + retry/failure model
 *   - PostgresWarmStore canonical lane no-ops + health
 */

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";
import type { MemWriteResult } from "../src/syscalls/index.js";
import {
  HttpWarmStore,
  PostgresWarmStore,
  WarmStoreManager,
  WarmStoreRegistry,
  WarmStoreUnavailableError,
} from "../src/warmstore/index.js";
import type {
  Identity,
  MemoryId,
  Namespace,
  Role,
  WarmMirrorRecord,
  WarmStoreDriver,
  WarmStoreHealth,
  WriteResult,
} from "../src/types.js";

const AGENT = "warmstore-test";

/** In-memory external mirror with injectable failure. */
class RecordingWarmStore implements WarmStoreDriver {
  readonly external = true;
  failing = false;
  readonly records = new Map<string, WarmMirrorRecord>();
  readonly removedNamespaces: string[] = [];
  /** Per-call batch sizes, for asserting the MIRROR_BATCH delivery cap. */
  readonly upsertCallSizes: number[] = [];
  readonly removeCallSizes: number[] = [];

  constructor(readonly name: string = "fake-external") {}

  capabilities(): { rebuildable: boolean } {
    return { rebuildable: true };
  }

  private gate(): void {
    if (this.failing) {
      throw new WarmStoreUnavailableError(this.name, "injected failure");
    }
  }

  async upsert(records: WarmMirrorRecord[]): Promise<void> {
    this.gate();
    this.upsertCallSizes.push(records.length);
    for (const r of records) this.records.set(r.id, r);
  }

  async remove(ids: MemoryId[]): Promise<void> {
    this.gate();
    this.removeCallSizes.push(ids.length);
    for (const id of ids) this.records.delete(id);
  }

  async removeNamespace(namespace: Namespace): Promise<void> {
    this.gate();
    this.removedNamespaces.push(namespace);
    for (const [id, r] of [...this.records]) {
      if (r.namespace === namespace || r.namespace.startsWith(`${namespace}/`)) {
        this.records.delete(id);
      }
    }
  }

  async health(): Promise<WarmStoreHealth> {
    return this.failing ? { ok: false, detail: "injected failure" } : { ok: true };
  }
}

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async write ticket");
  return result;
}

describe("warm-store mirrors (full kernel)", () => {
  let kernel: Kernel;
  let knowledgeDir: string;
  let root: Identity;
  let tenantOwner: Identity;
  let store: RecordingWarmStore;

  async function issueIdentity(
    namespace: string,
    actor: string,
    role: Role,
    caller?: Identity,
  ): Promise<Identity> {
    const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, caller ?? null);
    const identity = await kernel.auth.resolve(plaintext);
    if (!identity) throw new Error("issued key failed to resolve");
    return identity;
  }

  async function pendingCount(storeName: string): Promise<number> {
    const res = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM warm_mirror_ops WHERE store = $1`,
      [storeName],
    );
    return Number((res.rows[0] as Record<string, unknown>).n);
  }

  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-warmstore-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    store = new RecordingWarmStore();
    kernel.warm.registry.mount(store);

    root = await issueIdentity("", "platform-owner", "owner");
    tenantOwner = await issueIdentity("acme", "owner@acme.test", "owner", root);
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("write-through: a committed write lands in the external mirror", async () => {
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Acme refund window is 30 days.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    const mirrored = store.records.get(id);
    expect(mirrored).toBeDefined();
    expect(mirrored!.namespace).toBe("acme");
    expect(mirrored!.content).toContain("refund window is 30 days");
    expect(await pendingCount(store.name)).toBe(0);
  });

  it("disconnecting a backend invalidates every derived mirror record", async () => {
    const corpus = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-warm-disconnect-"));
    try {
      await fs.writeFile(
        path.join(corpus, "backend.txt"),
        "Disconnected backend knowledge must leave every retrieval layer.\n",
        "utf8",
      );
      const source = await kernel.sources.register("acme", "filesystem", { path: corpus });
      expect((await kernel.syncSource(source.id, tenantOwner)).stored).toBe(1);

      const attributable = JSON.stringify([{ sourceId: source.id }]);
      const current = await kernel.db.query(
        `SELECT id FROM memory_objects
          WHERE namespace = 'acme' AND status = 'active' AND t_valid_to IS NULL
            AND provenance @> $1::jsonb`,
        [attributable],
      );
      const ids = current.rows.map((row) => String(row.id));
      expect(ids.length).toBeGreaterThanOrEqual(1);
      expect(ids.every((id) => store.records.has(id))).toBe(true);

      await kernel.pauseSource(source.id, tenantOwner);

      expect(ids.every((id) => !store.records.has(id))).toBe(true);
      expect(await pendingCount(store.name)).toBe(0);
    } finally {
      await fs.rm(corpus, { recursive: true, force: true });
    }
  });

  it("mem.forget purges the mirror and reports warmPurges on the result", async () => {
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Erase-me: contractor badge code 9911.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    expect(store.records.has(id)).toBe(true);

    const result = await kernel.memForget(
      { target: { kind: "memory", value: id } },
      tenantOwner,
      AGENT,
    );
    expect(result.erasedCount).toBe(1);
    expect(result.warmPurges).toEqual([{ store: store.name, status: "purged" }]);
    expect(store.records.has(id)).toBe(false);
    expect(await pendingCount(store.name)).toBe(0);
  });

  it("brownout: a mirror failure never fails the write; flush repairs from canonical", async () => {
    store.failing = true;
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Queued while mirror is down.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    expect(store.records.has(id)).toBe(false);
    expect(await pendingCount(store.name)).toBeGreaterThan(0);

    const status = await kernel.warmStatus(root);
    const mine = status.find((s) => s.name === store.name)!;
    expect(mine.healthy).toBe(false);
    expect(mine.pendingOps).toBeGreaterThan(0);

    store.failing = false;
    const remaining = await kernel.warmFlush(root);
    expect(remaining[store.name]).toBe(0);
    // Flush re-read the CANONICAL row — content, not just the id, arrived.
    expect(store.records.get(id)?.content).toContain("Queued while mirror is down");
  });

  it("a forget while the mirror is down reports pending, and the queued purge wins over the queued upsert", async () => {
    store.failing = true;
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Write then erase while mirror is down.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;

    const result = await kernel.memForget(
      { target: { kind: "memory", value: id } },
      tenantOwner,
      AGENT,
    );
    expect(result.warmPurges).toEqual([
      { store: store.name, status: "pending", error: expect.stringContaining("injected") },
    ]);

    // F1 regression: the purge op was enqueued INSIDE the erasure transaction
    // — it is durably queued even though delivery failed.
    const purgeRows = await kernel.db.query(
      `SELECT op FROM warm_mirror_ops WHERE store = $1 AND ref = $2`,
      [store.name, id],
    );
    expect(purgeRows.rows.some((r) => String((r as Record<string, unknown>).op) === "purge")).toBe(true);

    // F12 regression: the wedged queue is visible in status.
    const status = await kernel.warmStatus(root);
    const mine = status.find((s) => s.name === store.name)!;
    expect(mine.maxAttempts).toBeGreaterThan(0);
    expect(mine.lastError).toContain("injected");

    store.failing = false;
    const remaining = await kernel.warmFlush(root);
    expect(remaining[store.name]).toBe(0);
    // Purge ran before the stale upsert; the upsert re-read canonical, found
    // the row erased, and removed rather than resurrected it.
    expect(store.records.has(id)).toBe(false);
  });

  it("re-running a forget drains still-pending purges (the repair lane)", async () => {
    store.failing = true;
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Repair-lane fact.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    const first = await kernel.memForget(
      { target: { kind: "memory", value: id } },
      tenantOwner,
      AGENT,
    );
    expect(first.warmPurges?.[0]?.status).toBe("pending");

    // Mirror heals; the SAME forget re-runs. It erases 0 rows (already gone
    // canonically) but must still drain the pending purge and report purged.
    store.failing = false;
    const second = await kernel.memForget(
      { target: { kind: "memory", value: id } },
      tenantOwner,
      AGENT,
    );
    expect(second.erasedCount).toBe(0);
    expect(second.warmPurges).toEqual([{ store: store.name, status: "purged" }]);
    expect(store.records.has(id)).toBe(false);
    expect(await pendingCount(store.name)).toBe(0);
  });

  it("rebuild leaves queued ops for other namespaces intact", async () => {
    store.failing = true;
    const written = sync(
      await kernel.memWrite(
        { scope: "team", content: "Queued in acme while a sibling rebuild runs.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const id = written.stored[0]!.id;
    expect(await pendingCount(store.name)).toBeGreaterThan(0);

    // Heal the store, rebuild an UNRELATED subtree — the queued acme op must
    // survive (F2 regression: rebuild used to wipe the store's whole outbox).
    store.failing = false;
    await kernel.warmRebuild(store.name, "other", root);
    const stillQueued = await kernel.db.query(
      `SELECT id FROM warm_mirror_ops WHERE store = $1 AND ref = $2`,
      [store.name, id],
    );
    expect(stillQueued.rows.length).toBe(1);

    const remaining = await kernel.warmFlush(root);
    expect(remaining[store.name]).toBe(0);
    expect(store.records.get(id)?.content).toContain("Queued in acme");
  });

  it("flush delivers in capped batches so a large backlog stays drainable", async () => {
    // 450 synthetic upsert ops for ids with no canonical row: flush re-reads
    // canonical, finds them gone, and issues remove() calls — each capped.
    const now = new Date().toISOString();
    for (let i = 0; i < 450; i++) {
      await kernel.db.query(
        `INSERT INTO warm_mirror_ops (id, store, op, ref, namespace, created_at)
         VALUES ($1, $2, 'upsert', $3, 'acme', $4)`,
        [`00BATCH${String(i).padStart(19, "0")}`, store.name, `no-such-id-${i}`, now],
      );
    }
    store.removeCallSizes.length = 0;
    const remaining = await kernel.warmFlush(root);
    expect(remaining[store.name]).toBe(0);
    expect(store.removeCallSizes.length).toBeGreaterThanOrEqual(3);
    for (const size of store.removeCallSizes) {
      expect(size).toBeLessThanOrEqual(200);
    }
  });

  it("rebuild reconstructs a wiped external cache from canonical rows, subtree-scoped", async () => {
    // Plant a row OUTSIDE the acme subtree to prove scoping.
    const other = await issueIdentity("other", "owner@other.test", "owner", root);
    const outside = sync(
      await kernel.memWrite(
        { scope: "team", content: "Other-tenant fact.", hints: { verbatim: true } },
        other,
        AGENT,
      ),
    );

    store.records.clear();
    const result = await kernel.warmRebuild(store.name, "acme", root);
    expect(result.records).toBeGreaterThan(0);
    expect(store.removedNamespaces).toContain("acme");
    for (const r of store.records.values()) {
      expect(r.namespace === "acme" || r.namespace.startsWith("acme/")).toBe(true);
    }
    expect(store.records.has(outside.stored[0]!.id)).toBe(false);
  });

  it("rebuilding the canonical postgres lane is rejected", async () => {
    await expect(kernel.warmRebuild("postgres", "acme", root)).rejects.toThrow(
      /canonical/,
    );
  });

  it("the admin surface is root-owner only", async () => {
    await expect(kernel.warmStatus(tenantOwner)).rejects.toThrow(/root owner/);
    await expect(kernel.warmFlush(tenantOwner)).rejects.toThrow(/root owner/);
    await expect(kernel.warmRebuild(store.name, "acme", tenantOwner)).rejects.toThrow(
      /root owner/,
    );
  });

  it("namespace mirror scoping: only configured subtrees fan out", async () => {
    const scopedStore = new RecordingWarmStore("scoped-external");
    const registry = new WarmStoreRegistry();
    registry.mount(scopedStore);
    const manager = new WarmStoreManager({
      db: kernel.db,
      registry,
      logger: kernel.logger,
      namespaceRoots: ["acme"],
    });

    const inScope = sync(
      await kernel.memWrite(
        { scope: "team", content: "Scoped mirror: acme keeps this.", hints: { verbatim: true } },
        tenantOwner,
        AGENT,
      ),
    );
    const other = await kernel.auth.resolve(
      (await kernel.auth.issueKey("other", "agent@other.test", "agent", root)).plaintext,
    );
    const outOfScope = sync(
      await kernel.memWrite(
        { scope: "team", content: "Scoped mirror: other is filtered.", hints: { verbatim: true } },
        other!,
        AGENT,
      ),
    );

    await manager.afterWrite(inScope);
    await manager.afterWrite(outOfScope);
    expect(scopedStore.records.has(inScope.stored[0]!.id)).toBe(true);
    expect(scopedStore.records.has(outOfScope.stored[0]!.id)).toBe(false);

    // F6 regression: rebuild must not become an export lane for subtrees
    // configured to stay off-box.
    await expect(manager.rebuild(scopedStore.name, "other")).rejects.toThrow(
      /outside the configured mirror scope/,
    );
    // No wipe happened either — the scope check precedes removeNamespace.
    expect(scopedStore.removedNamespaces).not.toContain("other");
  });

  it("supersedence enqueues an invalidate that removes the stale mirror copy", async () => {
    const staleId = "01STALEWARMSTOREID0000000000";
    store.records.set(staleId, {
      id: staleId,
      namespace: "acme",
      scope: "team",
      type: "fact",
      content: "stale superseded copy",
      tValidFrom: "2026-01-01T00:00:00.000Z",
    });
    await kernel.warm.afterWrite({
      stored: [],
      rejected: [],
      superseded: [staleId],
      deduplicated: 0,
    });
    expect(store.records.has(staleId)).toBe(false);
  });
});

describe("HttpWarmStore (sidecar protocol, injected fetch)", () => {
  interface Call {
    url: string;
    method: string;
    body: unknown;
  }

  function fakeFetch(
    handler: (call: Call) => { status: number; body?: unknown },
  ): { fetchImpl: typeof fetch; calls: Call[] } {
    const calls: Call[] = [];
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const call: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      };
      calls.push(call);
      const out = handler(call);
      return {
        ok: out.status >= 200 && out.status < 300,
        status: out.status,
        json: async () => out.body ?? {},
      } as Response;
    }) as typeof fetch;
    return { fetchImpl, calls };
  }

  const record: WarmMirrorRecord = {
    id: "01HTTPWARMSTORE0000000000000",
    namespace: "acme/team",
    scope: "team",
    type: "fact",
    content: "http mirror record",
    tValidFrom: "2026-01-01T00:00:00.000Z",
  };

  it("speaks the sidecar protocol", async () => {
    const { fetchImpl, calls } = fakeFetch(() => ({ status: 200, body: { ok: true } }));
    const store = new HttpWarmStore({ name: "mem0", url: "http://localhost:9999/", fetchImpl });

    await store.upsert([record]);
    await store.remove([record.id]);
    await store.removeNamespace("acme");
    const health = await store.health();

    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST http://localhost:9999/v1/memories",
      "POST http://localhost:9999/v1/memories/remove",
      "POST http://localhost:9999/v1/namespaces/remove",
      "GET http://localhost:9999/healthz",
    ]);
    expect(calls[0]!.body).toEqual({ records: [record] });
    expect(calls[1]!.body).toEqual({ ids: [record.id] });
    expect(calls[2]!.body).toEqual({ namespace: "acme" });
    expect(health).toEqual({ ok: true });
  });

  it("retries once, then throws WarmStoreUnavailableError", async () => {
    const { fetchImpl, calls } = fakeFetch(() => ({ status: 503 }));
    const store = new HttpWarmStore({ name: "mem0", url: "http://localhost:9999", fetchImpl });
    await expect(store.upsert([record])).rejects.toThrow(WarmStoreUnavailableError);
    expect(calls.length).toBe(2); // one retry = 2 attempts
  });

  it("health degrades instead of throwing", async () => {
    const { fetchImpl } = fakeFetch(() => ({ status: 500 }));
    const store = new HttpWarmStore({ name: "mem0", url: "http://localhost:9999", fetchImpl });
    const health = await store.health();
    expect(health.ok).toBe(false);
  });

  it("empty batches never touch the wire", async () => {
    const { fetchImpl, calls } = fakeFetch(() => ({ status: 200 }));
    const store = new HttpWarmStore({ name: "mem0", url: "http://localhost:9999", fetchImpl });
    await store.upsert([]);
    await store.remove([]);
    expect(calls.length).toBe(0);
  });

  it("requires a URL at construction", () => {
    expect(() => new HttpWarmStore({ name: "mem0", url: "" })).toThrow(
      WarmStoreUnavailableError,
    );
  });
});

describe("PostgresWarmStore (canonical lane)", () => {
  it("is mounted by default, reports healthy, and mirror ops are no-ops", async () => {
    const knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-warmpg-"));
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const pg = kernel.warm.registry.get("postgres");
      expect(pg).toBeInstanceOf(PostgresWarmStore);
      expect(pg.external).toBe(false);
      await pg.upsert([]);
      await pg.remove(["nonexistent"]);
      await pg.removeNamespace("acme");
      expect(await pg.health()).toEqual({ ok: true });
      // The canonical lane is never a fan-out target.
      expect(kernel.warm.registry.externals().map((s) => s.name)).toEqual([]);
    } finally {
      await kernel.close();
      await fs.rm(knowledgeDir, { recursive: true, force: true });
    }
  }, 120_000);
});
