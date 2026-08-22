import { describe, expect, it, vi } from "vitest";
import type { Db } from "../src/db/client.js";
import type { WarmMirrorRecord } from "../src/types.js";
import {
  Mem0WarmStore,
  SupermemoryWarmStore,
  WarmStoreManager,
  WarmStoreRegistry,
} from "../src/warmstore/index.js";

const record: WarmMirrorRecord = {
  id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", namespace: "acme/ops", scope: "team",
  type: "fact", content: "approved", tValidFrom: "2026-01-01T00:00:00.000Z",
};

describe("M7 governed warm reads and concrete adapters", () => {
  it.each([
    [Mem0WarmStore, "mem0"],
    [SupermemoryWarmStore, "supermemory"],
  ])("maps %s to halomem-warmstore/v1 including get", async (Adapter, name) => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { ids?: string[] };
      return new Response(JSON.stringify(body.ids ? { records: [record] } : { ok: true }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const adapter = new Adapter({ url: "http://127.0.0.1:8790", fetchImpl });

    await expect(adapter.get([record.id])).resolves.toEqual([record]);
    expect(adapter.name).toBe(name);
    expect(fetchImpl).toHaveBeenCalledWith("http://127.0.0.1:8790/v1/memories/get", expect.objectContaining({ method: "POST" }));
  });

  it("requires HTTPS and authentication for a remote warm store", async () => {
    expect(() => new SupermemoryWarmStore({ url: "http://memory.example.com" }))
      .toThrow(/HTTPS/);
    expect(() => new SupermemoryWarmStore({ url: "https://memory.example.com" }))
      .toThrow(/authentication token/);

    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ records: [record] }), {
      status: 200, headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
    const adapter = new SupermemoryWarmStore({
      url: "https://memory.example.com",
      authToken: "test-warm-token",
      fetchImpl,
    });

    await expect(adapter.get([record.id])).resolves.toEqual([record]);
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://memory.example.com/v1/memories/get",
      expect.objectContaining({
        redirect: "error",
        headers: expect.objectContaining({ authorization: "Bearer test-warm-token" }),
      }),
    );
  });

  it("returns canonical content only after version, namespace, and policy revalidation", async () => {
    const registry = new WarmStoreRegistry();
    const removed: string[] = [];
    registry.mount({
      name: "mirror", external: true, capabilities: () => ({ rebuildable: true }),
      upsert: async () => undefined, remove: async (ids) => { removed.push(...ids); },
      removeNamespace: async () => undefined, health: async () => ({ ok: true }),
      get: async () => [{ ...record, content: "poisoned mirror value" }, { ...record, id: "alien" }],
    });
    const db = {
      query: async () => ({ rows: [{
        id: record.id, namespace: record.namespace, scope: record.scope, type: record.type,
        content: record.content, t_valid_from: record.tValidFrom,
      }] }),
    } as unknown as Db;
    const manager = new WarmStoreManager({ db, registry, logger: { warn: () => undefined } as never });

    await expect(manager.governedGet("mirror", [record.id], {
      authorize: (candidate) => candidate.namespace === "acme/ops",
    })).resolves.toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(removed).toEqual([record.id]);
    expect(removed).not.toContain("alien");
  });

  it("returns canonical policy metadata and fails closed for an unapproved restricted mirror", async () => {
    const registry = new WarmStoreRegistry();
    const removed: string[] = [];
    registry.mount({
      name: "mem0", external: true, capabilities: () => ({ rebuildable: true }),
      upsert: async () => undefined, remove: async (ids) => { removed.push(...ids); },
      removeNamespace: async () => undefined, health: async () => ({ ok: true }),
      get: async () => [record],
    });
    const db = {
      query: async () => ({ rows: [{
        id: record.id, namespace: record.namespace, scope: record.scope, type: record.type,
        content: record.content, t_valid_from: record.tValidFrom,
        classification: {
          sensitivity: "restricted", piiSubjects: ["customer-1"], secretKinds: [],
          allowedDestinations: ["canonical-l2"],
        },
        source_access: { principals: ["user-1"], groups: [] },
      }] }),
    } as unknown as Db;
    const manager = new WarmStoreManager({ db, registry, logger: { warn: () => undefined } as never });
    let authorizeCalled = false;

    await expect(manager.governedGet("mem0", [record.id], {
      authorize: (candidate) => {
        authorizeCalled = true;
        return candidate.classification.sensitivity === "restricted" &&
          candidate.sourceAccess.principals.includes("user-1");
      },
    })).resolves.toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(authorizeCalled).toBe(false);
    expect(removed).toEqual([record.id]);
  });

  it("does not mirror confidential PII without explicit destination approval", async () => {
    const delivered: WarmMirrorRecord[][] = [];
    const registry = new WarmStoreRegistry();
    registry.mount({
      name: "supermemory", external: true, capabilities: () => ({ rebuildable: true }),
      upsert: async (records) => { delivered.push(records); }, remove: async () => undefined,
      removeNamespace: async () => undefined, health: async () => ({ ok: true }),
    });
    const db = {
      query: async (sql: string) => {
        if (sql.includes("INSERT INTO warm_store_leases")) {
          return { rows: [{ store: "supermemory" }] };
        }
        if (sql.includes("SELECT id, namespace FROM memory_objects")) {
          return { rows: [{ id: record.id, namespace: record.namespace }] };
        }
        if (sql.includes("SELECT id, namespace, scope, type, content")) {
          return { rows: [{
            id: record.id, namespace: record.namespace, scope: record.scope, type: record.type,
            content: "legal@example.com", t_valid_from: record.tValidFrom,
            classification: {
              sensitivity: "confidential", piiSubjects: ["email"], secretKinds: [],
              allowedDestinations: ["canonical-l2"],
            },
          }] };
        }
        return { rows: [] };
      },
    } as unknown as Db;
    const manager = new WarmStoreManager({ db, registry, logger: { warn: () => undefined } as never });

    await expect(manager.rebuild("supermemory", "acme")).resolves.toMatchObject({ records: 0 });

    expect(delivered).toEqual([]);
  });
});
