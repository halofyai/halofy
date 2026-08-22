/**
 * Module C tests — connector framework + credential-free connectors.
 *
 * Hermetic: an in-memory Map-backed SourceState, a fake IngestSink that records
 * the IngestRecords it was handed, real tmp dirs on disk (node:fs) for the
 * filesystem connector, and an injected `config.query` stub returning a fake
 * information_schema for the postgres connector. Zero network, zero real
 * Postgres, no `pg` client opened.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  IngestRecord,
  IngestSink,
  Namespace,
  SourceKind,
  SourceState,
  WriteResult,
} from "../src/types.js";
import { sha256hex, syncWithDrift } from "../src/ingest/connectors/framework.js";
import {
  FilesystemConnector,
  PostgresConnector,
  CONNECTORS,
} from "../src/ingest/connectors/index.js";

// ---------------------------------------------------------------------------
// Hermetic doubles
// ---------------------------------------------------------------------------

/** Map-backed SourceState — the connector's whole drift surface. */
class MemSourceState implements SourceState {
  private readonly hashes = new Map<string, string>();

  async priorHash(docId: string): Promise<string | null> {
    return this.hashes.get(docId) ?? null;
  }
  async record(docId: string, contentHash: string): Promise<void> {
    this.hashes.set(docId, contentHash);
  }
  async knownDocIds(): Promise<string[]> {
    return [...this.hashes.keys()];
  }
  async forget(docIds: string[]): Promise<void> {
    for (const id of docIds) this.hashes.delete(id);
  }
}

/** Fake sink — the connector's whole write surface. Records every write. */
class FakeSink implements IngestSink {
  readonly writes: IngestRecord[] = [];

  constructor(
    readonly namespace: Namespace = "org",
    readonly sourceId: string = "src:test",
    readonly sourceKind: SourceKind = "filesystem",
  ) {}

  async write(record: IngestRecord): Promise<WriteResult> {
    this.writes.push(record);
    return { stored: [], rejected: [], superseded: [], deduplicated: 0 };
  }
}

// ---------------------------------------------------------------------------
// Filesystem connector
// ---------------------------------------------------------------------------

describe("FilesystemConnector via syncWithDrift", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "halomem-fs-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const connector = new FilesystemConnector();

  function ctx(sink: FakeSink, state: SourceState) {
    return { sink, state, config: { path: dir } };
  }

  it("is registered, offline-available, and kind 'filesystem'", () => {
    expect(connector.kind).toBe("filesystem");
    expect(connector.available()).toBe(true);
    expect(CONNECTORS.filesystem).toBeInstanceOf(FilesystemConnector);
  });

  it("syncs new files, skips unchanged, detects edits and deletions (content-hash drift)", async () => {
    writeFileSync(join(dir, "a.md"), "# Alpha\n\nThe alpha fact.");
    writeFileSync(join(dir, "b.txt"), "The beta fact.");
    // nested, still matched recursively
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "sub", "c.md"), "The gamma fact.");
    // a non-matching extension is ignored
    writeFileSync(join(dir, "ignore.json"), '{"x":1}');

    const state = new MemSourceState();

    // First sync: 3 matching files → 3 changed, 0 unchanged.
    const sink1 = new FakeSink();
    const r1 = await connector.sync(ctx(sink1, state));
    expect(r1.scanned).toBe(3);
    expect(r1.changed).toBe(3);
    expect(r1.unchanged).toBe(0);
    expect(r1.removed).toEqual([]);
    expect(sink1.writes).toHaveLength(3);
    // Every filesystem doc is a raw document (extractor runs) landing at org.
    for (const w of sink1.writes) {
      expect(w.verbatim).toBe(false);
      expect(w.scope).toBe("org");
    }
    // docIds are POSIX-relative paths.
    expect(sink1.writes.map((w) => w.docId).sort()).toEqual([
      "a.md",
      "b.txt",
      "sub/c.md",
    ]);

    // Re-sync with no changes → 0 changed, 3 unchanged, nothing written.
    const sink2 = new FakeSink();
    const r2 = await connector.sync(ctx(sink2, state));
    expect(r2.changed).toBe(0);
    expect(r2.unchanged).toBe(3);
    expect(r2.removed).toEqual([]);
    expect(sink2.writes).toHaveLength(0);

    // Edit one file → 1 changed, 2 unchanged.
    writeFileSync(join(dir, "a.md"), "# Alpha\n\nThe alpha fact, revised.");
    const sink3 = new FakeSink();
    const r3 = await connector.sync(ctx(sink3, state));
    expect(r3.changed).toBe(1);
    expect(r3.unchanged).toBe(2);
    expect(sink3.writes).toHaveLength(1);
    expect(sink3.writes[0]!.docId).toBe("a.md");
    expect(sink3.writes[0]!.content).toContain("revised");

    // Delete one file → reported in removed, tracking dropped.
    rmSync(join(dir, "b.txt"));
    const sink4 = new FakeSink();
    const r4 = await connector.sync(ctx(sink4, state));
    expect(r4.removed).toEqual(["b.txt"]);
    expect(r4.scanned).toBe(2);
    expect(await state.knownDocIds()).not.toContain("b.txt");
  });

  it("strips YAML frontmatter from the fact text (gray-matter)", async () => {
    writeFileSync(
      join(dir, "fm.md"),
      "---\ntitle: Handbook\nowner: ops\n---\nRefunds are processed within 30 days.",
    );
    const state = new MemSourceState();
    const sink = new FakeSink();
    await connector.sync(ctx(sink, state));

    expect(sink.writes).toHaveLength(1);
    const content = sink.writes[0]!.content;
    expect(content).toContain("Refunds are processed within 30 days.");
    expect(content).not.toContain("title:");
    expect(content).not.toContain("owner:");
  });

  it("rejects markdown whose YAML frontmatter exceeds the safe parsing limit", async () => {
    writeFileSync(
      join(dir, "oversized.md"),
      `---\ntitle: ${"x".repeat(70_000)}\n---\nbody`,
    );
    const state = new MemSourceState();
    const sink = new FakeSink();

    await expect(connector.sync(ctx(sink, state))).rejects.toThrow(/frontmatter.*65,?536/i);
    expect(sink.writes).toHaveLength(0);
  });

  it("respects a custom exts config", async () => {
    writeFileSync(join(dir, "note.rst"), "Restructured fact.");
    writeFileSync(join(dir, "skip.md"), "Markdown fact.");
    const state = new MemSourceState();
    const sink = new FakeSink();
    await connector.sync({ sink, state, config: { path: dir, exts: [".rst"] } });

    expect(sink.writes.map((w) => w.docId)).toEqual(["note.rst"]);
  });
});

// ---------------------------------------------------------------------------
// Postgres connector (injected config.query — no pg client)
// ---------------------------------------------------------------------------

describe("PostgresConnector via injected config.query", () => {
  const connector = new PostgresConnector();

  // Fake information_schema.columns for two tables.
  const fakeRows = [
    { table_name: "customers", column_name: "id", data_type: "uuid" },
    { table_name: "customers", column_name: "email", data_type: "text" },
    { table_name: "orders", column_name: "id", data_type: "uuid" },
    { table_name: "orders", column_name: "total", data_type: "numeric" },
    { table_name: "orders", column_name: "status", data_type: "text" },
  ];

  function queryStub() {
    const calls: { sql: string; params?: unknown[] }[] = [];
    const query = async (sql: string, params?: unknown[]) => {
      calls.push({ sql, params });
      return { rows: fakeRows };
    };
    return { query, calls };
  }

  it("is registered and available with a query surface, unavailable without one", () => {
    expect(connector.kind).toBe("postgres");
    expect(CONNECTORS.postgres).toBeInstanceOf(PostgresConnector);
    expect(connector.available({ query: () => {} })).toBe(true);
    expect(connector.available({ dsn: "postgres://x" })).toBe(true);
    expect(connector.available({})).toBe(false);
  });

  it("introspects the schema into one verbatim doc per table", async () => {
    const state = new MemSourceState();
    const sink = new FakeSink("org", "src:pg", "postgres");
    const { query, calls } = queryStub();

    const result = await connector.sync({ sink, state, config: { query } });

    // information_schema queried exactly once.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.sql).toContain("information_schema.columns");
    expect(calls[0]!.sql).toContain("table_schema = 'public'");

    // Two tables → two docs.
    expect(result.scanned).toBe(2);
    expect(result.changed).toBe(2);
    expect(result.unchanged).toBe(0);
    expect(sink.writes).toHaveLength(2);

    const byDocId = new Map(sink.writes.map((w) => [w.docId, w]));
    const customers = byDocId.get("table:customers")!;
    const orders = byDocId.get("table:orders")!;
    expect(customers).toBeDefined();
    expect(orders).toBeDefined();

    // Structured facts: verbatim (no re-extraction), org scope.
    for (const w of sink.writes) {
      expect(w.verbatim).toBe(true);
      expect(w.scope).toBe("org");
    }
    expect(customers.content).toBe(
      "Table customers has columns: id (uuid), email (text).",
    );
    expect(orders.content).toBe(
      "Table orders has columns: id (uuid), total (numeric), status (text).",
    );
  });

  it("skips unchanged tables on re-sync (drift by content hash)", async () => {
    const state = new MemSourceState();
    const { query } = queryStub();

    const sink1 = new FakeSink("org", "src:pg", "postgres");
    const r1 = await connector.sync({ sink: sink1, state, config: { query } });
    expect(r1.changed).toBe(2);

    // Same schema → both hashes match → zero writes.
    const sink2 = new FakeSink("org", "src:pg", "postgres");
    const r2 = await connector.sync({ sink: sink2, state, config: { query } });
    expect(r2.changed).toBe(0);
    expect(r2.unchanged).toBe(2);
    expect(sink2.writes).toHaveLength(0);

    // Sanity: the stored hash matches the rebuilt sentence.
    const expected = sha256hex("Table customers has columns: id (uuid), email (text).");
    expect(await state.priorHash("table:customers")).toBe(expected);
  });

  it("rejects a config with neither query nor dsn", async () => {
    const state = new MemSourceState();
    const sink = new FakeSink("org", "src:pg", "postgres");
    await expect(
      connector.sync({ sink, state, config: {} }),
    ).rejects.toThrow(/config\.query or config\.dsn/);
  });

  // Regression (finding 7): the credential-free postgres path wires the
  // kernel's OWN Db.query into config.query, pointing this connector at the
  // SAME database that holds the control plane. Introspecting it must NOT ingest
  // HaloMem's internal tables (api_keys, audit_log, cost_ledger, …) as facts.
  it("excludes HaloMem's own control-plane tables from introspection", async () => {
    const state = new MemSourceState();
    const sink = new FakeSink("acme", "src:selfpg", "postgres");
    // A schema that mixes a real customer table with kernel-internal tables —
    // exactly what `db.query` sees when the credential-free case points at the
    // kernel's own database.
    const rows = [
      { table_name: "invoices", column_name: "id", data_type: "uuid" },
      { table_name: "invoices", column_name: "amount", data_type: "numeric" },
      { table_name: "api_keys", column_name: "key_hash", data_type: "text" },
      { table_name: "audit_log", column_name: "actor", data_type: "text" },
      { table_name: "memory_objects", column_name: "content", data_type: "text" },
      { table_name: "cost_ledger", column_name: "usd", data_type: "numeric" },
      { table_name: "sources", column_name: "config", data_type: "jsonb" },
      { table_name: "schema_migrations", column_name: "version", data_type: "integer" },
    ];
    const query = async () => ({ rows });

    const result = await connector.sync({ sink, state, config: { query } });

    // Only the genuine customer table is ingested; every internal table skipped.
    expect(result.scanned).toBe(1);
    expect(sink.writes.map((w) => w.docId)).toEqual(["table:invoices"]);
    const internal = ["api_keys", "audit_log", "memory_objects", "cost_ledger", "sources", "schema_migrations"];
    for (const w of sink.writes) {
      for (const t of internal) {
        expect(w.content).not.toContain(`Table ${t} `);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// syncWithDrift — the drift engine's record-only-on-landed contract (finding 3)
// ---------------------------------------------------------------------------

describe("syncWithDrift record-on-landed", () => {
  /** A sink whose WriteResult is scripted per call — to simulate a reject. */
  class ScriptedSink implements IngestSink {
    readonly writes: IngestRecord[] = [];
    constructor(
      private readonly result: () => WriteResult,
      readonly namespace: Namespace = "org",
      readonly sourceId: string = "src:scripted",
      readonly sourceKind: SourceKind = "filesystem",
    ) {}
    async write(record: IngestRecord): Promise<WriteResult> {
      this.writes.push(record);
      return this.result();
    }
  }

  const oneDoc = async () => [
    { docId: "doc-1", content: "a genuinely-present source fact", verbatim: false, scope: "org" as const },
  ];

  // Regression (finding 3): a write that rejected everything (failed
  // verification) persisted NOTHING but did NOT throw. Its hash must NOT be
  // recorded, so the next sync re-attempts the doc — otherwise a never-landed
  // doc is marked 'synced' forever (silent, unrecoverable data loss).
  it("does NOT record the drift hash when the write rejected everything", async () => {
    const state = new MemSourceState();
    const rejectAll = (): WriteResult => ({
      stored: [],
      rejected: [{ candidate: "a genuinely-present source fact", reason: "failed-verification" }],
      superseded: [],
      deduplicated: 0,
    });

    const sink1 = new ScriptedSink(rejectAll);
    const r1 = await syncWithDrift({ sink: sink1, state, config: {} }, oneDoc);
    expect(r1.changed).toBe(1);
    expect(r1.rejected).toBe(1);
    expect(r1.stored).toBe(0);
    // Hash NOT recorded → the doc is still unknown to the drift state.
    expect(await state.priorHash("doc-1")).toBeNull();
    expect(await state.knownDocIds()).not.toContain("doc-1");

    // Identical re-sync: because the hash was never recorded, the doc is
    // re-attempted (sink.write called again), NOT silently skipped.
    const sink2 = new ScriptedSink(rejectAll);
    const r2 = await syncWithDrift({ sink: sink2, state, config: {} }, oneDoc);
    expect(r2.unchanged).toBe(0);
    expect(r2.changed).toBe(1);
    expect(sink2.writes).toHaveLength(1);
  });

  // Contrast: a write that landed a fact (or deduped / superseded — the fact IS
  // present) DOES record the hash, so the next sync skips it (drift works).
  it("records the drift hash when a fact genuinely landed", async () => {
    const state = new MemSourceState();
    const storeOne = (): WriteResult => ({
      stored: [{ id: "m1" } as unknown as WriteResult["stored"][number]],
      rejected: [],
      superseded: [],
      deduplicated: 0,
    });

    const sink1 = new ScriptedSink(storeOne);
    await syncWithDrift({ sink: sink1, state, config: {} }, oneDoc);
    expect(await state.priorHash("doc-1")).not.toBeNull();

    // A doc that only deduped (already present) is also 'landed' → recorded.
    const state2 = new MemSourceState();
    const dedupeOnly = (): WriteResult => ({
      stored: [],
      rejected: [],
      superseded: [],
      deduplicated: 1,
    });
    await syncWithDrift({ sink: new ScriptedSink(dedupeOnly), state: state2, config: {} }, oneDoc);
    expect(await state2.priorHash("doc-1")).not.toBeNull();

    // Re-sync of the landed doc skips it (drift).
    const sink2 = new ScriptedSink(storeOne);
    const r2 = await syncWithDrift({ sink: sink2, state, config: {} }, oneDoc);
    expect(r2.unchanged).toBe(1);
    expect(sink2.writes).toHaveLength(0);
  });
});
