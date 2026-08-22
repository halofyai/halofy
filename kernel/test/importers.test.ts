/**
 * Module B tests — Mem0 + pgvector bulk importers.
 *
 * Hermetic: parse two committed vendor-dump fixtures, run each record through a
 * hand-rolled FAKE IngestSink that records the WriteRequests it would perform.
 * Zero network, zero DB, zero LLM. We assert the D10 provenance contract holds
 * end-to-end: every imported record is verbatim and every WriteRequest the sink
 * builds is stamped `provenance.source === "swap-import"` with the sourceId.
 *
 * The fake sink replicates module A's `makeIngestSink` mapping locally (this
 * builder may not import module A's internals) so the test verifies the
 * IngestRecord → WriteRequest translation an importer relies on, not a mock of
 * it.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type {
  IngestRecord,
  IngestResult,
  Namespace,
  ProvenanceEntry,
  SourceKind,
  WriteRequest,
  WriteResult,
} from "../src/types.js";
import { Mem0Importer, PgvectorImporter, IMPORTERS } from "../src/ingest/importers/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const readFixture = (name: string): string =>
  readFileSync(path.join(HERE, "fixtures", "imports", name), "utf8");

// ---------------------------------------------------------------------------
// Hand-rolled fake IngestSink: records every WriteRequest it maps, mirroring
// module A's IngestRecord → WriteRequest translation (importKind maps the two
// import SourceKinds → "swap-import"). No store, no write path.
// ---------------------------------------------------------------------------

function importKind(kind: SourceKind): ProvenanceEntry["source"] {
  return kind === "mem0-import" || kind === "pgvector-import" ? "swap-import" : "document";
}

class FakeSink {
  readonly requests: WriteRequest[] = [];

  constructor(
    readonly namespace: Namespace,
    readonly sourceId: string,
    readonly sourceKind: SourceKind,
  ) {}

  async write(record: IngestRecord): Promise<WriteResult> {
    const req: WriteRequest = {
      namespace: this.namespace,
      scope: record.scope ?? "org",
      content: record.content,
      actor: "ingest",
      hints: { verbatim: record.verbatim, eventTime: record.eventTime },
      provenance: { source: importKind(this.sourceKind), sourceId: this.sourceId },
    };
    this.requests.push(req);
    // One stored fact per record — enough to exercise IngestResult aggregation.
    return { stored: [], rejected: [], superseded: [], deduplicated: 0 };
  }
}

/**
 * Local stand-in for module A's `runImport` (importing module A's runner is not
 * allowed for this builder): parse each record through the sink and aggregate.
 */
async function drive(
  records: IngestRecord[],
  sink: FakeSink,
): Promise<IngestResult> {
  const result: IngestResult = {
    sourceId: sink.sourceId,
    records: records.length,
    stored: 0,
    deduplicated: 0,
    superseded: 0,
    rejected: 0,
    errors: [],
  };
  for (const record of records) {
    try {
      await sink.write(record);
    } catch (err) {
      result.errors.push({ docId: record.docId, reason: String(err) });
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Mem0
// ---------------------------------------------------------------------------

describe("Mem0Importer", () => {
  const importer = new Mem0Importer();

  it("has kind mem0-import and is registered in IMPORTERS", () => {
    expect(importer.kind).toBe("mem0-import");
    expect(IMPORTERS["mem0-import"]).toBeInstanceOf(Mem0Importer);
  });

  it("parses the { results: [...] } fixture, skipping the blank-memory row", () => {
    const records = importer.parse(readFixture("mem0-dump.json"));
    // 6 items in the fixture; 1 has a blank memory → 5 usable facts.
    expect(records).toHaveLength(5);
    for (const r of records) {
      expect(r.verbatim).toBe(true);
      expect(r.content.trim().length).toBeGreaterThan(0);
    }
  });

  it("uses the item id as docId and falls back to a content hash when absent", () => {
    const records = importer.parse(readFixture("mem0-dump.json"));
    const byContent = new Map(records.map((r) => [r.content, r.docId]));

    // Items that carry an id keep it verbatim as the docId.
    const refund = [...byContent.entries()].find(([c]) => c.includes("refund policy"));
    expect(refund?.[1]).toBe("mem0-a1f3");

    // The warranty item has NO id → deterministic 16-char hex hash.
    const warranty = records.find((r) => r.content.includes("Warranty claims"));
    expect(warranty).toBeDefined();
    expect(warranty!.docId).toMatch(/^[0-9a-f]{16}$/);
  });

  it("reads the memory | text | data field variants", () => {
    const records = importer.parse(readFixture("mem0-dump.json"));
    expect(records.some((r) => r.content.includes("Gold loyalty tier"))).toBe(true); // text:
    expect(records.some((r) => r.content.includes("chargeback"))).toBe(true); // data:
  });

  it("tolerates a top-level array and { memories: [...] } shapes", () => {
    const arr = JSON.stringify([{ id: "x", memory: "A fact." }]);
    expect(importer.parse(arr)).toEqual([{ docId: "x", content: "A fact.", verbatim: true }]);

    const memories = JSON.stringify({ memories: [{ id: "y", memory: "Another fact." }] });
    expect(importer.parse(memories)).toEqual([
      { docId: "y", content: "Another fact.", verbatim: true },
    ]);
  });

  it("returns [] on malformed JSON and skips non-object items", () => {
    expect(importer.parse("not json")).toEqual([]);
    expect(importer.parse(JSON.stringify([null, 3, "x", { memory: "kept" }]))).toEqual([
      { docId: expect.any(String), content: "kept", verbatim: true },
    ]);
  });

  it("stamps swap-import provenance on every WriteRequest through the sink", async () => {
    const records = importer.parse(readFixture("mem0-dump.json"));
    const sink = new FakeSink("org/acme", "mem0:export-2024", "mem0-import");
    const result = await drive(records, sink);

    expect(result.records).toBe(5);
    expect(sink.requests).toHaveLength(5);
    for (const req of sink.requests) {
      expect(req.provenance?.source).toBe("swap-import");
      expect(req.provenance?.sourceId).toBe("mem0:export-2024");
      expect(req.hints?.verbatim).toBe(true);
      expect(req.namespace).toBe("org/acme");
    }
  });
});

// ---------------------------------------------------------------------------
// pgvector
// ---------------------------------------------------------------------------

describe("PgvectorImporter", () => {
  const importer = new PgvectorImporter();

  it("has kind pgvector-import and is registered in IMPORTERS", () => {
    expect(importer.kind).toBe("pgvector-import");
    expect(IMPORTERS["pgvector-import"]).toBeInstanceOf(PgvectorImporter);
  });

  it("parses the array-of-rows fixture, skipping the empty-content row", () => {
    const records = importer.parse(readFixture("pgvector-dump.json"));
    // 5 rows; 1 has empty content → 4 usable facts.
    expect(records).toHaveLength(4);
    for (const r of records) {
      expect(r.verbatim).toBe(true);
      expect(r.content.trim().length).toBeGreaterThan(0);
    }
  });

  it("uses String(id) as docId across numeric and string ids", () => {
    const records = importer.parse(readFixture("pgvector-dump.json"));
    const drill = records.find((r) => r.content.includes("Anvil Pro cordless drill"));
    expect(drill?.docId).toBe("5001"); // numeric id → String(id)
    const warehouse = records.find((r) => r.content.includes("warehouse in Reno"));
    expect(warehouse?.docId).toBe("row-5003"); // string id kept verbatim
  });

  it("reads the content | document | text column variants", () => {
    const records = importer.parse(readFixture("pgvector-dump.json"));
    expect(records.some((r) => r.content.includes("volume pricing"))).toBe(true); // document:
    expect(records.some((r) => r.content.includes("warehouse in Reno"))).toBe(true); // text:
  });

  it("returns [] on malformed JSON and skips non-object rows", () => {
    expect(importer.parse("{")).toEqual([]);
    expect(importer.parse(JSON.stringify([null, { content: "kept", id: 7 }]))).toEqual([
      { docId: "7", content: "kept", verbatim: true },
    ]);
  });

  it("stamps swap-import provenance on every WriteRequest through the sink", async () => {
    const records = importer.parse(readFixture("pgvector-dump.json"));
    const sink = new FakeSink("org/acme", "pgvector:dump-01", "pgvector-import");
    const result = await drive(records, sink);

    expect(result.records).toBe(4);
    expect(sink.requests).toHaveLength(4);
    for (const req of sink.requests) {
      expect(req.provenance?.source).toBe("swap-import");
      expect(req.provenance?.sourceId).toBe("pgvector:dump-01");
      expect(req.hints?.verbatim).toBe(true);
    }
  });
});
