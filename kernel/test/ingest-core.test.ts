/**
 * Module A tests — ingest core (sink + runner).
 *
 * Hermetic: a fake `writeRecord` that records every `WriteRequest` and returns
 * a scripted `WriteResult`. Zero network, zero db, no Identity — module A never
 * sees any of those (D10).
 */

import { describe, expect, it } from "vitest";
import type {
  IngestRecord,
  MemoryObject,
  WriteRequest,
  WriteResult,
} from "../src/types.js";
import {
  FORBIDDEN_INGEST_IMPORTS,
  INGEST_ACTOR,
  aggregate,
  importKind,
  makeIngestSink,
  runImport,
} from "../src/ingest/index.js";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/** A recording `writeRecord`: captures each WriteRequest, returns a scripted result. */
function recordingWrite(script?: (req: WriteRequest) => WriteResult) {
  const requests: WriteRequest[] = [];
  const fn = async (req: WriteRequest): Promise<WriteResult> => {
    requests.push(req);
    return script ? script(req) : emptyResult();
  };
  return { requests, fn };
}

function emptyResult(): WriteResult {
  return { stored: [], rejected: [], superseded: [], deduplicated: 0 };
}

/** A WriteResult with one stored fact (content echoed) — enough to count. */
function storedResult(content: string): WriteResult {
  const obj = { id: "id-" + content, content } as unknown as MemoryObject;
  return { stored: [obj], rejected: [], superseded: [], deduplicated: 0 };
}

function record(over: Partial<IngestRecord> & { docId: string }): IngestRecord {
  return { content: "some content", ...over };
}

// ---------------------------------------------------------------------------
// importKind — the swap-import ↔ document decision
// ---------------------------------------------------------------------------

describe("importKind", () => {
  it("maps vendor dumps to swap-import and everything else to document", () => {
    expect(importKind("mem0-import")).toBe("swap-import");
    expect(importKind("pgvector-import")).toBe("swap-import");
    expect(importKind("filesystem")).toBe("document");
    expect(importKind("postgres")).toBe("document");
    expect(importKind("notion")).toBe("document");
    expect(importKind("slack")).toBe("document");
  });
});

// ---------------------------------------------------------------------------
// makeIngestSink — the IngestRecord → WriteRequest mapping
// ---------------------------------------------------------------------------

describe("makeIngestSink", () => {
  it("stamps provenance.source = swap-import for an import kind", async () => {
    const { requests, fn } = recordingWrite();
    const sink = makeIngestSink({
      namespace: "org/team",
      sourceId: "mem0:dump-2024",
      sourceKind: "mem0-import",
      writeRecord: fn,
    });

    expect(sink.namespace).toBe("org/team");
    expect(sink.sourceId).toBe("mem0:dump-2024");
    expect(sink.sourceKind).toBe("mem0-import");

    await sink.write(record({ docId: "d1", content: "Alice prefers email", verbatim: true }));

    expect(requests).toHaveLength(1);
    const req = requests[0]!;
    expect(req.provenance).toEqual({
      source: "swap-import",
      sourceId: "mem0:dump-2024",
      sourceKind: "mem0-import",
      documentKey: "d1",
      contentHash: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(req.namespace).toBe("org/team");
    expect(req.content).toBe("Alice prefers email");
    expect(req.actor).toBe(INGEST_ACTOR);
    expect(req.hints?.verbatim).toBe(true);
  });

  it("stamps provenance.source = document for a connector kind", async () => {
    const { requests, fn } = recordingWrite();
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "fs:handbook",
      sourceKind: "filesystem",
      writeRecord: fn,
    });

    await sink.write(record({ docId: "readme.md", content: "The refund window is 30 days" }));

    const req = requests[0]!;
    expect(req.provenance).toEqual({
      source: "document",
      sourceId: "fs:handbook",
      sourceKind: "filesystem",
      documentKey: "readme.md",
      contentHash: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
  });

  it("uses the sink source row as pointer authority, never a catalog-supplied id", async () => {
    const { requests, fn } = recordingWrite();
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "01SOURCEBOUND",
      sourceKind: "notion",
      writeRecord: fn,
    });

    await sink.write(record({
      docId: "provider-object",
      content: "Provider pointer",
      pointer: {
        connectorId: "notion-catalog-card",
        sourceRef: "pages",
        credentialMode: "service",
      },
    }));

    expect(requests[0]!.provenance).toMatchObject({
      sourceId: "01SOURCEBOUND",
      connectorId: "01SOURCEBOUND",
      sourceRef: "pages",
      pointer: true,
    });
  });

  it("defaults scope to org and threads eventTime + verbatim through", async () => {
    const { requests, fn } = recordingWrite();
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "fs:x",
      sourceKind: "filesystem",
      writeRecord: fn,
    });

    // No scope → defaults to "org".
    await sink.write(record({ docId: "a", content: "no scope given" }));
    expect(requests[0]!.scope).toBe("org");

    // Explicit scope is honored.
    await sink.write(record({ docId: "b", content: "user-scoped", scope: "user" }));
    expect(requests[1]!.scope).toBe("user");

    // eventTime + verbatim thread into hints; type is left undefined for ingestion.
    await sink.write(
      record({ docId: "c", content: "dated fact", eventTime: "2024-01-02T00:00:00Z", verbatim: false }),
    );
    expect(requests[2]!.hints).toEqual({
      type: undefined,
      verbatim: false,
      eventTime: "2024-01-02T00:00:00Z",
    });
  });

  it("returns the WriteResult from writeRecord unchanged", async () => {
    const scripted = storedResult("Alice prefers email");
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "s",
      sourceKind: "mem0-import",
      writeRecord: async () => scripted,
    });
    const out = await sink.write(record({ docId: "d1", content: "x" }));
    expect(out).toBe(scripted);
  });

  it("retries a conflicted verbatim record with deterministic entity annotations", async () => {
    const requests: WriteRequest[] = [];
    const scripted = storedResult("Complete Notion page body");
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "notion:workspace",
      sourceKind: "notion_direct",
      writeRecord: async (req) => {
        requests.push(req);
        if (!req.hints?.deterministicEntities) {
          throw new Error("entity resolution changed while writing: While");
        }
        return scripted;
      },
    });

    const out = await sink.write(record({
      docId: "page-1",
      content: "Complete Notion page body",
      verbatim: true,
    }));

    expect(out).toBe(scripted);
    expect(requests).toHaveLength(2);
    expect(requests[1]).toMatchObject({
      content: "Complete Notion page body",
      hints: { verbatim: true, deterministicEntities: true },
      provenance: { documentKey: "page-1" },
    });
  });
});

// ---------------------------------------------------------------------------
// aggregate — the reusable count folder
// ---------------------------------------------------------------------------

describe("aggregate", () => {
  it("folds stored / deduplicated / superseded / rejected across results", () => {
    const results: WriteResult[] = [
      { stored: [{} as MemoryObject, {} as MemoryObject], rejected: [], superseded: [], deduplicated: 0 },
      { stored: [], rejected: [{ candidate: "c", reason: "r" }], superseded: ["v1"], deduplicated: 3 },
    ];
    expect(aggregate(results)).toEqual({
      stored: 2,
      deduplicated: 3,
      superseded: 1,
      rejected: 1,
      disputed: 0,
    });
  });

  it("returns all-zero for an empty list", () => {
    expect(aggregate([])).toEqual({ stored: 0, deduplicated: 0, superseded: 0, rejected: 0, disputed: 0 });
  });
});

// ---------------------------------------------------------------------------
// runImport — batch drive + error capture
// ---------------------------------------------------------------------------

describe("runImport", () => {
  it("aggregates counts across every record and stamps sourceId on the result", async () => {
    const { fn } = recordingWrite((req) => {
      // First doc dedupes, second supersedes, third stores.
      if (req.content === "dup") return { stored: [], rejected: [], superseded: [], deduplicated: 1 };
      if (req.content === "sup") return { stored: [], rejected: [], superseded: ["old"], deduplicated: 0 };
      return storedResult(req.content);
    });
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "src-99",
      sourceKind: "filesystem",
      writeRecord: fn,
    });

    const records = [
      record({ docId: "1", content: "dup" }),
      record({ docId: "2", content: "sup" }),
      record({ docId: "3", content: "fresh" }),
    ];
    const result = await runImport(records, sink);

    expect(result.sourceId).toBe("src-99");
    expect(result.records).toBe(3);
    expect(result.stored).toBe(1);
    expect(result.deduplicated).toBe(1);
    expect(result.superseded).toBe(1);
    expect(result.rejected).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it("captures a thrown record into errors[] and continues the rest of the batch", async () => {
    const { requests, fn } = recordingWrite((req) => {
      if (req.content === "poison") throw new Error("write blew up");
      return storedResult(req.content);
    });
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "src-err",
      sourceKind: "pgvector-import",
      writeRecord: fn,
    });

    const records = [
      record({ docId: "ok-1", content: "first" }),
      record({ docId: "bad", content: "poison" }),
      record({ docId: "ok-2", content: "third" }),
    ];
    const result = await runImport(records, sink);

    // The throw did NOT abort the batch — all three records were attempted.
    expect(requests).toHaveLength(3);
    expect(result.records).toBe(3);
    expect(result.stored).toBe(2); // the two survivors landed
    expect(result.errors).toEqual([{ docId: "bad", reason: "write blew up" }]);

    // Provenance still stamped correctly on the surviving import writes.
    expect(requests.every((r) => r.provenance?.source === "swap-import")).toBe(true);
  });

  it("stringifies a non-Error throw into the error reason", async () => {
    const sink = makeIngestSink({
      namespace: "org",
      sourceId: "s",
      sourceKind: "filesystem",
      writeRecord: async () => {
        throw "raw string failure";
      },
    });
    const result = await runImport([record({ docId: "d" })], sink);
    expect(result.errors).toEqual([{ docId: "d", reason: "raw string failure" }]);
    expect(result.stored).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// FORBIDDEN_INGEST_IMPORTS — the D10 conformance regex list
// ---------------------------------------------------------------------------

describe("FORBIDDEN_INGEST_IMPORTS", () => {
  it("matches the forbidden kernel-internal relative imports", () => {
    const hits = (src: string) => FORBIDDEN_INGEST_IMPORTS.some((re) => re.test(src));
    expect(hits(`import { x } from "../../index/index.js";`)).toBe(true);
    expect(hits(`import { Db } from "../../db/index.js";`)).toBe(true);
    expect(hits(`import { AuditLog } from "../../audit/index.js";`)).toBe(true);
    expect(hits(`import { performWrite } from "../../write/index.js";`)).toBe(true);
    // Allowed imports do not trip the guard.
    expect(hits(`import type { IngestSink } from "../../types.js";`)).toBe(false);
    expect(hits(`import { readFileSync } from "node:fs";`)).toBe(false);
    expect(hits(`import matter from "gray-matter";`)).toBe(false);
  });

  // Regression (finding 1): the src-root barrel + kernel facade re-export the
  // write-path free function `performWrite` and `Kernel` (whose public `db` is a
  // raw Db handle). An importer/connector reaching either evades the sink and
  // writes the store directly — the exact D10 bypass. The prior denylist only
  // matched directory imports (`../index/`), so `../../index.js` slipped past.
  it("blocks the src-root barrel and kernel facade (D10 write-path bypass)", () => {
    const hits = (src: string) => FORBIDDEN_INGEST_IMPORTS.some((re) => re.test(src));
    // The barrel re-exports performWrite + Kernel — the store-bypass surface.
    expect(hits(`import { performWrite, Kernel } from "../../index.js";`)).toBe(true);
    expect(hits(`import type { SyscallDeps } from "../../index.js";`)).toBe(true);
    // The kernel facade directly (Kernel.db is a public raw Db handle).
    expect(hits(`import { Kernel } from "../../kernel.js";`)).toBe(true);
    expect(hits(`import { Kernel } from "../../kernel";`)).toBe(true);
    // The single legitimate relative seam MUST still pass (allowlist intact).
    expect(hits(`import type { Connector } from "../../types.js";`)).toBe(false);
    expect(hits(`import { syncWithDrift } from "./framework.js";`)).toBe(false);
  });
});
