/**
 * Module B — Mem0 bulk importer.
 *
 * A Mem0 export is a list of ALREADY-EXTRACTED facts (not transcripts), so
 * every record lands `verbatim: true` — the write path stores each as a single
 * fact and does NOT re-run LLM extraction. `parse` is pure and offline (D10):
 * the importer never touches the store, only produces `IngestRecord[]` that the
 * caller feeds to an `IngestSink` (which stamps provenance `swap-import`).
 *
 * Import surface is deliberately minimal: shared types + `node:crypto` only.
 * No `src/index`, `src/db`, `src/audit`, `src/write`, `src/kernel`.
 */

import { createHash } from "node:crypto";
import type { Importer, IngestRecord } from "../../types.js";

/**
 * Tolerated container shapes for a Mem0 export:
 *   - a top-level array of items, or
 *   - `{ results: [...] }` (v1 REST get_all), or
 *   - `{ memories: [...] }` (older dumps / manual exports).
 */
function extractItems(parsed: unknown): unknown[] {
  if (Array.isArray(parsed)) return parsed;
  if (parsed !== null && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;
    if (Array.isArray(obj.results)) return obj.results;
    if (Array.isArray(obj.memories)) return obj.memories;
  }
  return [];
}

/**
 * A Mem0 item stores the fact text under one of several field names across
 * export versions: `memory` (current), `text`, `data`, or `content`. Return the
 * first non-blank string, or null if none is usable.
 */
function factText(item: Record<string, unknown>): string | null {
  for (const key of ["memory", "text", "data", "content"] as const) {
    const v = item[key];
    if (typeof v === "string" && v.trim() !== "") return v.trim();
  }
  return null;
}

function sha16(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export class Mem0Importer implements Importer {
  readonly kind = "mem0-import" as const;

  parse(raw: string): IngestRecord[] {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [];
    }

    const records: IngestRecord[] = [];
    for (const item of extractItems(parsed)) {
      if (item === null || typeof item !== "object") continue;
      const obj = item as Record<string, unknown>;

      const content = factText(obj);
      if (content === null) continue; // no usable text → skip malformed row

      // Prefer the source's own stable id (drift + dedupe key); fall back to a
      // content hash so an item without an id still gets a deterministic docId.
      const rawId = obj.id;
      const docId =
        typeof rawId === "string" && rawId.trim() !== ""
          ? rawId.trim()
          : typeof rawId === "number" && Number.isFinite(rawId)
            ? String(rawId)
            : sha16(content);

      records.push({ docId, content, verbatim: true });
    }
    return records;
  }
}
