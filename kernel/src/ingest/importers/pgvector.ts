/**
 * Module B — pgvector bulk importer.
 *
 * A pgvector table dump is an array of rows whose text column already holds a
 * discrete fact/chunk, so every record lands `verbatim: true` (no LLM
 * re-extraction). `parse` is pure and offline (D10): it only produces
 * `IngestRecord[]`; the caller feeds them to an `IngestSink` that stamps
 * provenance `swap-import`.
 *
 * Import surface: shared types + `node:crypto` only.
 */

import { createHash } from "node:crypto";
import type { Importer, IngestRecord } from "../../types.js";

function factText(row: Record<string, unknown>): string | null {
  for (const key of ["content", "document", "text"] as const) {
    const v = row[key];
    if (typeof v === "string" && v.trim() !== "") return v.trim();
  }
  return null;
}

function sha16(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export class PgvectorImporter implements Importer {
  readonly kind = "pgvector-import" as const;

  parse(raw: string): IngestRecord[] {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [];
    }

    // A pgvector dump is a top-level array of rows. Tolerate a wrapping
    // `{ rows: [...] }` (common `pg` result shape) as well.
    let rows: unknown[];
    if (Array.isArray(parsed)) {
      rows = parsed;
    } else if (
      parsed !== null &&
      typeof parsed === "object" &&
      Array.isArray((parsed as Record<string, unknown>).rows)
    ) {
      rows = (parsed as Record<string, unknown>).rows as unknown[];
    } else {
      return [];
    }

    const records: IngestRecord[] = [];
    for (const row of rows) {
      if (row === null || typeof row !== "object") continue;
      const obj = row as Record<string, unknown>;

      const content = factText(obj);
      if (content === null) continue; // skip malformed / empty rows

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
