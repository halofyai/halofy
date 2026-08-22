import type { ProvenanceEntry } from "../types.js";

interface RetrievalSourceRow {
  content: string;
  provenance?: readonly ProvenanceEntry[];
}

export interface RetrievalSourceProjection {
  /** Friendly backend label resolved from the ACL-visible source registry. */
  label: string;
  /** Optional source ids selected server-side for a source-scoped search. */
  sourceIds?: readonly string[];
}

function sourceEntry(
  row: RetrievalSourceRow,
  projection?: RetrievalSourceProjection,
): ProvenanceEntry | undefined {
  const selected = projection?.sourceIds?.length
    ? new Set(projection.sourceIds)
    : null;
  return row.provenance?.find((entry) =>
    Boolean(entry.sourceId) && (!selected || selected.has(entry.sourceId!)));
}

function sourceLabel(kind: ProvenanceEntry["sourceKind"]): string | null {
  if (!kind) return null;
  const canonical = kind.endsWith("_direct") ? kind.slice(0, -7) : kind;
  return canonical
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part[0]!.toUpperCase() + part.slice(1))
    .join(" ");
}

/**
 * Project source identity into retrieved company-file evidence without
 * mutating the canonical memory object. Older company-file rows retained the
 * filename only as provenance.documentKey, so this keeps them searchable and
 * gives the model enough evidence to answer file-presence questions.
 */
export function retrievalContent(
  row: RetrievalSourceRow,
  projection?: RetrievalSourceProjection,
): string {
  const provenance = sourceEntry(row, projection);
  const label = projection?.label ?? sourceLabel(provenance?.sourceKind);
  const sourceContext = label
    ? `[source-context] ${JSON.stringify({
        backend: label,
        ...(provenance?.documentKey ? { document: provenance.documentKey } : {}),
      })}\n`
    : "";

  if (!row.content.startsWith("[company-file] ")) return sourceContext + row.content;
  const firstLineEnd = row.content.indexOf("\n");
  const firstLine = firstLineEnd === -1
    ? row.content
    : row.content.slice(0, firstLineEnd);
  if (firstLine.includes('"fileName":')) return sourceContext + row.content;

  const fileName = row.provenance
    ?.map((entry) => entry.documentKey?.trim())
    .find((value): value is string => Boolean(value));
  if (!fileName) return sourceContext + row.content;
  return sourceContext + `[company-file-source] ${JSON.stringify({ fileName })}\n${row.content}`;
}
