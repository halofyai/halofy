import { Buffer } from "node:buffer";
import type { IngestRecord, SourceAccess } from "../types.js";

const MAX_CONTENT_BYTES = 2 * 1024 * 1024;
const MAX_DOC_ID_CHARS = 2048;
const MAX_ACL_ENTRIES = 1024;
const MAX_ACL_ID_CHARS = 256;
const MAX_CLASSIFICATION_LABELS = 256;

export class IngestValidationError extends Error {
  readonly code = "invalid-ingest-record";

  constructor(reason: string) {
    super(`invalid ingest record: ${reason}`);
    this.name = "IngestValidationError";
  }
}

function labels(value: unknown, field: string, max = MAX_CLASSIFICATION_LABELS): string[] {
  if (!Array.isArray(value) || value.length > max) {
    throw new IngestValidationError(`${field} must be a bounded string array`);
  }
  const normalized: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !item.trim() || item.length > MAX_ACL_ID_CHARS) {
      throw new IngestValidationError(`${field} contains an invalid identifier`);
    }
    normalized.push(item.trim());
  }
  return [...new Set(normalized)].sort();
}

function sourceAccess(value: unknown): SourceAccess | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object") {
    throw new IngestValidationError("sourceAccess must be an object");
  }
  const raw = value as Record<string, unknown>;
  const principals = labels(raw.principals, "sourceAccess.principals", MAX_ACL_ENTRIES);
  const groups = labels(raw.groups, "sourceAccess.groups", MAX_ACL_ENTRIES);
  const inherited = raw.inheritedFrom;
  if (
    inherited !== undefined &&
    (typeof inherited !== "string" || !inherited.trim() || inherited.length > MAX_DOC_ID_CHARS)
  ) {
    throw new IngestValidationError("sourceAccess.inheritedFrom is invalid");
  }
  return {
    principals,
    groups,
    ...(typeof inherited === "string" ? { inheritedFrom: inherited.trim() } : {}),
  };
}

/** Runtime source-boundary validation before classification or persistence. */
export function validateIngestRecord(record: IngestRecord): IngestRecord {
  if (typeof record.docId !== "string" || !record.docId || record.docId.length > MAX_DOC_ID_CHARS) {
    throw new IngestValidationError("docId is invalid");
  }
  if (typeof record.content !== "string" || Buffer.byteLength(record.content, "utf8") > MAX_CONTENT_BYTES) {
    throw new IngestValidationError("content exceeds the source record limit");
  }
  const access = sourceAccess(record.sourceAccess);
  if (record.classification) {
    const hint = record.classification as Record<string, unknown>;
    for (const field of ["piiSubjects", "secretKinds", "allowedDestinations"] as const) {
      if (hint[field] !== undefined) labels(hint[field], `classification.${field}`);
    }
    if (
      hint.residency !== undefined &&
      (typeof hint.residency !== "string" || !hint.residency.trim() || hint.residency.length > 64)
    ) {
      throw new IngestValidationError("classification.residency is invalid");
    }
  }
  return { ...record, ...(access ? { sourceAccess: access } : {}) };
}
