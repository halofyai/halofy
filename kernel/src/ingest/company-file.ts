import { Buffer } from "node:buffer";
import { parse as parseYaml } from "yaml";

import type { IngestRecord } from "../types.js";
import { parseCsv } from "./connectors/csv.js";
import {
  BinaryDocumentError,
  extractBinaryDocumentText,
  isBinaryCompanyExtension,
} from "./binary-documents.js";

export const MAX_COMPANY_FILE_BYTES = 512 * 1024;
export const MAX_COMPANY_FILE_BINARY_BYTES = 5 * 1024 * 1024;
export const MAX_COMPANY_FILE_NAME_BYTES = 255;
export const MAX_COMPANY_FILE_PURPOSE_BYTES = 256;
export const MAX_COMPANY_FILE_DESCRIPTION_BYTES = 1_024;
export const MAX_COMPANY_FILE_BUSINESS_FUNCTION_BYTES = 120;
/**
 * Maximum extracted text sent through one governed write-path invocation.
 *
 * A document may be well inside the upload byte limit while its extracted text
 * is large enough to make provider latency or token limits unreliable. Twelve
 * KiB leaves room for the metadata envelope and for tokenizer expansion while
 * keeping ordinary short files as one unchanged document.
 */
export const MAX_COMPANY_FILE_CHUNK_BYTES = 12 * 1024;

const ALLOWED_FIELDS = new Set([
  "fileName",
  "content",
  "purpose",
  "description",
  "businessFunction",
  "dataSensitive",
]);
const AUTHORITY_FIELDS = new Set([
  "namespace",
  "actor",
  "uploadedby",
  "createdby",
  "scope",
  "sourceaccess",
  "acl",
  "principals",
  "groups",
  "role",
  "teamid",
  "teamnamespace",
]);
const SUPPORTED_EXTENSIONS = new Set([
  ".txt",
  ".md",
  ".markdown",
  ".csv",
  ".json",
  ".yaml",
  ".yml",
  ".pdf",
  ".docx",
]);
const CONTROL_OR_SEPARATOR = /[\\/\p{Cc}]/u;
const CONTROL_CHARACTER = /\p{Cc}/u;
const UNSAFE_TEXT_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

export class CompanyFileValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CompanyFileValidationError";
  }
}

export interface CompanyFileInput {
  fileName: string;
  content: Uint8Array;
  purpose: string;
  description?: string;
  businessFunction: string;
  dataSensitive: boolean;
}

interface NormalizedCompanyFileInput extends Omit<CompanyFileInput, "content"> {
  /** Decoded text for text formats; original bytes for binary (PDF/DOCX). */
  content: string | Uint8Array;
  extension: string;
}

/**
 * Validate one untrusted company file and map it to the D10 ingestion contract.
 * This boundary is pure: it performs no storage, identity, or authorization work.
 * Binary formats are extracted to text here, so every downstream stage sees the
 * same contract regardless of source format.
 */
export async function parseCompanyFileInput(input: unknown): Promise<IngestRecord[]> {
  const file = normalizeCompanyFileInput(input);
  let content: string;
  if (typeof file.content === "string") {
    content = file.content;
  } else {
    try {
      content = await extractBinaryDocumentText(file.extension, file.content);
    } catch (error) {
      if (error instanceof BinaryDocumentError) {
        throw new CompanyFileValidationError(error.message);
      }
      throw error;
    }
    if (UNSAFE_TEXT_CONTROL.test(content)) {
      throw new CompanyFileValidationError(
        "company file cannot contain binary control characters",
      );
    }
  }
  validateStructuredContent(file.extension, content);
  const metadata = {
    purpose: file.purpose,
    ...(file.description === undefined ? {} : { description: file.description }),
    businessFunction: file.businessFunction,
    dataSensitive: file.dataSensitive,
  };
  const chunks = splitCompanyFileText(content, MAX_COMPANY_FILE_CHUNK_BYTES);
  return chunks.map((chunk, index) => ({
    // Preserve the historical key for the overwhelmingly common one-record
    // case. Large documents get stable, ordered fragment keys so retries and
    // exact-attempt compensation remain deterministic.
    docId: chunks.length === 1
      ? file.fileName
      : `${file.fileName}#chunk-${String(index + 1).padStart(4, "0")}-of-${String(chunks.length).padStart(4, "0")}`,
    content: `[company-file] ${JSON.stringify({
      ...metadata,
      ...(chunks.length === 1 ? {} : { chunk: { index: index + 1, count: chunks.length } }),
    })}\n\n${chunk}`,
    scope: "org",
    verbatim: false,
    classification: {
      sensitivity: file.dataSensitive ? "confidential" : "internal",
    },
  }));
}

/**
 * Split extracted text on the latest useful structural boundary that fits.
 * Falls back to a UTF-8-safe hard boundary for a single oversized paragraph.
 * No overlap is added: overlapping source text can manufacture duplicate facts.
 */
function splitCompanyFileText(content: string, maxBytes: number): string[] {
  const remaining = content.trim();
  if (Buffer.byteLength(remaining, "utf8") <= maxBytes) return [remaining];
  const chunks: string[] = [];
  let cursor = remaining;
  while (Buffer.byteLength(cursor, "utf8") > maxBytes) {
    const bytes = Buffer.from(cursor, "utf8");
    let byteEnd = Math.min(maxBytes, bytes.byteLength);
    // A UTF-8 continuation byte cannot begin the remainder. Move the boundary
    // to the start of that code point; decoding both sides then stays lossless.
    while (byteEnd > 0 && byteEnd < bytes.byteLength && (bytes[byteEnd]! & 0xc0) === 0x80) {
      byteEnd--;
    }
    const prefix = bytes.subarray(0, byteEnd).toString("utf8");
    const candidates = [prefix.lastIndexOf("\n\n"), prefix.lastIndexOf("\n"), prefix.lastIndexOf(" ")];
    const structuralEnd = Math.max(...candidates);
    // Do not create tiny fragments just to honor a very early newline.
    const charEnd = structuralEnd >= Math.floor(prefix.length * 0.6)
      ? structuralEnd
      : prefix.length;
    const chunk = cursor.slice(0, charEnd).trim();
    if (chunk.length === 0) {
      throw new CompanyFileValidationError("company file text could not be chunked safely");
    }
    chunks.push(chunk);
    cursor = cursor.slice(charEnd).trimStart();
  }
  if (cursor.trim().length > 0) chunks.push(cursor.trim());
  return chunks;
}

/** Validate the upload envelope without performing binary/text extraction. */
export function validateCompanyFileInput(input: unknown): void {
  normalizeCompanyFileInput(input);
}

function normalizeCompanyFileInput(input: unknown): NormalizedCompanyFileInput {
  const raw = plainObject(input);
  for (const key of Object.keys(raw)) {
    const authorityKey = key.toLowerCase().replace(/[_-]/g, "");
    if (AUTHORITY_FIELDS.has(authorityKey)) {
      throw new CompanyFileValidationError(
        `caller-owned authority field '${key}' is not allowed`,
      );
    }
    if (!ALLOWED_FIELDS.has(key)) {
      throw new CompanyFileValidationError(`unknown company file field '${key}'`);
    }
  }

  const fileName = requiredText(
    raw.fileName,
    "filename",
    MAX_COMPANY_FILE_NAME_BYTES,
  );
  if (CONTROL_OR_SEPARATOR.test(fileName)) {
    throw new CompanyFileValidationError(
      "company filename cannot contain path separators or control characters",
    );
  }
  const extensionIndex = fileName.lastIndexOf(".");
  const extension = extensionIndex > 0
    ? fileName.slice(extensionIndex).toLowerCase()
    : "";
  if (!SUPPORTED_EXTENSIONS.has(extension)) {
    throw new CompanyFileValidationError("unsupported company file format");
  }

  if (!(raw.content instanceof Uint8Array)) {
    throw new CompanyFileValidationError("company file content must be bytes");
  }
  if (raw.content.byteLength === 0) {
    throw new CompanyFileValidationError("company file cannot be empty");
  }
  if (isBinaryCompanyExtension(extension)) {
    if (raw.content.byteLength > MAX_COMPANY_FILE_BINARY_BYTES) {
      throw new CompanyFileValidationError("company file exceeds the 5 MiB limit");
    }
    // Binary formats keep their original bytes here; text extraction happens
    // in parseCompanyFileInput once metadata has validated.
    return { fileName, content: raw.content, ...normalizeMetadata(raw), extension };
  }
  if (raw.content.byteLength > MAX_COMPANY_FILE_BYTES) {
    throw new CompanyFileValidationError("company file exceeds the 512 KiB limit");
  }
  let content: string;
  try {
    content = new TextDecoder("utf-8", { fatal: true }).decode(raw.content);
  } catch {
    throw new CompanyFileValidationError("company file must contain valid UTF-8");
  }
  content = content.replace(/^\uFEFF/, "");
  if (content.trim().length === 0) {
    throw new CompanyFileValidationError("company file cannot be empty");
  }
  if (UNSAFE_TEXT_CONTROL.test(content)) {
    throw new CompanyFileValidationError(
      "company file cannot contain binary control characters",
    );
  }

  return { fileName, content, ...normalizeMetadata(raw), extension };
}

function normalizeMetadata(raw: Record<string, unknown>): {
  purpose: string;
  description?: string;
  businessFunction: string;
  dataSensitive: boolean;
} {
  const purpose = requiredText(
    raw.purpose,
    "purpose",
    MAX_COMPANY_FILE_PURPOSE_BYTES,
  );
  const businessFunction = requiredText(
    raw.businessFunction,
    "businessFunction",
    MAX_COMPANY_FILE_BUSINESS_FUNCTION_BYTES,
  );
  const description = raw.description === undefined
    ? undefined
    : requiredText(
        raw.description,
        "description",
        MAX_COMPANY_FILE_DESCRIPTION_BYTES,
      );
  if (typeof raw.dataSensitive !== "boolean") {
    throw new CompanyFileValidationError(
      "dataSensitive must be explicitly true or false",
    );
  }

  return {
    purpose,
    ...(description === undefined ? {} : { description }),
    businessFunction,
    dataSensitive: raw.dataSensitive,
  };
}

function plainObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CompanyFileValidationError("company file input must be an object");
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CompanyFileValidationError("company file input must be a plain object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)) {
    throw new CompanyFileValidationError("company file input cannot contain accessors");
  }
  return value as Record<string, unknown>;
}

function requiredText(value: unknown, field: string, maxBytes: number): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new CompanyFileValidationError(`${field} is required`);
  }
  const normalized = value.trim();
  if (CONTROL_CHARACTER.test(normalized)) {
    throw new CompanyFileValidationError(`${field} cannot contain control characters`);
  }
  if (Buffer.byteLength(normalized, "utf8") > maxBytes) {
    throw new CompanyFileValidationError(`${field} exceeds its ${maxBytes}-byte limit`);
  }
  return normalized;
}

function validateStructuredContent(extension: string, content: string): void {
  if (extension === ".json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content) as unknown;
    } catch {
      throw new CompanyFileValidationError(
        "company .json file does not contain valid JSON",
      );
    }
    if (parsed === null || typeof parsed !== "object") {
      throw new CompanyFileValidationError(
        "company .json file must contain a JSON object or array",
      );
    }
    return;
  }
  if (extension === ".yaml" || extension === ".yml") {
    let parsed: unknown;
    try {
      parsed = parseYaml(content, {
        maxAliasCount: 50,
        strict: true,
        uniqueKeys: true,
      }) as unknown;
    } catch {
      throw new CompanyFileValidationError(
        "company YAML file does not contain valid YAML",
      );
    }
    if (parsed === null || typeof parsed !== "object") {
      throw new CompanyFileValidationError(
        "company YAML file must contain a mapping or sequence",
      );
    }
    return;
  }
  if (extension === ".csv") {
    let table;
    try {
      table = parseCsv(content);
    } catch {
      throw new CompanyFileValidationError(
        "company .csv file does not contain a CSV table",
      );
    }
    const uniqueHeaders = new Set(table.header);
    if (
      table.header.length < 2 ||
      table.rows.length < 1 ||
      uniqueHeaders.size !== table.header.length ||
      table.header.some((header) => !header.trim() || CONTROL_CHARACTER.test(header))
    ) {
      throw new CompanyFileValidationError(
        "company .csv file does not contain a CSV table",
      );
    }
  }
}
