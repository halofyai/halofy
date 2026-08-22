import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_AGE_MS = 5 * 60_000;
export const MAX_OBSIDIAN_BODY_BYTES = 1_048_576;
const MAX_RECORDS = 50;
const MAX_DELETIONS = 500;
const MAX_MANIFEST_PATHS = 20_000;
const MAX_PATH_LENGTH = 1_024;
const MAX_CONTENT_BYTES = 40 * 1_024;
const MAX_PROPERTIES_BYTES = 8 * 1_024;
const MAX_LINK_BYTES = 8 * 1_024;
const MAX_LINKS = 100;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

export type ObsidianPropertyValue = string | number | boolean | null |
  Array<string | number | boolean | null>;

export interface ObsidianNoteRecord {
  path: string;
  content: string;
  modifiedAt?: string;
  properties?: Record<string, ObsidianPropertyValue>;
  links?: string[];
}

export type ObsidianIngressPayload =
  | {
      version: 1;
      sequence: number;
      kind: "changes";
      records: ObsidianNoteRecord[];
      deleted: string[];
    }
  | {
      version: 1;
      sequence: number;
      kind: "manifest";
      paths: string[];
    };

export class ObsidianAuthorizationError extends Error {
  override readonly name = "ObsidianAuthorizationError";
}

export class ObsidianValidationError extends Error {
  override readonly name = "ObsidianValidationError";
}

export class ObsidianDeliveryError extends Error {
  override readonly name = "ObsidianDeliveryError";
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const set = new Set(allowed);
  return Object.keys(value).every((key) => set.has(key)) &&
    allowed.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

export function validateObsidianPath(value: unknown, label = "path"): string {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_PATH_LENGTH ||
      CONTROL.test(value) || value.startsWith("/") || value.includes("\\")) {
    throw new ObsidianValidationError(`obsidian ${label} is invalid`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === ".." ||
      segment.startsWith(".")) || !value.toLowerCase().endsWith(".md")) {
    throw new ObsidianValidationError(`obsidian ${label} is invalid`);
  }
  return value;
}

function propertyValue(value: unknown): value is ObsidianPropertyValue {
  const scalar = (item: unknown) => item === null || typeof item === "string" ||
    typeof item === "boolean" || (typeof item === "number" && Number.isFinite(item));
  return scalar(value) || (Array.isArray(value) && value.length <= 100 && value.every(scalar));
}

function parseProperties(value: unknown): Record<string, ObsidianPropertyValue> | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ObsidianValidationError("obsidian note properties are invalid");
  }
  const input = value as Record<string, unknown>;
  const entries = Object.entries(input);
  if (entries.length > 100 || Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_PROPERTIES_BYTES) {
    throw new ObsidianValidationError("obsidian note properties exceed their limit");
  }
  const output: Record<string, ObsidianPropertyValue> = {};
  for (const [key, item] of entries) {
    if (!key || key.length > 128 || CONTROL.test(key) || !propertyValue(item)) {
      throw new ObsidianValidationError("obsidian note properties are invalid");
    }
    output[key] = item;
  }
  return output;
}

function parseLinks(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > MAX_LINKS ||
      value.some((link) => typeof link !== "string" || !link || link.length > MAX_PATH_LENGTH ||
        CONTROL.test(link)) || Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_LINK_BYTES) {
    throw new ObsidianValidationError("obsidian note links are invalid");
  }
  return [...new Set(value as string[])].sort();
}

function parseRecord(value: unknown, index: number): ObsidianNoteRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ObsidianValidationError(`obsidian record ${index} is invalid`);
  }
  const record = value as Record<string, unknown>;
  if (!Object.keys(record).every((key) =>
    ["path", "content", "modifiedAt", "properties", "links"].includes(key)) ||
      !Object.prototype.hasOwnProperty.call(record, "path") ||
      !Object.prototype.hasOwnProperty.call(record, "content")) {
    throw new ObsidianValidationError(`obsidian record ${index} has undeclared fields`);
  }
  const path = validateObsidianPath(record.path, `record ${index} path`);
  if (typeof record.content !== "string" ||
      Buffer.byteLength(record.content, "utf8") > MAX_CONTENT_BYTES) {
    throw new ObsidianValidationError(`obsidian record ${index} content exceeds its limit`);
  }
  if (record.modifiedAt !== undefined && (typeof record.modifiedAt !== "string" ||
      Number.isNaN(Date.parse(record.modifiedAt)))) {
    throw new ObsidianValidationError(`obsidian record ${index} modifiedAt is invalid`);
  }
  const properties = parseProperties(record.properties);
  const links = parseLinks(record.links);
  return {
    path,
    content: record.content,
    ...(typeof record.modifiedAt === "string" ? { modifiedAt: record.modifiedAt } : {}),
    ...(properties ? { properties } : {}),
    ...(links ? { links } : {}),
  };
}

function uniquePaths(values: unknown[], label: string, max: number): string[] {
  if (values.length > max) throw new ObsidianValidationError(`obsidian ${label} exceed their limit`);
  const paths = values.map((value, index) => validateObsidianPath(value, `${label} ${index}`));
  if (new Set(paths).size !== paths.length) {
    throw new ObsidianValidationError(`obsidian ${label} contain duplicates`);
  }
  return paths;
}

function parsePayload(rawBody: string): ObsidianIngressPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody) as unknown;
  } catch {
    throw new ObsidianValidationError("obsidian body is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ObsidianValidationError("obsidian body is invalid");
  }
  const input = parsed as Record<string, unknown>;
  if (input.version !== 1 || !Number.isSafeInteger(input.sequence) || Number(input.sequence) < 1) {
    throw new ObsidianValidationError("obsidian protocol version or sequence is invalid");
  }
  const sequence = Number(input.sequence);
  if (input.kind === "changes") {
    if (!exactKeys(input, ["version", "sequence", "kind", "records", "deleted"]) ||
        !Array.isArray(input.records) || !Array.isArray(input.deleted) ||
        input.records.length > MAX_RECORDS) {
      throw new ObsidianValidationError("obsidian changes payload is invalid");
    }
    const records = input.records.map(parseRecord);
    const deleted = uniquePaths(input.deleted, "deleted paths", MAX_DELETIONS);
    const recordPaths = new Set(records.map((record) => record.path));
    if (deleted.some((path) => recordPaths.has(path))) {
      throw new ObsidianValidationError("obsidian changes cannot update and delete the same path");
    }
    return { version: 1, sequence, kind: "changes", records, deleted };
  }
  if (input.kind === "manifest") {
    if (!exactKeys(input, ["version", "sequence", "kind", "paths"]) ||
        !Array.isArray(input.paths)) {
      throw new ObsidianValidationError("obsidian manifest payload is invalid");
    }
    return {
      version: 1,
      sequence,
      kind: "manifest",
      paths: uniquePaths(input.paths, "manifest paths", MAX_MANIFEST_PATHS),
    };
  }
  throw new ObsidianValidationError("obsidian payload kind is invalid");
}

/** Verify the untouched body before admitting its fixed, authority-free shape. */
export function verifyObsidianIngress(
  signingSecret: string,
  rawBody: string,
  timestamp: string,
  signature: string,
  now = Date.now(),
): ObsidianIngressPayload {
  if (Buffer.byteLength(rawBody, "utf8") > MAX_OBSIDIAN_BODY_BYTES) {
    throw new ObsidianValidationError("obsidian payload exceeds 1MiB");
  }
  if (signingSecret.length < 43 || !/^\d{10,13}$/.test(timestamp)) {
    throw new ObsidianAuthorizationError("invalid obsidian signature");
  }
  const numericTimestamp = Number(timestamp);
  const timestampMs = timestamp.length === 13 ? numericTimestamp : numericTimestamp * 1_000;
  if (!Number.isSafeInteger(numericTimestamp) || Math.abs(now - timestampMs) > MAX_AGE_MS) {
    throw new ObsidianAuthorizationError("invalid obsidian signature");
  }
  const match = /^sha256=([0-9a-f]{64})$/i.exec(signature);
  if (!match) throw new ObsidianAuthorizationError("invalid obsidian signature");
  const supplied = Buffer.from(match[1], "hex");
  const expected = createHmac("sha256", signingSecret)
    .update(`${timestamp}.${rawBody}`, "utf8")
    .digest();
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new ObsidianAuthorizationError("invalid obsidian signature");
  }
  return parsePayload(rawBody);
}
