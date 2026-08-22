import type { VerifiedWebhookRecord } from "./webhook.js";
import { parseCsv } from "./connectors/csv.js";

const MAX_CSV_BYTES = 512 * 1024;
const MAX_CSV_ROWS = 1_000;
const MAX_CSV_COLUMNS = 64;
const MAX_TEXT_COLUMNS = 32;
const MAX_ROW_TEXT_LENGTH = 16_384;
const ROW_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;
const CLASSIFICATION_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;
const AUTHORITY_COLUMNS = new Set([
  "namespace",
  "actor",
  "acl",
  "principals",
  "groups",
  "sourceaccess",
  "source_access",
  "role",
  "scope",
]);

export interface CsvImportInput {
  csv: string;
  mapping: {
    idColumn: string;
    textColumns: string[];
    updatedAtColumn?: string;
    classificationColumn?: string;
  };
}

export interface CsvConnectorRecord extends Omit<VerifiedWebhookRecord, "eventTime"> {
  updatedAt?: string;
}

function isReservedColumn(column: string): boolean {
  const normalized = column.toLowerCase().replace(/\s+/g, "_");
  return AUTHORITY_COLUMNS.has(normalized) ||
    /(password|secret|signature|cookie|authorization|credential|api_?key|access_?token)/.test(normalized);
}

/** Map untrusted CSV into the fixed file-adapter envelope before D10 ingestion. */
export function mapCsvToConnectorRecords(input: CsvImportInput): CsvConnectorRecord[] {
  if (typeof input.csv !== "string" || Buffer.byteLength(input.csv, "utf8") > MAX_CSV_BYTES) {
    throw new Error("CSV import must be a UTF-8 document no larger than 512KiB");
  }
  const table = parseCsv(input.csv.replace(/^\uFEFF/, ""));
  if (table.header.length < 2 || table.header.length > MAX_CSV_COLUMNS) {
    throw new Error("CSV import must contain 2..64 columns");
  }
  if (table.header.some((column) => column.length === 0 || column.length > 120)) {
    throw new Error("CSV import has an invalid header");
  }
  if (new Set(table.header).size !== table.header.length) {
    throw new Error("CSV import headers must be unique");
  }
  if (table.rows.length < 1 || table.rows.length > MAX_CSV_ROWS) {
    throw new Error("CSV import must contain at most 1000 non-empty data rows");
  }

  const mapping = input.mapping;
  if (!mapping || typeof mapping !== "object" || typeof mapping.idColumn !== "string" ||
      !Array.isArray(mapping.textColumns) || mapping.textColumns.length < 1 ||
      mapping.textColumns.length > MAX_TEXT_COLUMNS ||
      mapping.textColumns.some((column) => typeof column !== "string")) {
    throw new Error("CSV import requires an ID column and 1..32 text columns");
  }
  const mappedColumns = [
    mapping.idColumn,
    ...mapping.textColumns,
    ...(mapping.updatedAtColumn ? [mapping.updatedAtColumn] : []),
    ...(mapping.classificationColumn ? [mapping.classificationColumn] : []),
  ];
  if (mappedColumns.some((column) => !table.header.includes(column))) {
    throw new Error("CSV import mapping references an unknown column");
  }
  if (mappedColumns.some(isReservedColumn)) {
    throw new Error("CSV import cannot map a reserved authority or credential column");
  }
  if (new Set(mapping.textColumns).size !== mapping.textColumns.length) {
    throw new Error("CSV import text columns must be unique");
  }

  const seenIds = new Set<string>();
  return table.rows.map((row, index) => {
    const id = row[mapping.idColumn]?.trim() ?? "";
    if (!ROW_ID_PATTERN.test(id)) {
      throw new Error(`CSV row ${index + 2} has an invalid stable ID`);
    }
    if (seenIds.has(id)) throw new Error(`CSV import has duplicate row ID '${id}'`);
    seenIds.add(id);

    const admitted = Object.fromEntries(
      mapping.textColumns.map((column) => [column, row[column] ?? ""]),
    );
    const text = JSON.stringify(admitted);
    if (Object.values(admitted).every((value) => value.trim().length === 0) ||
        text.length > MAX_ROW_TEXT_LENGTH) {
      throw new Error(`CSV row ${index + 2} has invalid mapped text`);
    }
    const updatedAt = mapping.updatedAtColumn
      ? row[mapping.updatedAtColumn]?.trim() ?? ""
      : "";
    if (updatedAt && Number.isNaN(Date.parse(updatedAt))) {
      throw new Error(`CSV row ${index + 2} has an invalid update time`);
    }
    const classification = mapping.classificationColumn
      ? row[mapping.classificationColumn]?.trim() ?? ""
      : "";
    if (classification && !CLASSIFICATION_PATTERN.test(classification)) {
      throw new Error(`CSV row ${index + 2} has an invalid classification`);
    }
    return {
      id,
      text,
      ...(updatedAt ? { updatedAt } : {}),
      ...(classification ? { classification } : {}),
    };
  });
}
