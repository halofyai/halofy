/**
 * Module A — ingest core barrel.
 *
 * Re-exports the ingestion write surface (`makeIngestSink`), the batch runner
 * (`runImport`) and its reusable count-folder (`aggregate`), plus `importKind`.
 *
 * Also exports `FORBIDDEN_INGEST_IMPORTS`: the regex list the D10 conformance /
 * exit test scans importer + connector source text against. No file under
 * `src/ingest/importers/` or `src/ingest/connectors/` may import
 * `src/index/`, `src/db/`, `src/audit/`, or `src/write/` — the sink is their
 * whole write surface, the SourceState their whole drift surface, and
 * ConnectorContext.config their whole source-query surface.
 *
 * Imports ONLY ../types.js (via the re-exports below) — no kernel internals.
 */

export { makeIngestSink, importKind, INGEST_ACTOR } from "./sink.js";
export type { MakeIngestSinkArgs } from "./sink.js";
export { IngestValidationError, validateIngestRecord } from "./validation.js";
export { runImport, aggregate } from "./runner.js";
export type { AggregateCounts } from "./runner.js";
export {
  CompanyFileValidationError,
  MAX_COMPANY_FILE_BYTES,
  MAX_COMPANY_FILE_CHUNK_BYTES,
  MAX_COMPANY_FILE_BUSINESS_FUNCTION_BYTES,
  MAX_COMPANY_FILE_DESCRIPTION_BYTES,
  MAX_COMPANY_FILE_NAME_BYTES,
  MAX_COMPANY_FILE_PURPOSE_BYTES,
  parseCompanyFileInput,
} from "./company-file.js";
export type { CompanyFileInput } from "./company-file.js";

/**
 * The forbidden relative-import patterns for files under
 * `src/ingest/importers/` and `src/ingest/connectors/` (D10). Each regex is
 * matched against the raw source text of a candidate file; a hit is a boundary
 * violation. Kept deliberately loose (matches `../index/`, `../../index/`, …)
 * so a deeper directory nesting can't sneak past.
 *
 * The src-root barrel (`../../index.js`) and the kernel facade
 * (`../../kernel.js`) are ALSO forbidden: the barrel re-exports `performWrite`
 * (the write-path free function) and `Kernel` (whose public `db` is a raw Db
 * handle), so an importer/connector reaching either evades the sink and writes
 * the store directly — the exact D10 bypass. These two patterns close that door
 * (they must not match the legitimate `../../types.js` seam).
 */
export const FORBIDDEN_INGEST_IMPORTS: readonly RegExp[] = [
  /\.\.\/index\//,
  /\.\.\/db\//,
  /\.\.\/audit\//,
  /\.\.\/write\//,
  /\.\.\/index\.js/,
  /\.\.\/kernel(\.js)?/,
];
