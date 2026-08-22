/**
 * Module B barrel — bulk importers of vendor dumps.
 *
 * D10: importers only produce `IngestRecord[]`; the kernel feeds them through
 * an `IngestSink` so imported data gets the SAME extraction / verification /
 * dedupe / supersedence / provenance as agent conversation. These files import
 * only shared types + `node:crypto` — never the store, write path, or audit.
 */

import type { Importer, SourceKind } from "../../types.js";
import { Mem0Importer } from "./mem0.js";
import { PgvectorImporter } from "./pgvector.js";

export { Mem0Importer } from "./mem0.js";
export { PgvectorImporter } from "./pgvector.js";

/**
 * Registry of the import-kind SourceKinds → their Importer. Keyed by
 * `SourceKind` (partial: the four connector kinds are not importers). The
 * kernel's `importDump(kind, raw, identity)` looks the importer up here.
 */
export const IMPORTERS: Partial<Record<SourceKind, Importer>> = {
  "mem0-import": new Mem0Importer(),
  "pgvector-import": new PgvectorImporter(),
};
