/**
 * Public connector barrel. Re-exports the drift engine and the standalone
 * filesystem, Postgres, Obsidian, and manual CSV cartridges, plus a partial
 * `CONNECTORS` registry keyed by SourceKind.
 *
 * D10: imports ONLY the local connector modules (which themselves import only
 * ../../types.js + stdlib + gray-matter/pg). No src/index, src/db, src/audit,
 * src/write.
 */

import type { Connector, SourceKind } from "../../types.js";
import { FilesystemConnector } from "./filesystem.js";
import { PostgresConnector } from "./postgres.js";
import { ObsidianConnector } from "./obsidian.js";
import { CsvSheetImportConnector } from "./csv-import.js";
import { ConnectorRegistry } from "./registry.js";

export { syncWithDrift, sha256hex, type EnumeratedDoc } from "./framework.js";
export {
  ConnectorConformanceError,
  ConnectorRegistry,
  validateConnectorConformance,
} from "./registry.js";
export {
  ConnectorLifecycle,
  type ConnectorLifecycleRecord,
  type ConnectorLifecycleState,
  type ConnectorLifecycleStore,
  type CreateConnectorInput,
  type SyncJobScheduler,
} from "./lifecycle.js";
export { FilesystemConnector } from "./filesystem.js";
export { PostgresConnector, type QueryFn } from "./postgres.js";
export { ObsidianConnector } from "./obsidian.js";
export { CsvSheetImportConnector } from "./csv-import.js";

/** Fresh registry so callers cannot mutate a process-global cartridge catalog. */
export function makeBuiltinConnectorRegistry(): ConnectorRegistry {
  return new ConnectorRegistry([
    new FilesystemConnector(),
    new PostgresConnector(),
    new ObsidianConnector(),
    new CsvSheetImportConnector(),
  ]);
}

/**
 * Partial map of the connectors shipped by the standalone composition.
 */
export const CONNECTORS: Partial<Record<SourceKind, Connector>> = {
  filesystem: new FilesystemConnector(),
  postgres: new PostgresConnector(),
  obsidian_vault: new ObsidianConnector(),
  csv_sheet_import: new CsvSheetImportConnector(),
};
