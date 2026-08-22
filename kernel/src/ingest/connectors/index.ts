/**
 * Module C — connector barrel. Re-exports the drift engine and the two
 * credential-free connectors, plus a partial `CONNECTORS` registry keyed by
 * SourceKind. The integrator adds notion/slack (module D) to this map.
 *
 * D10: imports ONLY the local connector modules (which themselves import only
 * ../../types.js + stdlib + gray-matter/pg). No src/index, src/db, src/audit,
 * src/write.
 */

import type { Connector, SourceKind } from "../../types.js";
import type { NangoProxyService } from "../nango.js";
import { FilesystemConnector } from "./filesystem.js";
import { PostgresConnector } from "./postgres.js";
import { NotionConnector } from "./notion.js";
import { GoogleDriveDirectConnector } from "./google-drive-direct.js";
import { ObsidianConnector } from "./obsidian.js";
import { SlackConnector } from "./slack.js";
import { ConnectorRegistry } from "./registry.js";
import { makePlatformConnectors } from "./catalog/index.js";

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
export { NotionConnector, type NotionConfig, type NotionPage } from "./notion.js";
export { GoogleDriveDirectConnector } from "./google-drive-direct.js";
export { ObsidianConnector } from "./obsidian.js";
export {
  LOCAL_CONNECTOR_CARDS,
  isLocalConnectorId,
  publicLocalConnectorCard,
  type LocalConnectorCard,
} from "./local-catalog.js";
export {
  AirtableDirectConnector,
  type AirtableDirectConfig,
  type AirtableSnapshot,
} from "./airtable-direct.js";
export { SlackConnector, type SlackConfig, type SlackMessage } from "./slack.js";
export {
  PLATFORM_CONNECTOR_CATALOG,
  connectorCatalogEntry,
  isPlatformConnectorId,
  makePlatformConnectors,
} from "./catalog/index.js";

/** Fresh registry so callers cannot mutate a process-global cartridge catalog. */
export function makeBuiltinConnectorRegistry(
  nangoProxy?: Pick<NangoProxyService, "proxyRequestConfiguration">,
  notionFetch?: typeof fetch,
  googleDriveFetch?: typeof fetch,
): ConnectorRegistry {
  return new ConnectorRegistry([
    new FilesystemConnector(),
    new PostgresConnector(),
    new NotionConnector(),
    new SlackConnector(),
    ...makePlatformConnectors(nangoProxy),
    new NotionConnector("notion_direct", notionFetch),
    new GoogleDriveDirectConnector(googleDriveFetch ?? fetch),
    new GoogleDriveDirectConnector(googleDriveFetch ?? fetch, {
      kind: "google_docs_direct",
      allowedMimeTypes: ["application/vnd.google-apps.document"],
    }),
    new GoogleDriveDirectConnector(googleDriveFetch ?? fetch, {
      kind: "google_sheets_direct",
      allowedMimeTypes: ["application/vnd.google-apps.spreadsheet"],
    }),
    new ObsidianConnector(),
  ]);
}

/**
 * Partial map of the credential-free connectors. The integrator merges the
 * network connectors (notion/slack) in when wiring the kernel.
 */
export const CONNECTORS: Partial<Record<SourceKind, Connector>> = {
  filesystem: new FilesystemConnector(),
  postgres: new PostgresConnector(),
};
