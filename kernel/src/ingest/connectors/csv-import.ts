import type {
  ConnectorContext,
  EnterpriseConnector,
  SyncResult,
} from "../../types.js";
import { syncWithDrift, type EnumeratedDoc } from "./framework.js";

function assertConfig(config: Record<string, unknown>): void {
  const selected = config.selectedDataPoints;
  if (!Array.isArray(selected) || selected.length !== 1 || selected[0] !== "mapped_rows") {
    throw new Error("CSV import requires the mapped_rows data point");
  }
  if (config.sourceAccessMode !== "namespace-open") {
    throw new Error("CSV import requires explicit namespace-open source access");
  }
}

/**
 * Registration cartridge for the authenticated CSV snapshot boundary.
 *
 * CSV sources are never polled: `Kernel.importCsvSource()` parses the caller's
 * bounded snapshot and writes its fixed row envelope through the normal ingest
 * sink. This cartridge exists so registration still receives the same
 * conformance and access-policy checks as every other source.
 */
export class CsvSheetImportConnector implements EnterpriseConnector {
  readonly kind = "csv_sheet_import" as const;
  readonly version = "halomem-connector/v1" as const;

  capabilities() {
    return {
      incremental: false,
      liveQuery: false,
      sourceAcl: false,
      webhook: false,
      oauth: false,
    };
  }

  available(config: Record<string, unknown>): boolean {
    try {
      assertConfig(config);
      return true;
    } catch {
      return false;
    }
  }

  async validateConfig(config: Record<string, unknown>): Promise<void> {
    assertConfig(config);
  }

  async testConnection(
    config: Record<string, unknown>,
  ): Promise<{ ok: boolean; detail?: string }> {
    try {
      assertConfig(config);
      return { ok: true, detail: "ready-for-authenticated-snapshot" };
    } catch {
      return { ok: false, detail: "invalid-csv-import-configuration" };
    }
  }

  async sync(ctx: ConnectorContext): Promise<SyncResult> {
    assertConfig(ctx.config);
    if (!Array.isArray(ctx.config.records)) {
      throw new Error("CSV import requires authenticated snapshot records");
    }
    const records = ctx.config.records.map((value, index): EnumeratedDoc => {
      if (!value || typeof value !== "object") {
        throw new Error(`CSV import record ${index + 1} is invalid`);
      }
      const record = value as Record<string, unknown>;
      if (typeof record.id !== "string" || typeof record.text !== "string") {
        throw new Error(`CSV import record ${index + 1} is invalid`);
      }
      return {
        docId: `csv_sheet_import:mapped_rows:${record.id}`,
        content: record.text,
        scope: "org",
        verbatim: true,
        ...(typeof record.updatedAt === "string" ? { eventTime: record.updatedAt } : {}),
      };
    });
    return syncWithDrift(ctx, async () => records);
  }
}
