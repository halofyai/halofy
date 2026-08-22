import type {
  ConnectorContext,
  ConnectorCursor,
  EnterpriseConnector,
  SyncResult,
} from "../../types.js";
import type {
  ObsidianIngressPayload,
  ObsidianNoteRecord,
  ObsidianPropertyValue,
} from "../obsidian.js";
import { syncWithDrift, type EnumeratedDoc } from "./framework.js";

const MAX_NORMALIZED_BYTES = 64 * 1_024;

interface ObsidianConfig {
  signingSecret: string;
  vaultName: string;
  includedFolders: string[];
  excludedFolders: string[];
  payload?: ObsidianIngressPayload;
}

function folderList(value: unknown, label: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100 || value.some((item) =>
    typeof item !== "string" || item.length > 512 || item.startsWith("/") ||
    item.includes("\\") || item.split("/").some((part) => !part || part === "." || part === ".." ||
      part.startsWith(".")))) {
    throw new Error(`obsidian ${label} are invalid`);
  }
  return [...new Set((value as string[]).map((item) => item.replace(/\/$/, "")))].sort();
}

function readConfig(config: Record<string, unknown>): ObsidianConfig {
  const signingSecret = config.signingSecret;
  const vaultName = config.vaultName;
  if (typeof signingSecret !== "string" || signingSecret.length < 43) {
    throw new Error("obsidian signing secret is unavailable");
  }
  if (typeof vaultName !== "string" || vaultName.trim().length < 1 || vaultName.length > 120 ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(vaultName)) {
    throw new Error("obsidian vault name is invalid");
  }
  const payload = config.payload;
  if (payload !== undefined && (!payload || typeof payload !== "object" ||
      !Number.isSafeInteger((payload as ObsidianIngressPayload).sequence))) {
    throw new Error("obsidian authenticated payload is invalid");
  }
  return {
    signingSecret,
    vaultName: vaultName.trim(),
    includedFolders: folderList(config.includedFolders, "included folders"),
    excludedFolders: folderList(config.excludedFolders, "excluded folders"),
    ...(payload ? { payload: payload as ObsidianIngressPayload } : {}),
  };
}

function under(path: string, folder: string): boolean {
  return path === folder || path.startsWith(`${folder}/`);
}

function allowed(path: string, config: ObsidianConfig): boolean {
  const segments = path.split("/");
  if (segments.some((segment) => segment.startsWith("."))) return false;
  if (config.includedFolders.length > 0 &&
      !config.includedFolders.some((folder) => under(path, folder))) return false;
  return !config.excludedFolders.some((folder) => under(path, folder));
}

function propertyText(value: ObsidianPropertyValue): string {
  return JSON.stringify(value);
}

function normalize(record: ObsidianNoteRecord, config: ObsidianConfig): EnumeratedDoc {
  const sections = [`Obsidian note: ${record.path}`, `Vault: ${config.vaultName}`];
  const properties = Object.entries(record.properties ?? {}).sort(([left], [right]) =>
    left.localeCompare(right));
  if (properties.length > 0) {
    sections.push("Properties:\n" + properties.map(([key, value]) =>
      `- ${key}: ${propertyText(value)}`).join("\n"));
  }
  const links = [...new Set(record.links ?? [])].sort();
  if (links.length > 0) sections.push("Outgoing note links:\n" + links.map((link) => `- ${link}`).join("\n"));
  sections.push(`Content:\n${record.content}`);
  const content = sections.join("\n\n");
  if (Buffer.byteLength(content, "utf8") > MAX_NORMALIZED_BYTES) {
    throw new Error(`obsidian note '${record.path}' exceeds the normalized document limit`);
  }
  return {
    docId: record.path,
    content,
    scope: "org",
    verbatim: false,
    ...(record.modifiedAt ? { eventTime: record.modifiedAt } : {}),
  };
}

function cursorSequence(cursor: ConnectorCursor | null): number {
  if (!cursor) return 0;
  try {
    const parsed = JSON.parse(cursor.value) as Record<string, unknown>;
    if (parsed.version === 1 && Number.isSafeInteger(parsed.sequence) && Number(parsed.sequence) >= 0) {
      return Number(parsed.sequence);
    }
  } catch {
    // Fixed failure below keeps cursor details out of errors.
  }
  throw new Error("obsidian cursor is invalid");
}

function emptyResult(sourceId: string): SyncResult {
  return {
    sourceId,
    records: 0,
    stored: 0,
    deduplicated: 0,
    superseded: 0,
    rejected: 0,
    disputed: 0,
    errors: [],
    scanned: 0,
    changed: 0,
    unchanged: 0,
    removed: [],
  };
}

export class ObsidianConnector implements EnterpriseConnector {
  readonly kind = "obsidian_vault" as const;
  readonly version = "halomem-connector/v1" as const;

  capabilities() {
    return {
      incremental: true,
      liveQuery: false,
      sourceAcl: false,
      webhook: true,
      oauth: false,
    };
  }

  available(config: Record<string, unknown>): boolean {
    try {
      readConfig(config);
      return true;
    } catch {
      return false;
    }
  }

  async validateConfig(config: Record<string, unknown>): Promise<void> {
    readConfig(config);
  }

  async testConnection(config: Record<string, unknown>): Promise<{ ok: boolean; detail?: string }> {
    try {
      readConfig(config);
      return { ok: true, detail: "awaiting-signed-plugin-ingress" };
    } catch {
      return { ok: false, detail: "obsidian-pairing-unavailable" };
    }
  }

  async sync(ctx: ConnectorContext): Promise<SyncResult> {
    return (await this.syncIncremental(ctx, null)).result;
  }

  async syncIncremental(ctx: ConnectorContext, cursor: ConnectorCursor | null): Promise<{
    result: SyncResult;
    cursor: ConnectorCursor | null;
  }> {
    const config = readConfig(ctx.config);
    const payload = config.payload;
    if (!payload) throw new Error("obsidian authenticated payload is required");
    const priorSequence = cursorSequence(cursor);
    if (payload.sequence !== priorSequence + 1) {
      throw new Error("obsidian batch sequence is not the next expected value");
    }

    let result: SyncResult;
    if (payload.kind === "changes") {
      const records = payload.records
        .filter((record) => allowed(record.path, config))
        .map((record) => normalize(record, config));
      result = await syncWithDrift(ctx, async () => records, { detectRemovals: false });
      if (result.rejected > 0 && result.errors.length === 0) {
        result.errors.push({
          docId: "obsidian-batch",
          reason: "one or more Obsidian note facts were rejected",
        });
      }
      const deleted = payload.deleted.filter((path) => allowed(path, config));
      if (result.errors.length === 0 && result.rejected === 0 && deleted.length > 0) {
        await ctx.state.forget(deleted);
        result.removed = deleted;
      }
    } else {
      const manifest = new Set(payload.paths.filter((path) => allowed(path, config)));
      const known = await ctx.state.knownDocIds();
      const removed = known.filter((path) => !manifest.has(path));
      if (removed.length > 0) await ctx.state.forget(removed);
      result = {
        ...emptyResult(ctx.sink.sourceId),
        scanned: manifest.size,
        unchanged: manifest.size,
        removed,
      };
    }
    return {
      result,
      cursor: result.errors.length === 0 && result.rejected === 0
        ? {
            value: JSON.stringify({ version: 1, sequence: payload.sequence }),
            updatedAt: new Date().toISOString(),
          }
        : cursor,
    };
  }
}
