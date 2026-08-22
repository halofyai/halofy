import {
  Notice,
  Plugin,
  PluginSettingTab,
  Setting,
  TFile,
  type App,
  type CachedMetadata,
  requestUrl,
} from "obsidian";

import {
  batchChanges,
  isAllowedMarkdownPath,
  MAX_CHANGE_RECORDS,
  serverClockOffsetMs,
  serverTimestampMs,
} from "./sync-policy.js";

const MAX_CONTENT_BYTES = 40 * 1024;
const MAX_BODY_BYTES = 1_048_576;
const MAX_MANIFEST_PATHS = 20_000;
const RETRY_MS = 15_000;
const CLOCK_OFFSET_TTL_MS = 60_000;

interface HaloMemSettings {
  endpoint: string;
  sourceId: string;
  secretId: string;
  sequence: number;
  includedFolders: string[];
  excludedFolders: string[];
  lastSyncAt: string;
  lastError: string;
}

interface PairingBundle {
  version: 1;
  endpoint: string;
  sourceId: string;
  secret: string;
  includedFolders?: string[];
  excludedFolders?: string[];
}

type PropertyValue = string | number | boolean | null |
  Array<string | number | boolean | null>;

interface NoteRecord {
  path: string;
  content: string;
  modifiedAt: string;
  properties?: Record<string, PropertyValue>;
  links?: string[];
}

const DEFAULT_SETTINGS: HaloMemSettings = {
  endpoint: "",
  sourceId: "",
  secretId: "",
  sequence: 0,
  includedFolders: [],
  excludedFolders: [],
  lastSyncAt: "",
  lastError: "",
};

function folderList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100) throw new Error("Pairing folders are invalid");
  const folders = value.map((item) => {
    if (typeof item !== "string") throw new Error("Pairing folders are invalid");
    const folder = item.trim().replace(/\/$/, "");
    if (!folder || folder.length > 512 || folder.startsWith("/") || folder.includes("\\") ||
        folder.split("/").some((part) => !part || part === "." || part === ".." || part.startsWith("."))) {
      throw new Error("Pairing folders are invalid");
    }
    return folder;
  });
  return [...new Set(folders)].sort();
}

function parsePairing(raw: string): PairingBundle {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Pairing bundle is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Pairing bundle is invalid");
  }
  const input = value as Record<string, unknown>;
  const keys = Object.keys(input);
  if (!keys.every((key) => [
    "version", "endpoint", "sourceId", "secret", "includedFolders", "excludedFolders",
  ].includes(key)) || input.version !== 1 || typeof input.endpoint !== "string" ||
      typeof input.sourceId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(input.sourceId) ||
      typeof input.secret !== "string" || input.secret.length < 43) {
    throw new Error("Pairing bundle is invalid");
  }
  const endpoint = new URL(input.endpoint);
  if (endpoint.username || endpoint.password ||
      (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" &&
        ["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname)))) {
    throw new Error("Pairing endpoint must use HTTPS (or localhost HTTP)");
  }
  if (!endpoint.pathname.endsWith(`/v1/ingest/obsidian/${encodeURIComponent(input.sourceId)}`)) {
    throw new Error("Pairing endpoint and source ID do not match");
  }
  if (endpoint.search || endpoint.hash) throw new Error("Pairing endpoint must not contain a query or fragment");
  return {
    version: 1,
    endpoint: endpoint.href,
    sourceId: input.sourceId,
    secret: input.secret,
    includedFolders: folderList(input.includedFolders ?? []),
    excludedFolders: folderList(input.excludedFolders ?? []),
  };
}

function scalar(value: unknown): value is string | number | boolean | null {
  return value === null || typeof value === "string" || typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value));
}

function properties(cache: CachedMetadata | null): Record<string, PropertyValue> | undefined {
  const source = cache?.frontmatter;
  if (!source || typeof source !== "object") return undefined;
  const output: Record<string, PropertyValue> = {};
  for (const [key, value] of Object.entries(source).sort(([a], [b]) => a.localeCompare(b))) {
    if (key === "position" || !key || key.length > 128 || Object.keys(output).length >= 100) continue;
    if (scalar(value)) output[key] = value;
    else if (Array.isArray(value) && value.length <= 100 && value.every(scalar)) output[key] = value;
    if (new TextEncoder().encode(JSON.stringify(output)).byteLength > 7_500) {
      delete output[key];
      break;
    }
  }
  return Object.keys(output).length > 0 ? output : undefined;
}

function outgoingLinks(cache: CachedMetadata | null): string[] | undefined {
  const links = [...(cache?.links ?? []), ...(cache?.embeds ?? [])]
    .map((link) => String(link.link || "").trim())
    .filter(Boolean);
  const unique = [...new Set(links)].sort().slice(0, 100);
  while (unique.length > 0 && new TextEncoder().encode(JSON.stringify(unique)).byteLength > 7_500) {
    unique.pop();
  }
  return unique.length > 0 ? unique : undefined;
}

function hmacKeyBytes(secret: string): ArrayBuffer {
  return new TextEncoder().encode(secret).buffer as ArrayBuffer;
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function responseHeader(
  headers: Readonly<Record<string, string>>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}

export default class HaloMemSyncPlugin extends Plugin {
  settings: HaloMemSettings = { ...DEFAULT_SETTINGS };
  private pendingRecords = new Set<string>();
  private pendingDeletes = new Set<string>();
  private flushTimer: number | null = null;
  private pipeline: Promise<void> = Promise.resolve();
  private clockOffsetMs = 0;
  private clockOffsetMeasuredAt = 0;

  async onload(): Promise<void> {
    this.settings = { ...DEFAULT_SETTINGS, ...await this.loadData() as Partial<HaloMemSettings> };
    this.addSettingTab(new HaloMemSettingTab(this.app, this));
    this.addCommand({
      id: "sync-vault-now",
      name: "Sync paired vault now",
      callback: () => {
        void this.syncNow(true).catch((error: unknown) => {
          new Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
        });
      },
    });
    this.registerEvent(this.app.vault.on("create", (file) => {
      if (file instanceof TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.registerEvent(this.app.vault.on("modify", (file) => {
      if (file instanceof TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.registerEvent(this.app.vault.on("delete", (file) => {
      if (file instanceof TFile && file.extension === "md") this.queueDelete(file.path);
    }));
    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => {
      if (oldPath.toLowerCase().endsWith(".md")) this.queueDelete(oldPath);
      if (file instanceof TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.app.workspace.onLayoutReady(() => {
      if (this.isPaired()) {
        void this.syncNow(false).catch((error: unknown) => {
          new Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
        });
      }
    });
  }

  onunload(): void {
    if (this.flushTimer !== null) window.clearTimeout(this.flushTimer);
  }

  private isPaired(): boolean {
    return Boolean(this.settings.endpoint && this.settings.sourceId && this.settings.secretId);
  }

  private allowed(path: string): boolean {
    return isAllowedMarkdownPath(
      path,
      this.app.vault.configDir,
      this.settings.includedFolders,
      this.settings.excludedFolders,
    );
  }

  private enqueue(task: () => Promise<void>): Promise<void> {
    const run = this.pipeline.then(task);
    this.pipeline = run.catch(async (error: unknown) => {
      this.settings.lastError = error instanceof Error ? error.message : "Sync failed";
      await this.saveData(this.settings);
    });
    return run;
  }

  private queueRecord(path: string): void {
    if (!this.isPaired() || !this.allowed(path)) return;
    this.pendingDeletes.delete(path);
    this.pendingRecords.add(path);
    this.scheduleFlush();
  }

  private queueDelete(path: string): void {
    if (!this.isPaired() || !this.allowed(path)) return;
    this.pendingRecords.delete(path);
    this.pendingDeletes.add(path);
    this.scheduleFlush();
  }

  private scheduleFlush(delay = 2_000): void {
    if (this.flushTimer !== null) window.clearTimeout(this.flushTimer);
    this.flushTimer = window.setTimeout(() => {
      this.flushTimer = null;
      void this.enqueue(async () => this.flushChanges()).catch(() => undefined);
    }, delay);
  }

  private async noteRecord(file: TFile): Promise<NoteRecord | null> {
    const content = await this.app.vault.cachedRead(file);
    if (new TextEncoder().encode(content).byteLength > MAX_CONTENT_BYTES) return null;
    const cache = this.app.metadataCache.getFileCache(file);
    const frontmatter = properties(cache);
    const links = outgoingLinks(cache);
    return {
      path: file.path,
      content,
      modifiedAt: new Date(file.stat.mtime).toISOString(),
      ...(frontmatter ? { properties: frontmatter } : {}),
      ...(links ? { links } : {}),
    };
  }

  private async flushChanges(): Promise<void> {
    if (!this.isPaired()) return;
    const recordPaths = [...this.pendingRecords].sort();
    const deleted = [...this.pendingDeletes].sort();
    this.pendingRecords.clear();
    this.pendingDeletes.clear();
    const records: NoteRecord[] = [];
    try {
      for (const path of recordPaths) {
        const file = this.app.vault.getFileByPath(path);
        if (!file) {
          deleted.push(path);
          continue;
        }
        const record = await this.noteRecord(file);
        if (record) records.push(record);
        else deleted.push(path);
      }
      for (const batch of batchChanges(records, [...new Set(deleted)])) {
        await this.send({
          version: 1,
          sequence: this.settings.sequence + 1,
          kind: "changes",
          records: batch.records,
          deleted: batch.deleted,
        });
      }
    } catch (error) {
      for (const path of recordPaths) this.pendingRecords.add(path);
      for (const path of deleted) this.pendingDeletes.add(path);
      this.scheduleFlush(RETRY_MS);
      throw error;
    }
  }

  async applyPairing(raw: string): Promise<void> {
    const bundle = parsePairing(raw);
    await this.pipeline;
    const secretId = `halomem-${bundle.sourceId.toLowerCase()}`;
    this.app.secretStorage.setSecret(secretId, bundle.secret);
    this.settings = {
      ...DEFAULT_SETTINGS,
      endpoint: bundle.endpoint,
      sourceId: bundle.sourceId,
      secretId,
      includedFolders: bundle.includedFolders ?? [],
      excludedFolders: bundle.excludedFolders ?? [],
    };
    this.clockOffsetMs = 0;
    this.clockOffsetMeasuredAt = 0;
    await this.saveData(this.settings);
    await this.syncNow(true);
  }

  async syncNow(notify: boolean): Promise<void> {
    return this.enqueue(async () => this.fullSync(notify));
  }

  async fullSync(notify: boolean): Promise<void> {
    if (!this.isPaired()) throw new Error("Paste a HaloMem pairing bundle in settings first");
    const files = this.app.vault.getMarkdownFiles()
      .filter((file) => this.allowed(file.path))
      .sort((left, right) => left.path.localeCompare(right.path));
    if (files.length > MAX_MANIFEST_PATHS) throw new Error("Selected vault exceeds 20,000 notes");
    let skipped = 0;
    const manifestPaths: string[] = [];
    for (let offset = 0; offset < files.length; offset += MAX_CHANGE_RECORDS) {
      const records: NoteRecord[] = [];
      for (const file of files.slice(offset, offset + MAX_CHANGE_RECORDS)) {
        const record = await this.noteRecord(file);
        if (record) {
          records.push(record);
          manifestPaths.push(file.path);
        }
        else skipped += 1;
      }
      if (records.length > 0) {
        await this.send({
          version: 1,
          sequence: this.settings.sequence + 1,
          kind: "changes",
          records,
          deleted: [],
        });
      }
    }
    await this.send({
      version: 1,
      sequence: this.settings.sequence + 1,
      kind: "manifest",
      paths: manifestPaths,
    });
    if (notify) {
      new Notice(`HaloMem Sync completed: ${files.length - skipped} notes${skipped ? `, ${skipped} oversized notes skipped` : ""}`);
    }
  }

  private async signingTimestamp(forceRefresh = false): Promise<number> {
    const localNow = Date.now();
    const measurementAge = localNow - this.clockOffsetMeasuredAt;
    if (!forceRefresh && this.clockOffsetMeasuredAt > 0 && measurementAge >= 0 &&
        measurementAge < CLOCK_OFFSET_TTL_MS) {
      return serverTimestampMs(localNow, this.clockOffsetMs);
    }

    const healthUrl = new URL("/healthz", this.settings.endpoint);
    healthUrl.searchParams.set("obsidian-clock-probe", String(localNow));
    const startedAt = Date.now();
    try {
      const response = await requestUrl({
        url: healthUrl.href,
        method: "GET",
        headers: { "cache-control": "no-cache" },
        throw: false,
      });
      const finishedAt = Date.now();
      this.clockOffsetMs = response.status >= 200 && response.status < 300
        ? serverClockOffsetMs(responseHeader(response.headers, "date"), startedAt, finishedAt)
        : 0;
      this.clockOffsetMeasuredAt = finishedAt;
    } catch {
      this.clockOffsetMs = 0;
      this.clockOffsetMeasuredAt = Date.now();
    }
    return serverTimestampMs(Date.now(), this.clockOffsetMs);
  }

  private async send(payload: Record<string, unknown>): Promise<void> {
    const secret = this.app.secretStorage.getSecret(this.settings.secretId);
    if (!secret) throw new Error("Pairing secret is missing; pair the vault again");
    const body = JSON.stringify(payload);
    if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) {
      throw new Error("Selected vault manifest exceeds the 1 MiB delivery limit");
    }
    const key = await crypto.subtle.importKey(
      "raw",
      hmacKeyBytes(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    let response;
    let timestamp = "";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      timestamp = String(await this.signingTimestamp(attempt > 0));
      const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(`${timestamp}.${body}`),
      );
      response = await requestUrl({
        url: this.settings.endpoint,
        method: "POST",
        contentType: "application/json",
        body,
        headers: {
          "x-halomem-timestamp": timestamp,
          "x-halomem-signature": `sha256=${hex(signature)}`,
        },
        throw: false,
      });
      if (response.status !== 401 || attempt > 0) break;
    }
    if (!response) throw new Error("HaloMem delivery failed");
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`HaloMem delivery failed (${response.status})`);
    }
    this.settings.sequence = Number(payload.sequence);
    this.settings.lastSyncAt = new Date(Number(timestamp)).toISOString();
    this.settings.lastError = "";
    await this.saveData(this.settings);
  }
}

class HaloMemSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: HaloMemSyncPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "HaloMem Sync" });
    containerEl.createEl("p", {
      text: "Create an Obsidian pairing in HaloMem Sources, then paste its one-time bundle here. Only selected Markdown notes are sent.",
    });
    let pairing = "";
    new Setting(containerEl)
      .setName("Pairing bundle")
      .setDesc("The secret is moved into Obsidian SecretStorage and is not retained in plugin settings.")
      .addTextArea((text) => text
        .setPlaceholder("Paste the JSON pairing bundle")
        .onChange((value) => { pairing = value; }));
    new Setting(containerEl)
      .addButton((button) => button
        .setButtonText("Pair & sync")
        .setCta()
        .onClick(async () => {
          try {
            await this.plugin.applyPairing(pairing);
            this.display();
          } catch (error) {
            new Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Pairing failed"}`);
          }
        }));
    if (this.plugin.settings.endpoint) {
      new Setting(containerEl).setName("Paired endpoint").setDesc(this.plugin.settings.endpoint);
      new Setting(containerEl).setName("Last completed delivery").setDesc(
        this.plugin.settings.lastSyncAt || "No delivery completed yet",
      );
      if (this.plugin.settings.lastError) {
        new Setting(containerEl).setName("Last error").setDesc(this.plugin.settings.lastError);
      }
      new Setting(containerEl)
        .setName("Sync now")
        .setDesc("Send all selected notes, then reconcile deleted paths.")
        .addButton((button) => button.setButtonText("Sync vault").onClick(async () => {
          try {
            await this.plugin.syncNow(true);
            this.display();
          } catch (error) {
            new Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
          }
        }));
    }
  }
}
