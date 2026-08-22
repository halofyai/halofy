"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => HaloMemSyncPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");

// src/sync-policy.ts
var MAX_CHANGE_RECORDS = 25;
var MAX_CHANGE_DELETIONS = 500;
function serverClockOffsetMs(serverDate, clientStartedAt, clientFinishedAt) {
  const serverTime = serverDate ? Date.parse(serverDate) : Number.NaN;
  if (!Number.isFinite(serverTime) || !Number.isFinite(clientStartedAt) || !Number.isFinite(clientFinishedAt) || clientFinishedAt < clientStartedAt) {
    return 0;
  }
  return Math.round(serverTime - (clientStartedAt + clientFinishedAt) / 2);
}
function serverTimestampMs(localNow, clockOffsetMs) {
  const adjusted = Math.round(localNow + clockOffsetMs);
  return Number.isSafeInteger(adjusted) ? adjusted : Math.round(localNow);
}
function under(path, folder) {
  return path === folder || path.startsWith(`${folder}/`);
}
function isAllowedMarkdownPath(path, configDir, includedFolders, excludedFolders) {
  if (!path.toLowerCase().endsWith(".md") || path.split("/").some((part) => part.startsWith(".")) || configDir && under(path, configDir)) {
    return false;
  }
  if (includedFolders.length > 0 && !includedFolders.some((folder) => under(path, folder))) return false;
  return !excludedFolders.some((folder) => under(path, folder));
}
function batchChanges(records, deleted) {
  const batches = [];
  let recordOffset = 0;
  let deletionOffset = 0;
  while (recordOffset < records.length || deletionOffset < deleted.length) {
    batches.push({
      records: records.slice(recordOffset, recordOffset + MAX_CHANGE_RECORDS),
      deleted: deleted.slice(deletionOffset, deletionOffset + MAX_CHANGE_DELETIONS)
    });
    recordOffset += MAX_CHANGE_RECORDS;
    deletionOffset += MAX_CHANGE_DELETIONS;
  }
  return batches;
}

// src/main.ts
var MAX_CONTENT_BYTES = 40 * 1024;
var MAX_BODY_BYTES = 1048576;
var MAX_MANIFEST_PATHS = 2e4;
var RETRY_MS = 15e3;
var CLOCK_OFFSET_TTL_MS = 6e4;
var DEFAULT_SETTINGS = {
  endpoint: "",
  sourceId: "",
  secretId: "",
  sequence: 0,
  includedFolders: [],
  excludedFolders: [],
  lastSyncAt: "",
  lastError: ""
};
function folderList(value) {
  if (!Array.isArray(value) || value.length > 100) throw new Error("Pairing folders are invalid");
  const folders = value.map((item) => {
    if (typeof item !== "string") throw new Error("Pairing folders are invalid");
    const folder = item.trim().replace(/\/$/, "");
    if (!folder || folder.length > 512 || folder.startsWith("/") || folder.includes("\\") || folder.split("/").some((part) => !part || part === "." || part === ".." || part.startsWith("."))) {
      throw new Error("Pairing folders are invalid");
    }
    return folder;
  });
  return [...new Set(folders)].sort();
}
function parsePairing(raw) {
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Pairing bundle is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Pairing bundle is invalid");
  }
  const input = value;
  const keys = Object.keys(input);
  if (!keys.every((key) => [
    "version",
    "endpoint",
    "sourceId",
    "secret",
    "includedFolders",
    "excludedFolders"
  ].includes(key)) || input.version !== 1 || typeof input.endpoint !== "string" || typeof input.sourceId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(input.sourceId) || typeof input.secret !== "string" || input.secret.length < 43) {
    throw new Error("Pairing bundle is invalid");
  }
  const endpoint = new URL(input.endpoint);
  if (endpoint.username || endpoint.password || endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname))) {
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
    excludedFolders: folderList(input.excludedFolders ?? [])
  };
}
function scalar(value) {
  return value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number" && Number.isFinite(value);
}
function properties(cache) {
  const source = cache?.frontmatter;
  if (!source || typeof source !== "object") return void 0;
  const output = {};
  for (const [key, value] of Object.entries(source).sort(([a], [b]) => a.localeCompare(b))) {
    if (key === "position" || !key || key.length > 128 || Object.keys(output).length >= 100) continue;
    if (scalar(value)) output[key] = value;
    else if (Array.isArray(value) && value.length <= 100 && value.every(scalar)) output[key] = value;
    if (new TextEncoder().encode(JSON.stringify(output)).byteLength > 7500) {
      delete output[key];
      break;
    }
  }
  return Object.keys(output).length > 0 ? output : void 0;
}
function outgoingLinks(cache) {
  const links = [...cache?.links ?? [], ...cache?.embeds ?? []].map((link) => String(link.link || "").trim()).filter(Boolean);
  const unique = [...new Set(links)].sort().slice(0, 100);
  while (unique.length > 0 && new TextEncoder().encode(JSON.stringify(unique)).byteLength > 7500) {
    unique.pop();
  }
  return unique.length > 0 ? unique : void 0;
}
function hmacKeyBytes(secret) {
  return new TextEncoder().encode(secret).buffer;
}
function hex(bytes) {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
function responseHeader(headers, name) {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}
var HaloMemSyncPlugin = class extends import_obsidian.Plugin {
  settings = { ...DEFAULT_SETTINGS };
  pendingRecords = /* @__PURE__ */ new Set();
  pendingDeletes = /* @__PURE__ */ new Set();
  flushTimer = null;
  pipeline = Promise.resolve();
  clockOffsetMs = 0;
  clockOffsetMeasuredAt = 0;
  async onload() {
    this.settings = { ...DEFAULT_SETTINGS, ...await this.loadData() };
    this.addSettingTab(new HaloMemSettingTab(this.app, this));
    this.addCommand({
      id: "sync-vault-now",
      name: "Sync paired vault now",
      callback: () => {
        void this.syncNow(true).catch((error) => {
          new import_obsidian.Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
        });
      }
    });
    this.registerEvent(this.app.vault.on("create", (file) => {
      if (file instanceof import_obsidian.TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.registerEvent(this.app.vault.on("modify", (file) => {
      if (file instanceof import_obsidian.TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.registerEvent(this.app.vault.on("delete", (file) => {
      if (file instanceof import_obsidian.TFile && file.extension === "md") this.queueDelete(file.path);
    }));
    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => {
      if (oldPath.toLowerCase().endsWith(".md")) this.queueDelete(oldPath);
      if (file instanceof import_obsidian.TFile && file.extension === "md") this.queueRecord(file.path);
    }));
    this.app.workspace.onLayoutReady(() => {
      if (this.isPaired()) {
        void this.syncNow(false).catch((error) => {
          new import_obsidian.Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
        });
      }
    });
  }
  onunload() {
    if (this.flushTimer !== null) window.clearTimeout(this.flushTimer);
  }
  isPaired() {
    return Boolean(this.settings.endpoint && this.settings.sourceId && this.settings.secretId);
  }
  allowed(path) {
    return isAllowedMarkdownPath(
      path,
      this.app.vault.configDir,
      this.settings.includedFolders,
      this.settings.excludedFolders
    );
  }
  enqueue(task) {
    const run = this.pipeline.then(task);
    this.pipeline = run.catch(async (error) => {
      this.settings.lastError = error instanceof Error ? error.message : "Sync failed";
      await this.saveData(this.settings);
    });
    return run;
  }
  queueRecord(path) {
    if (!this.isPaired() || !this.allowed(path)) return;
    this.pendingDeletes.delete(path);
    this.pendingRecords.add(path);
    this.scheduleFlush();
  }
  queueDelete(path) {
    if (!this.isPaired() || !this.allowed(path)) return;
    this.pendingRecords.delete(path);
    this.pendingDeletes.add(path);
    this.scheduleFlush();
  }
  scheduleFlush(delay = 2e3) {
    if (this.flushTimer !== null) window.clearTimeout(this.flushTimer);
    this.flushTimer = window.setTimeout(() => {
      this.flushTimer = null;
      void this.enqueue(async () => this.flushChanges()).catch(() => void 0);
    }, delay);
  }
  async noteRecord(file) {
    const content = await this.app.vault.cachedRead(file);
    if (new TextEncoder().encode(content).byteLength > MAX_CONTENT_BYTES) return null;
    const cache = this.app.metadataCache.getFileCache(file);
    const frontmatter = properties(cache);
    const links = outgoingLinks(cache);
    return {
      path: file.path,
      content,
      modifiedAt: new Date(file.stat.mtime).toISOString(),
      ...frontmatter ? { properties: frontmatter } : {},
      ...links ? { links } : {}
    };
  }
  async flushChanges() {
    if (!this.isPaired()) return;
    const recordPaths = [...this.pendingRecords].sort();
    const deleted = [...this.pendingDeletes].sort();
    this.pendingRecords.clear();
    this.pendingDeletes.clear();
    const records = [];
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
          deleted: batch.deleted
        });
      }
    } catch (error) {
      for (const path of recordPaths) this.pendingRecords.add(path);
      for (const path of deleted) this.pendingDeletes.add(path);
      this.scheduleFlush(RETRY_MS);
      throw error;
    }
  }
  async applyPairing(raw) {
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
      excludedFolders: bundle.excludedFolders ?? []
    };
    this.clockOffsetMs = 0;
    this.clockOffsetMeasuredAt = 0;
    await this.saveData(this.settings);
    await this.syncNow(true);
  }
  async syncNow(notify) {
    return this.enqueue(async () => this.fullSync(notify));
  }
  async fullSync(notify) {
    if (!this.isPaired()) throw new Error("Paste a HaloMem pairing bundle in settings first");
    const files = this.app.vault.getMarkdownFiles().filter((file) => this.allowed(file.path)).sort((left, right) => left.path.localeCompare(right.path));
    if (files.length > MAX_MANIFEST_PATHS) throw new Error("Selected vault exceeds 20,000 notes");
    let skipped = 0;
    const manifestPaths = [];
    for (let offset = 0; offset < files.length; offset += MAX_CHANGE_RECORDS) {
      const records = [];
      for (const file of files.slice(offset, offset + MAX_CHANGE_RECORDS)) {
        const record = await this.noteRecord(file);
        if (record) {
          records.push(record);
          manifestPaths.push(file.path);
        } else skipped += 1;
      }
      if (records.length > 0) {
        await this.send({
          version: 1,
          sequence: this.settings.sequence + 1,
          kind: "changes",
          records,
          deleted: []
        });
      }
    }
    await this.send({
      version: 1,
      sequence: this.settings.sequence + 1,
      kind: "manifest",
      paths: manifestPaths
    });
    if (notify) {
      new import_obsidian.Notice(`HaloMem Sync completed: ${files.length - skipped} notes${skipped ? `, ${skipped} oversized notes skipped` : ""}`);
    }
  }
  async signingTimestamp(forceRefresh = false) {
    const localNow = Date.now();
    const measurementAge = localNow - this.clockOffsetMeasuredAt;
    if (!forceRefresh && this.clockOffsetMeasuredAt > 0 && measurementAge >= 0 && measurementAge < CLOCK_OFFSET_TTL_MS) {
      return serverTimestampMs(localNow, this.clockOffsetMs);
    }
    const healthUrl = new URL("/healthz", this.settings.endpoint);
    healthUrl.searchParams.set("obsidian-clock-probe", String(localNow));
    const startedAt = Date.now();
    try {
      const response = await (0, import_obsidian.requestUrl)({
        url: healthUrl.href,
        method: "GET",
        headers: { "cache-control": "no-cache" },
        throw: false
      });
      const finishedAt = Date.now();
      this.clockOffsetMs = response.status >= 200 && response.status < 300 ? serverClockOffsetMs(responseHeader(response.headers, "date"), startedAt, finishedAt) : 0;
      this.clockOffsetMeasuredAt = finishedAt;
    } catch {
      this.clockOffsetMs = 0;
      this.clockOffsetMeasuredAt = Date.now();
    }
    return serverTimestampMs(Date.now(), this.clockOffsetMs);
  }
  async send(payload) {
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
      ["sign"]
    );
    let response;
    let timestamp = "";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      timestamp = String(await this.signingTimestamp(attempt > 0));
      const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(`${timestamp}.${body}`)
      );
      response = await (0, import_obsidian.requestUrl)({
        url: this.settings.endpoint,
        method: "POST",
        contentType: "application/json",
        body,
        headers: {
          "x-halomem-timestamp": timestamp,
          "x-halomem-signature": `sha256=${hex(signature)}`
        },
        throw: false
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
};
var HaloMemSettingTab = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "HaloMem Sync" });
    containerEl.createEl("p", {
      text: "Create an Obsidian pairing in HaloMem Sources, then paste its one-time bundle here. Only selected Markdown notes are sent."
    });
    let pairing = "";
    new import_obsidian.Setting(containerEl).setName("Pairing bundle").setDesc("The secret is moved into Obsidian SecretStorage and is not retained in plugin settings.").addTextArea((text) => text.setPlaceholder("Paste the JSON pairing bundle").onChange((value) => {
      pairing = value;
    }));
    new import_obsidian.Setting(containerEl).addButton((button) => button.setButtonText("Pair & sync").setCta().onClick(async () => {
      try {
        await this.plugin.applyPairing(pairing);
        this.display();
      } catch (error) {
        new import_obsidian.Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Pairing failed"}`);
      }
    }));
    if (this.plugin.settings.endpoint) {
      new import_obsidian.Setting(containerEl).setName("Paired endpoint").setDesc(this.plugin.settings.endpoint);
      new import_obsidian.Setting(containerEl).setName("Last completed delivery").setDesc(
        this.plugin.settings.lastSyncAt || "No delivery completed yet"
      );
      if (this.plugin.settings.lastError) {
        new import_obsidian.Setting(containerEl).setName("Last error").setDesc(this.plugin.settings.lastError);
      }
      new import_obsidian.Setting(containerEl).setName("Sync now").setDesc("Send all selected notes, then reconcile deleted paths.").addButton((button) => button.setButtonText("Sync vault").onClick(async () => {
        try {
          await this.plugin.syncNow(true);
          this.display();
        } catch (error) {
          new import_obsidian.Notice(`HaloMem Sync: ${error instanceof Error ? error.message : "Sync failed"}`);
        }
      }));
    }
  }
};
