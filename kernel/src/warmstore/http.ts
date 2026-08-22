/**
 * halomem-warmstore/v1 (R6) — HttpWarmStore: the EXTERNAL mirror
 * implementation (mem0 / supermemory via an adapter sidecar).
 *
 * Sidecar protocol (CONTRACTS-WARMSTORE.md):
 *   POST {url}/v1/memories          {records:[WarmMirrorRecord]}  -> 2xx
 *   POST {url}/v1/memories/get      {ids:[MemoryId]} -> {records:[WarmMirrorRecord]}
 *   POST {url}/v1/memories/remove   {ids:[MemoryId]}              -> 2xx
 *   POST {url}/v1/namespaces/remove {namespace}                   -> 2xx
 *   GET  {url}/healthz                                            -> {ok:true}
 *
 * Boundary rules: this module imports ONLY src/types.js and the shared error.
 * Optional reads return untrusted candidates; WarmStoreManager revalidates
 * them against canonical state and policy (the mirror is never authority).
 *
 * Failure model (same discipline as the mem0 retriever sidecar): each call
 * gets a 1.5 s timeout and ONE retry (2 attempts). Any transport error,
 * timeout, or non-2xx status on the final attempt throws
 * WarmStoreUnavailableError; the manager leaves the op in the durable outbox
 * and the syscall proceeds (brownout, never hard-fail).
 */

import type {
  MemoryId,
  Namespace,
  WarmMirrorRecord,
  WarmStoreDriver,
  WarmStoreHealth,
} from "../types.js";
import { WarmStoreUnavailableError } from "./errors.js";
import { trimTrailingRepeatedCharacter } from "../strings.js";

/** Per-attempt timeout (contract: 1.5s). */
export const WARMSTORE_TIMEOUT_MS = 1500;
/** Retries after the first attempt (contract: one retry = 2 attempts). */
export const WARMSTORE_RETRIES = 1;

export interface HttpWarmStoreOptions {
  /** Mount name, e.g. "mem0" or "supermemory". */
  name: string;
  /** Sidecar base URL. Required — the kernel mounts this driver iff its env URL is set. */
  url: string;
  /** Per-attempt timeout in ms (default 1500). Tests may shrink this. */
  timeoutMs?: number;
  /** Retries after the first attempt (default 1). */
  retries?: number;
  /** Injected fetch for hermetic tests (default globalThis.fetch). */
  fetchImpl?: typeof fetch;
  /** Bearer credential required for every non-loopback warm-store endpoint. */
  authToken?: string;
}

export class HttpWarmStore implements WarmStoreDriver {
  readonly name: string;
  readonly external = true;

  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly fetchImpl: typeof fetch;
  private readonly authToken?: string;

  constructor(opts: HttpWarmStoreOptions) {
    if (!opts.name) {
      throw new Error("HttpWarmStore: name is required");
    }
    if (!opts.url) {
      throw new WarmStoreUnavailableError(
        opts.name,
        "no warm-store sidecar URL configured",
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(opts.url);
    } catch {
      throw new WarmStoreUnavailableError(opts.name, "warm-store URL is invalid");
    }
    const loopback = parsed.hostname === "localhost" || parsed.hostname === "::1" ||
      parsed.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(parsed.hostname);
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new WarmStoreUnavailableError(
        opts.name,
        "warm-store URL must not contain credentials, query, or fragment",
      );
    }
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
      throw new WarmStoreUnavailableError(
        opts.name,
        "remote warm-store URL requires HTTPS",
      );
    }
    if (!loopback && !opts.authToken) {
      throw new WarmStoreUnavailableError(
        opts.name,
        "remote warm-store URL requires an authentication token",
      );
    }
    this.name = opts.name;
    this.url = trimTrailingRepeatedCharacter(parsed.toString(), "/");
    this.timeoutMs = opts.timeoutMs ?? WARMSTORE_TIMEOUT_MS;
    this.retries = opts.retries ?? WARMSTORE_RETRIES;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.authToken = opts.authToken;
  }

  capabilities(): { rebuildable: boolean } {
    return { rebuildable: true };
  }

  async upsert(records: WarmMirrorRecord[]): Promise<void> {
    if (records.length === 0) return;
    await this.post("/v1/memories", { records });
  }

  async remove(ids: MemoryId[]): Promise<void> {
    if (ids.length === 0) return;
    await this.post("/v1/memories/remove", { ids });
  }

  async removeNamespace(namespace: Namespace): Promise<void> {
    await this.post("/v1/namespaces/remove", { namespace });
  }

  async get(ids: MemoryId[]): Promise<WarmMirrorRecord[]> {
    if (ids.length === 0) return [];
    const response = await this.postJson("/v1/memories/get", { ids });
    if (!isObject(response) || !Array.isArray(response.records)) {
      throw new WarmStoreUnavailableError(this.name, "sidecar returned an invalid get response");
    }
    const records: WarmMirrorRecord[] = [];
    for (const candidate of response.records) {
      if (!isWarmMirrorRecord(candidate)) {
        throw new WarmStoreUnavailableError(this.name, "sidecar returned a malformed warm record");
      }
      records.push(candidate);
    }
    return records;
  }

  async health(): Promise<WarmStoreHealth> {
    try {
      const res = await this.attempt("GET", "/healthz", undefined);
      const body: unknown = await res.json().catch(() => null);
      const ok =
        typeof body === "object" &&
        body !== null &&
        (body as { ok?: unknown }).ok === true;
      return ok ? { ok: true } : { ok: false, detail: "healthz returned ok!=true" };
    } catch (err) {
      return { ok: false, detail: describeError(err) };
    }
  }

  // -------------------------------------------------------------------------

  private async post(path: string, body: unknown): Promise<void> {
    await this.postJson(path, body);
  }

  private async postJson(path: string, body: unknown): Promise<unknown> {
    const payload = JSON.stringify(body);
    const attempts = this.retries + 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        const response = await this.attempt("POST", path, payload);
        return await response.json().catch(() => null);
      } catch (err) {
        lastError = err;
      }
    }
    throw new WarmStoreUnavailableError(
      this.name,
      `sidecar at ${this.url} failed after ${attempts} attempt(s): ${describeError(lastError)}`,
      { cause: lastError },
    );
  }

  private async attempt(
    method: "GET" | "POST",
    path: string,
    payload: string | undefined,
  ): Promise<Response> {
    const headers: Record<string, string> = {};
    if (payload !== undefined) headers["content-type"] = "application/json";
    if (this.authToken) headers.authorization = `Bearer ${this.authToken}`;
    const res = await this.fetchImpl(`${this.url}${path}`, {
      method,
      headers,
      body: payload,
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) {
      throw new Error(`sidecar responded ${res.status}`);
    }
    return res;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isWarmMirrorRecord(value: unknown): value is WarmMirrorRecord {
  if (!isObject(value)) return false;
  const scopes = new Set(["private", "team", "org"]);
  const types = new Set(["fact", "preference", "episode", "entity", "concept", "pointer"]);
  return typeof value.id === "string" && typeof value.namespace === "string" &&
    typeof value.scope === "string" && scopes.has(value.scope) &&
    typeof value.type === "string" && types.has(value.type) &&
    typeof value.content === "string" && typeof value.tValidFrom === "string" &&
    Number.isFinite(Date.parse(value.tValidFrom));
}

function describeError(err: unknown): string {
  if (err instanceof Error) {
    return err.name === "TimeoutError" ? "timeout" : err.message;
  }
  return String(err);
}
