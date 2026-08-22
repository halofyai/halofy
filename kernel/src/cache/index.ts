/** M7/D20: process-local, content-addressed L1 cache with explicit invalidation. */
import { createHash } from "node:crypto";
import type { L1CacheEntry, Namespace } from "../types.js";

export interface L1CacheOptions {
  maxEntries?: number;
  now?: () => Date;
}

export interface L1CacheSetInput<T> {
  namespace: Namespace;
  value: T;
  /** Version of the complete canonical result represented by this entry. */
  version: string;
  /** Version of the ACL, classification, and destination policy decision. */
  policyVersion: string;
  ttlMs: number;
  /** Canonical memory/version ids whose supersedence invalidates this result. */
  dependencies?: readonly string[];
}

export interface L1CacheExpectation {
  namespace: Namespace;
  version: string;
  policyVersion: string;
}

interface StoredEntry<T> {
  entry: L1CacheEntry<T>;
  dependencies: Set<string>;
}

function canonicalize(value: unknown, seen: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("content address requires finite numbers");
    return value;
  }
  if (typeof value === "bigint") return { $bigint: value.toString() };
  if (value instanceof Uint8Array) return { $bytes: Buffer.from(value).toString("base64") };
  if (value instanceof Date) return { $date: value.toISOString() };
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new TypeError("content address does not support cyclic values");
    seen.add(value);
    const result = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return result;
  }
  if (typeof value !== "object" || value === undefined) {
    throw new TypeError(`content address does not support ${typeof value}`);
  }
  if (seen.has(value)) throw new TypeError("content address does not support cyclic values");
  seen.add(value);
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    result[key] = canonicalize((value as Record<string, unknown>)[key], seen);
  }
  seen.delete(value);
  return result;
}

/** Stable SHA-256 address independent of object insertion order. */
export function contentAddress(value: unknown): string {
  const canonical = JSON.stringify(canonicalize(value, new Set()));
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

export class ContentAddressedL1Cache<T = unknown> {
  private readonly entries = new Map<string, StoredEntry<T>>();
  private readonly byDependency = new Map<string, Set<string>>();
  private readonly maxEntries: number;
  private readonly now: () => Date;

  constructor(options: L1CacheOptions = {}) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 1_000);
    this.now = options.now ?? (() => new Date());
  }

  set(input: L1CacheSetInput<T>): L1CacheEntry<T> {
    if (!input.namespace || !input.version || !input.policyVersion) {
      throw new Error("namespace, version, and policyVersion are required");
    }
    if (!Number.isFinite(input.ttlMs) || input.ttlMs <= 0) throw new Error("ttlMs must be positive");
    const dependencies = [...new Set(input.dependencies ?? [])].sort();
    const key = contentAddress({
      namespace: input.namespace, value: input.value, version: input.version,
      policyVersion: input.policyVersion, dependencies,
    });
    this.delete(key);
    const entry: L1CacheEntry<T> = {
      key,
      namespace: input.namespace,
      value: structuredClone(input.value),
      version: input.version,
      expiresAt: new Date(this.now().getTime() + input.ttlMs).toISOString(),
      policyVersion: input.policyVersion,
    };
    this.entries.set(key, { entry, dependencies: new Set(dependencies) });
    for (const dependency of dependencies) {
      const keys = this.byDependency.get(dependency) ?? new Set<string>();
      keys.add(key);
      this.byDependency.set(dependency, keys);
    }
    while (this.entries.size > this.maxEntries) this.delete(this.entries.keys().next().value as string);
    return structuredClone(entry);
  }

  get(key: string, expected: L1CacheExpectation): L1CacheEntry<T> | null {
    const stored = this.entries.get(key);
    if (!stored) return null;
    const entry = stored.entry;
    if (
      new Date(entry.expiresAt).getTime() <= this.now().getTime() ||
      entry.namespace !== expected.namespace || entry.version !== expected.version ||
      entry.policyVersion !== expected.policyVersion
    ) {
      this.delete(key);
      return null;
    }
    // Refresh insertion order for bounded LRU eviction.
    this.entries.delete(key);
    this.entries.set(key, stored);
    return structuredClone(entry);
  }

  /** Test/diagnostic view; expiry is still enforced, policy is not bypassed for reads. */
  peek(key: string): L1CacheEntry<T> | null {
    const stored = this.entries.get(key);
    if (!stored) return null;
    if (new Date(stored.entry.expiresAt).getTime() <= this.now().getTime()) {
      this.delete(key);
      return null;
    }
    return structuredClone(stored.entry);
  }

  invalidateSuperseded(dependency: string): number {
    const keys = [...(this.byDependency.get(dependency) ?? [])];
    for (const key of keys) this.delete(key);
    return keys.length;
  }

  /** Drop entries evaluated under any policy version other than the current one. */
  invalidatePolicy(namespace: Namespace, currentPolicyVersion: string): number {
    return this.deleteWhere((entry) =>
      (entry.namespace === namespace || entry.namespace.startsWith(`${namespace}/`)) &&
      entry.policyVersion !== currentPolicyVersion,
    );
  }

  /** Exact `/`-segment subtree erasure; `%` and `_` are always literal. */
  eraseNamespace(namespace: Namespace): number {
    return this.deleteWhere((entry) =>
      entry.namespace === namespace || entry.namespace.startsWith(`${namespace}/`),
    );
  }

  clear(): void {
    this.entries.clear();
    this.byDependency.clear();
  }

  private deleteWhere(predicate: (entry: L1CacheEntry<T>) => boolean): number {
    const keys = [...this.entries].filter(([, stored]) => predicate(stored.entry)).map(([key]) => key);
    for (const key of keys) this.delete(key);
    return keys.length;
  }

  private delete(key: string): void {
    const stored = this.entries.get(key);
    if (!stored) return;
    this.entries.delete(key);
    for (const dependency of stored.dependencies) {
      const keys = this.byDependency.get(dependency);
      keys?.delete(key);
      if (keys?.size === 0) this.byDependency.delete(dependency);
    }
  }
}
