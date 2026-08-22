/**
 * Module E (M2) — driver routing.
 *
 * "Routing is config": which retriever driver serves a namespace is a policy
 * decision, not code. The effective policy (PolicyConfigX from
 * src/policy/store.ts) may carry:
 *
 *   retriever: <name>                     — fixed driver selection
 *   abTest: { a, b, pctB }                — deterministic per-query split
 *
 * Selection rules (pickDriverName):
 *   1. `abTest` present → FNV-1a(query) % 100 < pctB ? b : a.
 *      Deterministic: the SAME query string always routes to the SAME arm,
 *      so replays / retries / cache lookups never flip drivers mid-flight.
 *   2. else `retriever` if set, else 'baseline'.
 *
 * Unknown driver names are NOT resolved here — they flow through the
 * registry's `get()`, whose contract (module A) is to fall back to baseline
 * with a warning log. Routing stays a pure function of (policy, query).
 */

import type { RetrieverDriver } from "../types.js";

/** D1: the referee control lane is always available under this name. */
export const DEFAULT_RETRIEVER = "baseline";

export interface AbTestConfig {
  /** Control arm driver name. */
  a: string;
  /** Treatment arm driver name. */
  b: string;
  /** Percentage of queries routed to arm `b` (integer 0..100). */
  pctB: number;
}

/**
 * The routing-relevant slice of the effective policy. PolicyConfigX
 * (src/policy/store.ts) satisfies this structurally.
 */
export interface RoutingPolicy {
  retriever?: string;
  abTest?: AbTestConfig;
}

/**
 * Minimal registry surface routing needs. Module A's DriverRegistry
 * satisfies this shape; its `get()` resolves unknown names to the baseline
 * driver (with a warn log) — routing never has to special-case them.
 */
export interface DriverRegistryLike {
  get(name: string): RetrieverDriver;
}

/**
 * FNV-1a 32-bit hash over the query's UTF-16 code units. Same constants as
 * the HashEmbedder token hash (src/embed) — simple, stable, well spread.
 */
export function fnv1a32(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * Deterministic driver-name selection: abTest split when configured,
 * otherwise the policy's fixed `retriever`, otherwise 'baseline'.
 */
export function pickDriverName(policy: RoutingPolicy, query: string): string {
  const ab = policy.abTest;
  if (ab) {
    return fnv1a32(query) % 100 < ab.pctB ? ab.b : ab.a;
  }
  return policy.retriever ?? DEFAULT_RETRIEVER;
}

/**
 * Resolve the driver serving `query` under `policy`. Unknown names resolve
 * through the registry's baseline fallback.
 */
export function pickDriver(
  registry: DriverRegistryLike,
  policy: RoutingPolicy,
  query: string,
): RetrieverDriver {
  return registry.get(pickDriverName(policy, query));
}
