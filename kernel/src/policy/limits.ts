/**
 * Module D (M1) — rate limiting + budget caps.
 *
 * TokenBucket: in-process, per-keyId, continuous refill. Capacity equals the
 * per-minute limit (a full-minute burst is allowed from a cold bucket).
 * Stale buckets are evicted lazily so long-lived servers don't leak memory.
 *
 * BudgetGuard: month-to-date USD spend for a namespace SUBTREE via SUM over
 * `cost_ledger` (migration 003, module C). `state()` returns 'over' when the
 * policy's monthlyBudgetUsd cap is met or exceeded — callers DEGRADE
 * LLM-dependent features (verbatim-only writes, no verifier); they never
 * hard-fail the agent (brownout, §10).
 *
 * D4 note: neither primitive writes audit rows itself — the syscall/transport
 * layer that acts on `allow() === false` or `state() === 'over'` MUST write
 * the denial/degrade audit row (it owns the Identity + op context).
 */

import { escapeLikePattern, type Db } from "../db/client.js";
import type { Namespace } from "../types.js";
import type { PolicyConfigX } from "./store.js";

// ---------------------------------------------------------------------------
// TokenBucket
// ---------------------------------------------------------------------------

interface Bucket {
  tokens: number;
  /** Last refill timestamp, ms. */
  refilledAtMs: number;
  /** Last time this bucket served an allow() call, ms — eviction key. */
  usedAtMs: number;
}

export interface TokenBucketOptions {
  /** Injectable clock for tests (ms). */
  now?: () => number;
  /** Buckets idle longer than this are evicted (default 10 min). */
  evictAfterMs?: number;
  /** Minimum interval between eviction sweeps (default 60s). */
  sweepIntervalMs?: number;
}

export class TokenBucket {
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;
  private readonly evictAfterMs: number;
  private readonly sweepIntervalMs: number;
  private lastSweepMs: number;

  constructor(options: TokenBucketOptions = {}) {
    this.now = options.now ?? Date.now;
    this.evictAfterMs = options.evictAfterMs ?? 10 * 60_000;
    this.sweepIntervalMs = options.sweepIntervalMs ?? 60_000;
    this.lastSweepMs = this.now();
  }

  /**
   * Consume one request from `keyId`'s bucket at `limitPerMin`. Returns
   * false when the key is over its rate — caller responds 429 + audit row.
   * A non-positive/non-finite limit denies everything.
   */
  allow(keyId: string, limitPerMin: number): boolean {
    if (!Number.isFinite(limitPerMin) || limitPerMin <= 0) return false;
    const nowMs = this.now();
    this.maybeSweep(nowMs);

    let bucket = this.buckets.get(keyId);
    if (!bucket) {
      bucket = { tokens: limitPerMin, refilledAtMs: nowMs, usedAtMs: nowMs };
      this.buckets.set(keyId, bucket);
    } else {
      // Continuous refill; capacity tracks the (policy-overridable) limit so
      // a policy change takes effect on the next call.
      const elapsedMs = Math.max(0, nowMs - bucket.refilledAtMs);
      bucket.tokens = Math.min(
        limitPerMin,
        bucket.tokens + (elapsedMs * limitPerMin) / 60_000,
      );
      bucket.refilledAtMs = nowMs;
      bucket.usedAtMs = nowMs;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    return false;
  }

  /** Number of live buckets (exposed for eviction tests/metrics). */
  get size(): number {
    return this.buckets.size;
  }

  private maybeSweep(nowMs: number): void {
    if (nowMs - this.lastSweepMs < this.sweepIntervalMs) return;
    this.lastSweepMs = nowMs;
    for (const [keyId, bucket] of this.buckets) {
      if (nowMs - bucket.usedAtMs >= this.evictAfterMs) {
        this.buckets.delete(keyId);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// BudgetGuard
// ---------------------------------------------------------------------------

export type BudgetState = "ok" | "over";

export interface BudgetGuardOptions {
  /** Injectable clock for tests. */
  now?: () => Date;
}

export class BudgetGuard {
  private readonly db: Db;
  private readonly now: () => Date;

  constructor(db: Db, options: BudgetGuardOptions = {}) {
    this.db = db;
    this.now = options.now ?? (() => new Date());
  }

  /**
   * USD spent since the start of the current UTC month by `ns` and its
   * descendants (a cap set at org level covers the whole subtree).
   */
  async monthToDateUsd(ns: Namespace): Promise<number> {
    const monthStart = monthStartUtcIso(this.now());
    // `_`/`%` in the namespace must not act as LIKE wildcards — otherwise a
    // cap on 'org/team_a' absorbs sibling 'org/teamXa' spend and browns out
    // the wrong tenant. Escaped pattern + explicit ESCAPE, matching the
    // exact-match discipline of the ACL path (syscalls visibleNamespaces).
    const res = await this.db.query(
      `SELECT COALESCE(SUM(usd), 0) AS total
         FROM cost_ledger
        WHERE (namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
          AND ts >= $3`,
      [ns, escapeLikePattern(ns) + "/%", monthStart],
    );
    return Number(res.rows[0]?.total ?? 0);
  }

  /**
   * 'over' when month-to-date spend meets/exceeds the effective policy's
   * monthlyBudgetUsd (a cap of 0 means no LLM budget at all). No cap → 'ok'.
   * 'over' is advisory: callers degrade LLM features, never hard-fail.
   */
  async state(ns: Namespace, policy: PolicyConfigX): Promise<BudgetState> {
    const cap = policy.monthlyBudgetUsd;
    if (cap === undefined || cap === null) return "ok";
    const mtd = await this.monthToDateUsd(ns);
    return mtd >= cap ? "over" : "ok";
  }
}

function monthStartUtcIso(d: Date): string {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)).toISOString();
}
