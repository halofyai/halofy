import type { Identity, Namespace } from "../types.js";

export const QUOTA_FEATURES = [
  "assistant_luna",
  "assistant_grok",
  "retrieval",
  "memory_write",
  "ingest_bytes",
  "file",
  "file_bytes",
  "source",
  "source_sync",
  "automation",
  "consolidation",
  "conflict_scan",
  "export",
] as const;

export type QuotaFeature = (typeof QUOTA_FEATURES)[number];

export interface QuotaConsumeItem {
  feature: QuotaFeature;
  units?: number;
  reservedUsd?: number;
}

export interface QuotaConsumeOptions {
  idempotencyKey?: string;
  units?: number;
  enrollSeat?: boolean;
  reservedUsd?: number;
}

export interface QuotaConsumeManyOptions {
  idempotencyKey?: string;
  enrollSeat?: boolean;
}

export class QuotaLimitError extends Error {
  readonly name = "QuotaLimitError";
  readonly statusCode = 402;

  constructor(
    readonly code: string,
    message: string,
    readonly feature: QuotaFeature | null = null,
    readonly limit: number | null = null,
  ) {
    super(message);
  }
}

/** Everything the memory kernel needs from an optional quota authority. */
export interface QuotaPort {
  isEnabled(): boolean;
  consume(
    identity: Identity,
    feature: QuotaFeature,
    options?: QuotaConsumeOptions,
  ): Promise<void>;
  consumeMany(
    identity: Identity,
    items: readonly QuotaConsumeItem[],
    options?: QuotaConsumeManyOptions,
  ): Promise<void>;
  tenantCeiling(namespace: Namespace, feature: QuotaFeature): Promise<number>;
  summary(identity: Identity): Promise<Record<string, unknown>>;
  /** A quota provider may lower this limit, but must never raise it. */
  rateLimitPerMin(current: number, actor?: string): number;
}

/**
 * Standalone default: no licence switch, seats, credits, or artificial caps.
 * Product policy and security rate limits remain active elsewhere in the
 * kernel; this port only represents commercial packaging quotas.
 */
export const UNMETERED: QuotaPort = Object.freeze({
  isEnabled: () => false,
  async consume() {},
  async consumeMany() {},
  async tenantCeiling() { return Number.MAX_SAFE_INTEGER; },
  async summary(identity: Identity) {
    return {
      enabled: false,
      metered: false,
      namespace: identity.namespace,
      actor: identity.actor,
    };
  },
  rateLimitPerMin: (current: number) => current,
});

export interface MeterChargeResult {
  ok: boolean;
  state?: string;
}

/** Optional pay-per-use accounting. Absence means no commercial charge. */
export interface MeterPort {
  charge(
    identity: Identity,
    feature: string,
    options?: {
      units?: number;
      reason?: string;
      idempotencyKey?: string;
      policy?: unknown;
    },
  ): Promise<MeterChargeResult>;
}
