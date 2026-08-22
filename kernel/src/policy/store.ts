/**
 * Module D (M1) — PolicyStore over the `policies` table.
 *
 * Policies are stored as YAML text per namespace. `get(ns)` resolves the
 * EFFECTIVE policy by merging, in order:
 *
 *   kernel defaults  ←  each ancestor namespace's stored row (org first)
 *                    ←  the namespace's own stored row
 *
 * Stored rows are PARTIAL: a row only overrides the fields it declares
 * (ttlDefaultsSeconds merges per scope). Results are cached in-process for
 * 30s; `invalidate(ns)` drops the cache for a namespace and its descendants
 * (a parent change affects every child's merged view). `set()` invalidates
 * automatically.
 *
 * The M1-only optional fields (rateLimitPerMin, monthlyBudgetUsd, retriever)
 * live on the LOCAL PolicyConfigX extension — src/types.ts is scaffold-owned
 * and unmodified.
 */

import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { Db } from "../db/client.js";
import type { Namespace, PolicyConfig, Scope } from "../types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Conflict-review dial. It governs the write path's synchronous supersedence
 * decision AND (CA5) how much autonomy the write-time conflict autopilot has.
 * Detection itself is always on; this dial only decides who settles what.
 * - "auto": the trust lattice settles every judged contradiction on its own
 *   (higher trust wins, lower-trust claims are rejected, confident equal-trust
 *   ties go to the newer fact); only ambiguous ties reach a person. At the
 *   synchronous door it behaves as "lower-trust".
 * - "lower-trust": a write whose provenance source underranks the incumbent's
 *   quarantines as disputed instead of superseding; the autopilot may only act
 *   when the incoming fact OUTRANKS its neighbour.
 * - "all": every supersedence-band conflict quarantines, regardless of rank,
 *   and every judged contradiction becomes a review item.
 * - "off": pure recency at the door (pre-dispute behavior). The autopilot still
 *   applies the trust lattice — "off" asks for no human gate, not for worse
 *   decisions than the lattice already makes unattended.
 */
export type ConflictReviewMode = "auto" | "lower-trust" | "all" | "off";

/** PolicyConfig + M1 optional fields (local extension — do NOT edit types.ts). */
export interface PolicyConfigX extends PolicyConfig {
  /** Token-bucket rate limit per api key, requests per minute. Default 60. */
  rateLimitPerMin?: number;
  /** Month-to-date USD cap; at/over the cap LLM features degrade (brownout). */
  monthlyBudgetUsd?: number;
  /** Named retriever selection (D1 baseline unless overridden). */
  retriever?: string;
  /** M2 A/B routing: pctB% of queries (deterministic per query) go to `b`. */
  abTest?: { a: string; b: string; pctB: number };
  /** Trust-ranked conflict quarantine mode. Default "lower-trust". */
  conflictReview?: ConflictReviewMode;
  /**
   * M6 (D14): per-namespace federation dial. 'off' disables the L4 live lane
   * AND write-back caching for the subtree. Default 'on'.
   */
  federationCache?: "on" | "off";
  /** Explicit destinations allowed to receive restricted data. */
  restrictedDestinations?: string[];
  /** Deployment region used to enforce classification residency labels. */
  dataRegion?: string;
}

export interface PolicyRow {
  namespace: Namespace;
  yaml: string;
  updatedAt: string; // ISO-8601
}

export const DEFAULT_RATE_LIMIT_PER_MIN = 60;

const NINETY_DAYS_SECONDS = 90 * 24 * 60 * 60;
const CACHE_TTL_MS = 30_000;
const SCOPES: readonly Scope[] = ["user", "assistant", "team", "org"];

// ---------------------------------------------------------------------------
// YAML shape validation (zod). Every field optional — rows are partial
// overrides — but present fields must be well-formed. Unknown keys rejected.
// ---------------------------------------------------------------------------

const ttlDefaultsSchema = z
  .object({
    user: z.number().int().nullable(),
    assistant: z.number().int().nullable(),
    team: z.number().int().nullable(),
    org: z.number().int().nullable(),
  })
  .partial()
  .strict();

const abTestSchema = z
  .object({
    a: z.string().min(1),
    b: z.string().min(1),
    pctB: z.number().int().min(0).max(100),
  })
  .strict();

const policyYamlSchema = z
  .object({
    tokenBudget: z.number().int().positive(),
    ttlDefaultsSeconds: ttlDefaultsSchema,
    pinnedConcepts: z.array(z.string()),
    dedupeSimilarityThreshold: z.number().min(0).max(1),
    verifierEnabled: z.boolean(),
    rateLimitPerMin: z.number().int().positive(),
    monthlyBudgetUsd: z.number().nonnegative(),
    retriever: z.string().min(1),
    abTest: abTestSchema,
    conflictReview: z.enum(["auto", "lower-trust", "all", "off"]),
    federationCache: z.enum(["on", "off"]),
    restrictedDestinations: z.array(z.string().min(1).max(200)).max(64),
    dataRegion: z.string().min(1).max(100),
  })
  .partial()
  .strict();

/** The validated partial override shape a stored YAML row may contain. */
export type PolicyOverrides = z.infer<typeof policyYamlSchema>;

function formatZodError(err: z.ZodError): string {
  return err.issues
    .map((i) => (i.path.length ? `${i.path.join(".")}: ${i.message}` : i.message))
    .join("; ");
}

/** Parse + validate a stored/incoming YAML policy document. Throws with a clear message. */
export function parsePolicyYaml(ns: Namespace, yamlText: string): PolicyOverrides {
  let doc: unknown;
  try {
    doc = parseYaml(yamlText);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Invalid policy YAML for namespace '${ns}': ${msg}`);
  }
  if (doc === null || doc === undefined) {
    throw new Error(
      `Invalid policy YAML for namespace '${ns}': document is empty - expected a mapping of policy fields`,
    );
  }
  if (typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error(
      `Invalid policy YAML for namespace '${ns}': expected a mapping of policy fields, got ${
        Array.isArray(doc) ? "a sequence" : typeof doc
      }`,
    );
  }
  const parsed = policyYamlSchema.safeParse(doc);
  if (!parsed.success) {
    throw new Error(
      `Invalid policy for namespace '${ns}': ${formatZodError(parsed.error)}`,
    );
  }
  return parsed.data;
}

/** "org/team/agent" → ["org", "org/team", "org/team/agent"] (org first). */
export function namespaceChain(ns: Namespace): Namespace[] {
  const parts = ns.split("/").filter((p) => p.length > 0);
  const chain: Namespace[] = [];
  for (let i = 1; i <= parts.length; i++) {
    chain.push(parts.slice(0, i).join("/"));
  }
  return chain;
}

// ---------------------------------------------------------------------------
// PolicyStore
// ---------------------------------------------------------------------------

interface CacheEntry {
  value: PolicyConfigX;
  expiresAtMs: number;
}

interface ExplicitLimitFields {
  tokenBudget: boolean;
  rateLimitPerMin: boolean;
  monthlyBudgetUsd: boolean;
  ttlDefaultsSeconds: Record<Scope, boolean>;
}

export interface PolicyStoreOptions {
  /** Override kernel defaults (integrator passes config-derived values). */
  defaults?: Partial<Omit<PolicyConfigX, "namespace">>;
  /** Cache TTL override, ms (default 30_000). Tests may lower it. */
  cacheTtlMs?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

export class PolicyStore {
  private readonly db: Db;
  private readonly cache = new Map<Namespace, CacheEntry>();
  private readonly cacheTtlMs: number;
  private readonly now: () => number;
  private readonly defaults: Omit<PolicyConfigX, "namespace">;
  /**
   * Bumped by invalidate(). get() snapshots it before awaiting the DB and
   * only fills the cache if no invalidation raced the read — otherwise an
   * in-flight get() that read the PRE-set rows would repopulate the cache
   * right after set() cleared it, serving the acknowledged policy change
   * stale for a full TTL.
   */
  private generation = 0;

  constructor(db: Db, options: PolicyStoreOptions = {}) {
    this.db = db;
    this.cacheTtlMs = options.cacheTtlMs ?? CACHE_TTL_MS;
    this.now = options.now ?? Date.now;
    this.defaults = {
      tokenBudget: 3000,
      ttlDefaultsSeconds: {
        org: null,
        team: null,
        user: NINETY_DAYS_SECONDS,
        assistant: NINETY_DAYS_SECONDS,
      },
      pinnedConcepts: [],
      dedupeSimilarityThreshold: 0.92,
      verifierEnabled: true,
      rateLimitPerMin: DEFAULT_RATE_LIMIT_PER_MIN,
      conflictReview: "lower-trust",
      ...options.defaults,
    };
  }

  /**
   * Authorization-path read that bypasses the process-local performance cache.
   * The kernel uses this so a policy tightened on another replica is effective
   * on the next operation; direct PolicyStore consumers retain the documented
   * bounded cache semantics.
   */
  async getFresh(ns: Namespace): Promise<PolicyConfigX> {
    this.invalidate(ns);
    return this.get(ns);
  }

  /**
   * Effective policy for `ns`: kernel defaults ← ancestor rows (org first)
   * ← ns's own row. Cached 30s per namespace.
   */
  async get(ns: Namespace): Promise<PolicyConfigX> {
    const cached = this.cache.get(ns);
    if (cached && this.now() < cached.expiresAtMs) {
      return clonePolicy(cached.value);
    }

    const generationAtRead = this.generation;
    const chain = namespaceChain(ns);
    const merged: PolicyConfigX = { namespace: ns, ...clonePolicyFields(this.defaults) };
    const explicitLimits = emptyExplicitLimitFields();

    if (chain.length > 0) {
      const placeholders = chain.map((_, i) => `$${i + 1}`).join(", ");
      const res = await this.db.query(
        `SELECT namespace, yaml FROM policies WHERE namespace IN (${placeholders})`,
        chain,
      );
      const byNs = new Map<string, string>(
        res.rows.map((r: { namespace: string; yaml: string }) => [r.namespace, r.yaml]),
      );
      for (const ancestor of chain) {
        const yamlText = byNs.get(ancestor);
        if (yamlText === undefined) continue;
        const overrides = parsePolicyYaml(ancestor, yamlText);
        applyOverrides(merged, overrides, explicitLimits);
      }
    }

    // Cache only when no set()/invalidate() raced the awaited read above —
    // a lost invalidation here would serve a stale policy for a full TTL.
    if (this.generation === generationAtRead) {
      this.cache.set(ns, {
        value: clonePolicy(merged),
        expiresAtMs: this.now() + this.cacheTtlMs,
      });
    }
    return merged;
  }

  /**
   * Validate + upsert a partial policy for `ns`. Throws on invalid YAML or
   * shape (nothing is written in that case). Invalidates the cache for `ns`
   * and all descendants.
   */
  async set(ns: Namespace, yamlText: string): Promise<void> {
    if (typeof ns !== "string" || ns.trim().length === 0) {
      throw new Error("PolicyStore.set: namespace must be a non-empty string");
    }
    // Validate BEFORE touching the table — invalid policies never persist.
    const overrides = parsePolicyYaml(ns, yamlText);
    const chain = namespaceChain(ns);
    if (chain.length > 1) {
      const parentChain = chain.slice(0, -1);
      const [parent, explicitLimits] = await Promise.all([
        this.get(parentChain[parentChain.length - 1]),
        this.getExplicitLimitFields(parentChain),
      ]);
      assertTightensEffectiveParent(overrides, parent, explicitLimits);
    }
    await this.db.query(
      `INSERT INTO policies (namespace, yaml, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (namespace) DO UPDATE SET yaml = EXCLUDED.yaml, updated_at = EXCLUDED.updated_at`,
      [ns, yamlText, new Date().toISOString()],
    );
    this.invalidate(ns);
  }

  /** Drop cached merges for `ns` AND its descendants (they inherit from it). */
  invalidate(ns: Namespace): void {
    this.generation++; // in-flight get() reads must not repopulate the cache
    const prefix = ns + "/";
    for (const key of this.cache.keys()) {
      if (key === ns || key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  /** All stored policy rows (raw YAML, not merged), ordered by namespace. */
  async list(): Promise<PolicyRow[]> {
    const res = await this.db.query(
      `SELECT namespace, yaml, updated_at FROM policies ORDER BY namespace`,
    );
    return res.rows.map(
      (r: { namespace: string; yaml: string; updated_at: string | Date }) => ({
        namespace: r.namespace,
        yaml: r.yaml,
        updatedAt: new Date(r.updated_at).toISOString(),
      }),
    );
  }

  private async getExplicitLimitFields(
    chain: Namespace[],
  ): Promise<ExplicitLimitFields> {
    const flags = emptyExplicitLimitFields();
    if (chain.length === 0) return flags;

    const placeholders = chain.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT namespace, yaml FROM policies WHERE namespace IN (${placeholders})`,
      chain,
    );
    const byNs = new Map<string, string>(
      res.rows.map((r: { namespace: string; yaml: string }) => [r.namespace, r.yaml]),
    );
    for (const ancestor of chain) {
      const yamlText = byNs.get(ancestor);
      if (yamlText === undefined) continue;
      markExplicitLimitFields(flags, parsePolicyYaml(ancestor, yamlText));
    }
    return flags;
  }
}

// ---------------------------------------------------------------------------
// Merge helpers
// ---------------------------------------------------------------------------

function assertTightensEffectiveParent(
  overrides: PolicyOverrides,
  parent: PolicyConfigX,
  explicitLimits: ExplicitLimitFields,
): void {
  const caps: readonly [
    "tokenBudget" | "rateLimitPerMin" | "monthlyBudgetUsd",
    number | undefined,
    number | undefined,
    boolean,
  ][] = [
    ["tokenBudget", overrides.tokenBudget, parent.tokenBudget, explicitLimits.tokenBudget],
    [
      "rateLimitPerMin",
      overrides.rateLimitPerMin,
      parent.rateLimitPerMin,
      explicitLimits.rateLimitPerMin,
    ],
    [
      "monthlyBudgetUsd",
      overrides.monthlyBudgetUsd,
      parent.monthlyBudgetUsd,
      explicitLimits.monthlyBudgetUsd,
    ],
  ];
  for (const [field, childValue, parentValue, isExplicit] of caps) {
    if (
      isExplicit &&
      childValue !== undefined &&
      loosensEffectiveParent(childValue, parentValue)
    ) {
      throw new Error(
        `Policy ${field} cannot exceed effective parent value ${parentValue}`,
      );
    }
  }

  if (overrides.ttlDefaultsSeconds === undefined) return;
  for (const scope of SCOPES) {
    const childValue = overrides.ttlDefaultsSeconds[scope];
    const parentValue = parent.ttlDefaultsSeconds[scope];
    if (
      explicitLimits.ttlDefaultsSeconds[scope] &&
      childValue !== undefined &&
      loosensEffectiveParent(childValue, parentValue)
    ) {
      throw new Error(
        `Policy ttlDefaultsSeconds.${scope} cannot exceed effective parent value ${parentValue}`,
      );
    }
  }
}

function emptyExplicitLimitFields(): ExplicitLimitFields {
  return {
    tokenBudget: false,
    rateLimitPerMin: false,
    monthlyBudgetUsd: false,
    ttlDefaultsSeconds: {
      user: false,
      assistant: false,
      team: false,
      org: false,
    },
  };
}

function markExplicitLimitFields(
  fields: ExplicitLimitFields,
  overrides: PolicyOverrides,
): void {
  if (overrides.tokenBudget !== undefined) fields.tokenBudget = true;
  if (overrides.rateLimitPerMin !== undefined) fields.rateLimitPerMin = true;
  if (overrides.monthlyBudgetUsd !== undefined) fields.monthlyBudgetUsd = true;
  if (overrides.ttlDefaultsSeconds === undefined) return;
  for (const scope of SCOPES) {
    if (overrides.ttlDefaultsSeconds[scope] !== undefined) {
      fields.ttlDefaultsSeconds[scope] = true;
    }
  }
}

function loosensEffectiveParent(
  childValue: number | null,
  parentValue: number | null | undefined,
): boolean {
  return (
    parentValue !== null &&
    parentValue !== undefined &&
    (childValue === null || childValue > parentValue)
  );
}

function applyOverrides(
  target: PolicyConfigX,
  o: PolicyOverrides,
  explicitLimits: ExplicitLimitFields,
): void {
  if (
    o.tokenBudget !== undefined &&
    (!explicitLimits.tokenBudget ||
      !loosensEffectiveParent(o.tokenBudget, target.tokenBudget))
  ) {
    target.tokenBudget = o.tokenBudget;
  }
  if (o.tokenBudget !== undefined) explicitLimits.tokenBudget = true;
  if (o.ttlDefaultsSeconds !== undefined) {
    for (const scope of SCOPES) {
      const v = o.ttlDefaultsSeconds[scope];
      if (
        v !== undefined &&
        (!explicitLimits.ttlDefaultsSeconds[scope] ||
          !loosensEffectiveParent(v, target.ttlDefaultsSeconds[scope]))
      ) {
        target.ttlDefaultsSeconds[scope] = v;
      }
      if (v !== undefined) explicitLimits.ttlDefaultsSeconds[scope] = true;
    }
  }
  if (o.pinnedConcepts !== undefined) target.pinnedConcepts = [...o.pinnedConcepts];
  if (o.dedupeSimilarityThreshold !== undefined) {
    target.dedupeSimilarityThreshold = o.dedupeSimilarityThreshold;
  }
  if (o.verifierEnabled !== undefined) target.verifierEnabled = o.verifierEnabled;
  if (
    o.rateLimitPerMin !== undefined &&
    (!explicitLimits.rateLimitPerMin ||
      !loosensEffectiveParent(o.rateLimitPerMin, target.rateLimitPerMin))
  ) {
    target.rateLimitPerMin = o.rateLimitPerMin;
  }
  if (o.rateLimitPerMin !== undefined) explicitLimits.rateLimitPerMin = true;
  if (
    o.monthlyBudgetUsd !== undefined &&
    (!explicitLimits.monthlyBudgetUsd ||
      !loosensEffectiveParent(o.monthlyBudgetUsd, target.monthlyBudgetUsd))
  ) {
    target.monthlyBudgetUsd = o.monthlyBudgetUsd;
  }
  if (o.monthlyBudgetUsd !== undefined) explicitLimits.monthlyBudgetUsd = true;
  if (o.retriever !== undefined) target.retriever = o.retriever;
  if (o.abTest !== undefined) target.abTest = { ...o.abTest };
  if (o.conflictReview !== undefined) target.conflictReview = o.conflictReview;
  if (o.federationCache !== undefined) target.federationCache = o.federationCache;
  if (o.restrictedDestinations !== undefined) {
    target.restrictedDestinations = [...new Set(o.restrictedDestinations)].sort();
  }

  if (o.dataRegion !== undefined) target.dataRegion = o.dataRegion.trim().toLowerCase();
}

function clonePolicyFields(
  p: Omit<PolicyConfigX, "namespace">,
): Omit<PolicyConfigX, "namespace"> {
  const out: Omit<PolicyConfigX, "namespace"> = {
    ...p,
    ttlDefaultsSeconds: { ...p.ttlDefaultsSeconds },
    pinnedConcepts: [...p.pinnedConcepts],
  };
  if (p.abTest) out.abTest = { ...p.abTest };
  if (p.restrictedDestinations) out.restrictedDestinations = [...p.restrictedDestinations];
  return out;
}

function clonePolicy(p: PolicyConfigX): PolicyConfigX {
  return { namespace: p.namespace, ...clonePolicyFields(p) };
}
