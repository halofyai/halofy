/**
 * Module A (M4) — tenancy core.
 *
 * A tenant is simply a ROOT namespace with an isolated keyspace and per-tenant
 * caps. Tenant isolation is NOT a new fence: it is the SAME ancestor-prefix ACL
 * the index enforces (`namespaceAncestors` → exact `IN (...)`, never a `LIKE`
 * wildcard). This registry only names the roots and stores their caps/status;
 * the mutual invisibility of sibling roots is already a consequence of the ACL.
 *
 * D9: `register`/`list` take the server-resolved `Identity` — callers never
 * assert their own namespace or role. All SQL is parameterized; a namespace is
 * an arbitrary string, so it NEVER enters a LIKE pattern (a `_`/`%` inside a
 * namespace would silently match siblings — the wildcard leak the ACL avoids
 * with exact IN-lists).
 *
 * Kernel-side module: MAY import src/db + src/types. Imports no other builder's
 * class.
 */

import { ulid } from "ulid";
import { isRootOwner } from "../auth/index.js";
import { normalizedOrganizationName } from "../console/org-name.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import type { Identity, Namespace, Tenant } from "../types.js";

/** Thrown when a tenant id is not a single-segment root namespace. */
export class InvalidTenantIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidTenantIdError";
  }
}

/** Thrown when a non-owner attempts an owner-only tenant operation. */
export class TenantAuthzError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantAuthzError";
  }
}

/**
 * The first `/`-split segment of a namespace = its tenant root. Empty/blank
 * namespaces yield "" (which resolves to no tenant). Mirrors the ancestor
 * split used by the ACL so the two can never drift.
 */
export function tenantRootOf(namespace: Namespace): Namespace {
  const first = namespace.split("/").find((p) => p.length > 0);
  return first ?? "";
}

/** A tenant id must be exactly one non-empty namespace segment (no `/`). */
export function isValidTenantId(id: string): boolean {
  return id.length > 0 && !id.includes("/");
}

interface TenantRow {
  id: string;
  name: string;
  status: string;
  monthly_budget_usd: number | string | null;
  rate_limit_per_min: number | string | null;
  onboarding_completed_at?: Date | string | null;
  created_at: Date | string;
}

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

function rowToTenant(row: TenantRow): Tenant {
  return {
    id: row.id,
    name: row.name,
    status: row.status as Tenant["status"],
    monthlyBudgetUsd:
      row.monthly_budget_usd === null || row.monthly_budget_usd === undefined
        ? null
        : Number(row.monthly_budget_usd),
    rateLimitPerMin:
      row.rate_limit_per_min === null || row.rate_limit_per_min === undefined
        ? null
        : Number(row.rate_limit_per_min),
    onboardingCompletedAt:
      row.onboarding_completed_at === null ||
      row.onboarding_completed_at === undefined
        ? null
        : toIso(row.onboarding_completed_at),
    createdAt: toIso(row.created_at),
  };
}

const SELECT_COLUMNS =
  "id, name, status, monthly_budget_usd, rate_limit_per_min, onboarding_completed_at, created_at";

/** Fields a caller supplies to register a tenant (id + name required). */
export interface TenantInput {
  id: Namespace;
  name: string;
  monthlyBudgetUsd?: number | null;
  rateLimitPerMin?: number | null;
}

export interface TenantRegistryOptions {
  /**
   * Default skill library hook (src/skills/defaults.ts): invoked with the new
   * tenant root after its row lands. The kernel wiring brownouts on failure.
   */
  seedDefaultSkills?: (namespace: Namespace) => Promise<void>;
}

export class TenantRegistry {
  constructor(
    private readonly db: Db,
    private readonly options: TenantRegistryOptions = {},
  ) {}

  /**
   * Register a new tenant. Platform-root owner only (D9). The id must be a single-segment
   * root namespace — no `/`, non-empty — so a tenant is always a true root the
   * ancestor ACL isolates. Idempotent-safe: a duplicate id throws (PK).
   */
  async register(tenant: TenantInput, identity: Identity): Promise<Tenant> {
    if (!isRootOwner(identity)) {
      throw new TenantAuthzError("register tenant requires a root owner identity");
    }
    if (!isValidTenantId(tenant.id)) {
      throw new InvalidTenantIdError(
        `tenant id '${tenant.id}' must be a single-segment root namespace (no '/')`,
      );
    }
    const name = normalizedOrganizationName(tenant.name);
    const createdAt = new Date().toISOString();
    await this.db.query(
      `INSERT INTO tenants (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
       VALUES ($1, $2, 'active', $3, $4, $5)`,
      [
        tenant.id,
        name,
        tenant.monthlyBudgetUsd ?? null,
        tenant.rateLimitPerMin ?? null,
        createdAt,
      ],
    );
    await this.options.seedDefaultSkills?.(tenant.id);
    return {
      id: tenant.id,
      name,
      status: "active",
      monthlyBudgetUsd: tenant.monthlyBudgetUsd ?? null,
      rateLimitPerMin: tenant.rateLimitPerMin ?? null,
      onboardingCompletedAt: null,
      createdAt,
    };
  }

  /** Fetch a tenant by its exact root id, or null. */
  async get(id: Namespace): Promise<Tenant | null> {
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM tenants WHERE id = $1`,
      [id],
    );
    if (res.rows.length === 0) return null;
    return rowToTenant(res.rows[0] as TenantRow);
  }

  /**
   * List tenants visible to the caller, scoped to the SAME ancestor-prefix ACL
   * the index uses. A tenant id is visible iff it is an ancestor-or-self of the
   * caller's namespace (`namespaceAncestors` → exact `IN (...)`). An `acme`
   * owner's ancestor set is `{acme, ...}` and never contains a sibling root like
   * `globex`, so sibling tenants are invisible — no parallel filter that could
   * drift from the ACL, and no LIKE wildcard.
   */
  async list(identity: Identity): Promise<Tenant[]> {
    if (isRootOwner(identity)) {
      const res = await this.db.query(
        `SELECT ${SELECT_COLUMNS} FROM tenants ORDER BY id ASC`,
      );
      return (res.rows as TenantRow[]).map(rowToTenant);
    }
    const allowed = namespaceAncestors(identity.namespace);
    if (allowed.length === 0) return [];
    const placeholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM tenants
       WHERE id IN (${placeholders})
       ORDER BY id ASC`,
      allowed,
    );
    return (res.rows as TenantRow[]).map(rowToTenant);
  }

  /** Flip a tenant to `suspended` (a bulk revoke of its keyspace). */
  async suspend(id: Namespace): Promise<Tenant | null> {
    return this.setStatus(id, "suspended");
  }

  /** Flip a tenant back to `active`. */
  async activate(id: Namespace): Promise<Tenant | null> {
    return this.setStatus(id, "active");
  }

  private async setStatus(
    id: Namespace,
    status: Tenant["status"],
  ): Promise<Tenant | null> {
    const res = await this.db.query(
      `UPDATE tenants SET status = $2 WHERE id = $1 RETURNING ${SELECT_COLUMNS}`,
      [id, status],
    );
    if (res.rows.length === 0) return null;
    return rowToTenant(res.rows[0] as TenantRow);
  }

  /**
   * Resolve the tenant that OWNS a namespace = the tenant at its root, or null
   * when the root is unregistered. This is the hook the governance gate uses to
   * find the caps/status inherited by the whole subtree.
   */
  async resolveTenant(namespace: Namespace): Promise<Tenant | null> {
    const root = tenantRootOf(namespace);
    if (root.length === 0) return null;
    return this.get(root);
  }
}
