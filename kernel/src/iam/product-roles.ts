/**
 * M10 (D41, FR1) — the ONE product-role translation seam.
 *
 * The product boundary exposes exactly three human roles: `root`, `admin`,
 * `member` (`ProductHumanRole`). Internal storage (`users.role`,
 * `api_keys.role`, sessions, `HumanRole`, `rbac.ts`) is UNCHANGED this
 * milestone: `owner` translates to product role `root`; `auditor` translates
 * to `member` plus an explicit `audit:read` entitlement. This module is the
 * only place that translation may live — no scattered ternaries — and it is
 * applied only where a role string crosses the public/console HTTP boundary
 * (session/user payloads, people serializations, the S5 graph response).
 *
 * Inverse direction (public input -> internal storage value): new UI/API
 * paths must never mint `auditor` (throw) and may map `root` -> `owner`
 * ONLY through the documented root-assignment/bootstrap route
 * (`{ rootAssignment: true }`). Machine `agent` is a principal type, never a
 * human role, and never passes through this seam.
 */

import type { HumanRole, ProductHumanRole } from "../types.js";

/** The only human roles the product boundary exposes (D41). */
export const PRODUCT_HUMAN_ROLES: readonly ProductHumanRole[] = [
  "root",
  "admin",
  "member",
];

/** The scoped entitlement that replaces the retired `auditor` role. */
export const AUDIT_READ_ENTITLEMENT = "audit:read";

/** Type guard for a product human role value. */
export function isProductHumanRole(value: string): value is ProductHumanRole {
  return value === "root" || value === "admin" || value === "member";
}

/** What `toProductRole` yields for one internal role value. */
export interface ProductRoleView {
  role: ProductHumanRole;
  /** Explicit scoped entitlements (e.g. `audit:read` for legacy auditors). */
  entitlements: readonly string[];
  /** Present only when the internal value was unknown (fail-closed). */
  note?: string;
}

/**
 * Internal role -> product boundary view. Total: unknown values fail CLOSED
 * to `member` with zero entitlements and a note — never a wider role.
 */
export function toProductRole(internalRole: string): ProductRoleView {
  switch (internalRole) {
    case "owner":
      return { role: "root", entitlements: [] };
    case "admin":
      return { role: "admin", entitlements: [] };
    case "member":
      return { role: "member", entitlements: [] };
    case "auditor":
      return { role: "member", entitlements: [AUDIT_READ_ENTITLEMENT] };
    default:
      return {
        role: "member",
        entitlements: [],
        note: `unknown internal role '${internalRole}' surfaced as 'member' (fail-closed)`,
      };
  }
}

/** Short display label for a product role (UI-text rule: one plain word). */
export function productRoleLabel(role: ProductHumanRole): string {
  if (role === "root") return "Root";
  if (role === "admin") return "Admin";
  return "Member";
}

/** 400-mapped input error (same `name` convention as TeamBadRequestError). */
export class ProductRoleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

/**
 * Product role (public input) -> the internal value new assignments persist.
 *
 * - `admin` / `member` pass through unchanged.
 * - `auditor` is retired: ALWAYS throws — assign `member` plus a scoped
 *   `audit:read` grant instead (D41).
 * - `owner` is not a product role: ALWAYS throws.
 * - `root` -> `owner` ONLY when the caller is the documented
 *   root-assignment/bootstrap route (`{ rootAssignment: true }`); every other
 *   path throws. This is the compatibility hinge — nothing else may mint an
 *   internal `owner`.
 */
export function fromProductRole(
  product: string,
  options?: { rootAssignment?: boolean },
): HumanRole {
  if (product === "admin" || product === "member") return product;
  if (product === "auditor") {
    throw new ProductRoleError(
      "'auditor' is retired; assign 'member' plus an 'audit:read' grant",
    );
  }
  if (product === "owner") {
    throw new ProductRoleError(
      "'owner' is not a product role; 'root' is assigned only via the root-assignment route",
    );
  }
  if (product === "root") {
    if (options?.rootAssignment === true) return "owner";
    throw new ProductRoleError(
      "'root' may only be assigned via the root-assignment route",
    );
  }
  throw new ProductRoleError(`invalid product role '${product}'`);
}

/**
 * Serialize one user-shaped record for a public/console response: the
 * internal `role` is replaced by its product role, and non-empty entitlements
 * (legacy auditor -> `audit:read`) are attached. Every other field passes
 * through untouched. Never mutates its input.
 */
export function toPublicUser<T extends { role: string }>(
  record: T,
): Omit<T, "role"> & { role: ProductHumanRole; entitlements?: readonly string[] } {
  const view = toProductRole(record.role);
  const out: Omit<T, "role"> & {
    role: ProductHumanRole;
    entitlements?: readonly string[];
  } = { ...record, role: view.role };
  if (view.entitlements.length > 0) out.entitlements = view.entitlements;
  return out;
}
