import { randomBytes } from "node:crypto";
import { ulid } from "ulid";

import { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import type { Tenant, User } from "../types.js";
import { DEFAULT_SESSION_TTL_SECONDS, hashToken } from "./auth.js";
import {
  deriveTenantId,
  normalizedOrganizationName as sharedNormalizedOrganizationName,
} from "./org-name.js";
import {
  HumanDisplayNameError,
  humanNameFromAccountKey,
  normalizedHumanDisplayName,
} from "./person-name.js";

export const SIGNUP_TTL_SECONDS = 10 * 60;

export class SignupValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignupValidationError";
  }
}

export class SignupConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignupConflictError";
  }
}

export interface IssuedSignup {
  token: string;
  email: string;
  expiresAt: string;
}

export interface PendingSignup {
  email: string;
}

export interface SignupCompletion {
  token: string;
  organization: Tenant;
  user: User;
}

interface SignupServiceOptions {
  now?: () => Date;
  signupToken?: () => string;
  sessionToken?: () => string;
  userId?: () => string;
  tenantUlid?: () => string;
  audit?: AuditLog;
  /**
   * Default skill library hook (src/skills/defaults.ts): invoked with the new
   * tenant root after the signup transaction commits. The kernel wiring
   * brownouts on failure — provisioning never fails on a seed error.
   */
  seedDefaultSkills?: (namespace: string) => Promise<void>;
}

interface SignupRow {
  email: string;
  expires_at: Date | string;
  consumed_at: Date | string | null;
}

function normalizedEmail(value: string): string {
  const email = value.trim().toLowerCase();
  if (email.length === 0 || email.length > 320 || !email.includes("@")) {
    throw new SignupValidationError("invalid verified email");
  }
  return email;
}

/**
 * Shared with the install-time bootstrap path (`src/console/org-name.ts`) so
 * the two organization-creating paths derive identical ids. The signup surface
 * keeps reporting its own error type, so the HTTP status mapping here is
 * unchanged.
 */
function normalizedOrganizationName(value: string): string {
  try {
    return sharedNormalizedOrganizationName(value);
  } catch (err) {
    throw new SignupValidationError(
      err instanceof Error ? err.message : String(err),
    );
  }
}

/**
 * Whether an IdP-verified email that matches no user and no invitation may
 * create a NEW isolated organization.
 *
 * Early access defaults hosted signup to invite-only, but the two are separate
 * decisions: `HALOMEM_ALLOW_ORG_SIGNUP` overrides that default in either
 * direction, so trial limits and metering can stay ON while self-service
 * signup stays OPEN. Anything other than the two explicit strings falls back
 * to the early-access default (fail-closed while the gate is on).
 */
export function organizationSignupAllowed(
  env: Record<string, string | undefined> = process.env,
  earlyAccessEnabled: boolean = env.HALOMEM_EARLY_ACCESS === "true",
): boolean {
  const override = env.HALOMEM_ALLOW_ORG_SIGNUP;
  if (override === "true") return true;
  if (override === "false") return false;
  return !earlyAccessEnabled;
}

/**
 * Narrow capability for a verified unknown SSO identity to create exactly one
 * new tenant and its first owner. It deliberately does not call or weaken the
 * platform-root TenantRegistry.register authorization path.
 */
export class OrganizationSignupService {
  private readonly now: () => Date;
  private readonly signupToken: () => string;
  private readonly sessionToken: () => string;
  private readonly userId: () => string;
  private readonly tenantUlid: () => string;
  private readonly audit: AuditLog;
  private readonly seedDefaultSkills?: (namespace: string) => Promise<void>;

  constructor(
    private readonly db: Db,
    options: SignupServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.signupToken = options.signupToken ?? (() => randomBytes(32).toString("hex"));
    this.sessionToken = options.sessionToken ?? (() => randomBytes(32).toString("hex"));
    this.userId = options.userId ?? ulid;
    this.tenantUlid = options.tenantUlid ?? ulid;
    this.audit = options.audit ?? new AuditLog(db);
    this.seedDefaultSkills = options.seedDefaultSkills;
  }

  /** Rotate a ten-minute, hashed-at-rest authority for one verified email. */
  async issue(value: string): Promise<IssuedSignup> {
    const email = normalizedEmail(value);
    const token = this.signupToken();
    const createdAt = this.now();
    const expiresAt = new Date(createdAt.getTime() + SIGNUP_TTL_SECONDS * 1000);

    await this.db.transaction(async (tx) => {
      const existing = await tx.query(`SELECT status FROM users WHERE email = $1`, [email]);
      if (existing.rows.length > 0) {
        throw new SignupConflictError("the verified identity already has an account");
      }
      await tx.query(
        `INSERT INTO auth_signup_sessions
           (id, email, created_at, expires_at, consumed_at)
         VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (email) DO UPDATE SET
           id = EXCLUDED.id,
           created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at,
           consumed_at = NULL`,
        [hashToken(token), email, createdAt.toISOString(), expiresAt.toISOString()],
      );
      // The upsert may have waited behind a concurrent completion that created
      // the user after our first read. Re-check after taking the unique signup
      // row so that race rolls this authority back instead of leaving a stale
      // ticket for an existing account.
      const afterUpsert = await tx.query(`SELECT status FROM users WHERE email = $1`, [email]);
      if (afterUpsert.rows.length > 0) {
        throw new SignupConflictError("the verified identity already has an account");
      }
    });

    return { token, email, expiresAt: expiresAt.toISOString() };
  }

  /** Resolve only live, unconsumed signup authority. */
  async inspect(token: string): Promise<PendingSignup | null> {
    if (typeof token !== "string" || token.length === 0 || token.length > 512) return null;
    const result = await this.db.query(
      `SELECT email, expires_at, consumed_at
       FROM auth_signup_sessions WHERE id = $1`,
      [hashToken(token)],
    );
    const row = result.rows[0] as SignupRow | undefined;
    if (
      !row ||
      row.consumed_at !== null ||
      new Date(row.expires_at).getTime() <= this.now().getTime()
    ) {
      return null;
    }
    return { email: row.email };
  }

  /**
   * Atomically create the isolated tenant, first owner, normal session, audit
   * evidence, and consume the verified-email signup authority.
   */
  async complete(
    token: string,
    value: string,
    displayNameInput?: string,
  ): Promise<SignupCompletion | null> {
    const name = normalizedOrganizationName(value);
    let requestedDisplayName: string | null = null;
    if (displayNameInput !== undefined) {
      try {
        requestedDisplayName = normalizedHumanDisplayName(displayNameInput);
      } catch (error) {
        if (error instanceof HumanDisplayNameError) {
          throw new SignupValidationError(error.message);
        }
        throw error;
      }
    }
    if (typeof token !== "string" || token.length === 0 || token.length > 512) return null;
    const tokenHash = hashToken(token);
    const completedAt = this.now();
    const completedAtIso = completedAt.toISOString();
    const sessionExpiresAt = new Date(
      completedAt.getTime() + DEFAULT_SESSION_TTL_SECONDS * 1000,
    ).toISOString();
    const sessionToken = this.sessionToken();
    const tenantId = deriveTenantId(name, this.tenantUlid);
    const userId = this.userId();

    try {
      const completion: SignupCompletion | null = await this.db.transaction(async (tx) => {
        const pending = await tx.query(
          `SELECT email, expires_at, consumed_at
           FROM auth_signup_sessions WHERE id = $1 FOR UPDATE`,
          [tokenHash],
        );
        const row = pending.rows[0] as SignupRow | undefined;
        if (
          !row ||
          row.consumed_at !== null ||
          new Date(row.expires_at).getTime() <= completedAt.getTime()
        ) {
          return null;
        }

        const existing = await tx.query(`SELECT id FROM users WHERE email = $1`, [row.email]);
        if (existing.rows.length > 0) {
          throw new SignupConflictError("the verified identity already has an account");
        }

        const displayName = requestedDisplayName ?? humanNameFromAccountKey(row.email);
        await tx.query(
          `INSERT INTO tenants
             (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
           VALUES ($1, $2, 'active', NULL, NULL, $3)`,
          [tenantId, name, completedAtIso],
        );
        await tx.query(
          `INSERT INTO users
             (id, email, display_name, namespace, role, password_hash, status, created_at)
           VALUES ($1, $2, $3, $4, 'owner', NULL, 'active', $5)`,
          [userId, row.email, displayName, tenantId, completedAtIso],
        );
        await tx.query(
          `INSERT INTO sessions (id, user_id, created_at, expires_at)
           VALUES ($1, $2, $3, $4)`,
          [hashToken(sessionToken), userId, completedAtIso, sessionExpiresAt],
        );
        const consumed = await tx.query(
          `UPDATE auth_signup_sessions SET consumed_at = $1
           WHERE id = $2 AND consumed_at IS NULL RETURNING id`,
          [completedAtIso, tokenHash],
        );
        if (consumed.rows.length !== 1) {
          throw new SignupConflictError("signup authority was already consumed");
        }
        await this.audit.appendTo(tx, {
          ts: completedAtIso,
          actor: row.email,
          agentId: "console",
          op: "write",
          memoryId: null,
          namespace: tenantId,
          purpose: "console-self-service-signup",
          result: "ok",
          detail: "organization and first owner created",
        });

        return {
          token: sessionToken,
          organization: {
            id: tenantId,
            name,
            status: "active",
            monthlyBudgetUsd: null,
            rateLimitPerMin: null,
            onboardingCompletedAt: null,
            createdAt: completedAtIso,
          },
          user: {
            id: userId,
            email: row.email,
            displayName,
            namespace: tenantId,
            role: "owner",
            status: "active",
            createdAt: completedAtIso,
          },
        };
      });
      // Seed the default skill library at the new tenant root AFTER commit:
      // the seeder opens its own transactions on the shared handle.
      if (completion !== null) {
        await this.seedDefaultSkills?.(completion.organization.id);
      }
      return completion;
    } catch (err) {
      if (err instanceof SignupConflictError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) {
        throw new SignupConflictError("signup conflicts with an existing account or organization");
      }
      throw err;
    }
  }
}
