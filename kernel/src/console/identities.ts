/**
 * External identity links — the ONE join between a third-party account
 * (GitHub, Google) and a kernel `users` row (migration v42 + v57).
 *
 * The table is the only thing that makes "Sign in with X" land on an existing
 * account. Two invariants hold it together:
 *
 *  - UNIQUE(provider, provider_account_id) — a provider account resolves to at
 *    most one kernel user.
 *  - UNIQUE(user_id, provider) — a user connects at most one account per
 *    provider.
 *
 * Providers differ in how a link is CREATED, and that difference is
 * deliberate (see the module headers of `github-sso.ts` and `sso.ts`):
 *
 *  - `github`: never created by email match. An unlinked GitHub login gets its
 *    own account; only an explicit "Connect GitHub" from the signed-in Profile
 *    screen links the two.
 *  - `google`: the Supabase SSO exchange already grants a session on a
 *    verified email match, so recording the link there adds no privilege — it
 *    only makes the connection VISIBLE and stable (a later Google email change
 *    still lands on the same account).
 */

import { ulid } from "ulid";

import type { Db } from "../db/client.js";

/** Providers the link table accepts (migration v57 CHECK constraint). */
export type ExternalProvider = "github" | "google";

export const EXTERNAL_PROVIDERS: readonly ExternalProvider[] = ["github", "google"];

export function isExternalProvider(value: string): value is ExternalProvider {
  return (EXTERNAL_PROVIDERS as readonly string[]).includes(value);
}

export interface ExternalIdentity {
  id: string;
  userId: string;
  provider: ExternalProvider;
  providerAccountId: string;
  /** Provider-side handle (GitHub login, Google email/name), for display. */
  login: string;
  email: string | null;
  createdAt: string;
}

/** The minimum a provider must prove before a link row may be written. */
export interface ExternalIdentityProfile {
  /** Stable provider-side account id — never an email, never reused. */
  id: string;
  login: string;
  /** Verified provider email, or null when the provider exposes none. */
  email: string | null;
}

/** Thrown when a provider account is already linked to a DIFFERENT user. */
export class IdentityConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConflictError";
  }
}

interface IdentityRow {
  id: string;
  user_id: string;
  provider: string;
  provider_account_id: string;
  login: string;
  email: string | null;
  created_at: Date | string;
}

function rowToIdentity(row: IdentityRow): ExternalIdentity {
  return {
    id: row.id,
    userId: row.user_id,
    provider: row.provider as ExternalProvider,
    providerAccountId: row.provider_account_id,
    login: row.login,
    email: row.email,
    createdAt:
      row.created_at instanceof Date
        ? row.created_at.toISOString()
        : new Date(row.created_at).toISOString(),
  };
}

const IDENTITY_COLUMNS =
  `id, user_id, provider, provider_account_id, login, email, created_at`;

export class ExternalIdentityStore {
  constructor(private readonly db: Db) {}

  /** Resolve a provider account to its linked identity row. Null if unlinked. */
  async findByProviderId(
    provider: ExternalProvider,
    providerAccountId: string,
  ): Promise<ExternalIdentity | null> {
    const res = await this.db.query(
      `SELECT ${IDENTITY_COLUMNS} FROM user_external_identities
       WHERE provider = $1 AND provider_account_id = $2`,
      [provider, providerAccountId],
    );
    const row = res.rows[0] as IdentityRow | undefined;
    return row ? rowToIdentity(row) : null;
  }

  /** The user's link for one provider (at most one per UNIQUE(user_id, provider)). */
  async findForUser(
    userId: string,
    provider: ExternalProvider,
  ): Promise<ExternalIdentity | null> {
    const res = await this.db.query(
      `SELECT ${IDENTITY_COLUMNS} FROM user_external_identities
       WHERE user_id = $1 AND provider = $2`,
      [userId, provider],
    );
    const row = res.rows[0] as IdentityRow | undefined;
    return row ? rowToIdentity(row) : null;
  }

  /** Every external identity linked to a user (Profile screen listing). */
  async listForUser(userId: string): Promise<ExternalIdentity[]> {
    const res = await this.db.query(
      `SELECT ${IDENTITY_COLUMNS} FROM user_external_identities
       WHERE user_id = $1 ORDER BY created_at`,
      [userId],
    );
    return (res.rows as IdentityRow[]).map(rowToIdentity);
  }

  /**
   * Link a provider account to a user. Idempotent when the same pair is already
   * linked; IdentityConflictError when the provider account belongs to a
   * DIFFERENT user or the user already linked a different account for that
   * provider.
   */
  async link(
    userId: string,
    provider: ExternalProvider,
    profile: ExternalIdentityProfile,
  ): Promise<ExternalIdentity> {
    const existing = await this.findByProviderId(provider, profile.id);
    if (existing !== null) {
      if (existing.userId === userId) return existing;
      throw new IdentityConflictError(
        `this ${label(provider)} account is already connected to a different user`,
      );
    }
    const mine = await this.findForUser(userId, provider);
    if (mine !== null) {
      throw new IdentityConflictError(
        `a different ${label(provider)} account is already connected to this user`,
      );
    }
    const id = ulid();
    const createdAt = new Date().toISOString();
    try {
      await this.db.query(
        `INSERT INTO user_external_identities
           (id, user_id, provider, provider_account_id, login, email, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, userId, provider, profile.id, profile.login, profile.email, createdAt],
      );
    } catch (err) {
      // Unique-violation race → resolve the winner and report the conflict.
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) {
        const winner = await this.findByProviderId(provider, profile.id);
        if (winner !== null && winner.userId === userId) return winner;
        throw new IdentityConflictError(
          `this ${label(provider)} account is already connected to a different user`,
        );
      }
      throw err;
    }
    return {
      id,
      userId,
      provider,
      providerAccountId: profile.id,
      login: profile.login,
      email: profile.email,
      createdAt,
    };
  }

  /** Remove the user's link for one provider. True if a row was removed. */
  async unlink(userId: string, provider: ExternalProvider): Promise<boolean> {
    const res = await this.db.query(
      `DELETE FROM user_external_identities
       WHERE user_id = $1 AND provider = $2 RETURNING id`,
      [userId, provider],
    );
    return res.rows.length > 0;
  }
}

function label(provider: ExternalProvider): string {
  return provider === "github" ? "GitHub" : "Google";
}
