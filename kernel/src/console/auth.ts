/**
 * Module A (M5 part 1) — human sign-in for the control room.
 *
 * Agents authenticate with badges (API keys, D9); humans sign in with
 * email + password and act through a role. A resolved session yields the
 * SAME `Identity` shape the syscalls already require (keyId = session id,
 * namespace, actor = email, role) — the control room is a face on existing
 * controls, not a second auth system. The role is NEVER "agent": humans are
 * owner | admin | auditor | member (`HumanRole`, `Exclude<Role,"agent">`).
 *
 * Security invariants (the review will attack these):
 *  - Passwords are stored as `salt:scryptHash` where salt is 16 random bytes
 *    and the hash is scrypt(password, salt, 64). The plaintext password is
 *    NEVER stored and NEVER logged.
 *  - Session tokens are opaque `randomBytes(32).hex` (unpredictable). At rest
 *    `sessions.id` stores `sha256(token)` — a stolen DB never yields a live
 *    cookie. The raw token is NEVER logged.
 *  - Expiry is enforced server-side (`resolve` rejects `expires_at <= now`).
 *  - A disabled user cannot resolve a session (the JOIN filters on status).
 *  - `login` gives NO oracle: unknown email and wrong password both return
 *    null after a constant-shaped scrypt comparison against a decoy hash, so
 *    an attacker cannot distinguish the two from timing or the response.
 *
 * Imports: shared types (`src/types.js`), the db handle (`src/db/client.js`),
 * and `Role`/`isRole` from `src/auth/index.js`. It constructs its own SQL over
 * the migration-007 `users`/`sessions` tables (its whole surface).
 */

import {
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { ulid } from "ulid";

import { escapeLikePattern, type Db } from "../db/client.js";
import { isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import { tenantRoots } from "../team-memory-access/index.js";
import { AuditLog } from "../audit/index.js";
import { deriveTenantId, normalizedOrganizationName } from "./org-name.js";
import {
  HumanDisplayNameError,
  humanNameFromAccountKey,
  normalizedHumanDisplayName,
} from "./person-name.js";
import type { HumanRole, Identity, Session, Tenant, User } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Session IDLE lifetime: ten days since the last authenticated request.
 *
 * This is a sliding window, not a fixed one — `SessionStore.resolve` pushes
 * `expires_at` forward every time the session is used (see
 * `SESSION_RENEW_AFTER_SECONDS`). A human who works in the console regularly is
 * never signed out mid-use; an abandoned session still dies ten days later.
 *
 * Keep `SESSION_MAX_AGE_SECONDS` (src/http/console.ts) equal to this — that one
 * is the browser's copy of the same window, and the transport re-sends it on
 * every cookie-authenticated request so the two slide together. The server is
 * still the authority: `resolve` rejects `expires_at <= now` regardless of what
 * the browser kept.
 */
export const DEFAULT_SESSION_TTL_SECONDS = 10 * 24 * 3600;

/**
 * Absolute ceiling measured from `sessions.created_at`: a session may slide,
 * but never past ninety days. Without this a cookie stolen from an active user
 * would renew itself forever. Uses the existing `created_at` column, so no
 * migration is involved.
 */
export const SESSION_ABSOLUTE_TTL_SECONDS = 90 * 24 * 3600;

/**
 * Write throttle for the slide. `resolve` runs on EVERY cookie-authenticated
 * request, so it only issues the `UPDATE` once the window has drifted by at
 * least this much — one write per session per hour instead of one per request.
 * The cost is that the effective idle window is `DEFAULT_SESSION_TTL_SECONDS`
 * minus at most this, which at ten days versus one hour is immaterial.
 */
export const SESSION_RENEW_AFTER_SECONDS = 3600;

/** Default activation window for a copy-once invitation token: seven days. */
export const DEFAULT_INVITE_TTL_SECONDS = 7 * 24 * 3600;

const MIN_BOOTSTRAP_TOKEN_BYTES = 32;
const MIN_PASSWORD_LENGTH = 12;

/** scrypt key length (bytes) — matches CONTRACTS (scryptSync(pw, salt, 64)). */
const SCRYPT_KEYLEN = 64;

/** Salt length (bytes) for password hashing. */
const SALT_BYTES = 16;

/** Human roles: owner | admin | auditor | member — NEVER agent. */
const HUMAN_ROLES: readonly HumanRole[] = ["owner", "admin", "auditor", "member"];

/** True for a valid human role (owner|admin|auditor|member); rejects 'agent'. */
export function isHumanRole(value: string): value is HumanRole {
  return (HUMAN_ROLES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown on role/scope denials in the user store (maps to HTTP 403 in the
 * transport layer via server.ts's name-based mapping — same convention as
 * AuthService's AuthzError). Kept structurally identical (`name === "AuthzError"`)
 * so the transport treats it exactly like the API-key path's denials.
 */
export class UserAuthzError extends Error {
  constructor(message: string) {
    super(message);
    // Name matches AuthService.AuthzError so server.ts maps it to 403.
    this.name = "AuthzError";
  }
}

/** 400-mapped caller error (bad role, bad email, duplicate). */
export class UserBadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

// ---------------------------------------------------------------------------
// Password hashing (scrypt + constant-time compare)
// ---------------------------------------------------------------------------

/** Hash a plaintext password to `salt:scryptHash` (both hex). NEVER logs. */
export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_BYTES);
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN);
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

/**
 * Verify a plaintext password against a stored `salt:hash`. Uses
 * `timingSafeEqual` so a partial-match cannot be distinguished by timing.
 * Returns false (never throws) for a malformed stored value or a null hash.
 */
export function verifyPassword(stored: string | null, password: string): boolean {
  if (typeof stored !== "string") return false;
  const idx = stored.indexOf(":");
  if (idx <= 0 || idx === stored.length - 1) return false;
  const saltHex = stored.slice(0, idx);
  const hashHex = stored.slice(idx + 1);
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(saltHex, "hex");
    expected = Buffer.from(hashHex, "hex");
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;
  let derived: Buffer;
  try {
    derived = scryptSync(password, salt, expected.length);
  } catch {
    return false;
  }
  // Lengths always match here (derived to expected.length), but guard anyway:
  // timingSafeEqual throws on a length mismatch.
  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}

// A decoy stored hash used to keep `login`'s cost constant when the email is
// unknown — the scrypt work runs either way so an attacker cannot tell an
// unknown email from a wrong password by timing. Computed once at module load
// from a random password nobody knows.
const DECOY_STORED_HASH = hashPassword(randomBytes(32).toString("hex"));

// ---------------------------------------------------------------------------
// Token hashing
// ---------------------------------------------------------------------------

/** sha256 hex of a session token — what `sessions.id` stores at rest. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function equalTokenHashes(left: string, right: string): boolean {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

function normalizedEmail(email: string): string {
  const value = email.trim().toLowerCase();
  if (value.length === 0 || value.length > 320 || !value.includes("@")) {
    throw new UserBadRequestError("email is invalid");
  }
  return value;
}

function assertCredentialPassword(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH || password.length > 1024) {
    throw new UserBadRequestError(
      `password must be between ${MIN_PASSWORD_LENGTH} and 1024 characters`,
    );
  }
}

// ---------------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  email: string;
  display_name: string;
  avatar: string | null;
  namespace: string;
  role: string;
  status: string;
  created_at: Date | string;
}

interface UserRowWithHash extends UserRow {
  password_hash: string | null;
}

interface SessionJoinRow {
  id: string;
  user_id: string;
  created_at: Date | string;
  expires_at: Date | string;
  email: string;
  namespace: string;
  role: string;
  status: string;
}

/**
 * A live session plus whether resolving it slid `expires_at` forward. `renewed`
 * is the transport's cue to re-send the browser cookie so the two windows stay
 * in step; it is never a security signal.
 */
export interface ResolvedSession {
  session: Session;
  renewed: boolean;
}

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    avatar: row.avatar,
    namespace: row.namespace,
    role: row.role as HumanRole,
    status: row.status as User["status"],
    createdAt: toIso(row.created_at),
  };
}

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

/**
 * Where a PLATFORM-root (namespace "") caller files a new human. Root sits
 * above every organization, so a bare namespace like `tech` names no org and
 * would strand the user (and everything keyed off their namespace) outside
 * all of them. If the first segment already names a tenant the caller was
 * explicit — keep it. Otherwise attach under the sole tenant; with several
 * tenants refuse rather than guess. Namespace "" (another platform admin) and
 * non-root callers pass through untouched — their subtree checks already ran.
 */
async function organizationAttachedNamespace(
  db: Db,
  caller: Identity | null | undefined,
  namespace: string,
): Promise<string> {
  if (!caller || !isRootOwner(caller) || namespace === "") return namespace;
  const first = namespace.split("/", 1)[0]!;
  const known = await db.query(`SELECT id FROM tenants WHERE id = $1`, [first]);
  if (known.rows.length > 0) return namespace;
  const roots = await tenantRoots(db);
  if (roots.length === 0) return namespace;
  if (roots.length > 1) {
    throw new UserBadRequestError(
      `namespace '${namespace}' belongs to no organization - prefix it with an organization root`,
    );
  }
  return `${roots[0]}/${namespace}`;
}

export interface CreateUserInput {
  email: string;
  /** Human-facing name. Legacy trusted callers derive one from the account key. */
  displayName?: string;
  namespace: string;
  role: HumanRole;
  password?: string;
}

export class UserStore {
  constructor(private readonly db: Db) {}

  /**
   * Create a human user.
   *
   * Authorization: the bootstrap exception keys off "no caller present" (a
   * direct-DB/CLI process), NOT merely "table empty" — so a transport caller
   * can never mint an arbitrary owner while `users` is empty. With no caller and
   * an empty table, the first (owner) user is bootstrapped. With a caller, an
   * A root OWNER may mint any human role anywhere. A tenant OWNER may mint any
   * human role in its own subtree. An ADMIN may invite non-owner roles
   * (member/admin/auditor) in its subtree but may NOT mint an owner (that would
   * escalate a subtree-scoped admin to org owner); any other caller is denied.
   *
   * Validates that `role` is a HumanRole (rejects 'agent'). Rejects a
   * duplicate email. Passwords are stored `salt:scryptHash` — never plaintext.
   */
  async create(input: CreateUserInput, caller?: Identity | null): Promise<User> {
    const email = normalizedEmail(input.email);
    let displayName: string;
    try {
      displayName = input.displayName === undefined
        ? humanNameFromAccountKey(email)
        : normalizedHumanDisplayName(input.displayName);
    } catch (error) {
      if (error instanceof HumanDisplayNameError) {
        throw new UserBadRequestError(error.message);
      }
      throw error;
    }
    if (!isHumanRole(input.role)) {
      // Explicitly reject 'agent' and anything not owner|admin|auditor|member.
      throw new UserBadRequestError(`create: invalid human role '${input.role}'`);
    }

    // Authorization. The bootstrap exception keys off "no caller present" (a
    // direct-DB/CLI process), NOT merely "table empty": every transport path
    // (invite over HTTP) always carries a resolved caller, so it can NEVER take
    // the bootstrap branch and mint an arbitrary owner while `users` is empty
    // (users and api_keys are independent tables — the pre-first-login state is
    // empty users + populated api_keys, so an admin bearer/session identity is
    // a live caller). Rules:
    //  - no caller + empty table → bootstrap the first owner (direct DB only);
    //  - root owner caller       → may mint any human role anywhere;
    //  - tenant owner caller     → may mint any human role in its subtree;
    //  - admin caller            → may invite non-owner roles (member/admin/
    //    auditor) in its scope (scope already gated upstream); minting an OWNER
    //    requires an owner caller (prevents subtree-admin → org-owner escalation);
    //  - anything else           → denied.
    const firstHumanCheck = await this.db.query(`SELECT COUNT(*) AS n FROM users`);
    if (Number(firstHumanCheck.rows[0].n) === 0) {
      throw new UserAuthzError(
        "first human creation requires the single-use bootstrap credential",
      );
    }
    if (!caller) {
      const countRes = await this.db.query(`SELECT COUNT(*) AS n FROM users`);
      const empty = Number(countRes.rows[0].n) === 0;
      if (!empty) {
        throw new UserAuthzError(
          `create user requires an owner identity (caller role: none)`,
        );
      }
      // empty table + no caller → bootstrap the first (owner) user; fall through.
    } else if (caller.role === "owner") {
      if (!isRootOwner(caller) && !isSelfOrDescendant(input.namespace, caller.namespace)) {
        throw new UserAuthzError(
          `create user denied: namespace '${input.namespace}' is outside your subtree`,
        );
      }
    } else if (caller.role === "admin" && input.role !== "owner") {
      if (!isSelfOrDescendant(input.namespace, caller.namespace)) {
        throw new UserAuthzError(
          `create user denied: namespace '${input.namespace}' is outside your subtree`,
        );
      }
    } else {
      throw new UserAuthzError(
        `create user requires an owner identity to mint role '${input.role}' (caller role: ${caller.role})`,
      );
    }

    const namespace = await organizationAttachedNamespace(
      this.db,
      caller,
      input.namespace,
    );

    // Duplicate check up-front for a clean 400 (the UNIQUE index is the
    // authoritative guard against a race — catch it below).
    const existing = await this.db.query(
      `SELECT id FROM users WHERE email = $1`,
      [email],
    );
    if (existing.rows.length > 0) {
      throw new UserBadRequestError(`create: email '${email}' already exists`);
    }

    const id = ulid();
    const createdAt = new Date().toISOString();
    const passwordHash =
      input.password !== undefined && input.password.length > 0
        ? hashPassword(input.password)
        : null;

    try {
      await this.db.query(
        `INSERT INTO users
           (id, email, display_name, namespace, role, password_hash, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7)`,
        [id, email, displayName, namespace, input.role, passwordHash, createdAt],
      );
    } catch (err) {
      // Unique-violation race → clean 400 (never leak the raw hash/plaintext).
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) {
        throw new UserBadRequestError(`create: email '${email}' already exists`);
      }
      throw err;
    }

    return {
      id,
      email,
      displayName,
      avatar: null,
      namespace,
      role: input.role,
      status: "active",
      createdAt,
    };
  }

  /** Look up a user by email (case-insensitive). Null if none. */
  async byEmail(email: string): Promise<User | null> {
    const normalized = email.trim().toLowerCase();
    const res = await this.db.query(
      `SELECT id, email, display_name, avatar, namespace, role, status, created_at
       FROM users WHERE email = $1`,
      [normalized],
    );
    const row = res.rows[0] as UserRow | undefined;
    return row ? rowToUser(row) : null;
  }

  /**
   * Internal: full row including the password hash, by email. Used by `login`
   * only — never leaves this module.
   */
  async byEmailWithHash(email: string): Promise<UserRowWithHash | null> {
    const normalized = email.trim().toLowerCase();
    const res = await this.db.query(
      `SELECT id, email, display_name, avatar, namespace, role, status, created_at, password_hash
       FROM users WHERE email = $1`,
      [normalized],
    );
    return (res.rows[0] as UserRowWithHash | undefined) ?? null;
  }

  /**
   * Whether the user can sign in with a password at all. The Profile screen
   * needs this to present email+password as one of the connected sign-in
   * methods (SSO/OAuth-provisioned rows carry `password_hash = NULL`) and so
   * the last remaining method can never be disconnected. The hash itself never
   * leaves this module.
   */
  async hasPassword(id: string): Promise<boolean> {
    const res = await this.db.query(
      `SELECT password_hash IS NOT NULL AS has_password FROM users WHERE id = $1`,
      [id],
    );
    const row = res.rows[0] as { has_password: boolean } | undefined;
    return row?.has_password === true;
  }

  /** Look up a user by id. Null if none. */
  async byId(id: string): Promise<User | null> {
    const res = await this.db.query(
      `SELECT id, email, display_name, avatar, namespace, role, status, created_at
       FROM users WHERE id = $1`,
      [id],
    );
    const row = res.rows[0] as UserRow | undefined;
    return row ? rowToUser(row) : null;
  }

  /**
   * List users visible to the caller: the caller's own namespace subtree
   * (root owner → everywhere; anyone else, including a tenant owner → their
   * own ancestor-subtree, using the SAME ancestor-prefix ACL as the key path).
   * `_`/`%` in the namespace are escaped so they never act as LIKE wildcards
   * (the sibling-leak hazard the key path also guards against).
   */
  async list(identity: Identity): Promise<User[]> {
    if (isRootOwner(identity)) {
      const res = await this.db.query(
        `SELECT id, email, display_name, avatar, namespace, role, status, created_at
         FROM users ORDER BY created_at`,
      );
      return (res.rows as UserRow[]).map(rowToUser);
    }
    const res = await this.db.query(
      `SELECT id, email, display_name, avatar, namespace, role, status, created_at
       FROM users WHERE namespace = $1 OR namespace LIKE $2 ESCAPE '\\'
       ORDER BY created_at`,
      [identity.namespace, escapeLikePattern(identity.namespace) + "/%"],
    );
    return (res.rows as UserRow[]).map(rowToUser);
  }

  /** Mark a user disabled. Idempotent; returns true if a row was active. */
  async disable(id: string): Promise<boolean> {
    const res = await this.db.query(
      `UPDATE users SET status = 'disabled' WHERE id = $1 AND status = 'active' RETURNING id`,
      [id],
    );
    return res.rows.length > 0;
  }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

export class SessionStore {
  constructor(private readonly db: Db) {}

  /** Durable active-state check for an already-hashed session id (Identity.keyId). */
  async isActiveId(id: string): Promise<boolean> {
    const res = await this.db.query(
      `SELECT 1
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND s.expires_at > $2 AND u.status = 'active'
       LIMIT 1`,
      [id, new Date().toISOString()],
    );
    return res.rows.length > 0;
  }

  /** Re-resolve a human session from its already-hashed server-side id. */
  async resolveActiveIdentity(id: string): Promise<Identity | null> {
    const res = await this.db.query(
      `SELECT s.id, s.expires_at, u.email, u.namespace, u.role, u.status
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = $1`,
      [id],
    );
    const row = res.rows[0] as {
      id: string;
      expires_at: Date | string;
      email: string;
      namespace: string;
      role: HumanRole;
      status: string;
    } | undefined;
    if (!row || row.status !== "active" ||
        new Date(row.expires_at).getTime() <= Date.now()) return null;
    return {
      keyId: row.id,
      namespace: row.namespace,
      actor: row.email,
      role: row.role,
    };
  }

  /**
   * Mint a session for a user. Returns the RAW token (shown once, set as the
   * cookie) plus the Session record. At rest `sessions.id` stores
   * `sha256(token)` — the raw token is never persisted.
   */
  async create(
    user: User,
    ttlSeconds: number = DEFAULT_SESSION_TTL_SECONDS,
  ): Promise<{ token: string; session: Session }> {
    const token = randomBytes(32).toString("hex");
    const id = hashToken(token);
    const now = Date.now();
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ttlSeconds * 1000).toISOString();

    await this.db.query(
      `INSERT INTO sessions (id, user_id, created_at, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [id, user.id, createdAt, expiresAt],
    );

    const session: Session = {
      id,
      userId: user.id,
      namespace: user.namespace,
      actor: user.email,
      role: user.role,
      createdAt,
      expiresAt,
    };
    return { token, session };
  }

  /**
   * Resolve a raw token to a Session. Hashes the token, looks up the row,
   * JOINs `users` for the current role/namespace/email/status, and returns
   * null if: the token is unknown, the session is expired (server-side check),
   * or the user is disabled. Role/namespace/email come from the USER ROW, not
   * from any request — a forged cookie cannot assert a role.
   *
   * Resolving also SLIDES the session (see `resolveWithRenewal`), so ordinary
   * use keeps a human signed in. Every caller gets that for free; only callers
   * that need to refresh the browser cookie care whether a slide happened, and
   * they use `resolveWithRenewal` directly.
   */
  async resolve(token: string): Promise<Session | null> {
    const resolved = await this.resolveWithRenewal(token);
    return resolved === null ? null : resolved.session;
  }

  /**
   * `resolve`, plus whether this call pushed `expires_at` forward.
   *
   * The window is idle-based: each use re-bases expiry at
   * `now + DEFAULT_SESSION_TTL_SECONDS`, clamped to
   * `created_at + SESSION_ABSOLUTE_TTL_SECONDS` so a session can never renew
   * itself indefinitely. The write is throttled by
   * `SESSION_RENEW_AFTER_SECONDS` — this runs on every authenticated request
   * and must not become a per-request `UPDATE`.
   *
   * The expiry check happens BEFORE the slide: an already-expired session is
   * rejected, never revived. A disabled user is rejected before either.
   */
  async resolveWithRenewal(token: string): Promise<ResolvedSession | null> {
    const id = hashToken(token);
    const res = await this.db.query(
      `SELECT s.id, s.user_id, s.created_at, s.expires_at,
              u.email, u.namespace, u.role, u.status
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.id = $1`,
      [id],
    );
    const row = res.rows[0] as SessionJoinRow | undefined;
    if (!row) return null;
    if (row.status !== "active") return null; // disabled user → no session

    const now = Date.now();
    const expiresAtMs = new Date(toIso(row.expires_at)).getTime();
    if (!(expiresAtMs > now)) return null; // expired (server-side)

    const createdAtMs = new Date(toIso(row.created_at)).getTime();
    const ceilingMs = createdAtMs + SESSION_ABSOLUTE_TTL_SECONDS * 1000;
    const targetMs = Math.min(now + DEFAULT_SESSION_TTL_SECONDS * 1000, ceilingMs);

    let expiresAt = toIso(row.expires_at);
    let renewed = false;
    if (targetMs - expiresAtMs >= SESSION_RENEW_AFTER_SECONDS * 1000) {
      expiresAt = new Date(targetMs).toISOString();
      await this.db.query(`UPDATE sessions SET expires_at = $2 WHERE id = $1`, [
        id,
        expiresAt,
      ]);
      renewed = true;
    }

    return {
      session: {
        id: row.id,
        userId: row.user_id,
        namespace: row.namespace,
        actor: row.email,
        role: row.role as HumanRole,
        createdAt: toIso(row.created_at),
        expiresAt,
      },
      renewed,
    };
  }

  /** Delete a session by its raw token (logout). Returns true if one existed. */
  async destroy(token: string): Promise<boolean> {
    const id = hashToken(token);
    const res = await this.db.query(
      `DELETE FROM sessions WHERE id = $1 RETURNING id`,
      [id],
    );
    return res.rows.length > 0;
  }

  /** Bulk-delete every expired session. Returns the number removed. */
  async sweepExpired(): Promise<number> {
    const res = await this.db.query(
      `DELETE FROM sessions WHERE expires_at <= $1 RETURNING id`,
      [new Date().toISOString()],
    );
    return res.rows.length;
  }
}

// ---------------------------------------------------------------------------
// Free functions — the seam the kernel/transport reuse
// ---------------------------------------------------------------------------

export interface BootstrapInput {
  token: string;
  email: string;
  displayName?: string;
  password: string;
  /** Display name of the organization the first human will own. */
  organization: string;
}

export interface BootstrapResult {
  token: string;
  user: User;
  /** The organization created alongside the first human. */
  organization: Tenant;
}

export interface BootstrapServiceOptions {
  now?: () => Date;
  tenantUlid?: () => string;
  audit?: AuditLog;
}

/**
 * Atomic, permanently single-use creation of the first human AND the
 * organization they own.
 *
 * The organization is not optional. An earlier version created the first user
 * at namespace `""` and no organization at all, which produced an operator who
 * belonged to no org and an org that had no owner — two halves of an install
 * that never met. Every question of the form "what is YOUR organization?" then
 * had no answer for that account, and the setup gate answered it by scanning
 * every tenant on the deployment (see SG8 in CONTRACTS-SETUP-GATE.md).
 *
 * This path now matches `OrganizationSignupService.complete` exactly: one
 * transaction creating tenant + first owner + session + audit evidence. The
 * platform root (`""`) remains reachable only by direct DB/CLI provisioning —
 * an operator capability, never something a product path hands out.
 */
export class BootstrapService {
  private readonly now: () => Date;
  private readonly tenantUlid: () => string;
  private readonly audit: AuditLog;

  constructor(
    private readonly db: Db,
    private readonly configuredToken: string,
    options: BootstrapServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.tenantUlid = options.tenantUlid ?? ulid;
    this.audit = options.audit ?? new AuditLog(db);
  }

  async activate(input: BootstrapInput): Promise<BootstrapResult | null> {
    // Validate public input before inspecting the secret so malformed requests
    // behave identically for correct and incorrect bootstrap credentials.
    const email = normalizedEmail(input.email);
    let displayName: string;
    try {
      displayName = input.displayName === undefined
        ? humanNameFromAccountKey(email)
        : normalizedHumanDisplayName(input.displayName);
    } catch (error) {
      if (error instanceof HumanDisplayNameError) {
        throw new UserBadRequestError(error.message);
      }
      throw error;
    }
    assertCredentialPassword(input.password);
    // The organization name is validated with the PUBLIC input, before the
    // secret is inspected, so a malformed name cannot be used to probe whether
    // the bootstrap token was correct.
    const organizationName = normalizedOrganizationName(input.organization);
    if (Buffer.byteLength(this.configuredToken, "utf8") < MIN_BOOTSTRAP_TOKEN_BYTES) {
      return null;
    }
    if (!equalTokenHashes(hashToken(input.token), hashToken(this.configuredToken))) {
      return null;
    }
    const passwordHash = hashPassword(input.password);
    const tenantId = deriveTenantId(organizationName, this.tenantUlid);
    const userId = ulid();
    const sessionToken = randomBytes(32).toString("hex");
    const sessionId = hashToken(sessionToken);
    const now = this.now();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + DEFAULT_SESSION_TTL_SECONDS * 1000).toISOString();
    const expectedHash = hashToken(this.configuredToken);

    return this.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO auth_bootstrap (singleton, token_hash, created_at, consumed_at)
         VALUES (TRUE, $1, $2, NULL) ON CONFLICT (singleton) DO NOTHING`,
        [expectedHash, createdAt],
      );
      const state = await tx.query(
        `SELECT token_hash, consumed_at FROM auth_bootstrap
         WHERE singleton = TRUE FOR UPDATE`,
      );
      const row = state.rows[0] as
        | { token_hash: string; consumed_at: Date | string | null }
        | undefined;
      if (!row || row.consumed_at !== null || !equalTokenHashes(row.token_hash, expectedHash)) {
        return null;
      }
      const count = await tx.query(`SELECT COUNT(*) AS n FROM users`);
      if (Number(count.rows[0].n) !== 0) return null;

      // Organization first, then its owner INSIDE it — the same order and the
      // same transaction the self-service signup path uses.
      await tx.query(
        `INSERT INTO tenants
           (id, name, status, monthly_budget_usd, rate_limit_per_min, created_at)
         VALUES ($1, $2, 'active', NULL, NULL, $3)`,
        [tenantId, organizationName, createdAt],
      );
      await tx.query(
        `INSERT INTO users
           (id, email, display_name, namespace, role, password_hash, status, created_at)
         VALUES ($1, $2, $3, $4, 'owner', $5, 'active', $6)`,
        [userId, email, displayName, tenantId, passwordHash, createdAt],
      );
      await tx.query(
        `INSERT INTO sessions (id, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [sessionId, userId, createdAt, expiresAt],
      );
      const consumed = await tx.query(
        `UPDATE auth_bootstrap SET consumed_at = $1
         WHERE singleton = TRUE AND consumed_at IS NULL RETURNING singleton`,
        [createdAt],
      );
      if (consumed.rows.length !== 1) throw new Error("bootstrap consumption conflict");
      // D4: the install leaves evidence, in the same transaction as the rows it
      // is evidence for.
      await this.audit.appendTo(tx, {
        ts: createdAt,
        actor: email,
        agentId: "console",
        op: "write",
        memoryId: null,
        namespace: tenantId,
        purpose: "console-bootstrap",
        result: "ok",
        detail: "organization and first owner created at install",
      });
      return {
        token: sessionToken,
        user: {
          id: userId,
          email,
          displayName,
          namespace: tenantId,
          role: "owner",
          status: "active",
          createdAt,
        },
        organization: {
          id: tenantId,
          name: organizationName,
          status: "active",
          monthlyBudgetUsd: null,
          rateLimitPerMin: null,
          onboardingCompletedAt: null,
          createdAt,
        },
      };
    });
  }
}

export interface CreateInvitationInput {
  email: string;
  displayName?: string;
  namespace: string;
  role: HumanRole;
  ttlSeconds?: number;
}

export interface PendingInvitation {
  id: string;
  email: string;
  displayName: string;
  namespace: string;
  role: HumanRole;
  status: "pending";
  createdAt: string;
  expiresAt: string;
}

export interface IssuedInvitation {
  invite: PendingInvitation;
  /** Raw random credential returned exactly once; never stored or logged. */
  activationToken: string;
}

export type InvitationRotationKind = "reminder" | "reinvite";

export class InvitationStore {
  /**
   * M10 (integrator-wired): when set, invitation acceptance creates the
   * matching membership `access_grants` row INSIDE the acceptance
   * transaction (one permission system — the roster row and the grant
   * commit or roll back together). Structural: `AccessGrantStore` satisfies.
   */
  membershipGrants: {
    syncMembershipGrant(
      tx: Db,
      input: {
        tenantId: string;
        userId: string;
        teamOrFunctionId: string;
        action: "add" | "remove";
        actor: string;
      },
    ): Promise<void>;
  } | null = null;

  constructor(
    private readonly db: Db,
    private readonly now: () => Date = () => new Date(),
    private readonly audit: AuditLog = new AuditLog(db),
  ) {}

  async create(input: CreateInvitationInput, caller: Identity): Promise<IssuedInvitation> {
    const email = normalizedEmail(input.email);
    let displayName: string;
    try {
      displayName = input.displayName === undefined
        ? humanNameFromAccountKey(email)
        : normalizedHumanDisplayName(input.displayName);
    } catch (error) {
      if (error instanceof HumanDisplayNameError) {
        throw new UserBadRequestError(error.message);
      }
      throw error;
    }
    if (!isHumanRole(input.role)) {
      throw new UserBadRequestError(`invalid human role '${input.role}'`);
    }
    if (
      (caller.role !== "owner" && caller.role !== "admin") ||
      (caller.role === "admin" && input.role === "owner") ||
      (!isRootOwner(caller) && !isSelfOrDescendant(input.namespace, caller.namespace))
    ) {
      throw new UserAuthzError("invitation is outside the caller's role or namespace scope");
    }
    const ttlSeconds = input.ttlSeconds ?? DEFAULT_INVITE_TTL_SECONDS;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 30 * 24 * 3600) {
      throw new UserBadRequestError("invitation expiry must be between 60 seconds and 30 days");
    }
    const namespace = await organizationAttachedNamespace(
      this.db,
      caller,
      input.namespace,
    );
    const id = ulid();
    const activationToken = randomBytes(32).toString("hex");
    const createdAt = this.now();
    const expiresAt = new Date(createdAt.getTime() + ttlSeconds * 1000);
    try {
      await this.db.transaction(async (tx) => {
        // A waiting OR expired row is still live authority. It must be
        // explicitly rotated or revoked from Teams so duplicate invites never
        // invalidate a credential without a visible confirmation step.
        await tx.query(
          `INSERT INTO auth_invitations
             (id, email, display_name, namespace, role, token_hash, created_by, created_at,
              expires_at, accepted_at, revoked_at, last_reminded_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL, NULL, $8)`,
        [
          id,
          email,
          displayName,
          namespace,
          input.role,
          hashToken(activationToken),
          caller.actor,
          createdAt.toISOString(),
          expiresAt.toISOString(),
        ],
        );
        const users = await tx.query(`SELECT id FROM users WHERE email = $1`, [email]);
        if (users.rows.length > 0) {
          throw new UserBadRequestError("a user with this email already exists");
        }
        await this.audit.appendTo(tx, {
        ts: createdAt.toISOString(),
        actor: caller.actor,
        agentId: "console",
        op: "write",
        memoryId: null,
        namespace,
        purpose: "console-invitation-create",
        result: "ok",
        detail: `invitation issued for '${email}' with role '${input.role}'`,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/unique|duplicate/i.test(message)) {
        throw new UserBadRequestError(
          "a waiting or expired invitation already exists for this email",
        );
      }
      throw error;
    }
    return {
      activationToken,
      invite: {
        id,
        email,
        displayName,
        namespace,
        role: input.role,
        status: "pending",
        createdAt: createdAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      },
    };
  }

  async rotate(
    input: {
      invitationId: string;
      namespace: string;
      kind: InvitationRotationKind;
      ttlSeconds?: number;
    },
    caller: Identity,
  ): Promise<IssuedInvitation> {
    if (
      (caller.role !== "owner" && caller.role !== "admin") ||
      (!isRootOwner(caller) && !isSelfOrDescendant(input.namespace, caller.namespace))
    ) {
      throw new UserAuthzError("invitation is outside the caller's role or namespace scope");
    }
    const ttlSeconds = input.ttlSeconds ?? DEFAULT_INVITE_TTL_SECONDS;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 30 * 24 * 3600) {
      throw new UserBadRequestError("invitation expiry must be between 60 seconds and 30 days");
    }
    const activationToken = randomBytes(32).toString("hex");
    const now = this.now();
    const nowIso = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `SELECT id, email, display_name, namespace, role, created_at, expires_at,
                accepted_at, revoked_at, last_reminded_at
           FROM auth_invitations
          WHERE id = $1 AND namespace = $2
          FOR UPDATE`,
        [input.invitationId, input.namespace],
      );
      const row = result.rows[0] as {
        id: string;
        email: string;
        display_name: string;
        namespace: string;
        role: HumanRole;
        created_at: Date | string;
        expires_at: Date | string;
        accepted_at: Date | string | null;
        revoked_at: Date | string | null;
        last_reminded_at: Date | string | null;
      } | undefined;
      if (!row || row.accepted_at !== null || row.revoked_at !== null) {
        throw new UserBadRequestError("invitation is no longer active");
      }
      const expired = new Date(row.expires_at).getTime() <= now.getTime();
      if (input.kind === "reminder" && expired) {
        throw new UserBadRequestError("expired invitations must be re-invited");
      }
      if (input.kind === "reinvite" && !expired) {
        throw new UserBadRequestError("only expired invitations can be re-invited");
      }
      if (
        input.kind === "reminder" &&
        row.last_reminded_at !== null &&
        now.getTime() - new Date(row.last_reminded_at).getTime() < 60 * 60 * 1000
      ) {
        throw new UserBadRequestError("a reminder can be sent once per hour");
      }
      await tx.query(
        `UPDATE auth_invitations
            SET token_hash = $1,
                expires_at = $2,
                last_reminded_at = CASE
                  WHEN $3 = 'reminder' THEN $4::timestamptz
                  ELSE NULL
                END,
                updated_at = $4::timestamptz
          WHERE id = $5`,
        [hashToken(activationToken), expiresAt, input.kind, nowIso, row.id],
      );
      await this.audit.appendTo(tx, {
        ts: nowIso,
        actor: caller.actor,
        agentId: "console",
        op: "write",
        memoryId: null,
        namespace: row.namespace,
        purpose: input.kind === "reminder"
          ? "console-invitation-reminder"
          : "console-invitation-reinvite",
        result: "ok",
        detail: `${input.kind} issued for '${row.email}'`,
      });
      return {
        activationToken,
        invite: {
          id: row.id,
          email: row.email,
          displayName: row.display_name,
          namespace: row.namespace,
          role: row.role,
          status: "pending",
          createdAt: new Date(row.created_at).toISOString(),
          expiresAt,
        },
      };
    });
  }

  async revoke(
    input: { invitationId: string; namespace: string },
    caller: Identity,
  ): Promise<{ revoked: boolean }> {
    if (
      (caller.role !== "owner" && caller.role !== "admin") ||
      (!isRootOwner(caller) && !isSelfOrDescendant(input.namespace, caller.namespace))
    ) {
      throw new UserAuthzError("invitation is outside the caller's role or namespace scope");
    }
    const nowIso = this.now().toISOString();
    return this.db.transaction(async (tx) => {
      const result = await tx.query(
        `UPDATE auth_invitations
            SET revoked_at = $1, updated_at = $1
          WHERE id = $2 AND namespace = $3
            AND accepted_at IS NULL AND revoked_at IS NULL
        RETURNING email`,
        [nowIso, input.invitationId, input.namespace],
      );
      if (result.rows.length === 0) {
        throw new UserBadRequestError("invitation is no longer active");
      }
      const email = (result.rows[0] as { email: string }).email;
      await this.audit.appendTo(tx, {
        ts: nowIso,
        actor: caller.actor,
        agentId: "console",
        op: "write",
        memoryId: null,
        namespace: input.namespace,
        purpose: "console-invitation-revoke",
        result: "ok",
        detail: `invitation revoked for '${email}'`,
      });
      return { revoked: true };
    });
  }

  async accept(input: { token: string; password: string }): Promise<User | null> {
    assertCredentialPassword(input.password);
    const passwordHash = hashPassword(input.password);
    const tokenHash = hashToken(input.token);
    const acceptedAt = this.now().toISOString();

    try {
      return await this.db.transaction(async (tx) => {
        const result = await tx.query(
          `SELECT id, email, display_name, namespace, role, created_by, expires_at, accepted_at
           FROM auth_invitations
          WHERE token_hash = $1 AND revoked_at IS NULL
          FOR UPDATE`,
          [tokenHash],
        );
        const row = result.rows[0] as
          | {
              id: string;
              email: string;
              display_name: string;
              namespace: string;
              role: HumanRole;
              created_by: string;
              expires_at: Date | string;
              accepted_at: Date | string | null;
            }
          | undefined;
        if (
          !row ||
          row.accepted_at !== null ||
          new Date(row.expires_at).getTime() <= this.now().getTime()
        ) {
          return null;
        }
        const existing = await tx.query(`SELECT id FROM users WHERE email = $1`, [row.email]);
        if (existing.rows.length > 0) return null;

        const id = ulid();
        await tx.query(
          `INSERT INTO users
             (id, email, display_name, namespace, role, password_hash, status, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'active', $7)`,
          [id, row.email, row.display_name, row.namespace, row.role, passwordHash, acceptedAt],
        );
        await this.attachTeamMembership(tx, id, row.namespace, row.created_by, acceptedAt);
        const consumed = await tx.query(
          `UPDATE auth_invitations SET accepted_at = $1, updated_at = $1
           WHERE id = $2 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING id`,
          [acceptedAt, row.id],
        );
        if (consumed.rows.length !== 1) throw new Error("invitation consumption conflict");
        await this.audit.appendTo(tx, {
          ts: acceptedAt,
          actor: row.email,
          agentId: "console",
          op: "write",
          memoryId: null,
          namespace: row.namespace,
          purpose: "console-invitation-accept",
          result: "ok",
          detail: "invitation accepted",
        });
        return {
          id,
          email: row.email,
          displayName: row.display_name,
          namespace: row.namespace,
          role: row.role,
          status: "active",
          createdAt: acceptedAt,
        };
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) return null;
      throw err;
    }
  }

  /**
   * Consume a pending invitation for an EXTERNALLY AUTHENTICATED email (SSO).
   * The identity provider has already proven control of the address, so no
   * password is set — the user row is created with `password_hash = NULL`
   * (`login` rejects such rows, keeping the account SSO-only). Same
   * single-use/expiry semantics as `accept`, keyed by the invitation's email
   * instead of the activation token. Null when no live invitation exists.
   */
  async acceptSso(email: string): Promise<User | null> {
    const normalized = email.trim().toLowerCase();
    if (normalized.length === 0 || normalized.length > 320 || !normalized.includes("@")) {
      return null;
    }
    const acceptedAt = this.now().toISOString();

    try {
      return await this.db.transaction(async (tx) => {
        const result = await tx.query(
          `SELECT id, email, display_name, namespace, role, created_by, expires_at, accepted_at
           FROM auth_invitations
          WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL
          ORDER BY updated_at DESC LIMIT 1
          FOR UPDATE`,
          [normalized],
        );
        const row = result.rows[0] as
          | {
              id: string;
              email: string;
              display_name: string;
              namespace: string;
              role: HumanRole;
              created_by: string;
              expires_at: Date | string;
              accepted_at: Date | string | null;
            }
          | undefined;
        if (
          !row ||
          row.accepted_at !== null ||
          new Date(row.expires_at).getTime() <= this.now().getTime()
        ) {
          return null;
        }
        const existing = await tx.query(`SELECT id FROM users WHERE email = $1`, [row.email]);
        if (existing.rows.length > 0) return null;

        const id = ulid();
        await tx.query(
          `INSERT INTO users
             (id, email, display_name, namespace, role, password_hash, status, created_at)
           VALUES ($1, $2, $3, $4, $5, NULL, 'active', $6)`,
          [id, row.email, row.display_name, row.namespace, row.role, acceptedAt],
        );
        await this.attachTeamMembership(tx, id, row.namespace, row.created_by, acceptedAt);
        const consumed = await tx.query(
          `UPDATE auth_invitations SET accepted_at = $1, updated_at = $1
           WHERE id = $2 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING id`,
          [acceptedAt, row.id],
        );
        if (consumed.rows.length !== 1) throw new Error("invitation consumption conflict");
        await this.audit.appendTo(tx, {
          ts: acceptedAt,
          actor: row.email,
          agentId: "console",
          op: "write",
          memoryId: null,
          namespace: row.namespace,
          purpose: "console-invitation-accept-sso",
          result: "ok",
          detail: "SSO invitation accepted",
        });
        return {
          id,
          email: row.email,
          displayName: row.display_name,
          namespace: row.namespace,
          role: row.role,
          status: "active",
          createdAt: acceptedAt,
        };
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) return null;
      throw err;
    }
  }

  /** Team invitations become human membership inside the acceptance tx. */
  private async attachTeamMembership(
    tx: Db,
    userId: string,
    namespace: string,
    addedBy: string,
    addedAt: string,
  ): Promise<void> {
    const team = await tx.query(`SELECT id FROM org_teams WHERE namespace = $1`, [namespace]);
    const teamId = team.rows[0]?.id as string | undefined;
    if (teamId === undefined) return;
    await tx.query(
      `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
       VALUES ($1, $2, $3, $4)`,
      [teamId, userId, addedBy, addedAt],
    );
    // M10: the membership consume grant joins the SAME acceptance tx (D9:
    // the namespace root is re-resolved from org_teams inside the store).
    if (this.membershipGrants) {
      const idx = namespace.indexOf("/");
      await this.membershipGrants.syncMembershipGrant(tx, {
        tenantId: idx === -1 ? namespace : namespace.slice(0, idx),
        userId,
        teamOrFunctionId: teamId,
        action: "add",
        actor: addedBy,
      });
    }
  }
}

export interface AuthStores {
  users: UserStore;
  sessions: SessionStore;
}

/** Build the Identity a resolved session grants (session id = keyId). */
function sessionToIdentity(session: Session): Identity {
  return {
    keyId: session.id,
    namespace: session.namespace,
    actor: session.actor,
    role: session.role,
    // M10: the projection subject for read-scope resolution (server-minted).
    sessionUserId: session.userId,
  };
}

/**
 * Sign a human in with email + password. Returns `{ token, identity }` on
 * success, or `null` on ANY failure — an unknown email and a wrong password
 * are INDISTINGUISHABLE to the caller (no oracle) and cost the same scrypt
 * work (a decoy hash is verified when the email is unknown). A disabled user
 * cannot log in. Role/namespace come from the USER ROW, never the request.
 * NEVER logs the password or the minted token.
 */
export async function login(
  stores: AuthStores,
  email: string,
  password: string,
): Promise<{ token: string; identity: Identity } | null> {
  const row = await stores.users.byEmailWithHash(email);
  // Always run scrypt against SOMETHING so timing does not reveal whether the
  // email exists (decoy hash for the unknown-email path).
  const storedHash = row?.password_hash ?? DECOY_STORED_HASH;
  const passwordOk = verifyPassword(storedHash, password);

  if (row === null) return null; // unknown email (after equal-cost work)
  if (row.status !== "active") return null; // disabled user cannot log in
  if (row.password_hash === null) return null; // no password set (e.g. SSO-only)
  if (!passwordOk) return null; // wrong password

  const user: User = {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    namespace: row.namespace,
    role: row.role as HumanRole,
    status: "active",
    createdAt: toIso(row.created_at),
  };
  const { token, session } = await stores.sessions.create(user);
  return { token, identity: sessionToIdentity(session) };
}

/**
 * Resolve a raw session token to the D9 Identity shape the syscalls require:
 * `{ keyId: session.id, namespace, actor: email, role }`. Null for an
 * unknown/expired token or a disabled user.
 */
export async function resolveSessionIdentity(
  stores: AuthStores,
  token: string,
): Promise<Identity | null> {
  const session = await stores.sessions.resolve(token);
  return session ? sessionToIdentity(session) : null;
}

/** Invalidate a session token. Returns true if one existed. */
export async function logout(stores: AuthStores, token: string): Promise<boolean> {
  return stores.sessions.destroy(token);
}
