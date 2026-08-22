/**
 * GitHub OAuth for the control room — browser "Sign in with GitHub" plus
 * Profile account linking (migration v42 `user_external_identities`).
 *
 * Division of labour, mirroring the Supabase SSO module (and D9):
 *
 *  - AUTHENTICATION is delegated to GitHub (the authorization-code exchange
 *    proves control of the GitHub account; the profile is read SERVER-SIDE
 *    from api.github.com, never trusted from the browser).
 *  - AUTHORIZATION stays in the kernel: the `user_external_identities` link
 *    table is the ONLY thing that joins a GitHub identity to a `users` row.
 *    Email match alone NEVER merges accounts — an unlinked GitHub login gets
 *    its own account, and only an explicit "Connect GitHub" from the signed-in
 *    Profile screen links the two.
 *
 * Login resolution order (deliberately no email-match merge):
 *  1. Linked identity → that user (disabled → no_account).
 *  2. Verified GitHub email matches a live pending invitation → the invitation
 *     is consumed into a passwordless user (same as SSO) and linked.
 *  3. Otherwise auto-provision a fresh passwordless user in their OWN
 *     namespace (`gh/<github-id>` — the numeric id is never reused, so a
 *     renamed/recycled login can never inherit another account's data). If
 *     the verified email is already taken by an existing user row, the account
 *     is provisioned under the GitHub noreply alias instead — `users.email`
 *     is UNIQUE and unlinked accounts must stay separate.
 *
 * Config comes from `HALOMEM_GITHUB_CLIENT_ID` + `HALOMEM_GITHUB_CLIENT_SECRET`.
 * Absent → the service is null, the routes 404, and the login page hides the
 * button — self-hosted deployments keep working with zero GitHub config.
 */

import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import type { User } from "../types.js";
import type { AuthStores, InvitationStore } from "./auth.js";
import { ExternalIdentityStore, IdentityConflictError } from "./identities.js";
import type { ExternalIdentity } from "./identities.js";
import { normalizedHumanDisplayName } from "./person-name.js";
import { organizationSignupAllowed } from "./signup.js";

// The link table is shared with the Google (Supabase SSO) provider — see
// `identities.ts`. Re-exported here so existing importers keep working.
export {
  ExternalIdentityStore,
  IdentityConflictError,
} from "./identities.js";
export type {
  ExternalIdentity,
  ExternalIdentityProfile,
  ExternalProvider,
} from "./identities.js";

export interface GitHubProfile {
  /** GitHub numeric account id as a string — stable across renames. */
  id: string;
  login: string;
  /** Provider profile name; trusted provisioning falls back to the login. */
  displayName?: string;
  /** Primary + verified email, or null when the account has none. */
  email: string | null;
}

// ---------------------------------------------------------------------------
// GitHub OAuth service
// ---------------------------------------------------------------------------

export type GitHubLoginResult =
  /** Authenticated and authorized: kernel session minted. */
  | { status: "ok"; token: string; user: User }
  /** GitHub authenticated the account, but the linked user is disabled/gone. */
  | { status: "no_account" }
  /** Code exchange failed, profile unreadable, or GitHub unreachable. */
  | { status: "unauthenticated" };

export interface GitHubOAuthOptions {
  clientId: string;
  clientSecret: string;
  /** The one database (D5) — used for the auto-provision INSERT. */
  db: Db;
  stores: AuthStores;
  invitations: InvitationStore;
  identities: ExternalIdentityStore;
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Early access keeps authenticated-but-uninvited identities out. */
  allowOrganizationSignup?: boolean;
}

interface GitHubTokenResponse {
  access_token?: unknown;
  error?: unknown;
}

interface GitHubUserResponse {
  id?: unknown;
  login?: unknown;
  name?: unknown;
}

interface GitHubEmailEntry {
  email?: unknown;
  primary?: unknown;
  verified?: unknown;
}

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API_ORIGIN = "https://api.github.com";
/** Brownout ceiling for every outbound GitHub call. */
const GITHUB_TIMEOUT_MS = 10_000;
const OAUTH_SCOPE = "read:user user:email";

export class GitHubOAuthService {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly db: Db;
  private readonly stores: AuthStores;
  private readonly invitations: InvitationStore;
  private readonly identities: ExternalIdentityStore;
  private readonly fetchFn: typeof fetch;
  private readonly allowOrganizationSignup: boolean;

  constructor(options: GitHubOAuthOptions) {
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.db = options.db;
    this.stores = options.stores;
    this.invitations = options.invitations;
    this.identities = options.identities;
    this.fetchFn = options.fetchFn ?? fetch;
    this.allowOrganizationSignup = options.allowOrganizationSignup ?? true;
  }

  /** The GitHub authorization redirect target for one state nonce. */
  authorizeUrl(state: string, redirectUri: string): string {
    const url = new URL(GITHUB_AUTHORIZE_URL);
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", OAUTH_SCOPE);
    url.searchParams.set("state", state);
    return url.toString();
  }

  /**
   * Exchange an authorization code for an access token. Any failure (network,
   * non-200, GitHub error payload, malformed body) collapses to null — the
   * caller sees `unauthenticated`; brownout, never hard-fail.
   */
  async exchangeCode(code: string, redirectUri: string): Promise<string | null> {
    if (typeof code !== "string" || code.length === 0 || code.length > 1024) {
      return null;
    }
    let res: Response;
    try {
      res = await this.fetchFn(GITHUB_TOKEN_URL, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "user-agent": "halomem-kernel",
        },
        body: JSON.stringify({
          client_id: this.clientId,
          client_secret: this.clientSecret,
          code,
          redirect_uri: redirectUri,
        }),
        signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
      });
    } catch {
      return null;
    }
    if (res.status !== 200) return null;
    let body: GitHubTokenResponse;
    try {
      body = (await res.json()) as GitHubTokenResponse;
    } catch {
      return null;
    }
    const token = body.access_token;
    if (typeof token !== "string" || token.length === 0 || token.length > 512) {
      return null;
    }
    return token;
  }

  /**
   * Read the authenticated profile SERVER-SIDE from api.github.com. Returns
   * the stable numeric id, the login (display only), and the primary VERIFIED
   * email (null when none). Unverified emails are never used — a user could
   * otherwise attach any address to their GitHub account and steer the
   * invitation path.
   */
  async fetchProfile(accessToken: string): Promise<GitHubProfile | null> {
    const headers = {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${accessToken}`,
      "user-agent": "halomem-kernel",
    };
    let userRes: Response;
    try {
      userRes = await this.fetchFn(`${GITHUB_API_ORIGIN}/user`, {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
      });
    } catch {
      return null;
    }
    if (userRes.status !== 200) return null;
    let userBody: GitHubUserResponse;
    try {
      userBody = (await userRes.json()) as GitHubUserResponse;
    } catch {
      return null;
    }
    const id =
      typeof userBody.id === "number" && Number.isSafeInteger(userBody.id)
        ? String(userBody.id)
        : null;
    const login =
      typeof userBody.login === "string" && userBody.login.length > 0 &&
      userBody.login.length <= 100
        ? userBody.login
        : null;
    if (id === null || login === null) return null;

    let email: string | null = null;
    try {
      const emailsRes = await this.fetchFn(`${GITHUB_API_ORIGIN}/user/emails`, {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
      });
      if (emailsRes.status === 200) {
        const entries = (await emailsRes.json()) as GitHubEmailEntry[];
        if (Array.isArray(entries)) {
          const primary = entries.find(
            (entry) =>
              entry.primary === true &&
              entry.verified === true &&
              typeof entry.email === "string",
          );
          if (primary && typeof primary.email === "string") {
            const normalized = primary.email.trim().toLowerCase();
            if (normalized.length > 0 && normalized.length <= 320 && normalized.includes("@")) {
              email = normalized;
            }
          }
        }
      }
    } catch {
      email = null; // email read is best-effort; the noreply alias covers it
    }
    const displayName = normalizedHumanDisplayName(
      typeof userBody.name === "string" && userBody.name.trim() ? userBody.name : login,
    );
    return { id, login, displayName, email };
  }

  /** The unique-per-account email a provisioned user row is keyed by. */
  private provisionEmail(profile: GitHubProfile): string {
    return (
      profile.email ??
      `${profile.id}+${profile.login.toLowerCase()}@users.noreply.github.com`
    );
  }

  /**
   * Resolve an authenticated GitHub profile to a kernel session, per the
   * module-header order: linked identity → invitation → auto-provision.
   * An existing user with the SAME EMAIL is never merged implicitly.
   */
  async loginWithGitHub(profile: GitHubProfile): Promise<GitHubLoginResult> {
    // 1. Linked identity wins — this is the "connected" path that lands the
    //    user on the same account as their email+password login.
    const linked = await this.identities.findByProviderId("github", profile.id);
    if (linked !== null) {
      const user = await this.stores.users.byId(linked.userId);
      if (user === null || user.status !== "active") {
        return { status: "no_account" };
      }
      const { token } = await this.stores.sessions.create(user);
      return { status: "ok", token, user };
    }

    // 2. A live pending invitation for the verified email is consumed into a
    //    passwordless user (the IdP already proved the address — same as SSO).
    if (profile.email !== null) {
      const invited = await this.invitations.acceptSso(profile.email);
      if (invited !== null) {
        await this.identities.link(invited.id, "github", profile);
        const { token } = await this.stores.sessions.create(invited);
        return { status: "ok", token, user: invited };
      }
    }

    if (!this.allowOrganizationSignup) return { status: "no_account" };

    // 3. Auto-provision a separate account. When the verified email is taken
    //    by an existing (unlinked) user, provision under the noreply alias —
    //    users.email is UNIQUE and the two accounts must stay separate.
    let email = this.provisionEmail(profile);
    const taken = await this.stores.users.byEmail(email);
    if (taken !== null) {
      email = `${profile.id}+${profile.login.toLowerCase()}@users.noreply.github.com`;
      const aliasTaken = await this.stores.users.byEmail(email);
      if (aliasTaken !== null) return { status: "no_account" }; // defensive; unique per id
    }
    const createdAt = new Date().toISOString();
    const userId = ulid();
    const displayName = normalizedHumanDisplayName(profile.displayName ?? profile.login);
    // Direct INSERT (like BootstrapService/InvitationStore): UserStore.create's
    // caller-authz rules are for transport callers, not IdP-driven provisioning.
    await this.insertProvisionedUser(userId, email, profile, createdAt);
    const user: User = {
      id: userId,
      email,
      displayName,
      namespace: `gh/${profile.id}`,
      role: "owner",
      status: "active",
      createdAt,
    };
    await this.identities.link(userId, "github", profile);
    const { token } = await this.stores.sessions.create(user);
    return { status: "ok", token, user };
  }

  /** Insert the auto-provisioned passwordless user row. */
  private async insertProvisionedUser(
    userId: string,
    email: string,
    profile: GitHubProfile,
    createdAt: string,
  ): Promise<void> {
    try {
      await this.db.query(
        `INSERT INTO users
           (id, email, display_name, namespace, role, password_hash, status, created_at)
         VALUES ($1, $2, $3, $4, 'owner', NULL, 'active', $5)`,
        [userId, email, normalizedHumanDisplayName(profile.displayName ?? profile.login), `gh/${profile.id}`, createdAt],
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/unique|duplicate/i.test(message)) {
        throw new IdentityConflictError(
          "an account with this email already exists",
        );
      }
      throw err;
    }
  }

  /** Link a GitHub account to an explicitly signed-in user (Profile screen). */
  async linkForUser(
    userId: string,
    profile: GitHubProfile,
  ): Promise<ExternalIdentity> {
    return this.identities.link(userId, "github", profile);
  }
}

/**
 * Build the GitHub OAuth service from the environment, or null when
 * unconfigured (routes then 404 and the login page hides the button).
 */
export function githubOAuthFromEnv(
  deps: {
    stores: AuthStores;
    invitations: InvitationStore;
    identities: ExternalIdentityStore;
    db: Db;
    fetchFn?: typeof fetch;
  },
  env: Record<string, string | undefined> = process.env,
): GitHubOAuthService | null {
  const clientId = env.HALOMEM_GITHUB_CLIENT_ID;
  const clientSecret = env.HALOMEM_GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return new GitHubOAuthService({
    clientId,
    clientSecret,
    ...deps,
    allowOrganizationSignup: organizationSignupAllowed(env),
  });
}
