/**
 * Supabase-backed SSO for the control room — Google OAuth + hosted email auth.
 *
 * The console login page authenticates against the org's Supabase Auth
 * project (Google OAuth or email+password, handled entirely by GoTrue) and
 * then EXCHANGES the resulting Supabase access token for a kernel session
 * here. Division of labour, mirroring D9:
 *
 *  - AUTHENTICATION is delegated to Supabase (it proves control of an email).
 *  - AUTHORIZATION stays in the kernel `users` table: the exchanged email must
 *    match an existing active user, or a live pending invitation (which is
 *    then consumed into a passwordless, SSO-only user row). A Supabase account
 *    alone grants NOTHING — an uninvited email is refused.
 *
 * The access token is verified SERVER-SIDE by calling the issuing project's
 * `GET /auth/v1/user` endpoint — the kernel never trusts a client-asserted
 * email and needs no JWT library or shared secret beyond the public anon key.
 * That same response names the IdP behind the session, so a Google sign-in is
 * recorded in the shared `user_external_identities` table (see
 * `identities.ts`) and shows up as a CONNECTED account on the Profile screen —
 * which can also connect Google explicitly through `linkGoogle`.
 *
 * Config comes from `SUPABASE_URL` + `SUPABASE_ANON_KEY` (or their
 * `NEXT_PUBLIC_`-prefixed twins). Absent → SSO is disabled and the console
 * falls back to native email+password — self-hosted deployments keep working
 * with zero external dependencies.
 */

import type { User } from "../types.js";
import { trimTrailingRepeatedCharacter } from "../strings.js";
import type {
  AuthStores,
  InvitationStore,
} from "./auth.js";
import {
  IdentityConflictError,
  type ExternalIdentity,
  type ExternalIdentityProfile,
  type ExternalIdentityStore,
} from "./identities.js";
import {
  SignupConflictError,
  organizationSignupAllowed,
  type OrganizationSignupService,
} from "./signup.js";

/** What `GET /auth/sso/config` exposes to the (unauthenticated) login page. */
export interface SsoPublicConfig {
  enabled: boolean;
  /** Supabase project URL — public by design (ships in every client bundle). */
  url?: string;
  /** Supabase anon key — public by design (RLS/anon-scoped). */
  anonKey?: string;
  /** True only after production outbound email delivery is configured and verified. */
  emailDeliveryReady: boolean;
}

export type SsoExchangeResult =
  /** Authenticated and authorized: kernel session minted. */
  | { status: "ok"; token: string; user: User }
  /** Authenticated unknown identity: short-lived authority to create an org. */
  | { status: "onboarding_required"; signupToken: string; email: string }
  /** Authenticated by Supabase but blocked (for example, a disabled user). */
  | { status: "no_account"; email: string }
  /** Token invalid/expired/malformed, or the IdP could not be reached. */
  | { status: "unauthenticated" };

export interface SupabaseSsoOptions {
  /** Supabase project URL, e.g. https://xyz.supabase.co (no trailing slash). */
  url: string;
  /** Supabase anon (publishable) key. */
  anonKey: string;
  /** Explicit production-readiness gate for the hosted email/password channel. */
  emailDeliveryReady?: boolean;
  stores: AuthStores;
  invitations: InvitationStore;
  signup: OrganizationSignupService;
  /** False makes unknown identities invitation-only; existing/invited users still work. */
  allowOrganizationSignup?: boolean;
  /**
   * External identity links. Optional: without it the exchange behaves exactly
   * as before (email match only) — the connection is simply not recorded.
   */
  identities?: ExternalIdentityStore;
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch;
}

/** Shape of the GoTrue `GET /auth/v1/user` response we rely on. */
interface GoTrueUser {
  id?: unknown;
  email?: unknown;
  email_confirmed_at?: unknown;
  identities?: unknown;
}

/** One entry of the GoTrue `identities` array (the IdP behind the session). */
interface GoTrueIdentity {
  provider?: unknown;
  id?: unknown;
  identity_data?: unknown;
}

interface GoTrueSettings {
  mailer_autoconfirm?: unknown;
}

interface VerifiedPrincipal {
  email: string;
  /**
   * The Google account behind this token, when the session came from Google
   * OAuth. Null for the hosted email/password channel — there is no external
   * account to connect in that case.
   */
  google: ExternalIdentityProfile | null;
}

export type GoogleLinkResult =
  | { status: "linked"; identity: ExternalIdentity }
  /** The Google account belongs to another user, or one is already connected. */
  | { status: "conflict" }
  /** Token invalid/expired, IdP unreachable, or the session is not Google-backed. */
  | { status: "unauthenticated" };

const MAX_TOKEN_LENGTH = 8192;

export class SupabaseSsoService {
  private readonly url: string;
  private readonly anonKey: string;
  private readonly stores: AuthStores;
  private readonly invitations: InvitationStore;
  private readonly signup: OrganizationSignupService;
  private readonly identities: ExternalIdentityStore | null;
  private readonly fetchFn: typeof fetch;
  private readonly emailDeliveryReady: boolean;
  private readonly allowOrganizationSignup: boolean;

  constructor(options: SupabaseSsoOptions) {
    this.url = trimTrailingRepeatedCharacter(options.url, "/");
    this.anonKey = options.anonKey;
    this.stores = options.stores;
    this.invitations = options.invitations;
    this.signup = options.signup;
    this.identities = options.identities ?? null;
    this.fetchFn = options.fetchFn ?? fetch;
    this.emailDeliveryReady = options.emailDeliveryReady === true;
    this.allowOrganizationSignup = options.allowOrganizationSignup !== false;
  }

  /** Public login-page config. The anon key is publishable — not a secret. */
  publicConfig(): SsoPublicConfig {
    return {
      enabled: true,
      url: this.url,
      anonKey: this.anonKey,
      emailDeliveryReady: this.emailDeliveryReady,
    };
  }

  /** Refuse every exchange if email ownership could be bypassed by auto-confirm. */
  private async projectRequiresEmailConfirmation(): Promise<boolean> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.url}/auth/v1/settings`, {
        method: "GET",
        headers: { apikey: this.anonKey },
      });
    } catch {
      return false;
    }
    if (res.status !== 200) return false;

    let body: GoTrueSettings;
    try {
      body = (await res.json()) as GoTrueSettings;
    } catch {
      return false;
    }
    return body.mailer_autoconfirm === false;
  }

  /**
   * Verify a Supabase access token with the issuing project and return the
   * proven email, or null for anything invalid. Network/IdP failures collapse
   * to null (the caller sees `unauthenticated`) — brownout, never hard-fail.
   */
  private async verifiedPrincipal(accessToken: string): Promise<VerifiedPrincipal | null> {
    if (
      typeof accessToken !== "string" ||
      accessToken.length === 0 ||
      accessToken.length > MAX_TOKEN_LENGTH ||
      !/^[\x21-\x7e]+$/.test(accessToken)
    ) {
      return null; // malformed (also blocks header injection via CR/LF)
    }
    let res: Response;
    try {
      res = await this.fetchFn(`${this.url}/auth/v1/user`, {
        method: "GET",
        headers: {
          apikey: this.anonKey,
          authorization: `Bearer ${accessToken}`,
        },
      });
    } catch {
      return null; // IdP unreachable - refuse, never guess
    }
    if (res.status !== 200) return null;
    let body: GoTrueUser;
    try {
      body = (await res.json()) as GoTrueUser;
    } catch {
      return null;
    }
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (email.length === 0 || email.length > 320 || !email.includes("@")) return null;
    if (typeof body.email_confirmed_at !== "string" || body.email_confirmed_at.length === 0) {
      return null;
    }

    if (!(await this.projectRequiresEmailConfirmation())) return null;
    return { email, google: googleIdentityOf(body, email) };
  }

  /**
   * Exchange a verified Supabase access token for a kernel session.
   *
   * Order: a CONNECTED Google account wins (the Profile screen link, which
   * survives a later Google email change); else the existing ACTIVE user with
   * that email; else a live pending invitation is consumed into a passwordless
   * user (the IdP already proved the email, so no activation password is
   * required); else issue a short-lived, server-held self-service authority for
   * creation of a new isolated organization. A disabled user is `no_account` —
   * SSO can never resurrect a disabled row.
   *
   * Whichever branch resolves the user, the Google account is recorded in the
   * link table so the Profile screen can SHOW the connection. That records a
   * fact the email match already granted — it never widens access, and a
   * conflicting link (the Google account belongs to someone else) is left
   * untouched.
   */
  async exchange(accessToken: string): Promise<SsoExchangeResult> {
    const principal = await this.verifiedPrincipal(accessToken);
    if (principal === null) return { status: "unauthenticated" };
    const { email, google } = principal;

    if (google !== null && this.identities !== null) {
      const linked = await this.identities.findByProviderId("google", google.id);
      if (linked !== null) {
        const linkedUser = await this.stores.users.byId(linked.userId);
        if (linkedUser === null || linkedUser.status !== "active") {
          return { status: "no_account", email };
        }
        const { token } = await this.stores.sessions.create(linkedUser);
        return { status: "ok", token, user: linkedUser };
      }
    }

    let user: User | null = await this.stores.users.byEmail(email);
    if (user !== null && user.status !== "active") {
      return { status: "no_account", email };
    }
    if (user === null) {
      user = await this.invitations.acceptSso(email);
    }
    if (user === null) {
      if (!this.allowOrganizationSignup) return { status: "no_account", email };
      try {
        const issued = await this.signup.issue(email);
        return { status: "onboarding_required", signupToken: issued.token, email };
      } catch (err) {
        // The account may have appeared between the first lookup and issuance.
        // Re-resolve it once; disabled identities still fail closed.
        if (!(err instanceof SignupConflictError)) throw err;
        user = await this.stores.users.byEmail(email);
        if (user === null || user.status !== "active") {
          return { status: "no_account", email };
        }
      }
    }

    await this.recordGoogleLink(user.id, google);
    const { token } = await this.stores.sessions.create(user);
    return { status: "ok", token, user };
  }

  /**
   * Connect a Google account to an ALREADY signed-in kernel user (Profile
   * screen "Connect Google"). Both sides are proven: the kernel session cookie
   * on the request, and this token at the IdP. A token from the hosted
   * email/password channel carries no Google account and is refused.
   */
  async linkGoogle(accessToken: string, userId: string): Promise<GoogleLinkResult> {
    if (this.identities === null) return { status: "unauthenticated" };
    const principal = await this.verifiedPrincipal(accessToken);
    if (principal === null || principal.google === null) {
      return { status: "unauthenticated" };
    }
    try {
      const identity = await this.identities.link(userId, "google", principal.google);
      return { status: "linked", identity };
    } catch (err) {
      if (err instanceof IdentityConflictError) return { status: "conflict" };
      throw err;
    }
  }

  /** Best-effort link recording — a conflict is never allowed to fail a login. */
  private async recordGoogleLink(
    userId: string,
    google: ExternalIdentityProfile | null,
  ): Promise<void> {
    if (google === null || this.identities === null) return;
    try {
      await this.identities.link(userId, "google", google);
    } catch (err) {
      if (err instanceof IdentityConflictError) return;
      throw err;
    }
  }
}

/**
 * Extract the Google account behind a GoTrue user, or null when the session
 * came from another channel (hosted email/password). The stable `sub` claim is
 * the account id — never the email, which the user can change.
 */
function googleIdentityOf(
  body: GoTrueUser,
  fallbackEmail: string,
): ExternalIdentityProfile | null {
  if (!Array.isArray(body.identities)) return null;
  const entry = (body.identities as GoTrueIdentity[]).find(
    (candidate) =>
      candidate !== null &&
      typeof candidate === "object" &&
      candidate.provider === "google",
  );
  if (entry === undefined) return null;
  const data =
    entry.identity_data !== null && typeof entry.identity_data === "object"
      ? (entry.identity_data as Record<string, unknown>)
      : {};
  const sub =
    typeof data.sub === "string" && data.sub.length > 0
      ? data.sub
      : typeof entry.id === "string" && entry.id.length > 0
        ? entry.id
        : null;
  if (sub === null || sub.length > 255) return null;
  const identityEmail =
    typeof data.email === "string" && data.email.includes("@") && data.email.length <= 320
      ? data.email.trim().toLowerCase()
      : fallbackEmail;
  return { id: sub, login: identityEmail, email: identityEmail };
}

/**
 * Build the SSO service from the environment, or null when unconfigured.
 * Accepts both the plain and the NEXT_PUBLIC_-prefixed variable names so the
 * same env file as the Halofy dashboard works verbatim.
 */
export function supabaseSsoFromEnv(
  deps: {
    stores: AuthStores;
    invitations: InvitationStore;
    signup: OrganizationSignupService;
    allowOrganizationSignup?: boolean;
    identities?: ExternalIdentityStore;
    fetchFn?: typeof fetch;
  },
  env: Record<string, string | undefined> = process.env,
): SupabaseSsoService | null {
  const url = env.SUPABASE_URL ?? env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = env.SUPABASE_ANON_KEY ?? env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) return null;
  if (!/^https?:\/\//.test(url)) return null;
  return new SupabaseSsoService({
    url,
    anonKey,
    emailDeliveryReady: env.HALOMEM_SSO_EMAIL_DELIVERY_READY === "true",
    allowOrganizationSignup: deps.allowOrganizationSignup ??
      organizationSignupAllowed(env),
    ...deps,
  });
}
