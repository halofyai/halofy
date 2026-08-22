/**
 * Module A — Microsoft Entra (managed-identity) authentication for Postgres.
 *
 * Replaces the long-lived database password with an access token the platform
 * mints for THIS workload's managed identity. The token expires in minutes to
 * an hour and cannot be replayed by anyone who does not hold the identity, so
 * a leaked connection string stops being a total-compromise event.
 *
 * Deliberately dependency-free: the token comes from the local identity
 * endpoint over plain `fetch`, the same way `@azure/identity` would, without
 * pulling that SDK (and its transitive tree) into the kernel.
 *
 * Two ways the platform exposes the endpoint:
 *  - App Service / Container Apps / Functions: `IDENTITY_ENDPOINT` +
 *    `IDENTITY_HEADER` (the header is the shared secret proving we are the
 *    workload, so it is never logged).
 *  - Plain VMs: the IMDS address with a `Metadata: true` header.
 *
 * Brownout rule: every failure here is reported to the caller so the pool can
 * fall back to password auth while BOTH methods are enabled on the server.
 * The kernel keeps running on a degraded credential rather than hard-failing.
 */

/** OAuth resource for Azure Database for PostgreSQL. Fixed by the service. */
const OSSRDBMS_RESOURCE = "https://ossrdbms-aad.database.windows.net";

/** IMDS fallback when no App-Service-style identity endpoint is injected. */
const IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token";

/**
 * Renew this far before the stated expiry. A connection opened at T must still
 * authenticate at T+skew, and Postgres validates the token at CONNECT time
 * only — so the margin just has to cover the handshake plus clock drift.
 */
const RENEW_SKEW_SEC = 300;

/**
 * Bound the token fetch. A blackholed IMDS address (firewalled dev box,
 * non-Azure host) must brown out to the password fallback in seconds — never
 * hang the pool's password callback, which would hang every new connection.
 */
const DEFAULT_FETCH_TIMEOUT_MS = 3_000;

export interface EntraTokenSource {
  /** Fetch a bearer token for the Postgres resource. Throws on any failure. */
  token(): Promise<string>;
}

export interface EntraTokenOptions {
  /** Client id of the user-assigned identity. Omit to use the system-assigned one. */
  clientId?: string;
  /** Test seam. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Test seam for expiry maths. Defaults to Date.now. */
  now?: () => number;
  env?: NodeJS.ProcessEnv;
  /** Per-request bound on the token fetch. Defaults to 3 s. */
  timeoutMs?: number;
}

interface CachedToken {
  value: string;
  /** Absolute epoch SECONDS at which the token stops being usable. */
  expiresAtSec: number;
}

function tokenRequest(
  env: NodeJS.ProcessEnv,
  clientId: string | undefined,
): { url: string; headers: Record<string, string> } {
  const identityEndpoint = env.IDENTITY_ENDPOINT;
  const identityHeader = env.IDENTITY_HEADER;
  if (identityEndpoint && identityHeader) {
    const url = new URL(identityEndpoint);
    url.searchParams.set("api-version", "2019-08-01");
    url.searchParams.set("resource", OSSRDBMS_RESOURCE);
    if (clientId) url.searchParams.set("client_id", clientId);
    // X-IDENTITY-HEADER is a secret: it authenticates US to the local token
    // service. Never log this object.
    return { url: url.toString(), headers: { "x-identity-header": identityHeader } };
  }
  const url = new URL(IMDS_ENDPOINT);
  url.searchParams.set("api-version", "2018-02-01");
  url.searchParams.set("resource", OSSRDBMS_RESOURCE);
  if (clientId) url.searchParams.set("client_id", clientId);
  return { url: url.toString(), headers: { metadata: "true" } };
}

/**
 * `expires_on` is documented as epoch seconds but ships as a string on some
 * hosts and as an ISO date on others. Anything unparseable degrades to "treat
 * as already expiring", which costs an extra fetch — never a stale token.
 */
function parseExpiry(raw: unknown, nowSec: number): number {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string") {
    const asNumber = Number(raw);
    if (Number.isFinite(asNumber) && asNumber > 0) return asNumber;
    const asDate = Date.parse(raw);
    if (Number.isFinite(asDate)) return Math.floor(asDate / 1000);
  }
  return nowSec;
}

/**
 * A token source that caches until shortly before expiry and collapses
 * concurrent callers onto one in-flight request (a cold pool opens several
 * connections at once; without this they would each mint a token).
 */
export function createEntraTokenSource(options: EntraTokenOptions = {}): EntraTokenSource {
  const env = options.env ?? process.env;
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  let cached: CachedToken | null = null;
  let inFlight: Promise<string> | null = null;

  async function refresh(): Promise<string> {
    const { url, headers } = tokenRequest(env, options.clientId);
    const response = await fetchImpl(url, {
      headers,
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS),
    });
    if (!response.ok) {
      // Body may echo the request; keep the status only.
      throw new Error(`entra token request failed with status ${response.status}`);
    }
    const payload = await response.json() as Record<string, unknown>;
    const token = payload.access_token;
    if (typeof token !== "string" || token.length === 0) {
      throw new Error("entra token response had no access_token");
    }
    const nowSec = Math.floor(now() / 1000);
    cached = { value: token, expiresAtSec: parseExpiry(payload.expires_on, nowSec) };
    return token;
  }

  return {
    async token() {
      const nowSec = Math.floor(now() / 1000);
      if (cached && cached.expiresAtSec - RENEW_SKEW_SEC > nowSec) return cached.value;
      if (inFlight) return inFlight;
      inFlight = refresh().finally(() => { inFlight = null; });
      return inFlight;
    },
  };
}

export interface PostgresDsnParts {
  host: string;
  port: number;
  database: string;
  user: string;
  /** `pg` ssl option derived from the DSN's sslmode. */
  ssl: false | { rejectUnauthorized: boolean };
}

/**
 * Split a Postgres DSN into the discrete fields `pg` needs.
 *
 * Why not just hand `pg` the connection string and override the password?
 * Because `ConnectionParameters` does
 * `Object.assign({}, config, parse(config.connectionString))` — the parsed
 * string WINS, and `pg-connection-string` always emits a `password` key
 * (empty string when the DSN carries none). A `password` callback passed
 * alongside a `connectionString` is therefore silently discarded. Discrete
 * fields are the only way the callback survives.
 */
export function parsePostgresDsn(dsn: string): PostgresDsnParts {
  const url = new URL(dsn);
  const sslmode = url.searchParams.get("sslmode") ?? "";
  // Anything that is not an explicit opt-out verifies the chain. `verify-ca`
  // maps to full verification too: stricter than asked for is safe here,
  // looser never is.
  const ssl: PostgresDsnParts["ssl"] =
    sslmode === "disable" ? false
      : sslmode === "no-verify" ? { rejectUnauthorized: false }
        : { rejectUnauthorized: true };
  return {
    host: decodeURIComponent(url.hostname),
    port: url.port ? Number(url.port) : 5432,
    database: decodeURIComponent(url.pathname.replace(/^\//, "")),
    user: decodeURIComponent(url.username),
    ssl,
  };
}
