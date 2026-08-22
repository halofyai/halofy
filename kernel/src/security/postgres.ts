/** Require server-certificate verification for every non-loopback Postgres DSN. */
export function assertSecurePostgresDsn(dsn: string, label = "Postgres"): void {
  let parsed: URL;
  try {
    parsed = new URL(dsn);
  } catch {
    throw new Error(`${label}: DSN is invalid`);
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error(`${label}: DSN must use postgres:// or postgresql://`);
  }
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "::1" ||
    parsed.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(parsed.hostname);
  if (!loopback && parsed.searchParams.get("sslmode") !== "verify-full") {
    throw new Error(`${label}: remote DSN requires sslmode=verify-full`);
  }
}
