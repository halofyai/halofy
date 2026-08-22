/**
 * Organization display-name → tenant id derivation, shared by every path that
 * creates an organization.
 *
 * There are two such paths and they must agree byte-for-byte: self-service
 * signup (`src/console/signup.ts`) and first-install bootstrap
 * (`BootstrapService` in `src/console/auth.ts`). They diverged once — bootstrap
 * created an owner at namespace `""` and no organization at all, while signup
 * created both — and that gap is what put a live deployment's operator outside
 * every organization it owned (see CONTRACTS-SELF-SERVICE-ONBOARDING.md
 * decision 9). Keeping the derivation in one module is what stops the two from
 * drifting again.
 *
 * D9 holds throughout: the browser submits a display NAME, never a namespace.
 * The server derives the id, and the caller cannot influence it beyond the
 * name.
 */

/** Thrown when a submitted organization display name is unusable. */
export class OrganizationNameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OrganizationNameError";
  }
}

/**
 * Collapse whitespace, bound the length, and enforce the platform-wide
 * initial-capital display contract without destroying intentional brand
 * casing later in the name (for example, `OpenAI`).
 */
export function normalizedOrganizationName(value: string): string {
  const name = String(value ?? "").trim().replace(/\s+/g, " ");
  if (name.length < 2 || name.length > 100) {
    throw new OrganizationNameError(
      "organization name must be between 2 and 100 characters",
    );
  }
  const first = Array.from(name)[0]!;
  return first.toUpperCase() + name.slice(first.length);
}

/**
 * A URL/namespace-safe slug. Never empty: a name of only punctuation or
 * non-Latin script collapses to `org`, which the id suffix still makes unique.
 */
export function organizationSlug(name: string): string {
  const slug = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
    .replace(/-+$/g, "");
  return slug || "org";
}

/**
 * The tenant id for a display name: slug + the low 8 of a fresh ULID, so two
 * organizations may share a display name without colliding on the namespace
 * that carries their data.
 */
export function deriveTenantId(name: string, ulidFn: () => string): string {
  return `${organizationSlug(name)}-${ulidFn().slice(-8).toLowerCase()}`;
}
