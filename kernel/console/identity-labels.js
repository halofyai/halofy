/**
 * Human identity presentation for the console.
 *
 * Email/actor remains the immutable authentication, audit, filtering, and
 * mutation key. This module only chooses what a human sees on screen.
 */

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

const GENERATED_TENANT_SUFFIX = /-[0-9a-hjkmnp-tv-z]{8}$/i;

function organizationSlug(value) {
  return clean(value)
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
    .replace(/-+$/g, "");
}

/**
 * Human-facing scope label for a server-authoritative namespace.
 *
 * Tenant ids intentionally end in eight random ULID characters. Keep that id
 * for API and ACL work, but replace its root with the canonical organization
 * slug anywhere a person is reading the scope.
 */
export function organizationScopeLabel(namespace, organizationName, organizationNamespace) {
  const scope = clean(namespace);
  if (!scope) return "Organization root";

  const authorityRoot = clean(organizationNamespace).split("/")[0] || scope.split("/")[0];
  const canonicalRoot = organizationSlug(organizationName);
  const displayRoot = canonicalRoot || authorityRoot.replace(GENERATED_TENANT_SUFFIX, "");
  if (!displayRoot || scope === authorityRoot) return displayRoot || scope;
  if (scope.startsWith(authorityRoot + "/")) {
    return displayRoot + scope.slice(authorityRoot.length);
  }
  return scope;
}

const AVATAR_PREFIX = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const MAX_AVATAR_CHARS = 256_000;

function personKey(subject) {
  if (typeof subject === "string") return clean(subject);
  if (!subject || typeof subject !== "object") return "";
  return clean(subject.email) || clean(subject.actor) || clean(subject.name);
}

/** Stored name first, directory lookup second, immutable key as fallback. */
export function personDisplayName(subject, resolve, principal) {
  const explicit =
    subject && typeof subject === "object" ? clean(subject.displayName) : "";
  if (explicit) return explicit;
  const key = personKey(subject);
  // An actor string alone does not prove this is a person. Agent actors are
  // user-controlled and may collide with a human email, so directory lookup is
  // allowed only after the caller has server-derived human-principal evidence.
  if (key && principal === "human" && typeof resolve === "function") {
    const resolved = clean(resolve(key, "human"));
    if (resolved) return resolved;
  }
  return key;
}

function safeAvatar(value) {
  const candidate = clean(value);
  return candidate.length > 0 && candidate.length <= MAX_AVATAR_CHARS && AVATAR_PREFIX.test(candidate)
    ? candidate
    : null;
}

function personInitials(value) {
  const parts = clean(value).split(/[\s@._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  return parts.slice(0, 2).map((part) => Array.from(part)[0] || "").join("").toUpperCase() || "?";
}

/** Safe portrait URL for console surfaces that paint their own avatar tile. */
export function personAvatarUrl(subject, options) {
  const principal = options?.principal || "human";
  const explicit = subject && typeof subject === "object" ? safeAvatar(subject.avatar) : null;
  const resolved = !explicit && principal === "human" && typeof options?.avatar === "function"
    ? safeAvatar(options.avatar(subject))
    : null;
  return explicit || resolved;
}

/** Compact, accessible human portrait used by attribution tables. */
export function personAvatarHtml(subject, options) {
  const esc = options && typeof options.esc === "function" ? options.esc : String;
  const principal = options?.principal || "human";
  const label = personDisplayName(subject, options?.label, principal) || "Unknown person";
  const image = personAvatarUrl(subject, options);
  return '<span class="person-avatar" role="img" aria-label="' + esc(label) +
    '" title="' + esc(label) + '"><span class="person-avatar__fallback" aria-hidden="true">' +
    esc(personInitials(label)) + '</span>' + (image
      ? '<img class="person-avatar__image" data-person-avatar-image src="' + esc(image) +
        '" alt="" decoding="async">'
      : "") + "</span>";
}

/** Mutable in-memory directory populated from /auth/me and /people. */
export function createPersonDirectory(initial) {
  const labels = new Map();
  const avatars = new Map();

  function remember(subjects) {
    const list = Array.isArray(subjects) ? subjects : [subjects];
    for (const subject of list) {
      const key = personKey(subject);
      const label =
        subject && typeof subject === "object" ? clean(subject.displayName) : "";
      if (key && label) labels.set(key.toLowerCase(), label);
      else if (
        key &&
        subject &&
        typeof subject === "object" &&
        Object.prototype.hasOwnProperty.call(subject, "displayName")
      ) labels.delete(key.toLowerCase());
      if (
        key &&
        subject &&
        typeof subject === "object" &&
        Object.prototype.hasOwnProperty.call(subject, "avatar")
      ) {
        const avatar = safeAvatar(subject.avatar);
        if (avatar) avatars.set(key.toLowerCase(), avatar);
        else avatars.delete(key.toLowerCase());
      }
    }
  }

  function label(subject) {
    return personDisplayName(
      subject,
      (key) => labels.get(key.toLowerCase()) || key,
      "human",
    );
  }

  function avatar(subject) {
    const key = personKey(subject);
    return key ? avatars.get(key.toLowerCase()) || null : null;
  }

  if (initial !== undefined) remember(initial);
  return { remember, label, avatar };
}
