/** Canonical validation for the human name every user row must carry. */

export const MAX_HUMAN_DISPLAY_NAME = 80;

export class HumanDisplayNameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HumanDisplayNameError";
  }
}

/**
 * Normalize a user-supplied human name without changing its chosen casing.
 * Control characters are flattened so a name cannot forge roster structure.
 */
export function normalizedHumanDisplayName(value: unknown): string {
  if (typeof value !== "string") {
    throw new HumanDisplayNameError("display name must be a string");
  }
  const name = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().replace(/\s+/g, " ");
  if (name.length === 0) {
    throw new HumanDisplayNameError("display name is required");
  }
  if (name.length > MAX_HUMAN_DISPLAY_NAME) {
    throw new HumanDisplayNameError(
      `display name must be ${MAX_HUMAN_DISPLAY_NAME} characters or fewer`,
    );
  }
  return name;
}

/**
 * Compatibility path for trusted provisioning lanes that predate explicit
 * name capture. It produces a readable name, never an email address, and the
 * result is still persisted under the same database invariant.
 */
export function humanNameFromAccountKey(value: string): string {
  const local = value.trim().split("@", 1)[0]!.split("+", 1)[0]!;
  const words = local
    .replace(/[._-]+/g, " ")
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .trim()
    .replace(/\s+/g, " ");
  const readable = words
    .split(" ")
    .filter(Boolean)
    .map((word) => word.length > 1
      ? `${word[0]!.toLocaleUpperCase()}${word.slice(1)}`
      : word.toLocaleUpperCase())
    .join(" ");
  return normalizedHumanDisplayName(readable || "Member");
}
