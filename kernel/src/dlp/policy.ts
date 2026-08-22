import type { DataClassification } from "../types.js";

export interface DestinationContext {
  region?: string;
}

export interface IngestDestinationPolicy {
  /** Logical destination receiving the write, normally canonical-l2. */
  canonicalDestination?: string;
  /** Kernel-owned allowlist. Connector hints cannot expand this list. */
  allowedRestrictedDestinations?: string[];
  /** Region where the destination persists data. */
  region?: string;
}

export class ClassificationDeniedError extends Error {
  readonly code = "classification-denied";
  readonly sensitivity: DataClassification["sensitivity"];
  readonly destination: string;

  constructor(classification: DataClassification, destination: string, reason: string) {
    super(`classification denied for ${destination}: ${reason}`);
    this.name = "ClassificationDeniedError";
    this.sensitivity = classification.sensitivity;
    this.destination = destination;
  }
}

/** Validate residency and restricted-data destination allowlisting. */
export function destinationAllowed(
  classification: DataClassification,
  destination: string,
  context: DestinationContext = {},
): boolean {
  if (
    classification.residency &&
    (!context.region || classification.residency.toLowerCase() !== context.region.toLowerCase())
  ) {
    return false;
  }
  if (classification.sensitivity === "public" || classification.sensitivity === "internal") {
    return true;
  }
  if (classification.sensitivity === "confidential" &&
      (destination === "canonical-l2" || destination === "canonical-l3")) {
    return true;
  }
  return classification.allowedDestinations.includes(destination);
}

export function assertDestinationAllowed(
  classification: DataClassification,
  destination: string,
  context: DestinationContext = {},
): void {
  if (destinationAllowed(classification, destination, context)) return;
  const reason = classification.residency && !context.region
    ? "destination region is unknown"
    : classification.residency &&
        classification.residency.toLowerCase() !== context.region?.toLowerCase()
      ? "residency mismatch"
      : "confidential or restricted data requires an explicit destination policy";
  throw new ClassificationDeniedError(classification, destination, reason);
}
