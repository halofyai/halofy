import type {
  DataClassification,
  DataSensitivity,
} from "../types.js";

export interface ClassificationHints {
  sensitivity?: DataSensitivity;
  piiSubjects?: string[];
  secretKinds?: string[];
  residency?: string;
  allowedDestinations?: string[];
}

const SENSITIVITY_RANK: Record<DataSensitivity, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

const SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i],
  ["openai-api-key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/],
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ["github-token", /\bgh[oprsu]_[A-Za-z0-9]{20,}\b/],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
];

const PII_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
  ["us-ssn", /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/],
  ["phone", /\b(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}\b/],
  ["payment-card", /\b(?:\d[ -]*?){13,19}\b/],
];

function uniqueSorted(values: readonly string[] | undefined): string[] {
  return [...new Set((values ?? []).map((value) => value.trim()).filter(Boolean))].sort();
}

function maxSensitivity(a: DataSensitivity, b: DataSensitivity): DataSensitivity {
  return SENSITIVITY_RANK[a] >= SENSITIVITY_RANK[b] ? a : b;
}

/**
 * Pure deterministic classifier. It returns labels only: matched content is
 * never copied into the result, errors, or audit-safe metadata.
 */
export function classifyData(
  content: string,
  hints: ClassificationHints = {},
): DataClassification {
  const detectedSecrets = SECRET_PATTERNS
    .filter(([, pattern]) => pattern.test(content))
    .map(([kind]) => kind);
  const detectedPii = PII_PATTERNS
    .filter(([, pattern]) => pattern.test(content))
    .map(([kind]) => kind);

  const secretKinds = uniqueSorted([...detectedSecrets, ...(hints.secretKinds ?? [])]);
  const piiSubjects = uniqueSorted([...detectedPii, ...(hints.piiSubjects ?? [])]);

  let sensitivity: DataSensitivity = "internal";
  if (piiSubjects.length > 0) sensitivity = "confidential";
  if (secretKinds.length > 0) sensitivity = "restricted";
  if (hints.sensitivity) sensitivity = maxSensitivity(sensitivity, hints.sensitivity);

  return {
    sensitivity,
    piiSubjects,
    secretKinds,
    ...(hints.residency ? { residency: hints.residency.trim().toLowerCase() } : {}),
    allowedDestinations: uniqueSorted(hints.allowedDestinations),
  };
}
