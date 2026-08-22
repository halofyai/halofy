/** Canonical comparison form for governed PII-subject metadata. */
export function normalizePiiSubject(value: string): string {
  return value.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase();
}

/** Normalize, discard blanks, de-duplicate, and sort for stable persistence. */
export function normalizePiiSubjects(values: string[]): string[] {
  return [...new Set(values.map(normalizePiiSubject).filter((value) => value.length > 0))]
    .sort((a, b) => a.localeCompare(b));
}
