/**
 * What counts as a SUBJECT a reviewer would recognise (CA8).
 *
 * Subjects decide which facts are ever compared with each other, so the cost of
 * a bad one is asymmetric: a junk subject ("The", "Per", "March") collapses
 * unrelated facts into one group and buries real disagreements, while a missing
 * subject makes a fact invisible to grouped detection entirely. This module is
 * the single vocabulary both the write path and the tagger use, so the two can
 * never drift.
 */

import { parseEntitiesAnnotation } from "../ingest/kernel-store.js";

/**
 * Function words and calendar terms that `capitalizedWords` lifts out of
 * ordinary sentences ("The refund window…", "Per the playbook…", "March 1").
 * Observed live on 2026-08-09 as stored subjects; none of them is a thing an
 * organization has facts ABOUT.
 */
const STOP_SUBJECTS = new Set([
  "a", "an", "and", "any", "are", "as", "at", "be", "but", "by", "each", "for",
  "from", "has", "have", "however", "if", "in", "is", "it", "its", "no", "not",
  "of", "on", "once", "only", "or", "our", "per", "so", "that", "the", "their",
  "then", "there", "these", "they", "this", "those", "to", "we", "what", "when",
  "where", "which", "while", "who", "why", "with", "you", "your",
  "january", "february", "march", "april", "may", "june", "july", "august",
  "september", "october", "november", "december",
  "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
  "today", "tomorrow", "yesterday",
]);

/**
 * `capitalizedWords` derives mentions from any capitalised token, so an
 * identifier like `MET-012-01` contributes "MET". Those are not subjects — same
 * rule the scan already applies (CS19), kept here so the write side never
 * STORES what the read side would only discard.
 */
export function isUsableSubject(value: string): boolean {
  const subject = value.trim();
  if (subject.length < 4) return false;
  if (STOP_SUBJECTS.has(subject.toLowerCase())) return false;
  // A short all-caps token with no lowercase is an identifier prefix or code.
  if (/^[A-Z0-9]{2,5}$/.test(subject)) return false;
  // Must contain letters; a bare number or date fragment is never a subject.
  return /[A-Za-z]{3}/.test(subject);
}

/** Normalise, filter and de-duplicate a raw mention list into subjects. */
export function usableSubjects(mentions: readonly string[], limit = 8): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const mention of mentions) {
    const subject = String(mention ?? "").trim().replace(/\s+/g, " ");
    if (!isUsableSubject(subject)) continue;
    const key = subject.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(subject);
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * Every subject a fact can be grouped by: the write path's registry-resolved
 * annotation UNION the derived column. Union rather than precedence — the
 * annotation carries canonical names the registry resolved, the column carries
 * what deterministic or model derivation found later, and dropping either
 * shrinks the set of facts a conflict can be found between.
 */
export function factSubjects(content: string, derived: unknown): string[] {
  const fromColumn = Array.isArray(derived)
    ? derived.filter((value): value is string => typeof value === "string")
    : typeof derived === "string"
      ? (JSON.parse(derived) as unknown[]).filter((v): v is string => typeof v === "string")
      : [];
  return usableSubjects([...parseEntitiesAnnotation(content), ...fromColumn]);
}
