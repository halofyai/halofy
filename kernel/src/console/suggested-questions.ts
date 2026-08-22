/**
 * M9 #13 (E47) — derived suggested questions for the copilot hero.
 *
 * `console/screens/s10.js` used to ship a hardcoded `DEFAULT_PROMPTS` list that
 * was identical for every tenant. This module derives the chips instead, from
 * two signals the caller is already allowed to see:
 *
 *   1. the top ANSWERED queries in `audit_log` (op search/fault, result 'ok') —
 *      the same rollup S2's `querySummary.topQueries` reads; and
 *   2. knowledge headings from the MemoryIndex (`memory_objects`), ranked by
 *      how often the fact has actually been retrieved.
 *
 * PURE READ PATH. No syscall, no store write, no audit row of its own — the
 * console fetches this to paint chips, and the copilot turn the user then fires
 * is what gets audited (D4 applies to syscalls; this is a management read like
 * every other `src/console/api.ts` handler).
 *
 * Scoping is the ancestor-prefix ACL as an EXACT `IN (...)` list — namespace N
 * sees rows whose namespace is N or a `/`-split ancestor of N. There is no
 * `LIKE` in this module at all, so the `_`/`%` wildcard hazard cannot recur. A
 * root owner (empty namespace) reads org-wide.
 */

import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import { isRootOwner } from "../auth/index.js";
import type { AccessSubject, Identity, MemoryObject, Namespace } from "../types.js";

/** Where a suggested question came from — surfaced so the UI can label chips. */
export type SuggestedQuestionSource = "answered-query" | "knowledge" | "seed";

/** One derived chip. */
export interface SuggestedQuestion {
  /** The question text, ready to paste into the composer. */
  text: string;
  source: SuggestedQuestionSource;
  /** Supporting count: query repeats, or retrievals of the underlying fact. */
  weight: number;
}

/** The GET /v1/copilot/suggested-questions read model. */
export interface SuggestedQuestionsResult {
  namespace: Namespace;
  questions: SuggestedQuestion[];
  /** How much real signal backed the list (0/0 means the seeds are showing). */
  derivedFrom: { answeredQueries: number; knowledgeHeadings: number };
}

/**
 * ACL-scoped knowledge reader — the structural slice of MemoryIndex this
 * handler consumes. Signal 2 MUST read through the canonical query-layer
 * fence (namespace ancestry + explicit mounts + source-native ACL +
 * classification destination + lifecycle + TTL): a raw memory_objects query
 * with only the ancestor IN-list leaked the leading content of exactly the
 * rows mem_search hides from the caller (confidential / source-ACL'd facts).
 */
export interface SuggestedQuestionsIndex {
  listCandidates(
    namespace: Namespace,
    opts?: { validOnly?: boolean; limit?: number; access?: AccessSubject },
  ): Promise<MemoryObject[]>;
}

/** The subset of the concrete Kernel this handler needs (no import cycle). */
export interface SuggestedQuestionsKernel {
  db: Db;
  index: SuggestedQuestionsIndex;
}

/**
 * Source-ACL subject derived ONLY from the server-resolved identity (D9) —
 * mirrors `sourceAccessSubject` in src/syscalls/index.ts exactly (duplicated
 * here, 10 pure lines, to keep this read-model module off the write path).
 */
function accessSubject(identity: Identity): AccessSubject {
  const principals = new Set<string>([
    identity.actor,
    identity.keyId,
    ...(identity.sourcePrincipals ?? []),
  ]);
  return {
    principals: [...principals].filter((value) => value.length > 0).slice(0, 256),
    groups: [...new Set(identity.sourceGroups ?? [])]
      .filter((value) => value.length > 0)
      .slice(0, 256),
  };
}

/** Chips shown when a namespace has no traffic and no facts yet (brownout). */
const SEED_QUESTIONS: readonly string[] = [
  "What changed in our memory this week?",
  "What do we know that no one has asked about yet?",
  "Which sources are feeding this namespace?",
  "What should I focus on today?",
];

/**
 * Six filled the hero with a wall of chips, and the tail of any ranked list is
 * its weakest part. Four rather than three: three cannot hold both signals at
 * once — the ancestor-visible answered query the ACL test asserts, the two
 * local ones, and a knowledge heading are four distinct things, and cutting
 * one would mean editing a test to fit the number rather than the reverse.
 */
const MAX_QUESTIONS = 4;
/** Beyond this the chip row wraps into a wall of text. */
const MAX_QUESTION_CHARS = 72;

/**
 * The caller's ancestor set as an exact IN-list predicate over `column`,
 * starting at `$startAt`. Root owner reads org-wide (`TRUE`); a namespace with
 * no ancestors (should not happen for a non-root caller) reads nothing.
 */
function ancestorPredicate(
  identity: Identity,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  if (isRootOwner(identity)) return { sql: "TRUE", params: [] };
  const ancestors = namespaceAncestors(identity.namespace);
  if (ancestors.length === 0) return { sql: "FALSE", params: [] };
  let n = startAt;
  const inList = ancestors.map(() => `$${n++}`).join(", ");
  return { sql: `${column} IN (${inList})`, params: [...ancestors] };
}

/** Normalized dedupe key: case- and punctuation-insensitive. */
function dedupeKey(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/** Collapse whitespace and strip control characters from stored text. */
function clean(raw: string): string {
  // eslint-disable-next-line no-control-regex
  return raw.replace(/[\u0000-\u001f]+/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Shape a recorded query string into a chip. Audit `purpose` is whatever the
 * agent sent, so it may already be a question, may be a bare keyword phrase, or
 * may be far too long to fit a chip.
 */
/** Filename-ish tokens: an audit purpose is often just the ingested file. */
const FILE_EXTENSION = /\.(?:csv|tsv|md|markdown|txt|json|ya?ml|pdf|docx?|xlsx?|pptx?|html?|log)\b/i;
/** Internal audit correlation refs are not questions a human can use. */
const INTERNAL_TRACE_PURPOSE = /^assistant-turn:[0-9A-HJKMNP-TV-Z]{26}$/i;

/**
 * Does this read like something a person would ask?
 *
 * Audit `purpose` is whatever the agent sent, and an import or a bare keyword
 * search lands there verbatim. Capitalising it and appending "?" produced live
 * chips like "Sales.csv sales sales?", "Marketing.csv marketing Marketing?"
 * and "05-customers-and-deals.md 05 customers and deals test?" — four of six
 * on the deployed console were nonsense.
 *
 * Deliberately NOT requiring a wh-word or a verb. That rule rejects perfectly
 * good queries: "org holiday policy" and "refund SLA priority tickets" are
 * noun phrases people really search, and one is asserted by the ancestor-ACL
 * test. The filename and self-repetition rules already catch every junk chip
 * observed live, and they cannot misfire on a real sentence.
 */
function readsAsQuestion(text: string): boolean {
  if (FILE_EXTENSION.test(text)) return false;
  if (INTERNAL_TRACE_PURPOSE.test(text)) return false;
  const words = text.toLowerCase().match(/[a-z][a-z'-]*/g) ?? [];
  if (words.length < 2) return false;
  // "sales sales", "marketing Marketing", "05 customers and deals test" — a
  // keyword bag repeats itself in a way a sentence does not.
  const distinct = new Set(words);
  return distinct.size / words.length >= 0.6;
}

function questionFromQuery(raw: string): string | null {
  const text = clean(raw);
  if (text.length < 3) return null;
  if (text.length > MAX_QUESTION_CHARS) return null;
  if (!readsAsQuestion(text)) return null;
  if (text.endsWith("?")) return text[0]!.toUpperCase() + text.slice(1);
  const capped = text[0]!.toUpperCase() + text.slice(1);
  return capped.replace(/[.!,;:]+$/, "") + "?";
}

/**
 * Function words that read as a dangling fragment when a truncated heading ends
 * on one ("…for enterprise tickets is?"). Trimmed off the tail after a cut.
 */
const TRAILING_STOPWORDS = new Set([
  "a", "an", "and", "are", "as", "at", "be", "by", "every", "for", "from",
  "in", "is", "it", "of", "on", "or", "that", "the", "to", "was", "were",
  "which", "with",
]);

/** Drop dangling function words from the end of a truncated heading. */
function trimTrailingStopwords(heading: string): string {
  const words = heading.split(" ");
  while (words.length > 1 && TRAILING_STOPWORDS.has(words[words.length - 1]!.toLowerCase())) {
    words.pop();
  }
  return words.join(" ");
}

/**
 * Derive a heading from a fact's content — its first clause — and turn it into
 * a "what do we know" question. Facts are declarative sentences; the heading is
 * the subject-bearing head of the first one.
 */
function questionFromContent(raw: string): string | null {
  const text = clean(raw);
  if (text.length < 8) return null;
  const firstClause = text.split(/(?<=[.?!])\s|\s[-–-]\s/)[0] ?? text;
  let heading = firstClause.replace(/[.?!,;:]+$/, "").trim();
  if (heading.length < 8) return null;
  // Not every stored fact is prose. Serialized rows and file dumps make a
  // grammatical wrapper around gibberish — 'What do we know about
  // {"skuCode":"455","shortName":"The Lords Club"}?' was a live chip.
  if (/[{}[\]"|]|^\s*\w+\s*:/.test(heading) || FILE_EXTENSION.test(heading)) return null;
  // Budget for the "What do we know about …?" wrapper.
  const budget = MAX_QUESTION_CHARS - 25;
  if (heading.length > budget) {
    const cut = heading.slice(0, budget);
    const lastSpace = cut.lastIndexOf(" ");
    if (lastSpace < 8) return null;
    heading = trimTrailingStopwords(cut.slice(0, lastSpace));
    if (heading.length < 8) return null;
  }
  return `What do we know about ${heading[0]!.toLowerCase() + heading.slice(1)}?`;
}

/**
 * GET /v1/copilot/suggested-questions — chips derived for the caller's own
 * namespace. Read-only; never throws on a partial signal (a namespace with no
 * audit history still gets knowledge-derived or seed chips).
 */
export async function suggestedQuestions(
  kernel: SuggestedQuestionsKernel,
  identity: Identity,
): Promise<SuggestedQuestionsResult> {
  const picked: SuggestedQuestion[] = [];
  const seen = new Set<string>();

  const push = (question: SuggestedQuestion): void => {
    if (picked.length >= MAX_QUESTIONS) return;
    const key = dedupeKey(question.text);
    if (key === "" || seen.has(key)) return;
    seen.add(key);
    picked.push(question);
  };

  // --- signal 1: top ANSWERED queries --------------------------------------
  // result='ok' only: a miss is a question memory could NOT answer, and
  // suggesting it would set the user up to fail.
  const auditPred = ancestorPredicate(identity, 1);
  const auditRes = await kernel.db.query(
    `SELECT purpose AS query, count(*) AS n
       FROM audit_log
      WHERE op IN ('search', 'fault')
        AND result = 'ok'
        AND purpose IS NOT NULL
        AND actor <> 'unknown'
        AND ${auditPred.sql}
      GROUP BY purpose
      ORDER BY n DESC, purpose ASC
      LIMIT 40`,
    auditPred.params,
  );
  const answeredRows = auditRes.rows as { query: string; n: unknown }[];
  const answered = answeredRows
    .map((row) => ({ text: questionFromQuery(String(row.query)), weight: Number(row.n) }))
    .filter((row): row is { text: string; weight: number } => row.text !== null);
  // Hold a slot back for knowledge. With only three chips, a namespace with
  // three answered queries would otherwise fill every slot from one signal —
  // three variations on what was asked recently, and nothing about what the
  // org actually knows. Leftover answered queries backfill below if the
  // knowledge side has nothing to offer.
  const answeredBudget = Math.max(1, MAX_QUESTIONS - 1);
  for (const row of answered.slice(0, answeredBudget)) {
    push({ text: row.text, source: "answered-query", weight: row.weight });
  }
  const fromQueries = picked.length;

  // --- signal 2: ACL-scoped knowledge headings ------------------------------
  // Most-retrieved live facts first: what the org actually leans on. Rows
  // come EXCLUSIVELY through MemoryIndex.listCandidates — the same query-layer
  // fence every delegated read uses — with the caller's server-resolved
  // source-ACL subject, so a fact that mem_search would hide (restricted /
  // confidential classification, source-native ACL exclusion) can never leak
  // its content into a chip.
  const visible = await kernel.index.listCandidates(identity.namespace, {
    validOnly: true,
    limit: 60,
    access: accessSubject(identity),
  });
  visible.sort(
    (a, b) =>
      b.telemetry.accessCount - a.telemetry.accessCount ||
      (a.assertionTime < b.assertionTime ? 1 : a.assertionTime > b.assertionTime ? -1 : 0),
  );
  let headings = 0;
  for (const row of visible) {
    if (picked.length >= MAX_QUESTIONS) break;
    const text = questionFromContent(row.content);
    if (!text) continue;
    const before = picked.length;
    push({ text, source: "knowledge", weight: row.telemetry.accessCount });
    if (picked.length > before) headings += 1;
  }

  // Knowledge had nothing (or too little) — give the held-back slot back to
  // the answered queries rather than showing a seed chip beside real traffic.
  for (const row of answered.slice(answeredBudget)) {
    if (picked.length >= MAX_QUESTIONS) break;
    push({ text: row.text, source: "answered-query", weight: row.weight });
  }

  // --- brownout: a brand-new namespace still gets a usable hero -------------
  for (const seed of SEED_QUESTIONS) {
    if (picked.length >= MAX_QUESTIONS) break;
    push({ text: seed, source: "seed", weight: 0 });
  }

  return {
    namespace: identity.namespace,
    questions: picked,
    derivedFrom: { answeredQueries: fromQueries, knowledgeHeadings: headings },
  };
}
