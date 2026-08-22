/**
 * Module E (M2) — referee scorecard.
 *
 * Runs every mounted driver over the SAME ScopedView and scores them on
 * questions generated from the namespace's own facts:
 *
 *   - Q/A generation: take up to `maxQuestions` valid facts from the view's
 *     candidate set; the query for a fact is its 3–5 most DISTINCTIVE tokens
 *     (stopwords dropped, rarest-first by corpus document frequency, emitted
 *     in original content order). A fact with fewer than 3 distinctive
 *     tokens is skipped — its query would be too ambiguous to score fairly.
 *   - Metrics per driver: hit@3 (planted ref appears in the top 3 of
 *     plan()'s result), mean injected tokens (sum of tokenEstimate per
 *     question, averaged), p95 latency of plan() in ms. A plan() throw
 *     counts as a miss (and is tallied in `errors`) — a crashing driver
 *     must lose, not crash the referee. A driver that fails 3 questions in
 *     a row is treated as dead and skipped for the rest of the run (the
 *     skipped questions still count as errors), so a sidecar-down driver
 *     cannot block the scorecard for minutes.
 *   - Winner: highest hit@3; ties broken by FEWER errors, then LOWER mean
 *     tokens, then name.
 *
 * The scorecard persists into the `scorecards` table (migration 004) and
 * renders to markdown. The referee is kernel-side — it may touch the Db —
 * but the drivers it exercises see only the ScopedView.
 */

import { ulid } from "ulid";
import type { AuditEvent, Namespace, RetrieverDriver, ScopedView } from "../types.js";
import { tokenize } from "../embed/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Minimal Db surface the referee needs (src/db/client.ts Db satisfies it). */
export interface RefereeDb {
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface RefereeDeps {
  db: RefereeDb;
  /** Every mounted driver (integrator: the registry's full list). */
  drivers: RetrieverDriver[];
  /** ACL-scoped view for the namespace — the SAME view for every driver. */
  view: ScopedView;
  /**
   * D4 audit sink — a scorecard READS up to 200 real fact contents and runs
   * every driver over them, so it must leave an audit trail like every other
   * content-reading path. Optional only for module-level tests; the kernel
   * and CLI integrations always wire it.
   */
  audit?: { append(event: AuditEvent): Promise<void> };
  /** Audit attribution (defaults: actor "kernel", agentId "referee"). */
  actor?: string;
  agentId?: string;
}

export interface ScorecardOptions {
  /** Max Q/A pairs generated from the namespace's facts. Default 30. */
  maxQuestions?: number;
  /** k passed to each driver's plan(). Default 8. */
  k?: number;
  /** tokenBudget passed to each driver's plan(). Default 2000. */
  tokenBudget?: number;
}

export interface ScorecardQuestion {
  /** The planted fact's ref — the right answer. */
  ref: string;
  /** Distinctive-token query derived from that fact's content. */
  query: string;
}

export interface DriverScore {
  driver: string;
  questions: number;
  /** Fraction of questions whose planted ref appeared in the top 3 (0..1). */
  hitAt3: number;
  /** Mean sum-of-tokenEstimate of the refs a plan() call returned. */
  meanTokens: number;
  p95LatencyMs: number;
  /** plan() throws — each counted as a miss. */
  errors: number;
}

export interface Scorecard {
  id: string;
  namespace: Namespace;
  ranAt: string; // ISO-8601
  questionCount: number;
  drivers: DriverScore[];
  winner: string;
}

// ---------------------------------------------------------------------------
// Question generation
// ---------------------------------------------------------------------------

/** Small english stopword list — enough to keep glue words out of queries. */
const STOPWORDS = new Set([
  "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can",
  "did", "do", "does", "for", "from", "had", "has", "have", "he", "her",
  "his", "how", "i", "if", "in", "into", "is", "it", "its", "may", "not",
  "of", "on", "or", "our", "she", "should", "so", "than", "that", "the",
  "their", "them", "then", "there", "these", "they", "this", "to", "was",
  "we", "were", "what", "when", "where", "which", "who", "will", "with",
  "would", "you", "your",
]);

const MIN_DISTINCTIVE_TOKENS = 3;
const MAX_QUERY_TOKENS = 5;
/**
 * Cap on tokens with document frequency 1 (tokens that exist ONLY in the
 * answer fact) per query. An all-df=1 query is a verbatim token subsequence
 * unique to the planted answer — any lexical lane resolves it trivially and
 * hit@3 saturates at ~1.0 for every driver, making the scorecard
 * non-discriminating. Mixing in tokens SHARED with other facts (df >= 2)
 * forces drivers to actually disambiguate among the sharing documents.
 */
const MAX_UNIQUE_QUERY_TOKENS = 2;

/**
 * Build up to `maxQuestions` Q/A pairs from the candidate corpus. For each
 * fact: drop stopwords and short tokens, rank the remaining distinct tokens
 * by corpus document frequency (rarest first, token text as tie-break for
 * determinism), keep the rarest 5 — but at most MAX_UNIQUE_QUERY_TOKENS with
 * df=1 when shared (df>=2) tokens exist, so the query is not a subsequence
 * unique to the answer — and emit them in original content order.
 * Facts with fewer than 3 distinctive tokens are skipped.
 */
export function buildQuestions(
  corpus: { ref: string; content: string }[],
  maxQuestions: number,
): ScorecardQuestion[] {
  if (maxQuestions <= 0 || corpus.length === 0) return [];

  const docTokens = corpus.map((d) => tokenize(d.content));

  // Document frequency per token across the corpus.
  const df = new Map<string, number>();
  for (const toks of docTokens) {
    for (const t of new Set(toks)) df.set(t, (df.get(t) ?? 0) + 1);
  }

  const questions: ScorecardQuestion[] = [];
  for (let i = 0; i < corpus.length && questions.length < maxQuestions; i++) {
    const toks = docTokens[i];
    const distinct = [...new Set(toks)].filter(
      (t) => t.length >= 3 && !STOPWORDS.has(t),
    );
    if (distinct.length < MIN_DISTINCTIVE_TOKENS) continue; // invalid fact

    const ranked = distinct.sort(
      (a, b) => (df.get(a) ?? 0) - (df.get(b) ?? 0) || a.localeCompare(b),
    );
    // Rarest-first with a uniqueness cap: at most MAX_UNIQUE_QUERY_TOKENS
    // answer-only (df=1) tokens; the rest come from the rarest shared ones.
    const rarest: string[] = [];
    let uniqueUsed = 0;
    for (const t of ranked) {
      if (rarest.length >= MAX_QUERY_TOKENS) break;
      if ((df.get(t) ?? 0) <= 1) {
        if (uniqueUsed >= MAX_UNIQUE_QUERY_TOKENS) continue;
        uniqueUsed++;
      }
      rarest.push(t);
    }
    // Backfill from the skipped unique tokens when the fact has too few
    // shared tokens (fully-distinct corpora keep their old behavior).
    if (rarest.length < MAX_QUERY_TOKENS) {
      for (const t of ranked) {
        if (rarest.length >= MAX_QUERY_TOKENS) break;
        if (!rarest.includes(t)) rarest.push(t);
      }
    }

    // Emit in original content order so the query reads naturally.
    const chosen = new Set(rarest);
    const ordered: string[] = [];
    for (const t of toks) {
      if (chosen.has(t)) {
        ordered.push(t);
        chosen.delete(t);
      }
    }
    questions.push({ ref: corpus[i].ref, query: ordered.join(" ") });
  }
  return questions;
}

// ---------------------------------------------------------------------------
// Metrics helpers
// ---------------------------------------------------------------------------

/** p-th percentile (nearest-rank) of a latency sample; 0 for empty input. */
export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

/**
 * Highest hit@3 wins; ties broken by FEWER errors, then LOWER mean tokens,
 * then driver name. Errors rank before mean tokens so a dead driver
 * (hitAt3=0, meanTokens=0 because it never returned anything, errors=N)
 * cannot beat a healthy driver that answered every question — a crashing
 * driver must lose.
 */
export function rankDrivers(scores: DriverScore[]): DriverScore[] {
  return [...scores].sort(
    (a, b) =>
      b.hitAt3 - a.hitAt3 ||
      a.errors - b.errors ||
      a.meanTokens - b.meanTokens ||
      a.driver.localeCompare(b.driver),
  );
}

// ---------------------------------------------------------------------------
// runScorecard
// ---------------------------------------------------------------------------

const DEFAULT_MAX_QUESTIONS = 30;
const DEFAULT_K = 8;
const DEFAULT_TOKEN_BUDGET = 2000;
/** Candidate pull for question generation (mirrors the mem0 candidate cap). */
const CORPUS_LIMIT = 200;
/**
 * Short-circuit: after this many CONSECUTIVE plan() throws the driver is
 * treated as dead for the rest of the run — remaining questions are tallied
 * as errors WITHOUT calling plan(). A sidecar-down mem0 costs ~3s per failed
 * question (2 x 1.5s timeout); without this, 30 questions block the
 * synchronous admin scorecard route for ~90s.
 */
const MAX_CONSECUTIVE_DRIVER_ERRORS = 3;

export async function runScorecard(
  deps: RefereeDeps,
  namespace: Namespace,
  opts: ScorecardOptions = {},
): Promise<Scorecard> {
  const maxQuestions = opts.maxQuestions ?? DEFAULT_MAX_QUESTIONS;
  const k = opts.k ?? DEFAULT_K;
  const tokenBudget = opts.tokenBudget ?? DEFAULT_TOKEN_BUDGET;

  if (deps.drivers.length === 0) {
    throw new Error("runScorecard: no drivers to score");
  }

  const corpus = await deps.view.candidates(CORPUS_LIMIT);
  const questions = buildQuestions(corpus, maxQuestions);
  if (questions.length === 0) {
    throw new Error(
      `runScorecard: namespace '${namespace}' has no facts with enough distinctive tokens to build questions`,
    );
  }

  const scores: DriverScore[] = [];
  for (const driver of deps.drivers) {
    let hits = 0;
    let tokensTotal = 0;
    let errors = 0;
    let consecutiveErrors = 0;
    const latencies: number[] = [];

    for (const q of questions) {
      if (consecutiveErrors >= MAX_CONSECUTIVE_DRIVER_ERRORS) {
        // Driver is deterministically failing (e.g. sidecar down) — skip the
        // remaining questions instead of burning the full timeout budget on
        // each. Skipped questions still count as misses AND errors.
        errors++;
        continue;
      }
      const t0 = performance.now();
      try {
        const refs = await driver.plan({
          query: q.query,
          view: deps.view,
          tokenBudget,
          k,
        });
        latencies.push(performance.now() - t0);
        consecutiveErrors = 0;
        if (refs.slice(0, 3).some((r) => r.ref === q.ref)) hits++;
        tokensTotal += refs.reduce((s, r) => s + r.tokenEstimate, 0);
      } catch {
        // A crashing driver scores a miss; the referee keeps going.
        latencies.push(performance.now() - t0);
        errors++;
        consecutiveErrors++;
      }
    }

    scores.push({
      driver: driver.name,
      questions: questions.length,
      hitAt3: hits / questions.length,
      meanTokens: tokensTotal / questions.length,
      p95LatencyMs: percentile(latencies, 95),
      errors,
    });
  }

  const card: Scorecard = {
    id: ulid(),
    namespace,
    ranAt: new Date().toISOString(),
    questionCount: questions.length,
    drivers: rankDrivers(scores),
    winner: rankDrivers(scores)[0].driver,
  };

  await deps.db.query(
    `INSERT INTO scorecards (id, namespace, ran_at, json) VALUES ($1, $2, $3, $4)`,
    [card.id, card.namespace, card.ranAt, JSON.stringify(card)],
  );

  // D4: the run read real fact contents (view.candidates) and ranked them
  // through every driver — leave the same audit trail every other
  // content-reading path leaves.
  if (deps.audit) {
    await deps.audit.append({
      ts: card.ranAt,
      actor: deps.actor ?? "kernel",
      agentId: deps.agentId ?? "referee",
      op: "read",
      memoryId: null,
      namespace,
      purpose: "scorecard",
      result: "ok",
      detail:
        `scorecard=${card.id} questions=${card.questionCount} ` +
        `drivers=${card.drivers.map((d) => d.driver).join(",")} winner=${card.winner}`,
    });
  }

  return card;
}

// ---------------------------------------------------------------------------
// Markdown render
// ---------------------------------------------------------------------------

export function renderScorecardMarkdown(card: Scorecard): string {
  const lines: string[] = [];
  lines.push(`# Referee scorecard - ${card.namespace}`);
  lines.push("");
  lines.push(
    `Ran ${card.ranAt} · ${card.questionCount} questions · winner: **${card.winner}**`,
  );
  lines.push("");
  lines.push("| driver | hit@3 | mean tokens | p95 latency (ms) | errors |");
  lines.push("|---|---:|---:|---:|---:|");
  for (const s of card.drivers) {
    const name = s.driver === card.winner ? `**${s.driver}**` : s.driver;
    lines.push(
      `| ${name} | ${s.hitAt3.toFixed(2)} | ${s.meanTokens.toFixed(1)} | ${s.p95LatencyMs.toFixed(1)} | ${s.errors} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}
