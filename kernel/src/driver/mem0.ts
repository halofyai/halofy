/**
 * Module C (M2) — mem0 sidecar driver: out-of-process retriever cartridge.
 *
 * The driver speaks a tiny HTTP contract to a python sidecar
 * (sidecar/mem0/server.py):
 *
 *   POST /plan {query, candidates:[{ref,content}], budget, k}
 *     -> {refs:[{ref,score}]}
 *   GET  /healthz -> {ok:true, mode:"mem0"|"fallback"}
 *
 * Boundary rules (CONTRACTS-M2): drivers are read-only cartridges. This module
 * imports ONLY src/types.js — the ScopedView it receives is its whole world.
 * The sidecar can only REORDER what it was sent: any ref in the response that
 * was not part of the sent candidate set is dropped (and warn-logged via
 * console.warn — the metrics logger lives outside the driver boundary).
 *
 * Availability model (documented choice): the CONSTRUCTOR THROWS
 * `DriverUnavailableError` when no sidecar URL is configured (neither the
 * `url` option nor the HALOMEM_MEM0_URL env var). Rationale: Kernel.boot
 * mounts mem0 iff HALOMEM_MEM0_URL is set, so a URL-less Mem0Driver can never
 * serve a request — failing at construction keeps plan() failures strictly
 * about the sidecar being down.
 *
 * Failure model: each sidecar call gets a 1.5s timeout and ONE retry
 * (2 attempts total). Any transport error, timeout, non-2xx status, or
 * malformed response body on the final attempt throws
 * `DriverUnavailableError`; the kernel falls back to baseline and audits.
 *
 * Idempotency: POST /plan is side-effectful in real-mem0 mode (the sidecar
 * ingests every candidate through LLM/embedding calls), so a blind retry of
 * an abandoned-but-still-executing attempt would double that work. Every
 * plan() call therefore carries ONE `x-halomem-request-id` (UUID) across
 * both attempts; the sidecar coalesces duplicate ids onto the in-flight
 * computation (and serves completed ones from a small cache), so the retry
 * never re-executes the ingestion.
 */

import type { RetrieverDriver, RetrieverQuery, ScoredRef } from "../types.js";
import { estimateTokens } from "../types.js";
import { DriverUnavailableError } from "./index.js";

// Single canonical error class for the whole driver package (integration:
// module A's src/driver/index.ts owns it; re-exported here so existing
// `import { DriverUnavailableError } from './mem0.js'` callers keep working).
export { DriverUnavailableError };

/** Max candidates shipped to the sidecar per plan() call (contract: 200). */
export const MEM0_CANDIDATE_LIMIT = 200;
/** Per-attempt timeout (contract: 1.5s). */
export const MEM0_TIMEOUT_MS = 1500;
/** Retries after the first attempt (contract: one retry = 2 attempts). */
export const MEM0_RETRIES = 1;

export interface Mem0DriverOptions {
  /** Sidecar base URL; falls back to HALOMEM_MEM0_URL. */
  url?: string;
  /** Per-attempt timeout in ms (default 1500). Tests may shrink this. */
  timeoutMs?: number;
  /** Retries after the first attempt (default 1). */
  retries?: number;
  /** Candidate cap (default 200). */
  candidateLimit?: number;
  /** Warn sink (default console.warn). */
  warn?: (message: string) => void;
  /** Bearer credential required for every non-loopback sidecar endpoint. */
  authToken?: string;
}

interface SidecarRef {
  ref: string;
  score: number;
}

export class Mem0Driver implements RetrieverDriver {
  readonly name = "mem0";

  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly candidateLimit: number;
  private readonly warn: (message: string) => void;
  private readonly authToken?: string;

  constructor(opts: Mem0DriverOptions = {}) {
    const url = opts.url ?? process.env.HALOMEM_MEM0_URL;
    if (!url) {
      throw new DriverUnavailableError(
        "mem0",
        "no sidecar URL configured (set HALOMEM_MEM0_URL, e.g. http://localhost:8790)",
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new DriverUnavailableError("mem0", "sidecar URL is invalid");
    }
    const loopback = parsed.hostname === "localhost" || parsed.hostname === "::1" ||
      parsed.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(parsed.hostname);
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new DriverUnavailableError(
        "mem0",
        "sidecar URL must not contain credentials, query, or fragment",
      );
    }
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
      throw new DriverUnavailableError("mem0", "remote sidecar URL requires HTTPS");
    }
    if (!loopback && !opts.authToken) {
      throw new DriverUnavailableError(
        "mem0",
        "remote sidecar URL requires an authentication token",
      );
    }
    this.url = parsed.toString().replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? MEM0_TIMEOUT_MS;
    this.retries = opts.retries ?? MEM0_RETRIES;
    this.candidateLimit = opts.candidateLimit ?? MEM0_CANDIDATE_LIMIT;
    this.warn = opts.warn ?? ((m) => console.warn(m));
    this.authToken = opts.authToken;
  }

  capabilities(): { graph: boolean; streaming: boolean } {
    return { graph: false, streaming: false };
  }

  async plan(q: RetrieverQuery): Promise<ScoredRef[]> {
    if (q.k <= 0) return [];

    // The ScopedView is the fence: only ACL-visible rows ever reach the wire.
    const candidates = (await q.view.candidates(this.candidateLimit)).slice(
      0,
      this.candidateLimit,
    );
    if (candidates.length === 0) return [];

    const body = JSON.stringify({
      query: q.query,
      candidates,
      budget: q.tokenBudget,
      k: q.k,
    });

    // One id for the whole plan() call, reused across retry attempts so the
    // sidecar can dedupe (see "Idempotency" in the module header).
    const requestId = globalThis.crypto.randomUUID();
    const parsed = await this.postPlan(body, requestId);

    // Ref-whitelist mapping: the sidecar can only reorder what it was sent.
    const contentByRef = new Map(candidates.map((c) => [c.ref, c.content]));
    const seen = new Set<string>();
    const out: ScoredRef[] = [];
    for (const entry of parsed) {
      const content = contentByRef.get(entry.ref);
      if (content === undefined) {
        this.warn(
          `[mem0-driver] dropped ref '${entry.ref}' returned by sidecar: not in the sent candidate set`,
        );
        continue;
      }
      if (seen.has(entry.ref)) continue; // sidecar duplicates collapse
      seen.add(entry.ref);
      out.push({
        id: entry.ref,
        tier: "L2",
        ref: entry.ref,
        score: clamp01(entry.score),
        content,
        tokenEstimate: estimateTokens(content),
      });
    }

    // Kernel-side discipline regardless of sidecar behavior: rank order,
    // top-k, cumulative token budget (first hit always admitted).
    out.sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref));
    const trimmed: ScoredRef[] = [];
    let total = 0;
    for (const hit of out) {
      if (trimmed.length >= q.k) break;
      if (trimmed.length > 0 && total + hit.tokenEstimate > q.tokenBudget) continue;
      trimmed.push(hit);
      total += hit.tokenEstimate;
    }
    return trimmed;
  }

  /**
   * POST /plan with timeout + retry; validated {refs:[{ref,score}]} out.
   * The SAME `requestId` rides every attempt so the sidecar can coalesce a
   * retry onto the still-running first attempt instead of re-executing a
   * side-effectful ingestion (real-mem0 mode).
   */
  private async postPlan(body: string, requestId: string): Promise<SidecarRef[]> {
    const attempts = this.retries + 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        const res = await fetch(`${this.url}/plan`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-halomem-request-id": requestId,
            ...(this.authToken ? { authorization: `Bearer ${this.authToken}` } : {}),
          },
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
          redirect: "error",
        });
        if (!res.ok) {
          throw new Error(`sidecar responded ${res.status}`);
        }
        const json: unknown = await res.json();
        return parseSidecarResponse(json);
      } catch (err) {
        lastError = err;
      }
    }
    throw new DriverUnavailableError(
      "mem0",
      `sidecar at ${this.url} failed after ${attempts} attempt(s): ${describeError(lastError)}`,
      { cause: lastError },
    );
  }
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

function describeError(err: unknown): string {
  if (err instanceof Error) {
    // AbortSignal.timeout raises TimeoutError DOMException-alikes.
    return err.name === "TimeoutError" ? "timeout" : err.message;
  }
  return String(err);
}

/** Strict-ish response validation; malformed shapes are transport failures. */
function parseSidecarResponse(json: unknown): SidecarRef[] {
  if (typeof json !== "object" || json === null) {
    throw new Error("sidecar returned non-object body");
  }
  const refs = (json as { refs?: unknown }).refs;
  if (!Array.isArray(refs)) {
    throw new Error("sidecar response missing 'refs' array");
  }
  const out: SidecarRef[] = [];
  for (const entry of refs) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      typeof (entry as { ref?: unknown }).ref !== "string" ||
      typeof (entry as { score?: unknown }).score !== "number"
    ) {
      throw new Error("sidecar returned malformed ref entry");
    }
    out.push({
      ref: (entry as { ref: string }).ref,
      score: (entry as { score: number }).score,
    });
  }
  return out;
}
