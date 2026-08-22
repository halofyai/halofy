/**
 * M9 parity #6 — llms.txt / memory manifest (CONTRACTS-M9-PARITY.md E12–E14).
 *
 * Renders an ACL-scoped, per-badge llms.txt-style memory-index manifest (plus
 * a size-capped `full` variant) from ACTIVE, CURRENT-VERSION canonical L2/L3
 * rows only, with per-source freshness dates.
 *
 * Boundary (the review attacks this):
 *  - E12 — canonical rows ONLY. This module reads exclusively through the
 *    ACL-scoped MemoryIndex (src/index/index.ts). It never touches L0/L1
 *    working-set/cache layers, warm-store mirrors, or the cold store, and it
 *    filters out derived rows that DO live in memory_objects: pointer facts
 *    (M6/D11 — routes, not answers) and write-back cache facts (M6/D14 —
 *    usage-governed copies of live fetches). What remains is exactly the
 *    authoritative memory: active, currently-valid (t_valid_to IS NULL,
 *    D7 supersedence respected) L2 facts and L3 index entries.
 *  - E13 — the contents are exactly the calling badge's ACL view: namespace
 *    ancestry + explicit mounts + source-native access + classification are
 *    all enforced inside MemoryIndex.listCandidates, keyed off the
 *    server-resolved Identity (D9). Two different badges get two different
 *    manifests because their Identity differs — nothing here accepts a
 *    namespace or actor from the caller.
 *  - E14 — this is an audited read syscall (D4): ok, denied (revoked
 *    credential / suspended tenant / rate limit), and error outcomes each
 *    write an audit row (op:"read", purpose:"manifest").
 *  - Read-only: no store handle, no write path, no SQL. MemoryIndex read
 *    methods are the entire data surface (D1/D2 — we index and rank nothing
 *    here; the manifest is a rendering of governed rows, not a retriever).
 *
 * Markdown-render style follows src/ingest/fragmentation.ts.
 */

import type {
  AuditEvent,
  Identity,
  MemoryObject,
  Namespace,
} from "../types.js";
import type { SyscallDeps } from "../syscalls/index.js";
import { RateLimitError, sourceAccessSubject } from "../syscalls/index.js";
import { appendAuditEvent } from "../audit/index.js";
import { AuthzError } from "../auth/index.js";
import { DEFAULT_RATE_LIMIT_PER_MIN } from "../policy/index.js";
import {
  effectiveRateLimit,
  tenantGate,
  TenantSuspendedError,
} from "../policy/tenant.js";

// ---------------------------------------------------------------------------
// Public types (local per parallel-safety rule 5 — reported for promotion)
// ---------------------------------------------------------------------------

/** "index" = llms.txt-style listing; "full" = size-capped llms-full.txt. */
export type ManifestVariant = "index" | "full";

export interface MemManifestArgs {
  /** Default "index". */
  variant?: ManifestVariant;
  /** Byte cap on the rendered markdown. Clamped to [1024, 4 MiB]. */
  maxBytes?: number;
}

/** Per-source freshness rollup (E12 "per-source freshness dates"). */
export interface ManifestSourceFreshness {
  /** Company filename when present, otherwise sourceId or "conversation". */
  source: string;
  entryCount: number;
  /** ISO timestamp of the newest assertion attributed to this source. */
  freshestAt: string;
}

export interface ManifestResult {
  namespace: Namespace;
  variant: ManifestVariant;
  generatedAt: string;
  /** Canonical rows visible to the badge (before any byte-cap truncation). */
  entryCount: number;
  /** Entries actually rendered into `markdown` (== entryCount unless truncated). */
  renderedCount: number;
  sources: ManifestSourceFreshness[];
  /** True when entry or source-rollup rendering was byte-capped. */
  truncated: boolean;
  bytes: number;
  markdown: string;
}

/** Thrown by parseManifestArgs on a malformed request (transport → 400). */
export class ManifestArgsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestArgsError";
  }
}

/** Transport-level parse result: syscall args + response format. */
export interface ParsedManifestRequest {
  args: MemManifestArgs;
  /** "json" (default) → JSON envelope; "text" → raw text/markdown body. */
  format: "json" | "text";
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/** Default byte cap for the rendered manifest (both variants). */
export const DEFAULT_MANIFEST_MAX_BYTES = 262_144; // 256 KiB
const MIN_MAX_BYTES = 1_024;
const MAX_MAX_BYTES = 4_194_304; // 4 MiB
/** Same "all visible rows" bound memStats uses against listCandidates. */
const ALL_ROWS = 2_147_483_647;
/** Reserve for the truncation trailer so the cap is never overshot. */
const TRAILER_RESERVE = 160;

// ---------------------------------------------------------------------------
// Request parsing (used by the HTTP route; query params arrive as strings)
// ---------------------------------------------------------------------------

const ALLOWED_QUERY_KEYS = new Set(["variant", "maxBytes", "format"]);

export function parseManifestArgs(
  payload: Record<string, unknown>,
): ParsedManifestRequest {
  for (const key of Object.keys(payload)) {
    if (!ALLOWED_QUERY_KEYS.has(key)) {
      throw new ManifestArgsError(`unknown parameter '${key}'`);
    }
  }
  const args: MemManifestArgs = {};

  const variant = payload.variant;
  if (variant !== undefined && variant !== null) {
    if (variant !== "index" && variant !== "full") {
      throw new ManifestArgsError("variant must be 'index' or 'full'");
    }
    args.variant = variant;
  }

  const rawMax = payload.maxBytes;
  if (rawMax !== undefined && rawMax !== null) {
    const n = typeof rawMax === "number" ? rawMax : Number(rawMax);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
      throw new ManifestArgsError("maxBytes must be a positive integer");
    }
    args.maxBytes = n;
  }

  const format = payload.format;
  if (format !== undefined && format !== null && format !== "json" && format !== "text") {
    throw new ManifestArgsError("format must be 'json' or 'text'");
  }

  return { args, format: format === "text" ? "text" : "json" };
}

// ---------------------------------------------------------------------------
// Row selection (E12)
// ---------------------------------------------------------------------------

/**
 * True for rows the manifest may render: canonical L2/L3 memory. Pointer facts
 * are routes (D11) and cache facts are derived copies of live fetches (D14) —
 * both are governed rows but NOT authoritative organizational memory, so a
 * manifest must never present them as such. listCandidates already excludes
 * `type='pointer'` by default; the provenance checks are a belt for pointer/
 * cache stamps regardless of type.
 */
export function isManifestRow(obj: MemoryObject): boolean {
  if (obj.tier !== "L2" && obj.tier !== "L3") return false;
  if (obj.type === "pointer") return false;
  if (obj.status !== "active") return false;
  if (obj.tValidTo !== null) return false;
  for (const entry of obj.provenance) {
    if (entry.pointer === true || entry.cache === true) return false;
  }
  return true;
}

/** Source label a row is attributed to (mirrors DbFragmentationReader). */
function sourceLabel(obj: MemoryObject): string {
  return obj.provenance[0]?.documentKey ?? obj.provenance[0]?.sourceId ?? "conversation";
}

/** Per-source entry counts + freshest assertion time, sorted newest-first. */
export function sourceFreshness(rows: MemoryObject[]): ManifestSourceFreshness[] {
  const bySource = new Map<string, { count: number; freshest: string }>();
  for (const row of rows) {
    const label = sourceLabel(row);
    const cur = bySource.get(label);
    if (!cur) {
      bySource.set(label, { count: 1, freshest: row.assertionTime });
    } else {
      cur.count += 1;
      if (row.assertionTime > cur.freshest) cur.freshest = row.assertionTime;
    }
  }
  return [...bySource.entries()]
    .map(([source, { count, freshest }]) => ({
      source,
      entryCount: count,
      freshestAt: freshest,
    }))
    .sort(
      (a, b) =>
        b.freshestAt.localeCompare(a.freshestAt) || a.source.localeCompare(b.source),
    );
}

// ---------------------------------------------------------------------------
// Markdown rendering (style: src/ingest/fragmentation.ts)
// ---------------------------------------------------------------------------

/** Flatten newlines so an index line never breaks the list structure. */
function flat(text: string): string {
  return text.replace(/\r?\n/g, " ").trim();
}

/** Trim content to a readable one-line snippet. */
function snippet(content: string, max = 120): string {
  const s = flat(content);
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

/** ISO timestamp → date-only display (freshness dates). */
function day(iso: string): string {
  return iso.slice(0, 10);
}

function bytesOf(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

interface RenderOutcome {
  markdown: string;
  renderedCount: number;
  truncated: boolean;
}

/**
 * Optional header overrides for reuse by src/discovery/public.ts (#11a):
 * the redacted public tier renders through the SAME renderer, but its header
 * must not claim to be a badge-scoped ACL view. Both fields default to the
 * badge-manifest wording — existing callers are unaffected.
 */
export interface ManifestHeaderOverrides {
  title?: string;
  description?: string;
}

interface RenderHeaderOutcome {
  lines: string[];
  renderedSourceCount: number;
}

function renderHeader(
  namespace: Namespace,
  generatedAt: string,
  rows: MemoryObject[],
  sources: ManifestSourceFreshness[],
  variant: ManifestVariant,
  maxBytes: number,
  overrides?: ManifestHeaderOverrides,
): RenderHeaderOutcome {
  const lines: string[] = [];
  lines.push(overrides?.title ?? `# Memory manifest - ${flat(namespace)}`);
  lines.push("");
  lines.push(
    overrides?.description ??
      `> ACL-scoped index of active organizational memory visible to this badge. ` +
        `Variant: ${variant}. Generated ${generatedAt}. ` +
        `${rows.length} entries across ${sources.length} sources. ` +
        `Canonical current-version L2/L3 rows only.`,
  );
  lines.push("");
  lines.push("## Sources");
  lines.push("");
  let used = bytesOf(lines.join("\n"));
  const pushWithinBudget = (line: string): boolean => {
    const addition = `${lines.length > 0 ? "\n" : ""}${line}`;
    const additionBytes = bytesOf(addition);
    if (used + additionBytes > maxBytes) return false;
    lines.push(line);
    used += additionBytes;
    return true;
  };
  let renderedSourceCount = 0;
  if (sources.length === 0) {
    pushWithinBudget("_None._");
  } else {
    for (const s of sources) {
      const line =
        `- ${flat(s.source)} - ${s.entryCount} entries, freshest ${day(s.freshestAt)}`;
      // Leave room for a stable truncation marker whenever another source
      // remains. This keeps a large source catalog from consuming the entry
      // section that the manifest exists to expose.
      const reserve = renderedSourceCount + 1 < sources.length ? 96 : 0;
      if (used + bytesOf(`\n${line}`) + reserve > maxBytes) break;
      if (!pushWithinBudget(line)) break;
      renderedSourceCount += 1;
    }
  }
  if (renderedSourceCount < sources.length) {
    pushWithinBudget(
      `_Source rollup truncated: ${renderedSourceCount} of ${sources.length} sources listed._`,
    );
  }
  pushWithinBudget("");
  return { lines, renderedSourceCount };
}

/** One index-variant list line for a row. */
function indexEntry(obj: MemoryObject): string {
  return (
    `- [${obj.tier}/${obj.type}] ${snippet(obj.content)} ` +
    `(${flat(sourceLabel(obj))}, ${day(obj.assertionTime)}, id ${obj.id})`
  );
}

/** One full-variant section for a row. */
function fullEntry(obj: MemoryObject): string {
  return [
    `### ${obj.id}`,
    "",
    `- tier: ${obj.tier} · type: ${obj.type} · source: ${flat(sourceLabel(obj))}` +
      ` · updated: ${day(obj.assertionTime)} · confidence: ${obj.confidence.toFixed(2)}`,
    "",
    obj.content.trim(),
    "",
  ].join("\n");
}

/**
 * Render the manifest under a hard byte cap. A large source rollup is capped
 * before it can starve the entry section; entries (newest-first, the order
 * MemoryIndex returned) then consume the remaining budget greedily.
 */
export function renderManifestMarkdown(
  namespace: Namespace,
  rows: MemoryObject[],
  variant: ManifestVariant,
  maxBytes: number,
  generatedAt: string,
  overrides?: ManifestHeaderOverrides,
): RenderOutcome {
  const sources = sourceFreshness(rows);
  const budget = Math.max(maxBytes - TRAILER_RESERVE, 0);
  const entryReserve = Math.min(8_192, Math.floor(budget / 2));
  const headerBudget = Math.max(budget - entryReserve, 0);
  const header = renderHeader(
    namespace,
    generatedAt,
    rows,
    sources,
    variant,
    headerBudget,
    overrides,
  );
  const lines = header.lines;
  lines.push(variant === "full" ? "## Memory" : "## Memory index");
  lines.push("");

  let body = lines.join("\n");
  let used = bytesOf(body);
  let renderedCount = 0;

  if (rows.length === 0) {
    body += "\n_No visible memory._";
  } else {
    for (const row of rows) {
      const piece = (variant === "full" ? fullEntry(row) : indexEntry(row)) + "\n";
      const pieceBytes = bytesOf(piece);
      if (used + pieceBytes > budget) break;
      body += "\n" + piece.replace(/\n$/, "");
      used += pieceBytes;
      renderedCount += 1;
    }
  }

  const entriesTruncated = renderedCount < rows.length;
  const sourcesTruncated = header.renderedSourceCount < sources.length;
  const truncated = entriesTruncated || sourcesTruncated;
  if (truncated) {
    const sourceDetail = sourcesTruncated
      ? `; ${header.renderedSourceCount} of ${sources.length} sources listed`
      : "";
    body +=
      `\n\n_Truncated: ${renderedCount} of ${rows.length} entries rendered` +
      `${sourceDetail} (byte cap ${maxBytes})._`;
  }
  body += "\n";
  return { markdown: body, renderedCount, truncated };
}

// ---------------------------------------------------------------------------
// Audit helpers (D4 — mirrors the private helpers in src/syscalls/index.ts)
// ---------------------------------------------------------------------------

const MANIFEST_PURPOSE = "manifest";

function nowIso(): string {
  return new Date().toISOString();
}

function manifestEvent(
  identity: Identity,
  agentId: string,
  result: AuditEvent["result"],
  detail: string,
): AuditEvent {
  return {
    ts: nowIso(),
    actor: identity.actor,
    agentId,
    op: "read",
    memoryId: null,
    namespace: identity.namespace,
    purpose: MANIFEST_PURPOSE,
    result,
    detail: detail.slice(0, 500),
  };
}

/** Durable error audit with the same direct-append fallback syscalls use. */
async function auditManifestError(
  deps: SyscallDeps,
  identity: Identity,
  agentId: string,
  err: unknown,
): Promise<void> {
  const message = err instanceof Error ? err.message : String(err);
  const event = manifestEvent(identity, agentId, "error", message);
  try {
    await deps.audit.append(event);
  } catch (firstAuditError) {
    try {
      await appendAuditEvent(deps.db, event);
    } catch (fallbackAuditError) {
      throw new AggregateError(
        [err, firstAuditError, fallbackAuditError],
        `${message}; audit persistence failed`,
      );
    }
  }
}

/** Denial errors are audited as 'denied' here — never re-audit as 'error'. */
function isDenialError(err: unknown): boolean {
  return (
    err instanceof AuthzError ||
    err instanceof RateLimitError ||
    err instanceof TenantSuspendedError
  );
}

/**
 * Per-syscall gate, matching src/syscalls/index.ts gate(): credential-active
 * re-check, tenant suspend, then the caller's token bucket at the MIN of the
 * namespace limit and the tenant cap. Every denial writes an audit row (D4)
 * before the typed error is thrown.
 */
async function gateManifest(
  deps: SyscallDeps,
  identity: Identity,
  agentId: string,
): Promise<void> {
  if (!(await deps.isCredentialActive(identity))) {
    const detail = "credential revoked or inactive";
    await deps.audit.append(manifestEvent(identity, agentId, "denied", detail));
    throw new AuthzError(detail);
  }

  const tenant = await deps.resolveTenant(identity.namespace);
  try {
    tenantGate(tenant);
  } catch (err) {
    if (err instanceof TenantSuspendedError) {
      await deps.audit.append(
        manifestEvent(identity, agentId, "denied", err.message),
      );
    }
    throw err;
  }

  const policy = await deps.getPolicy(identity.namespace);
  const namespaceLimit = policy.rateLimitPerMin ?? DEFAULT_RATE_LIMIT_PER_MIN;
  const limit = effectiveRateLimit(namespaceLimit, tenant) ?? namespaceLimit;
  const denyRate = async (retryAfterSec?: number): Promise<never> => {
    await deps.audit.append(
      manifestEvent(
        identity,
        agentId,
        "denied",
        `rate limit exceeded (${limit}/min)`,
      ),
    );
    throw new RateLimitError(
      `rate limit exceeded (${limit} requests/min for this key)`,
      retryAfterSec,
    );
  };
  // Same durable bucket as the syscall gate, so the manifest lane shares one
  // per-credential window and can report retry-after on denial.
  const consume = deps.rateLimiter.consume?.bind(deps.rateLimiter);
  if (consume) {
    const outcome = await consume(`syscall:${identity.keyId}`, limit, 60_000);
    if (!outcome.allowed) await denyRate(outcome.retryAfterSec);
  } else if (!(await deps.rateLimiter.allow(identity.keyId, limit))) {
    await denyRate();
  }
}

// ---------------------------------------------------------------------------
// The syscall
// ---------------------------------------------------------------------------

/**
 * mem_manifest — audited, ACL-scoped read syscall behind GET /v1/mem/manifest.
 *
 * All roles may call it (it is a read, like mem_read/mem_search). Namespace,
 * actor, and source-access subject come ONLY from the resolved Identity (D9).
 */
export async function memManifest(
  deps: SyscallDeps,
  args: MemManifestArgs,
  identity: Identity,
  agentId: string,
): Promise<ManifestResult> {
  return deps.metrics.time("manifest", async () => {
    const namespace = identity.namespace;
    const variant: ManifestVariant = args.variant ?? "index";
    const maxBytes = Math.min(
      Math.max(args.maxBytes ?? DEFAULT_MANIFEST_MAX_BYTES, MIN_MAX_BYTES),
      MAX_MAX_BYTES,
    );
    try {
      await gateManifest(deps, identity, agentId);

      // The single central visibility boundary (E13): namespace ancestry,
      // exact active mounts, source-native ACL, classification, lifecycle,
      // and TTL are all applied inside MemoryIndex — the same fence every
      // delegated read uses. Rows come back newest-first (assertion_time
      // DESC, id DESC), which is the manifest's render order.
      const visible = await deps.index.listCandidates(namespace, {
        validOnly: true,
        limit: ALL_ROWS,
        includePointers: false,
        access: sourceAccessSubject(identity),
      });
      const rows = visible.filter(isManifestRow);

      const generatedAt = nowIso();
      const { markdown, renderedCount, truncated } = renderManifestMarkdown(
        namespace,
        rows,
        variant,
        maxBytes,
        generatedAt,
      );
      const sources = sourceFreshness(rows);
      const bytes = bytesOf(markdown);

      await deps.audit.append(
        manifestEvent(
          identity,
          agentId,
          "ok",
          `manifest variant=${variant} entries=${rows.length} ` +
            `rendered=${renderedCount} sources=${sources.length} ` +
            `bytes=${bytes} truncated=${truncated}`,
        ),
      );

      return {
        namespace,
        variant,
        generatedAt,
        entryCount: rows.length,
        renderedCount,
        sources,
        truncated,
        bytes,
        markdown,
      };
    } catch (err) {
      if (!isDenialError(err)) {
        await auditManifestError(deps, identity, agentId, err);
      }
      throw err;
    }
  });
}
