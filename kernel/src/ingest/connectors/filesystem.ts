/**
 * Module C — FilesystemConnector: a credential-free connector over a local
 * directory tree. Each `.md`/`.txt` file is one raw-document doc
 * (`verbatim:false` so the write path's extractor runs); frontmatter is
 * stripped with gray-matter so YAML metadata never leaks into the fact text.
 *
 * `.csv` files take a different path: a CSV row is already an atomic,
 * structured fact (same reasoning as PostgresConnector's `verbatim:true`
 * table docs) — it does not need LLM extraction, which was producing one
 * whole-file blob fact per CSV (and, with a real LLM, 15s+ extraction
 * timeouts on ~100-row files). Each row becomes one small verbatim fact; a
 * few recognized tables (customers, inventory, order_items, employee_shifts,
 * campaign_performance) also get 1-3 deterministic aggregate facts (top
 * customers, low stock, best sellers, ...) computed in csv.ts — no ranking
 * question can be answered from scattered per-row facts alone.
 *
 * D10: imports ONLY ../../types.js + node:fs/path + gray-matter + ./csv.js
 * (and, via framework.ts, node:crypto). No src/index, src/db, src/audit,
 * src/write.
 */

import { readdir, readFile } from "node:fs/promises";
import {
  join,
  relative,
  resolve,
  isAbsolute,
  sep,
  extname,
  basename,
} from "node:path";
import type {
  ConnectorContext,
  EnterpriseConnector,
  LiveDoc,
  LiveQueryContext,
  SyncResult,
} from "../../types.js";
import { parseMarkdownMatter } from "../../markdown-frontmatter.js";
import {
  SourceUnavailableError,
  syncWithDrift,
  type EnumeratedDoc,
} from "./framework.js";
import { aggregateFacts, parseCsv, rowKey, rowToFact } from "./csv.js";

const DEFAULT_EXTS = [".md", ".txt"];

interface FilesystemConfig {
  path: string;
  exts?: string[];
}

/**
 * Reads `config.path` off a connector context, validating it structurally so a
 * misconfigured source fails loud rather than walking `undefined`.
 */
function readConfig(config: Record<string, unknown>): FilesystemConfig {
  const path = config.path;
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("FilesystemConnector: config.path must be a non-empty string");
  }
  const rawExts = config.exts;
  const exts =
    Array.isArray(rawExts) && rawExts.every((e) => typeof e === "string")
      ? (rawExts as string[])
      : DEFAULT_EXTS;
  return { path, exts };
}

/** Recursively collect absolute file paths under `dir`. */
async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walk(full)));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

export class FilesystemConnector implements EnterpriseConnector {
  readonly kind = "filesystem" as const;
  readonly version = "halomem-connector/v1" as const;

  capabilities() {
    return {
      incremental: false,
      liveQuery: true,
      sourceAcl: false,
      webhook: false,
      oauth: false,
    };
  }

  async validateConfig(config: Record<string, unknown>): Promise<void> {
    readConfig(config);
  }

  async testConnection(config: Record<string, unknown>): Promise<{ ok: boolean; detail?: string }> {
    try {
      const { path } = readConfig(config);
      await readdir(path);
      return { ok: true };
    } catch {
      return { ok: false, detail: "filesystem-unreachable" };
    }
  }

  /**
   * Optional connection config for the live-query path (D12: import and
   * live-query share the connector's config). The default keeps
   * `new FilesystemConnector()` (registry, sync path) working unchanged.
   */
  constructor(private readonly config: Record<string, unknown> = {}) {}

  /** Offline connector — always available. */
  available(): boolean {
    return true;
  }

  /**
   * D12 live query: grep-style, case-insensitive term scan under the pointer's
   * sourceRef (a directory relative to the connection root). The resolved scan
   * root MUST stay inside `config.path` — traversal escapes are rejected before
   * any fs call. Read-only by construction: the only fs calls on this path are
   * readdir/readFile. One retry on fs failure, then SourceUnavailableError.
   */
  async liveQuery(ctx: LiveQueryContext): Promise<LiveDoc[]> {
    const { path: root, exts } = readConfig(this.config);
    const allowed = new Set((exts ?? DEFAULT_EXTS).map((e) => e.toLowerCase()));

    // Fence the pointer's sourceRef inside the configured root. sourceRef is
    // attacker-adjacent input (it rides in a fact row): absolute paths and
    // '..' escapes are rejected outright, before any fs call.
    const rootAbs = resolve(root);
    const ref = ctx.pointer.sourceRef;
    if (isAbsolute(ref)) {
      throw new Error(
        "FilesystemConnector.liveQuery: pointer sourceRef must be relative to the source root",
      );
    }
    const scanRoot = resolve(rootAbs, ref);
    const rel = relative(rootAbs, scanRoot);
    if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new Error(
        "FilesystemConnector.liveQuery: pointer sourceRef escapes the source root",
      );
    }

    const terms = ctx.query
      .split(/\s+/)
      .filter((t) => t.length > 0)
      .map((t) => t.toLowerCase());
    if (terms.length === 0) return [];
    const limit = Math.max(1, Math.floor(ctx.limit));

    let lastCause = "unknown failure";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const files = await walk(scanRoot);
        const docs: LiveDoc[] = [];
        for (const file of files) {
          if (docs.length >= limit) break;
          if (!allowed.has(extname(file).toLowerCase())) continue;
          const raw = await readFile(file, "utf8");
          const relPath = relative(rootAbs, file).split(sep).join("/");
          // Same frontmatter strip as enumerate: match and surface the body
          // only, never YAML metadata.
          const content = parseMarkdownMatter(raw, relPath).content;
          const haystack = content.toLowerCase();
          if (!terms.some((t) => haystack.includes(t))) continue;
          docs.push({
            docId: relPath,
            content,
            sourceRef: ctx.pointer.sourceRef,
            fetchedAt: new Date().toISOString(),
          });
        }
        return docs;
      } catch (err) {
        lastCause = err instanceof Error ? err.message : String(err);
      }
    }
    throw new SourceUnavailableError(ctx.credential.connectorId, lastCause);
  }

  async sync(ctx: ConnectorContext): Promise<SyncResult> {
    const { path: root, exts } = readConfig(ctx.config);
    const allowed = new Set((exts ?? DEFAULT_EXTS).map((e) => e.toLowerCase()));

    const enumerate = async (): Promise<EnumeratedDoc[]> => {
      const files = await walk(root);
      const docs: EnumeratedDoc[] = [];
      for (const file of files) {
        const ext = extname(file).toLowerCase();
        if (!allowed.has(ext)) continue;
        const raw = await readFile(file, "utf8");
        // docId root is the path relative to the source root, normalized to
        // POSIX separators so the drift key is stable across platforms.
        const relPath = relative(root, file).split(sep).join("/");

        if (ext === ".csv") {
          const table = parseCsv(raw);
          table.rows.forEach((row, index) => {
            docs.push({
              docId: `${relPath}#${rowKey(table.header, row, index)}`,
              content: rowToFact(row),
              verbatim: true,
              scope: "org",
            });
          });
          const aggregates = aggregateFacts(basename(file, ext), table);
          aggregates.forEach((content, index) => {
            docs.push({
              docId: `${relPath}#aggregate:${index}`,
              content,
              verbatim: true,
              scope: "org",
            });
          });
          continue;
        }

        // Strip YAML frontmatter; the fact text is the document body only.
        const content = parseMarkdownMatter(raw, relPath).content;
        docs.push({ docId: relPath, content, verbatim: false, scope: "org" });
      }
      return docs;
    };

    return syncWithDrift(ctx, enumerate);
  }
}
