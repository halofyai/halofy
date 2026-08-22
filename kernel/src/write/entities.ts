/**
 * Module E — entity registry resolution.
 *
 * Resolution order for a mention within a namespace:
 *   (a) exact / alias match (case-insensitive) in entity_registry
 *   (b) embedding cosine >= 0.85 against existing canonical names
 *       → treat as the same entity; add the mention as an alias
 *   (c) cosine in [0.6, 0.85) → LLM tiebreak against the single nearest
 *       candidate (StubLlm deterministically answers {"same": false})
 *   (d) otherwise create a new record (ulid, canonicalName = mention)
 */

import { ulid } from "ulid";
import type { Embedder, EntityRecord, LlmClient, Namespace } from "../types.js";
import { ENTITY_SYSTEM, buildEntityPrompt, parseLooseJson } from "../llm/index.js";
import { namespaceAncestors } from "../index/index.js";
import { writeFenceNamespaces } from "../erasure-fence.js";

/**
 * Minimal structural view of the module-A Db handle (module A does not exist
 * yet; PGlite and pg pool wrappers both satisfy this shape).
 */
export interface DbLike {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[] }>;
}

/** pgvector literal binding — pass vectors as the string '[v1,v2,...]'. */
export function toVectorLiteral(vec: number[]): string {
  return `[${vec.join(",")}]`;
}

const ALIAS_COSINE_THRESHOLD = 0.85;
const TIEBREAK_COSINE_FLOOR = 0.6;

interface EntityRow {
  id: string;
  canonical_name: string;
  aliases: unknown;
  created_at: string | Date;
}

interface NearestRow extends EntityRow {
  cos: number | string | null;
}

/**
 * Read/external-work result consumed by {@link EntityRegistry.resolvePrepared}.
 * Embedding and any LLM tiebreak happen before the caller opens its database
 * transaction; the prepared result performs only registry/fence SQL inside it.
 */
export interface PreparedEntityResolution {
  namespace: Namespace;
  mention: string;
  /** Null only when prepare found an exact match (no embedding was needed). */
  embedding: number[] | null;
  tiebreakCandidateId: string | null;
  tiebreakSame: boolean | null;
}

export class EntityResolutionConflictError extends Error {
  constructor(mention: string) {
    super(`entity resolution changed while writing: ${mention}`);
    this.name = "EntityResolutionConflictError";
  }
}

function parseAliases(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((a): a is string => typeof a === "string");
  if (typeof raw === "string") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.filter((a): a is string => typeof a === "string");
      }
    } catch {
      /* fall through */
    }
  }
  return [];
}

function toIso(ts: string | Date): string {
  return ts instanceof Date ? ts.toISOString() : ts;
}

/**
 * M2 integrator wiring — read-only, ACL-scoped entity listing for the
 * ScopedView (module A's `ViewEntitiesLike`). EntityRegistry itself has no
 * read surface and `src/driver` deliberately contains zero SQL, so the
 * kernel builds the reader here: entities visible to `namespace` are those
 * in the namespace itself or any '/'-split prefix ancestor (same rule as
 * MemoryIndex). Aliases arrive as JSONB (array) from PGlite or a JSON string
 * from pg — `parseAliases` handles both.
 */
export function makeEntitiesReader(db: DbLike): {
  listEntities(
    namespace: Namespace,
  ): Promise<{ canonicalName: string; aliases: string[] }[]>;
} {
  return {
    async listEntities(namespace: Namespace) {
      const allowed = namespaceAncestors(namespace);
      const placeholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
      const res = await db.query<{ canonical_name: string; aliases: unknown }>(
        `SELECT canonical_name, aliases FROM entity_registry
         WHERE namespace IN (${placeholders})`,
        [...allowed],
      );
      return res.rows.map((r) => ({
        canonicalName: r.canonical_name,
        aliases: parseAliases(r.aliases),
      }));
    },
  };
}

export class EntityRegistry {
  constructor(
    private readonly db: DbLike,
    private readonly embedder: Embedder,
    private readonly llm: LlmClient,
  ) {}

  async resolve(namespace: Namespace, mention: string): Promise<EntityRecord> {
    return this.resolvePrepared(await this.prepare(namespace, mention));
  }

  /**
   * Perform reads, embedding, and an optional LLM tiebreak without mutation.
   * WritePath invokes this before opening its memory/audit transaction so an
   * embedder cost ledger cannot attempt a nested write on the long-lived DB.
   */
  async prepare(namespace: Namespace, mention: string): Promise<PreparedEntityResolution> {
    const name = mention.trim();
    const lower = name.toLowerCase();

    const existing = await this.db.query<EntityRow>(
      `SELECT id, canonical_name, aliases, created_at
       FROM entity_registry WHERE namespace = $1`,
      [namespace],
    );
    for (const row of existing.rows) {
      const aliases = parseAliases(row.aliases);
      if (
        row.canonical_name.toLowerCase() === lower ||
        aliases.some((a) => a.toLowerCase() === lower)
      ) {
        return {
          namespace,
          mention: name,
          embedding: null,
          tiebreakCandidateId: null,
          tiebreakSame: null,
        };
      }
    }

    const [vec] = await this.embedder.embed([name]);
    const literal = toVectorLiteral(vec ?? []);

    const nearest = await this.db.query<NearestRow>(
      `SELECT id, canonical_name, aliases, created_at,
              1 - (embedding <=> $1::vector) AS cos
       FROM entity_registry
       WHERE namespace = $2 AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector
       LIMIT 1`,
      [literal, namespace],
    );
    const top = nearest.rows[0];
    const cos = Number(top?.cos ?? 0);
    let tiebreakSame: boolean | null = null;
    if (top && cos >= TIEBREAK_COSINE_FLOOR && cos < ALIAS_COSINE_THRESHOLD) {
      const raw = await this.llm.complete(
        ENTITY_SYSTEM,
        buildEntityPrompt(top.canonical_name, name),
      );
      const parsed = parseLooseJson(raw);
      tiebreakSame =
        parsed !== null &&
        typeof parsed === "object" &&
        (parsed as { same?: unknown }).same === true;
    }

    return {
      namespace,
      mention: name,
      embedding: vec ?? [],
      tiebreakCandidateId:
        top && cos >= TIEBREAK_COSINE_FLOOR && cos < ALIAS_COSINE_THRESHOLD
          ? top.id
          : null,
      tiebreakSame,
    };
  }

  /** Apply a prepared decision using only this registry's database handle. */
  async resolvePrepared(prepared: PreparedEntityResolution): Promise<EntityRecord> {
    const { namespace, mention: name } = prepared;
    const lower = name.toLowerCase();

    // Re-check exact matches inside the transaction. This also safely absorbs
    // a concurrent creator that committed after prepare().
    const existing = await this.db.query<EntityRow>(
      `SELECT id, canonical_name, aliases, created_at
       FROM entity_registry WHERE namespace = $1`,
      [namespace],
    );
    for (const row of existing.rows) {
      const aliases = parseAliases(row.aliases);
      if (
        row.canonical_name.toLowerCase() === lower ||
        aliases.some((a) => a.toLowerCase() === lower)
      ) {
        return {
          id: row.id,
          namespace,
          canonicalName: row.canonical_name,
          aliases,
          createdAt: toIso(row.created_at),
        };
      }
    }

    // prepare() skipped embedding only because it saw an exact row. If that
    // row vanished under an erasure before this transaction, fail closed and
    // let the caller retry from a fresh preparation rather than guessing.
    if (!prepared.embedding) throw new EntityResolutionConflictError(name);
    const literal = toVectorLiteral(prepared.embedding);
    const nearest = await this.db.query<NearestRow>(
      `SELECT id, canonical_name, aliases, created_at,
              1 - (embedding <=> $1::vector) AS cos
       FROM entity_registry
       WHERE namespace = $2 AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector
       LIMIT 1`,
      [literal, namespace],
    );
    const top = nearest.rows[0];
    if (top) {
      const cos = Number(top.cos ?? 0);
      if (cos >= ALIAS_COSINE_THRESHOLD) {
        return this.addAlias(top, namespace, name);
      }
      if (cos >= TIEBREAK_COSINE_FLOOR) {
        if (
          prepared.tiebreakCandidateId === top.id &&
          prepared.tiebreakSame === true
        ) {
          return this.addAlias(top, namespace, name);
        }
        // Commit-time state is authoritative. When the tiebreak band's
        // nearest neighbor is not the one prepare() judged (a concurrent
        // writer drifted the registry during the embed/LLM window), the fact
        // must NOT fail for alias uncertainty: land the mention as its own
        // record - exactly what an LLM "different" verdict produces - and
        // let consolidation merge the pair later. Failing here made
        // concurrent multi-file ingestion a retry lottery: every unrelated
        // entity commit in the namespace re-rolled the conflict, and
        // bounded re-preparation could not converge while a sibling lane
        // kept writing (production 2026-08-20, "UPS"/"Rose" exhausting all
        // retries). A drifted-in neighbor at or above the alias threshold
        // is still merged by the branch above; the fail-closed
        // EntityResolutionConflictError remains only for the vanished
        // exact-match case, which a fresh preparation genuinely resolves.
      }
    }

    // (d) new record.
    const record: EntityRecord = {
      id: ulid(),
      namespace,
      canonicalName: name,
      aliases: [],
      createdAt: new Date().toISOString(),
    };
    const fences = writeFenceNamespaces(namespace);
    const fenceTimeParam = 7 + fences.length;
    const fenceValues = fences.map((_, i) => `($${7 + i}, 1, $${fenceTimeParam})`).join(", ");
    await this.db.query(
      `WITH fence AS (
         INSERT INTO erasure_fences (namespace, generation, updated_at)
         VALUES ${fenceValues}
         ON CONFLICT (namespace) DO UPDATE SET
           generation = erasure_fences.generation + 1,
           updated_at = EXCLUDED.updated_at
         RETURNING namespace
       )
       INSERT INTO entity_registry (id, namespace, canonical_name, aliases, embedding, created_at)
       SELECT $1, $2, $3, $4, $5::vector, $6
         FROM (SELECT count(*) FROM fence) AS fence_lock`,
      [
        record.id,
        namespace,
        record.canonicalName,
        JSON.stringify(record.aliases),
        literal,
        record.createdAt,
        ...fences,
        new Date().toISOString(),
      ],
    );
    return record;
  }

  private async addAlias(
    row: EntityRow,
    namespace: Namespace,
    alias: string,
  ): Promise<EntityRecord> {
    const aliases = parseAliases(row.aliases);
    const lower = alias.toLowerCase();
    if (
      row.canonical_name.toLowerCase() !== lower &&
      !aliases.some((a) => a.toLowerCase() === lower)
    ) {
      aliases.push(alias);
      const fences = writeFenceNamespaces(namespace);
      const fenceTimeParam = 3 + fences.length;
      const fenceValues = fences.map((_, i) => `($${3 + i}, 1, $${fenceTimeParam})`).join(", ");
      await this.db.query(
        `WITH fence AS (
           INSERT INTO erasure_fences (namespace, generation, updated_at)
           VALUES ${fenceValues}
           ON CONFLICT (namespace) DO UPDATE SET
             generation = erasure_fences.generation + 1,
             updated_at = EXCLUDED.updated_at
           RETURNING namespace
         )
         UPDATE entity_registry
            SET aliases = $1
           FROM (SELECT count(*) FROM fence) AS fence_lock
          WHERE id = $2`,
        [JSON.stringify(aliases), row.id, ...fences, new Date().toISOString()],
      );
    }
    return {
      id: row.id,
      namespace,
      canonicalName: row.canonical_name,
      aliases,
      createdAt: toIso(row.created_at),
    };
  }
}
