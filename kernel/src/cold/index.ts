/**
 * Module B — L3 cold store.
 *
 * Reads OKF markdown concepts (YAML frontmatter via gray-matter) from a git
 * knowledge directory, syncs summaries + embeddings into the `concepts`
 * table, and serves hybrid (vector + keyword) search over them.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import matter from "gray-matter";
import type { Concept, Embedder, Namespace, ScoredRef } from "../types.js";
import { estimateTokens } from "../types.js";
import { parseMarkdownMatter } from "../markdown-frontmatter.js";
import { namespaceAncestors } from "../index/index.js";
import { normalizePiiSubjects } from "../pii.js";
import { acquireErasureFence, writeFenceNamespaces } from "../erasure-fence.js";

/** Minimal DB handle shape (matches src/db/client.ts `Db.query`). */
export interface ColdDb {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[] }>;
}

export interface TransactionalColdDb extends ColdDb {
  transaction<T>(fn: (tx: TransactionalColdDb) => Promise<T>): Promise<T>;
}

interface EncryptedBlobV2 {
  version: 2;
  alg: "A256GCM";
  iv: string;
  tag: string;
  ciphertext: string;
}

interface WrappedDekRow {
  wrapped_dek: unknown;
  wrap_iv: unknown;
  wrap_tag: unknown;
  namespace: unknown;
  pii_subjects: unknown;
  kek_id: unknown;
  envelope_version: unknown;
  write_state: unknown;
  kek_generation: unknown;
}

interface ActiveKekState {
  id: string;
  generation: number;
}

const ENVELOPE_VERSION = 2;

/** Max characters of body fed into the embedding input. */
const EMBED_BODY_CHARS = 2000;

/** Weights for the hybrid score merge. */
const VECTOR_WEIGHT = 0.6;
const KEYWORD_WEIGHT = 0.4;

function toPosix(p: string): string {
  return p.split(path.sep).join("/").replace(/\\/g, "/");
}

function asString(v: unknown): string {
  if (v == null) return "";
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

function asStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => asString(x)).filter((x) => x.length > 0);
  if (typeof v === "string" && v.length > 0) return [v];
  return [];
}

function vectorLiteral(vec: number[]): string {
  return `[${vec.join(",")}]`;
}

/** Parse one markdown file into a concept with exactly one ownership mode. */
function parseConcept(relPath: string, raw: string): Concept {
  const parsed = parseMarkdownMatter(raw, relPath);
  const fm = parsed.data as Record<string, unknown>;
  const type = asString(fm["type"]).trim();
  if (!type) throw new Error('missing required frontmatter field "type"');
  const namespace = asString(fm["namespace"]).trim();
  const visibility = asString(fm["visibility"]).trim();
  if ((namespace.length > 0) === (visibility.length > 0)) {
    throw new Error(
      'declare exactly one ownership field: non-empty "namespace" or "visibility: public"',
    );
  }
  if (visibility.length > 0 && visibility !== "public") {
    throw new Error('frontmatter "visibility" must be "public"');
  }
  if (namespace.length > 0 && !isCanonicalNamespace(namespace)) {
    throw new Error(`invalid concept namespace "${namespace}"`);
  }
  const hasPiiSubjects = Object.prototype.hasOwnProperty.call(fm, "pii_subjects");
  if (visibility === "public" && hasPiiSubjects) {
    throw new Error('public concepts may not declare "pii_subjects"');
  }
  const piiSubjects = normalizePiiSubjects(asStringArray(fm["pii_subjects"]));
  const fileBase = relPath.replace(/\.md$/i, "").split("/").pop() ?? relPath;
  const base = {
    path: relPath,
    type,
    title: asString(fm["title"]).trim() || fileBase,
    description: asString(fm["description"]).trim(),
    tags: asStringArray(fm["tags"]),
    body: parsed.content.trim(),
  };
  const concept: Concept = namespace
    ? { ...base, namespace, ...(piiSubjects.length > 0 ? { piiSubjects } : {}) }
    : { ...base, visibility: "public" };
  const owner = asString(fm["owner"]).trim();
  if (owner) concept.owner = owner;
  const verifiedAgainst = asString(fm["verified_against"]).trim();
  if (verifiedAgainst) concept.verifiedAgainst = verifiedAgainst;
  const verifiedAt = asString(fm["verified_at"]).trim();
  if (verifiedAt) concept.verifiedAt = verifiedAt;
  return concept;
}

export class ColdStore {
  private readonly knowledgeDir: string;
  private readonly kek: Buffer | null;
  private readonly kekId: string | null;
  private db: ColdDb | null = null;
  private quarantinedPaths = new Set<string>();
  /** Warnings collected by the most recent scoped list or sync scan. */
  public warnings: string[] = [];
  private mountedConceptPaths?: (namespace: Namespace) => Promise<string[]>;

  constructor(knowledgeDir: string, coldKek = "") {
    this.knowledgeDir = knowledgeDir;
    this.kek = decodeKek(coldKek);
    this.kekId = this.kek === null
      ? null
      : createHash("sha256").update(this.kek).digest("hex");
    if (coldKek && this.kek === null) {
      this.warnings.push("HALOMEM_COLD_KEK must be canonical base64 for exactly 32 bytes");
    }
  }

  /** Kernel-owned explicit-mount resolver; never exposed to drivers. */
  setMountedConceptResolver(resolve: (namespace: Namespace) => Promise<string[]>): void {
    this.mountedConceptPaths = resolve;
  }

  private async mounted(namespace: Namespace): Promise<string[]> {
    return this.mountedConceptPaths ? this.mountedConceptPaths(namespace) : [];
  }

  /** Reject a missing/mismatched configured KEK before serving encrypted data. */
  async validateBootConfiguration(db: ColdDb): Promise<void> {
    const encrypted = (await this.walk(this.knowledgeDir))
      .map((abs) => toPosix(path.relative(this.knowledgeDir, abs)))
      .filter((rel) => rel.toLowerCase().endsWith(".okf.enc"));
    if (encrypted.length === 0) return;
    if (this.kek === null || this.kekId === null) {
      throw new Error("HALOMEM_COLD_KEK must be valid when encrypted concepts exist");
    }
    const { rows } = await db.query(
      "SELECT path, kek_id FROM cold_concept_keys WHERE kek_id IS NOT NULL",
    );
    const encryptedSet = new Set(encrypted);
    for (const row of rows as Record<string, unknown>[]) {
      if (encryptedSet.has(asString(row["path"])) && asString(row["kek_id"]) !== this.kekId) {
        throw new Error(`HALOMEM_COLD_KEK does not match encrypted concept ${asString(row["path"])}`);
      }
    }
    await this.ensureActiveKek(db);
  }

  /** Transactionally rewrap every committed DEK for a KEK rotation. */
  static async rotateKek(
    db: TransactionalColdDb,
    oldKekBase64: string,
    newKekBase64: string,
  ): Promise<number> {
    const oldKek = decodeKek(oldKekBase64);
    const newKek = decodeKek(newKekBase64);
    if (oldKek === null || newKek === null) throw new Error("old and new KEKs must be canonical 32-byte base64");
    const oldId = createHash("sha256").update(oldKek).digest("hex");
    const newId = createHash("sha256").update(newKek).digest("hex");
    return db.transaction(async (tx) => {
      // Rotation is globally fenced: all governed L2/L3/entity writes acquire
      // the root fence, so no key can appear or change during the rewrap set.
      await acquireErasureFence(tx, "");
      await tx.query(
        `INSERT INTO cold_kek_state
           (singleton, active_kek_id, generation, maintenance, updated_at)
         VALUES (TRUE, $1, 1, FALSE, $2)
         ON CONFLICT (singleton) DO NOTHING`,
        [oldId, new Date().toISOString()],
      );
      const stateRows = await tx.query(
        `SELECT active_kek_id, generation, maintenance
           FROM cold_kek_state WHERE singleton = TRUE`,
      );
      const state = stateRows.rows[0] as Record<string, unknown> | undefined;
      if (
        !state ||
        asString(state["active_kek_id"]) !== oldId ||
        state["maintenance"] === true ||
        asString(state["maintenance"]) === "true"
      ) {
        throw new Error("supplied old KEK is not the active generation");
      }
      const generation = Number(state["generation"]);
      const pending = await tx.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE write_state = 'pending'",
      );
      if (Number(pending.rows[0]?.n ?? 0) > 0) {
        throw new Error("KEK rotation requires zero pending cold writes");
      }
      await tx.query(
        `UPDATE cold_concept_keys SET kek_generation = $1
          WHERE write_state = 'committed' AND kek_id = $2 AND kek_generation IS NULL`,
        [generation, oldId],
      );
      const { rows } = await tx.query(
        `SELECT path, namespace, wrapped_dek, wrap_iv, wrap_tag, kek_id,
                envelope_version, kek_generation
           FROM cold_concept_keys WHERE write_state = 'committed' ORDER BY path`,
      );
      const nextGeneration = generation + 1;
      for (const row of rows as Record<string, unknown>[]) {
        const rel = asString(row["path"]);
        const namespace = asString(row["namespace"]);
        if (
          asString(row["kek_id"]) !== oldId ||
          Number(row["kek_generation"]) !== generation ||
          Number(row["envelope_version"]) !== ENVELOPE_VERSION ||
          !isCanonicalNamespace(namespace)
        ) {
          throw new Error(`cold key ${rel} is not owned by the supplied old KEK`);
        }
        const aad = conceptAad(rel, namespace);
        const dek = decryptAesGcm(
          asString(row["wrapped_dek"]),
          asString(row["wrap_iv"]),
          asString(row["wrap_tag"]),
          oldKek,
          dekAad(aad),
        );
        const wrapped = encryptAesGcm(dek, newKek, dekAad(aad));
        await tx.query(
          `UPDATE cold_concept_keys
              SET wrapped_dek = $2, wrap_iv = $3, wrap_tag = $4,
                  kek_id = $5, kek_generation = $6
            WHERE path = $1 AND write_state = 'committed'`,
          [rel, wrapped.ciphertext, wrapped.iv, wrapped.tag, newId, nextGeneration],
        );
      }
      await tx.query(
        `UPDATE cold_kek_state
            SET active_kek_id = $1, generation = $2, updated_at = $3
          WHERE singleton = TRUE AND active_kek_id = $4 AND generation = $5`,
        [newId, nextGeneration, new Date().toISOString(), oldId, generation],
      );
      return rows.length;
    });
  }

  /** Promote a recoverable pending key while holding its ancestor fences. */
  private async promotePendingKey(
    db: ColdDb,
    rel: string,
    namespace: Namespace,
  ): Promise<boolean> {
    const snapshot = await this.snapshotFenceGenerations(db, namespace);
    const expectedStart = 3;
    const expectedValues = snapshot
      .map((_, i) => `($${expectedStart + i * 2}, $${expectedStart + i * 2 + 1}::bigint)`)
      .join(", ");
    const fenceTimeParam = expectedStart + snapshot.length * 2;
    const result = await db.query(
      `WITH expected(namespace, generation) AS (VALUES ${expectedValues}),
       fence AS (
         UPDATE erasure_fences current
            SET generation = current.generation + 1,
                updated_at = $${fenceTimeParam}
           FROM expected
          WHERE current.namespace = expected.namespace
            AND current.generation = expected.generation
         RETURNING current.namespace
       )
       UPDATE cold_concept_keys
          SET write_state = 'committed'
         FROM (SELECT count(*) AS n FROM fence) AS fence_lock
        WHERE path = $1
          AND write_state = 'pending'
          AND fence_lock.n = ${snapshot.length}
          AND NOT EXISTS (SELECT 1 FROM tombstones WHERE memory_id = $2)
          AND EXISTS (
            SELECT 1 FROM cold_kek_state active
             WHERE active.singleton = TRUE
               AND active.maintenance = FALSE
               AND active.active_kek_id = cold_concept_keys.kek_id
               AND active.generation = cold_concept_keys.kek_generation
          )
       RETURNING path`,
      [
        rel,
        `l3:${rel}`,
        ...snapshot.flatMap((entry) => [entry.namespace, entry.generation]),
        new Date().toISOString(),
      ],
    );
    return result.rows.length === 1;
  }

  private async snapshotFenceGenerations(
    db: ColdDb,
    namespace: Namespace,
  ): Promise<{ namespace: string; generation: number }[]> {
    const fences = writeFenceNamespaces(namespace);
    const values = fences.map((_, i) => `($${i + 1}, 0, $${fences.length + 1})`).join(", ");
    await db.query(
      `INSERT INTO erasure_fences (namespace, generation, updated_at)
       VALUES ${values} ON CONFLICT (namespace) DO NOTHING`,
      [...fences, new Date().toISOString()],
    );
    const placeholders = fences.map((_, i) => `$${i + 1}`).join(", ");
    const { rows } = await db.query(
      `SELECT namespace, generation FROM erasure_fences
        WHERE namespace IN (${placeholders}) ORDER BY namespace`,
      fences,
    );
    return (rows as Record<string, unknown>[]).map((row) => ({
      namespace: asString(row["namespace"]),
      generation: Number(row["generation"]),
    }));
  }

  private async ensureActiveKek(db: ColdDb): Promise<ActiveKekState> {
    if (this.kekId === null) throw new Error("HALOMEM_COLD_KEK is unavailable or invalid");
    await db.query(
      `INSERT INTO cold_kek_state
         (singleton, active_kek_id, generation, maintenance, updated_at)
       VALUES (TRUE, $1, 1, FALSE, $2)
       ON CONFLICT (singleton) DO NOTHING`,
      [this.kekId, new Date().toISOString()],
    );
    const { rows } = await db.query(
      `SELECT active_kek_id, generation, maintenance
         FROM cold_kek_state WHERE singleton = TRUE`,
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    if (
      !row ||
      asString(row["active_kek_id"]) !== this.kekId ||
      row["maintenance"] === true ||
      asString(row["maintenance"]) === "true"
    ) {
      throw new Error("configured cold KEK is not the active writable generation");
    }
    const generation = Number(row["generation"]);
    await db.query(
      `UPDATE cold_concept_keys SET kek_generation = $1
        WHERE kek_id = $2 AND kek_generation IS NULL AND write_state = 'committed'`,
      [generation, this.kekId],
    );
    return { id: this.kekId, generation };
  }

  /** Namespace-scoped concept enumeration; the unscoped repository scan is private. */
  async listConcepts(namespace: Namespace): Promise<Concept[]> {
    const concepts = await this.scanConcepts(this.db);
    const mounted = new Set(await this.mounted(namespace));
    let retiredLogicalPaths = new Set<string>();
    if (this.db !== null) {
      const retired = await this.db.query(
        `SELECT kv.path
           FROM knowledge_versions kv
           JOIN knowledge_concepts kc ON kc.id = kv.concept_id
          WHERE kv.state <> 'published'
             OR kc.status <> 'active'
             OR kc.current_version_id IS DISTINCT FROM kv.id`,
      );
      retiredLogicalPaths = new Set(retired.rows.map((row) => String(row.path)));
    }
    return concepts.filter((concept) =>
      !retiredLogicalPaths.has(concept.path) &&
      (isConceptVisible(concept, namespace) || mounted.has(concept.path)),
    );
  }

  /** Scan public plaintext and private encrypted blobs for projection sync. */
  private async scanConcepts(db: ColdDb | null): Promise<Concept[]> {
    this.warnings = [];
    this.quarantinedPaths = new Set<string>();
    const files = await this.walk(this.knowledgeDir);
    const concepts: Concept[] = [];
    for (const abs of files) {
      const rel = toPosix(path.relative(this.knowledgeDir, abs));
      let raw: string;
      try {
        raw = await fs.readFile(abs, "utf8");
      } catch (err) {
        this.warnings.push(`unreadable concept file ${rel}: ${(err as Error).message}`);
        this.quarantinedPaths.add(rel);
        continue;
      }
      let concept: Concept;
      try {
        if (rel.toLowerCase().endsWith(".okf.enc")) {
          concept = await this.decryptPrivateConcept(db, rel, raw);
        } else {
          concept = parseConcept(rel, raw);
          if (concept.namespace !== undefined) {
            throw new Error("private plaintext concepts are forbidden; write an .okf.enc blob");
          }
          if (concept.visibility !== "public") {
            throw new Error("plaintext concepts must declare visibility: public");
          }
        }
      } catch (err) {
        this.warnings.push(`invalid concept ${rel}: ${(err as Error).message}`);
        this.quarantinedPaths.add(rel);
        continue;
      }
      concepts.push(concept);
    }
    concepts.sort((a, b) => a.path.localeCompare(b.path));
    return concepts;
  }

  /** Read a single concept by repo-relative path; null when absent/invalid. */
  async readConcept(
    namespace: Namespace,
    conceptPath: string,
  ): Promise<Concept | null> {
    const { rel, abs } = await this.resolveConceptPath(conceptPath);
    if (this.db !== null) {
      const ancestors = namespaceAncestors(namespace);
      const mounted = await this.mounted(namespace);
      const ownerParams = ancestors.map((_, i) => `$${i + 2}`).join(", ");
      const mountParams = mounted.map((_, i) => `$${i + ancestors.length + 2}`).join(", ");
      const privateVisibility = [
        ancestors.length > 0 ? `c.namespace IN (${ownerParams})` : "",
        mounted.length > 0 ? `c.path IN (${mountParams})` : "",
      ].filter(Boolean).join(" OR ") || "FALSE";
      const { rows } = await this.db.query(
        `SELECT c.path, c.type, c.title, c.description, c.tags, c.namespace,
                c.visibility, c.pii_subjects, c.owner, c.verified_against,
                c.verified_at, c.body
           FROM concepts c
           LEFT JOIN cold_concept_keys ck ON ck.path = c.path
           LEFT JOIN cold_kek_state ks ON ks.singleton = TRUE
           LEFT JOIN knowledge_versions kv ON kv.path = c.path
           LEFT JOIN knowledge_concepts kc ON kc.id = kv.concept_id
          WHERE c.path = $1
            AND (kv.id IS NULL OR (
              kv.state = 'published' AND kc.status = 'active' AND kc.current_version_id = kv.id
            ))
            AND (
            c.visibility = 'public' OR (
              (${privateVisibility})
              AND ck.write_state = 'committed'
              AND ck.namespace = c.namespace
              AND ck.pii_subjects = c.pii_subjects
              AND ck.kek_id IS NOT NULL
              AND ck.envelope_version = 2
              AND ks.maintenance = FALSE
              AND ks.active_kek_id = ck.kek_id
              AND ks.generation = ck.kek_generation
            )
          )`,
        [rel, ...ancestors, ...mounted],
      );
      return rows.length === 0 ? null : conceptFromRow(rows[0]);
    }
    let raw: string;
    try {
      raw = await fs.readFile(abs, "utf8");
    } catch {
      return null;
    }
    try {
      if (rel.toLowerCase().endsWith(".okf.enc")) return null;
      const concept = parseConcept(rel, raw);
      if (concept.namespace !== undefined) {
        this.warnings.push(`invalid concept ${rel}: private plaintext concepts are forbidden`);
        return null;
      }
      return isConceptVisible(concept, namespace) ? concept : null;
    } catch (err) {
      this.warnings.push(`invalid concept ${rel}: ${(err as Error).message}`);
      return null;
    }
  }

  /**
   * Upsert every concept into the `concepts` table with a fresh embedding
   * (title + description + body, body truncated to ~2000 chars) and
   * synced_at = now. Returns the number of concepts synced.
   */
  async syncToDb(db: ColdDb, embedder: Embedder): Promise<number> {
    this.db = db;
    const concepts = await this.scanConcepts(db);
    // Failed paths are quarantined fail-closed: a stale plaintext/search
    // projection must not survive a key, crypto, or ownership failure.
    for (const failedPath of this.quarantinedPaths) {
      await db.query("DELETE FROM concepts WHERE path = $1", [failedPath]);
    }
    // Only an unreadable directory makes the repository inventory incomplete.
    const scanIncomplete = this.warnings.some((warning) =>
      warning.startsWith("cannot read knowledge dir"),
    );
    if (concepts.length === 0) {
      if (!scanIncomplete) await db.query("DELETE FROM concepts");
      return 0;
    }
    const inputs = concepts.map(
      (c) => `${c.title}\n${c.description}\n${c.body.slice(0, EMBED_BODY_CHARS)}`,
    );
    const embeddings = await embedder.embed(inputs);
    const now = new Date().toISOString();
    for (let i = 0; i < concepts.length; i++) {
      const c = concepts[i];
      await db.query(
        `INSERT INTO concepts
           (path, type, title, description, tags, namespace, visibility, pii_subjects, owner, verified_against, verified_at, body, embedding, synced_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13::vector, $14)
         ON CONFLICT (path) DO UPDATE SET
           type = EXCLUDED.type,
           title = EXCLUDED.title,
           description = EXCLUDED.description,
           tags = EXCLUDED.tags,
           namespace = EXCLUDED.namespace,
           visibility = EXCLUDED.visibility,
           pii_subjects = EXCLUDED.pii_subjects,
           owner = EXCLUDED.owner,
           verified_against = EXCLUDED.verified_against,
           verified_at = EXCLUDED.verified_at,
           body = EXCLUDED.body,
           embedding = EXCLUDED.embedding,
           synced_at = EXCLUDED.synced_at`,
        [
          c.path,
          c.type,
          c.title,
          c.description,
          JSON.stringify(c.tags),
          c.namespace ?? null,
          c.visibility ?? null,
          JSON.stringify(c.piiSubjects ?? []),
          c.owner ?? null,
          c.verifiedAgainst ?? null,
          c.verifiedAt ?? null,
          c.body,
          vectorLiteral(embeddings[i]),
          now,
        ],
      );
    }
    // Remove rows whose markdown files were deleted or renamed so the DB
    // never keeps serving retired L3 knowledge (path is the identity key, so
    // a rename would otherwise leave the old row behind as a duplicate).
    if (!scanIncomplete) {
      const keep = concepts.map((c) => c.path);
      const placeholders = keep.map((_, i) => `$${i + 1}`).join(", ");
      await db.query(
        `DELETE FROM concepts WHERE path NOT IN (${placeholders})`,
        keep,
      );
    }
    return concepts.length;
  }

  /**
   * Hybrid search over the `concepts` table: pgvector cosine distance
   * (embedding <=> $vec) merged with a case-insensitive keyword score over
   * title/description/tags/body. Scores normalized to 0..1.
   */
  async searchConcepts(
    db: ColdDb,
    embedder: Embedder,
    namespace: Namespace,
    query: string,
    k = 8,
  ): Promise<ScoredRef[]> {
    const [queryVec] = await embedder.embed([query]);
    const vecLit = vectorLiteral(queryVec);
    const ancestors = namespaceAncestors(namespace);
    const mounted = await this.mounted(namespace);
    const ownerParams = ancestors.map((_, i) => `$${i + 2}`).join(", ");
    const mountParams = mounted.map((_, i) => `$${i + ancestors.length + 2}`).join(", ");
    const privateVisibility = [
      ancestors.length > 0 ? `c.namespace IN (${ownerParams})` : "",
      mounted.length > 0 ? `c.path IN (${mountParams})` : "",
    ].filter(Boolean).join(" OR ") || "FALSE";
    const { rows } = await db.query(
      `SELECT c.path, c.title, c.description, c.tags, c.body,
              CASE WHEN c.embedding IS NULL THEN NULL
                   ELSE c.embedding <=> $1::vector END AS dist
         FROM concepts c
         LEFT JOIN cold_concept_keys ck ON ck.path = c.path
         LEFT JOIN cold_kek_state ks ON ks.singleton = TRUE
         LEFT JOIN knowledge_versions kv ON kv.path = c.path
         LEFT JOIN knowledge_concepts kc ON kc.id = kv.concept_id
        WHERE (kv.id IS NULL OR (
                kv.state = 'published' AND kc.status = 'active' AND kc.current_version_id = kv.id
              ))
          AND (c.visibility = 'public' OR (
             (${privateVisibility})
             AND ck.write_state = 'committed'
             AND ck.namespace = c.namespace
             AND ck.pii_subjects = c.pii_subjects
             AND ck.kek_id IS NOT NULL
             AND ck.envelope_version = 2
             AND ks.maintenance = FALSE
             AND ks.active_kek_id = ck.kek_id
             AND ks.generation = ck.kek_generation
        ))`,
      [vecLit, ...ancestors, ...mounted],
    );
    if (rows.length === 0) return [];

    const terms = query
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length > 1);

    interface Candidate {
      path: string;
      title: string;
      body: string;
      vecSim: number;
      kwScore: number;
    }

    const candidates: Candidate[] = rows.map((r) => {
      const tags: string[] = Array.isArray(r.tags)
        ? r.tags.map((t: unknown) => String(t))
        : asStringArray(typeof r.tags === "string" ? safeJson(r.tags) : r.tags);
      // Absolute cosine similarity, negative values clamped to 0. This is an
      // ABSOLUTE relevance signal: an unrelated query (orthogonal vectors)
      // scores ~0 here, so the fault handler's L3 floor can actually reject
      // it and the miss path stays reachable.
      const dist = r.dist == null ? 2 : Number(r.dist);
      const vecSim = Math.max(0, Math.min(1, 1 - dist));
      let kw = 0;
      const title = String(r.title ?? "").toLowerCase();
      const description = String(r.description ?? "").toLowerCase();
      const tagText = tags.join(" ").toLowerCase();
      const body = String(r.body ?? "").toLowerCase();
      for (const term of terms) {
        kw += 3 * countOccurrences(title, term);
        kw += 2 * countOccurrences(description, term);
        kw += 2 * countOccurrences(tagText, term);
        kw += 1 * countOccurrences(body, term);
      }
      return {
        path: String(r.path),
        title: String(r.title ?? ""),
        body: String(r.body ?? ""),
        vecSim,
        kwScore: kw,
      };
    });

    const maxKw = Math.max(...candidates.map((c) => c.kwScore), 0);

    const scored: ScoredRef[] = candidates
      .map((c) => {
        // Vector lane is deliberately NOT max-normalized: dividing by the
        // batch max would pin the top candidate at VECTOR_WEIGHT regardless
        // of actual relevance, making a score floor a no-op (mem_fault could
        // never miss once any concept existed). Keyword lane stays relative;
        // it is already 0 when no query term occurs at all.
        const kwNorm = maxKw > 0 ? c.kwScore / maxKw : 0;
        const score = VECTOR_WEIGHT * c.vecSim + KEYWORD_WEIGHT * kwNorm;
        const content = `${c.title}: ${c.body}`;
        return {
          id: null,
          tier: "L3" as const,
          ref: c.path,
          score,
          content,
          tokenEstimate: estimateTokens(content),
        };
      })
      .sort((a, b) => b.score - a.score || a.ref.localeCompare(b.ref))
      .slice(0, Math.max(0, k));

    return scored;
  }

  /**
   * Governed private write: encrypt plaintext with a unique DEK, wrap that DEK
   * with the kernel KEK, persist only wrapped key material in Postgres, and
   * write a versioned ciphertext-only repository blob.
   */
  async writePrivateConcept(db: ColdDb, concept: Concept): Promise<string> {
    if (this.kek === null) throw new Error("HALOMEM_COLD_KEK is unavailable or invalid");
    if (!concept.namespace || concept.visibility === "public") {
      throw new Error("private concept requires a non-empty namespace");
    }
    if (!isCanonicalNamespace(concept.namespace)) {
      throw new Error(`invalid concept namespace "${concept.namespace}"`);
    }
    if (!concept.path.toLowerCase().endsWith(".okf.enc")) {
      throw new Error("private concept path must end in .okf.enc");
    }
    const { rel, abs } = await this.resolveWritePath(concept.path);
    const erased = await db.query(
      "SELECT 1 FROM tombstones WHERE memory_id = $1 LIMIT 1",
      [`l3:${rel}`],
    );
    if (erased.rows.length > 0) {
      throw new Error(`private concept path was permanently erased: ${rel}`);
    }
    const normalized = { ...concept, path: rel } as Concept;
    const normalizedSubjects = normalizePiiSubjects(concept.piiSubjects ?? []);
    if (normalizedSubjects.length > 0) normalized.piiSubjects = normalizedSubjects;
    else delete normalized.piiSubjects;
    const plaintext = Buffer.from(serializePrivateConcept(normalized), "utf8");
    const existingKeys = await db.query(
      `SELECT wrapped_dek, wrap_iv, wrap_tag, namespace, pii_subjects, kek_id,
              envelope_version, write_state, kek_generation
         FROM cold_concept_keys WHERE path = $1`,
      [rel],
    );
    let existingBlob: string | null = null;
    try {
      existingBlob = await fs.readFile(abs, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    if (existingKeys.rows.length > 0 && existingBlob !== null) {
      const existing = await this.decryptPrivateConcept(db, rel, existingBlob, true);
      if (serializePrivateConcept(existing) === plaintext.toString("utf8")) {
        if (asString(existingKeys.rows[0]?.write_state) === "pending") {
          if (!(await this.promotePendingKey(db, rel, concept.namespace))) {
            throw new Error(`pending private concept was erased before commit: ${rel}`);
          }
        }
        this.db = db;
        return rel;
      }
      throw new Error(`private concept path already exists with different content: ${rel}`);
    }
    if (existingKeys.rows.length > 0 && existingBlob === null) {
      if (asString(existingKeys.rows[0]?.write_state) !== "pending") {
        throw new Error(`committed private concept blob is missing: ${rel}`);
      }
      await db.query("DELETE FROM cold_concept_keys WHERE path = $1 AND write_state = 'pending'", [rel]);
    } else if (existingKeys.rows.length === 0 && existingBlob !== null) {
      // A keyless blob is either crypto-shredded or corrupt. Never resurrect it
      // in place, because its stable path is part of the erasure evidence.
      throw new Error(`private concept path contains ciphertext without a key: ${rel}`);
    }

    if (this.kekId === null) throw new Error("HALOMEM_COLD_KEK is unavailable or invalid");
    const activeState = await this.ensureActiveKek(db);
    const fenceSnapshot = await this.snapshotFenceGenerations(db, concept.namespace);
    const aad = conceptAad(rel, concept.namespace);
    const dek = randomBytes(32);
    const encrypted = encryptAesGcm(plaintext, dek, aad);
    const wrapped = encryptAesGcm(dek, this.kek, dekAad(aad));
    const blob: EncryptedBlobV2 = { version: 2, alg: "A256GCM", ...encrypted };

    // Write to a sibling temp file then atomically rename. A DB failure leaves
    // no readable plaintext and no published blob; a rename failure removes
    // the key row so the partial ciphertext cannot become readable later.
    const temp = `${abs}.${randomBytes(8).toString("hex")}.tmp`;
    await fs.writeFile(temp, JSON.stringify(blob), { encoding: "utf8", flag: "wx", mode: 0o600 });
    let keyInserted = false;
    try {
      const expectedStart = 11;
      const expectedValues = fenceSnapshot
        .map((_, i) => `($${expectedStart + i * 2}, $${expectedStart + i * 2 + 1}::bigint)`)
        .join(", ");
      const fenceTimestampParam = expectedStart + fenceSnapshot.length * 2;
      const tombstoneParam = fenceTimestampParam + 1;
      const inserted = await db.query(
        `WITH expected(namespace, generation) AS (VALUES ${expectedValues}),
         fence AS (
           UPDATE erasure_fences current
              SET generation = current.generation + 1,
                  updated_at = $${fenceTimestampParam}
             FROM expected
            WHERE current.namespace = expected.namespace
              AND current.generation = expected.generation
           RETURNING current.namespace
         )
         INSERT INTO cold_concept_keys
           (path, wrapped_dek, wrap_iv, wrap_tag, created_at, namespace,
            pii_subjects, kek_id, envelope_version, write_state, kek_generation)
         SELECT $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, 'pending', $10
           FROM (SELECT count(*) AS n FROM fence) AS fence_lock
          WHERE fence_lock.n = ${fenceSnapshot.length}
            AND NOT EXISTS (SELECT 1 FROM tombstones WHERE memory_id = $${tombstoneParam})
            AND EXISTS (
              SELECT 1 FROM cold_kek_state active
               WHERE active.singleton = TRUE
                 AND active.maintenance = FALSE
                 AND active.active_kek_id = $8
                 AND active.generation = $10
            )
         RETURNING path`,
        [
          rel,
          wrapped.ciphertext,
          wrapped.iv,
          wrapped.tag,
          new Date().toISOString(),
          concept.namespace,
          JSON.stringify(normalizedSubjects),
          this.kekId,
          ENVELOPE_VERSION,
          activeState.generation,
          ...fenceSnapshot.flatMap((entry) => [entry.namespace, entry.generation]),
          new Date().toISOString(),
          `l3:${rel}`,
        ],
      );
      if (inserted.rows.length !== 1) {
        throw new Error(`private concept publication was fenced by erasure or KEK rotation: ${rel}`);
      }
      keyInserted = true;
      await fs.rename(temp, abs);
      if (!(await this.promotePendingKey(db, rel, concept.namespace))) {
        throw new Error(`pending private concept was erased before commit: ${rel}`);
      }
    } catch (err) {
      await fs.rm(temp, { force: true });
      if (keyInserted) {
        await db.query(
          `DELETE FROM cold_concept_keys
            WHERE path = $1 AND write_state = 'pending'
              AND kek_id = $2 AND kek_generation = $3`,
          [rel, activeState.id, activeState.generation],
        ).catch(() => undefined);
      }
      throw err;
    }
    this.db = db;
    return rel;
  }

  private async decryptPrivateConcept(
    db: ColdDb | null,
    rel: string,
    raw: string,
    allowPending = false,
  ): Promise<Concept> {
    if (this.kek === null) throw new Error("cold KEK unavailable or invalid");
    if (db === null) throw new Error("cold key database unavailable");
    const { rows } = await db.query(
      `SELECT wrapped_dek, wrap_iv, wrap_tag, namespace, pii_subjects, kek_id,
              envelope_version, write_state, kek_generation
         FROM cold_concept_keys WHERE path = $1`,
      [rel],
    );
    if (rows.length === 0) throw new Error("wrapped concept key is missing");
    const row = rows[0] as WrappedDekRow;
    const namespace = asString(row.namespace);
    const envelopeVersion = Number(row.envelope_version);
    const writeState = asString(row.write_state);
    const activeState = await this.ensureActiveKek(db);
    const storedSubjects = normalizePiiSubjects(
      Array.isArray(row.pii_subjects)
        ? (row.pii_subjects as unknown[]).map(asString)
        : asStringArray(safeJson(asString(row.pii_subjects))),
    );
    if (
      !isCanonicalNamespace(namespace) ||
      envelopeVersion !== ENVELOPE_VERSION ||
      (writeState !== "committed" && !(allowPending && writeState === "pending")) ||
      this.kekId === null ||
      asString(row.kek_id) !== this.kekId ||
      Number(row.kek_generation) !== activeState.generation
    ) {
      throw new Error("cold key metadata is missing, invalid, or belongs to another KEK");
    }
    const tombstone = await db.query(
      "SELECT 1 FROM tombstones WHERE memory_id = $1 LIMIT 1",
      [`l3:${rel}`],
    );
    if (tombstone.rows.length > 0) throw new Error("concept path was permanently erased");
    const aad = conceptAad(rel, namespace);
    const dek = decryptAesGcm(
      asString(row.wrapped_dek),
      asString(row.wrap_iv),
      asString(row.wrap_tag),
      this.kek,
      dekAad(aad),
    );
    if (dek.length !== 32) throw new Error("unwrapped concept DEK has invalid length");
    const blob = parseEncryptedBlob(raw);
    const plaintext = decryptAesGcm(blob.ciphertext, blob.iv, blob.tag, dek, aad).toString("utf8");
    const concept = parseConcept(rel, plaintext);
    if (
      !concept.namespace ||
      concept.visibility === "public" ||
      concept.namespace !== namespace ||
      JSON.stringify(normalizePiiSubjects(concept.piiSubjects ?? [])) !== JSON.stringify(storedSubjects)
    ) {
      throw new Error("encrypted concept ownership or PII metadata does not match its trusted key row");
    }
    return concept;
  }

  /** Count only current L3 concepts visible through ancestor ACL or exact mounts. */
  async countConcepts(db: ColdDb, namespace: Namespace): Promise<number> {
    const ancestors = namespaceAncestors(namespace);
    const mounted = await this.mounted(namespace);
    const ownerParams = ancestors.map((_, index) => `$${index + 1}`).join(", ");
    const mountParams = mounted
      .map((_, index) => `$${ancestors.length + index + 1}`)
      .join(", ");
    const privateVisibility = [
      ancestors.length > 0 ? `c.namespace IN (${ownerParams})` : "",
      mounted.length > 0 ? `c.path IN (${mountParams})` : "",
    ].filter(Boolean).join(" OR ") || "FALSE";
    const { rows } = await db.query(
      `SELECT count(*) AS n
         FROM concepts c
         LEFT JOIN cold_concept_keys ck ON ck.path = c.path
         LEFT JOIN cold_kek_state ks ON ks.singleton = TRUE
         LEFT JOIN knowledge_versions kv ON kv.path = c.path
         LEFT JOIN knowledge_concepts kc ON kc.id = kv.concept_id
        WHERE (kv.id IS NULL OR (
                kv.state = 'published' AND kc.status = 'active' AND kc.current_version_id = kv.id
              ))
          AND (c.visibility = 'public' OR (
             (${privateVisibility})
             AND ck.write_state = 'committed'
             AND ck.namespace = c.namespace
             AND ck.pii_subjects = c.pii_subjects
             AND ck.kek_id IS NOT NULL
             AND ck.envelope_version = 2
             AND ks.maintenance = FALSE
             AND ks.active_kek_id = ck.kek_id
             AND ks.generation = ck.kek_generation))`,
      [...ancestors, ...mounted],
    );
    return Number(rows[0]?.n ?? 0);
  }

  /** Recursively collect public .md and private .okf.enc concept files. */
  private async walk(dir: string): Promise<string[]> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch (err) {
      this.warnings.push(`cannot read knowledge dir ${dir}: ${(err as Error).message}`);
      return [];
    }
    const out: string[] = [];
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        out.push(...(await this.walk(abs)));
      } else if (
        entry.isFile() &&
        (entry.name.toLowerCase().endsWith(".md") ||
          entry.name.toLowerCase().endsWith(".okf.enc"))
      ) {
        out.push(abs);
      }
    }
    return out;
  }

  /** Canonical repo-relative path; existing symlinks must also remain inside. */
  private async resolveConceptPath(
    conceptPath: string,
  ): Promise<{ rel: string; abs: string }> {
    if (!conceptPath || path.isAbsolute(conceptPath)) {
      throw new Error("concept path must be a non-empty repo-relative path");
    }
    const base = path.resolve(this.knowledgeDir);
    const abs = path.resolve(base, conceptPath);
    const relative = path.relative(base, abs);
    if (
      relative === "" ||
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      throw new Error("concept path escapes outside the knowledge directory");
    }
    try {
      const [realBase, realTarget] = await Promise.all([
        fs.realpath(base),
        fs.realpath(abs),
      ]);
      const realRelative = path.relative(realBase, realTarget);
      if (
        realRelative === ".." ||
        realRelative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(realRelative)
      ) {
        throw new Error("concept path escapes outside the knowledge directory");
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    return { rel: toPosix(relative), abs };
  }

  private async resolveWritePath(
    conceptPath: string,
  ): Promise<{ rel: string; abs: string }> {
    const resolved = await this.resolveConceptPath(conceptPath);
    await fs.mkdir(path.dirname(resolved.abs), { recursive: true });
    const [realBase, realParent] = await Promise.all([
      fs.realpath(path.resolve(this.knowledgeDir)),
      fs.realpath(path.dirname(resolved.abs)),
    ]);
    const relative = path.relative(realBase, realParent);
    if (
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      throw new Error("concept path escapes outside the knowledge directory");
    }
    return resolved;
  }
}

function conceptFromRow(row: Record<string, unknown>): Concept {
  const base = {
    path: asString(row["path"]),
    type: asString(row["type"]),
    title: asString(row["title"]),
    description: asString(row["description"]),
    tags: Array.isArray(row["tags"])
      ? row["tags"].map((value) => asString(value))
      : asStringArray(safeJson(asString(row["tags"]))),
    body: asString(row["body"]),
  };
  const namespace = asString(row["namespace"]);
  const concept: Concept = namespace
    ? {
        ...base,
        namespace,
        ...(normalizePiiSubjects(
          Array.isArray(row["pii_subjects"])
            ? (row["pii_subjects"] as unknown[]).map(asString)
            : asStringArray(safeJson(asString(row["pii_subjects"]))),
        ).length > 0
          ? {
              piiSubjects: normalizePiiSubjects(
                Array.isArray(row["pii_subjects"])
                  ? (row["pii_subjects"] as unknown[]).map(asString)
                  : asStringArray(safeJson(asString(row["pii_subjects"]))),
              ),
            }
          : {}),
      }
    : { ...base, visibility: "public" };
  const owner = asString(row["owner"]);
  if (owner) concept.owner = owner;
  const verifiedAgainst = asString(row["verified_against"]);
  if (verifiedAgainst) concept.verifiedAgainst = verifiedAgainst;
  const verifiedAt = asString(row["verified_at"]);
  if (verifiedAt) concept.verifiedAt = verifiedAt;
  return concept;
}

function decodeKek(encoded: string): Buffer | null {
  if (!encoded) return null;
  try {
    const key = Buffer.from(encoded, "base64");
    return key.length === 32 && key.toString("base64") === encoded ? key : null;
  } catch {
    return null;
  }
}

function conceptAad(rel: string, namespace: string): Buffer {
  return Buffer.from(`halomem:cold:v${ENVELOPE_VERSION}\n${rel}\n${namespace}`, "utf8");
}

function dekAad(concept: Buffer): Buffer {
  return Buffer.concat([concept, Buffer.from("\ndek", "utf8")]);
}

function encryptAesGcm(
  plaintext: Buffer,
  key: Buffer,
  aad: Buffer,
): Omit<EncryptedBlobV2, "version" | "alg"> {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptAesGcm(
  ciphertext: string,
  iv: string,
  tag: string,
  key: Buffer,
  aad: Buffer,
): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);
}

function serializePrivateConcept(concept: Concept): string {
  if (!concept.namespace || concept.visibility === "public") {
    throw new Error("encrypted concepts must have a private namespace");
  }
  const fm: Record<string, unknown> = {
    type: concept.type,
    title: concept.title,
    description: concept.description,
    tags: concept.tags,
    namespace: concept.namespace,
  };
  if (concept.owner) fm["owner"] = concept.owner;
  if (concept.verifiedAgainst) fm["verified_against"] = concept.verifiedAgainst;
  if (concept.verifiedAt) fm["verified_at"] = concept.verifiedAt;
  if (concept.piiSubjects && concept.piiSubjects.length > 0) {
    fm["pii_subjects"] = normalizePiiSubjects(concept.piiSubjects);
  }
  return matter.stringify(concept.body, fm);
}

function parseEncryptedBlob(raw: string): EncryptedBlobV2 {
  const parsed = JSON.parse(raw) as Partial<EncryptedBlobV2>;
  if (
    parsed.version !== ENVELOPE_VERSION ||
    parsed.alg !== "A256GCM" ||
    typeof parsed.iv !== "string" ||
    typeof parsed.tag !== "string" ||
    typeof parsed.ciphertext !== "string"
  ) {
    throw new Error("unsupported or malformed encrypted concept blob");
  }
  return parsed as EncryptedBlobV2;
}

function isCanonicalNamespace(namespace: string): boolean {
  const parts = namespace.split("/");
  return (
    !namespace.includes("\\") &&
    parts.every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}

function isConceptVisible(concept: Concept, caller: Namespace): boolean {
  return (
    concept.visibility === "public" ||
    (concept.namespace !== undefined &&
      namespaceAncestors(caller).includes(concept.namespace))
  );
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    count++;
    idx = haystack.indexOf(needle, idx + needle.length);
  }
  return count;
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return [];
  }
}
