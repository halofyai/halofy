/**
 * Module B (M4 / D3) — mem.forget erasure engine.
 *
 * `forget(deps, target, identity)` is the ONE governed exception to D7's "never
 * delete": a compliance erasure. It resolves the target to a concrete id set
 * INSIDE the caller's subtree, then in ONE database transaction:
 *   1. nulls any dangling `supersedes` links from surviving rows into the
 *      to-be-deleted set (the FK `memory_objects.supersedes -> memory_objects.id`
 *      would otherwise reject the DELETE);
 *   2. HARD-DELETEs the matching rows (their inline embeddings go with them);
 *   3. inserts one tombstone per erased id;
 *   4. builds + ed25519-signs a DeletionCertificate (public key inline) and
 *      inserts it.
 * E6: derived usage rows (usage_events, query_traces for actor/namespace
 * targets) are scrubbed in the same transaction — no tombstones (they are not
 * memory objects), but the certificate enumerates their ids.
 * It NEVER touches `audit_log` — the audit trail is append-only (D4); the
 * syscall layer appends the `forget` audit row.
 *
 * Subtree scoping (isolation = the existing ancestor-prefix ACL, downward):
 *   - the caller may only erase within its OWN subtree — a target whose
 *     namespace is an ANCESTOR or a SIBLING of the caller's namespace resolves
 *     to zero rows;
 *   - resolution runs DOWNWARD: a namespace target matches that namespace and
 *     its descendants (again constrained to the caller's subtree).
 *
 * `deps` is a STRUCTURAL slice `{ db, audit }` — no kernel import.
 */

import { ulid } from "ulid";
import { isRootOwner } from "../auth/index.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import { normalizePiiSubject, normalizePiiSubjects } from "../pii.js";
import { acquireErasureFence } from "../erasure-fence.js";
import { assistantActorHash } from "./actor-hash.js";
import type {
  AuditEvent,
  AssistantPurgeResult,
  AssistantRecycleRecord,
  AssistantRecycleResult,
  DeletionCertificate,
  ForgetResult,
  ForgetTarget,
  Identity,
  MemoryId,
  Namespace,
  TombstoneRecord,
} from "../types.js";
import {
  signCertificate,
  type CertificatePayload,
} from "./certificate.js";
import { loadSigningKey, type SigningKey } from "./keys.js";

// Re-export the certificate + key surface so the integrator has one entry
// point: `import { forget, verifyCertificate, loadSigningKey } from "./erasure/index.js"`.
export {
  canonicalPayload,
  signCertificate,
  verifyCertificate,
  type CertificatePayload,
} from "./certificate.js";
export {
  generateSigningKey,
  loadSigningKey,
  SIGNING_KEY_ENV,
  type SigningKey,
} from "./keys.js";

// ---------------------------------------------------------------------------
// Structural dependency slice (no kernel imports)
// ---------------------------------------------------------------------------

/** Append-only audit surface. `forget` only ever APPENDS — never deletes. */
export interface AuditSink {
  append(event: AuditEvent): Promise<void>;
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface ForgetDeps {
  db: Db;
  audit: AuditSink;
  /**
   * The signing key. Optional: when omitted, `loadSigningKey()` is used (env
   * key or an ephemeral one). The kernel loads it once at boot and passes it in
   * so every certificate in a process shares one public key.
   */
  signingKey?: SigningKey;
  /**
   * R6: enqueue external warm-store purge ops for the erased ids INSIDE the
   * erasure transaction (same database — D5 makes this free). Atomicity is the
   * point: a DeletionCertificate can never exist without its mirror purge ops
   * durably queued, so no crash window can leave erased content live in an
   * external mirror with nothing left to retry. Structural callback — this
   * module stays kernel-import-free.
   */
  enqueueWarmPurges?(
    tx: Db,
    erasedIds: MemoryId[],
    namespace: Namespace,
  ): Promise<void>;
}

export type AssistantRecycleDeps = Pick<ForgetDeps, "db" | "audit" | "signingKey">;

// ---------------------------------------------------------------------------
// Subtree helpers (downward containment — the ancestor ACL, read the other way)
// ---------------------------------------------------------------------------

/**
 * True iff `candidate` is inside `root`'s subtree: candidate === root, or root
 * is a '/'-split prefix ancestor of candidate. This is exactly the existing
 * ancestor ACL relation `namespaceAncestors(candidate).includes(root)` — no
 * LIKE, no parallel fence. A caller at `root` may erase here.
 */
function isInSubtree(candidate: Namespace, root: Namespace, global: boolean): boolean {
  return global || namespaceAncestors(candidate).includes(root);
}

/** A minimal row shape pulled for erasure. */
interface EraseRow {
  id: MemoryId;
  namespace: Namespace;
}

interface ColdEraseRow {
  id: MemoryId;
  path: string;
  namespace: Namespace;
}

/** Resolve private cold objects from trusted key metadata, never plaintext projections. */
async function resolveColdTargets(
  db: Db,
  target: ForgetTarget,
  caller: Namespace,
  global: boolean,
): Promise<ColdEraseRow[]> {
  if (target.kind === "namespace" && !isInSubtree(target.value, caller, global)) return [];

  const { rows } = await db.query(
    `SELECT path, namespace, pii_subjects
       FROM cold_concept_keys
      WHERE namespace IS NOT NULL
        AND pii_subjects IS NOT NULL
        AND kek_id IS NOT NULL
        AND envelope_version = 2
        AND write_state IN ('pending','committed')`,
  );
  if (target.kind === "memory") {
    if (!target.value.startsWith("l3:")) return [];
    const path = target.value.slice(3);
    return (rows as Record<string, unknown>[])
      .filter((row) => String(row.path) === path)
      .filter((row) => isInSubtree(String(row.namespace) as Namespace, caller, global))
      .map((row) => ({
        id: `l3:${path}`,
        path,
        namespace: String(row.namespace) as Namespace,
      }));
  }
  const normalizedTarget =
    target.kind === "actor" || target.kind === "entity"
      ? normalizePiiSubject(target.value)
      : "";
  if ((target.kind === "actor" || target.kind === "entity") && normalizedTarget.length === 0) {
    return [];
  }

  return (rows as Record<string, unknown>[])
    .filter((row) => {
      const namespace = String(row.namespace ?? "") as Namespace;
      if (!namespace || !isInSubtree(namespace, caller, global)) return false;
      if (target.kind === "namespace") {
        return isInSubtree(namespace, target.value, false);
      }
      const subjects = normalizePiiSubjects(parseAliases(row.pii_subjects));
      return subjects.includes(normalizedTarget);
    })
    .map((row) => {
      const path = String(row.path);
      return {
        id: `l3:${path}`,
        path,
        namespace: String(row.namespace) as Namespace,
      };
    });
}

// ---------------------------------------------------------------------------
// Target resolution — always constrained to the caller's subtree
// ---------------------------------------------------------------------------

/**
 * Resolve a ForgetTarget to the concrete rows to erase, INSIDE `caller`'s
 * subtree only. Reads outside the transaction (the transaction re-checks
 * nothing that could change under it — resolution + delete run back to back on
 * the same handle in `forget`). All SQL is parameterized.
 */
async function resolveTargets(
  db: Db,
  target: ForgetTarget,
  caller: Namespace,
  global: boolean,
): Promise<EraseRow[]> {
  switch (target.kind) {
    case "memory": {
      const res = await db.query(
        `SELECT id, namespace FROM memory_objects WHERE id = $1`,
        [target.value],
      );
      if (res.rows.length === 0) return [];
      const row = res.rows[0] as Record<string, unknown>;
      const ns = row.namespace as Namespace;
      // Visible for erasure iff the row lives in the caller's subtree.
      if (!isInSubtree(ns, caller, global)) return [];
      return [{ id: row.id as MemoryId, namespace: ns }];
    }

    case "namespace": {
      // The target namespace must itself be within the caller's subtree;
      // otherwise erase nothing (no crossing into an ancestor/sibling).
      if (!isInSubtree(target.value, caller, global)) return [];
      // Match the target namespace AND its descendants. Descendants are
      // rows whose namespace starts with `${target.value}/`; we express that
      // without LIKE via the ancestor relation checked in JS on a scoped pull.
      const res = await db.query(
        `SELECT id, namespace FROM memory_objects`,
        [],
      );
      return (res.rows as Record<string, unknown>[])
        .map((r) => ({
          id: r.id as MemoryId,
          namespace: r.namespace as Namespace,
        }))
        .filter((r) => isInSubtree(r.namespace, target.value, false));
    }

    case "actor": {
      // Rows whose provenance array contains an entry with actor = value.
      // JSONB containment (`@>`) with an array probe is parameterized and
      // LIKE-free. Constrain to the caller's subtree in JS.
      const res = await db.query(
        `SELECT id, namespace FROM memory_objects
         WHERE provenance @> $1::jsonb`,
        [JSON.stringify([{ actor: target.value }])],
      );
      return (res.rows as Record<string, unknown>[])
        .map((r) => ({
          id: r.id as MemoryId,
          namespace: r.namespace as Namespace,
        }))
        .filter((r) => isInSubtree(r.namespace, caller, global));
    }

    case "entity": {
      // Facts MENTIONING the entity (whole-word, case-insensitive), within the
      // caller's subtree. Mirrors the graph driver's mention semantics (a name
      // embedded in a longer alphanumeric run is NOT a mention). We resolve the
      // entity's canonical name + aliases from the ACL-scoped entity_registry,
      // then match content in JS.
      const value = target.value.trim();
      if (value.length === 0) return [];

      const { names } = await resolveEntityRegistry(db, value, caller, global);
      const matchers = nameMatchers([...names]);

      const res = await db.query(
        `SELECT id, namespace, content FROM memory_objects`,
        [],
      );
      return (res.rows as Record<string, unknown>[])
        .filter((r) => {
          const ns = r.namespace as Namespace;
          if (!isInSubtree(ns, caller, global)) return false;
          const contentLower = String(r.content ?? "").toLowerCase();
          return matchers.some((re) => re.test(contentLower));
        })
        .map((r) => ({
          id: r.id as MemoryId,
          namespace: r.namespace as Namespace,
        }));
    }

    default: {
      const _exhaustive: never = target;
      return _exhaustive;
    }
  }
}

/**
 * Resolve an entity target's canonical name + aliases from entity_registry,
 * INSIDE the caller's subtree only. Returns the lowercase name-match set (target
 * value + every alias of any matching registry row) AND the ids of the registry
 * rows that name the entity — those rows are the erased person's PII and must be
 * hard-deleted alongside the facts (erasure completeness: the canonical_name
 * must not survive in an unerased path).
 *
 * Scoping matches the fact resolution below EXACTLY: rows are filtered to the
 * caller's DOWNWARD subtree via `isInSubtree` (caller + descendants), so a
 * SIBLING tenant's alias graph can never widen the match set or delete set, yet
 * descendant registry rows (where the facts actually live) are still resolved.
 */
async function resolveEntityRegistry(
  db: Db,
  value: string,
  caller: Namespace,
  global: boolean,
): Promise<{ names: Set<string>; registryIds: string[] }> {
  const entRes = await db.query(
    `SELECT id, namespace, canonical_name, aliases FROM entity_registry`,
    [],
  );
  const lowerValue = value.toLowerCase();
  const names = new Set<string>([lowerValue]);
  const registryIds: string[] = [];
  for (const r of entRes.rows as Record<string, unknown>[]) {
    const ns = r.namespace as Namespace;
    if (!isInSubtree(ns, caller, global)) continue; // caller's subtree only - no siblings
    const canonical = String(r.canonical_name ?? "");
    const aliases = parseAliases(r.aliases);
    const all = [canonical, ...aliases].map((n) => n.trim().toLowerCase());
    if (all.includes(lowerValue)) {
      for (const n of all) if (n.length > 0) names.add(n);
      registryIds.push(String(r.id));
    }
  }
  return { names, registryIds };
}

/**
 * Ids of the DERIVED report rows (fragmentation_reports, scorecards) whose
 * namespace is in the caller's DOWNWARD subtree. These JSONB snapshots embed
 * verbatim fact content, so a compliance erasure must scrub them too. Read all
 * ids + namespaces and filter by `isInSubtree` — same downward-subtree shape as
 * the memory-row resolution, so a sibling tenant's report is never touched.
 */
async function subtreeReportIds(
  db: Db,
  caller: Namespace,
  global: boolean,
): Promise<{ fragmentation: string[]; scorecards: string[] }> {
  const collect = async (table: "fragmentation_reports" | "scorecards"): Promise<string[]> => {
    const res = await db.query(`SELECT id, namespace FROM ${table}`, []);
    return (res.rows as Record<string, unknown>[])
      .filter((r) => isInSubtree(r.namespace as Namespace, caller, global))
      .map((r) => String(r.id));
  };
  return {
    fragmentation: await collect("fragmentation_reports"),
    scorecards: await collect("scorecards"),
  };
}

/**
 * E6: ids of the DERIVED usage rows (D36 usage_events, D37 query_traces)
 * matching the erasure target, with the same downward-subtree scoping as the
 * memory-object paths (no SQL LIKE anywhere). Scoping is pushed INTO SQL —
 * the candidate namespaces are enumerated cheaply (SELECT DISTINCT), filtered
 * in process with the same isInSubtree logic, and only those rows are pulled
 * — a full-table scan inside the forget transaction would blow PGlite's wasm
 * serializer ceiling at usage scale. kind "actor" matches rows whose actor is
 * the target value inside the CALLER's subtree; kind "namespace" matches rows
 * inside the TARGET subtree (itself gated to the caller's subtree). kind
 * "memory"/"entity" has NO usage linkage — usage rows reference
 * traces/actors, never memory or entity ids — so nothing is erased for those
 * targets. Sorted for deterministic certificate canonicalization.
 * `queryTraceKeys` carries the (namespace, trace_id) pairs for the DELETE:
 * query_traces is keyed (namespace, trace_id) (D37), so a colliding trace id
 * in another namespace is a different row and must survive.
 */
async function resolveUsageTargets(
  db: Db,
  target: ForgetTarget,
  caller: Namespace,
  global: boolean,
): Promise<{
  usageEventIds: string[];
  queryTraceIds: string[];
  queryTraceKeys: { namespace: string; traceId: string }[];
}> {
  const none: {
    usageEventIds: string[];
    queryTraceIds: string[];
    queryTraceKeys: { namespace: string; traceId: string }[];
  } = { usageEventIds: [], queryTraceIds: [], queryTraceKeys: [] };
  if (target.kind !== "actor" && target.kind !== "namespace") return none;
  if (target.kind === "namespace" && !isInSubtree(target.value, caller, global)) return none;
  const collect = async (
    table: "usage_events" | "query_traces",
    idColumn: "id" | "trace_id",
  ): Promise<Record<string, unknown>[]> => {
    const distinct = await db.query(`SELECT DISTINCT namespace FROM ${table}`, []);
    const candidateNs = (distinct.rows as Record<string, unknown>[])
      .map((row) => row.namespace as Namespace)
      .filter((ns) => isInSubtree(ns, caller, global));
    if (candidateNs.length === 0) return [];
    const ph = candidateNs.map((_, i) => `$${i + 1}`).join(", ");
    const params: unknown[] = [...candidateNs];
    // Exact IN binds only, never LIKE. The actor predicate rides the query.
    let sql = `SELECT ${idColumn} AS id, namespace, actor FROM ${table} WHERE namespace IN (${ph})`;
    if (target.kind === "actor") {
      params.push(target.value);
      sql += ` AND actor = $${params.length}`;
    }
    const res = await db.query(sql, params);
    return (res.rows as Record<string, unknown>[]).filter((row) =>
      target.kind === "namespace"
        ? isInSubtree(row.namespace as Namespace, target.value, false)
        : true,
    );
  };
  const eventRows = await collect("usage_events", "id");
  const traceRows = await collect("query_traces", "trace_id");
  const queryTraceKeys = traceRows.map((row) => ({
    namespace: row.namespace as string,
    traceId: String(row.id),
  }));
  return {
    usageEventIds: eventRows.map((row) => String(row.id)).sort(),
    queryTraceIds: [...new Set(queryTraceKeys.map((key) => key.traceId))].sort(),
    queryTraceKeys,
  };
}

function parseAliases(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
    } catch {
      return [];
    }
  }
  return [];
}

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g;

/** Whole-word, case-insensitive matchers for a set of lowercase names. */
function nameMatchers(names: string[]): RegExp[] {
  return names
    .filter((n) => n.length > 0)
    .map(
      (n) =>
        new RegExp(
          `(?<![a-z0-9])${n.replace(REGEX_SPECIALS, "\\$&")}(?![a-z0-9])`,
        ),
    );
}

// ---------------------------------------------------------------------------
// Assistant recycle / restore / hard purge (D57)
// ---------------------------------------------------------------------------

function canReadAssistantRecycle(identity: Identity): boolean {
  return identity.role === "owner" || identity.role === "admin" ||
    identity.role === "auditor" || identity.role === "member";
}

function canMutateAssistantRecycle(identity: Identity): boolean {
  return identity.role === "owner" || identity.role === "admin";
}

async function assistantScopedNamespaces(db: Db, identity: Identity): Promise<string[] | null> {
  if (isRootOwner(identity)) return null;
  const [turns, conversations, lifecycle] = await Promise.all([
    db.query(`SELECT DISTINCT namespace FROM ai_turns`),
    db.query(`SELECT DISTINCT namespace FROM copilot_conversations`),
    db.query(`SELECT DISTINCT namespace FROM assistant_actor_lifecycle`),
  ]);
  return [...new Set([
    ...(turns.rows as { namespace: string }[]).map((row) => row.namespace),
    ...(conversations.rows as { namespace: string }[]).map((row) => row.namespace),
    ...(lifecycle.rows as { namespace: string }[]).map((row) => row.namespace),
  ])].filter((namespace) => isInSubtree(namespace as Namespace, identity.namespace, false));
}

async function assistantActorNamespaces(
  db: Db,
  scoped: readonly string[] | null,
  actor: string,
  fallback: string,
): Promise<string[]> {
  const scope = exactNamespacePredicate(scoped, 2);
  const params = [actor, ...scope.params];
  const [turns, conversations] = await Promise.all([
    db.query(`SELECT DISTINCT namespace FROM ai_turns WHERE actor = $1 AND ${scope.sql}`, params),
    db.query(`SELECT DISTINCT namespace FROM copilot_conversations WHERE actor = $1 AND ${scope.sql}`, params),
  ]);
  return [...new Set([
    fallback,
    ...(turns.rows as { namespace: string }[]).map((row) => row.namespace),
    ...(conversations.rows as { namespace: string }[]).map((row) => row.namespace),
  ])];
}

async function setAssistantActorLifecycle(
  db: Db,
  namespaces: readonly string[],
  actorHash: string,
  changedBy: string,
  at: string,
  state: "recycled" | "active" | "purged",
): Promise<void> {
  for (const namespace of namespaces) {
    await db.query(
      `INSERT INTO assistant_actor_lifecycle
         (namespace, actor_hash, recycled_at, recycled_by, purged_at, generation, created_at, updated_at)
       VALUES ($1,$2,NULL,NULL,NULL,0,$3,$3)
       ON CONFLICT (namespace, actor_hash) DO NOTHING`,
      [namespace, actorHash, at],
    );
    if (state === "active") {
      const current = await db.query(
        `SELECT purged_at FROM assistant_actor_lifecycle
          WHERE namespace = $1 AND actor_hash = $2 FOR UPDATE`,
        [namespace, actorHash],
      );
      if (current.rows[0]?.purged_at !== null) throw new Error("hard-purged Assistant data cannot be restored");
      await db.query(
        `UPDATE assistant_actor_lifecycle
            SET recycled_at = NULL, recycled_by = NULL,
                generation = generation + 1, updated_at = $3
          WHERE namespace = $1 AND actor_hash = $2`,
        [namespace, actorHash, at],
      );
    } else {
      await db.query(
        `UPDATE assistant_actor_lifecycle
            SET recycled_at = COALESCE(recycled_at, $3),
                recycled_by = COALESCE(recycled_by, $4),
                purged_at = ${state === "purged" ? "COALESCE(purged_at, $3)" : "purged_at"},
                generation = generation + 1,
                updated_at = $3
          WHERE namespace = $1 AND actor_hash = $2`,
        [namespace, actorHash, at, changedBy],
      );
    }
  }
}

function exactNamespacePredicate(
  namespaces: readonly string[] | null,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  if (namespaces === null) return { sql: "TRUE", params: [] };
  if (namespaces.length === 0) return { sql: "FALSE", params: [] };
  let n = startAt;
  return {
    sql: `${column} IN (${namespaces.map(() => `$${n++}`).join(", ")})`,
    params: [...namespaces],
  };
}

async function assistantCategoryCounts(
  db: Db,
  namespaces: readonly string[] | null,
  actor: string,
  recycledOnly = false,
): Promise<DeletionCertificate["assistantCategories"]> {
  const scope = exactNamespacePredicate(namespaces, 2);
  const active = recycledOnly ? " AND recycled_at IS NOT NULL" : "";
  const params = [actor, ...scope.params];
  const [conversations, messages, turns, invocations, costs] = await Promise.all([
    db.query(`SELECT count(*) AS n FROM copilot_conversations WHERE actor = $1 AND ${scope.sql}${active}`, params),
    db.query(
      `SELECT count(*) AS n FROM copilot_conversation_messages m
        WHERE m.actor = $1 AND ${exactNamespacePredicate(namespaces, 2, "m.namespace").sql}
          AND EXISTS (SELECT 1 FROM copilot_conversations c
                       WHERE c.id = m.conversation_id AND c.recycled_at IS NOT NULL)`,
      params,
    ),
    db.query(`SELECT count(*) AS n FROM ai_turns WHERE actor = $1 AND ${scope.sql}${active}`, params),
    db.query(
      `SELECT count(*) AS n FROM model_invocations mi
        WHERE EXISTS (SELECT 1 FROM ai_turns at
                       WHERE at.id = mi.turn_id AND at.actor = $1
                         AND ${exactNamespacePredicate(namespaces, 2, "at.namespace").sql}${recycledOnly ? " AND at.recycled_at IS NOT NULL" : ""})`,
      params,
    ),
    db.query(
      `SELECT count(*) AS n FROM cost_ledger cl
        WHERE EXISTS (SELECT 1 FROM model_invocations mi JOIN ai_turns at ON at.id = mi.turn_id
                       WHERE mi.id = cl.invocation_id AND at.actor = $1
                         AND ${exactNamespacePredicate(namespaces, 2, "at.namespace").sql}${recycledOnly ? " AND at.recycled_at IS NOT NULL" : ""})`,
      params,
    ),
  ]);
  const count = (result: { rows: Record<string, unknown>[] }): number => Number(result.rows[0]?.n ?? 0);
  return {
    conversations: count(conversations),
    messages: count(messages),
    turns: count(turns),
    invocations: count(invocations),
    costRows: count(costs),
  };
}

export async function listAssistantRecycleBin(
  db: Db,
  identity: Identity,
): Promise<{ records: AssistantRecycleRecord[] }> {
  if (!canReadAssistantRecycle(identity)) return { records: [] };
  const namespaces = await assistantScopedNamespaces(db, identity);
  const scope = exactNamespacePredicate(namespaces, 1);
  const actorClause = identity.role === "member" ? ` AND actor = $${scope.params.length + 1}` : "";
  const params: unknown[] = [...scope.params, ...(identity.role === "member" ? [identity.actor] : [])];
  const [conversationRows, turnRows] = await Promise.all([
    db.query(
      `SELECT namespace, actor, min(recycled_at) AS recycled_at,
              max(recycled_by) AS recycled_by, count(*) AS conversations
         FROM copilot_conversations
        WHERE ${scope.sql} AND recycled_at IS NOT NULL${actorClause}
        GROUP BY namespace, actor`,
      params,
    ),
    db.query(
      `SELECT namespace, actor, min(recycled_at) AS recycled_at,
              max(recycled_by) AS recycled_by, count(*) AS turns
         FROM ai_turns
        WHERE ${scope.sql} AND recycled_at IS NOT NULL${actorClause}
        GROUP BY namespace, actor`,
      params,
    ),
  ]);
  const records = new Map<string, AssistantRecycleRecord>();
  const ensure = (row: Record<string, unknown>): AssistantRecycleRecord => {
    const key = `${row.namespace as string}\n${row.actor as string}`;
    let record = records.get(key);
    if (!record) {
      record = {
        namespace: row.namespace as Namespace,
        actor: String(row.actor),
        recycledAt: new Date(row.recycled_at as string).toISOString(),
        recycledBy: String(row.recycled_by ?? ""),
        conversations: 0,
        turns: 0,
        invocations: 0,
        costRows: 0,
      };
      records.set(key, record);
    }
    return record;
  };
  for (const row of conversationRows.rows as Record<string, unknown>[]) ensure(row).conversations = Number(row.conversations);
  for (const row of turnRows.rows as Record<string, unknown>[]) ensure(row).turns = Number(row.turns);
  for (const record of records.values()) {
    const counts = await assistantCategoryCounts(db, [record.namespace], record.actor, true);
    record.invocations = counts?.invocations ?? 0;
    record.costRows = counts?.costRows ?? 0;
  }
  return { records: [...records.values()].sort((a, b) => b.recycledAt.localeCompare(a.recycledAt)) };
}

export async function recycleAssistantActor(
  deps: AssistantRecycleDeps,
  actor: string,
  identity: Identity,
): Promise<AssistantRecycleResult> {
  if (!canMutateAssistantRecycle(identity)) throw new Error("Assistant recycle requires owner or admin");
  const target = actor.trim();
  if (target.length === 0 || target.length > 320) throw new Error("invalid Assistant recycle actor");
  const namespaces = await assistantScopedNamespaces(deps.db, identity);
  const actorNamespaces = await assistantActorNamespaces(deps.db, namespaces, target, identity.namespace);
  const targetHash = assistantActorHash(target);
  const now = new Date().toISOString();
  const categories = await deps.db.transaction(async (tx) => {
    await acquireErasureFence(tx, identity.namespace);
    await setAssistantActorLifecycle(tx, actorNamespaces, targetHash, identity.actor, now, "recycled");
    const counts = await assistantCategoryCounts(tx, namespaces, target);
    const scope = exactNamespacePredicate(namespaces, 3);
    const params = [now, identity.actor, ...scope.params, target];
    const actorParam = params.length;
    await tx.query(
      `UPDATE copilot_conversations SET recycled_at = $1, recycled_by = $2
        WHERE ${scope.sql} AND actor = $${actorParam} AND recycled_at IS NULL`,
      params,
    );
    await tx.query(
      `UPDATE ai_turns SET recycled_at = $1, recycled_by = $2, updated_at = $1
        WHERE ${scope.sql} AND actor = $${actorParam} AND recycled_at IS NULL`,
      params,
    );
    const relatedScope = exactNamespacePredicate(namespaces, 2, "at.namespace");
    const relatedParams = [now, ...relatedScope.params, target];
    const relatedActorParam = relatedParams.length;
    await tx.query(
      `UPDATE model_invocations SET recycled_at = $1
        WHERE turn_id IN (
          SELECT at.id FROM ai_turns at
           WHERE ${relatedScope.sql} AND at.actor = $${relatedActorParam}
        )`,
      relatedParams,
    );
    await tx.query(
      `UPDATE cost_ledger SET recycled_at = $1
        WHERE invocation_id IN (
          SELECT mi.id FROM model_invocations mi JOIN ai_turns at ON at.id = mi.turn_id
           WHERE ${relatedScope.sql} AND at.actor = $${relatedActorParam}
        )`,
      relatedParams,
    );
    await deps.audit.appendTo(tx, {
      ts: now, actor: identity.actor, agentId: identity.keyId, op: "assistant_recycle",
      memoryId: null, namespace: identity.namespace, purpose: "assistant-employee-recycle",
      result: "ok", detail: `actor_hash=${targetHash}; turns=${counts?.turns ?? 0}`,
    });
    return counts!;
  });
  return {
    namespace: identity.namespace,
    actor: target,
    recycledAt: now,
    recycledBy: identity.actor,
    ...categories,
  };
}

export async function restoreAssistantActor(
  deps: AssistantRecycleDeps,
  actor: string,
  identity: Identity,
): Promise<AssistantRecycleResult> {
  if (!canMutateAssistantRecycle(identity)) throw new Error("Assistant restore requires owner or admin");
  const target = actor.trim();
  const namespaces = await assistantScopedNamespaces(deps.db, identity);
  const actorNamespaces = await assistantActorNamespaces(deps.db, namespaces, target, identity.namespace);
  const targetHash = assistantActorHash(target);
  const before = await assistantCategoryCounts(deps.db, namespaces, target, true);
  const now = new Date().toISOString();
  await deps.db.transaction(async (tx) => {
    await acquireErasureFence(tx, identity.namespace);
    await setAssistantActorLifecycle(tx, actorNamespaces, targetHash, identity.actor, now, "active");
    const scope = exactNamespacePredicate(namespaces, 1);
    const params = [...scope.params, target];
    const actorParam = params.length;
    await tx.query(`UPDATE copilot_conversations SET recycled_at = NULL, recycled_by = NULL WHERE ${scope.sql} AND actor = $${actorParam}`, params);
    await tx.query(`UPDATE ai_turns SET recycled_at = NULL, recycled_by = NULL, updated_at = $${actorParam + 1} WHERE ${scope.sql} AND actor = $${actorParam}`, [...params, now]);
    await tx.query(`UPDATE model_invocations SET recycled_at = NULL WHERE turn_id IN (SELECT id FROM ai_turns WHERE ${scope.sql} AND actor = $${actorParam})`, params);
    await tx.query(
      `UPDATE cost_ledger SET recycled_at = NULL WHERE invocation_id IN (
         SELECT mi.id FROM model_invocations mi JOIN ai_turns at ON at.id = mi.turn_id
          WHERE ${exactNamespacePredicate(namespaces, 1, "at.namespace").sql} AND at.actor = $${actorParam})`,
      params,
    );
    await deps.audit.appendTo(tx, {
      ts: now, actor: identity.actor, agentId: identity.keyId, op: "assistant_restore",
      memoryId: null, namespace: identity.namespace, purpose: "assistant-employee-restore",
      result: "ok", detail: `actor_hash=${targetHash}; turns=${before?.turns ?? 0}`,
    });
  });
  return { namespace: identity.namespace, actor: target, recycledAt: now, recycledBy: identity.actor, ...before! };
}

export async function hardPurgeAssistantActor(
  deps: AssistantRecycleDeps,
  actor: string,
  identity: Identity,
  confirmation: string,
): Promise<AssistantPurgeResult> {
  if (identity.role !== "owner") throw new Error("Assistant hard purge requires owner");
  const target = actor.trim();
  if (confirmation !== `PURGE:${target}`) throw new Error("explicit hard-purge confirmation is required");
  const namespaces = await assistantScopedNamespaces(deps.db, identity);
  const actorNamespaces = await assistantActorNamespaces(deps.db, namespaces, target, identity.namespace);
  const targetHash = assistantActorHash(target);
  const key = deps.signingKey ?? loadSigningKey();
  const issuedAt = new Date().toISOString();
  const certificateId = ulid();
  const certificate = await deps.db.transaction(async (tx) => {
    await acquireErasureFence(tx, identity.namespace);
    await setAssistantActorLifecycle(tx, actorNamespaces, targetHash, identity.actor, issuedAt, "purged");
    const categories = await assistantCategoryCounts(tx, namespaces, target, true);
    if ((categories?.conversations ?? 0) + (categories?.turns ?? 0) === 0) {
      throw new Error("Assistant actor must be recycled before hard purge");
    }
    const scope = exactNamespacePredicate(namespaces, 1);
    const params = [...scope.params, target];
    const actorParam = params.length;
    const targetTurns = await tx.query(
      `SELECT id FROM ai_turns
        WHERE ${scope.sql} AND actor = $${actorParam} AND recycled_at IS NOT NULL`,
      params,
    );
    for (const row of targetTurns.rows as { id: string }[]) {
      await tx.query(
        `UPDATE ai_turns SET request_fingerprint = $1 WHERE id = $2`,
        [assistantActorHash(`purged:${certificateId}:${row.id}`), row.id],
      );
    }
    await tx.query(`DELETE FROM copilot_conversations WHERE ${scope.sql} AND actor = $${actorParam} AND recycled_at IS NOT NULL`, params);
    // Keep chart numerators/denominators while removing attribution. Assistant
    // query text is destroyed defensively even if an older writer persisted it.
    await tx.query(
      `UPDATE usage_events SET actor = 'Erased employee'
        WHERE ${scope.sql} AND actor = $${actorParam}`,
      params,
    );
    await tx.query(
      `UPDATE query_traces
          SET actor = 'Erased employee', query_summary = NULL,
              query_sha256 = 'purged:' || trace_id
        WHERE ${scope.sql} AND actor = $${actorParam}`,
      params,
    );
    await tx.query(
      `UPDATE cost_ledger SET actor = 'Erased employee', recycled_at = $${actorParam + 1}
        WHERE invocation_id IN (
          SELECT mi.id FROM model_invocations mi JOIN ai_turns at ON at.id = mi.turn_id
           WHERE ${exactNamespacePredicate(namespaces, 1, "at.namespace").sql}
             AND at.actor = $${actorParam} AND at.recycled_at IS NOT NULL)`,
      [...params, issuedAt],
    );
    await tx.query(
      `UPDATE answer_outcomes ao
          SET actor = 'Erased employee', session = NULL, query_sha256 = NULL,
              resolved_by = NULL, dispute_id = NULL, evidence_ids = '[]'::jsonb,
              detail = NULL
        WHERE ${exactNamespacePredicate(namespaces, 1, "ao.namespace").sql}
          AND ao.actor = $${actorParam}
          AND EXISTS (
            SELECT 1 FROM ai_turns at
             WHERE at.namespace = ao.namespace AND at.trace_id = ao.trace_id
               AND at.actor = $${actorParam} AND at.recycled_at IS NOT NULL
          )`,
      params,
    );
    await tx.query(
      `UPDATE ai_turns
          SET actor = 'Erased employee', conversation_id = 'purged:' || id,
              client_turn_id = id, user_message_id = NULL,
              assistant_message_id = NULL, recycled_by = NULL, updated_at = $${actorParam + 1}
        WHERE ${scope.sql} AND actor = $${actorParam} AND recycled_at IS NOT NULL`,
      [...params, issuedAt],
    );
    const payload: CertificatePayload = {
      id: certificateId,
      target: { kind: "actor", value: `sha256:${targetHash}` },
      namespace: identity.namespace,
      erasedIds: [],
      erasedCount: categories!.conversations + categories!.messages,
      usageEventIds: [],
      queryTraceIds: [],
      assistantCategories: categories,
      actor: identity.actor,
      issuedAt,
      algorithm: "ed25519",
      publicKey: key.publicKeyBase64,
    };
    const cert: DeletionCertificate = { ...payload, signature: signCertificate(payload, key) };
    await tx.query(
      `INSERT INTO deletion_certificates (id, namespace, actor, issued_at, json)
       VALUES ($1,$2,$3,$4,$5::jsonb)`,
      [cert.id, cert.namespace, cert.actor, cert.issuedAt, JSON.stringify(cert)],
    );
    await deps.audit.appendTo(tx, {
      ts: issuedAt, actor: identity.actor, agentId: identity.keyId, op: "assistant_purge",
      memoryId: null, namespace: identity.namespace, purpose: "assistant-hard-purge",
      result: "ok", detail: `categories=${JSON.stringify(categories)}; cert=${certificateId}`,
    });
    return cert;
  });
  return { certificate };
}

// ---------------------------------------------------------------------------
// forget
// ---------------------------------------------------------------------------

/**
 * Erase every row matching `target` inside `identity`'s subtree, atomically,
 * and mint a signed DeletionCertificate. Returns `{ certificate, erasedCount,
 * tombstones }`. An out-of-subtree (or unmatched) target erases 0 rows and
 * still returns a valid, verifiable certificate with `erasedCount === 0`.
 *
 * ROLE NOTE: role enforcement (owner/admin only, auditor DENIED) lives in the
 * syscall gate — the integrator calls `forget` only after the role check.
 */
export async function forget(
  deps: ForgetDeps,
  target: ForgetTarget,
  identity: Identity,
): Promise<ForgetResult> {
  const key = deps.signingKey ?? loadSigningKey();
  const caller = identity.namespace;
  const global = isRootOwner(identity);

  // Target resolution is intentionally performed only after the transaction
  // fence below is held.
  // Stable, deterministic id order — the certificate's erasedIds must be
  // reproducible for canonicalization / audit.
  const erasedAt = new Date().toISOString();
  const certificateId = ulid();

  // Erasure completeness: the erased content also survives in DERIVED paths that
  // carry verbatim fact content or the erased person's name, all within the
  // caller's subtree — scrub them in the SAME transaction:
  //   - fragmentation_reports / scorecards: regenerable snapshots whose JSON
  //     embeds verbatim fact content (member.content, contradiction facts,
  //     scorecard questions). Deleting the whole subtree-scoped row is the
  //     complete, surgical erasure — the report simply gets re-run on demand.
  //   - entity_registry (kind:"entity" only): the canonical_name + aliases ARE
  //     the erased person's PII; the naming rows must go too.
  const outcome = await deps.db.transaction(async (tx) => {
    const fenceNamespace = global
      ? ""
      : target.kind === "namespace" && isInSubtree(target.value, caller, false)
        ? target.value
        : caller;
    await acquireErasureFence(tx, fenceNamespace);

    const l2Rows = await resolveTargets(tx, target, caller, global);
    const coldRows = await resolveColdTargets(tx, target, caller, global);
    const eraseRows = [...l2Rows, ...coldRows]
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const l2Ids = l2Rows.map((row) => row.id);
    const ids = eraseRows.map((row) => row.id);
    const derivedReportIds = await subtreeReportIds(tx, caller, global);
    const registryIds =
      target.kind === "entity" && target.value.trim().length > 0
        ? (await resolveEntityRegistry(tx, target.value.trim(), caller, global)).registryIds
        : [];
    if (l2Ids.length > 0) {
      const idPlaceholders = l2Ids.map((_, i) => `$${i + 1}`).join(", ");

      // 1. Null dangling supersedes links from SURVIVING rows into the deleted
      //    set (a chain member being erased alongside is itself deleted, so we
      //    exclude ids that are also being deleted). Without this the FK
      //    memory_objects.supersedes -> memory_objects.id rejects the DELETE.
      //    The placeholders $1..$n appear TWICE in the SQL but refer to the
      //    same positional params, so we bind `ids` once.
      await tx.query(
        `UPDATE memory_objects
         SET supersedes = NULL
         WHERE supersedes IN (${idPlaceholders})
           AND id NOT IN (${idPlaceholders})`,
        l2Ids,
      );

      // 1b. Archive SURVIVING disputed facts whose incumbent is being erased.
      //     Their fact_disputes rows CASCADE away with the deleted side, and a
      //     status='disputed' row without an open dispute would be permanently
      //     invisible (no read path sees it, no queue resolves it) — orphaned
      //     limbo, so park it as archived (D7: never delete outside the
      //     erasure target itself).
      await tx.query(
        `UPDATE memory_objects
         SET status = 'archived'
         WHERE status = 'disputed'
           AND id NOT IN (${idPlaceholders})
           AND id IN (
             SELECT memory_id FROM fact_disputes
              WHERE status = 'open'
                AND disputed_against IN (${idPlaceholders})
           )`,
        l2Ids,
      );

      // 2. HARD-DELETE the matching rows (inline embeddings go with the row).
      await tx.query(
        `DELETE FROM memory_objects WHERE id IN (${idPlaceholders})`,
        l2Ids,
      );

      // 3a. Scrub DERIVED snapshots in the caller's subtree that embed the erased
      //     verbatim content (fragmentation_reports, scorecards). Only runs when
      //     rows were actually erased — a 0-row forget touches no reports. The
      //     snapshots are regenerable (re-run runFragmentation / runScorecard).
      if (derivedReportIds.fragmentation.length > 0) {
        const ph = derivedReportIds.fragmentation.map((_, i) => `$${i + 1}`).join(", ");
        await tx.query(
          `DELETE FROM fragmentation_reports WHERE id IN (${ph})`,
          derivedReportIds.fragmentation,
        );
      }
      if (derivedReportIds.scorecards.length > 0) {
        const ph = derivedReportIds.scorecards.map((_, i) => `$${i + 1}`).join(", ");
        await tx.query(
          `DELETE FROM scorecards WHERE id IN (${ph})`,
          derivedReportIds.scorecards,
        );
      }
    }

    // E6: scrub DERIVED usage telemetry matching the target, in the SAME
    // transaction. Runs whenever the target kind is actor/namespace — even
    // when l2Ids is empty: an actor can have usage rows but no stored
    // memories. No tombstones (these are not memory objects), but the
    // certificate below enumerates the ids. Concurrency note: usage rows are
    // written inside syscall transactions that do NOT take the erasure fence
    // — a usage row written concurrently for an erased actor may survive,
    // exactly like audit_log (never erased). Fencing syscalls was rejected
    // for derived telemetry.
    const usageIds = await resolveUsageTargets(tx, target, caller, global);
    if (usageIds.usageEventIds.length > 0) {
      const ph = usageIds.usageEventIds.map((_, i) => `$${i + 1}`).join(", ");
      await tx.query(
        `DELETE FROM usage_events WHERE id IN (${ph})`,
        usageIds.usageEventIds,
      );
    }
    if (usageIds.queryTraceKeys.length > 0) {
      // Delete by the COMPOSITE key (D37): a colliding caller trace hint in
      // another namespace is a different row and must survive the scrub.
      const ph = usageIds.queryTraceKeys
        .map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2})`)
        .join(", ");
      await tx.query(
        `DELETE FROM query_traces WHERE (namespace, trace_id) IN (${ph})`,
        usageIds.queryTraceKeys.flatMap((key) => [key.namespace, key.traceId]),
      );
    }

    // Crypto-shred private cold objects in the SAME transaction as L2: destroy
    // wrapped DEKs and every plaintext/search projection. Git ciphertext stays.
    if (coldRows.length > 0) {
      const paths = coldRows.map((row) => row.path);
      const ph = paths.map((_, i) => `$${i + 1}`).join(", ");
      await tx.query(`DELETE FROM cold_concept_keys WHERE path IN (${ph})`, paths);
      await tx.query(`DELETE FROM concepts WHERE path IN (${ph})`, paths);
    }

    // One tombstone for every L2 ULID and stable l3:<repo-relative-path> id.
    for (const row of eraseRows) {
      const tombstone: TombstoneRecord = {
        id: ulid(),
        memoryId: row.id,
        namespace: row.namespace,
        reason: forgetReason(target),
        erasedAt,
        certificateId,
      };
      await tx.query(
        `INSERT INTO tombstones (id, memory_id, namespace, reason, erased_at, certificate_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          tombstone.id,
          tombstone.memoryId,
          tombstone.namespace,
          tombstone.reason,
          tombstone.erasedAt,
          tombstone.certificateId,
        ],
      );
    }

    // 3b. kind:"entity" — hard-delete the naming rows themselves (canonical_name
    //     + aliases are the erased person's PII). Runs even for a 0-fact match:
    //     a registry row can outlive its last fact and still expose the name.
    if (registryIds.length > 0) {
      const ph = registryIds.map((_, i) => `$${i + 1}`).join(", ");
      await tx.query(
        `DELETE FROM entity_registry WHERE id IN (${ph})`,
        registryIds,
      );
    }

    // R6: queue the external warm-store purges in the SAME transaction as the
    // hard-delete + certificate. Commit means "canonically erased AND mirror
    // purges durably queued" as one fact.
    if (deps.enqueueWarmPurges && ids.length > 0) {
      await deps.enqueueWarmPurges(tx, ids, caller);
    }

    // 4. Build, sign, and persist the certificate (even for a 0-row erasure —
    //    "we looked and erased nothing here" is itself a provable claim).
    const payload: CertificatePayload = {
      id: certificateId,
      target,
      namespace: caller,
      erasedIds: ids,
      erasedCount: ids.length,
      usageEventIds: usageIds.usageEventIds,
      queryTraceIds: usageIds.queryTraceIds,
      actor: identity.actor,
      issuedAt: erasedAt,
      algorithm: "ed25519",
      publicKey: key.publicKeyBase64,
    };
    const signature = signCertificate(payload, key);
    const cert: DeletionCertificate = { ...payload, signature };

    await tx.query(
      `INSERT INTO deletion_certificates (id, namespace, actor, issued_at, json)
       VALUES ($1, $2, $3, $4, $5::jsonb)`,
      [cert.id, cert.namespace, cert.actor, cert.issuedAt, JSON.stringify(cert)],
    );

    await deps.audit.appendTo(tx, {
      ts: erasedAt,
      actor: identity.actor,
      agentId: identity.keyId,
      op: "forget",
      memoryId: null,
      namespace: caller,
      purpose: null,
      result: "ok",
      detail: `target=${target.kind}:${target.value} erased=${ids.length} cert=${certificateId}`,
    });
    return { certificate: cert, erasedCount: ids.length };
  });

  return {
    certificate: outcome.certificate,
    erasedCount: outcome.erasedCount,
    tombstones: outcome.erasedCount,
  };
}

/** Human-readable tombstone reason from the target. */
function forgetReason(target: ForgetTarget): string {
  return `mem.forget ${target.kind}=${target.value}`;
}
