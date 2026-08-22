/**
 * Module A — MemoryIndex repository.
 *
 * Owns all reads/writes against `memory_objects`. The ACL rule (CONTRACTS.md)
 * is enforced here, not in callers: a caller with namespace N sees rows whose
 * namespace is N itself or a '/'-split prefix ancestor of N. Denied vs miss is
 * surfaced through a second return channel so the syscall layer can audit
 * 'denied' distinctly (D4).
 *
 * Supersedence is chain-based (D7): rows are never overwritten; prior validity
 * is closed via closeValidity() and the new row links back via `supersedes`.
 */

import { escapeLikePattern, type Db } from "../db/client.js";
import { writeFenceNamespaces } from "../erasure-fence.js";
import { lexicalOrQuery } from "../retrieval/index.js";
import type {
  AccessSubject,
  DataClassification,
  MemoryId,
  MemoryObject,
  MemoryReadScope,
  MemoryStatus,
  MemoryType,
  Namespace,
  ProvenanceEntry,
  SourceAccess,
  Scope,
  Tier,
} from "../types.js";

export interface GetByIdResult {
  obj: MemoryObject | null;
  /** True when the row exists but the caller's namespace may not see it. */
  denied: boolean;
}

export interface VectorHit {
  obj: MemoryObject;
  /** Cosine similarity = 1 - cosine distance. */
  similarity: number;
}

export interface ListCandidatesOptions {
  validOnly?: boolean;
  limit?: number;
  /**
   * M6 (D11): pointer facts are ROUTES, not answers — retrieval surfaces
   * (search / fault / assemble / drivers) must never serve them as candidate
   * answers, so they are excluded by default. Opt in (write-path dedupe/
   * supersede, stats/lifecycle accounting) with `includePointers: true`.
   */
  includePointers?: boolean;
  /** M7/D17: source-native grants intersected in the query layer. */
  access?: AccessSubject;
  /** Kernel-resolved ingestion sources. Never accepted from public callers. */
  sourceIds?: readonly string[];
}

function sourceIdsSql(
  sourceIds: readonly string[] | undefined,
  start: number,
): { sql: string; params: string[] } | null {
  if (sourceIds === undefined) return null;
  const ids = [...new Set(sourceIds.map((id) => id.trim()).filter(Boolean))].slice(0, 64);
  if (ids.length === 0) return { sql: "FALSE", params: [] };
  return {
    sql: `(${ids.map((_, index) =>
      `provenance @> $${start + index}::jsonb`).join(" OR ")})`,
    params: ids.map((sourceId) => JSON.stringify([{ sourceId }])),
  };
}

/** '/'-split prefix ancestors of a namespace, including the namespace itself. */
export function namespaceAncestors(namespace: Namespace): string[] {
  const parts = namespace.split("/").filter((p) => p.length > 0);
  const out: string[] = [];
  for (let i = 1; i <= parts.length; i++) {
    out.push(parts.slice(0, i).join("/"));
  }
  return out.length > 0 ? out : [namespace];
}

/** pgvector literal binding: '[v1,v2,...]'. */
export function toVectorLiteral(embedding: number[]): string {
  return `[${embedding.join(",")}]`;
}

/**
 * M10 (D42/D44) read-scope predicate: exact IN list + govern subtrees
 * (exact match + escaped-prefix LIKE, `ESCAPE '\'`), minus excluded subtrees
 * (Amendment A1: registered tenants stay invisible to the "" organization
 * root). Returns `FALSE` when the scope grants nothing — the base ancestor
 * ACL clause remains the caller's floor either way.
 */
function readScopeSql(
  scope: MemoryReadScope | undefined,
  start: number,
  column = "namespace",
): { sql: string; params: string[] } | null {
  if (!scope || (scope.exact.length === 0 && scope.prefixes.length === 0)) {
    return null;
  }
  const params: string[] = [];
  const bind = (value: string): string => {
    params.push(value);
    return `$${start + params.length - 1}`;
  };
  const include: string[] = [];
  if (scope.exact.length > 0) {
    include.push(`${column} IN (${scope.exact.map(bind).join(", ")})`);
  }
  for (const prefix of scope.prefixes) {
    if (prefix === "") {
      // The unprefixed organization: every namespace, minus exclusions below.
      include.push("TRUE");
    } else {
      include.push(
        `(${column} = ${bind(prefix)} OR ${column} LIKE ${bind(escapeLikePattern(prefix) + "/%")} ESCAPE '\\')`,
      );
    }
  }
  const exclude = (scope.excludePrefixes ?? []).filter((p) => p.length > 0);
  const excludeSql = exclude.map((prefix) =>
    `NOT (${column} = ${bind(prefix)} OR ${column} LIKE ${bind(escapeLikePattern(prefix) + "/%")} ESCAPE '\\')`
  );
  const sql = `((${include.join(" OR ")})${excludeSql.length > 0 ? ` AND ${excludeSql.join(" AND ")}` : ""})`;
  return { sql, params };
}

/** JS twin of readScopeSql for single-row checks (getById). */
export function readScopeAllows(
  scope: MemoryReadScope | undefined,
  namespace: string,
): boolean {
  if (!scope) return false;
  const inSubtree = (ns: string, prefix: string): boolean =>
    prefix === "" ? true : ns === prefix || ns.startsWith(prefix + "/");
  const included =
    scope.exact.includes(namespace) ||
    scope.prefixes.some((p) => inSubtree(namespace, p));
  if (!included) return false;
  return !(scope.excludePrefixes ?? []).some(
    (p) => p.length > 0 && inSubtree(namespace, p),
  );
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  throw new Error(`expected timestamp, got ${typeof value}`);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

function parseJson<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return JSON.parse(value) as T;
  return value as T;
}

/** snake_case row → camelCase MemoryObject. */
export function rowToMemoryObject(row: Record<string, unknown>): MemoryObject {
  return {
    id: row.id as MemoryId,
    namespace: row.namespace as Namespace,
    scope: row.scope as Scope,
    tier: row.tier as Tier,
    backendRef: row.backend_ref as string,
    content: row.content as string,
    type: row.type as MemoryType,
    confidence: Number(row.confidence),
    eventTime: toIsoOrNull(row.event_time),
    assertionTime: toIso(row.assertion_time),
    tValidFrom: toIso(row.t_valid_from),
    tValidTo: toIsoOrNull(row.t_valid_to),
    supersedes: (row.supersedes as MemoryId | null) ?? null,
    provenance: parseJson<ProvenanceEntry[]>(row.provenance, []),
    classification: parseJson<DataClassification>(row.classification, {
      sensitivity: "internal", piiSubjects: [], secretKinds: [], allowedDestinations: [],
    }),
    sourceAccess: parseJson<SourceAccess>(row.source_access, { principals: [], groups: [] }),
    ttlSeconds: row.ttl_seconds === null || row.ttl_seconds === undefined ? null : Number(row.ttl_seconds),
    telemetry: {
      lastAccessed: toIsoOrNull(row.last_accessed),
      accessCount: Number(row.access_count ?? 0),
      faultCount: Number(row.fault_count ?? 0),
    },
    status: row.status as MemoryStatus,
  };
}

const SELECT_COLUMNS = `id, namespace, scope, tier, backend_ref, content, type, confidence,
  event_time, assertion_time, t_valid_from, t_valid_to, supersedes, provenance,
  classification, source_access, ttl_seconds, last_accessed, access_count, fault_count, status`;

const OPEN_SOURCE_ACCESS = `(jsonb_array_length(COALESCE(source_access->'principals', '[]'::jsonb)) = 0
  AND jsonb_array_length(COALESCE(source_access->'groups', '[]'::jsonb)) = 0)`;
const CLASSIFICATION_READ_ALLOWED = `(COALESCE(classification->>'sensitivity', 'restricted') IN ('public','internal')
  OR COALESCE(classification->'allowedDestinations', '[]'::jsonb) @> '["agent-context"]'::jsonb)`;

function sourceAccessSql(subject: AccessSubject | undefined, start: number): {
  sql: string;
  params: string[];
} {
  const claims = [
    ...(subject?.principals ?? []).slice(0, 256).map((value) => ({ principals: [value] })),
    ...(subject?.groups ?? []).slice(0, 256).map((value) => ({ groups: [value] })),
  ];
  const params = claims.map((claim) => JSON.stringify(claim));
  const matches = params.map((_, index) => `source_access @> $${start + index}::jsonb`);
  return { sql: `(${[OPEN_SOURCE_ACCESS, ...matches].join(" OR ")})`, params };
}

function sourceAccessAllows(raw: unknown, subject: AccessSubject | undefined): boolean {
  const access = parseJson<SourceAccess>(raw, { principals: [], groups: [] });
  if (access.principals.length === 0 && access.groups.length === 0) return true;
  if (!subject) return false;
  const principals = new Set(subject.principals);
  const groups = new Set(subject.groups);
  return access.principals.some((value) => principals.has(value)) ||
    access.groups.some((value) => groups.has(value));
}

function classificationAllowsRead(raw: unknown): boolean {
  const classification = parseJson<DataClassification>(raw, {
    sensitivity: "restricted", piiSubjects: [], secretKinds: [], allowedDestinations: [],
  });
  return (classification.sensitivity === "public" || classification.sensitivity === "internal") ||
    classification.allowedDestinations.includes("agent-context");
}

function companyPublishedShapeAllows(row: Record<string, unknown>): boolean {
  if (row.scope !== "org" || row.tier !== "L2" || row.type === "pointer") return false;
  const provenance = parseJson<ProvenanceEntry[]>(row.provenance, []);
  return provenance.length > 0 && provenance.every((entry) =>
    entry.cache !== true &&
    (entry.source === "document" || entry.source === "consolidation"));
}

/** Shared query-layer fence for a team's server-resolved company-memory grant. */
export function companyPublishedSql(
  subject: AccessSubject | undefined,
  start: number,
  memoryTable = "memory_objects",
): { sql: string; params: Array<string | number> } {
  const grant = subject?.teamMemoryGrant;
  if (!grant) return { sql: "FALSE", params: [] };
  return {
    sql: `(
      ${memoryTable}.scope = 'org'
      AND ${memoryTable}.tier = 'L2'
      AND ${memoryTable}.type <> 'pointer'
      AND NOT (${memoryTable}.provenance @> '[{"cache": true}]'::jsonb)
      AND jsonb_array_length(${memoryTable}.provenance) > 0
      AND NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(${memoryTable}.provenance) AS origin
         WHERE origin->>'source' IS NULL
            OR origin->>'source' NOT IN ('document', 'consolidation')
      )
      AND EXISTS (
        SELECT 1
          FROM org_teams viewer_team
          JOIN org_teams publisher_team
            ON publisher_team.namespace = ${memoryTable}.namespace
           AND publisher_team.organization_namespace = viewer_team.organization_namespace
         WHERE viewer_team.id = $${start}::text
           AND viewer_team.memory_access_mode = 'company-published'
           AND viewer_team.memory_access_version = $${start + 1}::integer
           AND publisher_team.id <> viewer_team.id
           AND strpos(
             publisher_team.namespace,
             viewer_team.namespace || '/'
           ) <> 1
      )
    )`,
    params: [grant.teamId, grant.version],
  };
}

/**
 * A row is TTL-visible when its base TTL has not elapsed since assertion — or,
 * for a write-back-CACHED fact (D14: "reuse extends life"), while the cache
 * keeper's usage-scaled idle window is still open: anchored on the last touch
 * (falling back to assertion), base TTL doubled per recorded access, capped at
 * 24h. This mirrors `idleWindowSeconds` in src/federation/cachekeeper.ts
 * EXACTLY, so a cached fact is readable precisely as long as the sweeper would
 * keep it — a reused cached fact can never go invisible-but-active ("zombie"),
 * which previously made every re-fault mint an un-deduped duplicate row.
 * Non-cached TTL rows keep the original assertion-anchored semantics.
 */
export const TTL_ACTIVE_CLAUSE = `(ttl_seconds IS NULL
  OR assertion_time + ttl_seconds * INTERVAL '1 second' > CURRENT_TIMESTAMP
  OR (provenance @> '[{"cache": true}]'::jsonb
      AND COALESCE(last_accessed, assertion_time)
        + LEAST(ttl_seconds * POWER(2, LEAST(access_count, 30)), 86400)
          * INTERVAL '1 second' > CURRENT_TIMESTAMP))`;

export class MemoryIndex {
  private mountedMemoryRefs?: (namespace: Namespace) => Promise<MemoryId[]>;

  constructor(private readonly db: Db) {}

  /** Kernel-owned explicit-mount resolver; drivers never see or implement it. */
  setMountedMemoryResolver(resolve: (namespace: Namespace) => Promise<MemoryId[]>): void {
    this.mountedMemoryRefs = resolve;
  }

  private async mounted(namespace: Namespace): Promise<MemoryId[]> {
    return this.mountedMemoryRefs ? this.mountedMemoryRefs(namespace) : [];
  }

  private async companyPublishedAllows(
    row: Record<string, unknown>,
    access: AccessSubject | undefined,
  ): Promise<boolean> {
    const grant = access?.teamMemoryGrant;
    if (!grant || !companyPublishedShapeAllows(row)) return false;
    const result = await this.db.query(
      `SELECT 1
         FROM org_teams viewer_team
         JOIN org_teams publisher_team
           ON publisher_team.namespace = $3
          AND publisher_team.organization_namespace = viewer_team.organization_namespace
        WHERE viewer_team.id = $1
          AND viewer_team.memory_access_mode = 'company-published'
          AND viewer_team.memory_access_version = $2
          AND publisher_team.id <> viewer_team.id
          AND strpos(
            publisher_team.namespace,
            viewer_team.namespace || '/'
          ) <> 1`,
      [grant.teamId, grant.version, row.namespace],
    );
    return result.rows.length === 1;
  }

  async insert(obj: MemoryObject, embedding: number[] | null): Promise<void> {
    const fenceNamespaces = writeFenceNamespaces(obj.namespace);
    const fenceTimestampParam = 23 + fenceNamespaces.length;
    const fenceValues = fenceNamespaces
      .map((_, i) => `($${23 + i}, 1, $${fenceTimestampParam})`)
      .join(", ");
    const governed = obj.provenance.find((entry) => entry.classification !== undefined);
    const classification = obj.classification ?? governed?.classification ?? {
      // Direct index writes are kernel-internal and predate M7 metadata. Keep
      // their established schema default; untrusted/source content reaches
      // this repository only through WritePath, which classifies before insert.
      sensitivity: "internal" as const,
      piiSubjects: [],
      secretKinds: [],
      allowedDestinations: [],
    };
    const sourceAccess = obj.sourceAccess ?? governed?.sourceAccess ?? {
      principals: [],
      groups: [],
    };
    await this.db.query(
      `WITH fence AS (
         INSERT INTO erasure_fences (namespace, generation, updated_at)
         VALUES ${fenceValues}
         ON CONFLICT (namespace) DO UPDATE SET
           generation = erasure_fences.generation + 1,
           updated_at = EXCLUDED.updated_at
         RETURNING namespace
       )
       INSERT INTO memory_objects (
         id, namespace, scope, tier, backend_ref, content, type, confidence,
         event_time, assertion_time, t_valid_from, t_valid_to, supersedes,
         provenance, classification, source_access, ttl_seconds, last_accessed,
         access_count, fault_count, status, embedding
       ) SELECT
         $1, $2, $3, $4, $5, $6, $7, $8,
         $9, $10, $11, $12, $13,
         $14, $15, $16, $17, $18, $19, $20,
         $21, $22::vector
       FROM (SELECT count(*) FROM fence) AS fence_lock`,
      [
        obj.id,
        obj.namespace,
        obj.scope,
        obj.tier,
        obj.backendRef,
        obj.content,
        obj.type,
        obj.confidence,
        obj.eventTime,
        obj.assertionTime,
        obj.tValidFrom,
        obj.tValidTo,
        obj.supersedes,
        JSON.stringify(obj.provenance),
        JSON.stringify(classification),
        JSON.stringify(sourceAccess),
        obj.ttlSeconds,
        obj.telemetry.lastAccessed,
        obj.telemetry.accessCount,
        obj.telemetry.faultCount,
        obj.status,
        embedding === null ? null : toVectorLiteral(embedding),
        ...fenceNamespaces,
        new Date().toISOString(),
      ],
    );
  }

  /**
   * ACL-checked point read. Returns { obj: null, denied: false } for a miss
   * (row does not exist) and { obj: null, denied: true } when the row exists
   * but is outside the caller's visibility — caller audits accordingly.
   */
  async getById(
    id: MemoryId,
    callerNamespace: Namespace,
    access?: AccessSubject,
  ): Promise<GetByIdResult> {
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM memory_objects
       WHERE id = $1
         AND status = 'active'
         AND t_valid_to IS NULL
         AND ${TTL_ACTIVE_CLAUSE}`,
      [id],
    );
    if (res.rows.length === 0) return { obj: null, denied: false };
    const row = res.rows[0] as Record<string, unknown>;
    const allowed = namespaceAncestors(callerNamespace).includes(row.namespace as string) ||
      readScopeAllows(access?.memoryReadScope, row.namespace as string) ||
      (await this.mounted(callerNamespace)).includes(id) ||
      await this.companyPublishedAllows(row, access);
    if (!allowed || !sourceAccessAllows(row.source_access, access) ||
        !classificationAllowsRead(row.classification)) {
      return { obj: null, denied: true };
    }
    return { obj: rowToMemoryObject(row), denied: false };
  }

  /**
   * M8 query-fence lookup for one exact governed backend surface. Filtering is
   * applied before the row leaves Postgres: namespace ancestry, source-native
   * ACL, classification destination, lifecycle, and the exact pointer stamp.
   */
  async getPointerBySource(
    callerNamespace: Namespace,
    connectorId: string,
    sourceRef: string,
    access?: AccessSubject,
  ): Promise<MemoryObject | null> {
    const allowed = namespaceAncestors(callerNamespace);
    const nsPlaceholders = allowed.map((_, index) => `$${index + 1}`).join(", ");
    const pointerParam = allowed.length + 1;
    const sourceAccess = sourceAccessSql(access, pointerParam + 1);
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM memory_objects
       WHERE namespace IN (${nsPlaceholders})
         AND type = 'pointer'
         AND status = 'active'
         AND t_valid_to IS NULL
         AND ${TTL_ACTIVE_CLAUSE}
         AND provenance @> $${pointerParam}::jsonb
         AND ${sourceAccess.sql}
         AND ${CLASSIFICATION_READ_ALLOWED}
       ORDER BY assertion_time DESC, id DESC
       LIMIT 1`,
      [
        ...allowed,
        JSON.stringify([{ pointer: true, connectorId, sourceRef }]),
        ...sourceAccess.params,
      ],
    );
    return res.rows.length === 1
      ? rowToMemoryObject(res.rows[0] as Record<string, unknown>)
      : null;
  }

  /**
   * M6 query-fence existence probe for live source routes. This must filter
   * `type = 'pointer'` before limiting: using the general candidate window can
   * hide every pointer behind newer ordinary facts in a populated namespace.
   */
  async hasPointerCandidates(
    callerNamespace: Namespace,
    access?: AccessSubject,
  ): Promise<boolean> {
    const allowed = namespaceAncestors(callerNamespace);
    const mounted = await this.mounted(callerNamespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 1}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = companyPublishedSql(access, allowed.length + mounted.length + 1);
    const scope = readScopeSql(
      access?.memoryReadScope,
      allowed.length + mounted.length + company.params.length + 1,
    );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 1,
    );
    const res = await this.db.query(
      `SELECT 1 FROM memory_objects
       WHERE ${visibility}
         AND type = 'pointer'
         AND status = 'active'
         AND t_valid_to IS NULL
         AND ${TTL_ACTIVE_CLAUSE}
         AND ${sourceAccess.sql}
         AND ${CLASSIFICATION_READ_ALLOWED}
       LIMIT 1`,
      [
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
      ],
    );
    return res.rows.length === 1;
  }

  /**
   * ACL-scoped pointer-only corpus for the embedding brownout lane. Filtering
   * happens in Postgres before LIMIT so ordinary memory volume cannot evict a
   * valid backend route from the fallback ranker.
   */
  async listPointerCandidates(
    callerNamespace: Namespace,
    { limit = 500, access }: Pick<ListCandidatesOptions, "limit" | "access"> = {},
  ): Promise<MemoryObject[]> {
    const boundedLimit = Math.min(Math.max(Math.floor(limit), 1), 1_000);
    const allowed = namespaceAncestors(callerNamespace);
    const mounted = await this.mounted(callerNamespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 1}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = companyPublishedSql(access, allowed.length + mounted.length + 1);
    const scope = readScopeSql(
      access?.memoryReadScope,
      allowed.length + mounted.length + company.params.length + 1,
    );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 1,
    );
    const limitParam = allowed.length + mounted.length + company.params.length +
      scopeParams.length + sourceAccess.params.length + 1;
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM memory_objects
       WHERE ${visibility}
         AND type = 'pointer'
         AND status = 'active'
         AND t_valid_to IS NULL
         AND ${TTL_ACTIVE_CLAUSE}
         AND ${sourceAccess.sql}
         AND ${CLASSIFICATION_READ_ALLOWED}
       ORDER BY assertion_time DESC, id DESC
       LIMIT $${limitParam}`,
      [
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
        boundedLimit,
      ],
    );
    return res.rows.map((row) => rowToMemoryObject(row as Record<string, unknown>));
  }

  /**
   * ACL-scoped pointer-only vector search. `type = 'pointer'` is part of the
   * authoritative query, not a post-LIMIT filter, so ordinary L2 facts cannot
   * crowd backend routes out of the nearest-neighbour window.
   */
  async vectorSearchPointers(
    callerNamespace: Namespace,
    embedding: number[],
    k: number,
    access?: AccessSubject,
  ): Promise<VectorHit[]> {
    const boundedLimit = Math.min(Math.max(Math.floor(k), 1), 1_000);
    const allowed = namespaceAncestors(callerNamespace);
    const mounted = await this.mounted(callerNamespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 2}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 2}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = companyPublishedSql(access, allowed.length + mounted.length + 2);
    const scope = readScopeSql(
      access?.memoryReadScope,
      allowed.length + mounted.length + company.params.length + 2,
    );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 2,
    );
    const limitParam = allowed.length + mounted.length + company.params.length +
      scopeParams.length + sourceAccess.params.length + 2;
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS}, (embedding <=> $1::vector) AS distance
       FROM memory_objects
       WHERE embedding IS NOT NULL
         AND ${visibility}
         AND type = 'pointer'
         AND status = 'active'
         AND t_valid_to IS NULL
         AND ${TTL_ACTIVE_CLAUSE}
         AND ${sourceAccess.sql}
         AND ${CLASSIFICATION_READ_ALLOWED}
       ORDER BY embedding <=> $1::vector
       LIMIT $${limitParam}`,
      [
        toVectorLiteral(embedding),
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
        boundedLimit,
      ],
    );
    return res.rows.map((raw) => {
      const row = raw as Record<string, unknown>;
      return {
        obj: rowToMemoryObject(row),
        similarity: 1 - Number(row.distance),
      };
    });
  }

  /**
   * ACL-scoped active rows for in-memory BM25 (module C consumes this).
   * validOnly (default true) restricts to currently-valid facts.
   */
  async listCandidates(
    callerNamespace: Namespace,
    {
      validOnly = true,
      limit = 500,
      includePointers = false,
      access,
      sourceIds,
    }: ListCandidatesOptions = {},
  ): Promise<MemoryObject[]> {
    const allowed = namespaceAncestors(callerNamespace);
    const mounted = await this.mounted(callerNamespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 1}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = companyPublishedSql(access, allowed.length + mounted.length + 1);
    const scope = readScopeSql(
      access?.memoryReadScope,
      allowed.length + mounted.length + company.params.length + 1,
    );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const validClause = validOnly ? "AND t_valid_to IS NULL" : "";
    const pointerClause = includePointers ? "" : "AND type <> 'pointer'";
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 1,
    );
    const sourceFilter = sourceIdsSql(
      sourceIds,
      allowed.length + mounted.length + company.params.length + scopeParams.length +
        sourceAccess.params.length + 1,
    );
    const limitParam = allowed.length + mounted.length + company.params.length +
      scopeParams.length + sourceAccess.params.length + (sourceFilter?.params.length ?? 0) + 1;
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS} FROM memory_objects
       WHERE ${visibility}
         AND status = 'active'
         AND ${TTL_ACTIVE_CLAUSE}
         AND ${sourceAccess.sql}
         ${sourceFilter ? `AND ${sourceFilter.sql}` : ""}
         AND ${CLASSIFICATION_READ_ALLOWED}
         ${validClause}
         ${pointerClause}
       ORDER BY assertion_time DESC, id DESC
       LIMIT $${limitParam}`,
      [
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
        ...(sourceFilter?.params ?? []),
        limit,
      ],
    );
    return res.rows.map((r) => rowToMemoryObject(r as Record<string, unknown>));
  }

  /**
   * ACL-scoped full-corpus lexical preselection for retriever cartridges.
   * Unlike `listCandidates`, this is query-selected before LIMIT, so an older
   * relevant fact cannot disappear merely because 500 newer rows exist. The
   * generated `search_document` weights the human/source title above body and
   * provenance text; the baseline driver still performs its normal BM25 merge
   * over this bounded pool.
   */
  async listLexicalCandidates(
    callerNamespace: Namespace,
    query: string,
    {
      validOnly = true,
      limit = 128,
      includePointers = false,
      access,
      sourceIds,
    }: ListCandidatesOptions = {},
  ): Promise<MemoryObject[]> {
    const tsQuery = lexicalOrQuery(query);
    if (!tsQuery || limit <= 0) return [];
    const boundedLimit = Math.min(Math.max(Math.floor(limit), 1), 1_000);
    const allowed = namespaceAncestors(callerNamespace);
    const mounted = await this.mounted(callerNamespace);
    // $1 is the server-derived tsquery. ACL parameters therefore start at $2,
    // mirroring vectorSearch's query-vector offset.
    const nsPlaceholders = allowed.map((_, i) => `$${i + 2}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 2}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = companyPublishedSql(access, allowed.length + mounted.length + 2);
    const scope = readScopeSql(
      access?.memoryReadScope,
      allowed.length + mounted.length + company.params.length + 2,
    );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const validClause = validOnly ? "AND t_valid_to IS NULL" : "";
    const pointerClause = includePointers ? "" : "AND type <> 'pointer'";
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 2,
    );
    const sourceFilter = sourceIdsSql(
      sourceIds,
      allowed.length + mounted.length + company.params.length + scopeParams.length +
        sourceAccess.params.length + 2,
    );
    const limitParam = allowed.length + mounted.length + company.params.length +
      scopeParams.length + sourceAccess.params.length + (sourceFilter?.params.length ?? 0) + 2;
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS},
              ts_rank_cd(search_document, to_tsquery('simple', $1), 32) AS lexical_rank
         FROM memory_objects
        WHERE ${visibility}
          AND status = 'active'
          AND ${TTL_ACTIVE_CLAUSE}
          AND ${sourceAccess.sql}
          ${sourceFilter ? `AND ${sourceFilter.sql}` : ""}
          AND ${CLASSIFICATION_READ_ALLOWED}
          AND search_document @@ to_tsquery('simple', $1)
          ${validClause}
          ${pointerClause}
        ORDER BY lexical_rank DESC, assertion_time DESC, id DESC
        LIMIT $${limitParam}`,
      [
        tsQuery,
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
        ...(sourceFilter?.params ?? []),
        boundedLimit,
      ],
    );
    return res.rows.map((row) => rowToMemoryObject(row as Record<string, unknown>));
  }

  /**
   * ACL-scoped cosine nearest-neighbour search over active rows.
   * similarity = 1 - cosine distance.
   *
   * `ownNamespaceOnly` restricts the query to rows in EXACTLY the caller's
   * namespace (no ancestors). The write path uses this for dedupe/
   * supersedence targeting: with the ACL-scoped query, 8+ closer ancestor
   * rows could crowd the k-window and hide the caller's own conflicting
   * fact, silently skipping supersedence (two currently-valid conflicting
   * facts — a D7 violation).
   *
   * `includePointers` (default false — M6/D11): pointer facts are routes, not
   * answers, so retrieval never sees them; the write path opts in so a pointer
   * re-mint can still find (dedupe/supersede) its stale predecessor.
   */
  async vectorSearch(
    callerNamespace: Namespace,
    embedding: number[],
    k: number,
    validOnly = true,
    ownNamespaceOnly = false,
    includePointers = false,
    access?: AccessSubject,
    sourceIds?: readonly string[],
  ): Promise<VectorHit[]> {
    const allowed = ownNamespaceOnly
      ? [callerNamespace]
      : namespaceAncestors(callerNamespace);
    const mounted = ownNamespaceOnly ? [] : await this.mounted(callerNamespace);
    const nsPlaceholders = allowed.map((_, i) => `$${i + 2}`).join(", ");
    const mountedPlaceholders = mounted.map((_, i) => `$${allowed.length + i + 2}`).join(", ");
    const legacyVisibility = mounted.length > 0
      ? `(namespace IN (${nsPlaceholders}) OR id IN (${mountedPlaceholders}))`
      : `namespace IN (${nsPlaceholders})`;
    const company = ownNamespaceOnly
      ? { sql: "FALSE", params: [] as Array<string | number> }
      : companyPublishedSql(access, allowed.length + mounted.length + 2);
    const scope = ownNamespaceOnly
      ? null
      : readScopeSql(
          access?.memoryReadScope,
          allowed.length + mounted.length + company.params.length + 2,
        );
    const scopeParams = scope?.params ?? [];
    const widening = [
      ...(company.params.length > 0 ? [company.sql] : []),
      ...(scope ? [scope.sql] : []),
    ];
    const visibility = widening.length > 0
      ? `(${legacyVisibility} OR ${widening.join(" OR ")})`
      : legacyVisibility;
    const validClause = validOnly ? "AND t_valid_to IS NULL" : "";
    const pointerClause = includePointers ? "" : "AND type <> 'pointer'";
    const sourceAccess = sourceAccessSql(
      access,
      allowed.length + mounted.length + company.params.length + scopeParams.length + 2,
    );
    const sourceFilter = sourceIdsSql(
      sourceIds,
      allowed.length + mounted.length + company.params.length + scopeParams.length +
        sourceAccess.params.length + 2,
    );
    const limitParam = allowed.length + mounted.length + company.params.length +
      scopeParams.length + sourceAccess.params.length + (sourceFilter?.params.length ?? 0) + 2;
    const res = await this.db.query(
      `SELECT ${SELECT_COLUMNS}, (embedding <=> $1::vector) AS distance
       FROM memory_objects
       WHERE embedding IS NOT NULL
         AND ${visibility}
         AND status = 'active'
         AND ${TTL_ACTIVE_CLAUSE}
         AND ${sourceAccess.sql}
         ${sourceFilter ? `AND ${sourceFilter.sql}` : ""}
         AND ${CLASSIFICATION_READ_ALLOWED}
         ${validClause}
         ${pointerClause}
       ORDER BY embedding <=> $1::vector
       LIMIT $${limitParam}`,
      [
        toVectorLiteral(embedding),
        ...allowed,
        ...mounted,
        ...company.params,
        ...scopeParams,
        ...sourceAccess.params,
        ...(sourceFilter?.params ?? []),
        k,
      ],
    );
    return res.rows.map((r) => {
      const row = r as Record<string, unknown>;
      return {
        obj: rowToMemoryObject(row),
        similarity: 1 - Number(row.distance),
      };
    });
  }

  /**
   * Close a row's validity interval (supersedence step 1 — never overwrite).
   * Guarded: only a CURRENTLY-VALID row is closed, so a concurrent writer
   * that already closed the same victim can never silently overwrite its
   * t_valid_to (D7). Returns the number of rows closed — 0 means the row was
   * already closed (callers re-run their supersede decision).
   */
  async closeValidity(id: MemoryId, ts: string): Promise<number> {
    const res = await this.db.query(
      `UPDATE memory_objects SET t_valid_to = $2
       WHERE id = $1 AND t_valid_to IS NULL
       RETURNING id`,
      [id, ts],
    );
    return res.rows.length;
  }

  /** Telemetry: bump access counters + last_accessed for retrieved rows. */
  async bumpAccess(ids: MemoryId[]): Promise<void> {
    if (ids.length === 0) return;
    const placeholders = ids.map((_, i) => `$${i + 2}`).join(", ");
    await this.db.query(
      `UPDATE memory_objects
       SET access_count = access_count + 1, last_accessed = $1
       WHERE id IN (${placeholders})`,
      [new Date().toISOString(), ...ids],
    );
  }

  /** Telemetry: bump fault counter + last_accessed for a faulted-in row. */
  async bumpFault(id: MemoryId): Promise<void> {
    await this.db.query(
      `UPDATE memory_objects
       SET fault_count = fault_count + 1, last_accessed = $1
       WHERE id = $2`,
      [new Date().toISOString(), id],
    );
  }

  /** Count of active rows in exactly this namespace. */
  async countByNamespace(namespace: Namespace): Promise<number> {
    const res = await this.db.query(
      `SELECT COUNT(*) AS n FROM memory_objects
       WHERE namespace = $1 AND status = 'active' AND ${TTL_ACTIVE_CLAUSE}`,
      [namespace],
    );
    return Number(res.rows[0].n);
  }

  /** Most-accessed active rows in a namespace (MemStats.topAccessed shape). */
  async topAccessed(
    namespace: Namespace,
    n: number,
  ): Promise<{ id: MemoryId; content: string; accessCount: number }[]> {
    const res = await this.db.query(
      `SELECT id, content, access_count FROM memory_objects
       WHERE namespace = $1 AND status = 'active' AND ${TTL_ACTIVE_CLAUSE}
       ORDER BY access_count DESC, id ASC
       LIMIT $2`,
      [namespace, n],
    );
    return res.rows.map((r) => ({
      id: r.id as MemoryId,
      content: r.content as string,
      accessCount: Number(r.access_count),
    }));
  }
}
