import { ulid } from "ulid";
import { escapeLikePattern, type Db } from "../db/client.js";
import type {
  KnowledgeBaseCreateInput,
  KnowledgeBaseKind,
  KnowledgeBaseLifecycleState,
  KnowledgeBaseListQuery,
  KnowledgeBaseListResult,
  KnowledgeBaseStatus,
  KnowledgeBaseSummary,
  Namespace,
} from "../types.js";

const MAX_NAMESPACE_LENGTH = 512;
const MAX_ACTOR_LENGTH = 512;
const MAX_NAME_LENGTH = 200;
const MAX_FUNCTION_LENGTH = 120;
const MAX_DESCRIPTION_LENGTH = 2_000;
const MAX_SOURCE_ID_LENGTH = 128;
const MAX_SEARCH_LENGTH = 200;
const MAX_VISIBLE_NAMESPACES = 1_024;
const MAX_PAGE_SIZE = 100;
const CONTROL_CHARACTER = /\p{Cc}/u;

const KINDS = new Set<KnowledgeBaseKind>(["file", "folder", "url"]);
const STATUSES = new Set<KnowledgeBaseStatus>([
  "empty",
  "processing",
  "ready",
  "needs_review",
  "failed",
]);
const LIFECYCLE_STATES = new Set<KnowledgeBaseLifecycleState>([
  "active",
  "paused",
  "archived",
]);

export class KnowledgeBaseValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KnowledgeBaseValidationError";
  }
}

export class KnowledgeBaseNotFoundError extends Error {
  constructor(message = "Knowledge base not found") {
    super(message);
    this.name = "KnowledgeBaseNotFoundError";
  }
}

export class KnowledgeBaseConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KnowledgeBaseConflictError";
  }
}

/** Editable metadata only. The kernel resolves team, namespace, and actor first. */
export type KnowledgeBaseMetadataInput = Omit<
  KnowledgeBaseCreateInput,
  "targetTeamId"
>;

/** Trusted result of kernel identity/team resolution; never construct from a body. */
export interface ResolvedKnowledgeBaseContext {
  namespace: Namespace;
  actor: string;
  targetTeamId: string | null;
}

/** Trusted exact ancestor list produced by the query-layer ACL seam. */
export interface KnowledgeBaseReadContext {
  visibleNamespaces: readonly Namespace[];
}

/** Trusted exact landing namespace for an owner/admin lifecycle operation. */
export interface KnowledgeBaseMutationContext {
  namespace: Namespace;
  actor: string;
}

interface KnowledgeBaseRow {
  id: string;
  namespace: string;
  target_team_id: string | null;
  name: string;
  kind: KnowledgeBaseKind;
  derived_status: KnowledgeBaseStatus;
  lifecycle_state: KnowledgeBaseLifecycleState;
  source_id: string | null;
  primary_business_function: string;
  description: string;
  data_sensitive: boolean;
  created_by: string;
  created_at: string | Date;
  updated_at: string | Date;
  file_count: number | string;
  source_count: number | string;
  item_count: number | string;
  fact_count: number | string;
}

interface NormalizedCreate {
  name: string;
  kind: KnowledgeBaseKind;
  sourceId: string | null;
  primaryBusinessFunction: string;
  description: string;
  dataSensitive: boolean;
}

const DERIVED_CTE = `WITH file_rollup AS (
  SELECT knowledge_base_id,
         count(*)::integer AS file_count,
         coalesce(sum(fact_count), 0)::integer AS fact_count,
         sum(CASE WHEN status = 'processing' THEN 1 ELSE 0 END)::integer AS processing_count,
         sum(CASE WHEN status = 'needs_review' THEN 1 ELSE 0 END)::integer AS review_count,
         sum(CASE WHEN status = 'ready' THEN 1 ELSE 0 END)::integer AS ready_count
    FROM company_files
   WHERE lifecycle_state = 'active' AND t_valid_to IS NULL
   GROUP BY knowledge_base_id
), source_rollup AS (
  SELECT ks.knowledge_base_id,
         count(*)::integer AS source_count,
         sum(CASE WHEN ks.status = 'processing' OR source.sync_status IN ('never_synced', 'pending') THEN 1 ELSE 0 END)::integer AS processing_count,
         sum(CASE WHEN ks.status = 'needs_review' THEN 1 ELSE 0 END)::integer AS review_count,
         sum(CASE WHEN ks.status = 'active' AND source.sync_status = 'synced' THEN 1 ELSE 0 END)::integer AS ready_count
    FROM knowledge_sources ks
    LEFT JOIN sources source ON source.id = ks.source_id
   WHERE ks.t_valid_to IS NULL AND ks.status <> 'archived'
   GROUP BY ks.knowledge_base_id
), derived AS (
  SELECT kb.id, kb.namespace, kb.target_team_id, kb.name, kb.kind,
         CASE
           WHEN kb.kind = 'file' THEN CASE
             WHEN coalesce(fr.processing_count, 0) + coalesce(sr.processing_count, 0) > 0 THEN 'processing'
             WHEN coalesce(fr.review_count, 0) + coalesce(sr.review_count, 0) > 0 THEN 'needs_review'
             WHEN coalesce(fr.ready_count, 0) + coalesce(sr.ready_count, 0) > 0 THEN 'ready'
             WHEN coalesce(fr.file_count, 0) + coalesce(sr.source_count, 0) > 0 THEN 'failed'
             ELSE 'empty'
           END
           WHEN source.sync_status = 'pending' THEN 'processing'
           WHEN source.sync_status = 'synced' THEN 'ready'
           WHEN source.sync_status = 'failed' THEN 'failed'
           ELSE 'empty'
         END AS derived_status,
         kb.lifecycle_state, kb.source_id, kb.primary_business_function,
         kb.description, kb.data_sensitive, kb.created_by, kb.created_at,
         kb.updated_at, coalesce(fr.file_count, 0)::integer AS file_count,
         coalesce(sr.source_count, 0)::integer AS source_count,
         (coalesce(fr.file_count, 0) + coalesce(sr.source_count, 0))::integer AS item_count,
         coalesce(fr.fact_count, 0)::integer AS fact_count
    FROM knowledge_bases kb
    LEFT JOIN sources source ON source.id = kb.source_id
    LEFT JOIN file_rollup fr ON fr.knowledge_base_id = kb.id
    LEFT JOIN source_rollup sr ON sr.knowledge_base_id = kb.id
)`;

export class KnowledgeBaseStore {
  private readonly now: () => Date;

  constructor(
    private readonly db: Db,
    now?: () => Date,
  ) {
    this.now = now ?? (() => new Date());
  }

  async create(
    input: KnowledgeBaseMetadataInput,
    context: ResolvedKnowledgeBaseContext,
  ): Promise<KnowledgeBaseSummary> {
    const normalized = normalizeCreate(input);
    const trusted = normalizeResolvedContext(context);
    const id = ulid();
    const createdAt = this.now().toISOString();

    await this.db.transaction(async (tx) => {
      if (trusted.targetTeamId !== null) {
        const team = await tx.query(
          `SELECT id FROM org_teams WHERE id = $1 AND namespace = $2 FOR UPDATE`,
          [trusted.targetTeamId, trusted.namespace],
        );
        if (team.rows.length !== 1) {
          throw new KnowledgeBaseValidationError(
            "target team does not belong to the resolved namespace",
          );
        }
      }

      if (normalized.kind === "file") {
        if (normalized.sourceId !== null) {
          throw new KnowledgeBaseValidationError(
            "file knowledge bases cannot bind a connector source",
          );
        }
      } else {
        if (normalized.sourceId === null) {
          throw new KnowledgeBaseValidationError(
            `${normalized.kind} knowledge bases require a sourceId`,
          );
        }
        const expectedKind = normalized.kind === "folder" ? "filesystem" : "doc_site";
        const source = await tx.query(
          `SELECT id FROM sources
            WHERE id = $1 AND namespace = $2 AND kind = $3
              AND lifecycle_state = 'active'
            FOR UPDATE`,
          [normalized.sourceId, trusted.namespace, expectedKind],
        );
        if (source.rows.length !== 1) {
          throw new KnowledgeBaseValidationError(
            `${normalized.kind} source must be an active same-namespace ${expectedKind} source`,
          );
        }
      }

      await tx.query(
        `INSERT INTO knowledge_bases
           (id, namespace, target_team_id, name, kind, status, lifecycle_state,
            source_id, primary_business_function, description, data_sensitive,
            supersedes, t_valid_from, t_valid_to, created_by, created_at,
            updated_at, archived_at)
         VALUES
           ($1, $2, $3, $4, $5, 'empty', 'active', $6, $7, $8, $9,
            NULL, $10, NULL, $11, $10, $10, NULL)`,
        [
          id,
          trusted.namespace,
          trusted.targetTeamId,
          normalized.name,
          normalized.kind,
          normalized.sourceId,
          normalized.primaryBusinessFunction,
          normalized.description,
          normalized.dataSensitive,
          createdAt,
          trusted.actor,
        ],
      );
    });

    return {
      id,
      namespace: trusted.namespace,
      targetTeamId: trusted.targetTeamId,
      name: normalized.name,
      kind: normalized.kind,
      status: "empty",
      lifecycleState: "active",
      sourceId: normalized.sourceId,
      primaryBusinessFunction: normalized.primaryBusinessFunction,
      description: normalized.description,
      dataSensitive: normalized.dataSensitive,
      fileCount: 0,
      sourceCount: 0,
      itemCount: 0,
      factCount: 0,
      createdBy: trusted.actor,
      createdAt,
      updatedAt: createdAt,
    };
  }

  async get(
    rawId: string,
    context: KnowledgeBaseReadContext,
  ): Promise<KnowledgeBaseSummary | null> {
    const id = requiredString(rawId, "id", MAX_SOURCE_ID_LENGTH);
    const visibleNamespaces = normalizeVisibleNamespaces(context.visibleNamespaces);
    if (visibleNamespaces.length === 0) return null;
    const placeholders = visibleNamespaces.map((_, index) => `$${index + 2}`).join(", ");
    const result = await this.db.query(
      `${DERIVED_CTE}
       SELECT * FROM derived
        WHERE id = $1 AND namespace IN (${placeholders})`,
      [id, ...visibleNamespaces],
    );
    return result.rows.length === 0
      ? null
      : rowToSummary(result.rows[0] as KnowledgeBaseRow);
  }

  async list(
    rawQuery: KnowledgeBaseListQuery,
    context: KnowledgeBaseReadContext,
  ): Promise<KnowledgeBaseListResult> {
    const query = normalizeListQuery(rawQuery);
    const visibleNamespaces = normalizeVisibleNamespaces(context.visibleNamespaces);
    if (visibleNamespaces.length === 0) return emptyList(query.page, query.pageSize);

    const params: unknown[] = [...visibleNamespaces];
    const namespaceParams = visibleNamespaces.map((_, index) => `$${index + 1}`).join(", ");
    const filters = [`namespace IN (${namespaceParams})`];
    const bind = (value: unknown): string => {
      params.push(value);
      return `$${params.length}`;
    };

    if (query.query !== "") {
      filters.push(
        `lower(name) LIKE ${bind(`%${escapeLikePattern(query.query.toLowerCase())}%`)} ESCAPE '\\'`,
      );
    }
    if (query.targetTeamId !== undefined) {
      filters.push(`target_team_id = ${bind(query.targetTeamId)}`);
    }
    if (query.kind !== undefined) filters.push(`kind = ${bind(query.kind)}`);
    if (query.status !== undefined) {
      filters.push(`derived_status = ${bind(query.status)}`);
    }
    if (query.lifecycleState !== undefined) {
      filters.push(`lifecycle_state = ${bind(query.lifecycleState)}`);
    }

    const where = filters.join(" AND ");
    const countResult = await this.db.query(
      `${DERIVED_CTE} SELECT count(*) AS total FROM derived WHERE ${where}`,
      params,
    );
    const total = Number(countResult.rows[0]?.total ?? 0);
    const limitParam = bind(query.pageSize);
    const offsetParam = bind((query.page - 1) * query.pageSize);
    const result = await this.db.query(
      `${DERIVED_CTE}
       SELECT * FROM derived WHERE ${where}
       ORDER BY created_at DESC, id DESC
       LIMIT ${limitParam} OFFSET ${offsetParam}`,
      params,
    );

    return {
      data: result.rows.map((row) => rowToSummary(row as KnowledgeBaseRow)),
      pagination: {
        page: query.page,
        pageSize: query.pageSize,
        total,
        totalPages: total === 0 ? 0 : Math.ceil(total / query.pageSize),
      },
    };
  }

  async pause(
    id: string,
    context: KnowledgeBaseMutationContext,
  ): Promise<KnowledgeBaseSummary> {
    return this.transition(id, context, "paused");
  }

  async resume(
    id: string,
    context: KnowledgeBaseMutationContext,
  ): Promise<KnowledgeBaseSummary> {
    return this.transition(id, context, "active");
  }

  async archive(
    id: string,
    context: KnowledgeBaseMutationContext,
  ): Promise<KnowledgeBaseSummary> {
    return this.transition(id, context, "archived");
  }

  private async transition(
    rawId: string,
    rawContext: KnowledgeBaseMutationContext,
    next: KnowledgeBaseLifecycleState,
  ): Promise<KnowledgeBaseSummary> {
    const id = requiredString(rawId, "id", MAX_SOURCE_ID_LENGTH);
    const context = normalizeMutationContext(rawContext);
    const at = this.now().toISOString();

    await this.db.transaction(async (tx) => {
      const selected = await tx.query(
        `SELECT lifecycle_state FROM knowledge_bases
          WHERE id = $1 AND namespace = $2 FOR UPDATE`,
        [id, context.namespace],
      );
      if (selected.rows.length !== 1) throw new KnowledgeBaseNotFoundError();
      const current = selected.rows[0]?.lifecycle_state as KnowledgeBaseLifecycleState;
      if (current === "archived" && next !== "archived") {
        throw new KnowledgeBaseConflictError("Archived knowledge bases cannot resume or pause");
      }
      if (current === next) return;

      if (next === "archived") {
        await tx.query(
          `UPDATE knowledge_bases
              SET lifecycle_state = 'archived', archived_at = $3,
                  t_valid_to = coalesce(t_valid_to, $3), updated_at = $3
            WHERE id = $1 AND namespace = $2`,
          [id, context.namespace, at],
        );
      } else {
        await tx.query(
          `UPDATE knowledge_bases
              SET lifecycle_state = $3, updated_at = $4
            WHERE id = $1 AND namespace = $2 AND lifecycle_state <> 'archived'`,
          [id, context.namespace, next, at],
        );
      }
    });

    const updated = await this.get(id, { visibleNamespaces: [context.namespace] });
    if (updated === null) throw new KnowledgeBaseNotFoundError();
    return updated;
  }
}

function normalizeCreate(input: KnowledgeBaseMetadataInput): NormalizedCreate {
  if (input === null || typeof input !== "object") {
    throw new KnowledgeBaseValidationError("Knowledge base metadata is required");
  }
  if (!KINDS.has(input.kind)) {
    throw new KnowledgeBaseValidationError("Unsupported knowledge base kind");
  }
  if (typeof input.dataSensitive !== "boolean") {
    throw new KnowledgeBaseValidationError("dataSensitive must be a boolean");
  }
  const sourceId = input.sourceId === undefined
    ? null
    : requiredString(input.sourceId, "sourceId", MAX_SOURCE_ID_LENGTH);
  return {
    name: requiredString(input.name, "name", MAX_NAME_LENGTH),
    kind: input.kind,
    sourceId,
    primaryBusinessFunction: requiredString(
      input.primaryBusinessFunction,
      "primaryBusinessFunction",
      MAX_FUNCTION_LENGTH,
    ),
    description: optionalString(input.description, "description", MAX_DESCRIPTION_LENGTH),
    dataSensitive: input.dataSensitive,
  };
}

function normalizeResolvedContext(
  context: ResolvedKnowledgeBaseContext,
): ResolvedKnowledgeBaseContext {
  if (context === null || typeof context !== "object") {
    throw new KnowledgeBaseValidationError("Resolved knowledge base context is required");
  }
  return {
    namespace: requiredString(context.namespace, "namespace", MAX_NAMESPACE_LENGTH) as Namespace,
    actor: requiredString(context.actor, "actor", MAX_ACTOR_LENGTH),
    targetTeamId: context.targetTeamId === null
      ? null
      : requiredString(context.targetTeamId, "targetTeamId", MAX_SOURCE_ID_LENGTH),
  };
}

function normalizeMutationContext(
  context: KnowledgeBaseMutationContext,
): KnowledgeBaseMutationContext {
  if (context === null || typeof context !== "object") {
    throw new KnowledgeBaseValidationError("Resolved mutation context is required");
  }
  return {
    namespace: requiredString(context.namespace, "namespace", MAX_NAMESPACE_LENGTH) as Namespace,
    actor: requiredString(context.actor, "actor", MAX_ACTOR_LENGTH),
  };
}

function normalizeVisibleNamespaces(raw: readonly Namespace[]): Namespace[] {
  if (!Array.isArray(raw) || raw.length > MAX_VISIBLE_NAMESPACES) {
    throw new KnowledgeBaseValidationError(
      `visibleNamespaces cannot exceed ${MAX_VISIBLE_NAMESPACES} entries`,
    );
  }
  return [...new Set(raw.map((namespace) => {
    if (typeof namespace !== "string" || namespace.length > MAX_NAMESPACE_LENGTH) {
      throw new KnowledgeBaseValidationError("visible namespace is invalid");
    }
    if (CONTROL_CHARACTER.test(namespace)) {
      throw new KnowledgeBaseValidationError("visible namespace contains controls");
    }
    return namespace as Namespace;
  }))];
}

function normalizeListQuery(raw: KnowledgeBaseListQuery): Required<
  Pick<KnowledgeBaseListQuery, "page" | "pageSize">
> & KnowledgeBaseListQuery & { query: string } {
  if (raw === null || typeof raw !== "object") {
    throw new KnowledgeBaseValidationError("Knowledge base list query is required");
  }
  const query = raw.query?.trim() ?? "";
  if (query.length > MAX_SEARCH_LENGTH || CONTROL_CHARACTER.test(query)) {
    throw new KnowledgeBaseValidationError(
      `query cannot exceed ${MAX_SEARCH_LENGTH} characters or contain controls`,
    );
  }
  if (raw.kind !== undefined && !KINDS.has(raw.kind)) {
    throw new KnowledgeBaseValidationError("Unsupported knowledge base kind filter");
  }
  if (raw.status !== undefined && !STATUSES.has(raw.status)) {
    throw new KnowledgeBaseValidationError("Unsupported knowledge base status filter");
  }
  if (
    raw.lifecycleState !== undefined &&
    !LIFECYCLE_STATES.has(raw.lifecycleState)
  ) {
    throw new KnowledgeBaseValidationError("Unsupported lifecycle filter");
  }
  const page = raw.page ?? 1;
  const pageSize = raw.pageSize ?? 25;
  if (!Number.isSafeInteger(page) || page < 1) {
    throw new KnowledgeBaseValidationError("page must be a positive integer");
  }
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
    throw new KnowledgeBaseValidationError(
      `pageSize must be between 1 and ${MAX_PAGE_SIZE}`,
    );
  }
  return {
    ...raw,
    query,
    targetTeamId: raw.targetTeamId === undefined
      ? undefined
      : requiredString(raw.targetTeamId, "targetTeamId", MAX_SOURCE_ID_LENGTH),
    page,
    pageSize,
  };
}

function emptyList(page: number, pageSize: number): KnowledgeBaseListResult {
  return {
    data: [],
    pagination: { page, pageSize, total: 0, totalPages: 0 },
  };
}

function requiredString(raw: unknown, label: string, max: number): string {
  if (typeof raw !== "string") {
    throw new KnowledgeBaseValidationError(`${label} must be a string`);
  }
  const value = raw.trim();
  if (value.length === 0 || value.length > max || CONTROL_CHARACTER.test(value)) {
    throw new KnowledgeBaseValidationError(
      `${label} must contain 1 to ${max} characters without controls`,
    );
  }
  return value;
}

function optionalString(raw: unknown, label: string, max: number): string {
  if (typeof raw !== "string") {
    throw new KnowledgeBaseValidationError(`${label} must be a string`);
  }
  const value = raw.trim();
  if (value.length > max || CONTROL_CHARACTER.test(value)) {
    throw new KnowledgeBaseValidationError(
      `${label} cannot exceed ${max} characters or contain controls`,
    );
  }
  return value;
}

function rowToSummary(row: KnowledgeBaseRow): KnowledgeBaseSummary {
  return {
    id: row.id,
    namespace: row.namespace as Namespace,
    targetTeamId: row.target_team_id,
    name: row.name,
    kind: row.kind,
    status: row.derived_status,
    lifecycleState: row.lifecycle_state,
    sourceId: row.source_id,
    primaryBusinessFunction: row.primary_business_function,
    description: row.description,
    dataSensitive: row.data_sensitive,
    fileCount: Number(row.file_count),
    sourceCount: Number(row.source_count),
    itemCount: Number(row.item_count),
    factCount: Number(row.fact_count),
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

function toIso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
