import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import type {
  KnowledgeBaseSourceCreateInput,
  KnowledgeBaseSourceKind,
  KnowledgeBaseSourceListResult,
  KnowledgeBaseSourceStatus,
  KnowledgeBaseSourceSummary,
  Namespace,
} from "../types.js";

const CONTROL_CHARACTER = /\p{Cc}/u;
const MAX_ID_LENGTH = 128;
const MAX_NAMESPACE_LENGTH = 512;
const MAX_ACTOR_LENGTH = 512;
const MAX_NAME_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 2_000;
const MAX_PURPOSE_LENGTH = 500;
const MAX_PAGE_SIZE = 100;

export class KnowledgeBaseSourceValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KnowledgeBaseSourceValidationError";
  }
}

export class KnowledgeBaseSourceNotFoundError extends Error {
  constructor(message = "Knowledge base not found") {
    super(message);
    this.name = "KnowledgeBaseSourceNotFoundError";
  }
}

export class KnowledgeBaseSourceConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KnowledgeBaseSourceConflictError";
  }
}

export interface KnowledgeBaseSourceContext {
  namespace: Namespace;
  actor: string;
}

interface KnowledgeBaseSourceRow {
  id: string;
  namespace: string;
  knowledge_base_id: string;
  source_id: string;
  source_kind: KnowledgeBaseSourceKind;
  display_name: string;
  description: string;
  purpose: string;
  team_id: string | null;
  attachment_status: "processing" | "active" | "needs_review" | "failed" | "archived";
  sync_status: "never_synced" | "pending" | "synced" | "failed" | null;
  created_by: string;
  created_at: string | Date;
}

export class KnowledgeBaseSourceStore {
  private readonly now: () => Date;

  constructor(
    private readonly db: Db,
    now?: () => Date,
  ) {
    this.now = now ?? (() => new Date());
  }

  async create(
    rawInput: KnowledgeBaseSourceCreateInput,
    rawContext: KnowledgeBaseSourceContext,
  ): Promise<KnowledgeBaseSourceSummary> {
    const input = normalizeCreate(rawInput);
    const context = normalizeContext(rawContext);
    const id = ulid();
    const createdAt = this.now().toISOString();

    await this.db.transaction(async (tx) => {
      const base = await tx.query(
        `SELECT target_team_id FROM knowledge_bases
          WHERE id = $1 AND namespace = $2
            AND lifecycle_state = 'active' AND t_valid_to IS NULL
          FOR UPDATE`,
        [input.knowledgeBaseId, context.namespace],
      );
      if (base.rows.length !== 1) throw new KnowledgeBaseSourceNotFoundError();

      const expectedKind = input.kind === "folder" ? "filesystem" : "doc_site";
      const source = await tx.query(
        `SELECT id FROM sources
          WHERE id = $1 AND namespace = $2 AND kind = $3
            AND lifecycle_state = 'active'
          FOR UPDATE`,
        [input.sourceId, context.namespace, expectedKind],
      );
      if (source.rows.length !== 1) {
        throw new KnowledgeBaseSourceValidationError(
          `${input.kind} must use an active same-namespace ${expectedKind} source`,
        );
      }

      const inserted = await tx.query(
        `INSERT INTO knowledge_sources
           (id, namespace, knowledge_base_id, source_id, source_key, source_kind,
            display_name, description, purpose, team_id, status, supersedes,
            t_valid_from, t_valid_to, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 'active', NULL, $11, NULL, $12, $11)
         ON CONFLICT DO NOTHING
         RETURNING id`,
        [
          id,
          context.namespace,
          input.knowledgeBaseId,
          input.sourceId,
          `source:${input.sourceId}`,
          input.kind,
          input.name,
          input.description,
          input.purpose,
          base.rows[0]?.target_team_id ?? null,
          createdAt,
          context.actor,
        ],
      );
      if (inserted.rows.length !== 1) {
        throw new KnowledgeBaseSourceConflictError(
          "This source is already attached to the knowledge base",
        );
      }
    });

    const created = await this.get(id, input.knowledgeBaseId, context.namespace);
    if (created === null) throw new KnowledgeBaseSourceNotFoundError("Knowledge piece not found");
    return created;
  }

  async list(
    rawKnowledgeBaseId: string,
    rawContext: Pick<KnowledgeBaseSourceContext, "namespace">,
    rawQuery: { page?: number; pageSize?: number } = {},
  ): Promise<KnowledgeBaseSourceListResult> {
    const knowledgeBaseId = requiredString(rawKnowledgeBaseId, "knowledgeBaseId", MAX_ID_LENGTH);
    const namespace = requiredString(rawContext.namespace, "namespace", MAX_NAMESPACE_LENGTH) as Namespace;
    const page = rawQuery.page ?? 1;
    const pageSize = rawQuery.pageSize ?? 25;
    if (!Number.isSafeInteger(page) || page < 1) {
      throw new KnowledgeBaseSourceValidationError("page must be a positive integer");
    }
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
      throw new KnowledgeBaseSourceValidationError(`pageSize must be between 1 and ${MAX_PAGE_SIZE}`);
    }

    const base = await this.db.query(
      `SELECT id FROM knowledge_bases WHERE id = $1 AND namespace = $2`,
      [knowledgeBaseId, namespace],
    );
    if (base.rows.length !== 1) throw new KnowledgeBaseSourceNotFoundError();

    const count = await this.db.query(
      `SELECT count(*) AS total FROM knowledge_sources
        WHERE knowledge_base_id = $1 AND namespace = $2 AND t_valid_to IS NULL`,
      [knowledgeBaseId, namespace],
    );
    const total = Number(count.rows[0]?.total ?? 0);
    const result = await this.db.query(
      `${selectSourceSql()}
        WHERE ks.knowledge_base_id = $1 AND ks.namespace = $2 AND ks.t_valid_to IS NULL
        ORDER BY ks.created_at DESC, ks.id DESC
        LIMIT $3 OFFSET $4`,
      [knowledgeBaseId, namespace, pageSize, (page - 1) * pageSize],
    );

    return {
      data: result.rows.map((row) => rowToSummary(row as KnowledgeBaseSourceRow)),
      pagination: {
        page,
        pageSize,
        total,
        totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
      },
    };
  }

  /** Archive every current connector piece when its owning collection is deleted. */
  async archiveForKnowledgeBase(
    rawKnowledgeBaseId: string,
    rawContext: KnowledgeBaseSourceContext,
  ): Promise<string[]> {
    const knowledgeBaseId = requiredString(rawKnowledgeBaseId, "knowledgeBaseId", MAX_ID_LENGTH);
    const context = normalizeContext(rawContext);
    const archivedAt = this.now().toISOString();
    return this.db.transaction(async (tx) => {
      const attached = await tx.query(
        `SELECT source_id FROM knowledge_sources
          WHERE knowledge_base_id = $1 AND namespace = $2
          ORDER BY source_id
          FOR UPDATE`,
        [knowledgeBaseId, context.namespace],
      );
      await tx.query(
        `UPDATE knowledge_sources
            SET status = 'archived', t_valid_to = $3
          WHERE knowledge_base_id = $1 AND namespace = $2
            AND status <> 'archived' AND t_valid_to IS NULL`,
        [knowledgeBaseId, context.namespace, archivedAt],
      );
      return [...new Set(attached.rows.map((row) => String(row.source_id)))];
    });
  }

  private async get(
    id: string,
    knowledgeBaseId: string,
    namespace: Namespace,
  ): Promise<KnowledgeBaseSourceSummary | null> {
    const result = await this.db.query(
      `${selectSourceSql()}
        WHERE ks.id = $1 AND ks.knowledge_base_id = $2 AND ks.namespace = $3`,
      [id, knowledgeBaseId, namespace],
    );
    return result.rows.length === 0
      ? null
      : rowToSummary(result.rows[0] as KnowledgeBaseSourceRow);
  }
}

function selectSourceSql(): string {
  return `SELECT ks.id, ks.namespace, ks.knowledge_base_id, ks.source_id,
                 ks.source_kind, ks.display_name, ks.description, ks.purpose,
                 ks.team_id, ks.status AS attachment_status, source.sync_status,
                 ks.created_by, ks.created_at
            FROM knowledge_sources ks
            LEFT JOIN sources source ON source.id = ks.source_id`;
}

function normalizeCreate(input: KnowledgeBaseSourceCreateInput): KnowledgeBaseSourceCreateInput {
  if (input === null || typeof input !== "object") {
    throw new KnowledgeBaseSourceValidationError("Knowledge piece is required");
  }
  if (input.kind !== "folder" && input.kind !== "website") {
    throw new KnowledgeBaseSourceValidationError("kind must be folder or website");
  }
  return {
    knowledgeBaseId: requiredString(input.knowledgeBaseId, "knowledgeBaseId", MAX_ID_LENGTH),
    kind: input.kind,
    sourceId: requiredString(input.sourceId, "sourceId", MAX_ID_LENGTH),
    name: requiredString(input.name, "name", MAX_NAME_LENGTH),
    description: optionalString(input.description, "description", MAX_DESCRIPTION_LENGTH),
    purpose: requiredString(input.purpose, "purpose", MAX_PURPOSE_LENGTH),
  };
}

function normalizeContext(context: KnowledgeBaseSourceContext): KnowledgeBaseSourceContext {
  if (context === null || typeof context !== "object") {
    throw new KnowledgeBaseSourceValidationError("Resolved context is required");
  }
  return {
    namespace: requiredString(context.namespace, "namespace", MAX_NAMESPACE_LENGTH) as Namespace,
    actor: requiredString(context.actor, "actor", MAX_ACTOR_LENGTH),
  };
}

function requiredString(raw: unknown, label: string, max: number): string {
  if (typeof raw !== "string") {
    throw new KnowledgeBaseSourceValidationError(`${label} must be a string`);
  }
  const value = raw.trim();
  if (value.length === 0 || value.length > max || CONTROL_CHARACTER.test(value)) {
    throw new KnowledgeBaseSourceValidationError(
      `${label} must contain 1 to ${max} characters without controls`,
    );
  }
  return value;
}

function optionalString(raw: unknown, label: string, max: number): string {
  if (typeof raw !== "string") {
    throw new KnowledgeBaseSourceValidationError(`${label} must be a string`);
  }
  const value = raw.trim();
  if (value.length > max || CONTROL_CHARACTER.test(value)) {
    throw new KnowledgeBaseSourceValidationError(
      `${label} cannot exceed ${max} characters or contain controls`,
    );
  }
  return value;
}

function rowToSummary(row: KnowledgeBaseSourceRow): KnowledgeBaseSourceSummary {
  return {
    id: row.id,
    knowledgeBaseId: row.knowledge_base_id,
    sourceId: row.source_id,
    namespace: row.namespace as Namespace,
    targetTeamId: row.team_id,
    kind: row.source_kind,
    name: row.display_name,
    description: row.description,
    purpose: row.purpose,
    status: toStatus(row.attachment_status, row.sync_status),
    createdBy: row.created_by,
    createdAt: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : new Date(row.created_at).toISOString(),
  };
}

function toStatus(
  attachment: KnowledgeBaseSourceRow["attachment_status"],
  sync: KnowledgeBaseSourceRow["sync_status"],
): KnowledgeBaseSourceStatus {
  if (attachment === "archived") return "archived";
  if (attachment === "needs_review") return "needs_review";
  if (attachment === "failed" || sync === "failed") return "failed";
  if (sync === "synced") return "ready";
  return "processing";
}
