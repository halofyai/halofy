/**
 * M10 preview module — root "View as" lifecycle (FR6, D43).
 *
 * Pure handler functions over an injected `Db` + audit seam; the INTEGRATOR
 * mounts the routes (`GET /v1/root/view-as/targets`,
 * `POST /v1/root/view-as/sessions`, `DELETE /v1/root/view-as/sessions/:id`)
 * and applies `enforcePreviewReadOnly` to EVERY route whenever the
 * `x-halomem-preview-token` header is present.
 *
 * Invariants the review attacks (D43, D46, D47, D4, D7, D9):
 *  - Only a caller whose PRODUCT role is `root` may start / end / list.
 *    The role translation is injected (`deps.toProductRole`) so the one D41
 *    seam stays in `src/iam/product-roles.ts` — no scattered ternaries here.
 *  - The preview credential is 32 random bytes, returned ONCE, stored ONLY
 *    as sha256 hex (`token_hash`), and never logged, echoed, or written to
 *    any audit detail. It travels solely in the dedicated header.
 *  - A role simulation REQUIRES >= 1 functional area (a bare role is not a
 *    valid preview); an actual-person preview carries no areas.
 *  - Subject and functional-area IDs are opaque and re-resolved inside the
 *    ROOT'S OWN tenant (D9). A foreign or unknown target returns the SAME
 *    constant not-found shape as a nonexistent one (D46) — no oracle.
 *  - Tenant subtree matching uses exact match + `escapeLikePattern` with
 *    `ESCAPE '\'` — `_`, `%`, `\` in namespaces are always literal.
 *  - Exit/expiry sets `ended_at` / is time-based; rows are NEVER deleted or
 *    overwritten (D47). The expiry sweep is integrator-side (`isExpired`).
 *  - Every lifecycle event (create, read-use, end, expiry, denial, blocked
 *    mutation) writes an audit row attributed to the ROOT actor — never to
 *    the preview subject (D4/D43).
 */

import { createHash, randomBytes } from "node:crypto";
import { ulid } from "ulid";

import { escapeLikePattern, type Db } from "../db/client.js";
import type {
  AuditEvent,
  HumanRole,
  Namespace,
  PreviewSessionRecord,
  PreviewSubject,
  ProductHumanRole,
  Session,
} from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The ONLY place a preview credential travels (D43). Never query/body. */
export const PREVIEW_TOKEN_HEADER = "x-halomem-preview-token";

/** Default preview lifetime: 15 minutes (D43). */
export const DEFAULT_PREVIEW_TTL_MS = 15 * 60_000;

const TOKEN_BYTES = 32;
const MAX_REASON_LENGTH = 200;
const AGENT_ID = "console";

// ---------------------------------------------------------------------------
// Errors (name-mapped by http/server.ts; integrator adds the 404 mapping)
// ---------------------------------------------------------------------------

/** 403-mapped (name "AuthzError" — existing transport mapping). */
export class PreviewAuthzError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthzError";
  }
}

/** 400-mapped (name "BadRequestError" — existing transport mapping). */
export class PreviewValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

/**
 * Uniform not-found (D46): foreign-tenant, disabled, and nonexistent targets
 * all throw THIS class with THIS constant message — byte-identical shapes.
 * Integrator maps name "PreviewNotFoundError" -> 404
 * `{ error: "not found", code: "not_found" }` (KnowledgeBaseNotFoundError idiom).
 */
export class PreviewNotFoundError extends Error {
  constructor() {
    super("not found");
    this.name = "PreviewNotFoundError";
  }
}

/** 403-mapped rejection for a mutation attempted under a preview credential. */
export class PreviewReadOnlyError extends Error {
  constructor() {
    super("preview is read-only");
    this.name = "AuthzError";
  }
}

// ---------------------------------------------------------------------------
// Dependency seam (integrator binds; tests stub)
// ---------------------------------------------------------------------------

/** Structural subset of `AuditLog` — the injected D4 sink. */
export interface ViewAsAudit {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface ViewAsDeps {
  db: Db;
  audit: ViewAsAudit;
  /**
   * The ONE D41 translation seam, injected: bind to `toProductRole` from
   * `src/iam/product-roles.ts`. This module never inlines owner/auditor
   * ternaries.
   */
  toProductRole(role: HumanRole): ProductHumanRole;
  /** Injected clock (fake in tests). Defaults to `() => new Date()`. */
  now?(): Date;
  /** Preview lifetime override; defaults to 15 minutes. */
  previewTtlMs?: number;
}

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

export interface CreatePreviewInput {
  rootSession: Session;
  /** Opaque user ID, re-resolved inside the root's tenant (D9). */
  subjectUserId?: string;
  /** Role simulation — REQUIRES >= 1 functional area. */
  simulatedRole?: "admin" | "member";
  /** Opaque functional-area (org team) IDs, re-resolved in-tenant (D9). */
  functionalAreaIds?: readonly string[];
  /** Required, 1..200 chars after trim. */
  reason: string;
}

export interface CreatedPreviewSession {
  session: PreviewSessionRecord;
  /** Returned ONCE. Never stored, never logged, never re-derivable. */
  token: string;
}

/** What `resolvePreview` yields for a live credential. */
export interface ResolvedPreview {
  /** Preview session id — the transport uses it to attribute audit rows. */
  sessionId: string;
  subject: PreviewSubject;
  expiresAt: string;
}

export interface PreviewTargetPerson {
  id: string;
  displayName: string;
  email: string;
  role: ProductHumanRole;
}

export interface PreviewTargetArea {
  id: string;
  name: string;
}

export interface PreviewTargets {
  people: PreviewTargetPerson[];
  areas: PreviewTargetArea[];
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** sha256 hex of a preview token — the ONLY at-rest form (D43). */
export function hashPreviewToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Tenant ROOT namespace of a namespace: its first `/`-segment ("acme/x" ->
 * "acme", "acme" -> "acme"). The platform root ("") keeps "" — org-wide.
 */
export function tenantRootOf(namespace: Namespace): Namespace {
  const idx = namespace.indexOf("/");
  return idx === -1 ? namespace : namespace.slice(0, idx);
}

/** True when the session's expiry has passed at `now`. Sweep is integrator-side. */
export function isExpired(session: PreviewSessionRecord, now: Date): boolean {
  return new Date(session.expiresAt).getTime() <= now.getTime();
}

/**
 * The transport read-only guard (D43): while a preview credential is
 * presented, ONLY safe methods pass. True for GET/HEAD, false for everything
 * else (POST, PUT, PATCH, DELETE, OPTIONS, unknown, empty).
 */
export function enforcePreviewReadOnly(method: string): boolean {
  const m = method.toUpperCase();
  return m === "GET" || m === "HEAD";
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function nowOf(deps: ViewAsDeps): Date {
  return deps.now ? deps.now() : new Date();
}

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

/**
 * Tenant-subtree predicate over a namespace column: exact match OR escaped
 * prefix (`ESCAPE '\'`) — `_`, `%`, `\` stay literal.
 *
 * Tenant "" is the UNPREFIXED ORGANIZATION (single-org installs; the
 * operator's own workspace): rows whose first namespace segment is NOT a
 * registered tenant. Registered tenants (every self-serve org signup mints
 * a `tenants` row) stay invisible, so the "" owner never spans customer
 * tenants (PRD §14.1 — Human Root is tenant-root, never platform-global).
 * The bare "" namespace itself is excluded: peers at the platform level are
 * not previewable organization members.
 */
function tenantScopePredicate(
  column: string,
  tenantId: Namespace,
  startAt: number,
): { sql: string; params: string[] } {
  if (tenantId === "") {
    return {
      sql:
        `(${column} <> '' AND split_part(${column}, '/', 1) NOT IN ` +
        `(SELECT id FROM tenants))`,
      params: [],
    };
  }
  return {
    sql: `(${column} = $${startAt} OR ${column} LIKE $${startAt + 1} ESCAPE '\\')`,
    params: [tenantId, escapeLikePattern(tenantId) + "/%"],
  };
}

interface PreviewRow {
  id: string;
  token_hash: string;
  tenant_id: string;
  root_user_id: string;
  subject_user_id: string | null;
  simulated_role: string | null;
  selected_resource_ids: unknown;
  reason: string;
  created_at: Date | string;
  expires_at: Date | string;
  ended_at: Date | string | null;
}

function resourceIdsOf(raw: unknown): string[] {
  const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
}

function rowToRecord(row: PreviewRow): PreviewSessionRecord {
  const subject: PreviewSubject = row.subject_user_id !== null
    ? { kind: "user", subjectUserId: row.subject_user_id }
    : {
        kind: "role",
        role: row.simulated_role as "admin" | "member",
        functionalAreaIds: resourceIdsOf(row.selected_resource_ids),
      };
  return {
    id: row.id,
    tenantId: row.tenant_id,
    rootUserId: row.root_user_id,
    subject,
    reason: row.reason,
    createdAt: toIso(row.created_at),
    expiresAt: toIso(row.expires_at),
    endedAt: row.ended_at === null ? null : toIso(row.ended_at),
  };
}

/**
 * D4 audit under the ROOT actor. `detail` NEVER contains the token or its
 * hash — only the preview session id, opaque caller-supplied IDs, and the
 * lifecycle outcome.
 */
async function auditPreview(
  deps: ViewAsDeps,
  session: Session,
  tenantId: Namespace,
  op: AuditEvent["op"],
  purpose: string,
  result: AuditEvent["result"],
  detail: Record<string, unknown>,
): Promise<void> {
  await deps.audit.appendTo(deps.db, {
    ts: nowOf(deps).toISOString(),
    actor: session.actor,
    agentId: AGENT_ID,
    op,
    memoryId: null,
    namespace: tenantId,
    purpose,
    result,
    detail: JSON.stringify(detail),
  });
}

/**
 * Root gate: product role must be `root` (via the injected D41 seam).
 * Non-root callers are audited (denied) and rejected 403. Returns the
 * caller's server-resolved tenant root (D9 — never from the request).
 */
async function requireRoot(
  deps: ViewAsDeps,
  session: Session,
  purpose: string,
): Promise<Namespace> {
  const tenantId = tenantRootOf(session.namespace);
  if (deps.toProductRole(session.role) !== "root") {
    await auditPreview(deps, session, tenantId, "read", purpose, "denied", {
      reason: "caller product role is not root",
    });
    throw new PreviewAuthzError("only root can use view-as");
  }
  // The namespace-"" owner is the ORGANIZATION ROOT of the unprefixed
  // organization (single-org installs; the operator's own workspace). Its
  // View-as reach is that organization only: namespaces whose first segment
  // is NOT a registered tenant (see tenantScopePredicate). Customer tenants
  // stay unreachable (PRD §14.1, D43) — platform break-glass remains out of
  // scope. Non-owner "" sessions never get here (product-role gate above).
  return tenantId;
}

/** Uniform D46 denial: audit, then the constant not-found shape. */
async function denyNotFound(
  deps: ViewAsDeps,
  session: Session,
  tenantId: Namespace,
  purpose: string,
  detail: Record<string, unknown>,
): Promise<never> {
  await auditPreview(deps, session, tenantId, "read", purpose, "denied", detail);
  throw new PreviewNotFoundError();
}

// ---------------------------------------------------------------------------
// createPreviewSession
// ---------------------------------------------------------------------------

const PURPOSE_START = "console-view-as-start";
const PURPOSE_READ = "console-view-as-read";
const PURPOSE_EXPIRED = "console-view-as-expired";
const PURPOSE_EXIT = "console-view-as-exit";
const PURPOSE_TARGETS = "console-view-as-targets";
const PURPOSE_MUTATION_DENIED = "console-view-as-mutation-denied";

/**
 * Start a preview: an actual tenant user XOR a role simulation with >= 1
 * functional area. Root-only; reason required (1..200 chars). The token is
 * minted from 32 random bytes, RETURNED ONCE, and stored only as sha256 hex.
 */
export async function createPreviewSession(
  deps: ViewAsDeps,
  input: CreatePreviewInput,
): Promise<CreatedPreviewSession> {
  const { rootSession } = input;
  const tenantId = await requireRoot(deps, rootSession, PURPOSE_START);

  const fail = async (message: string): Promise<never> => {
    await auditPreview(deps, rootSession, tenantId, "write", PURPOSE_START, "denied", {
      reason: message,
    });
    throw new PreviewValidationError(message);
  };

  const reason = typeof input.reason === "string" ? input.reason.trim() : "";
  if (reason.length === 0) await fail("reason is required");
  if (reason.length > MAX_REASON_LENGTH) {
    await fail(`reason must be at most ${MAX_REASON_LENGTH} characters`);
  }

  const hasSubject = typeof input.subjectUserId === "string" && input.subjectUserId.length > 0;
  const hasRole = input.simulatedRole !== undefined;
  if (hasSubject === hasRole) {
    await fail("choose exactly one: a person or a role");
  }

  let subjectUserId: string | null = null;
  let simulatedRole: "admin" | "member" | null = null;
  let areaIds: string[] = [];

  if (hasSubject) {
    if ((input.functionalAreaIds ?? []).length > 0) {
      await fail("a person preview takes no functional areas");
    }
    subjectUserId = input.subjectUserId as string;
    // Re-resolve the opaque ID inside the ROOT'S tenant (D9). Foreign,
    // disabled, and unknown all take the same denial path (D46).
    const scope = tenantScopePredicate("namespace", tenantId, 2);
    const res = await deps.db.query(
      `SELECT id FROM users WHERE id = $1 AND status = 'active' AND ${scope.sql}`,
      [subjectUserId, ...scope.params],
    );
    if (res.rows.length === 0) {
      await denyNotFound(deps, rootSession, tenantId, PURPOSE_START, {
        subjectUserId,
      });
    }
  } else {
    if (input.simulatedRole !== "admin" && input.simulatedRole !== "member") {
      await fail("role must be admin or member");
    }
    simulatedRole = input.simulatedRole as "admin" | "member";
    areaIds = [...new Set((input.functionalAreaIds ?? []).map((v) => String(v)))];
    if (areaIds.length === 0) {
      // PRD: a bare role is not a valid preview.
      await fail("a role preview needs at least one functional area");
    }
    // Every area must resolve inside the tenant; any miss is uniform (D46).
    const scope = tenantScopePredicate("namespace", tenantId, areaIds.length + 1);
    const placeholders = areaIds.map((_, i) => `$${i + 1}`).join(", ");
    const res = await deps.db.query(
      `SELECT id FROM org_teams WHERE id IN (${placeholders}) AND ${scope.sql}`,
      [...areaIds, ...scope.params],
    );
    if (res.rows.length !== areaIds.length) {
      await denyNotFound(deps, rootSession, tenantId, PURPOSE_START, {
        functionalAreaIds: areaIds,
      });
    }
  }

  const now = nowOf(deps);
  const ttlMs = deps.previewTtlMs ?? DEFAULT_PREVIEW_TTL_MS;
  const id = ulid();
  const token = randomBytes(TOKEN_BYTES).toString("hex");
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + ttlMs).toISOString();

  await deps.db.query(
    `INSERT INTO access_preview_sessions
       (id, token_hash, tenant_id, root_user_id, subject_user_id,
        simulated_role, selected_resource_ids, reason, created_at, expires_at, ended_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, NULL)`,
    [
      id,
      hashPreviewToken(token),
      tenantId,
      rootSession.userId,
      subjectUserId,
      simulatedRole,
      JSON.stringify(areaIds),
      reason,
      createdAt,
      expiresAt,
    ],
  );

  await auditPreview(deps, rootSession, tenantId, "write", PURPOSE_START, "ok", {
    previewSessionId: id,
    ...(subjectUserId !== null
      ? { subjectUserId }
      : { simulatedRole, functionalAreaIds: areaIds }),
    reason,
    expiresAt,
  });

  const subject: PreviewSubject = subjectUserId !== null
    ? { kind: "user", subjectUserId }
    : { kind: "role", role: simulatedRole as "admin" | "member", functionalAreaIds: areaIds };

  return {
    session: {
      id,
      tenantId,
      rootUserId: rootSession.userId,
      subject,
      reason,
      createdAt,
      expiresAt,
      endedAt: null,
    },
    token,
  };
}

// ---------------------------------------------------------------------------
// resolvePreview
// ---------------------------------------------------------------------------

/**
 * Resolve the raw `x-halomem-preview-token` header value into a preview
 * subject for the projection service. Valid only when the row's tenant AND
 * root user match the presenting root session, it has not ended, and it has
 * not expired at the injected clock. Anything else -> null (the caller
 * treats the request as having no preview) with a D4 denial row attributed
 * to the ROOT actor. An absent/empty header is "no preview" — no audit.
 */
export async function resolvePreview(
  deps: ViewAsDeps,
  tokenFromHeader: string | undefined | null,
  rootSession: Session,
): Promise<ResolvedPreview | null> {
  if (typeof tokenFromHeader !== "string" || tokenFromHeader.trim().length === 0) {
    return null;
  }
  const tenantId = tenantRootOf(rootSession.namespace);
  const res = await deps.db.query(
    `SELECT * FROM access_preview_sessions WHERE token_hash = $1`,
    [hashPreviewToken(tokenFromHeader.trim())],
  );
  const row = res.rows[0] as PreviewRow | undefined;

  const deny = async (purpose: string, why: string): Promise<null> => {
    await auditPreview(deps, rootSession, tenantId, "read", purpose, "denied", {
      ...(row !== undefined ? { previewSessionId: row.id } : {}),
      reason: why,
    });
    return null;
  };

  if (row === undefined) return deny(PURPOSE_READ, "unknown preview credential");
  // Tenant- and root-session-bound: only the minting root, in its tenant,
  // while still holding the root product role (fail-closed on demotion).
  if (
    row.root_user_id !== rootSession.userId ||
    row.tenant_id !== tenantId ||
    deps.toProductRole(rootSession.role) !== "root"
  ) {
    return deny(PURPOSE_READ, "credential not bound to this root session");
  }
  if (row.ended_at !== null) return deny(PURPOSE_READ, "preview ended");
  const record = rowToRecord(row);
  if (isExpired(record, nowOf(deps))) return deny(PURPOSE_EXPIRED, "preview expired");

  await auditPreview(deps, rootSession, tenantId, "read", PURPOSE_READ, "ok", {
    previewSessionId: record.id,
    subject: record.subject,
  });
  return { sessionId: record.id, subject: record.subject, expiresAt: record.expiresAt };
}

// ---------------------------------------------------------------------------
// endPreviewSession
// ---------------------------------------------------------------------------

/**
 * Exit a preview: sets `ended_at` (D47 — never a delete). Root-only;
 * foreign/unknown ids take the uniform not-found path (D46). Idempotent —
 * ending an already-ended session returns it unchanged.
 */
export async function endPreviewSession(
  deps: ViewAsDeps,
  id: string,
  rootSession: Session,
): Promise<PreviewSessionRecord> {
  const tenantId = await requireRoot(deps, rootSession, PURPOSE_EXIT);
  const res = await deps.db.query(
    `SELECT * FROM access_preview_sessions
      WHERE id = $1 AND tenant_id = $2 AND root_user_id = $3`,
    [id, tenantId, rootSession.userId],
  );
  const row = res.rows[0] as PreviewRow | undefined;
  if (row === undefined) {
    await denyNotFound(deps, rootSession, tenantId, PURPOSE_EXIT, {
      previewSessionId: id,
    });
  }
  const existing = rowToRecord(row as PreviewRow);
  if (existing.endedAt !== null) return existing;

  const endedAt = nowOf(deps).toISOString();
  await deps.db.query(
    `UPDATE access_preview_sessions SET ended_at = $1 WHERE id = $2 AND ended_at IS NULL`,
    [endedAt, id],
  );
  await auditPreview(deps, rootSession, tenantId, "write", PURPOSE_EXIT, "ok", {
    previewSessionId: id,
  });
  return { ...existing, endedAt };
}

// ---------------------------------------------------------------------------
// listPreviewTargets
// ---------------------------------------------------------------------------

/**
 * What root can preview: active users of ITS OWN tenant (id, display name,
 * PRODUCT role) and the tenant's functional areas as opaque IDs + short
 * names. Never a row from another tenant (exact + escaped-prefix scoping).
 */
export async function listPreviewTargets(
  deps: ViewAsDeps,
  rootSession: Session,
): Promise<PreviewTargets> {
  const tenantId = await requireRoot(deps, rootSession, PURPOSE_TARGETS);

  const userScope = tenantScopePredicate("namespace", tenantId, 1);
  const users = await deps.db.query(
    `SELECT id, email, display_name, role FROM users
      WHERE status = 'active' AND ${userScope.sql}
      ORDER BY email ASC`,
    userScope.params,
  );
  const areaScope = tenantScopePredicate("namespace", tenantId, 1);
  const areas = await deps.db.query(
    `SELECT id, name FROM org_teams WHERE ${areaScope.sql} ORDER BY name ASC`,
    areaScope.params,
  );

  const targets: PreviewTargets = {
    people: users.rows.map((r) => ({
      id: String(r.id),
      displayName: String(r.display_name),
      email: String(r.email),
      role: deps.toProductRole(String(r.role) as HumanRole),
    })),
    areas: areas.rows.map((r) => ({ id: String(r.id), name: String(r.name) })),
  };

  await auditPreview(deps, rootSession, tenantId, "read", PURPOSE_TARGETS, "ok", {
    people: targets.people.length,
    areas: targets.areas.length,
  });
  return targets;
}

// ---------------------------------------------------------------------------
// Read-only transport guard helpers
// ---------------------------------------------------------------------------

/**
 * D4 evidence for a mutation attempted while a preview credential was
 * presented: audits (denied) under the ROOT actor with the preview session
 * id, then throws the 403 shape. The integrator calls this from the
 * transport whenever `enforcePreviewReadOnly(method)` is false.
 */
export async function rejectPreviewMutation(
  deps: ViewAsDeps,
  rootSession: Session,
  previewSessionId: string,
  method: string,
  path: string,
): Promise<never> {
  const tenantId = tenantRootOf(rootSession.namespace);
  await auditPreview(
    deps,
    rootSession,
    tenantId,
    "write",
    PURPOSE_MUTATION_DENIED,
    "denied",
    { previewSessionId, method: method.toUpperCase(), path },
  );
  throw new PreviewReadOnlyError();
}
