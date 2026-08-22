/**
 * Skill library store — deduped, company-wide skill catalog (M9 decision #9).
 *
 * The `skills` table (migration "mintlify-parity-m9") is this module's own
 * catalog surface; the KNOWLEDGE-BEARING part of a registration (name +
 * description) additionally flows through the kernel write path via the
 * injected `writeMemory` seam so imported skill metadata receives the same
 * extraction / verification / provenance as every other ingested content
 * (E19 / D10). Redefinition is D7 supersedence: a changed definition closes
 * the incumbent row's validity (`t_valid_to`) and links back through
 * `supersedes` — the catalog never UPDATEs definition content in place and
 * never deletes.
 *
 * Visibility is the ancestor-prefix ACL (E21): an agent in namespace N may
 * use skills whose namespace is N or a '/'-split prefix ancestor of N,
 * resolved with EXACT string lists — never SQL LIKE. Owners/admins/auditors
 * additionally see their subtree for management, mirroring the dispute queue.
 *
 * Enforcement (E22): an unvetted / failed-vetting skill is BLOCKED from
 * invocation unless an audited admin override exists — the append-only
 * `skill_override` audit row bound to the EXACT skill row id IS the override
 * grant, so a redefinition (new row id, new content hash) automatically
 * invalidates prior overrides. Every invocation outcome — ok, denied, and
 * miss — writes a `skill_invoke` audit row (E20 / D4) in the same
 * transaction as the usage rollup.
 */

import { createHash } from "node:crypto";
import { ulid } from "ulid";
import type {
  AuditEvent,
  AuditOp,
  Identity,
  MemoryId,
  Namespace,
  SourceKind,
  WriteRequest,
  WriteResult,
} from "../types.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class SkillAuthorizationError extends Error {
  constructor() {
    super("skill operation denied");
    this.name = "SkillAuthorizationError";
  }
}

export class SkillNotFoundError extends Error {
  constructor() {
    super("skill not found");
    this.name = "SkillNotFoundError";
  }
}

export class SkillConflictError extends Error {
  constructor() {
    super("skill changed concurrently");
    this.name = "SkillConflictError";
  }
}

// ---------------------------------------------------------------------------
// Types (local to this module; candidates for promotion to src/types.ts)
// ---------------------------------------------------------------------------

export type SkillVettingStatus = "unvetted" | "vetting" | "vetted" | "blocked";
export type SkillStatus = "active" | "archived";
export type SkillApprovalStatus = "pending" | "approved" | "rejected";
/** Monitoring classification derived from vetting state + latest run (S16). */
export type SkillRiskBand = "good" | "risky" | "critical";

export const SKILL_LABEL_CATEGORIES = [
  "Research & Analysis",
  "Content & Drafting",
  "Engineering & Code",
  "Workflow Automation",
  "Governance & Compliance",
  "Customer & Revenue Ops",
  "Memory Operations",
  "Retrieval Engines",
  "Data Import & Connectors",
  "Agent Setup & Clients",
  "Deployment & Storage",
  "Reporting & Delivery",
] as const;

export const SKILL_HANDLING_TAGS = [
  "read-only",
  "writes-externally",
  "network-egress",
  "credentials-required",
  "handles-pii",
  "human-approval",
] as const;

export interface SkillLabels {
  category: string;
  purpose: string;
  tags: string[];
  handling: string[];
}

export class SkillLabelValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SkillLabelValidationError";
  }
}

export interface UpdateSkillLabelsInput {
  category: string;
  purpose: string;
  tags: string[];
}

export interface SkillLabelHistoryRecord {
  id: string;
  field: "category" | "purpose" | "tags";
  before: string | string[];
  after: string | string[];
  changedBy: string;
  changedAt: string;
}

export interface SkillRecord {
  id: string;
  namespace: Namespace;
  skillKey: string;
  name: string;
  description: string;
  definition: string;
  contentSha256: string;
  sourceId: string | null;
  sourceKind: SourceKind | null;
  vettingStatus: SkillVettingStatus;
  safetyScore: number | null;
  lastVettedAt: string | null;
  approvalStatus: SkillApprovalStatus;
  approvedBy: string | null;
  approvedAt: string | null;
  supersedes: string | null;
  tValidFrom: string;
  tValidTo: string | null;
  status: SkillStatus;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  labels: SkillLabels;
  /** 1-based position in the (namespace, skillKey) supersedence chain. */
  version: number;
}

export interface RegisterSkillInput {
  skillKey: string;
  name: string;
  description?: string;
  definition: string;
  /** Ingestion source identity when a connector/importer registered it. */
  sourceId?: string;
  sourceKind?: SourceKind;
  /** Discovery metadata stored outside the versioned skill file. */
  labels?: UpdateSkillLabelsInput;
}

/** Editable fields for one selected current skill. Scope and key stay server-owned. */
export interface UpdateSkillInput {
  name: string;
  description?: string;
  definition: string;
}

export interface RegisterSkillResult {
  skill: SkillRecord;
  /** True when the definition matched the current row byte-for-byte (dedupe). */
  deduplicated: boolean;
  /** True when this registration superseded a prior definition (D7). */
  superseded: boolean;
  /**
   * "ok" when the knowledge-bearing metadata landed through the write path
   * (E19), "degraded" when the write-path lane browned out (registration
   * still stands — rule 5, brownout never hard-fail), "skipped" when the
   * dedupe lane made a metadata write redundant.
   */
  metadataWrite: "ok" | "degraded" | "skipped";
}

export interface SkillInvokeDecision {
  allowed: boolean;
  reason: "vetted" | "override" | "not-found" | "blocked" | "unvetted" | "vetting" | "archived"
    | "pending" | "rejected";
  skill: SkillRecord | null;
}

/** Governed download of a distributable skill (approved + vetted), S16. */
export interface SkillExport {
  filename: string;
  content: string;
}

interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface SkillStoreDeps {
  db: Db;
  audit: AuditWriter;
  /**
   * Kernel-bound seam over performWrite (E19 / D10): the knowledge-bearing
   * skill metadata enters the SAME write path as every ingested document,
   * under the registrar's server-resolved Identity. Optional so hermetic
   * unit tests of the catalog can run without a full write path — absent or
   * failing, registration degrades (metadataWrite: "degraded"), never fails.
   */
  writeMemory?: (identity: Identity, req: WriteRequest) => Promise<WriteResult>;
  now?(): Date;
}

// ---------------------------------------------------------------------------
// Validation bounds
// ---------------------------------------------------------------------------

const SKILL_KEY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,199}$/;
const MAX_NAME_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 4_000;
const MAX_DEFINITION_LENGTH = 200_000;
const MAX_LABEL_PURPOSE_LENGTH = 140;
const MAX_SKILL_TAGS = 10;
const SKILL_TAG_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BUILT_IN_SKILL_CATEGORIES = new Set<string>(SKILL_LABEL_CATEGORIES);

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function normalizeTag(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, "-");
}

function inferredCategory(skillKey: string, name: string): string {
  const value = `${skillKey} ${name}`.toLowerCase();
  if (/driver[-_ ]/.test(value)) return "Retrieval Engines";
  if (/\bfrom[-_ ]|connector|import/.test(value)) return "Data Import & Connectors";
  if (/\bwith[-_ ]|deploy|storage|postgres|pgvector|pglite/.test(value)) return "Deployment & Storage";
  if (/claude|codex|rest[-_ ]agent|onboard|client/.test(value)) return "Agent Setup & Clients";
  if (/remember|recall|forget|memory|namespace|improve/.test(value)) return "Memory Operations";
  if (/summary|summarize|draft|digest/.test(value)) return "Content & Drafting";
  if (/report|linear|deliver|export/.test(value)) return "Reporting & Delivery";
  if (/policy|compliance|audit|contract|invoice/.test(value)) return "Governance & Compliance";
  if (/code|engineer|github/.test(value)) return "Engineering & Code";
  return "Research & Analysis";
}

function inferredPurpose(description: string): string {
  const value = description.trim();
  if (!value) return "";
  const sentence = `${value.charAt(0).toLowerCase()}${value.slice(1)}`;
  return `Use this when ${sentence}`.slice(0, MAX_LABEL_PURPOSE_LENGTH);
}

function inferredTags(skillKey: string, category: string): string[] {
  const tokens = skillKey
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((tag) => tag.length > 2 && tag !== "halomem")
    .slice(0, 4);
  const categoryDefaults: Record<string, string[]> = {
    "Content & Drafting": ["content", "summarize", "delivery"],
    "Engineering & Code": ["engineering", "code", "developer-tools"],
    "Governance & Compliance": ["governance", "compliance", "review"],
    "Memory Operations": ["memory", "operations", "governance"],
    "Retrieval Engines": ["retrieval", "memory", "data"],
    "Data Import & Connectors": ["import", "connectors", "data"],
    "Agent Setup & Clients": ["agents", "setup", "clients"],
    "Deployment & Storage": ["deployment", "storage", "infrastructure"],
    "Reporting & Delivery": ["reporting", "delivery", "automation"],
  };
  const merged = [...new Set([...tokens, ...(categoryDefaults[category] ?? ["research", "analysis", "knowledge"])])];
  return merged.slice(0, Math.max(3, Math.min(6, merged.length)));
}

function inferredLabels(skillKey: string, name: string, description: string): SkillLabels {
  const category = inferredCategory(skillKey, name);
  return {
    category,
    purpose: inferredPurpose(description),
    tags: inferredTags(skillKey, category),
    handling: [],
  };
}

/** System-only handling classification, refreshed by the vetting pipeline. */
export function deriveSkillHandling(definition: string, findingText = ""): string[] {
  const value = `${definition}\n${findingText}`.toLowerCase();
  const handling: string[] = [];
  if (/\b(post|send|write|append|publish|update|create)\b|webhook|slack|email/.test(value)) {
    handling.push("writes-externally");
  }
  if (/https?:\/\/|network|webhook|exfiltrat/.test(value)) handling.push("network-egress");
  if (/api[-_ ]?key|api token|bearer|credential|oauth|secret/.test(value)) handling.push("credentials-required");
  if (/\bpii\b|customer|email address|phone|personal data|personally identifiable/.test(value)) handling.push("handles-pii");
  if (/human approval|manual approval|confirm before|review before/.test(value)) handling.push("human-approval");
  return handling.length > 0 ? handling : ["read-only"];
}

// ---------------------------------------------------------------------------
// Shared ACL helpers (dispute-queue mirror; usage.ts and vetting.ts reuse them)
// ---------------------------------------------------------------------------

function isRootOwner(identity: Identity): boolean {
  return identity.role === "owner" && identity.namespace === "";
}

/**
 * Read visibility: the caller's own ancestor chain (usable skills propagate
 * down the tree, E21) plus — for owner/admin/auditor — the caller's subtree
 * (management view). Exact string computation via namespaceAncestors; no
 * SQL pattern matching is ever involved.
 */
export function canReadSkill(identity: Identity, namespace: Namespace): boolean {
  if (isRootOwner(identity)) return true;
  if (namespaceAncestors(identity.namespace).includes(namespace)) return true;
  return (
    (identity.role === "owner" || identity.role === "admin" || identity.role === "auditor") &&
    namespaceAncestors(namespace).includes(identity.namespace)
  );
}

/** Mutations (vet / override / retire): owner or admin over their subtree. */
export function canManageSkill(identity: Identity, namespace: Namespace): boolean {
  if (identity.role !== "owner" && identity.role !== "admin") return false;
  return isRootOwner(identity) || namespaceAncestors(namespace).includes(identity.namespace);
}

/**
 * Monitoring classification (S16): "good" = vetted (score ≥ 70, no critical
 * findings); "critical" = blocked, or the latest finalized vetting run
 * reported a critical-severity finding; "risky" = everything else
 * (unvetted, vetting, errored pipeline).
 */
function riskBandFor(skill: SkillRecord, latestRunHasCritical: boolean): SkillRiskBand {
  if (skill.vettingStatus === "blocked" || latestRunHasCritical) return "critical";
  if (skill.vettingStatus === "vetted") return "good";
  return "risky";
}

/** Double-quote a YAML scalar; backslash, quote, and line breaks escaped. */
function yamlQuote(value: string): string {
  return `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\r\n", "\\n")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\n")}"`;
}

/** SKILL.md for download: YAML frontmatter + the raw definition (S16). */
function renderSkillMarkdown(skill: SkillRecord): string {
  return [
    "---",
    `name: ${yamlQuote(skill.name)}`,
    `description: ${yamlQuote(skill.description)}`,
    `version: ${skill.version}`,
    `skill_key: ${yamlQuote(skill.skillKey)}`,
    `namespace: ${yamlQuote(skill.namespace)}`,
    `content_sha256: ${skill.contentSha256}`,
    `safety_score: ${skill.safetyScore ?? "null"}`,
    `approved_by: ${skill.approvedBy === null ? "null" : yamlQuote(skill.approvedBy)}`,
    `approved_at: ${skill.approvedAt === null ? "null" : yamlQuote(skill.approvedAt)}`,
    "---",
    "",
    skill.definition,
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

interface SkillRow {
  id: string;
  namespace: string;
  skill_key: string;
  name: string;
  description: string;
  definition: string;
  content_sha256: string;
  source_id: string | null;
  source_kind: string | null;
  vetting_status: string;
  safety_score: number | string | null;
  last_vetted_at: unknown;
  approval_status: string;
  approved_by: string | null;
  approved_at: unknown;
  supersedes: string | null;
  t_valid_from: unknown;
  t_valid_to: unknown;
  status: string;
  created_by: string;
  created_at: unknown;
  updated_at: unknown;
  version?: number | string;
  label_category?: string | null;
  label_purpose?: string | null;
  label_tags?: unknown;
  label_handling?: unknown;
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

export function rowToSkill(r: unknown): SkillRecord {
  const row = r as SkillRow;
  const fallback = inferredLabels(row.skill_key, row.name, row.description);
  const arrayValue = (value: unknown): string[] => {
    if (Array.isArray(value)) return value.map(String);
    if (typeof value === "string") {
      try {
        const parsed = JSON.parse(value) as unknown;
        return Array.isArray(parsed) ? parsed.map(String) : [];
      } catch {
        return [];
      }
    }
    return [];
  };
  return {
    id: row.id,
    namespace: row.namespace,
    skillKey: row.skill_key,
    name: row.name,
    description: row.description,
    definition: row.definition,
    contentSha256: row.content_sha256,
    sourceId: row.source_id ?? null,
    sourceKind: (row.source_kind as SourceKind | null) ?? null,
    vettingStatus: row.vetting_status as SkillVettingStatus,
    safetyScore: row.safety_score === null || row.safety_score === undefined
      ? null
      : Number(row.safety_score),
    lastVettedAt: toIsoOrNull(row.last_vetted_at),
    approvalStatus: row.approval_status as SkillApprovalStatus,
    approvedBy: row.approved_by ?? null,
    approvedAt: toIsoOrNull(row.approved_at),
    supersedes: row.supersedes ?? null,
    tValidFrom: toIso(row.t_valid_from),
    tValidTo: toIsoOrNull(row.t_valid_to),
    status: row.status as SkillStatus,
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
    labels: {
      category: row.label_category ?? fallback.category,
      purpose: row.label_purpose ?? fallback.purpose,
      tags: row.label_tags === null || row.label_tags === undefined ? fallback.tags : arrayValue(row.label_tags),
      handling: row.label_handling === null || row.label_handling === undefined
        ? fallback.handling
        : arrayValue(row.label_handling),
    },
    version: row.version === undefined ? 1 : Number(row.version),
  };
}

/** Every column of a skill row plus its chain position. */
const SKILL_SELECT = `
  SELECT s.*, l.category AS label_category, l.purpose AS label_purpose,
         l.tags AS label_tags, l.handling AS label_handling,
         (SELECT COUNT(*) FROM skills c
                WHERE c.namespace = s.namespace AND c.skill_key = s.skill_key
                  AND c.t_valid_from <= s.t_valid_from) AS version
    FROM skills s
    LEFT JOIN skill_labels l
      ON l.namespace = s.namespace AND l.skill_key = s.skill_key`;

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export class SkillStore {
  private readonly now: () => Date;

  constructor(private readonly deps: SkillStoreDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Register (or redefine) a skill in the CALLER'S namespace — the target
   * namespace is never read from the input (D9). Identical content is
   * deduplicated; changed content supersedes the incumbent (D7). The
   * knowledge-bearing metadata then flows through the write path (E19).
   */
  async register(identity: Identity, input: RegisterSkillInput): Promise<RegisterSkillResult> {
    this.validateRegisterInput(input);
    if (identity.role === "auditor" || identity.role === "agent") {
      await this.auditStandalone(identity, "write", null, identity.namespace, "denied",
        `skill-register denied role=${identity.role} key=${input.skillKey}`, "skill-register");
      throw new SkillAuthorizationError();
    }

    const namespace = identity.namespace; // D9: bound at issuance, never asserted
    const ts = this.now().toISOString();
    const contentSha = sha256Hex(input.definition);
    const description = input.description ?? "";
    const inferred = inferredLabels(input.skillKey, input.name, description);
    const initialLabels = input.labels
      ? {
          category: input.labels.category.trim(),
          purpose: input.labels.purpose.trim(),
          tags: [...new Set(input.labels.tags.map(normalizeTag))],
          handling: [] as string[],
        }
      : inferred;
    if (!initialLabels.category || initialLabels.category.length > 80) {
      throw new SkillLabelValidationError("invalid skill category");
    }
    if ((input.labels && !initialLabels.purpose) || initialLabels.purpose.length > MAX_LABEL_PURPOSE_LENGTH) {
      throw new SkillLabelValidationError("skill purpose must be 1..140 characters");
    }
    if (initialLabels.tags.length < 3 || initialLabels.tags.length > MAX_SKILL_TAGS ||
        initialLabels.tags.some((tag) => !SKILL_TAG_PATTERN.test(tag))) {
      throw new SkillLabelValidationError("skill tags must be 3..10 unique lowercase slugs");
    }
    let createCustomCategory = false;
    if (!BUILT_IN_SKILL_CATEGORIES.has(initialLabels.category)) {
      const custom = await this.deps.db.query(
        `SELECT namespace FROM skill_categories WHERE name = $1`,
        [initialLabels.category],
      );
      const allowed = custom.rows.some((row) =>
        namespaceAncestors(namespace).includes(String((row as { namespace: string }).namespace))
      );
      if (!allowed) {
        if (!input.labels || !canManageSkill(identity, namespace)) {
          throw new SkillLabelValidationError("unknown skill category");
        }
        createCustomCategory = true;
      }
    }
    const id = ulid();
    // S16 approval workflow: owner/admin registrations self-approve; member
    // submissions land `pending` and stay invisible to agent invocation until
    // a team admin (owner/admin over the namespace subtree) approves.
    const autoApproved = identity.role === "owner" || identity.role === "admin";

    const outcome = await this.deps.db.transaction(async (tx) => {
      const currentRes = await tx.query(
        `SELECT * FROM skills
          WHERE namespace = $1 AND skill_key = $2 AND t_valid_to IS NULL
          FOR UPDATE`,
        [namespace, input.skillKey],
      );
      const current = currentRes.rows[0] as SkillRow | undefined;

      if (current && current.content_sha256 === contentSha) {
        // Byte-identical redefinition — deduped, no new row (company-wide
        // dedupe is the point of the library).
        await this.audit(tx, identity, "write", current.id, namespace, "ok",
          `skill-register deduplicated key=${input.skillKey} sha=${contentSha.slice(0, 12)}`,
          "skill-register");
        return { skillId: current.id, deduplicated: true, superseded: false };
      }

      if (current) {
        // D7 supersedence: guarded close of the incumbent's validity; zero
        // rows means a concurrent writer got there first — roll back.
        const closed = await tx.query(
          `UPDATE skills SET t_valid_to = $2, updated_at = $2
            WHERE id = $1 AND t_valid_to IS NULL
            RETURNING id`,
          [current.id, ts],
        );
        if (closed.rows.length !== 1) throw new SkillConflictError();
      }

      if (createCustomCategory) {
        await tx.query(
          `INSERT INTO skill_categories (id, namespace, name, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (namespace, name) DO NOTHING`,
          [ulid(), namespace, initialLabels.category, identity.actor, ts],
        );
      }

      await tx.query(
        `INSERT INTO skills
           (id, namespace, skill_key, name, description, definition, content_sha256,
            source_id, source_kind, vetting_status, safety_score, last_vetted_at,
            approval_status, approved_by, approved_at,
            supersedes, t_valid_from, t_valid_to, status, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'unvetted', NULL, NULL,
                 $13, $14, $15,
                 $10, $11, NULL, 'active', $12, $11, $11)`,
        [
          id, namespace, input.skillKey, input.name, description, input.definition,
          contentSha, input.sourceId ?? null, input.sourceKind ?? null,
          current?.id ?? null, ts, identity.actor,
          autoApproved ? "approved" : "pending",
          autoApproved ? identity.actor : null,
          autoApproved ? ts : null,
        ],
      );
      await tx.query(
        `INSERT INTO skill_labels
           (namespace, skill_key, category, purpose, tags, handling,
            created_by, created_at, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, '[]', $6, $7, $6, $7)
         ON CONFLICT (namespace, skill_key) DO NOTHING`,
        [
          namespace, input.skillKey, initialLabels.category, initialLabels.purpose,
          JSON.stringify(initialLabels.tags), identity.actor, ts,
        ],
      );

      if (current) {
        await this.audit(tx, identity, "supersede", current.id, namespace, "ok",
          `skill redefinition; superseded by ${id} key=${input.skillKey}`, "skill-register");
      }
      await this.audit(tx, identity, "write", id, namespace, "ok",
        `skill-register key=${input.skillKey} sha=${contentSha.slice(0, 12)}` +
        (current ? ` supersedes=${current.id}` : "") +
        (autoApproved ? "" : " approval=pending"), "skill-register");
      return { skillId: id, deduplicated: false, superseded: current !== undefined };
    });

    // E19 / D10: the knowledge-bearing metadata enters through the write path
    // AFTER the catalog transaction commits. A write-path failure is a
    // brownout — the catalog registration stands, flagged degraded.
    let metadataWrite: RegisterSkillResult["metadataWrite"] = "skipped";
    if (!outcome.deduplicated) {
      metadataWrite = await this.writeMetadata(identity, input, contentSha, ts);
    }

    const skill = await this.loadById(outcome.skillId);
    if (!skill) throw new SkillNotFoundError();
    return {
      skill,
      deduplicated: outcome.deduplicated,
      superseded: outcome.superseded,
      metadataWrite,
    };
  }

  /**
   * Redefine one selected current skill. The row id is the optimistic-lock
   * token: a superseded/retired id conflicts instead of editing whichever row
   * later became current. Namespace, key, and provenance come from storage.
   */
  async update(
    identity: Identity,
    skillId: string,
    input: UpdateSkillInput,
  ): Promise<RegisterSkillResult> {
    const selected = await this.loadById(skillId);
    if (!selected) {
      await this.auditStandalone(identity, "write", skillId, identity.namespace, "miss",
        `skill=${skillId} not found`, "skill-update");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, selected.namespace)) {
      await this.auditStandalone(identity, "write", skillId, selected.namespace, "denied",
        `skill=${skillId} role=${identity.role}`, "skill-update");
      throw new SkillAuthorizationError();
    }
    if (selected.tValidTo !== null || selected.status !== "active") {
      await this.auditStandalone(identity, "write", skillId, selected.namespace, "denied",
        `skill=${skillId} not current (superseded or archived)`, "skill-update");
      throw new SkillConflictError();
    }

    const effectiveIdentity = { ...identity, namespace: selected.namespace };
    const registerInput: RegisterSkillInput = {
      skillKey: selected.skillKey,
      name: input.name.trim(),
      description: input.description ?? "",
      definition: input.definition,
      ...(selected.sourceId ? { sourceId: selected.sourceId } : {}),
      ...(selected.sourceKind ? { sourceKind: selected.sourceKind } : {}),
    };
    this.validateRegisterInput(registerInput);
    const ts = this.now().toISOString();
    const contentSha = sha256Hex(registerInput.definition);
    const id = ulid();

    let outcome: { skillId: string; deduplicated: boolean; superseded: boolean };
    try {
      outcome = await this.deps.db.transaction(async (tx) => {
      const locked = await tx.query(
        `SELECT * FROM skills WHERE id = $1 FOR UPDATE`,
        [skillId],
      );
      const current = locked.rows[0] as SkillRow | undefined;
      if (!current || current.t_valid_to !== null || current.status !== "active") {
        throw new SkillConflictError();
      }
      if (current.namespace !== selected.namespace || current.skill_key !== selected.skillKey) {
        throw new SkillConflictError();
      }

      const unchanged =
        current.content_sha256 === contentSha &&
        current.name === registerInput.name &&
        current.description === (registerInput.description ?? "");
      if (unchanged) {
        await this.audit(tx, effectiveIdentity, "write", current.id, selected.namespace, "ok",
          `skill-update deduplicated key=${selected.skillKey} sha=${contentSha.slice(0, 12)}`,
          "skill-update");
        return { skillId: current.id, deduplicated: true, superseded: false };
      }

      const closed = await tx.query(
        `UPDATE skills SET t_valid_to = $2, updated_at = $2
          WHERE id = $1 AND t_valid_to IS NULL AND status = 'active'
          RETURNING id`,
        [skillId, ts],
      );
      if (closed.rows.length !== 1) throw new SkillConflictError();

      await tx.query(
        `INSERT INTO skills
           (id, namespace, skill_key, name, description, definition, content_sha256,
            source_id, source_kind, vetting_status, safety_score, last_vetted_at,
            approval_status, approved_by, approved_at,
            supersedes, t_valid_from, t_valid_to, status, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'unvetted', NULL, NULL,
                 'approved', $12, $11, $10, $11, NULL, 'active', $12, $11, $11)`,
        [
          id, selected.namespace, selected.skillKey, registerInput.name,
          registerInput.description ?? "", registerInput.definition, contentSha,
          selected.sourceId, selected.sourceKind, skillId, ts, identity.actor,
        ],
      );
      await this.audit(tx, effectiveIdentity, "supersede", skillId, selected.namespace, "ok",
        `skill update; superseded by ${id} key=${selected.skillKey}`, "skill-update");
      await this.audit(tx, effectiveIdentity, "write", id, selected.namespace, "ok",
        `skill-update key=${selected.skillKey} sha=${contentSha.slice(0, 12)} supersedes=${skillId}`,
        "skill-update");
      return { skillId: id, deduplicated: false, superseded: true };
      });
    } catch (err) {
      if (err instanceof SkillConflictError) {
        // Transactional audit rows roll back with the losing update. Record the
        // rejected syscall separately so a concurrent edit never disappears.
        await this.auditStandalone(identity, "write", skillId, selected.namespace, "denied",
          `skill=${skillId} changed concurrently`, "skill-update");
      }
      throw err;
    }

    let metadataWrite: RegisterSkillResult["metadataWrite"] = "skipped";
    if (!outcome.deduplicated) {
      metadataWrite = await this.writeMetadata(effectiveIdentity, registerInput, contentSha, ts);
    }
    const skill = await this.loadById(outcome.skillId);
    if (!skill) throw new SkillNotFoundError();
    return { skill, ...outcome, metadataWrite };
  }

  /**
   * Current (t_valid_to IS NULL) skills visible to the caller, each carrying
   * its derived monitoring risk band (S16): "good" when vetted, "critical"
   * when blocked or when the latest FINALIZED vetting run reported a
   * critical-severity finding, "risky" otherwise. The critical-finding check
   * is one grouped query over the visible ids — never N+1. Superseded chain
   * rows are reachable per-skill via {@link history}. Rows are filtered by
   * exact ancestor-string computation, mirroring the dispute queue — never a
   * SQL pattern predicate.
   */
  async list(identity: Identity): Promise<Array<SkillRecord & { riskBand: SkillRiskBand }>> {
    const res = await this.deps.db.query(
      `${SKILL_SELECT} WHERE s.t_valid_to IS NULL ORDER BY s.namespace, s.skill_key`,
    );
    const skills = res.rows
      .filter((row) => canReadSkill(identity, (row as SkillRow).namespace))
      .map(rowToSkill);
    const critical = await this.latestRunsWithCritical(skills.map((s) => s.id));
    return skills.map((skill) => ({
      ...skill,
      riskBand: riskBandFor(skill, critical.has(skill.id)),
    }));
  }

  /**
   * Ids (out of `skillIds`) whose NEWEST finalized (passed/failed) vetting
   * run contains a critical-severity finding. DISTINCT ON picks the latest
   * run per skill; running/errored runs are not verdicts and are ignored.
   */
  private async latestRunsWithCritical(skillIds: string[]): Promise<Set<string>> {
    if (skillIds.length === 0) return new Set();
    const placeholders = skillIds.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.deps.db.query(
      `SELECT DISTINCT ON (skill_id) skill_id, findings
         FROM skill_vetting_runs
        WHERE status IN ('passed','failed') AND skill_id IN (${placeholders})
        ORDER BY skill_id, started_at DESC`,
      skillIds,
    );
    const critical = new Set<string>();
    for (const row of res.rows) {
      const r = row as { skill_id: string; findings: unknown };
      const findings = typeof r.findings === "string"
        ? (JSON.parse(r.findings) as Array<{ severity?: unknown }>)
        : ((r.findings ?? []) as Array<{ severity?: unknown }>);
      if (findings.some((f) => f.severity === "critical")) critical.add(r.skill_id);
    }
    return critical;
  }

  /** One skill row (any chain position) with an ACL check. */
  async get(identity: Identity, skillId: string): Promise<SkillRecord> {
    const skill = await this.loadById(skillId);
    if (!skill || !canReadSkill(identity, skill.namespace)) {
      // Not-found and not-visible are indistinguishable to the caller.
      throw new SkillNotFoundError();
    }
    return skill;
  }

  /**
   * Full supersedence chain for the (namespace, skillKey) of a skill row,
   * newest first — the D7 audit trail of every definition the key ever had.
   */
  async history(identity: Identity, skillId: string): Promise<SkillRecord[]> {
    const skill = await this.get(identity, skillId);
    const res = await this.deps.db.query(
      `${SKILL_SELECT}
        WHERE s.namespace = $1 AND s.skill_key = $2
        ORDER BY s.t_valid_from DESC`,
      [skill.namespace, skill.skillKey],
    );
    return res.rows.map(rowToSkill);
  }

  /**
   * Human discovery metadata follows the stable namespace/key identity. This
   * method never updates the skills table, never creates a version, and never
   * queues vetting. Handling is intentionally absent from the input type.
   */
  async updateLabels(
    identity: Identity,
    skillId: string,
    input: UpdateSkillLabelsInput,
  ): Promise<SkillRecord> {
    const selected = await this.loadById(skillId);
    if (!selected) {
      await this.auditStandalone(identity, "write", skillId, identity.namespace, "miss",
        `skill=${skillId} not found`, "skill-labels");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, selected.namespace)) {
      await this.auditStandalone(identity, "write", skillId, selected.namespace, "denied",
        `skill=${skillId} role=${identity.role}`, "skill-labels");
      throw new SkillAuthorizationError();
    }
    if (selected.tValidTo !== null || selected.status !== "active") {
      throw new SkillConflictError();
    }

    const category = input.category.trim();
    const purpose = input.purpose.trim();
    const tags = [...new Set(input.tags.map(normalizeTag))];
    if (!category || category.length > 80) throw new SkillLabelValidationError("invalid skill category");
    if (purpose.length > MAX_LABEL_PURPOSE_LENGTH) {
      throw new SkillLabelValidationError("skill purpose must be 140 characters or fewer");
    }
    if (tags.length > MAX_SKILL_TAGS || tags.some((tag) => !SKILL_TAG_PATTERN.test(tag))) {
      throw new SkillLabelValidationError("skill tags must be unique lowercase slugs (maximum 10)");
    }
    if (!BUILT_IN_SKILL_CATEGORIES.has(category)) {
      const custom = await this.deps.db.query(
        `SELECT namespace FROM skill_categories WHERE name = $1`,
        [category],
      );
      const allowed = custom.rows.some((row) =>
        namespaceAncestors(selected.namespace).includes(String((row as { namespace: string }).namespace))
      );
      if (!allowed) throw new SkillLabelValidationError("unknown skill category");
    }

    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const locked = await tx.query(
        `SELECT category, purpose, tags, handling
           FROM skill_labels
          WHERE namespace = $1 AND skill_key = $2
          FOR UPDATE`,
        [selected.namespace, selected.skillKey],
      );
      const prior = locked.rows[0] as {
        category?: string;
        purpose?: string;
        tags?: unknown;
        handling?: unknown;
      } | undefined;
      const before = prior
        ? {
            category: String(prior.category ?? selected.labels.category),
            purpose: String(prior.purpose ?? selected.labels.purpose),
            tags: Array.isArray(prior.tags) ? prior.tags.map(String) : selected.labels.tags,
          }
        : {
            category: selected.labels.category,
            purpose: selected.labels.purpose,
            tags: selected.labels.tags,
          };
      const handling = prior && Array.isArray(prior.handling)
        ? prior.handling.map(String)
        : selected.labels.handling;

      await tx.query(
        `INSERT INTO skill_labels
           (namespace, skill_key, category, purpose, tags, handling,
            created_by, created_at, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $8)
         ON CONFLICT (namespace, skill_key) DO UPDATE
           SET category = EXCLUDED.category,
               purpose = EXCLUDED.purpose,
               tags = EXCLUDED.tags,
               updated_by = EXCLUDED.updated_by,
               updated_at = EXCLUDED.updated_at`,
        [
          selected.namespace, selected.skillKey, category, purpose,
          JSON.stringify(tags), JSON.stringify(handling), identity.actor, ts,
        ],
      );

      const changes: Array<{ field: SkillLabelHistoryRecord["field"]; before: string | string[]; after: string | string[] }> = [];
      if (before.category !== category) changes.push({ field: "category", before: before.category, after: category });
      if (before.purpose !== purpose) changes.push({ field: "purpose", before: before.purpose, after: purpose });
      if (JSON.stringify(before.tags) !== JSON.stringify(tags)) {
        changes.push({ field: "tags", before: before.tags, after: tags });
      }
      for (const change of changes) {
        await tx.query(
          `INSERT INTO skill_label_history
             (id, namespace, skill_key, skill_id, field, before_value, after_value,
              changed_by, changed_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            ulid(), selected.namespace, selected.skillKey, skillId, change.field,
            JSON.stringify(change.before), JSON.stringify(change.after), identity.actor, ts,
          ],
        );
      }
      for (const tag of tags) {
        await tx.query(
          `INSERT INTO skill_tags
             (id, namespace, name, facet, aliases, created_by, created_at, updated_at)
           VALUES ($1, $2, $3, 'Function', '[]', $4, $5, $5)
           ON CONFLICT (namespace, name) DO NOTHING`,
          [ulid(), selected.namespace, tag, identity.actor, ts],
        );
      }
      await this.audit(tx, identity, "write", skillId, selected.namespace, "ok",
        `skill-labels fields=${changes.map((change) => change.field).join(",") || "none"}`,
        "skill-labels");
    });

    const updated = await this.loadById(skillId);
    if (!updated) throw new SkillNotFoundError();
    return updated;
  }

  async labelHistory(identity: Identity, skillId: string): Promise<SkillLabelHistoryRecord[]> {
    const skill = await this.get(identity, skillId);
    const result = await this.deps.db.query(
      `SELECT id, field, before_value, after_value, changed_by, changed_at
         FROM skill_label_history
        WHERE namespace = $1 AND skill_key = $2
        ORDER BY changed_at DESC, id DESC`,
      [skill.namespace, skill.skillKey],
    );
    const jsonValue = (value: unknown): string | string[] => {
      if (Array.isArray(value)) return value.map(String);
      if (typeof value !== "string") return String(value ?? "");
      try {
        const parsed = JSON.parse(value) as unknown;
        return Array.isArray(parsed) ? parsed.map(String) : String(parsed ?? "");
      } catch {
        return value;
      }
    };
    return result.rows.map((row) => {
      const record = row as Record<string, unknown>;
      return {
        id: String(record.id),
        field: String(record.field) as SkillLabelHistoryRecord["field"],
        before: jsonValue(record.before_value),
        after: jsonValue(record.after_value),
        changedBy: String(record.changed_by),
        changedAt: toIso(record.changed_at),
      };
    });
  }

  /**
   * The E22 gate + E20 audit + usage rollup, atomically. Resolves the
   * NEAREST currently-valid skill for `skillKey` along the caller's ancestor
   * chain (exact IN list), decides, and always writes a `skill_invoke`
   * audit row — ok, denied, and miss alike (D4).
   */
  async invoke(identity: Identity, skillKey: string): Promise<SkillInvokeDecision> {
    const ancestors = namespaceAncestors(identity.namespace);
    const ts = this.now().toISOString();

    return this.deps.db.transaction(async (tx) => {
      const placeholders = ancestors.map((_, i) => `$${i + 2}`).join(", ");
      const res = await tx.query(
        `${SKILL_SELECT}
          WHERE s.skill_key = $1 AND s.t_valid_to IS NULL
            AND s.namespace IN (${placeholders})`,
        [skillKey, ...ancestors],
      );
      const rows = res.rows.map(rowToSkill);
      if (rows.length === 0) {
        await this.audit(tx, identity, "skill_invoke", null, identity.namespace, "miss",
          `key=${skillKey} no visible skill`, "skill-invoke");
        return { allowed: false, reason: "not-found" as const, skill: null };
      }
      // Nearest definition wins: the deepest ancestor namespace.
      rows.sort((a, b) => b.namespace.length - a.namespace.length);
      const skill = rows[0]!;

      const decision = await this.decide(tx, skill);
      const allowed = decision === "vetted" || decision === "override";
      await this.audit(tx, identity, "skill_invoke", skill.id, skill.namespace,
        allowed ? "ok" : "denied",
        `key=${skillKey} skill=${skill.id} vetting=${skill.vettingStatus} via=${decision}`,
        "skill-invoke");
      await this.bumpUsage(tx, identity, skill, allowed, decision === "override", ts);
      return { allowed, reason: decision, skill };
    });
  }

  /**
   * Audited admin override (E22): the append-only `skill_override` audit row
   * bound to this EXACT skill row id is the durable grant checked by
   * {@link invoke}. A redefinition mints a new row id, so the override never
   * carries over to changed content. Denied attempts audit too (D4).
   */
  async override(identity: Identity, skillId: string, reason: string): Promise<SkillRecord> {
    const trimmed = reason.trim();
    if (trimmed.length === 0 || trimmed.length > 1_000) {
      throw new Error("override reason must be 1..1000 characters");
    }
    const skill = await this.loadById(skillId);
    if (!skill) {
      await this.auditStandalone(identity, "skill_override", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`, "skill-override");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, skill.namespace)) {
      await this.auditStandalone(identity, "skill_override", skillId, skill.namespace,
        "denied", `skill=${skillId} role=${identity.role}`, "skill-override");
      throw new SkillAuthorizationError();
    }
    if (skill.tValidTo !== null || skill.status !== "active") {
      await this.auditStandalone(identity, "skill_override", skillId, skill.namespace,
        "denied", `skill=${skillId} not current (superseded or archived)`, "skill-override");
      throw new SkillConflictError();
    }
    if (skill.vettingStatus === "vetted") {
      // Nothing to override — refuse rather than mint a meaningless grant.
      await this.auditStandalone(identity, "skill_override", skillId, skill.namespace,
        "denied", `skill=${skillId} already vetted; override refused`, "skill-override");
      throw new SkillConflictError();
    }
    await this.auditStandalone(identity, "skill_override", skillId, skill.namespace, "ok",
      `reason=${trimmed}`, "skill-override");
    return skill;
  }

  /**
   * S16 approval: a team admin (owner/admin over the skill's namespace
   * subtree, E21 management view) promotes a member submission from
   * `pending` to `approved`, recorded on the CURRENT row with the approver's
   * actor and timestamp. Only `pending` transitions — an already-approved or
   * rejected row is a conflict. Denials and misses audit too (D4).
   */
  async approve(identity: Identity, skillId: string): Promise<SkillRecord> {
    const skill = await this.loadById(skillId);
    if (!skill) {
      await this.auditStandalone(identity, "skill_approve", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`, "skill-approve");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, skill.namespace)) {
      await this.auditStandalone(identity, "skill_approve", skillId, skill.namespace,
        "denied", `skill=${skillId} role=${identity.role}`, "skill-approve");
      throw new SkillAuthorizationError();
    }
    if (skill.tValidTo !== null || skill.status !== "active") {
      await this.auditStandalone(identity, "skill_approve", skillId, skill.namespace,
        "denied", `skill=${skillId} not current (superseded or archived)`, "skill-approve");
      throw new SkillConflictError();
    }
    if (skill.approvalStatus !== "pending") {
      await this.auditStandalone(identity, "skill_approve", skillId, skill.namespace,
        "denied", `skill=${skillId} approval=${skill.approvalStatus}; not pending`,
        "skill-approve");
      throw new SkillConflictError();
    }
    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const updated = await tx.query(
        `UPDATE skills
            SET approval_status = 'approved', approved_by = $2, approved_at = $3, updated_at = $3
          WHERE id = $1 AND t_valid_to IS NULL AND approval_status = 'pending'
          RETURNING id`,
        [skillId, identity.actor, ts],
      );
      if (updated.rows.length !== 1) throw new SkillConflictError();
      await this.audit(tx, identity, "skill_approve", skillId, skill.namespace, "ok",
        `skill approved key=${skill.skillKey}`, "skill-approve");
    });
    const approved = await this.loadById(skillId);
    if (!approved) throw new SkillNotFoundError();
    return approved;
  }

  /**
   * S16 rejection: the mirror of {@link approve} — a team admin marks a
   * pending member submission `rejected` (approver fields cleared) with a
   * mandatory 1..1000-char reason recorded in the audit detail. The row and
   * its definition survive (D7); only the pending gate closes.
   */
  async reject(identity: Identity, skillId: string, reason: string): Promise<SkillRecord> {
    const trimmed = reason.trim();
    if (trimmed.length === 0 || trimmed.length > 1_000) {
      throw new Error("reject reason must be 1..1000 characters");
    }
    const skill = await this.loadById(skillId);
    if (!skill) {
      await this.auditStandalone(identity, "skill_reject", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`, "skill-reject");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, skill.namespace)) {
      await this.auditStandalone(identity, "skill_reject", skillId, skill.namespace,
        "denied", `skill=${skillId} role=${identity.role}`, "skill-reject");
      throw new SkillAuthorizationError();
    }
    if (skill.tValidTo !== null || skill.status !== "active") {
      await this.auditStandalone(identity, "skill_reject", skillId, skill.namespace,
        "denied", `skill=${skillId} not current (superseded or archived)`, "skill-reject");
      throw new SkillConflictError();
    }
    if (skill.approvalStatus !== "pending") {
      await this.auditStandalone(identity, "skill_reject", skillId, skill.namespace,
        "denied", `skill=${skillId} approval=${skill.approvalStatus}; not pending`,
        "skill-reject");
      throw new SkillConflictError();
    }
    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const updated = await tx.query(
        `UPDATE skills
            SET approval_status = 'rejected', approved_by = NULL, approved_at = NULL,
                updated_at = $2
          WHERE id = $1 AND t_valid_to IS NULL AND approval_status = 'pending'
          RETURNING id`,
        [skillId, ts],
      );
      if (updated.rows.length !== 1) throw new SkillConflictError();
      await this.audit(tx, identity, "skill_reject", skillId, skill.namespace, "ok",
        `reason=${trimmed}`, "skill-reject");
    });
    const rejected = await this.loadById(skillId);
    if (!rejected) throw new SkillNotFoundError();
    return rejected;
  }

  /**
   * Governed download (S16): a skill is distributable iff it is the CURRENT
   * row, active, approved, and vetted — "approved and status good". Every
   * outcome writes a `read` audit row with purpose `skill-export` (D4): the
   * ok export, the gated denial, and the miss alike. The content is the raw
   * definition under YAML frontmatter carrying the provenance an installer
   * needs (sha, score, approver) — nothing escaped, it is the user's own
   * content; only frontmatter string values are quoted safely.
   */
  async exportSkill(identity: Identity, skillId: string): Promise<SkillExport> {
    const skill = await this.loadById(skillId);
    if (!skill || !canReadSkill(identity, skill.namespace)) {
      // Not-found and not-visible are indistinguishable to the caller.
      await this.auditStandalone(identity, "read", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`, "skill-export");
      throw new SkillNotFoundError();
    }
    const distributable =
      skill.tValidTo === null && skill.status === "active" &&
      skill.approvalStatus === "approved" && skill.vettingStatus === "vetted";
    if (!distributable) {
      await this.auditStandalone(identity, "read", skillId, skill.namespace, "denied",
        `skill=${skillId} not distributable approval=${skill.approvalStatus} ` +
        `vetting=${skill.vettingStatus} status=${skill.status}`, "skill-export");
      throw new SkillAuthorizationError();
    }
    await this.auditStandalone(identity, "read", skillId, skill.namespace, "ok",
      `skill exported key=${skill.skillKey} sha=${skill.contentSha256.slice(0, 12)}`,
      "skill-export");
    return { filename: `${skill.skillKey}.md`, content: renderSkillMarkdown(skill) };
  }

  /**
   * Retire: archive + close validity (D7 — the row and its history survive).
   * Guarded on current validity so concurrent redefinition wins cleanly.
   */
  async retire(identity: Identity, skillId: string): Promise<SkillRecord> {
    const skill = await this.loadById(skillId);
    if (!skill) {
      await this.auditStandalone(identity, "retract", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`, "skill-retire");
      throw new SkillNotFoundError();
    }
    if (!canManageSkill(identity, skill.namespace)) {
      await this.auditStandalone(identity, "retract", skillId, skill.namespace,
        "denied", `skill=${skillId} role=${identity.role}`, "skill-retire");
      throw new SkillAuthorizationError();
    }
    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const closed = await tx.query(
        `UPDATE skills SET status = 'archived', t_valid_to = $2, updated_at = $2
          WHERE id = $1 AND t_valid_to IS NULL
          RETURNING id`,
        [skillId, ts],
      );
      if (closed.rows.length !== 1) throw new SkillConflictError();
      await this.audit(tx, identity, "retract", skillId, skill.namespace, "ok",
        `skill retired key=${skill.skillKey}`, "skill-retire");
    });
    const retired = await this.loadById(skillId);
    if (!retired) throw new SkillNotFoundError();
    return retired;
  }

  // -------------------------------------------------------------------------

  /** True when an ok `skill_override` audit row exists for this exact row id. */
  async hasOverride(db: Db, skillId: string): Promise<boolean> {
    const res = await db.query(
      `SELECT 1 FROM audit_log
        WHERE op = 'skill_override' AND result = 'ok' AND memory_id = $1
        LIMIT 1`,
      [skillId],
    );
    return res.rows.length > 0;
  }

  private async decide(
    tx: Db,
    skill: SkillRecord,
  ): Promise<SkillInvokeDecision["reason"]> {
    if (skill.status !== "active") return "archived";
    // S16 approval gate runs BEFORE the vetting checks: a member submission
    // is invisible to agents until a team admin approves it, and a rejected
    // skill stays rejected — both deny and audit like every other denial.
    if (skill.approvalStatus === "pending") return "pending";
    if (skill.approvalStatus === "rejected") return "rejected";
    if (skill.vettingStatus === "vetted") return "vetted";
    if (await this.hasOverride(tx, skill.id)) return "override";
    if (skill.vettingStatus === "blocked") return "blocked";
    if (skill.vettingStatus === "vetting") return "vetting";
    return "unvetted";
  }

  private async bumpUsage(
    tx: Db,
    identity: Identity,
    skill: SkillRecord,
    allowed: boolean,
    viaOverride: boolean,
    ts: string,
  ): Promise<void> {
    const usageDate = ts.slice(0, 10);
    const inv = allowed ? 1 : 0;
    const den = allowed ? 0 : 1;
    const ovr = viaOverride ? 1 : 0;
    await tx.query(
      `INSERT INTO skill_agent_usage
         (id, namespace, skill_id, key_id, actor, usage_date,
          invocations, denials, overrides, last_invoked_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
       ON CONFLICT (skill_id, key_id, usage_date) DO UPDATE SET
         invocations = skill_agent_usage.invocations + $7,
         denials = skill_agent_usage.denials + $8,
         overrides = skill_agent_usage.overrides + $9,
         last_invoked_at = COALESCE($10, skill_agent_usage.last_invoked_at),
         updated_at = $11`,
      [
        ulid(), identity.namespace, skill.id, identity.keyId, identity.actor,
        usageDate, inv, den, ovr, allowed ? ts : null, ts,
      ],
    );
  }

  private async loadById(skillId: string): Promise<SkillRecord | null> {
    const res = await this.deps.db.query(
      `${SKILL_SELECT} WHERE s.id = $1`,
      [skillId],
    );
    return res.rows.length === 0 ? null : rowToSkill(res.rows[0]);
  }

  private async writeMetadata(
    identity: Identity,
    input: RegisterSkillInput,
    contentSha: string,
    ts: string,
  ): Promise<"ok" | "degraded"> {
    if (!this.deps.writeMemory) return "degraded";
    const description = input.description ?? "";
    const content =
      `Skill "${input.name}" (${input.skillKey}) is available in the company skill library.` +
      (description.length > 0 ? ` ${description}` : "");
    const req: WriteRequest = {
      namespace: identity.namespace,
      scope: "org",
      content,
      actor: identity.actor,
      hints: { type: "fact", verbatim: true },
      provenance: {
        source: "document",
        sourceId: input.sourceId ?? `skill:${input.skillKey}`,
        documentKey: `skill/${input.skillKey}`,
        contentHash: contentSha,
      },
    };
    try {
      await this.deps.writeMemory(identity, req);
      return "ok";
    } catch (err) {
      // Brownout (rule 5): the catalog registration stands; log the miss.
      await this.auditStandalone(identity, "write", null, identity.namespace, "error",
        `skill-metadata write degraded key=${input.skillKey}: ` +
        `${err instanceof Error ? err.message : String(err)}`, "skill-register");
      return "degraded";
    }
  }

  private validateRegisterInput(input: RegisterSkillInput): void {
    if (!SKILL_KEY_PATTERN.test(input.skillKey)) {
      throw new Error("skillKey must match [a-z0-9][a-z0-9._-]{0,199}");
    }
    const name = input.name.trim();
    if (name.length === 0 || name.length > MAX_NAME_LENGTH) {
      throw new Error(`name must be 1..${MAX_NAME_LENGTH} characters`);
    }
    if ((input.description ?? "").length > MAX_DESCRIPTION_LENGTH) {
      throw new Error(`description must be at most ${MAX_DESCRIPTION_LENGTH} characters`);
    }
    if (input.definition.length === 0 || input.definition.length > MAX_DEFINITION_LENGTH) {
      throw new Error(`definition must be 1..${MAX_DEFINITION_LENGTH} characters`);
    }
  }

  private audit(
    tx: Db,
    identity: Identity,
    op: AuditOp,
    memoryId: MemoryId | null,
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
    purpose: string,
  ): Promise<void> {
    return this.deps.audit.appendTo(tx, {
      ts: this.now().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId,
      namespace,
      purpose,
      result,
      detail,
    });
  }

  private auditStandalone(
    identity: Identity,
    op: AuditOp,
    memoryId: MemoryId | null,
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
    purpose: string,
  ): Promise<void> {
    return this.deps.db.transaction((tx) =>
      this.audit(tx, identity, op, memoryId, namespace, result, detail, purpose),
    );
  }
}
