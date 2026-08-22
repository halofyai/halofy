/**
 * M9 #7 — Governed markdown export (locks D28).
 *
 * Every export is a governed egress event:
 *
 *   canExport(role, source, classification)  →  render active L2/L3 to .md
 *                                            →  append-only `export` audit row
 *
 * Ordering is load-bearing (E15): the role gate runs before ANY read, and the
 * per-row `canExport` decision runs before that row is rendered — never
 * render-then-check. A denied export still writes an audit row (E16, D4).
 *
 * Reads happen ONLY through the ACL-scoped MemoryIndex candidate listing and
 * an ACL-scoped concept lister the kernel injects (E17) — this module imports
 * no storage, write-path, or db module. The deps below are STRUCTURAL slices
 * (same pattern as src/driver/view.ts): the concrete `MemoryIndex`
 * (src/index) and `ColdStore.listConcepts` (whose query enforces the private
 * ancestor ACL + explicit-public rule) satisfy them as-is.
 *
 * No parallel permission system is invented: role vocabulary is `ROLES`
 * (src/auth), classification comes from the stored row classification or the
 * existing DLP classifier (src/dlp/classifier.ts) for L3 concept bodies, and
 * the classification gate is the existing DLP destination policy evaluated
 * for the `export` destination — egress reuses ingest-grade governance (D28).
 *
 * Fail-closed defaults:
 *   - roles: only owner/admin/auditor may export; member/agent are denied.
 *   - sources: `live-fetch` cache facts (D14 external content) and rows with
 *     no establishable source are not exportable.
 *   - classification: public/internal export freely; confidential/restricted
 *     only with an explicit `export` entry in `allowedDestinations`;
 *     residency-tagged data never exports (egress region is unknown).
 */

import { createHash } from "node:crypto";
import { classifyData } from "../dlp/classifier.js";
import { destinationAllowed } from "../dlp/policy.js";
import { AuthzError, ROLES } from "../auth/index.js";
import type {
  AccessSubject,
  AuditEvent,
  Concept,
  DataClassification,
  Identity,
  MemoryObject,
  MemoryReadScope,
  Namespace,
  Role,
} from "../types.js";

// ---------------------------------------------------------------------------
// Structural dependency slices (E17: ACL-scoped readers only — no store,
// write-path, or db import; the kernel wires the concrete instances).
// ---------------------------------------------------------------------------

/** Slice of module A's MemoryIndex — already ACL-scoped, active, valid-only. */
export interface ExportIndexLike {
  listCandidates(
    namespace: Namespace,
    opts?: { validOnly?: boolean; limit?: number; access?: AccessSubject },
  ): Promise<MemoryObject[]>;
}

/**
 * ACL-scoped L3 concept lister. `ColdStore.listConcepts(namespace)` satisfies
 * this shape as-is (it admits a concept iff it is explicitly public or its
 * namespace is visible to the caller, plus explicit mounts).
 */
export interface ExportConceptsLike {
  listConcepts(namespace: Namespace): Promise<Concept[]>;
}

/** Append-only audit slice (D4). */
export interface ExportAuditLike {
  append(event: AuditEvent): Promise<void>;
}

export interface ExporterDeps {
  index: ExportIndexLike;
  concepts: ExportConceptsLike;
  audit: ExportAuditLike;
  /**
   * Server-resolved read authority for SCOPED exports only (never
   * caller-assertable — the HTTP schema rejects it, the kernel injects it).
   * Required for the `""` organization root, whose downward reach must carry
   * the Amendment A1 registered-tenant exclusions the module cannot derive
   * without a db; non-root callers derive their own subtree from the
   * credential namespace and only merge `excludePrefixes` from here.
   */
  readScope?: MemoryReadScope;
}

/**
 * Source-ACL subject derived ONLY from the server-resolved identity (D9).
 * Mirrors `sourceAccessSubject` in src/syscalls/index.ts exactly; duplicated
 * here (10 pure lines) because this module's contract dependency set is
 * src/dlp + src/auth + ACL MemoryIndex + src/audit — importing the syscall
 * layer would transitively pull the write path into an egress-only module.
 */
export function exportAccessSubject(identity: Identity): AccessSubject {
  const principals = new Set<string>([
    identity.actor,
    identity.keyId,
    ...(identity.sourcePrincipals ?? []),
  ]);
  return {
    principals: [...principals].filter((value) => value.length > 0).slice(0, 256),
    groups: [...new Set(identity.sourceGroups ?? [])]
      .filter((value) => value.length > 0)
      .slice(0, 256),
  };
}

// ---------------------------------------------------------------------------
// canExport — the D28 gate. Pure and synchronous so it can run before any
// read or render, and per row before that row is rendered.
// ---------------------------------------------------------------------------

export type ExportDenialReason = "role" | "source" | "classification";

export interface ExportDecision {
  allowed: boolean;
  reason?: ExportDenialReason;
  detail?: string;
}

/** Roles permitted to perform exports. Member/agent are denied by default. */
export const EXPORT_ROLES: readonly Role[] = ["owner", "admin", "auditor"];

/**
 * Sources that never export: `live-fetch` rows are TTL'd caches of external
 * governed content (D14) — exporting them would re-distribute source-governed
 * data outside its lifecycle; `unknown` is the fail-closed bucket for rows
 * whose source cannot be established.
 */
export const EXPORT_DENIED_SOURCES: readonly string[] = ["live-fetch", "unknown"];

/** The DLP destination name an export egress evaluates against. */
export const EXPORT_DESTINATION = "export";

/** Least-privileged classification used for the pre-read role-only gate. */
const ROLE_GATE_CLASSIFICATION: DataClassification = {
  sensitivity: "public",
  piiSubjects: [],
  secretKinds: [],
  allowedDestinations: [],
};

/** Fail-closed classification for a row that somehow carries none. */
const FAIL_CLOSED_CLASSIFICATION: DataClassification = {
  sensitivity: "restricted",
  piiSubjects: [],
  secretKinds: [],
  allowedDestinations: [],
};

/**
 * D28 gate. `source === null` means "role-only check" (used once, before any
 * read). Classification is evaluated via the existing DLP destination policy
 * for the `export` destination — public/internal pass; confidential and
 * restricted require an explicit `export` entry in `allowedDestinations`;
 * residency-tagged classifications fail (the egress region is unknown).
 */
export function canExport(
  role: Role,
  source: string | null,
  classification: DataClassification,
): ExportDecision {
  if (!(ROLES as readonly string[]).includes(role) || !EXPORT_ROLES.includes(role)) {
    return {
      allowed: false,
      reason: "role",
      detail: `role '${role}' may not export`,
    };
  }
  if (source !== null && EXPORT_DENIED_SOURCES.includes(source)) {
    return {
      allowed: false,
      reason: "source",
      detail: `source '${source}' is not exportable`,
    };
  }
  if (!destinationAllowed(classification, EXPORT_DESTINATION)) {
    return {
      allowed: false,
      reason: "classification",
      detail: `sensitivity '${classification.sensitivity}' is not cleared for '${EXPORT_DESTINATION}'`,
    };
  }
  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Source + classification derivation for rows and concepts
// ---------------------------------------------------------------------------

/**
 * The exportable source label of an L2 row.
 *
 * D14 first: a write-back cache fact (l4WriteBack) ALWAYS carries BOTH
 * `source:'live-fetch'` AND `sourceId:<connectorId>` (plus `cache:true`) on
 * the same provenance entry — so the denied `live-fetch` label must win over
 * the connector attribution, or the D28 source gate would never fire for a
 * real cache fact. The check trusts the robust `cache` stamp as well as the
 * label, the same signal `isManifestRow` (src/discovery/manifest.ts) uses.
 *
 * Otherwise: the most recent provenance entry carrying a connector/importer
 * `sourceId` wins (that is the "where from" answer for bulk-ingested data,
 * e.g. "fs:handbook"); then the first entry's source kind ("conversation",
 * "document", …). No provenance at all is the fail-closed `unknown` bucket.
 */
export function exportSource(obj: MemoryObject): string {
  for (const entry of obj.provenance) {
    if (entry.cache === true || entry.source === "live-fetch") return "live-fetch";
  }
  for (let i = obj.provenance.length - 1; i >= 0; i--) {
    const sourceId = obj.provenance[i].sourceId;
    if (sourceId !== undefined && sourceId.length > 0) return sourceId;
  }
  return obj.provenance[0]?.source ?? "unknown";
}

/** L3 concepts are produced by the consolidation pipeline. */
export const CONCEPT_SOURCE = "consolidation";

/**
 * Concepts carry no stored DataClassification — reuse the existing DLP
 * classifier over the full text (title + description + body) with the
 * concept's declared PII subjects as hints. A secret pasted into a concept
 * body classifies restricted and is therefore excluded from export.
 */
export function conceptClassification(concept: Concept): DataClassification {
  return classifyData(`${concept.title}\n${concept.description}\n${concept.body}`, {
    piiSubjects: concept.piiSubjects ?? [],
  });
}

// ---------------------------------------------------------------------------
// Options / result shapes
// ---------------------------------------------------------------------------

export type ExportTier = "L2" | "L3";

/**
 * Target selection for a scoped export (D9: a selection, not an identity
 * assertion — same pattern as the erasure ForgetTarget). `team` is a
 * namespace subtree inside the caller's downward reach; `user` is a
 * provenance actor, matched exactly like the erasure engine's actor target.
 */
export type ExportScope =
  | { kind: "team"; namespace: Namespace }
  | { kind: "user"; actor: string };

export interface ExportOptions {
  /** Free-text purpose recorded on the audit row (capped at 500 chars). */
  purpose?: string;
  /** Which authoritative tiers to render; defaults to both. */
  tiers?: readonly ExportTier[];
  /** Rows considered: no cap by default (the export is complete); explicit limit clamps to 1..ALL_ROWS. */
  limit?: number;
  /** Absent = the caller's entire visible memory (unchanged behaviour). */
  scope?: ExportScope;
}

export interface ExportResult {
  markdown: string;
  /** Suggested download filename ("halomem-export-<ns>-<date>.md"). */
  filename: string;
  /** sha256 hex of the rendered markdown — the audit row's egress evidence. */
  sha256: string;
  includedL2: number;
  includedL3: number;
  /** Rows/concepts the gate excluded, tallied by denial reason. */
  excluded: Record<ExportDenialReason, number>;
  /** Machine-readable, versioned bundle containing the complete allowed objects. */
  portableJson: string;
  /** Suggested download filename for the portable JSON bundle. */
  portableFilename: string;
  /** sha256 hex of the exact portable JSON bytes. */
  portableSha256: string;
  /** Withholding evidence split by authoritative tier. */
  excludedByTier: Record<ExportTier, Record<ExportDenialReason, number>>;
}

export const PORTABLE_EXPORT_SCHEMA = "halomem.memory-export/v1";

/**
 * "All visible rows" bound — the same idiom the discovery manifest and
 * memStats use for a COMPLETE listing against listCandidates (int4 max).
 * A governed egress that silently truncates at 500 rows while claiming to
 * be the caller's entire memory is worse than no export at all.
 */
const ALL_ROWS = 2_147_483_647;
const PURPOSE_MAX = 500;
const EXPORT_AGENT_ID = "export";

// ---------------------------------------------------------------------------
// Markdown rendering (only ever called for rows that passed canExport)
// ---------------------------------------------------------------------------

function renderL2Row(obj: MemoryObject, source: string): string {
  const classification = obj.classification ?? FAIL_CLOSED_CLASSIFICATION;
  const lines = [
    `### ${obj.id} (${obj.type})`,
    "",
    obj.content,
    "",
    `- source: \`${source}\``,
    `- confidence: ${obj.confidence}`,
    `- valid from: ${obj.tValidFrom}`,
    `- sensitivity: ${classification.sensitivity}`,
  ];
  if (obj.supersedes !== null) lines.push(`- supersedes: ${obj.supersedes}`);
  return lines.join("\n");
}

function renderConcept(concept: Concept): string {
  const lines = [
    `### ${concept.title}`,
    "",
    `- path: \`${concept.path}\``,
    `- type: ${concept.type}`,
  ];
  if (concept.tags.length > 0) lines.push(`- tags: ${concept.tags.join(", ")}`);
  if (concept.owner !== undefined) lines.push(`- owner: ${concept.owner}`);
  if (concept.verifiedAt !== undefined) lines.push(`- verified at: ${concept.verifiedAt}`);
  if (concept.description.length > 0) {
    lines.push("", concept.description);
  }
  lines.push("", concept.body.trim());
  return lines.join("\n");
}

function filenameSlug(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

function exportFilename(
  namespace: Namespace,
  isoTs: string,
  scope?: ExportScope,
  extension: "md" | "json" = "md",
): string {
  const nsPart = filenameSlug(namespace === "" ? "root" : namespace) || "root";
  const scopePart =
    scope === undefined
      ? ""
      : scope.kind === "team"
        ? `-team-${filenameSlug(scope.namespace) || "root"}`
        : `-user-${filenameSlug(scope.actor) || "unknown"}`;
  return `halomem-export-${nsPart}${scopePart}-${isoTs.slice(0, 10)}.${extension}`;
}

// ---------------------------------------------------------------------------
// The export syscall
// ---------------------------------------------------------------------------

function normalizeTiers(tiers: readonly ExportTier[] | undefined): ExportTier[] {
  if (tiers === undefined || tiers.length === 0) return ["L2", "L3"];
  const out: ExportTier[] = [];
  for (const tier of tiers) {
    if (tier !== "L2" && tier !== "L3") {
      throw new Error(`mem_export: invalid tier '${String(tier)}' (expected "L2" | "L3")`);
    }
    if (!out.includes(tier)) out.push(tier);
  }
  return out;
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit)) return ALL_ROWS;
  return Math.min(ALL_ROWS, Math.max(1, Math.floor(limit)));
}

// ---------------------------------------------------------------------------
// Scoped export (team/user) — subtree math + server-resolved read authority.
// Pure, so the scope gate can run BEFORE any read (E15), like canExport.
// ---------------------------------------------------------------------------

/** Downward subtree membership; a `""` root admits every namespace. */
function inSubtree(namespace: string, root: string): boolean {
  return root === "" || namespace === root || namespace.startsWith(root + "/");
}

/** Amendment A1: is this namespace inside an excluded (registered-tenant) prefix? */
function excludedBy(
  namespace: string,
  excludePrefixes: readonly string[] | undefined,
): boolean {
  return (excludePrefixes ?? []).some((p) => p !== "" && inSubtree(namespace, p));
}

/**
 * The downward read authority a scoped export runs under. Non-root callers
 * reach their own credential subtree (merging any kernel-supplied A1
 * exclusions); the `""` organization root REQUIRES the kernel-resolved scope
 * (its exclusions need the tenant registry) — null fails closed to denial.
 */
function scopedReadScope(
  identity: Identity,
  deps: ExporterDeps,
): MemoryReadScope | null {
  if (identity.namespace !== "") {
    return {
      exact: [],
      prefixes: [identity.namespace],
      excludePrefixes: deps.readScope?.excludePrefixes,
    };
  }
  return deps.readScope ?? null;
}

/**
 * mem_export — governed markdown egress of the caller's ACL view of the
 * authoritative tiers (active current-version L2 rows + L3 concepts; never
 * L0/L1, warm mirrors, cache pointers — pointer rows are excluded by the
 * index's default listing per D11).
 *
 * Identity is server-resolved (D9): namespace, actor, role, and the source
 * ACL subject all come from the credential — nothing here reads them from a
 * request body. Every call appends exactly one `export` audit row (D4):
 * ok / denied / miss / error.
 */
export async function memExport(
  deps: ExporterDeps,
  identity: Identity,
  options: ExportOptions = {},
  agentId: string = EXPORT_AGENT_ID,
): Promise<ExportResult> {
  const ts = new Date().toISOString();
  const purpose =
    options.purpose === undefined ? null : options.purpose.slice(0, PURPOSE_MAX);

  const appendAudit = async (
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> => {
    await deps.audit.append({
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId,
      op: "export",
      memoryId: null,
      namespace: identity.namespace,
      purpose,
      result,
      detail,
    });
  };

  // E15: the gate runs BEFORE any read or render. A role that may not export
  // is denied here — nothing has been read, nothing rendered.
  const roleGate = canExport(identity.role, null, ROLE_GATE_CLASSIFICATION);
  if (!roleGate.allowed) {
    // E16: the denied export still writes its audit row (D4).
    await appendAudit("denied", roleGate.detail ?? "export denied");
    throw new AuthzError(roleGate.detail ?? `role '${identity.role}' may not export`);
  }

  // Scope gate (E15 ordering preserved): a scoped export resolves its
  // downward read authority and validates the target BEFORE any read. A
  // target outside the caller's subtree — or inside an A1-excluded tenant —
  // is an audited denial (E16), never an empty success.
  const scope = options.scope;
  let readScope: MemoryReadScope | null = null;
  if (scope !== undefined) {
    const denyScope = async (detail: string): Promise<never> => {
      await appendAudit("denied", detail);
      throw new AuthzError(detail);
    };
    readScope = scopedReadScope(identity, deps);
    if (readScope === null) {
      await denyScope(
        "scoped export unavailable: no resolved read scope for the organization root",
      );
    } else if (scope.kind === "team") {
      if (!inSubtree(scope.namespace, identity.namespace)) {
        await denyScope(
          `team scope '${scope.namespace}' is outside the caller's subtree`,
        );
      } else if (excludedBy(scope.namespace, readScope.excludePrefixes)) {
        await denyScope(
          `team scope '${scope.namespace}' is outside the caller's subtree (excluded tenant)`,
        );
      }
    }
  }

  let tiers: ExportTier[];
  let limit: number;
  try {
    // A user-scoped export covers the facts a person authored; consolidated
    // L3 knowledge is team-level, so the default narrows to L2 and an
    // explicit L3 request is an error, not a silent drop.
    tiers =
      scope?.kind === "user" && options.tiers === undefined
        ? ["L2"]
        : normalizeTiers(options.tiers);
    if (scope?.kind === "user" && tiers.includes("L3")) {
      throw new Error(
        "mem_export: the knowledge tier is team-level and not available for a user-scoped export",
      );
    }
    limit = clampLimit(options.limit);
  } catch (err) {
    await appendAudit("error", (err as Error).message);
    throw err;
  }

  const excluded: Record<ExportDenialReason, number> = {
    role: 0,
    source: 0,
    classification: 0,
  };
  const excludedByTier: Record<
    ExportTier,
    Record<ExportDenialReason, number>
  > = {
    L2: { role: 0, source: 0, classification: 0 },
    L3: { role: 0, source: 0, classification: 0 },
  };
  const l2Sections: string[] = [];
  const l3Sections: string[] = [];
  const portableL2: Array<MemoryObject & { source: string }> = [];
  const portableL3: Array<
    Concept & { source: typeof CONCEPT_SOURCE; classification: DataClassification }
  > = [];

  const recordExclusion = (
    tier: ExportTier,
    reason: ExportDenialReason,
  ): void => {
    excluded[reason] += 1;
    excludedByTier[tier][reason] += 1;
  };

  try {
    if (tiers.includes("L2")) {
      // E17: the ONLY L2 read surface is the ACL-scoped candidate listing
      // (namespace + ancestors, active, currently valid, pointer-free,
      // source-ACL intersected with the server-resolved subject). A scoped
      // export widens it with the M10 read-scope predicate — the target
      // subtree for a team, the caller's own downward reach for a user —
      // then keeps ONLY target-subtree rows (the base ancestor view is the
      // caller's, not the target's).
      const subject = exportAccessSubject(identity);
      const teamRoot = scope?.kind === "team" ? scope.namespace : null;
      const access: AccessSubject =
        readScope === null
          ? subject
          : {
              ...subject,
              memoryReadScope:
                teamRoot === null
                  ? readScope
                  : {
                      exact: [],
                      prefixes: [teamRoot],
                      excludePrefixes: readScope.excludePrefixes,
                    },
            };
      const listed = await deps.index.listCandidates(identity.namespace, {
        validOnly: true,
        limit,
        access,
      });
      const rows =
        scope === undefined
          ? listed
          : listed.filter((row) => {
              const root = teamRoot ?? identity.namespace;
              if (!inSubtree(row.namespace, root)) return false;
              if (excludedBy(row.namespace, readScope?.excludePrefixes)) return false;
              // User scope: the same probe as the erasure engine's actor
              // target — a provenance entry authored by exactly this actor.
              return scope.kind === "team"
                ? true
                : row.provenance.some((entry) => entry.actor === scope.actor);
            });
      for (const row of rows) {
        const source = exportSource(row);
        const decision = canExport(
          identity.role,
          source,
          row.classification ?? FAIL_CLOSED_CLASSIFICATION,
        );
        if (!decision.allowed) {
          recordExclusion("L2", decision.reason ?? "classification");
          continue; // never rendered (E15)
        }
        l2Sections.push(renderL2Row(row, source));
        portableL2.push({ ...row, source });
      }
    }

    if (tiers.includes("L3")) {
      // E17: concept reads go through the injected ACL-scoped lister only.
      // A team scope lists from the TARGET namespace (already gated to the
      // caller's subtree) and keeps only concepts owned inside it — public
      // and ancestor-inherited concepts belong to the org export, not the
      // team's own memory.
      const teamRoot = scope?.kind === "team" ? scope.namespace : null;
      const listed = await deps.concepts.listConcepts(
        teamRoot ?? identity.namespace,
      );
      const concepts =
        teamRoot === null
          ? listed
          : listed.filter(
              (concept) =>
                concept.namespace !== undefined &&
                inSubtree(concept.namespace, teamRoot) &&
                !excludedBy(concept.namespace, readScope?.excludePrefixes),
            );
      concepts.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
      for (const concept of concepts) {
        const classification = conceptClassification(concept);
        const decision = canExport(
          identity.role,
          CONCEPT_SOURCE,
          classification,
        );
        if (!decision.allowed) {
          recordExclusion("L3", decision.reason ?? "classification");
          continue;
        }
        l3Sections.push(renderConcept(concept));
        portableL3.push({
          ...concept,
          source: CONCEPT_SOURCE,
          classification,
        });
      }
    }
  } catch (err) {
    // D4: the failed export is still an audited egress attempt.
    await appendAudit("error", `export failed: ${(err as Error).message}`);
    throw err;
  }

  const header = [
    "# HaloMem memory export",
    "",
    `- Namespace: \`${identity.namespace === "" ? "(root)" : identity.namespace}\``,
    `- Exported by: \`${identity.actor}\` (${identity.role})`,
    `- Exported at: ${ts}`,
    `- Tiers: ${tiers.join(", ")}`,
    ...(scope === undefined
      ? []
      : [
          scope.kind === "team"
            ? `- Scope: team \`${scope.namespace}\``
            : `- Scope: authored by \`${scope.actor}\``,
        ]),
    ...(purpose === null ? [] : [`- Purpose: ${purpose}`]),
  ].join("\n");

  const parts = [header];
  if (tiers.includes("L2")) {
    parts.push(`## L2 memory (${l2Sections.length} facts)`);
    parts.push(...l2Sections);
  }
  if (tiers.includes("L3")) {
    parts.push(`## L3 knowledge (${l3Sections.length} concepts)`);
    parts.push(...l3Sections);
  }
  const markdown = parts.join("\n\n") + "\n";
  const sha256 = createHash("sha256").update(markdown, "utf8").digest("hex");
  const includedL2 = l2Sections.length;
  const includedL3 = l3Sections.length;
  const portableJson =
    JSON.stringify(
      {
        schema: PORTABLE_EXPORT_SCHEMA,
        export: {
          exportedAt: ts,
          namespace: identity.namespace,
          actor: identity.actor,
          role: identity.role,
          tiers,
          purpose,
          scope: scope ?? null,
          memoryState: "active-current",
          scopeMode:
            scope === undefined
              ? "caller-visible"
              : scope.kind === "team"
                ? "team-owned-subtree"
                : "actor-authored",
        },
        l2: portableL2,
        l3: portableL3,
        counts: { includedL2, includedL3 },
        excluded,
        excludedByTier,
      },
      null,
      2,
    ) + "\n";
  const portableSha256 = createHash("sha256")
    .update(portableJson, "utf8")
    .digest("hex");
  const excludedTotal = excluded.role + excluded.source + excluded.classification;
  const result: AuditEvent["result"] =
    includedL2 + includedL3 > 0 ? "ok" : excludedTotal > 0 ? "denied" : "miss";

  // The audit detail carries counts + the markdown digest — never content
  // (matched/classified content stays out of audit rows, same discipline as
  // the DLP classifier).
  await appendAudit(
    result,
    JSON.stringify({
      includedL2,
      includedL3,
      excluded,
      excludedByTier,
      sha256,
      portableSchema: PORTABLE_EXPORT_SCHEMA,
      portableSha256,
      tiers,
      limit,
      // Identifiers only, never content (the same discipline as the counts).
      ...(scope === undefined
        ? {}
        : {
            scope: {
              kind: scope.kind,
              value: scope.kind === "team" ? scope.namespace : scope.actor,
            },
          }),
    }),
  );

  return {
    markdown,
    filename: exportFilename(identity.namespace, ts, scope),
    sha256,
    includedL2,
    includedL3,
    excluded,
    portableJson,
    portableFilename: exportFilename(identity.namespace, ts, scope, "json"),
    portableSha256,
    excludedByTier,
  };
}
