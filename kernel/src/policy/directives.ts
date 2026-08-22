/**
 * Policy directives — the guardrail lane.
 *
 * A governed policy document already lands in memory through the canonical
 * write path (D10): `Kernel.uploadPolicyDocument` registers a `policy-upload`
 * source and runs the file through extraction, verification, and provenance,
 * so its clauses are ordinary bi-temporal L2 facts. This module reads those
 * facts back as an ORDERED, DIGESTED directive set so the context allocator
 * can ship them ahead of ordinary recall.
 *
 * Why the working set and not a system prompt: D2 says the kernel returns
 * ranked blocks and never assembles a prompt. Guardrails therefore ride the
 * same lane as every other block — but from a RESERVED slice of the token
 * budget, so a busy namespace can never evict its own policy. A client that
 * does own its system prompt (the Claude Code plugin's SessionStart hook, the
 * Codex installer) calls `mem_policy` and places the same blocks itself; both
 * paths are recorded against the same digest.
 *
 * Ordering is stable for prompt-cache friendliness: shallowest namespace
 * first (org policy before team policy), then document load order, then the
 * fact's own assertion order.
 */

import { createHash } from "node:crypto";

import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import { estimateTokens } from "../types.js";
import type {
  ContextBlock,
  Namespace,
  PolicyDirectiveDocument,
  PolicyDirectiveSet,
  PolicyDocumentEnforcement,
  PolicyDocumentKind,
} from "../types.js";

/**
 * Share of the working-set budget reserved for guardrails. Policy blocks are
 * packed first and capped here, so directives can neither be evicted by recall
 * nor starve it.
 */
export const POLICY_BUDGET_RATIO = 0.35;

/** Hard ceiling on directive facts read per assembly (bounded query). */
const MAX_DIRECTIVE_ROWS = 400;

/** The empty guardrail set — a namespace with no agent-ready policy. */
export const EMPTY_DIRECTIVE_SET: Omit<PolicyDirectiveSet, "namespace"> = {
  digest: "",
  documents: [],
  blocks: [],
  totalTokens: 0,
  required: false,
  truncated: 0,
};

interface DocumentRow {
  id: string;
  source_id: string;
  namespace: string;
  title: string;
  kind: PolicyDocumentKind;
  enforcement: PolicyDocumentEnforcement;
  origin: string | null;
  file_name: string;
  loaded_at: string | Date | null;
  content_sha256: string;
}

interface DirectiveRow {
  id: string;
  content: string;
  source_id: string;
  document_key: string | null;
  assertion_time: string | Date;
}

export interface PolicyDirectiveOptions {
  /** Token ceiling for the directive lane. Omit for "no ceiling". */
  tokenBudget?: number;
}

/**
 * Read the guardrail set governing `namespace`: every agent-ready policy
 * document at the namespace or one of its `/`-split prefix ancestors, plus the
 * directive facts those documents produced.
 *
 * Ancestors only — never descendants, never siblings — so this obeys the same
 * visibility rule as the query layer (a team inherits org policy; the org does
 * not inherit a team's).
 */
export async function loadPolicyDirectives(
  db: Db,
  namespace: Namespace,
  options: PolicyDirectiveOptions = {},
): Promise<PolicyDirectiveSet> {
  const scopes = policyScopes(namespace);
  const placeholders = scopes.map((_, index) => `$${index + 1}`).join(", ");
  const documents = await db.query(
    `SELECT id, source_id, namespace, title, kind, enforcement, origin,
            file_name, loaded_at, content_sha256
       FROM policy_documents
      WHERE namespace IN (${placeholders})
        AND status = 'active'
      ORDER BY length(namespace) - length(replace(namespace, '/', '')) ASC,
               namespace ASC, created_at ASC, id ASC`,
    scopes,
  );
  const documentRows = documents.rows as DocumentRow[];
  if (documentRows.length === 0) {
    return { namespace, ...EMPTY_DIRECTIVE_SET };
  }

  const sourceIds = [...new Set(documentRows.map((row) => row.source_id))];
  const sourcePlaceholders = sourceIds
    .map((_, index) => `$${scopes.length + index + 1}`)
    .join(", ");
  // A policy fact lands in its document's namespace, so the scope filter (an
  // indexed column) bounds the scan before provenance is unnested. Provenance
  // is an array — a superseding write appends — so match ANY entry rather than
  // element 0: a corrected clause keeps its document.
  const directives = await db.query(
    `SELECT m.id, m.content, p.source_id, p.document_key, m.assertion_time
       FROM memory_objects m
       JOIN LATERAL (
         SELECT DISTINCT entry->>'sourceId' AS source_id,
                         entry->>'documentKey' AS document_key
           FROM jsonb_array_elements(m.provenance) entry
       ) p ON p.source_id IN (${sourcePlaceholders})
      WHERE m.namespace IN (${placeholders})
        AND m.status = 'active'
        AND m.type <> 'pointer'
        AND (m.t_valid_to IS NULL OR m.t_valid_to > CURRENT_TIMESTAMP)
      ORDER BY m.assertion_time ASC, m.id ASC
      LIMIT ${MAX_DIRECTIVE_ROWS}`,
    [...scopes, ...sourceIds],
  );
  const bySource = new Map<string, DirectiveRow[]>();
  for (const row of directives.rows as DirectiveRow[]) {
    const bucket = bySource.get(row.source_id);
    if (bucket) bucket.push(row);
    else bySource.set(row.source_id, [row]);
  }

  /**
   * An UPLOADED document owns its source outright, so every fact under that
   * source is its own. An ADOPTED document shares a source with whatever else
   * that connector imported, so it claims only the facts of its own file —
   * otherwise adopting one policy CSV would ship an entire import as
   * guardrails.
   */
  const claims = (document: DocumentRow, row: DirectiveRow): boolean => {
    if (document.origin !== "adopted") return true;
    const key = row.document_key;
    if (key === null) return false;
    return key === document.file_name || key.startsWith(`${document.file_name}#`);
  };

  const ceiling = options.tokenBudget;
  const blocks: ContextBlock[] = [];
  const summaries: PolicyDirectiveDocument[] = [];
  const fingerprint = createHash("sha256");
  let totalTokens = 0;
  let truncated = 0;
  let required = false;

  for (let index = 0; index < documentRows.length; index++) {
    const document = documentRows[index]!;
    // One memory can appear once per provenance entry, so collapse by fact id.
    const seen = new Set<string>();
    const rows = (bySource.get(document.source_id) ?? []).filter((row) => {
      if (!claims(document, row) || seen.has(row.id)) return false;
      seen.add(row.id);
      return true;
    });
    if (rows.length === 0) continue;
    const enforcement: PolicyDocumentEnforcement =
      document.enforcement === "advisory" ? "advisory" : "required";
    if (enforcement === "required") required = true;
    fingerprint.update(
      `${document.id}\u0000${enforcement}\u0000${document.content_sha256}\u0000`,
    );

    let documentTokens = 0;
    let documentDirectives = 0;
    for (let position = 0; position < rows.length; position++) {
      const row = rows[position]!;
      fingerprint.update(`${row.id}\u0000`);
      const tokenEstimate = estimateTokens(row.content);
      if (ceiling !== undefined && totalTokens + tokenEstimate > ceiling) {
        truncated++;
        continue;
      }
      blocks.push({
        kind: "policy-directive",
        ref: row.id,
        content: row.content,
        tokenEstimate,
        // '0-policy-' sorts ahead of the allocator's '0-pin-' lane, so a
        // guardrail is always the first block the caller sees.
        orderKey:
          `0-policy-${String(index).padStart(4, "0")}-` +
          `${String(position).padStart(4, "0")}-${row.id}`,
      });
      totalTokens += tokenEstimate;
      documentTokens += tokenEstimate;
      documentDirectives++;
    }

    summaries.push({
      documentId: document.id,
      namespace: document.namespace,
      title: document.title,
      kind: document.kind,
      enforcement,
      directiveCount: documentDirectives,
      tokenEstimate: documentTokens,
      loadedAt:
        document.loaded_at === null
          ? null
          : new Date(document.loaded_at).toISOString(),
    });
  }

  if (summaries.length === 0) {
    return { namespace, ...EMPTY_DIRECTIVE_SET };
  }

  return {
    namespace,
    digest: fingerprint.digest("hex"),
    documents: summaries,
    blocks,
    totalTokens,
    required,
    truncated,
  };
}

/** The reserved directive slice of a working-set budget. */
export function policyTokenReserve(budget: number): number {
  if (!Number.isFinite(budget) || budget <= 0) return 0;
  return Math.max(1, Math.floor(budget * POLICY_BUDGET_RATIO));
}

/**
 * The `/`-split ancestor chain a policy document may govern from. Mirrors the
 * query layer's ACL rule so policy inheritance and memory visibility agree.
 */
function policyScopes(namespace: Namespace): string[] {
  return [...new Set(namespaceAncestors(namespace))];
}
