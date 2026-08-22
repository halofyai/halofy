/**
 * Organization adoption — the repair tool for pre-attachment deployments.
 *
 * Early consoles let the PLATFORM root (namespace "") create teams, users,
 * keys, and sources at TOP-LEVEL namespaces (`marketing`, not
 * `halofy/marketing`). Those rows belong to no organization: they carry no
 * `organization_namespace` label, sit outside every tenant's subtree, and are
 * invisible to any per-organization read (the setup checklist being the first
 * casualty). The creation paths now attach to the sole tenant up front; this
 * module moves the rows that were minted before that fix.
 *
 * `org adopt <tenant> <ns...>` re-roots each given top-level namespace under
 * the tenant: every base table with a namespace-shaped column gets its rows
 * inside the moved subtree rewritten `ns` → `<tenant>/ns` (path columns) or
 * relabeled to `<tenant>` (root-label columns). One transaction — either the
 * whole subtree moves or none of it does.
 *
 * What is deliberately NOT touched:
 *  - `audit_log` / `audit_chain_state` — the hash-chained record of what
 *    happened, under the namespaces it happened in (D4; rewriting would break
 *    the chain).
 *  - `deletion_certificates` / `tombstones` — signed erasure evidence; the
 *    signatures cover the recorded values.
 *  - Namespaces embedded inside JSON config/payload columns — best-effort
 *    limitation; new writes use the new namespace.
 *
 * D7 note: this rewrites a SCOPING label in place rather than superseding
 * rows. Adoption is an identity repair — the facts, their validity windows,
 * and their supersedence links are untouched; only where they are filed
 * changes. The operation itself is recorded in the audit log by the caller
 * (kernel method / CLI), so the relabeling is attributable.
 */

import type { Db } from "../db/client.js";
import { escapeLikePattern } from "../db/client.js";

/** Tables whose rows are historical/signed evidence — never rewritten. */
const EVIDENCE_TABLES = new Set([
  "audit_log",
  "audit_chain_state",
  "deletion_certificates",
  "tombstones",
]);

/**
 * Columns that hold an organization ROOT (a tenant id), not a namespace path.
 * Re-rooting `marketing` under `halofy` must set these to `halofy` — a
 * prefixed `halofy/marketing` is not a tenant id and would break every
 * equality join against `tenants.id`.
 */
const ROOT_LABEL_COLUMNS = new Set(["organization_namespace", "tenant_namespace"]);

export interface AdoptTableChange {
  table: string;
  column: string;
  rows: number;
}

export interface AdoptReport {
  tenant: string;
  namespaces: string[];
  dryRun: boolean;
  /** True when platform-root sources (namespace "") were also adopted. */
  rootSources: boolean;
  changes: AdoptTableChange[];
  /** Total rows rewritten (or that would be, under dryRun). */
  total: number;
}

export class AdoptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdoptError";
  }
}

interface NamespaceColumn {
  table: string;
  column: string;
}

/** Every BASE TABLE column that holds a namespace (path or root label). */
async function namespaceColumns(db: Db): Promise<NamespaceColumn[]> {
  const res = await db.query(
    `SELECT c.table_name AS table, c.column_name AS column
       FROM information_schema.columns c
       JOIN information_schema.tables t
         ON t.table_schema = c.table_schema AND t.table_name = c.table_name
      WHERE c.table_schema = 'public'
        AND t.table_type = 'BASE TABLE'
        AND (c.column_name = 'namespace' OR c.column_name LIKE '%\\_namespace' ESCAPE '\\')
        AND c.data_type IN ('text', 'character varying')
      ORDER BY c.table_name, c.column_name`,
  );
  return (res.rows as NamespaceColumn[]).filter(
    (r) => !EVIDENCE_TABLES.has(r.table),
  );
}

function assertValidInput(
  tenant: string,
  namespaces: string[],
  rootSources: boolean,
): void {
  if (tenant.length === 0 || tenant.includes("/")) {
    throw new AdoptError(`'${tenant}' is not a tenant root namespace`);
  }
  if (namespaces.length === 0 && !rootSources) {
    throw new AdoptError("no namespaces given to adopt");
  }
  for (const ns of namespaces) {
    if (ns.length === 0) {
      throw new AdoptError(
        "the root namespace '' cannot be adopted wholesale - it is the platform root, not an orphan",
      );
    }
    if (ns.includes("/")) {
      throw new AdoptError(
        `'${ns}' is not a top-level namespace - only orphan roots can be adopted`,
      );
    }
    if (ns === tenant) {
      throw new AdoptError(`'${ns}' is the target tenant itself`);
    }
  }
}

/**
 * Move the given top-level namespaces under `tenant`. All-or-nothing: runs in
 * one transaction unless `dryRun`, in which case only counts are read and
 * nothing is written. Fails when `tenant` does not exist or any namespace is
 * itself a tenant root (adopting one org into another is a different, scarier
 * operation this tool refuses).
 */
export async function adoptNamespaces(
  db: Db,
  input: {
    tenant: string;
    namespaces: string[];
    dryRun?: boolean;
    /**
     * Also move source-connector registrations the platform root created at
     * namespace "" (their sync documents follow, so the next sync sees them
     * as unchanged instead of re-importing everything). The root namespace
     * itself is never adopted wholesale — it is the platform, not an orphan.
     */
    rootSources?: boolean;
  },
): Promise<AdoptReport> {
  const tenant = input.tenant.trim();
  const namespaces = [...new Set(input.namespaces.map((n) => n.trim()))];
  const dryRun = input.dryRun === true;
  const rootSources = input.rootSources === true;
  assertValidInput(tenant, namespaces, rootSources);

  const tenantRow = await db.query(`SELECT id FROM tenants WHERE id = $1`, [tenant]);
  if (tenantRow.rows.length === 0) {
    throw new AdoptError(`no tenant with id '${tenant}'`);
  }
  for (const ns of namespaces) {
    const clash = await db.query(`SELECT id FROM tenants WHERE id = $1`, [ns]);
    if (clash.rows.length > 0) {
      throw new AdoptError(
        `'${ns}' is an organization root - merging organizations is not supported`,
      );
    }
  }

  const columns = await namespaceColumns(db);
  const changes: AdoptTableChange[] = [];

  const run = async (tx: Db): Promise<void> => {
    for (const { table, column } of columns) {
      let rows = 0;
      for (const ns of namespaces) {
        const like = escapeLikePattern(ns) + "/%";
        if (ROOT_LABEL_COLUMNS.has(column)) {
          // Root label: the orphan root becomes the tenant id, exactly.
          rows += dryRun
            ? await count(tx, `SELECT COUNT(*) AS n FROM ${table} WHERE ${column} = $1`, [ns])
            : (await tx.query(
                `UPDATE ${table} SET ${column} = $1 WHERE ${column} = $2 RETURNING 1`,
                [tenant, ns],
              )).rows.length;
        } else if (dryRun) {
          rows += await count(
            tx,
            `SELECT COUNT(*) AS n FROM ${table}
              WHERE ${column} = $1 OR ${column} LIKE $2 ESCAPE '\\'`,
            [ns, like],
          );
        } else {
          rows += (await tx.query(
            `UPDATE ${table} SET ${column} = $1 || '/' || ${column}
              WHERE ${column} = $2 OR ${column} LIKE $3 ESCAPE '\\' RETURNING 1`,
            [tenant, ns, like],
          )).rows.length;
        }
      }
      if (rows > 0) changes.push({ table, column, rows });
    }

    if (rootSources) {
      if (dryRun) {
        const n = await count(
          tx,
          `SELECT COUNT(*) AS n FROM sources WHERE namespace = ''`,
          [],
        );
        if (n > 0) changes.push({ table: "sources", column: "namespace (root)", rows: n });
      } else {
        const moved = await tx.query(
          `UPDATE sources SET namespace = $1 WHERE namespace = '' RETURNING id`,
          [tenant],
        );
        const ids = (moved.rows as { id: string }[]).map((r) => r.id);
        if (ids.length > 0) {
          changes.push({ table: "sources", column: "namespace (root)", rows: ids.length });
          const placeholders = ids.map((_, i) => `$${i + 2}`).join(", ");
          const docs = await tx.query(
            `UPDATE source_documents SET landing_namespace = $1
              WHERE landing_namespace = '' AND source_id IN (${placeholders})
              RETURNING 1`,
            [tenant, ...ids],
          );
          if (docs.rows.length > 0) {
            changes.push({
              table: "source_documents",
              column: "landing_namespace (root)",
              rows: docs.rows.length,
            });
          }
        }
      }
    }

    // Freshly moved teams get the organization label the creation path now
    // stamps up front — rows created before the label existed hold ''.
    if (!dryRun) {
      const labeled = await tx.query(
        `UPDATE org_teams SET organization_namespace = $1
          WHERE (namespace = $1 OR namespace LIKE $2 ESCAPE '\\')
            AND organization_namespace IS DISTINCT FROM $1
          RETURNING 1`,
        [tenant, escapeLikePattern(tenant) + "/%"],
      );
      if (labeled.rows.length > 0) {
        changes.push({
          table: "org_teams",
          column: "organization_namespace (relabel)",
          rows: labeled.rows.length,
        });
      }
    }
  };

  if (dryRun) await run(db);
  else await db.transaction(run);

  return {
    tenant,
    namespaces,
    dryRun,
    rootSources,
    changes,
    total: changes.reduce((n, c) => n + c.rows, 0),
  };
}

async function count(db: Db, sql: string, params: unknown[]): Promise<number> {
  const res = await db.query(sql, params);
  return Number((res.rows[0] as { n?: string | number } | undefined)?.n ?? 0);
}
