/**
 * M9 decision #5 (E42) — the STANDING setup checklist.
 *
 * `src/setup/index.ts` is a one-shot, idempotency-keyed provisioning
 * transaction: it either completed or it did not. That tells an operator
 * nothing about whether the org is *actually* wired up three weeks later — a
 * source can go stale, a badge can be revoked, a retriever can be unmounted.
 *
 * This module derives the outstanding steps LIVE, from real org signals, every
 * time it is asked. The derivation itself stores nothing: there is no
 * "dismissed" flag and no cached count, so a step that regresses re-opens on
 * its own. The count is therefore only ever zero when the org genuinely
 * satisfies every step.
 *
 * The ONE write (CONTRACTS-SETUP-GATE.md): when the derivation reports
 * `complete === true`, the org's `tenants.onboarding_completed_at` latch is
 * stamped (once — the UPDATE only touches NULL rows). The mandatory console
 * gate reads that latch; the live checklist keeps re-opening regressed steps
 * after the latch, but never re-locks a working console. A latch failure is
 * brownout-swallowed: it must never fail the checklist itself.
 *
 * Scoping (D9): the namespace comes from the server-resolved {@link Identity},
 * never from a request body or query string. The checklist is ALWAYS derived
 * for a single organization: a scoped caller gets their tenant root, and a
 * root owner gets each org judged on its own signals (per-tenant latching,
 * never a cross-org aggregate). The SQL fence is an exact
 * `split_part(namespace,'/',1) = $org` equality — no LIKE, escaped or
 * otherwise, so `_`/`%` in a namespace cannot become a wildcard.
 *
 * Brownout (never hard-fail): each step is probed independently and a probe
 * that throws yields `state: "unknown"` with the redacted reason instead of
 * failing the whole card. An unknown step is NOT complete, so it still counts
 * toward `remaining` — the checklist never clears on a degraded read.
 */

import type { Db } from "../db/client.js";
import { isRootOwner } from "../auth/index.js";
import { tenantRootOf } from "../tenancy/index.js";
import type { Identity, Namespace, Tenant } from "../types.js";

// ---------------------------------------------------------------------------
// Shape (report: promote to src/types.ts if a second consumer appears)
// ---------------------------------------------------------------------------

export type SetupStepId =
  | "team-space"
  | "source"
  | "memory"
  | "team"
  | "badge";

export type SetupStepState = "complete" | "outstanding" | "unknown";

export interface SetupChecklistStep {
  id: SetupStepId;
  /** Short imperative label for the checklist row. */
  title: string;
  /** One sentence: what the signal actually is. */
  detail: string;
  state: SetupStepState;
  /** Human evidence for the state — "3 synced sources", "no active badges". */
  evidence: string;
  /** Console screen id an operator should open to finish the step. */
  screen: string;
  /** True when the step is advisory (does not gate `complete`). */
  optional: boolean;
}

export interface SetupChecklist {
  /** The server-resolved namespace the steps were derived for (D9). */
  namespace: Namespace;
  /** The organization (tenant id) the steps were derived for; "" only on a
   *  fresh root install that has no organizations yet. */
  organization: string;
  steps: SetupChecklistStep[];
  /** Count of required steps that are not `complete` — the sidebar badge. */
  remaining: number;
  /** Required steps satisfied / required steps total. */
  completed: number;
  total: number;
  /** True only when every required step is genuinely `complete`. */
  complete: boolean;
  /** True when any probe degraded; the UI says so rather than lying. */
  degraded: boolean;
  derivedAt: string;
}

// ---------------------------------------------------------------------------
// Dependencies (structural — the real Kernel satisfies this, no import cycle)
// ---------------------------------------------------------------------------

interface ChecklistSource {
  syncStatus?: string;
}

export interface ChecklistDeps {
  readonly db: Db;
  readonly sources: {
    list(namespace: Namespace, global?: boolean): Promise<ChecklistSource[]>;
  };
  readonly tenants: {
    resolveTenant(namespace: Namespace): Promise<Tenant | null>;
    list(identity: Identity): Promise<Tenant[]>;
  };
}

/** An exact per-org namespace fence: first `/`-segment equality, never LIKE. */
function orgPredicate(
  org: string,
  startAt: number,
  column = "namespace",
): { sql: string; params: string[] } {
  if (org === "") return { sql: "TRUE", params: [] };
  return { sql: `split_part(${column}, '/', 1) = $${startAt}`, params: [org] };
}

function redact(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return message.length > 160 ? message.slice(0, 157) + "…" : message;
}

/** Run one probe, converting any failure into an `unknown` step (brownout). */
async function probe(
  spec: Omit<SetupChecklistStep, "state" | "evidence">,
  run: () => Promise<{ complete: boolean; evidence: string }>,
): Promise<SetupChecklistStep> {
  try {
    const { complete, evidence } = await run();
    return { ...spec, state: complete ? "complete" : "outstanding", evidence };
  } catch (err) {
    return {
      ...spec,
      state: "unknown",
      evidence: "could not be checked: " + redact(err),
    };
  }
}

async function countRows(
  db: Db,
  sql: string,
  params: readonly unknown[],
): Promise<number> {
  const res = await db.query(sql, [...params]);
  const row = res.rows[0] as { n?: string | number } | undefined;
  return row === undefined ? 0 : Number(row.n ?? 0);
}

// ---------------------------------------------------------------------------
// The derivation
// ---------------------------------------------------------------------------

/**
 * Derive the checklist for ONE organization. Every probe filters on the org's
 * namespace subtree (`split_part(namespace,'/',1) = org`), so a signal in org
 * A can never complete a step for org B. `org === ""` (a fresh root install
 * with no tenants yet) scans org-wide — there is nothing to cross-contaminate.
 *
 * Array order IS the guided journey: team space → data in → people →
 * agent connection. Data can arrive through either a synced backend or an
 * active knowledge-base file. The "up next" spotlight simply takes the first
 * incomplete required step. (The retriever-mount, retrieval-verification,
 * and spend-guard steps were removed: their CTAs pointed at screens where
 * the action does not exist — retriever selection lives on S4/S9 and the
 * budget cap on S2/S4 — so they could never be completed from the guided
 * path. Reintroduce them when those surfaces settle.)
 */
async function deriveForOrg(
  deps: ChecklistDeps,
  identity: Identity,
  org: string,
): Promise<SetupChecklist> {
  const steps = await Promise.all([
    probe(
      {
        id: "team-space",
        title: "Create your team space",
        detail:
          "At least one team exists for sources, knowledge, and agent badges to live under.",
        screen: "s13",
        optional: false,
      },
      async () => {
        // The SAME governed directory S13 lists (org_teams) — the legacy
        // verified-setup `teams` table is gone (migration v69). A team counts
        // for the org when it lives in the org's namespace subtree OR carries
        // the org's `organization_namespace` label: rows adopted from the
        // pre-attachment era are labeled before (or without) being re-rooted,
        // and the label alone must satisfy the step.
        const p = orgPredicate(org, 1);
        const labelClause = org === "" ? "" : ` OR organization_namespace = $${p.params.length + 1}`;
        const n = await countRows(
          deps.db,
          `SELECT COUNT(*) AS n FROM org_teams WHERE ${p.sql}${labelClause}`,
          org === "" ? p.params : [...p.params, org],
        );
        return n > 0
          ? { complete: true, evidence: `${n} team${n === 1 ? "" : "s"}` }
          : { complete: false, evidence: "no teams exist yet" };
      },
    ),

    probe(
      {
        id: "source",
        title: "Connect a backend or upload knowledge",
        detail:
          "Sync at least one backend, or upload one file to an active knowledge base.",
        screen: "s6",
        optional: false,
      },
      async () => {
        // These are independent OR lanes. A positive signal wins even when the
        // other read browns out; only a result with no positive signal and a
        // failed read is unknown. Connector scope uses the store's own escaped
        // subtree list. Uploaded files use the same exact first-segment org
        // fence as every SQL-backed checklist probe.
        const backends = (async () => {
          const rows = org === ""
            ? await deps.sources.list("", true)
            : await deps.sources.list(org);
          return {
            total: rows.length,
            synced: rows.filter((s) => s.syncStatus === "synced").length,
          };
        })();
        const files = (async () => {
          const p = orgPredicate(org, 1, "file.namespace");
          return countRows(
            deps.db,
            `SELECT COUNT(*) AS n
               FROM company_files file
               JOIN knowledge_bases kb
                 ON kb.id = file.knowledge_base_id
                AND kb.namespace = file.namespace
              WHERE ${p.sql}
                AND kb.lifecycle_state = 'active' AND kb.t_valid_to IS NULL
                AND file.lifecycle_state = 'active' AND file.t_valid_to IS NULL
                AND file.status IN ('ready', 'needs_review')`,
            p.params,
          );
        })();
        const [backendResult, fileResult] = await Promise.allSettled([backends, files]);
        const backend = backendResult.status === "fulfilled" ? backendResult.value : null;
        const fileCount = fileResult.status === "fulfilled" ? fileResult.value : null;
        const synced = backend?.synced ?? 0;
        const uploaded = fileCount ?? 0;
        if (synced > 0 || uploaded > 0) {
          const evidence = [
            synced > 0 ? `${synced} synced backend${synced === 1 ? "" : "s"}` : "",
            uploaded > 0 ? `${uploaded} uploaded knowledge file${uploaded === 1 ? "" : "s"}` : "",
          ].filter(Boolean).join("; ");
          return { complete: true, evidence };
        }
        if (backend === null || fileCount === null) {
          const failures = [
            backendResult.status === "rejected" ? backendResult.reason : null,
            fileResult.status === "rejected" ? fileResult.reason : null,
          ].filter((reason) => reason !== null).map(redact);
          throw new Error(failures.join("; ") || "data-source checks failed");
        }
        return {
          complete: false,
          evidence: backend.total === 0
            ? "no synced backends or uploaded knowledge files"
            : `${backend.total} backend${backend.total === 1 ? "" : "s"} connected, none synced; no knowledge files uploaded`,
        };
      },
    ),

    probe(
      {
        id: "memory",
        title: "Capture the first memory",
        detail: "At least one active, currently-valid memory object exists in scope.",
        screen: "s5",
        optional: false,
      },
      async () => {
        const p = orgPredicate(org, 1);
        const n = await countRows(
          deps.db,
          `SELECT COUNT(*) AS n FROM memory_objects
            WHERE ${p.sql} AND status = 'active' AND t_valid_to IS NULL`,
          p.params,
        );
        return n > 0
          ? { complete: true, evidence: `${n} active memories` }
          : { complete: false, evidence: "no memories written yet" };
      },
    ),

    probe(
      {
        id: "team",
        title: "Invite a teammate",
        detail:
          "Optional for solo workspaces. Sending one invitation is enough; acceptance is not required.",
        screen: "s13",
        optional: true,
      },
      async () => {
        const p = orgPredicate(org, 1);
        const invitationP = orgPredicate(org, 1, "auth_invitations.namespace");
        const [people, invitations] = await Promise.all([
          countRows(
            deps.db,
            `SELECT COUNT(*) AS n FROM users WHERE ${p.sql}`,
            p.params,
          ),
          countRows(
            deps.db,
            `SELECT COUNT(*) AS n FROM auth_invitations
              WHERE ${invitationP.sql}
                AND accepted_at IS NULL
                AND revoked_at IS NULL
                AND expires_at > CURRENT_TIMESTAMP`,
            invitationP.params,
          ),
        ]);
        if (people > 1) {
          return { complete: true, evidence: `${people} people` };
        }
        if (invitations > 0) {
          return {
            complete: true,
            evidence: `${invitations} active invitation${invitations === 1 ? "" : "s"} sent`,
          };
        }
        return { complete: false, evidence: "solo workspace; no invitations sent" };
      },
    ),

    probe(
      {
        id: "badge",
        title: "Connect an agent",
        detail: "At least one active API key exists for an agent to call the kernel with.",
        screen: "s3",
        optional: false,
      },
      async () => {
        // Only AGENT-role keys count: the operator's own console/owner key is
        // not an agent connection, and counting it would mark this step done
        // on a fresh install where no agent has ever been wired up.
        const p = orgPredicate(org, 1);
        const n = await countRows(
          deps.db,
          `SELECT COUNT(*) AS n FROM api_keys
            WHERE ${p.sql} AND status = 'active' AND role = 'agent'`,
          p.params,
        );
        return n > 0
          ? { complete: true, evidence: `${n} active agent badges` }
          : { complete: false, evidence: "no active agent badges" };
      },
    ),

  ]);

  const required = steps.filter((s) => !s.optional);
  const completed = required.filter((s) => s.state === "complete").length;
  return {
    namespace: identity.namespace,
    organization: org,
    steps,
    remaining: required.length - completed,
    completed,
    total: required.length,
    complete: completed === required.length,
    degraded: steps.some((s) => s.state === "unknown"),
    derivedAt: new Date().toISOString(),
  };
}

/**
 * Derive the outstanding setup steps. Scoped callers get their own org. A
 * root owner gets every organization judged on its OWN signals — no cross-org
 * mixing — with the first still-incomplete org's checklist returned for
 * display. The only write is the per-tenant onboarding latch, stamped when
 * that tenant's required steps all report complete. Takes no namespace from
 * the caller (D9).
 */
export async function setupChecklist(
  deps: ChecklistDeps,
  identity: Identity,
): Promise<SetupChecklist> {
  if (!isRootOwner(identity)) {
    const org = tenantRootOf(identity.namespace);
    const view = await deriveForOrg(deps, identity, org);
    if (view.complete) {
      // Pre-check keeps the latch first-wins (SG4) without a spurious
      // UPDATE on every complete derivation.
      const tenant = await deps.tenants
        .resolveTenant(identity.namespace)
        .catch(() => null);
      if (tenant && tenant.onboardingCompletedAt === null) {
        await latchTenant(deps, tenant.id);
      }
    }
    return view;
  }
  const tenants = await deps.tenants.list(identity);
  if (tenants.length === 0) return deriveForOrg(deps, identity, "");
  const views: SetupChecklist[] = [];
  for (const tenant of tenants) {
    const view = await deriveForOrg(deps, identity, tenant.id);
    if (view.complete && tenant.onboardingCompletedAt === null) {
      await latchTenant(deps, tenant.id);
    }
    views.push(view);
  }
  return views.find((v) => !v.complete) ?? views[views.length - 1]!;
}

/**
 * Stamp ONE org's `tenants.onboarding_completed_at` latch. One-way: the
 * UPDATE only touches NULL rows, so a regressed step later never un-stamps it
 * and concurrent first completions race harmlessly. Brownout: a failed latch
 * is swallowed — the checklist result must never fail because the gate record
 * could not write.
 */
async function latchTenant(deps: ChecklistDeps, tenantId: string): Promise<void> {
  try {
    await deps.db.query(
      `UPDATE tenants SET onboarding_completed_at = $1
        WHERE id = $2 AND onboarding_completed_at IS NULL`,
      [new Date().toISOString(), tenantId],
    );
  } catch {
    // Brownout: the gate record lags one call; the checklist stays truthful.
  }
}

// ---------------------------------------------------------------------------
// The gate read (CONTRACTS-SETUP-GATE.md)
// ---------------------------------------------------------------------------

export interface OnboardingState {
  /** True while the caller's org has never completed the setup checklist. */
  setupRequired: boolean;
  /** ISO timestamp of first completion, or null while still gated. */
  completedAt: string | null;
}

/**
 * The mandatory-setup gate decision, read straight from the persisted latch —
 * cheap enough for `/auth/me`. A root owner with NO tenants yet (a fresh
 * install) is gated; a scoped caller whose namespace resolves to no tenant is
 * not (nothing to set up against — their admin's org gates them instead).
 *
 * SG8 — only the platform root's OWN install gates it. With exactly one tenant
 * the root is that organization's operator, so its latch is the root's gate.
 * With several tenants the root is a platform operator and no single org is
 * "its" org: a customer signing up through the inline `/console/login` flow creates an
 * unlatched tenant, and gating on that would lock the operator out of a
 * working console every time a new customer arrives (observed in production
 * on 2026-08-01). Each tenant still gates its OWN scoped users below, and the
 * standing checklist still judges and latches every org on its own signals.
 */
export async function onboardingState(
  deps: ChecklistDeps,
  identity: Identity,
): Promise<OnboardingState> {
  if (isRootOwner(identity)) {
    const tenants = await deps.tenants.list(identity);
    if (tenants.length === 0) return { setupRequired: true, completedAt: null };
    const stamps = tenants
      .map((t) => t.onboardingCompletedAt)
      .filter((s): s is string => s !== null)
      .sort();
    const completedAt = stamps.length > 0 ? stamps[0]! : null;
    const sole = tenants.length === 1 ? tenants[0]! : null;
    return {
      setupRequired: sole !== null && sole.onboardingCompletedAt === null,
      completedAt,
    };
  }
  const tenant = await deps.tenants.resolveTenant(identity.namespace);
  if (tenant === null) return { setupRequired: false, completedAt: null };
  return {
    setupRequired: tenant.onboardingCompletedAt === null,
    completedAt: tenant.onboardingCompletedAt,
  };
}
