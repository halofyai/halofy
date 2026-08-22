/**
 * `skills sweep` (CONTRACTS-S16-VETTING-V2.md, E72).
 *
 * Re-vets every current non-superseded skill under a SERVER-SIDE system
 * identity (D9: nothing in the sweep path accepts a namespace/actor from
 * input). `--stale-engines` limits the sweep to skills whose latest
 * finalized run was stamped with engine versions older than the image's —
 * the re-vet pass after a scanner/rules upgrade (image rebuild).
 *
 * Partial failures are reported, never fatal: the caller prints the
 * per-skill outcomes and exits 0. Verdict flips need no further wiring —
 * E22 blocks invoke, E63 blocks download, S16 bands recompute on render.
 */

import type { Db } from "../db/client.js";
import type { Identity } from "../types.js";
import { SKILL_SWEEP_ACTOR, type SkillVetting, type VettingMode } from "./vetting.js";

/** The sweep's server-side system identity — root owner manages every subtree. */
export const SWEEP_IDENTITY: Identity = {
  keyId: "system-skills-sweep",
  namespace: "",
  actor: SKILL_SWEEP_ACTOR,
  role: "owner",
};

export interface SweepItemResult {
  skillId: string;
  namespace: string;
  skillKey: string;
  /** vetting_status before the sweep (current row). */
  before: string;
  /** vetting_status after the sweep, or unchanged when the vet errored out. */
  after: string;
  flipped: boolean;
  error: string | null;
}

export interface SweepOptions {
  /** Only re-vet skills whose latest finalized run predates the image's engine versions. */
  staleEnginesOnly: boolean;
}

interface CurrentSkillRow {
  id: string;
  namespace: string;
  skill_key: string;
  vetting_status: string;
}

/**
 * Ids of current skills with at least one lane whose LATEST finalized
 * (passed/failed) run for that mode carries an `engine_versions` stamp that
 * differs from the image's current stamp — legacy (null) stamps are stale
 * by definition. The comparison is PER LANE (`DISTINCT ON (skill_id, mode)`):
 * a scanner-only upgrade leaves the llm stamp current, and lane rows from
 * one vet share `started_at`, so judging on a single tie-picked row would
 * silently skip exactly the skills the flag exists for. Skills with no
 * finalized run have nothing to compare and are not selected (a plain
 * `skills sweep` covers them).
 */
async function staleEngineSkillIds(
  db: Db,
  current: Partial<Record<VettingMode, string>>,
): Promise<Set<string>> {
  const res = await db.query(
    `SELECT DISTINCT ON (skill_id, mode) skill_id, mode, engine_versions
       FROM skill_vetting_runs
      WHERE status IN ('passed','failed')
      ORDER BY skill_id, mode, started_at DESC`,
  );
  const stale = new Set<string>();
  for (const raw of res.rows) {
    const row = raw as { skill_id: string; mode: string; engine_versions: string | null };
    const currentStamp = current[row.mode as VettingMode];
    if (row.engine_versions === null || row.engine_versions !== currentStamp) {
      stale.add(row.skill_id);
    }
  }
  return stale;
}

export async function sweepSkills(
  deps: { db: Db; vetting: SkillVetting },
  opts: SweepOptions,
): Promise<SweepItemResult[]> {
  const res = await deps.db.query(
    `SELECT id, namespace, skill_key, vetting_status
       FROM skills WHERE t_valid_to IS NULL
      ORDER BY namespace, skill_key`,
  );
  let rows = res.rows.map((r) => r as CurrentSkillRow);

  if (opts.staleEnginesOnly) {
    const stale = await staleEngineSkillIds(deps.db, deps.vetting.currentEngineVersions());
    rows = rows.filter((row) => stale.has(row.id));
  }

  const results: SweepItemResult[] = [];
  for (const row of rows) {
    try {
      const vet = await deps.vetting.vet(SWEEP_IDENTITY, row.id);
      const after = vet.skill.vettingStatus;
      results.push({
        skillId: row.id,
        namespace: row.namespace,
        skillKey: row.skill_key,
        before: row.vetting_status,
        after,
        flipped: after !== row.vetting_status,
        error: vet.verdict === "error" ? "lane error - see run rows" : null,
      });
    } catch (err) {
      // Partial failure: reported, never fatal (E72).
      results.push({
        skillId: row.id,
        namespace: row.namespace,
        skillKey: row.skill_key,
        before: row.vetting_status,
        after: row.vetting_status,
        flipped: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return results;
}
