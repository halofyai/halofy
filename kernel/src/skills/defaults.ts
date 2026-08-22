/**
 * Default skill library seeding.
 *
 * The curated pack (DEFAULT_SKILLS, generated from repo-root
 * halomem-skills/<key>/SKILL.md by scripts/build-default-skills.mjs) ships as
 * PRODUCT DEFAULTS: every newly provisioned tenant root gets the full library
 * registered at its root namespace, so the ancestor-prefix ACL (E21) makes
 * each skill visible and invocable org-wide for free, and a team can still
 * shadow any default by redefining the same skill_key (nearest-ancestor-wins
 * invoke). Rows are marked by created_by = DEFAULT_SKILL_ACTOR — the console
 * "Default" badge and any future filtering derive from that marker; there is
 * deliberately no schema flag.
 *
 * The content is curated and version-controlled, so it ships PRE-VETTED: no
 * vetting pipeline runs at provisioning time (29 LLM scans inside onboarding
 * is not viable, and SKILL_VETTING_V2=required environments must seed
 * keyless). Audit continuity comes from one synthetic passing
 * `skill_vetting_runs` row per skill; `skills sweep` re-vets the pack for
 * real later, and `--stale-engines` picks the synthetic rows up after any
 * engine upgrade (their engine_versions stamp is null = stale).
 *
 * Seeding is idempotent: a skill_key with any current row at the target
 * namespace is SKIPPED, never superseded — a re-seed (or the
 * `skills seed-defaults <namespace>` CLI escape hatch for already-onboarded
 * orgs) can never clobber a team's edit of a default.
 */

import { ulid } from "ulid";

import type { Db } from "../db/client.js";
import type { Identity, Namespace } from "../types.js";
import { DEFAULT_SKILLS } from "./default-content.js";
import { sha256Hex, type SkillStore } from "./store.js";

/** The marker actor on every seeded default row; the S16 badge keys off it. */
export const DEFAULT_SKILL_ACTOR = "system-default-skills";

export interface SeedDefaultSkillsResult {
  seeded: number;
  skipped: number;
}

/** Server-side system identity for one tenant root (modeled on SWEEP_IDENTITY). */
export function systemSkillsIdentity(namespace: Namespace): Identity {
  return {
    keyId: DEFAULT_SKILL_ACTOR,
    namespace,
    actor: DEFAULT_SKILL_ACTOR,
    role: "owner",
  };
}

/**
 * Register every pack entry missing at `namespace` (a tenant root) and mark
 * it approved + vetted. Registration goes through SkillStore.register so
 * every seeded row is audited per D4; the owner-role system identity
 * self-approves, and the vetting stamp plus one synthetic passing run make
 * the row distributable and invocable immediately.
 */
export async function seedDefaultSkills(
  store: SkillStore,
  db: Db,
  namespace: Namespace,
): Promise<SeedDefaultSkillsResult> {
  const identity = systemSkillsIdentity(namespace);
  let seeded = 0;
  let skipped = 0;
  for (const entry of DEFAULT_SKILLS) {
    const existing = await db.query(
      `SELECT 1 FROM skills
        WHERE namespace = $1 AND skill_key = $2 AND t_valid_to IS NULL`,
      [namespace, entry.skillKey],
    );
    if (existing.rows.length > 0) {
      skipped += 1;
      continue;
    }
    const result = await store.register(identity, {
      skillKey: entry.skillKey,
      name: entry.name,
      description: entry.description,
      definition: entry.definition,
    });
    const ts = new Date().toISOString();
    await db.transaction(async (tx) => {
      await tx.query(
        `UPDATE skills
            SET vetting_status = 'vetted', safety_score = 100,
                last_vetted_at = $2, updated_at = $2
          WHERE id = $1 AND t_valid_to IS NULL`,
        [result.skill.id, ts],
      );
      await tx.query(
        `INSERT INTO skill_vetting_runs
           (id, namespace, skill_id, content_sha256, mode, status, safety_score,
            findings, detail, ran_by, started_at, finished_at, engine_versions)
         VALUES ($1, $2, $3, $4, 'static', 'passed', 100, '[]', $5, $6, $7, $7, NULL)`,
        [
          ulid(),
          namespace,
          result.skill.id,
          sha256Hex(entry.definition),
          "curated product default; re-vet with `skills sweep`",
          DEFAULT_SKILL_ACTOR,
          ts,
        ],
      );
    });
    seeded += 1;
  }
  return { seeded, skipped };
}
