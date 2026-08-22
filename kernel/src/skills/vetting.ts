/**
 * Skill security vetting (M9 decision #9, E20/E22; v2 per
 * CONTRACTS-S16-VETTING-V2.md, D32–D35).
 *
 * v2 pipeline over one exact `content_sha256` — up to three lanes:
 *
 *  1. `llm` — an Azure OpenAI scan of the definition as UNTRUSTED quoted
 *     data (D32), after the masked-rule redaction pre-flight strips any
 *     embedded secrets from the outbound text (D33). Fail-closed: any
 *     error shape (timeout, HTTP error, refusal, schema violation) is a
 *     lane error, never a pass.
 *  2. `cisco` / `skillspector` — the pinned external scanner CLIs run as
 *     subprocesses over a temp copy of the definition (D34), normalized
 *     into VettingFinding.
 *
 * Lane availability follows the D35 brownout ladder: all v2 lanes → v2
 * score = min(lanes); a missing lane is skipped-and-recorded under `auto`
 * (or a lane error under `required`); with no v2 lane available the
 * pipeline falls back to v1 exactly as it ran before:
 *
 *  1. `static` — a deterministic scan of the definition text for dangerous
 *     patterns: exec/eval directives, piped shell downloads, secret-like
 *     strings (masked in the PUBLIC findings — the score is public, the
 *     secret never is), raw-IP / unbounded network directives, destructive
 *     filesystem commands.
 *  2. `sandbox` — a dry-run through the kernel's existing DETERMINISTIC
 *     stub lane (`StubLlm` + the real extraction prompt): zero network,
 *     zero exec by construction. It checks the definition behaves as
 *     bounded, well-formed content when the write path would ingest it —
 *     bounded fan-out, bounded fact size, no control-character payloads.
 *
 * All runs persist to `skill_vetting_runs` (inserted `running` first so a
 * crash leaves visible evidence, then finalized exactly once) and roll up to
 * a public 0..100 safety score on the skill row. The verdict maps to
 * `vetting_status`: passed → `vetted`, failed → `blocked`, error →
 * `unvetted` (still blocked from use by the E22 gate — fail safe). Every
 * run writes a `skill_vet` audit row, including denied/miss/error (D4).
 */

import { ulid } from "ulid";
import type { AuditEvent, AuditOp, Identity, MemoryId, Namespace } from "../types.js";
import type { Db } from "../db/client.js";
import { EXTRACT_SYSTEM, StubLlm, parseLooseJson } from "../llm/index.js";
import {
  SkillAuthorizationError,
  SkillConflictError,
  SkillNotFoundError,
  canManageSkill,
  canReadSkill,
  deriveSkillHandling,
  rowToSkill,
  sha256Hex,
  type SkillRecord,
} from "./store.js";

// ---------------------------------------------------------------------------
// Types (local; candidates for promotion)
// ---------------------------------------------------------------------------

export type VettingMode = "static" | "sandbox" | "llm" | "cisco" | "skillspector";
export type VettingRunStatus = "running" | "passed" | "failed" | "error";
export type VettingSeverity = "low" | "medium" | "high" | "critical";

/** D35: how the v2 pipeline behaves when a lane is absent. */
export type VettingV2Mode = "auto" | "required" | "off";

export interface VettingFinding {
  rule: string;
  severity: VettingSeverity;
  message: string;
  /** Redacted/truncated excerpt — safe for the PUBLIC score surface. */
  excerpt: string;
}

/**
 * Cap a finding's prose at `max`, cutting on a word boundary and marking the
 * cut. A bare `slice` leaves the console rendering a sentence that stops
 * mid-word with no sign it was shortened, which reads as a rendering bug.
 */
export function clampFindingText(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const boundary = cut.lastIndexOf(" ");
  return `${(boundary > max * 0.6 ? cut.slice(0, boundary) : cut).trimEnd()}…`;
}

/**
 * One vetting lane (LLM scan or an external scanner cartridge). Lanes are
 * constructed at boot from config/availability and injected — the pipeline
 * never probes the environment itself, so tests stay hermetic.
 */
export interface SkillScanLane {
  /** Stamped on every finalized run row (`engine_versions`). */
  readonly engineVersions: string;
  /**
   * Scan one skill definition. Throws on ANY failure shape — a lane that
   * starts and fails is a lane error and fail-closes the vet (D32/D34).
   */
  scan(definition: string): Promise<VettingFinding[]>;
}

/** The v2 lane set; an absent key means the lane is unavailable. */
export interface SkillVettingLanes {
  llm?: SkillScanLane;
  cisco?: SkillScanLane;
  skillspector?: SkillScanLane;
}

export interface VettingRunRecord {
  id: string;
  namespace: Namespace;
  skillId: string;
  contentSha256: string;
  mode: VettingMode;
  status: VettingRunStatus;
  safetyScore: number | null;
  findings: VettingFinding[];
  detail: string | null;
  /** Engine/model stamp for v2 runs; null on legacy v1 rows. */
  engineVersions: string | null;
  ranBy: string;
  startedAt: string;
  finishedAt: string | null;
}

export interface VetSkillResult {
  skill: SkillRecord;
  runs: VettingRunRecord[];
  /** Overall public safety score: min of the per-lane scores. */
  safetyScore: number;
  verdict: "vetted" | "blocked" | "error";
}

interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

export interface SkillVettingDeps {
  db: Db;
  audit: AuditWriter;
  now?(): Date;
  /**
   * v2 lane configuration. Absent (or mode `off`) → the v1 static+sandbox
   * pipeline runs unchanged (D35-3, the keyless dev/test default).
   */
  v2?: { mode: VettingV2Mode; lanes: SkillVettingLanes };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHT: Record<VettingSeverity, number> = {
  low: 3,
  medium: 10,
  high: 25,
  critical: 60,
};

/** Pass line: score at or above this AND zero critical findings. */
export const VETTING_PASS_SCORE = 70;

export function scoreFindings(findings: VettingFinding[]): number {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function passed(findings: VettingFinding[]): boolean {
  return (
    scoreFindings(findings) >= VETTING_PASS_SCORE &&
    !findings.some((f) => f.severity === "critical")
  );
}

// ---------------------------------------------------------------------------
// Static scan
// ---------------------------------------------------------------------------

export interface StaticRule {
  rule: string;
  severity: VettingSeverity;
  message: string;
  pattern: RegExp;
  /** Mask the match in the public finding (secret-like rules). */
  mask?: boolean;
}

const STATIC_RULES: StaticRule[] = [
  {
    rule: "piped-shell-download",
    severity: "critical",
    message: "downloads remote content and pipes it into a shell",
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|da|k)?sh\b/i,
  },
  {
    rule: "base64-decode-exec",
    severity: "critical",
    message: "decodes base64 content into a shell",
    pattern: /base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba|z|da|k)?sh\b/i,
  },
  {
    rule: "aws-access-key",
    severity: "critical",
    message: "embedded AWS access key id",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    mask: true,
  },
  {
    rule: "api-secret-token",
    severity: "critical",
    message: "embedded provider API token",
    pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b/,
    mask: true,
  },
  {
    rule: "private-key-block",
    severity: "critical",
    message: "embedded private key material",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    mask: true,
  },
  {
    rule: "hardcoded-credential",
    severity: "high",
    message: "hardcoded credential-like assignment",
    pattern: /\b(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    mask: true,
  },
  {
    rule: "exec-directive",
    severity: "high",
    message: "spawns a child process",
    pattern: /\b(?:child_process|execSync|spawnSync|subprocess\.(?:run|Popen)|os\.system)\b/,
  },
  {
    rule: "dynamic-eval",
    severity: "high",
    message: "evaluates dynamically constructed code",
    pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/,
  },
  {
    rule: "destructive-fs",
    severity: "high",
    message: "destructive filesystem command",
    pattern: /\brm\s+-[a-z]*rf?\b|\bmkfs\b|\bdd\s+if=/i,
  },
  {
    rule: "privilege-escalation",
    severity: "high",
    message: "privilege escalation directive",
    pattern: /\bsudo\s+|\bchmod\s+777\b/,
  },
  {
    rule: "raw-ip-url",
    severity: "high",
    message: "network directive targeting a raw IP address",
    pattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/,
  },
  {
    rule: "tls-verification-off",
    severity: "medium",
    message: "disables TLS verification",
    pattern: /--insecure\b|\bverify\s*=\s*false\b|rejectUnauthorized\s*:\s*false/i,
  },
  {
    rule: "unbounded-loop",
    severity: "medium",
    message: "unbounded loop directive",
    pattern: /\bwhile\s*\(\s*true\s*\)|\bwhile\s+true\b|\bfor\s*\(\s*;\s*;\s*\)/,
  },
  {
    rule: "env-exfiltration",
    severity: "medium",
    message: "reads the whole process environment",
    pattern: /\bprocess\.env\b(?!\.)|\bprintenv\b|\benv\s*\|\s*curl/i,
  },
];

const EXCERPT_MAX = 80;

/**
 * The masked (secret-like) static rules, exported for the D33 redaction
 * pre-flight (`redact.ts`) — the single source for both the v1 static lane
 * and the v2 outbound-secret stripper, so the two never drift.
 */
export const REDACTION_RULES: readonly StaticRule[] = STATIC_RULES.filter(
  (rule) => rule.mask === true,
);

function excerptFor(match: string, mask: boolean): string {
  const flat = match.replace(/\s+/g, " ").trim();
  if (mask) {
    return `${flat.slice(0, 4)}…(${flat.length} chars, redacted)`;
  }
  return flat.length > EXCERPT_MAX ? `${flat.slice(0, EXCERPT_MAX)}…` : flat;
}

/** Pure, deterministic static scan — exported for direct unit testing. */
export function staticScan(definition: string): VettingFinding[] {
  const findings: VettingFinding[] = [];
  for (const rule of STATIC_RULES) {
    const match = rule.pattern.exec(definition);
    if (match) {
      findings.push({
        rule: rule.rule,
        severity: rule.severity,
        message: rule.message,
        excerpt: excerptFor(match[0], rule.mask === true),
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Sandboxed dry-run — the kernel's deterministic stub lane
// ---------------------------------------------------------------------------

const SANDBOX_MAX_FACTS = 500;
const SANDBOX_MAX_FACT_LENGTH = 10_000;
const SANDBOX_MAX_DEFINITION = 200_000;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/**
 * Dry-run the definition through the DETERMINISTIC extraction lane
 * (`StubLlm` with the real EXTRACT prompt — the same zero-network stub every
 * test and keyless deployment runs on). Nothing in the definition is
 * executed; the check is that the content is bounded and well-formed as
 * ingestable knowledge. Exported for direct unit testing.
 */
export async function sandboxDryRun(definition: string): Promise<VettingFinding[]> {
  const findings: VettingFinding[] = [];
  if (definition.length > SANDBOX_MAX_DEFINITION) {
    findings.push({
      rule: "oversized-definition",
      severity: "high",
      message: `definition exceeds ${SANDBOX_MAX_DEFINITION} characters`,
      excerpt: `${definition.length} chars`,
    });
  }
  const control = CONTROL_CHARS.exec(definition);
  if (control) {
    findings.push({
      rule: "control-characters",
      severity: "medium",
      message: "definition contains non-printable control characters",
      excerpt: `codepoint U+${control[0].codePointAt(0)!.toString(16).padStart(4, "0")}`,
    });
  }

  const stub = new StubLlm();
  const raw = await stub.complete(EXTRACT_SYSTEM, definition);
  const parsed = parseLooseJson(raw);
  if (!Array.isArray(parsed)) {
    findings.push({
      rule: "malformed-extraction",
      severity: "high",
      message: "deterministic extraction did not yield a fact array",
      excerpt: String(raw).slice(0, EXCERPT_MAX),
    });
    return findings;
  }
  if (parsed.length > SANDBOX_MAX_FACTS) {
    findings.push({
      rule: "unbounded-fan-out",
      severity: "medium",
      message: `extraction fans out to ${parsed.length} facts (cap ${SANDBOX_MAX_FACTS})`,
      excerpt: `${parsed.length} facts`,
    });
  }
  const oversized = parsed.filter(
    (f) => typeof (f as { content?: unknown }).content === "string" &&
      ((f as { content: string }).content.length > SANDBOX_MAX_FACT_LENGTH),
  ).length;
  if (oversized > 0) {
    findings.push({
      rule: "oversized-fact",
      severity: "medium",
      message: `${oversized} extracted fact(s) exceed ${SANDBOX_MAX_FACT_LENGTH} characters`,
      excerpt: `${oversized} oversized`,
    });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

interface VettingRunRow {
  id: string;
  namespace: string;
  skill_id: string;
  content_sha256: string;
  mode: string;
  status: string;
  safety_score: number | string | null;
  findings: unknown;
  detail: string | null;
  engine_versions?: string | null;
  ran_by: string;
  started_at: unknown;
  finished_at: unknown;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  throw new Error(`expected timestamp, got ${typeof value}`);
}

function rowToRun(r: unknown): VettingRunRecord {
  const row = r as VettingRunRow;
  const findings = typeof row.findings === "string"
    ? (JSON.parse(row.findings) as VettingFinding[])
    : ((row.findings ?? []) as VettingFinding[]);
  return {
    id: row.id,
    namespace: row.namespace,
    skillId: row.skill_id,
    contentSha256: row.content_sha256,
    mode: row.mode as VettingMode,
    status: row.status as VettingRunStatus,
    safetyScore: row.safety_score === null || row.safety_score === undefined
      ? null
      : Number(row.safety_score),
    findings,
    detail: row.detail ?? null,
    engineVersions: row.engine_versions ?? null,
    ranBy: row.ran_by,
    startedAt: toIso(row.started_at),
    finishedAt: row.finished_at === null || row.finished_at === undefined
      ? null
      : toIso(row.finished_at),
  };
}

// ---------------------------------------------------------------------------
// Lane planning (D35 brownout ladder)
// ---------------------------------------------------------------------------

/** ran_by stamp of the `skills sweep` CLI — the console "last swept" source. */
export const SKILL_SWEEP_ACTOR = "skills-sweep";

interface PlannedLane {
  mode: VettingMode;
  engineVersions: string | null;
  execute?: (definition: string) => Promise<VettingFinding[]>;
  /** Set when SKILL_VETTING_V2=required and the lane is missing (D35 → lane error). */
  unavailable?: string;
}

interface LanePlan {
  lanes: PlannedLane[];
  /** Lanes absent under `auto` — named in the audit detail, no run rows. */
  skipped: VettingMode[];
  /** Which pipeline ran — named in the audit detail. */
  pipeline: "v1" | "v2";
}

/** The D35-3 fallback: the v1 static+sandbox pipeline, exactly as before. */
function v1Lanes(): PlannedLane[] {
  return [
    { mode: "static", engineVersions: null, execute: async (d) => staticScan(d) },
    { mode: "sandbox", engineVersions: null, execute: (d) => sandboxDryRun(d) },
  ];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class SkillVetting {
  private readonly now: () => Date;

  constructor(private readonly deps: SkillVettingDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  /** Engine-version stamps of the configured v2 lanes (`skills sweep --stale-engines`). */
  currentEngineVersions(): Partial<Record<VettingMode, string>> {
    const out: Partial<Record<VettingMode, string>> = {};
    const lanes = this.deps.v2?.lanes;
    if (!lanes) return out;
    for (const mode of ["llm", "cisco", "skillspector"] as const) {
      const lane = lanes[mode];
      if (lane) out[mode] = lane.engineVersions;
    }
    return out;
  }

  /** Latest sweep-run timestamp across all namespaces (console "last swept"). */
  async lastSweepAt(): Promise<string | null> {
    const res = await this.deps.db.query(
      `SELECT MAX(started_at) AS ts FROM skill_vetting_runs WHERE ran_by = $1`,
      [SKILL_SWEEP_ACTOR],
    );
    const ts = (res.rows[0] as { ts?: unknown } | undefined)?.ts;
    return ts === null || ts === undefined ? null : toIso(ts);
  }

  /**
   * Lane selection per the D35 ladder. Absence is never an error: under
   * `auto` a missing lane is skipped-and-recorded; under `required` a
   * missing lane becomes a lane error and fail-closes (D32); with no v2
   * lane at all the v1 pipeline runs unchanged.
   */
  private planLanes(): LanePlan {
    const v2 = this.deps.v2;
    if (!v2 || v2.mode === "off") return { lanes: v1Lanes(), skipped: [], pipeline: "v1" };
    const lanes: PlannedLane[] = [];
    const skipped: VettingMode[] = [];
    for (const mode of ["llm", "cisco", "skillspector"] as const) {
      const lane = v2.lanes[mode];
      if (lane) {
        lanes.push({
          mode,
          engineVersions: lane.engineVersions,
          execute: (definition) => lane.scan(definition),
        });
      } else if (v2.mode === "required") {
        lanes.push({
          mode,
          engineVersions: null,
          unavailable: `${mode} lane unavailable (SKILL_VETTING_V2=required)`,
        });
      } else {
        skipped.push(mode);
      }
    }
    if (lanes.length === 0) {
      // D35-3: no v2 lane available → the v1 pipeline, unchanged.
      return { lanes: v1Lanes(), skipped, pipeline: "v1" };
    }
    return { lanes, skipped, pipeline: "v2" };
  }

  /**
   * Run the pipeline against the CURRENT content of a skill. Phase 1 claims
   * the skill (`vetting_status = 'vetting'`) and inserts every planned run
   * as `running` — a crash mid-vet leaves visible evidence and a
   * still-blocked skill. Phase 2 finalizes each run exactly once, writes the
   * public score onto the skill row, and audits `skill_vet` in the same
   * transaction (E20/D4).
   */
  async vet(identity: Identity, skillId: string): Promise<VetSkillResult> {
    const loaded = await this.deps.db.query(`SELECT * FROM skills WHERE id = $1`, [skillId]);
    if (loaded.rows.length === 0) {
      await this.auditStandalone(identity, "skill_vet", skillId, identity.namespace,
        "miss", `skill=${skillId} not found`);
      throw new SkillNotFoundError();
    }
    const skill = rowToSkill(loaded.rows[0]);
    if (!canManageSkill(identity, skill.namespace)) {
      await this.auditStandalone(identity, "skill_vet", skillId, skill.namespace,
        "denied", `skill=${skillId} role=${identity.role}`);
      throw new SkillAuthorizationError();
    }
    if (skill.tValidTo !== null) {
      await this.auditStandalone(identity, "skill_vet", skillId, skill.namespace,
        "denied", `skill=${skillId} superseded; vet the current row`);
      throw new SkillConflictError();
    }

    // Bind every run to the EXACT content hash being examined; a concurrent
    // redefinition mints a new row id and its runs never blur together.
    const contentSha = sha256Hex(skill.definition);
    const startTs = this.now().toISOString();
    const plan = this.planLanes();
    const runIds = plan.lanes.map(() => ulid());

    // Phase 1 — claim + running evidence.
    await this.deps.db.transaction(async (tx) => {
      const claimed = await tx.query(
        `UPDATE skills SET vetting_status = 'vetting', updated_at = $2
          WHERE id = $1 AND t_valid_to IS NULL
          RETURNING id`,
        [skillId, startTs],
      );
      if (claimed.rows.length !== 1) throw new SkillConflictError();
      for (const [i, lane] of plan.lanes.entries()) {
        await tx.query(
          `INSERT INTO skill_vetting_runs
             (id, namespace, skill_id, content_sha256, mode, status, safety_score,
              findings, detail, ran_by, started_at, finished_at)
           VALUES ($1, $2, $3, $4, $5, 'running', NULL, '[]', NULL, $6, $7, NULL)`,
          [runIds[i]!, skill.namespace, skillId, contentSha, lane.mode, identity.actor, startTs],
        );
      }
    });

    // Compute. A lane that STARTS and fails is a lane error (D32) — recorded
    // per lane, never mapped to "no findings = pass".
    interface LaneOutcome {
      findings: VettingFinding[];
      score: number;
      error: string | null;
    }
    const outcomes: LaneOutcome[] = [];
    for (const lane of plan.lanes) {
      if (lane.unavailable !== undefined) {
        outcomes.push({ findings: [], score: 0, error: lane.unavailable });
        continue;
      }
      try {
        const findings = await lane.execute!(skill.definition);
        outcomes.push({ findings, score: scoreFindings(findings), error: null });
      } catch (err) {
        outcomes.push({
          findings: [],
          score: 0,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const finishTs = this.now().toISOString();
    const anyError = outcomes.some((o) => o.error !== null);
    const overall = outcomes.reduce((min, o) => Math.min(min, o.score), 100);
    const verdict: VetSkillResult["verdict"] = anyError
      ? "error"
      : outcomes.every((o) => passed(o.findings))
        ? "vetted"
        : "blocked";
    // Fail safe: an errored pipeline returns the skill to `unvetted` — still
    // blocked from use by the E22 gate — rather than asserting a verdict.
    const nextStatus = verdict === "error" ? "unvetted" : verdict;

    const laneSummary = plan.lanes
      .map((lane, i) => `${lane.mode}:${outcomes[i]!.error !== null ? "error" : outcomes[i]!.score}`)
      .join(",");
    const skippedSummary = plan.skipped.length > 0 ? ` skipped=${plan.skipped.join(",")}` : "";
    const totalFindings = outcomes.reduce((sum, o) => sum + o.findings.length, 0);
    const firstError = outcomes.find((o) => o.error !== null)?.error ?? null;
    const handling = deriveSkillHandling(
      skill.definition,
      outcomes.flatMap((outcome) => outcome.findings)
        .map((finding) => `${finding.rule} ${finding.message} ${finding.excerpt ?? ""}`)
        .join("\n"),
    );

    // Phase 2 — finalize runs exactly once + public score + audit, atomically.
    await this.deps.db.transaction(async (tx) => {
      for (const [i, lane] of plan.lanes.entries()) {
        const outcome = outcomes[i]!;
        const status: VettingRunStatus = outcome.error !== null
          ? "error"
          : passed(outcome.findings)
            ? "passed"
            : "failed";
        await tx.query(
          `UPDATE skill_vetting_runs
              SET status = $2, safety_score = $3, findings = $4, detail = $5,
                  engine_versions = $6, finished_at = $7
            WHERE id = $1 AND status = 'running'`,
          [
            runIds[i]!, status, outcome.error !== null ? null : outcome.score,
            JSON.stringify(outcome.findings), outcome.error, lane.engineVersions, finishTs,
          ],
        );
      }
      await tx.query(
        `UPDATE skills
            SET vetting_status = $2, safety_score = $3, last_vetted_at = $4, updated_at = $4
          WHERE id = $1 AND vetting_status = 'vetting'`,
        [skillId, nextStatus, anyError ? null : overall, finishTs],
      );
      await tx.query(
        `UPDATE skill_labels
            SET handling = $3, updated_by = $4, updated_at = $5
          WHERE namespace = $1 AND skill_key = $2`,
        [skill.namespace, skill.skillKey, JSON.stringify(handling), identity.actor, finishTs],
      );
      await this.deps.audit.appendTo(tx, {
        ts: finishTs,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "skill_vet",
        memoryId: skillId,
        namespace: skill.namespace,
        purpose: "skill-vetting",
        result: anyError ? "error" : "ok",
        detail: anyError
          ? `verdict=error pipeline=${plan.pipeline} lanes=${laneSummary}${skippedSummary} ` +
            `sha=${contentSha.slice(0, 12)} - ${firstError}`
          : `verdict=${verdict} score=${overall} pipeline=${plan.pipeline} ` +
            `lanes=${laneSummary}${skippedSummary} findings=${totalFindings} ` +
            `sha=${contentSha.slice(0, 12)}`,
      });
    });

    const runs = await this.runsById(runIds);
    const after = await this.deps.db.query(
      `SELECT s.*, (SELECT COUNT(*) FROM skills c
                     WHERE c.namespace = s.namespace AND c.skill_key = s.skill_key
                       AND c.t_valid_from <= s.t_valid_from) AS version
         FROM skills s WHERE s.id = $1`,
      [skillId],
    );
    return {
      skill: rowToSkill(after.rows[0]),
      runs,
      safetyScore: overall,
      verdict,
    };
  }

  /** Vetting history for a skill's detail view, newest first (ACL-checked). */
  async listRuns(identity: Identity, skillId: string): Promise<VettingRunRecord[]> {
    const loaded = await this.deps.db.query(
      `SELECT namespace FROM skills WHERE id = $1`, [skillId],
    );
    const ns = (loaded.rows[0] as { namespace: string } | undefined)?.namespace;
    if (ns === undefined || !canReadSkill(identity, ns)) throw new SkillNotFoundError();
    const res = await this.deps.db.query(
      `SELECT * FROM skill_vetting_runs WHERE skill_id = $1
        ORDER BY started_at DESC, id DESC LIMIT 100`,
      [skillId],
    );
    return res.rows.map(rowToRun);
  }

  // -------------------------------------------------------------------------

  private async runsById(ids: string[]): Promise<VettingRunRecord[]> {
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.deps.db.query(
      `SELECT * FROM skill_vetting_runs WHERE id IN (${placeholders}) ORDER BY mode`,
      ids,
    );
    return res.rows.map(rowToRun);
  }

  private auditStandalone(
    identity: Identity,
    op: AuditOp,
    memoryId: MemoryId | null,
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> {
    return this.deps.db.transaction((tx) =>
      this.deps.audit.appendTo(tx, {
        ts: this.now().toISOString(),
        actor: identity.actor,
        agentId: identity.keyId,
        op,
        memoryId,
        namespace,
        purpose: "skill-vetting",
        result,
        detail,
      }),
    );
  }
}
