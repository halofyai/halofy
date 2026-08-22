/**
 * External scanner lane (CONTRACTS-S16-VETTING-V2.md, D34).
 *
 * Cisco `skill-scanner` and NVIDIA SkillSpector run as pinned,
 * subprocess-isolated cartridges: a child process over a temp copy of the
 * definition, hard timeout. Their LLM analyzers are enabled when the Azure
 * scan deployment is configured (2026-07-19 decision, amending the original
 * static-only D34): they share the ONE Azure OpenAI key surface with the
 * kernel's own scan lane — SkillSpector via OPENAI_BASE_URL, Cisco via
 * SKILL_SCANNER_LLM_BASE_URL, both pointing at the deployment's
 * OpenAI-compatible `/openai/v1/` endpoint. NOTE the D33 scope consequence:
 * a scanner's LLM analyzer sends the ORIGINAL definition text (redaction
 * only guards the kernel's own llm lane and persisted excerpts) to the same
 * sanctioned Azure endpoint.
 * Scanner temp dirs are created 0700 (mkdtemp default) and unlinked in
 * `finally`; the scanners run locally, so they see the ORIGINAL text —
 * redaction is only for the kernel's own outbound LLM call.
 *
 * Engine versions are probed at boot and stamped on every run row
 * (`engine_versions`, with a `+llm` suffix when the LLM analyzers are
 * active), so a rules upgrade is a deliberate image rebuild and stale runs
 * are queryable. Output is normalized into VettingFinding — external
 * severities and categories never leak raw into the score math, and an
 * unknown severity or malformed JSON is a lane error for THAT engine,
 * never a silently-dropped finding (boundary rule 4).
 *
 * The JSON field aliases in `extractRawFindings` are pinned by the real
 * captures in test/fixtures/ (cisco-known-bad.json,
 * skillspector-known-bad.json — contract open item #3, resolved 2026-07-19:
 * skill-scanner 2.0.12, SkillSpector v2.3.1).
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redactForOutbound } from "./redact.js";
import { clampFindingText } from "./vetting.js";
import type { SkillScanLane, VettingFinding, VettingSeverity } from "./vetting.js";

/** Any engine failure shape lands on this single error type. */
export class ExternalScanLaneError extends Error {}

export const EXTERNAL_SCAN_TIMEOUT_MS = 30_000;
/** LLM analyzers add real model latency to every scan (2026-07-19 amendment). */
export const EXTERNAL_SCAN_LLM_TIMEOUT_MS = 180_000;

/** Process spawn surface — injectable so tests never touch child_process. */
export type ProcessRunner = (
  command: string,
  args: string[],
  opts: { timeoutMs: number; env?: Record<string, string> },
) => Promise<{ stdout: string; stderr: string }>;

/**
 * LLM analyzer activation for one engine (2026-07-19 amendment): extra env
 * the child needs to reach the shared Azure OpenAI deployment. Absent →
 * the engine runs its static analyzers only.
 */
export interface ScannerLlmOptions {
  env: Record<string, string>;
}

/** One finding as an external engine reports it, pre-normalization. */
export interface RawExternalFinding {
  rule: string;
  severity: string;
  message: string;
  line: number | null;
  excerpt: string;
}

export interface ExternalEngineSpec {
  readonly lane: "cisco" | "skillspector";
  readonly command: string;
  readonly versionArgs: readonly string[];
  /**
   * CLI args for one scan. Cisco scans a skill PACKAGE (the directory);
   * SkillSpector scans the definition FILE. `llm` toggles each engine's own
   * LLM analyzer (pointed at the shared Azure deployment via ScannerLlmOptions).
   */
  readonly scanArgs: (scanDir: string, filePath: string, llm: boolean) => string[];
  /** Parse CLI stdout into raw findings; throws ExternalScanLaneError on malformed JSON. */
  readonly parse: (stdout: string) => RawExternalFinding[];
}

// ---------------------------------------------------------------------------
// Engine specs (static by default; LLM analyzers on the shared Azure key)
// ---------------------------------------------------------------------------

export const CISCO_SPEC: ExternalEngineSpec = {
  lane: "cisco",
  command: process.env.HALOMEM_CISCO_SCANNER_CMD ?? "skill-scanner",
  versionArgs: ["--version"],
  // --use-llm needs SKILL_SCANNER_LLM_API_KEY / _BASE_URL / _MODEL in the
  // child env (wired by v2.ts). Without them the CLI brownouts to static.
  scanArgs: (scanDir, _filePath, llm) => [
    "scan", scanDir, "--format", "json",
    ...(llm ? ["--use-llm", "--llm-provider", "openai-compatible"] : []),
  ],
  parse: (stdout) => extractRawFindings(stdout, "cisco"),
};

export const SKILLSPECTOR_SPEC: ExternalEngineSpec = {
  lane: "skillspector",
  command: process.env.HALOMEM_SKILLSPECTOR_CMD ?? "skillspector",
  versionArgs: ["--version"],
  // --no-llm is REQUIRED for static runs: without it (and without a key) the
  // CLI refuses to run at all. With the LLM env wired (v2.ts) it is omitted.
  scanArgs: (_scanDir, filePath, llm) => [
    "scan", filePath, "--format", "json",
    ...(llm ? [] : ["--no-llm"]),
  ],
  parse: (stdout) => extractRawFindings(stdout, "skillspector"),
};

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, VettingSeverity> = {
  critical: "critical",
  high: "high",
  error: "high",
  medium: "medium",
  moderate: "medium",
  warning: "medium",
  low: "low",
  info: "low",
  informational: "low",
  notice: "low",
};

/**
 * Map an external severity string onto the public severity scale. An
 * UNKNOWN severity is a lane error (boundary rule 4) — never silently
 * dropped, never guessed.
 */
export function normalizeSeverity(raw: string): VettingSeverity {
  const mapped = SEVERITY_MAP[raw.trim().toLowerCase()];
  if (!mapped) throw new ExternalScanLaneError(`unknown scanner severity '${raw}'`);
  return mapped;
}

/**
 * Cross-engine category buckets — the dedupe key's rule component. Two
 * engines reporting the same attack on the same line merge only when they
 * land in the same bucket AND the same line AND the same severity (never
 * cross-severity).
 */
const CATEGORY_KEYWORDS: readonly [string, readonly string[]][] = [
  ["download-run", ["download", "curl", "wget", "pipe", "remote"]],
  ["exec", ["exec", "eval", "spawn", "subprocess", "command-injection", "code-execution", "shell"]],
  ["exfiltration", ["exfil", "leak", "steal", "upload", "send-data"]],
  ["injection", ["injection", "override", "jailbreak", "smuggl", "role"]],
  ["destructive", ["destruct", "delete", "wipe", "rm-rf", "mkfs"]],
  ["privilege", ["privilege", "escalat", "sudo", "chmod"]],
  ["obfuscation", ["obfuscat", "base64", "hex", "invisible", "homoglyph", "unicode"]],
  ["credential", ["credential", "secret", "token", "api-key", "apikey", "password", "private-key"]],
  ["network", ["network", "url", "endpoint", "raw-ip", "ssrf"]],
];

export function categoryFor(rule: string, message: string): string {
  const text = `${rule} ${message}`.toLowerCase();
  for (const [category, keywords] of CATEGORY_KEYWORDS) {
    if (keywords.some((kw) => text.includes(kw))) return category;
  }
  return "other";
}

export interface NormalizedExternalFinding extends VettingFinding {
  line: number | null;
}

/**
 * Normalize one raw engine finding. Message/excerpt pass through the D33
 * redaction rules: the scanners see the ORIGINAL definition, so a finding
 * could quote embedded secret material — the same "the score is public,
 * the secret never is" rule as the v1 masked static findings applies to
 * everything persisted on the run row.
 */
export function normalizeFinding(raw: RawExternalFinding): NormalizedExternalFinding {
  const message = redactForOutbound(clampFindingText(`${raw.rule}: ${raw.message}`, 500)).redacted;
  const excerpt = raw.excerpt.length > 80 ? `${raw.excerpt.slice(0, 80)}…` : raw.excerpt;
  return {
    rule: categoryFor(raw.rule, raw.message),
    severity: normalizeSeverity(raw.severity),
    message,
    excerpt: redactForOutbound(excerpt).redacted,
    line: raw.line,
  };
}

/**
 * Cross-engine dedupe: merge only findings agreeing on normalized rule
 * (category) AND line AND severity — never cross-severity. First wins.
 */
export function dedupeFindings(
  findings: NormalizedExternalFinding[],
): NormalizedExternalFinding[] {
  const seen = new Set<string>();
  const out: NormalizedExternalFinding[] = [];
  for (const f of findings) {
    const key = `${f.rule}:${f.line ?? "-"}:${f.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// ---------------------------------------------------------------------------
// CLI output extraction (tolerant field aliases; strict on shape/severity)
// ---------------------------------------------------------------------------

const FINDINGS_KEYS = ["findings", "issues", "results", "violations"] as const;
const RULE_KEYS = ["rule_id", "ruleId", "rule", "id", "check", "name"] as const;
const SEVERITY_KEYS = ["severity", "level", "risk"] as const;
const MESSAGE_KEYS = ["message", "description", "explanation", "detail", "title"] as const;
const LINE_KEYS = ["line", "line_number", "lineNumber", "start_line", "startLine"] as const;
const EXCERPT_KEYS = ["excerpt", "snippet", "evidence", "match", "finding"] as const;

function pick(obj: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const key of keys) {
    if (obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return undefined;
}

/** Line numbers also hide inside a nested location object (SkillSpector). */
function pickLine(obj: Record<string, unknown>): number | null {
  const direct = pick(obj, LINE_KEYS);
  if (typeof direct === "number" && Number.isInteger(direct)) return direct;
  const location = obj.location;
  if (typeof location === "object" && location !== null) {
    const nested = pick(location as Record<string, unknown>, LINE_KEYS);
    if (typeof nested === "number" && Number.isInteger(nested)) return nested;
  }
  return null;
}

function extractRawFindings(stdout: string, engine: string): RawExternalFinding[] {
  // CLIs with LLM analyzers enabled can interleave library log lines with
  // the JSON document on stdout (litellm does this). Slice to the outermost
  // JSON span; absent or unparsable JSON remains a lane error.
  const firstObj = stdout.indexOf("{");
  const firstArr = stdout.indexOf("[");
  const start = firstArr !== -1 && (firstObj === -1 || firstArr < firstObj) ? firstArr : firstObj;
  const end = Math.max(stdout.lastIndexOf("}"), stdout.lastIndexOf("]"));
  if (start === -1 || end <= start) {
    throw new ExternalScanLaneError(`${engine} output was not JSON`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(start, end + 1));
  } catch {
    throw new ExternalScanLaneError(`${engine} output was not JSON`);
  }
  const findings = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" && parsed !== null
      ? pick(parsed as Record<string, unknown>, FINDINGS_KEYS)
      : undefined;
  if (!Array.isArray(findings)) {
    throw new ExternalScanLaneError(`${engine} output had no findings array`);
  }
  return findings.map((raw, i) => {
    if (typeof raw !== "object" || raw === null) {
      throw new ExternalScanLaneError(`${engine} finding #${i + 1} was not an object`);
    }
    const obj = raw as Record<string, unknown>;
    const rule = pick(obj, RULE_KEYS);
    const severity = pick(obj, SEVERITY_KEYS);
    if (typeof rule !== "string" || rule.length === 0) {
      throw new ExternalScanLaneError(`${engine} finding #${i + 1} had no rule id`);
    }
    if (typeof severity !== "string" || severity.length === 0) {
      throw new ExternalScanLaneError(`${engine} finding #${i + 1} had no severity`);
    }
    const baseMessage = pick(obj, MESSAGE_KEYS);
    // Category/pattern labels (SkillSpector) prefix the message so the
    // cross-engine category buckets see meaningful text, not opaque ids.
    const labels = [obj.category, obj.pattern]
      .filter((v): v is string => typeof v === "string" && v.length > 0)
      .join(" / ");
    const excerpt = pick(obj, EXCERPT_KEYS);
    return {
      rule,
      severity,
      message: `${labels.length > 0 ? `${labels}: ` : ""}${
        typeof baseMessage === "string" ? baseMessage : rule
      }`,
      line: pickLine(obj),
      excerpt: typeof excerpt === "string" ? excerpt : "",
    };
  });
}

// ---------------------------------------------------------------------------
// Runner + probe + lane
// ---------------------------------------------------------------------------

/**
 * Lane-error message for a failed spawn. Node's execFile error message
 * embeds the child's STDERR verbatim — a scanner that fails after echoing
 * an offending line would put original definition content into the run row
 * `detail` and audit `detail` (D33 / boundary rule 1). Keep only the
 * failure shape; spawn errors (binary never ran) are safe to quote.
 */
export function scanFailureMessage(
  command: string,
  err: Error & { code?: unknown; killed?: boolean; signal?: unknown },
  timeoutMs: number,
): string {
  if (err.killed === true || typeof err.signal === "string") {
    return `${command} timed out after ${timeoutMs}ms`;
  }
  if (typeof err.code === "number") {
    return `${command} exited ${err.code} with no parseable output`;
  }
  return `${command} failed: ${err.message}`;
}

export function createNodeProcessRunner(): ProcessRunner {
  return (command, args, opts) =>
    new Promise((resolve, reject) => {
      execFile(
        command,
        args,
        {
          timeout: opts.timeoutMs,
          maxBuffer: 16 * 1024 * 1024,
          windowsHide: true,
          env: opts.env ? { ...process.env, ...opts.env } : process.env,
        },
        (err, stdout, stderr) => {
          if (!err) {
            resolve({ stdout, stderr });
            return;
          }
          // A NON-ZERO EXIT with stdout is a completed scan: scanners such as
          // SkillSpector exit 1 when findings exist. Spawn failures (ENOENT)
          // and timeouts/kills are lane errors.
          const exitCode = (err as { code?: unknown }).code;
          if (typeof exitCode === "number" && stdout.trim().length > 0) {
            resolve({ stdout, stderr });
            return;
          }
          reject(new ExternalScanLaneError(
            scanFailureMessage(command, err as Error & { code?: unknown }, opts.timeoutMs),
          ));
        },
      );
    });
}

function probeVersion(stdout: string): string {
  const match = /(\d+\.\d+(?:\.\d+)?)/.exec(stdout);
  return match?.[1] ?? "unknown";
}

/**
 * Availability probe: run the engine's version command. Present → a ready
 * lane stamped `cisco@<ver>` / `skillspector@<ver>` (`+llm` suffix when the
 * LLM analyzers are active); absent (spawn error, non-zero exit) → null,
 * and the caller applies the D35 ladder.
 */
export async function probeExternalLane(
  spec: ExternalEngineSpec,
  runner: ProcessRunner,
  llm?: ScannerLlmOptions,
): Promise<SkillScanLane | null> {
  try {
    const { stdout } = await runner(spec.command, [...spec.versionArgs], {
      timeoutMs: EXTERNAL_SCAN_TIMEOUT_MS,
    });
    return new ExternalSkillScanLane(
      spec,
      `${spec.lane}@${probeVersion(stdout)}${llm ? "+llm" : ""}`,
      runner,
      llm,
    );
  } catch {
    return null;
  }
}

const HAS_FRONTMATTER = /^---\r?\n/;

/**
 * The scan copy of the definition. Cisco's loader REQUIRES SKILL.md
 * frontmatter with a `name` (it exits 1 with no output otherwise — the
 * first prod sweep failure), while HaloMem skill definitions are plain
 * instruction text. Synthesize a minimal manifest when absent; line
 * numbers from that engine shift by the header height, noted in excerpts.
 */
function definitionForScan(definition: string): string {
  if (HAS_FRONTMATTER.test(definition)) return definition;
  return `---\nname: skill\ndescription: Agent skill definition from the Halofy skill library.\n---\n${definition}`;
}

/**
 * Run one engine over a temp copy of the ORIGINAL definition (the scanners
 * are local; redaction is only for the kernel's own outbound LLM call).
 * The temp dir is mkdtemp's default 0700 and is unlinked in `finally` —
 * even on timeout.
 */
export async function runExternalScan(
  spec: ExternalEngineSpec,
  definition: string,
  runner: ProcessRunner,
  llm?: ScannerLlmOptions,
): Promise<NormalizedExternalFinding[]> {
  const dir = await mkdtemp(join(tmpdir(), "halomem-vet-"));
  try {
    const file = join(dir, "SKILL.md");
    await writeFile(file, definitionForScan(definition), { mode: 0o600 });
    const timeoutMs = llm ? EXTERNAL_SCAN_LLM_TIMEOUT_MS : EXTERNAL_SCAN_TIMEOUT_MS;
    const { stdout } = await runner(spec.command, spec.scanArgs(dir, file, llm !== undefined), {
      timeoutMs,
      env: llm?.env,
    });
    return dedupeFindings(spec.parse(stdout).map(normalizeFinding));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export class ExternalSkillScanLane implements SkillScanLane {
  constructor(
    readonly spec: ExternalEngineSpec,
    readonly engineVersions: string,
    private readonly runner: ProcessRunner,
    private readonly llm?: ScannerLlmOptions,
  ) {}

  async scan(definition: string): Promise<VettingFinding[]> {
    const findings = await runExternalScan(this.spec, definition, this.runner, this.llm);
    return findings.map(({ line: _line, ...finding }) => ({
      ...finding,
      excerpt: fline(finding.excerpt, _line),
    }));
  }
}

function fline(excerpt: string, line: number | null): string {
  if (line === null) return excerpt;
  const tagged = excerpt.length > 0 ? `L${line}: ${excerpt}` : `line ${line}`;
  return tagged.length > 80 ? `${tagged.slice(0, 80)}…` : tagged;
}
