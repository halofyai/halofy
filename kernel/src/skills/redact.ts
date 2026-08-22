/**
 * D33 redaction pre-flight (CONTRACTS-S16-VETTING-V2.md): secrets never
 * leave the box.
 *
 * Before any bytes of a skill definition are sent to the scan LLM, the
 * masked static rules (`aws-access-key`, `api-secret-token`,
 * `private-key-block`, `hardcoded-credential` — the single REDACTION_RULES
 * source shared with the v1 static lane, so the two never drift) run as a
 * REDACTOR: every match is replaced with `«REDACTED:<rule>»` in the
 * outbound text and simultaneously recorded as a finding (severity
 * unchanged — embedded secrets remain critical/high) attributed to the
 * `llm` lane. The unredacted definition never appears in any outbound
 * request, log line, finding excerpt, or run row detail.
 *
 * Pure function, exported for unit tests (E64).
 */

import { REDACTION_RULES, type VettingFinding } from "./vetting.js";

export interface RedactionResult {
  /** The definition with every secret match replaced — the ONLY outbound text. */
  redacted: string;
  /** One finding per rule that matched (severity unchanged from the rule). */
  findings: VettingFinding[];
}

/** The substitution marker; also the finding excerpt (never the secret). */
export function redactionMarker(rule: string): string {
  return `«REDACTED:${rule}»`;
}

function globalized(pattern: RegExp): RegExp {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return new RegExp(pattern.source, flags);
}

export function redactForOutbound(definition: string): RedactionResult {
  let redacted = definition;
  const findings: VettingFinding[] = [];
  for (const rule of REDACTION_RULES) {
    let matched = false;
    redacted = redacted.replace(globalized(rule.pattern), () => {
      matched = true;
      return redactionMarker(rule.rule);
    });
    if (matched) {
      findings.push({
        rule: rule.rule,
        severity: rule.severity,
        message: rule.message,
        excerpt: redactionMarker(rule.rule),
      });
    }
  }
  return { redacted, findings };
}
