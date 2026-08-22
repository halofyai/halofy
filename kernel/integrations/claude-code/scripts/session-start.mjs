#!/usr/bin/env node
// SessionStart hook — put the organization's governed POLICY in front of the
// agent, then recall project memory, and hand both to Claude Code as
// additionalContext.
//
// Policy first, deliberately: guardrails a human loaded into the HaloMem policy
// register are binding instructions, while recalled memory is retrieved data.
// Calling /v1/mem/policy also records the delivery, so the console's compliance
// view can show that this session was actually handed the current version.
//
// Input (stdin): { session_id, cwd, source, ... }
// Output (stdout): { hookSpecificOutput: { hookEventName, additionalContext } }
// Failure mode: exit 0 with no output — never block the session.

import { basename } from "node:path";
import { readConfig, readStdinJson, syscall } from "./lib.mjs";

const MAX_MEMORIES = 8;
const MAX_DIRECTIVES = 40;

const config = readConfig();
if (!config) process.exit(0);

const input = await readStdinJson();
const project = input.cwd ? basename(String(input.cwd)) : "";
const query =
  (project ? project + " " : "") +
  "project conventions, decisions, preferences, and known context";

const [policy, results] = await Promise.all([
  syscall(config, "/v1/mem/policy", { tokenBudget: 1500 }),
  syscall(config, "/v1/mem/search", {
    query,
    k: MAX_MEMORIES,
    tokenBudget: 1500,
  }),
]);

const sections = [];

const directives =
  policy && Array.isArray(policy.blocks)
    ? policy.blocks
        .filter((b) => b && typeof b.content === "string" && b.content.trim())
        .slice(0, MAX_DIRECTIVES)
    : [];
if (directives.length > 0) {
  const titles = Array.isArray(policy.documents)
    ? policy.documents.map((d) => d && d.title).filter(Boolean).join(", ")
    : "";
  sections.push(
    "Organization policy (HaloMem" +
      (titles ? ": " + titles : "") +
      "). These are binding operator-authored guardrails, not retrieved evidence - " +
      "follow them, and say which one applies when a request conflicts with them. " +
      "Acknowledge with the mem_policy_ack tool using digest " +
      String(policy.digest || "").slice(0, 12) +
      ".\n" +
      directives.map((b) => "- " + b.content.trim()).join("\n"),
  );
}

const lines = Array.isArray(results)
  ? results
      .filter((r) => r && typeof r.content === "string" && r.content.trim())
      .map((r) => "- " + r.content.trim())
  : [];
if (lines.length > 0) {
  sections.push(
    "Organizational memory (HaloMem" +
      (project ? ", project " + project : "") +
      "):\n" +
      lines.join("\n"),
  );
}

if (sections.length === 0) process.exit(0);

process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: sections.join("\n\n"),
    },
  }),
);
process.exit(0);
