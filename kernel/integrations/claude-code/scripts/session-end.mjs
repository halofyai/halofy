#!/usr/bin/env node
// Stop hook — capture what happened this session through the governed write
// path. The kernel runs extraction, verification, dedupe, and supersedence
// (D10): raw transcript text goes in, durable facts come out. Nothing is
// overwritten or deleted (D7).
//
// Input (stdin): { session_id, transcript_path, cwd, stop_hook_active, ... }
// Failure mode: exit 0 silently — never block or re-trigger the agent.

import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { readConfig, readStdinJson, syscall } from "./lib.mjs";

const MAX_CHARS = 6000;

const config = readConfig();
if (!config) process.exit(0);

const input = await readStdinJson();
if (input.stop_hook_active) process.exit(0); // do not loop

let transcript = "";
try {
  transcript = await readFile(String(input.transcript_path || ""), "utf8");
} catch {
  process.exit(0);
}

// Transcript is JSONL; keep human-meaningful turns (user text + assistant text).
const turns = [];
for (const line of transcript.split("\n")) {
  if (!line.trim()) continue;
  let entry;
  try {
    entry = JSON.parse(line);
  } catch {
    continue;
  }
  const message = entry && entry.message;
  if (!message || !message.role) continue;
  const content = message.content;
  let text = "";
  if (typeof content === "string") {
    text = content;
  } else if (Array.isArray(content)) {
    text = content
      .filter((part) => part && part.type === "text" && typeof part.text === "string")
      .map((part) => part.text)
      .join("\n");
  }
  text = text.trim();
  if (!text) continue;
  turns.push((message.role === "user" ? "User: " : "Assistant: ") + text);
}
if (turns.length === 0) process.exit(0);

// Most recent turns fit the budget; older context is the first to go.
let body = "";
for (let i = turns.length - 1; i >= 0; i--) {
  const candidate = turns[i] + "\n\n" + body;
  if (candidate.length > MAX_CHARS) break;
  body = candidate;
}
if (!body.trim()) body = turns[turns.length - 1].slice(0, MAX_CHARS);

const project = input.cwd ? basename(String(input.cwd)) : "";
await syscall(config, "/v1/mem/write", {
  scope: "user",
  content:
    "Claude Code session" + (project ? " in project " + project : "") + ":\n\n" + body.trim(),
  session: String(input.session_id || "") || undefined,
});

process.exit(0);
