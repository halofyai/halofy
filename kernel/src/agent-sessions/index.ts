/**
 * Governed agent-session observation.
 *
 * Raw turns exist only for the duration of `complete`. The injected summarizer
 * returns the only text this module is allowed to send through D10's canonical
 * write path; durable bookkeeping contains hashes, counts, and memory ids only.
 */

import { createHash } from "node:crypto";
import { ulid } from "ulid";

import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import type {
  AgentSessionCompleteInput,
  AgentSessionSummaryView,
  AgentSessionTurn,
  Identity,
  MemoryId,
  WriteRequest,
  WriteResult,
} from "../types.js";
import { redactForOutbound } from "../skills/redact.js";

const MAX_TURNS = 128;
const MAX_TURN_CHARS = 16_000;
const MAX_SESSION_CHARS = 64_000;
const ALLOWED_INPUT_KEYS = new Set(["sessionId", "startedAt", "endedAt", "turns"]);

export interface AgentSessionSummary {
  summary: string;
  claims: Array<{ content: string; role: AgentSessionTurn["role"] }>;
}

export interface AgentSessionSummaryDeps {
  db: Db;
  audit: AuditLog;
  summarize(turns: AgentSessionTurn[], identity: Identity): Promise<AgentSessionSummary>;
  write(request: WriteRequest, identity: Identity): Promise<WriteResult>;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

const PII_REDACTIONS: RegExp[] = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  /\b(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}\b/g,
  /\b(?:\d[ -]*?){13,19}\b/g,
];

function redactContent(content: string): string {
  let value = redactForOutbound(content).redacted;
  for (const pattern of PII_REDACTIONS) value = value.replace(pattern, "[REDACTED:PII]");
  return value;
}

function supportTokens(content: string): Set<string> {
  return new Set(content.toLowerCase().match(/[a-z0-9]{2,}/g) ?? []);
}

function assertSupported(text: string, transcriptTokens: Set<string>): void {
  const tokens = [...supportTokens(text)].filter((token) => ![
    "the", "and", "for", "from", "that", "this", "with", "was", "are", "our", "has", "have",
  ].includes(token));
  if (tokens.filter((token) => transcriptTokens.has(token)).length < 2) {
    throw new Error("summary generation returned unsupported content");
  }
  if (redactContent(text) !== text) {
    throw new Error("summary generation returned sensitive content");
  }
}

function optionalIso(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${field} must be an ISO-8601 timestamp`);
  }
  return new Date(value).toISOString();
}

function parseInput(value: unknown): AgentSessionCompleteInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("agent session input must be an object");
  }
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_INPUT_KEYS.has(key)) {
      throw new Error(`agent session identity field is not accepted: ${key}`);
    }
  }
  if (typeof raw.sessionId !== "string" || raw.sessionId.length === 0 || raw.sessionId.length > 256) {
    throw new Error("sessionId must be a non-empty string");
  }
  if (!Array.isArray(raw.turns) || raw.turns.length === 0 || raw.turns.length > MAX_TURNS) {
    throw new Error(`turns must contain 1-${MAX_TURNS} entries`);
  }
  let total = 0;
  const turns = raw.turns.map((entry, index): AgentSessionTurn => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`turns[${index}] must be an object`);
    }
    const turn = entry as Record<string, unknown>;
    if (Object.keys(turn).some((key) => key !== "role" && key !== "content")) {
      throw new Error(`turns[${index}] contains an unsupported field`);
    }
    if (turn.role !== "user" && turn.role !== "assistant") {
      throw new Error(`turns[${index}].role must be user or assistant`);
    }
    if (typeof turn.content !== "string" || turn.content.length === 0 || turn.content.length > MAX_TURN_CHARS) {
      throw new Error(`turns[${index}].content is invalid`);
    }
    total += turn.content.length;
    return { role: turn.role, content: turn.content };
  });
  if (total > MAX_SESSION_CHARS) throw new Error("agent session exceeds the capture limit");
  const startedAt = optionalIso(raw.startedAt, "startedAt");
  const endedAt = optionalIso(raw.endedAt, "endedAt");
  return {
    sessionId: raw.sessionId,
    turns,
    ...(startedAt ? { startedAt } : {}),
    ...(endedAt ? { endedAt } : {}),
  };
}

function validateSummary(value: AgentSessionSummary): AgentSessionSummary {
  if (!value || typeof value.summary !== "string" || value.summary.trim().length === 0) {
    throw new Error("summary generation returned no summary");
  }
  if (value.summary.length > 8_000 || !Array.isArray(value.claims) || value.claims.length > 64) {
    throw new Error("summary generation exceeded its output bounds");
  }
  const claims = value.claims.map((claim) => {
    if (!claim || typeof claim.content !== "string" || claim.content.trim().length === 0 ||
      claim.content.length > 4_000 || (claim.role !== "user" && claim.role !== "assistant")) {
      throw new Error("summary generation returned an invalid claim");
    }
    return { content: claim.content.trim(), role: claim.role };
  });
  return { summary: value.summary.trim(), claims };
}

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(String(value)).toISOString();
}

export class AgentSessionSummaryService {
  constructor(private readonly deps: AgentSessionSummaryDeps) {}

  private async view(id: string): Promise<AgentSessionSummaryView> {
    const [rowResult, memoryResult] = await Promise.all([
      this.deps.db.query(`SELECT * FROM agent_session_summaries WHERE id = $1`, [id]),
      this.deps.db.query(
        `SELECT memory_id FROM agent_session_summary_memories WHERE summary_id = $1 ORDER BY memory_id`,
        [id],
      ),
    ]);
    const row = rowResult.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new Error("agent session summary disappeared");
    return {
      id: String(row.id),
      namespace: String(row.namespace),
      status: row.status === "completed" ? "completed" : "failed",
      memoryIds: memoryResult.rows.map((entry) => String(entry.memory_id) as MemoryId),
      factCount: Number(row.fact_count ?? 0),
      startedAt: row.started_at == null ? null : iso(row.started_at),
      endedAt: row.ended_at == null ? null : iso(row.ended_at),
      createdAt: iso(row.created_at),
      completedAt: row.completed_at == null ? null : iso(row.completed_at),
      failureCode: row.failure_code == null ? null : String(row.failure_code),
    };
  }

  async complete(identity: Identity, value: unknown): Promise<AgentSessionSummaryView> {
    if (identity.role !== "agent") throw new Error("agent identity is required for session capture");
    const input = parseInput(value);
    const sessionHash = sha256(`${identity.keyId}\0${input.sessionId}`);
    const id = ulid();
    const createdAt = new Date().toISOString();
    const inputDigest = sha256(JSON.stringify(input.turns));
    const reserved = await this.deps.db.query(
      `INSERT INTO agent_session_summaries
         (id, namespace, key_id, actor, session_hash, input_digest, status,
          fact_count, started_at, ended_at, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,'processing',0,$7,$8,$9)
       ON CONFLICT (key_id,session_hash) DO NOTHING RETURNING id`,
      [id, identity.namespace, identity.keyId, identity.actor, sessionHash, inputDigest,
        input.startedAt ?? null, input.endedAt ?? null, createdAt],
    );
    if (!reserved.rows[0]) {
      for (let attempt = 0; attempt < 200; attempt += 1) {
        const existing = await this.deps.db.query(
          `SELECT id,status,created_at FROM agent_session_summaries
            WHERE key_id = $1 AND session_hash = $2`,
          [identity.keyId, sessionHash],
        );
        const row = existing.rows[0] as Record<string, unknown> | undefined;
        if (!row) break;
        if (row.status !== "processing") return this.view(String(row.id));
        if (Date.now() - new Date(String(row.created_at)).getTime() > 5 * 60_000) {
          await this.deps.db.query(
            `UPDATE agent_session_summaries SET status='failed',failure_code='processing_stale',
                completed_at=$2 WHERE id=$1 AND status='processing'`,
            [row.id, new Date().toISOString()],
          );
          return this.view(String(row.id));
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      throw new Error("agent session capture is already processing");
    }

    try {
      const redactedTurns = input.turns.map((turn) => ({ ...turn, content: redactContent(turn.content) }));
      const generated = validateSummary(await this.deps.summarize(redactedTurns, identity));
      const transcriptTokens = supportTokens(redactedTurns.map((turn) => turn.content).join("\n"));
      assertSupported(generated.summary, transcriptTokens);
      for (const claim of generated.claims) assertSupported(claim.content, transcriptTokens);
      const sourceId = `agent-chat:${identity.keyId}`;
      const content = [generated.summary, ...generated.claims.map((claim) => claim.content)].join("\n");
      const memoryIds: MemoryId[] = [];
      let factCount = 0;
      const request: WriteRequest = {
        namespace: identity.namespace,
        actor: identity.actor,
        scope: "team",
        content,
        session: sessionHash,
        hints: { type: "fact", summaryOnly: true },
        provenance: {
          source: "conversation",
          sourceId,
          documentKey: sessionHash,
          contentHash: sha256(content),
        },
      };
      const result = await this.deps.write(request, identity);
      factCount += result.stored.length;
      for (const stored of result.stored) memoryIds.push(stored.id);
      if (memoryIds.length === 0) throw new Error("summary write stored no verified facts");
      const completedAt = new Date().toISOString();
      await this.deps.db.transaction(async (tx) => {
        await tx.query(
          `UPDATE agent_session_summaries
              SET status = 'completed', summary_memory_id = $2, fact_count = $3,
                  completed_at = $4, failure_code = NULL
            WHERE id = $1`,
          [id, memoryIds[0] ?? null, factCount, completedAt],
        );
        for (const memoryId of memoryIds) {
          await tx.query(
            `INSERT INTO agent_session_summary_memories (summary_id, memory_id)
             VALUES ($1,$2) ON CONFLICT DO NOTHING`,
            [id, memoryId],
          );
        }
      });
      await this.deps.audit.append({
        ts: completedAt,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "session_capture",
        memoryId: memoryIds[0] ?? null,
        namespace: identity.namespace,
        purpose: "agent-session-summary",
        result: "ok",
        detail: `summary_id=${id} facts=${factCount}`,
      });
    } catch {
      const completedAt = new Date().toISOString();
      await this.deps.db.query(
        `UPDATE agent_session_summaries
            SET status = 'failed', failure_code = 'summary_or_write_failed', completed_at = $2
          WHERE id = $1`,
        [id, completedAt],
      );
      await this.deps.audit.append({
        ts: completedAt,
        actor: identity.actor,
        agentId: identity.keyId,
        op: "session_capture",
        memoryId: null,
        namespace: identity.namespace,
        purpose: "agent-session-summary",
        result: "error",
        detail: `summary_id=${id} code=summary_or_write_failed`,
      });
    }
    return this.view(id);
  }
}
