#!/usr/bin/env node
/**
 * Ingest a Mnemos benchmark JSONL (LoCoMo/LongMemEval/ConvoMem row shape) into
 * a kernel namespace through the real write path, then replay the benchmark
 * questions through mem_search and score retrieval.
 *
 * Usage:
 *   HALOMEM_BENCH_KEY=hm_... node scripts/bench-retrieval.mjs ingest <file.jsonl> [--base http://localhost:8787]
 *   HALOMEM_BENCH_KEY=hm_... node scripts/bench-retrieval.mjs eval   <file.jsonl> [--base ...] [--k 8]
 *
 * Writes go through POST /v1/mem/write with hints.verbatim (no LLM extraction
 * cost); the namespace comes from the key, never the body (D9). Each turn is
 * stored as `[<conversation> <dia_id>] (<session date>) <speaker>: <text>` so
 * eval can check evidence-turn recall by tag.
 */

import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

const [, , mode, file, ...rest] = process.argv;
if (!["ingest", "eval"].includes(mode) || !file) {
  console.error("usage: bench-retrieval.mjs <ingest|eval> <file.jsonl> [--base URL] [--k N]");
  process.exit(1);
}
const opt = (name, dflt) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 && rest[i + 1] ? rest[i + 1] : dflt;
};
const BASE = opt("base", "http://localhost:8787");
const K = Number(opt("k", "8"));
const KEY = process.env.HALOMEM_BENCH_KEY;
if (!KEY) {
  console.error("HALOMEM_BENCH_KEY is required");
  process.exit(1);
}

async function post(path, body) {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(BASE + path, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${KEY}` },
      body: JSON.stringify(body),
    });
    if (res.ok) return res.json();
    const text = await res.text();
    if (res.status === 429) {
      // Per-key rate limit window is a minute; wait it out instead of failing.
      await new Promise((r) => setTimeout(r, 10_000));
      continue;
    }
    if (attempt >= 3) throw new Error(`${path} -> ${res.status}: ${text.slice(0, 300)}`);
    await new Promise((r) => setTimeout(r, 500 * attempt));
  }
}

async function* rows(path) {
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.trim()) yield JSON.parse(line);
  }
}

const turnTag = (cid, diaId) => `[${cid} ${diaId}]`;

if (mode === "ingest") {
  // Multiple question rows share one conversation; ingest each conversation once.
  const seen = new Set();
  let written = 0;
  let skipped = 0;
  for await (const row of rows(file)) {
    const cid = row.conversation_id;
    if (seen.has(cid)) continue;
    seen.add(cid);
    for (const session of row.sessions ?? []) {
      const sessionKey = `${cid}:${session.id}`;
      for (const turn of session.turns ?? []) {
        const text = (turn.text ?? "").trim();
        if (!text) {
          skipped++;
          continue;
        }
        const content = `${turnTag(cid, turn.dia_id)} (${session.date}) ${turn.speaker}: ${text}`;
        await post("/v1/mem/write", {
          scope: "team",
          content,
          session: sessionKey,
          hints: { verbatim: true },
        });
        written++;
        if (written % 100 === 0) console.log(`  ${written} turns written...`);
      }
    }
    console.log(`conversation ${cid} done (${written} turns so far)`);
  }
  console.log(`INGEST COMPLETE: ${written} turns written, ${skipped} empty turns skipped, ${seen.size} conversations`);
} else {
  let asked = 0;
  let answerHit = 0;
  let evidenceAny = 0;
  let evidenceTotal = 0;
  let evidenceFound = 0;
  let unanswerable = 0;
  const byCategory = new Map();
  for await (const row of rows(file)) {
    if (row.unanswerable) {
      unanswerable++;
      continue;
    }
    const body = await post("/v1/mem/search", { query: row.question, k: K });
    const hits = Array.isArray(body) ? body : (body.results ?? body.hits ?? []);
    const corpus = hits.map((h) => h.content ?? "").join("\n").toLowerCase();
    asked++;

    const answer = String(row.answer ?? "").trim().toLowerCase();
    const aHit = answer.length > 0 && corpus.includes(answer);
    if (aHit) answerHit++;

    const evidence = row.evidence ?? [];
    let found = 0;
    for (const diaId of evidence) {
      if (corpus.includes(turnTag(row.conversation_id, diaId).toLowerCase())) found++;
    }
    evidenceTotal += evidence.length;
    evidenceFound += found;
    if (evidence.length > 0 && found > 0) evidenceAny++;

    const cat = row.category ?? "unknown";
    const c = byCategory.get(cat) ?? { asked: 0, answerHit: 0, evidenceAny: 0 };
    c.asked++;
    if (aHit) c.answerHit++;
    if (evidence.length > 0 && found > 0) c.evidenceAny++;
    byCategory.set(cat, c);

    if (asked % 100 === 0) console.log(`  ${asked} questions evaluated...`);
  }
  console.log(`\nEVAL COMPLETE (k=${K}) — ${asked} questions (${unanswerable} unanswerable skipped)`);
  console.log(`  answer-substring hit@${K}:  ${answerHit}/${asked} (${((100 * answerHit) / asked).toFixed(1)}%)`);
  console.log(`  >=1 evidence turn in top-${K}: ${evidenceAny}/${asked} (${((100 * evidenceAny) / asked).toFixed(1)}%)`);
  console.log(`  evidence turn recall@${K}:  ${evidenceFound}/${evidenceTotal} (${((100 * evidenceFound) / Math.max(1, evidenceTotal)).toFixed(1)}%)`);
  console.log(`  by category:`);
  for (const [cat, c] of [...byCategory.entries()].sort()) {
    console.log(
      `    ${cat.padEnd(16)} asked=${String(c.asked).padStart(3)}  answerHit=${((100 * c.answerHit) / c.asked).toFixed(1)}%  evidenceAny=${((100 * c.evidenceAny) / c.asked).toFixed(1)}%`,
    );
  }
}
