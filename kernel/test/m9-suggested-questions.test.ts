/**
 * M9 #13 (E47) — derived suggested questions.
 *
 * The chips must be DERIVED per the caller's namespace under the ancestor-prefix
 * ACL (exact IN-list, no LIKE), from answered queries + knowledge headings, and
 * the handler must never write. Hermetic: in-memory PGlite, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { MemoryIndex } from "../src/index/index.js";
import { suggestedQuestions } from "../src/console/suggested-questions.js";
import type { Identity } from "../src/types.js";

const DIM = 8;
let db: Db;
let index: MemoryIndex;

function kernelSlice(): { db: Db; index: MemoryIndex } {
  return { db, index };
}

const ident = (namespace: string, role: string): Identity =>
  ({ namespace, actor: "alice", role, keyId: "k1" } as unknown as Identity);

async function audit(
  namespace: string,
  purpose: string,
  result: string,
  times: number,
): Promise<void> {
  for (let i = 0; i < times; i++) {
    await db.query(
      `INSERT INTO audit_log (ts, actor, agent_id, op, namespace, purpose, result)
       VALUES (now(), 'alice', 'a1', 'search', $1, $2, $3)`,
      [namespace, purpose, result],
    );
  }
}

let memSeq = 0;
async function fact(
  namespace: string,
  content: string,
  accessCount: number,
  over: { classification?: Record<string, unknown>; sourceAccess?: Record<string, unknown> } = {},
): Promise<void> {
  const classification = over.classification ?? {
    sensitivity: "internal", piiSubjects: [], secretKinds: [], allowedDestinations: [],
  };
  const sourceAccess = over.sourceAccess ?? { principals: [], groups: [] };
  await db.query(
    `INSERT INTO memory_objects (id, namespace, scope, tier, backend_ref, content, type,
       confidence, assertion_time, t_valid_from, access_count, classification, source_access)
     VALUES ($1, $2, 'team', 'L2', 'ref', $3, 'fact', 0.9, now(), now(), $4, $5, $6)`,
    [
      `m-sq-${++memSeq}`, namespace, content, accessCount,
      JSON.stringify(classification), JSON.stringify(sourceAccess),
    ],
  );
}

beforeAll(async () => {
  db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
  await migrate(db, DIM);
  index = new MemoryIndex(db);

  await audit("acme/support", "what is our refund window", "ok", 5);
  await audit("acme/support", "who owns billing escalations?", "ok", 3);
  await audit("acme/support", "a query that always misses", "miss", 9);
  await audit("acme", "org holiday policy", "ok", 4);
  // Sibling and descendant traffic: neither is visible to acme/support.
  await audit("acme/sales", "SIBLINGSECRET pipeline forecast", "ok", 20);
  await audit("acme/support/triage", "DESCENDANTONLY triage backlog", "ok", 11);

  await fact(
    "acme/support",
    "The escalation SLA for enterprise tickets is four hours. It resets nightly.",
    40,
  );
  await fact("acme", "Company-wide security training happens every March", 30);
  await fact("acme/sales", "SIBLINGSECRET the Q4 pipeline target is 12 million dollars", 99);
  // Rows the canonical read fence must hide even INSIDE the caller's ancestry:
  // a confidential fact with no cleared destination, and a source-ACL'd fact
  // whose principals exclude the caller.
  await fact(
    "acme/support",
    "CONFIDENTIALSECRET acquisition of TargetCo closes March third",
    500,
    { classification: {
      sensitivity: "confidential", piiSubjects: [], secretKinds: [], allowedDestinations: [],
    } },
  );
  await fact(
    "acme/support",
    "SOURCEACLSECRET compensation bands for the leadership team",
    400,
    { sourceAccess: { principals: ["hr-lead"], groups: [] } },
  );
});

afterAll(async () => {
  await db.close();
});

describe("E47 derived suggested questions", () => {
  /**
   * An audit `purpose` is whatever the agent sent, so an import lands there
   * verbatim. Capitalising it and appending "?" put these on the deployed
   * console — four of six chips were unusable:
   *   "Sales.csv sales sales?"
   *   "Marketing.csv marketing Marketing?"
   *   "05-customers-and-deals.md 05 customers and deals test?"
   */
  it("rejects filename and keyword-bag purposes instead of appending a question mark", async () => {
    const junkNamespace = "acme/junk";
    await audit(junkNamespace, "Sales.csv sales sales", "ok", 90);
    await audit(junkNamespace, "Marketing.csv marketing Marketing", "ok", 80);
    await audit(junkNamespace, "05-customers-and-deals.md 05 customers and deals test", "ok", 70);
    await audit(junkNamespace, "11-team-preferences-and-norms.md 11 team preferences", "ok", 60);
    // A real noun-phrase query from the same namespace must still survive:
    // requiring a verb or wh-word would throw this away too.
    await audit(junkNamespace, "refund SLA priority tickets", "ok", 50);

    const res = await suggestedQuestions(kernelSlice(), ident(junkNamespace, "admin"));
    const blob = JSON.stringify(res);
    expect(blob).not.toContain(".csv");
    expect(blob).not.toContain(".md");
    expect(blob).not.toContain("sales sales");
    expect(blob).not.toContain("marketing Marketing");
    expect(res.questions.map((q) => q.text)).toContain("Refund SLA priority tickets?");
    expect(res.questions.length).toBeLessThanOrEqual(4);
  });

  it("rejects internal trace purposes instead of exposing them as questions", async () => {
    const traceNamespace = "acme/internal-trace";
    await audit(traceNamespace, "assistant-turn:01KZ9KCD40B0MQRNRZWK081HHJ", "ok", 100);
    await audit(traceNamespace, "what changed in customer operations", "ok", 1);

    const res = await suggestedQuestions(kernelSlice(), ident(traceNamespace, "admin"));
    const texts = res.questions.map((question) => question.text);
    expect(texts).not.toContain("Assistant-turn:01KZ9KCD40B0MQRNRZWK081HHJ?");
    expect(texts).toContain("What changed in customer operations?");
  });

  it("derives from answered queries and knowledge headings, not a hardcoded list", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("acme/support", "admin"));
    expect(res.namespace).toBe("acme/support");
    expect(res.derivedFrom.answeredQueries).toBeGreaterThan(0);
    expect(res.derivedFrom.knowledgeHeadings).toBeGreaterThan(0);

    const texts = res.questions.map((q) => q.text);
    expect(texts).toContain("What is our refund window?");
    expect(texts).toContain("Who owns billing escalations?");
    expect(texts.some((t) => t.includes("escalation SLA for enterprise tickets"))).toBe(true);
    // Every chip is a question, and short enough to fit the chip row.
    for (const t of texts) {
      expect(t.endsWith("?")).toBe(true);
      expect(t.length).toBeLessThanOrEqual(72);
    }
  });

  it("ranks the most-repeated answered query first and never suggests a miss", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("acme/support", "admin"));
    expect(res.questions[0]!.text).toBe("What is our refund window?");
    expect(res.questions[0]!.source).toBe("answered-query");
    expect(res.questions.some((q) => /always misses/i.test(q.text))).toBe(false);
  });

  it("reads DOWN the ancestor chain but never a sibling or a descendant", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("acme/support", "admin"));
    const blob = JSON.stringify(res);
    expect(blob).toContain("holiday policy"); // ancestor `acme` - visible
    expect(blob).not.toContain("SIBLINGSECRET"); // sibling `acme/sales`
    expect(blob).not.toContain("DESCENDANTONLY"); // child `acme/support/triage`
  });

  it("gives a root owner the org-wide view", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("", "owner"));
    expect(JSON.stringify(res)).toContain("SIBLINGSECRET");
  });

  it("falls back to seeds for a namespace with no traffic and no facts", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("brand/new", "admin"));
    expect(res.questions.length).toBeGreaterThan(0);
    expect(res.questions.every((q) => q.source === "seed")).toBe(true);
    expect(res.derivedFrom).toEqual({ answeredQueries: 0, knowledgeHeadings: 0 });
  });

  it("is a pure read path - it writes nothing", async () => {
    const before = await db.query(
      `SELECT (SELECT count(*) FROM audit_log) AS a,
              (SELECT count(*) FROM memory_objects) AS m`,
    );
    await suggestedQuestions(kernelSlice(), ident("acme/support", "admin"));
    const after = await db.query(
      `SELECT (SELECT count(*) FROM audit_log) AS a,
              (SELECT count(*) FROM memory_objects) AS m`,
    );
    expect(after.rows[0]).toEqual(before.rows[0]);
  });

  it("never leaks confidential or source-ACL'd fact content into chips", async () => {
    // The two hidden rows carry the HIGHEST access counts in the namespace,
    // so a raw access_count-ranked query would surface them first — the
    // canonical MemoryIndex fence must exclude them for every role.
    for (const role of ["agent", "member", "admin", "owner"]) {
      const res = await suggestedQuestions(kernelSlice(), ident("acme/support", role));
      const blob = JSON.stringify(res);
      expect(blob).not.toContain("CONFIDENTIALSECRET");
      expect(blob).not.toContain("SOURCEACLSECRET");
    }
  });

  it("deduplicates and caps the chip row", async () => {
    const res = await suggestedQuestions(kernelSlice(), ident("", "owner"));
    expect(res.questions.length).toBeLessThanOrEqual(6);
    const keys = res.questions.map((q) => q.text.toLowerCase());
    expect(new Set(keys).size).toBe(keys.length);
  });
});
