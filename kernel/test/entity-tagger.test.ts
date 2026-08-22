/**
 * Subject derivation and the subject-sliced scan
 * (CONTRACTS-CONFLICT-AUTOPILOT CA7-CA9).
 *
 * The properties under test are the two that made the batch scan miss real
 * conflicts: a fact with no subject joined no group, and the collection window
 * was contiguous in write time so distant facts never met. Both only exist at
 * the database boundary, so this runs against a real in-memory PGlite kernel.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import { EntityTagger } from "../src/entity-tagger/index.js";
import {
  factSubjects,
  isUsableSubject,
  usableSubjects,
} from "../src/entity-tagger/subjects.js";
import { enqueueEntityTag } from "../src/conflict-autopilot/queue.js";
import { MemoryIndex } from "../src/index/index.js";
import type { Identity, MemoryObject, ProvenanceEntry } from "../src/types.js";

const ACME = "acme";

describe("subject vocabulary (CA8)", () => {
  it("rejects the function words and dates that polluted live subjects", () => {
    // Every one of these was observed as a stored subject on 2026-08-09.
    for (const junk of ["The", "Per", "For", "March", "June", "CMP", "MET"]) {
      expect(isUsableSubject(junk)).toBe(false);
    }
  });

  it("keeps real organizational subjects", () => {
    for (const subject of ["Halofy", "Refund", "Enterprise", "Acme Corporation"]) {
      expect(isUsableSubject(subject)).toBe(true);
    }
  });

  it("de-duplicates case-insensitively and bounds the list", () => {
    expect(usableSubjects(["Halofy", "halofy", "HALOFY", "Enterprise"]))
      .toEqual(["Halofy", "Enterprise"]);
    expect(usableSubjects(Array.from({ length: 40 }, (_, i) => `Subject${i}`)))
      .toHaveLength(8);
  });

  it("unions the annotation with the derived column, filtering both", () => {
    const subjects = factSubjects(
      "Refund rules changed. [entities: Halofy, The, MET]",
      ["Enterprise", "Per"],
    );
    expect(subjects).toContain("Halofy");
    expect(subjects).toContain("Enterprise");
    expect(subjects).not.toContain("The");
    expect(subjects).not.toContain("Per");
    expect(subjects).not.toContain("MET");
  });
});

let kernel: Kernel;
let knowledgeDir: string;
let owner: Identity;

async function seedFact(input: {
  namespace?: string;
  content: string;
  source?: ProvenanceEntry["source"];
  embedding?: number[];
}): Promise<string> {
  const id = ulid();
  const now = new Date().toISOString();
  const fact: MemoryObject = {
    id,
    namespace: input.namespace ?? ACME,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: input.content,
    type: "fact",
    confidence: 1,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: input.source ?? "conversation", actor: "agent:test", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  const vector = new Array<number>(256).fill(0);
  vector[0] = 1;
  await new MemoryIndex(kernel.db).insert(fact, input.embedding ?? vector);
  await enqueueEntityTag(kernel.db, id, fact.namespace, now);
  return id;
}

async function subjectsOf(id: string): Promise<string[] | null> {
  const result = await kernel.db.query(
    `SELECT derived_entities FROM memory_objects WHERE id = $1`,
    [id],
  );
  const raw = (result.rows[0] as Record<string, unknown> | undefined)?.derived_entities;
  if (raw == null) return null;
  return typeof raw === "string" ? JSON.parse(raw) as string[] : raw as string[];
}

async function reset(): Promise<void> {
  await kernel.db.query(`DELETE FROM conflict_scan_findings`);
  await kernel.db.query(`DELETE FROM conflict_detection_queue`);
  await kernel.db.query(`DELETE FROM entity_tag_queue`);
  await kernel.db.query(`DELETE FROM memory_objects`);
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-entity-tagger-"));
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir,
    anthropicApiKey: "",
    openaiApiKey: "",
    embedDim: 256,
  });
  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root owner did not resolve");
  const acmeKey = await kernel.auth.issueKey(ACME, "owner:acme", "owner", root);
  const resolved = await kernel.auth.resolve(acmeKey.plaintext);
  if (!resolved) throw new Error("acme owner did not resolve");
  owner = resolved;
});

beforeEach(reset);

afterAll(async () => {
  await kernel.close();
  await rm(knowledgeDir, { recursive: true, force: true });
});

describe("entity tagger (CA8)", () => {
  it("gives an untagged agent-chat fact a subject without touching its content", async () => {
    const content = "Halofy Enterprise onboarding takes 45 days.";
    const id = await seedFact({ content });

    const run = await new EntityTagger(kernel.db, kernel.audit, 0).runOnce();
    expect(run).toMatchObject({ claimed: 1, tagged: 1 });
    expect(await subjectsOf(id)).toContain("Halofy");

    // D7: the stored bytes are untouched — subjects live in their own column.
    const row = await kernel.db.query(`SELECT content FROM memory_objects WHERE id = $1`, [id]);
    expect(String((row.rows[0] as Record<string, unknown>).content)).toBe(content);
  });

  it("mirrors an existing annotation into the column so one column can group everything", async () => {
    const id = await seedFact({
      content: "The refund window is 30 days. [entities: Refund Policy]",
    });
    await new EntityTagger(kernel.db, kernel.audit, 0).runOnce();
    expect(await subjectsOf(id)).toContain("Refund Policy");
  });

  it("never stores the junk subjects that polluted the live corpus", async () => {
    const id = await seedFact({ content: "The contract renews on March 1, 2027." });
    await new EntityTagger(kernel.db, kernel.audit, 0).runOnce();
    const subjects = await subjectsOf(id) ?? [];
    expect(subjects).not.toContain("The");
    expect(subjects).not.toContain("March");
  });

  it("records prose with no nameable subject instead of retrying it forever", async () => {
    const id = await seedFact({ content: "they want their money back right now" });
    const run = await new EntityTagger(kernel.db, kernel.audit, 0).runOnce();
    expect(run).toMatchObject({ claimed: 1, tagged: 0, empty: 1 });
    // Tagged as "no subject" (empty array), not left NULL — otherwise the
    // backlog gauge would count it as outstanding work forever.
    expect(await subjectsOf(id)).toEqual([]);
    const queue = await kernel.db.query(
      `SELECT status FROM entity_tag_queue WHERE memory_id = $1`, [id],
    );
    expect((queue.rows[0] as Record<string, unknown>).status).toBe("done");
  });

  it("uses the model only for prose the deterministic pass could not read", async () => {
    const deterministic = await seedFact({ content: "Halofy Growth quota is 500 gigabytes." });
    const prose = await seedFact({ content: "they asked for a bigger allowance" });
    const seen: string[] = [];
    const tagger = new EntityTagger(kernel.db, kernel.audit, 0);
    tagger.attach(async ({ content }) => {
      seen.push(content);
      return ["Storage Quota"];
    });

    await tagger.runOnce();
    // Exactly one model call: the fact with a proper noun never reached it.
    expect(seen).toEqual(["they asked for a bigger allowance"]);
    expect(await subjectsOf(deterministic)).toContain("Halofy");
    expect(await subjectsOf(prose)).toEqual(["Storage Quota"]);
  });

  it("filters model output through the same vocabulary as everything else", async () => {
    const id = await seedFact({ content: "they asked about it again" });
    const tagger = new EntityTagger(kernel.db, kernel.audit, 0);
    // Untrusted output: junk and an identifier fragment must not be stored.
    tagger.attach(async () => ["The", "MET", "Billing Policy"]);
    await tagger.runOnce();
    expect(await subjectsOf(id)).toEqual(["Billing Policy"]);
  });

  it("enrols every fact written through the real write path", async () => {
    const written = await kernel.memWrite(
      { scope: "team", content: "Halofy Scale plan rate limit is 2000 requests." },
      owner,
      "agent-test",
    );
    const id = written.stored[0]?.id;
    expect(id).toBeDefined();
    const queue = await kernel.db.query(
      `SELECT status FROM entity_tag_queue WHERE memory_id = $1`, [id],
    );
    expect(queue.rows).toHaveLength(1);
  });
});

describe("extraction stamp (CA9)", () => {
  it("distinguishes a requested verbatim write from a degraded fallback", async () => {
    const requested = await kernel.memWrite(
      { scope: "team", content: "Halofy Pro seats cost 49 dollars.", hints: { verbatim: true } },
      owner,
      "agent-test",
    );
    const stamp = requested.stored[0]?.provenance[0]?.extraction;
    // Asked for verbatim, got verbatim: nothing to resync later.
    expect(stamp).toBe("verbatim");
  });

  it("stamps a model-extracted write as extracted", async () => {
    const written = await kernel.memWrite(
      { scope: "team", content: "Halofy Pro seats cost 59 dollars." },
      owner,
      "agent-test",
    );
    // The stub LLM extracts, so this is the extracted lane, not a fallback.
    expect(written.stored[0]?.provenance[0]?.extraction).toBe("llm");
  });
});

describe("subject-sliced scan collection (CA7)", () => {
  it("compares two facts about one subject however far apart they were written", async () => {
    // The old window was contiguous in id (write) order. Plant the two related
    // facts at opposite ends of a large corpus: under the old slicing they
    // could never share a scan.
    const first = await seedFact({ content: "Halofy Enterprise onboarding takes 45 days." });
    // Each filler carries its OWN subject, so nothing else shares a group.
    for (let index = 0; index < 30; index += 1) {
      await seedFact({ content: `Widget${index} shipping note number ${index}.` });
    }
    const last = await seedFact({ content: "Halofy Enterprise onboarding takes 10 days." });
    await new EntityTagger(kernel.db, kernel.audit, 0).runOnce({ limit: 200 });

    const halofy = await kernel.db.query(
      `SELECT COUNT(*)::int AS n
         FROM memory_objects m, LATERAL jsonb_array_elements_text(m.derived_entities) AS s(subject)
        WHERE m.namespace = $1 AND s.subject = 'Halofy'`,
      [ACME],
    );
    // Both ends of the corpus share the subject, so one subject-sliced group
    // contains them both — which is exactly what the old age window prevented.
    expect(Number((halofy.rows[0] as Record<string, unknown>).n)).toBe(2);

    const grouped = await kernel.db.query(
      `SELECT id FROM memory_objects WHERE derived_entities ?| $1::text[] ORDER BY id`,
      [["Halofy"]],
    );
    const ids = grouped.rows.map((row) => String((row as Record<string, unknown>).id));
    expect(ids).toContain(first);
    expect(ids).toContain(last);
  });

  it("checks untagged facts through the scope-local fallback", async () => {
    await seedFact({ content: "Halofy Enterprise onboarding takes 45 days." });
    // Deliberately NOT tagged: the tagger has not run.
    const untagged = await kernel.db.query(
      `SELECT COUNT(*)::int AS count FROM memory_objects WHERE derived_entities IS NULL`,
    );
    expect(Number((untagged.rows[0] as Record<string, unknown>).count)).toBe(1);

    const run = await kernel.requestConflictScan(owner, {
      include: ["knowledge-base", "agent-summary", "policy-manual"],
    });
    await kernel.runConflictScanJobsOnce();
    const finished = await kernel.getConflictScan(run.id, owner);
    expect(finished?.status).toBe("completed");
    expect(finished?.progress.itemsScanned).toBe(1);
    expect(finished?.summary?.coverageGaps).not.toContain("entity_metadata_unavailable");
  });
});
