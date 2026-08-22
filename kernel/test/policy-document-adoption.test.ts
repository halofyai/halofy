/**
 * Adoption — the register catching up with memory.
 *
 * The policy library only ever knew about files uploaded through its own lane,
 * so a policy file that arrived through another governed lane (a connector, an
 * import, a company-file upload — all D10, all the same write path) was
 * invisible on S4 while agents could already read its facts. These tests use a
 * company-file upload as that other lane: it lands facts with `sourceId` and
 * `documentKey` provenance and writes no `policy_documents` row, which is
 * exactly the shape of a CSV import.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { loadPolicyDirectives } from "../src/policy/directives.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let acmeOwner: Identity;
let acmeAuditor: Identity;
let acmeAgent: Identity;
let knowledgeBaseId: string;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const resolved = await kernel.auth.resolve(issued.plaintext);
  if (!resolved) throw new Error(`identity resolution failed for ${actor}`);
  return resolved;
}

/** Land a file through the NON-register lane and return its source id. */
async function landFile(fileName: string, content: string): Promise<string> {
  const file = await kernel.uploadCompanyFile({
    knowledgeBaseId,
    fileName,
    content,
    title: fileName,
    description: "Imported reference",
    purpose: "Support agents",
  }, acmeOwner);
  return file.sourceId;
}

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-policy-adopt-"));
  kernel = await Kernel.boot({ databaseUrl: "", pgliteDataDir: "", knowledgeDir });

  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root identity resolution failed");
  root = resolvedRoot;
  acmeOwner = await issue("acme", "owner:acme", "owner", root);
  acmeAuditor = await issue("acme", "auditor:acme", "auditor", root);
  acmeAgent = await issue("acme/agent-1", "agent:acme", "agent", acmeOwner);
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\n");

  const base = await kernel.createKnowledgeBase({
    name: "Operating references",
    kind: "file",
    targetTeamId: null,
    primaryBusinessFunction: "Operations",
    description: "Imported company references",
    dataSensitive: false,
  }, acmeOwner);
  knowledgeBaseId = base.id;
}, 120_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("policy files already in memory", () => {
  it("reports a policy file that memory has but the register does not", async () => {
    await landFile(
      "returns-policy.md",
      "Refunds above 200 need owner approval before confirmation.",
    );
    await landFile(
      "quarterly-orders.md",
      "Order ORD-0044 shipped to Seattle on the fourth of June.",
    );

    const candidates = await kernel.listPolicyAdoptionCandidates(
      { namespace: "acme" },
      acmeOwner,
    );
    const files = candidates.data.map((candidate) => candidate.fileName);
    expect(files).toContain("returns-policy.md");
    // An ordinary business import is not policy material and must not be
    // offered as a guardrail.
    expect(files).not.toContain("quarterly-orders.md");

    const candidate = candidates.data.find((row) => row.fileName === "returns-policy.md");
    expect(candidate).toMatchObject({ namespace: "acme", signal: expect.any(String) });
    expect(candidate!.factCount).toBeGreaterThan(0);
    expect(candidate!.documentCount).toBeGreaterThan(0);
  });

  it("keeps the candidate lane inside the caller's subtree and role", async () => {
    // An auditor may look; a member-shaped agent may not.
    await expect(
      kernel.listPolicyAdoptionCandidates({ namespace: "acme" }, acmeAuditor),
    ).resolves.toBeTruthy();
    await expect(
      kernel.listPolicyAdoptionCandidates({ namespace: "acme" }, acmeAgent),
    ).rejects.toThrow(/may not list/);
    await expect(
      kernel.listPolicyAdoptionCandidates({ namespace: "other" }, acmeOwner),
    ).rejects.toThrow(/outside your namespace subtree/);
  });

  it("adopts a file without re-importing it, then hands it to agents as a guardrail", async () => {
    const before = await kernel.db.query(
      `SELECT id, assertion_time FROM memory_objects
        WHERE namespace = 'acme' AND status = 'active'
        ORDER BY id`,
    );

    const adopted = await kernel.adoptPolicyDocument({
      namespace: "acme",
      fileName: "returns-policy.md",
      sourceId: (await kernel.listPolicyAdoptionCandidates({ namespace: "acme" }, acmeOwner))
        .data.find((row) => row.fileName === "returns-policy.md")!.sourceId,
      title: "Customer returns policy",
    }, acmeOwner);

    expect(adopted).toMatchObject({
      namespace: "acme",
      title: "Customer returns policy",
      status: "active",
      origin: "adopted",
      kind: "policy",
      enforcement: "required",
      fileName: "returns-policy.md",
    });
    expect(adopted.factCount).toBeGreaterThan(0);

    // Nothing was re-ingested: the same facts, unchanged, still in place.
    const after = await kernel.db.query(
      `SELECT id, assertion_time FROM memory_objects
        WHERE namespace = 'acme' AND status = 'active'
        ORDER BY id`,
    );
    expect(after.rows).toEqual(before.rows);

    // It is now a register row, so it shows on S4 …
    const listed = await kernel.listPolicyDocuments({ namespace: "acme" }, acmeOwner);
    expect(listed.data.map((row) => row.fileName)).toContain("returns-policy.md");
    expect(listed.summary.active).toBeGreaterThan(0);

    // … and it ships as a guardrail, carrying only ITS file's facts even
    // though the source may hold other imported documents.
    const directives = await loadPolicyDirectives(kernel.db, "acme");
    expect(directives.required).toBe(true);
    expect(directives.documents.map((doc) => doc.title)).toContain(
      "Customer returns policy",
    );
    expect(directives.blocks.length).toBe(adopted.factCount);
    for (const block of directives.blocks) {
      expect(block.content).not.toContain("ORD-0044");
    }
  });

  it("refuses to adopt the same file twice, or a file with no active facts", async () => {
    const sourceId = (
      await kernel.listPolicyDocuments({ namespace: "acme" }, acmeOwner)
    ).data.find((row) => row.fileName === "returns-policy.md")!.sourceId;

    await expect(
      kernel.adoptPolicyDocument(
        { namespace: "acme", fileName: "returns-policy.md", sourceId },
        acmeOwner,
      ),
    ).rejects.toThrow(/already in the register/);

    await expect(
      kernel.adoptPolicyDocument(
        { namespace: "acme", fileName: "not-a-file.md", sourceId },
        acmeOwner,
      ),
    ).rejects.toThrow(/no active facts/);

    // Adoption is a mutation: read-only roles are denied.
    await expect(
      kernel.adoptPolicyDocument(
        { namespace: "acme", fileName: "returns-policy.md", sourceId },
        acmeAuditor,
      ),
    ).rejects.toThrow(/may not adopt/);
  });

  it("retracts exactly the adopted file's facts on delete, leaving history intact", async () => {
    const document = (
      await kernel.listPolicyDocuments({ namespace: "acme" }, acmeOwner)
    ).data.find((row) => row.fileName === "returns-policy.md")!;

    const activeBefore = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects
        WHERE namespace = 'acme' AND status = 'active'`,
    );

    await kernel.deletePolicyDocument(document.id, acmeOwner);

    // The register row is gone …
    const listed = await kernel.listPolicyDocuments({ namespace: "acme" }, acmeOwner);
    expect(listed.data.map((row) => row.fileName)).not.toContain("returns-policy.md");

    // … its facts left ACTIVE memory …
    const activeAfter = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects
        WHERE namespace = 'acme' AND status = 'active'`,
    );
    expect(Number(activeAfter.rows[0]!.n)).toBe(
      Number(activeBefore.rows[0]!.n) - document.factCount,
    );

    // … but were RETRACTED, not deleted (D7): they are archived with a closed
    // validity, which is what the deleted/history view reads.
    const archived = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects
        WHERE namespace = 'acme' AND status = 'archived' AND t_valid_to IS NOT NULL`,
    );
    expect(Number(archived.rows[0]!.n)).toBe(document.factCount);

    // The unrelated import is untouched.
    const orders = await kernel.db.query(
      `SELECT count(*)::int AS n FROM memory_objects
        WHERE namespace = 'acme' AND status = 'active' AND content LIKE '%ORD-0044%'`,
    );
    expect(Number(orders.rows[0]!.n)).toBeGreaterThan(0);

    // The deletion is audited, and the file becomes adoptable again only if it
    // still has active facts — it does not, so it is gone from both lanes.
    const audit = await kernel.db.query(
      `SELECT detail FROM audit_log WHERE op = 'policy_delete' ORDER BY seq DESC LIMIT 1`,
    );
    expect(String(audit.rows[0]!.detail)).toContain("origin=adopted");
    const candidates = await kernel.listPolicyAdoptionCandidates(
      { namespace: "acme" },
      acmeOwner,
    );
    expect(candidates.data.map((row) => row.fileName)).not.toContain(
      "returns-policy.md",
    );
  });
});
