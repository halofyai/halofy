import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { loadPolicyDirectives } from "../src/policy/index.js";
import type { Identity } from "../src/types.js";

/**
 * The guardrail lane: a policy a human loads into the S4 register reaches
 * agents ahead of recall, is acknowledged by digest, and its absence is
 * recorded when an agent acts without reading it.
 */

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let acmeOwner: Identity;
let acmeAuditor: Identity;
let acmeMember: Identity;
let legalAdmin: Identity;
let financeAdmin: Identity;
let legalAgent: Identity;
let financeAgent: Identity;

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

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-policy-guardrails-"));
  kernel = await Kernel.boot({ databaseUrl: "", pgliteDataDir: "", knowledgeDir });

  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const resolvedRoot = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolvedRoot) throw new Error("root identity resolution failed");
  root = resolvedRoot;
  acmeOwner = await issue("acme", "owner:acme", "owner", root);
  acmeAuditor = await issue("acme", "auditor:acme", "auditor", acmeOwner);
  acmeMember = await issue("acme", "member:acme", "member", acmeOwner);
  legalAdmin = await issue("acme/legal", "admin:legal", "admin", acmeOwner);
  financeAdmin = await issue("acme/finance", "admin:finance", "admin", acmeOwner);
  legalAgent = await issue("acme/legal/agent-1", "agent:legal", "agent", acmeOwner);
  financeAgent = await issue("acme/finance/agent-1", "agent:finance", "agent", acmeOwner);
  await kernel.setPolicy("acme", "rateLimitPerMin: 100000\n");

  await kernel.uploadPolicyDocument(
    {
      namespace: "acme",
      title: "Customer data handling",
      kind: "policy",
      fileName: "customer-data.md",
      content: [
        "Never export customer records to a personal device.",
        "Escalate any customer deletion request to the data protection officer.",
        "Retain support transcripts for no more than ninety days.",
      ].join("\n"),
    },
    acmeOwner,
  );
}, 180_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("policy directives", () => {
  it("inherits an ancestor's guardrails and never a sibling's", async () => {
    const legal = await loadPolicyDirectives(kernel.db, "acme/legal/agent-1");
    expect(legal.documents).toHaveLength(1);
    expect(legal.documents[0]?.namespace).toBe("acme");
    expect(legal.documents[0]?.enforcement).toBe("required");
    expect(legal.blocks.length).toBeGreaterThan(0);
    expect(legal.required).toBe(true);

    // A namespace outside the subtree sees nothing of acme's policy.
    const outside = await loadPolicyDirectives(kernel.db, "globex/legal");
    expect(outside.documents).toHaveLength(0);
    expect(outside.digest).toBe("");
  });

  it("orders directives ahead of every other block and reserves budget for them", async () => {
    const working = await kernel.memAssemble({}, legalAgent, "agent-1");
    const kinds = working.blocks.map((block) => block.kind);
    const firstOther = kinds.findIndex((kind) => kind !== "policy-directive");
    expect(kinds[0]).toBe("policy-directive");
    if (firstOther !== -1) {
      expect(kinds.slice(firstOther)).not.toContain("policy-directive");
    }
    expect(working.policy?.required).toBe(true);
    expect(working.policy?.digest).toHaveLength(64);
    expect(working.policy?.documents[0]?.title).toBe("Customer data handling");
  });

  it("serves the same digest through mem_policy and records the delivery", async () => {
    const served = await kernel.memPolicy({}, legalAgent, "agent-1");
    expect(served.digest).toHaveLength(64);
    expect(served.blocks.length).toBeGreaterThan(0);

    const report = await kernel.policyComplianceReport("acme", acmeOwner);
    expect(report.digest).toBe(served.digest);
    const agents = report.documents[0]?.agents ?? [];
    const agent = agents.find((entry) => entry.agentId === legalAgent.keyId);
    expect(agent?.servedCount).toBeGreaterThan(0);
    expect(agent?.current).toBe(true);
  });

  it("accepts an acknowledgement for the current digest and rejects a stale one", async () => {
    const served = await kernel.memPolicy({}, legalAgent, "agent-1");
    const ack = await kernel.memPolicyAck(
      { digest: served.digest, applied: true },
      legalAgent,
      "agent-1",
    );
    expect(ack).toMatchObject({ acknowledged: true, documents: 1 });

    await expect(
      kernel.memPolicyAck({ digest: "0".repeat(64) }, legalAgent, "agent-1"),
    ).rejects.toThrow(/stale/i);

    const report = await kernel.policyComplianceReport("acme", acmeOwner);
    const agent = (report.documents[0]?.agents ?? []).find(
      (entry) => entry.agentId === legalAgent.keyId,
    );
    expect(agent?.appliedCount).toBeGreaterThan(0);
    expect(agent?.state).toBe("acknowledged");
  });

  it("records a bypass when an agent writes without ever reading a required policy", async () => {
    await kernel.memWrite(
      {
        scope: "team",
        content: "Finance closed the Q3 books on 2026-07-01.",
        hints: { verbatim: true },
      },
      financeAgent,
      "agent-2",
    );

    const report = await kernel.policyComplianceReport("acme", acmeOwner);
    const agent = (report.documents[0]?.agents ?? []).find(
      (entry) => entry.agentId === financeAgent.keyId,
    );
    expect(agent?.bypassCount).toBe(1);
    expect(agent?.state).toBe("bypassed");
    expect(
      report.recent.some(
        (event) => event.kind === "bypassed" && event.agentId === financeAgent.keyId,
      ),
    ).toBe(true);

    // One bypass per (agent, digest) — a second write is not a second row.
    await kernel.memWrite(
      {
        scope: "team",
        content: "Finance filed the Q3 statutory return on 2026-07-05.",
        hints: { verbatim: true },
      },
      financeAgent,
      "agent-2",
    );
    const second = await kernel.policyComplianceReport("acme", acmeOwner);
    const repeated = (second.documents[0]?.agents ?? []).find(
      (entry) => entry.agentId === financeAgent.keyId,
    );
    expect(repeated?.bypassCount).toBe(1);
  });

  it("stops counting a miss once the agent reads the policy", async () => {
    const before = await loadPolicyDirectives(kernel.db, "acme/finance/agent-1");
    await kernel.memPolicy({}, financeAgent, "agent-2");
    await kernel.memWrite(
      { scope: "team", content: "Finance approved the travel budget.", hints: { verbatim: true } },
      financeAgent,
      "agent-2",
    );

    const report = await kernel.policyComplianceReport("acme", acmeOwner);
    const agent = (report.documents[0]?.agents ?? []).find(
      (entry) => entry.agentId === financeAgent.keyId,
    );
    expect(agent?.lastDigest).toBe(before.digest);
    expect(agent?.bypassCount).toBe(1); // unchanged: the earlier miss stands
    expect(agent?.servedCount).toBeGreaterThan(0);
  });

  it("keeps enforcement changes owner-only and reflected in the directive set", async () => {
    const listed = await kernel.listPolicyDocuments({ namespace: "acme" }, acmeOwner);
    const document = listed.data[0];
    expect(document?.enforcement).toBe("required");

    await expect(
      kernel.setPolicyDocumentEnforcement(document!.id, "advisory", legalAgent),
    ).rejects.toThrow(/may not change policy enforcement/);

    const updated = await kernel.setPolicyDocumentEnforcement(
      document!.id,
      "advisory",
      acmeOwner,
    );
    expect(updated.enforcement).toBe("advisory");

    const directives = await loadPolicyDirectives(kernel.db, "acme/legal/agent-1");
    expect(directives.required).toBe(false);
    // Restore so later runs of this file start from the documented default.
    await kernel.setPolicyDocumentEnforcement(document!.id, "required", acmeOwner);
  });
});

/**
 * Who may load a guardrail, and where. Upload is owner/admin only and always
 * inside the caller's own subtree — a team admin governs its team, never a
 * sibling team and never the organization above it.
 */
describe("policy guardrail scopes", () => {
  it("lets a team admin govern its own subtree only", async () => {
    const own = await kernel.uploadPolicyDocument(
      {
        namespace: "acme/legal",
        title: "Contract review checklist",
        kind: "procedure",
        fileName: "contract-review.md",
        content: "Route every contract over one hundred thousand dollars to outside counsel.",
      },
      legalAdmin,
    );
    expect(own.namespace).toBe("acme/legal");

    // Sibling team: denied.
    await expect(
      kernel.uploadPolicyDocument(
        {
          namespace: "acme/finance",
          title: "Sneaky sibling policy",
          kind: "policy",
          fileName: "sibling.md",
          content: "Finance must defer to legal on every purchase.",
        },
        legalAdmin,
      ),
    ).rejects.toThrow(/outside your namespace subtree/);

    // The organization above it: denied.
    await expect(
      kernel.uploadPolicyDocument(
        {
          namespace: "acme",
          title: "Org-wide policy from a team",
          kind: "policy",
          fileName: "org-grab.md",
          content: "All teams report to legal.",
        },
        legalAdmin,
      ),
    ).rejects.toThrow(/outside your namespace subtree/);

    // The platform root: root owner only.
    await expect(
      kernel.uploadPolicyDocument(
        {
          namespace: "",
          title: "Platform policy from a tenant",
          kind: "policy",
          fileName: "root-grab.md",
          content: "Every tenant must use legal's template.",
        },
        acmeOwner,
      ),
    ).rejects.toThrow(/only the platform root owner/);
  });

  it("denies upload to member, auditor, and agent roles", async () => {
    for (const caller of [acmeMember, acmeAuditor, legalAgent]) {
      await expect(
        kernel.uploadPolicyDocument(
          {
            namespace: "acme",
            title: "Unauthorized policy",
            kind: "policy",
            fileName: `unauthorized-${caller.role}.md`,
            content: "This upload must never land.",
          },
          caller,
        ),
      ).rejects.toThrow(/may not upload policy documents/);
    }
  });

  it("delivers a team's guardrail down its own subtree and never sideways", async () => {
    const legal = await loadPolicyDirectives(kernel.db, "acme/legal/agent-1");
    const legalTitles = legal.documents.map((document) => document.title);
    expect(legalTitles).toContain("Contract review checklist"); // own team
    expect(legalTitles).toContain("Customer data handling"); // inherited from acme

    const finance = await loadPolicyDirectives(kernel.db, "acme/finance/agent-1");
    const financeTitles = finance.documents.map((document) => document.title);
    expect(financeTitles).toContain("Customer data handling");
    expect(financeTitles).not.toContain("Contract review checklist");
  });

  it("fences compliance rows to the selected subtree", async () => {
    await kernel.memAssemble({}, legalAgent, "agent-1");
    await kernel.memAssemble({}, financeAgent, "agent-2");

    const legalReport = await kernel.policyComplianceReport("acme/legal", legalAdmin);
    const legalAgentIds = legalReport.documents.flatMap((document) =>
      document.agents.map((agent) => agent.agentId),
    );
    expect(legalAgentIds).toContain(legalAgent.keyId);
    expect(legalAgentIds).not.toContain(financeAgent.keyId);

    // The organization scope sees both teams; a sibling admin sees neither.
    const orgReport = await kernel.policyComplianceReport("acme", acmeOwner);
    const orgAgentIds = orgReport.documents.flatMap((document) =>
      document.agents.map((agent) => agent.agentId),
    );
    expect(orgAgentIds).toEqual(
      expect.arrayContaining([legalAgent.keyId, financeAgent.keyId]),
    );
    await expect(
      kernel.policyComplianceReport("acme/legal", financeAdmin),
    ).rejects.toThrow(/outside your namespace subtree/);
  });

  it("keeps compliance readable by auditors and closed to members and agents", async () => {
    const audited = await kernel.policyComplianceReport("acme", acmeAuditor);
    expect(audited.documents.length).toBeGreaterThan(0);

    for (const caller of [acmeMember, legalAgent]) {
      await expect(
        kernel.policyComplianceReport("acme", caller),
      ).rejects.toThrow(/may not read policy compliance/);
    }
  });

  it("keeps the enforcement flip owner/admin and inside the subtree", async () => {
    const legalDocuments = await kernel.listPolicyDocuments(
      { namespace: "acme/legal" },
      legalAdmin,
    );
    const legalDocument = legalDocuments.data.find(
      (document) => document.title === "Contract review checklist",
    );
    expect(legalDocument).toBeDefined();

    // Its own team admin may flip it.
    const flipped = await kernel.setPolicyDocumentEnforcement(
      legalDocument!.id,
      "advisory",
      legalAdmin,
    );
    expect(flipped.enforcement).toBe("advisory");

    // A sibling team's admin may not.
    await expect(
      kernel.setPolicyDocumentEnforcement(legalDocument!.id, "required", financeAdmin),
    ).rejects.toThrow(/outside your namespace subtree/);

    // Neither may an auditor or a member.
    for (const caller of [acmeAuditor, acmeMember]) {
      await expect(
        kernel.setPolicyDocumentEnforcement(legalDocument!.id, "required", caller),
      ).rejects.toThrow(/may not change policy enforcement/);
    }

    await kernel.setPolicyDocumentEnforcement(legalDocument!.id, "required", acmeOwner);
  });
});
