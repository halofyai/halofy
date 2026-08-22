/**
 * Team memory access: parent-issued company-published visibility.
 *
 * Hermetic: in-memory PGlite, HashEmbedder/StubLlm, zero network.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type {
  DataClassification,
  Identity,
  MemoryObject,
  ProvenanceEntry,
  Scope,
  SourceAccess,
} from "../src/types.js";

let kernel: Kernel;
let root: Identity;
let acmeOwner: Identity;
let acmeAdmin: Identity;
let globexOwner: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const identity = await kernel.auth.resolve(issued.plaintext);
  if (!identity) throw new Error(`identity '${actor}' did not resolve`);
  return identity;
}

function memory(
  namespace: string,
  content: string,
  options: {
    source?: ProvenanceEntry["source"];
    scope?: Scope;
    type?: MemoryObject["type"];
    sourceAccess?: SourceAccess;
    classification?: DataClassification;
    cache?: boolean;
    tier?: MemoryObject["tier"];
    provenance?: ProvenanceEntry[];
  } = {},
): MemoryObject {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    namespace,
    scope: options.scope ?? "org",
    tier: options.tier ?? "L2",
    backendRef: "inline",
    content,
    type: options.type ?? "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: options.provenance ?? [{
      source: options.source ?? "document",
      actor: "ingest",
      ...(options.cache ? { cache: true } : {}),
      ts: now,
    }],
    ...(options.sourceAccess ? { sourceAccess: options.sourceAccess } : {}),
    ...(options.classification ? { classification: options.classification } : {}),
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
}

beforeEach(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  const rootKey = await kernel.auth.issueKey("", "root@halomem.test", "owner");
  const resolved = await kernel.auth.resolve(rootKey.plaintext);
  if (!resolved) throw new Error("root owner did not resolve");
  root = resolved;
  acmeOwner = await issue("acme", "owner@acme.test", "owner", root);
  acmeAdmin = await issue("acme", "admin@acme.test", "admin", root);
  globexOwner = await issue("globex", "owner@globex.test", "owner", root);
});

afterEach(async () => {
  await kernel.close();
});

describe("team memory access administration", () => {
  it("defaults new teams to related and exposes server-derived transition permissions", async () => {
    const team = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    expect(team.memoryAccess).toEqual({
      mode: "related",
      version: 1,
      canBroaden: true,
      canTighten: true,
    });

    const listed = await kernel.listTeams(acmeOwner);
    expect(listed.find((candidate) => candidate.id === team.id)?.memoryAccess)
      .toEqual(team.memoryAccess);
  });

  it("lets the organization owner or admin change mode and audits the exact transition", async () => {
    const ownerTeam = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const enabled = await kernel.changeTeamMemoryAccess(
      acmeOwner,
      ownerTeam.id,
      "company-published",
    );
    expect(enabled.memoryAccess).toMatchObject({
      mode: "company-published",
      version: 2,
    });

    const adminTeam = await kernel.createTeam(acmeOwner, { name: "Support" });
    await expect(kernel.changeTeamMemoryAccess(
      acmeAdmin,
      adminTeam.id,
      "company-published",
    )).resolves.toMatchObject({
      memoryAccess: { mode: "company-published", version: 2 },
    });

    const audit = await kernel.db.query(
      `SELECT actor, namespace, purpose, result, detail
         FROM audit_log
        WHERE purpose = 'console-team-memory-access'
        ORDER BY seq`,
    );
    expect(audit.rows).toHaveLength(2);
    expect(audit.rows[0]).toMatchObject({
      actor: acmeOwner.actor,
      namespace: ownerTeam.namespace,
      purpose: "console-team-memory-access",
      result: "ok",
    });
    expect(String(audit.rows[0]?.detail)).toContain("related -> company-published");
  });

  it("allows team-local authority to tighten but never broaden", async () => {
    const team = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    await kernel.changeTeamMemoryAccess(acmeOwner, team.id, "company-published");
    const teamAdmin = await issue(team.namespace, "admin@marketing.test", "admin", root);

    await expect(kernel.changeTeamMemoryAccess(
      teamAdmin,
      team.id,
      "related",
    )).resolves.toMatchObject({ memoryAccess: { mode: "related" } });
    await expect(kernel.changeTeamMemoryAccess(
      teamAdmin,
      team.id,
      "company-published",
    )).rejects.toMatchObject({ name: "AuthzError" });
    const denied = await kernel.audit.list(team.namespace, { limit: 50 });
    expect(denied).toContainEqual(expect.objectContaining({
      purpose: "console-team-memory-access",
      result: "denied",
    }));
  });

  it("denies read-only roles, agents, siblings, and forged body authority", async () => {
    const team = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const auditor = await issue("acme", "auditor@acme.test", "auditor", root);
    const member = await issue(team.namespace, "member@marketing.test", "member", root);
    const agent = await issue(team.namespace, "agent@marketing.test", "agent", root);

    for (const identity of [auditor, member, agent]) {
      await expect(kernel.changeTeamMemoryAccess(
        identity,
        team.id,
        "company-published",
      )).rejects.toMatchObject({ name: "AuthzError" });
    }
    await expect(kernel.changeTeamMemoryAccess(
      globexOwner,
      team.id,
      "company-published",
    )).rejects.toMatchObject({
      name: "BadRequestError",
      message: expect.stringContaining("no team"),
    });
    const foreignDenied = await kernel.audit.list("globex", { limit: 50 });
    expect(foreignDenied).toContainEqual(expect.objectContaining({
      purpose: "console-team-memory-access",
      result: "denied",
    }));

    await expect(kernel.changeTeamMemoryAccess(
      acmeOwner,
      team.id,
      { mode: "company-published", namespace: "globex/finance" } as unknown as "company-published",
    )).rejects.toThrow(/mode|invalid/i);
  });

  it("rolls the mode back when the success audit cannot commit", async () => {
    const team = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const audit = vi.spyOn(kernel.audit, "appendTo")
      .mockRejectedValueOnce(new Error("audit unavailable"));

    await expect(kernel.changeTeamMemoryAccess(
      acmeOwner,
      team.id,
      "company-published",
    )).rejects.toThrow("audit unavailable");
    audit.mockRestore();

    const listed = await kernel.listTeams(acmeOwner);
    expect(listed.find((candidate) => candidate.id === team.id)?.memoryAccess.mode)
      .toBe("related");
  });
});

describe("effective retrieval visibility", () => {
  it("projects the effective company-published view into Memory Lane without sibling topology", async () => {
    const marketing = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const finance = await kernel.createTeam(acmeOwner, { name: "Finance" });
    const viewer = await issue(marketing.namespace, "member@marketing.test", "member", root);
    const companyDoc = memory(finance.namespace, "approved finance launch calendar MEMORYLANE");
    const privateScratchpad = memory(finance.namespace, "finance private scratchpad", {
      source: "manual",
    });
    const coldDocument = memory(finance.namespace, "finance cold document", { tier: "L3" });
    await kernel.index.insert(companyDoc, null);
    await kernel.index.insert(privateScratchpad, null);
    await kernel.index.insert(coldDocument, null);

    const related = await kernel.memoryMap(viewer, marketing.namespace);
    expect(related.hottest.some((item) => item.content.includes("MEMORYLANE"))).toBe(false);
    expect(related.topology.companyPublishedFacts).toBe(0);

    await kernel.changeTeamMemoryAccess(acmeOwner, marketing.id, "company-published");
    const shared = await kernel.memoryMap(viewer, marketing.namespace);
    expect(shared.hottest.some((item) => item.content.includes("MEMORYLANE"))).toBe(true);
    expect(shared.hottest.some((item) => item.content.includes("private scratchpad"))).toBe(false);
    expect(shared.hottest.some((item) => item.content.includes("cold document"))).toBe(false);
    expect(shared.topology.companyPublishedFacts).toBe(1);
    expect(JSON.stringify(shared.topology)).not.toContain(finance.namespace);
  });

  it("adds only governed sibling company memory and preserves every other fence", async () => {
    const marketing = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const finance = await kernel.createTeam(acmeOwner, { name: "Finance" });
    const globexFinance = await kernel.createTeam(globexOwner, { name: "Finance" });
    const marketingAdmin = await issue(marketing.namespace, "admin@marketing.test", "admin", root);
    const frontend = await kernel.createTeam(marketingAdmin, { name: "Frontend" });
    const viewer = await issue(
      marketing.namespace,
      "member@marketing.test",
      "member",
      root,
    );

    const companyDoc = memory(finance.namespace, "approved finance launch calendar");
    const consolidation = memory(finance.namespace, "approved quarterly planning summary", {
      source: "consolidation",
    });
    const manual = memory(finance.namespace, "manual finance scratchpad", { source: "manual" });
    const conversation = memory(finance.namespace, "private finance chat", { source: "conversation" });
    const teamScoped = memory(finance.namespace, "finance team private", { scope: "team" });
    const pointer = memory(finance.namespace, "postgres finance pointer", { type: "pointer" });
    const cache = memory(finance.namespace, "live finance cache", {
      source: "live-fetch",
      cache: true,
    });
    const mixedCache = memory(finance.namespace, "mixed provenance cache", {
      provenance: [
        { source: "document", actor: "ingest", ts: new Date().toISOString() },
        { source: "live-fetch", actor: "gateway", cache: true, ts: new Date().toISOString() },
      ],
    });
    const mixedManual = memory(finance.namespace, "mixed manual document", {
      provenance: [
        { source: "document", actor: "ingest", ts: new Date().toISOString() },
        { source: "manual", actor: "finance-user", ts: new Date().toISOString() },
      ],
    });
    const coldDocument = memory(finance.namespace, "finance cold document", { tier: "L3" });
    const descendantDocument = memory(frontend.namespace, "marketing frontend document");
    const sourceDenied = memory(finance.namespace, "finance source acl", {
      sourceAccess: { principals: ["finance-user"], groups: ["finance" ] },
    });
    const classificationDenied = memory(finance.namespace, "finance restricted", {
      classification: {
        sensitivity: "restricted",
        piiSubjects: [],
        secretKinds: ["credential"],
        allowedDestinations: [],
      },
    });
    const otherOrg = memory(globexFinance.namespace, "globex company document");
    const unregistered = memory("acme/unregistered", "unregistered publisher document");

    for (const item of [
      companyDoc,
      consolidation,
      manual,
      conversation,
      teamScoped,
      pointer,
      cache,
      mixedCache,
      mixedManual,
      coldDocument,
      descendantDocument,
      sourceDenied,
      classificationDenied,
      otherOrg,
      unregistered,
    ]) {
      await kernel.index.insert(item, null);
    }

    expect((await kernel.memRead({ id: companyDoc.id }, viewer)).found).toBe(false);
    await kernel.changeTeamMemoryAccess(acmeOwner, marketing.id, "company-published");

    expect((await kernel.memRead({ id: companyDoc.id }, viewer)).found).toBe(true);
    const resolvedGrant = await kernel.teamMemoryAccess.resolve(viewer);
    if (!resolvedGrant) throw new Error("expected server-resolved team grant");
    const forgedCrossOrg: Identity = {
      ...globexOwner,
      teamMemoryGrant: resolvedGrant,
    };
    expect((await kernel.memRead({ id: companyDoc.id }, forgedCrossOrg)).found).toBe(false);
    expect((await kernel.memRead({ id: consolidation.id }, viewer)).found).toBe(true);
    const search = await kernel.memSearch({ query: "approved finance launch calendar", k: 20 }, viewer);
    expect(search.map((hit) => hit.ref)).toContain(companyDoc.id);
    expect(search.map((hit) => hit.ref)).not.toContain(manual.id);
    expect(search.map((hit) => hit.ref)).not.toContain(mixedCache.id);
    expect(search.map((hit) => hit.ref)).not.toContain(mixedManual.id);
    expect(search.map((hit) => hit.ref)).not.toContain(coldDocument.id);
    expect(search.map((hit) => hit.ref)).not.toContain(descendantDocument.id);
    expect(search.map((hit) => hit.ref)).not.toContain(otherOrg.id);
    for (const denied of [
      manual,
      conversation,
      teamScoped,
      pointer,
      cache,
      mixedCache,
      mixedManual,
      coldDocument,
      descendantDocument,
      sourceDenied,
      classificationDenied,
      otherOrg,
      unregistered,
    ]) {
      expect(
        (await kernel.memRead({ id: denied.id }, viewer)).found,
        denied.content,
      ).toBe(false);
    }
  });

  it("keeps organization ancestors visible and reports the same company view as search", async () => {
    const sales = await kernel.createTeam(acmeOwner, { name: "Sales" });
    const finance = await kernel.createTeam(acmeOwner, { name: "Finance" });
    const badge = await issue(sales.namespace, "badge@sales.test", "agent", root);
    const organizationDocument = memory("acme", "organization ARR is 42 million ARR42");
    const siblingDocument = memory(finance.namespace, "finance renewal is September 30 RENEWAL930");
    await kernel.index.insert(organizationDocument, null);
    await kernel.index.insert(siblingDocument, null);

    const relatedSearch = await kernel.memSearch({ query: "ARR42", k: 10 }, badge);
    expect(relatedSearch.map((hit) => hit.ref)).toContain(organizationDocument.id);
    expect(relatedSearch.map((hit) => hit.ref)).not.toContain(siblingDocument.id);
    expect((await kernel.memStats({}, badge)).l2Count).toBe(1);

    await kernel.changeTeamMemoryAccess(acmeOwner, sales.id, "company-published");

    const organizationSearch = await kernel.memSearch({ query: "ARR42", k: 10 }, badge);
    expect(organizationSearch.map((hit) => hit.ref)).toContain(organizationDocument.id);
    const companySearch = await kernel.memSearch({ query: "RENEWAL930", k: 10 }, badge);
    expect(companySearch.map((hit) => hit.ref)).toContain(siblingDocument.id);
    expect((await kernel.memStats({}, badge)).l2Count).toBe(2);
  });

  it("revokes a primed L1 read for the same long-lived identity", async () => {
    const marketing = await kernel.createTeam(acmeOwner, { name: "Marketing" });
    const finance = await kernel.createTeam(acmeOwner, { name: "Finance" });
    const viewer = await issue(marketing.namespace, "member@marketing.test", "member", root);
    const companyDoc = memory(finance.namespace, "approved finance launch calendar");
    await kernel.index.insert(companyDoc, null);

    await kernel.changeTeamMemoryAccess(acmeOwner, marketing.id, "company-published");
    expect((await kernel.memRead({ id: companyDoc.id }, viewer)).found).toBe(true);
    expect((await kernel.memRead({ id: companyDoc.id }, viewer)).found).toBe(true);

    await kernel.changeTeamMemoryAccess(acmeOwner, marketing.id, "related");
    expect((await kernel.memRead({ id: companyDoc.id }, viewer)).found).toBe(false);
  });
});
