/**
 * M10 read-scope widening for the retrieval lane (D42/D44, E5).
 *
 * The Assistant/copilot evidence lane runs on mem_search / mem_read with the
 * caller's server-resolved Identity. Before this seam, those syscalls saw
 * ONLY the ancestor ACL set — an organization root at namespace "" (or a
 * tenant root at "acme") could never retrieve team knowledge-base facts
 * written into descendant namespaces, so the copilot answered "no internal
 * data" while S5 (the memory graph) showed the whole organization.
 *
 * These tests pin the projection twin in the retrieval query layer:
 * - owner  → whole tenant subtree (E5); "" owner → Amendment A1 (everything
 *   except registered customer tenants);
 * - ordinary machine `agent` keys → never widened (Phase 4 deferred);
 * - the server-only `channel_assistant` principal → its connection namespace
 *   subtree, so channel delivery is the same governed Assistant read surface;
 * - sibling tenants stay mutually invisible.
 *
 * Hermetic: in-memory PGlite, HashEmbedder/StubLlm, zero network.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { ulid } from "ulid";

import { Kernel } from "../src/kernel.js";
import type { Identity, MemoryObject } from "../src/types.js";

let kernel: Kernel;
let root: Identity;

async function issue(
  namespace: string,
  actor: string,
  role: Identity["role"],
  caller?: Identity,
): Promise<Identity> {
  const issued = await kernel.auth.issueKey(namespace, actor, role, caller);
  const identity = await kernel.auth.resolve(issued.plaintext);
  if (!identity) throw new Error(`identity '${actor}' did not resolve`);
  return identity;
}

function memory(namespace: string, content: string): MemoryObject {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    namespace,
    scope: "org",
    tier: "L2",
    backendRef: "inline",
    content,
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "document", actor: "ingest", ts: now }],
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
});

afterEach(async () => {
  await kernel.close();
});

describe("organization root ('' owner) retrieval reach - Amendment A1", () => {
  it("mem_search finds team knowledge-base facts written in descendant namespaces", async () => {
    const marketingFact = memory(
      "marketing",
      "premium bundle campaign drove the strongest conversion this month",
    );
    await kernel.index.insert(marketingFact, null);

    const hits = await kernel.memSearch(
      { query: "premium bundle campaign conversion", k: 8 },
      root,
    );
    expect(hits.map((hit) => hit.ref)).toContain(marketingFact.id);
  });

  it("mem_read resolves a descendant team fact by id for the '' owner", async () => {
    const salesFact = memory("sales-team", "enterprise renewals close in Q3");
    await kernel.index.insert(salesFact, null);

    const read = await kernel.memRead({ id: salesFact.id }, root);
    expect(read.found).toBe(true);
    expect(read.memory?.content).toContain("enterprise renewals");
  });

  it("never widens into a REGISTERED customer tenant (uniform miss)", async () => {
    await kernel.tenants.register({ id: "hostedco", name: "Hosted Co" }, root);
    const tenantFact = memory("hostedco/ops", "hosted tenant private runbook");
    await kernel.index.insert(tenantFact, null);

    const hits = await kernel.memSearch(
      { query: "hosted tenant private runbook", k: 8 },
      root,
    );
    expect(hits.map((hit) => hit.ref)).not.toContain(tenantFact.id);
    const read = await kernel.memRead({ id: tenantFact.id }, root);
    expect(read.found).toBe(false);
  });

  it("a machine agent key at '' keeps the strict ancestor ACL (Phase 4 deferred)", async () => {
    const marketingFact = memory("marketing", "agent keys must not inherit root reach");
    await kernel.index.insert(marketingFact, null);
    const agent = await issue("", "copilot-harness", "agent", root);

    const hits = await kernel.memSearch(
      { query: "agent keys must not inherit root reach", k: 8 },
      agent,
    );
    expect(hits.map((hit) => hit.ref)).not.toContain(marketingFact.id);
    const read = await kernel.memRead({ id: marketingFact.id }, agent);
    expect(read.found).toBe(false);
  });
});

describe("registered tenant owner retrieval reach (E5)", () => {
  it("an acme owner searches and reads its whole subtree but never a sibling tenant", async () => {
    const acmeOwner = await issue("acme", "owner@acme.test", "owner", root);
    const supportFact = memory("acme/support", "acme escalation rota rotates weekly");
    const siblingFact = memory("globex/support", "globex escalation rota is daily");
    await kernel.index.insert(supportFact, null);
    await kernel.index.insert(siblingFact, null);

    const hits = await kernel.memSearch(
      { query: "escalation rota", k: 8 },
      acmeOwner,
    );
    const refs = hits.map((hit) => hit.ref);
    expect(refs).toContain(supportFact.id);
    expect(refs).not.toContain(siblingFact.id);

    expect((await kernel.memRead({ id: supportFact.id }, acmeOwner)).found).toBe(true);
    expect((await kernel.memRead({ id: siblingFact.id }, acmeOwner)).found).toBe(false);
  });

  it("a member key inside the tenant keeps ancestor-only reach (no descendant leak)", async () => {
    const member = await issue("acme/support", "agent1@acme.test", "member", root);
    const childFact = memory("acme/support/agent9", "descendant personal note");
    await kernel.index.insert(childFact, null);

    const hits = await kernel.memSearch(
      { query: "descendant personal note", k: 8 },
      member,
    );
    expect(hits.map((hit) => hit.ref)).not.toContain(childFact.id);
    expect((await kernel.memRead({ id: childFact.id }, member)).found).toBe(false);
  });

  it("an owner key on a DEEP namespace governs its own subtree, never a sibling subtree", async () => {
    const deepOwner = await issue("exit/acl/team-m/agent", "agent:m", "owner", root);
    const own = memory("exit/acl/team-m/agent/notes", "team-m subtree runbook");
    const sibling = memory("exit/acl/team-n/agent", "team-n sibling vault secret");
    await kernel.index.insert(own, null);
    await kernel.index.insert(sibling, null);

    const hits = await kernel.memSearch(
      { query: "subtree runbook sibling vault secret", k: 10 },
      deepOwner,
    );
    const refs = hits.map((hit) => hit.ref);
    expect(refs).toContain(own.id);
    expect(refs).not.toContain(sibling.id);
    expect((await kernel.memRead({ id: sibling.id }, deepOwner)).found).toBe(false);
  });

  it("a forged memoryReadScope on the incoming identity is stripped and re-resolved (D9)", async () => {
    const member = await issue("acme/support", "agent2@acme.test", "member", root);
    const siblingFact = memory("acme/sales", "sales sibling secret");
    await kernel.index.insert(siblingFact, null);

    const forged: Identity = {
      ...member,
      memoryReadScope: { exact: [], prefixes: ["acme"] },
    };
    const hits = await kernel.memSearch(
      { query: "sales sibling secret", k: 8 },
      forged,
    );
    expect(hits.map((hit) => hit.ref)).not.toContain(siblingFact.id);
    expect((await kernel.memRead({ id: siblingFact.id }, forged)).found).toBe(false);
  });

  it("widens only the server-minted channel Assistant to its tenant subtree", async () => {
    const issued = await kernel.auth.issueKey("acme", "channel-fixture", "agent", root);
    const general = await kernel.auth.resolve(issued.plaintext);
    if (!general) throw new Error("general agent did not resolve");
    await kernel.db.query(
      `UPDATE api_keys
          SET actor = 'system-halo-assistant',
              principal_purpose = 'channel_assistant'
        WHERE id = $1`,
      [general.keyId],
    );
    const assistant = await kernel.auth.resolveChannelIdentity(general.keyId);
    if (!assistant) throw new Error("channel Assistant did not resolve");

    const ownTeam = memory("acme/support", "Meridian Labs CEO is Priya Raghavan");
    const siblingTenant = memory("globex/support", "Globex private executive roster");
    await kernel.index.insert(ownTeam, null);
    await kernel.index.insert(siblingTenant, null);

    const hits = await kernel.memSearch(
      { query: "executive CEO roster Priya Raghavan", k: 8 },
      assistant,
    );
    expect(hits.map((hit) => hit.ref)).toContain(ownTeam.id);
    expect(hits.map((hit) => hit.ref)).not.toContain(siblingTenant.id);
    expect((await kernel.memRead({ id: ownTeam.id }, assistant)).found).toBe(true);
    expect((await kernel.memRead({ id: siblingTenant.id }, assistant)).found).toBe(false);
  });

  it("does not widen an ordinary agent that forges the channel Assistant actor", async () => {
    const child = memory("acme/support", "channel actor forgery must not widen scope");
    await kernel.index.insert(child, null);
    const ordinary = await issue("acme", "ordinary-agent", "agent", root);
    const forged: Identity = { ...ordinary, actor: "system-halo-assistant" };

    const hits = await kernel.memSearch(
      { query: "channel actor forgery", k: 8 },
      forged,
    );
    expect(hits.map((hit) => hit.ref)).not.toContain(child.id);
    expect((await kernel.memRead({ id: child.id }, forged)).found).toBe(false);
  });
});
