/**
 * CONTRACTS-MEMBER-OPERATE: member-visible operating surfaces and hard
 * authorization boundaries. This suite is intentionally focused: it tests the
 * shell contract, HTTP role matrix, projection edge cases, self-bound profile,
 * and the existing agent-scope primitive without duplicating broad M5/M10
 * suites.
 */

import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { assertAgentKeyScope } from "../src/auth/agent-scope.js";
import type { Db } from "../src/db/client.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { createHttpServer, type HaloHttpServer, type HttpServerDeps } from "../src/http/server.js";
import { Kernel } from "../src/kernel.js";
import type { AuditEvent, Identity } from "../src/types.js";

const MEMBER: Identity = {
  keyId: "member-key",
  namespace: "acme/r_d",
  actor: "member@acme.test",
  role: "member",
  sessionUserId: "user-member",
};
const MEMBER_KEY = `hm_${"a".repeat(40)}`;

describe("member console information architecture", () => {
  const appSource = readFileSync(
    fileURLToPath(new URL("../console/app.js", import.meta.url)),
    "utf8",
  );

  it("gives members exactly the contracted operating screens", () => {
    const memberLine = /member:\s*(\[[^\]]+\])/.exec(appSource);
    expect(memberLine, "ROLE_SCREENS.member must remain explicit and reviewable").not.toBeNull();
    expect(JSON.parse(memberLine![1]!)).toEqual([
      "s2",
      "s5",
      "s6",
      "s14",
      "s16",
      "s18",
    ]);
  });

  it("does not advertise commercial analytics to members", () => {
    const navStart = appSource.indexOf("const NAV = [");
    const navEnd = appSource.indexOf("/** The flat set", navStart);
    const navSource = appSource.slice(navStart, navEnd);
    const operateStart = navSource.indexOf('group: "Operate"');
    const governStart = navSource.indexOf('group: "Govern"');
    const onboardStart = navSource.indexOf('group: "Onboard"');
    const operate = navSource.slice(operateStart, governStart);
    const govern = navSource.slice(governStart, onboardStart);

    expect(operate).not.toContain('label: "Usage analytics"');
    expect(govern).not.toContain('label: "Usage analytics"');

    const governedIds = ["s13", "s3", "s19", "s4", "s7", "s11", "s8", "s20", "s17"];
    const memberLine = /member:\s*(\[[^\]]+\])/.exec(appSource);
    const memberScreens = JSON.parse(memberLine![1]!) as string[];
    expect(memberScreens.filter((id) => governedIds.includes(id))).toEqual([]);
  });
});

function memberHttpDeps(calls: string[]): HttpServerDeps {
  const auth = {
    async resolve(key: string) {
      return key === MEMBER_KEY ? MEMBER : null;
    },
    async profile(identity: Identity) {
      calls.push(`profile:${identity.sessionUserId}:${identity.namespace}`);
      return {
        homeNamespace: identity.namespace,
        teams: [{ id: "team-member", name: "Research", namespace: identity.namespace, isHome: true }],
      };
    },
  } as unknown as HttpServerDeps["auth"];

  return {
    auth,
    syscalls: {
      async memRead() { return {}; },
      async memSearch() { return []; },
      async memWrite() { return {}; },
      async memFault() { return {}; },
      async memStats() { return {}; },
      async memAssemble() { return []; },
    },
    admin: {
      async getPolicy() { return {}; },
      async setPolicy() {},
      async listKeys() { calls.push("keys-get"); return []; },
      async issueKey() { calls.push("keys-post"); return {}; },
      async revokeKey() { calls.push("keys-delete"); return {}; },
      async overview() { return {}; },
      async memoryMap() { return {}; },
      async sourcesView(identity) { calls.push(`sources:${identity.namespace}`); return { sources: [] }; },
      async sourceLineage(id, identity) { calls.push(`source-lineage:${id}:${identity.namespace}`); return {}; },
      async listKnowledgeBases(_query, identity) { calls.push(`knowledge-bases:${identity.namespace}`); return { data: [] }; },
      async listKnowledgeBaseSources(_id, _query, identity) { calls.push(`knowledge-base-sources:${identity.namespace}`); return { data: [] }; },
      async listCompanyFiles(_query, identity) { calls.push(`company-files:${identity.namespace}`); return { data: [] }; },
      async connectors(identity) { calls.push(`connectors:${identity.namespace}`); return []; },
      async listSourceCredentials() { calls.push("credentials-get"); return []; },
      async connectSource() { calls.push("sources-post"); return {}; },
      async createKnowledgeBase() { calls.push("knowledge-bases-post"); return {}; },
      async attachKnowledgeBaseSource() { calls.push("knowledge-base-sources-post"); return {}; },
      async uploadCompanyFile() { calls.push("company-files-post"); return {}; },
      async people() { calls.push("people-get"); return []; },
      async listTeams() { calls.push("teams-get"); return []; },
      async auditSearch() { calls.push("audit-get"); return []; },
    },
    metrics: { snapshot: () => ({}) },
    audit: { async append(_event: AuditEvent) {} },
    buildMcpServer() { throw new Error("not used"); },
  } as HttpServerDeps;
}

function memberHeaders(): Record<string, string> {
  return { authorization: `Bearer ${MEMBER_KEY}`, "content-type": "application/json" };
}

describe("member HTTP surface", () => {
  let calls: string[];
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    calls = [];
    server = createHttpServer(memberHttpDeps(calls));
    base = `http://127.0.0.1:${await server.start(0)}`;
  });

  afterAll(async () => server.stop());

  it("allows only the metadata GETs needed by Sources", async () => {
    const paths = [
      "/v1/admin/sources",
      "/v1/admin/knowledge-bases",
      "/v1/admin/knowledge-bases/kb-team/sources",
      "/v1/admin/company-files?knowledgeBaseId=kb-team",
      "/v1/admin/connectors",
      "/v1/admin/keys",
    ];
    const responses = await Promise.all(paths.map((path) => fetch(base + path, { headers: memberHeaders() })));
    expect(responses.map((response) => response.status)).toEqual([200, 200, 200, 200, 200, 200]);
    expect(calls).toEqual(expect.arrayContaining([
      "sources:acme/r_d",
      "knowledge-bases:acme/r_d",
      "knowledge-base-sources:acme/r_d",
      "company-files:acme/r_d",
      "connectors:acme/r_d",
      "keys-get",
    ]));
  });

  it("keeps credentials, governance, and every source mutation forbidden", async () => {
    const reads = [
      "/v1/admin/source-credentials",
      "/v1/admin/people",
      "/v1/admin/teams",
      "/v1/admin/audit",
      "/v1/admin/oauth/clients",
      // The connection drawer's lineage is a subtree aggregate (D56): the
      // exact member projection does not carry one.
      "/v1/admin/sources/src-team/lineage",
    ];
    const writes: Array<[string, string]> = [
      ["POST", "/v1/admin/sources"],
      ["POST", "/v1/admin/knowledge-bases"],
      ["POST", "/v1/admin/knowledge-bases/kb-team/sources"],
      ["POST", "/v1/admin/company-files"],
      ["POST", "/v1/admin/source-credentials"],
    ];
    const readResponses = await Promise.all(reads.map((path) => fetch(base + path, { headers: memberHeaders() })));
    const writeResponses = await Promise.all(writes.map(([method, path]) => fetch(base + path, {
      method,
      headers: memberHeaders(),
      body: "{}",
    })));

    expect(readResponses.map((response) => response.status)).toEqual([403, 403, 403, 403, 403, 403]);
    expect(writeResponses.map((response) => response.status)).toEqual([403, 403, 403, 403, 403]);
    expect(calls).not.toEqual(expect.arrayContaining([
      "credentials-get",
      "people-get",
      "teams-get",
      "audit-get",
      "source-lineage:src-team:acme/r_d",
      "sources-post",
      "knowledge-bases-post",
      "knowledge-base-sources-post",
      "company-files-post",
    ]));
  });

  it("binds the profile portfolio to the resolved session user and rejects selectors", async () => {
    const profile = await fetch(base + "/auth/profile", { headers: memberHeaders() });
    expect(profile.status).toBe(200);
    expect(await profile.json()).toEqual({
      homeNamespace: "acme/r_d",
      teams: [{ id: "team-member", name: "Research", namespace: "acme/r_d", isHome: true }],
    });

    const selectorResponses = await Promise.all([
      "?userId=user-other",
      "?email=owner%40acme.test",
      "?actor=owner%40acme.test",
    ].map((query) => fetch(base + "/auth/profile" + query, { headers: memberHeaders() })));
    expect(selectorResponses.map((response) => response.status)).toEqual([400, 400, 400]);
    expect(calls.filter((call) => call.startsWith("profile:"))).toEqual([
      "profile:user-member:acme/r_d",
    ]);
  });
});

describe("member source and knowledge projection", () => {
  let kernel: Kernel;
  let knowledgeDir: string;
  let server: HaloHttpServer;
  let base: string;
  let memberKey: string;

  beforeAll(async () => {
    knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-member-operate-"));
    kernel = await Kernel.boot({ databaseUrl: "", pgliteDataDir: "", knowledgeDir });

    const issuedRoot = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(issuedRoot.plaintext);
    if (!root) throw new Error("root identity did not resolve");
    memberKey = (await kernel.auth.issueKey(MEMBER.namespace, MEMBER.actor, "member", root)).plaintext;

    await kernel.sources.register("acme", "filesystem", { path: "/org" }, "org-source");
    await kernel.sources.register("acme/r_d", "filesystem", { path: "/team" }, "team-source");
    await kernel.sources.register("acme/r_d/child", "filesystem", { path: "/child" }, "child-source");
    await kernel.sources.register("acme/read", "filesystem", { path: "/sibling" }, "sibling-source");

    const now = new Date().toISOString();
    for (const [id, namespace, name] of [
      ["kb-org", "acme", "Organization knowledge"],
      ["kb-team", "acme/r_d", "Research knowledge"],
      ["kb-child", "acme/r_d/child", "Child knowledge"],
      ["kb-sibling", "acme/read", "Sibling knowledge"],
    ]) {
      await kernel.db.query(
        `INSERT INTO knowledge_bases
           (id, namespace, name, kind, status, lifecycle_state,
            primary_business_function, description, t_valid_from, created_by,
            created_at, updated_at)
         VALUES ($1, $2, $3, 'file', 'ready', 'active', 'Operations', '', $4,
                 'owner@acme.test', $4, $4)`,
        [id, namespace, name, now],
      );
    }
    await kernel.db.query(
      `INSERT INTO fragmentation_reports (id, namespace, ran_at, json)
       VALUES ('frag-child', 'acme/r_d/child', $1, $2::jsonb)`,
      [now, JSON.stringify({
        namespace: "acme/r_d/child",
        ranAt: now,
        factCount: 777,
        duplicateClusters: [],
        contradictions: [],
      })],
    );

    server = createHttpServer(buildHttpDeps(kernel));
    base = `http://127.0.0.1:${await server.start(0)}`;
  }, 120_000);

  afterAll(async () => {
    if (server) await server.stop();
    if (kernel) await kernel.close();
    if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
  });

  it("returns organization ancestors plus the exact team, never wildcard sibling or descendant source metadata", async () => {
    const view = await kernel.sourcesView(MEMBER);
    expect(view.sources.map((source) => source.namespace).sort()).toEqual(["acme", "acme/r_d"]);
    expect(view.latestFragmentation).toBeNull();
    expect(JSON.stringify(view)).not.toMatch(/child-source|sibling-source|acme\/read|acme\/r_d\/child/);
    expect(JSON.stringify(view)).not.toContain("777");
  });

  it("returns organization ancestors plus the exact team, never wildcard sibling or descendant knowledge metadata", async () => {
    const view = await kernel.listKnowledgeBases({}, MEMBER);
    expect(view.data.map((base) => base.id).sort()).toEqual(["kb-org", "kb-team"]);
    expect(JSON.stringify(view)).not.toMatch(/kb-child|kb-sibling|Sibling knowledge|Child knowledge/);
  });

  it("collapses sibling and descendant knowledge-base direct IDs to not found", async () => {
    const headers = { authorization: `Bearer ${memberKey}` };
    const visible = await Promise.all([
      fetch(base + "/v1/admin/knowledge-bases/kb-team/sources", { headers }),
      fetch(base + "/v1/admin/company-files?knowledgeBaseId=kb-team", { headers }),
    ]);
    expect(visible.map((response) => response.status)).toEqual([200, 200]);

    const hidden = await Promise.all([
      fetch(base + "/v1/admin/knowledge-bases/kb-sibling/sources", { headers }),
      fetch(base + "/v1/admin/knowledge-bases/kb-child/sources", { headers }),
      fetch(base + "/v1/admin/company-files?knowledgeBaseId=kb-sibling", { headers }),
      fetch(base + "/v1/admin/company-files?knowledgeBaseId=kb-child", { headers }),
    ]);
    expect(hidden.map((response) => response.status)).toEqual([404, 404, 404, 404]);
    for (const response of hidden) {
      expect(JSON.stringify(await response.json())).not.toMatch(/Sibling knowledge|Child knowledge|acme\/read|acme\/r_d\/child/);
    }
  });
});

describe("member agent-key authority", () => {
  const dbWithoutTeams = {
    async query() { return { rows: [] }; },
  } as unknown as Db;

  it("allows an assistant agent only at the member's exact namespace and member level", async () => {
    await expect(assertAgentKeyScope(dbWithoutTeams, MEMBER, {
      namespace: MEMBER.namespace,
    })).resolves.toEqual({ namespace: MEMBER.namespace, level: "member" });

    for (const namespace of ["acme", "acme/read", "acme/r_d/child"]) {
      await expect(assertAgentKeyScope(dbWithoutTeams, MEMBER, { namespace }))
        .rejects.toThrow(/own team scope/);
    }
    await expect(assertAgentKeyScope(dbWithoutTeams, MEMBER, {
      namespace: MEMBER.namespace,
      level: "manager",
    })).rejects.toThrow(/member-scope agents/);
  });
});
