import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { Kernel } from "../src/kernel.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { KnowledgeBaseNotFoundError } from "../src/knowledge-bases/index.js";
import type { AuditEvent, Identity } from "../src/types.js";

const MEMBER: Identity = {
  keyId: "session-member",
  namespace: "ac_me%/support",
  actor: "member@acme.test",
  role: "member",
  sessionUserId: "user-member",
};

const COOKIE = "halomem_session=member-session";
const PUBLIC_ORIGIN = "https://app.halofy.ai";

describe("member operating HTTP boundary", () => {
  let server: HaloHttpServer;
  let base: string;
  let profileCalls = 0;
  let mutationCalls = 0;
  let claimCalls = 0;
  let revealCalls = 0;
  const auditEvents: AuditEvent[] = [];

  beforeAll(async () => {
    const marker = (route: string) => async () => ({ route });
    const deps: HttpServerDeps = {
      consoleDir: new URL("../console", import.meta.url).pathname,
      secureCookies: false,
      // Production reaches the kernel through Vercel/Azure, where the
      // upstream request Host is not the browser-visible public origin.
      publicUrl: PUBLIC_ORIGIN,
      auth: {
        resolve: async () => null,
        resolveSession: async (token) => token === "member-session" ? MEMBER : null,
        profile: async () => {
          profileCalls += 1;
          return {
            homeNamespace: MEMBER.namespace,
            teams: [{ id: "team-support", name: "Support", namespace: MEMBER.namespace, isHome: true }],
          };
        },
      },
      syscalls: {
        memRead: marker("read"),
        memSearch: marker("search"),
        memWrite: marker("write"),
        memFault: marker("fault"),
        memStats: marker("stats"),
        memAssemble: marker("assemble"),
      },
      admin: {
        getPolicy: marker("policy"),
        setPolicy: marker("policy-write"),
        listKeys: marker("keys"),
        issueKey: async () => { mutationCalls += 1; return {}; },
        listKeyHandoffs: async () => ({ handoffs: [{ id: "handoff-member", status: "pending" }] }),
        claimKeyHandoff: async () => {
          claimCalls += 1;
          return { plaintext: "hm_agt_test-once", record: { id: "key-member" } };
        },
        revealKey: async () => {
          revealCalls += 1;
          return { plaintext: "hm_agt_repeatable", record: { id: "key-member" } };
        },
        revokeKey: async () => { mutationCalls += 1; return {}; },
        sourcesView: marker("sources"),
        listKnowledgeBases: marker("knowledge-bases"),
        listKnowledgeBaseSources: marker("knowledge-base-sources"),
        listCompanyFiles: marker("company-files"),
        connectors: marker("connectors"),
        listSourceCredentials: marker("source-credentials"),
        connectSource: async () => { mutationCalls += 1; return {}; },
        createKnowledgeBase: async () => { mutationCalls += 1; return {}; },
        listOAuthClients: marker("oauth-clients"),
      },
      metrics: { snapshot: () => ({}) },
      audit: { append: async (event: AuditEvent) => { auditEvents.push(event); } },
      buildMcpServer: () => { throw new Error("not used"); },
    };
    server = createHttpServer(deps);
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => server.stop());

  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    return fetch(base + path, {
      ...init,
      headers: { cookie: COOKIE, ...(init.headers ?? {}) },
    });
  }

  it("allows only the safe member source and knowledge metadata GET routes", async () => {
    for (const path of [
      "/v1/admin/sources",
      "/v1/admin/knowledge-bases",
      "/v1/admin/knowledge-bases/kb-team/sources",
      "/v1/admin/company-files?knowledgeBaseId=kb-team",
      "/v1/admin/connectors",
    ]) {
      const response = await request(path);
      expect(response.status, path).toBe(200);
    }
  });

  it("keeps credentials, governance, and every source/knowledge mutation forbidden", async () => {
    for (const [path, method, body] of [
      ["/v1/admin/source-credentials", "GET", undefined],
      ["/v1/admin/oauth-clients", "GET", undefined],
      ["/v1/admin/sources", "POST", "{}"],
      ["/v1/admin/knowledge-bases", "POST", "{}"],
    ] as const) {
      const response = await request(path, {
        method,
        ...(body === undefined ? {} : { headers: { "content-type": "application/json" }, body }),
      });
      expect(response.status, `${method} ${path}`).toBe(403);
    }
    expect(mutationCalls).toBe(0);
  });

  it("returns the session user's profile portfolio and rejects every selector", async () => {
    const response = await request("/auth/profile");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      homeNamespace: MEMBER.namespace,
      teams: [{ id: "team-support", name: "Support", namespace: MEMBER.namespace, isHome: true }],
    });
    expect(profileCalls).toBe(1);

    for (const selector of ["userId=other", "email=other%40acme.test", "actor=other"]) {
      const rejected = await request(`/auth/profile?${selector}`);
      expect(rejected.status, selector).toBe(400);
    }
    expect(profileCalls).toBe(1);
  });

  it("binds handoff discovery to the session and claim to a same-origin human POST", async () => {
    const listed = await request("/v1/admin/key-handoffs");
    expect(listed.status).toBe(200);
    expect(listed.headers.get("cache-control")).toBe("no-store");
    expect(await listed.json()).toEqual({ handoffs: [{ id: "handoff-member", status: "pending" }] });

    const crossSite = await request("/v1/admin/key-handoffs/handoff-member/claim", {
      method: "POST",
      headers: { origin: "https://attacker.test" },
    });
    expect(crossSite.status).toBe(403);
    expect(claimCalls).toBe(0);
    expect(auditEvents).toEqual(expect.arrayContaining([
      expect.objectContaining({
        actor: MEMBER.actor,
        namespace: MEMBER.namespace,
        op: "share",
        result: "denied",
        detail: "403 POST /v1/admin/key-handoffs/:id/claim same-origin required",
      }),
    ]));
    expect(JSON.stringify(auditEvents)).not.toContain("attacker.test");

    const claimed = await request("/v1/admin/key-handoffs/handoff-member/claim", {
      method: "POST",
      headers: { origin: PUBLIC_ORIGIN },
    });
    expect(claimed.status).toBe(200);
    expect(claimed.headers.get("cache-control")).toBe("no-store");
    expect(claimed.headers.get("referrer-policy")).toBe("no-referrer");
    expect(await claimed.json()).toEqual({
      plaintext: "hm_agt_test-once",
      record: { id: "key-member" },
    });
    expect(claimCalls).toBe(1);
  });

  it("binds repeated bearer reveal to the same-origin human session", async () => {
    const crossSite = await request("/v1/admin/keys/key-member/reveal", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://attacker.test" },
      body: "{}",
    });
    expect(crossSite.status).toBe(403);
    expect(revealCalls).toBe(0);

    for (let i = 0; i < 2; i += 1) {
      const response = await request("/v1/admin/keys/key-member/reveal", {
        method: "POST",
        headers: { "content-type": "application/json", origin: PUBLIC_ORIGIN },
        body: "{}",
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("referrer-policy")).toBe("no-referrer");
      expect(await response.json()).toEqual({
        plaintext: "hm_agt_repeatable",
        record: { id: "key-member" },
      });
    }
    expect(revealCalls).toBe(2);
  });
});

describe("member source, knowledge, and profile projections", () => {
  let kernel: Kernel;
  const createdKnowledgeBaseIds = new Map<string, string>();

  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });

    const now = "2026-08-02T08:00:00.000Z";
    await kernel.db.query(
      `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at, display_name)
       VALUES ('user-member', 'member@acme.test', $1, 'member', NULL, 'active', $2, 'Member User'),
              ('user-other', 'other@acme.test', 'ac_me%/sales', 'member', NULL, 'active', $2, 'Other User'),
              ('user-creator', 'creator@acme.test', $1, 'admin', NULL, 'disabled', $2, 'Owner One'),
              ('user-admin', 'admin@acme.test', 'ac_me%', 'admin', NULL, 'active', $2, 'Admin User')`,
      [MEMBER.namespace, now],
    );
    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, name, description, created_by, created_at)
       VALUES ('team-org', 'ac_me%', 'Organization', '', 'test', $1),
              ('team-support', $2, 'Support', '', 'test', $1),
              ('team-child', 'ac_me%/support/child', 'Support child', '', 'test', $1),
              ('team-sales', 'ac_me%/sales', 'Sales', '', 'test', $1)`,
      [now, MEMBER.namespace],
    );
    await kernel.db.query(
      `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
       VALUES ('team-support', 'user-member', 'test', $1),
              ('team-org', 'user-member', 'test', $1),
              ('team-sales', 'user-other', 'test', $1)`,
      [now],
    );

    const teamCredential = await kernel.createSourceCredential({
      connectorId: "woocommerce",
      connectionKey: "woocommerce",
      name: "Member-hidden credential",
      config: { consumerKey: "test-key", consumerSecret: "test-secret" },
    }, { ...MEMBER, role: "owner" });
    for (const [label, namespace] of [
      ["org", "ac_me%"],
      ["team", MEMBER.namespace],
      ["child", "ac_me%/support/child"],
      ["sibling", "ac_me%/sales"],
      ["wildcard-lookalike", "acXmeY/support"],
    ] as const) {
      await kernel.sources.register(namespace, "filesystem", {
        path: `/safe/${label}`,
        ...(label === "team" ? { credentialId: teamCredential.id } : {}),
      }, `member-operate-${label}`);
      const base = await kernel.knowledgeBases.create(
        {
          name: `${label} knowledge`,
          kind: "file",
          primaryBusinessFunction: "Operations",
          description: "Metadata only",
          dataSensitive: false,
        },
        { namespace, actor: "creator@acme.test", targetTeamId: null },
      );
      createdKnowledgeBaseIds.set(label, base.id);
    }
  }, 120_000);

  afterAll(async () => kernel.close());

  it("returns only organization ancestors plus the exact member team, with no credential reference", async () => {
    const querySpy = vi.spyOn(kernel.db, "query");
    const sources = await kernel.sourcesView(MEMBER) as {
      sources: Array<Record<string, unknown> & { id: string; namespace: string }>;
    };
    const memberSql = querySpy.mock.calls.map(([sql]) => String(sql)).join("\n");
    querySpy.mockRestore();
    expect(memberSql).toContain("WHERE namespace IN");
    expect(memberSql).not.toMatch(/namespace LIKE|fragmentation_reports|durable_jobs|memory_objects/);
    expect(sources.sources.map((source) => source.namespace).sort()).toEqual([
      "ac_me%",
      MEMBER.namespace,
    ].sort());
    for (const source of sources.sources) {
      expect(source).toHaveProperty("credentialId", null);
      expect(source).not.toHaveProperty("config");
    }

    const knowledge = await kernel.listKnowledgeBases({}, MEMBER);
    expect(knowledge.data.map((base) => base.name).sort()).toEqual([
      "org knowledge",
      "team knowledge",
    ]);
    expect(knowledge.data.every((base) =>
      base.createdBy === "creator@acme.test" &&
      base.createdByDisplayName === "Owner One"
    )).toBe(true);
  });

  it("conceals guessed sibling and descendant knowledge-base detail metadata", async () => {
    for (const label of ["child", "sibling", "wildcard-lookalike"]) {
      const id = createdKnowledgeBaseIds.get(label)!;
      await expect(kernel.listKnowledgeBaseSources(id, {}, MEMBER)).rejects.toBeInstanceOf(
        KnowledgeBaseNotFoundError,
      );
      await expect(
        kernel.listCompanyFiles({ knowledgeBaseId: id }, MEMBER),
      ).rejects.toBeInstanceOf(KnowledgeBaseNotFoundError);
    }
  });

  it("resolves only the signed-in user's home and additional team memberships", async () => {
    await expect(kernel.memberProfile({ ...MEMBER, sessionUserId: undefined })).resolves.toBeNull();
    await expect(kernel.memberProfile(MEMBER)).resolves.toEqual({
      homeNamespace: MEMBER.namespace,
      displayName: "Member User",
      avatar: null,
      teams: [
        { id: "team-org", name: "Organization", namespace: "ac_me%", isHome: false },
        { id: "team-support", name: "Support", namespace: MEMBER.namespace, isHome: true },
      ],
    });
  });

  it("synthesizes a legacy active user's home team when the directory row is absent", async () => {
    await kernel.db.query(
      `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
       VALUES ('user-legacy-home', 'legacy@acme.test', 'ac_me%/legacy', 'member', NULL, 'active', $1)`,
      ["2026-08-02T08:00:00.000Z"],
    );
    await expect(kernel.memberProfile({
      ...MEMBER,
      namespace: "ac_me%/legacy",
      actor: "legacy@acme.test",
      sessionUserId: "user-legacy-home",
    })).resolves.toEqual({
      homeNamespace: "ac_me%/legacy",
      displayName: "Member",
      avatar: null,
      teams: [{ id: "", name: "legacy", namespace: "ac_me%/legacy", isHome: true }],
    });
  });

  it("rejects the legacy member key body before source entitlements reach issuance", async () => {
    const deps = buildHttpDeps(kernel);
    await expect(deps.admin.issueKey?.({
      namespace: MEMBER.namespace,
      actor: "member-agent",
      role: "agent",
      sourcePrincipals: ["other-user"],
      sourceGroups: ["other-group"],
    }, MEMBER)).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("delivers an admin-assigned badge only to the session-bound member", async () => {
    const deps = buildHttpDeps(kernel);
    const admin: Identity = {
      keyId: "session-admin",
      namespace: "ac_me%",
      actor: "admin@acme.test",
      role: "admin",
      sessionUserId: "user-admin",
    };
    const assigned = await deps.admin.issueKey({
      type: "assistant",
      namespace: MEMBER.namespace,
      actor: "delegated-member-agent",
      recipientUserId: "user-member",
      idempotencyKey: "member-operate-handoff",
      agentCanWrite: false,
    }, admin) as { handoff: { id: string } };

    expect(assigned).not.toHaveProperty("plaintext");
    await expect(deps.admin.listKeyHandoffs?.(MEMBER)).resolves.toEqual({
      handoffs: [expect.objectContaining({ id: assigned.handoff.id, status: "pending" })],
    });
    await expect(deps.admin.listKeyHandoffs?.({
      ...MEMBER,
      actor: "other@acme.test",
      sessionUserId: "user-other",
      namespace: "ac_me%/sales",
    })).resolves.toEqual({ handoffs: [] });

    const claim = await deps.admin.claimKeyHandoff?.(assigned.handoff.id, MEMBER) as {
      plaintext: string;
      record: { id: string; custodianUserId?: string };
    };
    expect(claim.plaintext).toMatch(/^hm_agt_[0-9a-f]{40}$/);
    expect(claim.record.custodianUserId).toBe("user-member");
    const firstReveal = await deps.admin.revealKey?.(
      claim.record.id,
      MEMBER,
    ) as { plaintext: string };
    const secondReveal = await deps.admin.revealKey?.(
      claim.record.id,
      MEMBER,
    ) as { plaintext: string };
    expect(firstReveal.plaintext).toBe(claim.plaintext);
    expect(secondReveal.plaintext).toBe(claim.plaintext);
    await expect(deps.admin.claimKeyHandoff?.(assigned.handoff.id, MEMBER))
      .rejects.toThrow(/not available/i);
  });
});
