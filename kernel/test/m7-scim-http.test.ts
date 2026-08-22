import { afterEach, describe, expect, it } from "vitest";

import {
  createHttpServer,
  type HaloHttpServer,
  type HttpScimTenant,
  type HttpServerDeps,
} from "../src/http/server.js";

function baseDeps(scim: HttpServerDeps["scim"]): HttpServerDeps {
  return {
    auth: { async resolve() { return null; } },
    syscalls: {
      async memRead() {}, async memSearch() {}, async memWrite() {},
      async memFault() {}, async memStats() {}, async memAssemble() {},
    },
    admin: {
      async getPolicy() {}, async setPolicy() {}, async listKeys() {},
      async issueKey() {}, async revokeKey() {},
    },
    metrics: { snapshot() { return {}; } },
    audit: { async append() {} },
    buildMcpServer() { return { async connect() {}, async close() {} }; },
    scim,
  };
}

function tenant(namespace: string): HttpScimTenant {
  const user = {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: `${namespace}-user`, externalId: "external-user", userName: "user@example.test",
    displayName: "Example User",
    active: true, groups: [],
  };
  return {
    async provisionUser() { return user; },
    async provisionGroup() { return { id: `${namespace}-group` }; },
    async getUser(id) { return id === user.id ? user : null; },
    async listUsers() { return [user]; },
    async replaceUser(id) { return id === user.id ? user : null; },
    async patchUser(id) { return id === user.id ? { ...user, active: false } : null; },
    async deleteUser(id) { return id === user.id; },
    async getGroup() { return null; }, async listGroups() { return []; },
    async replaceGroup() { return null; }, async patchGroup() { return null; },
    async deleteGroup() { return false; },
  };
}

describe("M7 tenant-scoped SCIM 2.0 HTTP surface", () => {
  const servers: HaloHttpServer[] = [];
  afterEach(async () => Promise.all(servers.splice(0).map((server) => server.stop())));

  async function start(): Promise<string> {
    const tenants = new Map([
      ["tenant-a-token", tenant("a")],
      ["tenant-b-token", tenant("b")],
    ]);
    const server = createHttpServer(baseDeps({ resolve: (token) => tenants.get(token) ?? null }));
    servers.push(server);
    return `http://127.0.0.1:${await server.start(0)}`;
  }

  it("isolates credentials and returns standard create/list/resource responses", async () => {
    const base = await start();
    const created = await fetch(`${base}/scim/v2/Users`, {
      method: "POST",
      headers: { authorization: "Bearer tenant-a-token", "content-type": "application/scim+json" },
      body: JSON.stringify({}),
    });
    expect(created.status).toBe(201);
    expect(created.headers.get("content-type")).toContain("application/scim+json");
    expect((await created.json() as { id: string }).id).toBe("a-user");

    const list = await fetch(`${base}/scim/v2/Users?startIndex=1&count=10`, {
      headers: { authorization: "Bearer tenant-b-token" },
    });
    const body = await list.json() as { schemas: string[]; Resources: Array<{ id: string }> };
    expect(body.schemas[0]).toContain("ListResponse");
    expect(body.Resources[0]?.id).toBe("b-user");

    const crossTenant = await fetch(`${base}/scim/v2/Users/a-user`, {
      headers: { authorization: "Bearer tenant-b-token" },
    });
    expect(crossTenant.status).toBe(404);
  });

  it("supports PATCH/DELETE and emits SCIM-shaped auth errors", async () => {
    const base = await start();
    const patched = await fetch(`${base}/scim/v2/Users/a-user`, {
      method: "PATCH",
      headers: { authorization: "Bearer tenant-a-token", "content-type": "application/scim+json" },
      body: JSON.stringify({ schemas: [], Operations: [] }),
    });
    expect(patched.status).toBe(200);
    expect((await patched.json() as { active: boolean }).active).toBe(false);

    const deleted = await fetch(`${base}/scim/v2/Users/a-user`, {
      method: "DELETE", headers: { authorization: "Bearer tenant-a-token" },
    });
    expect(deleted.status).toBe(204);

    const denied = await fetch(`${base}/scim/v2/Users`, {
      headers: { authorization: "Bearer wrong-token" },
    });
    const error = await denied.json() as { schemas: string[]; status: string };
    expect(denied.status).toBe(401);
    expect(error.schemas[0]).toContain("Error");
    expect(error.status).toBe("401");
  });
});
