import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { Kernel } from "../src/kernel.js";
import { BadRequestError, buildHttpDeps } from "../src/http/adapter.js";
import {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
} from "../src/http/server.js";
import type { AuditEvent, Identity } from "../src/types.js";

const ADMIN: Identity = {
  keyId: "admin",
  namespace: "acme",
  actor: "admin@acme.test",
  role: "admin",
};
const OWNER: Identity = {
  keyId: "owner",
  namespace: "",
  actor: "owner@halomem.test",
  role: "owner",
};
const AUDITOR: Identity = {
  keyId: "auditor",
  namespace: "acme",
  actor: "auditor@acme.test",
  role: "auditor",
};
const ROOT_ADMIN: Identity = {
  keyId: "root-admin",
  namespace: "",
  actor: "admin@halomem.test",
  role: "admin",
};
const ROOT_AUDITOR: Identity = {
  keyId: "root-auditor",
  namespace: "",
  actor: "auditor@halomem.test",
  role: "auditor",
};
const MEMBER: Identity = {
  keyId: "member",
  namespace: "acme/team",
  actor: "member@acme.test",
  role: "member",
};

const ADMIN_KEY = "hm_" + "a".repeat(40);
const AUDITOR_KEY = "hm_" + "b".repeat(40);
const MEMBER_KEY = "hm_" + "c".repeat(40);
const OWNER_KEY = "hm_" + "d".repeat(40);

const UPLOAD = {
  namespace: "acme/legal",
  title: "Data retention",
  kind: "policy",
  fileName: "retention.md",
  content: "Customer records are retained for seven years.",
};

interface AdminCall {
  op: "list" | "scopes" | "upload" | "delete";
  input: Record<string, unknown>;
  identity: Identity;
}

function makeServerStubs(): {
  deps: HttpServerDeps;
  calls: AdminCall[];
  audit: AuditEvent[];
} {
  const calls: AdminCall[] = [];
  const audit: AuditEvent[] = [];
  const deps: HttpServerDeps = {
    auth: {
      async resolve(key) {
        if (key === ADMIN_KEY) return ADMIN;
        if (key === OWNER_KEY) return OWNER;
        if (key === AUDITOR_KEY) return AUDITOR;
        if (key === MEMBER_KEY) return MEMBER;
        return null;
      },
    },
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
      async setPolicy() { return {}; },
      async listKeys() { return []; },
      async issueKey() { return {}; },
      async revokeKey() { return {}; },
      async listPolicyDocuments(input, identity) {
        calls.push({ op: "list", input, identity });
        return {
          data: [],
          pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 },
          summary: { total: 0, active: 0, needsReview: 0, failed: 0 },
        };
      },
      async listPolicyDocumentScopes(input, identity) {
        calls.push({ op: "scopes", input, identity });
        return { data: [{ namespace: identity.namespace, documentCount: 0 }], hasMore: false };
      },
      async uploadPolicyDocument(input, identity) {
        calls.push({ op: "upload", input, identity });
        return { id: "doc-1", ...input, status: "active" };
      },
      async deletePolicyDocument(documentId, identity) {
        calls.push({ op: "delete", input: { documentId }, identity });
        return { id: documentId, status: "deleted" };
      },
    },
    metrics: { snapshot: () => ({}) },
    audit: { async append(event) { audit.push(event); } },
    buildMcpServer() { throw new Error("not used"); },
  };
  return { deps, calls, audit };
}

function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}` };
}

describe("policy-document HTTP routes", () => {
  let stubs: ReturnType<typeof makeServerStubs>;
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    stubs = makeServerStubs();
    server = createHttpServer(stubs.deps);
    const port = await server.start(0);
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    stubs.calls.length = 0;
    stubs.audit.length = 0;
  });

  it("allows owner/admin/auditor list access and forwards filters with the resolved identity", async () => {
    const filtered = await fetch(
      base + "/v1/admin/policy-documents?namespace=acme%2Flegal&page=2&pageSize=40" +
        "&query=retention&kind=policy&status=active",
      { headers: bearer(ADMIN_KEY) },
    );
    const auditorDefault = await fetch(base + "/v1/admin/policy-documents", {
      headers: bearer(AUDITOR_KEY),
    });
    const ownerDefault = await fetch(base + "/v1/admin/policy-documents", {
      headers: bearer(OWNER_KEY),
    });

    expect([filtered.status, auditorDefault.status, ownerDefault.status]).toEqual([200, 200, 200]);
    expect(stubs.calls).toEqual([
      {
        op: "list",
        input: {
          namespace: "acme/legal",
          page: 2,
          pageSize: 40,
          query: "retention",
          kind: "policy",
          status: "active",
        },
        identity: ADMIN,
      },
      {
        op: "list",
        input: { namespace: AUDITOR.namespace },
        identity: AUDITOR,
      },
      {
        op: "list",
        input: { namespace: OWNER.namespace },
        identity: OWNER,
      },
    ]);
  });

  it("serves the bounded policy-scope directory to read-only governance roles", async () => {
    const response = await fetch(
      base + "/v1/admin/policy-scopes?query=legal&limit=25",
      { headers: bearer(AUDITOR_KEY) },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ hasMore: false });
    expect(stubs.calls).toEqual([{
      op: "scopes",
      input: { query: "legal", limit: 25 },
      identity: AUDITOR,
    }]);
  });

  it("denies member list access and audits the resolved identity", async () => {
    const response = await fetch(base + "/v1/admin/policy-documents", {
      headers: bearer(MEMBER_KEY),
    });

    expect(response.status).toBe(403);
    expect(stubs.calls).toHaveLength(0);
    expect(stubs.audit).toEqual([
      expect.objectContaining({
        actor: MEMBER.actor,
        namespace: MEMBER.namespace,
        op: "read",
        result: "denied",
      }),
    ]);
  });

  it("accepts owner/admin uploads, forwards the resolved identity, and denies auditor mutation", async () => {
    const uploaded = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(ADMIN_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });
    const ownerUpload = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(OWNER_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });
    const denied = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(AUDITOR_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });

    expect([uploaded.status, ownerUpload.status]).toEqual([201, 201]);
    expect(await uploaded.json()).toMatchObject({ id: "doc-1", status: "active" });
    expect(denied.status).toBe(403);
    expect(stubs.calls).toEqual([
      { op: "upload", input: UPLOAD, identity: ADMIN },
      { op: "upload", input: UPLOAD, identity: OWNER },
    ]);
    expect(stubs.audit.at(-1)).toMatchObject({
      actor: AUDITOR.actor,
      namespace: AUDITOR.namespace,
      op: "write",
      result: "denied",
    });
  });

  it("accepts a decoded-limit policy whose escaped JSON body exceeds the generic 1 MiB cap", async () => {
    const content = "\\".repeat(512 * 1024);
    const raw = JSON.stringify({ ...UPLOAD, fileName: "escaped.txt", content });
    expect(Buffer.byteLength(raw)).toBeGreaterThan(1_048_576);

    const response = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(ADMIN_KEY), "content-type": "application/json" },
      body: raw,
    });

    expect(response.status).toBe(201);
    expect(stubs.calls[0]).toMatchObject({
      op: "upload",
      input: { fileName: "escaped.txt", content },
      identity: ADMIN,
    });
  });

  it("maps active duplicate conflicts to 409", async () => {
    stubs.deps.admin.uploadPolicyDocument = async () => {
      throw Object.assign(new Error("policy document already exists"), {
        name: "PolicyDocumentConflictError",
      });
    };
    const response = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(ADMIN_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "policy document already exists",
      code: "conflict",
    });

    stubs.deps.admin.uploadPolicyDocument = async (input, identity) => {
      stubs.calls.push({ op: "upload", input, identity });
      return { id: "doc-1", ...input, status: "active" };
    };
  });

  it("maps aggregate policy storage quota exhaustion to a stable 409 code", async () => {
    stubs.deps.admin.uploadPolicyDocument = async () => {
      throw Object.assign(new Error("Policy document storage quota exceeded"), {
        name: "PolicyDocumentQuotaError",
      });
    };
    const response = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(ADMIN_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "Policy document storage quota exceeded",
      code: "policy_document_quota",
    });

    stubs.deps.admin.uploadPolicyDocument = async (input, identity) => {
      stubs.calls.push({ op: "upload", input, identity });
      return { id: "doc-1", ...input, status: "active" };
    };
  });

  it("maps store validation errors to 400", async () => {
    stubs.deps.admin.uploadPolicyDocument = async () => {
      throw Object.assign(new Error("unsupported policy file extension"), {
        name: "PolicyDocumentValidationError",
      });
    };
    const response = await fetch(base + "/v1/admin/policy-documents", {
      method: "POST",
      headers: { ...bearer(ADMIN_KEY), "content-type": "application/json" },
      body: JSON.stringify(UPLOAD),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ code: "bad_request" });

    stubs.deps.admin.uploadPolicyDocument = async (input, identity) => {
      stubs.calls.push({ op: "upload", input, identity });
      return { id: "doc-1", ...input, status: "active" };
    };
  });

  it("allows owner/admin delete and forwards the resolved identity", async () => {
    const adminDelete = await fetch(base + "/v1/admin/policy-documents/doc-1", {
      method: "DELETE",
      headers: bearer(ADMIN_KEY),
    });
    const ownerDelete = await fetch(base + "/v1/admin/policy-documents/doc-2", {
      method: "DELETE",
      headers: bearer(OWNER_KEY),
    });

    expect([adminDelete.status, ownerDelete.status]).toEqual([204, 204]);
    expect(stubs.calls).toEqual([
      { op: "delete", input: { documentId: "doc-1" }, identity: ADMIN },
      { op: "delete", input: { documentId: "doc-2" }, identity: OWNER },
    ]);
  });

  it("denies auditor/member delete and audits the resolved identity", async () => {
    const auditorDelete = await fetch(base + "/v1/admin/policy-documents/doc-1", {
      method: "DELETE",
      headers: bearer(AUDITOR_KEY),
    });
    const memberDelete = await fetch(base + "/v1/admin/policy-documents/doc-1", {
      method: "DELETE",
      headers: bearer(MEMBER_KEY),
    });

    expect([auditorDelete.status, memberDelete.status]).toEqual([403, 403]);
    expect(stubs.calls).toHaveLength(0);
    expect(stubs.audit).toEqual([
      expect.objectContaining({
        actor: AUDITOR.actor,
        namespace: AUDITOR.namespace,
        op: "write",
        result: "denied",
      }),
      expect.objectContaining({
        actor: MEMBER.actor,
        namespace: MEMBER.namespace,
        op: "write",
        result: "denied",
      }),
    ]);
  });

  it("maps policy delete validation errors to 400", async () => {
    stubs.deps.admin.deletePolicyDocument = async () => {
      throw Object.assign(new Error("policy document is unknown"), {
        name: "PolicyDocumentValidationError",
      });
    };
    const response = await fetch(base + "/v1/admin/policy-documents/doc-missing", {
      method: "DELETE",
      headers: bearer(ADMIN_KEY),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ code: "bad_request" });

    stubs.deps.admin.deletePolicyDocument = async (documentId, identity) => {
      stubs.calls.push({ op: "delete", input: { documentId }, identity });
      return { id: documentId, status: "deleted" };
    };
  });
});

describe("policy-document HTTP adapter validation and scoping", () => {
  let kernel: Kernel;
  let deps: HttpServerDeps;
  const calls: AdminCall[] = [];

  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
    });
    const policyKernel = kernel as Kernel & {
      listPolicyDocuments(input: Record<string, unknown>, identity: Identity): Promise<unknown>;
      listPolicyDocumentScopes(input: Record<string, unknown>, identity: Identity): Promise<unknown>;
      uploadPolicyDocument(input: Record<string, unknown>, identity: Identity): Promise<unknown>;
      deletePolicyDocument(documentId: string, identity: Identity): Promise<unknown>;
    };
    policyKernel.listPolicyDocuments = async (input, identity) => {
      calls.push({ op: "list", input, identity });
      return { data: [] };
    };
    policyKernel.uploadPolicyDocument = async (input, identity) => {
      calls.push({ op: "upload", input, identity });
      return { id: "doc-adapter", ...input };
    };
    policyKernel.listPolicyDocumentScopes = async (input, identity) => {
      calls.push({ op: "scopes", input, identity });
      return { data: [] };
    };
    policyKernel.deletePolicyDocument = async (documentId, identity) => {
      calls.push({ op: "delete", input: { documentId }, identity });
      return { id: documentId, status: "deleted" };
    };
    deps = buildHttpDeps(kernel);
  });

  afterAll(async () => {
    await kernel.close();
  });

  beforeEach(() => {
    calls.length = 0;
  });

  it("validates, defaults, caps, and scope-checks list queries", async () => {
    await deps.admin.listPolicyDocuments!(
      { namespace: "acme/legal", page: 2, pageSize: 500, query: " retention " },
      ADMIN,
    );
    expect(calls).toEqual([
      {
        op: "list",
        input: {
          namespace: "acme/legal",
          page: 2,
          pageSize: 50,
          query: "retention",
        },
        identity: ADMIN,
      },
    ]);

    await deps.admin.listPolicyDocuments!({ namespace: "" }, OWNER);
    expect(calls.at(-1)).toEqual({
      op: "list",
      input: { namespace: "", page: 1, pageSize: 20 },
      identity: OWNER,
    });

    await expect(
      deps.admin.listPolicyDocuments!({ namespace: "acme", page: 0 }, ADMIN),
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      deps.admin.listPolicyDocuments!({ namespace: "acme", status: "unknown" }, ADMIN),
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      deps.admin.listPolicyDocuments!({ namespace: "globex" }, AUDITOR),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("strictly validates uploads, authorizes the target scope, and preserves resolved identity", async () => {
    await deps.admin.uploadPolicyDocument!(UPLOAD, ADMIN);
    await deps.admin.uploadPolicyDocument!({ ...UPLOAD, namespace: "" }, OWNER);
    expect(calls).toEqual([
      { op: "upload", input: UPLOAD, identity: ADMIN },
      { op: "upload", input: { ...UPLOAD, namespace: "" }, identity: OWNER },
    ]);

    await expect(
      deps.admin.uploadPolicyDocument!({ ...UPLOAD, actor: "mallory" }, ADMIN),
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      deps.admin.uploadPolicyDocument!({ ...UPLOAD, kind: "memo" }, ADMIN),
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      deps.admin.uploadPolicyDocument!({ ...UPLOAD, namespace: "globex" }, ADMIN),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("denies global empty-scope access to root admin and auditor identities", async () => {
    await expect(
      deps.admin.listPolicyDocuments!({ namespace: "" }, ROOT_ADMIN),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      deps.admin.listPolicyDocuments!({ namespace: "" }, ROOT_AUDITOR),
    ).rejects.toMatchObject({ name: "AuthzError" });
    await expect(
      deps.admin.uploadPolicyDocument!({ ...UPLOAD, namespace: "" }, ROOT_ADMIN),
    ).rejects.toMatchObject({ name: "AuthzError" });
  });

  it("validates and forwards bounded policy scope searches", async () => {
    await deps.admin.listPolicyDocumentScopes!({ query: " legal ", limit: 25 }, AUDITOR);
    expect(calls).toEqual([{
      op: "scopes",
      input: { query: "legal", limit: 25 },
      identity: AUDITOR,
    }]);
    await expect(
      deps.admin.listPolicyDocumentScopes!({ limit: 101 }, ADMIN),
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it("maps store validation to 400 without swallowing conflicts", async () => {
    const policyKernel = kernel as Kernel & {
      uploadPolicyDocument(input: Record<string, unknown>, identity: Identity): Promise<unknown>;
    };
    policyKernel.uploadPolicyDocument = async () => {
      throw Object.assign(new Error("unsupported policy file extension"), {
        name: "PolicyDocumentValidationError",
      });
    };
    await expect(deps.admin.uploadPolicyDocument!(UPLOAD, ADMIN)).rejects.toBeInstanceOf(
      BadRequestError,
    );

    policyKernel.uploadPolicyDocument = async () => {
      throw Object.assign(new Error("duplicate"), { name: "PolicyDocumentConflictError" });
    };
    await expect(deps.admin.uploadPolicyDocument!(UPLOAD, ADMIN)).rejects.toMatchObject({
      name: "PolicyDocumentConflictError",
    });
  });

  it("validates and forwards policy deletes with the resolved identity", async () => {
    await deps.admin.deletePolicyDocument!("doc-1", ADMIN);
    await deps.admin.deletePolicyDocument!("doc-2", OWNER);
    expect(calls).toEqual([
      { op: "delete", input: { documentId: "doc-1" }, identity: ADMIN },
      { op: "delete", input: { documentId: "doc-2" }, identity: OWNER },
    ]);

    const policyKernel = kernel as Kernel & {
      deletePolicyDocument(documentId: string, identity: Identity): Promise<unknown>;
    };
    policyKernel.deletePolicyDocument = async () => {
      throw Object.assign(new Error("policy document is unknown"), {
        name: "PolicyDocumentValidationError",
      });
    };
    await expect(deps.admin.deletePolicyDocument!("doc-missing", ADMIN)).rejects.toBeInstanceOf(
      BadRequestError,
    );
  });
});
