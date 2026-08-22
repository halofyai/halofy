import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { BadRequestError, buildHttpDeps } from "../src/http/adapter.js";
import { createHttpServer, type HaloHttpServer, type HttpServerDeps } from "../src/http/server.js";
import type { AuditEvent, Identity } from "../src/types.js";

const ADMIN: Identity = { keyId: "admin", namespace: "acme", actor: "admin@acme.test", role: "admin" };
const AUDITOR: Identity = { keyId: "auditor", namespace: "acme", actor: "audit@acme.test", role: "auditor" };
const MEMBER: Identity = { keyId: "member", namespace: "acme/team", actor: "member@acme.test", role: "member" };
const KEYS = { admin: `hm_${"a".repeat(40)}`, auditor: `hm_${"b".repeat(40)}`, member: `hm_${"c".repeat(40)}` };

type Call = { op: string; id?: string; input?: Record<string, unknown>; identity: Identity };

function stubs(): { deps: HttpServerDeps; calls: Call[]; audit: AuditEvent[] } {
  const calls: Call[] = [];
  const audit: AuditEvent[] = [];
  return {
    calls,
    audit,
    deps: {
      auth: { async resolve(key) { return key === KEYS.admin ? ADMIN : key === KEYS.auditor ? AUDITOR : key === KEYS.member ? MEMBER : null; } },
      syscalls: {
        async memRead() { return {}; }, async memSearch() { return []; }, async memWrite() { return {}; },
        async memFault() { return {}; }, async memStats() { return {}; }, async memAssemble() { return []; },
      },
      admin: {
        async getPolicy() { return {}; }, async setPolicy() {}, async listKeys() { return []; },
        async issueKey() { return {}; }, async revokeKey() { return {}; },
        async listKnowledgeBases(input, identity) { calls.push({ op: "kb-list", input, identity }); return { data: [] }; },
        async createKnowledgeBase(input, identity) { calls.push({ op: "kb-create", input, identity }); return { id: "kb-1" }; },
        async listKnowledgeBaseSources(id, input, identity) { calls.push({ op: "piece-list", id, input, identity }); return { data: [] }; },
        async attachKnowledgeBaseSource(id, input, identity) { calls.push({ op: "piece-create", id, input, identity }); return { id: "piece-1" }; },
        async pauseKnowledgeBase(id, _body, identity) { calls.push({ op: "kb-pause", id, identity }); return { id, lifecycleState: "paused" }; },
        async resumeKnowledgeBase(id, _body, identity) { calls.push({ op: "kb-resume", id, identity }); return { id, lifecycleState: "active" }; },
        async archiveKnowledgeBase(id, _body, identity) { calls.push({ op: "kb-archive", id, identity }); return { id, lifecycleState: "archived" }; },
        async listCompanyFiles(input, identity) { calls.push({ op: "file-list", input, identity }); return { data: [] }; },
        async uploadCompanyFile(input, identity) { calls.push({ op: "file-upload", input, identity }); return { uploadId: "upload-1", status: "queued" }; },
        async companyFileUploadStatus(id, identity) { calls.push({ op: "file-upload-status", id, identity }); return { uploadId: id, status: "processing" }; },
        async archiveCompanyFile(id, _body, identity) { calls.push({ op: "file-archive", id, identity }); return { id, lifecycleState: "archived" }; },
        async updateSourceMetadata(id, input, identity) { calls.push({ op: "source-metadata", id, input, identity }); return { id, ...input }; },
      },
      metrics: { snapshot: () => ({}) },
      audit: { async append(event) { audit.push(event); } },
      buildMcpServer() { throw new Error("not used"); },
    },
  };
}

function headers(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}`, "content-type": "application/json" };
}

describe("knowledge base HTTP routes", () => {
  let state: ReturnType<typeof stubs>;
  let server: HaloHttpServer;
  let base: string;

  beforeAll(async () => {
    state = stubs();
    server = createHttpServer(state.deps);
    base = `http://127.0.0.1:${await server.start(0)}`;
  });
  afterAll(async () => server.stop());
  beforeEach(() => { state.calls.length = 0; state.audit.length = 0; });

  it("forwards list filters and resolved identity to read-only governance handlers", async () => {
    const kb = await fetch(base + "/v1/admin/knowledge-bases?query=shop&targetTeamId=t1&kind=url&status=ready&lifecycleState=active&page=2&pageSize=10", { headers: headers(KEYS.auditor) });
    const files = await fetch(base + "/v1/admin/company-files?knowledgeBaseId=kb-1&targetTeamId=t1&query=sku&status=ready&lifecycleState=active&includeUploads=true&page=3&pageSize=5", { headers: headers(KEYS.admin) });
    expect([kb.status, files.status]).toEqual([200, 200]);
    expect(state.calls).toEqual([
      { op: "kb-list", input: { query: "shop", targetTeamId: "t1", kind: "url", status: "ready", lifecycleState: "active", page: 2, pageSize: 10 }, identity: AUDITOR },
      { op: "file-list", input: { knowledgeBaseId: "kb-1", targetTeamId: "t1", query: "sku", status: "ready", lifecycleState: "active", includeUploads: true, page: 3, pageSize: 5 }, identity: ADMIN },
    ]);
  });

  it("exposes create, lifecycle, upload, archive and metadata mutations to admins", async () => {
    const kb = { name: "Commerce", kind: "file", targetTeamId: null, primaryBusinessFunction: "Sales", description: "Catalog", dataSensitive: false };
    const upload = { knowledgeBaseId: "kb-1", fileName: "catalog.csv", content: "sku,name\n1,Halo", idempotencyKey: "file_catalog_upload_001", description: "Catalog", purpose: "Sales lookup" };
    const metadata = { primaryBusinessFunction: "Sales", description: "Store", dataSensitive: true };
    const responses = await Promise.all([
      fetch(base + "/v1/admin/knowledge-bases", { method: "POST", headers: headers(KEYS.admin), body: JSON.stringify(kb) }),
      fetch(base + "/v1/admin/knowledge-bases/kb-1/pause", { method: "POST", headers: headers(KEYS.admin), body: "{}" }),
      fetch(base + "/v1/admin/knowledge-bases/kb-1/resume", { method: "POST", headers: headers(KEYS.admin), body: "{}" }),
      fetch(base + "/v1/admin/knowledge-bases/kb-1/archive", { method: "POST", headers: headers(KEYS.admin), body: "{}" }),
      fetch(base + "/v1/admin/company-files", { method: "POST", headers: headers(KEYS.admin), body: JSON.stringify(upload) }),
      fetch(base + "/v1/admin/company-files/file-1/archive", { method: "POST", headers: headers(KEYS.admin), body: "{}" }),
      fetch(base + "/v1/admin/sources/source-1/metadata", { method: "PATCH", headers: headers(KEYS.admin), body: JSON.stringify(metadata) }),
      fetch(base + "/v1/admin/knowledge-bases/kb-1/sources?page=2&pageSize=5", { headers: headers(KEYS.admin) }),
      fetch(base + "/v1/admin/knowledge-bases/kb-1/sources", { method: "POST", headers: headers(KEYS.admin), body: JSON.stringify({ kind: "website", sourceId: "source-1", name: "Docs", description: "Product docs", purpose: "Reference" }) }),
    ]);
    expect(responses.map((r) => r.status)).toEqual([201, 200, 200, 200, 202, 200, 200, 200, 201]);
    expect(state.calls).toContainEqual({ op: "piece-list", id: "kb-1", input: { page: 2, pageSize: 5 }, identity: ADMIN });
    expect(state.calls).toContainEqual({ op: "piece-create", id: "kb-1", input: { kind: "website", sourceId: "source-1", name: "Docs", description: "Product docs", purpose: "Reference" }, identity: ADMIN });
    expect(state.calls).toContainEqual({ op: "file-upload", input: upload, identity: ADMIN });
    const status = await fetch(base + "/v1/admin/company-file-uploads/upload-1", { headers: headers(KEYS.auditor) });
    expect(status.status).toBe(200);
    expect(state.calls).toContainEqual({ op: "file-upload-status", id: "upload-1", identity: AUDITOR });
  });

  it("denies auditor and member mutations before handlers run", async () => {
    const deniedWrite = await fetch(base + "/v1/admin/knowledge-bases", { method: "POST", headers: headers(KEYS.auditor), body: "{}" });
    const deniedMemberWrite = await fetch(base + "/v1/admin/company-files", { method: "POST", headers: headers(KEYS.member), body: "{}" });
    expect([deniedWrite.status, deniedMemberWrite.status]).toEqual([403, 403]);
    expect(state.calls).toHaveLength(0);
  });

  it("lets a member read the content-free company-file projection", async () => {
    // CONTRACTS-MEMBER-OPERATE D56: an operating member reads sources,
    // knowledge bases and company files. The route stops being a governance
    // gate for reads — the ACL narrows the ROWS, so the handler still receives
    // the server-resolved member identity and does the scoping itself.
    const memberRead = await fetch(base + "/v1/admin/company-files", { headers: headers(KEYS.member) });
    expect(memberRead.status).toBe(200);
    expect(state.calls).toHaveLength(1);
    expect(state.calls[0]!.op).toBe("file-list");
    expect(state.calls[0]!.identity).toEqual(MEMBER);
  });

  it("allows escaped decoded-limit content above the generic transport cap", async () => {
    const content = "\\".repeat(512 * 1024);
    const body = JSON.stringify({ knowledgeBaseId: "kb-1", fileName: "data.txt", content, description: "", purpose: "Audit" });
    expect(Buffer.byteLength(body)).toBeGreaterThan(1_048_576);
    const response = await fetch(base + "/v1/admin/company-files", { method: "POST", headers: headers(KEYS.admin), body });
    expect(response.status).toBe(202);
  });

  it("maps domain failures and redacts unexpected messages", async () => {
    const cases = [
      ["KnowledgeBaseValidationError", 400, "bad_request"], ["KnowledgeBaseNotFoundError", 404, "not_found"],
      ["KnowledgeBaseConflictError", 409, "conflict"], ["CompanyFileConflictError", 409, "conflict"],
      ["CompanyFileLeaseExpiredError", 409, "lease_expired"], ["CompanyFileQuotaError", 429, "company_file_quota"],
    ] as const;
    for (const [name, status, code] of cases) {
      state.deps.admin.listKnowledgeBases = async () => { const error = new Error("stable"); error.name = name; throw error; };
      const response = await fetch(base + "/v1/admin/knowledge-bases", { headers: headers(KEYS.admin) });
      expect([response.status, (await response.json() as { code: string }).code]).toEqual([status, code]);
    }
    for (const code of [
      "company_file_idempotency_conflict",
      "company_file_upload_processing",
      "company_file_upload_unreserved",
    ]) {
      state.deps.admin.listKnowledgeBases = async () => {
        const error = Object.assign(new Error("stable"), {
          name: "CompanyFileIdempotencyError",
          code,
        });
        throw error;
      };
      const response = await fetch(base + "/v1/admin/knowledge-bases", { headers: headers(KEYS.admin) });
      expect([response.status, (await response.json() as { code: string }).code]).toEqual([409, code]);
    }
    state.deps.admin.listKnowledgeBases = async () => { throw new Error("DATABASE_URL=secret"); };
    const response = await fetch(base + "/v1/admin/knowledge-bases", { headers: headers(KEYS.admin) });
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("secret");
  });
});

describe("knowledge base HTTP adapter validation", () => {
  const identity = ADMIN;
  const fake = {
    createKnowledgeBase: async (input: unknown) => input,
    listKnowledgeBases: async (input: unknown) => input,
    listKnowledgeBaseSources: async (_id: string, input: unknown) => input,
    attachKnowledgeBaseSource: async (_id: string, input: unknown) => input,
    pauseKnowledgeBase: async () => ({}), resumeKnowledgeBase: async () => ({}), archiveKnowledgeBase: async () => ({}),
    listCompanyFiles: async (input: unknown) => input, uploadCompanyFile: async (input: unknown) => input, archiveCompanyFile: async () => ({}),
    updateSourceMetadata: async (_id: string, input: unknown) => input,
  };
  const admin = buildHttpDeps(fake as never).admin;

  it("rejects unknown and caller-authority fields on every mutation shape", async () => {
    await expect(admin.createKnowledgeBase?.({ name: "A", kind: "file", targetTeamId: null, primaryBusinessFunction: "Sales", description: "", dataSensitive: false, namespace: "other" }, identity)).rejects.toBeInstanceOf(BadRequestError);
    await expect(admin.attachKnowledgeBaseSource?.("kb", { kind: "website", sourceId: "s", name: "Docs", description: "", purpose: "Reference", namespace: "other" }, identity)).rejects.toBeInstanceOf(BadRequestError);
    await expect(admin.uploadCompanyFile?.({ knowledgeBaseId: "kb", fileName: "a.txt", content: "a", description: "", purpose: "p", uploadedBy: "attacker" }, identity)).rejects.toBeInstanceOf(BadRequestError);
    await expect(admin.pauseKnowledgeBase?.("kb", { unexpected: true }, identity)).rejects.toBeInstanceOf(BadRequestError);
    await expect(admin.updateSourceMetadata?.("s", { primaryBusinessFunction: "Sales", description: "", dataSensitive: false, actor: "attacker" }, identity)).rejects.toBeInstanceOf(BadRequestError);
  });

  it("rejects malformed upload idempotency keys", async () => {
    await expect(admin.uploadCompanyFile?.({
      knowledgeBaseId: "kb",
      fileName: "a.txt",
      content: "a",
      idempotencyKey: "bad key",
      description: "",
      purpose: "p",
    }, identity)).rejects.toBeInstanceOf(BadRequestError);
  });
});
