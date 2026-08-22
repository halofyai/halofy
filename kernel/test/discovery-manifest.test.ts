/**
 * M9 parity #6 — llms.txt / memory manifest (E12–E14).
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 *
 * E12 — canonical rows only: pointer facts and write-back cache facts are
 *       never rendered, superseded rows are never rendered.
 * E13 — the manifest is exactly the calling badge's ACL view: two badges in
 *       sibling namespaces get different manifests; ancestor facts appear in
 *       both, sibling facts in neither's view of the other.
 * E14 — audited read syscall: ok AND denied outcomes write audit rows (D4).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomBytes } from "node:crypto";
import { ulid } from "ulid";
import { Kernel } from "../src/kernel.js";
import type { SyscallDeps } from "../src/syscalls/index.js";
import type { Identity, MemoryObject, Role } from "../src/types.js";
import {
  isManifestRow,
  memManifest,
  parseManifestArgs,
  renderManifestMarkdown,
  ManifestArgsError,
} from "../src/discovery/manifest.js";
import { AuthzError } from "../src/auth/index.js";

const AGENT = "vitest";

let knowledgeDir: string;
let kernel: Kernel;
let deps: SyscallDeps;
let idRoot: Identity;
let idSupport: Identity;
let idSales: Identity;

async function issueIdentity(
  ns: string,
  actor: string,
  role: Role,
  caller?: Identity,
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(ns, actor, role, caller ?? null);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued key failed to resolve");
  return identity;
}

/** Kernel-internal derived-row fixture (pointer / cache stamps). */
function derivedRow(
  namespace: string,
  content: string,
  stamp: { pointer?: boolean; cache?: boolean },
): MemoryObject {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    namespace,
    scope: "org",
    tier: "L2",
    backendRef: "inline",
    content,
    type: stamp.pointer ? "pointer" : "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [
      {
        source: "live-fetch",
        actor: "system",
        connectorId: "conn-x",
        sourceRef: "orders",
        ...stamp,
        ts: now,
      },
    ],
    ttlSeconds: stamp.cache ? 3600 : null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
}

describe("discovery/manifest - llms.txt memory manifest (E12–E14)", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-manifest-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    deps = (kernel as unknown as { deps: SyscallDeps }).deps;

    idRoot = await issueIdentity("", "platform-owner", "owner");
    const idOrg = await issueIdentity("org", "org-owner", "owner", idRoot);
    idSupport = await issueIdentity("org/support", "support-agent", "member", idOrg);
    idSales = await issueIdentity("org/sales", "sales-agent", "member", idOrg);

    // Ancestor fact — visible to both badges.
    await kernel.memWrite(
      { scope: "org", content: "Org rule: refunds require a ticket number.", hints: { verbatim: true, type: "fact" } },
      idOrg,
      AGENT,
    );
    // Sibling-private facts.
    await kernel.memWrite(
      { scope: "org", content: "Support playbook: escalate after two failed callbacks.", hints: { verbatim: true, type: "fact" } },
      idSupport,
      AGENT,
    );
    await kernel.memWrite(
      { scope: "org", content: "Sales quota: EMEA target is 40 seats per quarter.", hints: { verbatim: true, type: "fact" } },
      idSales,
      AGENT,
    );

    // Derived rows the manifest must NEVER render (E12): a pointer fact and a
    // write-back cache fact, inserted through the kernel-internal repository
    // exactly as the federation lane does.
    await deps.index.insert(
      derivedRow("org/support", "Orders live in the billing Postgres.", { pointer: true }),
      null,
    );
    await deps.index.insert(
      derivedRow("org/support", "Cached: order 4127 shipped Tuesday.", { cache: true }),
      null,
    );
  });

  afterAll(async () => {
    await kernel.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("E13: two different badges get different, ACL-exact manifests", async () => {
    const support = await memManifest(deps, {}, idSupport, AGENT);
    const sales = await memManifest(deps, {}, idSales, AGENT);

    // Ancestor fact in both.
    expect(support.markdown).toContain("refunds require a ticket number");
    expect(sales.markdown).toContain("refunds require a ticket number");
    // Own fact present, sibling fact invisible — in both directions.
    expect(support.markdown).toContain("escalate after two failed callbacks");
    expect(support.markdown).not.toContain("EMEA target");
    expect(sales.markdown).toContain("EMEA target");
    expect(sales.markdown).not.toContain("escalate after two failed callbacks");
    expect(support.markdown).not.toBe(sales.markdown);
    expect(support.namespace).toBe("org/support");
    expect(sales.namespace).toBe("org/sales");
  });

  it("E12: pointer and cache rows are never rendered; freshness is per source", async () => {
    const result = await memManifest(deps, {}, idSupport, AGENT);
    expect(result.markdown).not.toContain("billing Postgres");
    expect(result.markdown).not.toContain("order 4127");
    // Only canonical rows counted: org rule + support playbook.
    expect(result.entryCount).toBe(2);
    // Per-source freshness rollup present (verbatim writes → "conversation").
    expect(result.sources.length).toBeGreaterThan(0);
    const conversation = result.sources.find((s) => s.source === "conversation");
    expect(conversation).toBeDefined();
    expect(conversation!.freshestAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(result.markdown).toContain("## Sources");
    expect(result.markdown).toMatch(/conversation - \d+ entries, freshest \d{4}-\d{2}-\d{2}/);
  });

  it("labels uploaded company-file rows by filename instead of an opaque source id", async () => {
    const row = derivedRow("org/support", "Northstar generated the most revenue.", {});
    row.provenance[0] = {
      source: "company-file",
      sourceId: "01OPAQUESOURCE",
      documentKey: "sales.csv",
      actor: "owner@org.test",
      ts: row.assertionTime,
    };
    await deps.index.insert(row, null);

    const result = await memManifest(deps, {}, idSupport, AGENT);
    expect(result.markdown).toContain("sales.csv");
    expect(result.sources).toContainEqual(expect.objectContaining({ source: "sales.csv" }));
  });

  it("E12: cosine-similar observations both remain visible pending human review", async () => {
    await kernel.memWrite(
      { scope: "org", content: "Sales quota: EMEA target is 60 seats per quarter.", hints: { verbatim: true, type: "fact" } },
      idSales,
      AGENT,
    );
    const result = await memManifest(deps, {}, idSales, AGENT);
    expect(result.markdown).toContain("60 seats");
    expect(result.markdown).toContain("40 seats");
  });

  it("full variant respects the byte cap and reports truncation", async () => {
    const long = "Support macro: " + "customers deserve a complete answer. ".repeat(80);
    await kernel.memWrite(
      { scope: "org", content: long, hints: { verbatim: true, type: "fact" } },
      idSupport,
      AGENT,
    );
    const capped = await memManifest(
      deps,
      { variant: "full", maxBytes: 1024 },
      idSupport,
      AGENT,
    );
    expect(capped.variant).toBe("full");
    expect(capped.truncated).toBe(true);
    expect(capped.bytes).toBeLessThanOrEqual(1024);
    expect(capped.renderedCount).toBeLessThan(capped.entryCount);
    expect(capped.markdown).toContain("_Truncated:");

    const uncapped = await memManifest(deps, { variant: "full" }, idSupport, AGENT);
    expect(uncapped.truncated).toBe(false);
    expect(uncapped.renderedCount).toBe(uncapped.entryCount);
    expect(uncapped.markdown).toContain("customers deserve a complete answer");
  });

  it("keeps a many-source rollup inside the byte cap and preserves entry discovery", () => {
    const rows = Array.from({ length: 1_000 }, (_, index) => {
      const row = derivedRow("org", `Revenue fact ${index}`, {});
      row.provenance[0] = {
        source: "company-file",
        documentKey: `sales-region-${String(index).padStart(4, "0")}.csv`,
        actor: "owner@org.test",
        ts: row.assertionTime,
      };
      return row;
    });

    const rendered = renderManifestMarkdown(
      "org",
      rows,
      "index",
      16_000,
      "2026-07-28T00:00:00.000Z",
    );

    expect(Buffer.byteLength(rendered.markdown, "utf8")).toBeLessThanOrEqual(16_000);
    expect(rendered.markdown).toContain("## Memory index");
    expect(rendered.markdown).toContain("_Source rollup truncated:");
    expect(rendered.renderedCount).toBeGreaterThan(0);
    expect(rendered.truncated).toBe(true);
  });

  it("E14: ok outcome writes an audit row (op=read, purpose=manifest)", async () => {
    await memManifest(deps, {}, idSupport, AGENT);
    const res = await deps.db.query(
      `SELECT result, detail FROM audit_log
       WHERE namespace = $1 AND op = 'read' AND purpose = 'manifest' AND result = 'ok'`,
      ["org/support"],
    );
    expect(res.rows.length).toBeGreaterThan(0);
    const detail = (res.rows[0] as { detail: string }).detail;
    expect(detail).toContain("manifest variant=");
  });

  it("E14/D4: a revoked badge is denied AND the denial is audited", async () => {
    const doomed = await issueIdentity("org/sales", "doomed-agent", "member", idRoot);
    await kernel.auth.revoke(doomed.keyId);
    await expect(memManifest(deps, {}, doomed, AGENT)).rejects.toThrow(AuthzError);
    const res = await deps.db.query(
      `SELECT detail FROM audit_log
       WHERE namespace = $1 AND op = 'read' AND purpose = 'manifest'
         AND result = 'denied' AND actor = $2`,
      ["org/sales", "doomed-agent"],
    );
    expect(res.rows.length).toBe(1);
  });

  it("isManifestRow: belt filter rejects pointer/cache/closed/inactive rows", () => {
    const ok = derivedRow("org", "plain", {});
    ok.provenance = [{ source: "conversation", actor: "a", ts: ok.assertionTime }];
    expect(isManifestRow(ok)).toBe(true);
    expect(isManifestRow(derivedRow("org", "p", { pointer: true }))).toBe(false);
    expect(isManifestRow(derivedRow("org", "c", { cache: true }))).toBe(false);
    const closed = { ...ok, tValidTo: ok.assertionTime };
    expect(isManifestRow(closed)).toBe(false);
    const archived = { ...ok, status: "archived" as const };
    expect(isManifestRow(archived)).toBe(false);
  });

  it("parseManifestArgs: validates variant/maxBytes/format, rejects unknowns", () => {
    expect(parseManifestArgs({})).toEqual({ args: {}, format: "json" });
    expect(parseManifestArgs({ variant: "full", maxBytes: "2048", format: "text" }))
      .toEqual({ args: { variant: "full", maxBytes: 2048 }, format: "text" });
    expect(() => parseManifestArgs({ variant: "everything" })).toThrow(ManifestArgsError);
    expect(() => parseManifestArgs({ maxBytes: "-5" })).toThrow(ManifestArgsError);
    expect(() => parseManifestArgs({ maxBytes: "lots" })).toThrow(ManifestArgsError);
    expect(() => parseManifestArgs({ format: "xml" })).toThrow(ManifestArgsError);
    expect(() => parseManifestArgs({ namespace: "org" })).toThrow(ManifestArgsError);
  });
});
