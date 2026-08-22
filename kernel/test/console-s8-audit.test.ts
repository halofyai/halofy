/**
 * S8 — the audit trail's honesty guarantees.
 *
 * Every case here is a defect the screen shipped with, pinned so it cannot
 * come back:
 *
 *   1. The op filter allowlist drifted behind the audited vocabulary, and the
 *      transport DROPS an unknown op instead of rejecting it — so filtering by
 *      `conversation_read` silently returned the unfiltered trail.
 *   2. `until=2026-07-31` bound a TIMESTAMPTZ column at that day's midnight and
 *      discarded the whole last day of the range.
 *   3. A malformed date was passed straight to the database.
 *   4. The screen took the default 100-row page and said nothing about it, and
 *      there was no export at all — so "this is the trail" was never true.
 *
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, loopback HTTP only.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

import { Kernel } from "../src/kernel.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/index.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { AUDIT_OPS } from "../src/types.js";
import type { AuditOp, Identity } from "../src/types.js";
import { AUDIT_OP_LABELS, auditExportCsv, type KernelSlice } from "../src/console/api.js";

let kernel: Kernel;
let slice: KernelSlice;
let server: HaloHttpServer;
let baseUrl: string;
let ownerKey: string;
let auditorKey: string;
let memberKey: string;
let acmeOwner: Identity;

const CONSOLE_DIR = fileURLToPath(new URL("../console", import.meta.url));
const S8_PATH = fileURLToPath(new URL("../console/screens/s8.js", import.meta.url));

/** One audit row, appended directly — this suite is about reading the trail. */
async function appendRow(
  namespace: string,
  actor: string,
  op: AuditOp,
  ts: string,
  extra: { detail?: string; result?: "ok" | "denied" | "miss" | "error" } = {},
): Promise<void> {
  await kernel.audit.append({
    ts,
    actor,
    agentId: "s8-test",
    op,
    memoryId: null,
    namespace,
    purpose: null,
    result: extra.result ?? "ok",
    ...(extra.detail === undefined ? {} : { detail: extra.detail }),
  });
}

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });

  const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root owner failed to resolve");

  const acme = await kernel.auth.issueKey("acme", "owner@acme.test", "owner", root);
  ownerKey = acme.plaintext;
  const resolved = await kernel.auth.resolve(ownerKey);
  if (!resolved) throw new Error("acme owner failed to resolve");
  acmeOwner = resolved;

  auditorKey = (await kernel.auth.issueKey("acme", "auditor@acme.test", "auditor", root))
    .plaintext;
  memberKey = (await kernel.auth.issueKey("acme", "member@acme.test", "member", root))
    .plaintext;

  slice = {
    db: kernel.db,
    audit: kernel.audit,
    auth: { list: (id) => kernel.auth.list(id) },
    sources: { list: (ns, global) => kernel.sources.list(ns, global) },
    budget: { monthToDateUsd: (ns) => kernel.budget.monthToDateUsd(ns) },
    tenants: { resolveTenant: (ns) => kernel.tenants.resolveTenant(ns) },
    listUsers: async () => [],
    getPolicy: (ns) => kernel.getPolicy(ns),
  };

  // 620 rows inside acme — past BOTH the 100-row default and the 500-row cap,
  // so an export that stopped at either is visible as a wrong count.
  for (let i = 0; i < 620; i++) {
    await appendRow(
      "acme",
      "dana@acme.test",
      "read",
      new Date(Date.UTC(2026, 6, 1, 0, 0, i)).toISOString(),
    );
  }
  // A last-day-of-range event: the `until` off-by-one dropped exactly this row.
  await appendRow("acme", "dana@acme.test", "write", "2026-07-31T18:30:00.000Z");
  // An op that did not exist when the filter allowlist was written.
  await appendRow("acme", "dana@acme.test", "conversation_read", "2026-07-15T09:00:00.000Z");
  // A hostile detail: a spreadsheet formula, which CSV must neutralise.
  await appendRow("acme", "dana@acme.test", "forget", "2026-07-16T09:00:00.000Z", {
    detail: '=cmd|"/c calc"!A1',
    result: "denied",
  });
  // A sibling tenant's row — must never appear in acme's trail or export.
  await appendRow("rival", "spy@rival.test", "read", "2026-07-20T09:00:00.000Z");

  server = createHttpServer(
    buildHttpDeps(kernel, { consoleDir: CONSOLE_DIR, secureCookies: false }),
  );
  const port = await server.start(0);
  baseUrl = `http://127.0.0.1:${port}`;
}, 180_000);

afterAll(async () => {
  await server.stop();
});

function get(path: string, key: string = ownerKey): Promise<Response> {
  return fetch(`${baseUrl}${path}`, {
    headers: { authorization: `Bearer ${key}` },
  });
}

describe("S8 op vocabulary", () => {
  it("the transport accepts EVERY audited op, not a stale subset", async () => {
    // The regression: `conversation_read` was not in the allowlist, was dropped
    // silently, and the response came back unfiltered.
    const res = await get("/v1/admin/audit?op=conversation_read&limit=500");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as { op: string }[];
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((row) => row.op === "conversation_read")).toBe(true);
  });

  it("every canonical op has a plain-English label on BOTH surfaces", async () => {
    for (const op of AUDIT_OPS) {
      expect(AUDIT_OP_LABELS[op], `server label for ${op}`).toBeTruthy();
    }
    // The console keeps its own mirror (it cannot import TypeScript), so the
    // parity is asserted against the source rather than assumed.
    const s8 = await readFile(S8_PATH, "utf8");
    for (const op of AUDIT_OPS) {
      expect(s8, `console picker entry for ${op}`).toContain(`["${op}", "`);
    }
  });
});

describe("S8 exact summary", () => {
  it("counts the complete filtered, subtree-scoped trail past the 500-row screen cap", async () => {
    const res = await get("/v1/admin/audit/summary?op=read");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      events: 620,
      blocked: 0,
      deletions: 0,
      exports: 0,
    });
    expect((await get("/v1/admin/audit/summary?op=read", auditorKey)).status).toBe(200);
    expect((await get("/v1/admin/audit/summary?op=read", memberKey)).status).toBe(403);
  });
});

describe("S8 date range", () => {
  it("an `until` date includes that whole day (the off-by-one)", async () => {
    const res = await get("/v1/admin/audit?since=2026-07-31&until=2026-07-31&limit=500");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as { ts: string; op: string }[];
    expect(rows.map((row) => row.op)).toContain("write");
  });

  it("a malformed date is a 400, never a filter that quietly widens", async () => {
    const res = await get("/v1/admin/audit?since=july");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: string; error: string };
    expect(body.code).toBe("bad_request");
    expect(body.error).toContain("since");
  });
});

describe("S8 CSV export", () => {
  it("exports the COMPLETE trail, past the screen's 500-row cap", async () => {
    const screen = await kernel.auditSearch(acmeOwner, { limit: 5000 });
    expect(screen.length).toBe(500); // the search cap, unchanged

    const csv = await kernel.auditExportCsv(acmeOwner, {});
    const dataRows = csv.csv.trimEnd().split("\r\n").slice(1);
    expect(csv.rowCount).toBeGreaterThan(500);
    expect(csv.rowCount).toBe(dataRows.length);
    expect(csv.truncated).toBe(false);
    expect(csv.filename).toMatch(/^halomem-audit-acme-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  it("keeps the caller's ACL fence - a sibling tenant never leaks", async () => {
    const csv = await kernel.auditExportCsv(acmeOwner, {});
    expect(csv.csv).not.toContain("spy@rival.test");
    expect(csv.csv).not.toContain("rival");
  });

  it("honours the same filters as the table", async () => {
    const csv = await kernel.auditExportCsv(acmeOwner, { op: "conversation_read" });
    expect(csv.rowCount).toBe(1);
    expect(csv.csv).toContain("Read assistant history");
  });

  it("neutralises spreadsheet formulas in attacker-influenced fields", async () => {
    const csv = await kernel.auditExportCsv(acmeOwner, { op: "forget" });
    // Quoted AND prefixed: Excel must read it as text, not execute it.
    expect(csv.csv).toContain(`"'=cmd|""/c calc""!A1"`);
    expect(csv.csv).not.toContain(`"=cmd`);
  });

  it("is itself a governed egress - one export audit row per download", async () => {
    const before = await kernel.auditSearch(acmeOwner, { op: "export", limit: 500 });
    const csv = await auditExportCsv(slice, acmeOwner, { op: "forget" });
    const after = await kernel.auditSearch(acmeOwner, { op: "export", limit: 500 });
    expect(after.length).toBe(before.length + 1);
    const row = after[0]!;
    expect(row.purpose).toBe("audit-trail-csv");
    expect(row.result).toBe("ok");
    const detail = JSON.parse(row.detail ?? "{}") as {
      rowCount: number;
      sha256: string;
      truncated: boolean;
    };
    expect(detail.rowCount).toBe(csv.rowCount);
    expect(detail.sha256).toBe(csv.sha256);
    expect(detail.truncated).toBe(false);
  });

  it("rides the same roles as the trail: auditor reads it, member cannot", async () => {
    // A regulator downloads evidence; a member has no business reading the
    // organization's trail, and the screen is not the gate — the route is.
    expect((await get("/v1/admin/audit/export.csv?op=forget", auditorKey)).status).toBe(200);
    expect((await get("/v1/admin/audit/export.csv?op=forget", memberKey)).status).toBe(403);
  });

  it("serves the download with its own completeness headers", async () => {
    const res = await get("/v1/admin/audit/export.csv?op=conversation_read");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/csv");
    expect(res.headers.get("content-disposition")).toContain("attachment");
    expect(res.headers.get("x-audit-rows")).toBe("1");
    expect(res.headers.get("x-audit-truncated")).toBe("false");
    // Byte-level: `Response.text()` strips a BOM, so assert the actual bytes —
    // without it Excel renders a non-ASCII actor name as mojibake.
    const bytes = new Uint8Array(await res.arrayBuffer());
    expect([bytes[0], bytes[1], bytes[2]]).toEqual([0xef, 0xbb, 0xbf]);
    expect(new TextDecoder().decode(bytes)).toContain("What happened");
  });
});
