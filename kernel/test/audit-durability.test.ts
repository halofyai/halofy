/** R3B — syscall outcomes never succeed without durable D4 evidence. */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { promises as fs } from "node:fs";
import { randomBytes } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";

import { Kernel } from "../src/kernel.js";
import type { AuditEvent, Identity, Role, WriteResult } from "../src/types.js";
import type { Db } from "../src/db/client.js";
import type { MemWriteResult } from "../src/syscalls/index.js";

const NS = "audit-durability";
const OTHER_NS = "audit-durability-other";
const AGENT = "audit-durability-test";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let member: Identity;
let foreign: Identity;
let auditor: Identity;

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async ticket");
  return result;
}

async function issue(namespace: string, actor: string, role: Role): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, root);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued identity did not resolve");
  return identity;
}

function failAuditWhen(predicate: (event: AuditEvent) => boolean): void {
  const real = kernel.audit.appendTo.bind(kernel.audit);
  vi.spyOn(kernel.audit, "appendTo").mockImplementation(
    async (db: Db, event: AuditEvent): Promise<void> => {
      if (predicate(event)) throw new Error("injected audit sink failure");
      await real(db, event);
    },
  );
  // The usage-instrumented ops (D36) append through the seq-returning twin;
  // the same injected sink failure must cover both seams or those syscalls
  // could succeed without durable D4 evidence.
  const realWithSeq = kernel.audit.appendToWithSeq.bind(kernel.audit);
  vi.spyOn(kernel.audit, "appendToWithSeq").mockImplementation(
    async (db: Db, event: AuditEvent): Promise<number> => {
      if (predicate(event)) throw new Error("injected audit sink failure");
      return await realWithSeq(db, event);
    },
  );
}

async function accessCount(id: string): Promise<number> {
  const res = await kernel.db.query("SELECT access_count FROM memory_objects WHERE id = $1", [id]);
  return Number((res.rows[0] as { access_count: unknown }).access_count);
}

async function namespaceFaultCount(): Promise<number> {
  const res = await kernel.db.query(
    "SELECT coalesce(sum(fault_count), 0) AS n FROM memory_objects WHERE namespace = $1",
    [NS],
  );
  return Number((res.rows[0] as { n: unknown }).n);
}

describe("R3B durable syscall audit", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-audit-durability-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    const first = await kernel.auth.issueKey("", "root", "owner");
    const resolved = await kernel.auth.resolve(first.plaintext);
    if (!resolved) throw new Error("root identity did not resolve");
    root = resolved;
    member = await issue(NS, "member", "member");
    foreign = await issue(OTHER_NS, "foreign", "member");
    auditor = await issue(NS, "auditor", "auditor");
  }, 120_000);

  afterEach(() => vi.restoreAllMocks());

  afterAll(async () => {
    vi.restoreAllMocks();
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("rolls back read access telemetry when the success audit fails", async () => {
    const written = sync(await kernel.memWrite({
      scope: "user",
      content: "durable read canary lowercase",
      hints: { verbatim: true },
    }, member, AGENT));
    const id = written.stored[0]!.id;
    const before = await accessCount(id);
    failAuditWhen((event) => event.op === "read" && event.result === "ok");

    await expect(kernel.memRead({ id }, member, AGENT)).rejects.toThrow("injected audit sink failure");
    expect(await accessCount(id)).toBe(before);
  });

  it("does not return miss or denied when their audit append fails", async () => {
    failAuditWhen((event) => event.op === "read" && (event.result === "miss" || event.result === "denied"));
    await expect(kernel.memRead({ id: "missing-audit-durability" }, member, AGENT))
      .rejects.toThrow("injected audit sink failure");

    vi.restoreAllMocks();
    const written = sync(await kernel.memWrite({
      scope: "user",
      content: "foreign read canary lowercase",
      hints: { verbatim: true },
    }, member, AGENT));
    failAuditWhen((event) => event.op === "read" && event.result === "denied");
    await expect(kernel.memRead({ id: written.stored[0]!.id }, foreign, AGENT))
      .rejects.toThrow("injected audit sink failure");
  });

  it("fails search, assembly, and stats instead of returning unaudited results", async () => {
    for (const [op, call] of [
      ["search", () => kernel.memSearch({ query: "no matching durability fact" }, member, AGENT)],
      ["assemble", () => kernel.memAssemble({}, member, AGENT)],
      ["stats", () => kernel.memStats({}, member, AGENT)],
    ] as const) {
      failAuditWhen((event) => event.op === op && event.result !== "error");
      await expect(call()).rejects.toThrow("injected audit sink failure");
      vi.restoreAllMocks();
    }
  });

  it("rolls back fault telemetry when its success audit fails", async () => {
    const written = sync(await kernel.memWrite({
      scope: "user",
      content: "fault durability canary lowercase",
      hints: { verbatim: true },
    }, member, AGENT));
    const id = written.stored[0]!.id;
    const before = await accessCount(id);
    failAuditWhen((event) => event.op === "fault" && event.result === "ok");

    await expect(kernel.memFault({ query: "fault durability canary lowercase" }, member, AGENT))
      .rejects.toThrow("injected audit sink failure");
    expect(await accessCount(id)).toBe(before);
  });

  it("rolls back fault-pressure telemetry when its miss audit fails", async () => {
    const written = sync(await kernel.memWrite({
      scope: "user",
      content: "ordinary support preference lowercase",
      hints: { verbatim: true },
    }, member, AGENT));
    expect(written.stored).toHaveLength(1);
    const before = await namespaceFaultCount();
    failAuditWhen((event) => event.op === "fault" && event.result === "miss");

    await expect(kernel.memFault({ query: "zxqv blorp unrelated gibberish" }, member, AGENT))
      .rejects.toThrow("injected audit sink failure");
    expect(await namespaceFaultCount()).toBe(before);
  });

  it("rolls back a memory write when its success audit fails", async () => {
    const content = "write rollback durability canary lowercase";
    failAuditWhen((event) => event.op === "write" && event.result === "ok");

    await expect(kernel.memWrite({ scope: "user", content, hints: { verbatim: true } }, member, AGENT))
      .rejects.toThrow("injected audit sink failure");
    const res = await kernel.db.query("SELECT count(*) AS n FROM memory_objects WHERE content = $1", [content]);
    expect(Number((res.rows[0] as { n: unknown }).n)).toBe(0);
  });

  it("rolls back extracted entity mutations with the memory and success audit", async () => {
    const content = "Zorvella signed the durable registry agreement";
    const fencesBefore = await kernel.db.query<{ namespace: string; generation: number | string }>(
      "SELECT namespace, generation FROM erasure_fences ORDER BY namespace",
    );
    failAuditWhen((event) => event.op === "write" && event.result === "ok");

    await expect(kernel.memWrite({ scope: "user", content }, member, AGENT))
      .rejects.toThrow("injected audit sink failure");

    const entities = await kernel.db.query(
      "SELECT id FROM entity_registry WHERE namespace = $1 AND canonical_name = $2",
      [NS, "Zorvella"],
    );
    const memories = await kernel.db.query(
      "SELECT id FROM memory_objects WHERE namespace = $1 AND content LIKE $2",
      [NS, "%Zorvella%"],
    );
    const fencesAfter = await kernel.db.query<{ namespace: string; generation: number | string }>(
      "SELECT namespace, generation FROM erasure_fences ORDER BY namespace",
    );
    expect(entities.rows).toHaveLength(0);
    expect(memories.rows).toHaveLength(0);
    expect(fencesAfter.rows.map((row) => ({ ...row, generation: Number(row.generation) })))
      .toEqual(fencesBefore.rows.map((row) => ({ ...row, generation: Number(row.generation) })));
  });

  it("fails a role denial closed when the denied audit cannot be written", async () => {
    failAuditWhen((event) => event.op === "write" && event.result === "denied");
    await expect(kernel.memWrite({
      scope: "user",
      content: "auditor must not write",
      hints: { verbatim: true },
    }, auditor, AGENT)).rejects.toThrow("injected audit sink failure");
  });

  it("does not enqueue an async mutation when acceptance audit fails", async () => {
    const content = "async audit durability canary lowercase";
    failAuditWhen((event) => event.detail === "async write accepted for enqueue");
    await expect(kernel.memWrite({
      scope: "user",
      content,
      hints: { verbatim: true },
      async: true,
    }, member, AGENT)).rejects.toThrow("injected audit sink failure");
    await kernel.writeQueue.drain();
    const res = await kernel.db.query("SELECT count(*) AS n FROM memory_objects WHERE content = $1", [content]);
    expect(Number((res.rows[0] as { n: unknown }).n)).toBe(0);
  });

  it("preserves the primary syscall error when its error audit also fails", async () => {
    vi.spyOn(kernel.index, "getById").mockRejectedValueOnce(new Error("primary read failure"));
    failAuditWhen((event) => event.op === "read" && event.result === "error");
    await expect(kernel.memRead({ id: "irrelevant" }, member, AGENT))
      .rejects.toThrow("primary read failure");
    const res = await kernel.db.query(
      `SELECT result, detail FROM audit_log
       WHERE actor = $1 AND op = 'read'
       ORDER BY seq DESC LIMIT 1`,
      [member.actor],
    );
    expect(res.rows[0]).toMatchObject({
      result: "error",
      detail: "primary read failure",
    });
  });
});
