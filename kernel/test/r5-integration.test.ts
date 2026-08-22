import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";
import type { MemWriteResult } from "../src/syscalls/index.js";
import type { Identity, Role, WriteResult } from "../src/types.js";

const AGENT = "r5-integration";
const CANARY = "R5 mounted canary: platinum refunds require case RF-7421.";

let kernel: Kernel;
let knowledgeDir: string;
let root: Identity;
let tenantOwner: Identity;
let sourceAdmin: Identity;
let consumerAdmin: Identity;
let memoryId: string;

function sync(result: MemWriteResult): WriteResult {
  if ("ticket" in result) throw new Error("unexpected async write ticket");
  return result;
}

async function issueIdentity(
  namespace: string,
  actor: string,
  role: Role,
  caller?: Identity,
): Promise<Identity> {
  const { plaintext } = await kernel.auth.issueKey(namespace, actor, role, caller ?? null);
  const identity = await kernel.auth.resolve(plaintext);
  if (!identity) throw new Error("issued key failed to resolve");
  return identity;
}

describe("R5 user-visible pin and share lifecycle", () => {
  beforeAll(async () => {
    knowledgeDir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-r5-integration-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });

    root = await issueIdentity("", "platform-owner", "owner");
    tenantOwner = await issueIdentity("acme", "owner@acme.test", "owner", root);
    sourceAdmin = await issueIdentity("acme/source", "source@acme.test", "admin", tenantOwner);
    consumerAdmin = await issueIdentity("acme/consumer", "consumer@acme.test", "admin", tenantOwner);

    const written = sync(await kernel.memWrite({
      scope: "team",
      content: CANARY,
      hints: { verbatim: true, type: "policy" },
    }, sourceAdmin, AGENT));
    memoryId = written.stored[0]!.id;
  }, 120_000);

  afterAll(async () => {
    await kernel?.close();
    await fs.rm(knowledgeDir, { recursive: true, force: true });
  });

  it("makes a mounted memory immediately usable, prioritizable, and immediately revocable", async () => {
    const before = await kernel.memRead({ id: memoryId }, consumerAdmin, AGENT);
    // Transport intentionally collapses unauthorized IDs to a normal miss so
    // callers cannot use mem.read as a cross-namespace existence oracle.
    expect(before).toMatchObject({ found: false, denied: false });

    const shared = await kernel.memShare(
      { kind: "memory", ref: memoryId },
      consumerAdmin.namespace,
      tenantOwner,
    );

    const read = await kernel.memRead({ id: memoryId }, consumerAdmin, AGENT);
    expect(read.found).toBe(true);
    expect(read.memory?.content).toBe(CANARY);

    const search = await kernel.memSearch({ query: "platinum RF-7421", k: 8 }, consumerAdmin, AGENT);
    expect(search.some((hit) => hit.id === memoryId && hit.content === CANARY)).toBe(true);
    const mountedStats = await kernel.memStats({}, consumerAdmin, AGENT);
    expect(mountedStats.l2Count).toBe(1);
    expect(mountedStats.topAccessed.some((fact) => fact.id === memoryId)).toBe(true);

    const pin = await kernel.memPin({ kind: "memory", ref: memoryId }, consumerAdmin);
    const assembledPinned = await kernel.memAssemble({ taskHint: "unrelated weekly planning" }, consumerAdmin, AGENT);
    expect(assembledPinned.blocks.some((block) =>
      block.kind === "pinned-memory" && block.ref === memoryId && block.content === CANARY,
    )).toBe(true);

    await kernel.memUnpin(pin.pin.id, consumerAdmin);
    const assembledUnpinned = await kernel.memAssemble({ taskHint: "unrelated weekly planning" }, consumerAdmin, AGENT);
    expect(assembledUnpinned.blocks.some((block) =>
      block.kind === "pinned-memory" && block.ref === memoryId,
    )).toBe(false);

    await kernel.sharing.revokeMount(tenantOwner, shared.mount.id);

    const revokedRead = await kernel.memRead({ id: memoryId }, consumerAdmin, AGENT);
    expect(revokedRead).toMatchObject({ found: false, denied: false });
    const revokedSearch = await kernel.memSearch({ query: "platinum RF-7421", k: 8 }, consumerAdmin, AGENT);
    expect(revokedSearch.some((hit) => hit.id === memoryId)).toBe(false);
    const revokedWorkingSet = await kernel.memAssemble({ taskHint: "platinum RF-7421" }, consumerAdmin, AGENT);
    expect(revokedWorkingSet.blocks.some((block) => block.ref === memoryId)).toBe(false);
    const revokedStats = await kernel.memStats({}, consumerAdmin, AGENT);
    expect(revokedStats.l2Count).toBe(0);
    expect(revokedStats.topAccessed.some((fact) => fact.id === memoryId)).toBe(false);
  }, 120_000);

  it("denies and audits a cross-tenant share", async () => {
    await expect(kernel.memShare(
      { kind: "memory", ref: memoryId },
      "globex/consumer",
      root,
    )).rejects.toThrow("cross-tenant mounts are denied");

    const events = await kernel.audit.list("");
    expect(events.some((event) =>
      event.op === "share" &&
      event.result === "denied" &&
      event.detail === "cross-tenant mounts are denied",
    )).toBe(true);
  });
});
