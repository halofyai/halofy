import { afterEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";
import { ColdStore } from "../src/cold/index.js";
import { Kernel } from "../src/kernel.js";
import { forget } from "../src/erasure/index.js";
import type { Db } from "../src/db/client.js";
import type { Concept, Identity, MemoryObject } from "../src/types.js";

const dirs: string[] = [];
const NOW = "2026-07-10T00:00:00.000Z";

function privateConcept(
  pathname: string,
  namespace: string,
  body: string,
  piiSubjects: string[],
): Concept {
  return {
    path: pathname,
    namespace,
    type: "policy",
    title: "Private subject concept",
    description: "Tenant-only subject data",
    tags: ["private"],
    piiSubjects,
    body,
  };
}

function memory(id: string, namespace: string, actor: string): MemoryObject {
  return {
    id,
    namespace,
    scope: "team",
    tier: "L2",
    backendRef: "inline",
    content: `L2 private data authored by ${actor}`,
    type: "fact",
    confidence: 0.9,
    eventTime: null,
    assertionTime: NOW,
    tValidFrom: NOW,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "conversation", actor, ts: NOW }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
}

async function identity(kernel: Kernel, key: string): Promise<Identity> {
  const resolved = await kernel.auth.resolve(key);
  if (!resolved) throw new Error("identity did not resolve");
  return resolved;
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("private L3 erasure", () => {
  it("rejects public PII metadata and persists normalized private subjects", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-pii-"));
    dirs.push(dir);
    await fs.writeFile(
      path.join(dir, "invalid-public.md"),
      "---\ntype: policy\nvisibility: public\npii_subjects:\n  - Alice@Example.com\n---\npublic body\n",
    );
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      expect((await kernel.db.query("SELECT count(*) AS n FROM concepts")).rows[0]!.n).toBe(0);
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      await kernel.createPrivateConcept(
        privateConcept(
          "private.okf.enc",
          "acme",
          "SUBJECT-CANARY",
          [" Alice@Example.com ", "ALICE@example.com"],
        ),
        root,
      );
      const row = (await kernel.db.query(
        "SELECT pii_subjects FROM concepts WHERE path = $1",
        ["private.okf.enc"],
      )).rows[0];
      expect(row?.pii_subjects).toEqual(["alice@example.com"]);
    } finally {
      await kernel.close();
    }
  });

  it("crypto-shreds matching L2 and L3 data while retaining undecryptable ciphertext", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-forget-"));
    dirs.push(dir);
    await fs.writeFile(
      path.join(dir, "public.md"),
      "---\ntype: policy\nvisibility: public\ntitle: Public concept\n---\nPUBLIC-SURVIVOR\n",
    );
    const kek = randomBytes(32).toString("base64");
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: kek,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      const acmeKey = await kernel.auth.issueKey("acme", "acme-owner", "owner", root);
      const globexKey = await kernel.auth.issueKey("globex", "globex-owner", "owner", root);
      const acme = await identity(kernel, acmeKey.plaintext);
      const globex = await identity(kernel, globexKey.plaintext);

      const erasedPath = "acme-alice.okf.enc";
      const siblingPath = "globex-alice.okf.enc";
      await kernel.createPrivateConcept(
        privateConcept(erasedPath, "acme", "L3-ALICE-CANARY", [" Alice@Example.com "]),
        root,
      );
      await kernel.createPrivateConcept(
        privateConcept(siblingPath, "globex", "L3-SIBLING-CANARY", ["alice@example.com"]),
        root,
      );
      const l2 = memory("01R2CL2ALICE", "acme/support", "ALICE@example.com");
      const [embedding] = await kernel.embedder.embed([l2.content]);
      await kernel.index.insert(l2, embedding);
      await kernel.setPolicy("acme", `pinnedConcepts:\n  - "${erasedPath}"\n`);
      expect((await kernel.memAssemble({}, acme, "r2c-before")).blocks)
        .toEqual(expect.arrayContaining([expect.objectContaining({ ref: erasedPath })]));

      const ciphertextBefore = await fs.readFile(path.join(dir, erasedPath), "utf8");
      const siblingAttempt = await kernel.memForget(
        { target: { kind: "namespace", value: "acme" } },
        globex,
        "r2c-sibling",
      );
      expect(siblingAttempt.erasedCount).toBe(0);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
        [erasedPath],
      )).rows[0]!.n).toBe(1);

      const result = await kernel.memForget(
        { target: { kind: "actor", value: "ALICE@example.com" } },
        acme,
        "r2c-owner",
      );
      expect(result.erasedCount).toBe(2);
      expect(result.tombstones).toBe(2);
      expect(result.certificate.erasedIds).toEqual(
        ["01R2CL2ALICE", `l3:${erasedPath}`].sort(),
      );
      expect(kernel.verifyCertificate(result.certificate)).toBe(true);

      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
        [erasedPath],
      )).rows[0]!.n).toBe(0);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM concepts WHERE path = $1",
        [erasedPath],
      )).rows[0]!.n).toBe(0);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM memory_objects WHERE id = $1",
        [l2.id],
      )).rows[0]!.n).toBe(0);
      expect((await kernel.db.query(
        "SELECT memory_id FROM tombstones WHERE certificate_id = $1 ORDER BY memory_id",
        [result.certificate.id],
      )).rows.map((row) => row.memory_id)).toEqual(result.certificate.erasedIds);

      expect(await fs.readFile(path.join(dir, erasedPath), "utf8")).toBe(ciphertextBefore);
      expect(await fs.stat(path.join(dir, erasedPath))).toBeTruthy();
      await expect(kernel.createPrivateConcept(
        privateConcept(erasedPath, "acme", "RESURRECTION", ["alice@example.com"]),
        root,
      )).rejects.toThrow(/permanently erased/i);
      const restarted = new ColdStore(dir, kek);
      await restarted.syncToDb(kernel.db, kernel.embedder);
      expect(restarted.warnings.join(" ")).toMatch(/wrapped concept key is missing/i);
      expect(await restarted.readConcept("acme/support", erasedPath)).toBeNull();
      expect((await restarted.searchConcepts(
        kernel.db,
        kernel.embedder,
        "acme/support",
        "L3-ALICE-CANARY",
      )).some((hit) => hit.ref === erasedPath)).toBe(false);
      expect((await kernel.memFault(
        { query: "L3-ALICE-CANARY" },
        acme,
        "r2c-fault",
      )).injected.some((hit) => hit.ref === erasedPath)).toBe(false);
      expect((await kernel.memAssemble({}, acme, "r2c-after")).blocks
        .some((block) => block.ref === erasedPath)).toBe(false);

      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM concepts WHERE path = $1",
        [siblingPath],
      )).rows[0]!.n).toBe(1);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM concepts WHERE visibility = 'public' AND body LIKE '%PUBLIC-SURVIVOR%'",
      )).rows[0]!.n).toBe(1);
      expect(await fs.readFile(path.join(dir, "public.md"), "utf8")).toContain("PUBLIC-SURVIVOR");

      // A tombstone, not the presence of ciphertext, is the permanent path
      // fence: deleting the retained blob must not permit resurrection.
      await fs.rm(path.join(dir, erasedPath));
      await expect(kernel.createPrivateConcept(
        privateConcept(erasedPath, "acme", "RECREATE-AFTER-BLOB-DELETE", ["alice@example.com"]),
        root,
      )).rejects.toThrow(/permanently erased/i);
    } finally {
      await kernel.close();
    }
  });

  it("namespace erasure shreds private descendants but never public concepts", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-namespace-"));
    dirs.push(dir);
    await fs.writeFile(
      path.join(dir, "public.md"),
      "---\ntype: policy\nvisibility: public\ntitle: Public concept\n---\nPUBLIC-KEEP\n",
    );
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      await kernel.createPrivateConcept(
        privateConcept("child.okf.enc", "acme/team", "CHILD-PRIVATE", []),
        root,
      );
      const result = await kernel.memForget(
        { target: { kind: "namespace", value: "acme" } },
        root,
        "r2c-root",
      );
      expect(result.certificate.erasedIds).toContain("l3:child.okf.enc");
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM concepts WHERE path = 'public.md'",
      )).rows[0]!.n).toBe(1);
    } finally {
      await kernel.close();
    }
  });

  it("accepts a stable l3:path memory target with management-scope ACL", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-memory-target-"));
    dirs.push(dir);
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: randomBytes(32).toString("base64"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      const globexKey = await kernel.auth.issueKey("globex", "globex-owner", "owner", root);
      const globex = await identity(kernel, globexKey.plaintext);
      const concept = privateConcept("target.okf.enc", "acme", "TARGET", []);
      await kernel.createPrivateConcept(concept, root);

      expect((await kernel.memForget(
        { target: { kind: "memory", value: `l3:${concept.path}` } },
        globex,
      )).erasedCount).toBe(0);
      const result = await kernel.memForget(
        { target: { kind: "memory", value: `l3:${concept.path}` } },
        root,
      );
      expect(result.certificate.erasedIds).toEqual([`l3:${concept.path}`]);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
        [concept.path],
      )).rows[0]!.n).toBe(0);
    } finally {
      await kernel.close();
    }
  });

  it("terminally erases a pending write before its blob can publish", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-pending-race-"));
    dirs.push(dir);
    const kek = randomBytes(32).toString("base64");
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: kek,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      const concept = privateConcept(
        "pending-race.okf.enc",
        "acme",
        "PENDING-RACE-CANARY",
        ["pending@example.com"],
      );
      let inserted!: () => void;
      const insertedSignal = new Promise<void>((resolve) => { inserted = resolve; });
      let release!: () => void;
      const publishGate = new Promise<void>((resolve) => { release = resolve; });
      const blockedDb = {
        query: async (sql: string, params?: unknown[]) => {
          const result = await kernel.db.query(sql, params);
          if (/INSERT INTO cold_concept_keys/i.test(sql)) {
            inserted();
            await publishGate;
          }
          return result;
        },
      };
      const store = new ColdStore(dir, kek);
      const writeOutcome = store.writePrivateConcept(blockedDb, concept)
        .then(() => null, (error: unknown) => error as Error);
      await insertedSignal;
      expect((await kernel.db.query(
        "SELECT write_state FROM cold_concept_keys WHERE path = $1",
        [concept.path],
      )).rows[0]!.write_state).toBe("pending");

      const erased = await kernel.memForget(
        { target: { kind: "actor", value: "pending@example.com" } },
        root,
        "pending-race",
      );
      expect(erased.certificate.erasedIds).toEqual([`l3:${concept.path}`]);
      release();
      expect((await writeOutcome)?.message).toMatch(/erased before commit/i);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
        [concept.path],
      )).rows[0]!.n).toBe(0);
      expect(await fs.readFile(path.join(dir, concept.path), "utf8")).not.toContain("PENDING-RACE-CANARY");
      await expect(store.writePrivateConcept(kernel.db, concept)).rejects.toThrow(/permanently erased/i);
    } finally {
      await kernel.close();
    }
  });

  it("rejects a stale writer whose insert waited behind an erasure fence", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-reverse-race-"));
    dirs.push(dir);
    const kek = randomBytes(32).toString("base64");
    const kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: dir,
      coldKek: kek,
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    try {
      const rootKey = await kernel.auth.issueKey("", "root", "owner");
      const root = await identity(kernel, rootKey.plaintext);
      const concept = privateConcept("reverse-race.okf.enc", "acme", "REVERSE-RACE", []);

      let snapshotRead!: () => void;
      const snapshotSignal = new Promise<void>((resolve) => { snapshotRead = resolve; });
      let releaseSnapshot!: () => void;
      const snapshotGate = new Promise<void>((resolve) => { releaseSnapshot = resolve; });
      let insertAttempted!: () => void;
      const insertAttemptSignal = new Promise<void>((resolve) => { insertAttempted = resolve; });
      const writerDb = {
        query: async (sql: string, params?: unknown[]) => {
          if (/INSERT INTO cold_concept_keys/i.test(sql)) insertAttempted();
          const result = await kernel.db.query(sql, params);
          if (/SELECT namespace, generation FROM erasure_fences/i.test(sql)) {
            snapshotRead();
            await snapshotGate;
          }
          return result;
        },
      };
      const store = new ColdStore(dir, kek);
      const writeOutcome = store.writePrivateConcept(writerDb, concept)
        .then(() => null, (error: unknown) => error as Error);
      await snapshotSignal;

      let fenceHeld!: () => void;
      const fenceHeldSignal = new Promise<void>((resolve) => { fenceHeld = resolve; });
      let releaseErase!: () => void;
      const eraseGate = new Promise<void>((resolve) => { releaseErase = resolve; });
      const eraseDb: Db = {
        query: (sql, params) => kernel.db.query(sql, params),
        close: () => Promise.resolve(),
        transaction: (fn) => kernel.db.transaction((tx) => {
          const wrapped: Db = {
            query: async (sql, params) => {
              const result = await tx.query(sql, params);
              if (/INSERT INTO erasure_fences/i.test(sql)) {
                fenceHeld();
                await eraseGate;
              }
              return result;
            },
            transaction: tx.transaction.bind(tx),
            close: tx.close.bind(tx),
          };
          return fn(wrapped);
        }),
      };
      const erasePromise = forget(
        { db: eraseDb, audit: kernel.audit, signingKey: kernel.signingKey },
        { kind: "namespace", value: "acme" },
        root,
      );
      await fenceHeldSignal;
      releaseSnapshot();
      await insertAttemptSignal;
      releaseErase();

      expect((await erasePromise).erasedCount).toBe(0);
      expect((await writeOutcome)?.message).toMatch(/fenced by erasure/i);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
        [concept.path],
      )).rows[0]!.n).toBe(0);
      expect((await kernel.db.query(
        "SELECT count(*) AS n FROM concepts WHERE path = $1",
        [concept.path],
      )).rows[0]!.n).toBe(0);
    } finally {
      await kernel.close();
    }
  });
});
