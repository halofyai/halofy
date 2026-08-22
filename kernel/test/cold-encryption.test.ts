import { afterEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createDecipheriv, randomBytes } from "node:crypto";
import { ColdStore } from "../src/cold/index.js";
import { Kernel } from "../src/kernel.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import type { Concept, Embedder } from "../src/types.js";

const DIM = 16;
const dirs: string[] = [];

const embedder: Embedder = {
  name: "cold-encryption-test",
  dim: DIM,
  async embed(texts: string[]) {
    return texts.map((text) => {
      const out = Array.from({ length: DIM }, () => 0);
      for (let i = 0; i < text.length; i++) out[i % DIM]! += text.charCodeAt(i) / 1000;
      return out;
    });
  },
};

function privateConcept(pathname: string, namespace = "acme"): Concept {
  return {
    path: pathname,
    namespace,
    type: "policy",
    title: "Private refund rule",
    description: "Tenant-only policy",
    tags: ["refund"],
    body: "SECRET-CANARY refunds over 100 require finance approval",
  };
}

async function setup(): Promise<{ dir: string; db: Db; kek: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-enc-"));
  dirs.push(dir);
  const db = await createDb(loadConfig({ knowledgeDir: dir, embedDim: DIM }));
  await migrate(db, DIM);
  return { dir, db, kek: randomBytes(32).toString("base64") };
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("encrypted private L3 concepts", () => {
  it("round-trips through ciphertext and survives a ColdStore restart", async () => {
    const { dir, db, kek } = await setup();
    const first = new ColdStore(dir, kek);
    await first.writePrivateConcept(db, privateConcept("concepts/refund.okf.enc"));

    const raw = await fs.readFile(path.join(dir, "concepts", "refund.okf.enc"), "utf8");
    expect(raw).not.toContain("SECRET-CANARY");
    expect(raw).not.toContain("acme");
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(
      ["alg", "ciphertext", "iv", "tag", "version"].sort(),
    );
    expect(JSON.parse(raw).version).toBe(2);

    expect(await first.syncToDb(db, embedder)).toBe(1);
    expect((await first.readConcept("acme/team", "concepts/refund.okf.enc"))?.body)
      .toContain("SECRET-CANARY");
    expect(await first.readConcept("globex/team", "concepts/refund.okf.enc")).toBeNull();

    const restarted = new ColdStore(dir, kek);
    expect(await restarted.syncToDb(db, embedder)).toBe(1);
    expect((await restarted.readConcept("acme", "concepts/refund.okf.enc"))?.title)
      .toBe("Private refund rule");
    await db.close();
  });

  it("fails closed on missing or wrong KEKs by quarantining the plaintext projection", async () => {
    const { dir, db, kek } = await setup();
    const good = new ColdStore(dir, kek);
    await good.writePrivateConcept(db, privateConcept("private.okf.enc"));
    await good.syncToDb(db, embedder);

    for (const badKek of ["", randomBytes(32).toString("base64")]) {
      const bad = new ColdStore(dir, badKek);
      expect(await bad.syncToDb(db, embedder)).toBe(0);
      expect(bad.warnings.join(" ")).toMatch(/KEK|decrypt|authenticate|key/i);
      const rows = await db.query("SELECT path, body FROM concepts WHERE path = $1", ["private.okf.enc"]);
      expect(rows.rows).toHaveLength(0);
    }
    await db.close();
  });

  it("uses a unique DEK per concept even when plaintext is identical", async () => {
    const { dir, db, kek } = await setup();
    const store = new ColdStore(dir, kek);
    await store.writePrivateConcept(db, privateConcept("one.okf.enc"));
    await store.writePrivateConcept(db, privateConcept("two.okf.enc"));
    const rows = await db.query(
      "SELECT path, namespace, wrapped_dek, wrap_iv, wrap_tag FROM cold_concept_keys ORDER BY path",
    );
    const unwrap = (row: Record<string, unknown>): Buffer => {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        Buffer.from(kek, "base64"),
        Buffer.from(String(row["wrap_iv"]), "base64"),
      );
      decipher.setAAD(Buffer.from(`halomem:cold:v2\n${String(row["path"])}\n${String(row["namespace"])}\ndek`));
      decipher.setAuthTag(Buffer.from(String(row["wrap_tag"]), "base64"));
      return Buffer.concat([
        decipher.update(Buffer.from(String(row["wrapped_dek"]), "base64")),
        decipher.final(),
      ]);
    };
    expect(unwrap(rows.rows[0]!)).not.toEqual(unwrap(rows.rows[1]!));
    await db.close();
  });

  it("rejects duplicate writes without destroying the existing key or blob", async () => {
    const { dir, db, kek } = await setup();
    const store = new ColdStore(dir, kek);
    const original = privateConcept("stable.okf.enc");
    await store.writePrivateConcept(db, original);
    const blobBefore = await fs.readFile(path.join(dir, "stable.okf.enc"), "utf8");
    const keyBefore = (await db.query(
      "SELECT wrapped_dek, wrap_iv, wrap_tag FROM cold_concept_keys WHERE path = $1",
      [original.path],
    )).rows[0];

    await expect(store.writePrivateConcept(db, { ...original, body: "replacement" }))
      .rejects.toThrow();
    expect(await fs.readFile(path.join(dir, "stable.okf.enc"), "utf8")).toBe(blobBefore);
    expect((await db.query(
      "SELECT wrapped_dek, wrap_iv, wrap_tag FROM cold_concept_keys WHERE path = $1",
      [original.path],
    )).rows[0]).toEqual(keyBefore);
    expect(await store.syncToDb(db, embedder)).toBe(1);
    expect((await store.readConcept("acme", original.path))?.body).toContain("SECRET-CANARY");
    await db.close();
  });

  it("uses explicit pending/committed recovery states without guessing from a missing blob", async () => {
    const { dir, db, kek } = await setup();
    const store = new ColdStore(dir, kek);
    const concept = privateConcept("recoverable.okf.enc");
    await store.writePrivateConcept(db, concept);

    await db.query("UPDATE cold_concept_keys SET write_state = 'pending' WHERE path = $1", [concept.path]);
    await expect(store.writePrivateConcept(db, concept)).resolves.toBe(concept.path);
    expect((await db.query(
      "SELECT write_state FROM cold_concept_keys WHERE path = $1",
      [concept.path],
    )).rows[0]!.write_state).toBe("committed");

    await fs.rm(path.join(dir, concept.path));
    await expect(store.writePrivateConcept(db, concept)).rejects.toThrow(/committed.*missing/i);
    expect((await db.query(
      "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
      [concept.path],
    )).rows[0]!.n).toBe(1);

    await db.query("UPDATE cold_concept_keys SET write_state = 'pending' WHERE path = $1", [concept.path]);
    await expect(store.writePrivateConcept(db, concept)).resolves.toBe(concept.path);
    expect((await db.query(
      "SELECT write_state FROM cold_concept_keys WHERE path = $1",
      [concept.path],
    )).rows[0]!.write_state).toBe("committed");
    await db.close();
  });

  it("hides a private projection immediately when its committed key row disappears", async () => {
    const { dir, db, kek } = await setup();
    const store = new ColdStore(dir, kek);
    const concept = privateConcept("joined-read.okf.enc");
    await store.writePrivateConcept(db, concept);
    await store.syncToDb(db, embedder);
    expect(await store.readConcept("acme", concept.path)).not.toBeNull();

    await db.query("DELETE FROM cold_concept_keys WHERE path = $1", [concept.path]);
    expect((await db.query("SELECT count(*) AS n FROM concepts WHERE path = $1", [concept.path])).rows[0]!.n)
      .toBe(1);
    expect(await store.readConcept("acme", concept.path)).toBeNull();
    expect(await store.countConcepts(db, "acme")).toBe(0);
    expect((await store.searchConcepts(db, embedder, "acme", "SECRET-CANARY"))).toEqual([]);
    await db.close();
  });

  it("transactionally rotates wrapped DEKs to a new KEK", async () => {
    const { dir, db, kek } = await setup();
    const oldStore = new ColdStore(dir, kek);
    const concept = privateConcept("rotate.okf.enc");
    await oldStore.writePrivateConcept(db, concept);
    await oldStore.syncToDb(db, embedder);
    const nextKek = randomBytes(32).toString("base64");

    await db.query("UPDATE cold_concept_keys SET write_state = 'pending' WHERE path = $1", [concept.path]);
    await expect(ColdStore.rotateKek(db, kek, nextKek)).rejects.toThrow(/zero pending/i);
    await db.query("UPDATE cold_concept_keys SET write_state = 'committed' WHERE path = $1", [concept.path]);
    await expect(ColdStore.rotateKek(db, kek, nextKek)).resolves.toBe(1);
    const nextStore = new ColdStore(dir, nextKek);
    await expect(nextStore.validateBootConfiguration(db)).resolves.toBeUndefined();
    expect(await nextStore.syncToDb(db, embedder)).toBe(1);
    expect((await nextStore.readConcept("acme", concept.path))?.body).toContain("SECRET-CANARY");
    await expect(ColdStore.rotateKek(db, kek, nextKek)).rejects.toThrow(/old KEK/i);
    await db.close();
  });

  it("rejects an old-KEK writer whose stale fence snapshot spans rotation", async () => {
    const { dir, db, kek } = await setup();
    const oldStore = new ColdStore(dir, kek);
    await oldStore.writePrivateConcept(db, privateConcept("existing-before-rotation.okf.enc"));
    const staleConcept = privateConcept("stale-writer.okf.enc");
    let snapshotted!: () => void;
    const snapshotSignal = new Promise<void>((resolve) => { snapshotted = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const blockedDb = {
      query: async (sql: string, params?: unknown[]) => {
        const result = await db.query(sql, params);
        if (/SELECT namespace, generation FROM erasure_fences/i.test(sql)) {
          snapshotted();
          await gate;
        }
        return result;
      },
    };
    const outcome = oldStore.writePrivateConcept(blockedDb, staleConcept)
      .then(() => null, (error: unknown) => error as Error);
    await snapshotSignal;
    const nextKek = randomBytes(32).toString("base64");
    await ColdStore.rotateKek(db, kek, nextKek);
    release();
    expect((await outcome)?.message).toMatch(/fenced by erasure or KEK rotation/i);
    expect((await db.query(
      "SELECT count(*) AS n FROM cold_concept_keys WHERE path = $1",
      [staleConcept.path],
    )).rows[0]!.n).toBe(0);
    expect((await db.query(
      "SELECT active_kek_id, generation FROM cold_kek_state WHERE singleton = TRUE",
    )).rows[0]!.generation).toBe(2);
    await db.close();
  });

  it("rejects private plaintext instead of implicitly migrating it", async () => {
    const { dir, db, kek } = await setup();
    await fs.writeFile(
      path.join(dir, "illegal.md"),
      "---\ntype: policy\nnamespace: acme\ntitle: Illegal\n---\nplaintext secret\n",
    );
    const store = new ColdStore(dir, kek);
    expect(await store.syncToDb(db, embedder)).toBe(0);
    expect(store.warnings.join(" ")).toContain("private plaintext concepts are forbidden");
    expect((await db.query("SELECT count(*) AS n FROM concepts")).rows[0]!.n).toBe(0);
    expect((await db.query("SELECT count(*) AS n FROM cold_concept_keys")).rows[0]!.n).toBe(0);
    await db.close();
  });

  it("never writes private plaintext or ownership metadata into the repository", async () => {
    const { dir, db, kek } = await setup();
    const store = new ColdStore(dir, kek);
    await store.writePrivateConcept(db, privateConcept("nested/secret.okf.enc", "tenant/private"));
    const files = await fs.readdir(path.join(dir, "nested"));
    expect(files).toEqual(["secret.okf.enc"]);
    const repositoryText = await fs.readFile(path.join(dir, "nested", files[0]!), "utf8");
    expect(repositoryText).not.toMatch(/SECRET-CANARY|tenant\/private|Private refund rule/);
    await db.close();
  });

  it("rejects encrypted writes through a symlink that escapes the knowledge root", async (ctx) => {
    const { dir, db, kek } = await setup();
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-outside-"));
    dirs.push(outside);
    try {
      await fs.symlink(outside, path.join(dir, "escape"), process.platform === "win32" ? "junction" : "dir");
    } catch (err) {
      if (["EPERM", "EACCES", "ENOSYS"].includes((err as NodeJS.ErrnoException).code ?? "")) {
        ctx.skip();
        return;
      }
      throw err;
    }
    const store = new ColdStore(dir, kek);
    await expect(store.writePrivateConcept(db, privateConcept("escape/leak.okf.enc")))
      .rejects.toThrow(/outside|escape/i);
    expect(await fs.readdir(outside)).toEqual([]);
    await db.close();
  });

  it("keeps a sibling canary out of real fault and pinned-allocation paths", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-integration-"));
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
      const root = await kernel.auth.resolve(rootKey.plaintext);
      if (!root) throw new Error("root identity missing");
      const acmeKey = await kernel.auth.issueKey("acme", "acme-agent", "member", root);
      const globexKey = await kernel.auth.issueKey("globex", "globex-agent", "member", root);
      const acme = await kernel.auth.resolve(acmeKey.plaintext);
      const globex = await kernel.auth.resolve(globexKey.plaintext);
      if (!acme || !globex) throw new Error("tenant identity missing");

      await kernel.createPrivateConcept(privateConcept("acme-canary.okf.enc"), root);
      const writeAudit = await kernel.db.query(
        "SELECT result, detail FROM audit_log WHERE op = 'write' AND detail LIKE 'private concept written%' ORDER BY seq DESC LIMIT 1",
      );
      expect(writeAudit.rows[0]?.result).toBe("ok");
      expect(String(writeAudit.rows[0]?.detail)).toContain("acme-canary.okf.enc");

      await expect(
        kernel.createPrivateConcept(privateConcept("denied.okf.enc"), globex),
      ).rejects.toThrow(/owner\/admin required/i);
      const deniedAudit = await kernel.db.query(
        "SELECT result FROM audit_log WHERE op = 'write' AND detail LIKE 'private concept write denied%' ORDER BY seq DESC LIMIT 1",
      );
      expect(deniedAudit.rows[0]?.result).toBe("denied");
      await kernel.setPolicy("globex", 'pinnedConcepts:\n  - "acme-canary.okf.enc"\n');
      const assembled = await kernel.memAssemble({}, globex, "integration");
      expect(assembled.blocks.some((block) => block.content.includes("SECRET-CANARY"))).toBe(false);
      const assembleAudit = await kernel.db.query(
        "SELECT detail FROM audit_log WHERE op = 'assemble' AND namespace = $1 ORDER BY seq DESC LIMIT 1",
        ["globex"],
      );
      expect(String(assembleAudit.rows[0]?.detail)).toContain("rejectedPins=1");

      const siblingFault = await kernel.memFault(
        { query: "SECRET-CANARY finance approval refund" },
        globex,
        "integration",
      );
      expect(siblingFault.injected.some((hit) => hit.content.includes("SECRET-CANARY"))).toBe(false);
      const ownerFault = await kernel.memFault(
        { query: "SECRET-CANARY finance approval refund" },
        acme,
        "integration",
      );
      expect(ownerFault.injected.some((hit) => hit.content.includes("SECRET-CANARY"))).toBe(true);
    } finally {
      await kernel.close();
    }
  });
});
