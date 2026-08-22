import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LocalColdStoreDriver,
  runColdStoreConformance,
} from "../src/cold/driver.js";

describe("M7 halomem-coldstore/v1", () => {
  const roots: string[] = [];
  afterEach(async () => Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true }))));

  async function driver(): Promise<LocalColdStoreDriver> {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "halomem-cold-driver-"));
    roots.push(root);
    return new LocalColdStoreDriver({ root });
  }

  it("passes the reusable cold-store conformance contract", async () => {
    const result = await runColdStoreConformance(await driver());
    expect(result.ok).toBe(true);
    expect(result.checks).toContain("immutable-commit");
  });

  it("rejects traversal refs and digest mismatches without publishing", async () => {
    const store = await driver();
    await expect(store.writeDraft("../escape", new TextEncoder().encode("secret"))).rejects.toThrow(/ref/);
    await expect(store.writeDraft("acme/file:stream", new TextEncoder().encode("secret"))).rejects.toThrow(/ref/);
    await store.writeDraft("acme/policy/v1", new TextEncoder().encode("approved"));
    await expect(store.commit("acme/policy/v1", "sha256:wrong")).rejects.toThrow(/digest/);
    await expect(store.read("acme/policy/v1")).resolves.toBeNull();
  });
});
