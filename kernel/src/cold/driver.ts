/** halomem-coldstore/v1 local filesystem cartridge and reusable conformance probe. */
import { constants } from "node:fs";
import { promises as fs } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import type { ColdStoreDriver } from "../types.js";

export interface LocalColdStoreDriverOptions {
  root: string;
  name?: string;
}

function safeRef(ref: string): string {
  if (!ref || ref.includes("\\") || ref.includes("\0") || ref.includes(":") || path.posix.isAbsolute(ref)) {
    throw new Error("cold-store ref must be a non-empty relative POSIX path");
  }
  const normalized = path.posix.normalize(ref);
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized !== ref) {
    throw new Error("cold-store ref contains traversal or non-canonical segments");
  }
  return normalized;
}

function digest(content: Uint8Array): string {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

async function exists(file: string): Promise<boolean> {
  try { await fs.access(file); return true; } catch { return false; }
}

export class LocalColdStoreDriver implements ColdStoreDriver {
  readonly name: string;
  private readonly root: string;
  private readonly drafts: string;
  private readonly objects: string;

  constructor(options: LocalColdStoreDriverOptions) {
    if (!path.isAbsolute(options.root)) throw new Error("cold-store root must be absolute");
    this.name = options.name ?? "local";
    this.root = path.resolve(options.root);
    this.drafts = path.join(this.root, ".drafts");
    this.objects = path.join(this.root, "objects");
  }

  capabilities(): { versioned: boolean; encrypted: boolean; remote: boolean } {
    return { versioned: true, encrypted: false, remote: false };
  }

  async list(prefix: string): Promise<string[]> {
    const normalized = prefix ? safeRef(prefix) : "";
    const start = path.join(this.objects, ...normalized.split("/").filter(Boolean));
    if (!(await exists(start))) return [];
    const stat = await fs.stat(start);
    if (stat.isFile()) return [normalized];
    const refs: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      for (const item of await fs.readdir(dir, { withFileTypes: true })) {
        const file = path.join(dir, item.name);
        if (item.isDirectory()) await walk(file);
        else if (item.isFile()) refs.push(path.relative(this.objects, file).split(path.sep).join("/"));
      }
    };
    await walk(start);
    return refs.sort();
  }

  async read(ref: string): Promise<Uint8Array | null> {
    const file = this.objectPath(ref);
    try { return new Uint8Array(await fs.readFile(file)); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  async writeDraft(ref: string, content: Uint8Array): Promise<void> {
    const file = this.draftPath(ref);
    await fs.mkdir(path.dirname(file), { recursive: true });
    const temporary = `${file}.${randomUUID()}.tmp`;
    try {
      await fs.writeFile(temporary, content, { flag: "wx", mode: 0o600 });
      await fs.rename(temporary, file);
    } finally {
      await fs.rm(temporary, { force: true }).catch(() => undefined);
    }
  }

  async commit(ref: string, expectedDigest?: string): Promise<{ ref: string; digest: string }> {
    const normalized = safeRef(ref);
    const draft = this.draftPath(normalized);
    let content: Uint8Array;
    try { content = new Uint8Array(await fs.readFile(draft)); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error(`cold-store draft not found: ${normalized}`);
      throw error;
    }
    const actualDigest = digest(content);
    if (expectedDigest && expectedDigest !== actualDigest && `sha256:${expectedDigest}` !== actualDigest) {
      throw new Error(`cold-store digest mismatch for ${normalized}`);
    }

    const target = this.objectPath(normalized);
    await fs.mkdir(path.dirname(target), { recursive: true });
    try {
      await fs.copyFile(draft, target, constants.COPYFILE_EXCL);
      await fs.chmod(target, 0o400).catch(() => undefined);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const committed = new Uint8Array(await fs.readFile(target));
      if (digest(committed) !== actualDigest) {
        throw new Error(`cold-store ref is immutable and already committed: ${normalized}`);
      }
    }
    await fs.rm(draft, { force: true });
    return { ref: normalized, digest: actualDigest };
  }

  async remove(ref: string): Promise<void> {
    const normalized = safeRef(ref);
    const object = this.objectPath(normalized);
    await fs.chmod(object, 0o600).catch(() => undefined);
    await Promise.all([
      fs.rm(object, { force: true }),
      fs.rm(this.draftPath(normalized), { force: true }),
    ]);
  }

  async health(): Promise<{ ok: boolean; detail?: string }> {
    try {
      await fs.mkdir(this.drafts, { recursive: true });
      await fs.mkdir(this.objects, { recursive: true });
      await fs.access(this.root, constants.R_OK | constants.W_OK);
      return { ok: true };
    } catch (error) {
      return { ok: false, detail: error instanceof Error ? error.message : String(error) };
    }
  }

  private draftPath(ref: string): string {
    return path.join(this.drafts, ...safeRef(ref).split("/"));
  }

  private objectPath(ref: string): string {
    return path.join(this.objects, ...safeRef(ref).split("/"));
  }
}

export interface ColdStoreConformanceResult { ok: true; checks: string[] }

/** Destructive only inside a unique `_conformance/` prefix, removed on completion. */
export async function runColdStoreConformance(driver: ColdStoreDriver): Promise<ColdStoreConformanceResult> {
  const prefix = `_conformance/${randomUUID()}`;
  const ref = `${prefix}/version-1`;
  const original = new TextEncoder().encode("halomem-coldstore/v1");
  const changed = new TextEncoder().encode("must-not-overwrite");
  const checks: string[] = [];
  try {
    const health = await driver.health();
    if (!health.ok) throw new Error(`cold-store unhealthy: ${health.detail ?? "unknown"}`);
    checks.push("health");
    await driver.writeDraft(ref, original);
    const committed = await driver.commit(ref, digest(original));
    if (committed.ref !== ref || committed.digest !== digest(original)) throw new Error("commit identity mismatch");
    if (Buffer.compare(Buffer.from((await driver.read(ref)) ?? []), Buffer.from(original)) !== 0) {
      throw new Error("committed read mismatch");
    }
    checks.push("draft-commit-read");
    if (!(await driver.list(prefix)).includes(ref)) throw new Error("committed ref missing from list");
    checks.push("list");
    await driver.writeDraft(ref, changed);
    let immutable = false;
    try { await driver.commit(ref); } catch { immutable = true; }
    if (!immutable) throw new Error("committed ref was overwritten");
    checks.push("immutable-commit");
    await driver.remove(ref);
    if (await driver.read(ref)) throw new Error("removed ref remains readable");
    checks.push("remove");
    return { ok: true, checks };
  } finally {
    await driver.remove(ref).catch(() => undefined);
  }
}

export const assertColdStoreConformance = runColdStoreConformance;
