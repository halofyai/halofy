import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("HaloMem Sync Obsidian plugin package", () => {
  it("uses a community-safe manifest and moves the one-time secret out of plugin settings", async () => {
    const base = new URL("../integrations/halomem-sync/", import.meta.url);
    const manifest = JSON.parse(await readFile(new URL("manifest.json", base), "utf8")) as {
      id: string;
      minAppVersion: string;
      isDesktopOnly: boolean;
    };
    const source = await readFile(new URL("src/main.ts", base), "utf8");

    expect(manifest).toMatchObject({
      id: "halomem-sync",
      minAppVersion: "1.11.4",
      isDesktopOnly: false,
    });
    expect(manifest.id).not.toContain("obsidian");
    expect(source).toContain("this.app.secretStorage.setSecret(secretId, bundle.secret)");
    expect(source).toContain("this.app.secretStorage.getSecret(this.settings.secretId)");
    expect(source).not.toContain("this.settings.secret =");
    expect(source).toContain('requestUrl({');
    expect(source).toContain('this.app.vault.getMarkdownFiles()');
    expect(source).not.toMatch(/from ["']node:(fs|path|child_process)/);
  });

  it("is installed, typechecked, and built by the backend static-quality lane", async () => {
    const workflow = (await readFile(
      new URL("../../.github/workflows/ci.yml", import.meta.url),
      "utf8",
    )).replace(/\r\n/g, "\n");

    expect(workflow).toContain("cache-dependency-path: kernel/integrations/halomem-sync/package-lock.json");
    expect(workflow).toContain("name: Install");
    expect(workflow).toContain("name: Typecheck");
    expect(workflow).toContain("name: Build is reproducible");
    expect(workflow.match(/working-directory: kernel\/integrations\/halomem-sync/g)).toHaveLength(3);
  });
});
