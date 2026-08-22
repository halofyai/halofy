import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const dockerfilePath = fileURLToPath(new URL("../Dockerfile", import.meta.url));
const composePath = fileURLToPath(new URL("../docker-compose.yml", import.meta.url));

describe("production container image", () => {
  it("starts the shell entrypoint even when a Windows build context drops its mode", async () => {
    const dockerfile = await readFile(dockerfilePath, "utf8");

    expect(dockerfile).toContain("sed -i 's/\\r$//' /app/docker-entrypoint.sh");
    expect(dockerfile).toContain("chmod +x /app/docker-entrypoint.sh");
    expect(dockerfile).toContain('CMD ["/bin/sh", "./docker-entrypoint.sh"]');
  });

  it("keeps the local Compose stack out of production-only remote DSN enforcement", async () => {
    const compose = await readFile(composePath, "utf8");

    expect(compose).toMatch(/kernel:\s[\s\S]*?environment:\s[\s\S]*?NODE_ENV:\s*development/);
  });
});
