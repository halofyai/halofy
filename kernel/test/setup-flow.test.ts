import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildHttpDeps } from "../src/http/adapter.js";
import { Kernel } from "../src/kernel.js";
import type { Identity, SetupResult } from "../src/types.js";

const ROOT: Identity = {
  keyId: "setup-root-session",
  namespace: "",
  actor: "owner@halo.test",
  role: "owner",
};

describe("R4C resumable verified setup", () => {
  let root: string;
  let knowledgeDir: string;
  let sourceDir: string;
  let kernel: Kernel;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "halomem-setup-"));
    knowledgeDir = join(root, "knowledge");
    sourceDir = join(root, "source");
    await mkdir(knowledgeDir);
    await mkdir(sourceDir);
    await writeFile(join(sourceDir, "handbook.txt"), "Support hours are 09:00 to 17:00 UTC.");
    kernel = await Kernel.boot({ knowledgeDir });
  });

  afterEach(async () => {
    await kernel.close();
    await rm(root, { recursive: true, force: true });
  });

  function setupBody(idempotencyKey = "setup-acme-2026-07-10") {
    return {
      idempotencyKey,
      tenant: { id: "acme", name: "acme Incorporated", monthlyBudgetUsd: 500 },
      team: { id: "support", name: "Customer Support" },
      source: { kind: "filesystem", config: { path: sourceDir } },
      retriever: "graph",
      agentActor: "acme-support-agent",
    };
  }

  it("reports only mounted retrievers and their capabilities", async () => {
    const deps = buildHttpDeps(kernel, { publicUrl: "https://memory.acme.test" });
    const result = await deps.admin.setupCapabilities!(ROOT) as {
      retrievers: Array<{ name: string; capabilities: { graph: boolean; streaming: boolean } }>;
    };

    expect(result.retrievers.map((driver) => driver.name)).toEqual(["baseline", "graph"]);
    expect(result.retrievers.find((driver) => driver.name === "graph")?.capabilities.graph).toBe(true);
  });

  it("validates the whole request, public URL, source preflight, and mounted retriever before mutation", async () => {
    const deps = buildHttpDeps(kernel, { publicUrl: "https://memory.acme.test" });

    await expect(
      deps.admin.setup!({ ...setupBody(), retriever: "unmounted-retriever" }, ROOT),
    ).rejects.toThrow(/not mounted/i);
    await expect(
      deps.admin.setup!(
        {
          ...setupBody("setup-invalid-source"),
          source: { kind: "filesystem", config: { path: join(root, "missing") } },
        },
        ROOT,
      ),
    ).rejects.toThrow(/preflight/i);

    const tenants = await kernel.db.query("SELECT COUNT(*) AS n FROM tenants");
    const operations = await kernel.db.query("SELECT COUNT(*) AS n FROM setup_operations");
    expect(Number(tenants.rows[0].n)).toBe(0);
    expect(Number(operations.rows[0].n)).toBe(0);

    const insecure = buildHttpDeps(kernel, {
      secureCookies: true,
      publicUrl: "http://localhost:8787",
    });
    await expect(insecure.admin.setup!(setupBody("setup-insecure-url"), ROOT)).rejects.toThrow(
      /PUBLIC_URL/i,
    );
  });

  it("atomically creates an explicit team and team badge, syncs the source, and completes only after badge use", async () => {
    const deps = buildHttpDeps(kernel, { publicUrl: "https://memory.acme.test" });

    const first = await deps.admin.setup!(setupBody(), ROOT) as SetupResult;
    expect(first.status).toBe("waiting_for_agent");
    expect(first.team.namespace).toBe("acme/support");
    expect(first.badge.namespace).toBe("acme/support");
    expect(first.source?.status).toBe("synced");
    expect(first.source?.syncResult).not.toBeNull();
    expect(first.mcpSnippet).toContain("https://memory.acme.test/mcp");

    const badgeKey = JSON.parse(first.mcpSnippet!).mcpServers.halomem.headers.Authorization
      .replace(/^Bearer /, "");
    expect(badgeKey).toMatch(/^hm_[0-9a-f]{40}$/);

    const replay = await deps.admin.setup!(setupBody(), ROOT) as SetupResult;
    expect(replay.operationId).toBe(first.operationId);
    expect(replay.mcpSnippet).toBe(first.mcpSnippet);
    expect(replay.status).toBe("waiting_for_agent");

    const counts = await Promise.all([
      kernel.db.query("SELECT COUNT(*) AS n FROM tenants WHERE id = 'acme'"),
      kernel.db.query("SELECT COUNT(*) AS n FROM org_teams WHERE namespace = 'acme/support'"),
      kernel.db.query("SELECT COUNT(*) AS n FROM policies WHERE namespace = 'acme/support'"),
      kernel.db.query("SELECT COUNT(*) AS n FROM api_keys WHERE namespace = 'acme/support'"),
      kernel.db.query("SELECT COUNT(*) AS n FROM sources WHERE namespace = 'acme/support'"),
    ]);
    expect(counts.map((row) => Number(row.rows[0].n))).toEqual([1, 1, 1, 1, 1]);
    expect((await kernel.tenants.get("acme"))?.name).toBe("Acme Incorporated");
    expect(first.team.id).toBe("support");
    expect(first.team.tenantId).toBe("acme");

    expect((await kernel.auth.resolve(badgeKey))?.namespace).toBe("acme/support");
    const completed = await deps.admin.setup!(setupBody(), ROOT) as SetupResult;
    expect(completed.status).toBe("complete");
    expect(completed.badge.lastUsed).not.toBeNull();
  });

  it("records a failed first sync and resumes it without duplicating durable core state", async () => {
    const deps = buildHttpDeps(kernel, { publicUrl: "https://memory.acme.test" });
    const realSync = kernel.syncSource.bind(kernel);
    kernel.syncSource = async () => {
      throw new Error("injected source outage");
    };

    const failed = await deps.admin.setup!(setupBody("setup-source-retry"), ROOT) as SetupResult;
    expect(failed.status).toBe("source_failed");
    expect(failed.source?.status).toBe("failed");
    expect(failed.source?.error).toContain("source outage");

    kernel.syncSource = realSync;
    const resumed = await deps.admin.setupRetry!(failed.operationId, ROOT) as SetupResult;
    expect(resumed.operationId).toBe(failed.operationId);
    expect(resumed.source?.status).toBe("synced");
    expect(resumed.status).toBe("waiting_for_agent");

    const rows = await kernel.db.query(
      "SELECT (SELECT COUNT(*) FROM tenants) AS tenants, (SELECT COUNT(*) FROM org_teams) AS teams, (SELECT COUNT(*) FROM api_keys WHERE role = 'agent') AS badges, (SELECT COUNT(*) FROM sources) AS sources",
    );
    expect(rows.rows[0]).toMatchObject({ tenants: 1, teams: 1, badges: 1, sources: 1 });
  });

  it("rejects reuse of an idempotency key for a different setup", async () => {
    const deps = buildHttpDeps(kernel, { publicUrl: "https://memory.acme.test" });
    await deps.admin.setup!(setupBody("fixed-operation-key"), ROOT);

    await expect(
      deps.admin.setup!(
        {
          ...setupBody("fixed-operation-key"),
          team: { id: "sales", name: "Sales" },
        },
        ROOT,
      ),
    ).rejects.toMatchObject({ name: "SetupConflictError" });
  });
});
