import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildHttpDeps } from "../src/http/adapter.js";
import { createHttpServer, type HaloHttpServer } from "../src/http/server.js";
import { Kernel } from "../src/kernel.js";

describe("MCP 2026-07-28 real HTTP smoke", () => {
  let rootDir: string;
  let kernel: Kernel;
  let server: HaloHttpServer;
  let client: Client;

  beforeAll(async () => {
    rootDir = await mkdtemp(join(tmpdir(), "halomem-mcp-v2-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir: join(rootDir, "knowledge"),
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });

    const root = await kernel.auth.issueKey("", "owner:mcp-v2-smoke", "owner");
    const rootIdentity = await kernel.auth.resolve(root.plaintext);
    expect(rootIdentity).not.toBeNull();
    const badge = await kernel.auth.issueKey(
      "org/mcp-v2-smoke",
      "agent:mcp-v2-smoke",
      "agent",
      rootIdentity,
    );

    server = createHttpServer(buildHttpDeps(kernel, { secureCookies: false }));
    const port = await server.start(0);
    client = new Client(
      { name: "halomem-mcp-v2-e2e", version: "1.0.0" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    await client.connect(
      new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${port}/mcp`),
        {
          requestInit: {
            headers: { authorization: `Bearer ${badge.plaintext}` },
          },
        },
      ),
    );
  }, 120_000);

  afterAll(async () => {
    await client?.close();
    await server?.stop();
    await kernel?.close();
    if (rootDir) await rm(rootDir, { recursive: true, force: true });
  });

  it("writes and reads a real memory over a modern stateless connection", async () => {
    expect(client.getProtocolEra()).toBe("modern");
    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(
      expect.arrayContaining(["mem_write", "mem_read"]),
    );

    const marker = "MCP 2026-07-28 end-to-end smoke fact";
    const write = await client.callTool({
      name: "mem_write",
      arguments: {
        scope: "team",
        content: marker,
        type: "fact",
        verbatim: true,
      },
    });
    expect(write.isError).not.toBe(true);
    const writeText = write.content.find((block) => block.type === "text");
    expect(writeText?.type).toBe("text");
    const writeResult = JSON.parse(
      writeText?.type === "text" ? writeText.text : "{}",
    ) as { stored?: Array<{ id: string; content: string }> };
    expect(writeResult.stored?.[0]?.content).toBe(marker);

    const memoryId = writeResult.stored?.[0]?.id;
    expect(memoryId).toBeTruthy();
    const read = await client.callTool({
      name: "mem_read",
      arguments: { id: memoryId },
    });
    expect(read.isError).not.toBe(true);
    const readText = read.content.find((block) => block.type === "text");
    const readResult = JSON.parse(
      readText?.type === "text" ? readText.text : "{}",
    ) as { found?: boolean; memory?: { id: string; content: string } };
    expect(readResult).toMatchObject({
      found: true,
      memory: { id: memoryId, content: marker },
    });

    const audits = await kernel.db.query(
      `SELECT op, result, namespace
         FROM audit_log
        WHERE namespace = $1 AND op IN ('write', 'read')`,
      ["org/mcp-v2-smoke"],
    );
    expect(audits.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ op: "write", result: "ok" }),
        expect.objectContaining({ op: "read", result: "ok" }),
      ]),
    );
  }, 120_000);
});
