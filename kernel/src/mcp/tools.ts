/**
 * HaloMem MCP tool definitions (M1, D9) — the single factory shared by the
 * stdio server and the HTTP /mcp Streamable transport.
 *
 * BREAKING (CONTRACTS-M1.md): tool schemas have NO `namespace`/`actor`
 * params. Identity is resolved server-side from a credential (stdio:
 * HALOMEM_API_KEY at boot; HTTP: Bearer key per request) and bound into the
 * returned server instance.
 *
 * When `identity` is null (stdio booted without / with an invalid key), the
 * server still starts and every tool returns a clear error.
 */
import { McpServer, type ServerContext } from "@modelcontextprotocol/server";
import { z } from "zod";

import type {
  ForgetTarget,
  Identity,
  PinTarget,
  ScoredRef,
  SyscallContext,
} from "../types.js";
import { anchorCopilotToolQuery } from "../model-runtime/contextual-query.js";
import type { Kernel } from "../kernel.js";
import type { ManifestResult } from "../discovery/manifest.js";
import type {
  MemFaultResult,
  MemLiveResultArgs,
  MemLiveResultResult,
} from "../syscalls/index.js";
import {
  MAX_GATEWAY_BYTES,
  MAX_GATEWAY_FIELDS,
  MAX_GATEWAY_QUERY_TERM_LENGTH,
  MAX_GATEWAY_QUERY_TERMS,
  MAX_GATEWAY_REQUEST_DURATION_SECONDS,
  MAX_GATEWAY_REQUEST_USES,
  MAX_GATEWAY_ROWS,
  MIN_GATEWAY_REQUEST_DURATION_SECONDS,
} from "../gateway/contracts.js";

/**
 * M6 (D15): structural view of the kernel's federation surface. Optional so
 * this file compiles (and every tool keeps working) before the integrator
 * lands `Kernel.memLiveResult` — the tool degrades to a clear error instead.
 */
type LiveCapableKernel = Kernel & {
  memLiveResult?(
    args: MemLiveResultArgs,
    identity: Identity,
    agentId?: string,
    ctx?: SyscallContext,
  ): Promise<MemLiveResultResult>;
};

interface ToolResponse {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

function ok(result: unknown): ToolResponse {
  return { content: [{ type: "text", text: JSON.stringify(result) }] };
}

function textResponse(text: string): ToolResponse {
  return { content: [{ type: "text", text }] };
}

function fail(err: unknown): ToolResponse {
  const message = err instanceof Error ? err.message : String(err);
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ error: message }) }],
  };
}

const NO_IDENTITY_ERROR =
  "no identity: HALOMEM_API_KEY is missing, invalid, or revoked - " +
  "set a valid API key (issue one with `tsx src/cli.ts keygen <ns> <actor> <role>`) and restart";

// A manifest can legitimately span megabytes for administrative clients, but
// a delegated Copilot sends the serialized tool response back through the
// model context. Keep that specific response bounded so a broad catalog check
// cannot exhaust a later model step. Non-Copilot callers retain the public
// manifest result and limits.
const COPILOT_MANIFEST_MAX_BYTES = 16_000;
const COPILOT_MANIFEST_TRUNCATION_NOTICE =
  "\n\n_[Copilot tool output truncated; use targeted file or memory reads for more detail.]_";
const FULL_MANIFEST_ENTRY_HEADING = /^### [0-9A-HJKMNP-TV-Z]{26}$/;

function serializedBytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function deliveredManifestEntryCount(
  markdown: string,
  variant: ManifestResult["variant"],
): number {
  const lines = markdown.split(/\r?\n/);
  const heading = variant === "full" ? "## Memory" : "## Memory index";
  const sectionStart = lines.indexOf(heading);
  if (sectionStart < 0) return 0;
  const entryPattern =
    variant === "full" ? FULL_MANIFEST_ENTRY_HEADING : /^- \[(?:L2|L3)\//;
  return lines.slice(sectionStart + 1).filter((line) => entryPattern.test(line))
    .length;
}

function copilotManifestPrefixLineCounts(
  lines: string[],
  variant: ManifestResult["variant"],
): number[] {
  if (variant === "index") {
    return Array.from({ length: lines.length + 1 }, (_, index) => index);
  }
  const entryStarts = lines
    .map((line, index) => (FULL_MANIFEST_ENTRY_HEADING.test(line) ? index : -1))
    .filter((index) => index >= 0);
  const beforeFirstEntry = entryStarts[0] ?? lines.length;
  return [
    ...new Set([0, beforeFirstEntry, ...entryStarts.slice(1), lines.length]),
  ].sort((left, right) => left - right);
}

function compactCopilotManifestMarkdown(
  markdown: string,
  variant: ManifestResult["variant"],
  sourceCount: number,
): string {
  const lines = markdown.split(/\r?\n/);
  const sourcesStart = lines.indexOf("## Sources");
  const memoryStart = lines.indexOf(
    variant === "full" ? "## Memory" : "## Memory index",
  );
  if (sourcesStart < 0 || memoryStart < 0 || sourcesStart >= memoryStart)
    return markdown;
  return [
    ...lines.slice(0, sourcesStart),
    "## Sources",
    "",
    `_Source rollup omitted from Copilot output (${sourceCount} sources); use company_file_list for the governed file catalog._`,
    "",
    ...lines.slice(memoryStart),
  ].join("\n");
}

function copilotManifestResponse(result: ManifestResult): ToolResponse {
  const sourceCount = result.sources.length;
  const compactMarkdown = compactCopilotManifestMarkdown(
    result.markdown,
    result.variant,
    sourceCount,
  );
  const lines = compactMarkdown.split(/\r?\n/);
  const project = (markdown: string, outputTruncated: boolean) => ({
    namespace: result.namespace,
    variant: result.variant,
    generatedAt: result.generatedAt,
    entryCount: result.entryCount,
    renderedCount: deliveredManifestEntryCount(markdown, result.variant),
    sourceCount,
    // The bounded markdown carries a compact catalog note plus actionable
    // memory refs. Avoid duplicating the unbounded source array here.
    sources: [],
    sourcesTruncated: sourceCount > 0,
    truncated: result.truncated || outputTruncated,
    outputTruncated,
    bytes: serializedBytes(markdown),
    markdown,
  });

  let serialized = JSON.stringify(project(compactMarkdown, false));
  if (serializedBytes(serialized) <= COPILOT_MANIFEST_MAX_BYTES) {
    return textResponse(serialized);
  }

  const prefixLineCounts = copilotManifestPrefixLineCounts(
    lines,
    result.variant,
  );
  let low = 0;
  let high = prefixLineCounts.length - 1;
  let best = JSON.stringify(
    project(COPILOT_MANIFEST_TRUNCATION_NOTICE.trimStart(), true),
  );
  while (low <= high) {
    const midpoint = Math.floor((low + high) / 2);
    const prefix = lines.slice(0, prefixLineCounts[midpoint]).join("\n");
    const markdown = `${prefix}${COPILOT_MANIFEST_TRUNCATION_NOTICE}`;
    const candidate = JSON.stringify(project(markdown, true));
    if (serializedBytes(candidate) <= COPILOT_MANIFEST_MAX_BYTES) {
      best = candidate;
      low = midpoint + 1;
    } else {
      high = midpoint - 1;
    }
  }
  return textResponse(best);
}

/**
 * Server identity advertised by modern discovery and legacy `initialize`.
 * `icons` and `websiteUrl` are what a connector UI reads to brand the server; they need
 * an ABSOLUTE origin, so the HTTP transport passes the origin the caller
 * reached us on and stdio falls back to HALOMEM_PUBLIC_URL. Unknown origin →
 * name/version only (a relative icon src is worse than none).
 */
function serverIdentity(publicBaseUrl?: string): {
  name: string;
  version: string;
  title: string;
  description: string;
  websiteUrl?: string;
  icons?: { src: string; mimeType: string; sizes: string[] }[];
} {
  const base = (publicBaseUrl ?? process.env.HALOMEM_PUBLIC_URL ?? "").replace(
    /\/+$/,
    "",
  );
  return {
    name: "halomem",
    version: "0.1.0",
    title: "Halo Memory",
    description:
      "Organizational memory for AI agents - governed read, write, and recall.",
    ...(base === ""
      ? {}
      : {
          websiteUrl: base,
          icons: [
            {
              src: `${base}/icon.png`,
              mimeType: "image/png",
              sizes: ["716x769"],
            },
          ],
        }),
  };
}

/**
 * Build a per-identity MCP server over the kernel syscalls. The HTTP and stdio
 * serving entries both create it through an SDK v2 factory.
 */
export function buildMcpServer(
  kernel: Kernel,
  identity: Identity | null,
  agentId: string,
  serverContext?: SyscallContext,
  publicBaseUrl?: string,
): McpServer {
  const server = new McpServer(serverIdentity(publicBaseUrl));

  const enforceToolAllowlist = async (
    id: Identity,
    toolName: string,
  ): Promise<void> => {
    const allowedTools = (id as Identity & { allowedTools?: string[] })
      .allowedTools;
    if (allowedTools === undefined) {
      if (id.credentialKind === "copilot-capability") {
        throw new Error("delegated tool authority is unavailable");
      }
      return;
    }
    await kernel.requireOAuthTool(id, toolName);
  };

  const contextualQuery = (id: Identity, query: string, maxChars = 4_000): string =>
    id.credentialKind === "copilot-capability" && id.assistantContextQuery
      ? anchorCopilotToolQuery(query, id.assistantContextQuery, maxChars)
      : query;

  /** Guard + dispatch: every tool resolves through the bound identity. */
  const call = async (
    toolName: string,
    fn: (id: Identity, ctx: SyscallContext) => Promise<unknown>,
    mcpContext?: ServerContext,
    respond: (result: unknown, id: Identity) => ToolResponse = ok,
  ): Promise<ToolResponse> => {
    if (!identity) return fail(new Error(NO_IDENTITY_ERROR));
    try {
      // Closed server-side allowlist for OAuth and Copilot delegation
      // identities. The model-facing sidecar filter is only UX, never auth.
      await enforceToolAllowlist(identity, toolName);
      // D37: an opaque caller trace hint via MCP _meta.traceId — a grouping
      // hint only (validated at the syscall boundary), never identity (D9).
      const metaTrace = mcpContext?.mcpReq._meta?.["traceId"];
      const ctx: SyscallContext = {
        ...(serverContext?.traceId
          ? { traceId: serverContext.traceId }
          : typeof metaTrace === "string"
            ? { traceId: metaTrace }
            : {}),
        tool: serverContext?.tool ?? toolName,
        ...(serverContext?.sensitiveTurnId
          ? { sensitiveTurnId: serverContext.sensitiveTurnId }
          : {}),
      };
      return respond(await fn(identity, ctx), identity);
    } catch (err) {
      return fail(err);
    }
  };

  server.registerTool(
    "mem_read",
    {
      description:
        "Read a memory object by id. ACL-checked against YOUR key's namespace; every access is audited.",
      inputSchema: z.object({
        id: z.string().describe("Memory ULID"),
      }),
    },
    ({ id }, ctx) =>
      call(
        "mem_read",
        (identity, ctx) => kernel.memRead({ id }, identity, agentId, ctx),
        ctx,
      ),
  );

  server.registerTool(
    "mem_search",
    {
      description:
        "Hybrid semantic + lexical search over L2 memories visible to your key's namespace, capped by token budget.",
      inputSchema: z.object({
        query: z.string().describe("Natural-language search query"),
        k: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Max candidates (default 8)"),
        tokenBudget: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Token cap on results (default 2000)"),
        validOnly: z
          .boolean()
          .optional()
          .describe("Restrict to currently-valid facts (default true)"),
        live: z
          .enum(["off", "auto"])
          .optional()
          .describe(
            "'auto' (default): a search with no local results may start an audited live-source " +
              "confirmation whose verified facts are cached for subsequent calls; 'off' never queries live sources",
          ),
      }),
    },
    ({ query, k, tokenBudget, validOnly, live }, ctx) =>
      call(
        "mem_search",
        (identity, ctx) =>
          kernel.memSearch(
            { query: contextualQuery(identity, query), k, tokenBudget, validOnly, live },
            identity,
            agentId,
            ctx,
          ),
        ctx,
      ),
  );

  server.registerTool(
    "source_list",
    {
      description:
        "List connected backends visible to your identity with their sync and lifecycle state. Connector configuration and credentials are never returned.",
      inputSchema: z.object({}),
    },
    (_input, ctx) =>
      call(
        "source_list",
        (identity, ctx) => kernel.copilotSourceList(identity, agentId, ctx),
        ctx,
      ),
  );

  server.registerTool(
    "source_search",
    {
      description:
        "Search only memory imported from a backend named in the natural-language query. The kernel resolves visible source ids and applies memory and source ACLs server-side.",
      inputSchema: z.object({
        query: z.string().trim().min(1).max(4_000),
      }),
    },
    ({ query }, ctx) =>
      call(
        "source_search",
        (identity, ctx) => kernel.copilotSourceSearch(query, identity, agentId, ctx),
        ctx,
      ),
  );

  server.registerTool(
    "mem_write",
    {
      description:
        "Write new information to memory (lands in your key's namespace). Runs extraction, verification, dedupe, and supersedence; returns what was stored.",
      inputSchema: z.object({
        scope: z
          .enum(["user", "assistant", "team", "org"])
          .describe("Memory scope"),
        content: z.string().describe("Raw content to remember"),
        session: z.string().optional().describe("Session id for provenance"),
        type: z
          .enum(["fact", "preference", "episode", "entity", "concept"])
          .optional(),
        eventTime: z
          .string()
          .optional()
          .describe("ISO-8601 time the fact became true"),
        verbatim: z
          .boolean()
          .optional()
          .describe("Skip LLM extraction; store content as a single fact"),
        async: z
          .boolean()
          .optional()
          .describe("Queue the write and return a ticket immediately"),
      }),
    },
    ({ scope, content, session, type, eventTime, verbatim, async: isAsync }) =>
      call("mem_write", (identity) =>
        kernel.memWrite(
          {
            scope,
            content,
            session,
            hints: { type, eventTime, verbatim },
            async: isAsync,
          },
          identity,
          agentId,
        ),
      ),
  );

  const sourceReadFields = [
    "grantId",
    "connectorId",
    "sourceRef",
    "purpose",
    "query",
    "requestedFields",
    "requestedRows",
    "requestedBytes",
    "expectedPolicyVersion",
    "accessRequestId",
  ] as const;
  const sourceReadInput = z
    .object({
      grantId: z.string().trim().min(1).max(256),
      connectorId: z.string().trim().min(1).max(256),
      sourceRef: z
        .string()
        .trim()
        .regex(/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/),
      purpose: z.string().trim().min(1).max(256),
      query: z
        .string()
        .trim()
        .min(1)
        .max(4_096)
        .refine((query) => {
          const terms = query.split(/\s+/).filter(Boolean);
          return (
            terms.length <= MAX_GATEWAY_QUERY_TERMS &&
            terms.every((term) => term.length <= MAX_GATEWAY_QUERY_TERM_LENGTH)
          );
        }),
      requestedFields: z
        .array(
          z
            .string()
            .trim()
            .regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
        )
        .max(MAX_GATEWAY_FIELDS)
        .optional(),
      requestedRows: z
        .number()
        .int()
        .positive()
        .max(MAX_GATEWAY_ROWS)
        .optional(),
      requestedBytes: z
        .number()
        .int()
        .positive()
        .max(MAX_GATEWAY_BYTES)
        .optional(),
      expectedPolicyVersion: z.number().int().positive().optional(),
      accessRequestId: z.string().trim().min(1).max(256).optional(),
    })
    .passthrough();
  server.registerTool(
    "source_read",
    {
      description:
        "Read an explicitly allowlisted projection from an organization backend through a badge-bound HaloMem grant. Backend credentials, SQL, namespaces, and policy are always server-resolved. If a read is denied for scope, call describe_access to see this badge's standing access and, when the badge allows it, request_access to ask a human for temporary extra access.",
      inputSchema: sourceReadInput,
    },
    (input) =>
      call("source_read", (identity) => {
        const allowed = new Set<string>(sourceReadFields);
        if (Object.keys(input).some((key) => !allowed.has(key))) {
          return kernel.rejectAgentSourceReadIngress(
            {
              grantId: input.grantId,
              connectorId: input.connectorId,
              sourceRef: input.sourceRef,
              purpose: input.purpose,
            },
            identity,
          );
        }
        return kernel.agentSourceRead(
          { operation: "source-read", ...input },
          identity,
        );
      }),
  );

  server.registerTool(
    "describe_access",
    {
      description:
        "Show what this badge can access right now and whether it may ask a human for temporary extra access (request_access).",
    },
    () =>
      call("describe_access", (identity) =>
        kernel.describeAgentAccess(identity),
      ),
  );

  const requestAccessInput = z
    .object({
      grantId: z.string().trim().min(1).max(256),
      connectorId: z.string().trim().min(1).max(256),
      sourceRef: z
        .string()
        .trim()
        .regex(/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/),
      purpose: z.string().trim().min(1).max(256),
      requestedFields: z
        .array(
          z
            .string()
            .trim()
            .regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
        )
        .min(1)
        .max(MAX_GATEWAY_FIELDS),
      requestedRows: z.number().int().positive().max(MAX_GATEWAY_ROWS),
      requestedBytes: z.number().int().positive().max(MAX_GATEWAY_BYTES),
      justification: z.string().trim().min(1).max(2_000),
      requestedDurationSeconds: z
        .number()
        .int()
        .min(MIN_GATEWAY_REQUEST_DURATION_SECONDS)
        .max(MAX_GATEWAY_REQUEST_DURATION_SECONDS),
      maxUses: z.number().int().min(1).max(MAX_GATEWAY_REQUEST_USES).optional(),
    })
    .strict();
  server.registerTool(
    "request_access",
    {
      description:
        "Ask a human owner for one exact, temporary backend access. Approval never changes the standing badge access and expires after its time or use limit.",
      inputSchema: requestAccessInput,
    },
    (input) =>
      call("request_access", (identity) =>
        kernel.createAgentAccessRequest(input, identity),
      ),
  );

  server.registerTool(
    "mem_write_status",
    {
      description:
        "Check an async write ticket returned by mem_write {async:true}: queued|running|done|failed (with result or error). Unknown, expired, or foreign tickets report not-found.",
      inputSchema: z.object({
        ticket: z
          .string()
          .describe("Ticket id returned by mem_write {async:true}"),
      }),
    },
    ({ ticket }) =>
      call("mem_write_status", async (identity) => {
        const status = await kernel.writeStatus(ticket, identity);
        if (status === undefined) {
          throw new Error(`unknown or expired ticket '${ticket}'`);
        }
        return status;
      }),
  );

  server.registerTool(
    "mem_fault",
    {
      description:
        "Handle a memory page fault: search L2, fall back to L3 cold concepts, and return blocks to inject. " +
        "Two-phase (M6): when a federated pointer matches, the response answers from memory NOW and carries " +
        "liveStatus {state:'running', sources, ticket} - redeem the ticket with mem_live_result for live-confirmed data.",
      inputSchema: z.object({
        query: z
          .string()
          .describe("The question or topic the agent is missing context for"),
        k: z.number().int().positive().optional(),
        tokenBudget: z.number().int().positive().optional(),
        live: z
          .enum(["off", "auto"])
          .optional()
          .describe(
            "'auto' (default) may start a live source confirmation; 'off' never queries live sources",
          ),
        sourceTokens: z
          .record(z.string(), z.string())
          .optional()
          .describe(
            "Per-connector passthrough credentials (connectorId → token) for this request only. " +
              "Used solely to authenticate the live fetch; never stored, logged, audited, or echoed.",
          ),
      }),
    },
    async ({ query, k, tokenBudget, live, sourceTokens }, ctx) => {
      if (!identity) return fail(new Error(NO_IDENTITY_ERROR));
      try {
        await enforceToolAllowlist(identity, "mem_fault");
        // D37: same _meta.traceId hint handling as the call() guard (this
        // tool appends the phase-1 statement, so it dispatches directly).
        const metaTrace = ctx.mcpReq._meta?.["traceId"];
        const result = (await kernel.memFault(
          {
            query: contextualQuery(identity, query),
            k,
            tokenBudget,
            live,
            sourceTokens,
          },
          identity,
          agentId,
          {
            ...(typeof metaTrace === "string" ? { traceId: metaTrace } : {}),
            tool: "mem_fault",
          },
        )) as MemFaultResult;
        const response = ok(result);
        // D15: the phase-1 statement is model-facing TEXT, appended after the
        // JSON payload so the agent reads it even without parsing the result.
        if (
          typeof result.liveStatement === "string" &&
          result.liveStatement.length > 0
        ) {
          response.content.push({ type: "text", text: result.liveStatement });
        }
        return response;
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "mem_live_result",
    {
      description:
        "Redeem a two-phase live-confirmation ticket returned by mem_fault (liveStatus.ticket). " +
        "Phase 1 already answered from local memory; this returns the live-confirmed result " +
        "{state:'running'|'done'|'failed', blocks, superseded} once the federated fetch completes. " +
        "Unknown or expired tickets (120s) report {found:false} - retry the fault instead.",
      inputSchema: z.object({
        ticket: z
          .string()
          .min(1)
          .describe("Ticket from mem_fault's liveStatus"),
        sourceTokens: z
          .record(z.string().min(1).max(256), z.string().min(1).max(16_384))
          .refine(
            (tokens) => Object.keys(tokens).length <= 32,
            "at most 32 source tokens are allowed",
          )
          .optional()
          .describe(
            "Optional passthrough tokens re-submitted after a replica hop; never persisted",
          ),
      }),
    },
    ({ ticket, sourceTokens }, ctx) =>
      call(
        "mem_live_result",
        async (identity, ctx) => {
          const live = kernel as LiveCapableKernel;
          if (!live.memLiveResult) {
            throw new Error(
              "live results unavailable: federation lane is not wired on this kernel",
            );
          }
          return live.memLiveResult(
            { ticket, sourceTokens },
            identity,
            agentId,
            ctx,
          );
        },
        ctx,
      ),
  );

  server.registerTool(
    "mem_stats",
    {
      description:
        "Memory statistics for your key's namespace: tier counts, fault hit rate, working-set sizes, audit volume, top-accessed memories.",
      inputSchema: z.object({}),
    },
    () =>
      call("mem_stats", (identity) => kernel.memStats({}, identity, agentId)),
  );

  server.registerTool(
    "mem_assemble",
    {
      description:
        "Assemble a ranked working set of context blocks for your key's namespace under its token budget (the caller places them; HaloMem never builds prompts).",
      inputSchema: z.object({
        taskHint: z
          .string()
          .optional()
          .describe(
            "Optional hint about the upcoming task for relevance prediction",
          ),
      }),
    },
    ({ taskHint }, ctx) =>
      call(
        "mem_assemble",
        (identity, ctx) =>
          kernel.memAssemble({
            taskHint: identity.credentialKind === "copilot-capability"
              ? contextualQuery(identity, taskHint ?? "")
              : taskHint,
          }, identity, agentId, ctx),
        ctx,
      ),
  );

  server.registerTool(
    "mem_manifest",
    {
      description:
        "List the canonical current L2/L3 memory entries visible to your identity. Use this to discover relevant refs or verify coverage before claiming organization data is missing.",
      inputSchema: z.object({
        variant: z
          .enum(["index", "full"])
          .optional()
          .describe(
            "Index lists entries; full includes full content within maxBytes",
          ),
        maxBytes: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Maximum manifest bytes (server clamps to 1 KiB–4 MiB)"),
      }),
    },
    ({ variant, maxBytes }, ctx) =>
      call(
        "mem_manifest",
        (identity) => {
          const effectiveMaxBytes =
            identity.credentialKind === "copilot-capability"
              ? Math.min(
                  maxBytes ?? COPILOT_MANIFEST_MAX_BYTES,
                  COPILOT_MANIFEST_MAX_BYTES,
                )
              : maxBytes;
          return kernel.memManifest(
            { variant, maxBytes: effectiveMaxBytes },
            identity,
            agentId,
          );
        },
        ctx,
        (result, identity) =>
          identity.credentialKind === "copilot-capability"
            ? copilotManifestResponse(result as ManifestResult)
            : ok(result),
      ),
  );

  server.registerTool(
    "company_file_list",
    {
      description:
        "Discover uploaded company files visible to your identity. A zero-result filtered search falls back to the governed active-file inventory and includes matchingEvidence ranked for the original query; analyze that evidence before choosing files to read.",
      inputSchema: z.object({
        query: z.string().trim().min(1).max(256).optional(),
        status: z
          .enum(["processing", "ready", "needs_review", "failed"])
          .optional(),
        lifecycleState: z.enum(["active", "archived"]).optional(),
        page: z.number().int().positive().optional(),
        pageSize: z.number().int().positive().max(50).optional(),
      }),
    },
    ({ query, status, lifecycleState, page, pageSize }, ctx) =>
      call(
        "company_file_list",
        async (identity, ctx) => {
          const resolvedQuery = identity.credentialKind === "copilot-capability"
            ? contextualQuery(identity, query ?? "", 256)
            : query;
          const result = await kernel.listCompanyFiles(
            { query: resolvedQuery, status, lifecycleState, page, pageSize },
            identity,
          );
          if (resolvedQuery === undefined || result.data.length > 0) return result;
          const inventory = await kernel.listCompanyFiles(
            {
              status: status ?? "ready",
              lifecycleState: lifecycleState ?? "active",
              page: 1,
              pageSize: 50,
            },
            identity,
          );
          let matchingEvidence: ScoredRef[] = [];
          try {
            const hits = await kernel.memSearch(
              { query: resolvedQuery, k: 8, tokenBudget: 12_000, live: "off" },
              identity,
              agentId,
              ctx,
            );
            matchingEvidence = hits.filter((hit) =>
              inventory.data.some((file) =>
                hit.content.includes(file.fileName),
              ),
            );
          } catch {
            // Catalog discovery is still useful during a retrieval brownout.
          }
          const evidenceRank = new Map<string, number>();
          for (const [index, hit] of matchingEvidence.entries()) {
            for (const file of inventory.data) {
              if (
                hit.content.includes(file.fileName) &&
                !evidenceRank.has(file.fileName)
              ) {
                evidenceRank.set(file.fileName, index);
              }
            }
          }
          const data = [...inventory.data].sort(
            (left, right) =>
              (evidenceRank.get(left.fileName) ?? Number.MAX_SAFE_INTEGER) -
                (evidenceRank.get(right.fileName) ?? Number.MAX_SAFE_INTEGER) ||
              left.fileName.localeCompare(right.fileName),
          );
          return { ...inventory, data, queryFallback: true, matchingEvidence };
        },
        ctx,
      ),
  );

  server.registerTool(
    "company_file_read",
    {
      description:
        "Read the governed L2 contents of one uploaded company file by exact filename. Use this after company_file_list before claiming the file contents are unavailable or not indexed.",
      inputSchema: z.object({
        fileName: z.string().trim().min(1).max(256),
      }),
    },
    ({ fileName }, ctx) =>
      call(
        "company_file_read",
        async (identity, ctx) => {
          const listed = await kernel.listCompanyFiles(
            {
              query: fileName,
              status: "ready",
              lifecycleState: "active",
              page: 1,
              pageSize: 50,
            },
            identity,
          );
          const file =
            listed.data.find(
              (candidate) =>
                candidate.fileName.toLocaleLowerCase() ===
                fileName.toLocaleLowerCase(),
            ) ?? null;
          if (file === null) return { found: false, file: null, evidence: [] };
          const hits = await kernel.memSearch(
            { query: file.fileName, k: 8, tokenBudget: 12_000, live: "off" },
            identity,
            agentId,
            ctx,
          );
          const evidence = hits.filter((hit) =>
            hit.content.includes(file.fileName),
          );
          return {
            found: evidence.length > 0,
            file,
            evidence,
          };
        },
        ctx,
      ),
  );

  server.registerTool(
    "skill_list",
    {
      description:
        "List visible organization skills and their approval/vetting state. Definitions are excluded; invoke a matching approved skill through skill_invoke.",
      inputSchema: z.object({}),
    },
    (_args, ctx) =>
      call(
        "skill_list",
        async (identity) =>
          (await kernel.listSkills(identity)).map((skill) => ({
            id: skill.id,
            skillKey: skill.skillKey,
            name: skill.name,
            description: skill.description,
            approvalStatus: skill.approvalStatus,
            vettingStatus: skill.vettingStatus,
            riskBand: skill.riskBand,
            status: skill.status,
            version: skill.version,
          })),
        ctx,
      ),
  );

  server.registerTool(
    "skill_invoke",
    {
      description:
        "Resolve one visible skill by key through the approval and vetting gates. Returns its definition only when invocation is allowed.",
      inputSchema: z.object({
        skillKey: z.string().trim().min(1).max(256),
      }),
    },
    ({ skillKey }, ctx) =>
      call(
        "skill_invoke",
        async (identity) => {
          const decision = await kernel.invokeSkill(identity, skillKey);
          if (decision.allowed || decision.skill === null) return decision;
          return {
            allowed: false,
            reason: decision.reason,
            skill: {
              id: decision.skill.id,
              skillKey: decision.skill.skillKey,
              name: decision.skill.name,
              description: decision.skill.description,
              approvalStatus: decision.skill.approvalStatus,
              vettingStatus: decision.skill.vettingStatus,
              status: decision.skill.status,
              version: decision.skill.version,
            },
          };
        },
        ctx,
      ),
  );

  server.registerTool(
    "mem_policy",
    {
      description:
        "READ THIS FIRST, before acting in this namespace. Returns the governed policy directives " +
        "(guardrails a human loaded into the policy register) that apply to your key's namespace and its " +
        "ancestors, as ranked blocks plus a `digest`. Place the blocks in your system prompt or working " +
        "context, then call mem_policy_ack with the digest. mem_assemble ships the same directives in its " +
        "reserved lane, so calling either one counts as having read the policy.",
      inputSchema: z.object({
        tokenBudget: z
          .number()
          .int()
          .positive()
          .optional()
          .describe(
            "Token cap on the directive set (default: the namespace's reserved policy slice)",
          ),
      }),
    },
    ({ tokenBudget }, ctx) =>
      call(
        "mem_policy",
        (identity, ctx) =>
          kernel.memPolicy({ tokenBudget }, identity, agentId, ctx),
        ctx,
      ),
  );

  server.registerTool(
    "mem_policy_ack",
    {
      description:
        "Acknowledge the policy digest returned by mem_policy or mem_assemble. Set `applied: true` when you " +
        "actually acted under those guardrails. A stale digest is rejected - re-read the policy first.",
      inputSchema: z.object({
        digest: z
          .string()
          .min(1)
          .describe("The `digest` from mem_policy / mem_assemble"),
        applied: z
          .boolean()
          .optional()
          .describe(
            "True when this call reports acting under the directives, not just receiving them",
          ),
        note: z
          .string()
          .max(500)
          .optional()
          .describe("Optional short note recorded with the acknowledgement"),
      }),
    },
    ({ digest, applied, note }, ctx) =>
      call(
        "mem_policy_ack",
        (identity, ctx) =>
          kernel.memPolicyAck(
            { digest, applied, note },
            identity,
            agentId,
            ctx,
          ),
        ctx,
      ),
  );

  server.registerTool(
    "mem_pin",
    {
      description:
        "Pin one stable memory or logical concept ULID into your namespace's working sets. Raw lookup text is never accepted.",
      inputSchema: z.object({
        kind: z.enum(["memory", "concept"]),
        ref: z
          .string()
          .min(1)
          .describe("Stable memory or logical concept ULID"),
      }),
    },
    ({ kind, ref }) =>
      call("mem_pin", (identity) =>
        kernel.memPin({ kind, ref } as PinTarget, identity),
      ),
  );

  server.registerTool(
    "mem_unpin",
    {
      description: "Release a governed pin by its stable pin ULID.",
      inputSchema: z.object({ pinId: z.string().min(1) }),
    },
    ({ pinId }) =>
      call("mem_unpin", (identity) => kernel.memUnpin(pinId, identity)),
  );

  server.registerTool(
    "mem_share",
    {
      description:
        "Explicitly mount one stable memory or logical concept into another namespace you administer. Cross-tenant sharing is denied and revocation is immediate.",
      inputSchema: z.object({
        kind: z.enum(["memory", "concept"]),
        ref: z.string().min(1),
        targetNamespace: z.string().min(1),
      }),
    },
    ({ kind, ref, targetNamespace }) =>
      call("mem_share", (identity) =>
        kernel.memShare({ kind, ref } as PinTarget, targetNamespace, identity),
      ),
  );

  server.registerTool(
    "mem_forget",
    {
      description:
        "Compliance erasure (owner/admin only): hard-delete every memory matching the target INSIDE your key's subtree, write tombstones, and return a signed deletion certificate. Auditor/member/agent are denied. Subtree-scoped: a target outside your subtree erases nothing.",
      inputSchema: z.object({
        kind: z
          .enum(["actor", "entity", "namespace", "memory"])
          .describe(
            "What to erase by: a person (actor), a canonical entity, a whole namespace subtree, or one memory id",
          ),
        value: z
          .string()
          .min(1)
          .describe(
            "The actor id, entity name, namespace, or memory ULID to erase",
          ),
      }),
    },
    ({ kind, value }) =>
      call("mem_forget", (identity) =>
        kernel.memForget(
          { target: { kind, value } as ForgetTarget },
          identity,
          agentId,
        ),
      ),
  );

  return server;
}
