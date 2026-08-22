/**
 * M9 #11b (D29/E23–E27) — hosted OAuth authorization server, WIRED.
 *
 * The adversarial review found the whole src/oauth/ module was dead code: no
 * route, no bearer resolution, no allowedTools enforcement. These tests pin
 * the wiring: client lifecycle (E23 sha256-only at rest, E24 transitive
 * revocation), token issuance through the envelope handlers, role mapping
 * (E25 assistant→agent / read-only→auditor, never admin), audited outcomes
 * (E26), and the kernel-syscall allowedTools chokepoint (E27).
 * Hermetic: in-memory PGlite, zero network.
 */

import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Kernel } from "../src/kernel.js";
import { buildHttpDeps } from "../src/http/adapter.js";
import { sha256Hex } from "../src/oauth/clients.js";
import { AuthzError } from "../src/auth/index.js";
import type { HttpServerDeps } from "../src/http/server.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let deps: HttpServerDeps;
let owner: Identity;

beforeAll(async () => {
  kernel = await Kernel.boot({
    databaseUrl: "",
    pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  deps = buildHttpDeps(kernel);
  owner = { keyId: "root", namespace: "", actor: "root-owner", role: "owner" };
});

afterAll(async () => {
  await kernel.close();
});

describe("D29 OAuth authorization server is live", () => {
  it("stores only sha256(secret) at rest and refuses a PENDING client (E23)", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "ci-bot", tokenRole: "assistant", allowedTools: ["mem_search"] },
      owner,
    );
    expect(clientSecret.startsWith("hmcs_")).toBe(true);
    const row = await kernel.db.query(
      `SELECT client_secret_hash FROM oauth_clients WHERE id = $1`,
      [record.id],
    );
    expect(row.rows[0].client_secret_hash).toBe(sha256Hex(clientSecret));

    // Pending → the token endpoint refuses (unauthorized_client), audited.
    const denied = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret,
      },
    });
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe("unauthorized_client");
  });

  it("issues, resolves, and tool-fences an approved client's token (E25/E26/E27)", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "search-bot", tokenRole: "assistant", allowedTools: ["mem_search"] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);

    const issued = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret,
      },
    });
    expect(issued.status).toBe(200);
    const accessToken = issued.body.access_token as string;
    expect(accessToken.startsWith("hmt_")).toBe(true);
    expect(issued.headers["cache-control"]).toBe("no-store");

    // Only the sha256 of the token is stored (E23).
    const tokenRow = await kernel.db.query(
      `SELECT token_hash FROM oauth_tokens WHERE token_hash = $1`,
      [sha256Hex(accessToken)],
    );
    expect(tokenRow.rows.length).toBe(1);

    // The bearer resolves SERVER-side to an agent identity — never admin (E25).
    const identity = await kernel.resolveOAuthIdentity(accessToken);
    expect(identity).not.toBeNull();
    expect(identity!.role).toBe("agent");
    expect(identity!.namespace).toBe("");
    expect([...identity!.allowedTools]).toEqual(["mem_search"]);

    // E27: the kernel syscall chokepoint enforces allowedTools server-side.
    await expect(kernel.memStats({}, identity!)).rejects.toThrow(AuthzError);
    const denialAudit = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM audit_log
        WHERE op = 'reject' AND result = 'denied' AND detail LIKE '%mem_stats%denied for oauth client%'`,
    );
    expect(Number(denialAudit.rows[0].n)).toBeGreaterThan(0);
    // The granted tool passes the fence (its own agent-gates still apply).
    await expect(
      kernel.memSearch({ query: "anything", k: 3 }, identity!),
    ).resolves.toBeDefined();
  });

  it("fences the billable copilot lane and the answer-outcome governance write (E27)", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "narrow-bot", tokenRole: "assistant", allowedTools: ["mem_search"] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);
    const issued = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret,
      },
    });
    const identity = await kernel.resolveOAuthIdentity(issued.body.access_token as string);
    expect(identity).not.toBeNull();

    // Billable copilot lane (message_out debit): refused BEFORE any credit is
    // charged or the LLM runtime is touched — 'copilot_complete' not granted.
    const before = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM credit_ledger WHERE reason = 'copilot-message'`,
    );
    await expect(
      deps.copilot!.complete({
        message: "hi",
        conversationId: "01H00000000000000000000000",
        turnId: "oauth-fence-turn",
      }, identity!),
    ).rejects.toThrow(AuthzError);
    const after = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM credit_ledger WHERE reason = 'copilot-message'`,
    );
    expect(Number(after.rows[0].n)).toBe(Number(before.rows[0].n));

    // D31 governance write: refused before any answer_outcomes row lands —
    // 'answer_outcome' not granted (and an empty list grants NO tools).
    await expect(
      kernel.recordAnswerOutcome(identity!, {
        turnId: "t-oauth-fence",
        outcome: "answered-without-human",
      }),
    ).rejects.toThrow(AuthzError);
    const rows = await kernel.db.query(
      `SELECT COUNT(*) AS n FROM answer_outcomes WHERE turn_id = 't-oauth-fence'`,
    );
    expect(Number(rows.rows[0].n)).toBe(0);
  });

  it("read-only clients map to auditor and never escalate (E25)", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "read-bot", tokenRole: "read-only", allowedTools: ["mem_read"] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);
    const issued = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret,
      },
    });
    const identity = await kernel.resolveOAuthIdentity(issued.body.access_token as string);
    expect(identity!.role).toBe("auditor");
  });

  it("revoking a client transitively kills its live tokens (E24)", async () => {
    const { record, clientSecret } = await kernel.oauthClients.create(
      { name: "doomed-bot", tokenRole: "assistant", allowedTools: [] },
      owner,
    );
    await kernel.oauthClients.approve(record.id, owner);
    const issued = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret,
      },
    });
    const accessToken = issued.body.access_token as string;
    expect(await kernel.resolveOAuthIdentity(accessToken)).not.toBeNull();

    const { tokensRevoked } = await kernel.oauthClients.revoke(record.id, "compromised", owner);
    expect(tokensRevoked).toBe(1);
    expect(await kernel.resolveOAuthIdentity(accessToken)).toBeNull();
  });

  it("mounts the transport surface: metadata, bearer resolution, admin registry", async () => {
    // The HttpServerDeps the real server consumes must carry the OAuth lane.
    expect(deps.oauth).toBeDefined();
    const metadata = deps.oauth!.metadata("https://memory.example.com");
    expect(metadata.body.token_endpoint).toBe("https://memory.example.com/oauth/token");
    expect(deps.auth.resolveOauth).toBeDefined();
    expect(deps.admin.createOAuthClient).toBeDefined();
    expect(deps.admin.approveOAuthClient).toBeDefined();
    expect(deps.admin.revokeOAuthClient).toBeDefined();
    expect(deps.admin.listOAuthClients).toBeDefined();

    // An unknown hmt_ bearer resolves to null (→ 401), audited as a miss.
    expect(await deps.auth.resolveOauth!("hmt_" + "0".repeat(64))).toBeNull();
  });

  it("introspection is scoped to the authenticated client (RFC 7662)", async () => {
    const a = await kernel.oauthClients.create(
      { name: "client-a", tokenRole: "assistant", allowedTools: [] }, owner,
    );
    const b = await kernel.oauthClients.create(
      { name: "client-b", tokenRole: "assistant", allowedTools: [] }, owner,
    );
    await kernel.oauthClients.approve(a.record.id, owner);
    await kernel.oauthClients.approve(b.record.id, owner);
    const issued = await kernel.oauthToken({
      body: {
        grant_type: "client_credentials",
        client_id: a.record.clientId,
        client_secret: a.clientSecret,
      },
    });
    const token = issued.body.access_token as string;

    const own = await kernel.oauthIntrospect({
      body: { token, client_id: a.record.clientId, client_secret: a.clientSecret },
    });
    expect(own.body.active).toBe(true);
    const foreign = await kernel.oauthIntrospect({
      body: { token, client_id: b.record.clientId, client_secret: b.clientSecret },
    });
    expect(foreign.body.active).toBe(false);
  });
});
