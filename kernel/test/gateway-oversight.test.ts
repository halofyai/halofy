import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import type {
  AgentConnectionGrant,
  AgentConnectionOversight,
  ExactAgentAccessRequest,
  GatewayAdministrativeIdentity,
  ResolvedAgentIdentity,
} from "../src/gateway/contracts.js";
import { AgentOversightStore } from "../src/gateway/oversight.js";
import { AgentConnectionGrantStore } from "../src/gateway/store.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";
import { seedActiveSourceTeam } from "./source-team-test-fixture.js";

const DIM = 8;
const OVERSIGHT: AgentConnectionOversight = {
  maxRequestsPerMinute: 60,
  usageAlertThreshold: 2,
  deniedAlertThreshold: 2,
  recipientRoles: ["owner", "admin"],
  accessRequests: "allowed",
  approvalTtlSeconds: 3_600,
};

let db: Db;
let now: Date;
let idSequence: number;
let store: AgentOversightStore;

const admin = (
  namespace: string,
  role: GatewayAdministrativeIdentity["role"] = "admin",
): GatewayAdministrativeIdentity => ({ namespace, role });

const agent = (
  keyId = "key-eng",
  namespace = "acme/eng",
): ResolvedAgentIdentity => ({ keyId, namespace, role: "agent" });

function grant(
  overrides: Partial<AgentConnectionGrant> = {},
): AgentConnectionGrant {
  return {
    id: "grant-eng",
    keyId: "key-eng",
    namespace: "acme/eng",
    connectorId: "postgres-primary",
    allowedOperations: ["source-read"],
    allowedSourceRefs: ["customers"],
    allowedFields: { customers: ["id", "name"] },
    allowedPurposes: ["support"],
    maxSensitivity: "confidential",
    maxRows: 25,
    maxBytes: 64_000,
    policyVersion: 1,
    status: "active",
    expiresAt: "2099-01-01T00:00:00.000Z",
    oversight: OVERSIGHT,
    ...overrides,
  };
}

async function seedGrant(
  value: AgentConnectionGrant = grant(),
): Promise<void> {
  await db.query(
    `INSERT INTO api_keys
       (id, key_hash, namespace, actor, role, status, created_at, last_used)
     VALUES ($1, $2, $3, $4, 'agent', 'active', $5, NULL)`,
    [
      value.keyId,
      `hash-${value.keyId}`,
      value.namespace,
      `agent:${value.keyId}`,
      now.toISOString(),
    ],
  );
  await db.query(
    `INSERT INTO sources (id, namespace, kind, config, created_at)
     VALUES ($1, $2, 'postgres', '{}', $3)`,
    [value.connectorId, value.namespace, now.toISOString()],
  );
  await new AgentConnectionGrantStore(db).create(value, admin("acme"));
}

function event(
  overrides: Record<string, unknown> = {},
) {
  return {
    grantId: "grant-eng",
    keyId: "key-eng",
    namespace: "acme/eng",
    connectorId: "postgres-primary",
    sourceRef: "customers",
    operation: "source-read" as const,
    purpose: "support",
    decision: "allowed" as const,
    reasonCode: "within-scope",
    rows: 1,
    bytes: 100,
    policyVersion: 1,
    accessRequestId: null,
    ...overrides,
  };
}

function request(
  overrides: Record<string, unknown> = {},
) {
  return {
    grantId: "grant-eng",
    connectorId: "postgres-primary",
    sourceRef: "customers",
    operation: "source-read" as const,
    purpose: "support",
    requestedFields: ["id", "name"],
    requestedRows: 10,
    requestedBytes: 4_096,
    justification: "Resolve the active support case",
    requestedDurationSeconds: 1_800,
    maxUses: 2,
    ...overrides,
  };
}

function exact(
  overrides: Partial<ExactAgentAccessRequest> = {},
): ExactAgentAccessRequest {
  return {
    grantId: "grant-eng",
    connectorId: "postgres-primary",
    sourceRef: "customers",
    operation: "source-read",
    purpose: "support",
    requestedFields: ["id", "name"],
    requestedRows: 10,
    requestedBytes: 4_096,
    ...overrides,
  };
}

beforeEach(async () => {
  db = await createDb(loadConfig({
    databaseUrl: "",
    pgliteDataDir: "",
    embedDim: DIM,
  }));
  await migrate(db, DIM);
  now = new Date("2026-07-17T10:00:00.000Z");
  idSequence = 0;
  store = new AgentOversightStore(db, {
    now: () => now,
    makeId: () => `oversight-${++idSequence}`,
  });
  await seedGrant();
});

afterEach(async () => {
  await db.close();
});

describe("AgentOversightStore events and alerts", () => {
  it("writes the event and synchronously alerts at the configured denial threshold", async () => {
    const first = await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      OVERSIGHT,
    );
    const second = await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      OVERSIGHT,
    );
    const third = await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      OVERSIGHT,
    );

    expect(first.alerts).toEqual([
      expect.objectContaining({
        kind: "outside-scope",
        severity: "critical",
        recipientRoles: ["owner", "admin"],
        status: "open",
      }),
    ]);
    expect(second.alerts).toEqual([
      expect.objectContaining({ kind: "outside-scope" }),
      expect.objectContaining({ kind: "repeated-denial" }),
    ]);
    expect(third.alerts).toHaveLength(2);
    const rows = await db.query("SELECT COUNT(*) AS n FROM agent_access_alerts");
    expect(Number(rows.rows[0]?.n)).toBe(2);
  });

  it("serializes concurrent denials so the repeated-denial threshold cannot be lost", async () => {
    await Promise.all([
      store.recordEvent(
        event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
        OVERSIGHT,
      ),
      store.recordEvent(
        event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
        OVERSIGHT,
      ),
    ]);

    const alerts = await store.listAlerts(admin("acme"));
    expect(alerts.filter((alert) => alert.kind === "outside-scope")).toHaveLength(1);
    expect(alerts.filter((alert) => alert.kind === "repeated-denial")).toHaveLength(1);
  });

  it("creates an immediate rate-limit alert and a usage warning at the hourly threshold", async () => {
    const rateLimited = await store.recordEvent(
      event({ decision: "denied", reasonCode: "rate-limit", rows: 0, bytes: 0 }),
      OVERSIGHT,
    );
    expect(rateLimited.alerts).toEqual([
      expect.objectContaining({ kind: "rate-limit", severity: "critical" }),
    ]);

    expect((await store.recordEvent(event(), OVERSIGHT)).alerts).toEqual([]);
    expect((await store.recordEvent(event(), OVERSIGHT)).alerts).toEqual([
      expect.objectContaining({ kind: "usage-threshold", severity: "warning" }),
    ]);
  });

  it.each([
    "policy-version-mismatch",
    "authority-revoked",
    "credential-inactive",
    "source-authority-changed",
    "approval-changed",
    "authority-unavailable",
  ])("creates an authority-change alert for runtime reason %s", async (reasonCode) => {
    expect((await store.recordEvent(
      event({
        decision: "denied",
        reasonCode,
        rows: 0,
        bytes: 0,
      }),
      { ...OVERSIGHT, deniedAlertThreshold: 1 },
    )).alerts).toEqual([
      expect.objectContaining({ kind: "authority-change", severity: "critical" }),
    ]);
  });

  it("rejects content-bearing or malformed event input before persistence", async () => {
    await expect(store.recordEvent(
      { ...event(), query: "SELECT * FROM customers" } as never,
      OVERSIGHT,
    )).rejects.toThrow(/invalid.*event/i);
    await expect(store.recordEvent(
      event({ rows: -1 }),
      OVERSIGHT,
    )).rejects.toThrow(/invalid.*event/i);
    expect((await db.query("SELECT 1 FROM agent_access_events")).rows).toHaveLength(0);
  });

  it("lists and acknowledges alerts only inside the administrator subtree", async () => {
    const recorded = await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      { ...OVERSIGHT, deniedAlertThreshold: 1 },
    );
    const alertId = recorded.alerts[0]!.id;

    expect(await store.listAlerts(admin("acme/eng"), { status: "open" }))
      .toHaveLength(1);
    expect(await store.listAlerts(admin("acme/sales"), { status: "open" }))
      .toHaveLength(0);
    expect(await store.acknowledgeAlert(
      alertId,
      admin("acme/sales"),
      "admin:sales",
    )).toBe(false);
    expect(await store.acknowledgeAlert(
      alertId,
      admin("acme"),
      "owner:acme",
    )).toBe(true);
    expect(await store.listAlerts(admin("acme"), { status: "acknowledged" }))
      .toEqual([expect.objectContaining({ id: alertId, status: "acknowledged" })]);
  });

  it("allows auditors to inspect events and alerts without mutation authority", async () => {
    await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      {
        ...OVERSIGHT,
        deniedAlertThreshold: 1,
        recipientRoles: ["owner", "admin", "auditor"],
      },
    );
    const auditor = { namespace: "acme", role: "auditor" } as const;
    expect(await store.listEvents(auditor)).toHaveLength(1);
    expect(await store.listAlerts(auditor)).toHaveLength(1);
  });

  it("lists alerts only for viewer roles selected by the immutable recipient policy", async () => {
    await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      { ...OVERSIGHT, deniedAlertThreshold: 1, recipientRoles: ["owner"] },
    );
    expect(await store.listAlerts({ namespace: "acme", role: "owner" }))
      .toHaveLength(1);
    expect(await store.listAlerts({ namespace: "acme", role: "admin" }))
      .toHaveLength(0);
    expect(await store.listAlerts({ namespace: "acme", role: "auditor" }))
      .toHaveLength(0);
  });

  it("escapes wildcard characters while listing event subtrees", async () => {
    await store.recordEvent(event(), OVERSIGHT);
    expect(await store.listEvents(admin("acme/eng"), { keyId: "key-eng" }))
      .toHaveLength(1);
    expect(await store.listEvents(admin("acme/en_"), {})).toHaveLength(0);
  });
});

describe("AgentOversightStore temporary access requests", () => {
  it("creates an exact badge-bound request and hides it from sibling badges and admins", async () => {
    const created = await store.createRequest(request(), agent());

    expect(created).toMatchObject({
      keyId: "key-eng",
      namespace: "acme/eng",
      grantId: "grant-eng",
      connectorId: "postgres-primary",
      requestedFields: ["id", "name"],
      status: "pending",
      usedCount: 0,
      maxUses: 2,
    });
    expect(await store.listRequestsForAgent(agent())).toEqual([created]);
    expect(await store.listRequestsForAgent(agent("other-key", "acme/eng")))
      .toEqual([]);
    expect(await store.listRequests(admin("acme/eng"), { status: "pending" }))
      .toEqual([created]);
    expect(await store.listRequests(admin("acme/sales"), { status: "pending" }))
      .toEqual([]);
    expect(await store.listRequests(
      { namespace: "acme", role: "auditor" },
      { status: "pending" },
    )).toEqual([created]);
  });

  it("rejects disabled requests, grant mismatches, unsafe fields, and content-bearing input", async () => {
    await db.query(
      "UPDATE agent_connection_grants SET oversight = $1::jsonb WHERE id = $2",
      [JSON.stringify({ ...OVERSIGHT, accessRequests: "disabled" }), "grant-eng"],
    );
    await expect(store.createRequest(request(), agent())).rejects.toThrow(/disabled/i);
    await db.query(
      "UPDATE agent_connection_grants SET oversight = $1::jsonb WHERE id = $2",
      [JSON.stringify(OVERSIGHT), "grant-eng"],
    );
    await expect(store.createRequest(
      request({ connectorId: "postgres-other" }),
      agent(),
    )).rejects.toThrow(/grant|binding/i);
    await expect(store.createRequest(
      request({ requestedFields: ["secret; DROP TABLE customers"] }),
      agent(),
    )).rejects.toThrow(/invalid.*request/i);
    await expect(store.createRequest(
      { ...request(), query: "customer Ada" } as never,
      agent(),
    )).rejects.toThrow(/invalid.*request/i);
  });

  it("approves only a tighter duration/use cap and validates every exact field", async () => {
    const created = await store.createRequest(request(), agent());
    const approved = await store.approveRequest(
      created.id,
      admin("acme"),
      "owner:acme",
      { durationSeconds: 900, maxUses: 1, note: "One support lookup" },
    );
    expect(approved).toMatchObject({
      status: "approved",
      maxUses: 1,
      decidedBy: "owner:acme",
    });
    expect(approved?.approvedUntil).toBe("2026-07-17T10:15:00.000Z");
    await expect(store.validateApprovedRequest(
      created.id,
      exact(),
      agent(),
    )).resolves.toMatchObject({ id: created.id, status: "approved" });

    for (const mismatch of [
      exact({ grantId: "grant-other" }),
      exact({ connectorId: "postgres-other" }),
      exact({ sourceRef: "orders" }),
      exact({ purpose: "training" }),
      exact({ requestedFields: ["id"] }),
      exact({ requestedRows: 11 }),
      exact({ requestedBytes: 4_097 }),
    ]) {
      await expect(store.validateApprovedRequest(
        created.id,
        mismatch,
        agent(),
      )).resolves.toBeNull();
    }
  });

  it("atomically consumes one use and cannot be replayed", async () => {
    const created = await store.createRequest(request({ maxUses: 1 }), agent());
    await store.approveRequest(
      created.id,
      admin("acme"),
      "owner:acme",
      { durationSeconds: 900, maxUses: 1 },
    );

    const attempts = await Promise.all([
      store.consumeApprovedRequest(created.id, exact(), agent()),
      store.consumeApprovedRequest(created.id, exact(), agent()),
    ]);
    expect(attempts.filter(Boolean)).toHaveLength(1);
    expect(attempts.find(Boolean)).toMatchObject({
      status: "consumed",
      usedCount: 1,
    });
    await expect(store.validateApprovedRequest(created.id, exact(), agent()))
      .resolves.toBeNull();
  });

  it("fails closed after expiry, badge revocation, and namespace mismatch", async () => {
    const created = await store.createRequest(request(), agent());
    await store.approveRequest(created.id, admin("acme"), "owner:acme", {
      durationSeconds: 60,
      maxUses: 1,
    });
    now = new Date("2026-07-17T10:01:00.000Z");
    await expect(store.validateApprovedRequest(created.id, exact(), agent()))
      .resolves.toBeNull();

    now = new Date("2026-07-17T10:00:00.000Z");
    const active = await store.createRequest(request(), agent());
    await store.approveRequest(active.id, admin("acme"), "owner:acme", {});
    await db.query("UPDATE api_keys SET status = 'revoked' WHERE id = 'key-eng'");
    await expect(store.consumeApprovedRequest(active.id, exact(), agent()))
      .resolves.toBeNull();
    await expect(store.consumeApprovedRequest(
      active.id,
      exact(),
      agent("key-eng", "acme/sales"),
    )).resolves.toBeNull();
  });

  it("prevents sibling administration and terminal requests from being decided again", async () => {
    const created = await store.createRequest(request(), agent());
    await expect(store.approveRequest(
      created.id,
      admin("acme/sales"),
      "admin:sales",
      {},
    )).resolves.toBeNull();
    await expect(store.denyRequest(
      created.id,
      admin("acme"),
      "owner:acme",
      { note: "Not needed" },
    )).resolves.toMatchObject({ status: "denied" });
    await expect(store.approveRequest(
      created.id,
      admin("acme"),
      "owner:acme",
      {},
    )).resolves.toBeNull();
  });

  it("applies subtree scope in SQL before parsing a sibling request row", async () => {
    const siblingGrant = grant({
      id: "grant-sales",
      keyId: "key-sales",
      namespace: "acme/sales",
      connectorId: "postgres-sales",
    });
    await seedGrant(siblingGrant);
    const siblingRequest = await store.createRequest(
      request({ grantId: siblingGrant.id, connectorId: siblingGrant.connectorId }),
      agent(siblingGrant.keyId, siblingGrant.namespace),
    );
    await db.query(
      "UPDATE agent_access_requests SET requested_fields = '[1]'::jsonb WHERE id = $1",
      [siblingRequest.id],
    );

    await expect(store.approveRequest(
      siblingRequest.id,
      admin("acme/eng"),
      "admin:eng",
      {},
    )).resolves.toBeNull();
    await expect(store.denyRequest(
      siblingRequest.id,
      admin("acme/eng"),
      "admin:eng",
      {},
    )).resolves.toBeNull();
  });

  it("supports outer transactions for audited request and alert mutations", async () => {
    await expect(db.transaction(async (tx) => {
      await store.createRequestInTransaction(tx, request(), agent());
      throw new Error("rollback create and audit together");
    })).rejects.toThrow(/rollback create/i);
    expect((await db.query("SELECT 1 FROM agent_access_requests")).rows).toHaveLength(0);

    const pendingApprove = await store.createRequest(request(), agent());
    const pendingDeny = await store.createRequest(request(), agent());
    const alert = (await store.recordEvent(
      event({ decision: "denied", reasonCode: "source-ref-denied", rows: 0, bytes: 0 }),
      { ...OVERSIGHT, deniedAlertThreshold: 1 },
    )).alerts[0]!;

    await expect(db.transaction(async (tx) => {
      await store.approveRequestInTransaction(
        tx, pendingApprove.id, admin("acme"), "owner:acme", {},
      );
      await store.denyRequestInTransaction(
        tx, pendingDeny.id, admin("acme"), "owner:acme", {},
      );
      await store.acknowledgeAlertInTransaction(
        tx, alert.id, admin("acme"), "owner:acme",
      );
      throw new Error("rollback mutations and audit together");
    })).rejects.toThrow(/rollback mutations/i);

    expect(await store.listRequests(admin("acme"), { status: "pending" }))
      .toHaveLength(2);
    expect(await store.listAlerts(admin("acme"), { status: "open" }))
      .toHaveLength(1);
  });
});

describe("AgentConnectionGrantStore listActiveForKey", () => {
  it("returns only the caller badge's own active grants, never a sibling badge's", async () => {
    const store = new AgentConnectionGrantStore(db);
    const own = await store.listActiveForKey("key-eng");
    expect(own.map((row) => row.id)).toEqual(["grant-eng"]);
    expect(own[0]).toMatchObject({
      keyId: "key-eng",
      namespace: "acme/eng",
      status: "active",
      oversight: OVERSIGHT,
    });

    await seedGrant(grant({
      id: "grant-sales",
      keyId: "key-sales",
      namespace: "acme/sales",
      connectorId: "postgres-sales",
    }));
    expect((await store.listActiveForKey("key-eng")).map((row) => row.id))
      .toEqual(["grant-eng"]);
    expect((await store.listActiveForKey("key-sales")).map((row) => row.id))
      .toEqual(["grant-sales"]);
    expect(await store.listActiveForKey("key-unknown")).toEqual([]);
  });

  it("excludes expired grants, revoked grants, and grants of revoked badges", async () => {
    const store = new AgentConnectionGrantStore(db);
    await seedGrant(grant({
      id: "grant-expired",
      keyId: "key-exp",
      namespace: "acme/exp",
      connectorId: "postgres-exp",
      expiresAt: "2020-01-01T00:00:00.000Z",
    }));
    expect(await store.listActiveForKey("key-exp")).toEqual([]);

    await db.query(
      "UPDATE agent_connection_grants SET status = 'revoked' WHERE id = 'grant-eng'",
    );
    expect(await store.listActiveForKey("key-eng")).toEqual([]);

    await db.query(
      "UPDATE agent_connection_grants SET status = 'active' WHERE id = 'grant-eng'",
    );
    expect(await store.listActiveForKey("key-eng")).toHaveLength(1);
    await db.query("UPDATE api_keys SET status = 'revoked' WHERE id = 'key-eng'");
    expect(await store.listActiveForKey("key-eng")).toEqual([]);
  });
});

describe("Kernel describeAgentAccess", () => {
  let kernel: Kernel;
  let knowledgeDir: string;
  let root: Identity;
  let setupSequence = 0;

  beforeAll(async () => {
    knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-describe-"));
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      knowledgeDir,
      coldKek: randomBytes(32).toString("base64"),
    });
    const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
    const resolved = await kernel.auth.resolve(rootKey.plaintext);
    if (!resolved) throw new Error("root identity did not resolve");
    root = resolved;
  }, 120_000);

  afterAll(async () => {
    await kernel.close();
    await rm(knowledgeDir, { recursive: true, force: true });
  });

  async function setupBadge(
    oversight?: AgentConnectionOversight,
  ): Promise<{ agent: Identity; grantId: string }> {
    setupSequence += 1;
    const namespace = `describeco/team-${setupSequence}`;
    await seedActiveSourceTeam(kernel, namespace);
    const ownerKey = await kernel.auth.issueKey(namespace, `owner:${namespace}`, "owner", root);
    const owner = await kernel.auth.resolve(ownerKey.plaintext);
    if (!owner) throw new Error("owner identity did not resolve");
    const agentKey = await kernel.auth.issueKey(namespace, `agent:${namespace}`, "agent", owner);
    const agent = await kernel.auth.resolve(agentKey.plaintext);
    if (!agent) throw new Error("agent identity did not resolve");
    const source = await kernel.registerSource(
      "postgres",
      { credentialMode: "service", serviceSecret: "postgres://describe.internal/db" },
      owner,
    );
    const created = await kernel.createAgentConnectionGrant({
      keyId: agent.keyId,
      connectorId: source.id,
      allowedOperations: ["source-read"],
      allowedSourceRefs: ["customers"],
      allowedFields: { customers: ["id", "name"] },
      allowedPurposes: ["support"],
      maxSensitivity: "internal",
      maxRows: 10,
      maxBytes: 4_096,
      expiresAt: null,
      ...(oversight ? { oversight } : {}),
    }, owner);
    return { agent, grantId: created.id };
  }

  it("describes the badge's own grant with escalation enabled and a hint", async () => {
    const { agent, grantId } = await setupBadge({
      ...OVERSIGHT,
      accessRequests: "allowed",
      approvalTtlSeconds: 900,
    });
    const other = await setupBadge();

    const description = await kernel.describeAgentAccess(agent);
    expect(description).toHaveLength(1);
    expect(description[0]).toEqual({
      grantId,
      connectorId: expect.any(String),
      allowedOperations: ["source-read"],
      allowedSourceRefs: ["customers"],
      allowedFields: { customers: ["id", "name"] },
      allowedPurposes: ["support"],
      maxRows: 10,
      maxBytes: 4_096,
      maxSensitivity: "internal",
      expiresAt: null,
      policyVersion: 1,
      accessRequests: {
        enabled: true,
        maxDurationSeconds: 86_400,
        approvalTtlSeconds: 900,
        maxUsesCap: 100,
      },
      hint: expect.stringContaining("request_access"),
    });
    expect(description[0]?.hint).toContain("POST /v1/agent/access-requests");

    // The second badge never sees the first badge's grant.
    const otherDescription = await kernel.describeAgentAccess(other.agent);
    expect(otherDescription).toHaveLength(1);
    expect(otherDescription[0]?.grantId).not.toBe(grantId);
  });

  it("reports escalation disabled without a hint", async () => {
    const { agent } = await setupBadge({ ...OVERSIGHT, accessRequests: "disabled" });
    const description = await kernel.describeAgentAccess(agent);
    expect(description).toHaveLength(1);
    expect(description[0]?.accessRequests).toEqual({
      enabled: false,
      maxDurationSeconds: 86_400,
      approvalTtlSeconds: OVERSIGHT.approvalTtlSeconds,
      maxUsesCap: 100,
    });
    expect(description[0]).not.toHaveProperty("hint");
  });

  it("denies non-agent identities with an audited agent-role-required", async () => {
    await expect(kernel.describeAgentAccess(root)).rejects.toThrow(/agent role required/i);
    const audits = await kernel.db.query(
      `SELECT result, detail FROM audit_log
        WHERE purpose = 'gateway-describe-access' AND result = 'denied'`,
    );
    expect(audits.rows.length).toBeGreaterThan(0);
    expect(String(audits.rows[0]?.detail)).toContain("reason=agent-role-required");
  });
});
