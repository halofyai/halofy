/**
 * D50 (CONTRACTS-AGENT-SCOPE.md) — an agent never has more authority than the
 * human who deployed it, and no agent is ever organization-wide.
 *
 * Covers the exit criteria: the organization-root ban (every issuer, root owner
 * included), the team ceiling, the issuer table (root owner / admin / member),
 * level persistence and rotation, the D4 denial rows, and the end-to-end effect
 * — an assistant key bound to team A cannot read or search team B's memory.
 * Hermetic: in-memory PGlite, HashEmbedder, StubLlm, zero network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { loadConfig } from "../src/config.js";
import { AuditLog } from "../src/audit/index.js";
import { AuthService, AuthzError } from "../src/auth/index.js";
import { ProductKeyService } from "../src/auth/key-types.js";
import { assertAgentKeyScope, effectiveAgentLevel } from "../src/auth/agent-scope.js";
import { Kernel } from "../src/kernel.js";
import { SessionStore, UserStore, hashPassword } from "../src/console/auth.js";
import type { Identity } from "../src/types.js";

const DIM = 8;

let db: Db;
let auth: AuthService;
let audit: AuditLog;
let keys: ProductKeyService;
let rootOwner: Identity;

/** Two sibling teams under one tenant, plus one sub-team under marketing. */
const TENANT = "acme";
const MARKETING = "acme/marketing";
const SALES = "acme/sales";
const MARKETING_BRAND = "acme/marketing/brand";

async function registerTeam(namespace: string, name: string): Promise<void> {
  await db.query(
    `INSERT INTO org_teams (id, namespace, organization_namespace, name, description,
                            created_by, created_at)
     VALUES ($1, $2, $3, $4, '', 'test', $5)`,
    [`team-${name}`, namespace, TENANT, name, new Date().toISOString()],
  );
}

async function deniedCount(like: string): Promise<number> {
  const res = await db.query(
    `SELECT COUNT(*) AS n FROM audit_log
      WHERE result = 'denied' AND detail LIKE $1 ESCAPE '\\'`,
    [like],
  );
  return Number(res.rows[0].n);
}

/** The id of the single fact a verbatim write stored. */
function storedId(result: unknown): string {
  const stored = (result as { stored?: Array<{ id: string }> }).stored ?? [];
  if (stored.length === 0) throw new Error("write stored nothing");
  return stored[0]!.id;
}

function human(role: Identity["role"], namespace: string): Identity {
  return { keyId: `k-${role}-${namespace}`, namespace, actor: `${role}@acme.test`, role };
}

beforeAll(async () => {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  db = await createDb(config);
  await migrate(db, DIM);
  audit = new AuditLog(db);
  auth = new AuthService(db, audit);
  keys = new ProductKeyService(db, auth, audit);
  const { plaintext } = await auth.issueKey("", "root@acme.test", "owner");
  const resolved = await auth.resolve(plaintext);
  if (!resolved) throw new Error("bootstrap owner did not resolve");
  rootOwner = resolved;
  await registerTeam(MARKETING, "marketing");
  await registerTeam(SALES, "sales");
  await registerTeam(MARKETING_BRAND, "brand");
});

afterAll(async () => {
  await db.close();
});

describe("the two absolute bounds", () => {
  it("refuses an organization-root agent even for the root owner, and audits it", async () => {
    const before = await deniedCount("key issue denied: agent scope%");
    await expect(
      keys.issue({ type: "assistant", namespace: "", actor: "org-bot" }, rootOwner),
    ).rejects.toThrow(AuthzError);
    expect(await deniedCount("key issue denied: agent scope%")).toBe(before + 1);
  });

  it("refuses a tenant root that CONTAINS more than one team (the team ceiling)", async () => {
    await expect(
      keys.issue({ type: "assistant", namespace: TENANT, actor: "tenant-bot" }, rootOwner),
    ).rejects.toThrow(/may not exceed one team/);
  });

  it("allows a namespace that contains no team at all", async () => {
    // The ceiling forbids SPANNING teams, not "not being a team". A namespace
    // with no team under it spans nothing.
    const issued = await keys.issue(
      { type: "assistant", namespace: "acme/support", actor: "support-bot" },
      rootOwner,
    );
    expect(issued.record.namespace).toBe("acme/support");
  });

  it("allows a team namespace and a namespace below a team", async () => {
    const team = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "campaign-bot" },
      rootOwner,
    );
    expect(team.record.namespace).toBe(MARKETING);
    const below = await keys.issue(
      { type: "assistant", namespace: `${MARKETING}/alice`, actor: "alice-bot" },
      rootOwner,
    );
    expect(below.record.namespace).toBe(`${MARKETING}/alice`);
  });

  it("still refuses the organization root when no teams are registered", async () => {
    // Brownout path: with an empty org_teams the ceiling cannot be measured, but
    // rule 1 is absolute and must survive on its own.
    const bare = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM }));
    try {
      await migrate(bare, DIM);
      await expect(
        assertAgentKeyScope(bare, { ...rootOwner, namespace: "" }, { namespace: "" }),
      ).rejects.toThrow(/organization root/);
      // …and an arbitrary namespace is fine, because there is no ceiling yet.
      const decision = await assertAgentKeyScope(bare, rootOwner, { namespace: "anything" });
      expect(decision).toEqual({ namespace: "anything", level: "member" });
    } finally {
      await bare.close();
    }
  });
});

/**
 * D51 (CONTRACTS-AGENT-DEPLOY.md) — a deployed agent may carry a bounded
 * lifetime. Expiry is stored authority: read from the row, never from a
 * request, and enforced at resolve so it kills every transport at once.
 */
describe("bounded lifetime", () => {
  const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

  it("stores the expiry and reports it back on the record", async () => {
    const expiresAt = inDays(30);
    const issued = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "ttl-bot", expiresAt, description: "seasonal" },
      rootOwner,
    );
    expect(issued.record.expiresAt).toBe(expiresAt);
    expect(issued.record.expired).toBe(false);
    expect(issued.record.description).toBe("seasonal");
    const listed = (await keys.list(rootOwner)).find((k) => k.id === issued.record.id);
    expect(listed?.expiresAt).toBe(expiresAt);
    expect(listed?.expired).toBe(false);
  });

  it("refuses an expiry that has already passed rather than minting a dead key", async () => {
    await expect(
      keys.issue(
        { type: "assistant", namespace: MARKETING, actor: "past-bot", expiresAt: inDays(-1) },
        rootOwner,
      ),
    ).rejects.toThrow(/already in the past/);
  });

  it("stops resolving the moment the expiry passes, and audits why", async () => {
    const issued = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "lapse-bot", expiresAt: inDays(1) },
      rootOwner,
    );
    expect(await auth.resolve(issued.plaintext)).not.toBeNull();

    // Move the stored expiry into the past — the row is the only authority.
    await db.query(`UPDATE api_keys SET expires_at = $1 WHERE id = $2`, [
      new Date(Date.now() - 1000).toISOString(),
      issued.record.id,
    ]);
    const before = await deniedCount("resolve denied: key % expired at %");
    expect(await auth.resolve(issued.plaintext)).toBeNull();
    expect(await deniedCount("resolve denied: key % expired at %")).toBe(before + 1);

    // Expiry is not revocation: the row is still 'active', and the listing
    // says so honestly by flagging it rather than lying about its status.
    const listed = (await keys.list(rootOwner)).find((k) => k.id === issued.record.id);
    expect(listed?.status).toBe("active");
    expect(listed?.expired).toBe(true);
  });

  it("carries the expiry through rotation, and refuses to rotate a lapsed one", async () => {
    const expiresAt = inDays(45);
    const issued = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "rotate-ttl-bot", expiresAt },
      rootOwner,
    );
    const rotated = await keys.rotate(issued.record.id, rootOwner);
    expect(rotated.record.expiresAt).toBe(expiresAt);

    await db.query(`UPDATE api_keys SET expires_at = $1 WHERE id = $2`, [
      new Date(Date.now() - 1000).toISOString(),
      rotated.record.id,
    ]);
    await expect(keys.rotate(rotated.record.id, rootOwner)).rejects.toThrow(/cannot be rotated/);
  });

  it("leaves a credential with no expiry as standing access", async () => {
    const issued = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "standing-bot" },
      rootOwner,
    );
    expect(issued.record.expiresAt).toBeUndefined();
    expect(await auth.resolve(issued.plaintext)).not.toBeNull();
  });
});

/**
 * D54 — a read-only agent may search and read memory but never change it.
 * Deliberately its own capability rather than the `read-only` key type, which
 * maps to role 'auditor' and would also hand the agent the audit trail.
 */
describe("read-only agents", () => {
  it("stores the capability and reports it on the record", async () => {
    const readOnly = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "ro-bot", agentCanWrite: false },
      rootOwner,
    );
    expect(readOnly.record.agentCanWrite).toBe(false);
    const writer = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "rw-bot" },
      rootOwner,
    );
    expect(writer.record.agentCanWrite).toBe(true);
    const listed = (await keys.list(rootOwner)).find((k) => k.id === readOnly.record.id);
    expect(listed?.agentCanWrite).toBe(false);
  });

  it("puts the capability on the resolved identity, never on the request", async () => {
    const readOnly = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "ro-identity-bot", agentCanWrite: false },
      rootOwner,
    );
    const identity = await auth.resolve(readOnly.plaintext);
    expect(identity?.agentCanWrite).toBe(false);
    // A human key type has no such capability — its write rules come from role.
    const admin = await keys.issue(
      { type: "admin", namespace: MARKETING, actor: "human-admin", agentCanWrite: false },
      rootOwner,
    );
    const adminIdentity = await auth.resolve(admin.plaintext);
    expect(adminIdentity?.agentCanWrite).toBeUndefined();
  });

  it("survives rotation in both directions", async () => {
    const readOnly = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "ro-rotate-bot", agentCanWrite: false },
      rootOwner,
    );
    const rotatedRo = await keys.rotate(readOnly.record.id, rootOwner);
    expect(rotatedRo.record.agentCanWrite).toBe(false);

    const writer = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "rw-rotate-bot" },
      rootOwner,
    );
    const rotatedRw = await keys.rotate(writer.record.id, rootOwner);
    expect(rotatedRw.record.agentCanWrite).toBe(true);
  });

  it("keeps every pre-D54 agent writable - NULL is not a restriction", async () => {
    const legacy = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "legacy-bot" },
      rootOwner,
    );
    await db.query(`UPDATE api_keys SET agent_can_write = NULL WHERE id = $1`, [legacy.record.id]);
    const identity = await auth.resolve(legacy.plaintext);
    expect(identity?.agentCanWrite).toBe(true);
  });
});

describe("issuer authority", () => {
  it("lets an admin deploy manager and member agents inside its own subtree", async () => {
    const admin = human("admin", MARKETING);
    const manager = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "mkt-manager", agentAccessLevel: "manager" },
      admin,
    );
    expect(manager.record.agentAccessLevel).toBe("manager");
    const member = await keys.issue(
      { type: "assistant", namespace: MARKETING_BRAND, actor: "brand-bot", agentAccessLevel: "member" },
      admin,
    );
    expect(member.record.agentAccessLevel).toBe("member");
  });

  it("stops an admin from deploying into a sibling team", async () => {
    const admin = human("admin", MARKETING);
    await expect(
      keys.issue({ type: "assistant", namespace: SALES, actor: "poach-bot" }, admin),
    ).rejects.toThrow(/outside your subtree/);
  });

  it("lets a member deploy in its own scope, at member level only", async () => {
    const member = human("member", MARKETING);
    const issued = await keys.issue(
      { type: "assistant", namespace: MARKETING, actor: "my-helper" },
      member,
    );
    expect(issued.record.role).toBe("agent");
    expect(issued.record.agentAccessLevel).toBe("member");

    await expect(
      keys.issue(
        { type: "assistant", namespace: MARKETING, actor: "my-manager", agentAccessLevel: "manager" },
        member,
      ),
    ).rejects.toThrow(/member-scope agents/);
  });

  it("stops a member from deploying outside its own namespace - including below it", async () => {
    const member = human("member", MARKETING);
    for (const namespace of [SALES, MARKETING_BRAND]) {
      await expect(
        keys.issue({ type: "assistant", namespace, actor: "stray-bot" }, member),
      ).rejects.toThrow(/your own team scope|outside your subtree/);
    }
  });

  it("refuses every other role", async () => {
    for (const role of ["auditor", "agent"] as const) {
      await expect(
        keys.issue({ type: "assistant", namespace: MARKETING, actor: "x" }, human(role, MARKETING)),
      ).rejects.toThrow(/may not deploy agents/);
    }
  });

  it("never lets a member mint a human key type", async () => {
    const member = human("member", MARKETING);
    for (const type of ["admin", "read-only"] as const) {
      await expect(
        keys.issue({ type, namespace: MARKETING, actor: "escalate" }, member),
      ).rejects.toThrow(AuthzError);
    }
  });
});

describe("the resolved identity and its lifecycle", () => {
  it("carries the level onto the resolved Identity, and defaults to member", async () => {
    const { plaintext } = await keys.issue(
      { type: "assistant", namespace: SALES, actor: "sales-manager", agentAccessLevel: "manager" },
      rootOwner,
    );
    const identity = await auth.resolve(plaintext);
    expect(identity?.agentAccessLevel).toBe("manager");
    expect(effectiveAgentLevel(identity!)).toBe("manager");

    // A pre-migration agent row (NULL level) reads as the least privilege.
    await db.query(
      `UPDATE api_keys SET agent_access_level = NULL WHERE actor = 'sales-manager'`,
    );
    const downgraded = await auth.resolve(plaintext);
    expect(effectiveAgentLevel(downgraded!)).toBe("member");
  });

  it("preserves namespace AND level across rotation", async () => {
    const issued = await keys.issue(
      { type: "assistant", namespace: SALES, actor: "rotating-bot", agentAccessLevel: "manager" },
      rootOwner,
    );
    const rotated = await keys.rotate(issued.record.id, rootOwner);
    expect(rotated.record.namespace).toBe(SALES);
    expect(rotated.record.agentAccessLevel).toBe("manager");
    const identity = await auth.resolve(rotated.plaintext);
    expect(identity?.agentAccessLevel).toBe("manager");
  });

  it("grandfathers an existing organization-root agent but refuses to rotate it", async () => {
    // Minted the way a pre-D50 kernel would have: straight through AuthService.
    const legacy = await auth.issueKey("", "legacy-org-bot", "agent", rootOwner);
    const identity = await auth.resolve(legacy.plaintext);
    expect(identity).not.toBeNull();
    expect(identity?.role).toBe("agent");

    const listed = (await keys.list(rootOwner)).find((k) => k.id === legacy.record.id);
    expect(listed?.outOfPolicy).toBe(true);

    await expect(keys.rotate(legacy.record.id, rootOwner)).rejects.toThrow(/organization root/);
    expect((await keys.revoke(legacy.record.id, rootOwner)).revoked).toBe(true);
  });
});

describe("what the credential can actually reach", () => {
  let kernel: Kernel;
  let kernelOwner: Identity;
  let marketingAgent: Identity;
  let salesAgent: Identity;
  let marketingFactId: string;
  let salesFactId: string;

  beforeAll(async () => {
    kernel = await Kernel.boot({
      databaseUrl: "",
      pgliteDataDir: "",
      anthropicApiKey: "",
      openaiApiKey: "",
      embedDim: 256,
    });
    await kernel.db.query(
      `INSERT INTO org_teams (id, namespace, organization_namespace, name, description,
                              created_by, created_at)
       VALUES ('t-mkt', $1, $3, 'marketing', '', 'test', $4),
              ('t-sales', $2, $3, 'sales', '', 'test', $4)`,
      [MARKETING, SALES, TENANT, new Date().toISOString()],
    );
    const boot = await kernel.auth.issueKey("", "root@acme.test", "owner");
    const owner = (await kernel.auth.resolve(boot.plaintext))!;
    kernelOwner = owner;
    const service = new ProductKeyService(kernel.db, kernel.auth, kernel.audit);

    const mkt = await service.issue(
      { type: "assistant", namespace: MARKETING, actor: "mkt-agent" },
      owner,
    );
    const sales = await service.issue(
      { type: "assistant", namespace: SALES, actor: "sales-agent" },
      owner,
    );
    marketingAgent = (await kernel.auth.resolve(mkt.plaintext))!;
    salesAgent = (await kernel.auth.resolve(sales.plaintext))!;

    const mktWrite = await kernel.memWrite(
      {
        scope: "team",
        content: "MARKETING SECRET: the Q3 brand campaign budget is 250000 dollars.",
        hints: { verbatim: true, type: "fact" },
      },
      marketingAgent,
      "scope-test",
    );
    const salesWrite = await kernel.memWrite(
      {
        scope: "team",
        content: "SALES SECRET: the Northwind renewal closed at 92000 dollars.",
        hints: { verbatim: true, type: "fact" },
      },
      salesAgent,
      "scope-test",
    );
    marketingFactId = storedId(mktWrite);
    salesFactId = storedId(salesWrite);
  });

  afterAll(async () => {
    await kernel.close();
  });

  it("reads its own team's memory", async () => {
    const own = await kernel.memRead({ id: marketingFactId }, marketingAgent, "scope-test");
    expect(own.found).toBe(true);
  });

  it("cannot read the sibling team's memory by id", async () => {
    const cross = await kernel.memRead({ id: salesFactId }, marketingAgent, "scope-test");
    expect(cross.found).toBe(false);
    expect(cross.memory ?? null).toBeNull();
  });

  it("cannot surface the sibling team's memory through search", async () => {
    const hits = await kernel.memSearch({ query: "Northwind renewal" }, marketingAgent, "scope-test");
    expect(hits.map((hit) => hit.id)).not.toContain(salesFactId);
    const mirrored = await kernel.memSearch({ query: "brand campaign budget" }, salesAgent, "scope-test");
    expect(mirrored.map((hit) => hit.id)).not.toContain(marketingFactId);
  });

  it("writes land in the bound namespace, never a requested one", async () => {
    const row = await kernel.db.query(`SELECT namespace FROM memory_objects WHERE id = $1`, [
      marketingFactId,
    ]);
    expect(row.rows[0].namespace).toBe(MARKETING);
  });

  /**
   * The console Assistant grounds every answer in `kernel.memSearch` called
   * with the ASKER's identity (`src/application-runtime/index.ts` wires
   * `search:` straight to the syscall). So "the copilot only answers what this
   * person may see" reduces to "that search is scoped" — asserted here with the
   * exact Identity shape a console session produces (`sessionToIdentity`:
   * keyId/namespace/actor/role from the user row, D9).
   */
  describe("the copilot answers only from what the asker may see", () => {
    // Real console sessions: the syscall gate rejects any identity whose keyId
    // is not a live credential, so these are the same rows a browser sign-in
    // would produce — user row + session row, identity via sessionToIdentity.
    const sessions = new Map<string, Identity>();

    beforeAll(async () => {
      const users = new UserStore(kernel.db);
      const store = new SessionStore(kernel.db);
      // A platform root creates everyone else. Root is provisioned directly:
      // the bootstrap credential now creates an ORGANIZATION and its owner
      // inside it (CONTRACTS-SELF-SERVICE-ONBOARDING.md decision 9), so no
      // product path yields a caller at namespace "".
      const rootEmail = "root@acme.test";
      await kernel.db.query(
        `INSERT INTO users (id, email, namespace, role, password_hash, status, created_at)
         VALUES ($1, $2, '', 'owner', $3, 'active', $4)`,
        [
          "root-agent-scope",
          rootEmail,
          hashPassword("bootstrap-password"),
          new Date().toISOString(),
        ],
      );
      const rootCaller: Identity = {
        keyId: "test-root-agent-scope",
        namespace: "",
        actor: rootEmail,
        role: "owner",
      };
      for (const [namespace, role] of [
        [MARKETING, "member"],
        [MARKETING, "admin"],
        [SALES, "member"],
      ] as const) {
        const email = `${role}@${namespace.replace("/", "-")}.test`;
        const user = await users.create({ email, namespace, role }, rootCaller);
        const { session } = await store.create(user);
        sessions.set(`${namespace}:${role}`, {
          keyId: session.id,
          namespace: session.namespace,
          actor: session.actor,
          role: session.role,
        });
      }
    });

    const session = (namespace: string, role: "admin" | "member"): Identity => {
      const identity = sessions.get(`${namespace}:${role}`);
      if (!identity) throw new Error(`no session seeded for ${namespace}:${role}`);
      return identity;
    };

    it("grounds a marketing person's question in marketing memory only", async () => {
      const grounding = await kernel.memSearch(
        { query: "What is the Northwind renewal worth? codename Ironwood", k: 25 },
        session(MARKETING, "member"),
        "copilot-test",
      );
      const contents = grounding.map((hit) => hit.content ?? "");
      expect(contents.some((c) => c.includes("SALES SECRET"))).toBe(false);
    });

    it("gives a team admin no more memory reach than a team member", async () => {
      const asMember = await kernel.memSearch(
        { query: "SECRET", k: 25 },
        session(MARKETING, "member"),
        "copilot-test",
      );
      const asAdmin = await kernel.memSearch(
        { query: "SECRET", k: 25 },
        session(MARKETING, "admin"),
        "copilot-test",
      );
      // A human role is authority over governance, not a wider memory ACL.
      expect(asAdmin.map((h) => h.id).sort()).toEqual(asMember.map((h) => h.id).sort());
      expect(asAdmin.some((h) => (h.content ?? "").includes("SALES SECRET"))).toBe(false);
    });

    it("lets each team's person reach their own team's answer", async () => {
      const mkt = await kernel.memSearch(
        { query: "campaign budget codename", k: 25 },
        session(MARKETING, "member"),
        "copilot-test",
      );
      const sales = await kernel.memSearch(
        { query: "Northwind renewal", k: 25 },
        session(SALES, "member"),
        "copilot-test",
      );
      expect(mkt.some((h) => (h.content ?? "").includes("MARKETING SECRET"))).toBe(true);
      expect(sales.some((h) => (h.content ?? "").includes("SALES SECRET"))).toBe(true);
    });
  });

  /**
   * D54 end-to-end. The mutating operations do not share one chokepoint —
   * mem_write runs through the syscall layer, pin/share sit on their own
   * services, forget has its own erasure lane — so each is asserted separately.
   * A capability enforced only on the busiest path is not a capability.
   */
  describe("a read-only agent can read but never change", () => {
    let readOnlyAgent: Identity;

    beforeAll(async () => {
      // Reuse the suite's owner: api_keys is no longer empty, so the
      // first-boot bootstrap path is closed and issuance needs a real caller.
      const issued = await new ProductKeyService(kernel.db, kernel.auth, kernel.audit).issue(
        { type: "assistant", namespace: MARKETING, actor: "ro-agent", agentCanWrite: false },
        kernelOwner,
      );
      readOnlyAgent = (await kernel.auth.resolve(issued.plaintext))!;
    });

    it("still sees everything its team can see", async () => {
      const hits = await kernel.memSearch(
        { query: "Q3 brand campaign budget", k: 25 },
        readOnlyAgent,
        "ro-test",
      );
      expect(hits.some((h) => (h.content ?? "").includes("MARKETING SECRET"))).toBe(true);
      const read = await kernel.memRead({ id: marketingFactId }, readOnlyAgent, "ro-test");
      expect(read.found).toBe(true);
    });

    it("is refused on every path that changes memory, and each refusal is audited", async () => {
      // The Kernel boots its OWN in-memory PGlite, so the denial rows land
      // there — not in this file's outer `db`.
      const denials = async (): Promise<number> => {
        const res = await kernel.db.query(
          `SELECT COUNT(*) AS n FROM audit_log
            WHERE result = 'denied' AND detail = 'read-only agent may not change memory'`,
        );
        return Number(res.rows[0].n);
      };
      const before = await denials();

      await expect(kernel.memWrite(
        { scope: "team", content: "should never land", hints: { verbatim: true } },
        readOnlyAgent,
        "ro-test",
      )).rejects.toThrow(/read-only/);

      await expect(
        kernel.memPin({ kind: "memory", value: marketingFactId }, readOnlyAgent),
      ).rejects.toThrow(/read-only/);

      await expect(
        kernel.memShare({ kind: "memory", value: marketingFactId }, SALES, readOnlyAgent),
      ).rejects.toThrow(/read-only/);

      await expect(
        kernel.memForget({ target: { kind: "memory", value: marketingFactId } }, readOnlyAgent),
      ).rejects.toThrow(/read-only/);

      expect(await denials()).toBe(before + 4);
    });

    it("leaves the team's memory untouched after all of that", async () => {
      const read = await kernel.memRead({ id: marketingFactId }, marketingAgent, "ro-test");
      expect(read.found).toBe(true);
    });
  });
});
