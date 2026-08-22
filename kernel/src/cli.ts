/**
 * Module A (M1) — key management CLI.
 *
 *   tsx src/cli.ts keygen <namespace> <actor> <role>   mint a key (plaintext printed ONCE)
 *   tsx src/cli.ts revoke <id>                          revoke a key
 *   tsx src/cli.ts list                                 list visible keys
 *
 * Boots a Db from loadConfig(), runs migrations, and reads HALOMEM_API_KEY
 * for non-bootstrap calls. `keygen` works without a key only while the
 * api_keys table is empty (first-boot path); afterwards an owner key is
 * required. `revoke` and `list` always require a key.
 */

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { Kernel } from "./kernel.js";
import { renderFragmentationMarkdown } from "./ingest/fragmentation.js";
import { createDb, type Db } from "./db/client.js";
import { migrate } from "./db/migrate.js";
import { AuditLog } from "./audit/index.js";
import {
  AuthService,
  AuthzError,
  ensureApiKeysTable,
  isRootOwner,
  isRole,
  ROLES,
} from "./auth/index.js";
import { runConformance } from "./conformance/index.js";
import {
  BaselineDriver,
  DriverRegistry,
  buildScopedView,
} from "./driver/index.js";
import { GraphDriver } from "./driver/graph.js";
import { Mem0Driver } from "./driver/mem0.js";
import { makeEntitiesReader } from "./write/entities.js";
import { MemoryIndex } from "./index/index.js";
import { ColdStore } from "./cold/index.js";
import { createEmbedder } from "./embed/index.js";
import { runEmbeddingBackfillOnce as runEmbeddingBackfill } from "./embed/backfill.js";
import { ResilientEmbedder, type CostLedger } from "./resilience/index.js";
import { ulid } from "ulid";
import { runScorecard, renderScorecardMarkdown } from "./referee/index.js";
import { sweepSkills } from "./skills/sweep.js";
import { seedDefaultSkills } from "./skills/defaults.js";
import { SkillStore } from "./skills/store.js";
import type { Identity, Namespace, RetrieverDriver, SourceKind } from "./types.js";

const USAGE = `halomem key management

Usage:
  tsx src/cli.ts keygen <namespace> <actor> <role>   role: ${ROLES.join("|")}
  tsx src/cli.ts revoke <id>
  tsx src/cli.ts list
  tsx src/cli.ts scorecard <namespace>               referee run (owner/admin key)
  tsx src/cli.ts conformance <driverName>            M2 driver conformance kit (hermetic fixture)
  tsx src/cli.ts import <kind> <file> [namespace]    bulk-import a dump (mem0-import|pgvector-import)
  tsx src/cli.ts connect <kind> [--team-id=..] [--path=..|--dsn=..] [--exts=.csv,.md]   register a team source connector
  tsx src/cli.ts sync <sourceId>                     drift-sync a registered source
  tsx src/cli.ts fragmentation <namespace>           print the fragmentation report (markdown)
  tsx src/cli.ts forget <actor|entity|namespace|memory> <value> [namespace]   erase (owner/admin) + print the signed certificate
  tsx src/cli.ts tenant create <id> <name>           register a tenant (owner)
  tsx src/cli.ts tenant list                          list visible tenants
  tsx src/cli.ts tenant suspend <id>                 suspend a tenant (owner/admin)
  tsx src/cli.ts org adopt <tenant> <ns...> [--root-sources] [--dry-run]  re-root orphan namespaces under a tenant (root owner)
  tsx src/cli.ts warmstore list                       warm-store health + pending outbox (root owner)
  tsx src/cli.ts warmstore flush                      retry the mirror outbox now (root owner)
  tsx src/cli.ts warmstore rebuild <name> <namespace> wipe + rebuild one external mirror subtree (root owner)
  tsx src/cli.ts skills sweep [--stale-engines]       re-vet every current skill under the system identity (no API key; the monthly job)
  tsx src/cli.ts skills seed-defaults <namespace>     seed the curated default skill library at a tenant root (no API key; ops backfill)
  tsx src/cli.ts reembed                              force the missing-vector backfill to completion (root owner; the kernel also self-heals in the background)

Environment:
  HALOMEM_API_KEY   caller credential (required except first-boot keygen)
  DATABASE_URL / HALOMEM_DATA_DIR   database selection (see src/config.ts)
`;

function fail(message: string): never {
  process.stderr.write(message + "\n");
  process.exit(1);
}

async function resolveCaller(auth: AuthService): Promise<Identity | null> {
  const plaintext = process.env.HALOMEM_API_KEY ?? "";
  if (!plaintext) return null;
  return auth.resolve(plaintext);
}

/**
 * Module D — load a RetrieverDriver by name from src/driver/<name>.ts for
 * the conformance CLI. Dynamic (non-literal) specifier so this file compiles
 * before modules A/B/C land; scans the module's exports for the first
 * class-with-plan() or ready-made driver instance.
 */
async function loadRetrieverDriver(name: string): Promise<RetrieverDriver> {
  const spec = ["./driver", `${name}.js`].join("/");
  let mod: Record<string, unknown>;
  try {
    mod = (await import(spec)) as Record<string, unknown>;
  } catch {
    fail(
      `no driver module at src/driver/${name}.ts - build the M2 driver modules first`,
    );
  }
  for (const value of Object.values(mod)) {
    if (
      typeof value === "function" &&
      typeof (value as { prototype?: { plan?: unknown } }).prototype?.plan ===
        "function"
    ) {
      try {
        return new (value as new () => RetrieverDriver)();
      } catch {
        continue; // constructor needs args (e.g. mem0 url) - keep scanning
      }
    }
    if (
      value !== null &&
      typeof value === "object" &&
      typeof (value as { plan?: unknown }).plan === "function"
    ) {
      return value as RetrieverDriver;
    }
  }
  fail(`src/driver/${name}.ts exports no RetrieverDriver (class or instance)`);
}

/**
 * M3 ingestion commands (import/connect/sync/fragmentation) run through the
 * full Kernel — importDump/registerSource/syncSource/runFragmentation go
 * through performWrite so audit + brownout + supersedence + provenance apply.
 * They boot their OWN Kernel (which owns migrations 1..5 and its db handle),
 * resolve the caller from HALOMEM_API_KEY, and enforce owner/admin + subtree
 * scope exactly like `scorecard`. The kernel is always closed afterwards.
 */
async function withKernel(
  fn: (kernel: Kernel, caller: Identity) => Promise<void>,
): Promise<void> {
  const plaintext = process.env.HALOMEM_API_KEY ?? "";
  if (!plaintext) fail("this command requires a valid HALOMEM_API_KEY");
  const kernel = await Kernel.boot();
  try {
    const caller = await kernel.auth.resolve(plaintext);
    if (!caller) fail("HALOMEM_API_KEY is invalid or revoked");
    if (caller.role !== "owner" && caller.role !== "admin") {
      fail(`role '${caller.role}' may not run ingestion commands`);
    }
    await fn(kernel, caller);
  } finally {
    await kernel.close();
  }
}

/** owner sees its whole subtree; a target namespace must be self-or-descendant. */
function requireSubtree(caller: Identity, namespace: Namespace): void {
  if (isRootOwner(caller)) return;
  if (namespace !== caller.namespace && !namespace.startsWith(caller.namespace + "/")) {
    fail(`denied: namespace '${namespace}' is outside your subtree`);
  }
}

/** Validate a CLI-supplied SourceKind against the known set. */
function asSourceKind(value: string, expected: SourceKind[]): SourceKind {
  if (!(expected as string[]).includes(value)) {
    fail(`invalid kind '${value}' - expected one of: ${expected.join(", ")}`);
  }
  return value as SourceKind;
}

/** Parse `--flag=value` style args into a map (bare positionals ignored). */
function parseFlags(args: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of args) {
    const m = /^--([^=]+)=(.*)$/.exec(a);
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

/** Positional (non-flag) args, in order. */
function positionals(args: string[]): string[] {
  return args.filter((a) => !a.startsWith("--"));
}

/** Dispatch the four M3 ingestion commands through a booted Kernel. */
async function runIngestCommand(command: string, rest: string[]): Promise<void> {
  switch (command) {
    case "import": {
      // Bulk-import a vendor dump into the caller's (or a subtree) namespace.
      const [kindArg, file, ns] = rest;
      if (!kindArg || !file) fail(USAGE);
      const kind = asSourceKind(kindArg, ["mem0-import", "pgvector-import"]);
      if (!existsSync(file)) fail(`no such file: ${file}`);
      const raw = readFileSync(file, "utf8");
      await withKernel(async (kernel, caller) => {
        const namespace = ns ?? caller.namespace;
        requireSubtree(caller, namespace);
        const identity: Identity = { ...caller, namespace };
        const result = await kernel.importDump(kind, raw, identity);
        process.stdout.write(
          `imported ${result.records} record(s) into ${namespace} ` +
            `(source ${result.sourceId}): stored=${result.stored} ` +
            `deduplicated=${result.deduplicated} superseded=${result.superseded} ` +
            `rejected=${result.rejected} errors=${result.errors.length}\n`,
        );
        for (const e of result.errors) {
          process.stdout.write(`  ! ${e.docId}: ${e.reason}\n`);
        }
      });
      return;
    }

    case "connect": {
      // Register a source connector (does NOT sync — run `sync <id>` after).
      const [kindArg] = positionals(rest);
      if (!kindArg) fail(USAGE);
      const kind = asSourceKind(kindArg, [
        "filesystem",
        "postgres",
        "notion",
        "slack",
      ]);
      const flags = parseFlags(rest);
      const config: Record<string, unknown> = {};
      if (flags.path) config.path = flags.path;
      if (flags.dsn) config.dsn = flags.dsn;
      if (flags.token) config.token = flags.token;
      if (flags.exportPath) config.exportPath = flags.exportPath;
      if (flags.exts) config.exts = flags.exts.split(",").map((e) => e.trim());
      await withKernel(async (kernel, caller) => {
        const source = await kernel.registerSource(
          kind,
          config,
          caller,
          undefined,
          flags["team-id"] ?? null,
        );
        process.stdout.write(
          `registered ${kind} source ${source.id} for ${source.namespace} - ` +
            `run: tsx src/cli.ts sync ${source.id}\n`,
        );
      });
      return;
    }

    case "sync": {
      const [sourceId] = rest;
      if (!sourceId) fail(USAGE);
      await withKernel(async (kernel, caller) => {
        const result = await kernel.syncSource(sourceId, caller);
        process.stdout.write(
          `synced source ${result.sourceId}: scanned=${result.scanned} ` +
            `changed=${result.changed} unchanged=${result.unchanged} ` +
            `removed=${result.removed.length} | stored=${result.stored} ` +
            `deduplicated=${result.deduplicated} superseded=${result.superseded} ` +
            `rejected=${result.rejected} errors=${result.errors.length}\n`,
        );
        for (const e of result.errors) {
          process.stdout.write(`  ! ${e.docId}: ${e.reason}\n`);
        }
      });
      return;
    }

    case "fragmentation": {
      const [namespace] = rest;
      if (!namespace) fail(USAGE);
      await withKernel(async (kernel, caller) => {
        requireSubtree(caller, namespace);
        const report = await kernel.runFragmentation(namespace, caller);
        process.stdout.write(renderFragmentationMarkdown(report) + "\n");
      });
      return;
    }

    case "forget": {
      // M4: compliance erasure. Subtree-scoped like scorecard/fragmentation —
      // the erasure engine resolves ids INSIDE the caller's subtree only. Owner
      // /admin is enforced by withKernel; the kernel re-checks in memForget.
      const [kindArg, value, ns] = rest;
      if (!kindArg || !value) fail(USAGE);
      const kind = kindArg as "actor" | "entity" | "namespace" | "memory";
      if (!["actor", "entity", "namespace", "memory"].includes(kind)) {
        fail(`invalid forget kind '${kindArg}' - expected actor|entity|namespace|memory`);
      }
      await withKernel(async (kernel, caller) => {
        const namespace = ns ?? caller.namespace;
        requireSubtree(caller, namespace);
        const identity: Identity = { ...caller, namespace };
        const result = await kernel.memForget({ target: { kind, value } }, identity);
        process.stdout.write(
          `erased ${result.erasedCount} row(s), ${result.tombstones} tombstone(s). ` +
            `certificate verifies: ${kernel.verifyCertificate(result.certificate)}\n`,
        );
        // Print the full certificate JSON so an operator can persist/verify it.
        process.stdout.write(JSON.stringify(result.certificate, null, 2) + "\n");
      });
      return;
    }

    case "warmstore": {
      // R6: warm-store mirror admin. Root-owner-only — the kernel methods
      // enforce it; the mirror is process-global infrastructure.
      const [sub, ...warmArgs] = rest;
      if (!sub) fail(USAGE);
      await withKernel(async (kernel, caller) => {
        switch (sub) {
          case "list": {
            const stores = await kernel.warmStatus(caller);
            for (const s of stores) {
              process.stdout.write(
                `${s.name.padEnd(14)} ${s.external ? "external " : "canonical"} ` +
                  `${s.healthy ? "healthy" : `UNHEALTHY (${s.detail ?? "?"})`} ` +
                  `pendingOps=${s.pendingOps}\n`,
              );
            }
            return;
          }
          case "flush": {
            const remaining = await kernel.warmFlush(caller);
            const entries = Object.entries(remaining);
            if (entries.length === 0) {
              process.stdout.write("no external warm stores mounted\n");
              return;
            }
            for (const [store, n] of entries) {
              process.stdout.write(`${store}: ${n} op(s) still pending\n`);
            }
            return;
          }
          case "rebuild": {
            const [name, namespace] = warmArgs;
            if (!name || !namespace) fail(USAGE);
            const result = await kernel.warmRebuild(name, namespace, caller);
            process.stdout.write(
              `rebuilt ${result.store} for ${result.namespace}: ${result.records} record(s)\n`,
            );
            return;
          }
          default:
            fail(`unknown warmstore subcommand '${sub}' - expected list|flush|rebuild`);
        }
      });
      return;
    }

    case "org": {
      // Organization adoption (src/tenancy/adopt.ts): re-root orphan
      // top-level namespaces under a tenant. Kernel enforces root-owner.
      const [sub, ...orgArgs] = rest;
      if (sub !== "adopt") {
        fail(`unknown org subcommand '${sub ?? ""}' - expected adopt`);
      }
      const names = positionals(orgArgs);
      const [tenant, ...namespaces] = names;
      const rootSources = orgArgs.includes("--root-sources");
      if (!tenant || (namespaces.length === 0 && !rootSources)) {
        fail(
          "usage: tsx src/cli.ts org adopt <tenant> <namespace...> [--root-sources] [--dry-run]",
        );
      }
      const dryRun = orgArgs.includes("--dry-run");
      await withKernel(async (kernel, caller) => {
        const report = await kernel.adoptOrganizationNamespaces(
          { tenant: tenant!, namespaces, dryRun, rootSources },
          caller,
        );
        const verb = report.dryRun ? "would move" : "moved";
        for (const c of report.changes) {
          process.stdout.write(`${c.table}.${c.column}: ${c.rows} row(s)\n`);
        }
        process.stdout.write(
          `${verb} ${report.total} row(s) from [${report.namespaces.join(", ")}] ` +
            `into '${report.tenant}'${report.dryRun ? " (dry run - nothing written)" : ""}\n`,
        );
      });
      return;
    }

    case "tenant": {
      // M4: tenant admin — create/list/suspend. register() is owner-only (the
      // registry checks identity.role); withKernel already gates owner/admin.
      const [sub, ...tenantArgs] = rest;
      if (!sub) fail(USAGE);
      await withKernel(async (kernel, caller) => {
        switch (sub) {
          case "create": {
            const [id, ...nameParts] = tenantArgs;
            const name = nameParts.join(" ");
            if (!id || !name) fail(USAGE);
            const tenant = await kernel.registerTenant({ id, name }, caller);
            process.stdout.write(
              `registered tenant ${tenant.id} (${tenant.name}) status=${tenant.status} ` +
                `budgetUsd=${tenant.monthlyBudgetUsd ?? "unlimited"} ` +
                `rateLimit=${tenant.rateLimitPerMin ?? "unlimited"}\n`,
            );
            return;
          }
          case "list": {
            const tenants = await kernel.listTenants(caller);
            if (tenants.length === 0) {
              process.stdout.write("no tenants visible\n");
              return;
            }
            for (const t of tenants) {
              process.stdout.write(
                `${t.id.padEnd(16)} ${t.status.padEnd(9)} ${t.name} ` +
                  `(budgetUsd=${t.monthlyBudgetUsd ?? "-"} rateLimit=${t.rateLimitPerMin ?? "-"})\n`,
              );
            }
            return;
          }
          case "suspend": {
            const [id] = tenantArgs;
            if (!id) fail(USAGE);
            requireSubtree(caller, id);
            const tenant = await kernel.suspendTenant(id);
            if (!tenant) fail(`no tenant with id '${id}'`);
            process.stdout.write(`tenant ${tenant.id} status=${tenant.status}\n`);
            return;
          }
          default:
            fail(`unknown tenant subcommand '${sub}' - expected create|list|suspend`);
        }
      });
      return;
    }

    default:
      fail(`unknown ingestion command '${command}'`);
  }
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === "help" || command === "--help") {
    process.stdout.write(USAGE);
    process.exit(command ? 0 : 1);
  }

  // M3 ingestion commands run through the full Kernel (its own db handle +
  // migrations 1..5). They are dispatched HERE, before the legacy key-mgmt db
  // boot below, so a single command opens exactly one database handle — two
  // PGlite handles on one HALOMEM_DATA_DIR would split state. Existing
  // key-mgmt cases below are untouched.
  if (
    command === "import" ||
    command === "connect" ||
    command === "sync" ||
    command === "fragmentation" ||
    command === "forget" ||
    command === "tenant" ||
    command === "org" ||
    command === "warmstore"
  ) {
    await runIngestCommand(command, rest);
    return;
  }

  // S16 vetting v2 (E72): the sweep runs under a SERVER-SIDE system
  // identity (D9 — no caller key, no namespace/actor from input), so it
  // boots its own Kernel outside the key-mgmt path. Partial failures are
  // reported, never fatal: always exits 0.
  if (command === "skills") {
    const [sub, ...flags] = rest;
    const kernel = await Kernel.boot();
    try {
      if (sub === "sweep") {
        const results = await sweepSkills(
          { db: kernel.db, vetting: kernel.skillVetting },
          { staleEnginesOnly: flags.includes("--stale-engines") },
        );
        for (const r of results) {
          const flip = r.flipped ? ` FLIP ${r.before} -> ${r.after}` : ` ${r.after}`;
          const err = r.error !== null ? ` ERROR: ${r.error}` : "";
          process.stdout.write(`${r.namespace}/${r.skillKey}${flip}${err}\n`);
        }
        const flips = results.filter((r) => r.flipped).length;
        const errors = results.filter((r) => r.error !== null).length;
        process.stdout.write(
          `sweep complete: ${results.length} vetted, ${flips} flips, ${errors} partial failures\n`,
        );
        return;
      }
      if (sub === "seed-defaults") {
        // Ops backfill for already-onboarded orgs: the same seeder the three
        // provisioning paths call, under the server-side system identity (D9
        // — the namespace is a CLI argument to a local admin tool, never
        // request input). Idempotent; existing rows are never touched.
        const namespace = flags[0];
        if (!namespace || namespace.length === 0 || namespace.includes("/")) {
          fail("usage: tsx src/cli.ts skills seed-defaults <tenant-root-namespace>");
        }
        const store = new SkillStore({ db: kernel.db, audit: kernel.audit });
        const result = await seedDefaultSkills(store, kernel.db, namespace);
        process.stdout.write(
          `seed-defaults ${namespace}: seeded=${result.seeded} skipped=${result.skipped}\n`,
        );
        return;
      }
      fail(`unknown skills subcommand '${sub ?? ""}' - expected sweep or seed-defaults`);
    } finally {
      await kernel.close();
    }
    return;
  }

  const config = loadConfig();
  let db: Db | null = null;
  try {
    db = await createDb(config);
    // Call the current migrate; module C's numbered migrations replace this.
    await migrate(db, config.embedDim);
    // Safety net until migration 002 lands (idempotent, exact same DDL).
    await ensureApiKeysTable(db);

    const audit = new AuditLog(db);
    const auth = new AuthService(db, audit);

    switch (command) {
      case "keygen": {
        const [namespace, actor, role] = rest;
        if (!namespace || !actor || !role) fail(USAGE);
        if (!isRole(role)) fail(`invalid role '${role}' - expected one of: ${ROLES.join(", ")}`);
        const caller = await resolveCaller(auth);
        if (process.env.HALOMEM_API_KEY && !caller) {
          fail("HALOMEM_API_KEY is invalid or revoked");
        }
        const { record, plaintext } = await auth.issueKey(namespace, actor, role, caller);
        process.stdout.write(
          `key id:    ${record.id}\n` +
            `namespace: ${record.namespace}\n` +
            `actor:     ${record.actor}\n` +
            `role:      ${record.role}\n\n` +
            `API key (shown once, store it now):\n${plaintext}\n`,
        );
        break;
      }

      case "revoke": {
        const [id] = rest;
        if (!id) fail(USAGE);
        const caller = await resolveCaller(auth);
        if (!caller) fail("revoke requires a valid HALOMEM_API_KEY");
        if (caller.role !== "owner" && caller.role !== "admin") {
          fail(`role '${caller.role}' may not revoke keys`);
        }
        if (!isRootOwner(caller)) {
          // Same subtree rule as the HTTP adapter (adapter.ts revokeKey): an
          // admin may only revoke keys it can list — its own subtree. Without
          // this, a team-scoped admin could revoke the OWNER's key via the
          // CLI and lock the org out of key issuance entirely.
          const visible = await auth.list(caller);
          if (!visible.some((r) => r.id === id)) {
            fail(`denied: key ${id} is not in your subtree`);
          }
        }
        const revoked = await auth.revoke(id);
        if (revoked) {
          // D4: management mutations leave an audit trail (parity with the
          // HTTP admin surface, whose mutations audit under op 'write').
          await audit.append({
            ts: new Date().toISOString(),
            actor: caller.actor,
            agentId: "cli",
            op: "write",
            memoryId: null,
            namespace: caller.namespace,
            purpose: null,
            result: "ok",
            detail: `api key ${id} revoked via CLI`,
          });
        }
        process.stdout.write(revoked ? `revoked ${id}\n` : `no active key with id ${id}\n`);
        break;
      }

      case "list": {
        const caller = await resolveCaller(auth);
        if (!caller) fail("list requires a valid HALOMEM_API_KEY");
        const records = await auth.list(caller);
        if (records.length === 0) {
          process.stdout.write("no keys visible\n");
          break;
        }
        for (const r of records) {
          process.stdout.write(
            `${r.id}  ${r.status.padEnd(7)}  ${r.role.padEnd(7)}  ${r.namespace}  ${r.actor}` +
              `  created=${r.createdAt}  last_used=${r.lastUsed ?? "-"}\n`,
          );
        }
        break;
      }

      case "scorecard": {
        // Module E (M2) — referee run over every mounted driver.
        const [namespace] = rest;
        if (!namespace) fail(USAGE);
        const caller = await resolveCaller(auth);
        if (!caller) fail("scorecard requires a valid HALOMEM_API_KEY");
        if (caller.role !== "owner" && caller.role !== "admin") {
          fail(`role '${caller.role}' may not run scorecards`);
        }
        if (
          namespace !== caller.namespace &&
          !namespace.startsWith(caller.namespace + "/")
        ) {
          fail(`denied: namespace '${namespace}' is outside your subtree`);
        }

        // M2 integration: static wiring through the real driver core. The
        // view is built by the ONLY ScopedView constructor (module A) with
        // the kernel-side ACL-scoped entity_registry reader.
        //
        // The embedder is wrapped in ResilientEmbedder exactly like the
        // kernel path (kernel.ts runtimeFor): real-provider embed calls made
        // by the scorecard's drivers must land in cost_ledger (BudgetGuard's
        // month-to-date brownout accounting) and get breaker protection —
        // the raw createEmbedder(config) would bypass both.
        const costLedger: CostLedger = {
          async append(ns: Namespace, kind: "llm" | "embed", tokens: number, usd: number) {
            await db!.query(
              `INSERT INTO cost_ledger (id, namespace, kind, tokens, usd, ts)
               VALUES ($1, $2, $3, $4, $5, $6)`,
              [ulid(), ns, kind, Math.round(tokens), usd, new Date().toISOString()],
            );
          },
        };
        const embedder = new ResilientEmbedder(createEmbedder(config), costLedger, namespace);
        const index = new MemoryIndex(db);
        const cold = new ColdStore(config.knowledgeDir, config.coldKek);
        const view = buildScopedView(
          { db, index, cold, entities: makeEntitiesReader(db), embedder },
          namespace,
        );

        // Mount the same set Kernel.boot mounts: baseline + graph always,
        // mem0 iff HALOMEM_MEM0_URL points at a sidecar.
        const registry = new DriverRegistry();
        registry.mount(new BaselineDriver());
        registry.mount(new GraphDriver());
        if (process.env.HALOMEM_MEM0_URL) {
          try {
            registry.mount(new Mem0Driver());
          } catch (err) {
            process.stderr.write(
              `warning: mem0 driver not mounted: ${err instanceof Error ? err.message : String(err)}\n`,
            );
          }
        }
        const drivers = registry.list().map((name) => registry.get(name));

        // D4: the scorecard reads real fact contents — audit the run with
        // the CLI caller's identity, like every other content-reading path.
        const card = await runScorecard(
          { db, drivers, view, audit, actor: caller.actor, agentId: "cli" },
          namespace,
        );
        process.stdout.write(renderScorecardMarkdown(card) + "\n");
        break;
      }

      case "conformance": {
        // Module D (M2) — driver conformance kit. The kit builds its OWN
        // hermetic in-memory fixture (PGlite + HashEmbedder + planted facts);
        // the outer db/auth boot above is unused here but harmless.
        const [driverName = "baseline"] = rest;
        if (!/^[a-z0-9_-]+$/i.test(driverName)) {
          fail(`invalid driver name '${driverName}'`);
        }
        const driver = await loadRetrieverDriver(driverName);
        // Scan the driver's TypeScript source for the read-only check when
        // it exists next to this file (tsx runs from src/).
        const candidateSource = fileURLToPath(
          new URL(`./driver/${driverName}.ts`, import.meta.url),
        );
        const report = await runConformance(driver, {
          sourcePath: existsSync(candidateSource) ? candidateSource : undefined,
        });
        if (!report.pass) process.exitCode = 1;
        break;
      }

      /**
       * Re-embed every row whose vector is missing — the backfill that pairs
       * with migration 76. Switching on a real embeddings deployment changes
       * the vector width, and a 256-wide hash vector carries no meaning in a
       * 3072-wide semantic space, so the realign drops the old vectors and this
       * rebuilds them. Until it finishes, retrieval browns out to BM25.
       *
       * `concepts` is deliberately absent: ColdStore.syncToDb re-embeds every
       * concept from cold storage on each boot, so that table self-heals.
       */
      case "reembed": {
        const caller = await resolveCaller(auth);
        if (!caller) fail("reembed requires a valid HALOMEM_API_KEY");
        // A global vector rewrite is not a subtree operation: it touches every
        // tenant's rows, so only the platform root may run it.
        if (!isRootOwner(caller)) fail("reembed requires the root owner");
        // Wrapped for the retry + circuit breaker: a few thousand rows against a
        // capacity-limited deployment WILL see throttling, and a bare embedder
        // would abort on the first 429. Cost accounting is dropped on the floor
        // — this is platform maintenance, not tenant traffic.
        const backfillLedger: CostLedger = { append: async () => undefined };
        const embedder = new ResilientEmbedder(createEmbedder(config), backfillLedger, "");
        // Same module the kernel's background poller drives, so a forced run and
        // the self-healing pass can never diverge in what they consider a
        // correctly embedded row.
        for (;;) {
          const { repaired, remaining } = await runEmbeddingBackfill(db, embedder);
          process.stdout.write(`re-embedded ${repaired}, ${remaining} remaining\n`);
          if (remaining === 0) break;
          // No progress with work outstanding means the provider is refusing;
          // stop rather than spin. The kernel's poller will retry later.
          if (repaired === 0) {
            process.stdout.write("no progress - embedding provider unavailable; stopping\n");
            process.exitCode = 1;
            break;
          }
        }
        break;
      }

      default:
        fail(`unknown command '${command}'\n\n${USAGE}`);
    }
  } catch (err) {
    if (err instanceof AuthzError) fail(`denied: ${err.message}`);
    throw err;
  } finally {
    await db?.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
