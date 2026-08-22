/**
 * halomem-warmstore/v1 (R6) — governed warm-memory mirrors.
 *
 * HaloMem owns the memory map and lifecycle; external engines may hold
 * REBUILDABLE CACHES of warm (L2) memory, never authority (D5). This module
 * owns:
 *
 *   - WarmStoreRegistry   — mounted WarmStoreDriver cartridges by name
 *   - PostgresWarmStore   — the canonical lane (rule-of-two implementation 1):
 *                           mirror ops are no-ops because the canonical commit
 *                           already landed in Postgres; health probes the DB
 *   - WarmStoreManager    — the cache controller: durable outbox
 *                           (warm_mirror_ops), post-commit write-through fan-out,
 *                           erasure purge propagation, flush repair, and full
 *                           rebuild-from-canonical
 *
 * Invariants (CONTRACTS-WARMSTORE.md):
 *   - mutations originate here only; drivers never read canonical storage
 *   - optional mirror reads are untrusted until canonical + policy revalidation
 *   - a mirror failure is brownout: the op stays queued, the syscall succeeds
 *   - erasure purge ops are enqueued INSIDE the erasure transaction
 *     (enqueuePurgesTx) — a certificate can never exist without its mirror
 *     purges durably queued
 *   - outbox rows carry ids/namespaces only (no PII copies); flush re-reads
 *     the canonical row at send time, so an erased/superseded row is removed
 *     from the mirror rather than resurrected — and every delivered upsert is
 *     re-verified against canonical AFTER the send (compensating remove)
 *   - per-store op order: purge_namespace → purge → invalidate → upsert
 *   - flush and rebuild share one in-process serialization chain; the residual
 *     multi-process window is documented in the contract
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";
import type { Logger } from "../metrics/index.js";
import type {
  DataClassification,
  MemoryId,
  Namespace,
  SourceAccess,
  WarmMirrorRecord,
  WarmPurgeOutcome,
  WarmStoreDriver,
  WarmStoreHealth,
  WarmStoreStatus,
  WriteResult,
} from "../types.js";
import { WarmStoreUnavailableError } from "./errors.js";

export { WarmStoreUnavailableError } from "./errors.js";
export { HttpWarmStore, type HttpWarmStoreOptions } from "./http.js";
export {
  Mem0WarmStore,
  SupermemoryWarmStore,
  type WarmAdapterOptions,
} from "./adapters.js";

/** The canonical lane's mount name. */
export const POSTGRES_WARMSTORE_NAME = "postgres";

/** Max ops/records per external delivery call (flush batches AND rebuild). */
export const MIRROR_BATCH = 200;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export class WarmStoreRegistry {
  private readonly stores = new Map<string, WarmStoreDriver>();

  /** Mount (or replace) a warm store under its own `name`. */
  mount(store: WarmStoreDriver): void {
    if (!store.name) {
      throw new Error("WarmStoreRegistry.mount: store has no name");
    }
    this.stores.set(store.name, store);
  }

  /** Resolve by exact name. Unknown names throw — there is no fallback store. */
  get(name: string): WarmStoreDriver {
    const found = this.stores.get(name);
    if (!found) {
      throw new WarmStoreUnavailableError(name, `warm store "${name}" is not mounted`);
    }
    return found;
  }

  has(name: string): boolean {
    return this.stores.has(name);
  }

  list(): WarmStoreDriver[] {
    return [...this.stores.values()];
  }

  /** External mirrors only — the fan-out targets. */
  externals(): WarmStoreDriver[] {
    return this.list().filter((s) => s.external);
  }
}

// ---------------------------------------------------------------------------
// PostgresWarmStore — canonical lane (rule-of-two implementation 1)
// ---------------------------------------------------------------------------

/**
 * The canonical warm store. It is NOT a mirror: by the time any mirror op
 * fires, the canonical transaction has already committed to Postgres, so
 * upsert/remove/removeNamespace are contractually no-ops here. Mounting it
 * makes "serve warm memory from canonical" an explicit, named configuration
 * rather than an implicit default.
 */
export class PostgresWarmStore implements WarmStoreDriver {
  readonly name = POSTGRES_WARMSTORE_NAME;
  readonly external = false;

  constructor(private readonly db: Db) {}

  capabilities(): { rebuildable: boolean } {
    return { rebuildable: false }; // it IS the rebuild source
  }

  async upsert(_records: WarmMirrorRecord[]): Promise<void> {
    // Canonical commit already landed (write path transaction).
  }

  async remove(_ids: MemoryId[]): Promise<void> {
    // Canonical supersedence/erasure already landed.
  }

  async removeNamespace(_namespace: Namespace): Promise<void> {
    // Canonical erasure already landed.
  }

  async health(): Promise<WarmStoreHealth> {
    try {
      await this.db.query("SELECT 1", []);
      return { ok: true };
    } catch (err) {
      return { ok: false, detail: err instanceof Error ? err.message : String(err) };
    }
  }
}

// ---------------------------------------------------------------------------
// Manager — outbox + fan-out + flush + rebuild
// ---------------------------------------------------------------------------

type MirrorOpKind = "upsert" | "invalidate" | "purge" | "purge_namespace";

/**
 * Flush order per store: compliance first, then eviction, then refresh.
 * purge_namespace is a RESERVED lane (nothing enqueues it yet — rebuild wipes
 * the mirror directly); it stays first so a future producer inherits the
 * compliance-priority semantics.
 */
const OP_PRIORITY: Record<MirrorOpKind, number> = {
  purge_namespace: 0,
  purge: 1,
  invalidate: 2,
  upsert: 3,
};

interface MirrorOpRow {
  id: string;
  store: string;
  op: MirrorOpKind;
  ref: string;
  namespace: Namespace;
}

export interface WarmStoreManagerOptions {
  db: Db;
  registry: WarmStoreRegistry;
  logger: Logger;
  /**
   * Optional mirror scope: namespace roots whose subtrees are mirrored.
   * Empty/undefined mirrors everything (HALOMEM_WARMSTORE_NAMESPACES).
   */
  namespaceRoots?: Namespace[];
}

export interface GovernedWarmReadOptions {
  /** Re-evaluate source ACL, classification, purpose, and destination policy. */
  authorize(record: CanonicalWarmRecord): Promise<boolean> | boolean;
}

export interface CanonicalWarmRecord extends WarmMirrorRecord {
  classification: DataClassification;
  sourceAccess: SourceAccess;
}

export class WarmStoreManager {
  private readonly workerId = `warm:${process.pid}:${ulid()}`;
  private readonly db: Db;
  readonly registry: WarmStoreRegistry;
  private readonly logger: Logger;
  private readonly namespaceRoots: Namespace[];
  /**
   * Serializes flush AND rebuild so two triggers cannot interleave one
   * store's op order (in-process; the multi-process window is documented in
   * CONTRACTS-WARMSTORE.md and mitigated by the post-send verify below).
   */
  private chain: Promise<void> = Promise.resolve();

  constructor(opts: WarmStoreManagerOptions) {
    this.db = opts.db;
    this.registry = opts.registry;
    this.logger = opts.logger;
    this.namespaceRoots = (opts.namespaceRoots ?? []).filter((n) => n.length > 0);
  }

  /** True when the namespace is inside a mirrored subtree (default: all). */
  private mirrors(namespace: Namespace): boolean {
    if (this.namespaceRoots.length === 0) return true;
    const ancestors = namespaceAncestors(namespace);
    return this.namespaceRoots.some((root) => ancestors.includes(root));
  }

  private serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn);
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  // --- kernel hooks ---------------------------------------------------------

  /**
   * Post-commit write-through (performWrite hook — covers sync, queued, and
   * D10 ingestion writes). Never throws: a failure here must not fail the
   * syscall whose canonical commit already succeeded.
   */
  async afterWrite(result: WriteResult): Promise<void> {
    try {
      const externals = this.registry.externals();
      if (externals.length === 0) return;

      // Supersedence only ever targets the caller's own namespace, and a
      // superseded id always rides alongside its stored replacement — so the
      // stored twin's namespace is the superseded row's namespace too
      // (src/write/index.ts own-namespace scoping).
      const writeNamespace = result.stored[0]?.namespace ?? ("" as Namespace);

      const ops: Array<{ op: MirrorOpKind; ref: string; namespace: Namespace }> = [];
      for (const obj of result.stored) {
        if (obj.tier !== "L2" || !this.mirrors(obj.namespace)) continue;
        ops.push({ op: "upsert", ref: obj.id, namespace: obj.namespace });
      }
      for (const id of result.superseded) {
        // An un-mirrored subtree never sent the mirror the original row, so
        // it must not leak activity (ids) for it either.
        if (writeNamespace && !this.mirrors(writeNamespace)) continue;
        ops.push({ op: "invalidate", ref: id, namespace: writeNamespace });
      }
      if (ops.length === 0) return;

      for (const store of externals) {
        await this.enqueue(this.db, store.name, ops);
      }
      await this.flush();
    } catch (err) {
      this.logger.warn("warm-store write-through failed (brownout; ops remain queued)", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * R6 erasure atomicity: called by the erasure engine INSIDE the forget
   * transaction with the transaction handle. Enqueues one purge op per
   * external store per erased L2 id, so the DeletionCertificate and the
   * queued mirror purges commit (or roll back) as one fact. `l3:` ids are
   * crypto-shredded canonically and never mirrored.
   */
  async enqueuePurgesTx(
    tx: Db,
    erasedIds: MemoryId[],
    namespace: Namespace,
  ): Promise<void> {
    const externals = this.registry.externals();
    const l2Ids = erasedIds.filter((id) => !id.startsWith("l3:"));
    if (externals.length === 0 || l2Ids.length === 0) return;
    for (const store of externals) {
      await this.enqueue(
        tx,
        store.name,
        l2Ids.map((id) => ({ op: "purge" as const, ref: id, namespace })),
      );
    }
  }

  /** Queue mirror invalidations in the same transaction as source retirement. */
  async enqueueInvalidationsTx(
    tx: Db,
    retiredIds: MemoryId[],
    namespace: Namespace,
  ): Promise<void> {
    const externals = this.registry.externals();
    const l2Ids = retiredIds.filter((id) => !id.startsWith("l3:"));
    if (!this.mirrors(namespace) || externals.length === 0 || l2Ids.length === 0) return;
    for (const store of externals) {
      await this.enqueue(
        tx,
        store.name,
        l2Ids.map((id) => ({ op: "invalidate" as const, ref: id, namespace })),
      );
    }
  }

  /** Drain committed retirement invalidations without failing the caller. */
  async afterRetraction(): Promise<void> {
    try {
      await this.flush();
    } catch (err) {
      this.logger.warn("warm-store retraction propagation failed (ops remain queued)", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Post-commit erasure propagation (memForget hook): the purge ops are
   * already durably queued (enqueuePurgesTx, same transaction as the
   * certificate) — this drains each store's outbox NOW and reports the
   * per-store purge outcome. Called even for a 0-row forget so re-running a
   * forget after an outage drains any still-pending purges. Never throws.
   */
  async afterForget(
    erasedIds: MemoryId[],
    _namespace: Namespace,
  ): Promise<WarmPurgeOutcome[]> {
    const outcomes: WarmPurgeOutcome[] = [];
    try {
      const externals = this.registry.externals();
      if (externals.length === 0) return [];
      const erasedL2 = erasedIds.some((id) => !id.startsWith("l3:"));

      for (const store of externals) {
        try {
          // Report an outcome when this forget erased L2 rows OR older purge
          // ops are still pending (a re-run forget is the repair lane).
          const pendingBefore = await this.pendingPurgeCount(store.name);
          if (!erasedL2 && pendingBefore === 0) continue;
          const { lastError } = await this.flushStore(store.name);
          const left = await this.pendingPurgeCount(store.name);
          outcomes.push(
            left === 0
              ? { store: store.name, status: "purged" }
              : {
                  store: store.name,
                  status: "pending",
                  ...(lastError ? { error: lastError } : {}),
                },
          );
        } catch (err) {
          outcomes.push({
            store: store.name,
            status: "pending",
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    } catch (err) {
      this.logger.warn("warm-store purge propagation failed (purge ops remain queued)", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return outcomes;
  }

  // --- outbox ---------------------------------------------------------------

  private async enqueue(
    db: Db,
    store: string,
    ops: Array<{ op: MirrorOpKind; ref: string; namespace: Namespace }>,
  ): Promise<void> {
    const now = new Date().toISOString();
    for (const op of ops) {
      await db.query(
        `INSERT INTO warm_mirror_ops (id, store, op, ref, namespace, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [ulid(), store, op.op, op.ref, op.namespace, now],
      );
    }
  }

  private async pendingOps(store: string): Promise<MirrorOpRow[]> {
    const now = new Date();
    const res = await this.db.query(
      `WITH candidates AS (
         SELECT id FROM warm_mirror_ops
          WHERE store = $1 AND (
            lease_expires_at IS NULL OR lease_expires_at <= $2 OR lease_owner = $4
          )
          ORDER BY CASE op WHEN 'purge_namespace' THEN 1 WHEN 'purge' THEN 2
                   WHEN 'invalidate' THEN 3 ELSE 4 END, created_at, id
          LIMIT $3 FOR UPDATE SKIP LOCKED
       )
       UPDATE warm_mirror_ops AS op SET lease_owner = $4, lease_expires_at = $5
       FROM candidates WHERE op.id = candidates.id
       RETURNING op.id, op.store, op.op, op.ref, op.namespace`,
      [store, now.toISOString(), MIRROR_BATCH,
        this.workerId, new Date(now.getTime() + 5 * 60_000).toISOString()],
    );
    const rows = (res.rows as Record<string, unknown>[]).map((r) => ({
      id: String(r.id),
      store: String(r.store),
      op: String(r.op) as MirrorOpKind,
      ref: String(r.ref),
      namespace: String(r.namespace) as Namespace,
    }));
    rows.sort(
      (a, b) => OP_PRIORITY[a.op] - OP_PRIORITY[b.op] || (a.id < b.id ? -1 : 1),
    );
    return rows;
  }

  private async pendingPurgeCount(store: string): Promise<number> {
    const res = await this.db.query(
      `SELECT COUNT(*) AS n FROM warm_mirror_ops
        WHERE store = $1 AND op IN ('purge','purge_namespace')`,
      [store],
    );
    return Number((res.rows[0] as Record<string, unknown>)?.n ?? 0);
  }

  private async acquireStoreLease(store: string): Promise<boolean> {
    const now = new Date();
    const result = await this.db.query(
      `INSERT INTO warm_store_leases (store, lease_owner, lease_expires_at, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (store) DO UPDATE SET lease_owner = EXCLUDED.lease_owner,
         lease_expires_at = EXCLUDED.lease_expires_at, updated_at = EXCLUDED.updated_at
       WHERE warm_store_leases.lease_expires_at <= $4
          OR warm_store_leases.lease_owner = $2
       RETURNING store`,
      [store, this.workerId, new Date(now.getTime() + 5 * 60_000).toISOString(), now.toISOString()],
    );
    return result.rows.length === 1;
  }

  private async renewStoreLease(store: string): Promise<void> {
    const now = new Date();
    await this.db.query(
      `UPDATE warm_store_leases SET lease_expires_at = $3, updated_at = $4
       WHERE store = $1 AND lease_owner = $2`,
      [store, this.workerId, new Date(now.getTime() + 5 * 60_000).toISOString(), now.toISOString()],
    );
  }

  private async releaseStoreLease(store: string): Promise<void> {
    await this.db.query(
      `DELETE FROM warm_store_leases WHERE store = $1 AND lease_owner = $2`,
      [store, this.workerId],
    );
  }

  private async pendingCount(store: string): Promise<number> {
    const result = await this.db.query(
      `SELECT COUNT(*) AS n FROM warm_mirror_ops WHERE store = $1`, [store],
    );
    return Number(result.rows[0]?.n ?? 0);
  }

  private async deleteOps(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    const ph = ids.map((_, i) => `$${i + 2}`).join(", ");
    await this.db.query(
      `DELETE FROM warm_mirror_ops WHERE lease_owner = $1 AND id IN (${ph})`,
      [this.workerId, ...ids],
    );
  }

  private async markFailed(ids: string[], error: string): Promise<void> {
    if (ids.length === 0) return;
    const ph = ids.map((_, i) => `$${i + 2}`).join(", ");
    await this.db.query(
      `UPDATE warm_mirror_ops SET attempts = attempts + 1, last_error = $1,
          lease_owner = NULL, lease_expires_at = NULL
        WHERE id IN (${ph}) AND lease_owner = $${ids.length + 2}`,
      [error.slice(0, 500), ...ids, this.workerId],
    );
  }

  // --- flush ----------------------------------------------------------------

  /** Retry every store's outbox now. Returns per-store remaining counts. */
  async flush(): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    for (const store of this.registry.externals()) {
      const { remaining } = await this.flushStore(store.name);
      out[store.name] = remaining;
    }
    return out;
  }

  /**
   * Drain one store's outbox in priority order, stopping at the first
   * delivery failure (order preservation). Serialized with rebuild.
   */
  private flushStore(
    storeName: string,
  ): Promise<{ remaining: number; lastError: string | null }> {
    return this.serialize(() => this.flushStoreInner(storeName));
  }

  private async flushStoreInner(
    storeName: string,
  ): Promise<{ remaining: number; lastError: string | null }> {
    const store = this.registry.get(storeName);
    if (!(await this.acquireStoreLease(storeName))) {
      return { remaining: await this.pendingCount(storeName), lastError: null };
    }
    const heartbeat = setInterval(() => {
      void this.renewStoreLease(storeName).catch(() => undefined);
    }, 60_000);
    heartbeat.unref?.();
    try {
    let ops = await this.pendingOps(storeName);
    let lastError: string | null = null;

    while (ops.length > 0) {
      // One batch = the leading run of same-kind ops, capped at MIRROR_BATCH
      // (an unbounded batch after a long outage would exceed the sidecar
      // timeout forever — permanent livelock — and, past ~65k ids, the
      // bind-parameter limit).
      const kind = ops[0]!.op;
      const batch: MirrorOpRow[] = [];
      for (const op of ops) {
        if (op.op !== kind || batch.length >= MIRROR_BATCH) break;
        batch.push(op);
      }
      try {
        await this.deliver(store, kind, batch);
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        await this.markFailed(batch.map((o) => o.id), lastError).catch(() => undefined);
        break; // preserve order: nothing later may jump a failed batch
      }
      await this.deleteOps(batch.map((o) => o.id));
      ops = await this.pendingOps(storeName);
    }
    return { remaining: await this.pendingCount(storeName), lastError };
    } finally {
      clearInterval(heartbeat);
      await this.releaseStoreLease(storeName).catch(() => undefined);
    }
  }

  private async deliver(
    store: WarmStoreDriver,
    kind: MirrorOpKind,
    batch: MirrorOpRow[],
  ): Promise<void> {
    switch (kind) {
      case "purge_namespace": {
        for (const op of batch) {
          await store.removeNamespace(op.ref as Namespace);
        }
        return;
      }
      case "purge":
      case "invalidate": {
        await store.remove(batch.map((o) => o.ref));
        return;
      }
      case "upsert": {
        // Re-read canonical CURRENT rows at send time (no PII in the outbox;
        // no resurrection of rows erased/superseded since enqueue).
        const ids = batch.map((o) => o.ref);
        const records = await this.currentRecords(ids, store.name);
        const currentIds = new Set(records.map((r) => r.id));
        const gone = ids.filter((id) => !currentIds.has(id));
        if (gone.length > 0) await store.remove(gone);
        if (records.length > 0) {
          await store.upsert(records);
          await this.verifyAfterSend(store, records);
        }
        return;
      }
      default: {
        const _exhaustive: never = kind;
        return _exhaustive;
      }
    }
  }

  /**
   * Post-send compensation: a concurrent process (the CLI shares the
   * database, not this in-process chain) may have purged/superseded a row
   * BETWEEN our canonical re-read and the sidecar accepting the upsert.
   * Re-check canonical after the send and remove anything no longer current.
   * This shrinks the cross-process resurrection window to near-zero; the
   * residual is documented in CONTRACTS-WARMSTORE.md.
   */
  private async verifyAfterSend(
    store: WarmStoreDriver,
    sent: WarmMirrorRecord[],
  ): Promise<void> {
    const still = await this.currentRecords(sent.map((r) => r.id), store.name);
    const stillIds = new Set(still.map((r) => r.id));
    const stale = sent.filter((r) => !stillIds.has(r.id)).map((r) => r.id);
    if (stale.length > 0) await store.remove(stale);
  }

  /** Canonical CURRENT versions for a set of ids (active, currently valid). */
  private async currentRecords(ids: MemoryId[], warmStore?: string): Promise<WarmMirrorRecord[]> {
    if (ids.length === 0) return [];
    const ph = ids.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT id, namespace, scope, type, content, t_valid_from, classification
         FROM memory_objects
        WHERE id IN (${ph}) AND status = 'active' AND t_valid_to IS NULL
          AND tier = 'L2'`,
      ids,
    );
    return (res.rows as Record<string, unknown>[])
      .filter((row) => !warmStore || allowsWarmDestination(row.classification, warmStore))
      .map(rowToRecord);
  }

  private async currentGovernedRecords(
    ids: MemoryId[],
    warmStore: string,
  ): Promise<CanonicalWarmRecord[]> {
    if (ids.length === 0) return [];
    const ph = ids.map((_, i) => `$${i + 1}`).join(", ");
    const res = await this.db.query(
      `SELECT id, namespace, scope, type, content, t_valid_from, classification, source_access
         FROM memory_objects
        WHERE id IN (${ph}) AND status = 'active' AND t_valid_to IS NULL
          AND tier = 'L2'`,
      ids,
    );
    return (res.rows as Record<string, unknown>[])
      .filter((row) => allowsWarmDestination(row.classification, warmStore))
      .map(rowToCanonicalRecord);
  }

  /**
   * Optional mirror read-through. Mirror bytes are untrusted: the complete
   * record must match current canonical state, then the caller's source ACL,
   * classification, purpose, and destination policy gate must allow it. This
   * method returns canonical records only, never mirror-provided objects.
   */
  async governedGet(
    storeName: string,
    ids: MemoryId[],
    options: GovernedWarmReadOptions,
  ): Promise<WarmMirrorRecord[]> {
    const requested = [...new Set(ids)].slice(0, MIRROR_BATCH);
    if (requested.length === 0) return [];
    const store = this.registry.get(storeName);
    if (!store.external || !store.get) {
      throw new WarmStoreUnavailableError(storeName, `warm store "${storeName}" does not support governed reads`);
    }

    const [mirrorRecords, canonicalRecords] = await Promise.all([
      store.get(requested),
      this.currentGovernedRecords(requested, store.name),
    ]);
    const requestedIds = new Set(requested);
    const canonicalById = new Map(canonicalRecords.map((record) => [record.id, record]));
    const stale = new Set<MemoryId>();
    const validMirrorIds = new Set<MemoryId>();
    for (const mirror of mirrorRecords) {
      // A mirror must not be able to induce deletion of an unrequested id.
      if (!requestedIds.has(mirror.id)) continue;
      const canonical = canonicalById.get(mirror.id);
      if (!canonical || !sameWarmRecord(mirror, canonical)) {
        stale.add(mirror.id);
        continue;
      }
      validMirrorIds.add(mirror.id);
    }

    if (stale.size > 0) {
      store.remove([...stale]).catch((error) => {
        this.logger.warn("warm-store stale read compensation failed", {
          store: storeName,
          count: stale.size,
          error: error instanceof Error ? error.name : "unknown",
        });
      });
    }

    const result: WarmMirrorRecord[] = [];
    for (const id of requested) {
      const canonical = canonicalById.get(id);
      if (!canonical || !validMirrorIds.has(id)) continue;
      if (await options.authorize(canonical)) result.push(canonical);
    }
    return result;
  }

  // --- rebuild --------------------------------------------------------------

  /**
   * Reconstruct one external store's cache for a namespace subtree from
   * canonical rows: wipe the subtree at the mirror, then stream every CURRENT
   * fact back in batches. This is the "rebuildable cache, never authority"
   * rule as executable code — and the reconciliation lane for mutations that
   * bypass the write path (movement/archival).
   *
   * The outbox is NOT touched: queued upserts re-read canonical at flush time
   * (idempotent against a rebuild), queued invalidates target superseded ids
   * a rebuild never re-adds, and queued purges must survive at all costs.
   * Serialized with flush so a concurrent forget's purge cannot interleave
   * into the stream. A failed rebuild leaves the mirror partial — re-run it;
   * canonical rows and the outbox are unaffected.
   */
  async rebuild(
    storeName: string,
    namespace: Namespace,
  ): Promise<{ store: string; namespace: Namespace; records: number }> {
    const store = this.registry.get(storeName);
    if (!store.external) {
      throw new Error(`warm store "${storeName}" is canonical - nothing to rebuild`);
    }
    // The namespace scope is the governance control: a subtree configured to
    // stay off-box must not be exportable through the rebuild lane either.
    if (!this.mirrors(namespace)) {
      throw new Error(
        `namespace "${namespace}" is outside the configured mirror scope (HALOMEM_WARMSTORE_NAMESPACES)`,
      );
    }
    return this.serialize(async () => {
      if (!(await this.acquireStoreLease(store.name))) {
        throw new WarmStoreUnavailableError(
          `warm store "${store.name}" is busy on another replica`,
        );
      }
      const heartbeat = setInterval(() => {
        void this.renewStoreLease(store.name).catch(() => undefined);
      }, 60_000);
      heartbeat.unref?.();
      try {
        return await this.rebuildInner(store, namespace);
      } finally {
        clearInterval(heartbeat);
        await this.releaseStoreLease(store.name).catch(() => undefined);
      }
    });
  }

  private async rebuildInner(
    store: WarmStoreDriver,
    namespace: Namespace,
  ): Promise<{ store: string; namespace: Namespace; records: number }> {
    await store.removeNamespace(namespace);

    // Subtree membership: SQL-side prefix predicate (parameterized, LIKE-free)
    // narrows the scan; the ancestor-relation filter in JS stays as the
    // authoritative belt-and-braces check.
    const idRes = await this.db.query(
      `SELECT id, namespace FROM memory_objects
        WHERE status = 'active' AND t_valid_to IS NULL AND tier = 'L2'
          AND (namespace = $1 OR left(namespace, length($1) + 1) = $1 || '/')`,
      [namespace],
    );
    const ids = (idRes.rows as Record<string, unknown>[])
      .filter((r) =>
        namespaceAncestors(String(r.namespace) as Namespace).includes(namespace),
      )
      .map((r) => String(r.id));

    let sent = 0;
    for (let i = 0; i < ids.length; i += MIRROR_BATCH) {
      const records = await this.currentRecords(ids.slice(i, i + MIRROR_BATCH), store.name);
      if (records.length === 0) continue;
      await store.upsert(records);
      await this.verifyAfterSend(store, records);
      sent += records.length;
    }
    return { store: store.name, namespace, records: sent };
  }

  // --- status ---------------------------------------------------------------

  async status(): Promise<WarmStoreStatus[]> {
    const out: WarmStoreStatus[] = [];
    for (const store of this.registry.list()) {
      const health = await store.health();
      const res = await this.db.query(
        `SELECT COUNT(*) AS n, COALESCE(MAX(attempts), 0) AS max_attempts
           FROM warm_mirror_ops WHERE store = $1`,
        [store.name],
      );
      const row = res.rows[0] as Record<string, unknown>;
      const pendingOps = Number(row?.n ?? 0);
      const maxAttempts = Number(row?.max_attempts ?? 0);
      let lastError: string | undefined;
      if (pendingOps > 0) {
        const errRes = await this.db.query(
          `SELECT last_error FROM warm_mirror_ops
            WHERE store = $1 AND last_error IS NOT NULL
            ORDER BY attempts DESC, created_at LIMIT 1`,
          [store.name],
        );
        const errRow = errRes.rows[0] as Record<string, unknown> | undefined;
        if (errRow?.last_error) lastError = String(errRow.last_error);
      }
      out.push({
        name: store.name,
        external: store.external,
        healthy: health.ok,
        ...(health.detail ? { detail: health.detail } : {}),
        pendingOps,
        maxAttempts,
        ...(lastError ? { lastError } : {}),
      });
    }
    return out;
  }
}

function rowToRecord(r: Record<string, unknown>): WarmMirrorRecord {
  return {
    id: String(r.id),
    namespace: String(r.namespace) as Namespace,
    scope: String(r.scope) as WarmMirrorRecord["scope"],
    type: String(r.type) as WarmMirrorRecord["type"],
    content: String(r.content),
    tValidFrom:
      r.t_valid_from instanceof Date
        ? r.t_valid_from.toISOString()
        : String(r.t_valid_from),
  };
}

function rowToCanonicalRecord(r: Record<string, unknown>): CanonicalWarmRecord {
  return {
    ...rowToRecord(r),
    classification: parseClassification(r.classification),
    sourceAccess: parseSourceAccess(r.source_access),
  };
}

function jsonObject(value: unknown): Record<string, unknown> | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function parseClassification(value: unknown): DataClassification {
  const row = jsonObject(value);
  const sensitivity = row?.sensitivity;
  if (!row || !["public", "internal", "confidential", "restricted"].includes(String(sensitivity))) {
    return { sensitivity: "restricted", piiSubjects: [], secretKinds: [], allowedDestinations: [] };
  }
  return {
    sensitivity: sensitivity as DataClassification["sensitivity"],
    piiSubjects: Array.isArray(row.piiSubjects) ? row.piiSubjects.filter((v): v is string => typeof v === "string") : [],
    secretKinds: Array.isArray(row.secretKinds) ? row.secretKinds.filter((v): v is string => typeof v === "string") : [],
    allowedDestinations: Array.isArray(row.allowedDestinations)
      ? row.allowedDestinations.filter((v): v is string => typeof v === "string") : [],
    ...(typeof row.residency === "string" ? { residency: row.residency } : {}),
  };
}

function parseSourceAccess(value: unknown): SourceAccess {
  const row = jsonObject(value);
  return {
    principals: Array.isArray(row?.principals) ? row.principals.filter((v): v is string => typeof v === "string") : [],
    groups: Array.isArray(row?.groups) ? row.groups.filter((v): v is string => typeof v === "string") : [],
    ...(typeof row?.inheritedFrom === "string" ? { inheritedFrom: row.inheritedFrom } : {}),
  };
}

function allowsWarmDestination(value: unknown, store: string): boolean {
  const classification = parseClassification(value);
  if (classification.sensitivity === "public" || classification.sensitivity === "internal") {
    return true;
  }
  return classification.allowedDestinations.includes(`warm:${store}`);
}

function sameWarmRecord(left: WarmMirrorRecord, right: WarmMirrorRecord): boolean {
  return left.id === right.id && left.namespace === right.namespace &&
    left.scope === right.scope && left.type === right.type &&
    left.content === right.content && left.tValidFrom === right.tValidFrom;
}
