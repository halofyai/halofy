import type {
  ConnectorContext,
  ConnectorCursor,
  SourceKind,
  SyncResult,
} from "../../types.js";
import { ConnectorRegistry, validateConnectorConformance } from "./registry.js";

export type ConnectorLifecycleState = "active" | "paused" | "error";

export interface ConnectorLifecycleRecord {
  id: string;
  kind: SourceKind;
  config: Record<string, unknown>;
  state: ConnectorLifecycleState;
  cursor: ConnectorCursor | null;
  lastError: string | null;
  updatedAt: string;
}

/** Integrator implements this against Postgres; no process-local state is assumed. */
export interface ConnectorLifecycleStore {
  load(id: string): Promise<ConnectorLifecycleRecord | null>;
  save(record: ConnectorLifecycleRecord): Promise<void>;
}

/** Durable scheduler seam. Implementations enqueue a leased source-sync job. */
export interface SyncJobScheduler {
  enqueueSourceSync(connectorId: string, notBefore?: string): Promise<void>;
}

export interface CreateConnectorInput {
  id: string;
  kind: SourceKind;
  config: Record<string, unknown>;
}

function safeError(error: unknown): string {
  if (error instanceof Error) return error.name || "connector-error";
  return "connector-error";
}

export class ConnectorLifecycle {
  constructor(
    private readonly registry: ConnectorRegistry,
    private readonly store: ConnectorLifecycleStore,
    private readonly scheduler: SyncJobScheduler,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  /**
   * E57 note: the default re-crawl interval for `doc_site` sources is applied
   * at ROW creation in `SourceRegistry.register` (src/ingest/kernel-store.ts,
   * `defaultSyncIntervalSeconds`), not here — the sources table is the single
   * durable owner of `sync_interval_seconds`/`next_sync_at`, and the kernel's
   * source-sync worker re-arms via durable `availableAt` (notBefore) jobs.
   * This lifecycle seam stays interval-free on purpose: duplicating the
   * schedule here would fork the source of truth.
   */
  async create(input: CreateConnectorInput): Promise<ConnectorLifecycleRecord> {
    if (!input.id.trim()) throw new Error("connector id is required");
    if (await this.store.load(input.id)) throw new Error(`connector '${input.id}' already exists`);
    const connector = this.registry.require(input.kind);
    await validateConnectorConformance(connector, input.config);
    const record: ConnectorLifecycleRecord = {
      id: input.id,
      kind: input.kind,
      config: structuredClone(input.config),
      state: "active",
      cursor: null,
      lastError: null,
      updatedAt: this.now(),
    };
    await this.store.save(record);
    await this.scheduler.enqueueSourceSync(record.id);
    return record;
  }

  async pause(id: string): Promise<ConnectorLifecycleRecord> {
    const record = await this.requireRecord(id);
    const next = { ...record, state: "paused" as const, updatedAt: this.now() };
    await this.store.save(next);
    return next;
  }

  async resume(id: string): Promise<ConnectorLifecycleRecord> {
    const record = await this.requireRecord(id);
    const connector = this.registry.require(record.kind);
    await validateConnectorConformance(connector, record.config);
    const next = {
      ...record,
      state: "active" as const,
      lastError: null,
      updatedAt: this.now(),
    };
    await this.store.save(next);
    await this.scheduler.enqueueSourceSync(id);
    return next;
  }

  async test(id: string): Promise<{ ok: boolean; detail?: string }> {
    const record = await this.requireRecord(id);
    const connector = this.registry.require(record.kind);
    await connector.validateConfig(record.config);
    return connector.testConnection(record.config);
  }

  /** Queue the next run through the durable scheduler; never starts a timer. */
  async schedule(id: string, notBefore?: string): Promise<void> {
    const record = await this.requireRecord(id);
    if (record.state === "paused") throw new Error(`connector '${id}' is paused`);
    await this.scheduler.enqueueSourceSync(id, notBefore);
  }

  /** Operator retry after a recorded error, preserving the last durable cursor. */
  async retry(id: string, notBefore?: string): Promise<ConnectorLifecycleRecord> {
    const record = await this.requireRecord(id);
    if (record.state !== "error") throw new Error(`connector '${id}' is not in error`);
    const next = {
      ...record,
      state: "active" as const,
      lastError: null,
      updatedAt: this.now(),
    };
    await this.store.save(next);
    await this.scheduler.enqueueSourceSync(id, notBefore);
    return next;
  }

  async sync(id: string, ctx: ConnectorContext): Promise<SyncResult> {
    const record = await this.requireRecord(id);
    if (record.state === "paused") throw new Error(`connector '${id}' is paused`);
    const connector = this.registry.require(record.kind);
    const governedContext: ConnectorContext = { ...ctx, config: structuredClone(record.config) };
    try {
      const incremental = connector.syncIncremental
        ? await connector.syncIncremental(governedContext, record.cursor)
        : { result: await connector.sync(governedContext), cursor: record.cursor };
      await this.store.save({
        ...record,
        state: "active",
        cursor: incremental.cursor,
        lastError: null,
        updatedAt: this.now(),
      });
      return incremental.result;
    } catch (error) {
      await this.store.save({
        ...record,
        state: "error",
        // Do not persist provider messages: they may contain credentials/content.
        lastError: safeError(error),
        updatedAt: this.now(),
      });
      throw error;
    }
  }

  private async requireRecord(id: string): Promise<ConnectorLifecycleRecord> {
    const record = await this.store.load(id);
    if (!record) throw new Error(`connector '${id}' not found`);
    return record;
  }
}
