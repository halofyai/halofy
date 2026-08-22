/**
 * Module A (M2) — driver core: DriverRegistry + DriverUnavailableError.
 *
 * The registry holds mounted RetrieverDriver cartridges keyed by
 * `driver.name`. Routing policy resolves names through `get()`:
 *   - known name  → that driver;
 *   - unknown name → the mounted 'baseline' driver + a warn log (routing is
 *     config, so a typo'd or unmounted retriever name degrades gracefully
 *     instead of failing the request);
 *   - unknown name AND no baseline mounted → DriverUnavailableError.
 *
 * DriverUnavailableError is also thrown by out-of-process drivers (mem0)
 * when their sidecar is down; the kernel catches it, falls back to baseline,
 * and audits `driver_fallback=<name>->baseline`.
 */

import type { RetrieverDriver } from "../types.js";

export { buildScopedView } from "./view.js";
export type {
  ScopedViewDeps,
  ViewColdLike,
  ViewEntitiesLike,
  ViewEntityLike,
  ViewIndexLike,
  ViewRowLike,
} from "./view.js";
export { BaselineDriver } from "./baseline.js";

/** Name every registry falls back to when asked for an unknown driver. */
export const BASELINE_DRIVER_NAME = "baseline";

/** A driver (or its sidecar) cannot serve requests right now. */
export class DriverUnavailableError extends Error {
  constructor(
    public readonly driver: string,
    message?: string,
    options?: { cause?: unknown },
  ) {
    super(message ?? `driver "${driver}" is unavailable`, options);
    this.name = "DriverUnavailableError";
  }
}

/**
 * Duck-typed check for DriverUnavailableError. The kernel uses the name (not
 * instanceof) so an error thrown across module instances (e.g. a test that
 * imports the class from a different specifier) is still recognized and the
 * baseline fallback still fires.
 */
export function isDriverUnavailableError(err: unknown): err is DriverUnavailableError {
  return err instanceof Error && err.name === "DriverUnavailableError";
}

/** Minimal warn-only logger slice (kernel logger satisfies this). */
export interface DriverLogger {
  warn(message: string): void;
}

export class DriverRegistry {
  private readonly drivers = new Map<string, RetrieverDriver>();

  constructor(
    private readonly logger: DriverLogger = { warn: (m) => console.warn(m) },
  ) {}

  /** Mount (or replace) a driver under its own `name`. */
  mount(driver: RetrieverDriver): void {
    if (!driver.name) {
      throw new Error("DriverRegistry.mount: driver has no name");
    }
    this.drivers.set(driver.name, driver);
  }

  /**
   * Resolve a driver by name. Unknown names fall back to the mounted
   * baseline driver with a warn log; if no baseline is mounted either,
   * throws DriverUnavailableError.
   */
  get(name: string): RetrieverDriver {
    const found = this.drivers.get(name);
    if (found) return found;
    const baseline = this.drivers.get(BASELINE_DRIVER_NAME);
    if (baseline) {
      this.logger.warn(
        `DriverRegistry: unknown driver "${name}" - falling back to "${BASELINE_DRIVER_NAME}"`,
      );
      return baseline;
    }
    throw new DriverUnavailableError(
      name,
      `driver "${name}" is not mounted and no "${BASELINE_DRIVER_NAME}" fallback is available`,
    );
  }

  /** Mounted driver names, in mount order. */
  list(): string[] {
    return [...this.drivers.keys()];
  }

  /** Exact mounted-state check. Unlike get(), this never falls back. */
  has(name: string): boolean {
    return this.drivers.has(name);
  }

  /** Public setup capability inventory, sourced only from mounted cartridges. */
  capabilities(): Array<{
    name: string;
    capabilities: { graph: boolean; streaming: boolean };
  }> {
    return [...this.drivers.values()].map((driver) => ({
      name: driver.name,
      capabilities: driver.capabilities(),
    }));
  }
}
