/**
 * HaloMem kernel — public barrel (module F).
 */

export { Kernel } from "./kernel.js";
export { loadConfig } from "./config.js";
export type { KernelConfig } from "./config.js";

export {
  memRead,
  memSearch,
  memWrite,
  memFault,
  memAssemble,
  memStats,
  performWrite,
  aclAllows,
  toRetrievalIndex,
  RateLimitError,
} from "./syscalls/index.js";
export type {
  SyscallDeps,
  NamespaceRuntime,
  MemReadArgs,
  MemReadResult,
  MemSearchArgs,
  MemWriteArgs,
  MemWriteResult,
  MemFaultArgs,
  MemAssembleArgs,
  MemStatsArgs,
} from "./syscalls/index.js";

export * from "./types.js";
