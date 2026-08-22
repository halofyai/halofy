/** Named cartridges for vendor sidecars speaking halomem-warmstore/v1. */
import { HttpWarmStore, type HttpWarmStoreOptions } from "./http.js";

export type WarmAdapterOptions = Omit<HttpWarmStoreOptions, "name">;

export class Mem0WarmStore extends HttpWarmStore {
  constructor(options: WarmAdapterOptions) {
    super({ ...options, name: "mem0" });
  }
}

export class SupermemoryWarmStore extends HttpWarmStore {
  constructor(options: WarmAdapterOptions) {
    super({ ...options, name: "supermemory" });
  }
}
