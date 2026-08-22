import { describe, expect, it } from "vitest";
import { ContentAddressedL1Cache, contentAddress } from "../src/cache/index.js";

describe("M7 content-addressed L1 cache", () => {
  it("produces the same address for semantically identical objects", () => {
    expect(contentAddress({ b: 2, a: { d: 4, c: 3 } })).toBe(
      contentAddress({ a: { c: 3, d: 4 }, b: 2 }),
    );
  });

  it("rejects cyclic arrays with a bounded validation error", () => {
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    expect(() => contentAddress(cyclic)).toThrow(/cyclic/);
  });

  it("fails closed when namespace, object version, or policy version changes", () => {
    const cache = new ContentAddressedL1Cache({ now: () => new Date("2026-01-01T00:00:00Z") });
    const entry = cache.set({
      namespace: "acme/ops",
      value: { answer: 42 },
      version: "memory-v2",
      policyVersion: "acl-v7",
      ttlMs: 60_000,
      dependencies: ["memory-v2"],
    });

    expect(cache.get(entry.key, {
      namespace: "acme/ops",
      version: "memory-v1",
      policyVersion: "acl-v7",
    })).toBeNull();
    expect(cache.get(entry.key, {
      namespace: "acme/sales",
      version: "memory-v2",
      policyVersion: "acl-v7",
    })).toBeNull();
    expect(cache.get(entry.key, {
      namespace: "acme/ops",
      version: "memory-v2",
      policyVersion: "acl-v8",
    })).toBeNull();
  });

  it("invalidates superseded dependencies and policy changes", () => {
    const cache = new ContentAddressedL1Cache();
    const first = cache.set({
      namespace: "acme/ops",
      value: "first",
      version: "result-v1",
      policyVersion: "policy-v1",
      ttlMs: 60_000,
      dependencies: ["memory-old"],
    });
    const second = cache.set({
      namespace: "acme/ops",
      value: "second",
      version: "result-v2",
      policyVersion: "policy-v1",
      ttlMs: 60_000,
      dependencies: ["memory-new"],
    });

    expect(cache.invalidateSuperseded("memory-old")).toBe(1);
    expect(cache.peek(first.key)).toBeNull();
    expect(cache.peek(second.key)?.value).toBe("second");
    expect(cache.invalidatePolicy("acme/ops", "policy-v2")).toBe(1);
    expect(cache.peek(second.key)).toBeNull();
  });

  it("invalidates inherited policy changes across the namespace subtree", () => {
    const cache = new ContentAddressedL1Cache();
    const entry = cache.set({
      namespace: "acme/ops", value: "child", version: "v1",
      policyVersion: "org-policy-v1", ttlMs: 60_000,
    });
    expect(cache.invalidatePolicy("acme", "org-policy-v2")).toBe(1);
    expect(cache.peek(entry.key)).toBeNull();
  });

  it("erases an exact namespace subtree without wildcard sibling leakage", () => {
    const cache = new ContentAddressedL1Cache();
    const add = (namespace: string) => cache.set({
      namespace,
      value: namespace,
      version: "v1",
      policyVersion: "p1",
      ttlMs: 60_000,
    });
    const root = add("org/a_%");
    const child = add("org/a_%/child");
    const sibling = add("org/ax");

    expect(cache.eraseNamespace("org/a_%")).toBe(2);
    expect(cache.peek(root.key)).toBeNull();
    expect(cache.peek(child.key)).toBeNull();
    expect(cache.peek(sibling.key)?.value).toBe("org/ax");
  });
});
