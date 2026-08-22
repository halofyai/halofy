/**
 * A 429 must tell the caller WHEN to retry, not just that it failed.
 *
 * The durable store already computes the window reset; these tests prove it
 * survives the trip out through RateLimitError to the transport, on the
 * generic syscall lane (which previously discarded it, because the deps
 * surface exposed only a boolean `allow`), and that the console's header
 * parser turns the wire value back into seconds.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { parseRetryAfter } from "../console/app.js";
import { Kernel } from "../src/kernel.js";
import type { Identity } from "../src/types.js";

let kernel: Kernel;
let knowledgeDir: string;
let owner: Identity;

beforeAll(async () => {
  knowledgeDir = await mkdtemp(join(tmpdir(), "halomem-retry-after-"));
  kernel = await Kernel.boot({ databaseUrl: "", pgliteDataDir: "", knowledgeDir });
  const rootKey = await kernel.auth.issueKey("", "owner:platform", "owner");
  const root = await kernel.auth.resolve(rootKey.plaintext);
  if (!root) throw new Error("root identity resolution failed");
  const key = await kernel.auth.issueKey("acme", "owner:acme", "owner", root);
  const resolved = await kernel.auth.resolve(key.plaintext);
  if (!resolved) throw new Error("owner identity resolution failed");
  owner = resolved;
  // One request per minute: the second search inside the window is denied.
  await kernel.setPolicy("acme", "rateLimitPerMin: 1\nverifierEnabled: false\n");
}, 120_000);

afterAll(async () => {
  if (kernel) await kernel.close();
  if (knowledgeDir) await rm(knowledgeDir, { recursive: true, force: true });
});

describe("syscall rate-limit denials carry retry-after", () => {
  it("attaches the durable window's retryAfterSec to the generic syscall 429", async () => {
    let denial: { name?: string; retryAfterSec?: number } | undefined;
    for (let attempt = 0; attempt < 5 && denial === undefined; attempt += 1) {
      try {
        await kernel.memSearch({ query: "anything", k: 1 }, owner);
      } catch (error) {
        const err = error as { name?: string; retryAfterSec?: number };
        if (err.name === "RateLimitError") denial = err;
        else throw error;
      }
    }

    expect(denial).toBeDefined();
    // The whole point of the patch: a bare boolean could not produce this.
    expect(typeof denial?.retryAfterSec).toBe("number");
    expect(denial?.retryAfterSec).toBeGreaterThan(0);
    expect(denial?.retryAfterSec).toBeLessThanOrEqual(60);
  });
});

describe("console retry-after parsing", () => {
  it("reads delta-seconds and reports 0 when the server gives no usable guidance", () => {
    expect(parseRetryAfter("30")).toBe(30);
    expect(parseRetryAfter("1")).toBe(1);
    // Fractional seconds round up — never advise retrying too early.
    expect(parseRetryAfter("30.2")).toBe(31);
    // Absent, malformed, or non-positive values must not become a fake delay.
    expect(parseRetryAfter(null)).toBe(0);
    expect(parseRetryAfter(undefined)).toBe(0);
    expect(parseRetryAfter("")).toBe(0);
    expect(parseRetryAfter("soon")).toBe(0);
    expect(parseRetryAfter("0")).toBe(0);
    expect(parseRetryAfter("-5")).toBe(0);
    // The HTTP-date form is not emitted by the kernel; guessing would be worse
    // than admitting we have no guidance.
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT")).toBe(0);
  });
});
