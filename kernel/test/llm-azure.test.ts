/**
 * AzureOpenAiLlm request-shape contract.
 *
 * The write path's extractor and verifier run through this client. Production
 * points it at a GPT-5.5 reasoning deployment, which has two hard constraints
 * that a plain chat body violates:
 *
 *  - it rejects any non-default `temperature`, and
 *  - it spends the completion budget on reasoning tokens before emitting
 *    content, so an unbounded request can return an empty string.
 *
 * An empty completion is the dangerous case: the extractor reads it as "no
 * facts", falls back to a verbatim write, and the pipeline looks healthy while
 * every document lands unextracted. These assertions pin the body that avoids
 * both, so nobody re-introduces the failure by "simplifying" the request.
 */

import { afterEach, describe, expect, it } from "vitest";

import { AzureOpenAiLlm } from "../src/llm/index.js";

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

function captureFetch(content: string): { bodies: Record<string, unknown>[]; urls: string[] } {
  const bodies: Record<string, unknown>[] = [];
  const urls: string[] = [];
  globalThis.fetch = (async (url: unknown, init: unknown) => {
    urls.push(String(url));
    const request = init as { body?: string };
    bodies.push(JSON.parse(String(request.body)) as Record<string, unknown>);
    return {
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content } }] }),
      text: async () => "",
    };
  }) as unknown as typeof globalThis.fetch;
  return { bodies, urls };
}

describe("AzureOpenAiLlm request shape", () => {
  it("pins a completion budget so a reasoning deployment cannot return empty content", async () => {
    const { bodies } = captureFetch('{"ok":true}');
    const llm = new AzureOpenAiLlm("key", "https://x.cognitiveservices.azure.com/", "gpt-5.5-1", "2025-04-01-preview");

    const out = await llm.complete("system", "user");

    expect(out).toBe('{"ok":true}');
    expect(bodies).toHaveLength(1);
    expect(bodies[0]!.max_completion_tokens).toBeGreaterThan(0);
  });

  it("sends no temperature, which a GPT-5.5 deployment rejects outright", async () => {
    const { bodies } = captureFetch("{}");
    const llm = new AzureOpenAiLlm("key", "https://x.cognitiveservices.azure.com/", "gpt-5.5-1", "2025-04-01-preview");

    await llm.complete("system", "user");

    expect(bodies[0]).not.toHaveProperty("temperature");
    // max_tokens is the legacy budget field; a reasoning deployment rejects it
    // in favour of max_completion_tokens.
    expect(bodies[0]).not.toHaveProperty("max_tokens");
  });

  it("targets the configured deployment on the configured api version", async () => {
    const { urls } = captureFetch("{}");
    const llm = new AzureOpenAiLlm("key", "https://x.cognitiveservices.azure.com/", "gpt-5.5-1", "2025-04-01-preview");

    await llm.complete("system", "user");

    expect(urls[0]).toBe(
      "https://x.cognitiveservices.azure.com/openai/deployments/gpt-5.5-1" +
        "/chat/completions?api-version=2025-04-01-preview",
    );
  });

  it("forwards the caller's AbortSignal to fetch so a timed-out attempt stops billing", async () => {
    // Without this, withRetry's timeout abandons the promise but Azure keeps
    // generating (and charging for) the completion — the Aug 2026 cost spike.
    const seen: (AbortSignal | undefined)[] = [];
    globalThis.fetch = (async (_url: unknown, init: unknown) => {
      seen.push((init as { signal?: AbortSignal }).signal);
      return {
        ok: true,
        status: 200,
        json: async () => ({ choices: [{ message: { content: "{}" } }] }),
        text: async () => "",
      };
    }) as unknown as typeof globalThis.fetch;
    const llm = new AzureOpenAiLlm("key", "https://x.cognitiveservices.azure.com/", "gpt-5.6-luna-1", "2025-04-01-preview");

    const controller = new AbortController();
    await llm.complete("system", "user", { signal: controller.signal });
    await llm.complete("system", "user");

    expect(seen[0]).toBe(controller.signal); // forwarded verbatim
    expect(seen[1]).toBeUndefined(); // absent stays absent
  });

  it("reports the provider's real token usage - the count billing sees, reasoning included", async () => {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{ message: { content: "{}" } }],
        // completion_tokens includes the hidden reasoning tokens; recording
        // anything else re-creates the 17x under-report on the Azure bill.
        usage: { prompt_tokens: 341, completion_tokens: 660 },
      }),
      text: async () => "",
    })) as unknown as typeof globalThis.fetch;
    const llm = new AzureOpenAiLlm("key", "https://x.cognitiveservices.azure.com/", "gpt-5.6-luna-1", "2025-04-01-preview");

    const usages: { inputTokens: number; outputTokens: number }[] = [];
    await llm.complete("system", "user", { onUsage: (u) => usages.push(u) });
    await llm.complete("system", "user"); // no callback → no throw

    expect(usages).toEqual([{ inputTokens: 341, outputTokens: 660 }]);
  });
});
