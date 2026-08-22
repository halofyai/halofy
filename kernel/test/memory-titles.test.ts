import { afterEach, describe, expect, it } from "vitest";

import { Kernel } from "../src/kernel.js";

const opened: Kernel[] = [];

afterEach(async () => {
  await Promise.all(opened.splice(0).map((kernel) => kernel.close()));
});

async function boot(): Promise<Kernel> {
  const kernel = await Kernel.boot({ databaseUrl: "", pgliteDataDir: "" });
  opened.push(kernel);
  return kernel;
}

async function seed(kernel: Kernel, id: string, namespace: string, content: string): Promise<void> {
  const now = new Date().toISOString();
  await kernel.db.query(
    `INSERT INTO memory_objects
       (id, namespace, scope, tier, backend_ref, content, type, confidence,
        assertion_time, t_valid_from, provenance)
     VALUES ($1,$2,'team','L2','ref',$3,'fact',0.9,$4,$4,'[]')`,
    [id, namespace, content, now],
  );
}

describe("memory display titles", () => {
  it("summarizes pending memories independently and never changes their facts", async () => {
    const kernel = await boot();
    await seed(kernel, "mem-a", "acme/support", "Refund requests close after thirty days.");
    await seed(kernel, "mem-b", "beta/sales", "The Q4 pipeline target is twelve million dollars.");

    const seen: Array<{ memoryId: string; namespace: string; content: string }> = [];
    kernel.attachMemoryTitleExecutor(async (input) => {
      seen.push(input);
      return {
        title: input.memoryId === "mem-a" ? "Thirty-Day Refund Window" : "Q4 Pipeline Target",
        profileId: "luna-profile",
        providerId: "azure",
        model: "gpt-5.6-luna-1",
        inputTokens: 24,
        outputTokens: 6,
      };
    });

    const result = await kernel.runMemoryTitleJobsOnce({ limit: 10 });
    expect(result).toEqual({ claimed: 2, completed: 2, failed: 0 });
    expect(seen).toEqual(expect.arrayContaining([
      { memoryId: "mem-a", namespace: "acme/support", content: "Refund requests close after thirty days." },
      { memoryId: "mem-b", namespace: "beta/sales", content: "The Q4 pipeline target is twelve million dollars." },
    ]));

    const rows = await kernel.db.query(
      `SELECT id, content, display_title, display_title_model, title_status
         FROM memory_objects ORDER BY id`,
    );
    expect(rows.rows).toEqual([
      {
        id: "mem-a",
        content: "Refund requests close after thirty days.",
        display_title: "Thirty-Day Refund Window",
        display_title_model: "gpt-5.6-luna-1",
        title_status: "complete",
      },
      {
        id: "mem-b",
        content: "The Q4 pipeline target is twelve million dollars.",
        display_title: "Q4 Pipeline Target",
        display_title_model: "gpt-5.6-luna-1",
        title_status: "complete",
      },
    ]);
    const invocations = await kernel.db.query(
      `SELECT memory_id, namespace, model, status, input_tokens, output_tokens
         FROM memory_title_invocations ORDER BY memory_id`,
    );
    expect(invocations.rows).toEqual([
      {
        memory_id: "mem-a", namespace: "acme/support", model: "gpt-5.6-luna-1",
        status: "completed", input_tokens: 24, output_tokens: 6,
      },
      {
        memory_id: "mem-b", namespace: "beta/sales", model: "gpt-5.6-luna-1",
        status: "completed", input_tokens: 24, output_tokens: 6,
      },
    ]);
  });

  it("rejects unsafe output and leaves the memory eligible for retry", async () => {
    const kernel = await boot();
    await seed(kernel, "mem-a", "acme/support", "Never expose this content as HTML.");
    kernel.attachMemoryTitleExecutor(async () => ({
      title: "<script>alert(1)</script>",
      profileId: "luna-profile",
      providerId: "azure",
      model: "gpt-5.6-luna-1",
      inputTokens: 20,
      outputTokens: 10,
    }));

    await expect(kernel.runMemoryTitleJobsOnce({ limit: 1 })).resolves.toEqual({
      claimed: 1, completed: 0, failed: 1,
    });
    const row = await kernel.db.query(
      `SELECT display_title, title_status, title_attempts, title_last_error
         FROM memory_objects WHERE id = 'mem-a'`,
    );
    expect(row.rows[0]).toMatchObject({
      display_title: null,
      title_status: "pending",
      title_attempts: 1,
      title_last_error: "invalid_model_output",
    });
  });
});
