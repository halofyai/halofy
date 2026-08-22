import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

async function screenSource(name: string): Promise<string> {
  return readFile(
    fileURLToPath(new URL(`../console/screens/${name}.js`, import.meta.url)),
    "utf8",
  );
}

describe("operate console minimalism source contracts", () => {
  it("removes redundant Home card subtitles and the all-clear card wall", async () => {
    const source = await screenSource("s2");

    for (const copy of [
      "Assistant activity by model.",
      "Where saved knowledge comes from.",
      "Teams using memory most.",
      "People and agents using memory most.",
      "How often agents find the knowledge they need.",
      "Freshness, coverage and trust at a glance.",
      "Track this month&#39;s AI spend, credits and limits.",
    ]) {
      expect(source).not.toContain(copy);
    }
    // The all-clear wall and its Access Safety replacement are both gone from
    // Home. Governance stays on the dedicated Audit, Alerts, and access-request
    // surfaces while Home uses the space for Memory Writes.
    expect(source).not.toContain("Needs your attention");
    expect(source).not.toContain("Access Safety");
    expect(source).not.toContain("overreaching.length");
    expect(source).not.toContain("pendingRequests");
    // Model, source-contributor and query-category detail live on their own
    // screens now, so Home no longer hides a second dashboard in a disclosure.
    expect(source).not.toContain("home-activity-breakdown");
    expect(source).not.toContain("Top models");
    expect(source).toContain('goBtn("s15", "View all in Usage analytics');
  });

  it("is the memory graph alone - no activity rail, no guidance card", async () => {
    const source = await screenSource("s5");

    expect(source).not.toContain('class="compact-disclosure memory-signals-guide"');
    expect(source).not.toContain("Retrieval signals");
    expect(source).not.toContain("Hottest facts");
    expect(source).not.toContain("memory-signals-head");
    expect(source).not.toContain("memory-activity-card");
    expect(source).not.toContain("memory-facts-card");
    expect(source).not.toContain("memory-kept-card");
  });

  it("reduces topology chrome while retaining the accessible operating summary", async () => {
    const source = await screenSource("s5-topology");

    expect(source).toContain('id="memory-topology-summary" class="sr-only"');
    expect(source).not.toContain('<p>${detail}</p>');
    expect(source).not.toContain("Conceptual flow · live stage metrics</span>");
  });

  it("discloses source connection and machine-error detail", async () => {
    const source = await screenSource("s6");

    expect(source).toContain('class="compact-disclosure source-technical-details"');
    // Connection detail is disclosed by the drawer a tile opens, not by an
    // inline disclosure on a page-wide card.
    expect(source).toContain('aria-controls="source-detail-panel" aria-haspopup="dialog"');
    expect(source).toContain('sourceDetailSection("Connection details"');
    expect(source).not.toContain('class="compact-disclosure source-connection-disclosure"');
    expect(source).toContain('<p class="sr-only" data-summary-description>');
  });

  it("discloses scorecard methodology and assistant runtime evidence", async () => {
    const scorecard = await screenSource("s9");
    const assistant = await screenSource("s10");

    expect(scorecard).toContain('class="compact-disclosure scorecard-method"');
    expect(assistant).toContain('class="compact-disclosure copilot-panel"');
    expect(assistant).toContain('class="compact-disclosure__body copilot-panel-body"');
  });

  it("keeps connection setup secondary to the client action grid", async () => {
    const source = await screenSource("s14");

    expect(source).toContain('class="compact-disclosure intg-key-disclosure"');
    expect(source).toContain('class="compact-disclosure__body intg-key-disclosure-body"');
    expect(source).toContain('(mintedKey ? " open" : "")');
    expect(source).toContain("~/.hermes/config.yaml");
    expect(source).toContain("mcp_servers");
    expect(source).toContain("~/.openclaw/openclaw.json");
    expect(source).toContain('transport: "streamable-http"');
    expect(source).not.toContain("Mint or paste a key above");
    expect(source).not.toContain("cdn.brandfetch.io");
    expect(source).not.toContain('"</h2><p>" + subHtml');
  });

  it("keeps the memory graph summary available to assistive technology", async () => {
    const source = await screenSource("s5-topology");

    expect(source).toContain('aria-describedby="memory-topology-summary"');
    expect(source).toContain('id="memory-topology-summary" class="sr-only"');
    expect(source).toContain('aria-label="Interactive memory relationship graph"');
  });
});
