/**
 * S11 organization conflict-scan UI contract (CONTRACTS-CONFLICT-SCAN CS12).
 *
 * Pure Node/string-render tests: no browser, network, or production mutation.
 * The fixtures deliberately expose both conflict lanes so the screen cannot
 * accidentally route active-vs-active scan findings through the write-time
 * dispute resolution state machine.
 */

import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Role = "owner" | "admin" | "auditor" | "member";
type Method = "GET" | "POST";

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const S11_URL = fileURLToPath(new URL("../console/screens/s11.js", import.meta.url));

async function loadS11(): Promise<{
  render(ctx: unknown): Promise<string>;
  actions: Record<string, (ctx: unknown, el: unknown) => Promise<unknown> | unknown>;
  cleanup(): void;
}> {
  return import(S11_URL);
}

function writeDispute() {
  return {
    id: "01JWRITE000000000000000001",
    namespace: "acme/support",
    team: "acme/support",
    category: "policies-legal",
    reason: "document(40) outranks conversation(10)",
    rowVersion: 3,
    createdAt: "2026-07-22T08:30:00.000Z",
    disputed: {
      id: "01JWRITECLAIM000000000001",
      content: "The refund window is 14 days.",
      scope: "team",
      source: "conversation",
      actor: "agent-7",
      confidence: 0.91,
      tValidFrom: "2026-07-22T08:30:00.000Z",
      tValidTo: null,
    },
    incumbent: {
      id: "01JWRITEFACT0000000000001",
      content: "The refund window is 30 days.",
      scope: "team",
      source: "document",
      actor: "connector:handbook",
      confidence: 1,
      tValidFrom: "2026-07-01T00:00:00.000Z",
      tValidTo: null,
    },
    incumbentCurrent: true,
  };
}

function scanFinding() {
  return {
    id: "01JSCANFINDING000000000001",
    scanId: "01JSCAN000000000000000001",
    lane: "scan-finding",
    namespace: "acme/support",
    team: "Support",
    entity: "Refund policy",
    category: "policies-legal",
    kind: "contradiction",
    flags: ["agent-derived", "cross-source"],
    confidence: 0.94,
    status: "open",
    rowVersion: 1,
    sourcePair: ["Support handbook", "Agent chat summary"],
    firstSeenAt: "2026-07-22T09:00:00.000Z",
    lastSeenAt: "2026-07-22T09:00:00.000Z",
    evidence: [
      {
        id: "01JEVIDENCE00000000000001",
        content: "Refunds are accepted for 30 days.",
        source: "document",
        sourceLabel: "Support handbook",
        actor: "connector:handbook",
        session: null,
        confidence: 1,
        tValidFrom: "2026-07-01T00:00:00.000Z",
      },
      {
        id: "01JEVIDENCE00000000000002",
        content: "Refunds are accepted for 14 days.",
        source: "conversation",
        sourceLabel: "Agent chat summary",
        actor: "agent-7",
        session: "session-support-42",
        confidence: 0.91,
        tValidFrom: "2026-07-22T08:30:00.000Z",
      },
    ],
  };
}

interface LatestScan {
  id: string;
  status: "queued" | "running" | "completed" | "completed_with_gaps" | "failed";
  phase: string;
  requestedAt: string;
  completedAt: string | null;
  progress: {
    itemsScanned: number;
    itemsTotal: number;
    sourcesReached: number;
    agentSummaries: number | null;
    candidatePairs?: number;
    modelPairsReviewed?: number;
  };
  summary: null | {
    itemsScanned: number;
    sourcesReached: number;
    agentSummaries: number | null;
    newFindings: number;
    alreadyOpen: number;
  };
  coverageGaps: Array<{ code: string; label: string }>;
}

function completedScan(overrides: Partial<LatestScan> = {}): LatestScan {
  return {
    id: "01JSCAN000000000000000001",
    status: "completed",
    phase: "complete",
    requestedAt: "2026-07-22T08:59:00.000Z",
    completedAt: "2026-07-22T09:00:00.000Z",
    progress: {
      itemsScanned: 1284,
      itemsTotal: 1284,
      sourcesReached: 12,
      agentSummaries: 46,
    },
    summary: {
      itemsScanned: 1284,
      sourcesReached: 12,
      agentSummaries: 46,
      newFindings: 0,
      alreadyOpen: 0,
    },
    coverageGaps: [],
    ...overrides,
  };
}

function autoDecision(overrides: Record<string, unknown> = {}) {
  const finding = scanFinding();
  return {
    id: "01JAUTODECISION0000000001",
    targetNamespace: "acme/support",
    entity: "Refund policy",
    category: "policies-legal",
    reason: "conflicting_quantity",
    confidence: 0.97,
    flags: ["cross-source"],
    rowVersion: 1,
    resolution: "keep-left",
    rule: "lower-trust-rejected",
    decidedAt: "2026-07-22T09:05:00.000Z",
    left: finding.evidence[0],
    right: finding.evidence[1],
    ...overrides,
  };
}

function makeCtx(options: {
  role?: Role;
  disputes?: ReturnType<typeof writeDispute>[];
  findings?: ReturnType<typeof scanFinding>[];
  latestScan?: LatestScan | null;
  scans?: LatestScan[];
  autoDecisions?: ReturnType<typeof autoDecision>[];
  ledger?: Record<string, unknown> | null;
} = {}) {
  const disputes = options.disputes ?? [];
  const findings = options.findings ?? [];
  const latestScan = options.latestScan ?? null;
  const scans = options.scans ?? [];
  const calls: Array<{ method: Method; path: string; body?: unknown }> = [];
  const ctx = {
    esc,
    identity: {
      keyId: "session-test",
      namespace: "acme",
      actor: "owner@acme.test",
      role: options.role ?? "owner",
    },
    async go() {},
    api: {
      async get(path: string) {
        calls.push({ method: "GET", path });
        if (path === "/v1/admin/conflicts") {
          return {
            disputes,
            findings,
            latestScan,
            scans,
            autoDecisions: options.autoDecisions ?? [],
            ledger: options.ledger === undefined
              ? { autoResolved: 0, needsReview: 0, pendingChecks: 0, detectionDegraded: false }
              : options.ledger,
          };
        }
        if (path === "/v1/admin/conflict-scans/latest") return latestScan;
        if (path === "/v1/admin/disputes") return disputes;
        if (path === "/v1/admin/teams") {
          return [{ id: "team_support", name: "Support", namespace: "acme/support" }];
        }
        throw new Error(`unexpected GET ${path}`);
      },
      async post(path: string, body?: unknown) {
        calls.push({ method: "POST", path, body });
        if (path === "/v1/admin/conflict-scans") {
          return { id: "01JSCANNEW000000000000001", status: "queued" };
        }
        throw new Error(`unexpected POST ${path}`);
      },
    },
    refresh: vi.fn(async () => {}),
  };
  return { ctx, calls };
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("S11 conflict scan UI contract", () => {
  it("uses the Home summary language and keeps scan and upload conflicts in separate lanes", async () => {
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({ disputes: [writeDispute()], findings: [scanFinding()], latestScan: completedScan() }).ctx);
    expect(html).toContain('class="home-overview conflicts-overview"');
    expect(html).toContain('aria-label="Conflict review summary"');
    expect(html).toContain("Open Conflicts");
    expect(html).toContain("LLM Findings");
    expect(html).toContain("Legacy Review");
    expect(html).not.toContain("Facts Checked");
    expect(html).toContain('data-conflict-lane="scan"');
    expect(html).toContain('data-conflict-lane="write"');
  });

  it("gives owners a compact bounded scan action and posts a server-scoped request", async () => {
    const s11 = await loadS11();
    const { ctx, calls } = makeCtx();
    const html = await s11.render(ctx);

    expect(html).toContain("Scan memory");
    expect(html).toContain('data-action="toggle-conflict-scan"');
    expect(html).toContain('data-action="run-conflict-scan"');
    expect(html).toContain("bounded diagnostic scan");
    expect(html).toContain("never changes or deletes memory");
    expect(html).not.toContain("Latest scan");
    expect(html).not.toContain("Recent scans");
    expect(html).not.toContain("What limited this scan");
    expect(html).not.toContain('name="namespace"');
    expect(html).not.toContain('name="actor"');
    expect(html).not.toContain('name="agentId"');

    const status = { textContent: "" };
    const form = { querySelector: () => status };
    const button = {
      disabled: false,
      textContent: "Start scan",
      closest: () => form,
    };
    await s11.actions["run-conflict-scan"](ctx, button);
    expect(calls.find((call) => call.method === "POST")).toEqual({
      method: "POST",
      path: "/v1/admin/conflict-scans",
      body: {},
    });
  });

  it("does not expose the organization scan action to read-only roles", async () => {
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({ role: "auditor" }).ctx);
    expect(html).not.toContain("Scan memory");
    expect(html).not.toContain('data-action="run-conflict-scan"');
  });

  it("keeps a running manual scan live until the backend reaches a terminal state", async () => {
    let poll: (() => Promise<void>) | null = null;
    const setTimeout = vi.fn((callback: () => Promise<void>) => {
      poll = callback;
      return 17;
    });
    vi.stubGlobal("window", { setTimeout, clearTimeout: vi.fn() });
    const running = completedScan({
      status: "running",
      phase: "comparing",
      completedAt: null,
      progress: {
        itemsScanned: 2322,
        itemsTotal: 2322,
        sourcesReached: 34,
        agentSummaries: 4,
        candidatePairs: 430,
        modelPairsReviewed: 77,
      },
      summary: null,
    });
    const s11 = await loadS11();
    const { ctx } = makeCtx({ latestScan: running });
    const html = await s11.render(ctx);

    expect(html).toContain('data-manual-scan-state');
    expect(html).toContain("Manual scan");
    expect(html).toContain("77 of 430 candidate pairs reviewed");
    expect(html).toContain('role="progressbar"');
    expect(html).toContain('aria-label="Manual conflict scan progress"');
    expect(html).toContain('aria-valuenow="17.9"');
    expect(html).toContain('style="--conflict-scan-progress:17.9%"');
    expect(html).toContain("17.9% complete");
    expect(html).toContain("Comparing");
    expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 1_500);

    expect(poll).not.toBeNull();
    await (poll as unknown as () => Promise<void>)();
    expect(ctx.refresh).toHaveBeenCalledOnce();
    s11.cleanup();
  });

  it("shows a completed pair-review bar when no candidate pairs need LLM review", async () => {
    vi.stubGlobal("window", { setTimeout: vi.fn(() => 18), clearTimeout: vi.fn() });
    const running = completedScan({
      status: "running",
      phase: "comparing",
      completedAt: null,
      progress: {
        itemsScanned: 12,
        itemsTotal: 12,
        sourcesReached: 2,
        agentSummaries: 0,
        candidatePairs: 0,
        modelPairsReviewed: 0,
      },
      summary: null,
    });
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({ latestScan: running }).ctx);

    expect(html).toContain("No candidate pairs need LLM review");
    expect(html).toContain('aria-valuenow="100"');
    expect(html).toContain('style="--conflict-scan-progress:100%"');
    expect(html).not.toContain("is-pending");
    s11.cleanup();
  });

  it("reports what the autopilot settled and what it has not reached", async () => {
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({
      autoDecisions: [autoDecision()],
      findings: [scanFinding()],
      latestScan: completedScan(),
      ledger: { autoResolved: 1, needsReview: 1, pendingChecks: 3, detectionDegraded: false },
    }).ctx);

    expect(html).toContain("Conflict checking");
    expect(html).toContain('data-tip="Halo\'s Luna judge checks new and historical memory, flags conflicts for a person, and never chooses a winner."');
    expect(html).toContain('<strong>1</strong><div class="subtle">Historical auto decisions</div>');
    expect(html).toContain('<strong>1</strong><div class="subtle">Worth a look</div>');
    expect(html).not.toContain("1 worth a look · 1 historical automatic decision");
    expect(html).not.toContain('<span class="pill pill--live"><i class="dot"></i>On</span>');
    expect(html).toContain("Awaiting check");
    expect(html).toContain("3 recent writes are still being checked");
    // The decision is inspectable and reversible, with its rule in words.
    expect(html).toContain("Historical automatic decision");
    expect(html).toContain("less trusted source");
    expect(html).toContain('data-action="conflict-overturn"');
    expect(html).toContain('data-auto-decision-id="01JAUTODECISION0000000001"');
  });

  it("never renders an unavailable detector as a clean result", async () => {
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({
      latestScan: completedScan(),
      ledger: { autoResolved: 0, needsReview: 0, pendingChecks: 7, detectionDegraded: true },
    }).ctx);

    expect(html).toContain("Conflict checking is unavailable right now");
    expect(html).toContain("7 recent writes");
    expect(html).not.toContain(">Paused</span>");
    expect(html).not.toContain("No conflicts detected");
  });

  it("hides the automatic-decision controls from a read-only role", async () => {
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({
      role: "auditor",
      autoDecisions: [autoDecision()],
      ledger: { autoResolved: 1, needsReview: 0, pendingChecks: 0, detectionDegraded: false },
    }).ctx);
    expect(html).toContain("Historical automatic decision");
    expect(html).not.toContain('data-action="conflict-overturn"');
  });

  it("shows a compact terminal result without restoring scan history or verbose gap details", async () => {
    const partial = completedScan({
      status: "completed_with_gaps",
      progress: {
        itemsScanned: 800,
        itemsTotal: 1200,
        sourcesReached: 8,
        agentSummaries: null,
      },
      summary: {
        itemsScanned: 800,
        sourcesReached: 8,
        agentSummaries: null,
        newFindings: 0,
        alreadyOpen: 2,
      },
      coverageGaps: [
        { code: "agent_capture_unavailable", label: "Agent summary capture is unavailable" },
        { code: "entity_metadata_unavailable", label: "Some facts had no entity metadata" },
        { code: "fact_cap_reached", label: "The fact scan limit was reached" },
        { code: "contradiction_model_unavailable", label: "Semantic conflict review is unavailable" },
      ],
    });
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({ latestScan: partial }).ctx);

    expect(html).toContain("Manual scan");
    expect(html).toContain("800 of 1,200 items checked");
    expect(html).toContain('aria-valuenow="66.7"');
    expect(html).toContain("66.7% complete");
    expect(html).toContain("Partial — check incomplete");
    expect(html).not.toContain("Latest scan");
    expect(html).not.toContain("Completed with gaps");
    expect(html).not.toContain("Recent scans");
    expect(html).not.toContain("What limited this scan");
    expect(html).not.toContain("Agent summary capture is unavailable");
  });

  it("renders scan findings as active-vs-active review items without dispute-resolution actions", async () => {
    const s11 = await loadS11();
    const finding = scanFinding();
    const html = await s11.render(makeCtx({
      findings: [finding],
      latestScan: completedScan({
        summary: {
          itemsScanned: 1284,
          sourcesReached: 12,
          agentSummaries: 46,
          newFindings: 1,
          alreadyOpen: 0,
        },
      }),
    }).ctx);

    expect(html).toContain(`data-scan-finding-id="${finding.id}"`);
    // The heading must say what disagrees with what, in words. The canonical
    // entity is supporting context, never the only label on the card.
    expect(html).toContain("Support handbook disagrees with Agent chat summary");
    expect(html).toContain("About: Refund policy");
    expect(html).toContain("These two statements disagree with each other.");
    expect(html).toContain("From an agent chat");
    expect(html).toContain("Different sources");
    expect(html).toContain("AI-confirmed conflict");
    expect(html).not.toContain("94% confident");
    expect(html).toContain("session-support-42");
    // Raw stored text stays available, one disclosure away.
    expect(html).toContain("Show the full entries");

    const card = html.match(new RegExp(
      `<article[^>]*data-scan-finding-id="${finding.id}"[\\s\\S]*?</article>`,
    ))?.[0] ?? "";
    expect(card).not.toBe("");
    // A reviewer must be able to settle the conflict from the card. Reading it
    // and marking it seen leaves both facts live, so the next scan republishes
    // the same disagreement — the queue never drains.
    expect(card).toContain("Which one is right?");
    expect(card).toContain('data-action="scan-finding-keep" data-keep="left"');
    expect(card).toContain('data-action="scan-finding-keep" data-keep="right"');
    expect(card).toContain("Keep Support handbook");
    expect(card).toContain("Keep Agent chat summary");
    expect(card).toContain('data-action="scan-finding-dismiss"');
    expect(card).not.toContain("The other one stops being used. Nothing is deleted.");
    expect(card).toContain('class="card conflict-finding-card"');
    expect(card).toContain('class="conflict-finding-card__comparison"');
    // Acknowledge was the dead end: it changed no fact and only hid the row.
    expect(card).not.toContain('data-action="scan-finding-acknowledge"');
    expect(card).not.toContain("Uphold new");
    expect(card).not.toContain("Keep current");
    expect(card).not.toContain("Edit &amp; replace");
  });

  it("renders a structured-row finding as named sources and a field difference, never raw ids", async () => {
    const s11 = await loadS11();
    // The shape production actually stores: a table row, annotated with the
    // write path's reserved entity marker, provenance carrying only a ULID.
    const finding = {
      ...scanFinding(),
      entity: "Autumn Campaign",
      reason: "conflicting_quantity",
      left: {
        id: "01KX8204M3ET67EB59BSV9PRDA",
        namespace: "halofy",
        content: "campaign_id: CMP-012, channel: paid_search, impressions: 4055, "
          + "clicks: 118, revenue: 165 [entities: CMP]",
        scope: "team",
        confidence: 1,
        source: "document",
        sourceId: "01KX8204M3ET67EB59BSV9PRDZ",
        sourceName: "Marketing metrics export",
        actor: "ingest",
        session: null,
        assertionTime: "2026-07-11T07:43:05.000Z",
      },
      right: {
        id: "01KX8204M3ET67EB59BSV9PRDB",
        namespace: "halofy",
        content: "campaign_id: CMP-012, channel: paid_search, impressions: 4245, "
          + "clicks: 132, revenue: 165 [entities: CMP]",
        scope: "team",
        confidence: 1,
        source: "document",
        sourceId: "01KX8204M3ET67EB59BSV9PRDZ",
        sourceName: "Marketing metrics export",
        actor: "ingest",
        session: null,
        assertionTime: "2026-07-11T07:43:07.000Z",
      },
      evidence: undefined,
      sourcePair: undefined,
    };
    const html = await s11.render(makeCtx({
      findings: [finding as unknown as ReturnType<typeof scanFinding>],
      latestScan: completedScan(),
    }).ctx);

    expect(html).toContain("Two entries in Marketing metrics export disagree");
    expect(html).toContain("These give different numbers for the same thing.");
    // Only the fields that actually differ, named in words.
    expect(html).toContain('class="conflict-diff"');
    expect(html).toContain("Impressions");
    expect(html).toContain("Clicks");
    expect(html).not.toContain(">Revenue<");
    expect(html).not.toContain(">Channel<");
    // A reviewer must never be shown an internal handle as a label, nor the
    // write path's reserved entity marker.
    expect(html).not.toContain("01KX8204M3ET67EB59BSV9PRDZ");
    expect(html).not.toContain("[entities:");
  });

  it("ties keep buttons to their quotes when both sides share a source label", async () => {
    const base = scanFinding();
    const finding = {
      ...base,
      sourcePair: ["Agent chat summary", "Agent chat summary"],
      evidence: [
        { ...base.evidence[0], sourceLabel: "Agent chat summary", actor: "agent-7", tValidFrom: "2026-07-22T08:00:00.000Z" },
        { ...base.evidence[1], sourceLabel: "Agent chat summary", actor: "agent-9", tValidFrom: "2026-07-22T09:00:00.000Z" },
      ],
    };
    const s11 = await loadS11();
    const html = await s11.render(makeCtx({
      findings: [finding],
      latestScan: completedScan(),
    }).ctx);

    // Same-day, same-source entries fall back to the recorder; the quote
    // headers and the keep buttons share the same Entry numbering so a
    // reviewer can tell which button keeps which quote.
    expect(html).toContain("Keep Entry 1");
    expect(html).toContain("Keep Entry 2");
    expect(html).not.toContain("Keep Agent chat summary");
    expect(html).toMatch(/Entry 1 — (recorded|by) /);
    expect(html).toMatch(/Entry 2 — (recorded|by) /);
  });

  it("preserves the write-dispute comparison and all three governed resolution controls", async () => {
    const s11 = await loadS11();
    const dispute = writeDispute();
    const html = await s11.render(makeCtx({
      disputes: [dispute],
      findings: [scanFinding()],
      latestScan: completedScan(),
    }).ctx);

    const card = html.match(new RegExp(
      `<article[^>]*data-dispute-id="${dispute.id}"[\\s\\S]*?</article>`,
    ))?.[0] ?? "";
    expect(card).not.toBe("");
    expect(card).toContain("Current fact");
    expect(card).toContain("New claim — held for review");
    expect(card).toContain('data-action="dispute-uphold"');
    expect(card).toContain('data-action="dispute-keep"');
    expect(card).toContain('data-action="dispute-edit"');
    // The decision is asked in words, with its consequence, in the same shape
    // as the scan-finding card — never as resolution jargon.
    expect(card).toContain("Which one is right?");
    expect(card).toContain("Keep the new claim");
    expect(card).toContain("Keep the current fact");
    expect(card).toContain("nothing is deleted");
    expect(card).toContain("Edit &amp; replace");
    // The write path's trust-rank trace and the dispute ULID are internals; a
    // reviewer sees a plain-language reason instead.
    expect(card).not.toContain("outranks");
    expect(card).not.toContain(`dispute ${dispute.id}`);
    expect(card).toContain("more trusted source");
  });
});
