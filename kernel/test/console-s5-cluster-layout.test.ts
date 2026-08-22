import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { renderTopology } from "../console/screens/s5-topology.js";

const esc = (value: unknown): string => String(value ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/\"/g, "&quot;")
  .replace(/'/g, "&#39;");

function source(index: number) {
  const kind = index === 1
    ? "notion_direct"
    : index === 2
      ? "linear_direct"
      : index % 2 === 0 ? "shopify" : "rista";
  const documents = index <= 2
    ? Array.from({ length: 5 }, (_, documentIndex) => ({
        id: `${kind}-document-${documentIndex + 1}`,
        name: `${kind === "notion_direct" ? "Notion page" : "Linear issue"} ${documentIndex + 1}`,
        syncedAt: "2026-08-01T12:00:00.000Z",
      }))
    : [];
  return {
    id: `source-${index}`,
    namespace: "halofy",
    kind,
    documents,
    documentCount: index === 1 ? 7 : documents.length,
    syncStatus: "synced",
    lastSync: "2026-08-01T12:00:00.000Z",
    lastSyncError: null,
    lifecycleState: "active",
  };
}

function file(baseIndex: number, index: number) {
  return {
    id: `file-${baseIndex}-${index}`,
    sourceId: `source-${baseIndex + 1}`,
    name: `knowledge-${baseIndex}-${index}.md`,
    status: "ready",
    factCount: index + 1,
  };
}

function memory(index: number, tier: "L2" | "L3") {
  return {
    id: `memory-${index}`,
    namespace: "halofy",
    label: `Fact ${index}`,
    type: "fact",
    tier,
    accessCount: Math.max(0, 40 - index),
    state: index === 1 ? "older" : "current",
    supersedes: index === 2 ? "memory-1" : null,
    sourceIds: index === 3 ? ["source-1"] : [],
  };
}

function denseMap() {
  return {
    pinned: [],
    governedPins: [],
    topology: {
      scope: "selected-subtree",
      sources: Array.from({ length: 34 }, (_, index) => source(index + 1)),
      policies: [],
      memories: [
        ...Array.from({ length: 9 }, (_, index) => memory(index + 1, "L2" as const)),
        ...Array.from({ length: 2 }, (_, index) => memory(index + 10, "L3" as const)),
      ],
      knowledgeBases: Array.from({ length: 4 }, (_, baseIndex) => ({
        id: `base-${baseIndex + 1}`,
        namespace: "halofy",
        name: ["Growth", "Sales", "Product", "Operations"][baseIndex],
        kind: "file",
        status: "ready",
        sourceId: `source-${baseIndex + 1}`,
        files: Array.from({ length: 8 }, (_, index) => file(baseIndex + 1, index + 1)),
      })),
      skills: Array.from({ length: 30 }, (_, index) => ({
        id: `skill-${index + 1}`,
        namespace: "halofy",
        key: `skill-${index + 1}`,
        name: `Skill ${index + 1}`,
        vettingStatus: "vetted",
        safetyScore: 90,
      })),
      agents: Array.from({ length: 7 }, (_, index) => ({
        id: `agent-${index + 1}`,
        namespace: "halofy",
        actor: `Agent ${index + 1}`,
      })),
      activeFacts: 733,
      activityFacts: 2,
      companyPublishedFacts: 733,
      routing: { mode: "fixed", name: "baseline" },
    },
  };
}

function position(html: string, id: string): { x: number; y: number } {
  const match = html.match(new RegExp(
    `class="memory-graph-node[^"]*"[^>]*data-node-id="${id}"[^>]*style="--x:([0-9.]+)%;--y:([0-9.]+)%`,
  ));
  expect(match, `missing graph node ${id}`).not.toBeNull();
  return { x: Number(match?.[1]), y: Number(match?.[2]) };
}

function distance(a: { x: number; y: number }, b: { x: number; y: number }): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

describe("S5 clustered memory graph", () => {
  it("keeps the five disclosed backend connectors clear of one another", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const visible = Array.from({ length: 5 }, (_, index) => position(html, `b:source-${index + 1}`));
    for (let a = 0; a < visible.length; a += 1) {
      for (let b = a + 1; b < visible.length; b += 1) {
        const horizontalGap = Math.abs(visible[a].x - visible[b].x);
        const verticalGap = Math.abs(visible[a].y - visible[b].y);
        expect(horizontalGap * 10 >= 180 || verticalGap * 8 >= 15).toBe(true);
      }
    }
    expect(html).toContain('class="memory-graph-cluster memory-graph-cluster--backend"');
    expect(html).toContain('data-cluster-id="g:backends"');
    const nodeCount = html.match(/class="memory-graph-node-hit"/g)?.length ?? 0;
    const namedNodeCount = html.match(/class="memory-graph-node-hit"[^>]*aria-label="[^"]+"/g)?.length ?? 0;
    expect(namedNodeCount).toBe(nodeCount);
  });

  it("gives every expanded backend connector enough row and label clearance", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const connectors = Array.from(
      { length: 34 },
      (_, index) => position(html, `b:source-${index + 1}`),
    );

    for (let a = 0; a < connectors.length; a += 1) {
      for (let b = a + 1; b < connectors.length; b += 1) {
        const horizontalGap = Math.abs(connectors[a].x - connectors[b].x);
        const verticalGap = Math.abs(connectors[a].y - connectors[b].y);
        // Source labels extend to the right. Nodes may share a row only when
        // their columns are farther apart than a full label; nodes in one
        // column need more than a line of vertical clearance.
        expect(horizontalGap * 10 >= 180 || verticalGap * 8 >= 15).toBe(true);
      }
    }
  });

  it("keeps the expanded Backends and Skills bands vertically separate", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const connectors = Array.from(
      { length: 34 },
      (_, index) => position(html, `b:source-${index + 1}`),
    );
    const skills = Array.from(
      { length: 30 },
      (_, index) => position(html, `s:skill-${index + 1}`),
    );
    const backendBottom = Math.max(...connectors.map((entry) => entry.y));
    const skillsTop = Math.min(...skills.map((entry) => entry.y));

    expect((skillsTop - backendBottom) * 8).toBeGreaterThan(48);
  });

  it("places each knowledge file in the local orbit of its own knowledge-base center", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const base = position(html, "kb:base-1");
    const localFiles = Array.from({ length: 5 }, (_, index) => position(html, `f:file-1-${index + 1}`));

    for (const localFile of localFiles) {
      expect(distance(base, localFile)).toBeGreaterThan(4);
      expect(distance(base, localFile)).toBeLessThan(12);
    }
    expect(html).toContain('data-cluster-id="kb:base-1"');
  });

  it("nests backend files under their connector without mixing in knowledge-base uploads", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const notion = position(html, "b:source-1");
    const notionFiles = Array.from(
      { length: 5 },
      (_, index) => position(html, `bf:source-1:notion_direct-document-${index + 1}`),
    );

    for (const backendFile of notionFiles) {
      expect(distance(notion, backendFile)).toBeGreaterThan(3);
      expect(distance(notion, backendFile)).toBeLessThan(12);
    }
    expect(html).toContain('data-cluster-id="b:source-1"');
    expect(html).toContain('data-node-id="bf:rollup:source-1"');
    expect(html).toContain("2 more files");
    expect(html).toContain(">Notion<");
    expect(html).toContain(">Linear<");

    // Company-file uploads remain exclusively in their knowledge-base tree.
    expect(html).toMatch(/data-from="kb:base-1" data-to="f:file-1-1"/);
    expect(html).not.toContain('data-from="b:source-1" data-to="f:file-1-1"');
    expect(html).toContain("Backend files");
    expect(html).toContain("Knowledge uploads");
    expect(html).toMatch(
      /memory-graph-node--source[^>]*data-node-id="b:source-1"[^>]*>[\s\S]*?data-action="topo-toggle"/,
    );
    expect(html).toMatch(
      /memory-graph-node--backend-file is-collapsed"[^>]*data-node-id="bf:source-1:notion_direct-document-1"[^>]*data-collapse-parents="b:source-1"/,
    );
  });

  it("gives every memory lane its own bubble, spread apart like the other lanes", () => {
    const html = renderTopology({ esc } as never, denseMap());

    // Each of L0-L3 draws its own section halo, the way backends and skills do
    // - not four dots sharing one 'RAG / cache' blob.
    for (const tier of ["L0", "L1", "L2", "L3"]) {
      expect(html).toContain(`data-cluster-id="g:lane:${tier}"`);
    }
    // The junction that carries the lanes off the hub draws no halo of its own.
    expect(html).not.toContain('data-cluster-id="g:rag"');

    // The four lane nodes are spread, not stacked: every pair sits well apart.
    const lanes = ["L0", "L1", "L2", "L3"].map((tier) => position(html, `t:${tier}`));
    for (let a = 0; a < lanes.length; a += 1) {
      for (let b = a + 1; b < lanes.length; b += 1) {
        expect(distance(lanes[a], lanes[b])).toBeGreaterThan(12);
      }
    }

    // Records belong to their lane's bubble and are held clear of the hub.
    const hub = position(html, "core:governed");
    const warmMemories = Array.from({ length: 9 }, (_, index) => position(html, `m:memory-${index + 1}`));
    const coldMemories = [position(html, "m:memory-10"), position(html, "m:memory-11")];
    for (const memory of [...warmMemories, ...coldMemories]) {
      expect(distance(hub, memory)).toBeGreaterThan(20);
    }

    // Nine L2 memories exceed the five-visible budget, so the L2 lane node is
    // the disclosure control and the overflow starts collapsed.
    const warmButton = html.match(/<button[^>]*data-node-id="t:L2"[^>]*>/)?.[0] ?? "";
    expect(warmButton).toContain('data-action="topo-toggle"');
    expect(warmButton).toContain('aria-expanded="false"');
    expect(html).toMatch(/memory-graph-node--memory[^"]*is-collapsed"[^>]*data-node-id="m:memory-9"[^>]*data-collapse-parents="t:L2"/);
    // Two L3 memories fit the budget, so the cold lane keeps plain focus.
    const coldButton = html.match(/<button[^>]*data-node-id="t:L3"[^>]*>/)?.[0] ?? "";
    expect(coldButton).toContain('data-action="topo-focus"');

    // Supersedence and provenance stay visible relationships, not overwrites.
    expect(html).toMatch(/data-from="m:memory-2" data-to="m:memory-1"[^>]*data-relation="update"/);
    expect(html).toMatch(/data-from="b:source-1" data-to="m:memory-3"[^>]*data-relation="provenance"/);
  });

  it("keeps a 730-memory lane responsive with a bounded sample and roll-up", () => {
    const map = denseMap();
    map.topology.memories = Array.from(
      { length: 730 },
      (_, index) => memory(index + 1, "L2"),
    );

    const html = renderTopology({ esc } as never, map);
    const rendered = html.match(
      /class="memory-graph-node memory-graph-node--memory[^"]*"[^>]*data-node-id="m:memory-/g,
    ) ?? [];
    expect(rendered).toHaveLength(36);
    expect(html).not.toContain('data-node-id="m:memory-730"');
    expect(html).toContain('data-node-id="mem:rollup:L2"');
    expect(html).toContain("694 more memories");
    expect(html).toContain("Show 32 more connections");
  });

  it("runs the downstream flow outward past the lane, never back toward the junction", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const junction = position(html, "g:rag");
    const warmLane = position(html, "t:L2");
    const laneReach = distance(junction, warmLane);

    // Everything the warm lane feeds - its summary, the retrieval route, and
    // the agents at the end of it - sits past the lane on the far side. Tucked
    // between the junction and the lane, their links read as flowing back
    // toward the hub, which is the reverse of what actually happens.
    for (const id of ["mem:common", "r:fixed", "g:agents"]) {
      const downstream = position(html, id);
      expect(distance(junction, downstream)).toBeGreaterThan(laneReach);
      expect(downstream.x).toBeGreaterThan(warmLane.x);
    }
  });

  it("rings the memories evenly around their own lane, with nothing crowding in", () => {
    const html = renderTopology({ esc } as never, denseMap());
    const warmLane = position(html, "t:L2");
    const warmMemories = Array.from({ length: 9 }, (_, index) => position(html, `m:memory-${index + 1}`));

    // They surround the lane rather than sitting off to one side of it: the
    // inner ring is a full circle, so records fall on all four sides.
    expect(warmMemories.some((p) => p.x < warmLane.x)).toBe(true);
    expect(warmMemories.some((p) => p.x > warmLane.x)).toBe(true);
    expect(warmMemories.some((p) => p.y < warmLane.y)).toBe(true);
    expect(warmMemories.some((p) => p.y > warmLane.y)).toBe(true);

    // Nine records fill a ring of six and start a second: two distinct radii,
    // and the outer one is about twice the inner. A relaxed cloud has neither.
    const radii = warmMemories
      .map((p) => Math.round(distance(p, warmLane) * 2) / 2)
      .sort((a, b) => a - b);
    const bands = [...new Set(radii)];
    expect(bands.length).toBeGreaterThanOrEqual(2);
    expect(bands[bands.length - 1] / bands[0]).toBeGreaterThan(1.5);

    // No two records land on top of each other.
    for (let a = 0; a < warmMemories.length; a += 1) {
      for (let b = a + 1; b < warmMemories.length; b += 1) {
        expect(distance(warmMemories[a], warmMemories[b])).toBeGreaterThan(2);
      }
    }

    // Nothing else drifts in among them: pinned nodes still repel, so every
    // other node in the graph keeps its distance from the block.
    const others = [...html.matchAll(/data-node-id="((?!m:)[^"]+)"[^>]*style="--x:([0-9.]+)%;--y:([0-9.]+)%/g)]
      .map((match) => ({ id: match[1], x: Number(match[2]), y: Number(match[3]) }));
    expect(others.length).toBeGreaterThan(5);
    for (const other of others) {
      for (const memory of warmMemories) {
        expect(distance(other, memory)).toBeGreaterThan(3);
      }
    }

    // The lane's own links carry the quieter relation - one lane owning this
    // many records would otherwise draw a solid wedge of branch strokes.
    expect(html).toMatch(/data-from="t:L2" data-to="m:memory-1"[^>]*data-relation="memory"/);
  });

  it("keeps satellite labels and source state secondary to the hover and keyboard tooltip", async () => {
    const css = await readFile(
      fileURLToPath(new URL("../console/app.css", import.meta.url)),
      "utf8",
    );

    expect(css).toMatch(/\.memory-graph-node--source \.memory-graph-node-copy\{[\s\S]*?opacity:1;visibility:visible/);
    expect(css).toMatch(/\.memory-graph-node--source \.memory-graph-source-state\{opacity:0/);
    expect(css).toMatch(/\.memory-graph-node-hit:hover \.memory-graph-tooltip[\s\S]*?opacity:1/);
    expect(css).toMatch(/@media\(max-width:720px\)[\s\S]*?\.memory-graph-viewport\{min-width:600px\}/);
    expect(css).toContain(".memory-graph-cluster{position:absolute;z-index:0");
    expect(css).toMatch(/\.memory-graph-cluster\{[^}]*border:0/);
    expect(css).toContain(".memory-graph-node--hub .memory-graph-node-hit{width:22px;height:22px");
    expect(css).toContain(".memory-graph-node--branch .memory-graph-node-hit{width:14px;height:14px");
  });

  it("keeps expandable controls above overlapping graph nodes", async () => {
    const css = await readFile(
      fileURLToPath(new URL("../console/app.css", import.meta.url)),
      "utf8",
    );

    expect(css).toContain(
      ".memory-graph-node--expandable,.memory-graph-node--expandable:hover,.memory-graph-node--expandable:focus-within{z-index:13}",
    );
  });
});
