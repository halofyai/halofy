// S5 live memory graph. Customer-specific leaves and counts come only from the
// selected-subtree payload. The graph shows mounted systems, the L0-L3 memory
// lanes, and a bounded representative set of the memories the read model ships
// for this scope. High-cardinality lanes keep their authoritative count while
// the canvas rolls the remainder into one lightweight summary node.
//
// Individual memories are the densest population in the graph — dozens of them
// against a handful of backends or skills — so they get their own section on
// the right rather than orbiting their lane node. The lane keeps its place in
// the compact L0-L3 column and reaches across to the section it owns; clicking
// the lane still discloses the overflow.

export const GRAPH_VIEW_WIDTH = 1000;
export const GRAPH_VIEW_HEIGHT = 800;
const MAX_VISIBLE_CHILDREN = 5;
const MAX_VISIBLE_LINKS = 6;
const MAX_RENDERED_MEMORIES_PER_TIER = 36;
const GRAPH_SCALE = 0.9;
const TAU = Math.PI * 2;
const CLUSTER_LAYOUTS = {
  policies: { id: "g:policies", kind: "policy", x: 17, y: 19, radiusX: 9, radiusY: 10, phase: -0.7 },
  // Connector names stay visible on the canvas, so this lane needs enough
  // room for two label-width columns and a full row of clearance between
  // each source. High-cardinality branches use these radii as grid bounds.
  backends: { id: "g:backends", kind: "backend", x: 17, y: 43, radiusX: 14, radiusY: 22, phase: -1.1 },
  // Pulled in from the authored width so the lane column has clear air to its
  // right; the knowledge lane is the only one that grows toward it.
  knowledge: { id: "g:knowledge", kind: "knowledge", x: 42, y: 17, radiusX: 12, radiusY: 10, phase: -0.35 },
  skills: { id: "g:skills", kind: "skill", x: 32, y: 84, radiusX: 18, radiusY: 14, phase: -1.35 },
  // A junction, not a section: the four lanes each own a bubble of their own,
  // so this node only has to sit between the hub and them. It draws no halo.
  rag: { id: "g:rag", kind: "retrieval", x: 58, y: 40, radiusX: 5, radiusY: 6, phase: -0.7 },
  // Agents are the far end of the retrieval flow, so they sit past the lanes
  // rather than back beside the junction - the route that feeds them reads
  // outward instead of doubling back toward the hub.
  agents: { id: "g:agents", kind: "agent", x: 92, y: 88, radiusX: 7, radiusY: 6, phase: -0.85 },
};
/** Lanes own their own bubbles, so the junction's authored halo is never drawn. */
const HALOLESS_GROUPS = new Set(["g:rag"]);

// One section per memory lane, spread across the right the way the other lanes
// are spread across the left. L0 and L1 hold no records of their own, so they
// stay small; L2 and L3 are sized for the records that ring them.
const LANE_SECTIONS = {
  L0: { id: "g:lane:L0", kind: "retrieval", x: 68, y: 12, radiusX: 8, radiusY: 8, phase: -0.7 },
  L1: { id: "g:lane:L1", kind: "retrieval", x: 90, y: 12, radiusX: 8, radiusY: 8, phase: -0.7 },
  L2: { id: "g:lane:L2", kind: "retrieval", x: 89, y: 42, radiusX: 10, radiusY: 12, phase: -1.1 },
  // L3 takes the bottom rather than the right, so the outer edge past L2 stays
  // clear for the downstream flow — summaries, route, agents. Far enough down
  // that its own records still clear the hub.
  L3: { id: "g:lane:L3", kind: "retrieval", x: 66, y: 84, radiusX: 6, radiusY: 6, phase: -1.1 },
};
const MEMORY_TIER_ORDER = ["L2", "L3"];
/** Records per ring at radius k. Capacity rising with k keeps the arc gap even. */
const RING_BASE = 6;

/**
 * @param {import('../app.js').Ctx} ctx
 * @param {Record<string, any>} map
 * @returns {string}
 */
export function renderTopology(ctx, map) {
  const { esc } = ctx;
  const topology = map && map.topology;
  if (!validTopology(topology)) return renderUnavailable();

  const pins = [
    ...(Array.isArray(map.pinned) ? map.pinned : []),
    ...(Array.isArray(map.governedPins)
      ? map.governedPins.map((pin) => pin?.target?.ref).filter(nonEmptyString)
      : []),
  ];
  const files = topology.knowledgeBases.flatMap((base) => base.files);
  const backendDocumentCount = topology.sources.reduce(
    (total, source) => total + sourceDocumentCount(source),
    0,
  );
  const policies = Array.isArray(topology.policies) ? topology.policies : [];
  const companyPublishedFacts = number(topology.companyPublishedFacts);
  const flow = flowState(topology.sources);
  const graph = buildGraph({ ...topology, policies, pins });
  const routeSummary = routingSummary(topology.routing);

  const kindCounts = {
    policy: policies.length,
    backend: topology.sources.length,
    knowledge: topology.knowledgeBases.length + files.length,
    skill: topology.skills.length,
    retrieval: graph.nodes.filter((entry) => entry.kind === "retrieval").length,
    agent: topology.agents.length,
  };
  const stats = [
    `${fmt(graph.nodes.length)} ${plural(graph.nodes.length, "node", "nodes")}`,
    `${fmt(graph.edges.length)} ${plural(graph.edges.length, "link", "links")}`,
    `${fmt(topology.sources.length)} ${plural(topology.sources.length, "backend", "backends")}`,
    `${fmt(topology.skills.length)} ${plural(topology.skills.length, "skill", "skills")}`,
    `${fmt(topology.agents.length)} ${plural(topology.agents.length, "agent", "agents")}`,
  ].join(" · ");

  return `
    <section class="memory-graph" aria-label="Live memory network" aria-describedby="memory-topology-summary">
      <div class="memory-graph-head">
        <p class="memory-graph-stats">${esc(stats)}</p>
        <span class="pill ${flow.tone}"><i class="dot"></i>${flow.label}</span>
      </div>
      <p id="memory-topology-summary" class="sr-only">${esc(
        `Effective memory access includes ${fmt(companyPublishedFacts)} company-published ${plural(companyPublishedFacts, "item", "items")} and ${fmt(policies.length)} governed ${plural(policies.length, "policy guardrail", "policy guardrails")} delivered ahead of recall. Team topology connects ${fmt(topology.sources.length)} ${plural(topology.sources.length, "backend", "backends")} with ${fmt(backendDocumentCount)} associated ${plural(backendDocumentCount, "file", "files")}, plus ${fmt(topology.knowledgeBases.length)} separate knowledge ${plural(topology.knowledgeBases.length, "base", "bases")} containing ${fmt(files.length)} governed ${plural(files.length, "upload", "uploads")}. It also includes ${fmt(topology.skills.length)} ${plural(topology.skills.length, "skill", "skills")}, four memory lanes indexing ${fmt(topology.memories.length)} individual ${plural(topology.memories.length, "memory", "memories")} through a bounded visual sample, and ${fmt(topology.agents.length)} ${plural(topology.agents.length, "agent", "agents")}. Publishing-team systems and files stay hidden. Retrieval policy: ${routeSummary}.`,
      )}</p>

      <div class="memory-graph-shell">
        <div class="memory-graph-toolbar filter-strip filter-strip--scroll" aria-label="Graph filters">
          <span>Show</span>
          ${filter("policy", "Policies", policies.length)}
          ${filter("backend", "Backends", topology.sources.length)}
          ${filter("knowledge", "Knowledge bases", topology.knowledgeBases.length + files.length)}
          ${filter("skill", "Skills", topology.skills.length)}
          ${filter("retrieval", "RAG / cache", kindCounts.retrieval)}
          ${filter("agent", "Agents", topology.agents.length)}
        </div>

        <div class="memory-graph-layout">
          <div class="memory-graph-viewport" data-action="topo-clear" tabindex="0" aria-label="Interactive memory relationship graph" data-pointer-action="topo-pan" data-wheel-action="topo-zoom" data-zoom="1">
            <div class="memory-graph-grid" aria-hidden="true"></div>
            <div class="memory-graph-canvas" data-graph-canvas style="--zoom:1;--pan-x:0px;--pan-y:0px">
              ${renderClusters(esc, graph.clusters)}
              ${renderEdges(esc, graph.edges)}
              ${graph.nodes.map((node, index) => renderNode(esc, node, index)).join("")}
            </div>
            ${renderViewportControls()}
            <p class="memory-graph-hint" aria-hidden="true">drag to pan · scroll to zoom · click a node to inspect · drag a node to move it · press / to search</p>
          </div>

          <aside class="memory-graph-legend" aria-label="Graph legend and node details" aria-live="polite">
            ${renderGraphPanels(esc, graph, {
              policies: policies.length,
              sources: topology.sources.length,
              backendDocuments: backendDocumentCount,
              files: files.length,
              skills: topology.skills.length,
              agents: topology.agents.length,
              kinds: kindCounts,
            })}
          </aside>
        </div>
      </div>
    </section>`;
}

function buildGraph({ sources, memories, knowledgeBases, skills, agents, policies, pins, routing, activeFacts, activityFacts, companyPublishedFacts }) {
  const nodes = [];
  const edges = [];
  const clusters = [
    ...Object.values(CLUSTER_LAYOUTS).filter((layout) => !HALOLESS_GROUPS.has(layout.id)),
    ...Object.values(LANE_SECTIONS),
  ].map((layout) => cluster(layout));

  const hub = node("core:governed", "core", "hub", 50, 50, {
    label: "Governed memory",
    detail: "Halo Memory",
  });
  const groups = {
    policies: node("g:policies", "policy", "branch", CLUSTER_LAYOUTS.policies.x, CLUSTER_LAYOUTS.policies.y, {
      label: "Policies",
      detail: `${fmt(policies.length)} ${plural(policies.length, "guardrail", "guardrails")}`,
    }),
    backends: node("g:backends", "backend", "branch", CLUSTER_LAYOUTS.backends.x, CLUSTER_LAYOUTS.backends.y, { label: "Backends", detail: `${fmt(sources.length)} connected` }),
    knowledge: node("g:knowledge", "knowledge", "branch", CLUSTER_LAYOUTS.knowledge.x, CLUSTER_LAYOUTS.knowledge.y, { label: "Knowledge base", detail: `${fmt(knowledgeBases.length)} ${plural(knowledgeBases.length, "base", "bases")}` }),
    skills: node("g:skills", "skill", "branch", CLUSTER_LAYOUTS.skills.x, CLUSTER_LAYOUTS.skills.y, { label: "Skills", detail: `${fmt(skills.length)} connected` }),
    rag: node("g:rag", "retrieval", "branch", CLUSTER_LAYOUTS.rag.x, CLUSTER_LAYOUTS.rag.y, { label: "RAG / cache", detail: "L0-L3 lanes" }),
    agents: node("g:agents", "agent", "branch", CLUSTER_LAYOUTS.agents.x, CLUSTER_LAYOUTS.agents.y, { label: "All agents", detail: `${fmt(agents.length)} connected` }),
  };
  nodes.push(hub, ...Object.values(groups));
  edges.push(
    link(hub, groups.policies, "branch"),
    link(hub, groups.backends, "branch"),
    link(hub, groups.knowledge, "branch"),
    link(hub, groups.skills, "branch"),
    link(hub, groups.rag, "branch"),
    link(groups.rag, groups.agents, "branch"),
  );

  // Guardrails hang off the hub and feed the L0 context lane directly: a
  // governed policy is packed into every working set before recall, so the
  // graph draws that as its own edge rather than routing through retrieval.
  const policyNodes = policies.map((policy, index) => {
    const point = clusterPoint(index, policies.length, CLUSTER_LAYOUTS.policies);
    return node(`p:${string(policy.id)}`, "policy", "policy", point.x, point.y, {
      policy,
      parentId: groups.policies.id,
      clusterId: groups.policies.id,
    });
  });
  nodes.push(...policyNodes);
  for (const policyNode of policyNodes) edges.push(link(groups.policies, policyNode, "branch"));

  const sourceNodes = sources.map((source, index) => {
    const point = clusterPoint(index, sources.length, CLUSTER_LAYOUTS.backends);
    return node(`b:${string(source.id)}`, "backend", "source", point.x, point.y, {
      source,
      parentId: groups.backends.id,
      clusterId: groups.backends.id,
      pinned: sources.length > MAX_VISIBLE_CHILDREN,
    });
  });
  nodes.push(...sourceNodes);
  for (const sourceNode of sourceNodes) edges.push(link(groups.backends, sourceNode, "branch"));

  // Connector documents stay with their backend. They are deliberately not
  // drawn in the knowledge-base branch: uploads/folders/sites have their own
  // authoritative knowledge-base hierarchy below and their internal source
  // rows never reach `sources` from the read model.
  const backendDocumentNodes = [];
  const backendDocumentRollups = [];
  for (const sourceNode of sourceNodes) {
    const documents = sourceDocuments(sourceNode.source);
    const total = sourceDocumentCount(sourceNode.source);
    const itemCount = documents.length + (total > documents.length ? 1 : 0);
    documents.forEach((document, index) => {
      const point = clusterPoint(index, itemCount, {
        x: unscale(sourceNode.x),
        y: unscale(sourceNode.y),
        radiusX: 5.8,
        radiusY: 5.8,
        phase: -0.9,
      });
      backendDocumentNodes.push(node(
        `bf:${string(sourceNode.source.id)}:${string(document.id)}`,
        "backend",
        "backend-file",
        point.x,
        point.y,
        {
          source: sourceNode.source,
          document,
          parentId: sourceNode.id,
          clusterId: sourceNode.id,
        },
      ));
    });
    if (total > documents.length) {
      const point = clusterPoint(documents.length, itemCount, {
        x: unscale(sourceNode.x),
        y: unscale(sourceNode.y),
        radiusX: 5.8,
        radiusY: 5.8,
        phase: -0.9,
      });
      backendDocumentRollups.push(node(
        `bf:rollup:${string(sourceNode.source.id)}`,
        "backend",
        "backend-file-rollup",
        point.x,
        point.y,
        {
          label: `${fmt(total - documents.length)} more ${plural(total - documents.length, "file", "files")}`,
          detail: `${fmt(total)} total in ${backendDisplayName(sourceNode.source.kind)}`,
          source: sourceNode.source,
          parentId: sourceNode.id,
          clusterId: sourceNode.id,
        },
      ));
    }
  }
  nodes.push(...backendDocumentNodes, ...backendDocumentRollups);
  clusters.push(...sourceNodes
    .filter((entry) => sourceDocumentCount(entry.source) > 0)
    .map((entry) => nestedCluster(entry.id, entry.kind, entry.x, entry.y, 7, 7)));
  for (const documentNode of [...backendDocumentNodes, ...backendDocumentRollups]) {
    const parent = sourceNodes.find((entry) => entry.id === documentNode.parentId);
    if (parent) edges.push(link(parent, documentNode, "branch"));
  }

  const baseNodes = knowledgeBases.map((base, index) => {
    const point = clusterPoint(index, knowledgeBases.length, CLUSTER_LAYOUTS.knowledge);
    return node(`kb:${string(base.id)}`, "knowledge", "knowledge-base", point.x, point.y, {
      base,
      parentId: groups.knowledge.id,
      clusterId: groups.knowledge.id,
    });
  });
  nodes.push(...baseNodes);
  for (const baseNode of baseNodes) edges.push(link(groups.knowledge, baseNode, "branch"));

  const baseById = new Map(baseNodes.map((entry) => [string(entry.base.id), entry]));
  const fileRecords = knowledgeBases.flatMap((base) => base.files.map((file, index) => ({
    base,
    file,
    index,
    count: base.files.length,
  })));
  const fileNodes = fileRecords.map(({ base, file, index, count }) => {
    const parent = baseById.get(string(base.id));
    const point = clusterPoint(index, count, {
      x: unscale(parent?.x ?? groups.knowledge.x),
      y: unscale(parent?.y ?? groups.knowledge.y),
      radiusX: 6.5,
      radiusY: 6.5,
      phase: -0.9,
    });
    return node(`f:${string(file.id)}`, "knowledge", "file", point.x, point.y, {
      base,
      file,
      parentId: `kb:${string(base.id)}`,
      clusterId: `kb:${string(base.id)}`,
    });
  });
  nodes.push(...fileNodes);
  clusters.push(...baseNodes
    .filter((entry) => entry.base.files.length > 0)
    .map((entry) => nestedCluster(entry.id, entry.kind, entry.x, entry.y, 7.8, 7.8)));
  for (const fileNode of fileNodes) {
    const parent = baseById.get(string(fileNode.base.id));
    if (parent) edges.push(link(parent, fileNode, "branch"));
  }

  const skillNodes = skills.map((skill, index) => {
    const point = clusterPoint(index, skills.length, CLUSTER_LAYOUTS.skills);
    return node(`s:${string(skill.id)}`, "skill", "skill", point.x, point.y, {
      skill,
      parentId: groups.skills.id,
      clusterId: groups.skills.id,
      pinned: skills.length > MAX_VISIBLE_CHILDREN,
    });
  });
  nodes.push(...skillNodes);
  for (const skillNode of skillNodes) edges.push(link(groups.skills, skillNode, "branch"));

  const tierSpecs = [
    { tier: "L0", label: "Context", detail: "Per-call working set" },
    { tier: "L1", label: "Prompt cache", detail: "Provider-managed" },
    { tier: "L2", label: "Warm memory", detail: `${fmt(activeFacts)} active facts` },
    { tier: "L3", label: "Cold knowledge", detail: "Git-governed" },
  ];
  // Each lane is its own section, laid out like backends or skills: the lane
  // node sits at the heart of its bubble and its records ring around it. The
  // lane is pinned so the bubble keeps its shape — the ring is measured from
  // this point, and a lane that drifted would carry its records with it.
  const tierNodes = tierSpecs.map((spec) => {
    const section = LANE_SECTIONS[spec.tier];
    return node(`t:${spec.tier}`, "retrieval", "tier", section.x, section.y, {
      ...spec,
      clusterId: section.id,
      pinned: true,
    });
  });
  nodes.push(...tierNodes);
  for (const tierNode of tierNodes) edges.push(link(groups.rag, tierNode, "branch"));

  const tierByName = new Map(tierNodes.map((entry) => [entry.tier, entry]));
  const contextTier = tierByName.get("L0");
  if (contextTier && policyNodes.length > 0) {
    edges.push(link(groups.policies, contextTier, "flow"));
  }
  // Summaries hang off the OUTER side of their lane — the side away from the
  // junction. Anchored inboard they read as feeding back toward the hub, which
  // is the reverse of what the flow does.
  const commonMemory = node("mem:common", "retrieval", "common-memory", 98, 58, {
    label: "Common memories",
    detail: `${fmt(activeFacts)} active, ${fmt(activityFacts)} used`,
    tier: "L2",
  });
  nodes.push(commonMemory);
  const warmTier = tierByName.get("L2");
  if (warmTier) edges.push(link(warmTier, commonMemory, "flow"));

  if (number(companyPublishedFacts) > 0) {
    const companyMemory = node("mem:company-published", "retrieval", "company-memory", 98, 26, {
      label: "Company-published",
      detail: `${fmt(companyPublishedFacts)} ${plural(companyPublishedFacts, "shared item", "shared items")}`,
      tier: "L2",
    });
    nodes.push(companyMemory);
    if (warmTier) edges.push(link(warmTier, companyMemory, "flow"));
  }

  const coldTier = tierByName.get("L3");
  if (coldTier && pins.length > 0) {
    const pinned = node("mem:pinned", "retrieval", "pin-summary", 72, 94, {
      label: "Pinned knowledge",
      detail: `${fmt(pins.length)} ${plural(pins.length, "pinned ref", "pinned refs")}`,
      tier: "L3",
    });
    nodes.push(pinned);
    edges.push(link(coldTier, pinned, "flow"));
  }

  // Records ring their own lane. The read model already orders them
  // current-first / most-recalled first, so a bounded representative set is
  // enough for the canvas. Rendering hundreds of buttons, tooltips, and SVG
  // paths makes every pan/focus interaction pay for the full corpus. The
  // remainder is represented by one roll-up node while the authoritative
  // count and paginated Saved Memories stay complete.
  const memoriesByTier = new Map();
  for (const memory of memories) {
    const list = memoriesByTier.get(memory.tier) || [];
    list.push(memory);
    memoriesByTier.set(memory.tier, list);
  }
  const memoryNodes = [];
  const memoryRollups = [];
  for (const tierName of MEMORY_TIER_ORDER) {
    const list = memoriesByTier.get(tierName);
    const parent = tierByName.get(tierName);
    if (!list || !parent) continue;
    const renderedMemories = list.slice(0, MAX_RENDERED_MEMORIES_PER_TIER);
    const remaining = list.length - renderedMemories.length;
    const ring = memoryRings(renderedMemories.length + (remaining > 0 ? 1 : 0), LANE_SECTIONS[tierName]);
    renderedMemories.forEach((memory, index) => {
      const point = ring(index);
      memoryNodes.push(node(`m:${string(memory.id)}`, "retrieval", "memory", point.x, point.y, {
        memory,
        tier: memory.tier,
        parentId: parent.id,
        clusterId: LANE_SECTIONS[tierName].id,
        // Pinned: a record sits where its rank puts it, and the relaxation
        // pass leaves it there. Thirty-six satellites relaxed against each
        // other is the cloud these rings replaced.
        pinned: true,
      }));
    });
    if (remaining > 0) {
      const point = ring(renderedMemories.length);
      memoryRollups.push(node(`mem:rollup:${tierName}`, "retrieval", "memory-rollup", point.x, point.y, {
        label: `${fmt(remaining)} more ${plural(remaining, "memory", "memories")}`,
        detail: `${fmt(list.length)} total in ${tierName}`,
        remaining,
        tier: tierName,
        parentId: parent.id,
        clusterId: LANE_SECTIONS[tierName].id,
        pinned: true,
      }));
    }
  }
  nodes.push(...memoryNodes, ...memoryRollups);
  for (const memoryNode of [...memoryNodes, ...memoryRollups]) {
    const parent = tierByName.get(memoryNode.tier);
    // Its own relation, drawn fainter than a branch: one lane owning 36
    // records means 36 strokes leaving the same point, and at branch weight
    // they read as a solid wedge rather than as links.
    if (parent) edges.push(link(parent, memoryNode, "memory"));
  }

  const routes = routing.mode === "ab-test"
    ? [
        node("r:a", "retrieval", "route", 90, 72, { label: string(routing.a), lane: "A lane", share: 100 - percent(routing.pctB) }),
        node("r:b", "retrieval", "route", 94, 80, { label: string(routing.b), lane: "B lane", share: percent(routing.pctB) }),
      ]
    : [node("r:fixed", "retrieval", "route", 92, 76, { label: string(routing.name), lane: "Fixed retriever", share: 100 })];
  nodes.push(...routes);
  for (const route of routes) {
    edges.push(link(groups.rag, route, "flow"));
    edges.push(link(route, groups.agents, "flow"));
  }

  const agentNodes = agents.map((agent, index) => {
    const point = clusterPoint(index, agents.length, CLUSTER_LAYOUTS.agents);
    return node(`a:${string(agent.id)}`, "agent", "agent", point.x, point.y, {
      agent,
      parentId: groups.agents.id,
      clusterId: groups.agents.id,
    });
  });
  nodes.push(...agentNodes);
  for (const agentNode of agentNodes) edges.push(link(groups.agents, agentNode, "branch"));

  const sourceById = new Map(sourceNodes.map((entry) => [string(entry.source.id), entry]));
  for (const baseNode of baseNodes) {
    const source = sourceById.get(string(baseNode.base.sourceId));
    if (source) edges.push(link(source, baseNode, "source"));
  }
  for (const fileNode of fileNodes) {
    const source = sourceById.get(string(fileNode.file.sourceId));
    if (source) edges.push(link(source, fileNode, "provenance"));
  }
  const memoryNodeById = new Map(memoryNodes.map((entry) => [string(entry.memory.id), entry]));
  for (const memoryNode of memoryNodes) {
    for (const sourceId of memoryNode.memory.sourceIds) {
      const source = sourceById.get(string(sourceId));
      if (source) edges.push(link(source, memoryNode, "provenance"));
    }
    // Supersedence is an immutable relationship (D7): the newer fact points at
    // the version it closed, drawn only when both ends made the bounded sample.
    const prior = memoryNode.memory.supersedes
      ? memoryNodeById.get(string(memoryNode.memory.supersedes))
      : null;
    if (prior) edges.push(link(memoryNode, prior, "update"));
  }

  relaxLayout(nodes, edges);
  recomputeEdgeGeometry(nodes, edges);
  applyChildDisclosure(nodes, edges);
  return { nodes, edges, routes, clusters: fitClusters(clusters, nodes) };
}

// ---------------------------------------------------------------------------
// Layout relaxation.
//
// The authored cluster coordinates above decide WHERE a lane sits - backends
// left, agents lower right - and that composition is deliberate. What they
// cannot do is stop 34 satellites from stacking on the same ring. So the
// authored point becomes an anchor and a short deterministic relaxation pass
// (repel every pair, pull every edge to its rest length, hold each node near
// its anchor) settles the rest. No randomness anywhere: the same topology
// always renders the same picture.
// ---------------------------------------------------------------------------

const RELAX_ITERATIONS = 190;
// The authored plane is taller than it is wide in percentage units, so
// vertical gaps must be weighted or the graph relaxes into a flat band.
const GRAPH_UNIT_X = GRAPH_VIEW_WIDTH / 100;
const GRAPH_UNIT_Y = GRAPH_VIEW_HEIGHT / 100;
const Y_WEIGHT = GRAPH_UNIT_Y / GRAPH_UNIT_X;
const REST_LENGTH = { branch: 7.5, flow: 13, source: 16, provenance: 18, update: 12, memory: 24 };

function relaxLayout(nodes, edges) {
  // Pinned nodes hold their authored place but still push: the memory section
  // is drawn as a grid, and letting it relax would trade that legibility back
  // for the cloud it replaced. Repelling without moving is what keeps loose
  // nodes - the lane summaries especially - from drifting in among the grid.
  const active = nodes.filter((entry) => !entry.pinned);
  const movable = active.filter((entry) => entry.role !== "hub");
  if (movable.length < 2) return;
  for (const entry of active) {
    entry.anchorX = entry.x;
    entry.anchorY = entry.y;
  }

  const byId = new Map(active.map((entry) => [entry.id, entry]));
  const springs = edges
    .map((edge) => ({
      from: byId.get(edge.from),
      to: byId.get(edge.to),
      rest: REST_LENGTH[edge.relation] ?? 10,
    }))
    .filter((spring) => spring.from && spring.to);
  // Memory records already occupy authored concentric rings and never move.
  // Their lane and fitted halo reserve the section without per-record forces.
  const layoutNodes = nodes.filter((entry) => entry.role !== "memory");

  for (let step = 0; step < RELAX_ITERATIONS; step += 1) {
    const cooling = 1 - step / RELAX_ITERATIONS;
    const shifts = new Map(active.map((entry) => [entry.id, { dx: 0, dy: 0 }]));

    // Repulsion runs over the dynamic structural graph, not the record rings.
    for (let a = 0; a < layoutNodes.length; a += 1) {
      for (let b = a + 1; b < layoutNodes.length; b += 1) {
        const first = layoutNodes[a];
        const second = layoutNodes[b];
        if (first.pinned && second.pinned) continue;
        const dx = first.x - second.x;
        const dy = (first.y - second.y) * Y_WEIGHT;
        const distance = Math.max(0.35, Math.hypot(dx, dy));
        const sameCluster = first.clusterId && first.clusterId === second.clusterId;
        const strength = (sameCluster ? 9 : 12) / (distance * distance);
        const push = Math.min(3.2, strength) * cooling;
        const unitX = dx / distance;
        const unitY = dy / distance;
        const firstShift = shifts.get(first.id);
        const secondShift = shifts.get(second.id);
        if (firstShift) {
          firstShift.dx += unitX * push;
          firstShift.dy += unitY * push;
        }
        if (secondShift) {
          secondShift.dx -= unitX * push;
          secondShift.dy -= unitY * push;
        }
      }
    }

    // Springs along real edges.
    for (const spring of springs) {
      const dx = spring.to.x - spring.from.x;
      const dy = (spring.to.y - spring.from.y) * Y_WEIGHT;
      const distance = Math.max(0.35, Math.hypot(dx, dy));
      const pull = ((distance - spring.rest) * 0.035) * cooling;
      const unitX = (dx / distance) * pull;
      const unitY = (dy / distance) * pull;
      shifts.get(spring.from.id).dx += unitX;
      shifts.get(spring.from.id).dy += unitY;
      shifts.get(spring.to.id).dx -= unitX;
      shifts.get(spring.to.id).dy -= unitY;
    }

    for (const entry of movable) {
      const shift = shifts.get(entry.id);
      // The anchor is what keeps the composition: a node may breathe away
      // from its authored point, it may not migrate to another lane.
      const anchorPull = 0.06;
      const nextX = entry.x + shift.dx + (entry.anchorX - entry.x) * anchorPull;
      const nextY = entry.y + shift.dy / Y_WEIGHT + (entry.anchorY - entry.y) * anchorPull;
      entry.x = clamp(3, 97, nextX);
      entry.y = clamp(4, 96, nextY);
    }
  }

  for (const entry of nodes) {
    entry.x = Math.round(entry.x * 100) / 100;
    entry.y = Math.round(entry.y * 100) / 100;
    delete entry.anchorX;
    delete entry.anchorY;
  }
}

function recomputeEdgeGeometry(nodes, edges) {
  const byId = new Map(nodes.map((entry) => [entry.id, entry]));
  for (const edge of edges) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (!from || !to) continue;
    edge.x1 = from.x * GRAPH_UNIT_X;
    edge.y1 = from.y * GRAPH_UNIT_Y;
    edge.x2 = to.x * GRAPH_UNIT_X;
    edge.y2 = to.y * GRAPH_UNIT_Y;
  }
}

/** Redraw each lane's halo around where its members actually settled. */
function fitClusters(clusters, nodes) {
  const members = new Map();
  for (const entry of nodes) {
    if (!nonEmptyString(entry.clusterId)) continue;
    const list = members.get(entry.clusterId) || [];
    list.push(entry);
    members.set(entry.clusterId, list);
  }
  return clusters.map((entry) => {
    const list = members.get(entry.id) || [];
    if (list.length === 0) return entry;
    const xs = list.map((member) => member.x);
    const ys = list.map((member) => member.y);
    const padX = entry.nested ? 3.4 : 5;
    const padY = entry.nested ? 4.6 : 6.5;
    const minX = Math.min(...xs) - padX;
    const maxX = Math.max(...xs) + padX;
    const minY = Math.min(...ys) - padY;
    const maxY = Math.max(...ys) + padY;
    return {
      ...entry,
      x: (minX + maxX) / 2,
      y: (minY + maxY) / 2,
      width: maxX - minX,
      height: maxY - minY,
    };
  });
}

function node(id, kind, role, x, y, data = {}) {
  const scaledX = scale(x);
  const scaledY = scale(y);
  return {
    id,
    kind,
    role,
    x: clamp(2, 98, scaledX),
    y: clamp(3, 97, scaledY),
    ...data,
  };
}

/**
 * Concentric rings around the lane at the centre of its bubble — the same
 * read as a backend or skill lane, but authored rather than relaxed, so the
 * records stay evenly spaced however many there are.
 *
 * Ring k takes `RING_BASE * k` records at k/rings of the radius. Capacity
 * rising in step with radius is what keeps the gap along every ring the same:
 * twice around at twice the radius is twice the room.
 */
function memoryRings(count, layout) {
  const capacities = [];
  for (let remaining = count, ring = 1; remaining > 0; ring += 1) {
    const capacity = Math.min(remaining, RING_BASE * ring);
    capacities.push(capacity);
    remaining -= capacity;
  }
  const slots = capacities.flatMap((capacity, index) =>
    Array.from({ length: capacity }, (_, slot) => ({ ring: index + 1, slot, capacity })));
  return (index) => {
    const place = slots[index];
    if (!place) return { x: layout.x, y: layout.y };
    const fraction = place.ring / capacities.length;
    // Every other ring is offset half a step so the rings interleave instead
    // of lining records up in spokes.
    const stagger = place.ring % 2 === 0 ? Math.PI / place.capacity : 0;
    const angle = layout.phase + stagger + (TAU * place.slot) / place.capacity;
    return {
      x: layout.x + Math.cos(angle) * layout.radiusX * fraction,
      y: layout.y + Math.sin(angle) * layout.radiusY * fraction,
    };
  };
}

function clusterPoint(index, count, layout) {
  const visibleCount = Math.min(count, MAX_VISIBLE_CHILDREN);
  if (count > MAX_VISIBLE_CHILDREN && ["backend", "skill"].includes(layout.kind)) {
    return clusterGridPoint(index, count, layout);
  }
  if (index < visibleCount) {
    const angle = layout.phase + (TAU * index) / Math.max(visibleCount, 1);
    const radius = 0.78;
    return {
      x: layout.x + Math.cos(angle) * layout.radiusX * radius,
      y: layout.y + Math.sin(angle) * layout.radiusY * radius,
    };
  }

  const overflowIndex = index - visibleCount;
  const overflowCount = Math.max(1, count - visibleCount);
  const angle = overflowIndex * 2.3999632297 + layout.phase + Math.PI / 5;
  const radius = 0.38 + 0.62 * Math.sqrt((overflowIndex + 1) / overflowCount);
  return {
    x: layout.x + Math.cos(angle) * layout.radiusX * radius,
    y: layout.y + Math.sin(angle) * layout.radiusY * radius,
  };
}

/**
 * Overflow branches need label clearance, not another dense dot cloud. Lay
 * them out in centered rows so the five initially disclosed children remain
 * close to the parent while expansion reveals the remaining rows around
 * them. Backend labels are always visible, so that lane keeps two wide
 * columns; dot-first lanes can use three columns once they become large.
 */
function clusterGridPoint(index, count, layout) {
  const columns = layout.kind === "backend" ? 2 : count > 18 ? 3 : 2;
  const rows = Math.ceil(count / columns);
  const xExtent = layout.radiusX * 0.9;
  const yExtent = layout.radiusY * 0.9;
  const slots = [];
  for (let row = 0; row < rows; row += 1) {
    const y = rows === 1
      ? layout.y
      : layout.y - yExtent + (row * yExtent * 2) / (rows - 1);
    for (let column = 0; column < columns; column += 1) {
      if (slots.length >= count) break;
      const x = columns === 1
        ? layout.x
        : layout.x - xExtent + (column * xExtent * 2) / (columns - 1);
      slots.push({ x, y });
    }
  }
  slots.sort((first, second) => {
    const firstDistance = Math.abs(first.y - layout.y);
    const secondDistance = Math.abs(second.y - layout.y);
    if (firstDistance !== secondDistance) return firstDistance - secondDistance;
    if (first.y !== second.y) return first.y - second.y;
    return first.x - second.x;
  });
  return slots[index] || { x: layout.x, y: layout.y };
}

function cluster(layout) {
  return {
    id: layout.id,
    kind: layout.kind,
    x: scale(layout.x),
    y: scale(layout.y),
    width: layout.radiusX * 2 * GRAPH_SCALE,
    height: layout.radiusY * 2 * GRAPH_SCALE,
    nested: false,
  };
}

function nestedCluster(id, kind, x, y, radiusX, radiusY) {
  return {
    id,
    kind,
    x,
    y,
    width: radiusX * 2 * GRAPH_SCALE,
    height: radiusY * 2 * GRAPH_SCALE,
    nested: true,
  };
}

function scale(value) { return 50 + (value - 50) * GRAPH_SCALE; }
function unscale(value) { return 50 + (value - 50) / GRAPH_SCALE; }

function link(from, to, relation) {
  return {
    from: from.id,
    to: to.id,
    fromKind: from.kind,
    toKind: to.kind,
    relation,
    x1: from.x * GRAPH_UNIT_X,
    y1: from.y * GRAPH_UNIT_Y,
    x2: to.x * GRAPH_UNIT_X,
    y2: to.y * GRAPH_UNIT_Y,
  };
}

function applyChildDisclosure(nodes, edges) {
  const nodesById = new Map(nodes.map((entry) => [entry.id, entry]));
  const childrenByParent = new Map();
  for (const entry of nodes) {
    if (!nonEmptyString(entry.parentId)) continue;
    const children = childrenByParent.get(entry.parentId) || [];
    children.push(entry);
    childrenByParent.set(entry.parentId, children);
  }

  for (const [parentId, children] of childrenByParent) {
    const parent = nodesById.get(parentId);
    if (!parent) continue;
    // A connected backend is itself a branch. Its files should not spill into
    // the Backends overview just because the connector has only a few of
    // them; reveal those files only when that connector is explicitly opened.
    const visibleLimit = parent.role === "source" ? 0 : MAX_VISIBLE_CHILDREN;
    if (children.length <= visibleLimit) continue;
    parent.disclosure = {
      hiddenCount: children.length - visibleLimit,
      totalCount: children.length,
    };
    for (const child of children.slice(visibleLimit)) {
      addCollapseParent(child, parentId, childrenByParent);
    }
  }

  for (const edge of edges) {
    const collapseParents = new Set([
      ...(nodesById.get(edge.from)?.collapseParents || []),
      ...(nodesById.get(edge.to)?.collapseParents || []),
    ]);
    edge.collapseParents = Array.from(collapseParents);
  }
}

function addCollapseParent(entry, parentId, childrenByParent) {
  entry.collapseParents = Array.from(new Set([...(entry.collapseParents || []), parentId]));
  for (const child of childrenByParent.get(entry.id) || []) {
    addCollapseParent(child, parentId, childrenByParent);
  }
}

// Viewport controls. Every one of them is a pure client-side transform over
// the already-loaded graph - none of them refetches or widens the view.
function renderViewportControls() {
  const control = (action, label, glyph, extra = "") =>
    `<button type="button" class="memory-graph-control" data-action="${action}" aria-label="${label}"${extra}><span class="memory-graph-control-tip" aria-hidden="true">${label}</span><span aria-hidden="true">${glyph}</span></button>`;
  return `<div class="memory-graph-controls">
    ${control("topo-zoom-in", "Zoom in", "+")}
    ${control("topo-zoom-out", "Zoom out", "−")}
    ${control("topo-fit", "Fit to view", `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"></circle><path d="M12 3v2.4M12 18.6V21M3 12h2.4M18.6 12H21"></path></svg>`)}
    ${control("topo-fullscreen", "Full screen", `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"></path></svg>`, ' aria-pressed="false" data-expand-label="Full screen" data-collapse-label="Exit full screen"')}
  </div>`;
}

function renderClusters(esc, clusters) {
  return clusters.map((entry) => {
    const nestedClass = entry.nested ? " memory-graph-cluster--nested" : "";
    const style = `--cluster-x:${entry.x.toFixed(2)}%;--cluster-y:${entry.y.toFixed(2)}%;--cluster-w:${entry.width.toFixed(2)}%;--cluster-h:${entry.height.toFixed(2)}%`;
    return `<div class="memory-graph-cluster memory-graph-cluster--${entry.kind}${nestedClass}" data-cluster-id="${esc(entry.id)}" style="${style}" aria-hidden="true"></div>`;
  }).join("");
}

function renderEdges(esc, edges) {
  const paths = edges.map((entry, index) => {
    const d = topologyEdgePath(entry.x1, entry.y1, entry.x2, entry.y2);
    const collapseParents = entry.collapseParents || [];
    const collapsedClass = collapseParents.length ? " is-collapsed" : "";
    const collapseAttr = collapseParents.length
      ? ` data-collapse-parents="${esc(collapseParents.join(" "))}"`
      : "";
    const bendDirection = entry.x2 >= entry.x1 ? 1 : -1;
    const attrs = `data-from="${esc(entry.from)}" data-to="${esc(entry.to)}" data-from-kind="${entry.fromKind}" data-to-kind="${entry.toKind}" data-relation="${entry.relation}"${collapseAttr} data-x1="${round(entry.x1)}" data-y1="${round(entry.y1)}" data-x2="${round(entry.x2)}" data-y2="${round(entry.y2)}" data-bend-direction="${bendDirection}"`;
    const pulse = entry.relation === "flow"
      ? `<path class="memory-graph-edge memory-graph-edge--pulse memory-graph-edge--${entry.relation}${collapsedClass}" ${attrs} pathLength="100" style="--edge-delay:-${index % 9}s" d="${d}"></path>`
      : "";
    return `<path class="memory-graph-edge memory-graph-edge--${entry.relation}${collapsedClass}" ${attrs} d="${d}"></path>${pulse}`;
  }).join("");
  return `<svg class="memory-graph-links" aria-hidden="true" focusable="false" viewBox="0 0 ${GRAPH_VIEW_WIDTH} ${GRAPH_VIEW_HEIGHT}" preserveAspectRatio="none"><g>${paths}</g></svg>`;
}

export function topologyEdgePath(x1, y1, x2, y2, bendDirection) {
  const bend = Math.max(18, Math.abs(x2 - x1) * 0.16);
  const direction = bendDirection === -1 || bendDirection === 1
    ? bendDirection
    : x2 >= x1 ? 1 : -1;
  return `M${round(x1)} ${round(y1)} C${round(x1 + bend * direction)} ${round(y1)} ${round(x2 - bend * direction)} ${round(y2)} ${round(x2)} ${round(y2)}`;
}

function renderNode(esc, entry, index) {
  const position = `style="--x:${entry.x.toFixed(2)}%;--y:${entry.y.toFixed(2)}%;--node-delay:-${((index % 7) * 0.65).toFixed(2)}s"`;
  const tier = entry.tier ? ` data-tier="${esc(entry.tier)}"` : "";
  const presentation = nodePresentation(entry);
  const { label, detail } = presentation;
  let extra = "";
  if (entry.role === "source") {
    const state = sourceState(entry.source);
    extra = `<span class="memory-graph-source-state memory-graph-source-state--${state.tone}">${state.label}</span>`;
  } else if (entry.role === "policy") {
    if (entry.policy.inherited) {
      extra = `<span class="memory-graph-source-state memory-graph-source-state--idle">Inherited</span>`;
    }
  } else if (entry.role === "route") {
    extra = `<span class="memory-graph-share">${fmt(entry.share)}%</span>`;
  }
  const collapseParents = entry.collapseParents || [];
  const collapsedClass = collapseParents.length ? " is-collapsed" : "";
  const collapseAttr = collapseParents.length
    ? ` data-collapse-parents="${esc(collapseParents.join(" "))}"`
    : "";
  const clusterAttr = nonEmptyString(entry.clusterId)
    ? ` data-cluster-id="${esc(entry.clusterId)}"`
    : "";
  const disclosure = entry.disclosure;
  const hasDisclosure = disclosure && disclosure.hiddenCount > 0;
  const expandLabel = hasDisclosure
    ? `Expand ${label}. Show ${fmt(disclosure.hiddenCount)} more ${plural(disclosure.hiddenCount, "connection", "connections")}`
    : "";
  const collapseLabel = hasDisclosure
    ? `Collapse ${label}. Hide ${fmt(disclosure.hiddenCount)} ${plural(disclosure.hiddenCount, "connection", "connections")}`
    : "";
  const actionAttrs = hasDisclosure
    ? `data-action="topo-toggle" data-node-id="${esc(entry.id)}" aria-expanded="false" aria-label="${esc(expandLabel)}" data-expand-label="${esc(expandLabel)}" data-collapse-label="${esc(collapseLabel)}"`
    : `data-action="topo-focus" data-node-id="${esc(entry.id)}" aria-pressed="false" aria-label="${esc(label)}"`;
  const disclosureIcon = hasDisclosure
    ? `<span class="memory-graph-expand-icon" aria-hidden="true"></span>`
    : "";
  const tooltipId = `memory-graph-tooltip-${domId(entry.id)}`;
  const tooltipMeta = [detail, presentation.spaceLabel, presentation.updated.short]
    .filter(nonEmptyString)
    .join(" · ");
  const tooltipAlign = entry.x > 80 ? "end" : entry.x < 20 ? "start" : "center";
  const tooltipPlacement = entry.y < 20 ? "below" : "above";
  const tooltip = `<span id="${tooltipId}" class="memory-graph-tooltip" role="tooltip"><b>${esc(label)}</b><span>${esc(presentation.summary)}</span><small>${esc(tooltipMeta)}</small></span>`;
  const body = `<span class="memory-graph-dot" aria-hidden="true"></span><span class="memory-graph-node-copy"><b>${esc(label)}</b></span>${extra}${disclosureIcon}${tooltip}`;
  const expandableClass = hasDisclosure ? " memory-graph-node--expandable" : "";
  return `<div class="memory-graph-node memory-graph-node--${entry.role}${expandableClass}${collapsedClass}" data-kind="${entry.kind}"${tier} data-node-id="${esc(entry.id)}"${collapseAttr}${clusterAttr} ${position}><button type="button" class="memory-graph-node-hit" ${actionAttrs} aria-describedby="${tooltipId}" data-tooltip-align="${tooltipAlign}" data-tooltip-placement="${tooltipPlacement}" data-pointer-action="topo-drag">${body}</button></div>`;
}

function renderGraphPanels(esc, graph, counts) {
  const find = `<div class="memory-graph-find" data-graph-find>
    <label class="memory-graph-find-field">
      <span class="sr-only">Search the graph by name, space, or type</span>
      <input type="search" class="memory-graph-find-input" placeholder="Search nodes…" autocomplete="off" spellcheck="false" data-input-action="topo-search" data-hotkey="/">
      <kbd aria-hidden="true">/</kbd>
    </label>
    <ul class="memory-graph-find-results" data-find-results hidden></ul>
    <p class="memory-graph-find-status" data-find-status hidden role="status"></p>
  </div>`;
  const overview = `<div class="memory-graph-panel memory-graph-panel--overview" data-graph-panel="overview">
    <div class="memory-graph-panel-title">In this view</div>
    <ul class="memory-graph-statlist">
      ${stat("policy", counts.policies, "Active guardrails")}
      ${stat("backend", counts.sources, "Connected backends")}
      ${stat("backend", counts.backendDocuments, "Backend files")}
      ${stat("knowledge", counts.files, "Knowledge uploads")}
      ${stat("skill", counts.skills, "Connected skills")}
      ${stat("agent", counts.agents, "Connected agents")}
    </ul>
    <div class="memory-graph-key memory-graph-tier-key">
      <div class="memory-graph-panel-title">Memory lanes</div>
      ${lane("L0", "Context", "Packed into every agent call")}
      ${lane("L1", "Prompt cache", "Cached by the model provider")}
      ${lane("L2", "Warm memory", "Facts in active use")}
      ${lane("L3", "Cold knowledge", "Git-governed long-term store")}
      <p class="memory-graph-key-edge"><i class="memory-graph-key-line memory-graph-key-line--source" aria-hidden="true"></i>Connected source</p>
    </div>
  </div>`;
  const panelData = buildPanelData(graph);
  const details = `<section class="memory-graph-panel memory-graph-panel--details" data-graph-panel="details" hidden>
    <button type="button" class="memory-graph-panel-back" data-action="topo-panel-clear"><span aria-hidden="true">←</span> Graph overview</button>
    <div class="memory-graph-panel-heading"><span data-node-type></span><h3 data-node-title></h3><p data-node-detail></p></div>
    <p class="memory-graph-panel-summary" data-node-summary></p>
    <dl class="memory-graph-panel-meta">
      <div><dt>Space</dt><dd data-node-space></dd></div>
      <div><dt>Links</dt><dd data-node-degree></dd></div>
      <div><dt>Updated</dt><dd><time data-node-updated></time></dd></div>
    </dl>
    <div class="memory-graph-panel-links">
      <div class="memory-graph-panel-linkhead"><span>Feeds</span><b data-node-out-count></b></div>
      <ul class="memory-graph-linklist" data-node-outgoing></ul>
      <div class="memory-graph-panel-linkhead"><span>Fed by</span><b data-node-in-count></b></div>
      <ul class="memory-graph-linklist" data-node-incoming></ul>
      <p class="memory-graph-panel-empty" data-node-linkempty hidden>Not linked yet</p>
    </div>
    <div class="memory-graph-panel-connections"><div><span>Sub-nodes</span><b data-node-connections></b></div><ul class="memory-graph-children" data-node-children></ul><p class="memory-graph-panel-empty" data-node-empty hidden>No sub-nodes</p><p class="memory-graph-panel-more" data-node-more hidden></p></div>
  </section>`;
  return `${find}${overview}${details}<script type="application/json" data-graph-panel-data>${safeJson(panelData)}</script>`;
}

function buildPanelData(graph) {
  const childrenByParent = new Map();
  for (const entry of graph.nodes) {
    if (!nonEmptyString(entry.parentId)) continue;
    const children = childrenByParent.get(entry.parentId) || [];
    children.push(entry);
    childrenByParent.set(entry.parentId, children);
  }

  // Incoming/outgoing neighbours, resolved once so the inspector can list a
  // node's real links instead of only its nested children.
  const byId = new Map(graph.nodes.map((entry) => [entry.id, entry]));
  const outgoing = new Map();
  const incoming = new Map();
  for (const edge of graph.edges) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (!from || !to) continue;
    const out = outgoing.get(edge.from) || [];
    out.push({ id: to.id, kind: to.kind, relation: edge.relation, label: nodePresentation(to).label });
    outgoing.set(edge.from, out);
    const into = incoming.get(edge.to) || [];
    into.push({ id: from.id, kind: from.kind, relation: edge.relation, label: nodePresentation(from).label });
    incoming.set(edge.to, into);
  }

  return Object.fromEntries(graph.nodes.map((entry) => {
    const presentation = nodePresentation(entry);
    const children = childrenByParent.get(entry.id) || [];
    const visibleChildren = children.slice(0, MAX_VISIBLE_CHILDREN).map((child) => {
      const childPresentation = nodePresentation(child);
      return { label: childPresentation.label, type: childPresentation.type, kind: child.kind };
    });
    const out = outgoing.get(entry.id) || [];
    const into = incoming.get(entry.id) || [];
    return [entry.id, {
      label: presentation.label,
      type: presentation.type,
      kind: entry.kind,
      detail: presentation.detail,
      summary: presentation.summary,
      space: presentation.space,
      search: [presentation.label, presentation.type, presentation.spaceLabel].filter(nonEmptyString).join(" ").toLowerCase(),
      updated: presentation.updated,
      childCount: children.length,
      children: visibleChildren,
      remaining: children.length - visibleChildren.length,
      degree: { in: into.length, out: out.length },
      outgoing: out.slice(0, MAX_VISIBLE_LINKS),
      incoming: into.slice(0, MAX_VISIBLE_LINKS),
    }];
  }));
}

function safeJson(value) {
  return JSON.stringify(value)
    .replaceAll("&", "\\u0026")
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e");
}

// One short, literal line per node type. The inspector already shows the type,
// the space, the link counts, and the state badge - the summary only says what
// the thing is, in the words a non-engineer would use.
function nodePresentation(entry) {
  if (entry.role === "source") {
    const state = sourceState(entry.source);
    return presentation(entry, backendDisplayName(entry.source.kind), entry.source.namespace, "Backend", `${state.label} · ${fmt(sourceDocumentCount(entry.source))} ${plural(sourceDocumentCount(entry.source), "file", "files")}`, "A connected system and the files it syncs into this space.", entry.source.lastSync);
  }
  if (entry.role === "hub") return presentation(entry, entry.label, "All accessible spaces", "Memory hub", entry.detail, "Everything your agents can reach.");
  if (entry.role === "branch") {
    const summaries = {
      policy: "Rules applied before recall.",
      backend: "Systems that feed this space.",
      knowledge: "Governed files agents can read.",
      skill: "Approved actions agents can run.",
      retrieval: "How memory reaches an agent.",
      agent: "Agents connected to this space.",
    };
    return presentation(entry, entry.label, "All accessible spaces", "Group", entry.detail, summaries[entry.kind] || "A group of related items.");
  }
  if (entry.role === "policy") return presentation(entry, entry.policy.title, entry.policy.namespace, "Policy", `${title(entry.policy.enforcement)} · ${fmt(entry.policy.factCount)} ${plural(entry.policy.factCount, "directive", "directives")}`, "A guardrail packed in before recall.");
  if (entry.role === "knowledge-base") return presentation(entry, entry.base.name, entry.base.namespace, "Knowledge base", `${title(entry.base.kind)} · ${title(entry.base.status)}`, "A governed collection of files.");
  if (entry.role === "file") return presentation(entry, entry.file.name, entry.base.namespace, "File", `${fmt(entry.file.factCount)} ${plural(entry.file.factCount, "fact", "facts")} · ${title(entry.file.status)}`, `A file in ${entry.base.name}.`);
  if (entry.role === "backend-file") return presentation(entry, entry.document.name, entry.source.namespace, "Backend file", `Synced from ${backendDisplayName(entry.source.kind)}`, `A file associated with the ${backendDisplayName(entry.source.kind)} backend.`, entry.document.syncedAt);
  if (entry.role === "backend-file-rollup") return presentation(entry, entry.label, entry.source.namespace, "Backend files", entry.detail, "Additional files associated with this backend.");
  if (entry.role === "skill") {
    const score = entry.skill.safetyScore == null ? "Not scored" : `${fmt(entry.skill.safetyScore)} safety`;
    return presentation(entry, entry.skill.name, entry.skill.namespace, "Skill", `${title(entry.skill.vettingStatus)} · ${score}`, "An action agents are allowed to run.");
  }
  if (entry.role === "tier") {
    const summaries = {
      L0: "Packed into every agent call.",
      L1: "Cached by the model provider.",
      L2: "Facts in active use.",
      L3: "Git-governed long-term store.",
    };
    return presentation(entry, `${entry.tier} ${entry.label}`, "All accessible spaces", "Memory lane", entry.detail, summaries[entry.tier] || "A stage in the memory lifecycle.");
  }
  if (entry.role === "memory") {
    const memory = entry.memory;
    const label = nonEmptyString(memory.label) ? memory.label : title(memory.type) || "Memory";
    const detailParts = [
      title(memory.type) || "Memory",
      `${fmt(memory.accessCount)} ${plural(memory.accessCount, "recall", "recalls")}`,
    ];
    if (memory.state === "older") detailParts.push("Superseded");
    const summary = memory.state === "older"
      ? "An older version kept for history."
      : memory.tier === "L3"
        ? "A fact in the long-term store."
        : "A fact in active use.";
    return presentation(entry, label, memory.namespace, "Memory", detailParts.join(" · "), summary);
  }
  if (entry.role === "memory-rollup") return presentation(entry, entry.label, "All accessible spaces", "Memory group", entry.detail, "Additional memories available in Saved Memories.");
  if (entry.role === "common-memory") return presentation(entry, entry.label, "All accessible spaces", "Shared memory", entry.detail, "Facts shared across this space.");
  if (entry.role === "company-memory") return presentation(entry, entry.label, "All accessible spaces", "Published memory", entry.detail, "Published for the whole company.");
  if (entry.role === "pin-summary") return presentation(entry, entry.label, "All accessible spaces", "Pinned", entry.detail, "Kept in reach for every call.");
  if (entry.role === "route") return presentation(entry, entry.label, "All accessible spaces", "Retrieval route", `${entry.lane} · ${fmt(entry.share)}%`, "The engine that finds the matches.");
  return presentation(entry, entry.agent.actor, entry.agent.namespace, "Agent", entry.agent.namespace || "Organization root", "An agent using this space.");
}

function presentation(entry, label, space, type, detail, summary, updatedAt = null) {
  const updated = formatUpdated(updatedAt);
  return {
    id: entry.id,
    label,
    space: space || "Organization root",
    spaceLabel: spaceName(space),
    type,
    detail,
    summary,
    updated,
  };
}

function formatUpdated(value) {
  if (!nonEmptyString(value)) return { iso: null, short: "", long: "Not available" };
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return { iso: null, short: "", long: "Not available" };
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const label = `${months[date.getUTCMonth()]} ${date.getUTCDate()}, ${date.getUTCFullYear()}`;
  return { iso: value, short: `Updated ${label}`, long: label };
}

function spaceName(space) {
  if (!nonEmptyString(space)) return "Organization root";
  const segment = space.split("/").filter(Boolean).pop() || space;
  return `${title(segment.replace(/[-_]+/g, " "))} space`;
}

function domId(value) {
  const input = string(value);
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  const readable = input.replace(/[^a-zA-Z0-9_-]+/g, "-") || "node";
  return `${readable}-${(hash >>> 0).toString(36)}`;
}

function filter(kind, label, count) {
  return `<button type="button" class="memory-graph-filter" data-action="topo-filter" data-kind="${kind}" aria-pressed="true"><i class="memory-graph-filter-icon" aria-hidden="true">${KIND_GLYPHS[kind]}</i><span class="memory-graph-filter-label">${label}</span><span class="memory-graph-filter-count">${fmt(count)}</span></button>`;
}

/** One 14px line icon, drawn in the colour its owner already carries. */
function glyph(paths) {
  return `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}

// Legend iconography. The kinds match the graph's own colour key, so the panel
// reads as the same system as the canvas rather than a wall of numbers.
const KIND_GLYPHS = {
  policy: glyph('<path d="M12 3.2 5.4 5.9v5.4c0 3.9 2.7 7.2 6.6 8.2 3.9-1 6.6-4.3 6.6-8.2V5.9z"></path><path d="m9.4 12 1.9 1.9 3.4-3.6"></path>'),
  backend: glyph('<ellipse cx="12" cy="6.2" rx="6.4" ry="2.8"></ellipse><path d="M5.6 6.2v11.6c0 1.5 2.9 2.8 6.4 2.8s6.4-1.3 6.4-2.8V6.2"></path><path d="M5.6 12c0 1.6 2.9 2.8 6.4 2.8s6.4-1.2 6.4-2.8"></path>'),
  knowledge: glyph('<path d="M13.6 3.2H7.4a2 2 0 0 0-2 2v13.6a2 2 0 0 0 2 2h9.2a2 2 0 0 0 2-2V8.4z"></path><path d="M13.6 3.2v5.2h5"></path><path d="M8.8 13h6.4M8.8 16.4h4.4"></path>'),
  skill: glyph('<path d="M13.4 3.2 6.2 13.6h5.1l-1 7.2 7.5-10.6h-5z"></path>'),
  retrieval: glyph('<path d="m12 4 7.2 4-7.2 4-7.2-4z"></path><path d="m4.8 12 7.2 4 7.2-4M4.8 16l7.2 4 7.2-4"></path>'),
  agent: glyph('<rect x="4.2" y="8.4" width="15.6" height="11.4" rx="3.2"></rect><path d="M12 4v4.4"></path><circle cx="12" cy="3.4" r="1.1"></circle><path d="M9.4 13.6h.01M14.6 13.6h.01"></path>'),
};
const LANE_GLYPHS = {
  L0: glyph('<path d="M4 13.6h4.2l1.6 2.6h4.4l1.6-2.6H20"></path><path d="M6.4 4.4h11.2l2.4 9.2v4.4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-4.4z"></path>'),
  L1: glyph('<path d="M13.4 3.2 6.2 13.6h5.1l-1 7.2 7.5-10.6h-5z"></path>'),
  L2: glyph('<path d="m12 3.4 8.4 4.6-8.4 4.6-8.4-4.6z"></path><path d="m3.6 13.2 8.4 4.6 8.4-4.6"></path>'),
  L3: glyph('<rect x="3.6" y="4" width="16.8" height="4.2" rx="1.4"></rect><path d="M5.4 8.2v10a1.8 1.8 0 0 0 1.8 1.8h9.6a1.8 1.8 0 0 0 1.8-1.8v-10"></path><path d="M10.2 12h3.6"></path>'),
};

/** A legend count: kind icon, plain-language label, the number on the right. */
function stat(kind, count, label) {
  return `<li class="memory-graph-stat" data-kind="${kind}"><span class="memory-graph-stat-icon" aria-hidden="true">${KIND_GLYPHS[kind]}</span><span class="memory-graph-stat-label">${label}</span><b>${fmt(count)}</b></li>`;
}

/** One memory lane: tier-coloured icon, tier code, name, and what it means. */
function lane(tier, label, detail) {
  return `<p class="memory-graph-lane"><i data-tier="${tier}" aria-hidden="true">${LANE_GLYPHS[tier]}</i><b>${tier}</b><em>${label}</em><small>${detail}</small></p>`;
}

function routingSummary(routing) {
  return routing.mode === "ab-test"
    ? `${string(routing.a)} / ${string(routing.b)} - ${fmt(percent(routing.pctB))}% B`
    : `${string(routing.name)} - fixed`;
}

function sourceState(source) {
  if (source?.lifecycleState === "paused") return { label: "Paused", tone: "paused" };
  if (source?.lifecycleState === "disabled") return { label: "Disabled", tone: "disabled" };
  if (source?.syncStatus === "failed" || source?.lastSyncError) return { label: "Attention", tone: "bad" };
  if (source?.syncStatus === "pending") return { label: "Syncing", tone: "pending" };
  if (source?.syncStatus === "synced" || source?.lastSync) return { label: "Synced", tone: "ok" };
  return { label: "Registered", tone: "idle" };
}

function sourceDocuments(source) {
  return Array.isArray(source?.documents)
    ? source.documents.filter((document) =>
        document &&
        nonEmptyString(document.id) &&
        nonEmptyString(document.name) &&
        nonEmptyString(document.syncedAt))
    : [];
}

function sourceDocumentCount(source) {
  return Math.max(number(source?.documentCount), sourceDocuments(source).length);
}

function backendDisplayName(kind) {
  const value = string(kind);
  const friendly = {
    linear_direct: "Linear",
    notion: "Notion",
    notion_direct: "Notion",
    notion_catalogue: "Notion",
    notion_knowledge: "Notion",
  }[value];
  if (friendly) return friendly;
  return title(value.replace(/_(?:direct|catalogue|knowledge)$/, ""));
}

function flowState(sources) {
  const states = sources.map(sourceState);
  if (states.some((state) => ["bad", "disabled", "paused"].includes(state.tone))) return { label: "Source attention", tone: "pill--crit" };
  if (states.some((state) => state.tone === "ok")) return { label: "Flow online", tone: "pill--live" };
  if (states.some((state) => state.tone === "pending")) return { label: "Sources syncing", tone: "pill--warn" };
  return { label: sources.length ? "Sources configured" : "Waiting for source", tone: "pill--warn" };
}

function validTopology(topology) {
  if (!topology || topology.scope !== "selected-subtree") return false;
  if (!Array.isArray(topology.sources) || !topology.sources.every(validSource)) return false;
  if (!Array.isArray(topology.memories) || !topology.memories.every(validMemory)) return false;
  if (!Array.isArray(topology.knowledgeBases) || !topology.knowledgeBases.every(validKnowledgeBase)) return false;
  if (!Array.isArray(topology.skills) || !topology.skills.every(validSkill)) return false;
  if (!Array.isArray(topology.agents) || !topology.agents.every(validAgent)) return false;
  // Additive: a kernel that predates the guardrail lane omits `policies`
  // entirely, and the graph still renders every other lane.
  if (topology.policies !== undefined &&
      (!Array.isArray(topology.policies) || !topology.policies.every(validPolicy))) return false;
  if (!finiteNumber(topology.activeFacts) || !finiteNumber(topology.activityFacts)) return false;
  if (!finiteNumber(topology.companyPublishedFacts)) return false;
  const routing = topology.routing;
  if (!routing || (routing.mode !== "fixed" && routing.mode !== "ab-test")) return false;
  return routing.mode === "fixed"
    ? nonEmptyString(routing.name)
    : nonEmptyString(routing.a) && nonEmptyString(routing.b) && finiteNumber(routing.pctB) && routing.pctB <= 100;
}

function validSource(source) {
  return Boolean(source && typeof source === "object" && nonEmptyString(source.id) && typeof source.namespace === "string" && nonEmptyString(source.kind) && ["never_synced", "pending", "synced", "failed"].includes(source.syncStatus) && (source.lastSync === null || typeof source.lastSync === "string") && (source.lastSyncError === null || typeof source.lastSyncError === "string") && ["active", "paused", "disabled"].includes(source.lifecycleState));
}

function validMemory(memory) {
  return Boolean(memory && typeof memory === "object" && nonEmptyString(memory.id) && typeof memory.namespace === "string" && typeof memory.label === "string" && nonEmptyString(memory.type) && ["L2", "L3"].includes(memory.tier) && finiteNumber(memory.accessCount) && ["current", "older"].includes(memory.state) && (memory.supersedes === null || typeof memory.supersedes === "string") && Array.isArray(memory.sourceIds) && memory.sourceIds.every((id) => typeof id === "string"));
}

function validKnowledgeBase(base) {
  return Boolean(base && typeof base === "object" && nonEmptyString(base.id) && typeof base.namespace === "string" && nonEmptyString(base.name) && ["file", "folder", "url"].includes(base.kind) && nonEmptyString(base.status) && (base.sourceId === null || typeof base.sourceId === "string") && Array.isArray(base.files) && base.files.every(validFile));
}

function validFile(file) {
  return Boolean(file && typeof file === "object" && nonEmptyString(file.id) && nonEmptyString(file.sourceId) && nonEmptyString(file.name) && nonEmptyString(file.status) && finiteNumber(file.factCount));
}

function validSkill(skill) {
  return Boolean(skill && typeof skill === "object" && nonEmptyString(skill.id) && typeof skill.namespace === "string" && nonEmptyString(skill.key) && nonEmptyString(skill.name) && ["unvetted", "vetting", "vetted", "blocked"].includes(skill.vettingStatus) && (skill.safetyScore === null || (finiteNumber(skill.safetyScore) && skill.safetyScore <= 100)));
}

function validPolicy(policy) {
  return Boolean(policy && typeof policy === "object" && nonEmptyString(policy.id) && typeof policy.namespace === "string" && nonEmptyString(policy.title) && ["advisory", "required"].includes(policy.enforcement) && nonEmptyString(policy.status) && finiteNumber(policy.factCount) && typeof policy.inherited === "boolean");
}

function validAgent(agent) {
  return Boolean(agent && typeof agent === "object" && nonEmptyString(agent.id) && typeof agent.namespace === "string" && nonEmptyString(agent.actor));
}

function renderUnavailable() {
  return `<section class="memory-graph" aria-label="Live memory network"><div class="memory-graph-head"><span class="pill pill--warn"><i class="dot"></i>Topology unavailable</span></div><div class="memory-graph-shell memory-graph-unavailable" role="status"><span class="memory-graph-node-orb" aria-hidden="true"></span><div><h3>Topology unavailable</h3><p>Live relationships are temporarily unavailable.</p></div></div></section>`;
}

function clamp(min, max, value) { return Math.max(min, Math.min(max, value)); }
function round(value) { return Math.round(value * 10) / 10; }
function title(value) { return string(value).replace(/[_-]+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase()); }
function percent(value) { return Math.max(0, Math.min(100, Math.round(number(value)))); }
function string(value) { return value == null ? "" : String(value); }
function number(value) { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : 0; }
function finiteNumber(value) { return typeof value === "number" && Number.isFinite(value) && value >= 0; }
function nonEmptyString(value) { return typeof value === "string" && value.trim().length > 0; }
function plural(value, singular, many) { return number(value) === 1 ? singular : many; }
function fmt(value) { return number(value).toLocaleString("en-US"); }
