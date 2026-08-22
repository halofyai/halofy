import { describe, expect, it, vi } from "vitest";
import type { LlmClient } from "../src/types.js";
import type {
  RelationshipCandidate,
  RelationshipCandidateEntity,
} from "../src/relationships/candidates.js";
import type { RelationshipClassificationResult } from "../src/relationships/classifier.js";
import { RelationshipStoreError } from "../src/relationships/store.js";
import {
  RELATIONSHIP_PIPELINE_LIMITS,
  runRelationshipPipeline,
  type RelationshipPipelineDependencies,
} from "../src/relationships/pipeline.js";

const llm: LlmClient = {
  name: "pipeline-test",
  complete: async () => "unused",
};

function entity(
  entityId: string,
  overrides: Partial<RelationshipCandidateEntity> = {},
): RelationshipCandidateEntity {
  return {
    entityId,
    namespace: "acme",
    canonicalName: entityId,
    skus: ["sku-42"],
    evidence: [{ memoryId: `memory-${entityId}`, sourceId: `source-${entityId}` }],
    ...overrides,
  };
}

function candidate(overrides: Partial<RelationshipCandidate> = {}): RelationshipCandidate {
  return {
    candidateId: "candidate-safe-1",
    namespace: "acme",
    subjectEntityId: "entity-a",
    subjectEntityName: "Entity A",
    objectEntityId: "entity-b",
    objectEntityName: "Entity B",
    signals: ["shared_sku"],
    evidence: [{ memoryId: "memory-entity-a" }, { memoryId: "memory-entity-b" }],
    score: 0.97,
    classification: null,
    classificationInputs: [
      { entityId: "entity-a", classification: null },
      { entityId: "entity-b", classification: null },
    ],
    ...overrides,
  };
}

function accepted(
  overrides: Partial<Extract<RelationshipClassificationResult, { status: "accepted" }>> = {},
): Extract<RelationshipClassificationResult, { status: "accepted" }> {
  return {
    status: "accepted",
    subjectEntityId: "entity-a",
    objectEntityId: "entity-b",
    relationship: "uses",
    confidence: 0.88,
    evidenceMemoryIds: ["memory-entity-a", "memory-entity-b"],
    ...overrides,
  };
}

function input(overrides: Record<string, unknown> = {}) {
  return {
    namespace: "acme",
    actor: "relationship-worker",
    impactedMemoryIds: ["memory-entity-a", "memory-entity-b"],
    entities: [entity("entity-a"), entity("entity-b")],
    ...overrides,
  };
}

function dependencies(
  overrides: Partial<RelationshipPipelineDependencies> = {},
): RelationshipPipelineDependencies {
  return {
    llm,
    classify: vi.fn(async () => accepted()),
    store: {
      commit: vi.fn(async (_context, classification) => ({
        relationship: {
          id: "relationship-1",
          namespace: "acme",
          subjectEntityId: classification.subjectEntityId,
          relationship: classification.relationship,
          objectEntityId: classification.objectEntityId,
          confidence: classification.confidence,
          evidence: classification.evidenceMemoryIds.map((memoryId) => ({ memoryId })),
          assertionTime: "2026-07-21T10:00:00.000Z",
          eventTime: null,
          tValidFrom: "2026-07-21T10:00:00.000Z",
          tValidTo: null,
          supersedes: null,
          status: "active",
          createdBy: "relationship-worker",
        },
        deduplicated: false,
      })),
    },
    ...overrides,
  };
}

describe("runRelationshipPipeline", () => {
  it("generates candidates, classifies them, and commits with server-resolved context", async () => {
    const deps = dependencies();

    const result = await runRelationshipPipeline(input(), deps);

    expect(result).toEqual({
      namespace: "acme",
      status: "complete",
      candidateCount: 1,
      attempted: 1,
      committed: 1,
      deduplicated: 0,
      rejected: 0,
      pending: 0,
      truncated: false,
      pipelineError: null,
      outcomes: [{
        candidateId: expect.stringMatching(/^relcand_[0-9a-f]{24}$/),
        status: "committed",
        relationshipId: "relationship-1",
        deduplicated: false,
      }],
    });
    expect(deps.store.commit).toHaveBeenCalledWith(
      { namespace: "acme", actor: "relationship-worker" },
      accepted(),
      undefined,
    );
  });

  it("rejects mixed namespaces and evidence outside the server-resolved impacted set", async () => {
    const deps = dependencies();
    const mixedNamespace = input({
      entities: [entity("entity-a"), entity("entity-b", { namespace: "globex" })],
    });
    const foreignEvidence = input({
      entities: [
        entity("entity-a"),
        entity("entity-b", { evidence: [{ memoryId: "memory-admin" }] }),
      ],
    });

    await expect(runRelationshipPipeline(mixedNamespace, deps)).resolves.toMatchObject({
      status: "invalid",
      pipelineError: "invalid_input",
      outcomes: [],
    });
    await expect(runRelationshipPipeline(foreignEvidence, deps)).resolves.toMatchObject({
      status: "invalid",
      pipelineError: "invalid_input",
      outcomes: [],
    });
    expect(deps.classify).not.toHaveBeenCalled();
    expect(deps.store.commit).not.toHaveBeenCalled();
  });

  it.each([
    ["entity authority", accepted({ subjectEntityId: "entity-admin" })],
    ["object authority", accepted({ objectEntityId: "entity-admin" })],
    ["evidence authority", accepted({ evidenceMemoryIds: ["memory-admin"] })],
  ])("does not accept model-supplied %s", async (_label, classification) => {
    const commit = vi.fn();
    const result = await runRelationshipPipeline(input(), dependencies({
      generateCandidates: () => [candidate()],
      classify: async () => classification,
      store: { commit },
    }));

    expect(result).toMatchObject({
      status: "brownout",
      committed: 0,
      pending: 1,
      outcomes: [{
        candidateId: "candidate-safe-1",
        status: "pending",
        code: "invalid_classifier_result",
      }],
    });
    expect(commit).not.toHaveBeenCalled();
  });

  it.each([
    ["unknown reason", { status: "rejected", reason: "SECRET source content" }],
    ["malformed acceptance", {
      status: "accepted",
      subjectEntityId: "entity-a",
      objectEntityId: "entity-b",
      relationship: "uses",
      confidence: 0.9,
    }],
  ])("browns out content-free for a classifier %s", async (_label, hostile) => {
    const result = await runRelationshipPipeline(input(), dependencies({
      generateCandidates: () => [candidate()],
      classify: async () => hostile as RelationshipClassificationResult,
    }));

    expect(result.outcomes).toEqual([{
      candidateId: "candidate-safe-1",
      status: "pending",
      code: "invalid_classifier_result",
    }]);
    expect(JSON.stringify(result)).not.toContain("SECRET");
  });

  it("returns content-free per-candidate brownouts and continues after classifier and store failures", async () => {
    const candidates = [
      candidate({ candidateId: "candidate-1" }),
      candidate({ candidateId: "candidate-2" }),
      candidate({ candidateId: "candidate-3" }),
    ];
    let classifyCall = 0;
    const storeCommit = vi.fn(async () => {
      throw new RelationshipStoreError(
        "storage_unavailable",
        "SECRET database host and source content",
        true,
      );
    });
    const result = await runRelationshipPipeline(input(), dependencies({
      generateCandidates: () => candidates,
      classify: async () => {
        classifyCall += 1;
        if (classifyCall === 1) throw new Error("SECRET model response and prompt");
        if (classifyCall === 2) return { status: "pending", reason: "llm_unavailable" };
        return accepted();
      },
      store: { commit: storeCommit },
    }));

    expect(result).toMatchObject({
      status: "brownout",
      candidateCount: 3,
      attempted: 3,
      committed: 0,
      pending: 3,
      outcomes: [
        { candidateId: "candidate-1", status: "pending", code: "classifier_unavailable" },
        { candidateId: "candidate-2", status: "pending", code: "llm_unavailable" },
        { candidateId: "candidate-3", status: "pending", code: "store_storage_unavailable" },
      ],
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("SECRET");
    expect(serialized).not.toContain("source content");
    expect(storeCommit).toHaveBeenCalledOnce();
  });

  it("bounds entity, impacted-memory, candidate, and output work", async () => {
    const generateCandidates = vi.fn((_entities: readonly RelationshipCandidateEntity[]) =>
      Array.from({ length: 5 }, (_, index) => candidate({
        candidateId: `candidate-${index}`,
        subjectEntityId: "entity-0",
        objectEntityId: "entity-1",
        evidence: [{ memoryId: "memory-0" }, { memoryId: "memory-1" }],
      })),
    );
    const classify = vi.fn(async () => ({ status: "rejected", reason: "model_rejected" } as const));
    const entities = Array.from({ length: 5 }, (_, index) => entity(`entity-${index}`, {
      evidence: [{ memoryId: `memory-${index}` }],
    }));

    const result = await runRelationshipPipeline({
      namespace: "acme",
      actor: "worker",
      impactedMemoryIds: Array.from({ length: 5 }, (_, index) => `memory-${index}`),
      entities,
    }, dependencies({ generateCandidates, classify }), {
      maxEntities: 2,
      maxImpactedMemoryIds: 2,
      maxCandidates: 2,
    });

    expect(generateCandidates).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ entityId: "entity-0" }),
        expect.objectContaining({ entityId: "entity-1" }),
      ]),
      expect.objectContaining({ maxEntities: 2, maxPairs: 2 }),
    );
    expect(generateCandidates.mock.calls[0]?.[0]).toHaveLength(2);
    expect(classify).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({
      candidateCount: 2,
      attempted: 2,
      rejected: 2,
      truncated: true,
    });
    expect(result.outcomes).toHaveLength(2);
  });

  it("browns out candidate generation without throwing or returning exception content", async () => {
    const result = await runRelationshipPipeline(input(), dependencies({
      generateCandidates: () => { throw new Error("SECRET candidate payload"); },
    }));

    expect(result).toMatchObject({
      namespace: "acme",
      status: "brownout",
      pipelineError: "candidate_generation_failed",
      committed: 0,
      outcomes: [],
    });
    expect(JSON.stringify(result)).not.toContain("SECRET");
  });

  it("exposes fixed hard safety ceilings", () => {
    expect(RELATIONSHIP_PIPELINE_LIMITS).toEqual({
      maxEntities: 256,
      maxImpactedMemoryIds: 512,
      maxCandidates: 128,
    });
  });
});
