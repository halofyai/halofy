import { describe, expect, it } from "vitest";
import type { DataClassification } from "../src/types.js";
import {
  generateRelationshipCandidates,
  type RelationshipCandidateEntity,
} from "../src/relationships/candidates.js";

const internal: DataClassification = {
  sensitivity: "internal",
  piiSubjects: [],
  secretKinds: [],
  allowedDestinations: [],
};

function entity(
  entityId: string,
  overrides: Partial<RelationshipCandidateEntity> = {},
): RelationshipCandidateEntity {
  return {
    entityId,
    namespace: "acme",
    canonicalName: entityId,
    classification: internal,
    evidence: [{ memoryId: `mem-${entityId}`, sourceId: `source-${entityId}` }],
    ...overrides,
  };
}

describe("generateRelationshipCandidates", () => {
  it("deduplicates pairs and orders their deterministic signals by strength", () => {
    const left = entity("catalog-product", {
      canonicalName: "Trail Shoe",
      aliases: ["Trail Runner"],
      stableIds: ["gid://product/42"],
      skus: [" SKU-42 "],
      urls: ["https://shop.example/products/trail-shoe#details"],
      embedding: [1, 0],
      evidence: [{
        memoryId: "mem-catalog",
        sourceId: "shopify",
        documentKey: "products/42",
        contentHash: "hash-a",
        recordKeys: ["product:42"],
      }],
    });
    const right = entity("support-product", {
      canonicalName: "Trail Shoe",
      aliases: ["Trail Runner"],
      stableIds: ["GID://PRODUCT/42"],
      skus: ["sku-42"],
      urls: ["https://shop.example/products/trail-shoe"],
      embedding: [0.99, 0.01],
      evidence: [{
        memoryId: "mem-support",
        sourceId: "zendesk",
        documentKey: "tickets/7",
        contentHash: "hash-b",
        recordKeys: ["product:42"],
      }, {
        memoryId: "mem-catalog",
        sourceId: "zendesk",
      }],
    });

    const forward = generateRelationshipCandidates([left, right, left]);
    const reverse = generateRelationshipCandidates([right, left, right]);

    expect(forward).toEqual(reverse);
    expect(forward).toHaveLength(1);
    expect(forward[0]).toMatchObject({
      candidateId: expect.stringMatching(/^relcand_[0-9a-f]{24}$/),
      namespace: "acme",
      subjectEntityId: "catalog-product",
      subjectEntityName: "Trail Shoe",
      objectEntityId: "support-product",
      objectEntityName: "Trail Shoe",
      signals: [
        "shared_stable_id",
        "shared_sku",
        "shared_public_https_url",
        "shared_canonical_name",
        "cross_source_record_overlap",
        "shared_alias",
        "embedding_similarity",
        "entity_cooccurrence",
      ],
      classificationInputs: [
        { entityId: "catalog-product", classification: internal },
        { entityId: "support-product", classification: internal },
      ],
      classification: internal,
    });
    expect(forward[0]?.score).toBeGreaterThanOrEqual(0);
    expect(forward[0]?.score).toBeLessThanOrEqual(1);
    expect(forward[0]?.evidence).toEqual([
      {
        memoryId: "mem-catalog",
        sourceId: "shopify",
        documentKey: "products/42",
        contentHash: "hash-a",
      },
      { memoryId: "mem-catalog", sourceId: "zendesk" },
      {
        memoryId: "mem-support",
        sourceId: "zendesk",
        documentKey: "tickets/7",
        contentHash: "hash-b",
      },
    ]);
  });

  it("never creates a pair across namespaces", () => {
    const result = generateRelationshipCandidates([
      entity("acme-product", { stableIds: ["product-1"] }),
      entity("globex-product", { namespace: "globex", stableIds: ["product-1"] }),
    ]);

    expect(result).toEqual([]);
  });

  it("treats co-occurrence alone as weak", () => {
    const result = generateRelationshipCandidates([
      entity("order", { evidence: [{ memoryId: "mem-order", sourceId: "erp" }] }),
      entity("product", { evidence: [{ memoryId: "mem-order", sourceId: "erp" }] }),
    ]);

    expect(result).toHaveLength(1);
    expect(result[0]?.signals).toEqual(["entity_cooccurrence"]);
    expect(result[0]?.score).toBeLessThan(0.5);
  });

  it("requires public HTTPS URLs and ignores private, local, credentialed, and HTTP URLs", () => {
    const unsafeUrls = [
      "http://shop.example/products/1",
      "https://localhost/products/1",
      "https://127.0.0.1/products/1",
      "https://10.1.2.3/products/1",
      "https://user:secret@shop.example/products/1",
    ];
    const result = generateRelationshipCandidates([
      entity("one", { urls: unsafeUrls }),
      entity("two", { urls: unsafeUrls }),
    ]);

    expect(result).toEqual([]);
  });

  it("requires different sources for cross-source record overlap", () => {
    const sameSource = generateRelationshipCandidates([
      entity("one", {
        evidence: [{ memoryId: "mem-1", sourceId: "crm", recordKeys: ["customer:7"] }],
      }),
      entity("two", {
        evidence: [{ memoryId: "mem-2", sourceId: "crm", recordKeys: ["customer:7"] }],
      }),
    ]);
    const differentSources = generateRelationshipCandidates([
      entity("one", {
        evidence: [{ memoryId: "mem-1", sourceId: "crm", recordKeys: ["customer:7"] }],
      }),
      entity("two", {
        evidence: [{ memoryId: "mem-2", sourceId: "billing", recordKeys: ["customer:7"] }],
      }),
    ]);

    expect(sameSource).toEqual([]);
    expect(differentSources[0]?.signals).toEqual(["cross_source_record_overlap"]);
  });

  it("does not emit candidates without governed memory evidence", () => {
    const result = generateRelationshipCandidates([
      entity("one", { stableIds: ["shared"], evidence: [] }),
      entity("two", { stableIds: ["shared"] }),
    ]);

    expect(result).toEqual([]);
  });

  it("caps entity scans, output pairs, per-entity evidence, and output evidence", () => {
    const entities = Array.from({ length: 12 }, (_, index) => entity(`entity-${index}`, {
      stableIds: ["shared"],
      evidence: Array.from({ length: 12 }, (__, evidenceIndex) => ({
        memoryId: `mem-${index}-${evidenceIndex}`,
        sourceId: `source-${index}`,
      })),
    }));

    const result = generateRelationshipCandidates(entities, {
      maxEntities: 5,
      maxPairs: 3,
      maxEvidencePerEntity: 4,
      maxEvidencePerCandidate: 5,
    });

    expect(result).toHaveLength(3);
    expect(result.every((candidate) => candidate.evidence.length <= 5)).toBe(true);
    expect(result.every((candidate) => {
      const ids = [candidate.subjectEntityId, candidate.objectEntityId];
      return ids.every((id) => ["entity-0", "entity-1", "entity-10", "entity-11", "entity-2"].includes(id));
    })).toBe(true);
  });
});
