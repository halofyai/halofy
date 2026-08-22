import { describe, expect, it } from "vitest";
import type { WriteRequest, WriteResult } from "../src/types.js";
import {
  ClassificationDeniedError,
  classifyData,
  destinationAllowed,
} from "../src/dlp/index.js";
import { makeIngestSink } from "../src/ingest/sink.js";
import { IngestValidationError } from "../src/ingest/validation.js";

const emptyWrite = (): WriteResult => ({
  stored: [],
  rejected: [],
  superseded: [],
  deduplicated: 0,
});

describe("M7 deterministic pre-write DLP", () => {
  it("detects secrets and common PII without retaining matched values", () => {
    const classification = classifyData(
      "Email alice@example.com, SSN 123-45-6789, token sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    );

    expect(classification.sensitivity).toBe("restricted");
    expect(classification.piiSubjects).toEqual(["email", "us-ssn"]);
    expect(classification.secretKinds).toEqual(["openai-api-key"]);
    expect(JSON.stringify(classification)).not.toContain("alice@example.com");
    expect(JSON.stringify(classification)).not.toContain("123-45-6789");
    expect(JSON.stringify(classification)).not.toContain("sk-proj-");
  });

  it("allows restricted data only at an explicitly approved destination", () => {
    const classification = classifyData("AWS key AKIAABCDEFGHIJKLMNOP", {
      allowedDestinations: ["canonical-l2"],
      residency: "eu",
    });

    expect(destinationAllowed(classification, "canonical-l2", { region: "eu" })).toBe(true);
    expect(destinationAllowed(classification, "warm:mem0", { region: "eu" })).toBe(false);
    expect(destinationAllowed(classification, "canonical-l2", { region: "us" })).toBe(false);
  });

  it("fails closed before writeRecord for a detected secret without an explicit policy", async () => {
    const requests: WriteRequest[] = [];
    const sink = makeIngestSink({
      namespace: "acme",
      sourceId: "slack:security",
      sourceKind: "slack",
      writeRecord: async (req) => {
        requests.push(req);
        return emptyWrite();
      },
    });

    await expect(
      sink.write({ docId: "secret", content: "private key: -----BEGIN PRIVATE KEY-----" }),
    ).rejects.toBeInstanceOf(ClassificationDeniedError);
    expect(requests).toEqual([]);
  });

  it("reports a downstream write-path classification denial with its actual destination", async () => {
    const denied: Array<{ sensitivity: string; destination: string }> = [];
    const sink = makeIngestSink({
      namespace: "acme",
      sourceId: "policy:legal",
      sourceKind: "policy-upload",
      destinationPolicy: {
        canonicalDestination: "canonical-l2",
        allowedRestrictedDestinations: ["canonical-l2"],
      },
      onClassificationDenied: async (detail) => {
        denied.push(detail);
      },
      writeRecord: async (request) => {
        throw new ClassificationDeniedError(
          request.provenance!.classification!,
          "llm-extraction",
          "explicit approval required",
        );
      },
    });

    await expect(sink.write({
      docId: "legal.md",
      content: "Contact legal@example.com before disclosure.",
    })).rejects.toMatchObject({
      name: "ClassificationDeniedError",
      destination: "llm-extraction",
    });
    expect(denied).toEqual([{
      sensitivity: "confidential",
      destination: "llm-extraction",
    }]);
  });

  it("preserves source ACL and authoritative classification in write provenance", async () => {
    const requests: WriteRequest[] = [];
    const sink = makeIngestSink({
      namespace: "acme",
      sourceId: "notion:legal",
      sourceKind: "notion",
      destinationPolicy: {
        canonicalDestination: "canonical-l2",
        allowedRestrictedDestinations: ["canonical-l2"],
        region: "eu",
      },
      writeRecord: async (req) => {
        requests.push(req);
        return emptyWrite();
      },
    });

    await sink.write({
      docId: "page-1",
      content: "Contact legal@example.com",
      sourceAccess: {
        principals: ["user:42"],
        groups: ["legal"],
        inheritedFrom: "space:legal",
      },
      classification: {
        sensitivity: "restricted",
        residency: "eu",
        allowedDestinations: ["canonical-l2"],
      },
    });

    expect(requests[0]?.provenance?.sourceAccess).toEqual({
      principals: ["user:42"],
      groups: ["legal"],
      inheritedFrom: "space:legal",
    });
    expect(requests[0]?.provenance?.classification).toMatchObject({
      sensitivity: "restricted",
      piiSubjects: ["email"],
      secretKinds: [],
      residency: "eu",
      allowedDestinations: ["canonical-l2"],
    });
  });

  it("rejects malformed or oversized source ACL data before persistence", async () => {
    let writes = 0;
    const sink = makeIngestSink({
      namespace: "acme",
      sourceId: "source",
      sourceKind: "notion",
      writeRecord: async () => {
        writes += 1;
        return emptyWrite();
      },
    });

    await expect(sink.write({
      docId: "page-1",
      content: "safe",
      sourceAccess: { principals: ["x".repeat(300)], groups: [] },
    })).rejects.toBeInstanceOf(IngestValidationError);
    expect(writes).toBe(0);
  });
});
