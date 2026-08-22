import type { LlmClient } from "../types.js";
import type {
  ConsolidationDraft,
  ConsolidationEngine,
  ConsolidationEvidence,
} from "./index.js";

function jsonObject(raw: string): Record<string, unknown> {
  try {
    const value = JSON.parse(raw) as unknown;
    return value && !Array.isArray(value) && typeof value === "object"
      ? value as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

/** Adapter over the already-configured LLM; no retrieval or agent runtime. */
export class KernelConsolidationEngine implements ConsolidationEngine {
  constructor(private readonly llm: LlmClient) {}

  async createDrafts(evidence: readonly ConsolidationEvidence[]): Promise<ConsolidationDraft[]> {
    const raw = await this.llm.complete(
      "HALOMEM_CONSOLIDATION_V1. Cluster repeated evidence into concise company-knowledge drafts. Return only JSON {drafts:[{evidenceIds,slug,title,body,confidence,conceptId?}]}. Never invent facts.",
      JSON.stringify({ evidence }),
    );
    const drafts = jsonObject(raw).drafts;
    if (!Array.isArray(drafts)) return [];
    return drafts.filter((item): item is ConsolidationDraft => {
      if (!item || Array.isArray(item) || typeof item !== "object") return false;
      const row = item as Record<string, unknown>;
      return Array.isArray(row.evidenceIds) &&
        row.evidenceIds.every((id) => typeof id === "string") &&
        typeof row.slug === "string" && typeof row.title === "string" &&
        typeof row.body === "string" && typeof row.confidence === "number";
    });
  }

  async verifyDraft(
    draft: Readonly<Pick<ConsolidationDraft, "slug" | "title" | "body">>,
    evidence: readonly ConsolidationEvidence[],
  ): Promise<boolean> {
    const raw = await this.llm.complete(
      "HALOMEM_CONSOLIDATION_VERIFY_V1. Decide whether every factual claim in the draft is supported by the supplied evidence. Return only JSON {verified:boolean}.",
      JSON.stringify({ draft, evidence }),
    );
    return jsonObject(raw).verified === true;
  }
}
