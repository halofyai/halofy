/**
 * Module A — ingest core: the IngestSink factory.
 *
 * D10: connectors and importers feed the WRITE PATH, never the store. The sink
 * is their entire write surface. `writeRecord` is kernel-injected — already
 * bound to the ingestion Identity + policy (via `performWrite`), so this module
 * never sees an Identity, a db handle, or the audit log. It maps an
 * `IngestRecord` to a `WriteRequest`, stamping the ingestion provenance
 * (`source` + `sourceId`) that keeps the audit answer to "what do we know and
 * where from" whole once bulk data enters through the write path.
 *
 * Imports only the shared contract plus node:crypto for the provenance hash
 * (D10 boundary: no storage, DB, audit, or write-path internals).
 */

import { createHash } from "node:crypto";
import type {
  DataClassification,
  IngestRecord,
  IngestSink,
  Namespace,
  ProvenanceEntry,
  SourceKind,
  WriteRequest,
  WriteResult,
} from "../types.js";
import {
  assertDestinationAllowed,
  ClassificationDeniedError,
  classifyData,
  type IngestDestinationPolicy,
} from "../dlp/index.js";
import { validateIngestRecord } from "./validation.js";

/** Stable actor string stamped on every ingestion write for audit attribution. */
export const INGEST_ACTOR = "ingest";

function isEntityResolutionConflict(error: unknown): boolean {
  return error instanceof Error &&
    error.message.startsWith("entity resolution changed while writing: ");
}

/**
 * Map a SourceKind to the provenance source kind the write path records:
 * already-extracted vendor dumps (Mem0 / pgvector) are a `swap-import`; every
 * other kind (filesystem / postgres / notion / slack) is a `document`. This is
 * the ONLY place the swap-import ↔ document distinction is decided, so an
 * imported fact can never be mistaken for conversation.
 */
export function importKind(kind: SourceKind): ProvenanceEntry["source"] {
  return kind === "mem0-import" || kind === "pgvector-import"
    ? "swap-import"
    : "document";
}

/**
 * M6 (D11) belt-and-braces pointer recognition: the authoritative signal is
 * the record's structural `pointer` field (it carries credentialMode); the
 * fallback is the docId convention `pointer:<connectorId>:<sourceRef>` —
 * connectorId never contains ':', sourceRef may (split on the FIRST ':').
 * Implemented locally so this module keeps its D10 import boundary (shared
 * contract + node:crypto only).
 */
function pointerMetaFor(record: IngestRecord): IngestRecord["pointer"] | null {
  if (record.pointer) return record.pointer;
  const PREFIX = "pointer:";
  if (!record.docId.startsWith(PREFIX)) return null;
  const rest = record.docId.slice(PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep <= 0 || sep === rest.length - 1) return null;
  return {
    connectorId: rest.slice(0, sep),
    sourceRef: rest.slice(sep + 1),
    credentialMode: "service",
  };
}

export interface MakeIngestSinkArgs {
  namespace: Namespace;
  sourceId: string;
  sourceKind: SourceKind;
  /**
   * Kernel-injected write. Already bound to the ingestion Identity + policy
   * (typically `performWrite(deps, req, policy, identity, "ingest")`). Module A
   * never constructs this itself and never sees what it is bound to.
   */
  writeRecord: (req: WriteRequest) => Promise<WriteResult>;
  /** Kernel-owned DLP destination policy. Restricted data is denied by default. */
  destinationPolicy?: IngestDestinationPolicy;
  /** Kernel-owned safe audit hook; receives labels only, never source content. */
  onClassificationDenied?: (detail: {
    sensitivity: DataClassification["sensitivity"];
    destination: string;
  }) => Promise<void>;
  /** Kernel-only lease fence copied to every write from one policy attempt. */
  writeFence?: WriteRequest["writeFence"];
  /** Attempt-scoped provenance used for exact retry-safe compensation. */
  provenanceAttemptToken?: string;
  /**
   * Company-file availability lane: a denied external extraction/embedding
   * retries once as a verbatim local-only write. Canonical policy still gates.
   */
  localBrownoutOnClassificationDenied?: boolean;
}

function intersection(a: readonly string[], b: readonly string[]): string[] {
  const allowed = new Set(b);
  return [...new Set(a.filter((value) => allowed.has(value)))].sort();
}

function authoritativeClassification(
  record: IngestRecord,
  policy: IngestDestinationPolicy,
): DataClassification {
  const supplied = record.classification;
  const policyDestinations = policy.allowedRestrictedDestinations ?? [];
  const hintedDestinations = supplied?.allowedDestinations;
  return classifyData(record.content, {
    sensitivity: supplied?.sensitivity,
    piiSubjects: supplied?.piiSubjects,
    secretKinds: supplied?.secretKinds,
    residency: supplied?.residency,
    // Source hints may narrow kernel policy, never expand it.
    allowedDestinations: hintedDestinations
      ? intersection(hintedDestinations, policyDestinations)
      : policyDestinations,
  });
}

/**
 * Build the namespace-bound sink that is a connector's / importer's whole write
 * surface. `write(record)` maps `IngestRecord` → `WriteRequest` and returns the
 * `WriteResult` from `writeRecord` unchanged (so the caller can aggregate the
 * stored / deduplicated / superseded / rejected counts).
 */
export function makeIngestSink(args: MakeIngestSinkArgs): IngestSink {
  const { namespace, sourceId, sourceKind, writeRecord } = args;
  const source = importKind(sourceKind);
  const destinationPolicy = args.destinationPolicy ?? {};
  const destination = destinationPolicy.canonicalDestination ?? "canonical-l2";

  return {
    namespace,
    sourceId,
    sourceKind,
    async write(record: IngestRecord): Promise<WriteResult> {
      const validated = validateIngestRecord(record);
      const classification = authoritativeClassification(validated, destinationPolicy);
      try {
        assertDestinationAllowed(classification, destination, {
          region: destinationPolicy.region,
        });
      } catch (error) {
        await args.onClassificationDenied?.({
          sensitivity: classification.sensitivity,
          destination,
        });
        throw error;
      }
      const contentHash =
        validated.contentHash ??
        createHash("sha256").update(validated.content, "utf8").digest("hex");
      // M6 (D11): pointer records land as type='pointer' with the pointer
      // provenance stamp. credentialMode is the MODE string, never a token.
      const pointer = pointerMetaFor(validated);
      const governedClassification =
        classification.sensitivity !== "internal" ||
        classification.piiSubjects.length > 0 ||
        classification.secretKinds.length > 0 ||
        classification.residency !== undefined ||
        classification.allowedDestinations.length > 0;
      const req: WriteRequest = {
        namespace,
        scope: validated.scope ?? "org",
        content: validated.content,
        actor: INGEST_ACTOR,
        hints: {
          type: pointer ? "pointer" : undefined,
          verbatim: validated.verbatim,
          eventTime: validated.eventTime,
        },
        provenance: {
          source,
          sourceId,
          sourceKind,
          documentKey: validated.docId,
          contentHash,
          ...(args.provenanceAttemptToken
            ? { attemptToken: args.provenanceAttemptToken }
            : {}),
          ...(validated.sourceAccess ? { sourceAccess: validated.sourceAccess } : {}),
          ...(governedClassification ? { classification } : {}),
          ...(pointer
            ? {
                // The sink owns the source-row identity. Connector supplied
                // metadata may name a provider/catalog entry, but it may never
                // select credentials or another registry row.
                connectorId: sourceId,
                sourceRef: pointer.sourceRef,
                credentialMode: pointer.credentialMode,
                pointer: true,
              }
            : {}),
        },
        ...(args.writeFence ? { writeFence: args.writeFence } : {}),
      };
      try {
        return await writeRecord(req);
      } catch (error) {
        // The write path can reject a later destination (for example
        // llm-extraction or embedding-provider) after the canonical-l2
        // precheck above. D4 requires that denial to be audited with the
        // destination that actually refused the classified content.
        if (error instanceof ClassificationDeniedError) {
          await args.onClassificationDenied?.({
            sensitivity: error.sensitivity,
            destination: error.destination,
          });
          if (
            args.localBrownoutOnClassificationDenied &&
            (error.destination === "llm-extraction" ||
              error.destination === "embedding-provider")
          ) {
            return writeRecord({
              ...req,
              hints: {
                ...req.hints,
                verbatim: true,
                localOnly: true,
              },
            });
          }
        }
        // A verbatim ingestion record is one candidate, so no earlier
        // candidates can have committed before this error. Preserve the full
        // body and configured embedding lane, but replace registry mutation
        // with deterministic entity annotations for this one retry. This
        // avoids pinning a source cursor on an entity decision invalidated by
        // another mention from the same document.
        if (isEntityResolutionConflict(error) && req.hints?.verbatim) {
          return writeRecord({
            ...req,
            hints: {
              ...req.hints,
              deterministicEntities: true,
            },
          });
        }
        throw error;
      }
    },
  };
}
