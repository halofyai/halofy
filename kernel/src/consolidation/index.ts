/**
 * R5B governed consolidation core.
 *
 * This module owns review state and publication orchestration only. Evidence
 * clustering/drafting/verifying and the encrypted private L3 write are injected
 * boundaries, so consolidation neither becomes a retriever nor opens a second
 * storage system.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { ulid } from "ulid";
import type { AuditEvent, Identity, Namespace, ProvenanceEntry } from "../types.js";
import type { Db } from "../db/client.js";
import { namespaceAncestors } from "../index/index.js";

export type ProposalStatus = "pending_review" | "publishing" | "published" | "rejected";

export interface ConsolidationEvidence {
  id: string;
  namespace: Namespace;
  content: string;
  confidence: number;
  provenance: ProvenanceEntry[];
}

export interface ConsolidationDraft {
  evidenceIds: string[];
  slug: string;
  title: string;
  body: string;
  confidence: number;
  /** Existing logical concept to revise; absent creates one on approval. */
  conceptId?: string;
}

/** Adapter over the existing embedding + extractor/verifier boundary. */
export interface ConsolidationEngine {
  createDrafts(evidence: readonly ConsolidationEvidence[]): Promise<ConsolidationDraft[]>;
  verifyDraft(
    draft: Readonly<Pick<ConsolidationDraft, "slug" | "title" | "body">>,
    evidence: readonly ConsolidationEvidence[],
  ): Promise<boolean>;
}

export interface EncryptedDraftEnvelope {
  ciphertext: string;
  iv: string;
  tag: string;
  keyId: string;
}

export interface DraftCipher {
  encrypt(plaintext: string, aad: string): EncryptedDraftEnvelope;
  decrypt(envelope: EncryptedDraftEnvelope, aad: string): string;
}

export class AesGcmDraftCipher implements DraftCipher {
  private readonly key: Buffer;

  constructor(key: Uint8Array, private readonly keyId: string) {
    if (key.byteLength !== 32) throw new Error("proposal draft key must be exactly 32 bytes");
    if (keyId.trim().length === 0) throw new Error("proposal draft key id is required");
    this.key = Buffer.from(key);
  }

  encrypt(plaintext: string, aad: string): EncryptedDraftEnvelope {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      keyId: this.keyId,
    };
  }

  decrypt(envelope: EncryptedDraftEnvelope, aad: string): string {
    if (envelope.keyId !== this.keyId) throw new Error("proposal draft key is unavailable");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(envelope.iv, "base64"),
    );
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
  }
}

export interface PrivateKnowledgePublishInput {
  path: string;
  namespace: Namespace;
  conceptId: string;
  versionId: string;
  version: number;
  supersedesVersionId: string | null;
  slug: string;
  title: string;
  body: string;
}

/** Must be idempotent for the same immutable path and content. */
export interface PrivateKnowledgePublisher {
  publish(input: PrivateKnowledgePublishInput): Promise<void>;
}

interface AuditWriter {
  appendTo(db: Db, event: AuditEvent): Promise<void>;
}

interface StoredDraft {
  slug: string;
  title: string;
  body: string;
  edited: boolean;
}

export interface KnowledgeProposal {
  id: string;
  runId: string;
  namespace: Namespace;
  conceptId: string | null;
  baseVersionId: string | null;
  confidence: number;
  evidenceIds: string[];
  sourceSessionCount: number;
  status: ProposalStatus;
  rowVersion: number;
  createdAt: string;
  updatedAt: string;
  draft: Pick<StoredDraft, "slug" | "title" | "body">;
}

export interface ManualConsolidationInput {
  namespace: Namespace;
  evidenceIds: string[];
  windowStart: string;
  windowEnd: string;
}

export interface ManualConsolidationResult {
  runId: string;
  status: "complete" | "degraded";
  proposals: KnowledgeProposal[];
}

export interface PreparedConsolidation {
  readonly runId: string;
  readonly namespace: Namespace;
  readonly proposalIds: readonly string[];
  /** Commit only durable run/proposal/audit rows inside the caller's transaction. */
  commitPrepared(tx: Db): Promise<void>;
}

export interface ApproveInput {
  expectedRowVersion: number;
  editedDraft?: Pick<StoredDraft, "slug" | "title" | "body">;
}

export interface RejectInput {
  expectedRowVersion: number;
  reason?: string;
}

export interface EditInput {
  expectedRowVersion: number;
  draft: Pick<StoredDraft, "slug" | "title" | "body">;
}

export interface ProposalDecision {
  id: string;
  proposalId: string;
  actor: string;
  action: "approve" | "edit_approve" | "reject";
  edited: boolean;
  reason: string | null;
  contentHash: string;
  ts: string;
}

export interface ConsolidationMetrics {
  approvals: number;
  mergeWithoutEdit: number;
  mergeWithoutEditRatio: number;
}

export class ProposalConflictError extends Error {
  constructor() {
    super("proposal changed or was already decided");
    this.name = "ProposalConflictError";
  }
}

export class ConsolidationAuthorizationError extends Error {
  constructor() {
    super("consolidation operation denied");
    this.name = "ConsolidationAuthorizationError";
  }
}

export interface ConsolidationDependencies {
  db: Db;
  audit: AuditWriter;
  engine: ConsolidationEngine;
  cipher: DraftCipher;
  publisher: PrivateKnowledgePublisher;
  now?: () => Date;
}

interface ProposalRow extends Record<string, unknown> {
  id: string;
  run_id: string;
  namespace: string;
  concept_id: string | null;
  base_version_id: string | null;
  draft_ciphertext: string;
  draft_iv: string;
  draft_tag: string;
  draft_kek_id: string;
  content_hash: string;
  confidence: number;
  evidence_ids: string[] | string;
  source_session_count: number;
  status: ProposalStatus;
  row_version: number;
  created_at: string | Date;
  updated_at: string | Date;
}

interface PublishingClaim {
  proposal: ProposalRow;
  draft: StoredDraft;
  conceptId: string;
  versionId: string;
  version: number;
  path: string;
  supersedesVersionId: string | null;
}

interface PreparedProposalItem {
  id: string;
  draft: StoredDraft;
  source: ConsolidationDraft;
  envelope: EncryptedDraftEnvelope;
  evidence: ConsolidationEvidence[];
}

const MAX_DRAFT_CHARS = 100_000;
const PROPOSAL_SELECT = `
  SELECT id, run_id, namespace, concept_id, base_version_id,
         draft_ciphertext, draft_iv, draft_tag, draft_kek_id, content_hash,
         confidence, evidence_ids, source_session_count, status, row_version,
         created_at, updated_at
    FROM knowledge_proposals`;

export class ConsolidationService {
  private readonly now: () => Date;

  constructor(private readonly deps: ConsolidationDependencies) {
    this.now = deps.now ?? (() => new Date());
  }

  async runManual(
    identity: Identity,
    input: ManualConsolidationInput,
  ): Promise<ManualConsolidationResult> {
    let prepared: PreparedConsolidation;
    try {
      prepared = await this.prepare(identity, input);
    } catch (error) {
      const result = error instanceof ConsolidationAuthorizationError
        ? "denied"
        : error instanceof Error && error.message.includes("exact scope")
          ? "miss"
          : "error";
      return this.rethrowWithAudit(
        error,
        identity,
        "propose",
        input.namespace || identity.namespace,
        result,
        result === "denied" ? "manual denied" : result === "miss" ? "evidence unavailable" : "prepare failed",
      );
    }

    try {
      await this.deps.db.transaction((tx) => prepared.commitPrepared(tx));
    } catch (error) {
      return this.rethrowWithAudit(
        error, identity, "propose", prepared.namespace, "error", `run=${prepared.runId} commit_failed`,
      );
    }

    const proposals: KnowledgeProposal[] = [];
    for (const proposalId of prepared.proposalIds) {
      const proposal = await this.get(identity, proposalId);
      if (proposal !== null) proposals.push(proposal);
    }
    return { runId: prepared.runId, status: "complete", proposals };
  }

  /**
   * Perform validation, exact-scope evidence reads, drafting, verification, and
   * encryption without creating durable rows. The returned commit is reusable
   * by the manual syscall and the movement engine.
   */
  async prepare(
    identity: Identity,
    input: ManualConsolidationInput,
  ): Promise<PreparedConsolidation> {
    assertPrivateNamespace(input.namespace);
    this.assertMutator(identity, input.namespace);
    const evidenceIds = uniqueNonEmptyIds(input.evidenceIds);
    if (evidenceIds.length < 2) throw new Error("evidence selection requires at least two stable ids");
    const windowStart = validIso(input.windowStart, "windowStart");
    const windowEnd = validIso(input.windowEnd, "windowEnd");
    if (windowStart > windowEnd) throw new Error("consolidation window is invalid");

    const evidence = await this.selectEvidence(input.namespace, evidenceIds);
    if (evidence.length !== evidenceIds.length) {
      throw new Error("evidence selection is invalid for this exact scope");
    }

    const runId = ulid();
    let drafts: ConsolidationDraft[];
    try {
      drafts = await this.deps.engine.createDrafts(evidence);
    } catch (error) {
      throw error;
    }

    const evidenceById = new Map(evidence.map((item) => [item.id, item]));
    const items: PreparedProposalItem[] = [];

    try {
      for (const source of drafts) {
        validateDraft(source);
        const clusterIds = uniqueNonEmptyIds(source.evidenceIds);
        if (clusterIds.length < 2 || clusterIds.some((id) => !evidenceById.has(id))) {
          throw new Error("consolidation engine returned an invalid evidence cluster");
        }
        const cluster = clusterIds.map((id) => evidenceById.get(id) as ConsolidationEvidence);
        const verified = await this.deps.engine.verifyDraft(source, cluster);
        if (!verified) continue;
        const id = ulid();
        const draft: StoredDraft = {
          slug: normalizedSlug(source.slug),
          title: source.title.trim(),
          body: source.body.trim(),
          edited: false,
        };
        items.push({
          id,
          draft,
          source: { ...source, evidenceIds: clusterIds },
          envelope: this.deps.cipher.encrypt(JSON.stringify(draft), proposalAad(id, input.namespace)),
          evidence: cluster,
        });
      }
    } catch (error) {
      throw error;
    }

    const ts = this.now().toISOString();
    return {
      runId,
      namespace: input.namespace,
      proposalIds: items.map((item) => item.id),
      commitPrepared: async (tx) => {
        await tx.query(
        `INSERT INTO consolidation_runs
           (id, namespace, window_start, window_end, status, lease_until,
            metrics, error, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'complete', NULL, $5::jsonb, NULL, $6, $6)`,
          [runId, input.namespace, windowStart, windowEnd, JSON.stringify({ proposals: items.length }), ts],
        );
        for (const item of items) {
        let baseVersionId: string | null = null;
        if (item.source.conceptId !== undefined) {
          const concept = await tx.query(
            `SELECT current_version_id FROM knowledge_concepts
              WHERE id = $1 AND namespace = $2 AND status = 'active'`,
            [item.source.conceptId, input.namespace],
          );
          if (concept.rows.length !== 1) throw new Error("draft concept is not in the exact scope");
          baseVersionId = asNullableString(concept.rows[0].current_version_id);
        }
        await tx.query(
          `INSERT INTO knowledge_proposals
             (id, run_id, namespace, concept_id, base_version_id,
              draft_ciphertext, draft_iv, draft_tag, draft_kek_id, content_hash,
              confidence, evidence_ids, source_session_count, status, row_version,
              created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                   $12::jsonb, $13, 'pending_review', 1, $14, $14)`,
          [
            item.id,
            runId,
            input.namespace,
            item.source.conceptId ?? null,
            baseVersionId,
            item.envelope.ciphertext,
            item.envelope.iv,
            item.envelope.tag,
            item.envelope.keyId,
            sha256(item.draft.body),
            item.source.confidence,
            JSON.stringify(item.source.evidenceIds),
            sessionCount(item.evidence),
            ts,
          ],
        );
        await this.audit(tx, identity, "propose", input.namespace, "ok", `proposal=${item.id} evidence_count=${item.source.evidenceIds.length}`);
        }
        if (items.length === 0) {
          await this.audit(tx, identity, "propose", input.namespace, "miss", `run=${runId} proposals=0`);
        }
      },
    };
  }

  async list(identity: Identity): Promise<KnowledgeProposal[]> {
    const result = await this.deps.db.query(`${PROPOSAL_SELECT} ORDER BY created_at DESC, id DESC`);
    return (result.rows as ProposalRow[])
      .filter((row) => this.canRead(identity, row.namespace))
      .map((row) => this.toProposal(row));
  }

  async get(identity: Identity, proposalId: string): Promise<KnowledgeProposal | null> {
    const row = await this.getRow(this.deps.db, proposalId);
    if (row === null || !this.canRead(identity, row.namespace)) return null;
    return this.toProposal(row);
  }

  async reject(identity: Identity, proposalId: string, input: RejectInput): Promise<KnowledgeProposal> {
    try {
      assertRowVersion(input.expectedRowVersion);
      const ts = this.now().toISOString();
      await this.deps.db.transaction(async (tx) => {
      const row = await this.requireManageableRow(tx, identity, proposalId);
      if (row.status !== "pending_review" || Number(row.row_version) !== input.expectedRowVersion) {
        throw new ProposalConflictError();
      }
      const updated = await tx.query(
        `UPDATE knowledge_proposals
            SET status = 'rejected', row_version = row_version + 1, updated_at = $3
          WHERE id = $1 AND status = 'pending_review' AND row_version = $2
          RETURNING id`,
        [proposalId, input.expectedRowVersion, ts],
      );
      if (updated.rows.length !== 1) throw new ProposalConflictError();
      await tx.query(
        `INSERT INTO proposal_decisions
           (id, proposal_id, actor, action, edited, reason, content_hash, ts)
         VALUES ($1, $2, $3, 'reject', FALSE, $4, $5, $6)`,
        [ulid(), proposalId, identity.actor, input.reason?.trim() || null, row.content_hash, ts],
      );
      await this.audit(tx, identity, "reject", row.namespace, "ok", `proposal=${proposalId}`);
      });
      return this.requireVisible(identity, proposalId);
    } catch (error) {
      return this.rethrowProposalFailure(error, identity, "reject", proposalId);
    }
  }

  async edit(identity: Identity, proposalId: string, input: EditInput): Promise<KnowledgeProposal> {
    try {
      assertRowVersion(input.expectedRowVersion);
      const current = await this.requireManageableRow(this.deps.db, identity, proposalId);
    if (current.status !== "pending_review" || Number(current.row_version) !== input.expectedRowVersion) {
      throw new ProposalConflictError();
    }
    const candidate = validateEditedDraft(input.draft);
    const evidenceIds = jsonStringArray(current.evidence_ids);
    const evidence = await this.selectEvidence(current.namespace, evidenceIds);
    if (evidence.length !== evidenceIds.length) {
      throw new Error("proposal evidence is no longer active in its exact scope");
    }
    if (!(await this.deps.engine.verifyDraft(candidate, evidence))) {
      throw new Error("edited proposal failed verification");
    }
    const draft: StoredDraft = { ...candidate, edited: true };
    const envelope = this.deps.cipher.encrypt(
      JSON.stringify(draft),
      proposalAad(current.id, current.namespace),
    );
    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const row = await this.requireManageableRow(tx, identity, proposalId);
      if (row.status !== "pending_review" || Number(row.row_version) !== input.expectedRowVersion) {
        throw new ProposalConflictError();
      }
      const updated = await tx.query(
        `UPDATE knowledge_proposals
            SET draft_ciphertext = $3, draft_iv = $4, draft_tag = $5,
                draft_kek_id = $6, content_hash = $7,
                row_version = row_version + 1, updated_at = $8
          WHERE id = $1 AND status = 'pending_review' AND row_version = $2
          RETURNING id`,
        [
          proposalId,
          input.expectedRowVersion,
          envelope.ciphertext,
          envelope.iv,
          envelope.tag,
          envelope.keyId,
          sha256(draft.body),
          ts,
        ],
      );
      if (updated.rows.length !== 1) throw new ProposalConflictError();
      await this.audit(tx, identity, "edit", row.namespace, "ok", `proposal=${proposalId}`);
    });
      return this.requireVisible(identity, proposalId);
    } catch (error) {
      return this.rethrowProposalFailure(error, identity, "edit", proposalId);
    }
  }

  async decisions(identity: Identity, proposalId: string): Promise<ProposalDecision[]> {
    const proposal = await this.getRow(this.deps.db, proposalId);
    if (proposal === null || !this.canRead(identity, proposal.namespace)) return [];
    const result = await this.deps.db.query(
      `SELECT id, proposal_id, actor, action, edited, reason, content_hash, ts
         FROM proposal_decisions WHERE proposal_id = $1 ORDER BY ts, id`,
      [proposalId],
    );
    return (result.rows as Record<string, unknown>[]).map((row) => ({
      id: String(row.id),
      proposalId: String(row.proposal_id),
      actor: String(row.actor),
      action: String(row.action) as ProposalDecision["action"],
      edited: row.edited === true || String(row.edited) === "true",
      reason: asNullableString(row.reason),
      contentHash: String(row.content_hash),
      ts: iso(row.ts as string | Date),
    }));
  }

  async approve(identity: Identity, proposalId: string, input: ApproveInput): Promise<KnowledgeProposal> {
    try {
      assertRowVersion(input.expectedRowVersion);
      const current = await this.requireManageableRow(this.deps.db, identity, proposalId);
    if (current.status === "published" || current.status === "rejected") throw new ProposalConflictError();

    let editedDraft: StoredDraft | null = null;
    if (input.editedDraft !== undefined) {
      if (current.status !== "pending_review") throw new ProposalConflictError();
      const candidate = validateEditedDraft(input.editedDraft);
      const evidence = await this.selectEvidence(current.namespace, jsonStringArray(current.evidence_ids));
      if (evidence.length !== jsonStringArray(current.evidence_ids).length) {
        throw new Error("proposal evidence is no longer active in its exact scope");
      }
      if (!(await this.deps.engine.verifyDraft(candidate, evidence))) {
        throw new Error("edited proposal failed verification");
      }
      editedDraft = { ...candidate, edited: true };
    }

    const claim = await this.claimPublication(identity, current, input.expectedRowVersion, editedDraft);
    try {
      await this.deps.publisher.publish({
        path: claim.path,
        namespace: claim.proposal.namespace,
        conceptId: claim.conceptId,
        versionId: claim.versionId,
        version: claim.version,
        supersedesVersionId: claim.supersedesVersionId,
        slug: claim.draft.slug,
        title: claim.draft.title,
        body: claim.draft.body,
      });
    } catch (error) {
      await this.deps.db.transaction((tx) => this.audit(
        tx,
        identity,
        "publish",
        claim.proposal.namespace,
        "error",
        `proposal=${proposalId} version=${claim.versionId}`,
      ));
      throw error;
    }

    const ts = this.now().toISOString();
    await this.deps.db.transaction(async (tx) => {
      const row = await this.requireManageableRow(tx, identity, proposalId);
      if (row.status !== "publishing") throw new ProposalConflictError();
      const version = await tx.query(
        `SELECT id, concept_id, path FROM knowledge_versions
          WHERE proposal_id = $1 AND state = 'publishing'`,
        [proposalId],
      );
      if (version.rows.length !== 1 || String(version.rows[0].id) !== claim.versionId) {
        throw new ProposalConflictError();
      }
      await tx.query(
        `UPDATE knowledge_versions
            SET state = 'published', published_at = $2
          WHERE id = $1 AND state = 'publishing'`,
        [claim.versionId, ts],
      );
      // Keep immutable history, but retire the previous official version from
      // every normal retrieval/materialization lane in the same finalization
      // transaction that advances the logical concept pointer.
      await tx.query(
        `UPDATE knowledge_versions
            SET state = 'archived'
          WHERE concept_id = $1 AND id <> $2 AND state = 'published'`,
        [claim.conceptId, claim.versionId],
      );
      await tx.query(
        `UPDATE knowledge_concepts
            SET current_version_id = $2, title = $3, updated_at = $4
          WHERE id = $1 AND namespace = $5`,
        [claim.conceptId, claim.versionId, claim.draft.title, ts, row.namespace],
      );
      const updated = await tx.query(
        `UPDATE knowledge_proposals
            SET status = 'published', row_version = row_version + 1, updated_at = $2
          WHERE id = $1 AND status = 'publishing'
          RETURNING id`,
        [proposalId, ts],
      );
      if (updated.rows.length !== 1) throw new ProposalConflictError();
      await tx.query(
        `INSERT INTO proposal_decisions
           (id, proposal_id, actor, action, edited, reason, content_hash, ts)
         SELECT $1, $2, $3, $4, $5, NULL, $6, $7
          WHERE NOT EXISTS (SELECT 1 FROM proposal_decisions WHERE proposal_id = $2)`,
        [
          ulid(),
          proposalId,
          identity.actor,
          claim.draft.edited ? "edit_approve" : "approve",
          claim.draft.edited,
          sha256(claim.draft.body),
          ts,
        ],
      );
      await this.audit(tx, identity, "publish", row.namespace, "ok", `proposal=${proposalId} version=${claim.versionId}`);
    });
      return this.requireVisible(identity, proposalId);
    } catch (error) {
      return this.rethrowProposalFailure(error, identity, "approve", proposalId);
    }
  }

  async metrics(identity: Identity, namespace: Namespace): Promise<ConsolidationMetrics> {
    this.assertReadableTarget(identity, namespace);
    const result = await this.deps.db.query(
      `SELECT count(*) AS approvals,
              count(*) FILTER (WHERE d.edited = FALSE) AS merge_without_edit
         FROM proposal_decisions d
         JOIN knowledge_proposals p ON p.id = d.proposal_id
        WHERE p.namespace = $1 AND d.action IN ('approve','edit_approve')`,
      [namespace],
    );
    const approvals = Number(result.rows[0]?.approvals ?? 0);
    const mergeWithoutEdit = Number(result.rows[0]?.merge_without_edit ?? 0);
    return {
      approvals,
      mergeWithoutEdit,
      mergeWithoutEditRatio: approvals === 0 ? 0 : mergeWithoutEdit / approvals,
    };
  }

  private async claimPublication(
    identity: Identity,
    initial: ProposalRow,
    expectedRowVersion: number,
    editedDraft: StoredDraft | null,
  ): Promise<PublishingClaim> {
    return this.deps.db.transaction(async (tx) => {
      const row = await this.requireManageableRow(tx, identity, initial.id);
      if (row.status === "publishing") {
        // A retry is made from a freshly read publishing proposal. Requiring
        // the CURRENT row version makes restart/refresh recovery possible;
        // the former expected+1 rule only worked for a stale in-memory caller.
        if (Number(row.row_version) !== expectedRowVersion || editedDraft !== null) {
          throw new ProposalConflictError();
        }
        const existing = await tx.query(
          `SELECT id, concept_id, path, version, supersedes_version_id
             FROM knowledge_versions WHERE proposal_id = $1 AND state = 'publishing'`,
          [row.id],
        );
        if (existing.rows.length !== 1) throw new ProposalConflictError();
        return {
          proposal: row,
          draft: this.decryptDraft(row),
          conceptId: String(existing.rows[0].concept_id),
          versionId: String(existing.rows[0].id),
          version: Number(existing.rows[0].version),
          path: String(existing.rows[0].path),
          supersedesVersionId: asNullableString(existing.rows[0].supersedes_version_id),
        };
      }
      if (row.status !== "pending_review" || Number(row.row_version) !== expectedRowVersion) {
        throw new ProposalConflictError();
      }

      const draft = editedDraft ?? this.decryptDraft(row);
      const envelope = editedDraft === null
        ? null
        : this.deps.cipher.encrypt(JSON.stringify(draft), proposalAad(row.id, row.namespace));
      const updated = await tx.query(
        `UPDATE knowledge_proposals
            SET status = 'publishing', row_version = row_version + 1,
                draft_ciphertext = COALESCE($3, draft_ciphertext),
                draft_iv = COALESCE($4, draft_iv), draft_tag = COALESCE($5, draft_tag),
                draft_kek_id = COALESCE($6, draft_kek_id),
                content_hash = $7, updated_at = $8
          WHERE id = $1 AND status = 'pending_review' AND row_version = $2
          RETURNING id`,
        [
          row.id,
          expectedRowVersion,
          envelope?.ciphertext ?? null,
          envelope?.iv ?? null,
          envelope?.tag ?? null,
          envelope?.keyId ?? null,
          sha256(draft.body),
          this.now().toISOString(),
        ],
      );
      if (updated.rows.length !== 1) throw new ProposalConflictError();

      let conceptId = row.concept_id;
      let supersedesVersionId = row.base_version_id;
      if (conceptId === null) {
        conceptId = ulid();
        await tx.query(
          `INSERT INTO knowledge_concepts
             (id, namespace, slug, title, current_version_id, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NULL, 'active', $5, $5)`,
          [conceptId, row.namespace, draft.slug, draft.title, this.now().toISOString()],
        );
        await tx.query(`UPDATE knowledge_proposals SET concept_id = $2 WHERE id = $1`, [row.id, conceptId]);
        supersedesVersionId = null;
      } else {
        const concept = await tx.query(
          `SELECT current_version_id FROM knowledge_concepts
            WHERE id = $1 AND namespace = $2 AND status = 'active'
            FOR UPDATE`,
          [conceptId, row.namespace],
        );
        if (
          concept.rows.length !== 1 ||
          asNullableString(concept.rows[0].current_version_id) !== row.base_version_id
        ) {
          throw new ProposalConflictError();
        }
        const inFlight = await tx.query(
          `SELECT id FROM knowledge_versions
            WHERE concept_id = $1 AND state = 'publishing'`,
          [conceptId],
        );
        if (inFlight.rows.length > 0) throw new ProposalConflictError();
      }

      const next = await tx.query(
        `SELECT COALESCE(MAX(version), 0) + 1 AS version
           FROM knowledge_versions WHERE concept_id = $1`,
        [conceptId],
      );
      const version = Number(next.rows[0].version);
      const versionId = ulid();
      const path = immutableVersionPath(row.namespace, conceptId, version, versionId);
      await tx.query(
        `INSERT INTO knowledge_versions
           (id, concept_id, path, version, supersedes_version_id, content_hash,
            proposal_id, state, published_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'publishing', NULL, $8)`,
        [versionId, conceptId, path, version, supersedesVersionId, sha256(draft.body), row.id, this.now().toISOString()],
      );
      await this.audit(tx, identity, "approve", row.namespace, "ok", `proposal=${row.id} status=publishing`);
      const claimed = await this.getRow(tx, row.id);
      if (claimed === null) throw new ProposalConflictError();
      return { proposal: claimed, draft, conceptId, versionId, version, path, supersedesVersionId };
    });
  }

  private async selectEvidence(namespace: Namespace, ids: string[]): Promise<ConsolidationEvidence[]> {
    if (ids.length === 0) return [];
    const placeholders = ids.map((_, index) => `$${index + 2}`).join(", ");
    const result = await this.deps.db.query(
      `SELECT id, namespace, content, confidence, provenance
         FROM memory_objects
        WHERE namespace = $1 AND id IN (${placeholders})
          AND tier = 'L2' AND status = 'active' AND t_valid_to IS NULL
          AND (ttl_seconds IS NULL OR assertion_time + ttl_seconds * INTERVAL '1 second' > $${ids.length + 2})`,
      [namespace, ...ids, this.now().toISOString()],
    );
    const byId = new Map((result.rows as Record<string, unknown>[]).map((row) => [String(row.id), row]));
    return ids.flatMap((id) => {
      const row = byId.get(id);
      if (row === undefined) return [];
      return [{
        id,
        namespace: String(row.namespace),
        content: String(row.content),
        confidence: Number(row.confidence),
        provenance: jsonProvenance(row.provenance),
      }];
    });
  }

  private async getRow(db: Db, proposalId: string): Promise<ProposalRow | null> {
    const result = await db.query(`${PROPOSAL_SELECT} WHERE id = $1`, [proposalId]);
    return (result.rows[0] as ProposalRow | undefined) ?? null;
  }

  private async requireManageableRow(db: Db, identity: Identity, proposalId: string): Promise<ProposalRow> {
    const row = await this.getRow(db, proposalId);
    if (row === null || !this.canManage(identity, row.namespace)) {
      throw new ConsolidationAuthorizationError();
    }
    return row;
  }

  private async requireVisible(identity: Identity, proposalId: string): Promise<KnowledgeProposal> {
    const proposal = await this.get(identity, proposalId);
    if (proposal === null) throw new ConsolidationAuthorizationError();
    return proposal;
  }

  private toProposal(row: ProposalRow): KnowledgeProposal {
    const draft = this.decryptDraft(row);
    return {
      id: row.id,
      runId: row.run_id,
      namespace: row.namespace,
      conceptId: row.concept_id,
      baseVersionId: row.base_version_id,
      confidence: Number(row.confidence),
      evidenceIds: jsonStringArray(row.evidence_ids),
      sourceSessionCount: Number(row.source_session_count),
      status: row.status,
      rowVersion: Number(row.row_version),
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
      draft: { slug: draft.slug, title: draft.title, body: draft.body },
    };
  }

  private decryptDraft(row: ProposalRow): StoredDraft {
    const plaintext = this.deps.cipher.decrypt({
      ciphertext: row.draft_ciphertext,
      iv: row.draft_iv,
      tag: row.draft_tag,
      keyId: row.draft_kek_id,
    }, proposalAad(row.id, row.namespace));
    const parsed = JSON.parse(plaintext) as Partial<StoredDraft>;
    if (
      typeof parsed.slug !== "string" || typeof parsed.title !== "string" ||
      typeof parsed.body !== "string" || typeof parsed.edited !== "boolean"
    ) {
      throw new Error("proposal draft envelope is invalid");
    }
    return { slug: parsed.slug, title: parsed.title, body: parsed.body, edited: parsed.edited };
  }

  private canRead(identity: Identity, namespace: Namespace): boolean {
    if (isRootOwner(identity)) return true;
    if (namespaceAncestors(identity.namespace).includes(namespace)) return true;
    return (identity.role === "owner" || identity.role === "admin" || identity.role === "auditor") &&
      namespaceAncestors(namespace).includes(identity.namespace);
  }

  private canManage(identity: Identity, namespace: Namespace): boolean {
    if (identity.role !== "owner" && identity.role !== "admin") return false;
    return isRootOwner(identity) || namespaceAncestors(namespace).includes(identity.namespace);
  }

  private assertMutator(identity: Identity, namespace: Namespace): void {
    if (!this.canManage(identity, namespace)) throw new ConsolidationAuthorizationError();
  }

  private assertReadableTarget(identity: Identity, namespace: Namespace): void {
    if (!this.canRead(identity, namespace)) throw new ConsolidationAuthorizationError();
  }

  private audit(
    tx: Db,
    identity: Identity,
    op: AuditEvent["op"],
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> {
    return this.deps.audit.appendTo(tx, {
      ts: this.now().toISOString(),
      actor: identity.actor,
      agentId: identity.keyId,
      op,
      memoryId: null,
      namespace,
      purpose: "consolidation",
      result,
      detail,
    });
  }

  private async auditStandalone(
    identity: Identity,
    op: AuditEvent["op"],
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<void> {
    await this.deps.db.transaction((tx) => this.audit(tx, identity, op, namespace, result, detail));
  }

  private async rethrowProposalFailure(
    error: unknown,
    identity: Identity,
    op: "reject" | "edit" | "approve",
    proposalId: string,
  ): Promise<never> {
    let auditNamespace = identity.namespace;
    try {
      const proposal = await this.getRow(this.deps.db, proposalId);
      if (proposal !== null) auditNamespace = proposal.namespace;
    } catch {
      // Preserve the original operation failure. The standalone audit below
      // still records it in the caller namespace if proposal lookup is down.
    }
    const result = error instanceof ConsolidationAuthorizationError ? "denied" : "error";
    const category = error instanceof ProposalConflictError
      ? "conflict"
      : result === "denied"
        ? "denied"
        : "failed";
    return this.rethrowWithAudit(
      error,
      identity,
      op,
      auditNamespace,
      result,
      `proposal=${proposalId} ${category}`,
    );
  }

  private async rethrowWithAudit(
    error: unknown,
    identity: Identity,
    op: AuditEvent["op"],
    namespace: Namespace,
    result: AuditEvent["result"],
    detail: string,
  ): Promise<never> {
    try {
      await this.auditStandalone(identity, op, namespace, result, detail);
    } catch (auditError) {
      throw new AggregateError([error, auditError], "operation failed and its outcome audit could not be written");
    }
    throw error;
  }
}

function isRootOwner(identity: Identity): boolean {
  return identity.role === "owner" && identity.namespace === "";
}

function uniqueNonEmptyIds(ids: string[]): string[] {
  if (!Array.isArray(ids) || ids.some((id) => typeof id !== "string" || id.trim().length === 0)) {
    throw new Error("evidence selection requires stable ids");
  }
  const unique = [...new Set(ids.map((id) => id.trim()))];
  if (unique.length !== ids.length) throw new Error("evidence selection contains duplicate ids");
  return unique;
}

function validIso(value: string, field: string): string {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime())) throw new Error(`${field} must be an ISO timestamp`);
  return parsed.toISOString();
}

function validateDraft(draft: ConsolidationDraft): void {
  normalizedSlug(draft.slug);
  if (draft.title.trim().length === 0 || draft.title.length > 500) throw new Error("draft title is invalid");
  if (draft.body.trim().length === 0 || draft.body.length > MAX_DRAFT_CHARS) throw new Error("draft body is invalid");
  if (!Number.isFinite(draft.confidence) || draft.confidence < 0 || draft.confidence > 1) {
    throw new Error("draft confidence is invalid");
  }
}

function validateEditedDraft(
  draft: Pick<StoredDraft, "slug" | "title" | "body">,
): Pick<StoredDraft, "slug" | "title" | "body"> {
  const candidate: ConsolidationDraft = { ...draft, evidenceIds: ["validation", "only"], confidence: 1 };
  validateDraft(candidate);
  return { slug: normalizedSlug(draft.slug), title: draft.title.trim(), body: draft.body.trim() };
}

function normalizedSlug(value: string): string {
  const slug = value.trim().toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 120) {
    throw new Error("draft slug is invalid");
  }
  return slug;
}

function proposalAad(id: string, namespace: Namespace): string {
  return `halomem:proposal:v1:${namespace}:${id}`;
}

function immutableVersionPath(
  namespace: Namespace,
  conceptId: string,
  version: number,
  versionId: string,
): string {
  const owner = namespace.split("/").map((part) =>
    encodeURIComponent(part).replace(/[!'()*]/g, (character) =>
      `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
    )
  ).join("/");
  return `concepts/${owner}/${conceptId}/v${version}-${versionId}.okf.enc`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function jsonStringArray(value: unknown): string[] {
  const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error("proposal evidence ids are invalid");
  }
  return parsed as string[];
}

function jsonProvenance(value: unknown): ProvenanceEntry[] {
  const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
  return Array.isArray(parsed) ? parsed as ProvenanceEntry[] : [];
}

function sessionCount(evidence: ConsolidationEvidence[]): number {
  const sessions = new Set<string>();
  for (const item of evidence) {
    for (const provenance of item.provenance) {
      if (provenance.session) sessions.add(provenance.session);
    }
  }
  return sessions.size;
}

function asNullableString(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

function iso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function assertRowVersion(value: number): void {
  if (!Number.isInteger(value) || value < 1) throw new Error("expectedRowVersion must be a positive integer");
}

function assertPrivateNamespace(namespace: Namespace): void {
  const parts = namespace.split("/");
  if (
    namespace.length === 0 || namespace.includes("\\") ||
    parts.some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new Error("consolidation namespace must be a canonical private namespace");
  }
}
