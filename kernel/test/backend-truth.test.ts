import { describe, expect, it } from "vitest";

import { buildHttpDeps } from "../src/http/adapter.js";
import {
  signCertificate,
  verifyCertificate,
  type CertificatePayload,
} from "../src/erasure/certificate.js";
import { generateSigningKey } from "../src/erasure/keys.js";
import type { Kernel } from "../src/kernel.js";
import type { DeletionCertificate, Identity } from "../src/types.js";

const AUDITOR: Identity = {
  keyId: "auditor-session",
  namespace: "acme",
  actor: "auditor@acme.test",
  role: "auditor",
};

const ADMIN: Identity = {
  keyId: "admin-session",
  namespace: "acme/support",
  actor: "admin@acme.test",
  role: "admin",
};

describe("truthful backend payloads", () => {
  it("adds verification from the server trust root, not the inline certificate key", async () => {
    const trustedKey = generateSigningKey();
    const attackerKey = generateSigningKey();
    const payload: CertificatePayload = {
      id: "cert-1",
      target: { kind: "namespace", value: "acme/team" },
      namespace: "acme",
      erasedIds: ["memory-1"],
      erasedCount: 1,
      actor: "admin@acme.test",
      issuedAt: "2026-07-10T00:00:00.000Z",
      algorithm: "ed25519",
      publicKey: trustedKey.publicKeyBase64,
    };
    const trusted: DeletionCertificate = {
      ...payload,
      signature: signCertificate(payload, trustedKey),
    };
    const forgedPayload: CertificatePayload = {
      ...payload,
      id: "cert-forged",
      publicKey: attackerKey.publicKeyBase64,
    };
    const forged: DeletionCertificate = {
      ...forgedPayload,
      signature: signCertificate(forgedPayload, attackerKey),
    };

    const fakeKernel = {
      auth: {},
      metrics: {},
      audit: {},
      async getCertificate(id: string) {
        return id === forged.id ? forged : trusted;
      },
      verifyCertificate(certificate: DeletionCertificate) {
        return verifyCertificate(certificate, trustedKey.publicKeyBase64);
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);

    await expect(deps.admin.getCertificate!(trusted.id, AUDITOR)).resolves.toMatchObject({
      id: trusted.id,
      verified: true,
    });
    await expect(deps.admin.getCertificate!(forged.id, AUDITOR)).resolves.toMatchObject({
      id: forged.id,
      verified: false,
    });
  });

  it("preserves every current governed audit operation filter", async () => {
    const seen: unknown[] = [];
    const fakeKernel = {
      auth: {},
      metrics: {},
      audit: {},
      async auditSearch(_identity: Identity, filters: unknown) {
        seen.push(filters);
        return [];
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);
    const governedOps = [
      "read",
      "search",
      "write",
      "propose",
      "edit",
      "approve",
      "publish",
      "fault",
      "stats",
      "assemble",
      "pin",
      "unpin",
      "supersede",
      "reject",
      "retract",
      "move",
      "share",
      "forget",
    ];

    for (const op of governedOps) {
      await deps.admin.auditSearch!({ op }, AUDITOR);
    }

    expect(seen).toEqual(governedOps.map((op) => ({ op })));
  });

  it("enforces admin pin namespace scope before calling the pin service", async () => {
    const calls: string[] = [];
    const fakeKernel = {
      auth: {},
      metrics: {},
      audit: {},
      async listPins(_identity: Identity, namespace: string) {
        calls.push(`list:${namespace}`);
        return [];
      },
      pins: {
        async pin(_target: unknown, _identity: Identity, options: { namespace: string }) {
          calls.push(`pin:${options.namespace}`);
          return { created: true };
        },
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);
    const target = { kind: "memory", ref: "01ARZ3NDEKTSV4RRFFQ69G5FAV" };

    await deps.admin.listPins!("acme/support/triage", ADMIN);
    await deps.admin.createPin!({ target, namespace: "acme/support/triage" }, ADMIN);
    await expect(deps.admin.listPins!("acme/sales", ADMIN)).rejects.toMatchObject({ name: "AuthzError" });
    await expect(deps.admin.createPin!({ target, namespace: "acme/sales" }, ADMIN))
      .rejects.toMatchObject({ name: "AuthzError" });
    expect(calls).toEqual(["list:acme/support/triage", "pin:acme/support/triage"]);
  });

  it("forwards exact propose-cold evidence through the HTTP adapter", async () => {
    const calls: unknown[] = [];
    const fakeKernel = {
      auth: {},
      metrics: {},
      audit: {},
      movement: {
        async runManual(identity: Identity, input: unknown) {
          calls.push({ identity, input });
          return { status: "degraded" };
        },
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);
    const targetRef = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const evidenceIds = [targetRef, "01BX5ZZKBKACTAV9WEVGEMMVRZ"];

    await deps.admin.runMovement!({
      action: "propose_cold",
      targetRef,
      idempotencyKey: "proposal-1",
      evidenceIds,
    }, ADMIN);

    expect(calls).toEqual([{
      identity: ADMIN,
      input: { action: "propose_cold", targetRef, idempotencyKey: "proposal-1", evidenceIds },
    }]);
  });

  it("maps movement validation failures to a bad request at the adapter boundary", async () => {
    const fakeKernel = {
      auth: {},
      metrics: {},
      audit: {},
      movement: {
        async runManual() {
          throw new Error("propose_cold requires at least two unique stable evidenceIds including targetRef");
        },
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);

    await expect(deps.admin.runMovement!({
      action: "propose_cold",
      targetRef: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      idempotencyKey: "proposal-1",
      evidenceIds: ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
    }, ADMIN)).rejects.toMatchObject({ name: "BadRequestError" });
  });

  it("maps semantic consolidation input failures to a bad request", async () => {
    const fakeKernel = {
      auth: {}, metrics: {}, audit: {},
      // The early-access allowance gate runs before the manual pass; an
      // ungated stub lets the test stay about input validation.
      async consumeEarlyAccess() {},
      consolidation: {
        async runManual() {
          throw new Error("evidence selection is invalid for this exact scope");
        },
      },
    } as unknown as Kernel;
    const deps = buildHttpDeps(fakeKernel);
    await expect(deps.admin.runConsolidation!({
      namespace: "acme/support",
      evidenceIds: ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01BX5ZZKBKACTAV9WEVGEMMVRZ"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: "2026-07-10T00:00:00.000Z",
    }, ADMIN)).rejects.toMatchObject({ name: "BadRequestError" });

    await expect(deps.admin.runConsolidation!({
      namespace: "acme/support",
      evidenceIds: ["not-stable", "also-not-stable"],
      windowStart: "not-a-date",
      windowEnd: "2026-07-10T00:00:00.000Z",
    }, ADMIN)).rejects.toMatchObject({ name: "BadRequestError" });

    await expect(deps.admin.runConsolidation!({
      namespace: "acme//support",
      evidenceIds: ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01BX5ZZKBKACTAV9WEVGEMMVRZ"],
      windowStart: "2026-07-01T00:00:00.000Z",
      windowEnd: "2026-07-10T00:00:00.000Z",
    }, ADMIN)).rejects.toMatchObject({ name: "BadRequestError" });
  });
});
