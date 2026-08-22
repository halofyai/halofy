/**
 * Module B (M4) — deletion certificate canonicalization + signing + verify.
 *
 * Every field except `signature` is canonicalized to a deterministic JSON
 * string (recursively sorted keys) and signed with the kernel's ed25519 key.
 * The public key carried by the certificate is descriptive metadata only:
 * verification requires the same key from an out-of-band trusted source.
 *
 * Import surface: node:crypto + shared types only. No kernel imports.
 */

import {
  verify as cryptoVerify,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import type { DeletionCertificate } from "../types.js";
import type { SigningKey } from "./keys.js";

/** The certificate payload = every field except the signature. */
export type CertificatePayload = Omit<DeletionCertificate, "signature">;

/**
 * Deterministic JSON of an arbitrary JSON value with object keys sorted at
 * every depth. Arrays keep their order (erasedIds ordering is meaningful and
 * fixed by the resolver); objects (including the nested ForgetTarget) sort.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`,
  );
  return `{${parts.join(",")}}`;
}

/**
 * Canonical, signature-independent JSON string of a certificate. Given a full
 * certificate or a payload, the `signature` field is always excluded, so the
 * signer and the verifier hash exactly the same bytes.
 */
export function canonicalPayload(
  cert: CertificatePayload | DeletionCertificate,
): string {
  const { signature: _signature, ...payload } = cert as DeletionCertificate;
  return stableStringify(payload);
}

/**
 * Sign a certificate payload with the kernel's ed25519 key; returns the base64
 * signature over the canonical payload bytes (UTF-8).
 */
export function signCertificate(
  payload: CertificatePayload,
  key: SigningKey,
): string {
  const bytes = Buffer.from(canonicalPayload(payload), "utf8");
  return key.sign(bytes).toString("base64");
}

/**
 * Verify a certificate against an out-of-band trusted public key. The inline
 * key is signed descriptive metadata and must identify that same trusted key;
 * it is never itself a trust anchor. Rebuilds the canonical payload (dropping
 * `signature`) and checks the ed25519 signature.
 * Returns false — never throws — for a key mismatch, tampered field, bad
 * signature, malformed key, or non-ed25519 algorithm.
 */
export function verifyCertificate(
  cert: DeletionCertificate,
  trustedPublicKeyBase64: string,
): boolean {
  try {
    if (cert.algorithm !== "ed25519") return false;
    const inlineKeyDer = Buffer.from(cert.publicKey, "base64");
    const trustedKeyDer = Buffer.from(trustedPublicKeyBase64, "base64");
    if (
      inlineKeyDer.length === 0 ||
      inlineKeyDer.length !== trustedKeyDer.length ||
      !timingSafeEqual(inlineKeyDer, trustedKeyDer)
    ) {
      return false;
    }
    const publicKey = createPublicKey({
      key: trustedKeyDer,
      format: "der",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "ed25519") return false;
    const bytes = Buffer.from(canonicalPayload(cert), "utf8");
    const signature = Buffer.from(cert.signature, "base64");
    // ed25519: algorithm is null (the scheme fixes the digest).
    return cryptoVerify(null, bytes, publicKey, signature);
  } catch {
    return false;
  }
}
