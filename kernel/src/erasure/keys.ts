/**
 * Module B (M4) — erasure signing key.
 *
 * `loadSigningKey()` produces the kernel's ed25519 signing handle used to mint
 * DeletionCertificates. If `HALOMEM_SIGNING_KEY` is set (base64 PKCS8 DER of an
 * ed25519 private key) it is loaded; otherwise an ephemeral keypair is
 * generated and a one-time warning is emitted. An ephemeral key does not
 * persist across restarts, so an external verifier cannot pin one long-lived
 * trusted public key.
 *
 * ed25519 with node:crypto: the signing algorithm argument is `null`
 * (ed25519/ed448 are pure — the digest is fixed by the scheme).
 *
 * Import surface: node:crypto only. No kernel imports.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign as cryptoSign,
} from "node:crypto";

/** The kernel's signing handle. */
export interface SigningKey {
  /** Sign `bytes` with ed25519; returns the raw 64-byte signature. */
  sign(bytes: Buffer): Buffer;
  /** Base64 of the public key in SPKI DER form — travels inline on the cert. */
  readonly publicKeyBase64: string;
  /**
   * True when a persistent key was supplied via HALOMEM_SIGNING_KEY; false when
   * an ephemeral keypair was generated for this process.
   */
  readonly privateKeyAvailable: boolean;
}

/** Env var carrying a base64 PKCS8 DER ed25519 private key. */
export const SIGNING_KEY_ENV = "HALOMEM_SIGNING_KEY";

/** Guards the one-time ephemeral-key warning (process-global). */
let warnedEphemeral = false;

function warnEphemeralOnce(): void {
  if (warnedEphemeral) return;
  warnedEphemeral = true;
  console.warn(
    `[halomem] ${SIGNING_KEY_ENV} not set - generated an EPHEMERAL ed25519 ` +
      `signing key. Its trusted public key is not stable across restarts. ` +
      `Set ${SIGNING_KEY_ENV} ` +
      `(base64 PKCS8 DER) in production.`,
  );
}

/** Build a SigningKey handle around a private + public KeyObject pair. */
function makeSigningKey(
  privateKey: KeyObject,
  publicKey: KeyObject,
  privateKeyAvailable: boolean,
): SigningKey {
  const publicKeyBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  return {
    sign(bytes: Buffer): Buffer {
      // ed25519: algorithm is null (the scheme fixes the digest).
      return cryptoSign(null, bytes, privateKey);
    },
    publicKeyBase64,
    privateKeyAvailable,
  };
}

/** Generate a fresh process-local Ed25519 key, ignoring any configured env key. */
export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return makeSigningKey(privateKey, publicKey, false);
}

/**
 * Load the signing key from HALOMEM_SIGNING_KEY (base64 PKCS8 DER ed25519) or,
 * absent that, generate an ephemeral keypair (warn once).
 */
export function loadSigningKey(): SigningKey {
  const raw = process.env[SIGNING_KEY_ENV];
  if (raw && raw.trim().length > 0) {
    const der = Buffer.from(raw.trim(), "base64");
    const privateKey = createPrivateKey({
      key: der,
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `${SIGNING_KEY_ENV} must be an ed25519 key, got ${String(
          privateKey.asymmetricKeyType,
        )}`,
      );
    }
    // A private KeyObject re-exports as its matching public key.
    const publicKey = createPublicKey(privateKey);
    return makeSigningKey(privateKey, publicKey, true);
  }

  warnEphemeralOnce();
  return generateSigningKey();
}
