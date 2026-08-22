import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import type { SigningKey } from "../erasure/keys.js";

export interface AgentBearerEnvelope {
  ciphertext: string;
  iv: string;
  tag: string;
}

export interface AgentBearerEnvelopeRow {
  bearer_ciphertext: unknown;
  bearer_iv: unknown;
  bearer_tag: unknown;
}

function aad(keyId: string, namespace: string, actor: string): Buffer {
  return Buffer.from(JSON.stringify(["halomem-agent-bearer-v1", keyId, namespace, actor]), "utf8");
}

/**
 * Reversible storage for product-key bearer values.
 *
 * The AES key is domain-separated from the kernel's stable Ed25519 signing
 * key. Production already requires that key to survive restarts; no second
 * deploy secret is introduced. Every row is additionally bound to its stable
 * id, namespace, and actor through AES-GCM AAD, so moving an envelope to a
 * different authority row makes decryption fail closed.
 */
export class AgentBearerCipher {
  private readonly key: Buffer;

  constructor(signingKey: SigningKey) {
    const proof = signingKey.sign(Buffer.from("halomem/auth/agent-bearer/v1", "utf8"));
    this.key = createHash("sha256").update(proof).digest();
  }

  seal(plaintext: string, keyId: string, namespace: string, actor: string): AgentBearerEnvelope {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(aad(keyId, namespace, actor));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
  }

  open(
    row: AgentBearerEnvelopeRow,
    keyId: string,
    namespace: string,
    actor: string,
  ): string {
    const ciphertext = String(row.bearer_ciphertext ?? "");
    const iv = String(row.bearer_iv ?? "");
    const tag = String(row.bearer_tag ?? "");
    if (!ciphertext || !iv || !tag) throw new Error("bearer envelope is unavailable");
    const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(iv, "base64"));
    decipher.setAAD(aad(keyId, namespace, actor));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
  }
}
