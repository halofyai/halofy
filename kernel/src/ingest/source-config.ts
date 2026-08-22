import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { Namespace, SourceKind } from "../types.js";

export interface SealedSourceConfig {
  ciphertext: string;
  iv: string;
  tag: string;
  kekId: string;
  sha256: string;
}

export interface StoredSourceConfig {
  id: string;
  namespace: Namespace;
  kind: SourceKind;
  config_ciphertext?: unknown;
  config_iv?: unknown;
  config_tag?: unknown;
  config_kek_id?: unknown;
  config_sha256?: unknown;
}

/** Safe public marker: no connector field names or values are disclosed. */
export const REDACTED_SOURCE_CONFIG: Readonly<Record<string, unknown>> = Object.freeze({});

function decodeKek(encoded: string): Buffer | null {
  if (!encoded) return null;
  try {
    const decoded = Buffer.from(encoded, "base64");
    if (decoded.length !== 32 || decoded.toString("base64") !== encoded) return null;
    return decoded;
  } catch {
    return null;
  }
}

function aad(id: string, namespace: Namespace, kind: SourceKind): Buffer {
  return Buffer.from(`halomem-source-config:v1\0${id}\0${namespace}\0${kind}`, "utf8");
}

function asNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function serialized(config: Record<string, unknown>): string {
  const value = JSON.stringify(config);
  if (typeof value !== "string") throw new Error("source configuration must be JSON serializable");
  return value;
}

/**
 * Dedicated AES-256-GCM boundary for connector configuration.
 *
 * HALOMEM_SOURCE_CONFIG_KEK is deliberately distinct from the cold-store KEK.
 * An ephemeral key is permitted only for an in-memory development database;
 * durable databases must provide an explicit key or new config writes fail.
 */
export class SourceConfigCipher {
  private readonly kek: Buffer | null;
  readonly kekId: string | null;

  constructor(encodedKek: string, allowEphemeral = false) {
    const configured = decodeKek(encodedKek);
    this.kek = configured ?? (allowEphemeral && !encodedKek ? randomBytes(32) : null);
    this.kekId = this.kek
      ? `source-config:${createHash("sha256").update(this.kek).digest("hex").slice(0, 24)}`
      : null;
  }

  get available(): boolean {
    return this.kek !== null;
  }

  seal(
    id: string,
    namespace: Namespace,
    kind: SourceKind,
    config: Record<string, unknown>,
  ): SealedSourceConfig {
    if (!this.kek || !this.kekId) {
      throw new Error("source configuration encryption is unavailable");
    }
    const plaintext = Buffer.from(serialized(config), "utf8");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.kek, iv);
    cipher.setAAD(aad(id, namespace, kind));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      kekId: this.kekId,
      // AES-GCM's authentication tag already protects ciphertext integrity.
      // Never persist an unkeyed plaintext digest: it becomes an offline
      // guessing oracle for low-entropy passwords and Basic-auth secrets.
      sha256: "gcm-v1",
    };
  }

  open(row: StoredSourceConfig): Record<string, unknown> {
    if (!this.kek || !this.kekId) {
      throw new Error("source configuration is unavailable");
    }
    const storedKekId = asNonEmptyString(row.config_kek_id);
    const ciphertext = asNonEmptyString(row.config_ciphertext);
    const iv = asNonEmptyString(row.config_iv);
    const tag = asNonEmptyString(row.config_tag);
    if (!storedKekId || !ciphertext || !iv || !tag) {
      throw new Error("source configuration is unavailable");
    }
    const expected = Buffer.from(this.kekId, "utf8");
    const actual = Buffer.from(storedKekId, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      throw new Error("source configuration is unavailable");
    }
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.kek, Buffer.from(iv, "base64"));
      decipher.setAAD(aad(row.id, row.namespace, row.kind));
      decipher.setAuthTag(Buffer.from(tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]);
      const parsed = JSON.parse(plaintext.toString("utf8")) as unknown;
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
        throw new Error("invalid source configuration");
      }
      return parsed as Record<string, unknown>;
    } catch {
      throw new Error("source configuration is unavailable");
    }
  }
}

function collectSecretStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    if (value.length >= 2) out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectSecretStrings(item, out);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) {
      collectSecretStrings(item, out);
    }
  }
}

/** Remove connector values and common credential forms before persistence/API return. */
export function redactSourceError(
  error: unknown,
  config?: Record<string, unknown>,
): string {
  let safe = error instanceof Error ? error.message : String(error);
  const secrets: string[] = [];
  if (config) collectSecretStrings(config, secrets);
  secrets.sort((a, b) => b.length - a.length);
  for (const secret of secrets) safe = safe.split(secret).join("[redacted]");
  safe = safe
    .replace(/\b(?:postgres|postgresql):\/\/[^\s'"<>]+/gi, "[redacted-dsn]")
    .replace(/:\/\/([^/@\s:]+):([^/@\s]+)@/g, "://[redacted]@")
    .replace(/\bBearer\s+[^\s,;]+/gi, "Bearer [redacted]")
    .replace(/\b(token|password|secret|dsn|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, "$1=[redacted]");
  return safe.slice(0, 500);
}
