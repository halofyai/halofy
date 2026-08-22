import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_WEBHOOK_AGE_SECONDS = 300;
const MAX_WEBHOOK_BODY_BYTES = 256 * 1024;
const MAX_WEBHOOK_RECORDS = 100;
const MAX_WEBHOOK_TEXT_LENGTH = 16_384;
const EVENT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;
const CLASSIFICATION_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;

export interface VerifiedWebhookRecord {
  id: string;
  text: string;
  eventTime?: string;
  classification?: string;
}

export class WebhookAuthorizationError extends Error {
  override readonly name = "WebhookAuthorizationError";
}

export class WebhookValidationError extends Error {
  override readonly name = "WebhookValidationError";
}

export class WebhookDeliveryError extends Error {
  override readonly name = "WebhookDeliveryError";
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const admitted = new Set(allowed);
  return Object.keys(value).every((key) => admitted.has(key));
}

/**
 * Authenticate the raw request before parsing it, then admit only the fixed
 * server-owned event envelope. Namespace, actor, ACL, and arbitrary source
 * payload fields never reach connector configuration or the write path.
 */
export function verifyWebhookEnvelope(
  signingSecret: string,
  rawBody: string,
  timestamp: string,
  signature: string,
  now = Date.now(),
): VerifiedWebhookRecord[] {
  if (Buffer.byteLength(rawBody, "utf8") > MAX_WEBHOOK_BODY_BYTES) {
    throw new WebhookValidationError("webhook payload exceeds 256KiB");
  }
  if (signingSecret.length < 32 || !/^\d{10,13}$/.test(timestamp)) {
    throw new WebhookAuthorizationError("invalid webhook signature");
  }
  const timestampNumber = Number(timestamp);
  const timestampMs = timestamp.length === 13 ? timestampNumber : timestampNumber * 1_000;
  if (!Number.isSafeInteger(timestampNumber) || Math.abs(now - timestampMs) > MAX_WEBHOOK_AGE_SECONDS * 1_000) {
    throw new WebhookAuthorizationError("invalid webhook signature");
  }
  const match = /^sha256=([0-9a-f]{64})$/i.exec(signature);
  if (!match) throw new WebhookAuthorizationError("invalid webhook signature");
  const supplied = Buffer.from(match[1], "hex");
  const expected = createHmac("sha256", signingSecret)
    .update(`${timestamp}.${rawBody}`)
    .digest();
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new WebhookAuthorizationError("invalid webhook signature");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody) as unknown;
  } catch {
    throw new WebhookValidationError("webhook body is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      !exactKeys(parsed as Record<string, unknown>, ["records"])) {
    throw new WebhookValidationError("webhook body must contain only 'records'");
  }
  const records = (parsed as Record<string, unknown>).records;
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_WEBHOOK_RECORDS) {
    throw new WebhookValidationError("webhook records must contain 1..100 events");
  }

  return records.map((raw, index) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw) ||
        !exactKeys(raw as Record<string, unknown>, ["id", "text", "eventTime", "classification"])) {
      throw new WebhookValidationError(`webhook record ${index} has undeclared fields`);
    }
    const record = raw as Record<string, unknown>;
    if (typeof record.id !== "string" || !EVENT_ID_PATTERN.test(record.id)) {
      throw new WebhookValidationError(`webhook record ${index} has an invalid id`);
    }
    if (typeof record.text !== "string" || record.text.trim().length === 0 ||
        record.text.length > MAX_WEBHOOK_TEXT_LENGTH) {
      throw new WebhookValidationError(`webhook record ${index} has invalid text`);
    }
    if (record.eventTime !== undefined &&
        (typeof record.eventTime !== "string" || Number.isNaN(Date.parse(record.eventTime)))) {
      throw new WebhookValidationError(`webhook record ${index} has an invalid eventTime`);
    }
    if (record.classification !== undefined &&
        (typeof record.classification !== "string" ||
          !CLASSIFICATION_PATTERN.test(record.classification))) {
      throw new WebhookValidationError(`webhook record ${index} has an invalid classification`);
    }
    return {
      id: record.id,
      text: record.text,
      ...(typeof record.eventTime === "string" ? { eventTime: record.eventTime } : {}),
      ...(typeof record.classification === "string"
        ? { classification: record.classification }
        : {}),
    };
  });
}
