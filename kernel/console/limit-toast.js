/**
 * Limit-reached notifications for the shared action toaster.
 *
 * Every allowance denial the kernel can return (early-access 402s, credit
 * refusals, the per-minute rate clamp, the one-turn-at-a-time Assistant guard)
 * is translated here into ONE toast shape, so a limit reads the same whether
 * it was hit from Sources, the Assistant dock, an export, or a background
 * poll. The API client calls `notify` on every failed response; screens keep
 * no limit copy of their own.
 *
 * Pure module: no DOM access. `createLimitNotifier` takes the toaster so the
 * mapping and the dedupe window are testable without a document.
 */

/** Console labels for the metered features; mirrors S22 Billing. */
export const LIMIT_FEATURE_LABELS = Object.freeze({
  assistant_luna: "Luna Assistant turns",
  assistant_grok: "Assistant turns",
  retrieval: "Memory retrievals",
  memory_write: "Memory writes",
  ingest_bytes: "Ingested content",
  file: "Files",
  file_bytes: "File upload size",
  source: "Connected sources",
  source_sync: "Source syncs",
  automation: "Automations",
  consolidation: "Consolidation runs",
  conflict_scan: "Conflict scans",
  export: "Exports",
});

const BYTE_FEATURES = new Set(["ingest_bytes", "file_bytes"]);
const TEAM_FEATURES = new Set([
  "source",
  "source_sync",
  "ingest_bytes",
  "consolidation",
  "conflict_scan",
]);

/** Limit toasts stay up longer than a success confirmation: they explain why
 * something did NOT happen, and the reader was mid-task. */
export const LIMIT_TOAST_DURATION_MS = 9000;

function ownerHint(owner) {
  return owner
    ? "Open Billing to see every allowance."
    : "Ask your organization owner about allowances.";
}

function fmtInt(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString("en-US") : "";
}

function fmtMb(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return "";
  const mb = Math.round((n / (1024 * 1024)) * 10) / 10;
  return String(Number.isInteger(mb) ? mb : mb.toFixed(1)) + " MB";
}

function serverMessage(error) {
  return error && typeof error.message === "string" && error.message.trim() !== ""
    ? error.message.trim()
    : "";
}

/**
 * Translate a failed API response into a toast, or null when the failure is
 * not a limit (validation, not-found, server fault - those stay with the
 * screen's own error region).
 *
 * `error` is the object the console API client throws:
 *   { status, message, code?, feature?, limit?, retryAfter? }
 */
export function limitNotificationFor(error, { owner = false } = {}) {
  if (!error || typeof error !== "object") return null;
  const status = Number(error.status);
  const code = typeof error.code === "string" ? error.code : "";
  const feature = typeof error.feature === "string" ? error.feature : "";
  const limit = error.limit;
  const hint = ownerHint(owner);
  const base = { tone: "danger", duration: LIMIT_TOAST_DURATION_MS };

  if (status === 429 || code === "rate_limited") {
    const retry = Number(error.retryAfter);
    return {
      ...base,
      key: "429",
      title: "Request limit reached",
      message:
        "Too many requests in one minute." +
        (Number.isFinite(retry) && retry > 0 ? ` Try again in ${Math.ceil(retry)}s.` : " Try again shortly."),
    };
  }

  if (status === 409 && code === "turn_in_progress") {
    return {
      ...base,
      key: "409:turn_in_progress",
      title: "Assistant is still answering",
      message: "One Assistant turn runs at a time. Wait for the current reply to finish.",
    };
  }

  if (status !== 402) return null;

  switch (code) {
    case "quota_exhausted": {
      const label = LIMIT_FEATURE_LABELS[feature] || "Allowance";
      const amount = BYTE_FEATURES.has(feature) ? fmtMb(limit) : fmtInt(limit);
      const who = TEAM_FEATURES.has(feature) ? "Your team has" : "You have";
      return {
        ...base,
        key: `402:${code}:${feature}`,
        title: `${label} limit reached`,
        message:
          `${who} used all ${amount ? amount + " " : ""}${label.toLowerCase()} included in early access. ${hint}`,
      };
    }
    case "trial_expired":
      return {
        ...base,
        key: "402:trial_expired",
        title: "Early access trial ended",
        message: `Metered actions are paused. Your data and read-only access stay available. ${hint}`,
      };
    case "seat_limit":
      return {
        ...base,
        key: "402:seat_limit",
        title: "Team seat limit reached",
        message:
          `Early access includes ${fmtInt(limit) || "a fixed number of"} seats per team, and they are all taken. ${hint}`,
      };
    case "spend_cap":
      return {
        ...base,
        key: "402:spend_cap",
        title: "Assistant spending cap reached",
        message:
          `Early access caps Assistant provider cost at $${fmtInt(limit) || "the plan amount"} per person for the trial. ${hint}`,
      };
    case "model_not_allowed":
      return {
        ...base,
        key: "402:model_not_allowed",
        title: "Model not included in your plan",
        message: "Switch to GPT-5.6 Luna, the model included in early access.",
      };
    case "unpriced_model":
      return {
        ...base,
        key: "402:unpriced_model",
        title: "Model unavailable right now",
        message: serverMessage(error) || "This model has no trusted price today, so it cannot run.",
      };
    case "credits_exhausted":
      return {
        ...base,
        key: "402:credits_exhausted",
        title: "Credits exhausted",
        message: `${serverMessage(error) || "This workspace has no credits left for that action."} ${hint}`,
      };
    default:
      return {
        ...base,
        key: `402:${code || "unknown"}`,
        title: "Allowance reached",
        message: `${serverMessage(error) || "That action is outside your current allowance."} ${hint}`,
      };
  }
}

/** True when the failure is a limit the toaster will announce; screens use
 * this to skip their own inline copy for the same event. */
export function isLimitError(error) {
  return limitNotificationFor(error) !== null;
}

/**
 * Wrap a toaster with the limit mapping and a short dedupe window: a screen
 * that fires several requests at once (Sources loads four) must not stack four
 * identical "trial ended" toasts.
 */
export function createLimitNotifier(
  toaster,
  { owner = () => false, now = () => Date.now(), windowMs = 4000 } = {},
) {
  const recent = new Map();
  return {
    notify(error) {
      const notification = limitNotificationFor(error, { owner: owner() === true });
      if (!notification) return false;
      const at = now();
      const last = recent.get(notification.key);
      if (last !== undefined && at - last < windowMs) return false;
      recent.set(notification.key, at);
      if (toaster && typeof toaster.show === "function") toaster.show(notification);
      return true;
    },
  };
}
