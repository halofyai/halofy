import {
  policyLibraryActions,
  policyScopeNamespace,
  renderPolicyLibrary,
} from "./policy-library.js";
import {
  policyComplianceActions,
  renderPolicyCompliance,
} from "./policy-compliance.js";
import { organizationScopeLabel } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";

/**
 * S4 - Policy dials (Module C / govern).
 *
 * `render(ctx)` fetches GET /v1/admin/policy?namespace=<caller's namespace> -
 * the EFFECTIVE merged policy (PolicyConfigX): { namespace, tokenBudget,
 * ttlDefaultsSeconds{user,assistant,team,org}, pinnedConcepts[],
 * dedupeSimilarityThreshold, verifierEnabled, rateLimitPerMin, monthlyBudgetUsd?,
 * retriever? }. It draws the dials (retriever select, monthly spend cap,
 * customer-data expiry, per-badge rate limit, and the LLM fact verifier.
 *
 * Save → PUT /v1/admin/policy {namespace, yaml}, where the YAML is a MINIMAL doc
 * built from only the dials that changed against the loaded baseline. The policy
 * store validates the YAML (partial overrides), so we emit only known fields.
 *
 * XSS: the namespace and every rendered policy value passes through ctx.esc()
 * (they land in value="" attributes and inherited-from lines).
 *
 * Namespace default: the memory-map/policy namespace param defaults to the
 * caller's own namespace (ux-correctness lens) - never blank, never a sibling.
 */

/** True when the caller may mutate policy (owner/admin); false for auditor/member. */
function canMutate(ctx) {
  const r = ctx.identity && ctx.identity.role;
  return r === "owner" || r === "root" || r === "admin";
}

const RETRIEVERS = ["graph", "baseline", "mem0"];

// Conflict-review dial: when a conflicting write may auto-supersede vs be
// quarantined for the S11 review queue.
const CONFLICT_REVIEW_CHOICES = [
  { value: "lower-trust", label: "Lower-trust writes (default)" },
  { value: "all", label: "Every conflict" },
  { value: "off", label: "Off: newest write wins" },
];

// Expiry select maps a label → seconds (or null for "never"). The dial writes
// ttlDefaultsSeconds.user (customer/user-scope data is the GDPR-relevant tier).
const EXPIRY_CHOICES = [
  { label: "30 days", seconds: 30 * 24 * 60 * 60 },
  { label: "90 days", seconds: 90 * 24 * 60 * 60 },
  { label: "1 year", seconds: 365 * 24 * 60 * 60 },
  { label: "Never", seconds: null },
];

// The loaded baseline, so Save can diff and emit only changed fields.
let baseline = null;

export async function render(ctx) {
  // The scope resolves from the route before any read, so compliance and the
  // dials no longer queue behind the register. The register's bypass card is
  // a compliance figure, so that read has to land before the library renders.
  const ns = policyScopeNamespace(ctx);
  const [compliance, policyRead] = await Promise.all([
    renderPolicyCompliance(ctx, ns),
    ctx.api
      .get("/v1/admin/policy?namespace=" + encodeURIComponent(ns))
      .then((value) => ({ policy: value }), (error) => ({ error })),
  ]);
  const library = await renderPolicyLibrary(ctx, compliance.bypasses);
  const policy = policyRead.policy;
  const policyError = policyRead.error ?? null;
  if (!policy) {
    baseline = null;
    return pageMarkup(
      ctx,
      ns,
      library,
      compliance.html,
      errorScreen(ctx, policyError),
    );
  }
  baseline = policy;

  const mutate = canMutate(ctx);
  // Auditor/member: the dials are read-only (defense in depth - the server 403s
  // the PUT too). Hide Save and disable every input so nothing looks live.
  const dis = mutate ? "" : " disabled";

  const retriever = policy.retriever ?? "baseline";
  const spendCap =
    policy.monthlyBudgetUsd === undefined || policy.monthlyBudgetUsd === null
      ? ""
      : policy.monthlyBudgetUsd;
  const rateLimit = policy.rateLimitPerMin ?? 60;
  const userTtl =
    policy.ttlDefaultsSeconds && policy.ttlDefaultsSeconds.user !== undefined
      ? policy.ttlDefaultsSeconds.user
      : null;
  const verifierOn = policy.verifierEnabled !== false; // default true
  const conflictReview = policy.conflictReview ?? "lower-trust";

  const conflictOpts = CONFLICT_REVIEW_CHOICES.map((c) => {
    const sel = c.value === conflictReview ? " selected" : "";
    return `<option value="${ctx.esc(c.value)}"${sel}>${ctx.esc(c.label)}</option>`;
  }).join("");

  const retrieverOpts = RETRIEVERS.map((r) => {
    const sel = r === retriever ? " selected" : "";
    return `<option value="${ctx.esc(r)}"${sel}>${ctx.esc(r)}</option>`;
  }).join("");

  const expiryOpts = EXPIRY_CHOICES.map((c) => {
    const sel = c.seconds === userTtl ? " selected" : "";
    const val = c.seconds === null ? "null" : String(c.seconds);
    return `<option value="${val}"${sel}>${ctx.esc(c.label)}</option>`;
  }).join("");

  const runtime = `
    <div class="policy-dials">
      <div class="policy-dial-card"><div class="policy-dial-card__title">Retrieval &amp; Verification</div>
        <div class="policy-field"><label for="dial-retriever">Retriever</label>
          <select class="select policy-control" id="dial-retriever"${dis}>${retrieverOpts}</select></div>
        <div class="policy-field"><label for="dial-verifier">LLM fact verifier</label>
          <label class="toggle policy-switch"><input type="checkbox" id="dial-verifier"${
            verifierOn ? " checked" : ""
          }${dis}><span class="track"></span>Verify extracted (non-verbatim) facts before storage</label></div>
        <div class="policy-field"><label for="dial-conflict">Conflict review</label>
          <select class="select policy-control" id="dial-conflict"${dis}>${conflictOpts}</select></div>
      </div>
      <div class="policy-dial-card"><div class="policy-dial-card__title">Budget &amp; Retention</div>
        <div class="policy-field"><label for="dial-spend">Monthly spend cap (USD)</label>
          <input class="policy-control num" id="dial-spend" value="${ctx.esc(
            spendCap,
          )}" placeholder="None" inputmode="decimal"${dis}>
          <div class="policy-hint">Effective cap: <b>${
            spendCap === "" ? "none" : "$" + ctx.esc(spendCap)
          }</b></div></div>
        <div class="policy-field"><label for="dial-expiry">Customer-data expiry (user scope)</label>
          <select class="select policy-control" id="dial-expiry"${dis}>${expiryOpts}</select>
          <div class="policy-hint">Effective TTL: <b>${ctx.esc(
            ttlLabel(userTtl),
          )}</b></div></div>
        <div class="policy-field"><label for="dial-rate">Rate limit (requests / min per badge)</label>
          <input class="policy-control num" id="dial-rate" value="${ctx.esc(
            rateLimit,
          )}" inputmode="numeric"${dis}>
          <div class="policy-hint">Effective rate limit: <b>${ctx.esc(
            rateLimit,
          )}</b> req/min</div></div>
      </div>
    </div>
    <div class="policy-runtime-foot">
      <div id="policy-status" class="policy-status" role="status" aria-live="polite"></div>
      ${
        mutate
          ? `<button type="button" class="policy-primary" data-action="policy-save">Save Changes</button>`
          : `<span class="pill"><i class="dot"></i>Read-only</span>`
      }
    </div>`;
  return pageMarkup(ctx, ns, library, compliance.html, runtime);
}

function pageMarkup(ctx, namespace, library, complianceHtml, runtimeHtml) {
  const namespaceLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const acts = library.headActions
    ? `<div class="acts">${library.headActions}</div>`
    : "";
  // The info icon is a sibling of the title, not part of it: the prototype
  // sets the two in one flex row, and the h1 stays the page's one heading.
  return `<div class="policy-screen screen-flow">
    <div class="head policy-page-head"><div><div class="eyebrow">Govern · ${ctx.esc(namespaceLabel)}</div>
      <div class="policy-title"><h1>Policies</h1>${headingInfo(
        "Policies",
        "Governed documents every agent is handed before it acts. Delivery, acknowledgement and bypasses are recorded on an append-only ledger &mdash; the console never computes standing itself.",
      )}</div></div>${acts}</div>
    ${library.html}
    ${complianceHtml}
    <details class="policy-runtime"><summary><i aria-hidden="true"></i><span><b>Runtime Policy Dials</b>${headingInfo(
      "Runtime Policy Dials",
      `Effective defaults for ${ctx.esc(namespaceLabel)} &mdash; every scope inherits these unless overridden`,
    )}</span></summary>
      <div class="policy-runtime-body">${runtimeHtml}</div>
    </details>
  </div>`;
}

function ttlLabel(seconds) {
  if (seconds === null || seconds === undefined) return "never expires";
  const found = EXPIRY_CHOICES.find((c) => c.seconds === seconds);
  if (found) return found.label;
  return Math.round(seconds / 86400) + " days";
}

function errorScreen(ctx, err) {
  const msg = ctx.esc(err && err.message ? err.message : "Could not load policy.");
  return `<div class="policy-error" role="alert"><div><h3>Runtime policy dials are unavailable</h3><p>${msg}</p></div></div>`;
}

export const actions = {
  ...policyLibraryActions,
  ...policyComplianceActions,
  /** Diff the dials against the loaded baseline, PUT a minimal YAML override. */
  async "policy-save"(ctx, el) {
    const root = el.closest(".screen") ?? document;
    const status = root.querySelector("#policy-status");
    if (!baseline) {
      if (status) status.textContent = "Policy not loaded. Reopen this screen.";
      return;
    }
    const ns =
      baseline.namespace ?? (ctx.identity && ctx.identity.namespace) ?? "";

    const changes = {};

    // Retriever
    const retriever = root.querySelector("#dial-retriever")?.value;
    const baseRetriever = baseline.retriever ?? "baseline";
    if (retriever && retriever !== baseRetriever) changes.retriever = retriever;

    // Verifier toggle (auto-remember)
    const verifier = !!root.querySelector("#dial-verifier")?.checked;
    const baseVerifier = baseline.verifierEnabled !== false;
    if (verifier !== baseVerifier) changes.verifierEnabled = verifier;

    // Conflict review mode
    const conflict = root.querySelector("#dial-conflict")?.value;
    const baseConflict = baseline.conflictReview ?? "lower-trust";
    if (conflict && conflict !== baseConflict) changes.conflictReview = conflict;

    // Monthly spend cap
    const spendRaw = (root.querySelector("#dial-spend")?.value ?? "").trim();
    const baseSpend =
      baseline.monthlyBudgetUsd === undefined || baseline.monthlyBudgetUsd === null
        ? ""
        : String(baseline.monthlyBudgetUsd);
    if (spendRaw !== baseSpend && spendRaw !== "") {
      const n = Number(spendRaw);
      if (!Number.isFinite(n) || n < 0) {
        if (status) status.textContent = "Spend cap must be a non-negative number.";
        return;
      }
      changes.monthlyBudgetUsd = n;
    }

    // Rate limit
    const rateRaw = (root.querySelector("#dial-rate")?.value ?? "").trim();
    const baseRate = String(baseline.rateLimitPerMin ?? 60);
    if (rateRaw !== baseRate) {
      const n = Number(rateRaw);
      if (!Number.isInteger(n) || n <= 0) {
        if (status) status.textContent = "Rate limit must be a positive integer.";
        return;
      }
      changes.rateLimitPerMin = n;
    }

    // Expiry (user-scope TTL)
    const expiryVal = root.querySelector("#dial-expiry")?.value;
    const baseTtl =
      baseline.ttlDefaultsSeconds && baseline.ttlDefaultsSeconds.user !== undefined
        ? baseline.ttlDefaultsSeconds.user
        : null;
    const chosenTtl = expiryVal === "null" ? null : Number(expiryVal);
    if (chosenTtl !== baseTtl) {
      changes.ttlDefaultsSeconds = { user: chosenTtl };
    }

    if (Object.keys(changes).length === 0) {
      if (status) status.textContent = "No changes to save.";
      return;
    }

    const yaml = buildYaml(changes);
    if (status) status.textContent = "Saving…";
    try {
      await ctx.api.put("/v1/admin/policy", { namespace: ns, yaml });
    } catch (err) {
      if (status) {
        status.textContent =
          "Save failed: " + (err && err.message ? err.message : "unknown error");
      }
      return;
    }
    await ctx.go("s4");
  },
};

/** Build a minimal, valid policy YAML doc from the changed dials. */
function buildYaml(changes) {
  const lines = [];
  if (changes.retriever !== undefined) {
    lines.push(`retriever: ${JSON.stringify(changes.retriever)}`);
  }
  if (changes.verifierEnabled !== undefined) {
    lines.push(`verifierEnabled: ${changes.verifierEnabled ? "true" : "false"}`);
  }
  if (changes.conflictReview !== undefined) {
    lines.push(`conflictReview: ${JSON.stringify(changes.conflictReview)}`);
  }
  if (changes.monthlyBudgetUsd !== undefined) {
    lines.push(`monthlyBudgetUsd: ${changes.monthlyBudgetUsd}`);
  }
  if (changes.rateLimitPerMin !== undefined) {
    lines.push(`rateLimitPerMin: ${changes.rateLimitPerMin}`);
  }
  if (changes.ttlDefaultsSeconds !== undefined) {
    lines.push(`ttlDefaultsSeconds:`);
    const v = changes.ttlDefaultsSeconds.user;
    lines.push(`  user: ${v === null ? "null" : v}`);
  }
  return lines.join("\n") + "\n";
}
