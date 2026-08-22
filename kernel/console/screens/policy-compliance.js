import { headingInfo } from "../heading-info.js";

/**
 * S4 guardrail compliance. Answers the three questions a policy owner actually
 * has: did this policy reach the agents, did they acknowledge it, and did any
 * of them act without reading it.
 *
 * Read model: GET /v1/admin/policy-compliance?namespace=<scope>. Every value is
 * server-derived from the append-only policy event ledger — the console never
 * computes standing itself.
 *
 * Shape follows the prototype: four tiles, one pill tab per governed document
 * with that document's meta beside the strip, one agent ledger of row cards,
 * then the recent-activity feed.
 */

const STANDING_LABEL = {
  acknowledged: "Acknowledged",
  served: "Delivered",
  stale: "Stale Copy",
  bypassed: "Bypassed",
  "never-served": "Never Served",
};

const EVENT_VERB = {
  served: "was served",
  acknowledged: "acknowledged",
  applied: "acted under",
  bypassed: "acted WITHOUT reading",
};

const EVENT_TONE = {
  acknowledged: "ok",
  applied: "ok",
  bypassed: "bad",
};

/** Roles the compliance ledger is readable by (the server enforces the same). */
function canRead(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin" || role === "auditor";
}

function count(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

/**
 * @returns {{html: string, bypasses: number|null}} — `bypasses` feeds the
 * register's fourth stat card, and stays null when the ledger is unreadable so
 * that card says Unavailable instead of zero.
 */
export async function renderPolicyCompliance(ctx, namespace) {
  // A member never sees the panel at all rather than an authorization error.
  if (!canRead(ctx)) return { html: "", bypasses: null };
  let report = null;
  let error = null;
  try {
    report = await ctx.api.get(
      "/v1/admin/policy-compliance?namespace=" + encodeURIComponent(namespace),
    );
  } catch (loadError) {
    error = loadError;
  }
  return {
    html: complianceMarkup(ctx, namespace, report, error),
    bypasses: error || !report || !report.summary ? null : count(report.summary.bypassed),
  };
}

function complianceMarkup(ctx, namespace, report, error) {
  const { esc } = ctx;
  const head = `<div class="policy-panel__head">
    <div class="policy-panel__title">
      <h2 id="policy-compliance-title">Agent Compliance</h2>${headingInfo("Agent Compliance", "Every agent that assembles context in this scope is handed the active policy directives before anything else, and acknowledges the version it received. An agent that writes or reads a backend without ever being handed the current version is recorded here as a bypass.")}
    </div>
    ${
      report && report.digest
        ? `<span class="policy-digest" title="Current policy version">v ${esc(
            String(report.digest).slice(0, 12),
          )}</span>`
        : ""
    }
  </div>`;

  if (error) {
    return `<section class="policy-panel policy-compliance" aria-labelledby="policy-compliance-title">${head}
      <div class="policy-error" role="alert"><div><h3>Compliance is temporarily unavailable</h3>
      <p>${esc(error && error.message ? error.message : "The ledger could not be read.")}</p></div>
      <button type="button" class="policy-ghost" data-action="policy-compliance-retry">Retry</button></div>
    </section>`;
  }

  const documents = report && Array.isArray(report.documents) ? report.documents : [];
  if (documents.length === 0) {
    return `<section class="policy-panel policy-compliance" aria-labelledby="policy-compliance-title">${head}
      ${summaryMarkup(esc, report && report.summary)}
      <div class="policy-empty">No governed policy is active in this scope yet.
      <p>Load a policy file and it becomes a guardrail every agent receives.</p></div>
    </section>`;
  }

  return `<section class="policy-panel policy-compliance" aria-labelledby="policy-compliance-title">${head}
    ${summaryMarkup(esc, report.summary)}
    ${tabsMarkup(ctx, documents, namespace)}
    ${documents.map((document, index) => documentMarkup(ctx, document, index)).join("")}
    ${feedMarkup(ctx, report.recent)}
  </section>`;
}

function summaryMarkup(esc, summary) {
  const value = (key) => {
    const parsed = Number(summary && summary[key]);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
  };
  const cells = [
    ["Governed", value("documents"), ""],
    ["Agents In Scope", value("agents"), ""],
    ["Acknowledged", value("acknowledged"), ""],
    ["Bypassed", value("bypassed"), value("bypassed") > 0 ? " policy-tile--crit" : ""],
  ];
  return `<div class="policy-tiles" aria-label="Guardrail compliance summary">${cells
    .map(
      ([label, number, tone]) =>
        `<div class="policy-tile${tone}"><div class="policy-tile__k">${esc(label)}</div><div class="policy-tile__v num">${esc(number)}</div></div>`,
    )
    .join("")}</div>`;
}

/**
 * One tab per governed document, with that document's scope, directive count
 * and level riding beside the strip. The meta is rendered per document and
 * hidden with its panel, so switching tabs needs no text substitution.
 */
function tabsMarkup(ctx, documents, namespace) {
  const { esc } = ctx;
  const tabs = documents.map((document, index) => {
    const on = index === 0;
    return `<button type="button" class="policy-pill-tab${on ? " is-active" : ""}"
      role="tab" aria-selected="${on ? "true" : "false"}" aria-pressed="${on ? "true" : "false"}"
      aria-controls="policy-compliance-panel-${index}"
      data-action="policy-compliance-tab" data-index="${index}">${esc(
        (document && document.title) || "Untitled policy",
      )}</button>`;
  }).join("");
  const metas = documents.map((document, index) => {
    const level = (document && document.enforcement) === "advisory" ? "advisory" : "required";
    const scope = document && document.namespace === namespace
      ? "This scope"
      : `Inherited from ${(document && document.namespace) || "organization root"}`;
    return `<span class="policy-tabs__meta" data-policy-compliance-meta="${index}"${
      index === 0 ? "" : " hidden"
    }>${esc(scope)} &middot; ${esc(Number(document && document.factCount) || 0)} directives &middot; ${esc(
      level,
    )}</span>`;
  }).join("");
  return `<div class="policy-pill-tabs policy-compliance-tabs" role="tablist" aria-label="Governed policies">${tabs}${metas}</div>`;
}

const AGENT_COLUMNS =
  `<span>Agent</span><span>Standing</span><span class="num">Delivered</span>` +
  `<span class="num">Acked</span><span class="num">Bypasses</span><span class="num">Last Delivery</span>`;

function documentMarkup(ctx, document, index) {
  const agents = Array.isArray(document && document.agents) ? document.agents : [];
  return `<div class="policy-compliance-doc" id="policy-compliance-panel-${index}" role="tabpanel"
    data-policy-compliance-panel="${index}"${index === 0 ? "" : " hidden"}>
    ${
      agents.length === 0
        ? `<div class="policy-empty">No agent has been handed this policy yet.
           <p>It is delivered the next time an agent assembles context or calls <code>mem_policy</code>.</p></div>`
        : `<div class="policy-rowscroll"><div class="policy-rowset policy-rowset--agents">
            <div class="policy-rowhead policy-row--agent" aria-hidden="true">${AGENT_COLUMNS}</div>
            <div class="policy-rows" role="list">${agents.map((agent) => agentRow(ctx, agent)).join("")}</div>
          </div></div>`
    }
  </div>`;
}

function agentRow(ctx, agent) {
  const { esc } = ctx;
  const state = Object.hasOwn(STANDING_LABEL, agent && agent.state)
    ? agent.state
    : "never-served";
  const bypasses = count(agent && agent.bypassCount);
  return `<div class="policy-row policy-row--agent" role="listitem">
    <span class="policy-row__text">
      <strong>${esc((agent && agent.agentId) || "unknown")}</strong>
      <small>${esc((agent && agent.actor) || "unknown actor")}</small>
    </span>
    <span><span class="policy-state policy-state--${esc(state)}"><i aria-hidden="true"></i>${esc(
      STANDING_LABEL[state],
    )}</span></span>
    <span class="policy-row__cell num">${esc(count(agent && agent.servedCount))}</span>
    <span class="policy-row__cell num">${esc(
      count(agent && agent.acknowledgedCount) + count(agent && agent.appliedCount),
    )}</span>
    <span class="policy-row__cell num${bypasses > 0 ? " policy-bypass" : ""}">${esc(bypasses)}</span>
    <span class="policy-row__cell num policy-row__when">${esc(
      formatTime(agent && agent.lastServedAt),
    )}</span>
  </div>`;
}

function feedMarkup(ctx, events) {
  const { esc } = ctx;
  const rows = Array.isArray(events) ? events.slice(0, 12) : [];
  if (rows.length === 0) return "";
  return `<div class="policy-feed">
    <div class="policy-feed__head">Recent guardrail activity</div>
    <ol>${rows
      .map((event) => {
        const tone = EVENT_TONE[event && event.kind] || "neutral";
        return `<li><b>${esc((event && event.agentId) || "unknown")}</b>
        <span class="policy-feed__verb policy-feed__verb--${tone}">${esc(
          EVENT_VERB[event && event.kind] || "touched",
        )}</span>
        <span class="policy-feed__doc">${esc((event && event.documentTitle) || "a policy")}</span>
        <time>${esc(formatTime(event && event.ts))}</time></li>`;
      })
      .join("")}</ol>
  </div>`;
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Re-render the compliance panel in place. A new upload changes the governing
 * digest, which changes every agent's standing — leaving the panel stale after
 * an upload would show the previous version's compliance as if it still held.
 * The register's bypass card is refreshed from the same read.
 */
export async function refreshPolicyCompliance(ctx, root, namespace) {
  const host = root.querySelector(".policy-compliance");
  if (!host) return;
  const { html, bypasses } = await renderPolicyCompliance(ctx, namespace);
  if (html) host.outerHTML = html;
  const card = root.querySelector?.("[data-policy-summary] .metric-card--bypass");
  const value = card?.querySelector?.(".v");
  if (value) value.textContent = bypasses === null ? "Unavailable" : String(bypasses);
}

export const policyComplianceActions = {
  /** Swap which governed document's agent ledger is on screen. No refetch. */
  "policy-compliance-tab"(_ctx, el) {
    const section = el.closest?.(".policy-compliance");
    if (!section) return;
    const index = String(el.getAttribute("data-index") || "0");
    for (const tab of section.querySelectorAll?.("[data-action='policy-compliance-tab']") ?? []) {
      const on = String(tab.getAttribute?.("data-index") ?? "") === index;
      tab.setAttribute?.("aria-selected", on ? "true" : "false");
      tab.setAttribute?.("aria-pressed", on ? "true" : "false");
      tab.classList?.toggle?.("is-active", on);
    }
    for (const panel of section.querySelectorAll?.("[data-policy-compliance-panel]") ?? []) {
      panel.hidden = String(panel.getAttribute?.("data-policy-compliance-panel") ?? "") !== index;
    }
    for (const meta of section.querySelectorAll?.("[data-policy-compliance-meta]") ?? []) {
      meta.hidden = String(meta.getAttribute?.("data-policy-compliance-meta") ?? "") !== index;
    }
  },

  async "policy-compliance-retry"(ctx) {
    await ctx.go("s4");
  },
};
