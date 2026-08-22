import { organizationScopeLabel } from "../identity-labels.js";

// S9 - Retriever scorecard.
//
// Runs POST /v1/admin/scorecard {namespace:<caller's namespace>} and renders the
// returned Scorecard (src/referee/index.ts):
//   { id, namespace, ranAt, questionCount,
//     drivers:[{driver, questions, hitAt3, meanTokens, p95LatencyMs, errors}],
//     winner }
//
// Renders the engine table (hit@3 / tokens / p95 latency / errors), a winner
// pill, and a per-loser Switch action → PUT /v1/admin/policy setting retriever.
// If the run errors "no facts", show ui.empty. Switch is hidden for
// auditor/member (the server still enforces). Every API value passes esc().

/**
 * @param {import('../app.js').Ctx} ctx
 * @returns {Promise<string>}
 */
export async function render(ctx) {
  const { esc, ui } = ctx;
  const identityNamespace = (ctx.identity && ctx.identity.namespace) || "";
  const scopes = await availableScopes(ctx, identityNamespace);
  const requested = requestedScope();
  const namespace = scopes.some((scope) => scope.namespace === requested)
    ? requested
    : identityNamespace;
  const nsLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const canSwitch = canMutate(ctx);

  const head = ui.head({
    eyebrow: "Operate · " + esc(nsLabel),
    title: "Retrieval quality",
  });
  const scopePicker = scopes.length > 1
    ? '<div class="card scorecard-scope"><div class="field" style="margin:0"><label for="scorecard-scope">Run for</label>' +
      '<select class="select" id="scorecard-scope" data-change-action="scorecard-scope">' +
      scopes.map((scope) => `<option value="${esc(scope.namespace)}"${scope.namespace === namespace ? " selected" : ""}>${esc(scope.label)}</option>`).join("") +
      '</select><div class="hint">Choose a team with enough facts for a meaningful comparison.</div></div></div>'
    : "";

  let card;
  try {
    card = await ctx.api.post("/v1/admin/scorecard", { namespace });
  } catch (err) {
    // The backend maps "no facts / no drivers" to a 400 - surface the honest
    // empty state, not a raw error.
    const msg = err && err.message ? String(err.message) : "";
    if (/no facts|no drivers|no scorable|distinctive tokens/i.test(msg)) {
      return (
        head + scopePicker +
        ui.empty(
          "Not enough facts in " +
            esc(nsLabel) +
            " to run the referee yet. The scorecard needs facts with distinctive content to build questions from.",
        ) +
        (canSwitch
          ? '<div class="row" style="margin-top:var(--s3)"><button class="btn btn--solid" data-action="scorecard-open-sources">Add memory sources</button></div>'
          : "")
      );
    }
    return (
      head + scopePicker +
      ui.empty("Scorecard run failed" + (msg ? ": " + esc(msg) : "."))
    );
  }

  const drivers = Array.isArray(card && card.drivers) ? card.drivers : [];
  const winner = card && card.winner != null ? String(card.winner) : "";
  const questionCount = num(card && card.questionCount);
  const ranAt = card && card.ranAt ? formatWhen(card.ranAt) : "";
  let effectiveRetriever = "";
  try {
    const policy = await ctx.api.get(
      "/v1/admin/policy?namespace=" + encodeURIComponent(namespace),
    );
    if (policy && policy.retriever != null) effectiveRetriever = String(policy.retriever);
  } catch {
    // The benchmark remains useful, but the UI must not guess which retriever is live.
  }

  if (drivers.length === 0) {
    return (
      head + scopePicker +
      ui.empty(
        "The referee produced no driver scores for " + esc(nsLabel) + ".",
      )
    );
  }

  const rows = drivers
    .map(function (d) {
      // Referee field is `driver`; tolerate a `name` alias defensively.
      const name =
        d && d.driver != null
          ? String(d.driver)
          : d && d.name != null
            ? String(d.name)
            : "";
      const isWinner = name === winner;
      const isLive = effectiveRetriever !== "" && name === effectiveRetriever;
      const hit = fmtFloat(d && d.hitAt3, 2);
      const tokens = fmt(Math.round(num(d && d.meanTokens)));
      const p95 = fmtFloat(d && d.p95LatencyMs, 0);
      const errors = num(d && d.errors);

      const verdict =
        (isWinner
          ? '<span class="pill pill--ok"><i class="dot"></i>Benchmark winner</span> '
          : "") +
        (isLive
          ? '<span class="pill pill--live"><i class="dot"></i>Effective live retriever</span>'
          : !isWinner
            ? '<span class="subtle">candidate</span>'
            : "");

      // Switch only for losers, and only when the caller may mutate policy.
      const switchCell =
        !isLive && canSwitch
          ? '<td><button class="btn btn--outline btn--sm" data-action="switch-retriever" data-retriever="' +
            esc(name) +
            '" data-namespace="' + esc(namespace) +
            '">Switch</button></td>'
          : "<td></td>";

      return (
        "<tr><td>" +
        (isWinner ? "<b>" + esc(name) + "</b>" : esc(name)) +
        "</td>" +
        '<td class="num">' +
        hit +
        "</td>" +
        '<td class="num">' +
        tokens +
        "</td>" +
        '<td class="num">' +
        p95 +
        " ms</td>" +
        '<td class="num">' +
        fmt(errors) +
        "</td>" +
        "<td>" +
        verdict +
        "</td>" +
        switchCell +
        "</tr>"
      );
    })
    .join("");

  const tableCard =
    '<div class="card"><div class="between"><h3>' +
    esc(nsLabel) +
    " · " +
    questionCount +
    "-question referee run</h3>" +
    (ranAt ? '<span class="eyebrow">ran ' + esc(ranAt) + "</span>" : "") +
    "</div>" +
    '<div class="tblwrap" style="margin-top:var(--s3)"><table>' +
    "<thead><tr><th>Engine</th><th class=\"num\">Hit @ 3</th><th class=\"num\">Tokens / query</th><th class=\"num\">p95 latency</th><th class=\"num\">Errors</th><th>Verdict</th>" +
    (canSwitch ? "<th></th>" : "<th></th>") +
    "</tr></thead>" +
    "<tbody>" +
    rows +
    "</tbody></table></div>" +
    '<details class="compact-disclosure scorecard-method"><summary>How scoring works</summary>' +
    '<div class="compact-disclosure__body legend"><span><i style="background:#123a2e"></i>Higher hit@3 is better · lower tokens &amp; latency are better</span>' +
    '<span>Winner picked by hit@3, tie-broken by fewer errors then tokens.</span></div></details>' +
    "</div>";

  const effectiveLabel = effectiveRetriever || "Not reported by policy";
  // Benchmark and runtime policy are intentionally separate facts.
  const winnerCard =
    '<div class="card" style="margin-top:var(--s4)"><div class="grid g2">' +
    '<div class="stat"><div class="stat-label"><div class="k">Benchmark winner</div>' +
    statInfo("Benchmark winner", "latest referee run") + '</div><div class="v">' +
    esc(winner || "No winner") +
    '</div></div>' +
    '<div class="stat"><div class="stat-label"><div class="k">Effective live retriever</div>' +
    statInfo("Effective live retriever", "current effective policy") + '</div><div class="v">' +
    esc(effectiveLabel) +
    '</div></div></div>' +
    (canSwitch && winner && winner !== effectiveRetriever
      ? '<button class="btn btn--solid btn--sm" data-action="switch-retriever" data-retriever="' +
        esc(winner) +
        '" data-namespace="' + esc(namespace) +
        '">Switch live policy to ' +
        esc(winner) +
        "</button>"
      : "") +
    "</div>";

  return head + scopePicker + tableCard + winnerCard;
}

// ---------------------------------------------------------------------------
// Actions (wired by app.js via data-action).
// ---------------------------------------------------------------------------

export const actions = {
  async "scorecard-open-sources"(ctx) {
    await ctx.go("s6");
  },

  async "scorecard-scope"(ctx, el) {
    const namespace = el && "value" in el ? String(el.value ?? "") : "";
    await ctx.go("s9?scope=" + encodeURIComponent(namespace));
  },

  /**
   * PUT /v1/admin/policy setting the retriever for the rendered, server-validated namespace. A
   * partial policy override document - only `retriever`. Re-render to reflect
   * the switch (and the next referee run marks it live).
   * @param {import('../app.js').Ctx} ctx
   * @param {HTMLElement} el the clicked [data-action="switch-retriever"] element
   */
  async "switch-retriever"(ctx, el) {
    const retriever =
      el && el.getAttribute ? el.getAttribute("data-retriever") : "";
    if (!retriever) return;
    const namespace = el && el.getAttribute ? String(el.getAttribute("data-namespace") ?? "") : "";
    const yaml = JSON.stringify({ retriever });
    await ctx.api.put("/v1/admin/policy", { yaml, namespace });
    if (typeof ctx.go === "function") ctx.go("s9?scope=" + encodeURIComponent(namespace));
  },
};

async function availableScopes(ctx, baseNamespace) {
  const scopes = [{
    namespace: baseNamespace,
    label: baseNamespace === "" ? "Organization root" : baseNamespace,
  }];
  try {
    const response = await ctx.api.get("/v1/admin/teams");
    const teams = Array.isArray(response) ? response : Array.isArray(response?.teams) ? response.teams : [];
    for (const team of teams) {
      const namespace = String(team?.namespace ?? "");
      const inSubtree = baseNamespace === "" || namespace === baseNamespace || namespace.startsWith(baseNamespace + "/");
      if (!namespace || !inSubtree || scopes.some((scope) => scope.namespace === namespace)) continue;
      scopes.push({ namespace, label: String(team?.name ?? namespace) + " · " + namespace });
    }
  } catch {
    // Scorecard remains usable at the caller's own server-resolved scope.
  }
  return scopes;
}

function requestedScope() {
  if (typeof window === "undefined") return "";
  const query = String(window.location.hash || "").split("?", 2)[1] ?? "";
  return new URLSearchParams(query).get("scope") ?? "";
}

// --- local formatting helpers (numeric only; never touch raw API text) ---

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function fmt(n) {
  const x = Number(n) || 0;
  return x.toLocaleString("en-US");
}

function fmtFloat(v, digits) {
  const n = Number(v);
  if (!Number.isFinite(n)) return (0).toFixed(digits);
  return n.toFixed(digits);
}

function statInfo(label, detail) {
  return '<span class="metric-info stat-info" role="note" tabindex="0" aria-label="' + label + ": " + detail + '" data-tip="' + detail + '"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span>';
}

/** True when the caller may switch the retriever (owner/admin). */
function canMutate(ctx) {
  const role = ctx.identity && ctx.identity.role;
  return role === "owner" || role === "root" || role === "admin";
}

/** Human "time ago" from an ISO timestamp. */
function formatWhen(iso) {
  const t = Date.parse(String(iso));
  if (!Number.isFinite(t)) return String(iso);
  const secs = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return mins + (mins === 1 ? " min ago" : " mins ago");
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + (hrs === 1 ? " hour ago" : " hours ago");
  const days = Math.floor(hrs / 24);
  return days + (days === 1 ? " day ago" : " days ago");
}
