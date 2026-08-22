import { organizationScopeLabel } from "../identity-labels.js";
import { headingInfo } from "../heading-info.js";
import { isLimitError } from "../limit-toast.js";
import { metricCard as stat } from "../metric-card.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";

/**
 * S7 — Knowledge Operations.
 *
 * One operator workspace over the existing governed primitives:
 *   - fresh-summary delta sync (L2 evidence -> review drafts),
 *   - the canonical /readiness memory-health read model,
 *   - proposal review and resumable publication,
 *   - durable sync history.
 *
 * Search embeddings are deliberately not a manual control here. They are a
 * derived index maintained by the normal write path; this screen never creates
 * a second indexing or retrieval authority.
 */

const HEALTH_FACTORS = [
  { pillarId: "trust", label: "Factual Validity", tip: "Whether your saved knowledge contradicts itself." },
  { pillarId: "structure", label: "Hygiene & Deduplication", tip: "How clean the store is." },
  { pillarId: "freshness", label: "Recency & Decay", tip: "Whether what we hold is still current." },
  { pillarId: "coverage", label: "Intake Completeness", tip: "Whether submitted knowledge actually made it into memory." },
];

const HEALTH_TARGETS = {
  freshness: { screen: "s6", label: "Review sources" },
  coverage: { screen: "s6", label: "Improve coverage" },
  retrieval: { screen: "s6", label: "Review sources" },
  gaps: { screen: "s5", label: "Review gaps" },
  trust: { screen: "s11", label: "Review conflicts" },
  structure: { screen: "s5", label: "Review memory map" },
};

export async function render(ctx) {
  const namespace = ctx.identity?.namespace ?? "";
  const role = ctx.identity?.role;
  const canReview = role === "owner" || role === "root" || role === "admin";
  const canSync = role === "owner" || role === "root";

  // Independent reads brown out independently. A failed health or activity
  // read must not hide a proposal that still needs a human decision.
  const requests = [
    ctx.api.get("/v1/admin/proposals"),
    namespace
      ? ctx.api.get("/v1/admin/proposals/metrics?namespace=" + encodeURIComponent(namespace))
      : Promise.resolve(null),
    ctx.api.get("/v1/admin/readiness"),
    canSync ? ctx.api.get("/v1/admin/teams") : Promise.resolve(null),
    canReview ? ctx.api.get("/v1/admin/knowledge-sync") : Promise.resolve(null),
  ];
  const [proposalResult, metricResult, readinessResult, teamResult, activityResult] =
    await Promise.allSettled(requests);

  const proposalsValue = settledValue(proposalResult);
  const proposalsAvailable = Array.isArray(proposalsValue);
  const proposals = proposalsAvailable ? proposalsValue : [];
  const metrics = settledObject(metricResult);
  const readiness = settledObject(readinessResult);
  const teamsValue = settledValue(teamResult);
  const teams = Array.isArray(teamsValue) ? teamsValue : [];
  const activity = settledObject(activityResult);
  const teamsAvailable = !canSync || (teamResult.status === "fulfilled" && Array.isArray(teamsValue));
  const activityAvailable = canReview && activityResult.status === "fulfilled" && activity !== null;

  const pending = proposals.filter((proposal) => proposal?.status === "pending_review");
  const publishing = proposals.filter((proposal) => proposal?.status === "publishing");
  const actionable = [...publishing, ...pending];
  const scopeLabel = organizationScopeLabel(
    namespace,
    ctx.organizationName,
    ctx.identity?.namespace,
  );
  const canSyncOrganization = canSync && teamsAvailable &&
    !teams.some((team) => team?.namespace === namespace);
  const targetOptions = syncTargetOptions(ctx, teams, canSyncOrganization);
  const canQueue = canSync && targetOptions !== "";

  const panels = [
    canQueue ? updatePanel(ctx, targetOptions, namespace === "") : "",
    readiness ? healthPanel(ctx, readiness) : "",
    ...actionable.map((proposal, index) => proposalPanel(ctx, proposal, index, canReview)),
  ].join("");

  return shell(
    head(ctx, scopeLabel, canQueue, namespace === "") +
      summary(ctx, {
        pending: proposalsAvailable ? pending.length : null,
        publishing: proposalsAvailable ? publishing.length : null,
        activity: canReview ? activity : null,
        showActivity: canReview,
        activityAvailable,
        readiness,
        metrics,
        namespace,
      }) +
      '<div class="home-dashboard knowledge-dashboard">' +
      updateCard(ctx, {
        canSync,
        canQueue,
        canReview,
        teamsAvailable,
        activityAvailable,
        organizationRoot: namespace === "",
        activity,
      }) +
      healthCard(ctx, readiness) +
      reviewLane(ctx, actionable, proposalsAvailable, canReview) +
      (canReview ? activityLane(ctx, activity, activityAvailable) : "") +
      "</div>" +
      panels,
  );
}

function shell(content) {
  return '<div class="home-overview knowledge-operations"><div class="screen-flow">' + content + "</div></div>";
}

function head(ctx, scopeLabel, canQueue, organizationRoot) {
  return '<div class="head home-head"><div><div class="eyebrow">Operate · ' +
    ctx.esc(scopeLabel) + '</div><h1>Knowledge Operations</h1></div>' +
    (canQueue
      ? '<div class="acts home-head-actions"><button class="btn btn--solid btn--sm" type="button" data-action="knowledge-update-open" data-panel="knowledge-update-panel" aria-controls="knowledge-update-panel" aria-haspopup="dialog" aria-expanded="false">Update ' + (organizationRoot ? "company" : "team") + ' memory</button></div>'
      : "") +
    "</div>";
}

function summary(ctx, view) {
  const readinessScore = finite(view.readiness?.score)
    ? formatNumber(view.readiness.score)
    : "Unavailable";
  const active = view.activityAvailable && view.activity
    ? count(view.activity?.totals?.queued) + count(view.activity?.totals?.running)
    : null;
  const approval = approvalMetric(view.metrics, view.namespace);
  return '<div class="home-metrics knowledge-metrics" role="list" aria-label="Knowledge operations summary">' +
    stat({
      k: "Drafts To Review",
      v: captionlessNumber(view.pending === null ? "Unavailable" : String(view.pending)),
      foot: "Organized knowledge drafts waiting for a human decision.",
      icon: "review",
    }) +
    stat({
      k: "Recovery Needed",
      v: captionlessNumber(view.publishing === null ? "Unavailable" : String(view.publishing)),
      foot: "Publications that stopped after approval and can safely continue.",
      icon: "guardrail",
    }) +
    (view.showActivity
      ? stat({
          k: "Updates Running",
          v: captionlessNumber(active === null ? "Unavailable" : String(active)),
          foot: "Team memory updates currently queued or being processed.",
          icon: "latency",
        })
      : "") +
    stat({
      k: "Memory Health",
      v: readinessScore,
      foot: "The same ACL-scoped readiness score shown on Home.",
      icon: "memory",
      cap: view.readiness?.band ? ctx.esc(bandLabel(view.readiness.band)) : "",
    }) +
    stat({
      k: "Approved Unchanged",
      v: captionlessNumber(approval.value),
      foot: approval.foot,
      icon: "guardrail",
    }) +
    "</div>";
}

function captionlessNumber(value) {
  const text = String(value);
  return /^\d+(?:\.\d+)?%?$/.test(text)
    ? '<span class="knowledge-metric-value-only">' + text + "</span>"
    // A text fallback ("Team scoped", "Unavailable", "Not measured") is a
    // state, not a measurement — at the numeric KPI size it wraps to two
    // lines and reads like broken data next to real figures.
    : '<span class="knowledge-metric-text">' + text + "</span>";
}

function approvalMetric(metrics, namespace) {
  if (!namespace) {
    return {
      value: "Team scoped",
      foot: "Approval quality is measured inside a specific team memory space.",
    };
  }
  if (!metrics) return { value: "Unavailable", foot: "Approval outcomes could not be read." };
  const approvals = count(metrics.approvals);
  if (approvals === 0) {
    return { value: "Not measured", foot: "No approved drafts exist in this scope yet." };
  }
  const unchanged = count(metrics.mergeWithoutEdit);
  const ratio = finite(metrics.mergeWithoutEditRatio)
    ? Math.max(0, Math.min(1, Number(metrics.mergeWithoutEditRatio)))
    : unchanged / approvals;
  return {
    value: (ratio * 100).toFixed(1) + "%",
    foot: unchanged + " of " + approvals + " approved drafts were accepted without edits.",
  };
}

function updateCard(ctx, view) {
  const title = view.organizationRoot ? "Update company memory" : "Update team memory";
  const active = view.activity
    ? count(view.activity?.totals?.queued) + count(view.activity?.totals?.running)
    : 0;
  let footer;
  if (view.canQueue) {
    footer = '<div class="home-card-foot"><button class="home-card-link" type="button" data-action="knowledge-update-open" data-panel="knowledge-update-panel" aria-controls="knowledge-update-panel" aria-haspopup="dialog" aria-expanded="false"><span>Choose memory spaces and run update</span>' + chevron() + "</button></div>";
  } else if (!view.canSync) {
    footer = '<div class="home-card-foot"><span class="subtle home-text-sm">Only an owner can start a memory update. You can still inspect health and review available drafts.</span></div>';
  } else if (!view.teamsAvailable) {
    footer = '<div class="home-card-foot"><span class="subtle home-text-sm">Team directory unavailable. Refresh to try again.</span></div>';
  } else {
    footer = '<div class="home-card-foot"><span class="subtle home-text-sm">No team memory spaces are available to update.</span></div>';
  }
  return '<section class="card home-panel knowledge-update-card" aria-labelledby="knowledge-update-title">' +
    '<div class="between home-panel-head"><h3 id="knowledge-update-title">' + title +
    headingInfo(title, "Processes new saved memories, organizes related evidence, and creates drafts for human review.") + "</h3>" +
    (!view.canSync
      ? ctx.ui.pill("Read only")
      : !view.teamsAvailable || (view.canReview && !view.activityAvailable)
        ? ctx.ui.pill("Unavailable")
        : active > 0
          ? ctx.ui.pill(String(active) + " running", "live")
          // "Ready" beside a footer explaining nothing can run is a
          // contradiction; the pill states the same fact the footer does.
          : view.canQueue
            ? ctx.ui.pill("Ready")
            : ctx.ui.pill("Nothing to update")) + "</div>" +
    '<div class="knowledge-operation-steps">' +
    operationStep("1", "Find new memories", "Continue from the last completed team cursor.") +
    operationStep("2", "Organize related evidence", "Group supporting memories without changing the originals.") +
    operationStep("3", "Create review drafts", "Send proposed knowledge to the review queue below.") +
    "</div>" +
    footer + "</section>";
}

function operationStep(number, title, detail) {
  return '<div class="knowledge-operation-step"><span class="home-overview-row-icon" aria-hidden="true">' + number +
    '</span><div><strong>' + title + '</strong><span class="subtle home-text-xs">' + detail + "</span></div></div>";
}

function updatePanel(ctx, options, organizationRoot) {
  const title = organizationRoot ? "Update company memory" : "Update team memory";
  return rightPanelHtml({
    id: "knowledge-update-panel",
    eyebrow: "Knowledge operations",
    title,
    closeAction: "knowledge-panel-close",
    className: "knowledge-operations-drawer knowledge-update-panel",
    body:
      '<div class="knowledge-drawer-copy"><p>Choose which memory space to process. The update handles only new saved memories, creates review drafts, and keeps the daily incremental run active.</p></div>' +
      '<div class="knowledge-update-preview" aria-label="What this update does">' +
      operationStep("1", "Read new saved memories", "Original memories and provenance stay unchanged.") +
      operationStep("2", "Prepare organized drafts", "Related evidence is clustered and verified.") +
      operationStep("3", "Wait for human review", "No draft is published automatically.") +
      "</div>" +
      '<div class="field"><label for="knowledge-sync-target">Memory to update</label><select class="select" id="knowledge-sync-target" data-knowledge-sync-target>' + options + "</select></div>" +
      '<div class="knowledge-index-note"><strong>Search stays automatic</strong><span>New memories receive their search representation through the normal governed write path. There is no separate embedding action to run here.</span></div>' +
      '<span class="subtle knowledge-sync-status" role="status" aria-live="polite" data-knowledge-sync-status></span>' +
      '<div class="knowledge-drawer-actions"><button class="btn btn--solid" type="button" data-action="knowledge-sync">Run update</button><button class="btn btn--outline" type="button" data-action="knowledge-panel-close">Cancel</button></div>',
  });
}

function syncTargetOptions(ctx, teams, canSyncOrganization) {
  return [
    ...(canSyncOrganization ? ['<option value="organization">Entire organization</option>'] : []),
    ...teams.map((team) => '<option value="' + ctx.esc(team?.id ?? "") + '">' + ctx.esc(team?.name ?? "Unnamed team") + "</option>"),
  ].join("");
}

function healthCard(ctx, readiness) {
  if (!readiness || !finite(readiness.score)) {
    return '<section class="card home-panel knowledge-health-card"><div class="between home-panel-head"><h3>Memory Health</h3>' +
      ctx.ui.pill("Unavailable") + '</div><div class="home-card-empty">Memory health could not be checked. Refresh to try again.</div></section>';
  }
  const score = Math.max(0, Math.min(100, Number(readiness.score)));
  const band = readiness.band ? String(readiness.band) : "";
  const trend = readiness.trend && finite(readiness.trend.deltaPoints) ? readiness.trend : null;
  const trendText = !trend
    ? "Trend unavailable"
    : trend.direction === "up"
      ? "▲ +" + formatNumber(trend.deltaPoints) + " vs " + count(trend.windowDays || readiness.windowDays) + "d"
      : trend.direction === "down"
        ? "▼ " + formatNumber(trend.deltaPoints) + " vs " + count(trend.windowDays || readiness.windowDays) + "d"
        : "Flat vs " + count(trend.windowDays || readiness.windowDays) + "d";
  const pillars = Array.isArray(readiness.pillars) ? readiness.pillars : [];
  const factors = HEALTH_FACTORS.map((definition) => {
    const pillar = pillars.find((candidate) => candidate?.id === definition.pillarId);
    const available = pillar && pillar.available !== false && finite(pillar.score);
    const value = available ? Math.max(0, Math.min(100, Number(pillar.score))) : null;
    return '<div class="home-factor-row"><div class="home-factor-head"><div class="home-factor-title"><b>' +
      ctx.esc(definition.label) + "</b>" +
      (available && pillar?.band
        ? ctx.ui.pill(ctx.esc(bandLabel(pillar.band)), bandTone(pillar.band))
        : '<span class="tag">Unavailable</span>') +
      headingInfo(definition.label, definition.tip) + '</div><div class="home-factor-value"><span class="num">' +
      (value === null ? "—" : formatNumber(value)) + '</span><span class="subtle">/ 100</span></div></div>' +
      healthBar(value, ctx.esc(definition.label) + " score") + "</div>";
  }).join("");
  return '<section class="card home-panel home-health knowledge-health-card" aria-labelledby="knowledge-health-title">' +
    '<div class="between home-panel-head"><h3 id="knowledge-health-title">Memory Health</h3>' +
    (band ? ctx.ui.pill(ctx.esc(bandLabel(band)), bandTone(band)) : ctx.ui.pill("Unavailable")) + "</div>" +
    '<div class="home-health-scoreline"><div><span class="num home-score">' + formatNumber(score) +
    '</span><span class="subtle"> / 100</span></div><span class="home-health-trend">' + ctx.esc(trendText) + "</span></div>" +
    '<div class="home-factor-list">' + factors + "</div>" +
    (readiness.degraded === true
      ? '<p class="subtle home-health-note">Partial score: unavailable signals were excluded and the remaining pillars were reweighted.</p>'
      : "") +
    '<div class="home-card-foot"><button class="home-card-link" type="button" data-action="knowledge-health-open" data-panel="knowledge-health-panel" aria-controls="knowledge-health-panel" aria-haspopup="dialog" aria-expanded="false"><span>Review health and next steps</span>' + chevron() + "</button></div>" +
    "</section>";
}

function healthBar(value, label) {
  const available = finite(value);
  const safe = available ? Math.max(0, Math.min(100, Number(value))) : 0;
  return '<div class="home-factor-chart"><div class="home-factor-track"' +
    (available
      ? ' role="progressbar" aria-label="' + label + '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + formatNumber(safe) + '"'
      : "") + '><span style="width:' + safe + '%"></span><i></i><i></i><i></i></div></div>';
}

function healthPanel(ctx, readiness) {
  const pillars = Array.isArray(readiness.pillars) ? readiness.pillars : [];
  const rows = pillars.map((pillar) => {
    const available = pillar?.available !== false && finite(pillar?.score);
    const target = HEALTH_TARGETS[pillar?.id];
    const score = available ? formatNumber(pillar.score) : "—";
    return '<div class="knowledge-health-detail"><div class="knowledge-health-detail-head"><div><strong>' +
      ctx.esc(pillar?.label ?? pillar?.id ?? "Health signal") + "</strong>" +
      (available && pillar?.band
        ? ctx.ui.pill(ctx.esc(bandLabel(pillar.band)), bandTone(pillar.band))
        : ctx.ui.pill("Unavailable")) +
      '</div><span class="num">' + score + "</span></div>" +
      '<p>' + ctx.esc(plainHealthDetail(pillar?.detail)) + "</p>" +
      (available && target
        ? '<button class="btn btn--outline btn--sm" type="button" data-action="knowledge-go" data-screen="' + target.screen + '">' + target.label + "</button>"
        : "") + "</div>";
  }).join("");
  const score = finite(readiness.score) ? formatNumber(readiness.score) : "—";
  return rightPanelHtml({
    id: "knowledge-health-panel",
    eyebrow: "Memory health",
    title: "Health breakdown",
    closeAction: "knowledge-panel-close",
    className: "knowledge-operations-drawer knowledge-health-drawer",
    body:
      '<div class="knowledge-health-summary"><span class="num">' + score + '</span><span>/ 100</span>' +
      (readiness.band ? ctx.ui.pill(ctx.esc(bandLabel(readiness.band)), bandTone(readiness.band)) : "") + "</div>" +
      '<p class="knowledge-drawer-copy">This is the same health calculation shown on Home. Low usage is not treated as a negative signal.</p>' +
      '<div class="knowledge-health-details">' + rows + "</div>",
  });
}

function reviewLane(ctx, proposals, available, canReview) {
  let body;
  if (!available) {
    body = '<div class="knowledge-unavailable-row"><strong>Review queue unavailable</strong><span>We could not check drafts just now. Refresh to try again.</span></div>';
  } else if (proposals.length === 0) {
    body = '<div class="home-card-empty">No drafts are waiting for review or publication recovery.</div>';
  } else {
    body = '<div class="knowledge-review-list" role="list">' + proposals.map((proposal, index) =>
      proposalRow(ctx, proposal, index, canReview)).join("") + "</div>";
  }
  return '<section class="card home-panel knowledge-review-lane" aria-labelledby="knowledge-review-title">' +
    '<div class="between home-panel-head"><h3 id="knowledge-review-title">Review drafts</h3><span class="home-panel-meta">' +
    (available ? proposals.length + " awaiting a decision or recovery" : "Unavailable") + "</span></div>" + body + "</section>";
}

function proposalRow(ctx, proposal, index, canReview) {
  const draft = proposal?.draft ?? {};
  const publishing = proposal?.status === "publishing";
  const title = ctx.esc(draft.title ?? "Untitled draft");
  const preview = typeof draft.body === "string" ? ctx.esc(draft.body) : "";
  const panelId = "knowledge-proposal-panel-" + index;
  return '<article class="knowledge-review-row" role="listitem">' +
    '<span class="home-overview-row-icon" aria-hidden="true">' + proposalGlyph(publishing) + "</span>" +
    '<div class="knowledge-review-copy"><div class="knowledge-review-head"><strong>' + title + "</strong>" +
    headingInfo(title, preview) +
    ctx.ui.pill(publishing ? "Recovery needed" : "Needs review", publishing ? "warn" : undefined) + "</div></div>" +
    '<button class="home-card-link" type="button" data-action="knowledge-proposal-open" data-panel="' + panelId + '" aria-controls="' + panelId + '" aria-haspopup="dialog" aria-expanded="false"><span>' +
    (publishing ? "Recover" : canReview ? "Review" : "Inspect") + "</span>" + chevron() + "</button></article>";
}

function proposalPanel(ctx, proposal, index, canReview) {
  const draft = proposal?.draft ?? {};
  const baseDraft = proposal?.baseDraft ?? null;
  const id = String(proposal?.id ?? "");
  const rowVersion = positiveInteger(proposal?.rowVersion);
  const publishing = proposal?.status === "publishing";
  const canDecide = canReview && rowVersion !== null;
  const editable = canDecide && !publishing;
  const evidence = Array.isArray(proposal?.evidenceIds) ? proposal.evidenceIds.length : 0;
  const confidence = finite(proposal?.confidence)
    ? (Math.max(0, Math.min(1, Number(proposal.confidence))) * 100).toFixed(1) + "%"
    : "Unavailable";
  const decisions = canDecide
    ? publishing
      ? '<div class="knowledge-proposal-actions"><button class="btn btn--solid" type="button" data-action="proposal-retry">Retry publication</button><span class="subtle">Continues the same immutable version; it does not create another approval.</span></div>'
      : '<div class="knowledge-proposal-actions"><button class="btn btn--solid" type="button" data-action="proposal-approve">Approve unchanged</button><button class="btn btn--outline" type="button" data-action="proposal-edit-approve">Edit &amp; approve</button><button class="btn btn--outline" type="button" data-action="proposal-reject">Reject</button></div>'
    : canReview
      ? '<div class="knowledge-index-note"><strong>Decision unavailable</strong><span>This draft is missing its current version. Refresh before making a decision.</span></div>'
      : '<div class="knowledge-index-note"><strong>Read-only review</strong><span>Your role can inspect this draft and its evidence summary, but cannot publish or reject it.</span></div>';
  const body = '<article class="knowledge-proposal-detail" data-proposal-id="' + ctx.esc(id) + '" data-row-version="' + (rowVersion ?? "") + '">' +
    '<div class="knowledge-proposal-meta">' + ctx.ui.pill(publishing ? "Recovery needed" : "Needs review", publishing ? "warn" : undefined) +
    '<span>' + evidence + " evidence item" + (evidence === 1 ? "" : "s") + "</span><span>Confidence " + confidence + "</span></div>" +
    '<div class="knowledge-proposal-compare"><section><span>Previous official knowledge</span><p>' +
    ctx.esc(baseDraft?.body ?? "New knowledge: there is no previous official version.") + '</p></section><section><span>Proposed knowledge</span><p>' + ctx.esc(draft.body ?? "") + "</p></section></div>" +
    '<div class="field"><label>Slug</label><input class="input mono" data-proposal-slug value="' + ctx.esc(draft.slug ?? "") + '" ' + (editable ? "" : "disabled") + "></div>" +
    '<div class="field"><label>Title</label><input class="input" data-proposal-title value="' + ctx.esc(draft.title ?? "") + '" ' + (editable ? "" : "disabled") + "></div>" +
    '<div class="field"><label>Draft knowledge</label><textarea class="input" data-proposal-body rows="8" ' + (editable ? "" : "disabled") + ">" + ctx.esc(draft.body ?? "") + "</textarea></div>" +
    decisions + '<span class="subtle knowledge-proposal-status" role="status" aria-live="polite" data-proposal-status></span></article>';
  return rightPanelHtml({
    id: "knowledge-proposal-panel-" + index,
    eyebrow: ctx.esc(proposal?.namespace ?? "Knowledge draft"),
    title: ctx.esc(draft.title ?? "Untitled draft"),
    closeAction: "knowledge-panel-close",
    className: "knowledge-operations-drawer knowledge-proposal-drawer",
    body,
  });
}

function activityLane(ctx, activity, available) {
  const runs = Array.isArray(activity?.runs) ? activity.runs : [];
  const retention = finite(activity?.retentionDays)
    ? Math.max(1, Math.min(365, Math.round(Number(activity.retentionDays))))
    : 30;
  let body;
  if (!available) {
    body = '<div class="knowledge-unavailable-row"><strong>Activity unavailable</strong><span>Run history could not be checked. Refresh to try again.</span></div>';
  } else if (runs.length === 0) {
    body = '<div class="home-card-empty">No memory updates have been queued yet.</div>';
  } else {
    body = '<div class="knowledge-activity-list" role="list" aria-label="Memory update activity from the last ' + retention + ' days">' +
      runs.map((run) => syncRunRow(ctx, run)).join("") + "</div>";
  }
  return '<section class="card home-panel knowledge-activity-lane" aria-labelledby="knowledge-activity-title">' +
    '<div class="between home-panel-head"><h3 id="knowledge-activity-title">Recent activity</h3><span class="home-panel-meta">Last ' + retention + " days</span></div>" + body + "</section>";
}

function syncRunRow(ctx, run) {
  const status = String(run?.status ?? "scheduled");
  const tone = status === "failed" ? "crit" : status === "completed" ? "ok" : status === "running" ? "live" : "warn";
  const time = status === "queued" ? run?.queuedAt
    : status === "running" ? run?.startedAt
      : status === "scheduled" ? run?.nextRunAt
        : run?.completedAt;
  return '<article class="knowledge-activity-row" role="listitem"><span class="home-overview-row-icon" aria-hidden="true">' + activityGlyph(status) + "</span>" +
    '<div><strong>' + ctx.esc(run?.name ?? "Memory space") + '</strong><span class="subtle home-text-xs">' + ctx.esc(syncProgressText(run)) +
    (run?.hasMore === true ? " · More batches queued" : "") + (run?.lastError ? " · " + ctx.esc(run.lastError) : "") + "</span></div>" +
    '<div class="knowledge-activity-state">' + ctx.ui.pill(ctx.esc(status), tone) + '<span class="subtle home-text-xs">' + ctx.esc(formatSyncTime(time)) + "</span></div></article>";
}

function syncProgressText(run) {
  const processed = run?.processed == null ? Number.NaN : Number(run.processed);
  const proposals = run?.proposals == null ? Number.NaN : Number(run.proposals);
  if (Number.isFinite(processed) && Number.isFinite(proposals)) {
    return processed + " evidence checked · " + proposals + " drafts";
  }
  if (run?.status === "queued") return "Waiting for the worker";
  if (run?.status === "running") return "Worker is processing memory";
  if (run?.status === "scheduled") return "Next incremental update is scheduled";
  if (run?.status === "failed") return "Last run failed";
  return "Last run completed";
}

function formatSyncTime(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not recorded";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function proposalContext(el) {
  const card = el.closest?.("[data-proposal-id]");
  if (!card) return null;
  return {
    card,
    id: card.getAttribute("data-proposal-id"),
    expectedRowVersion: Number(card.getAttribute("data-row-version")),
    status: card.querySelector("[data-proposal-status]"),
  };
}

async function decide(ctx, el, action, editedDraft) {
  const item = proposalContext(el);
  if (!item?.id) return;
  if (item.status) item.status.textContent = "Saving…";
  const body = { expectedRowVersion: item.expectedRowVersion };
  if (editedDraft) body.editedDraft = editedDraft;
  if (action === "reject") body.reason = "Rejected by steward";
  try {
    await ctx.api.post(`/v1/admin/proposals/${encodeURIComponent(item.id)}/${action}`, body);
    if (typeof document !== "undefined") closeRightPanel(document);
    await repaint(ctx);
  } catch (err) {
    if (item.status) item.status.textContent = err?.message ?? "Decision failed";
  }
}

function openPanel(el) {
  const id = el.getAttribute?.("data-panel");
  if (!id) return;
  const doc = el.ownerDocument ?? globalThis.document;
  const root = el.closest?.(".knowledge-operations");
  const panel = doc?.getElementById?.(id);
  if (panel && (!root || root.contains?.(panel))) openRightPanel(panel, el, doc);
}

async function repaint(ctx) {
  if (typeof ctx.refresh === "function") await ctx.refresh();
  else await ctx.go("s7");
}

export const actions = {
  "knowledge-update-open"(_ctx, el) {
    openPanel(el);
  },
  "knowledge-health-open"(_ctx, el) {
    openPanel(el);
  },
  "knowledge-proposal-open"(_ctx, el) {
    openPanel(el);
  },
  "knowledge-panel-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
  },
  "knowledge-go"(ctx, el) {
    const screen = el.getAttribute("data-screen");
    if (screen) ctx.go(screen);
  },
  async "knowledge-sync"(ctx, el) {
    const root = el.closest?.("#knowledge-update-panel") ?? el.closest?.(".knowledge-update-panel") ?? el.closest?.(".card") ?? globalThis.document;
    const select = root.querySelector("[data-knowledge-sync-target]");
    const status = root.querySelector("[data-knowledge-sync-status]");
    const button = root.querySelector('[data-action="knowledge-sync"]');
    const value = String(select?.value ?? "");
    if (!value) return;
    if (button) {
      button.disabled = true;
      button.textContent = "Queueing…";
    }
    if (status) status.textContent = "Starting memory update…";
    try {
      const result = await ctx.api.post(
        "/v1/admin/knowledge-sync",
        value === "organization" ? { scope: "organization" } : { scope: "team", teamId: value },
      );
      const queued = Array.isArray(result?.queuedSpaces) ? result.queuedSpaces.length : 0;
      if (status) status.textContent = queued + " memory space" + (queued === 1 ? "" : "s") + " queued.";
      if (typeof document !== "undefined") closeRightPanel(document);
      await repaint(ctx);
    } catch (err) {
      if (status) status.textContent = isLimitError(err) ? "" : (err?.message ?? "Memory update could not be queued");
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = "Run update";
      }
    }
  },
  "proposal-approve": (ctx, el) => decide(ctx, el, "approve", null),
  "proposal-retry": (ctx, el) => decide(ctx, el, "approve", null),
  "proposal-reject": (ctx, el) => decide(ctx, el, "reject", null),
  async "proposal-edit-approve"(ctx, el) {
    const item = proposalContext(el);
    if (!item) return;
    const draft = {
      slug: (item.card.querySelector("[data-proposal-slug]")?.value ?? "").trim(),
      title: (item.card.querySelector("[data-proposal-title]")?.value ?? "").trim(),
      body: (item.card.querySelector("[data-proposal-body]")?.value ?? "").trim(),
    };
    return decide(ctx, el, "approve", draft);
  },
};

export function cleanup(reason) {
  if (reason !== "refresh" && typeof document !== "undefined") closeRightPanel(document);
}

function settledValue(result) {
  return result?.status === "fulfilled" ? result.value : null;
}

function settledObject(result) {
  const value = settledValue(result);
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function finite(value) {
  return Number.isFinite(Number(value));
}

function count(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.round(number)) : 0;
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function formatNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return Number.isInteger(number)
    ? number.toLocaleString("en-US")
    : number.toLocaleString("en-US", { maximumFractionDigits: 1 });
}

function bandLabel(value) {
  const band = String(value ?? "");
  if (band === "at-risk") return "At risk";
  return band ? band.charAt(0).toUpperCase() + band.slice(1) : "Unavailable";
}

function bandTone(value) {
  if (value === "excellent" || value === "healthy") return "ok";
  if (value === "fair") return "warn";
  if (value === "at-risk") return "crit";
  return undefined;
}

function plainHealthDetail(value) {
  return String(value ?? "")
    .replace(/distinct provenance sources/gi, "sources")
    .replace(/active facts/gi, "saved memories")
    .replace(/facts contested/gi, "saved memories challenged")
    .replace(/cross-source duplication/gi, "duplicate knowledge")
    .replace(/searches or faults/gi, "memory lookups")
    .replace(/reads came back empty, denied or errored/gi, "lookups found no usable memory")
    .replace(/connected sources have synced/gi, "connected sources are up to date")
    .replace(/sources synced/gi, "sources refreshed")
    .replace(/hit rate unproven/gi, "success rate not measured")
    .replace(/asserted/gi, "added")
    .replace(/detected/gi, "found")
    .replace(/\s*—\s*([a-z])/g, (_match, letter) => ". " + String(letter).toUpperCase())
    .replace(/\s*—\s*/g, ". ");
}

function chevron() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 18 6-6-6-6"></path></svg>';
}

function proposalGlyph(recovery) {
  return recovery
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 4h14v16H5zM8 9h8M8 13h6" stroke-linecap="round"/></svg>';
}

function activityGlyph(status) {
  if (status === "completed") return "✓";
  if (status === "failed") return "!";
  if (status === "running") return "↻";
  return "·";
}
