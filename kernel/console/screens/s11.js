import { personDisplayName } from "../identity-labels.js";
import { metricCard } from "../metric-card.js";
import { headingInfo } from "../heading-info.js";
import { isLimitError } from "../limit-toast.js";
import { closeRightPanel, openRightPanel, rightPanelHtml } from "../right-panel.js";

/** S11 - background Luna findings plus governed historical disputes. */

const CATEGORIES = ["policies-legal", "order-management", "product-info", "other"];
const CATEGORY_LABELS = {
  "policies-legal": "Policies &amp; legal",
  "order-management": "Order management",
  "product-info": "Product info",
  other: "Other",
};
let selectedCategory = "all";
let scanPollTimer = null;

function number(value) {
  return Number(value ?? 0).toLocaleString("en-US");
}

function isActiveScan(scan) {
  return scan?.status === "queued" || scan?.status === "running";
}

function scanPhaseLabel(scan) {
  return {
    queued: "Queued",
    collecting: "Collecting",
    comparing: "Comparing",
    publishing: "Publishing",
  }[String(scan?.phase ?? scan?.status)] ?? "Checking";
}

function manualScanState(scan) {
  if (!scan) return "";
  const progress = scan.progress ?? {};
  const itemsChecked = Number(progress.itemsScanned ?? 0);
  const itemsTotal = Number(progress.itemsTotal ?? 0);
  const pairsChecked = Number(progress.modelPairsReviewed ?? 0);
  const pairsTotal = Number(progress.candidatePairs ?? 0);
  const active = isActiveScan(scan);
  const reviewing = active && scan.phase === "comparing" &&
    (Object.hasOwn(progress, "modelPairsReviewed") || pairsTotal > 0);
  const publishing = active && scan.phase === "publishing";
  const checked = reviewing ? pairsChecked : itemsChecked;
  const total = reviewing ? pairsTotal : itemsTotal;
  const terminalComplete = !active && scan.status === "completed";
  const percent = terminalComplete || publishing ? 100 : total > 0
    ? Math.max(0, Math.min(100, Math.round((checked / total) * 1_000) / 10))
    : reviewing && pairsTotal === 0 ? 100 : 0;
  const percentLabel = `${number(percent)}%`;
  const count = reviewing
    ? pairsTotal > 0
      ? `${number(pairsChecked)} of ${number(pairsTotal)} candidate pairs reviewed`
      : "No candidate pairs need LLM review"
    : itemsTotal > 0
      ? `${number(itemsChecked)} of ${number(itemsTotal)} items checked`
      : itemsChecked > 0 ? `${number(itemsChecked)} items checked` : "Preparing items";
  const meter = total > 0 || reviewing
    ? `<div class="conflict-manual-scan__meter" role="progressbar" aria-label="Manual conflict scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}" aria-valuetext="${count} (${percentLabel})" style="--conflict-scan-progress:${percent}%"><span aria-hidden="true"></span></div>
      <div class="subtle conflict-manual-scan__percent">${percentLabel} complete</div>`
    : `<div class="conflict-manual-scan__meter is-pending" role="progressbar" aria-label="Manual conflict scan progress" aria-valuetext="Preparing items"><span aria-hidden="true"></span></div>`;
  if (active) {
    return `<div class="conflict-manual-scan" data-manual-scan-state role="status" aria-live="polite">
      <div class="between"><span class="sub"><strong>Manual scan</strong> · ${count}</span>
        <span class="pill pill--live"><i class="dot"></i>${scanPhaseLabel(scan)}</span></div>
      ${meter}</div>`;
  }
  if (scan.status === "failed") {
    return `<div class="sub conflict-manual-scan" data-manual-scan-state role="status" aria-live="polite"><strong>Manual scan</strong> · Could not finish</div>`;
  }
  const partial = scan.status === "completed_with_gaps";
  const result = partial ? "Partial — check incomplete" : "Complete";
  return `<div class="conflict-manual-scan" data-manual-scan-state role="status" aria-live="polite">
    <div class="between"><span class="sub"><strong>Manual scan</strong> · ${count}</span>
      <span class="pill"><i class="dot"></i>${result}</span></div>
    ${meter}</div>`;
}

function scheduleScanRefresh(ctx, active) {
  if (!active) {
    if (scanPollTimer && typeof window !== "undefined") window.clearTimeout(scanPollTimer);
    scanPollTimer = null;
    return;
  }
  if (typeof window === "undefined" || scanPollTimer) return;
  scanPollTimer = window.setTimeout(async () => {
    scanPollTimer = null;
    if (typeof ctx.refresh === "function") await ctx.refresh();
    else await ctx.go("s11");
  }, 1_500);
}

/** Plain-English names for the write path's provenance sources. */
const SOURCE_LABELS = {
  conversation: "Agent chat summary",
  document: "Connected source",
  manual: "Added by a person",
  consolidation: "Consolidated memory",
  "swap-import": "Imported memory",
};

/** A ULID is an internal handle. It must never be a reviewer's only label. */
function isOpaqueId(value) {
  return /^[0-9a-hjkmnp-tv-z]{26}$/i.test(String(value ?? "").trim());
}

function sourceTitle(fact) {
  const named = [fact?.sourceName, fact?.sourceLabel]
    .find((value) => value && !isOpaqueId(value));
  return String(named ?? SOURCE_LABELS[fact?.source] ?? fact?.source ?? "Unknown source");
}

/** Strip the write path's reserved `[entities: …]` marker from display text. */
function factText(value) {
  return String(value ?? "").replace(/\s*\[entities:\s*[^\]]*\]\s*$/i, "").trim();
}

function evidenceFor(finding) {
  if (Array.isArray(finding?.evidence)) return finding.evidence;
  return [finding?.left, finding?.right].filter(Boolean).map((fact) => ({
    ...fact,
    sourceLabel: sourceTitle(fact),
    tValidFrom: fact?.assertionTime,
  }));
}

/**
 * Parse `key: value, key: value` rows so a reviewer sees only the fields that
 * actually disagree, instead of two walls of identical columns.
 */
function structuredFields(content) {
  const text = factText(content);
  if (!text) return null;
  const fields = new Map();
  for (const part of text.split(/\s*,\s*/)) {
    const match = /^([A-Za-z][A-Za-z0-9_ .-]{0,60}?)\s*:\s*(.+)$/.exec(part.trim());
    if (!match) return null;
    fields.set(match[1].trim().toLowerCase().replace(/\s+/g, "_"), match[2].trim());
  }
  return fields.size >= 3 ? fields : null;
}

function fieldLabel(key) {
  const words = String(key).replace(/_/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Fields present on both sides with different values, most useful first. */
function differingFields(left, right) {
  const a = structuredFields(left?.content);
  const b = structuredFields(right?.content);
  if (!a || !b) return null;
  const rows = [];
  for (const [key, value] of a) {
    const other = b.get(key);
    if (other !== undefined && other !== value) rows.push({ key, left: value, right: other });
  }
  return rows.length > 0 ? rows.slice(0, 8) : null;
}

/** One sentence a non-technical admin can act on. */
const REASON_SENTENCES = {
  conflicting_value: "These give different answers to the same question.",
  conflicting_date: "These give different dates for the same thing.",
  conflicting_quantity: "These give different numbers for the same thing.",
  conflicting_permission: "These disagree about who is allowed to do this.",
  conflicting_requirement: "These disagree about what is required.",
  conflicting_availability: "These disagree about what is available.",
  mutually_exclusive_state: "Both of these cannot be true at the same time.",
  other_semantic_conflict: "These two statements disagree with each other.",
};

const FLAG_LABELS = {
  "cross-source": "Different sources",
  "agent-derived": "From an agent chat",
  "cross-team": "Across teams",
  "low-confidence": "Low confidence",
};

/**
 * The ledger distinguishes confirmed review work, historical automatic
 * decisions, and checks Luna has not completed yet.
 */
function ledgerState(esc, ledger, latestScan) {
  if (!ledger) return "";
  const auto = Number(ledger.autoResolved ?? 0);
  const review = Number(ledger.needsReview ?? 0);
  const pending = Number(ledger.pendingChecks ?? 0);
  const degraded = ledger.detectionDegraded === true;
  const backlog = degraded
    ? `<div class="sub" style="margin-top:var(--s3)">Conflict checking is unavailable right now, so ${number(pending)} recent ${pending === 1 ? "write has" : "writes have"} not been checked yet. Nothing has been missed — they are queued.</div>`
    : pending > 0
      ? `<div class="sub" style="margin-top:var(--s3)">${number(pending)} recent ${pending === 1 ? "write is" : "writes are"} still being checked.</div>`
      : "";
  return `<div class="card"><h3>Conflict checking${headingInfo("Conflict checking", "Halo's Luna judge checks new and historical memory, flags conflicts for a person, and never chooses a winner.")}</h3>
    <div class="grid g3" style="margin-top:var(--s2)">
      <div><strong>${number(auto)}</strong><div class="subtle">Historical auto decisions</div></div>
      <div><strong>${number(review)}</strong><div class="subtle">Worth a look</div></div>
      <div><strong>${number(pending)}</strong><div class="subtle">Awaiting check</div></div>
    </div>${backlog}${manualScanState(latestScan)}</div>`;
}

const AUTO_RULES = {
  "higher-trust-wins": "Kept the more trusted source.",
  "lower-trust-rejected": "The new claim came from a less trusted source, so the existing fact stayed in use.",
  "equal-trust-newest-wins": "Both sources rank the same, so the newer fact was kept.",
};

function autoDecisionCard(ctx, decision, canReview) {
  const { esc } = ctx;
  const kept = decision?.resolution === "keep-right" ? decision.right : decision?.left;
  const retired = decision?.resolution === "keep-right" ? decision?.left : decision?.right;
  const rule = AUTO_RULES[String(decision?.rule)] ?? AUTO_RULES["equal-trust-newest-wins"];
  const subject = String(decision?.entity ?? "").trim();
  return `<article class="card" data-auto-decision-id="${esc(String(decision?.id ?? ""))}" data-row-version="${Number(decision?.rowVersion ?? 1)}">
    <div class="between"><div><div class="eyebrow">${esc(String(decision?.targetNamespace ?? ""))}</div>
      <h3>Historical automatic decision</h3>${subject && subject !== "unspecified subject" ? `<div class="sub">About: ${esc(subject)}</div>` : ""}</div>
      <span class="pill"><i class="dot"></i>${esc(String(decision?.decidedAt ?? "").slice(0, 10))}</span></div>
    <div class="sub" style="margin-top:var(--s2)">${esc(rule)}</div>
    ${decision?.repairProposed ? `<div class="notice notice--warn" style="margin-top:var(--s2)">Luna's recheck says these entries may both be valid. This decision needs a governed repair review; memory was not changed automatically.</div>` : ""}
    <div class="grid g2" style="margin-top:var(--s3)">${evidenceQuote(ctx, "Now in use", kept)}${evidenceQuote(ctx, "No longer used", retired)}</div>
    ${canReview ? `<div class="conflict-decide">
      <div class="row"><button class="btn btn--outline" data-action="conflict-overturn">${decision?.repairProposed ? "Restore both entries" : "Overturn this"}</button>
        <span class="subtle" role="status" aria-live="polite" data-auto-decision-status></span></div>
      <div class="subtle">${decision?.repairProposed ? "Both entries return to use after a guarded chain check." : "Overturning swaps which one is used. Nothing was deleted."}</div>
    </div>` : ""}</article>`;
}

export function cleanup() {
  if (scanPollTimer && typeof window !== "undefined") window.clearTimeout(scanPollTimer);
  scanPollTimer = null;
  if (typeof document !== "undefined") closeRightPanel(document);
}

function scanMemoryForm() {
  return `<div data-conflict-scan-form>
    <div class="sub">Check current governed memory for likely contradictions. This bounded diagnostic scan reviews candidate pairs automatically in batches until it finishes; automatic checks for new writes continue separately.</div>
    <div class="notice" style="margin-top:var(--s3)">The scan only creates review findings. It never changes or deletes memory.</div>
    <div class="between" style="margin-top:var(--s4)"><span class="subtle" role="status" aria-live="polite" data-conflict-scan-status></span>
      <button class="btn btn--primary btn--sm" data-action="run-conflict-scan">Start scan</button></div>
  </div>`;
}

export async function render(ctx) {
  const { esc } = ctx;
  let disputes = [];
  let findings = [];
  let autoDecisions = [];
  let ledger = null;
  let latestScan = null;
  try {
    let unified;
    try {
      unified = await ctx.api.get("/v1/admin/conflicts");
    } catch {
      unified = { disputes: await ctx.api.get("/v1/admin/disputes"), findings: [] };
    }
    disputes = Array.isArray(unified?.disputes) ? unified.disputes : [];
    findings = Array.isArray(unified?.findings)
      ? unified.findings
      : Array.isArray(unified?.scanFindings) ? unified.scanFindings : [];
    autoDecisions = Array.isArray(unified?.autoDecisions) ? unified.autoDecisions : [];
    ledger = unified?.ledger ?? null;
    latestScan = unified?.latestScan ?? null;
  } catch (err) {
    return `<div class="card"><h3>Conflicts are unavailable</h3><div class="sub">${esc(err?.message ?? "Unable to load conflicts")}</div></div>`;
  }

  const canReview = ctx.identity?.role === "owner" || ctx.identity?.role === "root" || ctx.identity?.role === "admin";
  scheduleScanRefresh(ctx, isActiveScan(latestScan));
  const allItems = [...disputes, ...findings];
  const counts = { all: allItems.length };
  for (const category of CATEGORIES) counts[category] = 0;
  for (const item of allItems) if (counts[item?.category] !== undefined) counts[item.category] += 1;
  if (selectedCategory !== "all" && counts[selectedCategory] === 0) selectedCategory = "all";
  const visibleDisputes = selectedCategory === "all" ? disputes : disputes.filter((item) => item?.category === selectedCategory);
  const visibleFindings = selectedCategory === "all" ? findings : findings.filter((item) => item?.category === selectedCategory);
  const chips = ["all", ...CATEGORIES].map((category) => {
    const label = category === "all" ? "All" : CATEGORY_LABELS[category];
    return `<button class="btn${selectedCategory === category ? " btn--solid" : " btn--outline"}" data-action="dispute-filter" data-category="${esc(category)}" aria-pressed="${selectedCategory === category ? "true" : "false"}">${label} (${counts[category] ?? 0})</button>`;
  }).join(" ");
  const groupedCards = (items, renderCard, emptyText) => {
    const grouped = new Map();
    for (const item of items) {
      const team = String(item?.team ?? item?.namespace ?? item?.targetNamespace ?? "Organization");
      const rows = grouped.get(team) ?? [];
      rows.push(renderCard(item));
      grouped.set(team, rows);
    }
    return [...grouped.entries()].sort((a, b) => a[0].localeCompare(b[0]))
      .map(([team, rows]) => `<div class="navgroup">${esc(team)} · ${rows.length} conflict${rows.length === 1 ? "" : "s"}</div>${rows.join("")}`)
      .join("") || `<div class="conflict-lane-empty">${esc(emptyText)}</div>`;
  };
  const scanCards = groupedCards(visibleFindings, (finding) => scanFindingCard(ctx, finding, canReview), allItems.length > 0 && selectedCategory !== "all" ? "No scan findings in this category." : "No open conflicts from memory scans.");
  const uploadCards = groupedCards(visibleDisputes, (dispute) => disputeCard(ctx, dispute, canReview), allItems.length > 0 && selectedCategory !== "all" ? "No upload reviews in this category." : "No uploads are awaiting review.");
  const accessPill = canReview ? "" : '<span class="pill"><i class="dot"></i>Read-only</span>';
  const metrics = '<div class="conflict-summary-metrics" role="list" aria-label="Conflict review summary">' +
    metricCard({ k: "Open Conflicts", v: number(allItems.length), icon: "review", foot: "Every conflict currently waiting for a decision." }) +
    metricCard({ k: "LLM Findings", v: number(findings.length), icon: "query", foot: "Contradictions confirmed by Halo's context-aware Luna judge." }) +
    metricCard({ k: "Legacy Review", v: number(disputes.length), icon: "source", foot: "Historical quarantines awaiting governed review." }) + "</div>";
  return `<div class="home-overview conflicts-overview"><div class="screen-flow"><div class="head"><div><div class="eyebrow">Govern</div><h1>Conflicts</h1></div><div class="acts">
      <span class="pill"><i class="dot"></i>${allItems.length} open</span>${accessPill}
      ${canReview ? '<button class="btn btn--primary btn--sm" data-action="toggle-conflict-scan" aria-controls="conflict-scan-panel" aria-haspopup="dialog" aria-expanded="false">Scan memory</button>' : ""}</div></div>
    ${metrics}
    <div style="margin-bottom:var(--s4)">${ledgerState(esc, ledger, latestScan)}</div>
    <div class="filter-strip" style="margin-bottom:var(--s4)">${chips}</div>
    <section class="card home-panel conflict-lane" data-conflict-lane="scan" aria-labelledby="memory-scan-findings-title"><div class="between conflict-lane-head"><div><h2 id="memory-scan-findings-title">Memory scan findings</h2><div class="sub">Active L2 facts that Halo's Luna judge confirmed cannot be true together in the same context.</div></div><span class="pill">${number(visibleFindings.length)} open</span></div><div class="stack">${scanCards}</div></section>
    <section class="card home-panel conflict-lane" data-conflict-lane="write" aria-labelledby="upload-review-title"><div class="between conflict-lane-head"><div><h2 id="upload-review-title">Historical upload review</h2><div class="sub">Legacy quarantines are rechecked by Luna and remain human-controlled.</div></div><span class="pill">${number(visibleDisputes.length)} open</span></div><div class="stack">${uploadCards}</div></section>
    ${autoDecisions.length > 0 ? `<details class="compact-disclosure" style="margin-top:var(--s4)"><summary><span><b>Historical automatic decisions</b><small>${number(autoDecisions.length)}</small></span></summary>
      <div class="compact-disclosure__body stack">${autoDecisions.map((decision) => autoDecisionCard(ctx, decision, canReview)).join("")}</div></details>` : ""}
    ${canReview ? rightPanelHtml({ id: "conflict-scan-panel", eyebrow: "Conflicts", title: "Scan memory", closeAction: "conflict-scan-close", className: "conflict-scan-drawer", body: scanMemoryForm() }) : ""}</div></div>`;
}

function factSnippet(ctx, heading, fact, extra) {
  const { esc } = ctx;
  const from = String(fact?.tValidFrom ?? fact?.assertionTime ?? "").slice(0, 19).replace("T", " ");
  return `<div class="snippet"><strong>${heading}</strong>\n${esc(factText(fact?.content))}\n<span class="subtle">source: ${esc(sourceTitle(fact))} · by ${esc(personDisplayName(fact?.actor, ctx.personLabel))} · since ${esc(from)}${extra ?? ""}</span></div>`;
}

function evidenceMeta(ctx, fact) {
  const { esc } = ctx;
  const when = String(fact?.tValidFrom ?? fact?.assertionTime ?? "").slice(0, 10);
  const parts = [];
  if (fact?.actor) parts.push(`recorded by ${esc(personDisplayName(fact.actor, ctx.personLabel))}`);
  if (when) parts.push(esc(when));
  if (fact?.session) parts.push(`session ${esc(String(fact.session))}`);
  return parts.join(" · ");
}

function differenceTable(esc, rows, leftTitle, rightTitle) {
  const body = rows.map((row) => `<tr><th scope="row">${esc(fieldLabel(row.key))}</th>
      <td>${esc(row.left)}</td><td>${esc(row.right)}</td></tr>`).join("");
  return `<div class="tblwrap"><table class="conflict-diff">
    <thead><tr><th scope="col">What differs</th><th scope="col">${esc(leftTitle)}</th>
      <th scope="col">${esc(rightTitle)}</th></tr></thead><tbody>${body}</tbody></table></div>`;
}

function evidenceQuote(ctx, title, fact) {
  const { esc } = ctx;
  return `<div class="conflict-quote"><div class="conflict-quote__src">${esc(title)}</div>
    <p class="conflict-quote__text">${esc(factText(fact?.content))}</p>
    <div class="subtle">${evidenceMeta(ctx, fact)}</div></div>`;
}

function scanFindingCard(ctx, finding, canReview) {
  const { esc } = ctx;
  const id = String(finding?.id ?? "");
  const evidence = evidenceFor(finding);
  const reason = REASON_SENTENCES[String(finding?.reason ?? "")]
    ?? REASON_SENTENCES.other_semantic_conflict;
  const flags = (finding?.flags ?? []).map((flag) => {
    const key = String(flag);
    const label = FLAG_LABELS[key] ?? (key.charAt(0).toUpperCase() + key.slice(1));
    return `<span class="pill">${esc(label)}</span>`;
  }).join(" ");
  const sourcePair = Array.isArray(finding?.sourcePair)
    ? finding.sourcePair.map(String)
    : evidence.map((item) => sourceTitle(item));
  const leftTitle = sourcePair[0] ?? "First entry";
  const rightTitle = sourcePair[1] ?? "Second entry";
  const heading = leftTitle === rightTitle
    ? `Two entries in ${leftTitle} disagree`
    : `${leftTitle} disagrees with ${rightTitle}`;
  const subject = String(finding?.entity ?? "").trim();
  const rows = differingFields(evidence[0], evidence[1]);
  // When both sides carry the same source name, "Keep <source>" and two
  // identical quote headers leave nothing that ties a button to a quote.
  // Number the sides and use ONE label set everywhere — quote headers, the
  // difference table, the full entries, and the keep buttons — with when/who
  // as the tiebreaker so the two entries stay distinguishable.
  const when = (fact) => String(fact?.tValidFrom ?? fact?.assertionTime ?? "").slice(0, 10);
  const who = (fact) => personDisplayName(fact?.actor, ctx.personLabel);
  const sameTitle = leftTitle === rightTitle;
  const tiebreak = when(evidence[0]) !== when(evidence[1])
    ? (fact) => `recorded ${when(fact)}`
    : who(evidence[0]) !== who(evidence[1]) ? (fact) => `by ${who(fact)}` : () => "";
  const sideLabels = evidence.map((fact, index) => {
    if (!sameTitle) return sourcePair[index] ?? `Entry ${index + 1}`;
    const hint = tiebreak(fact);
    return hint ? `Entry ${index + 1} — ${hint}` : `Entry ${index + 1}`;
  });
  const keepLabels = sameTitle
    ? sideLabels.map((_, index) => `Entry ${index + 1}`)
    : sideLabels;
  const comparison = rows
    ? differenceTable(esc, rows, sideLabels[0], sideLabels[1])
    : `<div class="grid g2">${evidence
      .map((fact, index) => evidenceQuote(ctx, sideLabels[index], fact))
      .join("")}</div>`;
  // The raw stored fact stays one disclosure away: a reviewer who needs the
  // exact text can open it, without it being the first thing anyone must read.
  const full = evidence.map((fact, index) => factSnippet(ctx, sideLabels[index], fact,
    fact?.session ? ` · session ${esc(String(fact.session))}` : "")).join("");
  return `<article class="card conflict-finding-card" data-scan-finding-id="${esc(id)}" data-row-version="${Number(finding?.rowVersion ?? 1)}">
    <div class="between"><div><div class="eyebrow">${esc(String(finding?.team ?? finding?.namespace ?? finding?.targetNamespace ?? ""))}</div><h3>${esc(heading)}</h3>${subject ? `<div class="sub">About: ${esc(subject)}</div>` : ""}</div>
      <span class="pill"><i class="dot"></i>AI-confirmed conflict</span></div>
    <div class="sub" style="margin-top:var(--s2)">${esc(reason)}</div>
    ${flags ? `<div class="row" style="margin-top:var(--s2)">${flags}</div>` : ""}
    <div class="conflict-finding-card__comparison">${comparison}</div>
    <details class="compact-disclosure"><summary><span><b>Show the full entries</b></span></summary>
      <div class="compact-disclosure__body grid g2">${full}</div></details>
    ${canReview ? `<div class="conflict-decide">
      <div class="conflict-decide__ask">Which one is right?</div>
      <div class="row">
        <button class="btn btn--primary" data-action="scan-finding-keep" data-keep="left">Keep ${esc(keepLabels[0])}</button>
        <button class="btn btn--primary" data-action="scan-finding-keep" data-keep="right">Keep ${esc(keepLabels[1])}</button>
        <button class="btn btn--ghost" data-action="scan-finding-dismiss">Both are fine</button>
        <span class="subtle" role="status" aria-live="polite" data-scan-finding-status></span>
      </div>
    </div>` : ""}</article>`;
}

/**
 * The write path's dispute reason is an engineering trace ("conflict review
 * mode 'all': conversation(10) vs conversation(10)"). Say why the claim was
 * held in words a reviewer can act on; the raw trace is never their label.
 */
function disputeReasonSentence(dispute) {
  const reason = String(dispute?.reason ?? "");
  const newSource = SOURCE_LABELS[dispute?.disputed?.source]
    ?? String(dispute?.disputed?.source ?? "a new write");
  if (/outranks|underrank/i.test(reason)) {
    return `The current fact comes from a more trusted source than this ${newSource.toLowerCase()}, so the change was held for a person to decide.`;
  }
  if (/conflict review mode 'all'/i.test(reason)) {
    return "Your review policy sends every conflicting update to a person before anything changes.";
  }
  return "These two cannot both be true, so the new claim was held for a person to decide.";
}

function disputeCard(ctx, dispute, canReview) {
  const { esc } = ctx;
  const id = String(dispute?.id ?? "");
  const stale = dispute?.incumbentCurrent === false;
  return `<article class="card" data-dispute-id="${esc(id)}" data-row-version="${Number(dispute?.rowVersion ?? 0)}">
    <div class="between"><div><div class="eyebrow">${esc(String(dispute?.namespace ?? ""))}</div><h3>A new claim disagrees with the current fact</h3></div><span class="pill"><i class="dot"></i>${CATEGORY_LABELS[dispute?.category] ?? esc(String(dispute?.category ?? ""))}</span></div>
    <div class="sub">${esc(disputeReasonSentence(dispute))} The new claim is held out of use until you decide.</div>
    ${dispute?.repairProposed ? '<div class="notice notice--warn" style="margin-top:var(--s2)">Luna found that these may be valid in different contexts. No memory was changed; review before restoring the held entry.</div>' : ""}
    ${stale ? '<span class="pill"><i class="dot"></i>Stale: the current fact changed</span>' : ""}
    <div class="grid g2" style="margin-top:var(--s3)">${factSnippet(ctx, "Current fact — in use", dispute?.incumbent)}${factSnippet(ctx, "New claim — held for review", dispute?.disputed)}</div>
    ${canReview ? `<div class="conflict-decide">
      <div class="conflict-decide__ask">Which one is right?</div>
      <div class="row">
        <button class="btn btn--primary" data-action="dispute-uphold" ${stale ? "disabled" : ""}>Keep the new claim</button>
        <button class="btn btn--outline" data-action="dispute-keep">Keep the current fact</button>
        ${dispute?.repairProposed ? '<button class="btn btn--outline" data-action="dispute-both-valid">Both are valid</button>' : ""}
        <span class="subtle" role="status" aria-live="polite" data-dispute-status></span>
      </div>
      <div class="subtle">The one you keep is what agents use from now on. The other is archived — nothing is deleted.</div>
    </div>
    <details class="compact-disclosure conflict-edit"><summary><span><b>Neither is right? Edit &amp; replace</b><small>Optional</small></span></summary><div class="compact-disclosure__body field"><label>Write the corrected fact</label><textarea class="input" data-dispute-edit rows="3">${esc(String(dispute?.disputed?.content ?? ""))}</textarea><button class="btn btn--outline" data-action="dispute-edit" ${stale ? "disabled" : ""}>Edit &amp; replace</button><div class="subtle">Your correction becomes the fact in use; both of the above are archived.</div></div></details>` : ""}</article>`;
}

function disputeContext(el) {
  const card = el.closest("[data-dispute-id]");
  return card ? { card, id: card.getAttribute("data-dispute-id"), expectedRowVersion: Number(card.getAttribute("data-row-version")), status: card.querySelector("[data-dispute-status]") } : null;
}

async function decide(ctx, el, action, editedContent) {
  const item = disputeContext(el);
  if (!item?.id) return;
  if (item.status) item.status.textContent = "Saving…";
  const body = { action, expectedRowVersion: item.expectedRowVersion };
  if (editedContent !== undefined) body.editedContent = editedContent;
  try {
    await ctx.api.post(`/v1/admin/disputes/${encodeURIComponent(item.id)}/resolve`, body);
    await ctx.go("s11");
  } catch (err) {
    if (item.status) item.status.textContent = err?.message ?? "Resolution failed";
  }
}

async function reviewScanFinding(ctx, el, action, body) {
  const card = el.closest("[data-scan-finding-id]");
  if (!card) return;
  const status = card.querySelector("[data-scan-finding-status]");
  if (status) status.textContent = "Saving…";
  try {
    await ctx.api.post(`/v1/admin/conflict-findings/${encodeURIComponent(card.getAttribute("data-scan-finding-id"))}/${action}`, {
      ...body,
      expectedRowVersion: Number(card.getAttribute("data-row-version")),
    });
    await ctx.go("s11");
  } catch (err) {
    if (status) status.textContent = err?.message ?? "Review failed";
  }
}

export const actions = {
  async "dispute-filter"(ctx, el) {
    selectedCategory = el.getAttribute("data-category") ?? "all";
    await ctx.go("s11");
  },
  "toggle-conflict-scan"(_ctx, el) {
    const doc = el?.ownerDocument ?? (typeof document !== "undefined" ? document : null);
    const root = el?.closest?.(".screen") ?? doc;
    openRightPanel(root?.querySelector?.("#conflict-scan-panel"), el, doc);
  },
  "conflict-scan-close"() {
    if (typeof document !== "undefined") closeRightPanel(document);
  },
  async "run-conflict-scan"(ctx, el) {
    const root = el?.closest?.("[data-conflict-scan-form]") ?? el?.ownerDocument;
    const status = root?.querySelector?.("[data-conflict-scan-status]");
    el.disabled = true;
    el.textContent = "Starting…";
    if (status) status.textContent = "";
    try {
      await ctx.api.post("/v1/admin/conflict-scans", {});
      if (typeof document !== "undefined") closeRightPanel(document);
      if (typeof ctx.refresh === "function") await ctx.refresh();
      else await ctx.go("s11");
    } catch (err) {
      el.disabled = false;
      el.textContent = "Start scan";
      if (status) status.textContent = isLimitError(err) ? "" : (err?.message ?? "The scan could not start.");
    }
  },
  "scan-finding-acknowledge": (ctx, el) => reviewScanFinding(ctx, el, "acknowledge"),
  "scan-finding-dismiss": (ctx, el) => reviewScanFinding(ctx, el, "dismiss"),
  "scan-finding-keep": (ctx, el) => reviewScanFinding(ctx, el, "resolve", {
    keep: el.getAttribute("data-keep") === "right" ? "right" : "left",
  }),
  async "conflict-overturn"(ctx, el) {
    const card = el.closest("[data-auto-decision-id]");
    if (!card) return;
    const status = card.querySelector("[data-auto-decision-status]");
    if (status) status.textContent = "Saving…";
    try {
      await ctx.api.post(
        `/v1/admin/conflict-findings/${encodeURIComponent(card.getAttribute("data-auto-decision-id"))}/overturn`,
        { expectedRowVersion: Number(card.getAttribute("data-row-version")) },
      );
      await ctx.go("s11");
    } catch (err) {
      if (status) status.textContent = err?.message ?? "Overturn failed";
    }
  },
  "dispute-uphold": (ctx, el) => decide(ctx, el, "uphold-new"),
  "dispute-keep": (ctx, el) => decide(ctx, el, "keep-old"),
  "dispute-both-valid": (ctx, el) => decide(ctx, el, "both-valid"),
  async "dispute-edit"(ctx, el) {
    const item = disputeContext(el);
    if (!item) return;
    const edited = (item.card.querySelector("[data-dispute-edit]")?.value ?? "").trim();
    if (!edited) {
      if (item.status) item.status.textContent = "Enter the corrected fact text first.";
      return;
    }
    return decide(ctx, el, "edit", edited);
  },
};
