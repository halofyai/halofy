/**
 * Shared controller for management/detail surfaces that belong in the
 * platform's right-side panel. Callers own and escape the panel body; this
 * module owns geometry-independent open/close, Escape and focus restoration.
 */

const panelState = new WeakMap();

export function rightPanelHtml({ id, title, eyebrow = "Details", body, closeAction, className = "", navigationIcon = true }) {
  const classes = ["source-wizard-dialog", "console-right-panel__dialog", className]
    .filter(Boolean)
    .join(" ");
  return `<div id="${id}" class="source-wizard-overlay console-right-panel" hidden aria-hidden="true">
    <button type="button" class="source-wizard-backdrop" data-action="${closeAction}" aria-label="Return to page"></button>
    <section class="${classes}" role="dialog" aria-modal="true" aria-labelledby="${id}-title">
      <div class="between source-wizard-head"><div>
        <div class="console-right-panel__context">${navigationIcon ? '<span class="console-right-panel__nav-icon" data-right-panel-icon hidden aria-hidden="true"></span>' : ""}<div class="eyebrow">${eyebrow}</div></div><h3 id="${id}-title">${title}</h3></div>
        <button type="button" class="source-wizard-close halo-icon-control" data-action="${closeAction}" data-right-panel-focus aria-label="Return to page">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M10 17l-5-5 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Close</span>
        </button></div>
      <div class="console-right-panel__body">${body}</div>
    </section>
  </div>`;
}

export function openRightPanel(panel, opener, doc = panel?.ownerDocument ?? globalThis.document) {
  if (!panel || !doc) return false;
  closeRightPanel(doc);
  syncRightPanelIcon(panel, doc);
  panel.hidden = false;
  panel.setAttribute?.("aria-hidden", "false");
  doc.body?.classList?.add("source-modal-open");
  opener?.setAttribute?.("aria-expanded", "true");

  const onKeydown = (event) => {
    if (event.key === "Escape") closeRightPanel(doc);
  };
  doc.addEventListener?.("keydown", onKeydown);
  panelState.set(doc, { panel, opener: opener ?? null, onKeydown });

  const focusTarget = panel.querySelector?.("[data-right-panel-focus], input, select, textarea, button");
  focusTarget?.focus?.({ preventScroll: true });
  return true;
}

function syncRightPanelIcon(panel, doc) {
  const target = panel.querySelector?.("[data-right-panel-icon]");
  if (!target) return;
  const source = doc.querySelector?.("#rail-nav button[data-s].on svg");
  target.replaceChildren?.();
  if (!source || typeof source.cloneNode !== "function") {
    target.hidden = true;
    return;
  }
  target.replaceChildren?.(source.cloneNode(true));
  target.hidden = false;
}

export function closeRightPanel(doc = globalThis.document) {
  if (!doc) return false;
  const state = panelState.get(doc);
  if (!state) {
    doc.body?.classList?.remove("source-modal-open");
    return false;
  }
  state.panel.hidden = true;
  state.panel.setAttribute?.("aria-hidden", "true");
  doc.removeEventListener?.("keydown", state.onKeydown);
  doc.body?.classList?.remove("source-modal-open");
  state.opener?.setAttribute?.("aria-expanded", "false");
  state.opener?.focus?.({ preventScroll: true });
  panelState.delete(doc);
  return true;
}
