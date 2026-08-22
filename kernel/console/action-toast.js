/**
 * Shared success feedback for delegated console actions.
 *
 * Screens keep their local status regions for validation, progress, and error
 * detail. This layer adds a short, persistent-across-refresh confirmation only
 * after the action's API work completed successfully.
 */

const CONFIRMATIONS = Object.freeze({
  // Home + Settings
  "usage-cap-save": confirmation("Usage cap saved", "The monthly workspace limit was updated."),
  "org-name-save": confirmation("Organization updated", "The workspace name was saved."),
  "org-icon-pick": confirmation("Organization icon updated", "The new workspace icon is now in use."),
  "org-icon-clear": confirmation("Organization icon removed", "The workspace is using its initials again."),
  "profile-name-save": confirmation("Profile updated", "Your display name was saved."),
  "profile-avatar-pick": confirmation("Profile photo updated", "Your new photo is now in use."),
  "profile-avatar-clear": confirmation("Profile photo removed", "Your profile is using initials again."),
  "github-disconnect": confirmation("GitHub disconnected", "GitHub can no longer be used to sign in to this account."),
  "google-disconnect": confirmation("Google disconnected", "Google can no longer be used to sign in to this account."),

  // Policy library
  "policy-enforcement-toggle": confirmation("Enforcement updated", "The policy enforcement setting was saved."),
  "policy-document-delete": confirmation("Policy document deleted", "The selected policy document was removed."),
  "policy-adopt": confirmation("Policy adopted", "The policy is now active for the selected scope."),
  "policy-file-upload": confirmation("Policy uploaded", "The policy document entered governed processing."),

  // Agent connections + scoped policy
  "badge-create": confirmation("Agent key created", "The new agent credential is ready to copy."),
  "agent-source-submit": confirmation("Source access updated", "The agent's governed source access was saved."),
  "badge-revoke": confirmation("Agent access revoked", "The selected agent badge can no longer connect."),
  "key-rotate": confirmation("Agent key rotated", "The previous key is no longer valid."),
  "key-revoke": confirmation("Agent key revoked", "The selected key can no longer be used."),
  "policy-save": confirmation("Policy saved", "The scoped memory policy is now up to date."),
  "viewas-start": confirmation("Preview started", "The console is now showing the selected access view."),
  "viewas-exit": confirmation("Preview ended", "Your normal organization access has been restored."),

  // Sources + knowledge
  "create-kb-team": confirmation("Team access added", "The knowledge base is now available to the selected team."),
  "create-knowledge-base": confirmation("Knowledge base created", "The new governed knowledge container is ready."),
  "attach-knowledge-source": confirmation("Knowledge added", "The selected item was added to this knowledge base."),
  "upload-company-files": confirmation("Files uploaded", "The selected files entered governed processing."),
  "replace-company-file": confirmation("File replaced", "The replacement entered governed processing."),
  "confirm-delete-knowledge-base": confirmation("Knowledge base deleted", "The selected knowledge base was removed."),
  "confirm-delete-company-file": confirmation("File deleted", "The selected company file was removed."),
  "retry-company-file": confirmation("Processing restarted", "The file was queued for another processing attempt."),
  "connect-source": confirmation("Source connected", "The new source is ready for governed synchronization."),
  "complete-nango-connect": confirmation("Connection completed", "The authorized source is ready to use."),
  "sync-source": confirmation("Sync started", "The source was queued for synchronization."),
  "test-source": confirmation("Connection tested", "The latest connection test completed."),
  "pause-source": confirmation("Source disconnected", "Updates are stopped; existing memory and connection details are preserved."),
  "resume-source": confirmation("Source reconnected", "The connection was checked and updates are active again."),
  "import-csv": confirmation("Snapshot imported", "The CSV entered the governed write path."),
  "schedule-source": confirmation("Schedule saved", "The source synchronization schedule was updated."),
  "run-data-quality-check": confirmation("Quality check started", "The source was queued for a fresh quality check."),
  "knowledge-sync": confirmation("Knowledge sync started", "The review queue will update as the sync runs."),
  "proposal-approve": confirmation("Knowledge approved", "The proposal was published to governed memory."),
  "proposal-retry": confirmation("Publish retried", "The proposal was queued for another publish attempt."),
  "proposal-reject": confirmation("Knowledge rejected", "The proposal was removed from the review queue."),
  "proposal-edit-approve": confirmation("Knowledge approved", "Your edit was published to governed memory."),

  // Audit + retrieval
  "audit-csv": confirmation("Audit export ready", "The filtered audit CSV was prepared for download."),
  "cert-verify": confirmation("Certificate verified", "The erasure certificate passed verification."),
  "audit-erase": confirmation("Erasure completed", "The governed erasure and certificate were recorded."),
  "switch-retriever": confirmation("Retriever updated", "The selected retrieval lane is now active."),

  // Assistant + conflicts
  "routine-create": confirmation("Routine created", "The assistant routine is now scheduled."),
  "routine-pause": confirmation("Routine paused", "The assistant will not run this routine until it is resumed."),
  "routine-resume": confirmation("Routine resumed", "The assistant routine is active again."),
  "routine-delete-confirm": confirmation("Routine deleted", "The scheduled routine was removed."),
  "select-copilot-profile": confirmation("Assistant model updated", "The selected model profile is now active."),
  "clear-chat": confirmation("Conversation cleared", "The current assistant conversation was cleared."),
  "run-conflict-scan": confirmation("Conflict scan started", "The organization scan is running in the background."),
  "scan-finding-acknowledge": confirmation("Finding acknowledged", "The finding was marked as reviewed."),
  "scan-finding-dismiss": confirmation("Finding dismissed", "The finding was removed from the open review list."),
  "scan-finding-keep": confirmation("Conflict resolved", "The current governed value was kept."),
  "dispute-uphold": confirmation("Dispute resolved", "The new governed value was upheld."),
  "dispute-keep": confirmation("Dispute resolved", "The current governed value was kept."),
  "dispute-edit": confirmation("Dispute resolved", "The edited value was saved as the resolution."),

  // Models + teams
  "model-connection-create": confirmation("Model deployed", "The model is available in Halo Assistant."),
  "model-connection-delete": confirmation("Model connection removed", "The selected deployment connection was deleted."),
  "model-profile-save": confirmation("Model deployment updated", "The deployment settings were saved."),
  "model-profile-make-default": confirmation("Default model updated", "Halo Assistant will select this model by default."),
  "model-profile-delete": confirmation("Model deployment deleted", "The selected model deployment was removed."),
  "team-create": confirmation("Team created", "The new team space is ready."),
  "team-member-add": confirmation("Member added", "The person now has access to this team."),
  "team-invite-submit": confirmation("Invitation created", "The invite is ready to share."),
  "team-member-role": confirmation("Role updated", "The member's team role was saved."),
  "team-memory-access": confirmation("Memory access updated", "The team's memory access mode was saved."),
  "team-member-remove": confirmation("Member removed", "The person no longer has access to this team."),
  "team-invite-dismiss": confirmation("Invitation dismissed", "The invitation was removed from the pending list."),

  // Connected apps + usage controls
  "intg-revoke-badge": confirmation("Agent access revoked", "The connected agent badge can no longer be used."),
  "intg-mint": confirmation("Agent key created", "The new connection key is ready to copy."),
  "assistant-restore": confirmation("Assistant access restored", "The assistant can run again for this principal."),
  "assistant-purge": confirmation("Assistant data purged", "The selected assistant lifecycle data was removed."),

  // Skills + OAuth clients
  "skill-create": confirmation("Skill submitted", "The skill entered the approval workflow."),
  "skill-update": confirmation("Skill updated", "The new skill version entered the approval workflow."),
  "skill-approve": confirmation("Skill approved", "The skill is available to authorized agents."),
  "skill-reject": confirmation("Skill rejected", "The skill was returned with the recorded reason."),
  "skill-vet": confirmation("Skill checks completed", "The latest vetting results are ready to review."),
  "skill-override": confirmation("Vetting decision saved", "The governed override was recorded."),
  "skill-retire": confirmation("Skill retired", "Agents can no longer invoke this skill."),
  "oauth-client-submit": confirmation("OAuth client created", "The client is ready for review and approval."),
  "oauth-client-approve": confirmation("OAuth client approved", "The client can now complete authorization."),
  "oauth-client-revoke": confirmation("OAuth client revoked", "The client can no longer authorize connections."),

  // Alerts + export + channels
  "alerts-approve": confirmation("Access approved", "The scoped access request was approved."),
  "alerts-deny": confirmation("Access denied", "The scoped access request was denied."),
  "alerts-acknowledge": confirmation("Alert acknowledged", "The alert was removed from the open queue."),
  generate: confirmation("Export ready", "The governed export was generated for the selected scope."),
  "s21-create": confirmation("Channel created", "The new channel connection is ready for setup."),
  "s21-save-credentials": confirmation("Credentials saved", "The channel credentials were encrypted and stored."),
  "s21-assign": confirmation("Channel assigned", "The channel's agent assignment was updated."),
  "s21-register-webhook": confirmation("Webhook registered", "The provider webhook registration completed."),
  "s21-transition": confirmation("Channel updated", "The channel lifecycle state was updated."),

  // Local-only confirmations opt in explicitly after returning true.
  "audit-copy": confirmation("Audit ID copied", "The audit event ID is on your clipboard.", false, true),
  "team-invite-copy": confirmation("Invitation copied", "The invitation details are on your clipboard.", false, true),
  "intg-copy-endpoint": confirmation("Endpoint copied", "The MCP endpoint is on your clipboard.", false, true),
  "intg-copy-step": confirmation("Setup command copied", "The setup command is on your clipboard.", false, true),
  "intg-copy-key": confirmation("Agent key copied", "The one-time key is on your clipboard.", false, true),
  "skill-download": confirmation("Skill downloaded", "The skill package was saved to your device.", false, true),
  "skill-copy-step": confirmation("Install command copied", "The installation command is on your clipboard.", false, true),
  "oauth-secret-copy": confirmation("Client secret copied", "The one-time secret is on your clipboard.", false, true),
  "badge-key-copy": confirmation("Agent key copied", "The one-time key is on your clipboard.", false, true),
  "download-json": confirmation("JSON downloaded", "The portable export was saved to your device.", false, true),
  download: confirmation("Markdown downloaded", "The readable export was saved to your device.", false, true),
  copy: confirmation("Export copied", "The readable export is on your clipboard.", false, true),
});

function confirmation(title, message, requiresRequest = true, requireTrueResult = false) {
  return Object.freeze({ title, message, requiresRequest, requireTrueResult });
}

export function confirmationFor(actionName) {
  return CONFIRMATIONS[String(actionName || "")] || null;
}

/** Wrap the ctx API so caught request failures still suppress a success toast. */
export function trackActionRequests(actionCtx) {
  const state = { attempted: 0, succeeded: 0, failed: 0 };
  const sourceApi = actionCtx && actionCtx.api && typeof actionCtx.api === "object"
    ? actionCtx.api
    : {};
  const trackedApi = {};
  for (const [name, method] of Object.entries(sourceApi)) {
    if (typeof method !== "function") {
      trackedApi[name] = method;
      continue;
    }
    trackedApi[name] = async (...args) => {
      state.attempted += 1;
      try {
        const result = await method.apply(sourceApi, args);
        state.succeeded += 1;
        return result;
      } catch (error) {
        state.failed += 1;
        throw error;
      }
    };
  }
  const context = Object.assign(Object.create(actionCtx || null), { api: trackedApi });
  return { context, state };
}

export function shouldConfirmAction(spec, state, result) {
  if (!spec || !state || state.failed > 0) return false;
  if (spec.requireTrueResult === true) return result === true;
  if (spec.requiresRequest === false) return true;
  return state.succeeded > 0;
}

export function toastMarkup(notification, id) {
  const title = escapeHtml(notification && notification.title);
  const message = escapeHtml(notification && notification.message);
  const toastId = escapeHtml(id);
  const danger = notification && notification.tone === "danger";
  const mark = danger
    ? '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 6v5" stroke-linecap="round"/><circle cx="10" cy="14" r="0.5" fill="currentColor"/><path d="M10 2.5 18 17H2Z" stroke-linejoin="round"/></svg>'
    : '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="m5 10 3 3 7-7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  return `<article class="action-toast${danger ? " action-toast--danger" : ""}" data-action-toast-id="${toastId}">
    <span class="action-toast__mark" aria-hidden="true">
      ${mark}
    </span>
    <span class="action-toast__copy"><strong>${title}</strong><span>${message}</span></span>
    <button class="action-toast__dismiss" type="button" data-action-toast-dismiss aria-label="Dismiss notification">
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="m6 6 8 8m0-8-8 8" stroke-linecap="round"/></svg>
    </button>
  </article>`;
}

export function createActionToaster(doc, { duration = 4400, maxVisible = 3 } = {}) {
  if (!doc || !doc.body || typeof doc.createElement !== "function") {
    return { show() {}, clear() {} };
  }
  let root = doc.getElementById && doc.getElementById("action-toasts");
  if (!root) {
    root = doc.createElement("section");
    root.id = "action-toasts";
    root.className = "action-toasts";
    root.setAttribute("aria-label", "Action confirmations");
    root.setAttribute("aria-live", "polite");
    root.setAttribute("aria-atomic", "false");
    doc.body.appendChild(root);
  }

  let sequence = 0;
  const timers = new Map();
  const remove = (toast) => {
    if (!toast) return;
    const id = toast.getAttribute && toast.getAttribute("data-action-toast-id");
    if (id && timers.has(id)) {
      clearTimeout(timers.get(id));
      timers.delete(id);
    }
    toast.classList && toast.classList.add("is-leaving");
    setTimeout(() => toast.remove && toast.remove(), 180);
  };

  root.addEventListener("click", (event) => {
    const button = event.target && event.target.closest
      ? event.target.closest("[data-action-toast-dismiss]")
      : null;
    if (!button || !root.contains(button)) return;
    remove(button.closest("[data-action-toast-id]"));
  });

  return {
    show(notification) {
      if (!notification || !notification.title || !notification.message) return;
      const id = `action-toast-${++sequence}`;
      root.insertAdjacentHTML("afterbegin", toastMarkup(notification, id));
      const toast = root.querySelector(`[data-action-toast-id="${id}"]`);
      const visible = Array.from(root.querySelectorAll("[data-action-toast-id]"));
      visible.slice(maxVisible).forEach(remove);
      // A notification may ask for its own dwell time: limit toasts explain
      // why something did NOT happen and stay longer than a confirmation.
      const dwell = Number(notification.duration);
      timers.set(id, setTimeout(() => remove(toast), Number.isFinite(dwell) && dwell > 0 ? dwell : duration));
    },
    clear() {
      Array.from(root.querySelectorAll("[data-action-toast-id]")).forEach(remove);
    },
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
