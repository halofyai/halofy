/**
 * S1 — the mandatory setup surface: the standing checklist, nothing else.
 *
 * S1 wears the shared page chrome (workspace bar → breadcrumb → title bar) like
 * every other tab, so the title sits at the same offset here as on Home or the
 * Assistant. There is still exactly one title: the stepper's own header keeps
 * the organization line and the progress meter, and renders no heading of its
 * own — that was the duplication the setup screen had to avoid.
 *
 * The one-shot "verified setup" wizard that used to render below the
 * stepper was removed together with the legacy `teams` table (migration
 * v69): every step is completed on the screen its CTA points at (S13
 * teams, S6 sources, S5 memories, S3 badges), and the /v1/admin/setup*
 * API remains for programmatic provisioning only.
 */

import { load as loadChecklist, card as checklistCard } from "./setup-checklist.js";

export async function render(ctx) {
  // Derived LIVE from real org signals every render — a step that regresses
  // later re-opens on its own. `load` returns null on brownout; the card then
  // says the status is unavailable rather than blanking the screen.
  const view = await loadChecklist(ctx);
  return (
    ctx.ui.head({ eyebrow: "Onboard", title: "Set up Halofy" }) +
    checklistCard(ctx, view)
  );
}
