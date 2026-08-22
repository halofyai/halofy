/**
 * S18 — Settings. The two identity surfaces a signed-in human owns: their own
 * profile (display name) and, for owner/admin, the organization's display name
 * and mark.
 *
 * No presentation field participates in authorization. The account key is still the
 * email, the tenant is still the ROOT namespace, and renaming an organization
 * never re-derives its tenant id — a handle that moved when someone fixed a
 * typo would orphan every namespace beneath it. So this module changes only
 * what is displayed, and it writes an audit row for each change (D4).
 *
 * D9 holds: the subject of a profile update is `identity.sessionUserId`, and
 * the organization is resolved from `identity.namespace`. A caller never names
 * either one.
 */

import { AuthzError } from "../auth/index.js";
import type { AuditLog } from "../audit/index.js";
import type { Db } from "../db/client.js";
import { tenantRootOf } from "../tenancy/index.js";
import type { Identity, Namespace } from "../types.js";
import { normalizedOrganizationName } from "./org-name.js";
import {
  HumanDisplayNameError,
  normalizedHumanDisplayName,
} from "./person-name.js";
import { canHuman } from "./rbac.js";

const AGENT_ID = "console";

/** Longest stored icon data URL. ~256 KB of characters ≈ a 190 KB image. */
const MAX_ICON_CHARS = 256_000;

/** Raster only. An SVG mark would be arbitrary markup arriving from a form. */
const ICON_PREFIX = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

/** Thrown when a submitted settings value is unusable. */
export class SettingsBadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SettingsBadRequestError";
  }
}

/** The structural kernel subset the settings handlers consume. */
export interface SettingsSlice {
  readonly db: Db;
  readonly audit: AuditLog;
}

export interface OrganizationSettingsView {
  /** Tenant id = the organization's ROOT namespace. Stable across renames. */
  id: Namespace;
  name: string;
  /** Data URL, or null when the organization has no mark yet. */
  icon: string | null;
  status: string;
  createdAt: string;
  /** Whether THIS caller may write the two fields above. */
  canEdit: boolean;
}

export interface OrganizationSettingsUpdate {
  name?: unknown;
  icon?: unknown;
}

export interface MemberProfileUpdate {
  displayName?: unknown;
  avatar?: unknown;
}

export interface MemberProfileView {
  displayName: string;
  avatar: string | null;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

interface OrganizationRow {
  id: string;
  name: string;
  icon: string | null;
  status: string;
  created_at: Date | string;
}

/**
 * The tenant this caller's settings screen is about: the root of their own
 * namespace. The platform root (`""`) belongs to no organization; when the
 * deployment holds exactly one tenant that is unambiguously the one an operator
 * means, so it resolves — mirroring the setup gate's sole-tenant rule.
 */
async function resolveOrganizationRoot(
  slice: SettingsSlice,
  identity: Identity,
): Promise<Namespace | null> {
  const root = tenantRootOf(identity.namespace);
  if (root.length > 0) return root;
  const sole = await slice.db.query(`SELECT id FROM tenants LIMIT 2`);
  if (sole.rows.length !== 1) return null;
  return String(sole.rows[0].id) as Namespace;
}

async function loadOrganization(
  slice: SettingsSlice,
  root: Namespace,
): Promise<OrganizationRow | null> {
  const res = await slice.db.query(
    `SELECT id, name, icon, status, created_at FROM tenants WHERE id = $1`,
    [root],
  );
  if (res.rows.length === 0) return null;
  return res.rows[0] as OrganizationRow;
}

function toView(row: OrganizationRow, identity: Identity): OrganizationSettingsView {
  return {
    id: String(row.id) as Namespace,
    name: String(row.name),
    icon: row.icon === null || row.icon === undefined ? null : String(row.icon),
    status: String(row.status),
    createdAt: toIso(row.created_at),
    canEdit: canHuman(identity.role, "organization:write"),
  };
}

/**
 * Read the organization identity. Any human in the tenant may see the name and
 * mark of the organization they work in; only `canEdit` differs by role.
 */
export async function readOrganizationSettings(
  slice: SettingsSlice,
  identity: Identity,
): Promise<OrganizationSettingsView | null> {
  if (identity.role === "agent") throw new AuthzError("organization settings are human-only");
  const root = await resolveOrganizationRoot(slice, identity);
  if (root === null) return null;
  const row = await loadOrganization(slice, root);
  return row === null ? null : toView(row, identity);
}

/** Validate a submitted icon data URL, or null to clear the mark. */
function normalizedRasterDataUrl(value: unknown, field: "icon" | "avatar"): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new SettingsBadRequestError(`'${field}' must be a data URL string or null`);
  }
  const image = value.trim();
  if (image.length === 0) return null;
  if (image.length > MAX_ICON_CHARS) {
    throw new SettingsBadRequestError(`${field} is too large - use an image under 190 KB`);
  }
  if (!ICON_PREFIX.test(image)) {
    throw new SettingsBadRequestError(`${field} must be a base64 PNG, JPEG, or WebP data URL`);
  }
  return image;
}

const normalizedIcon = (value: unknown): string | null => normalizedRasterDataUrl(value, "icon");

/**
 * Rename the organization and/or replace its mark. Owner/admin only; the tenant
 * id is NEVER re-derived (see the module header).
 */
export async function updateOrganizationSettings(
  slice: SettingsSlice,
  body: OrganizationSettingsUpdate,
  identity: Identity,
): Promise<OrganizationSettingsView> {
  if (!canHuman(identity.role, "organization:write")) {
    throw new AuthzError("changing organization settings requires the owner or admin role");
  }
  const touchesName = Object.prototype.hasOwnProperty.call(body, "name");
  const touchesIcon = Object.prototype.hasOwnProperty.call(body, "icon");
  if (!touchesName && !touchesIcon) {
    throw new SettingsBadRequestError("supply 'name' and/or 'icon'");
  }
  const name = touchesName ? normalizedOrganizationName(String(body.name ?? "")) : null;
  const icon = touchesIcon ? normalizedIcon(body.icon) : null;

  const root = await resolveOrganizationRoot(slice, identity);
  if (root === null) throw new SettingsBadRequestError("no organization resolves for this account");

  const sets: string[] = [];
  const params: unknown[] = [root];
  if (touchesName) {
    params.push(name);
    sets.push(`name = $${params.length}`);
  }
  if (touchesIcon) {
    params.push(icon);
    sets.push(`icon = $${params.length}`);
  }

  const changed: string[] = [];
  if (touchesName) changed.push(`name → '${name}'`);
  if (touchesIcon) changed.push(icon === null ? "icon cleared" : "icon replaced");

  const view = await slice.db.transaction(async (tx) => {
    const res = await tx.query(
      `UPDATE tenants SET ${sets.join(", ")} WHERE id = $1
       RETURNING id, name, icon, status, created_at`,
      params,
    );
    if (res.rows.length === 0) return null;
    await slice.audit.appendTo(tx, {
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: root,
      purpose: "console-organization-settings",
      result: "ok",
      detail: `organization settings updated (${changed.join(", ")})`,
    });
    return toView(res.rows[0] as OrganizationRow, identity);
  });
  if (view === null) throw new SettingsBadRequestError("no organization resolves for this account");
  return view;
}

/** Validate the required name every human account carries. */
function normalizedDisplayName(value: unknown): string {
  try {
    return normalizedHumanDisplayName(value);
  } catch (error) {
    if (error instanceof HumanDisplayNameError) {
      throw new SettingsBadRequestError(error.message);
    }
    throw error;
  }
}

/**
 * Set the signed-in person's own presentation fields. Self-service for every
 * role — the subject is the session user and nothing else (D9).
 */
export async function updateMemberProfile(
  slice: SettingsSlice,
  body: MemberProfileUpdate,
  identity: Identity,
): Promise<MemberProfileView> {
  if (identity.role === "agent" || identity.sessionUserId === undefined) {
    throw new AuthzError("a profile update requires a signed-in human session");
  }
  const touchesName = Object.prototype.hasOwnProperty.call(body, "displayName");
  const touchesAvatar = Object.prototype.hasOwnProperty.call(body, "avatar");
  if (!touchesName && !touchesAvatar) {
    throw new SettingsBadRequestError("supply 'displayName' and/or 'avatar'");
  }
  const displayName = touchesName ? normalizedDisplayName(body.displayName) : null;
  const avatar = touchesAvatar ? normalizedRasterDataUrl(body.avatar, "avatar") : null;
  const userId = identity.sessionUserId;
  const updated = await slice.db.transaction(async (tx): Promise<MemberProfileView | null> => {
    const sets: string[] = [];
    const params: unknown[] = [userId];
    if (touchesName) {
      params.push(displayName);
      sets.push(`display_name = $${params.length}`);
    }
    if (touchesAvatar) {
      params.push(avatar);
      sets.push(`avatar = $${params.length}`);
    }
    const res = await tx.query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $1 AND status = 'active'
       RETURNING display_name, avatar`,
      params,
    );
    if (res.rows.length === 0) return null;
    const changed = [
      ...(touchesName ? ["display name updated"] : []),
      ...(touchesAvatar ? [avatar === null ? "avatar cleared" : "avatar updated"] : []),
    ];
    await slice.audit.appendTo(tx, {
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: identity.namespace,
      purpose: "console-profile-settings",
      result: "ok",
      detail: changed.join(", "),
    });
    const row = res.rows[0] as { display_name: string; avatar: string | null };
    return { displayName: row.display_name, avatar: row.avatar };
  });
  if (updated === null) throw new SettingsBadRequestError("no active account resolves for this session");
  return updated;
}

/** Backward-compatible narrow facade for callers that update only the name. */
export async function updateMemberDisplayName(
  slice: SettingsSlice,
  body: { displayName?: unknown },
  identity: Identity,
): Promise<{ displayName: string }> {
  const updated = await updateMemberProfile(slice, body, identity);
  return { displayName: updated.displayName };
}
