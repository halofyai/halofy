/**
 * S13 — teams. Named, namespace-backed groups an owner/admin creates, plus
 * explicit human membership (many-to-many over `users`).
 *
 * A team IS a namespace: creating "Support" under caller namespace `acme`
 * mints the namespace `acme/support`, so every existing ACL rule (ancestor
 * read-down, subtree admin scope, sibling invisibility) applies to it with no
 * new machinery. Membership rows are org structure — a roster, not memory —
 * so removal is a plain delete; every mutation still writes an audit row (D4).
 *
 * Scoping mirrors console/api.ts: root owner sees org-wide; everyone else
 * sees teams at their own namespace or below (exact match + escaped LIKE —
 * never an unescaped wildcard). Callers never assert a namespace (D9): the
 * team namespace is derived server-side from the caller's identity.
 */

import { ulid } from "ulid";
import type { Db } from "../db/client.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "../auth/index.js";
import type { AuditLog } from "../audit/index.js";
import type {
  HumanRole,
  Identity,
  Namespace,
  TeamMemoryAccessMode,
  TeamMemoryAccessView,
} from "../types.js";
import type { ConsoleUser, MembershipGrantSyncLike } from "./api.js";
import type {
  CreateInvitationInput,
  InvitationRotationKind,
  IssuedInvitation,
} from "./auth.js";
import { canHuman, type HumanAction } from "./rbac.js";
import { fromProductRole, toProductRole } from "../iam/product-roles.js";
import {
  resolveOrganizationNamespace,
  tenantRoots,
  TeamMemoryAccessPolicy,
} from "../team-memory-access/index.js";

const AGENT_ID = "console";

/** The structural kernel subset the team handlers consume. */
export interface TeamsSlice {
  readonly db: Db;
  readonly audit: AuditLog;
  /** Human roster visible to the caller (ancestor-subtree scoped, Module A). */
  listUsers(identity: Identity): Promise<ConsoleUser[]>;
  /**
   * M10: `access_grants` membership sync. When wired, roster mutations call
   * it INSIDE the same transaction — the grant and the roster row commit or
   * roll back together (one permission system, never drift).
   */
  readonly membershipGrants?: MembershipGrantSyncLike;
}

/**
 * Whether a role governs (vs consumes) the functions it is enrolled in.
 * Accepts internal ('owner') and product ('root') spellings — roster rows
 * may surface either at this seam (D41 boundary translation).
 */
function governsFunctions(role: string): boolean {
  return role === "owner" || role === "root" || role === "admin";
}

/** Tenant ROOT namespace of a team namespace: its first `/`-segment. */
function tenantRootOf(namespace: Namespace): Namespace {
  const idx = namespace.indexOf("/");
  return idx === -1 ? namespace : namespace.slice(0, idx);
}

export interface TeamMember {
  userId: string;
  email: string;
  displayName: string;
  avatar?: string | null;
  /** Product role at the boundary (D41): root | admin | member. */
  role: string;
  /** Account availability for recipient and roster actions. */
  status: "active" | "disabled";
  /** Scoped entitlements (legacy auditor -> ["audit:read"]); omitted if none. */
  entitlements?: readonly string[];
  namespace: Namespace;
  addedAt: string;
}

export interface Team {
  id: string;
  namespace: Namespace;
  name: string;
  description: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  status: "active" | "archived";
  archivedAt: string | null;
  members: TeamMember[];
  invitations: TeamInvitation[];
  memoryAccess: TeamMemoryAccessView;
}

export interface TeamInvitation {
  id: string;
  email: string;
  displayName: string;
  role: string;
  status: "waiting" | "expired" | "joined" | "revoked";
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  revokedAt: string | null;
  lastRemindedAt: string | null;
}

export interface PersonAccessImpact {
  userId: string;
  email: string;
  status: string;
  protected: boolean;
  teams: Array<{ id: string; name: string }>;
  activeSessions: number;
  createdAgentKeys: number;
  externalIdentityProviders: string[];
}

export interface CreateTeamInput {
  name: string;
  description?: string;
}

export interface InviteTeamMemberInput {
  email: string;
  displayName: string;
  /**
   * PRODUCT role (`root`/`admin`/`member`, D41). The retired internal
   * spellings `owner`/`auditor` are rejected by `fromProductRole`.
   */
  role: string;
}

export interface TeamInvitationIssuer {
  create(input: CreateInvitationInput, caller: Identity): Promise<IssuedInvitation>;
  rotate(
    input: {
      invitationId: string;
      namespace: string;
      kind: InvitationRotationKind;
      ttlSeconds?: number;
    },
    caller: Identity,
  ): Promise<IssuedInvitation>;
  revoke(
    input: { invitationId: string; namespace: string },
    caller: Identity,
  ): Promise<{ revoked: boolean }>;
}

export class TeamBadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Escape LIKE metacharacters so a namespace is matched literally. */
function escapeLike(literal: string): string {
  return literal.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * A `teams.namespace` predicate for the caller's own subtree (self +
 * descendants; root owner → everything). Exact match + escaped LIKE — the
 * same discipline as every other console read path.
 */
function teamScopePredicate(
  identity: Identity,
  startAt: number,
): { sql: string; params: string[] } {
  if (isRootOwner(identity)) return { sql: "TRUE", params: [] };
  return {
    sql: `(namespace = $${startAt} OR namespace LIKE $${startAt + 1} ESCAPE '\\')`,
    params: [identity.namespace, escapeLike(identity.namespace) + "/%"],
  };
}

/**
 * Derive the team's namespace segment from its display name: lowercased,
 * spaces → `-`, everything outside [a-z0-9-] dropped. "Support EU" → "support-eu".
 */
export function teamSlug(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
}

function assertCan(identity: Identity, action: HumanAction): void {
  if (canHuman(identity.role, action)) return;
  throw new AuthzError(`role '${identity.role}' may not perform '${action}'`);
}

/** Resolve a selected team id inside the caller's visible subtree (D9). */
export async function resolveTeamNamespace(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
): Promise<Namespace> {
  assertCan(identity, "teams:write");
  return (await requireTeam(slice, identity, teamId)).namespace;
}

async function auditTeamAction(
  slice: TeamsSlice,
  db: Db,
  identity: Identity,
  namespace: Namespace,
  purpose: string,
  detail: string,
): Promise<void> {
  await slice.audit.appendTo(db, {
    ts: new Date().toISOString(),
    actor: identity.actor,
    agentId: AGENT_ID,
    op: "write",
    memoryId: null,
    namespace,
    purpose,
    result: "ok",
    detail,
  });
}

interface TeamRow {
  id: string;
  namespace: string;
  name: string;
  description: string;
  created_by: string;
  created_at: Date | string;
  updated_at: Date | string;
  archived_at: Date | string | null;
  organization_namespace: string;
  memory_access_mode: string;
  memory_access_version: number | string;
}

interface InvitationRow {
  id: string;
  email: string;
  display_name: string;
  namespace: string;
  role: HumanRole;
  created_at: Date | string;
  expires_at: Date | string;
  accepted_at: Date | string | null;
  revoked_at: Date | string | null;
  last_reminded_at: Date | string | null;
}

interface MemberRow {
  team_id: string;
  user_id: string;
  email: string;
  display_name: string;
  avatar: string | null;
  role: string;
  status: "active" | "disabled";
  namespace: string;
  added_at: Date | string;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/** Teams inside the caller's subtree, each with its full member roster. */
export async function listTeams(
  slice: TeamsSlice,
  identity: Identity,
): Promise<Team[]> {
  assertCan(identity, "teams:read");
  const scope = teamScopePredicate(identity, 1);
  const teamsRes = await slice.db.query(
    `SELECT id, namespace, name, description, created_by, created_at,
            updated_at, archived_at,
            organization_namespace, memory_access_mode, memory_access_version
       FROM org_teams WHERE ${scope.sql} ORDER BY namespace`,
    scope.params,
  );
  const rows = teamsRes.rows as unknown as TeamRow[];
  if (rows.length === 0) return [];

  const ids = rows.map((row) => row.id);
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
  const membersRes = await slice.db.query(
    `SELECT tm.team_id, tm.user_id, tm.added_at, u.email, u.display_name, u.avatar,
            u.role, u.status, u.namespace
       FROM org_team_members tm JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id IN (${placeholders})
      ORDER BY tm.added_at`,
    ids,
  );
  const byTeam = new Map<string, TeamMember[]>();
  for (const raw of membersRes.rows as unknown as MemberRow[]) {
    const list = byTeam.get(raw.team_id) ?? [];
    // D41: the member detail crosses the console boundary with a PRODUCT
    // role (owner -> root, auditor -> member + audit:read entitlement).
    const view = toProductRole(raw.role);
    list.push({
      userId: raw.user_id,
      email: raw.email,
      displayName: raw.display_name,
      avatar: raw.avatar,
      role: view.role,
      status: raw.status,
      ...(view.entitlements.length > 0 ? { entitlements: view.entitlements } : {}),
      namespace: raw.namespace,
      addedAt: toIso(raw.added_at),
    });
    byTeam.set(raw.team_id, list);
  }
  const invitationRes = await slice.db.query(
    `SELECT id, email, display_name, namespace, role, created_at, expires_at, accepted_at,
            revoked_at, last_reminded_at
       FROM auth_invitations
      WHERE namespace IN (${placeholders})
      ORDER BY created_at DESC`,
    rows.map((row) => row.namespace),
  );
  const invitationByNamespace = new Map<string, TeamInvitation[]>();
  const now = Date.now();
  for (const raw of invitationRes.rows as unknown as InvitationRow[]) {
    const invitations = invitationByNamespace.get(raw.namespace) ?? [];
    const status: TeamInvitation["status"] = raw.revoked_at !== null
      ? "revoked"
      : raw.accepted_at !== null
        ? "joined"
        : new Date(raw.expires_at).getTime() <= now
          ? "expired"
          : "waiting";
    invitations.push({
      id: raw.id,
      email: raw.email,
      displayName: raw.display_name,
      role: toProductRole(raw.role).role,
      status,
      createdAt: toIso(raw.created_at),
      expiresAt: toIso(raw.expires_at),
      acceptedAt: raw.accepted_at === null ? null : toIso(raw.accepted_at),
      revokedAt: raw.revoked_at === null ? null : toIso(raw.revoked_at),
      lastRemindedAt: raw.last_reminded_at === null ? null : toIso(raw.last_reminded_at),
    });
    invitationByNamespace.set(raw.namespace, invitations);
  }
  const access = new TeamMemoryAccessPolicy(slice.db, slice.audit);
  return rows.map((row) => ({
    id: row.id,
    namespace: row.namespace,
    name: row.name,
    description: row.description,
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at ?? row.created_at),
    status: row.archived_at == null ? "active" : "archived",
    archivedAt: row.archived_at == null ? null : toIso(row.archived_at),
    members: byTeam.get(row.id) ?? [],
    invitations: invitationByNamespace.get(row.namespace) ?? [],
    memoryAccess: access.accessView(identity, row),
  }));
}

/**
 * Create a team under the CALLER's namespace (owner/admin only). The namespace
 * is derived server-side (`<caller-ns>/<slug(name)>`) — the request never
 * carries one (D9). The PLATFORM root (namespace "") is not an organization:
 * a team it creates must still land inside one, so the sole tenant is used as
 * the prefix. Minting `<slug>` at the top level would orphan the team outside
 * every org — no `organization_namespace`, invisible to the per-org setup
 * checklist — which is exactly the stranded-data shape the halofy deployment
 * had to be repaired from.
 */
export async function createTeam(
  slice: TeamsSlice,
  identity: Identity,
  input: CreateTeamInput,
): Promise<Team> {
  assertCan(identity, "teams:write");
  const name = String(input.name ?? "").trim();
  if (name.length === 0 || name.length > 80) {
    throw new TeamBadRequestError("team name must be 1-80 characters");
  }
  const description = String(input.description ?? "").trim().slice(0, 280);
  const slug = teamSlug(name);
  if (slug.length === 0) {
    throw new TeamBadRequestError(
      "team name must contain at least one letter or digit",
    );
  }
  let namespace: Namespace;
  if (identity.namespace === "") {
    const roots = await tenantRoots(slice.db);
    if (roots.length > 1) {
      throw new TeamBadRequestError(
        "multiple organizations exist - the platform root must create teams from within an organization scope",
      );
    }
    namespace = roots.length === 1 ? `${roots[0]}/${slug}` : slug;
  } else {
    namespace = `${identity.namespace}/${slug}`;
  }

  const id = ulid();
  const createdAt = new Date().toISOString();
  const organizationNamespace = await resolveOrganizationNamespace(slice.db, namespace);
  try {
    await slice.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO org_teams
           (id, namespace, organization_namespace, name, description, created_by,
            created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
        [id, namespace, organizationNamespace, name, description, identity.actor, createdAt],
      );
      await auditTeamAction(
        slice,
        tx,
        identity,
        namespace,
        "console-team-create",
        `team '${name}' created`,
      );
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/unique|duplicate/i.test(message)) {
      throw new TeamBadRequestError(`a team at '${namespace}' already exists`);
    }
    throw err;
  }
  return {
    id,
    namespace,
    name,
    description,
    createdBy: identity.actor,
    createdAt,
    updatedAt: createdAt,
    status: "active",
    archivedAt: null,
    members: [],
    invitations: [],
    memoryAccess: new TeamMemoryAccessPolicy(slice.db, slice.audit).accessView(identity, {
      id,
      namespace,
      organization_namespace: organizationNamespace,
      memory_access_mode: "related",
      memory_access_version: 1,
    }),
  };
}

/** Resolve a team by id, asserting it is inside the caller's subtree. */
async function requireTeam(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
): Promise<TeamRow> {
  const res = await slice.db.query(
    `SELECT id, namespace, name, description, created_by, created_at,
            updated_at, archived_at,
            organization_namespace, memory_access_mode, memory_access_version
       FROM org_teams WHERE id = $1`,
    [teamId],
  );
  const row = res.rows[0] as unknown as TeamRow | undefined;
  if (row === undefined) throw new TeamBadRequestError(`no team with id '${teamId}'`);
  if (!isRootOwner(identity) && !isSelfOrDescendant(row.namespace, identity.namespace)) {
    // Same message shape as the miss above — a sibling team is invisible, not
    // merely forbidden (no existence oracle across the sibling fence).
    throw new TeamBadRequestError(`no team with id '${teamId}'`);
  }
  return row;
}

function assertActiveTeam(team: TeamRow): void {
  if (team.archived_at != null) {
    throw new TeamBadRequestError("archived teams are read-only until restored");
  }
}

export async function renameTeam(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  nameInput: string,
): Promise<Team> {
  assertCan(identity, "teams:write");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  const name = String(nameInput ?? "").trim();
  if (name.length === 0 || name.length > 80) {
    throw new TeamBadRequestError("team name must be 1-80 characters");
  }
  const updatedAt = new Date().toISOString();
  await slice.db.transaction(async (tx) => {
    await tx.query(`UPDATE org_teams SET name = $1, updated_at = $2 WHERE id = $3`, [
      name,
      updatedAt,
      team.id,
    ]);
    await auditTeamAction(
      slice,
      tx,
      identity,
      team.namespace,
      "console-team-rename",
      `team renamed from '${team.name}' to '${name}'; address unchanged`,
    );
  });
  return (await listTeams(slice, identity)).find((candidate) => candidate.id === team.id)!;
}

export async function setTeamArchived(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  archived: boolean,
): Promise<Team> {
  if (identity.role !== "owner") {
    throw new AuthzError("only owners may archive or restore teams");
  }
  const team = await requireTeam(slice, identity, teamId);
  const changedAt = new Date().toISOString();
  await slice.db.transaction(async (tx) => {
    await tx.query(
      `UPDATE org_teams
          SET archived_at = $1, archived_by = $2, updated_at = $3
        WHERE id = $4`,
      [archived ? changedAt : null, archived ? identity.actor : null, changedAt, team.id],
    );
    await auditTeamAction(
      slice,
      tx,
      identity,
      team.namespace,
      archived ? "console-team-archive" : "console-team-restore",
      archived ? `team '${team.name}' archived` : `team '${team.name}' restored`,
    );
  });
  return (await listTeams(slice, identity)).find((candidate) => candidate.id === team.id)!;
}

/** Change one server-resolved team's effective company-memory mode. */
export async function changeTeamMemoryAccess(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  mode: TeamMemoryAccessMode,
): Promise<Team> {
  const policy = new TeamMemoryAccessPolicy(slice.db, slice.audit);
  let team: TeamRow;
  try {
    team = await requireTeam(slice, identity, teamId);
  } catch (error) {
    // Preserve the policy service's audited denial/miss behavior for callers
    // outside the selected team's scope. It will throw; the fallback throw is
    // only for type completeness.
    await policy.change(identity, teamId, mode);
    throw error;
  }
  assertActiveTeam(team);
  await policy.change(identity, teamId, mode);
  const teams = await listTeams(slice, identity);
  const selectedTeam = teams.find((candidate) => candidate.id === teamId);
  if (!selectedTeam) throw new TeamBadRequestError(`no team with id '${teamId}'`);
  return selectedTeam;
}

/**
 * Add a human to a team (owner/admin only). The user is resolved through the
 * caller-scoped roster (listUsers' ancestor-subtree ACL), so a caller can only
 * ever add people it is allowed to see.
 */
export async function addTeamMember(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  email: string,
): Promise<Team[]> {
  assertCan(identity, "members:write");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  const normalized = String(email ?? "").trim().toLowerCase();
  if (normalized.length === 0) throw new TeamBadRequestError("member email is required");
  const visible = await slice.listUsers(identity);
  const user = visible.find((u) => u.email.toLowerCase() === normalized);
  if (user === undefined) {
    throw new TeamBadRequestError(`no visible person with email '${normalized}'`);
  }
  try {
    await slice.db.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO org_team_members (team_id, user_id, added_by, added_at)
         VALUES ($1, $2, $3, $4)`,
        [team.id, user.id, identity.actor, new Date().toISOString()],
      );
      // M10: the matching grant commits WITH the roster row (D9: the
      // namespace root is re-resolved from org_teams inside the same tx).
      // Mode follows the member's INTERNAL role: owner/admin govern the
      // function subtree, member/auditor consume it (PRD §7.3).
      if (slice.membershipGrants) {
        await slice.membershipGrants.syncMembershipGrant(tx, {
          tenantId: tenantRootOf(team.namespace),
          userId: user.id,
          teamOrFunctionId: team.id,
          action: "add",
          actor: identity.actor,
          accessMode: governsFunctions(user.role) ? "govern" : "consume",
        });
      }
      await auditTeamAction(
        slice,
        tx,
        identity,
        team.namespace,
        "console-team-member-add",
        `member '${normalized}' added to team '${team.name}'`,
      );
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/unique|duplicate/i.test(message)) {
      throw new TeamBadRequestError(`'${normalized}' is already a member of this team`);
    }
    throw err;
  }
  return listTeams(slice, identity);
}

/** Remove a member (owner/admin only). Idempotent on an absent membership. */
export async function removeTeamMember(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  userId: string,
): Promise<Team[]> {
  assertCan(identity, "members:write");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  await slice.db.transaction(async (tx) => {
    await tx.query(
      `DELETE FROM org_team_members WHERE team_id = $1 AND user_id = $2`,
      [team.id, userId],
    );
    // M10: revoke the membership grant in the SAME transaction (D47: a row
    // state, never a delete). Roster and grants can never drift.
    if (slice.membershipGrants) {
      await slice.membershipGrants.syncMembershipGrant(tx, {
        tenantId: tenantRootOf(team.namespace),
        userId,
        teamOrFunctionId: team.id,
        action: "remove",
        actor: identity.actor,
      });
    }
    await auditTeamAction(
      slice,
      tx,
      identity,
      team.namespace,
      "console-team-member-remove",
      `member '${userId}' removed from team '${team.name}'`,
    );
  });
  return listTeams(slice, identity);
}

/**
 * Invite a human into a selected team. The selected team is re-resolved in
 * the caller's subtree and supplies the invitation namespace (D9); the input
 * cannot assert a namespace.
 */
export async function inviteTeamMember(
  slice: TeamsSlice,
  invitations: TeamInvitationIssuer,
  identity: Identity,
  teamId: string,
  input: InviteTeamMemberInput,
): Promise<IssuedInvitation> {
  assertCan(identity, "members:invite");
  // D41 inverse guard: the public input is a PRODUCT role. `owner`/`auditor`
  // spellings are retired and throw; `root` maps to the internal `owner`
  // through this documented owner-gated assignment route only.
  const internalRole: HumanRole = fromProductRole(String(input.role), {
    rootAssignment: true,
  });
  if (identity.role === "admin" && internalRole === "owner") {
    throw new AuthzError("admins may not invite root");
  }
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  const normalizedEmail = String(input.email ?? "").trim().toLowerCase();
  if (normalizedEmail) {
    const visibleTeams = await listTeams(slice, identity);
    const blockingTeam = visibleTeams.find((candidate) => candidate.invitations.some((invitation) =>
      invitation.email.trim().toLowerCase() === normalizedEmail &&
      (invitation.status === "waiting" || invitation.status === "expired"),
    ));
    if (blockingTeam) {
      throw new TeamBadRequestError(
        `This email already has a live invitation pending for ${blockingTeam.name}. ` +
        "Revoke it there or send a reminder instead of inviting again.",
      );
    }
  }
  return invitations.create({
    email: input.email,
    displayName: input.displayName,
    namespace: team.namespace,
    role: internalRole,
  }, identity);
}

export async function rotateTeamInvitation(
  slice: TeamsSlice,
  invitations: TeamInvitationIssuer,
  identity: Identity,
  teamId: string,
  invitationId: string,
  kind: InvitationRotationKind,
): Promise<IssuedInvitation> {
  assertCan(identity, "members:invite");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  return invitations.rotate({ invitationId, namespace: team.namespace, kind }, identity);
}

export async function revokeTeamInvitation(
  slice: TeamsSlice,
  invitations: TeamInvitationIssuer,
  identity: Identity,
  teamId: string,
  invitationId: string,
): Promise<{ revoked: boolean }> {
  assertCan(identity, "members:invite");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  return invitations.revoke({ invitationId, namespace: team.namespace }, identity);
}

interface RoleTargetRow {
  id: string;
  email: string;
  namespace: string;
  role: HumanRole;
  status: string;
}

/**
 * Owner-only role change for an existing human member of a scoped team.
 * `role` is a PRODUCT role (D41): `root` maps to internal `owner` through
 * this documented owner-gated root-assignment route; the retired `owner`
 * and `auditor` spellings are rejected by `fromProductRole` — no new
 * internal auditor/owner rows are ever minted from public input.
 */
export async function changeTeamMemberRole(
  slice: TeamsSlice,
  identity: Identity,
  teamId: string,
  userId: string,
  role: string,
): Promise<Team[]> {
  assertCan(identity, "roles:write");
  const team = await requireTeam(slice, identity, teamId);
  assertActiveTeam(team);
  const internalRole: HumanRole = fromProductRole(String(role), {
    rootAssignment: true,
  });

  await slice.db.transaction(async (tx) => {
    const targetResult = await tx.query(
      `SELECT u.id, u.email, u.namespace, u.role, u.status
         FROM org_team_members tm
         JOIN users u ON u.id = tm.user_id
        WHERE tm.team_id = $1 AND tm.user_id = $2
        FOR UPDATE OF u`,
      [team.id, userId],
    );
    const target = targetResult.rows[0] as unknown as RoleTargetRow | undefined;
    if (target === undefined) {
      throw new TeamBadRequestError(`user '${userId}' is not a member of this team`);
    }
    if (!isSelfOrDescendant(target.namespace, team.namespace)) {
      throw new TeamBadRequestError("member home namespace is outside the team subtree");
    }

    if (target.role === "owner" && target.status === "active" && internalRole !== "owner") {
      const namespacePattern = escapeLike(team.namespace) + "/%";
      const activeOwners = await tx.query(
        `SELECT u.id
           FROM users u
          WHERE u.role = 'owner'
            AND u.status = 'active'
            AND (u.namespace = $1 OR u.namespace LIKE $2 ESCAPE '\\')
            AND EXISTS (
              SELECT 1
                FROM org_team_members tm
                JOIN org_teams child ON child.id = tm.team_id
               WHERE tm.user_id = u.id
                 AND (child.namespace = $1 OR child.namespace LIKE $2 ESCAPE '\\')
            )
          FOR UPDATE OF u`,
        [team.namespace, namespacePattern],
      );
      if (activeOwners.rows.length <= 1) {
        throw new TeamBadRequestError("cannot demote the final active owner in the team subtree");
      }
    }

    await tx.query(`UPDATE users SET role = $1 WHERE id = $2`, [internalRole, target.id]);
    // M10 (PRD §11): the roster is the ONE source of functional grants.
    // `users.role` is global, so a role change re-syncs the grant mode of
    // EVERY team membership this user holds in the tenant, in the same tx
    // (admin/owner -> govern, member -> consume). Never two drifting systems.
    if (slice.membershipGrants) {
      const tenantId = tenantRootOf(team.namespace);
      const mode = governsFunctions(internalRole) ? "govern" as const : "consume" as const;
      const memberships = await tx.query(
        `SELECT tm.team_id
           FROM org_team_members tm
           JOIN org_teams t ON t.id = tm.team_id
          WHERE tm.user_id = $1
            AND (t.namespace = $2 OR t.namespace LIKE $3 ESCAPE '\\')`,
        [target.id, tenantId, escapeLike(tenantId) + "/%"],
      );
      for (const raw of memberships.rows) {
        await slice.membershipGrants.syncMembershipGrant(tx, {
          tenantId,
          userId: target.id,
          teamOrFunctionId: (raw as { team_id: string }).team_id,
          action: "update",
          actor: identity.actor,
          accessMode: mode,
        });
      }
    }
    await slice.audit.appendTo(tx, {
      ts: new Date().toISOString(),
      actor: identity.actor,
      agentId: AGENT_ID,
      op: "write",
      memoryId: null,
      namespace: team.namespace,
      purpose: "console-team-member-role-change",
      result: "ok",
      detail: `member '${target.email}' role changed from '${target.role}' to '${internalRole}'`,
    });
  });

  return listTeams(slice, identity);
}

async function requireVisiblePerson(
  slice: TeamsSlice,
  identity: Identity,
  userId: string,
): Promise<ConsoleUser> {
  assertCan(identity, "teams:read");
  const visible = await slice.listUsers(identity);
  const user = visible.find((candidate) => candidate.id === userId);
  if (!user) throw new TeamBadRequestError(`no visible person with id '${userId}'`);
  return user;
}

export async function personAccessImpact(
  slice: TeamsSlice,
  identity: Identity,
  userId: string,
): Promise<PersonAccessImpact> {
  const user = await requireVisiblePerson(slice, identity, userId);
  const [teams, sessions, keys, external] = await Promise.all([
    slice.db.query(
      `SELECT t.id, t.name
         FROM org_team_members tm
         JOIN org_teams t ON t.id = tm.team_id
        WHERE tm.user_id = $1
        ORDER BY t.name`,
      [user.id],
    ),
    slice.db.query(
      `SELECT COUNT(*)::int AS count FROM sessions
        WHERE user_id = $1 AND expires_at > $2`,
      [user.id, new Date().toISOString()],
    ),
    slice.db.query(
      `SELECT COUNT(*)::int AS count FROM api_keys
        WHERE created_by = $1 AND role = 'agent' AND status = 'active'`,
      [user.email],
    ),
    slice.db.query(
      `SELECT provider FROM user_external_identities
        WHERE user_id = $1 ORDER BY provider`,
      [user.id],
    ),
  ]);
  return {
    userId: user.id,
    email: user.email,
    status: user.status,
    protected: user.role === "owner" || identity.sessionUserId === user.id ||
      identity.actor.toLowerCase() === user.email.toLowerCase(),
    teams: teams.rows as Array<{ id: string; name: string }>,
    activeSessions: Number((sessions.rows[0] as { count: number | string }).count),
    createdAgentKeys: Number((keys.rows[0] as { count: number | string }).count),
    externalIdentityProviders: external.rows.map((row) => (row as { provider: string }).provider),
  };
}

export async function changePersonAccessState(
  slice: TeamsSlice,
  identity: Identity,
  userId: string,
  input: { status: "active" | "disabled"; revokeCreatedKeys?: boolean; reason?: string },
): Promise<PersonAccessImpact> {
  assertCan(identity, "members:write");
  const user = await requireVisiblePerson(slice, identity, userId);
  if (user.role === "owner") throw new TeamBadRequestError("owners are protected");
  if (
    identity.sessionUserId === user.id ||
    identity.actor.toLowerCase() === user.email.toLowerCase()
  ) {
    throw new TeamBadRequestError("you cannot suspend your own access");
  }
  const reason = String(input.reason ?? "").trim();
  if (reason.length > 500) throw new TeamBadRequestError("reason must be 500 characters or fewer");
  const changedAt = new Date().toISOString();
  await slice.db.transaction(async (tx) => {
    await tx.query(`UPDATE users SET status = $1 WHERE id = $2`, [input.status, user.id]);
    if (input.status === "disabled") {
      await tx.query(`DELETE FROM sessions WHERE user_id = $1`, [user.id]);
      // Custody is the member's live authority: suspension always removes it,
      // independent of the optional "keys they created" cleanup choice.
      await tx.query(
        `UPDATE api_keys SET status = 'revoked'
          WHERE custodian_user_id = $1 AND role = 'agent' AND status = 'active'`,
        [user.id],
      );
      await tx.query(
        `UPDATE agent_key_handoffs SET status = 'revoked', revoked_at = $1
          WHERE recipient_user_id = $2 AND status = 'pending'`,
        [changedAt, user.id],
      );
      if (input.revokeCreatedKeys === true) {
        await tx.query(
          `UPDATE api_keys SET status = 'revoked'
            WHERE created_by = $1 AND role = 'agent' AND status = 'active'`,
          [user.email],
        );
      }
    }
    await auditTeamAction(
      slice,
      tx,
      identity,
      user.namespace,
      input.status === "disabled" ? "console-person-suspend" : "console-person-reinstate",
      `person '${user.email}' ${input.status === "disabled" ? "suspended" : "reinstated"}` +
        (reason ? `; reason='${reason}'` : "") +
        (input.status === "disabled" && input.revokeCreatedKeys ? "; created agent keys revoked" : ""),
    );
  });
  return personAccessImpact(slice, identity, user.id);
}
