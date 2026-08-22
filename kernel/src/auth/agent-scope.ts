/**
 * D50 (CONTRACTS-AGENT-SCOPE.md) — the ONE place that decides where an agent
 * credential may be bound and at what level.
 *
 * The product rule this module encodes:
 *
 *   An agent never has more authority than the human who deployed it, and no
 *   agent is ever organization-wide.
 *
 * Two absolute bounds, checked before the issuer's own authority:
 *
 *  1. `namespace === ""` is refused for EVERY issuer, root owner included. An
 *     agent is bound to a team or an individual, never to the organization.
 *  2. Team ceiling — when the install has registered teams, the target must be
 *     a team namespace or a descendant of one. A namespace that merely CONTAINS
 *     teams (a tenant root) is above the ceiling and refused. With no teams
 *     registered (fresh install, hermetic tests) the ceiling browns out to
 *     rule 1 rather than hard-failing (non-negotiable #5).
 *
 * Then the issuer table: root owner → anywhere below the ceiling; owner/admin →
 * its own subtree; member → its OWN namespace exactly, `member` level only;
 * everyone else → denied.
 *
 * D9 holds throughout: `caller` is the resolved server-side Identity, and the
 * returned level is what gets persisted — a request body never decides either.
 */

import type { Db } from "../db/client.js";
import type { AgentAccessLevel, Identity, Namespace } from "../types.js";
import { AuthzError, isRootOwner, isSelfOrDescendant } from "./index.js";

export const AGENT_ACCESS_LEVELS: readonly AgentAccessLevel[] = ["manager", "member"];

export function isAgentAccessLevel(value: unknown): value is AgentAccessLevel {
  return value === "manager" || value === "member";
}

/**
 * The level an agent Identity acts at. A NULL/absent value on an agent row
 * (minted before migration 59) reads as the least-privileged level.
 */
export function effectiveAgentLevel(identity: Identity): AgentAccessLevel | null {
  if (identity.role !== "agent") return null;
  return isAgentAccessLevel(identity.agentAccessLevel) ? identity.agentAccessLevel : "member";
}

/** True for an agent credential that today's issuance rules would refuse. */
export function isOutOfPolicyAgentBinding(role: string, namespace: Namespace): boolean {
  return role === "agent" && namespace === "";
}

/** 400-mapped input error (same `name` convention as the other console errors). */
export class AgentScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

/**
 * Registered team namespaces. Returns null — meaning "no ceiling to enforce" —
 * when the table is absent (hermetic fixtures build api_keys from DDL without
 * the console schema) or empty. Never throws: a governance read that fails must
 * degrade to the stricter rule-1-only check, not break issuance.
 */
async function teamNamespaces(db: Db): Promise<string[] | null> {
  try {
    const res = await db.query(`SELECT namespace FROM org_teams`);
    const rows = res.rows as Array<{ namespace?: unknown }>;
    const namespaces = rows
      .map((row) => row.namespace)
      .filter((value): value is string => typeof value === "string" && value.length > 0);
    return namespaces.length > 0 ? namespaces : null;
  } catch {
    return null;
  }
}

export interface AgentScopeRequest {
  namespace: Namespace;
  /** Requested level; undefined means "the most this issuer may grant". */
  level?: AgentAccessLevel;
}

export interface AgentScopeDecision {
  namespace: Namespace;
  level: AgentAccessLevel;
}

/**
 * Authorize one agent-credential binding. Returns the (namespace, level) that
 * must be persisted; throws AuthzError (403) or AgentScopeError (400).
 *
 * Callers are responsible for the D4 denial audit row — this function stays
 * pure so it can be reused by issuance, badge issuance, and dry-run validation
 * without writing three different audit shapes.
 */
export async function assertAgentKeyScope(
  db: Db,
  caller: Identity,
  request: AgentScopeRequest,
): Promise<AgentScopeDecision> {
  const namespace = request.namespace;
  if (request.level !== undefined && !isAgentAccessLevel(request.level)) {
    throw new AgentScopeError(`invalid agent access level '${String(request.level)}'`);
  }

  // Bound 1 — never organization-wide, not even for the root owner.
  if (namespace === "") {
    throw new AuthzError(
      "an agent may not be scoped to the organization root; bind it to a team or a person",
    );
  }

  // Bound 2 — team ceiling. The rule is "an agent's scope may not SPAN teams",
  // so what is refused is a namespace that CONTAINS teams without being one:
  // a tenant root like `acme` when the teams are `acme/marketing` and
  // `acme/sales`. A registered team is fine even when it has sub-teams (it is
  // still one team), and so is any namespace below — an individual's scope.
  // A namespace that contains no team at all spans nothing and is fine too.
  const teams = await teamNamespaces(db);
  if (teams !== null && !teams.includes(namespace)) {
    const containsATeam = teams.some(
      (team) => team !== namespace && isSelfOrDescendant(team, namespace),
    );
    if (containsATeam) {
      throw new AuthzError(
        `an agent's scope may not exceed one team; '${namespace}' spans more than one team`,
      );
    }
  }

  // Issuer authority.
  if (caller.role === "member") {
    if (namespace !== caller.namespace) {
      throw new AuthzError(
        "you may only deploy agents in your own team scope",
      );
    }
    if (request.level === "manager") {
      throw new AuthzError(
        "a member may only deploy member-scope agents",
      );
    }
    return { namespace, level: "member" };
  }

  if (caller.role !== "owner" && caller.role !== "admin") {
    throw new AuthzError(
      `role '${caller.role}' may not deploy agents`,
    );
  }
  if (!isRootOwner(caller) && !isSelfOrDescendant(namespace, caller.namespace)) {
    throw new AuthzError(
      `namespace '${namespace}' is outside your subtree`,
    );
  }
  return { namespace, level: request.level ?? "member" };
}
