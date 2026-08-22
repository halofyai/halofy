/** Canonical server-owned permissions for human control-room roles. */

import type { HumanRole } from "../types.js";

export const HUMAN_ACTIONS = [
  "teams:read",
  "teams:write",
  "members:invite",
  "members:write",
  "roles:write",
  "organization:write",
] as const;

export type HumanAction = (typeof HUMAN_ACTIONS)[number];

export const HUMAN_ROLE_PERMISSIONS: Readonly<
  Record<HumanRole, readonly HumanAction[]>
> = {
  owner: HUMAN_ACTIONS,
  admin: [
    "teams:read",
    "teams:write",
    "members:invite",
    "members:write",
    "organization:write",
  ],
  auditor: ["teams:read"],
  member: [],
};

/** Fail closed for unknown roles and actions, including machine principals. */
export function canHuman(role: string, action: HumanAction): boolean {
  if (!Object.prototype.hasOwnProperty.call(HUMAN_ROLE_PERMISSIONS, role)) {
    return false;
  }
  return HUMAN_ROLE_PERMISSIONS[role as HumanRole].includes(action);
}
