/**
 * Canonical human control-room RBAC for the Teams surface.
 *
 * The server-owned map is the authority. Console copy may explain it, but no
 * screen gets to invent a second role matrix. Agents are deliberately absent:
 * they are machine principals, never human team members.
 */

import { describe, expect, it } from "vitest";

import {
  HUMAN_ROLE_PERMISSIONS,
  canHuman,
} from "../src/console/rbac.js";

const ACTIONS = [
  "teams:read",
  "teams:write",
  "members:invite",
  "members:write",
  "roles:write",
  "organization:write",
] as const;

describe("canonical human RBAC", () => {
  it("publishes the exact role-to-action map used by the Teams control room", () => {
    expect(HUMAN_ROLE_PERMISSIONS).toEqual({
      owner: ACTIONS,
      admin: [
        "teams:read",
        "teams:write",
        "members:invite",
        "members:write",
        "organization:write",
      ],
      auditor: ["teams:read"],
      member: [],
    });
    expect("agent" in HUMAN_ROLE_PERMISSIONS).toBe(false);
  });

  it("answers authorization checks only from the canonical map", () => {
    for (const action of ACTIONS) expect(canHuman("owner", action)).toBe(true);

    expect(canHuman("admin", "teams:write")).toBe(true);
    expect(canHuman("admin", "members:invite")).toBe(true);
    expect(canHuman("admin", "members:write")).toBe(true);
    expect(canHuman("admin", "roles:write")).toBe(false);
    expect(canHuman("admin", "organization:write")).toBe(true);
    expect(canHuman("auditor", "organization:write")).toBe(false);
    expect(canHuman("member", "organization:write")).toBe(false);

    expect(canHuman("auditor", "teams:read")).toBe(true);
    expect(canHuman("auditor", "teams:write")).toBe(false);
    expect(canHuman("member", "teams:read")).toBe(false);
    expect(canHuman("agent", "teams:read")).toBe(false);
  });
});
