import { describe, expect, it } from "vitest";

import {
  canonicalHash,
  SCREEN_ROUTES,
  screenIdFromHash,
  screenTargetHash,
} from "../console/routes.js";

describe("console public hash routes", () => {
  it("uses readable names for every console section", () => {
    expect(SCREEN_ROUTES).toEqual({
      s1: "setup",
      s2: "home",
      s3: "scopedmemory",
      s4: "policies",
      s5: "memory",
      s6: "sources",
      s7: "knowledgereview",
      s8: "audit",
      s9: "retrievalquality",
      s11: "conflicts",
      s13: "teams",
      s14: "agentconnections",
      s16: "skills",
      s17: "connectedapps",
      s18: "settings",
      s19: "alerts",
      s20: "export",
    });
    expect(screenTargetHash("s13")).toBe("#teams");
    expect(screenTargetHash("s20")).toBe("#export");
    expect(screenTargetHash("s8")).toBe("#audit");
    expect(screenTargetHash("s17")).toBe("#connectedapps");
    expect(screenTargetHash("s14")).toBe("#agentconnections");
    expect(screenTargetHash("s16")).toBe("#skills");
  });

  it("preserves query parameters on named routes", () => {
    expect(screenTargetHash("s18?tab=profile")).toBe("#settings?tab=profile");
    expect(screenTargetHash("s17?status=ok")).toBe("#connectedapps?status=ok");
  });

  it("resolves both named and legacy numeric hashes to internal screen ids", () => {
    expect(screenIdFromHash("#teams")).toBe("s13");
    expect(screenIdFromHash("#connectedapps?status=ok")).toBe("s17");
    expect(screenIdFromHash("#s13")).toBe("s13");
    expect(screenIdFromHash("#unknown")).toBeNull();
    expect(screenIdFromHash("#toString")).toBeNull();
    expect(screenTargetHash("constructor")).toBeNull();
  });

  it("canonicalizes legacy bookmarks without dropping their query", () => {
    expect(canonicalHash("#s13")).toBe("#teams");
    expect(canonicalHash("#s18?linked=github")).toBe("#settings?linked=github");
    expect(canonicalHash("#teams")).toBe("#teams");
    expect(canonicalHash("#unknown")).toBeNull();
  });
});
