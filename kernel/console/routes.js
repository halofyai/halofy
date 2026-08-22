/**
 * Public console hash names. Internal screen ids stay stable because they are
 * also module names, role grants, and setup-checklist targets.
 */
export const SCREEN_ROUTES = Object.freeze({
  s1: "setup",
  s2: "home",
  s3: "scopedmemory",
  s4: "policies",
  s5: "memory",
  s6: "sources",
  s7: "knowledgereview",
  s8: "audit",
  s9: "retrievalquality",
  s10: "assistant",
  s11: "conflicts",
  s12: "aimodels",
  s13: "teams",
  s14: "agentconnections",
  s15: "usageanalytics",
  s16: "skills",
  s17: "connectedapps",
  s18: "settings",
  s19: "alerts",
  s20: "export",
  s21: "channels",
  s22: "billing",
});

const ROUTE_SCREENS = Object.freeze(
  Object.fromEntries(Object.entries(SCREEN_ROUTES).map(([screenId, route]) => [route, screenId])),
);

function parts(value) {
  const raw = String(value || "").replace(/^#/, "");
  const queryAt = raw.indexOf("?");
  return queryAt === -1
    ? { name: raw, query: "" }
    : { name: raw.slice(0, queryAt), query: raw.slice(queryAt) };
}

/** Convert an internal target such as `s18?tab=profile` to its public hash. */
export function screenTargetHash(target) {
  const { name, query } = parts(target);
  const route = Object.hasOwn(SCREEN_ROUTES, name) ? SCREEN_ROUTES[name] : null;
  return route ? `#${route}${query}` : null;
}

/** Resolve either a public name or a legacy `s<N>` hash to an internal id. */
export function screenIdFromHash(hash) {
  const { name } = parts(hash);
  if (Object.hasOwn(SCREEN_ROUTES, name)) return name;
  return Object.hasOwn(ROUTE_SCREENS, name) ? ROUTE_SCREENS[name] : null;
}

/** Return the readable equivalent of a known hash, preserving its query. */
export function canonicalHash(hash) {
  const { query } = parts(hash);
  const screenId = screenIdFromHash(hash);
  return screenId ? screenTargetHash(screenId + query) : null;
}
