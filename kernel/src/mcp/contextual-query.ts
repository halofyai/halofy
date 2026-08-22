const MAX_TOOL_QUERY_CHARS = 4_000;

/**
 * Keep a model-generated retrieval rewrite tied to the server-resolved turn.
 * The bounded route anchors prevent a rewrite from dropping an issue, page,
 * URL, or source identifier that determines the governed retrieval route.
 */
export function anchorCopilotToolQuery(
  toolQuery: string,
  resolvedTurnQuery: string,
  maxChars = MAX_TOOL_QUERY_CHARS,
): string {
  const limit = Math.max(1, Math.min(MAX_TOOL_QUERY_CHARS, Math.floor(maxChars)));
  const fullCurrent = compact(resolvedTurnQuery, MAX_TOOL_QUERY_CHARS);
  const current = boundedAnchor(fullCurrent, limit);
  const requested = compact(toolQuery, limit);
  if (!current) return requested;
  if (!requested || requested === current || current.includes(requested)) return current;

  const routeAnchors = queryRouteAnchors(fullCurrent);
  const carriesRoute = routeAnchors.every((anchor) =>
    requested.toLowerCase().includes(anchor.toLowerCase()),
  );
  if (!current.includes("Conversation context for resolving references:") && carriesRoute) {
    return requested;
  }

  const routeLine = routeAnchors.length > 0
    ? `Resolved route anchors: ${routeAnchors.join(", ")}`
    : "";
  return fitQuery([
    routeLine,
    `Resolved current request: ${current}`,
    `Retrieval rewrite: ${requested}`,
  ], limit);
}

function boundedAnchor(value: string, limit: number): string {
  if (value.length <= limit) return value;
  const anchors = queryRouteAnchors(value);
  const suffix = anchors.length > 0 ? ` Anchors: ${anchors.join(", ")}` : "";
  if (suffix.length >= limit) return compact(suffix, limit);
  return compact(`${value.slice(0, limit - suffix.length)}${suffix}`, limit);
}

function queryRouteAnchors(value: string): string[] {
  const normalized = value.toLowerCase();
  const collectionConstraint = [
    "every workflow state",
    "in progress",
    "in review",
    "to do",
    "open",
    "active",
    "backlog",
    "todo",
    "unstarted",
    "started",
    "canceled",
    "cancelled",
    "closed",
    "completed",
  ].find((candidate) => normalized.includes(candidate));

  return unique([
    ...(value.match(/\b[a-z][a-z0-9]{0,14}-[1-9]\d{0,9}\b/gi) ?? []),
    ...(value.match(/https?:\/\/[^\s<>()]+/gi) ?? []),
    ...(value.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi) ?? []),
    ...(value.match(/\b(?:linear|notion)\b/gi) ?? []),
    ...(collectionConstraint ? [collectionConstraint] : []),
  ]);
}

function fitQuery(parts: readonly string[], limit: number): string {
  const output: string[] = [];
  let remaining = limit;
  for (const part of parts) {
    if (remaining <= 0) break;
    const separator = output.length === 0 ? "" : "\n";
    const available = remaining - separator.length;
    if (available <= 0) break;
    const value = compact(part, available);
    if (!value) continue;
    output.push(value);
    remaining -= separator.length + value.length;
  }
  return output.join("\n");
}

function compact(value: string, limit: number): string {
  return value.replace(/\s+/g, " ").trim().slice(0, Math.max(0, limit));
}

function unique(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}
