export interface HttpRequestObservation {
  requestId: string;
  traceId: string;
  method: string;
  route: string;
  status: number;
  durationMs: number;
}

export interface HttpTelemetry {
  observe(observation: HttpRequestObservation): void;
}

const STATIC_ROUTES = new Set([
  "/healthz", "/metrics", "/mcp",
  "/auth/login", "/auth/bootstrap", "/auth/invite/accept", "/auth/logout", "/auth/me",
  "/auth/halo-agents",
  "/scim/v2/Users", "/scim/v2/Groups",
  "/v1/mem/read", "/v1/mem/search", "/v1/mem/write", "/v1/mem/fault",
  "/v1/mem/stats", "/v1/mem/assemble", "/v1/mem/pin", "/v1/mem/unpin",
  "/v1/mem/share", "/v1/mem/live-result",
  "/v1/admin/policy", "/v1/admin/keys", "/v1/admin/pins",
  "/v1/admin/overview", "/v1/admin/people", "/v1/admin/memory-map",
  "/v1/admin/audit", "/v1/admin/audit/summary", "/v1/admin/audit/export.csv",
  "/v1/admin/sources", "/v1/admin/connectors",
  "/v1/admin/source-credentials", "/v1/admin/fragmentation",
  "/v1/admin/setup", "/v1/admin/setup/capabilities", "/v1/admin/proposals",
  "/v1/admin/proposals/metrics", "/v1/admin/disputes", "/v1/admin/warmstores",
  "/v1/admin/warmstores/flush", "/v1/admin/tenants", "/v1/admin/movement/run",
  "/v1/admin/scorecard", "/v1/admin/forget", "/v1/admin/consolidation/runs",
  "/v1/admin/usage/queries", "/v1/admin/usage/rollup",
]);

const DYNAMIC_ROUTES: Array<[RegExp, string]> = [
  [/^\/v1\/webhooks\/sources\/[^/]+$/, "/v1/webhooks/sources/:sourceId"],
  [/^\/v1\/mem\/write\/[^/]+$/, "/v1/mem/write/:ticket"],
  [/^\/v1\/admin\/keys\/[^/]+$/, "/v1/admin/keys/:id"],
  [/^\/v1\/admin\/pins\/[^/]+$/, "/v1/admin/pins/:id"],
  [/^\/v1\/admin\/certificate\/[^/]+$/, "/v1/admin/certificate/:id"],
  [/^\/v1\/admin\/mounts\/[^/]+$/, "/v1/admin/mounts/:id"],
  [/^\/v1\/admin\/sources\/[^/]+\/sync$/, "/v1/admin/sources/:id/sync"],
  [/^\/v1\/admin\/sources\/[^/]+\/import-csv$/, "/v1/admin/sources/:id/import-csv"],
  [/^\/v1\/admin\/sources\/[^/]+\/lineage$/, "/v1/admin/sources/:id/lineage"],
  [/^\/v1\/admin\/sources\/[^/]+\/(test|pause|resume|schedule)$/, "/v1/admin/sources/:id/:action"],
  [/^\/v1\/admin\/setup\/[^/]+\/retry$/, "/v1/admin/setup/:id/retry"],
  [/^\/v1\/admin\/setup\/[^/]+$/, "/v1/admin/setup/:id"],
  [/^\/v1\/admin\/proposals\/[^/]+\/(edit|approve|reject)$/, "/v1/admin/proposals/:id/:action"],
  [/^\/v1\/admin\/proposals\/[^/]+$/, "/v1/admin/proposals/:id"],
  [/^\/v1\/admin\/disputes\/[^/]+\/resolve$/, "/v1/admin/disputes/:id/resolve"],
  [/^\/v1\/admin\/warmstores\/[^/]+\/rebuild$/, "/v1/admin/warmstores/:name/rebuild"],
  [/^\/v1\/admin\/tenants\/[^/]+\/suspend$/, "/v1/admin/tenants/:id/suspend"],
  [/^\/v1\/admin\/usage\/queries\/[^/]+$/, "/v1/admin/usage/queries/:traceId"],
];

/** Converts an untrusted raw URL path to one of a finite set of metric labels. */
export function httpRouteTemplate(path: string): string {
  if (path === "/console" || path.startsWith("/console/")) return "/console/*";
  if (STATIC_ROUTES.has(path)) return path;
  for (const [pattern, template] of DYNAMIC_ROUTES) {
    if (pattern.test(path)) return template;
  }
  return "/other";
}

interface SeriesState {
  method: string;
  route: string;
  requests: number;
  errors: number;
  statusClasses: Record<string, number>;
  samples: number[];
}

export interface HttpRedSnapshot {
  series: Array<{
    method: string;
    route: string;
    requests: number;
    errors: number;
    statusClasses: Record<string, number>;
    durationMs: { p50: number; p95: number; p99: number };
  }>;
}

function percentile(values: number[], percent: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil((percent / 100) * sorted.length) - 1)] ?? 0;
}

export class BoundedHttpRedMetrics implements HttpTelemetry {
  private readonly maxSeries: number;
  private readonly sampleCapacity: number;
  private readonly states = new Map<string, SeriesState>();

  constructor(options: { maxSeries?: number; sampleCapacity?: number } = {}) {
    this.maxSeries = options.maxSeries ?? 128;
    this.sampleCapacity = options.sampleCapacity ?? 1024;
    if (!Number.isSafeInteger(this.maxSeries) || this.maxSeries <= 0) {
      throw new RangeError("maxSeries must be a positive safe integer");
    }
    if (!Number.isSafeInteger(this.sampleCapacity) || this.sampleCapacity <= 0) {
      throw new RangeError("sampleCapacity must be a positive safe integer");
    }
  }

  observe(observation: HttpRequestObservation): void {
    const method = /^[A-Z]{1,16}$/.test(observation.method) ? observation.method : "OTHER";
    const route = httpRouteTemplate(observation.route);
    let key = `${method}\0${route}`;
    if (!this.states.has(key) && this.states.size >= this.maxSeries) key = "OTHER\0/overflow";
    let state = this.states.get(key);
    if (!state) {
      const [boundedMethod, boundedRoute] = key.split("\0") as [string, string];
      state = {
        method: boundedMethod, route: boundedRoute, requests: 0, errors: 0,
        statusClasses: {}, samples: [],
      };
      this.states.set(key, state);
    }
    state.requests += 1;
    if (observation.status >= 500) state.errors += 1;
    const statusClass = observation.status >= 100 && observation.status <= 599
      ? `${Math.floor(observation.status / 100)}xx`
      : "other";
    state.statusClasses[statusClass] = (state.statusClasses[statusClass] ?? 0) + 1;
    if (Number.isFinite(observation.durationMs) && observation.durationMs >= 0) {
      state.samples.push(observation.durationMs);
      if (state.samples.length > this.sampleCapacity) state.samples.shift();
    }
  }

  snapshot(): HttpRedSnapshot {
    return {
      series: [...this.states.values()].map((state) => ({
        method: state.method,
        route: state.route,
        requests: state.requests,
        errors: state.errors,
        statusClasses: { ...state.statusClasses },
        durationMs: {
          p50: percentile(state.samples, 50),
          p95: percentile(state.samples, 95),
          p99: percentile(state.samples, 99),
        },
      })),
    };
  }
}
