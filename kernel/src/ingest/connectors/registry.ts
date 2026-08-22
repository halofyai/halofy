import type {
  ConnectorCapabilities,
  EnterpriseConnector,
  SourceKind,
} from "../../types.js";

const REQUIRED_CAPABILITIES: ReadonlyArray<keyof ConnectorCapabilities> = [
  "incremental",
  "liveQuery",
  "sourceAcl",
  "webhook",
  "oauth",
];

export class ConnectorConformanceError extends Error {
  constructor(message: string) {
    super(`connector conformance: ${message}`);
    this.name = "ConnectorConformanceError";
  }
}

function assertStructuralConformance(connector: EnterpriseConnector): void {
  if (connector.version !== "halomem-connector/v1") {
    throw new ConnectorConformanceError("unsupported version");
  }
  if (!connector.kind || typeof connector.kind !== "string") {
    throw new ConnectorConformanceError("kind is required");
  }
  for (const method of [
    "available",
    "sync",
    "capabilities",
    "validateConfig",
    "testConnection",
  ] as const) {
    if (typeof connector[method] !== "function") {
      throw new ConnectorConformanceError(`${method}() is required`);
    }
  }
  const capabilities = connector.capabilities();
  for (const capability of REQUIRED_CAPABILITIES) {
    if (typeof capabilities[capability] !== "boolean") {
      throw new ConnectorConformanceError(`capability '${capability}' must be boolean`);
    }
  }
  if (capabilities.incremental && typeof connector.syncIncremental !== "function") {
    throw new ConnectorConformanceError("incremental capability requires syncIncremental()");
  }
}

/** Runs the cartridge checks that require a candidate configuration. */
export async function validateConnectorConformance(
  connector: EnterpriseConnector,
  config: Record<string, unknown>,
): Promise<void> {
  assertStructuralConformance(connector);
  await connector.validateConfig(config);
  const result = await connector.testConnection(config);
  if (!result || typeof result.ok !== "boolean") {
    throw new ConnectorConformanceError("testConnection() returned an invalid result");
  }
  if (!result.ok) {
    throw new ConnectorConformanceError("connection test failed");
  }
}

/** Versioned connector catalog. Duplicate kinds fail instead of being replaced. */
export class ConnectorRegistry {
  private readonly connectors = new Map<SourceKind, EnterpriseConnector>();

  constructor(connectors: readonly EnterpriseConnector[] = []) {
    for (const connector of connectors) this.register(connector);
  }

  register(connector: EnterpriseConnector): void {
    assertStructuralConformance(connector);
    if (this.connectors.has(connector.kind)) {
      throw new ConnectorConformanceError(`duplicate kind '${connector.kind}'`);
    }
    this.connectors.set(connector.kind, connector);
  }

  get(kind: SourceKind): EnterpriseConnector | null {
    return this.connectors.get(kind) ?? null;
  }

  require(kind: SourceKind): EnterpriseConnector {
    const connector = this.get(kind);
    if (!connector) throw new ConnectorConformanceError(`kind '${kind}' is not registered`);
    return connector;
  }

  list(): EnterpriseConnector[] {
    return [...this.connectors.values()];
  }
}
