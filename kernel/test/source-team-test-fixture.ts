import type { Kernel } from "../src/kernel.js";

export function sourceTeamId(namespace: string): string {
  return `team-${namespace.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase()}`;
}

export async function seedActiveSourceTeam(
  kernel: Kernel,
  namespace: string,
  id = sourceTeamId(namespace),
): Promise<string> {
  const organizationNamespace = namespace.split("/")[0];
  if (!organizationNamespace || !namespace.includes("/")) {
    throw new Error(`source team fixture requires a nested namespace: ${namespace}`);
  }
  await kernel.db.query(
    `INSERT INTO org_teams
       (id, namespace, organization_namespace, name, description, created_by, created_at)
     VALUES ($1, $2, $3, $4, '', 'source-team-test-fixture', $5)
     ON CONFLICT (id) DO NOTHING`,
    [id, namespace, organizationNamespace, namespace, new Date().toISOString()],
  );
  return id;
}
