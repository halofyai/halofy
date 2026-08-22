import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const opened: Db[] = [];

afterEach(async () => {
  await Promise.all(opened.splice(0).map((db) => db.close()));
});

async function migratedDb(): Promise<Db> {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 8 }));
  opened.push(db);
  await migrate(db, 8);
  return db;
}

describe("M7 enterprise production-hardening exit surface", () => {
  it("persists classification, source ACLs, durable work, connector state, IAM and rate limits", async () => {
    const db = await migratedDb();
    const tables = await db.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const tableNames = tables.rows.map((row) => String(row.table_name));
    expect(tableNames).toEqual(expect.arrayContaining([
      "durable_jobs",
      "durable_rate_limits",
      "durable_tickets",
      "connector_cursors",
      "oidc_identities",
      "scim_groups",
      "scim_group_members",
      "audit_chain_state",
    ]));

    const memoryColumns = await db.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'memory_objects'`,
    );
    expect(memoryColumns.rows.map((row) => String(row.column_name))).toEqual(
      expect.arrayContaining(["classification", "source_access"]),
    );

    const sourceColumns = await db.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'sources'`,
    );
    expect(sourceColumns.rows.map((row) => String(row.column_name))).toEqual(
      expect.arrayContaining([
        "lifecycle_state",
        "sync_interval_seconds",
        "next_sync_at",
        "consecutive_failures",
      ]),
    );
  });

  it("runs kernel CI for pushes to the actual default branch", async () => {
    const workflow = await readFile(`${ROOT}/.github/workflows/kernel-ci.yml`, "utf8");
    expect(workflow).toMatch(/branches:\s*\[[^\]]*master[^\]]*\]/);
  });

  it("deploys successful master merges to Azure with branch-bound OIDC", async () => {
    const workflow = await readFile(`${ROOT}/.github/workflows/kernel-ci.yml`, "utf8");

    expect(workflow).toContain("deploy-azure:");
    expect(workflow).toContain(
      "if: always() && github.event_name == 'push' && github.ref == 'refs/heads/master' && needs.ci-required.result == 'success'",
    );
    expect(workflow).toContain(
      "needs: [ci-required]",
    );
    expect(workflow).toContain("group: halomem-production");
    expect(workflow).toContain("cancel-in-progress: false");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain(
      "uses: azure/login@532459ea530d8321f2fb9bb10d1e0bcf23869a43 # v3.0.0",
    );
    expect(workflow).toContain("client-id: ${{ secrets.AZURE_CLIENT_ID }}");
    expect(workflow).toContain(
      'image_tag="$AZURE_REGISTRY_SERVER/$AZURE_IMAGE_REPOSITORY:$GITHUB_SHA"',
    );
    expect(workflow).toContain('docker build --pull --tag "$image_tag" .');
    expect(workflow).toContain('HALOMEM_KERNEL_IMAGE="$image_tag" docker compose up --no-build --detach');
    expect(workflow).toContain('image="$AZURE_REGISTRY_SERVER/$AZURE_IMAGE_REPOSITORY@$digest"');
    expect(workflow).toContain('--image "${{ steps.image.outputs.image }}"');
    expect(workflow).toContain("az containerapp update");
    expect(workflow).toContain("properties.latestReadyRevisionName");
    expect(workflow).toContain('"https://$fqdn/healthz"');
    expect(workflow).toContain('"https://$fqdn/healthz/mastra"');
    expect(workflow).toContain("halomem-mastra-v2-internal-api");
    expect(workflow).toContain(
      '[ "$secret_ref" != "halomem-mastra-v2-internal-api" ]',
    );
    expect(workflow).toMatch(
      /halomem_token="\$\(az containerapp secret show \\\r?\n\s+--name "\$AZURE_CONTAINER_APP"/,
    );
    expect(workflow).toContain('--secret-name "$secret_ref"');
    expect(workflow).toContain("HALOMEM_MASTRA_V2_RUNTIME_BASE_URL");
    expect(workflow).toContain(
      "EXPECTED_MASTRA_SIDECAR_ORIGIN: https://halo-agents-v2-mastra-rt-dev.delightfultree-c8e6d4aa.eastus2.azurecontainerapps.io",
    );
    expect(workflow).toContain(
      '[ "$sidecar_base_url" != "$EXPECTED_MASTRA_SIDECAR_ORIGIN" ]',
    );
    expect(workflow).toContain('"${sidecar_base_url}/api/internal/runtimes/halomem-auth-probe/turn"');
    expect(workflow).not.toContain("AZURE_MASTRA_SIDECAR_APP");
    expect(workflow).not.toContain("--secret-name halo-internal-api");
    expect(workflow).not.toContain("az containerapp secret set");
    expect(workflow).toContain('invalid_probe_bearer="invalid-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"');
    expect(workflow).toContain('[ "$halomem_token" = "$invalid_probe_bearer" ]');
    expect(workflow).toContain('Authorization: Bearer ${invalid_probe_bearer}');
    expect(workflow).toContain('if [ "$invalid_probe_status" != "401" ]');
    expect(workflow).toContain('if [ "$probe_status" != "404" ]');
    expect(workflow).not.toContain("Authorization: Bearer halomem-readiness-invalid");
    expect(workflow).toContain("--connect-timeout 5");
    expect(workflow).toContain("rollback_to_previous");
    expect(workflow).not.toContain("AZURE_CREDENTIALS");
    expect(workflow).not.toContain("client-secret:");
  });

  it("keeps protected checks stable while risk-routing CI and secret scans", async () => {
    const workflow = await readFile(`${ROOT}/.github/workflows/kernel-ci.yml`, "utf8");
    const gitleaks = await readFile(`${ROOT}/.github/workflows/gitleaks.yml`, "utf8");
    const jobs = parseYaml(workflow).jobs;

    expect(workflow).toContain("ci-required:");
    for (const legacyCheck of ["quality", "postgres", "performance", "image", "compose-smoke"]) {
      expect(workflow).toContain(`  ${legacyCheck}:`);
      expect(jobs[legacyCheck].steps[0]["working-directory"]).toBe(".");
    }
    expect(jobs["ci-required"].steps[0]["working-directory"]).toBe(".");
    expect(workflow).toContain("merge_group:");
    expect(workflow).toContain("shard: [1, 2, 3, 4]");
    expect(workflow).toContain("--shard=${{ matrix.shard }}/4");

    expect(gitleaks).toContain("merge_group:");
    expect(gitleaks).toContain('cron: "47 2 * * *"');
    expect(gitleaks).toContain('--log-opts="$BASE_SHA..$HEAD_SHA"');
    expect(gitleaks).toContain("--log-opts=--all");
  });

  it("documents M7 as the current production-hardening milestone", async () => {
    const phases = await readFile(`${ROOT}/docs/archive/PHASES.md`, "utf8");
    expect(phases).toContain("M7");
    expect(phases).toContain("enterprise production hardening");
  });

  it("ships a multi-replica container deployment with disruption and secret controls", async () => {
    const deployment = await readFile(`${ROOT}/kernel/deploy/kubernetes/deployment.yaml`, "utf8");
    const pdb = await readFile(`${ROOT}/kernel/deploy/kubernetes/pdb.yaml`, "utf8");
    expect(deployment).toMatch(/replicas:\s*[2-9]/);
    expect(deployment).toContain("secretKeyRef:");
    expect(deployment).toContain("readinessProbe:");
    expect(deployment).toContain("securityContext:");
    expect(pdb).toMatch(/minAvailable:\s*1/);
    expect(deployment).not.toMatch(/value:\s*(postgres|hm_|sk-)/i);
  });
});
