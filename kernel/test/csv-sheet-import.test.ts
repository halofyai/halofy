import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

import { mapCsvToConnectorRecords } from "../src/ingest/csv-import.js";
import { Kernel } from "../src/kernel.js";

const kernels: Kernel[] = [];

afterEach(async () => {
  await Promise.all(kernels.splice(0).map((kernel) => kernel.close()));
});

describe("CSV / Sheet import boundary", () => {
  it("parses RFC4180 rows through an explicit bounded column map", () => {
    const records = mapCsvToConnectorRecords({
      csv: [
        "id,title,note,updated_at,classification,namespace,api_key",
        'r1,Roadmap,"Ship, then measure",2026-07-15T10:00:00.000Z,product-note,forged,secret',
      ].join("\n"),
      mapping: {
        idColumn: "id",
        textColumns: ["title", "note"],
        updatedAtColumn: "updated_at",
        classificationColumn: "classification",
      },
    });

    expect(records).toEqual([{
      id: "r1",
      text: JSON.stringify({ title: "Roadmap", note: "Ship, then measure" }),
      updatedAt: "2026-07-15T10:00:00.000Z",
      classification: "product-note",
    }]);
    expect(JSON.stringify(records)).not.toContain("forged");
    expect(JSON.stringify(records)).not.toContain("secret");
  });

  it("rejects authority columns, duplicate IDs, malformed CSV, and excessive rows", () => {
    expect(() => mapCsvToConnectorRecords({
      csv: "id,namespace\nr1,victim",
      mapping: { idColumn: "id", textColumns: ["namespace"] },
    })).toThrow(/reserved authority/i);
    expect(() => mapCsvToConnectorRecords({
      csv: "id,note\nr1,a\nr1,b",
      mapping: { idColumn: "id", textColumns: ["note"] },
    })).toThrow(/duplicate row id/i);
    expect(() => mapCsvToConnectorRecords({
      csv: 'id,note\nr1,"unterminated',
      mapping: { idColumn: "id", textColumns: ["note"] },
    })).toThrow(/unterminated quoted field/i);
    const tooMany = ["id,note", ...Array.from({ length: 1_001 }, (_, i) => `${i},x`)].join("\n");
    expect(() => mapCsvToConnectorRecords({
      csv: tooMany,
      mapping: { idColumn: "id", textColumns: ["note"] },
    })).toThrow(/at most 1000/i);
  });

  it("registers without a fake credential and imports through the governed source sink", async () => {
    const kernel = await Kernel.boot({ sourceConfigKek: randomBytes(32).toString("base64") });
    kernels.push(kernel);
    const rootKey = await kernel.auth.issueKey("", "owner:root", "owner");
    const root = await kernel.auth.resolve(rootKey.plaintext);
    if (!root) throw new Error("root identity failed");
    const tenantKey = await kernel.auth.issueKey("acme", "owner:acme", "owner", root);
    const owner = await kernel.auth.resolve(tenantKey.plaintext);
    if (!owner) throw new Error("tenant identity failed");
    await kernel.setPolicy(
      "acme",
      "restrictedDestinations:\n  - llm-extraction\n  - embedding-provider\n",
    );
    await kernel.db.query(
      `INSERT INTO org_teams
         (id, namespace, organization_namespace, name, description, created_by, created_at)
       VALUES ('team-csv-import', 'acme/imports', 'acme', 'Imports', '', 'owner:acme', $1)`,
      [new Date().toISOString()],
    );

    const source = await kernel.connectSource("csv_sheet_import", {
      selectedDataPoints: ["mapped_rows"],
      sourceAccessMode: "namespace-open",
    }, owner, undefined, "team-csv-import");
    expect(source.credentialId).toBeNull();
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs WHERE kind = 'source-sync' AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toEqual([]);
    await expect(kernel.scheduleSource(source.id, 3_600, owner)).rejects.toThrow(/cannot be scheduled/);
    await kernel.pauseSource(source.id, owner);
    await kernel.resumeSource(source.id, owner);
    expect((await kernel.db.query(
      `SELECT id FROM durable_jobs WHERE kind = 'source-sync' AND payload->>'sourceId' = $1`,
      [source.id],
    )).rows).toEqual([]);

    const result = await kernel.importCsvSource(source.id, {
      csv: "id,note,namespace,token\nr1,Remember this,victim,do-not-store",
      mapping: { idColumn: "id", textColumns: ["note"] },
    }, owner);
    expect(result).toMatchObject({ records: 1, errors: [] });
    const documents = await kernel.db.query(
      `SELECT document_key, landing_namespace FROM source_documents WHERE source_id = $1`,
      [source.id],
    );
    expect(documents.rows).toEqual([{
      document_key: "csv_sheet_import:mapped_rows:r1",
      landing_namespace: "acme/imports",
    }]);
    const memories = await kernel.db.query(
      `SELECT content FROM memory_objects WHERE namespace = $1 AND provenance @> $2::jsonb`,
      ["acme/imports", JSON.stringify([{ sourceId: source.id }])],
    );
    expect(JSON.stringify(memories.rows)).toContain("Remember this");
    expect(JSON.stringify(memories.rows)).not.toContain("victim");
    expect(JSON.stringify(memories.rows)).not.toContain("do-not-store");
  }, 30_000);
});
