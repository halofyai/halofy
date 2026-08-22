import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import { MemoryIndex } from "../src/index/index.js";
import type { MemoryObject } from "../src/types.js";

const opened: Db[] = [];
afterEach(async () => Promise.all(opened.splice(0).map((db) => db.close())));

it("persists and enforces source-native principals in every index read lane", async () => {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 3 }));
  opened.push(db);
  await migrate(db, 3);
  const index = new MemoryIndex(db);
  const now = new Date().toISOString();
  const memory: MemoryObject = {
    id: "m7-acl-memory",
    namespace: "acme/support",
    scope: "org",
    tier: "L2",
    backendRef: "inline",
    content: "restricted payroll fact",
    type: "fact",
    confidence: 1,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{
      source: "document", actor: "ingest", ts: now,
      sourceAccess: { principals: ["alice@example.com"], groups: ["finance"] },
      classification: {
        sensitivity: "restricted", piiSubjects: ["employee"], secretKinds: [],
        allowedDestinations: ["agent-context"],
      },
    }],
    classification: {
      sensitivity: "restricted", piiSubjects: ["employee"], secretKinds: [],
      allowedDestinations: ["agent-context"],
    },
    sourceAccess: { principals: ["alice@example.com"], groups: ["finance"] },
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
  await index.insert(memory, [1, 0, 0]);

  const alice = { principals: ["alice@example.com"], groups: [] };
  const finance = { principals: ["bob@example.com"], groups: ["finance"] };
  const outsider = { principals: ["mallory@example.com"], groups: ["sales"] };
  expect((await index.getById(memory.id, "acme/support", alice)).obj?.classification?.sensitivity)
    .toBe("restricted");
  expect((await index.getById(memory.id, "acme/support", finance)).obj?.id).toBe(memory.id);
  expect(await index.getById(memory.id, "acme/support", outsider)).toMatchObject({
    obj: null, denied: true,
  });
  expect(await index.listCandidates("acme/support", { access: outsider })).toHaveLength(0);
  expect(await index.vectorSearch("acme/support", [1, 0, 0], 5, true, false, false, alice))
    .toHaveLength(1);
});
