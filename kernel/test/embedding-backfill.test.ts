/**
 * Self-healing vector backfill.
 *
 * A width change nulls every existing vector (see embedding-realign.test.ts).
 * Repairing that must not depend on an operator running a CLI or on having
 * shell access to the container — semantic search is degraded org-wide until it
 * completes — so the kernel converges on its own, a bounded batch per pass.
 */

import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  BACKFILL_BATCH,
  MAX_BACKFILL_EMBED_CHARS,
  runEmbeddingBackfillOnce,
} from "../src/embed/backfill.js";
import { HashEmbedder } from "../src/embed/index.js";
import type { Embedder } from "../src/types.js";

const DIM = 8;

async function freshDb(): Promise<Db> {
  const config = loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: DIM });
  const db = await createDb(config);
  await migrate(db, DIM);
  return db;
}

async function seedFacts(db: Db, count: number): Promise<void> {
  const now = new Date().toISOString();
  for (let i = 0; i < count; i += 1) {
    await db.query(
      `INSERT INTO memory_objects
         (id, namespace, scope, tier, backend_ref, content, type, confidence,
          assertion_time, t_valid_from, provenance, embedding)
       VALUES ($1,'acme','org','L2','ref',$2,'fact',1,$3,$3,'[]',NULL)`,
      [`m${String(i).padStart(4, "0")}`, `fact number ${i}`, now],
    );
  }
}

async function nullCount(db: Db): Promise<number> {
  const res = await db.query(
    `SELECT COUNT(*)::int AS n FROM memory_objects WHERE embedding IS NULL`,
  );
  return Number((res.rows[0] as { n: number }).n);
}

describe("embedding backfill", () => {
  it("repairs rows whose vector is missing", async () => {
    const db = await freshDb();
    try {
      await seedFacts(db, 3);
      expect(await nullCount(db)).toBe(3);

      const result = await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));

      expect(result.repaired).toBe(3);
      expect(result.remaining).toBe(0);
      expect(await nullCount(db)).toBe(0);
    } finally {
      await db.close();
    }
  });

  it("is bounded per pass so it cannot saturate the embedding provider", async () => {
    const db = await freshDb();
    try {
      await seedFacts(db, BACKFILL_BATCH + 5);

      const first = await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));

      expect(first.repaired).toBe(BACKFILL_BATCH);
      expect(first.remaining).toBe(5);
      // Converges over subsequent passes rather than in one burst.
      const second = await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));
      expect(second.repaired).toBe(5);
      expect(second.remaining).toBe(0);
    } finally {
      await db.close();
    }
  });

  it("is a cheap no-op once every vector is present", async () => {
    const db = await freshDb();
    try {
      await seedFacts(db, 2);
      await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));

      const idle = await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));

      expect(idle).toEqual({ repaired: 0, remaining: 0 });
    } finally {
      await db.close();
    }
  });

  it("leaves rows for the next pass when the embedder is down, and never throws", async () => {
    const db = await freshDb();
    try {
      await seedFacts(db, 2);
      const broken: Embedder = {
        name: "broken",
        dim: DIM,
        embed: () => Promise.reject(new Error("provider unavailable")),
      };

      // Brownout, never hard-fail: this pass shares a poller with connectors and
      // conflict scans, so a provider outage must not take that poller down.
      const result = await runEmbeddingBackfillOnce(db, broken);

      expect(result.repaired).toBe(0);
      expect(result.remaining).toBe(2);
      expect(await nullCount(db)).toBe(2);
    } finally {
      await db.close();
    }
  });

  it("bounds oversized legacy rows so one record cannot poison a repair batch", async () => {
    const db = await freshDb();
    try {
      const now = new Date().toISOString();
      const oversized = `important beginning ${"legacy document content ".repeat(2_000)} important ending`;
      await db.query(
        `INSERT INTO memory_objects
           (id, namespace, scope, tier, backend_ref, content, type, confidence,
            assertion_time, t_valid_from, provenance, embedding)
         VALUES ('legacy-large','acme','org','L2','ref',$1,'fact',1,$2,$2,'[]',NULL),
                ('legacy-small','acme','org','L2','ref','small fact','fact',1,$2,$2,'[]',NULL)`,
        [oversized, now],
      );
      const seen: string[] = [];
      const boundedOnly: Embedder = {
        name: "bounded-only",
        dim: DIM,
        embed: async (texts) => {
          seen.push(...texts);
          if (texts.some((text) => text.length > MAX_BACKFILL_EMBED_CHARS)) {
            throw new Error("provider input too large");
          }
          return texts.map(() => Array.from({ length: DIM }, () => 0.1));
        },
      };

      const result = await runEmbeddingBackfillOnce(db, boundedOnly);

      expect(result).toEqual({ repaired: 2, remaining: 0 });
      expect(Math.max(...seen.map((text) => text.length))).toBeLessThanOrEqual(
        MAX_BACKFILL_EMBED_CHARS,
      );
      expect(seen.some((text) => text.includes("[embedding excerpt]"))).toBe(true);
      expect(seen.some((text) => text.includes("important beginning"))).toBe(true);
      expect(seen.some((text) => text.includes("important ending"))).toBe(true);
    } finally {
      await db.close();
    }
  });

  it("embeds the fact's base text, not the reserved entities marker", async () => {
    const db = await freshDb();
    try {
      const now = new Date().toISOString();
      await db.query(
        `INSERT INTO memory_objects
           (id, namespace, scope, tier, backend_ref, content, type, confidence,
            assertion_time, t_valid_from, provenance, embedding)
         VALUES ('annotated','acme','org','L2','ref',$1,'fact',1,$2,$2,'[]',NULL)`,
        ["Marcus Webb is the CEO [entities: Marcus, Webb, CEO]", now],
      );
      const seen: string[] = [];
      const recording: Embedder = {
        name: "recording",
        dim: DIM,
        embed: async (texts) => {
          seen.push(...texts);
          return texts.map(() => Array.from({ length: DIM }, () => 0.1));
        },
      };

      await runEmbeddingBackfillOnce(db, recording);

      // The write path appends the marker AFTER embedding and embeds only the
      // base text. Embedding the annotated form would place repaired rows in a
      // different region of the vector space than everything written normally.
      expect(seen).toEqual(["Marcus Webb is the CEO"]);
    } finally {
      await db.close();
    }
  });

  it("repairs entity_registry as well as memory_objects", async () => {
    const db = await freshDb();
    try {
      await db.query(
        `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, embedding, created_at)
         VALUES ('e1','acme','Halofy','[]',NULL,$1)`,
        [new Date().toISOString()],
      );

      const result = await runEmbeddingBackfillOnce(db, new HashEmbedder(DIM));

      expect(result.repaired).toBe(1);
      const res = await db.query(
        `SELECT COUNT(*)::int AS n FROM entity_registry WHERE embedding IS NULL`,
      );
      expect(Number((res.rows[0] as { n: number }).n)).toBe(0);
    } finally {
      await db.close();
    }
  });
});
