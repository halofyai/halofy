/**
 * Module D (M2) — conformance harness fixture.
 *
 * A self-contained kernel-in-memory fixture the conformance kit builds for
 * itself: in-memory PGlite (+ pgvector) via the existing createDb/migrate,
 * HashEmbedder, 10 distinctive planted facts in namespace 'conf/a' and 5
 * canary facts in the SIBLING namespace 'conf/b' (invisible to a 'conf/a'
 * caller under the deny-by-default ACL).
 *
 * The ScopedView handed to drivers is built via module A's
 * `src/driver/view.js buildScopedView(deps, namespace)` — the ONLY
 * constructor of ScopedView. The cold lane is an empty stub (the fixture
 * plants no L3 concepts) and the entities reader is a real ACL-scoped
 * listing over entity_registry. Callers may force a different view builder
 * via `BuildHarnessOptions.buildView`.
 *
 * NOTE: this fixture is KERNEL-side (it may import index/db/embed). The
 * driver boundary applies to drivers, not to the kit that judges them.
 */

import { ulid } from "ulid";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db/client.js";
import { migrate } from "../db/migrate.js";
import { MemoryIndex, namespaceAncestors } from "../index/index.js";
import { HashEmbedder } from "../embed/index.js";
import {
  buildScopedView,
  type ViewColdLike,
  type ViewEntitiesLike,
} from "../driver/view.js";
import type {
  Embedder,
  MemoryObject,
  Namespace,
  ScopedView,
} from "../types.js";

// ---------------------------------------------------------------------------
// Planted corpus — 10 distinctive facts (ns conf/a) + 5 canaries (ns conf/b).
// Each entry pairs the stored content with the query the kit will ask.
// Vocabulary is deliberately rare + disjoint so hybrid lexical/hash-vector
// ranking puts the right ref in the top-3 for a compliant driver.
// ---------------------------------------------------------------------------

export interface PlantedSpec {
  content: string;
  query: string;
}

export const PLANTED_FACTS: readonly PlantedSpec[] = [
  {
    content: "The zephyr booster burns cryogenic methalox propellant during ascent",
    query: "what propellant does the zephyr booster burn",
  },
  {
    content: "Marisol keeps her vintage accordion in the cedar attic closet",
    query: "where does Marisol keep the vintage accordion",
  },
  {
    content: "Project Quasar ships its telemetry dashboard every second Thursday",
    query: "when does project quasar ship the telemetry dashboard",
  },
  {
    content: "The Osaka warehouse stores exactly forty pallets of jasmine tea",
    query: "how many pallets of jasmine tea does the Osaka warehouse store",
  },
  {
    content: "Dr. Ibanez prescribed lavender balm for the recurring migraine flareups",
    query: "what did Dr. Ibanez prescribe for migraine flareups",
  },
  {
    content: "The glacier survey drone recharges at the northern basecamp solar array",
    query: "where does the glacier survey drone recharge",
  },
  {
    content: "Tobias tuned the harpsichord to baroque pitch before the winter recital",
    query: "what pitch did Tobias tune the harpsichord to",
  },
  {
    content: "The customs manifest lists seventeen crates of Bolivian quinoa",
    query: "how many crates of Bolivian quinoa are on the customs manifest",
  },
  {
    content: "Priya migrated the billing ledger to the columnar database on Friday",
    query: "which database did Priya migrate the billing ledger to",
  },
  {
    content: "The lighthouse keeper logs foghorn maintenance in the brass journal",
    query: "where does the lighthouse keeper log foghorn maintenance",
  },
] as const;

export const CANARY_FACTS: readonly PlantedSpec[] = [
  {
    content: "Canary alpha: the vault passphrase is nightingale-obsidian",
    query: "what is the vault passphrase",
  },
  {
    content: "Canary bravo: the payroll spreadsheet hides in the mango folder",
    query: "where does the payroll spreadsheet hide",
  },
  {
    content: "Canary charlie: the acquisition target is Meridian Robotics",
    query: "who is the acquisition target",
  },
  {
    content: "Canary delta: the staging server root password is peppercorn",
    query: "what is the staging server root password",
  },
  {
    content: "Canary echo: the secret roadmap unveils teleportation in March",
    query: "what does the secret roadmap unveil",
  },
] as const;

export const HARNESS_NAMESPACE: Namespace = "conf/a";
export const CANARY_NAMESPACE: Namespace = "conf/b";

/**
 * Entities registered in conf/a so graph-capable drivers get a real
 * entityFacts() lane (canonical name + aliases match the planted corpus).
 */
export const PLANTED_ENTITIES: readonly { canonicalName: string; aliases: string[] }[] = [
  { canonicalName: "Marisol", aliases: [] },
  { canonicalName: "Project Quasar", aliases: ["Quasar"] },
  { canonicalName: "Osaka", aliases: [] },
  { canonicalName: "Dr. Ibanez", aliases: ["Ibanez"] },
  { canonicalName: "Tobias", aliases: [] },
  { canonicalName: "Priya", aliases: [] },
] as const;

// ---------------------------------------------------------------------------
// Harness types
// ---------------------------------------------------------------------------

export interface PlantedFact {
  /** Memory id (== ScoredRef.ref for L2 rows). */
  ref: string;
  content: string;
  query: string;
}

/** Deps handed to the view builder — satisfies module A's ScopedViewDeps. */
export interface HarnessDeps {
  db: Db;
  index: MemoryIndex;
  embedder: Embedder;
  cold: ViewColdLike<Db>;
  entities: ViewEntitiesLike;
}

export interface ConformanceHarness {
  namespace: Namespace;
  canaryNamespace: Namespace;
  /** The ONLY surface a driver under test may touch. Scoped to conf/a. */
  view: ScopedView;
  /** Which builder produced `view` — module A's or a caller override. */
  viewSource: "driver/view.js" | "custom";
  planted: PlantedFact[];
  canaries: PlantedFact[];
  /** Every ref legitimately reachable through the view (candidate set). */
  allowedRefs: Set<string>;
  /** Refs of the sibling-namespace canary rows — must NEVER be returned. */
  canaryRefs: Set<string>;
  deps: HarnessDeps;
  close(): Promise<void>;
}

export interface BuildHarnessOptions {
  /** Force a specific view builder (e.g. module A's buildScopedView). */
  buildView?: (
    deps: HarnessDeps,
    namespace: Namespace,
  ) => ScopedView | Promise<ScopedView>;
}

// ---------------------------------------------------------------------------
// View deps: empty cold lane (fixture plants no L3 concepts) + a real
// ACL-scoped entity_registry reader (the kernel-side adapter module A's
// ViewEntitiesLike documents — src/driver holds no SQL).
// ---------------------------------------------------------------------------

const emptyColdLane: ViewColdLike<Db> = {
  async searchConcepts() {
    return [];
  },
};

function makeEntitiesReader(db: Db): ViewEntitiesLike {
  return {
    async listEntities(namespace: Namespace) {
      const allowed = namespaceAncestors(namespace);
      const placeholders = allowed.map((_, i) => `$${i + 1}`).join(", ");
      const res = await db.query(
        `SELECT canonical_name, aliases FROM entity_registry
         WHERE namespace IN (${placeholders})`,
        [...allowed],
      );
      return res.rows.map((r) => {
        const raw: unknown = r.aliases;
        let aliases: string[] = [];
        if (Array.isArray(raw)) {
          aliases = raw.filter((a): a is string => typeof a === "string");
        } else if (typeof raw === "string") {
          try {
            const parsed: unknown = JSON.parse(raw);
            if (Array.isArray(parsed)) {
              aliases = parsed.filter((a): a is string => typeof a === "string");
            }
          } catch {
            /* malformed alias JSON → no aliases */
          }
        }
        return { canonicalName: r.canonical_name as string, aliases };
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

function factRow(namespace: Namespace, content: string): MemoryObject {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    namespace,
    scope: "user",
    tier: "L2",
    backendRef: "inline",
    content,
    type: "fact",
    confidence: 1,
    eventTime: null,
    assertionTime: now,
    tValidFrom: now,
    tValidTo: null,
    supersedes: null,
    provenance: [{ source: "manual", actor: "conformance-kit", ts: now }],
    ttlSeconds: null,
    telemetry: { lastAccessed: null, accessCount: 0, faultCount: 0 },
    status: "active",
  };
}

export async function buildConformanceHarness(
  opts: BuildHarnessOptions = {},
): Promise<ConformanceHarness> {
  // Hermetic: force in-memory PGlite + HashEmbedder regardless of env.
  const config = loadConfig({
    databaseUrl: "",
    pgliteDataDir: "",
    openaiApiKey: "",
    anthropicApiKey: "",
  });
  const embedder = new HashEmbedder();
  const db = await createDb(config);
  try {
    await migrate(db, embedder.dim);
    const index = new MemoryIndex(db);
    const deps: HarnessDeps = {
      db,
      index,
      embedder,
      cold: emptyColdLane,
      entities: makeEntitiesReader(db),
    };

    const plant = async (namespace: Namespace, specs: readonly PlantedSpec[]) => {
      const planted: PlantedFact[] = [];
      for (const spec of specs) {
        const obj = factRow(namespace, spec.content);
        const [embedding] = await embedder.embed([spec.content]);
        await index.insert(obj, embedding);
        planted.push({ ref: obj.id, content: spec.content, query: spec.query });
      }
      return planted;
    };

    const planted = await plant(HARNESS_NAMESPACE, PLANTED_FACTS);
    const canaries = await plant(CANARY_NAMESPACE, CANARY_FACTS);

    // Register corpus entities so entityFacts() resolves for graph drivers.
    for (const e of PLANTED_ENTITIES) {
      const [emb] = await embedder.embed([e.canonicalName]);
      await db.query(
        `INSERT INTO entity_registry (id, namespace, canonical_name, aliases, embedding, created_at)
         VALUES ($1, $2, $3, $4, $5::vector, $6)`,
        [
          ulid(),
          HARNESS_NAMESPACE,
          e.canonicalName,
          JSON.stringify(e.aliases),
          `[${emb.join(",")}]`,
          new Date().toISOString(),
        ],
      );
    }

    let view: ScopedView;
    let viewSource: ConformanceHarness["viewSource"];
    if (opts.buildView) {
      view = await opts.buildView(deps, HARNESS_NAMESPACE);
      viewSource = "custom";
    } else {
      view = buildScopedView(deps, HARNESS_NAMESPACE);
      viewSource = "driver/view.js";
    }

    const allowedRefs = new Set(
      (await view.candidates(1000)).map((c) => c.ref),
    );
    const canaryRefs = new Set(canaries.map((c) => c.ref));

    return {
      namespace: HARNESS_NAMESPACE,
      canaryNamespace: CANARY_NAMESPACE,
      view,
      viewSource,
      planted,
      canaries,
      allowedRefs,
      canaryRefs,
      deps,
      close: () => db.close(),
    };
  } catch (err) {
    await db.close().catch(() => undefined);
    throw err;
  }
}
