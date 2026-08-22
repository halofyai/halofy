import type { Db } from "./db/client.js";
import { namespaceAncestors } from "./index/index.js";
import type { Namespace } from "./types.js";

/** Every write takes the global fence plus each namespace ancestor fence. */
export function writeFenceNamespaces(namespace: Namespace): Namespace[] {
  return [...new Set(["", ...namespaceAncestors(namespace)])];
}

/** Upsert/update a fence row; inside a transaction this holds its row lock. */
export async function acquireErasureFence(db: Pick<Db, "query">, namespace: Namespace): Promise<void> {
  await db.query(
    `INSERT INTO erasure_fences (namespace, generation, updated_at)
     VALUES ($1, 1, $2)
     ON CONFLICT (namespace) DO UPDATE SET
       generation = erasure_fences.generation + 1,
       updated_at = EXCLUDED.updated_at`,
    [namespace, new Date().toISOString()],
  );
}

