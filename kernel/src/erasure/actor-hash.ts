import { createHash } from "node:crypto";

/** Stable, irreversible lookup key for actor-scoped assistant erasure. */
export function assistantActorHash(actor: string): string {
  return createHash("sha256").update(actor, "utf8").digest("hex");
}
