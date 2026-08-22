/** Apply HaloMem's numbered schema migrations, then exit. */

import { loadConfig } from "../src/config.js";
import { createDb } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";

const config = loadConfig();
if (!config.databaseUrl) {
  throw new Error("DATABASE_URL is required for a deployment migration");
}

const db = await createDb(config);
try {
  await migrate(db, config.embedDim);
  const result = await db.query(
    "SELECT COUNT(*)::int AS count, MAX(version)::int AS latest FROM schema_migrations",
  );
  const row = result.rows[0] as { count: number; latest: number } | undefined;
  process.stdout.write(
    JSON.stringify({ migrations: row?.count ?? 0, latest: row?.latest ?? 0 }) + "\n",
  );
} finally {
  await db.close();
}
