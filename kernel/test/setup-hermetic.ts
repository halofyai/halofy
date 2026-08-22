// Each Vitest fork has an isolated process environment. Force the hermetic
// lane onto disposable, in-memory PGlite even when a developer shell happens
// to export production database settings. Tests that exercise real Postgres
// inject TEST_DATABASE_URL explicitly through loadConfig().
process.env.DATABASE_URL = "";
process.env.HALOMEM_DATA_DIR = "";
