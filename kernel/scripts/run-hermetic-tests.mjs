import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const vitestBin = fileURLToPath(
  new URL("../node_modules/vitest/vitest.mjs", import.meta.url),
);
const testEnvironment = { ...process.env };

testEnvironment.HALOMEM_TEST_LANE = "hermetic";
delete testEnvironment.DATABASE_URL;
delete testEnvironment.TEST_DATABASE_URL;
delete testEnvironment.HALOMEM_DATA_DIR;
delete testEnvironment.HALOMEM_KNOWLEDGE_DIR;

const child = spawn(
  process.execPath,
  [vitestBin, "run", ...process.argv.slice(2)],
  {
    env: testEnvironment,
    stdio: "inherit",
  },
);

child.once("error", (error) => {
  console.error(error);
  process.exitCode = 1;
});

child.once("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code ?? 1;
});
