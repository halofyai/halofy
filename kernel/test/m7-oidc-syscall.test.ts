import { afterEach, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { OidcIdentityMapper } from "../src/iam/oidc.js";
import { Kernel } from "../src/kernel.js";

const kernels: Kernel[] = [];
afterEach(async () => Promise.all(kernels.splice(0).map((kernel) => kernel.close())));

it("accepts a currently verified OIDC identity at the syscall gate", async () => {
  const kernel = await Kernel.boot({
    databaseUrl: "", pgliteDataDir: "",
    knowledgeDir: fileURLToPath(new URL("../knowledge", import.meta.url)),
  });
  kernels.push(kernel);
  const mapper = new OidcIdentityMapper({
    providers: [{
      issuer: "https://idp.example.test", audiences: ["halomem"],
      subjects: { "user-1": { namespace: "acme", role: "member" } },
    }],
  });
  const identity = mapper.map({
    iss: "https://idp.example.test", sub: "user-1", aud: "halomem",
    exp: Math.floor(Date.now() / 1000) + 300,
  });

  expect(identity.credentialExpiresAt).toBeTruthy();
  await expect(kernel.memStats({}, identity, "oidc-test")).resolves.toMatchObject({
    namespace: "acme",
  });
});
