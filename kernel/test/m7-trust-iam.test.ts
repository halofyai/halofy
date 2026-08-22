import { describe, expect, it } from "vitest";

import { OidcIdentityMapper, OidcMappingError } from "../src/iam/oidc.js";
import {
  SCIM_USER_SCHEMA,
  ScimProvisioningService,
  ScimValidationError,
  type ScimDirectory,
  type ScimDirectoryUser,
} from "../src/iam/scim.js";

describe("M7 OIDC identity boundary", () => {
  const mapper = new OidcIdentityMapper({
    providers: [{
      issuer: "https://idp.example.test",
      audiences: ["halomem"],
      subjects: {
        "subject-1": { namespace: "acme/eng", role: "admin" },
      },
      groups: {
        "acme-readers": { namespace: "acme", role: "member" },
      },
    }],
  });

  it("derives namespace and role only from server-side bindings", () => {
    const identity = mapper.map({
      iss: "https://idp.example.test",
      aud: "halomem",
      sub: "subject-1",
      exp: 1_900_000_000,
      email: "admin@acme.test",
      email_verified: true,
      namespace: "globex/root",
      role: "owner",
    }, { now: new Date("2026-07-11T00:00:00.000Z") });

    expect(identity).toMatchObject({
      namespace: "acme/eng",
      role: "admin",
      actor: "admin@acme.test",
    });
    expect(identity.keyId).toMatch(/^oidc:[0-9a-f]{64}$/);
  });

  it("fails closed for an untrusted issuer, wrong audience, expiry, or unmapped subject", () => {
    const base = {
      iss: "https://idp.example.test",
      aud: "halomem",
      sub: "subject-1",
      exp: 1_900_000_000,
    };
    const options = { now: new Date("2026-07-11T00:00:00.000Z") };

    expect(() => mapper.map({ ...base, iss: "https://evil.test" }, options))
      .toThrow(OidcMappingError);
    expect(() => mapper.map({ ...base, aud: "other" }, options)).toThrow(/audience/i);
    expect(() => mapper.map({ ...base, exp: 1 }, options)).toThrow(/expired/i);
    expect(() => mapper.map({ ...base, sub: "unknown" }, options)).toThrow(/binding/i);
  });
});

describe("M7 SCIM provisioning seam", () => {
  function harness() {
    const users: ScimDirectoryUser[] = [];
    const directory: ScimDirectory = {
      async upsertUser(user) {
        users.push(user);
      },
      async replaceGroup() {},
    };
    const service = new ScimProvisioningService(directory, {
      groups: {
        "acme-engineers": { namespace: "acme/eng", role: "member" },
      },
    });
    return { service, users };
  }

  it("maps a SCIM group through server configuration and never accepts caller scope", async () => {
    const { service, users } = harness();
    await service.provisionUser({
      schemas: [SCIM_USER_SCHEMA],
      externalId: "idp-user-7",
      userName: "person@acme.test",
      displayName: "Person Name",
      active: true,
      groups: [{ value: "acme-engineers" }],
    });
    expect(users[0]).toEqual({
      externalId: "idp-user-7",
      email: "person@acme.test",
      displayName: "Person Name",
      active: true,
      namespace: "acme/eng",
      role: "member",
      groupIds: ["acme-engineers"],
    });

    await expect(service.provisionUser({
      schemas: [SCIM_USER_SCHEMA],
      externalId: "attacker",
      userName: "attacker@evil.test",
      displayName: "Attacker",
      groups: [{ value: "acme-engineers" }],
      namespace: "",
      role: "owner",
    })).rejects.toThrow(ScimValidationError);
  });

  it("rejects unmapped and ambiguous groups instead of guessing authority", async () => {
    const { service } = harness();
    await expect(service.provisionUser({
      schemas: [SCIM_USER_SCHEMA],
      externalId: "unknown",
      userName: "unknown@acme.test",
      displayName: "Unknown User",
      groups: [{ value: "not-configured" }],
    })).rejects.toThrow(/mapped group/i);

    const directory: ScimDirectory = { async upsertUser() {}, async replaceGroup() {} };
    const ambiguous = new ScimProvisioningService(directory, {
      groups: {
        a: { namespace: "acme", role: "member" },
        b: { namespace: "globex", role: "member" },
      },
    });
    await expect(ambiguous.provisionUser({
      schemas: [SCIM_USER_SCHEMA],
      externalId: "ambiguous",
      userName: "ambiguous@example.test",
      displayName: "Ambiguous User",
      groups: [{ value: "a" }, { value: "b" }],
    })).rejects.toThrow(/ambiguous/i);
  });
});
