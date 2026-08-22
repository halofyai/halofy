import { describe, expect, it } from "vitest";

import { createEntraTokenSource, parsePostgresDsn } from "../src/db/entra-auth.js";
import { poolConfigFor } from "../src/db/client.js";
import { loadConfig, type KernelConfig } from "../src/config.js";

const DSN = "postgresql://halomem_app:s3cret@pg.example.test:5432/halomem?sslmode=verify-full";

function config(overrides: Partial<KernelConfig> = {}): KernelConfig {
  return { ...loadConfig(), databaseUrl: DSN, ...overrides };
}

function tokenResponse(token: string, expiresOn: unknown): Response {
  return new Response(
    JSON.stringify({ access_token: token, expires_on: expiresOn }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

describe("parsePostgresDsn", () => {
  it("splits the DSN into the discrete fields pg needs", () => {
    expect(parsePostgresDsn(DSN)).toEqual({
      host: "pg.example.test",
      port: 5432,
      database: "halomem",
      user: "halomem_app",
      ssl: { rejectUnauthorized: true },
    });
  });

  it("defaults the port when the DSN omits it", () => {
    expect(parsePostgresDsn("postgresql://u:p@h/db").port).toBe(5432);
  });

  it("maps sslmode to a verification posture that never loosens by accident", () => {
    const ssl = (mode: string) =>
      parsePostgresDsn(`postgresql://u:p@h:5432/db?sslmode=${mode}`).ssl;
    expect(ssl("verify-full")).toEqual({ rejectUnauthorized: true });
    // Stricter than libpq's verify-ca (which skips the hostname check) on
    // purpose: over-verifying is safe, under-verifying is not.
    expect(ssl("verify-ca")).toEqual({ rejectUnauthorized: true });
    expect(ssl("require")).toEqual({ rejectUnauthorized: true });
    expect(ssl("no-verify")).toEqual({ rejectUnauthorized: false });
    expect(ssl("disable")).toBe(false);
    // An absent or unrecognised sslmode must still verify.
    expect(parsePostgresDsn("postgresql://u:p@h:5432/db").ssl)
      .toEqual({ rejectUnauthorized: true });
  });
});

describe("entra token source", () => {
  it("uses the injected identity endpoint and its secret header", async () => {
    const seen: { url: string; headers: unknown }[] = [];
    const source = createEntraTokenSource({
      clientId: "client-1",
      env: { IDENTITY_ENDPOINT: "http://localhost:42/token", IDENTITY_HEADER: "shhh" },
      fetchImpl: async (url, init) => {
        seen.push({ url: String(url), headers: init?.headers });
        return tokenResponse("tok-1", 4_000_000_000);
      },
    });

    expect(await source.token()).toBe("tok-1");
    expect(seen[0]?.url).toContain("resource=https%3A%2F%2Fossrdbms-aad.database.windows.net");
    expect(seen[0]?.url).toContain("client_id=client-1");
    expect(seen[0]?.headers).toEqual({ "x-identity-header": "shhh" });
  });

  it("falls back to IMDS when no identity endpoint is injected", async () => {
    const seen: string[] = [];
    const source = createEntraTokenSource({
      env: {},
      fetchImpl: async (url, init) => {
        seen.push(String(url));
        expect(init?.headers).toEqual({ metadata: "true" });
        return tokenResponse("tok-imds", 4_000_000_000);
      },
    });

    expect(await source.token()).toBe("tok-imds");
    expect(seen[0]).toContain("169.254.169.254");
  });

  it("caches until the renewal window and then re-mints", async () => {
    let calls = 0;
    let nowMs = 1_000_000_000_000;
    const source = createEntraTokenSource({
      env: {},
      now: () => nowMs,
      fetchImpl: async () => {
        calls += 1;
        // Expires 10 minutes after the current clock.
        return tokenResponse(`tok-${calls}`, Math.floor(nowMs / 1000) + 600);
      },
    });

    expect(await source.token()).toBe("tok-1");
    expect(await source.token()).toBe("tok-1");
    expect(calls).toBe(1);

    // Inside the 5-minute renewal skew: must re-mint rather than hand back a
    // token that could expire mid-handshake.
    nowMs += 400_000;
    expect(await source.token()).toBe("tok-2");
    expect(calls).toBe(2);
  });

  it("collapses concurrent callers onto one in-flight request", async () => {
    let calls = 0;
    const source = createEntraTokenSource({
      env: {},
      fetchImpl: async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return tokenResponse("tok-shared", 4_000_000_000);
      },
    });

    const all = await Promise.all([source.token(), source.token(), source.token()]);
    expect(all).toEqual(["tok-shared", "tok-shared", "tok-shared"]);
    expect(calls).toBe(1);
  });

  it("treats an unparseable expiry as already expiring rather than caching it", async () => {
    let calls = 0;
    const source = createEntraTokenSource({
      env: {},
      fetchImpl: async () => {
        calls += 1;
        return tokenResponse(`tok-${calls}`, "not-a-date");
      },
    });

    await source.token();
    await source.token();
    expect(calls).toBe(2);
  });

  it("rejects a response with no access_token", async () => {
    const source = createEntraTokenSource({
      env: {},
      fetchImpl: async () =>
        new Response(JSON.stringify({}), { status: 200 }),
    });
    await expect(source.token()).rejects.toThrow(/no access_token/);
  });

  it("does not leak the response body on a failed token request", async () => {
    const source = createEntraTokenSource({
      env: {},
      fetchImpl: async () =>
        new Response("x-identity-header: shhh", { status: 500 }),
    });
    await expect(source.token()).rejects.toThrow(/status 500/);
    await expect(source.token()).rejects.not.toThrow(/shhh/);
  });
});

describe("poolConfigFor", () => {
  it("passes the DSN through untouched in password mode", () => {
    expect(poolConfigFor(config())).toEqual({ connectionString: DSN });
  });

  it("decomposes the DSN in entra mode so the password callback survives", () => {
    const built = poolConfigFor(config({
      dbAuthMode: "entra",
      dbEntraUser: "halomem-kernel-mi",
    }));
    // A `connectionString` here would silently discard `password`: pg does
    // Object.assign({}, config, parse(connectionString)) and the parser always
    // emits a password key.
    expect(built.connectionString).toBeUndefined();
    expect(built.user).toBe("halomem-kernel-mi");
    expect(built.host).toBe("pg.example.test");
    expect(built.database).toBe("halomem");
    expect(built.ssl).toEqual({ rejectUnauthorized: true });
    expect(typeof built.password).toBe("function");
  });

  it("keeps the DSN role when no entra user is configured", () => {
    const built = poolConfigFor(config({ dbAuthMode: "entra" }));
    expect(built.user).toBe("halomem_app");
  });

  // Both brownout tests INJECT a failing token source (hermetic — zero
  // network). The earlier versions let the real IMDS fetch fail and hung for
  // the whole abort window on hosts that blackhole 169.254.169.254; whether
  // the OS refuses fast is not a property of this kernel.
  const unreachable = {
    token: async (): Promise<string> => {
      throw new Error("identity endpoint unreachable");
    },
  };

  it("browns out to the DSN password when the token endpoint fails", async () => {
    const built = poolConfigFor(config({
      dbAuthMode: "entra",
      dbEntraUser: "halomem-kernel-mi",
    }), { tokens: unreachable });
    const password = built.password as () => Promise<string>;
    await expect(password()).resolves.toBe("s3cret");
  });

  it("propagates the failure when there is no password to fall back to", async () => {
    const built = poolConfigFor(config({
      databaseUrl: "postgresql://halomem_app@pg.example.test:5432/halomem?sslmode=verify-full",
      dbAuthMode: "entra",
      dbEntraUser: "halomem-kernel-mi",
    }), { tokens: unreachable });
    const password = built.password as () => Promise<string>;
    await expect(password()).rejects.toThrow(/unreachable/);
  });

  it("bounds the real token fetch so a blackholed IMDS cannot hang the pool", async () => {
    // A fetch that never settles on its own — only the AbortSignal ends it.
    const source = createEntraTokenSource({
      env: {},
      timeoutMs: 50,
      fetchImpl: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(Object.assign(new Error("aborted"), { name: "TimeoutError" })));
        }),
    });
    await expect(source.token()).rejects.toThrow();
  });
});
