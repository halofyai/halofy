import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const LOGIN_HTML = readFileSync(
  fileURLToPath(new URL("../console/login.html", import.meta.url)),
  "utf8",
);
const LOGIN_SCRIPT = LOGIN_HTML.match(/<script>\s*([\s\S]*?)<\/script>/)?.[1];

if (!LOGIN_SCRIPT) throw new Error("login.html has no inline script");

class FakeNode {
  hidden = true;
  textContent = "";
  value = "";
  disabled = false;
  autocomplete = "";
  style = { display: "" };
  classList = { toggle: () => undefined };

  /** Captured so a test can fire a real handler (e.g. the Google button). */
  handlers = new Map<string, (ev?: unknown) => void>();

  setAttribute(): void {}
  addEventListener(name: string, fn: (ev?: unknown) => void): void {
    this.handlers.set(name, fn);
  }
  focus(): void {}
}

interface FakeResponse {
  status: number;
  json(): Promise<Record<string, unknown>>;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function response(status: number, body: Record<string, unknown> = {}): FakeResponse {
  return { status, json: async () => body };
}

/**
 * `opts.search` seeds the address bar; `opts.storage` seeds sessionStorage —
 * both are what the OAuth consent bounce rides on (OA8).
 */
function callbackHarness(opts: {
  hash?: string;
  search?: string;
  storage?: Record<string, string>;
} = {}) {
  const ids = [...LOGIN_HTML.matchAll(/id="([^"]+)"/g)].map((match) => match[1]!);
  const nodes = new Map(ids.map((id) => [id, new FakeNode()]));
  nodes.get("auth-loading")!.hidden = false;

  const exchangeResponse = deferred<FakeResponse>();
  const fetchCalls: string[] = [];
  const replaceCalls: string[] = [];
  const signupBodies: Array<Record<string, unknown>> = [];
  const hash = opts.hash ?? "#access_token=idp-token&type=bearer";
  const location = {
    origin: "https://halomem.test",
    pathname: "/console/login",
    search: opts.search ?? "",
    hash,
    href: "https://halomem.test/console/login" + hash,
    replace(path: string) {
      replaceCalls.push(path);
    },
  };

  const backing = new Map(Object.entries(opts.storage ?? {}));
  const store = {
    getItem: (key: string) => (backing.has(key) ? backing.get(key)! : null),
    setItem: (key: string, value: string) => { backing.set(key, value); },
    removeItem: (key: string) => { backing.delete(key); },
  };

  const context = createContext({
    URLSearchParams,
    document: {
      getElementById(id: string) {
        const node = nodes.get(id);
        if (!node) throw new Error(`unknown login node: ${id}`);
        return node;
      },
    },
    fetch(url: string, init: { method?: string; body?: string } = {}) {
      fetchCalls.push(url);
      if (url === "/auth/sso/config") {
        return Promise.resolve(response(200, {
          enabled: true,
          url: "https://project.supabase.test",
          anonKey: "public-anon-key",
        }));
      }
      if (url === "/auth/sso") return exchangeResponse.promise;
      if (url === "/auth/signup") {
        if (init.method === "POST") {
          signupBodies.push(JSON.parse(init.body ?? "{}") as Record<string, unknown>);
          return Promise.resolve(response(201, {
            organization: { id: "acme-12345678", name: "Acme Labs" },
          }));
        }
        return Promise.resolve(response(200, { email: "founder@example.test" }));
      }
      throw new Error(`unexpected fetch: ${url}`);
    },
    history: { replaceState: () => undefined },
    window: { location, sessionStorage: store },
  });

  new Script(LOGIN_SCRIPT).runInContext(context);

  return { exchangeResponse, fetchCalls, location, nodes, replaceCalls, signupBodies, store };
}

async function flushPromises(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

describe("console Google OAuth callback", () => {
  it("keeps provider callback errors in the unified sign-in form", () => {
    expect(LOGIN_HTML).toMatch(
      /<div id="email-auth">[\s\S]*?<div class="hint auth-error" id="login-error"/,
    );
    expect(LOGIN_HTML).not.toContain('id="sso-error"');
  });

  it("keeps every sign-in control hidden while the kernel session exchange is pending", async () => {
    const harness = callbackHarness();
    await flushPromises();

    expect(harness.fetchCalls).toEqual(["/auth/sso/config", "/auth/sso"]);
    expect(harness.nodes.get("auth-loading")!.hidden).toBe(false);
    expect(harness.nodes.get("login-form")!.hidden).toBe(true);
  });

  it("replaces the callback page with the console after a successful exchange", async () => {
    const harness = callbackHarness();
    await flushPromises();
    harness.exchangeResponse.resolve(response(200));
    await flushPromises();

    expect(harness.replaceCalls).toEqual(["/console/"]);
    expect(harness.nodes.get("login-form")!.hidden).toBe(true);
  });

  it("shows organization signup in the same card for a verified first-time identity", async () => {
    const harness = callbackHarness();
    await flushPromises();
    harness.exchangeResponse.resolve(response(202, {
      code: "onboarding_required",
      next: "/console/login?signup=organization",
    }));
    await flushPromises();

    expect(harness.fetchCalls).toEqual(["/auth/sso/config", "/auth/sso", "/auth/signup"]);
    expect(harness.replaceCalls).toEqual([]);
    expect(harness.nodes.get("login-form")!.hidden).toBe(true);
    expect(harness.nodes.get("organization-signup")!.hidden).toBe(false);
    expect(harness.nodes.get("organization-signup-email")!.textContent).toBe(
      "founder@example.test",
    );
  });

  it("submits the required person and organization names, then enters the console", async () => {
    const harness = callbackHarness();
    await flushPromises();
    harness.exchangeResponse.resolve(response(202, {
      code: "onboarding_required",
      next: "/console/login?signup=organization",
    }));
    await flushPromises();

    harness.nodes.get("signup-display-name")!.value = "  Ada Lovelace  ";
    harness.nodes.get("organization-name")!.value = "  Acme Labs  ";
    harness.nodes.get("organization-signup")!.handlers.get("submit")!({
      preventDefault: () => undefined,
    });
    await flushPromises();

    expect(harness.signupBodies).toEqual([{
      displayName: "Ada Lovelace",
      organizationName: "Acme Labs",
    }]);
    expect(harness.replaceCalls).toEqual(["/console/"]);
  });

  it("restores the sign-in controls when the kernel session exchange fails", async () => {
    const harness = callbackHarness();
    await flushPromises();
    harness.exchangeResponse.resolve(response(403, { code: "no_console_access" }));
    await flushPromises();

    expect(harness.nodes.get("auth-loading")!.hidden).toBe(true);
    expect(harness.nodes.get("login-form")!.hidden).toBe(false);
    expect(harness.nodes.get("login-error")!.textContent).toContain("no control-room access");
  });

  it("opens account creation in the same card before starting Google", async () => {
    const harness = callbackHarness({ hash: "" });
    await flushPromises();

    harness.nodes.get("tab-signup")!.handlers.get("click")!();

    expect(harness.nodes.get("login-form")!.hidden).toBe(false);
    expect(harness.nodes.get("native-title")!.textContent).toBe("Create your account");
    expect(harness.nodes.get("sso-toggle-label")!.textContent).toBe("Continue with Google");
    expect(harness.replaceCalls).toEqual([]);
  });

  it("restores a pending organization signup in the login card after reload", async () => {
    const harness = callbackHarness({ hash: "", search: "?signup=organization" });
    await flushPromises();

    expect(harness.fetchCalls).toEqual(["/auth/sso/config", "/auth/signup"]);
    expect(harness.nodes.get("organization-signup")!.hidden).toBe(false);
    expect(harness.nodes.get("organization-signup-email")!.textContent).toBe(
      "founder@example.test",
    );
  });
});

/**
 * OA8 — the consent bounce must survive a provider round trip.
 *
 * Regression: `/oauth/authorize` sends a signed-out visitor to
 * `/console/login?next=/oauth/authorize?…`, but Google sign-in leaves for
 * Supabase and returns to a BARE `/console/login` — the `next` was gone by the
 * time the session exchange landed, so the user signed in, was dropped in the
 * console, and the connector that sent them (ChatGPT / Claude) sat there
 * unconnected forever. The value is now stashed before leaving and consumed on
 * return.
 */
describe("console login honors the OAuth consent bounce", () => {
  const NEXT = "/oauth/authorize?response_type=code&client_id=hmc_x&state=st-1";
  const KEY = "halomem.consent-next";

  it("returns to the authorize URL still present in the address bar", async () => {
    const harness = callbackHarness({ search: `?next=${encodeURIComponent(NEXT)}` });
    await flushPromises();
    harness.exchangeResponse.resolve(response(200));
    await flushPromises();
    expect(harness.replaceCalls).toEqual([NEXT]);
  });

  it("returns to the authorize URL stashed before the provider round trip", async () => {
    const harness = callbackHarness({ storage: { [KEY]: NEXT } });
    await flushPromises();
    harness.exchangeResponse.resolve(response(200));
    await flushPromises();
    expect(harness.replaceCalls).toEqual([NEXT]);
    // One-shot: a later sign-in must not be hijacked by a stale bounce.
    expect(harness.store.getItem(KEY)).toBeNull();
  });

  it("refuses a stashed value that is not this kernel's authorize endpoint", async () => {
    for (const hostile of ["https://evil.example/steal", "//evil.example", "/console/#s18"]) {
      const harness = callbackHarness({ storage: { [KEY]: hostile } });
      await flushPromises();
      harness.exchangeResponse.resolve(response(200));
      await flushPromises();
      expect(harness.replaceCalls, hostile).toEqual(["/console/"]);
    }
  });

  it("still lands in the console when there is no bounce at all", async () => {
    const harness = callbackHarness();
    await flushPromises();
    harness.exchangeResponse.resolve(response(200));
    await flushPromises();
    expect(harness.replaceCalls).toEqual(["/console/"]);
  });
});

describe("console login stashes the consent bounce before leaving for a provider", () => {
  const NEXT = "/oauth/authorize?response_type=code&client_id=hmc_x&state=st-1";
  const KEY = "halomem.consent-next";

  /** A page load with no auth fragment — the sign-in view, buttons wired. */
  function signInHarness(search: string) {
    return callbackHarness({ search, hash: "" });
  }

  it("Google: the bounce is stashed, because Supabase returns to a bare login URL", async () => {
    const harness = signInHarness(`?next=${encodeURIComponent(NEXT)}`);
    await flushPromises();
    harness.nodes.get("sso-toggle")!.handlers.get("click")!();
    expect(harness.store.getItem(KEY)).toBe(NEXT);
    expect(harness.location.href).toContain("provider=google");
  });

  it("GitHub: the bounce rides the query, because its callback never returns here", async () => {
    const harness = signInHarness(`?next=${encodeURIComponent(NEXT)}`);
    await flushPromises();
    harness.nodes.get("github-signin")!.handlers.get("click")!();
    expect(harness.location.href).toBe("/auth/github?next=" + encodeURIComponent(NEXT));
  });

  it("stashes nothing, and adds no query, when there is no bounce", async () => {
    const harness = signInHarness("");
    await flushPromises();
    harness.nodes.get("sso-toggle")!.handlers.get("click")!();
    expect(harness.store.getItem(KEY)).toBeNull();
    harness.nodes.get("github-signin")!.handlers.get("click")!();
    expect(harness.location.href).toBe("/auth/github");
  });

  it("stashes nothing for a hostile next", async () => {
    const harness = signInHarness("?next=" + encodeURIComponent("https://evil.example/steal"));
    await flushPromises();
    harness.nodes.get("sso-toggle")!.handlers.get("click")!();
    expect(harness.store.getItem(KEY)).toBeNull();
    harness.nodes.get("github-signin")!.handlers.get("click")!();
    expect(harness.location.href).toBe("/auth/github");
  });
});
