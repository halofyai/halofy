import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { describe, expect, it } from "vitest";

const LOGIN_HTML = fileURLToPath(new URL("../console/login.html", import.meta.url));
const SUPABASE_URL = "https://project.supabase.test";

type Listener = (event: { preventDefault(): void }) => unknown;

class FakeElement {
  hidden = false;
  disabled = false;
  textContent = "";
  value = "";
  autocomplete = "";
  style: Record<string, string> = {};
  readonly listeners = new Map<string, Listener>();
  readonly attributes = new Map<string, string>();
  readonly classes = new Set<string>();

  constructor(
    readonly id: string,
    hidden: boolean,
    private readonly onFocus: (element: FakeElement) => void,
  ) {
    this.hidden = hidden;
  }

  classList = {
    toggle: (name: string, force?: boolean) => {
      const enabled = force ?? !this.classes.has(name);
      if (enabled) this.classes.add(name);
      else this.classes.delete(name);
      return enabled;
    },
  };

  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, listener);
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  focus(): void {
    this.onFocus(this);
  }
}

type FetchReply = { status: number; body?: unknown } | Error;

async function loginSource(): Promise<string> {
  return readFile(LOGIN_HTML, "utf8");
}

async function settle(): Promise<void> {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
}

function inlineScript(source: string): string | null {
  const opening = "<script>";
  const closing = "</script>";
  const start = source.indexOf(opening);
  if (start < 0) return null;
  const contentStart = start + opening.length;
  const end = source.indexOf(closing, contentStart);
  return end < 0 ? null : source.slice(contentStart, end);
}

async function bootLogin(options: {
  emailDeliveryReady?: boolean;
  configRejects?: boolean;
  hash?: string;
  replies?: FetchReply[];
} = {}) {
  const source = await loginSource();
  const script = inlineScript(source);
  if (!script) throw new Error("login script not found");

  let activeElement: FakeElement | null = null;
  const elements = new Map<string, FakeElement>();
  const tags = source.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g);
  for (const match of tags) {
    const tag = match[0];
    const id = match[1];
    elements.set(
      id,
      new FakeElement(id, /\shidden(?:\s|>)/.test(tag), (element) => {
        activeElement = element;
      }),
    );
  }

  const location = {
    origin: "https://halomem.example.test",
    pathname: "/console/login",
    search: "",
    hash: options.hash ?? "",
    href: "",
  };
  const historyCalls: string[] = [];
  const history = {
    replaceState(_state: unknown, _title: string, url: string) {
      historyCalls.push(url);
      location.hash = "";
    },
  };
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const replies = [...(options.replies ?? [])];
  const response = (status: number, body: unknown) => ({
    status,
    json: async () => body,
  });
  const fetchFn = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "/auth/sso/config") {
      if (options.configRejects) throw new Error("config unavailable");
      return response(200, {
        enabled: true,
        url: SUPABASE_URL,
        anonKey: "public-anon-key",
        emailDeliveryReady: options.emailDeliveryReady === true,
      });
    }
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    if (!reply) return response(500, {});
    return response(reply.status, reply.body ?? {});
  };
  const document = {
    get activeElement() {
      return activeElement;
    },
    getElementById(id: string) {
      const element = elements.get(id);
      if (!element) throw new Error(`missing fake element ${id}`);
      return element;
    },
  };
  const window = { location };

  vm.runInNewContext(script, {
    document,
    window,
    history,
    fetch: fetchFn,
    URLSearchParams,
    encodeURIComponent,
    JSON,
    Promise,
    String,
  });
  await settle();

  return {
    source,
    elements,
    requests,
    historyCalls,
    get activeElement() {
      return activeElement;
    },
    get locationHref() {
      return location.href;
    },
    async trigger(id: string, type: string) {
      const listener = elements.get(id)?.listeners.get(type);
      if (!listener) throw new Error(`missing ${type} listener for ${id}`);
      listener({ preventDefault() { /* test event */ } });
      await settle();
    },
  };
}

describe("hosted email auth delivery", () => {
  it("starts with sign-in and account-creation choices in one form", async () => {
    const page = await bootLogin();

    expect(page.elements.get("login-form")?.hidden).toBe(false);
    expect(page.elements.get("sso-toggle")?.hidden).toBe(false);
    expect(page.activeElement?.id).toBe("native-title");

    const nativeForm = page.source.match(/<form class="auth-form" id="login-form"[\s\S]*?<\/form>/)?.[0];
    expect(nativeForm).toContain('type="email"');
    expect(nativeForm).toContain('type="password"');
    expect(nativeForm).not.toMatch(/otp|totp|mfa|2fa|two-factor/i);
    expect(nativeForm).toContain('class="google-signin" id="sso-toggle"');
    expect(nativeForm).toContain('class="google-signin__mark"');
    expect(nativeForm).toContain('id="sso-toggle-label">Sign in with Google</span>');
    expect(nativeForm.indexOf('id="tab-signin"')).toBeLessThan(nativeForm.indexOf('id="sso-toggle"'));
    expect(nativeForm.indexOf('id="tab-signup"')).toBeLessThan(nativeForm.indexOf('id="sso-toggle"'));
    expect(page.source).toContain('class="sub" id="auth-sub">Access your workspace.</div>');
    expect(page.source).toContain('class="hint auth-status sr-only" id="email-availability"');
    expect(page.source).toContain('class="auth-terms sr-only">By continuing, you agree');
    expect(page.source).not.toContain('id="native-toggle"');
    expect(page.source).not.toContain("Admin sign-in");

    await page.trigger("sso-toggle", "click");
    expect(page.locationHref).toContain(`${SUPABASE_URL}/auth/v1/authorize?provider=google`);
    expect(page.elements.get("login-form")?.hidden).toBe(false);
  });

  it("launches Google directly even when hosted email delivery is ready", async () => {
    const page = await bootLogin({ emailDeliveryReady: true });

    expect(page.elements.get("login-form")?.hidden).toBe(false);
    expect(page.elements.get("sso-toggle-label")?.textContent).toBe("Sign in with Google");
    expect(page.elements.get("sso-toggle")?.attributes.get("aria-label")).toBe(
      "Sign in with Google",
    );

    await page.trigger("sso-toggle", "click");
    expect(page.elements.get("email-auth")?.hidden).toBe(false);
    expect(page.locationHref).toContain(`${SUPABASE_URL}/auth/v1/authorize?provider=google`);
  });

  it("preserves OAuth and recovery callbacks ahead of the native primary view", async () => {
    const oauth = await bootLogin({
      hash: "#access_token=fake-oauth-token&type=signup",
      replies: [{ status: 401 }],
    });
    expect(oauth.historyCalls).toEqual(["/console/login"]);
    expect(oauth.elements.get("login-form")?.hidden).toBe(false);
    expect(oauth.requests.map((request) => request.url)).toEqual([
      "/auth/sso/config",
      "/auth/sso",
    ]);

    const cancelled = await bootLogin({
      hash: "#error=access_denied&error_description=Sign-in+was+cancelled",
    });
    expect(cancelled.elements.get("login-form")?.hidden).toBe(false);
    expect(cancelled.elements.get("login-error")?.textContent).toBe("Sign-in was cancelled");

    const recovery = await bootLogin({
      hash: "#access_token=fake-recovery-token&type=recovery",
    });
    expect(recovery.elements.get("sso-recovery")?.hidden).toBe(false);
    expect(recovery.elements.get("login-form")?.hidden).toBe(true);
    expect(recovery.activeElement?.id).toBe("recovery-title");
  });

  it("restores native submit focus after rejected and failed login attempts", async () => {
    const rejected = await bootLogin({ replies: [{ status: 401 }] });
    rejected.elements.get("email")!.value = "person@example.test";
    rejected.elements.get("password")!.value = "not-a-real-password";
    rejected.elements.get("email")!.focus();
    await rejected.trigger("login-form", "submit");
    expect(rejected.elements.get("login-error")?.textContent).toBe("Email or password is incorrect.");
    expect(rejected.activeElement?.id).toBe("submit");

    const failed = await bootLogin({ replies: [new Error("network down")] });
    failed.elements.get("email")!.value = "person@example.test";
    failed.elements.get("password")!.value = "not-a-real-password";
    failed.elements.get("password")!.focus();
    await failed.trigger("login-form", "submit");
    expect(failed.elements.get("login-error")?.textContent).toBe("Something went wrong. Please try again.");
    expect(failed.activeElement?.id).toBe("submit");
  });

  it("automatically tries hosted credentials after a local credential miss", async () => {
    const page = await bootLogin({
      emailDeliveryReady: true,
      replies: [
        { status: 401 },
        { status: 200, body: { access_token: "hosted-access-token" } },
        { status: 403, body: { code: "no_console_access" } },
      ],
    });
    page.elements.get("email")!.value = "person@example.test";
    page.elements.get("password")!.value = "not-a-real-password";

    await page.trigger("login-form", "submit");

    expect(page.requests.map((request) => request.url)).toEqual([
      "/auth/sso/config",
      "/auth/login",
      `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
      "/auth/sso",
    ]);
    expect(page.elements.get("login-error")?.textContent).toContain("no control-room access");
    expect(page.activeElement?.id).toBe("submit");
  });

  it("routes straight to Google and keeps hosted email unavailable when delivery is not ready", async () => {
    const page = await bootLogin();
    await page.trigger("sso-toggle", "click");

    expect(page.elements.get("login-form")?.hidden).toBe(false);
    expect(page.elements.get("email-auth")?.hidden).toBe(false);
    expect(page.locationHref).toContain(`${SUPABASE_URL}/auth/v1/authorize?provider=google`);
    expect(page.elements.get("email-availability")?.textContent).toContain(
      "Hosted email sign-in, account creation, and password reset are temporarily unavailable",
    );
    expect(page.requests).toHaveLength(1);
  });

  it("uses privacy-safe copy and focuses the pending heading after signup acceptance", async () => {
    const page = await bootLogin({
      emailDeliveryReady: true,
      replies: [{ status: 200, body: { id: "obfuscated-user", identities: [] } }],
    });
    await page.trigger("tab-signup", "click");
    page.elements.get("email")!.value = "person@example.test";
    page.elements.get("password")!.value = "not-a-real-password";
    await page.trigger("login-form", "submit");

    expect(page.elements.get("sso-pending")?.hidden).toBe(false);
    expect(page.elements.get("pending-email")?.textContent).toBe("person@example.test");
    expect(page.activeElement?.id).toBe("pending-title");
    expect(page.source).toContain("If account creation is available for this address and delivery succeeds");
    expect(page.source).not.toContain("A confirmation link was sent");
  });

  it("shows rate-limit errors instead of claiming signup or resend delivery", async () => {
    const signup = await bootLogin({
      emailDeliveryReady: true,
      replies: [{ status: 429, body: { msg: "Email rate limit exceeded" } }],
    });
    await signup.trigger("tab-signup", "click");
    signup.elements.get("email")!.value = "person@example.test";
    signup.elements.get("password")!.value = "not-a-real-password";
    await signup.trigger("login-form", "submit");
    expect(signup.elements.get("login-error")?.textContent).toContain("Too many attempts");
    expect(signup.elements.get("sso-pending")?.hidden).toBe(true);
    expect(signup.activeElement?.id).toBe("submit");

    const resend = await bootLogin({
      emailDeliveryReady: true,
      replies: [
        { status: 200, body: { id: "pending-user" } },
        { status: 429, body: { msg: "Email rate limit exceeded" } },
      ],
    });
    await resend.trigger("tab-signup", "click");
    resend.elements.get("email")!.value = "person@example.test";
    resend.elements.get("password")!.value = "not-a-real-password";
    await resend.trigger("login-form", "submit");
    await resend.trigger("resend-btn", "click");
    expect(resend.elements.get("pending-status")?.textContent).toContain("Too many attempts");
    expect(resend.activeElement?.id).toBe("resend-btn");
  });

  it("distinguishes accepted recovery requests from network failures", async () => {
    const accepted = await bootLogin({
      emailDeliveryReady: true,
      replies: [{ status: 200 }],
    });
    await accepted.trigger("forgot-link", "click");
    accepted.elements.get("forgot-email")!.value = "person@example.test";
    await accepted.trigger("forgot-form", "submit");
    expect(accepted.elements.get("forgot-status")?.textContent).toContain(
      "If an account exists and delivery succeeds",
    );
    expect(accepted.activeElement?.id).toBe("forgot-submit");

    const failed = await bootLogin({
      emailDeliveryReady: true,
      replies: [new Error("network down")],
    });
    await failed.trigger("forgot-link", "click");
    failed.elements.get("forgot-email")!.value = "person@example.test";
    await failed.trigger("forgot-form", "submit");
    expect(failed.elements.get("forgot-status")?.textContent).toBe(
      "We could not send a reset link. Please try again.",
    );
    expect(failed.activeElement?.id).toBe("forgot-submit");
  });

  it("scrubs recovery tokens before a config request can fail", async () => {
    const page = await bootLogin({
      configRejects: true,
      hash: "#access_token=secret-token&type=recovery",
    });

    expect(page.historyCalls).toEqual(["/console/login"]);
    expect(page.elements.get("login-form")?.hidden).toBe(false);
  });

  it("scrubs refresh-only credential fragments and restores focus on back navigation", async () => {
    const scrubbed = await bootLogin({
      configRejects: true,
      hash: "#refresh_token=refresh-secret&type=recovery",
    });
    expect(scrubbed.historyCalls).toEqual(["/console/login"]);

    const page = await bootLogin({
      emailDeliveryReady: true,
      replies: [{ status: 200, body: { id: "pending-user" } }],
    });
    await page.trigger("tab-signup", "click");
    page.elements.get("email")!.value = "person@example.test";
    page.elements.get("password")!.value = "not-a-real-password";
    await page.trigger("login-form", "submit");
    expect(page.activeElement?.id).toBe("pending-title");
    await page.trigger("pending-back", "click");
    expect(page.activeElement?.id).toBe("native-title");
    await page.trigger("sso-toggle", "click");
    expect(page.locationHref).toContain(`${SUPABASE_URL}/auth/v1/authorize?provider=google`);
  });
});
