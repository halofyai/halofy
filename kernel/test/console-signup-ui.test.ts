import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const LOGIN_HTML = readFileSync(
  fileURLToPath(new URL("../console/login.html", import.meta.url)),
  "utf8",
);
const APP_CSS = readFileSync(
  fileURLToPath(new URL("../console/app.css", import.meta.url)),
  "utf8",
);

describe("inline organization signup (setup gate, SG1/SG2)", () => {
  it("uses the device viewport instead of a scaled desktop canvas", () => {
    expect(LOGIN_HTML).toContain(
      '<meta name="viewport" content="width=device-width, initial-scale=1" />',
    );
  });

  it("keeps organization creation inside the same left-side auth card", () => {
    const cardStart = LOGIN_HTML.indexOf('class="card auth-card"');
    const cardEnd = LOGIN_HTML.indexOf("</main>", cardStart);
    const signupStart = LOGIN_HTML.indexOf('id="organization-signup"');

    expect(signupStart).toBeGreaterThan(cardStart);
    expect(signupStart).toBeLessThan(cardEnd);
    expect(LOGIN_HTML).not.toContain('href="/console/signup"');
  });

  it("collects the required person and organization names, then hands off", () => {
    expect(LOGIN_HTML).toContain('id="organization-signup"');
    expect(LOGIN_HTML).toContain('id="organization-signup-email"');
    expect(LOGIN_HTML).toContain('id="signup-display-name"');
    expect(LOGIN_HTML).toContain('id="organization-name"');
    expect(LOGIN_HTML).toContain('id="organization-signup-submit"');
    expect(LOGIN_HTML).toContain('fetch("/auth/signup"');
    expect(LOGIN_HTML).toContain('organizationName: organizationName');
    expect(LOGIN_HTML).toContain('displayName: displayName');
    expect(LOGIN_HTML).not.toContain('id="organization-signup-namespace"');
    expect(LOGIN_HTML).not.toContain('id="organization-signup-role"');
    // Success goes straight into the (self-gating) console shell.
    expect(LOGIN_HTML).toContain('window.location.replace("/console/")');
  });

  it("lets a fresh self-hosted deployment create its first local owner", () => {
    expect(LOGIN_HTML).toContain('id="local-bootstrap"');
    expect(LOGIN_HTML).toContain('id="bootstrap-token"');
    expect(LOGIN_HTML).toContain('id="bootstrap-display-name"');
    expect(LOGIN_HTML).toContain('id="bootstrap-organization"');
    expect(LOGIN_HTML).toContain('id="bootstrap-email"');
    expect(LOGIN_HTML).toContain('id="bootstrap-password"');
    expect(LOGIN_HTML).toContain('fetch("/auth/bootstrap"');
    expect(LOGIN_HTML).toContain('showView("local-bootstrap")');
  });

  it("has NO wizard steps and NO skip of any kind (SG2)", () => {
    expect(LOGIN_HTML).not.toContain("ob-step-");
    expect(LOGIN_HTML).not.toContain("ob-intro");
    expect(LOGIN_HTML).not.toContain("ob-finish");
    expect(LOGIN_HTML).not.toContain("ob-skip");
    expect(LOGIN_HTML).not.toMatch(/skip/i);
    expect(LOGIN_HTML).not.toContain("localStorage");
    expect(LOGIN_HTML).not.toContain("halomem.onboarding");
  });

  it("gives sign-in a branded story panel without drawing focus around headings", () => {
    expect(LOGIN_HTML).toContain('class="auth-story"');
    expect(LOGIN_HTML).not.toContain('class="auth-story-proof"');
    expect(APP_CSS).toMatch(/\.auth-card h1:focus\{outline:none\}/);
  });

  it("uses the console metallic green with white integration marks on soft-black spheres", () => {
    expect(APP_CSS).toMatch(/\.auth-story\{[^}]*background:var\(--metal\)/);
    expect(APP_CSS).toMatch(/\.auth-stream-chip\{[^}]*background:radial-gradient\([^}]*#252a26[^}]*#0b0d0b/);
    expect(APP_CSS).toMatch(/\.auth-stream-chip img\{[^}]*filter:brightness\(0\) invert\(1\)[^}]*opacity:\.86/);
    expect(APP_CSS).toMatch(/\.auth-stream-core\{[^}]*background:radial-gradient\([^}]*#252a26[^}]*#0b0d0b/);
  });

  it("keeps the sign-in brand to Halofy with a mark matching the word height", () => {
    expect(LOGIN_HTML).toContain("<title>Sign in &middot; Halofy</title>");
    expect(LOGIN_HTML).not.toContain("Halofy Halo Mem");
    expect(LOGIN_HTML).toContain("<div><b>Halofy</b></div>");
    expect(LOGIN_HTML).not.toContain("<small>Halo Mem</small>");
    expect(LOGIN_HTML).toContain('assets/marks/halo-orb-static.png');
    expect(LOGIN_HTML).not.toContain('assets/marks/halofy-mark-white.svg');
    expect(APP_CSS).toMatch(/\.auth-story-brand img\{[^}]*width:20px;height:20px/);
    expect(APP_CSS).toMatch(/\.auth-story-brand b\{[^}]*line-height:20px/);
  });

  it("centers the sign-in promise in two fixed lines", () => {
    expect(LOGIN_HTML).toContain("<span>Every agent starts with</span>");
    expect(LOGIN_HTML).toContain("<span>the right context.</span>");
    expect(APP_CSS).toMatch(/\.auth-story-copy h2\{[^}]*max-width:none[^}]*text-align:center/);
    expect(APP_CSS).toMatch(/\.auth-story-copy h2 span\{[^}]*display:block[^}]*white-space:nowrap/);
  });

  it("removes the proof strip and reduces the promise type by forty percent", () => {
    expect(LOGIN_HTML).not.toContain("Governed writes");
    expect(LOGIN_HTML).not.toContain("Scoped access");
    expect(LOGIN_HTML).not.toContain("One endpoint");
    expect(APP_CSS).not.toContain(".auth-story-proof");
    expect(APP_CSS).toMatch(/\.auth-story-copy h2\{[^}]*font-size:clamp\(18px,2\.16vw,24px\)/);
    expect(APP_CSS).toContain(".auth-story-copy h2{max-width:none;font-size:20.4px}");
    expect(APP_CSS).toContain(".auth-story-copy h2{max-width:none;font-size:14.4px;line-height:1.05}");
  });

  it("fills the viewport with the split sign-in frame while loading stays in the form side", () => {
    expect(LOGIN_HTML.indexOf('id="auth-loading"')).toBeGreaterThan(LOGIN_HTML.indexOf('class="auth-frame"'));
    expect(APP_CSS).toMatch(/\.auth-shell\{[^}]*min-height:100dvh[^}]*padding:0/);
    expect(APP_CSS).toMatch(/\.auth-frame\{[^}]*width:100%[^}]*min-height:100dvh[^}]*border:0[^}]*border-radius:0[^}]*box-shadow:none/);
    expect(APP_CSS).toMatch(/\.auth-loading\{[^}]*min-height:320px/);
  });

  it("runs the sphere lanes at half their original speed", () => {
    expect(APP_CSS).toContain(".auth-stream-lane--edge{--dur:88s");
    expect(APP_CSS).toContain(".auth-stream-lane--main{--dur:68s");
  });

  it("uses a neutral gray track behind the sign-in mode tabs", () => {
    const authTabs = APP_CSS.match(/\.auth-tabs\{[^}]*\}/)?.[0] ?? "";

    expect(authTabs).toContain("background:#eceeeb");
    expect(authTabs).not.toContain("sage");
  });

  it("keeps provider buttons near their resting elevation while pressed", () => {
    const providerHover = APP_CSS.match(/\.google-signin:hover\{[^}]*\}/)?.[0] ?? "";

    expect(providerHover).toContain(
      "background:linear-gradient(180deg,var(--panel) 0%,var(--stone) 100%)",
    );
    expect(providerHover).not.toContain("sage");
    expect(providerHover).not.toContain("evergreen");
    expect(APP_CSS).toMatch(
      /\.google-signin:active\{transform:translateY\(0\);[^}]*inset 0 1px 2px[^}]*0 1px 2px/,
    );
    expect(APP_CSS).not.toMatch(/\.google-signin:active\{[^}]*translateY\(1px\)/);
  });

  it("centers the sign-in controls in a compact shadowed white card", () => {
    expect(APP_CSS).toMatch(/\.auth-frame\{[^}]*grid-template-areas:"auth story"/);
    expect(APP_CSS).toMatch(/\.auth-frame\{[^}]*grid-template-columns:minmax\(400px,2fr\) minmax\(0,3fr\)/);
    expect(APP_CSS).toMatch(/\.auth-story\{[^}]*grid-area:story/);
    expect(APP_CSS).toMatch(/\.auth-card\{[^}]*align-self:center[^}]*justify-self:center/);
    expect(APP_CSS).toMatch(/\.auth-card\{[^}]*grid-area:auth/);
    expect(APP_CSS).toMatch(/\.auth-card\{[^}]*width:min\(420px,calc\(100% - 48px\)\)[^}]*max-width:420px[^}]*padding:var\(--s5\)/);
    expect(APP_CSS).toMatch(/\.auth-form\{[^}]*gap:var\(--s3\)/);
    expect(APP_CSS).toContain("#email-auth>.field:first-of-type{padding-top:var(--s1)}");
    expect(APP_CSS).toMatch(/\.auth-card\{[^}]*border:1px solid var\(--line\)[^}]*border-radius:var\(--r-lg\)[^}]*background:#fff[^}]*box-shadow:var\(--sh-4\)/);
    expect(APP_CSS).toContain('.auth-frame{grid-template-columns:1fr;grid-template-areas:"story" "auth";min-height:100dvh}');
  });
});
