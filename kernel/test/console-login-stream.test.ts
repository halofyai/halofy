import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { requiredStreamCopies } from "../console/login-stream.js";

const LOGIN_HTML = readFileSync(
  fileURLToPath(new URL("../console/login.html", import.meta.url)),
  "utf8",
);
const APP_CSS = readFileSync(
  fileURLToPath(new URL("../console/app.css", import.meta.url)),
  "utf8",
);

describe("login integration stream", () => {
  it("keeps a full lane covered after advancing by one icon sequence", () => {
    const viewports = [760, 1150, 2300, 3070];
    const sequenceWidths = [770, 792];

    for (const viewportWidth of viewports) {
      for (const sequenceWidth of sequenceWidths) {
        const copies = requiredStreamCopies(viewportWidth, sequenceWidth);

        expect(copies).toBeGreaterThanOrEqual(2);
        expect((copies - 1) * sequenceWidth).toBeGreaterThanOrEqual(viewportWidth);
      }
    }
  });

  it("loads the responsive stream filler and animates by one measured sequence", () => {
    expect(LOGIN_HTML).toContain(
      '<script type="module" src="login-stream.js"></script>',
    );
    expect(APP_CSS).toContain(
      "@keyframes auth-stream-run{to{transform:translateX(var(--auth-stream-shift,-50%))}}",
    );
  });
});
