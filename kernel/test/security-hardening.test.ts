import { describe, expect, it } from "vitest";

import { parseCookies } from "../src/http/console.js";
import {
  trimRepeatedCharacter,
  trimTrailingRepeatedCharacter,
} from "../src/strings.js";

describe("security hardening helpers", () => {
  it("trims repeated edge characters in linear scans", () => {
    expect(trimRepeatedCharacter("---audit---", "-")).toBe("audit");
    expect(trimTrailingRepeatedCharacter("https://halofy.test///", "/")).toBe(
      "https://halofy.test",
    );
  });

  it("ignores property-injection cookie names and keeps later duplicates", () => {
    const cookies = parseCookies(
      "__proto__=polluted; constructor=bad; session=old; session=new",
    );

    expect(cookies).toEqual({ session: "new" });
    expect(Object.getPrototypeOf(cookies)).toBe(Object.prototype);
  });
});
