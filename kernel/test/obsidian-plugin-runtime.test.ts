import { describe, expect, it } from "vitest";

import {
  batchChanges,
  isAllowedMarkdownPath,
  serverClockOffsetMs,
  serverTimestampMs,
} from "../integrations/halomem-sync/src/sync-policy.js";

describe("HaloMem Sync Obsidian runtime policy", () => {
  it("excludes a custom Obsidian configuration directory and all descendants", () => {
    expect(isAllowedMarkdownPath("Notes/Visible.md", "config", [], [])).toBe(true);
    expect(isAllowedMarkdownPath("config/Plugins/state.md", "config", [], [])).toBe(false);
    expect(isAllowedMarkdownPath("config.md", "config", [], [])).toBe(true);
  });

  it("batches records and deletions independently without overlap", () => {
    const records = Array.from({ length: 26 }, (_, index) => ({ path: `Note-${index}.md` }));
    const deleted = Array.from({ length: 501 }, (_, index) => `Deleted-${index}.md`);

    const batches = batchChanges(records, deleted);

    expect(batches).toHaveLength(2);
    expect(batches.map((batch) => batch.records.length)).toEqual([25, 1]);
    expect(batches.map((batch) => batch.deleted.length)).toEqual([500, 1]);
    expect(batches.flatMap((batch) => batch.deleted)).toEqual(deleted);
  });

  it("does not create a change batch when there is no work", () => {
    expect(batchChanges([], [])).toEqual([]);
  });

  it("signs with server time when the Windows clock is behind", () => {
    const clientStartedAt = Date.parse("2026-08-13T04:45:45.000Z");
    const clientFinishedAt = clientStartedAt + 200;
    const offset = serverClockOffsetMs(
      "Thu, 13 Aug 2026 10:15:45 GMT",
      clientStartedAt,
      clientFinishedAt,
    );

    expect(offset).toBe(19_799_900);
    expect(serverTimestampMs(clientFinishedAt + 1_000, offset)).toBe(
      Date.parse("2026-08-13T10:15:46.100Z"),
    );
  });

  it("falls back to the local clock when the server Date header is unavailable", () => {
    expect(serverClockOffsetMs(undefined, 1_000, 1_200)).toBe(0);
    expect(serverClockOffsetMs("not-a-date", 1_000, 1_200)).toBe(0);
    expect(serverTimestampMs(1_300, 0)).toBe(1_300);
  });
});
