export const MAX_CHANGE_RECORDS = 25;
export const MAX_CHANGE_DELETIONS = 500;

/**
 * HTTP Date is second-granular, so use the midpoint of the request window to
 * keep network latency from becoming clock error. Invalid/missing evidence
 * preserves the local-clock behavior instead of blocking offline/self-hosted
 * users whose server does not emit Date.
 */
export function serverClockOffsetMs(
  serverDate: string | undefined,
  clientStartedAt: number,
  clientFinishedAt: number,
): number {
  const serverTime = serverDate ? Date.parse(serverDate) : Number.NaN;
  if (!Number.isFinite(serverTime) || !Number.isFinite(clientStartedAt) ||
      !Number.isFinite(clientFinishedAt) || clientFinishedAt < clientStartedAt) {
    return 0;
  }
  return Math.round(serverTime - ((clientStartedAt + clientFinishedAt) / 2));
}

export function serverTimestampMs(localNow: number, clockOffsetMs: number): number {
  const adjusted = Math.round(localNow + clockOffsetMs);
  return Number.isSafeInteger(adjusted) ? adjusted : Math.round(localNow);
}

function under(path: string, folder: string): boolean {
  return path === folder || path.startsWith(`${folder}/`);
}

export function isAllowedMarkdownPath(
  path: string,
  configDir: string,
  includedFolders: readonly string[],
  excludedFolders: readonly string[],
): boolean {
  if (!path.toLowerCase().endsWith(".md") ||
      path.split("/").some((part) => part.startsWith(".")) ||
      (configDir && under(path, configDir))) {
    return false;
  }
  if (includedFolders.length > 0 &&
      !includedFolders.some((folder) => under(path, folder))) return false;
  return !excludedFolders.some((folder) => under(path, folder));
}

export function batchChanges<T>(
  records: readonly T[],
  deleted: readonly string[],
): Array<{ records: T[]; deleted: string[] }> {
  const batches: Array<{ records: T[]; deleted: string[] }> = [];
  let recordOffset = 0;
  let deletionOffset = 0;
  while (recordOffset < records.length || deletionOffset < deleted.length) {
    batches.push({
      records: records.slice(recordOffset, recordOffset + MAX_CHANGE_RECORDS),
      deleted: deleted.slice(deletionOffset, deletionOffset + MAX_CHANGE_DELETIONS),
    });
    recordOffset += MAX_CHANGE_RECORDS;
    deletionOffset += MAX_CHANGE_DELETIONS;
  }
  return batches;
}
