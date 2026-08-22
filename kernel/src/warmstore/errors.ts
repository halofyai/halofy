/** A warm store (or its sidecar) cannot serve mirror ops right now. */
export class WarmStoreUnavailableError extends Error {
  constructor(
    public readonly store: string,
    message?: string,
    options?: { cause?: unknown },
  ) {
    super(message ?? `warm store "${store}" is unavailable`, options);
    this.name = "WarmStoreUnavailableError";
  }
}
