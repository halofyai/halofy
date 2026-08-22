/**
 * Render descriptive heading copy as an accessible info tooltip.
 * Callers pass already-escaped strings, matching the console UI helper contract.
 */
export function headingInfo(label, detail) {
  if (!detail) return "";
  return (
    '<span class="heading-info" role="note" tabindex="0" aria-label="' +
    (label ?? "More information") +
    ": " +
    detail +
    '" data-tip="' +
    detail +
    '"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><circle cx="8" cy="8" r="5.7"/><path d="M8 7.2v3.3M8 5.1h.01" stroke-linecap="round"/></svg></span>'
  );
}
