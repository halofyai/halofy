function navigationLabel(value) {
  return String(value || "")
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'");
}

/** Build a role-safe breadcrumb trail from the same model as the console rail. */
export function buildBreadcrumbTrail({
  navigation,
  allowedScreens,
  screenId,
  tail = [],
}) {
  const groups = Array.isArray(navigation) ? navigation : [];
  const allowed = allowedScreens instanceof Set ? allowedScreens : new Set();
  const group = groups.find((candidate) =>
    Array.isArray(candidate.items) && candidate.items.some((item) => item.s === screenId),
  );
  const item = allowed.has(screenId) && group
    ? group.items.find((candidate) => candidate.s === screenId)
    : null;
  const nested = tail
    .map((segment) => typeof segment === "string" ? { label: segment } : segment)
    .filter((segment) => segment && String(segment.label || "").trim());

  const trail = [];
  const home = allowed.has("s2")
    ? groups.flatMap((candidate) => candidate.items || []).find((candidate) => candidate.s === "s2")
    : null;
  if (home) {
    trail.push({ label: navigationLabel(home.label), screenId: home.s, home: true });
  }
  if (item && item.s !== home?.s) {
    trail.push({ label: navigationLabel(item.label), screenId: item.s });
  } else if (item && trail.length === 0) {
    trail.push({ label: navigationLabel(item.label), screenId: item.s, home: item.s === "s2" });
  }
  return trail.concat(nested);
}

/** Render escaped, keyboard-accessible breadcrumb markup. */
export function breadcrumbMarkup(trail, esc) {
  const segments = Array.isArray(trail) ? trail : [];
  if (segments.length === 0) return "";
  const escape = typeof esc === "function" ? esc : String;
  const items = segments.map((segment, index) => {
    const current = index === segments.length - 1;
    const label = escape(String(segment.label || ""));
    const homeClass = segment.home ? " breadcrumb-home" : "";
    const visibleLabel = segment.home
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m4 11 8-7 8 7"/><path d="M6.5 9.5V20h11V9.5M10 20v-6h4v6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>' + label + "</span>"
      : label;
    const target = /^s\d+$/.test(String(segment.screenId || ""))
      ? String(segment.screenId)
      : null;
    const content = current
      ? `<span class="breadcrumb-current${homeClass}" aria-current="page">${visibleLabel}</span>`
      : target
        ? `<button${homeClass ? ` class="${homeClass.trim()}"` : ""} type="button" data-breadcrumb-screen="${escape(target)}">${visibleLabel}</button>`
        : `<span${homeClass ? ` class="${homeClass.trim()}"` : ""}>${visibleLabel}</span>`;
    const separator = index === 0
      ? ""
      : '<span class="breadcrumb-separator" aria-hidden="true">/</span>';
    return `<li>${separator}${content}</li>`;
  }).join("");
  return `<ol>${items}</ol>`;
}
