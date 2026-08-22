// Shared helpers for the HaloMem Claude Code hooks.
//
// Brownout, never hard-fail (kernel non-negotiable #5): a hook that cannot
// reach the kernel exits 0 with no output — the agent session keeps running.

export function readConfig() {
  const url = (process.env.HALOMEM_URL || "").replace(/\/+$/, "");
  const key = process.env.HALOMEM_API_KEY || "";
  if (!url || !key) return null;
  return { url, key };
}

export function readStdinJson() {
  return new Promise((resolve) => {
    let raw = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      raw += chunk;
    });
    process.stdin.on("end", () => {
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
    process.stdin.on("error", () => resolve({}));
  });
}

/** POST a kernel syscall; resolves null on any failure (timeout 8s). */
export async function syscall(config, route, body) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(config.url + route, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + config.key,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}
