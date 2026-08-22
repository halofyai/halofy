export function requiredStreamCopies(viewportWidth, sequenceWidth) {
  const viewport = Number.isFinite(viewportWidth) ? Math.max(0, viewportWidth) : 0;
  const sequence = Number.isFinite(sequenceWidth) ? sequenceWidth : 0;
  if (sequence <= 0) return 2;
  return Math.max(2, Math.ceil(viewport / sequence) + 1);
}

function fillStreamBelt(belt) {
  const sequence = belt.querySelector(".auth-stream-set");
  const lane = belt.closest(".auth-stream-lane");
  if (!sequence || !lane) return;

  const sequenceWidth = sequence.getBoundingClientRect().width;
  const laneWidth = lane.getBoundingClientRect().width;
  if (sequenceWidth <= 0 || laneWidth <= 0) return;

  const copyCount = requiredStreamCopies(laneWidth, sequenceWidth);
  let renderedCopies = belt.querySelectorAll(":scope > .auth-stream-set").length;
  while (renderedCopies < copyCount) {
    belt.append(sequence.cloneNode(true));
    renderedCopies += 1;
  }

  belt.style.setProperty("--auth-stream-shift", `-${sequenceWidth}px`);
}

export function fillAuthStreams(root = document) {
  root.querySelectorAll(".auth-stream-belt").forEach(fillStreamBelt);
}

function startAuthStreams() {
  fillAuthStreams();

  const belts = document.querySelectorAll(".auth-stream-belt");
  if (typeof ResizeObserver === "function") {
    const observer = new ResizeObserver((entries) => {
      entries.forEach((entry) => {
        const belt = entry.target.querySelector(".auth-stream-belt");
        if (belt) fillStreamBelt(belt);
      });
    });
    belts.forEach((belt) => {
      const lane = belt.closest(".auth-stream-lane");
      if (lane) observer.observe(lane);
    });
    return;
  }

  window.addEventListener("resize", () => fillAuthStreams(), { passive: true });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startAuthStreams, { once: true });
  } else {
    startAuthStreams();
  }
}
