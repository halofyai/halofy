/**
 * Owns the responsive rail state without coupling it to screen routing.
 * The injected targets keep the behavior testable without a browser DOM.
 */
export function createMobileNavigation({
  body,
  rail,
  toggle,
  close,
  backdrop,
  eventTarget,
  media,
  background = [],
  defer = (callback) => setTimeout(callback, 0),
}) {
  let open = false;

  function sync() {
    const drawerOpen = media.matches && open;
    body.classList.toggle("nav-open", drawerOpen);
    toggle.setAttribute("aria-expanded", String(drawerOpen));
    toggle.setAttribute(
      "aria-label",
      drawerOpen ? "Close navigation" : "Open navigation",
    );
    rail.setAttribute("aria-hidden", String(media.matches && !drawerOpen));
    rail.inert = media.matches && !drawerOpen;
    backdrop.setAttribute("aria-hidden", String(!drawerOpen));
    for (const element of background) element.inert = drawerOpen;
  }

  function setOpen(next, { returnFocus = false } = {}) {
    open = media.matches && Boolean(next);
    sync();
    const focusTarget = open ? close : returnFocus && media.matches ? toggle : null;
    if (focusTarget) {
      defer(() => {
        const targetIsCurrent = focusTarget === close ? open : !open && media.matches;
        if (targetIsCurrent) focusTarget.focus();
      });
    }
  }

  const onToggle = () => setOpen(!open, { returnFocus: open });
  const onClose = () => setOpen(false, { returnFocus: true });
  const onKeydown = (event) => {
    if (event.key === "Escape" && open) onClose();
  };
  const onMediaChange = () => {
    open = false;
    sync();
  };

  toggle.addEventListener("click", onToggle);
  close.addEventListener("click", onClose);
  backdrop.addEventListener("click", onClose);
  eventTarget.addEventListener("keydown", onKeydown);
  media.addEventListener("change", onMediaChange);
  sync();

  return {
    close(options = {}) {
      setOpen(false, options);
    },
    destroy() {
      toggle.removeEventListener("click", onToggle);
      close.removeEventListener("click", onClose);
      backdrop.removeEventListener("click", onClose);
      eventTarget.removeEventListener("keydown", onKeydown);
      media.removeEventListener("change", onMediaChange);
    },
  };
}
