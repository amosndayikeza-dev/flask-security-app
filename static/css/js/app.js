/* CYBERLAB — sidebar active link + terminal touches */
document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;

  // Sidebar links
  document.querySelectorAll(".sidebar__link").forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;
    if (href === "/" ? path === "/" : path.startsWith(href)) {
      link.setAttribute("aria-current", "page");
    }
  });

  // Legacy top nav (kept for compatibility)
  document.querySelectorAll(".app-bar__link").forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;
    if (href === "/" ? path === "/" : path.startsWith(href)) {
      link.setAttribute("aria-current", "page");
    }
  });

  // Subtle "terminal boot" log in the console
  console.log(
    "%c[ CYBERLAB ]%c security lab initialised — mode: %c%s",
    "color:#00e5ff;font-weight:bold;",
    "color:#7f95a5;",
    "color:#ff3b5c;font-weight:bold;",
    document.body.className || "default"
  );
});
