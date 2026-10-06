/* Highlight the current sidebar link based on the URL path. */
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

  // Legacy top nav links (kept for the vulnerable app)
  document.querySelectorAll(".app-bar__link").forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;
    if (href === "/" ? path === "/" : path.startsWith(href)) {
      link.setAttribute("aria-current", "page");
    }
  });
});