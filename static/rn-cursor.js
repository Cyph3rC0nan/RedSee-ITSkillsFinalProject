/* ============================================================
   RedSee — public-page custom cursor ("targeting reticle")
   A precise red dot at the pointer + a larger ring that trails
   with easing and locks on (expands) over interactive elements,
   echoing the radar-reticle logo. Desktop mouse only; the native
   cursor is kept for touch devices and reduced-motion users.
   ============================================================ */
(function () {
  var fine = window.matchMedia("(pointer: fine)").matches;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!fine || reduce) return;                 // native cursor: touch / reduced-motion

  var root = document.documentElement;
  var ring = document.createElement("div");
  var dot = document.createElement("div");
  ring.className = "rn-cur rn-cur-ring";
  dot.className = "rn-cur rn-cur-dot";
  ring.setAttribute("aria-hidden", "true");
  dot.setAttribute("aria-hidden", "true");
  document.body.appendChild(ring);
  document.body.appendChild(dot);
  root.classList.add("rn-cursor-on");          // hides the native cursor (CSS)

  var mx = 0, my = 0, rx = 0, ry = 0, seen = false;

  function place(el, x, y) {
    el.style.transform = "translate(" + x + "px," + y + "px) translate(-50%,-50%)";
  }

  window.addEventListener("mousemove", function (e) {
    mx = e.clientX; my = e.clientY;
    place(dot, mx, my);
    if (!seen) { seen = true; rx = mx; ry = my; ring.style.opacity = ""; dot.style.opacity = ""; root.classList.add("rn-cursor-live"); }
  }, { passive: true });

  // Ring eases toward the pointer — the trailing "lock-on" feel.
  (function loop() {
    rx += (mx - rx) * 0.18;
    ry += (my - ry) * 0.18;
    place(ring, rx, ry);
    requestAnimationFrame(loop);
  })();

  // Expand/lock-on over anything interactive.
  var HOVER = "a,button,input,textarea,select,label,[role='button'],tr," +
              ".rn-cta,.rn-cta-ghost,.rn-card,.rn-navlink,.rn-tools-list span," +
              ".nav-item,.mode-opt,.ops-table tbody tr";
  document.addEventListener("mouseover", function (e) {
    if (e.target.closest && e.target.closest(HOVER)) root.classList.add("rn-cur-hover");
  });
  document.addEventListener("mouseout", function (e) {
    if (e.target.closest && e.target.closest(HOVER)) root.classList.remove("rn-cur-hover");
  });

  // Press feedback.
  document.addEventListener("mousedown", function () { root.classList.add("rn-cur-down"); });
  document.addEventListener("mouseup", function () { root.classList.remove("rn-cur-down"); });

  // Fade out when the pointer leaves the window.
  document.addEventListener("mouseleave", function () { root.classList.remove("rn-cursor-live"); });
  document.addEventListener("mouseenter", function () { if (seen) root.classList.add("rn-cursor-live"); });
})();
