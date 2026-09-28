/* AGENTS-HQ shared HUD.
   One place for: platform status polling, theme, sidebar collapse, the command
   palette, and toasts. Loaded once from base.html; every page relies on it. */
(function () {
  "use strict";

  var SERVICES = ["tor", "vpn", "proxy"];
  var MOBILE = "(max-width: 900px)";

  /* ---- theme ---- */
  function currentTheme() {
    var a = document.documentElement.dataset.theme;
    if (a) return a;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function syncThemeIcons(t) {
    var href = t === "dark" ? "#i-moon" : "#i-sun";
    document.querySelectorAll("[data-theme-icon]").forEach(function (u) { u.setAttribute("href", href); });
  }
  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    syncThemeIcons(t);
  }
  function toggleTheme() {
    var next = currentTheme() === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("ahq-theme", next); } catch (e) {}
    window.dispatchEvent(new CustomEvent("themechange", { detail: { theme: next } }));
  }
  // theme is set pre-paint by an inline snippet in base.html; here we only sync icons
  syncThemeIcons(currentTheme());

  /* ---- sidebar ---- */
  var layout = null;
  function isMobile() { return window.matchMedia(MOBILE).matches; }
  function restoreSidebar() {
    if (!layout || isMobile()) return;
    var collapsed = false;
    try { collapsed = localStorage.getItem("ahq-sidebar") === "collapsed"; } catch (e) {}
    layout.classList.toggle("sidebar-collapsed", collapsed);
  }
  function toggleSidebar() {
    if (!layout) return;
    if (isMobile()) {
      layout.classList.toggle("sidebar-open");
      return;
    }
    var collapsed = layout.classList.toggle("sidebar-collapsed");
    try { localStorage.setItem("ahq-sidebar", collapsed ? "collapsed" : "open"); } catch (e) {}
  }

  /* ---- toast ---- */
  function toast(msg, kind) {
    var c = document.getElementById("toast-container");
    if (!c) return;
    var t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : "");
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function () { t.remove(); }, 3200);
  }

  /* ---- data fetch + empty/error states (shared by every page) ---- */
  function escText(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  // fetch JSON with real HTTP-status handling: fetch() does not reject on 4xx/5xx,
  // so callers that skipped this were parsing error bodies as data. On 401 the
  // session has expired, so send the user back to the login page.
  async function fetchJSON(url, opts) {
    var res = await fetch(url, opts);
    if (res.status === 401) { window.location.href = "/login"; throw new Error("Session expired"); }
    if (!res.ok) {
      var detail = "";
      try { var body = await res.json(); detail = body && body.detail; } catch (e) {}
      throw new Error(detail || ("Request failed (" + res.status + ")"));
    }
    return res.json();
  }
  // Render one consistent empty/error block into a container. Pass opts.colspan
  // for a <tbody> target, opts.error for the error styling, opts.hint for a
  // secondary line. Returns the markup so callers can compose it themselves.
  function emptyState(target, message, opts) {
    opts = opts || {};
    var el = typeof target === "string" ? document.getElementById(target) : target;
    var cls = "empty-state" + (opts.error ? " is-error" : "");
    var hint = opts.hint ? '<div class="empty-hint">' + escText(opts.hint) + "</div>" : "";
    var block = '<div class="' + cls + '"><div class="empty-msg">' + escText(message) + "</div>" + hint + "</div>";
    if (el) {
      el.innerHTML = opts.colspan
        ? '<tr><td colspan="' + opts.colspan + '">' + block + "</td></tr>"
        : block;
    }
    return block;
  }

  /* ---- status polling (single source of truth) ---- */
  function setDot(el, state) {
    if (!el) return;
    el.className = el.className.replace(/\b(online|running)\b/g, "").replace(/\s+/g, " ").trim();
    if (state) el.className += " " + state;
  }
  function updateService(svc, up) {
    var state = up ? "online" : "";
    ["health-" + svc, "hb-" + svc].forEach(function (id) { setDot(document.getElementById(id), state); });
    document.querySelectorAll('[data-health="' + svc + '"]').forEach(function (el) { setDot(el, state); });
  }
  async function pollStatus() {
    try {
      var r = await fetch("/api/status");
      var d = await r.json();
      SERVICES.forEach(function (s) { updateService(s, !!d[s]); });
      var agents = d.agents || {};
      var active = Object.values(agents).filter(function (s) { return s === "online" || s === "running"; }).length;
      var count = document.getElementById("sidebar-agent-count");
      if (count) count.textContent = active + "/10";
      var stamp = document.getElementById("health-updated");
      if (stamp) stamp.textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (e) {}
  }
  async function pollCritical() {
    try {
      var r = await fetch("/api/reports");
      var reports = await r.json();
      var crit = reports.reduce(function (s, x) { return s + ((x.priority_counts && x.priority_counts.CRITICAL) || 0); }, 0);
      // The critical KPI tile is owned by the dashboard (/api/metrics); hud keeps
      // the nav badge and the topbar alert banner.
      var badge = document.getElementById("nav-badge-critical");
      if (badge) { badge.textContent = crit; badge.style.display = crit > 0 ? "" : "none"; }
      var banner = document.getElementById("alert-banner");
      var acount = document.getElementById("alert-count");
      if (acount) acount.textContent = crit + " CRITICAL";
      if (banner) banner.classList.toggle("visible", crit > 0);
    } catch (e) {}
  }

  /* ---- command palette ---- */
  var pal = { root: null, input: null, list: null, items: [], filtered: [], sel: 0 };
  function collectItems() {
    var items = [];
    document.querySelectorAll("#sidebar .nav-item[href]").forEach(function (a) {
      var label = (a.getAttribute("data-label") || a.textContent || "").trim().replace(/\s+/g, " ");
      var group = a.getAttribute("data-group") || "Navigate";
      var icon = a.getAttribute("data-icon") || "i-dashboard";
      if (label) items.push({ label: label, group: group, icon: icon, href: a.getAttribute("href") });
    });
    items.push({ label: "Run an agent", group: "Action", icon: "i-agents", href: "/agents" });
    items.push({ label: "New batch scan", group: "Action", icon: "i-batch", href: "/batch" });
    return items;
  }
  function buildPalette() {
    var ov = document.createElement("div");
    ov.className = "palette-overlay";
    ov.id = "hud-palette";
    ov.innerHTML =
      '<div class="palette" role="dialog" aria-label="Command palette">' +
      '<input class="palette-input" id="hud-pal-input" placeholder="Jump to a page or run an action" autocomplete="off" spellcheck="false">' +
      '<div class="palette-list" id="hud-pal-list"></div>' +
      '<div class="palette-foot"><span>up / down navigate</span><span>enter open</span><span>esc close</span></div>' +
      '</div>';
    document.body.appendChild(ov);
    ov.addEventListener("click", function (e) { if (e.target === ov) closePalette(); });
    pal.root = ov;
    pal.input = ov.querySelector("#hud-pal-input");
    pal.list = ov.querySelector("#hud-pal-list");
    pal.input.addEventListener("input", function () { filterPalette(pal.input.value); });
    pal.input.addEventListener("keydown", onPaletteKey);
  }
  function openPalette() {
    if (!pal.root) buildPalette();
    pal.items = collectItems();
    pal.filtered = pal.items.slice();
    pal.sel = 0;
    pal.input.value = "";
    renderPalette();
    pal.root.classList.add("open");
    pal.input.focus();
  }
  function closePalette() { if (pal.root) pal.root.classList.remove("open"); }
  function filterPalette(q) {
    q = (q || "").toLowerCase();
    pal.filtered = pal.items.filter(function (it) {
      return it.label.toLowerCase().indexOf(q) > -1 || it.group.toLowerCase().indexOf(q) > -1;
    });
    pal.sel = 0;
    renderPalette();
  }
  function renderPalette() {
    if (!pal.filtered.length) { pal.list.innerHTML = '<div class="palette-item">No matches</div>'; return; }
    pal.list.innerHTML = pal.filtered.map(function (it, i) {
      return '<div class="palette-item' + (i === pal.sel ? " sel" : "") + '" data-i="' + i + '">' +
        '<svg><use href="#' + it.icon + '"/></svg>' + it.label +
        '<span class="grp">' + it.group + "</span></div>";
    }).join("");
    Array.prototype.forEach.call(pal.list.children, function (c) {
      if (!c.dataset.i) return;
      c.addEventListener("mousemove", function () { pal.sel = +c.dataset.i; renderPalette(); });
      c.addEventListener("click", choosePalette);
    });
  }
  function onPaletteKey(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); pal.sel = Math.min(pal.sel + 1, pal.filtered.length - 1); renderPalette(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); pal.sel = Math.max(pal.sel - 1, 0); renderPalette(); }
    else if (e.key === "Enter") { e.preventDefault(); choosePalette(); }
    else if (e.key === "Escape") { closePalette(); }
  }
  function choosePalette() {
    var it = pal.filtered[pal.sel];
    if (it && it.href) window.location.href = it.href;
  }

  /* ---- wiring ---- */
  function ready() {
    layout = document.getElementById("layout");
    restoreSidebar();

    var themeBtns = document.querySelectorAll("[data-action='theme']");
    themeBtns.forEach(function (b) { b.addEventListener("click", toggleTheme); });

    var sideBtns = document.querySelectorAll("[data-action='sidebar']");
    sideBtns.forEach(function (b) { b.addEventListener("click", toggleSidebar); });

    var palBtns = document.querySelectorAll("[data-action='palette']");
    palBtns.forEach(function (b) { b.addEventListener("click", openPalette); });

    var scrim = document.getElementById("sidebar-scrim");
    if (scrim) scrim.addEventListener("click", function () { if (layout) layout.classList.remove("sidebar-open"); });

    document.addEventListener("keydown", function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    });

    pollStatus();
    pollCritical();
    setInterval(pollStatus, 15000);
    setInterval(pollCritical, 30000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready);
  else ready();

  window.HUD = {
    toast: toast, toggleTheme: toggleTheme, openPalette: openPalette, currentTheme: currentTheme,
    fetchJSON: fetchJSON, emptyState: emptyState, esc: escText,
  };
})();
