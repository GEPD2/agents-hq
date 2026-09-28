/* Chart.js theming from design tokens.
   Load after Chart.js and before any page chart script. Sets global defaults
   from the current theme and re-applies them when the theme changes. Pages read
   colors via ChartTheme.color()/palette() and re-render on the themechange event. */
(function () {
  "use strict";

  function color(token) {
    return getComputedStyle(document.documentElement).getPropertyValue(token).trim();
  }

  function palette() {
    // Categorical series colors, accent-led, distinct in both themes.
    return [
      color("--accent"), color("--ioc-ip"), color("--low"), color("--high"),
      color("--ioc-email"), color("--ioc-domain"), color("--medium"), color("--ioc-hash")
    ];
  }

  function severity() {
    return {
      CRITICAL: color("--critical"), HIGH: color("--high"),
      MEDIUM: color("--medium"), LOW: color("--low")
    };
  }

  function applyDefaults() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.font.family = "JetBrains Mono, ui-monospace, Menlo, monospace";
    Chart.defaults.font.size = 11;
    Chart.defaults.color = color("--text-2");
    Chart.defaults.borderColor = color("--border");
    if (Chart.defaults.scale && Chart.defaults.scale.grid) {
      Chart.defaults.scale.grid.color = color("--border");
    }
    if (Chart.defaults.plugins && Chart.defaults.plugins.tooltip) {
      var tt = Chart.defaults.plugins.tooltip;
      tt.backgroundColor = color("--surface-3");
      tt.titleColor = color("--text");
      tt.bodyColor = color("--text-2");
      tt.borderColor = color("--border-strong");
      tt.borderWidth = 1;
    }
  }

  applyDefaults();
  window.addEventListener("themechange", applyDefaults);

  window.ChartTheme = { color: color, palette: palette, severity: severity, applyDefaults: applyDefaults };
})();
