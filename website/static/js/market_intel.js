function lineColors() { return ChartTheme.palette(); }
let marketChart = null;
let _lastData = null;

async function loadCorrelation() {
  const tickers = document.getElementById("market-tickers").value.trim();
  const days = document.getElementById("market-days").value;
  const status = document.getElementById("market-status");
  status.textContent = "Loading…";
  try {
    const params = new URLSearchParams({ days });
    if (tickers) params.set("tickers", tickers);
    const data = await HUD.fetchJSON(`/api/market/correlation?${params}`);
    renderChart(data);
    renderEvents(data.events);
    const hasPrices = Object.values(data.series).some(s => s.length);
    status.textContent = hasPrices ? `${data.tickers.join(", ")} · ${data.events.length} events`
                                   : "No price data (Yahoo unreachable or invalid tickers)";
  } catch (e) {
    status.textContent = "Error: " + e.message;
  }
}

function buildDateAxis(data) {
  const dates = new Set();
  Object.values(data.series).forEach(s => s.forEach(p => dates.add(p.date)));
  data.event_counts.forEach(e => dates.add(e.date));
  return Array.from(dates).sort();
}

function renderChart(data) {
  _lastData = data;
  const labels = buildDateAxis(data);
  const datasets = [];
  const colors = lineColors();

  data.tickers.forEach((t, i) => {
    const byDate = Object.fromEntries((data.series[t] || []).map(p => [p.date, p.close]));
    datasets.push({
      label: t,
      data: labels.map(d => byDate[d] ?? null),
      borderColor: colors[i % colors.length],
      backgroundColor: "transparent",
      borderWidth: 2, pointRadius: 0, spanGaps: true, tension: 0.2,
      yAxisID: "yPrice",
    });
  });

  const countByDate = Object.fromEntries(data.event_counts.map(e => [e.date, e.count]));
  datasets.push({
    label: "Security events",
    type: "bar",
    data: labels.map(d => countByDate[d] ?? 0),
    backgroundColor: ChartTheme.color("--critical"),
    borderWidth: 0,
    yAxisID: "yEvents",
  });

  const grid = ChartTheme.color("--border");
  const tick = ChartTheme.color("--muted");
  const legend = ChartTheme.color("--text");

  if (marketChart) marketChart.destroy();
  const ctx = document.getElementById("market-chart").getContext("2d");
  marketChart = new Chart(ctx, {
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: legend, font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: tick, maxTicksLimit: 12 }, grid: { color: grid } },
        yPrice: { position: "left", ticks: { color: tick }, grid: { color: grid },
                  title: { display: true, text: "Price ($)", color: tick } },
        yEvents: { position: "right", beginAtZero: true, ticks: { color: tick, precision: 0 },
                   grid: { drawOnChartArea: false },
                   title: { display: true, text: "Security events", color: tick } },
      },
    },
  });
}

function renderEvents(events) {
  const tbody = document.getElementById("market-events-tbody");
  if (!events.length) {
    HUD.emptyState("market-events-tbody", "No security events in range", { colspan: 3, hint: "Run Agents 08/09/10." });
    return;
  }
  const sorted = events.slice().sort((a, b) => b.date.localeCompare(a.date));
  tbody.innerHTML = sorted.map(e => {
    const cls = e.type === "cve" ? "ioc-cve" : "ioc-ip";
    return `<tr>
      <td class="text-muted" style="font-size:11px">${e.date}</td>
      <td><span class="ioc-tag ${cls}">${e.type}</span></td>
      <td style="font-family:monospace;font-size:11px">${escHtml(e.label)}</td>
    </tr>`;
  }).join("");
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", loadCorrelation);
window.addEventListener("themechange", () => { if (_lastData) renderChart(_lastData); });
