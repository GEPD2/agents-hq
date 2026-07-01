const LINE_COLORS = ["#7c3aed", "#22c55e", "#f97316", "#eab308", "#06b6d4", "#ec4899"];
let marketChart = null;

async function loadCorrelation() {
  const tickers = document.getElementById("market-tickers").value.trim();
  const days = document.getElementById("market-days").value;
  const status = document.getElementById("market-status");
  status.textContent = "Loading…";
  try {
    const params = new URLSearchParams({ days });
    if (tickers) params.set("tickers", tickers);
    const r = await fetch(`/api/market/correlation?${params}`);
    const data = await r.json();
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
  const labels = buildDateAxis(data);
  const datasets = [];

  data.tickers.forEach((t, i) => {
    const byDate = Object.fromEntries((data.series[t] || []).map(p => [p.date, p.close]));
    datasets.push({
      label: t,
      data: labels.map(d => byDate[d] ?? null),
      borderColor: LINE_COLORS[i % LINE_COLORS.length],
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
    backgroundColor: "rgba(239,68,68,0.55)",
    borderWidth: 0,
    yAxisID: "yEvents",
  });

  if (marketChart) marketChart.destroy();
  const ctx = document.getElementById("market-chart").getContext("2d");
  marketChart = new Chart(ctx, {
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: "#e5e5e5", font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: "#6b7280", maxTicksLimit: 12 }, grid: { color: "#262626" } },
        yPrice: { position: "left", ticks: { color: "#6b7280" }, grid: { color: "#262626" },
                  title: { display: true, text: "Price ($)", color: "#6b7280" } },
        yEvents: { position: "right", beginAtZero: true, ticks: { color: "#6b7280", precision: 0 },
                   grid: { drawOnChartArea: false },
                   title: { display: true, text: "Security events", color: "#6b7280" } },
      },
    },
  });
}

function renderEvents(events) {
  const tbody = document.getElementById("market-events-tbody");
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="3"><div class="empty">No security events in range — run Agents 08/09/10</div></td></tr>';
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
