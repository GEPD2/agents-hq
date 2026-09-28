const AGENT_NAMES = {
  "01": "OSINT Collector", "02": "Task Researcher", "03": "RAG KB",
  "04": "Orchestrator", "05": "Red Team", "06": "Ghidra RE",
  "07": "Crypto", "08": "News Intel", "09": "Market Intel", "10": "Dark Web"
};
const AGENT_FILES = {
  "01": "OSINT_", "02": "Recon_", "06": "RE_", "08": "INTEL_", "09": "MARKET_", "10": "DARKWEB_"
};

let statusInterval = null;

// Platform dots, sidebar count, alert banner, and critical badge are owned by
// hud.js. This page only fetches /api/status to render its own agent grid.
async function fetchStatus() {
  try {
    const data = await HUD.fetchJSON("/api/status");
    updateAgentGrid(data.agents);
  } catch(e) { console.error("status fetch failed", e); }
}

function updateAgentGrid(agents) {
  const grid = document.getElementById("agent-grid");
  if (!grid) return;
  grid.innerHTML = "";
  Object.entries(agents).forEach(([id, status]) => {
    const name = AGENT_NAMES[id] || `Agent-${id}`;
    const card = document.createElement("div");
    card.className = "agent-card";
    const dotClass = status === "online" ? "online" : status === "running" ? "running" : status === "n/a" ? "na" : "offline";
    card.innerHTML = `
      <div class="agent-card-header">
        <span class="agent-id">${id}</span>
        <span class="agent-name">${name}</span>
        <span class="agent-status-dot ${dotClass}" title="${status}"></span>
      </div>
      <div class="agent-meta">
        <span class="${dotClass === 'online' ? 'text-low' : dotClass === 'running' ? 'text-medium' : 'text-muted'}">${status}</span>
      </div>
    `;
    card.addEventListener("click", () => { window.location.href = "/agents"; });
    grid.appendChild(card);
  });
}

let _lastReports = [];

async function fetchReports() {
  try {
    const reports = await HUD.fetchJSON("/api/reports");
    _lastReports = reports;
    renderActivityFeed(reports.slice(0, 20));
    renderCharts(reports);
    // Compact timeline strip
    if (typeof renderTimeline === "function") {
      _tlReports = reports.filter(r => r.created);
      renderTimeline("dash-timeline", true);
    }
  } catch(e) { console.error("reports fetch failed", e); }
}

function renderActivityFeed(reports) {
  const feed = document.getElementById("activity-feed");
  if (!feed) return;
  if (!reports.length) {
    HUD.emptyState(feed, "No reports yet", { hint: "Run an agent to generate reports." });
    return;
  }
  feed.innerHTML = reports.map(r => {
    const agentBadge = r.agent !== "unknown" ? r.agent : "?";
    const ts = r.created ? new Date(r.created).toLocaleString() : "";
    const critCount = r.priority_counts?.CRITICAL || 0;
    const badge = critCount > 0 ? `<span class="badge badge-critical">${critCount} CRIT</span>` : "";
    return `
      <div class="feed-item">
        <span class="feed-agent-badge">${agentBadge}</span>
        <a href="/reports/${encodeURIComponent(r.filename)}" class="feed-filename truncate" title="${r.filename}">${r.filename}</a>
        ${badge}
        <span class="feed-time">${ts}</span>
      </div>
    `;
  }).join("");
}

// KPI tiles: value + delta vs the previous daily snapshot + a sparkline of the
// recent series, from the real /api/metrics time-series.
let _lastMetrics = null;

async function fetchMetrics() {
  try {
    _lastMetrics = await HUD.fetchJSON("/api/metrics");
    renderMetrics();
  } catch(e) {}
}

function sparkline(series) {
  if (!series || series.length < 2) return "";
  const w = 60, h = 18, n = series.length;
  const min = Math.min(...series), max = Math.max(...series);
  const span = (max - min) || 1;
  const pts = series.map((v, i) => {
    const x = (i / (n - 1)) * w;
    const y = h - ((v - min) / span) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const stroke = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`
    + `<polyline points="${pts}" fill="none" stroke="${stroke}" stroke-width="1.5"/></svg>`;
}

function renderMetrics() {
  if (!_lastMetrics) return;
  const tiles = _lastMetrics.tiles || {};
  document.querySelectorAll(".stat-card[data-metric]").forEach(card => {
    const m = tiles[card.dataset.metric];
    if (!m) return;
    card.querySelector(".stat-value").textContent = m.value;
    const d = card.querySelector(".stat-delta");
    if (d) {
      if (m.delta > 0)      { d.className = "stat-delta up";   d.textContent = "+" + m.delta; }
      else if (m.delta < 0) { d.className = "stat-delta down"; d.textContent = m.delta; }
      else                  { d.className = "stat-delta flat"; d.textContent = "no change"; }
    }
    const s = card.querySelector(".stat-spark");
    if (s) s.innerHTML = sparkline(m.series);
  });
}

// Live findings stream (SSE). Initial paint via /api/activity/recent, then an
// EventSource pushes new findings as agents run and IOCs are ingested. The feed
// keeps the newest FINDINGS_MAX on top and dedups by finding id.
const FINDINGS_MAX = 50;
const _findingsSeen = new Set();
let _findingsEvt = null;

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function findingRow(f) {
  const agent = f.agent && f.agent !== "unknown" ? f.agent : "?";
  const ts = f.ts ? new Date(f.ts).toLocaleTimeString() : "";
  let body;
  if (f.kind === "ioc") {
    const t = String(f.ioc_type || "").toLowerCase();
    const pivot = `/pivot/${encodeURIComponent(t)}/${encodeURIComponent(f.value)}`;
    body = `<span class="ioc-tag ioc-${escapeHtml(t)}">${escapeHtml(t)}</span>`
         + `<a class="finding-value truncate" href="${pivot}" title="${escapeHtml(f.value)}">${escapeHtml(f.value)}</a>`;
  } else {
    const sev = f.severity
      ? `<span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity).toUpperCase()}</span>`
      : "";
    body = `<span class="finding-kind">report</span>`
         + `<a class="finding-value truncate" href="/reports/${encodeURIComponent(f.value)}" title="${escapeHtml(f.value)}">${escapeHtml(f.value)}</a>${sev}`;
  }
  return `<div class="finding-item finding-new" data-fid="${escapeHtml(f.id)}">`
       + `<span class="feed-agent-badge">${escapeHtml(agent)}</span>${body}`
       + `<span class="feed-time">${escapeHtml(ts)}</span></div>`;
}

function pushFinding(f, animate) {
  const box = document.getElementById("findings-stream");
  if (!box || !f || !f.id || _findingsSeen.has(f.id)) return;
  _findingsSeen.add(f.id);
  const placeholder = box.querySelector(".empty, .empty-state");
  if (placeholder) box.innerHTML = "";
  box.insertAdjacentHTML("afterbegin", findingRow(f));
  if (!animate) {
    const first = box.firstElementChild;
    if (first) first.classList.remove("finding-new");
  }
  while (box.children.length > FINDINGS_MAX) box.removeChild(box.lastElementChild);
}

function setFindingsStatus(state) {
  const el = document.getElementById("findings-status");
  if (!el) return;
  el.dataset.state = state;
  const label = el.querySelector(".live-label");
  if (label) label.textContent = state;
}

async function paintFindings() {
  const box = document.getElementById("findings-stream");
  try {
    const data = await HUD.fetchJSON("/api/activity/recent?limit=30");
    const items = data.findings || [];
    if (box) box.innerHTML = "";
    if (!items.length) {
      if (box) HUD.emptyState(box, "No findings yet", { hint: "Findings appear as agents run and reports are ingested." });
      return;
    }
    // oldest first so the newest finding ends up on top after each prepend
    items.slice().reverse().forEach(f => pushFinding(f, false));
  } catch(e) {
    if (box && !box.children.length) HUD.emptyState(box, "Findings unavailable", { error: true });
  }
}

function connectFindings() {
  if (!window.EventSource) { setFindingsStatus("off"); return; }
  try {
    _findingsEvt = new EventSource("/api/activity/stream");
  } catch(e) {
    setFindingsStatus("off");
    return;
  }
  _findingsEvt.onopen = () => setFindingsStatus("live");
  _findingsEvt.onmessage = (ev) => {
    const d = ev.data;
    if (!d || d === "[HEARTBEAT]" || d === "[DONE]") return;
    if (d === "[READY]") { setFindingsStatus("live"); return; }
    try { pushFinding(JSON.parse(d), true); } catch(e) {}
  };
  // EventSource reconnects on its own; just reflect the state.
  _findingsEvt.onerror = () => setFindingsStatus("reconnecting");
}

window.addEventListener("beforeunload", () => { if (_findingsEvt) _findingsEvt.close(); });

let _chartByAgent = null;
let _chartPriority = null;

function renderCharts(reports) {
  if (typeof Chart === "undefined") return;

  const agentLabels = {"01":"OSINT","02":"Recon","06":"RE","08":"Intel","09":"Market","10":"DarkWeb","unknown":"Other"};
  const agentCounts = {};
  const priorityTotals = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};

  reports.forEach(r => {
    const label = agentLabels[r.agent] || r.agent;
    agentCounts[label] = (agentCounts[label] || 0) + 1;
    const pc = r.priority_counts || {};
    Object.keys(priorityTotals).forEach(k => { priorityTotals[k] += pc[k] || 0; });
  });

  const grid = ChartTheme.color("--border");
  const tick = ChartTheme.color("--muted");
  const sev = ChartTheme.severity();

  const ctx1 = document.getElementById("chart-by-agent");
  if (ctx1) {
    if (_chartByAgent) _chartByAgent.destroy();
    _chartByAgent = new Chart(ctx1, {
      type: "bar",
      data: {
        labels: Object.keys(agentCounts),
        datasets: [{ label: "Reports", data: Object.values(agentCounts),
          backgroundColor: ChartTheme.color("--accent"), borderRadius: 4 }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: tick }, grid: { color: grid } },
          y: { ticks: { color: tick }, grid: { color: grid }, beginAtZero: true }
        }
      }
    });
  }

  const ctx2 = document.getElementById("chart-priority");
  if (ctx2) {
    if (_chartPriority) _chartPriority.destroy();
    _chartPriority = new Chart(ctx2, {
      type: "doughnut",
      data: {
        labels: ["CRITICAL","HIGH","MEDIUM","LOW"],
        datasets: [{ data: Object.values(priorityTotals),
          backgroundColor: [sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW],
          borderWidth: 0 }]
      },
      options: { plugins: { legend: { labels: { color: ChartTheme.color("--text") } } } }
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  fetchStatus();
  fetchReports();
  fetchMetrics();
  paintFindings().then(connectFindings);
  statusInterval = setInterval(fetchStatus, 15000);
  setInterval(fetchReports, 30000);
  setInterval(fetchMetrics, 60000);
});

// Recolor charts + sparklines when the theme changes.
window.addEventListener("themechange", () => {
  if (_lastReports.length) renderCharts(_lastReports);
  renderMetrics();
});
