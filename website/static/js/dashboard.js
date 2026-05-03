const AGENT_NAMES = {
  "01": "OSINT Collector", "02": "Task Researcher", "03": "RAG KB",
  "04": "Orchestrator", "05": "Red Team", "06": "Ghidra RE",
  "07": "Crypto", "08": "News Intel", "09": "Market Intel", "10": "Dark Web"
};
const AGENT_FILES = {
  "01": "OSINT_", "02": "Recon_", "06": "RE_", "08": "INTEL_", "09": "MARKET_", "10": "DARKWEB_"
};

let statusInterval = null;
let reportsCritical = 0;

async function fetchStatus() {
  try {
    const r = await fetch("/api/status");
    const data = await r.json();
    updateHealthBar(data);
    updateAgentGrid(data.agents);
    updateSidebarDots(data.agents);
  } catch(e) { console.error("status fetch failed", e); }
}

function updateHealthBar(data) {
  const services = ["ollama", "chromadb", "n8n", "tor"];
  services.forEach(s => {
    const dot = document.getElementById(`health-${s}`);
    if (dot) dot.className = "status-dot " + (data[s] ? "online" : "");
  });
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

function updateSidebarDots(agents) {
  const online = Object.values(agents).filter(s => s === "online").length;
  const running = Object.values(agents).filter(s => s === "running").length;
  const el = document.getElementById("sidebar-agent-count");
  if (el) el.textContent = `${online}/10`;
}

async function fetchReports() {
  try {
    const r = await fetch("/api/reports");
    const reports = await r.json();
    renderActivityFeed(reports.slice(0, 20));
    updateStats(reports);
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
    feed.innerHTML = '<div class="empty"><div class="empty-icon">📂</div>No reports yet</div>';
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

function updateStats(reports) {
  const el = document.getElementById("stat-reports");
  if (el) el.textContent = reports.length;

  reportsCritical = reports.reduce((sum, r) => sum + (r.priority_counts?.CRITICAL || 0), 0);
  const alertBanner = document.getElementById("alert-banner");
  const alertCount = document.getElementById("alert-count");
  const navBadge = document.getElementById("nav-badge-critical");
  if (alertBanner && reportsCritical > 0) {
    alertBanner.classList.add("visible");
    if (alertCount) alertCount.textContent = `${reportsCritical} CRITICAL items in recent reports`;
  }
  if (navBadge) navBadge.textContent = reportsCritical;
  if (reportsCritical === 0 && navBadge) navBadge.style.display = "none";
}

async function fetchKbStats() {
  try {
    const r = await fetch("/api/kb/stats");
    const cols = await r.json();
    const total = cols.reduce((s, c) => s + (c.count || 0), 0);
    const el = document.getElementById("stat-docs");
    if (el) el.textContent = total;
  } catch(e) {}
}

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

  const chartDefaults = {
    plugins: { legend: { labels: { color: "#e5e5e5", font: { family: "JetBrains Mono", size: 11 } } } },
    scales: {
      x: { ticks: { color: "#6b7280", font: { family: "JetBrains Mono", size: 10 } }, grid: { color: "#262626" } },
      y: { ticks: { color: "#6b7280", font: { family: "JetBrains Mono", size: 10 } }, grid: { color: "#262626" }, beginAtZero: true }
    }
  };

  const ctx1 = document.getElementById("chart-by-agent");
  if (ctx1) {
    if (_chartByAgent) _chartByAgent.destroy();
    _chartByAgent = new Chart(ctx1, {
      type: "bar",
      data: {
        labels: Object.keys(agentCounts),
        datasets: [{ label: "Reports", data: Object.values(agentCounts),
          backgroundColor: "#7c3aed", borderRadius: 4 }]
      },
      options: { ...chartDefaults, plugins: { ...chartDefaults.plugins, legend: { display: false } } }
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
          backgroundColor: ["#ef4444","#f97316","#eab308","#22c55e"],
          borderWidth: 0 }]
      },
      options: { plugins: { legend: { labels: { color: "#e5e5e5", font: { family: "JetBrains Mono", size: 11 } } } } }
    });
  }
}

async function fetchThreatActors() {
  try {
    const r = await fetch("/api/kb/threat-actors");
    const actors = await r.json();
    const el = document.getElementById("stat-ta");
    if (el) el.textContent = actors.length;
  } catch(e) {}
}

document.addEventListener("DOMContentLoaded", () => {
  fetchStatus();
  fetchReports();
  fetchKbStats();
  fetchThreatActors();
  statusInterval = setInterval(fetchStatus, 15000);
  setInterval(fetchReports, 30000);
});
