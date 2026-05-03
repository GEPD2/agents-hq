const AGENT_LABELS = {
  "01": "OSINT", "02": "Recon", "06": "RE", "08": "Intel", "09": "Market", "10": "DarkWeb"
};

let allReports = [];
let activeFilter = "all";

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes/1024).toFixed(1)}KB`;
  return `${(bytes/1024/1024).toFixed(1)}MB`;
}

function formatDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString();
}

async function loadReports(query = "") {
  const table = document.getElementById("reports-tbody");
  table.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)"><span class="spinner"></span> Loading...</td></tr>';
  try {
    const url = query ? `/api/reports?q=${encodeURIComponent(query)}` : "/api/reports";
    const r = await fetch(url);
    allReports = await r.json();
    renderReports(allReports);
    buildFilterTabs();
  } catch(e) {
    table.innerHTML = `<tr><td colspan="6" style="color:var(--critical);padding:16px">Error: ${e.message}</td></tr>`;
  }
}

function buildFilterTabs() {
  const agents = [...new Set(allReports.map(r => r.agent))].filter(a => a !== "unknown");
  const tabs = document.getElementById("filter-tabs");
  if (!tabs) return;
  tabs.innerHTML = `<button class="tab-btn active" onclick="filterBy('all', this)">All (${allReports.length})</button>`;
  agents.forEach(a => {
    const count = allReports.filter(r => r.agent === a).length;
    const label = AGENT_LABELS[a] || `Agent-${a}`;
    tabs.innerHTML += `<button class="tab-btn" onclick="filterBy('${a}', this)">${label} (${count})</button>`;
  });
}

function filterBy(agent, btn) {
  activeFilter = agent;
  document.querySelectorAll("#filter-tabs .tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  applyFilter();
}

function applyFilter() {
  const query = (document.getElementById("search-input")?.value || "").toLowerCase();
  let filtered = allReports;
  if (activeFilter !== "all") {
    filtered = filtered.filter(r => r.agent === activeFilter);
  }
  if (query) {
    filtered = filtered.filter(r => r.filename.toLowerCase().includes(query));
  }
  renderReports(filtered);
}

function renderReports(reports) {
  const tbody = document.getElementById("reports-tbody");
  if (!reports.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="empty-icon">📄</div>No reports found</div></td></tr>';
    return;
  }
  tbody.innerHTML = reports.map(r => {
    const pc = r.priority_counts || {};
    const agentLabel = AGENT_LABELS[r.agent] || r.agent;
    const critBadge = pc.CRITICAL > 0 ? `<span class="badge badge-critical">${pc.CRITICAL}</span>` : "";
    const highBadge = pc.HIGH > 0     ? `<span class="badge badge-high">${pc.HIGH}</span>`         : "";
    const medBadge  = pc.MEDIUM > 0   ? `<span class="badge badge-medium">${pc.MEDIUM}</span>`     : "";
    return `
      <tr>
        <td>
          <a href="/reports/${encodeURIComponent(r.filename)}" class="text-purple truncate" style="max-width:320px;display:block" title="${r.filename}">
            ${r.filename}
          </a>
        </td>
        <td><span class="feed-agent-badge">${agentLabel}</span></td>
        <td>${formatSize(r.size)}</td>
        <td class="text-muted">${formatDate(r.created)}</td>
        <td><div style="display:flex;gap:4px;flex-wrap:wrap">${critBadge}${highBadge}${medBadge}</div></td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="deleteReport('${r.filename}', this)">✕</button>
        </td>
      </tr>
    `;
  }).join("");
}

async function deleteReport(filename, btn) {
  if (!confirm(`Delete ${filename}?`)) return;
  btn.disabled = true;
  try {
    const r = await fetch(`/api/reports/${encodeURIComponent(filename)}`, { method: "DELETE" });
    if (!r.ok) throw new Error("Failed");
    allReports = allReports.filter(x => x.filename !== filename);
    applyFilter();
    showToast(`Deleted ${filename}`, "success");
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
    btn.disabled = false;
  }
}

function showToast(msg, type = "") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

let _searchTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  loadReports();
  document.getElementById("search-input")?.addEventListener("input", e => {
    const q = e.target.value.trim();
    clearTimeout(_searchTimer);
    if (q.length === 0) { loadReports(); return; }
    if (q.length < 3) { applyFilter(); return; }
    // debounce content search to avoid hammering the API
    _searchTimer = setTimeout(() => loadReports(q), 400);
  });
});
