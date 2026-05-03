const IOC_COLORS = {
  ip:     "ioc-ip",     domain: "ioc-domain", email: "ioc-email",
  hash:   "ioc-hash",   cve:    "ioc-cve",    onion: "ioc-onion",
  wallet: "ioc-wallet",
};
const IOC_LABELS = {
  ip:"IPs", domain:"Domains", email:"Emails", hash:"Hashes",
  cve:"CVEs", onion:"Onions", wallet:"Wallets",
};

let currentType = null;
let currentPage = 1;

async function loadStats() {
  try {
    const r = await fetch("/api/iocs/stats");
    const stats = await r.json();
    renderStats(stats);
    renderTypeTabs(stats);
  } catch(e) {
    document.getElementById("ioc-stats-row").innerHTML = '<div class="empty">Failed to load stats</div>';
  }
}

function renderStats(stats) {
  const row = document.getElementById("ioc-stats-row");
  if (!stats.length) {
    row.innerHTML = '<div class="stat-card" style="grid-column:1/-1"><div class="stat-value">0</div><div class="stat-label">No IOCs indexed yet — click Scan All Reports</div></div>';
    return;
  }
  const total = stats.reduce((s, r) => s + r.unique_count, 0);
  let html = `<div class="stat-card"><div class="stat-value text-purple">${total}</div><div class="stat-label">Total Unique IOCs</div></div>`;
  stats.forEach(s => {
    const label = IOC_LABELS[s.type] || s.type;
    html += `<div class="stat-card" onclick="filterType('${s.type}')" style="cursor:pointer">
      <div class="stat-value">${s.unique_count}</div>
      <div class="stat-label">${label}</div>
    </div>`;
  });
  row.innerHTML = html;
}

function renderTypeTabs(stats) {
  const tabs = document.getElementById("ioc-type-tabs");
  let html = `<button class="tab-btn active" onclick="filterType(null,this)">All</button>`;
  stats.forEach(s => {
    const label = IOC_LABELS[s.type] || s.type;
    html += `<button class="tab-btn" onclick="filterType('${s.type}',this)">${label} (${s.unique_count})</button>`;
  });
  tabs.innerHTML = html;
}

function filterType(type, btn) {
  currentType = type;
  currentPage = 1;
  document.querySelectorAll("#ioc-type-tabs .tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  loadIocs();
}

async function loadIocs() {
  const tbody = document.getElementById("ioc-tbody");
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)"><span class="spinner"></span></td></tr>';
  try {
    const params = new URLSearchParams({ page: currentPage });
    if (currentType) params.set("type", currentType);
    const r = await fetch(`/api/iocs?${params}`);
    const iocs = await r.json();
    renderIocTable(iocs);
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--critical);padding:16px">Error: ${e.message}</td></tr>`;
  }
}

function renderIocTable(iocs) {
  const tbody = document.getElementById("ioc-tbody");
  if (!iocs.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty">No IOCs found — run agents or click Scan All Reports</div></td></tr>';
    return;
  }
  tbody.innerHTML = iocs.map(ioc => {
    const colorCls = IOC_COLORS[ioc.type] || "";
    const lastSeen = ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : "—";
    const pivotUrl = `/pivot/${encodeURIComponent(ioc.type)}/${encodeURIComponent(ioc.value)}`;
    const shortVal = ioc.value.length > 60 ? ioc.value.slice(0, 57) + "…" : ioc.value;
    return `<tr>
      <td><span class="ioc-tag ${colorCls}">${ioc.type}</span></td>
      <td style="font-family:monospace;font-size:11px" title="${escHtml(ioc.value)}">${escHtml(shortVal)}</td>
      <td style="text-align:center">${ioc.report_count}</td>
      <td class="text-muted" style="font-size:11px">${lastSeen}</td>
      <td><a href="${pivotUrl}" class="btn btn-outline btn-sm">Pivot ↗</a></td>
    </tr>`;
  }).join("");
}

async function ingestAll() {
  const btn = document.getElementById("btn-ingest-all");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const r = await fetch("/api/iocs/ingest-all", { method: "POST" });
    const d = await r.json();
    showToast(`Indexed ${d.iocs} IOCs from ${d.reports} reports`, "success");
    await loadStats();
    await loadIocs();
  } catch(e) {
    showToast("Scan failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan All Reports";
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function showToast(msg, type = "") {
  const c = document.getElementById("toast-container");
  if (!c) return;
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadStats();
  await loadIocs();
});
