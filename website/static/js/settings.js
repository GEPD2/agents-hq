let currentSettings = {};
let watchlistData = {};
let onionData = {};

async function loadSettings() {
  try {
    const r = await fetch("/api/settings");
    currentSettings = await r.json();
    renderEnvKeys(currentSettings.env || {});
    watchlistData = currentSettings.watchlist || {};
    onionData = currentSettings.onion_targets || {};
    renderWatchlist();
    renderOnionTargets();
  } catch(e) {
    showToast(`Failed to load settings: ${e.message}`, "error");
  }
}

function renderEnvKeys(env) {
  const container = document.getElementById("env-keys");
  const allKeys = [
    "OTX_API_KEY", "FINNHUB_API_KEY", "INTELX_API_KEY", "HIBP_API_KEY", "VT_API_KEY",
    "SHODAN_API_KEY", "GREYNOISE_API_KEY", "VIRUSTOTAL_KEY", "HUNTER_KEY",
    "URLSCAN_KEY", "SECURITYTRAILS_KEY", "IPINFO_TOKEN", "ABUSEIPDB_KEY",
  ];
  container.innerHTML = allKeys.map(key => {
    const val = env[key] || "";
    const hasVal = val && val !== "***";
    return `
      <div class="env-row">
        <span class="env-key">${key}</span>
        <span class="env-value">${val || '<span class="text-muted">not set</span>'}</span>
        <div class="env-actions">
          <button class="btn btn-outline btn-sm" onclick="editEnvKey('${key}')">Edit</button>
        </div>
      </div>
    `;
  }).join("");
}

function editEnvKey(key) {
  const overlay = document.getElementById("env-modal");
  document.getElementById("env-modal-key").textContent = key;
  document.getElementById("env-modal-value").value = "";
  document.getElementById("env-modal-value").placeholder = "Enter new value…";
  overlay.classList.add("open");
  overlay._currentKey = key;
  document.getElementById("env-modal-value").focus();
}

async function saveEnvKey() {
  const overlay = document.getElementById("env-modal");
  const key = overlay._currentKey;
  const value = document.getElementById("env-modal-value").value.trim();
  if (!value) return;

  try {
    const r = await fetch("/api/settings/env", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, value }),
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    showToast(`Updated ${key}`, "success");
    closeEnvModal();
    loadSettings();
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

function closeEnvModal() {
  document.getElementById("env-modal").classList.remove("open");
}

function renderWatchlist() {
  const container = document.getElementById("watchlist-editor");
  if (!Object.keys(watchlistData).length) {
    container.innerHTML = '<div class="text-muted">Watchlist not loaded (Agent-09 not mounted)</div>';
    return;
  }
  container.innerHTML = Object.entries(watchlistData).map(([sector, tickers]) => `
    <div class="mb-3">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-size:12px;font-weight:600;color:var(--text)">${sector}</span>
        <button class="btn btn-outline btn-sm" onclick="addTicker('${sector}')">+ Add</button>
      </div>
      <div id="tickers-${sector}" style="display:flex;flex-wrap:wrap;gap:5px">
        ${tickers.map(t => `
          <span style="background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-size:11px;display:flex;align-items:center;gap:4px">
            ${escHtml(t)}
            <button style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;padding:0;line-height:1" onclick="removeTicker('${sector}','${t}')">✕</button>
          </span>
        `).join("")}
      </div>
    </div>
  `).join("");
}

function addTicker(sector) {
  const ticker = prompt(`Add ticker to ${sector}:`);
  if (!ticker) return;
  const t = ticker.trim().toUpperCase();
  if (!t) return;
  if (!watchlistData[sector]) watchlistData[sector] = [];
  if (!watchlistData[sector].includes(t)) {
    watchlistData[sector].push(t);
    renderWatchlist();
  }
}

function removeTicker(sector, ticker) {
  if (!watchlistData[sector]) return;
  watchlistData[sector] = watchlistData[sector].filter(t => t !== ticker);
  renderWatchlist();
}

async function saveWatchlist() {
  try {
    const r = await fetch("/api/settings/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ watchlist: watchlistData }),
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    showToast("Watchlist saved", "success");
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

function renderOnionTargets() {
  const container = document.getElementById("onion-editor");
  if (Object.keys(onionData).length === 0) {
    container.innerHTML = `
      <div class="text-muted mb-3" style="font-size:11px">No .onion targets configured. Add them below.</div>
      <div id="onion-rows"></div>
    `;
  } else {
    container.innerHTML = `<div id="onion-rows"></div>`;
  }
  renderOnionRows();
}

function renderOnionRows() {
  const rows = document.getElementById("onion-rows");
  if (!rows) return;
  rows.innerHTML = Object.entries(onionData).map(([name, addr]) => `
    <div class="env-row">
      <span class="env-key" style="flex:0 0 160px">${escHtml(name)}</span>
      <span class="env-value text-muted" style="font-size:11px">${escHtml(addr)}</span>
      <div class="env-actions">
        <button class="btn btn-danger btn-sm" onclick="removeOnion('${escHtml(name)}')">✕</button>
      </div>
    </div>
  `).join("") || '<div class="text-muted" style="font-size:11px;padding:8px 0">No entries</div>';
}

function addOnion() {
  const name = document.getElementById("onion-name").value.trim();
  const addr = document.getElementById("onion-addr").value.trim();
  if (!name || !addr) { showToast("Both name and address required", "error"); return; }
  onionData[name] = addr;
  document.getElementById("onion-name").value = "";
  document.getElementById("onion-addr").value = "";
  renderOnionRows();
}

function removeOnion(name) {
  delete onionData[name];
  renderOnionRows();
}

async function saveOnionTargets() {
  try {
    const r = await fetch("/api/settings/onion", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets: onionData }),
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    showToast("Onion targets saved", "success");
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

async function loadAlerts() {
  try {
    const r = await fetch("/api/settings/alerts");
    const cfg = await r.json();
    document.getElementById("alert-webhook-url").value  = cfg.ALERT_WEBHOOK_URL  || "";
    document.getElementById("alert-smtp-host").value    = cfg.SMTP_HOST          || "";
    document.getElementById("alert-smtp-port").value    = cfg.SMTP_PORT          || "";
    document.getElementById("alert-smtp-user").value    = cfg.SMTP_USER          || "";
    document.getElementById("alert-smtp-password").value= "";  // never prefill password
    document.getElementById("alert-email-to").value     = cfg.ALERT_EMAIL_TO     || "";
  } catch(e) {
    // non-fatal — alert config section just stays empty
  }
}

async function saveAlerts() {
  const pw = document.getElementById("alert-smtp-password").value.trim();
  const config = {
    ALERT_WEBHOOK_URL: document.getElementById("alert-webhook-url").value.trim(),
    SMTP_HOST:         document.getElementById("alert-smtp-host").value.trim(),
    SMTP_PORT:         document.getElementById("alert-smtp-port").value.trim() || "587",
    SMTP_USER:         document.getElementById("alert-smtp-user").value.trim(),
    ALERT_EMAIL_TO:    document.getElementById("alert-email-to").value.trim(),
  };
  if (pw) config.SMTP_PASSWORD = pw;

  try {
    const r = await fetch("/api/settings/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config }),
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    const d = await r.json();
    showToast(`Saved ${d.saved.length} alert setting(s)`, "success");
    document.getElementById("alert-smtp-password").value = "";
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
  }
}

async function testAlert() {
  const btn = document.getElementById("btn-test-alert");
  btn.disabled = true;
  btn.textContent = "Sending…";
  try {
    const r = await fetch("/api/alerts/test", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      const channels = Object.entries(d.results || {})
        .map(([k, v]) => `${k}:${v ? "✓" : "✗"}`).join("  ");
      showToast(`Test sent — ${channels || "no channels configured"}`, "success");
    } else {
      showToast(d.detail || "No channels configured — save a webhook URL or SMTP settings first", "error");
    }
  } catch(e) {
    showToast(`Error: ${e.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Send Test";
  }
}

function escHtml(str) {
  if (!str) return "";
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function showToast(msg, type="") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  loadAlerts();
  document.getElementById("env-modal")?.addEventListener("click", e => {
    if (e.target === document.getElementById("env-modal")) closeEnvModal();
  });
  document.getElementById("env-modal-value")?.addEventListener("keydown", e => {
    if (e.key === "Enter") saveEnvKey();
  });
});
