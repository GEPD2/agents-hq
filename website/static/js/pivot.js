const PIVOT_COLORS = {
  ip:"ioc-ip", domain:"ioc-domain", email:"ioc-email",
  hash:"ioc-hash", cve:"ioc-cve", onion:"ioc-onion", wallet:"ioc-wallet",
};
const AGENT_LABEL = {
  "01":"OSINT","02":"Recon","06":"RE","08":"Intel","09":"Market","10":"DarkWeb"
};

document.addEventListener("DOMContentLoaded", async () => {
  const el   = document.getElementById("pivot-data");
  const type = el?.dataset?.type;
  const val  = el?.dataset?.value;
  if (!type || !val) return;

  document.getElementById("pivot-value").textContent = val;
  const badge = document.getElementById("pivot-type-badge");
  badge.className = `ioc-tag ${PIVOT_COLORS[type] || ""}`;
  badge.textContent = type.toUpperCase();

  await Promise.all([loadReports(type, val), loadRelated(type, val)]);
});

async function loadReports(type, value) {
  const tbody = document.getElementById("pivot-reports-tbody");
  try {
    const r = await fetch(`/api/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
    if (r.status === 401) { window.location.href = "/login"; return; }
    if (!r.ok) {
      HUD.emptyState("pivot-reports-tbody", "IOC not yet indexed",
        { colspan: 3, hint: "View the report first to trigger ingest." });
      document.getElementById("pivot-report-count").textContent = "0";
      return;
    }
    const d = await r.json();
    document.getElementById("pivot-report-count").textContent = d.count;
    if (!d.reports.length) {
      HUD.emptyState("pivot-reports-tbody", "No reports found", { colspan: 3 });
      return;
    }
    tbody.innerHTML = d.reports.map(r => {
      const agent = AGENT_LABEL[r.agent_id] || r.agent_id || "-";
      const seen  = r.seen_at ? new Date(r.seen_at).toLocaleDateString() : "-";
      return `<tr>
        <td><a href="/reports/${encodeURIComponent(r.report_file)}" class="text-purple truncate" style="max-width:220px;display:block" title="${escHtml(r.report_file)}">${escHtml(r.report_file)}</a></td>
        <td><span class="feed-agent-badge">${agent}</span></td>
        <td class="text-muted" style="font-size:11px">${seen}</td>
      </tr>`;
    }).join("");
  } catch(e) {
    HUD.emptyState("pivot-reports-tbody", "Failed to load reports", { error: true, colspan: 3, hint: e.message });
  }
}

async function loadRelated(type, value) {
  const panel = document.getElementById("pivot-related");
  try {
    const related = await HUD.fetchJSON(`/api/iocs/correlate/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
    if (!related.length) {
      HUD.emptyState(panel, "No co-occurring IOCs found");
      document.getElementById("pivot-related-count").textContent = "";
      return;
    }
    document.getElementById("pivot-related-count").textContent = `(${related.length})`;

    // Group by type
    const byType = {};
    related.forEach(ioc => {
      if (!byType[ioc.type]) byType[ioc.type] = [];
      byType[ioc.type].push(ioc);
    });

    panel.innerHTML = Object.entries(byType).map(([t, iocs]) => {
      const colorCls = PIVOT_COLORS[t] || "";
      return `<div class="mb-3">
        <div style="font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;margin-bottom:5px">
          ${t} (${iocs.length})
        </div>
        <div>${iocs.map(ioc => {
          const short = ioc.value.length > 40 ? ioc.value.slice(0, 37) + "…" : ioc.value;
          const pivotUrl = `/pivot/${encodeURIComponent(t)}/${encodeURIComponent(ioc.value)}`;
          return `<a href="${pivotUrl}" class="ioc-tag ${colorCls}" title="${escHtml(ioc.value)} - in ${ioc.co_count} report(s)">${escHtml(short)}</a>`;
        }).join("")}</div>
      </div>`;
    }).join("");
  } catch(e) {
    HUD.emptyState(panel, "Failed to load related IOCs", { error: true, hint: e.message });
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
