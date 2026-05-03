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
    if (!r.ok) {
      tbody.innerHTML = '<tr><td colspan="3"><div class="empty">IOC not yet indexed — view the report first to trigger ingest</div></td></tr>';
      document.getElementById("pivot-report-count").textContent = "0";
      return;
    }
    const d = await r.json();
    document.getElementById("pivot-report-count").textContent = d.count;
    if (!d.reports.length) {
      tbody.innerHTML = '<tr><td colspan="3"><div class="empty">No reports found</div></td></tr>';
      return;
    }
    tbody.innerHTML = d.reports.map(r => {
      const agent = AGENT_LABEL[r.agent_id] || r.agent_id || "—";
      const seen  = r.seen_at ? new Date(r.seen_at).toLocaleDateString() : "—";
      return `<tr>
        <td><a href="/reports/${encodeURIComponent(r.report_file)}" class="text-purple truncate" style="max-width:220px;display:block" title="${escHtml(r.report_file)}">${escHtml(r.report_file)}</a></td>
        <td><span class="feed-agent-badge">${agent}</span></td>
        <td class="text-muted" style="font-size:11px">${seen}</td>
      </tr>`;
    }).join("");
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--critical)">Error: ${escHtml(e.message)}</td></tr>`;
  }
}

async function loadRelated(type, value) {
  const panel = document.getElementById("pivot-related");
  try {
    const r = await fetch(`/api/iocs/correlate/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
    const related = await r.json();
    if (!related.length) {
      panel.innerHTML = '<div class="text-muted" style="font-size:12px;padding:8px">No co-occurring IOCs found</div>';
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
          return `<a href="${pivotUrl}" class="ioc-tag ${colorCls}" title="${escHtml(ioc.value)} — in ${ioc.co_count} report(s)">${escHtml(short)}</a>`;
        }).join("")}</div>
      </div>`;
    }).join("");
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--critical);font-size:12px">Error: ${escHtml(e.message)}</div>`;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
