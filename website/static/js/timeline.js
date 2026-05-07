const TL_COLORS = {
  "01": "#7c3aed", "06": "#f97316", "08": "#3b82f6",
  "09": "#22c55e", "10": "#ef4444", "02": "#6b7280"
};
const TL_LABELS = {
  "01": "OSINT", "02": "Recon", "06": "RE",
  "08": "Intel", "09": "Market", "10": "DarkWeb"
};

let _tlReports = [];
let _tlZoom = "all";

function tlInit(reports) {
  _tlReports = reports.filter(r => r.created);
  renderTimeline("tl-main", false);
}

function setZoom(z, btn) {
  _tlZoom = z;
  document.querySelectorAll(".tl-zoom-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  renderTimeline("tl-main", false);
}

function getZoomSince() {
  const now = Date.now();
  if (_tlZoom === "day")   return now - 86400000;
  if (_tlZoom === "week")  return now - 7 * 86400000;
  if (_tlZoom === "month") return now - 30 * 86400000;
  return null;
}

function renderTimeline(containerId, compact) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const since = getZoomSince();
  const reports = since
    ? _tlReports.filter(r => new Date(r.created).getTime() >= since)
    : [..._tlReports];

  if (!reports.length && _tlReports.length) {
    // Zoom window is empty but data exists — fall back to all-time view
    reports = [..._tlReports];
  }
  if (!reports.length) {
    container.innerHTML = '<div class="tl-empty">No reports yet</div>';
    return;
  }

  // Group by agent
  const byAgent = {};
  reports.forEach(r => {
    const a = (r.agent && r.agent !== "unknown") ? r.agent : "??";
    if (!byAgent[a]) byAgent[a] = [];
    byAgent[a].push(r);
  });
  const agents = Object.keys(byAgent).sort();

  // Time bounds
  const dates = reports.map(r => new Date(r.created).getTime());
  const minTs = since || Math.min(...dates);
  const maxTs = Math.max(...dates);
  const span  = Math.max(maxTs - minTs, 1);

  const labelW = compact ? 0  : 82;
  const padR   = 16;
  const padT   = compact ? 6  : 10;
  const padB   = compact ? 6  : 26;
  const rowH   = compact ? 26 : 38;
  const dotR   = compact ? 4  : 5;

  const svgW   = container.clientWidth || 800;
  const trackW = svgW - labelW - padR;
  const svgH   = agents.length * rowH + padT + padB;

  const xOf = ts => labelW + ((ts - minTs) / span) * trackW;

  let svg = `<svg width="${svgW}" height="${svgH}" xmlns="http://www.w3.org/2000/svg" style="display:block">`;

  if (!compact) {
    getTicks(minTs, maxTs).forEach(t => {
      const x = xOf(t.ts).toFixed(1);
      svg += `<line x1="${x}" y1="${padT}" x2="${x}" y2="${svgH - padB}" stroke="#1e1e1e" stroke-width="1"/>`;
      svg += `<text x="${x}" y="${svgH - 6}" text-anchor="middle" fill="#4b5563" font-size="9" font-family="JetBrains Mono,monospace">${t.label}</text>`;
    });
  }

  agents.forEach((agentId, i) => {
    const cy    = padT + i * rowH + rowH / 2;
    const color = TL_COLORS[agentId] || "#6b7280";
    const label = TL_LABELS[agentId] || `A${agentId}`;

    svg += `<line x1="${labelW}" y1="${cy}" x2="${svgW - padR}" y2="${cy}" stroke="#1a1a1a" stroke-width="1"/>`;

    if (!compact) {
      svg += `<text x="${labelW - 6}" y="${cy + 4}" text-anchor="end" fill="#6b7280" font-size="10" font-family="JetBrains Mono,monospace">${label}</text>`;
    }

    byAgent[agentId].forEach(r => {
      const cx    = xOf(new Date(r.created).getTime()).toFixed(1);
      const isCrit = (r.priority_counts?.CRITICAL || 0) > 0;
      const fill  = isCrit ? "#ef4444" : color;
      const rr    = isCrit ? dotR + 1 : dotR;
      const crit  = r.priority_counts?.CRITICAL || 0;
      const high  = r.priority_counts?.HIGH || 0;
      const title = `${r.filename.replace(/&/g,"&amp;").replace(/</g,"&lt;")}\n${new Date(r.created).toLocaleString()}\nCRIT: ${crit}  HIGH: ${high}`;
      const href  = `/reports/${encodeURIComponent(r.filename)}`;

      svg += `<a href="${href}">`;
      if (isCrit) {
        svg += `<circle cx="${cx}" cy="${cy}" r="${rr + 5}" fill="#ef4444" opacity="0.12" class="tl-pulse"/>`;
      }
      svg += `<circle cx="${cx}" cy="${cy}" r="${rr}" fill="${fill}" class="tl-dot"><title>${title}</title></circle>`;
      svg += `</a>`;
    });
  });

  svg += '</svg>';
  container.innerHTML = svg;
}

function getTicks(minTs, maxTs) {
  const span = maxTs - minTs;
  const ticks = [];
  const DAY = 86400000;

  if (span <= 2 * DAY) {
    const start = new Date(minTs); start.setMinutes(0, 0, 0);
    for (let d = new Date(start); d.getTime() <= maxTs; d.setHours(d.getHours() + 6)) {
      ticks.push({ ts: d.getTime(), label: `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2,"0")}h` });
    }
  } else if (span <= 14 * DAY) {
    const start = new Date(minTs); start.setHours(0, 0, 0, 0);
    for (let d = new Date(start); d.getTime() <= maxTs; d.setDate(d.getDate() + 1)) {
      ticks.push({ ts: d.getTime(), label: `${d.getMonth()+1}/${d.getDate()}` });
    }
  } else if (span <= 90 * DAY) {
    const start = new Date(minTs); start.setHours(0, 0, 0, 0);
    start.setDate(start.getDate() - start.getDay());
    for (let d = new Date(start); d.getTime() <= maxTs; d.setDate(d.getDate() + 7)) {
      ticks.push({ ts: d.getTime(), label: `${d.getMonth()+1}/${d.getDate()}` });
    }
  } else {
    const start = new Date(minTs); start.setDate(1); start.setHours(0, 0, 0, 0);
    for (let d = new Date(start); d.getTime() <= maxTs; d.setMonth(d.getMonth() + 1)) {
      ticks.push({ ts: d.getTime(), label: `${d.getMonth()+1}/${String(d.getFullYear()).slice(2)}` });
    }
  }
  return ticks;
}

window.addEventListener("resize", () => {
  if (!_tlReports.length) return;
  renderTimeline("tl-main", false);
  renderTimeline("dash-timeline", true);
});
