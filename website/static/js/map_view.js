let map = null;
let cluster = null;

function initMap() {
  map = L.map("geo-map", { worldCopyJump: true }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; OpenStreetMap &copy; CARTO",
    maxZoom: 18,
  }).addTo(map);
  cluster = L.markerClusterGroup ? L.markerClusterGroup() : L.layerGroup();
  map.addLayer(cluster);
}

async function loadPoints() {
  const status = document.getElementById("map-status");
  try {
    const r = await fetch("/api/map/ips");
    const data = await r.json();
    renderPoints(data.points);
    renderCountries(data.top_countries);
    if (!data.geocoding_enabled) {
      status.textContent = "geocoding disabled (no IPINFO_TOKEN)";
    } else {
      status.textContent = `${data.points.length} located / ${data.total_ips} IPs`;
    }
  } catch (e) {
    status.textContent = "Error: " + e.message;
  }
}

function renderPoints(points) {
  cluster.clearLayers();
  points.forEach(p => {
    const reports = (p.reports || []).slice(0, 8).map(f =>
      `<a href="/reports/${encodeURIComponent(f)}">${escHtml(f)}</a>`).join("<br>");
    const popup = `<b>${escHtml(p.ip)}</b><br>${escHtml(p.city || "")} ${escHtml(p.country)}<br>`
      + `Reports (${p.report_count}):<br>${reports}`;
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: Math.min(6 + p.report_count, 16),
      color: "#7c3aed", fillColor: "#7c3aed", fillOpacity: 0.6, weight: 1,
    }).bindPopup(popup);
    cluster.addLayer(marker);
  });
}

function renderCountries(countries) {
  const tbody = document.getElementById("country-tbody");
  if (!countries || !countries.length) {
    tbody.innerHTML = '<tr><td colspan="2"><div class="empty">No located IPs yet</div></td></tr>';
    return;
  }
  tbody.innerHTML = countries.map(c => `
    <tr>
      <td>${escHtml(c.country)}</td>
      <td style="text-align:right" class="text-purple">${c.count}</td>
    </tr>`).join("");
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", () => { initMap(); loadPoints(); });
