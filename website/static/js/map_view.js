// Offline SVG world map. Draws country outlines from a bundled GeoJSON and plots
// proportional-symbol circles by country from /api/map/ips. No external tiles,
// no API key. Equirectangular projection, plain math, no mapping library.

const VW = 1000, VH = 500;
let _world = null;         // { paths: [{iso, d}], centroids: {ISO2: [x,y]} }
let _countries = [];       // [{country, count, ips}]

function tok(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function proj(lon, lat) { return [(lon + 180) / 360 * VW, (90 - lat) / 180 * VH]; }

function ringToPath(ring) {
  let d = "";
  for (let i = 0; i < ring.length; i++) {
    const [x, y] = proj(ring[i][0], ring[i][1]);
    d += (i === 0 ? "M" : "L") + x.toFixed(1) + "," + y.toFixed(1);
  }
  return d + "Z";
}

function buildWorld(geojson) {
  const paths = [];
  const centroids = {};
  geojson.features.forEach(f => {
    const iso = f.properties.iso;
    const g = f.geometry;
    const polys = g.type === "Polygon" ? [g.coordinates] : g.type === "MultiPolygon" ? g.coordinates : [];
    let d = "";
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90, has = false;
    polys.forEach(poly => {
      poly.forEach(ring => {
        d += ringToPath(ring);
        ring.forEach(([lon, lat]) => {
          has = true;
          if (lon < minLon) minLon = lon; if (lon > maxLon) maxLon = lon;
          if (lat < minLat) minLat = lat; if (lat > maxLat) maxLat = lat;
        });
      });
    });
    if (d) paths.push({ iso: iso, d: d });
    if (has && iso && iso !== "-99") {
      centroids[iso] = proj((minLon + maxLon) / 2, (minLat + maxLat) / 2);
    }
  });
  return { paths: paths, centroids: centroids };
}

function render() {
  const host = document.getElementById("geo-map");
  if (!host || !_world) return;

  const land = tok("--surface-2"), stroke = tok("--border"), ocean = tok("--bg");
  const accent = tok("--accent"), accentHover = tok("--accent-hover");

  const max = _countries.reduce((m, c) => Math.max(m, c.count), 0) || 1;
  const rOf = n => 3 + Math.sqrt(n / max) * 22;

  let svg = `<svg viewBox="0 0 ${VW} ${VH}" width="100%" style="display:block" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<rect x="0" y="0" width="${VW}" height="${VH}" fill="${ocean}"/>`;
  svg += `<g fill="${land}" stroke="${stroke}" stroke-width="0.4">`;
  _world.paths.forEach(p => { svg += `<path d="${p.d}"/>`; });
  svg += `</g>`;

  let plotted = 0;
  _countries.forEach(c => {
    const ctr = _world.centroids[c.country];
    if (!ctr) return;
    plotted++;
    const r = rOf(c.count).toFixed(1);
    const title = `${c.country}: ${c.count} report(s) across ${c.ips.length}+ IP(s)`;
    svg += `<circle cx="${ctr[0].toFixed(1)}" cy="${ctr[1].toFixed(1)}" r="${r}" `
        + `fill="${accent}" fill-opacity="0.55" stroke="${accentHover}" stroke-width="1">`
        + `<title>${title}</title></circle>`;
  });
  svg += `</svg>`;
  host.innerHTML = svg;
  return plotted;
}

function renderCountries() {
  const tbody = document.getElementById("country-tbody");
  if (!tbody) return;
  if (!_countries.length) {
    HUD.emptyState("country-tbody", "No located IPs yet", { colspan: 2, hint: "Run Agents 01/02/10." });
    return;
  }
  tbody.innerHTML = _countries.slice(0, 15).map(c => `
    <tr>
      <td>${escHtml(c.country)}</td>
      <td style="text-align:right" class="text-accent">${c.count}</td>
    </tr>`).join("");
}

async function loadPoints() {
  const status = document.getElementById("map-status");
  try {
    const data = await HUD.fetchJSON("/api/map/ips");
    _countries = data.countries || [];
    render();
    renderCountries();
    const resolver = data.resolver === "offline" ? "offline dataset"
      : data.resolver === "cache" ? "cache only" : "no geo source";
    if (status) status.textContent = `${data.located} located / ${data.total_ips} IPs (${resolver})`;
  } catch (e) {
    if (status) status.textContent = "Error: " + e.message;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function initMap() {
  try {
    _world = buildWorld(await HUD.fetchJSON("/static/data/world.geojson"));
  } catch (e) {
    HUD.emptyState("geo-map", "World map data failed to load", { error: true, hint: e.message });
    return;
  }
  await loadPoints();
}

document.addEventListener("DOMContentLoaded", initMap);
window.addEventListener("themechange", () => { if (_world) render(); });
