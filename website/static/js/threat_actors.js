let allActors = [];
let selectedActor = null;

function daysSince(dateStr) {
  if (!dateStr) return Infinity;
  const d = new Date(dateStr);
  if (isNaN(d)) return Infinity;
  return (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
}

function activityClass(actor) {
  const days = daysSince(actor.last_updated);
  if (days <= 7)  return "active";
  if (days <= 30) return "recent";
  return "dormant";
}

function activityLabel(actor) {
  const days = daysSince(actor.last_updated);
  if (days <= 7)  return "ACTIVE";
  if (days <= 30) return "RECENT";
  return "DORMANT";
}

async function loadThreatActors() {
  const grid = document.getElementById("ta-grid");
  grid.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
  try {
    const r = await fetch("/api/kb/threat-actors");
    allActors = await r.json();
    renderGrid(allActors);
  } catch(e) {
    grid.innerHTML = `<div class="empty text-critical">Error: ${e.message}</div>`;
  }
}

function renderGrid(actors) {
  const grid = document.getElementById("ta-grid");
  const count = document.getElementById("ta-count");
  if (count) count.textContent = actors.length;

  if (!actors.length) {
    grid.innerHTML = '<div class="empty" style="grid-column:1/-1"><div class="empty-icon">🕵️</div>No threat actor profiles yet.<br><span class="text-muted" style="font-size:11px">Run Agent-10 to populate profiles.</span></div>';
    return;
  }

  // Sort: active first, then recent, then dormant
  const sorted = [...actors].sort((a, b) => {
    const order = { active: 0, recent: 1, dormant: 2 };
    return (order[activityClass(a)] || 2) - (order[activityClass(b)] || 2);
  });

  grid.innerHTML = sorted.map(actor => {
    const ac = activityClass(actor);
    const al = activityLabel(actor);
    const ts = actor.last_updated ? new Date(actor.last_updated).toLocaleDateString() : "unknown";
    const snippet = extractSnippet(actor.content);
    return `
      <div class="ta-card ${ac}-group" onclick="viewActor('${encodeURIComponent(actor.name)}')">
        <div class="ta-name">${escHtml(actor.name)}</div>
        <div class="ta-meta">${snippet}</div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px">
          <span class="ta-activity ${ac}">${al}</span>
          <span class="text-muted" style="font-size:10px">Updated: ${ts}</span>
        </div>
      </div>
    `;
  }).join("");
}

function extractSnippet(content) {
  if (!content) return "No profile data";
  const lines = content.split("\n").filter(l => l.trim() && !l.startsWith("#"));
  return escHtml(lines.slice(0, 2).join(" ").slice(0, 120)) + (content.length > 120 ? "…" : "");
}

async function viewActor(name) {
  const panel = document.getElementById("ta-profile");
  const panelName = document.getElementById("ta-profile-name");
  const panelContent = document.getElementById("ta-profile-content");

  panel.style.display = "block";
  panelName.textContent = decodeURIComponent(name);
  panelContent.innerHTML = '<div class="empty"><span class="spinner"></span></div>';

  try {
    const r = await fetch(`/api/kb/threat-actors/${encodeURIComponent(name)}`);
    const actor = await r.json();
    const html = marked.parse(actor.content || "No profile data", { breaks: true, gfm: true });
    panelContent.innerHTML = `<div class="report-content">${html}</div>`;

    const ac = activityClass(actor);
    const al = activityLabel(actor);
    panelName.innerHTML = `${escHtml(actor.name)} <span class="ta-activity ${ac}" style="vertical-align:middle">${al}</span>`;

    panel.scrollIntoView({ behavior: "smooth" });
  } catch(e) {
    panelContent.innerHTML = `<div class="empty text-critical">Error: ${e.message}</div>`;
  }
}

function filterActors() {
  const q = document.getElementById("ta-search")?.value.toLowerCase() || "";
  const filtered = allActors.filter(a => a.name.toLowerCase().includes(q));
  renderGrid(filtered);
}

function escHtml(str) {
  if (!str) return "";
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

document.addEventListener("DOMContentLoaded", () => {
  loadThreatActors();
  document.getElementById("ta-search")?.addEventListener("input", filterActors);
});
