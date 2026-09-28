async function loadCases() {
  const tbody = document.getElementById("cases-tbody");
  try {
    const cases = await HUD.fetchJSON("/api/cases");
    if (!cases.length) {
      HUD.emptyState("cases-tbody", "No cases yet", { colspan: 5, hint: "Create one above." });
      return;
    }
    tbody.innerHTML = cases.map(c => `
      <tr>
        <td><a href="/cases/${c.id}" class="text-purple" style="text-decoration:none">${escHtml(c.name)}</a></td>
        <td class="text-muted" style="font-size:11px">${escHtml(c.tags || "-")}</td>
        <td style="text-align:center">${c.item_count}</td>
        <td class="text-muted" style="font-size:11px">${c.updated_at ? c.updated_at.slice(0, 16) : "-"}</td>
        <td><button class="btn btn-outline btn-sm" onclick="deleteCase('${c.id}', event)">Delete</button></td>
      </tr>`).join("");
  } catch (e) {
    HUD.emptyState("cases-tbody", "Failed to load cases", { error: true, colspan: 5, hint: e.message });
  }
}

async function createCase() {
  const name = document.getElementById("case-name").value.trim();
  if (!name) { showToast("Case name is required", "error"); return; }
  const body = {
    name,
    description: document.getElementById("case-desc").value,
    tags: document.getElementById("case-tags").value,
  };
  try {
    const d = await HUD.fetchJSON("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    window.location.href = `/cases/${d.id}`;
  } catch (e) {
    showToast("Create failed: " + e.message, "error");
  }
}

async function deleteCase(id, ev) {
  ev.stopPropagation();
  if (!confirm("Delete this case?")) return;
  await fetch(`/api/cases/${id}`, { method: "DELETE" });
  showToast("Case deleted", "success");
  loadCases();
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function showToast(msg, type = "") {
  // Delegates to the shared HUD toast (hud.js).
  window.HUD ? HUD.toast(msg, type) : console.log(msg);
}

document.addEventListener("DOMContentLoaded", loadCases);
