async function loadCases() {
  const tbody = document.getElementById("cases-tbody");
  try {
    const r = await fetch("/api/cases");
    const cases = await r.json();
    if (!cases.length) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty">No cases yet — create one above</div></td></tr>';
      return;
    }
    tbody.innerHTML = cases.map(c => `
      <tr>
        <td><a href="/cases/${c.id}" class="text-purple" style="text-decoration:none">${escHtml(c.name)}</a></td>
        <td class="text-muted" style="font-size:11px">${escHtml(c.tags || "—")}</td>
        <td style="text-align:center">${c.item_count}</td>
        <td class="text-muted" style="font-size:11px">${c.updated_at ? c.updated_at.slice(0, 16) : "—"}</td>
        <td><button class="btn btn-outline btn-sm" onclick="deleteCase('${c.id}', event)">Delete</button></td>
      </tr>`).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--critical);padding:16px">Error: ${e.message}</td></tr>`;
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
    const r = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    const d = await r.json();
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
  const c = document.getElementById("toast-container");
  if (!c) return;
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

document.addEventListener("DOMContentLoaded", loadCases);
