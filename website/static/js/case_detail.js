const CASE_ID = window.CASE_ID;

async function loadCase() {
  try {
    const r = await fetch(`/api/cases/${CASE_ID}`);
    if (!r.ok) throw new Error("Case not found");
    const c = await r.json();
    document.getElementById("case-title").textContent = c.name;
    document.getElementById("case-desc-view").textContent =
      [c.description, c.tags ? "Tags: " + c.tags : ""].filter(Boolean).join(" · ");
    renderItems(c.items || []);
    const bv = document.getElementById("brief-view");
    if (c.brief) bv.textContent = c.brief;
  } catch (e) {
    document.getElementById("case-title").textContent = "Error: " + e.message;
  }
}

function renderItems(items) {
  const tbody = document.getElementById("items-tbody");
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty">No items linked yet</div></td></tr>';
    return;
  }
  tbody.innerHTML = items.map(it => {
    const ref = it.item_type === "report"
      ? `<a href="/reports/${encodeURIComponent(it.ref)}" class="text-purple">${escHtml(it.ref)}</a>`
      : escHtml(it.ref);
    return `<tr>
      <td><span class="ioc-tag">${it.item_type}</span></td>
      <td style="font-family:monospace;font-size:11px">${ref}</td>
      <td class="text-muted">${escHtml(it.label || "—")}</td>
      <td><button class="btn btn-outline btn-sm" onclick="removeItem('${it.id}')">Remove</button></td>
    </tr>`;
  }).join("");
}

async function loadReportOptions() {
  try {
    const r = await fetch("/api/reports");
    const reports = await r.json();
    const list = Array.isArray(reports) ? reports : (reports.reports || []);
    document.getElementById("report-list").innerHTML =
      list.map(rp => `<option value="${escHtml(rp.filename)}">`).join("");
  } catch (e) {}
}

async function addItem() {
  const body = {
    item_type: document.getElementById("item-type").value,
    ref: document.getElementById("item-ref").value.trim(),
    label: document.getElementById("item-label").value.trim(),
  };
  if (!body.ref) { showToast("Reference is required", "error"); return; }
  const r = await fetch(`/api/cases/${CASE_ID}/items`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) { showToast("Add failed", "error"); return; }
  document.getElementById("item-ref").value = "";
  document.getElementById("item-label").value = "";
  loadCase();
}

async function removeItem(itemId) {
  await fetch(`/api/cases/${CASE_ID}/items/${itemId}`, { method: "DELETE" });
  loadCase();
}

async function generateBrief() {
  const btn = document.getElementById("btn-brief");
  btn.disabled = true;
  btn.textContent = "Generating…";
  try {
    const r = await fetch(`/api/cases/${CASE_ID}/brief`, { method: "POST" });
    const d = await r.json();
    document.getElementById("brief-view").textContent = d.brief;
    showToast("Brief generated", "success");
  } catch (e) {
    showToast("Brief failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate Brief";
  }
}

function exportCase() {
  window.location.href = `/api/cases/${CASE_ID}/export`;
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

document.addEventListener("DOMContentLoaded", () => { loadCase(); loadReportOptions(); });
