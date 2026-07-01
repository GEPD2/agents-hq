let batchSource = null;

function loadFile(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { document.getElementById("batch-targets").value = reader.result; };
  reader.readAsText(file);
}

async function startBatch() {
  const targets = document.getElementById("batch-targets").value;
  const mode = document.getElementById("batch-mode").value;
  if (!targets.trim()) { showToast("Enter at least one target", "error"); return; }

  const btn = document.getElementById("btn-batch-start");
  btn.disabled = true;
  btn.textContent = "Starting…";
  try {
    const r = await fetch("/api/batch/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets, mode }),
    });
    if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    const d = await r.json();
    beginTracking(d.batch_id, d.total);
  } catch (e) {
    showToast("Batch failed: " + e.message, "error");
    btn.disabled = false;
    btn.textContent = "Start Batch";
  }
}

function beginTracking(batchId, total) {
  document.getElementById("batch-progress-card").style.display = "";
  document.getElementById("batch-log-card").style.display = "";
  document.getElementById("batch-results-tbody").innerHTML = "";
  document.getElementById("batch-log").innerHTML = "";
  setProgress(0, total);

  if (batchSource) batchSource.close();
  batchSource = new EventSource(`/api/batch/${batchId}/stream`);
  batchSource.onmessage = (e) => {
    if (e.data === "[HEARTBEAT]") return;
    if (e.data === "[DONE]") {
      batchSource.close();
      refreshStatus(batchId, true);
      const btn = document.getElementById("btn-batch-start");
      btn.disabled = false;
      btn.textContent = "Start Batch";
      showToast("Batch complete", "success");
      return;
    }
    appendLog(e.data);
    if (e.data.startsWith("[BATCH]")) refreshStatus(batchId, false);
  };
  batchSource.onerror = () => { appendLog("[stream closed]"); };
}

async function refreshStatus(batchId, final) {
  try {
    const r = await fetch(`/api/batch/${batchId}/status`);
    const s = await r.json();
    setProgress(s.completed, s.total);
    renderResults(s);
  } catch (e) {}
}

function setProgress(done, total) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  document.getElementById("batch-progress-fill").style.width = pct + "%";
  document.getElementById("batch-progress-label").textContent = `${done} / ${total}`;
}

function renderResults(s) {
  const tbody = document.getElementById("batch-results-tbody");
  const rows = s.results.map((r, i) => {
    const link = r.report
      ? `<a href="/reports/${encodeURIComponent(r.report)}" class="btn btn-outline btn-sm">View ↗</a>`
      : "—";
    const cls = r.status === "done" ? "log-done" : (r.status === "error" ? "log-error" : "");
    return `<tr>
      <td>${i + 1}</td>
      <td style="font-family:monospace;font-size:11px">${escHtml(r.target)}</td>
      <td class="${cls}">${r.status}</td>
      <td>${link}</td>
    </tr>`;
  });
  if (!s.done && s.completed < s.total) {
    const running = s.results.length;
    if (s.index < s.total) {
      rows.push(`<tr><td>${running + 1}</td><td style="font-family:monospace;font-size:11px">running…</td><td><span class="spinner"></span></td><td>—</td></tr>`);
    }
  }
  tbody.innerHTML = rows.join("");
}

function appendLog(line) {
  const pane = document.getElementById("batch-log");
  const div = document.createElement("div");
  if (/error|fail/i.test(line)) div.className = "log-error";
  else if (line.startsWith("[BATCH]")) div.className = "log-done";
  div.textContent = line;
  pane.appendChild(div);
  pane.scrollTop = pane.scrollHeight;
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
