let currentAgentId = null;
let currentJobId = null;
let sseSource = null;

async function loadAgents() {
  const container = document.getElementById("agents-container");
  try {
    const r = await fetch("/api/agents");
    const agents = await r.json();
    renderAgents(agents);
  } catch(e) {
    container.innerHTML = '<div class="empty">Failed to load agents</div>';
  }
}

function renderAgents(agents) {
  const container = document.getElementById("agents-container");
  container.innerHTML = "";
  agents.forEach(agent => {
    const section = buildAgentSection(agent);
    container.appendChild(section);
  });
}

function buildAgentSection(agent) {
  const el = document.createElement("div");
  el.id = `agent-section-${agent.id}`;
  el.className = "card mb-4";

  const dotClass = agent.status === "online" ? "online" :
                   agent.status === "running" ? "running" :
                   agent.status === "n/a" ? "na" : "offline";

  const isKb = agent.type === "kb";
  const canRun = agent.type !== "kb";

  let actionsHtml = "";
  if (isKb) {
    actionsHtml = `<a href="/kb" class="btn btn-outline btn-sm">Browse KB →</a>`;
  } else {
    actionsHtml = `
      <button class="btn btn-primary btn-sm" onclick="openRunModal('${agent.id}')" ${!canRun ? "disabled" : ""}>
        ▶ Run Now
      </button>
      <button class="btn btn-outline btn-sm" onclick="tailLogs('${agent.id}')">
        📋 Tail Logs
      </button>
    `;
  }

  el.innerHTML = `
    <div class="agent-card-header" style="margin-bottom:12px">
      <span class="agent-id">${agent.id}</span>
      <span class="agent-name">${agent.name}</span>
      <span class="agent-status-dot ${dotClass}" title="${agent.status}"></span>
      <span class="text-muted" style="font-size:11px;margin-left:4px">${agent.status}</span>
      <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
        ${actionsHtml}
      </div>
    </div>
    <div class="agent-desc mb-3">${agent.description}</div>
    <div class="agent-meta">
      ${agent.port ? `<span>Port: <span class="text-purple">${agent.port}</span></span>` : ""}
      ${agent.schedules.length ? `<span>Schedule: ${agent.schedules.join(", ")}</span>` : ""}
      ${agent.type === "subprocess" ? `<span class="badge badge-medium">subprocess</span>` : ""}
    </div>
    <div id="log-pane-${agent.id}" class="log-pane mt-3" style="display:none"></div>
  `;
  return el;
}

function openRunModal(agentId) {
  currentAgentId = agentId;
  const overlay = document.getElementById("run-modal");
  const title = document.getElementById("modal-agent-name");
  const targetRow = document.getElementById("modal-target-row");
  const sinceRow = document.getElementById("modal-since-row");
  const torRow = document.getElementById("modal-tor-row");
  const modeRow = document.getElementById("modal-mode-row");

  fetch("/api/agents").then(r => r.json()).then(agents => {
    const agent = agents.find(a => a.id === agentId);
    if (!agent) return;
    title.textContent = `Run Agent-${agentId}: ${agent.name}`;

    const params = agent.params || [];
    targetRow.style.display = params.includes("target") ? "block" : "none";
    sinceRow.style.display  = params.includes("since")  ? "block" : "none";
    torRow.style.display    = params.includes("tor")    ? "block" : "none";
    modeRow.style.display   = params.includes("mode")   ? "block" : "none";

    document.getElementById("modal-target").value = "";
    document.getElementById("modal-since").value  = "6";
    document.getElementById("modal-tor").checked  = false;
    document.getElementById("modal-mode").value   = "adaptive";

    overlay.classList.add("open");
  });
}

function closeRunModal() {
  document.getElementById("run-modal").classList.remove("open");
}

async function submitRun() {
  if (!currentAgentId) return;

  const target = document.getElementById("modal-target").value.trim();
  const since  = parseInt(document.getElementById("modal-since").value) || 6;
  const tor    = document.getElementById("modal-tor").checked;
  const mode   = document.getElementById("modal-mode").value;

  const body = { target, since, tor, mode };

  closeRunModal();
  showLogPane(currentAgentId);

  try {
    const r = await fetch(`/api/agents/${currentAgentId}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Failed to start");
    currentJobId = data.job_id;
    startLogStream(currentAgentId, data.job_id);
    showToast(`Agent-${currentAgentId} started (job ${data.job_id})`, "success");
  } catch(e) {
    appendLog(currentAgentId, `[ERROR] ${e.message}`, "error");
  }
}

function showLogPane(agentId) {
  const pane = document.getElementById(`log-pane-${agentId}`);
  if (pane) {
    pane.style.display = "block";
    pane.textContent = "";
  }
}

function appendLog(agentId, line, cls = "") {
  const pane = document.getElementById(`log-pane-${agentId}`);
  if (!pane) return;
  const span = document.createElement("span");
  if (cls) span.className = `log-${cls}`;
  span.textContent = line + "\n";
  pane.appendChild(span);
  pane.scrollTop = pane.scrollHeight;
}

function startLogStream(agentId, jobId) {
  if (sseSource) sseSource.close();
  const url = `/api/agents/${agentId}/stream?job_id=${jobId}`;
  sseSource = new EventSource(url);
  sseSource.onmessage = e => {
    const line = e.data;
    if (line === "[DONE]") {
      appendLog(agentId, "── Job complete ──", "done");
      sseSource.close();
      loadAgents();
    } else if (line === "[HEARTBEAT]") {
      // keep-alive, ignore
    } else if (line.startsWith("[ERROR]")) {
      appendLog(agentId, line, "error");
    } else {
      appendLog(agentId, line);
    }
  };
  sseSource.onerror = () => {
    appendLog(agentId, "[SSE connection closed]", "warn");
    sseSource.close();
  };
}

function tailLogs(agentId) {
  showLogPane(agentId);
  startLogStream(agentId, null);
}

function showToast(msg, type = "") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

document.addEventListener("DOMContentLoaded", () => {
  loadAgents();
  document.getElementById("run-modal").addEventListener("click", e => {
    if (e.target === document.getElementById("run-modal")) closeRunModal();
  });
});
