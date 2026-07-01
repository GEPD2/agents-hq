const NODE_COLORS = {
  ip: "#ef4444", domain: "#f97316", email: "#eab308", actor: "#7c3aed",
  cve: "#3b82f6", hash: "#9ca3af", wallet: "#92400e", onion: "#06b6d4",
};

let cy = null;

function buildStyle() {
  return [
    {
      selector: "node",
      style: {
        "background-color": ele => NODE_COLORS[ele.data("ntype")] || "#6b7280",
        "label": "data(label)",
        "color": "#e5e5e5",
        "font-size": "8px",
        "text-valign": "bottom",
        "text-halign": "center",
        "width": ele => 10 + Math.min(ele.data("count") * 3, 30),
        "height": ele => 10 + Math.min(ele.data("count") * 3, 30),
        "border-width": 1,
        "border-color": "#0d0d0d",
      },
    },
    {
      selector: "edge",
      style: {
        "width": ele => Math.min(1 + ele.data("weight"), 5),
        "line-color": ele => ele.data("etype") === "actor" ? "#7c3aed" : "#3f3f46",
        "curve-style": "haystack",
        "opacity": 0.6,
      },
    },
    { selector: "node:selected", style: { "border-width": 3, "border-color": "#7c3aed" } },
    { selector: ".faded", style: { "opacity": 0.12 } },
  ];
}

async function loadGraph() {
  const status = document.getElementById("graph-status");
  status.textContent = "Loading…";
  const type = document.getElementById("graph-type").value;
  const days = document.getElementById("graph-days").value;
  const params = new URLSearchParams();
  if (type) params.set("type", type);
  if (days) params.set("days", days);
  try {
    const r = await fetch(`/api/graph?${params}`);
    const data = await r.json();
    render(data);
    status.textContent = `${data.nodes.length} nodes · ${data.edges.length} edges`
      + (data.truncated ? ` (top ${data.nodes.length} of ${data.total_nodes})` : "");
  } catch (e) {
    status.textContent = "Error: " + e.message;
  }
}

function render(data) {
  if (cy) cy.destroy();
  cy = cytoscape({
    container: document.getElementById("cy"),
    elements: { nodes: data.nodes, edges: data.edges },
    style: buildStyle(),
    layout: { name: "cose", animate: false, nodeRepulsion: 6000, idealEdgeLength: 60 },
    wheelSensitivity: 0.2,
  });

  cy.on("tap", "node", evt => showPivot(evt.target));
  cy.on("dbltap", "node", evt => {
    const d = evt.target.data();
    if (d.ntype !== "actor") {
      const [t, ...rest] = d.id.split(":");
      window.location.href = `/pivot/${encodeURIComponent(t)}/${encodeURIComponent(rest.join(":"))}`;
    }
  });
  cy.on("tap", evt => { if (evt.target === cy) cy.elements().removeClass("faded"); });
}

function showPivot(node) {
  cy.elements().addClass("faded");
  const neighborhood = node.closedNeighborhood();
  neighborhood.removeClass("faded");

  const d = node.data();
  const neighbors = node.neighborhood("node").map(n => n.data());
  const rows = neighbors.slice(0, 40).map(n =>
    `<tr><td><span class="ioc-tag">${n.ntype}</span></td>
     <td style="font-family:monospace;font-size:11px">${escHtml(n.label)}</td></tr>`).join("");

  let pivotLink = "";
  if (d.ntype !== "actor") {
    const [t, ...rest] = d.id.split(":");
    pivotLink = `<a href="/pivot/${encodeURIComponent(t)}/${encodeURIComponent(rest.join(":"))}"
      class="btn btn-outline btn-sm" style="margin-top:8px">Open Pivot ↗</a>`;
  }

  document.getElementById("pivot-body").innerHTML = `
    <div style="margin-bottom:8px">
      <span class="ioc-tag">${d.ntype}</span>
      <div style="font-family:monospace;font-size:11px;margin-top:4px;word-break:break-all">${escHtml(d.label)}</div>
      <div class="text-muted" style="font-size:11px;margin-top:4px">${d.count} report(s) · ${neighbors.length} connected</div>
    </div>
    ${pivotLink}
    <table class="table" style="width:100%;margin-top:10px"><tbody>${rows || '<tr><td class="text-muted">No connections</td></tr>'}</tbody></table>`;
}

function exportPng() {
  if (!cy) return;
  const png = cy.png({ full: true, bg: "#0d0d0d", scale: 2 });
  const a = document.createElement("a");
  a.href = png;
  a.download = "intelligence_graph.png";
  a.click();
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", loadGraph);
