function tok(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function nodeColors() {
  return {
    ip: tok("--ioc-ip"), domain: tok("--ioc-domain"), email: tok("--ioc-email"),
    actor: tok("--accent"), cve: tok("--ioc-cve"), hash: tok("--ioc-hash"),
    wallet: tok("--ioc-wallet"), onion: tok("--ioc-onion"),
  };
}

let cy = null;

function buildStyle() {
  const colors = nodeColors();
  const accent = tok("--accent");
  return [
    {
      selector: "node",
      style: {
        "background-color": ele => colors[ele.data("ntype")] || tok("--muted"),
        "label": "data(label)",
        "color": tok("--text"),
        "font-size": "22px",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 6,
        "width": ele => 50 + Math.min(ele.data("count") * 7, 80),
        "height": ele => 50 + Math.min(ele.data("count") * 7, 80),
        "border-width": 1,
        "border-color": tok("--bg"),
      },
    },
    {
      selector: "edge",
      style: {
        "width": ele => Math.min(1 + ele.data("weight"), 5),
        "line-color": ele => ele.data("etype") === "actor" ? accent : tok("--border-strong"),
        "curve-style": "haystack",
        "opacity": 0.6,
      },
    },
    { selector: "node:selected", style: { "border-width": 3, "border-color": accent } },
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
    const data = await HUD.fetchJSON(`/api/graph?${params}`);
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
    layout: {
      // Deterministic n-gon: the shown nodes sit evenly on one ring, so the
      // node count sets the corners (3 = triangle, 4 = square, ... n-gon) and
      // the shape is stable on every filter/reload, no physics, no hand-dragging.
      name: "circle",
      animate: false,
      padding: 60,
      spacingFactor: 2.2,
      startAngle: -Math.PI / 2,
      sort: (a, b) => {
        const ta = a.data("ntype") || "", tb = b.data("ntype") || "";
        if (ta !== tb) return ta < tb ? -1 : 1;
        return (b.data("count") || 0) - (a.data("count") || 0);
      },
    },
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
  const png = cy.png({ full: true, bg: tok("--bg"), scale: 2 });
  const a = document.createElement("a");
  a.href = png;
  a.download = "intelligence_graph.png";
  a.click();
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", loadGraph);
window.addEventListener("themechange", () => { if (cy) cy.style(buildStyle()); });
