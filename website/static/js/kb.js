let collections = [];
let currentCollection = null;
let currentOffset = 0;
const PAGE_SIZE = 20;

async function loadKbStats() {
  try {
    const r = await fetch("/api/kb/stats");
    collections = await r.json();
    renderCollectionList();
  } catch(e) {
    document.getElementById("collections-list").innerHTML = '<div class="empty">Failed to load collections</div>';
  }
}

function renderCollectionList() {
  const el = document.getElementById("collections-list");
  if (!collections.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">🗄️</div>No MySQL collections found</div>';
    return;
  }
  el.innerHTML = collections.map(c => `
    <div class="card mb-3" style="cursor:pointer" onclick="browseCollection('${c.name}')">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <span class="text-purple" style="font-weight:600">${c.name}</span>
        <span class="badge badge-low">${c.count} docs</span>
      </div>
      <div class="text-muted mt-1" style="font-size:11px">ID: ${c.id}</div>
    </div>
  `).join("");
}

async function browseCollection(name) {
  currentCollection = name;
  currentOffset = 0;
  document.getElementById("browse-title").textContent = `Collection: ${name}`;
  document.getElementById("browse-panel").style.display = "block";
  await loadPage();
}

async function loadPage() {
  const container = document.getElementById("browse-docs");
  container.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
  try {
    const r = await fetch(`/api/kb/collections/${encodeURIComponent(currentCollection)}?offset=${currentOffset}&limit=${PAGE_SIZE}`);
    const data = await r.json();
    renderDocs(data.documents, data.total);
    renderPager(data.total);
  } catch(e) {
    container.innerHTML = `<div class="empty text-critical">Error: ${e.message}</div>`;
  }
}

function renderDocs(docs, total) {
  const container = document.getElementById("browse-docs");
  if (!docs.length) {
    container.innerHTML = '<div class="empty">No documents</div>';
    return;
  }
  container.innerHTML = docs.map((doc, i) => `
    <div class="search-result">
      <div class="search-result-meta">
        <span class="text-purple">#${currentOffset + i + 1}</span>
        <span>Source: ${doc.source || "unknown"}</span>
        <span>${doc.timestamp || ""}</span>
      </div>
      <div class="search-result-content" id="doc-${i}">
        ${escHtml(doc.content?.slice(0, 300) || "")}${doc.content?.length > 300 ? "…" : ""}
      </div>
      ${doc.content?.length > 300 ? `<button class="btn btn-outline btn-sm mt-2" onclick="expandDoc(${i}, ${JSON.stringify(doc.content).replace(/</g,'&lt;')})">Expand</button>` : ""}
    </div>
  `).join("");
}

function expandDoc(i, content) {
  const el = document.getElementById(`doc-${i}`);
  if (el) el.textContent = content;
}

function renderPager(total) {
  const pager = document.getElementById("browse-pager");
  const pages = Math.ceil(total / PAGE_SIZE);
  const current = Math.floor(currentOffset / PAGE_SIZE) + 1;
  pager.innerHTML = `
    <span class="text-muted" style="font-size:11px">Page ${current} of ${pages} (${total} docs)</span>
    <button class="btn btn-outline btn-sm" onclick="prevPage()" ${currentOffset === 0 ? "disabled" : ""}>← Prev</button>
    <button class="btn btn-outline btn-sm" onclick="nextPage()" ${currentOffset + PAGE_SIZE >= total ? "disabled" : ""}>Next →</button>
  `;
}

function prevPage() {
  if (currentOffset > 0) { currentOffset -= PAGE_SIZE; loadPage(); }
}

function nextPage() {
  currentOffset += PAGE_SIZE; loadPage();
}

async function doSearch() {
  const q = document.getElementById("search-q").value.trim();
  const n = parseInt(document.getElementById("search-n").value) || 10;
  if (!q) return;

  const container = document.getElementById("search-results");
  container.innerHTML = '<div class="empty"><span class="spinner"></span> Searching...</div>';

  try {
    const r = await fetch(`/api/kb/search?q=${encodeURIComponent(q)}&n=${n}`);
    const results = await r.json();
    renderSearchResults(results, q);
  } catch(e) {
    container.innerHTML = `<div class="empty text-critical">Error: ${e.message}</div>`;
  }
}

function renderSearchResults(results, q) {
  const container = document.getElementById("search-results");
  if (!results.length) {
    container.innerHTML = '<div class="empty">No results found</div>';
    return;
  }
  container.innerHTML = results.map((r, i) => `
    <div class="search-result">
      <div class="search-result-meta">
        <span class="search-result-dist">score: ${r.distance ?? "?"}</span>
        <span>Source: ${escHtml(r.source || "unknown")}</span>
        <span>${r.timestamp || ""}</span>
        ${r.metadata?.filename ? `<a href="/reports/${encodeURIComponent(r.metadata.filename)}" class="text-purple">View Report</a>` : ""}
      </div>
      <div class="search-result-content">${highlight(escHtml(r.content?.slice(0, 500) || ""), q)}${r.content?.length > 500 ? "…" : ""}</div>
    </div>
  `).join("");
}

function highlight(html, q) {
  if (!q) return html;
  const words = q.split(/\s+/).filter(Boolean);
  words.forEach(w => {
    const re = new RegExp(`(${w.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, "gi");
    html = html.replace(re, '<mark style="background:rgba(124,58,237,0.3);color:var(--text);border-radius:2px">$1</mark>');
  });
  return html;
}

function escHtml(str) {
  if (!str) return "";
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function switchTab(tab, btn) {
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`tab-${tab}`)?.classList.add("active");
  btn.classList.add("active");
}

document.addEventListener("DOMContentLoaded", () => {
  loadKbStats();
  document.getElementById("search-q")?.addEventListener("keydown", e => {
    if (e.key === "Enter") doSearch();
  });
});
