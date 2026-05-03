let rawMarkdown = "";
let extractedIocs = {};
let showingRaw = false;

const IOC_PATTERNS = {
  ip:     /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  cve:    /\bCVE-\d{4}-\d{4,7}\b/gi,
  hash:   /\b[a-fA-F0-9]{32,64}\b/g,
  onion:  /\b[a-z2-7]{16,56}\.onion\b/gi,
  wallet: /\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
};

const PRIORITY_COLORS = {
  CRITICAL: "badge-critical",
  HIGH:     "badge-high",
  MEDIUM:   "badge-medium",
  LOW:      "badge-low",
};

async function loadReport(filename) {
  const contentEl = document.getElementById("report-content");
  const titleEl   = document.getElementById("report-title");

  titleEl.textContent = filename;
  contentEl.innerHTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span></div>';

  try {
    const r = await fetch(`/api/reports/${encodeURIComponent(filename)}`);
    if (!r.ok) throw new Error("Report not found");
    rawMarkdown = await r.text();
    renderMarkdown();
    parseIocs();
    renderIocPanel();
    // lazy ingest into IOC correlation engine (background, non-blocking)
    fetch(`/api/iocs/ingest/${encodeURIComponent(filename)}`, { method: "POST" }).catch(() => {});
  } catch(e) {
    contentEl.innerHTML = `<div class="empty text-critical">${e.message}</div>`;
  }
}

function renderMarkdown() {
  const contentEl = document.getElementById("report-content");
  if (showingRaw) {
    contentEl.innerHTML = `<pre style="white-space:pre-wrap;word-break:break-all;font-size:12px;color:var(--text)">${escHtml(rawMarkdown)}</pre>`;
    return;
  }
  const html = marked.parse(rawMarkdown, { breaks: true, gfm: true });
  contentEl.innerHTML = `<div class="report-content">${html}</div>`;
  injectPriorityBadges();
  highlightIocsInContent();
}

function injectPriorityBadges() {
  const content = document.querySelector(".report-content");
  if (!content) return;
  content.querySelectorAll("h1,h2,h3,h4").forEach(h => {
    const text = h.textContent.toUpperCase();
    for (const [level, cls] of Object.entries(PRIORITY_COLORS)) {
      if (text.includes(level)) {
        const badge = document.createElement("span");
        badge.className = `badge ${cls}`;
        badge.style.marginLeft = "8px";
        badge.style.verticalAlign = "middle";
        badge.textContent = level;
        h.appendChild(badge);
        break;
      }
    }
  });
}

function highlightIocsInContent() {
  const content = document.querySelector(".report-content");
  if (!content) return;
  // Walk text nodes and wrap IOCs
  const walker = document.createTreeWalker(content, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentNode;
      if (!parent) return NodeFilter.FILTER_REJECT;
      const tag = parent.tagName?.toLowerCase();
      if (["code", "pre", "script", "style"].includes(tag)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);

  nodes.forEach(node => {
    let text = node.textContent;
    let replaced = false;

    // Only handle CVE and onion to avoid false positives
    const patterns = [
      { re: /\bCVE-\d{4}-\d{4,7}\b/gi, cls: "ioc-cve" },
      { re: /\b[a-z2-7]{16,56}\.onion\b/gi, cls: "ioc-onion" },
    ];

    let result = text;
    let hasMatch = false;
    const frag = document.createDocumentFragment();
    let lastIdx = 0;
    const combinedRe = /\bCVE-\d{4}-\d{4,7}\b|\b[a-z2-7]{16,56}\.onion\b/gi;
    let m;
    while ((m = combinedRe.exec(text)) !== null) {
      hasMatch = true;
      if (m.index > lastIdx) frag.appendChild(document.createTextNode(text.slice(lastIdx, m.index)));
      const span = document.createElement("span");
      span.className = "ioc-tag " + (m[0].match(/CVE/i) ? "ioc-cve" : "ioc-onion");
      span.textContent = m[0];
      span.title = "Click to copy";
      span.addEventListener("click", () => navigator.clipboard.writeText(m[0]));
      frag.appendChild(span);
      lastIdx = m.index + m[0].length;
    }
    if (hasMatch) {
      if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
      node.parentNode.replaceChild(frag, node);
    }
  });
}

function parseIocs() {
  extractedIocs = {};
  for (const [type, re] of Object.entries(IOC_PATTERNS)) {
    re.lastIndex = 0;
    const matches = [...rawMarkdown.matchAll(re)].map(m => m[0]);
    const unique = [...new Set(matches)];
    if (unique.length) extractedIocs[type] = unique;
  }
}

function renderIocPanel() {
  const panel = document.getElementById("ioc-panel");
  const count = document.getElementById("ioc-count");
  const total = Object.values(extractedIocs).reduce((s, a) => s + a.length, 0);
  if (count) count.textContent = total;
  if (!panel) return;
  if (total === 0) {
    panel.innerHTML = '<div class="text-muted" style="font-size:11px">No IOCs detected</div>';
    return;
  }

  const labels = { ip: "IPs", cve: "CVEs", hash: "Hashes", onion: "Onions", wallet: "Wallets", domain: "Domains" };
  panel.innerHTML = Object.entries(extractedIocs).map(([type, iocs]) => `
    <div class="mb-3">
      <div style="font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;margin-bottom:5px">
        ${labels[type] || type} (${iocs.length})
      </div>
      <div>${iocs.map(ioc => {
        const pivotUrl = `/pivot/${encodeURIComponent(type)}/${encodeURIComponent(ioc)}`;
        return `<span style="display:inline-flex;align-items:center;gap:2px;margin:2px">
          <span class="ioc-tag ioc-${type}" onclick="navigator.clipboard.writeText('${ioc.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}');showCopied(this)" title="Click to copy" style="margin:0">${escHtml(ioc)}</span><a href="${pivotUrl}" class="ioc-pivot-link" title="Pivot — find correlations">↗</a>
        </span>`;
      }).join("")}</div>
    </div>
  `).join("");
}

function showCopied(el) {
  const orig = el.textContent;
  el.textContent = "✓ copied";
  setTimeout(() => el.textContent = orig, 1200);
}

function copyAllIocs() {
  const json = JSON.stringify(extractedIocs, null, 2);
  navigator.clipboard.writeText(json).then(() => showToast("All IOCs copied as JSON", "success"));
}

function toggleRaw() {
  showingRaw = !showingRaw;
  const btn = document.getElementById("btn-raw");
  if (btn) btn.textContent = showingRaw ? "Rendered" : "Raw";
  renderMarkdown();
}

function printReport() {
  window.print();
}

function escHtml(str) {
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function showToast(msg, type="") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

document.addEventListener("DOMContentLoaded", () => {
  const filename = document.getElementById("report-filename")?.dataset?.filename;
  if (filename) loadReport(filename);
});
