# AGENTS-HQ — Website / Control Panel Build Plan

## Overview

A unified web-based control panel for the entire AGENTS-HQ platform.
Runs locally at `http://localhost:8080`. Provides a dark-themed dashboard,
agent control panel, report browser, ChromaDB knowledge base explorer,
and real-time log streaming — all backed by a FastAPI Python server.

No build step, no Node.js, no frameworks. FastAPI backend + pure
HTML / CSS / vanilla JS frontend. Served from the same process.

---

## Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Backend | **FastAPI** (Python) | Async, WebSocket/SSE support, consistent with agent stack |
| Templating | **Jinja2** (FastAPI built-in) | Server-side HTML, no client framework needed |
| Realtime | **Server-Sent Events (SSE)** | One-way log streaming, simpler than WebSockets |
| Markdown | **marked.js** (CDN, no build) | Client-side report rendering |
| Charts | **Chart.js** (CDN, no build) | Agent run history, threat level timelines |
| Code highlight | **Prism.js** (CDN, no build) | IOC blocks, JSON output in reports |
| Styling | **Custom CSS** (dark terminal theme) | No Bootstrap dependency, full control |
| Port | **8080** | No conflict with existing stack |

---

## Pages

### 1. Dashboard  `/`
**The first thing you see. Status at a glance.**

- **Platform health bar**: live status dots for Ollama, ChromaDB, n8n, Tor, each agent webhook
- **Agent grid**: 10 cards — name, status (online / offline / running), last run timestamp, next scheduled run
- **Alert banner**: CRITICAL item count from the last report of agents 08, 09, 10
- **Recent activity feed**: last 20 report files (name + timestamp + agent type)
- **Stats row**: total reports generated, total ChromaDB documents, active ransomware groups tracked (from `ta_profile_*` count)

---

### 2. Agents  `/agents`
**Control panel — trigger, monitor, configure each agent.**

One section per agent (01 → 10), showing:
- Status indicator (green = webhook responding, red = down, yellow = running)
- Last run time and duration
- "Run Now" button → opens a modal to set parameters (target for 01/02/05/06/07, lookback for 08/09/10, Tor toggle for 10)
- "View Last Report" link
- Live log tail (last 50 lines, auto-refreshed via SSE while running)

Agent-02 note: has no webhook server — the Run Now button triggers it via
a subprocess spawned by the FastAPI server (captured stdout streamed via SSE).

Agent-03 note: displayed as "RAG Knowledge Base — not a process" with a link to `/kb`.

---

### 3. Reports  `/reports`
**Browse and read all generated markdown reports.**

- File list sorted by date (newest first), grouped by agent type:
  - `OSINT_*` → Agent-01
  - `Recon_*` → Agent-02
  - `RE_*` → Agent-06
  - `INTEL_*` → Agent-08
  - `MARKET_*` → Agent-09
  - `DARKWEB_*` → Agent-10
- Each row shows: filename, size, creation date, CRITICAL/HIGH count (parsed from report)
- Search/filter bar (client-side, by filename or content keywords)
- Click any report → opens `/reports/{filename}`

---

### 4. Report Viewer  `/reports/{filename}`
**Full rendered markdown with threat-intel enhancements.**

- Markdown rendered to HTML via marked.js
- Priority badges auto-inserted next to CRITICAL / HIGH / MEDIUM / LOW headings
- IOC auto-detection: IPs, CVEs, wallet addresses, hashes, .onion addresses highlighted
  and made copyable with a single click
- "Copy All IOCs" button → dumps all extracted IOCs to clipboard as JSON
- "Send to Agent-01" button (on OSINT-relevant reports) → pre-fills the agent trigger modal
- Raw markdown toggle (shows source)
- Print / export PDF button

---

### 5. Knowledge Base  `/kb`
**Browse and search ChromaDB.**

Two tabs:

**Search tab**
- Text input → semantic search against `security_docs` collection
- Returns top-N matching documents with source, timestamp, snippet
- Result cards link back to the original report if filename is in metadata

**Collections tab**
- List of all ChromaDB collections (name, document count, last updated)
- Per-collection document browser (paginated, 20 per page)
- Each document shows: doc_id, source, timestamp, truncated content, expand button

---

### 6. Threat Actors  `/threat-actors`
**Persistent profiles built by Agent-10's `update_threat_actor` tool.**

- Lists all `ta_profile_*` documents from ChromaDB
- Card per group: name, last updated, victim count (parsed), sectors targeted, activity level
- Click → full profile page: rendered markdown, victim timeline, known infrastructure, IOCs
- Groups color-coded by activity: red = active (last 7 days), yellow = recent (30 days), grey = dormant

---

### 7. Settings  `/settings`
**Platform configuration.**

Three sections:

**API Keys** — view (masked) / edit values in `agent_01_osint/.env`:
`OTX_API_KEY`, `FINNHUB_API_KEY`, `INTELX_API_KEY`, `HIBP_API_KEY`, `VT_API_KEY`

**Watchlist** — edit Agent-09's ticker watchlist by sector.
Edits write directly to `agent_09_market_intel/agent_09_market_intel.py`
`WATCHLIST_BY_SECTOR` (simple find-replace on the dict block).

**ONION_TARGETS** — edit Agent-10's `.onion` address dict.
Same approach — targeted file edit on the `ONION_TARGETS` block.

---

## API Endpoints (FastAPI)

```
GET  /api/status                      Platform health: all agents + Ollama + ChromaDB + Tor
GET  /api/agents                      List all agents with metadata + current health
GET  /api/agents/{id}/health          Single agent webhook health check
POST /api/agents/{id}/run             Trigger agent (body: {"target": "...", "since": 12, "tor": false, ...})
GET  /api/agents/{id}/stream          SSE: stream live stdout of a running agent job

GET  /api/reports                     List all report files (name, size, date, agent, priority_counts)
GET  /api/reports/{filename}          Report content (raw markdown text)
DELETE /api/reports/{filename}        Delete a report file

GET  /api/kb/stats                    ChromaDB: collection names + document counts
GET  /api/kb/search?q=&n=10          Semantic search (query_texts → top N docs)
GET  /api/kb/collections/{name}       List documents in a collection (paginated)
GET  /api/kb/threat-actors            List all ta_profile_* documents
GET  /api/kb/threat-actors/{name}     Single threat actor profile

GET  /api/settings                    Read current .env values (masked) + watchlist + onion targets
POST /api/settings/env                Write a single env key
POST /api/settings/watchlist          Update ticker watchlist (writes file)
POST /api/settings/onion              Update ONION_TARGETS dict (writes file)
```

---

## Real-time Log Streaming (SSE)

When a "Run Now" is triggered:
1. FastAPI spawns the agent script as a `subprocess.Popen` with `stdout=PIPE`
2. A background thread reads stdout line by line
3. Lines are pushed to a `asyncio.Queue`
4. The SSE endpoint `/api/agents/{id}/stream` consumes the queue and yields events
5. The frontend `EventSource` appends lines to the live log pane in real time
6. Stream closes when the subprocess exits (sends a `data: [DONE]` event)

For always-on agents (08, 09, 10) in `--n8n-server` mode, the SSE stream tails
`docker logs agents-agent08 --follow` instead of spawning a new process.

---

## Directory Structure

```
website/
├── main.py                  # FastAPI app, mounts static + routers
├── routers/
│   ├── agents.py            # agent health, trigger, SSE stream
│   ├── reports.py           # report list, read, delete
│   ├── kb.py                # ChromaDB search + collections + threat actors
│   └── settings.py          # .env / watchlist / onion targets
├── services/
│   ├── agent_monitor.py     # health check all webhook ports, job registry
│   ├── chroma_client.py     # thin ChromaDB HTTP wrapper
│   ├── log_streamer.py      # subprocess spawn + SSE queue
│   └── report_parser.py     # extract priority counts + IOCs from markdown
├── static/
│   ├── css/
│   │   └── style.css        # dark terminal theme (see Design section)
│   └── js/
│       ├── dashboard.js     # health polling, agent grid, activity feed
│       ├── agents.js        # run modal, SSE log pane
│       ├── reports.js       # file list, search, filter
│       ├── report_view.js   # marked.js render, IOC highlight, copy buttons
│       ├── kb.js            # search tab, collections tab
│       ├── threat_actors.js # profile cards, timeline
│       └── settings.js      # env edit, watchlist edit, onion edit
└── templates/
    ├── base.html            # nav sidebar + topbar + content slot
    ├── dashboard.html
    ├── agents.html
    ├── reports.html
    ├── report_view.html
    ├── kb.html
    ├── threat_actors.html
    └── settings.html
```

---

## Design / UI Theme

**Color palette:**

| Role | Hex | Usage |
|------|-----|-------|
| Background | `#0d0d0d` | Page background |
| Surface | `#141414` | Cards, panels |
| Border | `#262626` | Card borders, dividers |
| Purple (primary) | `#7c3aed` | Nav active, buttons, accents |
| CRITICAL | `#ef4444` | Score ≥ 80 badges |
| HIGH | `#f97316` | Score 60-79 badges |
| MEDIUM | `#eab308` | Score 30-59 badges |
| LOW | `#22c55e` | Score < 30 badges |
| Text primary | `#e5e5e5` | Body text |
| Text muted | `#6b7280` | Timestamps, metadata |
| Online | `#22c55e` | Agent status dot |
| Offline | `#ef4444` | Agent status dot |
| Running | `#f59e0b` | Agent status dot (pulsing) |

**Typography:** `JetBrains Mono` (Google Fonts) for all text — reinforces the terminal aesthetic.

**Layout:** Fixed left sidebar (240px) with nav links + platform status summary.
Main content area scrolls independently. Top bar shows current page + live CRITICAL alert count.

**Agent status dots:** 10px circle, animated pulse when agent is actively running.

---

## Docker Integration

Add to `docker-compose.yml`:

```yaml
  website:
    build:
      context: ./website
      dockerfile: Dockerfile
    image: agents-hq-website:latest
    container_name: agents-website
    restart: unless-stopped
    network_mode: host          # reach agents at localhost:8763-8770, ChromaDB at 8000
    volumes:
      - ./reports:/agents-hq/reports:ro
      - ./agent_01_osint/.env:/agents-hq/agent_01_osint/.env
      - ./agent_09_market_intel:/agents-hq/agent_09_market_intel
      - ./agent_10_darkweb:/agents-hq/agent_10_darkweb
      - /var/run/docker.sock:/var/run/docker.sock:ro  # for docker logs streaming
    depends_on:
      - chromadb
      - agent-08
      - agent-09
      - agent-10
```

**Website Dockerfile** (separate, lightweight):
```dockerfile
FROM python:3.12-slim
RUN pip install fastapi uvicorn jinja2 python-multipart aiofiles
WORKDIR /app
COPY . /app/
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

Access at: `http://localhost:8080`

---

## Build Order (Milestones)

### M1 — Skeleton + Infrastructure (Day 1)
- [ ] `website/` directory + `main.py` (FastAPI app, static mount, Jinja2)
- [ ] `base.html` layout (sidebar nav, topbar, content slot)
- [ ] `style.css` dark theme (full color palette, typography, components)
- [ ] `GET /api/status` — health check all webhook ports + ChromaDB + Ollama
- [ ] Dashboard page (agent grid with live health dots, placeholder cards)

### M2 — Agent Control (Day 2)
- [ ] `routers/agents.py` — health, trigger, SSE stream
- [ ] `services/agent_monitor.py` + `services/log_streamer.py`
- [ ] Agents page (cards, Run Now modal, live log pane via SSE)
- [ ] Agent-02 subprocess execution via FastAPI

### M3 — Reports (Day 3)
- [ ] `routers/reports.py` — list, read, delete
- [ ] `services/report_parser.py` — priority counts + IOC extraction from markdown
- [ ] Reports list page (grouped by agent, sortable, searchable)
- [ ] Report viewer (marked.js render, IOC highlights, copy buttons)

### M4 — Knowledge Base (Day 4)
- [ ] `services/chroma_client.py` — search, list collections, get documents
- [ ] `routers/kb.py` — all KB endpoints
- [ ] Knowledge Base page (search tab + collections tab)
- [ ] Threat Actors page (profile cards, full profile view)

### M5 — Settings + Polish (Day 5)
- [ ] `routers/settings.py` — read/write .env, watchlist, onion targets
- [ ] Settings page (masked API keys, editable watchlist, onion targets)
- [ ] Charts: agent run history (Chart.js), threat level over time
- [ ] Docker service added to docker-compose.yml
- [ ] Final dark theme polish, mobile-friendly adjustments

---

## Access

```
http://localhost:8080              Dashboard
http://localhost:8080/agents       Agent control panel
http://localhost:8080/reports      Report browser
http://localhost:8080/kb           Knowledge base
http://localhost:8080/threat-actors Threat actor profiles
http://localhost:8080/settings     Settings
http://localhost:8080/docs         FastAPI auto-docs (dev only)
```
