# AGENTS-HQ — Future Updates Roadmap

## Completed Updates

### Infrastructure
- [x] FastAPI website control panel (`website/`) — dashboard, agents, reports, KB, threat actors, settings
- [x] MySQL replacing ChromaDB — stable storage, fulltext search, no container instability
- [x] Shared `tools/rag_mysql.py` — all agents (01, 08, 09, 10) write to MySQL after each run
- [x] Agent-10 threat actor profiles stored in `threat_actors` MySQL table
- [x] Log rotation — 10 MB × 5 files per container across all services
- [x] `.env` / `.env.example` — MySQL credentials externalized from docker-compose
- [x] `GET /health` handlers added to agents 01, 04, 05, 06, 07

### Website
- [x] Dashboard Chart.js charts — Reports by Agent (bar) + Priority Distribution (doughnut)
- [x] Report content search — fulltext search across file content, debounced
- [x] "ChromaDB" labels replaced with "MySQL" throughout UI
- [x] Settings page — HIBP key hint with signup link

---

## Planned Updates

### Priority 1 — Intelligence Graph (Palantir-style)

**Page:** `/graph`
**Library:** Cytoscape.js (purpose-built for network/link analysis)

Force-directed network graph built from IOCs extracted across all reports and agent runs.

**Nodes (by type):**
- 🔴 IP address
- 🟠 Domain / URL
- 🟡 Email address
- 🟣 Threat actor
- 🔵 CVE
- ⚫ Hash (MD5 / SHA1 / SHA256)
- 🟤 Wallet address (BTC / ETH)
- 🕸️ .onion address

**Edges:**
- Co-occurrence in the same report
- Shared infrastructure (same IP → multiple domains)
- Same victim across multiple threat actor profiles
- Same CVE referenced by multiple agents

**Interactions:**
- Click node → pivot panel opens (all connected entities + which reports they appear in)
- Double-click → open most recent report containing that node
- Filter by node type, agent source, date range
- Color intensity = frequency (more reports = brighter node)
- Export visible graph as PNG

**Backend:** New `/api/graph` endpoint reads IOC data from MySQL, returns nodes + edges JSON

---

### ~~Priority 2 — IOC Correlation Engine~~ ✅ DONE

**Page:** `/pivot/{ioc_type}/{value}` (e.g. `/pivot/ip/185.220.101.5`)

Foundational for the graph — stores extracted IOCs in a dedicated MySQL table and enables cross-report pivoting.

**Schema addition:**
```sql
CREATE TABLE iocs (
    id           VARCHAR(255) PRIMARY KEY,
    type         ENUM('ip','domain','email','hash','cve','onion','wallet'),
    value        VARCHAR(500) NOT NULL,
    report_file  VARCHAR(500),
    agent_id     VARCHAR(10),
    first_seen   DATETIME,
    last_seen    DATETIME,
    count        INT DEFAULT 1,
    INDEX idx_value (value(100)),
    INDEX idx_type  (type)
);
```

**Flow:**
1. Agent completes a run → `report_parser.py` extracts IOCs → stored in `iocs` table
2. Report viewer "Find Correlations" button → hits `/pivot` endpoint
3. Pivot page shows: all reports containing this IOC, related IOCs (same reports), timeline of appearances

**New API endpoints:**
```
GET /api/iocs                       List all IOCs (paginated, filterable by type)
GET /api/iocs/{type}/{value}        Single IOC detail + all reports that contain it
GET /api/iocs/correlate/{value}     IOCs that co-occur with this value
POST /api/iocs/ingest/{filename}    Extract + store IOCs from a report file
```

---

### ~~Priority 3 — Threat Activity Timeline~~ ✅ DONE

**Location:** Dashboard (third row below charts) + standalone `/timeline` page

Horizontal scrollable timeline showing all agent activity chronologically.

**Features:**
- Each report = one dot on the timeline, colored by agent
- CRITICAL findings = red pulsing marker
- Zoom: day / week / month / all-time
- Click event → open report
- Hover → tooltip with filename, agent, priority counts
- Group rows by agent (OSINT row, DarkWeb row, Intel row, etc.)

**Implementation:** Pure JS + SVG, no additional library needed. Data from `/api/reports`.

---

### Priority 4 — Geolocation Map

**Page:** `/map` (or tab within `/graph`)
**Library:** Leaflet.js (CDN, ~40KB)

World map plotting IPs extracted from all reports.

**Features:**
- Cluster markers — click to expand and list reports
- Heatmap overlay toggle (concentration of threat activity)
- Sidebar: top 10 countries by IOC count
- Filter by agent, date range
- IP geolocation via `ipinfo.io` API (key already in `.env`)

**Backend:**
```
GET /api/map/ips     Returns [{ip, lat, lon, country, reports:[...]}]
```
Geocoding cached in MySQL to avoid repeated API calls.

---

### ~~Priority 5 — Alert System~~ ✅ DONE

**Location:** Settings page (new "Alerts" section)

Push notifications when any agent run produces CRITICAL findings.

**Channels:**
- Webhook (Slack / Discord / custom HTTP POST)
- Email via SMTP (configurable host/port/credentials)

**Trigger:** After every `/api/agents/{id}/run` completes, if `CRITICAL > 0` in the generated report → fire alert with report filename, agent name, CRITICAL count, and a direct link to the report viewer.

**Settings fields:**
```
ALERT_WEBHOOK_URL    = https://hooks.slack.com/...
SMTP_HOST            = smtp.gmail.com
SMTP_PORT            = 587
SMTP_USER            = alerts@example.com
SMTP_PASSWORD        = ...
ALERT_EMAIL_TO       = analyst@example.com
```

---

### Priority 6 — Market × Security Correlation

**Location:** New tab on Agent-09 report viewer or `/market-intel` page

Correlate Agent-09 (stock prices) with Agent-08 (threat intel) and Agent-10 (ransomware activity).

**Chart:** Dual-axis Chart.js line chart
- Left axis: stock price (CRWD, PANW, S)
- Right axis: CVE severity score / ransomware victim count
- Overlay markers: CVE disclosure dates, ransomware attack dates, breach announcements

**Value:** Visualizes the market impact of security events on cybersecurity stocks.

---

### Priority 7 — Case Files

**Page:** `/cases`

Group related intelligence into named investigations.

**Features:**
- Create case: name, description, tags, assigned agents
- Drag reports, IOC pivot results, threat actor profiles into a case
- Case overview page renders a consolidated markdown brief auto-generated by Ollama
- Cases stored in MySQL (`cases` + `case_items` tables)
- Export case as ZIP (all linked reports + auto-brief)

---

### Priority 8 — Batch OSINT

**Location:** Agent-01 "Run Now" modal — new "Batch" tab

Upload a `.txt` file (one target per line) or paste a list → Agent-01 runs sequentially on each target, all reports linked to the batch run ID.

**Features:**
- Progress bar showing X/N completed
- Live log pane streams current target's output
- Batch summary report auto-generated when all targets complete
- Useful for: checking a list of company emails, scanning a subnet, profiling a set of domains

---

## Technical Notes

- **Graph library:** Cytoscape.js preferred over D3 for link analysis — better performance on large graphs, built-in layouts (cola, cose-bilkent), native click/hover events
- **Map library:** Leaflet.js — lightweight, no API key needed for OpenStreetMap tiles
- **No new Python dependencies needed** for priorities 1–4 — all data already in MySQL
- **IOC table** is the shared foundation for graph, correlation, and map — build it first

---

## Stack Reference

| Component | Technology | Port |
|-----------|-----------|------|
| Website   | FastAPI + Jinja2 + vanilla JS | 8080 |
| Database  | MySQL 8.4 | 3306 |
| LLM       | Ollama (deepseek-r1:8b) | 11434 |
| Workflow  | n8n | 5678 |
| Proxy     | nginx | — |
| Tor       | osminogin/tor-simple | 9050 |
| Agents    | Python 3.12 + http.server webhooks | 8763–8770 |
