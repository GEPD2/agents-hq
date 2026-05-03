# AGENTS-HQ — Autonomous Intelligence Platform

A modular, local-first security intelligence platform built around Ollama LLMs.
All agents run fully on-device — no cloud AI, no telemetry, no external inference.
Everything is bound to `127.0.0.1`. Nothing is exposed outside localhost.

---

## Stack

| Component | Technology | Port |
|-----------|-----------|------|
| Control Panel | FastAPI + Jinja2 + vanilla JS | 8080 |
| Database | MySQL 8.4 (reports, IOCs, KB, threat actors) | 3306 |
| LLM | Ollama (deepseek-r1:8b) | 11434 |
| Workflow | n8n | 5678 |
| Proxy | nginx (routes Docker → Ollama on host) | — |
| Tor | osminogin/tor-simple | 9050 |
| Agents | Python 3.12 + http.server webhooks | 8763–8770 |

---

## Quick Start

### 1. Prerequisites

- Docker + Docker Compose
- Ollama running on the host with `deepseek-r1:8b` pulled
- (Optional) Ghidra installed if using Agent-06

```bash
ollama pull deepseek-r1:8b
```

### 2. Configure credentials

```bash
cp .env.example agent_01_osint/.env
# Edit agent_01_osint/.env — fill in your API keys
# The root .env controls MySQL passwords (docker-compose reads it)
cp .env.example .env
# Edit .env — set MYSQL_ROOT_PASSWORD and MYSQL_PASSWORD
```

### 3. Build and start

```bash
cd ~/Desktop/programming_environment/agents-hq
docker compose up --build -d
```

### 4. Open the control panel

```
http://127.0.0.1:8080
```

### 5. Verify services

```bash
curl -s http://127.0.0.1:8080/api/status   # platform health
curl -s http://127.0.0.1:5678/healthz       # n8n
curl -s http://127.0.0.1:11434/api/tags     # Ollama
```

### Stop

```bash
docker compose down
```

### Rebuild after code changes

```bash
docker compose up --build -d
```

---

## Control Panel (`/` — port 8080)

The web UI is the primary interface for the platform. All agent runs, report viewing, and configuration happen here.

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Platform health, agent status, stats, charts, activity timeline |
| Agents | `/agents` | Run agents, stream live logs via SSE, tail Docker logs |
| Reports | `/reports` | Browse all generated reports, fulltext search, delete |
| Report Viewer | `/reports/{filename}` | Rendered markdown, IOC sidebar with pivot links |
| Knowledge Base | `/kb` | Search MySQL RAG documents across all collections |
| Threat Actors | `/threat-actors` | Threat actor profiles ingested by Agent-10 |
| Settings | `/settings` | API keys, ticker watchlist, onion targets, alert channels |
| Timeline | `/timeline` | Chronological dot-plot of all reports by agent with zoom controls |
| IOC Explorer | `/iocs` | All extracted IOCs from all reports, filterable by type |
| Pivot | `/pivot/{type}/{value}` | Cross-report correlation for any IOC value |

---

## Agent Roster

| # | Agent | Status | Port | Schedule |
|---|-------|--------|------|----------|
| 01 | OSINT Collector | ✅ Built | 8765 | On-demand |
| 02 | Task Recon | ✅ Built | — | Subprocess |
| 03 | RAG Knowledge Base | ✅ Built | — | Passive store (MySQL) |
| 04 | Master Orchestrator | ✅ Built | 8764 | On-demand |
| 05 | Red Team | ✅ Built | 8763 | On-demand |
| 06 | Ghidra RE | ✅ Built | 8766 | On-demand |
| 07 | Crypto Analysis | ✅ Built | 8767 | On-demand |
| 08 | News Intel | ✅ Built | 8768 | Every 6h (n8n cron) |
| 09 | Market Intel | ✅ Built | 8769 | Daily 13:30 UTC (n8n cron) |
| 10 | Dark Web Monitor | ✅ Built | 8770 | Every 12h (n8n cron) |

### Agent-01 — OSINT Collector
Maps the public attack surface of any target type:
- **Domain** → WHOIS, DNS, crt.sh, subdomains, Wayback, reverse IP
- **IP** → Shodan, GreyNoise, Censys, AbuseIPDB, ASN/BGP, ipinfo
- **Email** → HIBP breach check, Hunter.io pattern, DNS
- **Phone** → Numverify carrier/region
- **Company** → web search, cert search, email harvest
- **Image** → EXIF/GPS extraction

Modes: `fast` (15 steps) | `deep` (25) | `adaptive` (30) | `insane` (60)

Webhook: `POST http://127.0.0.1:8765/webhook/agent01`

### Agent-02 — Task Recon
Penetration testing: `nmap` → RAG lookup → ExploitDB → NVD → report.
ReAct loop with tools: `shell`, `web_search`, `exploitdb`, `rag_lookup`, `file_write`.

### Agent-03 — RAG Knowledge Base
Passive MySQL-backed store. Not a running process.
All other agents write to it via `tools/rag_mysql.py` after each run.
Queryable at `/kb` in the control panel.

### Agent-04 — Master Orchestrator
Routes any input to the correct agent pipeline.

| Input | Pipeline |
|-------|----------|
| IP / Domain | Agent-01 → Agent-02 → Agent-03 |
| Email / Phone | Agent-01 |
| Hash | Agent-01 (VT) → Agent-06 (Ghidra) |
| File / Binary | Agent-06 → Agent-01 (IOCs) → Agent-03 |
| CVE ID | Agent-03 (RAG) → Agent-02 (NVD) |

Webhook: `POST http://127.0.0.1:8764/webhook/agent04`

### Agent-05 — Red Team
PTES methodology + MITRE ATT&CK framework.
- **Advisory mode** (webhook): full attack surface analysis, kill chain, technique mapping.
- **Active mode** (CLI only): ReAct loop with real execution — every action requires human approval (`yes`/`no` prompt, no bypass).

Webhook: `POST http://127.0.0.1:8763/webhook/agent05` (advisory only)

### Agent-06 — Ghidra RE
Full binary reverse engineering pipeline:
`binary_info` → `hash` → `VirusTotal` → `PE analysis` → `strings` → `IOC extract`
→ `Ghidra decompile` → `function map` → `YARA generate` → `RAG ingest`

Requires Ghidra installed at `$GHIDRA_PATH` (auto-detects `/opt/ghidra`).
Webhook: `POST http://127.0.0.1:8766/webhook/agent06`

### Agent-07 — Crypto Analysis
- Hash identification + cracking (hashcat GPU / john CPU fallback)
- TLS audit across all protocol versions, vuln checks (POODLE, BEAST, SWEET32…)
- X.509 certificate chain analysis
- Entropy check on binaries (flags encrypted/packed to Agent-06)

Webhook: `POST http://127.0.0.1:8767/webhook/agent07` (TLS/cert only — hash cracking requires CLI)

### Agent-08 — News Intel
30+ sources across 5 intelligence tracks (CTI feeds, CISA KEV, NVD, GovCERT, GeoInt, Patents).
Runs every 6 hours via n8n cron. Writes findings to MySQL RAG.

Webhook: `POST http://127.0.0.1:8768/webhook/agent08` with `{"since": 6}`

### Agent-09 — Market Intel
Tracks cybersecurity stocks (CRWD, PANW, S, FTNT, CYBR…), generates RSI/MACD/BB signals,
correlates market moves with threat activity from Agent-08 and Agent-10.

Webhook: `POST http://127.0.0.1:8769/webhook/agent09`

### Agent-10 — Dark Web Monitor
Monitors `.onion` sites, paste sites, and leak forums via Tor.
Extracts IOCs, builds threat actor profiles in MySQL, scores findings by severity.
Supports Tor-proxied requests: `POST {"tor": true}`.

Webhook: `POST http://127.0.0.1:8770/webhook/agent10`

---

## Data Flow

```
                    ┌──────────────────────┐
                    │    Web Control Panel │  :8080
                    │  (run / view / pivot)│
                    └──────────┬───────────┘
                               │ HTTP webhooks
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
    Agent-04             Agent-01              Agent-08/09/10
   Orchestrator         OSINT Collector         Scheduled feeds
        │                     │                      │
        ├──► Agent-01          │                      │
        ├──► Agent-02          └──► Agent-06 ◄────────┘
        ├──► Agent-05               Ghidra RE  (binary samples)
        └──► Agent-06          
                               All agents
                                   │
                                   ▼
                         MySQL (tools/rag_mysql.py)
                         ├── documents        (RAG KB)
                         ├── threat_actors    (Agent-10 profiles)
                         └── iocs             (IOC Correlation Engine)
```

---

## File Structure

```
agents-hq/
├── docker-compose.yml           All services
├── Dockerfile                   Shared agent image (Python 3.12)
├── requirements.txt             Shared agent Python deps
├── .env.example                 Template — copy to .env and agent_01_osint/.env
├── setup_stack.sh               One-command stack launcher
│
├── agent_01_osint/
│   ├── agent_01_osint_v3.py
│   └── .env                     API keys (gitignored) — shared by all agents
│
├── agent_02_task/agent.py
├── agent_03_rag/                ingest.py, query.py (legacy — MySQL is now primary)
├── agent_04_orchestrator/agent_04_orchestrator.py
├── agent_05_redteam/agent_05_redteam.py
├── agent_06_ghidra/agent_06_ghidra.py
├── agent_07_crypto/agent_07_crypto.py
├── agent_08_news_intel/agent_08_news_intel.py
├── agent_09_market_intel/agent_09_market_intel.py
├── agent_10_darkweb/agent_10_darkweb.py
│
├── tools/
│   └── rag_mysql.py             Shared RAG module — all agents import this
│
├── mysql/
│   └── init.sql                 Schema: documents, threat_actors, iocs
│
├── website/                     FastAPI control panel
│   ├── main.py
│   ├── Dockerfile
│   ├── routers/                 agents, reports, kb, settings, iocs
│   ├── services/                agent_monitor, alerter, ioc_store, mysql_client, report_parser, log_streamer
│   ├── templates/               Jinja2 HTML (base, dashboard, agents, reports, kb, threat_actors, settings, timeline, iocs, pivot)
│   └── static/                  CSS + JS (no build step, no Node.js)
│
├── runtime/
│   └── nginx-ollama.conf        Proxy config (mounted into ollama-proxy container)
│
├── n8n_workflows/               n8n workflow JSON exports
├── yara/                        YARA rules generated by Agent-06
├── reports/                     All agent output (gitignored — may contain PII)
├── memory/                      Reserved for persistent agent memory
└── models/                      Reserved for local model files
```

---

## API Keys

All keys live in `agent_01_osint/.env` (gitignored). Use the Settings page at
`http://127.0.0.1:8080/settings` to update individual keys without editing files manually.

| Key | Service | Free tier |
|-----|---------|-----------|
| `OTX_API_KEY` | AlienVault OTX | Yes |
| `FINNHUB_API_KEY` | Finnhub (market data) | Yes |
| `INTELX_API_KEY` | IntelligenceX | Yes |
| `HIBP_API_KEY` | Have I Been Pwned | Paid |
| `VT_API_KEY` | VirusTotal | Yes |
| `SHODAN_API_KEY` | Shodan | Paid |
| `GREYNOISE_API_KEY` | GreyNoise | Yes |
| `CENSYS_ID` / `CENSYS_SECRET` | Censys | Yes |
| `HUNTER_KEY` | Hunter.io | Yes |
| `URLSCAN_KEY` | urlscan.io | Yes |
| `SECURITYTRAILS_KEY` | SecurityTrails | Yes |
| `IPINFO_TOKEN` | ipinfo.io | Yes |
| `ABUSEIPDB_KEY` | AbuseIPDB | Yes |

Free / keyless sources always available: crt.sh, Wayback CDX, BGPView, HackerTarget,
DuckDuckGo, NVD NIST, ExploitDB, Shodan InternetDB.

---

## Alert System

Configure in Settings → Alert Channels. Fires on any `CRITICAL` finding after an agent run.

**Webhook** (Slack / Discord / custom): set `ALERT_WEBHOOK_URL` in `.env`.

**Email via SMTP**: set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_TO`.

Use the **Send Test** button to verify channels before relying on them.

---

## IOC Correlation

Every report viewed in the control panel automatically ingests its IOCs into MySQL.
Use **IOC Explorer** (`/iocs`) to browse all extracted indicators across all reports,
then click **Pivot ↗** on any IOC to see which other reports contain it and what
other IOCs co-occur with it in the same reports.

Bulk-ingest all existing reports at once: IOC Explorer → **Scan All Reports**.

---

## Triggering Agents Manually

Via the control panel (recommended): Agents → Run Now.

Via curl:
```bash
# OSINT on a target
curl -s -X POST http://127.0.0.1:8765/webhook/agent01 \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "mode": "deep"}'

# News intel (last 6 hours)
curl -s -X POST http://127.0.0.1:8768/webhook/agent08 \
  -H "Content-Type: application/json" \
  -d '{"since": 6}'

# Dark web monitor (via Tor)
curl -s -X POST http://127.0.0.1:8770/webhook/agent10 \
  -H "Content-Type: application/json" \
  -d '{"tor": true}'
```

---

## Hardware

```
OS:      Parrot OS (Debian-based)
CPU:     Intel i5 12th gen
RAM:     16 GB DDR4
GPU:     NVIDIA RTX 3050 Laptop 4 GB VRAM  (CUDA 12.4)
Storage: 512 GB SSD + 1 TB HDD
Docker:  v5.1.0
```
