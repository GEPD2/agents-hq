# Agent-10 — Dark Web Monitor — Build Plan

## Overview
Underground intelligence layer. Monitors dark web sources for ransomware victims,
credential dumps, exploit sales, and threat actor activity. Builds persistent threat
actor profiles in ChromaDB and feeds IOCs and malware samples to downstream agents.

Highest-value agent in the platform.

---

## Transport Modes

At startup (interactive and one-shot), the agent **prompts the operator**:

```
[Agent-10] Transport mode:
  [1] Clearnet only  (default, no Tor required)
  [2] Tor + Clearnet (requires Tor daemon at localhost:9050)
Choice [1]:
```

Default is clearnet-only — pressing Enter skips Tor. The webhook server (`--n8n-server`)
defaults to clearnet and accepts `"tor": true` in the POST body to enable Tor per-run.

**Tor connectivity:** pure stdlib SOCKS5 implementation (~50 lines, no PySocks or
third-party deps). Graceful fallback with a warning if `localhost:9050` is unreachable.

---

## Data Sources

### Clearnet (always active — no key, no Tor required)

| Source | Endpoint | What we get |
|--------|----------|-------------|
| ransomware.live victims | `api.ransomware.live/victims` | Recent victim list: company, sector, country, group, date |
| ransomware.live groups | `api.ransomware.live/recentgroups` | Active groups with recent post counts |
| ransomware.live posts | `api.ransomware.live/posts` | Raw leak site post content |
| HIBP public breaches | `haveibeenpwned.com/api/v3/breaches` | Full breach catalog — name, domain, date, record count |
| Pastebin RSS | `pastebin.com/archive/rss` | Public pastes — filtered for creds, hashes, CVEs |
| IntelligenceX | `2.intelx.io/intelligent/search` | Dark web search (optional — `INTELX_API_KEY` in `.env`) |

### Tor mode (opt-in at startup)

| Source | What we get |
|--------|-------------|
| Ransomware group leak sites | Direct `.onion` — configurable list in `ONION_TARGETS` dict, operator-updatable |
| Dark paste sites | `.onion` pastebins (zerobin, stronghold variants) |
| Ahmia.fi via Tor | Dark web keyword search |

`ONION_TARGETS` is defined at the top of the file as a plain dict — operators add/remove
`.onion` addresses without touching logic.

---

## Tracks

```
ransomware   — ransomware.live API + direct onion leak sites (if Tor enabled)
paste        — Pastebin RSS + dark paste .onion sites (if Tor enabled)
hibp         — HIBP public breach catalog
ixapi        — IntelligenceX search (optional, free key)
onion        — Tor-only: full sweep of configured ONION_TARGETS list
```

---

## Scoring

| Score | Tier | Signal |
|-------|------|--------|
| 100 | CRITICAL | New ransomware victim matching Agent-09 watchlist companies |
| 95 | CRITICAL | Credential dump containing monitored domain(s) |
| 90 | CRITICAL | New ransomware victim (any sector, fresh post) |
| 85 | HIGH | New exploit / RAT / 0day posted for sale |
| 80 | HIGH | Ransomware group infrastructure change or rebrand |
| 65 | HIGH | New threat actor first observed |
| 50 | MEDIUM | Leaked database > 100k records |
| 30 | MEDIUM | Known group activity (no new victims) |
| 20 | LOW | General dark web chatter |

Cross-reference against Agent-09's `WATCHLIST_BY_SECTOR` at score time —
any victim company matching a watchlist ticker's company name gets bumped to 100.

---

## LLM Tools

```
extract_iocs(text)
  — Extracts: credentials (email:pass patterns), Bitcoin/ETH wallet addresses,
    .onion addresses, Telegram channels, MD5/SHA256 hashes, CVEs, IPs, domains.

rag_lookup(query)
  — Check ChromaDB for prior context on a group, victim, or IOC.

rag_ingest(text, doc_id)
  — Store intel brief or individual finding to ChromaDB.

update_threat_actor(name, data)
  — Upsert structured threat actor profile. doc_id: ta_profile_{normalized_name}.
    Accumulates across runs: victim list, TTPs, sectors, infrastructure, aliases.

file_write(filename, content)
  — Write final report to reports/DARKWEB_*.md
```

`update_threat_actor` is unique to Agent-10 — it's how persistent group profiles
are built up over time across multiple runs.

---

## Report Structure

```
# AGENTS-HQ Dark Web Intel Brief — {ts}

## Run Metadata
(transport mode, sources hit, Tor status, items collected)

## CRITICAL — New Ransomware Victims & Active Campaigns

## Credential Leaks & Data Dumps

## Exploit Marketplace (New Tools for Sale)

## Threat Actor Profiles (Updated This Run)

## Malware Samples → Agent-06 Queue

## IOCs Extracted
(wallets, hashes, .onion addresses, Telegram channels, credentials)

## Platform Recommendations
(specific Agent-01/02/05/06 action items)
```

---

## Platform Integration

| Target | Trigger | Action |
|--------|---------|--------|
| Agent-03 | Every run | Full brief + individual threat actor profiles ingested |
| Agent-06 | Malware hash/path found | Forward sample for RE and YARA generation |
| Agent-01 | New ransomware victim identified | OSINT sweep on victim domain |
| Agent-02 | Exploit for sale targeting known CVE | CVE recon on exposed assets |
| Agent-09 | Watchlist company appears as victim | Immediate CRITICAL cross-alert |

---

## Operational Details

- **Webhook port:** 8770
- **Webhook endpoint:** `/webhook/agent10`
- **n8n cron:** every 12h
- **Report filename:** `DARKWEB_{timestamp}.md`
- **Tor prompt:** shown in interactive and one-shot modes; skipped in `--n8n-server`
  (controlled via POST body `"tor": true/false`)
- **Optional API keys in `.env`:** `INTELX_API_KEY`

---

## Build Notes

- Follow exact Agent-08/09 pattern: parallel Phase 1, scoring, LLM ReAct, RAG ingest, file write
- Pure stdlib only (no third-party deps) — SOCKS5 implemented via `socket` module
- `ONION_TARGETS` dict at top of file, easy for operator to extend
- Threat actor profiles accumulate: each run merges new victims/TTPs into existing profile
