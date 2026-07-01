#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-08 News Intel v1

Scheduled threat intelligence aggregator. No target required — sweeps 30+ sources
every 6 hours and keeps the entire platform current on the threat landscape.

Five intelligence tracks:
  1. CTI          — Check Point, Talos, Unit 42, Securelist, MSRC, CrowdStrike,
                    BleepingComputer, THN, SANS ISC, Packet Storm, Krebs, SecurityWeek
  2. CISA/NVD/OTX — CISA KEV (JSON API), NVD REST API, AlienVault OTX pulses
  3. GovInt       — NSA, NCSC UK, ANSSI France, BSI Germany, CERT-EU, ENISA,
                    FBI Cyber, ACSC Australia, Five Eyes joint advisories
  4. GeoInt       — ISW, Bellingcat, War on the Rocks, CSIS, Reuters Security
  5. Patents      — USPTO PatentsView API (security-relevant filings)

Pipeline:
  Phase 1 — Collect  (Python, parallel threads): fetch all feeds, parse, deduplicate
  Phase 2 — Analyze  (LLM ReAct loop): score, classify, extract IOCs, write intel brief
  Phase 3 — Persist  (Python): rag_ingest critical items, file_write final report

Usage:
  python3 agent_08_news_intel.py                   # one-shot, 6h lookback
  python3 agent_08_news_intel.py --since 24        # 24h lookback
  python3 agent_08_news_intel.py --tracks cti,gov  # specific tracks only
  python3 agent_08_news_intel.py --interactive
  python3 agent_08_news_intel.py --n8n-server
"""

import sys, json, re, os, time, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import email.utils

# ── Config ─────────────────────────────────────────────────────
OLLAMA_HOST           = "localhost"
OLLAMA_PORT           = 11434
AGENT_MODEL           = "qwen2.5:14b"
CHROMA_HOST           = "localhost"
CHROMA_PORT           = 8000
REPORTS_DIR           = Path(__file__).parent.parent / "reports"
N8N_WEBHOOK_PORT      = int(os.environ.get("N8N_WEBHOOK_PORT", "8768"))
MAX_ITERATIONS        = 12
DEFAULT_LOOKBACK_HOURS = 6
MAX_ITEMS_FOR_LLM     = 45     # scored items passed to LLM after noise filter
TIMEOUT_HTTP          = 15
PATENT_LOOKBACK_DAYS  = 30     # patents filed slowly — wider window
MAX_FETCH_WORKERS     = 14

# ── ANSI Colors ─────────────────────────────────────────────────
C_HEAD  = "\033[38;5;208m"   # orange   — agent identity
C_PHASE = "\033[38;5;220m"   # yellow   — phase headers
C_TOOL  = "\033[38;5;226m"   # bright   — tool calls
C_OBS   = "\033[38;5;82m"    # green    — observations
C_THINK = "\033[38;5;244m"   # grey     — LLM thinking
C_WARN  = "\033[38;5;196m"   # red      — warnings
C_CRIT  = "\033[38;5;201m"   # magenta  — critical findings
C_RESET = "\033[0m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── Env / API keys ───────────────────────────────────────────────
def load_env():
    for candidate in [
        Path(__file__).parent / ".env",
        Path(__file__).parent.parent / "agent_01_osint" / ".env",
    ]:
        if candidate.exists():
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())
            break

load_env()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  FEED REGISTRY
# ══════════════════════════════════════════════════════════════
RSS_FEEDS = {
    # Track: Cyber Threat Intelligence
    "cti": {
        "Check Point Research":   "https://research.checkpoint.com/feed/",
        "Cisco Talos":            "https://blog.talosintelligence.com/rss/",
        "Palo Alto Unit 42":      "https://unit42.paloaltonetworks.com/feed/",
        "Securelist":             "https://securelist.com/feed/",
        "Microsoft MSRC":         "https://msrc.microsoft.com/blog/feed/",
        "CrowdStrike Blog":       "https://www.crowdstrike.com/blog/feed/",
        "BleepingComputer":       "https://www.bleepingcomputer.com/feed/",
        "The Hacker News":        "https://feeds.feedburner.com/TheHackersNews",
        "SANS ISC":               "https://isc.sans.edu/rssfeed_full.xml",
        "Packet Storm":           "https://rss.packetstormsecurity.com/files/",
        "Krebs on Security":      "https://krebsonsecurity.com/feed/",
        "SecurityWeek":           "https://www.securityweek.com/feed",
        "Dark Reading":           "https://www.darkreading.com/rss.xml",
    },
    # Track: Government / Intelligence Agencies
    "gov": {
        "CISA Advisories":        "https://www.cisa.gov/cybersecurity-advisories/feed",
        "NCSC UK":                "https://www.ncsc.gov.uk/api/1/services/v1/all-guidance-rss.xml",
        "ANSSI France":           "https://www.cert.ssi.gouv.fr/feed/",
        "BSI Germany":            "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSS_Cybersicherheitsempfehlungen.xml",
        "CERT-EU":                "https://cert.europa.eu/publications/security-advisories/rss.xml",
        "ENISA":                  "https://www.enisa.europa.eu/publications/rss",
        "FBI Cyber Alerts":       "https://www.ic3.gov/RSS/IC3Alerts.aspx",
        "US-CERT Alerts":         "https://www.cisa.gov/uscert/ncas/alerts/feed",
        "AusCERT":                "https://www.auscert.org.au/resources/security-bulletins/rss/",
    },
    # Track: Geopolitical / Conflict Intelligence
    "geo": {
        "ISW":                    "https://www.understandingwar.org/news-feed",
        "Bellingcat":             "https://www.bellingcat.com/feed/",
        "War on the Rocks":       "https://warontherocks.com/feed/",
        "CSIS":                   "https://www.csis.org/rss.xml",
        "Reuters Security":       "https://feeds.reuters.com/reuters/cybersecurityNews",
        "AP Security":            "https://rsshub.app/ap/topics/apf-topnews",
    },
}

# Scoring keyword rules — highest match wins per item
SCORE_RULES = [
    (100, ["actively exploited", "zero-day", "0-day", "in the wild",
           "emergency directive", "five eyes", "joint advisory",
           "critical infrastructure attack", "nation-state attack",
           "immediate patching", "mass exploitation"]),
    (80,  ["nation-state", "state-sponsored", "apt", "advanced persistent threat",
           "remote code execution", "unauthenticated rce", "ransomware campaign",
           "supply chain compromise", "backdoor discovered", "war", "military cyber",
           "cyber warfare", "critical vulnerability"]),
    (60,  ["cvss 9", "cvss 10", "cvss: 9", "cvss: 10", "authentication bypass",
           "privilege escalation", "firmware vulnerability", "ics attack",
           "scada vulnerability", "geopolitical", "conflict escalation",
           "intelligence agency", "nsa", "gchq", "fsb", "apt28", "apt29",
           "lazarus", "sandworm", "cozy bear", "fancy bear"]),
    (40,  ["high severity", "cvss 7", "cvss 8", "malware", "phishing campaign",
           "data breach", "critical patch", "security advisory",
           "exploit released", "poc published", "proof of concept"]),
    (20,  ["vulnerability", "patch tuesday", "advisory", "security update",
           "exploit", "cve-", "threat actor", "campaign"]),
    (10,  ["patent", "research", "analysis", "report", "whitepaper"]),
]

# IOC extraction patterns
_IP_RE      = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_CVE_RE     = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_MD5_RE     = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA256_RE  = re.compile(r'\b[0-9a-fA-F]{64}\b')
_DOMAIN_RE  = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:onion|ru|cn|ir|kp|su|xyz|top|tk)\b'
)
_PRIVATE_IP = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)'
)


# ══════════════════════════════════════════════════════════════
#  DATE PARSING (RSS 2.0 and Atom formats)
# ══════════════════════════════════════════════════════════════
def parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    date_str = date_str.strip()
    # RFC 2822 (RSS 2.0): "Mon, 01 Jan 2024 12:00:00 +0000"
    try:
        ts = email.utils.parsedate_to_datetime(date_str)
        return ts.astimezone(timezone.utc)
    except Exception:
        pass
    # ISO 8601 (Atom): "2024-01-01T12:00:00Z" or "2024-01-01T12:00:00+00:00"
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:len(fmt)+2], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


# ══════════════════════════════════════════════════════════════
#  RSS / ATOM PARSER
# ══════════════════════════════════════════════════════════════
ATOM_NS = "{http://www.w3.org/2005/Atom}"

def _strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', ' ', text or '').strip()[:600]

def parse_feed_xml(content: str, source_name: str, track: str,
                   lookback_hours: int) -> list[dict]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    items  = []
    tag    = root.tag

    if "rss" in tag or root.find("channel") is not None:
        # RSS 2.0
        channel = root.find("channel") or root
        for item in channel.findall("item"):
            title    = _strip_html(item.findtext("title") or "")
            link     = (item.findtext("link") or "").strip()
            summary  = _strip_html(item.findtext("description") or "")
            pub      = parse_date(item.findtext("pubDate") or "")
            if pub and pub < cutoff:
                continue
            if not title:
                continue
            items.append({
                "title":   title,
                "url":     link,
                "summary": summary,
                "source":  source_name,
                "date":    pub.isoformat() if pub else "",
                "track":   track,
                "score":   0,
            })

    elif ATOM_NS + "feed" in tag or "feed" in tag:
        # Atom
        pfx = ATOM_NS if tag.startswith(ATOM_NS) else ""
        for entry in root.findall(f"{pfx}entry"):
            title   = _strip_html(entry.findtext(f"{pfx}title") or "")
            summary = _strip_html(
                entry.findtext(f"{pfx}summary") or
                entry.findtext(f"{pfx}content") or ""
            )
            link_el = entry.find(f"{pfx}link")
            link    = (link_el.attrib.get("href") if link_el is not None else "") or ""
            updated = parse_date(entry.findtext(f"{pfx}updated") or
                                 entry.findtext(f"{pfx}published") or "")
            if updated and updated < cutoff:
                continue
            if not title:
                continue
            items.append({
                "title":   title,
                "url":     link,
                "summary": summary,
                "source":  source_name,
                "date":    updated.isoformat() if updated else "",
                "track":   track,
                "score":   0,
            })

    return items


# ══════════════════════════════════════════════════════════════
#  PHASE 1 — DATA COLLECTORS
# ══════════════════════════════════════════════════════════════
def _http_get(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "agents-hq/1.0 (security research platform)",
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP) as r:
        return r.read()


def collect_rss_feed(source_name: str, url: str, track: str,
                     lookback_hours: int) -> list[dict]:
    try:
        raw = _http_get(url).decode("utf-8", errors="replace")
        return parse_feed_xml(raw, source_name, track, lookback_hours)
    except Exception:
        return []


def collect_cisa_kev(lookback_hours: int) -> list[dict]:
    """CISA Known Exploited Vulnerabilities catalog."""
    try:
        raw  = _http_get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        data = json.loads(raw)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        items  = []
        for v in data.get("vulnerabilities", []):
            date_added = parse_date(v.get("dateAdded", ""))
            if date_added and date_added < cutoff:
                continue
            cve_id   = v.get("cveID", "")
            product  = v.get("product", "")
            vendor   = v.get("vendorProject", "")
            desc     = v.get("shortDescription", "")
            items.append({
                "title":   f"[KEV] {cve_id} — {vendor} {product}",
                "url":     f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "summary": desc[:500],
                "source":  "CISA KEV",
                "date":    date_added.isoformat() if date_added else "",
                "track":   "kev",
                "score":   100,   # KEV entries are always CRITICAL
            })
        return items
    except Exception:
        return []


def collect_nvd_recent(lookback_hours: int) -> list[dict]:
    """NVD 2.0 API — recently published/modified CVEs."""
    try:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=lookback_hours)
        fmt   = "%Y-%m-%dT%H:%M:%S.000"
        url   = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
            "&resultsPerPage=50"
        )
        raw  = _http_get(url)
        data = json.loads(raw)
        items = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

            # CVSS score
            metrics = cve.get("metrics", {})
            score_val = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score_val = float(
                        metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                    )
                    break

            published = parse_date(cve.get("published", ""))
            items.append({
                "title":   f"{cve_id} (CVSS {score_val:.1f})",
                "url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": desc[:500],
                "source":  "NVD/NIST",
                "date":    published.isoformat() if published else "",
                "track":   "nvd",
                "score":   0,
                "cvss":    score_val,
            })
        return items
    except Exception:
        return []


def collect_otx_pulses(lookback_hours: int) -> list[dict]:
    """AlienVault OTX pulse feed."""
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key:
        return []
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
                 ).strftime('%Y-%m-%dT%H:%M:%S')
        url   = (f"https://otx.alienvault.com/api/v1/pulses/subscribed"
                 f"?modified_since={since}&limit=25")
        raw   = _http_get(url, headers={"X-OTX-API-KEY": api_key})
        data  = json.loads(raw)
        items = []
        for pulse in data.get("results", []):
            name    = pulse.get("name", "")
            tags    = ", ".join(pulse.get("tags", [])[:5])
            tlp     = pulse.get("tlp", "white")
            desc    = pulse.get("description", "")[:400]
            ioc_cnt = pulse.get("indicator_count", 0)
            items.append({
                "title":   f"[OTX] {name}",
                "url":     f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                "summary": f"TLP:{tlp.upper()} | Tags: {tags} | IOCs: {ioc_cnt} | {desc}",
                "source":  "AlienVault OTX",
                "date":    pulse.get("modified", ""),
                "track":   "otx",
                "score":   0,
            })
        return items
    except Exception:
        return []


def collect_patents(lookback_days: int = PATENT_LOOKBACK_DAYS) -> list[dict]:
    """USPTO PatentsView API — recent security-relevant patents."""
    end_date   = datetime.now().strftime('%Y-%m-%d')
    start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')

    # Rotate through keywords to stay within API limits
    keyword_groups = [
        "vulnerability exploitation",
        "zero-day exploit",
        "side-channel attack",
        "cryptographic weakness",
        "malware detection evasion",
        "firmware security",
        "network intrusion detection",
    ]

    results = []
    for kw in keyword_groups:
        try:
            query = json.dumps({
                "_and": [
                    {"_text_phrase": {"patent_abstract": kw}},
                    {"_gte": {"patent_date": start_date}},
                    {"_lte": {"patent_date": end_date}},
                ]
            })
            fields = json.dumps([
                "patent_number", "patent_title", "patent_date",
                "patent_abstract", "assignee_organization",
            ])
            opts = json.dumps({"per_page": 5})
            url  = (
                "https://api.patentsview.org/patents/query"
                f"?q={urllib.parse.quote(query)}"
                f"&f={urllib.parse.quote(fields)}"
                f"&o={urllib.parse.quote(opts)}"
            )
            raw   = _http_get(url)
            data  = json.loads(raw)
            for p in (data.get("patents") or []):
                num      = p.get("patent_number", "")
                title    = p.get("patent_title", "")
                assignee = (p.get("assignee_organization") or [{}])
                assignee_name = assignee[0].get("assignee_organization", "Unknown") \
                    if isinstance(assignee, list) and assignee else "Unknown"
                abstract = (p.get("patent_abstract") or "")[:400]
                results.append({
                    "title":   f"[PATENT] {title} ({assignee_name})",
                    "url":     f"https://patents.google.com/patent/US{num}",
                    "summary": f"Keyword: '{kw}' | {abstract}",
                    "source":  "USPTO Patents",
                    "date":    p.get("patent_date", ""),
                    "track":   "patents",
                    "score":   0,
                })
        except Exception:
            pass

    return results


def collect_all(lookback_hours: int, enabled_tracks: set | None = None) -> list[dict]:
    """Run all collectors in parallel, return merged item list."""
    cprint(C_PHASE, "\n[PHASE 1] Collecting intelligence feeds...")
    tasks = []

    if enabled_tracks is None or "kev" in enabled_tracks:
        tasks.append(("collect_cisa_kev", lambda: collect_cisa_kev(lookback_hours)))
    if enabled_tracks is None or "nvd" in enabled_tracks:
        tasks.append(("collect_nvd", lambda: collect_nvd_recent(lookback_hours)))
    if enabled_tracks is None or "otx" in enabled_tracks:
        tasks.append(("collect_otx", lambda: collect_otx_pulses(lookback_hours)))
    if enabled_tracks is None or "patents" in enabled_tracks:
        tasks.append(("collect_patents", lambda: collect_patents(PATENT_LOOKBACK_DAYS)))

    for track_key, feeds in RSS_FEEDS.items():
        if enabled_tracks and track_key not in enabled_tracks:
            continue
        for name, url in feeds.items():
            feed_name = name
            feed_url  = url
            track     = track_key
            tasks.append((
                f"rss:{feed_name}",
                lambda n=feed_name, u=feed_url, t=track: collect_rss_feed(n, u, t, lookback_hours)
            ))

    all_items: list[dict] = []
    lock = threading.Lock()

    def run_task(label_fn):
        label, fn = label_fn
        try:
            result = fn()
            with lock:
                all_items.extend(result)
            cprint(C_OBS, f"  ✓ {label}: {len(result)} item(s)")
        except Exception as e:
            cprint(C_WARN, f"  ✗ {label}: {e}")

    with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as pool:
        list(pool.map(run_task, tasks))

    cprint(C_PHASE, f"[PHASE 1] Collected {len(all_items)} raw items from {len(tasks)} sources.")
    return all_items


# ══════════════════════════════════════════════════════════════
#  SCORING + DEDUPLICATION
# ══════════════════════════════════════════════════════════════
def score_item(item: dict) -> int:
    text = (item.get("title", "") + " " + item.get("summary", "")).lower()

    # KEV items are always CRITICAL
    if item.get("track") == "kev":
        return 100

    # NVD: score by CVSS
    if item.get("track") == "nvd":
        cvss = float(item.get("cvss", 0))
        if cvss >= 9.0:
            return 90
        if cvss >= 7.0:
            return 60
        if cvss >= 4.0:
            return 30
        return 10

    # Keyword scoring
    for score, keywords in SCORE_RULES:
        if any(kw in text for kw in keywords):
            return score

    return 5


def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    out  = []
    for item in items:
        # Dedup key: hash of normalized title
        key = hashlib.md5(item.get("title", "").lower().strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def score_and_filter(items: list[dict], max_items: int = MAX_ITEMS_FOR_LLM) -> list[dict]:
    """Score, deduplicate, and filter to top N most relevant items."""
    deduped = deduplicate(items)
    for item in deduped:
        item["score"] = score_item(item)

    sorted_items = sorted(deduped, key=lambda x: x["score"], reverse=True)
    result = sorted_items[:max_items]

    # Count by priority tier
    critical = sum(1 for i in result if i["score"] >= 80)
    high     = sum(1 for i in result if 60 <= i["score"] < 80)
    medium   = sum(1 for i in result if 30 <= i["score"] < 60)
    low      = sum(1 for i in result if i["score"] < 30)
    cprint(C_PHASE,
           f"[FILTER] {len(deduped)} unique → top {len(result)} | "
           f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} LOW:{low}")
    return result


# ══════════════════════════════════════════════════════════════
#  TOOL: IOC EXTRACTION
# ══════════════════════════════════════════════════════════════
def tool_extract_iocs(text: str) -> str:
    cprint(C_TOOL, f"  [EXTRACT_IOCS] {len(text)} chars")
    raw_ips   = _IP_RE.findall(text)
    ips       = list({ip for ip in raw_ips if not _PRIVATE_IP.match(ip)})[:20]
    cves      = list(set(_CVE_RE.findall(text)))[:20]
    md5s      = list(set(_MD5_RE.findall(text)))[:10]
    sha256s   = list(set(_SHA256_RE.findall(text)))[:10]
    domains   = list(set(_DOMAIN_RE.findall(text)))[:15]

    parts = []
    if cves:    parts.append(f"CVEs: {', '.join(cves)}")
    if ips:     parts.append(f"IPs: {', '.join(ips[:10])}")
    if domains: parts.append(f"Domains: {', '.join(domains[:8])}")
    if md5s:    parts.append(f"MD5: {', '.join(md5s[:5])}")
    if sha256s: parts.append(f"SHA256: {', '.join(sha256s[:5])}")

    if not parts:
        return "[EXTRACT_IOCS] No IOCs found in provided text."
    return "[EXTRACT_IOCS] Extracted:\n" + "\n".join(f"  {p}" for p in parts)


# ══════════════════════════════════════════════════════════════
#  TOOL: RAG LOOKUP / INGEST
# ══════════════════════════════════════════════════════════════
def tool_rag_lookup(query: str) -> str:
    cprint(C_TOOL, f"  [RAG_LOOKUP] {query[:60]}")
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    from rag_mysql import rag_lookup
    return rag_lookup(query)


def tool_rag_ingest(text: str, doc_id: str | None = None) -> str:
    cprint(C_TOOL, f"  [RAG_INGEST] {len(text)} chars")
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    from rag_mysql import rag_ingest
    return rag_ingest(text, source="agent08_news_intel", doc_id=doc_id)


# ══════════════════════════════════════════════════════════════
#  TOOL: FILE WRITE
# ══════════════════════════════════════════════════════════════
def tool_file_write(filename: str, content: str) -> str:
    cprint(C_TOOL, f"  [FILE_WRITE] {filename}")
    out_path = REPORTS_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)
    return f"[FILE_WRITE] Written: {out_path}"


# ══════════════════════════════════════════════════════════════
#  TOOL DISPATCHER (Phase 2 — LLM tools only)
# ══════════════════════════════════════════════════════════════
TOOL_SCHEMA = [
    {
        "name": "rag_lookup",
        "description": "Check if a CVE, threat actor, or campaign is already in the knowledge base.",
        "parameters": {"query": "Search string (e.g. CVE-2024-12345 or 'APT29 phishing')."}
    },
    {
        "name": "extract_iocs",
        "description": "Extract IPs, domains, CVE IDs, and hashes from a block of text.",
        "parameters": {"text": "Raw text to extract IOCs from."}
    },
    {
        "name": "rag_ingest",
        "description": "Store critical findings into the ChromaDB knowledge base for other agents.",
        "parameters": {
            "text":   "Content to store.",
            "doc_id": "Optional document ID."
        }
    },
    {
        "name": "file_write",
        "description": "Write the final structured intelligence report to the reports/ directory.",
        "parameters": {
            "filename": "Report filename (e.g. INTEL_20250101_120000.md).",
            "content":  "Full report content in Markdown."
        }
    },
]


def dispatch_tool(name: str, params: dict) -> str:
    if name == "rag_lookup":
        return tool_rag_lookup(params.get("query", ""))
    elif name == "extract_iocs":
        return tool_extract_iocs(params.get("text", ""))
    elif name == "rag_ingest":
        return tool_rag_ingest(params.get("text", ""), params.get("doc_id"))
    elif name == "file_write":
        return tool_file_write(params.get("filename", "intel.md"), params.get("content", ""))
    return f"[DISPATCH] Unknown tool: {name}"


# ══════════════════════════════════════════════════════════════
#  OLLAMA CALL
# ══════════════════════════════════════════════════════════════
def ollama_call(messages: list[dict], stream: bool = True) -> str:
    payload = json.dumps({
        "model":    AGENT_MODEL,
        "messages": messages,
        "stream":   stream,
    }).encode()
    req = urllib.request.Request(
        f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat",
        data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    full_text = ""
    try:
        with urllib.request.urlopen(req, timeout=240) as resp:
            for raw_line in resp:
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    obj   = json.loads(line)
                    token = obj.get("message", {}).get("content", "")
                    full_text += token
                    if stream:
                        print(token, end="", flush=True)
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        return f"[OLLAMA] Error: {e}"
    if stream:
        print()
    return full_text


# ══════════════════════════════════════════════════════════════
#  PHASE 2 — LLM ANALYSIS (ReAct loop)
# ══════════════════════════════════════════════════════════════
def _format_items_for_llm(items: list[dict]) -> str:
    lines = []
    for i, item in enumerate(items, 1):
        score  = item.get("score", 0)
        track  = item.get("track", "")
        source = item.get("source", "")
        title  = item.get("title", "")
        url    = item.get("url", "")
        summ   = item.get("summary", "")[:300]
        date   = item.get("date", "")[:10]

        priority = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 30 else "LOW"
        )
        lines.append(
            f"[{i:02d}] [{priority}] [{track.upper()}] {source} | {date}\n"
            f"     Title  : {title}\n"
            f"     Summary: {summ}\n"
            f"     URL    : {url}"
        )
    return "\n\n".join(lines)


def build_system_prompt(lookback_hours: int, item_count: int, ts: str) -> str:
    tool_docs = "\n".join(
        f"  {t['name']}({', '.join(t['parameters'].keys())}) — {t['description']}"
        for t in TOOL_SCHEMA
    )
    return f"""You are Agent-08 — the threat intelligence analyst for the AGENTS-HQ security platform.

Run timestamp : {ts}
Lookback      : last {lookback_hours} hours
Items provided: {item_count} (pre-scored and ranked)

Your mission: analyze the collected intelligence items and produce a structured threat intelligence brief.

Available tools:
{tool_docs}

ReAct format — follow exactly:
  THOUGHT: <your reasoning>
  ACTION: <tool_name>
  PARAMS: <JSON object>

Conclude with:
  FINAL: <one-paragraph executive summary for the operator>

Your analysis workflow:
  1. For any CRITICAL or HIGH item you don't recognize, call rag_lookup to check the KB.
  2. Call extract_iocs on any item containing IP addresses, domain names, or hash values.
  3. Compose the full intelligence report (in FINAL or as content for file_write).
  4. Call rag_ingest with the complete brief (so other agents can access it).
  5. Call file_write with the full structured report.

Report structure to produce:
  # AGENTS-HQ Intelligence Brief — {ts}
  ## Run Metadata
  ## CRITICAL — Actively Exploited / Emergency Advisories
  ## HIGH — Critical Vulnerabilities & Active Campaigns
  ## Threat Actor Activity (OTX + vendor reports)
  ## Government & Agency Advisories
  ## Geopolitical Context (conflicts → nation-state cyber activity)
  ## Notable Patent Filings
  ## IOCs Extracted
  ## Platform Recommendations (what Agent-02/05/06 should act on)

Rules:
  1. Do not repeat a tool call with identical parameters.
  2. CRITICAL items must all appear in the report, even if the KB already has them.
  3. Patents section: note assignee, filing date, and why it matters offensively or defensively.
  4. Geopolitical items: explain the cyber nexus — why does this conflict event matter for threat actors?
  5. Platform Recommendations should be specific: "Run Agent-02 against X", "Forward hash Y to Agent-06".
  6. Report filename: INTEL_{ts.replace('-','').replace(':','').replace(' ','_')[:15]}.md
"""


def parse_action(text: str) -> tuple[str | None, dict | None]:
    action_m = re.search(r"ACTION:\s*(\w+)", text, re.IGNORECASE)
    params_m = re.search(r"PARAMS:\s*(\{.*?\})", text, re.DOTALL | re.IGNORECASE)
    if not action_m:
        return None, None
    tool_name = action_m.group(1).strip()
    params    = {}
    if params_m:
        try:
            params = json.loads(params_m.group(1))
        except json.JSONDecodeError:
            for m in re.finditer(r'"(\w+)"\s*:\s*"([^"]*)"', params_m.group(1)):
                params[m.group(1)] = m.group(2)
    return tool_name, params


def analyze_with_llm(scored_items: list[dict], lookback_hours: int) -> str:
    cprint(C_PHASE, "\n[PHASE 2] LLM analysis...")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    formatted = _format_items_for_llm(scored_items)
    system_prompt = build_system_prompt(lookback_hours, len(scored_items), ts)

    messages = [
        {"role": "system",  "content": system_prompt},
        {"role": "user",
         "content": f"Here are the {len(scored_items)} scored intelligence items:\n\n{formatted}\n\nBegin analysis."},
    ]

    iteration      = 0
    action_history = []
    final_output   = ""

    while iteration < MAX_ITERATIONS:
        iteration += 1
        cprint(C_PHASE, f"\n── Iteration {iteration}/{MAX_ITERATIONS} ──────────────────")
        cprint(C_THINK, "  [LLM] Analyzing...")

        response = ollama_call(messages, stream=True)
        messages.append({"role": "assistant", "content": response})

        if "FINAL:" in response:
            fm = re.search(r"FINAL:\s*(.*)", response, re.DOTALL)
            if fm:
                final_output = fm.group(1).strip()
            cprint(C_OBS, "\n[✓] Analysis complete.")
            break

        tool_name, params = parse_action(response)
        if not tool_name:
            messages.append({
                "role":    "user",
                "content": "No ACTION found. Continue with next THOUGHT/ACTION/PARAMS or emit FINAL.",
            })
            continue

        action_key = f"{tool_name}:{json.dumps(params, sort_keys=True)}"
        if action_history.count(action_key) >= 2:
            observation = f"[LOOP_GUARD] '{tool_name}' already called with these params. Choose a different action or emit FINAL."
        else:
            action_history.append(action_key)
            cprint(C_TOOL, f"\n  → {tool_name}({params})")
            observation = dispatch_tool(tool_name, params)

        cprint(C_OBS, f"\n  [OBS] {observation[:400]}{'...' if len(observation)>400 else ''}")
        messages.append({"role": "user", "content": f"OBSERVATION: {observation}"})

    else:
        cprint(C_WARN, f"\n[!] Max iterations reached.")
        final_output = "[Agent-08] Analysis complete. See report in reports/ directory."

    return final_output


# ══════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════
def run_pipeline(lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
                 enabled_tracks: set | None = None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cprint(C_HEAD, f"\n{'='*64}")
    cprint(C_HEAD, f"  AGENT-08 — NEWS INTEL")
    cprint(C_HEAD, f"  Lookback : {lookback_hours}h  |  Started : {ts}")
    cprint(C_HEAD, f"{'='*64}")

    # Phase 1: collect
    raw_items    = collect_all(lookback_hours, enabled_tracks)
    scored_items = score_and_filter(raw_items)

    if not scored_items:
        cprint(C_WARN, "[!] No items collected. Check network / feeds.")
        return "No items collected."

    # Phase 2: LLM analysis
    summary = analyze_with_llm(scored_items, lookback_hours)

    cprint(C_HEAD, f"\n[DONE] Run complete at {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
    return summary


# ══════════════════════════════════════════════════════════════
#  INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════
def interactive_mode():
    cprint(C_HEAD, "\n══════════════════════════════════════════════")
    cprint(C_HEAD, "  AGENT-08 — NEWS INTEL  [interactive]")
    cprint(C_HEAD, "══════════════════════════════════════════════")
    print("  Type 'exit' to quit.\n")

    while True:
        try:
            since_str = input(f"{C_PHASE}  Lookback hours [default: {DEFAULT_LOOKBACK_HOURS}] > {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if since_str.lower() in ("exit", "quit"):
            break

        tracks_str = input(
            f"{C_PHASE}  Tracks [cti/gov/geo/kev/nvd/otx/patents or Enter for all] > {C_RESET}"
        ).strip()

        try:
            lookback_hours = int(since_str) if since_str else DEFAULT_LOOKBACK_HOURS
        except ValueError:
            lookback_hours = DEFAULT_LOOKBACK_HOURS

        enabled_tracks = (
            set(t.strip() for t in tracks_str.split(",") if t.strip())
            if tracks_str else None
        )

        run_pipeline(lookback_hours, enabled_tracks)


# ══════════════════════════════════════════════════════════════
#  N8N WEBHOOK SERVER  (n8n cron triggers this every 6 hours)
# ══════════════════════════════════════════════════════════════
def start_webhook_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != "/webhook/agent08":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data  = json.loads(body) if body else {}
            except Exception:
                data = {}

            lookback = int(data.get("since", DEFAULT_LOOKBACK_HOURS))
            tracks_raw = data.get("tracks", None)
            enabled_tracks = (
                set(t.strip() for t in tracks_raw.split(",") if t.strip())
                if isinstance(tracks_raw, str) and tracks_raw else None
            )

            def run():
                run_pipeline(lookback, enabled_tracks)
            threading.Thread(target=run, daemon=True).start()

            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status":   "accepted",
                "lookback": lookback,
                "tracks":   list(enabled_tracks) if enabled_tracks else "all",
                "message":  "Agent-08 started. Check reports/ for INTEL_*.md output.",
            }).encode())

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok","agent":"agent08"}')
            else:
                self.send_error(404)

    server = HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler)
    cprint(C_HEAD, f"\n[WEBHOOK] Agent-08 on http://127.0.0.1:{N8N_WEBHOOK_PORT}/webhook/agent08")
    cprint(C_HEAD,  '  POST {"since": 6}                    — run with 6h lookback')
    cprint(C_HEAD,  '  POST {"since": 24, "tracks": "cti"}  — 24h, CTI track only')
    cprint(C_HEAD,  '  GET  /health                         — liveness check\n')
    server.serve_forever()


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Agent-08 — News Intel (threat intelligence aggregator)"
    )
    parser.add_argument("--since",       type=int, default=DEFAULT_LOOKBACK_HOURS,
                        help="Lookback window in hours (default: 6)")
    parser.add_argument("--tracks",      default=None,
                        help="Comma-separated tracks: cti,gov,geo,kev,nvd,otx,patents")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--n8n-server",  action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        start_webhook_server()
        return

    if args.interactive:
        interactive_mode()
        return

    enabled_tracks = (
        set(t.strip() for t in args.tracks.split(",") if t.strip())
        if args.tracks else None
    )
    run_pipeline(args.since, enabled_tracks)


if __name__ == "__main__":
    main()
