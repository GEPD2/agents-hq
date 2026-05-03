#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-10 Dark Web Monitor v1

Underground intelligence layer. Monitors dark web sources for ransomware victims,
credential dumps, exploit sales, and threat actor activity. Builds persistent threat
actor profiles in ChromaDB across runs and feeds IOCs and malware samples downstream.

Highest-value agent in the platform.

Five intelligence tracks:
  1. ransomware  — ransomware.live API (victims, groups, posts) + direct .onion leak sites
  2. paste       — Pastebin RSS (credential/hash filter) + dark paste .onion sites via Tor
  3. hibp        — Have I Been Pwned public breach catalog
  4. ixapi       — IntelligenceX dark web search (optional — INTELX_API_KEY in .env)
  5. onion       — Tor-only: direct sweep of operator-configured ONION_TARGETS

Transport modes (prompted at startup in interactive and one-shot runs):
  [1] Clearnet only  — default, no Tor required
  [2] Tor + Clearnet — requires Tor daemon at localhost:9050

Tor connectivity uses a pure stdlib SOCKS5 implementation (no third-party deps).
Graceful fallback to clearnet-only if the daemon is unreachable.

Pipeline:
  Phase 1 — Collect  (parallel threads): ransomware.live, HIBP, Pastebin, IntelX, Tor
  Phase 2 — Score    (Python): anomaly scoring, watchlist cross-reference, dedup
  Phase 3 — Analyze  (LLM ReAct): IOC extraction, threat actor profile updates, report
  Phase 4 — Persist  (Python): RAG ingest + file write

Usage:
  python3 agent_10_darkweb.py                     # one-shot, prompts for Tor
  python3 agent_10_darkweb.py --tor               # one-shot, Tor enabled (skip prompt)
  python3 agent_10_darkweb.py --no-tor            # one-shot, clearnet only (skip prompt)
  python3 agent_10_darkweb.py --since 24          # 24h lookback
  python3 agent_10_darkweb.py --tracks ransomware,hibp
  python3 agent_10_darkweb.py --interactive
  python3 agent_10_darkweb.py --n8n-server
"""

import sys, json, re, os, hashlib, struct, socket, time
import ssl
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import email.utils

# ── Config ───────────────────────────────────────────────────────────────────
OLLAMA_HOST           = "localhost"
OLLAMA_PORT           = 11434
AGENT_MODEL           = "deepseek-r1:8b"
CHROMA_HOST           = "localhost"
CHROMA_PORT           = 8000
REPORTS_DIR           = Path(__file__).parent.parent / "reports"
N8N_WEBHOOK_PORT      = int(os.environ.get("N8N_WEBHOOK_PORT", "8770"))
MAX_ITERATIONS        = 14
DEFAULT_LOOKBACK_HOURS = 12
MAX_ITEMS_FOR_LLM     = 45
TIMEOUT_CLEARNET      = 20
TIMEOUT_TOR           = 45
TOR_PROXY_HOST        = "127.0.0.1"
TOR_PROXY_PORT        = 9050
MAX_FETCH_WORKERS     = 8

# ── ANSI Colors ───────────────────────────────────────────────────────────────
C_HEAD  = "\033[38;5;129m"   # purple   — agent identity
C_PHASE = "\033[38;5;220m"   # yellow   — phase headers
C_TOOL  = "\033[38;5;226m"   # bright   — tool calls
C_OBS   = "\033[38;5;82m"    # green    — observations
C_THINK = "\033[38;5;244m"   # grey     — LLM thinking
C_WARN  = "\033[38;5;196m"   # red      — warnings
C_CRIT  = "\033[38;5;201m"   # magenta  — critical findings
C_TOR   = "\033[38;5;51m"    # cyan     — Tor status
C_RESET = "\033[0m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C_RESET}", end=end, flush=True)

# ── Env / API keys ───────────────────────────────────────────────────────────
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

# ── Onion targets (operator-maintained) ──────────────────────────────────────
# Add/remove .onion addresses here as groups rebrand or get taken down.
# These are publicly documented by security researchers (Recorded Future, Unit42, etc.)
# Verify addresses before use — they change frequently.
ONION_TARGETS: dict[str, str] = {
    # "GroupName": "address.onion",
}

# Ahmia dark web search — accessible via Tor
AHMIA_ONION   = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
AHMIA_QUERIES = [
    "ransomware new victim",
    "database leak sale",
    "zero day exploit sale",
    "credentials combo list",
    "malware source code",
]

# ── Agent-09 watchlist cross-reference ───────────────────────────────────────
# Company name fragments to match against ransomware victim names.
# Keep lowercase. Add client domains / targets as needed.
WATCHLIST_NAMES = {
    "microsoft", "google", "alphabet", "meta", "amazon", "apple", "nvidia",
    "salesforce", "oracle", "ibm", "crowdstrike", "palo alto", "fortinet",
    "zscaler", "sentinelone", "cyberark", "okta", "rapid7",
    "lockheed", "raytheon", "northrop", "general dynamics", "boeing", "saic",
    "jpmorgan", "jp morgan", "bank of america", "goldman sachs",
    "visa", "mastercard", "citigroup", "citi",
    "unitedhealth", "united health", "cvs", "hca",
    "at&t", "verizon", "t-mobile",
    "exxon", "chevron",
    "coinbase",
}

# ── IOC patterns (dark web focused) ──────────────────────────────────────────
_CRED_RE   = re.compile(
    r'\b[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:;|]\s*\S{6,}'
)
_BTC_RE    = re.compile(r'\b(bc1[ac-hj-np-z02-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_ETH_RE    = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_ONION_RE  = re.compile(r'\b[a-z2-7]{16,56}\.onion\b')
_TG_RE     = re.compile(r'(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})')
_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
_MD5_RE    = re.compile(r'\b[0-9a-fA-F]{32}\b')
_CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_IP_RE     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_PRIVATE   = re.compile(r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)')

# Keywords that make a paste worth including
PASTE_KEYWORDS = [
    "combo", "combolist", "credential", "password", "dump", "breach", "leak",
    "database", "dox", "doxed", "credit card", "fullz", "ssn", "exploit",
    "ransomware", "malware", "rat ", "stealer", "infostealer", "keylog",
]

# Scoring keyword rules for paste / general dark web items
DW_SCORE_RULES = [
    (95,  ["credential dump", "combo list", "millions of credentials",
           "full database leak", "ssn", "social security"]),
    (85,  ["zero-day", "0day", "rce exploit", "remote code execution for sale",
           "rat for sale", "stealer", "infostealer source", "ransomware builder"]),
    (75,  ["database for sale", "breach database", "hacked database",
           "dark web sale", "exploit kit", "initial access", "rdp access for sale"]),
    (60,  ["combo", "combolist", "credential list", "password list",
           "dox", "doxing", "leaked emails", "phishing kit"]),
    (40,  ["malware", "trojan", "botnet", "ddos", "crypter", "packer"]),
    (20,  ["hacking", "cracking", "account", "login"]),
]


# ══════════════════════════════════════════════════════════════════════════════
#  DATE PARSING
# ══════════════════════════════════════════════════════════════════════════════
def parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    date_str = date_str.strip()
    try:
        return email.utils.parsedate_to_datetime(date_str).astimezone(timezone.utc)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:len(fmt) + 2], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP — CLEARNET
# ══════════════════════════════════════════════════════════════════════════════
def _http_get(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "agents-hq/1.0 (security research platform)",
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT_CLEARNET) as r:
        return r.read()

def _strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', ' ', text or '').strip()


# ══════════════════════════════════════════════════════════════════════════════
#  TOR — PURE STDLIB SOCKS5 IMPLEMENTATION
# ══════════════════════════════════════════════════════════════════════════════
def _socks5_connect(host: str, port: int) -> socket.socket:
    """Open a raw TCP connection to host:port through the Tor SOCKS5 proxy."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_TOR)
    s.connect((TOR_PROXY_HOST, TOR_PROXY_PORT))
    # No-auth greeting
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        s.close()
        raise ConnectionError(f"SOCKS5 auth negotiation failed: {resp!r}")
    # CONNECT request — ATYP=0x03 (domain name)
    host_b = host.encode('ascii')
    s.sendall(
        struct.pack('!BBB', 5, 1, 0) +       # VER=5, CMD=CONNECT, RSV=0
        b'\x03' +                             # ATYP=domain
        struct.pack('!B', len(host_b)) + host_b +
        struct.pack('!H', port)
    )
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0x00:
        s.close()
        status = resp[1] if len(resp) > 1 else 255
        raise ConnectionError(f"SOCKS5 connect failed: status={status}")
    return s


def _tor_http_get(url: str) -> bytes:
    """Fetch a URL (http or https) through Tor. Works for .onion and clearnet."""
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    path   = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

    s = _socks5_connect(host, port)
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: text/html,application/json,*/*\r\n"
        f"Connection: close\r\n\r\n"
    )
    s.sendall(request.encode())

    chunks = []
    while True:
        try:
            chunk = s.recv(8192)
        except Exception:
            break
        if not chunk:
            break
        chunks.append(chunk)
    s.close()

    raw = b"".join(chunks)
    if b"\r\n\r\n" in raw:
        _, body = raw.split(b"\r\n\r\n", 1)
        return body
    return raw


def check_tor() -> bool:
    """Return True if Tor SOCKS5 daemon is reachable at localhost:9050."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TOR_PROXY_HOST, TOR_PROXY_PORT))
        s.close()
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  TOR MODE PROMPT
# ══════════════════════════════════════════════════════════════════════════════
def prompt_tor_mode() -> bool:
    """
    Ask the operator whether to enable Tor. Default is clearnet-only.
    Returns True if Tor mode is confirmed and the daemon is reachable.
    """
    cprint(C_TOR, "\n[Agent-10] Transport mode:")
    cprint(C_TOR, "  [1] Clearnet only  (default, no Tor required)")
    cprint(C_TOR, "  [2] Tor + Clearnet (requires Tor daemon at localhost:9050)")
    try:
        choice = input(f"{C_HEAD}  Choice [1]: {C_RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return False

    if choice == "2":
        cprint(C_TOR, "  Checking Tor daemon...", end=" ")
        if check_tor():
            cprint(C_OBS, "reachable. Tor mode enabled.")
            return True
        else:
            cprint(C_WARN, "NOT reachable at localhost:9050. Falling back to clearnet.")
            return False
    cprint(C_TOR, "  Clearnet-only mode.")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — DATA COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

# ── 1a. ransomware.live — victims ─────────────────────────────────────────────
def collect_ransomware_victims(lookback_hours: int) -> list[dict]:
    """Recent ransomware victims from ransomware.live public API."""
    try:
        raw    = _http_get("https://api.ransomware.live/victims")
        data   = json.loads(raw)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        items  = []

        for v in (data if isinstance(data, list) else []):
            published = parse_date(
                v.get("published") or v.get("date") or v.get("added") or ""
            )
            if published and published < cutoff:
                continue

            victim  = (v.get("victim") or v.get("name") or "Unknown").strip()
            group   = (v.get("group") or v.get("gang") or "Unknown").strip()
            country = v.get("country", "")
            sector  = v.get("activity") or v.get("sector") or ""
            website = v.get("website") or v.get("url") or ""
            desc    = (_strip_html(v.get("description") or ""))[:400]

            # Cross-reference Agent-09 watchlist
            victim_l = victim.lower()
            watchlist_hit = any(name in victim_l or victim_l in name
                                for name in WATCHLIST_NAMES)
            score = 100 if watchlist_hit else 90

            items.append({
                "title":   f"[RANSOMWARE] {group.upper()} → {victim} ({country})",
                "url":     "https://ransomware.live/#recent",
                "summary": f"Sector: {sector} | Domain: {website} | {desc}",
                "source":  "ransomware.live",
                "date":    published.isoformat() if published else "",
                "track":   "ransomware",
                "score":   score,
                "group":   group,
                "victim":  victim,
                "website": website,
            })
        return items
    except Exception:
        return []


# ── 1b. ransomware.live — active groups ──────────────────────────────────────
def collect_ransomware_groups() -> list[dict]:
    """Active ransomware group profiles — used to trigger threat actor profile updates."""
    try:
        raw  = _http_get("https://api.ransomware.live/recentgroups")
        data = json.loads(raw)
        items = []
        for g in (data if isinstance(data, list) else []):
            name  = (g.get("name") or g.get("group") or "Unknown").strip()
            posts = g.get("posts") or g.get("count") or 0
            items.append({
                "title":   f"[GROUP] {name} — {posts} recent posts",
                "url":     f"https://ransomware.live/#group/{name}",
                "summary": f"Active ransomware group. Recent post count: {posts}",
                "source":  "ransomware.live",
                "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "track":   "ransomware",
                "score":   30,
                "group":   name,
                "_group_profile": True,
            })
        return items
    except Exception:
        return []


# ── 1c. HIBP — public breach catalog ─────────────────────────────────────────
def collect_hibp_breaches(lookback_hours: int) -> list[dict]:
    """Have I Been Pwned — recently added breaches (no API key required)."""
    try:
        raw    = _http_get("https://haveibeenpwned.com/api/v3/breaches")
        data   = json.loads(raw)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        items  = []

        for breach in data:
            added = parse_date(breach.get("AddedDate", ""))
            if added and added < cutoff:
                continue

            name    = breach.get("Name", "")
            domain  = breach.get("Domain", "")
            date    = breach.get("BreachDate", "")
            count   = breach.get("PwnCount", 0)
            classes = ", ".join(breach.get("DataClasses", [])[:8])
            desc    = _strip_html(breach.get("Description", ""))[:300]
            sensitive = breach.get("IsSensitive", False)
            is_verified = breach.get("IsVerified", False)

            # Score by record count and data sensitivity
            if count >= 10_000_000:    score = 70
            elif count >= 1_000_000:   score = 55
            elif count >= 100_000:     score = 40
            else:                      score = 20
            if "Passwords" in (breach.get("DataClasses") or []):  score += 15
            if "Credit cards" in (breach.get("DataClasses") or []): score += 20
            if sensitive:              score += 10
            score = min(score, 95)

            items.append({
                "title":   f"[BREACH] {name} ({domain}) — {count:,} records",
                "url":     f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                "summary": (f"Breach date: {date} | Verified: {is_verified} | "
                            f"Data: {classes} | {desc}"),
                "source":  "HIBP",
                "date":    added.isoformat() if added else date,
                "track":   "hibp",
                "score":   score,
            })
        return items
    except Exception:
        return []


# ── 1d. Pastebin RSS — credential / malware filter ───────────────────────────
ATOM_NS = "{http://www.w3.org/2005/Atom}"

def collect_pastebin_rss(lookback_hours: int) -> list[dict]:
    """Public Pastebin archive — filter to items likely containing creds or malware."""
    try:
        raw    = _http_get("https://pastebin.com/archive/rss").decode("utf-8", errors="replace")
        root   = ET.fromstring(raw)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        items  = []

        channel = root.find("channel") or root
        for item in channel.findall("item"):
            title   = (item.findtext("title") or "").strip()
            link    = (item.findtext("link") or "").strip()
            pub     = parse_date(item.findtext("pubDate") or "")
            if pub and pub < cutoff:
                continue
            if not title:
                continue

            title_l = title.lower()
            if not any(kw in title_l for kw in PASTE_KEYWORDS):
                continue

            # Score on keywords
            score = 20
            for s, keywords in DW_SCORE_RULES:
                if any(kw in title_l for kw in keywords):
                    score = s
                    break

            items.append({
                "title":   f"[PASTE] {title}",
                "url":     link,
                "summary": f"Public paste matching dark web keywords. Title: {title}",
                "source":  "Pastebin",
                "date":    pub.isoformat() if pub else "",
                "track":   "paste",
                "score":   score,
            })
        return items
    except Exception:
        return []


# ── 1e. IntelligenceX — dark web search (optional) ───────────────────────────
def collect_intelx(lookback_hours: int) -> list[dict]:
    """IntelligenceX API — dark web search across paste sites, leak forums, .onion."""
    api_key = os.environ.get("INTELX_API_KEY", "")
    if not api_key:
        return []

    queries = [
        "ransomware victim leak",
        "database dump sale",
        "credentials combo",
        "zero day exploit",
    ]
    items = []

    for query in queries:
        try:
            # Start search
            payload = json.dumps({
                "term":     query,
                "buckets":  [],
                "lookuplevel": 0,
                "maxresults": 10,
                "timeout":  10,
                "datefrom": (datetime.now(timezone.utc) - timedelta(hours=lookback_hours))
                            .strftime("%Y-%m-%d %H:%M:%S"),
                "dateto":   "",
                "sort":     4,
                "media":    0,
                "terminate": [],
            }).encode()
            req = urllib.request.Request(
                "https://2.intelx.io/intelligent/search",
                data=payload,
                headers={"Content-Type": "application/json", "x-key": api_key},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                search_data = json.loads(resp.read())

            search_id = search_data.get("id", "")
            if not search_id:
                continue

            # Retrieve results
            time.sleep(2)
            result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=5"
            req2 = urllib.request.Request(
                result_url, headers={"x-key": api_key}
            )
            with urllib.request.urlopen(req2, timeout=15) as resp2:
                results = json.loads(resp2.read())

            for rec in (results.get("records") or [])[:5]:
                name  = rec.get("name", "")
                date  = rec.get("date", "")
                stype = rec.get("stype", 0)
                items.append({
                    "title":   f"[INTELX] {query} — {name}",
                    "url":     f"https://intelx.io/?did={rec.get('systemid', '')}",
                    "summary": f"Query: '{query}' | Type: {stype} | Date: {date}",
                    "source":  "IntelligenceX",
                    "date":    date[:10],
                    "track":   "ixapi",
                    "score":   0,
                })
        except Exception:
            pass

    return items


# ── 1f. Direct .onion targets (Tor only) ─────────────────────────────────────
def collect_onion_target(name: str, onion_addr: str) -> list[dict]:
    """Fetch the index page of a .onion target and extract text content."""
    url = f"http://{onion_addr}/"
    try:
        raw     = _tor_http_get(url)
        content = raw.decode("utf-8", errors="replace")
        text    = _strip_html(content)[:3000]
        # Count victim-like patterns
        victim_lines = [l.strip() for l in text.splitlines()
                        if l.strip() and len(l.strip()) > 20][:20]
        summary = " | ".join(victim_lines[:5]) if victim_lines else text[:400]
        return [{
            "title":    f"[ONION] {name} leak site — live",
            "url":      url,
            "summary":  summary[:500],
            "source":   f"Onion/{name}",
            "date":     datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "track":    "onion",
            "score":    70,
            "_content": text,
        }]
    except Exception as e:
        cprint(C_WARN, f"  ✗ onion:{name}: {e}")
        return []


def collect_ahmia_tor(tor_enabled: bool) -> list[dict]:
    """Ahmia dark web search engine — via Tor."""
    if not tor_enabled:
        return []
    items = []
    for query in AHMIA_QUERIES[:3]:   # limit queries to avoid rate limiting
        try:
            url  = f"http://{AHMIA_ONION}/search/?q={urllib.parse.quote(query)}"
            raw  = _tor_http_get(url)
            text = raw.decode("utf-8", errors="replace")
            # Extract result titles and links from HTML
            links = re.findall(
                r'<h4[^>]*>(.*?)</h4>.*?<a[^>]+href="(http[^"]+)"',
                text, re.DOTALL
            )[:5]
            for title_html, link in links:
                title = _strip_html(title_html).strip()
                if not title:
                    continue
                items.append({
                    "title":   f"[AHMIA] {title}",
                    "url":     link,
                    "summary": f"Ahmia search result for query: '{query}'",
                    "source":  "Ahmia/Tor",
                    "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "track":   "onion",
                    "score":   0,
                })
        except Exception:
            pass
    return items


# ── 1g. Orchestrate all collectors ────────────────────────────────────────────
def collect_all(lookback_hours: int, enabled_tracks: set | None,
                tor_enabled: bool) -> list[dict]:
    cprint(C_PHASE, "\n[PHASE 1] Collecting dark web intelligence...")
    cprint(C_TOR,
           f"  Transport: {'Tor + Clearnet' if tor_enabled else 'Clearnet only'}")

    tasks: list[tuple[str, callable]] = []

    if enabled_tracks is None or "ransomware" in enabled_tracks:
        tasks.append(("ransomware.live/victims",
                      lambda: collect_ransomware_victims(lookback_hours)))
        tasks.append(("ransomware.live/groups",
                      lambda: collect_ransomware_groups()))

    if enabled_tracks is None or "paste" in enabled_tracks:
        tasks.append(("Pastebin RSS",
                      lambda: collect_pastebin_rss(lookback_hours)))

    if enabled_tracks is None or "hibp" in enabled_tracks:
        tasks.append(("HIBP breaches",
                      lambda: collect_hibp_breaches(lookback_hours)))

    if enabled_tracks is None or "ixapi" in enabled_tracks:
        tasks.append(("IntelligenceX",
                      lambda: collect_intelx(lookback_hours)))

    # Tor-only sources
    if tor_enabled and (enabled_tracks is None or "onion" in enabled_tracks):
        for name, addr in ONION_TARGETS.items():
            tasks.append((
                f"onion:{name}",
                lambda n=name, a=addr: collect_onion_target(n, a)
            ))
        tasks.append(("Ahmia/Tor", lambda: collect_ahmia_tor(tor_enabled)))

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

    cprint(C_PHASE,
           f"[PHASE 1] Collected {len(all_items)} raw items from {len(tasks)} sources.")
    return all_items


# ══════════════════════════════════════════════════════════════════════════════
#  SCORING + DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════
def score_item(item: dict) -> int:
    if item.get("track") in ("ransomware", "onion"):
        return item.get("score", 30)
    if item.get("track") == "hibp":
        return item.get("score", 20)

    text = (item.get("title", "") + " " + item.get("summary", "")).lower()
    for score, keywords in DW_SCORE_RULES:
        if any(kw in text for kw in keywords):
            return score
    return 10


def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    out  = []
    for item in items:
        key = hashlib.md5(item.get("title", "").lower().strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def score_and_filter(items: list[dict],
                      max_items: int = MAX_ITEMS_FOR_LLM) -> list[dict]:
    deduped = deduplicate(items)
    for item in deduped:
        item["score"] = score_item(item)

    sorted_items = sorted(deduped, key=lambda x: x["score"], reverse=True)
    result   = sorted_items[:max_items]
    critical = sum(1 for i in result if i["score"] >= 80)
    high     = sum(1 for i in result if 60 <= i["score"] < 80)
    medium   = sum(1 for i in result if 30 <= i["score"] < 60)
    low      = sum(1 for i in result if i["score"] < 30)
    cprint(C_PHASE,
           f"[FILTER] {len(deduped)} unique → top {len(result)} | "
           f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} LOW:{low}")
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  TOOLS (LLM callable)
# ══════════════════════════════════════════════════════════════════════════════
def tool_extract_iocs(text: str) -> str:
    cprint(C_TOOL, f"  [EXTRACT_IOCS] {len(text)} chars")
    creds   = list(set(_CRED_RE.findall(text)))[:10]
    btc     = list(set(_BTC_RE.findall(text)))[:10]
    eth     = list(set(_ETH_RE.findall(text)))[:10]
    onions  = list(set(_ONION_RE.findall(text)))[:10]
    tg      = list(set(_TG_RE.findall(text)))[:10]
    sha256s = list(set(_SHA256_RE.findall(text)))[:10]
    md5s    = list(set(_MD5_RE.findall(text)))[:10]
    cves    = list(set(_CVE_RE.findall(text)))[:10]
    raw_ips = _IP_RE.findall(text)
    ips     = list({ip for ip in raw_ips if not _PRIVATE.match(ip)})[:10]

    parts = []
    if creds:   parts.append(f"Credentials ({len(creds)}): " + " | ".join(creds[:3]) + ("..." if len(creds) > 3 else ""))
    if btc:     parts.append(f"BTC wallets: {', '.join(btc[:5])}")
    if eth:     parts.append(f"ETH wallets: {', '.join(eth[:5])}")
    if onions:  parts.append(f".onion addresses: {', '.join(onions[:5])}")
    if tg:      parts.append(f"Telegram: {', '.join(tg[:5])}")
    if sha256s: parts.append(f"SHA256: {', '.join(sha256s[:5])}")
    if md5s:    parts.append(f"MD5: {', '.join(md5s[:5])}")
    if cves:    parts.append(f"CVEs: {', '.join(cves)}")
    if ips:     parts.append(f"IPs: {', '.join(ips[:10])}")

    if not parts:
        return "[EXTRACT_IOCS] No IOCs found."
    return "[EXTRACT_IOCS] Extracted:\n" + "\n".join(f"  {p}" for p in parts)


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
    return rag_ingest(text, source="agent10_darkweb", doc_id=doc_id)


def tool_update_threat_actor(name: str, data: str) -> str:
    """Upsert a structured threat actor profile into MySQL threat_actors table."""
    cprint(C_TOOL, f"  [UPDATE_TA] {name}")
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    from rag_mysql import rag_ingest_threat_actor
    return rag_ingest_threat_actor(name, data)


def tool_file_write(filename: str, content: str) -> str:
    cprint(C_TOOL, f"  [FILE_WRITE] {filename}")
    out_path = REPORTS_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)
    return f"[FILE_WRITE] Written: {out_path}"


# ── Tool schema & dispatcher ──────────────────────────────────────────────────
TOOL_SCHEMA = [
    {
        "name":        "extract_iocs",
        "description": "Extract credentials, BTC/ETH wallets, .onion addresses, Telegram channels, hashes, CVEs, and IPs from raw text.",
        "parameters":  {"text": "Raw text to extract IOCs from."}
    },
    {
        "name":        "rag_lookup",
        "description": "Check if a threat actor, victim company, or IOC is already in the knowledge base.",
        "parameters":  {"query": "Search string (e.g. 'LockBit victims 2024' or 'ACME Corp breach')."}
    },
    {
        "name":        "rag_ingest",
        "description": "Store an intelligence finding in ChromaDB for other agents.",
        "parameters":  {"text": "Content to store.", "doc_id": "Optional document ID."}
    },
    {
        "name":        "update_threat_actor",
        "description": "Upsert a structured threat actor profile (persists across runs). Use for every active ransomware group.",
        "parameters":  {
            "name": "Threat actor / group name (e.g. 'LockBit', 'BlackCat').",
            "data": "Structured profile data: known victims, TTPs, sectors targeted, infrastructure, aliases, activity level."
        }
    },
    {
        "name":        "file_write",
        "description": "Write the final dark web intelligence report to the reports/ directory.",
        "parameters":  {
            "filename": "Report filename (e.g. DARKWEB_20250101_1200.md).",
            "content":  "Full report in Markdown."
        }
    },
]

def dispatch_tool(name: str, params: dict) -> str:
    if name == "extract_iocs":
        return tool_extract_iocs(params.get("text", ""))
    elif name == "rag_lookup":
        return tool_rag_lookup(params.get("query", ""))
    elif name == "rag_ingest":
        return tool_rag_ingest(params.get("text", ""), params.get("doc_id"))
    elif name == "update_threat_actor":
        return tool_update_threat_actor(
            params.get("name", "unknown"), params.get("data", "")
        )
    elif name == "file_write":
        return tool_file_write(
            params.get("filename", "darkweb.md"), params.get("content", "")
        )
    return f"[DISPATCH] Unknown tool: {name}"


# ══════════════════════════════════════════════════════════════════════════════
#  OLLAMA CALL
# ══════════════════════════════════════════════════════════════════════════════
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


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — LLM ANALYSIS (ReAct loop)
# ══════════════════════════════════════════════════════════════════════════════
def _format_items_for_llm(items: list[dict]) -> str:
    lines = []
    for i, item in enumerate(items, 1):
        score    = item.get("score", 0)
        track    = item.get("track", "")
        source   = item.get("source", "")
        title    = item.get("title", "")
        url      = item.get("url", "")
        summary  = item.get("summary", "")[:350]
        date     = item.get("date", "")[:10]
        priority = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 30 else "LOW"
        )
        lines.append(
            f"[{i:02d}] [{priority}] [{track.upper()}] {source} | {date}\n"
            f"     Title  : {title}\n"
            f"     Summary: {summary}\n"
            f"     URL    : {url}"
        )
    return "\n\n".join(lines)


def build_system_prompt(lookback_hours: int, item_count: int,
                         tor_enabled: bool, ts: str) -> str:
    tool_docs = "\n".join(
        f"  {t['name']}({', '.join(t['parameters'].keys())}) — {t['description']}"
        for t in TOOL_SCHEMA
    )
    watchlist_sample = ", ".join(sorted(WATCHLIST_NAMES)[:12]) + "..."
    return f"""You are Agent-10 — the dark web intelligence analyst for the AGENTS-HQ security platform.

Run timestamp  : {ts}
Lookback       : last {lookback_hours} hours
Transport mode : {'Tor + Clearnet' if tor_enabled else 'Clearnet only'}
Items provided : {item_count} (pre-scored and ranked)
Watchlist names: {watchlist_sample}

Your mission: analyze dark web intelligence through a defensive threat-intel lens.
Connect ransomware victims to the platform's watchlist, build threat actor profiles,
extract IOCs for downstream agents, and produce actionable recommendations.

Available tools:
{tool_docs}

ReAct format — follow exactly:
  THOUGHT: <your reasoning>
  ACTION: <tool_name>
  PARAMS: <JSON object>

Conclude with:
  FINAL: <one-paragraph executive summary for the operator>

Analysis workflow:
  1. For every CRITICAL item (score ≥ 80): call rag_lookup to check prior context.
  2. For any item containing wallets, hashes, .onion addresses, or credentials: call extract_iocs.
  3. For every active ransomware group in the data: call update_threat_actor with a structured
     profile (victims this run, sectors, countries, TTPs, infrastructure if known).
  4. Compose the full dark web intelligence report.
  5. Call rag_ingest with the complete brief.
  6. Call file_write with the full structured report.

Threat-nexus rules:
  RANSOMWARE VICTIM matching watchlist — immediately flag in CRITICAL section.
    → Recommend Agent-01 OSINT on victim domain; Agent-02 CVE recon on their stack.
  NEW EXPLOIT FOR SALE — cross-reference CVE with Agent-08 advisories.
    → Recommend Agent-02 scan; Agent-05 red team update.
  CREDENTIAL DUMP — extract volume, sectors, and pass to Agent-06 for hash cracking context.
  MALWARE HASH — forward to Agent-06 for RE and YARA generation.
  NEW GROUP / REBRAND — note infrastructure and TTPs for Agent-05 ATT&CK mapping.

Report structure to produce:
  # AGENTS-HQ Dark Web Intel Brief — {ts}
  ## Run Metadata
  ## CRITICAL — New Ransomware Victims & Active Campaigns
  ## Credential Leaks & Data Dumps
  ## Exploit Marketplace (New Tools for Sale)
  ## Threat Actor Profiles (Updated This Run)
  ## Malware Samples → Agent-06 Queue
  ## IOCs Extracted (wallets, hashes, .onion addresses, Telegram channels)
  ## Platform Recommendations (specific Agent-01/02/05/06 action items)

Rules:
  1. Do not repeat a tool call with identical parameters.
  2. All CRITICAL items must appear in the report.
  3. update_threat_actor must be called for every distinct ransomware group in the data.
  4. Platform Recommendations must name the specific agent and target.
  5. Report filename: DARKWEB_{ts.replace('-','').replace(':','').replace(' ','_')[:15]}.md
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


def analyze_with_llm(scored_items: list[dict], lookback_hours: int,
                      tor_enabled: bool) -> str:
    cprint(C_PHASE, "\n[PHASE 2] LLM analysis...")
    ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    formatted = _format_items_for_llm(scored_items)
    system_p  = build_system_prompt(lookback_hours, len(scored_items), tor_enabled, ts)

    messages = [
        {"role": "system", "content": system_p},
        {"role": "user",
         "content": (
             f"Here are the {len(scored_items)} scored dark web intelligence items:\n\n"
             f"{formatted}\n\nBegin analysis."
         )},
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
                "content": "No ACTION found. Continue with THOUGHT/ACTION/PARAMS or emit FINAL.",
            })
            continue

        action_key = f"{tool_name}:{json.dumps(params, sort_keys=True)}"
        if action_history.count(action_key) >= 2:
            observation = (
                f"[LOOP_GUARD] '{tool_name}' already called with these params. "
                "Choose a different action or emit FINAL."
            )
        else:
            action_history.append(action_key)
            cprint(C_TOOL, f"\n  → {tool_name}({params})")
            observation = dispatch_tool(tool_name, params)

        cprint(C_OBS,
               f"\n  [OBS] {observation[:400]}{'...' if len(observation) > 400 else ''}")
        messages.append({"role": "user", "content": f"OBSERVATION: {observation}"})

    else:
        cprint(C_WARN, "\n[!] Max iterations reached.")
        final_output = "[Agent-10] Analysis complete. See reports/ for DARKWEB_*.md output."

    return final_output


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def run_pipeline(lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
                 enabled_tracks: set | None = None,
                 tor_enabled: bool = False) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cprint(C_HEAD, f"\n{'='*64}")
    cprint(C_HEAD, f"  AGENT-10 — DARK WEB MONITOR")
    cprint(C_HEAD, f"  Lookback : {lookback_hours}h  |  Started : {ts}")
    cprint(C_HEAD, f"  Transport: {'Tor + Clearnet' if tor_enabled else 'Clearnet only'}")
    cprint(C_HEAD, f"{'='*64}")

    raw_items    = collect_all(lookback_hours, enabled_tracks, tor_enabled)
    scored_items = score_and_filter(raw_items)

    if not scored_items:
        cprint(C_WARN, "[!] No items collected. Check network / feeds.")
        return "No items collected."

    summary = analyze_with_llm(scored_items, lookback_hours, tor_enabled)

    cprint(C_HEAD,
           f"\n[DONE] Run complete at {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
    return summary


# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════════════════════
def interactive_mode():
    cprint(C_HEAD, "\n══════════════════════════════════════════════")
    cprint(C_HEAD, "  AGENT-10 — DARK WEB MONITOR  [interactive]")
    cprint(C_HEAD, "══════════════════════════════════════════════")
    print("  Type 'exit' to quit.\n")

    while True:
        tor_enabled = prompt_tor_mode()

        try:
            since_str = input(
                f"{C_PHASE}  Lookback hours [default: {DEFAULT_LOOKBACK_HOURS}] > {C_RESET}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if since_str.lower() in ("exit", "quit"):
            break

        tracks_str = input(
            f"{C_PHASE}  Tracks [ransomware/paste/hibp/ixapi/onion or Enter for all] > {C_RESET}"
        ).strip()

        try:
            lookback_hours = int(since_str) if since_str else DEFAULT_LOOKBACK_HOURS
        except ValueError:
            lookback_hours = DEFAULT_LOOKBACK_HOURS

        enabled_tracks = (
            set(t.strip() for t in tracks_str.split(",") if t.strip())
            if tracks_str else None
        )

        run_pipeline(lookback_hours, enabled_tracks, tor_enabled)


# ══════════════════════════════════════════════════════════════════════════════
#  N8N WEBHOOK SERVER
#  Recommended cron: every 12 hours
#  POST body: {"since": 12, "tor": true, "tracks": "ransomware,hibp"}
# ══════════════════════════════════════════════════════════════════════════════
def start_webhook_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != "/webhook/agent10":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}

            lookback_hours = int(data.get("since", DEFAULT_LOOKBACK_HOURS))
            tor_requested  = bool(data.get("tor", False))
            tracks_raw     = data.get("tracks", None)

            enabled_tracks = (
                set(t.strip() for t in tracks_raw.split(",") if t.strip())
                if isinstance(tracks_raw, str) and tracks_raw
                else None
            )

            # Verify Tor if requested
            tor_enabled = False
            if tor_requested:
                if check_tor():
                    tor_enabled = True
                    cprint(C_TOR, "[WEBHOOK] Tor mode enabled.")
                else:
                    cprint(C_WARN,
                           "[WEBHOOK] Tor requested but daemon unreachable — clearnet only.")

            threading.Thread(
                target=lambda: run_pipeline(lookback_hours, enabled_tracks, tor_enabled),
                daemon=True
            ).start()

            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status":    "accepted",
                "lookback":  lookback_hours,
                "tor":       tor_enabled,
                "tracks":    list(enabled_tracks) if enabled_tracks else "all",
                "message":   "Agent-10 started. Check reports/ for DARKWEB_*.md output.",
            }).encode())

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "status": "ok",
                        "agent":  "agent10",
                        "tor":    check_tor(),
                    }).encode()
                )
            else:
                self.send_error(404)

    server = HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler)
    cprint(C_HEAD, f"\n[WEBHOOK] Agent-10 on http://127.0.0.1:{N8N_WEBHOOK_PORT}/webhook/agent10")
    cprint(C_HEAD,  '  POST {}                              — run with defaults')
    cprint(C_HEAD,  '  POST {"since": 12, "tor": true}     — 12h lookback, Tor enabled')
    cprint(C_HEAD,  '  POST {"tracks": "ransomware,hibp"}  — specific tracks only')
    cprint(C_HEAD,  '  GET  /health                        — liveness + Tor status check\n')
    server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Agent-10 — Dark Web Monitor (underground threat intelligence)"
    )
    parser.add_argument("--since",       type=int, default=None,
                        help=f"Lookback window in hours (default: {DEFAULT_LOOKBACK_HOURS})")
    parser.add_argument("--tracks",      default=None,
                        help="Comma-separated tracks: ransomware,paste,hibp,ixapi,onion")
    parser.add_argument("--tor",         action="store_true",
                        help="Enable Tor mode without prompting")
    parser.add_argument("--no-tor",      action="store_true",
                        help="Clearnet only without prompting")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--n8n-server",  action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        start_webhook_server()
        return

    if args.interactive:
        interactive_mode()
        return

    # Resolve Tor mode
    if args.tor:
        if check_tor():
            tor_enabled = True
            cprint(C_TOR, "[✓] Tor mode enabled.")
        else:
            cprint(C_WARN, "[!] --tor specified but daemon unreachable. Falling back to clearnet.")
            tor_enabled = False
    elif args.no_tor:
        tor_enabled = False
    else:
        tor_enabled = prompt_tor_mode()

    lookback_hours = args.since if args.since is not None else DEFAULT_LOOKBACK_HOURS
    enabled_tracks = (
        set(t.strip() for t in args.tracks.split(",") if t.strip())
        if args.tracks else None
    )
    run_pipeline(lookback_hours, enabled_tracks, tor_enabled)


if __name__ == "__main__":
    main()
