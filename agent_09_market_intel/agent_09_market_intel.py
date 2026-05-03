#!/usr/bin/env python3
"""
AGENTS-HQ — Agent-09 Market Intel v1

Financial intelligence layer. Monitors a 34-ticker watchlist for anomalous
market signals that correlate with cyber events (breach discovery, ransomware
disclosure, insider trading before disclosures), tracks financially motivated
threat actors, and flags M&A activity that changes target attack surfaces.

Four intelligence tracks:
  1. OHLCV / Signals  — Yahoo Finance: price drops, volume spikes, RSI/MACD/Bollinger Bands
  2. SEC Filings       — 8-K cybersecurity incident disclosures (Item 1.05) and M&A
  3. Finance News      — RSS: MarketWatch, CNBC, Reuters, WSJ, ZeroHedge, CoinDesk (12 feeds)
  4. Crypto/DeFi       — Exchange hacks, DeFi exploits, ransomware payment tracking

Pipeline:
  Phase 1 — Collect  (Python, parallel threads): OHLCV + indicators, SEC EDGAR, RSS, Finnhub
  Phase 2 — Score    (Python): anomaly scoring, deduplication, top-N filter
  Phase 3 — Analyze  (LLM ReAct loop): threat-nexus analysis, report generation
  Phase 4 — Persist  (Python): RAG ingest + file write

Usage:
  python3 agent_09_market_intel.py                       # one-shot, 1-day lookback
  python3 agent_09_market_intel.py --days 3              # 3-day lookback for signals
  python3 agent_09_market_intel.py --tickers MSFT,CRWD   # override watchlist
  python3 agent_09_market_intel.py --tracks ohlcv,sec    # specific tracks only
  python3 agent_09_market_intel.py --interactive
  python3 agent_09_market_intel.py --n8n-server
"""

import sys, json, re, os, time, hashlib, math
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
OLLAMA_HOST          = "localhost"
OLLAMA_PORT          = 11434
AGENT_MODEL          = "deepseek-r1:8b"
CHROMA_HOST          = "localhost"
CHROMA_PORT          = 8000
REPORTS_DIR          = Path(__file__).parent.parent / "reports"
N8N_WEBHOOK_PORT     = int(os.environ.get("N8N_WEBHOOK_PORT", "8769"))
MAX_ITERATIONS       = 12
DEFAULT_LOOKBACK_DAYS = 1
MAX_ITEMS_FOR_LLM    = 40
TIMEOUT_HTTP         = 20
MAX_FETCH_WORKERS    = 8
YAHOO_DELAY_S        = 0.15   # throttle between Yahoo Finance requests

# ── ANSI Colors ───────────────────────────────────────────────────────────────
C_HEAD  = "\033[38;5;33m"    # blue     — agent identity
C_PHASE = "\033[38;5;220m"   # yellow   — phase headers
C_TOOL  = "\033[38;5;226m"   # bright   — tool calls
C_OBS   = "\033[38;5;82m"    # green    — observations
C_THINK = "\033[38;5;244m"   # grey     — LLM thinking
C_WARN  = "\033[38;5;196m"   # red      — warnings
C_CRIT  = "\033[38;5;201m"   # magenta  — critical findings
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

# ── Watchlist ─────────────────────────────────────────────────────────────────
WATCHLIST_BY_SECTOR = {
    "big_tech":      ["MSFT", "GOOGL", "META", "AMZN", "AAPL", "NVDA", "CRM", "ORCL"],
    "cybersecurity": ["CRWD", "PANW", "FTNT", "ZS", "S", "CYBR", "OKTA"],
    "defense":       ["LMT", "RTX", "NOC", "GD", "BA", "SAIC"],
    "finance":       ["JPM", "BAC", "GS", "V", "MA", "C"],
    "healthcare":    ["UNH", "CVS", "HCA"],
    "telecom":       ["T", "VZ"],
    "energy":        ["XOM", "CVX"],
    "crypto":        ["COIN", "MSTR", "MARA"],
}
DEFAULT_WATCHLIST = [t for tickers in WATCHLIST_BY_SECTOR.values() for t in tickers]

# ── Financial RSS feeds ───────────────────────────────────────────────────────
FINANCE_RSS_FEEDS = {
    "finance": {
        "MarketWatch":    "http://feeds.marketwatch.com/marketwatch/topstories",
        "CNBC Finance":   "https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=10000664",
        "Reuters Biz":    "https://feeds.reuters.com/reuters/businessNews",
        "WSJ Markets":    "https://feeds.a.dj.com/rss/RSSMarketsMain.xml",
        "Investopedia":   "https://www.investopedia.com/feedbuilder/feed/getfeed/?feedName=rss_headline",
        "ZeroHedge":      "https://feeds.feedburner.com/zerohedge/feed",
        "The Street":     "https://www.thestreet.com/.rss/full",
        "Barron's":       "https://www.barrons.com/xml/rss/3_7014.xml",
    },
    "crypto": {
        "CoinDesk":       "https://www.coindesk.com/arc/outboundfeeds/rss/",
        "Cointelegraph":  "https://cointelegraph.com/rss",
        "Decrypt":        "https://decrypt.co/feed",
        "The Block":      "https://www.theblock.co/rss.xml",
    },
}

# ── Finance scoring rules ─────────────────────────────────────────────────────
FINANCE_SCORE_RULES = [
    (100, ["cybersecurity incident", "material cybersecurity", "data breach disclosed",
           "sec 8-k cyber", "ransomware attack confirmed", "systems compromised"]),
    (85,  ["ransomware", "data breach", "cyberattack", "unauthorized access",
           "crypto exchange hacked", "defi exploit", "smart contract exploit",
           "funds stolen", "million drained", "hack"]),
    (70,  ["insider trading", "sec investigation", "market manipulation",
           "business email compromise", "bec fraud", "wire fraud",
           "crypto theft", "north korea", "lazarus group", "sanctions"]),
    (55,  ["acquisition", "merger", "takeover", "buyout",
           "earnings miss", "profit warning", "guidance cut",
           "layoffs", "bankruptcy", "chapter 11"]),
    (40,  ["vulnerability", "exploit", "patch", "security update",
           "phishing", "supply chain", "third-party breach"]),
    (20,  ["market", "earnings", "quarterly", "revenue",
           "analyst", "upgrade", "downgrade", "stocks"]),
]


# ══════════════════════════════════════════════════════════════════════════════
#  TECHNICAL INDICATORS  (computed from raw OHLCV, no API key required)
# ══════════════════════════════════════════════════════════════════════════════
def _ema_series(data: list[float], period: int) -> list[float]:
    """Exponential moving average — full series, same length as input."""
    if not data:
        return []
    k   = 2.0 / (period + 1)
    ema = [data[0]]
    for price in data[1:]:
        ema.append(price * k + ema[-1] * (1 - k))
    return ema


def calculate_rsi(closes: list[float], period: int = 14) -> float:
    """Wilder's smoothed RSI."""
    if len(closes) < period + 1:
        return 50.0
    deltas   = [closes[i] - closes[i-1] for i in range(1, len(closes))]
    gains    = [max(0.0, d) for d in deltas]
    losses   = [max(0.0, -d) for d in deltas]
    avg_gain = sum(gains[:period]) / period
    avg_loss = sum(losses[:period]) / period
    for i in range(period, len(gains)):
        avg_gain = (avg_gain * (period - 1) + gains[i]) / period
        avg_loss = (avg_loss * (period - 1) + losses[i]) / period
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return round(100.0 - (100.0 / (1 + rs)), 2)


def calculate_macd(closes: list[float], fast: int = 12, slow: int = 26,
                   signal: int = 9) -> dict:
    """MACD line, signal line, and histogram."""
    if len(closes) < slow + signal:
        return {"macd": 0.0, "signal_line": 0.0, "histogram": 0.0}
    ema_fast    = _ema_series(closes, fast)
    ema_slow    = _ema_series(closes, slow)
    macd_series = [f - s for f, s in zip(ema_fast, ema_slow)]
    # Skip EMA warm-up period — only use values from index slow-1 onward
    macd_series = macd_series[slow - 1:]
    if len(macd_series) < signal:
        return {"macd": 0.0, "signal_line": 0.0, "histogram": 0.0}
    sig_series = _ema_series(macd_series, signal)
    macd_val   = macd_series[-1]
    sig_val    = sig_series[-1]
    return {
        "macd":        round(macd_val, 4),
        "signal_line": round(sig_val, 4),
        "histogram":   round(macd_val - sig_val, 4),
    }


def calculate_bollinger(closes: list[float], period: int = 20,
                         n_std: float = 2.0) -> dict:
    """Bollinger Bands with %B and bandwidth."""
    if len(closes) < period:
        return {"upper": 0.0, "middle": 0.0, "lower": 0.0,
                "pct_b": 50.0, "bandwidth": 0.0}
    recent  = closes[-period:]
    middle  = sum(recent) / period
    std_dev = math.sqrt(sum((x - middle) ** 2 for x in recent) / period)
    upper   = middle + n_std * std_dev
    lower   = middle - n_std * std_dev
    current = closes[-1]
    pct_b   = (current - lower) / (upper - lower) * 100.0 if upper != lower else 50.0
    bw      = (upper - lower) / middle * 100.0 if middle else 0.0
    return {
        "upper":     round(upper, 4),
        "middle":    round(middle, 4),
        "lower":     round(lower, 4),
        "pct_b":     round(pct_b, 1),
        "bandwidth": round(bw, 2),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  DATE PARSING  (RSS 2.0 and Atom)
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
#  HTTP HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _http_get(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "agents-hq/1.0 (financial intelligence platform)",
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP) as r:
        return r.read()

def _strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', ' ', text or '').strip()[:600]


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — DATA COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

# ── 1a. Yahoo Finance OHLCV + indicators ─────────────────────────────────────
def collect_yahoo_ohlcv(ticker: str) -> dict | None:
    """Fetch 3-month daily OHLCV and compute RSI, MACD, Bollinger Bands."""
    url = (f"https://query1.finance.yahoo.com/v8/finance/chart/{ticker}"
           f"?interval=1d&range=3mo")
    try:
        raw    = _http_get(url, headers={"Accept": "application/json"})
        data   = json.loads(raw)
        result = data.get("chart", {}).get("result", [])
        if not result:
            return None
        r      = result[0]
        meta   = r.get("meta", {})
        quotes = r.get("indicators", {}).get("quote", [{}])[0]

        closes  = [x for x in (quotes.get("close")  or []) if x is not None]
        volumes = [x for x in (quotes.get("volume") or []) if x is not None]

        if len(closes) < 2:
            return None

        current    = meta.get("regularMarketPrice") or closes[-1]
        prev_close = meta.get("chartPreviousClose") or closes[-2]
        chg_pct    = (current - prev_close) / prev_close * 100.0 if prev_close else 0.0

        avg_vol_30 = sum(volumes[-30:]) / min(30, len(volumes)) if volumes else 1
        last_vol   = volumes[-1] if volumes else 0
        vol_ratio  = last_vol / avg_vol_30 if avg_vol_30 else 1.0

        rsi  = calculate_rsi(closes)
        macd = calculate_macd(closes)
        bb   = calculate_bollinger(closes)

        # Anomaly signal detection
        signals = []
        if chg_pct <= -15:                          signals.append(("PRICE_DROP_15", 90))
        elif chg_pct <= -10:                        signals.append(("PRICE_DROP_10", 80))
        elif chg_pct <= -5:                         signals.append(("PRICE_DROP_5",  70))
        if vol_ratio >= 5:                          signals.append(("VOL_SPIKE_5X",  75))
        elif vol_ratio >= 3:                        signals.append(("VOL_SPIKE_3X",  65))
        if rsi < 25 or rsi > 75:                   signals.append(("RSI_EXTREME",   60))
        if bb["pct_b"] < 0 or bb["pct_b"] > 100:  signals.append(("BB_BREAK",      55))
        if macd["histogram"] < 0:                  signals.append(("MACD_BEARISH",  50))
        w52_low = meta.get("fiftyTwoWeekLow")
        if w52_low and current <= w52_low * 1.05:  signals.append(("WEEK52_LOW",    40))
        if not signals:                             signals.append(("NORMAL",        15))

        top_signal, top_score = max(signals, key=lambda x: x[1])

        return {
            "ticker":     ticker,
            "name":       meta.get("longName") or meta.get("shortName") or ticker,
            "current":    round(current, 2),
            "prev_close": round(prev_close, 2),
            "chg_pct":    round(chg_pct, 2),
            "volume":     last_vol,
            "avg_vol_30": round(avg_vol_30),
            "vol_ratio":  round(vol_ratio, 2),
            "rsi":        rsi,
            "macd":       macd,
            "bb":         bb,
            "signals":    signals,
            "top_signal": top_signal,
            "score":      top_score,
            "currency":   meta.get("currency", "USD"),
            "week52_high": meta.get("fiftyTwoWeekHigh"),
            "week52_low":  w52_low,
        }
    except Exception:
        return None


def collect_all_ohlcv(watchlist: list[str]) -> list[dict]:
    results = []
    lock    = threading.Lock()

    def fetch_one(ticker):
        time.sleep(YAHOO_DELAY_S)
        data = collect_yahoo_ohlcv(ticker)
        if data:
            with lock:
                results.append(data)
            cprint(C_OBS,
                   f"  ✓ {ticker:6s} | {data['chg_pct']:+.2f}% | "
                   f"vol×{data['vol_ratio']:.1f} | RSI={data['rsi']:.0f} | "
                   f"{data['top_signal']}")
        else:
            cprint(C_WARN, f"  ✗ {ticker}: no data")

    with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as pool:
        pool.map(fetch_one, watchlist)
    return results


def ohlcv_to_intel_items(ohlcv_data: list[dict]) -> list[dict]:
    items = []
    for d in ohlcv_data:
        direction = "▼" if d["chg_pct"] < 0 else "▲"
        summary = (
            f"Price: ${d['current']} ({direction}{abs(d['chg_pct']):.2f}%) | "
            f"Vol ratio: {d['vol_ratio']:.1f}x | RSI: {d['rsi']:.0f} | "
            f"MACD: {d['macd']['macd']:.4f} (hist: {d['macd']['histogram']:.4f}) | "
            f"BB %B: {d['bb']['pct_b']:.0f} (bw: {d['bb']['bandwidth']:.1f}%) | "
            f"Signal: {d['top_signal']}"
        )
        items.append({
            "title":   f"[OHLCV] {d['ticker']} ({d['name']}): "
                       f"{direction}{abs(d['chg_pct']):.2f}% — {d['top_signal']}",
            "url":     f"https://finance.yahoo.com/quote/{d['ticker']}",
            "summary": summary,
            "source":  "Yahoo Finance",
            "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "track":   "ohlcv",
            "score":   d["score"],
        })
    return items


# ── 1b. SEC EDGAR 8-K cybersecurity disclosures ───────────────────────────────
def collect_sec_8k(lookback_days: int = 7) -> list[dict]:
    end_date   = datetime.now().strftime('%Y-%m-%d')
    start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')

    search_terms = [
        '"cybersecurity incident"',
        '"material cybersecurity"',
        '"ransomware"',
        '"data breach"',
        '"unauthorized access"',
    ]

    seen  = set()
    items = []

    for term in search_terms:
        try:
            url = (
                "https://efts.sec.gov/LATEST/search-index"
                f"?q={urllib.parse.quote(term)}"
                f"&dateRange=custom&startdt={start_date}&enddt={end_date}"
                "&forms=8-K"
            )
            raw  = _http_get(url, headers={"Accept": "application/json"})
            data = json.loads(raw)
            hits = data.get("hits", {}).get("hits", [])

            for hit in hits[:8]:
                src    = hit.get("_source", {})
                entity = src.get("entity_name", "Unknown").strip()
                filed  = src.get("file_date", "")
                period = src.get("period_of_report", "")
                eid    = src.get("entity_id", "")
                key    = f"{entity}:{filed}"
                if key in seen:
                    continue
                seen.add(key)
                link = (
                    f"https://www.sec.gov/cgi-bin/browse-edgar"
                    f"?action=getcompany&CIK={eid}&type=8-K&owner=include&count=5"
                    if eid else "https://efts.sec.gov/LATEST/search-index"
                )
                items.append({
                    "title":   f"[SEC 8-K] {entity} — {term.strip(chr(34))}",
                    "url":     link,
                    "summary": f"Filed: {filed} | Period: {period} | Match: {term}",
                    "source":  "SEC EDGAR",
                    "date":    filed,
                    "track":   "sec",
                    "score":   100,
                    "entity":  entity,
                })
        except Exception:
            pass

    return items


# ── 1c. Financial RSS feeds ───────────────────────────────────────────────────
ATOM_NS = "{http://www.w3.org/2005/Atom}"

def parse_feed_xml(content: str, source_name: str, track: str,
                   lookback_days: int) -> list[dict]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    items  = []
    tag    = root.tag

    if "rss" in tag or root.find("channel") is not None:
        channel = root.find("channel") or root
        for item in channel.findall("item"):
            title   = _strip_html(item.findtext("title") or "")
            link    = (item.findtext("link") or "").strip()
            summary = _strip_html(item.findtext("description") or "")
            pub     = parse_date(item.findtext("pubDate") or "")
            if pub and pub < cutoff:
                continue
            if not title:
                continue
            items.append({
                "title":   title, "url": link, "summary": summary,
                "source":  source_name,
                "date":    pub.isoformat() if pub else "",
                "track":   track, "score": 0,
            })

    elif ATOM_NS + "feed" in tag or "feed" in tag:
        pfx = ATOM_NS if tag.startswith(ATOM_NS) else ""
        for entry in root.findall(f"{pfx}entry"):
            title   = _strip_html(entry.findtext(f"{pfx}title") or "")
            summary = _strip_html(
                entry.findtext(f"{pfx}summary") or
                entry.findtext(f"{pfx}content") or ""
            )
            link_el = entry.find(f"{pfx}link")
            link    = (link_el.attrib.get("href") if link_el is not None else "") or ""
            updated = parse_date(
                entry.findtext(f"{pfx}updated") or
                entry.findtext(f"{pfx}published") or ""
            )
            if updated and updated < cutoff:
                continue
            if not title:
                continue
            items.append({
                "title":   title, "url": link, "summary": summary,
                "source":  source_name,
                "date":    updated.isoformat() if updated else "",
                "track":   track, "score": 0,
            })

    return items


def collect_rss_feed(source_name: str, url: str, track: str,
                     lookback_days: int) -> list[dict]:
    try:
        raw = _http_get(url).decode("utf-8", errors="replace")
        return parse_feed_xml(raw, source_name, track, lookback_days)
    except Exception:
        return []


# ── 1d. Finnhub company news (optional — requires FINNHUB_API_KEY in .env) ───
def collect_finnhub_news(ticker: str, lookback_days: int) -> list[dict]:
    api_key = os.environ.get("FINNHUB_API_KEY", "")
    if not api_key:
        return []
    end   = datetime.now().strftime('%Y-%m-%d')
    start = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
    try:
        url  = (f"https://finnhub.io/api/v1/company-news"
                f"?symbol={ticker}&from={start}&to={end}&token={api_key}")
        raw  = _http_get(url)
        news = json.loads(raw)
        items = []
        for article in news[:5]:
            headline = article.get("headline", "")
            summary  = article.get("summary", "")[:400]
            url_link = article.get("url", "")
            dt       = datetime.fromtimestamp(
                article.get("datetime", 0), tz=timezone.utc
            )
            items.append({
                "title":   f"[{ticker}] {headline}",
                "url":     url_link,
                "summary": summary,
                "source":  f"Finnhub/{ticker}",
                "date":    dt.isoformat(),
                "track":   "finance",
                "score":   0,
            })
        return items
    except Exception:
        return []


# ── 1e. Orchestrate all collectors ────────────────────────────────────────────
def collect_all(watchlist: list[str], lookback_days: int,
                enabled_tracks: set | None) -> tuple[list[dict], list[dict]]:
    """
    Returns (ohlcv_raw_list, intel_items_list).
    ohlcv_raw_list: raw OHLCV dicts — cached for price_check tool.
    intel_items_list: unified scored intel items.
    """
    cprint(C_PHASE, "\n[PHASE 1] Collecting market intelligence...")

    # OHLCV
    ohlcv_raw   = []
    ohlcv_items = []
    if enabled_tracks is None or "ohlcv" in enabled_tracks:
        cprint(C_PHASE, f"  Fetching OHLCV for {len(watchlist)} tickers...")
        ohlcv_raw   = collect_all_ohlcv(watchlist)
        ohlcv_items = ohlcv_to_intel_items(ohlcv_raw)

    # SEC + RSS + Finnhub (parallel)
    tasks = []

    if enabled_tracks is None or "sec" in enabled_tracks:
        tasks.append(("SEC EDGAR 8-K",
                      lambda: collect_sec_8k(max(lookback_days, 7))))

    for track_key, feeds in FINANCE_RSS_FEEDS.items():
        if enabled_tracks and track_key not in enabled_tracks:
            continue
        for name, url in feeds.items():
            tasks.append((
                f"rss:{name}",
                lambda n=name, u=url, t=track_key:
                    collect_rss_feed(n, u, t, lookback_days)
            ))

    # Finnhub for highest-anomaly tickers (skips gracefully if no API key)
    if enabled_tracks is None or "finance" in enabled_tracks:
        anomalous = [d["ticker"] for d in ohlcv_raw if d.get("score", 0) >= 65][:5]
        for ticker in anomalous:
            tasks.append((
                f"finnhub:{ticker}",
                lambda t=ticker: collect_finnhub_news(t, lookback_days)
            ))

    other_items: list[dict] = []
    lock = threading.Lock()

    def run_task(label_fn):
        label, fn = label_fn
        try:
            result = fn()
            with lock:
                other_items.extend(result)
            cprint(C_OBS, f"  ✓ {label}: {len(result)} item(s)")
        except Exception as e:
            cprint(C_WARN, f"  ✗ {label}: {e}")

    with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as pool:
        list(pool.map(run_task, tasks))

    all_items = ohlcv_items + other_items
    cprint(C_PHASE,
           f"[PHASE 1] Collected: {len(ohlcv_items)} OHLCV + "
           f"{len(other_items)} news/SEC = {len(all_items)} total")
    return ohlcv_raw, all_items


# ══════════════════════════════════════════════════════════════════════════════
#  SCORING + DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════
def score_item(item: dict) -> int:
    if item.get("track") == "sec":
        return 100
    if item.get("track") == "ohlcv":
        return item.get("score", 15)
    text = (item.get("title", "") + " " + item.get("summary", "")).lower()
    for score, keywords in FINANCE_SCORE_RULES:
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
        if item.get("track") != "ohlcv":
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
_ohlcv_cache: dict[str, dict] = {}

def tool_price_check(ticker: str) -> str:
    cprint(C_TOOL, f"  [PRICE_CHECK] {ticker}")
    ticker = ticker.upper().strip()
    data = _ohlcv_cache.get(ticker) or collect_yahoo_ohlcv(ticker)
    if not data:
        return f"[PRICE_CHECK] No data for {ticker}."
    if ticker not in _ohlcv_cache:
        _ohlcv_cache[ticker] = data
    direction = "▼" if data["chg_pct"] < 0 else "▲"
    return (
        f"[PRICE_CHECK] {ticker} ({data['name']}): ${data['current']} "
        f"({direction}{abs(data['chg_pct']):.2f}%) | "
        f"RSI={data['rsi']:.0f} | Vol×{data['vol_ratio']:.1f} | "
        f"MACD hist={data['macd']['histogram']:.4f} | "
        f"BB %B={data['bb']['pct_b']:.0f} | Signal: {data['top_signal']}"
    )


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
    return rag_ingest(text, source="agent09_market_intel", doc_id=doc_id)


def tool_file_write(filename: str, content: str) -> str:
    cprint(C_TOOL, f"  [FILE_WRITE] {filename}")
    out_path = REPORTS_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)
    return f"[FILE_WRITE] Written: {out_path}"


# ── Tool schema & dispatcher ──────────────────────────────────────────────────
TOOL_SCHEMA = [
    {
        "name":        "price_check",
        "description": "Get current price, % change, RSI, volume ratio, MACD, and BB for any ticker.",
        "parameters":  {"ticker": "Stock or ETF ticker symbol (e.g. MSFT, CRWD, COIN)."}
    },
    {
        "name":        "rag_lookup",
        "description": "Check if a company, threat actor, or incident is in the knowledge base.",
        "parameters":  {"query": "Search string (e.g. 'MSFT breach 2024' or 'Lazarus ransomware')."}
    },
    {
        "name":        "rag_ingest",
        "description": "Store the market intelligence brief in ChromaDB for other agents.",
        "parameters":  {"text": "Content to store.", "doc_id": "Optional document ID."}
    },
    {
        "name":        "file_write",
        "description": "Write the final market intelligence report to the reports/ directory.",
        "parameters":  {
            "filename": "Report filename (e.g. MARKET_20250101_0930.md).",
            "content":  "Full report in Markdown."
        }
    },
]

def dispatch_tool(name: str, params: dict) -> str:
    if name == "price_check":
        return tool_price_check(params.get("ticker", ""))
    elif name == "rag_lookup":
        return tool_rag_lookup(params.get("query", ""))
    elif name == "rag_ingest":
        return tool_rag_ingest(params.get("text", ""), params.get("doc_id"))
    elif name == "file_write":
        return tool_file_write(params.get("filename", "market.md"),
                               params.get("content", ""))
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


def build_system_prompt(watchlist: list[str], lookback_days: int,
                         item_count: int, ts: str) -> str:
    tool_docs = "\n".join(
        f"  {t['name']}({', '.join(t['parameters'].keys())}) — {t['description']}"
        for t in TOOL_SCHEMA
    )
    sectors = "\n".join(
        f"  {sector.upper():15s}: {', '.join(tickers)}"
        for sector, tickers in WATCHLIST_BY_SECTOR.items()
    )
    return f"""You are Agent-09 — the market intelligence analyst for the AGENTS-HQ security platform.

Run timestamp : {ts}
Lookback      : {lookback_days} day(s)
Items provided: {item_count} (pre-scored and ranked)
Watchlist:
{sectors}

Your mission: analyze market signals through a threat-intelligence lens. Every financial anomaly
may signal a cyber event. Bridge the financial data to threat-actor motivations, attack vectors,
and concrete recommendations for the platform's other agents.

Available tools:
{tool_docs}

ReAct format — follow exactly:
  THOUGHT: <your reasoning>
  ACTION: <tool_name>
  PARAMS: <JSON object>

Conclude with:
  FINAL: <one-paragraph executive summary for the operator>

Analysis workflow:
  1. For CRITICAL items (SEC 8-K, price drops >10%): call rag_lookup for prior context.
  2. For tickers with unusual signals: call price_check for deeper detail if needed.
  3. Compose the full market intelligence report.
  4. Call rag_ingest with the complete brief.
  5. Call file_write with the full structured report.

Threat-nexus interpretation guide:
  PRICE_DROP_10 / PRICE_DROP_15 — Possible undisclosed breach, ransomware, or regulatory action.
    → Recommend Agent-01 OSINT sweep on company domain; Agent-02 CVE recon on their tech stack.
  VOL_SPIKE_5X on defense/big-tech — Insider trading, M&A leak, or nation-state intelligence.
    → Flag for Agent-05 red team targeting context update.
  SEC 8-K CYBER — Confirmed material breach. Company is a live incident site.
    → Recommend Agent-02 full CVE/exploit scan on disclosed vendor/product.
  RSI_EXTREME (<25) — Company in financial distress → elevated insider threat and social engineering risk.
  MACD_BEARISH on cybersecurity stocks (CRWD, PANW, ZS) — Sector sell-off; possible regulatory
    event or major breach eroding confidence. Cross-reference with Agent-08 recent advisories.
  Crypto DeFi exploits — Extract blockchain addresses and amounts; forward IOCs to Agent-06.
  M&A announcement — Attack surface changing. Target + acquirer stacks merge → new vuln window.

Report structure to produce:
  # AGENTS-HQ Market Intel Brief — {ts}
  ## Run Metadata
  ## CRITICAL — SEC Cybersecurity Disclosures & Major Price Events
  ## HIGH — Anomalous Market Signals (Volume Spikes, Large Drops)
  ## Technical Analysis Summary (RSI / MACD / Bollinger Bands)
  ## Financially Motivated Threat Actor Context
  ## M&A Activity & Attack Surface Changes
  ## Crypto / DeFi Exploits & Ransomware Payments
  ## Platform Recommendations (specific Agent-01/02/05/06 action items)

Rules:
  1. Do not repeat a tool call with identical parameters.
  2. All CRITICAL items must appear in the report.
  3. Platform Recommendations must name the specific agent and target:
     "Run Agent-01 against <domain>", "Forward <ticker> 8-K to Agent-02".
  4. Report filename: MARKET_{ts.replace('-','').replace(':','').replace(' ','_')[:15]}.md
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


def analyze_with_llm(scored_items: list[dict], watchlist: list[str],
                      lookback_days: int) -> str:
    cprint(C_PHASE, "\n[PHASE 2] LLM analysis...")
    ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    formatted = _format_items_for_llm(scored_items)
    system_p  = build_system_prompt(watchlist, lookback_days, len(scored_items), ts)

    messages = [
        {"role": "system", "content": system_p},
        {"role": "user",
         "content": (
             f"Here are the {len(scored_items)} scored market intelligence items:\n\n"
             f"{formatted}\n\nBegin threat-nexus analysis."
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

        cprint(C_OBS, f"\n  [OBS] {observation[:400]}{'...' if len(observation) > 400 else ''}")
        messages.append({"role": "user", "content": f"OBSERVATION: {observation}"})

    else:
        cprint(C_WARN, "\n[!] Max iterations reached.")
        final_output = "[Agent-09] Analysis complete. See reports/ for MARKET_*.md output."

    return final_output


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def run_pipeline(watchlist: list[str] | None = None,
                 lookback_days: int = DEFAULT_LOOKBACK_DAYS,
                 enabled_tracks: set | None = None) -> str:
    if watchlist is None:
        watchlist = DEFAULT_WATCHLIST
    _ohlcv_cache.clear()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cprint(C_HEAD, f"\n{'='*64}")
    cprint(C_HEAD, f"  AGENT-09 — MARKET INTEL")
    cprint(C_HEAD, f"  Watchlist : {len(watchlist)} tickers  |  Started : {ts}")
    cprint(C_HEAD, f"{'='*64}")

    ohlcv_raw, all_items = collect_all(watchlist, lookback_days, enabled_tracks)

    for d in ohlcv_raw:
        _ohlcv_cache[d["ticker"]] = d

    scored_items = score_and_filter(all_items)
    if not scored_items:
        cprint(C_WARN, "[!] No items collected. Check network / feeds.")
        return "No items collected."

    summary = analyze_with_llm(scored_items, watchlist, lookback_days)

    cprint(C_HEAD, f"\n[DONE] Run complete at {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
    return summary


# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════════════════════
def interactive_mode():
    cprint(C_HEAD, "\n══════════════════════════════════════════════")
    cprint(C_HEAD, "  AGENT-09 — MARKET INTEL  [interactive]")
    cprint(C_HEAD, "══════════════════════════════════════════════")
    print("  Type 'exit' to quit.\n")

    while True:
        try:
            tickers_str = input(
                f"{C_PHASE}  Tickers [Enter for default {len(DEFAULT_WATCHLIST)}-ticker watchlist] > {C_RESET}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if tickers_str.lower() in ("exit", "quit"):
            break

        days_str   = input(f"{C_PHASE}  Lookback days [default: {DEFAULT_LOOKBACK_DAYS}] > {C_RESET}").strip()
        tracks_str = input(
            f"{C_PHASE}  Tracks [ohlcv/sec/finance/crypto or Enter for all] > {C_RESET}"
        ).strip()

        watchlist = (
            [t.strip().upper() for t in tickers_str.split(",") if t.strip()]
            if tickers_str else None
        )
        try:
            lookback_days = int(days_str) if days_str else DEFAULT_LOOKBACK_DAYS
        except ValueError:
            lookback_days = DEFAULT_LOOKBACK_DAYS

        enabled_tracks = (
            set(t.strip() for t in tracks_str.split(",") if t.strip())
            if tracks_str else None
        )

        run_pipeline(watchlist, lookback_days, enabled_tracks)


# ══════════════════════════════════════════════════════════════════════════════
#  N8N WEBHOOK SERVER
#  Recommended cron: daily at 13:30 UTC (9:30 AM ET — US market open)
# ══════════════════════════════════════════════════════════════════════════════
def start_webhook_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != "/webhook/agent09":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}

            tickers_raw   = data.get("tickers", None)
            lookback_days = int(data.get("days", DEFAULT_LOOKBACK_DAYS))
            tracks_raw    = data.get("tracks", None)

            watchlist = (
                [t.strip().upper() for t in tickers_raw.split(",") if t.strip()]
                if isinstance(tickers_raw, str) and tickers_raw
                else None
            )
            enabled_tracks = (
                set(t.strip() for t in tracks_raw.split(",") if t.strip())
                if isinstance(tracks_raw, str) and tracks_raw
                else None
            )

            threading.Thread(
                target=lambda: run_pipeline(watchlist, lookback_days, enabled_tracks),
                daemon=True
            ).start()

            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status":   "accepted",
                "tickers":  (watchlist or DEFAULT_WATCHLIST)[:5],
                "days":     lookback_days,
                "tracks":   list(enabled_tracks) if enabled_tracks else "all",
                "message":  "Agent-09 started. Check reports/ for MARKET_*.md output.",
            }).encode())

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok","agent":"agent09"}')
            else:
                self.send_error(404)

    server = HTTPServer(("127.0.0.1", N8N_WEBHOOK_PORT), Handler)
    cprint(C_HEAD, f"\n[WEBHOOK] Agent-09 on http://127.0.0.1:{N8N_WEBHOOK_PORT}/webhook/agent09")
    cprint(C_HEAD,  '  POST {}                                  — full watchlist, 1-day lookback')
    cprint(C_HEAD,  '  POST {"tickers": "MSFT,CRWD", "days": 3} — specific tickers, 3-day window')
    cprint(C_HEAD,  '  POST {"tracks": "sec,ohlcv"}             — SEC filings + OHLCV only')
    cprint(C_HEAD,  '  GET  /health                             — liveness check\n')
    server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Agent-09 — Market Intel (financial threat intelligence)"
    )
    parser.add_argument("--tickers",     default=None,
                        help=f"Comma-separated tickers (default: {len(DEFAULT_WATCHLIST)}-ticker watchlist)")
    parser.add_argument("--days",        type=int, default=DEFAULT_LOOKBACK_DAYS,
                        help="Lookback window in days (default: 1)")
    parser.add_argument("--tracks",      default=None,
                        help="Comma-separated tracks: ohlcv,sec,finance,crypto")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--n8n-server",  action="store_true")
    args = parser.parse_args()

    if args.n8n_server:
        start_webhook_server()
        return

    if args.interactive:
        interactive_mode()
        return

    watchlist = (
        [t.strip().upper() for t in args.tickers.split(",") if t.strip()]
        if args.tickers else None
    )
    enabled_tracks = (
        set(t.strip() for t in args.tracks.split(",") if t.strip())
        if args.tracks else None
    )
    run_pipeline(watchlist, args.days, enabled_tracks)


if __name__ == "__main__":
    main()
