import json
import os
import re
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

DB_HOST = os.environ.get("MYSQL_HOST", "localhost")
DB_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
DB_NAME = os.environ.get("MYSQL_DATABASE", "agents_hq")
DB_USER = os.environ.get("MYSQL_USER", "agents")
DB_PASS = os.environ.get("MYSQL_PASSWORD", "agents_hq")

DEFAULT_TICKERS = ["CRWD", "PANW", "S"]
_TICKER_RE = re.compile(r"^[A-Z.\-]{1,8}$")
_RANGE_MAP = {30: "1mo", 90: "3mo", 180: "6mo", 365: "1y"}


def _conn():
    if not HAS_PYMYSQL:
        raise RuntimeError("pymysql not installed")
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


def _http_get(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (AGENTS-HQ market correlator)",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:
        return None


def fetch_series(ticker: str, days: int) -> list[dict]:
    """Daily close prices from Yahoo Finance chart API (no key required)."""
    if not _TICKER_RE.match(ticker):
        return []
    rng = _RANGE_MAP.get(days, "3mo")
    url = (f"https://query1.finance.yahoo.com/v8/finance/chart/{ticker}"
           f"?range={rng}&interval=1d")
    data = _http_get(url)
    try:
        result = data["chart"]["result"][0]
        stamps = result["timestamp"]
        closes = result["indicators"]["quote"][0]["close"]
    except (TypeError, KeyError, IndexError):
        return []
    out = []
    for ts, close in zip(stamps, closes):
        if close is None:
            continue
        out.append({
            "date": datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d"),
            "close": round(float(close), 2),
        })
    return out


def collect_events(days: int) -> list[dict]:
    """Security-event markers: CVE first-appearances + CRITICAL report dates."""
    events = []
    cutoff = datetime.utcnow() - timedelta(days=days)

    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT value AS cve, MIN(seen_at) AS first_seen
                    FROM iocs WHERE type='cve'
                    GROUP BY value
                    HAVING first_seen >= %s
                    ORDER BY first_seen
                """, (cutoff,))
                for r in cur.fetchall():
                    if not r.get("first_seen"):
                        continue
                    events.append({
                        "date": r["first_seen"].strftime("%Y-%m-%d"),
                        "type": "cve",
                        "label": r["cve"],
                    })
    except Exception:
        pass

    try:
        from services.report_parser import list_reports
        for rep in list_reports():
            if rep["agent"] not in ("08", "09", "10"):
                continue
            if rep["priority_counts"].get("CRITICAL", 0) <= 0:
                continue
            date = rep["created"][:10]
            if date < cutoff.strftime("%Y-%m-%d"):
                continue
            events.append({
                "date": date,
                "type": "critical",
                "label": rep["filename"],
            })
    except Exception:
        pass

    return events


def event_counts_by_day(events: list[dict]) -> list[dict]:
    counter = Counter(e["date"] for e in events)
    return [{"date": d, "count": c} for d, c in sorted(counter.items())]


def build_correlation(tickers: list[str] | None = None, days: int = 90) -> dict:
    tickers = tickers or DEFAULT_TICKERS
    tickers = [t.strip().upper() for t in tickers if _TICKER_RE.match(t.strip().upper())][:6]
    series = {t: fetch_series(t, days) for t in tickers}
    events = collect_events(days)
    return {
        "tickers": tickers,
        "days": days,
        "series": series,
        "events": events,
        "event_counts": event_counts_by_day(events),
    }
