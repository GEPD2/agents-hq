import bisect
import ipaddress
import json
import os
import urllib.request
from datetime import datetime
from pathlib import Path

# Keyless offline IP-to-country dataset (fetched into website/data/ by setup_stack.py).
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_IP_DB_FILE = DATA_DIR / "ip_country.csv"

# Parallel sorted arrays for a bisect lookup: start ints, end ints, ISO2 codes.
_ip4_starts: list[int] = []
_ip4_ends: list[int] = []
_ip4_cc: list[str] = []
_ip_db_loaded = False


def _load_ip_country() -> None:
    global _ip_db_loaded
    if _ip_db_loaded:
        return
    _ip_db_loaded = True
    if not _IP_DB_FILE.exists():
        return
    rows = []
    try:
        for line in _IP_DB_FILE.read_text().splitlines():
            parts = line.split(",")
            if len(parts) < 3:
                continue
            start, end, cc = parts[0].strip(), parts[1].strip(), parts[2].strip().upper()
            if ":" in start or ":" in end or len(cc) != 2:
                continue
            try:
                s = int(ipaddress.IPv4Address(start))
                e = int(ipaddress.IPv4Address(end))
            except ValueError:
                continue
            rows.append((s, e, cc))
    except Exception:
        return
    rows.sort(key=lambda r: r[0])
    _ip4_starts[:] = [r[0] for r in rows]
    _ip4_ends[:] = [r[1] for r in rows]
    _ip4_cc[:] = [r[2] for r in rows]


def _resolve_country_offline(ip: str) -> str | None:
    _load_ip_country()
    if not _ip4_starts:
        return None
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(_ip4_starts, n) - 1
    if 0 <= i < len(_ip4_ends) and n <= _ip4_ends[i]:
        return _ip4_cc[i]
    return None

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

AGENTS_BASE_DIR = os.environ.get("AGENTS_BASE_DIR", "/agents-hq")


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


def _ipinfo_token() -> str | None:
    token = os.environ.get("IPINFO_TOKEN")
    if token:
        return token
    env_file = Path(AGENTS_BASE_DIR) / "agent_01_osint" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("IPINFO_TOKEN=") and "=" in line:
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def _get_cached(ip: str) -> dict | None:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("SELECT ip, lat, lon, country, city FROM ip_geo WHERE ip=%s", (ip,))
                return cur.fetchone()
    except Exception:
        return None


def _cache(ip: str, geo: dict) -> None:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO ip_geo (ip, lat, lon, country, city, cached_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        lat=VALUES(lat), lon=VALUES(lon),
                        country=VALUES(country), city=VALUES(city), cached_at=VALUES(cached_at)
                """, (ip, geo.get("lat"), geo.get("lon"), geo.get("country"),
                      geo.get("city"), datetime.utcnow()))
            db.commit()
    except Exception:
        pass


def _geocode(ip: str, token: str | None) -> dict | None:
    if not token:
        return None
    url = f"https://ipinfo.io/{ip}/json?token={token}"
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    loc = data.get("loc")
    if not loc or "," not in loc:
        return None
    lat, lon = loc.split(",", 1)
    try:
        geo = {"lat": float(lat), "lon": float(lon),
               "country": data.get("country"), "city": data.get("city")}
    except ValueError:
        return None
    _cache(ip, geo)
    return geo


def _distinct_ips() -> list[dict]:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT value AS ip,
                           COUNT(*) AS report_count,
                           GROUP_CONCAT(DISTINCT report_file SEPARATOR '|||') AS reports,
                           MAX(seen_at) AS last_seen
                    FROM iocs WHERE type='ip'
                    GROUP BY value
                    ORDER BY report_count DESC
                    LIMIT 500
                """)
                rows = cur.fetchall()
        for r in rows:
            r["reports"] = r["reports"].split("|||") if r.get("reports") else []
            r["last_seen"] = str(r["last_seen"]) if r.get("last_seen") else ""
        return rows
    except Exception:
        return []


def get_map_ips() -> dict:
    """Aggregate IP IOCs to country level, keyless and offline. Country comes from
    the offline dataset first, then the cached ip_geo country. The SVG world map
    plots these by country centroid client-side; no external calls are made."""
    rows = _distinct_ips()
    agg: dict[str, dict] = {}
    located = 0
    for r in rows:
        ip = r["ip"]
        if not _is_public(ip):
            continue
        country = _resolve_country_offline(ip)
        if not country:
            cached = _get_cached(ip)
            country = (cached or {}).get("country")
        if not country:
            continue
        located += 1
        entry = agg.setdefault(country, {"country": country, "count": 0, "ips": []})
        entry["count"] += r["report_count"]
        if len(entry["ips"]) < 25:
            entry["ips"].append(ip)

    countries = sorted(agg.values(), key=lambda e: e["count"], reverse=True)
    _load_ip_country()
    resolver = "offline" if _ip4_starts else ("cache" if located else "none")

    return {
        "countries": countries,
        "top_countries": [{"country": c["country"], "count": c["count"]} for c in countries[:10]],
        "resolver": resolver,
        "located": located,
        "total_ips": len(rows),
    }
