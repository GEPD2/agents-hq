import ipaddress
import json
import os
import urllib.request
from datetime import datetime
from pathlib import Path

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


def get_map_ips(limit_geocode: int = 100) -> dict:
    """Aggregate IP IOCs and resolve to coordinates (cache-first, ipinfo fallback)."""
    token = _ipinfo_token()
    rows = _distinct_ips()
    points = []
    geocoded = 0
    for r in rows:
        ip = r["ip"]
        if not _is_public(ip):
            continue
        geo = _get_cached(ip)
        if not geo and geocoded < limit_geocode:
            geo = _geocode(ip, token)
            if geo:
                geocoded += 1
        if not geo or geo.get("lat") is None:
            continue
        points.append({
            "ip": ip,
            "lat": geo["lat"], "lon": geo["lon"],
            "country": geo.get("country") or "??",
            "city": geo.get("city") or "",
            "report_count": r["report_count"],
            "reports": r["reports"],
            "last_seen": r["last_seen"],
        })

    countries = {}
    for p in points:
        countries[p["country"]] = countries.get(p["country"], 0) + p["report_count"]
    top = sorted(countries.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        "points": points,
        "top_countries": [{"country": c, "count": n} for c, n in top],
        "geocoding_enabled": token is not None,
        "total_ips": len(rows),
    }
